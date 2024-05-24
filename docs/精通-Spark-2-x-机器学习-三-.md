# 精通 Spark 2.x 机器学习（三）

> 原文：[`zh.annas-archive.org/md5/3BA1121D202F8663BA917C3CD75B60BC`](https://zh.annas-archive.org/md5/3BA1121D202F8663BA917C3CD75B60BC)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：GraphX 的图形分析

在我们相互连接的世界中，图形是无处不在的。**万维网**（**WWW**）只是一个我们可以考虑为图形的复杂结构的例子，其中网页代表着通过它们之间的传入和传出链接连接的实体。在 Facebook 的社交图中，成千上万的用户形成一个网络，连接着全球的朋友。我们今天看到并且可以收集数据的许多其他重要结构都具有自然的图形结构；也就是说，它们可以在非常基本的层面上被理解为一组通过我们称之为*边*的方式相互连接的*顶点*的集合。以这种一般性的方式陈述，这一观察反映了图形是多么普遍。它的价值在于图形是经过深入研究的结构，并且有许多可用的算法可以让我们获得关于这些图形代表的重要见解。

Spark 的 GraphX 库是研究大规模图形的自然入口点。利用 Spark 核心中的 RDD 来编码顶点和边，我们可以使用 GraphX 对大量数据进行图形分析。在本章中，您将学习以下主题：

+   基本图形属性和重要的图形操作

+   GraphX 如何表示属性图形以及如何处理它们

+   以各种方式加载图形数据并生成合成图形数据以进行实验

+   使用 GraphX 的核心引擎来实现基本图形属性

+   使用名为 Gephi 的开源工具可视化图形

+   使用 GraphX 的两个关键 API 实现高效的图形并行算法。

+   使用 GraphFrames，这是 DataFrame 到图形的扩展，并使用优雅的查询语言研究图形

+   在社交图上运行 GraphX 中可用的重要图形算法，包括转发和一起出现在电影中的演员的图形

# 基本图形理论

在深入研究 Spark GraphX 及其应用之前，我们将首先在基本层面上定义图形，并解释它们可能具有的属性以及在我们的上下文中值得研究的结构。在介绍这些属性的过程中，我们将给出更多我们在日常生活中考虑的图形的具体例子。

# 图形

为了简要地形式化引言中简要概述的图形概念，在纯数学层面上，图形*G = (V, E)*可以描述为一对*顶点*V 和*边*E，如下所示：

*V = {v[1], ..., v[n]}*

*E = {e[1], ..., e[m]}*

我们称 V 中的元素*v[i]*为一个顶点，称 E 中的*e[i]*为一条边，其中连接两个顶点*v[1]*和*v[2]*的每条边实际上只是一对顶点，即*e[i] = (v[1], v[2])*。让我们构建一个由五个顶点和六条边组成的简单图形，如下图所示：

*V ={v[1], v[2], v[3], v[4], v[5]}*

*E = {e[1] = (v[1], v[2]), e[2] = (v[1], v[3]), e[3] = (v[2], v[3]),*

*       e[4] = (v[3], v[4]), e[5] = (v[4], v[1]), e[6] = (v[4], v[5])}*

这就是图形的样子：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00152.jpeg)

图 1：一个由五个顶点和六条边组成的简单无向图

请注意，在*图 1*中实现的图形的实现中，节点相对位置、边的长度和其他视觉属性对于图形是不重要的。实际上，我们可以通过变形以任何其他方式显示图形。图形的定义完全决定了它的*拓扑*。

# 有向图和无向图

在构成边*e*的一对顶点中，按照惯例，我们称第一个顶点为*源*，第二个顶点为*目标*。这里的自然解释是，边*e*所代表的连接具有*方向*；它从源流向目标。请注意，在*图 1*中，显示的图形是无向的；也就是说，我们没有区分源和目标。

使用完全相同的定义，我们可以创建我们图的有向版本，如下图所示。请注意，图在呈现方式上略有不同，但顶点和边的连接保持不变：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00153.jpeg)

图 2：具有与前一个相同拓扑结构的有向图。事实上，忘记边的方向将产生与图 1 中相同的图形

每个有向图自然地有一个相关的无向图，通过简单地忘记所有边的方向来实现。从实际角度来看，大多数图的实现本质上都建立在有向边上，并在需要时抑制方向的附加信息。举个例子，将前面的图看作是由关系“友谊”连接的五个人组成的。我们可以认为友谊是一种对称属性，如果你是我的朋友，我也是你的朋友。根据这种解释，方向性在这个例子中并不是一个非常有用的概念，因此我们实际上最好将其视为一个无向图的例子。相比之下，如果我们要运行一个允许用户主动向其他用户发送好友请求的社交网络，有向图可能更适合编码这些信息。

# 顺序和度

对于任何图，无论是有向的还是不是，我们都可以得出一些基本的性质，这些性质在本章后面会讨论。我们称顶点的数量|V|为图的*顺序*，边的数量|E|为它的*度*，有时也称为*价度*。顶点的度是具有该顶点作为源或目标的边的数量。对于有向图和给定的顶点*v*，我们还可以区分*入度*，即指向*v*的所有边的总和，和*出度*，即从*v*开始的所有边的总和。举个例子，图 1 中的无向图的顺序为 5，度为 6，与图 2 中显示的有向图相同。在后者中，顶点 v1 的出度为 2，入度为 1，而 v5 的出度为 0，入度为 1。

在最后两个例子中，我们用它们各自的标识符注释了顶点和边，如定义*G = (V, E)*所指定的那样。对于接下来的大多数图形可视化，我们将假设顶点和边的标识是隐含已知的，并将通过为我们的图形加上额外信息来代替它们。我们明确区分标识符和标签的原因是 GraphX 标识符不能是字符串，我们将在下一节中看到。下图显示了一个带有一组人的关系的标记图的示例：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00154.jpeg)

图 3：显示了一组人及其关系的有向标记图

# 有向无环图

我们接下来要讨论的概念是无环性。*循环图*是指至少有一个顶点，通过图中的路径连接到自身。我们称这样的路径为*循环*。在无向图中，任何形成循环的链都可以，而在有向图中，只有当我们可以通过遵循有向边到达起始顶点时，我们才谈论循环。例如，考虑我们之前看到的一些图。在图 2 中，由{e2, e4, e5}形成了一个循环，而在其无向版本中，即图 1 中，有两个循环，分别是{e2, e4, e5}和{e1, e2, e3}。

有几种值得在这里提到的循环图的特殊情况。首先，如果一个顶点通过一条边与自身相连，我们将说图中有一个*循环*。其次，一个不包含任何两个顶点之间双向边的有向图被称为*定向图*。第三，包含*三角形*的图被认为包含三角形。三角形的概念是重要的，因为它经常用于评估图的连通性，我们将在后面讨论。以下图显示了一个具有不同类型循环的人工示例：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00155.jpeg)

图 4：一个玩具图，说明了循环或自环、双向边和三角形。

一般来说，研究图中任意自然数*n*的循环可以告诉你很多关于图的信息，但三角形是最常见的。由于有向循环不仅计算成本更高，而且比它们的无向版本更少见，我们通常只会在图中寻找无向三角形；也就是说，我们会忽略它的有向结构。

在许多应用程序中反复出现的一类重要图是**有向无环图**（DAGs）。我们已经从上一段知道了 DAG 是什么，即一个没有循环的有向图，但由于 DAG 是如此普遍，我们应该花更多的时间来了解它们。

我们在前面的所有章节中隐式使用的一个 DAG 实例是 Spark 的作业执行图。请记住，任何 Spark 作业都由按特定顺序执行的阶段组成。阶段由在每个分区上执行的任务组成，其中一些可能是独立的，而其他则彼此依赖。因此，我们可以将 Spark 作业的执行解释为由阶段（或任务）组成的有向图，其中边表示一个计算的输出被下一个计算所需。典型的例子可能是需要前一个映射阶段的输出的减少阶段。自然地，这个执行图不包含任何循环，因为这意味着我们要将一些运算符的输出无限地输入到图中，从而阻止我们的程序最终停止。因此，这个执行图可以被表示，并实际上在 Spark 调度器中实现为 DAG：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00156.jpeg)

图 5：用 Spark 在 RDD 上执行的一系列操作的可视化。执行图从定义上是一个 DAG。

# 连通分量

图的另一个重要属性是*连通性*。如果我们选择的任意两个顶点之间存在一条边的路径，无论边的方向如何，我们就说图是*连通的*。因此，对于有向图，我们在这个定义中完全忽略方向。对于有向图，可以使用更严格的连通性定义吗？如果任意两个顶点都可以通过有向边连接，我们就说图是*强连通的*。请注意，强连通性是对有向图施加的一个非常严格的假设。特别地，任何强连通图都是循环的。这些定义使我们能够定义（强）连通分量的相关概念。每个图都可以分解为连通分量。如果它是连通的，那么恰好有一个这样的分量。如果不是，那么至少有两个。正式定义，连通分量是给定图的最大子图，仍然是连通的。强连通分量也是同样的道理。连通性是一个重要的度量，因为它使我们能够将图的顶点聚类成自然属于一起的组。

例如，一个人可能对社交图中表示友谊的连接组件数量感兴趣。在一个小图中，可能有许多独立的组件。然而，随着图的规模变大，人们可能会怀疑它更有可能只有一个连接的组件，遵循着普遍接受的理由，即每个人都通过大约六个连接与其他人相连。

我们将在下一节中看到如何使用 GraphX 计算连接组件；现在，让我们只检查一个简单的例子。在下面的图表中，我们看到一个有十二个顶点的有向图：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00157.jpeg)

图 6：在小图中，连接和强连接组件可以很容易地读取，但对于更大的图来说，这变得越来越困难。

我们可以立即看到它有三个连接的组件，即三组顶点*{1, 2, 3}, {4, 5}*, 和 *{6, 7, 8, 9, 10, 11, 12}*。至于强连接组件，这需要比快速的视觉检查更多的努力。我们可以看到*{4, 5}*形成了一个强连接组件，*{8, 9, 10, 11}*也是如此。其他六个顶点形成了自己的强连接组件，也就是说，它们是孤立的。这个例子继续说明，对于一个有数百万个顶点的大图，通过正确的可视化工具，我们可能会幸运地找到大致连接的组件，但强连接组件的计算会更加复杂，这正是 Spark GraphX 派上用场的一个用例。

# 树

有了我们手头的连接组件的定义，我们可以转向另一类有趣的图，即树。*树*是一个连接的图，在其中恰好有一条路径连接任何给定的顶点到另一个顶点。由一组树的不相交组成的图称为森林。在下面的图表中，我们看到了一个在众所周知的鸢尾花数据集上运行的示意*决策树*。请注意，这仅用于说明目的，即展示此算法的输出如何被视为一个图：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00158.jpeg)

图 7：在鸢尾花数据集上运行的简单决策树，通过两个特征，即花瓣长度（PL）和花瓣宽度（PW），将其分类为三个类别 Setosa，Virginica 和 Versicolor

# 多重图

一般来说，没有环或多重边的图被称为*简单*。在本章的应用中，我们将遇到的大多数图都不具备这个属性。通常，从现实世界数据构建的图会在顶点之间有多重边。在文献中，具有多重边的图被称为多重图或伪图。在整个章节中，我们将坚持多重图的概念，并遵循这样一个约定，即这样的多重图也可以包括环。由于 Spark 支持多重图（包括环），这个概念在应用中将非常有用。在下面的图表中，我们看到了一个复杂的多重图，其中有多个连接的组件：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00159.jpeg)

图 8：一个稍微复杂的社交多重图，带有环和多重边。

# 属性图

在我们继续介绍 GraphX 作为图处理引擎之前，让我们看一下我们之前所见过的图的扩展。我们已经考虑过标记的图作为一种方便的方式来命名顶点和边。一般来说，在应用中我们将考虑的图数据将附加更多信息到顶点和边上，我们需要一种方法在我们的图中对这些额外的信息进行建模。为此，我们可以利用*属性图*的概念。

从图的基本定义作为顶点和边的一对开始，直接向这两个结构附加额外信息是不可能的。历史上，规避这一点的一种方法是扩展图并创建更多与属性对应的顶点，通过新的边与原始顶点连接，这些边编码与新顶点的关系。例如，在我们之前的朋友图示例中，如果我们还想在图中编码家庭地址，表示一个人的每个顶点必须与表示他们地址的顶点连接，它们之间的边是*lives at*。不难想象，这种方法会产生很多复杂性，特别是如果顶点属性相互关联。通过主语-谓语-宾语*三元组*在图中表示属性已经在所谓的**资源描述框架**（**RDF**）中得到了形式化，并且其结果被称为 RDF 模型。RDF 是一个独立的主题，并且比我们所介绍的更灵活。无论如何，熟悉这个概念并了解其局限性是很好的。

相比之下，在*属性图*中，我们可以为顶点和边增加基本上任意的附加结构。与任何事物一样，获得这种一般性的灵活性通常是一种权衡。在我们的情况下，许多图数据库中实现的基本图允许对查询进行强大的优化，而在属性图中，当涉及性能时，我们应该小心。在下一节中，当我们展示 Spark GraphX 如何实现属性图时，我们将更详细地讨论这个话题。

在本章的其余部分，我们将使用以下约定来表示属性图。附加到顶点的额外数据称为*顶点数据*，附加到边的数据称为*边数据*。为了举例更复杂的顶点和边数据，请参见以下图表，扩展了我们扩展朋友图的想法。这个例子也展示了我们所说的*三元组*，即带有其相邻顶点及其所有属性的边：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00160.jpeg)

图 9：显示通过地址数据增强的朋友属性图，通过多个关系连接。属性数据以 JSON 格式编码。

请注意，在前面的例子中，我们故意保持简单，但在更现实的情况下，我们需要嵌套数据结构--例如，回答欠款金额和到期时间。

在我们的上下文中，属性图的一个有趣的特殊情况是*加权图*，其中边、顶点或两者都具有权重，例如，附加到它们的整数或浮点数。这种情况的一个典型例子是一个由一组城市作为顶点组成的图，连接它们的边携带着位置之间的距离。在这种情况下会出现一些经典问题。一个例子是找到两个给定城市之间的最短路径。相关问题是*旅行推销员问题*，其中一个假设的推销员被要求使用可能的最短路线访问每个城市。

作为本节的结束语，重要的是要知道，在文献中，有一个广泛使用的与顶点同义的概念，即节点。我们在这里不使用这个术语，因为在 Spark 的上下文中，它很容易与执行任务的计算节点混淆。相反，我们将在整个章节中坚持使用顶点。此外，每当我们谈论图时，我们通常假设它是一个*有限*的*图*，也就是说，顶点和边的数量是有限的，在实践中，这几乎不算是限制。

# GraphX 分布式图处理引擎

除了 Spark MLlib 用于机器学习，我们在本书中已经遇到了几次，以及其他组件，如我们将在第八章“Lending Club Loan Prediction”中介绍的 Spark Streaming，Spark GraphX 是 Spark 生态系统的核心组件之一。GraphX 通过构建在 RDD 之上，专门用于以高效的方式处理大型图形。

使用上一节开发的命名法，GraphX 中的图形是一个带有环的有限多重图，其中*图形*实际上是指之前讨论的属性图扩展。接下来，我们将看到 GraphX 中图形是如何在内部构建的。

对于使用的示例，我们建议在本地启动`spark-shell`，这将自动为 GraphX 提供依赖项。要测试这在您的设置中是否正常工作，请尝试使用 Scala 的通配符运算符导入完整的 GraphX 核心模块，如下所示：

```scala
import org.apache.spark.graphx._
```

在您的屏幕上，您应该看到以下提示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00161.jpeg)

如果您更愿意通过使用 sbt 构建一个包来跟随示例，您应该在您的`build.sbt`中包含以下`libraryDependencies`：

```scala
"org.apache.spark" %% "spark-graphx" % "2.1.1"
```

这样做应该允许你导入 GraphX，就像之前展示的那样，创建一个你可以用 spark-submit 调用的应用程序。

# GraphX 中的图形表示

回想一下，对于我们来说，属性图是一个具有自定义数据对象的有向多重图。GraphX 的中心入口点是`Graph` API，具有以下签名：

```scala
class Graph[VD, ED] {
  val vertices: VertexRDD[VD]
  val edges: EdgeRDD[ED]
}
```

因此，在 GraphX 中，图形内部由一个编码顶点的 RDD 和一个编码边的 RDD 表示。在这里，`VD`是顶点数据类型，`ED`是我们属性图的边数据类型。我们将更详细地讨论`VertexRDD`和`EdgeRDD`，因为它们对接下来的内容非常重要。

在 Spark GraphX 中，顶点具有`Long`类型的唯一标识符，称为`VertexId`。`VertexRDD[VD]`实际上只是`RDD[(VertexId, VD)]`的扩展，但经过优化并具有大量的实用功能列表，我们将详细讨论。因此，简而言之，GraphX 中的顶点是带有标识符和顶点数据的 RDD，这与之前发展的直觉相一致。

为了解释`EdgeRDD`的概念，让我们快速解释一下 GraphX 中的`Edge`是什么。简化形式上，`Edge`由以下签名定义：

```scala
case class Edge[ED] (
  var srcId: VertexId,
  var dstId: VertexId,
  var attr: ED
)
```

因此，边完全由源顶点 ID（称为`srcId`）、目标或目的地顶点 ID（称为`dstId`）和`ED`数据类型的属性对象`attr`确定。与前面的顶点 RDD 类似，我们可以将`EdgeRDD[ED]`理解为`RDD[Edge[ED]]`的扩展。因此，GraphX 中的边由`ED`类型的边的 RDD 给出，这与我们迄今讨论的内容一致。

我们现在知道，从 Spark 2.1 开始，GraphX 中的图形本质上是顶点和边 RDD 的对。这是重要的信息，因为它原则上允许我们将 Spark 核心的 RDD 的全部功能和能力应用到这些图形中。然而，需要警告的是，图形带有许多针对图形处理目的进行优化的功能。每当你发现自己在使用基本的 RDD 功能时，看看是否可以找到特定的图形等效功能，这可能会更高效。

举个具体的例子，让我们使用刚刚学到的知识从头开始构建一个图。我们假设您有一个名为`sc`的 Spark 上下文可用。我们将创建一个人与彼此连接的图，即上一节中*图 3*中的图，即一个带标签的图。在我们刚刚学到的 GraphX 语言中，要创建这样一个图，我们需要顶点和边数据类型都是`String`类型。我们通过使用`parallelize`来创建顶点，如下所示：

```scala
import org.apache.spark.rdd.RDD
val vertices: RDD[(VertexId, String)] = sc.parallelize(
  Array((1L, "Anne"),
    (2L, "Bernie"),
    (3L, "Chris"),
    (4L, "Don"),
    (5L, "Edgar")))
```

同样，我们可以创建边；请注意以下定义中`Edge`的使用：

```scala
val edges: RDD[Edge[String]] = sc.parallelize(
  Array(Edge(1L, 2L, "likes"),
    Edge(2L, 3L, "trusts"),
    Edge(3L, 4L, "believes"),
    Edge(4L, 5L, "worships"),
    Edge(1L, 3L, "loves"),
    Edge(4L, 1L, "dislikes")))
```

拥有这两个准备好的 RDD 已经足以创建`Graph`，就像以下一行一样简单：

```scala
val friendGraph: Graph[String, String] = Graph(vertices, edges)
```

请注意，我们明确地为所有变量写出类型，这只是为了清晰。我们可以把它们留空，依赖 Scala 编译器为我们推断类型。此外，如前面的签名所示，我们可以通过`friendGraph.vertices`访问顶点，通过`friendGraph.edges`访问边。为了初步了解可能的操作，我们现在可以收集所有顶点并打印它们如下：

```scala
friendGraph.vertices.collect.foreach(println)
```

以下是输出：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00162.jpeg)

请注意，这不使用任何 GraphX 特定的功能，只是使用我们已经从 RDD 中知道的知识。举个例子，让我们计算所有源 ID 大于目标 ID 的边的数量。可以这样做：

```scala
friendGraph.edges.map( e => e.srcId > e.dstId ).filter(_ == true).count
```

这给出了预期的答案，即`1`，但有一个缺点。一旦我们在图上调用`.edges`，我们就完全失去了之前拥有的所有图结构。假设我们想要进一步处理具有转换边的图，这不是正确的方法。在这种情况下，最好使用内置的`Graph`功能，比如以下的`mapEdges`方法：

```scala
val mappedEdgeGraph: Graph[String, Boolean] = 
  friendGraph.mapEdges( e => e.srcId > e.dstId )
```

请注意，这种情况下的返回值仍然是一个图，但是边的数据类型现在是`Boolean`，正如预期的那样。我们将在接下来看到更多关于图处理可能性的例子。看完这个例子后，让我们退一步，讨论为什么 Spark GraphX 实现图的方式。一个原因是我们可以有效地利用*数据并行性*和*图并行性*。在前几章中，我们已经了解到 Spark 中的 RDD 和数据框利用数据并行性，通过在每个节点上将数据分布到分区中并将数据保存在内存中。因此，如果我们只关心顶点或边本身，而不想研究它们的关系，那么使用顶点和边 RDD 将非常高效。

相比之下，通过图并行性，我们指的是相对于图的概念进行并行操作。例如，图并行任务将是对每个顶点的所有入边的权重进行求和。要执行此任务，我们需要处理顶点和边数据，这涉及多个 RDD。要高效地执行此操作，需要合适的内部表示。GraphX 试图在这两种范式之间取得平衡，而其他一些替代程序则没有提供这种平衡。

# 图属性和操作

看完另一个人工例子后，让我们转而看一个更有趣的例子，用它来研究我们在上一节中学习的一些核心属性。本章中我们将考虑的数据可以在[`networkrepository.com/`](http://networkrepository.com/)找到，这是一个拥有大量有趣数据的开放网络数据存储库。首先，我们将加载从 Twitter 获取的一个相对较小的数据集，可以从[`networkrepository.com/rt-occupywallstnyc.php`](http://networkrepository.com/rt-occupywallstnyc.php)下载。下载此页面上提供的 zip 文件，即存储 rt_occupywallstnyc.zip 并解压以访问文件 rt_occupywallstnyc.edges。该文件以逗号分隔的 CSV 格式。每一行代表了有关纽约市占领华尔街运动的推文的转发。前两列显示了 Twitter 用户 ID，第三列表示转发的 ID；也就是说，第二列中的用户转发了第一列中相应用户的推文。

前十个项目如下所示：

```scala
3212,221,1347929725
3212,3301,1347923714
3212,1801,1347714310
3212,1491,1347924000
3212,1483,1347923691
3212,1872,1347939690
1486,1783,1346181381
2382,3350,1346675417
2382,1783,1342925318
2159,349,1347911999
```

例如，我们可以看到用户 3,212 的推文至少被转发了六次，但由于我们不知道文件是否以任何方式排序，并且其中包含大约 3.6k 个顶点，我们应该利用 GraphX 来为我们回答这样的问题。

要构建一个图，我们将首先从该文件创建一个边的 RDD，即`RDD[Edge[Long]]`，使用基本的 Spark 功能：

```scala
val edges: RDD[Edge[Long]] =
  sc.textFile("./rt_occupywallstnyc.edges").map { line =>
    val fields = line.split(",")
    Edge(fields(0).toLong, fields(1).toLong, fields(2).toLong)
  }
```

请记住，GraphX 中的 ID 是`Long`类型，这就是为什么在加载文本文件并通过逗号拆分每一行后，我们将所有值转换为`Long`的原因；也就是说，在这种情况下，我们的边数据类型是`Long`。在这里，我们假设所讨论的文件位于我们启动`spark-shell`的同一文件夹中；如果需要，可以根据自己的需求进行调整。有了这样的边 RDD，我们现在可以使用`Graph`伴生对象的`fromEdges`方法，如下所示：

```scala
val rtGraph: Graph[String, Long] = Graph.fromEdges(edges, defaultValue =  "")
```

也许不足为奇的是，我们需要为这个方法提供`edges`，但`defaultValue`关键字值得一些解释。请注意，到目前为止，我们只知道边，虽然顶点 ID 隐式地作为边的源和目标可用，但我们仍然没有确定任何 GraphX 图所需的顶点数据类型`VD`。`defaultValue`允许您创建一个默认的顶点数据值，带有一个类型。在我们的情况下，我们选择了一个空字符串，这解释了`rtGraph`的签名。

加载了这个第一个真实世界的数据图后，让我们检查一些基本属性。使用之前的符号，图的*顺序*和*度*可以计算如下：

```scala
val order = rtGraph.numVertices
val degree = rtGraph.numEdges
```

前面的代码将分别产生 3,609 和 3,936。至于各个顶点的度，GraphX 提供了 Graphs 上的`degrees`方法，返回整数顶点数据类型的图，用于存储度数。让我们计算一下我们的转发图的平均度：

```scala
val avgDegree = rtGraph.degrees.map(_._2).reduce(_ + _) / order.toDouble
```

这个操作的结果应该大约是`2.18`，这意味着每个顶点平均连接了大约两条边。这个简洁操作中使用的符号可能看起来有点密集，主要是因为使用了许多通配符，所以让我们来详细解释一下。为了解释这一点，我们首先调用 degrees，如前所述。然后，我们通过映射到对中的第二个项目来提取度数；也就是说，我们忘记了顶点 ID。这给我们留下了一个整数值的 RDD，我们可以通过加法减少来总结。最后一步是将`order.toDouble`转换为确保我们得到浮点除法，然后除以这个总数。下一个代码清单显示了相同的四个步骤以更详细的方式展开：

```scala
val vertexDegrees: VertexRDD[Int] = rtGraph.degrees
val degrees: RDD[Int] = vertexDegrees.map(v => v._2)
val sumDegrees: Int = degrees.reduce((v1, v2) => v1 + v2 )
val avgDegreeAlt = sumDegrees / order.toDouble
```

接下来，我们通过简单地调用`inDegrees`和`outDegrees`来计算这个有向图的入度和出度。为了使事情更有趣，让我们计算图中所有顶点的最大入度，以及最小出度，并返回其 ID。我们首先解决最大入度：

```scala
val maxInDegree: (Long, Int) = rtGraph.inDegrees.reduce(
  (v1,v2) => if (v1._2 > v2._2) v1 else v2
)
```

进行这个计算，你会看到 ID 为`1783`的顶点的入度为 401，这意味着具有这个 ID 的用户转发了 401 条不同的推文。因此，一个有趣的后续问题是，“这个用户转发了多少不同用户的推文？”同样，我们可以通过计算所有边中这个目标的不同来源来非常快速地回答这个问题：

```scala
rtGraph.edges.filter(e => e.dstId == 1783).map(_.srcId).distinct()
```

执行这个命令应该会提示 34，所以平均而言，用户`1783`从任何给定的用户那里转发了大约 12 条推文。这反过来意味着我们找到了一个有意义的多图的例子--在这个图中有许多不同连接的顶点对。现在回答最小出度的问题就很简单了：

```scala
val minOutDegree: (Long, Int) = rtGraph.outDegrees.reduce(
  (v1,v2) => if (v1._2 < v2._2) v1 else v2
)
```

在这种情况下，答案是`1`，这意味着在这个数据集中，每条推文至少被转发了一次。

请记住，属性图的*三元组*由边及其数据以及连接顶点及其各自的数据组成。在 Spark GraphX 中，这个概念是在一个叫做`EdgeTriplet`的类中实现的，我们可以通过`attr`检索边数据，通过`srcAttr`、`dstAttr`、`srcId`和`dstId`自然地检索顶点数据和 ID。为了获得我们的转发图的三元组，我们可以简单地调用以下内容：

```scala
val triplets: RDD[EdgeTriplet[String, Long]] = rtGraph.triplets
```

三元组通常很实用，因为我们可以直接检索相应的边和顶点数据，否则这些数据将分别存在于图中的不同 RDD 中。例如，我们可以通过执行以下操作，快速将生成的三元组转换为每次转发的可读数据：

```scala
val tweetStrings = triplets.map(
  t => t.dstId + " retweeted " + t.attr + " from " + t.srcId
)
tweetStrings.take(5)
```

前面的代码产生了以下输出：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00163.jpeg)

当我们之前讨论`friendGraph`示例时，我们注意到`mapEdges`在某些方面优于先调用`edges`然后再`map`它们。对于顶点和三元组也是如此。假设我们想要将图的顶点数据简单地更改为顶点 ID 而不是先前选择的默认值。这可以通过以下方式最快、最有效地实现：

```scala
val vertexIdData: Graph[Long, Long] = rtGraph.mapVertices( (id, _) => id)
```

同样地，我们可以直接从我们的初始图开始，而不是首先检索三元组，然后使用`mapTriplets`直接转换三元组，返回一个具有修改后的边数据的图形对象。为了实现与前面的`tweetStrings`相同的效果，但保持图形结构不变，我们可以运行以下操作：

```scala
val mappedTripletsGraph = rtGraph.mapTriplets(
  t => t.dstId + " retweeted " + t.attr + " from " + t.srcId
)
```

作为基本图处理功能的最后一个示例，我们现在将看一下给定图的子图以及如何将图形彼此连接。考虑提取我们的图中至少被转发 10 次的所有 Twitter 用户的信息的任务。我们已经看到如何从`rtGraph.outDegrees`中获取出度。为了使这些信息在我们的原始图中可访问，我们需要将这些信息连接到原始图中。为此，GraphX 提供了`outerJoinVertices`的功能。为了这样做，我们需要提供一个顶点数据类型`U`的`VertexRDD`，以及一个确定如何聚合顶点数据的函数。如果我们称要加入的 RDD 为`other`，那么在纸上看起来如下：

```scala
def outerJoinVerticesU, VD2])
  (mapFunc: (VertexId, VD, Option[U]) => VD2): Graph[VD2, ED]
```

请注意，由于我们进行了外连接，原始图中的所有 ID 可能在`other`中没有相应的值，这就是为什么我们在相应的映射函数中看到`Option`类型的原因。对于我们手头的具体例子，这样做的工作方式如下：

```scala
val outDegreeGraph: Graph[Long, Long] =
  rtGraph.outerJoinVerticesInt, Long(
    mapFunc = (id, origData, outDeg) => outDeg.getOrElse(0).toLong
  )
```

我们将我们的原始图与出度`VertexRDD`连接，并将映射函数简单地丢弃原始顶点数据并替换为出度。如果没有出度可用，我们可以使用`getOrElse`将其设置为`0`来解决`Option`。

接下来，我们想要检索该图的子图，其中每个顶点至少有 10 次转发。图的子图由原始顶点和边的子集组成。形式上，我们定义子图为对边、顶点或两者的*谓词*的结果。我们指的是在顶点或边上评估的表达式，返回 true 或 false。图上子图方法的签名定义如下：

```scala
def subgraph(
  epred: EdgeTriplet[VD,ED] => Boolean = (x => true),
  vpred: (VertexId, VD) => Boolean = ((v, d) => true)): Graph[VD, ED]
```

请注意，由于提供了默认函数，我们可以选择只提供`vpred`或`epred`中的一个。在我们具体的例子中，我们想要限制至少有`10`度的顶点，可以按照以下方式进行：

```scala
val tenOrMoreRetweets = outDegreeGraph.subgraph(
  vpred = (id, deg) => deg >= 10
)
tenOrMoreRetweets.vertices.count
tenOrMoreRetweets.edges.count
```

生成的图仅有`10`个顶点和`5`条边，但有趣的是这些有影响力的人似乎彼此之间的连接大致与平均水平相当。

为了结束这一部分，一个有趣的技术是*掩码*。假设我们现在想知道具有少于 10 次转发的顶点的子图，这与前面的`tenOrMoreRetweets`相反。当然，这可以通过子图定义来实现，但我们也可以通过以下方式掩盖原始图形`tenOrMoreRetweets`。

```scala
val lessThanTenRetweets = rtGraph.mask(tenOrMoreRetweets)
```

如果我们愿意，我们可以通过将`tenOrMoreRetweets`与`lessThanTenRetweets`连接来重建`rtGraph`。

# 构建和加载图

在上一节中，我们在图分析方面取得了很大进展，并讨论了一个有趣的转发图。在我们深入研究更复杂的操作之前，让我们退一步考虑使用 GraphX 构建图的其他选项。完成了这个插曲后，我们将快速查看可视化工具，然后转向更复杂的应用。

实际上，我们已经看到了创建 GraphX 图的两种方法，一种是显式地构建顶点和边 RDD，然后从中构建图；另一种是使用`Graph.fromEdges`。另一个非常方便的可能性是加载所谓的*边列表文件*。这种格式的一个例子如下：

```scala
1 3
5 3
4 2
3 2
1 5
```

因此，边列表文件是一个文本文件，每行有一对 ID，用空格分隔。假设我们将前面的数据存储为`edge_list.txt`在当前工作目录中，我们可以使用`GraphLoader`接口从中一行加载一个图对象：

```scala
import org.apache.spark.graphx.GraphLoader
val edgeListGraph = GraphLoader.edgeListFile(sc, "./edge_list.txt")
```

这代表了一个非常方便的入口点，因为我们有以正确格式提供的数据。加载边列表文件后，还必须将其他顶点和边数据连接到生成的图中。从前面的数据构建图的另一种类似方法是使用`Graph`对象提供的`fromEdgeTuples`方法，可以像下面的代码片段中所示那样使用：

```scala
val rawEdges: RDD[(VertexId, VertexId)] = sc.textFile("./edge_list.txt").map { 
  line =>
    val field = line.split(" ")
    (field(0).toLong, field(1).toLong)
}
val edgeTupleGraph = Graph.fromEdgeTuples(
  rawEdges=rawEdges, defaultValue="")
```

与之前的构建不同之处在于，我们创建了一个原始边 RDD，其中包含顶点 ID 对，连同顶点数据的默认值，一起输入到图的构建中。

通过最后一个例子，我们基本上已经看到了 GraphX 目前支持的从给定数据加载图的每一种方式。然而，还有*生成*随机和确定性图的可能性，这对于测试、快速检查和演示非常有帮助。为此，我们导入以下类：

```scala
import org.apache.spark.graphx.util.GraphGenerators
```

这个类有很多功能可供使用。两种确定性图构建方法有助于构建*星形*和*网格*图。星形图由一个中心顶点和几个顶点组成，这些顶点只通过一条边连接到中心顶点。以下是如何创建一个有十个顶点连接到中心顶点的星形图：

```scala
val starGraph = GraphGenerators.starGraph(sc, 11)
```

以下图片是星形图的图形表示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00164.jpeg)

图 10：一个星形图，有十个顶点围绕着一个中心顶点。

图的另一种确定性构建方法是构建网格，意味着顶点被组织成一个矩阵，每个顶点都与其直接邻居在垂直和水平方向上连接。在一个有*n*行和*m*列的网格图中，有精确地*n(m-1) + m(n-1)*条边--第一项是所有垂直连接，第二项是所有水平网格连接。以下是如何在 GraphX 中构建一个有 40 条边的`5`乘`5`网格：

```scala
val gridGraph = GraphGenerators.gridGraph(sc, 5, 5)
```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00165.jpeg)

图 11：一个由 12 个顶点组成的 3x3 的二次网格图。

就随机图而言，我们将介绍一种创建方法，它在结构上大致反映了许多现实世界的图，即*对数正态图*。现实生活中许多结构都遵循*幂律*，其中一个实体的度量由另一个的幂给出。一个具体的例子是帕累托原则，通常称为 80/20 原则，它意味着 80%的财富由 20%的人拥有，也就是说，大部分财富归属于少数人。这个原则的一个变体，称为*齐夫定律*，适用于我们的情景，即少数顶点具有非常高的度，而大多数顶点连接很少。在社交图的背景下，很少有人倾向于拥有很多粉丝，而大多数人拥有很少的粉丝。这导致了顶点度数的分布遵循*对数正态分布*。*图 10*中的星形图是这种行为的一个极端变体，其中所有的边都集中在一个顶点周围。

在 GraphX 中创建一个具有 20 个顶点的对数正态图很简单，如下所示：

```scala
val logNormalGraph  = GraphGenerators.logNormalGraph(
  sc, numVertices = 20, mu=1, sigma = 3
)
```

在上述代码片段中，我们还对每个顶点施加了一个平均出度和三个标准差。让我们看看是否可以确认顶点出度的对数正态分布：

```scala
logNormalGraph.outDegrees.map(_._2).collect().sorted
```

这将产生一个 Scala 数组，应该如下所示。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00166.jpeg)

请注意，由于图是随机生成的，您可能会得到不同的结果。接下来，让我们看看如何可视化我们迄今为止构建的一些图。

# 使用 Gephi 可视化图形

GraphX 没有内置的图形可视化工具，因此为了处理可视化大规模图形，我们必须考虑其他选项。有许多通用的可视化库，以及一些专门的图形可视化工具。在本章中，我们选择*Gephi*基本上有两个原因：

+   这是一个免费的开源工具，适用于所有主要平台

+   我们可以利用一个简单的交换格式 GEXF 来保存 GraphX 图，并可以将它们加载到 Gephi GUI 中，以指定可视化。

虽然第一个观点应该被普遍认为是一个优点，但并不是每个人都喜欢 GUI，对于大多数开发人员来说，以编程方式定义可视化更符合精神。请注意，事实上，使用 Gephi 也是可能的，但稍后再详细讨论。我们选择上述方法的原因是为了使本书内容自包含，而关于 Spark 的编码部分仅使用 Gephi 提供的强大可视化。

# Gephi

要开始，请从[`gephi.org/`](https://gephi.org/)下载 Gephi 并在本地安装在您的机器上。在撰写本书时，稳定版本是 0.9.1，我们将在整个过程中使用。打开 Gephi 应用程序时，您将收到欢迎消息，并可以选择一些示例来探索。我们将使用`Les Miserables.gexf`来熟悉工具。我们将在稍后更详细地讨论 GEXF 文件格式；现在，让我们专注于应用程序。这个例子的基础图数据包括代表作品《悲惨世界》中的角色的顶点，以及表示角色关联的边，*加权*表示连接的重要性评估。

Gephi 是一个非常丰富的工具，我们只能在这里讨论一些基础知识。一旦您打开前面的文件，您应该已经看到示例图的预览。Gephi 有三个主要视图：

+   **概述**：这是我们可以操纵图的所有视觉属性并获得预览的视图。对于我们的目的，这是最重要的视图，我们将更详细地讨论它。

+   **数据实验室**：此视图以表格格式显示原始图形数据，分为*节点*和*边*，也可以根据需要进行扩展和修改。

+   **预览**：预览视图用于查看结果，即图形可视化，它也可以导出为各种格式，如 SVG、PDF 和 PNG。

如果尚未激活，请选择概述以继续。在应用程序的主菜单中，可以选择各种选项卡。确保打开图形、预览设置、外观、布局和统计，如下图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00167.jpeg)

图 12：Gephi 的三个主要视图和概述视图中使用的基本选项卡

Graphtab 可以用于最后的润色和视觉检查，您应该已经看到了样本*悲惨世界*图的视觉表示。例如，窗口左侧的*矩形选择*允许您通过选择顶点来选择子图，而使用*拖动*，您可以根据自己的审美需求移动顶点。

在*预览设置*中，可能是我们最感兴趣的选项卡，我们可以配置图形的大部分视觉方面。*预设*允许您更改图形的一般样式，例如曲线与直线边。我们将保持*默认*设置不变。您可能已经注意到，图形预览没有顶点或边的标签，因此无法看到每个顶点代表什么。我们可以通过在*节点标签*类别中选择*显示标签*，然后取消选择*比例大小*复选框来更改这一点，以便所有标签具有相同的大小。如果现在转到*预览*视图，您看到的图形应该如下图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00168.jpeg)

图 13：悲惨世界示例图，经过 Gephi 轻微修改。顶点是作品中的角色，边表示连接的重要性，通过边的粗细表示。顶点大小由度确定，顶点还根据颜色分组以表示家族成员资格，后者在打印中看不到。

请注意，前面的图形具有我们没有专门设置的视觉属性。顶点大小与顶点度成比例，边的粗细由权重决定，图形的颜色编码显示了个体角色所属的家族。为了了解这是如何完成的，我们接下来讨论*外观*选项卡，它还区分了*节点*和*边*。在该选项卡的右上角，有四个选项可供选择，我们选择*大小*，它用一个显示几个圆圈的图标表示。这样做后，我们可以首先在左上角选择*节点*，然后在其下方选择*排名*。在下拉菜单中，我们可以选择一个属性来确定节点的大小，前面的例子中是*度*。同样，前面讨论过的另外两个属性也可以配置。

继续，我们讨论的下一个选项卡是*布局*，在这里我们可以选择自动排列图形的方法。有趣的布局包括两种可用的*力引导*方案，它们模拟顶点相互吸引和排斥的属性。在*图 13*中，没有选择布局，但探索一下可能会很有趣。无论您选择哪种布局，都可以通过点击*运行*按钮来激活它们。

使用*统计*选项卡，我们可以在 Gephi 内探索图形属性，例如连通分量和 PageRank。由于我们将讨论如何在 GraphX 中执行此操作，而且 GraphX 的性能也更高，因此我们将就此结束，尽管鼓励您在此选项卡中尝试功能，因为它可以帮助快速建立直觉。

在我们根据需要配置属性后，我们现在可以切换到*预览*视图，看看生成的图形是否符合我们的预期。假设一切顺利，*预览设置*选项卡的 SVG/PDF/PNG 按钮可以用来导出我们的最终信息图，以供在您的产品中使用，无论是报告、进一步分析还是其他用途。

# 创建 GEXF 文件从 GraphX 图

要将 Gephi 的图形可视化能力与 Spark GraphX 图形连接起来，我们需要解决两者之间的通信方式。这样做的标准候选者是 Gephi 的**图形交换 XML 格式**（**GEXF**），其描述可以在[`gephi.org/gexf/format/`](https://gephi.org/gexf/format/)找到。在以下代码清单中显示了如何以这种格式描述图形的一个非常简单的示例：

```scala
<?xml version="1.0" encoding="UTF-8"?>
<gexf  version="1.2">
    <meta lastmodifieddate="2009-03-20">
        <creator>Gexf.net</creator>
        <description>A hello world! file</description>
    </meta>
    <graph mode="static" defaultedgetype="directed">
        <nodes>
            <node id="0" label="Hello" />
            <node id="1" label="Word" />
        </nodes>
        <edges>
            <edge id="0" source="0" target="1" />
        </edges>
    </graph>
</gexf>
```

除了 XML 的头部和元数据之外，图形编码本身是不言自明的。值得知道的是，前面的 XML 只是图形描述所需的最低限度，实际上，GEXF 还可以用于编码其他属性，例如边的权重或甚至 Gephi 自动捕捉的视觉属性。

为了连接 GraphX，让我们编写一个小的辅助函数，它接受一个`Graph`版本并返回前面 XML 格式的`String`版本：

```scala
def toGexfVD, ED: String = {
  val header =
    """<?xml version="1.0" encoding="UTF-8"?>
      |<gexf  version="1.2">
      |  <meta>
      |    <description>A gephi graph in GEXF format</description>
      |  </meta>
      |    <graph mode="static" defaultedgetype="directed">
    """.stripMargin

  val vertices = "<nodes>\n" + g.vertices.map(
    v => s"""<node id=\"${v._1}\" label=\"${v._2}\"/>\n"""
  ).collect.mkString + "</nodes>\n"

  val edges = "<edges>\n" + g.edges.map(
    e => s"""<edge source=\"${e.srcId}\" target=\"${e.dstId}\" label=\"${e.attr}\"/>\n"""
  ).collect.mkString + "</edges>\n"

  val footer = "</graph>\n</gexf>"

  header + vertices + edges + footer
}
```

虽然代码乍一看可能有点神秘，但实际上发生的事情很少。我们定义了 XML 的头部和尾部。我们需要将边和顶点属性映射到`<nodes>`和`<edges>` XML 标签。为此，我们使用 Scala 方便的`${}`符号直接将变量注入到字符串中。改变一下，让我们在一个完整的 Scala 应用程序中使用这个`toGexf`函数，该应用程序使用了我们之前的简单朋友图。请注意，为了使其工作，假设`toGexf`对`GephiApp`可用。因此，要么将其存储在相同的对象中，要么存储在另一个文件中以从那里导入。如果您想继续使用 spark-shell，只需粘贴导入和主方法的主体，不包括创建`conf`和`sc`，应该可以正常工作：

```scala
import java.io.PrintWriter
import org.apache.spark._
import org.apache.spark.graphx._
import org.apache.spark.rdd.RDD

object GephiApp {
  def main(args: Array[String]) {

    val conf = new SparkConf()
      .setAppName("Gephi Test Writer")
      .setMaster("local[4]")
    val sc = new SparkContext(conf)

    val vertices: RDD[(VertexId, String)] = sc.parallelize(
      Array((1L, "Anne"),
        (2L, "Bernie"),
        (3L, "Chris"),
        (4L, "Don"),
        (5L, "Edgar")))

    val edges: RDD[Edge[String]] = sc.parallelize(
      Array(Edge(1L, 2L, "likes"),
        Edge(2L, 3L, "trusts"),
        Edge(3L, 4L, "believes"),
        Edge(4L, 5L, "worships"),
        Edge(1L, 3L, "loves"),
        Edge(4L, 1L, "dislikes")))

    val graph: Graph[String, String] = Graph(vertices, edges)

    val pw = new PrintWriter("./graph.gexf")
    pw.write(toGexf(graph))
    pw.close()
  }
}
```

这个应用程序将我们的朋友图存储为`graph.gexf`，我们可以将其导入到 Gephi 中使用。要这样做，转到“文件”，然后点击“打开”以选择此文件并导入图形。通过使用之前描述的选项卡和方法调整视觉属性，以下图表显示了此过程的结果：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00169.jpeg)

图 14：使用 Gephi 显示的我们的示例朋友图

正如前面所述，确实可以使用*Gephi Toolkit*以编程方式定义视觉属性，这是一个可以导入到项目中的 Java 库。还有其他语言包装器可用，但这是支持的库，可作为单个 JAR 文件使用。讨论工具包远远超出了本书的范围，但如果您感兴趣，可以参考[`gephi.org/toolkit/`](https://gephi.org/toolkit/)，这是一个很好的入门点。

# 高级图处理

在快速介绍了图生成和可视化之后，让我们转向更具挑战性的应用程序和更高级的图分析技术。总结一下，到目前为止，我们在图处理方面所做的只是使用 GraphX 图的基本属性，以及一些转换，包括`mapVertices`、`mapEdges`和`mapTriplets`。正如我们所见，这些技术已经非常有用，但单独使用还不足以实现图并行算法。为此，GraphX 图有两个强大的候选者，我们将在下一节讨论。包括三角形计数、PageRank 等大多数内置的 GraphX 算法都是使用其中一个或另一个实现的。

# 聚合消息

首先，我们讨论 GraphX 图带有的`aggregateMessages`方法。基本思想是在整个图中并行沿着边传递消息，合适地聚合这些消息并将结果存储以供进一步处理。让我们更仔细地看一下`aggregateMessages`是如何定义的：

```scala
def aggregateMessagesMsg: ClassTag => Msg,
  tripletFields: TripletFields = TripletFields.All
): VertexRDD[Msg]
```

如您所见，要实现`aggregateMessages`算法，我们需要指定消息类型`Msg`并提供三个函数，我们将在下面解释。您可能会注意到我们之前没有遇到的两种额外类型，即`EdgeContext`和`TripletFields`。简而言之，边上下文是我们已经看到的`EdgeTriplets`的扩展，即边加上所有关于相邻顶点的信息，唯一的区别是我们还可以额外发送信息到源顶点和目标顶点，定义如下：

```scala
def sendToSrc(msg: A): Unit
def sendToDst(msg: A): Unit
```

`TripletFields`允许限制计算中使用的`EdgeContext`字段，默认为所有可用字段。实际上，在接下来的内容中，我们将简单地使用`tripletFields`的默认值，并专注于`sendMsg`和`mergeMsg`。如本主题的介绍所示，`sendMsg`用于沿着边传递消息，`mergeMsg`对它们进行聚合，并将此操作的结果存储在`Msg`类型的顶点 RDD 中。为了使这更具体化，考虑以下示例，这是一种计算先前的小伙伴图中所有顶点的入度的替代方法：

```scala
val inDegVertexRdd: VertexRDD[Int] = friendGraph.aggregateMessagesInt,
  mergeMsg = (msg1, msg2) => msg1+msg2
)
assert(inDegVertexRdd.collect.deep == friendGraph.inDegrees.collect.deep)
```

在这个例子中，发送消息是通过使用其`sendToDst`方法从边上下文中定义的，向每个目标顶点发送一个整数消息，即数字 1。这意味着并行地，对于每条边，我们向该边指向的每个顶点发送一个 1。这样，顶点就会收到我们需要合并的消息。这里的`mergeMsg`应该被理解为 RDD 中`reduce`的方式，也就是说，我们指定了如何合并两个消息，并且这个方法被用来将所有消息合并成一个。在这个例子中，我们只是将所有消息求和，这根据定义得到了每个顶点的入度。我们通过断言在主节点上收集到的`inDegVertexRdd`和`friendGraph.inDegrees`的数组的相等性来确认这一点。

请注意，`aggregateMessages`的返回值是顶点 RDD，而不是图。因此，使用这种机制进行迭代，我们需要在每次迭代中生成一个新的图对象，这并不理想。由于 Spark 在迭代算法方面特别强大，因为它可以将分区数据保存在内存中，而且许多有趣的图算法实际上都是迭代的，接下来我们将讨论略微复杂但非常强大的 Pregel API。

# Pregel

Pregel 是 Google 内部开发的系统，其伴随论文非常易于访问，并可在[`www.dcs.bbk.ac.uk/~dell/teaching/cc/paper/sigmod10/p135-malewicz.pdf`](http://www.dcs.bbk.ac.uk/~dell/teaching/cc/paper/sigmod10/p135-malewicz.pdf)上下载。它代表了一种高效的迭代图并行计算模型，允许实现大量的图算法。GraphX 对 Pregel 的实现与前述论文略有不同，但我们无法详细讨论这一点。

在口味上，GraphX 的`Pregel`实现与`aggregateMessages`非常接近，但有一些关键的区别。两种方法共享的特征是发送和合并消息机制。除此之外，使用 Pregel，我们可以定义一个所谓的*顶点程序*`vprog`，在发送之前执行以转换顶点数据。此外，我们在每个顶点上都有一个共享的初始消息，并且可以指定要执行*vprog-send-merge*循环的迭代次数，也就是说，迭代是规范的一部分。

Pregel 实现的`apply`方法是草图。请注意，它接受两组输入，即由图本身、初始消息、要执行的最大迭代次数和名为`activeDirection`的字段组成的四元组。最后一个参数值得更多关注。我们还没有讨论的 Pregel 规范的一个细节是，*我们只从在上一次迭代中收到消息的顶点发送新消息*。活动方向默认为`Either`，但也可以是`In`或`Out`。这种行为自然地让算法在许多情况下收敛，并且也解释了为什么第三个参数被称为`maxIterations` - 我们可能会比指定的迭代次数提前停止：

```scala
object Pregel {
  def apply[VD: ClassTag, ED: ClassTag, A: ClassTag]
    (graph: Graph[VD, ED],
     initialMsg: A,
     maxIterations: Int = Int.MaxValue,
     activeDirection: EdgeDirection = EdgeDirection.Either)
    (vprog: (VertexId, VD, A) => VD,
     sendMsg: EdgeTriplet[VD, ED] => Iterator[(VertexId, A)],
     mergeMsg: (A, A) => A)
  : Graph[VD, ED]
}
```

Pregel 的第二组参数是我们已经草拟的三元组，即顶点程序，以及发送和合并消息函数。与以前的唯一值得注意的区别是`sendMsg`的签名，它返回一个*顶点 ID 和消息对的迭代器*。这对我们来说没有太大变化，但有趣的是，在 Spark 1.6 之前，`aggregateMessage`中`sendMsg`的签名一直是这样的迭代器，并且在 Spark 2.0 的更新中已更改为我们之前讨论的内容。很可能，Pregel 的签名也会相应地进行更改，但截至 2.1.1，它仍然保持原样。

为了说明 Pregel API 的可能性，让我们草拟一个计算连接组件的算法的实现。这是对 GraphX 中当前可用的实现的轻微修改。我们定义了`ConnectedComponents`对象，其中有一个名为`run`的方法，该方法接受任何图和最大迭代次数。算法的核心思想很容易解释。对于每条边，每当其源 ID 小于其目标 ID 时，将源 ID 发送到目标 ID，反之亦然。为了聚合这些消息，只需取所有广播值的最小值，并迭代此过程足够长，以便它耗尽更新。在这一点上，与另一个顶点连接的每个顶点都具有相同的 ID 作为顶点数据，即原始图中可用的最小 ID：

```scala
import org.apache.spark.graphx._
import scala.reflect.ClassTag

object ConnectedComponents extends Serializable {

  def runVD: ClassTag, ED: ClassTag
  : Graph[VertexId, ED] = {

    val idGraph: Graph[VertexId, ED] = graph.mapVertices((id, _) => id)

    def vprog(id: VertexId, attr: VertexId, msg: VertexId): VertexId = {
      math.min(attr, msg)
    }

    def sendMsg(edge: EdgeTriplet[VertexId, ED]): Iterator[(VertexId, VertexId)] = {
      if (edge.srcAttr < edge.dstAttr) {
        Iterator((edge.dstId, edge.srcAttr))
      } else if (edge.srcAttr > edge.dstAttr) {
        Iterator((edge.srcId, edge.dstAttr))
      } else {
        Iterator.empty
      }
    }

    def mergeMsg(v1: VertexId, v2: VertexId): VertexId = math.min(v1, v2)

    Pregel(
      graph = idGraph,
      initialMsg = Long.MaxValue,
      maxIterations,
      EdgeDirection.Either)(
      vprog,
      sendMsg,
      mergeMsg)
  }
}
```

逐步进行，算法的步骤如下。首先，我们通过定义`idGraph`来忘记所有先前可用的顶点数据。接下来，我们定义顶点程序以发出当前顶点数据属性和当前消息的最小值。这样我们就可以将最小顶点 ID 存储为顶点数据。`sendMsg`方法将较小的 ID 传播到源或目标的每条边上，如前所述，`mergeMsg`再次只是取 ID 的最小值。定义了这三个关键方法后，我们可以简单地在指定的`maxIterations`上运行`idGraph`上的`Pregel`。请注意，我们不关心消息流向的方向，因此我们使用`EdgeDirection.Either`。此外，我们从最大可用的 Long 值作为我们的初始消息开始，这是有效的，因为我们在顶点 ID 上取最小值。

定义了这一点使我们能够在先前的转发图`rtGraph`上找到连接的组件，如下所示，选择五次迭代作为最大值：

```scala
val ccGraph = ConnectedComponents.run(rtGraph, 5)
cc.vertices.map(_._2).distinct.count
```

对结果图的不同顶点数据项进行计数，可以得到连接组件的数量（在这种情况下只有一个组件），也就是说，如果忘记方向性，数据集中的所有推文都是连接的。有趣的是，我们实际上需要五次迭代才能使算法收敛。使用更少的迭代次数运行它，即 1、2、3 或 4，会得到 1771、172、56 和 4 个连接组件。由于至少有一个连接组件，我们知道进一步增加迭代次数不会改变结果。然而，一般情况下，我们宁愿不指定迭代次数，除非时间或计算能力成为问题。通过将前面的 run 方法包装如下，我们可以在图上运行此算法，而无需显式提供迭代次数：

```scala
def runVD: ClassTag, ED: ClassTag
: Graph[VertexId, ED] = {
  run(graph, Int.MaxValue)
}
```

只需将此作为`ConnectedComponents`对象的附加方法。对于转发图，我们现在可以简单地编写。看过`aggregateMessages`和 Pregel 后，读者现在应该足够有能力开发自己的图算法：

```scala
val ccGraph = ConnectedComponents.run(rtGraph)
```

# GraphFrames

到目前为止，为了计算给定图上的任何有趣的指标，我们必须使用图的计算模型，这是我们从 RDDs 所知的扩展。考虑到 Spark 的 DataFrame 或 Dataset 概念，读者可能会想知道是否有可能使用类似 SQL 的语言来对图进行分析运行查询。查询语言通常提供了一种快速获取结果的便捷方式。

GraphFrames 确实可以做到这一点。该库由 Databricks 开发，并作为 GraphX 图的自然扩展到 Spark DataFrames。不幸的是，GraphFrames 不是 Spark GraphX 的一部分，而是作为 Spark 软件包提供的。要在启动 spark-submit 时加载 GraphFrames，只需运行

`spark-shell --packages graphframes:graphframes:0.5.0-spark2.1-s_2.11`

并适当调整您首选的 Spark 和 Scala 版本的先前版本号。将 GraphX 图转换为`GraphFrame`，反之亦然，就像变得那么容易；在接下来，我们将我们之前的朋友图转换为`GraphFrame`，然后再转换回来：

```scala
import org.graphframes._

val friendGraphFrame = GraphFrame.fromGraphX(friendGraph)
val graph = friendGraphFrame.toGraphX
```

如前所述，GraphFrames 的一个附加好处是您可以与它们一起使用 Spark SQL，因为它们是建立在 DataFrame 之上的。这也意味着 GraphFrames 比图快得多，因为 Spark 核心团队通过他们的 catalyst 和 tungsten 框架为 DataFrame 带来了许多速度提升。希望我们在接下来的发布版本中看到 GraphFrames 添加到 Spark GraphX 中。

我们不再看 Spark SQL 示例，因为这应该已经在之前的章节中很熟悉了，我们考虑 GraphFrames 可用的另一种查询语言，它具有非常直观的计算模型。GraphFrames 从图数据库*neo4j*中借用了*Cypher* SQL 方言，可以用于非常表达式的查询。继续使用`friendGraphFrame`，我们可以非常容易地找到所有长度为 2 的路径，这些路径要么以顶点"Chris"结尾，要么首先通过边"trusts"，只需使用一个简洁的命令：

```scala
friendGraphFrame.find("(v1)-[e1]->(v2); (v2)-[e2]->(v3)").filter(
  "e1.attr = 'trusts' OR v3.attr = 'Chris'"
).collect.foreach(println)
```

注意我们可以以一种让您以实际图的方式思考的方式指定图结构，也就是说，我们有两条边*e1*和*e2*，它们通过一个共同的顶点*v2*连接在一起。此操作的结果列在以下屏幕截图中，确实给出了满足前述条件的三条路径：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00170.jpeg)

不幸的是，我们无法在这里更详细地讨论 GraphFrames，但感兴趣的读者可以参考[`graphframes.github.io/`](https://graphframes.github.io/)上的文档获取更多详细信息。相反，我们现在将转向 GraphX 中可用的算法，并将它们应用于大规模的演员数据图。

# 图算法和应用

在这个应用程序部分中，我们将讨论三角形计数、（强）连通组件、PageRank 和 GraphX 中可用的其他算法，我们将从[`networkrepository.com/`](http://networkrepository.com/)加载另一个有趣的图数据集。这次，请从[`networkrepository.com/ca-hollywood-2009.php`](http://networkrepository.com/ca-hollywood-2009.php)下载数据，该数据集包含一个无向图，其顶点表示出现在电影中的演员。文件的每一行包含两个顶点 ID，表示这些演员在一部电影中一起出现。

该数据集包括约 110 万个顶点和 5630 万条边。尽管文件大小即使解压后也不是特别大，但这样大小的图对于图处理引擎来说是一个真正的挑战。由于我们假设您在本地使用 Spark 的独立模式工作，这个图很可能不适合您计算机的内存，并且会导致 Spark 应用程序崩溃。为了防止这种情况发生，让我们稍微限制一下数据，这也给了我们清理文件头的机会。我们假设您已经解压了`ca-hollywood-2009.mtx`并将其存储在当前工作目录中。我们使用 unix 工具*tail*和*head*删除前两行，然后限制到前一百万条边：

`tail -n+3 ca-hollywood-2009.mtx | head -1000000 > ca-hollywood-2009.txt`

如果这些工具对您不可用，任何其他工具都可以，包括手动修改文件。从前面描述的结构中，我们可以简单地使用`edgeListFile`功能将图加载到 Spark 中，并确认它确实有一百万条边：

```scala
val actorGraph = GraphLoader.edgeListFile(sc, "./ca-hollywood-2009.txt")
actorGraph.edges.count()
```

接下来，让我们看看 GraphX 能够如何分析这个图。

# 聚类

给定一个图，一个自然的问题是是否有任何子图与之自然地相连，也就是说，以某种方式对图进行聚类。这个问题可以用许多种方式来解决，其中我们已经自己实现了一种，即通过研究连接的组件。这次我们不使用我们自己的实现，而是使用 GraphX 的内置版本。为此，我们可以直接在图本身上调用`connectedComponents`：

```scala
val actorComponents = actorGraph.connectedComponents().cache 
actorComponents.vertices.map(_._2).distinct().count
```

与我们自己的实现一样，图的顶点数据包含集群 ID，这些 ID 对应于集群中可用的最小顶点 ID。这使我们能够直接计算连接的组件，通过收集不同的集群 ID。我们受限制的集群图的答案是 173。计算组件后，我们缓存图，以便可以进一步用于其他计算。例如，我们可能会询问连接的组件有多大，例如通过计算顶点数量的最大值和最小值来计算。我们可以通过使用集群 ID 作为键，并通过计算每个组的项数来减少每个组来实现这一点：

```scala
val clusterSizes =actorComponents.vertices.map(
  v => (v._2, 1)).reduceByKey(_ + _)
clusterSizes.map(_._2).max
clusterSizes.map(_._2).min
```

结果表明，最大的集群包含了一个庞大的 193,518 名演员，而最小的集群只有三名演员。接下来，让我们忽略这样一个事实，即所讨论的图实际上没有方向性，因为一起出现在电影中是对称的，并且假装边对是有方向性的。我们不必在这里强加任何东西，因为在 Spark GraphX 中，边始终具有源和目标。这使我们也能够研究*强*连接的组件。我们可以像对连接的组件那样调用这个算法，但在这种情况下，我们还必须指定迭代次数。原因是在“追踪”有向边方面，与我们对连接的组件和收敛速度相比，计算要求更高，收敛速度更慢。

让我们只进行一次迭代来进行计算，因为这非常昂贵：

```scala
val strongComponents = actorGraph.stronglyConnectedComponents(numIter = 1)
strongComponents.vertices.map(_._2).distinct().count
```

这个计算可能需要几分钟才能完成。如果您在您的机器上运行甚至这个例子时遇到问题，请考虑进一步限制`actorGraph`。

接下来，让我们为演员图计算三角形，这是另一种对其进行聚类的方法。为此，我们需要稍微准备一下图，也就是说，我们必须*规范化*边并指定*图分区策略*。规范化图意味着摆脱循环和重复边，并确保对于所有边，源 ID 始终小于目标 ID：

```scala
val canonicalGraph = actorGraph.mapEdges(
  e => 1).removeSelfEdges().convertToCanonicalEdges()
```

图分区策略，就像我们已经遇到的 RDD 分区一样，关注的是如何有效地在集群中分发图。当然，有效意味着在很大程度上取决于我们对图的处理方式。粗略地说，有两种基本的分区策略，即*顶点切割*和*边切割*。顶点切割策略意味着通过切割顶点来强制以不相交的方式分割边，也就是说，如果需要，顶点会在分区之间重复。边切割策略则相反，其中顶点在整个集群中是唯一的，但我们可能会复制边。GraphX 有四种基于顶点切割的分区策略。我们不会在这里详细讨论它们，而是只使用`RandomVertexCut`，它对顶点 ID 进行哈希处理，以便使顶点之间的所有同向边位于同一分区。

请注意，当创建图时没有指定分区策略时，图会通过简单地采用已提供用于构建的底层 EdgeRDD 的结构来进行分发。根据您的用例，这可能不是理想的，例如因为边的分区可能非常不平衡。

为了对`canonicalGraph`进行分区并继续进行三角形计数，我们现在使用上述策略对我们的图进行分区，如下所示：

```scala
val partitionedGraph = canonicalGraph.partitionBy(PartitionStrategy.RandomVertexCut)
```

计算三角形在概念上是很简单的。我们首先收集每个顶点的所有相邻顶点，然后计算每条边的这些集合的交集。逻辑是，如果源顶点和目标顶点集合都包含相同的第三个顶点，则这三个顶点形成一个三角形。作为最后一步，我们将*交集集合的计数*发送到源和目标，从而将每个三角形计数两次，然后我们简单地除以二得到每个顶点的三角形计数。现在进行三角形计数实际上就是运行：

```scala
import org.apache.spark.graphx.lib.TriangleCount
val triangles = TriangleCount.runPreCanonicalized(partitionedGraph)
```

事实上，我们可以不需要显式地规范化`actorGraph`，而是可以直接在初始图上直接施加`triangleCount`，也就是通过计算以下内容：

```scala
actorGraph.triangleCount()
```

同样，我们也可以导入`TriangleCount`并在我们的 actor 图上调用它，如下所示：

```scala
import org.apache.spark.graphx.lib.TriangleCount
TriangleCount.run(actorGraph)
```

然而，需要注意的是，这两个等价操作实际上将以相同的方式规范化所讨论的图，而规范化是一个计算上非常昂贵的操作。因此，每当你看到已经以规范形式加载图的机会时，第一种方法将更有效。

# 顶点重要性

在一个相互连接的朋友图中，一个有趣的问题是谁是群体中最有影响力的人。是拥有最多连接的人，也就是具有最高度的顶点吗？对于有向图，入度可能是一个很好的第一猜测。或者更确切地说，是那些认识一些人，而这些人本身又有很多连接的人？肯定有很多方法来描述一个顶点的重要性或权威性，具体的答案将在很大程度上取决于问题域，以及我们在图中附加的其他数据。此外，在我们给出的例子中，对于图中的特定人物，另一个人可能因为他们自己非常主观的原因而是最有影响力的。

寻找给定图中顶点的重要性是一个具有挑战性的问题，一个历史上重要的算法示例是*PageRank*，它在 1998 年的开创性论文"The Anatomy of a Large-Scale Hypertextual Web Search Engine"中被描述，可以在[`ilpubs.stanford.edu:8090/361/1/1998-8.pdf`](http://ilpubs.stanford.edu:8090/361/1/1998-8.pdf)上找到。在这篇论文中，Sergey Brin 和 Larry Page 奠定了他们的搜索引擎 Google 在公司刚刚起步时运行的基础。虽然 PageRank 对于在由链接连接的庞大网页图中找到相关的搜索结果产生了重大影响，但这个算法在多年来已经被 Google 内部的其他方法所取代。然而，PageRank 仍然是如何对网页或图进行排名的一个主要示例，以获得更深入的理解。GraphX 提供了 PageRank 的实现，在描述算法本身之后我们将对其进行介绍。

PageRank 是一个针对有向图的迭代算法，通过将相同的值*1/N*初始化为每个顶点的值，其中*N*表示图的阶数，也就是顶点的数量。然后，它重复相同的更新顶点值的过程，也就是它们的 PageRank，直到我们选择停止或满足某些收敛标准。更具体地说，在每次迭代中，一个顶点将其*当前 PageRank 除以其出度*发送到所有它有出站连接的顶点，也就是说，它将其当前 PageRank 均匀分布到所有出站边上。然后顶点们将接收到的所有值相加以设置它们的新 PageRank。如果整体 PageRank 在上一次迭代中没有发生太大变化，则停止该过程。这是算法的非常基本的公式，我们将在讨论 GraphX 实现时进一步指定停止标准。

然而，我们还需要通过引入*阻尼因子 d*稍微扩展基线算法。阻尼因子是为了防止所谓的*排名汇*。想象一个强连接组件，它只有来自图的其余部分的入边，那么按照前面的规定，这个组件将在每次迭代中通过入边积累越来越多的 PageRank，但从不通过出边“释放”任何 PageRank。这种情况被称为排名汇，为了摆脱它，我们需要通过阻尼引入更多的*排名源*。PageRank 所做的是模拟一个完全随机的用户，以链接目标的 PageRank 给出的概率随机地跟随链接。阻尼的概念改变了这一点，引入了一个概率 d 的机会，用户按照他们当前的路径前进，并以概率(*1-d*)继续阅读一个完全不同的页面。

在上面的排名示例中，用户将离开强连接组件，然后在图中的其他地方停留，从而增加了其他部分的相关性，也就是 PageRank。为了总结这个解释，带有阻尼的 PageRank 更新规则可以写成如下形式：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00171.jpeg)

也就是说，为了更新顶点*v*的 PageRank *PR*，我们对所有入边顶点*w*的 PageRank 除以它们各自的出度*out(w)*求和。

Spark GraphX 有两种 PageRank 的实现，一种称为静态，另一种称为动态。在静态版本中，我们只需对预先指定的固定次数`numIter`执行前面的更新规则。在动态版本中，我们为收敛指定了一个*容差*`tol`，即如果顶点在上一次迭代中其 PageRank 至少没有变化`tol`，那么它将退出计算，这意味着它既不会发出新的 PageRanks，也不会再更新自己。让我们为微小的`friendGraph`计算静态和动态版本的 PageRank。使用 10 次迭代的静态版本如下调用：

```scala
friendGraph.staticPageRank(numIter = 10).vertices.collect.foreach(println)
```

运行算法后，我们只需在主节点上收集所有顶点并打印它们，得到以下结果：

```scala
 (1,0.42988729103845036)
 (2,0.3308390977362031)
 (3,0.6102873825386869)
 (4,0.6650182732476072)
 (5,0.42988729103845036)
```

看到 PageRanks 随着迭代次数的变化而变化是很有趣的；请参阅以下表格以获取详细信息：

| **numIter / vertex** | **Anne** | **Bernie** | **Chris** | **Don** | **Edgar** |
| --- | --- | --- | --- | --- | --- |
| 1 | 0.213 | 0.213 | 0.341 | 0.277 | 0.213 |
| 2 | 0.267 | 0.240 | 0.422 | 0.440 | 0.267 |
| 3 | 0.337 | 0.263 | 0.468 | 0.509 | 0.337 |
| 4 | 0.366 | 0.293 | 0.517 | 0.548 | 0.366 |
| 5 | 0.383 | 0.305 | 0.554 | 0.589 | 0.383 |
| 10 | 0.429 | 0.330 | 0.610 | 0.665 | 0.429 |
| 20 | 0.438 | 0.336 | 0.622 | 0.678 | 0.438 |
| 100 | 0.438 | 0.336 | 0.622 | 0.678 | 0.483 |

虽然在只有两次迭代后，哪个顶点比其他顶点更重要的一般趋势已经确定，但请注意，即使对于这个微小的图形，PageRanks 稳定下来也需要大约 20 次迭代。因此，如果您只对粗略排名顶点感兴趣，或者运行动态版本太昂贵，静态算法可以派上用场。要计算动态版本，我们将容差`tol`指定为`0.0001`，将所谓的`resetProb`指定为`0.15`。后者不过是*1-d*，也就是说，离开当前路径并在图中的随机顶点出现的概率。实际上，`0.15`是`resetProb`的默认值，并反映了原始论文的建议：

```scala
friendGraph.pageRank(tol = 0.0001, resetProb = 0.15)
```

运行这个程序会产生以下的 PageRank 值，显示在*图 15*中。这些数字应该看起来很熟悉，因为它们与具有 20 次或更多迭代的静态版本相同：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00172.jpeg)

图 15：使用动态 GraphX 实现计算的我们的玩具朋友图的 PageRanks。

对于一个更有趣的例子，让我们再次转向演员图。使用与前面示例中相同的容差，我们可以快速找到具有最高 PageRank 的顶点 ID：

```scala
val actorPrGraph: Graph[Double, Double] = actorGraph.pageRank(0.0001)
actorPrGraph.vertices.reduce((v1, v2) => {
  if (v1._2 > v2._2) v1 else v2
})
```

这返回 ID 33024，PageRank 为 7.82。为了突出 PageRank 与简单地将入度作为顶点重要性的想法有何不同，考虑以下分析：

```scala
actorPrGraph.inDegrees.filter(v => v._1 == 33024L).collect.foreach(println)
```

限制为所讨论的顶点 ID 并检查其入度结果为 62 个入边。让我们看看图中最高的十个入度是什么：

```scala
actorPrGraph.inDegrees.map(_._2).collect().sorted.takeRight(10)
```

这导致`Array(704, 733, 746, 756, 762, 793, 819, 842, 982, 1007)`，这意味着具有最高 PageRank 的顶点甚至没有接近具有最高入度的顶点。事实上，总共有 2167 个顶点至少有 62 个入边，可以通过运行以下命令来查看：

```scala
actorPrGraph.inDegrees.map(_._2).filter(_ >= 62).count
```

因此，虽然这仍然意味着该顶点在入度方面处于所有顶点的前 2%，但我们看到 PageRank 得出了与其他方法完全不同的答案。

# GraphX 的上下文

在整个章节中看到了许多图分析的应用之后，一个自然的问题是 GraphX 如何适应 Spark 生态系统的其他部分，以及我们如何将其与之前看到的 MLlib 等系统一起用于机器学习应用。

简而言之，尽管图的概念仅限于 Spark GraphX，但由于图的基础顶点和边 RDD，我们可以无缝地与 Spark 的任何其他模块进行交流。事实上，我们在整个章节中使用了许多核心 RDD 操作，但并不止于此。MLlib 确实在一些特定的地方使用了 GraphX 功能，比如*潜在狄利克雷分析*或*幂迭代聚类*，但这超出了本章的范围。相反，我们专注于从第一原理解释 GraphX 的基础知识。然而，鼓励读者将本章学到的知识与之前的知识结合起来，并尝试使用前面的算法进行实验。为了完整起见，GraphX 中完全实现了一种机器学习算法，即*SVD++*，您可以在[`public.research.att.com/~volinsky/netflix/kdd08koren.pdf`](http://public.research.att.com/~volinsky/netflix/kdd08koren.pdf)上了解更多信息，这是一种基于图的推荐算法。

# 总结

在本章中，我们已经看到了如何使用 Spark GraphX 将大规模图分析付诸实践。将实体关系建模为具有顶点和边的图是一种强大的范例，可以评估许多有趣的问题。

在 GraphX 中，图是有限的、有向的属性图，可能具有多个边和环。GraphX 对顶点和边 RDD 的高度优化版本进行图分析，这使您可以利用数据和图并行应用。我们已经看到这样的图可以通过从`edgeListFile`加载或从其他 RDD 单独构建来读取。除此之外，我们还看到了如何轻松地创建随机和确定性图数据进行快速实验。仅使用`Graph`模型的丰富内置功能，我们已经展示了如何调查图的核心属性。为了可视化更复杂的图形，我们介绍了*Gephi*及其接口，这使得我们可以直观地了解手头的图结构。

在 Spark GraphX 提供的许多其他可能性中，我们介绍了两种强大的图分析工具，即`aggregateMessages`和`Pregel` API。大多数 GraphX 内置算法都是使用这两个选项之一编写的。我们已经看到如何使用这些 API 编写我们自己的算法。我们还简要介绍了 GraphFrames 包，它建立在 DataFrames 之上，配备了一种优雅的查询语言，这种语言在普通的 GraphX 中不可用，并且可以在分析目的上派上用场。

在实际应用方面，我们看到了一个有趣的转发图，以及好莱坞电影演员图的应用。我们仔细解释并应用了谷歌的 PageRank 算法，研究了图的（强）连通组件，并计算三角形作为聚类的手段。最后，我们讨论了 Spark MLlib 和 GraphX 在高级机器学习应用中的关系。


# 第八章：Lending Club 贷款预测

我们几乎已经到了本书的结尾，但最后一章将利用我们在前几章中涵盖的所有技巧和知识。我们向您展示了如何利用 Spark 的强大功能进行数据处理和转换，以及我们向您展示了包括线性模型、树模型和模型集成在内的数据建模的不同方法。本质上，本章将是各种问题的“综合章节”，我们将一次性处理许多问题，从数据摄入、处理、预处理、异常值处理和建模，一直到模型部署。

我们的主要目标之一是提供数据科学家日常生活的真实画面——从几乎原始数据开始，探索数据，构建几个模型，比较它们，找到最佳模型，并将其部署到生产环境——如果一直都这么简单就好了！在本书的最后一章中，我们将借鉴 Lending Club 的一个真实场景，这是一家提供点对点贷款的公司。我们将应用您学到的所有技能，看看是否能够构建一个确定贷款风险性的模型。此外，我们将与实际的 Lending Club 数据进行比较，以评估我们的过程。

# 动机

Lending Club 的目标是最小化提供坏贷款的投资风险，即那些有很高违约或延迟概率的贷款，但也要避免拒绝好贷款，从而损失利润。在这里，主要标准是由接受的风险驱动——Lending Club 可以接受多少风险仍然能够盈利。

此外，对于潜在的贷款，Lending Club 需要提供一个反映风险并产生收入的适当利率，或者提供贷款调整。因此，如果某项贷款的利率较高，我们可能推断出这种贷款的固有风险比利率较低的贷款更大。

在我们的书中，我们可以从 Lending Club 的经验中受益，因为他们提供了不仅是良好贷款而且是坏贷款的历史追踪。此外，所有历史数据都可用，包括代表最终贷款状态的数据，这为扮演 Lending Club 数据科学家的角色并尝试匹配甚至超越他们的预测模型提供了独特的机会。

我们甚至可以再进一步——我们可以想象一个“自动驾驶模式”。对于每笔提交的贷款，我们可以定义投资策略（即，我们愿意接受多少风险）。自动驾驶将接受/拒绝贷款，并提出机器生成的利率，并计算预期收益。唯一的条件是，如果您使用我们的模型赚了一些钱，我们希望分享利润！

# 目标

总体目标是创建一个机器学习应用程序，能够根据给定的投资策略训练模型，并将这些模型部署为可调用的服务，处理进入的贷款申请。该服务将能够决定是否批准特定的贷款申请并计算利率。我们可以从业务需求开始，自上而下地定义我们的意图。记住，一个优秀的数据科学家对所提出的问题有着牢固的理解，这取决于对业务需求的理解，具体如下：

+   我们需要定义投资策略的含义以及它如何优化/影响我们的机器学习模型的创建和评估。然后，我们将采用模型的发现，并根据指定的投资策略将其应用于我们的贷款组合，以最大程度地优化我们的利润。

+   我们需要定义基于投资策略的预期回报计算，并且应用程序应该提供出借人的预期回报。这对于投资者来说是一个重要的贷款属性，因为它直接连接了贷款申请、投资策略（即风险）和可能的利润。我们应该记住这一点，因为在现实生活中，建模管道是由不是数据科学或统计专家的用户使用的，他们更感兴趣于对建模输出的更高层次解释。

+   此外，我们需要设计并实现一个贷款预测管道，其中包括以下内容：

+   基于贷款申请数据和投资策略的模型决定贷款状态-贷款是否应该被接受或拒绝。

+   模型需要足够健壮，以拒绝所有不良贷款（即导致投资损失的贷款），但另一方面，不要错过任何好贷款（即不要错过任何投资机会）。

+   模型应该是可解释的-它应该解释为什么会拒绝贷款。有趣的是，关于这个主题有很多研究；关键利益相关者希望得到比“模型说了算”更具体的东西。

对于那些对模型可解释性感兴趣的人，UCSD 的 Zachary Lipton 有一篇名为*模型可解释性的神话*的杰出论文，[`arxiv.org/abs/1606.03490`](https://arxiv.org/abs/1606.03490)直接讨论了这个话题。对于那些经常需要解释他们的魔法的数据科学家来说，这是一篇特别有用的论文！

+   +   还有另一个模型，它推荐接受贷款的利率。根据指定的贷款申请，模型应该决定最佳利率，既不能太高以至于失去借款人，也不能太低以至于错失利润。

+   最后，我们需要决定如何部署这个复杂的、多方面的机器学习管道。就像我们之前的章节一样，将多个模型组合成一个管道，我们将使用数据集中的所有输入-我们将看到它们是非常不同类型的-并进行处理、特征提取、模型预测和基于我们的投资策略的推荐：这是一个艰巨的任务，但我们将在本章中完成！

# 数据

Lending Club 提供所有可用的贷款申请及其结果。2007-2012 年和 2013-2014 年的数据可以直接从[`www.lendingclub.com/info/download-data.action`](https://www.lendingclub.com/info/download-data.action)下载。

下载拒绝贷款数据，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00173.jpeg)

下载的文件包括`filesLoanStats3a.CSV`和`LoanStats3b.CSV`。

我们拥有的文件包含大约 230k 行，分为两个部分：

+   符合信用政策的贷款：168k

+   不符合信用政策的贷款：62k（注意不平衡的数据集）

和往常一样，建议通过查看样本行或前 10 行来查看数据；鉴于我们这里的数据集的大小，我们可以使用 Excel 来查看一行是什么样子：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00174.jpeg)

要小心，因为下载的文件可能包含一行 Lending Club 下载系统的注释。最好在加载到 Spark 之前手动删除它。

# 数据字典

Lending Club 下载页面还提供了包含单独列解释的数据字典。具体来说，数据集包含 115 个具有特定含义的列，收集关于借款人的数据，包括他们的银行历史、信用历史和贷款申请。此外，对于已接受的贷款，数据包括付款进度或贷款的最终状态-如果完全支付或违约。研究数据字典的一个重要原因是防止使用可能会预示你试图预测的结果的列，从而导致模型不准确。这个信息很清楚但非常重要：研究并了解你的数据！

# 环境准备

在本章中，我们将使用 Scala API 构建两个独立的 Spark 应用程序，一个用于模型准备，另一个用于模型部署，而不是使用 Spark shell。在 Spark 的情况下，Spark 应用程序是一个正常的 Scala 应用程序，具有作为执行入口的主方法。例如，这是一个用于模型训练的应用程序的框架：

```scala
object Chapter8 extends App {

val spark = SparkSession.builder()
     .master("local[*]")
     .appName("Chapter8")
     .getOrCreate()

val sc = spark.sparkContext
sc.setLogLevel("WARN")
script(spark, sc, spark.sqlContext)

def script(spark: SparkSession, sc: SparkContext, sqlContext: SQLContext): Unit = {
      // ...code of application
}
}

```

此外，我们将尝试提取可以在两个应用程序之间共享的部分到一个库中。这将使我们能够遵循 DRY（不要重复自己）原则：

```scala
object Chapter8Library {
    // ...code of library
  }
```

# 数据加载

通常情况下，第一步涉及将数据加载到内存中。在这一点上，我们可以决定使用 Spark 或 H2O 的数据加载能力。由于数据存储在 CSV 文件格式中，我们将使用 H2O 解析器快速地了解数据：

```scala
val DATASET_DIR = s"${sys.env.get("DATADIR").getOrElse("data")}" val DATASETS = Array("LoanStats3a.CSV", "LoanStats3b.CSV")
import java.net.URI

import water.fvec.H2OFrame
val loanDataHf = new H2OFrame(DATASETS.map(name => URI.create(s"${DATASET_DIR}/${name}")):_*)
```

加载的数据集可以直接在 H2O Flow UI 中进行探索。我们可以直接验证存储在内存中的数据的行数、列数和大小：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00175.jpeg)

# 探索-数据分析

现在，是时候探索数据了。我们可以问很多问题，比如：

+   我们想要模拟支持我们目标的目标特征是什么？

+   每个目标特征的有用训练特征是什么？

+   哪些特征不适合建模，因为它们泄漏了关于目标特征的信息（请参阅前一节）？

+   哪些特征是无用的（例如，常量特征，或者包含大量缺失值的特征）？

+   如何清理数据？对缺失值应该怎么处理？我们能工程化新特征吗？

# 基本清理

在数据探索过程中，我们将执行基本的数据清理。在我们的情况下，我们可以利用两种工具的力量：我们使用 H2O Flow UI 来探索数据，找到数据中可疑的部分，并直接用 H2O 或者更好地用 Spark 进行转换。

# 无用的列

第一步是删除每行包含唯一值的列。这种典型的例子是用户 ID 或交易 ID。在我们的情况下，我们将根据数据描述手动识别它们：

```scala
import com.packtpub.mmlwspark.utils.Tabulizer.table
val idColumns = Seq("id", "member_id")
println(s"Columns with Ids: ${table(idColumns, 4, None)}")

```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00176.jpeg)

下一步是识别无用的列，例如以下列：

+   常量列

+   坏列（只包含缺失值）

以下代码将帮助我们做到这一点：

```scala
val constantColumns = loanDataHf.names().indices
   .filter(idx => loanDataHf.vec(idx).isConst || loanDataHf.vec(idx).isBad)
   .map(idx => loanDataHf.name(idx))
println(s"Constant and bad columns: ${table(constantColumns, 4, None)}")
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00177.jpeg)

# 字符串列

现在，是时候探索数据集中不同类型的列了。简单的步骤是查看包含字符串的列-这些列就像 ID 列一样，因为它们包含唯一值：

```scala
val stringColumns = loanDataHf.names().indices
   .filter(idx => loanDataHf.vec(idx).isString)
   .map(idx => loanDataHf.name(idx))
println(s"String columns:${table(stringColumns, 4, None)}")
```

输出显示在以下截图中：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00178.jpeg)

问题是`url`特征是否包含我们可以提取的任何有用信息。我们可以直接在 H2O Flow 中探索数据，并在以下截图中查看特征列中的一些数据样本：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00179.jpeg)

我们可以直接看到`url`特征只包含指向 Lending Club 网站的指针，使用我们已经删除的应用程序 ID。因此，我们可以决定删除它。

# 贷款进度列

我们的目标是基于贷款申请数据做出固有风险的预测，但是一些列包含了关于贷款支付进度的信息，或者它们是由 Lending Club 自己分配的。在这个例子中，为了简单起见，我们将放弃它们，只关注贷款申请流程中的列。重要的是要提到，在现实场景中，甚至这些列可能包含有用的信息（例如支付进度）可用于预测。然而，我们希望基于贷款的初始申请来构建我们的模型，而不是在贷款已经被 a）接受和 b）有历史支付记录的情况下。根据数据字典，我们检测到以下列：

```scala
val loanProgressColumns = Seq("funded_amnt", "funded_amnt_inv", "grade", "initial_list_status",
"issue_d", "last_credit_pull_d", "last_pymnt_amnt", "last_pymnt_d",
"next_pymnt_d", "out_prncp", "out_prncp_inv", "pymnt_plan",
"recoveries", "sub_grade", "total_pymnt", "total_pymnt_inv",
"total_rec_int", "total_rec_late_fee", "total_rec_prncp")
```

现在，我们可以直接记录所有我们需要删除的列，因为它们对建模没有任何价值：

```scala
val columnsToRemove = (idColumns ++ constantColumns ++ stringColumns ++ loanProgressColumns)
```

# 分类列

在下一步中，我们将探索分类列。H2O 解析器只有在列包含有限的字符串值集时才将列标记为分类列。这是与标记为字符串列的列的主要区别。它们包含超过 90%的唯一值（例如，我们在上一段中探索的`url`列）。让我们收集我们数据集中所有分类列的列表，以及各个特征的稀疏性：

```scala
val categoricalColumns = loanDataHf.names().indices
  .filter(idx => loanDataHf.vec(idx).isCategorical)
  .map(idx => (loanDataHf.name(idx), loanDataHf.vec(idx).cardinality()))
  .sortBy(-_._2)

println(s"Categorical columns:${table(tblize(categoricalColumns, true, 2))}")
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00180.jpeg)

现在，我们可以探索单独的列。例如，“purpose”列包含 13 个类别，主要目的是债务合并：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00181.jpeg)

这个列看起来是有效的，但现在，我们应该关注可疑的列，即，首先是高基数列：`emp_title`，`title`，`desc`。有几个观察结果：

+   每列的最高值是一个空的“值”。这可能意味着一个缺失的值。然而，对于这种类型的列（即，表示一组值的列），一个专门的级别用于缺失值是非常合理的。它只代表另一个可能的状态，“缺失”。因此，我们可以保持它不变。

+   “title”列与“purpose”列重叠，可以被删除。

+   `emp_title`和`desc`列纯粹是文本描述。在这种情况下，我们不会将它们视为分类，而是应用 NLP 技术以后提取重要信息。

现在，我们将专注于以“mths_”开头的列，正如列名所示，该列应该包含数字值，但我们的解析器决定这些列是分类的。这可能是由于收集数据时的不一致性造成的。例如，当我们探索“mths_since_last_major_derog”列的域时，我们很容易就能发现一个原因：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00182.jpeg)

列中最常见的值是一个空值（即，我们之前已经探索过的相同缺陷）。在这种情况下，我们需要决定如何替换这个值以将列转换为数字列：它应该被缺失值替换吗？

如果我们想尝试不同的策略，我们可以为这种类型的列定义一个灵活的转换。在这种情况下，我们将离开 H2O API 并切换到 Spark，并定义我们自己的 Spark UDF。因此，与前几章一样，我们将定义一个函数。在这种情况下，一个给定替换值和一个字符串的函数，产生代表给定字符串的浮点值，或者如果字符串为空则返回指定值。然后，将该函数包装成 Spark UDF：

```scala
import org.apache.spark.sql.functions._
val toNumericMnths = (replacementValue: Float) => (mnths: String) => {
if (mnths != null && !mnths.trim.isEmpty) mnths.trim.toFloat else replacementValue
}
val toNumericMnthsUdf = udf(toNumericMnths(0.0f))
```

一个好的做法是保持我们的代码足够灵活，以允许进行实验，但不要使其过于复杂。在这种情况下，我们只是为我们期望更详细探讨的情况留下了一个开放的大门。

还有两列需要我们关注：`int_rate`和`revol_util`。两者都应该是表示百分比的数字列；然而，如果我们对它们进行探索，我们很容易看到一个问题--列中包含“％”符号而不是数字值。因此，我们有两个更多的候选列需要转换：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00183.jpeg)

然而，我们不会直接处理数据，而是定义 Spark UDF 转换，将基于字符串的利率转换为数字利率。但是，在我们的 UDF 定义中，我们将简单地使用 H2O 提供的信息，确认两列中的类别列表只包含以百分号结尾的数据：

```scala
import org.apache.spark.sql.functions._
val toNumericRate = (rate: String) => {
val num = if (rate != null) rate.stripSuffix("%").trim else ""
if (!num.isEmpty) num.toFloat else Float.NaN
}
val toNumericRateUdf = udf(toNumericRate)
```

定义的 UDF 将在稍后与其他 Spark 转换一起应用。此外，我们需要意识到这些转换需要在训练和评分时应用。因此，我们将它们放入我们的共享库中。

# 文本列

在前面的部分中，我们确定了`emp_title`和`desc`列作为文本转换的目标。我们的理论是这些列可能包含有用的信息，可以帮助区分好坏贷款。

# 缺失数据

我们数据探索旅程的最后一步是探索缺失值。我们已经观察到一些列包含表示缺失值的值；然而，在本节中，我们将专注于纯缺失值。首先，我们需要收集它们：

```scala
val naColumns = loanDataHf.names().indices
   .filter(idx => loanDataHf.vec(idx).naCnt() >0)
   .map(idx =>
          (loanDataHf.name(idx),
            loanDataHf.vec(idx).naCnt(),
f"${100*loanDataHf.vec(idx).naCnt()/loanDataHf.numRows().toFloat}%2.1f%%")
   ).sortBy(-_._2)
println(s"Columns with NAs (#${naColumns.length}):${table(naColumns)}")
```

列表包含 111 列，缺失值的数量从 0.2％到 86％不等：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00184.jpeg)

有很多列缺少五个值，这可能是由于错误的数据收集引起的，如果它们呈现出某种模式，我们可以很容易地将它们过滤掉。对于更“污染的列”（例如，有许多缺失值的列），我们需要根据数据字典中描述的列语义找出每列的正确策略。

在所有这些情况下，H2O Flow UI 允许我们轻松快速地探索数据的基本属性，甚至执行基本的数据清理。但是，对于更高级的数据操作，Spark 是正确的工具，因为它提供了一个预先准备好的转换库和本地 SQL 支持。

哇！正如我们所看到的，数据清理虽然相当费力，但对于数据科学家来说是一项非常重要的任务，希望能够得到对深思熟虑的问题的良好答案。在解决每一个新问题之前，这个过程必须经过仔细考虑。正如古老的广告语所说，“垃圾进，垃圾出”-如果输入不正确，我们的模型将遭受后果。

此时，可以将所有确定的转换组合成共享库函数：

```scala
def basicDataCleanup(loanDf: DataFrame, colsToDrop: Seq[String] = Seq()) = {
   (
     (if (loanDf.columns.contains("int_rate"))
       loanDf.withColumn("int_rate", toNumericRateUdf(col("int_rate")))
else loanDf)
       .withColumn("revol_util", toNumericRateUdf(col("revol_util")))
       .withColumn("mo_sin_old_il_acct", toNumericMnthsUdf(col("mo_sin_old_il_acct")))
       .withColumn("mths_since_last_delinq", toNumericMnthsUdf(col("mths_since_last_delinq")))
       .withColumn("mths_since_last_record", toNumericMnthsUdf(col("mths_since_last_record")))
       .withColumn("mths_since_last_major_derog", toNumericMnthsUdf(col("mths_since_last_major_derog")))
       .withColumn("mths_since_recent_bc", toNumericMnthsUdf(col("mths_since_recent_bc")))
       .withColumn("mths_since_recent_bc_dlq", toNumericMnthsUdf(col("mths_since_recent_bc_dlq")))
       .withColumn("mths_since_recent_inq", toNumericMnthsUdf(col("mths_since_recent_inq")))
       .withColumn("mths_since_recent_revol_delinq", toNumericMnthsUdf(col("mths_since_recent_revol_delinq")))
   ).drop(colsToDrop.toArray :_*)
 }
```

该方法以 Spark DataFrame 作为输入，并应用所有确定的清理转换。现在，是时候构建一些模型了！

# 预测目标

进行数据清理后，是时候检查我们的预测目标了。我们理想的建模流程包括两个模型：一个控制贷款接受的模型，一个估计利率的模型。你应该已经想到，第一个模型是一个二元分类问题（接受或拒绝贷款），而第二个模型是一个回归问题，结果是一个数值。

# 贷款状态模型

第一个模型需要区分好坏贷款。数据集已经提供了`loan_status`列，这是我们建模目标的最佳特征表示。让我们更详细地看看这一列。

贷款状态由一个分类特征表示，有七个级别：

+   全额支付：借款人支付了贷款和所有利息

+   当前：贷款按计划积极支付

+   宽限期内：逾期付款 1-15 天

+   逾期（16-30 天）：逾期付款

+   逾期（31-120 天）：逾期付款

+   已冲销：贷款逾期 150 天

+   违约：贷款丢失

对于第一个建模目标，我们需要区分好贷款和坏贷款。好贷款可能是已全额偿还的贷款。其余的贷款可以被视为坏贷款，除了需要更多关注的当前贷款（例如，存活分析），或者我们可以简单地删除包含“Current”状态的所有行。为了将 loan_status 特征转换为二进制特征，我们将定义一个 Spark UDF：

```scala
val toBinaryLoanStatus = (status: String) => status.trim.toLowerCase() match {
case "fully paid" =>"good loan"
case _ =>"bad loan"
}
val toBinaryLoanStatusUdf = udf(toBinaryLoanStatus)
```

我们可以更详细地探索各个类别的分布。在下面的截图中，我们还可以看到好贷款和坏贷款之间的比例非常不平衡。在训练和评估模型时，我们需要牢记这一事实，因为我们希望优化对坏贷款的召回概率：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00185.jpeg)

loan_status 列的属性。

# 基本模型

此时，我们已经准备好了目标预测列并清理了输入数据，现在可以构建一个基本模型了。基本模型可以让我们对数据有基本的直觉。为此，我们将使用除了被检测为无用的列之外的所有列。我们也将跳过处理缺失值，因为我们将使用 H2O 和 RandomForest 算法，它可以处理缺失值。然而，第一步是通过定义的 Spark 转换来准备数据集：

```scala
import com.packtpub.mmlwspark.chapter8.Chapter8Library._
val loanDataDf = h2oContext.asDataFrame(loanDataHf)(sqlContext)
val loanStatusBaseModelDf = basicDataCleanup(
   loanDataDf
     .where("loan_status is not null")
     .withColumn("loan_status", toBinaryLoanStatusUdf($"loan_status")),
   colsToDrop = Seq("title") ++ columnsToRemove)
```

我们将简单地删除所有已知与我们的目标预测列相关的列，所有携带文本描述的高分类列（除了`title`和`desc`，我们稍后会使用），并应用我们在前面部分确定的所有基本清理转换。

下一步涉及将数据分割成两部分。像往常一样，我们将保留大部分数据用于训练，其余部分用于模型验证，并将其转换为 H2O 模型构建器接受的形式：

```scala
val loanStatusDfSplits = loanStatusBaseModelDf.randomSplit(Array(0.7, 0.3), seed = 42)

val trainLSBaseModelHf = toHf(loanStatusDfSplits(0).drop("emp_title", "desc"), "trainLSBaseModelHf")(h2oContext)
val validLSBaseModelHf = toHf(loanStatusDfSplits(1).drop("emp_title", "desc"), "validLSBaseModelHf")(h2oContext)
def toHf(df: DataFrame, name: String)(h2oContext: H2OContext): H2OFrame = {
val hf = h2oContext.asH2OFrame(df, name)
val allStringColumns = hf.names().filter(name => hf.vec(name).isString)
     hf.colToEnum(allStringColumns)
     hf
 }
```

有了清理后的数据，我们可以轻松地构建一个模型。我们将盲目地使用 RandomForest 算法，因为它直接为我们提供了数据和个体特征的重要性。我们之所以说“盲目”，是因为正如你在第二章中回忆的那样，*探测暗物质 - 强子玻色子粒子*，RandomForest 模型可以接受许多不同类型的输入，并使用不同的特征构建许多不同的树，这让我们有信心使用这个算法作为我们的开箱即用模型，因为它在包括所有特征时表现得非常好。因此，该模型也定义了一个我们希望通过构建新特征来改进的基线。

我们将使用默认设置。RandomForest 提供了基于袋外样本的验证模式，因此我们暂时可以跳过交叉验证。然而，我们将增加构建树的数量，但通过基于 Logloss 的停止准则限制模型构建的执行。此外，我们知道预测目标是不平衡的，好贷款的数量远远高于坏贷款，因此我们将通过启用 balance_classes 选项要求对少数类进行上采样：

```scala

import _root_.hex.tree.drf.DRFModel.DRFParameters
import _root_.hex.tree.drf.{DRF, DRFModel}
import _root_.hex.ScoreKeeper.StoppingMetric
import com.packtpub.mmlwspark.utils.Utils.let

val loanStatusBaseModelParams = let(new DRFParameters) { p =>
   p._response_column = "loan_status" p._train = trainLSBaseModelHf._key
p._ignored_columns = Array("int_rate")
   p._stopping_metric = StoppingMetric.logloss
p._stopping_rounds = 1
p._stopping_tolerance = 0.1
p._ntrees = 100
p._balance_classes = true p._score_tree_interval = 20
}
val loanStatusBaseModel1 = new DRF(loanStatusBaseModelParams, water.Key.makeDRFModel)
   .trainModel()
   .get()
```

模型构建完成后，我们可以像在之前的章节中那样探索其质量，但我们首先要看的是特征的重要性：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00186.jpeg)

最令人惊讶的事实是，zip_code 和 collection_recovery_fee 特征的重要性远高于其他列。这是可疑的，可能表明该列与目标变量直接相关。

我们可以重新查看数据字典，其中将**zip_code**列描述为“借款人在贷款申请中提供的邮政编码的前三个数字”，第二列描述为“后收费用”。后者指示与响应列的直接联系，因为“好贷款”将具有等于零的值。我们还可以通过探索数据来验证这一事实。在 zip_code 的情况下，与响应列没有明显的联系。

因此，我们将进行一次模型运行，但在这种情况下，我们将尝试忽略`zip_code`和`collection_recovery_fee`列：

```scala
loanStatusBaseModelParams._ignored_columns = Array("int_rate", "collection_recovery_fee", "zip_code")
val loanStatusBaseModel2 = new DRF(loanStatusBaseModelParams, water.Key.makeDRFModel)
   .trainModel()
   .get()
```

构建模型后，我们可以再次探索变量重要性图，并看到变量之间的重要性分布更有意义。根据图表，我们可以决定仅使用前 10 个输入特征来简化模型的复杂性并减少建模时间。重要的是要说，我们仍然需要考虑已删除的列作为相关的输入特征：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00187.jpeg)

**基础模型性能**

现在，我们可以查看创建模型的模型性能。我们需要记住，在我们的情况下，以下内容适用：

+   模型的性能是基于袋外样本报告的，而不是未见数据。

+   我们使用固定参数作为最佳猜测；然而，进行随机参数搜索将有益于了解输入参数如何影响模型的性能。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00188.jpeg)

我们可以看到在袋外样本数据上测得的 AUC 相当高。即使对于最小化各个类别准确率的选择阈值，各个类别的错误率也很低。然而，让我们探索模型在未见数据上的性能。我们将使用准备好的部分数据进行验证：

```scala
import _root_.hex.ModelMetrics
val lsBaseModelPredHf = loanStatusBaseModel2.score(validLSBaseModelHf)
println(ModelMetrics.getFromDKV(loanStatusBaseModel2, validLSBaseModelHf))
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00189.jpeg)

计算得到的模型指标也可以在 Flow UI 中进行可视化探索。

我们可以看到 AUC 较低，各个类别的错误率较高，但仍然相当不错。然而，所有测量的统计属性都无法给我们任何关于模型的“业务”价值的概念-借出了多少钱，违约贷款损失了多少钱等等。在下一步中，我们将尝试为模型设计特定的评估指标。

声明模型做出错误预测是什么意思？它可以将良好的贷款申请视为不良的，这将导致拒绝申请。这也意味着从贷款利息中损失利润。或者，模型可以将不良的贷款申请推荐为良好的，这将导致全部或部分借出的资金损失。让我们更详细地看看这两种情况。

前一种情况可以用以下函数描述：

```scala
def profitMoneyLoss = (predThreshold: Double) =>
     (act: String, predGoodLoanProb: Double, loanAmount: Int, intRate: Double, term: String) => {
val termInMonths = term.trim match {
case "36 months" =>36
case "60 months" =>60
}
val intRatePerMonth = intRate / 12 / 100
if (predGoodLoanProb < predThreshold && act == "good loan") {
         termInMonths*loanAmount*intRatePerMonth / (1 - Math.pow(1+intRatePerMonth, -termInMonths)) - loanAmount
       } else 0.0
}
```

该函数返回如果模型预测了不良贷款，但实际数据表明贷款是良好的时候损失的金额。返回的金额考虑了预测的利率和期限。重要的变量是`predGoodLoanProb`，它保存了模型预测的将实际贷款视为良好贷款的概率，以及`predThreshold`，它允许我们设置一个标准，当预测良好贷款的概率对我们来说足够高时。

类似地，我们将描述后一种情况：

```scala
val loanMoneyLoss = (act: String, predGoodLoanProb: Double, predThreshold: Double, loanAmount: Int) => {
if (predGoodLoanProb > predThreshold /* good loan predicted */
&& act == "bad loan" /* actual is bad loan */) loanAmount else 0
}
```

要意识到我们只是按照假阳性和假阴性的混淆矩阵定义，并应用我们对输入数据的领域知识来定义特定的模型评估指标。

现在，是时候利用这两个函数并定义`totalLoss`了-如果我们遵循模型的建议，接受不良贷款和错过良好贷款时我们可以损失多少钱：

```scala
import org.apache.spark.sql.Row
def totalLoss(actPredDf: DataFrame, threshold: Double): (Double, Double, Long, Double, Long, Double) = {

val profitMoneyLossUdf = udf(profitMoneyLoss(threshold))
val loanMoneyLossUdf = udf(loanMoneyLoss(threshold))

val lostMoneyDf = actPredDf
     .where("loan_status is not null and loan_amnt is not null")
     .withColumn("profitMoneyLoss", profitMoneyLossUdf($"loan_status", $"good loan", $"loan_amnt", $"int_rate", $"term"))
     .withColumn("loanMoneyLoss", loanMoneyLossUdf($"loan_status", $"good loan", $"loan_amnt"))

   lostMoneyDf
     .agg("profitMoneyLoss" ->"sum", "loanMoneyLoss" ->"sum")
     .collect.apply(0) match {
case Row(profitMoneyLossSum: Double, loanMoneyLossSum: Double) =>
       (threshold,
         profitMoneyLossSum, lostMoneyDf.where("profitMoneyLoss > 0").count,
         loanMoneyLossSum, lostMoneyDf.where("loanMoneyLoss > 0").count,
         profitMoneyLossSum + loanMoneyLossSum
       )
   }
 }
```

`totalLoss`函数是为 Spark DataFrame 和阈值定义的。Spark DataFrame 包含实际验证数据和预测，由三列组成：默认阈值的实际预测、良好贷款的概率和不良贷款的概率。阈值帮助我们定义良好贷款概率的合适标准；也就是说，如果良好贷款概率高于阈值，我们可以认为模型建议接受贷款。

如果我们对不同的阈值运行该函数，包括最小化各个类别错误的阈值，我们将得到以下表格：

```scala
import _root_.hex.AUC2.ThresholdCriterion
val predVActHf: Frame = lsBaseModel2PredHf.add(validLSBaseModelHf)
 water.DKV.put(predVActHf)
val predVActDf = h2oContext.asDataFrame(predVActHf)(sqlContext)
val DEFAULT_THRESHOLDS = Array(0.4, 0.45, 0.5, 0.55, 0.6, 0.65, 0.7, 0.75, 0.8, 0.85, 0.9, 0.95)

println(
table(Array("Threshold", "Profit Loss", "Count", "Loan loss", "Count", "Total loss"),
         (DEFAULT_THRESHOLDS :+
               ThresholdCriterion.min_per_class_accuracy.max_criterion(lsBaseModel2PredModelMetrics.auc_obj()))
          .map(threshold =>totalLoss(predVActDf, threshold)),
Map(1 ->"%,.2f", 3 ->"%,.2f", 5 ->"%,.2f")))
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00190.jpeg)

从表中可以看出，我们的指标的最低总损失是基于阈值`0.85`，这代表了一种相当保守的策略，侧重于避免坏账。

我们甚至可以定义一个函数，找到最小的总损失和相应的阈值：

```scala
// @Snippet
def findMinLoss(model: DRFModel,
                 validHf: H2OFrame,
                 defaultThresholds: Array[Double]): (Double, Double, Double, Double) = {
import _root_.hex.ModelMetrics
import _root_.hex.AUC2.ThresholdCriterion
// Score model
val modelPredHf = model.score(validHf)
val modelMetrics = ModelMetrics.getFromDKV(model, validHf)
val predVActHf: Frame = modelPredHf.add(validHf)
   water.DKV.put(predVActHf)
//
val predVActDf = h2oContext.asDataFrame(predVActHf)(sqlContext)
val min = (DEFAULT_THRESHOLDS :+ ThresholdCriterion.min_per_class_accuracy.max_criterion(modelMetrics.auc_obj()))
     .map(threshold =>totalLoss(predVActDf, threshold)).minBy(_._6)
   ( /* Threshold */ min._1, /* Total loss */ min._6, /* Profit loss */ min._2, /* Loan loss */ min._4)
 }
val minLossModel2 = findMinLoss(loanStatusBaseModel2, validLSBaseModelHf, DEFAULT_THRESHOLDS)
println(f"Min total loss for model 2: ${minLossModel2._2}%,.2f (threshold = ${minLossModel2._1})")
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00191.jpeg)

基于报告的结果，我们可以看到模型将总损失最小化到阈值约为`0.85`，这比模型识别的默认阈值（F1 = 0.66）要高。然而，我们仍然需要意识到这只是一个基本的朴素模型；我们没有进行任何调整和搜索正确的训练参数。我们仍然有两个字段，`title`和`desc`，我们可以利用。是时候改进模型了！

# emp_title 列转换

第一列`emp_title`描述了就业头衔。然而，它并不统一-有多个版本具有相同的含义（“Bank of America”与“bank of america”）或类似的含义（“AT&T”和“AT&T Mobility”）。我们的目标是将标签统一成基本形式，检测相似的标签，并用一个共同的标题替换它们。理论上，就业头衔直接影响偿还贷款的能力。

标签的基本统一是一个简单的任务-将标签转换为小写形式并丢弃所有非字母数字字符（例如“&”或“.”）。对于这一步，我们将使用 Spark API 进行用户定义的函数：

```scala
val unifyTextColumn = (in: String) => {
if (in != null) in.toLowerCase.replaceAll("[^\\w ]|", "") else null
}
val unifyTextColumnUdf = udf(unifyTextColumn)
```

下一步定义了一个分词器，一个将句子分割成单独标记并丢弃无用和停用词（例如，太短的词或连词）的函数。在我们的情况下，我们将使最小标记长度和停用词列表作为输入参数灵活：

```scala
val ALL_NUM_REGEXP = java.util.regex.Pattern.compile("\\d*")
val tokenizeTextColumn = (minLen: Int) => (stopWords: Array[String]) => (w: String) => {
if (w != null)
     w.split(" ").map(_.trim).filter(_.length >= minLen).filter(!ALL_NUM_REGEXP.matcher(_).matches()).filter(!stopWords.contains(_)).toSeq
else Seq.empty[String]
 }
import org.apache.spark.ml.feature.StopWordsRemover
val tokenizeUdf = udf(tokenizeTextColumn(3)(StopWordsRemover.loadDefaultStopWords("english")))
```

重要的是要提到，Spark API 已经提供了停用词列表作为`StopWordsRemover`转换的一部分。我们对`tokenizeUdf`的定义直接利用了提供的英文停用词列表。

现在，是时候更详细地查看列了。我们将从已创建的 DataFrame `loanStatusBaseModelDf`中选择`emp_title`列，并应用前面定义的两个函数：

```scala
val empTitleColumnDf = loanStatusBaseModelDf
   .withColumn("emp_title", unifyTextColumnUdf($"emp_title"))
   .withColumn("emp_title_tokens", tokenizeUdf($"emp_title"))
```

现在，我们有一个重要的 Spark DataFrame，其中包含两个重要的列：第一列包含统一的`emp_title`，第二列由标记列表表示。借助 Spark SQL API，我们可以轻松地计算`emp_title`列中唯一值的数量，或者具有超过 100 个频率的唯一标记的数量（即，这意味着该单词在超过 100 个`emp_titles`中使用）：

```scala
println("Number of unique values in emp_title column: " +
        empTitleColumn.select("emp_title").groupBy("emp_title").count().count())
println("Number of unique tokens with freq > 100 in emp_title column: " +
        empTitleColumn.rdd.flatMap(row => row.getSeqString.map(w => (w, 1)))
          .reduceByKey(_ + _).filter(_._2 >100).count)
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00192.jpeg)

您可以看到`emp_title`列中有许多唯一值。另一方面，只有`717`个标记一遍又一遍地重复。我们的目标是*压缩*列中唯一值的数量，并将相似的值分组在一起。我们可以尝试不同的方法。例如，用一个代表性标记对每个`emp_title`进行编码，或者使用基于 Word2Vec 算法的更高级的技术。

在前面的代码中，我们将 DataFrame 查询功能与原始 RDD 的计算能力相结合。许多查询可以用强大的基于 SQL 的 DataFrame API 来表达；然而，如果我们需要处理结构化数据（例如前面示例中的字符串标记序列），通常 RDD API 是一个快速的选择。

让我们看看第二个选项。Word2Vec 算法将文本特征转换为向量空间，其中相似的单词在表示单词的相应向量的余弦距离方面彼此靠近。这是一个很好的特性；然而，我们仍然需要检测“相似单词组”。对于这个任务，我们可以简单地使用 KMeans 算法。

第一步是创建 Word2Vec 模型。由于我们的数据在 Spark DataFrame 中，我们将简单地使用`ml`包中的 Spark 实现：

```scala
import org.apache.spark.ml.feature.Word2Vec
val empTitleW2VModel = new Word2Vec()
  .setInputCol("emp_title_tokens")
  .setOutputCol("emp_title_w2vVector")
  .setMinCount(1)
  .fit(empTitleColumn)
```

算法输入由存储在“tokens”列中的句子表示的标记序列定义。`outputCol`参数定义了模型的输出，如果用于转换数据的话：

```scala

 val empTitleColumnWithW2V =   w2vModel.transform(empTitleW2VModel)
 empTitleColumnWithW2V.printSchema()
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00193.jpeg)

从转换的输出中，您可以直接看到 DataFrame 输出不仅包含`emp_title`和`emp_title_tokens`输入列，还包含`emp_title_w2vVector`列，它代表了 w2vModel 转换的输出。

需要提到的是，Word2Vec 算法仅针对单词，但 Spark 实现也将句子（即单词序列）转换为向量，方法是通过对句子表示的所有单词向量进行平均。

接下来，我们将构建一个 K 均值模型，将代表个人就业头衔的向量空间划分为预定义数量的聚类。在这之前，重要的是要考虑为什么这样做是有益的。想想你所知道的“软件工程师”的许多不同变体：程序分析员，SE，高级软件工程师等等。鉴于这些本质上意思相同并且将由相似向量表示的变体，聚类为我们提供了一种将相似头衔分组在一起的方法。然而，我们需要指定我们应该检测到多少 K 个聚类-这需要更多的实验，但为简单起见，我们将尝试`500`个聚类：

```scala
import org.apache.spark.ml.clustering.KMeans
val K = 500
val empTitleKmeansModel = new KMeans()
  .setFeaturesCol("emp_title_w2vVector")
  .setK(K)
  .setPredictionCol("emp_title_cluster")
  .fit(empTitleColumnWithW2V)
```

该模型允许我们转换输入数据并探索聚类。聚类编号存储在一个名为`emp_title_cluster`的新列中。

指定聚类数量是棘手的，因为我们正在处理无监督的机器学习世界。通常，从业者会使用一个简单的启发式方法，称为肘部法则（参考以下链接：[`en.wikipedia.org/wiki/Determining_the_number_of_clusters_in_a_data_set`](https://en.wikipedia.org/wiki/Determining_the_number_of_clusters_in_a_data_set)），基本上通过许多 K 均值模型，增加 K 聚类的数量作为每个聚类之间的异质性（独特性）的函数。通常情况下，随着 K 聚类数量的增加，收益会递减，关键是找到增加变得边际的点，以至于收益不再值得运行时间。

另外，还有一些信息准则统计量，被称为**AIC**（**阿凯克信息准则**）（[`en.wikipedia.org/wiki/Akaike_information_criterion`](https://en.wikipedia.org/wiki/Akaike_information_criterion)）和**BIC**（**贝叶斯信息准则**）（[`en.wikipedia.org/wiki/Bayesian_information_criterion`](https://en.wikipedia.org/wiki/Bayesian_information_criterion)），对此感兴趣的人应该进一步了解。需要注意的是，在撰写本书时，Spark 尚未实现这些信息准则，因此我们不会详细介绍。

看一下以下代码片段：

```scala
val clustered = empTitleKmeansModel.transform(empTitleColumnWithW2V)
clustered.printSchema()
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00194.jpeg)

此外，我们可以探索与随机聚类相关的单词：

```scala
println(
s"""Words in cluster '133':
 |${clustered.select("emp_title").where("emp_title_cluster = 133").take(10).mkString(", ")}
 |""".stripMargin)
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00195.jpeg)

看看前面的聚类，问自己，“这些标题看起来像是一个逻辑聚类吗？”也许需要更多的训练，或者也许我们需要考虑进一步的特征转换，比如运行 n-grammer，它可以识别高频发生的单词序列。感兴趣的人可以在 Spark 中查看 n-grammer 部分。

此外，`emp_title_cluster`列定义了一个新特征，我们将用它来替换原始的`emp_title`列。我们还需要记住在列准备过程中使用的所有步骤和模型，因为我们需要重现它们来丰富新数据。为此，Spark 管道被定义为：

```scala
import org.apache.spark.ml.Pipeline
import org.apache.spark.sql.types._

val empTitleTransformationPipeline = new Pipeline()
   .setStages(Array(
new UDFTransformer("unifier", unifyTextColumn, StringType, StringType)
       .setInputCol("emp_title").setOutputCol("emp_title_unified"),
new UDFTransformer("tokenizer",
                        tokenizeTextColumn(3)(StopWordsRemover.loadDefaultStopWords("english")),
                        StringType, ArrayType(StringType, true))
       .setInputCol("emp_title_unified").setOutputCol("emp_title_tokens"),
     empTitleW2VModel,
     empTitleKmeansModel,
new ColRemover().setKeep(false).setColumns(Array("emp_title", "emp_title_unified", "emp_title_tokens", "emp_title_w2vVector"))
   ))
```

前两个管道步骤代表了用户定义函数的应用。我们使用了与第四章中使用的相同技巧，将 UDF 包装成 Spark 管道转换器，并借助定义的`UDFTransformer`类。其余步骤代表了我们构建的模型。

定义的`UDFTransformer`类是将 UDF 包装成 Spark 管道转换器的一种好方法，但对于 Spark 来说，它是一个黑匣子，无法执行所有强大的转换。然而，它可以被 Spark SQLTransformer 的现有概念所取代，后者可以被 Spark 优化器理解；另一方面，它的使用并不那么直接。

管道仍然需要拟合；然而，在我们的情况下，由于我们只使用了 Spark 转换器，拟合操作将所有定义的阶段捆绑到管道模型中：

```scala
val empTitleTransformer = empTitleTransformationPipeline.fit(loanStatusBaseModelDf)
```

现在，是时候评估新特征对模型质量的影响了。我们将重复我们之前在评估基本模型质量时所做的相同步骤：

+   准备训练和验证部分，并用一个新特征`emp_title_cluster`来丰富它们。

+   构建模型。

+   计算总损失金额并找到最小损失。

对于第一步，我们将重用准备好的训练和验证部分；然而，我们需要用准备好的管道对它们进行转换，并丢弃“原始”列`desc`：

```scala
val trainLSBaseModel3Df = empTitleTransformer.transform(loanStatusDfSplits(0))
val validLSBaseModel3Df = empTitleTransformer.transform(loanStatusDfSplits(1))
val trainLSBaseModel3Hf = toHf(trainLSBaseModel3Df.drop("desc"), "trainLSBaseModel3Hf")(h2oContext)
val validLSBaseModel3Hf = toHf(validLSBaseModel3Df.drop("desc"), "validLSBaseModel3Hf")(h2oContext)
```

当数据准备好时，我们可以使用与基本模型训练相同的参数重复模型训练，只是我们使用准备好的输入训练部分：

```scala
loanStatusBaseModelParams._train = trainLSBaseModel3Hf._key
val loanStatusBaseModel3 = new DRF(loanStatusBaseModelParams, water.Key.makeDRFModel)
   .trainModel()
   .get()
```

最后，我们可以在验证数据上评估模型，并根据总损失金额计算我们的评估指标：

```scala
val minLossModel3 = findMinLoss(loanStatusBaseModel3, validLSBaseModel3Hf, DEFAULT_THRESHOLDS)
println(f"Min total loss for model 3: ${minLossModel3._2}%,.2f (threshold = ${minLossModel3._1})")
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00196.jpeg)

我们可以看到，利用自然语言处理技术来检测相似的职位标题略微提高了模型的质量，导致了在未知数据上计算的总美元损失的减少。然而，问题是我们是否可以根据`desc`列进一步改进我们的模型，其中可能包含有用的信息。

# desc 列转换

我们将要探索的下一列是`desc`。我们的动机仍然是从中挖掘任何可能的信息，并提高模型的质量。`desc`列包含了借款人希望贷款的纯文本描述。在这种情况下，我们不打算将它们视为分类值，因为大多数都是唯一的。然而，我们将应用自然语言处理技术来提取重要信息。与`emp_title`列相反，我们不会使用 Word2Vec 算法，而是尝试找到能够区分坏贷款和好贷款的词语。

为了达到这个目标，我们将简单地将描述分解为单独的单词（即标记化），并根据 tf-idf 赋予每个使用的单词权重，并探索哪些单词最有可能代表好贷款或坏贷款。我们可以使用词频而不是 tf-idf 值，但 tf-idf 值更好地区分了信息性词语（如“信用”）和常见词语（如“贷款”）。

让我们从我们在`emp_title`列的情况下执行的相同过程开始，定义将`desc`列转录为统一标记列表的转换：

```scala
import org.apache.spark.sql.types._
val descColUnifier = new UDFTransformer("unifier", unifyTextColumn, StringType, StringType)
   .setInputCol("desc")
.setOutputCol("desc_unified")

val descColTokenizer = new UDFTransformer("tokenizer",
                                           tokenizeTextColumn(3)(StopWordsRemover.loadDefaultStopWords("english")),
                                           StringType, ArrayType(StringType, true))
.setInputCol("desc_unified")
.setOutputCol("desc_tokens")
```

转换准备了一个包含每个输入`desc`值的单词列表的`desc_tokens`列。现在，我们需要将字符串标记转换为数字形式以构建 tf-idf 模型。在这种情况下，我们将使用`CountVectorizer`，它提取所使用的单词的词汇表，并为每一行生成一个数值向量。数值向量中的位置对应于词汇表中的单个单词，值表示出现的次数。我们希望将标记转换为数值向量，因为我们希望保留向量中的数字与表示它的标记之间的关系。与 Spark HashingTF 相反，`CountVectorizer`保留了单词与生成向量中其出现次数之间的双射关系。我们稍后将重用这种能力：

```scala
import org.apache.spark.ml.feature.CountVectorizer
val descCountVectorizer = new CountVectorizer()
   .setInputCol("desc_tokens")
   .setOutputCol("desc_vector")
   .setMinDF(1)
   .setMinTF(1)
```

定义 IDF 模型：

```scala
import org.apache.spark.ml.feature.IDF
val descIdf = new IDF()
   .setInputCol("desc_vector")
   .setOutputCol("desc_idf_vector")
   .setMinDocFreq(1)
```

当我们将所有定义的转换放入单个管道中时，我们可以直接在输入数据上训练它：

```scala
import org.apache.spark.ml.Pipeline
val descFreqPipeModel = new Pipeline()
   .setStages(
Array(descColUnifier,
           descColTokenizer,
           descCountVectorizer,
           descIdf)
   ).fit(loanStatusBaseModelDf)
```

现在，我们有一个管道模型，可以为每个输入`desc`值转换一个数值向量。此外，我们可以检查管道模型的内部，并从计算的`CountVectorizerModel`中提取词汇表，从`IDFModel`中提取单词权重：

```scala
val descFreqDf = descFreqPipeModel.transform(loanStatusBaseModelDf)
import org.apache.spark.ml.feature.IDFModel
import org.apache.spark.ml.feature.CountVectorizerModel
val descCountVectorizerModel = descFreqPipeModel.stages(2).asInstanceOf[CountVectorizerModel]
val descIdfModel = descFreqPipeModel.stages(3).asInstanceOf[IDFModel]
val descIdfScores = descIdfModel.idf.toArray
val descVocabulary = descCountVectorizerModel.vocabulary
println(
s"""
     ~Size of 'desc' column vocabulary: ${descVocabulary.length} ~Top ten highest scores:
     ~${table(descVocabulary.zip(descIdfScores).sortBy(-_._2).take(10))}
""".stripMargin('~'))
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00197.jpeg)

在这一点上，我们知道单词的权重；然而，我们仍然需要计算哪些单词被“好贷款”和“坏贷款”使用。为此，我们将利用由准备好的管道模型计算的单词频率信息，并存储在`desc_vector`列中（实际上，这是`CountVectorizer`的输出）。我们将分别为好贷款和坏贷款单独总结所有这些向量：

```scala
import org.apache.spark.ml.linalg.{Vector, Vectors}
val rowAdder = (toVector: Row => Vector) => (r1: Row, r2: Row) => {
Row(Vectors.dense((toVector(r1).toArray, toVector(r2).toArray).zipped.map((a, b) => a + b)))
 }

val descTargetGoodLoan = descFreqDf
   .where("loan_status == 'good loan'")
   .select("desc_vector")
   .reduce(rowAdder((row:Row) => row.getAsVector)).getAsVector.toArray

val descTargetBadLoan = descFreqDf
   .where("loan_status == 'bad loan'")
   .select("desc_vector")
   .reduce(rowAdder((row:Row) => row.getAsVector)).getAsVector.toArray
```

计算了值之后，我们可以轻松地找到只被好/坏贷款使用的单词，并探索它们计算出的 IDF 权重：

```scala
val descTargetsWords = descTargetGoodLoan.zip(descTargetBadLoan)
   .zip(descVocabulary.zip(descIdfScores)).map(t => (t._1._1, t._1._2, t._2._1, t._2._2))
println(
s"""
      ~Words used only in description of good loans:
      ~${table(descTargetsWords.filter(t => t._1 >0 && t._2 == 0).sortBy(-_._1).take(10))} ~
      ~Words used only in description of bad loans:
      ~${table(descTargetsWords.filter(t => t._1 == 0 && t._2 >0).sortBy(-_._1).take(10))}
""".stripMargin('~'))
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00198.jpeg)

产生的信息似乎并不有用，因为我们只得到了非常罕见的单词，这些单词只允许我们检测到一些高度特定的贷款描述。然而，我们希望更通用，并找到更常见的单词，这些单词被两种贷款类型使用，但仍然允许我们区分好坏贷款。

因此，我们需要设计一个单词得分，它将针对在好（或坏）贷款中高频使用的单词，但惩罚罕见的单词。例如，我们可以定义如下：

```scala
def descWordScore = (freqGoodLoan: Double, freqBadLoan: Double, wordIdfScore: Double) =>
   Math.abs(freqGoodLoan - freqBadLoan) * wordIdfScore * wordIdfScore
```

如果我们在词汇表中的每个单词上应用单词得分方法，我们将得到一个基于得分降序排列的单词列表：

```scala
val numOfGoodLoans = loanStatusBaseModelDf.where("loan_status == 'good loan'").count()
val numOfBadLoans = loanStatusBaseModelDf.where("loan_status == 'bad loan'").count()

val descDiscriminatingWords = descTargetsWords.filter(t => t._1 >0 && t. _2 >0).map(t => {
val freqGoodLoan = t._1 / numOfGoodLoans
val freqBadLoan = t._2 / numOfBadLoans
val word = t._3
val idfScore = t._4
       (word, freqGoodLoan*100, freqBadLoan*100, idfScore, descWordScore(freqGoodLoan, freqBadLoan, idfScore))
     })
println(
table(Seq("Word", "Freq Good Loan", "Freq Bad Loan", "Idf Score", "Score"),
     descDiscriminatingWords.sortBy(-_._5).take(100),
Map(1 ->"%.2f", 2 ->"%.2f")))
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00199.jpeg)

根据生成的列表，我们可以识别有趣的单词。我们可以选择其中的 10 个或 100 个。然而，我们仍然需要弄清楚如何处理它们。解决方案很简单；对于每个单词，我们将生成一个新的二进制特征-如果单词出现在`desc`值中，则为 1；否则为 0：

```scala
val descWordEncoder = (denominatingWords: Array[String]) => (desc: String) => {
if (desc != null) {
val unifiedDesc = unifyTextColumn(desc)
       Vectors.dense(denominatingWords.map(w =>if (unifiedDesc.contains(w)) 1.0 else 0.0))
     } else null }
```

我们可以在准备好的训练和验证样本上测试我们的想法，并衡量模型的质量。再次，第一步是准备带有新特征的增强数据。在这种情况下，新特征是一个包含由 descWordEncoder 生成的二进制特征的向量：

```scala
val trainLSBaseModel4Df = trainLSBaseModel3Df.withColumn("desc_denominating_words", descWordEncoderUdf($"desc")).drop("desc")
val validLSBaseModel4Df = validLSBaseModel3Df.withColumn("desc_denominating_words", descWordEncoderUdf($"desc")).drop("desc")
val trainLSBaseModel4Hf = toHf(trainLSBaseModel4Df, "trainLSBaseModel4Hf")
val validLSBaseModel4Hf = toHf(validLSBaseModel4Df, "validLSBaseModel4Hf")
 loanStatusBaseModelParams._train = trainLSBaseModel4Hf._key
val loanStatusBaseModel4 = new DRF(loanStatusBaseModelParams, water.Key.makeDRFModel)
   .trainModel()
   .get()
```

现在，我们只需要计算模型的质量：

```scala
val minLossModel4 = findMinLoss(loanStatusBaseModel4, validLSBaseModel4Hf, DEFAULT_THRESHOLDS)
println(f"Min total loss for model 4: ${minLossModel4._2}%,.2f (threshold = ${minLossModel4._1})")
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00200.jpeg)

我们可以看到新特征有所帮助，并提高了我们模型的精度。另一方面，它也为实验开辟了很多空间-我们可以选择不同的单词，甚至在单词是`desc`列的一部分时使用 IDF 权重而不是二进制值。

总结我们的实验，我们将比较我们产生的三个模型的计算结果：（1）基础模型，（2）在通过`emp_title`特征增强的数据上训练的模型，以及（3）在通过`desc`特征丰富的数据上训练的模型：

```scala
println(
s"""
     ~Results:
     ~${table(Seq("Threshold", "Total loss", "Profit loss", "Loan loss"),
Seq(minLossModel2, minLossModel3, minLossModel4),
Map(1 ->"%,.2f", 2 ->"%,.2f", 3 ->"%,.2f"))}
""".stripMargin('~'))
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00201.jpeg)

我们的小实验展示了特征生成的强大概念。每个新生成的特征都改善了基础模型的质量，符合我们的模型评估标准。

此时，我们可以完成对第一个模型的探索和训练，以检测好/坏贷款。我们将使用我们准备的最后一个模型，因为它给出了最好的质量。仍然有许多方法可以探索数据和提高我们的模型质量；然而，现在是构建我们的第二个模型的时候了。

# 利率模型

第二个模型预测已接受贷款的利率。在这种情况下，我们将仅使用对应于良好贷款的训练数据的部分，因为它们已经分配了适当的利率。然而，我们需要了解，剩下的坏贷款可能携带与利率预测相关的有用信息。

与其他情况一样，我们将从准备训练数据开始。我们将使用初始数据，过滤掉坏贷款，并删除字符串列：

```scala
val intRateDfSplits = loanStatusDfSplits.map(df => {
   df
     .where("loan_status == 'good loan'")
     .drop("emp_title", "desc", "loan_status")
     .withColumn("int_rate", toNumericRateUdf(col("int_rate")))
 })
val trainIRHf = toHf(intRateDfSplits(0), "trainIRHf")(h2oContext)
val validIRHf = toHf(intRateDfSplits(1), "validIRHf")(h2oContext)
```

在下一步中，我们将利用 H2O 随机超空间搜索的能力，在定义的参数超空间中找到最佳的 GBM 模型。我们还将通过额外的停止标准限制搜索，这些标准基于请求的模型精度和整体搜索时间。

第一步是定义通用的 GBM 模型构建器参数，例如训练、验证数据集和响应列：

```scala
import _root_.hex.tree.gbm.GBMModel.GBMParameters
val intRateModelParam = let(new GBMParameters()) { p =>
   p._train = trainIRHf._key
p._valid = validIRHf._key
p._response_column = "int_rate" p._score_tree_interval  = 20
}
```

下一步涉及定义要探索的参数超空间。我们可以对任何有趣的值进行编码，但请记住，搜索可能使用任何参数组合，甚至是无用的参数：

```scala
import _root_.hex.grid.{GridSearch}
import water.Key
import scala.collection.JavaConversions._
val intRateHyperSpace: java.util.Map[String, Array[Object]] = Map[String, Array[AnyRef]](
"_ntrees" -> (1 to 10).map(v => Int.box(100*v)).toArray,
"_max_depth" -> (2 to 7).map(Int.box).toArray,
"_learn_rate" ->Array(0.1, 0.01).map(Double.box),
"_col_sample_rate" ->Array(0.3, 0.7, 1.0).map(Double.box),
"_learn_rate_annealing" ->Array(0.8, 0.9, 0.95, 1.0).map(Double.box)
 )
```

现在，我们将定义如何遍历定义的参数超空间。H2O 提供两种策略：简单的笛卡尔搜索，逐步构建每个参数组合的模型，或者随机搜索，从定义的超空间中随机选择参数。令人惊讶的是，随机搜索的性能相当不错，特别是当用于探索庞大的参数空间时：

```scala
import _root_.hex.grid.HyperSpaceSearchCriteria.RandomDiscreteValueSearchCriteria
val intRateHyperSpaceCriteria = let(new RandomDiscreteValueSearchCriteria) { c =>
   c.set_stopping_metric(StoppingMetric.RMSE)
   c.set_stopping_tolerance(0.1)
   c.set_stopping_rounds(1)
   c.set_max_runtime_secs(4 * 60 /* seconds */)
 }
```

在这种情况下，我们还将通过两个停止条件限制搜索：基于 RMSE 的模型性能和整个网格搜索的最大运行时间。此时，我们已经定义了所有必要的输入，现在是启动超级搜索的时候了：

```scala
val intRateGrid = GridSearch.startGridSearch(Key.make("intRateGridModel"),
                                              intRateModelParam,
                                              intRateHyperSpace,
new GridSearch.SimpleParametersBuilderFactory[GBMParameters],
                                              intRateHyperSpaceCriteria).get()
```

搜索结果是一组称为`grid`的模型。让我们找一个具有最低 RMSE 的模型：

```scala
val intRateModel = intRateGrid.getModels.minBy(_._output._validation_metrics.rmse())
println(intRateModel._output._validation_metrics)
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00202.jpeg)

在这里，我们可以定义我们的评估标准，并选择正确的模型，不仅基于选择的模型指标，还要考虑预测值和实际值之间的差异，并优化利润。然而，我们将相信我们的搜索策略找到了最佳的可能模型，并直接跳入部署我们的解决方案。

# 使用模型进行评分

在前几节中，我们探索了不同的数据处理步骤，并构建和评估了几个模型，以预测已接受贷款的贷款状态和利率。现在，是时候使用所有构建的工件并将它们组合在一起，对新贷款进行评分了。

有多个步骤需要考虑：

1.  数据清理

1.  `emp_title`列准备管道

1.  将`desc`列转换为表示重要单词的向量

1.  用于预测贷款接受状态的二项模型

1.  用于预测贷款利率的回归模型

要重用这些步骤，我们需要将它们连接成一个单一的函数，该函数接受输入数据并生成涉及贷款接受状态和利率的预测。

评分函数很简单-它重放了我们在前几章中所做的所有步骤：

```scala
import _root_.hex.tree.drf.DRFModel
def scoreLoan(df: DataFrame,
                     empTitleTransformer: PipelineModel,
                     loanStatusModel: DRFModel,
                     goodLoanProbThreshold: Double,
                     intRateModel: GBMModel)(h2oContext: H2OContext): DataFrame = {
val inputDf = empTitleTransformer.transform(basicDataCleanup(df))
     .withColumn("desc_denominating_words", descWordEncoderUdf(col("desc")))
     .drop("desc")
val inputHf = toHf(inputDf, "input_df_" + df.hashCode())(h2oContext)
// Predict loan status and int rate
val loanStatusPrediction = loanStatusModel.score(inputHf)
val intRatePrediction = intRateModel.score(inputHf)
val probGoodLoanColName = "good loan" val inputAndPredictionsHf = loanStatusPrediction.add(intRatePrediction).add(inputHf)
   inputAndPredictionsHf.update()
// Prepare field loan_status based on threshold
val loanStatus = (threshold: Double) => (predGoodLoanProb: Double) =>if (predGoodLoanProb < threshold) "bad loan" else "good loan" val loanStatusUdf = udf(loanStatus(goodLoanProbThreshold))
   h2oContext.asDataFrame(inputAndPredictionsHf)(df.sqlContext).withColumn("loan_status", loanStatusUdf(col(probGoodLoanColName)))
 }
```

我们使用之前准备的所有定义-`basicDataCleanup`方法，`empTitleTransformer`，`loanStatusModel`，`intRateModel`-并按相应顺序应用它们。

请注意，在`scoreLoan`函数的定义中，我们不需要删除任何列。所有定义的 Spark 管道和模型只使用它们定义的特征，并保持其余部分不变。

该方法使用所有生成的工件。例如，我们可以以以下方式对输入数据进行评分：

```scala
val prediction = scoreLoan(loanStatusDfSplits(0), 
                            empTitleTransformer, 
                            loanStatusBaseModel4, 
                            minLossModel4._4, 
                            intRateModel)(h2oContext)
 prediction.show(10)
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00203.jpeg)

然而，为了独立于我们的训练代码对新贷款进行评分，我们仍然需要以某种可重复使用的形式导出训练好的模型和管道。对于 Spark 模型和管道，我们可以直接使用 Spark 序列化。例如，定义的`empTitleTransormer`可以以这种方式导出：

```scala
val MODELS_DIR = s"${sys.env.get("MODELSDIR").getOrElse("models")}" val destDir = new File(MODELS_DIR)
 empTitleTransformer.write.overwrite.save(new File(destDir, "empTitleTransformer").getAbsolutePath)
```

我们还为`desc`列定义了转换为`udf`函数`descWordEncoderUdf`。然而，我们不需要导出它，因为我们将其定义为共享库的一部分。

对于 H2O 模型，情况更加复杂，因为有几种模型导出的方式：二进制、POJO 和 MOJO。二进制导出类似于 Spark 导出；然而，要重用导出的二进制模型，需要运行 H2O 集群的实例。其他方法消除了这种限制。POJO 将模型导出为 Java 代码，可以独立于 H2O 集群进行编译和运行。最后，MOJO 导出模型以二进制形式存在，可以在不运行 H2O 集群的情况下进行解释和使用。在本章中，我们将使用 MOJO 导出，因为它简单直接，也是模型重用的推荐方法。

```scala
loanStatusBaseModel4.getMojo.writeTo(new FileOutputStream(new File(destDir, "loanStatusModel.mojo")))
 intRateModel.getMojo.writeTo(new FileOutputStream(new File(destDir, "intRateModel.mojo")))
```

我们还可以导出定义输入数据的 Spark 模式。这对于新数据的解析器的定义将很有用：

```scala
def saveSchema(schema: StructType, destFile: File, saveWithMetadata: Boolean = false) = {
import java.nio.file.{Files, Paths, StandardOpenOption}

import org.apache.spark.sql.types._
val processedSchema = StructType(schema.map {
case StructField(name, dtype, nullable, metadata) =>StructField(name, dtype, nullable, if (saveWithMetadata) metadata else Metadata.empty)
case rec => rec
    })

   Files.write(Paths.get(destFile.toURI),
               processedSchema.json.getBytes(java.nio.charset.StandardCharsets.UTF_8),
               StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.CREATE)
 }
```

```scala
saveSchema(loanDataDf.schema, new File(destDir, "inputSchema.json"))
```

请注意，`saveSchema`方法处理给定的模式并删除所有元数据。这不是常见的做法。然而，在这种情况下，我们将删除它们以节省空间。

还要提到的是，从 H2O 框架中创建数据的过程会隐式地将大量有用的统计信息附加到生成的 Spark DataFrame 上。

# 模型部署

模型部署是模型生命周期中最重要的部分。在这个阶段，模型由现实生活数据提供支持决策的结果（例如，接受或拒绝贷款）。

在本章中，我们将构建一个简单的应用程序，结合 Spark 流式处理我们之前导出的模型和共享代码库，这是我们在编写模型训练应用程序时定义的。

最新的 Spark 2.1 引入了结构化流，它建立在 Spark SQL 之上，允许我们透明地利用 SQL 接口处理流数据。此外，它以“仅一次”语义的形式带来了一个强大的特性，这意味着事件不会被丢弃或多次传递。流式 Spark 应用程序的结构与“常规”Spark 应用程序相同：

```scala
object Chapter8StreamApp extends App {

val spark = SparkSession.builder()
     .master("local[*]")
     .appName("Chapter8StreamApp")
     .getOrCreate()

script(spark,
          sys.env.get("MODELSDIR").getOrElse("models"),
          sys.env.get("APPDATADIR").getOrElse("appdata"))

def script(ssc: SparkSession, modelDir: String, dataDir: String): Unit = {
// ...
val inputDataStream = spark.readStream/* (1) create stream */

val outputDataStream = /* (2) transform inputDataStream */

 /* (3) export stream */ outputDataStream.writeStream.format("console").start().awaitTermination()
   }
 }
```

有三个重要部分：（1）输入流的创建，（2）创建流的转换，（3）写入结果流。

# 流创建

有几种方法可以创建流，Spark 文档中有描述（[`spark.apache.org/docs/2.1.1/structured-streaming-programming-guide.html)`](https://spark.apache.org/docs/2.1.1/structured-streaming-programming-guide.html)），包括基于套接字、Kafka 或基于文件的流。在本章中，我们将使用基于文件的流，指向一个目录并传递出现在目录中的所有新文件。

此外，我们的应用程序将读取 CSV 文件；因此，我们将将流输入与 Spark CSV 解析器连接。我们还需要使用从模型训练应用程序中导出的输入数据模式配置解析器。让我们先加载模式：

```scala
def loadSchema(srcFile: File): StructType = {
import org.apache.spark.sql.types.DataType
StructType(
     DataType.fromJson(scala.io.Source.fromFile(srcFile).mkString).asInstanceOf[StructType].map {
case StructField(name, dtype, nullable, metadata) =>StructField(name, dtype, true, metadata)
case rec => rec
     }
   )
 }
```

```scala
val inputSchema = Chapter8Library.loadSchema(new File(modelDir, "inputSchema.json"))
```

`loadSchema`方法通过将所有加载的字段标记为可为空来修改加载的模式。这是一个必要的步骤，以允许输入数据在任何列中包含缺失值，而不仅仅是在模型训练期间包含缺失值的列。

在下一步中，我们将直接配置一个 CSV 解析器和输入流，以从给定的数据文件夹中读取 CSV 文件：

```scala
val inputDataStream = spark.readStream
   .schema(inputSchema)
   .option("timestampFormat", "MMM-yyy")
   .option("nullValue", null)
   .CSV(s"${dataDir}/*.CSV")
```

CSV 解析器需要进行一些配置，以设置时间戳特征的格式和缺失值的表示。在这一点上，我们甚至可以探索流的结构：

```scala
inputDataStream.schema.printTreeString()
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00204.jpeg)

# 流转换

输入流发布了与 Spark DataSet 类似的接口；因此，它可以通过常规 SQL 接口或机器学习转换器进行转换。在我们的情况下，我们将重用在前几节中保存的所有训练模型和转换操作。

首先，我们将加载`empTitleTransformer`-它是一个常规的 Spark 管道转换器，可以借助 Spark 的`PipelineModel`类加载：

```scala
val empTitleTransformer = PipelineModel.load(s"${modelDir}/empTitleTransformer")
```

`loanStatus`和`intRate`模型以 H2O MOJO 格式保存。要加载它们，需要使用`MojoModel`类：

```scala
val loanStatusModel = MojoModel.load(new File(s"${modelDir}/loanStatusModel.mojo").getAbsolutePath)
val intRateModel = MojoModel.load(new File(s"${modelDir}/intRateModel.mojo").getAbsolutePath)
```

此时，我们已经准备好所有必要的工件；但是，我们不能直接使用 H2O MOJO 模型来转换 Spark 流。但是，我们可以将它们包装成 Spark transformer。我们已经在第四章中定义了一个名为 UDFTransfomer 的转换器，*使用 NLP 和 Spark Streaming 预测电影评论*，因此我们将遵循类似的模式：

```scala
class MojoTransformer(override val uid: String,
                       mojoModel: MojoModel) extends Transformer {

case class BinomialPrediction(p0: Double, p1: Double)
case class RegressionPrediction(value: Double)

implicit def toBinomialPrediction(bmp: AbstractPrediction) =
BinomialPrediction(bmp.asInstanceOf[BinomialModelPrediction].classProbabilities(0),
                        bmp.asInstanceOf[BinomialModelPrediction].classProbabilities(1))
implicit def toRegressionPrediction(rmp: AbstractPrediction) =
RegressionPrediction(rmp.asInstanceOf[RegressionModelPrediction].value)

val modelUdf = {
val epmw = new EasyPredictModelWrapper(mojoModel)
     mojoModel._category match {
case ModelCategory.Binomial =>udf[BinomialPrediction, Row] { r: Row => epmw.predict(rowToRowData(r)) }
case ModelCategory.Regression =>udf[RegressionPrediction, Row] { r: Row => epmw.predict(rowToRowData(r)) }
     }
   }

val predictStruct = mojoModel._category match {
case ModelCategory.Binomial =>StructField("p0", DoubleType)::StructField("p1", DoubleType)::Nil
case ModelCategory.Regression =>StructField("pred", DoubleType)::Nil
}

val outputCol = s"${uid}Prediction" override def transform(dataset: Dataset[_]): DataFrame = {
val inputSchema = dataset.schema
val args = inputSchema.fields.map(f => dataset(f.name))
     dataset.select(col("*"), modelUdf(struct(args: _*)).as(outputCol))
   }

private def rowToRowData(row: Row): RowData = new RowData {
     row.schema.fields.foreach(f => {
       row.getAsAnyRef match {
case v: Number => put(f.name, v.doubleValue().asInstanceOf[Object])
case v: java.sql.Timestamp => put(f.name, v.getTime.toDouble.asInstanceOf[Object])
case null =>// nop
case v => put(f.name, v)
       }
     })
   }

override def copy(extra: ParamMap): Transformer =  defaultCopy(extra)

override def transformSchema(schema: StructType): StructType =  {
val outputFields = schema.fields :+ StructField(outputCol, StructType(predictStruct), false)
     StructType(outputFields)
   }
 }
```

定义的`MojoTransformer`支持二项式和回归 MOJO 模型。它接受一个 Spark 数据集，并通过新列对其进行丰富：对于二项式模型，两列包含真/假概率，对于回归模型，一个列代表预测值。这体现在`transform`方法中，该方法使用 MOJO 包装器`modelUdf`来转换输入数据集：

dataset.select(*col*(**"*"**), *modelUdf*(*struct*(args: _*)).as(*outputCol*))

`modelUdf`模型实现了将数据表示为 Spark Row 转换为 MOJO 接受的格式，调用 MOJO 以及将 MOJO 预测转换为 Spark Row 格式的转换。

定义的`MojoTransformer`允许我们将加载的 MOJO 模型包装成 Spark transformer API：

```scala
val loanStatusTransformer = new MojoTransformer("loanStatus", loanStatusModel)
val intRateTransformer = new MojoTransformer("intRate", intRateModel)
```

此时，我们已经准备好所有必要的构建模块，并且可以将它们应用于输入流：

```scala
val outputDataStream =
   intRateTransformer.transform(
     loanStatusTransformer.transform(
       empTitleTransformer.transform(
         Chapter8Library.basicDataCleanup(inputDataStream))
         .withColumn("desc_denominating_words", descWordEncoderUdf(col("desc"))))
```

代码首先调用共享库函数`basicDataCleanup`，然后使用另一个共享库函数`descWordEncoderUdf`转换`desc`列：这两种情况都是基于 Spark DataSet SQL 接口实现的。其余步骤将应用定义的转换器。同样，我们可以探索转换后的流的结构，并验证它是否包含我们转换引入的字段：

```scala
outputDataStream.schema.printTreeString()
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00205.jpeg)

我们可以看到模式中有几个新字段：empTitle 集群的表示，命名词向量和模型预测。概率来自贷款状态模型，实际值来自利率模型。

# 流输出

Spark 为流提供了所谓的“输出接收器”。接收器定义了流如何以及在哪里写入；例如，作为 parquet 文件或作为内存表。但是，对于我们的应用程序，我们将简单地在控制台中显示流输出：

```scala
outputDataStream.writeStream.format("console").start().awaitTermination()
```

前面的代码直接启动了流处理，并等待应用程序终止。该应用程序简单地处理给定文件夹中的每个新文件（在我们的情况下，由环境变量`APPDATADIR`给出）。例如，给定一个包含五个贷款申请的文件，流会生成一个包含五个评分事件的表：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00206.jpeg)

事件的重要部分由最后一列表示，其中包含预测值：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00207.jpeg)

如果我们在文件夹中再写入一个包含单个贷款申请的文件，应用程序将显示另一个评分批次：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-ml-spark-2x/img/00208.jpeg)

通过这种方式，我们可以部署训练模型和相应的数据处理操作，并让它们评分实际事件。当然，我们只是演示了一个简单的用例；实际情况会复杂得多，涉及适当的模型验证，当前使用模型的 A/B 测试，以及模型的存储和版本控制。

# 摘要

本章总结了整本书中你学到的一切，通过端到端的示例。我们分析了数据，对其进行了转换，进行了几次实验，以找出如何设置模型训练流程，并构建了模型。本章还强调了需要良好设计的代码，可以在多个项目中共享。在我们的示例中，我们创建了一个共享库，用于训练时和评分时使用。这在称为“模型部署”的关键操作上得到了证明，训练好的模型和相关工件被用来评分未知数据。

本章还将我们带到了书的结尾。我们的目标是要展示，用 Spark 解决机器学习挑战主要是关于对数据、参数、模型进行实验，调试数据/模型相关问题，编写可测试和可重用的代码，并通过获得令人惊讶的数据洞察和观察来获得乐趣。
