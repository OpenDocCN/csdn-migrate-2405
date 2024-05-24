# Flink 学习手册（三）

> 原文：[`zh.annas-archive.org/md5/0715B65CE6CD5C69C124166C204B4830`](https://zh.annas-archive.org/md5/0715B65CE6CD5C69C124166C204B4830)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章： Flink 图 API - Gelly

我们生活在社交媒体时代，每个人都以某种方式与他人联系。每个单独的对象都与另一个对象有关系。Facebook 和 Twitter 是社交图的绝佳例子，其中*x*与*y*是朋友，*p*正在关注*q*，等等。这些图如此庞大，以至于我们需要一个能够高效处理它们的引擎。如果我们被这样的图所包围，分析它们以获取更多关于它们关系和下一级关系的见解非常重要。

市场上有各种技术可以帮助我们分析这样的图，例如 Titan 和 Neo4J 等图数据库，Spark GraphX 和 Flink Gelly 等图处理库等。在本章中，我们将了解图的细节以及如何使用 Flink Gelly 来分析图数据。

那么让我们开始吧。

# 什么是图？

在计算机科学领域，图是表示对象之间关系的一种方式。它由一组通过边连接的顶点组成。**顶点**是平面上的对象，由坐标或某个唯一的 id/name 标识，而**边**是连接顶点的链接，具有一定的权重或关系。图可以是有向的或无向的。在有向图中，边从一个顶点指向另一个顶点，而在无向图中，边没有方向。

以下图表显示了有向图的基本表示：

![什么是图？](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-flink/img/image_07_001.jpg)

图结构可以用于各种目的，例如找到到达某个目的地的最短路径，或者用于查找某些顶点之间关系的程度，或者用于查找最近的邻居。

现在让我们深入了解 Flink 的图 API - Gelly。

# Flink 图 API - Gelly

Flink 提供了一个名为 Gelly 的图处理库，以简化图分析的开发。它提供了用于存储和表示图数据的数据结构，并提供了分析图的方法。在 Gelly 中，我们可以使用 Flink 的高级函数将图从一种状态转换为另一种状态。它还提供了一组用于详细图分析的算法。

Gelly 目前作为 Flink 库的一部分可用，因此我们需要在程序中添加 Maven 依赖项才能使用它。

Java 依赖：

```java
<dependency> 
    <groupId>org.apache.flink</groupId> 
    <artifactId>flink-gelly_2.11</artifactId> 
    <version>1.1.4</version> 
</dependency> 

```

Scala 依赖：

```java
<dependency> 
    <groupId>org.apache.flink</groupId> 
    <artifactId>flink-gelly-scala_2.11</artifactId> 
    <version>1.1.4</version> 
</dependency> 

```

现在让我们看看我们有哪些选项可以有效地使用 Gelly。

## 图表示

在 Gelly 中，图被表示为节点数据集和边数据集。

### 图节点

图节点由`Vertex`数据类型表示。`Vertex`数据类型包括唯一 ID 和可选值。唯一 ID 应实现可比较接口，因为在进行图处理时，我们通过它们的 ID 进行比较。一个`Vertex`可以有一个值，也可以有一个空值。空值顶点由类型`NullValue`定义。

以下代码片段显示了如何创建节点：

在 Java 中：

```java
// A vertex with a Long ID and a String value 
Vertex<Long, String> v = new Vertex<Long, String>(1L, "foo"); 

// A vertex with a Long ID and no value 
Vertex<Long, NullValue> v = new Vertex<Long, NullValue>(1L, NullValue.getInstance()); 

```

在 Scala 中：

```java
// A vertex with a Long ID and a String value 
val v = new Vertex(1L, "foo") 

// A vertex with a Long ID and no value 
val v = new Vertex(1L, NullValue.getInstance()) 

```

### 图边

同样，边可以由类型`Edge`定义。`Edge`具有源节点 ID、目标节点 ID 和可选值。该值表示关系的程度或权重。源和目标 ID 需要是相同类型的。没有值的边可以使用`NullValue`定义。

以下代码片段显示了 Java 和 Scala 中的`Edge`定义：

在 Java 中：

```java
// Edge connecting Vertices with Ids 1 and 2 having weight 0.5 

Edge<Long, Double> e = new Edge<Long, Double>(1L, 2L, 0.5); 

Double weight = e.getValue(); // weight = 0.5 

```

在 Scala 中：

```java
// Edge connecting Vertices with Ids 1 and 2 having weight 0.5 

val e = new Edge(1L, 2L, 0.5) 

val weight = e.getValue // weight = 0.5 

```

在 Gelly 中，图始终是从源顶点到目标顶点的有向的。为了显示无向图，我们应该添加另一条边，表示从目标到源的连接和返回。

以下代码片段表示了 Gelly 中的有向图：

在 Java 中：

```java
// A vertex with a Long ID and a String value 
Vertex<Long, String> v1 = new Vertex<Long, String>(1L, "foo"); 

// A vertex with a Long ID and a String value 
Vertex<Long, String> v2 = new Vertex<Long, String>(2L, "bar"); 

// Edge connecting Vertices with Ids 1 and 2 having weight 0.5 

Edge<Long, Double> e = new Edge<Long, Double>(1L, 2L, 0.5); 

```

在 Scala 中：

```java
// A vertex with a Long ID and a String value 
val v1 = new Vertex(1L, "foo") 

// A vertex with a Long ID and a String value 
val v2 = new Vertex(1L, "bar") 

// Edge connecting Vertices with Ids 1 and 2 having weight 0.5 

val e = new Edge(1L, 2L, 0.5) 

```

以下是它的可视化表示：

![图边](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-flink/img/image_07_002.jpg)

以下代码片段表示了 Gelly 中无向图的顶点和边的定义：

在 Java 中：

```java
// A vertex with a Long ID and a String value 
Vertex<Long, String> v1 = new Vertex<Long, String>(1L, "foo"); 

// A vertex with a Long ID and a String value 
Vertex<Long, String> v2 = new Vertex<Long, String>(2L, "bar"); 

// Edges connecting Vertices with Ids 1 and 2 having weight 0.5 

Edge<Long, Double> e1 = new Edge<Long, Double>(1L, 2L, 0.5); 

Edge<Long, Double> e2 = new Edge<Long, Double>(2L, 1L, 0.5); 

```

在 Scala 中：

```java
// A vertex with a Long ID and a String value 
val v1 = new Vertex(1L, "foo") 

// A vertex with a Long ID and a String value 
val v2 = new Vertex(1L, "bar") 

// Edges connecting Vertices with Ids 1 and 2 having weight 0.5 

val e1 = new Edge(1L, 2L, 0.5) 

val e2 = new Edge(2L, 1L, 0.5) 

```

以下是其相同的可视表示：

![Graph edges](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-flink/img/image_07_003.jpg)

## 图创建

在 Flink Gelly 中，可以以多种方式创建图。以下是一些示例。

### 来自边和顶点数据集

以下代码片段表示我们如何使用边数据集和可选顶点创建图：

在 Java 中：

```java
ExecutionEnvironment env = ExecutionEnvironment.getExecutionEnvironment(); 

DataSet<Vertex<String, Long>> vertices = ... 

DataSet<Edge<String, Double>> edges = ... 

Graph<String, Long, Double> graph = Graph.fromDataSet(vertices, edges, env); 

```

在 Scala 中：

```java
val env = ExecutionEnvironment.getExecutionEnvironment 

val vertices: DataSet[Vertex[String, Long]] = ... 

val edges: DataSet[Edge[String, Double]] = ... 

val graph = Graph.fromDataSet(vertices, edges, env) 

```

### 来自表示边的元组数据集

以下代码片段表示我们如何使用表示边的 Tuple2 数据集创建图。在这里，Gelly 会自动将 Tuple2 转换为具有源和目标顶点 ID 以及空值的边。

在 Java 中：

```java
ExecutionEnvironment env = ExecutionEnvironment.getExecutionEnvironment(); 

DataSet<Tuple2<String, String>> edges = ... 

Graph<String, NullValue, NullValue> graph = Graph.fromTuple2DataSet(edges, env); 

```

在 Scala 中：

```java
val env = ExecutionEnvironment.getExecutionEnvironment 

val edges: DataSet[(String, String)] = ... 

val graph = Graph.fromTuple2DataSet(edges, env) 

```

以下代码片段表示我们如何使用表示边的 Tuple3 数据集创建图。这里，顶点使用 Tuple2 表示，而边使用 Tuple3 表示，包含有关源顶点、目标顶点和权重的信息。我们还可以从 CSV 文件中读取一组值：

在 Java 中：

```java
ExecutionEnvironment env = ExecutionEnvironment.getExecutionEnvironment(); 

DataSet<Tuple2<String, Long>> vertexTuples = env.readCsvFile("path/to/vertex/input.csv").types(String.class, Long.class); 

DataSet<Tuple3<String, String, Double>> edgeTuples = env.readCsvFile("path/to/edge/input.csv").types(String.class, String.class, Double.class); 

Graph<String, Long, Double> graph = Graph.fromTupleDataSet(vertexTuples, edgeTuples, env); 

```

在 Scala 中：

```java
val env = ExecutionEnvironment.getExecutionEnvironment 

val vertexTuples = env.readCsvFileString, Long 

val edgeTuples = env.readCsvFileString, String, Double 

val graph = Graph.fromTupleDataSet(vertexTuples, edgeTuples, env) 

```

### 来自 CSV 文件

以下代码片段表示我们如何使用 CSV 文件读取器创建图。CSV 文件应以顶点和边的形式表示数据。

以下代码片段创建了一个图，该图来自 CSV 文件，格式为边的源、目标、权重，以及顶点的 ID、名称：

```java
val env = ExecutionEnvironment.getExecutionEnvironment 

// create a Graph with String Vertex IDs, Long Vertex values and Double Edge values 
val graph = Graph.fromCsvReaderString, Long, Double 

```

我们还可以通过在创建图时定义`map`函数来使用顶点值初始化程序：

```java
val simpleGraph = Graph.fromCsvReaderLong, Double, NullValue { 
            def map(id: Long): Double = { 
                id.toDouble 
            } 
        }, 
        env = env) 

```

### 来自集合列表

我们还可以从列表集合创建图。以下代码片段显示了我们如何从边和顶点列表创建图：

在 Java 中：

```java
ExecutionEnvironment env = ExecutionEnvironment.getExecutionEnvironment(); 

List<Vertex<Long, Long>> vertexList = new ArrayList... 

List<Edge<Long, String>> edgeList = new ArrayList... 

Graph<Long, Long, String> graph = Graph.fromCollection(vertexList, edgeList, env); 

```

在 Scala 中：

```java
val env = ExecutionEnvironment.getExecutionEnvironment 

val vertexList = List(...) 

val edgeList = List(...) 

val graph = Graph.fromCollection(vertexList, edgeList, env) 

```

如果没有提供顶点输入，则可以考虑提供一个`map`初始化函数，如下所示：

```java
val env = ExecutionEnvironment.getExecutionEnvironment 

// initialize the vertex value to be equal to the vertex ID 
val graph = Graph.fromCollection(edgeList, 
    new MapFunction[Long, Long] { 
       def map(id: Long): Long = id 
    }, env)
```

## 图属性

以下表格显示了用于检索图属性的一组可用方法：

| **属性** | **在 Java 中** | **在 Scala 中** |
| --- | --- | --- |
| `getVertices`数据集 | `DataSet<Vertex<K, VV>> getVertices()` | `getVertices: DataSet[Vertex<K, VV>]` |
| `getEdges`数据集 | `DataSet<Edge<K, EV>> getEdges()` | `getEdges: DataSet[Edge<K, EV>]` |
| `getVertexIds` | `DataSet<K> getVertexIds()` | `getVertexIds: DataSet[K]` |
| `getEdgeIds` | `DataSet<Tuple2<K, K>> getEdgeIds()` | `getEdgeIds: DataSet[(K, K)]` |
| 获取顶点 ID 和所有顶点的`inDegrees`数据集 | `DataSet<Tuple2<K, LongValue>> inDegrees()` | `inDegrees: DataSet[(K, LongValue)]` |
| 获取顶点 ID 和所有顶点的`outDegrees`数据集 | `DataSet<Tuple2<K, LongValue>> outDegrees()` | `outDegrees: DataSet[(K, LongValue)]` |
| 获取顶点 ID 和所有顶点的 in、`getDegree`数据集 | `DataSet<Tuple2<K, LongValue>> getDegrees()` | `getDegrees: DataSet[(K, LongValue)]` |
| 获取`numberOfVertices` | `long numberOfVertices()` | `numberOfVertices: Long` |
| 获取`numberOfEdges` | `long numberOfEdges()` | `numberOfEdges: Long` |
| `getTriplets`提供了由源顶点、目标顶点和边组成的三元组 | `DataSet<Triplet<K, VV, EV>> getTriplets()` | `getTriplets: DataSet[Triplet<K, VV, EV>]` |

## 图转换

Gelly 提供了各种转换操作，可帮助将图从一种形式转换为另一种形式。以下是我们可以使用 Gelly 进行的一些转换。

### 映射

Gelly 提供了保持顶点和边 ID 不变并根据函数中给定的值转换值的映射转换。此操作始终返回一个新图。以下代码片段显示了如何使用它。

在 Java 中：

```java
ExecutionEnvironment env = ExecutionEnvironment.getExecutionEnvironment(); 
Graph<Long, Long, Long> graph = Graph.fromDataSet(vertices, edges, env); 

// increment each vertex value by 5 
Graph<Long, Long, Long> updatedGraph = graph.mapVertices( 
        new MapFunction<Vertex<Long, Long>, Long>() { 
          public Long map(Vertex<Long, Long> value) { 
            return value.getValue() + 5; 
          } 
        }); 

```

在 Scala 中：

```java
val env = ExecutionEnvironment.getExecutionEnvironment 
val graph = Graph.fromDataSet(vertices, edges, env) 

// increment each vertex value by 5 
val updatedGraph = graph.mapVertices(v => v.getValue + 5) 

```

### 翻译

Translate 是一种特殊函数，允许翻译顶点 ID、顶点值、边 ID 等。翻译是使用用户提供的自定义映射函数执行的。以下代码片段显示了我们如何使用 translate 函数。

在 Java 中：

```java
// translate each vertex and edge ID to a String 
Graph<String, Long, Long> updatedGraph = graph.translateGraphIds( 
        new MapFunction<Long, String>() { 
          public String map(Long id) { 
            return id.toString(); 
          } 
        }); 

// translate vertex IDs, edge IDs, vertex values, and edge values to LongValue 
Graph<LongValue, LongValue, LongValue> updatedGraph = graph 
                .translateGraphIds(new LongToLongValue()) 
                .translateVertexValues(new LongToLongValue()) 
                .translateEdgeValues(new LongToLongValue()) 

```

在 Scala 中：

```java
// translate each vertex and edge ID to a String 
val updatedGraph = graph.translateGraphIds(id => id.toString) 

```

### 过滤

`FilterFunction`可用于根据某些条件过滤顶点和边。`filterOnEdges`将创建原始图的子图。在此操作中，顶点数据集保持不变。同样，`filterOnVertices`对顶点值应用过滤器。在这种情况下，找不到目标节点的边将被移除。以下代码片段显示了我们如何在 Gelly 中使用`FilterFunction`。

在 Java 中：

```java
Graph<Long, Long, Long> graph = ... 

graph.subgraph( 
    new FilterFunction<Vertex<Long, Long>>() { 
           public boolean filter(Vertex<Long, Long> vertex) { 
          // keep only vertices with positive values 
          return (vertex.getValue() > 2); 
         } 
       }, 
    new FilterFunction<Edge<Long, Long>>() { 
        public boolean filter(Edge<Long, Long> edge) { 
          // keep only edges with negative values 
          return (edge.getTarget() == 3); 
        } 
    }) 

```

在 Scala 中：

```java
val graph: Graph[Long, Long, Long] = ... 
graph.subgraph((vertex => vertex.getValue > 2), (edge => edge.getTarget == 3)) 

```

以下是前述代码的图形表示：

![Filter](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-flink/img/image_07_004.jpg)

同样，以下图表显示了`filterOnEdges`：

![Filter](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-flink/img/image_07_005.jpg)

### 连接

`join`操作有助于将顶点和边数据集与其他数据集进行连接。`joinWithVertices`方法与顶点 ID 和 Tuple2 的第一个字段进行连接。`join`方法返回一个新的图。同样，输入数据集可以与边进行连接。我们可以通过三种方式连接边：

+   `joinWithEdges`：在源和目标顶点 ID 的复合键上与 Tuple3 数据集进行连接

+   `joinWithEdgeOnSource`：与 Tuple2 数据集在源键和 Tuple2 数据集的第一个属性上进行连接

+   `joinWithEdgeOnTarget`：与目标键和 Tuple2 数据集的第一个属性进行连接

以下代码片段显示了如何在 Gelly 中使用连接：

在 Java 中：

```java
Graph<Long, Double, Double> network = ... 

DataSet<Tuple2<Long, LongValue>> vertexOutDegrees = network.outDegrees(); 

// assign the transition probabilities as the edge weights 
Graph<Long, Double, Double> networkWithWeights = network.joinWithEdgesOnSource(vertexOutDegrees, 
        new VertexJoinFunction<Double, LongValue>() { 
          public Double vertexJoin(Double vertexValue, LongValue inputValue) { 
            return vertexValue / inputValue.getValue(); 
          } 
        }); 

```

在 Scala 中：

```java
val network: Graph[Long, Double, Double] = ... 

val vertexOutDegrees: DataSet[(Long, LongValue)] = network.outDegrees 
// assign the transition probabilities as the edge weights 

val networkWithWeights = network.joinWithEdgesOnSource(vertexOutDegrees, (v1: Double, v2: LongValue) => v1 / v2.getValue) 

```

### 反向

`reverse`方法返回一个边方向被颠倒的图。

以下代码片段显示了如何使用相同的方法：

在 Java 中：

```java
Graph<Long, Double, Double> network = ...; 
Graph<Long, Double, Double> networkReverse  = network.reverse(); 

```

在 Scala 中：

```java
val network: Graph[Long, Double, Double] = ... 
val networkReversed: Graph[Long, Double, Double] = network.reverse  

```

### 无向的

`undirected`方法返回一个具有与原始边相反的额外边的新图。

以下代码片段显示了如何使用相同的方法：

在 Java 中：

```java
Graph<Long, Double, Double> network = ...; 
Graph<Long, Double, Double> networkUD  = network.undirected(); 

```

在 Scala 中：

```java
val network: Graph[Long, Double, Double] = ... 
val networkUD: Graph[Long, Double, Double] = network.undirected 

```

### 联合

`union`操作返回一个组合了两个图的顶点和边的图。它在顶点 ID 上进行连接。重复的顶点将被移除，而边将被保留。

以下是`union`操作的图形表示：

![Union](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-flink/img/image_07_006.jpg)

### 相交

`intersect`方法执行给定图数据集的边的交集。如果两条边具有相同的源和目标顶点，则它们被视为相等。该方法还包含 distinct 参数；如果设置为`true`，它只返回不同的图。以下是一些代码片段，展示了`intersect`方法的用法。

在 Java 中：

```java
ExecutionEnvironment env = ExecutionEnvironment.getExecutionEnvironment(); 

// create first graph from edges {(1, 2, 10) (1, 2, 11), (1, 2, 10)} 
List<Edge<Long, Long>> edges1 = ... 
Graph<Long, NullValue, Long> graph1 = Graph.fromCollection(edges1, env); 

// create second graph from edges {(1, 2, 10)} 
List<Edge<Long, Long>> edges2 = ... 
Graph<Long, NullValue, Long> graph2 = Graph.fromCollection(edges2, env); 

// Using distinct = true results in {(1,2,10)} 
Graph<Long, NullValue, Long> intersect1 = graph1.intersect(graph2, true); 

// Using distinct = false results in {(1,2,10),(1,2,10)} as there is one edge pair 
Graph<Long, NullValue, Long> intersect2 = graph1.intersect(graph2, false); 

```

在 Scala 中：

```java
val env = ExecutionEnvironment.getExecutionEnvironment 

// create first graph from edges {(1, 2, 10) (1, 2, 11), (1, 2, 10)} 
val edges1: List[Edge[Long, Long]] = ... 
val graph1 = Graph.fromCollection(edges1, env) 

// create second graph from edges {(1, 2, 10)} 
val edges2: List[Edge[Long, Long]] = ... 
val graph2 = Graph.fromCollection(edges2, env) 

// Using distinct = true results in {(1,2,10)} 
val intersect1 = graph1.intersect(graph2, true) 

// Using distinct = false results in {(1,2,10),(1,2,10)} as there is one edge pair 
val intersect2 = graph1.intersect(graph2, false) 

```

## 图变异

Gelly 提供了向现有图添加/移除边和顶点的方法。让我们逐一了解这些变异。

| **变异** | **在 Java 中** | **在 Scala 中** |
| --- | --- | --- |
| 添加顶点。`Graph<K, VV, EV> addVertex(final Vertex<K, VV> vertex)` `addVertex(vertex: Vertex[K, VV])` |
| 添加顶点列表。`Graph<K, VV, EV> addVertices(List<Vertex<K, VV>> verticesToAdd)` `addVertices(verticesToAdd: List[Vertex[K, VV]])` |
| 向图中添加边。如果边和顶点不存在，则添加新的边和顶点。`Graph<K, VV, EV> addEdge(Vertex<K, VV> source, Vertex<K, VV> target, EV edgeValue)` `addEdge(source: Vertex[K, VV], target: Vertex[K, VV], edgeValue: EV)` |
| 添加边，如果顶点不存在，则该边被视为无效。`Graph<K, VV, EV> addEdges(List<Edge<K, EV>> newEdges)` `addEdges(edges: List[Edge[K, EV]])` |
| 从给定的图中移除顶点，移除边和顶点。`Graph<K, VV, EV> removeVertex(Vertex<K, VV> vertex)` `removeVertex(vertex: Vertex[K, VV])` |
| 从给定的图中移除多个顶点。`Graph<K, VV, EV> removeVertices(List<Vertex<K, VV>> verticesToBeRemoved)` `removeVertices(verticesToBeRemoved: List[Vertex[K, VV]])` |
| 移除与给定边匹配的所有边。`Graph<K, VV, EV> removeEdge(Edge<K, EV> edge)` `removeEdge(edge: Edge[K, EV])` |
| 移除与给定边列表匹配的边。`Graph<K, VV, EV> removeEdges(List<Edge<K, EV>> edgesToBeRemoved)` `removeEdges(edgesToBeRemoved: List[Edge[K, EV]])` |

## 邻域方法

邻域方法有助于执行与其第一跳邻域相关的操作。诸如`reduceOnEdges()`和`reduceOnNeighbours()`之类的方法可用于执行聚合操作。第一个用于计算顶点相邻边的聚合，而后者用于计算相邻顶点的聚合。邻居范围可以通过提供边方向来定义，我们有选项，如`IN`，`OUT`或`ALL`。

考虑一个例子，我们需要获取`OUT`方向边的所有顶点的最大权重：

![邻域方法](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-flink/img/image_07_007.jpg)

现在我们想要找出每个顶点的最大加权`OUT`边。Gelly 为我们提供了邻域方法，我们可以用它找到所需的结果。以下是相同的代码片段：

在 Java 中：

```java
Graph<Long, Long, Double> graph = ... 

DataSet<Tuple2<Long, Double>> maxWeights = graph.reduceOnEdges(new SelectMaxWeight(), EdgeDirection.OUT); 

// user-defined function to select the max weight 
static final class SelectMaxWeight implements ReduceEdgesFunction<Double> { 

    @Override 
    public Double reduceEdges(Double firstEdgeValue, Double secondEdgeValue) { 
      return Math.max(firstEdgeValue, secondEdgeValue); 
    } 
} 

```

在 Scala 中：

```java
val graph: Graph[Long, Long, Double] = ... 

val minWeights = graph.reduceOnEdges(new SelectMaxWeight, EdgeDirection.OUT) 

// user-defined function to select the max weight 
final class SelectMaxWeight extends ReduceEdgesFunction[Double] { 
  override def reduceEdges(firstEdgeValue: Double, secondEdgeValue: Double): Double = { 
    Math.max(firstEdgeValue, secondEdgeValue) 
  } 
 } 

```

Gelly 通过首先分离每个顶点并找出每个顶点的最大加权边来解决这个问题。以下是相同的图形表示：

![邻域方法](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-flink/img/image_07_008.jpg)

同样，我们也可以编写一个函数来计算所有邻域中传入边的值的总和。

在 Java 中：

```java
Graph<Long, Long, Double> graph = ... 

DataSet<Tuple2<Long, Long>> verticesWithSum = graph.reduceOnNeighbors(new SumValues(), EdgeDirection.IN); 

static final class SumValues implements ReduceNeighborsFunction<Long> { 

        @Override 
        public Long reduceNeighbors(Long firstNeighbor, Long secondNeighbor) { 
          return firstNeighbor + secondNeighbor; 
      } 
} 

```

在 Scala 中：

```java
val graph: Graph[Long, Long, Double] = ... 

val verticesWithSum = graph.reduceOnNeighbors(new SumValues, EdgeDirection.IN) 

final class SumValues extends ReduceNeighborsFunction[Long] { 
     override def reduceNeighbors(firstNeighbor: Long, secondNeighbor: Long): Long = { 
      firstNeighbor + secondNeighbor 
    } 
} 

```

## 图验证

Gelly 为我们提供了一个实用程序，在将其发送进行处理之前验证输入图。在各种情况下，我们首先需要验证图是否符合某些条件，然后才能将其发送进行进一步处理。验证可能是检查图是否包含重复边或检查图结构是否为二部图。

### 注意

二部图或双图是一个图，其顶点可以分为两个不同的集合，以便每个集合中的每个顶点都与另一个集合中的顶点相连。二部图的一个简单例子是篮球运动员和他们所效力的球队的图。在这里，我们将有两个集合，分别是球员和球队，每个球员集合中的顶点都将与球队集合中的顶点相连。有关二部图的更多细节，请阅读这里[`en.wikipedia.org/wiki/Bipartite_graph`](https://en.wikipedia.org/wiki/Bipartite_graph)。

我们也可以定义自定义验证方法来获得所需的输出。Gelly 还提供了一个名为`InvalidVertexValidator`的内置验证器。这将检查边集是否包含验证顶点 ID。以下是一些展示其用法的代码片段。

在 Java 中：

```java
Graph<Long, Long, Long> graph = Graph.fromCollection(vertices, edges, env); 

// Returns false for invalid vertex id.  
graph.validate(new InvalidVertexIdsValidator<Long, Long, Long>()); 

```

在 Scala 中：

```java
val graph = Graph.fromCollection(vertices, edges, env) 

// Returns false for invalid vertex id.  
graph.validate(new InvalidVertexIdsValidator[Long, Long, Long]) 

```

# 迭代图处理

Gelly 增强了 Flink 的迭代处理能力，以支持大规模图处理。目前它支持以下模型的实现：

+   顶点中心

+   分散-聚集

+   聚集-求和-应用

让我们首先在 Gelly 的背景下理解这些模型。

## 顶点中心迭代

正如名称所示，这些迭代是建立在顶点处于中心的思想上。在这里，每个顶点并行处理相同的用户定义函数。执行的每一步被称为**超集**。只要顶点知道其唯一 ID，它就可以向另一个顶点发送消息。这个消息将被用作下一个超集的输入。

要使用顶点中心迭代，用户需要提供一个`ComputeFunction`。我们还可以定义一个可选的`MessageCombiner`来减少通信成本。我们可以解决问题，比如单源最短路径，在这种情况下，我们需要找到从源顶点到所有其他顶点的最短路径。

### 注意

单源最短路径是我们试图最小化连接两个不同顶点的权重之和。一个非常简单的例子可能是城市和航班路线的图。在这种情况下，SSSP 算法将尝试找到连接两个城市的最短距离，考虑到可用的航班路线。有关 SSSP 的更多细节，请参阅[`en.wikipedia.org/wiki/Shortest_path_problem`](https://en.wikipedia.org/wiki/Shortest_path_problem)。

以下代码片段展示了我们如何使用 Gelly 解决单源最短路径问题。

在 Java 中：

```java
// maximum number of iterations 
int maxIterations = 5; 

// Run vertex-centric iteration 
Graph<Long, Double, Double> result = graph.runVertexCentricIteration( 
            new SSSPComputeFunction(), new SSSPCombiner(), maxIterations); 

// Extract the vertices as the result 
DataSet<Vertex<Long, Double>> singleSourceShortestPaths = result.getVertices(); 

//User defined compute function to minimize the distance between //the vertices 

public static final class SSSPComputeFunction extends ComputeFunction<Long, Double, Double, Double> { 

public void compute(Vertex<Long, Double> vertex, MessageIterator<Double> messages) { 

    double minDistance = (vertex.getId().equals(srcId)) ? 0d : Double.POSITIVE_INFINITY; 

    for (Double msg : messages) { 
        minDistance = Math.min(minDistance, msg); 
    } 

    if (minDistance < vertex.getValue()) { 
        setNewVertexValue(minDistance); 
        for (Edge<Long, Double> e: getEdges()) { 
            sendMessageTo(e.getTarget(), minDistance + e.getValue()); 
        } 
    } 
} 

// message combiner helps in optimizing the communications 
public static final class SSSPCombiner extends MessageCombiner<Long, Double> { 

    public void combineMessages(MessageIterator<Double> messages) { 

        double minMessage = Double.POSITIVE_INFINITY; 
        for (Double msg: messages) { 
           minMessage = Math.min(minMessage, msg); 
        } 
        sendCombinedMessage(minMessage); 
    } 
} 

```

在 Scala 中：

```java
// maximum number of iterations 
val maxIterations = 5 

// Run the vertex-centric iteration 
val result = graph.runVertexCentricIteration(new SSSPComputeFunction, new SSSPCombiner, maxIterations) 

// Extract the vertices as the result 
val singleSourceShortestPaths = result.getVertices 

//User defined compute function to minimize the distance between //the vertices 

final class SSSPComputeFunction extends ComputeFunction[Long, Double, Double, Double] { 

    override def compute(vertex: Vertex[Long, Double], messages:   
    MessageIterator[Double]) = { 

    var minDistance = if (vertex.getId.equals(srcId)) 0 else  
    Double.MaxValue 

    while (messages.hasNext) { 
        val msg = messages.next 
        if (msg < minDistance) { 
            minDistance = msg 
        } 
    } 

    if (vertex.getValue > minDistance) { 
        setNewVertexValue(minDistance) 
        for (edge: Edge[Long, Double] <- getEdges) { 
            sendMessageTo(edge.getTarget, vertex.getValue +  
            edge.getValue) 
        } 
    } 
} 

// message combiner helps in optimizing the communications 
final class SSSPCombiner extends MessageCombiner[Long, Double] { 

    override def combineMessages(messages: MessageIterator[Double]) { 

        var minDistance = Double.MaxValue 

        while (messages.hasNext) { 
          val msg = inMessages.next 
          if (msg < minDistance) { 
            minDistance = msg 
          } 
        } 
        sendCombinedMessage(minMessage) 
    } 
} 

```

我们可以在顶点中心迭代中使用以下配置。

| **参数** | **描述** |
| --- | --- |
| 名称：`setName()` | 设置顶点中心迭代的名称。可以在日志中看到。 |
| 并行度：`setParallelism()` | 设置并行执行的并行度。 |
| 广播变量：`addBroadcastSet()` | 将广播变量添加到计算函数中。 |
| 聚合器：`registerAggregator()` | 注册自定义定义的聚合器函数，供计算函数使用。 |
| 未管理内存中的解集：`setSolutionSetUnmanagedMemory()` | 定义解集是否保存在受控内存中。 |

## Scatter-Gather 迭代

Scatter-Gather 迭代也适用于超集迭代，并且在其中心也有一个顶点，我们还定义了一个并行执行的函数。在这里，每个顶点有两件重要的事情要做：

+   **Scatter**：Scatter 生成需要发送到其他顶点的消息

+   **Gather**：Gather 从收到的消息中更新顶点值

Gelly 提供了 scatter 和 gather 的方法。用户只需实现这两个函数即可利用这些迭代。`ScatterFunction`为其余顶点生成消息，而`GatherFunction`根据收到的消息计算顶点的更新值。

以下代码片段显示了如何使用 Gelly-Scatter-Gather 迭代解决单源最短路径问题：

在 Java 中：

```java
// maximum number of iterations 
int maxIterations = 5; 

// Run the scatter-gather iteration 
Graph<Long, Double, Double> result = graph.runScatterGatherIteration( 
      new MinDistanceMessenger(), new VertexDistanceUpdater(), maxIterations); 

// Extract the vertices as the result 
DataSet<Vertex<Long, Double>> singleSourceShortestPaths = result.getVertices(); 

// Scatter Gather function definition  

// Through scatter function, we send distances from each vertex 
public static final class MinDistanceMessenger extends ScatterFunction<Long, Double, Double, Double> { 

  public void sendMessages(Vertex<Long, Double> vertex) { 
    for (Edge<Long, Double> edge : getEdges()) { 
      sendMessageTo(edge.getTarget(), vertex.getValue() + edge.getValue()); 
    } 
  } 
} 

// In gather function, we gather messages sent in previous //superstep to find out the minimum distance.  
public static final class VertexDistanceUpdater extends GatherFunction<Long, Double, Double> { 

  public void updateVertex(Vertex<Long, Double> vertex, MessageIterator<Double> inMessages) { 
    Double minDistance = Double.MAX_VALUE; 

    for (double msg : inMessages) { 
      if (msg < minDistance) { 
        minDistance = msg; 
      } 
    } 

    if (vertex.getValue() > minDistance) { 
      setNewVertexValue(minDistance); 
    } 
  } 
} 

```

在 Scala 中：

```java
// maximum number of iterations 
val maxIterations = 5 

// Run the scatter-gather iteration 
val result = graph.runScatterGatherIteration(new MinDistanceMessenger, new VertexDistanceUpdater, maxIterations) 

// Extract the vertices as the result 
val singleSourceShortestPaths = result.getVertices 

// Scatter Gather definitions 

// Through scatter function, we send distances from each vertex 
final class MinDistanceMessenger extends ScatterFunction[Long, Double, Double, Double] { 

  override def sendMessages(vertex: Vertex[Long, Double]) = { 
    for (edge: Edge[Long, Double] <- getEdges) { 
      sendMessageTo(edge.getTarget, vertex.getValue + edge.getValue) 
    } 
  } 
} 

// In gather function, we gather messages sent in previous //superstep to find out the minimum distance.  
final class VertexDistanceUpdater extends GatherFunction[Long, Double, Double] { 

  override def updateVertex(vertex: Vertex[Long, Double], inMessages: MessageIterator[Double]) = { 
    var minDistance = Double.MaxValue 

    while (inMessages.hasNext) { 
      val msg = inMessages.next 
      if (msg < minDistance) { 
      minDistance = msg 
      } 
    } 

    if (vertex.getValue > minDistance) { 
      setNewVertexValue(minDistance) 
    } 
  } 
} 

```

我们可以使用以下参数配置 Scatter-Gather 迭代：

| 参数 | 描述 |
| --- | --- |
| 名称：`setName()` | 设置 scatter-gather 迭代的名称。可以在日志中看到。 |
| 并行度：`setParallelism()` | 设置并行执行的并行度。 |
| 广播变量：`addBroadcastSet()` | 将广播变量添加到计算函数中。 |
| 聚合器：`registerAggregator()` | 注册自定义定义的聚合器函数，供计算函数使用。 |
| 未管理内存中的解集：`setSolutionSetUnmanagedMemory()` | 定义解集是否保存在受控内存中。 |
| 顶点数量：`setOptNumVertices()` | 访问迭代中顶点的总数。 |
| 度数：`setOptDegrees()` | 设置在迭代中要达到的入/出度数。 |
| 消息方向：`setDirection()` | 默认情况下，我们只考虑出度进行处理，但我们可以通过设置此属性来更改。选项有`in`、`out`和`all`。 |

## Gather-Sum-Apply 迭代

与前两个模型一样，**Gather-Sum-Apply**（**GSA**）迭代也在迭代步骤中同步。每个超集包括以下步骤：

1.  **Gather**：在边和每个邻居上执行用户定义的函数，生成部分值。

1.  **Sum**：在早期步骤中计算的部分值将在此步骤中聚合。

1.  **Apply**：通过将上一步的聚合值和当前值应用于顶点值来更新每个顶点值。

我们将尝试使用 GSA 迭代来解决单源最短路径问题。要使用此功能，我们需要为 gather、sum 和 apply 定义自定义函数。

在 Java 中：

```java
// maximum number of iterations 
int maxIterations = 5; 

// Run the GSA iteration 
Graph<Long, Double, Double> result = graph.runGatherSumApplyIteration( 
        new CalculateDistances(), new ChooseMinDistance(), new UpdateDistance(), maxIterations); 

// Extract the vertices as the result 
DataSet<Vertex<Long, Double>> singleSourceShortestPaths = result.getVertices(); 

// Functions for GSA 

// Gather 
private static final class CalculateDistances extends GatherFunction<Double, Double, Double> { 

  public Double gather(Neighbor<Double, Double> neighbor) { 
    return neighbor.getNeighborValue() + neighbor.getEdgeValue(); 
  } 
} 

// Sum 
private static final class ChooseMinDistance extends SumFunction<Double, Double, Double> { 

  public Double sum(Double newValue, Double currentValue) { 
    return Math.min(newValue, currentValue); 
  } 
} 

// Apply 
private static final class UpdateDistance extends ApplyFunction<Long, Double, Double> { 

  public void apply(Double newDistance, Double oldDistance) { 
    if (newDistance < oldDistance) { 
      setResult(newDistance); 
    } 
  } 
} 

```

在 Scala 中：

```java
// maximum number of iterations 
val maxIterations = 10 

// Run the GSA iteration 
val result = graph.runGatherSumApplyIteration(new CalculateDistances, new ChooseMinDistance, new UpdateDistance, maxIterations) 

// Extract the vertices as the result 
val singleSourceShortestPaths = result.getVertices 

// Custom function for GSA 

// Gather 
final class CalculateDistances extends GatherFunction[Double, Double, Double] { 

  override def gather(neighbor: Neighbor[Double, Double]): Double = { 
    neighbor.getNeighborValue + neighbor.getEdgeValue 
  } 
} 

// Sum 
final class ChooseMinDistance extends SumFunction[Double, Double, Double] { 

  override def sum(newValue: Double, currentValue: Double): Double = { 
    Math.min(newValue, currentValue) 
  } 
} 

// Apply 
final class UpdateDistance extends ApplyFunction[Long, Double, Double] { 

  override def apply(newDistance: Double, oldDistance: Double) = { 
    if (newDistance < oldDistance) { 
      setResult(newDistance) 
    } 
  } 
} 

```

我们可以使用以下参数配置 GSA 迭代：

| **参数** | **描述** |
| --- | --- |
| 名称：`setName()` | 设置 GSA 迭代的名称。可以在日志中看到。 |
| 并行度：`setParallelism()` | 设置并行执行的并行度。 |
| 广播变量：`addBroadcastSet()` | 将广播变量添加到计算函数中。 |
| 聚合器：`registerAggregator()` | 注册自定义定义的聚合器函数，供计算函数使用。 |
| 未管理内存中的解集：`setSolutionSetUnmanagedMemory()` | 定义解集是否保存在受控内存中。 |
| 顶点数量：`setOptNumVertices()` | 访问迭代中顶点的总数。 |
| 邻居方向：`setDirection()` | 默认情况下，我们只考虑处理的`OUT`度，但我们可以通过设置此属性来更改。选项有`IN`、`OUT`和`ALL`。 |

# 用例 - 机场旅行优化

让我们考虑一个使用案例，其中我们有关于机场和它们之间距离的数据。为了从特定机场前往某个目的地，我们必须找到两者之间的最短路径。我们的机场数据如下表所示：

| Id | 机场名称 |
| --- | --- |
| s01 | A |
| s02 | B |
| s03 | C |
| s04 | D |
| s05 | E |

机场之间的距离信息如下表所示：

| From | To | Distance |
| --- | --- | --- |
| s01 | s02 | 10 |
| s01 | s02 | 12 |
| s01 | s03 | 22 |
| s01 | s04 | 21 |
| s04 | s11 | 22 |
| s05 | s15 | 21 |
| s06 | s17 | 21 |
| s08 | s09 | 11 |
| s08 | s09 | 12 |

现在让我们使用 Gelly 来找到单源最短路径。

在这里，我们可以在前一节学到的三种算法中选择其中一种。在这个例子中，我们将使用顶点中心迭代方法。

为了解决单源最短路径问题，我们必须首先从 CSV 文件中加载数据，如下面的代码所示：

```java
// set up the batch execution environment 
final ExecutionEnvironment env = ExecutionEnvironment.getExecutionEnvironment(); 

// Create graph by reading from CSV files 
DataSet<Tuple2<String, Double>> airportVertices = env 
            .readCsvFile("nodes.csv").types(String.class, Double.class); 

DataSet<Tuple3<String, String, Double>> airportEdges = env 
            .readCsvFile("edges.csv") 
            .types(String.class, String.class, Double.class); 

Graph<String, Double, Double> graph = Graph.fromTupleDataSet(airportVertices, airportEdges, env); 

```

接下来，我们在创建的图上运行前一节中讨论的顶点中心迭代：

```java
// define the maximum number of iterations
int maxIterations = 10;

// Execute the vertex-centric iteration
Graph<String, Double, Double> result = graph.runVertexCentricIteration(new SSSPComputeFunction(), new SSSPCombiner(), maxIterations);

// Extract the vertices as the result
DataSet<Vertex<String, Double>> singleSourceShortestPaths = result.getVertices();
singleSourceShortestPaths.print();
```

计算函数和组合器的实现与我们在前一节中所看到的类似。当我们运行这段代码时，我们将得到从给定源顶点到 SSSP 的答案。

此用例的完整代码和样本数据可在 [`github.com/deshpandetanmay/mastering-flink/tree/master/chapter07/flink-gelly`](https://github.com/deshpandetanmay/mastering-flink/tree/master/chapter07/flink-gelly) 上找到

总的来说，所有三种迭代方式看起来都很相似，但它们有微小的差异。根据用例，人们需要真正思考使用哪种算法。这里有一些关于这个想法的好文章 [`ci.apache.org/projects/flink/flink-docs-release-1.1/apis/batch/libs/gelly.html#iteration-abstractions-comparison`](https://ci.apache.org/projects/flink/flink-docs-release-1.1/apis/batch/libs/gelly.html#iteration-abstractions-comparison)。

# 总结

在本章中，我们探讨了 Flink Gelly 库提供的图处理 API 的各个方面。我们学习了如何定义图，加载数据并对其进行处理。我们还研究了可以对图进行的各种转换。最后，我们学习了 Gelly 提供的迭代图处理选项的详细信息。

在下一章中，我们将看到如何在 Hadoop 和 YARN 上执行 Flink 应用程序。


# 第八章：使用 Flink 和 Hadoop 进行分布式数据处理

在过去的几年中，Apache Hadoop 已成为数据处理和分析基础设施的核心和必要部分。通过 Hadoop 1.X，社区学习了使用 MapReduce 框架进行分布式数据处理，而 Hadoop 的下一个版本，2.X 则教会了我们使用 YARN 框架进行资源的高效利用和调度。YARN 框架是 Hadoop 数据处理的核心部分，它处理诸如作业执行、分发、资源分配、调度等复杂任务。它允许多租户、可伸缩性和高可用性。

YARN 最好的部分在于它不仅仅是一个框架，更像是一个完整的操作系统，开发人员可以自由开发和执行他们选择的应用程序。它通过让开发人员只专注于应用程序开发，忘记并行数据和执行分发的痛苦来提供抽象。YARN 位于 Hadoop 分布式文件系统之上，还可以从 AWS S3 等文件系统中读取数据。

YARN 应用程序框架建得非常好，可以托管任何分布式处理引擎。最近，新的分布式数据处理引擎如 Spark、Flink 等出现了显著增长。由于它们是为在 YARN 集群上执行而构建的，因此人们可以很容易地在同一个 YARN 集群上并行尝试新的东西。这意味着我们可以在同一个集群上使用 YARN 运行 Spark 和 Flink 作业。在本章中，我们将看到如何利用现有的 Hadoop/YARN 集群并行执行我们的 Flink 作业。

所以让我们开始吧。

# Hadoop 的快速概述

你们大多数人可能已经了解 Hadoop 及其功能，但对于那些对分布式计算世界还不熟悉的人，让我试着简要介绍一下 Hadoop。

Hadoop 是一个分布式的开源数据处理框架。它由两个重要部分组成：一个数据存储单元，Hadoop 分布式文件系统（HDFS）和资源管理单元，另一个资源协商器（YARN）。以下图表显示了 Hadoop 生态系统的高级概述：

![Hadoop 的快速概述](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-flink/img/image_08_001.jpg)

## HDFS

HDFS，顾名思义，是一个用于数据存储的高可用性分布式文件系统。如今，这是大多数公司的核心框架之一。HDFS 由主从架构组成，具有 NameNode、辅助 NameNode 和 DataNode 等守护程序。

在 HDFS 中，NameNode 存储有关要存储的文件的元数据，而 DataNode 存储组成文件的实际块。数据块默认情况下是三倍复制的，以实现高可用性。辅助 NameNode 用于备份存储在 NameNode 上的文件系统元数据。

### 注意

这是一个链接，您可以在[`hadoop.apache.org/docs/current/hadoop-project-dist/hadoop-hdfs/HdfsDesign.html`](http://hadoop.apache.org/docs/current/hadoop-project-dist/hadoop-hdfs/HdfsDesign.html)上阅读有关 HDFS 的更多信息。

## YARN

在 YARN 之前，MapReduce 是运行在 HDFS 之上的数据处理框架。但人们开始意识到它在处理作业跟踪器数量方面的限制。这催生了 YARN。YARN 背后的基本思想是分离资源管理和调度任务。YARN 具有全局资源管理器和每个应用程序的应用程序主管。资源管理器在主节点上工作，而它有一个每个工作节点代理——节点管理器，负责管理容器，监视它们的使用情况（CPU、磁盘、内存）并向资源管理器报告。

资源管理器有两个重要组件--**调度程序**和**应用程序管理器**。调度程序负责在队列中调度应用程序，而应用程序管理器负责接受作业提交，协商应用程序特定应用程序主节点的第一个容器。它还负责在应用程序主节点发生故障时重新启动**应用程序主节点**。

由于像 YARN 这样的操作系统提供了可以扩展构建应用程序的 API。**Spark**和**Flink**就是很好的例子。

### 注意

您可以在[`hadoop.apache.org/docs/current/hadoop-yarn/hadoop-yarn-site/YARN.html`](http://hadoop.apache.org/docs/current/hadoop-yarn/hadoop-yarn-site/YARN.html)阅读更多关于 YARN 的信息。

现在让我们看看如何在 YARN 上使用 Flink。

# Flink 在 YARN 上

Flink 已经内置支持在 YARN 上准备执行。使用 Flink API 构建的任何应用程序都可以在 YARN 上执行，而无需太多努力。如果用户已经有一个 YARN 集群，则无需设置或安装任何内容。Flink 希望满足以下要求：

+   Hadoop 版本应该是 2.2 或更高

+   HDFS 应该已经启动

## 配置

为了在 YARN 上运行 Flink，需要进行以下配置。首先，我们需要下载与 Hadoop 兼容的 Flink 发行版。

### 注意

二进制文件可在[`flink.apache.org/downloads.html`](http://flink.apache.org/downloads.html)下载。您必须从以下选项中进行选择。

![配置](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-flink/img/image_08_002.jpg)

假设我们正在运行 Hadoop 2.7 和 Scala 2.11。我们将下载特定的二进制文件并将其存储在安装和运行 Hadoop 的节点上。

下载后，我们需要按照这里所示的方式提取`tar`文件：

```java
$tar -xzf flink-1.1.4-bin-hadoop27-scala_2.11.tgz
$cd flink-1.1.4

```

## 启动 Flink YARN 会话

一旦二进制文件被提取，我们就可以启动 Flink 会话。Flink 会话是一个会话，它在各自的节点上启动所有所需的 Flink 服务（作业管理器和任务管理器），以便我们可以开始执行 Flink 作业。要启动 Flink 会话，我们有以下可执行文件和给定选项：

```java
# bin/yarn-session.sh
Usage:
 Required
 -n,--container <arg>            Number of YARN container to     
                                         allocate (=Number of Task  
                                         Managers)
 Optional
 -D <arg>                        Dynamic properties
 -d,--detached                   Start detached
 -id,--applicationId <arg>       Attach to running YARN session
 -j,--jar <arg>                  Path to Flink jar file
 -jm,--jobManagerMemory <arg>    Memory for JobManager 
                                         Container [in MB]
 -n,--container <arg>            Number of YARN container to 
                                         allocate (=Number of Task 
                                         Managers)
 -nm,--name <arg>                Set a custom name for the 
                                         application on YARN
 -q,--query                      Display available YARN 
                                         resources (memory, cores)
 -qu,--queue <arg>               Specify YARN queue.
 -s,--slots <arg>                Number of slots per 
                                         TaskManager
 -st,--streaming                 Start Flink in streaming mode
 -t,--ship <arg>                 Ship files in the specified 
                                         directory (t for transfer)
 -tm,--taskManagerMemory <arg>   Memory per TaskManager  
                                         Container [in MB]
 -z,--zookeeperNamespace <arg>   Namespace to create the 
                                         Zookeeper sub-paths for high 
                                         availability mode

```

我们必须确保`YARN_CONF_DIR`和`HADOOP_CONF_DIR`环境变量已设置，以便 Flink 可以找到所需的配置。现在让我们通过提供信息来启动 Flink 会话。

以下是我们如何通过提供有关任务管理器数量、每个任务管理器的内存和要使用的插槽的详细信息来启动 Flink 会话：

```java
# bin/yarn-session.sh -n 2 -tm 1024 -s 10
2016-11-14 10:46:00,126 WARN    
    org.apache.hadoop.util.NativeCodeLoader                                   
    - Unable to load native-hadoop library for your platform... using 
    builtin-java classes where applicable
2016-11-14 10:46:00,184 INFO  
    org.apache.flink.yarn.YarnClusterDescriptor                            
    - The configuration directory ('/usr/local/flink/flink-1.1.3/conf') 
    contains both LOG4J and Logback configuration files. Please delete 
    or rename one of them.
2016-11-14 10:46:01,263 INFO  org.apache.flink.yarn.Utils                                   
    - Copying from file:/usr/local/flink/flink-
    1.1.3/conf/log4j.properties to 
    hdfs://hdpcluster/user/root/.flink/application_1478079131011_0107/
    log4j.properties
2016-11-14 10:46:01,463 INFO  org.apache.flink.yarn.Utils                                      
    - Copying from file:/usr/local/flink/flink-1.1.3/lib to   
    hdfs://hdp/user/root/.flink/application_1478079131011_0107/lib
2016-11-14 10:46:02,337 INFO  org.apache.flink.yarn.Utils                                     
    - Copying from file:/usr/local/flink/flink-1.1.3/conf/logback.xml    
    to hdfs://hdpcluster/user/root/.flink/
    application_1478079131011_0107/logback.xml
2016-11-14 10:46:02,350 INFO  org.apache.flink.yarn.Utils                                      
    - Copying from file:/usr/local/flink/flink-1.1.3/lib/flink-  
    dist_2.11-1.1.3.jar to hdfs://hdpcluster/user/root/.flink/
    application_1478079131011_0107/flink-dist_2.11-1.1.3.jar
2016-11-14 10:46:03,157 INFO  org.apache.flink.yarn.Utils                                      
    - Copying from /usr/local/flink/flink-1.1.3/conf/flink-conf.yaml to    
    hdfs://hdpcluster/user/root/.flink/application_1478079131011_0107/
    flink-conf.yaml
org.apache.flink.yarn.YarnClusterDescriptor                           
    - Deploying cluster, current state ACCEPTED
2016-11-14 10:46:11,976 INFO  
    org.apache.flink.yarn.YarnClusterDescriptor                               
    - YARN application has been deployed successfully.
Flink JobManager is now running on 10.22.3.44:43810
JobManager Web Interface: 
    http://myhost.com:8088/proxy/application_1478079131011_0107/
2016-11-14 10:46:12,387 INFO  Remoting                                                      
    - Starting remoting
2016-11-14 10:46:12,483 INFO  Remoting                                                      
    - Remoting started; listening on addresses :
    [akka.tcp://flink@10.22.3.44:58538]
2016-11-14 10:46:12,627 INFO     
    org.apache.flink.yarn.YarnClusterClient                                
    - Start application client.
2016-11-14 10:46:12,634 INFO  
    org.apache.flink.yarn.ApplicationClient                                
    - Notification about new leader address 
    akka.tcp://flink@10.22.3.44:43810/user/jobmanager with session ID 
    null.
2016-11-14 10:46:12,637 INFO    
    org.apache.flink.yarn.ApplicationClient                                
    - Received address of new leader   
    akka.tcp://flink@10.22.3.44:43810/user/jobmanager 
    with session ID null.
2016-11-14 10:46:12,638 INFO  
    org.apache.flink.yarn.ApplicationClient                                
    - Disconnect from JobManager null.
2016-11-14 10:46:12,640 INFO  
    org.apache.flink.yarn.ApplicationClient                                
    - Trying to register at JobManager 
    akka.tcp://flink@10.22.3.44:43810/user/jobmanager.
2016-11-14 10:46:12,649 INFO  
    org.apache.flink.yarn.ApplicationClient                                
    - Successfully registered at the ResourceManager using JobManager 
    Actor[akka.tcp://flink@10.22.3.44:43810/user/jobmanager#-862361447]

```

如果配置目录未正确设置，您将收到错误消息。在这种情况下，首先可以设置配置目录，然后启动 Flink YARN 会话。

以下命令设置了配置目录：

```java
export HADOOP_CONF_DIR=/etc/hadoop/conf
export YARN_CONF_DIR=/etc/hadoop/conf

```

### 注意

我们还可以通过访问以下 URL 来检查 Flink Web UI：`http://host:8088/proxy/application_<id>/#/overview.`

这是同样的屏幕截图：

![启动 Flink YARN 会话](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-flink/img/image_08_003.jpg)

同样，我们也可以在`http://myhost:8088/cluster/app/application_1478079131011_0107`上检查 YARN 应用程序 UI。

![启动 Flink YARN 会话](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-flink/img/image_08_004.jpg)

## 将作业提交到 Flink

现在我们已经连接到 YARN 的 Flink 会话，我们已经准备好将 Flink 作业提交到 YARN。

我们可以使用以下命令和选项提交 Flink 作业：

```java
#./bin/flink
./flink <ACTION> [OPTIONS] [ARGUMENTS]

```

我们可以使用运行操作来执行 Flink 作业。在运行中，我们有以下选项：

| **选项** | **描述** |
| --- | --- |
| `-c`, `--class <classname>` | 具有程序入口点（`main()`方法或`getPlan()`方法）的类。只有在 JAR 文件没有在其清单中指定类时才需要。 |
| -C，--classpath <url> | 在集群中的所有节点的每个用户代码类加载器中添加 URL。路径必须指定协议（例如`file://`）并且在所有节点上都可以访问（例如通过 NFS 共享）。您可以多次使用此选项来指定多个 URL。协议必须受到{@link java.net.URLClassLoader}支持。如果您希望在 Flink YARN 会话中使用某些第三方库，可以使用此选项。 |
| -d，--detached | 如果存在，以分离模式运行作业。分离模式在您不想一直运行 Flink YARN 会话时很有用。在这种情况下，Flink 客户端只会提交作业并分离自己。我们无法使用 Flink 命令停止分离的 Flink YARN 会话。为此，我们必须使用 YARN 命令杀死应用程序 yarn application -kill <appId> |
| -m，--jobmanager <host:port> | 要连接的作业管理器（主节点）的地址。使用此标志连接到与配置中指定的不同作业管理器。 |
| -p，--parallelism <parallelism> | 运行程序的并行度。可选标志，用于覆盖配置中指定的默认值。 |
| -q，--sysoutLogging | 如果存在，抑制标准`OUT`的日志输出。 |
| -s，--fromSavepoint <savepointPath> | 重置作业的保存点路径，例如 file:///flink/savepoint-1537。保存点是 Flink 程序的外部存储状态。它们是存储在某个位置的快照。如果 Flink 程序失败，我们可以从其上次存储的保存点恢复它。有关保存点的更多详细信息 [`ci.apache.org/projects/flink/flink-docs-release-1.2/setup/savepoints.html`](https://ci.apache.org/projects/flink/flink-docs-release-1.2/setup/savepoints.html) |
| -z，--zookeeperNamespace <zookeeperNamespace> | 用于创建高可用模式的 Zookeeper 子路径的命名空间 |

`yarn-cluster`模式提供以下选项：

| **选项** | **描述** |
| --- | --- |
| -yD <arg> | 动态属性 |
| yd，--yarndetached | 启动分离 |
| -yid，--yarnapplicationId <arg> | 连接到正在运行的 YARN 会话 |
| -yj，--yarnjar <arg> | Flink jar 文件的路径 |
| -yjm，--yarnjobManagerMemory <arg> | 作业管理器容器的内存（以 MB 为单位） |
| -yn，--yarncontainer <arg> | 分配的 YARN 容器数（=任务管理器数） |
| -ynm，--yarnname <arg> | 为 YARN 上的应用设置自定义名称 |
| -yq，--yarnquery | 显示可用的 YARN 资源（内存，核心） |
| -yqu，--yarnqueue <arg> | 指定 YARN 队列 |
| -ys，--yarnslots <arg> | 每个任务管理器的插槽数 |
| -yst，--yarnstreaming | 以流模式启动 Flink |
| -yt，--yarnship <arg> | 在指定目录中传输文件（t 表示传输） |
| -ytm，--yarntaskManagerMemory <arg> | 每个 TaskManager 容器的内存（以 MB 为单位） |
| -yz，--yarnzookeeperNamespace <arg> | 用于创建高可用模式的 Zookeeper 子路径的命名空间 |

现在让我们尝试在 YARN 上运行一个示例单词计数示例。以下是如何执行的步骤。

首先，让我们将输入文件存储在 HDFS 上，作为单词计数程序的输入。在这里，我们将在 Apache 许可证文本上运行单词计数。以下是我们下载并将其存储在 HDFS 上的方式：

```java
wget -O LICENSE-2.0.txt http://www.apache.org/licenses/LICENSE-
    2.0.txt
hadoop fs -mkdir in
hadoop fs -put LICENSE-2.0.txt in

```

现在我们将提交示例单词计数作业：

```java
./bin/flink run ./examples/batch/WordCount.jar 
    hdfs://myhost/user/root/in  hdfs://myhost/user/root/out

```

这将调用在 YARN 集群上执行的 Flink 作业。您应该在控制台上看到：

```java
 **# ./bin/flink run ./examples/batch/WordCount.jar** 
2016-11-14 11:26:32,603 INFO  
    org.apache.flink.yarn.cli.FlinkYarnSessionCli               
    - YARN properties set default parallelism to 20
2016-11-14 11:26:32,603 INFO   
    org.apache.flink.yarn.cli.FlinkYarnSessionCli                 
    - YARN properties set default parallelism to 20
YARN properties set default parallelism to 20
2016-11-14 11:26:32,603 INFO    
    org.apache.flink.yarn.cli.FlinkYarnSessionCli               
    - Found YARN properties file /tmp/.yarn-properties-root
2016-11-14 11:26:32,603 INFO  
    org.apache.flink.yarn.cli.FlinkYarnSessionCli              
    - Found YARN properties file /tmp/.yarn-properties-root
Found YARN properties file /tmp/.yarn-properties-root
2016-11-14 11:26:32,603 INFO  
    org.apache.flink.yarn.cli.FlinkYarnSessionCli             
    - Using Yarn application id from YARN properties  
    application_1478079131011_0107
2016-11-14 11:26:32,603 INFO  
    org.apache.flink.yarn.cli.FlinkYarnSessionCli                        
    - Using Yarn application id from YARN properties  
    application_1478079131011_0107
Using Yarn application id from YARN properties   
    application_1478079131011_0107
2016-11-14 11:26:32,604 INFO  
    org.apache.flink.yarn.cli.FlinkYarnSessionCli               
    - YARN properties set default parallelism to 20
2016-11-14 11:26:32,604 INFO  
    org.apache.flink.yarn.cli.FlinkYarnSessionCli                
    - YARN properties set default parallelism to 20
YARN properties set default parallelism to 20
2016-11-14 11:26:32,823 INFO  
    org.apache.hadoop.yarn.client.api.impl.TimelineClientImpl     
    - Timeline service address: http://hdpdev002.pune-
    in0145.slb.com:8188/ws/v1/timeline/
2016-11-14 11:26:33,089 INFO  
    org.apache.flink.yarn.YarnClusterDescriptor               
    - Found application JobManager host name myhost.com' and port  
    '43810' from supplied application id 
    'application_1478079131011_0107'
Cluster configuration: Yarn cluster with application id 
    application_1478079131011_0107
Using address 163.183.206.249:43810 to connect to JobManager.
Starting execution of program
2016-11-14 11:26:33,711 INFO  
    org.apache.flink.yarn.YarnClusterClient                  
    - TaskManager status (2/1)
TaskManager status (2/1)
2016-11-14 11:26:33,712 INFO  
    org.apache.flink.yarn.YarnClusterClient                
    - All TaskManagers are connected
All TaskManagers are connected
2016-11-14 11:26:33,712 INFO  
    org.apache.flink.yarn.YarnClusterClient                       
    - Submitting job with JobID: b57d682dd09f570ea336b0d56da16c73\. 
    Waiting for job completion.
Submitting job with JobID: b57d682dd09f570ea336b0d56da16c73\. 
    Waiting for job completion.
Connected to JobManager at 
    Actor[akka.tcp://flink@163.183.206.249:43810/user/
    jobmanager#-862361447]
11/14/2016 11:26:33     Job execution switched to status RUNNING.
11/14/2016 11:26:33     CHAIN DataSource (at   
    getDefaultTextLineDataSet(WordCountData.java:70) 
    (org.apache.flink.api.java.io.CollectionInputFormat)) -> FlatMap 
    (FlatMap at main(WordCount.java:80)) -> Combine(SUM(1), at 
    main(WordCount.java:83)(1/1) switched to RUNNING
11/14/2016 11:26:34     DataSink (collect())(20/20) switched to 
    FINISHED
...
11/14/2016 11:26:34     Job execution switched to status FINISHED.
(after,1)
(coil,1)
(country,1)
(great,1)
(long,1)
(merit,1)
(oppressor,1)
(pangs,1)
(scorns,1)
(what,1)
(a,5)
(death,2)
(die,2)
(rather,1)
(be,4)
(bourn,1)
(d,4)
(say,1)
(takes,1)
(thy,1)
(himself,1)
(sins,1)
(there,2)
(whips,1)
(would,2)
(wrong,1)
...
 **Program execution finished** 
 **Job with JobID b57d682dd09f570ea336b0d56da16c73 has finished.** 
 **Job Runtime: 575 ms** 
Accumulator Results:
- 4950e35c195be901e0ad6a8ed25790de (java.util.ArrayList) [170 
      elements]
2016-11-14 11:26:34,378 INFO    
      org.apache.flink.yarn.YarnClusterClient             
      - Disconnecting YarnClusterClient from ApplicationMaster

```

以下是来自 Flink 应用程序主 UI 的作业执行的屏幕截图。这是 Flink 执行计划的屏幕截图：

![提交作业到 Flink](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-flink/img/image_08_005.jpg)

接下来我们可以看到执行此作业的步骤的屏幕截图：

![提交作业到 Flink](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-flink/img/image_08_006.jpg)

最后，我们有 Flink 作业执行时间轴的截图。时间轴显示了所有可以并行执行的步骤以及需要按顺序执行的步骤：

![提交作业到 Flink](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-flink/img/image_08_007.jpg)

## 停止 Flink YARN 会话

处理完成后，您可以以两种方式停止 Flink YARN 会话。首先，您可以在启动 YARN 会话的控制台上简单地执行*Cltr*+*C*。这将发送终止信号并停止 YARN 会话。

第二种方法是执行以下命令来停止会话：

```java
./bin/yarn-session.sh -id application_1478079131011_0107 stop

```

我们可以立即看到 Flink YARN 应用程序被终止：

```java
2016-11-14 11:56:59,455 INFO  
    org.apache.flink.yarn.YarnClusterClient  
    Sending shutdown request to the Application Master
2016-11-14 11:56:59,456 INFO    
    org.apache.flink.yarn.ApplicationClient  
    Sending StopCluster request to JobManager.
2016-11-14 11:56:59,464 INFO  
    org.apache.flink.yarn.YarnClusterClient  
    - Deleted Yarn properties file at /tmp/.yarn-properties-root
2016-11-14 11:56:59,464 WARN  
    org.apache.flink.yarn.YarnClusterClient  
    Session file directory not set. Not deleting session files
2016-11-14 11:56:59,565 INFO  
    org.apache.flink.yarn.YarnClusterClient  
    - Application application_1478079131011_0107 finished with state   
    FINISHED and final state SUCCEEDED at 1479104819469
 **2016-11-14 11:56:59,565 INFO  
    org.apache.flink.yarn.YarnClusterClient  
    - YARN Client is shutting down** 

```

## 在 YARN 上运行单个 Flink 作业

我们还可以在 YARN 上运行单个 Flink 作业，而不会阻塞 YARN 会话的资源。如果您只希望在 YARN 上运行单个 Flink 作业，这是一个很好的选择。在之前的情况下，当我们在 YARN 上启动 Flink 会话时，它会阻塞资源和核心，直到我们停止会话，而在这种情况下，资源会在作业执行时被阻塞，并且一旦作业完成，它们就会被释放。以下命令显示了如何在 YARN 上执行单个 Flink 作业而不需要会话：

```java
./bin/flink run -m yarn-cluster -yn 2  
    ./examples/batch/WordCount.jar

```

我们可以看到与之前情况下相似的结果。我们还可以使用 YARN 应用程序 UI 跟踪其进度和调试。以下是同一样本的截图：

![在 YARN 上运行单个 Flink 作业](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-flink/img/image_08_008.jpg)

## Flink 在 YARN 上的恢复行为

Flink 在 YARN 上提供以下配置参数来调整恢复行为：

| **参数** | **描述** |
| --- | --- |
| `yarn.reallocate-failed` | 设置 Flink 是否应重新分配失败的任务管理器容器。默认值为`true`。 |
| `yarn.maximum-failed-containers` | 设置应用程序主在 YARN 会话失败之前接受的最大失败容器数。默认值为启动时请求的任务管理器数量。 |
| `yarn.application-attempts` | 设置应用程序主尝试的次数。默认值为`1`，这意味着如果应用程序主失败，YARN 会话将失败。 |

这些配置需要在`conf/flink-conf.yaml`中，或者可以在会话启动时使用`-D`参数进行设置。

## 工作细节

在前面的章节中，我们看到了如何在 YARN 上使用 Flink。现在让我们试着了解它的内部工作原理：

![工作细节](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-flink/img/image_08_009.jpg)

上图显示了 Flink 在 YARN 上的内部工作原理。它经历了以下步骤：

1.  检查 Hadoop 和 YARN 配置目录是否已设置。

1.  如果是，则联系 HDFS 并将 JAR 和配置存储在 HDFS 上。

1.  联系节点管理器以分配应用程序主。

1.  一旦分配了应用程序主，就会启动 Flink 作业管理器。

1.  稍后，根据给定的配置参数启动 Flink 任务管理器。

现在我们已经准备好在 YARN 上提交 Flink 作业了。

# 摘要

在本章中，我们讨论了如何使用现有的 YARN 集群以分布式模式执行 Flink 作业。我们详细了解了一些实际示例。

在下一章中，我们将看到如何在云环境中执行 Flink 作业。


# 第九章：在云上部署 Flink

近年来，越来越多的公司投资于基于云的解决方案，这是有道理的，考虑到我们通过云实现的成本和效率。**亚马逊网络服务**（**AWS**）、**Google Cloud 平台**（**GCP**）和微软 Azure 目前在这一业务中是明显的领导者。几乎所有这些公司都提供了相当方便使用的大数据解决方案。云提供了及时高效的解决方案，人们不需要担心硬件购买、网络等问题。

在本章中，我们将看到如何在云上部署 Flink。我们将详细介绍在 AWS 和 Google Cloud 上安装和部署应用程序的方法。所以让我们开始吧。

# 在 Google Cloud 上的 Flink

Flink 可以使用一个名为 BDUtil 的实用程序在 Google Cloud 上部署。这是一个开源实用程序，供所有人使用 [`cloud.google.com/hadoop/bdutil`](https://cloud.google.com/hadoop/bdutil)。我们需要做的第一步是安装**Google Cloud SDK**。

## 安装 Google Cloud SDK

Google Cloud SDK 是一个可执行实用程序，可以安装在 Windows、Mac 或 UNIX 操作系统上。您可以根据您的操作系统选择安装模式。以下是一个链接，指导用户了解详细的安装过程 [`cloud.google.com/sdk/downloads`](https://cloud.google.com/sdk/downloads)。

在这里，我假设您已经熟悉 Google Cloud 的概念和术语；如果没有，我建议阅读 [`cloud.google.com/docs/`](https://cloud.google.com/docs/)。

在我的情况下，我将使用 UNIX 机器启动一个 Flink-Hadoop 集群。所以让我们开始安装。

首先，我们需要下载 Cloud SDK 的安装程序。

```java
wget 
    https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-
    cloud-sdk-135.0.0-linux-x86_64.tar.gz

```

接下来，我们通过以下命令解压文件：

```java
tar -xzf google-cloud-sdk-135.0.0-linux-x86_64.tar.gz

```

完成后，我们需要初始化 SDK：

```java
cd google-cloud-sdk
bin/gcloud init

```

这将启动一个交互式安装过程，并需要您根据需要提供输入。下面的截图显示了这个过程：

![安装 Google Cloud SDK](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-flink/img/image_09_001.jpg)

还建议通过执行以下命令进行身份验证：

```java
gcloud auth login

```

这将为您提供一个 URL，可以在您的机器浏览器中打开。点击该 URL，您将获得一个用于身份验证的代码。

身份验证完成后，我们就可以开始 BDUtil 安装了。

## 安装 BDUtil

正如我们之前所说，BDUtil 是 Google 开发的一个实用程序，旨在在 Google Cloud 上实现无故障的大数据安装。您可以安装以下服务：

+   Hadoop - HDP 和 CDH

+   Flink

+   Hama

+   Hbase

+   Spark

+   Storm

+   Tajo

安装 BDUtil 需要以下步骤。首先，我们需要下载源代码：

```java
wget 
    https://github.com/GoogleCloudPlatform/bdutil/archive/master.zip

```

通过以下命令解压代码：

```java
unzip master.zip
cd bdutil-master

```

### 注意

如果您在 Google Compute 机器上使用 BDUtil 操作，建议使用**非 root 帐户**。通常情况下，所有计算引擎机器默认禁用 root 登录。

现在我们已经完成了 BDUtil 的安装，并准备好部署了。

## 启动 Flink 集群

BDUtil 至少需要一个项目，我们将在其中进行安装，并且需要一个存放临时文件的存储桶。要创建一个存储桶，您可以转到**Cloud Storage**部分，并选择创建一个存储桶，如下截图所示：

![启动 Flink 集群](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-flink/img/image_09_002.jpg)

我们已经将这个存储桶命名为**bdutil-flink-bucket**。接下来，我们需要编辑`bdutil_env.sh`文件，配置有关项目名称、存储桶名称和要使用的 Google Cloud 区域的信息。我们还可以设置其他内容，如机器类型和操作系统。`bdutil_env.sh`如下所示：

```java
 # A GCS bucket used for sharing generated SSH keys and GHFS configuration. 
CONFIGBUCKET="bdutil-flink-bucket" 

# The Google Cloud Platform text-based project-id which owns the GCE resources. 
PROJECT="bdutil-flink-project" 

###################### Cluster/Hardware Configuration ######### 
# These settings describe the name, location, shape and size of your cluster, 
# though these settings may also be used in deployment-configuration--for 
# example, to whitelist intra-cluster SSH using the cluster prefix. 

# GCE settings. 
GCE_IMAGE='https://www.googleapis.com/compute/v1/projects/debian-cloud/global/images/backports-debian-7-wheezy-v20160531' 
GCE_MACHINE_TYPE='n1-standard-4' 
GCE_ZONE="europe-west1-d" 
# When setting a network it's important for all nodes be able to communicate 
# with eachother and for SSH connections to be allowed inbound to complete 
# cluster setup and configuration. 

```

默认情况下，配置启动三个节点，Hadoop/Flink 集群，一个主节点和两个工作节点。

### 注意

如果您正在使用 GCP 的试用版，则建议使用机器类型为**n1-standard-2**。这将限制节点类型的 CPU 和存储。

现在我们已经准备好启动集群，使用以下命令：

```java
./bdutil -e extensions/flink/flink_env.sh deploy

```

这将开始创建机器并在其上部署所需的软件。如果一切顺利，通常需要 10-20 分钟的时间来启动和运行集群。在开始执行之前，您应该查看屏幕截图告诉我们什么。

![启动 Flink 集群](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-flink/img/image_09_003.jpg)

完成后，您将看到以下消息：

```java
gcloud --project=bdutil ssh --zone=europe-west1-c hadoop-m 
Sat Nov 19 06:12:27 UTC 2016: Staging files successfully deleted. 
Sat Nov 19 06:12:27 UTC 2016: Invoking on master: ./deploy-ssh-master-setup.sh 
.Sat Nov 19 06:12:27 UTC 2016: Waiting on async 'ssh' jobs to finish. Might take a while... 
. 
Sat Nov 19 06:12:29 UTC 2016: Step 'deploy-ssh-master-setup,*' done... 
Sat Nov 19 06:12:29 UTC 2016: Invoking on workers: ./deploy-core-setup.sh 
..Sat Nov 19 06:12:29 UTC 2016: Invoking on master: ./deploy-core-setup.sh 
.Sat Nov 19 06:12:30 UTC 2016: Waiting on async 'ssh' jobs to finish. Might take a while... 
... 
Sat Nov 19 06:13:14 UTC 2016: Step 'deploy-core-setup,deploy-core-setup' done... 
Sat Nov 19 06:13:14 UTC 2016: Invoking on workers: ./deploy-ssh-worker-setup.sh 
..Sat Nov 19 06:13:15 UTC 2016: Waiting on async 'ssh' jobs to finish. Might take a while... 
.. 
Sat Nov 19 06:13:17 UTC 2016: Step '*,deploy-ssh-worker-setup' done... 
Sat Nov 19 06:13:17 UTC 2016: Invoking on master: ./deploy-master-nfs-setup.sh 
.Sat Nov 19 06:13:17 UTC 2016: Waiting on async 'ssh' jobs to finish. Might take a while... 
. 
Sat Nov 19 06:13:23 UTC 2016: Step 'deploy-master-nfs-setup,*' done... 
Sat Nov 19 06:13:23 UTC 2016: Invoking on workers: ./deploy-client-nfs-setup.sh 
..Sat Nov 19 06:13:23 UTC 2016: Invoking on master: ./deploy-client-nfs-setup.sh 
.Sat Nov 19 06:13:24 UTC 2016: Waiting on async 'ssh' jobs to finish. Might take a while... 
... 
Sat Nov 19 06:13:33 UTC 2016: Step 'deploy-client-nfs-setup,deploy-client-nfs-setup' done... 
Sat Nov 19 06:13:33 UTC 2016: Invoking on master: ./deploy-start.sh 
.Sat Nov 19 06:13:34 UTC 2016: Waiting on async 'ssh' jobs to finish. Might take a while... 
. 
Sat Nov 19 06:13:49 UTC 2016: Step 'deploy-start,*' done... 
Sat Nov 19 06:13:49 UTC 2016: Invoking on workers: ./install_flink.sh 
..Sat Nov 19 06:13:49 UTC 2016: Invoking on master: ./install_flink.sh 
.Sat Nov 19 06:13:49 UTC 2016: Waiting on async 'ssh' jobs to finish. Might take a while... 
... 
Sat Nov 19 06:13:53 UTC 2016: Step 'install_flink,install_flink' done... 
Sat Nov 19 06:13:53 UTC 2016: Invoking on master: ./start_flink.sh 
.Sat Nov 19 06:13:54 UTC 2016: Waiting on async 'ssh' jobs to finish. Might take a while... 
. 
Sat Nov 19 06:13:55 UTC 2016: Step 'start_flink,*' done... 
Sat Nov 19 06:13:55 UTC 2016: Command steps complete. 
Sat Nov 19 06:13:55 UTC 2016: Execution complete. Cleaning up temporary files... 
Sat Nov 19 06:13:55 UTC 2016: Cleanup complete. 

```

如果中途出现任何故障，请查看日志。您可以访问 Google 云计算引擎控制台以获取主机和从机的确切 IP 地址。

现在，如果您检查作业管理器 UI，您应该有两个任务管理器和四个任务插槽可供使用。您可以访问 URL `http://<master-node-ip>:8081`。以下是相同的示例屏幕截图：

![启动 Flink 集群](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-flink/img/image_09_004.jpg)

## 执行示例作业

您可以通过启动一个示例词频统计程序来检查一切是否正常运行。为此，我们首先需要登录到 Flink 主节点。以下命令启动了 Flink 安装提供的一个示例词频统计程序。

```java
/home/hadoop/flink-install/bin$ ./flink run   
    ../examples/WordCount.jar

11/19/2016 06:56:05     Job execution switched to status RUNNING. 
11/19/2016 06:56:05     CHAIN DataSource (at getDefaultTextLineDataSet(WordCountData.java:70) (org.apache.flink.api.java.io.CollectionInputFormat)) -> FlatMap (FlatMap at main(WordCount.java:69)) -> Combine(SUM(1), at main(WordCount.java:72)(1/1) switched to SCHEDULED 
11/19/2016 06:56:05     CHAIN DataSource (at getDefaultTextLineDataSet(WordCountData.java:70) (org.apache.flink.api.java.io.CollectionInputFormat)) -> FlatMap (FlatMap at main(WordCount.java:69)) -> Combine(SUM(1), at main(WordCount.java:72)(1/1) switched to DEPLOYING 
11/19/2016 06:56:05     CHAIN DataSource (at getDefaultTextLineDataSet(WordCountData.java:70) (org.apache.flink.api.java.io.CollectionInputFormat)) -> FlatMap (FlatMap at main(WordCount.java:69)) -> Combine(SUM(1), at main(WordCount.java:72)(1/1) switched to RUNNING 
11/19/2016 06:56:05     CHAIN Reduce (SUM(1), at main(WordCount.java:72) -> FlatMap (collect())(1/4) switched to SCHEDULED 
11/19/2016 06:56:05     CHAIN DataSource (at getDefaultTextLineDataSet(WordCountData.java:70) (org.apache.flink.api.java.io.CollectionInputFormat)) -> FlatMap (FlatMap at main(WordCount.java:69)) -> Combine(SUM(1), at main(WordCount.java:72)(1/1) switched to FINISHED 
... 
RUNNING 
11/19/2016 06:56:06     DataSink (collect() sink)(3/4) switched to SCHEDULED 
11/19/2016 06:56:06     DataSink (collect() sink)(3/4) switched to DEPLOYING 
11/19/2016 06:56:06     DataSink (collect() sink)(1/4) switched to SCHEDULED 
11/19/2016 06:56:06     DataSink (collect() sink)(1/4) switched to DEPLOYING 
11/19/2016 06:56:06     CHAIN Reduce (SUM(1), at main(WordCount.java:72) -> FlatMap (collect())(1/4) switched to FINISHED 
11/19/2016 06:56:06     CHAIN Reduce (SUM(1), at main(WordCount.java:72) -> FlatMap (collect())(3/4) switched to FINISHED 
11/19/2016 06:56:06     DataSink (collect() sink)(3/4) switched to  
11/19/2016 06:56:06     CHAIN Reduce (SUM(1), at  
11/19/2016 06:56:06     DataSink (collect() sink)(2/4) switched to FINISHED 
11/19/2016 06:56:06     Job execution switched to status FINISHED. 
(after,1) 
(arms,1) 
(arrows,1) 
(awry,1) 
(bare,1) 
(be,4) 
(coil,1) 
(consummation,1) 
(contumely,1) 
(d,4) 
(delay,1) 
(despis,1) 
... 

```

以下屏幕截图显示了作业的执行地图：

![执行示例作业](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-flink/img/image_09_005.jpg)

以下是一个时间轴的屏幕截图，显示了所有任务的执行情况：

![执行示例作业](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-flink/img/image_09_006.jpg)

## 关闭集群

一旦我们完成了所有的执行，如果我们不再希望进一步使用集群，最好关闭它。

以下是一个命令，我们需要执行以关闭我们启动的集群：

```java
./bdutil -e extensions/flink/flink_env.sh delete

```

在删除集群之前，请务必确认配置。以下是一个屏幕截图，显示了将要删除的内容和完整的过程：

![关闭集群](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-flink/img/image_09_007.jpg)

# 在 AWS 上使用 Flink

现在让我们看看如何在亚马逊网络服务（AWS）上使用 Flink。亚马逊提供了一个托管的 Hadoop 服务，称为弹性 Map Reduce（EMR）。我们可以结合使用 Flink。我们可以在 EMR 上进行阅读[`aws.amazon.com/documentation/elastic-mapreduce/`](https://aws.amazon.com/documentation/elastic-mapreduce/)。

在这里，我假设您已经有 AWS 帐户并了解 AWS 的基础知识。

## 启动 EMR 集群

我们需要做的第一件事就是启动 EMR 集群。我们首先需要登录到 AWS 帐户，并从控制台中选择 EMR 服务，如下图所示：

![启动 EMR 集群](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-flink/img/image_09_008.jpg)

接下来，我们转到 EMR 控制台，并启动一个包含一个主节点和两个从节点的三节点集群。在这里，我们选择最小的集群大小以避免意外计费。以下屏幕截图显示了 EMR 集群创建屏幕：

![启动 EMR 集群](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-flink/img/image_09_009.jpg)

通常需要 10-15 分钟才能启动和运行集群。一旦集群准备就绪，我们可以通过 SSH 连接到集群。为此，我们首先需要单击“创建安全组”部分，并添加规则以添加 SSH 端口 22 规则。以下屏幕显示了安全组部分，在其中我们需要编辑 SSH 的“入站”流量规则：

![启动 EMR 集群](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-flink/img/image_09_010.jpg)

现在我们已经准备好使用 SSH 和私钥登录到主节点。一旦使用 Hadoop 用户名登录，您将看到以下屏幕：

![启动 EMR 集群](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-flink/img/image_09_011.jpg)

## 在 EMR 上安装 Flink

一旦我们的 EMR 集群准备就绪，安装 Flink 就非常容易。我们需要执行以下步骤：

1.  从链接[`flink.apache.org/downloads.html`](http://flink.apache.org/downloads.html)下载与正确的 Hadoop 版本兼容的 Flink。我正在下载与 Hadoop 2.7 版本兼容的 Flink：

```java
wget http://www-eu.apache.org/dist/flink/flink-1.1.4/flink-
        1.1.4-bin-hadoop27-scala_2.11.tgz

```

1.  接下来，我们需要解压安装程序：

```java
tar -xzf flink-1.1.4-bin-hadoop27-scala_2.11.tgz

```

1.  就是这样，只需进入解压后的文件夹并设置以下环境变量，我们就准备好了：

```java
cd flink-1.1.4
export HADOOP_CONF_DIR=/etc/hadoop/conf
export YARN_CONF_DIR=/etc/hadoop/conf

```

## 在 EMR-YARN 上执行 Flink

在 YARN 上执行 Flink 非常容易。我们已经在上一章中学习了有关 YARN 上的 Flink 的详细信息。以下步骤显示了一个示例作业执行。这将向 YARN 提交一个单个的 Flink 作业：

```java
./bin/flink run -m yarn-cluster -yn 2 
    ./examples/batch/WordCount.jar

```

您将立即看到 Flink 的执行开始，并在完成后，您将看到词频统计结果：

```java
2016-11-20 06:41:45,760 INFO  org.apache.flink.yarn.YarnClusterClient                       - Submitting job with JobID: 0004040e04879e432365825f50acc80c. Waiting for job completion. 
Submitting job with JobID: 0004040e04879e432365825f50acc80c. Waiting for job completion. 
Connected to JobManager at Actor[akka.tcp://flink@172.31.0.221:46603/user/jobmanager#478604577] 
11/20/2016 06:41:45     Job execution switched to status RUNNING. 
11/20/2016 06:41:46     CHAIN DataSource (at getDefaultTextLineDataSet(WordCountData.java:70) (org.apache.flink.api.java.io.CollectionInputFormat)) -> FlatMap (FlatMap at main(WordCount.java:80)) -> Combine(SUM(1), at main(WordCount.java:83)(1/1) switched to RUNNING 
11/20/2016 06:41:46     Reduce (SUM(1), at  
getDefaultTextLineDataSet(WordCountData.java:70) (org.apache.flink.api.java.io.CollectionInputFormat)) -> FlatMap (FlatMap at main(WordCount.java:80)) -> Combine(SUM(1), at main(WordCount.java:83)(1/1) switched to FINISHED 
11/20/2016 06:41:46     Reduce (SUM(1), at main(WordCount.java:83)(1/2) switched to DEPLOYING 
11/20/2016 06:41:46     Reduce (SUM(1), at main(WordCount.java:83)(1/2) switched to RUNNING 
11/20/2016 06:41:46     Reduce (SUM(1), at main(WordCount.java:83)(2/2) switched to RUNNING 
1/20/2016 06:41:46     Reduce (SUM(1), at main(WordCount.java:83)(1/2) switched to FINISHED 
11/20/2016 06:41:46     DataSink (collect())(2/2) switched to DEPLOYING 
11/20/2016 06:41:46     Reduce (SUM(1), at main(WordCount.java:83)(2/2) switched to FINISHED 
11/20/2016 06:41:46     DataSink (collect())(2/2) switched to RUNNING 
11/20/2016 06:41:46     DataSink (collect())(2/2) switched to FINISHED 
11/20/2016 06:41:46     Job execution switched to status FINISHED. 
(action,1) 
(after,1) 
(against,1) 
(and,12) 
(arms,1) 
(arrows,1) 
(awry,1) 
(ay,1) 
(bare,1) 
(be,4) 
(bodkin,1) 
(bourn,1) 
(calamity,1) 
(cast,1) 
(coil,1) 
(come,1) 

```

我们还可以查看 YARN 集群 UI，如下面的屏幕截图所示：

![在 EMR-YARN 上执行 Flink](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-flink/img/image_09_012.jpg)

## 启动 Flink YARN 会话

或者，我们也可以通过阻止我们在上一章中已经看到的资源来启动 YARN 会话。Flink YARN 会话将创建一个持续运行的 YARN 会话，可用于执行多个 Flink 作业。此会话将持续运行，直到我们停止它。

要启动 Flink YARN 会话，我们需要执行以下命令：

```java
$ bin/yarn-session.sh -n 2 -tm 768 -s 4

```

在这里，我们启动了两个具有每个 768 MB 内存和 4 个插槽的任务管理器。您将在控制台日志中看到 YARN 会话已准备就绪的情况：

```java
2016-11-20 06:49:09,021 INFO  org.apache.flink.yarn.YarnClusterDescriptor                 
- Using values: 
2016-11-20 06:49:09,023 INFO  org.apache.flink.yarn.YarnClusterDescriptor                   
-   TaskManager count = 2
2016-11-20 06:49:09,023 INFO  org.apache.flink.yarn.YarnClusterDescriptor                   
-   JobManager memory = 1024
2016-11-20 06:49:09,023 INFO  org.apache.flink.yarn.YarnClusterDescriptor                   
-   TaskManager memory = 768 
2016-11-20 06:49:09,488 INFO  org.apache.hadoop.yarn.client.api.impl.TimelineClientImpl     
- Timeline service address: http://ip-172-31-2-68.ap-south-1.compute.internal:8188/ws/v1/timeline/ 
2016-11-20 06:49:09,613 INFO  org.apache.hadoop.yarn.client.RMProxy                         - Connecting to ResourceManager at ip-172-31-2-68.ap-south-1.compute.internal/172.31.2.68:8032 
2016-11-20 06:49:10,309 WARN  org.apache.flink.yarn.YarnClusterDescriptor                   
- The configuration directory ('/home/hadoop/flink-1.1.3/conf') contains both LOG4J and Logback configuration files. Please delete or rename one of them. 
2016-11-20 06:49:10,325 INFO  org.apache.flink.yarn.Utils                                   - Copying from file:/home/hadoop/flink-1.1.3/conf/log4j.properties to hdfs://ip-172-31-2-68.ap-south-1.compute.internal:8020/user/hadoop/.flink/application_1479621657204_0004/log4j.properties 
2016-11-20 06:49:10,558 INFO  org.apache.flink.yarn.Utils                                   - Copying from file:/home/hadoop/flink-1.1.3/lib to hdfs://ip-172-31-2-68.ap-south-1.compute.internal:8020/user/hadoop/.flink/application_1479621657204_0004/lib 
2016-11-20 06:49:12,392 INFO  org.apache.flink.yarn.Utils                                   - Copying from /home/hadoop/flink-1.1.3/conf/flink-conf.yaml to hdfs://ip-172-31-2-68.ap-south-1.compute.internal:8020/user/hadoop/.flink/application_1479621657204_0004/flink-conf.yaml 
2016-11-20 06:49:12,825 INFO  org.apache.flink.yarn.YarnClusterDescriptor                   
- Submitting application master application_1479621657204_0004 
2016-11-20 06:49:12,893 INFO  org.apache.hadoop.yarn.client.api.impl.YarnClientImpl         
- Submitted application application_1479621657204_0004 
2016-11-20 06:49:12,893 INFO  org.apache.flink.yarn.YarnClusterDescriptor                   
- Waiting for the cluster to be allocated 
2016-11-20 06:49:17,929 INFO  org.apache.flink.yarn.YarnClusterDescriptor                   
- YARN application has been deployed successfully. 
Flink JobManager is now running on 172.31.0.220:45056 
JobManager Web Interface: http://ip-172-31-2-68.ap-south-1.compute.internal:20888/proxy/application_1479621657204_0004/ 
2016-11-20 06:49:18,117 INFO  org.apache.flink.yarn.YarnClusterClient                       - Starting client actor system. 
2016-11-20 06:49:18,591 INFO  akka.event.slf4j.Slf4jLogger                                  - Slf4jLogger started 
2016-11-20 06:49:18,671 INFO  Remoting                                                       
akka.tcp://flink@172.31.0.220:45056/user/jobmanager. 
2016-11-20 06:49:19,343 INFO  org.apache.flink.yarn.ApplicationClient                       - Successfully registered at the ResourceManager using JobManager Actor[akka.tcp://flink@172.31.0.220:45056/user/jobmanager#1383364724] 
Number of connected TaskManagers changed to 2\. Slots available: 8 

```

这是 Flink 作业管理器 UI 的屏幕截图，我们可以看到两个任务管理器和八个任务插槽：

![启动 Flink YARN 会话](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-flink/img/image_09_013.jpg)

## 在 YARN 会话上执行 Flink 作业

现在我们可以使用这个 YARN 会话来提交 Flink 作业，执行以下命令：

```java
$./bin/flink run ./examples/batch/WordCount.jar

```

您将看到如下代码所示的词频统计作业的执行：

```java
2016-11-20 06:53:06,439 INFO  org.apache.flink.yarn.cli.FlinkYarnSessionCli                 
- Found YARN properties file /tmp/.yarn-properties-hadoop 
2016-11-20 06:53:06,439 INFO  org.apache.flink.yarn.cli.FlinkYarnSessionCli                 
- Found YARN properties file /tmp/.yarn-properties-hadoop 
Found YARN properties file /tmp/.yarn-properties-hadoop 
2016-11-20 06:53:06,508 INFO  org.apache.flink.yarn.cli.FlinkYarnSessionCli                 
-  
org.apache.flink.yarn.cli.FlinkYarnSessionCli                 
- YARN properties set default parallelism to 8 
YARN properties set default parallelism to 8 
2016-11-20 06:53:06,510 INFO  org.apache.flink.yarn.cli.FlinkYarnSessionCli                 
- Found YARN properties file /tmp/.yarn-properties-hadoop 
2016-11-20 06:53:07,069 INFO  org.apache.hadoop.yarn.client.api.impl.TimelineClientImpl     
- Timeline service address: http://ip-172-31-2-68.ap-south-1.compute.internal:8188/ws/v1/timeline/ 
Executing WordCount example with default input data set. 
Use --input to specify file input. 
Printing result to stdout. Use --output to specify output path. 
2016-11-20 06:53:07,728 INFO  org.apache.flink.yarn.YarnClusterClient                       - Waiting until all TaskManagers have connected 
Waiting until all TaskManagers have connected 
2016-11-20 06:53:07,729 INFO  org.apache.flink.yarn.YarnClusterClient                        
Submitting job with JobID: a0557f5751fa599b3eec30eb50d0a9ed. Waiting for job completion. 
Connected to JobManager at Actor[akka.tcp://flink@172.31.0.220:45056/user/jobmanager#1383364724] 
11/20/2016 06:53:09     Job execution switched to status RUNNING. 
11/20/2016 06:53:09     CHAIN DataSource (at getDefaultTextLineDataSet(WordCountData.java:70) (org.apache.flink.api.java.io.CollectionInputFormat)) -> FlatMap (FlatMap at main(WordCount.java:80)) -> Combine(SUM(1), at main(WordCount.java:83)(1/1) switched to SCHEDULED 
11/20/2016 06:53:09     CHAIN DataSource (at getDefaultTextLineDataSet(WordCountData.java:70) (org.apache.flink.api.java.io.CollectionInputFormat)) -> FlatMap (FlatMap at main(WordCount.java:80)) -> Combine(SUM(1), at main(WordCount.java:83)(1/1) switched to DEPLOYING 
11/20/2016 06:53:09     CHAIN DataSource (at getDefaultTextLineDataSet(WordCountData.java:70) (org.apache.flink.api.java.io.CollectionInputFormat)) -> FlatMap (FlatMap at main(WordCount.java:80)) -> Combine(SUM(1), at  
11/20/2016 06:53:10     DataSink (collect())(7/8) switched to FINISHED 
11/20/2016 06:53:10     DataSink (collect())(8/8) switched to FINISHED 
11/20/2016 06:53:10     Job execution switched to status FINISHED. 
(bourn,1) 
(coil,1) 
(come,1) 
(d,4) 
(dread,1) 
(is,3) 
(long,1) 
(make,2) 
(more,1) 
(must,1) 
(no,2) 
(oppressor,1) 
(pangs,1) 
(perchance,1) 
(sicklied,1) 
(something,1) 
(takes,1) 
(these,1) 
(us,3) 
(what,1) 
Program execution finished 
Job with JobID a0557f5751fa599b3eec30eb50d0a9ed has finished. 
Job Runtime: 903 ms 
Accumulator Results: 
- f895985ab9d76c97aba23bc6689c7936 (java.util.ArrayList) [170 elements] 

```

这是作业执行详细信息和任务分解的屏幕截图：

![在 YARN 会话上执行 Flink 作业](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-flink/img/image_09_014.jpg)

我们还可以看到时间轴详细信息，显示了所有并行执行的任务以及按顺序执行的任务。以下是同样的屏幕截图：

![在 YARN 会话上执行 Flink 作业](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-flink/img/image_09_015.jpg)

## 关闭集群

完成所有工作后，关闭集群非常重要。为此，我们需要再次转到 AWS 控制台，然后点击**终止**按钮。

## EMR 5.3+上的 Flink

AWS 现在默认支持其 EMR 集群中的 Flink。为了获得这一点，我们必须遵循这些说明。

首先，我们必须转到 AWS EMR 创建集群屏幕，然后点击**转到高级选项链接**，如下面的屏幕截图中所示：

![EMR 5.3+上的 Flink](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-flink/img/image_09_016.jpg)

接下来，您将看到一个屏幕，让您选择您希望拥有的其他服务。在那里，您需要勾选 Flink 1.1.4：

![EMR 5.3+上的 Flink](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-flink/img/image_09_017.jpg)

然后点击**下一步**按钮，继续进行其余的设置。其余步骤与我们在前几节中看到的相同。一旦集群启动并运行，您就可以直接使用 Flink。

## 在 Flink 应用程序中使用 S3

**亚马逊简单存储服务**（**S3**）是 AWS 提供的一种软件即服务，用于在 AWS 云中存储数据。许多公司使用 S3 进行廉价的数据存储。它是作为服务的托管文件系统。S3 可以用作 HDFS 的替代方案。如果某人不想投资于完整的 Hadoop 集群，可以考虑使用 S3 而不是 HDFS。Flink 为您提供 API，允许读取存储在 S3 上的数据。

我们可以像简单文件一样使用 S3 对象。以下代码片段显示了如何在 Flink 中使用 S3 对象：

```java
// Read data from S3 bucket 
env.readTextFile("s3://<bucket>/<endpoint>"); 

// Write data to S3 bucket 
stream.writeAsText("s3://<bucket>/<endpoint>"); 

// Use S3 as FsStatebackend 
env.setStateBackend(new FsStateBackend("s3://<your-bucket>/<endpoint>"));

```

Flink 将 S3 视为任何其他文件系统。它使用 Hadoop 的 S3 客户端。

要访问 S3 对象，Flink 需要进行身份验证。这可以通过使用 AWS IAM 服务来提供。这种方法有助于保持安全性，因为我们不需要分发访问密钥和秘密密钥。

# 总结

在本章中，我们学习了如何在 AWS 和 GCP 上部署 Flink。这对于更快的部署和安装非常方便。我们可以用最少的工作量生成和删除 Flink 集群。

在下一章中，我们将学习如何有效地使用 Flink 的最佳实践。
