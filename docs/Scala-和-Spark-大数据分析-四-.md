# Scala 和 Spark 大数据分析（四）

> 原文：[`zh.annas-archive.org/md5/39EECC62E023387EE8C22CA10D1A221A`](https://zh.annas-archive.org/md5/39EECC62E023387EE8C22CA10D1A221A)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：引入一点结构 - Spark SQL

“一台机器可以完成五十个普通人的工作。没有一台机器可以完成一个非凡人的工作。”

- Elbert Hubbard

在本章中，您将学习如何使用 Spark 分析结构化数据（非结构化数据，例如包含任意文本或其他格式的文档必须转换为结构化形式）；我们将看到 DataFrames/datasets 在这里是基石，以及 Spark SQL 的 API 如何使查询结构化数据变得简单而强大。此外，我们将介绍数据集，并看到数据集、DataFrames 和 RDD 之间的区别。简而言之，本章将涵盖以下主题：

+   Spark SQL 和 DataFrames

+   DataFrame 和 SQL API

+   DataFrame 模式

+   数据集和编码器

+   加载和保存数据

+   聚合

+   连接

# Spark SQL 和 DataFrames

在 Apache Spark 之前，每当有人想在大量数据上运行类似 SQL 的查询时，Apache Hive 都是首选技术。Apache Hive 基本上将 SQL 查询转换为类似 MapReduce 的逻辑，自动使得在大数据上执行许多种类的分析变得非常容易，而无需实际学习如何用 Java 和 Scala 编写复杂的代码。

随着 Apache Spark 的出现，我们在大数据规模上执行分析的方式发生了范式转变。Spark SQL 在 Apache Spark 的分布式计算能力之上提供了一个易于使用的类似 SQL 的层。事实上，Spark SQL 可以用作在线分析处理数据库。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00297.jpeg)

Spark SQL 通过将类似 SQL 的语句解析为**抽象语法树**（**AST**）来工作，随后将该计划转换为逻辑计划，然后将逻辑计划优化为可以执行的物理计划。最终的执行使用底层的 DataFrame API，使任何人都可以通过简单地使用类似 SQL 的接口而不是学习所有内部细节来使用 DataFrame API。由于本书深入探讨了各种 API 的技术细节，我们将主要涵盖 DataFrame API，并在某些地方展示 Spark SQL API，以对比使用 API 的不同方式。

因此，DataFrame API 是 Spark SQL 下面的基础层。在本章中，我们将向您展示如何使用各种技术创建 DataFrames，包括 SQL 查询和对 DataFrames 执行操作。

DataFrame 是**弹性分布式数据集**（**RDD**）的抽象，处理使用 catalyst 优化器优化的更高级函数，并且通过 Tungsten 计划也非常高效。您可以将数据集视为具有经过高度优化的数据的 RDD 的有效表。使用编码器实现了数据的二进制表示，编码器将各种对象序列化为二进制结构，比 RDD 表示具有更好的性能。由于 DataFrames 内部使用 RDD，因此 DataFrame/数据集也像 RDD 一样分布，因此也是分布式数据集。显然，这也意味着数据集是不可变的。

以下是数据的二进制表示的示例：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00037.jpeg)

数据集在 Spark 1.6 中添加，并在 DataFrames 之上提供了强类型的好处。事实上，自 Spark 2.0 以来，DataFrame 只是数据集的别名。

`org.apache.spark.sql`定义类型`DataFrame`为`dataset[Row]`，这意味着大多数 API 将与数据集和`DataFrames`一起很好地工作

**类型 DataFrame = dataset[Row]**

DataFrame 在概念上类似于关系数据库中的表。因此，DataFrame 包含数据行，每行由多个列组成。

我们需要牢记的第一件事就是，与 RDD 一样，DataFrames 是不可变的。DataFrames 具有不可变性的属性意味着每次转换或操作都会创建一个新的 DataFrame。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00034.jpeg)

让我们更深入地了解 DataFrame 以及它们与 RDD 的不同之处。如前所述，RDD 代表 Apache Spark 中数据操作的低级 API。DataFrame 是在 RDD 的基础上创建的，以抽象出 RDD 的低级内部工作，并公开易于使用且提供大量功能的高级 API。DataFrame 是通过遵循 Python pandas 包、R 语言、Julia 语言等中发现的类似概念创建的。

正如我们之前提到的，DataFrame 将 SQL 代码和特定领域语言表达式转换为优化的执行计划，以在 Spark Core API 之上运行 SQL 语句执行各种操作。DataFrame 支持许多不同类型的输入数据源和许多类型的操作。这包括所有类型的 SQL 操作，例如连接、分组、聚合和窗口函数，就像大多数数据库一样。Spark SQL 也与 Hive 查询语言非常相似，由于 Spark 提供了与 Apache Hive 的自然适配器，因此在 Apache Hive 中工作的用户可以轻松将其知识转移到 Spark SQL 中，从而最小化过渡时间。

DataFrame 基本上依赖于表的概念，如前所述。表可以操作得非常类似于 Apache Hive 的工作方式。实际上，Apache Spark 中表的许多操作与 Apache Hive 处理表和对这些表进行操作的方式非常相似。一旦有了作为 DataFrame 的表，就可以将 DataFrame 注册为表，并且可以使用 Spark SQL 语句操作数据，而不是使用 DataFrame API。

DataFrame 依赖于催化剂优化器和 Tungsten 性能改进，因此让我们简要地了解一下催化剂优化器的工作原理。催化剂优化器从输入 SQL 创建解析的逻辑计划，然后通过查看 SQL 语句中使用的所有各种属性和列来分析逻辑计划。一旦创建了分析的逻辑计划，催化剂优化器进一步尝试通过组合多个操作和重新排列逻辑来优化计划以获得更好的性能。

为了理解催化剂优化器，可以将其视为一种常识逻辑优化器，可以重新排序操作，例如过滤和转换，有时将几个操作组合成一个，以便最小化在工作节点之间传输的数据量。例如，催化剂优化器可能决定在执行不同数据集之间的联接操作时广播较小的数据集。使用 explain 查看任何数据框的执行计划。催化剂优化器还计算 DataFrame 的列和分区的统计信息，提高执行速度。

例如，如果数据分区上有转换和过滤器，那么过滤数据和应用转换的顺序对操作的整体性能非常重要。由于所有优化的结果，生成了优化的逻辑计划，然后将其转换为物理计划。显然，有几种物理计划可以执行相同的 SQL 语句并生成相同的结果。成本优化逻辑根据成本优化和估算确定并选择一个良好的物理计划。

钨性能改进是 Spark 2.x 背后的秘密酱的另一个关键因素，与之前的版本（如 Spark 1.6 和更早版本）相比，它提供了卓越的性能改进。钨实现了对内存管理和其他性能改进的彻底改革。最重要的内存管理改进使用对象的二进制编码，并在堆外和堆内存中引用它们。因此，钨允许使用二进制编码机制来编码所有对象的堆外内存。二进制编码的对象占用的内存要少得多。Tungsten 项目还改进了洗牌性能。

数据通常通过`DataFrameReader`加载到 DataFrame 中，并且数据通过`DataFrameWriter`保存。

# DataFrame API 和 SQL API

可以通过多种方式创建 DataFrame：

+   通过执行 SQL 查询

+   加载 Parquet、JSON、CSV、文本、Hive、JDBC 等外部数据

+   将 RDD 转换为数据框

可以通过加载 CSV 文件来创建 DataFrame。我们将查看一个名为`statesPopulation.csv`的 CSV 文件，它被加载为 DataFrame。

CSV 文件具有 2010 年至 2016 年美国各州人口的以下格式。

| **州** | **年份** | **人口** |
| --- | --- | --- |
| 阿拉巴马州 | 2010 | 4785492 |
| 阿拉斯加州 | 2010 | 714031 |
| 亚利桑那州 | 2010 | 6408312 |
| 阿肯色州 | 2010 | 2921995 |
| 加利福尼亚州 | 2010 | 37332685 |

由于此 CSV 具有标题，因此我们可以使用它快速加载到具有隐式模式检测的 DataFrame 中。

```scala
scala> val statesDF = spark.read.option("header", "true").option("inferschema", "true").option("sep", ",").csv("statesPopulation.csv")
statesDF: org.apache.spark.sql.DataFrame = [State: string, Year: int ... 1 more field]

```

加载 DataFrame 后，可以检查其模式：

```scala
scala> statesDF.printSchema
root
 |-- State: string (nullable = true)
 |-- Year: integer (nullable = true)
 |-- Population: integer (nullable = true)

```

`option("header", "true").option("inferschema", "true").option("sep", ",")` 告诉 Spark CSV 文件有`header`；逗号分隔符用于分隔字段/列，还可以隐式推断模式。

DataFrame 通过解析逻辑计划、分析逻辑计划、优化计划，最后执行执行物理计划来工作。

使用 DataFrame 上的 explain 显示执行计划：

```scala
scala> statesDF.explain(true)
== Parsed Logical Plan ==
Relation[State#0,Year#1,Population#2] csv
== Analyzed Logical Plan ==
State: string, Year: int, Population: int
Relation[State#0,Year#1,Population#2] csv
== Optimized Logical Plan ==
Relation[State#0,Year#1,Population#2] csv
== Physical Plan ==
*FileScan csv [State#0,Year#1,Population#2] Batched: false, Format: CSV, Location: InMemoryFileIndex[file:/Users/salla/states.csv], PartitionFilters: [], PushedFilters: [], ReadSchema: struct<State:string,Year:int,Population:int>

```

DataFrame 还可以注册为表名（如下所示），然后您可以像关系数据库一样输入 SQL 语句。

```scala
scala> statesDF.createOrReplaceTempView("states")

```

一旦我们将 DataFrame 作为结构化 DataFrame 或表，我们可以运行命令来操作数据：

```scala
scala> statesDF.show(5)
scala> spark.sql("select * from states limit 5").show
+----------+----+----------+
| State|Year|Population|
+----------+----+----------+
| Alabama|2010| 4785492|
| Alaska|2010| 714031|
| Arizona|2010| 6408312|
| Arkansas|2010| 2921995|
|California|2010| 37332685|
+----------+----+----------+

```

如果您看到上述代码片段，我们已经编写了类似 SQL 的语句，并使用`spark.sql` API 执行了它。

请注意，Spark SQL 只是转换为 DataFrame API 以进行执行，SQL 只是用于方便使用的 DSL。

使用 DataFrame 上的`sort`操作，可以按任何列对 DataFrame 中的行进行排序。我们可以看到使用`Population`列进行降序`sort`的效果如下。行按人口数量降序排序。

```scala
scala> statesDF.sort(col("Population").desc).show(5)
scala> spark.sql("select * from states order by Population desc limit 5").show
+----------+----+----------+
| State|Year|Population|
+----------+----+----------+
|California|2016| 39250017|
|California|2015| 38993940|
|California|2014| 38680810|
|California|2013| 38335203|
|California|2012| 38011074|
+----------+----+----------+

```

使用`groupBy`可以按任何列对 DataFrame 进行分组。以下是按`State`分组行，然后对每个`State`的`Population`计数进行求和的代码。

```scala
scala> statesDF.groupBy("State").sum("Population").show(5)
scala> spark.sql("select State, sum(Population) from states group by State limit 5").show
+---------+---------------+
| State|sum(Population)|
+---------+---------------+
| Utah| 20333580|
| Hawaii| 9810173|
|Minnesota| 37914011|
| Ohio| 81020539|
| Arkansas| 20703849|
+---------+---------------+

```

使用`agg`操作，您可以对 DataFrame 的列执行许多不同的操作，例如查找列的`min`、`max`和`avg`。您还可以执行操作并同时重命名列，以适应您的用例。

```scala
scala> statesDF.groupBy("State").agg(sum("Population").alias("Total")).show(5)
scala> spark.sql("select State, sum(Population) as Total from states group by State limit 5").show
+---------+--------+
| State| Total|
+---------+--------+
| Utah|20333580|
| Hawaii| 9810173|
|Minnesota|37914011|
| Ohio|81020539|
| Arkansas|20703849|
+---------+--------+

```

自然，逻辑越复杂，执行计划也越复杂。让我们看看`groupBy`和`agg` API 调用的执行计划，以更好地了解底层发生了什么。以下是显示按`State`分组和人口总和的执行计划的代码：

```scala
scala> statesDF.groupBy("State").agg(sum("Population").alias("Total")).explain(true)
== Parsed Logical Plan ==
'Aggregate [State#0], [State#0, sum('Population) AS Total#31886]
+- Relation[State#0,Year#1,Population#2] csv

== Analyzed Logical Plan ==
State: string, Total: bigint
Aggregate [State#0], [State#0, sum(cast(Population#2 as bigint)) AS Total#31886L]
+- Relation[State#0,Year#1,Population#2] csv

== Optimized Logical Plan ==
Aggregate [State#0], [State#0, sum(cast(Population#2 as bigint)) AS Total#31886L]
+- Project [State#0, Population#2]
 +- Relation[State#0,Year#1,Population#2] csv

== Physical Plan ==
*HashAggregate(keys=[State#0], functions=[sum(cast(Population#2 as bigint))], output=[State#0, Total#31886L])
+- Exchange hashpartitioning(State#0, 200)
 +- *HashAggregate(keys=[State#0], functions=[partial_sum(cast(Population#2 as bigint))], output=[State#0, sum#31892L])
 +- *FileScan csv [State#0,Population#2] Batched: false, Format: CSV, Location: InMemoryFileIndex[file:/Users/salla/states.csv], PartitionFilters: [], PushedFilters: [], ReadSchema: struct<State:string,Population:int>

```

DataFrame 操作可以很好地链接在一起，以便执行可以利用成本优化（钨性能改进和催化剂优化器共同工作）。

我们还可以将操作链接在一条语句中，如下所示，我们不仅按`State`列对数据进行分组，然后对`Population`值进行求和，还对 DataFrame 进行排序：

```scala
scala> statesDF.groupBy("State").agg(sum("Population").alias("Total")).sort(col("Total").desc).show(5)
scala> spark.sql("select State, sum(Population) as Total from states group by State order by Total desc limit 5").show
+----------+---------+
| State| Total|
+----------+---------+
|California|268280590|
| Texas|185672865|
| Florida|137618322|
| New York|137409471|
| Illinois| 89960023|
+----------+---------+

```

前面的链式操作包括多个转换和操作，可以使用以下图表进行可视化：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00042.jpeg)

也可以同时创建多个聚合，如下所示：

```scala
scala> statesDF.groupBy("State").agg(
             min("Population").alias("minTotal"), 
             max("Population").alias("maxTotal"),        
             avg("Population").alias("avgTotal"))
           .sort(col("minTotal").desc).show(5) 
scala> spark.sql("select State, min(Population) as minTotal, max(Population) as maxTotal, avg(Population) as avgTotal from states group by State order by minTotal desc limit 5").show
+----------+--------+--------+--------------------+
| State|minTotal|maxTotal| avgTotal|
+----------+--------+--------+--------------------+
|California|37332685|39250017|3.8325798571428575E7|
| Texas|25244310|27862596| 2.6524695E7|
| New York|19402640|19747183| 1.962992442857143E7|
| Florida|18849098|20612439|1.9659760285714287E7|
| Illinois|12801539|12879505|1.2851431857142856E7|
+----------+--------+--------+--------------------+

```

# 旋转

旋转是将表转换为不同视图的一种很好的方式，更适合进行许多汇总和聚合。这是通过取列的值并使每个值成为实际列来实现的。

为了更好地理解这一点，让我们通过`Year`来旋转 DataFrame 的行并检查结果，结果显示，现在，列`Year`通过将每个唯一值转换为实际列创建了几个新列。这样做的最终结果是，现在，我们不仅可以查看年份列，还可以使用按年份创建的列来进行汇总和聚合。

```scala
scala> statesDF.groupBy("State").pivot("Year").sum("Population").show(5)
+---------+--------+--------+--------+--------+--------+--------+--------+
| State| 2010| 2011| 2012| 2013| 2014| 2015| 2016|
+---------+--------+--------+--------+--------+--------+--------+--------+
| Utah| 2775326| 2816124| 2855782| 2902663| 2941836| 2990632| 3051217|
| Hawaii| 1363945| 1377864| 1391820| 1406481| 1416349| 1425157| 1428557|
|Minnesota| 5311147| 5348562| 5380285| 5418521| 5453109| 5482435| 5519952|
| Ohio|11540983|11544824|11550839|11570022|11594408|11605090|11614373|
| Arkansas| 2921995| 2939493| 2950685| 2958663| 2966912| 2977853| 2988248|
+---------+--------+--------+--------+--------+--------+--------+--------+

```

# 过滤器

DataFrame 还支持过滤器，可以用于快速过滤 DataFrame 行以生成新的 DataFrame。过滤器使得数据的重要转换变得非常重要，可以将 DataFrame 缩小到我们的用例。例如，如果您只想分析加利福尼亚州的情况，那么使用`filter` API 可以在每个数据分区上消除不匹配的行，从而提高操作的性能。

让我们查看过滤 DataFrame 以仅考虑加利福尼亚州的执行计划。

```scala
scala> statesDF.filter("State == 'California'").explain(true)

== Parsed Logical Plan ==
'Filter ('State = California)
+- Relation[State#0,Year#1,Population#2] csv

== Analyzed Logical Plan ==
State: string, Year: int, Population: int
Filter (State#0 = California)
+- Relation[State#0,Year#1,Population#2] csv

== Optimized Logical Plan ==
Filter (isnotnull(State#0) && (State#0 = California))
+- Relation[State#0,Year#1,Population#2] csv

== Physical Plan ==
*Project [State#0, Year#1, Population#2]
+- *Filter (isnotnull(State#0) && (State#0 = California))
 +- *FileScan csv [State#0,Year#1,Population#2] Batched: false, Format: CSV, Location: InMemoryFileIndex[file:/Users/salla/states.csv], PartitionFilters: [], PushedFilters: [IsNotNull(State), EqualTo(State,California)], ReadSchema: struct<State:string,Year:int,Population:int>

```

现在我们可以看到执行计划，让我们执行`filter`命令，如下所示：

```scala
scala> statesDF.filter("State == 'California'").show
+----------+----+----------+
| State|Year|Population|
+----------+----+----------+
|California|2010| 37332685|
|California|2011| 37676861|
|California|2012| 38011074|
|California|2013| 38335203|
|California|2014| 38680810|
|California|2015| 38993940|
|California|2016| 39250017|
+----------+----+----------+

```

# 用户定义函数（UDFs）

UDFs 定义了扩展 Spark SQL 功能的新基于列的函数。通常，Spark 提供的内置函数不能处理我们确切的需求。在这种情况下，Apache Spark 支持创建可以使用的 UDF。

`udf()`在内部调用一个案例类用户定义函数，它本身在内部调用 ScalaUDF。

让我们通过一个简单将 State 列值转换为大写的 UDF 示例来进行说明。

首先，我们在 Scala 中创建我们需要的函数。

```scala
import org.apache.spark.sql.functions._

scala> val toUpper: String => String = _.toUpperCase
toUpper: String => String = <function1>

```

然后，我们必须将创建的函数封装在`udf`中以创建 UDF。

```scala
scala> val toUpperUDF = udf(toUpper)
toUpperUDF: org.apache.spark.sql.expressions.UserDefinedFunction = UserDefinedFunction(<function1>,StringType,Some(List(StringType)))

```

现在我们已经创建了`udf`，我们可以使用它将 State 列转换为大写。

```scala
scala> statesDF.withColumn("StateUpperCase", toUpperUDF(col("State"))).show(5)
+----------+----+----------+--------------+
| State|Year|Population|StateUpperCase|
+----------+----+----------+--------------+
| Alabama|2010| 4785492| ALABAMA|
| Alaska|2010| 714031| ALASKA|
| Arizona|2010| 6408312| ARIZONA|
| Arkansas|2010| 2921995| ARKANSAS|
|California|2010| 37332685| CALIFORNIA|
+----------+----+----------+--------------+

```

# 数据的模式结构

模式是数据结构的描述，可以是隐式的或显式的。

由于 DataFrame 在内部基于 RDD，因此有两种将现有 RDD 转换为数据集的主要方法。可以使用反射将 RDD 转换为数据集，以推断 RDD 的模式。创建数据集的第二种方法是通过编程接口，使用该接口可以获取现有 RDD 并提供模式以将 RDD 转换为具有模式的数据集。

为了通过反射推断模式从 RDD 创建 DataFrame，Spark 的 Scala API 提供了可以用来定义表模式的案例类。DataFrame 是通过 RDD 以编程方式创建的，因为在所有情况下都不容易使用案例类。例如，在 1000 列表上创建案例类是耗时的。

# 隐式模式

让我们看一个将**CSV**（逗号分隔值）文件加载到 DataFrame 中的示例。每当文本文件包含标题时，读取 API 可以通过读取标题行来推断模式。我们还可以选择指定用于拆分文本文件行的分隔符。

我们从标题行推断模式读取`csv`并使用逗号（`,`）作为分隔符。我们还展示了`schema`命令和`printSchema`命令来验证输入文件的模式。

```scala
scala> val statesDF = spark.read.option("header", "true")
                                .option("inferschema", "true")
                                .option("sep", ",")
                                .csv("statesPopulation.csv")
statesDF: org.apache.spark.sql.DataFrame = [State: string, Year: int ... 1 more field]

scala> statesDF.schema
res92: org.apache.spark.sql.types.StructType = StructType(
                                                  StructField(State,StringType,true),
                                                  StructField(Year,IntegerType,true),
                                                  StructField(Population,IntegerType,true))
scala> statesDF.printSchema
root
 |-- State: string (nullable = true)
 |-- Year: integer (nullable = true)
 |-- Population: integer (nullable = true)

```

# 显式模式

使用`StructType`来描述模式，它是`StructField`对象的集合。

`StructType`和`StructField`属于`org.apache.spark.sql.types`包。

诸如`IntegerType`、`StringType`之类的数据类型也属于`org.apache.spark.sql.types`包。

使用这些导入，我们可以定义一个自定义的显式模式。

首先，导入必要的类：

```scala
scala> import org.apache.spark.sql.types.{StructType, IntegerType, StringType}
import org.apache.spark.sql.types.{StructType, IntegerType, StringType}

```

定义一个包含两列/字段的模式-一个`Integer`，后面是一个`String`：

```scala
scala> val schema = new StructType().add("i", IntegerType).add("s", StringType)
schema: org.apache.spark.sql.types.StructType = StructType(StructField(i,IntegerType,true), StructField(s,StringType,true))

```

打印新创建的`schema`很容易：

```scala
scala> schema.printTreeString
root
 |-- i: integer (nullable = true)
 |-- s: string (nullable = true)

```

还有一个选项可以打印 JSON，如下所示，使用`prettyJson`函数：

```scala
scala> schema.prettyJson
res85: String =
{
 "type" : "struct",
 "fields" : [ {
 "name" : "i",
 "type" : "integer",
 "nullable" : true,
 "metadata" : { }
 }, {
 "name" : "s",
 "type" : "string",
 "nullable" : true,
 "metadata" : { }
 } ]
}

```

Spark SQL 的所有数据类型都位于包`org.apache.spark.sql.types`中。您可以通过以下方式访问它们：

```scala
import org.apache.spark.sql.types._

```

# Encoders

Spark 2.x 支持一种不同的方式来定义复杂数据类型的模式。首先，让我们来看一个简单的例子。

为了使用 Encoders，必须使用 import 语句导入 Encoders：

```scala
import org.apache.spark.sql.Encoders 

```

让我们来看一个简单的例子，定义一个元组作为数据类型在数据集 API 中使用：

```scala

scala> Encoders.product[(Integer, String)].schema.printTreeString
root
 |-- _1: integer (nullable = true)
 |-- _2: string (nullable = true)

```

上述代码看起来在任何时候都很复杂，所以我们也可以为我们的需求定义一个案例类，然后使用它。我们可以定义一个名为`Record`的案例类，有两个字段-一个`Integer`和一个`String`：

```scala
scala> case class Record(i: Integer, s: String)
defined class Record

```

使用`Encoders`，我们可以轻松地在案例类之上创建一个`schema`，从而使我们能够轻松使用各种 API：

```scala
scala> Encoders.product[Record].schema.printTreeString
root
 |-- i: integer (nullable = true)
 |-- s: string (nullable = true)

```

Spark SQL 的所有数据类型都位于包**`org.apache.spark.sql.types`**中。您可以通过以下方式访问它们：

```scala
import org.apache.spark.sql.types._

```

您应该在代码中使用`DataTypes`对象来创建复杂的 Spark SQL 类型，如数组或映射，如下所示：

```scala
scala> import org.apache.spark.sql.types.DataTypes
import org.apache.spark.sql.types.DataTypes

scala> val arrayType = DataTypes.createArrayType(IntegerType)
arrayType: org.apache.spark.sql.types.ArrayType = ArrayType(IntegerType,true)

```

以下是 Spark SQL API 中支持的数据类型：

| **数据类型** | **Scala 中的值类型** | **访问或创建数据类型的 API** |
| --- | --- | --- |
| `ByteType` | `Byte` | `ByteType` |
| `ShortType` | `Short` | `ShortType` |
| `IntegerType` | `Int` | `IntegerType` |
| `LongType` | `Long` | `LongType` |
| `FloatType` | `Float` | `FloatType` |
| `DoubleType` | `Double` | `DoubleType` |
| `DecimalType` | `java.math.BigDecimal` | `DecimalType` |
| `StringType` | `String` | `StringType` |
| `BinaryType` | `Array[Byte]` | `BinaryType` |
| `BooleanType` | `Boolean` | `BooleanType` |
| `TimestampType` | `java.sql.Timestamp` | `TimestampType` |
| `DateType` | `java.sql.Date` | `DateType` |
| `ArrayType` | `scala.collection.Seq` | `ArrayType(elementType, [containsNull])` |
| `MapType` | `scala.collection.Map` | `MapType(keyType, valueType, [valueContainsNull])` 注意：`valueContainsNull`的默认值为`true`。 |
| `StructType` | `org.apache.spark.sql.Row` | `StructType(fields)` 注意：fields 是`StructFields`的`Seq`。另外，不允许有相同名称的两个字段。 |

# 加载和保存数据集

我们需要将数据读入集群作为输入和输出，或者将结果写回存储，以便对我们的代码进行任何实际操作。输入数据可以从各种数据集和来源中读取，如文件、Amazon S3 存储、数据库、NoSQL 和 Hive，输出也可以类似地保存到文件、S3、数据库、Hive 等。

几个系统通过连接器支持 Spark，并且随着更多系统接入 Spark 处理框架，这个数字正在日益增长。

# 加载数据集

Spark SQL 可以通过`DataFrameReader`接口从外部存储系统，如文件、Hive 表和 JDBC 数据库中读取数据。

API 调用的格式是`spark.read.inputtype`

+   Parquet

+   CSV

+   Hive 表

+   JDBC

+   ORC

+   文本

+   JSON

让我们来看一些简单的例子，将 CSV 文件读入 DataFrame 中：

```scala
scala> val statesPopulationDF = spark.read.option("header", "true").option("inferschema", "true").option("sep", ",").csv("statesPopulation.csv")
statesPopulationDF: org.apache.spark.sql.DataFrame = [State: string, Year: int ... 1 more field]

scala> val statesTaxRatesDF = spark.read.option("header", "true").option("inferschema", "true").option("sep", ",").csv("statesTaxRates.csv")
statesTaxRatesDF: org.apache.spark.sql.DataFrame = [State: string, TaxRate: double]

```

# 保存数据集

Spark SQL 可以将数据保存到外部存储系统，如文件、Hive 表和 JDBC 数据库，通过`DataFrameWriter`接口。

API 调用的格式是`dataframe``.write.outputtype`

+   Parquet

+   ORC

+   文本

+   Hive 表

+   JSON

+   CSV

+   JDBC

让我们来看一些将 DataFrame 写入或保存到 CSV 文件的例子：

```scala
scala> statesPopulationDF.write.option("header", "true").csv("statesPopulation_dup.csv")

scala> statesTaxRatesDF.write.option("header", "true").csv("statesTaxRates_dup.csv")

```

# 聚合

聚合是根据条件收集数据并对数据进行分析的方法。聚合对于理解各种规模的数据非常重要，因为仅仅拥有原始数据记录对于大多数用例来说并不那么有用。

例如，如果你看下面的表，然后看聚合视图，很明显，仅仅原始记录并不能帮助你理解数据。

想象一个包含世界上每个城市每天的一次温度测量的表，为期五年。

下面是一个包含每个城市每天平均温度记录的表：

| **城市** | **日期** | **温度** |
| --- | --- | --- |
| Boston | 12/23/2016 | 32 |
| New York | 12/24/2016 | 36 |
| Boston | 12/24/2016 | 30 |
| Philadelphia | 12/25/2016 | 34 |
| Boston | 12/25/2016 | 28 |

如果我们想要计算上表中我们有测量数据的所有天的每个城市的平均温度，我们可以看到类似以下表的结果：

| **城市** | **平均温度** |
| --- | --- |
| Boston | 30 - *(32 + 30 + 28)/3* |
| New York | 36 |
| Philadelphia | 34 |

# 聚合函数

大多数聚合可以使用`org.apache.spark.sql.functions`包中的函数来完成。此外，还可以创建自定义聚合函数，也称为**用户定义的聚合函数**（**UDAF**）。

每个分组操作都返回一个`RelationalGroupeddataset`，您可以在其中指定聚合。

我们将加载示例数据，以说明本节中所有不同类型的聚合函数：

```scala
val statesPopulationDF = spark.read.option("header", "true").option("inferschema", "true").option("sep", ",").csv("statesPopulation.csv")

```

# 计数

计数是最基本的聚合函数，它只是计算指定列的行数。扩展是`countDistinct`，它还可以消除重复项。

`count` API 有几种实现，如下所示。使用的确切 API 取决于特定的用例：

```scala
def count(columnName: String): TypedColumn[Any, Long]
Aggregate function: returns the number of items in a group.

def count(e: Column): Column
Aggregate function: returns the number of items in a group.

def countDistinct(columnName: String, columnNames: String*): Column
Aggregate function: returns the number of distinct items in a group.

def countDistinct(expr: Column, exprs: Column*): Column
Aggregate function: returns the number of distinct items in a group.

```

让我们看看如何在 DataFrame 上调用`count`和`countDistinct`来打印行计数：

```scala
import org.apache.spark.sql.functions._
scala> statesPopulationDF.select(col("*")).agg(count("State")).show
scala> statesPopulationDF.select(count("State")).show
+------------+
|count(State)|
+------------+
| 350|
+------------+

scala> statesPopulationDF.select(col("*")).agg(countDistinct("State")).show
scala> statesPopulationDF.select(countDistinct("State")).show
+---------------------+
|count(DISTINCT State)|
+---------------------+
| 50|

```

# 首先

获取`RelationalGroupeddataset`中的第一条记录。

`first` API 有几种实现，如下所示。使用的确切 API 取决于特定的用例：

```scala
def first(columnName: String): Column
Aggregate function: returns the first value of a column in a group.

def first(e: Column): Column
Aggregate function: returns the first value in a group.

def first(columnName: String, ignoreNulls: Boolean): Column
Aggregate function: returns the first value of a column in a group.

def first(e: Column, ignoreNulls: Boolean): Column
Aggregate function: returns the first value in a group.

```

让我们看一个在 DataFrame 上调用`first`来输出第一行的例子：

```scala
import org.apache.spark.sql.functions._
scala> statesPopulationDF.select(first("State")).show
+-------------------+
|first(State, false)|
+-------------------+
| Alabama|
+-------------------+

```

# 最后

获取`RelationalGroupeddataset`中的最后一条记录。

`last` API 有几种实现，如下所示。使用的确切 API 取决于特定的用例：

```scala
def last(columnName: String): Column
Aggregate function: returns the last value of the column in a group.

def last(e: Column): Column
Aggregate function: returns the last value in a group.

def last(columnName: String, ignoreNulls: Boolean): Column
Aggregate function: returns the last value of the column in a group.

def last(e: Column, ignoreNulls: Boolean): Column
Aggregate function: returns the last value in a group.

```

让我们看一个在 DataFrame 上调用`last`来输出最后一行的例子。

```scala
import org.apache.spark.sql.functions._
scala> statesPopulationDF.select(last("State")).show
+------------------+
|last(State, false)|
+------------------+
| Wyoming|
+------------------+

```

# approx_count_distinct

近似不同计数要快得多，它可以近似计算不同记录的数量，而不是进行精确计数，后者通常需要大量的洗牌和其他操作。虽然近似计数不是 100%准确，但许多用例即使没有精确计数也可以表现得同样好。

`approx_count_distinct` API 有几种实现，如下所示。使用的确切 API 取决于特定的用例。

```scala
def approx_count_distinct(columnName: String, rsd: Double): Column
Aggregate function: returns the approximate number of distinct items in a group.

def approx_count_distinct(e: Column, rsd: Double): Column
Aggregate function: returns the approximate number of distinct items in a group.

def approx_count_distinct(columnName: String): Column
Aggregate function: returns the approximate number of distinct items in a group.

def approx_count_distinct(e: Column): Column
Aggregate function: returns the approximate number of distinct items in a group.

```

让我们看一个在 DataFrame 上调用`approx_count_distinct`来打印 DataFrame 的近似计数的例子：

```scala
import org.apache.spark.sql.functions._
scala> statesPopulationDF.select(col("*")).agg(approx_count_distinct("State")).show
+----------------------------+
|approx_count_distinct(State)|
+----------------------------+
| 48|
+----------------------------+

scala> statesPopulationDF.select(approx_count_distinct("State", 0.2)).show
+----------------------------+
|approx_count_distinct(State)|
+----------------------------+
| 49|
+----------------------------+

```

# 最小

DataFrame 中某一列的最小值。例如，如果要查找城市的最低温度。

`min` API 有几种实现，如下所示。使用的确切 API 取决于特定的用例：

```scala
def min(columnName: String): Column
Aggregate function: returns the minimum value of the column in a group.

def min(e: Column): Column
Aggregate function: returns the minimum value of the expression in a group.

```

让我们看一个在 DataFrame 上调用`min`来打印最小人口的例子：

```scala
import org.apache.spark.sql.functions._
scala> statesPopulationDF.select(min("Population")).show
+---------------+
|min(Population)|
+---------------+
| 564513|
+---------------+

```

# 最大

DataFrame 中某一列的最大值。例如，如果要查找城市的最高温度。

`max` API 有几种实现，如下所示。使用的确切 API 取决于特定的用例。

```scala
def max(columnName: String): Column
Aggregate function: returns the maximum value of the column in a group.

def max(e: Column): Column
Aggregate function: returns the maximum value of the expression in a group.

```

让我们看一个在 DataFrame 上调用`max`来打印最大人口的例子：

```scala
import org.apache.spark.sql.functions._
scala> statesPopulationDF.select(max("Population")).show
+---------------+
|max(Population)|
+---------------+
| 39250017|
+---------------+

```

# 平均

值的平均数是通过将值相加并除以值的数量来计算的。

1,2,3 的平均值是(1 + 2 + 3) / 3 = 6/3 = 2

`avg` API 有几种实现，如下所示。使用的确切 API 取决于特定的用例：

```scala
def avg(columnName: String): Column
Aggregate function: returns the average of the values in a group.

def avg(e: Column): Column
Aggregate function: returns the average of the values in a group.

```

让我们看一个在 DataFrame 上调用`avg`来打印平均人口的例子：

```scala
import org.apache.spark.sql.functions._
scala> statesPopulationDF.select(avg("Population")).show
+-----------------+
| avg(Population)|
+-----------------+
|6253399.371428572|
+-----------------+

```

# 总和

计算列值的总和。可以选择使用`sumDistinct`仅添加不同的值。

`sum` API 有几种实现，如下所示。使用的确切 API 取决于特定的用例：

```scala
def sum(columnName: String): Column
Aggregate function: returns the sum of all values in the given column.

def sum(e: Column): Column
Aggregate function: returns the sum of all values in the expression.

def sumDistinct(columnName: String): Column
Aggregate function: returns the sum of distinct values in the expression

def sumDistinct(e: Column): Column
Aggregate function: returns the sum of distinct values in the expression.

```

让我们看一个在 DataFrame 上调用`sum`的例子，打印`Population`的总和。

```scala
import org.apache.spark.sql.functions._
scala> statesPopulationDF.select(sum("Population")).show
+---------------+
|sum(Population)|
+---------------+
| 2188689780|
+---------------+

```

# 峰度

峰度是量化分布形状差异的一种方式，这些分布在均值和方差方面可能看起来非常相似，但实际上是不同的。在这种情况下，峰度成为分布尾部的权重与分布中部的权重相比的一个很好的度量。

`kurtosis` API 有几种实现，具体使用的 API 取决于特定的用例。

```scala
def kurtosis(columnName: String): Column
Aggregate function: returns the kurtosis of the values in a group.

def kurtosis(e: Column): Column
Aggregate function: returns the kurtosis of the values in a group.

```

让我们看一个在 DataFrame 的`Population`列上调用`kurtosis`的例子：

```scala
import org.apache.spark.sql.functions._
scala> statesPopulationDF.select(kurtosis("Population")).show
+--------------------+
|kurtosis(Population)|
+--------------------+
| 7.727421920829375|
+--------------------+

```

# Skewness

Skewness 测量数据中值围绕平均值或均值的不对称性。

`skewness` API 有几种实现，具体使用的 API 取决于特定的用例。

```scala
def skewness(columnName: String): Column
Aggregate function: returns the skewness of the values in a group.

def skewness(e: Column): Column
Aggregate function: returns the skewness of the values in a group.

```

让我们看一个在人口列上调用`skewness`的 DataFrame 的例子：

```scala
import org.apache.spark.sql.functions._
scala> statesPopulationDF.select(skewness("Population")).show
+--------------------+
|skewness(Population)|
+--------------------+
| 2.5675329049100024|
+--------------------+

```

# 方差

方差是每个值与均值的差的平方的平均值。

`var` API 有几种实现，具体使用的 API 取决于特定的用例：

```scala
def var_pop(columnName: String): Column
Aggregate function: returns the population variance of the values in a group.

def var_pop(e: Column): Column
Aggregate function: returns the population variance of the values in a group.

def var_samp(columnName: String): Column
Aggregate function: returns the unbiased variance of the values in a group.

def var_samp(e: Column): Column
Aggregate function: returns the unbiased variance of the values in a group.

```

现在，让我们看一个在测量`Population`方差的 DataFrame 上调用`var_pop`的例子：

```scala
import org.apache.spark.sql.functions._
scala> statesPopulationDF.select(var_pop("Population")).show
+--------------------+
| var_pop(Population)|
+--------------------+
|4.948359064356177E13|
+--------------------+

```

# 标准差

标准差是方差的平方根（见前文）。

`stddev` API 有几种实现，具体使用的 API 取决于特定的用例：

```scala
def stddev(columnName: String): Column
Aggregate function: alias for stddev_samp.

def stddev(e: Column): Column
Aggregate function: alias for stddev_samp.

def stddev_pop(columnName: String): Column
Aggregate function: returns the population standard deviation of the expression in a group.

def stddev_pop(e: Column): Column
Aggregate function: returns the population standard deviation of the expression in a group.

def stddev_samp(columnName: String): Column
Aggregate function: returns the sample standard deviation of the expression in a group.

def stddev_samp(e: Column): Column
Aggregate function: returns the sample standard deviation of the expression in a group.

```

让我们看一个在 DataFrame 上调用`stddev`的例子，打印`Population`的标准差：

```scala
import org.apache.spark.sql.functions._
scala> statesPopulationDF.select(stddev("Population")).show
+-----------------------+
|stddev_samp(Population)|
+-----------------------+
| 7044528.191173398|
+-----------------------+

```

# 协方差

协方差是两个随机变量联合变异性的度量。如果一个变量的较大值主要对应于另一个变量的较大值，并且较小值也是如此，那么这些变量倾向于显示相似的行为，协方差是正的。如果相反是真的，并且一个变量的较大值对应于另一个变量的较小值，那么协方差是负的。

`covar` API 有几种实现，具体使用的 API 取决于特定的用例。

```scala
def covar_pop(columnName1: String, columnName2: String): Column
Aggregate function: returns the population covariance for two columns.

def covar_pop(column1: Column, column2: Column): Column
Aggregate function: returns the population covariance for two columns.

def covar_samp(columnName1: String, columnName2: String): Column
Aggregate function: returns the sample covariance for two columns.

def covar_samp(column1: Column, column2: Column): Column
Aggregate function: returns the sample covariance for two columns.

```

让我们看一个在 DataFrame 上调用`covar_pop`的例子，计算年份和人口列之间的协方差：

```scala
import org.apache.spark.sql.functions._
scala> statesPopulationDF.select(covar_pop("Year", "Population")).show
+---------------------------+
|covar_pop(Year, Population)|
+---------------------------+
| 183977.56000006935|
+---------------------------+

```

# groupBy

数据分析中常见的任务是将数据分组为分组类别，然后对结果数据组执行计算。

理解分组的一种快速方法是想象被要求迅速评估办公室所需的物品。您可以开始四处看看，并将不同类型的物品分组，例如笔、纸、订书机，并分析您拥有的和您需要的。

让我们在`DataFrame`上运行`groupBy`函数，打印每个州的聚合计数：

```scala
scala> statesPopulationDF.groupBy("State").count.show(5)
+---------+-----+
| State|count|
+---------+-----+
| Utah| 7|
| Hawaii| 7|
|Minnesota| 7|
| Ohio| 7|
| Arkansas| 7|
+---------+-----+

```

您还可以`groupBy`，然后应用先前看到的任何聚合函数，例如`min`、`max`、`avg`、`stddev`等：

```scala
import org.apache.spark.sql.functions._
scala> statesPopulationDF.groupBy("State").agg(min("Population"), avg("Population")).show(5)
+---------+---------------+--------------------+
| State|min(Population)| avg(Population)|
+---------+---------------+--------------------+
| Utah| 2775326| 2904797.1428571427|
| Hawaii| 1363945| 1401453.2857142857|
|Minnesota| 5311147| 5416287.285714285|
| Ohio| 11540983|1.1574362714285715E7|
| Arkansas| 2921995| 2957692.714285714|
+---------+---------------+--------------------+

```

# Rollup

Rollup 是用于执行分层或嵌套计算的多维聚合。例如，如果我们想显示每个州+年份组的记录数，以及每个州的记录数（聚合所有年份以给出每个`State`的总数，而不考虑`Year`），我们可以使用`rollup`如下：

```scala
scala> statesPopulationDF.rollup("State", "Year").count.show(5)
+------------+----+-----+
| State|Year|count|
+------------+----+-----+
|South Dakota|2010| 1|
| New York|2012| 1|
| California|2014| 1|
| Wyoming|2014| 1|
| Hawaii|null| 7|
+------------+----+-----+

```

`rollup`计算州和年份的计数，例如加利福尼亚+2014，以及加利福尼亚州（所有年份的总和）。

# Cube

Cube 是用于执行分层或嵌套计算的多维聚合，就像 rollup 一样，但不同之处在于 cube 对所有维度执行相同的操作。例如，如果我们想显示每个`State`和`Year`组的记录数，以及每个`State`的记录数（聚合所有年份以给出每个`State`的总数，而不考虑`Year`），我们可以使用 rollup 如下。此外，`cube`还显示每年的总数（不考虑`State`）：

```scala
scala> statesPopulationDF.cube("State", "Year").count.show(5)
+------------+----+-----+
| State|Year|count|
+------------+----+-----+
|South Dakota|2010| 1|
| New York|2012| 1|
| null|2014| 50|
| Wyoming|2014| 1|
| Hawaii|null| 7|
+------------+----+-----+

```

# 窗口函数

窗口函数允许您在数据窗口上执行聚合，而不是整个数据或一些经过筛选的数据。这些窗口函数的用例包括：

+   累积总和

+   与先前相同键的前一个值的增量

+   加权移动平均

理解窗口函数的最佳方法是想象一个滑动窗口覆盖整个数据集。您可以指定一个窗口，查看三行 T-1、T 和 T+1，并进行简单的计算。您还可以指定最新/最近的十个值的窗口：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00047.jpeg)

窗口规范的 API 需要三个属性，`partitionBy()`，`orderBy()`和`rowsBetween()`。`partitionBy`将数据分成由`partitionBy()`指定的分区/组。`orderBy()`用于对数据进行排序，以便在每个数据分区内进行排序。

`rowsBetween()`指定了滑动窗口的窗口帧或跨度来执行计算。

要尝试窗口函数，需要某些包。您可以使用导入指令导入必要的包，如下所示：

```scala
import org.apache.spark.sql.expressions.Window
import org.apache.spark.sql.functions.col import org.apache.spark.sql.functions.max

```

现在，您已经准备好编写一些代码来了解窗口函数。让我们为按`Population`排序并按`State`分区的分区创建一个窗口规范。还要指定我们希望将当前行之前的所有行视为`Window`的一部分。

```scala
 val windowSpec = Window
 .partitionBy("State")
 .orderBy(col("Population").desc)
 .rowsBetween(Window.unboundedPreceding, Window.currentRow)

```

计算窗口规范上的`rank`。结果将是一个排名（行号）添加到每一行，只要它在指定的`Window`内。在这个例子中，我们选择按`State`进行分区，然后进一步按降序对每个`State`的行进行排序。因此，所有州的行都有自己的排名号码分配。

```scala
import org.apache.spark.sql.functions._
scala> statesPopulationDF.select(col("State"), col("Year"), max("Population").over(windowSpec), rank().over(windowSpec)).sort("State", "Year").show(10)
+-------+----+------------------------------------------------------------------------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------+
| State|Year|max(Population) OVER (PARTITION BY State ORDER BY Population DESC NULLS LAST ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW)|RANK() OVER (PARTITION BY State ORDER BY Population DESC NULLS LAST ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW)|
+-------+----+------------------------------------------------------------------------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------+
|Alabama|2010| 4863300| 6|
|Alabama|2011| 4863300| 7|
|Alabama|2012| 4863300| 5|
|Alabama|2013| 4863300| 4|
|Alabama|2014| 4863300| 3|

```

# ntiles

ntiles 是窗口上的一种常见聚合，通常用于将输入数据集分成 n 部分。例如，在预测分析中，通常使用十分位数（10 部分）首先对数据进行分组，然后将其分成 10 部分以获得数据的公平分布。这是窗口函数方法的自然功能，因此 ntiles 是窗口函数如何帮助的一个很好的例子。

例如，如果我们想要按`statesPopulationDF`按`State`进行分区（窗口规范如前所示），按人口排序，然后分成两部分，我们可以在`windowspec`上使用`ntile`：

```scala
import org.apache.spark.sql.functions._
scala> statesPopulationDF.select(col("State"), col("Year"), ntile(2).over(windowSpec), rank().over(windowSpec)).sort("State", "Year").show(10)
+-------+----+-----------------------------------------------------------------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------+
| State|Year|ntile(2) OVER (PARTITION BY State ORDER BY Population DESC NULLS LAST ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW)|RANK() OVER (PARTITION BY State ORDER BY Population DESC NULLS LAST ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW)|
+-------+----+-----------------------------------------------------------------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------+
|Alabama|2010| 2| 6|
|Alabama|2011| 2| 7|
|Alabama|2012| 2| 5|
|Alabama|2013| 1| 4|
|Alabama|2014| 1| 3|
|Alabama|2015| 1| 2|
|Alabama|2016| 1| 1|
| Alaska|2010| 2| 7|
| Alaska|2011| 2| 6|
| Alaska|2012| 2| 5|
+-------+----+-----------------------------------------------------------------------------------------------------------------------+------------------------------------------------------------------------------

```

如前所示，我们已经使用`Window`函数和`ntile()`一起将每个`State`的行分成两个相等的部分。

这个函数的一个常见用途是计算数据科学模型中使用的十分位数。

# 连接

在传统数据库中，连接用于将一个交易表与另一个查找表连接，以生成更完整的视图。例如，如果您有一个按客户 ID 分类的在线交易表，另一个包含客户城市和客户 ID 的表，您可以使用连接来生成有关按城市分类的交易的报告。

**交易表**：以下表有三列，**CustomerID**，**购买的物品**，以及客户为该物品支付了多少钱：

| **CustomerID** | **购买的物品** | **支付的价格** |
| --- | --- | --- |
| 1 | Headphone | 25.00 |
| 2 | 手表 | 100.00 |
| 3 | 键盘 | 20.00 |
| 1 | 鼠标 | 10.00 |
| 4 | 电缆 | 10.00 |
| 3 | Headphone | 30.00 |

**客户信息表**：以下表有两列，**CustomerID**和客户居住的**City**：

| **CustomerID** | **City** |
| --- | --- |
| 1 | 波士顿 |
| 2 | 纽约 |
| 3 | 费城 |
| 4 | 波士顿 |

将交易表与客户信息表连接将生成以下视图：

| **CustomerID** | **购买的物品** | **支付的价格** | **城市** |
| --- | --- | --- | --- |
| 1 | Headphone | 25.00 | 波士顿 |
| 2 | 手表 | 100.00 | 纽约 |
| 3 | 键盘 | 20.00 | 费城 |
| 1 | 鼠标 | 10.00 | 波士顿 |
| 4 | 电缆 | 10.00 | 波士顿 |
| 3 | Headphone | 30.00 | Philadelphia |

现在，我们可以使用这个连接的视图来生成**按城市**的**总销售价格**的报告：

| **城市** | **#物品** | **总销售价格** |
| --- | --- | --- |
| 波士顿 | 3 | 45.00 |
| Philadelphia | 2 | 50.00 |
| New York | 1 | 100.00 |

连接是 Spark SQL 的重要功能，因为它使您能够将两个数据集合并在一起，正如之前所见。当然，Spark 不仅仅是用来生成报告的，而是用来处理 PB 级别的数据，处理实时流处理用例，机器学习算法或纯粹的分析。为了实现这些目标，Spark 提供了所需的 API 函数。

两个数据集之间的典型连接是使用左侧和右侧数据集的一个或多个键进行的，然后对键集合上的条件表达式进行布尔表达式的评估。如果布尔表达式的结果为 true，则连接成功，否则连接的 DataFrame 将不包含相应的连接。

连接 API 有 6 种不同的实现：

```scala
join(right: dataset[_]): DataFrame
Condition-less inner join

join(right: dataset[_], usingColumn: String): DataFrame
Inner join with a single column

join(right: dataset[_], usingColumns: Seq[String]): DataFrame 
Inner join with multiple columns

join(right: dataset[_], usingColumns: Seq[String], joinType: String): DataFrame
Join with multiple columns and a join type (inner, outer,....)

join(right: dataset[_], joinExprs: Column): DataFrame
Inner Join using a join expression

join(right: dataset[_], joinExprs: Column, joinType: String): DataFrame 
Join using a Join expression and a join type (inner, outer, ...)

```

我们将使用其中一个 API 来了解如何使用连接 API；然而，您可以根据用例选择使用其他 API：

```scala
def   join(right: dataset[_], joinExprs: Column, joinType: String): DataFrame Join with another DataFrame using the given join expression

right: Right side of the join.
joinExprs: Join expression.
joinType : Type of join to perform. Default is *inner* join

// Scala:
import org.apache.spark.sql.functions._
import spark.implicits._
df1.join(df2, $"df1Key" === $"df2Key", "outer") 

```

请注意，连接将在接下来的几个部分中详细介绍。

# 连接的内部工作方式

连接通过使用多个执行器对 DataFrame 的分区进行操作。然而，实际操作和随后的性能取决于`join`的类型和被连接的数据集的性质。在下一节中，我们将看看连接的类型。

# Shuffle 连接

两个大数据集之间的连接涉及到分区连接，其中左侧和右侧数据集的分区被分布到执行器上。Shuffles 是昂贵的，重要的是要分析逻辑，以确保分区和 Shuffles 的分布是最优的。以下是内部展示 Shuffle 连接的示例：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00166.jpeg)

# 广播连接

通过将较小的数据集广播到所有执行器，可以对一个大数据集和一个小数据集进行连接，其中左侧数据集的分区存在。以下是广播连接内部工作的示例：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00194.jpeg)

# 连接类型

以下是不同类型连接的表格。这很重要，因为在连接两个数据集时所做的选择在输出和性能上都有很大的区别。

| **Join type** | **Description** |
| --- | --- |
| **inner** | 内连接将*left*中的每一行与*right*中的行进行比较，并仅在两者都具有非 NULL 值时才组合匹配的*left*和*right*数据集的行。 |
| **cross** | cross join 将*left*中的每一行与*right*中的每一行匹配，生成笛卡尔积。 |
| **outer, full, fullouter** | full outer Join 给出*left*和*right*中的所有行，如果只在*right*或*left*中，则填充 NULL。 |
| **leftanti** | leftanti Join 仅基于*right*一侧的不存在给出*left*中的行。 |
| **left, leftouter** | leftouter Join 给出*left*中的所有行以及*left*和*right*的公共行（内连接）。如果*right*中没有，则填充 NULL。 |
| **leftsemi** | leftsemi Join 仅基于*right*一侧的存在给出*left*中的行。不包括*right*一侧的值。 |
| **right, rightouter** | rightouter Join 给出*right*中的所有行以及*left*和*right*的公共行（内连接）。如果*left*中没有，则填充 NULL。 |

我们将使用示例数据集来研究不同连接类型的工作方式。

```scala
scala> val statesPopulationDF = spark.read.option("header", "true").option("inferschema", "true").option("sep", ",").csv("statesPopulation.csv")
statesPopulationDF: org.apache.spark.sql.DataFrame = [State: string, Year: int ... 1 more field]

scala> val statesTaxRatesDF = spark.read.option("header", "true").option("inferschema", "true").option("sep", ",").csv("statesTaxRates.csv")
statesTaxRatesDF: org.apache.spark.sql.DataFrame = [State: string, TaxRate: double]

scala> statesPopulationDF.count
res21: Long = 357

scala> statesTaxRatesDF.count
res32: Long = 47

%sql
statesPopulationDF.createOrReplaceTempView("statesPopulationDF")
statesTaxRatesDF.createOrReplaceTempView("statesTaxRatesDF")

```

# 内连接

当州在两个数据集中都不为 NULL 时，内连接会给出`statesPopulationDF`和`statesTaxRatesDF`的行。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00095.jpeg)

通过州列连接两个数据集如下：

```scala
val joinDF = statesPopulationDF.join(statesTaxRatesDF, statesPopulationDF("State") === statesTaxRatesDF("State"), "inner")

%sql
val joinDF = spark.sql("SELECT * FROM statesPopulationDF INNER JOIN statesTaxRatesDF ON statesPopulationDF.State = statesTaxRatesDF.State")

scala> joinDF.count
res22: Long = 329

scala> joinDF.show
+--------------------+----+----------+--------------------+-------+
| State|Year|Population| State|TaxRate|
+--------------------+----+----------+--------------------+-------+
| Alabama|2010| 4785492| Alabama| 4.0|
| Arizona|2010| 6408312| Arizona| 5.6|
| Arkansas|2010| 2921995| Arkansas| 6.5|
| California|2010| 37332685| California| 7.5|
| Colorado|2010| 5048644| Colorado| 2.9|
| Connecticut|2010| 3579899| Connecticut| 6.35|

```

您可以在`joinDF`上运行`explain()`来查看执行计划：

```scala
scala> joinDF.explain
== Physical Plan ==
*BroadcastHashJoin [State#570], [State#577], Inner, BuildRight
:- *Project [State#570, Year#571, Population#572]
: +- *Filter isnotnull(State#570)
: +- *FileScan csv [State#570,Year#571,Population#572] Batched: false, Format: CSV, Location: InMemoryFileIndex[file:/Users/salla/spark-2.1.0-bin-hadoop2.7/statesPopulation.csv], PartitionFilters: [], PushedFilters: [IsNotNull(State)], ReadSchema: struct<State:string,Year:int,Population:int>
+- BroadcastExchange HashedRelationBroadcastMode(List(input[0, string, true]))
 +- *Project [State#577, TaxRate#578]
 +- *Filter isnotnull(State#577)
 +- *FileScan csv [State#577,TaxRate#578] Batched: false, Format: CSV, Location: InMemoryFileIndex[file:/Users/salla/spark-2.1.0-bin-hadoop2.7/statesTaxRates.csv], PartitionFilters: [], PushedFilters: [IsNotNull(State)], ReadSchema: struct<State:string,TaxRate:double>

```

# Left outer join

Left outer join 结果包括`statesPopulationDF`中的所有行，包括`statesPopulationDF`和`statesTaxRatesDF`中的任何公共行。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00273.jpeg)

通过州列连接两个数据集，如下所示：

```scala
val joinDF = statesPopulationDF.join(statesTaxRatesDF, statesPopulationDF("State") === statesTaxRatesDF("State"), "leftouter")

%sql
val joinDF = spark.sql("SELECT * FROM statesPopulationDF LEFT OUTER JOIN statesTaxRatesDF ON statesPopulationDF.State = statesTaxRatesDF.State")

scala> joinDF.count
res22: Long = 357

scala> joinDF.show(5)
+----------+----+----------+----------+-------+
| State|Year|Population| State|TaxRate|
+----------+----+----------+----------+-------+
| Alabama|2010| 4785492| Alabama| 4.0|
| Alaska|2010| 714031| null| null|
| Arizona|2010| 6408312| Arizona| 5.6|
| Arkansas|2010| 2921995| Arkansas| 6.5|
|California|2010| 37332685|California| 7.5|
+----------+----+----------+----------+-------+

```

# Right outer join

Right outer join 结果包括`statesTaxRatesDF`中的所有行，包括`statesPopulationDF`和`statesTaxRatesDF`中的任何公共行。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00319.jpeg)

按照`State`列连接两个数据集如下：

```scala
val joinDF = statesPopulationDF.join(statesTaxRatesDF, statesPopulationDF("State") === statesTaxRatesDF("State"), "rightouter")

%sql
val joinDF = spark.sql("SELECT * FROM statesPopulationDF RIGHT OUTER JOIN statesTaxRatesDF ON statesPopulationDF.State = statesTaxRatesDF.State")

scala> joinDF.count
res22: Long = 323

scala> joinDF.show
+--------------------+----+----------+--------------------+-------+
| State|Year|Population| State|TaxRate|
+--------------------+----+----------+--------------------+-------+
| Colorado|2011| 5118360| Colorado| 2.9|
| Colorado|2010| 5048644| Colorado| 2.9|
| null|null| null|Connecticut| 6.35|
| Florida|2016| 20612439| Florida| 6.0|
| Florida|2015| 20244914| Florida| 6.0|
| Florida|2014| 19888741| Florida| 6.0|

```

# 外连接

外连接结果包括`statesPopulationDF`和`statesTaxRatesDF`中的所有行。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00245.jpeg)

按照`State`列连接两个数据集如下：

```scala
val joinDF = statesPopulationDF.join(statesTaxRatesDF, statesPopulationDF("State") === statesTaxRatesDF("State"), "fullouter")

%sql
val joinDF = spark.sql("SELECT * FROM statesPopulationDF FULL OUTER JOIN statesTaxRatesDF ON statesPopulationDF.State = statesTaxRatesDF.State")

scala> joinDF.count
res22: Long = 351

scala> joinDF.show
+--------------------+----+----------+--------------------+-------+
| State|Year|Population| State|TaxRate|
+--------------------+----+----------+--------------------+-------+
| Delaware|2010| 899816| null| null|
| Delaware|2011| 907924| null| null|
| West Virginia|2010| 1854230| West Virginia| 6.0|
| West Virginia|2011| 1854972| West Virginia| 6.0|
| Missouri|2010| 5996118| Missouri| 4.225|
| null|null| null|  Connecticut|   6.35|

```

# 左反连接

左反连接的结果只包括`statesPopulationDF`中的行，如果且仅如果在`statesTaxRatesDF`中没有相应的行。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00072.jpeg)

按照以下方式通过`State`列连接两个数据集：

```scala
val joinDF = statesPopulationDF.join(statesTaxRatesDF, statesPopulationDF("State") === statesTaxRatesDF("State"), "leftanti")

%sql
val joinDF = spark.sql("SELECT * FROM statesPopulationDF LEFT ANTI JOIN statesTaxRatesDF ON statesPopulationDF.State = statesTaxRatesDF.State")

scala> joinDF.count
res22: Long = 28

scala> joinDF.show(5)
+--------+----+----------+
| State|Year|Population|
+--------+----+----------+
| Alaska|2010| 714031|
|Delaware|2010| 899816|
| Montana|2010| 990641|
| Oregon|2010| 3838048|
| Alaska|2011| 722713|
+--------+----+----------+

```

# 左半连接

左半连接的结果只包括`statesPopulationDF`中的行，如果且仅如果在`statesTaxRatesDF`中有相应的行。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00097.jpeg)

按照州列连接两个数据集如下：

```scala
val joinDF = statesPopulationDF.join(statesTaxRatesDF, statesPopulationDF("State") === statesTaxRatesDF("State"), "leftsemi")

%sql
val joinDF = spark.sql("SELECT * FROM statesPopulationDF LEFT SEMI JOIN statesTaxRatesDF ON statesPopulationDF.State = statesTaxRatesDF.State")

scala> joinDF.count
res22: Long = 322

scala> joinDF.show(5)
+----------+----+----------+
| State|Year|Population|
+----------+----+----------+
| Alabama|2010| 4785492|
| Arizona|2010| 6408312|
| Arkansas|2010| 2921995|
|California|2010| 37332685|
| Colorado|2010| 5048644|
+----------+----+----------+

```

# 交叉连接

交叉连接将*left*中的每一行与*right*中的每一行进行匹配，生成笛卡尔乘积。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00312.jpeg)

按照以下方式通过`State`列连接两个数据集：

```scala
scala> val joinDF=statesPopulationDF.crossJoin(statesTaxRatesDF)
joinDF: org.apache.spark.sql.DataFrame = [State: string, Year: int ... 3 more fields]

%sql
val joinDF = spark.sql("SELECT * FROM statesPopulationDF CROSS JOIN statesTaxRatesDF")

scala> joinDF.count
res46: Long = 16450

scala> joinDF.show(10)
+-------+----+----------+-----------+-------+
| State|Year|Population| State|TaxRate|
+-------+----+----------+-----------+-------+
|Alabama|2010| 4785492| Alabama| 4.0|
|Alabama|2010| 4785492| Arizona| 5.6|
|Alabama|2010| 4785492| Arkansas| 6.5|
|Alabama|2010| 4785492| California| 7.5|
|Alabama|2010| 4785492| Colorado| 2.9|
|Alabama|2010| 4785492|Connecticut| 6.35|
|Alabama|2010| 4785492| Florida| 6.0|
|Alabama|2010| 4785492| Georgia| 4.0|
|Alabama|2010| 4785492| Hawaii| 4.0|
|Alabama|2010| 4785492| Idaho| 6.0|
+-------+----+----------+-----------+-------+

```

您还可以使用交叉连接类型的连接，而不是调用交叉连接 API。`statesPopulationDF.join(statesTaxRatesDF, statesPopulationDF("State").isNotNull, "cross").count`。

# 连接的性能影响

选择的连接类型直接影响连接的性能。这是因为连接需要在执行任务之间对数据进行洗牌，因此在使用连接时需要考虑不同的连接，甚至连接的顺序。

以下是编写`Join`代码时可以参考的表：

| **连接类型** | **性能考虑和提示** |
| --- | --- |
| **inner** | 内连接要求左表和右表具有相同的列。如果左侧或右侧的键有重复或多个副本，连接将迅速膨胀成一种笛卡尔连接，完成时间比设计正确以最小化多个键的连接要长得多。 |
| **cross** | Cross Join 将*left*中的每一行与*right*中的每一行进行匹配，生成笛卡尔乘积。这需要谨慎使用，因为这是性能最差的连接，只能在特定用例中使用。 |
| **outer, full, fullouter** | Fullouter Join 给出*left*和*right*中的所有行，如果只在*right*或*left*中，则填充 NULL。如果在共同点很少的表上使用，可能导致非常大的结果，从而降低性能。 |
| **leftanti** | Leftanti Join 仅基于*right*一侧的不存在给出*left*中的行。性能非常好，因为只考虑一个表，另一个表只需检查连接条件。 |
| **left, leftouter** | Leftouter Join 给出*left*中的所有行以及*left*和*right*中的共同行（内连接）。如果*right*中没有，则填充 NULL。如果在共同点很少的表上使用，可能导致非常大的结果，从而降低性能。 |
| **leftsemi** | Leftsemi Join 仅基于*right*一侧的存在给出*left*中的行。不包括*right*一侧的值。性能非常好，因为只考虑一个表，另一个表只需检查连接条件。 |
| **right, rightouter** | Rightouter Join 给出*right*中的所有行以及*left*和*right*中的共同行（内连接）。如果*left*中没有，则填充 NULL。性能与上表中先前提到的 leftouter join 类似。 |

# 总结

在本章中，我们讨论了 DataFrame 的起源以及 Spark SQL 如何在 DataFrame 之上提供 SQL 接口。DataFrame 的强大之处在于，执行时间比原始基于 RDD 的计算减少了很多倍。拥有这样一个强大的层和一个简单的类似 SQL 的接口使它们变得更加强大。我们还研究了各种 API 来创建和操作 DataFrame，并深入挖掘了聚合的复杂特性，包括`groupBy`、`Window`、`rollup`和`cubes`。最后，我们还研究了连接数据集的概念以及可能的各种连接类型，如内连接、外连接、交叉连接等。

在下一章中，我们将探索实时数据处理和分析的激动人心的世界，即第九章，*Stream Me Up, Scotty - Spark Streaming*。


# 第九章：Stream Me Up, Scotty - Spark Streaming

“我真的很喜欢流媒体服务。这是人们发现你的音乐的好方法。”

- Kygo

在本章中，我们将学习 Spark Streaming，并了解如何利用它来使用 Spark API 处理数据流。此外，在本章中，我们将通过一个实际的例子学习处理实时数据流的各种方法，以消费和处理来自 Twitter 的推文。简而言之，本章将涵盖以下主题：

+   流媒体的简要介绍

+   Spark Streaming

+   离散流

+   有状态/无状态转换

+   检查点

+   与流媒体平台的互操作性（Apache Kafka）

+   结构化流

# 流媒体的简要介绍

在当今互联设备和服务的世界中，很难一天中甚至只有几个小时不使用我们的智能手机来检查 Facebook，或者预订 Uber 出行，或者发推文关于你刚买的汉堡，或者查看你最喜欢的球队的最新新闻或体育更新。我们依赖手机和互联网，无论是完成工作，浏览，还是给朋友发电子邮件，都需要它们。这种现象是无法避免的，应用程序和服务的数量和种类只会随着时间的推移而增长。

因此，智能设备随处可见，它们一直在产生大量数据。这种现象，也广泛称为物联网，已经永久改变了数据处理的动态。每当你在 iPhone、Droid 或 Windows 手机上使用任何服务或应用时，实时数据处理都在发挥作用。由于很多东西都取决于应用的质量和价值，各种初创公司和成熟公司如何应对**SLA**（**服务级别协议**）的复杂挑战，以及数据的有用性和及时性都受到了很多关注。

组织和服务提供商正在研究和采用的范式之一是在非常尖端的平台或基础设施上构建非常可扩展的、接近实时或实时的处理框架。一切都必须快速，并且对变化和故障也要有反应。如果你的 Facebook 每小时只更新一次，或者你一天只收到一次电子邮件，你肯定不会喜欢；因此，数据流、处理和使用都尽可能接近实时是至关重要的。我们感兴趣监控或实施的许多系统产生了大量数据，作为一个无限持续的事件流。

与任何其他数据处理系统一样，我们面临着数据的收集、存储和处理的基本挑战。然而，额外的复杂性是由于平台的实时需求。为了收集这种无限的事件流，并随后处理所有这些事件以生成可操作的见解，我们需要使用高度可扩展的专门架构来处理巨大的事件速率。因此，多年来已经建立了许多系统，从 AMQ、RabbitMQ、Storm、Kafka、Spark、Flink、Gearpump、Apex 等等。

为了处理如此大量的流数据，现代系统采用了非常灵活和可扩展的技术，这些技术不仅非常高效，而且比以前更好地实现了业务目标。使用这些技术，可以从各种数据源中获取数据，然后几乎立即或在需要时在各种用例中使用它。

让我们来谈谈当你拿出手机预订 Uber 去机场的时候会发生什么。通过几次触摸屏幕，你可以选择一个地点，选择信用卡，付款，预订车辆。一旦交易完成，你就可以实时在手机地图上监控车辆的进度。当车辆向你靠近时，你可以准确地知道车辆的位置，也可以决定在等车的时候去当地的星巴克买咖啡。

你还可以通过查看车辆的预计到达时间来对车辆和随后的机场行程做出明智的决定。如果看起来车辆要花很长时间来接你，而且这可能对你即将要赶的航班构成风险，你可以取消预订并搭乘附近的出租车。另外，如果交通状况不允许你按时到达机场，从而对你即将要赶的航班构成风险，你也可以决定重新安排或取消你的航班。

现在，为了理解这样的实时流架构是如何提供如此宝贵的信息的，我们需要了解流架构的基本原则。一方面，实时流架构能够以非常高的速率消耗极大量的数据，另一方面，还要确保数据被摄入后也得到合理的处理。

下图显示了一个带有生产者将事件放入消息系统的通用流处理系统，而消费者正在从消息系统中读取事件：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00125.jpeg)

实时流数据的处理可以分为以下三种基本范式：

+   至少一次处理

+   至多一次处理

+   精确一次处理

让我们看看这三种流处理范式对我们的业务用例意味着什么。

虽然对于我们来说，实时事件的精确一次处理是最终的理想境界，但在不同的场景中总是实现这一目标非常困难。在那些保证的好处被实现的复杂性所压倒的情况下，我们不得不在精确一次处理的属性上做出妥协。

# 至少一次处理

至少一次处理范式涉及一种机制，即**只有在**事件实际处理并且结果被持久化之后才保存最后接收到的事件的位置，以便在发生故障并且消费者重新启动时，消费者将再次读取旧事件并处理它们。然而，由于无法保证接收到的事件根本没有被处理或部分处理，这会导致事件的潜在重复，因此事件至少被处理一次。

至少一次处理理想地适用于任何涉及更新瞬时标记或表盘以显示当前值的应用程序。任何累积总和、计数器或依赖于聚合的准确性（`sum`、`groupBy`等）都不适用于这种处理的用例，因为重复的事件会导致不正确的结果。

消费者的操作顺序如下：

1.  保存结果

1.  保存偏移量

下面是一个示例，说明了如果出现故障并且**消费者**重新启动会发生什么。由于事件已经被处理，但偏移量没有保存，消费者将从之前保存的偏移量读取，从而导致重复。在下图中，事件 0 被处理了两次：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00277.jpeg)

# 至多一次处理

至多一次处理范式涉及一种机制，在事件实际被处理并结果被持久化到某个地方之前，保存最后接收到的事件的位置，以便在发生故障并且消费者重新启动时，消费者不会尝试再次读取旧事件。然而，由于无法保证接收到的事件是否全部被处理，这可能导致事件的潜在丢失，因为它们永远不会再次被获取。这导致事件最多被处理一次或根本不被处理。

至多一次理想适用于任何需要更新一些即时标记或计量器以显示当前值的应用程序，以及任何累积总和、计数器或其他聚合，只要准确性不是必需的或应用程序绝对需要所有事件。任何丢失的事件都将导致不正确的结果或缺失的结果。

消费者的操作顺序如下：

1.  保存偏移量

1.  保存结果

以下是如果发生故障并且**消费者**重新启动时会发生的情况的示例。由于事件尚未被处理但偏移量已保存，消费者将从保存的偏移量读取，导致事件被消费时出现间隙。在以下图中，事件 0 从未被处理：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00340.jpeg)

# 一次性处理

一次性处理范式类似于至少一次处理范式，并涉及一种机制，只有在事件实际被处理并且结果被持久化到某个地方后，才保存最后接收到的事件的位置，以便在发生故障并且消费者重新启动时，消费者将再次读取旧事件并处理它们。然而，由于无法保证接收到的事件是否根本未被处理或部分处理，这可能导致事件的潜在重复，因为它们会再次被获取。然而，与至少一次处理范式不同，重复的事件不会被处理，而是被丢弃，从而导致一次性处理范式。

一次性处理范式适用于任何需要准确计数器、聚合或一般需要每个事件仅被处理一次且绝对一次（无损失）的应用程序。

消费者的操作顺序如下：

1.  保存结果

1.  保存偏移量

以下是示例显示了如果发生故障并且**消费者**重新启动时会发生的情况。由于事件已经被处理但偏移量尚未保存，消费者将从先前保存的偏移量读取，从而导致重复。在以下图中，事件 0 仅被处理一次，因为**消费者**丢弃了重复的事件 0：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00105.jpeg)

一次性范式如何丢弃重复项？这里有两种技术可以帮助：

1.  幂等更新

1.  事务更新

Spark Streaming 还在 Spark 2.0+中实现了结构化流处理，支持一次性处理。我们将在本章后面讨论结构化流处理。

幂等更新涉及基于生成的某个唯一 ID/键保存结果，以便如果有重复，生成的唯一 ID/键已经存在于结果中（例如，数据库），因此消费者可以丢弃重复项而不更新结果。这很复杂，因为并非总是可能或容易生成唯一键。它还需要在消费者端进行额外的处理。另一点是，数据库可以分开用于结果和偏移量。

事务更新以批量方式保存结果，其中包括事务开始和事务提交阶段，因此在提交发生时，我们知道事件已成功处理。因此，当接收到重复事件时，可以在不更新结果的情况下丢弃它们。这种技术比幂等更新复杂得多，因为现在我们需要一些事务性数据存储。另一点是，数据库必须用于结果和偏移量。

您应该研究您正在构建的用例，并查看至少一次处理或最多一次处理是否可以合理地广泛应用，并且仍然可以实现可接受的性能和准确性。

在接下来的章节中，我们将仔细研究 Spark Streaming 的范例，以及如何使用 Spark Streaming 并从 Apache Kafka 中消费事件。

# Spark Streaming

Spark Streaming 并不是第一个出现的流处理架构。 随着时间的推移，出现了几种技术来处理各种业务用例的实时处理需求。 Twitter Storm 是最早流行的流处理技术之一，并被许多组织使用，满足了许多企业的需求。

Apache Spark 配备了一个流处理库，它迅速发展成为最广泛使用的技术。 Spark Streaming 相对于其他技术具有一些明显的优势，首先是 Spark Streaming API 与 Spark 核心 API 之间的紧密集成，使得构建双重用途的实时和批量分析平台比以往更可行和高效。 Spark Streaming 还与 Spark ML 和 Spark SQL 以及 GraphX 集成，使其成为可以满足许多独特和复杂用例的最强大的流处理技术。 在本节中，我们将更深入地了解 Spark Streaming 的全部内容。

有关 Spark Streaming 的更多信息，您可以参考[`spark.apache.org/docs/2.1.0/streaming-programming-guide.html`](https://spark.apache.org/docs/2.1.0/streaming-programming-guide.html)。

Spark Streaming 支持多种输入源，并可以将结果写入多个接收器。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00004.jpeg)

虽然 Flink、Heron（Twitter Storm 的继任者）、Samza 等都可以在收集事件时以最小的延迟处理事件，但 Spark Streaming 会消耗连续的数据流，然后以微批次的形式处理收集到的数据。 微批次的大小可以低至 500 毫秒，但通常不会低于这个值。

Apache Apex、Gear pump、Flink、Samza、Heron 或其他即将推出的技术在某些用例中与 Spark Streaming 竞争。 如果您需要真正的事件处理，那么 Spark Streaming 不适合您的用例。

流媒体的工作方式是根据配置定期创建事件批次，并在每个指定的时间间隔交付数据的微批次以进行进一步处理。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00011.jpeg)

就像`SparkContext`一样，Spark Streaming 也有一个`StreamingContext`，它是流作业/应用程序的主要入口点。 `StreamingContext`依赖于`SparkContext`。 实际上，`SparkContext`可以直接在流作业中使用。 `StreamingContext`类似于`SparkContext`，只是`StreamingContext`还需要程序指定批处理间隔的时间间隔或持续时间，可以是毫秒或分钟。

请记住，`SparkContext`是入口点，任务调度和资源管理是`SparkContext`的一部分，因此`StreamingContext`重用了这一逻辑。

# StreamingContext

`StreamingContext`是流处理的主要入口点，基本上负责流处理应用程序，包括 DStreams 的检查点、转换和操作。

# 创建 StreamingContext

可以通过两种方式创建新的 StreamingContext：

1.  使用现有的`SparkContext`创建`StreamingContext`如下：

```scala
 StreamingContext(sparkContext: SparkContext, batchDuration: Duration) scala> val ssc = new StreamingContext(sc, Seconds(10))

```

1.  通过提供新的`SparkContext`所需的配置来创建`StreamingContext`如下：

```scala
 StreamingContext(conf: SparkConf, batchDuration: Duration) scala> val conf = new SparkConf().setMaster("local[1]")
                                       .setAppName("TextStreams")
      scala> val ssc = new StreamingContext(conf, Seconds(10))

```

1.  第三种方法是使用`getOrCreate()`，它用于从检查点数据重新创建`StreamingContext`，或创建一个新的`StreamingContext`。如果检查点数据存在于提供的`checkpointPath`中，则将从检查点数据重新创建`StreamingContext`。如果数据不存在，则将通过调用提供的`creatingFunc`创建`StreamingContext`：

```scala
        def getOrCreate(
          checkpointPath: String,
          creatingFunc: () => StreamingContext,
          hadoopConf: Configuration = SparkHadoopUtil.get.conf,
          createOnError: Boolean = false
        ): StreamingContext

```

# 开始 StreamingContext

`start()`方法启动使用`StreamingContext`定义的流的执行。这实质上启动了整个流应用程序：

```scala
def start(): Unit 

scala> ssc.start()

```

# 停止 StreamingContext

停止`StreamingContext`将停止所有处理，您将需要重新创建一个新的`StreamingContext`并在其上调用`start()`来重新启动应用程序。有两个有用的 API 用于停止流处理应用程序。

立即停止流的执行（不等待所有接收到的数据被处理）：

```scala
def stop(stopSparkContext: Boolean) scala> ssc.stop(false)

```

停止流的执行，并确保所有接收到的数据都已被处理：

```scala
def stop(stopSparkContext: Boolean, stopGracefully: Boolean) scala> ssc.stop(true, true)

```

# 输入流

有几种类型的输入流，如`receiverStream`和`fileStream`，可以使用`StreamingContext`创建，如下面的子节所示：

# receiverStream

使用任意用户实现的接收器创建一个输入流。它可以定制以满足用例。

在[`spark.apache.org/docs/latest/streaming-custom-receivers.html`](http://spark.apache.org/docs/latest/streaming-custom-receivers.html)找到更多细节。

以下是`receiverStream`的 API 声明：

```scala
 def receiverStreamT: ClassTag: ReceiverInputDStream[T]

```

# socketTextStream

这将从 TCP 源`hostname:port`创建一个输入流。使用 TCP 套接字接收数据，并将接收到的字节解释为 UTF8 编码的`\n`分隔行：

```scala
def socketTextStream(hostname: String, port: Int,
 storageLevel: StorageLevel = StorageLevel.MEMORY_AND_DISK_SER_2):
    ReceiverInputDStream[String]

```

# rawSocketStream

从网络源`hostname:port`创建一个输入流，其中数据作为序列化块（使用 Spark 的序列化器进行序列化）接收，可以直接推送到块管理器而无需对其进行反序列化。这是最有效的

接收数据的方法。

```scala
def rawSocketStreamT: ClassTag:
    ReceiverInputDStream[T]

```

# fileStream

创建一个输入流，监视 Hadoop 兼容文件系统以获取新文件，并使用给定的键值类型和输入格式进行读取。文件必须通过将它们从同一文件系统中的另一个位置移动到监视目录中来写入。以点（`.`）开头的文件名将被忽略，因此这是在监视目录中移动文件名的明显选择。使用原子文件重命名函数调用，以`.`开头的文件名现在可以重命名为实际可用的文件名，以便`fileStream`可以捡起它并让我们处理文件内容：

```scala
def fileStream[K: ClassTag, V: ClassTag, F <: NewInputFormat[K, V]: ClassTag] (directory: String): InputDStream[(K, V)]

```

# textFileStream

创建一个输入流，监视 Hadoop 兼容文件系统以获取新文件，并将它们作为文本文件读取（使用`LongWritable`作为键，Text 作为值，`TextInputFormat`作为输入格式）。文件必须通过将它们从同一文件系统中的另一个位置移动到监视目录中来写入。以`.`开头的文件名将被忽略：

```scala
def textFileStream(directory: String): DStream[String]

```

# binaryRecordsStream

创建一个输入流，监视 Hadoop 兼容文件系统以获取新文件，并将它们作为固定长度的二进制文件读取，生成每个记录的一个字节数组。文件必须通过将它们从同一文件系统中的另一个位置移动到监视目录中来写入。以`.`开头的文件名将被忽略：

```scala
def binaryRecordsStream(directory: String, recordLength: Int): DStream[Array[Byte]]

```

# queueStream

从 RDD 队列创建一个输入流。在每个批处理中，它将处理队列返回的一个或所有 RDD：

```scala
def queueStreamT: ClassTag: InputDStream[T]

```

# textFileStream 示例

以下是使用`textFileStream`的 Spark Streaming 的简单示例。在这个例子中，我们从 spark-shell 的`SparkContext`（`sc`）和一个间隔为 10 秒的时间间隔创建了一个`StreamingContext`。这将启动`textFileStream`，监视名为**streamfiles**的目录，并处理在目录中找到的任何新文件。在这个例子中，我们只是打印 RDD 中的元素数量：

```scala
scala> import org.apache.spark._
scala> import org.apache.spark.streaming._

scala> val ssc = new StreamingContext(sc, Seconds(10))

scala> val filestream = ssc.textFileStream("streamfiles")

scala> filestream.foreachRDD(rdd => {println(rdd.count())})

scala> ssc.start

```

# twitterStream 示例

让我们看另一个示例，说明我们如何使用 Spark Streaming 处理来自 Twitter 的推文：

1.  首先，打开一个终端并将目录更改为`spark-2.1.1-bin-hadoop2.7`。

1.  在您安装了 spark 的`spark-2.1.1-bin-hadoop2.7`文件夹下创建一个`streamouts`文件夹。当应用程序运行时，`streamouts`文件夹将收集推文到文本文件中。

1.  将以下 jar 文件下载到目录中：

+   [`central.maven.org/maven2/org/apache/bahir/spark-streaming-twitter_2.11/2.1.0/spark-streaming-twitter_2.11-2.1.0.jar`](http://central.maven.org/maven2/org/apache/bahir/spark-streaming-twitter_2.11/2.1.0/spark-streaming-twitter_2.11-2.1.0.jar)

+   [`central.maven.org/maven2/org/twitter4j/twitter4j-core/4.0.6/twitter4j-core-4.0.6.jar`](http://central.maven.org/maven2/org/twitter4j/twitter4j-core/4.0.6/twitter4j-core-4.0.6.jar)

+   [`central.maven.org/maven2/org/twitter4j/twitter4j-stream/4.0.6/twitter4j-stream-4.0.6.jar`](http://central.maven.org/maven2/org/twitter4j/twitter4j-stream/4.0.6/twitter4j-stream-4.0.6.jar)

1.  使用指定的 Twitter 集成所需的 jar 启动 spark-shell：

```scala
 ./bin/spark-shell --jars twitter4j-stream-4.0.6.jar,
                               twitter4j-core-4.0.6.jar,
                               spark-streaming-twitter_2.11-2.1.0.jar

```

1.  现在，我们可以编写一个示例代码。以下是用于测试 Twitter 事件处理的代码：

```scala
        import org.apache.spark._
        import org.apache.spark.streaming._
        import org.apache.spark.streaming.Twitter._
        import twitter4j.auth.OAuthAuthorization
        import twitter4j.conf.ConfigurationBuilder

        //you can replace the next 4 settings with your own Twitter
              account settings.
        System.setProperty("twitter4j.oauth.consumerKey",
                           "8wVysSpBc0LGzbwKMRh8hldSm") 
        System.setProperty("twitter4j.oauth.consumerSecret",
                  "FpV5MUDWliR6sInqIYIdkKMQEKaAUHdGJkEb4MVhDkh7dXtXPZ") 
        System.setProperty("twitter4j.oauth.accessToken",
                  "817207925756358656-yR0JR92VBdA2rBbgJaF7PYREbiV8VZq") 
        System.setProperty("twitter4j.oauth.accessTokenSecret",
                  "JsiVkUItwWCGyOLQEtnRpEhbXyZS9jNSzcMtycn68aBaS")

        val ssc = new StreamingContext(sc, Seconds(10))

        val twitterStream = TwitterUtils.createStream(ssc, None)

        twitterStream.saveAsTextFiles("streamouts/tweets", "txt")
        ssc.start()

        //wait for 30 seconds

        ss.stop(false)

```

您将看到`streamouts`文件夹中包含几个文本文件中的`tweets`输出。您现在可以打开`streamouts`目录并检查文件是否包含`tweets`。

# 离散流

Spark Streaming 是建立在一个称为**离散流**的抽象上的，称为**DStreams**。DStream 被表示为一系列 RDD，每个 RDD 在每个时间间隔创建。DStream 可以以类似于常规 RDD 的方式进行处理，使用类似的概念，如基于有向无环图的执行计划（有向无环图）。就像常规 RDD 处理一样，执行计划中的转换和操作也适用于 DStreams。

DStream 基本上将一个永无止境的数据流分成较小的块，称为微批处理，基于时间间隔，将每个单独的微批处理实现为一个 RDD，然后可以像常规 RDD 一样进行处理。每个这样的微批处理都是独立处理的，微批处理之间不保留状态，因此本质上是无状态的处理。假设批处理间隔为 5 秒，那么在事件被消耗时，每 5 秒间隔都会创建一个实时和微批处理，并将微批处理作为 RDD 交给进一步处理。Spark Streaming 的一个主要优势是用于处理事件微批处理的 API 调用与 spark 的 API 紧密集成，以提供与架构的其余部分无缝集成。当创建一个微批处理时，它会转换为一个 RDD，这使得使用 spark API 进行无缝处理成为可能。

`DStream`类在源代码中如下所示，显示了最重要的变量，即`HashMap[Time, RDD]`对：

```scala
class DStream[T: ClassTag] (var ssc: StreamingContext)

//hashmap of RDDs in the DStream
var generatedRDDs = new HashMap[Time, RDD[T]]()

```

以下是一个由每**T**秒创建的 RDD 组成的 DStream 的示例：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00076.jpeg)

在以下示例中，创建了一个流上下文，以便每 5 秒创建一个微批处理，并创建一个 RDD，它就像 Spark 核心 API RDD 一样。DStream 中的 RDD 可以像任何其他 RDD 一样进行处理。

构建流应用程序涉及的步骤如下：

1.  从`SparkContext`创建一个`StreamingContext`。

1.  从`StreamingContext`创建一个`DStream`。

1.  提供可以应用于每个 RDD 的转换和操作。

1.  最后，通过在`StreamingContext`上调用`start()`来启动流应用程序。这将启动消费和处理实时事件的整个过程。

一旦 Spark Streaming 应用程序启动，就不能再添加其他操作了。停止的上下文无法重新启动，如果有这样的需要，您必须创建一个新的流上下文。

以下是一个访问 Twitter 的简单流作业的示例：

1.  从`SparkContext`创建`StreamingContext`：

```scala
 scala> val ssc = new StreamingContext(sc, Seconds(5))
      ssc: org.apache.spark.streaming.StreamingContext = 
 org.apache.spark.streaming.StreamingContext@8ea5756

```

1.  从`StreamingContext`创建`DStream`：

```scala
 scala> val twitterStream = TwitterUtils.createStream(ssc, None)
      twitterStream: org.apache.spark.streaming.dstream
 .ReceiverInputDStream[twitter4j.Status] = 
 org.apache.spark.streaming.Twitter.TwitterInputDStream@46219d14

```

1.  提供可应用于每个 RDD 的转换和操作：

```scala
 val aggStream = twitterStream
 .flatMap(x => x.getText.split(" ")).filter(_.startsWith("#"))
 .map(x => (x, 1))
 .reduceByKey(_ + _)

```

1.  最后，通过在`StreamingContext`上调用`start()`来启动流应用程序。这将启动整个实时事件的消费和处理过程：

```scala
 ssc.start()      //to stop just call stop on the StreamingContext
 ssc.stop(false)

```

1.  创建了一个`ReceiverInputDStream`类型的`DStream`，它被定义为定义任何必须在工作节点上启动接收器以接收外部数据的`InputDStream`的抽象类。在这里，我们从 Twitter 流接收：

```scala
        class InputDStreamT: ClassTag extends
                                        DStreamT

        class ReceiverInputDStreamT: ClassTag
                                  extends InputDStreamT

```

1.  如果在`twitterStream`上运行`flatMap()`转换，将得到一个`FlatMappedDStream`，如下所示：

```scala
 scala> val wordStream = twitterStream.flatMap(x => x.getText()
                                                          .split(" "))
      wordStream: org.apache.spark.streaming.dstream.DStream[String] = 
 org.apache.spark.streaming.dstream.FlatMappedDStream@1ed2dbd5

```

# 转换

DStream 上的转换类似于适用于 Spark 核心 RDD 的转换。由于 DStream 由 RDD 组成，因此转换也适用于每个 RDD，以生成转换后的 RDD，然后创建转换后的 DStream。每个转换都创建一个特定的`DStream`派生类。

以下图表显示了从父`DStream`类开始的`DStream`类的层次结构。我们还可以看到从父类继承的不同类：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00019.jpeg)

有很多`DStream`类是专门为功能而构建的。映射转换、窗口函数、减少操作和不同类型的输入流都是使用从`DStream`类派生的不同类来实现的。

以下是对基本 DStream 进行转换以生成过滤 DStream 的示例。同样，任何转换都适用于 DStream：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00382.jpeg)

参考以下表格，了解可能的转换类型。

| 转换 | 意义 |
| --- | --- |
| `map(func)` | 将转换函数应用于 DStream 的每个元素，并返回一个新的 DStream。 |
| `flatMap(func)` | 这类似于 map；然而，就像 RDD 的`flatMap`与 map 一样，使用`flatMap`对每个元素进行操作并应用`flatMap`，从而为每个输入产生多个输出项。 |
| `filter(func)` | 这将过滤掉 DStream 的记录，返回一个新的 DStream。 |
| `repartition(numPartitions)` | 这将创建更多或更少的分区以重新分发数据以更改并行性。 |
| `union(otherStream)` | 这将合并两个源 DStream 中的元素，并返回一个新的 DStream。 |
| `count()` | 通过计算源 DStream 的每个 RDD 中的元素数量，返回一个新的 DStream。 |
| `reduce(func)` | 通过在源 DStream 的每个元素上应用`reduce`函数，返回一个新的 DStream。 |
| `countByValue()` | 这计算每个键的频率，并返回一个新的(key, long)对的 DStream。 |
| `reduceByKey(func, [numTasks])` | 这将按键聚合源 DStream 的 RDD，并返回一个新的(key, value)对的 DStream。 |
| `join(otherStream, [numTasks])` | 这将连接两个*(K, V)*和*(K, W)*对的 DStream，并返回一个新的*(K, (V, W))*对的 DStream，结合了两个 DStream 的值。 |
| `cogroup(otherStream, [numTasks])` | `cogroup()`在对*(K, V)*和*(K, W)*对的 DStream 调用时，将返回一个新的*(K, Seq[V], Seq[W])*元组的 DStream。 |
| `transform(func)` | 这在源 DStream 的每个 RDD 上应用转换函数，并返回一个新的 DStream。 |
| `updateStateByKey(func)` | 这通过在键的先前状态和键的新值上应用给定的函数来更新每个键的状态。通常用于维护状态机。 |

# 窗口操作

Spark Streaming 提供了窗口处理，允许您在事件的滑动窗口上应用转换。滑动窗口是在指定的间隔内创建的。每当窗口在源 DStream 上滑动时，窗口规范内的源 RDD 将被组合并操作以生成窗口化的 DStream。窗口需要指定两个参数：

+   **窗口长度：指定为窗口考虑的间隔长度**

+   滑动间隔：这是创建窗口的间隔

窗口长度和滑动间隔都必须是块间隔的倍数。

以下是一个示例，显示了具有滑动窗口操作的 DStream，显示了旧窗口（虚线矩形）如何在一个间隔内向右滑动到新窗口（实线矩形）：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00028.jpeg)

一些常见的窗口操作如下。

| 转换 | 意义 |
| --- | --- |
| `window(windowLength, slideInterval)` | 在源 DStream 上创建窗口，并返回一个新的 DStream。 |
| `countByWindow(windowLength, slideInterval)` | 通过应用滑动窗口返回 DStream 中元素的计数。 |
| `reduceByWindow(func, windowLength, slideInterval)` | 创建一个新的 DStream，通过在创建长度为`windowLength`的滑动窗口后，对源 DStream 的每个元素应用 reduce 函数来实现。 |
| `reduceByKeyAndWindow(func, windowLength, slideInterval, [numTasks])` | 在应用于源 DStream 的 RDD 的窗口中按键聚合数据，并返回新的（键，值）对的 DStream。计算由函数`func`提供。 |
| `reduceByKeyAndWindow(func, invFunc, windowLength, slideInterval, [numTasks])` | 在应用于源 DStream 的 RDD 的窗口中按键聚合数据，并返回新的（键，值）对的 DStream。与前一个函数的关键区别在于`invFunc`，它提供了在滑动窗口开始时要执行的计算。 |
| `countByValueAndWindow(windowLength, slideInterval, [numTasks])` | 这计算每个键的频率，并返回指定滑动窗口内的新 DStream 的（键，长）对。 |

让我们更详细地看一下 Twitter 流示例。我们的目标是每五秒打印流式传输的推文中使用的前五个单词，使用长度为 15 秒的窗口，每 10 秒滑动一次。因此，我们可以在 15 秒内获得前五个单词。

要运行此代码，请按照以下步骤操作：

1.  首先，打开终端并切换到`spark-2.1.1-bin-hadoop2.7`目录。

1.  在安装了 spark 的`spark-2.1.1-bin-hadoop2.7`文件夹下创建一个名为`streamouts`的文件夹。当应用程序运行时，`streamouts`文件夹将收集推文到文本文件中。

1.  将以下 jar 包下载到目录中：

+   [`central.maven.org/maven2/org/apache/bahir/spark-streaming-twitter_2.11/2.1.0/spark-streaming-twitter_2.11-2.1.0.jar`](http://central.maven.org/maven2/org/apache/bahir/spark-streaming-twitter_2.11/2.1.0/spark-streaming-twitter_2.11-2.1.0.jar)

+   [`central.maven.org/maven2/org/twitter4j/twitter4j-core/4.0.6/twitter4j-core-4.0.6.jar`](http://central.maven.org/maven2/org/twitter4j/twitter4j-core/4.0.6/twitter4j-core-4.0.6.jar)

+   [`central.maven.org/maven2/org/twitter4j/twitter4j-stream/4.0.6/twitter4j-stream-4.0.6.jar`](http://central.maven.org/maven2/org/twitter4j/twitter4j-stream/4.0.6/twitter4j-stream-4.0.6.jar)

1.  使用指定的 Twitter 集成所需的 jar 启动 spark-shell：

```scala
 ./bin/spark-shell --jars twitter4j-stream-4.0.6.jar,
                               twitter4j-core-4.0.6.jar,
                               spark-streaming-twitter_2.11-2.1.0.jar

```

1.  现在，我们可以编写代码。以下是用于测试 Twitter 事件处理的代码：

```scala
        import org.apache.log4j.Logger
        import org.apache.log4j.Level
        Logger.getLogger("org").setLevel(Level.OFF)

       import java.util.Date
       import org.apache.spark._
       import org.apache.spark.streaming._
       import org.apache.spark.streaming.Twitter._
       import twitter4j.auth.OAuthAuthorization
       import twitter4j.conf.ConfigurationBuilder

       System.setProperty("twitter4j.oauth.consumerKey",
                          "8wVysSpBc0LGzbwKMRh8hldSm")
       System.setProperty("twitter4j.oauth.consumerSecret",
                  "FpV5MUDWliR6sInqIYIdkKMQEKaAUHdGJkEb4MVhDkh7dXtXPZ")
       System.setProperty("twitter4j.oauth.accessToken",
                  "817207925756358656-yR0JR92VBdA2rBbgJaF7PYREbiV8VZq")
       System.setProperty("twitter4j.oauth.accessTokenSecret",
                  "JsiVkUItwWCGyOLQEtnRpEhbXyZS9jNSzcMtycn68aBaS")

       val ssc = new StreamingContext(sc, Seconds(5))

       val twitterStream = TwitterUtils.createStream(ssc, None)

       val aggStream = twitterStream
             .flatMap(x => x.getText.split(" "))
             .filter(_.startsWith("#"))
             .map(x => (x, 1))
             .reduceByKeyAndWindow(_ + _, _ - _, Seconds(15),
                                   Seconds(10), 5)

       ssc.checkpoint("checkpoints")
       aggStream.checkpoint(Seconds(10))

       aggStream.foreachRDD((rdd, time) => {
         val count = rdd.count()

         if (count > 0) {
           val dt = new Date(time.milliseconds)
           println(s"\n\n$dt rddCount = $count\nTop 5 words\n")
           val top5 = rdd.sortBy(_._2, ascending = false).take(5)
           top5.foreach {
             case (word, count) =>
             println(s"[$word] - $count")
           }
         }
       })

       ssc.start

       //wait 60 seconds
       ss.stop(false)

```

1.  输出每 15 秒在控制台上显示，并且看起来像下面这样：

```scala
 Mon May 29 02:44:50 EDT 2017 rddCount = 1453
 Top 5 words

 [#RT] - 64
 [#de] - 24
 [#a] - 15
 [#to] - 15
 [#the] - 13

 Mon May 29 02:45:00 EDT 2017 rddCount = 3312
 Top 5 words

 [#RT] - 161
 [#df] - 47
 [#a] - 35
 [#the] - 29
 [#to] - 29

```

# 有状态/无状态转换

如前所述，Spark Streaming 使用 DStreams 的概念，这些 DStreams 实质上是作为 RDDs 创建的微批数据。我们还看到了在 DStreams 上可能的转换类型。DStreams 上的转换可以分为两种类型：**无状态转换**和**有状态转换**。

在无状态转换中，每个微批处理的处理不依赖于先前的数据批处理。因此，这是一个无状态的转换，每个批处理都独立于此批处理之前发生的任何事情进行处理。

在有状态转换中，每个微批处理的处理取决于先前的数据批处理，完全或部分地。因此，这是一个有状态的转换，每个批处理都考虑了此批处理之前发生的事情，并在计算此批处理中的数据时使用这些信息。

# 无状态转换

无状态转换通过对 DStream 中的每个 RDD 应用转换来将一个 DStream 转换为另一个 DStream。诸如`map()`、`flatMap()`、`union()`、`join()`和`reduceByKey`等转换都是无状态转换的示例。

下面的示例显示了对`inputDStream`进行`map()`转换以生成新的`mapDstream`：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00210.jpeg)

# 有状态转换

有状态转换在 DStream 上进行操作，但计算取决于先前的处理状态。诸如`countByValueAndWindow`、`reduceByKeyAndWindow`、`mapWithState`和`updateStateByKey`等操作都是有状态转换的示例。实际上，所有基于窗口的转换都是有状态的，因为根据窗口操作的定义，我们需要跟踪 DStream 的窗口长度和滑动间隔。

# 检查点

实时流应用程序旨在长时间运行并对各种故障具有弹性。Spark Streaming 实现了一个检查点机制，可以维护足够的信息以从故障中恢复。

需要检查点的两种数据类型：

+   元数据检查点

+   数据检查点

可以通过在`StreamingContext`上调用`checkpoint()`函数来启用检查点，如下所示：

```scala
def checkpoint(directory: String)

```

指定可靠存储检查点数据的目录。

请注意，这必须是像 HDFS 这样的容错文件系统。

一旦设置了检查点目录，任何 DStream 都可以根据指定的间隔检查点到该目录中。看看 Twitter 的例子，我们可以每 10 秒将每个 DStream 检查点到`checkpoints`目录中：

```scala
val ssc = new StreamingContext(sc, Seconds(5))

val twitterStream = TwitterUtils.createStream(ssc, None)

val wordStream = twitterStream.flatMap(x => x.getText().split(" "))

val aggStream = twitterStream
 .flatMap(x => x.getText.split(" ")).filter(_.startsWith("#"))
 .map(x => (x, 1))
 .reduceByKeyAndWindow(_ + _, _ - _, Seconds(15), Seconds(10), 5)

ssc.checkpoint("checkpoints")

aggStream.checkpoint(Seconds(10))

wordStream.checkpoint(Seconds(10))

```

几秒钟后，`checkpoints`目录看起来像下面这样，显示了元数据以及 RDDs，`logfiles`也作为检查点的一部分进行维护：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00246.jpeg)

# 元数据检查点

**元数据检查点**保存定义流操作的信息，这些信息由**有向无环图**（**DAG**）表示到 HDFS。这可以用于在发生故障并且应用程序重新启动时恢复 DAG。驱动程序重新启动并从 HDFS 读取元数据，并重建 DAG 并恢复崩溃之前的所有操作状态。

元数据包括以下内容：

+   **配置**：用于创建流应用程序的配置

+   **DStream 操作**：定义流应用程序的 DStream 操作集

+   **不完整的批处理**：作业已排队但尚未完成的批处理

# 数据检查点

数据检查点将实际的 RDD 保存到 HDFS，以便如果流应用程序发生故障，应用程序可以恢复检查点的 RDD 并从中断的地方继续。虽然流应用程序恢复是数据检查点的一个很好的用例，但检查点还有助于在某些 RDD 由于缓存清理或执行器丢失而丢失时实例化生成的 RDD，而无需等待所有父 RDD 在血统（DAG）中重新计算。

对于具有以下任何要求的应用程序，必须启用检查点：

+   **使用有状态转换**：如果应用程序中使用了`updateStateByKey`或`reduceByKeyAndWindow`（带有逆函数），则必须提供检查点目录以允许定期 RDD 检查点。

+   **从运行应用程序的驱动程序的故障中恢复**：元数据检查点用于恢复进度信息。

如果您的流应用程序没有有状态的转换，则可以在不启用检查点的情况下运行应用程序。

您的流应用程序中可能会丢失已接收但尚未处理的数据。

请注意，RDD 的检查点会产生将每个 RDD 保存到存储的成本。这可能会导致 RDD 检查点的批次处理时间增加。因此，检查点的间隔需要谨慎设置，以免引起性能问题。在小批量大小（比如 1 秒）的情况下，每个小批量频繁检查点可能会显著降低操作吞吐量。相反，检查点太不频繁会导致血统和任务大小增长，这可能会导致处理延迟，因为要持久化的数据量很大。

对于需要 RDD 检查点的有状态转换，默认间隔是批处理间隔的倍数，至少为 10 秒。

一个 5 到 10 个滑动间隔的 DStream 的检查点间隔是一个很好的起点设置。

# 驱动程序故障恢复

使用`StreamingContext.getOrCreate()`可以实现驱动程序故障恢复，以初始化`StreamingContext`从现有检查点或创建新的 StreamingContext。

流应用程序启动时的两个条件如下：

+   当程序第一次启动时，需要从检查点目录中的检查点数据初始化一个新的`StreamingContext`，设置所有流，然后调用`start()`

+   在故障后重新启动程序时，需要从检查点目录中的检查点数据初始化一个`StreamingContext`，然后调用`start()`

我们将实现一个名为`createStreamContext()`的函数，它创建`StreamingContext`并设置各种 DStreams 来解析推文，并使用窗口每 15 秒生成前五个推文标签。但是，我们将调用`getOrCreate()`而不是调用`createStreamContext()`然后调用`ssc.start()`，这样如果`checkpointDirectory`存在，那么上下文将从检查点数据中重新创建。如果目录不存在（应用程序第一次运行），那么将调用函数`createStreamContext()`来创建一个新的上下文并设置 DStreams：

```scala
val ssc = StreamingContext.getOrCreate(checkpointDirectory,
                                       createStreamContext _)

```

以下是显示函数定义以及如何调用`getOrCreate()`的代码：

```scala
val checkpointDirectory = "checkpoints"

// Function to create and setup a new StreamingContext
def createStreamContext(): StreamingContext = {
  val ssc = new StreamingContext(sc, Seconds(5))

  val twitterStream = TwitterUtils.createStream(ssc, None)

  val wordStream = twitterStream.flatMap(x => x.getText().split(" "))

  val aggStream = twitterStream
    .flatMap(x => x.getText.split(" ")).filter(_.startsWith("#"))
    .map(x => (x, 1))
    .reduceByKeyAndWindow(_ + _, _ - _, Seconds(15), Seconds(10), 5)

  ssc.checkpoint(checkpointDirectory)

  aggStream.checkpoint(Seconds(10))

  wordStream.checkpoint(Seconds(10))

  aggStream.foreachRDD((rdd, time) => {
    val count = rdd.count()

    if (count > 0) {
      val dt = new Date(time.milliseconds)
      println(s"\n\n$dt rddCount = $count\nTop 5 words\n")
      val top10 = rdd.sortBy(_._2, ascending = false).take(5)
      top10.foreach {
        case (word, count) => println(s"[$word] - $count")
      }
    }
  })
  ssc
}

// Get StreamingContext from checkpoint data or create a new one
val ssc = StreamingContext.getOrCreate(checkpointDirectory, createStreamContext _)

```

# 与流平台（Apache Kafka）的互操作性

Spark Streaming 与 Apache Kafka 有非常好的集成，这是当前最流行的消息平台。Kafka 集成有几种方法，并且该机制随着时间的推移而不断发展，以提高性能和可靠性。

将 Spark Streaming 与 Kafka 集成有三种主要方法：

+   基于接收器的方法

+   直接流方法

+   结构化流

# 基于接收器的方法

基于接收器的方法是 Spark 和 Kafka 之间的第一个集成。在这种方法中，驱动程序在执行程序上启动接收器，使用高级 API 从 Kafka 代理中拉取数据。由于接收器从 Kafka 代理中拉取事件，接收器会将偏移量更新到 Zookeeper 中，这也被 Kafka 集群使用。关键之处在于使用**WAL**（预写式日志），接收器在从 Kafka 消耗数据时会不断写入。因此，当出现问题并且执行程序或接收器丢失或重新启动时，可以使用 WAL 来恢复事件并处理它们。因此，这种基于日志的设计既提供了耐用性又提供了一致性。

每个接收器都会从 Kafka 主题创建一个输入 DStream，同时查询 Zookeeper 以获取 Kafka 主题、代理、偏移量等。在此之后，我们在前几节中讨论过的 DStreams 就会发挥作用。

长时间运行的接收器使并行性变得复杂，因为随着应用程序的扩展，工作负载不会得到适当的分布。依赖 HDFS 也是一个问题，还有写操作的重复。至于一次性处理所需的可靠性，只有幂等方法才能起作用。接收器基于事务的方法无法起作用的原因是，无法从 HDFS 位置或 Zookeeper 访问偏移量范围。

基于接收器的方法适用于任何消息系统，因此更通用。

您可以通过调用`createStream()` API 创建基于接收器的流，如下所示：

```scala
def createStream(
 ssc: StreamingContext, // StreamingContext object
 zkQuorum: String, //Zookeeper quorum (hostname:port,hostname:port,..)
 groupId: String, //The group id for this consumer
 topics: Map[String, Int], //Map of (topic_name to numPartitions) to
                  consume. Each partition is consumed in its own thread
 storageLevel: StorageLevel = StorageLevel.MEMORY_AND_DISK_SER_2 
  Storage level to use for storing the received objects
  (default: StorageLevel.MEMORY_AND_DISK_SER_2)
): ReceiverInputDStream[(String, String)] //DStream of (Kafka message key, Kafka message value)

```

以下是创建基于接收器的流的示例，从 Kafka 代理中拉取消息：

```scala
val topicMap = topics.split(",").map((_, numThreads.toInt)).toMap
val lines = KafkaUtils.createStream(ssc, zkQuorum, group,
                                    topicMap).map(_._2)

```

以下是驱动程序如何在执行程序上启动接收器，使用高级 API 从 Kafka 中拉取数据的示例。接收器从 Kafka Zookeeper 集群中拉取主题偏移量范围，然后在从代理中拉取事件时也更新 Zookeeper：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00078.jpeg)

# 直接流

基于直接流的方法是相对于 Kafka 集成的较新方法，通过使用驱动程序直接连接到代理并拉取事件。关键之处在于使用直接流 API，Spark 任务在处理 Spark 分区到 Kafka 主题/分区时是一对一的比例。不依赖于 HDFS 或 WAL 使其灵活。此外，由于现在我们可以直接访问偏移量，我们可以使用幂等或事务性方法进行一次性处理。

创建一个直接从 Kafka 代理中拉取消息而不使用任何接收器的输入流。此流可以保证每条来自 Kafka 的消息在转换中被包含一次。

直接流的属性如下：

+   **没有接收器**：此流不使用任何接收器，而是直接查询 Kafka。

+   **偏移量**：这不使用 Zookeeper 来存储偏移量，而是由流本身跟踪消耗的偏移量。您可以从生成的 RDD 中访问每个批次使用的偏移量。

+   **故障恢复**：要从驱动程序故障中恢复，必须在`StreamingContext`中启用检查点。

+   **端到端语义**：此流确保每条记录被有效接收和转换一次，但不能保证转换后的数据是否被输出一次。

您可以使用 KafkaUtils 的`createDirectStream()` API 创建直接流，如下所示：

```scala
def createDirectStream[
 K: ClassTag, //K type of Kafka message key
 V: ClassTag, //V type of Kafka message value
 KD <: Decoder[K]: ClassTag, //KD type of Kafka message key decoder
 VD <: Decoder[V]: ClassTag, //VD type of Kafka message value decoder
 R: ClassTag //R type returned by messageHandler
](
 ssc: StreamingContext, //StreamingContext object
 KafkaParams: Map[String, String], 
  /*
  KafkaParams Kafka <a  href="http://Kafka.apache.org/documentation.html#configuration">
  configuration parameters</a>. Requires "metadata.broker.list" or   "bootstrap.servers"
to be set with Kafka broker(s) (NOT zookeeper servers) specified in
  host1:port1,host2:port2 form.
  */
 fromOffsets: Map[TopicAndPartition, Long], //fromOffsets Per- topic/partition Kafka offsets defining the (inclusive) starting point of the stream
 messageHandler: MessageAndMetadata[K, V] => R //messageHandler Function for translating each message and metadata into the desired type
): InputDStream[R] //DStream of R

```

以下是创建直接流的示例，从 Kafka 主题中拉取数据并创建 DStream：

```scala
val topicsSet = topics.split(",").toSet
val KafkaParams : Map[String, String] =
        Map("metadata.broker.list" -> brokers,
            "group.id" -> groupid )

val rawDstream = KafkaUtils.createDirectStreamString, String, StringDecoder, StringDecoder

```

直接流 API 只能与 Kafka 一起使用，因此这不是一种通用方法。

以下是驱动程序如何从 Zookeeper 中拉取偏移量信息，并指示执行程序根据驱动程序指定的偏移量范围启动任务从代理中拉取事件的示例：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00118.jpeg)

# 结构化流

结构化流是 Apache Spark 2.0+中的新功能，从 Spark 2.2 版本开始已经是 GA。您将在下一节中看到详细信息，以及如何使用结构化流的示例。

有关结构化流中 Kafka 集成的更多详细信息，请参阅[`spark.apache.org/docs/latest/structured-streaming-kafka-integration.html`](https://spark.apache.org/docs/latest/structured-streaming-kafka-integration.html)。

使用结构化流中的 Kafka 源流的示例如下：

```scala
val ds1 = spark
 .readStream
 .format("Kafka")
 .option("Kafka.bootstrap.servers", "host1:port1,host2:port2")
 .option("subscribe", "topic1")
 .load()

ds1.selectExpr("CAST(key AS STRING)", "CAST(value AS STRING)")
 .as[(String, String)]

```

使用 Kafka 源而不是源流的示例（如果您想要更多的批量分析方法）如下：

```scala
val ds1 = spark
 .read
 .format("Kafka")
 .option("Kafka.bootstrap.servers", "host1:port1,host2:port2")
 .option("subscribe", "topic1")
 .load()

ds1.selectExpr("CAST(key AS STRING)", "CAST(value AS STRING)")
 .as[(String, String)]

```

# 结构化流

结构化流是建立在 Spark SQL 引擎之上的可伸缩和容错的流处理引擎。这将流处理和计算更接近批处理，而不是 DStream 范式和当前时刻涉及的 Spark 流处理 API 的挑战。结构化流引擎解决了诸多挑战，如精确一次的流处理、处理结果的增量更新、聚合等。

结构化流 API 还提供了解决 Spark 流的一个重大挑战的手段，即，Spark 流以微批处理方式处理传入数据，并使用接收时间作为数据分割的手段，因此不考虑数据的实际事件时间。结构化流允许您在接收的数据中指定这样一个事件时间，以便自动处理任何延迟的数据。

结构化流在 Spark 2.2 中是 GA 的，API 已标记为 GA。请参阅[`spark.apache.org/docs/latest/structured-streaming-programming-guide.html`](https://spark.apache.org/docs/latest/structured-streaming-programming-guide.html)。

结构化流的关键思想是将实时数据流视为不断追加到的无界表，随着事件从流中处理，可以运行计算和 SQL 查询。例如，Spark SQL 查询将处理无界表：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00348.jpeg)

随着 DStream 随时间的变化，将处理更多的数据以生成结果。因此，无界输入表用于生成结果表。输出或结果表可以写入称为**输出**的外部接收器。

**输出**是写出的内容，可以以不同的模式定义：

+   **完整模式**：整个更新后的结果表将写入外部存储。由存储连接器决定如何处理整个表的写入。

+   **追加模式**：自上次触发以来附加到结果表的任何新行都将写入外部存储。这仅适用于查询，其中不希望更改结果表中的现有行。

+   **更新模式**：自上次触发以来更新的行将写入外部存储。请注意，这与完整模式不同，因为此模式仅输出自上次触发以来发生更改的行。如果查询不包含聚合，它将等同于追加模式。

下面是从无界表输出的示例：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00001.jpeg)

我们将展示一个示例，通过监听本地端口 9999 来创建一个结构化流查询。

如果使用 Linux 或 Mac，在端口 9999 上启动一个简单的服务器很容易：nc -lk 9999。

下面是一个示例，我们首先通过调用 SparkSession 的`readStream` API 创建一个`inputStream`，然后从行中提取单词。然后我们对单词进行分组和计数，最后将结果写入输出流：

```scala
//create stream reading from localhost 9999
val inputLines = spark.readStream
 .format("socket")
 .option("host", "localhost")
 .option("port", 9999)
 .load()
inputLines: org.apache.spark.sql.DataFrame = [value: string]

// Split the inputLines into words
val words = inputLines.as[String].flatMap(_.split(" "))
words: org.apache.spark.sql.Dataset[String] = [value: string]

// Generate running word count
val wordCounts = words.groupBy("value").count()
wordCounts: org.apache.spark.sql.DataFrame = [value: string, count: bigint]

val query = wordCounts.writeStream
 .outputMode("complete")
 .format("console")
query: org.apache.spark.sql.streaming.DataStreamWriter[org.apache.spark.sql.Row] = org.apache.spark.sql.streaming.DataStreamWriter@4823f4d0

query.start()

```

当您在终端中不断输入单词时，查询会不断更新并生成结果，这些结果将打印在控制台上：

```scala
scala> -------------------------------------------
Batch: 0
-------------------------------------------
+-----+-----+
|value|count|
+-----+-----+
| dog| 1|
+-----+-----+

-------------------------------------------
Batch: 1
-------------------------------------------
+-----+-----+
|value|count|
+-----+-----+
| dog| 1|
| cat| 1|
+-----+-----+

scala> -------------------------------------------
Batch: 2
-------------------------------------------
+-----+-----+
|value|count|
+-----+-----+
| dog| 2|
| cat| 1|
+-----+-----+

```

# 处理事件时间和延迟数据

**事件时间**是数据本身的时间。传统的 Spark 流处理只处理 DStream 目的的接收时间，但这对于许多需要事件时间的应用程序来说是不够的。例如，如果要每分钟获取推文中特定标签出现的次数，则应该使用生成数据时的时间，而不是 Spark 接收事件时的时间。通过将事件时间作为行/事件中的列来将事件时间纳入结构化流中是非常容易的。这允许基于窗口的聚合使用事件时间而不是接收时间运行。此外，该模型自然地处理了根据其事件时间到达的数据。由于 Spark 正在更新结果表，因此它可以完全控制在出现延迟数据时更新旧的聚合，以及清理旧的聚合以限制中间状态数据的大小。还支持为事件流设置水印，允许用户指定延迟数据的阈值，并允许引擎相应地清理旧状态。

水印使引擎能够跟踪当前事件时间，并通过检查数据的延迟阈值来确定是否需要处理事件或已经通过处理。例如，如果事件时间由`eventTime`表示，延迟到达数据的阈值间隔为`lateThreshold`，则通过检查`max(eventTime) - lateThreshold`的差异，并与从时间 T 开始的特定窗口进行比较，引擎可以确定是否可以在此窗口中考虑处理事件。

下面是对结构化流的前面示例的扩展，监听端口 9999。在这里，我们启用`Timestamp`作为输入数据的一部分，以便我们可以对无界表执行窗口操作以生成结果：

```scala
import java.sql.Timestamp import org.apache.spark.sql.SparkSession
import org.apache.spark.sql.functions._ // Create DataFrame representing the stream of input lines from connection to host:port
val inputLines = spark.readStream
 .format("socket")
 .option("host", "localhost")
 .option("port", 9999)
 .option("includeTimestamp", true)
 .load() // Split the lines into words, retaining timestamps
val words = inputLines.as[(String, Timestamp)].flatMap(line =>
 line._1.split(" ").map(word => (word, line._2))
).toDF("word", "timestamp") // Group the data by window and word and compute the count of each group
val windowedCounts = words.withWatermark("timestamp", "10 seconds")
.groupBy(
 window($"timestamp", "10 seconds", "10 seconds"), $"word"
).count().orderBy("window") // Start running the query that prints the windowed word counts to the console
val query = windowedCounts.writeStream
 .outputMode("complete")
 .format("console")
 .option("truncate", "false")

query.start()
query.awaitTermination()

```

# 容错语义

实现“端到端精确一次语义”是结构化流设计的关键目标之一，它实现了结构化流源、输出接收器和执行引擎，可可靠地跟踪处理的确切进度，以便能够通过重新启动和/或重新处理来处理任何类型的故障。假定每个流式源都有偏移量（类似于 Kafka 偏移量）来跟踪流中的读取位置。引擎使用检查点和预写日志来记录每个触发器中正在处理的数据的偏移量范围。流式输出接收器设计为幂等，以处理重新处理。通过使用可重放的源和幂等的接收器，结构化流可以确保在任何故障情况下实现端到端的精确一次语义。

请记住，传统流式处理中的范式更加复杂，需要使用一些外部数据库或存储来维护偏移量。

结构化流仍在不断发展，并且在被广泛使用之前需要克服一些挑战。其中一些挑战如下：

+   流式数据集上尚不支持多个流式聚合

+   流式数据集上不支持限制和获取前*N*行

+   流式数据集上不支持不同的操作

+   在执行聚合步骤之后，流式数据集上仅支持排序操作，而且仅在完整输出模式下才支持

+   目前还不支持任何两个流式数据集之间的连接操作。

+   只支持少数类型的接收器 - 文件接收器和每个接收器

# 总结

在本章中，我们讨论了流处理系统、Spark 流处理、Apache Spark 的 DStreams 概念、DStreams 是什么、DStreams 的 DAG 和血统、转换和操作。我们还研究了流处理的窗口概念。我们还看了使用 Spark 流处理从 Twitter 消费推文的实际示例。

此外，我们还研究了从 Kafka 消费数据的基于接收者和直接流的方法。最后，我们还研究了新的结构化流处理，它承诺解决许多挑战，如流上的容错和精确一次语义。我们还讨论了结构化流处理如何简化与 Kafka 或其他消息系统的集成。

在下一章中，我们将看一下图形处理以及它是如何运作的。
