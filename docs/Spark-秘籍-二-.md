# Spark 秘籍（二）

> 原文：[`zh.annas-archive.org/md5/BF1FAE88E839F4D0A5A0FD250CEC5835`](https://zh.annas-archive.org/md5/BF1FAE88E839F4D0A5A0FD250CEC5835)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：Spark SQL

Spark SQL 是用于处理结构化数据的 Spark 模块。本章分为以下几个部分：

+   了解 Catalyst 优化器

+   创建 HiveContext

+   使用案例类推断模式

+   以编程方式指定模式

+   使用 Parquet 格式加载和保存数据

+   使用 JSON 格式加载和保存数据

+   从关系数据库加载和保存数据

+   从任意源加载和保存数据

# 介绍

Spark 可以处理来自各种数据源的数据，如 HDFS、Cassandra、HBase 和关系数据库，包括 HDFS。大数据框架（不像关系数据库系统）在写入时不强制执行模式。HDFS 是一个完美的例子，在写入阶段任何任意文件都是可以的。然而，读取数据是另一回事。即使是完全非结构化的数据，你也需要给它一些结构来理解。有了这些结构化数据，SQL 在分析时非常方便。

Spark SQL 是 Spark 生态系统中相对较新的组件，首次在 Spark 1.0 中引入。它包含了一个名为 Shark 的项目，这是一个让 Hive 在 Spark 上运行的尝试。

Hive 本质上是一个关系抽象，它将 SQL 查询转换为 MapReduce 作业。

![介绍](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_04_01.jpg)

Shark 用 Spark 替换了 MapReduce 部分，同时保留了大部分代码库。

![介绍](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_04_02.jpg)

最初，它运行良好，但很快，Spark 开发人员遇到了障碍，无法进一步优化。最终，他们决定从头开始编写 SQL 引擎，这就诞生了 Spark SQL。

![介绍](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_04_03.jpg)

Spark SQL 解决了所有性能挑战，但它必须与 Hive 兼容，因此，`HiveContext`上面创建了一个新的包装器上下文`SQLContext`。

Spark SQL 支持使用标准 SQL 查询和 HiveQL 访问数据，HiveQL 是 Hive 使用的类似 SQL 的查询语言。在本章中，我们将探索 Spark SQL 的不同特性。它支持 HiveQL 的一个子集以及 SQL 92 的一个子集。它可以在现有的 Hive 部署中运行 SQL/HiveQL 查询或替代它们。

运行 SQL 只是创建 Spark SQL 的原因之一。一个很大的原因是它有助于更快地创建和运行 Spark 程序。它让开发人员编写更少的代码，程序读取更少的数据，并让优化器来处理所有繁重的工作。

Spark SQL 使用了一个名为 DataFrame 的编程抽象。它是一个以命名列组织的分布式数据集合。DataFrame 相当于数据库表，但提供了更精细的优化级别。DataFrame API 还确保了 Spark 在不同语言绑定中的性能是一致的。

让我们对比一下 DataFrame 和 RDD。RDD 是一个不透明的对象集合，对底层数据格式一无所知。相反，DataFrame 与它们关联了模式。实际上，直到 Spark 1.2，有一个名为**SchemaRDD**的组件，现在已经演变成了 DataFrame。它们提供比 SchemaRDD 更丰富的功能。

关于模式的额外信息使得许多优化成为可能，这是其他情况下不可能的。

DataFrame 还可以透明地从各种数据源加载，如 Hive 表、Parquet 文件、JSON 文件和使用 JDBC 的外部数据库。DataFrame 可以被视为一组行对象的 RDD，允许用户调用过程式的 Spark API，如 map。

DataFrame API 在 Spark 1.4 开始提供 Scala、Java、Python 和 R。

用户可以使用**领域特定语言**（**DSL**）在 DataFrame 上执行关系操作。DataFrame 支持所有常见的关系操作符，它们都使用有限的 DSL 中的表达式对象，让 Spark 捕获表达式的结构。

我们将从 Spark SQL 的入口点 SQLContext 开始。我们还将介绍 HiveContext，它是 SQLContext 的包装器，用于支持 Hive 功能。请注意，HiveContext 经过了更多的实战检验，并提供了更丰富的功能，因此强烈建议即使您不打算连接到 Hive，也要使用它。慢慢地，SQLContext 将达到与 HiveContext 相同的功能水平。

有两种方法可以将模式与 RDD 关联起来创建 DataFrame。简单的方法是利用 Scala case 类，我们将首先介绍这种方法。Spark 使用 Java 反射从 case 类中推断模式。还有一种方法可以为高级需求编程指定模式，我们将在下一节中介绍。

Spark SQL 提供了一种简单的方法来加载和保存 Parquet 文件，我们也将介绍。最后，我们将介绍从 JSON 加载和保存数据。

# 理解 Catalyst 优化器

Spark SQL 的大部分功能都来自于 Catalyst 优化器，因此花一些时间来了解它是有意义的。

![理解 Catalyst 优化器](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_04_04.jpg)

## 工作原理…

Catalyst 优化器主要利用了 Scala 的函数式编程构造，如模式匹配。它提供了一个通用的框架来转换树，我们用它来执行分析、优化、规划和运行时代码生成。

Catalyst 优化器有两个主要目标：

+   使添加新的优化技术变得容易

+   使外部开发人员能够扩展优化器

Spark SQL 在四个阶段使用 Catalyst 的转换框架：

+   分析逻辑计划以解析引用

+   逻辑计划优化

+   物理规划

+   代码生成以将查询的部分编译为 Java 字节码

### 分析

分析阶段涉及查看 SQL 查询或 DataFrame，创建一个逻辑计划（仍未解析）（引用的列可能不存在或类型错误），然后使用 Catalog 对象解析此计划（连接到物理数据源），并创建一个逻辑计划，如下图所示：

![分析](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_04_05.jpg)

### 逻辑计划优化

逻辑计划优化阶段对逻辑计划应用标准的基于规则的优化。这些包括常量折叠、谓词下推、投影修剪、空值传播、布尔表达式简化和其他规则。

我想特别注意这里的谓词下推规则。这个概念很简单；如果您在一个地方发出查询来运行对大量数据的查询，这个数据存储在另一个地方，它可能导致大量不必要的数据在网络上移动。

如果我们可以将查询的一部分下推到数据存储的地方，从而过滤掉不必要的数据，就可以显著减少网络流量。

![逻辑计划优化](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_04_06.jpg)

### 物理规划

在物理规划阶段，Spark SQL 接受逻辑计划并生成一个或多个物理计划。然后它测量每个物理计划的成本，并基于此生成一个物理计划。

![物理规划](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_04_07.jpg)

### 代码生成

查询优化的最后阶段涉及生成 Java 字节码以在每台机器上运行。它使用了一种特殊的 Scala 功能，称为**准引用**来实现这一点。

# 创建 HiveContext

`SQLContext`及其后代`HiveContext`是进入 Spark SQL 世界的两个入口点。`HiveContext`提供了 SQLContext 提供的功能的超集。附加功能包括：

+   更完整和经过实战检验的 HiveQL 解析器

+   访问 Hive UDFs

+   从 Hive 表中读取数据的能力

从 Spark 1.3 开始，Spark shell 加载了 sqlContext（它是`HiveContext`的实例，而不是`SQLContext`）。如果您在 Scala 代码中创建`SQLContext`，可以使用`SparkContext`来创建，如下所示：

```scala
val sc: SparkContext
val sqlContext = new org.apache.spark.sql.SQLContext(sc)
```

在本教程中，我们将介绍如何创建`HiveContext`的实例，然后通过 Spark SQL 访问 Hive 功能。

## 准备工作

为了启用 Hive 功能，请确保已启用 Hive（-Phive）装配 JAR 可在所有工作节点上使用；另外，将`hive-site.xml`复制到 Spark 安装的`conf`目录中。Spark 必须能够访问`hive-site.xml`，否则它将创建自己的 Hive 元数据存储，并且不会连接到现有的 Hive 仓库。

默认情况下，Spark SQL 创建的所有表都是由 Hive 管理的表，也就是说，Hive 完全控制表的生命周期，包括使用`drop table`命令删除表元数据。这仅适用于持久表。Spark SQL 还有机制可以将 DataFrame 创建为临时表，以便编写查询，它们不受 Hive 管理。

请注意，Spark 1.4 支持 Hive 版本 0.13.1。您可以在使用 Maven 构建时使用`-Phive-<version> build`选项指定要构建的 Hive 版本。例如，要使用 0.12.0 构建，您可以使用`-Phive-0.12.0`。

## 如何做...

1.  启动 Spark shell 并为其提供一些额外的内存：

```scala
$ spark-shell --driver-memory 1G

```

1.  创建`HiveContext`的实例：

```scala
scala> val hc = new org.apache.spark.sql.hive.HiveContext(sc)

```

1.  创建一个 Hive 表`Person`，其中`first_name`、`last_name`和`age`作为列：

```scala
scala>  hc.sql("create table if not exists person(first_name string, last_name string, age int) row format delimited fields terminated by ','")

```

1.  在另一个 shell 中创建`person`数据并放入本地文件：

```scala
$ mkdir person
$ echo "Barack,Obama,53" >> person/person.txt
$ echo "George,Bush,68" >> person/person.txt
$ echo "Bill,Clinton,68" >> person/person.txt

```

1.  在`person`表中加载数据：

```scala
scala> hc.sql("load data local inpath \"/home/hduser/person\" into table person")

```

1.  或者，从 HDFS 中加载`person`表中的数据：

```scala
scala> hc.sql("load data inpath \"/user/hduser/person\" into table person")

```

### 注意

请注意，使用`load data inpath`将数据从另一个 HDFS 位置移动到 Hive 的`warehouse`目录，默认为`/user/hive/warehouse`。您还可以指定完全限定的路径，例如`hdfs://localhost:9000/user/hduser/person`。

1.  使用 HiveQL 选择人员数据：

```scala
scala> val persons = hc.sql("from person select first_name,last_name,age")
scala> persons.collect.foreach(println)

```

1.  从`select`查询的输出创建新表：

```scala
scala> hc.sql("create table person2 as select first_name, last_name from person;")

```

1.  您还可以直接从一个表复制到另一个表：

```scala
scala> hc.sql("create table person2 like person location '/user/hive/warehouse/person'")

```

1.  创建两个表`people_by_last_name`和`people_by_age`来保持计数：

```scala
scala> hc.sql("create table people_by_last_name(last_name string,count int)")
scala> hc.sql("create table people_by_age(age int,count int)")

```

1.  您还可以使用 HiveQL 查询将记录插入多个表中：

```scala
scala> hc.sql("""from person
 insert overwrite table people_by_last_name
 select last_name, count(distinct first_name)
 group by last_name
insert overwrite table people_by_age
 select age, count(distinct first_name)
 group by age; """)

```

# 使用案例类推断模式

案例类是 Scala 中的特殊类，为您提供了构造函数、getter（访问器）、equals 和 hashCode 的样板实现，并实现了`Serializable`。案例类非常适合封装数据作为对象。熟悉 Java 的读者可以将其与**普通旧的 Java 对象**（**POJOs**）或 Java bean 相关联。

案例类的美妙之处在于，所有在 Java 中需要的繁重工作都可以在案例类中用一行代码完成。Spark 使用案例类的反射来推断模式。

## 如何做...

1.  启动 Spark shell 并为其提供一些额外的内存：

```scala
$ spark-shell --driver-memory 1G

```

1.  导入隐式转换：

```scala
scala> import sqlContext.implicits._

```

1.  创建一个`Person`案例类：

```scala
scala> case class Person(first_name:String,last_name:String,age:Int)

```

1.  在另一个 shell 中，创建一些样本数据放入 HDFS 中：

```scala
$ mkdir person
$ echo "Barack,Obama,53" >> person/person.txt
$ echo "George,Bush,68" >> person/person.txt
$ echo "Bill,Clinton,68" >> person/person.txt
$ hdfs dfs -put person person

```

1.  将`person`目录加载为 RDD：

```scala
scala> val p = sc.textFile("hdfs://localhost:9000/user/hduser/person")

```

1.  根据逗号将每行拆分为字符串数组，作为分隔符：

```scala
val pmap = p.map( line => line.split(","))

```

1.  将 Array[String]的 RDD 转换为`Person`案例对象的 RDD：

```scala
scala> val personRDD = pmap.map( p => Person(p(0),p(1),p(2).toInt))

```

1.  将`personRDD`转换为`personDF` DataFrame：

```scala
scala> val personDF = personRDD.toDF

```

1.  将`personDF`注册为表：

```scala
scala> personDF.registerTempTable("person")

```

1.  对其运行 SQL 查询：

```scala
scala> val people = sql("select * from person")

```

1.  从`persons`获取输出值：

```scala
scala> people.collect.foreach(println)

```

# 以编程方式指定模式

有些情况下案例类可能不起作用；其中之一是案例类不能拥有超过 22 个字段。另一种情况可能是您事先不知道模式。在这种方法中，数据被加载为`Row`对象的 RDD。模式是使用`StructType`和`StructField`对象分别创建的，它们分别表示表和字段。模式应用于`Row` RDD 以创建 DataFrame。

## 如何做...

1.  启动 Spark shell 并为其提供一些额外的内存：

```scala
$ spark-shell --driver-memory 1G

```

1.  导入隐式转换：

```scala
scala> import sqlContext.implicit._

```

1.  导入 Spark SQL 数据类型和`Row`对象：

```scala
scala> import org.apache.spark.sql._
scala> import org.apache.spark.sql.types._

```

1.  在另一个 shell 中，创建一些样本数据放入 HDFS 中：

```scala
$ mkdir person
$ echo "Barack,Obama,53" >> person/person.txt
$ echo "George,Bush,68" >> person/person.txt
$ echo "Bill,Clinton,68" >> person/person.txt
$ hdfs dfs -put person person

```

1.  在 RDD 中加载`person`数据：

```scala
scala> val p = sc.textFile("hdfs://localhost:9000/user/hduser/person")

```

1.  根据逗号将每行拆分为字符串数组，作为分隔符：

```scala
scala> val pmap = p.map( line => line.split(","))

```

1.  将 array[string]的 RDD 转换为`Row`对象的 RDD：

```scala
scala> val personData = pmap.map( p => Row(p(0),p(1),p(2).toInt))

```

1.  使用`StructType`和`StructField`对象创建模式。`StructField`对象以参数名、参数类型和可空性的形式接受参数：

```scala
scala> val schema = StructType(
 Array(StructField("first_name",StringType,true),
StructField("last_name",StringType,true),
StructField("age",IntegerType,true)
))

```

1.  应用模式以创建`personDF` DataFrame：

```scala
scala> val personDF = sqlContext.createDataFrame(personData,schema)

```

1.  将`personDF`注册为表：

```scala
scala> personDF.registerTempTable("person")

```

1.  对其运行 SQL 查询：

```scala
scala> val persons = sql("select * from person")

```

1.  从`persons`获取输出值：

```scala
scala> persons.collect.foreach(println)

```

在本教程中，我们学习了如何通过以编程方式指定模式来创建 DataFrame。

## 它是如何工作的…

`StructType`对象定义了模式。您可以将其视为关系世界中的表或行的等价物。`StructType`接受`StructField`对象的数组，如以下签名所示：

```scala
StructType(fields: Array[StructField])
```

`StructField`对象具有以下签名：

```scala
StructField(name: String, dataType: DataType, nullable: Boolean = true, metadata: Metadata = Metadata.empty)
```

以下是有关使用的参数的更多信息：

+   `name`：这代表字段的名称。

+   `dataType`：这显示了该字段的数据类型。

允许以下数据类型：

| `IntegerType` | `FloatType` |
| --- | --- |
| `BooleanType` | `ShortType` |
| `LongType` | `ByteType` |
| `DoubleType` | `StringType` |

+   `nullable`：这显示了该字段是否可以为 null。

+   `metadata`：这显示了该字段的元数据。元数据是`Map[String,Any]`的包装器，因此它可以包含任意元数据。

# 使用 Parquet 格式加载和保存数据

Apache Parquet 是一种列式数据存储格式，专为大数据存储和处理而设计。Parquet 基于 Google Dremel 论文中的记录分解和组装算法。在 Parquet 中，单个列中的数据是连续存储的。

列格式为 Parquet 带来了一些独特的好处。例如，如果您有一个具有 100 列的表，并且您主要访问 10 列，在基于行的格式中，您将不得不加载所有 100 列，因为粒度级别在行级别。但是，在 Parquet 中，您只会加载 10 列。另一个好处是，由于给定列中的所有数据都是相同的数据类型（根据定义），因此压缩效率要高得多。

## 如何做…

1.  打开终端并在本地文件中创建`person`数据：

```scala
$ mkdir person
$ echo "Barack,Obama,53" >> person/person.txt
$ echo "George,Bush,68" >> person/person.txt
$ echo "Bill,Clinton,68" >> person/person.txt

```

1.  将`person`目录上传到 HDFS：

```scala
$ hdfs dfs -put person /user/hduser/person

```

1.  启动 Spark shell 并为其提供一些额外的内存：

```scala
$ spark-shell --driver-memory 1G

```

1.  导入隐式转换：

```scala
scala> import sqlContext.implicits._

```

1.  为`Person`创建一个 case 类：

```scala
scala> case class Person(firstName: String, lastName: String, age:Int)

```

1.  从 HDFS 加载`person`目录并将其映射到`Person` case 类：

```scala
scala> val personRDD = sc.textFile("hdfs://localhost:9000/user/hduser/person").map(_.split("\t")).map(p => Person(p(0),p(1),p(2).toInt))

```

1.  将`personRDD`转换为`person` DataFrame：

```scala
scala> val person = personRDD.toDF

```

1.  将`person` DataFrame 注册为临时表，以便可以对其运行 SQL 查询。请注意，DataFrame 名称不必与表名相同。

```scala
scala> person.registerTempTable("person")

```

1.  选择所有年龄超过 60 岁的人：

```scala
scala> val sixtyPlus = sql("select * from person where age > 60")

```

1.  打印值：

```scala
scala> sixtyPlus.collect.foreach(println)

```

1.  让我们以 Parquet 格式保存这个`sixtyPlus` RDD：

```scala
scala> sixtyPlus.saveAsParquetFile("hdfs://localhost:9000/user/hduser/sp.parquet")

```

1.  上一步在 HDFS 根目录中创建了一个名为`sp.parquet`的目录。您可以在另一个 shell 中运行`hdfs dfs -ls`命令来确保它已创建：

```scala
$ hdfs dfs -ls sp.parquet

```

1.  在 Spark shell 中加载 Parquet 文件的内容：

```scala
scala> val parquetDF = sqlContext.load("hdfs://localhost:9000/user/hduser/sp.parquet")

```

1.  将加载的`parquet` DF 注册为`temp`表：

```scala
scala> 
parquetDF
.registerTempTable("sixty_plus")

```

1.  对上述`temp`表运行查询：

```scala
scala> sql("select * from sixty_plus")

```

## 它是如何工作的…

让我们花一些时间更深入地了解 Parquet 格式。以下是以表格格式表示的示例数据：

| 名 | 姓 | 年龄 |
| --- | --- | --- |
| Barack | Obama | 53 |
| George | Bush | 68 |
| Bill | Clinton | 68 |

在行格式中，数据将存储如下：

| Barack | Obama | 53 | George | Bush | 68 | Bill | Clinton | 68 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |

在列式布局中，数据将存储如下：

| 行组 => | Barack | George | Bill | Obama | Bush | Clinton | 53 | 68 | 68 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
|   | 列块 | 列块 | 列块 |

以下是有关不同部分的简要描述：

+   **行组**：这显示了数据在行中的水平分区。行组由列块组成。

+   **列块**：列块包含行组中给定列的数据。列块始终是物理上连续的。每个行组每列只有一个列块。

+   **页面**：列块被分成页面。页面是存储单位，不能进一步分割。页面在列块中依次写入。页面的数据可以被压缩。

如果 Hive 表中已经有数据，比如`person`表，您可以通过以下步骤直接将其保存为 Parquet 格式：

1.  创建名为`person_parquet`的表，模式与`person`相同，但存储格式为 Parquet（从 Hive 0.13 开始）：

```scala
hive> create table person_parquet like person stored as parquet

```

1.  通过从`person`表导入数据，在`person_parquet`表中插入数据：

```scala
hive> insert overwrite table person_parquet select * from person;

```

### 提示

有时，从其他来源（如 Impala）导入的数据会将字符串保存为二进制。在读取时将其转换为字符串，设置以下属性在`SparkConf`中：

```scala
scala> sqlContext.setConf("spark.sql.parquet.binaryAsString","true")

```

## 还有更多...

如果您使用的是 Spark 1.4 或更高版本，有一个新的接口可以写入和从 Parquet 中读取。要将数据写入 Parquet（第 11 步重写），让我们将这个`sixtyPlus` RDD 保存为 Parquet 格式（RDD 隐式转换为 DataFrame）：

```scala
scala>sixtyPlus.write.parquet("hdfs://localhost:9000/user/hduser/sp.parquet")

```

要从 Parquet 中读取（第 13 步重写；结果是 DataFrame），在 Spark shell 中加载 Parquet 文件的内容：

```scala
scala>val parquetDF = sqlContext.read.parquet("hdfs://localhost:9000/user/hduser/sp.parquet")

```

# 使用 JSON 格式加载和保存数据

JSON 是一种轻量级的数据交换格式。它基于 JavaScript 编程语言的一个子集。JSON 的流行与 XML 的不受欢迎直接相关。XML 是提供数据结构的一种很好的解决方案，以纯文本格式呈现。随着时间的推移，XML 文档变得越来越沉重，开销不值得。

JSON 通过提供结构并最小化开销解决了这个问题。有些人称 JSON 为**无脂肪 XML**。

JSON 语法遵循以下规则：

+   数据以键值对的形式呈现：

```scala
"firstName" : "Bill"
```

+   JSON 中有四种数据类型：

+   字符串（"firstName"："Barack"）

+   数字（"age"：53）

+   布尔值（"alive"：true）

+   null（"manager"：null）

+   数据由逗号分隔

+   花括号{}表示对象：

```scala
{ "firstName" : "Bill", "lastName": "Clinton", "age": 68 }
```

+   方括号[]表示数组：

```scala
[{ "firstName" : "Bill", "lastName": "Clinton", "age": 68 },{"firstName": "Barack","lastName": "Obama", "age": 43}]
```

在本教程中，我们将探讨如何以 JSON 格式保存和加载数据。

## 如何做...

1.  打开终端并以 JSON 格式创建`person`数据：

```scala
$ mkdir jsondata
$ vi jsondata/person.json
{"first_name" : "Barack", "last_name" : "Obama", "age" : 53}
{"first_name" : "George", "last_name" : "Bush", "age" : 68 }
{"first_name" : "Bill", "last_name" : "Clinton", "age" : 68 }

```

1.  将`jsondata`目录上传到 HDFS：

```scala
$ hdfs dfs -put jsondata /user/hduser/jsondata

```

1.  启动 Spark shell 并为其提供一些额外的内存：

```scala
$ spark-shell --driver-memory 1G

```

1.  创建`SQLContext`的实例：

```scala
scala> val sqlContext = new org.apache.spark.sql.SQLContext(sc)

```

1.  导入隐式转换：

```scala
scala> import sqlContext.implicits._

```

1.  从 HDFS 加载`jsondata`目录：

```scala
scala> val person = sqlContext.jsonFile("hdfs://localhost:9000/user/hduser/jsondata")

```

1.  将`person` DF 注册为`temp`表，以便对其运行 SQL 查询：

```scala
scala> person.registerTempTable("person")

```

1.  选择所有年龄超过 60 岁的人：

```scala
scala> val sixtyPlus = sql("select * from person where age > 60")

```

1.  打印值：

```scala
scala> sixtyPlus.collect.foreach(println)
```

1.  让我们以 JSON 格式保存这个`sixtyPlus`数据框

```scala
scala> sixtyPlus.toJSON.saveAsTextFile("hdfs://localhost:9000/user/hduser/sp")

```

1.  上一步在 HDFS 根目录创建了一个名为`sp`的目录。您可以在另一个 shell 中运行`hdfs dfs -ls`命令来确保它已创建：

```scala
$ hdfs dfs -ls sp

```

## 它的工作原理...

`sc.jsonFile`内部使用`TextInputFormat`，它一次处理一行。因此，一个 JSON 记录不能跨多行。如果使用多行，它将是有效的 JSON 格式，但不会在 Spark 中工作，并会抛出异常。

允许一行中有多个对象。例如，您可以将两个人的信息作为数组放在一行中，如下所示：

```scala
[{"firstName":"Barack", "lastName":"Obama"},{"firstName":"Bill", "lastName":"Clinton"}]
```

本教程介绍了使用 Spark 以 JSON 格式保存和加载数据的方法。

## 还有更多...

如果您使用的是 Spark 1.4 或更高版本，`SqlContext`提供了一个更容易的接口来从 HDFS 加载`jsondata`目录：

```scala
scala> val person = sqlContext.read.json ("hdfs://localhost:9000/user/hduser/jsondata")

```

`sqlContext.jsonFile`在 1.4 版本中已被弃用，推荐使用`sqlContext.read.json`。

# 从关系数据库加载和保存数据

在上一章中，我们学习了如何使用 JdbcRDD 将关系数据加载到 RDD 中。Spark 1.4 支持直接从 JDBC 资源加载数据到 Dataframe。本教程将探讨如何实现这一点。

## 准备工作

请确保 JDBC 驱动程序 JAR 在客户端节点和所有执行器将运行的从节点上可见。

## 如何做...

1.  在 MySQL 中创建名为`person`的表，使用以下 DDL：

```scala
CREATE TABLE 'person' (
  'person_id' int(11) NOT NULL AUTO_INCREMENT,
  'first_name' varchar(30) DEFAULT NULL,
  'last_name' varchar(30) DEFAULT NULL,
  'gender' char(1) DEFAULT NULL,
  'age' tinyint(4) DEFAULT NULL,
  PRIMARY KEY ('person_id')
)
```

1.  插入一些数据：

```scala
Insert into person values('Barack','Obama','M',53);
Insert into person values('Bill','Clinton','M',71);
Insert into person values('Hillary','Clinton','F',68);
Insert into person values('Bill','Gates','M',69);
Insert into person values('Michelle','Obama','F',51);
```

1.  从[`dev.mysql.com/downloads/connector/j/`](http://dev.mysql.com/downloads/connector/j/)下载`mysql-connector-java-x.x.xx-bin.jar`。

1.  使 MySQL 驱动程序可用于 Spark shell 并启动它：

```scala
$ spark-shell --driver-class-path/path-to-mysql-jar/mysql-connector-java-5.1.34-bin.jar

```

### 注意

请注意，`path-to-mysql-jar`不是实际的路径名。您需要使用您的路径名。

1.  构建 JDBC URL：

```scala
scala> val url="jdbc:mysql://localhost:3306/hadoopdb"

```

1.  创建一个包含用户名和密码的连接属性对象：

```scala
scala> val prop = new java.util.Properties
scala> prop.setProperty("user","hduser")
scala> prop.setProperty("password","********")

```

1.  使用 JDBC 数据源加载 DataFrame（url、表名、属性）：

```scala
 scala> val people = sqlContext.read.jdbc(url,"person",prop)

```

1.  通过执行以下命令以漂亮的表格格式显示结果：

```scala
scala> people.show

```

1.  这已经加载了整个表。如果我只想加载男性（url、表名、谓词、属性）怎么办？要做到这一点，请运行以下命令：

```scala
scala> val males = sqlContext.read.jdbc(url,"person",Array("gender='M'"),prop)
scala> males.show

```

1.  通过执行以下命令只显示名字：

```scala
scala> val first_names = people.select("first_name")
scala> first_names.show

```

1.  通过执行以下命令只显示年龄低于 60 岁的人：

```scala
scala> val below60 = people.filter(people("age") < 60)
scala> below60.show

```

1.  按性别对人进行分组：

```scala
scala> val grouped = people.groupBy("gender")

```

1.  通过执行以下命令找到男性和女性的数量：

```scala
scala> val gender_count = grouped.count
scala> gender_count.show

```

1.  通过执行以下命令找到男性和女性的平均年龄：

```scala
scala> val avg_age = grouped.avg("age")
scala> avg_age.show

```

1.  现在，如果您想将这个`avg_age`数据保存到一个新表中，请运行以下命令：

```scala
scala> gender_count.write.jdbc(url,"gender_count",prop)

```

1.  将 people DataFrame 以 Parquet 格式保存：

```scala
scala> people.write.parquet("people.parquet")

```

1.  将 people DataFrame 保存为 JSON 格式：

```scala
scala> people.write.json("people.json")

```

# 从任意数据源加载和保存数据

到目前为止，我们已经涵盖了三种内置于 DataFrame 中的数据源——`parquet`（默认），`json`和`jdbc`。DataFrame 不仅限于这三种，可以通过手动指定格式加载和保存到任意数据源。

在本教程中，我们将介绍从任意数据源加载和保存数据。

## 如何做到这一点...

1.  启动 Spark shell 并为其提供一些额外的内存：

```scala
$ spark-shell --driver-memory 1G

```

1.  从 Parquet 加载数据；由于`parquet`是默认数据源，您不必指定它：

```scala
scala> val people = sqlContext.read.load("hdfs://localhost:9000/user/hduser/people.parquet") 

```

1.  通过手动指定格式从 Parquet 加载数据：

```scala
scala> val people = sqlContext.read.format("org.apache.spark.sql.parquet").load("hdfs://localhost:9000/user/hduser/people.parquet") 

```

1.  对于内置数据类型（`parquet`，`json`和`jdbc`），您不必指定完整的格式名称，只需指定`"parquet"`，`"json"`或`"jdbc"`即可：

```scala
scala> val people = sqlContext.read.format("parquet").load("hdfs://localhost:9000/user/hduser/people.parquet") 

```

### 注意

在写入数据时，有四种保存模式：`append`，`overwrite`，`errorIfExists`和`ignore`。`append`模式将数据添加到数据源，`overwrite`将其覆盖，`errorIfExists`在数据已经存在时抛出异常，`ignore`在数据已经存在时不执行任何操作。

1.  将 people 保存为 JSON 格式，使用`append`模式：

```scala
scala> val people = people.write.format("json").mode("append").save ("hdfs://localhost:9000/user/hduser/people.json") 

```

## 还有更多...

Spark SQL 的数据源 API 可以保存到各种数据源。要获取更多信息，请访问[`spark-packages.org/`](http://spark-packages.org/)。


# 第五章：Spark Streaming

Spark Streaming 为 Apache Spark 增加了大数据处理的圣杯——即实时分析。它使 Spark 能够摄取实时数据流，并以极低的延迟（几秒钟）提供实时智能。

在本章中，我们将涵盖以下配方：

+   使用流式处理的单词计数

+   流式处理 Twitter 数据

+   使用 Kafka 进行流式处理

# 介绍

流式处理是将持续流动的输入数据分成离散单元的过程，以便可以轻松处理。现实生活中熟悉的例子是流式视频和音频内容（尽管用户可以在观看之前下载完整的电影，但更快的解决方案是以小块流式传输数据，这些数据开始播放给用户，而其余数据则在后台下载）。

除了多媒体之外，流式处理的实际例子包括市场数据源、天气数据、电子股票交易数据等的处理。所有这些应用程序产生大量数据，速度非常快，并且需要对数据进行特殊处理，以便实时从数据中获取洞察。

流式处理有一些基本概念，在我们专注于 Spark Streaming 之前最好先了解。流式应用程序接收数据的速率称为**数据速率**，以**每秒千字节**（**kbps**）或**每秒兆字节**（**mbps**）的形式表示。

流式处理的一个重要用例是**复杂事件处理**（**CEP**）。在 CEP 中，控制正在处理的数据范围很重要。这个范围称为窗口，可以基于时间或大小。基于时间的窗口的一个例子是分析过去一分钟内的数据。基于大小的窗口的一个例子可以是给定股票的最近 100 笔交易的平均要价。

Spark Streaming 是 Spark 的库，提供支持处理实时数据。这个流可以来自任何来源，比如 Twitter、Kafka 或 Flume。

在深入研究配方之前，Spark Streaming 有一些基本构建块，我们需要充分理解。

Spark Streaming 有一个称为`StreamingContext`的上下文包装器，它包装在`SparkContext`周围，并且是 Spark Streaming 功能的入口点。流式数据根据定义是连续的，需要进行时间切片处理。这段时间被称为**批处理间隔**，在创建`StreamingContext`时指定。RDD 和批处理之间是一对一的映射，也就是说，每个批处理都会产生一个 RDD。正如您在下图中所看到的，Spark Streaming 接收连续数据，将其分成批次并馈送给 Spark。

![Introduction](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_05_01.jpg)

批处理间隔对于优化流式应用程序非常重要。理想情况下，您希望至少以数据获取的速度进行处理；否则，您的应用程序将产生积压。Spark Streaming 在一个批处理间隔的持续时间内收集数据，比如 2 秒。一旦这个 2 秒的间隔结束，该间隔内收集的数据将被交给 Spark 进行处理，而流式处理将专注于收集下一个批处理间隔的数据。现在，这个 2 秒的批处理间隔是 Spark 处理数据的全部时间，因为它应该空闲以接收下一个批处理的数据。如果 Spark 能够更快地处理数据，您可以将批处理间隔减少到 1 秒。如果 Spark 无法跟上这个速度，您必须增加批处理间隔。

Spark Streaming 中的 RDD 的连续流需要以一种抽象的形式表示，通过这种抽象可以对其进行处理。这种抽象称为**离散流**（**DStream**）。对 DStream 应用的任何操作都会导致对底层 RDD 的操作。

每个输入 DStream 都与一个接收器相关联（除了文件流）。接收器从输入源接收数据并将其存储在 Spark 的内存中。有两种类型的流式源：

+   基本来源，如文件和套接字连接

+   高级来源，如 Kafka 和 Flume

Spark Streaming 还提供了窗口计算，您可以在其中对数据的滑动窗口应用转换。滑动窗口操作基于两个参数：

+   **窗口长度**：这是窗口的持续时间。例如，如果您想要获取最后 1 分钟的数据分析，窗口长度将是 1 分钟。

+   **滑动间隔**：这表示您希望多频繁执行操作。比如您希望每 10 秒执行一次操作；这意味着每 10 秒，窗口的 1 分钟将有 50 秒的数据与上一个窗口相同，以及 10 秒的新数据。

这两个参数都作用于底层的 RDD，显然不能被分开；因此，这两个参数都应该是批处理间隔的倍数。窗口长度也必须是滑动间隔的倍数。

DStream 还具有输出操作，允许将数据推送到外部系统。它们类似于 RDD 上的操作（在 DStream 上发生的抽象级别更高）。

除了打印 DStream 的内容之外，还支持标准 RDD 操作，例如`saveAsTextFile`，`saveAsObjectFile`和`saveAsHadoopFile`，分别由类似的对应物`saveAsTextFiles`，`saveAsObjectFiles`和`saveAsHadoopFiles`。

一个非常有用的输出操作是`foreachRDD(func)`，它将任意函数应用于所有 RDD。

# 使用流媒体进行单词计数

让我们从一个简单的流媒体示例开始，在其中一个终端中，我们将输入一些文本，流媒体应用程序将在另一个窗口中捕获它。

## 如何做...

1.  启动 Spark shell 并为其提供一些额外的内存：

```scala
$ spark-shell --driver-memory 1G

```

1.  流特定的导入：

```scala
scala> import org.apache.spark.SparkConf
scala> import org.apache.spark.streaming.{Seconds, StreamingContext}
scala> import org.apache.spark.storage.StorageLevel
scala> import StorageLevel._

```

1.  隐式转换的导入：

```scala
scala> import org.apache.spark._
scala> import org.apache.spark.streaming._
scala> import org.apache.spark.streaming.StreamingContext._

```

1.  使用 2 秒批处理间隔创建`StreamingContext`： 

```scala
scala> val ssc = new StreamingContext(sc, Seconds(2))

```

1.  在本地主机上使用端口`8585`创建一个`SocketTextStream` Dstream，并使用`MEMORY_ONLY`缓存：

```scala
scala> val lines = ssc.socketTextStream("localhost",8585,MEMORY_ONLY)

```

1.  将行分成多个单词：

```scala
scala> val wordsFlatMap = lines.flatMap(_.split(" "))

```

1.  将单词转换为（单词，1），即将`1`作为单词的每次出现的值输出为键：

```scala
scala> val wordsMap = wordsFlatMap.map( w => (w,1))

```

1.  使用`reduceByKey`方法为每个单词的出现次数添加一个数字作为键（该函数一次处理两个连续的值，由`a`和`b`表示）：

```scala
scala> val wordCount = wordsMap.reduceByKey( (a,b) => (a+b))

```

1.  打印`wordCount`：

```scala
scala> wordCount.print

```

1.  启动`StreamingContext`；记住，直到启动`StreamingContext`之前什么都不会发生：

```scala
scala> ssc.start

```

1.  现在，在一个单独的窗口中，启动 netcat 服务器：

```scala
$ nc -lk 8585

```

1.  输入不同的行，例如`to be or not to be`：

```scala
to be or not to be

```

1.  检查 Spark shell，您将看到类似以下截图的单词计数结果：![如何做...](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_05_02.jpg)

# 流媒体 Twitter 数据

Twitter 是一个著名的微博平台。它每天产生大量数据，大约有 5 亿条推文。Twitter 允许通过 API 访问其数据，这使其成为测试任何大数据流应用程序的典范。

在这个示例中，我们将看到如何使用 Twitter 流媒体库在 Spark 中实时流式传输数据。Twitter 只是提供流数据给 Spark 的一个来源，并没有特殊的地位。因此，Twitter 没有内置的库。尽管如此，Spark 确实提供了一些 API 来促进与 Twitter 库的集成。

使用实时 Twitter 数据源的一个示例用途是查找过去 5 分钟内的热门推文。

## 如何做...

1.  如果您还没有 Twitter 帐户，请创建一个 Twitter 帐户。

1.  转到[`apps.twitter.com`](http://apps.twitter.com)。

1.  点击**创建新应用**。

1.  输入**名称**，**描述**，**网站**和**回调 URL**，然后点击**创建您的 Twitter 应用程序**。![如何做...](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_05_03.jpg)

1.  您将到达**应用程序管理**屏幕。

1.  导航到**密钥和访问令牌** | **创建我的访问令牌**。![如何做...](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_05_04.jpg)

1.  记下屏幕上的四个值，我们将在第 14 步中使用：

**消费者密钥（API 密钥）**

**消费者密钥（API 密钥）**

**访问令牌**

访问令牌密钥

1.  我们将需要在一段时间内在这个屏幕上提供这些值，但是，现在，让我们从 Maven 中央库下载所需的第三方库：

```scala
$ wget http://central.maven.org/maven2/org/apache/spark/spark-streaming-twitter_2.10/1.2.0/spark-streaming-twitter_2.10-1.2.0.jar
$ wget http://central.maven.org/maven2/org/twitter4j/twitter4j-stream/4.0.2/twitter4j-stream-4.0.2.jar
$ wget http://central.maven.org/maven2/org/twitter4j/twitter4j-core/4.0.2/twitter4j-core-4.0.2.jar

```

1.  打开 Spark shell，提供前面三个 JAR 作为依赖项：

```scala
$ spark-shell --jars spark-streaming-twitter_2.10-1.2.0.jar, twitter4j-stream-4.0.2.jar,twitter4j-core-4.0.2.jar

```

1.  执行特定于 Twitter 的导入：

```scala
scala> import org.apache.spark.streaming.twitter._
scala> import twitter4j.auth._
scala> import twitter4j.conf._

```

1.  流特定的导入：

```scala
scala> import org.apache.spark.streaming.{Seconds, StreamingContext}

```

1.  导入隐式转换：

```scala
scala> import org.apache.spark._
scala> import org.apache.spark.streaming._
scala> import org.apache.spark.streaming.StreamingContext._

```

1.  使用 10 秒批处理间隔创建`StreamingContext`：

```scala
scala> val ssc = new StreamingContext(sc, Seconds(10))

```

1.  使用 2 秒批处理间隔创建`StreamingContext`：

```scala
scala> val cb = new ConfigurationBuilder
scala> cb.setDebugEnabled(true)
.setOAuthConsumerKey("FKNryYEKeCrKzGV7zuZW4EKeN")
.setOAuthConsumerSecret("x6Y0zcTBOwVxpvekSCnGzbi3NYNrM5b8ZMZRIPI1XRC3pDyOs1")
 .setOAuthAccessToken("31548859-DHbESdk6YoghCLcfhMF88QEFDvEjxbM6Q90eoZTGl")
.setOAuthAccessTokenSecret("wjcWPvtejZSbp9cgLejUdd6W1MJqFzm5lByUFZl1NYgrV")
val auth = new OAuthAuthorization(cb.build)

```

### 注意

这些是示例值，您应该放入自己的值。

1.  创建 Twitter DStream：

```scala
scala> val tweets = TwitterUtils.createStream(ssc,auth)

```

1.  过滤掉英文推文：

```scala
scala> val englishTweets = tweets.filter(_.getLang()=="en")

```

1.  从推文中获取文本：

```scala
scala> val status = englishTweets.map(status => status.getText)

```

1.  设置检查点目录：

```scala
scala> ssc.checkpoint("hdfs://localhost:9000/user/hduser/checkpoint")

```

1.  启动`StreamingContext`：

```scala
scala> ssc.start
scala> ssc.awaitTermination

```

1.  您可以使用`:paste`将所有这些命令放在一起：

```scala
scala> :paste
import org.apache.spark.streaming.twitter._
import twitter4j.auth._
import twitter4j.conf._
import org.apache.spark.streaming.{Seconds, StreamingContext}
import org.apache.spark._
import org.apache.spark.streaming._
import org.apache.spark.streaming.StreamingContext._
val ssc = new StreamingContext(sc, Seconds(10))
val cb = new ConfigurationBuilder
cb.setDebugEnabled(true).setOAuthConsumerKey("FKNryYEKeCrKzGV7zuZW4EKeN")
 .setOAuthConsumerSecret("x6Y0zcTBOwVxpvekSCnGzbi3NYNrM5b8ZMZRIPI1XRC3pDyOs1")
 .setOAuthAccessToken("31548859-DHbESdk6YoghCLcfhMF88QEFDvEjxbM6Q90eoZTGl")
 .setOAuthAccessTokenSecret("wjcWPvtejZSbp9cgLejUdd6W1MJqFzm5lByUFZl1NYgrV")
val auth = new OAuthAuthorization(cb.build)
val tweets = TwitterUtils.createStream(ssc,Some(auth))
val englishTweets = tweets.filter(_.getLang()=="en")
val status = englishTweets.map(status => status.getText)
status.print
ssc.checkpoint("hdfs://localhost:9000/checkpoint")
ssc.start
ssc.awaitTermination

```

# 使用 Kafka 进行流处理

Kafka 是一个分布式、分区和复制的提交日志服务。简单地说，它是一个分布式消息服务器。Kafka 将消息源维护在称为**主题**的类别中。主题的一个示例可以是您想要获取有关的公司的新闻的股票代码，例如 Cisco 的 CSCO。

生成消息的进程称为**生产者**，消费消息的进程称为**消费者**。在传统的消息传递中，消息服务有一个中央消息服务器，也称为**代理**。由于 Kafka 是一个分布式消息传递服务，它有一个代理集群，功能上充当一个 Kafka 代理，如下所示：

![使用 Kafka 进行流处理](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/B03056_05_06.jpg)

对于每个主题，Kafka 维护分区日志。这个分区日志由分布在集群中的一个或多个分区组成，如下图所示：

![使用 Kafka 进行流处理](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/B03056_05_07.jpg)

Kafka 从 Hadoop 和其他大数据框架借鉴了许多概念。分区的概念与 Hadoop 中的`InputSplit`概念非常相似。在最简单的形式中，使用`TextInputFormat`时，`InputSplit`与块相同。块以`TextInputFormat`中的键值对形式读取，其中键是行的字节偏移量，值是行的内容本身。类似地，在 Kafka 分区中，记录以键值对的形式存储和检索，其中键是称为偏移量的顺序 ID 号，值是实际消息。

在 Kafka 中，消息的保留不取决于消费者的消费。消息将保留一段可配置的时间。每个消费者可以以任何他们喜欢的顺序读取消息。它需要保留的只是一个偏移量。另一个类比可以是阅读一本书，其中页码类似于偏移量，而页内容类似于消息。只要他们记住书签（当前偏移量），读者可以以任何方式阅读。

为了提供类似于传统消息系统中的发布/订阅和 PTP（队列）的功能，Kafka 有消费者组的概念。消费者组是一组消费者，Kafka 集群将其视为一个单元。在消费者组中，只需要一个消费者接收消息。如果消费者 C1 在下图中接收主题 T1 的第一条消息，则该主题上的所有后续消息也将传递给该消费者。使用这种策略，Kafka 保证了给定主题的消息传递顺序。

在极端情况下，当所有消费者都在一个消费者组中时，Kafka 集群的行为类似于 PTP/队列。在另一个极端情况下，如果每个消费者都属于不同的组，它的行为类似于发布/订阅。在实践中，每个消费者组有一定数量的消费者。

![使用 Kafka 进行流处理](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/B03056_05_08.jpg)

这个示例将展示如何使用来自 Kafka 的数据执行单词计数。

## 准备好

这个示例假设 Kafka 已经安装。Kafka 自带 ZooKeeper。我们假设 Kafka 的主目录在`/opt/infoobjects/kafka`中：

1.  启动 ZooKeeper：

```scala
$ /opt/infoobjects/kafka/bin/zookeeper-server-start.sh /opt/infoobjects/kafka/config/zookeeper.properties

```

1.  启动 Kafka 服务器：

```scala
$ /opt/infoobjects/kafka/bin/kafka-server-start.sh /opt/infoobjects/kafka/config/server.properties

```

1.  创建一个`test`主题：

```scala
$ /opt/infoobjects/kafka/bin/kafka-topics.sh --create --zookeeper localhost:2181 --replication-factor 1 --partitions 1 --topic test

```

## 如何做...：

1.  下载`spark-streaming-kafka`库及其依赖项：

```scala
$ wget http://central.maven.org/maven2/org/apache/spark/spark-streaming-kafka_2.10/1.2.0/spark-streaming-kafka_2.10-1.2.0.jar
$ wget http://central.maven.org/maven2/org/apache/kafka/kafka_2.10/0.8.1/kafka_2.10-0.8.1.jar
$ wget http://central.maven.org/maven2/com/yammer/metrics/metrics-core/2.2.0/metrics-core-2.2.0.jar
$ wget http://central.maven.org/maven2/com/101tec/zkclient/0.4/zkclient-0.4.jar

```

1.  启动 Spark shell 并提供`spark-streaming-kafka`库：

```scala
$ spark-shell --jars spark-streaming-kafka_2.10-1.2.0.jar, kafka_2.10-0.8.1.jar,metrics-core-2.2.0.jar,zkclient-0.4.jar

```

1.  流特定导入：

```scala
scala> import org.apache.spark.streaming.{Seconds, StreamingContext}

```

1.  隐式转换导入：

```scala
scala> import org.apache.spark._
scala> import org.apache.spark.streaming._
scala> import org.apache.spark.streaming.StreamingContext._
scala> import org.apache.spark.streaming.kafka.KafkaUtils

```

1.  创建具有 2 秒批处理间隔的`StreamingContext`：

```scala
scala> val ssc = new StreamingContext(sc, Seconds(2))

```

1.  设置 Kafka 特定变量：

```scala
scala> val zkQuorum = "localhost:2181"
scala> val group = "test-group"
scala> val topics = "test"
scala> val numThreads = 1

```

1.  创建`topicMap`：

```scala
scala> val topicMap = topics.split(",").map((_,numThreads.toInt)).toMap

```

1.  创建 Kafka DStream：

```scala
scala> val lineMap = KafkaUtils.createStream(ssc, zkQuorum, group, topicMap)

```

1.  从 lineMap 中取出值：

```scala
scala> val lines = lineMap.map(_._2)

```

1.  创建值的`flatMap`：

```scala
scala> val words = lines.flatMap(_.split(" "))

```

1.  创建（单词，出现次数）的键值对：

```scala
scala> val pair = words.map( x => (x,1))

```

1.  对滑动窗口进行单词计数：

```scala
scala> val wordCounts = pair.reduceByKeyAndWindow(_ + _, _ - _, Minutes(10), Seconds(2), 2)
scala> wordCounts.print

```

1.  设置`checkpoint`目录：

```scala
scala> ssc.checkpoint("hdfs://localhost:9000/user/hduser/checkpoint")

```

1.  启动`StreamingContext`：

```scala
scala> ssc.start
scala> ssc.awaitTermination

```

1.  在另一个窗口的 Kafka 中的`test`主题上发布一条消息：

```scala
$ /opt/infoobjects/kafka/bin/kafka-console-producer.sh --broker-list localhost:9092 --topic test

```

1.  现在，通过在第 15 步按*Enter*并在每条消息后按*Enter*来在 Kafka 上发布消息。

1.  现在，当您在 Kafka 上发布消息时，您将在 Spark shell 中看到它们：![如何做...](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_05_05.jpg)

## 还有更多...

假设您想要维护每个单词出现次数的运行计数。Spark Streaming 具有名为`updateStateByKey`操作的功能。`updateStateByKey`操作允许您在更新时维护任意状态并使用新提供的信息进行更新。

这种任意状态可以是聚合值，也可以是状态的改变（比如 Twitter 用户的心情）。执行以下步骤：

1.  让我们在对 RDD 对调用`updateStateByKey`：

```scala
scala> val runningCounts = wordCounts.updateStateByKey( (values: Seq[Int], state: Option[Int]) => Some(state.sum + values.sum))

```

### 注意

`updateStateByKey`操作返回一个新的“状态”DStream，其中每个键的状态都通过在键的先前状态和键的新值上应用给定函数来更新。这可以用于维护每个键的任意状态数据。

使此操作生效涉及两个步骤：

+   定义状态

+   定义状态`update`函数

对于每个键，都会调用一次`updateStateByKey`操作，值表示与该键关联的值序列，非常类似于 MapReduce，状态可以是任意状态，我们选择使其为`Option[Int]`。在第 18 步的每次调用中，通过将当前值的总和添加到先前状态来更新先前状态。

1.  打印结果：

```scala
scala> runningCounts.print

```

1.  以下是使用`updateStateByKey`操作来维护任意状态的所有步骤的组合：

```scala
Scala> :paste
import org.apache.spark.streaming.{Seconds, StreamingContext}
 import org.apache.spark._
 import org.apache.spark.streaming._
 import org.apache.spark.streaming.kafka._
 import org.apache.spark.streaming.StreamingContext._
 val ssc = new StreamingContext(sc, Seconds(2))
 val zkQuorum = "localhost:2181"
 val group = "test-group"
 val topics = "test"
 val numThreads = 1
 val topicMap = topics.split(",").map((_,numThreads.toInt)).toMap
 val lineMap = KafkaUtils.createStream(ssc, zkQuorum, group, topicMap)
 val lines = lineMap.map(_._2)
 val words = lines.flatMap(_.split(" "))
 val pairs = words.map(x => (x,1))
 val runningCounts = pairs.updateStateByKey( (values: Seq[Int], state: Option[Int]) => Some(state.sum + values.sum))
 runningCounts.print
ssc.checkpoint("hdfs://localhost:9000/user/hduser/checkpoint")
 ssc.start
 ssc.awaitTermination

```

1.  按下*Ctrl* + *D*运行它（使用`:paste`粘贴的代码）。


# 第六章：使用 MLlib 开始机器学习

本章分为以下配方：

+   创建向量

+   创建标记点

+   创建矩阵

+   计算摘要统计信息

+   计算相关性

+   进行假设检验

+   使用 ML 创建机器学习管道

# 介绍

以下是维基百科对机器学习的定义：

> *"机器学习是一门探索从数据中学习的算法的构建和研究的科学学科。"*

基本上，机器学习是利用过去的数据来预测未来。机器学习在很大程度上依赖于统计分析和方法。

在统计学中，有四种测量标度：

| 规模类型 | 描述 |
| --- | --- |
| 名义标度 | =，≠识别类别不能是数字示例：男性，女性 |
| 序数标度 | =，≠，<，>名义标度+从最不重要到最重要的排名示例：公司等级制度 |
| 间隔标度 | =，≠，<，>，+，-序数标度+观察之间的距离分配的数字指示顺序任何连续值之间的差异与其他值相同 60°温度不是 30°的两倍 |
| 比例标度 | =，≠，<，>，+，×，÷间隔标度+观察的比率$20 是$10 的两倍 |

数据之间可以进行的另一个区分是连续数据和离散数据。连续数据可以取任何值。大多数属于间隔和比例标度的数据是连续的。

离散变量只能取特定的值，值之间有明确的界限。例如，一所房子可以有两间或三间房间，但不能有 2.75 间。属于名义和序数标度的数据始终是离散的。

MLlib 是 Spark 的机器学习库。在本章中，我们将专注于机器学习的基础知识。

# 创建向量

在了解向量之前，让我们专注于点是什么。一个点只是一组数字。这组数字或坐标定义了点在空间中的位置。坐标的数量确定了空间的维度。

我们可以用最多三个维度来可视化空间。具有三个以上维度的空间称为**超空间**。让我们利用这个空间的隐喻。

让我们从一个人开始。一个人具有以下维度：

+   重量

+   身高

+   年龄

我们在三维空间中工作。因此，点（160,69,24）的解释将是 160 磅的体重，69 英寸的身高和 24 岁的年龄。

### 注意

点和向量是同一回事。向量中的维度称为**特征**。换句话说，我们可以将特征定义为被观察现象的个体可测属性。

Spark 有本地向量和矩阵，还有分布式矩阵。分布式矩阵由一个或多个 RDD 支持。本地向量具有数字索引和双值，并存储在单台机器上。

MLlib 中有两种本地向量：密集和稀疏。密集向量由其值的数组支持，而稀疏向量由两个并行数组支持，一个用于索引，另一个用于值。

因此，人的数据（160,69,24）将使用密集向量表示为[160.0,69.0,24.0]，使用稀疏向量格式表示为（3，[0,1,2]，[160.0,69.0,24.0]）。

是将向量稀疏还是密集取决于它有多少空值或 0。让我们以一个包含 10,000 个值的向量为例，其中有 9,000 个值为 0。如果我们使用密集向量格式，它将是一个简单的结构，但会浪费 90%的空间。稀疏向量格式在这里会更好，因为它只保留非零的索引。

稀疏数据非常常见，Spark 支持`libsvm`格式，该格式每行存储一个特征向量。

## 如何做…

1.  启动 Spark shell：

```scala
$ spark-shell

```

1.  显式导入 MLlib 向量（不要与其他向量类混淆）：

```scala
Scala> import org.apache.spark.mllib.linalg.{Vectors,Vector}

```

1.  创建密集向量：

```scala
scala> val dvPerson = Vectors.dense(160.0,69.0,24.0)

```

1.  创建稀疏向量：

```scala
scala> val svPerson = Vectors.sparse(3,Array(0,1,2),Array(160.0,69.0,24.0))

```

## 它是如何工作的...

以下是`vectors.dense`的方法签名：

```scala
def dense(values: Array[Double]): Vector
```

这里，值表示向量中元素的双精度数组。

以下是`Vectors.sparse`的方法签名：

```scala
def sparse(size: Int, indices: Array[Int], values: Array[Double]): Vector
```

这里，`size`表示向量的大小，`indices`是索引数组，`values`是双精度值数组。确保您指定`double`作为数据类型，或者至少在一个值中使用十进制；否则，对于只有整数的数据集，它将抛出异常。

# 创建一个带标签的点

带标签的点是一个带有相关标签的本地向量（稀疏/密集），在监督学习中用于帮助训练算法。您将在下一章中了解更多相关信息。

标签以双精度值存储在`LabeledPoint`中。这意味着当您有分类标签时，它们需要被映射为双精度值。您分配给类别的值是无关紧要的，只是一种便利。

| 类型 | 标签值 |
| --- | --- |
| 二元分类 | 0 或 1 |
| 多类分类 | 0, 1, 2… |
| 回归 | 十进制值 |

## 如何做…

1.  启动 Spark shell：

```scala
$spark-shell

```

1.  显式导入 MLlib 向量：

```scala
scala> import org.apache.spark.mllib.linalg.{Vectors,Vector}

```

1.  导入`LabeledPoint`：

```scala
scala> import org.apache.spark.mllib.regression.LabeledPoint

```

1.  使用正标签和密集向量创建一个带标签的点：

```scala
scala> val willBuySUV = LabeledPoint(1.0,Vectors.dense(300.0,80,40))

```

1.  使用负标签和密集向量创建一个带标签的点：

```scala
scala> val willNotBuySUV = LabeledPoint(0.0,Vectors.dense(150.0,60,25))

```

1.  使用正标签和稀疏向量创建一个带标签的点：

```scala
scala> val willBuySUV = LabeledPoint(1.0,Vectors.sparse(3,Array(0,1,2),Array(300.0,80,40)))

```

1.  使用负标签和稀疏向量创建一个带标签的点：

```scala
scala> val willNotBuySUV = LabeledPoint(0.0,Vectors.sparse(3,Array(0,1,2),Array(150.0,60,25)))

```

1.  创建一个包含相同数据的`libsvm`文件：

```scala
$vi person_libsvm.txt (libsvm indices start with 1)
0  1:150 2:60 3:25
1  1:300 2:80 3:40

```

1.  将`person_libsvm.txt`上传到`hdfs`：

```scala
$ hdfs dfs -put person_libsvm.txt person_libsvm.txt

```

1.  做更多的导入：

```scala
scala> import org.apache.spark.mllib.util.MLUtils
scala> import org.apache.spark.rdd.RDD

```

1.  从`libsvm`文件加载数据：

```scala
scala> val persons = MLUtils.loadLibSVMFile(sc,"person_libsvm.txt")

```

# 创建矩阵

矩阵只是一个表示多个特征向量的表。可以存储在一台机器上的矩阵称为**本地矩阵**，可以分布在集群中的矩阵称为**分布式矩阵**。

本地矩阵具有基于整数的索引，而分布式矩阵具有基于长整数的索引。两者的值都是双精度。

有三种类型的分布式矩阵：

+   `RowMatrix`：每行都是一个特征向量。

+   `IndexedRowMatrix`：这也有行索引。

+   `CoordinateMatrix`：这只是一个`MatrixEntry`的矩阵。`MatrixEntry`表示矩阵中的一个条目，由其行和列索引表示。

## 如何做…

1.  启动 Spark shell：

```scala
$spark-shell

```

1.  导入与矩阵相关的类：

```scala
scala> import org.apache.spark.mllib.linalg.{Vectors,Matrix, Matrices}

```

1.  创建一个密集的本地矩阵：

```scala
scala> val people = Matrices.dense(3,2,Array(150d,60d,25d, 300d,80d,40d))

```

1.  创建一个`personRDD`作为向量的 RDD：

```scala
scala> val personRDD = sc.parallelize(List(Vectors.dense(150,60,25), Vectors.dense(300,80,40)))

```

1.  导入`RowMatrix`和相关类：

```scala
scala> import org.apache.spark.mllib.linalg.distributed.{IndexedRow, IndexedRowMatrix,RowMatrix, CoordinateMatrix, MatrixEntry}

```

1.  创建一个`personRDD`的行矩阵：

```scala
scala> val personMat = new RowMatrix(personRDD)

```

1.  打印行数：

```scala
scala> print(personMat.numRows)

```

1.  打印列数：

```scala
scala> print(personMat.numCols)

```

1.  创建一个索引行的 RDD：

```scala
scala> val personRDD = sc.parallelize(List(IndexedRow(0L, Vectors.dense(150,60,25)), IndexedRow(1L, Vectors.dense(300,80,40))))

```

1.  创建一个索引行矩阵：

```scala
scala> val pirmat = new IndexedRowMatrix(personRDD)

```

1.  打印行数：

```scala
scala> print(pirmat.numRows)

```

1.  打印列数：

```scala
scala> print(pirmat.numCols)

```

1.  将索引行矩阵转换回行矩阵：

```scala
scala> val personMat = pirmat.toRowMatrix

```

1.  创建一个矩阵条目的 RDD：

```scala
scala> val meRDD = sc.parallelize(List(
 MatrixEntry(0,0,150),
 MatrixEntry(1,0,60),
MatrixEntry(2,0,25),
MatrixEntry(0,1,300),
MatrixEntry(1,1,80),
MatrixEntry(2,1,40)
))

```

1.  创建一个坐标矩阵：

```scala
scala> val pcmat = new CoordinateMatrix(meRDD)

```

1.  打印行数：

```scala
scala> print(pcmat.numRows)

```

1.  打印列数：

```scala
scala> print(pcmat.numCols)

```

# 计算摘要统计

汇总统计用于总结观察结果，以获得对数据的整体感觉。摘要包括以下内容：

+   数据的中心趋势-均值、众数、中位数

+   数据的分布-方差、标准差

+   边界条件-最小值、最大值

这个示例介绍了如何生成摘要统计信息。

## 如何做…

1.  启动 Spark shell：

```scala
$ spark-shell

```

1.  导入与矩阵相关的类：

```scala
scala> import org.apache.spark.mllib.linalg.{Vectors,Vector}
scala> import org.apache.spark.mllib.stat.Statistics

```

1.  创建一个`personRDD`作为向量的 RDD：

```scala
scala> val personRDD = sc.parallelize(List(Vectors.dense(150,60,25), Vectors.dense(300,80,40)))

```

1.  计算列的摘要统计：

```scala
scala> val summary = Statistics.colStats(personRDD)

```

1.  打印这个摘要的均值：

```scala
scala> print(summary.mean)

```

1.  打印方差：

```scala
scala> print(summary.variance)

```

1.  打印每列中非零值的数量：

```scala
scala> print(summary.numNonzeros)

```

1.  打印样本大小：

```scala
scala> print(summary.count)

```

1.  打印每列的最大值：

```scala
scala> print(summary.max)

```

# 计算相关性

相关性是两个变量之间的统计关系，当一个变量改变时，会导致另一个变量的改变。相关性分析衡量了这两个变量相关的程度。

如果一个变量的增加导致另一个变量的增加，这被称为**正相关**。如果一个变量的增加导致另一个变量的减少，这是**负相关**。

Spark 支持两种相关算法：Pearson 和 Spearman。Pearson 算法适用于两个连续变量，例如一个人的身高和体重或房屋大小和房价。Spearman 处理一个连续和一个分类变量，例如邮政编码和房价。

## 准备就绪

让我们使用一些真实数据，这样我们可以更有意义地计算相关性。以下是 2014 年初加利福尼亚州萨拉托加市房屋的大小和价格：

| 房屋面积（平方英尺） | 价格 |
| --- | --- |
| 2100 | $1,620,000 |
| 2300 | $1,690,000 |
| 2046 | $1,400,000 |
| 4314 | $2,000,000 |
| 1244 | $1,060,000 |
| 4608 | $3,830,000 |
| 2173 | $1,230,000 |
| 2750 | $2,400,000 |
| 4010 | $3,380,000 |
| 1959 | $1,480,000 |

## 如何做…

1.  启动 Spark shell：

```scala
$ spark-shell

```

1.  导入统计和相关类：

```scala
scala> import org.apache.spark.mllib.linalg._
scala> import org.apache.spark.mllib.stat.Statistics

```

1.  创建一个房屋面积的 RDD：

```scala
scala> val sizes = sc.parallelize(List(2100, 2300, 2046, 4314, 1244, 4608, 2173, 2750, 4010, 1959.0))

```

1.  创建一个房价的 RDD：

```scala
scala> val prices = sc.parallelize(List(1620000 , 1690000, 1400000, 2000000, 1060000, 3830000, 1230000, 2400000, 3380000, 1480000.00))

```

1.  计算相关性：

```scala
scala> val correlation = Statistics.corr(sizes,prices)
correlation: Double = 0.8577177736252577 

```

`0.85` 表示非常强的正相关性。

由于这里没有特定的算法，所以默认是 Pearson。`corr`方法被重载以将算法名称作为第三个参数。

1.  用 Pearson 计算相关性：

```scala
scala> val correlation = Statistics.corr(sizes,prices)

```

1.  用 Spearman 计算相关性：

```scala
scala> val correlation = Statistics.corr(sizes,prices,"spearman")

```

在前面的例子中，两个变量都是连续的，所以 Spearman 假设大小是离散的。Spearman 使用的更好的例子是邮政编码与价格。

# 进行假设检验

假设检验是确定给定假设为真的概率的一种方法。假设一个样本数据表明女性更倾向于投票给民主党。这可能对更大的人口来说是真的，也可能不是。如果这个模式只是样本数据中的偶然现象呢？

观察假设检验目标的另一种方式是回答这个问题：如果一个样本中有一个模式，那么这个模式存在的机会是多少？

我们怎么做？有一句话说，证明某事最好的方法是试图证伪它。

要证伪的假设被称为**零假设**。假设检验适用于分类数据。让我们看一个党派倾向的民意调查的例子。

| 党派 | 男性 | 女性 |
| --- | --- | --- |
| 民主党 | 32 | 41 |
| 共和党 | 28 | 25 |
| 独立 | 34 | 26 |

## 如何做…

1.  启动 Spark shell：

```scala
$ spark-shell

```

1.  导入相关的类：

```scala
scala> import org.apache.spark.mllib.stat.Statistics
scala> import org.apache.spark.mllib.linalg.{Vector,Vectors}
scala> import org.apache.spark.mllib.linalg.{Matrix, Matrices}

```

1.  为民主党创建一个向量：

```scala
scala> val dems = Vectors.dense(32.0,41.0)

```

1.  为共和党创建一个向量：

```scala
scala> val reps= Vectors.dense(28.0,25.0)

```

1.  为独立党创建一个向量：

```scala
scala> val indies = Vectors.dense(34.0,26.0)

```

1.  对观察数据进行卡方拟合度检验：

```scala
scala> val dfit = Statistics.chiSqTest(dems)
scala> val rfit = Statistics.chiSqTest(reps)
scala> val ifit = Statistics.chiSqTest(indies)

```

1.  打印拟合度检验结果：

```scala
scala> print(dfit)
scala> print(rfit)
scala> print(ifit)

```

1.  创建输入矩阵：

```scala
scala> val mat = Matrices.dense(2,3,Array(32.0,41.0, 28.0,25.0, 34.0,26.0))

```

1.  进行卡方独立性检验：

```scala
scala> val in = Statistics.chiSqTest(mat)

```

1.  打印独立性检验结果：

```scala
scala> print(in)

```

# 使用 ML 创建机器学习管道

Spark ML 是 Spark 中构建机器学习管道的新库。这个库正在与 MLlib 一起开发。它有助于将多个机器学习算法组合成一个单一的管道，并使用 DataFrame 作为数据集。

## 准备就绪

让我们首先了解一些 Spark ML 中的基本概念。它使用转换器将一个 DataFrame 转换为另一个 DataFrame。简单转换的一个例子可以是追加列。你可以把它看作是关系世界中的"alter table"的等价物。

另一方面，估计器代表一个机器学习算法，它从数据中学习。估计器的输入是一个 DataFrame，输出是一个转换器。每个估计器都有一个`fit()`方法，它的工作是训练算法。

机器学习管道被定义为一系列阶段；每个阶段可以是估计器或者转换器。

我们在这个示例中要使用的例子是某人是否是篮球运动员。为此，我们将有一个估计器和一个转换器的管道。

估计器获取训练数据来训练算法，然后转换器进行预测。

暂时假设`LogisticRegression`是我们正在使用的机器学习算法。我们将在随后的章节中解释`LogisticRegression`的细节以及其他算法。

## 如何做…

1.  启动 Spark shell：

```scala
$ spark-shell

```

1.  进行导入：

```scala
scala> import org.apache.spark.mllib.linalg.{Vector,Vectors}
scala> import org.apache.spark.mllib.regression.LabeledPoint
scala> import org.apache.spark.ml.classification.LogisticRegression

```

1.  为篮球运动员 Lebron 创建一个标记点，身高 80 英寸，体重 250 磅：

```scala
scala> val lebron = LabeledPoint(1.0,Vectors.dense(80.0,250.0))

```

1.  为不是篮球运动员的 Tim 创建一个标记点，身高 70 英寸，体重 150 磅：

```scala
scala> val tim = LabeledPoint(0.0,Vectors.dense(70.0,150.0))

```

1.  为篮球运动员 Brittany 创建一个标记点，身高 80 英寸，体重 207 磅：

```scala
scala> val brittany = LabeledPoint(1.0,Vectors.dense(80.0,207.0))

```

1.  为不是篮球运动员的 Stacey 创建一个标记点，身高 65 英寸，体重 120 磅：

```scala
scala> val stacey = LabeledPoint(0.0,Vectors.dense(65.0,120.0))

```

1.  创建一个训练 RDD：

```scala
scala> val trainingRDD = sc.parallelize(List(lebron,tim,brittany,stacey))

```

1.  创建一个训练 DataFrame：

```scala
scala> val trainingDF = trainingRDD.toDF

```

1.  创建一个`LogisticRegression`估计器：

```scala
scala> val estimator = new LogisticRegression

```

1.  通过拟合训练 DataFrame 来创建一个转换器：

```scala
scala> val transformer = estimator.fit(trainingDF)

```

1.  现在，让我们创建一个测试数据—John 身高 90 英寸，体重 270 磅，是篮球运动员：

```scala
scala> val john = Vectors.dense(90.0,270.0)

```

1.  创建另一个测试数据—Tom 身高 62 英寸，体重 150 磅，不是篮球运动员：

```scala
scala> val tom = Vectors.dense(62.0,120.0)

```

1.  创建一个训练 RDD：

```scala
scala> val testRDD = sc.parallelize(List(john,tom))

```

1.  创建一个`Features` case 类：

```scala
scala> case class Feature(v:Vector)

```

1.  将`testRDD`映射到`Features`的 RDD：

```scala
scala> val featuresRDD = testRDD.map( v => Feature(v))

```

1.  将`featuresRDD`转换为具有列名`"features"`的 DataFrame：

```scala
scala> val featuresDF = featuresRDD.toDF("features")

```

1.  通过向其添加`predictions`列来转换`featuresDF`：

```scala
scala> val predictionsDF = transformer.transform(featuresDF)

```

1.  打印`predictionsDF`：

```scala
scala> predictionsDF.foreach(println)

```

1.  `PredictionDF`，如您所见，除了保留特征之外，还创建了三列—`rawPrediction`、`probability`和`prediction`。让我们只选择`features`和`prediction`：

```scala
scala> val shorterPredictionsDF = predictionsDF.select("features","prediction")

```

1.  将预测重命名为`isBasketBallPlayer`：

```scala
scala> val playerDF = shorterPredictionsDF.toDF("features","isBasketBallPlayer")

```

1.  打印`playerDF`的模式：

```scala
scala> playerDF.printSchema

```
