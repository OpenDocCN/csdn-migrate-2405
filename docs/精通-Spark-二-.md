# 精通 Spark（二）

> 原文：[`zh.annas-archive.org/md5/5211DAC7494A736A2B4617944224CFC3`](https://zh.annas-archive.org/md5/5211DAC7494A736A2B4617944224CFC3)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：Apache Spark SQL

在本章中，我想检查 Apache Spark SQL，使用 Apache Hive 与 Spark 以及数据框。数据框在 Spark 1.3 中引入，是列式数据存储结构，大致相当于关系数据库表。本书的章节并非按顺序开发，因此早期章节可能使用比后期章节更旧的 Spark 版本。我还想检查 Spark SQL 的用户定义函数。关于 Spark 类 API 的信息，可以在以下位置找到：`spark.apache.org/docs/<version>/api/scala/index.html`。

我更喜欢使用 Scala，但 API 信息也可用于 Java 和 Python 格式。`<version>`值是指您将使用的 Spark 版本的发布版本-1.3.1。本章将涵盖以下主题：

+   SQL 上下文

+   导入和保存数据

+   数据框

+   使用 SQL

+   用户定义的函数

+   使用 Hive

在直接进入 SQL 和数据框之前，我将概述 SQL 上下文。

# SQL 上下文

SQL 上下文是在 Apache Spark 中处理列数据的起点。它是从 Spark 上下文创建的，并提供了加载和保存不同类型数据文件的方法，使用数据框，以及使用 SQL 操作列数据等功能。它可用于以下操作：

+   通过 SQL 方法执行 SQL

+   通过 UDF 方法注册用户定义的函数

+   缓存

+   配置

+   数据框

+   数据源访问

+   DDL 操作

我相信还有其他领域，但你明白我的意思。本章的示例是用 Scala 编写的，只是因为我更喜欢这种语言，但你也可以用 Python 和 Java 进行开发。如前所示，SQL 上下文是从 Spark 上下文创建的。隐式导入 SQL 上下文允许您将 RDD 隐式转换为数据框：

```scala
val sqlContext = new org.apache.spark.sql.SQLContext(sc)
import sqlContext.implicits._

```

例如，使用之前的`implicits`调用，允许您导入 CSV 文件并按分隔符字符拆分它。然后可以使用`toDF`方法将包含数据的 RDD 转换为数据框。

还可以为访问和操作 Apache Hive 数据库表数据定义 Hive 上下文（Hive 是 Hadoop 生态系统的一部分的 Apache 数据仓库，它使用 HDFS 进行存储）。与 Spark 上下文相比，Hive 上下文允许使用 SQL 功能的超集。在本章的后面部分将介绍如何在 Spark 中使用 Hive。

接下来，我将检查一些支持的文件格式，用于导入和保存数据。

# 导入和保存数据

我想在这里添加有关导入和保存数据的部分，即使它并不纯粹关于 Spark SQL，这样我就可以介绍诸如**Parquet**和**JSON**文件格式等概念。这一部分还让我能够涵盖如何在一个地方方便地访问和保存松散文本数据，以及 CSV、Parquet 和 JSON 格式。

## 处理文本文件

使用 Spark 上下文，可以使用`textFile`方法将文本文件加载到 RDD 中。此外，`wholeTextFile`方法可以将目录的内容读取到 RDD 中。以下示例显示了如何将基于本地文件系统（`file://`）或 HDFS（`hdfs://`）的文件读取到 Spark RDD 中。这些示例显示数据将被分成六个部分以提高性能。前两个示例相同，因为它们都操作 Linux 文件系统上的文件：

```scala
sc.textFile("/data/spark/tweets.txt",6)
sc.textFile("file:///data/spark/tweets.txt",6)
sc.textFile("hdfs://server1:4014/data/spark/tweets.txt",6)

```

## 处理 JSON 文件

JSON 是一种数据交换格式，由 Javascript 开发。**JSON**实际上代表**JavaScript** **Object** **Notation**。它是一种基于文本的格式，可以表示为 XML。以下示例使用名为`jsonFile`的 SQL 上下文方法加载基于 HDFS 的 JSON 数据文件，名称为`device.json`。生成的数据被创建为数据框：

```scala
val dframe = sqlContext.jsonFile("hdfs:///data/spark/device.json")

```

数据可以使用数据框`toJSON`方法以 JSON 格式保存，如下例所示。首先导入 Apache Spark 和 Spark SQL 类：

```scala
import org.apache.spark._
import org.apache.spark.SparkContext._
import org.apache.spark.sql.Row;
import org.apache.spark.sql.types.{StructType,StructField,StringType};

```

接下来，定义了一个名为`sql1`的对象类，以及一个带参数的主方法。定义了一个配置对象，用于创建一个 Spark 上下文。主 Spark URL 保留为默认值，因此 Spark 期望本地模式，本地主机和`7077`端口：

```scala
object sql1 {

 def main(args: Array[String]) {

 val appName = "sql example 1"
 val conf    = new SparkConf()

 conf.setAppName(appName)

 val sc = new SparkContext(conf)

```

从 Spark 上下文创建一个 SQL 上下文，并使用`textFile`方法加载 CSV 格式的原始文本文件`adult.test.data_1x`。然后创建一个包含数据列名称的模式字符串，并通过将字符串按其间距拆分，并使用`StructType`和`StructField`方法将每个模式列定义为字符串值：

```scala
 val sqlContext = new org.apache.spark.sql.SQLContext(sc)

 val rawRdd = sc.textFile("hdfs:///data/spark/sql/adult.test.data_1x")

 val schemaString = "age workclass fnlwgt education " +   "educational-num  marital-status occupation relationship " +
"race gender capital-gain capital-loss hours-per-week " +
"native-country income"

 val schema =
 StructType(
 schemaString.split(" ").map(fieldName => StructField(fieldName, StringType, true)))

```

然后，通过使用逗号作为行分隔符从原始 CSV 数据中创建每个数据行，然后将元素添加到`Row()`结构中。从模式创建数据框，然后将行数据转换为 JSON 格式，使用`toJSON`方法。最后，使用`saveAsTextFile`方法将数据保存到 HDFS：

```scala
 val rowRDD = rawRdd.map(_.split(","))
 .map(p => Row( p(0),p(1),p(2),p(3),p(4),p(5),p(6),p(7),p(8),
 p(9),p(10),p(11),p(12),p(13),p(14) ))

 val adultDataFrame = sqlContext.createDataFrame(rowRDD, schema)

 val jsonData = adultDataFrame.toJSON

 jsonData.saveAsTextFile("hdfs:///data/spark/sql/adult.json")

 } // end main

} // end sql1

```

因此，可以在 HDFS 上看到生成的数据，Hadoop 文件系统`ls`命令如下所示，数据驻留在`target`目录中作为成功文件和两个部分文件。

```scala
[hadoop@hc2nn sql]$ hdfs dfs -ls /data/spark/sql/adult.json

Found 3 items
-rw-r--r--   3 hadoop supergroup          0 2015-06-20 17:17 /data/spark/sql/adult.json/_SUCCESS
-rw-r--r--   3 hadoop supergroup       1731 2015-06-20 17:17 /data/spark/sql/adult.json/part-00000
-rw-r--r--   3 hadoop supergroup       1724 2015-06-20 17:17 /data/spark/sql/adult.json/part-00001

```

使用 Hadoop 文件系统的`cat`命令，可以显示 JSON 数据的内容。我将展示一个示例以节省空间：

```scala
[hadoop@hc2nn sql]$ hdfs dfs -cat /data/spark/sql/adult.json/part-00000 | more

{"age":"25","workclass":" Private","fnlwgt":" 226802","education":" 11th","educational-num":"
 7","marital-status":" Never-married","occupation":" Machine-op-inspct","relationship":" Own-
child","race":" Black","gender":" Male","capital-gain":" 0","capital-loss":" 0","hours-per-we
ek":" 40","native-country":" United-States","income":" <=50K"}

```

处理 Parquet 数据非常类似，接下来我将展示。

## 处理 Parquet 文件

Apache Parquet 是 Hadoop 工具集中许多工具使用的另一种基于列的数据格式，例如 Hive、Pig 和 Impala。它通过使用高效的压缩和编码例程来提高性能。

Parquet 处理示例与 JSON Scala 代码非常相似。创建数据框，然后使用 Parquet 类型的 save 方法以 Parquet 格式保存：

```scala
 val adultDataFrame = sqlContext.createDataFrame(rowRDD, schema)
 adultDataFrame.save("hdfs:///data/spark/sql/adult.parquet","parquet")

 } // end main

} // end sql2

```

这会生成一个基于 HDFS 的目录，其中包含三个基于 Parquet 的文件：一个常见的元数据文件，一个元数据文件和一个临时文件：

```scala
[hadoop@hc2nn sql]$ hdfs dfs -ls /data/spark/sql/adult.parquet
Found 3 items
-rw-r--r--   3 hadoop supergroup       1412 2015-06-21 13:17 /data/spark/sql/adult.parquet/_common_metadata
-rw-r--r--   3 hadoop supergroup       1412 2015-06-21 13:17 /data/spark/sql/adult.parquet/_metadata
drwxr-xr-x   - hadoop supergroup          0 2015-06-21 13:17 /data/spark/sql/adult.parquet/_temporary

```

使用 Hadoop 文件系统的`cat`命令列出元数据文件的内容，可以了解数据格式。但是 Parquet 头是二进制的，因此不能使用`more`和`cat`显示：

```scala
[hadoop@hc2nn sql]$ hdfs dfs -cat /data/spark/sql/adult.parquet/_metadata | more
s%
ct","fields":[{"name":"age","type":"string","nullable":true,"metadata":{}},{"name":"workclass
","type":"string","nullable":true,"metadata":{}},{"name":"fnlwgt","type":"string","nullable":
true,"metadata":{}},

```

有关可能的 Spark 和 SQL 上下文方法的更多信息，请检查名为`org.apache.spark.SparkContext`和`org.apache.spark.sql.SQLContext`的类的内容，使用 Apache Spark API 路径，以获取您感兴趣的 Spark 的特定`<version>`：

```scala
spark.apache.org/docs/<version>/api/scala/index.html

```

在下一节中，我将研究在 Spark 1.3 中引入的 Apache Spark DataFrames。

# 数据框

我已经提到 DataFrame 是基于列的格式。可以从中创建临时表，但我将在下一节中展开。数据框可用许多方法允许数据操作和处理。我基于上一节中使用的 Scala 代码，所以我只会展示工作行和输出。可以像这样显示数据框模式：

```scala
adultDataFrame.printSchema()

root
 |-- age: string (nullable = true)
 |-- workclass: string (nullable = true)
 |-- fnlwgt: string (nullable = true)
 |-- education: string (nullable = true)
 |-- educational-num: string (nullable = true)
 |-- marital-status: string (nullable = true)
 |-- occupation: string (nullable = true)
 |-- relationship: string (nullable = true)
 |-- race: string (nullable = true)
 |-- gender: string (nullable = true)
 |-- capital-gain: string (nullable = true)
 |-- capital-loss: string (nullable = true)
 |-- hours-per-week: string (nullable = true)
 |-- native-country: string (nullable = true)
 |-- income: string (nullable = true)

```

可以使用`select`方法从数据中过滤列。在这里，我在行数方面进行了限制，但你可以理解：

```scala
adultDataFrame.select("workclass","age","education","income").show()

workclass         age education     income
 Private          25   11th          <=50K
 Private          38   HS-grad       <=50K
 Local-gov        28   Assoc-acdm    >50K
 Private          44   Some-college  >50K
 none             18   Some-college  <=50K
 Private          34   10th          <=50K
 none             29   HS-grad       <=50K
 Self-emp-not-inc 63   Prof-school   >50K
 Private          24   Some-college  <=50K
 Private          55   7th-8th       <=50K

```

可以使用`filter`方法过滤从 DataFrame 返回的数据。在这里，我已经将职业列添加到输出中，并根据工人年龄进行了过滤：

```scala
 adultDataFrame
 .select("workclass","age","education","occupation","income")
 .filter( adultDataFrame("age") > 30 )
 .show()

workclass         age education     occupation         income
 Private          38   HS-grad       Farming-fishing    <=50K
 Private          44   Some-college  Machine-op-inspct  >50K
 Private          34   10th          Other-service      <=50K
 Self-emp-not-inc 63   Prof-school   Prof-specialty     >50K
 Private          55   7th-8th       Craft-repair       <=50K

```

还有一个`group by`方法用于确定数据集中的数量。由于这是一个基于收入的数据集，我认为工资范围内的数量会很有趣。我还使用了一个更大的数据集以获得更有意义的结果：

```scala
 adultDataFrame
 .groupBy("income")
 .count()
 .show()

income count
 <=50K 24720
 >50K  7841

```

这很有趣，但如果我想比较`income`档次和`occupation`，并对结果进行排序以更好地理解呢？以下示例显示了如何做到这一点，并给出了示例数据量。它显示与其他职业相比，管理角色的数量很大。此示例还通过职业列对输出进行了排序：

```scala
 adultDataFrame
 .groupBy("income","occupation")
 .count()
 .sort("occupation")
 .show()

income occupation         count
 >50K   Adm-clerical      507
 <=50K  Adm-clerical      3263
 <=50K  Armed-Forces      8
 >50K   Armed-Forces      1
 <=50K  Craft-repair      3170
 >50K   Craft-repair      929
 <=50K  Exec-managerial   2098
 >50K   Exec-managerial   1968
 <=50K  Farming-fishing   879
 >50K   Farming-fishing   115
 <=50K  Handlers-cleaners 1284
 >50K   Handlers-cleaners 86
 >50K   Machine-op-inspct 250
 <=50K  Machine-op-inspct 1752
 >50K   Other-service     137
 <=50K  Other-service     3158
 >50K   Priv-house-serv   1
 <=50K  Priv-house-serv   148
 >50K   Prof-specialty    1859
 <=50K  Prof-specialty    2281

```

因此，可以对数据框执行类似 SQL 的操作，包括`select`、`filter`、排序`group by`和`print`。下一节将展示如何从数据框创建表，以及如何对其执行基于 SQL 的操作。

# 使用 SQL

在使用先前的 Scala 示例从 HDFS 上的基于 CSV 的数据输入文件创建数据框后，我现在可以定义一个临时表，基于数据框，并对其运行 SQL。以下示例显示了临时表`adult`的定义，并使用`COUNT(*)`创建了行数：

```scala
 adultDataFrame.registerTempTable("adult")

 val resRDD = sqlContext.sql("SELECT COUNT(*) FROM adult")

 resRDD.map(t => "Count - " + t(0)).collect().foreach(println)

```

这给出了超过 32,000 行的行数：

```scala
Count – 32561

```

还可以使用`LIMIT` SQL 选项限制从表中选择的数据量，如下例所示。已从数据中选择了前 10 行，如果我只想检查数据类型和质量，这是有用的：

```scala
 val resRDD = sqlContext.sql("SELECT * FROM adult LIMIT 10")

 resRDD.map(t => t(0)  + " " + t(1)  + " " + t(2)  + " " + t(3)  + " " +
 t(4)  + " " + t(5)  + " " + t(6)  + " " + t(7)  + " " +
 t(8)  + " " + t(9)  + " " + t(10) + " " + t(11) + " " +
 t(12) + " " + t(13) + " " + t(14)
 )
 .collect().foreach(println)

```

数据的一个样本如下：

```scala
50  Private  283676  Some-college  10  Married-civ-spouse  Craft-repair  Husband  White  Male  0  0  40  United-States  >50K

```

当在上一节的基于 Scala 的数据框示例中创建此数据的模式时，所有列都被创建为字符串。但是，如果我想在 SQL 中使用`WHERE`子句过滤数据，那么拥有正确的数据类型将是有用的。例如，如果年龄列存储整数值，那么它应该存储为整数，以便我可以对其执行数值比较。我已经更改了我的 Scala 代码，以包括所有可能的类型：

```scala
import org.apache.spark.sql.types._

```

我现在也已经使用不同的类型定义了我的模式，以更好地匹配数据，并且已经根据实际数据类型定义了行数据，将原始数据字符串值转换为整数值：

```scala
 val schema =
 StructType(
 StructField("age",                IntegerType, false) ::
 StructField("workclass",          StringType,  false) ::
 StructField("fnlwgt",             IntegerType, false) ::
 StructField("education",          StringType,  false) ::
 StructField("educational-num",    IntegerType, false) ::
 StructField("marital-status",     StringType,  false) ::
 StructField("occupation",         StringType,  false) ::
 StructField("relationship",       StringType,  false) ::
 StructField("race",               StringType,  false) ::
 StructField("gender",             StringType,  false) ::
 StructField("capital-gain",       IntegerType, false) ::
 StructField("capital-loss",       IntegerType, false) ::
 StructField("hours-per-week",     IntegerType, false) ::
 StructField("native-country",     StringType,  false) ::
 StructField("income",             StringType,  false) ::
 Nil)

 val rowRDD = rawRdd.map(_.split(","))
 .map(p => Row( p(0).trim.toInt,p(1),p(2).trim.toInt,p(3),
 p(4).trim.toInt,p(5),p(6),p(7),p(8),
 p(9),p(10).trim.toInt,p(11).trim.toInt,
 p(12).trim.toInt,p(13),p(14) ))

```

SQL 现在可以正确地在`WHERE`子句中使用数值过滤器。如果`age`列是字符串，这将无法工作。现在您可以看到数据已被过滤以给出 60 岁以下的年龄值：

```scala
 val resRDD = sqlContext.sql("SELECT COUNT(*) FROM adult WHERE age < 60")
 resRDD.map(t => "Count - " + t(0)).collect().foreach(println)

```

这给出了大约 30,000 行的行数：

```scala
Count – 29917

```

可以在基于`WHERE`的过滤子句中使用布尔逻辑。以下示例指定了数据的年龄范围。请注意，我已经使用变量来描述 SQL 语句的`select`和`filter`组件。这使我能够将语句分解为不同的部分，因为它们变得更大：

```scala
 val selectClause = "SELECT COUNT(*) FROM adult "
 val filterClause = "WHERE age > 25 AND age < 60"
 val resRDD = sqlContext.sql( selectClause + filterClause )
 resRDD.map(t => "Count - " + t(0)).collect().foreach(println)

```

给出了约 23,000 行的数据计数：

```scala
Count – 23506

```

我可以使用布尔术语（如`AND`、`OR`）以及括号创建复合过滤子句：

```scala
 val selectClause = "SELECT COUNT(*) FROM adult "
 val filterClause =
 "WHERE ( age > 15 AND age < 25 ) OR ( age > 30 AND age < 45 ) "

 val resRDD = sqlContext.sql( selectClause + filterClause )
 resRDD.map(t => "Count - " + t(0)).collect().foreach(println)

```

这给我一个约 17,000 行的行数，并表示数据中两个年龄范围的计数：

```scala
Count – 17198

```

在 Apache Spark SQL 中也可以使用子查询。您可以在以下示例中看到，我通过从表`adult`中选择三列`age`、`education`和`occupation`来创建了一个名为`t1`的子查询。然后我使用名为`t1`的表创建了一个行数。我还在表`t1`的年龄列上添加了一个过滤子句。还要注意，我已经添加了`group by`和`order by`子句，尽管它们目前是空的，到我的 SQL 中：

```scala
 val selectClause = "SELECT COUNT(*) FROM "
 val tableClause = " ( SELECT age,education,occupation from adult) t1 "
 val filterClause = "WHERE ( t1.age > 25 ) "
 val groupClause = ""
 val orderClause = ""

 val resRDD = sqlContext.sql( selectClause + tableClause +
 filterClause +
 groupClause + orderClause
 )

 resRDD.map(t => "Count - " + t(0)).collect().foreach(println)

```

为了检查表连接，我创建了一个名为`adult.train.data2`的成人 CSV 数据文件的版本，它与原始文件的唯一区别是添加了一个名为`idx`的第一列，这是一个唯一索引。Hadoop 文件系统的`cat`命令在这里显示了数据的一个样本。使用 Linux 的`head`命令限制了文件的输出：

```scala
[hadoop@hc2nn sql]$ hdfs dfs -cat /data/spark/sql/adult.train.data2 | head -2

1,39, State-gov, 77516, Bachelors, 13, Never-married, Adm-clerical, Not-in-family, White, Male, 2174, 0, 40, United-States, <=50K
2,50, Self-emp-not-inc, 83311, Bachelors, 13, Married-civ-spouse, Exec-managerial, Husband, White, Male, 0, 0, 13, United-States, <=50K

```

模式现在已重新定义，具有整数类型的第一列`idx`作为索引，如下所示：

```scala
 val schema =
 StructType(
 StructField("idx",                IntegerType, false) ::
 StructField("age",                IntegerType, false) ::
 StructField("workclass",          StringType,  false) ::
 StructField("fnlwgt",             IntegerType, false) ::
 StructField("education",          StringType,  false) ::
 StructField("educational-num",    IntegerType, false) ::
 StructField("marital-status",     StringType,  false) ::
 StructField("occupation",         StringType,  false) ::
 StructField("relationship",       StringType,  false) ::
 StructField("race",               StringType,  false) ::
 StructField("gender",             StringType,  false) ::
 StructField("capital-gain",       IntegerType, false) ::
 StructField("capital-loss",       IntegerType, false) ::
 StructField("hours-per-week",     IntegerType, false) ::
 StructField("native-country",     StringType,  false) ::
 StructField("income",             StringType,  false) ::
 Nil)

```

在 Scala 示例中的原始行 RDD 现在处理了新的初始列，并将字符串值转换为整数：

```scala
 val rowRDD = rawRdd.map(_.split(","))
 .map(p => Row( p(0).trim.toInt,
 p(1).trim.toInt,
 p(2),
 p(3).trim.toInt,
 p(4),
 p(5).trim.toInt,
 p(6),
 p(7),
 p(8),
 p(9),
 p(10),
 p(11).trim.toInt,
 p(12).trim.toInt,
 p(13).trim.toInt,
 p(14),
 p(15)
 ))

 val adultDataFrame = sqlContext.createDataFrame(rowRDD, schema)

```

我们已经看过子查询。现在，我想考虑表连接。下一个示例将使用刚刚创建的索引。它使用它来连接两个派生表。这个示例有点牵强，因为它连接了来自相同基础表的两个数据集，但你明白我的意思。两个派生表被创建为子查询，并在一个公共索引列上连接。

现在，表连接的 SQL 如下。从临时表`adult`创建了两个派生表，分别称为`t1`和`t2`作为子查询。新的行索引列称为`idx`已被用来连接表`t1`和`t2`中的数据。主要的`SELECT`语句从复合数据集中输出所有七列。我添加了一个`LIMIT`子句来最小化数据输出：

```scala
 val selectClause = "SELECT t1.idx,age,education,occupation,workclass,race,gender FROM "
 val tableClause1 = " ( SELECT idx,age,education,occupation FROM adult) t1 JOIN "
 val tableClause2 = " ( SELECT idx,workclass,race,gender FROM adult) t2 "
 val joinClause = " ON (t1.idx=t2.idx) "
 val limitClause = " LIMIT 10"

 val resRDD = sqlContext.sql( selectClause +
 tableClause1 + tableClause2 +
 joinClause   + limitClause
 )

 resRDD.map(t => t(0) + " " + t(1) + " " + t(2) + " " +
 t(3) + " " + t(4) + " " + t(5) + " " + t(6)
 )
 .collect().foreach(println)

```

请注意，在主要的`SELECT`语句中，我必须定义索引列来自哪里，所以我使用了`t1.idx`。所有其他列都是唯一的`t1`和`t2`数据集，所以我不需要使用别名来引用它们（即`t1.age`）。因此，现在输出的数据如下：

```scala
33 45  Bachelors  Exec-managerial  Private  White  Male
233 25  Some-college  Adm-clerical  Private  White  Male
433 40  Bachelors  Prof-specialty  Self-emp-not-inc  White  Female
633 43  Some-college  Craft-repair  Private  White  Male
833 26  Some-college  Handlers-cleaners  Private  White  Male
1033 27  Some-college  Sales  Private  White  Male
1233 27  Bachelors  Adm-clerical  Private  White  Female
1433 32  Assoc-voc  Sales  Private  White  Male
1633 40  Assoc-acdm  Adm-clerical  State-gov  White  Male
1833 46  Some-college  Prof-specialty  Local-gov  White  Male

```

这给出了 Apache Spark 中基于 SQL 的功能的一些想法，但如果我发现需要的方法不可用怎么办？也许我需要一个新函数。这就是**用户定义的函数**（**UDFs**）有用的地方。我将在下一节中介绍它们。

# 用户定义的函数

为了在 Scala 中创建一些用户定义的函数，我需要检查之前的成年人数据集中的数据。我计划创建一个 UDF，用于枚举教育列，以便我可以将列转换为整数值。如果我需要将数据用于机器学习，并创建一个 LabelPoint 结构，这将非常有用。所使用的向量，代表每条记录，需要是数值型的。我将首先确定存在哪种唯一的教育值，然后创建一个函数来枚举它们，最后在 SQL 中使用它。

我已经创建了一些 Scala 代码来显示教育值的排序列表。`DISTINCT`关键字确保每个值只有一个实例。我已经选择数据作为子表，使用一个名为`edu_dist`的别名来确保`ORDER BY`子句起作用：

```scala
 val selectClause = "SELECT t1.edu_dist FROM "
 val tableClause  = " ( SELECT DISTINCT education AS edu_dist FROM adult ) t1 "
 val orderClause  = " ORDER BY t1.edu_dist "

 val resRDD = sqlContext.sql( selectClause + tableClause  + orderClause )

 resRDD.map(t => t(0)).collect().foreach(println)

```

数据如下。我已经删除了一些值以节省空间，但你明白我的意思：

```scala
 10th
 11th
 12th
 1st-4th
 ………..
 Preschool
 Prof-school
 Some-college

```

我在 Scala 中定义了一个方法，接受基于字符串的教育值，并返回代表它的枚举整数值。如果没有识别到值，则返回一个名为`9999`的特殊值：

```scala
 def enumEdu( education:String ) : Int =
 {
 var enumval = 9999

 if ( education == "10th" )         { enumval = 0 }
 else if ( education == "11th" )         { enumval = 1 }
 else if ( education == "12th" )         { enumval = 2 }
 else if ( education == "1st-4th" )      { enumval = 3 }
 else if ( education == "5th-6th" )      { enumval = 4 }
 else if ( education == "7th-8th" )      { enumval = 5 }
 else if ( education == "9th" )          { enumval = 6 }
 else if ( education == "Assoc-acdm" )   { enumval = 7 }
 else if ( education == "Assoc-voc" )    { enumval = 8 }
 else if ( education == "Bachelors" )    { enumval = 9 }
 else if ( education == "Doctorate" )    { enumval = 10 }
 else if ( education == "HS-grad" )      { enumval = 11 }
 else if ( education == "Masters" )      { enumval = 12 }
 else if ( education == "Preschool" )    { enumval = 13 }
 else if ( education == "Prof-school" )  { enumval = 14 }
 else if ( education == "Some-college" ) { enumval = 15 }

 return enumval
 }

```

现在，我可以使用 Scala 中的 SQL 上下文注册此函数，以便在 SQL 语句中使用：

```scala
 sqlContext.udf.register( "enumEdu", enumEdu _ )

```

然后，SQL 和 Scala 代码用于枚举数据如下。新注册的名为`enumEdu`的函数在`SELECT`语句中使用。它以教育类型作为参数，并返回整数枚举。此值形成的列被别名为`idx`：

```scala
 val selectClause = "SELECT enumEdu(t1.edu_dist) as idx,t1.edu_dist FROM "
 val tableClause  = " ( SELECT DISTINCT education AS edu_dist FROM adult ) t1 "
 val orderClause  = " ORDER BY t1.edu_dist "

 val resRDD = sqlContext.sql( selectClause + tableClause  + orderClause )

 resRDD.map(t => t(0) + " " + t(1) ).collect().foreach(println)

```

结果数据输出，作为教育值及其枚举的列表，如下所示：

```scala
0  10th
1  11th
2  12th
3  1st-4th
4  5th-6th
5  7th-8th
6  9th
7  Assoc-acdm
8  Assoc-voc
9  Bachelors
10  Doctorate
11  HS-grad
12  Masters
13  Preschool
14  Prof-school
15  Some-college

```

另一个示例函数名为`ageBracket`，它接受成年人的整数年龄值，并返回一个枚举的年龄段：

```scala
 def ageBracket( age:Int ) : Int =
 {
 var bracket = 9999

 if ( age >= 0  && age < 20  ) { bracket = 0 }
 else if ( age >= 20 && age < 40  ) { bracket = 1 }
 else if ( age >= 40 && age < 60  ) { bracket = 2 }
 else if ( age >= 60 && age < 80  ) { bracket = 3 }
 else if ( age >= 80 && age < 100 ) { bracket = 4 }
 else if ( age > 100 )              { bracket = 5 }

 return bracket
 }

```

再次，使用 SQL 上下文注册函数，以便在 SQL 语句中使用：

```scala
 sqlContext.udf.register( "ageBracket", ageBracket _ )

```

然后，基于 Scala 的 SQL 使用它从成年人数据集中选择年龄、年龄段和教育值：

```scala
 val selectClause = "SELECT age, ageBracket(age) as bracket,education FROM "
 val tableClause  = " adult "
 val limitClause  = " LIMIT 10 "

 val resRDD = sqlContext.sql( selectClause + tableClause  +
 limitClause )

 resRDD.map(t => t(0) + " " + t(1) + " " + t(2) ).collect().foreach(println)

```

然后，由于我使用了`LIMIT`子句将输出限制为 10 行，因此生成的数据如下：

```scala
39 1  Bachelors
50 2  Bachelors
38 1  HS-grad
53 2  11th
28 1  Bachelors
37 1  Masters
49 2  9th
52 2  HS-grad
31 1  Masters
42 2  Bachelors

```

还可以在 SQL 中定义函数，通过 SQL 上下文在 UDF 注册期间内联使用。以下示例定义了一个名为`dblAge`的函数，它只是将成年人的年龄乘以二。注册如下。它接受整数参数（`age`），并返回两倍的值：

```scala
 sqlContext.udf.register( "dblAge", (a:Int) => 2*a )

```

并且使用它的 SQL 现在选择`age`和`age`值的两倍，称为`dblAge(age)`：

```scala
 val selectClause = "SELECT age,dblAge(age) FROM "
 val tableClause  = " adult "
 val limitClause  = " LIMIT 10 "

 val resRDD = sqlContext.sql( selectClause + tableClause  + limitClause )

 resRDD.map(t => t(0) + " " + t(1) ).collect().foreach(println)

```

现在，输出数据的两列包含年龄及其加倍值，看起来是这样的：

```scala
39 78
50 100
38 76
53 106
28 56
37 74
49 98
52 104
31 62
42 84

```

到目前为止，已经检查了 DataFrame、SQL 和用户定义函数，但是如果像我一样使用 Hadoop 堆栈集群，并且有 Apache Hive 可用，会怎么样呢？到目前为止我定义的`adult`表是一个临时表，但是如果我使用 Apache Spark SQL 访问 Hive，我可以访问静态数据库表。下一节将检查执行此操作所需的步骤。

# 使用 Hive

如果您有低延迟要求和多用户的商业智能类型工作负载，那么您可能考虑使用 Impala 来访问数据库。Apache Spark 在 Hive 上用于批处理和 ETL 链。本节将用于展示如何连接 Spark 到 Hive，以及如何使用此配置。首先，我将开发一个使用本地 Hive 元数据存储的应用程序，并展示它不会在 Hive 本身存储和持久化表数据。然后，我将设置 Apache Spark 连接到 Hive 元数据服务器，并在 Hive 中存储表和数据。我将从本地元数据服务器开始。

## 本地 Hive 元数据服务器

以下示例 Scala 代码显示了如何使用 Apache Spark 创建 Hive 上下文，并创建基于 Hive 的表。首先导入了 Spark 配置、上下文、SQL 和 Hive 类。然后，定义了一个名为`hive_ex1`的对象类和主方法。定义了应用程序名称，并创建了一个 Spark 配置对象。然后从配置对象创建了 Spark 上下文：

```scala
import org.apache.spark.{SparkConf, SparkContext}
import org.apache.spark.sql._
import org.apache.spark.sql.hive.HiveContext

object hive_ex1 {

 def main(args: Array[String]) {

 val appName = "Hive Spark Ex 1"
 val conf    = new SparkConf()

 conf.setAppName(appName)

 val sc = new SparkContext(conf)

```

接下来，我从 Spark 上下文中创建一个新的 Hive 上下文，并导入 Hive implicits 和 Hive 上下文 SQL。`implicits`允许进行隐式转换，而 SQL 包含允许我运行基于 Hive 上下文的 SQL：

```scala
 val hiveContext = new HiveContext(sc)

 import hiveContext.implicits._
 import hiveContext.sql

```

下一个语句在 Hive 中创建了一个名为`adult2`的空表。您将会在本章中已经使用过的 adult 数据中识别出模式：

```scala
 hiveContext.sql( " 
 CREATE TABLE IF NOT EXISTS adult2
 (
 idx             INT,
 age             INT,
 workclass       STRING,
 fnlwgt          INT,
 education       STRING,
 educationnum    INT,
 maritalstatus   STRING,
 occupation      STRING,
 relationship    STRING,
 race            STRING,
 gender          STRING,
 capitalgain     INT,
 capitalloss     INT,
 nativecountry   STRING,
 income          STRING
 )

 ")

```

接下来，通过`COUNT(*)`从名为`adult2`的表中获取行计数，并打印输出值：

```scala
 val resRDD = hiveContext.sql("SELECT COUNT(*) FROM adult2")

 resRDD.map(t => "Count : " + t(0) ).collect().foreach(println)

```

如预期的那样，表中没有行。

```scala
Count : 0

```

在 Apache Spark Hive 中也可以创建基于 Hive 的外部表。以下的 HDFS 文件列表显示了名为`adult.train.data2`的 CSV 文件存在于名为`/data/spark/hive`的 HDFS 目录中，并且包含数据：

```scala
[hadoop@hc2nn hive]$ hdfs dfs -ls /data/spark/hive
Found 1 items
-rw-r--r--   3 hadoop supergroup    4171350 2015-06-24 15:18 /data/spark/hive/adult.train.data2

```

现在，我调整我的基于 Scala 的 Hive SQL 以创建一个名为`adult3`的外部表（如果不存在），该表与先前表具有相同的结构。在此表创建语句中的行格式指定逗号作为行列分隔符，这是 CSV 数据所期望的。此语句中的位置选项指定了 HDFS 上的`/data/spark/hive`目录作为数据的位置。因此，在此位置上可以有多个文件在 HDFS 上，用于填充此表。每个文件都需要具有与此表结构匹配的相同数据结构：

```scala
 hiveContext.sql("

 CREATE EXTERNAL TABLE IF NOT EXISTS adult3
 (
 idx             INT,
 age             INT,
 workclass       STRING,
 fnlwgt          INT,
 education       STRING,
 educationnum    INT,
 maritalstatus   STRING,
 occupation      STRING,
 relationship    STRING,
 race            STRING,
 gender          STRING,
 capitalgain     INT,
 capitalloss     INT,
 nativecountry   STRING,
 income          STRING
 )
 ROW FORMAT DELIMITED FIELDS TERMINATED BY ','
 LOCATION '/data/spark/hive'

 ")

```

然后对`adult3`表进行行计数，并打印计数结果：

```scala
 val resRDD = hiveContext.sql("SELECT COUNT(*) FROM adult3")

 resRDD.map(t => "Count : " + t(0) ).collect().foreach(println)

```

如您所见，表现在包含大约 32,000 行。由于这是一个外部表，基于 HDFS 的数据并没有被移动，行计算是从底层基于 CSV 的数据中推导出来的。

```scala
Count : 32561

```

我意识到我想要从外部的`adult3`表中剥离维度数据。毕竟，Hive 是一个数据仓库，因此在使用基于原始 CSV 数据的一般 ETL 链的一部分时，会从数据中剥离维度和对象，并创建新的表。如果考虑教育维度，并尝试确定存在哪些唯一值，那么例如，SQL 将如下所示：

```scala
 val resRDD = hiveContext.sql("

 SELECT DISTINCT education AS edu FROM adult3
 ORDER BY edu

 ")

 resRDD.map(t => t(0) ).collect().foreach(println)

```

有序数据与本章早期使用 Spark SQL 推导出的值匹配：

```scala
 10th
 11th
 12th
 1st-4th
 5th-6th
 7th-8th
 9th
 Assoc-acdm
 Assoc-voc
 Bachelors
 Doctorate
 HS-grad
 Masters
 Preschool
 Prof-school
 Some-college

```

这很有用，但如果我想创建维度值，然后为以前的教育维度值分配整数索引值怎么办。例如，`10th`将是`0`，`11th`将是`1`。我已经在 HDFS 上为教育维度设置了一个维度 CSV 文件，如下所示。内容只包含唯一值的列表和一个索引：

```scala
[hadoop@hc2nn hive]$ hdfs dfs -ls /data/spark/dim1/
Found 1 items
-rw-r--r--   3 hadoop supergroup        174 2015-06-25 14:08 /data/spark/dim1/education.csv
[hadoop@hc2nn hive]$ hdfs dfs -cat /data/spark/dim1/education.csv
1,10th
2,11th
3,12th

```

现在，我可以在我的 Apache 应用程序中运行一些 Hive QL 来创建一个教育维度表。首先，如果教育表已经存在，我会删除它，然后通过解析 HDFS CSV 文件来创建表：

```scala
 hiveContext.sql("  DROP TABLE IF EXISTS education ")
 hiveContext.sql("

 CREATE TABLE IF NOT EXISTS  education
 (
 idx        INT,
 name       STRING
 )
 ROW FORMAT DELIMITED FIELDS TERMINATED BY ','
 LOCATION '/data/spark/dim1/'
 ")

```

然后我可以选择新的教育表的内容，以确保它看起来是正确的。

```scala
val resRDD = hiveContext.sql(" SELECT * FROM education ")
resRDD.map( t => t(0)+" "+t(1) ).collect().foreach(println)

```

这给出了预期的索引列表和教育维度值：

```scala
1 10th
2 11th
3 12th
………
16 Some-college

```

因此，我已经开始了 ETL 管道的开端。原始 CSV 数据被用作外部表，然后创建了维度表，然后可以用来将原始数据中的维度转换为数字索引。我现在已经成功创建了一个 Spark 应用程序，它使用 Hive 上下文连接到 Hive Metastore 服务器，这使我能够创建和填充表。

我在我的 Linux 服务器上安装了 Hadoop 堆栈 Cloudera CDH 5.3。我正在写这本书时使用它来访问 HDFS，并且我还安装并运行了 Hive 和 Hue（CDH 安装信息可以在 Cloudera 网站[`cloudera.com/content/cloudera/en/documentation.html`](http://cloudera.com/content/cloudera/en/documentation.html)找到）。当我检查 HDFS 中的`adult3`表时，它应该已经创建在`/user/hive/warehouse`下，我看到了以下内容：

```scala
[hadoop@hc2nn hive]$ hdfs dfs -ls /user/hive/warehouse/adult3
ls: `/user/hive/warehouse/adult3': No such file or directory

```

基于 Hive 的表并不存在于 Hive 的预期位置。我可以通过检查 Hue Metastore 管理器来确认这一点，以查看默认数据库中存在哪些表。以下图表显示了我的默认数据库目前是空的。我已经添加了红线，以表明我目前正在查看默认数据库，并且没有数据。显然，当我运行基于 Apache Spark 的应用程序时，使用 Hive 上下文，我是连接到 Hive Metastore 服务器的。我知道这是因为日志表明了这一点，而且以这种方式创建的表在重新启动 Apache Spark 时会持久存在。

![本地 Hive Metastore 服务器](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_04_01.jpg)

刚刚运行的应用程序中的 Hive 上下文已经使用了本地 Hive Metastore 服务器，并将数据存储在本地位置；实际上，在这种情况下是在 HDFS 上的`/tmp`下。我现在想要使用基于 Hive 的 Metastore 服务器，这样我就可以直接在 Hive 中创建表和数据。接下来的部分将展示如何实现这一点。

## 基于 Hive 的 Metastore 服务器

我已经提到我正在使用 Cloudera 的 CDH 5.3 Hadoop 堆栈。我正在运行 Hive、HDFS、Hue 和 Zookeeper。我正在使用安装在`/usr/local/spark`下的 Apache Spark 1.3.1，以便创建和运行应用程序（我知道 CDH 5.3 发布了 Spark 1.2，但我想在这种情况下使用 Spark 1.3.x 中可用的 DataFrames）。

配置 Apache Spark 连接到 Hive 的第一件事是将名为`hive-site.xml`的 Hive 配置文件放入所有安装了 Spark 的服务器上的 Spark 配置目录中：

```scala
[hadoop@hc2nn bin]# cp /var/run/cloudera-scm-agent/process/1237-hive-HIVEMETASTORE/hive-site.xml /usr/local/spark/conf

```

然后，鉴于我已经通过 CDH Manager 安装了 Apache Hive 以便使用 PostgreSQL，我需要为 Spark 安装一个 PostgreSQL 连接器 JAR，否则它将不知道如何连接到 Hive，并且会出现类似这样的错误：

```scala
15/06/25 16:32:24 WARN DataNucleus.Connection: BoneCP specified but not present in CLASSPATH (s)
Caused by: java.lang.RuntimeException: Unable to instantiate org.apache.hadoop.hive.metastore.
Caused by: java.lang.reflect.InvocationTargetException
Caused by: javax.jdo.JDOFatalInternalException: Error creating transactional connection factor
Caused by: org.datanucleus.exceptions.NucleusException: Attempt to invoke the "dbcp-builtin" pnectionPool gave an 
error : The specified datastore driver ("org.postgresql.Driver") was not f. Please check your CLASSPATH
specification, and the name of the driver.
Caused by: org.datanucleus.store.rdbms.connectionpool.DatastoreDriverNotFoundException: The spver
("org.postgresql.Driver") was not found in the CLASSPATH. Please check your CLASSPATH specme of the driver.

```

我已经将错误消息简化为只包含相关部分，否则它将非常长。我已经确定了我安装的 PostgreSQL 的版本，如下所示。从 Cloudera 基于包的 jar 文件中确定为 9.0 版本：

```scala
[root@hc2nn jars]# pwd ; ls postgresql*
/opt/cloudera/parcels/CDH/jars
postgresql-9.0-801.jdbc4.jar

```

接下来，我使用[`jdbc.postgresql.org/`](https://jdbc.postgresql.org/)网站下载必要的 PostgreSQL 连接器库。我已确定我的 Java 版本为 1.7，如下所示，这会影响要使用的库的版本：

```scala
[hadoop@hc2nn spark]$ java -version
java version "1.7.0_75"
OpenJDK Runtime Environment (rhel-2.5.4.0.el6_6-x86_64 u75-b13)
OpenJDK 64-Bit Server VM (build 24.75-b04, mixed mode)

```

该网站表示，如果您使用的是 Java 1.7 或 1.8，则应该使用该库的 JDBC41 版本。因此，我已经获取了`postgresql-9.4-1201.jdbc41.jar`文件。下一步是将此文件复制到 Apache Spark 安装的`lib`目录中，如下所示：

```scala
[hadoop@hc2nn lib]$ pwd ; ls -l postgresql*
/usr/local/spark/lib
-rw-r--r-- 1 hadoop hadoop 648487 Jun 26 13:20 postgresql-9.4-1201.jdbc41.jar

```

现在，必须将 PostgreSQL 库添加到 Spark 的`CLASSPATH`中，方法是在 Spark 的`bin`目录中的名为`compute-classpath.sh`的文件中添加一个条目，如下所示：

```scala
[hadoop@hc2nn bin]$ pwd ; tail compute-classpath.sh
/usr/local/spark/bin

# add postgresql connector to classpath
appendToClasspath "${assembly_folder}"/postgresql-9.4-1201.jdbc41.jar

echo "$CLASSPATH"

```

在我的情况下，我遇到了有关 CDH 5.3 Hive 和 Apache Spark 之间的 Hive 版本错误，如下所示。我认为版本如此接近，以至于我应该能够忽略这个错误：

```scala
Caused by: MetaException(message:Hive Schema version 0.13.1aa does not match metastore's schema version 0.13.0

Metastore is not upgraded or corrupt)

```

在这种情况下，我决定在我的 Spark 版本的`hive-site.xml`文件中关闭模式验证。这必须在该文件的所有基于 Spark 的实例中完成，然后重新启动 Spark。更改如下所示；值设置为`false`：

```scala
 <property>
 <name>hive.metastore.schema.verification</name>
 <value>false</value>
 </property>

```

现在，当我运行与上一节相同的基于应用程序的 SQL 集时，我可以在 Apache Hive 默认数据库中创建对象。首先，我将使用基于 Spark 的 Hive 上下文创建名为`adult2`的空表：

```scala
 hiveContext.sql( "

 CREATE TABLE IF NOT EXISTS adult2
 (
 idx             INT,
 age             INT,
 workclass       STRING,
 fnlwgt          INT,
 education       STRING,
 educationnum    INT,
 maritalstatus   STRING,
 occupation      STRING,
 relationship    STRING,
 race            STRING,
 gender          STRING,
 capitalgain     INT,
 capitalloss     INT,
 nativecountry   STRING,
 income          STRING
 )

 ")

```

如您所见，当我运行应用程序并检查 Hue 元数据浏览器时，表`adult2`现在已经存在：

![基于 Hive 的元数据服务器](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_04_02.jpg)

我之前展示了表条目，并通过选择称为`adult2`的表条目在 Hue 默认数据库浏览器中获得了其结构：

![基于 Hive 的元数据服务器](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_04_03.jpg)

现在，可以执行基于 Spark 的 Hive QL 的外部表`adult3`，并从 Hue 确认数据访问。在最后一节中，必要的 Hive QL 如下：

```scala
 hiveContext.sql("

 CREATE EXTERNAL TABLE IF NOT EXISTS adult3
 (
 idx             INT,
 age             INT,
 workclass       STRING,
 fnlwgt          INT,
 education       STRING,
 educationnum    INT,
 maritalstatus   STRING,
 occupation      STRING,
 relationship    STRING,
 race            STRING,
 gender          STRING,
 capitalgain     INT,
 capitalloss     INT,
 nativecountry   STRING,
 income          STRING
 )
 ROW FORMAT DELIMITED FIELDS TERMINATED BY ','
 LOCATION '/data/spark/hive'

 ")

```

现在您可以看到，基于 Hive 的名为`adult3`的表已经由 Spark 创建在默认数据库中。下图再次生成自 Hue 元数据浏览器：

![基于 Hive 的元数据服务器](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_04_04.jpg)

以下 Hive QL 已从 Hue Hive 查询编辑器执行。它显示`adult3`表可以从 Hive 访问。我限制了行数以使图像可呈现。我不担心数据，只关心我能否访问它：

![基于 Hive 的元数据服务器](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_04_05.jpg)

我将在本节中提到的最后一件事对于在 Spark 中使用 Hive QL 对 Hive 进行操作将非常有用，那就是用户定义的函数或 UDF。例如，我将考虑`row_sequence`函数，该函数在以下基于 Scala 的代码中使用：

```scala
hiveContext.sql("

ADD JAR /opt/cloudera/parcels/CDH-5.3.3-1.cdh5.3.3.p0.5/jars/hive-contrib-0.13.1-cdh5.3.3.jar

 ")

hiveContext.sql("

CREATE TEMPORARY FUNCTION row_sequence as 'org.apache.hadoop.hive.contrib.udf.UDFRowSequence';

 ")

 val resRDD = hiveContext.sql("

 SELECT row_sequence(),t1.edu FROM
 ( SELECT DISTINCT education AS edu FROM adult3 ) t1
 ORDER BY t1.edu

 ")

```

通过`ADD JAR`命令可以将现有的或您自己的基于 JAR 的库添加到 Spark Hive 会话中。然后，可以使用基于包的类名将该库中的功能注册为临时函数，并在 Hive QL 语句中将新函数名称合并。

本章已成功将基于 Apache Spark 的应用程序连接到 Hive，并对 Hive 运行 Hive QL，以便表和数据更改在 Hive 中持久存在。但为什么这很重要呢？嗯，Spark 是一种内存并行处理系统。它的处理速度比基于 Hadoop 的 Map Reduce 快一个数量级。Apache Spark 现在可以作为处理引擎使用，而 Hive 数据仓库可以用于存储。快速的基于内存的 Spark 处理速度与 Hive 中可用的大数据规模结构化数据仓库存储相结合。

# 总结

本章开始时解释了 Spark SQL 上下文和文件 I/O 方法。然后展示了可以操作基于 Spark 和 HDFS 的数据，既可以使用类似 SQL 的方法和 DataFrames，也可以通过注册临时表和 Spark SQL。接下来，介绍了用户定义的函数，以展示 Spark SQL 的功能可以通过创建新函数来扩展以满足您的需求，将它们注册为 UDF，然后在 SQL 中调用它们来处理数据。

最后，Hive 上下文被引入用于在 Apache Spark 中使用。请记住，Spark 中的 Hive 上下文提供了 SQL 上下文功能的超集。我知道随着时间的推移，SQL 上下文将被扩展以匹配 Hive 上下文的功能。在 Spark 中使用 Hive 上下文进行 Hive QL 数据处理时，使用了本地 Hive 和基于 Hive 的 Metastore 服务器。我认为后者的配置更好，因为表被创建，数据更改会持久保存在您的 Hive 实例中。

在我的案例中，我使用的是 Cloudera CDH 5.3，其中使用了 Hive 0.13、PostgreSQL、ZooKeeper 和 Hue。我还使用了 Apache Spark 版本 1.3.1。我向您展示的配置设置纯粹是针对这个配置的。如果您想使用 MySQL，例如，您需要研究必要的更改。一个好的起点可能是`<user@spark.apache.org>`邮件列表。

最后，我想说 Apache Spark Hive 上下文配置，使用基于 Hive 的存储，非常有用。它允许您将 Hive 用作大数据规模的数据仓库，使用 Apache Spark 进行快速的内存处理。它不仅提供了使用基于 Spark 的模块（MLlib、SQL、GraphX 和 Stream）操纵数据的能力，还提供了使用其他基于 Hadoop 的工具，使得创建 ETL 链更加容易。

下一章将研究 Spark 图处理模块 GraphX，还将调查 Neo4J 图数据库和 MazeRunner 应用程序。


# 第五章：Apache Spark GraphX

在本章中，我想要研究 Apache Spark GraphX 模块和图处理。我还想简要介绍一下图数据库 Neo4j。因此，本章将涵盖以下主题：

+   GraphX 编码

+   Neo4j 的 Mazerunner

GraphX 编码部分使用 Scala 编写，将提供一系列图编码示例。Kenny Bastani 在实验性产品 Mazerunner 上的工作，我也将进行审查，将这两个主题结合在一个实际示例中。它提供了一个基于 Docker 的示例原型，用于在 Apache Spark GraphX 和 Neo4j 存储之间复制数据。

在 Scala 中编写代码使用 Spark GraphX 模块之前，我认为提供一个关于图处理实际上是什么的概述会很有用。下一节将使用一些简单的图示例进行简要介绍。

# 概览

图可以被视为一种数据结构，它由一组顶点和连接它们的边组成。图中的顶点或节点可以是对象，也可以是人，而边缘则是它们之间的关系。边缘可以是有方向的，意味着关系是从一个节点到下一个节点的。例如，节点 A 是节点 B 的父亲。

在下面的图表中，圆圈代表顶点或节点（**A**到**D**），而粗线代表边缘或它们之间的关系（**E1**到**E6**）。每个节点或边缘可能具有属性，这些值由相关的灰色方块（**P1**到**P7**）表示。

因此，如果一个图代表了寻路的实际路线图，那么边缘可能代表次要道路或高速公路。节点将是高速公路交叉口或道路交叉口。节点和边缘的属性可能是道路类型、速度限制、距离、成本和网格位置。

有许多类型的图实现，但一些例子包括欺诈建模、金融货币交易建模、社交建模（如 Facebook 上的朋友关系）、地图处理、网络处理和页面排名。

![概览](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_05_01.jpg)

前面的图表显示了一个带有相关属性的图的通用示例。它还显示了边缘关系可以是有方向的，也就是说，**E2**边缘是从节点**B**到节点**C**的。然而，下面的例子使用了家庭成员及其之间的关系来创建一个图。请注意，两个节点或顶点之间可以有多条边。例如，**Mike**和**Sarah**之间的夫妻关系。此外，一个节点或边上可能有多个属性。

![概览](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_05_02.jpg)

因此，在前面的例子中，**Sister**属性是从节点 6 **Flo**到节点 1 **Mike**的。这些都是简单的图，用来解释图的结构和元素性质。真实的图应用可能会达到极大的规模，并且需要分布式处理和存储来使它们能够被操作。Facebook 能够处理包含超过 1 万亿边的图，使用**Apache Giraph**（来源：Avery Ching-Facebook）。Giraph 是用于图处理的 Apache Hadoop 生态系统工具，它在历史上基于 Map Reduce 进行处理，但现在使用 TinkerPop，这将在第六章中介绍，*基于图的存储*。尽管本书集中讨论 Apache Spark，但边的数量提供了一个非常令人印象深刻的指标，显示了图可以达到的规模。

在下一节中，我将使用 Scala 来研究 Apache Spark GraphX 模块的使用。

# GraphX 编码

本节将使用上一节中展示的家庭关系图数据样本，使用 Scala 中的 Apache Spark GraphX 编程来进行分析。这些数据将存储在 HDFS 上，并将作为顶点和边的列表进行访问。尽管这个数据集很小，但是用这种方式构建的图可能非常大。我使用 HDFS 进行存储，因为如果你的图扩展到大数据规模，那么你将需要某种类型的分布式和冗余存储。正如本章所示的例子，这可能是 HDFS。使用 Apache Spark SQL 模块，存储也可以是 Apache Hive；详情请参见第四章，“Apache Spark SQL”。

## 环境

我使用了服务器`hc2nn`上的 hadoop Linux 账户来开发基于 Scala 的 GraphX 代码。SBT 编译的结构遵循与之前示例相同的模式，代码树存在于名为`graphx`的子目录中，其中有一个名为`graph.sbt`的 SBT 配置文件：

```scala
[hadoop@hc2nn graphx]$ pwd
/home/hadoop/spark/graphx

[hadoop@hc2nn graphx]$ ls
 src   graph.sbt          project     target

```

源代码如预期的那样位于此级别的子树下，名为`src/main/scala`，包含五个代码示例：

```scala
[hadoop@hc2nn scala]$ pwd
/home/hadoop/spark/graphx/src/main/scala

[hadoop@hc2nn scala]$ ls
graph1.scala  graph2.scala  graph3.scala  graph4.scala  graph5.scala

```

在每个基于图的示例中，Scala 文件使用相同的代码从 HDFS 加载数据，并创建图；但是，每个文件提供了基于 GraphX 的图处理的不同方面。由于本章使用了不同的 Spark 模块，`sbt`配置文件`graph.sbt`已经更改以支持这项工作：

```scala
[hadoop@hc2nn graphx]$ more graph.sbt

name := "Graph X"

version := "1.0"

scalaVersion := "2.10.4"

libraryDependencies += "org.apache.hadoop" % "hadoop-client" % "2.3.0"

libraryDependencies += "org.apache.spark" %% "spark-core"  % "1.0.0"

libraryDependencies += "org.apache.spark" %% "spark-graphx" % "1.0.0"

// If using CDH, also add Cloudera repo
resolvers += "Cloudera Repository" at https://repository.cloudera.com/artifactory/cloudera-repos/

```

`graph.sbt`文件的内容如前所示，通过 Linux 的`more`命令。这里只有两个变化需要注意——名称的值已更改以表示内容。更重要的是，Spark GraphX 1.0.0 库已添加为库依赖项。

两个数据文件已放置在 HDFS 的`/data/spark/graphx/`目录下。它们包含将用于本节的顶点和边的数据。如 Hadoop 文件系统的`ls`命令所示，文件名分别为`graph1_edges.cvs`和`graph1_vertex.csv`：

```scala
[hadoop@hc2nn scala]$ hdfs dfs -ls /data/spark/graphx
Found 2 items
-rw-r--r--   3 hadoop supergroup        129 2015-03-01 13:52 /data/spark/graphx/graph1_edges.csv
-rw-r--r--   3 hadoop supergroup         59 2015-03-01 13:52 /data/spark/graphx/graph1_vertex.csv

```

下面显示的“顶点”文件，通过 Hadoop 文件系统的`cat`命令，只包含六行，表示上一节中使用的图。每个顶点代表一个人，具有顶点 ID 号、姓名和年龄值：

```scala
[hadoop@hc2nn scala]$ hdfs dfs -cat /data/spark/graphx/graph1_vertex.csv
1,Mike,48
2,Sarah,45
3,John,25
4,Jim,53
5,Kate,22
6,Flo,52

```

边文件包含一组有向边值，形式为源顶点 ID、目标顶点 ID 和关系。因此，记录一形成了`Flo`和`Mike`之间的姐妹关系：

```scala
[hadoop@hc2nn scala]$  hdfs dfs -cat /data/spark/graphx/graph1_edges.csv
6,1,Sister
1,2,Husband
2,1,Wife
5,1,Daughter
5,2,Daughter
3,1,Son
3,2,Son
4,1,Friend
1,5,Father
1,3,Father
2,5,Mother
2,3,Mother

```

在解释了 sbt 环境和基于 HDFS 的数据之后，我们现在准备检查一些 GraphX 代码示例。与之前的示例一样，代码可以从`graphx`子目录编译和打包。这将创建一个名为`graph-x_2.10-1.0.jar`的 JAR 文件，从中可以运行示例应用程序：

```scala
[hadoop@hc2nn graphx]$ pwd
/home/hadoop/spark/graphx

[hadoop@hc2nn graphx]$  sbt package

Loading /usr/share/sbt/bin/sbt-launch-lib.bash
[info] Set current project to Graph X (in build file:/home/hadoop/spark/graphx/)
[info] Compiling 5 Scala sources to /home/hadoop/spark/graphx/target/scala-2.10/classes...
[info] Packaging /home/hadoop/spark/graphx/target/scala-2.10/graph-x_2.10-1.0.jar ...
[info] Done packaging.
[success] Total time: 30 s, completed Mar 3, 2015 5:27:10 PM

```

## 创建图

本节将解释通用的 Scala 代码，直到从基于 HDFS 的数据创建 GraphX 图为止。这将节省时间，因为相同的代码在每个示例中都被重用。一旦这一点得到解释，我将集中在每个代码示例中的实际基于图的操作上。

通用代码从导入 Spark 上下文、graphx 和 RDD 功能开始，以便在 Scala 代码中使用：

```scala
import org.apache.spark.SparkContext
import org.apache.spark.SparkContext._
import org.apache.spark.SparkConf

import org.apache.spark.graphx._
import org.apache.spark.rdd.RDD
```

然后，定义一个应用程序，它扩展了`App`类，并且每个示例的应用程序名称从`graph1`更改为`graph5`。在使用`spark-submit`运行应用程序时将使用此应用程序名称：

```scala
object graph1 extends App
{
```

数据文件是根据 HDFS 服务器和端口、它们在 HDFS 下的路径和它们的文件名来定义的。如前所述，有两个包含“顶点”和“边”信息的数据文件：

```scala
  val hdfsServer = "hdfs://hc2nn.semtech-solutions.co.nz:8020"
  val hdfsPath   = "/data/spark/graphx/"
  val vertexFile = hdfsServer + hdfsPath + "graph1_vertex.csv"
  val edgeFile   = hdfsServer + hdfsPath + "graph1_edges.csv"
```

定义了 Spark Master URL，以及应用程序名称，当应用程序运行时将出现在 Spark 用户界面中。创建了一个新的 Spark 配置对象，并将 URL 和名称分配给它：

```scala
  val sparkMaster = "spark://hc2nn.semtech-solutions.co.nz:7077"
  val appName = "Graph 1"
  val conf = new SparkConf()
  conf.setMaster(sparkMaster)
  conf.setAppName(appName)
```

使用刚刚定义的配置创建了一个新的 Spark 上下文：

```scala
  val sparkCxt = new SparkContext(conf)
```

基于 HDFS 文件的顶点信息然后使用`sparkCxt.textFile`方法加载到名为`vertices`的基于 RDD 的结构中。数据存储为长整型`VertexId`和字符串表示人的姓名和年龄。数据行按逗号拆分，因为这是基于 CSV 的数据：

```scala
  val vertices: RDD[(VertexId, (String, String))] =
      sparkCxt.textFile(vertexFile).map { line =>
        val fields = line.split(",")
        ( fields(0).toLong, ( fields(1), fields(2) ) )
  }
```

同样，基于 HDFS 的边缘数据加载到名为`edges`的基于 RDD 的数据结构中。基于 CSV 的数据再次按逗号值拆分。前两个数据值转换为长整型值，因为它们代表源和目标顶点 ID。表示边关系的最终值保留为字符串。请注意，RDD 结构 edges 中的每个记录现在实际上是一个`Edge`记录：

```scala
  val edges: RDD[Edge[String]] =
      sparkCxt.textFile(edgeFile).map { line =>
        val fields = line.split(",")
        Edge(fields(0).toLong, fields(1).toLong, fields(2))
  }
```

在连接或顶点缺失的情况下定义了一个默认值，然后从基于 RDD 的结构`vertices`、`edges`和`default`记录构建图：

```scala
  val default = ("Unknown", "Missing")
  val graph = Graph(vertices, edges, default)
```

这创建了一个名为`graph`的基于 GraphX 的结构，现在可以用于每个示例。请记住，尽管这些数据样本很小，但您可以使用这种方法创建非常大的图形。许多这些算法都是迭代应用，例如 PageRank 和 Triangle Count，因此程序将生成许多迭代的 Spark 作业。

## 示例 1 - 计数

图已加载，我们知道数据文件中的数据量，但是实际图中的顶点和边的数据内容如何？通过使用顶点和边计数函数，可以很容易地提取这些信息，如下所示：

```scala
  println( "vertices : " + graph.vertices.count )
  println( "edges    : " + graph.edges.count )
```

使用先前创建的示例名称和 JAR 文件运行`graph1`示例将提供计数信息。提供主 URL 以连接到 Spark 集群，并为执行器内存和总执行器核心提供一些默认参数：

```scala
spark-submit \
  --class graph1 \
  --master spark://hc2nn.semtech-solutions.co.nz:7077  \
  --executor-memory 700M \
  --total-executor-cores 100 \
 /home/hadoop/spark/graphx/target/scala-2.10/graph-x_2.10-1.0.jar
```

名为`graph1`的 Spark 集群作业提供了以下输出，这是预期的，也与数据文件匹配：

```scala
vertices : 6
edges    : 12

```

## 示例 2 - 过滤

如果我们需要从主图创建一个子图，并按照人的年龄或关系进行筛选，会发生什么？第二个示例 Scala 文件`graph2`中的示例代码显示了如何做到这一点：

```scala
  val c1 = graph.vertices.filter { case (id, (name, age)) => age.toLong > 40 }.count

  val c2 = graph.edges.filter { case Edge(from, to, property)
    => property == "Father" | property == "Mother" }.count

  println( "Vertices count : " + c1 )
  println( "Edges    count : " + c2 )
```

两个示例计数是从主图创建的。第一个筛选基于年龄的顶点，只取那些年龄大于 40 岁的人。请注意，存储为字符串的“年龄”值已转换为长整型进行比较。前面的第二个示例筛选了“母亲”或“父亲”的关系属性的边。创建了两个计数值：`c1`和`c2`，并按照 Spark 输出显示在这里打印出来：

```scala
Vertices count : 4
Edges    count : 4

```

## 示例 3 - PageRank

PageRank 算法为图中的每个顶点提供了一个排名值。它假设连接到最多边的顶点是最重要的。搜索引擎使用 PageRank 为网页搜索期间的页面显示提供排序：

```scala
  val tolerance = 0.0001
  val ranking = graph.pageRank(tolerance).vertices
  val rankByPerson = vertices.join(ranking).map {
    case (id, ( (person,age) , rank )) => (rank, id, person)
  }
```

前面的示例代码创建了一个`tolerance`值，并使用它调用了图的`pageRank`方法。然后将顶点排名为一个新值排名。为了使排名更有意义，排名值与原始顶点 RDD 连接。然后，`rankByPerson`值包含排名、顶点 ID 和人的姓名。

PageRank 结果存储在`rankByPerson`中，然后使用 case 语句逐条打印记录内容，并使用格式语句打印内容。我这样做是因为我想定义排名值的格式可能会有所不同：

```scala
  rankByPerson.collect().foreach {
    case (rank, id, person) =>
      println ( f"Rank $rank%1.2f id $id person $person")
  }
```

应用程序的输出如下所示。预期的是，`Mike`和`Sarah`具有最高的排名，因为他们有最多的关系：

```scala
Rank 0.15 id 4 person Jim
Rank 0.15 id 6 person Flo
Rank 1.62 id 2 person Sarah
Rank 1.82 id 1 person Mike
Rank 1.13 id 3 person John
Rank 1.13 id 5 person Kate

```

## 示例 4 - 三角形计数

三角形计数算法提供了与该顶点相关的三角形数量的基于顶点的计数。例如，顶点`Mike`（1）连接到`Kate`（5），后者连接到`Sarah`（2）；`Sarah`连接到`Mike`（1），因此形成了一个三角形。这对于路由查找可能很有用，需要为路由规划生成最小的无三角形的生成树图。

执行三角形计数并打印的代码很简单，如下所示。对图顶点执行`triangleCount`方法。结果保存在值`tCount`中，然后打印出来：

```scala
  val tCount = graph.triangleCount().vertices
  println( tCount.collect().mkString("\n") )
```

应用作业的结果显示，称为`Flo`（4）和`Jim`（6）的顶点没有三角形，而`Mike`（1）和`Sarah`（2）有最多的三角形，正如预期的那样，因为它们有最多的关系：

```scala
(4,0)
(6,0)
(2,4)
(1,4)
(3,2)
(5,2)

```

## 示例 5 - 连通组件

当从数据创建一个大图时，它可能包含未连接的子图，也就是说，彼此隔离并且之间没有桥接或连接边的子图。该算法提供了这种连接性的度量。根据您的处理方式，知道所有顶点是否连接可能很重要。

对于这个示例的 Scala 代码调用了两个图方法：`connectedComponents`和`stronglyConnectedComponents`。强方法需要一个最大迭代计数，已设置为`1000`。这些计数作用于图的顶点：

```scala
  val iterations = 1000
  val connected  = graph.connectedComponents().vertices
  val connectedS = graph.stronglyConnectedComponents(iterations).vertices
```

然后将顶点计数与原始顶点记录连接起来，以便将连接计数与顶点信息（例如人的姓名）关联起来。

```scala
  val connByPerson = vertices.join(connected).map {
    case (id, ( (person,age) , conn )) => (conn, id, person)
  }

  val connByPersonS = vertices.join(connectedS).map {
    case (id, ( (person,age) , conn )) => (conn, id, person)
  }
The results are then output using a case statement, and formatted printing:
  connByPerson.collect().foreach {
    case (conn, id, person) =>
      println ( f"Weak $conn  $id $person" )
  }
```

如`connectedComponents`算法所预期的那样，结果显示每个顶点只有一个组件。这意味着所有顶点都是单个图的成员，就像本章前面显示的图表一样：

```scala
Weak 1  4 Jim
Weak 1  6 Flo
Weak 1  2 Sarah
Weak 1  1 Mike
Weak 1  3 John
Weak 1  5 Kate

```

`stronglyConnectedComponents`方法提供了图中连接性的度量，考虑了它们之间关系的方向。`stronglyConnectedComponents`算法的结果如下：

```scala
  connByPersonS.collect().foreach {
    case (conn, id, person) =>
      println ( f"Strong $conn  $id $person" )
  }
```

您可能会注意到从图中，关系`Sister`和`Friend`是从顶点`Flo`（6）和`Jim`（4）到`Mike`（1）的边和顶点数据如下所示：

```scala
6,1,Sister
4,1,Friend

1,Mike,48
4,Jim,53
6,Flo,52

```

因此，强方法的输出显示，对于大多数顶点，第二列中的`1`表示只有一个图组件。然而，由于它们关系的方向，顶点`4`和`6`是不可达的，因此它们有一个顶点 ID 而不是组件 ID：

```scala
Strong 4  4 Jim
Strong 6  6 Flo
Strong 1  2 Sarah
Strong 1  1 Mike
Strong 1  3 John
Strong 1  5 Kate

```

# Neo4j 的 Mazerunner

在前面的部分中，您已经学会了如何在 Scala 中编写 Apache Spark graphx 代码来处理基于 HDFS 的图形数据。您已经能够执行基于图形的算法，例如 PageRank 和三角形计数。然而，这种方法有一个限制。Spark 没有存储功能，并且将基于图形的数据存储在 HDFS 上的平面文件中不允许您在其存储位置对其进行操作。例如，如果您的数据存储在关系数据库中，您可以使用 SQL 在原地对其进行查询。Neo4j 等数据库是图数据库。这意味着它们的存储机制和数据访问语言作用于图形。在本节中，我想看一下 Kenny Bastani 创建的 Mazerunner，它是一个 GraphX Neo4j 处理原型。

以下图描述了 Mazerunner 架构。它显示了 Neo4j 中的数据被导出到 HDFS，并通过通知过程由 GraphX 处理。然后将 GraphX 数据更新保存回 HDFS 作为键值更新列表。然后将这些更改传播到 Neo4j 进行存储。此原型架构中的算法可以通过基于 Rest 的 HTTP URL 访问，稍后将显示。这里的重点是，算法可以通过 graphx 中的处理运行，但数据更改可以通过 Neo4j 数据库 cypher 语言查询进行检查。Kenny 的工作和更多细节可以在以下网址找到：[`www.kennybastani.com/2014/11/using-apache-spark-and-neo4j-for-big.html`](http://www.kennybastani.com/2014/11/using-apache-spark-and-neo4j-for-big.html)。

本节将专门解释 Mazerunner 架构，并将通过示例展示如何使用。该架构提供了一个基于 GraphX 处理的独特示例，结合了基于图的存储。

![Neo4j 的 Mazerunner](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_05_03.jpg)

## 安装 Docker

安装 Mazerunner 示例代码的过程在[`github.com/kbastani/neo4j-mazerunner`](https://github.com/kbastani/neo4j-mazerunner)中有描述。

我使用了 64 位 Linux Centos 6.5 机器`hc1r1m1`进行安装。Mazerunner 示例使用 Docker 工具，在此示例中创建了运行 HDFS、Neo4j 和 Mazerunner 的虚拟容器，占用空间很小。首先，我必须安装 Docker。我已经使用 Linux root 用户通过`yum`命令完成了这一点。第一条命令安装了`docker-io`模块（docker 名称已经被另一个应用程序用于 CentOS 6.5）：

```scala
[root@hc1r1m1 bin]# yum -y install docker-io

```

我需要启用`public_ol6_latest`存储库，并安装`device-mapper-event-libs`包，因为我发现我当前安装的 lib-device-mapper 没有导出 Docker 需要的 Base 符号。我以`root`身份执行了以下命令：

```scala
[root@hc1r1m1 ~]# yum-config-manager --enable public_ol6_latest
[root@hc1r1m1 ~]# yum install device-mapper-event-libs

```

我遇到的实际错误如下：

```scala
/usr/bin/docker: relocation error: /usr/bin/docker: symbol dm_task_get_info_with_deferred_remove, version Base not defined in file libdevmapper.so.1.02 with link time reference

```

然后我可以通过以下调用检查 Docker 的版本号，以确保 Docker 可以运行：

```scala
[root@hc1r1m1 ~]# docker version
Client version: 1.4.1
Client API version: 1.16
Go version (client): go1.3.3
Git commit (client): 5bc2ff8/1.4.1
OS/Arch (client): linux/amd64
Server version: 1.4.1
Server API version: 1.16
Go version (server): go1.3.3
Git commit (server): 5bc2ff8/1.4.1

```

我可以使用以下服务命令启动 Linux docker 服务。我还可以使用以下`chkconfig`命令强制 Docker 在 Linux 服务器启动时启动：

```scala
[root@hc1r1m1 bin]# service docker start
[root@hc1r1m1 bin]# chkconfig docker on

```

然后可以下载三个 Docker 镜像（HDFS，Mazerunner 和 Neo4j）。它们很大，所以可能需要一些时间：

```scala
[root@hc1r1m1 ~]# docker pull sequenceiq/hadoop-docker:2.4.1
Status: Downloaded newer image for sequenceiq/hadoop-docker:2.4.1

[root@hc1r1m1 ~]# docker pull kbastani/docker-neo4j:latest
Status: Downloaded newer image for kbastani/docker-neo4j:latest

[root@hc1r1m1 ~]# docker pull kbastani/neo4j-graph-analytics:latest
Status: Downloaded newer image for kbastani/neo4j-graph-analytics:latest

```

下载完成后，Docker 容器可以按顺序启动；HDFS，Mazerunner，然后 Neo4j。将加载默认的 Neo4j 电影数据库，并使用这些数据运行 Mazerunner 算法。HDFS 容器的启动如下：

```scala
[root@hc1r1m1 ~]# docker run -i -t --name hdfs sequenceiq/hadoop-docker:2.4.1 /etc/bootstrap.sh –bash

Starting sshd:                                [  OK  ]
Starting namenodes on [26d939395e84]
26d939395e84: starting namenode, logging to /usr/local/hadoop/logs/hadoop-root-namenode-26d939395e84.out
localhost: starting datanode, logging to /usr/local/hadoop/logs/hadoop-root-datanode-26d939395e84.out
Starting secondary namenodes [0.0.0.0]
0.0.0.0: starting secondarynamenode, logging to /usr/local/hadoop/logs/hadoop-root-secondarynamenode-26d939395e84.out
starting yarn daemons
starting resourcemanager, logging to /usr/local/hadoop/logs/yarn--resourcemanager-26d939395e84.out
localhost: starting nodemanager, logging to /usr/local/hadoop/logs/yarn-root-nodemanager-26d939395e84.out

```

Mazerunner 服务容器的启动如下：

```scala
[root@hc1r1m1 ~]# docker run -i -t --name mazerunner --link hdfs:hdfs kbastani/neo4j-graph-analytics

```

输出很长，所以我不会在这里全部包含，但你不会看到任何错误。还有一行，说明安装正在等待消息：

```scala
[*] Waiting for messages. To exit press CTRL+C

```

为了启动 Neo4j 容器，我需要安装程序为我创建一个新的 Neo4j 数据库，因为这是第一次安装。否则在重新启动时，我只需提供数据库目录的路径。使用`link`命令，Neo4j 容器链接到 HDFS 和 Mazerunner 容器：

```scala
[root@hc1r1m1 ~]# docker run -d -P -v /home/hadoop/neo4j/data:/opt/data --name graphdb --link mazerunner:mazerunner --link hdfs:hdfs kbastani/docker-neo4j

```

通过检查`neo4j/data`路径，我现在可以看到已经创建了一个名为`graph.db`的数据库目录：

```scala
[root@hc1r1m1 data]# pwd
/home/hadoop/neo4j/data

[root@hc1r1m1 data]# ls
graph.db

```

然后我可以使用以下`docker inspect`命令，该命令提供了基于容器的 IP 地址和 Docker 基础的 Neo4j 容器。`inspect`命令提供了我需要访问 Neo4j 容器的本地 IP 地址。`curl`命令连同端口号（我从 Kenny 的网站上知道）默认为`7474`，显示 Rest 接口正在运行：

```scala
[root@hc1r1m1 data]# docker inspect --format="{{.NetworkSettings.IPAddress}}" graphdb
172.17.0.5

[root@hc1r1m1 data]# curl  172.17.0.5:7474
{
 "management" : "http://172.17.0.5:7474/db/manage/",
 "data" : "http://172.17.0.5:7474/db/data/"
}

```

## Neo4j 浏览器

本节中的其余工作现在将使用 Neo4j 浏览器 URL 进行，如下所示：

`http://172.17.0.5:7474/browser`。

这是一个基于本地 Docker 的 IP 地址，将可以从`hc1r1m1`服务器访问。如果没有进一步的网络配置，它将不会在本地局域网的其他地方可见。

这将显示默认的 Neo4j 浏览器页面。可以通过点击这里的电影链接，选择 Cypher 查询并执行来安装电影图。

![Neo4j 浏览器](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_05_04.jpg)

然后可以使用 Cypher 查询来查询数据，这将在下一章中更深入地探讨。以下图表与它们相关的 Cypher 查询一起提供，以显示数据可以作为可视化显示的图形进行访问。第一个图表显示了一个简单的人到电影关系，关系细节显示在连接的边上。

![Neo4j 浏览器](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_05_05.jpg)

第二个图表作为 Neo4j 强大性能的视觉示例，展示了一个更复杂的 Cypher 查询和生成的图表。该图表表示包含 135 个节点和 180 个关系。在处理方面，这些数字相对较小，但很明显图表变得复杂。

![Neo4j 浏览器](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_05_06.jpg)

以下图表展示了通过 HTTP Rest URL 调用 Mazerunner 示例算法。调用由要调用的算法和它将在图中操作的属性定义：

`http://localhost:7474/service/mazerunner/analysis/{algorithm}/{attribute}`。

例如，如下一节将展示的，可以使用通用 URL 来运行 PageRank 算法，设置`algorithm=pagerank`。该算法将通过设置`attribute=FOLLOWS`来操作`follows`关系。下一节将展示如何运行每个 Mazerunner 算法以及 Cypher 输出的示例。

## Mazerunner 算法

本节展示了如何使用上一节中显示的基于 Rest 的 HTTP URL 运行 Mazerunner 示例算法。这一章中已经检查并编码了许多这些算法。请记住，本节中发生的有趣事情是数据从 Neo4j 开始，经过 Spark 和 GraphX 处理，然后更新回 Neo4j。看起来很简单，但是有底层的过程在进行所有的工作。在每个示例中，通过 Cypher 查询来询问算法已经添加到图中的属性。因此，每个示例不是关于查询，而是数据更新到 Neo4j 已经发生。

### PageRank 算法

第一个调用显示了 PageRank 算法和 PageRank 属性被添加到电影图中。与以前一样，PageRank 算法根据顶点的边连接数量给出一个排名。在这种情况下，它使用`FOLLOWS`关系进行处理。

![PageRank 算法](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_05_07.jpg)

以下图像显示了 PageRank 算法结果的截图。图像顶部的文本（以`MATCH`开头）显示了 Cypher 查询，证明了 PageRank 属性已被添加到图中。

![PageRank 算法](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_05_08.jpg)

### 接近度中心性算法

接近度算法试图确定图中最重要的顶点。在这种情况下，`closeness`属性已被添加到图中。

![接近度中心性算法](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_05_09.jpg)

以下图像显示了接近度算法结果的截图。图像顶部的文本（以`MATCH`开头）显示了 Cypher 查询，证明了`closeness_centrality`属性已被添加到图中。请注意，此 Cypher 查询中使用了一个名为`closeness`的别名，表示`closeness_centrality`属性，因此输出更具可读性。

![接近度中心性算法](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_05_10.jpg)

### 三角形计数算法

`triangle_count`算法已被用于计算与顶点相关的三角形数量。使用了`FOLLOWS`关系，并且`triangle_count`属性已被添加到图中。

![三角形计数算法](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_05_11.jpg)

以下图片显示了三角形算法结果的屏幕截图。图像顶部的文本（以`MATCH`开头）显示了 Cypher 查询，证明了`triangle_count`属性已被添加到图中。请注意，在此 Cypher 查询中使用了一个名为**tcount**的别名，表示`triangle_count`属性，因此输出更加可呈现。

![三角形计数算法](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_05_12.jpg)

### 连接组件算法

连接组件算法是衡量图形数据中存在多少实际组件的一种方法。例如，数据可能包含两个子图，它们之间没有路径。在这种情况下，`connected_components`属性已被添加到图中。

![连接组件算法](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_05_13.jpg)

以下图片显示了连接组件算法结果的屏幕截图。图像顶部的文本（以`MATCH`开头）显示了 Cypher 查询，证明了`connected_components`属性已被添加到图中。请注意，在此 Cypher 查询中使用了一个名为**ccomp**的别名，表示`connected_components`属性，因此输出更加可呈现。

![连接组件算法](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_05_14.jpg)

### 强连接组件算法

强连接组件算法与连接组件算法非常相似。使用方向性的`FOLLOWS`关系从图形数据创建子图。创建多个子图，直到使用所有图形组件。这些子图形成了强连接组件。如此所见，`strongly_connected_components`属性已被添加到图中：

![强连接组件算法](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_05_15.jpg)

以下图片显示了强连接组件算法结果的屏幕截图。图像顶部的文本（以`MATCH`开头）显示了 Cypher 查询，证明了`strongly_connected_components`连接组件属性已被添加到图中。请注意，在此 Cypher 查询中使用了一个名为**sccomp**的别名，表示`strongly_connected_components`属性，因此输出更加可呈现。

![强连接组件算法](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_05_16.jpg)

# 总结

本章已经通过示例展示了如何使用基于 Scala 的代码调用 Apache Spark 中的 GraphX 算法。之所以使用 Scala，是因为开发示例所需的代码更少，节省时间。可以使用基于 Scala 的 shell，并且可以将代码编译成 Spark 应用程序。本章提供了使用 SBT 工具进行应用程序编译和配置的示例。本章的配置和代码示例也将随书提供下载。

最后，介绍了 Mazerunner 示例架构（由 Kenny Bastani 在 Neo 期间开发）用于 Neo4j 和 Apache Spark。为什么 Mazerunner 很重要？它提供了一个示例，说明了图形数据库可以用于图形存储，而 Apache Spark 用于图形处理。我并不是建议目前在生产场景中使用 Mazerunner。显然，还需要做更多工作，使这种架构准备好发布。然而，与分布式环境中的基于图形处理相关联的基于图形存储，提供了使用 Neo4j 的 Cypher 等查询语言来查询数据的选项。

希望你觉得这一章很有用。下一章将更深入地探讨基于图的存储。你现在可以深入了解更多 GraphX 编码，尝试运行提供的示例，并尝试修改代码，以便熟悉开发过程。


# 第六章：基于图形的存储

使用 Apache Spark 和特别是 GraphX 进行处理提供了使用基于内存的集群的实时图形处理的能力。然而，Apache Spark 并不提供存储；基于图形的数据必须来自某个地方，并且在处理之后，可能会需要存储。在本章中，我将以 Titan 图形数据库为例，研究基于图形的存储。本章将涵盖以下主题：

+   Titan 概述

+   TinkerPop 概述

+   安装 Titan

+   使用 HBase 与 Titan

+   使用 Cassandra 的 Titan

+   使用 Spark 与 Titan

这个处理领域的年轻意味着 Apache Spark 和基于图形的存储系统 Titan 之间的存储集成还不够成熟。

在上一章中，我们研究了 Neo4j Mazerunner 架构，展示了基于 Spark 的事务如何被复制到 Neo4j。本章讨论 Titan 并不是因为它今天展示的功能，而是因为它与 Apache Spark 一起在图形存储领域所提供的未来前景。

# Titan

Titan 是由 Aurelius（[`thinkaurelius.com/`](http://thinkaurelius.com/)）开发的图形数据库。应用程序源代码和二进制文件可以从 GitHub（[`thinkaurelius.github.io/titan/`](http://thinkaurelius.github.io/titan/)）下载，该位置还包含 Titan 文档。Titan 已经作为 Apache 2 许可证的开源应用程序发布。在撰写本书时，Aurelius 已被 DataStax 收购，尽管 Titan 的发布应该会继续。

Titan 提供了许多存储选项，但我只会集中在两个上面，即 HBase——Hadoop NoSQL 数据库和 Cassandra——非 Hadoop NoSQL 数据库。使用这些底层存储机制，Titan 能够在大数据范围内提供基于图形的存储。

基于 TinkerPop3 的 Titan 0.9.0-M2 版本于 2015 年 6 月发布，这将使其与 Apache Spark 更好地集成（TinkerPop 将在下一节中解释）。我将在本章中使用这个版本。Titan 现在使用 TinkerPop 进行图形操作。这个 Titan 版本是一个实验性的开发版本，但希望未来的版本能够巩固 Titan 的功能。

本章集中讨论 Titan 数据库而不是其他图形数据库，比如 Neo4j，因为 Titan 可以使用基于 Hadoop 的存储。此外，Titan 在与 Apache Spark 集成方面提供了未来的前景，用于大数据规模的内存图形处理。下图显示了本章讨论的架构。虚线表示直接 Spark 数据库访问，而实线表示 Spark 通过 Titan 类访问数据。

![Titan](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_06_01.jpg)

Spark 接口目前还没有正式存在（只在 M2 开发版本中可用），但这只是为了参考而添加的。尽管 Titan 提供了使用 Oracle 进行存储的选项，但本章不会涉及。我将首先研究 Titan 与 HBase 和 Cassandra 的架构，然后考虑 Apache Spark 的集成。在考虑（分布式）HBase 时，还需要 ZooKeeper 进行集成。鉴于我正在使用现有的 CDH5 集群，HBase 和 ZooKeeper 已经安装好。

# TinkerPop

TinkerPop，截至 2015 年 7 月目前版本为 3，是一个 Apache 孵化器项目，可以在[`tinkerpop.incubator.apache.org/`](http://tinkerpop.incubator.apache.org/)找到。它使得图形数据库（如 Titan）和图形分析系统（如 Giraph）可以将其作为图形处理的子系统使用，而不是创建自己的图形处理模块。

![TinkerPop](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_06_02.jpg)

前面的图表（从 TinkerPop 网站借来）显示了 TinkerPop 架构。蓝色层显示了核心 TinkerPop API，为图、顶点和边处理提供了图处理 API。**供应商 API**框显示了供应商将实现以整合其系统的 API。图表显示有两种可能的 API：一种用于**OLTP**数据库系统，另一种用于**OLAP**分析系统。

图表还显示，**Gremlin**语言用于为 TinkerPop 和 Titan 创建和管理图。最后，Gremlin 服务器位于架构的顶部，并允许集成到像 Ganglia 这样的监控系统。

# 安装 Titan

由于本章需要使用 Titan，我现在将安装它，并展示如何获取、安装和配置它。我已经下载了最新的预构建版本（0.9.0-M2）的 Titan：[s3.thinkaurelius.com/downloads/titan/titan-0.9.0-M2-hadoop1.zip](http://s3.thinkaurelius.com/downloads/titan/titan-0.9.0-M2-hadoop1.zip)。

我已将压缩版本下载到临时目录，如下所示。执行以下步骤，确保 Titan 在集群中的每个节点上都安装了：

```scala
[[hadoop@hc2nn tmp]$ ls -lh titan-0.9.0-M2-hadoop1.zip
-rw-r--r-- 1 hadoop hadoop 153M Jul 22 15:13 titan-0.9.0-M2-hadoop1.zip

```

使用 Linux 的解压命令，解压缩压缩的 Titan 发行文件：

```scala
[hadoop@hc2nn tmp]$ unzip titan-0.9.0-M2-hadoop1.zip

[hadoop@hc2nn tmp]$ ls -l
total 155752
drwxr-xr-x 10 hadoop hadoop      4096 Jun  9 00:56 titan-0.9.0-M2-hadoop1
-rw-r--r--  1 hadoop hadoop 159482381 Jul 22 15:13 titan-0.9.0-M2-hadoop1.zip

```

现在，使用 Linux 的`su`（切换用户）命令切换到`root`账户，并将安装移到`/usr/local/`位置。更改安装文件和组成员身份为`hadoop`用户，并创建一个名为`titan`的符号链接，以便将当前的 Titan 版本简化为路径`/usr/local/titan`：

```scala
[hadoop@hc2nn ~]$ su –
[root@hc2nn ~]# cd /home/hadoop/tmp
[root@hc2nn titan]# mv titan-0.9.0-M2-hadoop1 /usr/local
[root@hc2nn titan]# cd /usr/local
[root@hc2nn local]# chown -R hadoop:hadoop titan-0.9.0-M2-hadoop1
[root@hc2nn local]# ln -s titan-0.9.0-M2-hadoop1 titan
[root@hc2nn local]# ls -ld *titan*
lrwxrwxrwx  1 root   root     19 Mar 13 14:10 titan -> titan-0.9.0-M2-hadoop1
drwxr-xr-x 10 hadoop hadoop 4096 Feb 14 13:30 titan-0.9.0-M2-hadoop1

```

使用稍后将演示的 Titan Gremlin shell，现在可以使用 Titan。这个版本的 Titan 需要 Java 8；确保您已经安装了它。

# 带有 HBase 的 Titan

如前图所示，HBase 依赖于 ZooKeeper。鉴于我在 CDH5 集群上有一个正常运行的 ZooKeeper 仲裁（运行在`hc2r1m2`、`hc2r1m3`和`hc2r1m4`节点上），我只需要确保 HBase 在我的 Hadoop 集群上安装并正常运行。

## HBase 集群

我将使用 Cloudera CDH 集群管理器安装分布式版本的 HBase。使用管理器控制台，安装 HBase 是一项简单的任务。唯一需要决定的是在集群上放置 HBase 服务器的位置。下图显示了 CDH HBase 安装的**按主机查看**表单。HBase 组件显示在右侧作为**已添加角色**。

我选择将 HBase 区域服务器（RS）添加到`hc2r1m2`、`hc2r1m3`和`hc2r1m4`节点上。我在`hc2r1m1`主机上安装了 HBase 主服务器（M）、HBase REST 服务器（HBREST）和 HBase Thrift 服务器（HBTS）。

![HBase 集群](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_06_03.jpg)

我过去曾手动安装和配置过许多基于 Hadoop 的组件，我发现这种简单的基于管理器的安装和配置组件的方法既快速又可靠。这节省了我时间，让我可以集中精力处理其他系统，比如 Titan。

安装了 HBase，并且已经从 CDH 管理器控制台启动，需要检查以确保它正常工作。我将使用下面显示的 HBase shell 命令来执行此操作：

```scala
[hadoop@hc2r1m2 ~]$ hbase shell
Version 0.98.6-cdh5.3.2, rUnknown, Tue Feb 24 12:56:59 PST 2015
hbase(main):001:0>

```

如前面的命令所示，我以 Linux 用户`hadoop`身份运行 HBase shell。已安装 HBase 版本 0.98.6；在开始使用 Titan 时，这个版本号将变得重要：

```scala
hbase(main):001:0> create 'table2', 'cf1'
hbase(main):002:0> put 'table2', 'row1', 'cf1:1', 'value1'
hbase(main):003:0> put 'table2', 'row2', 'cf1:1', 'value2'

```

我已经创建了一个名为`table2`的简单表，列族为`cf1`。然后我添加了两行，每行有两个不同的值。这个表是从`hc2r1m2`节点创建的，现在将从 HBase 集群中的另一个名为`hc2r1m4`的节点进行检查：

```scala
[hadoop@hc2r1m4 ~]$ hbase shell

hbase(main):001:0> scan 'table2'

ROW                     COLUMN+CELL
 row1                   column=cf1:1, timestamp=1437968514021, value=value1
 row2                   column=cf1:1, timestamp=1437968520664, value=value2
2 row(s) in 0.3870 seconds

```

如您所见，从不同的主机可以看到`table2`中的两行数据，因此 HBase 已安装并正常工作。现在是时候尝试使用 HBase 和 Titan Gremlin shell 在 Titan 中创建图了。

## Gremlin HBase 脚本

我已经检查了我的 Java 版本，以确保我使用的是 8 版本，否则 Titan 0.9.0-M2 将无法工作：

```scala
[hadoop@hc2r1m2 ~]$ java -version
openjdk version "1.8.0_51"

```

如果您没有正确设置 Java 版本，您将会遇到这样的错误，直到您谷歌它们，它们似乎没有意义：

```scala
Exception in thread "main" java.lang.UnsupportedClassVersionError: org/apache/tinkerpop/gremlin/groovy/plugin/RemoteAcceptor :
Unsupported major.minor version 52.0

```

交互式 Titan Gremlin shell 可以在 Titan 安装的 bin 目录中找到，如下所示。一旦启动，它会提供一个 Gremlin 提示：

```scala
[hadoop@hc2r1m2 bin]$ pwd
/usr/local/titan/

[hadoop@hc2r1m2 titan]$ bin/gremlin.sh
gremlin>

```

以下脚本将使用 Gremlin shell 输入。脚本的第一部分定义了存储（HBase）的配置，使用的 ZooKeeper 服务器，ZooKeeper 端口号以及要使用的 HBase 表名：

```scala
hBaseConf = new BaseConfiguration();
hBaseConf.setProperty("storage.backend","hbase");
hBaseConf.setProperty("storage.hostname","hc2r1m2,hc2r1m3,hc2r1m4");
hBaseConf.setProperty("storage.hbase.ext.hbase.zookeeper.property.clientPort","2181")
hBaseConf.setProperty("storage.hbase.table","titan")

titanGraph = TitanFactory.open(hBaseConf);

```

下一部分定义了要使用管理系统创建的图的通用顶点属性的名称和年龄。然后提交管理系统的更改：

```scala
manageSys = titanGraph.openManagement();
nameProp = manageSys.makePropertyKey('name').dataType(String.class).make();
ageProp  = manageSys.makePropertyKey('age').dataType(String.class).make();
manageSys.buildIndex('nameIdx',Vertex.class).addKey(nameProp).buildCompositeIndex();
manageSys.buildIndex('ageIdx',Vertex.class).addKey(ageProp).buildCompositeIndex();

manageSys.commit();

```

现在，将六个顶点添加到图中。每个顶点都被赋予一个数字标签来表示其身份。每个顶点都被赋予年龄和姓名值：

```scala
v1=titanGraph.addVertex(label, '1');
v1.property('name', 'Mike');
v1.property('age', '48');

v2=titanGraph.addVertex(label, '2');
v2.property('name', 'Sarah');
v2.property('age', '45');

v3=titanGraph.addVertex(label, '3');
v3.property('name', 'John');
v3.property('age', '25');

v4=titanGraph.addVertex(label, '4');
v4.property('name', 'Jim');
v4.property('age', '53');

v5=titanGraph.addVertex(label, '5');
v5.property('name', 'Kate');
v5.property('age', '22');

v6=titanGraph.addVertex(label, '6');
v6.property('name', 'Flo');
v6.property('age', '52');

```

最后，图的边被添加以将顶点连接在一起。每条边都有一个关系值。一旦创建，更改就会被提交以将它们存储到 Titan，因此也存储到 HBase：

```scala
v6.addEdge("Sister", v1)
v1.addEdge("Husband", v2)
v2.addEdge("Wife", v1)
v5.addEdge("Daughter", v1)
v5.addEdge("Daughter", v2)
v3.addEdge("Son", v1)
v3.addEdge("Son", v2)
v4.addEdge("Friend", v1)
v1.addEdge("Father", v5)
v1.addEdge("Father", v3)
v2.addEdge("Mother", v5)
v2.addEdge("Mother", v3)

titanGraph.tx().commit();

```

这导致了一个简单的基于人的图，如下图所示，这也是在上一章中使用的：

![The Gremlin HBase script](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_06_04.jpg)

然后可以在 Titan 中使用 Gremlin shell 测试这个图，使用与之前类似的脚本。只需在`gremlin>`提示符下输入以下脚本，就像之前展示的那样。它使用相同的六行来创建`titanGraph`配置，但然后创建了一个图遍历变量`g`：

```scala
hBaseConf = new BaseConfiguration();
hBaseConf.setProperty("storage.backend","hbase");
hBaseConf.setProperty("storage.hostname","hc2r1m2,hc2r1m3,hc2r1m4");
hBaseConf.setProperty("storage.hbase.ext.hbase.zookeeper.property.clientPort","2181")
hBaseConf.setProperty("storage.hbase.table","titan")

titanGraph = TitanFactory.open(hBaseConf);

gremlin> g = titanGraph.traversal()

```

现在，图遍历变量可以用来检查图的内容。使用`ValueMap`选项，可以搜索名为`Mike`和`Flo`的图节点。它们已经成功找到了：

```scala
gremlin> g.V().has('name','Mike').valueMap();
==>[name:[Mike], age:[48]]

gremlin> g.V().has('name','Flo').valueMap();
==>[name:[Flo], age:[52]]

```

因此，使用 Gremlin shell 在 Titan 中创建并检查了图，但我们也可以使用 HBase shell 检查 HBase 中的存储，并检查 Titan 表的内容。以下扫描显示表存在，并包含此小图的`72`行数据：

```scala
[hadoop@hc2r1m2 ~]$ hbase shell
hbase(main):002:0> scan 'titan'
72 row(s) in 0.8310 seconds

```

现在图已经创建，并且我确信它已经存储在 HBase 中，我将尝试使用 apache Spark 访问数据。我已经在所有节点上启动了 Apache Spark，如前一章所示。这将是从 Apache Spark 1.3 直接访问 HBase 存储。我目前不打算使用 Titan 来解释存储在 HBase 中的图。

## Spark on HBase

为了从 Spark 访问 HBase，我将使用 Cloudera 的`SparkOnHBase`模块，可以从[`github.com/cloudera-labs/SparkOnHBase`](https://github.com/cloudera-labs/SparkOnHBase)下载。

下载的文件是以压缩格式的，需要解压。我使用 Linux unzip 命令在临时目录中完成了这个操作：

```scala
[hadoop@hc2r1m2 tmp]$ ls -l SparkOnHBase-cdh5-0.0.2.zip
-rw-r--r-- 1 hadoop hadoop 370439 Jul 27 13:39 SparkOnHBase-cdh5-0.0.2.zip

[hadoop@hc2r1m2 tmp]$ unzip SparkOnHBase-cdh5-0.0.2.zip

[hadoop@hc2r1m2 tmp]$ ls
SparkOnHBase-cdh5-0.0.2  SparkOnHBase-cdh5-0.0.2.zip

```

然后，我进入解压后的模块，并使用 Maven 命令`mvn`来构建 JAR 文件：

```scala
[hadoop@hc2r1m2 tmp]$ cd SparkOnHBase-cdh5-0.0.2
[hadoop@hc2r1m2 SparkOnHBase-cdh5-0.0.2]$ mvn clean package

[INFO] -----------------------------------------------------------
[INFO] BUILD SUCCESS
[INFO] -----------------------------------------------------------
[INFO] Total time: 13:17 min
[INFO] Finished at: 2015-07-27T14:05:55+12:00
[INFO] Final Memory: 50M/191M
[INFO] -----------------------------------------------------------

```

最后，我将构建的组件移动到我的开发区域，以保持整洁，这样我就可以在我的 Spark HBase 代码中使用这个模块：

```scala
[hadoop@hc2r1m2 SparkOnHBase-cdh5-0.0.2]$ cd ..
[hadoop@hc2r1m2 tmp]$ mv SparkOnHBase-cdh5-0.0.2 /home/hadoop/spark

```

## 使用 Spark 访问 HBase

与以前的章节一样，我将使用 SBT 和 Scala 将基于 Spark 的脚本编译成应用程序。然后，我将使用 spark-submit 在 Spark 集群上运行这些应用程序。我的 SBT 配置文件如下所示。它包含了 Hadoop、Spark 和 HBase 库：

```scala
[hadoop@hc2r1m2 titan_hbase]$ pwd
/home/hadoop/spark/titan_hbase

[hadoop@hc2r1m2 titan_hbase]$ more titan.sbt
name := "T i t a n"
version := "1.0"
scalaVersion := "2.10.4"

libraryDependencies += "org.apache.hadoop" % "hadoop-client" % "2.3.0"
libraryDependencies += "org.apache.spark" %% "spark-core"  % "1.3.1"
libraryDependencies += "com.cloudera.spark" % "hbase"   % "5-0.0.2" from "file:///home/hadoop/spark/SparkOnHBase-cdh5-0.0.2/target/SparkHBase.jar"
libraryDependencies += "org.apache.hadoop.hbase" % "client"   % "5-0.0.2" from "file:///home/hadoop/spark/SparkOnHBase-cdh5-0.0.2/target/SparkHBase.jar"
resolvers += "Cloudera Repository" at "https://repository.cloudera.com/artifactory/clouder
a-repos/"

```

请注意，我正在`hc2r1m2`服务器上运行此应用程序，使用 Linux`hadoop`帐户，在`/home/hadoop/spark/titan_hbase`目录下。我创建了一个名为`run_titan.bash.hbase`的 Bash shell 脚本，允许我运行在`src/main/scala`子目录下创建和编译的任何应用程序：

```scala
[hadoop@hc2r1m2 titan_hbase]$ pwd ; more run_titan.bash.hbase
/home/hadoop/spark/titan_hbase

#!/bin/bash

SPARK_HOME=/usr/local/spark
SPARK_BIN=$SPARK_HOME/bin
SPARK_SBIN=$SPARK_HOME/sbin

JAR_PATH=/home/hadoop/spark/titan_hbase/target/scala-2.10/t-i-t-a-n_2.10-1.0.jar
CLASS_VAL=$1

CDH_JAR_HOME=/opt/cloudera/parcels/CDH/lib/hbase/
CONN_HOME=/home/hadoop/spark/SparkOnHBase-cdh5-0.0.2/target/

HBASE_JAR1=$CDH_JAR_HOME/hbase-common-0.98.6-cdh5.3.3.jar
HBASE_JAR2=$CONN_HOME/SparkHBase.jar

cd $SPARK_BIN

./spark-submit \
 --jars $HBASE_JAR1 \
 --jars $HBASE_JAR2 \
 --class $CLASS_VAL \
 --master spark://hc2nn.semtech-solutions.co.nz:7077  \
 --executor-memory 100M \
 --total-executor-cores 50 \
 $JAR_PATH

```

Bash 脚本保存在相同的`titan_hbase`目录中，并接受应用程序类名的单个参数。`spark-submit`调用的参数与先前的示例相同。在这种情况下，在`src/main/scala`下只有一个脚本，名为`spark3_hbase2.scala`：

```scala
[hadoop@hc2r1m2 scala]$ pwd
/home/hadoop/spark/titan_hbase/src/main/scala

[hadoop@hc2r1m2 scala]$ ls
spark3_hbase2.scala

```

Scala 脚本首先定义了应用程序类所属的包名称。然后导入了 Spark、Hadoop 和 HBase 类：

```scala
package nz.co.semtechsolutions

import org.apache.spark.SparkContext
import org.apache.spark.SparkContext._
import org.apache.spark.SparkConf

import org.apache.hadoop.hbase._
import org.apache.hadoop.fs.Path
import com.cloudera.spark.hbase.HBaseContext
import org.apache.hadoop.hbase.client.Scan
```

应用程序类名也被定义，以及主方法。然后根据应用程序名称和 Spark URL 创建一个配置对象。最后，从配置创建一个 Spark 上下文：

```scala
object spark3_hbase2
{

  def main(args: Array[String]) {

    val sparkMaster = "spark://hc2nn.semtech-solutions.co.nz:7077"
    val appName = "Spark HBase 2"
    val conf = new SparkConf()

    conf.setMaster(sparkMaster)
    conf.setAppName(appName)

    val sparkCxt = new SparkContext(conf)
```

接下来，创建一个 HBase 配置对象，并添加一个基于 Cloudera CDH `hbase-site.xml`文件的资源：

```scala
    val jobConf = HBaseConfiguration.create()

    val hbasePath="/opt/cloudera/parcels/CDH/etc/hbase/conf.dist/"

    jobConf.addResource(new Path(hbasePath+"hbase-site.xml"))
```

使用 Spark 上下文和 HBase 配置对象创建一个 HBase 上下文对象。还定义了扫描和缓存配置：

```scala
    val hbaseContext = new HBaseContext(sparkCxt, jobConf)

    var scan = new Scan()
    scan.setCaching(100)
```

最后，使用`hbaseRDD` HBase 上下文方法和扫描对象检索了 HBase `Titan`表中的数据。打印了 RDD 计数，然后关闭了脚本：

```scala
    var hbaseRdd = hbaseContext.hbaseRDD("titan", scan)

    println( "Rows in Titan hbase table : " + hbaseRdd.count() )

    println( " >>>>> Script Finished <<<<< " )

  } // end main

} // end spark3_hbase2
```

我只打印了检索到的数据计数，因为 Titan 以 GZ 格式压缩数据。因此，直接尝试操纵它将没有多大意义。

使用`run_titan.bash.hbase`脚本运行名为`spark3_hbase2`的 Spark 应用程序。它输出了一个 RDD 行计数为`72`，与先前找到的 Titan 表行计数相匹配。这证明 Apache Spark 已能够访问原始的 Titan HBase 存储的图形数据，但 Spark 尚未使用 Titan 库来访问 Titan 数据作为图形。这将在稍后讨论。以下是代码：

```scala
[hadoop@hc2r1m2 titan_hbase]$ ./run_titan.bash.hbase nz.co.semtechsolutions.spark3_hbase2

Rows in Titan hbase table : 72
 >>>>> Script Finished <<<<<

```

# 使用 Cassandra 的 Titan

在本节中，Cassandra NoSQL 数据库将作为 Titan 的存储机制。尽管它不使用 Hadoop，但它本身是一个大规模的基于集群的数据库，并且可以扩展到非常大的集群规模。本节将遵循相同的流程。与 HBase 一样，将创建一个图，并使用 Titan Gremlin shell 将其存储在 Cassandra 中。然后将使用 Gremlin 进行检查，并在 Cassandra 中检查存储的数据。然后将从 Spark 中访问原始的 Titan Cassandra 图形数据。因此，第一步是在集群中的每个节点上安装 Cassandra。

## 安装 Cassandra

创建一个允许使用 Linux 的`yum`命令安装 DataStax Cassandra 社区版本的 repo 文件。这将需要 root 访问权限，因此使用`su`命令切换用户到 root。在所有节点上安装 Cassandra：

```scala
[hadoop@hc2nn lib]$ su -
[root@hc2nn ~]# vi /etc/yum.repos.d/datastax.repo

[datastax]
name= DataStax Repo for Apache Cassandra
baseurl=http://rpm.datastax.com/community
enabled=1
gpgcheck=0

```

现在，在集群中的每个节点上使用 Linux 的`yum`命令安装 Cassandra：

```scala
[root@hc2nn ~]# yum -y install dsc20-2.0.13-1 cassandra20-2.0.13-1

```

通过修改`cassandra.yaml`文件，在`/etc/cassandra/conf`下设置 Cassandra 配置：

```scala
[root@hc2nn ~]# cd /etc/cassandra/conf   ; vi cassandra.yaml

```

我已经做了以下更改，以指定我的集群名称、服务器种子 IP 地址、RPC 地址和 snitch 值。种子节点是其他节点首先尝试连接的节点。在这种情况下，NameNode（`103`）和 node2（`108`）被用作`seeds`。snitch 方法管理网络拓扑和路由：

```scala
cluster_name: 'Cluster1'
seeds: "192.168.1.103,192.168.1.108"
listen_address:
rpc_address: 0.0.0.0
endpoint_snitch: GossipingPropertyFileSnitch

```

现在可以作为 root 在每个节点上启动 Cassandra，使用 service 命令：

```scala
[root@hc2nn ~]# service cassandra start

```

日志文件可以在`/var/log/cassandra`下找到，数据存储在`/var/lib/cassandra`下。`nodetool`命令可以在任何 Cassandra 节点上使用，以检查 Cassandra 集群的状态：

```scala
[root@hc2nn cassandra]# nodetool status
Datacenter: DC1
===============
Status=Up/Down
|/ State=Normal/Leaving/Joining/Moving
--  Address        Load       Tokens  Owns (effective)  Host ID Rack
UN  192.168.1.105  63.96 KB   256     37.2%             f230c5d7-ff6f-43e7-821d-c7ae2b5141d3  RAC1
UN  192.168.1.110  45.86 KB   256     39.9%             fc1d80fe-6c2d-467d-9034-96a1f203c20d  RAC1
UN  192.168.1.109  45.9 KB    256     40.9%             daadf2ee-f8c2-4177-ae72-683e39fd1ea0  RAC1
UN  192.168.1.108  50.44 KB   256     40.5%             b9d796c0-5893-46bc-8e3c-187a524b1f5a  RAC1
UN  192.168.1.103  70.68 KB   256     41.5%             53c2eebd-
a66c-4a65-b026-96e232846243  RAC1

```

Cassandra CQL shell 命令称为`cqlsh`，可用于访问集群并创建对象。接下来调用 shell，它显示 Cassandra 版本 2.0.13 已安装：

```scala
[hadoop@hc2nn ~]$ cqlsh
Connected to Cluster1 at localhost:9160.
[cqlsh 4.1.1 | Cassandra 2.0.13 | CQL spec 3.1.1 | Thrift protocol 19.39.0]
Use HELP for help.
cqlsh>

```

Cassandra 查询语言接下来显示了一个名为`keyspace1`的键空间，通过 CQL shell 创建和使用：

```scala
cqlsh> CREATE KEYSPACE keyspace1 WITH REPLICATION = { 'class' : 'SimpleStrategy', 'replication_factor' : 1 };

cqlsh> USE keyspace1;

cqlsh:keyspace1> SELECT * FROM system.schema_keyspaces;

 keyspace_name | durable_writes | strategy_class                              | strategy_options
--------------+------+---------------------------------------------+----------------------------
 keyspace1  | True | org.apache.cassandra.locator.SimpleStrategy | {"replication_factor":"1"}
 system  | True |  org.apache.cassandra.locator.LocalStrategy |                         {}
system_traces | True | org.apache.cassandra.locator.SimpleStrategy | {"replication_factor":"2"}

```

由于 Cassandra 已安装并运行，现在是时候使用 Cassandra 创建 Titan 图形存储。这将在下一节中使用 Titan Gremlin shell 来解决。它将遵循之前 HBase 部分的相同格式。

## Gremlin Cassandra 脚本

与之前的 Gremlin 脚本一样，这个 Cassandra 版本创建了相同的简单图。这个脚本的不同之处在于配置。后端存储类型被定义为 Cassandra，主机名被定义为 Cassandra 种子节点。指定了 key space 和端口号，最后创建了图：

```scala
cassConf = new BaseConfiguration();
cassConf.setProperty("storage.backend","cassandra");
cassConf.setProperty("storage.hostname","hc2nn,hc2r1m2");
cassConf.setProperty("storage.port","9160")
cassConf.setProperty("storage.keyspace","titan")
titanGraph = TitanFactory.open(cassConf);
```

从这一点开始，脚本与之前的 HBase 示例相同，所以我不会重复它。这个脚本将作为`cassandra_create.bash`在下载包中提供。可以在 Gremlin shell 中使用之前的配置进行相同的检查以检查数据。这返回与之前检查相同的结果，证明图已经被存储：

```scala
gremlin> g = titanGraph.traversal()

gremlin> g.V().has('name','Mike').valueMap();
==>[name:[Mike], age:[48]]

gremlin> g.V().has('name','Flo').valueMap();
==>[name:[Flo], age:[52]]

```

通过使用 Cassandra CQL shell 和 Titan `keyspace`，可以看到在 Cassandra 中已经创建了许多 Titan 表：

```scala
[hadoop@hc2nn ~]$ cqlsh
cqlsh> use titan;
cqlsh:titan> describe tables;
edgestore        graphindex        system_properties systemlog  txlog
edgestore_lock_  graphindex_lock_  system_properties_lock_  titan_ids

```

还可以看到数据存在于 Cassandra 的`edgestore`表中：

```scala
cqlsh:titan> select * from edgestore;
 key                | column1            | value
--------------------+--------------------+------------------------------------------------
 0x0000000000004815 |               0x02 |                                     0x00011ee0
 0x0000000000004815 |             0x10c0 |                           0xa0727425536fee1ec0
.......
 0x0000000000001005 |             0x10c8 |                       0x00800512644c1b149004a0
 0x0000000000001005 | 0x30c9801009800c20 |   0x000101143c01023b0101696e6465782d706ff30200

```

这向我保证了在 Gremlin shell 中已经创建了 Titan 图，并且存储在 Cassandra 中。现在，我将尝试从 Spark 中访问数据。

## Spark Cassandra 连接器

为了从 Spark 访问 Cassandra，我将下载 DataStax Spark Cassandra 连接器和驱动程序库。关于这方面的信息和版本匹配可以在[`mvnrepository.com/artifact/com.datastax.spark/`](http://mvnrepository.com/artifact/com.datastax.spark/)找到。

这个 URL 的版本兼容性部分显示了应该与每个 Cassandra 和 Spark 版本一起使用的 Cassandra 连接器版本。版本表显示连接器版本应该与正在使用的 Spark 版本匹配。下一个 URL 允许在[`mvnrepository.com/artifact/com.datastax.spark/spark-cassandra-connector_2.10`](http://mvnrepository.com/artifact/com.datastax.spark/spark-cassandra-connector_2.10)找到这些库。

通过上面的 URL，并选择一个库版本，你将看到与该库相关的编译依赖关系表，其中指示了你需要的所有其他依赖库及其版本。以下库是与 Spark 1.3.1 一起使用所需的。如果你使用前面的 URL，你将看到每个 Spark 版本应该使用哪个版本的 Cassandra 连接器库。你还将看到 Cassandra 连接器依赖的库。请小心选择所需的库版本：

```scala
[hadoop@hc2r1m2 titan_cass]$ pwd ; ls *.jar
/home/hadoop/spark/titan_cass

spark-cassandra-connector_2.10-1.3.0-M1.jar
cassandra-driver-core-2.1.5.jar
cassandra-thrift-2.1.3.jar
libthrift-0.9.2.jar
cassandra-clientutil-2.1.3.jar
guava-14.0.1.jar
joda-time-2.3.jar
joda-convert-1.2.jar

```

## 使用 Spark 访问 Cassandra

现在我已经准备好了 Cassandra 连接器库和所有的依赖关系，我可以开始考虑连接到 Cassandra 所需的 Scala 代码。首先要做的事情是设置 SBT 构建配置文件，因为我使用 SBT 作为开发工具。我的配置文件看起来像这样：

```scala
[hadoop@hc2r1m2 titan_cass]$ pwd ; more titan.sbt
/home/hadoop/spark/titan_cass

name := "Spark Cass"
version := "1.0"
scalaVersion := "2.10.4"
libraryDependencies += "org.apache.hadoop" % "hadoop-client" % "2.3.0"
libraryDependencies += "org.apache.spark" %% "spark-core"  % "1.3.1"
libraryDependencies += "com.datastax.spark" % "spark-cassandra-connector"  % "1.3.0-M1" fr
om "file:///home/hadoop/spark/titan_cass/spark-cassandra-connector_2.10-1.3.0-M1.jar"
libraryDependencies += "com.datastax.cassandra" % "cassandra-driver-core"  % "2.1.5" from
"file:///home/hadoop/spark/titan_cass/cassandra-driver-core-2.1.5.jar"
libraryDependencies += "org.joda"  % "time" % "2.3" from "file:///home/hadoop/spark/titan_
cass/joda-time-2.3.jar"
libraryDependencies += "org.apache.cassandra" % "thrift" % "2.1.3" from "file:///home/hado
op/spark/titan_cass/cassandra-thrift-2.1.3.jar"
libraryDependencies += "com.google.common" % "collect" % "14.0.1" from "file:///home/hadoo
p/spark/titan_cass/guava-14.0.1.jar
resolvers += "Cloudera Repository" at "https://repository.cloudera.com/artifactory/clouder
a-repos/"

```

Cassandra 连接器示例的 Scala 脚本，名为`spark3_cass.scala`，现在看起来像以下代码。首先，定义了包名。然后，为 Spark 和 Cassandra 连接器导入了类。接下来，定义了对象应用类`spark3_cass` ID，以及主方法：

```scala
package nz.co.semtechsolutions

import org.apache.spark.SparkContext
import org.apache.spark.SparkContext._
import org.apache.spark.SparkConf

import com.datastax.spark.connector._

object spark3_cass
{

  def main(args: Array[String]) {
```

使用 Spark URL 和应用程序名称创建了一个 Spark 配置对象。将 Cassandra 连接主机添加到配置中。然后，使用配置对象创建了 Spark 上下文：

```scala
    val sparkMaster = "spark://hc2nn.semtech-solutions.co.nz:7077"
    val appName = "Spark Cass 1"
    val conf = new SparkConf()

    conf.setMaster(sparkMaster)
    conf.setAppName(appName)

    conf.set("spark.cassandra.connection.host", "hc2r1m2")

    val sparkCxt = new SparkContext(conf)
```

要检查的 Cassandra `keyspace`和表名已经定义。然后，使用名为`cassandraTable`的 Spark 上下文方法连接到 Cassandra，并获取`edgestore`表的内容作为 RDD。然后打印出这个 RDD 的大小，脚本退出。我们暂时不会查看这些数据，因为只需要证明可以连接到 Cassandra：

```scala
    val keySpace =  "titan"
    val tableName = "edgestore"

    val cassRDD = sparkCxt.cassandraTable( keySpace, tableName )

    println( "Cassandra Table Rows : " + cassRDD.count )

    println( " >>>>> Script Finished <<<<< " )

  } // end main

} // end spark3_cass
```

与之前的示例一样，Spark 的`submit`命令已放置在一个名为`run_titan.bash.cass`的 Bash 脚本中。下面显示的脚本看起来与已经使用的许多其他脚本类似。这里需要注意的是有一个 JARs 选项，列出了所有在运行时可用的 JAR 文件。这个选项中 JAR 文件的顺序已经确定，以避免类异常错误：

```scala
[hadoop@hc2r1m2 titan_cass]$ more run_titan.bash

#!/bin/bash

SPARK_HOME=/usr/local/spark
SPARK_BIN=$SPARK_HOME/bin
SPARK_SBIN=$SPARK_HOME/sbin

JAR_PATH=/home/hadoop/spark/titan_cass/target/scala-2.10/spark-cass_2.10-1.0.jar
CLASS_VAL=$1

CASS_HOME=/home/hadoop/spark/titan_cass/

CASS_JAR1=$CASS_HOME/spark-cassandra-connector_2.10-1.3.0-M1.jar
CASS_JAR2=$CASS_HOME/cassandra-driver-core-2.1.5.jar
CASS_JAR3=$CASS_HOME/cassandra-thrift-2.1.3.jar
CASS_JAR4=$CASS_HOME/libthrift-0.9.2.jar
CASS_JAR5=$CASS_HOME/cassandra-clientutil-2.1.3.jar
CASS_JAR6=$CASS_HOME/guava-14.0.1.jar
CASS_JAR7=$CASS_HOME/joda-time-2.3.jar
CASS_JAR8=$CASS_HOME/joda-convert-1.2.jar

cd $SPARK_BIN

./spark-submit \
 --jars $CASS_JAR8,$CASS_JAR7,$CASS_JAR5,$CASS_JAR4,$CASS_JAR3,$CASS_JAR6,$CASS_JAR2,$CASS_JAR1 \
 --class $CLASS_VAL \
 --master spark://hc2nn.semtech-solutions.co.nz:7077  \
 --executor-memory 100M \
 --total-executor-cores 50 \
 $JAR_PATH

```

此应用程序是通过之前的 Bash 脚本调用的。它连接到 Cassandra，选择数据，并返回基于 Cassandra 表数据的计数为`218`行。

```scala
[hadoop@hc2r1m2 titan_cass]$ ./run_titan.bash.cass nz.co.semtechsolutions.spark3_cass

Cassandra Table Rows : 218
 >>>>> Script Finished <<<<<

```

这证明了可以从 Apache Spark 访问基于原始 Cassandra 的 Titan 表数据。然而，与 HBase 示例一样，这是基于原始表的 Titan 数据，而不是 Titan 图形中的数据。下一步将是使用 Apache Spark 作为 Titan 数据库的处理引擎。这将在下一节中进行讨论。

# 使用 Spark 访问 Titan

到目前为止，在本章中，已经安装了 Titan 0.9.0-M2，并成功使用 HBase 和 Cassandra 作为后端存储选项创建了图形。这些图形是使用基于 Gremlin 的脚本创建的。在本节中，将使用属性文件通过 Gremlin 脚本来处理基于 Titan 的图形，使用相同的两个后端存储选项 HBase 和 Cassandra。

以下图表基于本章前面的 TinkerPop3 图表，展示了本节中使用的架构。我简化了图表，但基本上与之前的 TinkerPop 版本相同。我只是通过图形计算机 API 添加了到 Apache Spark 的链接。我还通过 Titan 供应商 API 添加了 HBase 和 Cassandra 存储。当然，HBase 的分布式安装同时使用 Zookeeper 进行配置，使用 HDFS 进行存储。

Titan 使用 TinkerPop 的 Hadoop-Gremlin 包进行图处理 OLAP 过程。文档部分的链接可以在这里找到：[`s3.thinkaurelius.com/docs/titan/0.9.0-M2/titan-hadoop-tp3.html`](http://s3.thinkaurelius.com/docs/titan/0.9.0-M2/titan-hadoop-tp3.html)。

本节将展示如何使用 Bash shell、Groovy 和属性文件来配置和运行基于 Titan Spark 的作业。它将展示配置作业的不同方法，并展示管理日志以启用错误跟踪的方法。还将描述属性文件的不同配置，以便访问 HBase、Cassandra 和 Linux 文件系统。

请记住，本章基于的 Titan 0.9.0-M2 版本是一个开发版本。这是一个原型版本，尚未准备好投入生产。我假设随着未来 Titan 版本的推出，Titan 与 Spark 之间的链接将更加完善和稳定。目前，本节中的工作仅用于演示目的，考虑到 Titan 版本的性质。

![使用 Spark 访问 Titan](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark/img/B01989_06_05.jpg)

在下一节中，我将解释使用 Gremlin 和 Groovy 脚本，然后转向使用 Cassandra 和 HBase 作为存储选项将 Titan 连接到 Spark。

## Gremlin 和 Groovy

用于执行 Groovy 命令的 Gremlin shell 可以以多种方式使用。第一种使用方法只涉及启动 Gremlin shell 以用作交互式会话。只需执行以下命令：

```scala
cd $TITAN_HOME/bin ; ./ gremlin.sh

```

这将启动会话，并自动设置所需的插件，如 TinkerPop 和 Titan（见下文）。显然，之前的`TITAN_HOME`变量用于指示所讨论的 bin 目录位于您的 Titan 安装（`TITAN_HOME`）目录中：

```scala
plugin activated: tinkerpop.server
plugin activated: tinkerpop.utilities
plugin activated: tinkerpop.hadoop
plugin activated: tinkerpop.tinkergraph
plugin activated: aurelius.titan

```

然后它会提供一个 Gremlin shell 提示符，您可以在其中交互式地执行对 Titan 数据库的 shell 命令。此 shell 对于测试脚本和针对 Titan 数据库运行临时命令非常有用。

```scala
gremlin>

```

第二种方法是在调用`gremlin.sh`命令时将您的 Groovy 命令嵌入到脚本中。在这个例子中，EOF 标记之间的 Groovy 命令被传送到 Gremlin shell 中。当最后一个 Groovy 命令执行完毕时，Gremlin shell 将终止。当您仍希望使用 Gremlin shell 的自动化环境设置，但仍希望能够快速重新执行脚本时，这是很有用的。这段代码片段是从 Bash shell 脚本中执行的，如下一个例子所示。以下脚本使用`titan.sh`脚本来管理 Gremlin 服务器：

```scala
#!/bin/bash

TITAN_HOME=/usr/local/titan/

cd $TITAN_HOME

bin/titan.sh start

bin/gremlin.sh   <<  EOF

 t = TitanFactory.open('cassandra.properties')
 GraphOfTheGodsFactory.load(t)
 t.close()
EOF

bin/titan.sh stop

```

第三种方法涉及将 Groovy 命令移动到一个单独的 Groovy 文件中，并使用 Gremlin shell 的`-e`选项来执行该文件。这种方法为错误跟踪提供了额外的日志选项，但意味着在为 Groovy 脚本设置 Gremlin 环境时需要采取额外的步骤：

```scala
#!/bin/bash

TITAN_HOME=/usr/local/titan/
SCRIPTS_HOME=/home/hadoop/spark/gremlin
GREMLIN_LOG_FILE=$TITAN_HOME/log/gremlin_console.log

GROOVY_SCRIPT=$1

export GREMLIN_LOG_LEVEL="DEBUG"

cd $TITAN_HOME

bin/titan.sh start

bin/gremlin.sh -e  $SCRIPTS_HOME/$GROOVY_SCRIPT  > $GREMLIN_LOG_FILE 2>&1

bin/titan.sh stop

```

因此，这个脚本定义了 Gremlin 日志级别，可以设置为不同的日志级别以获取有关问题的额外信息，即 INFO、WARN 和 DEBUG。它还将脚本输出重定向到日志文件（`GREMLIN_LOG_FILE`），并将错误重定向到同一个日志文件（`2>&1`）。这样做的好处是可以持续监视日志文件，并提供会话的永久记录。要执行的 Groovy 脚本名称然后作为参数（`$1`）传递给封装的 Bash shell 脚本。

正如我之前提到的，以这种方式调用的 Groovy 脚本需要额外的环境配置，以设置 Gremlin 会话，与之前的 Gremlin 会话选项相比。例如，需要导入将要使用的必要的 TinkerPop 和 Aurelius 类：

```scala
import com.thinkaurelius.titan.core.*
import com.thinkaurelius.titan.core.titan.*
import org.apache.tinkerpop.gremlin.*
```

在描述了启动 Gremlin shell 会话和运行 Groovy 脚本所需的脚本和配置选项之后，从现在开始我将集中讨论 Groovy 脚本和配置 Gremlin 会话所需的属性文件。

## TinkerPop 的 Hadoop Gremlin

正如前面在本节中已经提到的，Titan 中的 TinkerPop Hadoop Gremlin 包将用于调用 Apache Spark 作为处理引擎（Hadoop Giraph 也可以用于处理）。链接[`s3.thinkaurelius.com/docs/titan/0.9.0-M2/titan-hadoop-tp3.html`](http://s3.thinkaurelius.com/docs/titan/0.9.0-M2/titan-hadoop-tp3.html)提供了 Hadoop Gremlin 的文档；请记住，这个 TinkerPop 包仍在开发中，可能会有所改变。

在这一点上，我将检查一个属性文件，该文件可用于将 Cassandra 作为 Titan 的存储后端进行连接。它包含了用于 Cassandra、Apache Spark 和 Hadoop Gremlin 配置的部分。我的 Cassandra 属性文件名为`cassandra.properties`，内容如下（以井号（`#`）开头的行是注释）：

```scala
####################################
# Storage details
####################################
storage.backend=cassandra
storage.hostname=hc2r1m2
storage.port=9160
storage.cassandra.keyspace=dead
cassandra.input.partitioner.class=org.apache.cassandra.dht.Murmur3Partitioner

```

前面基于 Cassandra 的属性描述了 Cassandra 主机和端口。这就是存储后端类型为 Cassandra 的原因，要使用的 Cassandra `keyspace`称为`dead`（代表感激的死者——在本例中将使用的数据）。请记住，Cassandra 表是在 keyspaces 中分组的。前面的`partitioner`类定义了将用于对 Cassandra 数据进行分区的 Cassandra 类。Apache Spark 配置部分包含主 URL、执行器内存和要使用的数据`serializer`类：

```scala
####################################
# Spark
####################################
spark.master=spark://hc2nn.semtech-solutions.co.nz:6077
spark.executor.memory=400M
spark.serializer=org.apache.spark.serializer.KryoSerializer

```

最后，这里显示了属性文件中 Hadoop Gremlin 部分，该部分定义了用于图形和非图形输入和输出的类。它还定义了数据输入和输出位置，以及用于缓存 JAR 文件和推导内存的标志。

```scala
####################################
# Hadoop Gremlin
####################################
gremlin.graph=org.apache.tinkerpop.gremlin.hadoop.structure.HadoopGraph
gremlin.hadoop.graphInputFormat=com.thinkaurelius.titan.hadoop.formats.cassandra.CassandraInputFormat
gremlin.hadoop.graphOutputFormat=org.apache.tinkerpop.gremlin.hadoop.structure.io.gryo.GryoOutputFormat
gremlin.hadoop.memoryOutputFormat=org.apache.hadoop.mapreduce.lib.output.SequenceFileOutputFormat

gremlin.hadoop.deriveMemory=false
gremlin.hadoop.jarsInDistributedCache=true
gremlin.hadoop.inputLocation=none
gremlin.hadoop.outputLocation=output

```

蓝图是 TinkerPop 属性图模型接口。Titan 发布了自己的蓝图实现，所以在前面的属性中，你会看到`gremlin.graph`而不是`blueprints.graph`。这定义了用于定义应该使用的图的类。如果省略了这个选项，那么图类型将默认为以下内容：

```scala
com.thinkaurelius.titan.core.TitanFactory

```

`CassandraInputFormat`类定义了数据是从 Cassandra 数据库中检索出来的。图输出序列化类被定义为`GryoOutputFormat`。内存输出格式类被定义为使用 Hadoop Map Reduce 类`SequenceFileOutputFormat`。

`jarsInDistributedCache`值已被定义为 true，以便将 JAR 文件复制到内存中，使 Apache Spark 能够使用它们。如果有更多时间，我会研究使 Titan 类对 Spark 可见的方法，以避免过多的内存使用。

鉴于 TinkerPop Hadoop Gremlin 模块目前仅作为开发原型版本发布，目前文档很少。编码示例非常有限，似乎也没有文档描述之前的每个属性。

在我深入探讨 Groovy 脚本示例之前，我想向您展示一种使用配置对象配置 Groovy 作业的替代方法。

## 替代 Groovy 配置

可以使用`BaseConfiguration`方法创建配置对象。在这个例子中，我创建了一个名为`cassConf`的 Cassandra 配置：

```scala
cassConf = new BaseConfiguration();

cassConf.setProperty("storage.backend","cassandra");
cassConf.setProperty("storage.hostname","hc2r1m2");
cassConf.setProperty("storage.port","9160")
cassConf.setProperty("storage.cassandra.keyspace","titan")

titanGraph = TitanFactory.open(cassConf);
```

然后使用`setProperty`方法来定义 Cassandra 连接属性，如后端类型、主机、端口和`keyspace`。最后，使用 open 方法创建了一个名为`titanGraph`的 Titan 图。稍后将会展示，Titan 图可以使用配置对象或属性文件路径来创建。已设置的属性与之前描述的 Cassandra 属性文件中定义的属性相匹配。

接下来的几节将展示如何创建和遍历图。它们将展示如何使用 Cassandra、HBase 和文件系统进行存储。鉴于我已经花了很多篇幅描述 Bash 脚本和属性文件，我只会描述每个实例中需要更改的属性。我还将在每个实例中提供简单的 Groovy 脚本片段。

## 使用 Cassandra

名为`cassandra.properties`的基于 Cassandra 的属性文件已经在前面描述过，所以我不会在这里重复细节。这个示例 Groovy 脚本创建了一个示例图，并将其存储在 Cassandra 中。它已经使用**EOF**来将脚本传输到 Gremlin shell 执行：

```scala
t1 = TitanFactory.open('/home/hadoop/spark/gremlin/cassandra.properties')
GraphOfTheGodsFactory.load(t1)

t1.traversal().V().count()

t1.traversal().V().valueMap()

t1.close()

```

使用`TitanFactory.open`方法和 Cassandra 属性文件创建了一个 Titan 图。它被称为`t1`。上帝之图，一个提供给 Titan 的示例图，已经被加载到图`t1`中，使用了`GraphOfTheGodsFactory.load`方法。然后生成了顶点的计数(`V()`)以及`ValueMap`来显示图的内容。输出如下：

```scala
==>12

==>[name:[jupiter], age:[5000]]
==>[name:[hydra]]
==>[name:[nemean]]
==>[name:[tartarus]]
==>[name:[saturn], age:[10000]]
==>[name:[sky]]
==>[name:[pluto], age:[4000]]
==>[name:[alcmene], age:[45]]
==>[name:[hercules], age:[30]]
==>[name:[sea]]
==>[name:[cerberus]]
==>[name:[neptune], age:[4500]]

```

因此，图中有 12 个顶点，每个顶点都有一个在前面数据中显示的名称和年龄元素。成功创建了一个图后，现在可以配置之前的图遍历 Gremlin 命令以使用 Apache Spark 进行处理。只需在遍历命令中指定`SparkGraphComputer`即可实现。有关架构细节，请参见本章顶部的完整*TinkerPop*图。执行此命令时，您将在 Spark 集群用户界面上看到任务出现：

```scala
t1.traversal(computer(SparkGraphComputer)).V().count()

```

## 使用 HBase

在使用 HBase 时，需要更改属性文件。以下数值取自我的`hbase.properties`文件：

```scala
gremlin.hadoop.graphInputFormat=com.thinkaurelius.titan.hadoop.formats.hbase.HBaseInputFormat

input.conf.storage.backend=hbase
input.conf.storage.hostname=hc2r1m2
input.conf.storage.port=2181
input.conf.storage.hbase.table=titan
input.conf.storage.hbase.ext.zookeeper.znode.parent=/hbase

```

请记住，HBase 使用 Zookeeper 进行配置。因此，连接的端口号和服务器现在变成了`zookeeper`服务器和`zookeeper`主端口 2181。在 Zookeeper 中，`znode`父值也被定义为顶级节点`/hbase`。当然，后端类型现在被定义为`hbase`。

此外，`GraphInputFormat`类已更改为`HBaseInputFormat`，以描述 HBase 作为输入源。现在可以使用此属性文件创建 Titan 图，就像上一节所示的那样。我不会在这里重复图的创建，因为它与上一节相同。接下来，我将转向文件系统存储。

## 使用文件系统

为了运行这个例子，我使用了一个基本的 Gremlin shell（`bin/gremlin.sh`）。在 Titan 发布的数据目录中，有许多可以加载以创建图形的示例数据文件格式。在这个例子中，我将使用名为`grateful-dead.kryo`的文件。因此，这次数据将直接从文件加载到图形中，而不需要指定存储后端，比如 Cassandra。我将使用的属性文件只包含以下条目：

```scala
gremlin.graph=org.apache.tinkerpop.gremlin.hadoop.structure.HadoopGraph
gremlin.hadoop.graphInputFormat=org.apache.tinkerpop.gremlin.hadoop.structure.io.gryo.GryoInputFormat
gremlin.hadoop.graphOutputFormat=org.apache.tinkerpop.gremlin.hadoop.structure.io.gryo.GryoOutputFormat
gremlin.hadoop.jarsInDistributedCache=true
gremlin.hadoop.deriveMemory=true

gremlin.hadoop.inputLocation=/usr/local/titan/data/grateful-dead.kryo
gremlin.hadoop.outputLocation=output

```

再次，它使用了 Hadoop Gremlin 包，但这次图形输入和输出格式被定义为`GryoInputFormat`和`GryoOutputFormat`。输入位置被指定为实际的基于`kyro`的文件。因此，输入和输出的源是文件。现在，Groovy 脚本看起来像这样。首先，使用属性文件创建图形。然后创建图形遍历，以便我们可以计算顶点并查看结构：

```scala
graph = GraphFactory.open('/home/hadoop/spark/gremlin/hadoop-gryo.properties')
g1 = graph.traversal()

```

接下来，执行了一个顶点计数，显示有 800 多个顶点；最后，一个值映射显示了数据的结构，我显然剪辑了一些以节省空间。但你可以看到歌曲名称、类型和表演细节：

```scala
g1.V().count()
==>808
g1.V().valueMap()
==>[name:[MIGHT AS WELL], songType:[original], performances:[111]]
==>[name:[BROWN EYED WOMEN], songType:[original], performances:[347]]

```

这给您一个关于可用功能的基本概念。我相信，如果您搜索网络，您会发现更复杂的使用 Spark 与 Titan 的方法。以这个为例：

```scala
r = graph.compute(SparkGraphComputer.class).program(PageRankVertexProgram.build().create()).submit().get()

```

前面的例子指定了使用`SparkGraphComputer`类的 compute 方法。它还展示了如何使用 Titan 提供的页面排名顶点程序来执行程序方法。这将通过为每个顶点添加页面排名来修改您的图形。我提供这个作为一个例子，因为我不确定它现在是否适用于 Spark。

# 总结

本章介绍了 Aurelius 的 Titan 图形数据库。它展示了如何在 Linux 集群上安装和配置它。使用 Titan Gremlin shell 示例，图形已经被创建，并存储在 HBase 和 Cassandra NoSQL 数据库中。所需的 Titan 存储选项将取决于您的项目需求；HBase 基于 HDFS 的存储或 Cassandra 非 HDFS 的存储。本章还表明，您可以交互地使用 Gremlin shell 开发图形脚本，并使用 Bash shell 脚本运行带有关联日志的定期作业。

提供了简单的 Spark Scala 代码，显示了 Apache Spark 可以访问 Titan 在 HBase 和 Cassandra 上创建的基础表。这是通过使用 Cloudera 提供的数据库连接器模块（用于 HBase）和 DataStax（用于 Cassandra）实现的。所有示例代码和构建脚本都已经描述，并附有示例输出。我包含了这个基于 Scala 的部分，以向您展示可以在 Scala 中访问基于图形的数据。前面的部分从 Gremlin shell 处理数据，并使用 Spark 作为处理后端。这一部分将 Spark 作为主要处理引擎，并从 Spark 访问 Titan 数据。如果 Gremlin shell 不适合您的需求，您可以考虑这种方法。随着 Titan 的成熟，您可以通过 Scala 以不同的方式将 Titan 与 Spark 集成。

最后，Titan 的 Gremlin shell 已经与 Apache Spark 一起使用，演示了创建和访问基于 Titan 的图形的简单方法。为此，数据已存储在文件系统、Cassandra 和 HBase 上。

通过以下网址，Aurelius 和 Gremlin 用户可以使用 Google 群组：[`groups.google.com/forum/#!forum/aureliusgraphs`](https://groups.google.com/forum/#!forum/aureliusgraphs) 和 [`groups.google.com/forum/#!forum/gremlin-users`](https://groups.google.com/forum/#!forum/gremlin-users)。

尽管 Titan 社区似乎比其他 Apache 项目要小，帖子数量可能有些少，很难得到回复。

今年，创建了 Cassandra 的 DataStax 收购了创建 Titan 的 Aurelius。Titan 的创建者现在参与开发 DataStax 的 DSE 图数据库，这可能会对 Titan 的发展产生影响。话虽如此，0.9.x Titan 版本已经发布，预计会有 1.0 版本的发布。

因此，通过一个使用 Scala 和 Gremlin 的示例展示了 Titan 功能的一部分后，我将在此结束本章。我想展示基于 Spark 的图处理和图存储系统的配对。我喜欢开源系统的开发速度和可访问性。我并不是说 Titan 就是适合你的数据库，但它是一个很好的例子。如果它的未来能够得到保证，并且其社区不断壮大，那么随着其成熟，它可能会成为一个有价值的资源。

请注意，本章中使用了两个版本的 Spark：1.3 和 1.2.1。较早的版本是必需的，因为显然它是唯一与 Titan 的`SparkGraphComputer`兼容的版本，因此避免了 Kyro 序列化错误。

在下一章中，将从[`h2o.ai/`](http://h2o.ai/) H2O 产品的角度，研究对 Apache Spark MLlib 机器学习库的扩展。将使用 Scala 开发一个基于神经网络的深度学习示例，以展示其潜在功能。
