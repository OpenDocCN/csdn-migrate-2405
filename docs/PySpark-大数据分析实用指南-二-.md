# PySpark 大数据分析实用指南（二）

> 原文：[`zh.annas-archive.org/md5/62C4D847CB664AD1379DE037B94D0AE5`](https://zh.annas-archive.org/md5/62C4D847CB664AD1379DE037B94D0AE5)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：避免洗牌和减少操作费用

在本章中，我们将学习如何避免洗牌并减少我们作业的操作费用，以及检测过程中的洗牌。然后，我们将测试在 Apache Spark 中导致洗牌的操作，以找出我们何时应该非常小心以及我们应该避免哪些操作。接下来，我们将学习如何改变具有广泛依赖关系的作业设计。之后，我们将使用`keyBy()`操作来减少洗牌，在本章的最后一节中，我们将看到如何使用自定义分区来减少数据的洗牌。

在本章中，我们将涵盖以下主题：

+   检测过程中的洗牌

+   在 Apache Spark 中进行导致洗牌的测试操作

+   改变具有广泛依赖关系的作业设计

+   使用`keyBy()`操作来减少洗牌

+   使用自定义分区器来减少洗牌

# 检测过程中的洗牌

在本节中，我们将学习如何检测过程中的洗牌。

在本节中，我们将涵盖以下主题：

+   加载随机分区的数据

+   使用有意义的分区键发出重新分区

+   通过解释查询来理解洗牌是如何发生的

我们将加载随机分区的数据，以查看数据是如何加载的以及数据加载到了哪里。接下来，我们将使用有意义的分区键发出一个分区。然后，我们将使用确定性和有意义的键将数据重新分区到适当的执行程序。最后，我们将使用`explain()`方法解释我们的查询并理解洗牌。在这里，我们有一个非常简单的测试。

我们将创建一个带有一些数据的 DataFrame。例如，我们创建了一个带有一些随机 UID 和`user_1`的`InputRecord`，以及另一个带有`user_1`中随机 ID 的输入，以及`user_2`的最后一条记录。假设这些数据是通过外部数据系统加载的。数据可以从 HDFS 加载，也可以从数据库加载，例如 Cassandra 或 NoSQL：

```py
class DetectingShuffle extends FunSuite {
  val spark: SparkSession = SparkSession.builder().master("local[2]").getOrCreate()

  test("should explain plan showing logical and physical with UDF and DF") {
    //given
    import spark.sqlContext.implicits._
    val df = spark.sparkContext.makeRDD(List(
      InputRecord("1234-3456-1235-1234", "user_1"),
      InputRecord("1123-3456-1235-1234", "user_1"),
      InputRecord("1123-3456-1235-9999", "user_2")
    )).toDF()
```

在加载的数据中，我们的数据没有预定义或有意义的分区，这意味着输入记录编号 1 可能会最先出现在执行程序中，而记录编号 2 可能会最先出现在执行程序中。因此，即使数据来自同一用户，我们也很可能会为特定用户执行操作。

如前一章第八章中所讨论的，*不可变设计*，我们使用了`reducebyKey()`方法，该方法获取用户 ID 或特定 ID 以减少特定键的所有值。这是一个非常常见的操作，但具有一些随机分区。最好使用有意义的键`repartition`数据。

在使用`userID`时，我们将使用`repartition`的方式，使结果记录具有相同用户 ID 的数据。因此，例如`user_1`最终将出现在第一个执行程序上：

```py
//when
    val q = df.repartition(df("userId"))
```

第一个执行程序将拥有所有`userID`的数据。如果`InputRecord("1234-3456-1235-1234", "user_1")`在执行程序 1 上，而`InputRecord("1123-3456-1235-1234", "user_1")`在执行程序 2 上，在对来自执行程序 2 的数据进行分区后，我们需要将其发送到执行程序 1，因为它是此分区键的父级。这会导致洗牌。洗牌是由于加载数据而导致的，这些数据没有有意义地分区，或者根本没有分区。我们需要处理我们的数据，以便我们可以对特定键执行操作。

我们可以进一步`repartition`数据，但应该在链的开头进行。让我们开始测试来解释我们的查询：

```py
 q.explain(true)
```

我们在逻辑计划中对`userID`表达式进行了重新分区，但当我们检查物理计划时，显示使用了哈希分区，并且我们将对`userID`值进行哈希处理。因此，我们扫描所有 RDD 和所有具有相同哈希的键，并将其发送到相同的执行程序以实现我们的目标：

！[](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-bgdt-anlt-pyspark/img/d4014b30-3c14-4244-8bdd-4ed9875fa4d4.png)

在下一节中，我们将测试在 Apache Spark 中导致洗牌的操作。

# 在 Apache Spark 中进行导致洗牌的测试操作

在本节中，我们将测试在 Apache Spark 中导致洗牌的操作。我们将涵盖以下主题：

+   使用 join 连接两个 DataFrame

+   使用分区不同的两个 DataFrame

+   测试导致洗牌的连接

连接是一种特定的操作，会导致洗牌，我们将使用它来连接我们的两个 DataFrame。我们将首先检查它是否会导致洗牌，然后我们将检查如何避免它。为了理解这一点，我们将使用两个分区不同的 DataFrame，并检查连接两个未分区或随机分区的数据集或 DataFrame 的操作。如果它们位于不同的物理机器上，将会导致洗牌，因为没有办法连接具有相同分区键的两个数据集。

在我们连接数据集之前，我们需要将它们发送到同一台物理机器上。我们将使用以下测试。

我们需要创建`UserData`，这是一个我们已经见过的案例类。它有用户 ID 和数据。我们有用户 ID，即`user_1`，`user_2`和`user_4`：

```py
test("example of operation that is causing shuffle") {
    import spark.sqlContext.implicits._
    val userData =
    spark.sparkContext.makeRDD(List(
        UserData("user_1", "1"),
        UserData("user_2", "2"),
        UserData("user_4", "200")
    )).toDS()
```

然后我们创建一些类似于用户 ID（`user_1`，`user_2`和`user_3`）的交易数据：

```py
val transactionData =
    spark.sparkContext.makeRDD(List(
        UserTransaction("user_1", 100),
        UserTransaction("user_2", 300),
        UserTransaction("user_3", 1300)
    )).toDS()
```

我们使用`joinWith`在`UserData`上的交易，使用`UserData`和`transactionData`的`userID`列。由于我们发出了`inner`连接，结果有两个元素，因为记录和交易之间有连接，即`UserData`和`UserTransaction`。但是，`UserData`没有交易，`Usertransaction`没有用户数据：

```py
//shuffle: userData can stay on the current executors, but data from
//transactionData needs to be send to those executors according to joinColumn
//causing shuffle
//when
val res: Dataset[(UserData, UserTransaction)]
= userData.joinWith(transactionData, userData("userId") === transactionData("userId"), "inner")
```

当我们连接数据时，数据没有分区，因为这是 Spark 的一些随机数据。它无法知道用户 ID 列是分区键，因为它无法猜测。由于它没有预分区，要连接来自两个数据集的数据，需要将数据从用户 ID 发送到执行器。因此，由于数据没有分区，将会有大量数据从执行器洗牌。

让我们解释查询，执行断言，并通过启动测试显示结果：

```py
//then
 res.show()
 assert(res.count() == 2)
 }
}
```

我们可以看到我们的结果如下：

```py
+------------+-------------+
|         _1 |           _2|
+----------- +-------------+
+ [user_1,1] | [user_1,100]|
| [user_2,2] | [user_2,300]|
+------------+-------------+
```

我们有`[user_1,1]`和`[user_1,100]`，即`userID`和`userTransaction`。看起来连接工作正常，但让我们看看物理参数。我们使用`SortMergeJoin`对第一个数据集和第二个数据集使用`userID`，然后我们使用`Sort`和`hashPartitioning`。

在前一节中，*检测过程中的洗牌*，我们使用了`partition`方法，该方法在底层使用了`hashPartitioning`。虽然我们使用了`join`，但我们仍然需要使用哈希分区，因为我们的数据没有正确分区。因此，我们需要对第一个数据集进行分区，因为会有大量的洗牌，然后我们需要对第二个 DataFrame 做完全相同的事情。再次，洗牌将会进行两次，一旦数据根据连接字段进行分区，连接就可以在执行器本地进行。

在执行物理计划后，将对记录进行断言，指出`userID`用户数据一与用户交易`userID`一位于同一执行器上。没有`hashPartitioning`，就没有保证，因此我们需要进行分区。

在下一节中，我们将学习如何更改具有广泛依赖的作业的设计，因此我们将看到如何在连接两个数据集时避免不必要的洗牌。

# 更改具有广泛依赖的作业的设计

在本节中，我们将更改在未分区数据上执行`join`的作业。我们将更改具有广泛依赖的作业的设计。

在本节中，我们将涵盖以下主题：

+   使用公共分区键对 DataFrame 进行重新分区

+   理解使用预分区数据进行连接

+   理解我们如何避免洗牌

我们将在 DataFrame 上使用`repartition`方法，使用一个公共分区键。我们发现，当进行连接时，重新分区会在底层发生。但通常，在使用 Spark 时，我们希望在 DataFrame 上执行多个操作。因此，当我们与其他数据集执行连接时，`hashPartitioning`将需要再次执行。如果我们在加载数据时进行分区，我们将避免再次分区。

在这里，我们有我们的示例测试用例，其中包含我们之前在 Apache Spark 的“导致洗牌的测试操作”部分中使用的数据。我们有`UserData`，其中包含三条用户 ID 的记录 - `user_1`，`user_2`和`user_4` - 以及`UserTransaction`数据，其中包含用户 ID - 即`user_1`，`user_2`，`user_3`：

```py
test("example of operation that is causing shuffle") {
    import spark.sqlContext.implicits._
    val userData =
        spark.sparkContext.makeRDD(List(
            UserData("user_1", "1"),
            UserData("user_2", "2"),
            UserData("user_4", "200")
        )).toDS()
```

然后，我们需要对数据进行`repartition`，这是要做的第一件非常重要的事情。我们使用`userId`列来重新分区我们的`userData`：

```py
val repartitionedUserData = userData.repartition(userData("userId"))
```

然后，我们将使用`userId`列重新分区我们的数据，这次是针对`transactionData`：

```py
 val repartitionedTransactionData = transactionData.repartition(transactionData("userId"))
```

一旦我们重新分区了我们的数据，我们就可以确保具有相同分区键的任何数据 - 在本例中是`userId` - 将落在同一个执行器上。因此，我们的重新分区数据将不会有洗牌，连接将更快。最终，我们能够进行连接，但这次我们连接的是预分区的数据：

```py
//when
//data is already partitioned using join-column. Don't need to shuffle
val res: Dataset[(UserData, UserTransaction)]
= repartitionedUserData.joinWith(repartitionedTransactionData, userData("userId") === transactionData("userId"), "inner")
```

我们可以使用以下代码显示我们的结果：

```py
 //then
 res.show()
 assert(res.count() == 2)
 }
}
```

输出显示在以下截图中：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-bgdt-anlt-pyspark/img/74702856-ff35-41d9-9e4b-25370715cf4c.png)

在上述截图中，我们有用户 ID 和交易的物理计划。我们对用户 ID 数据和交易数据的用户 ID 列执行了哈希分区。在连接数据之后，我们可以看到数据是正确的，并且连接有一个物理计划。

这次，物理计划有点不同。

我们有一个`SortMergeJoin`操作，并且我们正在对我们的数据进行排序，这些数据在我们执行引擎的上一步已经预分区。这样，我们的 Spark 引擎将执行排序合并连接，无需进行哈希连接。它将正确排序数据，连接将更快。

在下一节中，我们将使用`keyBy()`操作来进一步减少洗牌。

# 使用 keyBy()操作来减少洗牌

在本节中，我们将使用`keyBy()`操作来减少洗牌。我们将涵盖以下主题：

+   加载随机分区的数据

+   尝试以有意义的方式预分区数据

+   利用`keyBy()`函数

我们将加载随机分区的数据，但这次使用 RDD API。我们将以有意义的方式重新分区数据，并提取底层正在进行的信息，类似于 DataFrame 和 Dataset API。我们将学习如何利用`keyBy()`函数为我们的数据提供一些结构，并在 RDD API 中引起预分区。

本节中我们将使用以下测试。我们创建两个随机输入记录。第一条记录有一个随机用户 ID，`user_1`，第二条记录有一个随机用户 ID，`user_1`，第三条记录有一个随机用户 ID，`user_2`：

```py
test("Should use keyBy to distribute traffic properly"){
    //given
    val rdd = spark.sparkContext.makeRDD(List(
        InputRecord("1234-3456-1235-1234", "user_1"),
        InputRecord("1123-3456-1235-1234", "user_1"),
        InputRecord("1123-3456-1235-9999", "user_2")
    ))
```

我们将使用`rdd.toDebugString`提取 Spark 底层发生的情况：

```py
println(rdd.toDebugString)
```

此时，我们的数据是随机分布的，用户 ID 字段的记录可能在不同的执行器上，因为 Spark 执行引擎无法猜测`user_1`是否对我们有意义，或者`1234-3456-1235-1234`是否有意义。我们知道`1234-3456-1235-1234`不是一个有意义的键，而是一个唯一标识符。将该字段用作分区键将给我们一个随机分布和大量的洗牌，因为在使用唯一字段作为分区键时没有数据局部性。

Spark 无法知道相同用户 ID 的数据将落在同一个执行器上，这就是为什么在分区数据时我们需要使用用户 ID 字段，即`user_1`、`user_1`或`user_2`。为了在 RDD API 中实现这一点，我们可以在我们的数据中使用`keyBy(_.userId)`，但这次它将改变 RDD 类型：

```py
val res = rdd.keyBy(_.userId)
```

如果我们检查 RDD 类型，我们会发现这次，RDD 不是输入记录，而是字符串和输入记录的 RDD。字符串是我们在这里期望的字段类型，即`userId`。我们还将通过在结果上使用`toDebugString`来提取有关`keyBy()`函数的信息：

```py
println(res.toDebugString)
```

一旦我们使用`keyBy()`，相同用户 ID 的所有记录都将落在同一个执行器上。正如我们所讨论的，这可能是危险的，因为如果我们有一个倾斜的键，这意味着我们有一个具有非常高基数的键，我们可能会耗尽内存。此外，结果上的所有操作都将按键进行，因此我们将在预分区数据上进行操作：

```py
res.collect()
```

让我们开始这个测试。输出将如下所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-bgdt-anlt-pyspark/img/b3deb20a-fd50-456f-bd7e-30bd4a636036.png)

我们可以看到我们的第一个调试字符串非常简单，我们只有 RDD 上的集合，但第二个有点不同。我们有一个`keyBy()`方法，并在其下面创建了一个 RDD。我们有来自第一部分的子 RDD 和父 RDD，即*测试在 Apache Spark 中引起洗牌的操作*，当我们扩展了 RDD 时。这是由`keyBy()`方法发出的父子链。

在下一节中，我们将使用自定义分区器进一步减少洗牌。

# 使用自定义分区器来减少洗牌

在本节中，我们将使用自定义分区器来减少洗牌。我们将涵盖以下主题：

+   实现自定义分区器

+   使用`partitionBy`方法在 Spark 上使用分区器

+   验证我们的数据是否被正确分区

我们将使用自定义逻辑实现自定义分区器，该分区器将对数据进行分区。它将告诉 Spark 每条记录应该落在哪个执行器上。我们将使用 Spark 上的`partitionBy`方法。最后，我们将验证我们的数据是否被正确分区。为了测试的目的，我们假设有两个执行器：

```py
import com.tomekl007.UserTransaction
import org.apache.spark.sql.SparkSession
import org.apache.spark.{Partitioner, SparkContext}
import org.scalatest.FunSuite
import org.scalatest.Matchers._

class CustomPartitioner extends FunSuite {
val spark: SparkContext = SparkSession.builder().master("local[2]").getOrCreate().sparkContext

test("should use custom partitioner") {
//given
val numberOfExecutors = 2
```

假设我们想将我们的数据均匀地分成`2`个执行器，并且具有相同键的数据实例将落在同一个执行器上。因此，我们的输入数据是一个`UserTransactions`列表：`"a"`,`"b"`,`"a"`,`"b"`和`"c"`。值并不那么重要，但我们需要记住它们以便稍后测试行为。给定`UserTransactions`的`amount`分别为`100`,`101`,`202`,`1`和`55`：

```py
val data = spark
    .parallelize(List(
        UserTransaction("a", 100),
        UserTransaction("b", 101),
        UserTransaction("a", 202),
        UserTransaction("b", 1),
        UserTransaction("c", 55)
```

当我们使用`keyBy`时，`(_.userId)`被传递给我们的分区器，因此当我们发出`partitionBy`时，我们需要扩展`override`方法：

```py
).keyBy(_.userId)
.partitionBy(new Partitioner {
    override def numPartitions: Int = numberOfExecutors
```

`getPartition`方法接受一个`key`，它将是`userId`。键将在这里传递，类型将是字符串：

```py
override def getPartition(key: Any): Int = {
    key.hashCode % numberOfExecutors
    }
})
```

这些方法的签名是`Any`，所以我们需要`override`它，并且还需要覆盖分区的数量。

然后我们打印我们的两个分区，`numPartitions`返回值为`2`：

```py
println(data.partitions.length)
```

`getPartition`非常简单，因为它获取`hashCode`和`numberOfExecutors`的模块。它确保相同的键将落在同一个执行器上。

然后，我们将为各自的分区映射每个分区，因为我们得到一个迭代器。在这里，我们正在为测试目的获取`amount`：

```py
//when
val res = data.mapPartitionsLong.map(_.amount)
).collect().toList
```

最后，我们断言`55`,`100`,`202`,`101`和`1`；顺序是随机的，所以不需要关心顺序：

```py
//then
res should contain theSameElementsAs List(55, 100, 202, 101, 1)
}
}
```

如果我们仍然希望，我们应该使用`sortBy`方法。让我们开始这个测试，看看我们的自定义分区器是否按预期工作。现在，我们可以开始了。我们有`2`个分区，所以它按预期工作，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-bgdt-anlt-pyspark/img/b29036a1-2b48-4d1b-a9c1-5c99d1d65299.png)

# 总结

在本章中，我们学习了如何检测过程中的洗牌。我们涵盖了在 Apache Spark 中导致洗牌的测试操作。我们还学习了如何在 RDD 中使用分区。如果需要分区数据，了解如何使用 API 是很重要的，因为 RDD 仍然被广泛使用，所以我们使用`keyBy`操作来减少洗牌。我们还学习了如何使用自定义分区器来减少洗牌。

在下一章中，我们将学习如何使用 Spark API 以正确的格式保存数据。


# 第十章：将数据保存在正确的格式中

在之前的章节中，我们专注于处理和加载数据。我们学习了有关转换、操作、连接、洗牌和 Spark 的其他方面。

在本章中，我们将学习如何以正确的格式保存数据，还将使用 Spark 的标准 API 以纯文本格式保存数据。我们还将利用 JSON 作为数据格式，并学习如何使用标准 API 保存 JSON。Spark 有 CSV 格式，我们也将利用该格式。然后，我们将学习更高级的基于模式的格式，其中需要支持导入第三方依赖项。接下来，我们将使用 Avro 与 Spark，并学习如何使用和保存列格式的数据，即 Parquet。到本章结束时，我们还将学会如何检索数据以验证其是否以正确的方式存储。

在本章中，我们将涵盖以下主题：

+   以纯文本格式保存数据

+   利用 JSON 作为数据格式

+   表格式 - CSV

+   使用 Avro 与 Spark

+   列格式 - Parquet

# 以纯文本格式保存数据

在本节中，我们将学习如何以纯文本格式保存数据。将涵盖以下主题：

+   以纯文本格式保存数据

+   加载纯文本数据

+   测试

我们将以纯文本格式保存我们的数据，并研究如何将其保存到 Spark 目录中。然后我们将加载纯文本数据，然后测试并保存以检查我们是否可以产生相同的结果代码。这是我们的`SavePlainText.scala`文件：

```py
package com.tomekl007.chapter_4

import java.io.File

import com.tomekl007.UserTransaction
import org.apache.spark.sql.SparkSession
import org.apache.spark.{Partitioner, SparkContext}
import org.scalatest.{BeforeAndAfterEach, FunSuite}
import org.scalatest.Matchers._

import scala.reflect.io.Path

class SavePlainText extends FunSuite with BeforeAndAfterEach{
    val spark: SparkContext = SparkSession.builder().master("local[2]").getOrCreate().sparkContext

    private val FileName = "transactions.txt"

    override def afterEach() {
        val path = Path (FileName)
        path.deleteRecursively()
    }

    test("should save and load in plain text") {
        //given
        val rdd = spark.makeRDD(List(UserTransaction("a", 100), UserTransaction("b", 200)))

        //when
        rdd.coalesce(1).saveAsTextFile(FileName)

        val fromFile = spark.textFile(FileName)

        fromFile.collect().toList should contain theSameElementsAs List(
            "UserTransaction(a,100)", "UserTransaction(b,200)"
            //note - this is string!
        )
    }
}
```

我们将需要一个`FileName`变量，在我们的情况下，它将是一个文件夹名称，然后 Spark 将在其下创建一些文件：

```py
import java.io.File
import com.tomekl007.UserTransaction
import org.apache.spark.sql.SparkSession
import org.apache.spark.{Partitioner, SparkContext}
import org.scalatest.{BeforeAndAfterEach, FunSuite}
import org.scalatest.Matchers._
import scala.reflect.io.Path
class SavePlainText extends FunSuite with BeforeAndAfterEach{
    val spark: SparkContext = SparkSession.builder().master("local[2]").getOrCreate().sparkContext
    private val FileName = "transactions.txt"
```

我们将在我们的测试用例中使用`BeforeAndAfterEach`来清理我们的目录，这意味着路径应该被递归删除。测试后整个路径将被删除，因为需要重新运行测试而没有失败。我们需要注释掉以下代码，以便在第一次运行时调查保存的文本文件的结构：

```py
//override def afterEach() {
//         val path = Path (FileName)
//         path.deleteRecursively()
//     }

//test("should save and load in plain text") {
```

然后我们将创建两个交易的 RDD，`UserTransaction("a", 100)`和`UserTransaction("b", 200)`：

```py
val rdd = spark.makeRDD(List(UserTransaction("a", 100), UserTransaction("b", 200)))
```

然后，我们将我们的数据合并为一个分区。`coalesce()`是一个非常重要的方面。如果我们想将数据保存在单个文件中，我们需要将其合并为一个，但这样做有一个重要的含义：

```py
rdd.coalesce(1).saveAsTextFile(FileName)
```

如果我们将其合并为一个文件，那么只有一个执行程序可以将数据保存到我们的系统中。这意味着保存数据将非常缓慢，并且还存在内存不足的风险，因为所有数据将被发送到一个执行程序。通常，在生产环境中，我们根据可用的执行程序将其保存为多个分区，甚至乘以自己的因子。因此，如果我们有 16 个执行程序，那么我们可以将其保存为`64`。但这会导致`64`个文件。出于测试目的，我们将保存为一个文件，如前面的代码片段所示：

```py
rdd.coalesce (numPartitions = 1).saveAsTextFile(FileName)
```

现在，我们将加载数据。我们只需要将文件名传递给`TextFile`方法，它将返回`fromFile`：

```py
    val fromFile = spark.textFile(FileName)
```

然后我们断言我们的数据，这将产生`theSameElementsAS List`，`UserTransaction(a,100)`和`UserTransaction(b,200)`：

```py
    fromFile.collect().toList should contain theSameElementsAs List(
      "UserTransaction(a,100)", "UserTransaction(b,200)"
      //note - this is string!
    )
  }
}
```

需要注意的重要事项是，对于字符串列表，Spark 不知道我们的数据模式，因为我们将其保存为纯文本。

这是在保存纯文本时需要注意的一点，因为加载数据并不容易，因为我们需要手动将每个字符串映射到`UserTransaction`。因此，我们将不得不手动解析每条记录，但是，出于测试目的，我们将把我们的交易视为字符串。

现在，让我们开始测试并查看创建的文件夹的结构：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-bgdt-anlt-pyspark/img/8d1da1f2-4d80-4e73-ac6d-ac20b973bf51.png)

在前面的屏幕截图中，我们可以看到我们的测试通过了，我们得到了`transactions.txt`。在文件夹中，我们有四个文件。第一个是`._SUCCESS.crc`，这意味着保存成功。接下来，我们有`.part-00000.crc`，用于控制和验证一切是否正常工作，这意味着保存是正确的。然后，我们有`_SUCCESS`和`part-00000`，这两个文件都有校验和，但`part-00000`也包含了所有的数据。然后，我们还有`UserTransaction(a,100)`和`UserTransaction(b,200)`：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-bgdt-anlt-pyspark/img/a829d808-2760-4b34-bdf4-6e4b5a64fc13.png)

在下一节中，我们将学习如果增加分区数量会发生什么。

# 利用 JSON 作为数据格式

在本节中，我们将利用 JSON 作为数据格式，并将我们的数据保存为 JSON。以下主题将被涵盖：

+   以 JSON 格式保存数据

+   加载 JSON 数据

+   测试

这些数据是人类可读的，并且比简单的纯文本给我们更多的含义，因为它携带了一些模式信息，比如字段名。然后，我们将学习如何以 JSON 格式保存数据并加载我们的 JSON 数据。

我们将首先创建一个`UserTransaction("a", 100)`和`UserTransaction("b", 200)`的 DataFrame，并使用`.toDF()`保存 DataFrame API：

```py
val rdd = spark.sparkContext
         .makeRDD(List(UserTransaction("a", 100), UserTransaction("b", 200)))
         .toDF()
```

然后我们将发出`coalesce()`，这次我们将取值为`2`，并且我们将得到两个结果文件。然后我们将发出`write.format`方法，并且需要指定一个格式，我们将使用`json`格式：

```py
rdd.coalesce(2).write.format("json").save(FileName)
```

如果我们使用不支持的格式，我们将得到一个异常。让我们通过将源输入为`not`来测试这一点：

```py
rdd.coalesce(2).write.format("not").save(FileName)
```

我们将得到诸如“此格式不是预期的”、“找不到数据源：not”和“没有这样的数据源”等异常：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-bgdt-anlt-pyspark/img/6c3f7d35-803b-470a-bea8-be3b9f91940a.png)

在我们原始的 JSON 代码中，我们将指定格式，并且需要将其保存到`FileName`。如果我们想要读取，我们需要将其指定为`read`模式，并且还需要添加一个文件夹的路径：

```py
val fromFile = spark.read.json(FileName)
```

在这种情况下，让我们注释掉`afterEach()`来调查生成的 JSON：

```py
// override def afterEach() {
// val path = Path(FileName)
// path.deleteRecursively()
// }
```

让我们开始测试：

```py
 fromFile.show()
 assert(fromFile.count() == 2)
 }
}
```

输出如下：

```py
+------+------+
|amount|userId|
|   200|     b|
|   100|     a|
+------+------+
```

在前面的代码输出中，我们可以看到我们的测试通过了，并且 DataFrame 包含了所有有意义的数据。

从输出中，我们可以看到 DataFrame 具有所需的所有模式。它有`amount`和`userId`，这非常有用。

`transactions.json`文件夹有两部分——一部分是`r-00000`，另一部分是`r-00001`，因为我们发出了两个分区。如果我们在生产系统中保存数据有 100 个分区，我们最终会得到 100 个部分文件，而且每个部分文件都会有一个 CRC 校验和文件。

这是第一个文件：

```py
{"userId":"a","amount":"100"}
```

在这里，我们有一个带有模式的 JSON 文件，因此我们有一个`userID`字段和`amount`字段。

另一方面，我们有第二个文件，其中包含第二条记录，包括`userID`和`amount`：

```py
{"userId":"b","amount":"200"}
```

这样做的好处是 Spark 能够从模式中推断出数据，并且以格式化的 DataFrame 加载，具有适当的命名和类型。然而，缺点是每条记录都有一些额外的开销。每条记录都需要在其中有一个字符串，并且在每个字符串中，如果我们有一个包含数百万个文件的文件，并且我们没有对其进行压缩，那么将会有相当大的开销，这是不理想的。

JSON 是人类可读的，但另一方面，它消耗了大量资源，就像 CPU 用于压缩、读取和写入，以及磁盘和内存用于开销一样。除了 JSON 之外，还有更好的格式，我们将在接下来的部分中介绍。

在下一节中，我们将查看表格格式，我们将介绍一个经常用于导入到 Microsoft Excel 或 Google 电子表格的 CSV 文件。这对数据科学家也是非常有用的格式，但仅在使用较小的数据集时。

# 表格式——CSV

在本节中，我们将介绍文本数据，但以表格格式——CSV。以下主题将被涵盖：

+   以 CSV 格式保存数据

+   加载 CSV 数据

+   测试

保存 CSV 文件比 JSON 和纯文本更复杂，因为我们需要指定是否要在 CSV 文件中保留数据的头信息。

首先，我们将创建一个 DataFrame：

```py
test("should save and load CSV with header") {
 //given
 import spark.sqlContext.implicits._
 val rdd = spark.sparkContext
 .makeRDD(List(UserTransaction("a", 100), UserTransaction("b", 200)))
 .toDF()
```

然后，我们将使用`write`格式 CSV。我们还需要指定我们不想在其中包含`header`选项：

```py
//when
rdd.coalesce(1)
    .write
    .format("csv")
    .option("header", "false")
    .save(FileName)
```

然后，我们将进行测试以验证条件是`true`还是`false`：

```py
    //when
    rdd.coalesce(1)
      .write
      .format("csv")
      .option("header", "true")
      .save(FileName)  
```

此外，我们无需添加任何额外的依赖来支持 CSV，如以前的版本所需。

然后，我们将指定应该与`write`模式相似的`read`模式，并且我们需要指定是否有`header`：

```py
val fromFile = spark.read.option("header", "false").csv(FileName)
```

让我们开始测试并检查输出：

```py
+---+---+
|_c0|_c1|
+---+---+
|  a|100|
|  b|200|
+---+---+
```

在前面的代码输出中，我们可以看到数据已加载，但我们丢失了我们的模式。`c0`和`c1`是由 Spark 创建的列 0（`c0`）和列 1（`c1`）的别名。

因此，如果我们指定`header`应保留该信息，让我们在`write`和`read`时指定`header`：

```py
val fromFile = spark.read.option("header", "true).csv(FileName)
```

我们将指定`header`应保留我们的信息。在以下输出中，我们可以看到关于模式的信息在读写操作中被感知到：

```py
+------+------+
|userId|amount|
+------+------+
|     a|   100|
|     b|   200|
+------+------+
```

让我们看看如果我们在`write`时使用`header`，而在`read`时不使用它会发生什么。我们的测试应该失败，如下面的代码截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-bgdt-anlt-pyspark/img/0b41f63f-a78b-462a-b058-f27cde819782.png)

在前面的截图中，我们可以看到我们的测试失败了，因为我们没有模式，因为我们在没有头的情况下进行读取。第一条记录，也就是`header`，被视为列值。

让我们尝试一个不同的情况，我们在没有`header`的情况下进行写入，并在有`header`的情况下进行读取：

```py
  //when
 rdd.coalesce(1)
     .write
     .format("csv")
     .option("header", "false")
     .save(FileName)

val fromFile = spark.read.option("header", "false").csv(FileName)
```

我们的测试将再次失败，因为这一次，我们将我们的第一条记录视为头记录。

让我们将读和写操作都设置为`header`并在之前添加的注释后测试我们的代码：

```py
override def afterEach() {
    val path = Path(FileName)
    path.deleteRecursively()
}
```

CSV 和 JSON 文件将具有模式，但开销较小。因此，它甚至可能比 JSON 更好。

在下一节中，我们将看到如何将基于模式的格式作为整体与 Spark 一起使用。

# 使用 Avro 与 Spark

到目前为止，我们已经看过基于文本的文件。我们使用纯文本、JSON 和 CSV。JSON 和 CSV 比纯文本更好，因为它们携带了一些模式信息。

在本节中，我们将研究一个名为 Avro 的高级模式。将涵盖以下主题：

+   以 Avro 格式保存数据

+   加载 Avro 数据

+   测试

Avro 具有嵌入其中的模式和数据。这是一种二进制格式，不是人类可读的。我们将学习如何以 Avro 格式保存数据，加载数据，然后进行测试。

首先，我们将创建我们的用户交易：

```py
 test("should save and load avro") {
 //given
 import spark.sqlContext.implicits._
 val rdd = spark.sparkContext
     .makeRDD(List(UserTransaction("a", 100), UserTransaction("b", 200)))
     .toDF()
```

然后我们将进行`coalesce`并写入 Avro：

```py
 //when
 rdd.coalesce(2)
     .write
     .avro(FileName)
```

在使用 CSV 时，我们指定了像 CSV 这样的格式，当我们指定 JSON 时，这也是一个格式。但是在 Avro 中，我们有一个方法。这种方法不是标准的 Spark 方法；它来自第三方库。为了具有 Avro 支持，我们需要访问`build.sbt`并从`com.databricks`添加`spark-avro`支持。

然后我们需要导入适当的方法。我们将导入`com.databricks.spark.avro._`以给我们扩展 Spark DataFrame 的隐式函数：

```py
import com.databricks.spark.avro._
```

实际上我们正在使用一个 Avro 方法，我们可以看到`implicit class`接受一个`DataFrameWriter`类，并以 Spark 格式写入我们的数据。

在我们之前使用的`coalesce`代码中，我们可以使用`write`，指定格式，并执行`com.databricks.spark.avro`类。`avro`是一个快捷方式，不需要将`com.databricks.spark.avro`作为整个字符串写入：

```py
//when
 rdd.coalesce(2)
     .write.format(com.databricks.spark.avro)
     .avro(FileName)
```

简而言之，无需指定格式；只需应用隐式`avro`方法。

让我们注释掉代码并删除 Avro 以检查它是如何保存的：

```py
// override def afterEach() {
    // val path = Path(FileName)
    // path.deleteRecursively()
// }
```

如果我们打开`transactions.avro`文件夹，我们有两部分——`part-r-00000`和`part-r-00001`。

第一部分将包含二进制数据。它由许多二进制记录和一些人类可读的数据组成，这就是我们的模式：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-bgdt-anlt-pyspark/img/ea76f872-a5d0-4c5d-a5eb-440c5d453832.png)

我们有两个字段 - `user ID`，它是一个字符串类型或空值，和`name`：`amount`，它是一个整数。作为原始类型，JVM 不能有空值。需要注意的重要事情是，在生产系统中，我们必须保存非常大的数据集，将有成千上万条记录。模式始终在每个文件的第一行。如果我们检查第二部分，我们将看到完全相同的模式，然后是二进制数据。

通常，如果有复杂的模式，我们只有一行或更多行，但仍然是非常少量的数据。

我们可以看到在生成的数据集中，我们有`userID`和`amount`：

```py
+------+------+
|userId|amount|
+------+------+
|     a|   100|
|     b|   200|
+------+------+
```

在上面的代码块中，我们可以看到模式被描绘在文件中。虽然它是一个二进制文件，但我们可以提取它。

在下一节中，我们将研究列格式 - Parquet。

# 列格式 - Parquet

在本节中，我们将研究第二种基于模式的格式 Parquet。将涵盖以下主题：

+   以 Parquet 格式保存数据

+   加载 Parquet 数据

+   测试

这是一种列格式，因为数据是以列方式存储的，而不是以行方式，就像我们在 JSON、CSV、纯文本和 Avro 文件中看到的那样。

这是一个非常有趣和重要的大数据处理格式，可以加快处理过程。在本节中，我们将专注于向 Spark 添加 Parquet 支持，将数据保存到文件系统中，重新加载数据，然后进行测试。Parquet 与 Avro 类似，因为它提供了一个`parquet`方法，但这次是一个稍微不同的实现。

在`build.sbt`文件中，对于 Avro 格式，我们需要添加外部依赖，但对于 Parquet，我们已经在 Spark 中有了该依赖。因此，Parquet 是 Spark 的首选，因为它包含在标准包中。

让我们来看看`SaveParquet.scala`文件中用于保存和加载 Parquet 文件的逻辑。

首先，我们合并了两个分区，指定了格式，然后指定我们要保存`parquet`：

```py
package com.tomekl007.chapter_4

import com.databricks.spark.avro._
import com.tomekl007.UserTransaction
import org.apache.spark.sql.SparkSession
import org.scalatest.{BeforeAndAfterEach, FunSuite}

import scala.reflect.io.Path

class SaveParquet extends FunSuite with BeforeAndAfterEach {
  val spark = SparkSession.builder().master("local[2]").getOrCreate()

  private val FileName = "transactions.parquet"

  override def afterEach() {
    val path = Path(FileName)
    path.deleteRecursively()
  }

  test("should save and load parquet") {
    //given
    import spark.sqlContext.implicits._
    val rdd = spark.sparkContext
      .makeRDD(List(UserTransaction("a", 100), UserTransaction("b", 200)))
      .toDF()

    //when
    rdd.coalesce(2)
      .write
      .parquet(FileName)
```

`read`方法也实现了完全相同的方法：

```py
    val fromFile = spark.read.parquet(FileName)

    fromFile.show()
    assert(fromFile.count() == 2)
  }

}
```

让我们开始这个测试，但在此之前，我们将在`SaveParquet.scala`文件中注释掉以下代码，以查看文件的结构：

```py
//    override def afterEach() {
//    val path = Path(FileName)
//    path.deleteRecursively()
//  } 
```

创建了一个新的`transactions.parquet`文件夹，里面有两个部分 - `part-r-00000`和`part-r-00001`。但这次，格式完全是二进制的，并且嵌入了一些元数据。

我们嵌入了元数据，还有`amount`和`userID`字段，它们是`string`类型。`r-00000`部分完全相同，并且嵌入了模式。因此，Parquet 也是一种基于模式的格式。当我们读取数据时，我们可以看到我们有`userID`和`amount`列可用。

# 摘要

在本章中，我们学习了如何以纯文本格式保存数据。我们注意到，当我们没有正确加载数据时，模式信息会丢失。然后我们学习了如何利用 JSON 作为数据格式，并发现 JSON 保留了模式，但它有很多开销，因为模式是针对每条记录的。然后我们了解了 CSV，并发现 Spark 对其有嵌入支持。然而，这种方法的缺点是模式不是关于特定类型的记录，并且需要隐式推断制表符。在本章的最后，我们介绍了 Avro 和 Parquet，它们具有列格式，也嵌入了 Spark。

在下一章中，我们将使用 Spark 的键/值 API。


# 第十一章：使用 Spark 键/值 API

在本章中，我们将使用 Spark 键/值 API。我们将首先查看可用的键/值对转换。然后，我们将学习如何使用`aggregateByKey`方法而不是`groupBy()`方法。稍后，我们将研究键/值对的操作，并查看可用的键/值数据分区器。在本章结束时，我们将实现一个高级分区器，该分区器将能够按范围对我们的数据进行分区。

在本章中，我们将涵盖以下主题：

+   可用的键/值对操作

+   使用`aggregateByKey`而不是`groupBy()`

+   键/值对操作

+   可用的键/值数据分区器

+   实现自定义分区器

# 可用的键/值对操作

在本节中，我们将涵盖以下主题：

+   可用的键/值对转换

+   使用`countByKey()`

+   了解其他方法

因此，这是我们众所周知的测试，我们将在其中使用键/值对的转换。

首先，我们将为用户`A`，`B`，`A`，`B`和`C`创建一个用户交易数组，以某种金额，如下例所示：

```py
 val keysWithValuesList =
 Array(
 UserTransaction("A", 100),
 UserTransaction("B", 4),
 UserTransaction("A", 100001),
 UserTransaction("B", 10),
 UserTransaction("C", 10)
 )
```

然后，根据以下示例，我们需要按特定字段对数据进行键入：

```py
val keyed = data.keyBy(_.userId)
```

我们将通过调用`keyBy`方法并使用`userId`参数对其进行键入。

现在，我们的数据分配给了`keyed`变量，其类型为元组。第一个元素是字符串，即`userId`，第二个元素是`UserTransaction`。

让我们看一下可用的转换。首先，我们将看看`countByKey`。

让我们看一下它的实现，如下例所示：

```py
val data = spark.parallelize(keysWithValuesList)
 val keyed = data.keyBy(_.userId)
//when
 val counted = keyed.countByKey()
// keyed.combineByKey()
// keyed.aggregateByKey()
// keyed.foldByKey()
// keyed.groupByKey()
//then
 counted should contain theSameElementsAs Map("B" -> 2, "A" -> 2, "C" -> 1)
```

这将返回一个`Map`，键`K`和`Long`是一种通用类型，因为它可以是任何类型的键。在本例中，键将是一个字符串。每个返回映射的操作都不是完全安全的。如果您看到返回映射的方法的签名，这表明这些数据将被发送到驱动程序，并且需要适合内存。如果有太多的数据无法适应一个驱动程序的内存，那么我们将耗尽内存。因此，在使用此方法时，我们需要谨慎。

然后，我们执行一个包含与地图相同元素的断言计数，如下例所示：

```py
counted should contain theSameElementsAs Map("B" -> 2, "A" -> 2, "C" -> 1)
```

`B`是`2`，因为我们有两个值。另外，`A`与`C`类似，因为它们只有一个值。`countByKey()`不占用内存，因为它只存储键和计数器。但是，如果键是一个复杂且大的对象，例如具有多个字段的交易，超过两个，那么该映射可能会非常大。

但让我们从下面的例子开始这个测试：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-bgdt-anlt-pyspark/img/18dbf0ad-9949-4e70-acfc-f826330185be.png)

从前面的屏幕截图中，我们可以看到我们的测试通过了。

我们还有一个`combineByKey()`方法，它将相同键的相同元素组合在一起，并共享负面的`aggregateByKey()`，能够聚合不同类型。我们有`foldByKey`，它正在获取当前状态和值，但返回与键的值相同的类型。

我们还有`groupByKey()`，我们在上一节中了解过。这将根据特定键对所有内容进行分组，并返回键的值迭代器。这也是一个非常占用内存的操作，因此在使用时需要小心。

在下一节中，我们将使用`aggregateByKey`而不是`groupBy`。我们将学习`groupBy`的工作原理并修复其缺陷。

# 使用`aggregateByKey`而不是`groupBy()`

在本节中，我们将探讨为什么我们使用`aggregateByKey`而不是`groupBy`。

我们将涵盖以下主题：

+   为什么我们应该避免使用`groupByKey`

+   `aggregateByKey`给我们的是什么

+   使用`aggregateByKey`实现逻辑

首先，我们将创建我们的用户交易数组，如下例所示：

```py
 val keysWithValuesList =
 Array(
 UserTransaction("A", 100),
 UserTransaction("B", 4),
 UserTransaction("A", 100001),
 UserTransaction("B", 10),
 UserTransaction("C", 10)
 )
```

然后，我们将使用`parallelize`创建一个 RDD，因为我们希望我们的数据按键排序。这在下面的例子中显示：

```py
 val data = spark.parallelize(keysWithValuesList)
 val keyed = data.keyBy(_.userId)
```

在前面的代码中，我们调用了`keyBy`来对`userId`进行操作，以获得付款人、键和用户交易的数据。

让我们假设我们想要聚合，我们想要对相同的键执行一些特定的逻辑，如下面的例子所示：

```py
 val aggregatedTransactionsForUserId = keyed
 .aggregateByKey(amountForUser)(addAmount, mergeAmounts)
```

这样做的原因可能是选择最大元素、最小元素或计算平均值。`aggregateByKey`需要接受三个参数，如下面的例子所示：

```py
aggregateByKey(amountForUser)(addAmount, mergeAmounts)
```

第一个参数是 T 类型的初始参数，定义`amountForUser`是一个类型为`ArrayBuffer`的初始参数。这非常重要，因为 Scala 编译器将推断出该类型，并且在这个例子中，参数 1 和 2 需要具有完全相同的类型 T：`ArrayBuffer.empty[long]`。

下一个参数是一个方法，它接受我们正在处理的当前元素。在这个例子中，`transaction: UserTransaction) =>`是一个当前交易，也需要带上我们初始化函数的状态，因此这里将是一个数组缓冲区。

它需要与以下代码块中显示的相同类型，因此这是我们的类型 T：

```py
mutable.ArrayBuffer.empty[Long]
```

在这一点上，我们能够获取任何交易并将其添加到特定状态中。这是以分布式方式完成的。对于一个键，执行在一个执行器上完成，对于完全相同的键，执行在不同的执行器上完成。这是并行进行的，因此对于相同的键将添加多个交易。

现在，Spark 知道，对于完全相同的键，它有多个 T 类型的状态`ArrayBuffer`，需要合并。因此，我们需要为相同的键`mergeAmounts`我们的交易。

`mergeArgument`是一个方法，它接受两个状态，这两个状态都是 T 类型的中间状态，如下面的代码块所示：

```py
 val mergeAmounts = (p1: mutable.ArrayBuffer[Long], p2: mutable.ArrayBuffer[Long]) => p1 ++= p2
```

在这个例子中，我们想要将释放缓冲区合并成一个数组缓冲区。因此，我们发出`p1 ++= p2`。这将两个数组缓冲区合并成一个。

现在，我们已经准备好所有参数，我们能够执行`aggregateByKey`并查看结果是什么样子的。结果是一个字符串和类型 T 的 RDD，`ArrayBuffer[long]`，这是我们的状态。我们将不再在 RDD 中保留`UserTransaction`，这有助于减少内存使用。`UserTransaction`是一个重量级对象，因为它可以有多个字段，在这个例子中，我们只对金额字段感兴趣。因此，这样我们可以减少内存的使用。

下面的例子展示了我们的结果应该是什么样子的：

```py
 aggregatedTransactionsForUserId.collect().toList should contain theSameElementsAs List(
 ("A", ArrayBuffer(100, 100001)),
 ("B", ArrayBuffer(4,10)),
 ("C", ArrayBuffer(10)))
```

我们应该有一个键`A`，和一个`ArrayBuffer`的`100`和`10001`，因为这是我们的输入数据。`B`应该是`4`和`10`，最后，`C`应该是`10`。

让我们开始测试，检查我们是否已经正确实现了`aggregateByKey`，如下面的例子所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-bgdt-anlt-pyspark/img/26cd4ebd-1378-493b-a9d9-3e2b5f821a41.png)

从前面的输出中，我们可以看到它按预期工作。

在下一节中，我们将研究可用于键/值对的操作。

# 键/值对上的操作

在本节中，我们将研究键/值对上的操作。

我们将涵盖以下主题：

+   检查键/值对上的操作

+   使用`collect()`

+   检查键/值 RDD 的输出

在本章的第一部分中，我们介绍了可用于键/值对的转换。我们看到它们与 RDD 相比有些不同。此外，对于操作，结果略有不同，但方法名称并没有变化。

因此，我们将使用`collect()`，并且我们将检查我们对这些键/值对的操作的输出。

首先，我们将根据`userId`创建我们的交易数组和 RDD，如下面的例子所示：

```py
 val keysWithValuesList =
 Array(
 UserTransaction("A", 100),
 UserTransaction("B", 4),
 UserTransaction("A", 100001),
 UserTransaction("B", 10),
 UserTransaction("C", 10)
 )
```

我们首先想到的操作是`collect()`。`collect()`会取出每个元素并将其分配给结果，因此我们的结果与`keyBy`的结果非常不同。

我们的结果是一对键，`userId`和一个值，即`UserTransaction`。我们可以从下面的例子中看到，我们可以有一个重复的键：

```py
 res should contain theSameElementsAs List(
 ("A",UserTransaction("A",100)),
 ("B",UserTransaction("B",4)),
 ("A",UserTransaction("A",100001)),
 ("B",UserTransaction("B",10)),
 ("C",UserTransaction("C",10))
 )//note duplicated key
```

在前面的代码中，我们可以看到同一个订单有多个出现。对于一个简单的字符串键，重复并不是很昂贵。然而，如果我们有一个更复杂的键，那么就会很昂贵。

因此，让我们开始这个测试，如下例所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-bgdt-anlt-pyspark/img/0bcc197e-ee8b-4de6-ae59-4cb32a6655ff.png)

从前面的输出中，我们可以看到我们的测试已经通过。要查看其他动作，我们将查看不同的方法。

如果一个方法返回 RDD，比如`collect[U] (f: PartialFunction[(String, UserTransaction), U])`，这意味着这不是一个动作。如果某些东西返回 RDD，这意味着它不是一个动作。这适用于键/值对。

`collect()`不会返回 RDD，而是返回数组，因此它是一个动作。`count`返回`long`，因此这也是一个动作。`countByKey`返回 map。如果我们想要`reduce`我们的元素，那么这是一个动作，但`reduceByKey`不是一个动作。这就是`reduce`和`reduceByKey`之间的重大区别。

我们可以看到根据 RDD，一切都是正常的，因此动作是相同的，差异只在于转换。

在下一节中，我们将看一下键/值数据上可用的分区器。

# 键/值数据上可用的分区器

我们知道分区和分区器是 Apache Spark 的关键组件。它们影响我们的数据如何分区，这意味着它们影响数据实际驻留在哪些执行器上。如果我们有一个良好的分区器，那么我们将有良好的数据局部性，这将减少洗牌。我们知道洗牌对处理来说是不可取的，因此减少洗牌是至关重要的，因此选择适当的分区器对我们的系统也是至关重要的。

在本节中，我们将涵盖以下主题：

+   检查`HashPartitioner`

+   检查`RangePartitioner`

+   测试

我们将首先检查我们的`HashPartitioner`和`RangePartitioner`。然后我们将比较它们并使用两个分区器测试代码。

首先，我们将创建一个`UserTransaction`数组，如下例所示：

```py
 val keysWithValuesList =
 Array(
 UserTransaction("A", 100),
 UserTransaction("B", 4),
 UserTransaction("A", 100001),
 UserTransaction("B", 10),
 UserTransaction("C", 10)
 )
```

然后我们将使用`keyBy`（如下例所示），因为分区器将自动处理我们数据的键：

```py
 val keyed = data.keyBy(_.userId)
```

然后我们将获取键数据的`partitioner`，如下例所示：

```py
 val partitioner = keyed.partitioner
```

代码显示`partitioner.isEmpty`，因为我们还没有定义任何`partitioner`，因此在这一点上它是空的，如下例所示：

```py
 assert(partitioner.isEmpty)
```

我们可以使用`partitionBy`方法指定一个`partitioner`，如下例所示：

```py
val hashPartitioner = keyed.partitionBy(new HashPartitioner(100))
```

该方法期望一个`partitioner`抽象类的实现。我们将有一些实现，但首先，让我们专注于`HashPartitioner`。

`HashPartitioner`需要一个分区数，并且有一个分区数。`numPartition`返回我们的参数，但`getPartition`会更加复杂，如下例所示：

```py
    def numPartitions: Int = partitions
    def getPartition(key: Any): int = key match {
        case null => 0
        case_ => Utils.nonNegativeMode(key.hashCode, numPartitions)
    }
```

它首先检查我们的`key`是否为`null`。如果是`null`，它将落在分区号`0`。如果我们有带有`null`键的数据，它们都将落在相同的执行器上，正如我们所知，这不是一个好的情况，因为执行器将有很多内存开销，并且它们可能会因为内存异常而失败。

如果`key`不是`null`，那么它会从`hashCode`和分区数中进行`nonNegativeMod`。它必须是分区数的模数，这样它才能分配到适当的分区。因此，`hashCode`方法对我们的键非常重要。

如果我们提供了一个自定义的键而不是像整数或字符串这样的原始类型，它有一个众所周知的`hashCode`，我们需要提供和实现一个适当的`hashCode`。但最佳实践是使用 Scala 中的`case`类，因为它们已经为你实现了`hashCode`和 equals。

我们现在已经定义了`partitioner`，但`partitioner`是可以动态更改的。我们可以将我们的`partitioner`更改为`rangePartitioner`。`rangePartitioner`接受 RDD 中的分区。

`rangePartitioner`更复杂，因为它试图将我们的数据划分为范围，这不像`HashPartitioner`在获取分区时那样简单。该方法非常复杂，因为它试图均匀地分布我们的数据，并且对将其分布到范围中的逻辑非常复杂。

让我们开始我们的测试，检查我们是否能够正确地分配`partitioner`，如下所示的输出：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-bgdt-anlt-pyspark/img/d0cd68c3-e380-4192-895c-307a2cd974ec.png)

我们的测试已经通过。这意味着，在最初的时候，`partitioner`是空的，然后我们必须在`partitionBy`处对 RDD 进行洗牌，还有一个`branchPartitioner`。但它只显示了我们创建`partitioner`接口的实例的数值线。

在下一部分，我们将尝试改进它，或者尝试通过实现自定义分区器来调整和玩弄分区器。

# 实现自定义分区器

在这一部分，我们将实现一个自定义的分区器，并创建一个接受带有范围的解析列表的分区器。如果我们的键落入特定范围，我们将分配列表的分区号索引。

我们将涵盖以下主题：

+   实现自定义分区器

+   实现一个范围分区器

+   测试我们的分区器

我们将根据我们自己的范围分区逻辑来实现范围分区，并测试我们的分区器。让我们从不查看实现的黑盒测试开始。

代码的第一部分与我们已经使用的类似，但这次我们有`keyBy`数量的数据，如下例所示：

```py
 val keysWithValuesList =
 Array(
 UserTransaction("A", 100),
 UserTransaction("B", 4),
 UserTransaction("A", 100001),
 UserTransaction("B", 10),
 UserTransaction("C", 10)
 )
 val data = spark.parallelize(keysWithValuesList)
 val keyed = data.keyBy(_.amount)
```

我们按数量进行分组，我们有以下键：`100`，`4`，`100001`，`10`和`10`。

然后，我们将创建一个分区器，并将其命名为`CustomRangePartitioner`，它将接受一个元组列表，如下例所示：

```py
 val partitioned = keyed.partitionBy(new CustomRangePartitioner(List((0,100), (100, 10000), (10000, 1000000))))
```

第一个元素是从`0`到`100`，这意味着如果键在`0`到`100`的范围内，它应该进入分区`0`。因此，有四个键应该落入该分区。下一个分区号的范围是`100`和`10000`，因此该范围内的每条记录都应该落入分区号`1`，包括两端。最后一个范围是`10000`到`1000000`元素之间，因此，如果记录在该范围内，它应该落入该分区。如果我们有一个超出范围的元素，那么分区器将因非法参数异常而失败。

让我们看一下下面的例子，展示了我们自定义范围分区器的实现：

```py
class CustomRangePartitioner(ranges: List[(Int,Int)]) extends Partitioner{
 override def numPartitions: Int = ranges.size
override def getPartition(key: Any): Int = {
 if(!key.isInstanceOf[Int]){
 throw new IllegalArgumentException("partitioner works only for Int type")
 }
 val keyInt = key.asInstanceOf[Int]
 val index = ranges.lastIndexWhere(v => keyInt >= v._1 && keyInt <= v._2)
 println(s"for key: $key return $index")
 index
 }
}
```

它将范围作为元组的参数列表，如下例所示：

```py
(ranges: List[(Int,Int)])
```

我们的`numPartitions`应该等于`ranges.size`，因此分区的数量等于范围的数量。

接下来，我们有`getPartition`方法。首先，我们的分区器只对整数有效，如下例所示：

```py
if(!key.isInstanceOf[Int])
```

我们可以看到这是一个整数，不能用于其他类型。出于同样的原因，我们首先需要检查我们的键是否是整数的实例，如果不是，我们会得到一个`IllegalArgumentException`，因为该分区器只对 int 类型有效。

我们现在可以通过`asInstanceOf`来测试我们的`keyInt`。完成后，我们可以遍历范围，并在索引在谓词之间时取最后一个范围。我们的谓词是一个元组`v`，应该如下所示：

```py
 val index = ranges.lastIndexWhere(v => keyInt >= v._1 && keyInt <= v._2)
```

`KeyInt`应该大于或等于`v._1`，即元组的第一个元素，但也应该小于第二个元素`v._2`。

范围的起始是`v._1`，范围的结束是`v._2`，因此我们可以检查我们的元素是否在范围内。

最后，我们将打印我们在调试目的中找到的键的索引，并返回索引，这将是我们的分区。如下例所示：

```py
println(s"for key: $key return $index")
```

让我们开始下面的测试：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-bgdt-anlt-pyspark/img/485d4143-f478-4f9b-be3f-35c580667323.png)

我们可以看到对于键`100001`，代码返回了预期的分区号`2`。对于键`100`返回分区一，对于`10`，`4`，`10`返回分区零，这意味着我们的代码按预期工作。

# 摘要

在本章中，我们首先看到了关于键/值对的转换操作。然后我们学习了如何使用`aggregateByKey`而不是`groupBy`。我们还涵盖了关于键/值对的操作。之后，我们看了一下可用的分区器，比如`rangePartitioner`和`HashPartition`在键/值数据上。在本章结束时，我们已经实现了我们自定义的分区器，它能够根据范围的起始和结束来分配分区，以便学习目的。

在下一章中，我们将学习如何测试我们的 Spark 作业和 Apache Spark 作业。


# 第十二章：测试 Apache Spark 作业

在本章中，我们将测试 Apache Spark 作业，并学习如何将逻辑与 Spark 引擎分离。

我们将首先对我们的代码进行单元测试，然后在 SparkSession 中进行集成测试。之后，我们将使用部分函数模拟数据源，然后学习如何利用 ScalaCheck 进行基于属性的测试以及 Scala 中的类型。在本章结束时，我们将在不同版本的 Spark 中执行测试。

在本章中，我们将涵盖以下主题：

+   将逻辑与 Spark 引擎分离-单元测试

+   使用 SparkSession 进行集成测试

+   使用部分函数模拟数据源

+   使用 ScalaCheck 进行基于属性的测试

+   在不同版本的 Spark 中进行测试

# 将逻辑与 Spark 引擎分离-单元测试

让我们从将逻辑与 Spark 引擎分离开始。

在本节中，我们将涵盖以下主题：

+   创建具有逻辑的组件

+   该组件的单元测试

+   使用模型类的案例类进行领域逻辑

让我们先看逻辑，然后是简单的测试。

因此，我们有一个`BonusVerifier`对象，只有一个方法`quaifyForBonus`，它接受我们的`userTransaction`模型类。根据以下代码中的登录，我们加载用户交易并过滤所有符合奖金资格的用户。首先，我们需要测试它以创建一个 RDD 并对其进行过滤。我们需要创建一个 SparkSession，并为模拟 RDD 或 DataFrame 创建数据，然后测试整个 Spark API。由于这涉及逻辑，我们将对其进行隔离测试。逻辑如下：

```py
package com.tomekl007.chapter_6
import com.tomekl007.UserTransaction
object BonusVerifier {
 private val superUsers = List("A", "X", "100-million")
def qualifyForBonus(userTransaction: UserTransaction): Boolean = {
 superUsers.contains(userTransaction.userId) && userTransaction.amount > 100
 }
}
```

我们有一个超级用户列表，其中包括`A`、`X`和`100-million`用户 ID。如果我们的`userTransaction.userId`在`superUsers`列表中，并且`userTransaction.amount`高于`100`，那么用户就有资格获得奖金；否则，他们就没有资格。在现实世界中，奖金资格逻辑将更加复杂，因此非常重要的是对逻辑进行隔离测试。

以下代码显示了我们使用`userTransaction`模型的测试。我们知道我们的用户交易包括`userId`和`amount`。以下示例显示了我们的领域模型对象，它在 Spark 执行集成测试和我们的单元测试之间共享，与 Spark 分开：

```py
package com.tomekl007

import java.util.UUID

case class UserData(userId: String , data: String)

case class UserTransaction(userId: String, amount: Int)

case class InputRecord(uuid: String = UUID.*randomUUID()*.toString(), userId: String)
```

我们需要为用户 ID `X` 和金额`101`创建我们的`UserTransaction`，如下例所示：

```py
package com.tomekl007.chapter_6
import com.tomekl007.UserTransaction
import org.scalatest.FunSuite
class SeparatingLogic extends FunSuite {
test("test complex logic separately from spark engine") {
 //given
 val userTransaction = UserTransaction("X", 101)
//when
 val res = BonusVerifier.qualifyForBonus(userTransaction)
//then
 assert(res)
 }
}
```

然后我们将`userTransaction`传递给`qualifyForBonus`，结果应该是`true`。这个用户应该有资格获得奖金，如下输出所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-bgdt-anlt-pyspark/img/49908d22-b2a3-4b0b-9150-e533a6cda546.png)

现在，让我们为负面用例编写一个测试，如下所示：

```py
test(testName = "test complex logic separately from spark engine - non qualify") {
 //given
 val userTransaction = UserTransaction("X", 99)
//when
 val res = BonusVerifier.*qualifyForBonus*(userTransaction)
//then
 assert(!res)
 }
```

在这里，我们有一个用户`X`，花费`99`，所以我们的结果应该是 false。当我们验证我们的代码时，我们可以看到从以下输出中，我们的测试已经通过了：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-bgdt-anlt-pyspark/img/fee898ff-e179-4e5b-941a-a434a8c812c9.png)

我们已经涵盖了两种情况，但在现实世界的场景中，还有更多。例如，如果我们想测试指定`userId`不在这个超级用户列表中的情况，我们有一个花了很多钱的`some_new_user`，在我们的案例中是`100000`，我们得到以下结果：

```py
test(testName = "test complex logic separately from spark engine - non qualify2") {
 //given
 val userTransaction = UserTransaction("some_new_user", 100000)
//when
 val res = BonusVerifier.*qualifyForBonus*(userTransaction)
//then
 assert(!res)
 }
```

假设它不应该符合条件，因此这样的逻辑有点复杂。因此，我们以单元测试的方式进行测试：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-bgdt-anlt-pyspark/img/028fcf7e-9829-424e-a479-5497fc29c89d.png)

我们的测试非常快，因此我们能够检查一切是否按预期工作，而无需引入 Spark。在下一节中，我们将使用 SparkSession 进行集成测试来更改逻辑。

# 使用 SparkSession 进行集成测试

现在让我们学习如何使用 SparkSession 进行集成测试。

在本节中，我们将涵盖以下主题：

+   利用 SparkSession 进行集成测试

+   使用经过单元测试的组件

在这里，我们正在创建 Spark 引擎。以下行对于集成测试至关重要：

```py
 val spark: SparkContext = SparkSession.builder().master("local[2]").getOrCreate().sparkContext
```

创建一个轻量级对象并不是一件简单的事情。SparkSession 是一个非常重的对象，从头开始构建它是一项昂贵的操作，从资源和时间的角度来看。与上一节的单元测试相比，诸如创建 SparkSession 的测试将花费更多的时间。

出于同样的原因，我们应该经常使用单元测试来转换所有边缘情况，并且仅在逻辑的较小部分，如资本边缘情况时才使用集成测试。

以下示例显示了我们正在创建的数组：

```py
 val keysWithValuesList =
 Array(
 UserTransaction("A", 100),
 UserTransaction("B", 4),
 UserTransaction("A", 100001),
 UserTransaction("B", 10),
 UserTransaction("C", 10)
 )
```

以下示例显示了我们正在创建的 RDD：

```py
 val data = spark.parallelize(keysWithValuesList)
```

这是 Spark 第一次参与我们的集成测试。创建 RDD 也是一个耗时的操作。与仅创建数组相比，创建 RDD 真的很慢，因为它也是一个重量级对象。

我们现在将使用我们的`data.filter`来传递一个`qualifyForBonus`函数，如下例所示：

```py
 val aggregatedTransactionsForUserId = data.filter(BonusVerifier.qualifyForBonus)
```

这个函数已经经过单元测试，所以我们不需要考虑所有边缘情况，不同的 ID，不同的金额等等。我们只是创建了一些 ID 和一些金额来测试我们整个逻辑链是否按预期工作。

应用了这个逻辑之后，我们的输出应该类似于以下内容：

```py
 UserTransaction("A", 100001)
```

让我们开始这个测试，检查执行单个集成测试需要多长时间，如下输出所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-bgdt-anlt-pyspark/img/e492184d-4a2b-4069-bb7f-86937d6c0393.png)

执行这个简单测试大约需要`646 毫秒`。

如果我们想要覆盖每一个边缘情况，与上一节的单元测试相比，值将乘以数百倍。让我们从三个边缘情况开始这个单元测试，如下输出所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-bgdt-anlt-pyspark/img/4cb08050-118a-499c-8694-469a568f3a1e.png)

我们可以看到我们的测试只花了`18 毫秒`，这意味着即使我们覆盖了三个边缘情况，与只有一个情况的集成测试相比，速度快了 20 倍。

在这里，我们覆盖了许多逻辑，包括数百个边缘情况，我们可以得出结论，尽可能低的级别进行单元测试是非常明智的。

在下一节中，我们将使用部分函数来模拟数据源。

# 使用部分函数模拟数据源

在本节中，我们将涵盖以下主题：

+   创建一个从 Hive 读取数据的 Spark 组件

+   模拟组件

+   测试模拟组件

假设以下代码是我们的生产线：

```py
 ignore("loading data on prod from hive") {
 UserDataLogic.loadAndGetAmount(spark, HiveDataLoader.loadUserTransactions)
 }
```

在这里，我们使用`UserDataLogic.loadAndGetAmount`函数，它需要加载我们的用户数据交易并获取交易的金额。这个方法需要两个参数。第一个参数是`sparkSession`，第二个参数是`sparkSession`的`provider`，它接受`SparkSession`并返回`DataFrame`，如下例所示：

```py
object UserDataLogic {
  def loadAndGetAmount(sparkSession: SparkSession, provider: SparkSession => DataFrame): DataFrame = {
    val df = provider(sparkSession)
    df.select(df("amount"))
  }
}
```

对于生产，我们将加载用户交易，并查看`HiveDataLoader`组件只有一个方法，`sparkSession.sql`和`("select * from transactions")`，如下代码块所示：

```py
object HiveDataLoader {
 def loadUserTransactions(sparkSession: SparkSession): DataFrame = {
 sparkSession.sql("select * from transactions")
 }
}
```

这意味着该函数去 Hive 检索我们的数据并返回一个 DataFrame。根据我们的逻辑，它执行了返回 DataFrame 的`provider`，然后从 DataFrame 中选择`amount`。

这个逻辑并不简单，因为我们的 SparkSession `provider`在生产中与外部系统进行交互。因此，我们可以创建一个如下的函数：

```py
UserDataLogic.loadAndGetAmount(spark, HiveDataLoader.loadUserTransactions)
```

让我们看看如何测试这样一个组件。首先，我们将创建一个用户交易的 DataFrame，这是我们的模拟数据，如下例所示：

```py
 val df = spark.sparkContext
 .makeRDD(List(UserTransaction("a", 100), UserTransaction("b", 200)))
 .toDF()
```

然而，我们需要将数据保存到 Hive 中，嵌入它，然后启动 Hive。

由于我们使用了部分函数，我们可以将部分函数作为第二个参数传递，如下例所示：

```py
val res = UserDataLogic.loadAndGetAmount(spark, _ => df)
```

第一个参数是`spark`，但这次我们的方法中没有使用它。第二个参数是一个接受 SparkSession 并返回 DataFrame 的方法。

然而，我们的执行引擎、架构和代码并不考虑这个 SparkSession 是否被使用，或者是否进行了外部调用；它只想返回 DataFrame。我们可以使用`_`作为我们的第一个参数，因为它被忽略，只返回 DataFrame 作为返回类型。

因此我们的`loadAndGetAmount`将获得一个模拟 DataFrame，这是我们创建的 DataFrame。

但是，对于所示的逻辑，它是透明的，不考虑 DataFrame 是来自 Hive、SQL、Cassandra 还是其他任何来源，如下例所示：

```py
 val df = provider(sparkSession)
 df.select(df("amount"))
```

在我们的例子中，`df`来自我们为测试目的创建的内存。我们的逻辑继续并选择了数量。

然后，我们展示我们的列，`res.show()`，并且该逻辑应该以一个列的数量结束。让我们开始这个测试，如下例所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-bgdt-anlt-pyspark/img/8dca11c2-8423-432f-9233-897f3fba401b.png)

我们可以从上面的例子中看到，我们的结果 DataFrame 在`100`和`200`值中有一个列的数量。这意味着它按预期工作，而无需启动嵌入式 Hive。关键在于使用提供程序而不是在逻辑中嵌入我们的选择开始。

在下一节中，我们将使用 ScalaCheck 进行基于属性的测试。

# 使用 ScalaCheck 进行基于属性的测试

在本节中，我们将涵盖以下主题：

+   基于属性的测试

+   创建基于属性的测试

让我们看一个简单的基于属性的测试。在定义属性之前，我们需要导入一个依赖项。我们还需要一个 ScalaCheck 库的依赖项，这是一个用于基于属性的测试的库。

在上一节中，每个测试都扩展了`FunSuite`。我们使用了功能测试，但是必须显式提供参数。在这个例子中，我们扩展了来自 ScalaCheck 库的`Properties`，并测试了`StringType`，如下所示：

```py
object PropertyBasedTesting extends Properties("StringType")
```

我们的 ScalaCheck 将为我们生成一个随机字符串。如果我们为自定义类型创建基于属性的测试，那么 ScalaCheck 是不知道的。我们需要提供一个生成器，它将生成该特定类型的实例。

首先，让我们以以下方式定义我们字符串类型的第一个属性：

```py
property("length of strings") = forAll { (a: String, b: String) =>
 a.length + b.length >= a.length
 }
```

`forAll`是 ScalaCheck 属性的一个方法。我们将在这里传递任意数量的参数，但它们需要是我们正在测试的类型。

假设我们想要获得两个随机字符串，并且在这些字符串中，不变性应该被感知。

如果我们将字符串`a`的长度加上字符串`b`的长度，那么它们的总和应该大于或等于`a.length`，因为如果`b`是`0`，那么它们将相等，如下例所示：

```py
a.length + b.length >= a.length
```

然而，这是`string`的不变性，对于每个输入字符串，它应该是`true`。

我们正在定义的第二个属性更复杂，如下代码所示：

```py
property("creating list of strings") = forAll { (a: String, b: String, c: String) =>
 List(a,b,c).map(_.length).sum == a.length + b.length + c.length
 }
```

在上面的代码中，我们要求 ScalaCheck 运行时引擎这次共享三个字符串，即`a`、`b`和`c`。当我们创建一个字符串列表时，我们将测试这个。

在这里，我们正在创建一个字符串列表，即`a`、`b`、`c`，如下代码所示：

```py
List(a,b,c)
```

当我们将每个元素映射到`length`时，这些元素的总和应该等于通过长度添加所有元素。在这里，我们有`a.length + b.length + c.length`，我们将测试集合 API，以检查映射和其他函数是否按预期工作。

让我们开始这个基于属性的测试，以检查我们的属性是否正确，如下例所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-bgdt-anlt-pyspark/img/9319cfda-c10b-40bf-8d3b-9e41fa26fe7f.png)

我们可以看到`string`的`StringType.length`属性通过并执行了`100`次测试。`100`次测试被执行可能会让人惊讶，但让我们尝试看看通过以下代码传递了什么参数：

```py
println(s"a: $a, b: $b")
```

我们将打印`a`参数和`b`参数，并通过测试以下输出来重试我们的属性：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-bgdt-anlt-pyspark/img/a7df281d-ce0d-408d-a174-96b691f2a45b.png)

我们可以看到生成了许多奇怪的字符串，因此这是一个我们无法事先创建的边缘情况。基于属性的测试将创建一个非常奇怪的唯一代码，这不是一个合适的字符串。因此，这是一个用于测试我们的逻辑是否按预期针对特定类型工作的好工具。

在下一节中，我们将在不同版本的 Spark 中进行测试。

# 在不同版本的 Spark 中进行测试

在本节中，我们将涵盖以下主题：

+   将组件更改为与 Spark pre-2.x 一起使用

+   Mock 测试 pre-2.x

+   RDD 模拟测试

让我们从本章第三节开始，模拟数据源——*使用部分函数模拟数据源*。

由于我们正在测试`UserDataLogic.loadAndGetAmount`，请注意一切都在 DataFrame 上操作，因此我们有一个 SparkSession 和 DataFrame。

现在，让我们将其与 Spark pre-2.x 进行比较。我们可以看到这一次我们无法使用 DataFrame。假设以下示例显示了我们在以前的 Spark 中的逻辑：

```py
test("mock loading data from hive"){
 //given
 import spark.sqlContext.implicits._
 val df = spark.sparkContext
 .makeRDD(List(UserTransaction("a", 100), UserTransaction("b", 200)))
 .toDF()
 .rdd
//when
 val res = UserDataLogicPre2.loadAndGetAmount(spark, _ => df)
//then
 println(res.collect().toList)
 }
}
```

我们可以看到这一次我们无法使用 DataFrame。

在前面的部分中，`loadAndGetAmount`正在接受`spark`和 DataFrame，但在下面的示例中，DataFrame 是一个 RDD，不再是 DataFrame，因此我们传递了一个`rdd`：

```py
 val res = UserDataLogicPre2.loadAndGetAmount(spark, _ => rdd)
```

然而，我们需要为 Spark 创建一个不同的`UserDataLogicPre2`，它接受 SparkSession 并在映射整数的 RDD 之后返回一个 RDD，如下例所示：

```py
object UserDataLogicPre2 {
 def loadAndGetAmount(sparkSession: SparkSession, provider: SparkSession => RDD[Row]): RDD[Int] = {
 provider(sparkSession).map(_.getAsInt)
 }
}
object HiveDataLoaderPre2 {
 def loadUserTransactions(sparkSession: SparkSession): RDD[Row] = {
 sparkSession.sql("select * from transactions").rdd
 }
}
```

在前面的代码中，我们可以看到`provider`正在执行我们的提供程序逻辑，映射每个元素，将其作为`int`获取。然后，我们得到了金额。`Row`是一个可以有可变数量参数的泛型类型。

在 Spark pre-2.x 中，我们没有`SparkSession`，因此需要使用`SparkContext`并相应地更改我们的登录。

# 总结

在本章中，我们首先学习了如何将逻辑与 Spark 引擎分离。然后，我们查看了一个在没有 Spark 引擎的情况下经过良好测试的组件，并使用 SparkSession 进行了集成测试。为此，我们通过重用已经经过良好测试的组件创建了一个 SparkSession 测试。通过这样做，我们不必在集成测试中涵盖所有边缘情况，而且我们的测试速度更快。然后，我们学习了如何利用部分函数在测试阶段提供模拟数据。我们还介绍了 ScalaCheck 用于基于属性的测试。在本章结束时，我们已经在不同版本的 Spark 中测试了我们的代码，并学会了将 DataFrame 模拟测试更改为 RDD。

在下一章中，我们将学习如何利用 Spark GraphX API。


# 第十三章：利用 Spark GraphX API

在本章中，我们将学习如何从数据源创建图。然后，我们将使用 Edge API 和 Vertex API 进行实验。在本章结束时，您将知道如何计算顶点的度和 PageRank。

在本章中，我们将涵盖以下主题：

+   从数据源创建图

+   使用 Vertex API

+   使用 Edge API

+   计算顶点的度

+   计算 PageRank

# 从数据源创建图

我们将创建一个加载器组件，用于加载数据，重新审视图格式，并从文件加载 Spark 图。

# 创建加载器组件

`graph.g`文件包含顶点到顶点的结构。在下面的`graph.g`文件中，如果我们将`1`对齐到`2`，这意味着顶点 ID`1`和顶点 ID`2`之间有一条边。第二行表示从顶点 ID`1`到顶点 ID`3`有一条边，然后从`2`到`3`，最后从`3`到`5`：

```py
1  2
1  3
2  3
3  5
```

我们将取`graph.g`文件，加载它，并查看它将如何在 Spark 中提供结果。首先，我们需要获取我们的`graph.g`文件的资源。我们将使用`getClass.getResource()`方法来获取它的路径，如下所示：

```py
package com.tomekl007.chapter_7

import org.apache.spark.SparkContext
import org.apache.spark.sql.SparkSession
import org.scalatest.FunSuite

class CreatingGraph extends FunSuite {
  val spark: SparkContext = SparkSession.builder().master("local[2]").getOrCreate().sparkContext

  test("should load graph from a file") {
    //given
    val path = getClass.getResource("/graph.g").getPath
```

# 重新审视图格式

接下来，我们有`GraphBuilder`方法，这是我们自己的组件：

```py
    //when
    val graph = GraphBuilder.loadFromFile(spark, path)
```

以下是我们的`GraphBuilder.scala`文件，用于我们的`GraphBuilder`方法：

```py
package com.tomekl007.chapter_7

import org.apache.spark.SparkContext
import org.apache.spark.graphx.{Graph, GraphLoader}

object GraphBuilder {

  def loadFromFile(sc: SparkContext, path: String): Graph[Int, Int] = {
    GraphLoader.edgeListFile(sc, path)
  }
}
```

它使用了`org.apache.spark.graphx.{Graph, GraphLoader}`包中的`GraphLoader`类，并且我们指定了格式。

这里指定的格式是`edgeListFile`。我们传递了`sc`参数，即`SparkContext`和`path`参数，其中包含文件的路径。得到的图将是`Graph [Int, Int]`，我们将使用它作为我们顶点的标识符。

# 从文件加载 Spark

一旦我们得到了结果图，我们可以将`spark`和`path`参数传递给我们的`GraphBuilder.loadFromFile()`方法，此时，我们将得到一个`Graph [Int, Int]`的构造图，如下所示：

```py
  val graph = GraphBuilder.loadFromFile(spark, path)
```

迭代和验证我们的图是否被正确加载，我们将使用`图`中的`三元组`，它们是一对顶点到顶点，也是这些顶点之间的边。我们将看到图的结构是否被正确加载：

```py
    //then
    graph.triplets.foreach(println(_))
```

最后，我们断言我们得到了`4`个三元组（如前面在*创建加载器组件*部分中所示，我们从`graph.g`文件中有四个定义）：

```py
    assert(graph.triplets.count() == 4)
  }

}
```

我们将开始测试并查看我们是否能够正确加载我们的图。

我们得到了以下输出。这里，我们有`(2, 1)`，`(3, 1)`，`(3,1)`，`(5,1)`，`(1,1)`，`(2,1)`，`(1,1)`和`(3,1)`：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-bgdt-anlt-pyspark/img/5623373e-3747-48f4-bcc0-935cffd2fed2.png)

因此，根据输出的图，我们能够使用 Spark 重新加载我们的图。

# 使用 Vertex API

在这一部分，我们将使用边来构建图。我们将学习使用 Vertex API，并利用边的转换。

# 使用顶点构建图

构建图不是一项简单的任务；我们需要提供顶点和它们之间的边。让我们专注于第一部分。第一部分包括我们的`users`，`users`是一个`VertexId`和`String`的 RDD，如下所示：

```py
package com.tomekl007.chapter_7

import org.apache.spark.SparkContext
import org.apache.spark.graphx.{Edge, Graph, VertexId}
import org.apache.spark.rdd.RDD
import org.apache.spark.sql.SparkSession
import org.scalatest.FunSuite

class VertexAPI extends FunSuite {
  val spark: SparkContext = SparkSession.builder().master("local[2]").getOrCreate().sparkContext

  test("Should use Vertex API") {
    //given
    val users: RDD[(VertexId, (String))] =
      spark.parallelize(Array(
        (1L, "a"),
        (2L, "b"),
        (3L, "c"),
        (4L, "d")
      ))
```

`VertexId`是`long`类型；这只是`Long`的`type`别名：

```py
type VertexID = Long
```

但由于我们的图有时包含大量内容，`VertexId`应该是唯一的且非常长的数字。我们的顶点 RDD 中的每个顶点都应该有一个唯一的`VertexId`。与顶点关联的自定义数据可以是任何类，但我们将选择使用`String`类来简化。首先，我们创建一个 ID 为`1`的顶点和字符串数据`a`，下一个 ID 为`2`的顶点和字符串数据`b`，下一个 ID 为`3`的顶点和字符串数据`c`，以及 ID 为`4`的数据和字符串`d`，如下所示：

```py
    val users: RDD[(VertexId, (String))] =
      spark.parallelize(Array(
        (1L, "a"),
        (2L, "b"),
        (3L, "c"),
        (4L, "d")
      ))
```

仅从顶点创建图是正确的，但并不是非常有用。图是查找数据之间关系的最佳方式，这就是为什么图是社交网络的主要构建块。

# 创建夫妻关系

在这一部分，我们将创建顶点之间的夫妻关系和边缘。在这里，我们将有一个关系，即`Edge`。`Edge`是来自`org.apache.spark.graphx`包的一个样例类。它稍微复杂一些，因为我们需要指定源顶点 ID 和目标顶点 ID。我们想要指定顶点 ID`1`和`2`有一个关系，所以让我们为这个关系创建一个标签。在下面的代码中，我们将指定顶点 ID`1`和 ID`2`为`friend`，然后我们还将指定顶点 ID`1`和 ID`3`也为`friend`。最后，顶点 ID`2`和 ID`4`将是`wife`：

```py
    val relationships =
      spark.parallelize(Array(
        Edge(1L, 2L, "friend"),
        Edge(1L, 3L, "friend"),
        Edge(2L, 4L, "wife")
      ))
```

此外，标签可以是任何类型-它不需要是`String`类型；我们可以输入我们想要的内容并传递它。一旦我们有了我们的顶点、用户和边缘关系，我们就可以创建一个图。我们使用`Graph`类的`apply`方法来构建我们的 Spark GraphX 图。我们需要传递`users`、`VertexId`和`relationships`，如下所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-bgdt-anlt-pyspark/img/f41c7ab7-c2ee-417c-a501-8baa146d05ed.png)

返回的`graph`是一个 RDD，但它是一个特殊的 RDD：

```py
    val graph = Graph(users, relationships)
```

当我们转到`Graph`类时，我们会看到`Graph`类有一个顶点的 RDD 和一个边缘的 RDD，所以`Graph`类是两个 RDD 的伴生对象，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-bgdt-anlt-pyspark/img/3ed921b5-e3c9-454d-9c28-34296efda1c4.png)

我们可以通过发出一些方法来获取`vertices`和`edges`的基础 RDD。例如，如果要获取所有顶点，我们可以映射所有顶点，我们将获取属性和`VertexId`。在这里，我们只对属性感兴趣，我们将其转换为大写，如下所示：

```py
    val res = graph.mapVertices((_, att) => att.toUpperCase())
```

以下是属性：

```py
    val users: RDD[(VertexId, (String))] =
      spark.parallelize(Array(
        (1L, "a"),
        (2L, "b"),
        (3L, "c"),
        (4L, "d")
      ))
```

一旦我们将其转换为大写，我们可以收集所有顶点并执行`toList()`，如下所示：

```py
    println(res.vertices.collect().toList)
  }

}
```

我们可以看到，在对值应用转换后，我们的图具有以下顶点：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-bgdt-anlt-pyspark/img/c5639e74-f504-4de7-9c38-dad03641c394.png)

# 使用 Edge API

在这一部分，我们将使用 Edge API 构建图。我们还将使用顶点，但这次我们将专注于边缘转换。

# 使用边缘构建图

正如我们在前面的部分中看到的，我们有边缘和顶点，这是一个 RDD。由于这是一个 RDD，我们可以获取一个边缘。我们有许多可用于普通 RDD 的方法。我们可以使用`max`方法、`min`方法、`sum`方法和所有其他操作。我们将应用`reduce`方法，因此`reduce`方法将获取两个边缘，我们将获取`e1`、`e2`，并对其执行一些逻辑。

`e1`边缘是一个具有属性、目的地和源的边缘，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-bgdt-anlt-pyspark/img/70fff1b2-97e3-4840-845f-7689be653d0a.png)

由于边缘将两个顶点链接在一起，我们可以在这里执行一些逻辑。例如，如果`e1`边缘属性等于`friend`，我们希望使用`filter`操作提升一个边缘。因此，`filter`方法只获取一个边缘，然后如果边缘`e1`是`friend`，它将被自动感知。我们可以看到最后我们可以`collect`它并执行`toList`，以便 Spark 上的 API 可供我们使用。以下代码将帮助我们实现我们的逻辑：

```py
import org.apache.spark.SparkContext
import org.apache.spark.graphx.{Edge, Graph, VertexId}
import org.apache.spark.rdd.RDD
import org.apache.spark.sql.SparkSession
import org.scalatest.FunSuite

class EdgeAPI extends FunSuite {
  val spark: SparkContext = SparkSession.builder().master("local[2]").getOrCreate().sparkContext

  test("Should use Edge API") {
    //given
    val users: RDD[(VertexId, (String))] =
      spark.parallelize(Array(
        (1L, "a"),
        (2L, "b"),
        (3L, "c"),
        (4L, "d")
      ))

    val relationships =
      spark.parallelize(Array(
        Edge(1L, 2L, "friend"),
        Edge(1L, 3L, "friend"),
        Edge(2L, 4L, "wife")
      ))

    val graph = Graph(users, relationships)

    //when
 val resFromFilter = graph.edges.filter((e1) => e1.attr == "friend").collect().toList
 println(resFromFilter)
```

它还具有标准 RDD 的一些方法。例如，我们可以执行一个 map edge，它将获取一个边缘，我们可以获取一个属性，并将每个标签映射为大写，如下所示：

```py
    val res = graph.mapEdges(e => e.attr.toUpperCase)
```

在图上，我们还可以执行边缘分组。边缘分组类似于`GROUP BY`，但仅适用于边缘。

输入以下命令以打印线路映射边缘：

```py
    println(res.edges.collect().toList)
```

让我们开始我们的代码。我们可以在输出中看到，我们的代码已经过滤了`wife`边缘-我们只能感知从顶点 ID`1`到 ID`2`的`friend`边缘，以及从顶点 ID`1`到 ID`3`的边缘，并将边缘映射如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-bgdt-anlt-pyspark/img/ad57af2a-f940-43aa-8b89-ed7248c18624.png)

# 计算顶点的度

在本节中，我们将涵盖总度数，然后将其分为两部分——入度和出度——并且我们将了解这在代码中是如何工作的。

对于我们的第一个测试，让我们构建我们已经了解的图：

```py
package com.tomekl007.chapter_7

import org.apache.spark.SparkContext
import org.apache.spark.graphx.{Edge, Graph, VertexId}
import org.apache.spark.rdd.RDD
import org.apache.spark.sql.SparkSession
import org.scalatest.FunSuite
import org.scalatest.Matchers._

class CalculateDegreeTest extends FunSuite {
  val spark: SparkContext = SparkSession.builder().master("local[2]").getOrCreate().sparkContext

  test("should calculate degree of vertices") {
    //given
    val users: RDD[(VertexId, (String))] =
      spark.parallelize(Array(
        (1L, "a"),
        (2L, "b"),
        (3L, "c"),
        (4L, "d")
      ))

    val relationships =
      spark.parallelize(Array(
        Edge(1L, 2L, "friend"),
        Edge(1L, 3L, "friend"),
        Edge(2L, 4L, "wife")
      ))
```

我们可以使用`degrees`方法获得度。`degrees`方法返回`VertexRDD`，因为`degrees`是一个顶点：

```py
    val graph = Graph(users, relationships)

    //when
    val degrees = graph.degrees.collect().toList
```

结果如下：

```py
    //then
    degrees should contain theSameElementsAs List(
      (4L, 1L),
      (2L, 2L),
      (1L, 2L),
      (3L, 1L)
    )
  }
```

上面的代码解释了对于`VertexId 4L`实例，只有一个关系，因为`2L`和`4L`之间存在关系。

然后，对于`VertexId 2L`实例，有两个，分别是`1L, 2L`和`2L, 4L`。对于`VertexId 1L`实例，有两个，分别是`1L, 2L`和`1L, 3L`，对于`VertexId 3L`，只有一个关系，即`1L`和`3L`之间。通过这种方式，我们可以检查我们的图是如何耦合的，以及有多少关系。我们可以通过对它们进行排序来找出哪个顶点最知名，因此我们可以看到我们的测试在下面的截图中通过了。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-bgdt-anlt-pyspark/img/14383131-b9a0-495e-b272-bf7b723f32bd.png)

# 入度

入度告诉我们有多少个顶点进入第二个顶点，但反之则不然。这次，我们可以看到对于`VertexId 2L`实例，只有一个入站顶点。我们可以看到`2L`与`1L`有关系，`3L`也与`1L`有关系，`4L`与`1L`有关系。在下面的结果数据集中，将没有`VertexId 1L`的数据，因为`1L`是输入。所以，`1L`只会是一个源，而不是目的地：

```py
  test("should calculate in-degree of vertices") {
    //given
    val users: RDD[(VertexId, (String))] =
      spark.parallelize(Array(
        (1L, "a"),
        (2L, "b"),
        (3L, "c"),
        (4L, "d")
      ))

    val relationships =
      spark.parallelize(Array(
        Edge(1L, 2L, "friend"),
        Edge(1L, 3L, "friend"),
        Edge(2L, 4L, "wife")
      ))

    val graph = Graph(users, relationships)

    //when
    val degrees = graph.inDegrees.collect().toList

    //then
    degrees should contain theSameElementsAs List(
      (2L, 1L),
      (3L, 1L),
      (4L, 1L)
    )
  }
```

入度的前面特征是一个非常有用的属性。当我们无法找出哪些页面非常重要，因为它们通过页面而不是从页面链接时，我们使用入度。

通过运行这个测试，我们可以看到它按预期工作：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-bgdt-anlt-pyspark/img/b833ae5d-5154-4b61-9758-359815e92eaa.png)

# 出度

出度解释了有多少个顶点出去。这次，我们将计算边缘、关系的源，而不是目的地，就像我们在入度方法中所做的那样。

为了获得出度，我们将使用以下代码：

```py
val degrees = graph.outDegrees.collect().toList
```

`outDegrees`方法包含`RDD`和`VertexRDD`，我们使用`collect`和`toList`方法将其收集到列表中。

在这里，`VertexId 1L`应该有两个出站顶点，因为`1L, 2L`和`1L, 3L`之间存在关系：

```py
  test("should calculate out-degree of vertices") {
    //given
    val users: RDD[(VertexId, (String))] =
      spark.parallelize(Array(
        (1L, "a"),
        (2L, "b"),
        (3L, "c"),
        (4L, "d")
      ))

    val relationships =
      spark.parallelize(Array(
        Edge(1L, 2L, "friend"),
        Edge(1L, 3L, "friend"),
        Edge(2L, 4L, "wife")
      ))

    val graph = Graph(users, relationships)

    //when
    val degrees = graph.outDegrees.collect().toList

    //then
    degrees should contain theSameElementsAs List(
      (1L, 2L),
      (2L, 1L)
    )
  }

}
```

另外，`VertexId 2L`应该有一个出站顶点，因为`2L`和`4L`之间存在关系，而反之则不然，如前面的代码所示。

我们将运行这个测试并得到以下输出：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-bgdt-anlt-pyspark/img/572ee639-66b1-4f94-8249-ba5853949981.png)

# 计算 PageRank

在本节中，我们将加载关于用户的数据并重新加载关于他们关注者的数据。我们将使用图形 API 和我们的数据结构，并计算 PageRank 来计算用户的排名。

首先，我们需要加载`edgeListFile`，如下所示：

```py
package com.tomekl007.chapter_7

import org.apache.spark.graphx.GraphLoader
import org.apache.spark.sql.SparkSession
import org.scalatest.FunSuite
import org.scalatest.Matchers._

class PageRankTest extends FunSuite {
  private val sc = SparkSession.builder().master("local[2]").getOrCreate().sparkContext

  test("should calculate page rank using GraphX API") {
    //given
    val graph = GraphLoader.edgeListFile(sc, getClass.getResource("/pagerank/followers.txt").getPath)
```

我们有一个`followers.txt`文件；以下截图显示了文件的格式，与我们在*创建加载器组件*部分看到的文件类似：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-bgdt-anlt-pyspark/img/ce7f1f3a-0eff-4b12-9171-bb5b3fe8a45c.png)

我们可以看到每个顶点 ID 之间存在关系。因此，我们从`followers.txt`文件加载`graph`，然后发出 PageRank。我们将需要`vertices`，如下所示：

```py
    val ranks = graph.pageRank(0.0001).vertices
```

PageRank 将计算我们的顶点之间的影响和关系。

# 加载和重新加载关于用户和关注者的数据

为了找出哪个用户有哪个名字，我们需要加载`users.txt`文件。`users.txt`文件将`VertexId`分配给用户名和自己的名字。我们使用以下代码：

```py
    val users = sc.textFile(getClass.getResource("/pagerank/users.txt").getPath).map { line =>
```

以下是`users.txt`文件：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-bgdt-anlt-pyspark/img/b5c42ab0-8639-4371-8915-5905dbba68bc.png)

我们在逗号上拆分，第一组是我们的整数，它将是顶点 ID，然后`fields(1)`是顶点的名称，如下所示：

```py
      val fields = line.split(",")
      (fields(0).toLong, fields(1))
    }
```

接下来，我们将使用`join`将`users`与`ranks`连接起来。我们将使用用户的`VertexId`通过用户的`username`和`rank`来`join` `users`。一旦我们有了这些，我们就可以按`rank`对所有内容进行排序，所以我们将取元组的第二个元素，并且应该按`sortBy ((t) =>t.2`进行排序。在文件的开头，我们将拥有影响力最大的用户：

```py
    //when
 val rankByUsername = users.join(ranks).map {
      case (_, (username, rank)) => (username, rank)
    }.sortBy((t) => t._2, ascending = false)
      .collect()
      .toList
```

我们将打印以下内容并按`rankByUsername`进行排序：

```py
    println(rankByUsername)
    //then
    rankByUsername.map(_._1) should contain theSameElementsInOrderAs List(
      "BarackObama",
      "ladygaga",
      "odersky",
      "jeresig",
      "matei_zaharia",
      "justinbieber"
    )
  }

}
```

如果我们跳过`sortBy`方法，Spark 不保证元素的任何排序；为了保持排序，我们需要使用`sortBy`方法。

在运行代码后，我们得到以下输出：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-bgdt-anlt-pyspark/img/3d25a619-5388-4912-97c8-016a62cb11a9.png)

当我们开始运行这个测试时，我们可以看到 GraphX PageRank 是否能够计算出我们用户的影响力。我们得到了前面截图中显示的输出，其中`BarackObama`的影响力最大为`1.45`，然后是`ladygaga`，影响力为`1.39`，`odersky`为`1.29`，`jeresig`为`0.99`，`matai_zaharia`为`0.70`，最后是`justinbieber`，影响力为`0.15`。

根据前面的信息，我们能够用最少的代码计算复杂的算法。

# 总结

在本章中，我们深入研究了转换和操作，然后学习了 Spark 的不可变设计。我们研究了如何避免洗牌以及如何减少运营成本。然后，我们看了如何以正确的格式保存数据。我们还学习了如何使用 Spark 键/值 API 以及如何测试 Apache Spark 作业。之后，我们学习了如何从数据源创建图形，然后研究并尝试了边缘和顶点 API。我们学习了如何计算顶点的度。最后，我们看了 PageRank 以及如何使用 Spark GraphicX API 进行计算。
