# Spark 数据科学（二）

> 原文：[`zh.annas-archive.org/md5/D6F94257998256DE126905D8038FBE11`](https://zh.annas-archive.org/md5/D6F94257998256DE126905D8038FBE11)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：Spark 上的数据分析

大规模数据分析领域一直在不断发展。为数据分析开发了各种库和工具，具有丰富的算法集。与此同时，分布式计算技术也在不断发展，以便规模化处理大型数据集。这两种特征必须融合，这是开发 Spark 的主要意图。

前两章概述了数据科学的技术方面。它涵盖了 DataFrame API、数据集、流数据的一些基础知识，以及它如何通过数据框架来表示数据，这是 R 和 Python 用户熟悉的。在介绍了这个 API 之后，我们看到操作数据集变得比以往更容易。我们还看到 Spark SQL 如何在支持 DataFrame API 时发挥了后台作用，具有其强大的功能和优化技术。在本章中，我们将涵盖大数据分析的科学方面，并学习可以在 Spark 上执行的各种数据分析技术。

作为本章的先决条件，对 DataFrame API 和统计基础的基本理解是有益的。然而，我们已经尽量简化内容，并详细介绍了一些重要的基础知识，以便任何人都可以开始使用 Spark 进行统计分析。本章涵盖的主题如下：

+   数据分析生命周期

+   数据获取

+   数据准备

+   数据整合

+   数据清洗

+   数据转换

+   统计基础

+   抽样

+   数据分布

+   描述性统计

+   位置测量

+   传播测量

+   总结统计

+   图形技术

+   推断统计

+   离散概率分布

+   连续概率分布

+   标准误差

+   置信水平

+   误差边界和置信区间

+   总体变异性

+   估计样本大小

+   假设检验

+   卡方检验

+   F 检验

+   相关性

# 数据分析生命周期

对于大多数现实项目，需要遵循一定的步骤顺序。然而，对于数据分析和数据科学，没有普遍认可的定义或界限。一般来说，“数据分析”这个术语包括检查数据、发现有用见解和传达这些见解所涉及的技术和过程。术语“数据科学”可以最好地被视为一个跨学科领域，涵盖*统计学*、*计算机科学*和*数学*。这两个术语都涉及处理原始数据以获取知识或见解，通常是迭代的过程，有些人将它们互换使用。

根据不同的业务需求，有不同的解决问题的方式，但没有一个适合所有可能情况的唯一标准流程。典型的流程工作流程可以总结为制定问题、探索、假设、验证假设、分析结果，并重新开始的循环。这在下图中用粗箭头表示。从数据角度看，工作流程包括数据获取、预处理、数据探索、建模和传达结果。这在图中显示为圆圈。分析和可视化发生在每个阶段，从数据收集到结果传达。数据分析工作流程包括两个视图中显示的所有活动：

![数据分析生命周期](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_05_001.jpg)

整个生命周期中最重要的是提出的问题。可能包含答案（相关数据！）的数据紧随其后。根据问题，第一个任务是根据需要从一个或多个数据源收集正确的数据。组织通常维护**数据湖**，这是数据以其原始格式存储的巨大存储库。

下一步是清洗/转换数据到所需的格式。数据清洗也称为数据整理、数据处理或数据清理。这包括在评估手头数据的质量后进行的活动，如处理缺失值和异常值。你可能还需要对数据进行聚合/绘图以更好地理解。这个制定最终数据矩阵以便处理的过程被吹捧为最耗时的步骤。这也是一个被低估的组成部分，被认为是预处理的一部分，还有其他活动，比如特征提取和数据转换。

数据科学的核心，即训练模型和提取模式，接下来就要进行，这需要大量使用统计学和机器学习。最后一步是发布结果。

本章的其余部分将更深入地探讨每个步骤以及如何使用 Spark 实现这些步骤。还包括一些统计学的基础知识，以便读者能够轻松地跟随代码片段。

# 数据获取

数据获取，或者说数据收集，是任何数据科学项目中的第一步。通常情况下，你不会在一个地方找到所有所需的完整数据集，因为它分布在**业务线**（**LOB**）应用程序和系统中。

本节的大部分内容已经在上一章中涵盖了，概述了如何从不同的数据源获取数据并将数据存储在 DataFrames 中以便进行更轻松的分析。Spark 中有一种内置机制，可以从一些常见的数据源中获取数据，并为那些不受 Spark 支持的数据源提供*数据源 API*。

为了更好地理解数据获取和准备阶段，让我们假设一个场景，并尝试用示例代码片段解决所有涉及的步骤。假设员工数据分布在本地 RDD、JSON 文件和 SQL 服务器上。那么，让我们看看如何将它们转换为 Spark DataFrames：

**Python**

```scala
// From RDD: Create an RDD and convert to DataFrame
>>> employees = sc.parallelize([(1, "John", 25), (2, "Ray", 35), (3, "Mike", 24), (4, "Jane", 28), (5, "Kevin", 26), (6, "Vincent", 35), (7, "James", 38), (8, "Shane", 32), (9, "Larry", 29), (10, "Kimberly", 29), (11, "Alex", 28), (12, "Garry", 25), (13, "Max", 31)]).toDF(["emp_id","name","age"])
>>>

// From JSON: reading a JSON file
>>> salary = sqlContext.read.json("./salary.json")
>>> designation = sqlContext.read.json("./designation.json")
```

**Scala**

```scala
// From RDD: Create an RDD and convert to DataFrame
scala> val employees = sc.parallelize(List((1, "John", 25), (2, "Ray", 35), (3, "Mike", 24), (4, "Jane", 28), (5, "Kevin", 26), (6, "Vincent", 35), (7, "James", 38), (8, "Shane", 32), (9, "Larry", 29), (10, "Kimberly", 29), (11, "Alex", 28), (12, "Garry", 25), (13, "Max", 31))).toDF("emp_id","name","age")
employees: org.apache.spark.sql.DataFrame = [emp_id: int, name: string ... 1 more field]
scala> // From JSON: reading a JSON file
scala> val salary = spark.read.json("./salary.json")
salary: org.apache.spark.sql.DataFrame = [e_id: bigint, salary: bigint]
scala> val designation = spark.read.json("./designation.json")
designation: org.apache.spark.sql.DataFrame = [id: bigint, role: string]
```

# 数据准备

数据质量一直是行业中普遍存在的问题。不正确或不一致的数据可能会产生你分析的误导性结果。如果数据没有经过清洗和准备，按照要求，实施更好的算法或构建更好的模型也不会有太大帮助。有一个行业术语叫做**数据工程**，指的是数据的获取和准备。这通常由数据科学家完成，在一些组织中，还有专门的团队负责这个目的。然而，在准备数据时，通常需要科学的视角来做正确的处理。例如，你可能不只是进行*均值替换*来处理缺失值，还要查看数据分布以找到更合适的替代值。另一个例子是，你可能不只是查看箱线图或散点图来寻找异常值，因为可能存在多变量异常值，如果你只绘制一个变量，是看不到的。有不同的方法，比如**高斯混合模型**（**GMMs**）和**期望最大化**（**EM**）算法，使用**马哈拉诺比斯距离**来寻找多变量异常值。

数据准备阶段是一个非常重要的阶段，不仅是为了算法能够正常工作，也是为了让你更好地理解你的数据，以便在实施算法时采取正确的方法。

一旦数据从不同的来源获取到，下一步就是将它们整合起来，以便对数据作为一个整体进行清洗、格式化和转换，以满足你的分析需求。请注意，根据情况，你可能需要从这些来源中取样数据，然后准备数据进行进一步分析。本章后面将讨论可以使用的各种取样技术。

## 数据整合

在本节中，我们将看看如何合并从各种数据源获取的数据：

**Python**

```scala
// Creating the final data matrix using the join operation
>>> final_data = employees.join(salary, employees.emp_id == salary.e_id).join(designation, employees.emp_id == designation.id).select("emp_id", "name", "age", "role", "salary")
>>> final_data.show(5)
+------+-----+---+---------+------+
|emp_id| name|age|     role|salary|
+------+-----+---+---------+------+
|     1| John| 25|Associate| 10000|
|     2|  Ray| 35|  Manager| 12000|
|     3| Mike| 24|  Manager| 12000|
|     4| Jane| 28|Associate|  null|
|     5|Kevin| 26|  Manager|   120|
+------+-----+---+---------+------+
only showing top 5 rows
```

**Scala**

```scala
// Creating the final data matrix using the join operation
scala> val final_data = employees.join(salary, $"emp_id" === $"e_id").join(designation, $"emp_id" === $"id").select("emp_id", "name", "age", "role", "salary")
final_data: org.apache.spark.sql.DataFrame = [emp_id: int, name: string ... 3 more fields]
```

从这些来源整合数据后，最终数据集（在本例中是`final_data`）应该是以下格式（只是示例数据）：

| **emp_id** | **name** | **age** | **role** | **salary** |
| --- | --- | --- | --- | --- |
| 1 | John | 25 | 职员 | 10,000 美元 |
| 2 | Ray | 35 | 经理 | 12,000 美元 |
| 3 | Mike | 24 | 经理 | 12,000 美元 |
| 4 | Jane | 28 | 职员 | null |
| 5 | Kevin | 26 | 经理 | 12,000 美元 |
| 6 | Vincent | 35 | 高级经理 | 22,000 美元 |
| 7 | James | 38 | 高级经理 | 20,000 美元 |
| 8 | Shane | 32 | 经理 | 12,000 美元 |
| 9 | Larry | 29 | 经理 | 10,000 美元 |
| 10 | Kimberly | 29 | 职员 | 8,000 美元 |
| 11 | Alex | 28 | 经理 | 12,000 美元 |
| 12 | Garry | 25 | 经理 | 12,000 美元 |
| 13 | Max | 31 | 经理 | 12,000 美元 |

## 数据清洗

一旦您将数据整合到一个地方，非常重要的是在分析之前花足够的时间和精力对其进行清理。这是一个迭代的过程，因为您必须验证对数据所采取的操作，并持续进行，直到对数据质量感到满意。建议您花时间分析您在数据中检测到的异常的原因。

任何数据集中通常都存在一定程度的不纯度。数据可能存在各种问题，但我们将解决一些常见情况，例如缺失值、重复值、转换或格式化（向数字添加或删除数字，将一列拆分为两列，将两列合并为一列）。

### 缺失值处理

处理缺失值的方法有很多种。一种方法是删除包含缺失值的行。即使单个列有缺失值，我们可能也想删除一行，或者对不同的列采取不同的策略。只要该行中的缺失值总数低于阈值，我们可能希望保留该行。另一种方法可能是用常量值替换空值，比如在数值变量的情况下用平均值替换空值。

在本节中，我们将不会提供 Scala 和 Python 的一些示例，并尝试涵盖各种情景，以便给您更广泛的视角。

**Python**

```scala
// Dropping rows with missing value(s)
>>> clean_data = final_data.na.drop()
>>> 
// Replacing missing value by mean
>>> import math
>>> from pyspark.sql import functions as F
>>> mean_salary = math.floor(salary.select(F.mean('salary')).collect()[0][0])
>>> clean_data = final_data.na.fill({'salary' : mean_salary})
>>> 
//Another example for missing value treatment
>>> authors = [['Thomas','Hardy','June 2, 1840'],
       ['Charles','Dickens','7 February 1812'],
        ['Mark','Twain',None],
        ['Jane','Austen','16 December 1775'],
      ['Emily',None,None]]
>>> df1 = sc.parallelize(authors).toDF(
       ["FirstName","LastName","Dob"])
>>> df1.show()
+---------+--------+----------------+
|FirstName|LastName|             Dob|
+---------+--------+----------------+
|   Thomas|   Hardy|    June 2, 1840|
|  Charles| Dickens| 7 February 1812|
|     Mark|   Twain|            null|
|     Jane|  Austen|16 December 1775|
|    Emily|    null|            null|
+---------+--------+----------------+

// Drop rows with missing values
>>> df1.na.drop().show()
+---------+--------+----------------+
|FirstName|LastName|             Dob|
+---------+--------+----------------+
|   Thomas|   Hardy|    June 2, 1840|
|  Charles| Dickens| 7 February 1812|
|     Jane|  Austen|16 December 1775|
+---------+--------+----------------+

// Drop rows with at least 2 missing values
>>> df1.na.drop(thresh=2).show()
+---------+--------+----------------+
|FirstName|LastName|             Dob|
+---------+--------+----------------+
|   Thomas|   Hardy|    June 2, 1840|
|  Charles| Dickens| 7 February 1812|
|     Mark|   Twain|            null|
|     Jane|  Austen|16 December 1775|
+---------+--------+----------------+

// Fill all missing values with a given string
>>> df1.na.fill('Unknown').show()
+---------+--------+----------------+
|FirstName|LastName|             Dob|
+---------+--------+----------------+
|   Thomas|   Hardy|    June 2, 1840|
|  Charles| Dickens| 7 February 1812|
|     Mark|   Twain|         Unknown|
|     Jane|  Austen|16 December 1775|
|    Emily| Unknown|         Unknown|
+---------+--------+----------------+

// Fill missing values in each column with a given string
>>> df1.na.fill({'LastName':'--','Dob':'Unknown'}).show()
+---------+--------+----------------+
|FirstName|LastName|             Dob|
+---------+--------+----------------+
|   Thomas|   Hardy|    June 2, 1840|
|  Charles| Dickens| 7 February 1812|
|     Mark|   Twain|         Unknown|
|     Jane|  Austen|16 December 1775|
|    Emily|      --|         Unknown|
+---------+--------+----------------+
```

**Scala**

```scala
//Missing value treatment
// Dropping rows with missing value(s)
scala> var clean_data = final_data.na.drop() //Note the var declaration instead of val
clean_data: org.apache.spark.sql.DataFrame = [emp_id: int, name: string ... 3 more fields]
scala>

// Replacing missing value by mean
scal> val mean_salary = final_data.select(floor(avg("salary"))).
            first()(0).toString.toDouble
mean_salary: Double = 20843.0
scal> clean_data = final_data.na.fill(Map("salary" -> mean_salary)) 

//Reassigning clean_data
clean_data: org.apache.spark.sql.DataFrame = [emp_id: int, name: string ... 3 more fields]
scala>

//Another example for missing value treatment
scala> case class Author (FirstName: String, LastName: String, Dob: String)
defined class Author
scala> val authors = Seq(
        Author("Thomas","Hardy","June 2, 1840"),
        Author("Charles","Dickens","7 February 1812"),
        Author("Mark","Twain",null),
        Author("Emily",null,null))
authors: Seq[Author] = List(Author(Thomas,Hardy,June 2, 1840),
   Author(Charles,Dickens,7 February 1812), Author(Mark,Twain,null),
   Author(Emily,null,null))
scala> val ds1 = sc.parallelize(authors).toDS()
ds1: org.apache.spark.sql.Dataset[Author] = [FirstName: string, LastName: string ... 1 more field]
scala> ds1.show()
+---------+--------+---------------+
|FirstName|LastName|            Dob|
+---------+--------+---------------+
|   Thomas|   Hardy|   June 2, 1840|
|  Charles| Dickens|7 February 1812|
|     Mark|   Twain|           null|
|    Emily|    null|           null|
+---------+--------+---------------+
scala>

// Drop rows with missing values
scala> ds1.na.drop().show()
+---------+--------+---------------+
|FirstName|LastName|            Dob|
+---------+--------+---------------+
|   Thomas|   Hardy|   June 2, 1840|
|  Charles| Dickens|7 February 1812|
+---------+--------+---------------+
scala>

//Drop rows with at least 2 missing values
//Note that there is no direct scala function to drop rows with at least n missing values
//However, you can drop rows containing under specified non nulls
//Use that function to achieve the same result
scala> ds1.na.drop(minNonNulls = df1.columns.length - 1).show()
//Fill all missing values with a given string
scala> ds1.na.fill("Unknown").show()
+---------+--------+---------------+
|FirstName|LastName|            Dob|
+---------+--------+---------------+
|   Thomas|   Hardy|   June 2, 1840|
|  Charles| Dickens|7 February 1812|
|     Mark|   Twain|        Unknown|
|    Emily| Unknown|        Unknown|
+---------+--------+---------------+
scala>

//Fill missing values in each column with a given string
scala> ds1.na.fill(Map("LastName"->"--",
                    "Dob"->"Unknown")).show()
+---------+--------+---------------+
|FirstName|LastName|            Dob|
+---------+--------+---------------+
|   Thomas|   Hardy|   June 2, 1840|
|  Charles| Dickens|7 February 1812|
|     Mark|   Twain|        Unknown|
|    Emily|      --|        Unknown|
+---------+--------+---------------+
```

### 异常值处理

了解异常值是什么也很重要，以便妥善处理。简而言之，异常值是一个数据点，它与其他数据点不具有相同的特征。例如：如果您有一个学童数据集，并且有一些年龄值在 30-40 范围内，那么它们可能是异常值。现在让我们看一个不同的例子：如果您有一个数据集，其中一个变量只能在两个范围内具有数据点，比如在 10-20 或 80-90 范围内，那么在这两个范围之间具有值的数据点（比如 40 或 55）也可能是异常值。在这个例子中，40 或 55 既不属于 10-20 范围，也不属于 80-90 范围，是异常值。

此外，可能存在单变量异常值，也可能存在多变量异常值。出于简单起见，我们将专注于本书中的单变量异常值，因为在撰写本书时，Spark MLlib 可能没有所有所需的算法。

为了处理异常值，您必须首先查看是否存在异常值。有不同的方法，例如摘要统计和绘图技术，来查找异常值。您可以使用内置的库函数，例如 Python 的`matplotlib`来可视化您的数据。您可以通过连接到 Spark 通过笔记本（例如 Jupyter）来执行此操作，以便生成可视化效果，这在命令行上可能不可能。

一旦找到异常值，您可以删除包含异常值的行，或者在异常值的位置上填充平均值，或者根据您的情况进行更相关的操作。让我们在这里看一下平均替换方法：

**Python**

```scala
// Identify outliers and replace them with mean
//The following example reuses the clean_data dataset and mean_salary computed in previous examples
>>> mean_salary
20843.0
>>> 
//Compute deviation for each row
>>> devs = final_data.select(((final_data.salary - mean_salary) ** 2).alias("deviation"))

//Compute standard deviation
>>> stddev = math.floor(math.sqrt(devs.groupBy().
          avg("deviation").first()[0]))

//check standard deviation value
>>> round(stddev,2)
30351.0
>>> 
//Replace outliers beyond 2 standard deviations with the mean salary
>>> no_outlier = final_data.select(final_data.emp_id, final_data.name, final_data.age, final_data.salary, final_data.role, F.when(final_data.salary.between(mean_salary-(2*stddev), mean_salary+(2*stddev)), final_data.salary).otherwise(mean_salary).alias("updated_salary"))
>>> 
//Observe modified values
>>> no_outlier.filter(no_outlier.salary != no_outlier.updated_salary).show()
+------+----+---+------+-------+--------------+
|emp_id|name|age|salary|   role|updated_salary|
+------+----+---+------+-------+--------------+
|    13| Max| 31|120000|Manager|       20843.0|
+------+----+---+------+-------+--------------+
>>>

```

**Scala**

```scala
// Identify outliers and replace them with mean
//The following example reuses the clean_data dataset and mean_salary computed in previous examples
//Compute deviation for each row
scala> val devs = clean_data.select(((clean_data("salary") - mean_salary) *
        (clean_data("salary") - mean_salary)).alias("deviation"))
devs: org.apache.spark.sql.DataFrame = [deviation: double]

//Compute standard deviation
scala> val stddev = devs.select(sqrt(avg("deviation"))).
            first().getDouble(0)
stddev: Double = 29160.932595617614

//If you want to round the stddev value, use BigDecimal as shown
scala> scala.math.BigDecimal(stddev).setScale(2,
             BigDecimal.RoundingMode.HALF_UP)
res14: scala.math.BigDecimal = 29160.93
scala>

//Replace outliers beyond 2 standard deviations with the mean salary
scala> val outlierfunc = udf((value: Long, mean: Double) => {if (value > mean+(2*stddev)
            || value < mean-(2*stddev)) mean else value})

//Use the UDF to compute updated_salary
//Note the usage of lit() to wrap a literal as a column
scala> val no_outlier = clean_data.withColumn("updated_salary",
            outlierfunc(col("salary"),lit(mean_salary)))

//Observe modified values
scala> no_outlier.filter(no_outlier("salary") =!=  //Not !=
             no_outlier("updated_salary")).show()
+------+----+---+-------+------+--------------+
|emp_id|name|age|   role|salary|updated_salary|
+------+----+---+-------+------+--------------+
|    13| Max| 31|Manager|120000|       20843.0|
+------+----+---+-------+------+--------------+
```

### 重复值处理

有不同的方法来处理数据集中的重复记录。我们将在以下代码片段中演示这些方法：

**Python**

```scala
// Deleting the duplicate rows
>>> authors = [['Thomas','Hardy','June 2,1840'],
    ['Thomas','Hardy','June 2,1840'],
    ['Thomas','H',None],
    ['Jane','Austen','16 December 1775'],
    ['Emily',None,None]]
>>> df1 = sc.parallelize(authors).toDF(
      ["FirstName","LastName","Dob"])
>>> df1.show()
+---------+--------+----------------+
|FirstName|LastName|             Dob|
+---------+--------+----------------+
|   Thomas|   Hardy|    June 2, 1840|
|   Thomas|   Hardy|    June 2, 1840|
|   Thomas|       H|            null|
|     Jane|  Austen|16 December 1775|
|    Emily|    null|            null|
+---------+--------+----------------+

// Drop duplicated rows
>>> df1.dropDuplicates().show()
+---------+--------+----------------+
|FirstName|LastName|             Dob|
+---------+--------+----------------+
|    Emily|    null|            null|
|     Jane|  Austen|16 December 1775|
|   Thomas|       H|            null|
|   Thomas|   Hardy|    June 2, 1840|
+---------+--------+----------------+

// Drop duplicates based on a sub set of columns
>>> df1.dropDuplicates(subset=["FirstName"]).show()
+---------+--------+----------------+
|FirstName|LastName|             Dob|
+---------+--------+----------------+
|    Emily|    null|            null|
|   Thomas|   Hardy|    June 2, 1840|
|     Jane|  Austen|16 December 1775|
+---------+--------+----------------+
>>> 
```

**Scala:**

```scala
//Duplicate values treatment
// Reusing the Author case class
// Deleting the duplicate rows
scala> val authors = Seq(
            Author("Thomas","Hardy","June 2,1840"),
            Author("Thomas","Hardy","June 2,1840"),
            Author("Thomas","H",null),
            Author("Jane","Austen","16 December 1775"),
            Author("Emily",null,null))
authors: Seq[Author] = List(Author(Thomas,Hardy,June 2,1840), Author(Thomas,Hardy,June 2,1840), Author(Thomas,H,null), Author(Jane,Austen,16 December 1775), Author(Emily,null,null))
scala> val ds1 = sc.parallelize(authors).toDS()
ds1: org.apache.spark.sql.Dataset[Author] = [FirstName: string, LastName: string ... 1 more field]
scala> ds1.show()
+---------+--------+----------------+
|FirstName|LastName|             Dob|
+---------+--------+----------------+
|   Thomas|   Hardy|     June 2,1840|
|   Thomas|   Hardy|     June 2,1840|
|   Thomas|       H|            null|
|     Jane|  Austen|16 December 1775|
|    Emily|    null|            null|
+---------+--------+----------------+
scala>

// Drop duplicated rows
scala> ds1.dropDuplicates().show()
+---------+--------+----------------+                                          
|FirstName|LastName|             Dob|
+---------+--------+----------------+
|     Jane|  Austen|16 December 1775|
|    Emily|    null|            null|
|   Thomas|   Hardy|     June 2,1840|
|   Thomas|       H|            null|
+---------+--------+----------------+
scala>

// Drop duplicates based on a sub set of columns
scala> ds1.dropDuplicates("FirstName").show()
+---------+--------+----------------+                                           
|FirstName|LastName|             Dob|
+---------+--------+----------------+
|    Emily|    null|            null|
|     Jane|  Austen|16 December 1775|
|   Thomas|   Hardy|     June 2,1840|
+---------+--------+----------------+
```

## 数据转换

可能会有各种各样的数据转换需求，每种情况大多是独一无二的。我们将涵盖一些基本类型的转换，如下所示：

+   将两列合并为一列

+   向现有字符/数字添加字符/数字

+   从现有的字符/数字中删除或替换字符/数字

+   更改日期格式

**Python**

```scala
// Merging columns
//Create a udf to concatenate two column values
>>> import pyspark.sql.functions
>>> concat_func = pyspark.sql.functions.udf(lambda name, age: name + "_" + str(age))

//Apply the udf to create merged column
>>> concat_df = final_data.withColumn("name_age", concat_func(final_data.name, final_data.age))
>>> concat_df.show(4)
+------+----+---+---------+------+--------+
|emp_id|name|age|     role|salary|name_age|
+------+----+---+---------+------+--------+
|     1|John| 25|Associate| 10000| John_25|
|     2| Ray| 35|  Manager| 12000|  Ray_35|
|     3|Mike| 24|  Manager| 12000| Mike_24|
|     4|Jane| 28|Associate|  null| Jane_28|
+------+----+---+---------+------+--------+
only showing top 4 rows
// Adding constant to data
>>> data_new = concat_df.withColumn("age_incremented",concat_df.age + 10)
>>> data_new.show(4)
+------+----+---+---------+------+--------+---------------+
|emp_id|name|age|     role|salary|name_age|age_incremented|
+------+----+---+---------+------+--------+---------------+
|     1|John| 25|Associate| 10000| John_25|             35|
|     2| Ray| 35|  Manager| 12000|  Ray_35|             45|
|     3|Mike| 24|  Manager| 12000| Mike_24|             34|
|     4|Jane| 28|Associate|  null| Jane_28|             38|
+------+----+---+---------+------+--------+---------------+
only showing top 4 rows
>>> 

//Replace values in a column
>>> df1.replace('Emily','Charlotte','FirstName').show()
+---------+--------+----------------+
|FirstName|LastName|             Dob|
+---------+--------+----------------+
|   Thomas|   Hardy|    June 2, 1840|
|  Charles| Dickens| 7 February 1812|
|     Mark|   Twain|            null|
|     Jane|  Austen|16 December 1775|
|Charlotte|    null|            null|
+---------+--------+----------------+

// If the column name argument is omitted in replace, then replacement is applicable to all columns
//Append new columns based on existing values in a column
//Give 'LastName' instead of 'Initial' if you want to overwrite
>>> df1.withColumn('Initial',df1.LastName.substr(1,1)).show()
+---------+--------+----------------+-------+
|FirstName|LastName|             Dob|Initial|
+---------+--------+----------------+-------+
|   Thomas|   Hardy|    June 2, 1840|      H|
|  Charles| Dickens| 7 February 1812|      D|
|     Mark|   Twain|            null|      T|
|     Jane|  Austen|16 December 1775|      A|
|    Emily|    null|            null|   null|
+---------+--------+----------------+-------+
```

**Scala:**

```scala
// Merging columns
//Create a udf to concatenate two column values
scala> val concatfunc = udf((name: String, age: Integer) =>
                           {name + "_" + age})
concatfunc: org.apache.spark.sql.expressions.UserDefinedFunction = UserDefinedFunction(<function2>,StringType,Some(List(StringType, IntegerType)))
scala>

//Apply the udf to create merged column
scala> val concat_df = final_data.withColumn("name_age",
                         concatfunc($"name", $"age"))
concat_df: org.apache.spark.sql.DataFrame =
         [emp_id: int, name: string ... 4 more fields]
scala> concat_df.show(4)
+------+----+---+---------+------+--------+
|emp_id|name|age|     role|salary|name_age|
+------+----+---+---------+------+--------+
|     1|John| 25|Associate| 10000| John_25|
|     2| Ray| 35|  Manager| 12000|  Ray_35|
|     3|Mike| 24|  Manager| 12000| Mike_24|
|     4|Jane| 28|Associate|  null| Jane_28|
+------+----+---+---------+------+--------+
only showing top 4 rows
scala>

// Adding constant to data
scala> val addconst = udf((age: Integer) => {age + 10})
addconst: org.apache.spark.sql.expressions.UserDefinedFunction =
      UserDefinedFunction(<function1>,IntegerType,Some(List(IntegerType)))
scala> val data_new = concat_df.withColumn("age_incremented",
                 addconst(col("age")))
data_new: org.apache.spark.sql.DataFrame =
     [emp_id: int, name: string ... 5 more fields]
scala> data_new.show(4)
+------+----+---+---------+------+--------+---------------+
|emp_id|name|age|     role|salary|name_age|age_incremented|
+------+----+---+---------+------+--------+---------------+
|     1|John| 25|Associate| 10000| John_25|             35|
|     2| Ray| 35|  Manager| 12000|  Ray_35|             45|
|     3|Mike| 24|  Manager| 12000| Mike_24|             34|
|     4|Jane| 28|Associate|  null| Jane_28|             38|
+------+----+---+---------+------+--------+---------------+
only showing top 4 rows

// Replace values in a column
//Note: As of Spark 2.0.0, there is no replace on DataFrame/ Dataset does not work so .na. is a work around
scala> ds1.na.replace("FirstName",Map("Emily" -> "Charlotte")).show()
+---------+--------+---------------+
|FirstName|LastName|            Dob|
+---------+--------+---------------+
|   Thomas|   Hardy|   June 2, 1840|
|  Charles| Dickens|7 February 1812|
|     Mark|   Twain|           null|
|Charlotte|    null|           null|
+---------+--------+---------------+
scala>

// If the column name argument is "*" in replace, then replacement is applicable to all columns
//Append new columns based on existing values in a column
//Give "LastName" instead of "Initial" if you want to overwrite
scala> ds1.withColumn("Initial",ds1("LastName").substr(1,1)).show()
+---------+--------+---------------+-------+
|FirstName|LastName|            Dob|Initial|
+---------+--------+---------------+-------+
|   Thomas|   Hardy|   June 2, 1840|      H|
|  Charles| Dickens|7 February 1812|      D|
|     Mark|   Twain|           null|      T|
|    Emily|    null|           null|   null|
+---------+--------+---------------+-------+
```

现在我们已经熟悉了基本示例，让我们来看一个稍微复杂的例子。您可能已经注意到作者数据中的日期列具有不同的日期格式。在某些情况下，月份后面跟着日期，反之亦然。这种异常在现实世界中很常见，数据可能来自不同的来源。在这里，我们正在研究一个情况，即日期列具有许多不同日期格式的数据点。我们需要将所有不同的日期格式标准化为一个格式。为此，我们首先必须创建一个**用户定义的函数**（**udf**），该函数可以处理不同的格式并将其转换为一个通用格式。

```scala
// Date conversions
//Create udf for date conversion that converts incoming string to YYYY-MM-DD format
// The function assumes month is full month name and year is always 4 digits
// Separator is always a space or comma
// Month, date and year may come in any order
//Reusing authors data
>>> authors = [['Thomas','Hardy','June 2, 1840'],
        ['Charles','Dickens','7 February 1812'],
        ['Mark','Twain',None],
        ['Jane','Austen','16 December 1775'],
        ['Emily',None,None]]
>>> df1 = sc.parallelize(authors).toDF(
      ["FirstName","LastName","Dob"])
>>> 

// Define udf
//Note: You may create this in a script file and execute with execfile(filename.py)
>>> def toDate(s):
 import re
 year = month = day = ""
 if not s:
  return None
 mn = [0,'January','February','March','April','May',
  'June','July','August','September',
  'October','November','December']

 //Split the string and remove empty tokens
 l = [tok for tok in re.split(",| ",s) if tok]

//Assign token to year, month or day
 for a in l:
  if a in mn:
   month = "{:0>2d}".format(mn.index(a))
  elif len(a) == 4:
   year = a
  elif len(a) == 1:
   day = '0' + a
  else:
   day = a
 return year + '-' + month + '-' + day
>>> 

//Register the udf
>>> from pyspark.sql.functions import udf
>>> from pyspark.sql.types import StringType
>>> toDateUDF = udf(toDate, StringType())

//Apply udf
>>> df1.withColumn("Dob",toDateUDF("Dob")).show()
+---------+--------+----------+
|FirstName|LastName|       Dob|
+---------+--------+----------+
|   Thomas|   Hardy|1840-06-02|
|  Charles| Dickens|1812-02-07|
|     Mark|   Twain|      null|
|     Jane|  Austen|1775-12-16|
|    Emily|    null|      null|
+---------+--------+----------+
>>> 
```

**Scala**

```scala
//Date conversions
//Create udf for date conversion that converts incoming string to YYYY-MM-DD format
// The function assumes month is full month name and year is always 4 digits
// Separator is always a space or comma
// Month, date and year may come in any order
//Reusing authors case class and data
>>> val authors = Seq(
        Author("Thomas","Hardy","June 2, 1840"),
        Author("Charles","Dickens","7 February 1812"),
        Author("Mark","Twain",null),
        Author("Jane","Austen","16 December 1775"),
        Author("Emily",null,null))
authors: Seq[Author] = List(Author(Thomas,Hardy,June 2, 1840), Author(Charles,Dickens,7 February 1812), Author(Mark,Twain,null), Author(Jane,Austen,16 December 1775), Author(Emily,null,null))
scala> val ds1 = sc.parallelize(authors).toDS()
ds1: org.apache.spark.sql.Dataset[Author] = [FirstName: string, LastName: string ... 1 more field]
scala>

// Define udf
//Note: You can type :paste on REPL to paste  multiline code. CTRL + D signals end of paste mode
def toDateUDF = udf((s: String) => {
    var (year, month, day) = ("","","")
    val mn = List("","January","February","March","April","May",
        "June","July","August","September",
        "October","November","December")
    //Tokenize the date string and remove trailing comma, if any
    if(s != null) {
      for (x <- s.split(" ")) {
        val token = x.stripSuffix(",")
        token match {
        case "" =>
        case x if (mn.contains(token)) =>
            month = "%02d".format(mn.indexOf(token))
        case x if (token.length() == 4) =>
            year = token
        case x =>
            day = token
        }
     }   //End of token processing for
     year + "-" + month + "-" + day=
   } else {
       null
   }
})
toDateUDF: org.apache.spark.sql.expressions.UserDefinedFunction
scala>

//Apply udf and convert date strings to standard form YYYY-MM-DD
scala> ds1.withColumn("Dob",toDateUDF(ds1("Dob"))).show()
+---------+--------+----------+
|FirstName|LastName|       Dob|
+---------+--------+----------+
|   Thomas|   Hardy| 1840-06-2|
|  Charles| Dickens| 1812-02-7|
|     Mark|   Twain|      null|
|     Jane|  Austen|1775-12-16|
|    Emily|    null|      null|
+---------+--------+----------+
```

这样就整齐地排列了出生日期字符串。随着我们遇到更多日期格式的变化，我们可以不断调整 udf。

在进行数据分析之前，非常重要的一点是，在从开始数据采集到清理和转换的过程中，您应该暂停一下，重新评估您所采取的行动。有很多情况下，由于分析和建模的数据不正确，导致了大量的时间和精力投入的项目失败。这些案例成为了著名的计算机格言“垃圾进，垃圾出”（**GIGO**）的完美例子。

# 统计学基础

统计学领域主要是关于使用数学程序以某种有意义的方式对数据集的原始事实和数字进行总结，以便您能够理解。这包括但不限于：收集数据，分析数据，解释数据和表示数据。

统计学领域的存在主要是因为通常不可能收集整个人口的数据。因此，使用统计技术，我们通过处理不确定性，利用样本统计来估计总体参数。

在本节中，我们将介绍一些基本的统计和分析技术，这些技术将帮助我们全面理解本书涵盖的概念。

统计学的研究可以大致分为两个主要分支：

+   描述性统计

+   推断统计

以下图表描述了这两个术语，并展示了我们如何从样本中估计总体参数：

![统计学基础](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_05_002.jpg)

在开始这些工作之前，重要的是要对抽样和分布有一些了解。

## 抽样

通过抽样技术，我们只需取一部分人口数据集并对其进行处理：

![抽样](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_05_003.jpg)

但是为什么要抽样？以下是抽样的各种原因：

+   难以获取整个人口的数据；例如，任何国家的公民身高。

+   难以处理整个数据集。当我们谈论像 Spark 这样的大数据计算平台时，这个挑战的范围几乎消失了。然而，可能会出现这样的情况，您必须将整个数据视为样本，并将您的分析结果推广到未来的时间或更大的人口。

+   难以绘制大量数据以进行可视化。这可能会有技术上的限制。

+   用于验证分析或验证预测模型 - 尤其是当您使用小数据集并且必须依赖交叉验证时。

为了有效抽样，有两个重要的限制：一个是确定样本量，另一个是选择抽样技术。样本量极大地影响了对总体参数的估计。在涵盖了一些先决基础知识后，我们将在本章后面涵盖这一方面。在本节中，我们将专注于抽样技术。

有各种基于概率的（每个样本被选中的概率已知）和非概率的（每个样本被选中的概率未知）抽样技术可用，但我们将把讨论限制在仅基于概率的技术上。

### 简单随机抽样

**简单随机抽样**（**SRS**）是最基本的概率抽样方法，其中每个元素被选择的概率相同。这意味着每个可能的*n*元素样本被选择的机会是相等的。

### 系统抽样

系统抽样可能是所有基于概率的抽样技术中最简单的，其中总体的每个*k*元素被抽样。因此，这又被称为间隔抽样。它从随机选择的固定起始点开始，然后估计一个间隔（第*k*个元素，其中*k =（总体大小）/（样本大小）*）。在这里，当达到末尾时，通过元素的进展循环开始，直到达到样本大小。

### 分层抽样

当总体内的子群体或子群体变化时，这种抽样技术是首选，因为其他抽样技术可能无法帮助提取一个良好代表总体的样本。通过分层抽样，总体被划分为同质子群体称为**分层**，然后从这些分层中随机选择样本，比例与总体相同。因此，样本中的分层大小与总体大小的比率也得到了维持：

**Python**

```scala
/* ”Sample” function is defined for DataFrames (not RDDs) which takes three parameters:
withReplacement - Sample with replacement or not (input: True/False)
fraction - Fraction of rows to generate (input: any number between 0 and 1 as per your requirement of sample size)
seed - Seed for sampling (input: Any random seed)
*/
>>> sample1 = data_new.sample(False, 0.6) //With random seed as no seed value specified
>>> sample2 = data_new.sample(False, 0.6, 10000) //With specific seed value of 10000
```

**Scala**：

```scala
scala> val sample1 = data_new.sample(false, 0.6) //With random seed as no seed value specified
sample1: org.apache.spark.sql.Dataset[org.apache.spark.sql.Row] = [emp_id: int, name: string ... 5 more fields]
scala> val sample2 = data_new.sample(false, 0.6, 10000) //With specific seed value of 10000
sample2: org.apache.spark.sql.Dataset[org.apache.spark.sql.Row] = [emp_id: int, name: string ... 5 more fields]
```

### 注意

我们只研究了 DataFrame 上的抽样；还有 MLlib 库函数，如`sampleByKey`和`sampleByKeyExact`，可以对键值对的 RDD 进行分层抽样。查看`spark.util.random`包，了解伯努利、泊松或随机抽样器。

## 数据分布

了解数据的分布是您需要执行的主要任务之一，以将数据转化为信息。分析变量的分布有助于检测异常值，可视化数据中的趋势，并且还可以塑造您对手头数据的理解。这有助于正确思考并采取正确的方法来解决业务问题。绘制分布使其在视觉上更直观，我们将在*描述性统计*部分中涵盖这一方面。

### 频率分布

频率分布解释了变量取值和它们出现的频率。通常用一个表格表示，其中包含每个可能的值及其相应的出现次数。

让我们考虑一个例子，我们掷一个六面骰子 100 次，并观察以下频率：

![频率分布](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/Chapter-5_NEw.jpg)

频率表

同样，您可能会观察到每组 100 次掷骰子的不同分布，因为这将取决于机会。

有时，您可能对发生的比例感兴趣，而不仅仅是发生的次数。在前面的掷骰子示例中，我们总共掷了 100 次骰子，因此比例分布或**相对频率分布**将如下所示：

![频率分布](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/Final-5-RT-3.jpg)

相对频率表

### 概率分布

在掷骰子的相同例子中，我们知道总概率为 1 分布在骰子的所有面上。这意味着 1/6（约 0.167）的概率与面 1 到面 6 相关联。无论你掷骰子的次数多少（一个公平的骰子！），1/6 的相同概率将均匀分布在骰子的所有面上。因此，如果你绘制这个分布，它将如下所示：

![概率分布](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/Chapter-new.jpg)

概率分布

我们在这里看了三种分布 - 频率分布、相对频率分布和概率分布。

这个概率分布实际上是人口的分布。在现实世界中，有时我们对人口分布有先验知识（在我们的例子中，是一个公平骰子的六个面上的概率为 0.167），有时我们没有。在我们没有人口分布的情况下，找到人口分布本身成为推断统计的一部分。此外，与公平骰子的例子不同，其中所有面都与相同的概率相关联，变量可以取的值可能与不同的概率相关联，并且它们也可能遵循特定类型的分布。

现在是时候揭示秘密了！相对频率分布与概率分布之间的关系是统计推断的基础。相对频率分布也称为基于我们观察到的样本的经验分布（在这里，是 100 个样本）。正如前面讨论的那样，每 100 次掷骰子的经验分布会因机会而异。现在，掷骰子的次数越多，相对频率分布就会越接近概率分布。因此，无限次掷骰子的相对频率就是概率分布，而概率分布又是人口分布。

有各种各样的概率分布，再次根据变量的类型分为两类 - 分类或连续。我们将在本章的后续部分详细介绍这些分布。然而，我们应该知道这些类别意味着什么！分类变量只能有几个类别；例如，通过/不通过，零/一，癌症/恶性是具有两个类别的分类变量的例子。同样，分类变量可以有更多的类别，例如红/绿/蓝，类型 1/类型 2/类型 3/类型 4 等。连续变量可以在给定范围内取任何值，并且在连续比例上进行测量，例如年龄、身高、工资等。理论上，连续变量的任何两个值之间可能有无限多个可能的值。例如，在 5'6"和 6'4"之间的身高值（英尺和英寸刻度），可能有许多分数值。在以厘米为单位的刻度上测量时也是如此。

# 描述性统计

在前一节中，我们学习了分布是如何形成的。在本节中，我们将学习如何通过描述性统计来描述它们。分布的两个重要组成部分可以帮助描述它，即其位置和其传播。

## 位置测量

位置测量是描述数据中心位置的单个值。位置的三个最常见的测量是平均值、中位数和众数。

### 平均值

到目前为止，最常见和广泛使用的集中趋势度量是**平均值**，也就是平均值。无论是样本还是人口，平均值或平均值都是所有元素的总和除以元素的总数。

### 中位数

**中位数**是数据系列中的中间值，当按任何顺序排序时，使得一半数据大于中位数，另一半数据小于中位数。当存在两个中间值（数据项数量为偶数时），中位数是这两个中间值的平均值。当数据存在异常值（极端值）时，中位数是更好的位置测量。

### 模式

**模式**是最频繁的数据项。它可以确定定性和定量数据。

Python

//重复使用在重复值处理中创建的 data_new

```scala
>>> mean_age = data_new.agg({'age': 'mean'}).first()[0]
>>> age_counts = data_new.groupBy("age").agg({"age": "count"}).alias("freq")
>>> mode_age = age_counts.sort(age_counts["COUNT(age)"].desc(), age_counts.age.asc()).first()[0]
>>> print(mean_age, mode_age)
(29.615384615384617, 25)
>>> age_counts.sort("count(age)",ascending=False).show(2)
+---+----------+                                                               
|age|count(age)|
+---+----------+
| 28|         3|
| 29|         2|
+---+----------+
only showing top 2 rows
```

Scala

```scala
//Reusing data_new created 
scala> val mean_age = data_new.select(floor(avg("age"))).first().getLong(0)
mean_age: Long = 29
scala> val mode_age = data_new.groupBy($"age").agg(count($"age")).
                 sort($"count(age)".desc, $"age").first().getInt(0)
mode_age: Int = 28
scala> val age_counts = data_new.groupBy("age").agg(count($"age") as "freq")
age_counts: org.apache.spark.sql.DataFrame = [age: int, freq: bigint]
scala> age_counts.sort($"freq".desc).show(2)
+---+----+                                                                     
|age|freq|
+---+----+
| 35|   2|
| 28|   2|
+---+----+
```

## 传播措施

传播措施描述了特定变量或数据项的数据是多么接近或分散。

### 范围

范围是变量的最小值和最大值之间的差异。它的一个缺点是它没有考虑数据中的每个值。

### 方差

要找到数据集中的变异性，我们可以从平均值中减去每个值，将它们平方以消除负号（也扩大幅度），然后将它们全部相加并除以总值的数量：

![方差](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_05_007.jpg)

如果数据更分散，方差将是一个很大的数字。它的一个缺点是它给异常值赋予了不应有的权重。

### 标准差

与方差类似，标准差也是数据内部分散的一种度量。方差的局限性在于数据的单位也被平方，因此很难将方差与数据集中的值联系起来。因此，标准差被计算为方差的平方根：

![标准差](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_05_008.jpg)

Python

```scala
//Reusing data_new created before
import math
>>> range_salary = data_new.agg({'salary': 'max'}).first()[0] - data_new.agg({'salary': 'min'}).first()[0]
>>> mean_salary = data_new.agg({'salary': 'mean'}).first()[0]
>>> salary_deviations = data_new.select(((data_new.salary - mean_salary) *
       (data_new.salary - mean_salary)).alias("deviation"))
>>> stddev_salary = math.sqrt(salary_deviations.agg({'deviation' : 
'avg'}).first()[0])
>>> variance_salary = salary_deviations.groupBy().avg("deviation").first()[0]
>>> print(round(range_salary,2), round(mean_salary,2),
      round(variance_salary,2), round(stddev_salary,2))
(119880.0, 20843.33, 921223322.22, 30351.66)
>>> 
```

Scala

```scala
//Reusing data_new created before
scala> val range_salary = data_new.select(max("salary")).first().
          getLong(0) - data_new.select(min("salary")).first().getLong(0)
range_salary: Long = 119880
scala> val mean_salary = data_new.select(floor(avg("salary"))).first().getLong(0)
mean_salary: Long = 20843
scala> val salary_deviations = data_new.select(((data_new("salary") - mean_salary)
                     * (data_new("salary") - mean_salary)).alias("deviation"))
salary_deviations: org.apache.spark.sql.DataFrame = [deviation: bigint]
scala> val variance_salary = { salary_deviations.select(avg("deviation"))
                                       .first().getDouble(0) }
variance_salary: Double = 9.212233223333334E8
scala> val stddev_salary = { salary_deviations
                    .select(sqrt(avg("deviation")))
                    .first().getDouble(0) }
stddev_salary: Double = 30351.660948510435
```

## 摘要统计

数据集的摘要统计是极其有用的信息，它可以让我们快速了解手头的数据。使用统计中可用的`colStats`函数，我们可以获得包含列最大值、最小值、平均值、方差、非零数和总计数的`RDD[Vector]`的多变量统计摘要。让我们通过一些代码示例来探索这一点：

Python

```scala
>>> import numpy
>>> from pyspark.mllib.stat import Statistics
// Create an RDD of number vectors
//This example creates an RDD with 5 rows with 5 elements each
>>> observations = sc.parallelize(numpy.random.random_integers(0,100,(5,5)))
// Compute column summary statistics.
//Note that the results may vary because of random numbers
>>> summary = Statistics.colStats(observations)
>>> print(summary.mean())       // mean value for each column
>>> print(summary.variance())  // column-wise variance
>>> print(summary.numNonzeros())// number of nonzeros in each column
```

Scala

```scala
scala> import org.apache.spark.mllib.linalg.Vectors
import org.apache.spark.mllib.linalg.Vectors
scala> import org.apache.spark.mllib.stat.{
          MultivariateStatisticalSummary, Statistics}
import org.apache.spark.mllib.stat.{MultivariateStatisticalSummary, Statistics}
// Create an RDD of number vectors
//This example creates an RDD with 5 rows with 5 elements each
scala> val observations = sc.parallelize(Seq.fill(5)(Vectors.dense(Array.fill(5)(
                    scala.util.Random.nextDouble))))
observations: org.apache.spark.rdd.RDD[org.apache.spark.mllib.linalg.Vector] = ParallelCollectionRDD[43] at parallelize at <console>:27
scala>
// Compute column summary statistics.
//Note that the results may vary because of random numbers
scala> val summary = Statistics.colStats(observations)
summary: org.apache.spark.mllib.stat.MultivariateStatisticalSummary = org.apache.spark.mllib.stat.MultivariateOnlineSummarizer@36836161
scala> println(summary.mean)  // mean value for each column
[0.5782406967737089,0.5903954680966121,0.4892908815930067,0.45680701799234835,0.6611492334819364]
scala> println(summary.variance)    // column-wise variance
[0.11893608153330748,0.07673977181967367,0.023169197889513014,0.08882605965192601,0.08360159585590332]
scala> println(summary.numNonzeros) // number of nonzeros in each column
[5.0,5.0,5.0,5.0,5.0]
```

### 提示

Apache Spark MLlib 基于 RDD 的 API 在 Spark 2.0 开始处于维护模式。它们预计将在 2.2+中被弃用，并在 Spark 3.0 中移除。

## 图形技术

要了解数据点的行为，您可能需要绘制它们并查看。但是，您需要一个平台来以*箱线图*、*散点图*或*直方图*等形式可视化您的数据。iPython/Jupyter 笔记本或 Spark 支持的任何其他第三方笔记本都可以用于在浏览器中可视化数据。Databricks 提供了他们自己的笔记本。可视化在其自己的章节中进行了介绍，本章重点介绍完整的生命周期。但是，Spark 提供了直方图数据准备，以便将桶范围和频率传输到客户端机器，而不是完整的数据集。以下示例显示了相同的内容。

Python

```scala
//Histogram
>>>from random import randint
>>> numRDD = sc.parallelize([randint(0,9) for x in xrange(1,1001)])
// Generate histogram data for given bucket count
>>> numRDD.histogram(5)
([0.0, 1.8, 3.6, 5.4, 7.2, 9], [202, 213, 215, 188, 182])
//Alternatively, specify ranges
>>> numRDD.histogram([0,3,6,10])
([0, 3, 6, 10], [319, 311, 370])
```

Scala：

```scala
//Histogram
scala> val numRDD = sc.parallelize(Seq.fill(1000)(
                    scala.util.Random.nextInt(10)))
numRDD: org.apache.spark.rdd.RDD[Int] =
     ParallelCollectionRDD[0] at parallelize at <console>:24
// Generate histogram data for given bucket count
scala> numRDD.histogram(5)
res10: (Array[Double], Array[Long]) = (Array(0.0, 1.8, 3.6, 5.4, 7.2, 9.0),Array(194, 209, 215, 195, 187))
scala>
//Alternatively, specify ranges
scala> numRDD.histogram(Array(0,3.0,6,10))
res13: Array[Long] = Array(293, 325, 382)
```

# 推断统计

我们看到描述性统计在描述和展示数据方面非常有用，但它们没有提供一种使用样本统计来推断人口参数或验证我们可能提出的任何假设的方法。因此，推断统计技术出现以满足这些要求。推断统计的一些重要用途包括：

+   人口参数的估计

+   假设检验

请注意，样本永远不能完美地代表一个群体，因为每次抽样都会自然地产生抽样误差，因此需要推断统计！让我们花一些时间了解各种类型的概率分布，这些分布可以帮助推断人口参数。

## 离散概率分布

离散概率分布用于对离散性数据进行建模，这意味着数据只能取特定的值，如整数。与分类变量不同，离散变量只能取数值数据，尤其是来自一组不同整数值的计数数据。此外，随机变量所有可能值的概率之和为 1。离散概率分布是用概率质量函数描述的。可以有各种类型的离散概率分布。以下是一些例子。

### 伯努利分布

伯努利分布是一种描述只有两种可能结果的试验的分布，例如成功/失败，正面/反面，六面骰子的点数是 4 或不是，发送的消息是否被接收等。伯努利分布可以推广到具有两种或更多可能结果的任何分类变量。

让我们以“考试通过率”为例，其中 0.6（60％）是学生通过考试的概率**P**，0.4（40％）是学生考试不及格的概率（**1-P**）。让我们将不及格表示为**0**，及格表示为**1**：

![伯努利分布](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_05_011.jpg)

这种分布无法回答诸如学生的预期通过率之类的问题，因为预期值（μ）将是该分布无法取得的某个分数。它只能意味着如果你抽取 1,000 名学生，那么有 600 名会通过，400 名会不及格。

### 二项分布

该分布可以描述一系列伯努利试验（每次只有两种可能结果）。此外，它假设一次试验的结果不会影响后续试验，并且任何事件发生的概率在每次试验中都是相同的。二项分布的一个例子是抛硬币五次。在这里，第一次抛硬币的结果不会影响第二次抛硬币的结果，并且与每个结果相关的概率在所有抛硬币中都是相同的。

如果*n*是试验次数，*p*是每次试验中成功的概率，则该二项分布的均值（μ）为：

*μ = n * p*

方差（σ2x）由以下公式给出：

*σ2x = n*p*(1-p).*

通常，遵循参数为*n*和*p*的二项分布的随机变量*X*，我们可以写为*X ~ B(n, p)*。对于这种分布，可以通过概率质量函数描述在*n*次试验中获得恰好*k*次成功的概率，如下所示：

![二项分布](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_05_012.jpg)![二项分布](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_05_013.jpg)

在这里，k = 0, 1, 2, ..., n

#### 样本问题

让我们假设一个假设情景。假设一个城市中有 24％的公司宣布他们将作为企业社会责任活动的一部分，为受海啸影响地区提供支持。在随机选择的 20 家公司样本中，找出宣布他们将帮助受海啸影响地区的公司数量的概率：

+   恰好三个

+   少于三

+   三个或更多

**解决方案**：

样本大小 = *n* = 20。

随机选择一家公司宣布将提供帮助的概率 = *P = 0.24*。

a) P(x = 3) = ²⁰C[3] (0.24)³ (0.76) ¹⁷ = 0.15

b) P(x < 3) = P(0) + P(1) + P(2)

= (0.76) ²⁰ + ²⁰C[1] (0.24) (0.76)¹⁹ + ²⁰C[2] (0.24)² (0.76)¹⁸

= 0.0041 + 0.0261 + 0.0783 = 0.11

c) P(x >= 3) = 1 - P(x <= 2) = 1- 0.11 = 0.89

请注意，二项分布广泛用于模拟从大小为*N*的总体中抽取大小为*n*的样本的成功率。如果是无放回抽样，则抽取将不再是独立的，因此将不再正确地遵循二项分布。然而，这样的情况确实存在，并且可以使用不同类型的分布进行建模，例如超几何分布。

### 泊松分布

泊松分布可以描述在固定时间或空间间隔内以已知平均速率发生的独立事件的概率。请注意，事件应该只有二进制结果，例如成功或失败，例如，您每天收到的电话数量或每小时通过信号的汽车数量。您需要仔细观察这些例子。请注意，这里您没有这些信息的相反一半，也就是说，您每天没有收到多少电话或者多少辆汽车没有通过那个信号。这些数据点没有另一半的信息。相反，如果我说 50 名学生中有 30 名通过了考试，您可以轻松推断出 20 名学生失败了！您有这些信息的另一半。

如果*µ*是发生的事件的平均数量（固定时间或空间间隔内的已知平均速率），则在同一间隔内发生*k*个事件的概率可以用概率质量函数描述：

![泊松分布](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_05_014.jpg)

这里，*k* = 0, 1, 2, 3...

前面的方程描述了泊松分布。

对于泊松分布，均值和方差是相同的。此外，泊松分布在其均值或方差增加时更趋于对称。

#### 示例问题

假设你知道工作日向消防站打电话的平均次数是 8。在给定的工作日中有 11 通电话的概率是多少？这个问题可以使用基于泊松分布的以下公式来解决：

![示例问题](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_05_015.jpg)

## 连续概率分布

连续概率分布用于建模连续性数据，这意味着数据只能在指定范围内取任何值。因此，我们处理与区间相关的概率，而不是与任何特定值相关的概率，因为它为零。连续概率分布是实验的理论模型；它是由无限数量的观察构建的相对频率分布。这意味着当你缩小区间时，观察数量增加，随着观察数量的不断增加并接近无穷大，它形成了一个连续概率分布。曲线下的总面积为 1，要找到与任何特定范围相关的概率，我们必须找到曲线下的面积。因此，连续分布通常用**概率密度函数**（**PDF**）来描述，其类型如下：

P(a ≤ X ≤ b) = a∫^b f(x) dx

可以有各种类型的连续概率分布。以下部分是一些示例。

### 正态分布

正态分布是一种简单、直接，但非常重要的连续概率分布。它也被称为高斯分布或**钟形曲线**，因为它的外观。此外，对于完美的正态分布，均值、中位数和众数都是相同的。

许多自然现象遵循正态分布（它们也可能遵循不同的分布！），例如人的身高、测量误差等。然而，正态分布不适合模拟高度倾斜或固有为正的变量（例如股价或学生的测试分数，其中难度水平很低）。这些变量可能更适合用不同的分布或数据转换后的正态分布（如对数转换）来描述。

正态分布可以用两个描述符来描述：均值表示中心位置，标准差表示扩散（高度和宽度）。代表正态分布的概率密度函数如下：

![正态分布](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_05_016.jpg)

正态分布之所以成为最受欢迎的分布之一，其中一个原因是**中心极限定理**（**CLT**）。它规定，无论人口分布如何，从同一人口分布独立抽取的样本均值几乎呈正态分布，随着样本量的增加，这种正态性会越来越明显。这种行为实际上是统计假设检验的基础。

此外，每个正态分布，无论其均值和标准差如何，都遵循经验法则（68-95-99.7 法则），该法则规定曲线下约 68％的面积落在均值的一个标准差内，曲线下约 95％的面积落在均值的两个标准差内，曲线下约 99.7％的面积落在均值的三个标准差内。

现在，要找到事件的概率，可以使用积分微积分，也可以将分布转换为标准正态分布，如下一节所述。

### 标准正态分布

标准正态分布是一种均值为 *0*，标准差为 *1* 的正态分布。这种分布很少自然存在。它主要设计用于找到正态分布曲线下的面积（而不是使用微积分进行积分）或者对数据点进行标准化。

假设随机变量 *X* 正态分布，均值（*μ*）和标准差（*σ*），那么随机变量 *Z* 将具有均值 *0* 和标准差 *1* 的标准正态分布。可以找到 *Z* 的值如下：

![标准正态分布](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_05_017.jpg)

由于数据可以以这种方式标准化，因此数据点可以表示为在分布中与均值相差多少个标准差，并且可以进行解释。这有助于比较两个具有不同尺度的分布。

您可以在以下场景中找到正态分布的应用，其中一个想要找到落在指定范围内的百分比 - 假设分布近似正态。

考虑以下例子：

如果店主在某一天经营店铺的时间遵循均值为 *8* 小时和标准差为 *0.5* 小时的正态分布，那么他在店里待的时间少于 7.5 小时的概率是多少？

概率分布如下：

![标准正态分布](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_05_018.jpg)

数据分布

![标准正态分布](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/Capture.jpg)![标准正态分布](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_05_020.jpg)

标准正态分布

因此，店主在店里待的时间少于 7.5 小时的概率为：

*P(z = -1) = 0.1587 = 15.87*

### 注意

这是使用 Z-表找出的。

请注意，数据集中的正态性大多是一种近似。您首先需要检查数据的正态性，然后如果您的分析基于数据的正态性假设，可以进一步进行。有各种不同的检查正态性的方法：您可以选择直方图（使用数据的均值和标准差拟合的曲线）、正态概率图或 QQ 图。

### 卡方分布

卡方分布是统计推断中最广泛使用的分布之一。它是伽玛分布的特例，用于对不是负数的变量的偏斜分布进行建模。它规定，如果随机变量 *X* 正态分布，*Z* 是其标准正态变量之一，则 *Z[2]* 将具有一个自由度的 X[²] 分布。同样，如果我们从相同分布中取出许多这样的随机独立标准正态变量，对它们进行平方并相加，那么结果也将遵循 X[²] 分布，如下所示：

*Z[12] + Z[22] + ... + Z[k2]* 将具有 *k* 自由度的 X[2] 分布。

卡方分布主要用于推断给定样本方差或标准差的总体方差或总体标准差。这是因为 X[2]分布是用另一种方式定义的，即以样本方差与总体方差的比率来定义。

为了证明这一点，让我们从方差为![卡方分布](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/Ch.jpg)的正态分布中随机抽取一个样本（*x[1]*, *x[2]*,...,*xn*）。

样本均值由以下公式给出：

![卡方分布](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_05_021.jpg)

然而，样本方差由以下公式给出：

![卡方分布](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_05_022.jpg)

考虑到前面提到的事实，我们可以定义卡方统计量如下：

![卡方分布](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_05_023.jpg)

（记住![卡方分布](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_05_024.jpg)和*Z[2]*将具有 X[2]分布。）

所以，![卡方分布](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_05_025.jpg)

因此，卡方统计量的抽样分布将遵循自由度为*(n-1)*的卡方分布。

具有自由度为*n*和伽玛函数*Г*的卡方分布的概率密度函数如下：

![卡方分布](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_05_026.jpg)

对于自由度为*k*的*χ2*分布，均值（*µ*）= *k*，方差（*σ2*）= *2k*。

请注意，卡方分布呈正偏态，但偏斜度随着自由度的增加而减小，并趋近于正态分布。

#### 样本问题

找到方差和标准差的 90%置信区间，以美元表示成成年人单张电影票的价格。给定的数据代表全国电影院的选定样本。假设变量服从正态分布。

给定样本（以美元计）：10, 08, 07, 11, 12, 06, 05, 09, 15, 12

解：

*N* = *10*

样本均值：

![样本问题](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/样本均值.jpg)

样本的方差：

![样本问题](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/方差.jpg)

样本的标准差：

S = sqrt(9.61)

自由度：

10-1 = 9

现在我们需要找到 90%的置信区间，这意味着数据的 10%将留在尾部。

![样本问题](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_05_027.jpg)

现在，让我们使用公式：

![样本问题](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_05_028.jpg)![样本问题](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_05_029.jpg)

然后我们可以使用表格或计算机程序找到卡方值。

为了找到中间 90%的置信区间，我们可以考虑左边的 95%和右边的 5%。

因此，代入数字后，我们得到：

![样本问题](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_05_030.jpg)![样本问题](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_05_031.jpg)![样本问题](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_05_032.jpg)

因此，我们可以得出结论，我们有 90%的把握，认为全国电影票价格的标准差在 2.26 美元和 5.10 美元之间，基于对 10 个全国电影票价格的样本。

### 学生 t 分布

学生 t 分布用于估计正态分布总体的均值，当总体标准差未知或样本量太小时。在这种情况下，*μ*和*σ*都是未知的，人口参数只能通过样本估计。

这个分布是钟形的，对称的，就像正态分布，但尾部更重。当样本量大时，t 分布变成正态分布。

让我们从均值为*μ*，方差为*σ2*的正态分布中随机抽取一个样本（*x1*, *x2*,...,*xn*）。

样本均值将是![学生 t 分布](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_05_033.jpg)和样本方差![学生 t 分布](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_05_034.jpg)

考虑到上述事实，t 统计量可以定义为：

![学生 t 分布](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_05_035.jpg)

t 统计量的抽样分布将遵循具有*(n-1)*自由度(**df**)的 t 分布。自由度越高，t 分布将越接近标准正态分布。

t 分布的均值（*μ*）= *0*，方差（*σ2）= df/df-2

现在，为了更清楚地说明问题，让我们回顾一下并考虑一下当总体*σ*已知时的情况。当总体正态分布时，样本均值*x̄*大多数情况下也是正态分布的，无论样本大小和*x̄*的任何线性变换，如![学生 t 分布](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_05_037.jpg)也会遵循正态分布。

如果总体不是正态分布呢？即使在这种情况下，当样本量足够大时，*x̄*（即抽样分布）或![学生 t 分布](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_05_037.jpg)的分布也会遵循中心极限定理的正态分布！

另一种情况是总体*σ*未知。在这种情况下，如果总体正态分布，样本均值*x̄*大多数情况下也是正态分布的，但随机变量![学生 t 分布](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_05_039.jpg)不会遵循正态分布；它遵循具有*(n-1)*自由度的 t 分布。原因是因为分母中*S*的随机性，对于不同的样本是不同的。

在上述情况下，如果总体不是正态分布，当样本量足够大时，![学生 t 分布](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_05_040.jpg)的分布将遵循中心极限定理的正态分布（而不是在样本量较小的情况下！）。因此，样本量足够大时，![学生 t 分布](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_05_040.jpg)的分布遵循正态分布，可以安全地假设它遵循 t 分布，因为 t 分布随着样本量的增加而接近正态分布。

### F 分布

在统计推断中，F 分布用于研究两个正态分布总体的方差。它表明来自两个独立正态分布总体的样本方差的抽样分布具有相同总体方差，遵循 F 分布。

如果样本 1 的样本方差为![F 分布](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_05_041.jpg)，如果样本 2 的样本方差为![F 分布](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_05_042.jpg)，那么，![F 分布](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_05_043.jpg)将具有 F 分布（*σ12 = σ22*）。

从上述事实中，我们也可以说![F 分布](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_05_044.jpg)也将遵循 F 分布。

在前面的卡方分布部分，我们也可以说

![F 分布](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_05_045.jpg)也将具有*n1-1*和*n2-1*自由度的 F 分布。对于这些自由度的每种组合，都会有不同的 F 分布。

## 标准误差

统计量（如均值或方差）的抽样分布的标准差称为**标准误差**（**SE**），是一种变异性度量。换句话说，**均值的标准误差**（**SEM**）可以定义为样本均值对总体均值的估计的标准差。

随着样本量的增加，样本均值的抽样分布变得越来越正态，标准差变得越来越小。已经证明：

![标准误差](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_05_046.jpg)

（*n*为样本量）

![标准误差](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_05_047.jpg)

标准误差越小，样本对整体总体的代表性就越高。此外，样本量越大，标准误差就越小。

标准误差在统计推断的其他测量中非常重要，例如误差边界和置信区间。

## 置信水平

这是一个衡量你希望在通过样本统计估计总体参数时有多大把握（概率），以便期望值落入所需范围或置信区间的度量。它通过从显著水平（*α*）中减去*1*（即*置信水平=1-α*）来计算。因此，如果*α=0.05*，置信水平将是*1-0.05=0.95*。

通常情况下，置信水平越高，所需的样本量就越大。然而，通常会有权衡，你必须决定你希望有多大的把握，以便你可以估计所需的置信水平下的样本量。

## 误差范围和置信区间

正如前面讨论的，由于样本永远不能完全代表总体，通过推断估计总体参数总会因抽样误差而产生一定的误差范围。通常情况下，样本量越大，误差范围越小。然而，你必须决定允许多少误差，并且估计所需的适当样本量将取决于这一点。

因此，基于误差范围的样本统计值下方和上方的值范围被称为**置信区间**。换句话说，置信区间是我们相信真实总体参数在其中落入一定百分比时间内的一系列数字（置信水平）。

请注意，像“我有 95%的把握置信区间包含真实值”这样的陈述可能会误导！正确的陈述方式可能是“*如果我取相同大小的无限数量样本，那么 95%的时间置信区间将包含真实值*”。

例如，当你将置信水平设为 95%，置信区间设为 4%时，对于样本统计值 58（这里，58 可以是任何样本统计值，如均值、方差或标准差），你可以说你有 95%的把握，真实的总体百分比在 58-4=54%和 58+4=62%之间。

## 总体的变异性

总体的变异性是我们在推断统计中应该考虑的最重要因素之一。它在估计样本量中起着重要作用。无论你选择什么样的抽样算法来最好地代表总体，样本量仍然起着至关重要的作用-这是显而易见的！

如果总体变异性更大，那么所需的样本量也会更多。

## 估计样本量

我们已经在前面的部分中涵盖了抽样技术。在本节中，我们将讨论如何估计样本量。假设你需要证明一个概念或评估某些行动的结果，那么你会获取一些相关数据并试图证明你的观点。然而，你如何确保你有足够的数据？太大的样本浪费时间和资源，而太小的样本可能导致误导性的结果。估计样本量主要取决于误差范围或置信区间、置信水平和总体的变异性等因素。

考虑以下例子：

学院院长要求统计老师估计学院学生的平均年龄。需要多大的样本？统计老师希望有 99%的把握，估计应该在 1 年内准确。根据以前的研究，年龄的标准差已知为 3 年。

解决方案：

![估计样本量](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_05_048.jpg)![估计样本量](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_05_049.jpg)

## 假设检验

假设检验是关于检验对总体参数所做的假设。这有助于确定一个结果是否具有统计学意义或是偶然发生的。这是统计研究中最重要的工具。我们将讨论一些测试，以查看总体中变量之间的关系。

### 零假设和备择假设

零假设（表示为 H0）通常是关于总体参数的初始声明，大多数情况下表明*没有影响*或*没有关系*。在我们的假设检验中，我们的目标是否定和拒绝零假设，以便接受备择假设（表示为 H1）。备择假设表明实验中的某种影响。在实验中，请注意，您要么拒绝零假设，要么未能拒绝零假设。如果您成功地拒绝了零假设，那么备择假设将被考虑，如果您未能拒绝零假设，则将被考虑零假设（尽管可能不是真的）。

因此，我们通常希望获得非常小的 P 值（低于定义的显著性水平α），以便拒绝零假设。如果 P 值大于α，则未能拒绝零假设。

### 卡方检验

大多数统计推断技术用于估计总体参数或使用样本统计量（如*均值*）来检验假设。然而，卡方统计量采用完全不同的方法，通过检查整个分布或两个分布之间的关系。在推断统计领域，许多检验统计量类似于卡方分布。使用该分布的最常见检验是适合度卡方检验（单向表）和独立性卡方检验（双向表）。*适合度*检验用于确定样本数据是否遵循总体中的相同分布，*独立性*检验用于确定两个分类变量在总体中是否相关。

输入数据类型决定是否进行*适合度*或*独立性*检验，而无需明确指定它们作为开关。因此，如果您提供向量作为输入，则进行*适合度*检验，如果您提供矩阵作为输入，则进行*独立性*检验。在任何情况下，都需要提供作为输入的事件频率向量或列联表，您需要首先计算它们。让我们通过示例来探讨这些问题：

Python

```scala
 //Chi-Square test
>>> from pyspark.mllib.linalg import Vectors, Matrices
>>> from pyspark.mllib.stat import Statistics
>>> import random
>>> 
//Make a vector of frequencies of events
>>> vec = Vectors.dense( random.sample(xrange(1,101),10))
>>> vec
DenseVector([45.0, 40.0, 93.0, 66.0, 56.0, 82.0, 36.0, 30.0, 85.0, 15.0])
// Get Goodnesss of fit test results
>>> GFT_Result = Statistics.chiSqTest(vec)
// Here the ‘goodness of fit test’ is conducted because your input is a vector
//Make a contingency matrix
>>> mat = Matrices.dense(5,6,random.sample(xrange(1,101),30))\
//Get independense test results\\
>>> IT_Result = Statistics.chiSqTest(mat)
// Here the ‘independence test’ is conducted because your input is a vector
//Examine the independence test results
>>> print(IT_Result)
Chi squared test summary:
method: pearson
degrees of freedom = 20
statistic = 285.9423808343265
pValue = 0.0
Very strong presumption against null hypothesis: the occurrence of the outcomes is statistically independent..
```

**Scala**

```scala
scala> import org.apache.spark.mllib.linalg.{Vectors, Matrices}
import org.apache.spark.mllib.linalg.{Vectors, Matrices} 

scala> import org.apache.spark.mllib.stat.Statistics 

scala> val vec = Vectors.dense( Array.fill(10)(               scala.util.Random.nextDouble))vec: org.apache.spark.mllib.linalg.Vector = [0.4925741159101148,....] 

scala> val GFT_Result = Statistics.chiSqTest(vec)GFT_Result: org.apache.spark.mllib.stat.test.ChiSqTestResult =Chi squared test summary:
method: pearson
degrees of freedom = 9
statistic = 1.9350768763253192
pValue = 0.9924531181394086
No presumption against null hypothesis: observed follows the same distribution as expected..
// Here the ‘goodness of fit test’ is conducted because your input is a vector
scala> val mat = Matrices.dense(5,6, Array.fill(30)(scala.util.Random.nextDouble)) // a contingency matrix
mat: org.apache.spark.mllib.linalg.Matrix =..... 
scala> val IT_Result = Statistics.chiSqTest(mat)
IT_Result: org.apache.spark.mllib.stat.test.ChiSqTestResult =Chi squared test summary:
method: pearson
degrees of freedom = 20
statistic = 2.5401190679900663
pValue = 0.9999990459111089
No presumption against null hypothesis: the occurrence of the outcomes is statistically independent..
// Here the ‘independence test’ is conducted because your input is a vector

```

### F 检验

我们已经在前面的部分中介绍了如何计算 F 统计量。现在我们将解决一个样本问题。

#### 问题：

您想要测试的信念是，硕士学位持有者的收入变异性大于学士学位持有者的收入。抽取了 21 名毕业生的随机样本和 30 名硕士的随机样本。毕业生样本的标准偏差为 180 美元，硕士样本的标准偏差为 112 美元。

解决方案：

零假设是：*H[0] : σ[1]² =σ[2]²*

给定*S[1] = $180*，*n[1] = 21*，*S[2] = $112*，*n[2] = 30*

考虑显著性水平为*α = 0.05*

*F = S[1]² /S[2]² = 180²/112² = 2.58*

根据显著性水平为 0.05 的 F 表，df1=20 和 df2=29，我们可以看到 F 值为 1.94。

由于计算出的 F 值大于 F 表中的临界值，我们可以拒绝零假设，并得出结论*σ[1]² >σ[2]* ^(*2*) 。

### 相关性

相关性提供了一种衡量两个数值型随机变量之间的统计依赖性的方法。这显示了两个变量彼此变化的程度。基本上有两种相关性测量方法：Pearson 和 Spearman。Pearson 更适合间隔尺度数据，如温度、身高等。Spearman 更适合顺序尺度，如满意度调查，其中 1 表示不满意，5 表示最满意。此外，Pearson 是基于真实值计算的，有助于找到线性关系，而 Spearman 是基于秩次的，有助于找到单调关系。单调关系意味着变量确实一起变化，但变化速率不是恒定的。请注意，这两种相关性测量只能测量线性或单调关系，不能描绘其他类型的关系，如非线性关系。

在 Spark 中，这两种都受支持。如果您输入两个`RDD[Double]`，输出是*Double*，如果您输入一个`RDD[Vector]`，输出是*相关矩阵*。在 Scala 和 Python 的实现中，如果您没有提供相关性的类型作为输入，那么默认考虑的始终是 Pearson。

**Python**

```scala
>>> from pyspark.mllib.stat import Statistics
>>> import random 
// Define two series
//Number of partitions and cardinality of both Ser_1 and Ser_2 should be the same
>>> Ser_1 = sc.parallelize(random.sample(xrange(1,101),10))       
// Define Series_1>>> Ser_2 = sc.parallelize(random.sample(xrange(1,101),10))       
// Define Series_2 
>>> correlation = Statistics.corr(Ser_1, Ser_2, method = "pearson") 
//if you are interested in Spearman method, use “spearman” switch instead
>>> round(correlation,2)-0.14
>>> correlation = Statistics.corr(Ser_1, Ser_2, method ="spearman")
>>> round(correlation,2)-0.19//Check on matrix//The following statement creates 100 rows of 5 elements each
>>> data = sc.parallelize([random.sample(xrange(1,51),5) for x in range(100)])
>>> correlMatrix = Statistics.corr(data, method = "pearson") 
//method may be spearman as per you requirement
>>> correlMatrix
array([[ 1.        ,  0.09889342, -0.14634881,  0.00178334,  0.08389984],       [ 0.09889342,  1.        , -0.07068631, -0.02212963, -0.1058252 ],       [-0.14634881, -0.07068631,  1.        , -0.22425991,  0.11063062],       [ 0.00178334, -0.02212963, -0.22425991,  1.        , -0.04864668],       [ 0.08389984, -0.1058252 ,  0.11063062, -0.04864668,  1.        
]])
>>> 

```

**Scala**

```scala
scala> val correlation = Statistics.corr(Ser_1, Ser_2, "pearson")correlation: Double = 0.43217145308272087 
//if you are interested in Spearman method, use “spearman” switch instead
scala> val correlation = Statistics.corr(Ser_1, Ser_2, "spearman")correlation: Double = 0.4181818181818179 
scala>
//Check on matrix
//The following statement creates 100 rows of 5 element Vectors
scala> val data = sc.parallelize(Seq.fill(100)(Vectors.dense(Array.fill(5)(              scala.util.Random.nextDouble))))
data: org.apache.spark.rdd.RDD[org.apache.spark.mllib.linalg.Vector] = ParallelCollectionRDD[37] at parallelize at <console>:27 
scala> val correlMatrix = Statistics.corr(data, method="pearson") 
//method may be spearman as per you requirement
correlMatrix: org.apache.spark.mllib.linalg.Matrix =1.0                    -0.05478051936343809  ... (5 total)-0.05478051936343809   1.0                   ..........
```

# 摘要

在本章中，我们简要介绍了数据科学生命周期中涉及的步骤，如数据获取、数据准备和通过描述性统计进行数据探索。我们还学会了使用一些流行的工具和技术通过样本统计来估计总体参数。

我们从理论和实践两方面解释了统计学的基础知识，通过深入研究一些领域的基础知识，以解决业务问题。最后，我们学习了一些关于如何在 Apache Spark 上执行统计分析的示例，利用了基本上是本章的目标的开箱即用的功能。

在下一章中，我们将讨论数据科学中机器学习部分的更多细节，因为我们已经在本章中建立了统计理解。从本章的学习应该有助于以更明智的方式连接到机器学习算法。

# 参考资料

Spark 支持的统计信息：

[`spark.apache.org/docs/latest/mllib-statistics.html`](http://spark.apache.org/docs/latest/mllib-statistics.html)

Databricks 的特性绘图：

[`docs.cloud.databricks.com/docs/latest/databricks_guide/04%20Visualizations/4%20Matplotlib%20and%20GGPlot.html`](https://docs.cloud.databricks.com/docs/latest/databricks_guide/04%20Visualizations/4%20Matplotlib%20and%20GGPlot.html)

MLLIB 统计的 OOTB 库函数的详细信息：

[`spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.stat.Statistics$`](http://spark.apache.org/docs/latest/api/scala/index.html#org.apache.spark.mllib.stat.Statistics%24)


# 第六章：机器学习

我们每天都在使用机器学习，无论我们是否注意到。例如，谷歌等电子邮件提供商会自动将一些收件箱中的邮件推送到“垃圾邮件”文件夹中，亚马逊等在线购物网站或 Facebook 等社交网络网站会提供出人意料的有用的推荐。那么，是什么使这些软件产品能够重新连接失散已久的朋友呢？这些只是机器学习在实际中的一些例子。

从形式上讲，机器学习是**人工智能**（**AI**）的一部分，它处理一类可以从数据中学习并进行预测的算法。这些技术和基本概念来自统计学领域。机器学习存在于计算机科学和统计学的交叉点，被认为是数据科学中最重要的组成部分之一。它已经存在了一段时间，但随着数据量和可扩展性要求的增加，其复杂性也在增加。机器学习算法往往需要大量资源，并且具有迭代性质，这使它们不适合 MapReduce 范式。MapReduce 非常适用于单次遍历算法，但对于多次遍历的算法并不那么适用。Spark 研究项目正是为了解决这一挑战而启动的。Apache Spark 在其 MLlib 库中配备了高效的算法，即使在迭代计算需求下也能表现良好。

上一章概述了数据分析的生命周期及其各个组成部分，如数据清洗、数据转换、抽样技术和可视化数据的图形技术，以及涵盖描述性统计和推断统计的概念。我们还研究了一些可以在 Spark 平台上执行的统计测试。在上一章中建立的基础上，我们将在本章中涵盖大部分机器学习算法以及如何使用它们在 Spark 上构建模型。

作为本章的先决条件，对机器学习算法和计算机科学基础的基本理解是很有帮助的。然而，我们已经涵盖了一些算法的理论基础，并配以一套合适的实际例子，使这些更易于理解和实施。本章涵盖的主题有：

+   机器学习介绍

+   演变

+   监督学习

+   无监督学习

+   MLlib 和 Pipeline API

+   MLlib

+   ML 管道

+   机器学习介绍

+   参数方法

+   非参数方法

+   回归方法

+   线性回归

+   回归正则化

+   分类方法

+   逻辑回归

+   线性支持向量机（SVM）

+   决策树

+   不纯度度量

+   停止规则

+   分裂候选

+   决策树的优势

+   例子

+   集成

+   随机森林

+   梯度提升树

+   多层感知器分类器

+   聚类技术

+   K 均值聚类

+   总结

# 介绍

机器学习就是通过示例数据进行学习的过程；这些示例为给定输入产生特定输出。机器学习有各种各样的商业用例。让我们看一些例子，以了解它到底是什么：

+   推荐引擎，推荐用户可能感兴趣的购买商品

+   客户细分（将具有相似特征的客户分组）用于营销活动

+   癌症的疾病分类-恶性/良性

+   预测建模，例如，销售预测，天气预测

+   绘制业务推论，例如，了解产品价格变化对销售的影响

## 演变

统计学习的概念甚至在第一台计算机系统出现之前就已存在。在 19 世纪，最小二乘法（现在称为线性回归）已经被发展出来。对于分类问题，费舍尔提出了**线性判别分析**（**LDA**）。大约在 20 世纪 40 年代，LDA 的替代方案，即**逻辑回归**，被提出，所有这些方法不仅随着时间的推移得到改进，而且还激发了其他新算法的发展。

在那些时代，计算是一个大问题，因为它是用纸和笔完成的。因此，拟合非线性方程并不太可行，因为它需要大量的计算。20 世纪 80 年代后，随着技术的改进和计算机系统的引入，分类/回归树被引入。随着技术和计算系统的进一步发展，统计学习在某种程度上与现在所称的机器学习融合在一起。

## 监督学习

如前一节所讨论的，机器学习完全是基于示例数据的学习。根据算法如何理解数据并对其进行训练，它们大致分为两类：**监督学习**和**无监督学习**。

监督统计学习涉及基于一个或多个输入构建模型以获得特定输出。这意味着我们获得的输出可以根据我们提供的输入监督我们的分析。换句话说，对于预测变量的每个观察（例如年龄、教育和费用变量），都有一个相关的结果变量的响应测量（例如工资）。参考以下表格，以了解我们正在尝试根据**年龄**、**教育**和**费用**变量预测**工资**的示例数据集：

![监督学习](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_06_001.jpg)

监督算法可用于预测、估计、分类和其他类似要求，我们将在以下部分进行介绍。

## 无监督学习

无监督统计学习涉及基于一个或多个输入构建模型，但没有产生特定输出的意图。这意味着没有明确的响应/输出变量需要预测；但输出通常是共享某些相似特征的数据点的组。与监督学习不同，您不知道要将数据点分类到哪些组/标签中，而是让算法自行决定。

在这里，没有“训练”数据集的概念，该数据集用于通过构建模型将结果变量与“预测”变量相关联，然后使用“测试”数据集验证模型。无监督算法的输出不能监督您基于您提供的输入进行分析。这样的算法可以从数据中学习关系和结构。*聚类*和*关联规则学习*是无监督学习技术的例子。

以下图像描述了聚类如何用于将共享某些相似特征的数据项分组：

![无监督学习](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_06_002.jpg)

# MLlib 和管道 API

让我们首先学习一些 Spark 基础知识，以便能够在其上执行机器学习操作。我们将在本节讨论 MLlib 和管道 API。

## MLlib

MLlib 是建立在 Apache Spark 之上的机器学习库，其中包含大多数可以大规模实施的算法。MLlib 与 GraphX、SQL 和 Streaming 等其他组件的无缝集成为开发人员提供了一个相对容易地组装复杂、可扩展和高效的工作流的机会。MLlib 库包括常见的学习算法和实用程序，包括分类、回归、聚类、协同过滤和降维。

MLlib 与`spark.ml`包配合使用，后者提供了高级 Pipeline API。这两个包之间的基本区别在于 MLlib（`spark.mllib`）在 RDD 之上工作，而 ML（`spark.ml`）包在 DataFrame 之上工作，并支持 ML Pipeline。目前，Spark 支持这两个包，但建议使用`spark.ml`包。

此库中的基本数据类型是向量和矩阵。向量是本地的，可以是密集的或稀疏的。密集向量存储为值数组。稀疏向量存储为两个数组；第一个数组存储非零值索引，第二个数组存储实际值。所有元素值都存储为双精度浮点数，索引存储为从零开始的整数。了解基本结构对于有效使用库非常重要，它应该有助于从头开始编写任何新算法。让我们看一些示例代码，以更好地理解这两种向量表示：

**Scala**

```scala
//Create vectors
scala> import org.apache.spark.ml.linalg.{Vector, Vectors}
import org.apache.spark.ml.linalg.{Vector, Vectors}

//Create dense vector
scala> val dense_v: Vector = Vectors.dense(10.0,0.0,20.0,30.0,0.0)
dense_v: org.apache.spark.ml.linalg.Vector = [10.0,0.0,20.0,30.0,0.0]
scala>

//Create sparse vector: pass size, position index array and value array
scala> val sparse_v1: Vector = Vectors.sparse(5,Array(0,2,3),
       Array(10.0,20.0,30.0))
sparse_v1: org.apache.spark.ml.linalg.Vector = (5,[0,2,3],[10.0,20.0,30.0])
scala>

//Another way to create sparse vector with position, value tuples
scala> val sparse_v2: Vector = Vectors.sparse(5,
        Seq((0,10.0),(2,20.0),(3,30.0)))
sparse_v2: org.apache.spark.ml.linalg.Vector = (5,[0,2,3],[10.0,20.0,30.0])
scala>  
 Compare vectors 
--------------- cala> sparse_v1 == sparse_v2
res0: Boolean = true
scala> sparse_v1 == dense_v
res1: Boolean = true      //All three objects are equal but...
scala> dense_v.toString()
res2: String = [10.0,0.0,20.0,30.0,0.0]
scala> sparse_v2.toString()
res3: String = (5,[0,2,3],[10.0,20.0,30.0]) //..internal representation
differs
scala> sparse_v2.toArray
res4: Array[Double] = Array(10.0, 0.0, 20.0, 30.0, 0.0)

Interchangeable ---------------
scala> dense_v.toSparse
res5: org.apache.spark.mllib.linalg.SparseVector = (5,[0,2,3]
[10.0,20.0,30.0])
scala> sparse_v1.toDense
res6: org.apache.spark.mllib.linalg.DenseVector = [10.0,0.0,20.0,30.0,0.0]
scala>

A common operation ------------------
scala> Vectors.sqdist(sparse_v1,
        Vectors.dense(1.0,2.0,3.0,4.0,5.0))
res7: Double = 1075.0
```

Python:

```scala
//Create vectors
>>> from pyspark.ml.linalg import Vector, Vectors
//Create vectors
>>> dense_v = Vectors.dense(10.0,0.0,20.0,30.0,0.0)
//Pass size, position index array and value array
>>> sparse_v1 = Vectors.sparse(5,[0,2,3],
                    [10.0,20.0,30.0])
>>> 

//Another way to create sparse vector with position, value tuples
>>> sparse_v2 = Vectors.sparse(5,
                  [[0,10.0],[2,20.0],[3,30.0]])
>>> 

Compare vectors 
--------------- >>> sparse_v1 == sparse_v2
True
>>> sparse_v1 == dense_v
True      //All three objects are equal but...
>>> dense_v
DenseVector([10.0, 0.0, 20.0, 30.0, 0.0])
>>> sparse_v1
SparseVector(5, {0: 10.0, 2: 20.0, 3: 30.0}) //..internal representation
differs
>>> sparse_v2
SparseVector(5, {0: 10.0, 2: 20.0, 3: 30.0})

Interchangeable 
---------------- //Note: as of Spark 2.0.0, toDense and toSparse are not available in pyspark
 A common operation 
------------------- >>> Vectors.squared_distance(sparse_v1,
        Vectors.dense(1.0,2.0,3.0,4.0,5.0))
1075.0
```

矩阵可以是本地的或分布式的，密集的或稀疏的。本地矩阵存储在单个机器上作为一维数组。密集本地矩阵按列主序存储（列成员是连续的），而稀疏矩阵值以**压缩稀疏列**（**CSC**）格式按列主序存储。在这种格式中，矩阵以三个数组的形式存储。第一个数组包含非零值的行索引，第二个数组包含每列的起始值索引，第三个数组是所有非零值的数组。索引的类型为从零开始的整数。第一个数组包含从零到行数减一的值。第三个数组的元素类型为双精度浮点数。第二个数组需要一些解释。该数组中的每个条目对应于每列中第一个非零元素的索引。例如，假设在一个 3 乘 3 的矩阵中每列只有一个非零元素。那么第二个数组的元素将包含 0,1,2。第一个数组包含行位置，第三个数组包含三个值。如果某列中的元素都不是非零的，你会注意到第二个数组中重复相同的索引。让我们看一些示例代码：

**Scala:**

```scala
scala> import org.apache.spark.ml.linalg.{Matrix,Matrices}
import org.apache.spark.ml.linalg.{Matrix, Matrices}

Create dense matrix 
------------------- //Values in column major order
Matrices.dense(3,2,Array(9.0,0,0,0,8.0,6))
res38: org.apache.spark.mllib.linalg.Matrix =
9.0  0.0
0.0  8.0
0.0  6.0
 Create sparse matrix 
-------------------- //1.0 0.0 4.0
0.0 3.0 5.0
2.0 0.0 6.0//
val sm: Matrix = Matrices.sparse(3,3,
        Array(0,2,3,6), Array(0,2,1,0,1,2),
        Array(1.0,2.0,3.0,4.0,5.0,6.0))
sm: org.apache.spark.mllib.linalg.Matrix =
3 x 3 CSCMatrix
(0,0) 1.0
(2,0) 2.0
(1,1) 3.0
(0,2) 4.0
(1,2) 5.0
(2,2) 6.0
 Sparse matrix, a column of all zeros 
------------------------------------ //third column all zeros
Matrices.sparse(3,4,Array(0,2,3,3,6),
    Array(0,2,1,0,1,2),values).toArray
res85: Array[Double] = Array(1.0, 0.0, 2.0, 0.0, 3.0, 0.0, 0.0, 0.0, 0.0,
4.0, 5.0, 6.0)

```

**Python:**

```scala
//Create dense matrix
>>> from pyspark.ml.linalg import Matrix, Matrices

//Values in column major order
>>> Matrices.dense(3,2,[9.0,0,0,0,8.0,6])
DenseMatrix(3, 2, [9.0, 0.0, 0.0, 0.0, 8.0, 6.0], False)
>>> 

//Create sparse matrix
//1.0 0.0 4.0
0.0 3.0 5.0
2.0 0.0 6.0//
>>> sm = Matrices.sparse(3,3,
        [0,2,3,6], [0,2,1,0,1,2],
        [1.0,2.0,3.0,4.0,5.0,6.0])
>>> 

//Sparse matrix, a column of all zeros
//third column all zeros
>>> Matrices.sparse(3,4,[0,2,3,3,6],
        [0,2,1,0,1,2],
    values=[1.0,2.0,3.0,4.0,5.0,6.0]).toArray()
array([[ 1.,  0.,  0.,  4.],
       [ 0.,  3.,  0.,  5.],
       [ 2.,  0.,  0.,  6.]])
>>> 
```

分布式矩阵是最复杂的，选择正确的分布式矩阵类型非常重要。分布式矩阵由一个或多个 RDD 支持。行和列的索引类型为`long`，以支持非常大的矩阵。分布式矩阵的基本类型是`RowMatrix`，它简单地由其行的 RDD 支持。

每一行依次是一个本地向量。当列数非常低时，这是合适的。记住，我们需要传递 RDD 来创建分布式矩阵，不像本地矩阵。让我们看一个例子：

**Scala:**

```scala
scala> import org.apache.spark.mllib.linalg.{Vector,Vectors}
import org.apache.spark.mllib.linalg.{Vector, Vectors}
scala> import org.apache.spark.mllib.linalg.distributed.RowMatrix
import org.apache.spark.mllib.linalg.distributed.RowMatrix

scala>val dense_vlist: Array[Vector] = Array(
    Vectors.dense(11.0,12,13,14),
    Vectors.dense(21.0,22,23,24),
    Vectors.dense(31.0,32,33,34))
dense_vlist: Array[org.apache.spark.mllib.linalg.Vector] =
Array([11.0,12.0,13.0,14.0], [21.0,22.0,23.0,24.0], [31.0,32.0,33.0,34.0])
scala>

//Distribute the vector list
scala> val rows  = sc.parallelize(dense_vlist)
rows: org.apache.spark.rdd.RDD[org.apache.spark.mllib.linalg.Vector] =
ParallelCollectionRDD[0] at parallelize at <console>:29
scala> val m: RowMatrix = new RowMatrix(rows)
m: org.apache.spark.mllib.linalg.distributed.RowMatrix =
org.apache.spark.mllib.linalg.distributed.RowMatrix@5c5043fe
scala> print("Matrix size is " + m.numRows()+"X"+m.numCols())
Matrix size is 3X4
scala>
```

**Python:**

```scala
>>> from pyspark.mllib.linalg import Vector,Vectors
>>> from pyspark.mllib.linalg.distributed import RowMatrix

>>> dense_vlist = [Vectors.dense(11.0,12,13,14),
         Vectors.dense(21.0,22,23,24), Vectors.dense(31.0,32,33,34)]
>>> rows  = sc.parallelize(dense_vlist)
>>> m = RowMatrix(rows)
>>> "Matrix size is {0} X {1}".format(m.numRows(), m.numCols())
'Matrix size is 3 X 4'
```

`IndexedRowMatrix`将行索引前缀到行条目中。这在执行连接时非常有用。您需要传递`IndexedRow`对象来创建`IndexedRowMatrix`。`IndexedRow`对象是一个包装器，带有长`Index`和一组行元素的`Vector`。

`CoordinatedMatrix`将数据存储为行、列索引和元素值的元组。`BlockMatrix`表示分布式矩阵，以本地矩阵块的形式存储。提供了从一种类型转换为另一种类型的方法，但这些是昂贵的操作，应谨慎使用。

## ML pipeline

现实生活中的机器学习工作流程是数据提取、数据清洗、预处理、探索、特征提取、模型拟合和评估的迭代循环。Spark 上的 ML Pipeline 是用户设置复杂 ML 工作流的简单 API。它旨在解决一些痛点，如参数调整，或基于数据不同拆分（交叉验证）或不同参数集训练多个模型。编写脚本来自动化整个过程不再是必需的，可以在 Pipeline API 中处理。

Pipeline API 由一系列流水线阶段（实现为*transformers*和*estimators*等抽象）组成，以按所需顺序执行。

在 ML Pipeline 中，您可以调用前一章中讨论的数据清洗/转换函数，并调用 MLlib 中可用的机器学习算法。这可以以迭代的方式进行，直到获得所需的模型性能。

![ML 流水线](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_06_003.jpg)

### Transformer

Transformer 是一个抽象，实现`transform()`方法将一个 DataFrame 转换为另一个。如果该方法是特征转换器，则生成的 DataFrame 可能包含基于您执行的操作的一些额外转换列。但是，如果该方法是学习模型，则生成的 DataFrame 将包含一个带有预测结果的额外列。

### Estimator

Estimator 是一个抽象，可以是任何实现`fit()`方法以在 DataFrame 上进行训练以生成模型的学习算法。从技术上讲，该模型是给定 DataFrame 的 transformer。

示例：逻辑回归是一种学习算法，因此是一个 estimator。调用`fit()`训练逻辑回归模型，这是一个结果模型，因此是一个 transformer，可以生成包含预测列的 DataFrame。

以下示例演示了一个简单的单阶段流水线。

**Scala:**

```scala
//Pipeline example with single stage to illustrate syntax
scala> import org.apache.spark.ml.Pipeline
import org.apache.spark.ml.Pipeline
scala> import org.apache.spark.ml.feature._
import org.apache.spark.ml.feature._

//Create source data frame
scala> val df = spark.createDataFrame(Seq(
         ("Oliver Twist","Charles Dickens"),
        ("Adventures of Tom Sawyer","Mark Twain"))).toDF(
        "Title","Author")

//Split the Title to tokens
scala> val tok = new Tokenizer().setInputCol("Title").
          setOutputCol("words")
tok: org.apache.spark.ml.feature.Tokenizer = tok_2b2757a3aa5f

//Define a pipeline with a single stage
scala> val p = new Pipeline().setStages(Array(tok))
p: org.apache.spark.ml.Pipeline = pipeline_f5e0de400666

//Run an Estimator (fit) using the pipeline
scala> val model = p.fit(df)
model: org.apache.spark.ml.PipelineModel = pipeline_d00989625bb2

//Examine stages
scala> p.getStages   //Returns a list of stage objects
res1: Array[org.apache.spark.ml.PipelineStage] = Array(tok_55af0061af6d)

// Examine the results
scala> val m = model.transform(df).select("Title","words")
m: org.apache.spark.sql.DataFrame = [Title: string, words: array<string>]
scala> m.select("words").collect().foreach(println)
[WrappedArray(oliver, twist)]
[WrappedArray(adventures, of, tom, sawyer)]
```

**Python:**

```scala
//Pipeline example with single stage to illustrate syntax
//Create source data frame
>>> from pyspark.ml.pipeline import Pipeline
>>> from pyspark.ml.feature import Tokenizer
>>>  df = sqlContext.createDataFrame([
    ("Oliver Twist","Charles Dickens"),
    ("Adventures of Tom Sawyer","Mark Twain")]).toDF("Title","Author")
>>> 

//Split the Title to tokens
>>> tok = Tokenizer(inputCol="Title",outputCol="words")

//Define a pipeline with a single stage
>>> p = Pipeline(stages=[tok])

//Run an Estimator (fit) using the pipeline
>>> model = p.fit(df)

//Examine stages
>>> p.getStages()  //Returns a list of stage objects
[Tokenizer_4f35909c4c504637a263]

// Examine the results
>>> m = model.transform(df).select("Title","words")
>>> [x[0] for x in m.select("words").collect()]
[[u'oliver', u'twist'], [u'adventures', u'of', u'tom', u'sawyer']]
>>> 
```

上面的示例展示了流水线的创建和执行，尽管只有一个阶段，在这种情况下是一个分词器。Spark 提供了几种“特征转换器”作为开箱即用的功能。这些特征转换器在数据清洗和数据准备阶段非常方便。

以下示例展示了将原始文本转换为特征向量的真实示例。如果您对 TF-IDF 不熟悉，请阅读来自[`www.tfidf.com`](http://www.tfidf.com)的简短教程。

**Scala:**

```scala
scala> import org.apache.spark.ml.Pipeline
import org.apache.spark.ml.Pipeline
scala> import org.apache.spark.ml.feature._
import org.apache.spark.ml.feature._
scala> 

//Create a dataframe
scala> val df2 = spark.createDataset(Array(
         (1,"Here is some text to illustrate pipeline"),
         (2, "and tfidf, which stands for term frequency inverse document
frequency"
         ))).toDF("LineNo","Text")

//Define feature transformations, which are the pipeline stages
// Tokenizer splits text into tokens
scala> val tok = new Tokenizer().setInputCol("Text").
             setOutputCol("Words")
tok: org.apache.spark.ml.feature.Tokenizer = tok_399dbfe012f8

// HashingTF maps a sequence of words to their term frequencies using hashing
// Larger value of numFeatures reduces hashing collision possibility
scala> val tf = new HashingTF().setInputCol("Words").setOutputCol("tf").setNumFeatures(100)
tf: org.apache.spark.ml.feature.HashingTF = hashingTF_e6ad936536ea
// IDF, Inverse Docuemnt Frequency is a statistical weight that reduces weightage of commonly occuring words
scala> val idf = new IDF().setInputCol("tf").setOutputCol("tf_idf")
idf: org.apache.spark.ml.feature.IDF = idf_8af1fecad60a
// VectorAssembler merges multiple columns into a single vector column
scala> val va = new VectorAssembler().setInputCols(Array("tf_idf")).setOutputCol("features")
va: org.apache.spark.ml.feature.VectorAssembler = vecAssembler_23205c3f92c8
//Define pipeline
scala> val tfidf_pipeline = new Pipeline().setStages(Array(tok,tf,idf,va))
val tfidf_pipeline = new Pipeline().setStages(Array(tok,tf,idf,va))
scala> tfidf_pipeline.getStages
res2: Array[org.apache.spark.ml.PipelineStage] = Array(tok_399dbfe012f8, hashingTF_e6ad936536ea, idf_8af1fecad60a, vecAssembler_23205c3f92c8)
scala>

//Now execute the pipeline
scala> val result = tfidf_pipeline.fit(df2).transform(df2).select("words","features").first()
result: org.apache.spark.sql.Row = [WrappedArray(here, is, some, text, to, illustrate, pipeline),(100,[0,3,35,37,69,81],[0.4054651081081644,0.4054651081081644,0.4054651081081644,0.4054651081081644,0.4054651081081644,0.4054651081081644])]
```

**Python:**

```scala
//A realistic, multi-step pipeline that converts text to TF_ID
>>> from pyspark.ml.pipeline import Pipeline
>>> from pyspark.ml.feature import Tokenizer, HashingTF, IDF, VectorAssembler, \
               StringIndexer, VectorIndexer

//Create a dataframe
>>> df2 = sqlContext.createDataFrame([
    [1,"Here is some text to illustrate pipeline"],
    [2,"and tfidf, which stands for term frequency inverse document
frequency"
    ]]).toDF("LineNo","Text")

//Define feature transformations, which are the pipeline stages
//Tokenizer splits text into tokens
>>> tok = Tokenizer(inputCol="Text",outputCol="words")

// HashingTF maps a sequence of words to their term frequencies using
hashing

// Larger the numFeatures, lower the hashing collision possibility
>>> tf = HashingTF(inputCol="words", outputCol="tf",numFeatures=1000)

// IDF, Inverse Docuemnt Frequency is a statistical weight that reduces
weightage of commonly occuring words
>>> idf = IDF(inputCol = "tf",outputCol="tf_idf")

// VectorAssembler merges multiple columns into a single vector column
>>> va = VectorAssembler(inputCols=["tf_idf"],outputCol="features")

//Define pipeline
>>> tfidf_pipeline = Pipeline(stages=[tok,tf,idf,va])
>>> tfidf_pipeline.getStages()
[Tokenizer_4f5fbfb6c2a9cf5725d6, HashingTF_4088a47d38e72b70464f, IDF_41ddb3891541821c6613, VectorAssembler_49ae83b800679ac2fa0e]
>>>

//Now execute the pipeline
>>> result = tfidf_pipeline.fit(df2).transform(df2).select("words","features").collect()
>>> [(x[0],x[1]) for x in result]
[([u'here', u'is', u'some', u'text', u'to', u'illustrate', u'pipeline'], SparseVector(1000, {135: 0.4055, 169: 0.4055, 281: 0.4055, 388: 0.4055, 400: 0.4055, 603: 0.4055, 937: 0.4055})), ([u'and', u'tfidf,', u'which', u'stands', u'for', u'term', u'frequency', u'inverse', u'document', u'frequency'], SparseVector(1000, {36: 0.4055, 188: 0.4055, 333: 0.4055, 378: 0.4055, 538: 0.4055, 597: 0.4055, 727: 0.4055, 820: 0.4055, 960: 0.8109}))]
>>> 
```

此示例已创建并执行了一个多阶段流水线，将文本转换为可以由机器学习算法处理的特征向量。在我们继续之前，让我们看看更多功能。

**Scala:**

```scala
scala> import org.apache.spark.ml.feature._
import org.apache.spark.ml.feature._
scala>

//Basic examples illustrating features usage
//Look at model examples for more feature examples
//Binarizer converts continuous value variable to two discrete values based on given threshold
scala> import scala.util.Random
import scala.util.Random
scala> val nums = Seq.fill(10)(Random.nextDouble*100)
...
scala> val numdf = spark.createDataFrame(nums.map(Tuple1.apply)).toDF("raw_nums")
numdf: org.apache.spark.sql.DataFrame = [raw_nums: double]
scala> val binarizer = new Binarizer().setInputCol("raw_nums").
            setOutputCol("binary_vals").setThreshold(50.0)
binarizer: org.apache.spark.ml.feature.Binarizer = binarizer_538e392f56db
scala> binarizer.transform(numdf).select("raw_nums","binary_vals").show(2)
+------------------+-----------+
|          raw_nums|binary_vals|
+------------------+-----------+
|55.209245003482884|        1.0|
| 33.46202184060426|        0.0|
+------------------+-----------+
scala>

//Bucketizer to convert continuous value variables to desired set of discrete values
scala> val split_vals:Array[Double] = Array(0,20,50,80,100) //define intervals
split_vals: Array[Double] = Array(0.0, 20.0, 50.0, 80.0, 100.0)
scala> val b = new Bucketizer().
           setInputCol("raw_nums").
           setOutputCol("binned_nums").
           setSplits(split_vals)
b: org.apache.spark.ml.feature.Bucketizer = bucketizer_a4dd599e5977
scala> b.transform(numdf).select("raw_nums","binned_nums").show(2)
+------------------+-----------+
|          raw_nums|binned_nums|
+------------------+-----------+
|55.209245003482884|        2.0|
| 33.46202184060426|        1.0|
+------------------+-----------+
scala>

//Bucketizer is effectively equal to binarizer if only two intervals are
given 
scala> new Bucketizer().setInputCol("raw_nums").
        setOutputCol("binned_nums").setSplits(Array(0,50.0,100.0)).
        transform(numdf).select("raw_nums","binned_nums").show(2)
+------------------+-----------+
|          raw_nums|binned_nums|
+------------------+-----------+
|55.209245003482884|        1.0|
| 33.46202184060426|        0.0|
+------------------+-----------+
scala>
```

**Python:**

```scala
//Some more features
>>> from pyspark.ml import feature, pipeline
>>> 

//Basic examples illustrating features usage
//Look at model examples for more examples
//Binarizer converts continuous value variable to two discrete values based on given threshold
>>> import random
>>> nums = [random.random()*100 for x in range(1,11)]
>>> numdf = sqlContext.createDataFrame(
             [[x] for x in nums]).toDF("raw_nums")
>>> binarizer = feature.Binarizer(threshold= 50,
       inputCol="raw_nums", outputCol="binary_vals")
>>> binarizer.transform(numdf).select("raw_nums","binary_vals").show(2)
+------------------+-----------+
|          raw_nums|binary_vals|
+------------------+-----------+
| 95.41304359504672|        1.0|
|41.906045589243405|        0.0|
+------------------+-----------+
>>> 

//Bucketizer to convert continuous value variables to desired set of discrete values
>>> split_vals = [0,20,50,80,100] //define intervals
>>> b =
feature.Bucketizer(inputCol="raw_nums",outputCol="binned_nums",splits=split
vals)
>>> b.transform(numdf).select("raw_nums","binned_nums").show(2)
+------------------+-----------+
|          raw_nums|binned_nums|
+------------------+-----------+
| 95.41304359504672|        3.0|
|41.906045589243405|        1.0|
+------------------+-----------+

//Bucketizer is effectively equal to binarizer if only two intervals are
given 
>>> feature.Bucketizer(inputCol="raw_nums",outputCol="binned_nums",                  
                       splits=[0,50.0,100.0]).transform(numdf).select(
                       "raw_nums","binned_nums").show(2)
+------------------+-----------+
|          raw_nums|binned_nums|
+------------------+-----------+
| 95.41304359504672|        1.0|
|41.906045589243405|        0.0|
+------------------+-----------+
>>> 
```

# 机器学习简介

在本书的前几节中，我们学习了响应/结果变量如何与预测变量相关联，通常在监督学习环境中。这些类型的变量人们现在使用各种不同的名称。让我们看看它们的一些同义词，并在书中交替使用它们：

+   **输入变量（X）**：特征，预测变量，解释变量，自变量

+   **输出变量（Y）**：响应变量，因变量

如果*Y*与*X*之间存在关系，其中*X=X[1], X[2], X[3],..., X[n]*（n 个不同的预测变量），则可以写成如下形式：

![机器学习简介](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_06_004.jpg)

这里![机器学习简介](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_06_005.jpg)是一个表示*X*描述*Y*且未知的函数！这是我们使用手头观察到的数据点来找出的。术语

![机器学习简介](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_06_006.jpg)

是一个均值为零且与*X*无关的随机误差项。

与这样一个方程相关的基本上有两种类型的错误 - 可减少的错误和不可减少的错误。顾名思义，可减少的错误与函数相关，可以通过提高准确性来最小化

![机器学习简介](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_06_007.jpg)

通过使用更好的学习算法或调整相同的算法。由于*Y*也是一个函数

![机器学习简介](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_06_008.jpg)

，这是独立于*X*的，仍然会有一些与之相关的错误，无法解决。这被称为不可减少的错误（

![机器学习简介](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_06_009.jpg)

）。总是有一些因素影响结果变量，但在建模时未考虑（因为大多数情况下它们是未知的），并且导致不可减少的错误项。因此，我们在本书中讨论的方法只关注最小化可减少的错误。

我们构建的大多数机器学习模型可以用于预测或推断，或者两者结合。对于一些算法，函数

![机器学习简介](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_06_010.jpg)

可以表示为一个方程，告诉我们因变量*Y*如何与自变量（*X1*，*X2*，...，*Xn*）相关。在这种情况下，我们既可以进行推断，也可以进行预测。然而，一些算法是黑匣子，我们只能进行预测，无法进行推断，因为*Y*与*X*的关系是未知的。

请注意，线性机器学习模型可能更适合推断设置，因为它们对业务用户更具可解释性。然而，在预测设置中，可能有更好的算法提供更准确的预测，但它们的可解释性较差。当推断是目标时，我们应该更喜欢使用诸如线性回归之类的限制性模型，以获得更好的可解释性，而当只有预测是目标时，我们可以选择使用高度灵活的模型，例如**支持向量机**（**SVM**），这些模型不太可解释，但更准确（然而，这在所有情况下可能并不成立）。在选择算法时，您需要根据业务需求来权衡可解释性和准确性之间的权衡。让我们深入了解这些概念背后的基本原理。

基本上，我们需要一组数据点（训练数据）来构建一个模型来估计

![机器学习简介](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_06_011.jpg)

*(X)*，以便*Y =*

![机器学习简介](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_06_012.jpg)

*(X)*。广义上说，这样的学习方法可以是参数化的，也可以是非参数化的。

## 参数方法

参数方法遵循两步过程。在第一步中，您假设

![参数方法](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_06_013.jpg)

*()*。例如，*X*与*Y*呈线性关系，因此*X*的函数，即

![参数方法](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_06_014.jpg)

*(X)*，可以用下面显示的线性方程表示：

![参数方法](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/Beta1.jpg)

模型选择后，第二步是通过使用手头的数据点来训练模型来估计参数*Î²0*，*Î²1*，...，*Î²n*，以便：

![参数方法](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/Beta-2.jpg)

这种参数化方法的一个缺点是我们对于![参数方法](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_06_016.jpg) *()* 在现实生活中的情况下可能不成立。

## 非参数方法

我们不对*Y*和*X*之间的线性关系以及变量的数据分布做任何假设，因此

![非参数方法](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_06_017.jpg)

*()* 在非参数化中。因为它不假设任何形式的

![非参数方法](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_06_018.jpg)

*()*，通过与数据点很好地拟合，可以产生更好的结果，这可能是一个优势。

因此，与参数方法相比，非参数方法需要更多的数据点来估计

![非参数方法](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_06_019.jpg)

*()*准确。但是请注意，如果处理不当，它可能会导致过度拟合问题。随着我们的进展，我们将更多地讨论这个问题。

# 回归方法

回归方法是一种监督学习的类型。如果响应变量是定量/连续的（取数值，如年龄、工资、身高等），则无论解释变量的类型如何，问题都可以称为回归问题。有各种建模技术来解决回归问题。在本节中，我们将重点放在线性回归技术和一些不同的变体上。

回归方法可用于预测任何实值结果。以下是一些例子：

+   根据教育水平、地点、工作类型等预测员工的工资

+   预测股票价格

+   预测客户的购买潜力

+   预测机器故障前需要的时间

## 线性回归

在前一节*参数方法*中讨论的内容之后，假设线性是

![线性回归](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_06_020.jpg)

*(X)*，我们需要训练数据来拟合一个描述解释变量（表示为*X*）和响应变量（表示为*Y*）之间关系的模型。当只有一个解释变量时，称为简单线性回归，当有多个解释变量时，称为多元线性回归。简单线性回归就是在二维设置中拟合一条直线，当有两个预测变量时，它将在三维设置中拟合一个平面，以此类推，当有两个以上的变量时，它将在更高维的设置中拟合一个平面。

线性回归方程的通常形式可以表示为：

Y' =

![线性回归](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_06_021.jpg)

(X) +

![线性回归](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_06_022.jpg)

这里*Y'*代表了预测的结果变量。

只有一个预测变量的线性回归方程可以表示为：

![线性回归](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/Beta11.jpg)

具有多个预测变量的线性回归方程可以表示为：

![线性回归](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/Beta22.jpg)

这里![线性回归](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_06_025.jpg)是与*X*无关的不可减小的误差项，均值为零。我们无法控制它，但我们可以努力优化

![线性回归](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_06_026.jpg)

*(X)*。由于没有任何模型可以达到 100%的准确性，总会有一些与之相关的误差，因为不可减小的误差组成部分(

![线性回归](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_06_027.jpg)

)。

拟合线性回归最常见的方法称为**最小二乘法**，也称为**普通最小二乘法**（**OLS**）方法。该方法通过最小化每个数据点到回归线的垂直偏差的平方和来找到最适合观察数据点的回归线。为了更好地理解线性回归的工作原理，让我们现在看一个简单线性回归的形式：

![线性回归](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/Beta33.jpg)

其中，*Î²0*是回归线的 Y 截距，*Î²1*定义了线的斜率。这意味着*Î²1*是*X*每变化一个单位时*Y*的平均变化。让我们举个*X*和*Y*的例子：

| **X** | **Y** |
| --- | --- |
| **1** | 12 |
| 2 20 |
| **3** | 13 |
| **4** | 38 |
| **5** | 27 |

如果我们通过前面表格中显示的数据点拟合一条线性回归线，那么它将如下所示：

![线性回归](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_06_028.jpg)

上图中的红色垂直线表示预测误差，可以定义为实际 Y 值与预测 Y'值之间的差异。如果平方这些差异并将它们相加，就称为残差平方和(SSE)，这是用于找到最佳拟合线的最常用的度量。下表显示了如何计算 SSE：

| **X** | **Y** | **Y'** | **Y-Y'** | **(Y-Y') 2** |
| --- | --- | --- | --- | --- |
| **1** | 12 | 12.4 | 0.4 | 0.16 |
| **2** | 20 | 17.2 | 2.8 | 7.84 |
| **3** | 13 | 22 | -9 | 81 |
| **4** | 38 | 26.8 | 11.2 | 125.44 |
| **5** | 27 | 31.6 | -4.6 | 21.16 |
| | | | 总和 | 235.6 |

在上表中，术语(Y-Y')称为残差。残差平方和(RSS)可以表示为：

*RSS = 残差[1]² + 残差[2]² + 残差[3]² + ......+ 残差[n]²*

请注意，回归对异常值非常敏感，如果在应用回归之前不加以处理，可能会引入巨大的 RSS 误差。

在观察到的数据点中拟合回归线后，应该通过将它们在 Y 轴上绘制出来，并将解释变量放在 X 轴上来检查残差。如果图表几乎是一条直线，那么你对线性关系的假设是有效的，否则可能表明存在某种非线性关系。在存在非线性关系的情况下，可能需要考虑非线性。其中一种技术是将高阶多项式添加到方程中。

我们看到 RSS 是拟合回归线时的一个重要特征（在构建模型时）。现在，为了评估回归拟合的好坏（一旦模型建立好），你需要另外两个统计量 - 残差标准误差(RSE)和 R²统计量。

我们讨论了不可减小的误差组件Îµ，因此即使你的方程完全拟合数据点并且正确估计了系数，你的回归仍然会有一定水平的误差。RSE 是Îµ的标准差的估计，可以定义如下：

![线性回归](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_06_029.jpg)

这意味着实际值与真实回归线的偏差平均为 RSE 的因素。

由于 RSE 实际上是以 Y 的单位来衡量的（参考我们在上一节中如何计算 RSS），很难说它是模型准确性的唯一最佳统计量。

因此，引入了一种另类方法，称为 R²统计量（也称为决定系数）。计算 R²的公式如下：

![线性回归](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_06_030.jpg)

总平方和(TSS)可以计算如下：

![线性回归](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_06_031.jpg)

在这里要注意，TSS 测量了在执行回归预测 Y 之前 Y 中固有的总方差。注意它里面没有 Y'。相反，RSS 代表了回归后未能解释的 Y 中的变异性。这意味着(TSS - RSS)能够解释回归后响应的变异性。

R²统计量通常在 0 到 1 之间，但如果拟合比拟合水平线更差，可能会是负数，但这种情况很少见。接近 1 的值表示回归方程可以解释响应变量中大部分的变异性，是一个很好的拟合。相反，接近 0 的值表示回归没有解释响应变量中的大部分方差，不是一个很好的拟合。例如，R²为 0.25 意味着 25%的 Y 的方差由 X 解释，并且表明需要调整模型以改进。

现在让我们讨论如何通过回归来处理数据集中的非线性。正如前面讨论的，当发现非线性关系时，需要妥善处理。为了使用相同的线性回归技术建模非线性方程，您必须创建更高阶的特征，这些特征将被回归技术视为另一个变量。例如，如果*薪水*是一个特征/变量，用于预测*购买潜力*，并且我们发现它们之间存在非线性关系，那么我们可能会创建一个名为（*salary3*）的特征，具体取决于需要解决多少非线性。请注意，当您创建这些更高阶特征时，您还必须保留基本特征。在这个例子中，您必须在回归方程中同时使用（*salary*）和（*salary3*）。

到目前为止，我们有点假设所有的预测变量都是连续的。如果有分类预测变量怎么办？在这种情况下，我们必须对这些变量进行虚拟编码（比如男性为 1，女性为 0），以便回归技术生成两个方程，一个用于性别=男性（方程将包含性别变量），另一个用于性别=女性（方程将不包含性别变量，因为它将被编码为 0）。有时，对于非常少的分类变量，根据分类变量的级别划分数据集并为其构建单独的模型可能是一个好主意。

最小二乘线性回归的一个主要优势是它解释了结果变量与预测变量的关系。这使得它非常可解释，并且可以用于推断以及预测。

### 损失函数

许多机器学习问题可以被制定为凸优化问题。这个问题的目标是找到使平方损失最小的系数值。这个目标函数基本上有两个组成部分 - 正则化器和损失函数。正则化器用于控制模型的复杂性（以防止过拟合），损失函数用于估计回归函数的系数，使得平方损失（RSS）最小。

最小二乘法使用的损失函数称为**平方损失**，如下所示：

![损失函数](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_06_032.jpg)

这里*Y*是响应变量（实值），*W*是权重向量（系数的值），*X*是特征向量。所以

![损失函数](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/Capture-1.jpg)

给出了预测值，我们将其与实际值*Y*相等，以找到需要最小化的平方损失。

用于估计系数的算法称为**梯度下降**。不同类型的损失函数和优化算法适用于不同类型的机器学习算法，我们将根据需要进行介绍。

### 优化

最终，线性方法必须优化损失函数。在幕后，线性方法使用凸优化方法来优化目标函数。MLlib 支持**随机梯度下降**（**SGD**）和**有限内存 - Broyden-Fletcher-Goldfarb-Shanno**（**L-BFGS**）。目前，大多数算法 API 支持 SGD，少数支持 L-BFGS。

SGD 是一种适用于大规模数据和分布式计算环境的一阶优化技术。目标函数（损失函数）被写成求和形式的优化问题最适合使用 SGD 来解决。

L-BFGS 是一种在拟牛顿方法家族中的优化算法，用于解决优化问题。与 SGD 等一阶优化技术相比，L-BFGS 通常能够实现更快的收敛。

MLlib 中提供的一些线性方法都支持 SGD 和 L-BFGS。您应该根据所考虑的目标函数选择其中一种。一般来说，L-BFGS 比 SGD 更快地收敛，但您需要根据需求进行仔细评估。

## 回归的正则化

具有较大权重（系数值）时，容易过拟合模型。正则化是一种主要用于通过控制模型复杂性来消除过拟合问题的技术。通常在看到模型在训练数据和测试数据上的性能差异时进行。如果训练性能高于测试数据，可能是过拟合（高方差）的情况。

为了解决这个问题，引入了一种会对损失函数进行惩罚的正则化技术。在训练数据观测数量较少时，通常建议使用任何一种正则化技术。

在进一步讨论正则化技术之前，我们必须了解在监督学习环境中，“偏差”和“方差”是什么意思，以及为什么总是存在相关的权衡。虽然两者都与错误有关，“偏差”模型意味着它偏向于某些错误的假设，并且可能在一定程度上忽略预测变量和响应变量之间的关系。这是欠拟合的情况！另一方面，“高方差”模型意味着它试图触及每个数据点，并最终对数据集中存在的随机噪声进行建模。这代表了过拟合的情况。

带有 L2 惩罚（L2 正则化）的线性回归称为**岭回归**，带有 L1 惩罚（L1 正则化）的线性回归称为**套索回归**。当同时使用 L1 和 L2 惩罚时，称为**弹性网络回归**。我们将在下一节依次讨论它们。

与 L1 正则化问题相比，L2 正则化问题通常更容易解决，因为它更加平滑，但 L1 正则化问题可能导致权重的稀疏性，从而导致更小且更可解释的模型。因此，套索有时用于特征选择。

### 岭回归

当我们在最小二乘损失函数中加入 L2 惩罚（也称为**收缩惩罚**）时，就变成了岭回归，如下所示：

![岭回归](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_06_034.jpg)

这里*λ*（大于 0）是一个单独确定的调整参数。在前述方程的第二项被称为收缩惩罚，只有当系数（*Î²0*，*Î²1*...等等）很小时并且接近 0 时，它才会很小。当*λ=0*时，岭回归变为最小二乘法。当 lambda 趋近于无穷大时，回归系数趋近于零（但永远不会为零）。

岭回归为每个*λ*值生成不同的系数值集。因此，需要使用交叉验证来谨慎选择 lambda 值。随着 lambda 值的增加，回归线的灵活性减少，从而减少方差并增加偏差。

请注意，收缩惩罚适用于除截距项*Î²0*之外的所有解释变量。

当训练数据较少或者预测变量或特征的数量超过观测数量时，岭回归效果非常好。此外，岭回归所需的计算几乎与最小二乘法相同。

由于岭回归不会将任何系数值减少到零，所有变量都将出现在模型中，这可能会使模型在变量数量较多时变得不太可解释。

### 套索回归

套索回归是在岭回归之后引入的。当我们在最小二乘损失函数中加入 L1 惩罚时，就变成了套索回归，如下所示：

![套索回归](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_06_035.jpg)

这里的区别在于，它不是取平方系数，而是取系数的模。与岭回归不同，它可以强制一些系数为零，这可能导致一些变量的消除。因此，Lasso 也可以用于变量选择！

Lasso 为每个 lambda 值生成不同的系数值集。因此需要使用交叉验证来谨慎选择 lambda 值。与岭回归一样，随着 lambda 的增加，方差减小，偏差增加。

Lasso 相对于岭回归产生更好的可解释模型，因为它通常只有总变量数的子集。当存在许多分类变量时，建议选择 Lasso 而不是岭回归。

实际上，岭回归和 Lasso 并不总是一个比另一个更好。Lasso 通常在具有实质性系数的少量预测变量和其余具有非常小系数的情况下表现良好。当存在许多预测变量且几乎所有预测变量具有实质性但相似的系数大小时，岭回归通常表现更好。

岭回归适用于分组选择，也可以解决多重共线性问题。另一方面，Lasso 不能进行分组选择，倾向于只选择一个预测变量。此外，如果一组预测变量彼此高度相关，Lasso 倾向于只选择其中一个，并将其他收缩为零。

### 弹性网络回归

当我们在最小二乘的损失函数中同时添加 L1 和 L2 惩罚时，它就成为了弹性网络回归，如下所示：

![弹性网络回归](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_06_036.jpg)

以下是弹性网络回归的优点：

+   强制稀疏性并帮助去除最不有效的变量

+   鼓励分组效应

+   结合了岭回归和 Lasso 的优点

Naive 版本的弹性网络回归存在双收缩问题，导致增加偏差和较差的预测准确性。为了解决这个问题，一种方法是通过将估计系数乘以(*1+ λ2*)来重新缩放它们：

**Scala**

```scala
import org.apache.spark.mllib.linalg.Vectors
import org.apache.spark.mllib.regression.LabeledPoint
import org.apache.spark.mllib.regression.LinearRegressionModel
import org.apache.spark.mllib.regression.LinearRegressionWithSGD
scala> import org.apache.spark.ml.regression.{LinearRegression,LinearRegressionModel}
import org.apache.spark.ml.regression.{LinearRegression,LinearRegressionModel}
// Load the data
scala> val data = spark.read.format("libsvm").load("data/mllib/sample_linear_regression_data.txt")
data: org.apache.spark.sql.DataFrame = [label: double, features: vector]

// Build the model
scala> val lrModel = new LinearRegression().fit(data)

//Note: You can change ElasticNetParam, MaxIter and RegParam
// Defaults are 0.0, 100 and 0.0
lrModel: org.apache.spark.ml.regression.LinearRegressionModel = linReg_aa788bcebc42

//Check Root Mean Squared Error
scala> println("Root Mean Squared Error = " + lrModel.summary.rootMeanSquaredError)
Root Mean Squared Error = 10.16309157133015
```

**Python**：

```scala
>>> from pyspark.ml.regression import LinearRegression, LinearRegressionModel
>>>

// Load the data
>>> data = spark.read.format("libsvm").load("data/mllib/sample_linear_regression_data.txt")
>>> 

// Build the model
>>> lrModel = LinearRegression().fit(data)

//Note: You can change ElasticNetParam, MaxIter and RegParam
// Defaults are 0.0, 100 and 0.0
//Check Root Mean Squared Error
>>> print "Root Mean Squared Error = ", lrModel.summary.rootMeanSquaredError
Root Mean Squared Error = 10.16309157133015
>>> 
```

# 分类方法

如果响应变量是定性/分类的（取诸如性别、贷款违约、婚姻状况等分类值），那么问题可以被称为分类问题，而不管解释变量的类型。有各种类型的分类方法，但在本节中我们将专注于逻辑回归和支持向量机。

以下是一些分类方法的一些含义的例子：

+   一个顾客购买产品或不购买产品

+   一个人是否患有糖尿病

+   一个申请贷款的个人是否违约

+   一个电子邮件接收者是否阅读电子邮件

## 逻辑回归

逻辑回归衡量了解释变量和分类响应变量之间的关系。我们不使用线性回归来处理分类响应变量，因为响应变量不是在连续尺度上，因此误差项不是正态分布的。

因此，逻辑回归是一种分类算法。逻辑回归不直接对响应变量*Y*建模，而是对*Y*属于特定类别的概率分布*P(Y*|*X)*进行建模。条件分布(*Y*|*X*)是伯努利分布，而不是高斯分布。逻辑回归方程可以表示如下：

![逻辑回归](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_06_037.jpg)

对于二分类，模型的输出应该限制为两个类中的一个（比如 0 或 1）。由于逻辑回归预测的是概率而不是直接的类，我们使用逻辑函数（也称为*sigmoid 函数*）来将输出限制为单个类：

![逻辑回归](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_06_038.jpg)

解决上述方程得到以下结果：

![逻辑回归](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/Capture-2.jpg)

可以进一步简化为：

![逻辑回归](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_06_040.jpg)

左边的数量 *P(X)/1-P(X)* 被称为 *赔率*。赔率的值范围从 0 到无穷大。接近 0 的值表示概率很低，而数字较大的值表示高概率。有时根据情况直接使用赔率而不是概率。

如果我们取赔率的对数，它就变成了对数赔率或 logit，可以表示如下：

![逻辑回归](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_06_041.jpg)

从前面的方程可以看出，logit 与 *X* 线性相关。

在有两个类别 1 和 0 的情况下，如果 *p >= 0.5* 则预测 *Y = 1*，如果 *p < 0.5* 则预测 *Y = 0*。因此，逻辑回归实际上是一个决策边界在 *p = 0.5* 处的线性分类器。在某些业务案例中，*p* 并不是默认设置为 0.5，您可能需要使用一些数学技术来找出正确的值。

一种称为最大似然的方法用于通过计算回归系数来拟合模型，算法可以是梯度下降，就像在线性回归设置中一样。

在逻辑回归中，损失函数应该解决误分类率。因此，逻辑回归使用的损失函数称为 *逻辑损失*，如下所示：

![逻辑回归](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_06_042.jpg)

### 注意

请注意，当您使用高阶多项式更好地拟合模型时，逻辑回归也容易过拟合。为了解决这个问题，您可以像在线性回归中那样使用正则化项。截至目前，Spark 不支持正则化的逻辑回归，因此我们暂时跳过这部分。 

# 线性支持向量机（SVM）

**支持向量机**（**SVM**）是一种监督式机器学习算法，可用于分类和回归。但是，它在解决分类问题方面更受欢迎，由于 Spark 将其作为 SVM 分类器提供，因此我们将仅限于讨论分类设置。在用作分类器时，与逻辑回归不同，它是一种非概率分类器。

SVM 已经从一个称为**最大间隔分类器**的简单分类器发展而来。由于最大间隔分类器要求类别可由线性边界分开，因此它无法应用于许多数据集。因此，它被扩展为一个称为**支持向量分类器**的改进版本，可以处理类别重叠且类别之间没有明显分离的情况。支持向量分类器进一步扩展为我们所说的 SVM，以适应非线性类边界。让我们逐步讨论 SVM 的演变，以便更清楚地了解它的工作原理。

如果数据集中有 *p* 个维度（特征），那么我们在 p 维空间中拟合一个超平面，其方程可以定义如下：

![线性支持向量机（SVM）](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_06_043.jpg)

这个超平面被称为形成决策边界的分离超平面。结果将根据结果进行分类；如果大于 0，则在一侧，如果小于 0，则在另一侧，如下图所示：

![线性支持向量机（SVM）](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_06_044.jpg)

观察前面的图表，可以有多个超平面（它们可以是无限的）。应该有一个合理的方法来选择最佳的超平面。这就是我们选择最大间隔超平面的地方。如果计算所有数据点到分离超平面的垂直距离，那么最小距离将被称为间隔。因此，对于最大间隔分类器，超平面应具有最大间隔。

距离分隔超平面接近但等距离的训练观测被称为支持向量。对支持向量进行微小改变会导致超平面重新定位。这些支持向量实际上定义了边缘。那么，如果考虑的两个类别是不可分的呢？我们可能希望有一个分类器，它不完全分离两个类别，并且具有一个更柔和的边界，允许一定程度的误分类。这一要求导致了支持向量分类器的引入（也称为软边界分类器）。

从数学上讲，正是方程中的松弛变量允许了误分类。此外，在支持向量分类器中有一个调节参数，应该使用交叉验证来选择。这个调节参数是在偏差和方差之间进行权衡的参数，应该小心处理。当它很大时，边缘会更宽，包含许多支持向量，具有低方差和高偏差。如果它很小，那么边缘将有更少的支持向量，分类器将具有低偏差但高方差。

SVM 的损失函数可以表示如下：

![线性支持向量机（SVM）](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_06_045.jpg)

截至目前，Spark 仅支持线性 SVM。默认情况下，线性 SVM 使用 L2 正则化进行训练。Spark 还支持替代的 L1 正则化。

到目前为止一切顺利！但是当类别之间存在非线性边界时，支持向量分类器会如何工作呢，就像下面的图片所示的那样：

![线性支持向量机（SVM）](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_06_046.jpg)

任何线性分类器，比如支持向量分类器，在前述情况下表现都非常糟糕。如果它通过数据点画一条直线，那么类别就无法正确分离。这是非线性类边界的情况。解决这个问题的方法是支持向量机（SVM）。换句话说，当支持向量分类器与非线性核融合时，它就成为了 SVM。

与我们在回归方程中引入高阶多项式项以解决非线性问题的方式类似，在 SVM 的情境下也可以做一些处理。SVM 使用称为核的东西来处理数据集中不同类型的非线性；不同类型的非线性需要不同的核。核方法将数据映射到更高维的空间，这样做可能会使数据得到更好的分离。同时，它也使得区分不同类别变得更容易。让我们讨论一下一些重要的核，以便能够选择合适的核。

## 线性核

这是最基本类型的核之一，它允许我们只选择线或超平面。它相当于支持向量分类器。如果数据集中存在非线性，它就无法解决。

## 多项式核

这允许我们在多项式阶数的范围内解决一定程度的非线性。当训练数据被归一化时，这种方法效果很好。这个核通常有更多的超参数，因此增加了模型的复杂性。

## 径向基函数核

当你不确定使用哪种核时，径向基函数（RBF）可能是一个不错的默认选择。它允许你选择甚至是圆或超球体。尽管这通常比线性或多项式核表现更好，但当特征数量很大时，它的表现就不那么好了。

## Sigmoid 核

Sigmoid 核源自神经网络。因此，具有 Sigmoid 核的 SVM 等效于具有两层感知器的神经网络。

# 训练 SVM

在训练 SVM 时，建模者需要做出一些决策：

+   如何预处理数据（转换和缩放）。分类变量应通过虚拟化转换为数值变量。此外，需要对数值进行缩放（0 到 1 或-1 到+1）。

+   要使用哪种核（如果无法可视化数据和/或对其进行结论，则使用交叉验证进行检查）。

+   SVM 的参数设置：惩罚参数和核参数（使用交叉验证或网格搜索进行查找）

如果需要，可以使用基于熵的特征选择来在模型中仅包括重要特征。

**Scala**：

```scala
scala> import org.apache.spark.mllib.classification.{SVMModel, SVMWithSGD}
import org.apache.spark.mllib.classification.{SVMModel, SVMWithSGD}
scala> import org.apache.spark.mllib.evaluation.BinaryClassificationMetrics
import org.apache.spark.mllib.evaluation.BinaryClassificationMetrics
scala> import org.apache.spark.mllib.util.MLUtils
import org.apache.spark.mllib.util.MLUtils
scala>

// Load training data in LIBSVM format.
scala> val data = MLUtils.loadLibSVMFile(sc, "data/mllib/sample_libsvm_data.txt")
data: org.apache.spark.rdd.RDD[org.apache.spark.mllib.regression.LabeledPoint] = MapPartitionsRDD[6] at map at MLUtils.scala:84
scala>

// Split data into training (60%) and test (40%).
scala> val splits = data.randomSplit(Array(0.6, 0.4), seed = 11L)
splits: Array[org.apache.spark.rdd.RDD[org.apache.spark.mllib.regression.LabeledPoint]] = Array(MapPartitionsRDD[7] at randomSplit at <console>:29, MapPartitionsRDD[8] at randomSplit at <console>:29)
scala> val training = splits(0).cache()
training: org.apache.spark.rdd.RDD[org.apache.spark.mllib.regression.LabeledPoint] = MapPartitionsRDD[7] at randomSplit at <console>:29
scala> val test = splits(1)
test: org.apache.spark.rdd.RDD[org.apache.spark.mllib.regression.LabeledPoint] = MapPartitionsRDD[8] at randomSplit at <console>:29
scala>

// Run training algorithm to build the model
scala> val model = SVMWithSGD.train(training, numIterations=100)
model: org.apache.spark.mllib.classification.SVMModel = org.apache.spark.mllib.classification.SVMModel: intercept = 0.0, numFeatures = 692, numClasses = 2, threshold = 0.0
scala>

// Clear the default threshold.
scala> model.clearThreshold()
res1: model.type = org.apache.spark.mllib.classification.SVMModel: intercept =
0.0, numFeatures = 692, numClasses = 2, threshold = None
scala>

// Compute raw scores on the test set.
scala> val scoreAndLabels = test.map { point =>
       val score = model.predict(point.features)
      (score, point.label)
      }
scoreAndLabels: org.apache.spark.rdd.RDD[(Double, Double)] =
MapPartitionsRDD[213] at map at <console>:37
scala>

// Get evaluation metrics.
scala> val metrics = new BinaryClassificationMetrics(scoreAndLabels)
metrics: org.apache.spark.mllib.evaluation.BinaryClassificationMetrics = org.apache.spark.mllib.evaluation.BinaryClassificationMetrics@3106aebb
scala> println("Area under ROC = " + metrics.areaUnderROC())
Area under ROC = 1.0
scala>
```

### 注意

`mllib`已经进入维护模式，SVM 在 ml 下仍不可用，因此仅提供 Scala 代码以供说明。

# 决策树

决策树是一种非参数的监督学习算法，可用于分类和回归。决策树就像倒置的树，根节点在顶部，叶节点向下形成。有不同的算法将数据集分割成类似分支的段。每个叶节点分配给代表最合适目标值的类。

决策树不需要对数据集进行任何缩放或转换，并且可以处理分类和连续特征，还可以处理数据集中的非线性。在其核心，决策树是一种贪婪算法（它考虑当前的最佳分割，并不考虑未来的情况），它对特征空间进行递归二元分区。分割是基于每个节点的信息增益进行的，因为信息增益衡量了给定属性如何根据目标类别或值分隔训练示例。第一个分割发生在生成最大信息增益的特征上，并成为根节点。

节点的信息增益是父节点不纯度与两个子节点不纯度加权和之间的差异。为了估计信息增益，Spark 目前针对分类问题有两种不纯度度量，针对回归问题有一种不纯度度量，如下所述。

## 不纯度度量

不纯度是同质性的度量，也是递归分区的最佳标准。通过计算不纯度，决定最佳的分割候选。大多数不纯度度量都是基于概率的：

*类的概率=该类的观察次数/总观察次数*

让我们花一些时间来了解 Spark 支持的不同类型的重要不纯度度量。

### 基尼指数

基尼指数主要用于数据集中的连续属性或特征。如果不是，它将假定所有属性和特征都是连续的。分割使得子节点比父节点更*纯净*。基尼倾向于找到最大的类 - 响应变量的类别，其观察次数最多。可以定义如下：

![基尼指数](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_06_047.jpg)

如果响应的所有观察属于单个类，则该类的概率*P*，即(*Pj*)，将为 1，因为只有一个类，*(Pj)2*也将为 1。这使得基尼指数为零。

### 熵

熵主要用于数据集中的分类属性或特征。可以定义如下：

![熵](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_06_048.jpg)

如果响应的所有观察属于单个类，则该类的概率(*Pj*)将为 1，*log(P)*将为零。这使得熵为零。

以下图表描述了公平硬币抛掷的概率：

![熵](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/Capture-3.jpg)

仅为了解释前面的图表，如果抛掷一个公平硬币，正面或反面的概率将为 0.5，因此在概率为 0.5 时观察次数最多。

如果数据样本完全同质，则熵将为零，如果样本可以平均分为两部分，则熵将为一。

与 Gini 相比，计算速度稍慢，因为它还必须计算对数。

### 方差

与基尼指数和熵不同，方差用于计算回归问题的信息增益。方差可以定义为：

![方差](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_06_050.jpg)

## 停止规则

当满足以下条件之一时，递归树构造停止在一个节点上：

+   节点深度等于`maxDepth`训练参数

+   没有分裂候选者导致信息增益大于`minInfoGain`

+   没有分裂候选者产生子节点，每个子节点至少有一个`minInstancesPerNode`训练实例

## 分裂候选者

数据集通常包含混合的分类和连续特征。我们应该了解特征如何进一步分裂为分裂候选者，因为有时我们需要一定程度的控制来构建更好的模型。

### 分类特征

对于具有*M*个可能值（类别）的分类特征，可以提出*2(M-1)-1*个分裂候选者。无论是二元分类还是回归，通过按平均标签对分类特征值进行排序，可以将分裂候选者的数量减少到*M-1*。

例如，考虑一个具有三个类别 A、B 和 C 的分类特征的二元分类（0/1）问题，它们对应的标签-1 响应变量的比例分别为 0.2、0.6 和 0.4。在这种情况下，分类特征可以被排序为 A、C、B。因此，两个分裂候选者（*M-1* = *3-1* = *2*）可以是*A | (C, B)*和*A, (C | B)*，其中“|”表示分裂。

### 连续特征

对于连续特征变量，可能存在没有两个相同值的情况（至少我们可以假设如此）。如果有*n*个观察结果，那么*n*个分裂候选者可能不是一个好主意，特别是在大数据环境中。

在 Spark 中，通过对数据样本进行分位数计算，并相应地对数据进行分箱来实现。您仍然可以通过使用`maxBins`参数来控制允许的最大箱数。`maxBins`的最大默认值为`32`。

## 决策树的优势

+   它们易于理解和解释，因此易于向业务用户解释

+   它们适用于分类和回归

+   在构建决策树时，可以容纳定性和定量数据

决策树中的信息增益偏向于具有更多级别的属性。

## 决策树的缺点

+   它们对于连续结果变量的有效性不是很好

+   当类别很多且数据集很小时，性能较差。

+   轴平行分裂降低了准确性

+   它们因试图拟合几乎所有数据点而遭受高方差

## 例子

实现方面，在分类和回归树之间没有主要区别。让我们在 Spark 上实际实现它。

**Scala:**

```scala
//Assuming ml.Pipeline and ml.features are already imported
scala> import org.apache.spark.ml.classification.{
        DecisionTreeClassifier, DecisionTreeClassificationModel}
import org.apache.spark.ml.classification.{DecisionTreeClassifier,
DecisionTreeClassificationModel}
scala>
/prepare train data
scala> val f:String = "<Your path>/simple_file1.csv"
f: String = <your path>/simple_file1.csv
scala> val trainDF = spark.read.options(Map("header"->"true",
            "inferSchema"->"true")).csv(f)
trainDF: org.apache.spark.sql.DataFrame = [Text: string, Label: int]

scala>

 //define DecisionTree pipeline
//StringIndexer maps labels(String or numeric) to label indices
//Maximum occurrence label becomes 0 and so on
scala> val lblIdx = new StringIndexer().
                setInputCol("Label").
                setOutputCol("indexedLabel")
lblIdx: org.apache.spark.ml.feature.StringIndexer = strIdx_3a7bc9c1ed0d
scala>

// Create labels list to decode predictions
scala> val labels = lblIdx.fit(trainDF).labels
labels: Array[String] = Array(2, 1, 3)
scala>

//Define Text column indexing stage
scala> val fIdx = new StringIndexer().
                setInputCol("Text").
              setOutputCol("indexedText")
fIdx: org.apache.spark.ml.feature.StringIndexer = strIdx_49253a83c717

// VectorAssembler
scala> val va = new VectorAssembler().
              setInputCols(Array("indexedText")).
              setOutputCol("features")
va: org.apache.spark.ml.feature.VectorAssembler = vecAssembler_764720c39a85

//Define Decision Tree classifier. Set label and features vector
scala> val dt = new DecisionTreeClassifier().
            setLabelCol("indexedLabel").
            setFeaturesCol("features")
dt: org.apache.spark.ml.classification.DecisionTreeClassifier = dtc_84d87d778792

//Define label converter to convert prediction index back to string
scala> val lc = new IndexToString().
                setInputCol("prediction").
                setOutputCol("predictedLabel").
                setLabels(labels)
lc: org.apache.spark.ml.feature.IndexToString = idxToStr_e2f4fa023665
scala>

//String the stages together to form a pipeline
scala> val dt_pipeline = new Pipeline().setStages(
          Array(lblIdx,fIdx,va,dt,lc))
dt_pipeline: org.apache.spark.ml.Pipeline = pipeline_d4b0e884dcbf
scala>
//Apply pipeline to the train data
scala> val resultDF = dt_pipeline.fit(trainDF).transform(trainDF)

//Check results. Watch Label and predictedLabel column values match
resultDF: org.apache.spark.sql.DataFrame = [Text: string, Label: int ... 6 more
fields]
scala>
resultDF.select("Text","Label","features","prediction","predictedLabel").show()
+----+-----+--------+----------+--------------+
|Text|Label|features|prediction|predictedLabel|
+----+-----+--------+----------+--------------+
|   A|    1|   [1.0]|       1.0|             1|
|   B|    2|   [0.0]|       0.0|             2|
|   C|    3|   [2.0]|       2.0|             3|
|   A|    1|   [1.0]|       1.0|             1|
|   B|    2|   [0.0]|       0.0|             2|
+----+-----+--------+----------+--------------+
scala>

//Prepare evaluation data
scala> val eval:String = "<Your path>/simple_file2.csv"
eval: String = <Your path>/simple_file2.csv
scala> val evalDF = spark.read.options(Map("header"->"true",
            "inferSchema"->"true")).csv(eval)
evalDF: org.apache.spark.sql.DataFrame = [Text: string, Label: int]
scala>

//Apply the same pipeline to the evaluation data
scala> val eval_resultDF = dt_pipeline.fit(evalDF).transform(evalDF)
eval_resultDF: org.apache.spark.sql.DataFrame = [Text: string, Label: int ... 7
more fields]

//Check evaluation results
scala>
eval_resultDF.select("Text","Label","features","prediction","predictedLabel").sh
w()
+----+-----+--------+----------+--------------+
|Text|Label|features|prediction|predictedLabel|
+----+-----+--------+----------+--------------+
|   A|    1|   [0.0]|       1.0|             1|
|   A|    1|   [0.0]|       1.0|             1|
|   A|    2|   [0.0]|       1.0|             1|
|   B|    2|   [1.0]|       0.0|             2|
|   C|    3|   [2.0]|       2.0|             3|
+----+-----+--------+----------+--------------+
//Note that predicted label for the third row is 1 as against Label(2) as
expected

Python:

//Model training example
>>> from pyspark.ml.pipeline import Pipeline
>>> from pyspark.ml.feature import StringIndexer, VectorIndexer, VectorAssembler,
IndexToString
>>> from pyspark.ml.classification import DecisionTreeClassifier,
DecisionTreeClassificationModel
>>> 

//prepare train data
>>> file_location = "../work/simple_file1.csv"
>>> trainDF = spark.read.csv(file_location,header=True,inferSchema=True)

 //Read file
>>>

//define DecisionTree pipeline
//StringIndexer maps labels(String or numeric) to label indices
//Maximum occurrence label becomes 0 and so on
>>> lblIdx = StringIndexer(inputCol = "Label",outputCol = "indexedLabel")

// Create labels list to decode predictions
>>> labels = lblIdx.fit(trainDF).labels
>>> labels
[u'2', u'1', u'3']
>>> 

//Define Text column indexing stage
>>> fidx = StringIndexer(inputCol="Text",outputCol="indexedText")

// Vector assembler
>>> va = VectorAssembler(inputCols=["indexedText"],outputCol="features")

//Define Decision Tree classifier. Set label and features vector
>>> dt = DecisionTreeClassifier(labelCol="indexedLabel",featuresCol="features")

//Define label converter to convert prediction index back to string
>>> lc = IndexToString(inputCol="prediction",outputCol="predictedLabel",
                       labels=labels)

//String the stages together to form a pipeline
>>> dt_pipeline = Pipeline(stages=[lblIdx,fidx,va,dt,lc])
>>>
>>> 

//Apply decision tree pipeline
>>> dtModel = dt_pipeline.fit(trainDF)
>>> dtDF = dtModel.transform(trainDF)
>>> dtDF.columns
['Text', 'Label', 'indexedLabel', 'indexedText', 'features', 'rawPrediction',
'probability', 'prediction', 'predictedLabel']
>>> dtDF.select("Text","Label","indexedLabel","prediction",
"predictedLabel").show()
+----+-----+------------+----------+--------------+
|Text|Label|indexedLabel|prediction|predictedLabel|
+----+-----+------------+----------+--------------+
|   A|    1|         1.0|       1.0|             1|
|   B|    2|         0.0|       0.0|             2|
|   C|    3|         2.0|       2.0|             3|
|   A|    1|         1.0|       1.0|             1|
|   B|    2|         0.0|       0.0|             2|
+----+-----+------------+----------+--------------+

>>>

>>> //prepare evaluation dataframe
>>> eval_file_path = "../work/simple_file2.csv"
>>> evalDF = spark.read.csv(eval_file_path,header=True, inferSchema=True) 

//Read eval file
>>> eval_resultDF = dt_pipeline.fit(evalDF).transform(evalDF)
>>> eval_resultDF.columns
['Text', 'Label', 'indexedLabel', 'indexedText', 'features', 'rawPrediction', 'probability', 'prediction', 'predictedLabel']
>>> eval_resultDF.select("Text","Label","indexedLabel","prediction",
"predictedLabel").show()
+----+-----+------------+----------+--------------+
|Text|Label|indexedLabel|prediction|predictedLabel|
+----+-----+------------+----------+--------------+
|   A|    1|         1.0|       1.0|             1|
|   A|    1|         1.0|       1.0|             1|
|   A|    2|         0.0|       1.0|             1|
|   B|    2|         0.0|       0.0|             2|
|   C|    3|         2.0|       2.0|             3|
+----+-----+------------+----------+--------------+
>>> 

Accompanying data files:
simple_file1.csv Text,Label
A,1
B,2
C,3
A,1
B,2simple_file2.csv Text,Label
A,1
A,1
A,2
B,2
C,3
```

# 集成

正如其名称所示，集成方法使用多个学习算法来获得更准确的模型，通常这些技术需要更多的计算能力，并使模型更复杂，这使得难以解释。让我们讨论 Spark 上可用的各种类型的集成技术。

## 随机森林

随机森林是决策树的集成技术。在我们讨论随机森林之前，让我们看看它是如何发展的。我们知道决策树通常存在高方差问题，并且倾向于过度拟合模型。为了解决这个问题，引入了一个称为*bagging*（也称为自举聚合）的概念。对于决策树，想法是从数据集中获取多个训练集（自举训练集），并从中创建单独的决策树，然后对回归树进行平均。对于分类树，我们可以从所有树中获取多数投票或最常出现的类。这些树生长深入，并且根本没有被修剪。这确实减少了方差，尽管单个树可能具有高方差。

纯粹的 bagging 方法的一个问题是，对于大多数自举训练集，强预测变量占据了顶部分裂的位置，这几乎使得袋装树看起来相似。这意味着预测也看起来相似，如果你对它们进行平均，那么它并没有像预期的那样减少方差。为了解决这个问题，需要一种技术，它将采用与袋装树类似的方法，但消除树之间的相关性，因此产生了*随机森林*。

在这种方法中，您构建自举训练样本以创建决策树，但唯一的区别是每次发生分裂时，从总共 K 个预测变量中选择 P 个预测变量的随机样本。这就是随机森林向这种方法注入随机性的方式。作为一个经验法则，我们可以将 P 取为 Q 的平方根。

就像在 bagging 的情况下，如果你的目标是回归，你也会平均预测结果，如果目标是分类，你会采取多数投票。Spark 提供了一些调整参数来调整这个模型，如下所示：

+   `numTrees`：您可以指定在随机森林中考虑的树的数量。如果数字很高，那么预测的方差会较小，但所需的时间会更长。

+   `maxDepth`：您可以指定每棵树的最大深度。增加深度会使树在预测准确度方面更加强大。尽管它们倾向于过度拟合单独的树，但总体输出仍然很好，因为我们无论如何都会平均结果，从而减少方差。

+   `subsamplingRate`：这个参数主要用于加速训练。它用于设置自举训练样本的大小。小于 1.0 的值可以加快性能。

+   `featureSubsetStrategy`：这个参数也可以帮助加快执行。它用于设置每个节点用作分裂候选的特征数。它应该谨慎设置，因为太低或太高的值可能会影响模型的准确性。

### 随机森林的优势

+   它们运行速度更快，因为执行是并行进行的

+   它们不太容易过度拟合

+   它们易于调整

+   与树或袋装树相比，预测准确度更高

+   它们即使在预测变量是分类和连续特征的混合时也能很好地工作，并且不需要缩放

## 梯度提升树

与随机森林一样，**梯度提升树**（**GBTs**）也是一种树的集成。它们可以应用于分类和回归问题。与袋装树或随机森林不同，树是顺序构建的。每棵树都是使用先前生长树的结果来生长的。请注意，GBT 不适用于自举样本。

在每次迭代中，GBT 使用当前集成来预测训练实例的标签，并将它们与真实标签进行比较，并估计错误。预测准确度较差的训练实例将被重新标记，以便基于先前错误的错误率在下一次迭代中纠正决策树。

找到错误率并重新标记实例的机制是基于损失函数的。GBT 旨在减少每次迭代的损失函数。Spark 支持以下类型的损失函数：

+   **对数损失**：这用于分类问题。

+   **平方误差（L2 损失）**：这用于回归问题，并且默认设置。它是所有观察值的实际值和预测输出之间的平方差异的总和。对于这种损失函数，异常值应该得到很好的处理才能表现良好。

+   **绝对误差（L1 损失）**：这也用于回归问题。它是所有观察值的实际值和预测输出之间的绝对差异的总和。与平方误差相比，它对异常值更具鲁棒性。

Spark 提供了一些调整参数来调整此模型，如下所示：

+   `loss`：您可以根据前面讨论的数据集和您打算进行分类或回归的意图，传递一个损失函数。

+   `numIterations`：每次迭代只生成一棵树！如果将此设置得很高，那么执行所需的时间也会很长，因为操作将是顺序的，并且还可能导致过拟合。应该谨慎设置以获得更好的性能和准确性。

+   `learningRate`：这实际上不是一个调整参数。如果算法的行为不稳定，那么减小这个值可以帮助稳定模型。

+   `algo`：*分类*或*回归*是根据您的需求设置的。

GBT 可能会过度拟合具有更多树的模型，因此 Spark 提供了`runWithValidation`方法来防止过拟合。

### 提示

截至目前，Spark 上的 GBT 尚不支持多类分类。

让我们看一个示例来说明 GBT 的工作原理。示例数据集包含二十名学生的平均分和出勤情况。数据还包含结果为通过或失败，遵循一组标准。然而，一对学生（id 为 1009 和 1020）被“授予”通过状态，尽管他们实际上并没有资格。现在我们的任务是检查模型是否选择了这两名学生。

通过标准如下：

+   分数应至少为 40，出勤应至少为“足够”

+   如果分数在 40 到 60 之间，则出勤应为“全勤”才能通过

以下示例还强调了在多个模型中重复使用管道阶段。因此，我们首先构建一个 DecisionTree 分类器，然后构建一个 GBT。我们构建了两个共享阶段的不同管道。

**输入**：

```scala
// Marks < 40 = Fail
// Attendence == Poor => Fail
// Marks >40 and attendence Full => Pass
// Marks > 60 and attendence Enough or Full => Pass
// Two exceptions were studentId 1009 and 1020 who were granted Pass
//This example also emphasizes the reuse of pipeline stages
// Initially the code trains a DecisionTreeClassifier
// Then, same stages are reused to train a GBT classifier
```

**Scala：**

```scala
scala> import org.apache.spark.ml.feature._
scala> import org.apache.spark.ml.Pipeline
scala> import org.apache.spark.ml.classification.{DecisionTreeClassifier,
                                   DecisionTreeClassificationModel}
scala> case class StResult(StudentId:String, Avg_Marks:Double,
        Attendance:String, Result:String)
scala> val file_path = "../work/StudentsPassFail.csv"
scala> val source_ds = spark.read.options(Map("header"->"true",
            "inferSchema"->"true")).csv(file_path).as[StResult]
source_ds: org.apache.spark.sql.Dataset[StResult] = [StudentId: int, Avg_Marks:
double ... 2 more fields]
scala>
//Examine source data
scala> source_ds.show(4)
+---------+---------+----------+------+
|StudentId|Avg_Marks|Attendance|Result|
+---------+---------+----------+------+
|     1001|     48.0|      Full|  Pass|
|     1002|     21.0|    Enough|  Fail|
|     1003|     24.0|    Enough|  Fail|
|     1004|      4.0|      Poor|  Fail|
+---------+---------+----------+------+

scala>           
//Define preparation pipeline
scala> val marks_bkt = new Bucketizer().setInputCol("Avg_Marks").
        setOutputCol("Mark_bins").setSplits(Array(0,40.0,60.0,100.0))
marks_bkt: org.apache.spark.ml.feature.Bucketizer = bucketizer_5299d2fbd1b2
scala> val att_idx = new StringIndexer().setInputCol("Attendance").
        setOutputCol("Att_idx")
att_idx: org.apache.spark.ml.feature.StringIndexer = strIdx_2db54ba5200a
scala> val label_idx = new StringIndexer().setInputCol("Result").
        setOutputCol("Label")
label_idx: org.apache.spark.ml.feature.StringIndexer = strIdx_20f4316d6232
scala>

//Create labels list to decode predictions
scala> val resultLabels = label_idx.fit(source_ds).labels
resultLabels: Array[String] = Array(Fail, Pass)
scala> val va = new VectorAssembler().setInputCols(Array("Mark_bins","Att_idx")).
                  setOutputCol("features")
va: org.apache.spark.ml.feature.VectorAssembler = vecAssembler_5dc2dbbef48c
scala> val dt = new DecisionTreeClassifier().setLabelCol("Label").
         setFeaturesCol("features")
dt: org.apache.spark.ml.classification.DecisionTreeClassifier = dtc_e8343ae1a9eb
scala> val lc = new IndexToString().setInputCol("prediction").
             setOutputCol("predictedLabel").setLabels(resultLabels)
lc: org.apache.spark.ml.feature.IndexToString = idxToStr_90b6693d4313
scala>

//Define pipeline
scala>val dt_pipeline = new
Pipeline().setStages(Array(marks_bkt,att_idx,label_idx,va,dt,lc))
dt_pipeline: org.apache.spark.ml.Pipeline = pipeline_95876bb6c969
scala> val dtModel = dt_pipeline.fit(source_ds)
dtModel: org.apache.spark.ml.PipelineModel = pipeline_95876bb6c969
scala> val resultDF = dtModel.transform(source_ds)
resultDF: org.apache.spark.sql.DataFrame = [StudentId: int, Avg_Marks: double ...
10 more fields]
scala> resultDF.filter("Label != prediction").select("StudentId","Label","prediction","Result","predictedLabel").show()
+---------+-----+----------+------+--------------+
|StudentId|Label|prediction|Result|predictedLabel|
+---------+-----+----------+------+--------------+\
|     1009|  1.0|       0.0|  Pass|          Fail|
|     1020|  1.0|       0.0|  Pass|          Fail|
+---------+-----+----------+------+--------------+

//Note that the difference is in the student ids that were granted pass

//Same example using Gradient boosted tree classifier, reusing the pipeline stages
scala> import org.apache.spark.ml.classification.GBTClassifier
import org.apache.spark.ml.classification.GBTClassifier
scala> val gbt = new GBTClassifier().setLabelCol("Label").
              setFeaturesCol("features").setMaxIter(10)
gbt: org.apache.spark.ml.classification.GBTClassifier = gbtc_cb55ae2174a1
scala> val gbt_pipeline = new
Pipeline().setStages(Array(marks_bkt,att_idx,label_idx,va,gbt,lc))
gbt_pipeline: org.apache.spark.ml.Pipeline = pipeline_dfd42cd89403
scala> val gbtResultDF = gbt_pipeline.fit(source_ds).transform(source_ds)
gbtResultDF: org.apache.spark.sql.DataFrame = [StudentId: int, Avg_Marks: double ... 8 more fields]
scala> gbtResultDF.filter("Label !=
prediction").select("StudentId","Label","Result","prediction","predictedLabel").show()
+---------+-----+------+----------+--------------+
|StudentId|Label|Result|prediction|predictedLabel|
+---------+-----+------+----------+--------------+
|     1009|  1.0|  Pass|       0.0|          Fail|
|     1020|  1.0|  Pass|       0.0|          Fail|
+---------+-----+------+----------+--------------+
```

**Python：**

```scala
>>> from pyspark.ml.pipeline import Pipeline
>>> from pyspark.ml.feature import Bucketizer, StringIndexer, VectorAssembler, IndexToString
>>> from pyspark.ml.classification import DecisionTreeClassifier,
DecisionTreeClassificationModel
>>> 

//Get source file
>>> file_path = "../work/StudentsPassFail.csv"
>>> source_df = spark.read.csv(file_path,header=True,inferSchema=True)
>>> 

//Examine source data
>>> source_df.show(4)
+---------+---------+----------+------+
|StudentId|Avg_Marks|Attendance|Result|
+---------+---------+----------+------+
|     1001|     48.0|      Full|  Pass|
|     1002|     21.0|    Enough|  Fail|
|     1003|     24.0|    Enough|  Fail|
|     1004|      4.0|      Poor|  Fail|
+---------+---------+----------+------+

//Define preparation pipeline
>>> marks_bkt = Bucketizer(inputCol="Avg_Marks",
        outputCol="Mark_bins", splits=[0,40.0,60.0,100.0])
>>> att_idx = StringIndexer(inputCol = "Attendance",
        outputCol="Att_idx")
>>> label_idx = StringIndexer(inputCol="Result",
                   outputCol="Label")
>>> 

//Create labels list to decode predictions
>>> resultLabels = label_idx.fit(source_df).labels
>>> resultLabels
[u'Fail', u'Pass']
>>> 
>>> va = VectorAssembler(inputCols=["Mark_bins","Att_idx"],
                         outputCol="features")
>>> dt = DecisionTreeClassifier(labelCol="Label", featuresCol="features")
>>> lc = IndexToString(inputCol="prediction",outputCol="predictedLabel",
             labels=resultLabels)
>>> dt_pipeline = Pipeline(stages=[marks_bkt, att_idx, label_idx,va,dt,lc])
>>> dtModel = dt_pipeline.fit(source_df)
>>> resultDF = dtModel.transform(source_df)
>>>

//Look for obervatiuons where prediction did not match
>>> resultDF.filter("Label != prediction").select(
         "StudentId","Label","prediction","Result","predictedLabel").show()
+---------+-----+----------+------+--------------+
|StudentId|Label|prediction|Result|predictedLabel|
+---------+-----+----------+------+--------------+
|     1009|  1.0|       0.0|  Pass|          Fail|
|     1020|  1.0|       0.0|  Pass|          Fail|
+---------+-----+----------+------+--------------+

//Note that the difference is in the student ids that were granted pass
>>> 
//Same example using Gradient boosted tree classifier, reusing the pipeline
stages
>>> from pyspark.ml.classification import GBTClassifier
>>> gbt = GBTClassifier(labelCol="Label", featuresCol="features",maxIter=10)
>>> gbt_pipeline = Pipeline(stages=[marks_bkt,att_idx,label_idx,va,gbt,lc])
>>> gbtResultDF = gbt_pipeline.fit(source_df).transform(source_df)
>>> gbtResultDF.columns
['StudentId', 'Avg_Marks', 'Attendance', 'Result', 'Mark_bins', 'Att_idx',
'Label', 'features', 'prediction', 'predictedLabel']
>>> gbtResultDF.filter("Label !=
prediction").select("StudentId","Label","Result","prediction","predictedLabel").show()
+---------+-----+------+----------+--------------+
|StudentId|Label|Result|prediction|predictedLabel|
+---------+-----+------+----------+--------------+
|     1009|  1.0|  Pass|       0.0|          Fail|
|     1020|  1.0|  Pass|       0.0|          Fail|
+---------+-----+------+----------+--------------+
```

# 多层感知器分类器

**多层感知器分类器**（**MLPC**）是一种前馈人工神经网络，具有多层节点以有向方式相互连接。它使用一种称为*反向传播*的监督学习技术来训练网络。

中间层的节点使用 sigmoid 函数将输出限制在 0 和 1 之间，输出层的节点使用`softmax`函数，这是 sigmoid 函数的广义版本。

**Scala：**

```scala
scala> import org.apache.spark.ml.classification.MultilayerPerceptronClassifier
import org.apache.spark.ml.classification.MultilayerPerceptronClassifier
scala> import org.apache.spark.ml.evaluation.MulticlassClassificationEvaluator
import org.apache.spark.ml.evaluation.MulticlassClassificationEvaluator
scala> import org.apache.spark.mllib.util.MLUtils
import org.apache.spark.mllib.util.MLUtils

// Load training data
scala> val data = MLUtils.loadLibSVMFile(sc,
"data/mllib/sample_multiclass_classification_data.txt").toDF()
data: org.apache.spark.sql.DataFrame = [label: double, features: vector]

//Convert mllib vectors to ml Vectors for spark 2.0+. Retain data for previous versions
scala> val data2 = MLUtils.convertVectorColumnsToML(data)
data2: org.apache.spark.sql.Dataset[org.apache.spark.sql.Row] = [label: double, features: vector]

// Split the data into train and test
scala> val splits = data2.randomSplit(Array(0.6, 0.4), seed = 1234L)
splits: Array[org.apache.spark.sql.Dataset[org.apache.spark.sql.Row]] = Array([label: double, features: vector], [label: double, features: vector])
scala> val train = splits(0)
train: org.apache.spark.sql.Dataset[org.apache.spark.sql.Row] = [label: double, features: vector]
scala> val test = splits(1)
test: org.apache.spark.sql.Dataset[org.apache.spark.sql.Row] = [label: double, features: vector]

// specify layers for the neural network:
// input layer of size 4 (features), two intermediate of size 5 and 4 and output of size 3 (classes)
scala> val layers = ArrayInt
layers: Array[Int] = Array(4, 5, 4, 3)

// create the trainer and set its parameters
scala> val trainer = new MultilayerPerceptronClassifier().
           setLayers(layers).setBlockSize(128).
           setSeed(1234L).setMaxIter(100)
trainer: org.apache.spark.ml.classification.MultilayerPerceptronClassifier = mlpc_edfa49fbae3c

// train the model
scala> val model = trainer.fit(train)
model: org.apache.spark.ml.classification.MultilayerPerceptronClassificationModel = mlpc_edfa49fbae3c

// compute accuracy on the test set
scala> val result = model.transform(test)
result: org.apache.spark.sql.DataFrame = [label: double, features: vector ... 1 more field]
scala> val predictionAndLabels = result.select("prediction", "label")
predictionAndLabels: org.apache.spark.sql.DataFrame = [prediction: double, label: double]
scala> val evaluator = new MulticlassClassificationEvaluator().setMetricName("accuracy")
evaluator: org.apache.spark.ml.evaluation.MulticlassClassificationEvaluator = mcEval_a4f43d85f261
scala> println("Accuracy:" + evaluator.evaluate(predictionAndLabels))
Accuracy:0.9444444444444444

Python: >>> from pyspark.ml.classification import MultilayerPerceptronClassifier
>>> from pyspark.ml.evaluation import MulticlassClassificationEvaluator
>>> from pyspark.mllib.util import MLUtils
>>>

  //Load training data
>>> data = spark.read.format("libsvm").load(      "data/mllib/sample_multiclass_classification_data.txt")

//Convert mllib vectors to ml Vectors for spark 2.0+. Retain data for previous versions
>>> data2 = MLUtils.convertVectorColumnsToML(data)
>>>

 // Split the data into train and test
>>> splits = data2.randomSplit([0.6, 0.4], seed = 1234L)
>>> train, test = splits[0], splits[1]
>>>

 // specify layers for the neural network:
 // input layer of size 4 (features), two intermediate of size 5 and 4 and output of size 3 (classes)
>>> layers = [4,5,4,3] 

// create the trainer and set its parameters
>>> trainer = MultilayerPerceptronClassifier(layers=layers, blockSize=128,
                 seed=1234L, maxIter=100)
// train the model
>>> model = trainer.fit(train)
>>>

// compute accuracy on the test set
>>> result = model.transform(test)
>>> predictionAndLabels = result.select("prediction", "label")
>>> evaluator = MulticlassClassificationEvaluator().setMetricName("accuracy")
>>> print "Accuracy:",evaluator.evaluate(predictionAndLabels)
Accuracy: 0.901960784314
>>> 
```

# 聚类技术

聚类是一种无监督学习技术，其中没有响应变量来监督模型。其思想是对具有某种相似性水平的数据点进行聚类。除了探索性数据分析外，它还可作为监督管道的一部分，其中可以在不同的簇上构建分类器或回归器。有许多聚类技术可用。让我们看一下由 Spark 支持的一些重要技术。

## K-means 聚类

K-means 是最常见的聚类技术之一。k-means 问题是找到最小化簇内方差的簇中心，即，从要进行聚类的每个数据点到其簇中心（最接近它的中心）的平方距离之和。您必须预先指定数据集中要使用的簇的数量。

由于它使用欧几里得距离度量来找到数据点之间的差异，因此在使用 k-means 之前，需要将特征缩放到可比较的单位。欧几里得距离可以用图形方式更好地解释如下：

![K-means 聚类](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_06_051.jpg)

给定一组数据点（*x1*，*x2*，...，*xn*），具有与变量数量相同的维度，k-means 聚类旨在将 n 个观察结果分成 k（小于*n*）个集合，其中*S = {S1，S2，...，Sk}*，以最小化**簇内平方和**（**WCSS**）。换句话说，它的目标是找到：

![K-means 聚类](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_06_052.jpg)

Spark 需要将以下参数传递给此算法：

+   `k`：这是所需簇的数量。

+   `maxIterations`：这是运行的最大迭代次数。

+   `initializationMode`：这指定随机初始化或通过 k-means||初始化。

+   `runs`：这是运行 k-means 算法的次数（k-means 不能保证找到全局最优解，当在给定数据集上运行多次时，算法返回最佳的聚类结果）。

+   `initializationSteps`：这确定 k-means||算法中的步数。

+   `epsilon`：这确定我们认为 k-means 已经收敛的距离阈值。

+   `initialModel`：这是用于初始化的一组可选的聚类中心。如果提供了此参数，将只执行一次运行。

### k-means 的缺点

+   它只适用于数值特征

+   在实施算法之前需要进行缩放

+   它容易受到局部最优解的影响（解决方法是 k-means++）

### 示例

让我们在相同的学生数据上运行 k-means 聚类。

```scala
scala> import org.apache.spark.ml.clustering.{KMeans, KMeansModel}
import org.apache.spark.ml.clustering.{KMeans, KMeansModel}
scala> import org.apache.spark.ml.linalg.Vectors
import org.apache.spark.ml.linalg.Vectors
scala>

//Define pipeline for kmeans. Reuse the previous stages in ENSEMBLES
scala> val km = new KMeans()
km: org.apache.spark.ml.clustering.KMeans = kmeans_b34da02bd7c8
scala> val kmeans_pipeline = new
Pipeline().setStages(Array(marks_bkt,att_idx,label_idx,va,km,lc))
kmeans_pipeline: org.apache.spark.ml.Pipeline = pipeline_0cd64aa93a88

//Train and transform
scala> val kmeansDF = kmeans_pipeline.fit(source_ds).transform(source_ds)
kmeansDF: org.apache.spark.sql.DataFrame = [StudentId: int, Avg_Marks: double ... 8 more fields]

//Examine results
scala> kmeansDF.filter("Label != prediction").count()
res17: Long = 13

```

**Python**：

```scala
>>> from pyspark.ml.clustering import KMeans, KMeansModel
>>> from pyspark.ml.linalg import Vectors
>>> 

//Define pipeline for kmeans. Reuse the previous stages in ENSEMBLES
>>> km = KMeans()
>>> kmeans_pipeline = Pipeline(stages = [marks_bkt, att_idx, label_idx,va,km,lc])

//Train and transform
>>> kmeansDF = kmeans_pipeline.fit(source_df).transform(source_df)
>>> kmeansDF.columns
['StudentId', 'Avg_Marks', 'Attendance', 'Result', 'Mark_bins', 'Att_idx', 'Label', 'features', 'prediction', 'predictedLabel']
>>> kmeansDF.filter("Label != prediction").count()
4
```

# 总结

在本章中，我们解释了各种机器学习算法，以及它们在 MLlib 库中的实现方式，以及如何在管道 API 中使用它们进行流畅的执行。这些概念通过 Python 和 Scala 代码示例进行了解释，以供参考。

在下一章中，我们将讨论 Spark 如何支持 R 编程语言，重点关注一些算法及其执行，类似于我们在本章中涵盖的内容。

# 参考资料

MLlib 中支持的算法：

+   [`spark.apache.org/docs/latest/mllib-guide.html`](http://spark.apache.org/docs/latest/mllib-guide.html)

+   [`spark.apache.org/docs/latest/mllib-decision-tree.html`](http://spark.apache.org/docs/latest/mllib-decision-tree.html)

Spark ML 编程指南：

+   [`spark.apache.org/docs/latest/ml-guide.html`](http://spark.apache.org/docs/latest/ml-guide.html)

2015 年 6 月峰会幻灯片中的高级数据科学在 spark.pdf 中：

+   [`databricks.com/blog/2015/07/29/new-features-in-machine-learning-pipelines-in-spark-1-4.html`](https://databricks.com/blog/2015/07/29/new-features-in-machine-learning-pipelines-in-spark-1-4.html)

+   [`databricks.com/blog/2015/06/02/statistical-and-mathematical-functions-with-dataframes-in-spark.html`](https://databricks.com/blog/2015/06/02/statistical-and-mathematical-functions-with-dataframes-in-spark.html)

+   [`databricks.com/blog/2015/01/07/ml-pipelines-a-new-high-level-api-for-mllib.html`](https://databricks.com/blog/2015/01/07/ml-pipelines-a-new-high-level-api-for-mllib.html)
