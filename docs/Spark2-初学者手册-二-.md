# Spark2 初学者手册（二）

> 原文：[`zh.annas-archive.org/md5/4803F9F0B1A27EADC7FE0DFBB64A3594`](https://zh.annas-archive.org/md5/4803F9F0B1A27EADC7FE0DFBB64A3594)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：Spark 编程与 R

R 是一种流行的统计计算编程语言，被许多人使用，并根据**通用公共许可证**（**GNU**）免费提供。R 源自 John Chambers 创建的编程语言 S。R 由 Ross Ihaka 和 Robert Gentleman 开发。许多数据科学家使用 R 来满足他们的计算需求。R 内置支持许多统计函数和许多标量数据类型，并具有向量、矩阵、数据框等复合数据结构，用于统计计算。R 高度可扩展，因此可以创建外部包。一旦创建了外部包，就必须安装并加载它，以便任何程序都可以使用它。目录下的一组此类包构成一个 R 库。换句话说，R 附带了一组基本包和附加包，可以安装在它上面，以形成满足所需计算需求的库。除了函数之外，数据集也可以打包在 R 包中。

本章我们将涵盖以下主题：

+   对 SparkR 的需求

+   R 基础

+   数据框

+   聚合

+   使用 SparkR 进行多数据源连接

# 对 SparkR 的需求

**SparkR** 包使得基础 R 安装能够与 Spark 交互，它提供了 R 与 Spark 生态系统对话所需的所有对象和函数。与 Scala、Java 和 Python 相比，R 中的 Spark 编程有所不同，SparkR 包主要提供基于 DataFrame 的 Spark SQL 编程的 R API。目前，R 无法直接操作 Spark 的 RDD。因此，实际上，R 的 Spark API 只能访问 Spark SQL 抽象。由于 Spark **MLlib** 使用 DataFrames，因此也可以使用 R 进行编程。

SparkR 如何帮助数据科学家进行更好的数据处理？基础 R 安装要求所有数据都必须存储（或可访问）在安装了 R 的计算机上。数据处理发生在安装了 R 的单台计算机上。此外，如果数据大小超过了计算机上的主内存，R 将无法执行所需的加工。通过 SparkR 包，可以访问一个全新的集群节点世界，用于数据存储和数据处理。借助 SparkR 包，R 可以访问 Spark DataFrames 和 R DataFrames。

了解 R Dataframes 和 Spark Dataframes 这两种数据框之间的区别非常重要。R DataFrame 是完全本地的，是 R 语言的数据结构。Spark DataFrame 是由 Spark 基础设施管理的结构化数据的并行集合。

R DataFrame 可以转换为 Spark DataFrame，Spark DataFrame 也可以转换为 R DataFrame。

当 Spark DataFrame 转换为 R DataFrame 时，它应该能适配到计算机的可用内存中。这种转换是一个很好的特性，也是有必要的。通过将 R DataFrame 转换为 Spark DataFrame，数据可以分布并并行处理。通过将 Spark DataFrame 转换为 R DataFrame，可以使用其他 R 函数进行大量计算、制图和绘图。简而言之，SparkR 包为 R 带来了分布式和并行计算的能力。

通常，在使用 R 进行数据处理时，由于数据量巨大且需要将其适配到计算机的主内存中，数据处理会分多个批次进行，并将结果汇总以计算最终结果。如果使用 Spark 与 R 来处理数据，这种多批次处理完全可以避免。

通常，报告、制图和绘图都是基于汇总和概述的原始数据进行的。原始数据量可能非常庞大，无需适配到一台计算机上。在这种情况下，可以使用 Spark 与 R 来处理整个原始数据，最终，汇总和概述的数据可用于生成报告、图表或绘图。

由于 R 无法处理大量数据以及进行数据分析，很多时候，ETL 工具被用来进行原始数据的预处理或转换，只有在最后阶段才使用 R 进行数据分析。由于 Spark 能够大规模处理数据，Spark 与 R 可以取代整个 ETL 流程，并用 R 进行所需的数据分析。

许多 R 用户使用**dplyr** R 包来操作 R 中的数据集。该包提供了快速的数据操作功能，支持 R DataFrames。就像操作本地 R DataFrames 一样，它也可以访问某些 RDBMS 表中的数据。除了这些基本的数据操作功能外，它缺乏 Spark 中提供的许多数据处理特性。因此，Spark 与 R 是诸如 dplyr 等包的良好替代品。

SparkR 包是另一个 R 包，但这并不妨碍任何人继续使用已有的任何 R 包。同时，它通过利用 Spark 强大的数据处理能力，极大地增强了 R 的数据处理功能。

# R 语言基础

这并非 R 编程的指南。但是，为了帮助不熟悉 R 的人理解本章所涵盖的内容，简要介绍 R 语言的基础知识是很重要的。这里涵盖了语言特性的非常基本的介绍。

R 自带了几种内置数据类型来存储数值、字符和布尔值。还有复合数据结构，其中最重要的是向量、列表、矩阵和数据框。向量是由给定类型的有序值集合组成。列表是有序的元素集合，这些元素可以是不同类型。例如，一个列表可以包含两个向量，其中一个向量包含数值，另一个向量包含布尔值。矩阵是二维数据结构，按行和列存储数值。数据框是二维数据结构，包含行和列，其中列可以有不同的数据类型，但单个列不能包含不同的数据类型。

以下代码示例展示了使用变量（向量的特殊情况）、数值向量、字符向量、列表、矩阵、数据框以及为数据框分配列名的方法。变量名尽可能自描述，以便读者无需额外解释即可理解。以下代码片段在常规 R REPL 上运行，展示了 R 的数据结构：

```scala
$ r 
R version 3.2.2 (2015-08-14) -- "Fire Safety" 
Copyright (C) 2015 The R Foundation for Statistical Computing 
Platform: x86_64-apple-darwin13.4.0 (64-bit) 

R is free software and comes with ABSOLUTELY NO WARRANTY. 
You are welcome to redistribute it under certain conditions. 
Type 'license()' or 'licence()' for distribution details. 

  Natural language support but running in an English locale 

R is a collaborative project with many contributors. 
Type 'contributors()' for more information and 
'citation()' on how to cite R or R packages in publications. 

Type 'demo()' for some demos, 'help()' for on-line help, or 
'help.start()' for an HTML browser interface to help. 
Type 'q()' to quit R. 

Warning: namespace 'SparkR' is not available and has been replaced 
by .GlobalEnv when processing object 'goodTransRecords' 
[Previously saved workspace restored] 
> 
> x <- 5 
> x 
[1] 5 
> aNumericVector <- c(10,10.5,31.2,100) 
> aNumericVector 
[1]  10.0  10.5  31.2 100.0 
> aCharVector <- c("apple", "orange", "mango") 
> aCharVector 
[1] "apple"  "orange" "mango"  
> aBooleanVector <- c(TRUE, FALSE, TRUE, FALSE, FALSE) 
> aBooleanVector 
[1]  TRUE FALSE  TRUE FALSE FALSE 
> aList <- list(aNumericVector, aCharVector) 
> aList 
[[1]] 
[1]  10.0  10.5  31.2 100.0 
[[2]] 
[1] "apple"  "orange" "mango" 
> aMatrix <- matrix(c(100, 210, 76, 65, 34, 45),nrow=3,ncol=2,byrow = TRUE) 
> aMatrix 
     [,1] [,2] 
[1,]  100  210 
[2,]   76   65 
[3,]   34   45 
> bMatrix <- matrix(c(100, 210, 76, 65, 34, 45),nrow=3,ncol=2,byrow = FALSE) 
> bMatrix 
     [,1] [,2] 
[1,]  100   65 
[2,]  210   34 
[3,]   76   45 
> ageVector <- c(21, 35, 52)  
> nameVector <- c("Thomas", "Mathew", "John")  
> marriedVector <- c(FALSE, TRUE, TRUE)  
> aDataFrame <- data.frame(ageVector, nameVector, marriedVector)  
> aDataFrame 
  ageVector nameVector marriedVector 
1        21     Thomas         FALSE 
2        35     Mathew          TRUE 
3        52       John          TRUE 
> colnames(aDataFrame) <- c("Age","Name", "Married") 
> aDataFrame 
  Age   Name Married 
1  21 Thomas   FALSE 
2  35 Mathew    TRUE 
3  52   John    TRUE 

```

这里讨论的主要话题将围绕数据框展开。以下展示了与数据框常用的一些函数。所有这些命令都应在常规 R REPL 中执行，作为执行前述代码片段的会话的延续：

```scala
> # Returns the first part of the data frame and return two rows 
> head(aDataFrame,2) 
  Age   Name Married 
1  21 Thomas   FALSE 
2  35 Mathew    TRUE 

> # Returns the last part of the data frame and return two rows 
> tail(aDataFrame,2) 
  Age   Name Married  
2  35 Mathew    TRUE 
3  52   John    TRUE 
> # Number of rows in a data frame 
> nrow(aDataFrame) 
[1] 3 
> # Number of columns in a data frame 
> ncol(aDataFrame) 
[1] 3 
> # Returns the first column of the data frame. The return value is a data frame 
> aDataFrame[1] 
  Age 
1  21 
2  35 
3  52 
> # Returns the second column of the data frame. The return value is a data frame 
> aDataFrame[2] 
    Name 
1 Thomas 
2 Mathew 
3   John 
> # Returns the named columns of the data frame. The return value is a data frame 
> aDataFrame[c("Age", "Name")] 
  Age   Name 
1  21 Thomas 
2  35 Mathew 
3  52   John 
> # Returns the contents of the second column of the data frame as a vector.  
> aDataFrame[[2]] 
[1] Thomas Mathew John   
Levels: John Mathew Thomas 
> # Returns the slice of the data frame by a row 
> aDataFrame[2,] 
  Age   Name Married 
2  35 Mathew    TRUE 
> # Returns the slice of the data frame by multiple rows 
> aDataFrame[c(1,2),] 
  Age   Name Married 
1  21 Thomas   FALSE 
2  35 Mathew    TRUE 

```

# R 与 Spark 中的数据框

在使用 R 操作 Spark 时，很容易对 DataFrame 数据结构感到困惑。如前所述，R 和 Spark SQL 中都存在 DataFrame。下面的代码片段涉及将 R 数据框转换为 Spark 数据框以及反向转换。当使用 R 编程 Spark 时，这将是一种非常常见的操作。以下代码片段应在 Spark 的 R REPL 中执行。从现在开始，所有对 R REPL 的引用都是指 Spark 的 R REPL：

```scala
$ cd $SPARK_HOME 
$ ./bin/sparkR 

R version 3.2.2 (2015-08-14) -- "Fire Safety" 
Copyright (C) 2015 The R Foundation for Statistical Computing 
Platform: x86_64-apple-darwin13.4.0 (64-bit) 

R is free software and comes with ABSOLUTELY NO WARRANTY. 
You are welcome to redistribute it under certain conditions. 
Type 'license()' or 'licence()' for distribution details. 

  Natural language support but running in an English locale 

R is a collaborative project with many contributors. 
Type 'contributors()' for more information and 
'citation()' on how to cite R or R packages in publications. 

Type 'demo()' for some demos, 'help()' for on-line help, or 
'help.start()' for an HTML browser interface to help. 
Type 'q()' to quit R. 

[Previously saved workspace restored] 

Launching java with spark-submit command /Users/RajT/source-code/spark-source/spark-2.0/bin/spark-submit   "sparkr-shell" /var/folders/nf/trtmyt9534z03kq8p8zgbnxh0000gn/T//RtmpmuRsTC/backend_port2d121acef4  
Using Spark's default log4j profile: org/apache/spark/log4j-defaults.properties 
Setting default log level to "WARN". 
To adjust logging level use sc.setLogLevel(newLevel). 
16/07/16 21:08:50 WARN NativeCodeLoader: Unable to load native-hadoop library for your platform... using builtin-java classes where applicable 

 Welcome to 
    ____              __  
   / __/__  ___ _____/ /__  
  _\ \/ _ \/ _ `/ __/  '_/  
 /___/ .__/\_,_/_/ /_/\_\   version  2.0.1-SNAPSHOT  
    /_/  

 Spark context is available as sc, SQL context is available as sqlContext 
During startup - Warning messages: 
1: 'SparkR::sparkR.init' is deprecated. 
Use 'sparkR.session' instead. 
See help("Deprecated")  
2: 'SparkR::sparkRSQL.init' is deprecated. 
Use 'sparkR.session' instead. 
See help("Deprecated")  
> 
> # faithful is a data set and the data frame that comes with base R 
> # Obviously it is an R DataFrame 
> head(faithful) 
  eruptions waiting 
1     3.600      79 
2     1.800      54 
3     3.333      74 
4     2.283      62 
5     4.533      85 
6     2.883      55 
> tail(faithful) 
    eruptions waiting 
267     4.750      75 
268     4.117      81 
269     2.150      46 
270     4.417      90 
271     1.817      46 
272     4.467      74 
> # Convert R DataFrame to Spark DataFrame  
> sparkFaithful <- createDataFrame(faithful) 
> head(sparkFaithful) 
  eruptions waiting 
1     3.600      79 
2     1.800      54 
3     3.333      74 
4     2.283      62 
5     4.533      85 
6     2.883      55 
> showDF(sparkFaithful) 
+---------+-------+ 
|eruptions|waiting| 
+---------+-------+ 
|      3.6|   79.0| 
|      1.8|   54.0| 
|    3.333|   74.0| 
|    2.283|   62.0| 
|    4.533|   85.0| 
|    2.883|   55.0| 
|      4.7|   88.0| 
|      3.6|   85.0| 
|     1.95|   51.0| 
|     4.35|   85.0| 
|    1.833|   54.0| 
|    3.917|   84.0| 
|      4.2|   78.0| 
|     1.75|   47.0| 
|      4.7|   83.0| 
|    2.167|   52.0| 
|     1.75|   62.0| 
|      4.8|   84.0| 
|      1.6|   52.0| 
|     4.25|   79.0| 
+---------+-------+ 
only showing top 20 rows 
> # Try calling a SparkR function showDF() on an R DataFrame. The following error message will be shown 
> showDF(faithful) 
Error in (function (classes, fdef, mtable)  :  
  unable to find an inherited method for function 'showDF' for signature '"data.frame"' 
> # Convert the Spark DataFrame to an R DataFrame 
> rFaithful <- collect(sparkFaithful) 
> head(rFaithful) 
  eruptions waiting 
1     3.600      79 
2     1.800      54 
3     3.333      74 
4     2.283      62 
5     4.533      85 
6     2.883      55 

```

在支持的函数方面，R 数据框与 Spark 数据框之间没有完全的兼容性和互操作性。

### 提示

为了区分两种不同类型的数据框，在 R 程序中最好按照约定俗成的规则为 R 数据框和 Spark 数据框命名。并非所有 R 数据框支持的函数都适用于 Spark 数据框，反之亦然。务必参考正确的 R API 版本以使用 Spark。

对于经常使用图表和绘图的人来说，在处理 R DataFrames 与 Spark DataFrames 结合时必须格外小心。R 的图表和绘图功能仅适用于 R DataFrames。如果需要使用 Spark 处理的数据并将其呈现在 Spark DataFrame 中的图表或绘图中，则必须将其转换为 R DataFrame 才能继续进行图表和绘图。以下代码片段将对此有所启示。我们将在 Spark 的 R REPL 中再次使用 faithful 数据集进行说明：

```scala
head(faithful) 
  eruptions waiting 
1     3.600      79 
2     1.800      54 
3     3.333      74 
4     2.283      62 
5     4.533      85 
6     2.883      55 
> # Convert the faithful R DataFrame to Spark DataFrame   
> sparkFaithful <- createDataFrame(faithful) 
> # The Spark DataFrame sparkFaithful NOT producing a histogram 
> hist(sparkFaithful$eruptions,main="Distribution of Eruptions",xlab="Eruptions") 
Error in hist.default(sparkFaithful$eruptions, main = "Distribution of Eruptions",  :  
  'x' must be numeric 
> # The R DataFrame faithful producing a histogram 
> hist(faithful$eruptions,main="Distribution of Eruptions",xlab="Eruptions")

```

此处数字仅用于演示，说明 Spark DataFrame 不能用于制图，而必须使用 R DataFrame 进行相同的操作：

![R 与 Spark 中的 DataFrames](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-bg/img/image_04_002.jpg)

图 1

当图表和绘图库与 Spark DataFrame 一起使用时，由于数据类型不兼容，出现了错误。

### 提示

需要记住的最重要的一点是，R DataFrame 是一种内存驻留数据结构，而 Spark DataFrame 是一种跨集群节点分布的并行数据集集合。因此，所有使用 R DataFrames 的功能不一定适用于 Spark DataFrames，反之亦然。

让我们再次回顾一下大局，如*图 2*所示，以便设定背景并了解正在讨论的内容，然后再深入探讨并处理这些用例。在前一章中，同一主题是通过使用 Scala 和 Python 编程语言引入的。在本章中，将使用 R 实现 Spark SQL 编程中使用的同一组用例：

![R 与 Spark 中的 DataFrames](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-bg/img/image_04_004.jpg)

图 2

此处将要讨论的用例将展示在 R 中混合使用 SQL 查询和 Spark 程序的能力。将选择多个数据源，使用 DataFrame 从这些源读取数据，并演示统一的数据访问。

# Spark DataFrame 编程与 R

以下是用于阐明使用 DataFrame 进行 Spark SQL 编程的用例：

+   交易记录是以逗号分隔的值。

+   从列表中筛选出仅包含良好交易记录的记录。账户号码应以`SB`开头，且交易金额应大于零。

+   找出所有交易金额大于 1000 的高价值交易记录。

+   找出所有账户号码不良的交易记录。

+   找出所有交易金额小于或等于零的交易记录。

+   找出所有不良交易记录的合并列表。

+   找出所有交易金额的总和。

+   找出所有交易金额的最大值。

+   找出所有交易金额的最小值。

+   找出所有良好账户号码。

这正是上一章中使用的一组用例，但在这里，编程模型完全不同。此处，编程采用 R 语言。通过这组用例，展示了两种编程模型：一种是使用 SQL 查询，另一种是使用 DataFrame API。

### 提示

运行以下代码片段所需的数据文件可从保存 R 代码的同一目录中获取。

在以下代码片段中，数据从文件系统中的文件读取。由于所有这些代码片段都在 Spark 的 R REPL 中执行，因此所有数据文件都应保存在`$SPARK_HOME`目录中。

## 使用 SQL 编程

在 R REPL 提示符下，尝试以下语句：

```scala
> # TODO - Change the data directory location to the right location in the system in which this program is being run 
> DATA_DIR <- "/Users/RajT/Documents/CodeAndData/R/" 
> # Read data from a JSON file to create DataFrame 
>  
> acTransDF <- read.json(paste(DATA_DIR, "TransList1.json", sep = "")) 
> # Print the structure of the DataFrame 
> print(acTransDF) 
SparkDataFrame[AccNo:string, TranAmount:bigint] 
> # Show sample records from the DataFrame 
> showDF(acTransDF) 
+-------+----------+ 
|  AccNo|TranAmount| 
+-------+----------+ 
|SB10001|      1000| 
|SB10002|      1200| 
|SB10003|      8000| 
|SB10004|       400| 
|SB10005|       300| 
|SB10006|     10000| 
|SB10007|       500| 
|SB10008|        56| 
|SB10009|        30| 
|SB10010|      7000| 
|CR10001|      7000| 
|SB10002|       -10| 
+-------+----------+ 
> # Register temporary view definition in the DataFrame for SQL queries 
> createOrReplaceTempView(acTransDF, "trans") 
> # DataFrame containing good transaction records using SQL 
> goodTransRecords <- sql("SELECT AccNo, TranAmount FROM trans WHERE AccNo like 'SB%' AND TranAmount > 0") 
> # Register temporary table definition in the DataFrame for SQL queries 

> createOrReplaceTempView(goodTransRecords, "goodtrans") 
> # Show sample records from the DataFrame 
> showDF(goodTransRecords) 
+-------+----------+ 
|  AccNo|TranAmount| 
+-------+----------+ 
|SB10001|      1000| 
|SB10002|      1200| 
|SB10003|      8000| 
|SB10004|       400| 
|SB10005|       300| 
|SB10006|     10000| 
|SB10007|       500| 
|SB10008|        56| 
|SB10009|        30| 
|SB10010|      7000| 
+-------+----------+ 
> # DataFrame containing high value transaction records using SQL 
> highValueTransRecords <- sql("SELECT AccNo, TranAmount FROM goodtrans WHERE TranAmount > 1000") 
> # Show sample records from the DataFrame 
> showDF(highValueTransRecords) 
+-------+----------+ 
|  AccNo|TranAmount| 
+-------+----------+ 
|SB10002|      1200| 
|SB10003|      8000| 
|SB10006|     10000| 
|SB10010|      7000| 
+-------+----------+ 
> # DataFrame containing bad account records using SQL 
> badAccountRecords <- sql("SELECT AccNo, TranAmount FROM trans WHERE AccNo NOT like 'SB%'") 
> # Show sample records from the DataFrame 
> showDF(badAccountRecords) 
+-------+----------+ 
|  AccNo|TranAmount| 
+-------+----------+ 
|CR10001|      7000| 
+-------+----------+ 
> # DataFrame containing bad amount records using SQL 
> badAmountRecords <- sql("SELECT AccNo, TranAmount FROM trans WHERE TranAmount < 0") 
> # Show sample records from the DataFrame 
> showDF(badAmountRecords) 
+-------+----------+ 
|  AccNo|TranAmount| 
+-------+----------+ 
|SB10002|       -10| 
+-------+----------+ 
> # Create a DataFrame by taking the union of two DataFrames 
> badTransRecords <- union(badAccountRecords, badAmountRecords) 
> # Show sample records from the DataFrame 
> showDF(badTransRecords) 
+-------+----------+ 
|  AccNo|TranAmount| 
+-------+----------+ 
|CR10001|      7000| 
|SB10002|       -10| 
+-------+----------+ 
> # DataFrame containing sum amount using SQL 
> sumAmount <- sql("SELECT sum(TranAmount) as sum FROM goodtrans") 
> # Show sample records from the DataFrame 
> showDF(sumAmount) 
+-----+ 
|  sum| 
+-----+ 
|28486| 
+-----+ 
> # DataFrame containing maximum amount using SQL 
> maxAmount <- sql("SELECT max(TranAmount) as max FROM goodtrans") 
> # Show sample records from the DataFrame 
> showDF(maxAmount) 
+-----+ 
|  max| 
+-----+ 
|10000| 
+-----+ 
> # DataFrame containing minimum amount using SQL 
> minAmount <- sql("SELECT min(TranAmount)as min FROM goodtrans") 
> # Show sample records from the DataFrame 
> showDF(minAmount) 
+---+ 
|min| 
+---+ 
| 30| 
+---+ 
> # DataFrame containing good account number records using SQL 
> goodAccNos <- sql("SELECT DISTINCT AccNo FROM trans WHERE AccNo like 'SB%' ORDER BY AccNo") 
> # Show sample records from the DataFrame 
> showDF(goodAccNos) 
+-------+ 
|  AccNo| 
+-------+ 
|SB10001| 
|SB10002| 
|SB10003| 
|SB10004| 
|SB10005| 
|SB10006| 
|SB10007| 
|SB10008| 
|SB10009| 
|SB10010| 
+-------+

```

零售银行交易记录包含账号、交易金额，通过 SparkSQL 处理以获得用例所需的预期结果。以下是前述脚本所做工作的概述：

+   与其他支持 Spark 的编程语言不同，R 不具备 RDD 编程能力。因此，不采用从集合构建 RDD 的方式，而是从包含交易记录的 JSON 文件中读取数据。

+   从 JSON 文件创建了一个 Spark DataFrame。

+   通过给 DataFrame 注册一个名称，该名称可用于 SQL 语句中。

+   然后，所有其他活动都是通过 SparkR 包中的 SQL 函数发出 SQL 语句。

+   所有这些 SQL 语句的结果都存储为 Spark DataFrames，并使用`showDF`函数将值提取到调用的 R 程序中。

+   通过 SQL 语句也进行了聚合值的计算。

+   使用 SparkR 的`showDF`函数，DataFrame 内容以表格形式显示。

+   使用 print 函数显示 DataFrame 结构的详细视图。这类似于数据库表的 describe 命令。

在前述的 R 代码中，编程风格与 Scala 代码相比有所不同，这是因为它是 R 程序。通过使用 SparkR 库，正在使用 Spark 特性。但函数和其他抽象并没有采用截然不同的风格。

### 注意

本章中，将多次涉及 DataFrames 的使用。很容易混淆哪个是 R DataFrame，哪个是 Spark DataFrame。因此，特别注意通过限定 DataFrame 来明确指出，例如 R DataFrame 和 Spark DataFrame。

## 使用 R DataFrame API 编程

在本节中，代码片段将在同一 R REPL 中运行。与前述代码片段类似，最初会给出一些 DataFrame 特定的基本命令。这些命令常用于查看内容并对 DataFrame 及其内容进行一些基本测试。这些命令在数据分析的探索阶段经常使用，以深入了解底层数据的结构和内容。

在 R REPL 提示符下，尝试以下语句：

```scala
> # Read data from a JSON file to create DataFrame 
> acTransDF <- read.json(paste(DATA_DIR, "TransList1.json", sep = "")) 
> print(acTransDF) 
SparkDataFrame[AccNo:string, TranAmount:bigint] 
> # Show sample records from the DataFrame 
> showDF(acTransDF) 
+-------+----------+ 
|  AccNo|TranAmount| 
+-------+----------+ 
|SB10001|      1000| 
|SB10002|      1200| 
|SB10003|      8000| 
|SB10004|       400| 
|SB10005|       300| 
|SB10006|     10000| 
|SB10007|       500| 
|SB10008|        56| 
|SB10009|        30| 
|SB10010|      7000| 
|CR10001|      7000| 
|SB10002|       -10| 
+-------+----------+ 
> # DataFrame containing good transaction records using API 
> goodTransRecordsFromAPI <- filter(acTransDF, "AccNo like 'SB%' AND TranAmount > 0") 
> # Show sample records from the DataFrame 
> showDF(goodTransRecordsFromAPI) 
+-------+----------+ 
|  AccNo|TranAmount| 
+-------+----------+ 
|SB10001|      1000| 
|SB10002|      1200| 
|SB10003|      8000| 
|SB10004|       400| 
|SB10005|       300| 
|SB10006|     10000| 
|SB10007|       500| 
|SB10008|        56| 
|SB10009|        30| 
|SB10010|      7000| 
+-------+----------+ 
> # DataFrame containing high value transaction records using API 
> highValueTransRecordsFromAPI = filter(goodTransRecordsFromAPI, "TranAmount > 1000") 
> # Show sample records from the DataFrame 
> showDF(highValueTransRecordsFromAPI) 
+-------+----------+ 
|  AccNo|TranAmount| 
+-------+----------+ 
|SB10002|      1200| 
|SB10003|      8000| 
|SB10006|     10000| 
|SB10010|      7000| 
+-------+----------+ 
> # DataFrame containing bad account records using API 
> badAccountRecordsFromAPI <- filter(acTransDF, "AccNo NOT like 'SB%'") 
> # Show sample records from the DataFrame 
> showDF(badAccountRecordsFromAPI) 
+-------+----------+ 
|  AccNo|TranAmount| 
+-------+----------+ 
|CR10001|      7000| 
+-------+----------+ 
> # DataFrame containing bad amount records using API 
> badAmountRecordsFromAPI <- filter(acTransDF, "TranAmount < 0") 
> # Show sample records from the DataFrame 
> showDF(badAmountRecordsFromAPI) 
+-------+----------+ 
|  AccNo|TranAmount| 
+-------+----------+ 
|SB10002|       -10| 
+-------+----------+ 
> # Create a DataFrame by taking the union of two DataFrames 
> badTransRecordsFromAPI <- union(badAccountRecordsFromAPI, badAmountRecordsFromAPI) 
> # Show sample records from the DataFrame 
> showDF(badTransRecordsFromAPI) 
+-------+----------+ 
|  AccNo|TranAmount| 
+-------+----------+ 
|CR10001|      7000| 
|SB10002|       -10| 
+-------+----------+ 
> # DataFrame containing sum amount using API 
> sumAmountFromAPI <- agg(goodTransRecordsFromAPI, sumAmount = sum(goodTransRecordsFromAPI$TranAmount)) 
> # Show sample records from the DataFrame 
> showDF(sumAmountFromAPI) 
+---------+ 
|sumAmount| 
+---------+ 
|    28486| 
+---------+ 
> # DataFrame containing maximum amount using API 
> maxAmountFromAPI <- agg(goodTransRecordsFromAPI, maxAmount = max(goodTransRecordsFromAPI$TranAmount)) 
> # Show sample records from the DataFrame 
> showDF(maxAmountFromAPI) 
+---------+ 
|maxAmount| 
+---------+ 
|    10000| 
+---------+ 
> # DataFrame containing minimum amount using API 
> minAmountFromAPI <- agg(goodTransRecordsFromAPI, minAmount = min(goodTransRecordsFromAPI$TranAmount))  
> # Show sample records from the DataFrame 
> showDF(minAmountFromAPI) 
+---------+ 
|minAmount| 
+---------+ 
|       30| 
+---------+ 
> # DataFrame containing good account number records using API 
> filteredTransRecordsFromAPI <- filter(goodTransRecordsFromAPI, "AccNo like 'SB%'") 
> accNosFromAPI <- select(filteredTransRecordsFromAPI, "AccNo") 
> distinctAccNoFromAPI <- distinct(accNosFromAPI) 
> sortedAccNoFromAPI <- arrange(distinctAccNoFromAPI, "AccNo") 
> # Show sample records from the DataFrame 
> showDF(sortedAccNoFromAPI) 
+-------+ 
|  AccNo| 
+-------+ 
|SB10001| 
|SB10002| 
|SB10003| 
|SB10004| 
|SB10005| 
|SB10006| 
|SB10007| 
|SB10008| 
|SB10009| 
|SB10010| 
+-------+ 
> # Persist the DataFrame into a Parquet file  
> write.parquet(acTransDF, "r.trans.parquet") 
> # Read the data from the Parquet file 
> acTransDFFromFile <- read.parquet("r.trans.parquet")  
> # Show sample records from the DataFrame 
> showDF(acTransDFFromFile) 
+-------+----------+ 
|  AccNo|TranAmount| 
+-------+----------+ 
|SB10007|       500| 
|SB10008|        56| 
|SB10009|        30| 
|SB10010|      7000| 
|CR10001|      7000| 
|SB10002|       -10| 
|SB10001|      1000| 
|SB10002|      1200| 
|SB10003|      8000| 
|SB10004|       400| 
|SB10005|       300| 
|SB10006|     10000| 
+-------+----------+ 

```

以下是从 DataFrame API 角度对前面脚本所做操作的概述：

+   在前一节中使用的包含所有数据的 DataFrame 在此处被使用。

+   接下来演示记录的筛选。这里需注意的最重要一点是，筛选条件必须与 SQL 语句中的谓词完全一致。无法链式应用过滤器。

+   接下来计算聚合方法。

+   本组中的最终语句执行选择、筛选、选择唯一记录和排序。

+   最后，交易记录以 Parquet 格式持久化，从 Parquet 存储中读取，并创建了一个 Spark DataFrame。关于持久化格式的更多细节已在上一章中涵盖，概念保持不变。仅 DataFrame API 语法有所不同。

+   在此代码片段中，Parquet 格式的数据存储在当前目录，从该目录调用相应的 REPL。当作为 Spark 程序运行时，目录再次成为从该处调用 Spark 提交的当前目录。

最后几条语句涉及将 DataFrame 内容持久化到介质中。若与前一章中 Scala 和 Python 的持久化机制相比较，此处也以类似方式实现。

# 理解 Spark R 中的聚合

在 SQL 中，数据聚合非常灵活。Spark SQL 中亦是如此。与在单机上的单一数据源运行 SQL 语句不同，Spark SQL 能够在分布式数据源上执行相同操作。在涵盖 RDD 编程的章节中，讨论了一个用于数据聚合的 MapReduce 用例，这里同样使用该用例来展示 Spark SQL 的聚合能力。本节中，用例既通过 SQL 查询方式处理，也通过 DataFrame API 方式处理。

此处给出了用于阐明 MapReduce 类型数据处理的选定用例：

+   零售银行业务交易记录以逗号分隔的字符串形式包含账户号和交易金额

+   查找所有交易的账户级别汇总以获取账户余额

在 R REPL 提示符下，尝试以下语句：

```scala
> # Read data from a JSON file to create DataFrame 
> acTransDFForAgg <- read.json(paste(DATA_DIR, "TransList2.json", sep = "")) 
> # Register temporary view definition in the DataFrame for SQL queries 
> createOrReplaceTempView(acTransDFForAgg, "transnew") 
> # Show sample records from the DataFrame 
> showDF(acTransDFForAgg) 
+-------+----------+ 
|  AccNo|TranAmount| 
+-------+----------+ 
|SB10001|      1000| 
|SB10002|      1200| 
|SB10001|      8000| 
|SB10002|       400| 
|SB10003|       300| 
|SB10001|     10000| 
|SB10004|       500| 
|SB10005|        56| 
|SB10003|        30| 
|SB10002|      7000| 
|SB10001|      -100| 
|SB10002|       -10| 
+-------+----------+ 
> # DataFrame containing account summary records using SQL 
> acSummary <- sql("SELECT AccNo, sum(TranAmount) as TransTotal FROM transnew GROUP BY AccNo") 
> # Show sample records from the DataFrame 
> showDF(acSummary) 
+-------+----------+ 
|  AccNo|TransTotal| 
+-------+----------+ 
|SB10001|     18900| 
|SB10002|      8590| 
|SB10003|       330| 
|SB10004|       500| 
|SB10005|        56| 
+-------+----------+ 
> # DataFrame containing account summary records using API 
> acSummaryFromAPI <- agg(groupBy(acTransDFForAgg, "AccNo"), TranAmount="sum") 
> # Show sample records from the DataFrame 
> showDF(acSummaryFromAPI) 
+-------+---------------+ 
|  AccNo|sum(TranAmount)| 
+-------+---------------+ 
|SB10001|          18900| 
|SB10002|           8590| 
|SB10003|            330| 
|SB10004|            500| 
|SB10005|             56| 
+-------+---------------+ 

```

在 R DataFrame API 中，与 Scala 或 Python 版本相比，存在一些语法差异，主要是因为这是一种纯粹基于 API 的编程模型。

# 理解 SparkR 中的多数据源连接

在前一章中，基于键合并多个 DataFrame 的内容已进行讨论。本节中，同一用例通过 Spark SQL 的 R API 实现。以下部分给出了用于阐明基于键合并多个数据集的选定用例。

第一个数据集包含零售银行业务主记录摘要，包括账号、名字和姓氏。第二个数据集包含零售银行账户余额，包括账号和余额金额。两个数据集的关键字段均为账号。将两个数据集连接，创建一个包含账号、名字、姓氏和余额金额的数据集。从此报告中，挑选出余额金额排名前三的账户。

Spark DataFrames 由持久化的 JSON 文件创建。除 JSON 文件外，还可使用任何支持的数据文件。随后，这些文件从磁盘读取以形成 DataFrames，并进行连接。

在 R REPL 提示符下，尝试以下语句：

```scala
> # Read data from JSON file 
> acMasterDF <- read.json(paste(DATA_DIR, "MasterList.json", sep = "")) 
> # Show sample records from the DataFrame 
> showDF(acMasterDF) 
+-------+---------+--------+ 
|  AccNo|FirstName|LastName| 
+-------+---------+--------+ 
|SB10001|    Roger| Federer| 
|SB10002|     Pete| Sampras| 
|SB10003|   Rafael|   Nadal| 
|SB10004|    Boris|  Becker| 
|SB10005|     Ivan|   Lendl| 
+-------+---------+--------+ 
> # Register temporary view definition in the DataFrame for SQL queries 
> createOrReplaceTempView(acMasterDF, "master")  
> acBalDF <- read.json(paste(DATA_DIR, "BalList.json", sep = "")) 
> # Show sample records from the DataFrame 
> showDF(acBalDF) 
+-------+---------+ 
|  AccNo|BalAmount| 
+-------+---------+ 
|SB10001|    50000| 
|SB10002|    12000| 
|SB10003|     3000| 
|SB10004|     8500| 
|SB10005|     5000| 
+-------+---------+ 

> # Register temporary view definition in the DataFrame for SQL queries 
> createOrReplaceTempView(acBalDF, "balance") 
> # DataFrame containing account detail records using SQL by joining multiple DataFrame contents 
> acDetail <- sql("SELECT master.AccNo, FirstName, LastName, BalAmount FROM master, balance WHERE master.AccNo = balance.AccNo ORDER BY BalAmount DESC") 
> # Show sample records from the DataFrame 
> showDF(acDetail) 
+-------+---------+--------+---------+ 
|  AccNo|FirstName|LastName|BalAmount| 
+-------+---------+--------+---------+ 
|SB10001|    Roger| Federer|    50000| 
|SB10002|     Pete| Sampras|    12000| 
|SB10004|    Boris|  Becker|     8500| 
|SB10005|     Ivan|   Lendl|     5000| 
|SB10003|   Rafael|   Nadal|     3000| 
+-------+---------+--------+---------+ 

> # Persist data in the DataFrame into Parquet file 
> write.parquet(acDetail, "r.acdetails.parquet") 
> # Read data into a DataFrame by reading the contents from a Parquet file 

> acDetailFromFile <- read.parquet("r.acdetails.parquet") 
> # Show sample records from the DataFrame 
> showDF(acDetailFromFile) 
+-------+---------+--------+---------+ 
|  AccNo|FirstName|LastName|BalAmount| 
+-------+---------+--------+---------+ 
|SB10002|     Pete| Sampras|    12000| 
|SB10003|   Rafael|   Nadal|     3000| 
|SB10005|     Ivan|   Lendl|     5000| 
|SB10001|    Roger| Federer|    50000| 
|SB10004|    Boris|  Becker|     8500| 
+-------+---------+--------+---------+ 

```

在同一 R REPL 会话中，以下代码行通过 DataFrame API 获得相同结果：

```scala
> # Change the column names 
> acBalDFWithDiffColName <- selectExpr(acBalDF, "AccNo as AccNoBal", "BalAmount") 
> # Show sample records from the DataFrame 
> showDF(acBalDFWithDiffColName) 
+--------+---------+ 
|AccNoBal|BalAmount| 
+--------+---------+ 
| SB10001|    50000| 
| SB10002|    12000| 
| SB10003|     3000| 
| SB10004|     8500| 
| SB10005|     5000| 
+--------+---------+ 
> # DataFrame containing account detail records using API by joining multiple DataFrame contents 
> acDetailFromAPI <- join(acMasterDF, acBalDFWithDiffColName, acMasterDF$AccNo == acBalDFWithDiffColName$AccNoBal) 
> # Show sample records from the DataFrame 
> showDF(acDetailFromAPI) 
+-------+---------+--------+--------+---------+ 
|  AccNo|FirstName|LastName|AccNoBal|BalAmount| 
+-------+---------+--------+--------+---------+ 
|SB10001|    Roger| Federer| SB10001|    50000| 
|SB10002|     Pete| Sampras| SB10002|    12000| 
|SB10003|   Rafael|   Nadal| SB10003|     3000| 
|SB10004|    Boris|  Becker| SB10004|     8500| 
|SB10005|     Ivan|   Lendl| SB10005|     5000| 
+-------+---------+--------+--------+---------+ 
> # DataFrame containing account detail records using SQL by selecting specific fields 
> acDetailFromAPIRequiredFields <- select(acDetailFromAPI, "AccNo", "FirstName", "LastName", "BalAmount") 
> # Show sample records from the DataFrame 
> showDF(acDetailFromAPIRequiredFields) 
+-------+---------+--------+---------+ 
|  AccNo|FirstName|LastName|BalAmount| 
+-------+---------+--------+---------+ 
|SB10001|    Roger| Federer|    50000| 
|SB10002|     Pete| Sampras|    12000| 
|SB10003|   Rafael|   Nadal|     3000| 
|SB10004|    Boris|  Becker|     8500| 
|SB10005|     Ivan|   Lendl|     5000| 
+-------+---------+--------+---------+ 

```

前述代码段中选择的连接类型为内连接。实际上，可通过 SQL 查询方式或 DataFrame API 方式使用其他任何类型的连接。在使用 DataFrame API 进行连接前，需注意两个 Spark DataFrame 的列名必须不同，以避免结果 DataFrame 中的歧义。在此特定用例中，可以看出 DataFrame API 处理起来略显复杂，而 SQL 查询方式则显得非常直接。

在前述章节中，已涵盖 Spark SQL 的 R API。通常，若可能，应尽可能使用 SQL 查询方式编写代码。DataFrame API 正在改进，但与其他语言（如 Scala 或 Python）相比，其灵活性仍显不足。

与本书其他章节不同，本章是专为 R 程序员介绍 Spark 的独立章节。本章讨论的所有用例均在 Spark 的 R REPL 中运行。但在实际应用中，这种方法并不理想。R 命令需组织在脚本文件中，并提交至 Spark 集群运行。最简便的方法是使用现有的`$SPARK_HOME/bin/spark-submit <path to the R script file>`脚本，其中 R 文件名需相对于命令调用时的当前目录给出完整路径。

# 参考资料

更多信息，请参考：[`spark.apache.org/docs/latest/api/R/index.html`](https://spark.apache.org/docs/latest/api/R/index.html)

# 总结

本章涵盖了对 R 语言的快速概览，随后特别提到了需要明确理解 R DataFrame 与 Spark DataFrame 之间的区别。接着，使用与前几章相同的用例介绍了基本的 Spark 编程与 R。涵盖了 Spark 的 R API，并通过 SQL 查询方式和 DataFrame API 方式实现了用例。本章帮助数据科学家理解 Spark 的强大功能，并将其应用于他们的 R 应用程序中，使用随 Spark 附带的 SparkR 包。这为使用 Spark 与 R 处理结构化数据的大数据处理打开了大门。

关于基于 Spark 的数据处理在多种语言中的主题已经讨论过，现在是时候专注于一些数据分析以及图表和绘图了。Python 自带了许多能够生成出版质量图片的图表和绘图库。下一章将讨论使用 Spark 处理的数据进行图表和绘图。


# 第五章：Spark 与 Python 的数据分析

处理数据的最终目标是利用结果回答业务问题。理解用于回答业务问题的数据至关重要。为了更好地理解数据，采用了各种制表方法、图表和绘图技术。数据的可视化表示强化了对底层数据的理解。因此，数据可视化在数据分析中得到了广泛应用。

在各种出版物中，用于表示分析数据以回答业务问题的术语各不相同。数据分析、数据分析和商业智能是一些普遍存在的术语。本章不会深入讨论这些术语的含义、相似之处或差异。相反，重点将放在如何弥合数据科学家或数据分析师通常执行的两个主要活动之间的差距。第一个是数据处理。第二个是利用处理过的数据借助图表和绘图进行分析。数据分析是数据分析师和数据科学家的专长。本章将重点介绍使用 Spark 和 Python 处理数据，并生成图表和图形。

在许多数据分析用例中，处理一个超集数据，并将缩减后的结果数据集用于数据分析。在大数据分析中，这一点尤为正确，其中一小部分处理过的数据用于分析。根据用例，针对各种数据分析需求，作为前提条件进行适当的数据处理。本章将要涵盖的大多数用例都属于这种模式，其中第一步涉及必要的数据处理，第二步涉及数据分析所需的图表和绘图。

在典型的数据分析用例中，活动链涉及一个广泛且多阶段的**提取**、**转换**和**加载**（**ETL**）管道，最终形成一个数据分析平台或应用程序。这一系列活动链的最终结果包括但不限于汇总数据表以及以图表和图形形式呈现的各种数据可视化。由于 Spark 能非常有效地处理来自异构分布式数据源的数据，因此在传统数据分析应用中存在的庞大 ETL 管道可以整合为自包含的应用程序，进行数据处理和数据分析。

本章我们将探讨以下主题：

+   图表和绘图库

+   设置数据集

+   捕捉数据分析用例的高层次细节

+   各种图表和图形

# 图表和绘图库

Python 是当今数据分析师和数据科学家广泛使用的编程语言。有众多科学和统计数据处理库，以及图表和绘图库，可在 Python 程序中使用。Python 也广泛用于开发 Spark 中的数据处理应用程序。这为使用 Spark、Python 及其库实现统一的数据处理和分析框架提供了极大的灵活性，使我们能够进行科学和统计处理，以及图表和绘图。有许多与 Python 兼容的此类库。其中，**NumPy**和**SciPy**库在此用于数值、统计和科学数据处理。**matplotlib**库在此用于生成 2D 图像的图表和绘图。

### 提示

确保**NumPy**、**SciPy**和**matplotlib** Python 库与 Python 安装正常工作非常重要，然后再尝试本章给出的代码示例。这需要在将其用于 Spark 应用程序之前进行测试和验证。

如图*图 1*所示的框图给出了应用程序堆栈的整体结构：

![图表和绘图库](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-bg/img/image_05_002.jpg)

图 1

# 设置数据集

有许多公共数据集可供公众用于教育、研究和开发目的。MovieLens 网站允许用户对电影进行评分并个性化推荐。GroupLens Research 发布了来自 MovieLens 的评分数据集。这些数据集可从其网站[`grouplens.org/datasets/movielens/`](http://grouplens.org/datasets/movielens/)下载。本章使用 MovieLens 100K 数据集来演示如何结合 Python、NumPy、SciPy 和 matplotlib 使用 Spark 进行分布式数据处理。

### 提示

在 GroupLens Research 网站上，除了上述数据集外，还有更多庞大的数据集可供下载，如 MovieLens 1M 数据集、MovieLens 10M 数据集、MovieLens 20M 数据集以及 MovieLens 最新数据集。一旦读者对程序相当熟悉，并在处理数据时达到足够的舒适度，就可以利用这些额外数据集进行自己的分析工作，以巩固本章所获得的知识。

MovieLens 100K 数据集包含多个文件中的数据。以下是本章数据分析用例中将使用的文件：

+   `u.user`：关于对电影进行评分的用户的用户人口统计信息。数据集的结构如下所示，与数据集附带的 README 文件中复制的相同：

    +   用户 ID

    +   年龄

    +   性别

    +   职业

    +   邮政编码

+   `u.item`：关于用户评分的电影信息。数据集的结构如下所示，从随数据集提供的 README 文件中复制而来：

    +   电影 ID

    +   电影标题

    +   发行日期

    +   视频发行日期

    +   IMDb 链接

    +   未知类型

    +   动作片

    +   冒险片

    +   动画片

    +   儿童片

    +   喜剧片

    +   犯罪片

    +   纪录片

    +   剧情片

    +   奇幻片

    +   黑色电影

    +   恐怖片

    +   音乐片

    +   悬疑片

    +   爱情片

    +   科幻片

    +   惊悚片

    +   战争片

    +   西部片

# 数据分析用例

以下列表捕捉了数据分析用例的高级细节。大多数用例都围绕创建各种图表和图形展开：

+   使用直方图绘制对电影进行评分的用户的年龄分布。

+   使用与直方图相同的数据，绘制用户的年龄概率密度图。

+   绘制年龄分布数据的摘要，以找到用户的最低年龄、第 25 百分位数、中位数、第 75 百分位数和最高年龄。

+   在同一图上绘制多个图表或图形，以便对数据进行并排比较。

+   创建一个条形图，捕捉对电影进行评分的用户数量最多的前 10 个职业。

+   创建一个堆叠条形图，按职业显示对电影进行评分的男性和女性用户数量。

+   创建一个饼图，捕捉对电影进行评分的用户数量最少的 10 个职业。

+   创建一个圆环图，捕捉对电影进行评分的用户数量最多的前 10 个邮政编码。

+   使用三个职业类别，创建箱线图，捕捉对电影进行评分的用户的汇总统计信息。所有三个箱线图都必须在单个图上绘制，以便进行比较。

+   创建一个条形图，按电影类型捕捉电影数量。

+   创建一个散点图，捕捉每年发行电影数量最多的前 10 年。

+   创建一个散点图，捕捉每年发行电影数量最多的前 10 年。在这个图中，不是用点来表示，而是创建与该年发行电影数量成比例的圆形区域。

+   创建一条折线图，包含两个数据集，一个数据集是过去 10 年发行的动作片数量，另一个数据集是过去 10 年发行的剧情片数量，以便进行比较。

### 提示

在前述所有用例中，当涉及实施时，Spark 用于处理数据并准备所需的数据集。一旦所需的已处理数据在 Spark DataFrame 中可用，它就会被收集到驱动程序中。换句话说，数据从 Spark 的分布式集合转移到本地集合，在 Python 程序中作为元组，用于制图和绘图。对于制图和绘图，Python 需要本地数据。它不能直接使用 Spark DataFrames 进行制图和绘图。

# 图表和图形

本节将重点介绍创建各种图表和图形，以直观地表示与前述部分描述的用例相关的 MovieLens 100K 数据集的各个方面。本章描述的图表和图形绘制过程遵循一种模式。以下是该活动模式中的重要步骤：

1.  使用 Spark 从数据文件读取数据。

1.  使数据在 Spark DataFrame 中可用。

1.  使用 DataFrame API 应用必要的数据处理。

1.  处理主要是为了仅提供制图和绘图所需的最小和必要数据。

1.  将处理后的数据从 Spark DataFrame 传输到 Spark 驱动程序中的本地 Python 集合对象。

1.  使用图表和绘图库，利用 Python 集合对象中的数据生成图形。

## 直方图

直方图通常用于展示给定数值数据集在连续且不重叠的等宽区间上的分布情况。区间或箱宽的选择基于数据集。箱或区间代表数据的范围。在此用例中，数据集包含用户的年龄。在这种情况下，设置 100 的箱宽没有意义，因为只会得到一个箱，整个数据集都会落入其中。代表箱的条形的高度表示该箱或区间内数据项的频率。

以下命令集用于启动 Spark 的 Python REPL，随后是进行数据处理、制图和绘图的程序：

```scala
$ cd $SPARK_HOME
$ ./bin/pyspark
>>> # Import all the required libraries 
>>> from pyspark.sql import Row
>>> import matplotlib.pyplot as plt
>>> import numpy as np
>>> import matplotlib.pyplot as plt
>>> import pylab as P
>>> plt.rcdefaults()
>>> # TODO - The following location has to be changed to the appropriate data file location
>>> dataDir = "/Users/RajT/Documents/Writing/SparkForBeginners/SparkDataAnalysisWithPython/Data/ml-100k/">>> # Create the DataFrame of the user dataset
>>> lines = sc.textFile(dataDir + "u.user")
>>> splitLines = lines.map(lambda l: l.split("|"))
>>> usersRDD = splitLines.map(lambda p: Row(id=p[0], age=int(p[1]), gender=p[2], occupation=p[3], zipcode=p[4]))
>>> usersDF = spark.createDataFrame(usersRDD)
>>> usersDF.createOrReplaceTempView("users")
>>> usersDF.show()
      +---+------+---+-------------+-------+

      |age|gender| id|   occupation|zipcode|

      +---+------+---+-------------+-------+

      | 24|     M|  1|   technician|  85711|

      | 53|     F|  2|        other|  94043|

      | 23|     M|  3|       writer|  32067|

      | 24|     M|  4|   technician|  43537|

      | 33|     F|  5|        other|  15213|

      | 42|     M|  6|    executive|  98101|

      | 57|     M|  7|administrator|  91344|

      | 36|     M|  8|administrator|  05201|

      | 29|     M|  9|      student|  01002|

      | 53|     M| 10|       lawyer|  90703|

      | 39|     F| 11|        other|  30329|

      | 28|     F| 12|        other|  06405|

      | 47|     M| 13|     educator|  29206|

      | 45|     M| 14|    scientist|  55106|

      | 49|     F| 15|     educator|  97301|

      | 21|     M| 16|entertainment|  10309|

      | 30|     M| 17|   programmer|  06355|

      | 35|     F| 18|        other|  37212|

      | 40|     M| 19|    librarian|  02138|

      | 42|     F| 20|    homemaker|  95660|

      +---+------+---+-------------+-------+

      only showing top 20 rows
    >>> # Create the DataFrame of the user dataset with only one column age
	>>> ageDF = spark.sql("SELECT age FROM users")
	>>> ageList = ageDF.rdd.map(lambda p: p.age).collect()
	>>> ageDF.describe().show()
      +-------+------------------+

      |summary|               age|

      +-------+------------------+

      |  count|               943|

      |   mean| 34.05196182396607|

      | stddev|12.186273150937206|

      |    min|                 7|

      |    max|                73|

      +-------+------------------+
 >>> # Age distribution of the users
 >>> plt.hist(ageList)
 >>> plt.title("Age distribution of the users\n")
 >>> plt.xlabel("Age")
 >>> plt.ylabel("Number of users")
 >>> plt.show(block=False)

```

在前述部分，用户数据集被逐行读取以形成 RDD。从 RDD 创建了一个 Spark DataFrame。使用 Spark SQL，创建了另一个仅包含年龄列的 Spark DataFrame。显示了该 Spark DataFrame 的摘要，以展示内容的摘要统计信息；内容被收集到本地 Python 集合对象中。使用收集的数据，绘制了年龄列的直方图，如*图 2*所示：

![直方图](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-bg/img/image_05_003.jpg)

图 2

## 密度图

还有一种图表与直方图非常接近，那就是密度图。每当有有限的数据样本需要估计随机变量的概率密度函数时，密度图被广泛使用。直方图无法显示数据何时平滑或数据点何时连续。为此，使用密度图。

### 注意

由于直方图和密度图用于类似目的，但对相同数据表现出不同行为，通常，直方图和密度图在很多应用中并排使用。

*图 3*是为绘制直方图的同一数据集绘制的密度图。

在同一 Spark 的 Python REPL 中继续运行以下命令：

```scala
>>> # Draw a density plot
>>> from scipy.stats import gaussian_kde
>>> density = gaussian_kde(ageList)
>>> xAxisValues = np.linspace(0,100,1000)
>>> density.covariance_factor = lambda : .5
>>> density._compute_covariance()
>>> plt.title("Age density plot of the users\n")
>>> plt.xlabel("Age")
>>> plt.ylabel("Density")
>>> plt.plot(xAxisValues, density(xAxisValues))
>>> plt.show(block=False)

```

![密度图](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-bg/img/image_05_004.jpg)

图 3

在前一节中，使用了仅包含年龄列的同一 Spark DataFrame，并将内容收集到本地 Python 集合对象中。利用收集的数据，绘制了年龄列的密度图，如*图 3*所示，其中 0 到 100 的线间距代表年龄。

如果需要并排查看多个图表或图，**matplotlib**库提供了实现这一目的的方法。图 4 展示了并排的直方图和箱线图。

作为同一 Python REPL 的 Spark 的延续，运行以下命令：

```scala
>>> # The following example demonstrates the creation of multiple diagrams
        in one figure
		>>> # There are two plots on one row
		>>> # The first one is the histogram of the distribution 
		>>> # The second one is the boxplot containing the summary of the 
        distribution
		>>> plt.subplot(121)
		>>> plt.hist(ageList)
		>>> plt.title("Age distribution of the users\n")
		>>> plt.xlabel("Age")
		>>> plt.ylabel("Number of users")
		>>> plt.subplot(122)
		>>> plt.title("Summary of distribution\n")
		>>> plt.xlabel("Age")
		>>> plt.boxplot(ageList, vert=False)
		>>> plt.show(block=False)

```

![密度图](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-bg/img/image_05_005.jpg)

图 4

在前一节中，使用了仅包含年龄列的同一 Spark DataFrame，并将内容收集到本地 Python 集合对象中。利用收集的数据，绘制了年龄列的直方图以及包含最小值、第 25 百分位数、中位数、第 75 百分位数和最大值指示器的箱线图，如*图 4*所示。当在同一图形中绘制多个图表或图时，为了控制布局，请查看方法调用`plt.subplot(121)`。这是关于一行两列布局中图表选择的讨论，并选择了第一个。同样，`plt.subplot(122)`讨论了一行两列布局中的图表选择，并选择了第二个。

## 条形图

条形图可以以不同方式绘制。最常见的是条形垂直于*X*轴站立。另一种变体是条形绘制在*Y*轴上，条形水平排列。*图 5*展示了一个水平条形图。

### 注意

人们常常混淆直方图和条形图。重要的区别在于，直方图用于绘制连续但有限的数值，而条形图用于表示分类数据。

作为同一 Python REPL 的 Spark 的延续，运行以下命令：

```scala
>>> occupationsTop10 = spark.sql("SELECT occupation, count(occupation) as usercount FROM users GROUP BY occupation ORDER BY usercount DESC LIMIT 10")
>>> occupationsTop10.show()
      +-------------+---------+

      |   occupation|usercount|

      +-------------+---------+

      |      student|      196|

      |        other|      105|

      |     educator|       95|

      |administrator|       79|

      |     engineer|       67|

      |   programmer|       66|

      |    librarian|       51|

      |       writer|       45|

      |    executive|       32|

      |    scientist|       31|

      +-------------+---------+
	  >>> occupationsTop10Tuple = occupationsTop10.rdd.map(lambda p:
	  (p.occupation,p.usercount)).collect()
	  >>> occupationsTop10List, countTop10List = zip(*occupationsTop10Tuple)
	  >>> occupationsTop10Tuple
	  >>> # Top 10 occupations in terms of the number of users having that
	  occupation who have rated movies
	  >>> y_pos = np.arange(len(occupationsTop10List))
	  >>> plt.barh(y_pos, countTop10List, align='center', alpha=0.4)
	  >>> plt.yticks(y_pos, occupationsTop10List)
	  >>> plt.xlabel('Number of users')
	  >>> plt.title('Top 10 user types\n')
	  >>> plt.gcf().subplots_adjust(left=0.15)
	  >>> plt.show(block=False)

```

![条形图](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-bg/img/image_05_006.jpg)

图 5

在前一节中，创建了一个 Spark DataFrame，其中包含按用户评分电影数量排名的前 10 种职业。数据被收集到一个 Python 集合对象中，用于绘制条形图。

### 堆叠条形图

在前一节中绘制的条形图展示了按用户数量排名的前 10 种用户职业。但这并未提供关于该数字如何按用户性别构成的详细信息。在这种情况下，使用堆叠条形图是很好的选择，每个条形图显示按性别统计的数量。*图 6*展示了一个堆叠条形图。

作为同一 Python REPL 的 Spark 的延续，运行以下命令：

```scala
>>> occupationsGender = spark.sql("SELECT occupation, gender FROM users")>>> occupationsGender.show()
      +-------------+------+

      |   occupation|gender|

      +-------------+------+

      |   technician|     M|

      |        other|     F|

      |       writer|     M|

      |   technician|     M|

      |        other|     F|

      |    executive|     M|

      |administrator|     M|

      |administrator|     M|

      |      student|     M|

      |       lawyer|     M|

      |        other|     F|

      |        other|     F|

      |     educator|     M|

      |    scientist|     M|

      |     educator|     F|

      |entertainment|     M|

      |   programmer|     M|

      |        other|     F|

      |    librarian|     M|

      |    homemaker|     F|

      +-------------+------+

      only showing top 20 rows
    >>> occCrossTab = occupationsGender.stat.crosstab("occupation", "gender")>>> occCrossTab.show()
      +-----------------+---+---+

      |occupation_gender|  M|  F|

      +-----------------+---+---+

      |        scientist| 28|  3|

      |          student|136| 60|

      |           writer| 26| 19|

      |         salesman|  9|  3|

      |          retired| 13|  1|

      |    administrator| 43| 36|

      |       programmer| 60|  6|

      |           doctor|  7|  0|

      |        homemaker|  1|  6|

      |        executive| 29|  3|

      |         engineer| 65|  2|

      |    entertainment| 16|  2|

      |        marketing| 16| 10|

      |       technician| 26|  1|

      |           artist| 15| 13|

      |        librarian| 22| 29|

      |           lawyer| 10|  2|

      |         educator| 69| 26|

      |       healthcare|  5| 11|

      |             none|  5|  4|

      +-----------------+---+---+

      only showing top 20 rows
      >>> occupationsCrossTuple = occCrossTab.rdd.map(lambda p:
	 (p.occupation_gender,p.M, p.F)).collect()
	 >>> occList, mList, fList = zip(*occupationsCrossTuple)
	 >>> N = len(occList)
	 >>> ind = np.arange(N) # the x locations for the groups
	 >>> width = 0.75 # the width of the bars
	 >>> p1 = plt.bar(ind, mList, width, color='r')
	 >>> p2 = plt.bar(ind, fList, width, color='y', bottom=mList)
	 >>> plt.ylabel('Count')
	 >>> plt.title('Gender distribution by occupation\n')
	 >>> plt.xticks(ind + width/2., occList, rotation=90)
	 >>> plt.legend((p1[0], p2[0]), ('Male', 'Female'))
	 >>> plt.gcf().subplots_adjust(bottom=0.25)
	 >>> plt.show(block=False)

```

![堆叠条形图](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-bg/img/image_05_007.jpg)

图 6

在前述部分中，创建了一个仅包含职业和性别列的 Spark DataFrame。对其实施了交叉表操作，生成了另一个 Spark DataFrame，该 DataFrame 包含了职业、男性用户数和女性用户数列。在最初的 Spark DataFrame 中，职业和性别列均为非数值列，因此基于这些数据绘制图表或图形并无意义。但若对这两列的值进行交叉表操作，针对每个不同的职业字段，性别列的值计数将得以呈现。如此一来，职业字段便成为了一个分类变量，此时绘制条形图便合乎逻辑。鉴于数据中仅有两种性别值，采用堆叠条形图既能显示总数，又能展示各职业类别中男女用户数的比例，显得合情合理。

在 Spark DataFrame 中，有许多统计和数学函数可供使用。在这种情境下，交叉表操作显得尤为便捷。对于庞大的数据集，交叉表操作可能会非常耗费处理器资源和时间，但 Spark 的分布式处理能力在此类情况下提供了极大的帮助。

Spark SQL 具备丰富的数学和统计数据处理功能。前述部分使用了`SparkDataFrame`对象上的`describe().show()`方法。在这些 Spark DataFrames 中，该方法作用于现有的数值列。在存在多个数值列的情况下，该方法能够选择所需的列以获取汇总统计信息。同样，也有方法可以计算来自 Spark DataFrame 的数据的协方差、相关性等。以下代码片段展示了这些方法：

```scala
>>> occCrossTab.describe('M', 'F').show()
      +-------+------------------+------------------+

      |summary|                 M|                 F|

      +-------+------------------+------------------+

      |  count|                21|                21|

      |   mean|31.904761904761905|              13.0|

      | stddev|31.595516200735347|15.491933384829668|

      |    min|                 1|                 0|

      |    max|               136|                60|

      +-------+------------------+------------------+
    >>> occCrossTab.stat.cov('M', 'F')
      381.15
    >>> occCrossTab.stat.corr('M', 'F')
      0.7416099517313641 

```

## 饼图

若需通过视觉手段展示数据集以阐明整体与部分的关系，饼图是常用的选择。*图 7*展示了一个饼图。

在同一 Python REPL 的 Spark 会话中，执行以下命令：

```scala
>>> occupationsBottom10 = spark.sql("SELECT occupation, count(occupation) as usercount FROM users GROUP BY occupation ORDER BY usercount LIMIT 10")
>>> occupationsBottom10.show()
      +-------------+---------+

      |   occupation|usercount|

      +-------------+---------+

      |    homemaker|        7|

      |       doctor|        7|

      |         none|        9|

      |     salesman|       12|

      |       lawyer|       12|

      |      retired|       14|

      |   healthcare|       16|

      |entertainment|       18|

      |    marketing|       26|

      |   technician|       27|

      +-------------+---------+
    >>> occupationsBottom10Tuple = occupationsBottom10.rdd.map(lambda p: (p.occupation,p.usercount)).collect()
	>>> occupationsBottom10List, countBottom10List = zip(*occupationsBottom10Tuple)
	>>> # Bottom 10 occupations in terms of the number of users having that occupation who have rated movies
	>>> explode = (0, 0, 0, 0,0.1,0,0,0,0,0.1)
	>>> plt.pie(countBottom10List, explode=explode, labels=occupationsBottom10List, autopct='%1.1f%%', shadow=True, startangle=90)
	>>> plt.title('Bottom 10 user types\n')
	>>> plt.show(block=False)

```

![饼图](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-bg/img/image_05_008.jpg)

*图 7*

在前述部分中，创建了一个 Spark DataFrame，其中包含了用户按评分电影数量排名的底部 10 种职业。数据被收集到一个 Python 集合对象中，以便绘制饼图。

### 环形图

饼图可以有多种绘制形式。其中一种形式，即环形图，近年来颇受欢迎。*图 8*展示了这种饼图的环形图变体。

在同一 Python REPL 的 Spark 会话中，执行以下命令：

```scala
>>> zipTop10 = spark.sql("SELECT zipcode, count(zipcode) as usercount FROM users GROUP BY zipcode ORDER BY usercount DESC LIMIT 10")
>>> zipTop10.show()
      +-------+---------+

      |zipcode|usercount|

      +-------+---------+

      |  55414|        9|

      |  55105|        6|

      |  20009|        5|

      |  55337|        5|

      |  10003|        5|

      |  55454|        4|

      |  55408|        4|

      |  27514|        4|

      |  11217|        3|

      |  14216|        3|

      +-------+---------+
    >>> zipTop10Tuple = zipTop10.rdd.map(lambda p: (p.zipcode,p.usercount)).collect()
	>>> zipTop10List, countTop10List = zip(*zipTop10Tuple)
	>>> # Top 10 zipcodes in terms of the number of users living in that zipcode who have rated movies>>> explode = (0.1, 0, 0, 0,0,0,0,0,0,0)  # explode a slice if required
	>>> plt.pie(countTop10List, explode=explode, labels=zipTop10List, autopct='%1.1f%%', shadow=True)
	>>> #Draw a circle at the center of pie to make it look like a donut
	>>> centre_circle = plt.Circle((0,0),0.75,color='black', fc='white',linewidth=1.25)
	>>> fig = plt.gcf()
	>>> fig.gca().add_artist(centre_circle)
	>>> # The aspect ratio is to be made equal. This is to make sure that pie chart is coming perfectly as a circle.
	>>> plt.axis('equal')
	>>> plt.text(- 0.25,0,'Top 10 zip codes')
	>>> plt.show(block=False)

```

![环形图](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-bg/img/image_05_009.jpg)

*图 8*

在前面的部分中，创建了一个包含用户居住地区和评价电影的用户数量最多的前 10 个邮政编码的 Spark DataFrame。数据被收集到一个 Python 集合对象中以绘制圆环图。

### 提示

与其他图表相比，*图 8*的标题位于中间。这是使用`text()`方法而不是`title()`方法完成的。此方法可用于在图表和绘图上打印水印文本。

## 箱形图

在单个图表中比较不同数据集的汇总统计信息是一个常见需求。箱形图是一种常用的图表，用于直观地捕捉数据集的汇总统计信息。接下来的部分正是这样做的，*图 9*展示了单个图表上的多个箱形图。

在同一 Python REPL 的 Spark 中继续，运行以下命令：

```scala
>>> ages = spark.sql("SELECT occupation, age FROM users WHERE occupation ='administrator' ORDER BY age")
>>> adminAges = ages.rdd.map(lambda p: p.age).collect()
>>> ages.describe().show()
      +-------+------------------+

      |summary|               age|

      +-------+------------------+

      |  count|                79|

      |   mean| 38.74683544303797|

      | stddev|11.052771408491363|

      |    min|                21|

      |    max|                70|

      +-------+------------------+
    >>> ages = spark.sql("SELECT occupation, age FROM users WHERE occupation ='engineer' ORDER BY age")>>> engAges = ages.rdd.map(lambda p: p.age).collect()
	>>> ages.describe().show()
      +-------+------------------+

      |summary|               age|

      +-------+------------------+

      |  count|                67|

      |   mean| 36.38805970149254|

      | stddev|11.115345348003853|

      |    min|                22|

      |    max|                70|

      +-------+------------------+
    >>> ages = spark.sql("SELECT occupation, age FROM users WHERE occupation ='programmer' ORDER BY age")>>> progAges = ages.rdd.map(lambda p: p.age).collect()
	>>> ages.describe().show()
      +-------+------------------+

      |summary|               age|

      +-------+------------------+

      |  count|                66|

      |   mean|33.121212121212125|

      | stddev| 9.551320948648684|

      |    min|                20|

      |    max|                63|

      +-------+------------------+
 >>> # Box plots of the ages by profession
 >>> boxPlotAges = [adminAges, engAges, progAges]
 >>> boxPlotLabels = ['administrator','engineer', 'programmer' ]
 >>> x = np.arange(len(boxPlotLabels))
 >>> plt.figure()
 >>> plt.boxplot(boxPlotAges)
 >>> plt.title('Age summary statistics\n')
 >>> plt.ylabel("Age")
 >>> plt.xticks(x + 1, boxPlotLabels, rotation=0)
 >>> plt.show(block=False)

```

![箱形图](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-bg/img/image_05_010.jpg)

图 9

在前面的部分中，使用职业和年龄列为管理员、工程师和程序员三种职业创建了一个 Spark DataFrame。在一张图上为每个数据集创建了箱形图，该图包含每个数据集的最小值、第 25 百分位数、中位数、第 75 百分位数、最大值和异常值的指示器，以便于比较。程序员职业的箱形图显示了两个由`+`符号表示的值点。它们是异常值。

## 垂直条形图

在前面的部分中，用于引出各种图表和绘图用例的主要数据集是用户数据。接下来要处理的数据集是电影数据集。在许多数据集中，为了制作各种图表和绘图，需要对数据进行适当的处理以适应相应的图表。Spark 提供了丰富的功能来进行数据处理。

下面的用例展示了通过应用一些聚合并使用 Spark SQL 来准备数据，为包含按类型统计电影数量的经典条形图准备了所需的数据集。*图 10*展示了在电影数据上应用聚合操作后的条形图。

在同一 Python REPL 的 Spark 中继续，运行以下命令：

```scala
>>> movieLines = sc.textFile(dataDir + "u.item")
>>> splitMovieLines = movieLines.map(lambda l: l.split("|"))
>>> moviesRDD = splitMovieLines.map(lambda p: Row(id=p[0], title=p[1], releaseDate=p[2], videoReleaseDate=p[3], url=p[4], unknown=int(p[5]),action=int(p[6]),adventure=int(p[7]),animation=int(p[8]),childrens=int(p[9]),comedy=int(p[10]),crime=int(p[11]),documentary=int(p[12]),drama=int(p[13]),fantasy=int(p[14]),filmNoir=int(p[15]),horror=int(p[16]),musical=int(p[17]),mystery=int(p[18]),romance=int(p[19]),sciFi=int(p[20]),thriller=int(p[21]),war=int(p[22]),western=int(p[23])))
>>> moviesDF = spark.createDataFrame(moviesRDD)
>>> moviesDF.createOrReplaceTempView("movies")
>>> genreDF = spark.sql("SELECT sum(unknown) as unknown, sum(action) as action,sum(adventure) as adventure,sum(animation) as animation, sum(childrens) as childrens,sum(comedy) as comedy,sum(crime) as crime,sum(documentary) as documentary,sum(drama) as drama,sum(fantasy) as fantasy,sum(filmNoir) as filmNoir,sum(horror) as horror,sum(musical) as musical,sum(mystery) as mystery,sum(romance) as romance,sum(sciFi) as sciFi,sum(thriller) as thriller,sum(war) as war,sum(western) as western FROM movies")
>>> genreList = genreDF.collect()
>>> genreDict = genreList[0].asDict()
>>> labelValues = list(genreDict.keys())
>>> countList = list(genreDict.values())
>>> genreDict
      {'animation': 42, 'adventure': 135, 'romance': 247, 'unknown': 2, 'musical': 56, 'western': 27, 'comedy': 505, 'drama': 725, 'war': 71, 'horror': 92, 'mystery': 61, 'fantasy': 22, 'childrens': 122, 'sciFi': 101, 'filmNoir': 24, 'action': 251, 'documentary': 50, 'crime': 109, 'thriller': 251}
    >>> # Movie types and the counts
	>>> x = np.arange(len(labelValues))
	>>> plt.title('Movie types\n')
	>>> plt.ylabel("Count")
	>>> plt.bar(x, countList)
	>>> plt.xticks(x + 0.5, labelValues, rotation=90)
	>>> plt.gcf().subplots_adjust(bottom=0.20)
	>>> plt.show(block=False)

```

![垂直条形图](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-bg/img/image_05_011.jpg)

图 10

在前面的部分中，使用电影数据集创建了一个 `SparkDataFrame`。电影类型被捕获在单独的列中。在整个数据集中，使用 Spark SQL 进行了聚合，创建了一个新的 `SparkDataFrame` 摘要，并将数据值收集到一个 Python 集合对象中。由于数据集中列太多，使用了一个 Python 函数将这种数据结构转换为包含列名作为键和选定单行值作为键值的词典对象。从该词典中，创建了两个数据集，并绘制了一个条形图。

### 提示

在使用 Spark 进行数据分析应用开发时，Python 几乎肯定会用到许多图表和图形。与其尝试在本章中给出的所有代码示例在 Spark 的 Python REPL 中运行，不如使用 IPython 笔记本作为 IDE，以便代码和结果可以一起查看。本书的下载部分包含一个包含所有这些代码和结果的 IPython 笔记本。读者可以直接开始使用它。

## 散点图

散点图常用于绘制具有两个变量的值，例如笛卡尔空间中的一个点，它具有`X`值和`Y`值。在本电影数据集中，某一年发布的电影数量就表现出这种特性。在散点图中，通常`X`坐标和`Y`坐标的交点处表示的值是点。由于近期技术的发展和高级图形包的可用性，许多人使用不同的形状和颜色来表示这些点。在下面的散点图中，如*图 11*所示，使用了具有统一面积和随机颜色的小圆圈来表示这些值。当采用这些直观且巧妙的技术在散点图中表示点时，必须确保它不会违背散点图的初衷，也不会失去散点图传达数据行为所提供的简洁性。简单而优雅的形状，不会使笛卡尔空间显得杂乱，是这种非点表示值的理想选择。

在同一 Python REPL 中继续使用 Spark，运行以下命令：

```scala
>>> yearDF = spark.sql("SELECT substring(releaseDate,8,4) as releaseYear, count(*) as movieCount FROM movies GROUP BY substring(releaseDate,8,4) ORDER BY movieCount DESC LIMIT 10")
>>> yearDF.show()
      +-----------+----------+

      |releaseYear|movieCount|

      +-----------+----------+

      |       1996|       355|

      |       1997|       286|

      |       1995|       219|

      |       1994|       214|

      |       1993|       126|

      |       1998|        65|

      |       1992|        37|

      |       1990|        24|

      |       1991|        22|

      |       1986|        15|

      +-----------+----------+
    >>> yearMovieCountTuple = yearDF.rdd.map(lambda p: (int(p.releaseYear),p.movieCount)).collect()
	>>> yearList,movieCountList = zip(*yearMovieCountTuple)
	>>> countArea = yearDF.rdd.map(lambda p: np.pi * (p.movieCount/15)**2).collect()
	>>> plt.title('Top 10 movie release by year\n')
	>>> plt.xlabel("Year")
	>>> plt.ylabel("Number of movies released")
	>>> plt.ylim([0,max(movieCountList) + 20])
	>>> colors = np.random.rand(10)
	>>> plt.scatter(yearList, movieCountList,c=colors)
	>>> plt.show(block=False)

```

![散点图](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-bg/img/image_05_012.jpg)

图 11

在前一节中，使用了一个`SparkDataFrame`来收集按电影发布数量排名的前 10 年，并将这些值收集到一个 Python 集合对象中，并绘制了一个散点图。

### 增强型散点图

*图 11*是一个非常简单而优雅的散点图，但它并没有真正传达出与同一空间中其他值相比，给定绘制值的比较行为。为此，与其将点表示为固定半径的圆，不如将点绘制为面积与值成比例的圆，这将提供一个不同的视角。图 12 将展示具有相同数据但用面积与值成比例的圆来表示点的散点图。

在同一 Python REPL 中继续使用 Spark，运行以下命令：

```scala
>>> # Top 10 years where the most number of movies have been released
>>> plt.title('Top 10 movie release by year\n')
>>> plt.xlabel("Year")
>>> plt.ylabel("Number of movies released")
>>> plt.ylim([0,max(movieCountList) + 100])
>>> colors = np.random.rand(10)
>>> plt.scatter(yearList, movieCountList,c=colors, s=countArea)
>>> plt.show(block=False)

```

![增强型散点图](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-bg/img/image_05_013.jpg)

图 12

在前一节中，使用相同的数据集为*图 11*绘制了相同的散点图。与使用统一面积的圆圈绘制点不同，这些点是用面积与值成比例的圆圈绘制的。

### 提示

在这些代码示例中，图表和图形都是通过 show 方法展示的。matplotlib 中有方法可以将生成的图表和图形保存到磁盘，这些图表和图形可用于电子邮件发送、发布到仪表板等。

## 折线图

散点图与折线图之间存在相似之处。散点图非常适合表示单个数据点，但将所有点放在一起可以显示趋势。折线图也代表单个数据点，但这些点是相连的。这对于观察从一个点到另一个点的过渡非常理想。在一张图中，可以绘制多个折线图，便于比较两个数据集。前面的用例使用散点图来表示几年内发行的电影数量。这些数字只是绘制在一张图上的离散数据点。如果需要查看多年来电影发行的趋势，折线图是理想的选择。同样，如果需要比较两个不同类型电影的发行情况，则可以为每个类型使用一条线，并将两者都绘制在单个折线图上。*图 13*是一个包含多个数据集的折线图。

作为同一 Python REPL 会话中 Spark 的延续，运行以下命令：

```scala
>>> yearActionDF = spark.sql("SELECT substring(releaseDate,8,4) as actionReleaseYear, count(*) as actionMovieCount FROM movies WHERE action = 1 GROUP BY substring(releaseDate,8,4) ORDER BY actionReleaseYear DESC LIMIT 10")
>>> yearActionDF.show()
      +-----------------+----------------+

      |actionReleaseYear|actionMovieCount|

      +-----------------+----------------+

      |             1998|              12|

      |             1997|              46|

      |             1996|              44|

      |             1995|              40|

      |             1994|              30|

      |             1993|              20|

      |             1992|               8|

      |             1991|               2|

      |             1990|               7|

      |             1989|               6|

      +-----------------+----------------+
    >>> yearActionDF.createOrReplaceTempView("action")
	>>> yearDramaDF = spark.sql("SELECT substring(releaseDate,8,4) as dramaReleaseYear, count(*) as dramaMovieCount FROM movies WHERE drama = 1 GROUP BY substring(releaseDate,8,4) ORDER BY dramaReleaseYear DESC LIMIT 10")
	>>> yearDramaDF.show()
      +----------------+---------------+

      |dramaReleaseYear|dramaMovieCount|

      +----------------+---------------+

      |            1998|             33|

      |            1997|            113|

      |            1996|            170|

      |            1995|             89|

      |            1994|             97|

      |            1993|             64|

      |            1992|             14|

      |            1991|             11|

      |            1990|             12|

      |            1989|              8|

      +----------------+---------------+
    >>> yearDramaDF.createOrReplaceTempView("drama")
	>>> yearCombinedDF = spark.sql("SELECT a.actionReleaseYear as releaseYear, a.actionMovieCount, d.dramaMovieCount FROM action a, drama d WHERE a.actionReleaseYear = d.dramaReleaseYear ORDER BY a.actionReleaseYear DESC LIMIT 10")
	>>> yearCombinedDF.show()
      +-----------+----------------+---------------+

      |releaseYear|actionMovieCount|dramaMovieCount|

      +-----------+----------------+---------------+

      |       1998|              12|             33|

      |       1997|              46|            113|

      |       1996|              44|            170|

      |       1995|              40|             89|

      |       1994|              30|             97|

      |       1993|              20|             64|

      |       1992|               8|             14|

      |       1991|               2|             11|

      |       1990|               7|             12|

      |       1989|               6|              8|

      +-----------+----------------+---------------+
   >>> yearMovieCountTuple = yearCombinedDF.rdd.map(lambda p: (p.releaseYear,p.actionMovieCount, p.dramaMovieCount)).collect()
   >>> yearList,actionMovieCountList,dramaMovieCountList = zip(*yearMovieCountTuple)
   >>> plt.title("Movie release by year\n")
   >>> plt.xlabel("Year")
   >>> plt.ylabel("Movie count")
   >>> line_action, = plt.plot(yearList, actionMovieCountList)
   >>> line_drama, = plt.plot(yearList, dramaMovieCountList)
   >>> plt.legend([line_action, line_drama], ['Action Movies', 'Drama Movies'],loc='upper left')
   >>> plt.gca().get_xaxis().get_major_formatter().set_useOffset(False)
   >>> plt.show(block=False)

```

![折线图](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-bg/img/image_05_014.jpg)

图 13

在前一部分中，创建了 Spark DataFrames 以获取过去 10 年中动作电影和剧情电影的发行数据集。数据被收集到 Python 集合对象中，并在同一图像中绘制了折线图。

Python 结合 matplotlib 库，在生成出版质量的图表和图形方面非常丰富。Spark 可以作为处理来自异构数据源的数据的工具，并且结果也可以保存为多种数据格式。

那些熟悉 Python 数据分析库**pandas**的人会发现本章内容易于理解，因为 Spark DataFrames 的设计灵感来源于 R DataFrame 以及**pandas**。

本章仅涵盖了使用**matplotlib**库可以创建的几种示例图表和图形。本章的主要目的是帮助读者理解将此库与 Spark 结合使用的能力，其中 Spark 负责数据处理，而**matplotlib**负责图表和图形的绘制。

本章使用的数据文件是从本地文件系统读取的。除此之外，它也可以从 HDFS 或任何其他 Spark 支持的数据源读取。

当使用 Spark 作为数据处理的主要框架时，最重要的是要记住，任何可能的数据处理都应该由 Spark 完成，主要是因为 Spark 能以最佳方式进行数据处理。只有经过处理的数据才会返回给 Spark 驱动程序，用于绘制图表和图形。

# 参考文献

如需更多信息，请参考以下链接：

+   [`www.numpy.org/`](http://www.numpy.org/)

+   [`www.scipy.org/`](http://www.scipy.org/)

+   [`matplotlib.org/`](http://matplotlib.org/)

+   [`movielens.org/`](https://movielens.org/)

+   [`grouplens.org/datasets/movielens/`](http://grouplens.org/datasets/movielens/)

+   [`pandas.pydata.org/`](http://pandas.pydata.org/)

# 总结

处理后的数据用于数据分析。数据分析需要对处理后的数据有深入的理解。图表和绘图增强了理解底层数据特征的能力。本质上，对于一个数据分析应用来说，数据处理、制图和绘图是必不可少的。本章涵盖了使用 Python 与 Spark 结合，以及 Python 制图和绘图库，来开发数据分析应用的内容。

在大多数组织中，业务需求推动了构建涉及实时数据摄取的数据处理应用的需求，这些数据以各种形式和形态，以极高的速度涌入。这要求对流入组织数据池的数据流进行处理。下一章将讨论 Spark Streaming，这是一个建立在 Spark 之上的库，能够处理各种类型的数据流。


# 第六章：Spark 流处理

数据处理用例主要可以分为两种类型。第一种类型是数据静态，处理作为一个工作单元或分成更小的批次进行。在数据处理过程中，底层数据集不会改变，也不会有新的数据集添加到处理单元中。这是批处理。

第二种类型是数据像流水一样生成，处理随着数据生成而进行。这就是流处理。在本书的前几章中，所有数据处理用例都属于前一种类型。本章将关注后者。

本章我们将涵盖以下主题：

+   数据流处理

+   微批数据处理

+   日志事件处理器

+   窗口数据处理及其他选项

+   Kafka 流处理

+   使用 Spark 进行流作业

# 数据流处理

数据源生成数据如同流水，许多现实世界的用例要求它们实时处理。*实时*的含义因用例而异。定义特定用例中实时含义的主要参数是，从上次间隔以来摄取的数据或频繁间隔需要多快处理。例如，当重大体育赛事进行时，消费比分事件并将其发送给订阅用户的应用程序应尽可能快地处理数据。发送得越快，效果越好。

但这里的*快*是什么定义呢？在比分事件发生后一小时内处理比分数据是否可以？可能不行。在比分事件发生后一分钟内处理数据是否可以？这肯定比一小时内处理要好。在比分事件发生后一秒内处理数据是否可以？可能可以，并且比之前的数据处理时间间隔要好得多。

在任何数据流处理用例中，这个时间间隔都非常重要。数据处理框架应具备在自选的适当时间间隔内处理数据流的能力，以提供良好的商业价值。

当以自选的常规间隔处理流数据时，数据从时间间隔的开始收集到结束，分组为微批，并对该批数据进行数据处理。在较长时间内，数据处理应用程序将处理许多这样的微批数据。在这种类型的处理中，数据处理应用程序在给定时间点只能看到正在处理的特定微批。换句话说，应用程序对已经处理的微批数据没有任何可见性或访问权限。

现在，这种处理类型还有另一个维度。假设给定的用例要求每分钟处理数据，但在处理给定的微批数据时，需要查看过去 15 分钟内已处理的数据。零售银行交易处理应用程序的欺诈检测模块是这种特定业务需求的良好示例。毫无疑问，零售银行交易应在发生后的毫秒内进行处理。在处理 ATM 现金提取交易时，查看是否有人试图连续提取现金，如果发现，发送适当的警报是一个好主意。为此，在处理给定的现金提取交易时，应用程序检查在过去 15 分钟内是否从同一 ATM 使用同一张卡进行了任何其他现金提取。业务规则是在过去 15 分钟内此类交易超过两次时发送警报。在此用例中，欺诈检测应用程序应该能够查看过去 15 分钟内发生的所有交易。

一个好的流数据处理框架应该具有在任何给定时间间隔内处理数据的能力，以及在滑动时间窗口内查看已摄取数据的能力。在 Spark 之上工作的 Spark Streaming 库是具有这两种能力的最佳数据流处理框架之一。

再次查看*图 1*中给出的 Spark 库堆栈的全貌，以设置上下文并了解正在讨论的内容，然后再深入探讨和处理用例。

![数据流处理](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-bg/img/image_06_001.jpg)

图 1

# 微批处理数据处理

每个 Spark Streaming 数据处理应用程序将持续运行，直到被终止。该应用程序将不断*监听*数据源以接收传入的数据流。Spark Streaming 数据处理应用程序将有一个配置的批处理间隔。在每个批处理间隔结束时，它将产生一个名为**离散流**（**DStream**）的数据抽象，该抽象与 Spark 的 RDD 非常相似。与 RDD 一样，DStream 支持常用 Spark 转换和 Spark 操作的等效方法。

### 提示

正如 RDD 一样，DStream 也是不可变的和分布式的。

*图 2*展示了在 Spark Streaming 数据处理应用程序中 DStreams 是如何产生的。

![微批处理数据处理](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-bg/img/image_06_004.jpg)

图 2

*图 2*描绘了 Spark Streaming 应用程序最重要的元素。对于配置的批处理间隔，应用程序产生一个 DStream。每个 DStream 是一个由该批处理间隔内收集的数据组成的 RDD 集合。对于给定的批处理间隔，DStream 中的 RDD 数量会有所不同。

### 提示

由于 Spark Streaming 应用程序是持续运行的应用程序，用于收集数据，本章中，我们不再通过 REPL 运行代码，而是讨论完整的应用程序，包括编译、打包和运行的指令。

Spark 编程模型已在第二章，*Spark 编程模型*中讨论。

## 使用 DStreams 进行编程

在 Spark Streaming 数据处理应用程序中使用 DStreams 也遵循非常相似的模式，因为 DStreams 由一个或多个 RDD 组成。当对 DStream 调用诸如 Spark 转换或 Spark 操作等方法时，相应的操作将应用于构成 DStream 的所有 RDD。

### 注意

这里需要注意的是，并非所有适用于 RDD 的 Spark 转换和 Spark 操作都适用于 DStreams。另一个显著的变化是不同编程语言之间的能力差异。

Spark Streaming 的 Scala 和 Java API 在支持 Spark Streaming 数据处理应用程序开发的特性数量上领先于 Python API。

*图 3*展示了应用于 DStream 的方法如何应用于底层 RDDs。在使用 DStreams 上的任何方法之前，应查阅 Spark Streaming 编程指南。Spark Streaming 编程指南在 Python API 与其 Scala 或 Java 对应部分存在差异的地方，用特殊标注包含文本*Python API*。

假设在 Spark Streaming 数据处理应用程序的给定批次间隔内，生成一个包含多个 RDD 的 DStream。当对该 DStream 应用过滤方法时，以下是其如何转换为底层 RDDs 的过程。*图 3*显示了对包含两个 RDD 的 DStream 应用过滤转换，由于过滤条件，结果生成仅包含一个 RDD 的另一个 DStream。

![使用 DStreams 进行编程](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-bg/img/image_06_003.jpg)

图 3

# 日志事件处理器

如今，许多企业普遍拥有一个中央应用程序日志事件存储库。此外，这些日志事件被实时流式传输到数据处理应用程序，以便实时监控运行应用程序的性能，从而及时采取补救措施。本节将讨论这样一个用例，以展示使用 Spark Streaming 数据处理应用程序对日志事件进行实时处理。在此用例中，实时应用程序日志事件被写入 TCP 套接字。Spark Streaming 数据处理应用程序持续监听给定主机上的特定端口，以收集日志事件流。

## 准备 Netcat 服务器

这里使用大多数 UNIX 安装附带的 Netcat 实用程序作为数据服务器。为了确保系统中安装了 Netcat，请按照以下脚本中的手动命令操作，退出后运行它，并确保没有错误消息。一旦服务器启动并运行，在 Netcat 服务器控制台的标准输入中输入的内容将被视为应用程序日志事件，以简化演示目的。从终端提示符运行的以下命令将在 localhost 端口`9999`上启动 Netcat 数据服务器：

```scala
$ man nc
 NC(1)          BSD General Commands Manual
NC(1) 
NAME
     nc -- arbitrary TCP and UDP connections and listens 
SYNOPSIS
     nc [-46AcDCdhklnrtUuvz] [-b boundif] [-i interval] [-p source_port] [-s source_ip_address] [-w timeout] [-X proxy_protocol] [-x proxy_address[:port]]
        [hostname] [port[s]]
 DESCRIPTION
     The nc (or netcat) utility is used for just about anything under the sun involving TCP or UDP.  It can open TCP connections, send UDP packets, listen on
     arbitrary TCP and UDP ports, do port scanning, and deal with both IPv4 and IPv6.  Unlike telnet(1), nc scripts nicely, and separates error messages onto
     standard error instead of sending them to standard output, as telnet(1) does with some. 
     Common uses include: 
           o   simple TCP proxies
           o   shell-script based HTTP clients and servers
           o   network daemon testing
           o   a SOCKS or HTTP ProxyCommand for ssh(1)
           o   and much, much more
$ nc -lk 9999

```

完成上述步骤后，Netcat 服务器就绪，Spark Streaming 数据处理应用程序将处理在前一个控制台窗口中输入的所有行。不要关闭此控制台窗口；所有后续的 shell 命令将在另一个终端窗口中运行。

由于不同编程语言之间 Spark Streaming 特性的不一致，使用 Scala 代码来解释所有 Spark Streaming 概念和用例。之后，给出 Python 代码，如果 Python 中讨论的任何特性缺乏支持，也会记录下来。

如*图 4*所示，Scala 和 Python 代码的组织方式。为了编译、打包和运行代码，使用了 Bash 脚本，以便读者可以轻松运行它们以产生一致的结果。这些脚本文件的内容在此讨论。

## 文件组织

在下面的文件夹树中，`project`和`target`文件夹在运行时创建。本书附带的源代码可以直接复制到系统中方便的文件夹中：

![文件组织](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-bg/img/image_06_007.jpg)

*图 4*

编译和打包使用**Scala 构建工具**(**sbt**)。为了确保 sbt 正常工作，请从*图 4*中树的`Scala`文件夹中在终端窗口中运行以下命令。这是为了确保 sbt 运行正常，代码编译无误：

```scala
$ cd Scala
$ sbt
> compile
 [success] Total time: 1 s, completed 24 Jul, 2016 8:39:04 AM 
 > exit
	  $

```

下表概述了正在讨论的 Spark Streaming 数据处理应用程序中文件的代表性样本列表及其各自用途。

| **文件名** | **用途** |
| --- | --- |
| `README.txt` | 运行应用程序的说明。一份针对 Scala 应用程序，另一份针对 Python 应用程序。 |
| `submitPy.sh` | 向 Spark 集群提交 Python 作业的 Bash 脚本。 |
| `compile.sh` | 编译 Scala 代码的 Bash 脚本。 |
| `submit.sh` | 向 Spark 集群提交 Scala 作业的 Bash 脚本。 |
| `config.sbt` | sbt 配置文件。 |
| `*.scala` | Scala 中的 Spark Streaming 数据处理应用程序代码。 |
| `*.py` | Python 中的 Spark Streaming 数据处理应用程序代码。 |
| `*.jar` | 需要下载并放置在`lib`目录下的 Spark Streaming 和 Kafka 集成 JAR 文件，以确保应用程序正常运行。这在`submit.sh`和`submitPy.sh`中用于向集群提交作业。 |

## 向 Spark 集群提交作业

为了正确运行应用程序，其中一些配置取决于它运行的系统。它们需要在`submit.sh`文件和`submitPy.sh`文件中进行编辑。无论何处需要此类编辑，都会使用`[FILLUP]`标签给出注释。其中最重要的是设置 Spark 安装目录和 Spark 主配置，这可能因系统而异。前面脚本`submit.sh`文件的源代码如下：

```scala
#!/bin/bash
	  #-----------
	  # submit.sh
	  #-----------
	  # IMPORTANT - Assumption is that the $SPARK_HOME and $KAFKA_HOME environment variables are already set in the system that is running the application
	  # [FILLUP] Which is your Spark master. If monitoring is needed, use the desired Spark master or use local
	  # When using the local mode. It is important to give more than one cores in square brackets
	  #SPARK_MASTER=spark://Rajanarayanans-MacBook-Pro.local:7077
	  SPARK_MASTER=local[4]
	  # [OPTIONAL] Your Scala version
	  SCALA_VERSION="2.11"
	  # [OPTIONAL] Name of the application jar file. You should be OK to leave it like that
	  APP_JAR="spark-for-beginners_$SCALA_VERSION-1.0.jar"
	  # [OPTIONAL] Absolute path to the application jar file
	  PATH_TO_APP_JAR="target/scala-$SCALA_VERSION/$APP_JAR"
	  # [OPTIONAL] Spark submit commandSPARK_SUBMIT="$SPARK_HOME/bin/spark-submit"
	  # [OPTIONAL] Pass the application name to run as the parameter to this script
	  APP_TO_RUN=$1
	  sbt package
	  if [ $2 -eq 1 ]
	  then
	  $SPARK_SUBMIT --class $APP_TO_RUN --master $SPARK_MASTER --jars $KAFKA_HOME/libs/kafka-clients-0.8.2.2.jar,$KAFKA_HOME/libs/kafka_2.11-0.8.2.2.jar,$KAFKA_HOME/libs/metrics-core-2.2.0.jar,$KAFKA_HOME/libs/zkclient-0.3.jar,./lib/spark-streaming-kafka-0-8_2.11-2.0.0-preview.jar $PATH_TO_APP_JAR
	  else
	  $SPARK_SUBMIT --class $APP_TO_RUN --master $SPARK_MASTER --jars $PATH_TO_APP_JAR $PATH_TO_APP_JAR
	  fi

```

前面脚本文件`submitPy.sh`的源代码如下：

```scala
 #!/usr/bin/env bash
	  #------------
	  # submitPy.sh
	  #------------
	  # IMPORTANT - Assumption is that the $SPARK_HOME and $KAFKA_HOME environment variables are already set in the system that is running the application
	  # Disable randomized hash in Python 3.3+ (for string) Otherwise the following exception will occur
	  # raise Exception("Randomness of hash of string should be disabled via PYTHONHASHSEED")
	  # Exception: Randomness of hash of string should be disabled via PYTHONHASHSEED
	  export PYTHONHASHSEED=0
	  # [FILLUP] Which is your Spark master. If monitoring is needed, use the desired Spark master or use local
	  # When using the local mode. It is important to give more than one cores in square brackets
	  #SPARK_MASTER=spark://Rajanarayanans-MacBook-Pro.local:7077
	  SPARK_MASTER=local[4]
	  # [OPTIONAL] Pass the application name to run as the parameter to this script
	  APP_TO_RUN=$1
	  # [OPTIONAL] Spark submit command
	  SPARK_SUBMIT="$SPARK_HOME/bin/spark-submit"
	  if [ $2 -eq 1 ]
	  then
	  $SPARK_SUBMIT --master $SPARK_MASTER --jars $KAFKA_HOME/libs/kafka-clients-0.8.2.2.jar,$KAFKA_HOME/libs/kafka_2.11-0.8.2.2.jar,$KAFKA_HOME/libs/metrics-core-2.2.0.jar,$KAFKA_HOME/libs/zkclient-0.3.jar,./lib/spark-streaming-kafka-0-8_2.11-2.0.0-preview.jar $APP_TO_RUN
	  else
	  $SPARK_SUBMIT --master $SPARK_MASTER $APP_TO_RUN
	  fi

```

## 监控正在运行的应用程序

如第二章所述，*Spark 编程模型*，Spark 安装自带一个强大的 Spark Web UI，用于监控正在运行的 Spark 应用程序。

对于正在运行的 Spark Streaming 作业，还有额外的可视化工具可用。

以下脚本启动 Spark 主节点和工作者，并启用监控。这里的假设是读者已经按照第二章，*Spark 编程模型*中的建议进行了所有配置更改，以启用 Spark 应用程序监控。如果没有这样做，应用程序仍然可以运行。唯一需要做的更改是将`submit.sh`文件和`submitPy.sh`文件中的情况更改为确保使用`local[4]`之类的内容，而不是 Spark 主 URL。在终端窗口中运行以下命令：

```scala
 $ cd $SPARK_HOME
	  $ ./sbin/start-all.sh
       starting org.apache.spark.deploy.master.Master, logging to /Users/RajT/source-code/spark-source/spark-2.0/logs/spark-RajT-org.apache.spark.deploy.master.Master-1-Rajanarayanans-MacBook-Pro.local.out 
 localhost: starting org.apache.spark.deploy.worker.Worker, logging to /Users/RajT/source-code/spark-source/spark-2.0/logs/spark-RajT-org.apache.spark.deploy.worker.Worker-1-Rajanarayanans-MacBook-Pro.local.out

```

通过访问`http://localhost:8080/`确保 Spark Web UI 已启动并运行。

## 在 Scala 中实现应用程序

以下代码片段是用于日志事件处理应用程序的 Scala 代码：

```scala
 /**
	  The following program can be compiled and run using SBT
	  Wrapper scripts have been provided with this
	  The following script can be run to compile the code
	  ./compile.sh
	  The following script can be used to run this application in Spark
	  ./submit.sh com.packtpub.sfb.StreamingApps
	  **/
	  package com.packtpub.sfb
	  import org.apache.spark.sql.{Row, SparkSession}
	  import org.apache.spark.streaming.{Seconds, StreamingContext}
	  import org.apache.spark.storage.StorageLevel
	  import org.apache.log4j.{Level, Logger}
	  object StreamingApps{
	  def main(args: Array[String]) 
	  {
	  // Log level settings
	  	  LogSettings.setLogLevels()
	  	  // Create the Spark Session and the spark context	  
	  	  val spark = SparkSession
	  	  .builder
	  	  .appName(getClass.getSimpleName)
	  	  .getOrCreate()
	     // Get the Spark context from the Spark session for creating the streaming context
	  	  val sc = spark.sparkContext   
	      // Create the streaming context
	      val ssc = new StreamingContext(sc, Seconds(10))
	      // Set the check point directory for saving the data to recover when 
       there is a crash   ssc.checkpoint("/tmp")
	      println("Stream processing logic start")
	      // Create a DStream that connects to localhost on port 9999
	      // The StorageLevel.MEMORY_AND_DISK_SER indicates that the data will be 
       stored in memory and if it overflows, in disk as well
	      val appLogLines = ssc.socketTextStream("localhost", 9999, 
       StorageLevel.MEMORY_AND_DISK_SER)
	      // Count each log message line containing the word ERROR
	      val errorLines = appLogLines.filter(line => line.contains("ERROR"))
	      // Print the elements of each RDD generated in this DStream to the 
        console   errorLines.print()
		   // Count the number of messages by the windows and print them
		   errorLines.countByWindow(Seconds(30), Seconds(10)).print()
		   println("Stream processing logic end")
		   // Start the streaming   ssc.start()   
		   // Wait till the application is terminated             
		   ssc.awaitTermination()    }
		}object LogSettings{
		  /** 
		   Necessary log4j logging level settings are done 
		  */  def setLogLevels() {
		    val log4jInitialized = 
         Logger.getRootLogger.getAllAppenders.hasMoreElements
		     if (!log4jInitialized) {
		        // This is to make sure that the console is clean from other INFO 
            messages printed by Spark
			       Logger.getRootLogger.setLevel(Level.WARN)
			    }
			  }
			}

```

在前面的代码片段中，有两个 Scala 对象。一个是设置适当的日志级别，以确保控制台上不显示不需要的消息。`StreamingApps` Scala 对象包含流处理的逻辑。以下列表捕捉了功能的本质：

+   使用应用程序名称创建 Spark 配置。

+   创建了一个 Spark `StreamingContext`对象，这是流处理的中心。`StreamingContext`构造函数的第二个参数是批处理间隔，这里是 10 秒。包含`ssc.socketTextStream`的行在每个批处理间隔（此处为 10 秒）创建 DStreams，其中包含在 Netcat 控制台中输入的行。

+   接下来对 DStream 应用过滤转换，只包含包含单词`ERROR`的行。过滤转换创建仅包含过滤行的新 DStreams。

+   下一行将 DStream 内容打印到控制台。换句话说，对于每个批处理间隔，如果存在包含单词`ERROR`的行，则会在控制台上显示。

+   在此数据处理逻辑结束时，给定的`StreamingContext`启动并运行，直到被终止。

在前面的代码片段中，没有循环结构告诉应用程序重复直到运行应用程序被终止。这是由 Spark Streaming 库本身实现的。从数据处理应用程序开始到终止，所有语句都运行一次。对 DStreams 的所有操作都会重复（内部）每个批次。如果仔细检查前一个应用程序的输出，尽管这些语句位于`StreamingContext`的初始化和终止之间，但只能在控制台上看到 println()语句的输出一次。这是因为*魔法循环*仅对包含原始和派生 DStreams 的语句重复。

由于 Spark Streaming 应用程序中实现的循环的特殊性，在应用程序代码的流逻辑中给出打印语句和日志语句是徒劳的，就像代码片段中给出的那样。如果必须这样做，那么这些日志语句应该在传递给 DStreams 进行转换和操作的函数中进行设置。

### 提示

如果需要对处理后的数据进行持久化，DStreams 提供了多种输出操作，就像 RDDs 一样。

## 编译和运行应用程序

以下命令在终端窗口中运行以编译和运行应用程序。可以使用简单的 sbt 编译命令，而不是使用`./compile.sh`。

### 注意

请注意，如前所述，在执行这些命令之前，Netcat 服务器必须正在运行。

```scala
 $ cd Scala
			$ ./compile.sh

      [success] Total time: 1 s, completed 24 Jan, 2016 2:34:48 PM

	$ ./submit.sh com.packtpub.sfb.StreamingApps

      Stream processing logic start    

      Stream processing logic end  

      -------------------------------------------                                     

      Time: 1469282910000 ms

      -------------------------------------------

      -------------------------------------------

      Time: 1469282920000 ms

      ------------------------------------------- 

```

如果没有显示错误消息，并且结果与之前的输出一致，则 Spark Streaming 数据处理应用程序已正确启动。

## 处理输出

请注意，打印语句的输出在 DStream 输出打印之前。到目前为止，还没有在 Netcat 控制台中输入任何内容，因此没有要处理的内容。

现在转到之前启动的 Netcat 控制台，输入以下几行日志事件消息，间隔几秒钟，以确保输出到多个批次，其中批处理大小为 10 秒：

```scala
 [Fri Dec 20 01:46:23 2015] [ERROR] [client 1.2.3.4.5.6] Directory index forbidden by rule: /home/raj/
	  [Fri Dec 20 01:46:23 2015] [WARN] [client 1.2.3.4.5.6] Directory index forbidden by rule: /home/raj/
	  [Fri Dec 20 01:54:34 2015] [ERROR] [client 1.2.3.4.5.6] Directory index forbidden by rule: /apache/web/test
	  [Fri Dec 20 01:54:34 2015] [WARN] [client 1.2.3.4.5.6] Directory index forbidden by rule: /apache/web/test
	  [Fri Dec 20 02:25:55 2015] [ERROR] [client 1.2.3.4.5.6] Client sent malformed Host header
	  [Fri Dec 20 02:25:55 2015] [WARN] [client 1.2.3.4.5.6] Client sent malformed Host header
	  [Mon Dec 20 23:02:01 2015] [ERROR] [client 1.2.3.4.5.6] user test: authentication failure for "/~raj/test": Password Mismatch
	  [Mon Dec 20 23:02:01 2015] [WARN] [client 1.2.3.4.5.6] user test: authentication failure for "/~raj/test": Password Mismatch 

```

一旦日志事件消息输入到 Netcat 控制台窗口，以下结果将开始显示在 Spark Streaming 数据处理应用程序中，仅过滤包含关键字 ERROR 的日志事件消息。

```scala
	  -------------------------------------------
	  Time: 1469283110000 ms
	  -------------------------------------------
	  [Fri Dec 20 01:46:23 2015] [ERROR] [client 1.2.3.4.5.6] Directory index
      forbidden by rule: /home/raj/
	  -------------------------------------------
	  Time: 1469283190000 ms
	  -------------------------------------------
	  -------------------------------------------
	  Time: 1469283200000 ms
	  -------------------------------------------
	  [Fri Dec 20 01:54:34 2015] [ERROR] [client 1.2.3.4.5.6] Directory index
      forbidden by rule: /apache/web/test
	  -------------------------------------------
	  Time: 1469283250000 ms
	  -------------------------------------------
	  -------------------------------------------
	  Time: 1469283260000 ms
	  -------------------------------------------
	  [Fri Dec 20 02:25:55 2015] [ERROR] [client 1.2.3.4.5.6] Client sent 
      malformed Host header
	  -------------------------------------------
	  Time: 1469283310000 ms
	  -------------------------------------------
	  [Mon Dec 20 23:02:01 2015] [ERROR] [client 1.2.3.4.5.6] user test:
      authentication failure for "/~raj/test": Password Mismatch
	  -------------------------------------------
	  Time: 1453646710000 ms
	  -------------------------------------------

```

Spark Web UI（`http://localhost:8080/`）已启用，图 5 和图 6 显示了 Spark 应用程序和统计信息。

从主页（访问 URL `http://localhost:8080/`后），点击正在运行的 Spark Streaming 数据处理应用程序的名称链接，以调出常规监控页面。从该页面，点击**Streaming**标签，以显示包含流统计信息的页面。

需要点击的链接和标签以红色圆圈标出：

![处理输出](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-bg/img/image_06_008.jpg)

图 5

从*图 5*所示页面中，点击圆圈内的应用程序链接；这将带您到相关页面。从该页面，一旦点击**Streaming**标签，将显示包含流统计信息的页面，如*图 6*所示：

![处理输出](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-bg/img/image_06_009.jpg)

图 6

这些 Spark 网页界面提供了大量的应用程序统计信息，深入探索它们有助于更深入地理解提交的 Spark Streaming 数据处理应用程序的行为。

### 提示

在启用流应用程序监控时必须小心，以确保不影响应用程序本身的性能。

## 在 Python 中实现应用程序

相同的用例在 Python 中实现，以下代码片段保存在`StreamingApps.py`中用于执行此操作：

```scala
 # The following script can be used to run this application in Spark
	  # ./submitPy.sh StreamingApps.py
	  from __future__ import print_function
	  import sys
	  from pyspark import SparkContext
	  from pyspark.streaming import StreamingContext
	  if __name__ == "__main__":
	      # Create the Spark context
	      sc = SparkContext(appName="PythonStreamingApp")
	      # Necessary log4j logging level settings are done 
	      log4j = sc._jvm.org.apache.log4j
	      log4j.LogManager.getRootLogger().setLevel(log4j.Level.WARN)
	      # Create the Spark Streaming Context with 10 seconds batch interval
	      ssc = StreamingContext(sc, 10)
	      # Set the check point directory for saving the data to recover when
        there is a crash
		    ssc.checkpoint("\tmp")
		    # Create a DStream that connects to localhost on port 9999
		    appLogLines = ssc.socketTextStream("localhost", 9999)
		    # Count each log messge line containing the word ERROR
		    errorLines = appLogLines.filter(lambda appLogLine: "ERROR" in appLogLine)
		    # // Print the elements of each RDD generated in this DStream to the console 
		    errorLines.pprint()
		    # Count the number of messages by the windows and print them
		    errorLines.countByWindow(30,10).pprint()
		    # Start the streaming
		    ssc.start()
		    # Wait till the application is terminated   
		    ssc.awaitTermination()
```

以下命令在终端窗口中运行 Python Spark Streaming 数据处理应用程序，该目录是代码下载的位置。在运行应用程序之前，如同对用于运行 Scala 应用程序的脚本进行修改一样，`submitPy.sh`文件也需要更改，以指向正确的 Spark 安装目录并配置 Spark 主节点。如果启用了监控，并且提交指向了正确的 Spark 主节点，则相同的 Spark 网页界面也将捕获 Python Spark Streaming 数据处理应用程序的统计信息。

以下命令在终端窗口中运行 Python 应用程序：

```scala
 $ cd Python
		$ ./submitPy.sh StreamingApps.py 

```

一旦将用于 Scala 实现中的相同日志事件消息输入到 Netcat 控制台窗口中，以下结果将开始显示在流应用程序中，仅过滤包含关键字`ERROR`的日志事件消息：

```scala
		-------------------------------------------
		Time: 2016-07-23 15:21:50
		-------------------------------------------
		-------------------------------------------
		Time: 2016-07-23 15:22:00
		-------------------------------------------
		[Fri Dec 20 01:46:23 2015] [ERROR] [client 1.2.3.4.5.6] 
		Directory index forbidden by rule: /home/raj/
		-------------------------------------------
		Time: 2016-07-23 15:23:50
		-------------------------------------------
		[Fri Dec 20 01:54:34 2015] [ERROR] [client 1.2.3.4.5.6] 
		Directory index forbidden by rule: /apache/web/test
		-------------------------------------------
		Time: 2016-07-23 15:25:10
		-------------------------------------------
		-------------------------------------------
		Time: 2016-07-23 15:25:20
		-------------------------------------------
		[Fri Dec 20 02:25:55 2015] [ERROR] [client 1.2.3.4.5.6] 
		Client sent malformed Host header
		-------------------------------------------
		Time: 2016-07-23 15:26:50
		-------------------------------------------
		[Mon Dec 20 23:02:01 2015] [ERROR] [client 1.2.3.4.5.6] 
		user test: authentication failure for "/~raj/test": Password Mismatch
		-------------------------------------------
		Time: 2016-07-23 15:26:50
		-------------------------------------------

```

如果您查看 Scala 和 Python 程序的输出，可以清楚地看到在给定的批次间隔内是否存在包含单词`ERROR`的日志事件消息。一旦数据被处理，应用程序会丢弃已处理的数据，不保留它们以供将来使用。

换言之，该应用程序不会保留或记忆任何来自先前批次间隔的日志事件消息。如果需要捕获错误消息的数量，例如在过去 5 分钟左右，那么先前的方法将不适用。我们将在下一节讨论这一点。

# 窗口化数据处理

在前一节讨论的 Spark Streaming 数据处理应用程序中，假设需要统计前三个批次中包含关键字 ERROR 的日志事件消息的数量。换句话说，应该能够跨三个批次的窗口统计此类事件消息的数量。在任何给定时间点，随着新数据批次的可用，窗口应随时间滑动。这里讨论了三个重要术语，*图 7*解释了它们。它们是：

+   批处理间隔：生成 DStream 的时间间隔

+   窗口长度：需要查看在那些批处理间隔中生成的所有 DStreams 的批处理间隔的持续时间

+   滑动间隔：执行窗口操作（如统计事件消息）的时间间隔

![窗口化数据处理](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-bg/img/image_06_011.jpg)

图 7

在*图 7*中，在某一特定时间点，用于执行操作的 DStreams 被包含在一个矩形内。

在每个批处理间隔中，都会生成一个新的 DStream。这里，窗口长度为三，窗口内要执行的操作是统计该窗口内的事件消息数量。滑动间隔保持与批处理间隔相同，以便在新 DStream 生成时执行计数操作，从而始终确保计数的准确性。

在时间**t2**，计数操作针对在时间**t0**、**t1**和**t2**生成的 DStreams 执行。在时间**t3**，由于滑动窗口保持与批处理间隔相同，计数操作再次执行，这次针对在时间**t1**、**t2**和**t3**生成的 DStreams 进行事件计数。在时间**t4**，计数操作再次执行，针对在时间**t2**、**t3**和**t4**生成的 DStreams 进行事件计数。操作以此类推，直到应用程序终止。

## 在 Scala 中统计已处理的日志事件消息数量

在前述部分，讨论了日志事件消息的处理。在同一应用程序代码中，在打印包含单词`ERROR`的日志事件消息之后，在 Scala 应用程序中包含以下代码行：

```scala
errorLines.print()errorLines.countByWindow(Seconds(30), Seconds(10)).print()
```

第一个参数是窗口长度，第二个参数是滑动窗口间隔。这条神奇的代码行将在 Netcat 控制台输入以下行后，打印出已处理的日志事件消息的计数：

```scala
[Fri Dec 20 01:46:23 2015] [ERROR] [client 1.2.3.4.5.6] Directory index forbidden by rule: /home/raj/[Fri Dec 20 01:46:23 2015] [WARN] [client 1.2.3.4.5.6] Directory index forbidden by rule: /home/raj/[Fri Dec 20 01:54:34 2015] [ERROR] [client 1.2.3.4.5.6] Directory index forbidden by rule: /apache/web/test

```

在 Scala 中运行的相同的 Spark Streaming 数据处理应用程序，加上额外的代码行，会产生以下输出：

```scala
-------------------------------------------
Time: 1469284630000 ms
-------------------------------------------
[Fri Dec 20 01:46:23 2015] [ERROR] [client 1.2.3.4.5.6] Directory index 
      forbidden by rule: /home/raj/
-------------------------------------------
Time: 1469284630000 ms
      -------------------------------------------
1
-------------------------------------------
Time: 1469284640000 ms
-------------------------------------------
[Fri Dec 20 01:54:34 2015] [ERROR] [client 1.2.3.4.5.6] Directory index 
      forbidden by rule: /apache/web/test
-------------------------------------------
Time: 1469284640000 ms
-------------------------------------------
2
-------------------------------------------
Time: 1469284650000 ms
-------------------------------------------
2
-------------------------------------------
Time: 1469284660000 ms
-------------------------------------------
1
-------------------------------------------
Time: 1469284670000 ms
-------------------------------------------
0

```

如果仔细研究输出，可以注意到，在第一个批处理间隔中，处理了一个日志事件消息。显然，该批处理间隔显示的计数为`1`。在下一个批处理间隔中，又处理了一个日志事件消息。该批处理间隔显示的计数为`2`。在下一个批处理间隔中，没有处理日志事件消息。但该窗口的计数仍然是`2`。对于另一个窗口，计数显示为`2`。然后它减少到`1`，然后是 0。

这里需要注意的是，在 Scala 和 Python 的应用程序代码中，在创建 StreamingContext 之后，需要立即插入以下代码行来指定检查点目录：

```scala
ssc.checkpoint("/tmp") 

```

## 在 Python 中统计处理日志事件消息的数量

在 Python 应用程序代码中，在打印包含单词 ERROR 的日志事件消息之后，在 Scala 应用程序中包含以下代码行：

```scala
errorLines.pprint()
errorLines.countByWindow(30,10).pprint()
```

第一个参数是窗口长度，第二个参数是滑动窗口间隔。这条神奇的代码行将在 Netcat 控制台输入以下行后，打印出处理的日志事件消息的计数：

```scala
[Fri Dec 20 01:46:23 2015] [ERROR] [client 1.2.3.4.5.6] 
Directory index forbidden by rule: /home/raj/
[Fri Dec 20 01:46:23 2015] [WARN] [client 1.2.3.4.5.6] 
Directory index forbidden by rule: /home/raj/
[Fri Dec 20 01:54:34 2015] [ERROR] [client 1.2.3.4.5.6] 
Directory index forbidden by rule: /apache/web/test

```

在 Python 中使用相同的 Spark Streaming 数据处理应用程序，添加额外的代码行，产生以下输出：

```scala
------------------------------------------- 
Time: 2016-07-23 15:29:40 
------------------------------------------- 
[Fri Dec 20 01:46:23 2015] [ERROR] [client 1.2.3.4.5.6] Directory index forbidden by rule: /home/raj/ 
------------------------------------------- 
Time: 2016-07-23 15:29:40 
------------------------------------------- 
1 
------------------------------------------- 
Time: 2016-07-23 15:29:50 
------------------------------------------- 
[Fri Dec 20 01:54:34 2015] [ERROR] [client 1.2.3.4.5.6] Directory index forbidden by rule: /apache/web/test 
------------------------------------------- 
Time: 2016-07-23 15:29:50 
------------------------------------------- 
2 
------------------------------------------- 
Time: 2016-07-23 15:30:00 
------------------------------------------- 
------------------------------------------- 
Time: 2016-07-23 15:30:00 
------------------------------------------- 
2 
------------------------------------------- 
Time: 2016-07-23 15:30:10 
------------------------------------------- 
------------------------------------------- 
Time: 2016-07-23 15:30:10 
------------------------------------------- 
1 
------------------------------------------- 
Time: 2016-07-23 15:30:20 
------------------------------------------- 
------------------------------------------- 
Time: 2016-07-23 15:30:20 
-------------------------------------------

```

Python 应用程序的输出模式与 Scala 应用程序也非常相似。

# 更多处理选项

除了窗口中的计数操作外，还可以在 DStreams 上进行更多操作，并与窗口化结合。下表捕捉了重要的转换。所有这些转换都作用于选定的窗口并返回一个 DStream。

| **转换** | **描述** |
| --- | --- |
| `window(windowLength, slideInterval)` | 返回在窗口中计算的 DStreams |
| `countByWindow(windowLength, slideInterval)` | 返回元素的计数 |
| `reduceByWindow(func, windowLength, slideInterval)` | 通过应用聚合函数返回一个元素 |
| `reduceByKeyAndWindow(func, windowLength, slideInterval, [numTasks])` | 对每个键应用多个值的聚合函数后，返回每个键的一对键/值 |
| `countByValueAndWindow(windowLength, slideInterval, [numTasks])` | 对每个键应用多个值的计数后，返回每个键的一对键/计数 |

流处理中最关键的步骤之一是将流数据持久化到辅助存储中。由于 Spark Streaming 数据处理应用程序中的数据速度将非常高，任何引入额外延迟的持久化机制都不是一个可取的解决方案。

在批处理场景中，向 HDFS 和其他基于文件系统的存储写入数据是可行的。但涉及到流输出存储时，应根据用例选择理想的流数据存储机制。

NoSQL 数据存储如 Cassandra 支持快速写入时间序列数据。它也非常适合读取存储的数据以供进一步分析。Spark Streaming 库支持 DStreams 上的多种输出方法。它们包括将流数据保存为文本文件、对象文件、Hadoop 文件等的选项。此外，还有许多第三方驱动程序可用于将数据保存到各种数据存储中。

# Kafka 流处理

本章介绍的日志事件处理器示例正在监听 TCP 套接字，以接收 Spark Streaming 数据处理应用程序将要处理的消息流。但在现实世界的用例中，情况并非如此。

具有发布-订阅功能的消息队列系统通常用于处理消息。传统的消息队列系统因每秒需要处理大量消息以满足大规模数据处理应用的需求而表现不佳。

Kafka 是一种发布-订阅消息系统，被许多物联网应用用于处理大量消息。以下 Kafka 的功能使其成为最广泛使用的消息系统之一：

+   极速处理：Kafka 能够通过在短时间内处理来自许多应用程序客户端的读写操作来处理大量数据

+   高度可扩展：Kafka 设计用于通过使用商品硬件向上和向外扩展以形成集群

+   持久化大量消息：到达 Kafka 主题的消息被持久化到辅助存储中，同时处理大量流经的消息

### 注意

Kafka 的详细介绍超出了本书的范围。假设读者熟悉并具有 Kafka 的实际操作知识。从 Spark Streaming 数据处理应用程序的角度来看，无论是使用 TCP 套接字还是 Kafka 作为消息源，实际上并没有什么区别。但是，通过使用 Kafka 作为消息生产者的预告用例，可以很好地了解企业广泛使用的工具集。*《学习 Apache Kafka》第二版*由*Nishant Garg*编写（[`www.packtpub.com/big-data-and-business-intelligence/learning-apache-kafka-second-edition`](https://www.packtpub.com/big-data-and-business-intelligence/learning-apache-kafka-second-edition)）是学习 Kafka 的优秀参考书。

以下是 Kafka 的一些重要元素，也是进一步了解之前需要理解的术语：

+   生产者：消息的实际来源，如气象传感器或移动电话网络

+   代理：Kafka 集群，接收并持久化由各种生产者发布到其主题的消息

+   消费者：数据处理应用程序订阅了 Kafka 主题，这些主题消费了发布到主题的消息

在前一节中讨论的相同日志事件处理应用程序用例再次用于阐明 Kafka 与 Spark Streaming 的使用。这里，Spark Streaming 数据处理应用程序将作为 Kafka 主题的消费者，而发布到该主题的消息将被消费。

Spark Streaming 数据处理应用程序使用 Kafka 作为消息代理的 0.8.2.2 版本，假设读者已经至少在独立模式下安装了 Kafka。以下活动是为了确保 Kafka 准备好处理生产者产生的消息，并且 Spark Streaming 数据处理应用程序可以消费这些消息：

1.  启动随 Kafka 安装一起提供的 Zookeeper。

1.  启动 Kafka 服务器。

1.  为生产者创建一个主题以发送消息。

1.  选择一个 Kafka 生产者，开始向新创建的主题发布日志事件消息。

1.  使用 Spark Streaming 数据处理应用程序处理发布到新创建主题的日志事件。

## 启动 Zookeeper 和 Kafka

以下脚本在单独的终端窗口中运行，以启动 Zookeeper 和 Kafka 代理，并创建所需的 Kafka 主题：

```scala
$ cd $KAFKA_HOME 
$ $KAFKA_HOME/bin/zookeeper-server-start.sh 
$KAFKA_HOME/config/zookeeper.properties  
[2016-07-24 09:01:30,196] INFO binding to port 0.0.0.0/0.0.0.0:2181 (org.apache.zookeeper.server.NIOServerCnxnFactory) 
$ $KAFKA_HOME/bin/kafka-server-start.sh $KAFKA_HOME/config/server.properties  

[2016-07-24 09:05:06,381] INFO 0 successfully elected as leader 
(kafka.server.ZookeeperLeaderElector) 
[2016-07-24 09:05:06,455] INFO [Kafka Server 0], started 
(kafka.server.KafkaServer) 
$ $KAFKA_HOME/bin/kafka-topics.sh --create --zookeeper localhost:2181 
--replication-factor 1 --partitions 1 --topic sfb 
Created topic "sfb". 
$ $KAFKA_HOME/bin/kafka-console-producer.sh --broker-list 
localhost:9092 --topic sfb

```

### 提示

确保环境变量`$KAFKA_HOME`指向 Kafka 安装的目录。同时，在单独的终端窗口中启动 Zookeeper、Kafka 服务器、Kafka 生产者和 Spark Streaming 日志事件数据处理应用程序非常重要。

Kafka 消息生产者可以是任何能够向 Kafka 主题发布消息的应用程序。这里，使用随 Kafka 一起提供的`kafka-console-producer`作为首选生产者。一旦生产者开始运行，在其控制台窗口中输入的任何内容都将被视为发布到所选 Kafka 主题的消息。启动`kafka-console-producer`时，Kafka 主题作为命令行参数给出。

提交消费由 Kafka 生产者产生的日志事件消息的 Spark Streaming 数据处理应用程序与前一节中介绍的应用程序略有不同。这里，数据处理需要许多 Kafka jar 文件。由于它们不是 Spark 基础设施的一部分，因此必须提交给 Spark 集群。以下 jar 文件是成功运行此应用程序所必需的：

+   `$KAFKA_HOME/libs/kafka-clients-0.8.2.2.jar`

+   `$KAFKA_HOME/libs/kafka_2.11-0.8.2.2.jar`

+   `$KAFKA_HOME/libs/metrics-core-2.2.0.jar`

+   `$KAFKA_HOME/libs/zkclient-0.3.jar`

+   `Code/Scala/lib/spark-streaming-kafka-0-8_2.11-2.0.0-preview.jar`

+   `Code/Python/lib/spark-streaming-kafka-0-8_2.11-2.0.0-preview.jar`

在前述的 jar 文件列表中，`spark-streaming-kafka-0-8_2.11-2.0.0-preview.jar`的 Maven 仓库坐标是`"org.apache.spark" %% "spark-streaming-kafka-0-8" % "2.0.0-preview"`。这个特定的 jar 文件必须下载并放置在图 4 所示的目录结构的 lib 文件夹中。它被用于`submit.sh`和`submitPy.sh`脚本中，这些脚本将应用程序提交给 Spark 集群。该 jar 文件的下载 URL 在本章的参考部分给出。

在`submit.sh`和`submitPy.sh`文件中，最后几行包含一个条件语句，查找第二个参数值为 1 以识别此应用程序，并将所需的 jar 文件发送到 Spark 集群。

### 提示

与其在提交作业时单独将这些 jar 文件发送到 Spark 集群，不如使用 sbt 创建的程序集 jar。

## 在 Scala 中实现应用程序

以下代码片段是用于处理由 Kafka 生产者产生的消息的日志事件处理应用程序的 Scala 代码。该应用程序的使用案例与前一节讨论的关于窗口操作的使用案例相同：

```scala
/** 
The following program can be compiled and run using SBT 
Wrapper scripts have been provided with this 
The following script can be run to compile the code 
./compile.sh 

The following script can be used to run this application in Spark. The second command line argument of value 1 is very important. This is to flag the shipping of the kafka jar files to the Spark cluster 
./submit.sh com.packtpub.sfb.KafkaStreamingApps 1 
**/ 
package com.packtpub.sfb 

import java.util.HashMap 
import org.apache.spark.streaming._ 
import org.apache.spark.sql.{Row, SparkSession} 
import org.apache.spark.streaming.kafka._ 
import org.apache.kafka.clients.producer.{ProducerConfig, KafkaProducer, ProducerRecord} 

object KafkaStreamingApps { 
  def main(args: Array[String]) { 
   // Log level settings 
   LogSettings.setLogLevels() 
   // Variables used for creating the Kafka stream 
   //The quorum of Zookeeper hosts 
    val zooKeeperQuorum = "localhost" 
   // Message group name 
   val messageGroup = "sfb-consumer-group" 
   //Kafka topics list separated by coma if there are multiple topics to be listened on 
   val topics = "sfb" 
   //Number of threads per topic 
   val numThreads = 1 
   // Create the Spark Session and the spark context            
   val spark = SparkSession 
         .builder 
         .appName(getClass.getSimpleName) 
         .getOrCreate() 
   // Get the Spark context from the Spark session for creating the streaming context 
   val sc = spark.sparkContext    
   // Create the streaming context 
   val ssc = new StreamingContext(sc, Seconds(10)) 
    // Set the check point directory for saving the data to recover when there is a crash 
   ssc.checkpoint("/tmp") 
   // Create the map of topic names 
    val topicMap = topics.split(",").map((_, numThreads.toInt)).toMap 
   // Create the Kafka stream 
    val appLogLines = KafkaUtils.createStream(ssc, zooKeeperQuorum, messageGroup, topicMap).map(_._2) 
   // Count each log messge line containing the word ERROR 
    val errorLines = appLogLines.filter(line => line.contains("ERROR")) 
   // Print the line containing the error 
   errorLines.print() 
   // Count the number of messages by the windows and print them 
   errorLines.countByWindow(Seconds(30), Seconds(10)).print() 
   // Start the streaming 
    ssc.start()    
   // Wait till the application is terminated             
    ssc.awaitTermination()  
  } 
} 

```

与前一节中的 Scala 代码相比，主要区别在于流创建的方式。

## 在 Python 中实现应用程序

以下代码片段是用于处理由 Kafka 生产者产生的消息的日志事件处理应用程序的 Python 代码。该应用程序的使用案例与前一节讨论的关于窗口操作的使用案例相同：

```scala
 # The following script can be used to run this application in Spark 
# ./submitPy.sh KafkaStreamingApps.py 1 

from __future__ import print_function 
import sys 
from pyspark import SparkContext 
from pyspark.streaming import StreamingContext 
from pyspark.streaming.kafka import KafkaUtils 

if __name__ == "__main__": 
    # Create the Spark context 
    sc = SparkContext(appName="PythonStreamingApp") 
    # Necessary log4j logging level settings are done  
    log4j = sc._jvm.org.apache.log4j 
    log4j.LogManager.getRootLogger().setLevel(log4j.Level.WARN) 
    # Create the Spark Streaming Context with 10 seconds batch interval 
    ssc = StreamingContext(sc, 10) 
    # Set the check point directory for saving the data to recover when there is a crash 
    ssc.checkpoint("\tmp") 
    # The quorum of Zookeeper hosts 
    zooKeeperQuorum="localhost" 
    # Message group name 
    messageGroup="sfb-consumer-group" 
    # Kafka topics list separated by coma if there are multiple topics to be listened on 
    topics = "sfb" 
    # Number of threads per topic 
    numThreads = 1     
    # Create a Kafka DStream 
    kafkaStream = KafkaUtils.createStream(ssc, zooKeeperQuorum, messageGroup, {topics: numThreads}) 
    # Create the Kafka stream 
    appLogLines = kafkaStream.map(lambda x: x[1]) 
    # Count each log messge line containing the word ERROR 
    errorLines = appLogLines.filter(lambda appLogLine: "ERROR" in appLogLine) 
    # Print the first ten elements of each RDD generated in this DStream to the console 
    errorLines.pprint() 
    errorLines.countByWindow(30,10).pprint() 
    # Start the streaming 
    ssc.start() 
    # Wait till the application is terminated    
    ssc.awaitTermination()

```

以下命令是在终端窗口中运行 Scala 应用程序的命令：

```scala
 $ cd Scala
	$ ./submit.sh com.packtpub.sfb.KafkaStreamingApps 1

```

以下命令是在终端窗口中运行 Python 应用程序的命令：

```scala
 $ cd Python
	$ 
	./submitPy.sh KafkaStreamingApps.py 1

```

当上述两个程序都在运行时，无论在 Kafka 控制台生产者的控制台窗口中输入什么日志事件消息，并通过以下命令和输入调用，都将由应用程序处理。该程序的输出将与前一节给出的输出非常相似：

```scala
	$ $KAFKA_HOME/bin/kafka-console-producer.sh --broker-list localhost:9092 
	--topic sfb 
	[Fri Dec 20 01:46:23 2015] [ERROR] [client 1.2.3.4.5.6] Directory index forbidden by rule: /home/raj/ 
	[Fri Dec 20 01:46:23 2015] [WARN] [client 1.2.3.4.5.6] Directory index forbidden by rule: /home/raj/ 
	[Fri Dec 20 01:54:34 2015] [ERROR] [client 1.2.3.4.5.6] Directory index forbidden by rule: 
	/apache/web/test 

```

Spark 提供两种处理 Kafka 流的方法。第一种是之前讨论过的基于接收器的方法，第二种是直接方法。

这种直接处理 Kafka 消息的方法是一种简化方式，其中 Spark Streaming 利用 Kafka 的所有可能功能，就像任何 Kafka 主题消费者一样，通过偏移量号在特定主题和分区中轮询消息。根据 Spark Streaming 数据处理应用程序的批处理间隔，它从 Kafka 集群中选择一定数量的偏移量，并将此范围内的偏移量作为一批处理。这种方法高效且非常适合需要精确一次处理的消息。此方法还减少了 Spark Streaming 库实现消息处理精确一次语义的需求，并将该责任委托给 Kafka。此方法的编程构造在用于数据处理的 API 中略有不同。请查阅相关参考资料以获取详细信息。

前述章节介绍了 Spark Streaming 库的概念，并讨论了一些实际应用案例。从部署角度来看，开发用于处理静态批处理数据的 Spark 数据处理应用程序与开发用于处理动态流数据的应用程序之间存在很大差异。处理数据流的数据处理应用程序的可用性必须持续不断。换句话说，此类应用程序不应具有单点故障组件。下一节将讨论此主题。

# Spark Streaming 作业在生产环境中

当 Spark Streaming 应用程序处理传入数据时，确保数据处理不间断至关重要，以便所有正在摄取的数据都能得到处理。在关键业务流应用程序中，大多数情况下，即使遗漏一条数据也可能产生巨大的业务影响。为应对这种情况，避免应用程序基础设施中的单点故障至关重要。

从 Spark Streaming 应用程序的角度来看，了解生态系统中底层组件的布局是有益的，以便采取适当措施避免单点故障。

部署在 Hadoop YARN、Mesos 或 Spark 独立模式等集群中的 Spark Streaming 应用程序，与其他类型的 Spark 应用程序一样，主要包含两个相似的组件：

+   **Spark 驱动程序**：包含用户编写的应用程序代码

+   **执行器**：执行由 Spark 驱动程序提交的作业的执行器

但执行器有一个额外的组件，称为接收器，它接收作为流输入的数据并将其保存为内存中的数据块。当一个接收器正在接收数据并形成数据块时，它们会被复制到另一个执行器以实现容错。换句话说，数据块的内存复制是在不同的执行器上完成的。在每个批处理间隔结束时，这些数据块被合并以形成 DStream，并发送出去进行下游进一步处理。

*图 8*描绘了在集群中部署的 Spark Streaming 应用基础设施中协同工作的组件：

![生产环境中的 Spark Streaming 作业](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark2-bg/img/image_06_013.jpg)

图 8

*图 8*中展示了两个执行器。为了表明第二个执行器并未使用接收器，而是直接从另一个执行器收集复制的块数据，故意未显示其接收器组件。但在需要时，例如第一个执行器发生故障时，第二个执行器的接收器可以开始工作。

## 在 Spark Streaming 数据处理应用中实现容错机制

Spark Streaming 数据处理应用的基础设施包含多个动态部分。任何一部分都可能发生故障，导致数据处理中断。通常，故障可能发生在 Spark 驱动程序或执行器上。

### 注意

本节并非旨在详细介绍在生产环境中运行具有容错能力的 Spark Streaming 应用。其目的是让读者了解在生产环境中部署 Spark Streaming 数据处理应用时应采取的预防措施。

当某个执行器发生故障时，由于数据复制是定期进行的，接收数据流的任务将由数据正在被复制的执行器接管。存在一种情况，即当执行器失败时，所有未处理的数据都将丢失。为规避此问题，可将数据块以预写日志的形式持久化到 HDFS 或 Amazon S3 中。

### 提示

无需在同一基础设施中同时保留数据块的内存复制和预写日志。根据需求，只保留其中之一即可。

当 Spark 驱动程序失败时，驱动程序停止运行，所有执行器失去连接并停止工作。这是最危险的情况。为应对这种情况，需要进行一些配置和代码更改。

Spark 驱动程序必须配置为支持集群管理器的自动驱动程序重启。这包括更改 Spark 作业提交方法，以在任何集群管理器中具有集群模式。当驱动程序重新启动时，为了从崩溃的地方开始，必须在驱动程序程序中实现检查点机制。这在使用的代码示例中已经完成。以下代码行完成了这项工作：

```scala
 ssc = StreamingContext(sc, 10) 
    ssc.checkpoint("\tmp")

```

### 提示

在示例应用中，使用本地系统目录作为检查点目录是可以的。但在生产环境中，最好将此检查点目录保持为 Hadoop 情况下的 HDFS 位置，或亚马逊云情况下的 S3 位置。

从应用编码的角度来看，创建`StreamingContext`的方式略有不同。不应每次都创建新的`StreamingContext`，而应使用函数与`StreamingContext`的工厂方法`getOrCreate`一起使用，如下面的代码段所示。如果这样做，当驱动程序重新启动时，工厂方法将检查检查点目录，以查看是否正在使用早期的`StreamingContext`，如果检查点数据中找到，则创建它。否则，将创建一个新的`StreamingContext`。

以下代码片段给出了一个函数的定义，该函数可与`StreamingContext`的`getOrCreate`工厂方法一起使用。如前所述，这些方面的详细讨论超出了本书的范围：

```scala
	 /** 
  * The following function has to be used when the code is being restructured to have checkpointing and driver recovery 
  * The way it should be used is to use the StreamingContext.getOrCreate with this function and do a start of that 
  */ 
  def sscCreateFn(): StreamingContext = { 
   // Variables used for creating the Kafka stream 
   // The quorum of Zookeeper hosts 
    val zooKeeperQuorum = "localhost" 
   // Message group name 
   val messageGroup = "sfb-consumer-group" 
   //Kafka topics list separated by coma if there are multiple topics to be listened on 
   val topics = "sfb" 
   //Number of threads per topic 
   val numThreads = 1      
   // Create the Spark Session and the spark context            
   val spark = SparkSession 
         .builder 
         .appName(getClass.getSimpleName) 
         .getOrCreate() 
   // Get the Spark context from the Spark session for creating the streaming context 
   val sc = spark.sparkContext    
   // Create the streaming context 
   val ssc = new StreamingContext(sc, Seconds(10)) 
   // Create the map of topic names 
    val topicMap = topics.split(",").map((_, numThreads.toInt)).toMap 
   // Create the Kafka stream 
    val appLogLines = KafkaUtils.createStream(ssc, zooKeeperQuorum, messageGroup, topicMap).map(_._2) 
   // Count each log messge line containing the word ERROR 
    val errorLines = appLogLines.filter(line => line.contains("ERROR")) 
   // Print the line containing the error 
   errorLines.print() 
   // Count the number of messages by the windows and print them 
   errorLines.countByWindow(Seconds(30), Seconds(10)).print() 
   // Set the check point directory for saving the data to recover when there is a crash 
   ssc.checkpoint("/tmp") 
   // Return the streaming context 
   ssc 
  } 

```

在数据源级别，构建并行性以加快数据处理是一个好主意，并且根据数据源的不同，这可以通过不同的方式实现。Kafka 本身支持主题级别的分区，这种扩展机制支持大量的并行性。作为 Kafka 主题的消费者，Spark Streaming 数据处理应用可以通过创建多个流来拥有多个接收器，并且这些流生成的数据可以通过对 Kafka 流的联合操作来合并。

Spark Streaming 数据处理应用的生产部署应完全基于所使用的应用类型。之前给出的一些指导原则仅具有介绍性和概念性。解决生产部署问题没有一劳永逸的方法，它们必须随着应用开发而发展。

## 结构化流

截至目前所讨论的数据流应用案例中，涉及众多开发者任务，包括构建结构化数据以及为应用程序实现容错机制。迄今为止在数据流应用中处理的数据均为非结构化数据。正如批量数据处理案例一样，即便在流式处理案例中，若能处理结构化数据，亦是一大优势，可避免大量预处理工作。数据流处理应用是持续运行的应用，必然会遭遇故障或中断。在此类情况下，构建数据流应用的容错机制至关重要。

在任何数据流应用中，数据持续被导入，若需在任意时间点查询接收到的数据，应用开发者必须将已处理的数据持久化至支持查询的数据存储中。在 Spark 2.0 中，结构化流处理概念围绕这些方面构建，全新特性自底层打造旨在减轻应用开发者在这些问题上的困扰。撰写本章时，一项编号为 SPARK-8360 的特性正在开发中，其进展可通过访问相应页面进行监控。

结构化流处理概念可通过实际案例加以阐述，例如我们之前探讨的银行业务交易案例。假设以逗号分隔的交易记录（包含账号及交易金额）正以流的形式传入。在结构化流处理方法中，所有这些数据项均被导入至一个支持使用 Spark SQL 进行查询的无界表或 DataFrame。换言之，由于数据累积于 DataFrame 中，任何可通过 DataFrame 实现的数据处理同样适用于流数据，从而减轻了应用开发者的负担，使其能够专注于业务逻辑而非基础设施相关方面。

# 参考资料

如需更多信息，请访问以下链接：

+   [`spark.apache.org/docs/latest/streaming-programming-guide.html`](https://spark.apache.org/docs/latest/streaming-programming-guide.html)

+   [`kafka.apache.org/`](http://kafka.apache.org/)

+   [`spark.apache.org/docs/latest/streaming-kafka-integration.html`](http://spark.apache.org/docs/latest/streaming-kafka-integration.html)

+   [`www.packtpub.com/big-data-and-business-intelligence/learning-apache-kafka-second-edition`](https://www.packtpub.com/big-data-and-business-intelligence/learning-apache-kafka-second-edition)

+   [`search.maven.org/remotecontent?filepath=org/apache/spark/spark-streaming-kafka-0-8_2.11/2.0.0-preview/spark-streaming-kafka-0-8_2.11-2.0.0-preview.jar`](http://search.maven.org/remotecontent?filepath=org/apache/spark/spark-streaming-kafka-0-8_2.11/2.0.0-preview/spark-streaming-kafka-0-8_2.11-2.0.0-preview.jar)

+   [`issues.apache.org/jira/browse/SPARK-836`](https://issues.apache.org/jira/browse/SPARK-836)

# 概述

Spark 在其核心之上提供了一个非常强大的库，用于处理高速摄取的数据流。本章介绍了 Spark Streaming 库的基础知识，并开发了一个简单的日志事件消息处理系统，该系统使用了两种类型的数据源：一种使用 TCP 数据服务器，另一种使用 Kafka。在本章末尾，简要介绍了 Spark Streaming 数据处理应用程序的生产部署，并讨论了在 Spark Streaming 数据处理应用程序中实现容错的可能方法。

Spark 2.0 引入了在流式应用程序中处理和查询结构化数据的能力，这一概念的引入减轻了应用程序开发人员对非结构化数据进行预处理、构建容错性和近乎实时地查询正在摄取的数据的负担。

应用数学家和统计学家已经提出了各种方法来回答与新数据片段相关的问题，这些问题基于对现有数据集的*学习*。通常，这些问题包括但不限于：这个数据片段是否符合给定模型，这个数据片段是否可以以某种方式分类，以及这个数据片段是否属于任何组或集群？

有许多算法可用于*训练*数据模型，并向该*模型*询问有关新数据片段的问题。这一快速发展的数据科学分支在数据处理中具有巨大的适用性，并被广泛称为机器学习。下一章将讨论 Spark 的机器学习库。
