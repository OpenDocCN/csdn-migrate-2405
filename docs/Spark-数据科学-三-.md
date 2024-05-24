# Spark 数据科学（三）

> 原文：[`zh.annas-archive.org/md5/D6F94257998256DE126905D8038FBE11`](https://zh.annas-archive.org/md5/D6F94257998256DE126905D8038FBE11)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：使用 SparkR 扩展 Spark

统计学家和数据科学家一直在几乎所有领域使用 R 解决具有挑战性的问题，从生物信息学到选举活动。他们喜欢 R 是因为它具有强大的可视化能力、强大的社区以及丰富的统计和机器学习包生态系统。世界各地的许多学术机构使用 R 语言教授数据科学和统计学。

R 最初是在 1990 年代中期由统计学家创建的，目标是提供更好、更用户友好的数据分析方式。R 最初用于学术和研究。随着企业越来越意识到数据科学在业务增长中的作用，企业部门使用 R 的数据分析师数量也在增长。在存在了 20 年后，R 语言用户基数被认为超过 200 万。

所有这一切成功背后的推动因素之一是，R 旨在使分析师的生活更轻松，而不是计算机的生活。R 本质上是单线程的，它只能处理完全适合单台计算机内存的数据集。但如今，R 用户正在处理越来越大的数据集。现代分布式处理能力与成熟的 R 语言的无缝集成，使数据科学家能够充分利用两者的优势。他们可以满足不断增长的业务需求，并继续从他们喜爱的 R 语言的灵活性中受益。

本章介绍了 SparkR，这是一个面向 R 程序员的 R API，使他们可以利用 Spark 的强大功能，而无需学习一种新语言。由于已经假定具有 R、R Studio 和数据分析技能的先验知识，因此本章不试图介绍 R。提供了 Spark 计算引擎的非常简要的概述作为快速回顾。读者应该阅读本书的前三章，以更深入地了解 Spark 编程模型和 DataFrames。这些知识非常重要，因为开发人员必须了解他的代码的哪一部分在本地 R 环境中执行，哪一部分由 Spark 计算引擎处理。本章涵盖的主题如下：

+   SparkR 基础知识

+   R 与 Spark 的优势及其局限性

+   使用 SparkR 进行编程

+   SparkR DataFrames

+   机器学习

# SparkR 基础知识

R 是一种用于统计计算和图形的语言和环境。SparkR 是一个 R 包，提供了一个轻量级的前端，以便从 R 中访问 Apache Spark。SparkR 的目标是结合 R 环境提供的灵活性和易用性，以及 Spark 计算引擎提供的可伸缩性和容错性。在讨论 SparkR 如何实现其目标之前，让我们回顾一下 Spark 的架构。

Apache Spark 是一个快速、通用、容错的框架，用于大规模分布式数据集的交互式和迭代计算。它支持各种数据源和存储层。它提供统一的数据访问，可以结合不同的数据格式、流数据，并使用高级、可组合的操作定义复杂的操作。您可以使用 Scala、Python 或 R shell（或没有 shell 的 Java）交互式地开发应用程序。您可以将其部署在家用台式机上，也可以在成千上万个节点的大型集群上运行，处理 PB 级数据。

### 注意

SparkR 起源于 AMPLab（[`amplab.cs.berkeley.edu/`](https://amplab.cs.berkeley.edu/)），旨在探索将 R 的易用性与 Spark 的可伸缩性相结合的不同技术。它作为 Apache Spark 1.4 中的一个 alpha 组件发布，该版本于 2015 年 6 月发布。Spark 1.5 版本改进了 R 的可用性，并引入了带有**广义线性模型**（**GLMs**）的 MLlib 机器学习包。2016 年 1 月发布的 Spark 1.6 版本增加了一些功能，例如模型摘要和特征交互。2016 年 7 月发布的 Spark 2.0 版本带来了一些重要功能，例如 UDF，改进的模型覆盖范围，DataFrames 窗口函数 API 等。

## 从 R 环境访问 SparkR

您可以从 R shell 或 R Studio 启动 SparkR。SparkR 的入口点是 SparkSession 对象，它表示与 Spark 集群的连接。运行 R 的节点成为驱动程序。由 R 程序创建的任何对象都驻留在此驱动程序上。通过 SparkSession 创建的任何对象都将创建在集群中的工作节点上。以下图表描述了 R 与运行在集群上的 Spark 的运行时视图。请注意，R 解释器存在于集群中的每个工作节点上。以下图表不显示集群管理器，也不显示存储层。您可以使用任何集群管理器（例如 Yarn 或 Mesos）和任何存储选项，例如 HDFS、Cassandra 或 Amazon S3：

![从 R 环境访问 SparkR](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_07_001.jpg)

来源：http://www.slideshare.net/Hadoop_Summit/w-145p210-avenkataraman。

通过传递应用程序名称、内存、核心数和要连接的集群管理器等信息来创建 SparkSession 对象。与 Spark 引擎的任何交互都是通过此 SparkSession 对象启动的。如果使用 SparkR shell，则已为您创建了 SparkSession 对象。否则，您必须显式创建它。此对象替换了 Spark 1.x 版本中存在的 SparkContext 和 SQLContext 对象。这些对象仍然存在以确保向后兼容性。即使前面的图表显示了 SparkContext，您也应该将其视为 Spark 2.0 之后的 SparkSession。

现在我们已经了解了如何从 R 环境访问 Spark，让我们来看看 Spark 引擎提供的核心数据抽象。

## RDD 和 DataFrames

在 Spark 引擎的核心是其主要数据抽象，称为**弹性分布式数据集**（**RDD**）。RDD 由一个或多个数据源组成，并由用户定义为对一个或多个稳定（具体）数据源的一系列转换（也称为血统）。每个 RDD 或 RDD 分区都知道如何使用血统图在失败时重新创建自己，从而提供容错性。RDD 是不可变的数据结构，这意味着它可以在线程之间共享而无需同步开销，因此适合并行化。RDD 上的操作要么是转换，要么是动作。转换是血统中的单个步骤。换句话说，它们是创建 RDD 的操作，因为每个转换都是从稳定数据源获取数据或转换不可变 RDD 并创建另一个 RDD。转换只是声明；直到对该 RDD 应用*动作*操作之前，它们才会被评估。动作是利用 RDD 的操作。

Spark 根据手头的动作优化 RDD 计算。例如，如果动作是读取第一行，只计算一个分区，跳过其余部分。它会自动执行内存计算，并在内存不足时将其溢出到磁盘，并在所有核心上分布处理。如果在程序逻辑中频繁访问 RDD，则可以对其进行缓存，从而避免重新计算开销。

R 语言提供了一个称为*DataFrame*的二维数据结构，使数据操作变得方便。Apache Spark 带有自己的 DataFrames，受到了 R 和 Python（通过 Pandas）中的 DataFrame 的启发。Spark DataFrame 是一种专门的数据结构，建立在 RDD 数据结构抽象之上。它提供了分布式 DataFrame 实现，从开发者的角度看，它看起来非常类似于 R DataFrame，同时可以支持非常大的数据集。Spark 数据集 API 为 DataFrame 添加了结构，这种结构在底层提供了更多的优化信息。

## 入门

现在我们已经了解了底层数据结构和运行时视图，是时候运行一些命令了。在本节中，我们假设您已经成功安装了 R 和 Spark，并将其添加到了路径中。我们还假设`SPARK_HOME`环境变量已设置。让我们看看如何从 R shell 或 R Studio 访问 SparkR：

```scala
> R  // Start R shell  
> Sys.getenv("SPARK_HOME") //Confirm SPARK_HOME is set 
  <Your SPARK_HOME path> 
> library(SparkR, lib.loc = 
    c(file.path(Sys.getenv("SPARK_HOME"), "R", "lib"))) 

Attaching package: 'SparkR' 
The following objects are masked from 'package:stats': 

    cov, filter, lag, na.omit, predict, sd, var, window 

The following objects are masked from 'package:base': 

    as.data.frame, colnames, colnames<-, drop, endsWith, intersect, 
    rank, rbind, sample, startsWith, subset, summary, transform, union 
> 

> //Try help(package=SparkR) if you want to more information 
//initialize SparkSession object 
>  sparkR.session()  
Java ref type org.apache.spark.sql.SparkSession id 1  
> 
Alternatively, you may launch sparkR shell which comes with predefined SparkSession. 

> bin/sparkR  // Start SparkR shell  
>      // For simplicity sake, no Log messages are shown here 
> //Try help(package=SparkR) if you want to more information 
> 

```

这就是您从 R 环境中访问 Spark DataFrames 的全部内容。

# 优势和限制

R 语言长期以来一直是数据科学家的通用语言。它简单易懂的 DataFrame 抽象、表达丰富的 API 和充满活力的包生态系统正是分析师所需要的。主要挑战在于可扩展性。SparkR 通过提供分布式内存中的 DataFrame 来弥合这一差距，而不会离开 R 生态系统。这种共生关系使用户能够获得以下好处：

+   分析师无需学习新语言

+   SparkR 的 API 与 R 的 API 类似

+   您可以从 R Studio 访问 SparkR，还可以使用自动完成功能

+   大规模数据集的交互式探索性分析不再受内存限制或长时间的等待时间的限制

+   从不同类型的数据源访问数据变得更加容易。大多数以前必须是命令式的任务现在已经变成了声明式的。查看[第四章](http://Chapter%204)，*统一数据访问*，了解更多信息

+   您可以自由混合 dplyr、Spark 函数、SQL 和仍未在 Spark 中可用的 R 库

尽管结合两者最好的优势令人兴奋，但这种组合仍然存在一些限制。这些限制可能不会影响每种用例，但我们无论如何都需要意识到它们：

+   R 的固有动态特性限制了可用于催化剂优化器的信息。与静态类型语言（如 Scala）相比，我们可能无法充分利用优化，例如谓词推回。

+   SparkR 不支持所有已经在其他 API（如 Scala API）中可用的机器学习算法。

总之，在数据预处理方面使用 Spark，而在分析和可视化方面使用 R 似乎是未来最好的方法。

# 使用 SparkR 进行编程

到目前为止，我们已经了解了 SparkR 的运行时模型和提供容错性和可扩展性的基本数据抽象。我们已经了解了如何从 R shell 或 R Studio 访问 Spark API。现在是时候尝试一些基本和熟悉的操作了：

```scala
> 
> //Open the shell 
> 
> //Try help(package=SparkR) if you want to more information 
> 
> df <- createDataFrame(iris) //Create a Spark DataFrame 
> df    //Check the type. Notice the column renaming using underscore 
SparkDataFrame[Sepal_Length:double, Sepal_Width:double, Petal_Length:double, Petal_Width:double, Species:string] 
> 
> showDF(df,4) //Print the contents of the Spark DataFrame 
+------------+-----------+------------+-----------+-------+ 
|Sepal_Length|Sepal_Width|Petal_Length|Petal_Width|Species| 
+------------+-----------+------------+-----------+-------+ 
|         5.1|        3.5|         1.4|        0.2| setosa| 
|         4.9|        3.0|         1.4|        0.2| setosa| 
|         4.7|        3.2|         1.3|        0.2| setosa| 
|         4.6|        3.1|         1.5|        0.2| setosa| 
+------------+-----------+------------+-----------+-------+ 
>  
> head(df,2)  //Returns an R data.frame. Default 6 rows 
  Sepal_Length Sepal_Width Petal_Length Petal_Width Species 
1          5.1         3.5          1.4         0.2  setosa 
2          4.9         3.0          1.4         0.2  setosa 
> //You can use take(df,2) to get the same results 
//Check the dimensions 
> nrow(df) [1] 150 > ncol(df) [1] 5 

```

操作看起来与 R DataFrame 函数非常相似，因为 Spark DataFrames 是基于 R DataFrames 和 Python（Pandas）DataFrames 建模的。但是，如果不小心，这种相似性可能会引起混淆。您可能会在 R 的`data.frame`上运行计算密集型函数，以为负载会被分布，从而意外地使本地机器崩溃。例如，intersect 函数在两个包中具有相同的签名。您需要注意对象是`SparkDataFrame`（Spark DataFrame）还是`data.frame`（R DataFrame）。您还需要尽量减少本地 R `data.frame`对象和 Spark DataFrame 对象之间的来回转换。让我们通过尝试一些示例来感受这种区别：

```scala
> 
> //Open the SparkR shell 
> df <- createDataFrame(iris) //Create a Spark DataFrame 
> class(df) [1] "SparkDataFrame" attr(,"package") [1] "SparkR" 
> df2 <- head(df,2) //Create an R data frame 
> class(df2) 
 [1] "data.frame" 
> //Now try running some R command on both data frames 
> unique(df2$Species)   //Works fine as expected [1] "setosa" > unique(df$Species)    //Should fail Error in unique.default(df$Species) : unique() applies only to vectors > class(df$Species)   //Each column is a Spark's Column class [1] "Column" attr(,"package") [1] "SparkR" > class(df2$Species) [1] "character" 

```

## 函数名称屏蔽

现在我们已经尝试了一些基本操作，让我们稍微偏离一下。我们必须了解当加载的库具有与基本包或已加载的其他包重叠的函数名称时会发生什么。有时这被称为函数名称重叠、函数屏蔽或名称冲突。您可能已经注意到在加载 SparkR 包时提到了被屏蔽的对象的消息。这对于加载到 R 环境中的任何包都很常见，不仅仅是 SparkR。如果 R 环境已经包含与要加载的包中的函数同名的函数，那么对该函数的任何后续调用都会表现出最新加载的包中函数的行为。如果您想访问以前的函数而不是`SparkR`函数，您需要显式使用其包名称作为前缀，如下所示：

```scala
//First try in R environment, without loading sparkR 
//Try sampling from a column in an R data.frame 
>sample(iris$Sepal.Length,6,FALSE) //Returns any n elements [1] 5.1 4.9 4.7 4.6 5.0 5.4 >sample(head(iris),3,FALSE) //Returns any 3 columns 
//Try sampling from an R data.frame 
//The Boolean argument is for with_replacement 
> sample(head 
> head(sample(iris,3,TRUE)) //Returns any 3 columns
  Species Species.1 Petal.Width
1  setosa    setosa         0.2 
2  setosa    setosa         0.2 
3  setosa    setosa         0.2 
4  setosa    setosa         0.2 
5  setosa    setosa         0.2 
6  setosa    setosa         0.4 

//Load sparkR, initialize sparkSession and then execute this  
> df <- createDataFrame(iris) //Create a Spark DataFrame 
> sample_df <- sample(df,TRUE,0.3) //Different signature 
> dim(sample_df)  //Different behavior [1] 44  5 
> //Returned 30% of the original data frame and all columns 
> //Try with base prefix 
> head(base::sample(iris),3,FALSE)  //Call base package's sample
  Species Petal.Width Petal.Length 
1  setosa         0.2          1.4
2  setosa         0.2          1.4 
3  setosa         0.2          1.3 
4  setosa         0.2          1.5 
5  setosa         0.2          1.4 
6  setosa         0.4          1.7 

```

## 子集数据

R DataFrame 上的子集操作非常灵活，SparkR 试图保留这些操作或类似的等价操作。我们已经在前面的示例中看到了一些操作，但本节以有序的方式呈现它们：

```scala
//Subsetting data examples 
> b1 <- createDataFrame(beaver1) 
//Get one column 
> b1$temp 
Column temp    //Column class and not a vector 
> //Select some columns. You may use positions too 
> select(b1, c("day","temp")) 
SparkDataFrame[day:double, temp:double] 
>//Row subset based on conditions 
> head(subset(b1,b1$temp>37,select= c(2,3))) 
  time  temp 
1 1730 37.07 
2 1740 37.05 
3 1940 37.01 
4 1950 37.10 
5 2000 37.09 
6 2010 37.02 
> //Multiple conditions with AND and OR 
> head(subset(b1, between(b1$temp,c(36.0,37.0)) |  
        b1$time %in% 900 & b1$activ == 1,c(2:4)),2) 
 time  temp activ 
1  840 36.33     0 
2  850 36.34     0 

```

### 提示

在撰写本书时（Apache Spark 2.0 发布），基于行索引的切片不可用。您将无法使用`df[n,]`或`df[m:n,]`语法获取特定行或行范围。

```scala
//For example, try on a normal R data.frame 
> beaver1[2:4,] 
  day time  temp activ 
2 346  850 36.34     0 
3 346  900 36.35     0 
4 346  910 36.42     0 
//Now, try on Spark Data frame 
> b1[2:4,] //Throws error 
Expressions other than filtering predicates are not supported in the first parameter of extract operator [ or subset() method. 
> 

```

## 列函数

您可能已经注意到在子集数据部分中的列函数`between`。这些函数在`Column`类上操作。正如名称所示，这些函数一次在单个列上操作，并且通常用于子集 DataFrame。除了在列内的值上工作之外，您还可以将列附加到 DataFrame 或从 DataFrame 中删除一个或多个列。负列下标可以用于省略列，类似于 R。以下示例展示了在子集操作中使用`Column`类函数，然后添加和删除列：

```scala
> //subset using Column operation using airquality dataset as df 
> head(subset(df,isNull(df$Ozone)),2) 
  Ozone Solar_R Wind Temp Month Day 
1    NA      NA 14.3   56     5   5 
2    NA     194  8.6   69     5  10 
> 
> //Add column and drop column examples 
> b1 <- createDataFrame(beaver1) 

//Add new column 
> b1$inRetreat <- otherwise(when(b1$activ == 0,"No"),"Yes") 
 head(b1,2) 
  day time  temp activ inRetreat 
1 346  840 36.33     0        No 
2 346  850 36.34     0        No 
> 
//Drop a column.  
> b1$day <- NULL 
> b1  // Example assumes b1$inRetreat does not exist 
SparkDataFrame[time:double, temp:double, activ:double] 
> //Drop columns using negative subscripts 
> b2 <- b1[,-c(1,4)]  > head(b2) 
   time  temp 
1  840 36.33 
2  850 36.34 
3  900 36.35 
4  910 36.42 
5  920 36.55 
6  930 36.69 
>  

```

## 分组数据

DataFrame 数据可以使用`group_by`函数进行分组，类似于 SQL。执行此类操作的多种方式。我们在本节中介绍了一个稍微复杂的示例。此外，我们使用了`magrittr`库提供的`%>%`，也称为前向管道运算符，它提供了一个链接命令的机制：

```scala
> //GroupedData example using iris data as df 
> //Open SparkR shell and create df using iris dataset  
> groupBy(df,"Species") 
GroupedData    //Returns GroupedData object 
> library(magrittr)  //Load the required library 
//Get group wise average sepal length 
//Report results sorted by species name 
>df2 <- df %>% groupBy("Species") %>%  
          avg("Sepal_Length") %>%  
          withColumnRenamed("avg(Sepal_Length)","avg_sepal_len") %>% 
          orderBy ("Species") 
//Format the computed double column 
df2$avg_sepal_len <- format_number(df2$avg_sepal_len,2) 
showDF(df2) 
+----------+-------------+ 
|   Species|avg_sepal_len| 
+----------+-------------+ 
|    setosa|         5.01| 
|versicolor|         5.94| 
| virginica|         6.59| 
+----------+-------------+ 

```

您可以继续使用前向管道运算符链接操作。仔细查看代码中的列重命名部分。列名参数是前面操作的输出，在此操作开始之前已经完成，因此您可以安全地假定`avg(sepal_len)`列已经存在。`format_number`按预期工作，这是另一个方便的`Column`操作。

下一节有一个类似的示例，使用`GroupedData`及其等效的`dplyr`实现。

# SparkR DataFrames

在本节中，我们尝试一些有用的常用操作。首先，我们尝试传统的 R/`dplyr`操作，然后展示使用 SparkR API 的等效操作：

```scala
> //Open the R shell and NOT SparkR shell  
> library(dplyr,warn.conflicts=FALSE)  //Load dplyr first 
//Perform a common, useful operation  
> iris %>%               
+   group_by(Species) %>% +   summarise(avg_length = mean(Sepal.Length),  
+             avg_width = mean(Sepal.Width)) %>% +   arrange(desc(avg_length)) 
Source: local data frame [3 x 3] 
     Species avg_length avg_width 
      (fctr)      (dbl)     (dbl) 
1  virginica      6.588     2.974 
2 versicolor      5.936     2.770 
3     setosa      5.006     3.428 

//Remove from R environment 
> detach("package:dplyr",unload=TRUE) 

```

此操作与 SQL 分组非常相似，并且后跟排序。它在 SparkR 中的等效实现也与`dplyr`示例非常相似。查看以下示例。注意方法名称并将其与前面的`dplyr`示例进行比较：

```scala
> //Open SparkR shell and create df using iris dataset  
> collect(arrange(summarize(groupBy(df,df$Species),  +     avg_sepal_length = avg(df$Sepal_Length), +     avg_sepal_width = avg(df$Sepal_Width)), +     "avg_sepal_length", decreasing = TRUE))  
     Species avg_sepal_length avg_sepal_width 
1     setosa            5.006           3.428 
2 versicolor            5.936           2.770 
3  virginica            6.588           2.974 

```

SparkR 旨在尽可能接近现有的 R API。因此，方法名称看起来与`dplyr`方法非常相似。例如，看看具有`groupBy`的示例，而`dplyr`具有`group_by`。SparkR 支持冗余函数名称。例如，它有`group_by`以及`groupBy`，以满足来自不同编程环境的开发人员。`dplyr`和 SparkR 中的方法名称再次非常接近 SQL 关键字`GROUP BY`。但是这些方法调用的顺序不同。示例还显示了将 Spark DataFrame 转换为 R `data.frame`的附加步骤，使用`collect`。这些方法是从内到外排列的，意思是首先对数据进行分组，然后进行汇总，然后进行排列。这是可以理解的，因为在 SparkR 中，内部方法中创建的 DataFrame 成为其直接前任的参数，依此类推。

## SQL 操作

如果您对前面示例中的语法不太满意，您可能希望尝试编写一个 SQL 字符串，如所示，它与前面的示例完全相同，但使用了传统的 SQL 语法：

```scala
> //Register the Spark DataFrame as a table/View 
> createOrReplaceTempView(df,"iris_vw")  
//Look at the table structure and some rows
> collect(sql(sqlContext, "SELECT * FROM iris_tbl LIMIT 5"))
    Sepal_Length Sepal_Width Petal_Length Petal_Width Species 
1          5.1         3.5          1.4         0.2  setosa 
2          4.9         3.0          1.4         0.2  setosa 
3          4.7         3.2          1.3         0.2  setosa 
4          4.6         3.1          1.5         0.2  setosa 
5          5.0         3.6          1.4         0.2  setosa 
> //Try out the above example using SQL syntax 
> collect(sql(sqlContext, "SELECT Species,       avg(Sepal_Length) avg_sepal_length,      avg(Sepal_Width) avg_sepal_width       FROM iris_tbl        GROUP BY Species       ORDER BY avg_sepal_length desc")) 

  Species avg_sepal_length avg_sepal_width 

1  virginica            6.588           2.974 
2 versicolor            5.936           2.770 
3     setosa            5.006           3.428 

```

如果您习惯从 RDBMS 表中获取数据，前面的示例看起来像是实现手头操作的最自然方式。但我们是如何做到这一点的呢？第一条语句告诉 Spark 注册一个临时表（或者，如其名称所示，一个视图，表的逻辑抽象）。这并不完全等同于数据库表。它是临时的，意味着在销毁 SparkSession 对象时会被销毁。您并没有将数据明确写入任何 RDBMS 数据存储（您必须使用`SaveAsTable`）。但是一旦您将 Spark DataFrame 注册为临时表，就可以自由地使用 SQL 语法对该 DataFrame 进行操作。下一条语句是一个基本的`SELECT`语句，显示列名，然后是五行，由`LIMIT`关键字指定。下一个 SQL 语句创建了一个包含 Species 列的 Spark DataFrame，后跟两个平均列，按平均萼片长度排序。然后，通过使用 collect 将此 DataFrame 作为 R `data.frame`收集。最终结果与前面的示例完全相同。您可以自由选择使用任何语法。有关更多信息和示例，请查看[第四章](http://chapter%204)中的 SQL 部分，*统一数据访问*。

## 集合操作

SparkR 中可以直接使用常见的集合操作，如`union`、`intersection`和`minus`。实际上，当加载 SparkR 时，警告消息显示`intersect`作为其中一个屏蔽函数。以下示例基于`beaver`数据集：

```scala
> //Create b1 and b2 DataFrames using beaver1 and beaver2 datasets 
> b1 <- createDataFrame(beaver1) 
> b2 <- createDataFrame(beaver2) 
//Get individual and total counts 
> > c(nrow(b1), nrow(b2), nrow(b1) + nrow(b2)) 
[1] 114 100 214 
//Try adding both data frames using union operation 
> nrow(unionAll(b1,b2)) 
[1] 214     //Sum of two datsets 
> //intersect example 
//Remove the first column (day) and find intersection 
showDF(intersect(b1[,-c(1)],b2[,-c(1)])) 

+------+-----+-----+ 
|  time| temp|activ| 
+------+-----+-----+ 
|1100.0|36.89|  0.0| 
+------+-----+-----+ 
> //except (minus or A-B) is covered in machine learning examples   

```

## 合并 DataFrame

下一个示例说明了使用`merge`命令连接两个 DataFrame。示例的第一部分显示了 R 的实现，下一部分显示了 SparkR 的实现：

```scala
> //Example illustrating data frames merging using R (Not SparkR) 
> //Create two data frames with a matching column 
//Products df with two rows and two columns 
> products_df <- data.frame(rbind(c(101,"Product 1"), 
                    c(102,"Product 2"))) 
> names(products_df) <- c("Prod_Id","Product") 
> products_df 
 Prod_Id   Product 
1     101 Product 1 
2     102 Product 2 

//Sales df with sales for each product and month 24x3 
> sales_df <- data.frame(cbind(rep(101:102,each=12), month.abb, 
                    sample(1:10,24,replace=T)*10)) 
> names(sales_df) <- c("Prod_Id","Month","Sales") 

//Look at first 2 and last 2 rows in the sales_df 
> sales_df[c(1,2,23,24),] 
   Prod_Id Month Sales 
1      101   Jan    60 
2      101   Feb    40 
23     102   Nov    20 
24     102   Dec   100 

> //merge the data frames and examine the data 
> total_df <- merge(products_df,sales_df) 
//Look at the column names 
> colnames(total_df) 
> [1] "Prod_Id" "Product" "Month"   "Sales" 

//Look at first 2 and last 2 rows in the total_df 
> total_df[c(1,2,23,24),]     
   Prod_Id   Product Month Sales 
1      101 Product 1   Jan    10 
2      101 Product 1   Feb    20 
23     102 Product 2   Nov    60 
24     102 Product 2   Dec    10 

```

上述代码完全依赖于 R 的基本包。为简单起见，我们在两个 DataFrame 中使用了相同的连接列名称。下一段代码演示了使用 SparkR 的相同示例。它看起来与前面的代码类似，因此请仔细查看其中的区别：

```scala
> //Example illustrating data frames merging using SparkR 
> //Create an R data frame first and then pass it on to Spark 
> //Watch out the base prefix for masked rbind function 
> products_df <- createDataFrame(data.frame( 
    base::rbind(c(101,"Product 1"), 
    c(102,"Product 2")))) 
> names(products_df) <- c("Prod_Id","Product") 
>showDF(products_df) 
+-------+---------+ 
|Prod_Id|  Product| 
+-------+---------+ 
|    101|Product 1| 
|    102|Product 2| 
+-------+---------+ 
> //Create Sales data frame 
> //Notice the as.data.frame similar to other R functions 
> //No cbind in SparkR so no need for base:: prefix 
> sales_df <- as.DataFrame(data.frame(cbind( 
             "Prod_Id" = rep(101:102,each=12), 
"Month" = month.abb, 
"Sales" = base::sample(1:10,24,replace=T)*10))) 
> //Check sales dataframe dimensions and some random rows  
> dim(sales_df) 
[1] 24  3 
> collect(sample(sales_df,FALSE,0.20)) 
  Prod_Id Month Sales 
1     101   Sep    50 
2     101   Nov    80 
3     102   Jan    90 
4     102   Jul   100 
5     102   Nov    20 
6     102   Dec    50 
> //Merge the data frames. The following merge is from SparkR library 
> total_df <- merge(products_df,sales_df) 
// You may try join function for the same purpose 
//Look at the columns in total_df 
> total_df 
SparkDataFrame[Prod_Id_x:string, Product:string, Prod_Id_y:string, Month:string, Sales:string] 
//Drop duplicate column 
> total_df$Prod_Id_y <- NULL    
> head(total_df) 
  Prod_Id_x   Product Month Sales 
1       101 Product 1   Jan    40 
2       101 Product 1   Feb    10 
3       101 Product 1   Mar    90 
4       101 Product 1   Apr    10 
5       101 Product 1   May    50 
6       101 Product 1   Jun    70 
> //Note: As of Spark 2.0 version, SparkR does not support 
    row sub-setting  

```

您可能想尝试不同类型的连接，例如左外连接和右外连接，或不同的列名，以更好地理解此函数。

# 机器学习

SparkR 提供了现有 MLLib 函数的包装器。R 公式被实现为 MLLib 特征转换器。转换器是一个 ML 管道（`spark.ml`）阶段，它以 DataFrame 作为输入并产生另一个 DataFrame 作为输出，通常包含一些附加列。特征转换器是一种将输入列转换为特征向量的转换器，这些特征向量被附加到源 DataFrame。例如，在线性回归中，字符串输入列被独热编码，数值被转换为双精度数。标签列将被附加（如果数据框中没有的话）作为响应变量的副本。

在这一部分，我们涵盖了朴素贝叶斯和高斯 GLM 模型的示例代码。我们不解释模型本身或它们产生的摘要。相反，我们直接讨论如何使用 SparkR 来完成这些操作。

## 朴素贝叶斯模型

朴素贝叶斯模型是一个直观简单的模型，适用于分类数据。我们将使用朴素贝叶斯模型训练一个样本数据集。我们不会解释模型的工作原理，而是直接使用 SparkR 来训练模型。如果您想要更多信息，请参考第六章 *机器学习*。

这个例子使用了一个包含二十名学生的平均分数和出勤情况的数据集。实际上，这个数据集已经在[第六章](http://Chapter%206) *机器学习*中被引入，用于训练集成。然而，让我们重新审视一下它的内容。

学生根据一组明确定义的规则被授予`及格`或`不及格`。两名 ID 为`1009`和`1020`的学生被授予`及格`，即使在其他情况下他们本来会不及格。尽管我们没有向模型提供实际规则，但我们期望模型预测这两名学生的结果为`不及格`。以下是`及格`/`不及格`的标准：

+   分数 < 40 => 不及格

+   出勤不足 => 不及格

+   分数超过 40 且出勤全 => 及格

+   分数 > 60 且至少出勤足够 => 及格以下是训练朴素贝叶斯模型的示例：

```scala
//Example to train NaÃ¯ve Bayes model 

//Read file 
> myFile <- read.csv("../work/StudentsPassFail.csv") //R data.frame 
> df <- createDataFrame(myFile) //sparkDataFrame 
//Look at the data 
> showDF(df,4) 
+---------+---------+----------+------+ 
|StudentId|Avg_Marks|Attendance|Result| 
+---------+---------+----------+------+ 
|     1001|     48.0|      Full|  Pass| 
|     1002|     21.0|    Enough|  Fail| 
|     1003|     24.0|    Enough|  Fail| 
|     1004|      4.0|      Poor|  Fail| 
+---------+---------+----------+------+ 

//Make three buckets out of Avg_marks 
// A >60; 40 < B < 60; C > 60 
> df$marks_bkt <- otherwise(when(df$Avg_marks < 40, "C"), 
                           when(df$Avg_marks > 60, "A")) 
> df$marks_bkt <- otherwise(when(df$Avg_marks < 40, "C"), 
                           when(df$Avg_marks > 60, "A")) 
> df <- fillna(df,"B",cols="marks_bkt") 
//Split train and test 
> trainDF <- sample(df,TRUE,0.7) 
> testDF <- except(df, trainDF) 

//Build model by supplying RFormula, training data 
> model <- spark.naiveBayes(Result ~ Attendance + marks_bkt, data = trainDF) 
> summary(model) 
$apriori 
          Fail      Pass 
[1,] 0.6956522 0.3043478 

$tables 
     Attendance_Poor Attendance_Full marks_bkt_C marks_bkt_B 
Fail 0.5882353       0.1764706       0.5882353   0.2941176   
Pass 0.125           0.875           0.125       0.625       

//Run predictions on test data 
> predictions <- predict(model, newData= testDF) 
//Examine results 
> showDF(predictions[predictions$Result != predictions$prediction, 
     c("StudentId","Attendance","Avg_Marks","marks_bkt", "Result","prediction")]) 
+---------+----------+---------+---------+------+----------+                     
|StudentId|Attendance|Avg_Marks|marks_bkt|Result|prediction| 
+---------+----------+---------+---------+------+----------+ 
|     1010|      Full|     19.0|        C|  Fail|      Pass| 
|     1019|    Enough|     45.0|        B|  Fail|      Pass| 
|     1014|      Full|     12.0|        C|  Fail|      Pass| 
+---------+----------+---------+---------+------+----------+ 
//Note that the predictions are not exactly what we anticipate but models are usually not 100% accurate 

```

## 高斯 GLM 模型

在这个例子中，我们尝试根据臭氧、太阳辐射和风的值来预测温度：

```scala
> //Example illustrating Gaussian GLM model using SparkR 
> a <- createDataFrame(airquality) 
//Remove rows with missing values 
> b <- na.omit(a) 
> //Inspect the dropped rows with missing values 
> head(except(a,b),2)    //MINUS set operation 
  Ozone Solar_R Wind Temp Month Day 
1    NA     186  9.2   84     6   4 
2    NA     291 14.9   91     7  14 

> //Prepare train data and test data 
traindata <- sample(b,FALSE,0.8) //Not base::sample 
testdata <- except(b,traindata) 

> //Build model 
> model <- glm(Temp ~ Ozone + Solar_R + Wind,  
          data = traindata, family = "gaussian") 
> // Get predictions 
> predictions <- predict(model, newData = testdata) 
> head(predictions[,c(predictions$Temp, predictions$prediction)], 
                 5) 
  Temp prediction 
1   90   81.84338 
2   79   80.99255 
3   88   85.25601 
4   87   76.99957 
5   76   71.75683 

```

# 总结

到目前为止，SparkR 不支持 Spark 中所有可用的算法，但正在积极开发以弥合差距。Spark 2.0 版本已经改进了算法覆盖范围，包括朴素贝叶斯、k 均值聚类和生存回归。查看最新的支持算法文档。在将来，我们将继续努力推出 SparkR 的 CRAN 版本，更好地与 R 包和 Spark 包集成，并提供更好的 RFormula 支持。

# 参考资料

+   *SparkR: 过去、现在和未来* 作者 *Shivaram Venkataraman: *[`shivaram.org/talks/sparkr-summit-2015.pdf`](http://shivaram.org/talks/sparkr-summit-2015.pdf)

+   *通过 Spark 和 R 实现探索性数据科学* 作者 *Shivaram Venkataraman* 和 *Hossein Falaki:*[`www.slideshare.net/databricks/enabling-exploratory-data-science-with-spark-and-r`](http://www.slideshare.net/databricks/enabling-exploratory-data-science-with-spark-and-r)

+   *SparkR: 用 Spark 扩展 R 程序* 作者 *Shivaram Venkataraman* 和其他人: [`shivaram.org/publications/sparkr-sigmod.pdf`](http://shivaram.org/publications/sparkr-sigmod.pdf)

+   *SparkR 的最新发展* 作者 *Xiangrui Meng*: [`files.meetup.com/4439192/Recent%20Development%20in%20SparkR%20for%20Advanced%20Analytics.pdf`](http://files.meetup.com/4439192/Recent%20Development%20in%20SparkR%20for%20Advanced%20Analytics.pdf)

+   要了解 RFormula，请尝试以下链接：

+   [`stat.ethz.ch/R-manual/R-devel/library/stats/html/formula.html`](https://stat.ethz.ch/R-manual/R-devel/library/stats/html/formula.html)

+   [`spark.apache.org/docs/latest/ml-features.html#rformula`](http://spark.apache.org/docs/latest/ml-features.html#rformula)


# 第八章：分析非结构化数据

在这个大数据时代，非结构化数据的激增是令人震惊的。存在许多方法，如数据挖掘、自然语言处理（NLP）、信息检索等，用于分析非结构化数据。由于各种业务中非结构化数据的快速增长，可扩展的解决方案已成为当务之急。Apache Spark 配备了用于文本分析的开箱即用算法，并支持自定义开发默认情况下不可用的算法。

在上一章中，我们已经展示了 SparkR 如何利用 Spark 的 R API 来发挥其强大功能，而无需学习一种新语言。在本章中，我们将步入一个全新的维度，探索利用 Spark 从非结构化数据中提取信息的算法和技术。

作为本章的先决条件，对 Python 或 Scala 编程的基本理解以及对文本分析和机器学习的整体理解是很有帮助的。然而，我们已经涵盖了一些理论基础，并提供了一套实际示例，使其更易于理解和实施。本章涵盖的主题包括：

+   非结构化数据的来源

+   处理非结构化数据

+   计数向量化器

+   TF-IDF

+   停用词去除

+   归一化/缩放

+   Word2Vec

+   n-gram 建模

+   文本分类

+   朴素贝叶斯分类器

+   文本聚类

+   K 均值

+   降维

+   奇异值分解

+   主成分分析

+   总结

# 非结构化数据的来源

自上世纪八九十年代的电子表格和商业智能工具以来，数据分析已经取得了长足的进步。计算能力的巨大提升、复杂算法和开源文化的推动，促成了数据分析以及其他领域的前所未有的增长。这些技术的进步为新的机遇和新的挑战铺平了道路。企业开始着眼于从以往难以处理的数据源中生成见解，如内部备忘录、电子邮件、客户满意度调查等。数据分析现在包括这种非结构化的、通常是基于文本的数据，以及传统的行和列数据。在关系型数据库管理系统表中存储的高度结构化数据和完全非结构化的纯文本之间，我们有 NoSQL 数据存储、XML 或 JSON 文档以及图形或网络数据源等半结构化数据源。根据目前的估计，非结构化数据约占企业数据的 80%，并且正在迅速增长。卫星图像、大气数据、社交网络、博客和其他网页、患者记录和医生笔记、公司内部通信等等 - 所有这些组合只是非结构化数据源的一个子集。

我们已经看到了成功利用非结构化数据和结构化数据的数据产品。一些公司利用社交网络的力量为他们的客户提供可操作的见解。新兴领域，如情感分析和多媒体分析，正在从非结构化数据中获取见解。然而，分析非结构化数据仍然是一项艰巨的任务。例如，当代文本分析工具和技术无法识别讽刺。然而，潜在的好处无疑超过了局限性。

# 处理非结构化数据

非结构化数据不适用于大多数编程任务。它必须以各种不同的方式进行处理，以便作为任何机器学习算法的输入或进行可视化分析。广义上，非结构化数据分析可以被视为以下图表所示的一系列步骤：

![处理非结构化数据](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_08_001.jpg)

数据预处理是任何非结构化数据分析中最关键的步骤。幸运的是，随着时间的积累，已经积累了几种被证明有效的技术，这些技术非常有用。Spark 通过`ml.features`包提供了大部分这些技术。大多数技术旨在将文本数据转换为简洁的数字向量，这些向量可以轻松地被机器学习算法消化。开发人员应该了解其组织的具体要求，以确定最佳的预处理工作流程。请记住，更好、相关的数据是产生更好洞察的关键。

让我们探讨一些处理原始文本并将其转换为数据框的示例。第一个示例将一些文本作为输入并提取所有类似日期的字符串，而第二个示例从 twitter 文本中提取标签。第一个示例只是一个热身，使用简单的正则表达式分词器特征转换器，而不使用任何特定于 spark 的库。它还引起了您对可能的误解的注意。例如，形式为 1-11-1111 的产品代码可能被解释为日期。第二个示例说明了一个非平凡的、多步骤的提取过程，最终只得到了所需的标签。**用户定义的函数**（**udf**）和 ML 管道在开发这种多步骤的提取过程中非常有用。本节的其余部分描述了 apache Spark 中提供的一些更方便的工具。

**示例-1：** **从文本中提取类似日期的字符串**

**Scala**：

```scala
scala> import org.apache.spark.ml.feature.RegexTokenizer
import org.apache.spark.ml.feature.RegexTokenizer
scala> val date_pattern: String = "\\d{1,4}[/ -]\\d{1,4}[/ -]\\d{1,4}"
date_pattern: String = \d{1,4}[/ -]\d{1,4}[/ -]\d{1,4}
scala> val textDF  = spark.createDataFrame(Seq(
    (1, "Hello 1996-12-12 this 1-21-1111 is a 18-9-96 text "),
    (2, "string with dates in different 01/02/89 formats"))).
    toDF("LineNo","Text")
textDF: org.apache.spark.sql.DataFrame = [LineNo: int, Text: string]
scala> val date_regex = new RegexTokenizer().
        setInputCol("Text").setOutputCol("dateStr").
        setPattern(date_pattern).setGaps(false)
date_regex: org.apache.spark.ml.feature.RegexTokenizer = regexTok_acdbca6d1c4c
scala> date_regex.transform(textDF).select("dateStr").show(false)
+--------------------------------+
|dateStr                         |
+--------------------------------+
|[1996-12-12, 1-21-1111, 18-9-96]|
|[01/02/89]                      |
+--------------------------------+
```

**Python**：

```scala
// Example-1: Extract date like strings from text
>>> from pyspark.ml.feature import RegexTokenizer
>>> date_pattern = "\\d{1,4}[/ -]\\d{1,4}[/ -]\\d{1,4}"
>>> textDF  = spark.createDataFrame([
        [1, "Hello 1996-12-12 this 1-21-1111 is a 18-9-96 text "],
        [2, "string with dates in different 01/02/89 formats"]]).toDF(
        "LineNo","Text")
>>> date_regex = RegexTokenizer(inputCol="Text",outputCol="dateStr",
            gaps=False, pattern=date_pattern)
>>> date_regex.transform(textDF).select("dateStr").show(5,False)
+--------------------------------+
|dateStr                         |
+--------------------------------+
|[1996-12-12, 1-21-1111, 18-9-96]|
|[01/02/89]                      |
+--------------------------------+
```

前面的例子定义了一个正则表达式模式，用于识别日期字符串。正则表达式模式和示例文本 DataFrame 被传递给`RegexTokenizer`以提取匹配的日期字符串。`gaps=False`选项选择匹配的字符串，`False`的值将使用给定的模式作为分隔符。请注意，显然不是日期的`1-21-1111`也被选中。

下一个示例从 twitter 文本中提取标签并识别最流行的标签。您也可以使用相同的方法收集哈希（`#`）标签。

此示例使用内置函数`explode`，它将单个具有值数组的行转换为多个行，每个数组元素一个值。

**示例-2：从 twitter“文本”中提取标签**

**Scala**：

```scala
//Step1: Load text containing @ from source file
scala> val path = "<Your path>/tweets.json"
path: String = <Your path>/tweets.json
scala> val raw_df = spark.read.text(path).filter($"value".contains("@"))
raw_df: org.apache.spark.sql.Dataset[org.apache.spark.sql.Row] = [value: string]
//Step2: Split the text to words and filter out non-tag words
scala> val df1 = raw_df.select(explode(split('value, " ")).as("word")).
        filter($"word".startsWith("@"))
df1: org.apache.spark.sql.Dataset[org.apache.spark.sql.Row] = [word: string]
//Step3: compute tag-wise counts and report top 5
scala> df1.groupBy($"word").agg(count($"word")).
        orderBy($"count(word)".desc).show(5)
+------------+-----------+
+                                                     
|        word|count(word)|
+------------+-----------+
|@ApacheSpark|         15|
|    @SSKapci|          9|
|@databricks:|          4|
|     @hadoop|          4|
| @ApacheApex|          4|
+------------+-----------+
```

**Python**：

```scala
>> from pyspark.sql.functions import explode, split
//Step1: Load text containing @ from source file
>>> path ="<Your path>/tweets.json"
>>> raw_df1 = spark.read.text(path)
>>> raw_df = raw_df1.where("value like '%@%'")
>>> 
//Step2: Split the text to words and filter out non-tag words
>>> df = raw_df.select(explode(split("value"," ")))
>>> df1 = df.where("col like '@%'").toDF("word")
>>> 
//Step3: compute tag-wise counts and report top 5
>>> df1.groupBy("word").count().sort(
     "count",ascending=False).show(5)
+------------+-----+
+                                                        
|        word|count|
+------------+-----+
|@ApacheSpark|   15|
|    @SSKapci|    9|
|@databricks:|    4|
| @ApacheApex|    4|
|     @hadoop|    4|
+------------+-----+

```

## 计数向量化器

计数向量化器从文档中提取词汇（标记）并在没有字典的情况下生成`CountVectorizerModel`模型。正如其名称所示，文本文档被转换为标记和计数的向量。该模型生成文档对词汇的稀疏表示。

您可以微调行为以限制词汇量大小、最小标记计数等，使其适用于您的业务案例。

//示例 3：计数向量化器示例

**Scala**

```scala
scala> import org.apache.spark.ml.feature.{CountVectorizer, CountVectorizerModel}
import org.apache.spark.ml.feature.{CountVectorizer, CountVectorizerModel}
scala> import org.apache.spark.sql.DataFrame
import org.apache.spark.sql.DataFrame
scala> import org.apache.spark.ml.linalg.Vector
import org.apache.spark.ml.linalg.Vector
scala> val df: DataFrame = spark.createDataFrame(Seq(
  (0, Array("ant", "bat", "cat", "dog", "eel")),
  (1, Array("dog","bat", "ant", "bat", "cat"))
)).toDF("id", "words")
df: org.apache.spark.sql.DataFrame = [id: int, words: array<string>]
scala>
// Fit a CountVectorizerModel from the corpus 
// Minimum occurrences (DF) is 2 and pick 10 top words(vocabsize) only scala> val cvModel: CountVectorizerModel = new CountVectorizer().
        setInputCol("words").setOutputCol("features").
        setMinDF(2).setVocabSize(10).fit(df)
cvModel: org.apache.spark.ml.feature.CountVectorizerModel = cntVec_7e79157ba561
// Check vocabulary. Words are arranged as per frequency 
// eel is dropped because it is below minDF = 2 scala> cvModel.vocabulary
res6: Array[String] = Array(bat, dog, cat, ant)
//Apply the model on document
scala> val cvDF: DataFrame = cvModel.transform(df)
cvDF: org.apache.spark.sql.DataFrame = [id: int, words: array<string> ... 1 more field]
//Check the word count scala> cvDF.select("features").collect().foreach(row =>
println(row(0).asInstanceOf[Vector].toDense))

[1.0,1.0,1.0,1.0]
[2.0,1.0,1.0,1.0]
```

**Python**：

```scala
>>> from pyspark.ml.feature import CountVectorizer,CountVectorizerModel
>>> from pyspark.ml.linalg import Vector
>>> 
// Define source DataFrame
>>> df = spark.createDataFrame([
    [0, ["ant", "bat", "cat", "dog", "eel"]],
    [1, ["dog","bat", "ant", "bat", "cat"]]
  ]).toDF("id", "words")
>>> 
// Fit a CountVectorizerModel from the corpus
// Minimum occorrences (DF) is 2 and pick 10 top words(vocabsize) only
>>> cvModel = CountVectorizer(inputCol="words", outputCol="features",
        minDF = 2, vocabSize = 10).fit(df)
>>> 
// Check vocabulary. Words are arranged as per frequency
// eel is dropped because it is below minDF = 2
>>> cvModel.vocabulary
[u'bat', u'ant', u'cat', u'dog']
//Apply the model on document
>>> cvDF = cvModel.transform(df)
//Check the word count
>>> cvDF.show(2,False)
+---+-------------------------+-------------------------------+
|id |words                    |features                       |
+---+-------------------------+-------------------------------+
|0  |[ant, bat, cat, dog, eel]|(4,[0,1,2,3],[1.0,1.0,1.0,1.0])|
|1  |[dog, bat, ant, bat, cat]|(4,[0,1,2,3],[2.0,1.0,1.0,1.0])|
+---+-------------------------+-------------------------------+
```

**输入**：

```scala
 |id | text                  
 +---+-------------------------+-------------------------------+
 |0  | "ant", "bat", "cat", "dog", "eel"     
 |1  | "dog","bat", "ant", "bat", "cat"
```

**输出**：

```scala
id| text                               | Vector 
--|------------------------------------|-------------------- 
0 | "ant", "bat", "cat", "dog", "eel" |[1.0,1.0,1.0,1.0] 
1 | "dog","bat", "ant", "bat", "cat"   |[2.0,1.0,1.0,1.0]

```

前面的例子演示了`CountVectorizer`作为估计器的工作原理，用于提取词汇并生成`CountVectorizerModel`。请注意，特征向量的顺序对应于词汇而不是输入序列。让我们也看看如何通过预先构建字典来实现相同的效果。但是，请记住它们有自己的用例。

示例 4：使用先验词汇定义 CountVectorizerModel

**Scala**：

```scala
// Example 4: define CountVectorizerModel with a-priori vocabulary
scala> val cvm: CountVectorizerModel = new CountVectorizerModel(
        Array("ant", "bat", "cat")).
        setInputCol("words").setOutputCol("features")
cvm: org.apache.spark.ml.feature.CountVectorizerModel = cntVecModel_ecbb8e1778d5

//Apply on the same data. Feature order corresponds to a-priory vocabulary order scala> cvm.transform(df).select("features").collect().foreach(row =>
        println(row(0).asInstanceOf[Vector].toDense))
[1.0,1.0,1.0]
[1.0,2.0,1.0]
```

**Python**：

截至 Spark 2.0.0 尚不可用

## TF-IDF

**词频-逆文档频率**（**TF-IDF**）可能是文本分析中最流行的度量之一。这个度量指示了给定术语在一组文档中的重要性。它包括两个度量，**词频**（**TF**）和**逆文档频率**（**IDF**）。让我们逐一讨论它们，然后看看它们的综合效果。

TF 是一个词在文档中相对重要性的度量，通常是该词频率除以文档中的词数。假设一个文本文档包含 100 个单词，其中单词*apple*出现了八次。*apple*的 TF 将是*TF = (8 / 100) = 0.08*。因此，一个词在文档中出现的频率越高，其 TF 系数就越大。

IDF 是一个词在整个文档集合中的重要性的度量，也就是说，这个词在所有文档中出现的频率有多低。一个词的重要性与其频率成反比。Spark 提供了两种单独的方法来执行这些任务。假设我们有 600 万个文档，单词*apple*出现在其中的 6000 个文档中。那么，IDF 被计算为*IDF = Log(6,000,000 / 6,000) = 3*。如果你仔细观察这个例子，分母越小，IDF 值就越大。这意味着包含特定词的文档数量越少，它的重要性就越高。

因此，TF-IDF 得分将是*TF * IDF = 0.08 * 3 = 0.24*。请注意，它会惩罚在文档中更频繁出现且不重要的词，比如*the*、*this*、*a*等，并赋予更重要的词更大的权重。

在 Spark 中，TF 被实现为 HashingTF。它接受一系列术语（通常是分词器的输出）并产生一个固定长度的特征向量。它执行特征哈希将术语转换为固定长度的索引。然后 IDF 接受这些特征向量（HashingTF 的输出）作为输入，并根据文档集中的词频进行缩放。上一章有一个这种转换的示例。

## 停用词移除

常见的词如*is*、*was*和*the*被称为停用词。它们通常不会增加分析的价值，并且在数据准备阶段应该被删除。Spark 提供了`StopWordsRemover`转换器，它可以做到这一点。它接受一系列标记作为字符串输入的序列，比如分词器的输出，并移除所有的停用词。Spark 默认有一个停用词列表，你可以通过提供自己的停用词列表来覆盖它。你可以选择打开默认关闭的`caseSensitive`匹配。

示例 5：停用词移除

**Scala:**

```scala
scala> import org.apache.spark.ml.feature.StopWordsRemover
import org.apache.spark.ml.feature.StopWordsRemover
scala> import org.apache.spark.sql.DataFrame
import org.apache.spark.sql.DataFrame
scala> import org.apache.spark.ml.linalg.Vector
import org.apache.spark.ml.linalg.Vector
scala> val rawdataDF = spark.createDataFrame(Seq(
        (0, Array("I", "ate", "the", "cake")),
        (1, Array("John ", "had", "a", " tennis", "racquet")))).
        toDF("id","raw_text")
rawdataDF: org.apache.spark.sql.DataFrame = [id: int, raw_text: array<string>]
scala> val remover = new StopWordsRemover().setInputCol("raw_text").
                setOutputCol("processed_text")
remover: org.apache.spark.ml.feature.StopWordsRemover = stopWords_55edbac88edb
scala> remover.transform(rawdataDF).show(truncate=false)
+---+---------------------------------+-------------------------+
|id |raw_text                         |processed_text           |
+---+---------------------------------+-------------------------+
|0  |[I, ate, the, cake]              |[ate, cake]              |
|1  |[John , had, a,  tennis, racquet]|[John ,  tennis, racquet]|
+---+---------------------------------+-------------------------+
```

**Python:**

```scala
>>> from pyspark.ml.feature import StopWordsRemover
>>> RawData = sqlContext.createDataFrame([
    (0, ["I", "ate", "the", "cake"]),
    (1, ["John ", "had", "a", " tennis", "racquet"])
    ], ["id", "raw_text"])
>>> 
>>> remover = StopWordsRemover(inputCol="raw_text",
        outputCol="processed_text")
>>> remover.transform(RawData).show(truncate=False)
+---+---------------------------------+-------------------------+
|id |raw_text                         |processed_text           |
+---+---------------------------------+-------------------------+
|0  |[I, ate, the, cake]              |[ate, cake]              |
|1  |[John , had, a,  tennis, racquet]|[John ,  tennis, racquet]|
+---+---------------------------------+-------------------------+
```

假设我们有以下带有`id`和`raw_text`列的 DataFrame：

```scala
 id | raw_text 
----|---------- 
 0  | [I, ate, the, cake] 
 1  | [John, had, a, tennis, racquet] 

```

在对前面的示例应用`StopWordsRemover`，将`raw_text`作为输入列，`processed_text`作为输出列后，我们应该得到以下输出：

```scala

 id | raw_text                       | processed_text 
----|--------------------------------|-------------------- 
 0  | [I, ate, the, cake]            |  [ate, cake] 
 1  |[John, had, a, tennis, racquet] |[John, tennis, racquet] 

```

## 归一化/缩放

归一化是数据准备中常见的预处理步骤。大多数机器学习算法在所有特征处于相同尺度时效果更好。例如，如果有两个特征，其中一个的值大约是另一个的 100 倍，将它们调整到相同的尺度可以反映出两个变量之间有意义的相对活动。任何非数值的值，比如高、中、低，最好都转换为适当的数值量化作为最佳实践。然而，在这样做时需要小心，因为可能需要领域专业知识。例如，如果你为高、中、低分别分配 3、2 和 1，那么应该检查这三个单位是否相互等距。

特征归一化的常见方法包括*缩放*、*均值减法*和*特征标准化*，仅举几例。在缩放中，每个数值特征向量被重新缩放，使其值范围在*-1*到*+1*或*0*到*1*或类似的范围内。在均值减法中，你计算数值特征向量的均值，并从每个值中减去该均值。我们对相对于均值的相对偏差感兴趣，而绝对值可能并不重要。特征标准化是指将数据设置为零均值和单位（1）方差。

Spark 提供了`Normalizer`特征转换器，将每个向量归一化为单位范数；`StandardScaler`将单位范数和零均值；`MinMaxScaler`将每个特征重新缩放到特定范围的值。默认情况下，最小值和最大值为 0 和 1，但您可以根据数据要求自行设置值参数。

## Word2Vec

Word2Vec 是一种 PCA（您很快会了解更多）的类型，它接受一系列单词并生成一个映射（字符串，向量）。字符串是单词，向量是一个独特的固定大小的向量。生成的单词向量表示在许多机器学习和自然语言处理应用中非常有用，比如命名实体识别和标记。让我们看一个例子。

**示例 6：Word2Vec**

**Scala**

```scala
scala> import org.apache.spark.ml.feature.Word2Vec
import org.apache.spark.ml.feature.Word2Vec

//Step1: Load text file and split to words scala> val path = "<Your path>/RobertFrost.txt"
path: String = <Your path>/RobertFrost.txt
scala> val raw_text = spark.read.text(path).select(
        split('value, " ") as "words")
raw_text: org.apache.spark.sql.DataFrame = [words: array<string>]

//Step2: Prepare features vector of size 4 scala> val resultDF = new Word2Vec().setInputCol("words").
        setOutputCol("features").setVectorSize(4).
        setMinCount(2).fit(raw_text).transform(raw_text)
resultDF: org.apache.spark.sql.DataFrame = [words: array<string>, features: vector]

//Examine results scala> resultDF.show(5)
+--------------------+--------------------+
|               words|            features|
+--------------------+--------------------+
|[Whose, woods, th...|[-0.0209098898340...|
|[His, house, is, ...|[-0.0013444167044...|
|[He, will, not, s...|[-0.0058525378408...|
|[To, watch, his, ...|[-0.0189630933296...|
|[My, little, hors...|[-0.0084691265597...|
+--------------------+--------------------+
```

**Python:**

```scala
>>> from pyspark.ml.feature import Word2Vec
>>> from pyspark.sql.functions import explode, split
>>>

//Step1: Load text file and split to words >>> path = "<Your path>/RobertFrost.txt"
>>> raw_text = spark.read.text(path).select(
        split("value"," ")).toDF("words")

//Step2: Prepare features vector of size 4 >>> resultDF = Word2Vec(inputCol="words",outputCol="features",
                 vectorSize=4, minCount=2).fit(
                 raw_text).transform(raw_text)

//Examine results scala> resultDF.show(5)
+--------------------+--------------------+
|               words|            features|
+--------------------+--------------------+
|[Whose, woods, th...|[-0.0209098898340...|
|[His, house, is, ...|[-0.0013444167044...|
|[He, will, not, s...|[-0.0058525378408...|
|[To, watch, his, ...|[-0.0189630933296...|
|[My, little, hors...|[-0.0084691265597...|
+--------------------+--------------------+
```

## n-gram 建模

n-gram 是给定文本或语音序列中*n*个项目的连续序列。大小为*1*的 n-gram 称为*unigram*，大小为*2*的称为*bigram*，大小为*3*的称为*trigram*。或者，它们可以根据*n*的值来命名，例如 four-gram，five-gram 等。让我们看一个例子来理解这个模型可能的结果：

```scala

 input |1-gram sequence  | 2-gram sequence | 3-gram sequence 
-------|-----------------|-----------------|--------------- 
 apple | a,p,p,l,e       |  ap,pp,pl,le    |  app,ppl,ple 

```

这是一个单词到 n-gram 字母的例子。对于句子（或标记化的单词）到 n-gram 单词也是一样的。例如，句子*Kids love to eat chocolates*的 2-gram 等效于：

'Kids love', 'love to', 'to eat', 'eat chocolates'.

n-gram 建模在文本挖掘和自然语言处理中有各种应用。其中一个例子是预测每个单词在先前上下文中出现的概率（条件概率）。

在 Spark 中，`NGram`是一个特征转换器，它将字符串的输入数组（例如，分词器的输出）转换为 n-gram 的数组。默认情况下，输入数组中的空值将被忽略。它返回一个 n-gram 的数组，其中每个 n-gram 由一个用空格分隔的单词字符串表示。

**示例 7：NGram**

**Scala**

```scala
scala> import org.apache.spark.ml.feature.NGram
import org.apache.spark.ml.feature.NGram
scala> val wordDF = spark.createDataFrame(Seq(
        (0, Array("Hi", "I", "am", "a", "Scientist")),
        (1, Array("I", "am", "just", "learning", "Spark")),
        (2, Array("Coding", "in", "Scala", "is", "easy"))
        )).toDF("label", "words")

//Create an ngram model with 3 words length (default is 2) scala> val ngramModel = new NGram().setInputCol(
                "words").setOutputCol("ngrams").setN(3)
ngramModel: org.apache.spark.ml.feature.NGram = ngram_dc50209cf693

//Apply on input data frame scala> ngramModel.transform(wordDF).select("ngrams").show(false)
+--------------------------------------------------+
|ngrams                                            |
+--------------------------------------------------+
|[Hi I am, I am a, am a Scientist]                 |
|[I am just, am just learning, just learning Spark]|
|[Coding in Scala, in Scala is, Scala is easy]     |
+--------------------------------------------------+

//Apply the model on another dataframe, Word2Vec raw_text scala>ngramModel.transform(raw_text).select("ngrams").take(1).foreach(println)
[WrappedArray(Whose woods these, woods these are, these are I, are I think, I think I, think I know.)]
```

**Python:**

```scala
>>> from pyspark.ml.feature import NGram
>>> wordDF = spark.createDataFrame([
         [0, ["Hi", "I", "am", "a", "Scientist"]],
         [1, ["I", "am", "just", "learning", "Spark"]],
         [2, ["Coding", "in", "Scala", "is", "easy"]]
         ]).toDF("label", "words")

//Create an ngram model with 3 words length (default is 2) >>> ngramModel = NGram(inputCol="words", outputCol= "ngrams",n=3)
>>> 

//Apply on input data frame >>> ngramModel.transform(wordDF).select("ngrams").show(4,False)
+--------------------------------------------------+
|ngrams                                            |
+--------------------------------------------------+
|[Hi I am, I am a, am a Scientist]                 |
|[I am just, am just learning, just learning Spark]|
|[Coding in Scala, in Scala is, Scala is easy]     |
+--------------------------------------------------+

//Apply the model on another dataframe from Word2Vec example >>> ngramModel.transform(resultDF).select("ngrams").take(1)
[Row(ngrams=[u'Whose woods these', u'woods these are', u'these are I', u'are I think', u'I think I', u'think I know.'])]
```

# 文本分类

文本分类是指将主题、主题类别、流派或类似内容分配给文本块。例如，垃圾邮件过滤器将垃圾邮件或非垃圾邮件分配给电子邮件。

Apache Spark 通过 MLlib 和 ML 包支持各种分类器。SVM 分类器和朴素贝叶斯分类器是流行的分类器，前者已经在前一章中介绍过。现在让我们来看看后者。

## 朴素贝叶斯分类器

**朴素贝叶斯**（**NB**）分类器是一种多类概率分类器，是最好的分类算法之一。它假设每对特征之间有很强的独立性。它计算每个特征和给定标签的条件概率分布，然后应用贝叶斯定理来计算给定观察结果的标签的条件概率。在文档分类方面，观察结果是要分类到某个类别的文档。尽管它对数据有很强的假设，但它非常受欢迎。它可以处理少量的训练数据-无论是真实的还是离散的。它非常高效，因为它只需一次通过训练数据；一个约束是特征向量必须是非负的。默认情况下，ML 包支持多项式 NB。但是，如果需要伯努利 NB，可以将参数`modelType`设置为`Bernoulli`。

**拉普拉斯平滑**技术可以通过指定平滑参数来应用，并且在您想要为罕见的单词或新单词分配一个小的非零概率以使后验概率不会突然降为零的情况下非常有用。

Spark 还提供了一些其他超参数，如`thresholds`，以获得细粒度控制。以下是一个将 Twitter 文本分类的示例。此示例包含一些手工编码的规则，将类别分配给训练数据。如果文本包含相应的单词，则分配特定的类别。例如，如果文本包含"survey"或"poll"，则类别为"survey"。该模型是基于此训练数据进行训练的，并且在不同时间收集的不同文本样本上进行评估。

**示例 8：朴素贝叶斯**

Scala：

```scala
// Step 1: Define a udf to assign a category // One or more similar words are treated as one category (eg survey, poll)
// If input list contains any of the words in a category list, it is assigned to that category
// "General" is assigned if none of the categories matched
scala> import scala.collection.mutable.WrappedArray
import scala.collection.mutable.WrappedArray
scala> val findCategory = udf ((words: WrappedArray[String]) =>
    { var idx = 0; var category : String = ""
    val categories : List[Array[String]] =  List(
     Array("Python"), Array("Hadoop","hadoop"),
     Array("survey","poll"),
      Array("event","training", "Meetup", "summit",
          "talk", "talks", "Setting","sessions", "workshop"),
     Array("resource","Guide","newsletter", "Blog"))
    while(idx < categories.length && category.isEmpty ) {
        if (!words.intersect(categories(idx)).isEmpty) {
         category = categories(idx)(0) }  //First word in the category list
     idx += 1 }
    if (category.isEmpty) {
    category = "General"  }
    category
  })
findCategory: org.apache.spark.sql.expressions.UserDefinedFunction = UserDefinedFunction(<function1>,StringType,Some(List(ArrayType(StringType,true))))

//UDF to convert category to a numerical label scala> val idxCategory = udf ((category: String) =>
        {val catgMap = Map({"General"->1},{"event"->2},{"Hadoop"->3},
                             {"Python"->4},{"resource"->5})
         catgMap(category)})
idxCategory: org.apache.spark.sql.expressions.UserDefinedFunction =
UserDefinedFunction(<function1>,IntegerType,Some(List(StringType)))
scala> val labels = Array("General","event","Hadoop","Python","resource")
 //Step 2: Prepare train data 
//Step 2a: Extract "text" data and split to words scala> val path = "<Your path>/tweets_train.txt"
path: String = <Your path>../work/tweets_train.txt
scala> val pattern = ""text":"
pattern: String = "text":
scala> val raw_text = spark.read.text(path).filter($"value".contains(pattern)).
               select(split('value, " ") as "words")
raw_text: org.apache.spark.sql.DataFrame = [words: array<string>]
scala>

//Step 2b: Assign a category to each line scala> val train_cat_df = raw_text.withColumn("category",

findCategory(raw_text("words"))).withColumn("label",idxCategory($"category"))
train_cat_df: org.apache.spark.sql.DataFrame = [words: array<string>, category:
string ... 1 more field]

//Step 2c: Examine categories scala> train_cat_df.groupBy($"category").agg(count("category")).show()
+--------+---------------+                                                     
|category|count(category)|
+--------+---------------+
| General|            146|
|resource|              1|
|  Python|              2|
|   event|             10|
|  Hadoop|              6|
+--------+---------------+ 

//Step 3: Build pipeline scala> import org.apache.spark.ml.Pipeline
import org.apache.spark.ml.Pipeline
scala> import org.apache.spark.ml.feature.{StopWordsRemover, CountVectorizer,
                  IndexToString}
import org.apache.spark.ml.feature.{StopWordsRemover, CountVectorizer,
StringIndexer, IndexToString}
scala> import org.apache.spark.ml.classification.NaiveBayes
import org.apache.spark.ml.classification.NaiveBayes
scala>

//Step 3a: Define pipeline stages 
//Stop words should be removed first scala> val stopw = new StopWordsRemover().setInputCol("words").
                setOutputCol("processed_words")
stopw: org.apache.spark.ml.feature.StopWordsRemover = stopWords_2fb707daa92e
//Terms to term frequency converter scala> val cv = new CountVectorizer().setInputCol("processed_words").
             setOutputCol("features")
cv: org.apache.spark.ml.feature.CountVectorizer = cntVec_def4911aa0bf
//Define model scala> val model = new NaiveBayes().
                setFeaturesCol("features").
                setLabelCol("label")
model: org.apache.spark.ml.classification.NaiveBayes = nb_f2b6c423f12c
//Numerical prediction label to category converter scala> val lc = new IndexToString().setInputCol("prediction").
              setOutputCol("predictedCategory").
              setLabels(labels)
lc: org.apache.spark.ml.feature.IndexToString = idxToStr_3d71be25382c
 //Step 3b: Build pipeline with desired stages scala> val p = new Pipeline().setStages(Array(stopw,cv,model,lc))
p: org.apache.spark.ml.Pipeline = pipeline_956942e70b3f
 //Step 4: Process train data and get predictions 
//Step 4a: Execute pipeline with train data scala> val resultsDF = p.fit(train_cat_df).transform(train_cat_df)
resultsDF: org.apache.spark.sql.DataFrame = [words: array<string>, category:
string ... 7 more fields]

//Step 4b: Examine results scala> resultsDF.select("category","predictedCategory").show(3)
+--------+-----------------+
|category|predictedCategory|
+--------+-----------------+
|   event|            event|
|   event|            event|
| General|          General|
+--------+-----------------+
 //Step 4c: Look for prediction mismatches scala> resultsDF.filter("category != predictedCategory").select(
         "category","predictedCategory").show(3)
+--------+-----------------+
|category|predictedCategory|
+--------+-----------------+
| General|            event|
| General|           Hadoop|
|resource|           Hadoop|
+--------+-----------------+
 //Step 5: Evaluate model using test data 
//Step5a: Prepare test data scala> val path = "<Your path> /tweets.json"
path: String = <Your path>/tweets.json
scala> val raw_test_df =
spark.read.text(path).filter($"value".contains(pattern)).
               select(split('value, " ") as "words"

raw_test_df: org.apache.spark.sql.DataFrame = [words: array<string>]
scala> val test_cat_df = raw_test_df.withColumn("category",

findCategory(raw_test_df("words")))withColumn("label",idxCategory($"category"))
test_cat_df: org.apache.spark.sql.DataFrame = [words: array<string>, category:
string ... 1 more field]
scala> test_cat_df.groupBy($"category").agg(count("category")).show()
+--------+---------------+                                                     
|category|count(category)|
+--------+---------------+
| General|              6|
|   event|             11|
+--------+---------------+
 //Step 5b: Run predictions on test data scala> val testResultsDF = p.fit(test_cat_df).transform(test_cat_df)
testResultsDF: org.apache.spark.sql.DataFrame = [words: array<string>,
category: string ... 7 more fields]
//Step 5c:: Examine results
scala> testResultsDF.select("category","predictedCategory").show(3)
+--------+-----------------+
|category|predictedCategory|
+--------+-----------------+
| General|            event|
|   event|          General|
|   event|          General|
+--------+-----------------+

//Step 5d: Look for prediction mismatches scala> testResultsDF.filter("category != predictedCategory").select(
         "category","predictedCategory").show()
+--------+-----------------+
|category|predictedCategory|
+--------+-----------------+
|   event|          General|
|   event|          General|
+--------+-----------------+
```

Python：

```scala
// Step 1: Initialization 
//Step1a: Define a udfs to assign a category // One or more similar words are treated as one category (eg survey, poll)
// If input list contains any of the words in a category list, it is assigned to that category
// "General" is assigned if none of the categories matched
>>> def findCategory(words):
        idx = 0; category  = ""
        categories = [["Python"], ["Hadoop","hadoop"],
          ["survey","poll"],["event","training", "Meetup", "summit",
          "talk", "talks", "Setting","sessions", "workshop"],
          ["resource","Guide","newsletter", "Blog"]]
        while(not category and idx < len(categories)):
          if len(set(words).intersection(categories[idx])) > 0:
             category = categories[idx][0] #First word in the category list
          else:
             idx+=1
        if not category:   #No match found
          category = "General"
        return category
>>> 
//Step 1b: Define udf to convert string category to a numerical label >>> def idxCategory(category):
       catgDict = {"General" :1, "event" :2, "Hadoop" :2,
             "Python": 4, "resource" : 5}
       return catgDict[category]
>>> 
//Step 1c: Register UDFs >>> from pyspark.sql.functions import udf
>>> from pyspark.sql.types import StringType, IntegerType
>>> findCategoryUDF = udf(findCategory, StringType())
>>> idxCategoryUDF = udf(idxCategory, IntegerType())

//Step 1d: List categories >>> categories =["General","event","Hadoop","Python","resource"]
//Step 2: Prepare train data 
//Step 2a: Extract "text" data and split to words >>> from pyspark.sql.functions import split
>>> path = "../work/tweets_train.txt"
>>> raw_df1 = spark.read.text(path)
>>> raw_df = raw_df1.where("value like '%"text":%'").select(
             split("value", " ")).toDF("words")

//Step 2b: Assign a category to each line >>> train_cat_df = raw_df.withColumn("category",\
        findCategoryUDF("words")).withColumn(
        "label",idxCategoryUDF("category"))

//Step 2c: Examine categories scala> train_cat_df.groupBy("category").count().show()
+--------+---------------+                                                     
|category|count(category)|
+--------+---------------+
| General|            146|
|resource|              1|
|  Python|              2|
|   event|             10|
|  Hadoop|              6|
+--------+---------------+

//Step 3: Build pipeline >>> from pyspark.ml import Pipeline
>>> from pyspark.ml.feature import StopWordsRemover, CountVectorizer,
IndexToString
>>> from pyspark.ml.classification import NaiveBayes
>>>

//Step 3a: Define pipeline stages 
//Stop words should be removed first >>> stopw = StopWordsRemover(inputCol = "words",
                  outputCol = "processed_words")
//Terms to term frequency converter >>> cv = CountVectorizer(inputCol = "processed_words",
             outputCol = "features")
//Define model >>> model = NaiveBayes(featuresCol="features",
                   labelCol = "label")
//Numerical prediction label to category converter >>> lc = IndexToString(inputCol = "prediction",
           outputCol = "predictedCategory",
           labels = categories)
>>> 

//Step 3b: Build pipeline with desired stages >>> p = Pipeline(stages = [stopw,cv,model,lc])
>>> 
 //Step 4: Process train data and get predictions 
//Step 4a: Execute pipeline with train data >>> resultsDF = p.fit(train_cat_df).transform(train_cat_df)

//Step 4b: Examine results >>> resultsDF.select("category","predictedCategory").show(3)
+--------+-----------------+
|category|predictedCategory|
+--------+-----------------+
|   event|            event|
|   event|            event|
| General|          General|
+--------+-----------------+
 //Step 4c: Look for prediction mismatches >>> resultsDF.filter("category != predictedCategory").select(
         "category","predictedCategory").show(3)
+--------+-----------------+
|category|predictedCategory|
+--------+-----------------+
|  Python|           Hadoop|
|  Python|           Hadoop|
|  Hadoop|            event|
+--------+-----------------+
 //Step 5: Evaluate model using test data 
//Step5a: Prepare test data >>> path = "<Your path>/tweets.json">>> raw_df1 = spark.read.text(path)
>>> raw_test_df = raw_df1.where("va
ue like '%"text":%'").select(
               split("value", " ")).toDF("words")
>>> test_cat_df = raw_test_df.withColumn("category",
        findCategoryUDF("words")).withColumn(
        "label",idxCategoryUDF("category"))
>>> test_cat_df.groupBy("category").count().show()
+--------+---------------+                                                     
|category|count(category)|
+--------+---------------+
| General|              6|
|   event|             11|
+--------+---------------+
 //Step 5b: Run predictions on test data >>> testResultsDF = p.fit(test_cat_df).transform(test_cat_df)
//Step 5c:: Examine results >>> testResultsDF.select("category","predictedCategory").show(3)
+--------+-----------------+
|category|predictedCategory|
+--------+-----------------+
| General|          General|
|   event|            event|
|   event|            event|
+--------+-----------------+
//Step 5d: Look for prediction mismatches >>> testResultsDF.filter("category != predictedCategory").select(
         "category","predictedCategory").show()
+--------+-----------------+
|category|predictedCategory|
+--------+-----------------+
|   event|          General|
|   event|          General|
+--------+-----------------+
```

完成后，可以使用此步骤的输出训练模型，该模型可以对文本块或文件进行分类。

# 文本聚类

聚类是一种无监督学习技术。直观地，聚类将对象分成不相交的集合。我们不知道数据中存在多少组，或者这些组（簇）之间可能存在什么共性。

文本聚类有几个应用。例如，组织实体可能希望根据某种相似度度量将其内部文档组织成相似的簇。相似性或距离的概念对聚类过程至关重要。常用的度量包括 TF-IDF 和余弦相似度。余弦相似度或余弦距离是两个文档的词频向量的余弦乘积。Spark 提供了各种聚类算法，可以有效地用于文本分析。

## K-means

也许 K-means 是所有聚类算法中最直观的。其想法是根据某种相似度度量（如余弦距离或欧几里得距离）将数据点分隔为*K*个不同的簇。该算法从*K*个随机单点簇开始，然后将其余数据点分配到最近的簇。然后重新计算簇中心，并且算法再次循环遍历数据点。这个过程迭代地继续，直到没有重新分配或达到预定义的迭代次数为止。

如何确定簇的数量（*K*）并不明显。确定初始簇中心也不明显。有时业务需求可能决定簇的数量；例如，将所有现有文档分成 10 个不同的部分。但在大多数真实世界的场景中，我们需要通过试错找到*K*。一种方法是逐渐增加*K*值并计算簇质量，例如簇方差。在某个*K*值之后，质量停止显着改善，这可能是您理想的*K*。还有其他各种技术，如肘部法，**阿卡奇信息准则**（**AIC**）和**贝叶斯信息准则**（**BIC**）。

同样，从不同的起始点开始，直到簇的质量令人满意。然后您可能希望使用 Silhouette Score 等技术验证您的结果。但是，这些活动需要大量计算。

Spark 提供了来自 MLlib 和 ml 包的 K-means。您可以指定最大迭代次数或收敛容差来微调算法性能。

# 降维

想象一个有许多行和列的大矩阵。在许多矩阵应用中，这个大矩阵可以由一些窄矩阵代表，这些窄矩阵具有少量行和列，但仍代表原始矩阵。然后处理这个较小的矩阵可能会产生与原始矩阵相似的结果。这可能是计算效率高的。

降维是关于找到那个小矩阵的。MLLib 支持 RowMatrix 类的两种算法，SVD 和 PCA，用于降维。这两种算法都允许我们指定我们感兴趣的保留维度的数量。让我们先看一个例子，然后深入研究其中的理论。

**示例 9：降维**

Scala：

```scala
scala> import scala.util.Random
import scala.util.Random
scala> import org.apache.spark.mllib.linalg.{Vector, Vectors}
import org.apache.spark.mllib.linalg.{Vector, Vectors}
scala> import org.apache.spark.mllib.linalg.distributed.RowMatrix
import org.apache.spark.mllib.linalg.distributed.RowMatrix

//Create a RowMatrix of 6 rows and 5 columns scala> var vlist: Array[Vector] = Array()
vlist: Array[org.apache.spark.mllib.linalg.Vector] = Array()
scala> for (i <- 1 to 6) vlist = vlist :+ Vectors.dense(
       Array.fill(5)(Random.nextInt*1.0))
scala> val rows_RDD = sc.parallelize(vlist)
rows_RDD: org.apache.spark.rdd.RDD[org.apache.spark.mllib.linalg.Vector] =
ParallelCollectionRDD[0] at parallelize at <console>:29
scala> val row_matrix = new RowMatrix(rows_RDD)
row_matrix: org.apache.spark.mllib.linalg.distributed.RowMatrix = org.apache.spark.mllib.linalg.distributed.RowMatrix@348a6639
 //SVD example for top 3 singular values scala> val SVD_result = row_matrix.computeSVD(3)
SVD_result:
org.apache.spark.mllib.linalg.SingularValueDecomposition[org.apache.spark.mlli
.linalg.distributed.RowMatrix,org.apache.spark.mllib.linalg.Matrix] =
SingularValueDecomposition(null,
[4.933482776606544E9,3.290744495921952E9,2.971558550447048E9],
-0.678871347405378    0.054158900880961904  -0.23905281217240534
0.2278187940802       -0.6393277579229861   0.078663353163388
0.48824560481341733   0.3139021297613471    -0.7800061948839081
-0.4970903877201546   2.366428606359744E-4  -0.3665502780139027
0.041829015676406664  0.6998515759330556    0.4403374382132576    )

scala> SVD_result.s   //Show the singular values (strengths)
res1: org.apache.spark.mllib.linalg.Vector =
[4.933482776606544E9,3.290744495921952E9,2.971558550447048E9]

//PCA example to compute top 2 principal components scala> val PCA_result = row_matrix.computePrincipalComponents(2)
PCA_result: org.apache.spark.mllib.linalg.Matrix =
-0.663822435334425    0.24038790854106118
0.3119085619707716    -0.30195355896094916
0.47440026368044447   0.8539858509513869
-0.48429601343640094  0.32543904517535094
-0.0495437635382354   -0.12583837216152594
```

Python：

截至 Spark 2.0.0，Python 中不可用。

# 奇异值分解

**奇异值分解**（**SVD**）是线性代数的重要组成部分之一，广泛用于许多实际建模需求。它提供了一种将矩阵分解为更简单、更小的矩阵的便捷方法。这导致了高维矩阵的低维表示。它帮助我们消除矩阵中不太重要的部分，以产生一个近似表示。这种技术在降维和数据压缩中非常有用。

设*M*是一个大小为 m 行 n 列的矩阵。矩阵的秩是线性无关的行数。如果一行至少有一个非零元素，并且不是一个或多个行的线性组合，则该行被认为是独立的。如果我们考虑列而不是行，那么将得到相同的秩 - 就像在线性代数中一样。

如果一行的元素是两行的和，则该行不是独立的。因此，作为 SVD 的结果，我们找到了满足以下方程的三个矩阵*U*、*∑*和*V*：

*M = U∑VT*

这三个矩阵具有以下特性：

+   **U**：这是一个具有 m 行和 r 列的列正交矩阵。正交矩阵意味着每个列都是单位向量，并且任意两列之间的点积为 0。

+   **V**：这是一个具有*n*行和*r*列的列正交矩阵。

+   **∑**：这是一个*r* x *r*对角矩阵，其主对角线值为非负实数，按降序排列。在对角矩阵中，除了主对角线上的元素外，其他元素都是零。

*∑*矩阵中的主对角线值被称为奇异值。它们被认为是连接矩阵的行和列的基本*概念*或*组件*。它们的大小代表了相应组件的强度。例如，想象一下，前面例子中的矩阵包含了六个读者对五本书的评分。SVD 允许我们将它们分成三个矩阵：*∑*包含奇异值，代表了基本主题的*强度*；*U*将人连接到概念；*V*将概念连接到书籍。

在一个大矩阵中，我们可以将较低幅度的奇异值替换为零，从而减少剩余两个矩阵中的相应行。请注意，如果我们在右侧重新计算矩阵乘积，并将其与左侧的原始矩阵进行比较，它们将几乎相似。我们可以使用这种技术来保留所需的维度。

## 主成分分析

**主成分分析**（**PCA**）是一种将 n 维数据点投影到具有最小信息损失的较小（更少维度）子空间的技术。在高维空间中，一组数据点找到了这些元组最佳排列的方向。换句话说，我们需要找到一个旋转，使得第一个坐标具有可能的最大方差，然后依次每个坐标具有可能的最大方差。这个想法是将元组集合视为矩阵*M*，并找到 MMT 的特征向量。

如果*A*是一个方阵，*e*是一个列矩阵，行数与*A*相同，*λ*是一个常数，使得*Me = λe*，那么*e*被称为*M*的特征向量，*λ*被称为*M*的特征值。在 n 维平面上，特征向量是方向，特征值是沿着该方向的方差的度量。我们可以丢弃特征值较低的维度，从而找到一个更小的子空间，而不会丢失信息。

# 总结

在本章中，我们研究了非结构化数据的来源以及分析非结构化数据背后的动机。我们解释了预处理非结构化数据所需的各种技术，以及 Spark 如何提供大部分这些工具。我们还介绍了 Spark 支持的一些可用于文本分析的算法。

在下一章中，我们将介绍不同类型的可视化技术，这些技术在数据分析生命周期的不同阶段都具有洞察力。

# 参考资料：

以下是参考资料：

+   [`totoharyanto.staff.ipb.ac.id/files/2012/10/Building-Machine-Learning-Systems-with-Python-Richert-Coelho.pdf`](http://totoharyanto.staff.ipb.ac.id/files/2012/10/Building-Machine-Learning-Systems-with-Python-Richert-Coelho.pdf)

+   [`www.cs.nyu.edu/web/Research/Theses/borthwick_andrew.pdf`](https://www.cs.nyu.edu/web/Research/Theses/borthwick_andrew.pdf)

+   [`web.stanford.edu/class/cs124/lec/naivebayes.pdf`](https://web.stanford.edu/class/cs124/lec/naivebayes.pdf)

+   [`nlp.stanford.edu/IR-book/html/htmledition/naive-bayes-text-classification-1.html`](http://nlp.stanford.edu/IR-book/html/htmledition/naive-bayes-text-classification-1.html)

+   [`www.mmds.org/`](http://www.mmds.org/)

+   [`sebastianraschka.com/Articles/2014_pca_step_by_step.html`](http://sebastianraschka.com/Articles/2014_pca_step_by_step.html)

+   [`arxiv.org/pdf/1404.1100.pdf`](http://arxiv.org/pdf/1404.1100.pdf)

+   [`spark.apache.org/docs/latest/mllib-dimensionality-reduction.html`](http://spark.apache.org/docs/latest/mllib-dimensionality-reduction.html)

计数向量化器：

+   [`spark.apache.org/docs/1.6.1/api/java/org/apache/spark/ml/feature/CountVectorizer.html`](https://spark.apache.org/docs/1.6.1/api/java/org/apache/spark/ml/feature/CountVectorizer.html)

n-gram 建模：

+   [`en.wikipedia.org/wiki/N-gram`](https://en.wikipedia.org/wiki/N-gram)


# 第九章：可视化大数据

适当的数据可视化在过去解决了许多业务问题，而没有涉及太多统计学或机器学习。即使在今天，随着技术的不断进步、应用统计学和机器学习，适当的可视化仍然是业务用户消化信息或某些分析的最终交付物。以正确的格式传达正确的信息是数据科学家渴望的，有效的可视化价值连城。此外，以一种易于业务消化的方式表示生成的模型和见解也非常重要。尽管如此，通过可视化探索大数据是非常繁琐和具有挑战性的。由于 Spark 是为大数据处理而设计的，它也支持大数据可视化。已经在 Spark 上为此目的构建了许多工具和技术。

前几章概述了如何对结构化和非结构化数据进行建模，并从中生成见解。在本章中，我们将从两个广泛的视角来看数据可视化——一个是从数据科学家的视角，可视化是探索和有效理解数据的基本需求，另一个是从业务用户的视角，其中可视化是业务的最终交付物，必须易于理解。我们将探索各种数据可视化工具，如*IPythonNotebook*和*Zeppelin*，可以在 Apache Spark 上使用。

作为本章的先决条件，对 SQL 和 Python、Scala 或其他类似框架的编程有基本的了解是很有帮助的。本章涵盖的主题如下：

+   为什么要可视化数据？

+   数据工程师的视角

+   数据科学家的视角

+   业务用户的视角

+   数据可视化工具

+   IPython 笔记本

+   Apache Zeppelin

+   第三方工具

+   数据可视化技术

+   总结和可视化

+   子集和可视化

+   抽样和可视化

+   建模和可视化

# 为什么要可视化数据？

数据可视化涉及以视觉形式表示数据，以便使人们能够理解其中的模式和趋势。地理地图，十七世纪的条形图和折线图，是早期数据可视化的一些例子。Excel 可能是我们大多数人已经使用过的熟悉的数据可视化工具。所有数据分析工具都配备了复杂的交互式数据可视化仪表板。然而，大数据、流式数据和实时分析的最近激增一直在推动这些工具的边界，它们似乎已经到了极限。其想法是使可视化看起来简单、准确和相关，同时隐藏所有复杂性。根据业务需求，任何可视化解决方案理想上应具有以下特点：

+   互动性

+   可重现性

+   对细节的控制

除此之外，如果解决方案允许用户在可视化或报告上进行协作并相互分享，那么这将构成一个端到端的可视化解决方案。

特别是大数据可视化本身就存在着自己的挑战，因为我们可能会得到比屏幕上的像素更多的数据。处理大量数据通常需要内存和 CPU 密集型处理，并可能具有较长的延迟。将实时或流式数据添加到混合中，问题变得更加具有挑战性。Apache Spark 是从头开始设计的，专门用于通过并行化 CPU 和内存使用来解决这种延迟。在探索可视化和处理大数据的工具和技术之前，让我们首先了解数据工程师、数据科学家和业务用户的可视化需求。

## 数据工程师的视角

数据工程师在几乎每一个数据驱动的需求中扮演着至关重要的角色：从不同数据源获取数据，整合它们，清洗和预处理它们，分析它们，然后通过可视化和仪表板进行最终报告。他们的活动可以广泛地陈述如下：

+   可视化来自不同来源的数据，以便将其集成和 consolida te 成一个单一的数据矩阵

+   可视化并发现数据中的各种异常，如缺失值、异常值等（这可能是在抓取、获取、ETL 等过程中），并将其修复

+   就数据集的属性和特征向数据科学家提供建议

+   探索可视化数据的各种可能方式，并最终确定根据业务需求更具信息量和直观性的方式

请注意，数据工程师不仅在获取和准备数据方面起着关键作用，还会根据商业用户的需求选择最合适的可视化输出。他们通常也与业务密切合作，以对业务需求和手头的具体问题有非常清晰的理解。

## 数据科学家的视角

数据科学家对可视化数据的需求与数据工程师不同。请注意，在一些企业中，有一些专业人员既扮演数据工程师又扮演数据科学家的双重角色。

数据科学家需要可视化数据，以便在进行统计分析时做出正确的决策，并确保分析项目的正确执行。他们希望以各种可能的方式切分数据，以找到隐藏的见解。让我们看一些数据科学家可能需要可视化数据的示例要求：

+   查看各个变量的数据分布

+   可视化数据中的异常值

+   可视化数据集中所有变量的缺失数据百分比

+   绘制相关矩阵以找到相关的变量

+   绘制回归后残差的行为

+   在数据清洗或转换活动之后，重新绘制变量并观察其行为

请注意，刚才提到的一些事情与数据工程师的情况非常相似。然而，数据科学家可能在这些分析背后有更科学/统计的意图。例如，数据科学家可能从不同的角度看待异常值并进行统计处理，而数据工程师可能会考虑触发这种异常的各种选项。

## 商业用户的视角

一个商业用户的视角与数据工程师或数据科学家完全不同。商业用户通常是信息的消费者！他们希望从数据中提取更多信息，为此，正确的可视化起着关键作用。此外，大多数商业问题如今更加复杂和因果关系。老式报告已经不再足够。让我们看一些商业用户希望从报告、可视化和仪表板中提取的示例查询：

+   在某个地区，高价值客户是谁？

+   这些客户的共同特征是什么？

+   预测新客户是否会是高价值客户

+   在哪种媒体上做广告会带来最大的投资回报？

+   如果我不在报纸上做广告会怎样？

+   影响客户购买行为的因素是什么？

# 数据可视化工具

在许多不同的可视化选项中，选择合适的可视化取决于具体的需求。同样，选择可视化工具取决于目标受众和业务需求。

数据科学家或数据工程师更倾向于一个更具交互性的控制台进行快速而肮脏的分析。他们使用的可视化通常不是为业务用户而设计的。他们希望以各种可能的方式剖析数据，以获得更有意义的见解。因此，他们通常更喜欢支持这些活动的笔记本类型界面。笔记本是一个交互式的计算环境，他们可以在其中组合代码块和绘制数据进行探索。有一些可用选项，如**IPython**/**Jupyter**或**DataBricks**等笔记本。

业务用户更倾向于更直观和信息丰富的可视化，他们可以分享给彼此或用来生成报告。他们期望通过可视化收到最终结果。有数以百计的工具，包括一些流行的工具如**Tableau**，企业使用；但很多时候，开发人员必须根据一些独特的需求定制特定类型，并通过 Web 应用程序公开它们。微软的**PowerBI**和**Zeppelin**等开源解决方案就是其中的几个例子。

## IPython 笔记本

在 Spark 的**PySpark** API 之上的 IPython/Jupyter 笔记本是数据科学家探索和可视化数据的绝佳组合。笔记本内部会启动一个新的 PySpark 内核实例。还有其他可用的内核；例如，Apache **Toree**内核可以用于支持 Scala。

对于许多数据科学家来说，它是默认选择，因为它能够在一个 JSON 文档文件中集成文本、代码、公式和图形。IPython 笔记本支持`matplotlib`，这是一个可以生成高质量可视化的 2D 可视化库。生成图表、直方图、散点图、图表等变得简单而容易。它还支持`seaborn`库，实际上是建立在 matplotlib 之上的，但易于使用，因为它提供了更高级的抽象并隐藏了底层复杂性。

## Apache Zeppelin

Apache Zeppelin 是建立在 JVM 之上的，并与 Apache Spark 很好地集成在一起。它是一个基于浏览器或前端的开源工具，具有自己的笔记本。它支持 Scala、Python、R、SQL 和其他图形模块，不仅为业务用户提供可视化解决方案，也为数据科学家提供支持。在下面关于可视化技术的部分，我们将看看 Zeppelin 如何支持 Apache Spark 代码生成有趣的可视化。您需要下载 Zeppelin（[`zeppelin.apache.org/`](https://zeppelin.apache.org/)）来尝试这些示例。

## 第三方工具

有许多产品支持 Apache Spark 作为底层数据处理引擎，并且构建以适应组织的大数据生态系统。在利用 Spark 的处理能力的同时，它们提供了支持各种交互式可视化的可视化界面，它们还支持协作。Tableau 就是一个利用 Spark 的工具的例子。

# 数据可视化技术

数据可视化是数据分析生命周期的每个阶段的核心。它对于探索性分析和沟通结果尤为重要。在任何情况下，目标都是将数据转换为人类消费的高效格式。将转换委托给客户端库的方法无法扩展到大型数据集。转换必须在服务器端进行，仅将相关数据发送到客户端进行渲染。大多数常见的转换在 Apache Spark 中都是开箱即用的。让我们更仔细地看看这些转换。

## 总结和可视化

**总结和可视化**是许多**商业智能**（**BI**）工具使用的技术。由于总结将是一个简洁的数据集，无论底层数据集的大小如何，图表看起来都足够简单且易于呈现。有各种各样的数据总结方法，例如聚合、透视等。如果呈现工具支持交互性并具有钻取功能，用户可以从完整数据中探索感兴趣的子集。我们将展示如何通过 Zeppelin 笔记本快速和交互式地使用 Spark 进行总结。

下面的图片显示了带有源代码和分组条形图的 Zeppelin 笔记本。数据集包含 24 个观测值，其中包含两种产品**P1**和**P2**的 12 个月销售信息。第一个单元格包含读取文本文件并将数据注册为临时表的代码。这个单元格使用默认的 Spark 解释器使用 Scala。第二个单元格使用了 SQL 解释器，该解释器支持开箱即用的可视化选项。您可以通过点击右侧图标切换图表类型。请注意，无论是 Scala 还是 Python 还是 R 解释器，可视化都是相似的。

总结示例如下：

1.  读取数据并注册为 SQL 视图的源代码：

**Scala（默认）**：

![总结和可视化](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_09_001.jpg)

**PySpark**：

![总结和可视化](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_09_002.jpg)

**R**：

![总结和可视化](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_09_003.jpg)

所有三个都是读取数据文件并将其注册为临时 SQL 视图。请注意，在前面的三个脚本中存在一些细微差异。例如，我们需要删除 R 的标题行并设置列名。下一步是生成可视化，它可以从`%sql`解释器中工作。下面的第一张图片显示了生成每种产品季度销售额的脚本。它还显示了开箱即用的图表类型，然后是设置及其选择。在进行选择后，您可以折叠设置。您甚至可以利用 Zeppelin 内置的动态表单，比如在运行时接受一个产品。第二张图片显示了实际输出。

1.  用于生成两种产品季度销售额的脚本：![总结和可视化](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_09_004.jpg)

1.  生成的输出：![总结和可视化](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_09_005.jpg)

我们在前面的例子中已经看到了 Zeppelin 内置的可视化。但是我们也可以使用其他绘图库。我们的下一个例子利用了 PySpark 解释器和 Zeppelin 中的 matplotlib 来绘制直方图。这个例子的代码使用 RDD 的直方图函数计算箱子间隔和箱子计数，并将这些总结数据带到驱动节点。在绘制箱子时，频率被作为权重提供，以便给出与普通直方图相同的视觉理解，但数据传输非常低。

直方图示例如下：

![总结和可视化](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_09_006.jpg)

这是生成的输出（可能会显示为单独的窗口）：

![总结和可视化](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_09_007.jpg)

在前面的直方图准备示例中，请注意可以使用内置的动态表单支持来参数化桶计数。

## 子集和可视化

有时，我们可能有一个大型数据集，但我们可能只对其中的一个子集感兴趣。分而治之是一种方法，我们可以一次探索一小部分数据。Spark 允许使用类似 SQL 的过滤器和聚合在行列数据集以及图形数据上对数据进行子集化。让我们先进行 SQL 子集化，然后进行一个 GraphX 示例。

以下示例获取了 Zeppelin 提供的银行数据，并提取了与仅经理相关的几列数据。它使用了`google 可视化库`来绘制气泡图。数据是使用 PySpark 读取的。数据子集和可视化是使用 R 进行的。请注意，我们可以选择任何解释器来执行这些任务，这里的选择只是任意的。

使用 SQL 进行数据子集示例如下：

1.  读取数据并注册 SQL 视图：![子集和可视化](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_09_008.jpg)

1.  子集经理的数据并显示气泡图：![子集和可视化](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_09_009.jpg)

下一个示例演示了使用**Stanford Network Analysis Project** (**SNAP**)提供的数据进行的一些 GraphX 处理。脚本提取了覆盖给定节点集的子图。在这里，每个节点代表一个 Facebook ID，边代表两个节点（或人）之间的连接。此外，脚本识别了给定节点（id: 144）的直接连接。这些是级别 1 节点。然后它识别了这些*级别 1 节点*的直接连接，这些连接形成了给定节点的*级别 2 节点*。即使第二级联系可能连接到多个第一级联系，但它只显示一次，从而形成一个没有交叉边的连接树。由于连接树可能有太多的节点，脚本限制了级别 1 和级别 2 的连接，因此在给定根节点下只显示 12 个节点（一个根+三个级别 1 节点+每个级别 2 节点三个）。

**Scala**

```scala
//Subset and visualize 
//GraphX subset example 
//Datasource: http://snap.stanford.edu/data/egonets-Facebook.html  
import org.apache.spark.graphx._ 
import org.apache.spark.graphx.util.GraphGenerators 
//Load edge file and create base graph 
val base_dir = "../data/facebook" 
val graph = GraphLoader.edgeListFile(sc,base_dir + "/0.edges") 

//Explore subgraph of a given set of nodes 
val circle = "155  99  327  140  116  147  144  150  270".split("\t").map( 
       x=> x.toInt) 
val subgraph = graph.subgraph(vpred = (id,name) 
     => circle.contains(id)) 
println("Edges: " + subgraph.edges.count +  
       " Vertices: " + subgraph.vertices.count) 

//Create a two level contact tree for a given node  
//Step1: Get all edges for a given source id 
val subgraph_level1 = graph.subgraph(epred= (ed) =>  
    ed.srcId == 144) 

//Step2: Extract Level 1 contacts 
import scala.collection.mutable.ArrayBuffer 
val lvl1_nodes : ArrayBuffer[Long] = ArrayBuffer() 
subgraph_level1.edges.collect().foreach(x=> lvl1_nodes+= x.dstId) 

//Step3: Extract Level 2 contacts, 3 each for 3 lvl1_nodes 
import scala.collection.mutable.Map 
val linkMap:Map[Long, ArrayBuffer[Long]] = Map() //parent,[Child] 
val lvl2_nodes : ArrayBuffer[Long] = ArrayBuffer() //1D Array 
var n : ArrayBuffer[Long] = ArrayBuffer() 
for (i <- lvl1_nodes.take(3)) {    //Limit to 3 
    n = ArrayBuffer() 
    graph.subgraph(epred = (ed) => ed.srcId == i && 
        !(lvl2_nodes contains ed.dstId)).edges.collect(). 
             foreach(x=> n+=x.dstId) 
    lvl2_nodes++=n.take(3)    //Append to 1D array. Limit to 3 
  linkMap(i) = n.take(3)  //Assign child nodes to its parent 
 } 

 //Print output and examine the nodes 
 println("Level1 nodes :" + lvl1_nodes) 
 println("Level2 nodes :" + lvl2_nodes) 
 println("Link map :" + linkMap) 

 //Copy headNode to access from another cell 
 z.put("headNode",144) 
 //Make a DataFrame out of lvl2_nodes and register as a view 
 val nodeDF = sc.parallelize(linkMap.toSeq).toDF("parentNode","childNodes") 
 nodeDF.createOrReplaceTempView("node_tbl") 

```

### 注意

请注意`z.put`和`z.get`的使用。这是在 Zeppelin 中在单元格/解释器之间交换数据的机制。

现在我们已经创建了一个包含级别 1 联系人及其直接联系人的数据框，我们已经准备好绘制树了。以下脚本使用了图形可视化库 igraph 和 Spark R。

提取节点和边。绘制树：

![子集和可视化](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_09_010.jpg)

前面的脚本从节点表中获取父节点，这些父节点是级别 2 节点的父节点，也是给定头节点的直接连接。创建头节点和级别 1 节点的有序对，并分配给`edges1`。下一步将级别 2 节点的数组展开，形成每个数组元素一行。因此获得的数据框被转置并粘贴在一起形成边对。由于粘贴将数据转换为字符串，因此它们被重新转换为数字。这些是级别 2 的边。级别 1 和级别 2 的边被连接在一起形成一个边的单个列表。这些被用来形成下面显示的图形。请注意，`headNode`中的模糊是 144，尽管在下图中看不到：

![子集和可视化](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_09_011.jpg)

给定节点的连接树

## 抽样和可视化

抽样和可视化长期以来一直被统计学家使用。通过抽样技术，我们可以取得数据集的一部分并对其进行处理。我们将展示 Spark 如何支持不同的抽样技术，如**随机抽样**、**分层抽样**和**sampleByKey**等。以下示例是使用 Jupyter 笔记本、PySpark 内核和`seaborn`库创建的。数据文件是 Zeppelin 提供的银行数据集。第一个图显示了每个教育类别的余额。颜色表示婚姻状况。

读取数据并随机抽样 5%：

![抽样和可视化](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_09_012.jpg)

使用`stripplot`渲染数据：

![抽样和可视化](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_09_013.jpg)

前面的示例展示了可用数据的随机样本，这比完全绘制总体要好得多。但是，如果感兴趣的分类变量（在本例中是`education`）的级别太多，那么这个图就会变得难以阅读。例如，如果我们想要绘制`job`的余额而不是`education`，那么会有太多的条带，使图片看起来凌乱。相反，我们可以只取所需分类级别的所需样本，然后检查数据。请注意，这与子集不同，因为我们无法使用 SQL 的`WHERE`子句来指定正常子集中的样本比例。我们需要使用`sampleByKey`来做到这一点，如下所示。以下示例仅采用两种工作和特定的抽样比例：

![抽样和可视化](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_09_014.jpg)

分层抽样

## 建模和可视化

建模和可视化是可能的，使用 Spark 的**MLLib**和**ML**模块。Spark 的统一编程模型和多样的编程接口使得将这些技术结合到一个单一的环境中以从数据中获得洞察成为可能。我们已经在前几章中涵盖了大部分建模技术。然而，以下是一些示例供您参考：

+   **聚类**：K 均值，高斯混合建模

+   **分类和回归**：线性模型，决策树，朴素贝叶斯，支持向量机

+   **降维**：奇异值分解，主成分分析

+   **协同过滤**

+   **统计测试**：相关性，假设检验

以下示例来自第七章，*用 SparkR 扩展 Spark*，它尝试使用朴素贝叶斯模型预测学生的及格或不及格结果。这个想法是利用 Zeppelin 提供的开箱即用的功能，并检查模型的行为。因此，我们加载数据，进行数据准备，构建模型，并运行预测。然后我们将预测注册为 SQL 视图，以便利用内置的可视化：

```scala
//Model visualization example using zeppelin visualization  
 Prepare Model and predictions 

```

![建模和可视化](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_09_015.jpg)

下一步是编写所需的 SQL 查询并定义适当的设置。请注意 SQL 中 UNION 运算符的使用以及匹配列的定义方式。

定义 SQL 以查看模型性能：

![建模和可视化](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_09_016.jpg)

以下图片帮助我们理解模型预测与实际数据的偏差。这样的可视化有助于接受业务用户的输入，因为他们不需要任何数据科学的先验知识来理解：

![建模和可视化](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_09_017.jpg)

可视化模型性能

我们通常使用误差度量来评估统计模型，但是将它们以图形方式可视化而不是看到数字，使它们更直观，因为通常更容易理解图表而不是表中的数字。例如，前面的可视化也可以被数据科学社区之外的人轻松理解。

# 总结

在本章中，我们探讨了在大数据设置中支持的大多数常用可视化工具和技术。我们通过代码片段解释了一些技术，以更好地理解数据分析生命周期不同阶段的可视化需求。我们还看到了如何通过适当的可视化技术满足业务需求，以解决大数据的挑战。

下一章是到目前为止解释的所有概念的高潮。我们将通过一个示例数据集走完完整的数据分析生命周期。

# 参考

+   21 个必备的数据可视化工具：[`www.kdnuggets.com/2015/05/21-essential-data-visualization-tools.html`](http://www.kdnuggets.com/2015/05/21-essential-data-visualization-tools.html)

+   Apache Zeppelin 笔记本主页：[`zeppelin.apache.org/`](https://zeppelin.apache.org/)

+   Jupyter 笔记本主页：[`jupyter.org/`](https://jupyter.org/)

+   使用 Apache Spark 的 IPython Notebook：[`hortonworks.com/hadoop-tutorial/using-ipython-notebook-with-apache-spark/`](http://hortonworks.com/hadoop-tutorial/using-ipython-notebook-with-apache-spark/)

+   Apache Toree，可在应用程序和 Spark 集群之间进行交互式工作负载。可与 jupyter 一起使用以运行 Scala 代码：[`toree.incubator.apache.org/`](https://toree.incubator.apache.org/)

+   使用 R 的 GoogleVis 软件包：[`cran.rproject.org/web/packages/googleVis/vignettes/googleVis_examples.html`](https://cran.rproject.org/web/packages/googleVis/vignettes/googleVis_examples.html)

+   GraphX 编程指南：[`spark.apache.org/docs/latest/graphx-programming-guide.html`](http://spark.apache.org/docs/latest/graphx-programming-guide.html)

+   使用 R 的 igraph 软件包进行病毒式传播：[`www.r-bloggers.com/going-viral-with-rs-igraph-package/`](https://www.r-bloggers.com/going-viral-with-rs-igraph-package/)

+   使用分类数据绘图：[`stanford.edu/~mwaskom/software/seaborn/tutorial/categorical.html#categorical-tutorial`](https://stanford.edu/~mwaskom/software/seaborn/tutorial/categorical.html#categorical-tutorial)

## 数据来源引用

**银行数据来源（引用）**

+   [Moro 等人，2011] S. Moro，R. Laureano 和 P. Cortez。使用数据挖掘进行银行直接营销：CRISP-DM 方法论的应用

+   在 P. Novais 等人（编），欧洲模拟与建模会议 - ESM'2011 论文集，第 117-121 页，葡萄牙吉马良斯，2011 年 10 月。EUROSIS

+   可在[pdf] [`hdl.handle.net/1822/14838`](http://hdl.handle.net/1822/14838)找到

+   [bib] http://www3.dsi.uminho.pt/pcortez/bib/2011-esm-1.txt

**Facebook 数据来源（引用）**

+   J. McAuley 和 J. Leskovec。学习在自我网络中发现社交圈。NIPS，2012 年。


# 第十章：将所有内容整合在一起

大数据分析正在改变企业经营的方式，并为许多此前无法想象的机会铺平了道路。几乎每个企业、个人研究人员或调查记者都有大量数据需要处理。我们需要一种简洁的方法，从原始数据开始，根据手头的问题得出有意义的见解。

我们在先前的章节中使用 Apache Spark 涵盖了数据科学的各个方面。我们开始讨论大数据分析需求以及 Apache Spark 的适用性。逐渐地，我们深入研究了 Spark 编程模型、RDD 和 DataFrame 抽象，并学习了 Spark 数据集实现的统一数据访问以及连续应用的流式方面。然后，我们涵盖了使用 Apache Spark 进行整个数据分析生命周期，随后是机器学习。我们学习了 Spark 上的结构化和非结构化数据分析，并探索了数据工程师和科学家以及业务用户的可视化方面。

所有先前讨论的章节都帮助我们理解每个章节中的一个简洁方面。我们现在已经具备了遍历整个数据科学生命周期的能力。在本章中，我们将进行一个端到端的案例研究，并应用到目前为止学到的所有知识。我们不会介绍任何新概念；这将有助于应用到目前为止所获得的知识，并加强我们的理解。但是，我们已经重申了一些概念，而没有过多地详细介绍，以使本章内容自成一体。本章涵盖的主题与数据分析生命周期中的步骤大致相同：

+   快速回顾

+   引入案例研究

+   构建业务问题

+   数据获取和数据清洗

+   制定假设

+   数据探索

+   数据准备

+   模型构建

+   数据可视化

+   将结果传达给业务用户

+   总结

# 快速回顾

我们已经在不同的章节中详细讨论了典型数据科学项目中涉及的各种步骤。让我们快速浏览一下我们已经涵盖的内容，并触及一些重要方面。所涉步骤的高级概述可能如下图所示：

![快速回顾](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_10_001.jpg)

在前面的图示中，我们试图解释了涉及数据科学项目的步骤，大部分是通用于许多数据科学任务的。实际上，在每个阶段都存在许多子步骤，但可能因项目而异。

对于数据科学家来说，很难在开始时找到最佳方法和步骤。通常，数据科学项目没有像**软件开发生命周期**（**SDLC**）那样定义明确的生命周期。通常情况下，数据科学项目会因为生命周期中的大多数步骤都是迭代的而陷入交付延迟。此外，团队之间可能存在循环依赖，增加了复杂性并导致执行延迟。然而，在处理大数据分析项目时，对数据科学家来说，遵循明确定义的数据科学工作流程是重要且有利的，无论不同的业务案例如何。这不仅有助于组织执行，还有助于我们专注于目标，因为在大多数情况下，数据科学项目本质上是敏捷的。此外，建议您计划对任何给定项目的数据、领域和算法进行一定程度的研究。

在本章中，我们可能无法在单个流程中容纳所有细粒度步骤，但将讨论重要领域，以便提前了解。我们将尝试查看一些在先前章节中未涵盖的不同编码示例。

# 引入案例研究

在本章中，我们将探讨奥斯卡奖的人口统计学。你可以从 GitHub 仓库下载数据[`www.crowdflower.com/wp-content/uploads/2016/03/Oscars-demographics-DFE.csv`](https://www.crowdflower.com/wp-content/uploads/2016/03/Oscars-demographics-DFE.csv)。

这个数据集是基于[`www.crowdflower.com/data-for-everyone`](http://www.crowdflower.com/data-for-everyone)提供的数据。它包含人口统计学细节，如种族、出生地和年龄。行数大约为 400，可以在普通家用电脑上轻松处理，因此你可以在 Spark 上执行数据科学项目的**概念验证**（**POC**）。

从下载文件并检查数据开始。数据可能看起来不错，但当你仔细查看时，你会注意到它并不是“干净”的。例如，出生日期列的格式不一致。有些年份是两位数格式，而有些是四位数格式。出生地没有美国境内地点的国家信息。

同样，你也会注意到数据看起来有偏差，美国有更多“白人”种族的人。但你可能会感觉到趋势在后来的年份有所改变。到目前为止，你还没有使用任何工具或技术，只是快速浏览了一下数据。在数据科学的现实世界中，这种看似琐碎的活动在生命周期的后期可能会非常有帮助。你可以对手头的数据产生一种感觉，并同时对数据进行假设。这将带你进入工作流程的第一步。

# 业务问题

正如之前所述，任何数据科学项目最重要的方面是所面临的问题。对于*我们试图解决什么问题？*有清晰的理解至关重要。这对项目的成功至关重要。它还决定了什么是相关数据，什么不是。例如，在当前案例研究中，如果我们想要研究的是人口统计学，那么电影名称和人名就是无关的。有时候，手头上没有具体的问题！*那么呢？*即使没有具体的问题，业务可能仍然有一些目标，或者数据科学家和领域专家可以共同努力找到要处理的业务领域。为了理解业务、功能、问题陈述或数据，数据科学家从“质疑”开始。这不仅有助于定义工作流程，还有助于获取正确的数据。

例如，如果业务重点是人口统计信息，一个正式的业务问题陈述可以被定义为：

*种族和出生国家在奥斯卡奖得主中的影响是什么？*

在现实世界中，这一步并不会如此直接。提出正确的问题是数据科学家、战略团队、领域专家和项目所有者的共同责任。如果不符合目的，整个练习就是徒劳的，数据科学家必须咨询所有利益相关者，并尽可能从他们那里获取尽可能多的信息。然而，他们可能最终得到宝贵的见解或“直觉”。所有这些结合起来构成了最初的假设的核心，并帮助数据科学家了解他们应该寻找什么。

在业务没有明确问题需要寻找答案的情况下，处理起来更有趣，但在执行上可能更复杂！

# 数据获取和数据清洗

**数据获取**是下一个逻辑步骤。它可能只是从单个电子表格中选择数据，也可能是一个独立的几个月的项目。数据科学家必须收集尽可能多的相关数据。这里的关键词是“相关”。记住，更相关的数据胜过聪明的算法。

我们已经介绍了如何从异构数据源获取数据并 consoli，以形成单个数据矩阵，因此我们将不在这里重复相同的基础知识。相反，我们从单一来源获取数据并提取其子集。

现在是时候查看数据并开始清理了。本章中呈现的脚本往往比以前的示例要长，但仍然不是生产质量的。现实世界的工作需要更多的异常检查和性能调优：

**Scala**

```scala
//Load tab delimited file 
scala> val fp = "<YourPath>/Oscars.txt" 
scala> val init_data = spark.read.options(Map("header"->"true", "sep" -> "\t","inferSchema"->"true")).csv(fp) 
//Select columns of interest and ignore the rest 
>>> val awards = init_data.select("birthplace", "date_of_birth", 
        "race_ethnicity","year_of_award","award").toDF( 
         "birthplace","date_of_birth","race","award_year","award") 
awards: org.apache.spark.sql.DataFrame = [birthplace: string, date_of_birth: string ... 3 more fields] 
//register temporary view of this dataset 
scala> awards.createOrReplaceTempView("awards") 

//Explore data 
>>> awards.select("award").distinct().show(10,false) //False => do not truncate 
+-----------------------+                                                        
|award                  | 
+-----------------------+ 
|Best Supporting Actress| 
|Best Director          | 
|Best Actress           | 
|Best Actor             | 
|Best Supporting Actor  | 
+-----------------------+ 
//Check DOB quality. Note that length varies based on month name 
scala> spark.sql("SELECT distinct(length(date_of_birth)) FROM awards ").show() 
+---------------------+                                                          
|length(date_of_birth)| 
+---------------------+ 
|                   15| 
|                    9| 
|                    4| 
|                    8| 
|                   10| 
|                   11| 
+---------------------+ 

//Look at the value with unexpected length 4 Why cant we show values for each of the length type ?  
scala> spark.sql("SELECT date_of_birth FROM awards WHERE length(date_of_birth) = 4").show() 
+-------------+ 
|date_of_birth| 
+-------------+ 
|         1972| 
+-------------+ 
//This is an invalid date. We can either drop this record or give some meaningful value like 01-01-1972 

```

**Python**

```scala
    //Load tab delimited file
    >>> init_data = spark.read.csv("<YOURPATH>/Oscars.txt",sep="\t",header=True)
    //Select columns of interest and ignore the rest
    >>> awards = init_data.select("birthplace", "date_of_birth",
            "race_ethnicity","year_of_award","award").toDF(
             "birthplace","date_of_birth","race","award_year","award")
    //register temporary view of this dataset
    >>> awards.createOrReplaceTempView("awards")
    scala>
    //Explore data
    >>> awards.select("award").distinct().show(10,False) //False => do not truncate
    +-----------------------+                                                       
    |award                  |
    +-----------------------+
    |Best Supporting Actress|
    |Best Director          |
    |Best Actress           |
    |Best Actor             |
    |Best Supporting Actor  |
    +-----------------------+
    //Check DOB quality
    >>> spark.sql("SELECT distinct(length(date_of_birth)) FROM awards ").show()
    +---------------------+                                                         
    |length(date_of_birth)|
    +---------------------+
    |                   15|
    |                    9|
    |                    4|
    |                    8|
    |                   10|
    |                   11|
    +---------------------+
    //Look at the value with unexpected length 4\. Note that length varies based on month name
    >>> spark.sql("SELECT date_of_birth FROM awards WHERE length(date_of_birth) = 4").show()
    +-------------+
    |date_of_birth|
    +-------------+
    |         1972|
    +-------------+
    //This is an invalid date. We can either drop this record or give some meaningful value like 01-01-1972

Most of the datasets contain a date field and unless they come from a single, controlled data source, it is highly likely that they will differ in their formats and are almost always a candidate for cleaning.
```

对于手头的数据集，您可能还注意到`date_of_birth`和`birthplace`需要大量清理。以下代码显示了分别清理`date_of_birth`和`birthplace`的两个**用户定义函数**（**UDFs**）。这些 UDFs 一次处理一个数据元素，它们只是普通的 Scala/Python 函数。这些用户定义函数应该被注册，以便它们可以从 SQL 语句中使用。最后一步是创建一个经过清理的数据框，以便参与进一步的分析。

注意清理`birthplace`的逻辑。这是一个薄弱的逻辑，因为我们假设任何以两个字符结尾的字符串都是美国州。我们必须将它们与有效缩写列表进行比较。同样，假设两位数年份总是来自二十世纪是另一个容易出错的假设。根据使用情况，数据科学家/数据工程师必须决定保留更多行是否重要，或者只应包含质量数据。所有这些决定都应该被清晰地记录以供参考：

**Scala:**

```scala
//UDF to clean date 
//This function takes 2 digit year and makes it 4 digit 
// Any exception returns an empty string 
scala> def fncleanDate(s:String) : String = {  
  var cleanedDate = "" 
  val dateArray: Array[String] = s.split("-") 
  try{    //Adjust year 
     var yr = dateArray(2).toInt 
     if (yr < 100) {yr = yr + 1900 } //make it 4 digit 
     cleanedDate = "%02d-%s-%04d".format(dateArray(0).toInt, 
                dateArray(1),yr) 
     } catch { case e: Exception => None } 
     cleanedDate } 
fncleanDate: (s: String)String 

```

**Python:**

```scala
    //This function takes 2 digit year and makes it 4 digit
    // Any exception returns an empty string
    >>> def fncleanDate(s):
          cleanedDate = ""
          dateArray = s.split("-")
          try:    //Adjust year
             yr = int(dateArray[2])
             if (yr < 100):
                  yr = yr + 1900 //make it 4 digit
             cleanedDate = "{0}-{1}-{2}".format(int(dateArray[0]),
                      dateArray[1],yr)
          except :
              None
          return cleanedDate

```

清理日期的 UDF 接受一个连字符日期字符串并拆分它。如果最后一个组件，即年份，是两位数长，则假定它是二十世纪的日期，并添加 1900 以将其转换为四位数格式。

以下 UDF 附加了国家作为美国，如果国家字符串是纽约市或最后一个组件为两个字符长，那么假定它是美国的一个州：

```scala
//UDF to clean birthplace 
// Data explorartion showed that  
// A. Country is omitted for USA 
// B. New York City does not have State code as well 
//This function appends country as USA if 
// A. the string contains New York City  (OR) 
// B. if the last component is of length 2 (eg CA, MA) 
scala> def fncleanBirthplace(s: String) : String = { 
        var cleanedBirthplace = "" 
        var strArray : Array[String] =  s.split(" ") 
        if (s == "New York City") 
           strArray = strArray ++ Array ("USA") 
        //Append country if last element length is 2 
        else if (strArray(strArray.length-1).length == 2) 
            strArray = strArray ++ Array("USA") 
        cleanedBirthplace = strArray.mkString(" ") 
        cleanedBirthplace } 

```

Python:

```scala
    >>> def fncleanBirthplace(s):
            cleanedBirthplace = ""
            strArray = s.split(" ")
            if (s == "New York City"):
                strArray += ["USA"]  //Append USA
            //Append country if last element length is 2
            elif (len(strArray[len(strArray)-1]) == 2):
                strArray += ["USA"]
            cleanedBirthplace = " ".join(strArray)
            return cleanedBirthplace

```

如果要从 SELECT 字符串中访问 UDFs，则应注册 UDFs：

**Scala:**

```scala
//Register UDFs 
scala> spark.udf.register("fncleanDate",fncleanDate(_:String)) 
res10: org.apache.spark.sql.expressions.UserDefinedFunction = UserDefinedFunction(<function1>,StringType,Some(List(StringType))) 
scala> spark.udf.register("fncleanBirthplace", fncleanBirthplace(_:String)) 
res11: org.apache.spark.sql.expressions.UserDefinedFunction = UserDefinedFunction(<function1>,StringType,Some(List(StringType))) 

```

**Python:**

```scala
    >>> from pyspark.sql.types import StringType
    >>> sqlContext.registerFunction("cleanDateUDF",fncleanDate, StringType())
    >>> sqlContext.registerFunction( "cleanBirthplaceUDF",fncleanBirthplace, StringType())

```

使用 UDFs 清理数据框。执行以下清理操作：

1.  调用 UDFs `fncleanDate`和`fncleanBirthplace`来修复出生地和国家。

1.  从`award_year`中减去出生年份以获得获奖时的`age`。

1.  保留`race`和`award`。

**Scala:**

```scala
//Create cleaned data frame 
scala> var cleaned_df = spark.sql ( 
            """SELECT fncleanDate (date_of_birth) dob, 
               fncleanBirthplace(birthplace) birthplace, 
               substring_index(fncleanBirthplace(birthplace),' ',-1)  
                               country, 
               (award_year - substring_index(fncleanDate( date_of_birth),'-',-1)) age, race, award FROM awards""") 
cleaned_df: org.apache.spark.sql.DataFrame = [dob: string, birthplace: string ... 4 more fields] 

```

**Python:**

```scala
//Create cleaned data frame 
>>> from pyspark.sql.functions import substring_index>>> cleaned_df = spark.sql (            """SELECT cleanDateUDF (date_of_birth) dob,               cleanBirthplaceUDF(birthplace) birthplace,               substring_index(cleanBirthplaceUDF(birthplace),' ',-1) country,               (award_year - substring_index(cleanDateUDF( date_of_birth),               '-',-1)) age, race, award FROM awards""")
```

最后一行需要一些解释。UDFs 类似于 SQL 函数，并且表达式被别名为有意义的名称。我们添加了一个计算列`age`，因为我们也想验证年龄的影响。`substring_index`函数搜索第一个参数的第二个参数。`-1`表示从右边查找第一次出现。

# 制定假设

假设是关于结果的最佳猜测。您根据问题、与利益相关者的对话以及查看数据形成初始假设。对于给定的问题，您可能会形成一个或多个假设。这个初始假设作为指导您进行探索性分析的路线图。制定假设对于统计上批准或不批准一个陈述非常重要，而不仅仅是通过查看数据作为数据矩阵或甚至通过视觉来进行。这是因为我们仅仅通过查看数据建立的认知可能是不正确的，有时甚至是具有欺骗性的。

现在你知道你的最终结果可能证明假设是正确的，也可能不是。来到我们为这节课考虑的案例研究，我们得出以下初始假设：

+   获奖者大多是白人

+   大多数获奖者来自美国

+   最佳男演员和女演员往往比最佳导演年轻

现在我们已经明确了我们的假设，我们已经准备好继续进行生命周期的下一步了。

# 数据探索

现在我们有了一个包含相关数据和初始假设的干净数据框架，是时候真正探索我们拥有的东西了。数据框架抽象提供了`group by`等函数，供您随时查看。您可以将清理后的数据框架注册为表，并运行经过时间考验的 SQL 语句来执行相同的操作。

现在也是绘制一些图表的时候了。这个可视化阶段是数据可视化章节中提到的探索性分析。这次探索的目标受到您从业务利益相关者和假设中获得的初始信息的极大影响。换句话说，您与利益相关者的讨论帮助您知道要寻找什么。

有一些通用准则适用于几乎所有数据科学任务，但又因不同的使用情况而异。让我们看一些通用的准则：

+   查找缺失数据并处理它。我们已经讨论了在第五章*Spark 上的数据分析*中执行此操作的各种方法。

+   查找数据集中的异常值并处理它们。我们也讨论了这个方面。请注意，有些情况下，我们认为是异常值和正常数据点的界限可能会根据使用情况而改变。

+   进行单变量分析，其中您单独探索数据集中的每个变量。频率分布或百分位数分布是相当常见的。也许绘制一些图表以获得更好的想法。这也将帮助您在进行数据建模之前准备数据。

+   验证您的初始假设。

+   检查数值数据的最小值和最大值。如果任何列中的变化太大，那可能是数据归一化或缩放的候选项。

+   检查分类数据（如城市名称等字符串值）中的不同值及其频率。如果任何列中有太多不同的值（也称为级别），则可能需要寻找减少级别数量的方法。如果一个级别几乎总是出现，那么该列对模型区分可能结果没有帮助。这样的列很可能被移除。在探索阶段，您只需找出这样的候选列，让数据准备阶段来处理实际操作。

在我们当前的数据集中，我们没有任何缺失数据，也没有任何可能造成挑战的数值数据。但是，当处理无效日期时，可能会出现一些缺失值。因此，以下代码涵盖了剩余的操作项目。此代码假定`cleaned_df`已经创建：

**Scala/Python:**

```scala
cleaned_df = cleaned_df.na.drop //Drop rows with missing values 
cleaned_df.groupBy("award","country").count().sort("country","award","count").show(4,False) 
+-----------------------+---------+-----+                                        
|award                  |country  |count| 
+-----------------------+---------+-----+ 
|Best Actor             |Australia|1    | 
|Best Actress           |Australia|1    | 
|Best Supporting Actor  |Australia|1    | 
|Best Supporting Actress|Australia|1    | 
+-----------------------+---------+-----+ 
//Re-register data as table 
cleaned_df.createOrReplaceTempView("awards") 
//Find out levels (distinct values) in each categorical variable 
spark.sql("SELECT count(distinct country) country_count, count(distinct race) race_count, count(distinct award) award_count from awards").show() 
+-------------+----------+-----------+                                           
|country_count|race_count|award_count| 
+-------------+----------+-----------+ 
|           34|         6|          5| 
+-------------+----------+-----------+ 

```

以下可视化与初始假设相对应。请注意，我们发现两个假设是正确的，但第三个假设不正确。这些可视化是使用 zeppelin 创建的：

![数据探索](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-ds/img/image_10_002.jpg)

请注意，并非所有假设都可以通过可视化来验证，因为它们有时可能具有欺骗性。因此，需要根据适用情况执行适当的统计检验，如 t 检验、ANOVA、卡方检验、相关性检验等。我们不会在本节详细介绍。有关详细信息，请参阅第五章*Spark 上的数据分析*。

# 数据准备

数据探索阶段帮助我们确定了在进入建模阶段之前需要修复的所有问题。每个单独的问题都需要仔细思考和审议，以选择最佳的修复方法。以下是一些常见问题和可能的修复方法。最佳修复取决于手头的问题和/或业务背景。

## 分类变量中的太多级别

这是我们面临的最常见问题之一。解决此问题取决于多个因素：

+   如果列几乎总是唯一的，例如，它是一个交易 ID 或时间戳，那么它在建模过程中不参与，除非你正在从中派生新特征。您可以安全地删除该列而不会丢失任何信息内容。通常在数据清洗阶段就会删除它。

+   如果可能用粗粒度级别（例如，州或国家而不是城市）替换级别，这在当前情境下通常是解决此问题的最佳方式。

+   您可能希望为每个不同级别添加具有 0 或 1 值的虚拟列。例如，如果单个列中有 100 个级别，则添加 100 个列。最多，一个观察（行）中将有一个列具有 1。这称为**独热编码**，Spark 通过`ml.features`包提供了这个功能。

+   另一个选择是保留最频繁的级别。您甚至可以将这些级别中的每一个附加到某个被认为与该级别“更接近”的主导级别中。此外，您可以将其余级别捆绑到一个单一的桶中，例如`Others`。

+   没有绝对限制级别的硬性规定。这取决于您对每个单独特征所需的粒度以及性能约束。

当前数据集在分类变量`country`中有太多级别。我们选择保留最频繁的级别，并将其余级别捆绑到`Others`中：

**Scala:**

```scala
//Country has too many values. Retain top ones and bundle the rest 
//Check out top 6 countries with most awards. 
scala> val top_countries_df = spark.sql("SELECT country, count(*) freq FROM awards GROUP BY country ORDER BY freq DESC LIMIT 6") 
top_countries_df: org.apache.spark.sql.DataFrame = [country: string, freq: bigint] 
scala> top_countries_df.show() 
+-------+----+                                                                   
|country|freq| 
+-------+----+ 
|    USA| 289| 
|England|  57| 
| France|   9| 
| Canada|   8| 
|  Italy|   7| 
|Austria|   7| 
+-------+----+ 
//Prepare top_countries list 
scala> val top_countries = top_countries_df.select("country").collect().map(x => x(0).toString) 
top_countries: Array[String] = Array(USA, England, New York City, France, Canada, Italy) 
//UDF to fix country. Retain top 6 and bundle the rest into "Others" 
scala> import org.apache.spark.sql.functions.udf 
import org.apache.spark.sql.functions.udf 
scala > val setCountry = udf ((s: String) => 
        { if (top_countries.contains(s)) {s} else {"Others"}}) 
setCountry: org.apache.spark.sql.expressions.UserDefinedFunction = UserDefinedFunction(<function1>,StringType,Some(List(StringType))) 
//Apply udf to overwrite country 
scala> cleaned_df = cleaned_df.withColumn("country", setCountry(cleaned_df("country"))) 
cleaned_df: org.apache.spark.sql.DataFrame = [dob: string, birthplace: string ... 4 more fields] 

```

**Python:**

```scala
    //Check out top 6 countries with most awards.
    >>> top_countries_df = spark.sql("SELECT country, count(*) freq FROM awards GROUP BY country ORDER BY freq DESC LIMIT 6")
    >>> top_countries_df.show()
    +-------+----+                                                                  
    |country|freq|
    +-------+----+
    |    USA| 289|
    |England|  57|
    | France|   9|
    | Canada|   8|
    |  Italy|   7|
    |Austria|   7|
    +-------+----+
    >>> top_countries = [x[0] for x in top_countries_df.select("country").collect()]
    //UDF to fix country. Retain top 6 and bundle the rest into "Others"
    >>> from pyspark.sql.functions import udf
    >>> from pyspark.sql.types import StringType
    >>> setCountry = udf(lambda s: s if s in top_countries else "Others", StringType())
    //Apply UDF
    >>> cleaned_df = cleaned_df.withColumn("country", setCountry(cleaned_df["country"]))

```

## 具有太多变化的数值变量

有时，数值数据值可能相差几个数量级。例如，如果您正在查看个人的年收入，它可能会有很大变化。Z 分数标准化（标准化）和最小-最大缩放是处理这种数据的两种常用选择。Spark 在`ml.features`包中提供了这两种转换。

我们当前的数据集没有这样的变量。我们唯一的数值变量是年龄，其值均匀为两位数。这是一个问题少了一个问题。

请注意，并非总是需要对此类数据进行标准化。如果您正在比较两个不同规模的变量，或者如果您正在使用聚类算法或 SVM 分类器，或者任何其他真正需要对数据进行标准化的情况，您可以对数据进行标准化。

### 缺失数据

这是一个重要的关注领域。任何目标本身缺失的观察应该从训练数据中删除。根据要求，剩下的观察可以保留一些填充值或删除。在填充缺失值时，您应该非常小心；否则可能会导致误导性的输出！看起来很容易只需继续并在连续变量的空白单元格中替换平均值，但这可能不是正确的方法。

我们当前的案例研究没有任何缺失数据，因此没有处理的余地。不过，让我们看一个例子。

假设您正在处理一个学生数据集，其中包含从一年级到五年级的数据。如果有一些缺失的`Age`值，您只需找到整个列的平均值并替换，那么这将成为一个异常值，并可能导致模糊的结果。您可以选择仅找到学生所在班级的平均值，然后填充该值。这至少是一个更好的方法，但可能不是完美的方法。在大多数情况下，您还必须给其他变量赋予权重。如果这样做，您可能会建立一个预测模型来查找缺失的值，这可能是一个很好的方法！

### 连续数据

数值数据通常是连续的，必须离散化，因为这是一些算法的先决条件。它通常被分成不同的桶或值的范围。然而，可能存在这样的情况，你不仅仅是根据数据的范围均匀地分桶，你可能需要考虑方差或标准差或任何其他适用的原因来正确地分桶。现在，决定桶的数量也取决于数据科学家的判断，但这也需要仔细分析。太少的桶会降低粒度，而太多的桶与拥有太多的分类级别几乎是一样的。在我们的案例研究中，“年龄”就是这样的数据的一个例子，我们需要将其离散化。我们将其分成不同的桶。例如，看看这个管道阶段，它将“年龄”转换为 10 个桶：

**Scala:**

```scala
scala> val splits = Array(Double.NegativeInfinity, 35.0, 45.0, 55.0, 
          Double.PositiveInfinity) 
splits: Array[Double] = Array(-Infinity, 35.0, 45.0, 55.0, Infinity) 
scala> val bucketizer = new Bucketizer().setSplits(splits). 
                 setInputCol("age").setOutputCol("age_buckets") 
bucketizer: org.apache.spark.ml.feature.Bucketizer = bucketizer_a25c5d90ac14 

```

**Python:**

```scala
    >>> splits = [-float("inf"), 35.0, 45.0, 55.0,
                   float("inf")]
    >>> bucketizer = Bucketizer(splits = splits, inputCol = "age",
                        outputCol = "age_buckets")

```

### 分类数据

我们已经讨论了将连续数据离散化并转换为类别或桶的需要。我们还讨论了引入虚拟变量，每个分类变量的每个不同值都有一个。还有一个常见的数据准备做法，即将分类级别转换为数值（离散）数据。这是因为许多机器学习算法使用数值数据、整数和实值数字，或者其他情况可能需要。因此，我们需要将分类数据转换为数值数据。

这种方法可能存在缺点。在本质上无序的数据中引入顺序有时可能是不合逻辑的。例如，将数字 0、1、2、3 分配给颜色“红色”、“绿色”、“蓝色”和“黑色”是没有意义的。这是因为我们不能说红色距离“绿色”一单位，绿色距离“蓝色”也是如此！如果适用，在许多这种情况下引入虚拟变量更有意义。

### 准备数据

在讨论了常见问题和可能的修复方法之后，让我们看看如何准备我们当前的数据集。我们已经涵盖了与太多级别问题相关的代码修复。以下示例显示了其余部分。它将所有特征转换为单个特征列。它还将一些数据设置为测试模型。这段代码严重依赖于`ml.features`包，该包旨在支持数据准备阶段。请注意，这段代码只是定义了需要做什么。转换尚未进行。这些将成为随后定义的管道中的阶段。执行被尽可能地推迟，直到实际模型建立。Catalyst 优化器找到了实施管道的最佳路径：

**Scala:**

```scala
//Define pipeline to convert categorical labels to numerical labels 
scala> import org.apache.spark.ml.feature.{StringIndexer, Bucketizer, VectorAssembler} 
import org.apache.spark.ml.feature.{StringIndexer, Bucketizer, VectorAssembler} 
scala> import org.apache.spark.ml.Pipeline 
import org.apache.spark.ml.Pipeline 
//Race 
scala> val raceIdxer = new StringIndexer(). 
           setInputCol("race").setOutputCol("raceIdx") 
raceIdxer: org.apache.spark.ml.feature.StringIndexer = strIdx_80eddaa022e6 
//Award (prediction target) 
scala> val awardIdxer = new StringIndexer(). 
         setInputCol("award").setOutputCol("awardIdx") 
awardIdxer: org.apache.spark.ml.feature.StringIndexer = strIdx_256fe36d1436 
//Country 
scala> val countryIdxer = new StringIndexer(). 
         setInputCol("country").setOutputCol("countryIdx") 
countryIdxer: org.apache.spark.ml.feature.StringIndexer = strIdx_c73a073553a2 

//Convert continuous variable age to buckets 
scala> val splits = Array(Double.NegativeInfinity, 35.0, 45.0, 55.0, 
          Double.PositiveInfinity) 
splits: Array[Double] = Array(-Infinity, 35.0, 45.0, 55.0, Infinity) 

scala> val bucketizer = new Bucketizer().setSplits(splits). 
                 setInputCol("age").setOutputCol("age_buckets") 
bucketizer: org.apache.spark.ml.feature.Bucketizer = bucketizer_a25c5d90ac14 

//Prepare numerical feature vector by clubbing all individual features 
scala> val assembler = new VectorAssembler().setInputCols(Array("raceIdx", 
          "age_buckets","countryIdx")).setOutputCol("features") 
assembler: org.apache.spark.ml.feature.VectorAssembler = vecAssembler_8cf17ee0cd60 

//Define data preparation pipeline 
scala> val dp_pipeline = new Pipeline().setStages( 
          Array(raceIdxer,awardIdxer, countryIdxer, bucketizer, assembler)) 
dp_pipeline: org.apache.spark.ml.Pipeline = pipeline_06717d17140b 
//Transform dataset 
scala> cleaned_df = dp_pipeline.fit(cleaned_df).transform(cleaned_df) 
cleaned_df: org.apache.spark.sql.DataFrame = [dob: string, birthplace: string ... 9 more fields] 
//Split data into train and test datasets 
scala> val Array(trainData, testData) = 
        cleaned_df.randomSplit(Array(0.7, 0.3)) 
trainData: org.apache.spark.sql.Dataset[org.apache.spark.sql.Row] = [dob: string, birthplace: string ... 9 more fields] 
testData: org.apache.spark.sql.Dataset[org.apache.spark.sql.Row] = [dob: string, birthplace: string ... 9 more fields] 

```

**Python:**

```scala
    //Define pipeline to convert categorical labels to numcerical labels
    >>> from pyspark.ml.feature import StringIndexer, Bucketizer, VectorAssembler
    >>> from pyspark.ml import Pipelin
    //Race
    >>> raceIdxer = StringIndexer(inputCol= "race", outputCol="raceIdx")
    //Award (prediction target)
    >>> awardIdxer = StringIndexer(inputCol = "award", outputCol="awardIdx")
    //Country
    >>> countryIdxer = StringIndexer(inputCol = "country", outputCol = "countryIdx")

    //Convert continuous variable age to buckets
    >>> splits = [-float("inf"), 35.0, 45.0, 55.0,
                   float("inf")]
    >>> bucketizer = Bucketizer(splits = splits, inputCol = "age",
                        outputCol = "age_buckets")
    >>>
    //Prepare numerical feature vector by clubbing all individual features
    >>> assembler = VectorAssembler(inputCols = ["raceIdx", 
              "age_buckets","countryIdx"], outputCol = "features")

    //Define data preparation pipeline
    >>> dp_pipeline = Pipeline(stages = [raceIdxer,
             awardIdxer, countryIdxer, bucketizer, assembler])
    //Transform dataset
    >>> cleaned_df = dp_pipeline.fit(cleaned_df).transform(cleaned_df)
    >>> cleaned_df.columns
    ['dob', 'birthplace', 'country', 'age', 'race', 'award', 'raceIdx', 'awardIdx', 'countryIdx', 'age_buckets', 'features']

    //Split data into train and test datasets
    >>> trainData, testData = cleaned_df.randomSplit([0.7, 0.3])

```

在进行所有数据准备活动之后，您将得到一个完全数字化的数据，没有缺失值，并且每个属性中的级别是可管理的。您可能已经删除了可能对手头的分析没有太大价值的任何属性。这就是我们所说的**最终数据矩阵**。现在您已经准备好开始对数据进行建模了。因此，首先将源数据分成训练数据和测试数据。模型使用训练数据进行“训练”，并使用测试数据进行“测试”。请注意，拆分是随机的，如果重新进行拆分，您可能会得到不同的训练和测试分区。

# 模型构建

模型是事物的表现，现实的描述或描述。就像物理建筑的模型一样，数据科学模型试图理解现实；在这种情况下，现实是特征和预测变量之间的基本关系。它们可能不是 100%准确，但仍然非常有用，可以根据数据为我们的业务空间提供一些深刻的见解。

有几种机器学习算法可以帮助我们对数据进行建模，Spark 提供了其中许多。然而，要构建哪种模型仍然是一个价值百万的问题。这取决于各种因素，比如解释性和准确性的权衡、手头有多少数据、分类或数值变量、时间和内存限制等等。在下面的代码示例中，我们随机训练了一些模型，以展示如何完成这些步骤。

我们将根据种族、年龄和国家来预测奖项类型。我们将使用 DecisionTreeClassifier、RandomForestClassifier 和 OneVsRest 算法。这三个是任意选择的。它们都适用于多类标签，并且易于理解。我们使用了`ml`包提供的以下评估指标：

+   **准确性**：正确预测的观察比例。

+   **加权精确度**：精确度是正确的正例观察值与所有正例观察值的比率。加权精确度考虑了各个类别的频率。

+   **加权召回率**：召回率是正例与实际正例的比率。实际正例是真正例和假负例的总和。加权召回率考虑了各个类别的频率。

+   **F1**：默认的评估指标。这是精确度和召回率的加权平均值。

**Scala：**

```scala
scala> import org.apache.spark.ml.Pipeline 
import org.apache.spark.ml.Pipeline 
scala> import org.apache.spark.ml.classification.DecisionTreeClassifier 
import org.apache.spark.ml.classification.DecisionTreeClassifier 

//Use Decision tree classifier 
scala> val dtreeModel = new DecisionTreeClassifier(). 
           setLabelCol("awardIdx").setFeaturesCol("features"). 
           fit(trainData) 
dtreeModel: org.apache.spark.ml.classification.DecisionTreeClassificationModel = DecisionTreeClassificationModel (uid=dtc_76c9e80680a7) of depth 5 with 39 nodes 

//Run predictions using testData 
scala> val dtree_predictions = dtreeModel.transform(testData) 
dtree_predictions: org.apache.spark.sql.DataFrame = [dob: string, birthplace: string ... 12 more fields] 

//Examine results. Your results may vary due to randomSplit 
scala> dtree_predictions.select("award","awardIdx","prediction").show(4) 
+--------------------+--------+----------+ 
|               award|awardIdx|prediction| 
+--------------------+--------+----------+ 
|       Best Director|     1.0|       1.0| 
|        Best Actress|     0.0|       0.0| 
|        Best Actress|     0.0|       0.0| 
|Best Supporting A...|     4.0|       3.0| 
+--------------------+--------+----------+ 

//Compute prediction mismatch count 
scala> dtree_predictions.filter(dtree_predictions("awardIdx") =!= dtree_predictions("prediction")).count() 
res10: Long = 88 
scala> testData.count 
res11: Long = 126 
//Predictions match with DecisionTreeClassifier model is about 30% ((126-88)*100/126) 

//Train Random forest 
scala> import org.apache.spark.ml.classification.RandomForestClassifier 
import org.apache.spark.ml.classification.RandomForestClassifier 
scala> import org.apache.spark.ml.classification.RandomForestClassificationModel 
import org.apache.spark.ml.classification.RandomForestClassificationModel 
scala> import org.apache.spark.ml.feature.{StringIndexer, IndexToString, VectorIndexer} 
import org.apache.spark.ml.feature.{StringIndexer, IndexToString, VectorIndexer} 

//Build model 
scala> val RFmodel = new RandomForestClassifier(). 
        setLabelCol("awardIdx"). 
        setFeaturesCol("features"). 
        setNumTrees(6).fit(trainData) 
RFmodel: org.apache.spark.ml.classification.RandomForestClassificationModel = RandomForestClassificationModel (uid=rfc_c6fb8d764ade) with 6 trees 
//Run predictions on the same test data using Random Forest model 
scala> val RF_predictions = RFmodel.transform(testData) 
RF_predictions: org.apache.spark.sql.DataFrame = [dob: string, birthplace: string ... 12 more fields] 
//Check results 
scala> RF_predictions.filter(RF_predictions("awardIdx") =!= RF_predictions("prediction")).count() 
res29: Long = 87 //Roughly the same as DecisionTreeClassifier 

//Try OneVsRest Logistic regression technique 
scala> import org.apache.spark.ml.classification.{LogisticRegression, OneVsRest} 
import org.apache.spark.ml.classification.{LogisticRegression, OneVsRest} 
//This model requires a base classifier 
scala> val classifier = new LogisticRegression(). 
            setLabelCol("awardIdx"). 
            setFeaturesCol("features"). 
            setMaxIter(30). 
            setTol(1E-6). 
            setFitIntercept(true) 
classifier: org.apache.spark.ml.classification.LogisticRegression = logreg_82cd24368c87 

//Fit OneVsRest model 
scala> val ovrModel = new OneVsRest(). 
           setClassifier(classifier). 
           setLabelCol("awardIdx"). 
           setFeaturesCol("features"). 
           fit(trainData) 
ovrModel: org.apache.spark.ml.classification.OneVsRestModel = oneVsRest_e696c41c0bcf 
//Run predictions 
scala> val OVR_predictions = ovrModel.transform(testData) 
predictions: org.apache.spark.sql.DataFrame = [dob: string, birthplace: string ... 10 more fields] 
//Check results 
scala> OVR_predictions.filter(OVR_predictions("awardIdx") =!= OVR_predictions("prediction")).count()          
res32: Long = 86 //Roughly the same as other models 

```

**Python：**

```scala
    >>> from pyspark.ml import Pipeline
    >>> from pyspark.ml.classification import DecisionTreeClassifier

    //Use Decision tree classifier
    >>> dtreeModel = DecisionTreeClassifier(labelCol = "awardIdx", featuresCol="features").fit(trainData)

    //Run predictions using testData
    >>> dtree_predictions = dtreeModel.transform(testData)

    //Examine results. Your results may vary due to randomSplit
    >>> dtree_predictions.select("award","awardIdx","prediction").show(4)
    +--------------------+--------+----------+
    |               award|awardIdx|prediction|
    +--------------------+--------+----------+
    |       Best Director|     1.0|       4.0|
    |       Best Director|     1.0|       1.0|
    |       Best Director|     1.0|       1.0|
    |Best Supporting A...|     4.0|       3.0|
    +--------------------+--------+----------+

    >>> dtree_predictions.filter(dtree_predictions["awardIdx"] != dtree_predictions["prediction"]).count()
    92
    >>> testData.count()
    137
    >>>
    //Predictions match with DecisionTreeClassifier model is about 31% ((133-92)*100/133)

    //Train Random forest
    >>> from pyspark.ml.classification import RandomForestClassifier, RandomForestClassificationModel
    >>> from pyspark.ml.feature import StringIndexer, IndexToString, VectorIndexer
    >>> from pyspark.ml.evaluation import MulticlassClassificationEvaluator

    //Build model
    >>> RFmodel = RandomForestClassifier(labelCol = "awardIdx", featuresCol = "features", numTrees=6).fit(trainData)

    //Run predictions on the same test data using Random Forest model
    >>> RF_predictions = RFmodel.transform(testData)
    //Check results
    >>> RF_predictions.filter(RF_predictions["awardIdx"] != RF_predictions["prediction"]).count()
    94     //Roughly the same as DecisionTreeClassifier

    //Try OneVsRest Logistic regression technique
    >>> from pyspark.ml.classification import LogisticRegression, OneVsRest

    //This model requires a base classifier
    >>> classifier = LogisticRegression(labelCol = "awardIdx", featuresCol="features",
                  maxIter = 30, tol=1E-6, fitIntercept = True)
    //Fit OneVsRest model
    >>> ovrModel = OneVsRest(classifier = classifier, labelCol = "awardIdx",
                    featuresCol = "features").fit(trainData)
    //Run predictions
    >>> OVR_predictions = ovrModel.transform(testData)
    //Check results
    >>> OVR_predictions.filter(OVR_predictions["awardIdx"] != OVR_predictions["prediction"]).count()
    90  //Roughly the same as other models

```

到目前为止，我们尝试了一些模型，并发现它们大致表现相同。还有其他各种验证模型性能的方法。这再次取决于你使用的算法、业务背景和产生的结果。让我们看看`spark.ml.evaluation`包中提供的一些开箱即用的指标：

**Scala：**

```scala
scala> import org.apache.spark.ml.evaluation.MulticlassClassificationEvaluator 
import org.apache.spark.ml.evaluation.MulticlassClassificationEvaluator 
//F1 
scala> val f1_eval = new MulticlassClassificationEvaluator(). 
                     setLabelCol("awardIdx") //Default metric is F1 
f1_eval: org.apache.spark.ml.evaluation.MulticlassClassificationEvaluator = mcEval_e855a949bb0e 

//WeightedPrecision 
scala> val wp_eval = new MulticlassClassificationEvaluator(). 
                     setMetricName("weightedPrecision").setLabelCol("awardIdx") 
wp_eval: org.apache.spark.ml.evaluation.MulticlassClassificationEvaluator = mcEval_44fd64e29d0a 

//WeightedRecall 
scala> val wr_eval = new MulticlassClassificationEvaluator(). 
                     setMetricName("weightedRecall").setLabelCol("awardIdx") 
wr_eval: org.apache.spark.ml.evaluation.MulticlassClassificationEvaluator = mcEval_aa341966305a 
//Compute measures for all models 
scala> val f1_eval_list = List (dtree_predictions, RF_predictions, OVR_predictions) map ( 
           x => f1_eval.evaluate(x)) 
f1_eval_list: List[Double] = List(0.2330854098674473, 0.2330854098674473, 0.2330854098674473) 
scala> val wp_eval_list = List (dtree_predictions, RF_predictions, OVR_predictions) map ( 
           x => wp_eval.evaluate(x)) 
wp_eval_list: List[Double] = List(0.2661599224979506, 0.2661599224979506, 0.2661599224979506) 

scala> val wr_eval_list = List (dtree_predictions, RF_predictions, OVR_predictions) map ( 
           x => wr_eval.evaluate(x)) 
wr_eval_list: List[Double] = List(0.31746031746031744, 0.31746031746031744, 0.31746031746031744) 

```

**Python：**

```scala
    >>> from pyspark.ml.evaluation import MulticlassClassificationEvaluator

    //F1
    >>> f1_eval = MulticlassClassificationEvaluator(labelCol="awardIdx") //Default metric is F1
    //WeightedPrecision
    >>> wp_eval = MulticlassClassificationEvaluator(labelCol="awardIdx", metricName="weightedPrecision")
    //WeightedRecall
    >>> wr_eval = MulticlassClassificationEvaluator(labelCol="awardIdx", metricName="weightedRecall")
    //Accuracy
    >>> acc_eval = MulticlassClassificationEvaluator(labelCol="awardIdx", metricName="Accuracy")
    //Compute measures for all models
    >>> f1_eval_list = [ f1_eval.evaluate(x) for x in [dtree_predictions, RF_predictions, OVR_predictions]]
    >>> wp_eval_list = [ wp_eval.evaluate(x) for x in [dtree_predictions, RF_predictions, OVR_predictions]]
    >>> wr_eval_list = [ wr_eval.evaluate(x) for x in [dtree_predictions, RF_predictions, OVR_predictions]]
    //Print results for DecisionTree, Random Forest and OneVsRest
    >>> f1_eval_list
    [0.2957949866055487, 0.2645186821042419, 0.2564967990214734]
    >>> wp_eval_list
    [0.3265407181548341, 0.31914852065228005, 0.25295826631254753]
    >>> wr_eval_list
    [0.3082706766917293, 0.2932330827067669, 0.3233082706766917]

```

**输出：**

|  | **决策树** | **随机森林** | **OneVsRest** |
| --- | --- | --- | --- |
| F1 | 0.29579 | 0.26451 | 0.25649 |
| 加权精确度 | 0.32654 | 0.26451 | 0.25295 |
| 加权召回率 | 0.30827 | 0.29323 | 0.32330 |

在验证模型性能后，你将不得不尽可能调整模型。现在，调整可以在数据级别和算法级别两种方式进行。提供算法期望的正确数据非常重要。问题在于，无论你提供什么数据，算法可能仍然会给出一些输出-它从不抱怨！因此，除了通过处理缺失值、处理一元和多元异常值等来正确清理数据之外，你还可以创建更多相关的特征。这种特征工程通常被视为数据科学中最重要的方面。具有良好的领域专业知识有助于构建更好的特征。现在，来到调整的算法方面，总是有优化我们传递给算法的参数的空间。你可以选择使用网格搜索来找到最佳参数。此外，数据科学家应该质疑自己要使用哪种损失函数以及为什么，以及在 GD、SGD、L-BFGS 等中，要使用哪种算法来优化损失函数以及为什么。

请注意，前面的方法仅用于演示如何在 Spark 上执行这些步骤。仅仅通过准确性水平来选择一种算法可能不是最佳方式。选择算法取决于你处理的数据类型、结果变量、业务问题/需求、计算挑战、可解释性等等。

# 数据可视化

**数据可视化**是在从事数据科学任务时经常需要的东西。在构建任何模型之前，最好是要可视化每个变量，以了解它们的分布，理解它们的特征，并找到异常值，以便进行处理。散点图、箱线图、条形图等简单工具是用于这些目的的一些多功能、方便的工具。此外，您将不得不在大多数步骤中使用可视化工具，以确保您朝着正确的方向前进。

每次您想与业务用户或利益相关者合作时，通过可视化传达您的分析总是一个很好的做法。可视化可以更有意义地容纳更多的数据，并且本质上是直观的。

请注意，大多数数据科学任务的结果最好通过可视化和仪表板向业务用户呈现。我们已经有了一个专门讨论这个主题的章节，所以我们不会深入讨论。

# 向业务用户传达结果

在现实生活中，通常情况下，您必须不断与业务进行沟通。在最终确定生产就绪模型之前，您可能必须构建多个模型，并将结果传达给业务。

可实施的模型并不总是取决于准确性；您可能需要引入其他措施，如灵敏度、特异性或 ROC 曲线，并通过可视化来表示您的结果，比如增益/提升图表或具有统计显著性的 K-S 测试的输出。请注意，这些技术需要业务用户的输入。这种输入通常指导您构建模型或设置阈值的方式。让我们看一些例子，以更好地理解它是如何工作的：

+   如果一个回归器预测事件发生的概率，那么盲目地将阈值设置为 0.5，并假设大于 0.5 的为 1，小于 0.5 的为 0 可能不是最佳方式！您可以使用 ROC 曲线，并做出更科学或更合乎逻辑的决定。

+   对于癌症测试的假阴性预测可能根本不可取！这是一种极端的生命风险。

+   与寄送硬拷贝相比，电子邮件营销成本更低。因此，企业可能决定向预测概率低于 0.5（比如 0.35）的收件人发送电子邮件。

请注意，前述决策受到业务用户或问题所有者的严重影响，数据科学家与他们密切合作，以在这些情况下做出决策。

正如前面已经讨论过的，正确的可视化是向业务传达结果的最佳方式。

# 摘要

在本章中，我们进行了一个案例研究，并完成了数据分析的整个生命周期。在构建数据产品的过程中，我们应用了之前章节中所学到的知识。我们提出了一个业务问题，形成了一个初始假设，获取了数据，并准备好了模型构建。我们尝试构建多个模型，并找到了一个合适的模型。

在下一章，也是最后一章中，我们将讨论使用 Spark 构建真实世界的应用程序。

# 参考文献

[`www2.sas.com/proceedings/forum2007/073-2007.pdf`](http://www2.sas.com/proceedings/forum2007/073-2007.pdf)。

[`azure.microsoft.com/en-in/documentation/articles/machine-learning-algorithm-choice/`](https://azure.microsoft.com/en-in/documentation/articles/machine-learning-algorithm-choice/)。

[`www.cs.cornell.edu/courses/cs578/2003fa/performance_measures.pdf`](http://www.cs.cornell.edu/courses/cs578/2003fa/performance_measures.pdf)。
