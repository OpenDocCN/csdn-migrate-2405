# PySpark 大数据分析实用指南（一）

> 原文：[`zh.annas-archive.org/md5/62C4D847CB664AD1379DE037B94D0AE5`](https://zh.annas-archive.org/md5/62C4D847CB664AD1379DE037B94D0AE5)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

Apache Spark 是一个开源的并行处理框架，已经存在了相当长的时间。Apache Spark 的许多用途之一是在集群计算机上进行数据分析应用程序。

本书将帮助您实施一些实用和经过验证的技术，以改进 Apache Spark 中的编程和管理方面。您不仅将学习如何使用 Spark 和 Python API 来创建高性能的大数据分析，还将发现测试、保护和并行化 Spark 作业的技术。

本书涵盖了 PySpark 的安装和设置、RDD 操作、大数据清理和整理，以及将数据聚合和总结为有用报告。您将学习如何从所有流行的数据托管平台（包括 HDFS、Hive、JSON 和 S3）获取数据，并使用 PySpark 处理大型数据集，获得实际的大数据经验。本书还将帮助您在本地机器上开发原型，然后逐步处理生产环境和大规模的混乱数据。

# 本书的受众

本书适用于开发人员、数据科学家、业务分析师或任何需要可靠地分析大量大规模真实世界数据的人。无论您是负责创建公司的商业智能功能，还是为机器学习模型创建出色的数据平台，或者希望使用代码放大业务影响，本书都适合您。

# 本书涵盖的内容

第一章《安装 Pyspark 并设置开发环境》涵盖了 PySpark 的安装，以及学习 Spark 的核心概念，包括弹性分布式数据集（RDDs）、SparkContext 和 Spark 工具，如 SparkConf 和 SparkShell。

第二章《使用 RDD 将大数据导入 Spark 环境》解释了如何使用 RDD 将大数据导入 Spark 环境，使用各种工具与修改数据进行交互，以便提取有用的见解。

第三章《使用 Spark 笔记本进行大数据清理和整理》介绍了如何在笔记本应用程序中使用 Spark，从而促进 RDD 的有效使用。

第四章《将数据聚合和总结为有用报告》描述了如何使用 map 和 reduce 函数计算平均值，执行更快的平均值计算，并使用键/值对数据点的数据透视表。

第五章《使用 MLlib 进行强大的探索性数据分析》探讨了 Spark 执行回归任务的能力，包括线性回归和 SVM 等模型。

第六章《使用 SparkSQL 为大数据添加结构》解释了如何使用 Spark SQL 模式操作数据框，并使用 Spark DSL 构建结构化数据操作的查询。

第七章《转换和操作》介绍了 Spark 转换以推迟计算，然后考虑应避免的转换。我们还将使用`reduce`和`reduceByKey`方法对数据集进行计算。

第八章《不可变设计》解释了如何使用 DataFrame 操作进行转换，以讨论高度并发环境中的不可变性。

第九章《避免洗牌和减少运营成本》涵盖了洗牌和应该使用的 Spark API 操作。然后我们将测试在 Apache Spark 中引起洗牌的操作，以了解应避免哪些操作。

第十章《以正确格式保存数据》解释了如何以正确格式保存数据，以及如何使用 Spark 的标准 API 将数据保存为纯文本。

第十一章《使用 Spark 键/值 API》，讨论了可用于键/值对的转换。我们将研究键/值对的操作，并查看键/值数据上可用的分区器。

第十二章《测试 Apache Spark 作业》更详细地讨论了在不同版本的 Spark 中测试 Apache Spark 作业。

第十三章，*利用 Spark GraphX API*，介绍了如何利用 Spark GraphX API。我们将对 Edge API 和 Vertex API 进行实验。

# 充分利用本书

本书需要一些 PySpark、Python、Java 和 Scala 的基本编程经验。

# 下载示例代码文件

您可以从您在[www.packt.com](http://www.packt.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了这本书，您可以访问[www.packt.com/support](http://www.packt.com/support)并注册，以便文件直接通过电子邮件发送给您。

您可以按照以下步骤下载代码文件：

1.  在[www.packt.com](http://www.packt.com)登录或注册。

1.  选择“支持”选项卡。

1.  单击“代码下载和勘误”。

1.  在搜索框中输入书名并按照屏幕上的说明操作。

下载文件后，请确保使用最新版本的解压缩或提取文件夹：

+   WinRAR/7-Zip for Windows

+   Zipeg/iZip/UnRarX for Mac

+   7-Zip/PeaZip for Linux

本书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Hands-On-Big-Data-Analytics-with-PySpark`](https://github.com/PacktPublishing/Hands-On-Big-Data-Analytics-with-PySpark)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还有其他代码包，来自我们丰富的书籍和视频目录，可在**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**上找到。请查看！

# 下载彩色图像

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图像。您可以在这里下载：[`www.packtpub.com/sites/default/files/downloads/9781838644130_ColorImages.pdf`](http://www.packtpub.com/sites/default/files/downloads/9781838644130_ColorImages.pdf)。

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：指示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。以下是一个例子：“将下载的`WebStorm-10*.dmg`磁盘映像文件挂载为系统中的另一个磁盘。”

代码块设置如下：

```py
test("Should use immutable DF API") {
    import spark.sqlContext.implicits._
    //given
    val userData =
        spark.sparkContext.makeRDD(List(
            UserData("a", "1"),
            UserData("b", "2"),
            UserData("d", "200")
        )).toDF()
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```py
class ImmutableRDD extends FunSuite {
    val spark: SparkContext = SparkSession
        .builder().master("local[2]").getOrCreate().sparkContext

test("RDD should be immutable") {
    //given
    val data = spark.makeRDD(0 to 5)
```

任何命令行输入或输出都以以下方式编写：

```py
total_duration/(normal_data.count())
```

**粗体**：表示一个新术语、一个重要词或屏幕上看到的词。例如，菜单或对话框中的词会以这种方式出现在文本中。以下是一个例子：“从管理面板中选择系统信息。”

警告或重要说明会出现在这样的地方。

提示和技巧会出现在这样的地方。


# 第一章：安装 Pyspark 并设置开发环境

在本章中，我们将介绍 Spark 并学习核心概念，如 SparkContext，以及 Spark 工具，如 SparkConf 和 Spark shell。唯一的先决条件是对基本 Python 概念的了解，并且希望从大数据中寻求洞察力。我们将学习如何使用 Spark SQL 分析和发现模式，以改进我们的业务智能。此外，您将能够通过设置 PySpark 来快速迭代解决方案。在本书结束时，您将能够使用 PySpark 处理真实的混乱数据集，从而获得实际的大数据经验。

在本章中，我们将涵盖以下主题：

+   PySpark 概述

+   在 Windows 上设置 Spark 和 PySpark

+   Spark 和 PySpark 中的核心概念

# PySpark 概述

在开始安装 PySpark 之前，PySpark 是 Spark 的 Python 接口，让我们先了解一些 Spark 和 PySpark 的核心概念。Spark 是 Apache 的最新大数据工具，可以通过简单地转到[`spark.apache.org/`](http://spark.apache.org/)找到。它是用于大规模数据处理的统一分析引擎。这意味着，如果您有大量数据，您可以将这些数据输入 Spark 以快速创建一些分析。如果我们比较 Hadoop 和 Spark 的运行时间，Spark 比 Hadoop 快一百倍以上。它非常易于使用，因为有非常好的 API 可用于与 Spark 一起使用。

Spark 平台的四个主要组件如下：

+   **Spark SQL**：Spark 的清理语言

+   **Spark Streaming**：允许您提供实时流数据

+   **MLlib（机器学习）**：Spark 的机器学习库

+   **GraphX（图形）**：Spark 的图形库

Spark 中的核心概念是 RDD，它类似于 pandas DataFrame，或 Python 字典或列表。这是 Spark 用来在基础设施上存储大量数据的一种方式。RDD 与存储在本地内存中的内容（如 pandas DataFrame）的关键区别在于，RDD 分布在许多机器上，但看起来像一个统一的数据集。这意味着，如果您有大量数据要并行操作，您可以将其放入 RDD 中，Spark 将为您处理并行化和数据的集群。

Spark 有三种不同的接口，如下所示：

+   Scala

+   Java

+   Python

Python 类似于 PySpark 集成，我们将很快介绍。现在，我们将从 PySpark 包中导入一些库，以帮助我们使用 Spark。我们理解 Spark 的最佳方式是查看示例，如下面的屏幕截图所示：

```py
lines = sc.textFile("data.txt")
lineLengths = lines.map(lambda s: len(s))
totalLength = lineLengths.reduce(lambda a, b: a + b)
```

在上面的代码中，我们通过调用`SC.textFile("data.txt")`创建了一个名为`lines`的新变量。`sc`是代表我们的 Spark 集群的 Python 对象。Spark 集群是一系列存储我们的 Spark 进程的实例或云计算机。通过调用`textFile`构造函数并输入`data.text`，我们可能已经输入了一个大型文本文件，并仅使用这一行创建了一个 RDD。换句话说，我们在这里要做的是将一个大型文本文件输入到分布式集群和 Spark 中，而 Spark 会为我们处理这个集群。

在第二行和第三行，我们有一个 MapReduce 函数。在第二行，我们使用`lambda`函数将长度函数映射到`data.text`的每一行。在第三行，我们调用了一个减少函数，将所有`lineLengths`相加，以产生文档的总长度。虽然 Python 的`lines`是一个包含`data.text`中所有行的变量，但在幕后，Spark 实际上正在处理`data.text`的片段在 Spark 集群上的两个不同实例上的分布，并处理所有这些实例上的 MapReduce 计算。

# Spark SQL

Spark SQL 是 Spark 平台上的四个组件之一，正如我们在本章中之前看到的。它可以用于执行 SQL 查询或从任何现有的 Hive 绝缘中读取数据，其中 Hive 也是来自 Apache 的数据库实现。Spark SQL 看起来非常类似于 MySQL 或 Postgres。以下代码片段是一个很好的例子：

```py
#Register the DataFrame as a SQL temporary view
df.CreateOrReplaceTempView("people")

sqlDF = spark.sql("SELECT * FROM people")
sqlDF.show()

#+----+-------+
#| age|   name|
#+----+-------+
#+null|Jackson|
#|  30| Martin|
#|  19| Melvin|
#+----|-------|
```

您需要从某个表中选择所有列，例如`people`，并使用 Spark 对象，您将输入一个非常标准的 SQL 语句，这将显示一个 SQL 结果，就像您从正常的 SQL 实现中所期望的那样。

现在让我们看看数据集和数据框。数据集是分布式数据集合。它是在 Spark 1.6 中添加的一个接口，提供了 RDD 的优势。另一方面，数据框对于那些使用过 pandas 或 R 的人来说非常熟悉。数据框只是一个组织成命名列的数据集，类似于关系数据库或 Python 中的数据框。数据集和数据框之间的主要区别在于数据框有列名。可以想象，这对于机器学习工作和输入到诸如 scikit-learn 之类的东西非常方便。

让我们看看如何使用数据框。以下代码片段是数据框的一个快速示例：

```py
# spark is an existing SparkSession
df = spark.read.json("examples/src/main/resources/people.json")
# Displays the content of the DataFrame to stdout
df.show()

#+----+-------+
#| age|   name|
#+----+-------+
#+null|Jackson|
#|  30| Martin|
#|  19| Melvin|
#+----|-------|
```

与 pandas 或 R 一样，`read.json`允许我们从 JSON 文件中输入一些数据，而`df.show`以类似于 pandas 的方式显示数据框的内容。

正如我们所知，MLlib 用于使机器学习变得可扩展和简单。MLlib 允许您执行常见的机器学习任务，例如特征化；创建管道；保存和加载算法、模型和管道；以及一些实用程序，例如线性代数、统计和数据处理。另一件事需要注意的是，Spark 和 RDD 几乎是不可分割的概念。如果您对 Spark 的主要用例是机器学习，Spark 现在实际上鼓励您使用基于数据框的 MLlib API，这对我们来说非常有益，因为我们已经熟悉 pandas，这意味着平稳过渡到 Spark。

在下一节中，我们将看到如何在 Windows 上设置 Spark，并设置 PySpark 作为接口。

# 在 Windows 上设置 Spark 和 PySpark

完成以下步骤，在 Windows 计算机上安装 PySpark：

1.  从[`github.com/bmatzelle/gow/releases/download/v0.8.0/Gow-0.8.0.exe`](https://github.com/bmatzelle/gow/releases/download/v0.8.0/Gow-0.8.0.exe)下载**Gnu on Windows**（**GOW**）。

1.  GOW 允许在 Windows 上使用 Linux 命令。我们可以使用以下命令来查看通过安装 GOW 允许的基本 Linux 命令：

```py
gow --list 
```

这会产生以下输出：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-bgdt-anlt-pyspark/img/fa145c7d-15ef-487b-8867-4a1b54fdf2bb.png)

1.  下载并安装 Anaconda。如果需要帮助，可以参考以下教程：[`medium.com/@GalarnykMichael/install-python-on-windows-anaconda-c63c7c3d1444`](https://medium.com/@GalarnykMichael/install-python-on-windows-anaconda-c63c7c3d1444)。

1.  关闭先前的命令行，打开一个新的命令行。

1.  转到 Apache Spark 网站（[`spark.apache.org/`](https://spark.apache.org/)）。

1.  要下载 Spark，请从下拉菜单中选择以下内容：

+   最近的 Spark 版本

+   适当的软件包类型

以下屏幕截图显示了 Apache Spark 的下载页面：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-bgdt-anlt-pyspark/img/6ed179f0-ad5c-4927-a36f-d43a63b2c7b8.png)

1.  然后，下载 Spark。下载完成后，将文件移动到您想要解压缩的文件夹中。

1.  您可以手动解压缩，也可以使用以下命令：

```py
gzip -d spark-2.1.0-bin-hadoop2.7.tgz tar xvf spark-2.1.0-bin-hadoop2.7.tar
```

1.  现在，使用以下命令将`winutils.exe`下载到您的`spark-2.1.0-bin-hadoop2.7\bin`文件夹中：

```py
curl -k -L -o winutils.exe https://github.com/steveloughran/winutils/blob/master/hadoop-2.6.0/bin/winutils.exe?raw=true
```

1.  确保您的计算机上已安装 Java。您可以使用以下命令查看 Java 版本：

```py
java --version
```

这会产生以下输出：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-bgdt-anlt-pyspark/img/f08c68fa-631b-4c66-984b-f63e77052d5d.png)

1.  使用以下命令检查 Python 版本：

```py
python --version 
```

这会产生以下输出：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-bgdt-anlt-pyspark/img/42925ce3-f91e-40dd-be15-3be663c8e818.png)

1.  让我们编辑我们的环境变量，这样我们可以在任何目录中打开 Spark，如下所示：

```py
setx SPARK_HOME C:\opt\spark\spark-2.1.0-bin-hadoop2.7
setx HADOOP_HOME C:\opt\spark\spark-2.1.0-bin-hadoop2.7
setx PYSPARK_DRIVER_PYTHON ipython
setx PYSPARK_DRIVER_PYTHON_OPTS notebook
```

将`C:\opt\spark\spark-2.1.0-bin-hadoop2.7\bin`添加到你的路径中。

1.  关闭终端，打开一个新的终端，并输入以下命令：

```py
--master local[2]
```

`PYSPARK_DRIVER_PYTHON`和`PYSPARK_DRIVER_PYTHON_OPTS`参数用于在 Jupyter Notebook 中启动 PySpark shell。`--master`参数用于设置主节点地址。

1.  接下来要做的是在`bin`文件夹中运行 PySpark 命令：

```py
.\bin\pyspark
```

这将产生以下输出：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-bgdt-anlt-pyspark/img/6e33e968-011e-4439-9616-2457bc36493d.png)

# Spark 和 PySpark 中的核心概念

现在让我们来看看 Spark 和 PySpark 中的以下核心概念：

+   SparkContext

+   SparkConf

+   Spark shell

# SparkContext

SparkContext 是 Spark 中的一个对象或概念。它是一个大数据分析引擎，允许你以编程方式利用 Spark 的强大功能。

当你有大量数据无法放入本地机器或笔记本电脑时，Spark 的强大之处就显现出来了，因此你需要两台或更多计算机来处理它。在处理数据的同时，你还需要保持处理速度。我们不仅希望数据在几台计算机上进行计算，还希望计算是并行的。最后，你希望这个计算看起来像是一个单一的计算。

让我们考虑一个例子，我们有一个包含 5000 万个名字的大型联系人数据库，我们可能想从每个联系人中提取第一个名字。显然，如果每个名字都嵌入在一个更大的联系人对象中，将 5000 万个名字放入本地内存中是困难的。这就是 Spark 发挥作用的地方。Spark 允许你给它一个大数据文件，并将帮助处理和上传这个数据文件，同时为你处理在这个数据上进行的所有操作。这种能力由 Spark 的集群管理器管理，如下图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-bgdt-anlt-pyspark/img/de3d8722-4e52-4873-aa4c-216c7dbc627c.png)

集群管理器管理多个工作节点；可能有 2 个、3 个，甚至 100 个。关键是 Spark 的技术有助于管理这个工作节点集群，你需要一种方法来控制集群的行为，并在工作节点之间传递数据。

**SparkContext** 让你可以像使用 Python 对象一样使用 Spark 集群管理器的功能。因此，有了**SparkContext**，你可以传递作业和资源，安排任务，并完成从**SparkContext**到**Spark 集群管理器**的下游任务，然后**Spark 集群管理器**完成计算后将结果带回来。

让我们看看这在实践中是什么样子，以及如何设置 SparkContext：

1.  首先，我们需要导入`SparkContext`。

1.  创建一个新对象，将其赋给变量`sc`，代表使用`SparkContext`构造函数的 SparkContext。

1.  在`SparkContext`构造函数中，传递一个`local`上下文。在这种情况下，我们正在研究`PySpark`的实际操作，如下所示：

```py
from pyspark import SparkContext
sc = SparkContext('local', 'hands on PySpark')
```

1.  一旦我们建立了这一点，我们只需要使用`sc`作为我们 Spark 操作的入口点，就像下面的代码片段中所演示的那样：

```py
visitors = [10, 3, 35, 25, 41, 9, 29] df_visitors = sc.parallelize(visitors) df_visitors_yearly = df_visitors.map(lambda x: x*365).collect() print(df_visitors_yearly)
```

让我们举个例子；如果我们要分析我们服装店的虚拟数据集的访客数量，我们可能有一个表示每天访客数量的`visitors`列表。然后，我们可以创建一个 DataFrame 的并行版本，调用`sc.parallelize(visitors)`，并输入`visitors`数据集。`df_visitors`然后为我们创建了一个访客的 DataFrame。然后，我们可以映射一个函数；例如，通过映射一个`lambda`函数，将每日数字（`x`）乘以`365`，即一年中的天数，将其推断为一年的数字。然后，我们调用`collect()`函数，以确保 Spark 执行这个`lambda`调用。最后，我们打印出`df_visitors_yearly`。现在，我们让 Spark 在幕后处理我们的虚拟数据的计算，而这只是一个 Python 操作。

# Spark shell

我们将返回到我们的 Spark 文件夹，即`spark-2.3.2-bin-hadoop2.7`，然后通过输入`.\bin\pyspark`来启动我们的 PySpark 二进制文件。

我们可以看到我们已经在以下截图中启动了一个带有 Spark 的 shell 会话：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-bgdt-anlt-pyspark/img/ba96adf0-562b-47ec-9924-986c14b08156.png)

现在，Spark 对我们来说是一个`spark`变量。让我们在 Spark 中尝试一件简单的事情。首先要做的是加载一个随机文件。在每个 Spark 安装中，都有一个`README.md`的 markdown 文件，所以让我们将其加载到内存中，如下所示：

```py
text_file = spark.read.text("README.md")
```

如果我们使用`spark.read.text`然后输入`README.md`，我们会得到一些警告，但目前我们不必太担心这些，因为我们将在稍后看到如何解决这些问题。这里的主要问题是我们可以使用 Python 语法来访问 Spark。

我们在这里所做的是将`README.md`作为`spark`读取的文本数据放入 Spark 中，然后我们可以使用`text_file.count()`来让 Spark 计算我们的文本文件中有多少个字符，如下所示：

```py
text_file.count()
```

从中，我们得到以下输出：

```py
103
```

我们还可以通过以下方式查看第一行是什么：

```py
text_file.first()
```

我们将得到以下输出：

```py
Row(value='# Apache Spark')
```

现在，我们可以通过以下方式计算包含单词`Spark`的行数：

```py
lines_with_spark = text_file.filter(text_file.value.contains("Spark"))
```

在这里，我们使用`filter()`函数过滤了行，并在`filter()`函数内部指定了`text_file_value.contains`包含单词`"Spark"`，然后将这些结果放入了`lines_with_spark`变量中。

我们可以修改上述命令，简单地添加`.count()`，如下所示：

```py
text_file.filter(text_file.value.contains("Spark")).count()
```

现在我们将得到以下输出：

```py
20
```

我们可以看到文本文件中有`20`行包含单词`Spark`。这只是一个简单的例子，展示了我们如何使用 Spark shell。

# SparkConf

SparkConf 允许我们配置 Spark 应用程序。它将各种 Spark 参数设置为键值对，通常会使用`SparkConf()`构造函数创建一个`SparkConf`对象，然后从`spark.*`底层 Java 系统中加载值。

有一些有用的函数；例如，我们可以使用`sets()`函数来设置配置属性。我们可以使用`setMaster()`函数来设置要连接的主 URL。我们可以使用`setAppName()`函数来设置应用程序名称，并使用`setSparkHome()`来设置 Spark 将安装在工作节点上的路径。

您可以在[`spark.apache.org/docs/0.9.0/api/pyspark/pysaprk.conf.SparkConf-class.html`](https://spark.apache.org/docs/0.9.0/api/pyspark/pysaprk.conf.SparkConf-class.html)了解更多关于 SparkConf 的信息。

# 摘要

在本章中，我们学习了 Spark 和 PySpark 中的核心概念。我们学习了在 Windows 上设置 Spark 和使用 PySpark。我们还介绍了 Spark 的三大支柱，即 SparkContext、Spark shell 和 SparkConf。

在下一章中，我们将学习如何使用 RDD 将大数据导入 Spark 环境。


# 第二章：使用 RDD 将大数据导入 Spark 环境

主要是，本章将简要介绍如何使用**弹性分布式数据集**（**RDDs**）将大数据导入 Spark 环境。我们将使用各种工具来与和修改这些数据，以便提取有用的见解。我们将首先将数据加载到 Spark RDD 中，然后使用 Spark RDD 进行并行化。

在本章中，我们将涵盖以下主题：

+   将数据加载到 Spark RDD 中

+   使用 Spark RDD 进行并行化

+   RDD 操作的基础知识

# 将数据加载到 Spark RDD 中

在本节中，我们将看看如何将数据加载到 Spark RDD 中，并将涵盖以下主题：

+   UCI 机器学习数据库

+   从存储库将数据导入 Python

+   将数据导入 Spark

让我们首先概述一下 UCI 机器学习数据库。

# UCI 机器学习库

我们可以通过导航到[`archive.ics.uci.edu/ml/`](https://archive.ics.uci.edu/ml/)来访问 UCI 机器学习库。那么，UCI 机器学习库是什么？UCI 代表加州大学尔湾分校机器学习库，它是一个非常有用的资源，可以获取用于机器学习的开源和免费数据集。尽管 PySpark 的主要问题或解决方案与机器学习无关，但我们可以利用这个机会获取帮助我们测试 PySpark 功能的大型数据集。

让我们来看一下 KDD Cup 1999 数据集，我们将下载，然后将整个数据集加载到 PySpark 中。

# 将数据从存储库加载到 Spark

我们可以按照以下步骤下载数据集并将其加载到 PySpark 中：

1.  点击数据文件夹。

1.  您将被重定向到一个包含各种文件的文件夹，如下所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-bgdt-anlt-pyspark/img/e7fb27a2-161d-4d0a-bddf-1955206aab1d.png)

您可以看到有 kddcup.data.gz，还有 kddcup.data_10_percent.gz 中的 10%数据。我们将使用食品数据集。要使用食品数据集，右键单击 kddcup.data.gz，选择复制链接地址，然后返回到 PySpark 控制台并导入数据。

让我们看看如何使用以下步骤：

1.  启动 PySpark 后，我们需要做的第一件事是导入`urllib`，这是一个允许我们与互联网上的资源进行交互的库，如下所示：

```py
import urllib.request
```

1.  接下来要做的是使用这个`request`库从互联网上拉取一些资源，如下面的代码所示：

```py
f = urllib.request.urlretrieve("https://archive.ics.uci.edu/ml/machine-learning-databases/kddcup99-mld/kddcup.data.gz"),"kddcup.data.gz"
```

这个命令将需要一些时间来处理。一旦文件被下载，我们可以看到 Python 已经返回，控制台是活动的。

1.  接下来，使用`SparkContext`加载这个。所以，在 Python 中，`SparkContext`被实例化或对象化为`sc`变量，如下所示：

```py
sc
```

此输出如下面的代码片段所示：

```py
SparkContext
Spark UI
Version
 v2.3.3
Master
 local[*]
AppName
 PySparkShell
```

# 将数据导入 Spark

1.  接下来，使用`sc`将 KDD cup 数据加载到 PySpark 中，如下面的命令所示：

```py
raw_data = sc.textFile("./kddcup.data.gz")
```

1.  在下面的命令中，我们可以看到原始数据现在在`raw_data`变量中：

```py
raw_data
```

此输出如下面的代码片段所示：

```py
./kddcup.data,gz MapPartitionsRDD[3] at textFile at NativeMethodAccessorImpl.java:0
```

如果我们输入`raw_data`变量，它会给我们关于`kddcup.data.gz`的详细信息，其中包含数据文件的原始数据，并告诉我们关于`MapPartitionsRDD`。

现在我们知道如何将数据加载到 Spark 中，让我们学习一下如何使用 Spark RDD 进行并行化。

# 使用 Spark RDD 进行并行化

现在我们知道如何在从互联网接收的文本文件中创建 RDD，我们可以看一种不同的创建这个 RDD 的方法。让我们讨论一下如何使用我们的 Spark RDD 进行并行化。

在这一部分，我们将涵盖以下主题：

+   什么是并行化？

+   我们如何将 Spark RDD 并行化？

让我们从并行化开始。

# 什么是并行化？

了解 Spark 或任何语言的最佳方法是查看文档。如果我们查看 Spark 的文档，它清楚地说明，对于我们上次使用的`textFile`函数，它从 HDFS 读取文本文件。

另一方面，如果我们看一下`parallelize`的定义，我们可以看到这是通过分发本地 Scala 集合来创建 RDD。

使用`parallelize`创建 RDD 和使用`textFile`创建 RDD 之间的主要区别在于数据的来源。

让我们看看这是如何实际工作的。让我们回到之前离开的 PySpark 安装屏幕。因此，我们导入了`urllib`，我们使用`urllib.request`从互联网检索一些数据，然后我们使用`SparkContext`和`textFile`将这些数据加载到 Spark 中。另一种方法是使用`parallelize`。

让我们看看我们可以如何做到这一点。让我们首先假设我们的数据已经在 Python 中，因此，为了演示目的，我们将创建一个包含一百个数字的 Python 列表如下：

```py
a = range(100)
a
```

这给我们以下输出：

```py
range(0, 100)
```

例如，如果我们看一下`a`，它只是一个包含 100 个数字的列表。如果我们将其转换为`list`，它将显示我们的 100 个数字的列表：

```py
list (a)
```

这给我们以下输出：

```py
[0,
 1,
 2,
 3,
 4,
 5,
 6,
 7,
 8,
 9,
 10,
 11,
 12,
 13,
 14,
 15,
 16,
 17,
 18,
 19,
 20,
 21,
 22,
 23,
 24,
 25,
 26,
 27,
...
```

以下命令向我们展示了如何将其转换为 RDD：

```py
list_rdd = sc.parallelize(a)
```

如果我们看一下`list_rdd`包含什么，我们可以看到它是`PythonRDD.scala:52`，因此，这告诉我们 Scala 支持的 PySpark 实例已经识别出这是一个由 Python 创建的 RDD，如下所示：

```py
list_rdd
```

这给我们以下输出：

```py
PythonRDD[3] at RDD at PythonRDD.scala:52
```

现在，让我们看看我们可以用这个列表做什么。我们可以做的第一件事是通过以下命令计算`list_rdd`中有多少元素：

```py
list_rdd.count()
```

这给我们以下输出：

```py
100
```

我们可以看到`list_rdd`计数为 100。如果我们再次运行它而不切入结果，我们实际上可以看到，由于 Scala 在遍历 RDD 时是实时运行的，它比只运行`a`的长度要慢，后者是瞬时的。

然而，RDD 需要一些时间，因为它需要时间来遍历列表的并行化版本。因此，在小规模的情况下，只有一百个数字，可能没有这种权衡非常有帮助，但是对于更大量的数据和数据元素的更大个体大小，这将更有意义。

我们还可以从列表中取任意数量的元素，如下所示：

```py
list_rdd.take(10)
```

这给我们以下输出：

```py
[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
```

当我们运行上述命令时，我们可以看到 PySpark 在返回列表的前十个元素之前进行了一些计算。请注意，所有这些现在都由 PySpark 支持，并且我们正在使用 Spark 的功能来操作这个包含 100 个项目的列表。

现在让我们在`list_rdd`中使用`reduce`函数，或者在 RDDs 中一般使用，来演示我们可以用 PySpark 的 RDDs 做什么。我们将两个参数函数应用为匿名的`lambda`函数到`reduce`调用如下：

```py
list_rdd.reduce(lambda a, b: a+b)
```

在这里，`lambda`接受两个参数`a`和`b`。它简单地将这两个数字相加，因此`a+b`，并返回输出。通过`RDD`的`reduce`调用，我们可以依次将 RDD 列表的前两个数字相加，返回结果，然后将第三个数字添加到结果中，依此类推。因此，最终，通过使用`reduce`，您可以将所有 100 个数字添加到相同的结果中。

现在，在通过分布式数据库进行一些工作之后，我们现在可以看到，从`0`到`99`的数字相加得到`4950`，并且所有这些都是使用 PySpark 的 RDD 方法完成的。您可能会从 MapReduce 这个术语中认出这个函数，确实，它就是这样。

我们刚刚学习了在 PySpark 中并行化是什么，以及我们如何可以并行化 Spark RDDs。这实际上相当于我们创建 RDDs 的另一种方式，对我们非常有用。现在，让我们来看一些 RDD 操作的基础知识。

# RDD 操作的基础知识

现在让我们来看一些 RDD 操作的基础知识。了解某个功能的最佳方法是查看文档，以便我们可以严格理解函数的执行方式。

这是非常重要的原因是文档是函数定义和设计用途的黄金来源。通过阅读文档，我们确保我们在理解上尽可能接近源头。相关文档的链接是[`spark.apache.org/docs/latest/rdd-programming-guide.html`](https://spark.apache.org/docs/latest/rdd-programming-guide.html)。

让我们从`map`函数开始。`map`函数通过将`f`函数应用于此 RDD 的每个元素来返回一个 RDD。换句话说，它的工作方式与我们在 Python 中看到的`map`函数相同。另一方面，`filter`函数返回一个仅包含满足谓词的元素的新 RDD，该谓词是一个布尔值，通常由输入`filter`函数的`f`函数返回。同样，这与 Python 中的`filter`函数非常相似。最后，`collect()`函数返回一个包含此 RDD 中所有元素的列表。这就是我认为阅读文档真正发光的地方，当我们看到这样的说明时。如果你只是在谷歌搜索这个，这种情况永远不会出现在 Stack Overflow 或博客文章中。

因此，我们说`collect()`只有在预期结果数组很小的情况下才应该使用，因为所有数据都加载在驱动程序的内存中。这意味着，如果我们回想一下第一章，*安装 PySpark 并设置开发环境*，Spark 非常出色，因为它可以在许多不同的独立机器上收集和并行化数据，并且可以从一个终端透明地操作。`collect()`的说明是，如果我们调用`collect()`，则生成的 RDD 将完全加载到驱动程序的内存中，在这种情况下，我们将失去在 Spark 实例集群中分发数据的好处。

现在我们知道了所有这些，让我们看看如何实际将这三个函数应用于我们的数据。因此，返回到 PySpark 终端；我们已经将原始数据作为文本文件加载，就像我们在之前的章节中看到的那样。

我们将编写一个`filter`函数来查找所有包含单词`normal`的行，指示 RDD 数据，如下面的屏幕截图所示：

```py
contains_normal = raw_data.filter(lambda line: "normal." in line)
```

让我们分析一下这意味着什么。首先，我们正在为 RDD 原始数据调用`filter`函数，并且我们正在向其提供一个匿名的`lambda`函数，该函数接受一个`line`参数并返回谓词，正如我们在文档中所读到的，关于单词`normal`是否存在于该行中。此刻，正如我们在之前的章节中讨论的那样，我们实际上还没有计算这个`filter`操作。我们需要做的是调用一个实际整合数据并迫使 Spark 计算某些内容的函数。在这种情况下，我们可以依赖`contains_normal`，就像下面的屏幕截图中所示的那样：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-bgdt-anlt-pyspark/img/67a5b615-fcae-4356-99da-0bf6b0e22232.png)

您可以看到，在原始数据中，包含单词`normal`的行数超过了 970,000 行。要使用`filter`函数，我们提供了一个`lambda`函数，并使用一个整合函数，比如`counts`，来强制 Spark 计算和计算底层 DataFrame 中的数据。

对于第二个例子，我们将使用 map。由于我们下载了 KDD 杯数据，我们知道它是一个逗号分隔的值文件，因此，我们很容易做的一件事是通过两个逗号拆分每一行，如下所示：

```py
split_file = raw_data.map(lambda line: line.split(","))
```

让我们分析一下发生了什么。我们在`raw_data`上调用`map`函数。我们向它提供了一个名为`line`的匿名`lambda`函数，在这个函数中，我们使用`,`来分割`line`函数。结果是一个分割文件。现在，这里真正发挥了 Spark 的力量。回想一下，在`contains_normal.`过滤器中，当我们调用一个强制 Spark 计算`count`的函数时，需要几分钟才能得出正确的结果。如果我们执行`map`函数，它会产生相同的效果，因为我们需要对数百万行数据进行映射。因此，快速预览我们的映射函数是否正确运行的一种方法是，我们可以将几行材料化而不是整个文件。

为了做到这一点，我们可以使用之前使用过的`take`函数，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-bgdt-anlt-pyspark/img/e99a6e8a-4409-4b4e-b1e1-858e278abc2d.png)

这可能需要几秒钟，因为我们只取了五行，这是我们的分割，实际上相当容易管理。如果我们查看这个样本输出，我们可以理解我们的`map`函数已经成功创建。我们可以做的最后一件事是在原始数据上调用`collect()`，如下所示：

```py
raw_data.collect()
```

这旨在将 Spark 的 RDD 数据结构中的所有原始数据移动到内存中。

# 总结

在本章中，我们学习了如何在 Spark RDD 上加载数据，还介绍了 Spark RDD 的并行化。在加载数据之前，我们简要概述了 UCI 机器学习存储库。我们概述了基本的 RDD 操作，并检查了官方文档中的函数。

在下一章中，我们将介绍大数据清洗和数据整理。


# 第三章：使用 Spark 笔记本进行大数据清洗和整理

在本章中，我们将学习使用 Spark 笔记本进行大数据清洗和整理。我们还将看看在笔记本应用程序上使用 Spark 如何有效地使用 RDD。我们将使用 Spark 笔记本快速迭代想法，并进行抽样/过滤 RDD 以挑选出相关数据点。我们还将学习如何拆分数据集并使用集合操作创建新的组合。

在本章中，我们将讨论以下主题：

+   使用 Spark 笔记本快速迭代想法

+   对 RDD 进行抽样/过滤以挑选出相关数据点

+   拆分数据集并创建一些新的组合

# 使用 Spark 笔记本快速迭代想法

在这一部分，我们将回答以下问题：

+   什么是 Spark 笔记本？

+   如何启动 Spark 笔记本？

+   如何使用 Spark 笔记本？

让我们从为 Spark 设置类似 Jupyter Notebook 的环境开始。Spark 笔记本只是一个使用 Scala 和 Spark 的交互式和反应式数据科学环境。

如果我们查看 GitHub 页面（[`github.com/spark-notebook/spark-notebook`](https://github.com/spark-notebook/spark-notebook)），我们会发现笔记本的功能实际上非常简单，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-bgdt-anlt-pyspark/img/edaecfa4-9892-4f8e-9831-a38e1520b220.png)

如果我们看一下 Spark 笔记本，我们会发现它们看起来非常像 Python 开发人员使用的 Jupyter 笔记本。您可以在文本框中输入一些代码，然后在文本框下方执行代码，这与笔记本格式类似。这使我们能够使用 Apache Spark 和大数据生态系统执行可重现的分析。

因此，我们可以直接使用 Spark 笔记本，我们只需要转到 Spark 笔记本网站，然后点击“快速启动”即可启动笔记本，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-bgdt-anlt-pyspark/img/10274ddd-d867-401e-b359-00846d61a5b2.png)

我们需要确保我们正在运行 Java 7。我们可以看到设置步骤也在文档中提到，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-bgdt-anlt-pyspark/img/87e2fc62-6f8d-45f8-a8bf-21c574afb867.png)

Spark 笔记本的主要网站是`spark-notebook.io`，在那里我们可以看到许多选项。以下截图显示了其中一些选项：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-bgdt-anlt-pyspark/img/8518e8f2-1513-4569-822d-39bc6d0f8814.png)

我们可以下载 TAR 文件并解压缩。您可以使用 Spark 笔记本，但是在本书中我们将使用 Jupyter Notebook。因此，回到 Jupyter 环境，我们可以查看 PySpark 附带的代码文件。在`第三章`笔记本中，我们已经包含了一个方便的方法来设置环境变量，以使 PySpark 与 Jupyter 一起工作，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-bgdt-anlt-pyspark/img/cb54d381-06e9-41f2-960c-41210cd0e36f.png)

首先，我们需要在我们的环境中创建两个新的环境变量。如果您使用 Linux，可以使用 Bash RC。如果您使用 Windows，您只需要更改和编辑系统环境变量。有多个在线教程可以帮助您完成此操作。我们要做的是编辑或包含`PYSPARK_DRIVER_PYTHON`变量，并将其指向您的 Jupyter Notebook 安装位置。如果您使用 Anaconda，可能会指向 Anaconda Jupyter Bash 文件。由于我们使用的是 WinPython，我已将其指向了我的 WinPython Jupyter Notebook Bash 文件。我们要导出的第二个环境变量只是`PYSPARK_DRIVER_PYTHON_OPTS`。

其中一个建议是，我们在选项中包括笔记本文件夹和笔记本应用程序，要求它不要在浏览器中打开，并告诉它要绑定到哪个端口。 在实践中，如果您使用的是 Windows 和 WinPython 环境，那么您实际上不需要在这里使用这行代码，您可以直接跳过它。 完成后，只需从命令行重新启动 PySpark。 发生的情况是，与我们以前看到的控制台不同，它直接启动到 Jupyter Notebook 实例，并且我们可以像在 Jupyter Notebook 中一样使用 Spark 和 SparkContext 变量。 因此，让我们测试一下，如下所示：

```py
sc
```

我们立即获得了我们的`SparkContext`，告诉我们 Spark 的版本是`2.3.3`，我们的`Master`是`local`，`AppName`是 Python SparkShell（`PySparkShell`），如下面的代码片段所示：

```py
SparkContext
Spark UI
Version
 v2.3.3
Master
 local[*]
AppName
 PySparkShell
```

因此，现在我们知道了如何在 Jupyter 中创建类似笔记本的环境。 在下一节中，我们将看一下对 RDD 进行抽样和过滤以挑选出相关数据点。

# 抽样/过滤 RDD 以挑选出相关数据点

在本节中，我们将查看对 RDD 进行抽样和过滤以挑选出相关数据点。 这是一个非常强大的概念，它使我们能够规避大数据的限制，并在特定样本上执行我们的计算。

现在让我们检查抽样不仅加速了我们的计算，而且还给了我们对我们试图计算的统计量的良好近似。 为此，我们首先导入`time`库，如下所示：

```py
from time import time
```

我们接下来要做的是查看 KDD 数据库中包含单词`normal`的行或数据点：

```py
raw_data = sc.textFile("./kdd.data.gz")
```

我们需要创建`raw_data`的样本。 我们将样本存储到`sample`变量中，我们正在从`raw_data`中进行无替换的抽样。 我们正在抽样数据的 10％，并且我们提供`42`作为我们的随机种子：

```py
sampled = raw_data.sample(False, 0.1, 42)
```

接下来要做的是链接一些`map`和`filter`函数，就像我们通常处理未抽样数据集一样：

```py
contains_normal_sample = sampled.map(lambda x: x.split(",")).filter(lambda x: "normal" in x)
```

接下来，我们需要计算在样本中计算行数需要多长时间：

```py
t0 = time()
num_sampled = contains_normal_sample.count()
duration = time() - t0
```

我们在这里发布计数声明。 正如您从上一节中所知，这将触发 PySpark 中`contains_normal_sample`中定义的所有计算，并且我们记录了样本计数发生之前的时间。 我们还记录了样本计数发生后的时间，这样我们就可以看到在查看样本时需要多长时间。 一旦完成了这一点，让我们来看看以下代码片段中`duration`持续了多长时间：

```py
duration
```

输出将如下所示：

```py
23.724565505981445
```

我们花了 23 秒来运行这个操作，占数据的 10％。 现在，让我们看看如果我们在所有数据上运行相同的转换会发生什么：

```py
contains_normal = raw_data.map(lambda x: x.split(",")).filter(lambda x: "normal" in x)
t0 = time()
num_sampled = contains_normal.count()
duration = time() - t0
```

让我们再次看一下`duration`：

```py
duration 
```

这将提供以下输出：

```py
36.51565098762512
```

有一个小差异，因为我们正在比较`36.5`秒和`23.7`秒。 但是，随着数据集变得更加多样化，以及您处理的数据量变得更加复杂，这种差异会变得更大。 这其中的好处是，如果您通常处理大数据，使用数据的小样本验证您的答案是否合理可以帮助您更早地捕捉错误。

最后要看的是我们如何使用`takeSample`。 我们只需要使用以下代码：

```py
data_in_memory = raw_data.takeSample(False, 10, 42)
```

正如我们之前学到的，当我们呈现新函数时，我们调用`takeSample`，它将给我们`10`个具有随机种子`42`的项目，现在我们将其放入内存。 现在这些数据在内存中，我们可以使用本机 Python 方法调用相同的`map`和`filter`函数，如下所示：

```py
contains_normal_py = [line.split(",") for line in data_in_memory if "normal" in line]
len(contains_normal_py)
```

输出将如下所示：

```py
1
```

我们现在通过将`data_in_memory`带入来计算我们的`contains_normal`函数。 这很好地说明了 PySpark 的强大之处。

我们最初抽取了 10,000 个数据点的样本，这导致了机器崩溃。 因此，在这里，我们将取这十个数据点，看看它是否包含单词`normal`。

我们可以看到在前一个代码块中计算已经完成，它比在 PySpark 中进行计算花费了更长的时间并且使用了更多的内存。这就是为什么我们使用 Spark，因为 Spark 允许我们并行处理任何大型数据集，并且以并行方式操作它，这意味着我们可以用更少的内存和更少的时间做更多的事情。在下一节中，我们将讨论拆分数据集并使用集合操作创建新的组合。

# 拆分数据集并创建一些新的组合

在本节中，我们将看看如何拆分数据集并使用集合操作创建新的组合。我们将学习特别是减法和笛卡尔积。

让我们回到我们一直在查看包含单词`normal`的数据集中的行的 Jupyter 笔记本的`第三章`。让我们尝试获取不包含单词`normal`的所有行。一种方法是使用`filter`函数查看不包含`normal`的行。但是，在 PySpark 中我们可以使用一些不同的东西：一个名为`subtract`的函数来取整个数据集并减去包含单词`normal`的数据。让我们看看以下片段：

```py
normal_sample = sampled.filter(lambda line: "normal." in line)
```

然后我们可以通过从整个样本中减去`normal`样本来获得不包含单词`normal`的交互或数据点如下：

```py
non_normal_sample = sampled.subtract(normal_sample)
```

我们取`normal`样本，然后从整个样本中减去它，这是整个数据集的 10%。让我们按如下方式发出一些计数：

```py
sampled.count()
```

这将为我们提供以下输出：

```py
490705
```

正如你所看到的，数据集的 10%给我们`490705`个数据点，其中有一些包含单词`normal`的数据点。要找出它的计数，写下以下代码：

```py
normal_sample.count()
```

这将为我们提供以下输出：

```py
97404
```

所以，这里有`97404`个数据点。如果我们计算正常样本，因为我们只是从另一个样本中减去一个样本，计数应该大约略低于 400,000 个数据点，因为我们有 490,000 个数据点减去 97,000 个数据点，这应该导致大约 390,000。让我们看看使用以下代码片段会发生什么：

```py
non_normal_sample.count()
```

这将为我们提供以下输出：

```py
393301
```

正如预期的那样，它返回了`393301`的值，这验证了我们的假设，即减去包含`normal`的数据点会给我们所有非正常的数据点。

现在让我们讨论另一个名为`cartesian`的函数。这允许我们给出两个不同特征的不同值之间的所有组合。让我们看看以下代码片段中这是如何工作的：

```py
feature_1 = sampled.map(lambda line: line.split(",")).map(lambda features: features[1]).distinct()
```

在这里，我们使用`,`来拆分`line`函数。因此，我们将拆分逗号分隔的值 - 对于拆分后得到的所有特征，我们取第一个特征，并找到该列的所有不同值。我们可以重复这个过程来获取第二个特征，如下所示：

```py
feature_2 = sampled.map(lambda line: line.split(",")).map(lambda features: features[2]).distinct()
```

因此，我们现在有两个特征。我们可以查看`feature_1`和`feature_2`中的实际项目，如下所示，通过发出我们之前看到的`collect()`调用：

```py
f1 = feature_1.collect()
f2 = feature_2.collect()
```

让我们分别看一下如下：

```py
f1
```

这将提供以下结果：

```py
['tcp', 'udp', 'icmp']
```

所以，`f1`有三个值；让我们检查`f2`如下：

```py
f2
```

这将为我们提供以下输出：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-bgdt-anlt-pyspark/img/d4407ef2-4c27-4d7a-a633-41a19dd42187.png)

`f2`有更多的值，我们可以使用`cartesian`函数收集`f1`和`f2`之间的所有组合如下：

```py
len(feature_1.cartesian(feature_2).collect())
```

这将为我们提供以下输出：

```py
198
```

这是我们如何使用`cartesian`函数找到两个特征之间的笛卡尔积。在本章中，我们看了 Spark 笔记本；抽样、过滤和拆分数据集；以及使用集合操作创建新的组合。

# 摘要

在本章中，我们看了 Spark 笔记本进行快速迭代。然后我们使用抽样或过滤来挑选出相关的数据点。我们还学会了如何拆分数据集并使用集合操作创建新的组合。

在下一章中，我们将介绍将数据聚合和汇总为有用的报告。


# 第四章：将数据聚合和汇总为有用的报告

在本章中，我们将学习如何将数据聚合和汇总为有用的报告。我们将学习如何使用 `map` 和 `reduce` 函数计算平均值，执行更快的平均计算，并使用键值对数据点的数据透视表。

本章中，我们将涵盖以下主题：

+   使用 `map` 和 `reduce` 计算平均值

+   使用聚合进行更快的平均计算

+   使用键值对数据点进行数据透视表

# 使用 map 和 reduce 计算平均值

在本节中，我们将回答以下三个主要问题：

+   我们如何计算平均值？

+   什么是 map？

+   什么是 reduce？

您可以在[`spark.apache.org/docs/latest/api/python/pyspark.html?highlight=map#pyspark.RDD.map`](https://spark.apache.org/docs/latest/api/python/pyspark.html?highlight=map#pyspark.RDD.map)上查看文档。

`map` 函数接受两个参数，其中一个是可选的。`map` 的第一个参数是 `f`，它是一个应用于整个 RDD 的函数。第二个参数或参数是 `preservesPartitioning` 参数，默认值为 `False`。

如果我们查看文档，它说 `map` 通过将函数应用于此 RDD 的每个元素来简单地返回一个新的 RDD，显然，此函数指的是我们输入到 `map` 函数本身的 `f`。文档中有一个非常简单的例子，如果我们并行化一个包含三个字符 `b`、`a` 和 `c` 的 `rdd` 方法，并且我们映射一个创建每个元素的元组的函数，那么我们将创建一个包含三个元组的列表，其中原始字符放在元组的第一个元素中，整数 `1` 放在第二个元素中，如下所示：

```py
rdd =  sc.paralleize(["b", "a", "c"])
sorted(rdd.map(lambda x: (x, 1)).collect())
```

这将给我们以下输出：

```py
[('a', 1), ('b', 1), ('c', 1)]
```

`reduce` 函数只接受一个参数，即 `f`。`f` 是一个将列表减少为一个数字的函数。从技术角度来看，指定的可交换和可结合的二进制运算符减少了此 RDD 的元素。

让我们使用我们一直在使用的 KDD 数据来举个例子。我们启动我们的 Jupyter Notebook 实例，它链接到一个 Spark 实例，就像我们以前做过的那样。然后我们通过从本地磁盘加载 `kddcup.data.gz` 文本文件来创建一个 `raw_data` 变量，如下所示：

```py
raw_data = sc.textFile("./kddcup.data.gz")
```

接下来要做的是将此文件拆分为 `csv`，然后我们将过滤包含单词 `normal` 的特征 41 的行：

```py
csv = raw_data.map(lambda x: x.split(","))
normal_data = csv.filter(lambda x: x[41]=="normal.")
```

然后我们使用 `map` 函数将这些数据转换为整数，最后，我们可以使用 `reduce` 函数来计算 `total_duration`，然后我们可以打印 `total_duration` 如下：

```py
duration = normal_data.map(lambda x: int(x[0]))
total_duration = duration.reduce(lambda x, y: x+y)
total_duration
```

然后我们将得到以下输出：

```py
211895753
```

接下来要做的是将 `total_duration` 除以数据的计数，如下所示：

```py
total_duration/(normal_data.count())
```

这将给我们以下输出：

```py
217.82472416710442
```

稍微计算后，我们将使用 `map` 和 `reduce` 创建两个计数。我们刚刚学会了如何使用 PySpark 计算平均值，以及 PySpark 中的 `map` 和 `reduce` 函数是什么。

# 使用聚合进行更快的平均计算

在上一节中，我们看到了如何使用 `map` 和 `reduce` 计算平均值。现在让我们看看如何使用 `aggregate` 函数进行更快的平均计算。您可以参考前一节中提到的文档。

`aggregate` 是一个带有三个参数的函数，其中没有一个是可选的。

第一个是 `zeroValue` 参数，我们在其中放入聚合结果的基本情况。

第二个参数是顺序运算符 (`seqOp`)，它允许您在 `zeroValue` 之上堆叠和聚合值。您可以从 `zeroValue` 开始，将您的 RDD 中的值传递到 `seqOp` 函数中，并将其堆叠或聚合到 `zeroValue` 之上。

最后一个参数是`combOp`，表示组合操作，我们只需将通过`seqOp`参数聚合的`zeroValue`参数组合成一个值，以便我们可以使用它来完成聚合。

因此，我们正在聚合每个分区的元素，然后使用组合函数和中性零值对所有分区的结果进行聚合。在这里，我们有两件事需要注意：

1.  `op`函数允许修改`t1`，但不应修改`t2`

1.  第一个函数`seqOp`可以返回不同的结果类型`U`

在这种情况下，我们都需要一个操作来将`T`合并到`U`，以及一个操作来合并这两个`U`。

让我们去我们的 Jupyter Notebook 检查这是如何完成的。`aggregate`允许我们同时计算总持续时间和计数。我们调用`duration_count`函数。然后我们取`normal_data`并对其进行聚合。请记住，聚合有三个参数。第一个是初始值；也就是零值，`(0,0)`。第二个是一个顺序操作，如下所示：

```py
duration_count = duration.aggregate(
 (0,0),
 (lambda db, new_value: (db[0] + new_value, db[1] + 1))
)
```

我们需要指定一个具有两个参数的`lambda`函数。第一个参数是当前的累加器，或者聚合器，或者也可以称为数据库（`db`）。然后，在我们的`lambda`函数中，我们有第二个参数`new_value`，或者我们在 RDD 中处理的当前值。我们只是想对数据库做正确的事情，也就是说，我们知道我们的数据库看起来像一个元组，第一个元素是持续时间的总和，第二个元素是计数。在这里，我们知道我们的数据库看起来像一个元组，持续时间的总和是第一个元素，计数是第二个元素。每当我们查看一个新值时，我们需要将新值添加到当前的运行总数中，并将`1`添加到当前的运行计数中。

运行总数是第一个元素，`db[0]`。然后我们只需要将`1`添加到第二个元素`db[1]`，即计数。这是顺序操作。

每当我们得到一个`new_value`，如前面的代码块所示，我们只需将其添加到运行总数中。而且，因为我们已经将`new_value`添加到运行总数中，我们需要将计数增加`1`。其次，我们需要放入组合器操作。现在，我们只需要将两个单独的数据库`db1`和`db2`的相应元素组合如下：

```py
duration_count = duration.aggregate(
 (0,0),
 (lambda db, new_value: (db[0] + new_value, db[1] + 1)),
 (lambda db1, db2: (db1[0] + db2[0], db1[1] + db2[1]))
)
```

由于持续时间计数是一个元组，它在第一个元素上收集了我们的总持续时间，在第二个元素上记录了我们查看的持续时间数量，计算平均值非常简单。我们需要将第一个元素除以第二个元素，如下所示：

```py
duration_count[0]/duration_count[1]
```

这将给我们以下输出：

```py
217.82472416710442
```

您可以看到它返回了与我们在上一节中看到的相同的结果，这很棒。在下一节中，我们将看一下带有键值对数据点的数据透视表。

# 带有键值对数据点的数据透视表

数据透视表非常简单且易于使用。我们将使用大型数据集，例如 KDD 杯数据集，并根据某些键对某些值进行分组。

例如，我们有一个包含人和他们最喜欢的水果的数据集。我们想知道有多少人把苹果作为他们最喜欢的水果，因此我们将根据水果将人数进行分组，这是值，而不是键。这就是数据透视表的简单概念。

我们可以使用`map`函数将 KDD 数据集移动到键值对范例中。我们使用`lambda`函数将数据集的特征`41`映射到`kv`键值，并将值附加如下：

```py
kv = csv.map(lambda x: (x[41], x))
kv.take(1)
```

我们使用特征`41`作为键，值是数据点，即`x`。我们可以使用`take`函数来获取这些转换行中的一个，以查看其外观。

现在让我们尝试类似于前面的例子。为了找出特征`41`中每种数值的总持续时间，我们可以再次使用`map`函数，简单地将`41`特征作为我们的键。我们可以将数据点中第一个数字的浮点数作为我们的值。我们将使用`reduceByKey`函数来减少每个键的持续时间。

因此，`reduceByKey`不仅仅是减少所有数据点，而是根据它们所属的键来减少持续时间数字。您可以在[`spark.apache.org/docs/latest/api/python/pyspark.html?highlight=map#pyspark.RDD.reduceByKey`](https://spark.apache.org/docs/latest/api/python/pyspark.html?highlight=map#pyspark.RDD.reduceByKey)上查看文档。`reduceByKey`使用关联和交换的`reduce`函数合并每个键的值。它在将结果发送到减速器之前在每个映射器上执行本地合并，这类似于 MapReduce 中的组合器。

`reduceByKey`函数只需一个参数。我们将使用`lambda`函数。我们取两个不同的持续时间并将它们相加，PySpark 足够聪明，可以根据键应用这个减少函数，如下所示：

```py
kv_duration = csv.map(lambda x: (x[41], float(x[0]))).reduceByKey(lambda x, y: x+y)
kv_duration.collect()
```

结果输出如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-bgdt-anlt-pyspark/img/dc4b7020-d1a2-48ee-8e9f-6f152fefc69f.png)

如果我们收集键值持续时间数据，我们可以看到持续时间是由出现在特征`41`中的值收集的。如果我们在 Excel 中使用数据透视表，有一个方便的函数是`countByKey`函数，它执行的是完全相同的操作，如下所示：

```py
kv.countByKey()
```

这将给我们以下输出：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-bgdt-anlt-pyspark/img/0e2d8e34-d50e-447b-818e-d2139cdaa519.png)

您可以看到调用`kv.countByKey()`函数与调用`reduceByKey`函数相同，先前是从键到持续时间的映射。 

# 摘要

在本章中，我们学习了如何使用`map`和`reduce`计算平均值。我们还学习了使用`aggregate`进行更快的平均计算。最后，我们了解到数据透视表允许我们根据特征的不同值对数据进行聚合，并且在 PySpark 中，我们可以利用`reducedByKey`或`countByKey`等方便的函数。

在下一章中，我们将学习关于 MLlib 的内容，其中涉及机器学习，这是一个非常热门的话题。


# 第五章：使用 MLlib 进行强大的探索性数据分析

在本章中，我们将探索 Spark 执行回归任务的能力，使用线性回归和支持向量机等模型。我们将学习如何使用 MLlib 计算汇总统计，并使用 Pearson 和 Spearman 相关性发现数据集中的相关性。我们还将在大型数据集上测试我们的假设。

我们将涵盖以下主题：

+   使用 MLlib 计算汇总统计

+   使用 Pearson 和 Spearman 方法发现相关性

+   在大型数据集上测试我们的假设

# 使用 MLlib 计算汇总统计

在本节中，我们将回答以下问题：

+   什么是汇总统计？

+   我们如何使用 MLlib 创建汇总统计？

MLlib 是随 Spark 一起提供的机器学习库。最近有一个新的发展，允许我们使用 Spark 的数据处理能力传输到 Spark 本身的机器学习能力。这意味着我们不仅可以使用 Spark 来摄取、收集和转换数据，还可以分析和使用它来构建 PySpark 平台上的机器学习模型，这使我们能够拥有更无缝的可部署解决方案。

汇总统计是一个非常简单的概念。我们熟悉某个变量的平均值、标准差或方差。这些是数据集的汇总统计。之所以称其为汇总统计，是因为它通过某个统计量给出了某个东西的摘要。例如，当我们谈论数据集的平均值时，我们正在总结数据集的一个特征，而这个特征就是平均值。

让我们看看如何在 Spark 中计算汇总统计。关键因素在于`colStats`函数。`colStats`函数计算`rdd`输入的逐列汇总统计。`colStats`函数接受一个参数，即`rdd`，并允许我们使用 Spark 计算不同的汇总统计。

让我们看一下 Jupyter Notebook 中的代码（可在[`github.com/PacktPublishing/Hands-On-Big-Data-Analytics-with-PySpark/tree/master/Chapter05`](https://github.com/PacktPublishing/Hands-On-Big-Data-Analytics-with-PySpark/tree/master/Chapter05)找到），在`Chapter5.ipynb`中的本章。我们将首先从`kddcup.data.gz`文本文件中收集数据，并将其传输到`raw_data`变量中：

```py
raw_data = sc.textFile("./kddcup.data.gz")
```

`kddcup.data`文件是一个逗号分隔值（CSV）文件。我们必须通过`,`字符拆分这些数据，并将其放入`csv`变量中，如下所示：

```py
csv = raw_data.map(lambda x: x.split(","))
```

让我们取数据文件的第一个特征`x[0]`；这个特征代表`持续时间`，也就是数据的方面。我们将把它转换为整数，并将其包装成列表，如下所示：

```py
duration = csv.map(lambda x: [int(x[0])])
```

这有助于我们对多个变量进行汇总统计，而不仅仅是其中一个。要激活`colStats`函数，我们需要导入`Statistics`包，如下面的代码片段所示：

```py
from pyspark.mllib.stat import Statistics
```

这个`Statistics`包是`pyspark.mllib.stat`的一个子包。现在，我们需要在`Statistics`包中调用`colStats`函数，并向其提供一些数据。这里，我们谈论的是数据集中的`持续时间`数据，并将汇总统计信息输入到`summary`变量中：

```py
summary = Statistics.colStats(duration)
```

要访问不同的汇总统计，如平均值、标准差等，我们可以调用`summary`对象的函数，并访问不同的汇总统计。例如，我们可以访问`mean`，由于我们的`持续时间`数据集中只有一个特征，我们可以通过`00`索引对其进行索引，然后得到数据集的平均值，如下所示：

```py
summary.mean()[0]
```

这将给我们以下输出：

```py
47.97930249928637
```

同样，如果我们从 Python 标准库中导入`sqrt`函数，我们可以创建数据集中持续时间的标准差，如下面的代码片段所示：

```py
from math import sqrt
sqrt(summary.variance()[0])
```

这将给我们以下输出：

```py
707.746472305374
```

如果我们不使用`[0]`对摘要统计信息进行索引，我们可以看到`summary.max()`和`summary.min()`会返回一个数组，其中第一个元素是我们所需的摘要统计信息，如下面的代码片段所示：

```py
summary.max()
array ([58329.]) #output
summary.min()
array([0.])  #output
```

# 使用 Pearson 和 Spearman 相关性来发现相关性

在这一部分，我们将看到在数据集中计算相关性的两种不同方法，这两种方法分别称为 Pearson 和 Spearman 相关性。

# Pearson 相关性

Pearson 相关系数向我们展示了两个不同变量同时变化的程度，然后根据它们的变化程度进行调整。如果你有一个数据集，这可能是计算相关性最流行的方法之一。

# Spearman 相关性

Spearman 秩相关不是内置在 PySpark 中的默认相关计算，但它非常有用。Spearman 相关系数是排名变量之间的 Pearson 相关系数。使用不同的相关性观察方法可以让我们更全面地理解相关性的工作原理。让我们看看在 PySpark 中如何计算这个。

# 计算 Pearson 和 Spearman 相关性

为了理解这一点，让我们假设我们正在从数据集中取出前三个数值变量。为此，我们要访问之前定义的`csv`变量，我们只需使用逗号（`,`）分割`raw_data`。我们只考虑前三列是数值的特征。我们不会取包含文字的任何内容；我们只对纯粹基于数字的特征感兴趣。在我们的例子中，在`kddcup.data`中，第一个特征的索引是`0`；特征 5 和特征 6 的索引分别是`4`和`5`，这些是我们拥有的数值变量。我们使用`lambda`函数将这三个变量放入一个列表中，并将其放入`metrics`变量中：

```py
metrics = csv.map(lambda x: [x[0], x[4], x[5]])
Statistics.corr(metrics, method="spearman")
```

这将给我们以下输出：

```py
array([[1\.       ,  0.01419628,  0.29918926],
 [0.01419628,  1\.        , -0.16793059],
 [0.29918926, -0.16793059,  1\.        ]])
```

在*使用 MLlib 计算摘要统计信息*部分，我们只是将第一个特征放入一个列表中，并创建了一个长度为 1 的列表。在这里，我们将三个变量的三个量放入同一个列表中。现在，每个列表的长度都是三。

为了计算相关性，我们在`metrics`变量上调用`corr`方法，并指定`method`为`"spearman"`。PySpark 会给我们一个非常简单的矩阵，告诉我们变量之间的相关性。在我们的例子中，`metrics`变量中的第三个变量比第二个变量更相关。

如果我们再次在`metrics`上运行`corr`，但指定方法为`pearson`，那么它会给我们 Pearson 相关性。因此，让我们看看为什么我们需要有资格称为数据科学家或机器学习研究人员来调用这两个简单的函数，并简单地改变第二个参数的值。许多机器学习和数据科学都围绕着我们对统计学的理解，对数据行为的理解，对机器学习模型基础的理解以及它们的预测能力是如何产生的。

因此，作为一个机器学习从业者或数据科学家，我们只是把 PySpark 当作一个大型计算器来使用。当我们使用计算器时，我们从不抱怨计算器使用简单——事实上，它帮助我们以更直接的方式完成目标。PySpark 也是一样的情况；一旦我们从数据工程转向 MLlib，我们会注意到代码变得逐渐更容易。它试图隐藏数学的复杂性，但我们需要理解不同相关性之间的差异，也需要知道如何以及何时使用它们。

# 在大型数据集上测试我们的假设

在本节中，我们将研究假设检验，并学习如何使用 PySpark 测试假设。让我们看看 PySpark 中实现的一种特定类型的假设检验。这种假设检验称为 Pearson 卡方检验。卡方检验评估了两个数据集之间的差异是由偶然因素引起的可能性有多大。

例如，如果我们有一个没有任何人流量的零售店，突然之间有了人流量，那么这是随机发生的可能性有多大，或者现在我们得到的访客水平与以前相比是否有任何统计学上显著的差异？之所以称之为卡方检验，是因为测试本身参考了卡方分布。您可以参考在线文档了解更多关于卡方分布的信息。

Pearson 的卡方检验有三种变体。我们将检查观察到的数据集是否与理论数据集分布不同。

让我们看看如何实现这一点。让我们从`pyspark.mllib.linalg`中导入`Vectors`包开始。使用这个向量，我们将创建一个存储中每天访客频率的密集向量。

假设访问频率从每小时的 0.13 到 0.61，0.8，0.5，最后在星期五结束时为 0.3。因此，我们将这些访客频率放入`visitors_freq`变量中。由于我们使用 PySpark，我们可以很容易地从`Statistics`包中运行卡方检验，我们已经导入如下：

```py
from pyspark.mllib.linalg import Vectors
visitors_freq = Vectors.dense(0.13, 0.61, 0.8, 0.5, 0.3)
print(Statistics.chiSqTest(visitors_freq))
```

通过运行卡方检验，`visitors_freq`变量为我们提供了大量有用的信息，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-bgdt-anlt-pyspark/img/ec0a248d-d599-476c-bbd7-665a504a76bc.png)

前面的输出显示了卡方检验的摘要。我们使用了`pearson`方法，在我们的 Pearson 卡方检验中有 4 个自由度，统计数据为 0.585，这意味着`pValue`为 0.964。这导致没有反对零假设的推定。这样，观察到的数据遵循与预期相同的分布，这意味着我们的访客实际上并没有不同。这使我们对假设检验有了很好的理解。

# 摘要

在本章中，我们学习了摘要统计信息并使用 MLlib 计算摘要统计信息。我们还了解了 Pearson 和 Spearman 相关性，以及如何使用 PySpark 在数据集中发现这些相关性。最后，我们学习了一种特定的假设检验方法，称为 Pearson 卡方检验。然后，我们使用 PySpark 的假设检验函数在大型数据集上测试了我们的假设。

在下一章中，我们将学习如何在 Spark SQL 中处理大数据的结构。


# 第六章：使用 SparkSQL 为您的大数据添加结构

在本章中，我们将学习如何使用 Spark SQL 模式操作数据框，并使用 Spark DSL 构建结构化数据操作的查询。到目前为止，我们已经学会了将大数据导入 Spark 环境使用 RDD，并对这些大数据进行多个操作。现在让我们看看如何操作我们的数据框并构建结构化数据操作的查询。

具体来说，我们将涵盖以下主题：

+   使用 Spark SQL 模式操作数据框

+   使用 Spark DSL 构建查询

# 使用 Spark SQL 模式操作数据框

在本节中，我们将学习更多关于数据框，并学习如何使用 Spark SQL。

Spark SQL 接口非常简单。因此，去除标签意味着我们处于无监督学习领域。此外，Spark 对聚类和降维算法有很好的支持。通过使用 Spark SQL 为大数据赋予结构，我们可以有效地解决学习问题。

让我们看一下我们将在 Jupyter Notebook 中使用的代码。为了保持一致，我们将使用相同的 KDD 杯数据：

1.  我们首先将`textFile`输入到`raw_data`变量中，如下所示：

```py
raw_data = sc.textFile("./kddcup.data.gz")
```

1.  新的是我们从`pyspark.sql`中导入了两个新包：

+   `Row`

+   `SQLContext`

1.  以下代码向我们展示了如何导入这些包：

```py
from pyspark.sql import Row, SQLContext
sql_context = SQLContext(sc)
csv = raw_data.map(lambda l: l.split(","))
```

使用`SQLContext`，我们创建一个新的`sql_context`变量，其中包含由 PySpark 创建的`SQLContext`变量的对象。由于我们使用`SparkContext`来启动这个`SQLContext`变量，我们需要将`sc`作为`SQLContext`创建者的第一个参数。之后，我们需要取出我们的`raw_data`变量，并使用`l.split`lambda 函数将其映射为一个包含我们的逗号分隔值（CSV）的对象。

1.  我们将利用我们的新重要`Row`对象来创建一个新对象，其中定义了标签。这是为了通过我们正在查看的特征对我们的数据集进行标记，如下所示：

```py
rows = csv.map(lambda p: Row(duration=int(p[0]), protocol=p[1], service=p[2]))
```

在上面的代码中，我们取出了我们的逗号分隔值（csv），并创建了一个`Row`对象，其中包含第一个特征称为`duration`，第二个特征称为`protocol`，第三个特征称为`service`。这直接对应于实际数据集中的标签。

1.  现在，我们可以通过在`sql_context`变量中调用`createDataFrame`函数来创建一个新的数据框。要创建这个数据框，我们需要提供我们的行数据对象，结果对象将是`df`中的数据框。之后，我们需要注册一个临时表。在这里，我们只是称之为`rdd`。通过这样做，我们现在可以使用普通的 SQL 语法来查询由我们的行构造的临时表中的内容：

```py
df = sql_context.createDataFrame(rows)
df.registerTempTable("rdd")
```

1.  在我们的示例中，我们需要从`rdd`中选择`duration`，这是一个临时表。我们在这里选择的协议等于`'tcp'`，而我们在一行中的第一个特征是大于`2000`的`duration`，如下面的代码片段所示：

```py
sql_context.sql("""SELECT duration FROM rdd WHERE protocol = 'tcp' AND duration > 2000""")
```

1.  现在，当我们调用`show`函数时，它会给我们每个符合这些条件的数据点：

```py
sql_context.sql("""SELECT duration FROM rdd WHERE protocol = 'tcp' AND duration > 2000""").show()
```

1.  然后我们将得到以下输出：

```py
+--------+
|duration|
+--------+
|   12454|
|   10774|
|   13368|
|   10350|
|   10409|
|   14918|
|   10039|
|   15127|
|   25602|
|   13120|
|    2399|
|    6155|
|   11155|
|   12169|
|   15239|
|   10901|
|   15182|
|    9494|
|    7895|
|   11084|
+--------+
only showing top 20 rows
```

使用前面的示例，我们可以推断出我们可以使用 PySpark 包中的`SQLContext`变量将数据打包成 SQL 友好格式。

因此，PySpark 不仅支持使用 SQL 语法查询数据，还可以使用 Spark 领域特定语言（DSL）构建结构化数据操作的查询。

# 使用 Spark DSL 构建查询

在本节中，我们将使用 Spark DSL 构建结构化数据操作的查询：

1.  在以下命令中，我们使用了与之前相同的查询；这次使用了 Spark DSL 来说明和比较使用 Spark DSL 与 SQL 的不同之处，但实现了与我们在前一节中展示的 SQL 相同的目标：

```py
df.select("duration").filter(df.duration>2000).filter(df.protocol=="tcp").show()
```

在这个命令中，我们首先取出了在上一节中创建的`df`对象。然后我们通过调用`select`函数并传入`duration`参数来选择持续时间。

1.  接下来，在前面的代码片段中，我们两次调用了`filter`函数，首先使用`df.duration`，第二次使用`df.protocol`。在第一种情况下，我们试图查看持续时间是否大于`2000`，在第二种情况下，我们试图查看协议是否等于`"tcp"`。我们还需要在命令的最后附加`show`函数，以获得与以下代码块中显示的相同结果。

```py
+--------+
|duration|
+--------+
|   12454|
|   10774|
|   13368|
|   10350|
|   10409|
|   14918|
|   10039|
|   15127|
|   25602|
|   13120|
|    2399|
|    6155|
|   11155|
|   12169|
|   15239|
|   10901|
|   15182|
|    9494|
|    7895|
|   11084|
+--------+
only showing top 20 rows
```

在这里，我们再次有了符合代码描述的前 20 行数据点的结果。

# 总结

在本章中，我们涵盖了 Spark DSL，并学习了如何构建查询。我们还学习了如何使用 Spark SQL 模式操纵 DataFrames，然后我们使用 Spark DSL 构建了结构化数据操作的查询。现在我们对 Spark 有了很好的了解，让我们在接下来的章节中看一些 Apache Spark 中的技巧和技术。

在下一章中，我们将看一下 Apache Spark 程序中的转换和操作。


# 第七章：转换和操作

转换和操作是 Apache Spark 程序的主要构建模块。在本章中，我们将看一下 Spark 转换来推迟计算，然后看一下应该避免哪些转换。然后，我们将使用`reduce`和`reduceByKey`方法对数据集进行计算。然后，我们将执行触发实际计算的操作。在本章结束时，我们还将学习如何重用相同的`rdd`进行不同的操作。

在本章中，我们将涵盖以下主题：

+   使用 Spark 转换来推迟计算到以后的时间

+   避免转换

+   使用`reduce`和`reduceByKey`方法来计算结果

+   执行触发实际计算我们的**有向无环图**（**DAG**）的操作

+   重用相同的`rdd`进行不同的操作

# 使用 Spark 转换来推迟计算到以后的时间

让我们首先了解 Spark DAG 的创建。我们将通过发出操作来执行 DAG，并推迟关于启动作业的决定，直到最后一刻来检查这种可能性给我们带来了什么。

让我们看一下我们将在本节中使用的代码。

首先，我们需要初始化 Spark。我们进行的每个测试都是相同的。在开始使用之前，我们需要初始化它，如下例所示：

```py
class DeferComputations extends FunSuite {
val spark: SparkContext = SparkSession.builder().master("local[2]").getOrCreate().sparkContext
```

然后，我们将进行实际测试。在这里，`test`被称为`should defer computation`。它很简单，但展示了 Spark 的一个非常强大的抽象。我们首先创建一个`InputRecord`的`rdd`，如下例所示：

```py
test("should defer computations") {
 //given
    val input = spark.makeRDD(
        List(InputRecord(userId = "A"),
            InputRecord(userId = "B")))
```

`InputRecord`是一个具有可选参数的唯一标识符的案例类。

如果我们没有提供它和必需的参数`userId`，它可以是一个随机的`uuid`。`InputRecord`将在本书中用于测试目的。我们已经创建了两条`InputRecord`的记录，我们将对其应用转换，如下例所示：

```py
//when apply transformation
val rdd = input
    .filter(_.userId.contains("A"))
    .keyBy(_.userId)
.map(_._2.userId.toLowerCase)
//.... built processing graph lazy
```

我们只会过滤`userId`字段中包含`A`的记录。然后我们将其转换为`keyBy(_.userId)`，然后从值中提取`userId`并将其映射为小写。这就是我们的`rdd`。所以，在这里，我们只创建了 DAG，但还没有执行。假设我们有一个复杂的程序，在实际逻辑之前创建了许多这样的无环图。

Spark 的优点是直到发出操作之前不会执行，但我们可以有一些条件逻辑。例如，我们可以得到一个快速路径的执行。假设我们有`shouldExecutePartOfCode()`，它可以检查配置开关，或者去 REST 服务计算`rdd`计算是否仍然相关，如下例所示：

```py
if (shouldExecutePartOfCode()) {
     //rdd.saveAsTextFile("") ||
     rdd.collect().toList
  } else {
    //condition changed - don't need to evaluate DAG
 }
}
```

我们已经使用了简单的方法进行测试，我们只是返回`true`，但在现实生活中，这可能是复杂的逻辑：

```py
private def shouldExecutePartOfCode(): Boolean = {
    //domain logic that decide if we still need to calculate
    true
    }
}
```

在它返回`true`之后，我们可以决定是否要执行 DAG。如果要执行，我们可以调用`rdd.collect().toList`或`saveAsTextFile`来执行`rdd`。否则，我们可以有一个快速路径，并决定我们不再对输入的`rdd`感兴趣。通过这样做，只会创建图。

当我们开始测试时，它将花费一些时间来完成，并返回以下输出：

```py
"C:\Program Files\Java\jdk-12\bin\java.exe" "-javaagent:C:\Program Files\JetBrains\IntelliJ IDEA 2018.3.5\lib\idea_rt.jar=50627:C:\Program Files\JetBrains\IntelliJ IDEA 2018.3.5\bin" -Dfile.encoding=UTF-8 -classpath C:\Users\Sneha\IdeaProjects\Chapter07\out\production\Chapter07 com.company.Main

Process finished with exit code 0
```

我们可以看到我们的测试通过了，我们可以得出它按预期工作的结论。现在，让我们看一些应该避免的转换。

# 避免转换

在本节中，我们将看一下应该避免的转换。在这里，我们将专注于一个特定的转换。

我们将从理解`groupBy`API 开始。然后，我们将研究在使用`groupBy`时的数据分区，然后我们将看一下什么是 skew 分区以及为什么应该避免 skew 分区。

在这里，我们正在创建一个交易列表。`UserTransaction`是另一个模型类，包括`userId`和`amount`。以下代码块显示了一个典型的交易，我们正在创建一个包含五个交易的列表：

```py
test("should trigger computations using actions") {
 //given
 val input = spark.makeRDD(
     List(
         UserTransaction(userId = "A", amount = 1001),
         UserTransaction(userId = "A", amount = 100),
         UserTransaction(userId = "A", amount = 102),
         UserTransaction(userId = "A", amount = 1),
         UserTransaction(userId = "B", amount = 13)))
```

我们已经为`userId = "A"`创建了四笔交易，为`userId = "B"`创建了一笔交易。

现在，让我们考虑我们想要合并特定`userId`的交易以获得交易列表。我们有一个`input`，我们正在按`userId`分组，如下例所示：

```py
//when apply transformation
val rdd = input
    .groupBy(_.userId)
    .map(x => (x._1,x._2.toList))
    .collect()
    .toList
```

对于每个`x`元素，我们将创建一个元组。元组的第一个元素是一个 ID，而第二个元素是该特定 ID 的每个交易的迭代器。我们将使用`toList`将其转换为列表。然后，我们将收集所有内容并将其分配给`toList`以获得我们的结果。让我们断言结果。`rdd`应该包含与`B`相同的元素，即键和一个交易，以及`A`，其中有四个交易，如下面的代码所示：

```py
//then
rdd should contain theSameElementsAs List(
    ("B", List(UserTransaction("B", 13))),
    ("A", List(
        UserTransaction("A", 1001),
        UserTransaction("A", 100),
        UserTransaction("A", 102),
        UserTransaction("A", 1))
    )
  )
 }
}
```

让我们开始这个测试，并检查它是否按预期行为。我们得到以下输出：

```py
"C:\Program Files\Java\jdk-12\bin\java.exe" "-javaagent:C:\Program Files\JetBrains\IntelliJ IDEA 2018.3.5\lib\idea_rt.jar=50822:C:\Program Files\JetBrains\IntelliJ IDEA 2018.3.5\bin" -Dfile.encoding=UTF-8 -classpath C:\Users\Sneha\IdeaProjects\Chapter07\out\production\Chapter07 com.company.Main

Process finished with exit code 0
```

乍一看，它已经通过了，并且按预期工作。但是，为什么我们要对它进行分组的问题就出现了。我们想要对它进行分组以将其保存到文件系统或进行一些进一步的操作，例如连接所有金额。

我们可以看到我们的输入不是正常分布的，因为几乎所有的交易都是针对`userId = "A"`。因此，我们有一个偏斜的键。这意味着一个键包含大部分数据，而其他键包含较少的数据。当我们在 Spark 中使用`groupBy`时，它会获取所有具有相同分组的元素，例如在这个例子中是`userId`，并将这些值发送到完全相同的执行者。

例如，如果我们的执行者有 5GB 的内存，我们有一个非常大的数据集，有数百 GB，其中一个键有 90%的数据，这意味着所有数据都将传输到一个执行者，其余的执行者将获取少数数据。因此，数据将不会正常分布，并且由于非均匀分布，处理效率将不会尽可能高。

因此，当我们使用`groupBy`键时，我们必须首先回答为什么要对其进行分组的问题。也许我们可以在`groupBy`之前对其进行过滤或聚合，然后我们只会对结果进行分组，或者根本不进行分组。我们将在以下部分中研究如何使用 Spark API 解决这个问题。

# 使用 reduce 和 reduceByKey 方法来计算结果

在本节中，我们将使用`reduce`和`reduceBykey`函数来计算我们的结果，并了解`reduce`的行为。然后，我们将比较`reduce`和`reduceBykey`函数，以确定在特定用例中应该使用哪个函数。

我们将首先关注`reduce`API。首先，我们需要创建一个`UserTransaction`的输入。我们有用户交易`A`，金额为`10`，`B`的金额为`1`，`A`的金额为`101`。假设我们想找出全局最大值。我们对特定键的数据不感兴趣，而是对全局数据感兴趣。我们想要扫描它，取最大值，并返回它，如下例所示：

```py
test("should use reduce API") {
    //given
    val input = spark.makeRDD(List(
    UserTransaction("A", 10),
    UserTransaction("B", 1),
    UserTransaction("A", 101)
    ))
```

因此，这是减少使用情况。现在，让我们看看如何实现它，如下例所示：

```py
//when
val result = input
    .map(_.amount)
    .reduce((a, b) => if (a > b) a else b)

//then
assert(result == 101)
}
```

对于`input`，我们需要首先映射我们感兴趣的字段。在这种情况下，我们对`amount`感兴趣。我们将取`amount`，然后取最大值。

在前面的代码示例中，`reduce`有两个参数，`a`和`b`。一个参数将是我们正在传递的特定 Lambda 中的当前最大值，而第二个参数将是我们现在正在调查的实际值。如果该值高于到目前为止的最大状态，我们将返回`a`；如果不是，它将返回`b`。我们将遍历所有元素，最终结果将只是一个长数字。

因此，让我们测试一下，检查结果是否确实是`101`，如以下代码输出所示。这意味着我们的测试通过了。

```py
"C:\Program Files\Java\jdk-12\bin\java.exe" "-javaagent:C:\Program Files\JetBrains\IntelliJ IDEA 2018.3.5\lib\idea_rt.jar=50894:C:\Program Files\JetBrains\IntelliJ IDEA 2018.3.5\bin" -Dfile.encoding=UTF-8 -classpath C:\Users\Sneha\IdeaProjects\Chapter07\out\production\Chapter07 com.company.Main

Process finished with exit code 0
```

现在，让我们考虑一个不同的情况。我们想找到最大的交易金额，但这次我们想根据用户来做。我们不仅想找出用户`A`的最大交易，还想找出用户`B`的最大交易，但我们希望这些事情是独立的。因此，对于相同的每个键，我们只想从我们的数据中取出最大值，如以下示例所示：

```py
test("should use reduceByKey API") {
    //given
    val input = spark.makeRDD(
    List(
        UserTransaction("A", 10),
        UserTransaction("B", 1),
        UserTransaction("A", 101)
    )
)
```

要实现这一点，`reduce`不是一个好选择，因为它将遍历所有的值并给出全局最大值。我们在 Spark 中有关键操作，但首先，我们要为特定的元素组做这件事。我们需要使用`keyBy`告诉 Spark 应该将哪个 ID 作为唯一的，并且它将仅在特定的键内执行`reduce`函数。因此，我们使用`keyBy(_.userId)`，然后得到`reducedByKey`函数。`reduceByKey`函数类似于`reduce`，但它按键工作，因此在 Lambda 内，我们只会得到特定键的值，如以下示例所示：

```py
    //when
    val result = input
      .keyBy(_.userId)
      .reduceByKey((firstTransaction, secondTransaction) =>
        TransactionChecker.higherTransactionAmount(firstTransaction, secondTransaction))
      .collect()
      .toList
```

通过这样做，我们得到第一笔交易，然后是第二笔。第一笔将是当前的最大值，第二笔将是我们正在调查的交易。我们将创建一个辅助函数，它接受这些交易并称之为`higherTransactionAmount`。

`higherTransactionAmount`函数用于获取`firstTransaction`和`secondTransaction`。请注意，对于`UserTransaction`类型，我们需要传递该类型。它还需要返回`UserTransaction`，我们不能返回不同的类型。

如果您正在使用 Spark 的`reduceByKey`方法，我们需要返回与`input`参数相同的类型。如果`firstTransaction.amount`高于`secondTransaction.amount`，我们将返回`firstTransaction`，因为我们返回的是`secondTransaction`，所以是交易对象而不是总金额。这在以下示例中显示：

```py
object TransactionChecker {
    def higherTransactionAmount(firstTransaction: UserTransaction, secondTransaction: UserTransaction): UserTransaction = {
        if (firstTransaction.amount > secondTransaction.amount) firstTransaction else     secondTransaction
    }
}
```

现在，我们将收集、添加和测试交易。在我们的测试之后，我们得到了输出，对于键`B`，我们应该得到交易`("B", 1)`，对于键`A`，交易`("A", 101)`。没有交易`("A", 10)`，因为我们已经过滤掉了它，但我们可以看到对于每个键，我们都能找到最大值。这在以下示例中显示：

```py
    //then
    result should contain theSameElementsAs
      List(("B", UserTransaction("B", 1)), ("A", UserTransaction("A", 101)))
  }

}
```

我们可以看到测试通过了，一切都如预期的那样，如以下输出所示：

```py
"C:\Program Files\Java\jdk-12\bin\java.exe" "-javaagent:C:\Program Files\JetBrains\IntelliJ IDEA 2018.3.5\lib\idea_rt.jar=50909:C:\Program Files\JetBrains\IntelliJ IDEA 2018.3.5\bin" -Dfile.encoding=UTF-8 -classpath C:\Users\Sneha\IdeaProjects\Chapter07\out\production\Chapter07 com.company.Main

Process finished with exit code 0
```

在下一节中，我们将执行触发数据计算的操作。

# 执行触发计算的操作

Spark 有更多触发 DAG 的操作，我们应该了解所有这些，因为它们非常重要。在本节中，我们将了解 Spark 中可以成为操作的内容，对操作进行一次遍历，并测试这些操作是否符合预期。

我们已经涵盖的第一个操作是`collect`。除此之外，我们还涵盖了两个操作——在上一节中我们都涵盖了`reduce`和`reduceByKey`。这两种方法都是操作，因为它们返回单个结果。

首先，我们将创建我们的交易的`input`，然后应用一些转换，仅用于测试目的。我们将只取包含`A`的用户，使用`keyBy_.userId`，然后只取所需交易的金额，如以下示例所示：

```py
test("should trigger computations using actions") {
     //given
     val input = spark.makeRDD(
     List(
         UserTransaction(userId = "A", amount = 1001),
         UserTransaction(userId = "A", amount = 100),
         UserTransaction(userId = "A", amount = 102),
         UserTransaction(userId = "A", amount = 1),
         UserTransaction(userId = "B", amount = 13)))

//when apply transformation
 val rdd = input
     .filter(_.userId.contains("A"))
     .keyBy(_.userId)
     .map(_._2.amount)
```

我们已经知道的第一个操作是`rdd.collect().toList`。接下来是`count()`，它需要获取所有的值并计算`rdd`中有多少值。没有办法在不触发转换的情况下执行`count()`。此外，Spark 中还有不同的方法，如`countApprox`、`countApproxDistinct`、`countByValue`和`countByValueApprox`。以下示例显示了`rdd.collect().toList`的代码：

```py
//then
 println(rdd.collect().toList)
 println(rdd.count()) //and all count*
```

如果我们有一个庞大的数据集，并且近似计数就足够了，你可以使用`countApprox`，因为它会快得多。然后我们使用`rdd.first()`，但这个选项有点不同，因为它只需要取第一个元素。有时，如果你想取第一个元素并执行我们 DAG 中的所有操作，我们需要专注于这一点，并以以下方式检查它：

```py
println(rdd.first())
```

此外，在`rdd`上，我们有`foreach()`，这是一个循环，我们可以传递任何函数。假定 Scala 函数或 Java 函数是 Lambda，但要执行我们结果`rdd`的元素，需要计算 DAG，因为从这里开始，它就是一个操作。`foreach()`方法的另一个变体是`foreachPartition()`，它获取每个分区并返回分区的迭代器。在其中，我们有一个迭代器再次进行迭代并打印我们的元素。我们还有我们的`max()`和`min()`方法，预期的是，`max()`取最大值，`min()`取最小值。但这些方法都需要隐式排序。

如果我们有一个简单的原始类型的`rdd`，比如`Long`，我们不需要在这里传递它。但如果我们不使用`map()`，我们需要为 Spark 定义`UserTransaction`的排序，以便找出哪个元素是`max`，哪个元素是`min`。这两件事需要执行 DAG，因此它们被视为操作，如下面的例子所示：

```py
 rdd.foreach(println(_))
 rdd.foreachPartition(t => t.foreach(println(_)))
 println(rdd.max())
 println(rdd.min())
```

然后我们有`takeOrdered()`，这是一个比`first()`更耗时的操作，因为`first()`取一个随机元素。`takeOrdered()`需要执行 DAG 并对所有内容进行排序。当一切都排序好后，它才取出顶部的元素。

在我们的例子中，我们取`num = 1`。但有时，出于测试或监控的目的，我们需要只取数据的样本。为了取样，我们使用`takeSample()`方法并传递一个元素数量，如下面的代码所示：

```py
 println(rdd.takeOrdered(1).toList)
 println(rdd.takeSample(false, 2).toList)
 }
}
```

现在，让我们开始测试并查看实现前面操作的输出，如下面的屏幕截图所示：

```py
List(1001, 100, 102 ,1)
4
1001
1001
100
102
1
```

第一个操作返回所有值。第二个操作返回`4`作为计数。我们将考虑第一个元素`1001`，但这是一个随机值，它是无序的。然后我们在循环中打印所有的元素，如下面的输出所示：

```py
102
1
1001
1
List(1)
List(100, 1)
```

然后我们得到`max`和`min`值，如`1001`和`1`，这与`first()`类似。之后，我们得到一个有序列表`List(1)`，和一个样本`List(100, 1)`，这是随机的。因此，在样本中，我们从输入数据和应用的转换中得到随机值。

在下一节中，我们将学习如何重用`rdd`进行不同的操作。

# 重用相同的 rdd 进行不同的操作

在这一部分，我们将重用相同的`rdd`进行不同的操作。首先，我们将通过重用`rdd`来最小化执行时间。然后，我们将查看缓存和我们代码的性能测试。

下面的例子是前面部分的测试，但稍作修改，这里我们通过`currentTimeMillis()`取`start`和`result`。因此，我们只是测量执行的所有操作的`result`：

```py
//then every call to action means that we are going up to the RDD chain
//if we are loading data from external file-system (I.E.: HDFS), every action means
//that we need to load it from FS.
    val start = System.currentTimeMillis()
    println(rdd.collect().toList)
    println(rdd.count())
    println(rdd.first())
    rdd.foreach(println(_))
    rdd.foreachPartition(t => t.foreach(println(_)))
    println(rdd.max())
    println(rdd.min())
    println(rdd.takeOrdered(1).toList)
    println(rdd.takeSample(false, 2).toList)
    val result = System.currentTimeMillis() - start

    println(s"time taken (no-cache): $result")

}
```

如果有人对 Spark 不太了解，他们会认为所有操作都被巧妙地执行了。我们知道每个操作都意味着我们要上升到链中的`rdd`，这意味着我们要对所有的转换进行加载数据。在生产系统中，加载数据将来自外部的 PI 系统，比如 HDFS。这意味着每个操作都会导致对文件系统的调用，这将检索所有数据，然后应用转换，如下例所示：

```py
//when apply transformation
val rdd = input
    .filter(_.userId.contains("A"))
    .keyBy(_.userId)
    .map(_._2.amount)
```

这是一个非常昂贵的操作，因为每个操作都非常昂贵。当我们开始这个测试时，我们可以看到没有缓存的时间为 632 毫秒，如下面的输出所示：

```py
List(1)
List(100, 1)
time taken (no-cache): 632
Process finished with exit code 0
```

让我们将这与缓存使用进行比较。乍一看，我们的测试看起来非常相似，但这并不相同，因为您正在使用`cache()`，而我们正在返回`rdd`。因此，`rdd`将已经被缓存，对`rdd`的每个后续调用都将经过`cache`，如下例所示：

```py
//when apply transformation
val rdd = input
    .filter(_.userId.contains("A"))
    .keyBy(_.userId)
    .map(_._2.amount)
    .cache()
```

第一个操作将执行 DAG，将数据保存到我们的缓存中，然后后续的操作将根据从内存中调用的方法来检索特定的内容。不会有 HDFS 查找，所以让我们按照以下示例开始这个测试，看看需要多长时间：

```py
//then every call to action means that we are going up to the RDD chain
//if we are loading data from external file-system (I.E.: HDFS), every action means
//that we need to load it from FS.
    val start = System.currentTimeMillis()
    println(rdd.collect().toList)
    println(rdd.count())
    println(rdd.first())
    rdd.foreach(println(_))
    rdd.foreachPartition(t => t.foreach(println(_)))
    println(rdd.max())
    println(rdd.min())
    println(rdd.takeOrdered(1).toList)
    println(rdd.takeSample(false, 2).toList)
    val result = System.currentTimeMillis() - start

    println(s"time taken(cache): $result")

    }
}
```

第一个输出将如下所示：

```py
List(1)
List(100, 102)
time taken (no-cache): 585
List(1001, 100, 102, 1)
4
```

第二个输出将如下所示：

```py
1
List(1)
List(102, 1)
time taken(cache): 336
Process finished with exit code 0
```

没有缓存，值为`585`毫秒，有缓存时，值为`336`。这个差异并不大，因为我们只是在测试中创建数据。然而，在真实的生产系统中，这将是一个很大的差异，因为我们需要从外部文件系统中查找数据。

# 总结

因此，让我们总结一下这一章节。首先，我们使用 Spark 转换来推迟计算到以后的时间，然后我们学习了哪些转换应该避免。接下来，我们看了如何使用`reduceByKey`和`reduce`来计算我们的全局结果和特定键的结果。之后，我们执行了触发计算的操作，然后了解到每个操作都意味着加载数据的调用。为了缓解这个问题，我们学习了如何为不同的操作减少相同的`rdd`。

在下一章中，我们将看一下 Spark 引擎的不可变设计。


# 第八章：不可变设计

在本章中，我们将看看 Apache Spark 的不可变设计。我们将深入研究 Spark RDD 的父/子链，并以不可变的方式使用 RDD。然后，我们将使用 DataFrame 操作进行转换，以讨论在高度并发的环境中的不可变性。在本章结束时，我们将以不可变的方式使用数据集 API。

在这一章中，我们将涵盖以下主题：

+   深入研究 Spark RDD 的父/子链

+   以不可变的方式使用 RDD

+   使用 DataFrame 操作进行转换

+   在高度并发的环境中的不可变性

+   以不可变的方式使用数据集 API

# 深入研究 Spark RDD 的父/子链

在本节中，我们将尝试实现我们自己的 RDD，继承 RDD 的父属性。

我们将讨论以下主题：

+   扩展 RDD

+   与父 RDD 链接新的 RDD

+   测试我们的自定义 RDD

# 扩展 RDD

这是一个有很多隐藏复杂性的简单测试。让我们从创建记录的列表开始，如下面的代码块所示：

```py
class InheritanceRdd extends FunSuite {
  val spark: SparkContext = SparkSession
    .builder().master("local[2]").getOrCreate().sparkContext

  test("use extended RDD") {
    //given
    val rdd = spark.makeRDD(List(Record(1, "d1")))
```

`Record`只是一个具有`amount`和`description`的案例类，所以`amount`是 1，`d1`是描述。

然后我们创建了`MultipledRDD`并将`rdd`传递给它，然后将乘数设置为`10`，如下面的代码所示：

```py
val extendedRdd = new MultipliedRDD(rdd, 10)
```

我们传递父 RDD，因为它包含在另一个 RDD 中加载的数据。通过这种方式，我们构建了两个 RDD 的继承链。

# 与父 RDD 链接新的 RDD

我们首先创建了一个多重 RDD 类。在`MultipliedRDD`类中，我们有两个传递参数的东西：

+   记录的简要 RDD，即`RDD[Record]`

+   乘数，即`Double`

在我们的情况下，可能会有多个 RDD 的链，这意味着我们的 RDD 中可能会有多个 RDD。因此，这并不总是所有有向无环图的父级。我们只是扩展了类型为记录的 RDD，因此我们需要传递扩展的 RDD。

RDD 有很多方法，我们可以覆盖任何我们想要的方法。但是，这一次，我们选择了`compute`方法，我们将覆盖计算乘数的方法。在这里，我们获取`Partition`分区和`TaskContext`。这些是执行引擎传递给我们方法的，因此我们不需要担心这一点。但是，我们需要返回与我们通过继承链中的 RDD 类传递的类型完全相同的迭代器。这将是记录的迭代器。

然后我们执行第一个父逻辑，第一个父只是获取我们链中的第一个 RDD。这里的类型是`Record`，我们获取`split`和`context`的`iterator`，其中`split`只是将要执行的分区。我们知道 Spark RDD 是由分区器分区的，但是在这里，我们只是获取我们需要拆分的特定分区。因此，迭代器获取分区和任务上下文，因此它知道应该从该迭代方法返回哪些值。对于迭代器中的每条记录，即`salesRecord`，如`amount`和`description`，我们将`amount`乘以传递给构造函数的`multiplier`来获得我们的`Double`。

通过这样做，我们已经将我们的金额乘以了乘数，然后我们可以返回具有新金额的新记录。因此，我们现在有了旧记录乘以我们的“乘数”的金额和`salesRecord`的描述。对于第二个过滤器，我们需要“覆盖”的是`getPartitions`，因为我们希望保留父 RDD 的分区。例如，如果之前的 RDD 有 100 个分区，我们也希望我们的`MultipledRDD`有 100 个分区。因此，我们希望保留关于分区的信息，而不是丢失它。出于同样的原因，我们只是将其代理给`firstParent`。RDD 的`firstParent`然后只会从特定 RDD 中获取先前的分区。

通过这种方式，我们创建了一个新的`multipliedRDD`，它传递了父级和乘数。对于我们的`extendedRDD`，我们需要`collect`它并调用`toList`，我们的列表应该包含`10`和`d1`，如下例所示：

```py
extendedRdd.collect().toList should contain theSameElementsAs List(
 Record(10, "d1")
 )
 }
}
```

当我们创建新的 RDD 时，计算会自动执行，因此它总是在没有显式方法调用的情况下执行。

# 测试我们的自定义 RDD

让我们开始这个测试，以检查这是否已经创建了我们的 RDD。通过这样做，我们可以扩展我们的父 RDD 并向我们的 RDD 添加行为。这在下面的截图中显示：

```py
"C:\Program Files\Java\jdk-12\bin\java.exe" "-javaagent:C:\Program Files\JetBrains\IntelliJ IDEA 2018.3.5\lib\idea_rt.jar=51687:C:\Program Files\JetBrains\IntelliJ IDEA 2018.3.5\bin" -Dfile.encoding=UTF-8 -classpath C:\Users\Sneha\IdeaProjects\Chapter07\out\production\Chapter07 com.company.Main

Process finished with exit code 0
```

在下一节中，我们将以不可变的方式使用 RDD。

# 以不可变的方式使用 RDD

现在我们知道如何使用 RDD 继承创建执行链，让我们学习如何以不可变的方式使用 RDD。

在这一部分，我们将讨论以下主题：

+   理解 DAG 的不可变性

+   从一个根 RDD 创建两个叶子

+   检查两个叶子的结果

让我们首先了解有向无环图的不可变性以及它给我们带来了什么。然后，我们将从一个节点 RDD 创建两个叶子，并检查如果我们在一个叶子 RDD 上创建一个转换，那么两个叶子是否完全独立地行为。然后，我们将检查当前 RDD 的两个叶子的结果，并检查对任何叶子的任何转换是否不会改变或影响根 RDD。以这种方式工作是至关重要的，因为我们发现我们将无法从根 RDD 创建另一个叶子，因为根 RDD 将被更改，这意味着它将是可变的。为了克服这一点，Spark 设计师为我们创建了一个不可变的 RDD。

有一个简单的测试来显示 RDD 应该是不可变的。首先，我们将从`0 到 5`创建一个 RDD，它被添加到来自 Scala 分支的序列中。`to`获取`Int`，第一个参数是一个隐式参数，来自 Scala 包，如下例所示：

```py
class ImmutableRDD extends FunSuite {
    val spark: SparkContext = SparkSession
        .builder().master("local[2]").getOrCreate().sparkContext

test("RDD should be immutable") {
    //given
    val data = spark.makeRDD(0 to 5)
```

一旦我们有了 RDD 数据，我们可以创建第一个叶子。第一个叶子是一个结果（`res`），我们只是将每个元素乘以`2`。让我们创建第二个叶子，但这次它将被标记为`4`，如下例所示：

```py
//when
val res = data.map(_ * 2)

val leaf2 = data.map(_ * 4)
```

所以，我们有我们的根 RDD 和两个叶子。首先，我们将收集第一个叶子，并看到其中的元素为`0, 2, 4, 6, 8, 10`，所以这里的一切都乘以`2`，如下例所示：

```py
//then
res.collect().toList should contain theSameElementsAs List(
    0, 2, 4, 6, 8, 10
)
```

然而，即使我们在`res`上有了通知，数据仍然与一开始的完全相同，即`0, 1, 2, 3, 4, 5`，如下例所示：

```py
data.collect().toList should contain theSameElementsAs List(
    0, 1, 2, 3, 4, 5
    )
  }
}
```

所以，一切都是不可变的，执行`* 2`的转换并没有改变我们的数据。如果我们为`leaf2`创建一个测试，我们将`collect`它并调用`toList`。我们会看到它应该包含像`0, 4, 8, 12, 16, 20`这样的元素，如下例所示：

```py
leaf2.collect().toList should contain theSameElementsAs List(
 0, 4, 8, 12, 16, 20
)
```

当我们运行测试时，我们会看到我们执行中的每条路径，即数据或第一个叶子和第二个叶子，彼此独立地行为，如下面的代码输出所示：

```py
"C:\Program Files\Java\jdk-12\bin\java.exe" "-javaagent:C:\Program Files\JetBrains\IntelliJ IDEA 2018.3.5\lib\idea_rt.jar=51704:C:\Program Files\JetBrains\IntelliJ IDEA 2018.3.5\bin" -Dfile.encoding=UTF-8 -classpath C:\Users\Sneha\IdeaProjects\Chapter07\out\production\Chapter07 com.company.Main

Process finished with exit code 0
```

每次变异都是不同的；我们可以看到测试通过了，这表明我们的 RDD 是不可变的。

# 使用 DataFrame 操作进行转换

API 的数据下面有一个 RDD，因此 DataFrame 是不可变的。在 DataFrame 中，不可变性甚至更好，因为我们可以动态地添加和减去列，而不改变源数据集。

在这一部分，我们将涵盖以下主题：

+   理解 DataFrame 的不可变性

+   从一个根 DataFrame 创建两个叶子

+   通过发出转换来添加新列

我们将首先使用操作的数据来转换我们的 DataFrame。首先，我们需要了解 DataFrame 的不可变性，然后我们将从一个根 DataFrame 创建两个叶子，但这次是。然后，我们将发出一个略有不同于 RDD 的转换。这将向我们的结果 DataFrame 添加一个新列，因为我们在 DataFrame 中是这样操作的。如果我们想要映射数据，那么我们需要从第一列中获取数据，进行转换，并保存到另一列，然后我们将有两列。如果我们不再感兴趣，我们可以删除第一列，但结果将是另一个 DataFrame。

因此，我们将有第一个 DataFrame 有一列，第二个有结果和源，第三个只有一个结果。让我们看看这一部分的代码。

我们将创建一个 DataFrame，所以我们需要调用`toDF()`方法。我们将使用`"a"`作为`"1"`，`"b"`作为`"2"`，`"d"`作为`"200"`来创建`UserData`。`UserData`有`userID`和`data`两个字段，都是`String`类型，如下例所示：

```py
test("Should use immutable DF API") {
 import spark.sqlContext.implicits._
 //given
 val userData =
 spark.sparkContext.makeRDD(List(
 UserData("a", "1"),
 UserData("b", "2"),
 UserData("d", "200")
 )).toDF()
```

在测试中使用案例类创建 RDD 是很重要的，因为当我们调用 DataFrame 时，这部分将推断模式并相应地命名列。以下代码是这方面的一个例子，我们只从`userData`中的`userID`列中进行过滤：

```py
//when
    val res = userData.filter(userData("userId").isin("a"))
```

我们的结果应该只有一条记录，所以我们要删除两列，但是我们创建的`userData`源将有 3 行。因此，通过过滤对其进行修改，创建了另一个名为`res`的 DataFrame，而不修改输入的`userData`，如下例所示：

```py
    assert(res.count() == 1)
    assert(userData.count() == 3)

    }
}
```

让我们开始这个测试，看看来自 API 的不可变数据的行为，如下屏幕截图所示：

```py
"C:\Program Files\Java\jdk-12\bin\java.exe" "-javaagent:C:\Program Files\JetBrains\IntelliJ IDEA 2018.3.5\lib\idea_rt.jar=51713:C:\Program Files\JetBrains\IntelliJ IDEA 2018.3.5\bin" -Dfile.encoding=UTF-8 -classpath C:\Users\Sneha\IdeaProjects\Chapter07\out\production\Chapter07 com.company.Main

Process finished with exit code 0
```

正如我们所看到的，我们的测试通过了，并且从结果（`res`）中，我们知道我们的父级没有被修改。因此，例如，如果我们想在`res.map()`上映射一些东西，我们可以映射`userData`列，如下例所示：

```py
res.map(a => a.getString("userId") + "can")
```

另一个叶子将具有一个额外的列，而不更改`userId`源代码，因此这就是 DataFrame 的不可变性。

# 高并发环境中的不可变性

我们看到了不可变性如何影响程序的创建和设计，现在我们将了解它的用途。

在本节中，我们将涵盖以下主题：

+   可变集合的缺点

+   创建两个同时修改可变集合的线程

+   推理并发程序

让我们首先了解可变集合的原因。为此，我们将创建两个同时修改可变集合的线程。我们将使用此代码进行测试。首先，我们将创建一个`ListBuffer`，它是一个可变列表。然后，我们可以添加和删除链接，而无需为任何修改创建另一个列表。然后，我们可以创建一个具有两个线程的`Executors`服务。我们需要两个线程同时开始修改状态。稍后，我们将使用`Java.util.concurrent`中的`CountDownLatch`构造。这在下面的例子中显示：

```py
import java.util.concurrent.{CountDownLatch, Executors}
import org.scalatest.FunSuite
import scala.collection.mutable.ListBuffer
class MultithreadedImmutabilityTest extends FunSuite {

test("warning: race condition with mutability") {
//given
var listMutable = new ListBuffer[String]()
val executors = Executors.newFixedThreadPool(2)
val latch = new CountDownLatch(2)
```

`CountDownLatch`是一种构造，它帮助我们阻止线程处理，直到我们要求它们开始。我们需要等待逻辑，直到两个线程开始执行。然后，我们向`executors`提交一个`Runnable`，我们的`run()`方法通过发出`countDown()`来表示准备好进行操作，并将`"A"`添加到`listMutable`，如下例所示：

```py
 //when
 executors.submit(new Runnable {
     override def run(): Unit = {
         latch.countDown()
         listMutable += "A"
     }
 })
```

然后，另一个线程启动，并且也使用`countDown`来表示它已准备好开始。但首先，它会检查列表是否包含`"A"`，如果没有，就会添加`"A"`，如下例所示：

```py
 executors.submit(new Runnable {
     override def run(): Unit = {
         latch.countDown()
         if(!listMutable.contains("A")) {
             listMutable += "A"
         }
     }
 })
```

然后，我们使用`await()`等待`countDown`发出，当它发出时，我们可以继续验证我们的程序，如下例所示：

```py
    latch.await()
```

`listMutable`包含`"A"`或可能包含`"A","A"`。`listMutable`检查列表是否包含`"A"`,如果没有，它将不会添加该元素，如下例所示：

```py
    //then
    //listMutable can have ("A") or ("A","A")
    }
}
```

但这里存在竞争条件。在检查`if(!listMutable.contains("A"))`之后，`run()`线程可能会将`"A"`元素添加到列表中。但我们在`if`中，所以我们将通过`listMutable += "A"`添加另一个`"A"`。由于状态的可变性以及它通过另一个线程进行了修改，我们可能会有`"A"`或`"A","A"`。

在使用可变状态时需要小心，因为我们不能有这样一个损坏的状态。为了缓解这个问题，我们可以在`java.util`集合上使用同步列表。

但如果我们有同步块，那么我们的程序将非常慢，因为我们需要独占地访问它。我们还可以使用`java.util.concurrent.locks`包中的`lock`。我们可以使用`ReadLock`或`WriteLock`等实现。在下面的例子中，我们将使用`WriteLock`：

```py
val lock = new WriteLock()
```

我们还需要对我们的`lock()`进行`lock`，然后再进行下一步，如下例所示：

```py
lock.lock()
```

之后，我们可以使用`unlock()`。然而，我们也应该在第二个线程中这样做，这样我们的列表只有一个元素，如下例所示：

```py
lock.unlock()
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/hsn-bgdt-anlt-pyspark/img/9b19108c-26d0-4115-92a9-8191a1900bdb.png)

锁定是一个非常艰难和昂贵的操作，因此不可变性是性能程序的关键。

# 以不可变的方式使用数据集 API

在本节中，我们将以不可变的方式使用数据集 API。我们将涵盖以下主题：

+   数据集的不可变性

+   从一个根数据集创建两个叶子

+   通过发出转换添加新列

数据集的测试用例非常相似，但我们需要对我们的数据进行`toDS()`以确保类型安全。数据集的类型是`userData`，如下例所示：

```py
import com.tomekl007.UserData
import org.apache.spark.sql.SparkSession
import org.scalatest.FunSuite

class ImmutableDataSet extends FunSuite {
 val spark: SparkSession = SparkSession
 .builder().master("local[2]").getOrCreate()

test("Should use immutable DF API") {
 import spark.sqlContext.implicits._
 //given
 val userData =
 spark.sparkContext.makeRDD(List(
 UserData("a", "1"),
 UserData("b", "2"),
 UserData("d", "200")
 )).toDF()
```

现在，我们将发出对`userData`的过滤，并指定`isin`，如下例所示：

```py
   //when
    val res = userData.filter(userData("userId").isin("a"))
```

它将返回结果（`res`），这是一个带有我们的`1`元素的叶子。由于这个明显的根，`userData`仍然有`3`个元素。让我们执行这个程序，如下例所示：

```py
    assert(res.count() == 1)
    assert(userData.count() == 3)

 }
}
```

我们可以看到我们的测试通过了，这意味着数据集也是 DataFrame 之上的不可变抽象，并且具有相同的特性。`userData`有一个非常有用的类型集，如果使用`show()`方法，它将推断模式并知道`"a"`字段是字符串或其他类型，如下例所示：

```py
userData.show()
```

输出将如下所示：

```py
+------+----+
|userId|data|
|----- |----|
|     a|   1|
|     b|   2|
|     d| 200|
+------|----+ 
```

在前面的输出中，我们有`userID`和`data`字段。

# 总结

在本章中，我们深入研究了 Spark RDD 的父子链，并创建了一个能够根据父 RDD 计算一切的乘数 RDD，还基于父 RDD 的分区方案。我们以不可变的方式使用了 RDD。我们看到，从父级创建的叶子的修改并没有修改部分。我们还学习了一个更好的抽象，即 DataFrame，因此我们学会了可以在那里使用转换。然而，每个转换只是添加到另一列，而不是直接修改任何内容。接下来，我们只需在高度并发的环境中设置不可变性。我们看到了当访问多个线程时，可变状态是不好的。最后，我们看到数据集 API 也是以不可变的方式创建的，我们可以在这里利用这些特性。

在下一章中，我们将看看如何避免洗牌和减少个人开支。
