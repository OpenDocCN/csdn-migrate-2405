# Scala 和 Spark 大数据分析（九）

> 原文：[`zh.annas-archive.org/md5/39EECC62E023387EE8C22CA10D1A221A`](https://zh.annas-archive.org/md5/39EECC62E023387EE8C22CA10D1A221A)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十九章：PySpark 和 SparkR

在本章中，我们将讨论另外两个流行的 API：PySpark 和 SparkR，分别用于使用 Python 和 R 编程语言编写 Spark 代码。本章的第一部分将涵盖在使用 PySpark 时的一些技术方面。然后我们将转向 SparkR，并看看如何轻松使用它。本章将在整个过程中讨论以下主题：

+   PySpark 介绍

+   安装和开始使用 PySpark

+   与 DataFrame API 交互

+   使用 PySpark 的 UDFs

+   使用 PySpark 进行数据分析

+   SparkR 介绍

+   为什么要使用 SparkR？

+   安装和开始使用 SparkR

+   数据处理和操作

+   使用 SparkR 处理 RDD 和 DataFrame

+   使用 SparkR 进行数据可视化

# PySpark 介绍

Python 是最受欢迎的通用编程语言之一，具有许多令人兴奋的特性，可用于数据处理和机器学习任务。为了从 Python 中使用 Spark，最初开发了 PySpark 作为 Python 到 Apache Spark 的轻量级前端，并使用 Spark 的分布式计算引擎。在本章中，我们将讨论使用 Python IDE（如 PyCharm）从 Python 中使用 Spark 的一些技术方面。

许多数据科学家使用 Python，因为它具有丰富的数值库，具有统计、机器学习或优化的重点。然而，在 Python 中处理大规模数据集通常很麻烦，因为运行时是单线程的。因此，只能处理适合主内存的数据。考虑到这一限制，并为了在 Python 中获得 Spark 的全部功能，PySpark 最初被开发为 Python 到 Apache Spark 的轻量级前端，并使用 Spark 的分布式计算引擎。这样，Spark 提供了非 JVM 语言（如 Python）的 API。

这个 PySpark 部分的目的是提供使用 PySpark 的基本分布式算法。请注意，PySpark 是用于基本测试和调试的交互式 shell，不应该用于生产环境。

# 安装和配置

有许多安装和配置 PySpark 在 Python IDEs 如 PyCharm，Spider 等的方法。或者，如果您已经安装了 Spark 并配置了`SPARK_HOME`，您可以使用 PySpark。第三，您也可以从 Python shell 使用 PySpark。接下来我们将看到如何配置 PySpark 来运行独立的作业。

# 通过设置 SPARK_HOME

首先，下载并将 Spark 分发放在您喜欢的位置，比如`/home/asif/Spark`。现在让我们设置`SPARK_HOME`如下：

```scala
echo "export SPARK_HOME=/home/asif/Spark" >> ~/.bashrc

```

现在让我们设置`PYTHONPATH`如下：

```scala
echo "export PYTHONPATH=$SPARK_HOME/python/" >> ~/.bashrc
echo "export PYTHONPATH=$SPARK_HOME/python/lib/py4j-0.10.1-src.zip" >> ~/.bashrc

```

现在我们需要将以下两个路径添加到环境路径中：

```scala
echo "export PATH=$PATH:$SPARK_HOME" >> ~/.bashrc
echo "export PATH=$PATH:$PYTHONPATH" >> ~/.bashrc

```

最后，让我们刷新当前终端，以便使用新修改的`PATH`变量：

```scala
source ~/.bashrc

```

PySpark 依赖于`py4j` Python 包。它帮助 Python 解释器动态访问来自 JVM 的 Spark 对象。可以在 Ubuntu 上安装此软件包，方法如下：

```scala
$ sudo pip install py4j

```

或者，也可以使用默认的`py4j`，它已经包含在 Spark 中（`$SPARK_HOME/python/lib`）。

# 使用 Python shell

与 Scala 交互式 shell 一样，Python 也有一个交互式 shell。您可以从 Spark 根文件夹执行 Python 代码，如下所示：

```scala
$ cd $SPARK_HOME
$ ./bin/pyspark

```

如果命令执行正常，您应该在终端（Ubuntu）上观察到以下屏幕：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00375.jpeg)**图 1**：使用 PySpark shell 入门

现在您可以使用 Python 交互式 shell 来使用 Spark。这个 shell 可能足够用于实验和开发。但是，对于生产级别，您应该使用独立的应用程序。

PySpark 现在应该在系统路径中可用。编写 Python 代码后，可以简单地使用 Python 命令运行代码，然后它将在本地 Spark 实例中以默认配置运行：

```scala
$ python <python_file.py>

```

请注意，当前版本的 Spark 仅兼容 Python 2.7+。因此，我们将严格遵守这一点。

此外，如果您想在运行时传递配置值，最好使用`spark-submit`脚本。该命令与 Scala 的命令非常相似：

```scala
$ cd $SPARK_HOME
$ ./bin/spark-submit  --master local[*] <python_file.py>

```

配置值可以在运行时传递，或者可以在`conf/spark-defaults.conf`文件中进行更改。在配置 Spark 配置文件之后，运行 PySpark 应用程序时，这些更改也会反映出来，只需使用简单的 Python 命令。

然而，不幸的是，在撰写本文时，使用 PySpark 没有 pip 安装优势。但预计在 Spark 2.2.0 版本中将可用（有关更多信息，请参阅[`issues.apache.org/jira/browse/SPARK-1267`](https://issues.apache.org/jira/browse/SPARK-1267)）。为什么 PySpark 没有 pip 安装的原因可以在 JIRA 票证[`issues.apache.org/jira/browse/SPARK-1267`](https://issues.apache.org/jira/browse/SPARK-1267)中找到。

# 通过在 Python IDEs 上设置 PySpark

我们还可以在 Python IDEs（如 PyCharm）中配置和运行 PySpark。在本节中，我们将展示如何操作。如果您是学生，您可以在[`www.jetbrains.com/student/`](https://www.jetbrains.com/student/)上使用您的大学/学院/研究所电子邮件地址注册后获得 PyCharm 的免费许可副本。此外，PyCharm 还有一个社区（即免费）版本，因此您不需要是学生才能使用它。

最近，PySpark 已经发布了 Spark 2.2.0 PyPI（请参阅[`pypi.python.org/pypi/pyspark`](https://pypi.python.org/pypi/pyspark)）。这是一个漫长的过程（以前的版本包括 pip 可安装的构件，由于各种原因无法发布到 PyPI）。因此，如果您（或您的朋友）希望能够在笔记本电脑上本地使用 PySpark，您可以更容易地开始，只需执行以下命令：

```scala
$ sudo pip install pyspark # for python 2.7 
$ sudo pip3 install pyspark # for python 3.3+

```

然而，如果您使用的是 Windos 7、8 或 10，您应该手动安装 pyspark。例如，使用 PyCharm，您可以按照以下步骤操作：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00281.jpeg)**图 2**：在 Windows 10 上的 Pycharm IDE 上安装 PySpark

首先，您应该创建一个带有项目解释器的 Python 脚本，解释器为 Python 2.7+。然后，您可以按照以下方式导入 pyspark 以及其他所需的模块：

```scala
import os
import sys
import pyspark

```

现在，如果您是 Windows 用户，Python 还需要具有 Hadoop 运行时；您应该将`winutils.exe`文件放在`SPARK_HOME/bin`文件夹中。然后按以下方式创建环境变量：

选择您的 python 文件 | 运行 | 编辑配置 | 创建一个环境变量，其键为`HADOOP_HOME`，值为`PYTHON_PATH`，例如对于我的情况，它是`C:\Users\admin-karim\Downloads\spark-2.1.0-bin-hadoop2.7`。最后，按下 OK，然后您就完成了：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00110.jpeg)**图 3**：在 Windows 10 上的 Pycharm IDE 上设置 Hadoop 运行时环境

这就是您需要的全部。现在，如果您开始编写 Spark 代码，您应该首先将导入放在`try`块中，如下所示（仅供参考）：

```scala
try: 
    from pyspark.ml.featureimport PCA
    from pyspark.ml.linalgimport Vectors
    from pyspark.sqlimport SparkSession
    print ("Successfully imported Spark Modules")

```

`catch`块可以放在以下位置：

```scala
ExceptImportErroras e: 
    print("Can not import Spark Modules", e)
    sys.exit(1)

```

请参考以下图，显示在 PySpark shell 中导入和放置 Spark 包：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00256.jpeg)**图 4**：在 PySpark shell 中导入和放置 Spark 包

如果这些块成功执行，您应该在控制台上观察到以下消息：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00005.jpeg)**图 5**：PySpark 包已成功导入

# 开始使用 PySpark

在深入之前，首先我们需要看一下如何创建 Spark 会话。可以按照以下步骤完成：

```scala
spark = SparkSession\
         .builder\
         .appName("PCAExample")\
         .getOrCreate()

```

现在在这个代码块下，您应该放置您的代码，例如：

```scala
data = [(Vectors.sparse(5, [(1, 1.0), (3, 7.0)]),),
         (Vectors.dense([2.0, 0.0, 3.0, 4.0, 5.0]),),
         (Vectors.dense([4.0, 0.0, 0.0, 6.0, 7.0]),)]
 df = spark.createDataFrame(data, ["features"])

 pca = PCA(k=3, inputCol="features", outputCol="pcaFeatures")
 model = pca.fit(df)

 result = model.transform(df).select("pcaFeatures")
 result.show(truncate=False)

```

上述代码演示了如何在 RowMatrix 上计算主要成分，并将它们用于将向量投影到低维空间。为了更清晰地了解情况，请参考以下代码，该代码显示了如何在 PySpark 上使用 PCA 算法：

```scala
import os
import sys

try:
from pyspark.sql import SparkSession
from pyspark.ml.feature import PCA
from pyspark.ml.linalg import Vectors
print ("Successfully imported Spark Modules")

except ImportErrorase:
print ("Can not import Spark Modules", e)
 sys.exit(1)

spark = SparkSession\
   .builder\
   .appName("PCAExample")\
   .getOrCreate()

data = [(Vectors.sparse(5, [(1, 1.0), (3, 7.0)]),),
    (Vectors.dense([2.0, 0.0, 3.0, 4.0, 5.0]),),
    (Vectors.dense([4.0, 0.0, 0.0, 6.0, 7.0]),)]
df = spark.createDataFrame(data, ["features"])

pca = PCA(k=3, inputCol="features", outputCol="pcaFeatures")
model = pca.fit(df)

result = model.transform(df).select("pcaFeatures")
result.show(truncate=False)

spark.stop()

```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00188.jpeg)**图 6**：Python 脚本成功执行后的 PCA 结果

# 使用 DataFrames 和 RDDs

SparkDataFrame 是具有命名列的分布式行集合。从技术上讲，它可以被视为具有列标题的关系数据库中的表。此外，PySpark DataFrame 类似于 Python pandas。但是，它还与 RDD 共享一些相同的特征：

+   不可变：就像 RDD 一样，一旦创建了 DataFrame，就无法更改。在应用转换后，我们可以将 DataFrame 转换为 RDD，反之亦然。

+   **惰性评估**：其性质是惰性评估。换句话说，任务直到执行操作才会被执行。

+   分布式：RDD 和 DataFrame 都具有分布式特性。

与 Java/Scala 的 DataFrame 一样，PySpark DataFrame 专为处理大量结构化数据而设计；甚至可以处理 PB 级数据。表格结构帮助我们了解 DataFrame 的模式，这也有助于优化 SQL 查询的执行计划。此外，它具有广泛的数据格式和来源。

您可以使用 PySpark 以多种方式创建 RDD、数据集和 DataFrame。在接下来的小节中，我们将展示一些示例。

# 以 Libsvm 格式读取数据集

让我们看看如何使用读取 API 和`load()`方法以指定数据格式（即`libsvm`）来以 LIBSVM 格式读取数据：

```scala
# Creating DataFrame from libsvm dataset
 myDF = spark.read.format("libsvm").load("C:/Exp//mnist.bz2")

```

可以从[`www.csie.ntu.edu.tw/~cjlin/libsvmtools/datasets/multiclass/mnist.bz2`](https://www.csie.ntu.edu.tw/~cjlin/libsvmtools/datasets/multiclass/mnist.bz2)下载前述的 MNIST 数据集。这将返回一个 DataFrame，可以通过调用`show()`方法查看内容如下：

```scala
myDF.show() 

```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00068.gif)**图 7**：LIBSVM 格式手写数据集的快照

您还可以指定其他选项，例如原始数据集中要给 DataFrame 的特征数量如下：

```scala
myDF= spark.read.format("libsvm")
           .option("numFeatures", "780")
           .load("data/Letterdata_libsvm.data")

```

现在，如果您想从相同的数据集创建 RDD，可以使用`pyspark.mllib.util`中的 MLUtils API 如下：

```scala
*Creating RDD from the libsvm data file* myRDD = MLUtils.loadLibSVMFile(spark.sparkContext, "data/Letterdata_libsvm.data")

```

现在，您可以按以下方式将 RDD 保存在首选位置：

```scala
myRDD.saveAsTextFile("data/myRDD")

```

# 读取 CSV 文件

让我们从加载、解析和查看简单的航班数据开始。首先，从[`s3-us-west-2.amazonaws.com/sparkr-data/nycflights13.csv`](https://s3-us-west-2.amazonaws.com/sparkr-data/nycflights13.csv)下载 NYC 航班数据集作为 CSV。现在让我们使用 PySpark 的`read.csv()` API 加载和解析数据集：

```scala
# Creating DataFrame from data file in CSV formatdf = spark.read.format("com.databricks.spark.csv")
          .option("header", "true")
          .load("data/nycflights13.csv")

```

这与读取 libsvm 格式非常相似。现在您可以查看生成的 DataFrame 的结构如下：

```scala
df.printSchema() 

```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00338.gif)**图 8**：NYC 航班数据集的模式

现在让我们使用`show()`方法查看数据集的快照如下：

```scala
df.show() 

```

现在让我们查看数据的样本如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00370.gif)**图 9**：NYC 航班数据集的样本

# 读取和操作原始文本文件

您可以使用`textFile()`方法读取原始文本数据文件。假设您有一些购买的日志：

```scala
number\tproduct_name\ttransaction_id\twebsite\tprice\tdate0\tjeans\t30160906182001\tebay.com\t100\t12-02-20161\tcamera\t70151231120504\tamazon.com\t450\t09-08-20172\tlaptop\t90151231120504\tebay.ie\t1500\t07--5-20163\tbook\t80151231120506\tpackt.com\t45\t03-12-20164\tdrone\t8876531120508\talibaba.com\t120\t01-05-2017

```

现在，使用`textFile()`方法读取和创建 RDD 非常简单如下：

```scala
myRDD = spark.sparkContext.textFile("sample_raw_file.txt")
$cd myRDD
$ cat part-00000  
number\tproduct_name\ttransaction_id\twebsite\tprice\tdate  0\tjeans\t30160906182001\tebay.com\t100\t12-02-20161\tcamera\t70151231120504\tamazon.com\t450\t09-08-2017

```

如您所见，结构并不那么可读。因此，我们可以考虑通过将文本转换为 DataFrame 来提供更好的结构。首先，我们需要收集标题信息如下：

```scala
header = myRDD.first() 

```

现在过滤掉标题，并确保其余部分看起来正确如下：

```scala
textRDD = myRDD.filter(lambda line: line != header)
newRDD = textRDD.map(lambda k: k.split("\\t"))

```

我们仍然有 RDD，但数据结构稍微好一些。但是，将其转换为 DataFrame 将提供更好的事务数据视图。

以下代码通过指定`header.split`来创建 DataFrame，提供列的名称：

```scala
 textDF = newRDD.toDF(header.split("\\t"))
 textDF.show()

```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00208.gif)**图 10**：事务数据的样本

现在，您可以将此 DataFrame 保存为视图并进行 SQL 查询。现在让我们对此 DataFrame 进行查询：

```scala
textDF.createOrReplaceTempView("transactions")
spark.sql("SELECT *** FROM transactions").show()
spark.sql("SELECT product_name, price FROM transactions WHERE price >=500 ").show()
spark.sql("SELECT product_name, price FROM transactions ORDER BY price DESC").show()

```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00051.gif)**图 11**：使用 Spark SQL 对事务数据进行查询的结果

# 在 PySpark 上编写 UDF

与 Scala 和 Java 一样，您也可以在 PySpark 上使用**用户定义的函数**（也称为**UDF**）。让我们在下面看一个例子。假设我们想要根据一些在大学上课程的学生的分数来查看成绩分布。

我们可以将它们存储在两个单独的数组中，如下所示：

```scala
# Let's generate somerandom lists
 students = ['Jason', 'John', 'Geroge', 'David']
 courses = ['Math', 'Science', 'Geography', 'History', 'IT', 'Statistics']

```

现在让我们声明一个空数组，用于存储有关课程和学生的数据，以便稍后可以将两者都附加到此数组中，如下所示：

```scala
rawData = []
for (student, course) in itertools.product(students, courses):
    rawData.append((student, course, random.randint(0, 200)))

```

请注意，为了使前面的代码工作，请在文件开头导入以下内容：

```scala
import itertools
import random

```

现在让我们从这两个对象创建一个 DataFrame，以便将相应的成绩转换为每个成绩的分数。为此，我们需要定义一个显式模式。假设在您计划的 DataFrame 中，将有三列名为`Student`，`Course`和`Score`。

首先，让我们导入必要的模块：

```scala
from pyspark.sql.types
import StructType, StructField, IntegerType, StringType

```

现在模式可以定义如下：

```scala
schema = StructType([StructField("Student", StringType(), nullable=False),
                     StructField("Course", StringType(), nullable=False),
                     StructField("Score", IntegerType(), nullable=False)])

```

现在让我们从原始数据创建一个 RDD，如下所示：

```scala
courseRDD = spark.sparkContext.parallelize(rawData)

```

现在让我们将 RDD 转换为 DataFrame，如下所示：

```scala
courseDF = spark.createDataFrame(courseRDD, schema) 
coursedDF.show() 

```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00311.gif)**图 12**：随机生成的学科学生分数样本

好了，现在我们有了三列。但是，我们需要将分数转换为等级。假设您有以下分级模式：

+   *90~100=> A*

+   *80~89 => B*

+   *60~79 => C*

+   *0~59 => D*

为此，我们可以创建自己的 UDF，使其将数字分数转换为等级。可以用几种方法来做。以下是一个这样做的例子：

```scala
# Define udfdef scoreToCategory(grade):
 if grade >= 90:
 return 'A'
 elif grade >= 80:
 return 'B'
 elif grade >= 60:
 return 'C'
 else:
 return 'D'

```

现在我们可以有自己的 UDF 如下：

```scala
from pyspark.sql.functions
import udf
udfScoreToCategory = udf(scoreToCategory, StringType())

```

`udf()`方法中的第二个参数是方法的返回类型（即`scoreToCategory`）。现在您可以调用此 UDF 以一种非常直接的方式将分数转换为等级。让我们看一个例子：

```scala
courseDF.withColumn("Grade", udfScoreToCategory("Score")).show(100)

```

前一行将接受分数作为所有条目的输入，并将分数转换为等级。此外，将添加一个名为`Grade`的新 DataFrame 列。

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00354.gif)**图 13**：分配的成绩

现在我们也可以在 SQL 语句中使用 UDF。但是，为此，我们需要将此 UDF 注册如下：

```scala
spark.udf.register("udfScoreToCategory", scoreToCategory, StringType()) 

```

前一行将默认情况下在数据库中将 UDF 注册为临时函数。现在我们需要创建一个团队视图，以允许执行 SQL 查询：

```scala
courseDF.createOrReplaceTempView("score")

```

现在让我们对视图`score`执行 SQL 查询，如下所示：

```scala
spark.sql("SELECT Student, Score, udfScoreToCategory(Score) as Grade FROM score").show() 

```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00153.gif)**图 14**：关于学生分数和相应成绩的查询

此示例的完整源代码如下：

```scala
import os
import sys
import itertools
import random

from pyspark.sql import SparkSession
from pyspark.sql.types import StructType, StructField, IntegerType, StringType
from pyspark.sql.functions import udf

spark = SparkSession \
        .builder \
        .appName("PCAExample") \
        .getOrCreate()

# Generate Random RDD
students = ['Jason', 'John', 'Geroge', 'David']
courses = ['Math', 'Science', 'Geography', 'History', 'IT', 'Statistics']
rawData = []
for (student, course) in itertools.product(students, courses):
    rawData.append((student, course, random.randint(0, 200)))

# Create Schema Object
schema = StructType([
    StructField("Student", StringType(), nullable=False),
    StructField("Course", StringType(), nullable=False),
    StructField("Score", IntegerType(), nullable=False)
])

courseRDD = spark.sparkContext.parallelize(rawData)
courseDF = spark.createDataFrame(courseRDD, schema)
courseDF.show()

# Define udf
def scoreToCategory(grade):
    if grade >= 90:
        return 'A'
    elif grade >= 80:
        return 'B'
    elif grade >= 60:
        return 'C'
    else:
        return 'D'

udfScoreToCategory = udf(scoreToCategory, StringType())
courseDF.withColumn("Grade", udfScoreToCategory("Score")).show(100)

spark.udf.register("udfScoreToCategory", scoreToCategory, StringType())
courseDF.createOrReplaceTempView("score")
spark.sql("SELECT Student, Score, udfScoreToCategory(Score) as Grade FROM score").show()

spark.stop()

```

关于使用 UDF 的更详细讨论可以在[`jaceklaskowski.gitbooks.io/mastering-apache-spark/content/spark-sql-udfs.html`](https://jaceklaskowski.gitbooks.io/mastering-apache-spark/content/spark-sql-udfs.html)找到。

现在让我们在 PySpark 上进行一些分析任务。在下一节中，我们将展示使用 k-means 算法进行聚类任务的示例。

# 让我们使用 k-means 聚类进行一些分析

异常数据是指与正态分布不同寻常的数据。因此，检测异常是网络安全的重要任务，异常的数据包或请求可能被标记为错误或潜在攻击。

在此示例中，我们将使用 KDD-99 数据集（可以在此处下载：[`kdd.ics.uci.edu/databases/kddcup99/kddcup99.html`](http://kdd.ics.uci.edu/databases/kddcup99/kddcup99.html)）。将根据数据点的某些标准过滤出许多列。这将帮助我们理解示例。其次，对于无监督任务；我们将不得不删除标记的数据。让我们将数据集加载并解析为简单的文本。然后让我们看看数据集中有多少行：

```scala
INPUT = "C:/Users/rezkar/Downloads/kddcup.data" spark = SparkSession\
         .builder\
         .appName("PCAExample")\
         .getOrCreate()

 kddcup_data = spark.sparkContext.textFile(INPUT)

```

这本质上返回一个 RDD。让我们看看数据集中有多少行，使用`count()`方法如下所示：

```scala
count = kddcup_data.count()
print(count)>>4898431

```

所以，数据集非常大，具有许多特征。由于我们已将数据集解析为简单文本，因此不应期望看到数据集的更好结构。因此，让我们朝着将 RDD 转换为 DataFrame 的方向努力：

```scala
kdd = kddcup_data.map(lambda l: l.split(","))
from pyspark.sql import SQLContext
sqlContext = SQLContext(spark)
df = sqlContext.createDataFrame(kdd)

```

然后让我们看一下 DataFrame 中的一些选定列：

```scala
df.select("_1", "_2", "_3", "_4", "_42").show(5)

```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00080.gif)**图 15**：KKD 杯 99 数据集样本

因此，这个数据集已经被标记。这意味着恶意网络行为的类型已被分配到标签为最后一列（即`_42`）的行中。DataFrame 的前五行被标记为正常。这意味着这些数据点是正常的。现在是我们需要确定整个数据集中每种标签的计数的时候了：

```scala
#Identifying the labels for unsupervised tasklabels = kddcup_data.map(lambda line: line.strip().split(",")[-1])
from time import time
start_label_count = time()
label_counts = labels.countByValue()
label_count_time = time()-start_label_count

from collections import OrderedDict
sorted_labels = OrderedDict(sorted(label_counts.items(), key=lambda t: t[1], reverse=True))
for label, count in sorted_labels.items():
 print label, count

```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00134.gif)**图 16**：KDD 杯数据集中可用的标签（攻击类型）

我们可以看到有 23 个不同的标签（数据对象的行为）。大多数数据点属于 Smurf。这是一种异常行为，也称为 DoS 数据包洪水。Neptune 是第二高的异常行为。*正常*事件是数据集中第三种最常发生的事件类型。然而，在真实的网络数据集中，你不会看到任何这样的标签。

此外，正常流量将远远高于任何异常流量。因此，从大规模未标记的数据中识别异常攻击或异常将是费时的。为简单起见，让我们忽略最后一列（即标签），并认为这个数据集也是未标记的。在这种情况下，唯一可以概念化异常检测的方法是使用无监督学习算法，如 k-means 进行聚类。

现在让我们开始对数据点进行聚类。关于 K-means 的一个重要事项是，它只接受数值值进行建模。然而，我们的数据集还包含一些分类特征。现在我们可以根据它们是否为*TCP*，为分类特征分配二进制值 1 或 0。可以按如下方式完成：

```scala
from numpy import array
def parse_interaction(line):
     line_split = line.split(",")
     clean_line_split = [line_split[0]]+line_split[4:-1]
     return (line_split[-1], array([float(x) for x in clean_line_split]))

 parsed_data = kddcup_data.map(parse_interaction)
 pd_values = parsed_data.values().cache()

```

因此，我们的数据集几乎准备好了。现在我们可以准备我们的训练集和测试集，轻松地训练 k-means 模型：

```scala
 kdd_train = pd_values.sample(False, .75, 12345)
 kdd_test = pd_values.sample(False, .25, 12345)
 print("Training set feature count: " + str(kdd_train.count()))
 print("Test set feature count: " + str(kdd_test.count()))

```

输出如下：

```scala
Training set feature count: 3674823 Test set feature count: 1225499

```

然而，由于我们将一些分类特征转换为数值特征，因此还需要进行一些标准化。标准化可以提高优化过程中的收敛速度，还可以防止具有非常大方差的特征在模型训练过程中产生影响。

现在我们将使用 StandardScaler，这是一个特征转换器。它通过将特征缩放到单位方差来帮助我们标准化特征。然后使用训练集样本中的列汇总统计将均值设置为零：

```scala
standardizer = StandardScaler(True, True) 

```

现在让我们通过拟合前面的转换器来计算汇总统计信息：

```scala
standardizer_model = standardizer.fit(kdd_train) 

```

现在问题是，我们用于训练 k-means 的数据没有正态分布。因此，我们需要对训练集中的每个特征进行标准化，使其具有单位标准差。为实现这一点，我们需要进一步转换前面的标准化模型，如下所示：

```scala
data_for_cluster = standardizer_model.transform(kdd_train) 

```

干得好！现在训练集终于准备好训练 k-means 模型了。正如我们在聚类章节中讨论的那样，聚类算法中最棘手的事情是通过设置 K 的值找到最佳聚类数，使数据对象能够自动聚类。

一个天真的方法是采用蛮力法，设置`K=2`并观察结果，直到获得最佳结果。然而，一个更好的方法是肘部法，我们可以不断增加`K`的值，并计算**集合内平方误差和**（**WSSSE**）作为聚类成本。简而言之，我们将寻找最小化 WSSSE 的最佳`K`值。每当观察到急剧下降时，我们将知道最佳的`K`值：

```scala
import numpy
our_k = numpy.arange(10, 31, 10)
metrics = []
def computeError(point):
 center = clusters.centers[clusters.predict(point)]
 denseCenter = DenseVector(numpy.ndarray.tolist(center))
return sqrt(sum([x**2 for x in (DenseVector(point.toArray()) - denseCenter)]))
for k in our_k:
      clusters = KMeans.train(data_for_cluster, k, maxIterations=4, initializationMode="random")
      WSSSE = data_for_cluster.map(lambda point: computeError(point)).reduce(lambda x, y: x + y)
      results = (k, WSSSE)
 metrics.append(results)
print(metrics)

```

输出如下：

```scala
[(10, 3364364.5203123973), (20, 3047748.5040717563), (30, 2503185.5418753517)]

```

在这种情况下，30 是 k 的最佳值。让我们检查每个数据点的簇分配，当我们有 30 个簇时。下一个测试将是运行`k`值为 30、35 和 40。三个 k 值不是您在单次运行中测试的最多值，但仅用于此示例：

```scala
modelk30 = KMeans.train(data_for_cluster, 30, maxIterations=4, initializationMode="random")
 cluster_membership = data_for_cluster.map(lambda x: modelk30.predict(x))
 cluster_idx = cluster_membership.zipWithIndex()
 cluster_idx.take(20)
 print("Final centers: " + str(modelk30.clusterCenters))

```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00100.jpeg)**图 17：**每种攻击类型的最终簇中心（摘要）

现在让我们计算并打印整体聚类的总成本如下：

```scala
print("Total Cost: " + str(modelk30.computeCost(data_for_cluster)))

```

输出如下：

```scala
Total Cost: 68313502.459

```

最后，我们的 k 均值模型的 WSSSE 可以计算并打印如下：

```scala
WSSSE = data_for_cluster.map(lambda point: computeError
(point)).reduce(lambda x, y: x + y)
 print("WSSSE: " + str(WSSSE))

```

输出如下：

```scala
WSSSE: 2503185.54188

```

您的结果可能略有不同。这是由于在我们首次开始聚类算法时，质心的随机放置。多次执行可以让您看到数据中的点如何改变其 k 值或保持不变。此解决方案的完整源代码如下所示：

```scala
import os
import sys
import numpy as np
from collections import OrderedDict

try:
    from collections import OrderedDict
    from numpy import array
    from math import sqrt
    import numpy
    import urllib
    import pyspark
    from pyspark.sql import SparkSession
    from pyspark.mllib.feature import StandardScaler
    from pyspark.mllib.clustering import KMeans, KMeansModel
    from pyspark.mllib.linalg import DenseVector
    from pyspark.mllib.linalg import SparseVector
    from collections import OrderedDict
    from time import time
    from pyspark.sql.types import *
    from pyspark.sql import DataFrame
    from pyspark.sql import SQLContext
    from pyspark.sql import Row
    print("Successfully imported Spark Modules")

except ImportError as e:
    print ("Can not import Spark Modules", e)
    sys.exit(1)

spark = SparkSession\
        .builder\
        .appName("PCAExample")\
        .getOrCreate()

INPUT = "C:/Exp/kddcup.data.corrected"
kddcup_data = spark.sparkContext.textFile(INPUT)
count = kddcup_data.count()
print(count)
kddcup_data.take(5)
kdd = kddcup_data.map(lambda l: l.split(","))
sqlContext = SQLContext(spark)
df = sqlContext.createDataFrame(kdd)
df.select("_1", "_2", "_3", "_4", "_42").show(5)

#Identifying the leabels for unsupervised task
labels = kddcup_data.map(lambda line: line.strip().split(",")[-1])
start_label_count = time()
label_counts = labels.countByValue()
label_count_time = time()-start_label_count

sorted_labels = OrderedDict(sorted(label_counts.items(), key=lambda t: t[1], reverse=True))
for label, count in sorted_labels.items():
    print(label, count)

def parse_interaction(line):
    line_split = line.split(",")
    clean_line_split = [line_split[0]]+line_split[4:-1]
    return (line_split[-1], array([float(x) for x in clean_line_split]))

parsed_data = kddcup_data.map(parse_interaction)
pd_values = parsed_data.values().cache()

kdd_train = pd_values.sample(False, .75, 12345)
kdd_test = pd_values.sample(False, .25, 12345)
print("Training set feature count: " + str(kdd_train.count()))
print("Test set feature count: " + str(kdd_test.count()))

standardizer = StandardScaler(True, True)
standardizer_model = standardizer.fit(kdd_train)
data_for_cluster = standardizer_model.transform(kdd_train)

initializationMode="random"

our_k = numpy.arange(10, 31, 10)
metrics = []

def computeError(point):
    center = clusters.centers[clusters.predict(point)]
    denseCenter = DenseVector(numpy.ndarray.tolist(center))
    return sqrt(sum([x**2 for x in (DenseVector(point.toArray()) - denseCenter)]))

for k in our_k:
     clusters = KMeans.train(data_for_cluster, k, maxIterations=4, initializationMode="random")
     WSSSE = data_for_cluster.map(lambda point: computeError(point)).reduce(lambda x, y: x + y)
     results = (k, WSSSE)
     metrics.append(results)
print(metrics)

modelk30 = KMeans.train(data_for_cluster, 30, maxIterations=4, initializationMode="random")
cluster_membership = data_for_cluster.map(lambda x: modelk30.predict(x))
cluster_idx = cluster_membership.zipWithIndex()
cluster_idx.take(20)
print("Final centers: " + str(modelk30.clusterCenters))
print("Total Cost: " + str(modelk30.computeCost(data_for_cluster)))
WSSSE = data_for_cluster.map(lambda point: computeError(point)).reduce(lambda x, y: x + y)
print("WSSSE" + str(WSSSE))

```

有关此主题的更全面讨论，请参阅[`github.com/jadianes/kdd-cup-99-spark`](https://github.com/jadianes/kdd-cup-99-spark)。此外，感兴趣的读者可以参考 PySpark API 的主要和最新文档，网址为[`spark.apache.org/docs/latest/api/python/`](http://spark.apache.org/docs/latest/api/python/)。

现在是时候转向 SparkR，这是另一个与名为 R 的流行统计编程语言一起使用的 Spark API。

# SparkR 简介

R 是最流行的统计编程语言之一，具有许多令人兴奋的功能，支持统计计算、数据处理和机器学习任务。然而，在 R 中处理大规模数据集通常很繁琐，因为运行时是单线程的。因此，只有适合机器内存的数据集才能被处理。考虑到这一限制，并为了充分体验 R 中 Spark 的功能，SparkR 最初在 AMPLab 开发，作为 R 到 Apache Spark 的轻量级前端，并使用 Spark 的分布式计算引擎。

这样可以使 R 程序员从 RStudio 使用 Spark 进行大规模数据分析。在 Spark 2.1.0 中，SparkR 提供了一个支持选择、过滤和聚合等操作的分布式数据框实现。这与 R 数据框（如`dplyr`）有些类似，但可以扩展到大规模数据集。

# 为什么选择 SparkR？

您也可以使用 SparkR 编写支持 MLlib 的分布式机器学习的 Spark 代码。总之，SparkR 从与 Spark 紧密集成中继承了许多好处，包括以下内容：

+   **支持各种数据源 API**：SparkR 可以用于从各种来源读取数据，包括 Hive 表、JSON 文件、关系型数据库和 Parquet 文件。

+   数据框优化：SparkR 数据框也继承了计算引擎的所有优化，包括代码生成、内存管理等。从下图可以观察到，Spark 的优化引擎使得 SparkR 能够与 Scala 和 Python 竞争力十足：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00108.jpeg)**图 18：**SparkR 数据框与 Scala/Python 数据框

+   **可扩展性：**在 SparkR 数据框上执行的操作会自动分布到 Spark 集群上所有可用的核心和机器上。因此，SparkR 数据框可以用于大量数据，并在具有数千台机器的集群上运行。

# 安装和入门

使用 SparkR 的最佳方式是从 RStudio 开始。您可以使用 R shell、Rescript 或其他 R IDE 将您的 R 程序连接到 Spark 集群。

**选项 1.** 在环境中设置`SPARK_HOME`（您可以查看[`stat.ethz.ch/R-manual/R-devel/library/base/html/Sys.getenv.html`](https://stat.ethz.ch/R-manual/R-devel/library/base/html/Sys.getenv.html)），加载 SparkR 包，并调用`sparkR.session`如下。它将检查 Spark 安装，如果找不到，将自动下载和缓存：

```scala
if (nchar(Sys.getenv("SPARK_HOME")) < 1) { 
Sys.setenv(SPARK_HOME = "/home/spark") 
} 
library(SparkR, lib.loc = c(file.path(Sys.getenv("SPARK_HOME"), "R", "lib"))) 

```

**选项 2.** 您还可以在 RStudio 上手动配置 SparkR。为此，请在 R 脚本中执行以下 R 代码行：

```scala
SPARK_HOME = "spark-2.1.0-bin-hadoop2.7/R/lib" 
HADOOP_HOME= "spark-2.1.0-bin-hadoop2.7/bin" 
Sys.setenv(SPARK_MEM = "2g") 
Sys.setenv(SPARK_HOME = "spark-2.1.0-bin-hadoop2.7") 
.libPaths(c(file.path(Sys.getenv("SPARK_HOME"), "R", "lib"), .libPaths())) 

```

现在加载 SparkR 库如下：

```scala
library(SparkR, lib.loc = SPARK_HOME)

```

现在，就像 Scala/Java/PySpark 一样，您的 SparkR 程序的入口点是通过调用`sparkR.session`创建的 SparkR 会话，如下所示：

```scala
sparkR.session(appName = "Hello, Spark!", master = "local[*]")

```

此外，如果您愿意，还可以指定特定的 Spark 驱动程序属性。通常，这些应用程序属性和运行时环境无法以编程方式设置，因为驱动程序 JVM 进程已经启动；在这种情况下，SparkR 会为您处理这些设置。要设置它们，将它们传递给`sparkR.session()`的`sparkConfig`参数，如下所示：

```scala
sparkR.session(master = "local[*]", sparkConfig = list(spark.driver.memory = "2g")) 

```

此外，以下 Spark 驱动程序属性可以在 RStudio 中使用`sparkConfig`和`sparkR.session`进行设置：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00146.gif)**图 19**：可以在 RStudio 中使用`sparkConfig`和`sparkR.session`设置 Spark 驱动程序属性

# 入门

让我们从加载、解析和查看简单的航班数据开始。首先，从[`s3-us-west-2.amazonaws.com/sparkr-data/nycflights13.csv`](https://s3-us-west-2.amazonaws.com/sparkr-data/nycflights13.csv)下载 NY 航班数据集作为 CSV。现在让我们使用 R 的`read.csv()` API 加载和解析数据集：

```scala
#Creating R data frame
dataPath<- "C:/Exp/nycflights13.csv"
df<- read.csv(file = dataPath, header = T, sep =",")

```

现在让我们使用 R 的`View()`方法查看数据集的结构如下：

```scala
View(df)

```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00217.jpeg)**图 20**：NYC 航班数据集的快照

现在让我们从 R DataFrame 创建 Spark DataFrame 如下：

```scala
##Converting Spark DataFrame 
 flightDF<- as.DataFrame(df)

```

让我们通过探索 DataFrame 的模式来查看结构：

```scala
printSchema(flightDF)

```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00197.gif)**图 21**：NYC 航班数据集的模式

现在让我们看 DataFrame 的前 10 行：

```scala
showDF(flightDF, numRows = 10)

```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00222.gif)**图 22**：NYC 航班数据集的前 10 行

因此，您可以看到相同的结构。但是，这不可扩展，因为我们使用标准 R API 加载了 CSV 文件。为了使其更快速和可扩展，就像在 Scala 中一样，我们可以使用外部数据源 API。

# 使用外部数据源 API

如前所述，我们也可以使用外部数据源 API 来创建 DataFrame。在以下示例中，我们使用`com.databricks.spark.csv` API 如下：

```scala
flightDF<- read.df(dataPath,  
header='true',  
source = "com.databricks.spark.csv",  
inferSchema='true') 

```

让我们通过探索 DataFrame 的模式来查看结构：

```scala
printSchema(flightDF)

```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00132.gif)**图 23**：使用外部数据源 API 查看 NYC 航班数据集的相同模式

现在让我们看看 DataFrame 的前 10 行：

```scala
showDF(flightDF, numRows = 10)

```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00003.jpeg)**图 24**：使用外部数据源 API 的 NYC 航班数据集的相同样本数据

因此，您可以看到相同的结构。干得好！现在是时候探索更多内容了，比如使用 SparkR 进行数据操作。

# 数据操作

显示 SparkDataFrame 中的列名如下：

```scala
columns(flightDF)
[1] "year" "month" "day" "dep_time" "dep_delay" "arr_time" "arr_delay" "carrier" "tailnum" "flight" "origin" "dest" 
[13] "air_time" "distance" "hour" "minute" 

```

显示 SparkDataFrame 中的行数如下：

```scala
count(flightDF)
[1] 336776

```

过滤目的地仅为迈阿密的航班数据，并显示前六个条目如下：

```scala
 showDF(flightDF[flightDF$dest == "MIA", ], numRows = 10)

```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00285.jpeg)**图 25**：目的地仅为迈阿密的航班

选择特定列。例如，让我们选择所有前往爱荷华州的延误航班。还包括起飞机场名称：

```scala
delay_destination_DF<- select(flightDF, "flight", "dep_delay", "origin", "dest") 
 delay_IAH_DF<- filter(delay_destination_DF, delay_destination_DF$dest == "IAH") showDF(delay_IAH_DF, numRows = 10)

```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00269.gif)**图 26**：所有前往爱荷华州的延误航班

我们甚至可以使用它来链接数据框操作。举个例子，首先按日期分组航班，然后找到平均每日延误。最后，将结果写入 SparkDataFrame 如下：

```scala
install.packages(c("magrittr")) 
library(magrittr) 
groupBy(flightDF, flightDF$day) %>% summarize(avg(flightDF$dep_delay), avg(flightDF$arr_delay)) ->dailyDelayDF 

```

现在打印计算出的 DataFrame：

```scala
head(dailyDelayDF)

```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00300.gif)**图 27**：按日期分组航班，然后找到平均每日延误

让我们看另一个示例，对整个目的地机场的平均到达延误进行聚合：

```scala
avg_arr_delay<- collect(select(flightDF, avg(flightDF$arr_delay))) 
 head(avg_arr_delay)
avg(arr_delay)
 1 6.895377

```

还可以执行更复杂的聚合。例如，以下代码对每个目的地机场的平均、最大和最小延误进行了聚合。它还显示了降落在这些机场的航班数量：

```scala
flight_avg_arrival_delay_by_destination<- collect(agg( 
 groupBy(flightDF, "dest"), 
 NUM_FLIGHTS=n(flightDF$dest), 
 AVG_DELAY = avg(flightDF$arr_delay), 
 MAX_DELAY=max(flightDF$arr_delay), 
 MIN_DELAY=min(flightDF$arr_delay) 
 ))
head(flight_avg_arrival_delay_by_destination)

```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00290.gif)**图 28**：每个目的地机场的最大和最小延误

# 查询 SparkR DataFrame

与 Scala 类似，一旦将 DataFrame 保存为`TempView`，我们就可以对其执行 SQL 查询，使用`createOrReplaceTempView()`方法。让我们看一个例子。首先，让我们保存航班 DataFrame（即`flightDF`）如下：

```scala
# First, register the flights SparkDataFrame as a table
createOrReplaceTempView(flightDF, "flight")

```

现在让我们选择所有航班的目的地和目的地的承运人信息如下：

```scala
destDF<- sql("SELECT dest, origin, carrier FROM flight") 
 showDF(destDF, numRows=10)

```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00293.jpeg)**图 29**：所有航班的目的地和承运人信息

现在让我们使 SQL 复杂一些，比如找到所有至少延误 120 分钟的航班的目的地机场如下：

```scala
selected_flight_SQL<- sql("SELECT dest, origin, arr_delay FROM flight WHERE arr_delay>= 120")
showDF(selected_flight_SQL, numRows = 10)

```

前面的代码段查询并显示了所有至少延误 2 小时的航班的机场名称：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00302.jpeg)**图 30**：所有至少延误 2 小时的航班的目的地机场

现在让我们进行更复杂的查询。让我们找到所有飞往爱荷华的航班的起点，至少延误 2 小时。最后，按到达延误排序，并将计数限制为 20 如下：

```scala
selected_flight_SQL_complex<- sql("SELECT origin, dest, arr_delay FROM flight WHERE dest='IAH' AND arr_delay>= 120 ORDER BY arr_delay DESC LIMIT 20")
showDF(selected_flight_SQL_complex, numRows=20)

```

前面的代码段查询并显示了所有至少延误 2 小时到爱荷华的航班的机场名称：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00308.jpeg)**图 31**：所有航班的起点都至少延误 2 小时，目的地是爱荷华

# 在 RStudio 上可视化您的数据

在前一节中，我们已经看到了如何加载、解析、操作和查询 DataFrame。现在如果我们能够展示数据以便更好地看到就更好了。例如，对航空公司可以做些什么？我的意思是，是否可能从图表中找到最频繁的航空公司？让我们试试`ggplot2`。首先，加载相同的库：

```scala
library(ggplot2) 

```

现在我们已经有了 SparkDataFrame。如果我们直接尝试在`ggplot2`中使用我们的 SparkSQL DataFrame 类会怎么样？

```scala
my_plot<- ggplot(data=flightDF, aes(x=factor(carrier)))
>>
ERROR: ggplot2 doesn't know how to deal with data of class SparkDataFrame.

```

显然，这样是行不通的，因为`ggplot2`函数不知道如何处理这些类型的分布式数据框架（Spark 的数据框架）。相反，我们需要在本地收集数据并将其转换回传统的 R 数据框架如下：

```scala
flight_local_df<- collect(select(flightDF,"carrier"))

```

现在让我们使用`str()`方法查看我们得到了什么：

```scala
str(flight_local_df)

```

输出如下：

```scala
'data.frame':  336776 obs. of 1 variable: $ carrier: chr "UA" "UA" "AA" "B6" ...

```

这很好，因为当我们从 SparkSQL DataFrame 中收集结果时，我们得到一个常规的 R `data.frame`。这也非常方便，因为我们可以根据需要对其进行操作。现在我们准备创建`ggplot2`对象如下：

```scala
my_plot<- ggplot(data=flight_local_df, aes(x=factor(carrier)))

```

最后，让我们给图表一个适当的表示，作为条形图如下：

```scala
my_plot + geom_bar() + xlab("Carrier")

```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00314.jpeg)**图 32**：最频繁的航空公司是 UA、B6、EV 和 DL

从图表中可以清楚地看出，最频繁的航空公司是 UA、B6、EV 和 DL。这在 R 中的以下代码行中更清晰：

```scala
carrierDF = sql("SELECT carrier, COUNT(*) as cnt FROM flight GROUP BY carrier ORDER BY cnt DESC")
showDF(carrierDF)

```

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00317.gif)**图 33**：最频繁的航空公司是 UA、B6、EV 和 DL

前面分析的完整源代码如下，以了解代码的流程：

```scala
#Configure SparkR
SPARK_HOME = "C:/Users/rezkar/Downloads/spark-2.1.0-bin-hadoop2.7/R/lib"
HADOOP_HOME= "C:/Users/rezkar/Downloads/spark-2.1.0-bin-hadoop2.7/bin"
Sys.setenv(SPARK_MEM = "2g")
Sys.setenv(SPARK_HOME = "C:/Users/rezkar/Downloads/spark-2.1.0-bin-hadoop2.7")
.libPaths(c(file.path(Sys.getenv("SPARK_HOME"), "R", "lib"), .libPaths()))

#Load SparkR
library(SparkR, lib.loc = SPARK_HOME)

# Initialize SparkSession
sparkR.session(appName = "Example", master = "local[*]", sparkConfig = list(spark.driver.memory = "8g"))
# Point the data file path:
dataPath<- "C:/Exp/nycflights13.csv"

#Creating DataFrame using external data source API
flightDF<- read.df(dataPath,
header='true',
source = "com.databricks.spark.csv",
inferSchema='true')
printSchema(flightDF)
showDF(flightDF, numRows = 10)
# Using SQL to select columns of data

# First, register the flights SparkDataFrame as a table
createOrReplaceTempView(flightDF, "flight")
destDF<- sql("SELECT dest, origin, carrier FROM flight")
showDF(destDF, numRows=10)

#And then we can use SparkR sql function using condition as follows:
selected_flight_SQL<- sql("SELECT dest, origin, arr_delay FROM flight WHERE arr_delay>= 120")
showDF(selected_flight_SQL, numRows = 10)

#Bit complex query: Let's find the origins of all the flights that are at least 2 hours delayed where the destiantionn is Iowa. Finally, sort them by arrival delay and limit the count upto 20 and the destinations
selected_flight_SQL_complex<- sql("SELECT origin, dest, arr_delay FROM flight WHERE dest='IAH' AND arr_delay>= 120 ORDER BY arr_delay DESC LIMIT 20")
showDF(selected_flight_SQL_complex)

# Stop the SparkSession now
sparkR.session.stop()

```

# 摘要

在本章中，我们展示了如何在 Python 和 R 中编写您的 Spark 代码的一些示例。这些是数据科学家社区中最流行的编程语言。

我们讨论了使用 PySpark 和 SparkR 进行大数据分析的动机，几乎与 Java 和 Scala 同样简单。我们讨论了如何在流行的 IDE（如 PyCharm 和 RStudio）上安装这些 API。我们还展示了如何从这些 IDE 中使用 DataFrames 和 RDDs。此外，我们还讨论了如何从 PySpark 和 SparkR 中执行 Spark SQL 查询。然后，我们还讨论了如何对数据集进行可视化分析。最后，我们看到了如何使用 UDFs 来进行 PySpark 的示例。

因此，我们讨论了两个 Spark 的 API：PySpark 和 SparkR 的几个方面。还有更多内容可以探索。感兴趣的读者应该参考它们的网站获取更多信息。

+   PySpark: [`spark.apache.org/docs/latest/api/python/`](http://spark.apache.org/docs/latest/api/python/)

+   SparkR: [`spark.apache.org/docs/latest/sparkr.html﻿`](https://spark.apache.org/docs/latest/sparkr.html)


# 第二十章：使用 Alluxio 加速 Spark

“显而易见，我们的技术已经超出了我们的人性。”

- 阿尔伯特·爱因斯坦

在这里，您将学习如何使用 Alluxio 与 Spark 加速处理速度。Alluxio 是一个开源的分布式内存存储系统，可用于加速跨平台的许多应用程序的速度，包括 Apache Spark。

简而言之，本章将涵盖以下主题：

+   对 Alluxio 的需求

+   开始使用 Alluxio

+   与 YARN 集成

+   在 Spark 中使用 Alluxio

# 对 Alluxio 的需求

我们已经了解了 Apache Spark 以及围绕 Spark 核心、流式处理、GraphX、Spark SQL 和 Spark 机器学习的各种功能。我们还看了许多围绕数据操作和处理的用例和操作。任何处理任务中的关键步骤是数据输入、数据处理和数据输出。

这里显示了一个 Spark 作业的示例：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00323.jpeg)

如图所示，作业的输入和输出通常依赖于基于磁盘的较慢存储选项，而处理通常是使用内存/RAM 完成的。由于内存比磁盘访问快 100 倍，如果我们可以减少磁盘使用并更多地使用内存，作业的性能显然可以显著提高。在任何作业中，不需要甚至不可能完全不使用任何磁盘；相反，我们只是打算尽可能多地使用内存。

首先，我们可以尝试尽可能多地在内存中缓存数据，以加速使用执行器进行处理。虽然这对某些作业可能有效，但对于在运行 Spark 的分布式集群中运行的大型作业来说，不可能拥有如此多的 GB 或 TB 内存。此外，即使您的使用环境中有一个大型集群，也会有许多用户，因此很难为所有作业使用如此多的资源。

我们知道分布式存储系统，如 HDFS、S3 和 NFS。同样，如果我们有一个分布式内存系统，我们可以将其用作所有作业的存储系统，以减少作业或管道中的中间作业所需的 I/O。Alluxio 正是通过实现分布式内存文件系统来提供这一点，Spark 可以使用它来满足所有输入/输出需求。

# 开始使用 Alluxio

Alluxio，以前称为 Tachyon，统一了数据访问并桥接了计算框架和底层存储系统。Alluxio 的内存为中心的架构使得数据访问比现有解决方案快几个数量级。Alluxio 也与 Hadoop 兼容，因此可以无缝集成到现有基础设施中。现有的数据分析应用程序，如 Spark 和 MapReduce 程序，可以在 Alluxio 之上运行，而无需进行任何代码更改，这意味着过渡时间微不足道，而性能更好：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00326.jpeg)

# 下载 Alluxio

您可以通过在[`www.alluxio.org/download`](http://www.alluxio.org/download)网站上注册您的姓名和电子邮件地址来下载 Alluxio：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00207.jpeg)

或者，您也可以直接转到[`downloads.alluxio.org/downloads/files`](http://downloads.alluxio.org/downloads/files)并下载最新版本：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00216.jpeg)

# 安装和在本地运行 Alluxio

我们将在本地安装和运行 1.5.0。您可以使用任何其他版本进行相同操作。如果您下载了版本 1.5.0，您将看到一个名为`alluxio-1.5.0-hadoop2.7-bin.tar.gz`的文件。

使用 Alluxio 的先决条件是已安装 JDK 7 或更高版本。

解压下载的`alluxio-1.5.0-hadoop2.7-bin.tar.gz`文件：

```scala
tar -xvzf alluxio-1.5.0-hadoop2.7-bin.tar.gz
cd alluxio-1.5.0-hadoop-2.7

```

此外，如果在本地运行，Alluxio 将需要一个环境变量才能正确绑定到主机，因此运行以下命令：

```scala
export ALLUXIO_MASTER_HOSTNAME=localhost

```

使用`/bin/alluxio`命令格式化 Alluxio 文件系统。

只有在首次运行 Alluxio 时才需要此步骤，运行时，Alluxio 文件系统中以前存储的所有数据和元数据将被删除。

运行`/bin/alluxio`格式命令来格式化文件系统：

```scala
falcon:alluxio-1.5.0-hadoop-2.7 salla$ ./bin/alluxio format
Waiting for tasks to finish...
All tasks finished, please analyze the log at /Users/salla/alluxio-1.5.0-hadoop-2.7/bin/../logs/task.log.
Formatting Alluxio Master @ falcon

```

在本地启动 Alluxio 文件系统：

```scala
falcon:alluxio-1.5.0-hadoop-2.7 salla$ ./bin/alluxio-start.sh local
Waiting for tasks to finish...
All tasks finished, please analyze the log at /Users/salla/alluxio-1.5.0-hadoop-2.7/bin/../logs/task.log.
Waiting for tasks to finish...
All tasks finished, please analyze the log at /Users/salla/alluxio-1.5.0-hadoop-2.7/bin/../logs/task.log.
Killed 0 processes on falcon
Killed 0 processes on falcon
Starting master @ falcon. Logging to /Users/salla/alluxio-1.5.0-hadoop-2.7/logs
Formatting RamFS: ramdisk 2142792 sectors (1gb).
Started erase on disk2
Unmounting disk
Erasing
Initialized /dev/rdisk2 as a 1 GB case-insensitive HFS Plus volume
Mounting disk
Finished erase on disk2 ramdisk
Starting worker @ falcon. Logging to /Users/salla/alluxio-1.5.0-hadoop-2.7/logs
Starting proxy @ falcon. Logging to /Users/salla/alluxio-1.5.0-hadoop-2.7/logs

```

您可以使用类似的语法停止 Alluxio。

您可以通过在本地运行`./bin/alluxio-stop.sh`来停止 Alluxio。

通过使用`runTests`参数运行 Alluxio 脚本来验证 Alluxio 是否正在运行：

```scala
falcon:alluxio-1.5.0-hadoop-2.7 salla$ ./bin/alluxio runTests
2017-06-11 10:31:13,997 INFO type (MetricsSystem.java:startSinksFromConfig) - Starting sinks with config: {}.
2017-06-11 10:31:14,256 INFO type (AbstractClient.java:connect) - Alluxio client (version 1.5.0) is trying to connect with FileSystemMasterClient master @ localhost/127.0.0.1:19998
2017-06-11 10:31:14,280 INFO type (AbstractClient.java:connect) - Client registered with FileSystemMasterClient master @ localhost/127.0.0.1:19998
runTest Basic CACHE_PROMOTE MUST_CACHE
2017-06-11 10:31:14,585 INFO type (AbstractClient.java:connect) - Alluxio client (version 1.5.0) is trying to connect with BlockMasterClient master @ localhost/127.0.0.1:19998
2017-06-11 10:31:14,587 INFO type (AbstractClient.java:connect) - Client registered with BlockMasterClient master @ localhost/127.0.0.1:19998
2017-06-11 10:31:14,633 INFO type (ThriftClientPool.java:createNewResource) - Created a new thrift client alluxio.thrift.BlockWorkerClientService$Client@36b4cef0
2017-06-11 10:31:14,651 INFO type (ThriftClientPool.java:createNewResource) - Created a new thrift client alluxio.thrift.BlockWorkerClientService$Client@4eb7f003
2017-06-11 10:31:14,779 INFO type (BasicOperations.java:writeFile) - writeFile to file /default_tests_files/Basic_CACHE_PROMOTE_MUST_CACHE took 411 ms.
2017-06-11 10:31:14,852 INFO type (BasicOperations.java:readFile) - readFile file /default_tests_files/Basic_CACHE_PROMOTE_MUST_CACHE took 73 ms.
Passed the test!

```

有关其他选项和详细信息，请参阅[`www.alluxio.org/docs/master/en/Running-Alluxio-Locally.html`](http://www.alluxio.org/docs/master/en/Running-Alluxio-Locally.html)。

您还可以使用 Web UI 来查看 Alluxio 进程，方法是打开浏览器并输入`http://localhost:19999/`。

# 概述

概述选项卡显示摘要信息，例如主地址、运行的工作节点、版本和集群的正常运行时间。还显示了集群使用摘要，显示了工作节点的容量和文件系统 UnderFS 容量。然后，还可以看到存储使用摘要，显示了空间容量和已使用空间：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00219.jpeg)

# 浏览

浏览选项卡允许您查看内存文件系统的当前内容。此选项卡显示文件系统中的内容，文件的名称、大小和块大小，我们是否将数据加载到内存中，以及文件的 ACL 和权限，指定谁可以访问它并执行读写等操作。您将在浏览选项卡中看到 Alluxio 中管理的所有文件：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00225.jpeg)

# 配置

配置选项卡显示使用的所有配置参数。一些最重要的参数是使用的配置目录、主节点和工作节点的 CPU 资源和内存资源分配。还可以看到文件系统名称、路径、JDK 设置等。所有这些都可以被覆盖以定制 Alluxio 以适应您的用例。这里的任何更改也将需要重新启动集群。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00231.jpeg)

# 工作者

Workers 选项卡只是显示 Alluxio 集群中的工作节点。在我们的本地设置中，这只会显示本地机器，但在典型的许多工作节点的集群中，您将看到所有工作节点以及节点的状态，工作节点的容量，已使用的空间和最后接收到的心跳，这显示了工作节点是否存活并参与集群操作：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00234.jpeg)

# 内存数据

内存数据选项卡显示 Alluxio 文件系统内存中的当前数据。这显示了集群内存中的内容。内存中每个数据集显示的典型信息包括权限、所有权、创建和修改时间：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00243.jpeg)

# 日志

日志选项卡允许您查看各种日志文件，用于调试和监视目的。您将看到名为`master.log`的主节点的日志文件，名为`worker.log`的工作节点的日志文件，`task.log`，`proxy.log`以及用户日志。每个日志文件都会独立增长，并且在诊断问题或仅监视集群的健康状况方面非常有用：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00252.jpeg)

# 指标

指标选项卡显示有用的指标，用于监视 Alluxio 文件系统的当前状态。这里的主要信息包括主节点和文件系统容量。还显示了各种操作的计数器，例如文件创建和删除的逻辑操作，以及目录创建和删除。另一部分显示了 RPC 调用，您可以使用它来监视 CreateFile、DeleteFile 和 GetFileBlockInfo 等操作：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00255.jpeg)

# 当前功能

正如前面所看到的，Alluxio 提供了许多功能，以支持高速内存文件系统，显着加速 Spark 或许多其他计算系统。当前版本具有许多功能，以下是一些主要功能的描述：

+   **灵活的文件 API**提供了与 Hadoop 兼容的文件系统，允许 Hadoop MapReduce 和 Spark 使用 Alluxio。

+   **可插拔的底层存储**将内存中的数据检查点到底层存储系统，支持 Amazon S3、Google Cloud Storage、OpenStack Swift、HDFS 等。

+   **分层存储**可以管理 SSD 和 HDD，除了内存，还允许将更大的数据集存储在 Alluxio 中。

+   **统一命名空间**通过挂载功能在不同存储系统之间实现有效的数据管理。此外，透明命名确保在将这些对象持久化到底层存储系统时，Alluxio 中创建的对象的文件名和目录层次结构得以保留。

+   **血统**可以通过血统实现高吞吐量写入，而不会影响容错性，其中丢失的输出通过重新执行创建输出的作业来恢复，就像 Apache Spark 中的 DAG 一样。

+   **Web UI 和命令行**允许用户通过 Web UI 轻松浏览文件系统。在调试模式下，管理员可以查看每个文件的详细信息，包括位置和检查点路径。用户还可以使用`./bin/alluxio fs`与 Alluxio 进行交互，例如，复制数据进出文件系统。

有关最新功能和更多最新信息，请参阅[`www.alluxio.org/`](http://www.alluxio.org/)。

这已经足够让 Alluxio 在本地启动了。接下来，我们将看到如何与集群管理器（如 YARN）集成。

# 与 YARN 集成

YARN 是最常用的集群管理器之一，其次是 Mesos。如果您还记得第五章中的内容，*处理大数据 - Spark 加入派对*，YARN 可以管理 Hadoop 集群的资源，并允许数百个应用程序共享集群资源。我们可以使用 YARN 和 Spark 集成来运行长时间运行的 Spark 作业，以处理实时信用卡交易，例如。

但是，不建议尝试将 Alluxio 作为 YARN 应用程序运行；相反，应该将 Alluxio 作为独立集群与 YARN 一起运行。Alluxio 应该与 YARN 一起运行，以便所有 YARN 节点都可以访问本地的 Alluxio worker。为了使 YARN 和 Alluxio 共存，我们必须通知 YARN 有关 Alluxio 使用的资源。例如，YARN 需要知道为 Alluxio 留下多少内存和 CPU。

# Alluxio worker 内存

Alluxio worker 需要一些内存用于其 JVM 进程和一些内存用于其 RAM 磁盘；通常 1GB 对于 JVM 内存来说是足够的，因为这些内存仅用于缓冲和元数据。

RAM 磁盘内存可以通过设置`alluxio.worker.memory.size`进行配置。

存储在非内存层中的数据，如 SSD 或 HDD，不需要包括在内存大小计算中。

# Alluxio master 内存

Alluxio master 存储有关 Alluxio 中每个文件的元数据，因此对于更大的集群部署，它应该至少为 1GB，最多为 32GB。

# CPU vcores

每个 Alluxio worker 至少应该有一个 vcore，生产部署中 Alluxio master 可以使用至少一个到四个 vcores。

要通知 YARN 在每个节点上为 Alluxio 保留的资源，请修改`yarn-site.xml`中的 YARN 配置参数。

将`yarn.nodemanager.resource.memory-mb`更改为为 Alluxio worker 保留一些内存。

确定在节点上为 Alluxio 分配多少内存后，从`yarn.nodemanager.resource.memory-mb`中减去这个值，并使用新值更新参数。

将`yarn.nodemanager.resource.cpu-vcores`更改为为 Alluxio worker 保留 CPU vcores。

确定在节点上为 Alluxio 分配多少内存后，从`yarn.nodemanager.resource.cpu-vcores`中减去这个值，并使用新值更新参数。

更新 YARN 配置后，重新启动 YARN 以使其应用更改。

# 使用 Alluxio 与 Spark

为了在 Spark 中使用 Alluxio，您将需要一些依赖的 JAR 文件。这是为了使 Spark 能够连接到 Alluxio 文件系统并读取/写入数据。一旦我们启动具有 Alluxio 集成的 Spark，大部分 Spark 代码仍然保持完全相同，只有代码的读取和写入部分发生了变化，因为现在您必须使用`alluxio://`来表示 Alluxio 文件系统。

然而，一旦设置了 Alluxio 集群，Spark 作业（执行器）将连接到 Alluxio 主服务器以获取元数据，并连接到 Alluxio 工作节点进行实际数据读取/写入操作。

这里显示了从 Spark 作业中使用的 Alluxio 集群的示例： 

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00261.jpeg)

以下是如何使用 Alluxio 启动 Spark-shell 并运行一些代码的步骤：

**第 1 步**，将目录更改为提取 Spark 的目录：

```scala
 cd spark-2.2.0-bin-hadoop2.7

```

**第 2 步**，将 JAR 文件从 Alluxio 复制到 Spark：

```scala
cp ../alluxio-1.5.0-hadoop-2.7/core/common/target/alluxio-core-common-1.5.0.jar .
cp ../alluxio-1.5.0-hadoop-2.7/core/client/hdfs/target/alluxio-core-client-hdfs-1.5.0.jar .
cp ../alluxio-1.5.0-hadoop-2.7/core/client/fs/target/alluxio-core-client-fs-1.5.0.jar .
cp ../alluxio-1.5.0-hadoop-2.7/core/protobuf/target/alluxio-core-protobuf-1.5.0.jar . 

```

**第 3 步**，使用 Alluxio JAR 文件启动 Spark-shell：

```scala
./bin/spark-shell --master local[2] --jars alluxio-core-common-1.5.0.jar,alluxio-core-client-fs-1.5.0.jar,alluxio-core-client-hdfs-1.5.0.jar,alluxio-otobuf-1.5.0.jar

```

第 4 步，将样本数据集复制到 Alluxio 文件系统中：

```scala
$ ./bin/alluxio fs copyFromLocal ../spark-2.1.1-bin-hadoop2.7/Sentiment_Analysis_Dataset10k.csv /Sentiment_Analysis_Dataset10k.csv
Copied ../spark-2.1.1-bin-hadoop2.7/Sentiment_Analysis_Dataset10k.csv to /Sentiment_Analysis_Dataset10k.csv

```

您可以使用浏览选项卡在 Alluxio 中验证文件；它是大小为 801.29KB 的 Sentiment_Analysis_Dataset10k.csv 文件：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00053.jpeg)

第 4 步。访问带有和不带有 Alluxio 的文件。

首先，在 shell 中设置 Alluxio 文件系统配置：

```scala
scala> sc.hadoopConfiguration.set("fs.alluxio.impl", "alluxio.hadoop.FileSystem")

```

从 Alluxio 加载文本文件：

```scala
scala> val alluxioFile = sc.textFile("alluxio://localhost:19998/Sentiment_Analysis_Dataset10k.csv")
alluxioFile: org.apache.spark.rdd.RDD[String] = alluxio://localhost:19998/Sentiment_Analysis_Dataset10k.csv MapPartitionsRDD[39] at textFile at <console>:24

scala> alluxioFile.count
res24: Long = 9999

```

从本地文件系统加载相同的文本文件：

```scala
scala> val localFile = sc.textFile("Sentiment_Analysis_Dataset10k.csv")
localFile: org.apache.spark.rdd.RDD[String] = Sentiment_Analysis_Dataset10k.csv MapPartitionsRDD[41] at textFile at <console>:24

scala> localFile.count
res23: Long = 9999

```

如果您可以加载大量数据到 Alluxio 中，Alluxio 集成将提供更高的性能，而无需缓存数据。这带来了几个优势，包括消除了每个使用 Spark 集群的用户缓存大型数据集的需要。

# 摘要

在本附录中，我们探讨了使用 Alluxio 作为加速 Spark 应用程序的一种方式，利用了 Alluxio 的内存文件系统功能。这带来了几个优势，包括消除了每个使用 Spark 集群的用户缓存大型数据集的需要。

在下一个附录中，我们将探讨如何使用 Apache Zeppelin，一个基于 Web 的笔记本，进行交互式数据分析。


# 第二十一章：使用 Apache Zeppelin 进行交互式数据分析

从数据科学的角度来看，交互式可视化数据分析也很重要。Apache Zeppelin 是一个基于 Web 的笔记本，用于交互式和大规模数据分析，具有多个后端和解释器，如 Spark、Scala、Python、JDBC、Flink、Hive、Angular、Livy、Alluxio、PostgreSQL、Ignite、Lens、Cassandra、Kylin、Elasticsearch、JDBC、HBase、BigQuery、Pig、Markdown、Shell 等等。

毫无疑问，Spark 有能力以可扩展和快速的方式处理大规模数据集。但是，Spark 中缺少一件事--它没有实时或交互式的可视化支持。考虑到 Zeppelin 的上述令人兴奋的功能，在本章中，我们将讨论如何使用 Apache Zeppelin 进行大规模数据分析，使用 Spark 作为后端的解释器。总之，将涵盖以下主题：

+   Apache Zeppelin 简介

+   安装和入门

+   数据摄入

+   数据分析

+   数据可视化

+   数据协作

# Apache Zeppelin 简介

Apache Zeppelin 是一个基于 Web 的笔记本，可以让您以交互方式进行数据分析。使用 Zeppelin，您可以使用 SQL、Scala 等制作美丽的数据驱动、交互式和协作文档。Apache Zeppelin 解释器概念允许将任何语言/数据处理后端插入 Zeppelin。目前，Apache Zeppelin 支持许多解释器，如 Apache Spark、Python、JDBC、Markdown 和 Shell。Apache Zeppelin 是 Apache 软件基金会的一个相对较新的技术，它使数据科学家、工程师和从业者能够利用数据探索、可视化、共享和协作功能。

# 安装和入门

由于使用其他解释器不是本书的目标，而是在 Zeppelin 上使用 Spark，所有代码都将使用 Scala 编写。因此，在本节中，我们将展示如何使用仅包含 Spark 解释器的二进制包配置 Zeppelin。Apache Zeppelin 官方支持并在以下环境上进行了测试：

| **要求** | **值/版本** | **其他要求** |
| --- | --- | --- |
| Oracle JDK | 1.7 或更高版本 | 设置`JAVA_HOME` |

| 操作系统 | macOS 10.X+ Ubuntu 14.X+

CentOS 6.X+

Windows 7 Pro SP1+ | - |

# 安装和配置

如前表所示，要在 Zeppelin 上执行 Spark 代码，需要 Java。因此，如果尚未设置，请在上述任何平台上安装和设置 Java。或者，您可以参考第一章，*Scala 简介*，了解如何在计算机上设置 Java。

可以从[`zeppelin.apache.org/download.html`](https://zeppelin.apache.org/download.html)下载最新版本的 Apache Zeppelin。每个版本都有三个选项：

1.  **带有所有解释器的二进制包**：它包含对许多解释器的支持。例如，Spark、JDBC、Pig、Beam、Scio、BigQuery、Python、Livy、HDFS、Alluxio、Hbase、Scalding、Elasticsearch、Angular、Markdown、Shell、Flink、Hive、Tajo、Cassandra、Geode、Ignite、Kylin、Lens、Phoenix 和 PostgreSQL 目前在 Zeppelin 中得到支持。

1.  **带有 Spark 解释器的二进制包**：通常只包含 Spark 解释器。它还包含解释器的网络安装脚本。

1.  **源代码**：您还可以从 GitHub 存储库构建 Zeppelin（更多内容将在后续介绍）。

为了展示如何安装和配置 Zeppelin，我们从以下站点镜像下载了二进制包：

[`www.apache.org/dyn/closer.cgi/zeppelin/zeppelin-0.7.1/zeppelin-0.7.1-bin-netinst.tgz`](http://www.apache.org/dyn/closer.cgi/zeppelin/zeppelin-0.7.1/zeppelin-0.7.1-bin-netinst.tgz)

下载后，在计算机上的某个位置解压缩它。假设您解压缩文件的路径是`/home/Zeppelin/`。

# 从源代码构建

您还可以从 GitHub 存储库中构建所有最新更改的 Zeppelin。如果要从源代码构建，必须首先安装以下工具：

+   Git：任何版本

+   Maven：3.1.x 或更高版本

+   JDK：1.7 或更高版本

+   npm：最新版本

+   libfontconfig：最新版本

如果您尚未安装 Git 和 Maven，请从[`zeppelin.apache.org/docs/0.8.0-SNAPSHOT/install/build.html#build-requirements`](http://zeppelin.apache.org/docs/0.8.0-SNAPSHOT/install/build.html#build-requirements)检查构建要求说明。但是，由于页面限制，我们没有详细讨论所有步骤。如果您感兴趣，可以参考此 URL 获取更多详细信息：[`zeppelin.apache.org/docs/snapshot/install/build.html`](http://zeppelin.apache.org/docs/snapshot/install/build.html)。

# 启动和停止 Apache Zeppelin

在所有类 Unix 平台（例如 Ubuntu、macOS 等）上，使用以下命令：

```scala
$ bin/zeppelin-daemon.sh start

```

如果前面的命令成功执行，您应该在终端上看到以下日志：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00061.jpeg)**图 1**：从 Ubuntu 终端启动 Zeppelin

如果您使用 Windows，使用以下命令：

```scala
$ bin\zeppelin.cmd

```

Zeppelin 成功启动后，使用您的网络浏览器转到`http://localhost:8080`，您将看到 Zeppelin 正在运行。更具体地说，您将在浏览器上看到以下视图：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00069.jpeg)**图 2**：Zeppelin 正在 http://localhost:8080 上运行

恭喜！您已成功安装了 Apache Zeppelin！现在，让我们继续使用 Zeppelin，并在配置了首选解释器后开始我们的数据分析。

现在，要从命令行停止 Zeppelin，请发出以下命令：

```scala
$ bin/zeppelin-daemon.sh stop

```

# 创建笔记本

一旦您在`http://localhost:8080/`上，您可以探索不同的选项和菜单，以帮助您了解如何熟悉 Zeppelin。您可以在[`zeppelin.apache.org/docs/0.7.1/quickstart/explorezeppelinui.html`](https://zeppelin.apache.org/docs/0.7.1/quickstart/explorezeppelinui.html)上找到更多关于 Zeppelin 及其用户友好的 UI 的信息（您也可以根据可用版本参考最新的快速入门文档）。

现在，让我们首先创建一个示例笔记本并开始。如下图所示，您可以通过单击“创建新笔记”选项来创建一个新的笔记本：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00082.jpeg)**图 3**：创建一个示例 Zeppelin 笔记本

如前图所示，默认解释器选择为 Spark。在下拉列表中，您还将只看到 Spark，因为我们已经为 Zeppelin 下载了仅包含 Spark 的二进制包。

# 配置解释器

每个解释器都属于一个解释器组。解释器组是启动/停止解释器的单位。默认情况下，每个解释器属于一个单一组，但该组可能包含更多的解释器。例如，Spark 解释器组包括 Spark 支持、pySpark、Spark SQL 和依赖项加载器。如果您想在 Zeppelin 上执行 SQL 语句，应该使用`%`符号指定解释器类型；例如，要使用 SQL，应该使用`%sql`；要使用标记，使用`%md`，依此类推。

有关更多信息，请参考以下图片：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00086.jpeg)**图 4**：在 Zeppelin 上使用 Spark 的解释器属性数据摄入

好了，一旦您创建了笔记本，就可以直接在代码部分编写 Spark 代码。对于这个简单的例子，我们将使用银行数据集，该数据集可供研究使用，并可从[`archive.ics.uci.edu/ml/machine-learning-databases/00222/`](https://archive.ics.uci.edu/ml/machine-learning-databases/00222/)下载，由 S. Moro、R. Laureano 和 P. Cortez 提供，使用数据挖掘进行银行直接营销：CRISP-DM 方法的应用。数据集包含诸如年龄、职业头衔、婚姻状况、教育、是否为违约者、银行余额、住房、是否从银行借款等客户的信息，以 CSV 格式提供。以下是数据集的样本：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00094.jpeg)**图 5**：银行数据集样本

现在，让我们首先在 Zeppelin 笔记本上加载数据：

```scala
valbankText = sc.textFile("/home/asif/bank/bank-full.csv")

```

执行此代码行后，创建一个新的段落，并将其命名为数据摄入段落：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00098.jpeg)**图 6**：数据摄入段落

如果您仔细观察前面的图像，代码已经运行，我们不需要定义 Spark 上下文。原因是它已经在那里定义为`sc`。甚至不需要隐式定义 Scala。稍后我们将看到一个例子。

# 数据处理和可视化

现在，让我们创建一个案例类，告诉我们如何从数据集中选择所需的字段：

```scala
case class Bank(age:Int, job:String, marital : String, education : String, balance : Integer)

```

现在，将每行拆分，过滤掉标题（以`age`开头），并将其映射到`Bank`案例类中，如下所示：

```scala
val bank = bankText.map(s=>s.split(";")).filter(s => (s.size)>5).filter(s=>s(0)!="\"age\"").map( 
  s=>Bank(s(0).toInt,  
  s(1).replaceAll("\"", ""), 
  s(2).replaceAll("\"", ""), 
  s(3).replaceAll("\"", ""), 
  s(5).replaceAll("\"", "").toInt 
        ) 
) 

```

最后，转换为 DataFrame 并创建临时表：

```scala
bank.toDF().createOrReplaceTempView("bank")

```

以下截图显示所有代码片段都成功执行，没有显示任何错误：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00102.jpeg)**图 7**：数据处理段落

为了更加透明，让我们在代码执行后查看标记为绿色的状态（在图像右上角），如下所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00114.jpeg)**图 8**：每个段落中 Spark 代码的成功执行

现在让我们加载一些数据，以便使用以下 SQL 命令进行操作：

```scala
%sql select age, count(1) from bank where age >= 45 group by age order by age

```

请注意，上述代码行是一个纯 SQL 语句，用于选择年龄大于或等于 45 岁的所有客户的姓名（即年龄分布）。最后，它计算了同一客户组的数量。

现在让我们看看前面的 SQL 语句在临时视图（即`bank`）上是如何工作的：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00126.jpeg)**图 9**：选择所有年龄分布的客户姓名的 SQL 查询[表格]

现在您可以从结果部分附近的选项卡中选择图形选项，例如直方图、饼图、条形图等。例如，使用直方图，您可以看到`年龄组>=45`的相应计数。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00092.jpeg)**图 10**：选择所有年龄分布的客户姓名的 SQL 查询[直方图]

这是使用饼图的效果：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00328.jpeg)**图 11**：选择所有年龄分布的客户姓名的 SQL 查询[饼图]

太棒了！现在我们几乎可以使用 Zeppelin 进行更复杂的数据分析问题了。

# 使用 Zeppelin 进行复杂数据分析

在本节中，我们将看到如何使用 Zeppelin 执行更复杂的分析。首先，我们将明确问题，然后将探索将要使用的数据集。最后，我们将应用一些可视化分析和机器学习技术。

# 问题定义

在本节中，我们将构建一个垃圾邮件分类器，用于将原始文本分类为垃圾邮件或正常邮件。我们还将展示如何评估这样的模型。我们将尝试专注于使用和处理 DataFrame API。最终，垃圾邮件分类器模型将帮助您区分垃圾邮件和正常邮件。以下图像显示了两条消息的概念视图（分别为垃圾邮件和正常邮件）：

![](https://blog.codecentric.de/files/2016/06/ham-vs-spam.png)**图 12**：垃圾邮件和正常邮件示例

我们使用一些基本的机器学习技术来构建和评估这种类型问题的分类器。具体来说，逻辑回归算法将用于解决这个问题。

# 数据集描述和探索

我们从[`archive.ics.uci.edu/ml/datasets/SMS+Spam+Collection`](https://archive.ics.uci.edu/ml/datasets/SMS+Spam+Collection)下载的垃圾数据集包含 5,564 条短信，已经被手动分类为正常或垃圾。这些短信中只有 13.4%是垃圾短信。这意味着数据集存在偏斜，并且只提供了少量垃圾短信的示例。这是需要记住的一点，因为它可能在训练模型时引入偏差：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00336.jpeg)**图 13**：短信数据集的快照

那么，这些数据是什么样子的呢？您可能已经看到，社交媒体文本可能会非常肮脏，包含俚语、拼写错误、缺少空格、缩写词，比如*u*、*urs*、*yrs*等等，通常违反语法规则。有时甚至包含消息中的琐碎词语。因此，我们需要处理这些问题。在接下来的步骤中，我们将遇到这些问题，以更好地解释分析结果。

第 1 步。在 Zeppelin 上加载所需的包和 API - 让我们加载所需的包和 API，并在 Zeppelin 上创建第一个段落，然后再将数据集导入：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00345.jpeg)**图 14**：包/ API 加载段落

第 2 步。加载和解析数据集 - 我们将使用 Databricks 的 CSV 解析库（即`com.databricks.spark.csv`）将数据读入 DataFrame：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00351.jpeg)**图 15**：数据摄取/加载段落

第 3 步。使用`StringIndexer`创建数字标签 - 由于原始 DataFrame 中的标签是分类的，我们需要将它们转换回来，以便在机器学习模型中使用：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00357.jpeg)**图 16**：StringIndexer 段落，输出显示原始标签、原始文本和相应标签。

第 4 步。使用`RegexTokenizer`创建词袋 - 我们将使用`RegexTokenizer`去除不需要的单词并创建一个词袋：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00363.jpeg)**图 17**：RegexTokenizer 段落，输出显示原始标签、原始文本、相应标签和标记

第 5 步。删除停用词并创建一个经过筛选的 DataFrame - 我们将删除停用词并创建一个经过筛选的 DataFrame 以进行可视化分析。最后，我们展示 DataFrame：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00329.jpeg)**图 18**：StopWordsRemover 段落，输出显示原始标签、原始文本、相应标签、标记和去除停用词的筛选标记

第 6 步。查找垃圾消息/单词及其频率 - 让我们尝试创建一个仅包含垃圾单词及其相应频率的 DataFrame，以了解数据集中消息的上下文。我们可以在 Zeppelin 上创建一个段落：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00349.jpeg)**图 19**：带有频率段落的垃圾邮件标记

现在，让我们通过 SQL 查询在图表中查看它们。以下查询选择所有频率超过 100 的标记。然后，我们按照它们的频率降序排序标记。最后，我们使用动态表单来限制记录的数量。第一个是原始表格格式：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00128.jpeg)**图 20**：带有频率可视化段落的垃圾邮件标记[表格]

然后，我们将使用条形图，这提供了更多的视觉洞察。现在我们可以看到，垃圾短信中最频繁出现的单词是 call 和 free，分别出现了 355 次和 224 次：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00096.jpeg)**图 21**：带有频率可视化段落的垃圾邮件标记[直方图]

最后，使用饼图提供了更好更广泛的可见性，特别是如果您指定了列范围：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00145.jpeg)**图 22**：带有频率可视化段落的垃圾邮件标记[饼图]

第 7 步。使用 HashingTF 进行词频- 使用`HashingTF`生成每个过滤标记的词频，如下所示：

图 23：HashingTF 段落，输出显示原始标签、原始文本、相应标签、标记、过滤后的标记和每行的相应词频

第 8 步。使用 IDF 进行词频-逆文档频率（TF-IDF）- TF-IDF 是一种在文本挖掘中广泛使用的特征向量化方法，用于反映术语对语料库中文档的重要性：

图 24：IDF 段落，输出显示原始标签、原始文本、相应标签、标记、过滤后的标记、词频和每行的相应 IDF

词袋：词袋为句子中每个单词的出现赋予值`1`。这可能不是理想的，因为句子的每个类别很可能具有相同的*the*、*and*等词的频率；而*viagra*和*sale*等词可能在确定文本是否为垃圾邮件方面应该具有更高的重要性。

TF-IDF：这是文本频率-逆文档频率的缩写。这个术语本质上是每个词的文本频率和逆文档频率的乘积。这在 NLP 或文本分析中的词袋方法中常用。

使用 TF-IDF：让我们来看看词频。在这里，我们考虑单个条目中单词的频率，即术语。计算文本频率（TF）的目的是找到在每个条目中似乎重要的术语。然而，诸如“the”和“and”之类的词在每个条目中可能出现得非常频繁。我们希望降低这些词的重要性，因此我们可以想象将前述 TF 乘以整个文档频率的倒数可能有助于找到重要的词。然而，由于文本集合（语料库）可能相当大，通常会取逆文档频率的对数。简而言之，我们可以想象 TF-IDF 的高值可能表示对确定文档内容非常重要的词。创建 TF-IDF 向量需要我们将所有文本加载到内存中，并在开始训练模型之前计算每个单词的出现次数。

第 9 步。使用 VectorAssembler 生成 Spark ML 管道的原始特征- 正如您在上一步中看到的，我们只有过滤后的标记、标签、TF 和 IDF。然而，没有任何可以输入任何 ML 模型的相关特征。因此，我们需要使用 Spark VectorAssembler API 根据前一个 DataFrame 中的属性创建特征，如下所示：

图 25：VectorAssembler 段落，显示使用 VectorAssembler 进行特征创建

第 10 步。准备训练和测试集- 现在我们需要准备训练和测试集。训练集将用于在第 11 步中训练逻辑回归模型，测试集将用于在第 12 步中评估模型。在这里，我将其设置为 75%用于训练，25%用于测试。您可以根据需要进行调整：

图 26：准备训练/测试集段落

第 11 步。训练二元逻辑回归模型- 由于问题本身是一个二元分类问题，我们可以使用二元逻辑回归分类器，如下所示：

图 27：LogisticRegression 段落，显示如何使用必要的标签、特征、回归参数、弹性网参数和最大迭代次数训练逻辑回归分类器

请注意，为了获得更好的结果，我们已经迭代了 200 次的训练。我们已经将回归参数和弹性网参数设置得非常低-即 0.0001，以使训练更加密集。

**步骤 12. 模型评估** - 让我们计算测试集的原始预测。然后，我们使用二元分类器评估器来实例化原始预测，如下所示：

**![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00335.jpeg)****图 28**: 模型评估段落

现在让我们计算模型在测试集上的准确性，如下所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00346.jpeg)**图 29**: 准确性计算段落

这相当令人印象深刻。然而，如果您选择使用交叉验证进行模型调优，例如，您可能会获得更高的准确性。最后，我们将计算混淆矩阵以获得更多见解：

图 30: 混淆段落显示了正确和错误预测的数量，以计数值总结，并按每个类别进行了分解

# 数据和结果协作

此外，Apache Zeppelin 提供了一个功能，用于发布您的笔记本段落结果。使用此功能，您可以在自己的网站上展示 Zeppelin 笔记本段落结果。非常简单；只需在您的页面上使用`<iframe>`标签。如果您想分享 Zeppelin 笔记本的链接，发布段落结果的第一步是复制段落链接。在 Zeppelin 笔记本中运行段落后，单击位于右侧的齿轮按钮。然后，在菜单中单击链接此段落，如下图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00355.jpeg)**图 31**: 链接段落

然后，只需复制提供的链接，如下所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00358.jpeg)**图 32**: 获取与协作者共享段落的链接

现在，即使您想发布复制的段落，您也可以在您的网站上使用`<iframe>`标签。这是一个例子：

```scala
<iframe src="img/...?asIframe" height="" width="" ></iframe>

```

现在，您可以在您的网站上展示您美丽的可视化结果。这更多或少是我们使用 Apache Zeppelin 进行数据分析旅程的结束。有关更多信息和相关更新，您应该访问 Apache Zeppelin 的官方网站[`zeppelin.apache.org/`](https://zeppelin.apache.org/)；您甚至可以订阅 Zeppelin 用户 users-subscribe@zeppelin.apache.org。

# 摘要

Apache Zeppelin 是一个基于 Web 的笔记本，可以让您以交互方式进行数据分析。使用 Zeppelin，您可以使用 SQL、Scala 等制作美丽的数据驱动、交互式和协作文档。它正在日益受到欢迎，因为最近的版本中添加了更多功能。然而，由于页面限制，并且为了让您更专注于仅使用 Spark，我们展示了仅适用于使用 Scala 的 Spark 的示例。但是，您可以用 Python 编写您的 Spark 代码，并以类似的轻松方式测试您的笔记本。

在本章中，我们讨论了如何使用 Apache Zeppelin 进行后端使用 Spark 进行大规模数据分析。我们看到了如何安装和开始使用 Zeppelin。然后，我们看到了如何摄取您的数据并解析和分析以获得更好的可见性。然后，我们看到了如何将其可视化以获得更好的见解。最后，我们看到了如何与协作者共享 Zeppelin 笔记本。
