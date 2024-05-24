# PySpark 秘籍（二）

> 原文：[`zh.annas-archive.org/md5/226400CAE1A4CC3FBFCCD639AAB45F06`](https://zh.annas-archive.org/md5/226400CAE1A4CC3FBFCCD639AAB45F06)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三章：使用 DataFrame 抽象数据

在本章中，您将学习以下示例：

+   创建 DataFrame

+   访问底层 RDD

+   性能优化

+   使用反射推断模式

+   以编程方式指定模式

+   创建临时表

+   使用 SQL 与 DataFrame 交互

+   DataFrame 转换概述

+   DataFrame 操作概述

# 介绍

在本章中，我们将探索当前的基本数据结构——DataFrame。DataFrame 利用了钨项目和 Catalyst Optimizer 的发展。这两个改进使 PySpark 的性能与 Scala 或 Java 的性能相媲美。

Project tungsten 是针对 Spark 引擎的一系列改进，旨在将其执行过程更接近于*裸金属*。主要成果包括：

+   **在运行时生成代码**：这旨在利用现代编译器中实现的优化

+   **利用内存层次结构**：算法和数据结构利用内存层次结构进行快速执行

+   **直接内存管理**：消除了与 Java 垃圾收集和 JVM 对象创建和管理相关的开销

+   **低级编程**：通过将立即数据加载到 CPU 寄存器中加快内存访问

+   **虚拟函数调度消除**：这消除了多个 CPU 调用的必要性

查看 Databricks 的博客以获取更多信息：[`www.databricks.com/blog/2015/04/28/project-tungsten-bringing-spark-closer-to-bare-metal.html`](https://www.databricks.com/blog/2015/04/28/project-tungsten-bringing-spark-closer-to-bare-metal.html)。

Catalyst Optimizer 位于 Spark SQL 的核心，并驱动对数据和 DataFrame 执行的 SQL 查询。该过程始于向引擎发出查询。首先优化执行的逻辑计划。基于优化的逻辑计划，派生多个物理计划并通过成本优化器推送。然后选择最具成本效益的计划，并将其转换（使用作为钨项目的一部分实施的代码生成优化）为优化的基于 RDD 的执行代码。

# 创建 DataFrame

Spark DataFrame 是在集群中分布的不可变数据集合。DataFrame 中的数据组织成命名列，可以与关系数据库中的表进行比较。

在这个示例中，我们将学习如何创建 Spark DataFrame。

# 准备工作

要执行此示例，您需要一个可用的 Spark 2.3 环境。如果没有，请返回第一章，*安装和配置 Spark*，并按照那里找到的示例进行操作。

您在本章中需要的所有代码都可以在我们为本书设置的 GitHub 存储库中找到：[`bit.ly/2ArlBck`](http://bit.ly/2ArlBck)；转到`第三章`并打开`3. 使用 DataFrame 抽象数据.ipynb`笔记本。

没有其他要求。

# 如何做...

有许多创建 DataFrame 的方法，但最简单的方法是创建一个 RDD 并将其转换为 DataFrame：

```py
sample_data = sc.parallelize([
      (1, 'MacBook Pro', 2015, '15"', '16GB', '512GB SSD'
        , 13.75, 9.48, 0.61, 4.02)
    , (2, 'MacBook', 2016, '12"', '8GB', '256GB SSD'
        , 11.04, 7.74, 0.52, 2.03)
    , (3, 'MacBook Air', 2016, '13.3"', '8GB', '128GB SSD'
        , 12.8, 8.94, 0.68, 2.96)
    , (4, 'iMac', 2017, '27"', '64GB', '1TB SSD'
        , 25.6, 8.0, 20.3, 20.8)
])

sample_data_df = spark.createDataFrame(
    sample_data
    , [
        'Id'
        , 'Model'
        , 'Year'
        , 'ScreenSize'
        , 'RAM'
        , 'HDD'
        , 'W'
        , 'D'
        , 'H'
        , 'Weight'
    ]
)
```

# 它是如何工作的...

如果您已经阅读了上一章，您可能已经知道如何创建 RDD。在这个示例中，我们只需调用`sc.parallelize(...)`方法。

我们的示例数据集只包含了一些相对较新的苹果电脑的记录。然而，与所有 RDD 一样，很难弄清楚元组的每个元素代表什么，因为 RDD 是无模式的结构。

因此，当使用`SparkSession`的`.createDataFrame(...)`方法时，我们将列名列表作为第二个参数传递；第一个参数是我们希望转换为 DataFrame 的 RDD。

现在，如果我们使用`sample_data.take(1)`来查看`sample_data` RDD 的内容，我们将检索到第一条记录：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00034.jpeg)

要比较 DataFrame 的内容，我们可以运行`sample_data_df.take(1)`来获取以下内容：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00035.jpeg)

现在您可以看到，DataFrame 是`Row(...)`对象的集合。`Row(...)`对象由命名的数据组成，与 RDD 不同。

如果前面的`Row(...)`对象对您来说看起来类似于字典，那么您是正确的。任何`Row(...)`对象都可以使用`.asDict(...)`方法转换为字典。有关更多信息，请查看[`spark.apache.org/docs/latest/api/python/pyspark.sql.html#pyspark.sql.Row`](http://spark.apache.org/docs/latest/api/python/pyspark.sql.html#pyspark.sql.Row)。

然而，如果我们要查看`sample_data_df` DataFrame 中的数据，使用`.show(...)`方法，我们会看到以下内容：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00036.jpeg)

由于 DataFrames 具有模式，让我们使用`.printSchema()`方法查看我们的`sample_data_df`的模式：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00037.jpeg)

正如您所看到的，我们 DataFrame 中的列具有与原始`sample_data` RDD 的数据类型匹配的数据类型。

尽管 Python 不是一种强类型语言，但 PySpark 中的 DataFrames 是。与 RDD 不同，DataFrame 列的每个元素都有指定的类型（这些都列在`pyspark.sql.types`子模块中），并且所有数据必须符合指定的模式。

# 更多信息...

当您使用`SparkSession`的`.read`属性时，它会返回一个`DataFrameReader`对象。`DataFrameReader`是一个用于将数据读入 DataFrame 的接口。

# 从 JSON

要从 JSON 格式文件中读取数据，您只需执行以下操作：

```py
sample_data_json_df = (
    spark
    .read
    .json('../Data/DataFrames_sample.json')
)
```

从 JSON 格式文件中读取数据的唯一缺点（尽管是一个小缺点）是所有列将按字母顺序排序。通过运行`sample_data_json_df.show()`来自己看看：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00038.jpeg)

但数据类型保持不变：`sample_data_json_df.printSchema()`

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00039.jpeg)

# 从 CSV

从 CSV 文件中读取同样简单：

```py
sample_data_csv = (
    spark
    .read
    .csv(
        '../Data/DataFrames_sample.csv'
        , header=True
        , inferSchema=True)
)
```

传递的唯一附加参数确保该方法将第一行视为列名（`header`参数），并且它将尝试根据内容为每列分配正确的数据类型（`inferSchema`参数默认分配字符串）。

与从 JSON 格式文件中读取数据不同，从 CSV 文件中读取可以保留列的顺序。

# 另请参阅

+   请查看 Spark 的文档，了解支持的数据格式的完整列表：[`spark.apache.org/docs/latest/api/python/pyspark.sql.html#pyspark.sql.DataFrameReader`](http://spark.apache.org/docs/latest/api/python/pyspark.sql.html#pyspark.sql.DataFrameReader)

# 访问底层 RDD

切换到使用 DataFrames 并不意味着我们需要完全放弃 RDD。在底层，DataFrames 仍然使用 RDD，但是`Row(...)`对象，如前所述。在本示例中，我们将学习如何与 DataFrame 的底层 RDD 交互。

# 准备工作

要执行此示例，您需要一个可用的 Spark 2.3 环境。此外，您应该已经完成了上一个示例，因为我们将重用我们在那里创建的数据。

没有其他要求。

# 如何做...

在这个示例中，我们将把 HDD 的大小和类型提取到单独的列中，然后计算放置每台计算机所需的最小容量：

```py
import pyspark.sql as sql
import pyspark.sql.functions as f

sample_data_transformed = (
    sample_data_df
    .rdd
    .map(lambda row: sql.Row(
        **row.asDict()
        , HDD_size=row.HDD.split(' ')[0]
        )
    )
    .map(lambda row: sql.Row(
        **row.asDict()
        , HDD_type=row.HDD.split(' ')[1]
        )
    )
    .map(lambda row: sql.Row(
        **row.asDict()
        , Volume=row.H * row.D * row.W
        )
    )
    .toDF()
    .select(
        sample_data_df.columns + 
        [
              'HDD_size'
            , 'HDD_type'
            , f.round(
                f.col('Volume')
            ).alias('Volume_cuIn')
        ]
    )
)
```

# 它是如何工作的...

正如前面指出的，DataFrame 中的 RDD 的每个元素都是一个`Row(...)`对象。您可以通过运行以下两个语句来检查它：

```py
sample_data_df.rdd.take(1)
```

还有：

```py
sample_data.take(1)
```

第一个产生一个单项列表，其中元素是`Row(...)`：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00040.jpeg)

另一个也产生一个单项列表，但项目是一个元组：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00041.jpeg)

`sample_data` RDD 是我们在上一个示例中创建的第一个 RDD。

有了这个想法，现在让我们把注意力转向代码。

首先，我们加载必要的模块：要使用`Row(...)`对象，我们需要`pyspark.sql`，稍后我们将使用`.round(...)`方法，因此我们需要`pyspark.sql.functions`子模块。

接下来，我们从`sample_data_df`中提取`.rdd`。使用`.map(...)`转换，我们首先将`HDD_size`列添加到模式中。

由于我们正在使用 RDD，我们希望保留所有其他列。因此，我们首先使用`.asDict()`方法将行（即`Row(...)`对象）转换为字典，然后我们可以稍后使用`**`进行解包。

在 Python 中，单个`*`在元组列表之前，如果作为函数的参数传递，将列表的每个元素作为单独的参数传递给函数。双`**`将第一个元素转换为关键字参数，并使用第二个元素作为要传递的值。

第二个参数遵循一个简单的约定：我们传递要创建的列的名称（`HDD_size`），并将其设置为所需的值。在我们的第一个示例中，我们拆分了`.HDD`列并提取了第一个元素，因为它是`HDD_size`。

我们将重复此步骤两次：首先创建`HDD_type`列，然后创建`Volume`列。

接下来，我们使用`.toDF(...)`方法将我们的 RDD 转换回 DataFrame。请注意，您仍然可以使用`.toDF(...)`方法将常规 RDD（即每个元素不是`Row(...)`对象的情况）转换为 DataFrame，但是您需要将列名的列表传递给`.toDF(...)`方法，否则您将得到未命名的列。

最后，我们`.select(...)`列，以便我们可以`.round(...)`新创建的`Volume`列。`.alias(...)`方法为生成的列产生不同的名称。

生成的 DataFrame 如下所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00042.jpeg)

毫不奇怪，台式 iMac 需要最大的盒子。

# 性能优化

从 Spark 2.0 开始，使用 DataFrame 的 PySpark 性能与 Scala 或 Java 相当。但是，有一个例外：使用**用户定义函数**（**UDFs**）；如果用户定义了一个纯 Python 方法并将其注册为 UDF，在幕后，PySpark 将不断切换运行时（Python 到 JVM 再到 Python）。这是与 Scala 相比性能巨大下降的主要原因，Scala 不需要将 JVM 对象转换为 Python 对象。

在 Spark 2.3 中，情况发生了显著变化。首先，Spark 开始使用新的 Apache 项目。Arrow 创建了一个所有环境都使用的单一内存空间，从而消除了不断复制和转换对象的需要。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00043.jpeg)

来源：https://arrow.apache.org/img/shared.png

有关 Apache Arrow 的概述，请访问[`arrow.apache.org`](https://arrow.apache.org)。

其次，Arrow 将列对象存储在内存中，从而大大提高了性能。因此，为了进一步利用这一点，PySpark 代码的部分已经进行了重构，这为我们带来了矢量化 UDF。

在本示例中，我们将学习如何使用它们，并测试旧的逐行 UDF 和新的矢量化 UDF 的性能。

# 准备工作

要执行此示例，您需要有一个可用的 Spark 2.3 环境。

没有其他要求。

# 如何做...

在本示例中，我们将使用 SciPy 返回在 0 到 1 之间的 100 万个随机数集的正态概率分布函数（PDF）的值。

```py
import pyspark.sql.functions as f
import pandas as pd
from scipy import stats

big_df = (
    spark
    .range(0, 1000000)
    .withColumn('val', f.rand())
)

big_df.cache()
big_df.show(3)

@f.pandas_udf('double', f.PandasUDFType.SCALAR)
def pandas_pdf(v):
    return pd.Series(stats.norm.pdf(v))

(
    big_df
    .withColumn('probability', pandas_pdf(big_df.val))
    .show(5)
)
```

# 它是如何工作的...

首先，像往常一样，我们导入我们将需要运行此示例的所有模块：

+   `pyspark.sql.functions`为我们提供了访问 PySpark SQL 函数的途径。我们将使用它来创建带有随机数字的 DataFrame。

+   `pandas`框架将为我们提供`.Series(...)`数据类型的访问权限，以便我们可以从我们的 UDF 返回一个列。

+   `scipy.stats`为我们提供了访问统计方法的途径。我们将使用它来计算我们的随机数字的正态 PDF。

接下来是我们的`big_df`。`SparkSession`有一个方便的方法`.range(...)`，允许我们在指定的范围内创建一系列数字；在这个示例中，我们只是创建了一个包含一百万条记录的 DataFrame。

在下一行中，我们使用`.withColumn(...)`方法向 DataFrame 添加另一列；列名为`val`，它将包含一百万个`.rand()`数字。

`.rand()`方法返回从 0 到 1 之间的均匀分布中抽取的伪随机数。

最后，我们使用`.cache()`方法缓存 DataFrame，以便它完全保留在内存中（以加快速度）。

接下来，我们定义`pandas_cdf(...)`方法。请注意`@f.pandas_udf`装饰器在方法声明之前，因为这是在 PySpark 中注册矢量化 UDF 的关键，并且仅在 Spark 2.3 中才可用。

请注意，我们不必装饰我们的方法；相反，我们可以将我们的矢量化方法注册为`f.pandas_udf(f=pandas_pdf, returnType='double', functionType=f.PandasUDFType.SCALAR)`。

装饰器方法的第一个参数是 UDF 的返回类型，在我们的例子中是`double`。这可以是 DDL 格式的类型字符串，也可以是`pyspark.sql.types.DataType`。第二个参数是函数类型；如果我们从我们的方法返回单列（例如我们的示例中的 pandas'`.Series(...)`），它将是`.PandasUDFType.SCALAR`（默认情况下）。另一方面，如果我们操作多列（例如 pandas'`DataFrame(...)`），我们将定义`.PandasUDFType.GROUPED_MAP`。

我们的`pandas_pdf(...)`方法简单地接受一个单列，并返回一个带有正态 CDF 对应数字值的 pandas'`.Series(...)`对象。

最后，我们简单地使用新方法来转换我们的数据。以下是前五条记录的样子（您的可能看起来不同，因为我们正在创建一百万个随机数）：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00044.jpeg)

# 还有更多...

现在让我们比较这两种方法的性能：

```py
def test_pandas_pdf():
    return (big_df
            .withColumn('probability', pandas_pdf(big_df.val))
            .agg(f.count(f.col('probability')))
            .show()
        )

%timeit -n 1 test_pandas_pdf()

# row-by-row version with Python-JVM conversion
@f.udf('double')
def pdf(v):
    return float(stats.norm.pdf(v))

def test_pdf():
    return (big_df
            .withColumn('probability', pdf(big_df.val))
            .agg(f.count(f.col('probability')))
            .show()
        )

%timeit -n 1 test_pdf()
```

`test_pandas_pdf()`方法简单地使用`pandas_pdf(...)`方法从正态分布中检索 PDF，执行`.count(...)`操作，并使用`.show(...)`方法打印结果。`test_pdf()`方法也是一样，但是使用`pdf(...)`方法，这是使用 UDF 的逐行方式。

`%timeit`装饰器简单地运行`test_pandas_pdf()`或`test_pdf()`方法七次，每次执行都会乘以。这是运行`test_pandas_pdf()`方法的一个示例输出（因为它是高度重复的，所以缩写了）：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00045.jpeg)

`test_pdf()`方法的时间如下所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00046.jpeg)

如您所见，矢量化 UDF 提供了约 100 倍的性能改进！不要太激动，因为只有对于更复杂的查询才会有这样的加速，就像我们之前使用的那样。

# 另请参阅

+   要了解更多，请查看 Databricks 发布的关于矢量化 UDF 的博客文章：[`databricks.com/blog/2017/10/30/introducing-vectorized-udfs-for-pyspark.html`](https://databricks.com/blog/2017/10/30/introducing-vectorized-udfs-for-pyspark.html)

# 使用反射推断模式

DataFrame 有模式，RDD 没有。也就是说，除非 RDD 由`Row(...)`对象组成。

在这个示例中，我们将学习如何使用反射推断模式创建 DataFrames。

# 准备工作

要执行此示例，您需要拥有一个可用的 Spark 2.3 环境。

没有其他要求。

# 如何做...

在这个示例中，我们首先将 CSV 样本数据读入 RDD，然后从中创建一个 DataFrame。以下是代码：

```py
import pyspark.sql as sql

sample_data_rdd = sc.textFile('../Data/DataFrames_sample.csv')

header = sample_data_rdd.first()

sample_data_rdd_row = (
    sample_data_rdd
    .filter(lambda row: row != header)
    .map(lambda row: row.split(','))
    .map(lambda row:
        sql.Row(
            Id=int(row[0])
            , Model=row[1]
            , Year=int(row[2])
            , ScreenSize=row[3]
            , RAM=row[4]
            , HDD=row[5]
            , W=float(row[6])
            , D=float(row[7])
            , H=float(row[8])
            , Weight=float(row[9])
        )
    )
)
```

# 它是如何工作的...

首先，加载 PySpark 的 SQL 模块。

接下来，使用 SparkContext 的`.textFile(...)`方法读取`DataFrames_sample.csv`文件。

如果您还不知道如何将数据读入 RDD，请查看前一章。

生成的 RDD 如下所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00047.jpeg)

如您所见，RDD 仍然包含具有列名的行。为了摆脱它，我们首先使用`.first()`方法提取它，然后使用`.filter(...)`转换来删除与标题相等的任何行。

接下来，我们用逗号分割每一行，并为每个观察创建一个`Row(...)`对象。请注意，我们将所有字段转换为适当的数据类型。例如，`Id`列应该是整数，`Model`名称是字符串，`W`（宽度）是浮点数。

最后，我们只需调用 SparkSession 的`.createDataFrame(...)`方法，将我们的`Row(...)`对象的 RDD 转换为 DataFrame。这是最终结果：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00048.jpeg)

# 另请参阅

+   查看 Spark 的文档以了解更多信息：[`spark.apache.org/docs/latest/sql-programming-guide.html#inferring-the-schema-using-reflection`](https://spark.apache.org/docs/latest/sql-programming-guide.html#inferring-the-schema-using-reflection)

# 以编程方式指定模式

在上一个示例中，我们学习了如何使用反射推断 DataFrame 的模式。

在这个示例中，我们将学习如何以编程方式指定模式。

# 准备工作

要执行此示例，您需要一个可用的 Spark 2.3 环境。

没有其他要求。

# 如何做...

在这个例子中，我们将学习如何以编程方式指定模式：

```py
import pyspark.sql.types as typ

sch = typ.StructType([
      typ.StructField('Id', typ.LongType(), False)
    , typ.StructField('Model', typ.StringType(), True)
    , typ.StructField('Year', typ.IntegerType(), True)
    , typ.StructField('ScreenSize', typ.StringType(), True)
    , typ.StructField('RAM', typ.StringType(), True)
    , typ.StructField('HDD', typ.StringType(), True)
    , typ.StructField('W', typ.DoubleType(), True)
    , typ.StructField('D', typ.DoubleType(), True)
    , typ.StructField('H', typ.DoubleType(), True)
    , typ.StructField('Weight', typ.DoubleType(), True)
])

sample_data_rdd = sc.textFile('../Data/DataFrames_sample.csv')

header = sample_data_rdd.first()

sample_data_rdd = (
    sample_data_rdd
    .filter(lambda row: row != header)
    .map(lambda row: row.split(','))
    .map(lambda row: (
                int(row[0])
                , row[1]
                , int(row[2])
                , row[3]
                , row[4]
                , row[5]
                , float(row[6])
                , float(row[7])
                , float(row[8])
                , float(row[9])
        )
    )
)

sample_data_schema = spark.createDataFrame(sample_data_rdd, schema=sch)
sample_data_schema.show()
```

# 它是如何工作的...

首先，我们创建一个`.StructField(...)`对象的列表。`.StructField(...)`是在 PySpark 中以编程方式向模式添加字段的方法。第一个参数是我们要添加的列的名称。

第二个参数是我们想要存储在列中的数据的数据类型；一些可用的类型包括`.LongType()`、`.StringType()`、`.DoubleType()`、`.BooleanType()`、`.DateType()`和`.BinaryType()`。

有关 PySpark 中可用数据类型的完整列表，请转到[`spark.apache.org/docs/latest/api/python/pyspark.sql.html#module-pyspark.sql.types.`](http://spark.apache.org/docs/latest/api/python/pyspark.sql.html#module-pyspark.sql.types.)

`.StructField(...)`的最后一个参数指示列是否可以包含空值；如果设置为`True`，则表示可以。

接下来，我们使用 SparkContext 的`.textFile(...)`方法读取`DataFrames_sample.csv`文件。我们过滤掉标题，因为我们将明确指定模式，不需要存储在第一行的名称列。接下来，我们用逗号分割每一行，并对每个元素施加正确的数据类型，使其符合我们刚刚指定的模式。

最后，我们调用`.createDataFrame(...)`方法，但这次，除了 RDD，我们还传递`schema`。生成的 DataFrame 如下所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00049.jpeg)

# 另请参阅

+   查看 Spark 的文档以了解更多信息：[`spark.apache.org/docs/latest/sql-programming-guide.html#programmatically-specifying-the-schema`](https://spark.apache.org/docs/latest/sql-programming-guide.html#programmatically-specifying-the-schema)

# 创建临时表

在 Spark 中，可以很容易地使用 SQL 查询来操作 DataFrame。

在这个示例中，我们将学习如何创建临时视图，以便您可以使用 SQL 访问 DataFrame 中的数据。

# 准备工作

要执行此示例，您需要一个可用的 Spark 2.3 环境。您应该已经完成了上一个示例，因为我们将使用那里创建的`sample_data_schema` DataFrame。

没有其他要求。

# 如何做...

我们只需使用 DataFrame 的`.createTempView(...)`方法：

```py
sample_data_schema.createTempView('sample_data_view')
```

# 它是如何工作的...

`.createTempView(...)`方法是创建临时视图的最简单方法，稍后可以用来查询数据。唯一需要的参数是视图的名称。

让我们看看这样的临时视图现在如何被用来提取数据：

```py
spark.sql('''
    SELECT Model
        , Year
        , RAM
        , HDD
    FROM sample_data_view
''').show()
```

我们只需使用 SparkSession 的`.sql(...)`方法，这使我们能够编写 ANSI-SQL 代码来操作 DataFrame 中的数据。在这个例子中，我们只是提取了四列。这是我们得到的：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00050.jpeg)

# 还有更多...

一旦创建了临时视图，就不能再创建具有相同名称的另一个视图。但是，Spark 提供了另一种方法，允许我们创建或更新视图：`.createOrReplaceTempView（...）`。顾名思义，通过调用此方法，我们要么创建一个新视图（如果不存在），要么用新视图替换已经存在的视图：

```py
sample_data_schema.createOrReplaceTempView('sample_data_view')
```

与以前一样，我们现在可以使用它来使用 SQL 查询与数据交互：

```py
spark.sql('''
    SELECT Model
        , Year
        , RAM
        , HDD
        , ScreenSize
    FROM sample_data_view
''').show()
```

这是我们得到的：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00051.jpeg)

# 使用 SQL 与 DataFrame 交互

在上一个示例中，我们学习了如何创建或替换临时视图。

在这个示例中，我们将学习如何使用 SQL 查询在 DataFrame 中处理数据。

# 准备工作

要执行此示例，您需要具有工作的 Spark 2.3 环境。您应该已经通过*以编程方式指定模式*的示例，因为我们将使用在那里创建的`sample_data_schema` DataFrame。

没有其他要求。

# 如何做...

在这个例子中，我们将扩展我们原始的数据，为苹果电脑的每个型号添加形式因子：

```py
models_df = sc.parallelize([
      ('MacBook Pro', 'Laptop')
    , ('MacBook', 'Laptop')
    , ('MacBook Air', 'Laptop')
    , ('iMac', 'Desktop')
]).toDF(['Model', 'FormFactor'])

models_df.createOrReplaceTempView('models')

sample_data_schema.createOrReplaceTempView('sample_data_view')

spark.sql('''
    SELECT a.*
        , b.FormFactor
    FROM sample_data_view AS a
    LEFT JOIN models AS b
        ON a.Model == b.Model
    ORDER BY Weight DESC
''').show()
```

# 它是如何工作的...

首先，我们创建一个简单的 DataFrame，其中包含两列：`Model`和`FormFactor`。在这个例子中，我们使用 RDD 的`.toDF（...）`方法，快速将其转换为 DataFrame。我们传递的列表只是列名的列表，模式将自动推断。

接下来，我们创建模型视图并替换`sample_data_view`。

最后，要将`FormFactor`附加到我们的原始数据，我们只需在`Model`列上连接两个视图。由于`.sql（...）`方法接受常规 SQL 表达式，因此我们还使用`ORDER BY`子句，以便按权重排序。

这是我们得到的：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00052.jpeg)

# 还有更多...

SQL 查询不仅限于仅提取数据。我们还可以运行一些聚合：

```py
spark.sql('''
    SELECT b.FormFactor
        , COUNT(*) AS ComputerCnt
    FROM sample_data_view AS a
    LEFT JOIN models AS b
        ON a.Model == b.Model
    GROUP BY FormFactor
''').show()
```

在这个简单的例子中，我们将计算不同 FormFactors 的不同计算机数量。`COUNT（*）`运算符计算我们有多少台计算机，并与指定聚合列的`GROUP BY`子句一起工作。

从这个查询中我们得到了什么：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00053.jpeg)

# DataFrame 转换概述

就像 RDD 一样，DataFrame 既有转换又有操作。作为提醒，转换将一个 DataFrame 转换为另一个 DataFrame，而操作对 DataFrame 执行一些计算，并通常将结果返回给驱动程序。而且，就像 RDD 一样，DataFrame 中的转换是惰性的。

在这个示例中，我们将回顾最常见的转换。

# 准备工作

要执行此示例，您需要具有工作的 Spark 2.3 环境。您应该已经通过*以编程方式指定模式*的示例，因为我们将使用在那里创建的`sample_data_schema` DataFrame。

没有其他要求。

# 如何做...

在本节中，我们将列出一些可用于 DataFrame 的最常见转换。此列表的目的不是提供所有可用转换的全面枚举，而是为您提供最常见转换背后的一些直觉。

# `.select（...）`转换

`.select（...）`转换允许我们从 DataFrame 中提取列。它的工作方式与 SQL 中的`SELECT`相同。

看一下以下代码片段：

```py
# select Model and ScreenSize from the DataFrame

sample_data_schema.select('Model', 'ScreenSize').show()
```

它产生以下输出：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00054.jpeg)

在 SQL 语法中，这将如下所示：

```py
SELECT Model
    , ScreenSize
FROM sample_data_schema;
```

# `.filter（...）`转换

`.filter（...）`转换与`.select（...）`相反，仅选择满足指定条件的行。它可以与 SQL 中的`WHERE`语句进行比较。

看一下以下代码片段：

```py
# extract only machines from 2015 onwards

(
    sample_data_schema
    .filter(sample_data_schema.Year > 2015)
    .show()
)
```

它产生以下输出：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00055.jpeg)

在 SQL 语法中，前面的内容相当于：

```py
SELECT *
FROM sample_data_schema
WHERE Year > 2015
```

# `.groupBy（...）`转换

`.groupBy（...）`转换根据列（或多个列）的值执行数据聚合。在 SQL 语法中，这相当于`GROUP BY`。

看一下以下代码：

```py
(
    sample_data_schema
    .groupBy('RAM')
    .count()
    .show()
)
```

它产生此结果：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00056.jpeg)

在 SQL 语法中，这将是：

```py
SELECT RAM
    , COUNT(*) AS count
FROM sample_data_schema
GROUP BY RAM
```

# `.orderBy(...)` 转换

`.orderBy(...)` 转换根据指定的列对结果进行排序。 SQL 世界中的等效项也将是`ORDER BY`。

查看以下代码片段：

```py
# sort by width (W)

sample_data_schema.orderBy('W').show()
```

它产生以下输出：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00057.jpeg)

SQL 等效项将是：

```py
SELECT *
FROM sample_data_schema
ORDER BY W
```

您还可以使用列的`.desc()`开关（`.col(...)`方法）将排序顺序更改为降序。看看以下片段：

```py
# sort by height (H) in descending order

sample_data_schema.orderBy(f.col('H').desc()).show()
```

它产生以下输出：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00058.jpeg)

以 SQL 语法表示，前面的表达式将是：

```py
SELECT *
FROM sample_data_schema
ORDER BY H DESC
```

# `.withColumn(...)` 转换

`.withColumn(...)` 转换将函数应用于其他列和/或文字（使用`.lit(...)`方法）并将其存储为新函数。在 SQL 中，这可以是应用于任何列的任何转换的任何方法，并使用`AS`分配新列名。此转换扩展了原始数据框。

查看以下代码片段：

```py
# split the HDD into size and type

(
    sample_data_schema
    .withColumn('HDDSplit', f.split(f.col('HDD'), ' '))
    .show()
)
```

它产生以下输出：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00059.jpeg)

您可以使用`.select(...)`转换来实现相同的结果。以下代码将产生相同的结果：

```py
# do the same as withColumn

(
    sample_data_schema
    .select(
        f.col('*')
        , f.split(f.col('HDD'), ' ').alias('HDD_Array')
    ).show()
)
```

SQL（T-SQL）等效项将是：

```py
SELECT *
    , STRING_SPLIT(HDD, ' ') AS HDD_Array
FROM sample_data_schema
```

# `.join(...)` 转换

`.join(...)` 转换允许我们连接两个数据框。第一个参数是我们要连接的另一个数据框，而第二个参数指定要连接的列，最后一个参数指定连接的性质。可用类型为`inner`，`cross`，`outer`，`full`，`full_outer`，`left`，`left_outer`，`right`，`right_outer`，`left_semi`和`left_anti`。在 SQL 中，等效项是`JOIN`语句。

如果您不熟悉`ANTI`和`SEMI`连接，请查看此博客：[`blog.jooq.org/2015/10/13/semi-join-and-anti-join-should-have-its-own-syntax-in-sql/`](https://blog.jooq.org/2015/10/13/semi-join-and-anti-join-should-have-its-own-syntax-in-sql/)。

如下查看以下代码：

```py
models_df = sc.parallelize([
      ('MacBook Pro', 'Laptop')
    , ('MacBook', 'Laptop')
    , ('MacBook Air', 'Laptop')
    , ('iMac', 'Desktop')
]).toDF(['Model', 'FormFactor'])

(
    sample_data_schema
    .join(
        models_df
        , sample_data_schema.Model == models_df.Model
        , 'left'
    ).show()
)
```

它产生以下输出：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00060.jpeg)

在 SQL 语法中，这将是：

```py
SELECT a.*
    , b,FormFactor
FROM sample_data_schema AS a
LEFT JOIN models_df AS b
    ON a.Model == b.Model
```

如果我们有一个数据框，不会列出每个`Model`（请注意`MacBook`缺失），那么以下代码是：

```py
models_df = sc.parallelize([
      ('MacBook Pro', 'Laptop')
    , ('MacBook Air', 'Laptop')
    , ('iMac', 'Desktop')
]).toDF(['Model', 'FormFactor'])

(
    sample_data_schema
    .join(
        models_df
        , sample_data_schema.Model == models_df.Model
        , 'left'
    ).show()
)
```

这将生成一个带有一些缺失值的表：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00061.jpeg)

`RIGHT`连接仅保留与右数据框中的记录匹配的记录。因此，看看以下代码：

```py
(
    sample_data_schema
    .join(
        models_df
        , sample_data_schema.Model == models_df.Model
        , 'right'
    ).show()
)
```

这将产生以下表：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00062.jpeg)

`SEMI`和`ANTI`连接是相对较新的添加。`SEMI`连接保留与右数据框中的记录匹配的左数据框中的所有记录（与`RIGHT`连接一样），但*仅保留左数据框中的列*；`ANTI`连接是`SEMI`连接的相反，它仅保留在右数据框中找不到的记录。因此，`SEMI`连接的以下示例是：

```py
(
    sample_data_schema
    .join(
        models_df
        , sample_data_schema.Model == models_df.Model
        , 'left_semi'
    ).show()
)
```

这将产生以下结果：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00063.jpeg)

而`ANTI`连接的示例是：

```py
(
    sample_data_schema
    .join(
        models_df
        , sample_data_schema.Model == models_df.Model
        , 'left_anti'
    ).show()
)
```

这将生成以下内容：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00064.jpeg)

# `.unionAll(...)` 转换

`.unionAll(...)` 转换附加来自另一个数据框的值。 SQL 语法中的等效项是`UNION ALL`。

看看以下代码：

```py
another_macBookPro = sc.parallelize([
      (5, 'MacBook Pro', 2018, '15"', '16GB', '256GB SSD', 13.75, 9.48, 0.61, 4.02)
]).toDF(sample_data_schema.columns)

sample_data_schema.unionAll(another_macBookPro).show()
```

它产生以下结果：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00065.jpeg)

在 SQL 语法中，前面的内容将读作：

```py
SELECT *
FROM sample_data_schema

UNION ALL
SELECT *
FROM another_macBookPro
```

# `.distinct(...)` 转换

`.distinct(...)` 转换返回列中不同值的列表。 SQL 中的等效项将是`DISTINCT`。

看看以下代码：

```py
# select the distinct values from the RAM column

sample_data_schema.select('RAM').distinct().show()
```

它产生以下结果：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00066.jpeg)

在 SQL 语法中，这将是：

```py
SELECT DISTINCT RAM
FROM sample_data_schema
```

# `.repartition(...)` 转换

`.repartition(...)` 转换在集群中移动数据并将其组合成指定数量的分区。您还可以指定要在其上执行分区的列。在 SQL 世界中没有直接等效项。

看看以下代码：

```py
sample_data_schema_rep = (
    sample_data_schema
    .repartition(2, 'Year')
)

sample_data_schema_rep.rdd.getNumPartitions()
```

它产生了（预期的）这个结果：

```py
2
```

# `.fillna(...)` 转换

`.fillna(...)` 转换填充 DataFrame 中的缺失值。您可以指定一个单个值，所有缺失的值都将用它填充，或者您可以传递一个字典，其中每个键是列的名称，值是要填充相应列中的缺失值。在 SQL 世界中没有直接的等价物。

看下面的代码：

```py
missing_df = sc.parallelize([
    (None, 36.3, 24.2)
    , (1.6, 32.1, 27.9)
    , (3.2, 38.7, 24.7)
    , (2.8, None, 23.9)
    , (3.9, 34.1, 27.9)
    , (9.2, None, None)
]).toDF(['A', 'B', 'C'])

missing_df.fillna(21.4).show()
```

它产生了以下输出：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00067.jpeg)

我们还可以指定字典，因为 `21.4` 值实际上并不适合 `A` 列。在下面的代码中，我们首先计算每列的平均值：

```py
miss_dict = (
    missing_df
    .agg(
        f.mean('A').alias('A')
        , f.mean('B').alias('B')
        , f.mean('C').alias('C')
    )
).toPandas().to_dict('records')[0]

missing_df.fillna(miss_dict).show()
```

`.toPandas()` 方法是一个操作（我们将在下一个示例中介绍），它返回一个 pandas DataFrame。pandas DataFrame 的 `.to_dict(...)` 方法将其转换为字典，其中 `records` 参数产生一个常规字典，其中每个列是键，每个值是记录。

上述代码产生以下结果：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00068.jpeg)

# `.dropna(...)` 转换

`.dropna(...)` 转换删除具有缺失值的记录。您可以指定阈值，该阈值转换为记录中的最少缺失观察数，使其符合被删除的条件。与 `.fillna(...)` 一样，在 SQL 世界中没有直接的等价物。

看下面的代码：

```py
missing_df.dropna().show()
```

它产生了以下结果：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00069.jpeg)

指定 `thresh=2`：

```py
missing_df.dropna(thresh=2).show()
```

它保留了第一条和第四条记录：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00070.jpeg)

# `.dropDuplicates(...)` 转换

`.dropDuplicates(...)` 转换，顾名思义，删除重复的记录。您还可以指定一个子集参数作为列名的列表；该方法将根据这些列中找到的值删除重复的记录。

看下面的代码：

```py
dupes_df = sc.parallelize([
      (1.6, 32.1, 27.9)
    , (3.2, 38.7, 24.7)
    , (3.9, 34.1, 27.9)
    , (3.2, 38.7, 24.7)
]).toDF(['A', 'B', 'C'])

dupes_df.dropDuplicates().show()
```

它产生了以下结果

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00071.jpeg)

# `.summary()` 和 `.describe()` 转换

`.summary()` 和 `.describe()` 转换产生类似的描述性统计数据，`.summary()` 转换另外还产生四分位数。

看下面的代码：

```py
sample_data_schema.select('W').summary().show()
sample_data_schema.select('W').describe().show()
```

它产生了以下结果：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00072.jpeg)

# `.freqItems(...)` 转换

`.freqItems(...)` 转换返回列中频繁项的列表。您还可以指定 `minSupport` 参数，该参数将丢弃低于某个阈值的项。

看下面的代码：

```py
sample_data_schema.freqItems(['RAM']).show()
```

它产生了这个结果：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00073.jpeg)

# 另请参阅

+   有关更多转换，请参阅 Spark 文档：[`spark.apache.org/docs/latest/api/python/pyspark.sql.html#pyspark.sql.DataFrame`](http://spark.apache.org/docs/latest/api/python/pyspark.sql.html#pyspark.sql.DataFrame)

# DataFrame 操作概述

上一个示例中列出的转换将一个 DataFrame 转换为另一个 DataFrame。但是，只有在对 **DataFrame** 调用操作时才会执行它们。

在本示例中，我们将概述最常见的操作。

# 准备工作

要执行此示例，您需要一个可用的 Spark 2.3 环境。您应该已经完成了上一个示例，*以编程方式指定模式*，因为我们将使用在那里创建的 `sample_data_schema` DataFrame。

没有其他要求。

# 如何做...

在本节中，我们将列出一些可用于 DataFrame 的最常见操作。此列表的目的不是提供所有可用转换的全面枚举，而是为您提供对最常见转换的直觉。

# `.show(...)` 操作

`.show(...)` 操作默认显示表格形式的前五行记录。您可以通过传递整数作为参数来指定要检索的记录数。

看下面的代码：

```py
sample_data_schema.select('W').describe().show()
```

它产生了这个结果：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00074.jpeg)

# `.collect()` 操作

`.collect()` 操作，顾名思义，从所有工作节点收集所有结果，并将它们返回给驱动程序。在大型数据集上使用此方法时要小心，因为如果尝试返回数十亿条记录的整个 DataFrame，驱动程序很可能会崩溃；只能用此方法返回小的、聚合的数据。

看看下面的代码：

```py
sample_data_schema.groupBy('Year').count().collect()
```

它产生了以下结果：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00075.jpeg)

# `.take(...)` 操作

`.take(...)` 操作的工作方式与 RDDs 中的相同–它将指定数量的记录返回给驱动节点：

```py
Look at the following code:sample_data_schema.take(2)
```

它产生了这个结果：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00076.jpeg)

# `.toPandas()` 操作

`.toPandas()` 操作，顾名思义，将 Spark DataFrame 转换为 pandas DataFrame。与`.collect()` 操作一样，需要在这里发出相同的警告–`.toPandas()` 操作从所有工作节点收集所有记录，将它们返回给驱动程序，然后将结果转换为 pandas DataFrame。

由于我们的样本数据很小，我们可以毫无问题地做到这一点：

```py
sample_data_schema.toPandas()
```

这就是结果的样子：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00077.jpeg)

# 另请参阅

+   参考 Spark 的文档以获取更多操作：[`spark.apache.org/docs/latest/api/python/pyspark.sql.html#pyspark.sql.DataFrame`](http://spark.apache.org/docs/latest/api/python/pyspark.sql.html#pyspark.sql.DataFrame)


# 第四章：为建模准备数据

在本章中，我们将介绍如何清理数据并为建模做准备。您将学习以下内容：

+   处理重复项

+   处理缺失观察

+   处理异常值

+   探索描述性统计

+   计算相关性

+   绘制直方图

+   可视化特征之间的相互作用

# 介绍

现在我们对 RDD 和 DataFrame 的工作原理以及它们的功能有了深入的了解，我们可以开始为建模做准备了。

有名的人（阿尔伯特·爱因斯坦）曾经说过（引用）：

"宇宙和任何数据集的问题都是无限的，我对前者不太确定。"

前面的话当然是一个笑话。然而，您处理的任何数据集，无论是在工作中获取的、在线找到的、自己收集的，还是通过其他方式获取的，都是脏的，直到证明为止；您不应该信任它，不应该玩弄它，甚至不应该看它，直到您自己证明它足够干净（没有完全干净的说法）。

您的数据集可能会出现哪些问题？嗯，举几个例子：

+   **重复的观察**：这些是由系统和操作员的错误导致的

+   **缺失观察**：这可能是由于传感器问题、受访者不愿回答问题，或者仅仅是一些数据损坏导致的

+   **异常观察**：与数据集或人口其他部分相比，观察结果在观察时显得突出

+   **编码**：文本字段未经规范化（例如，单词未经词干处理或使用同义词），使用不同语言，或者您可能遇到无意义的文本输入，日期和日期时间字段可能没有以相同的方式编码

+   **不可信的答案（尤其是调查）**：受访者因任何原因而撒谎；这种脏数据更难处理和清理

正如您所看到的，您的数据可能会受到成千上万个陷阱的困扰，它们正等待着您去陷入其中。清理数据并熟悉数据是我们（作为数据科学家）80%的时间所做的事情（剩下的 20%我们花在建模和抱怨清理数据上）。所以系好安全带，准备迎接*颠簸的旅程*，这是我们信任我们拥有的数据并熟悉它所必需的。

在本章中，我们将使用一个包含`22`条记录的小数据集：

```py
dirty_data = spark.createDataFrame([
          (1,'Porsche','Boxster S','Turbo',2.5,4,22,None)
        , (2,'Aston Martin','Vanquish','Aspirated',6.0,12,16,None)
        , (3,'Porsche','911 Carrera 4S Cabriolet','Turbo',3.0,6,24,None)
        , (3,'General Motors','SPARK ACTIV','Aspirated',1.4,None,32,None)
        , (5,'BMW','COOPER S HARDTOP 2 DOOR','Turbo',2.0,4,26,None)
        , (6,'BMW','330i','Turbo',2.0,None,27,None)
        , (7,'BMW','440i Coupe','Turbo',3.0,6,23,None)
        , (8,'BMW','440i Coupe','Turbo',3.0,6,23,None)
        , (9,'Mercedes-Benz',None,None,None,None,27,None)
        , (10,'Mercedes-Benz','CLS 550','Turbo',4.7,8,21,79231)
        , (11,'Volkswagen','GTI','Turbo',2.0,4,None,None)
        , (12,'Ford Motor Company','FUSION AWD','Turbo',2.7,6,20,None)
        , (13,'Nissan','Q50 AWD RED SPORT','Turbo',3.0,6,22,None)
        , (14,'Nissan','Q70 AWD','Aspirated',5.6,8,18,None)
        , (15,'Kia','Stinger RWD','Turbo',2.0,4,25,None)
        , (16,'Toyota','CAMRY HYBRID LE','Aspirated',2.5,4,46,None)
        , (16,'Toyota','CAMRY HYBRID LE','Aspirated',2.5,4,46,None)
        , (18,'FCA US LLC','300','Aspirated',3.6,6,23,None)
        , (19,'Hyundai','G80 AWD','Turbo',3.3,6,20,None)
        , (20,'Hyundai','G80 AWD','Turbo',3.3,6,20,None)
        , (21,'BMW','X5 M','Turbo',4.4,8,18,121231)
        , (22,'GE','K1500 SUBURBAN 4WD','Aspirated',5.3,8,18,None)
    ], ['Id','Manufacturer','Model','EngineType','Displacement',
        'Cylinders','FuelEconomy','MSRP'])
```

在接下来的教程中，我们将清理前面的数据集，并对其进行更深入的了解。

# 处理重复项

数据中出现重复项的原因很多，但有时很难发现它们。在这个教程中，我们将向您展示如何发现最常见的重复项，并使用 Spark 进行处理。

# 准备工作

要执行此教程，您需要一个可用的 Spark 环境。如果没有，请返回第一章，*安装和配置 Spark*，并按照那里找到的教程进行操作。

我们将使用介绍中的数据集。本章中所需的所有代码都可以在我们为本书设置的 GitHub 存储库中找到：[`bit.ly/2ArlBck`](http://bit.ly/2ArlBck)。转到`Chapter04`并打开[4.Preparing data for modeling.ipynb](https://github.com/drabastomek/PySparkCookbook/blob/devel/Chapter04/4.Preparing%20data%20for%20modeling.ipynb)笔记本。

不需要其他先决条件。

# 操作步骤...

重复项是数据集中出现多次的记录。它是一个完全相同的副本。Spark DataFrames 有一个方便的方法来删除重复的行，即`.dropDuplicates()`转换：

1.  检查是否有任何重复行，如下所示：

```py
dirty_data.count(), dirty_data.distinct().count()
```

1.  如果有重复项，请删除它们：

```py
full_removed = dirty_data.dropDuplicates()
```

# 它是如何工作的...

你现在应该知道这个了，但是`.count()`方法计算我们的 DataFrame 中有多少行。第二个命令检查我们有多少个不同的行。在我们的`dirty_data` DataFrame 上执行这两个命令会产生`(22, 21)`的结果。因此，我们现在知道我们的数据集中有两条完全相同的记录。让我们看看哪些：

```py
(
    dirty_data
    .groupby(dirty_data.columns)
    .count()
    .filter('count > 1')
    .show()
)
```

让我们解开这里发生的事情。首先，我们使用`.groupby(...)`方法来定义用于聚合的列；在这个例子中，我们基本上使用了所有列，因为我们想找到数据集中所有列的所有不同组合。接下来，我们使用`.count()`方法计算这样的值组合发生的次数；该方法将`count`列添加到我们的数据集中。使用`.filter(...)`方法，我们选择数据集中出现多次的所有行，并使用`.show()`操作将它们打印到屏幕上。

这产生了以下结果：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00078.jpeg)

因此，`Id`等于`16`的行是重复的。因此，让我们使用`.dropDuplicates(...)`方法将其删除。最后，运行`full_removed.count()`命令确认我们现在有 21 条记录。

# 还有更多...

嗯，还有更多的内容，你可能会想象。在我们的`full_removed` DataFrame 中仍然有一些重复的记录。让我们仔细看看。

# 只有 ID 不同

如果您随时间收集数据，可能会记录具有不同 ID 但相同数据的数据。让我们检查一下我们的 DataFrame 是否有这样的记录。以下代码片段将帮助您完成此操作：

```py
(
    full_removed
    .groupby([col for col in full_removed.columns if col != 'Id'])
    .count()
    .filter('count > 1')
    .show()
)
```

就像以前一样，我们首先按所有列分组，但是我们排除了`'Id'`列，然后计算给定此分组的记录数，最后提取那些具有`'count > 1'`的记录并在屏幕上显示它们。运行上述代码后，我们得到以下结果：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00079.jpeg)

正如你所看到的，我们有四条不同 ID 但是相同车辆的记录：`BMW` `440i Coupe`和`Hyundai` `G80 AWD`。

我们也可以像以前一样检查计数：

```py
no_ids = (
    full_removed
    .select([col for col in full_removed.columns if col != 'Id'])
)

no_ids.count(), no_ids.distinct().count()
(21, 19), indicating that we have four records that are duplicated, just like we saw earlier.
```

`.dropDuplicates(...)`方法可以轻松处理这种情况。我们需要做的就是将要考虑的所有列的列表传递给`subset`参数，以便在搜索重复项时使用。方法如下：

```py
id_removed = full_removed.dropDuplicates(
    subset = [col for col in full_removed.columns if col != 'Id']
)
```

再次，我们选择除了`'Id'`列之外的所有列来定义重复的列。如果我们现在计算`id_removed` DataFrame 中的总行数，应该得到`19`：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00080.jpeg)

这正是我们得到的！

# ID 碰撞

您可能还会假设，如果有两条具有相同 ID 的记录，它们是重复的。嗯，虽然这可能是真的，但是当我们基于所有列删除记录时，我们可能已经删除了它们。因此，在这一点上，任何重复的 ID 更可能是碰撞。

重复的 ID 可能出现多种原因：仪器误差或存储 ID 的数据结构不足，或者如果 ID 表示记录元素的某个哈希函数，可能会出现哈希函数的选择引起的碰撞。这只是您可能具有重复 ID 但记录实际上并不重复的原因中的一部分。

让我们检查一下我们的数据集是否符合这一点：

```py
import pyspark.sql.functions as fn

id_removed.agg(
      fn.count('Id').alias('CountOfIDs')
    , fn.countDistinct('Id').alias('CountOfDistinctIDs')
).show()
```

在这个例子中，我们将使用`.agg(...)`方法，而不是对记录进行子集化，然后计算记录数，然后计算不同的记录数。为此，我们首先从`pyspark.sql.functions`模块中导入所有函数。

有关`pyspark.sql.functions`中所有可用函数的列表，请参阅[`spark.apache.org/docs/latest/api/python/pyspark.sql.html#module-pyspark.sql.functions`](https://spark.apache.org/docs/latest/api/python/pyspark.sql.html#module-pyspark.sql.functions)。

我们将使用的两个函数将允许我们一次完成计数：`.count(...)`方法计算指定列中非空值的所有记录的数量，而`.countDistinct(...)`返回这样一列中不同值的计数。`.alias(...)`方法允许我们为计数结果的列指定友好的名称。在计数之后，我们得到了以下结果：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00081.jpeg)

好的，所以我们有两条具有相同 ID 的记录。再次，让我们检查哪些 ID 是重复的：

```py
(
    id_removed
    .groupby('Id')
    .count()
    .filter('count > 1')
    .show()
)
```

与之前一样，我们首先按`'Id'`列中的值进行分组，然后显示所有具有大于`1`的`count`的记录。这是我们得到的结果：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00082.jpeg)

嗯，看起来我们有两条`'Id == 3'`的记录。让我们检查它们是否相同：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00083.jpeg)

这些绝对不是相同的记录，但它们共享相同的 ID。在这种情况下，我们可以创建一个新的 ID，这将是唯一的（我们已经确保数据集中没有其他重复）。PySpark 的 SQL 函数模块提供了一个`.monotonically_increasing_id()`方法，它创建一个唯一的 ID 流。

`.monotonically_increasing_id()`生成的 ID 保证是唯一的，只要你的数据存在少于十亿个分区，并且每个分区中的记录少于八十亿条。这是一个非常大的数字。

以下是一个代码段，将创建并替换我们的 ID 列为一个唯一的 ID：

```py
new_id = (
    id_removed
    .select(
        [fn.monotonically_increasing_id().alias('Id')] + 
        [col for col in id_removed.columns if col != 'Id'])
)

new_id.show()
```

我们首先创建 ID 列，然后选择除原始`'Id'`列之外的所有其他列。新的 ID 看起来是这样的：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00084.jpeg)

这些数字绝对是唯一的。我们现在准备处理数据集中的其他问题。

# 处理缺失观察

缺失观察在数据集中几乎是第二常见的问题。这是由于许多原因引起的，正如我们在介绍中已经提到的那样。在这个示例中，我们将学习如何处理它们。

# 准备好了

要执行这个示例，你需要一个可用的 Spark 环境。此外，我们将在前一个示例中创建的`new_id` DataFrame 上进行操作，因此我们假设你已经按照步骤删除了重复的记录。

不需要其他先决条件。

# 如何做...

由于我们的数据有两个维度（行和列），我们需要检查每行和每列中缺失数据的百分比，以确定保留什么，放弃什么，以及（可能）插补什么：

1.  要计算一行中有多少缺失观察，使用以下代码段：

```py
(
    spark.createDataFrame(
        new_id
        .rdd
        .map(
           lambda row: (
                 row['Id']
               , sum([c == None for c in row])
           )
        )
        .collect()
        .filter(lambda el: el[1] > 1)
        ,['Id', 'CountMissing']
    )
    .orderBy('CountMissing', ascending=False)
    .show()
)
```

1.  要计算每列中缺少多少数据，使用以下代码：

```py
for k, v in sorted(
    merc_out
        .agg(*[
               (1 - (fn.count(c) / fn.count('*')))
                    .alias(c + '_miss')
               for c in merc_out.columns
           ])
        .collect()[0]
        .asDict()
        .items()
    , key=lambda el: el[1]
    , reverse=True
):
    print(k, v)
```

让我们一步一步地走过这些。

# 它是如何工作的...

现在让我们详细看看如何处理行和列中的缺失观察。

# 每行的缺失观察

要计算一行中缺少多少数据，更容易使用 RDD，因为我们可以循环遍历 RDD 记录的每个元素，并计算缺少多少值。因此，我们首先访问`new_id` DataFrame 中的`.rdd`。使用`.map(...)`转换，我们循环遍历每一行，提取`'Id'`，并使用`sum([c == None for c in row])`表达式计算缺少元素的次数。这些操作的结果是每个都有两个值的元素的 RDD：行的 ID 和缺失值的计数。

接下来，我们只选择那些有多于一个缺失值的记录，并在驱动程序上`.collect()`这些记录。然后，我们创建一个简单的 DataFrame，通过缺失值的计数按降序`.orderBy(...)`，并显示记录。

结果如下所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00085.jpeg)

正如你所看到的，其中一条记录有八个值中的五个缺失。让我们看看那条记录：

```py
(
    new_id
    .where('Id == 197568495616')
    .show()
)
```

前面的代码显示了`Mercedes-Benz`记录中大部分值都缺失：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00086.jpeg)

因此，我们可以删除整个观测值，因为这条记录中实际上并没有太多价值。为了实现这个目标，我们可以使用 DataFrame 的`.dropna(...)`方法：`merc_out = new_id.dropna(thresh=4)`。

如果你使用`.dropna()`而不传递任何参数，任何具有缺失值的记录都将被删除。

我们指定`thresh=4`，所以我们只删除具有至少四个非缺失值的记录；我们的记录只有三个有用的信息。

让我们确认一下：运行`new_id.count(), merc_out.count()`会产生`(19, 18)`，所以是的，确实，我们移除了一条记录。我们真的移除了`Mercedes-Benz`吗？让我们检查一下：

```py
(
    merc_out
    .where('Id == 197568495616')
    .show()
)
Id equal to 197568495616, as shown in the following screenshot:
```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00087.jpeg)

# 每列的缺失观测值

我们还需要检查是否有某些列中有特别低的有用信息发生率。在我们提供的代码中发生了很多事情，所以让我们一步一步地拆开它。

让我们从内部列表开始：

```py
[
    (1 - (fn.count(c) / fn.count('*')))
        .alias(c + '_miss')
    for c in merc_out.columns
]
```

我们遍历`merc_out` DataFrame 中的所有列，并计算我们在每列中找到的非缺失值的数量。然后我们将它除以所有行的总数，并从中减去 1，这样我们就得到了缺失值的百分比。

我们在本章前面导入了`pyspark.sql.functions`作为`fn`。

然而，我们在这里实际上做的并不是真正的计算。Python 存储这些信息的方式，此时只是作为一系列对象或指针，指向某些操作。只有在我们将列表传递给`.agg(...)`方法后，它才会被转换为 PySpark 的内部执行图（只有在我们调用`.collect()`动作时才会执行）。

`.agg(...)`方法接受一组参数，不是作为列表对象，而是作为逗号分隔的参数列表。因此，我们没有将列表本身传递给`.agg(...)`方法，而是在列表前面包含了`'*'`，这样我们的列表的每个元素都会被展开，并像参数一样传递给我们的方法。

`.collect()`方法将返回一个元素的列表——一个包含聚合信息的`Row`对象。我们可以使用`.asDict()`方法将`Row`转换为字典，然后提取其中的所有`items`。这将导致一个元组的列表，其中第一个元素是列名（我们使用`.alias(...)`方法将`'_miss'`附加到每一列），第二个元素是缺失观测值的百分比。

在循环遍历排序列表的元素时，我们只是将它们打印到屏幕上：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00088.jpeg)

嗯，看起来`MSRP`列中的大部分信息都是缺失的。因此，我们可以删除它，因为它不会给我们带来任何有用的信息：

```py
no_MSRP = merc_out.select([col for col in new_id.columns if col != 'MSRP'])
```

我们仍然有两列有一些缺失信息。让我们对它们做点什么。

# 还有更多...

PySpark 允许你填补缺失的观测值。你可以传递一个值，所有数据中的`null`或`None`都将被替换，或者你可以传递一个包含不同值的字典，用于每个具有缺失观测值的列。在这个例子中，我们将使用后一种方法，并指定燃油经济性和排量之间的比例，以及气缸数和排量之间的比例。

首先，让我们创建我们的字典：

```py
multipliers = (
    no_MSRP
    .agg(
          fn.mean(
              fn.col('FuelEconomy') / 
              (
                  fn.col('Displacement') * fn.col('Cylinders')
              )
          ).alias('FuelEconomy')
        , fn.mean(
            fn.col('Cylinders') / 
            fn.col('Displacement')
        ).alias('Cylinders')
    )
).toPandas().to_dict('records')[0]
```

在这里，我们有效地计算了我们的乘数。为了替换燃油经济性中的缺失值，我们将使用以下公式：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00089.jpeg)

对于气缸数，我们将使用以下方程：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00090.jpeg)

我们先前的代码使用这两个公式来计算每一行的乘数，然后取这些乘数的平均值。

这不会是完全准确的，但鉴于我们拥有的数据，它应该足够准确。

在这里，我们还提供了另一种将您的（小型！）Spark DataFrame 创建为字典的方法：使用`.toPandas()`方法将 Spark DataFrame 转换为 pandas DataFrame。 pandas DataFrame 具有`.to_dict(...)`方法，该方法将允许您将我们的数据转换为字典。 `'records'`参数指示方法将每一行转换为一个字典，其中键是具有相应记录值的列名。

查看此链接以了解更多关于`.to_dict(...)`方法的信息：[`pandas.pydata.org/pandas-docs/stable/generated/pandas.DataFrame.to_dict.html`](https://pandas.pydata.org/pandas-docs/stable/generated/pandas.DataFrame.to_dict.html)。

我们的结果字典如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00091.jpeg)

现在让我们使用它来填补我们的缺失数据：

```py
imputed = (
    no_MSRP
    .withColumn('FuelEconomy', fn.col('FuelEconomy') / fn.col('Displacement') / fn.col('Cylinders'))
    .withColumn('Cylinders', fn.col('Cylinders') / fn.col('Displacement'))
    .fillna(multipliers)
    .withColumn('Cylinders', (fn.col('Cylinders') * fn.col('Displacement')).cast('integer'))
    .withColumn('FuelEconomy', fn.col('FuelEconomy') * fn.col('Displacement') * fn.col('Cylinders'))
)
```

首先，我们将原始数据转换为反映我们之前指定的比率的数据。接下来，我们使用乘数字典填充缺失值，最后将列恢复到其原始状态。

请注意，每次使用`.withColumn(...)`方法时，都会覆盖原始列名。

生成的 DataFrame 如下所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00092.jpeg)

正如您所看到的，汽缸和燃油经济性的结果值并不完全准确，但仍然可以说比用预定义值替换它们要好。

# 另请参阅

+   查看 PySpark 关于缺失观察方法的文档：[`spark.apache.org/docs/latest/api/python/pyspark.sql.html#pyspark.sql.DataFrameNaFunctions`](https://spark.apache.org/docs/latest/api/python/pyspark.sql.html#pyspark.sql.DataFrameNaFunctions)

# 处理异常值

异常值是与其余观察结果差异很大的观察结果，即它们位于数据分布的长尾部分，本配方中，我们将学习如何定位和处理异常值。

# 准备工作

要执行此配方，您需要有一个可用的 Spark 环境。此外，我们将在前一个配方中创建的`imputed`DataFrame 上进行操作，因此我们假设您已经按照处理缺失观察的步骤进行了操作。

不需要其他先决条件。

# 如何做...

让我们从异常值的一个常见定义开始。

一个点，![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00093.jpeg)，符合以下标准：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00094.jpeg)

不被视为异常值；在此范围之外的任何点都是异常值。在上述方程中，*Q¹*是第一四分位数（25^(th)百分位数），*Q³*是第三四分位数，*IQR*是**四分位距**，定义为*Q³*和*Q¹*的差值：IQR= *Q³-Q¹*。

要标记异常值，请按照以下步骤进行：

1.  让我们先计算我们的范围：

```py
features = ['Displacement', 'Cylinders', 'FuelEconomy']
quantiles = [0.25, 0.75]

cut_off_points = []

for feature in features:
    quants = imputed.approxQuantile(feature, quantiles, 0.05)

    IQR = quants[1] - quants[0]
    cut_off_points.append((feature, [
        quants[0] - 1.5 * IQR,
        quants[1] + 1.5 * IQR,
    ]))

cut_off_points = dict(cut_off_points)
```

1.  接下来，我们标记异常值：

```py
outliers = imputed.select(*['id'] + [
       (
           (imputed[f] < cut_off_points[f][0]) |
           (imputed[f] > cut_off_points[f][1])
       ).alias(f + '_o') for f in features
  ])
```

# 它是如何工作的...

我们只会查看数值变量：排量、汽缸和燃油经济性。

我们循环遍历所有这些特征，并使用`.approxQuantile(...)`方法计算第一和第三四分位数。该方法将特征（列）名称作为第一个参数，要计算的四分位数的浮点数（或浮点数列表）作为第二个参数，第三个参数指定相对目标精度（将此值设置为 0 将找到精确的四分位数，但可能非常昂贵）。

该方法返回两个（在我们的情况下）值的列表：*Q¹*和*Q³*。然后我们计算四分位距，并将`(feature_name, [lower_bound, upper_bound])`元组附加到`cut_off_point`列表中。转换为字典后，我们的截断点如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00095.jpeg)

因此，现在我们可以使用这些来标记我们的异常观察结果。我们只会选择 ID 列，然后循环遍历我们的特征，以检查它们是否落在我们计算的边界之外。这是我们得到的结果：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00096.jpeg)

因此，我们在燃油经济性列中有两个异常值。让我们检查记录：

```py
with_outliers_flag = imputed.join(outliers, on='Id')

(
    with_outliers_flag
    .filter('FuelEconomy_o')
    .select('Id', 'Manufacturer', 'Model', 'FuelEconomy')
    .show()
)
```

首先，我们将我们的`imputed` DataFrame 与`outliers`进行连接，然后我们根据`FuelEconomy_o`标志进行筛选，仅选择我们的异常记录。最后，我们只提取最相关的列以显示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00097.jpeg)

因此，我们有`SPARK ACTIV`和`CAMRY HYBRID LE`作为异常值。`SPARK ACTIV`由于我们的填充逻辑而成为异常值，因为我们不得不填充其燃油经济值；考虑到其引擎排量为 1.4 升，我们的逻辑并不奏效。好吧，您可以用其他方法填充值。作为混合动力车，凯美瑞在由大型涡轮增压引擎主导的数据集中显然是一个异常值；看到它出现在这里并不奇怪。

尝试基于带有异常值的数据构建机器学习模型可能会导致一些不可信的结果或无法很好泛化的模型，因此我们通常会从数据集中删除这些异常值：

```py
no_outliers = (
    with_outliers_flag
    .filter('!FuelEconomy_o')
    .select(imputed.columns)
)
FuelEconomy_o column. That's it!
```

# 另请参阅

+   查看此网站以获取有关异常值的更多信息：[`www.itl.nist.gov/div898/handbook/prc/section1/prc16.htm`](http://www.itl.nist.gov/div898/handbook/prc/section1/prc16.htm)

# 探索描述性统计

描述性统计是您可以在数据上计算的最基本的度量。在本示例中，我们将学习在 PySpark 中熟悉我们的数据集是多么容易。

# 准备工作

要执行此示例，您需要一个可用的 Spark 环境。此外，我们将使用在*处理异常值*示例中创建的`no_outliers` DataFrame，因此我们假设您已经按照处理重复项、缺失观测值和异常值的步骤进行了操作。

不需要其他先决条件。

# 如何做...

在 PySpark 中计算数据的描述性统计非常容易。以下是方法：

```py
descriptive_stats = no_outliers.describe(features)
```

就是这样！

# 工作原理...

上述代码几乎不需要解释。`.describe(...)`方法接受要计算描述性统计的列的列表，并返回一个包含基本描述性统计的 DataFrame：计数、平均值、标准偏差、最小值和最大值。

您可以将数字和字符串列都指定为`.describe(...)`的输入参数。

这是我们在`features`列上运行`.describe(...)`方法得到的结果：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00098.jpeg)

正如预期的那样，我们总共有`16`条记录。我们的数据集似乎偏向于较大的引擎，因为平均排量为`3.44`升，有六个汽缸。对于如此庞大的引擎来说，燃油经济性似乎还不错，为 19 英里/加仑。

# 还有更多...

如果您不传递要计算描述性统计的列的列表，PySpark 将返回 DataFrame 中每一列的统计信息。请查看以下代码片段：

```py
descriptive_stats_all = no_outliers.describe()
descriptive_stats_all.show()
```

这将导致以下表：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00099.jpeg)

正如您所看到的，即使字符串列也有它们的描述性统计，但解释起来相当可疑。

# 聚合列的描述性统计

有时，您希望在一组值中计算一些描述性统计。在此示例中，我们将为具有不同汽缸数量的汽车计算一些基本统计信息：

```py
(
    no_outliers
    .select(features)
    .groupBy('Cylinders')
    .agg(*[
          fn.count('*').alias('Count')
        , fn.mean('FuelEconomy').alias('MPG_avg')
        , fn.mean('Displacement').alias('Disp_avg')
        , fn.stddev('FuelEconomy').alias('MPG_stdev')
```

```py

        , fn.stddev('Displacement').alias('Disp_stdev')
    ])
    .orderBy('Cylinders')
).show()
```

首先，我们选择我们的`features`列列表，以减少我们需要分析的数据量。接下来，我们在汽缸列上聚合我们的数据，并使用（已经熟悉的）`.agg(...)`方法来计算燃油经济性和排量的计数、平均值和标准偏差。

`pyspark.sql.functions`模块中还有更多的聚合函数：`avg(...)`, `count(...)`, `countDistinct(...)`, `first(...)`, `kurtosis(...)`, `max(...)`, `mean(...)`, `min(...)`, `skewness(...)`, `stddev_pop(...)`, `stddev_samp(...)`, `sum(...)`, `sumDistinct(...)`, `var_pop(...)`, `var_samp(...)`, 和 `variance(...)`.

这是结果表：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00100.jpeg)

我们可以从这个表中得出两点结论：

+   我们的填充方法真的不准确，所以下次我们应该想出一个更好的方法。

+   六缸汽车的`MPG_avg`高于四缸汽车，这可能有些可疑。这就是为什么你应该熟悉你的数据，因为这样你就可以发现数据中的隐藏陷阱。

如何处理这样的发现超出了本书的范围。但是，重点是这就是为什么数据科学家会花 80%的时间来清理数据并熟悉它，这样建立在这样的数据上的模型才能得到可靠的依赖。

# 另请参阅

+   你可以在你的数据上计算许多其他统计量，我们在这里没有涵盖（但 PySpark 允许你计算）。为了更全面地了解，我们建议你查看这个网站：[`www.socialresearchmethods.net/kb/statdesc.php`](https://www.socialresearchmethods.net/kb/statdesc.php)。

# 计算相关性

与结果相关的特征是可取的，但那些在彼此之间也相关的特征可能会使模型不稳定。在这个配方中，我们将向你展示如何计算特征之间的相关性。

# 准备工作

要执行这个步骤，你需要一个可用的 Spark 环境。此外，我们将使用我们在*处理离群值*配方中创建的`no_outliers` DataFrame，所以我们假设你已经按照处理重复项、缺失观察和离群值的步骤进行了操作。

不需要其他先决条件。

# 如何做...

要计算两个特征之间的相关性，你只需要提供它们的名称：

```py
(
    no_outliers
    .corr('Cylinders', 'Displacement')
)
```

就是这样！

# 它是如何工作的...

`.corr(...)`方法接受两个参数，即你想要计算相关系数的两个特征的名称。

目前只有皮尔逊相关系数是可用的。

上述命令将为我们的数据集产生一个相关系数等于`0.938`。

# 还有更多...

如果你想计算一个相关矩阵，你需要手动完成这个过程。以下是我们的解决方案：

```py
n_features = len(features)

corr = []

for i in range(0, n_features):
    temp = [None] * i

    for j in range(i, n_features):
        temp.append(no_outliers.corr(features[i], features[j]))
    corr.append([features[i]] + temp)

correlations = spark.createDataFrame(corr, ['Column'] + features)
```

上述代码实际上是在我们的`features`列表中循环，并计算它们之间的成对相关性，以填充矩阵的上三角部分。

我们在*处理离群值*配方中介绍了`features`列表。

然后将计算出的系数附加到`temp`列表中，然后将其添加到`corr`列表中。最后，我们创建了相关性 DataFrame。它看起来是这样的：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00101.jpeg)

如你所见，唯一的强相关性是`Displacement`和`Cylinders`之间的，这当然不足为奇。`FuelEconomy`与排量并没有真正相关，因为还有其他影响`FuelEconomy`的因素，比如汽车的阻力和重量。然而，如果你试图预测，例如最大速度，并假设（这是一个合理的假设），`Displacement`和`Cylinders`都与最大速度高度正相关，那么你应该只使用其中一个。

# 绘制直方图

直方图是直观检查数据分布的最简单方法。在这个配方中，我们将向你展示如何在 PySpark 中做到这一点。

# 准备工作

要执行这个步骤，你需要一个可用的 Spark 环境。此外，我们将使用我们在*处理离群值*配方中创建的`no_outliers` DataFrame，所以我们假设你已经按照处理重复项、缺失观察和离群值的步骤进行了操作。

不需要其他先决条件。

# 如何做...

在 PySpark 中有两种生成直方图的方法：

+   选择你想要可视化的特征，在驱动程序上`.collect()`它，然后使用 matplotlib 的本地`.hist(...)`方法来绘制直方图

+   在 PySpark 中计算每个直方图箱中的计数，并将计数返回给驱动程序进行可视化

前一个解决方案适用于小数据集（例如本章中的数据），但如果数据太大，它将破坏您的驱动程序。此外，我们分发数据的一个很好的原因是，我们可以并行计算而不是在单个线程中进行计算。因此，在这个示例中，我们只会向您展示第二个解决方案。这是为我们做所有计算的片段：

```py
histogram_MPG = (
    no_outliers
    .select('FuelEconomy')
    .rdd
    .flatMap(lambda record: record)
    .histogram(5)
)
```

# 它是如何工作的...

上面的代码非常容易理解。首先，我们选择感兴趣的特征（在我们的例子中是燃油经济）。

Spark DataFrames 没有本地的直方图方法，这就是为什么我们要切换到底层的 RDD。

接下来，我们将结果展平为一个长列表（而不是一个`Row`对象），并使用`.histogram(...)`方法来计算我们的直方图。

`.histogram(...)`方法接受一个整数，该整数指定要将我们的数据分配到的桶的数量，或者是一个具有指定桶限制的列表。

查看 PySpark 关于`.histogram(...)`的文档：[`spark.apache.org/docs/latest/api/python/pyspark.html#pyspark.RDD.histogram`](https://spark.apache.org/docs/latest/api/python/pyspark.html#pyspark.RDD.histogram)。

该方法返回两个元素的元组：第一个元素是一个 bin 边界的列表，另一个元素是相应 bin 中元素的计数。这是我们的燃油经济特征的样子：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00102.jpeg)

请注意，我们指定`.histogram(...)`方法将我们的数据分桶为五个 bin，但第一个列表中有六个元素。但是，我们的数据集中仍然有五个桶：*[8.97, 12.38), [ 12.38, 15.78), [15.78, 19.19), [19.19, 22.59)*和*[22.59, 26.0)*。

我们不能在 PySpark 中本地创建任何图表，而不经过大量设置（例如，参见这个：[`plot.ly/python/apache-spark/`](https://plot.ly/python/apache-spark/)）。更简单的方法是准备一个包含我们的数据的 DataFrame，并在驱动程序上使用一些*魔法*（好吧，是 sparkmagics，但它仍然有效！）。

首先，我们需要提取我们的数据并创建一个临时的`histogram_MPG`表：

```py
(
    spark
    .createDataFrame(
        [(bins, counts) 
         for bins, counts 
         in zip(
             histogram_MPG[0], 
             histogram_MPG[1]
         )]
        , ['bins', 'counts']
    )
    .registerTempTable('histogram_MPG')
)
```

我们创建一个两列的 DataFrame，其中第一列包含 bin 的下限，第二列包含相应的计数。`.registerTempTable(...)`方法（顾名思义）注册一个临时表，这样我们就可以在`%%sql`魔法中使用它：

```py
%%sql -o hist_MPG -q
SELECT * FROM histogram_MPG
```

上面的命令从我们的临时`histogram_MPG`表中选择所有记录，并将其输出到本地可访问的`hist_MPG`变量；`-q`开关是为了确保笔记本中没有打印出任何内容。

有了本地可访问的`hist_MPG`，我们现在可以使用它来生成我们的图表：

```py
%%local
import matplotlib.pyplot as plt
%matplotlib inline
plt.style.use('ggplot')

fig = plt.figure(figsize=(12,9))
ax = fig.add_subplot(1, 1, 1)
ax.bar(hist_MPG['bins'], hist_MPG['counts'], width=3)
ax.set_title('Histogram of fuel economy')
```

`%%local`在本地模式下执行笔记本单元格中的任何内容。首先，我们导入`matplotlib`库，并指定它在笔记本中内联生成图表，而不是每次生成图表时弹出一个新窗口。`plt.style.use(...)`更改我们图表的样式。

要查看可用样式的完整列表，请查看[`matplotlib.org/devdocs/gallery/style_sheets/style_sheets_reference.html`](https://matplotlib.org/devdocs/gallery/style_sheets/style_sheets_reference.html)。

接下来，我们创建一个图表，并向其中添加一个子图，最后，我们使用`.bar(...)`方法来绘制我们的直方图并设置标题。图表的样子如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00103.jpeg)

就是这样！

# 还有更多...

Matplotlib 不是我们绘制直方图的唯一库。Bokeh（可在[`bokeh.pydata.org/en/latest/`](https://bokeh.pydata.org/en/latest/)找到）是另一个功能强大的绘图库，建立在`D3.js`之上，允许您与图表进行交互。

在[`bokeh.pydata.org/en/latest/docs/gallery.html`](https://bokeh.pydata.org/en/latest/docs/gallery.html)上查看示例的图库。

这是使用 Bokeh 绘图的方法：

```py
%%local
from bokeh.io import show
from bokeh.plotting import figure
from bokeh.io import output_notebook
output_notebook()

labels = [str(round(e, 2)) for e in hist_MPG['bins']]

p = figure(
    x_range=labels, 
    plot_height=350, 
    title='Histogram of fuel economy'
)

p.vbar(x=labels, top=hist_MPG['counts'], width=0.9)

show(p)
```

首先，我们加载 Bokeh 的所有必要组件；`output_notebook()`方法确保我们在笔记本中内联生成图表，而不是每次都打开一个新窗口。接下来，我们生成要放在图表上的标签。然后，我们定义我们的图形：`x_range`参数指定*x*轴上的点数，`plot_height`设置我们图表的高度。最后，我们使用`.vbar(...)`方法绘制我们直方图的条形；`x`参数是要放在我们图表上的标签，`top`参数指定计数。

结果如下所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00104.jpeg)

这是相同的信息，但您可以在浏览器中与此图表进行交互。

# 另请参阅

+   如果您想要进一步自定义您的直方图，这是一个可能有用的页面：[`plot.ly/matplotlib/histograms/`](https://plot.ly/matplotlib/histograms/)

# 可视化特征之间的相互作用

绘制特征之间的相互作用可以进一步加深您对数据分布的理解，也可以了解特征之间的关系。在这个配方中，我们将向您展示如何从您的数据中创建散点图。

# 准备工作

要执行此操作，您需要拥有一个可用的 Spark 环境。此外，我们将在*处理异常值*配方中创建的`no_outliers` DataFrame 上进行操作，因此我们假设您已经按照处理重复项、缺失观察和异常值的步骤进行了操作。

不需要其他先决条件。

# 如何做...

再次，我们将从 DataFrame 中选择我们的数据并在本地公开它：

```py
scatter = (
    no_outliers
    .select('Displacement', 'Cylinders')
)

scatter.registerTempTable('scatter')

%%sql -o scatter_source -q
SELECT * FROM scatter
```

# 它是如何工作的...

首先，我们选择我们想要了解其相互作用的两个特征；在我们的案例中，它们是排量和汽缸特征。

我们的示例很小，所以我们可以使用所有的数据。然而，在现实世界中，您应该在尝试绘制数十亿数据点之前首先对数据进行抽样。

在注册临时表之后，我们使用`%%sql`魔术方法从`scatter`表中选择所有数据并在本地公开为`scatter_source`。现在，我们可以开始绘图了：

```py
%%local
import matplotlib.pyplot as plt
%matplotlib inline
plt.style.use('ggplot')

fig = plt.figure(figsize=(12,9))
ax = fig.add_subplot(1, 1, 1)
ax.scatter(
      list(scatter_source['Cylinders'])
    , list(scatter_source['Displacement'])
    , s = 200
    , alpha = 0.5
)

ax.set_xlabel('Cylinders')
ax.set_ylabel('Displacement')

ax.set_title('Relationship between cylinders and displacement')
```

首先，我们加载 Matplotlib 库并对其进行设置。

有关这些 Matplotlib 命令的更详细解释，请参阅*绘制直方图*配方。

接下来，我们创建一个图形并向其添加一个子图。然后，我们使用我们的数据绘制散点图；*x*轴将代表汽缸数，*y*轴将代表排量。最后，我们设置轴标签和图表标题。

最终结果如下所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00105.jpeg)

# 还有更多...

您可以使用`bokeh`创建前面图表的交互版本：

```py
%%local 
from bokeh.io import show
from bokeh.plotting import figure
from bokeh.io import output_notebook
output_notebook()

p = figure(title = 'Relationship between cylinders and displacement')
p.xaxis.axis_label = 'Cylinders'
p.yaxis.axis_label = 'Displacement'

p.circle( list(scatter_source['Cylinders'])
         , list(scatter_source['Displacement'])
         , fill_alpha=0.2, size=10)

show(p)
```

首先，我们创建画布，即我们将绘图的图形。接下来，我们设置我们的标签。最后，我们使用`.circle(...)`方法在画布上绘制点。

最终结果如下所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/pyspark-cb/img/00106.jpeg)
