# Flink 学习手册（二）

> 原文：[`zh.annas-archive.org/md5/0715B65CE6CD5C69C124166C204B4830`](https://zh.annas-archive.org/md5/0715B65CE6CD5C69C124166C204B4830)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：使用表 API 进行数据处理

在前几章中，我们谈到了 Apache Flink 提供的批处理和流处理数据处理 API。在本章中，我们将讨论 Table API，它是 Flink 中用于数据处理的 SQL 接口。Table API 操作的是可以从数据集和数据流中创建的表接口。一旦数据集/数据流被注册为表，我们就可以自由地应用关系操作，如聚合、连接和选择。

表也可以像常规 SQL 查询一样进行查询。一旦操作完成，我们需要将表转换回数据集或数据流。Apache Flink 在内部使用另一个名为 Apache Calcite 的开源项目来优化这些查询转换。

在本章中，我们将涵盖以下主题：

+   注册表

+   访问已注册的表

+   操作员

+   数据类型

+   SQL

现在让我们开始吧。

为了使用 Table API，我们需要做的第一件事是创建一个 Java Maven 项目，并在其中添加以下依赖项：

```java
  <dependency> 
      <groupId>org.apache.flink</groupId> 
      <artifactId>flink-table_2.11</artifactId> 
      <version>1.1.4</version> 
    </dependency> 

```

这个依赖项将在你的类路径中下载所有必需的 JAR 包。下载完成后，我们就可以使用 Table API 了。

# 注册表

为了对数据集/数据流进行操作，首先我们需要在`TableEnvironment`中注册一个表。一旦表以唯一名称注册，就可以轻松地从`TableEnvironment`中访问。

`TableEnvironment`维护一个内部表目录用于表注册。以下图表显示了细节：

![注册表](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-flink/img/B05653_image1.jpg)

拥有唯一的表名非常重要，否则你会得到一个异常。

## 注册数据集

为了在数据集上执行 SQL 操作，我们需要在`BatchTableEnvironment`中将其注册为表。在注册表时，我们需要定义一个 Java POJO 类。

例如，假设我们需要注册一个名为 Word Count 的数据集。这个表中的每条记录都有单词和频率属性。相同的 Java POJO 如下所示：

```java
public static class WC { 
    public String word; 
    public long frequency; 
    public WC(){ 
    } 

    public WC(String word, long frequency) { 
      this.word = word; 
      this.frequency = frequency; 
    } 

    @Override 
    public String toString() { 
      return "WC " + word + " " + frequency; 
    } 
  } 

```

在 Scala 中，相同的类可以定义如下：

```java
case class WordCount(word: String, frequency: Long) 

```

现在我们可以注册这个表了。

在 Java 中：

```java
ExecutionEnvironment env = ExecutionEnvironment.getExecutionEnvironment(); 

BatchTableEnvironment tEnv = TableEnvironment.getTableEnvironment(env); 

DataSet<WC> input = env.fromElements(new WC("Hello", 1), new WC("World", 1), new WC("Hello", 1)); 

// register the DataSet as table "WordCount" 
tEnv.registerDataSet("WordCount", input, "word, frequency"); 

```

在 Scala 中：

```java
val env = ExecutionEnvironment.getExecutionEnvironment 

val tEnv = TableEnvironment.getTableEnvironment(env) 

val input = env.fromElements(WordCount("hello", 1), WordCount("hello", 1), WordCount("world", 1), WordCount("hello", 1)) 

//register the dataset  
tEnv.registerDataSet("WordCount", input, 'word, 'frequency) 

```

### 注意

请注意，数据集表的名称不能匹配`^_DataSetTable_[0-9]+`模式，因为它保留用于内部内存使用。

## 注册数据流

与数据集类似，我们也可以在`StreamTableEnvironment`中注册数据流。在注册表时，我们需要定义一个 Java POJO 类。

例如，假设我们需要注册一个名为 Word Count 的数据流。这个表中的每条记录都有一个单词和频率属性。相同的 Java POJO 如下所示：

```java
public static class WC { 
    public String word; 
    public long frequency; 

    public WC() { 
    }s 
    public WC(String word, long frequency) { 
      this.word = word; 
      this.frequency = frequency; 
    } 

    @Override 
    public String toString() { 
      return "WC " + word + " " + frequency; 
    } 
  } 

```

在 Scala 中，相同的类可以定义如下：

```java
case class WordCount(word: String, frequency: Long) 

```

现在我们可以注册这个表了。

在 Java 中：

```java
StreamExecutionEnvironment env = StreamExecutionEnvironment.getExecutionEnvironment(); 
    StreamTableEnvironment tEnv = TableEnvironment.getTableEnvironment(env); 

    DataStream<WC> input = env.fromElements(new WC("Hello", 1), new WC("World", 1), new WC("Hello", 1)); 

    // register the DataStream as table "WordCount" 
    tEnv.registerDataStream("WordCount", input, "word, frequency"); 

```

在 Scala 中：

```java
val env = StreamExecutionEnvironment.getExecutionEnvironment 

val tEnv = TableEnvironment.getTableEnvironment(env) 

val input = env.fromElements(WordCount("hello", 1), WordCount("hello", 1), WordCount("world", 1), WordCount("hello", 1)) 

//register the dataset  
tEnv.registerDataStream("WordCount", input, 'word, 'frequency) 

```

### 注意

请注意，数据流表的名称不能匹配`^_DataStreamTable_[0-9]+`模式，因为它保留用于内部内存使用。

## 注册表

与数据集和数据流类似，我们也可以注册来自 Table API 的表。

在 Java 中：

```java
ExecutionEnvironment env = ExecutionEnvironment.getExecutionEnvironment(); 
BatchTableEnvironment tEnv = TableEnvironment.getTableEnvironment(env); 

DataSet<WC> input = env.fromElements(new WC("Hello", 1), new WC("World", 1), new WC("Hello", 1)); 

tEnv.registerDataSet("WordCount", input, "word, frequency"); 

Table selectedTable = tEnv 
        .sql("SELECT word, SUM(frequency) as frequency FROM WordCount GROUP BY word having word = 'Hello'"); 

tEnv.registerTable("selected", selectedTable); 

```

在 Scala 中：

```java
val env = ExecutionEnvironment.getExecutionEnvironment 

val tEnv = TableEnvironment.getTableEnvironment(env) 

val input = env.fromElements(WordCount("hello", 1), WordCount("hello", 1), WordCount("world", 1), WordCount("hello", 1)) 

tEnv.registerDataSet("WordCount", input, 'word, 'frequency) 

val table = tEnv.sql("SELECT word, SUM(frequency) FROM WordCount GROUP BY word") 

val selected = tEnv.sql("SELECT word, SUM(frequency) FROM WordCount GROUP BY word where word = 'hello'") 
    tEnv.registerTable("selected", selected) 

```

## 注册外部表源

Flink 允许我们使用`TableSource`从源中注册外部表。表源可以让我们访问存储在数据库中的数据，如 MySQL 和 Hbase，在文件系统中的数据，如 CSV、Parquet 和 ORC，或者还可以读取消息系统，如 RabbitMQ 和 Kafka。

目前，Flink 允许使用 CSV 源从 CSV 文件中读取数据，并使用 Kafka 源从 Kafka 主题中读取 JSON 数据。

### CSV 表源

现在让我们看看如何直接使用 CSV 源读取数据，然后在表环境中注册源。

CSV 源默认在`flink-table`API JAR 中可用，因此不需要添加任何其他额外的 Maven 依赖项。以下依赖项就足够了：

```java
    <dependency> 
      <groupId>org.apache.flink</groupId> 
      <artifactId>flink-table_2.11</artifactId> 
      <version>1.1.4</version> 
    </dependency> 

```

以下代码片段显示了如何读取 CSV 文件并注册表源。

在 Java 中：

```java
ExecutionEnvironment env = ExecutionEnvironment.getExecutionEnvironment(); 
BatchTableEnvironment tableEnv = TableEnvironment.getTableEnvironment(env); 

TableSource orders = new CsvTableSource("/path/to/file", ...) 

// register a TableSource as external table "orders" 
tableEnv.registerTableSource("orders", orders) 

```

在 Scala 中：

```java
val env = ExecutionEnvironment.getExecutionEnvironment 
val tableEnv = TableEnvironment.getTableEnvironment(env) 

val orders: TableSource = new CsvTableSource("/path/to/file", ...) 

// register a TableSource as external table "orders" 
tableEnv.registerTableSource("orders", orders) 

```

### Kafka JSON 表源

我们还可以在表环境中注册 Kafka JSON 表源。为了使用此 API，我们需要添加以下两个依赖项：

第一个是 Table API：

```java
<dependency> 
      <groupId>org.apache.flink</groupId> 
      <artifactId>flink-table_2.11</artifactId> 
      <version>1.1.4</version> 
    </dependency> 

```

第二个依赖项将是 Kafka Flink 连接器：

+   如果您使用 Kafka 0.8，请应用：

```java
        <dependency> 
            <groupId>org.apache.flink</groupId> 
            <artifactId>flink-connector-kafka-0.8_2.11</artifactId> 
            <version>1.1.4</version> 
        </dependency> 

```

+   如果您使用 Kafka 0.9，请应用：

```java
        <dependency> 
            <groupId>org.apache.flink</groupId> 
            <artifactId>flink-connector-kafka-0.9_2.11</artifactId> 
            <version>1.1.4</version> 
        </dependency> 

```

现在我们需要按照以下代码片段中所示编写代码：

```java
String[] fields =  new String[] { "id", "name", "price"}; 
Class<?>[] types = new Class<?>[] { Integer.class, String.class, Double.class }; 

KafkaJsonTableSource kafkaTableSource = new Kafka08JsonTableSource( 
    kafkaTopic, 
    kafkaProperties, 
    fields, 
    types); 

tableEnvironment.registerTableSource("kafka-source", kafkaTableSource); 
Table result = tableEnvironment.ingest("kafka-source"); 

```

在前面的代码中，我们为 Kafka 0.8 定义了 Kafka 源，然后在表环境中注册了该源。

# 访问注册的表

一旦表被注册，我们可以从`TableEnvironment`中很容易地访问它，如下所示：

```java
tableEnvironment.scan("tableName") 

```

前面的语句扫描了以名称`"tableName"`注册的表在`BatchTableEnvironment`中：

```java
tableEnvironment.ingest("tableName") 

```

前面的语句摄取了以名称`"tableName"`注册的表在`StreamTableEnvironment`中：

# 操作符

Flink 的 Table API 提供了各种操作符作为其特定领域语言的一部分。大多数操作符都在 Java 和 Scala API 中可用。让我们逐个查看这些操作符。

## select 操作符

`select`操作符类似于 SQL select 操作符，允许您选择表中的各种属性/列。

在 Java 中：

```java
Table result = in.select("id, name"); 
Table result = in.select("*"); 

```

在 Scala 中：

```java
val result = in.select('id, 'name); 
val result = in.select('*); 

```

## where 操作符

`where`操作符用于过滤结果。

在 Java 中：

```java
Table result = in.where("id = '101'"); 

```

在 Scala 中：

```java
val result = in.where('id == "101"); 

```

## 过滤器操作符

`filter`操作符可以用作`where`操作符的替代。

在 Java 中：

```java
Table result = in.filter("id = '101'"); 

```

在 Scala 中：

```java
val result = in.filter('id == "101"); 

```

## as 操作符

`as`操作符用于重命名字段：

在 Java 中：

```java
Table in = tableEnv.fromDataSet(ds, "id, name"); 
Table result = in.as("order_id, order_name"); 

```

在 Scala 中：

```java
val in = ds.toTable(tableEnv).as('order_id, 'order_name ) 

```

## groupBy 操作符

这类似于 SQL `groupBy`操作，根据给定的属性对结果进行聚合。

在 Java 中：

```java
Table result = in.groupBy("company"); 

```

在 Scala 中：

```java
val in = in.groupBy('company) 

```

## join 操作符

`join`操作符用于连接表。我们必须至少指定一个相等的连接条件。

在 Java 中：

```java
Table employee = tableEnv.fromDataSet(emp, "e_id, e_name, deptId"); 

Table dept = tableEnv.fromDataSet(dept, "d_id, d_name"); 

Table result = employee.join(dept).where("deptId = d_id").select("e_id, e_name, d_name"); 

```

在 Scala 中：

```java
val employee = empDS.toTable(tableEnv, 'e_id, 'e_name, 'deptId); 

val dept = deptDS.toTable(tableEnv, 'd_id, 'd_name); 

Table result = employee.join(dept).where('deptId == 'd_id).select('e_id, 'e_name, 'd_name); 

```

## leftOuterJoin 操作符

`leftOuterJoin`操作符通过从左侧指定的表中获取所有值并仅从右侧表中选择匹配的值来连接两个表。我们必须至少指定一个相等的连接条件。

在 Java 中：

```java
Table employee = tableEnv.fromDataSet(emp, "e_id, e_name, deptId"); 

Table dept = tableEnv.fromDataSet(dept, "d_id, d_name"); 

Table result = employee.leftOuterJoin(dept).where("deptId = d_id").select("e_id, e_name, d_name"); 

```

在 Scala 中：

```java
val employee = empDS.toTable(tableEnv, 'e_id, 'e_name, 'deptId); 

val dept = deptDS.toTable(tableEnv, 'd_id, 'd_name); 

Table result = employee.leftOuterJoin(dept).where('deptId == 'd_id).select('e_id, 'e_name, 'd_name); 

```

## rightOuterJoin 操作符

`rightOuterJoin`操作符通过从右侧指定的表中获取所有值并仅从左侧表中选择匹配的值来连接两个表。我们必须至少指定一个相等的连接条件。

在 Java 中：

```java
Table employee = tableEnv.fromDataSet(emp, "e_id, e_name, deptId"); 

Table dept = tableEnv.fromDataSet(dept, "d_id, d_name"); 

Table result = employee.rightOuterJoin(dept).where("deptId = d_id").select("e_id, e_name, d_name"); 

```

在 Scala 中：

```java
val employee = empDS.toTable(tableEnv, 'e_id, 'e_name, 'deptId); 

val dept = deptDS.toTable(tableEnv, 'd_id, 'd_name); 

Table result = employee.rightOuterJoin(dept).where('deptId == 'd_id).select('e_id, 'e_name, 'd_name); 

```

## fullOuterJoin 操作符

`fullOuterJoin`操作符通过从两个表中获取所有值来连接两个表。我们必须至少指定一个相等的连接条件。

在 Java 中：

```java
Table employee = tableEnv.fromDataSet(emp, "e_id, e_name, deptId"); 

Table dept = tableEnv.fromDataSet(dept, "d_id, d_name"); 

Table result = employee.fullOuterJoin(dept).where("deptId = d_id").select("e_id, e_name, d_name"); 

```

在 Scala 中：

```java
val employee = empDS.toTable(tableEnv, 'e_id, 'e_name, 'deptId); 

val dept = deptDS.toTable(tableEnv, 'd_id, 'd_name); 

Table result = employee.fullOuterJoin(dept).where('deptId == 'd_id).select('e_id, 'e_name, 'd_name); 

```

## union 操作符

`union`操作符合并两个相似的表。它删除结果表中的重复值。

在 Java 中：

```java
Table employee1 = tableEnv.fromDataSet(emp, "e_id, e_name, deptId"); 

Table employee2 = tableEnv.fromDataSet(emp, "e_id, e_name, deptId"); 

Table result = employee1.union(employee2); 

```

在 Scala 中：

```java
val employee1 = empDS.toTable(tableEnv, 'e_id, 'e_name, 'deptId) 

val employee2 = empDS.toTable(tableEnv, 'e_id, 'e_name, 'deptId) 

Table result = employee1.union(employee2) 

```

## unionAll 操作符

`unionAll`操作符合并两个相似的表。

在 Java 中：

```java
Table employee1 = tableEnv.fromDataSet(emp, "e_id, e_name, deptId"); 

Table employee2 = tableEnv.fromDataSet(emp, "e_id, e_name, deptId"); 

Table result = employee1.unionAll(employee2); 

```

在 Scala 中：

```java
val employee1 = empDS.toTable(tableEnv, 'e_id, 'e_name, 'deptId) 

val employee2 = empDS.toTable(tableEnv, 'e_id, 'e_name, 'deptId) 

Table result = employee1.unionAll(employee2) 

```

## intersect 操作符

`intersect`操作符返回两个表中匹配的值。它确保结果表没有任何重复项。

在 Java 中：

```java
Table employee1 = tableEnv.fromDataSet(emp, "e_id, e_name, deptId"); 

Table employee2 = tableEnv.fromDataSet(emp, "e_id, e_name, deptId"); 

Table result = employee1.intersect(employee2); 

```

在 Scala 中：

```java
val employee1 = empDS.toTable(tableEnv, 'e_id, 'e_name, 'deptId) 

val employee2 = empDS.toTable(tableEnv, 'e_id, 'e_name, 'deptId) 

Table result = employee1.intersect(employee2) 

```

## intersectAll 操作符

`intersectAll`操作符返回两个表中匹配的值。结果表可能有重复记录。

在 Java 中：

```java
Table employee1 = tableEnv.fromDataSet(emp, "e_id, e_name, deptId"); 

Table employee2 = tableEnv.fromDataSet(emp, "e_id, e_name, deptId"); 

Table result = employee1.intersectAll(employee2); 

```

在 Scala 中：

```java
val employee1 = empDS.toTable(tableEnv, 'e_id, 'e_name, 'deptId) 

val employee2 = empDS.toTable(tableEnv, 'e_id, 'e_name, 'deptId) 

Table result = employee1.intersectAll(employee2) 

```

## minus 操作符

`minus`操作符返回左表中不存在于右表中的记录。它确保结果表没有任何重复项。

在 Java 中：

```java
Table employee1 = tableEnv.fromDataSet(emp, "e_id, e_name, deptId"); 

Table employee2 = tableEnv.fromDataSet(emp, "e_id, e_name, deptId"); 

Table result = employee1.minus(employee2); 

```

在 Scala 中：

```java
val employee1 = empDS.toTable(tableEnv, 'e_id, 'e_name, 'deptId) 

val employee2 = empDS.toTable(tableEnv, 'e_id, 'e_name, 'deptId) 

Table result = employee1.minus(employee2) 

```

## minusAll 操作符

`minusAll`操作符返回左表中不存在于右表中的记录。结果表可能有重复记录。

在 Java 中：

```java
Table employee1 = tableEnv.fromDataSet(emp, "e_id, e_name, deptId"); 

Table employee2 = tableEnv.fromDataSet(emp, "e_id, e_name, deptId"); 

Table result = employee1.minusAll(employee2); 

```

在 Scala 中：

```java
val employee1 = empDS.toTable(tableEnv, 'e_id, 'e_name, 'deptId) 

val employee2 = empDS.toTable(tableEnv, 'e_id, 'e_name, 'deptId) 

Table result = employee1.minusAll(employee2) 

```

## distinct 操作符

`distinct`操作符仅从表中返回唯一值记录。

在 Java 中：

```java
Table employee1 = tableEnv.fromDataSet(emp, "e_id, e_name, deptId"); 

Table result = employee1.distinct(); 

```

在 Scala 中：

```java
val employee1 = empDS.toTable(tableEnv, 'e_id, 'e_name, 'deptId) 

Table result = employee1.distinct() 

```

## orderBy 操作符

`orderBy`操作符返回在全局并行分区中排序的记录。您可以选择升序或降序的顺序。

在 Java 中：

```java
Table employee1 = tableEnv.fromDataSet(emp, "e_id, e_name, deptId"); 

Table result = employee1.orderBy("e_id.asc"); 

```

在 Scala 中：

```java
val employee1 = empDS.toTable(tableEnv, 'e_id, 'e_name, 'deptId) 

Table result = employee1.orderBy('e_id.asc) 

```

## limit 操作符

`limit`操作符限制了从给定偏移量排序的记录在全局并行分区中。

在 Java 中：

```java
Table employee1 = tableEnv.fromDataSet(emp, "e_id, e_name, deptId"); 

//returns records from 6th record 
Table result = employee1.orderBy("e_id.asc").limit(5); 

//returns 5 records from 4th record 
Table result1 = employee1.orderBy("e_id.asc").limit(3,5); 

```

在 Scala 中：

```java
val employee1 = empDS.toTable(tableEnv, 'e_id, 'e_name, 'deptId) 
//returns records from 6th record 
Table result = employee1.orderBy('e_id.asc).limit(5) 
//returns 5 records from 4th record 
Table result = employee1.orderBy('e_id.asc).limit(3,5) 

```

## 数据类型

表 API 支持常见的 SQL 数据类型，可以轻松使用。在内部，它使用`TypeInformation`来识别各种数据类型。目前它不支持所有 Flink 数据类型：

| 表 API | SQL | Java 类型 |
| --- | --- | --- |
| `Types.STRING` | `VARCHAR` | `java.lang.String` |
| `Types.BOOLEAN` | `BOOLEAN` | `java.lang.Boolean` |
| `Types.BYTE` | `TINYINT` | `java.lang.Byte` |
| `Types.SHORT` | `SMALLINT` | `java.lang.Short` |
| `Types.INT` | `INTEGER`，`INT` | `java.lang.Integer` |
| `Types.LONG` | `BIGINT` | `java.lang.Long` |
| `Types.FLOAT` | `REAL`，`FLOAT` | `java.lang.Float` |
| `Types.DOUBLE` | `DOUBLE` | `java.lang.Double` |
| `Types.DECIMAL` | `DECIMAL` | `java.math.BigDecimal` |
| `Types.DATE` | `DATE` | `java.sql.Date` |
| `Types.TIME` | `TIME` | `java.sql.Time` |
| `Types.TIMESTAMP` | `TIMESTAMP(3)` | `java.sql.Timestamp` |
| `Types.INTERVAL_MONTHS` | INTERVAL YEAR TO MONTH | `java.lang.Integer` |
| `Types.INTERVAL_MILLIS` | INTERVAL DAY TO SECOND(3) | `java.lang.Long` |

随着社区的持续发展和支持，将很快支持更多的数据类型。

# SQL

表 API 还允许我们使用`sql()`方法编写自由形式的 SQL 查询。该方法在内部还使用 Apache Calcite 进行 SQL 语法验证和优化。它执行查询并以表格格式返回结果。稍后，表格可以再次转换为数据集或数据流或`TableSink`以进行进一步处理。

这里需要注意的一点是，为了让 SQL 方法访问表，它们必须在`TableEnvironment`中注册。

SQL 方法不断添加更多支持，因此如果不支持任何语法，将出现`TableException`错误。

现在让我们看看如何在数据集和数据流上使用 SQL 方法。

## 数据流上的 SQL

可以使用`SELECT STREAM`关键字在使用`TableEnvironment`注册的数据流上执行 SQL 查询。数据集和数据流之间的大部分 SQL 语法是通用的。要了解更多关于流语法的信息，Apache Calcite 的 Streams 文档会很有帮助。可以在以下网址找到：[`calcite.apache.org/docs/stream.html`](https://calcite.apache.org/docs/stream.html)。

假设我们想要分析定义为（`id`，`name`，`stock`）的产品模式。需要使用`sql()`方法编写以下代码。

在 Java 中：

```java
StreamExecutionEnvironment env = StreamExecutionEnvironment.getExecutionEnvironment(); 
StreamTableEnvironment tableEnv = TableEnvironment.getTableEnvironment(env); 

DataStream<Tuple3<Long, String, Integer>> ds = env.addSource(...); 
// register the DataStream as table "Products" 
tableEnv.registerDataStream("Products", ds, "id, name, stock"); 
// run a SQL query on the Table and retrieve the result as a new Table 
Table result = tableEnv.sql( 
  "SELECT STREAM * FROM Products WHERE name LIKE '%Apple%'"); 

```

在 Scala 中：

```java
val env = StreamExecutionEnvironment.getExecutionEnvironment 
val tEnv = TableEnvironment.getTableEnvironment(env) 

val ds: DataStream[(Long, String, Integer)] = env.addSource(...) 
// register the DataStream under the name "Products" 
tableEnv.registerDataStream("Products", ds, 'id, 'name, 'stock) 
// run a SQL query on the Table and retrieve the result as a new Table 
val result = tableEnv.sql( 
  "SELECT STREAM * FROM Products WHERE name LIKE '%Apple%'") 

```

表 API 使用类似于 Java 的词法策略来正确定义查询。这意味着标识符的大小写保留，并且它们是区分大小写匹配的。如果您的任何标识符包含非字母数字字符，则可以使用反引号引用它们。

例如，如果要定义一个名为`'my col'`的列，则需要使用如下所示的反引号：

```java
"SELECT col as `my col` FROM table " 

```

## 支持的 SQL 语法

正如前面所述，Flink 使用 Apache Calcite 来验证和优化 SQL 查询。在当前版本中，支持以下**巴科斯-瑙尔范式**（**BNF**）：

```java
query: 
  values 
  | { 
      select 
      | selectWithoutFrom 
      | query UNION [ ALL ] query 
      | query EXCEPT query 
      | query INTERSECT query 
    } 
    [ ORDER BY orderItem [, orderItem ]* ] 
    [ LIMIT { count | ALL } ] 
    [ OFFSET start { ROW | ROWS } ] 
    [ FETCH { FIRST | NEXT } [ count ] { ROW | ROWS } ONLY] 

orderItem: 
  expression [ ASC | DESC ] 

select: 
  SELECT [ STREAM ] [ ALL | DISTINCT ] 
  { * | projectItem [, projectItem ]* } 
  FROM tableExpression 
  [ WHERE booleanExpression ] 
  [ GROUP BY { groupItem [, groupItem ]* } ] 
  [ HAVING booleanExpression ] 

selectWithoutFrom: 
  SELECT [ ALL | DISTINCT ] 
  { * | projectItem [, projectItem ]* } 

projectItem: 
  expression [ [ AS ] columnAlias ] 
  | tableAlias . * 

tableExpression: 
  tableReference [, tableReference ]* 
  | tableExpression [ NATURAL ] [ LEFT | RIGHT | FULL ] JOIN tableExpression [ joinCondition ] 

joinCondition: 
  ON booleanExpression 
  | USING '(' column [, column ]* ')' 

tableReference: 
  tablePrimary 
  [ [ AS ] alias [ '(' columnAlias [, columnAlias ]* ')' ] ] 

tablePrimary: 
  [ TABLE ] [ [ catalogName . ] schemaName . ] tableName 

values: 
  VALUES expression [, expression ]* 

groupItem: 
  expression 
  | '(' ')' 
  | '(' expression [, expression ]* ')' 

```

## 标量函数

表 API 和 SQL 支持各种内置的标量函数。让我们逐一了解这些。

### 表 API 中的标量函数

以下是表 API 中支持的标量函数列表：

| **Java 函数** | **Scala 函数** | **描述** |
| --- | --- | --- |
| `ANY.isNull` | `ANY.isNull` | 如果给定的表达式为空，则返回`true`。 |
| `ANY.isNotNull` | `ANY.isNotNull` | 如果给定的表达式不为空，则返回`true`。 |
| `BOOLEAN.isTrue` | `BOOLEAN.isTrue` | 如果给定的布尔表达式为`true`，则返回`true`。否则返回`False`。 |
| `BOOLEAN.isFalse` | `BOOLEAN.isFalse` | 如果给定的布尔表达式为 false，则返回`true`。否则返回`False`。 |
| `NUMERIC.log10()` | `NUMERIC.log10()` | 计算给定值的以 10 为底的对数。 |
| `NUMERIC.ln()` | `NUMERIC.ln()` | 计算给定值的自然对数。 |
| `NUMERIC.power(NUMERIC)` | `NUMERIC.power(NUMERIC)` | 计算给定数字的另一个值的幂。 |
| `NUMERIC.abs()` | `NUMERIC.abs()` | 计算给定值的绝对值。 |
| `NUMERIC.floor()` | `NUMERIC.floor()` | 计算小于或等于给定数字的最大整数。 |
| `NUMERIC.ceil()` | `NUMERIC.ceil()` | 计算大于或等于给定数字的最小整数。 |
| `STRING.substring(INT, INT)` | `STRING.substring(INT, INT)` | 在给定索引处创建给定长度的字符串子串 |
| `STRING.substring(INT)` | `STRING.substring(INT)` | 创建给定字符串的子串，从给定索引开始到末尾。起始索引从 1 开始，包括在内。 |
| `STRING.trim(LEADING, STRING)` `STRING.trim(TRAILING, STRING)` `STRING.trim(BOTH, STRING)` `STRING.trim(BOTH)` `STRING.trim()` | `STRING.trim(leading = true, trailing = true, character = " ")` | 从给定字符串中移除前导和/或尾随字符。默认情况下，两侧的空格将被移除。 |
| `STRING.charLength()` | `STRING.charLength()` | 返回字符串的长度。 |
| `STRING.upperCase()` | `STRING.upperCase()` | 使用默认区域设置的规则将字符串中的所有字符转换为大写。 |
| `STRING.lowerCase()` | `STRING.lowerCase()` | 使用默认区域设置的规则将字符串中的所有字符转换为小写。 |
| `STRING.initCap()` | `STRING.initCap()` | 将字符串中每个单词的初始字母转换为大写。假设字符串只包含`[A-Za-z0-9]`，其他所有内容都视为空格。 |
| `STRING.like(STRING)` | `STRING.like(STRING)` | 如果字符串与指定的 LIKE 模式匹配，则返回 true。例如，`"Jo_n%"`匹配以`"Jo(任意字母)n"`开头的所有字符串。 |
| `STRING.similar(STRING)` | `STRING.similar(STRING)` | 如果字符串与指定的 SQL 正则表达式模式匹配，则返回`true`。例如，`"A+"`匹配至少包含一个`"A"`的所有字符串。 |
| `STRING.toDate()` | `STRING.toDate` | 将形式为`"yy-mm-dd"`的日期字符串解析为 SQL 日期。 |
| `STRING.toTime()` | `STRING.toTime` | 将形式为`"hh:mm:ss"`的时间字符串解析为 SQL 时间。 |
| `STRING.toTimestamp()` | `STRING.toTimestamp` | 将形式为`"yy-mm-dd hh:mm:ss.fff"`的时间戳字符串解析为 SQL 时间戳。 |
| `TEMPORAL.extract(TIMEINTERVALUNIT)` | NA | 提取时间点或时间间隔的部分。将该部分作为长整型值返回。例如，`2006-06-05 .toDate.extract(DAY)` 导致 `5`。 |
| `TIMEPOINT.floor(TIMEINTERVALUNIT)` | `TIMEPOINT.floor(TimeIntervalUnit)` | 将时间点向下舍入到给定的单位。例如，`"12:44:31".toDate.floor(MINUTE)` 导致 `12:44:00`。 |
| `TIMEPOINT.ceil(TIMEINTERVALUNIT)` | `TIMEPOINT.ceil(TimeIntervalUnit)` | 将时间点四舍五入到给定的单位。例如，`"12:44:31".toTime.floor(MINUTE)` 导致 `12:45:00`。 |
| `currentDate()` | `currentDate()` | 返回 UTC 时区的当前 SQL 日期。 |
| `currentTime()` | `currentTime()` | 返回 UTC 时区的当前 SQL 时间。 |
| `currentTimestamp()` | `currentTimestamp()` | 返回 UTC 时区的当前 SQL 时间戳。 |
| `localTime()` | `localTime()` | 返回本地时区的当前 SQL 时间。 |
| `localTimestamp()` | `localTimestamp()` | 返回本地时区的当前 SQL 时间戳。 |

## Scala functions in SQL

以下是`sql()`方法中支持的标量函数列表：

| 函数 | 描述 |
| --- | --- |
| `EXP(NUMERIC)` | 计算给定幂的自然对数。 |
| `LOG10(NUMERIC)` | 计算给定值的以 10 为底的对数。 |
| `LN(NUMERIC)` | 计算给定值的自然对数。 |
| `POWER(NUMERIC, NUMERIC)` | 计算给定数字的另一个值的幂。 |
| `ABS(NUMERIC)` | 计算给定值的绝对值。 |
| `FLOOR(NUMERIC)` | 计算小于或等于给定数字的最大整数。 |
| `CEIL(NUMERIC)` | 计算大于或等于给定数字的最小整数。 |
| `SUBSTRING(VARCHAR, INT, INT) SUBSTRING(VARCHAR FROM INT FOR INT)` | 从给定索引开始创建给定长度的字符串的子字符串。索引从 1 开始，是包含的，即包括索引处的字符。子字符串具有指定的长度或更少。 |
| `SUBSTRING(VARCHAR, INT)``SUBSTRING(VARCHAR FROM INT)` | 从给定索引开始创建给定字符串的子字符串直到末尾。起始索引从 1 开始，是包含的。 |
| `TRIM(LEADING VARCHAR FROM VARCHAR) TRIM(TRAILING VARCHAR FROM VARCHAR) TRIM(BOTH VARCHAR FROM VARCHAR) TRIM(VARCHAR)` | 从给定的字符串中移除前导和/或尾随字符。默认情况下，两侧的空格将被移除。 |
| `CHAR_LENGTH(VARCHAR)` | 返回字符串的长度。 |
| `UPPER(VARCHAR)` | 使用默认区域设置的规则将字符串中的所有字符转换为大写。 |
| `LOWER(VARCHAR)` | 使用默认区域设置的规则将字符串中的所有字符转换为小写。 |
| `INITCAP(VARCHAR)` | 将字符串中每个单词的首字母转换为大写。假定字符串仅包含`[A-Za-z0-9]`，其他所有内容都视为空格。 |
| `VARCHAR LIKE VARCHAR` | 如果字符串与指定的 LIKE 模式匹配，则返回 true。例如，`"Jo_n%"`匹配所有以`"Jo(任意字母)n"`开头的字符串。 |
| `VARCHAR SIMILAR TO VARCHAR` | 如果字符串与指定的 SQL 正则表达式模式匹配，则返回 true。例如，`"A+"`匹配至少包含一个`"A"`的所有字符串。 |
| `DATE VARCHAR` | 将形式为`"yy-mm-dd"`的日期字符串解析为 SQL 日期。 |
| `TIME VARCHAR` | 将形式为`"hh:mm:ss"`的时间字符串解析为 SQL 时间。 |
| `TIMESTAMP VARCHAR` | 将形式为`"yy-mm-dd hh:mm:ss.fff"`的时间戳字符串解析为 SQL 时间戳。 |
| `EXTRACT(TIMEINTERVALUNIT FROM TEMPORAL)` | 提取时间点或时间间隔的部分。将该部分作为长值返回。例如，`EXTRACT(DAY FROM DATE '2006-06-05')`得到`5`。 |
| `FLOOR(TIMEPOINT TO TIMEINTERVALUNIT)` | 将时间点向下舍入到给定的单位。例如，`FLOOR(TIME '12:44:31' TO MINUTE)`得到`12:44:00`。 |
| `CEIL(TIMEPOINT TO TIMEINTERVALUNIT)` | 将时间点向上舍入到给定的单位。例如，`CEIL(TIME '12:44:31' TO MINUTE)`得到`12:45:00`。 |
| `CURRENT_DATE` | 返回 UTC 时区中的当前 SQL 日期。 |
| `CURRENT_TIME` | 返回 UTC 时区中的当前 SQL 时间。 |
| `CURRENT_TIMESTAMP` | 返回 UTC 时区中的当前 SQL 时间戳。 |
| `LOCALTIME` | 返回本地时区中的当前 SQL 时间。 |
| `LOCALTIMESTAMP` | 返回本地时区中的当前 SQL 时间戳。 |

# 使用案例 - 使用 Flink Table API 进行运动员数据洞察

现在我们已经了解了 Table API 的细节，让我们尝试将这些知识应用到一个真实的用例中。假设我们手头有一个数据集，其中包含有关奥运运动员及其在各种比赛中的表现的信息。

样本数据如下表所示：

| **运动员** | **国家** | **年份** | **比赛** | **金牌** | **银牌** | **铜牌** | **总计** |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 杨伊琳 | 中国 | 2008 | 体操 | 1 | 0 | 2 | 3 |
| 利塞尔·琼斯 | 澳大利亚 | 2000 | 游泳 | 0 | 2 | 0 | 2 |
| 高基贤 | 韩国 | 2002 | 短道速滑 | 1 | 1 | 0 | 2 |
| 陈若琳 | 中国 | 2008 | 跳水 | 2 | 0 | 0 | 2 |
| 凯蒂·莱德基 | 美国 | 2012 | 游泳 | 1 | 0 | 0 | 1 |
| 鲁塔·梅卢蒂特 | 立陶宛 | 2012 | 游泳 | 1 | 0 | 0 | 1 |
| 丹尼尔·吉尔塔 | 匈牙利 | 2004 | 游泳 | 0 | 1 | 0 | 1 |
| 阿里安娜·方塔纳 | 意大利 | 2006 | 短道速滑 | 0 | 0 | 1 | 1 |
| 奥尔加·格拉茨基赫 | 俄罗斯 | 2004 | 韵律体操 | 1 | 0 | 0 | 1 |
| Kharikleia Pantazi | 希腊 | 2000 | 韵律体操 | 0 | 0 | 1 | 1 |
| Kim Martin | 瑞典 | 2002 | 冰球 | 0 | 0 | 1 | 1 |
| Kyla Ross | 美国 | 2012 | 体操 | 1 | 0 | 0 | 1 |
| Gabriela Dragoi | 罗马尼亚 | 2008 | 体操 | 0 | 0 | 1 | 1 |
| Tasha Schwikert-Warren | 美国 | 2000 | 体操 | 0 | 0 | 1 | 1 |

现在我们想要得到答案，比如，每个国家或每个比赛赢得了多少枚奖牌。由于我们的数据是结构化数据，我们可以使用 Table API 以 SQL 方式查询数据。所以让我们开始吧。

可用的数据是以 CSV 格式提供的。因此，我们将使用 Flink API 提供的 CSV 阅读器，如下面的代码片段所示：

```java
ExecutionEnvironment env = ExecutionEnvironment.getExecutionEnvironment(); 
BatchTableEnvironment tableEnv = TableEnvironment.getTableEnvironment(env); 
DataSet<Record> csvInput = env 
          .readCsvFile("olympic-athletes.csv") 
          .pojoType(Record.class, "playerName", "country", "year",   
                    "game", "gold", "silver", "bronze", "total"); 

```

接下来，我们需要使用这个数据集创建一个表，并在 Table Environment 中注册它以进行进一步处理：

```java
Table atheltes = tableEnv.fromDataSet(csvInput); 
tableEnv.registerTable("athletes", atheltes); 

```

接下来，我们可以编写常规的 SQL 查询，以从数据中获取更多见解。或者我们可以使用 Table API 操作符来操作数据，如下面的代码片段所示：

```java
Table groupedByCountry = tableEnv.sql("SELECT country, SUM(total) as frequency FROM athletes group by country"); 
DataSet<Result> result = tableEnv.toDataSet(groupedByCountry, Result.class); 
result.print(); 
Table groupedByGame = atheltes.groupBy("game").select("game, total.sum as frequency"); 
DataSet<GameResult> gameResult = tableEnv.toDataSet(groupedByGame, GameResult.class); 
gameResult.print(); 

```

通过 Table API，我们可以以更简单的方式分析这样的数据。这个用例的完整代码可以在 GitHub 上找到：[`github.com/deshpandetanmay/mastering-flink/tree/master/chapter04/flink-table`](https://github.com/deshpandetanmay/mastering-flink/tree/master/chapter04/flink-table)。

# 总结

在本章中，我们了解了 Flink 支持的基于 SQL 的 API，称为 Table API。我们还学习了如何将数据集/流转换为表，使用`TableEnvironment`注册表、数据集和数据流，然后使用注册的表执行各种操作。对于来自 SQL 数据库背景的人来说，这个 API 是一种福音。

在下一章中，我们将讨论一个非常有趣的库，叫做**复杂事件处理**，以及如何将其用于解决各种业务用例。


# 第五章：复杂事件处理

在上一章中，我们谈到了 Apache Flink 提供的 Table API 以及我们如何使用它来处理关系数据结构。从本章开始，我们将开始学习有关 Apache Flink 提供的库以及如何将它们用于特定用例的更多信息。首先，让我们尝试了解一个名为**复杂事件处理**（**CEP**）的库。CEP 是一个非常有趣但复杂的主题，在各行业都有其价值。无论在哪里都有预期的事件流，人们自然希望在所有这些用例中执行复杂事件处理。让我们尝试了解 CEP 的全部内容。

# 什么是复杂事件处理？

CEP 分析高频率和低延迟发生的不同事件流。如今，各行业都可以找到流事件，例如：

+   在石油和天然气领域，传感器数据来自各种钻井工具或上游油管设备

+   在安全领域，活动数据、恶意软件信息和使用模式数据来自各种终端

+   在可穿戴设备领域，数据来自各种手腕带，包含有关您的心率、活动等信息

+   在银行领域，数据来自信用卡使用、银行活动等

分析变化模式以实时通知常规装配中的任何变化非常重要。CEP 可以理解事件流、子事件及其序列中的模式。CEP 有助于识别有意义的模式和无关事件之间的复杂关系，并实时或准实时发送通知以防止损害：

![什么是复杂事件处理？](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-flink/img/image_05_001.jpg)

上图显示了 CEP 流程的工作原理。尽管流程看起来很简单，但 CEP 具有各种能力，例如：

+   在输入事件流可用时立即生成结果的能力

+   提供诸如时间内聚合和两个感兴趣事件之间的超时等计算能力

+   提供在检测到复杂事件模式时实时/准实时警报和通知的能力

+   能够连接和关联异构源并分析其中的模式

+   实现高吞吐量、低延迟处理的能力

市场上有各种解决方案。随着大数据技术的进步，我们有多个选项，如 Apache Spark、Apache Samza、Apache Beam 等，但没有一个专门的库适用于所有解决方案。现在让我们尝试了解 Flink 的 CEP 库可以实现什么。

# Flink CEP

Apache Flink 提供了 Flink CEP 库，提供了执行复杂事件处理的 API。该库包括以下核心组件：

+   事件流

+   模式定义

+   模式检测

+   警报生成

![Flink CEP](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-flink/img/image_05_002.jpg)

Flink CEP 使用 Flink 的数据流 API 称为 DataStream。程序员需要定义要从事件流中检测到的模式，然后 Flink 的 CEP 引擎检测到模式并采取适当的操作，例如生成警报。

为了开始，我们需要添加以下 Maven 依赖项：

```java
<!-- https://mvnrepository.com/artifact/org.apache.flink/flink-cep-scala_2.10 --> 
<dependency> 
    <groupId>org.apache.flink</groupId> 
    <artifactId>flink-cep-scala_2.11</artifactId> 
    <version>1.1.4</version> 
</dependency> 

```

## 事件流

CEP 的一个非常重要的组件是其输入事件流。在早期的章节中，我们已经看到了 DataStream API 的详细信息。现在让我们利用这些知识来实现 CEP。我们需要做的第一件事就是为事件定义一个 Java POJO。假设我们需要监视温度传感器事件流。

首先，我们定义一个抽象类，然后扩展这个类。

### 注意

在定义事件 POJO 时，我们需要确保实现`hashCode()`和`equals()`方法，因为在比较事件时，编译将使用它们。

以下代码片段演示了这一点。

首先，我们编写一个抽象类，如下所示：

```java
package com.demo.chapter05; 

public abstract class MonitoringEvent { 

  private String machineName; 

  public String getMachineName() { 
    return machineName; 
  } 

  public void setMachineName(String machineName) { 
    this.machineName = machineName; 
  } 

  @Override 
  public int hashCode() { 
    final int prime = 31; 
    int result = 1; 
    result = prime * result + ((machineName == null) ? 0 : machineName.hashCode()); 
    return result; 
  } 

  @Override 
  public boolean equals(Object obj) { 
    if (this == obj) 
      return true; 
    if (obj == null) 
      return false; 
    if (getClass() != obj.getClass()) 
      return false; 
    MonitoringEvent other = (MonitoringEvent) obj; 
    if (machineName == null) { 
      if (other.machineName != null) 
        return false; 
    } else if (!machineName.equals(other.machineName)) 
      return false; 
    return true; 
  } 

  public MonitoringEvent(String machineName) { 
    super(); 
    this.machineName = machineName; 
  } 

} 

```

然后我们为实际温度事件创建一个 POJO：

```java
package com.demo.chapter05; 

public class TemperatureEvent extends MonitoringEvent { 

  public TemperatureEvent(String machineName) { 
    super(machineName); 
  } 

  private double temperature; 

  public double getTemperature() { 
    return temperature; 
  } 

  public void setTemperature(double temperature) { 
    this.temperature = temperature; 
  } 

  @Override 
  public int hashCode() { 
    final int prime = 31; 
    int result = super.hashCode(); 
    long temp; 
    temp = Double.doubleToLongBits(temperature); 
    result = prime * result + (int) (temp ^ (temp >>> 32)); 
    return result; 
  } 

  @Override 
  public boolean equals(Object obj) { 
    if (this == obj) 
      return true; 
    if (!super.equals(obj)) 
      return false; 
    if (getClass() != obj.getClass()) 
      return false; 
    TemperatureEvent other = (TemperatureEvent) obj; 
    if (Double.doubleToLongBits(temperature) != Double.doubleToLongBits(other.temperature)) 
      return false; 
    return true; 
  } 

  public TemperatureEvent(String machineName, double temperature) { 
    super(machineName); 
    this.temperature = temperature; 
  } 

  @Override 
  public String toString() { 
    return "TemperatureEvent [getTemperature()=" + getTemperature() + ", getMachineName()=" + getMachineName() 
        + "]"; 
  } 

} 

```

现在我们可以定义事件源如下：

在 Java 中：

```java
StreamExecutionEnvironment env = StreamExecutionEnvironment.getExecutionEnvironment(); 
    DataStream<TemperatureEvent> inputEventStream = env.fromElements(new TemperatureEvent("xyz", 22.0), 
        new TemperatureEvent("xyz", 20.1), new TemperatureEvent("xyz", 21.1), new TemperatureEvent("xyz", 22.2), 
        new TemperatureEvent("xyz", 22.1), new TemperatureEvent("xyz", 22.3), new TemperatureEvent("xyz", 22.1), 
        new TemperatureEvent("xyz", 22.4), new TemperatureEvent("xyz", 22.7), 
        new TemperatureEvent("xyz", 27.0)); 

```

在 Scala 中：

```java
val env: StreamExecutionEnvironment = StreamExecutionEnvironment.getExecutionEnvironment 
    val input: DataStream[TemperatureEvent] = env.fromElements(new TemperatureEvent("xyz", 22.0), 
      new TemperatureEvent("xyz", 20.1), new TemperatureEvent("xyz", 21.1), new TemperatureEvent("xyz", 22.2), 
      new TemperatureEvent("xyz", 22.1), new TemperatureEvent("xyz", 22.3), new TemperatureEvent("xyz", 22.1), 
      new TemperatureEvent("xyz", 22.4), new TemperatureEvent("xyz", 22.7), 
      new TemperatureEvent("xyz", 27.0)) 

```

# 模式 API

模式 API 允许您非常轻松地定义复杂的事件模式。每个模式由多个状态组成。要从一个状态转换到另一个状态，通常需要定义条件。条件可以是连续性或过滤掉的事件。

![Pattern API](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-flink/img/image_05_003.jpg)

让我们尝试详细了解每个模式操作。

## 开始

初始状态可以定义如下：

在 Java 中：

```java
Pattern<Event, ?> start = Pattern.<Event>begin("start"); 

```

在 Scala 中：

```java
val start : Pattern[Event, _] = Pattern.begin("start") 

```

## 过滤器

我们还可以为初始状态指定过滤条件：

在 Java 中：

```java
start.where(new FilterFunction<Event>() { 
    @Override 
    public boolean filter(Event value) { 
        return ... // condition 
    } 
}); 

```

在 Scala 中：

```java
start.where(event => ... /* condition */) 

```

## 子类型

我们还可以根据它们的子类型过滤事件，使用`subtype()`方法：

在 Java 中：

```java
start.subtype(SubEvent.class).where(new FilterFunction<SubEvent>() { 
    @Override 
    public boolean filter(SubEvent value) { 
        return ... // condition 
    } 
}); 

```

在 Scala 中：

```java
start.subtype(classOf[SubEvent]).where(subEvent => ... /* condition */) 

```

## 或

模式 API 还允许我们一起定义多个条件。我们可以使用`OR`和`AND`运算符。

在 Java 中：

```java
pattern.where(new FilterFunction<Event>() { 
    @Override 
    public boolean filter(Event value) { 
        return ... // condition 
    } 
}).or(new FilterFunction<Event>() { 
    @Override 
    public boolean filter(Event value) { 
        return ... // or condition 
    } 
}); 

```

在 Scala 中：

```java
pattern.where(event => ... /* condition */).or(event => ... /* or condition */) 

```

## 连续性

如前所述，我们并不总是需要过滤事件。总是可能有一些我们需要连续而不是过滤的模式。

连续性可以有两种类型 - 严格连续性和非严格连续性。

### 严格连续性

严格连续性需要直接成功的两个事件，这意味着两者之间不应该有其他事件。这个模式可以通过`next()`定义。

在 Java 中：

```java
Pattern<Event, ?> strictNext = start.next("middle"); 

```

在 Scala 中：

```java
val strictNext: Pattern[Event, _] = start.next("middle") 

```

### 非严格连续

非严格连续性可以被定义为其他事件允许在特定两个事件之间。这个模式可以通过`followedBy()`定义。

在 Java 中：

```java
Pattern<Event, ?> nonStrictNext = start.followedBy("middle"); 

```

在 Scala 中：

```java
val nonStrictNext : Pattern[Event, _] = start.followedBy("middle") 

```

## 内

模式 API 还允许我们根据时间间隔进行模式匹配。我们可以定义基于时间的时间约束如下。

在 Java 中：

```java
next.within(Time.seconds(30)); 

```

在 Scala 中：

```java
next.within(Time.seconds(10)) 

```

## 检测模式

要检测事件流中的模式，我们需要通过模式运行流。`CEP.pattern()`返回`PatternStream`。

以下代码片段显示了我们如何检测模式。首先定义模式，以检查温度值是否在`10`秒内大于`26.0`度。

在 Java 中：

```java
Pattern<TemperatureEvent, ?> warningPattern = Pattern.<TemperatureEvent> begin("first") 
        .subtype(TemperatureEvent.class).where(new FilterFunction<TemperatureEvent>() { 
          public boolean filter(TemperatureEvent value) { 
            if (value.getTemperature() >= 26.0) { 
              return true; 
            } 
            return false; 
          } 
        }).within(Time.seconds(10)); 

    PatternStream<TemperatureEvent> patternStream = CEP.pattern(inputEventStream, warningPattern); 

```

在 Scala 中：

```java
val env: StreamExecutionEnvironment = StreamExecutionEnvironment.getExecutionEnvironment 

val input = // data 

val pattern: Pattern[TempEvent, _] = Pattern.begin("start").where(event => event.temp >= 26.0) 

val patternStream: PatternStream[TempEvent] = CEP.pattern(input, pattern) 

```

## 从模式中选择

一旦模式流可用，我们需要从中选择模式，然后根据需要采取适当的操作。我们可以使用`select`或`flatSelect`方法从模式中选择数据。

### 选择

select 方法需要`PatternSelectionFunction`实现。它有一个 select 方法，该方法将为每个事件序列调用。`select`方法接收匹配事件的字符串/事件对的映射。字符串由状态的名称定义。`select`方法返回确切的一个结果。

要收集结果，我们需要定义输出 POJO。在我们的案例中，假设我们需要生成警报作为输出。然后我们需要定义 POJO 如下：

```java
package com.demo.chapter05; 

public class Alert { 

  private String message; 

  public String getMessage() { 
    return message; 
  } 

  public void setMessage(String message) { 
    this.message = message; 
  } 

  public Alert(String message) { 
    super(); 
    this.message = message; 
  } 

  @Override 
  public String toString() { 
    return "Alert [message=" + message + "]"; 
  } 

  @Override 
  public int hashCode() { 
    final int prime = 31; 
    int result = 1; 
    result = prime * result + ((message == null) ? 0 :  
    message.hashCode()); 
    return result; 
  } 

  @Override 
  public boolean equals(Object obj) { 
    if (this == obj) 
      return true; 
    if (obj == null) 
      return false; 
    if (getClass() != obj.getClass()) 
      return false; 
    Alert other = (Alert) obj; 
    if (message == null) { 
      if (other.message != null) 
        return false; 
    } else if (!message.equals(other.message)) 
      return false; 
    return true; 
  } 

} 

```

接下来我们定义选择函数。

在 Java 中：

```java
class MyPatternSelectFunction<IN, OUT> implements PatternSelectFunction<IN, OUT> { 
    @Override 
    public OUT select(Map<String, IN> pattern) { 
        IN startEvent = pattern.get("start"); 
        IN endEvent = pattern.get("end"); 
        return new OUT(startEvent, endEvent); 
    } 
} 

```

在 Scala 中：

```java
def selectFn(pattern : mutable.Map[String, IN]): OUT = { 
    val startEvent = pattern.get("start").get 
    val endEvent = pattern.get("end").get 
    OUT(startEvent, endEvent) 
} 

```

### flatSelect

`flatSelect`方法类似于`select`方法。两者之间的唯一区别是`flatSelect`可以返回任意数量的结果。`flatSelect`方法有一个额外的`Collector`参数，用于输出元素。

以下示例显示了如何使用`flatSelect`方法。

在 Java 中：

```java
class MyPatternFlatSelectFunction<IN, OUT> implements PatternFlatSelectFunction<IN, OUT> { 
    @Override 
    public void select(Map<String, IN> pattern, Collector<OUT> collector) { 
        IN startEvent = pattern.get("start"); 
        IN endEvent = pattern.get("end"); 

        for (int i = 0; i < startEvent.getValue(); i++ ) { 
            collector.collect(new OUT(startEvent, endEvent)); 
        } 
    } 
} 

```

在 Scala 中：

```java
def flatSelectFn(pattern : mutable.Map[String, IN], collector : Collector[OUT]) = { 
    val startEvent = pattern.get("start").get 
    val endEvent = pattern.get("end").get 
    for (i <- 0 to startEvent.getValue) { 
        collector.collect(OUT(startEvent, endEvent)) 
    } 
} 

```

## 处理超时的部分模式

有时，如果我们将模式限制在时间边界内，可能会错过某些事件。可能会丢弃事件，因为它们超出了长度。为了对超时事件采取行动，`select`和`flatSelect`方法允许超时处理程序。对于每个超时事件模式，都会调用此处理程序。

在这种情况下，select 方法包含两个参数：`PatternSelectFunction`和`PatternTimeoutFunction`。超时函数的返回类型可以与选择模式函数不同。超时事件和选择事件被包装在`Either.Right`和`Either.Left`类中。

以下代码片段显示了我们在实践中如何做事情。

在 Java 中：

```java
PatternStream<Event> patternStream = CEP.pattern(input, pattern); 

DataStream<Either<TimeoutEvent, ComplexEvent>> result = patternStream.select( 
    new PatternTimeoutFunction<Event, TimeoutEvent>() {...}, 
    new PatternSelectFunction<Event, ComplexEvent>() {...} 
); 

DataStream<Either<TimeoutEvent, ComplexEvent>> flatResult = patternStream.flatSelect( 
    new PatternFlatTimeoutFunction<Event, TimeoutEvent>() {...}, 
    new PatternFlatSelectFunction<Event, ComplexEvent>() {...} 
);  

```

在 Scala 中，选择 API：

```java
val patternStream: PatternStream[Event] = CEP.pattern(input, pattern) 

DataStream[Either[TimeoutEvent, ComplexEvent]] result = patternStream.select{ 
    (pattern: mutable.Map[String, Event], timestamp: Long) => TimeoutEvent() 
} { 
    pattern: mutable.Map[String, Event] => ComplexEvent() 
} 

```

`flatSelect` API 与`Collector`一起调用，因为它可以发出任意数量的事件：

```java
val patternStream: PatternStream[Event] = CEP.pattern(input, pattern) 

DataStream[Either[TimeoutEvent, ComplexEvent]] result = patternStream.flatSelect{ 
    (pattern: mutable.Map[String, Event], timestamp: Long, out: Collector[TimeoutEvent]) => 
        out.collect(TimeoutEvent()) 
} { 
    (pattern: mutable.Map[String, Event], out: Collector[ComplexEvent]) => 
        out.collect(ComplexEvent()) 
} 

```

# 用例 - 在温度传感器上进行复杂事件处理

在早期的章节中，我们学习了 Flink CEP 引擎提供的各种功能。现在是时候了解我们如何在现实世界的解决方案中使用它了。为此，让我们假设我们在一个生产某些产品的机械公司工作。在产品工厂中，有必要不断监视某些机器。工厂已经设置了传感器，这些传感器不断发送机器的温度。

现在我们将建立一个系统，不断监视温度值，并在温度超过一定值时生成警报。

我们可以使用以下架构：

![温度传感器上的复杂事件处理用例](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-flink/img/image_05_004.jpg)

在这里，我们将使用 Kafka 从传感器收集事件。为了编写一个 Java 应用程序，我们首先需要创建一个 Maven 项目并添加以下依赖项：

```java
  <!-- https://mvnrepository.com/artifact/org.apache.flink/flink-cep-scala_2.11 --> 
    <dependency> 
      <groupId>org.apache.flink</groupId> 
      <artifactId>flink-cep-scala_2.11</artifactId> 
      <version>1.1.4</version> 
    </dependency> 
    <!-- https://mvnrepository.com/artifact/org.apache.flink/flink- streaming-java_2.11 --> 
    <dependency> 
      <groupId>org.apache.flink</groupId> 
      <artifactId>flink-streaming-java_2.11</artifactId> 
      <version>1.1.4</version> 
    </dependency> 
    <!-- https://mvnrepository.com/artifact/org.apache.flink/flink- streaming-scala_2.11 --> 
    <dependency> 
      <groupId>org.apache.flink</groupId> 
      <artifactId>flink-streaming-scala_2.11</artifactId> 
      <version>1.1.4</version> 
    </dependency> 
    <dependency> 
      <groupId>org.apache.flink</groupId> 
      <artifactId>flink-connector-kafka-0.9_2.11</artifactId> 
      <version>1.1.4</version> 
    </dependency> 

```

接下来，我们需要做以下事情来使用 Kafka。

首先，我们需要定义一个自定义的 Kafka 反序列化器。这将从 Kafka 主题中读取字节并将其转换为`TemperatureEvent`。以下是执行此操作的代码。

`EventDeserializationSchema.java`：

```java
package com.demo.chapter05; 

import java.io.IOException; 
import java.nio.charset.StandardCharsets; 

import org.apache.flink.api.common.typeinfo.TypeInformation; 
import org.apache.flink.api.java.typeutils.TypeExtractor; 
import org.apache.flink.streaming.util.serialization.DeserializationSchema; 

public class EventDeserializationSchema implements DeserializationSchema<TemperatureEvent> { 

  public TypeInformation<TemperatureEvent> getProducedType() { 
    return TypeExtractor.getForClass(TemperatureEvent.class); 
  } 

  public TemperatureEvent deserialize(byte[] arg0) throws IOException { 
    String str = new String(arg0, StandardCharsets.UTF_8); 

    String[] parts = str.split("="); 
    return new TemperatureEvent(parts[0], Double.parseDouble(parts[1])); 
  } 

  public boolean isEndOfStream(TemperatureEvent arg0) { 
    return false; 
  } 

} 

```

接下来，在 Kafka 中创建名为`temperature`的主题：

```java
bin/kafka-topics.sh --create --zookeeper localhost:2181 --replication-factor 1 --partitions 1 --topic temperature 

```

现在我们转到 Java 代码，该代码将监听 Flink 流中的这些事件：

```java
StreamExecutionEnvironment env = StreamExecutionEnvironment.getExecutionEnvironment(); 

    Properties properties = new Properties(); 
    properties.setProperty("bootstrap.servers", "localhost:9092"); 
    properties.setProperty("group.id", "test"); 

DataStream<TemperatureEvent> inputEventStream = env.addSource( 
        new FlinkKafkaConsumer09<TemperatureEvent>("temperature", new EventDeserializationSchema(), properties)); 

```

接下来，我们将定义模式，以检查温度是否在`10`秒内是否大于`26.0`摄氏度：

```java
Pattern<TemperatureEvent, ?> warningPattern = Pattern.<TemperatureEvent> begin("first").subtype(TemperatureEvent.class).where(new FilterFunction<TemperatureEvent>() { 
          private static final long serialVersionUID = 1L; 

          public boolean filter(TemperatureEvent value) { 
            if (value.getTemperature() >= 26.0) { 
              return true; 
            } 
            return false; 
          } 
        }).within(Time.seconds(10)); 

```

接下来将此模式与事件流匹配并选择事件。我们还将将警报消息添加到结果流中，如下所示：

```java
DataStream<Alert> patternStream = CEP.pattern(inputEventStream, warningPattern) 
        .select(new PatternSelectFunction<TemperatureEvent, Alert>() { 
          private static final long serialVersionUID = 1L; 

          public Alert select(Map<String, TemperatureEvent> event) throws Exception { 

            return new Alert("Temperature Rise Detected:" + event.get("first").getTemperature() 
                + " on machine name:" + event.get("first").getMachineName()); 
          } 

}); 

```

为了知道警报是如何生成的，我们将打印结果：

```java
patternStream.print(); 

```

然后我们执行流：

```java
env.execute("CEP on Temperature Sensor"); 

```

现在我们已经准备好执行应用程序了。当我们在 Kafka 主题中收到消息时，CEP 将继续执行。

实际执行将如下所示。以下是我们如何提供样本输入：

```java
xyz=21.0 
xyz=30.0 
LogShaft=29.3 
Boiler=23.1 
Boiler=24.2 
Boiler=27.0 
Boiler=29.0 

```

以下是样本输出的样子：

```java
Connected to JobManager at Actor[akka://flink/user/jobmanager_1#1010488393] 
10/09/2016 18:15:55  Job execution switched to status RUNNING. 
10/09/2016 18:15:55  Source: Custom Source(1/4) switched to SCHEDULED  
10/09/2016 18:15:55  Source: Custom Source(1/4) switched to DEPLOYING  
10/09/2016 18:15:55  Source: Custom Source(2/4) switched to SCHEDULED  
10/09/2016 18:15:55  Source: Custom Source(2/4) switched to DEPLOYING  
10/09/2016 18:15:55  Source: Custom Source(3/4) switched to SCHEDULED  
10/09/2016 18:15:55  Source: Custom Source(3/4) switched to DEPLOYING  
10/09/2016 18:15:55  Source: Custom Source(4/4) switched to SCHEDULED  
10/09/2016 18:15:55  Source: Custom Source(4/4) switched to DEPLOYING  
10/09/2016 18:15:55  CEPPatternOperator(1/1) switched to SCHEDULED  
10/09/2016 18:15:55  CEPPatternOperator(1/1) switched to DEPLOYING  
10/09/2016 18:15:55  Map -> Sink: Unnamed(1/4) switched to SCHEDULED  
10/09/2016 18:15:55  Map -> Sink: Unnamed(1/4) switched to DEPLOYING  
10/09/2016 18:15:55  Map -> Sink: Unnamed(2/4) switched to SCHEDULED  
10/09/2016 18:15:55  Map -> Sink: Unnamed(2/4) switched to DEPLOYING  
10/09/2016 18:15:55  Map -> Sink: Unnamed(3/4) switched to SCHEDULED  
10/09/2016 18:15:55  Map -> Sink: Unnamed(3/4) switched to DEPLOYING  
10/09/2016 18:15:55  Map -> Sink: Unnamed(4/4) switched to SCHEDULED  
10/09/2016 18:15:55  Map -> Sink: Unnamed(4/4) switched to DEPLOYING  
10/09/2016 18:15:55  Source: Custom Source(2/4) switched to RUNNING  
10/09/2016 18:15:55  Source: Custom Source(3/4) switched to RUNNING  
10/09/2016 18:15:55  Map -> Sink: Unnamed(1/4) switched to RUNNING  
10/09/2016 18:15:55  Map -> Sink: Unnamed(2/4) switched to RUNNING  
10/09/2016 18:15:55  Map -> Sink: Unnamed(3/4) switched to RUNNING  
10/09/2016 18:15:55  Source: Custom Source(4/4) switched to RUNNING  
10/09/2016 18:15:55  Source: Custom Source(1/4) switched to RUNNING  
10/09/2016 18:15:55  CEPPatternOperator(1/1) switched to RUNNING  
10/09/2016 18:15:55  Map -> Sink: Unnamed(4/4) switched to RUNNING  
1> Alert [message=Temperature Rise Detected:30.0 on machine name:xyz] 
2> Alert [message=Temperature Rise Detected:29.3 on machine name:LogShaft] 
3> Alert [message=Temperature Rise Detected:27.0 on machine name:Boiler] 
4> Alert [message=Temperature Rise Detected:29.0 on machine name:Boiler] 

```

我们还可以配置邮件客户端并使用一些外部网络钩子来发送电子邮件或即时通讯通知。

### 注意

应用程序的代码可以在 GitHub 上找到：[`github.com/deshpandetanmay/mastering-flink`](https://github.com/deshpandetanmay/mastering-flink)。

# 摘要

在本章中，我们学习了 CEP。我们讨论了涉及的挑战以及我们如何使用 Flink CEP 库来解决 CEP 问题。我们还学习了 Pattern API 以及我们可以使用的各种运算符来定义模式。在最后一节中，我们试图连接各个点，看到一个完整的用例。通过一些改变，这个设置也可以在其他领域中使用。

在下一章中，我们将看到如何使用 Flink 的内置机器学习库来解决复杂的问题。


# 第六章：使用 FlinkML 进行机器学习

在上一章中，我们讨论了如何使用 Flink CEP 库解决复杂的事件处理问题。在本章中，我们将看到如何使用 Flink 的机器学习库 FlinkML 进行机器学习。FlinkML 包括一组支持的算法，可用于解决现实生活中的用例。在本章中，我们将看看 FlinkML 中有哪些算法以及如何应用它们。

在深入研究 FlinkML 之前，让我们首先尝试理解基本的机器学习原理。

# 什么是机器学习？

机器学习是一种利用数学让机器根据提供给它们的数据进行分类、预测、推荐等的工程流。这个领域非常广阔，我们可以花费数年来讨论它。但为了保持我们的讨论集中，我们只讨论本书范围内所需的内容。

非常广泛地，机器学习可以分为三大类：

+   监督学习

+   无监督学习

+   半监督学习！什么是机器学习？

前面的图表显示了机器学习算法的广泛分类。现在让我们详细讨论这些。

## 监督学习

在监督学习中，我们通常会得到一个输入数据集，这是实际事件的历史记录。我们还知道预期的输出应该是什么样子。使用历史数据，我们选择了哪些因素导致了结果。这些属性被称为特征。使用历史数据，我们了解了以前的结果是如何计算的，并将相同的理解应用于我们想要进行预测的数据。

监督学习可以再次细分为：

+   回归

+   分类

### 回归

在回归问题中，我们试图使用连续函数的输入来预测结果。回归意味着基于另一个变量的分数来预测一个变量的分数。我们将要预测的变量称为标准变量，我们将进行预测的变量称为预测变量。可能会有多个预测变量；在这种情况下，我们需要找到最佳拟合线，称为回归线。

### 注意

您可以在[`en.wikipedia.org/wiki/Regression_analysis`](https://en.wikipedia.org/wiki/Regression_analysis)上了解更多关于回归的信息。

用于解决回归问题的一些常见算法如下：

+   逻辑回归

+   决策树

+   支持向量机（SVM）

+   朴素贝叶斯

+   随机森林

+   线性回归

+   多项式回归

### 分类

在分类中，我们预测离散结果的输出。分类作为监督学习的一部分，也需要提供输入数据和样本输出。在这里，基于特征，我们试图将结果分类为一组定义好的类别。例如，根据给定的特征，将人员记录分类为男性或女性。或者，根据客户行为，预测他/她是否会购买产品。或者根据电子邮件内容和发件人，预测电子邮件是否是垃圾邮件。参考[`en.wikipedia.org/wiki/Statistical_classification`](https://en.wikipedia.org/wiki/Statistical_classification)。

为了理解回归和分类之间的区别，考虑股票数据的例子。回归算法可以帮助预测未来几天股票的价值，而分类算法可以帮助决定是否购买股票。

## 无监督学习

无监督学习并不给我们任何关于结果应该如何的想法。相反，它允许我们根据属性的特征对数据进行分组。我们根据记录之间的关系推导出聚类。

与监督学习不同，我们无法验证结果，这意味着没有反馈方法来告诉我们是否做对了还是错了。无监督学习主要基于聚类算法。

### 聚类

为了更容易理解聚类，让我们考虑一个例子；假设我们有 2 万篇关于各种主题的新闻文章，我们需要根据它们的内容对它们进行分组。在这种情况下，我们可以使用聚类算法，将一组文章分成小组。

我们还可以考虑水果的基本例子。假设我们有苹果、香蕉、柠檬和樱桃在一个水果篮子里，我们需要将它们分类成组。如果我们看它们的颜色，我们可以将它们分成两组：

+   **红色组**：苹果和樱桃

+   **黄色组**：香蕉和柠檬

现在我们可以根据另一个特征，它的大小，进行更多的分组：

+   **红色和大尺寸**：苹果

+   **红色和小尺寸**：樱桃

+   **黄色和大尺寸**：香蕉

+   **黄色和小尺寸**：柠檬

以下图表显示了聚类的表示：

![聚类](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-flink/img/image_06_002.jpg)

通过查看更多特征，我们也可以进行更多的聚类。在这里，我们没有任何训练数据和要预测的变量，不像在监督学习中。我们的唯一任务是学习更多关于特征，并根据输入对记录进行聚类。

以下是一些常用于聚类的算法：

+   K 均值聚类

+   层次聚类

+   隐马尔可夫模型

### 关联

关联问题更多是关于学习和通过定义关联规则进行推荐。例如，关联规则可能指的是购买 iPhone 的人更有可能购买 iPhone 手机壳的假设。

如今，许多零售公司使用这些算法进行个性化推荐。例如，在[www.amazon.com](http://www.amazon.com)，如果我倾向于购买产品*X*，然后亚马逊也向我推荐产品*Y*，那么这两者之间一定存在一些关联。

基于这些原则的一些算法如下：

+   Apriori 算法

+   Eclat 算法

+   FDP 增长算法

## 半监督学习

半监督学习是监督学习的一个子类，它考虑了用于训练的未标记数据。通常，在训练过程中，有大量未标记数据，只有很少量的标记数据。许多研究人员和机器学习实践者发现，当标记数据与未标记数据一起使用时，结果很可能更准确。

### 注意

有关半监督学习的更多细节，请参阅[`en.wikipedia.org/wiki/Semi-supervised_learning`](https://en.wikipedia.org/wiki/Semi-supervised_learning)。

# FlinkML

FlinkML 是由 Flink 支持的一组算法库，可用于解决现实生活中的用例。这些算法被构建成可以利用 Flink 的分布式计算能力，并且可以轻松进行预测、聚类等。目前，只支持了少量算法集，但列表正在增长。

FlinkML 的重点是 ML 开发人员需要编写最少的粘合代码。粘合代码是帮助将各种组件绑定在一起的代码。FlinkML 的另一个目标是保持算法的使用简单。

Flink 利用内存数据流和本地执行迭代数据处理。FlinkML 允许数据科学家在本地测试他们的模型，使用数据子集，然后在更大的数据上以集群模式执行它们。

FlinkML 受 scikit-learn 和 Spark 的 MLlib 启发，允许您清晰地定义数据管道，并以分布式方式解决机器学习问题。

Flink 开发团队的路线图如下：

+   转换器和学习者的管道

+   数据预处理：

+   特征缩放

+   多项式特征基映射

+   特征哈希

+   文本特征提取

+   降维

+   模型选择和性能评估：

+   使用各种评分函数进行模型评估

+   用于模型选择和评估的交叉验证

+   超参数优化

+   监督学习：

+   优化框架

+   随机梯度下降

+   L-BFGS

+   广义线性模型

+   多元线性回归

+   LASSO，岭回归

+   多类逻辑回归

+   随机森林

+   支持向量机

+   决策树

+   无监督学习：

+   聚类

+   K 均值聚类

+   主成分分析

+   推荐：

+   ALS

+   文本分析：

+   LDA

+   统计估计工具

+   分布式线性代数

+   流式机器学习

突出显示的算法已经是现有的 Flink 源代码的一部分。在接下来的部分中，我们将看看如何在实践中使用它们。

# 支持的算法

要开始使用 FlinkML，我们首先需要添加以下 Maven 依赖项：

```java
<!-- https://mvnrepository.com/artifact/org.apache.flink/flink-ml_2.11 --> 
<dependency> 
    <groupId>org.apache.flink</groupId> 
    <artifactId>flink-ml_2.11</artifactId> 
    <version>1.1.4</version> 
</dependency> 

```

现在让我们试着了解支持的算法以及如何使用它们。

## 监督学习

Flink 支持监督学习类别中的三种算法。它们如下：

+   支持向量机（SVM）

+   多元线性回归

+   优化框架

让我们一次学习一个开始。

### 支持向量机

**支持向量机**（**SVMs**）是监督学习模型，用于解决分类和回归问题。它有助于将对象分类到一个类别或另一个类别。它是非概率线性分类。SVM 可以用在各种例子中，例如以下情况：

+   常规数据分类问题

+   文本和超文本分类问题

+   图像分类问题

+   生物学和其他科学问题

Flink 支持基于软间隔的 SVM，使用高效的通信分布式双坐标上升算法。

有关该算法的详细信息可在[`ci.apache.org/projects/flink/flink-docs-release-1.2/dev/libs/ml/svm.html#description`](https://ci.apache.org/projects/flink/flink-docs-release-1.2/dev/libs/ml/svm.html#description)找到。

Flink 使用**随机双坐标上升**（**SDCA**）来解决最小化问题。为了使该算法在分布式环境中高效，Flink 使用 CoCoA 算法，该算法在本地数据块上计算 SDCA，然后将其合并到全局状态中。

### 注意

该算法的实现基于以下论文：[`arxiv.org/pdf/1409.1458v2.pdf`](https://arxiv.org/pdf/1409.1458v2.pdf)。

现在让我们看看如何使用该算法解决实际问题。我们将以鸢尾花数据集（[`en.wikipedia.org/wiki/Iris_flower_data_set`](https://en.wikipedia.org/wiki/Iris_flower_data_set)）为例，该数据集由四个属性组成，决定了鸢尾花的种类。以下是一些示例数据：

| **萼片长度** | **萼片宽度** | **花瓣长度** | **花瓣宽度** | **种类** |
| --- | --- | --- | --- | --- |
| 5.1 | 3.5 | 1.4 | 0.2 | 1 |
| 5.6 | 2.9 | 3.6 | 1.3 | 2 |
| 5.8 | 2.7 | 5.1 | 1.9 | 3 |

在这里，使用数字格式的类别作为 SVM 的输入非常重要：

| **种类代码** | **种类名称** |
| --- | --- |
| 1 | 鸢尾花山鸢尾 |
| 2 | 鸢尾花变色鸢尾 |
| 3 | 鸢尾花维吉尼亚 |

在使用 Flink 的 SVM 算法之前，我们需要做的另一件事是将 CSV 数据转换为 LibSVM 数据。

### 注意

LibSVM 数据是一种用于指定 SVM 数据集的特殊格式。有关 LibSVM 的更多信息，请访问[`www.csie.ntu.edu.tw/~cjlin/libsvmtools/datasets/`](https://www.csie.ntu.edu.tw/~cjlin/libsvmtools/datasets/)。

要将 CSV 数据转换为 LibSVM 数据，我们将使用[`github.com/zygmuntz/phraug/blob/master/csv2libsvm.py`](https://github.com/zygmuntz/phraug/blob/master/csv2libsvm.py)上提供的一些开源 Python 代码。

要将 CSV 转换为 LibSVM，我们需要执行以下命令：

```java
    csv2libsvm.py <input file> <output file> [<label index = 0>] [<skip 
    headers = 0>]

```

现在让我们开始编写程序：

```java
package com.demo.chapter06 

import org.apache.flink.api.scala._ 
import org.apache.flink.ml.math.Vector 
import org.apache.flink.ml.common.LabeledVector 
import org.apache.flink.ml.classification.SVM 
import org.apache.flink.ml.RichExecutionEnvironment 

object MySVMApp { 
  def main(args: Array[String]) { 
    // set up the execution environment 
    val pathToTrainingFile: String = "iris-train.txt" 
    val pathToTestingFile: String = "iris-train.txt" 
    val env = ExecutionEnvironment.getExecutionEnvironment 

    // Read the training dataset, from a LibSVM formatted file 
    val trainingDS: DataSet[LabeledVector] = 
    env.readLibSVM(pathToTrainingFile) 

    // Create the SVM learner 
    val svm = SVM() 
      .setBlocks(10) 

    // Learn the SVM model 
    svm.fit(trainingDS) 

    // Read the testing dataset 
    val testingDS: DataSet[Vector] = 
    env.readLibSVM(pathToTestingFile).map(_.vector) 

    // Calculate the predictions for the testing dataset 
    val predictionDS: DataSet[(Vector, Double)] = 
    svm.predict(testingDS) 
    predictionDS.writeAsText("out") 

    env.execute("Flink SVM App") 
  } 
} 

```

所以，现在我们已经准备好运行程序了，您将在输出文件夹中看到预测的输出。

以下是代码：

```java
(SparseVector((0,5.1), (1,3.5), (2,1.4), (3,0.2)),1.0) 
(SparseVector((0,4.9), (1,3.0), (2,1.4), (3,0.2)),1.0) 
(SparseVector((0,4.7), (1,3.2), (2,1.3), (3,0.2)),1.0) 
(SparseVector((0,4.6), (1,3.1), (2,1.5), (3,0.2)),1.0) 
(SparseVector((0,5.0), (1,3.6), (2,1.4), (3,0.2)),1.0) 
(SparseVector((0,5.4), (1,3.9), (2,1.7), (3,0.4)),1.0) 
(SparseVector((0,4.6), (1,3.4), (2,1.4), (3,0.3)),1.0) 
(SparseVector((0,5.0), (1,3.4), (2,1.5), (3,0.2)),1.0) 
(SparseVector((0,4.4), (1,2.9), (2,1.4), (3,0.2)),1.0) 
(SparseVector((0,4.9), (1,3.1), (2,1.5), (3,0.1)),1.0) 
(SparseVector((0,5.4), (1,3.7), (2,1.5), (3,0.2)),1.0) 
(SparseVector((0,4.8), (1,3.4), (2,1.6), (3,0.2)),1.0) 
(SparseVector((0,4.8), (1,3.0), (2,1.4), (3,0.1)),1.0) 

```

我们还可以通过设置各种参数来微调结果：

| **参数** | **描述** |
| --- | --- |
| `Blocks` | 设置输入数据将被分成的块数。最好将这个数字设置为你想要实现的并行度。在每个块上，执行本地随机对偶坐标上升。默认值为`None`。 |
| `Iterations` | 设置外部循环方法的迭代次数，例如，SDCA 方法在分块数据上应用的次数。默认值为`10`。 |
| `LocalIterations` | 定义需要在本地执行的 SDCA 迭代的最大次数。默认值为`10`。 |
| `Regularization` | 设置算法的正则化常数。您设置的值越高，加权向量的 2 范数就越小。默认值为`1`。 |
| `StepSize` | 定义了权重向量更新的初始步长。在算法变得不稳定的情况下，需要设置这个值。默认值为`1.0`。 |
| `ThresholdValue` | 定义决策函数的限制值。默认值为`0.0`。 |
| `OutputDecisionFunction` | 将其设置为 true 将返回每个示例的超平面距离。将其设置为 false 将返回二进制标签。 |
| `Seed` | 设置随机长整数。这将用于初始化随机数生成器。 |

### 多元线性回归

**多元线性回归**（**MLR**）是简单线性回归的扩展，其中使用多个自变量（*X*）来确定单个自变量（*Y*）。预测值是输入变量的线性变换，使得观察值和预测值的平方偏差之和最小。

MLR 试图通过拟合线性方程来建模多个解释变量和响应变量之间的关系。

### 注意

关于 MLR 的更详细的解释可以在此链接找到[`www.stat.yale.edu/Courses/1997-98/101/linmult.htm`](http://www.stat.yale.edu/Courses/1997-98/101/linmult.htm)。

现在让我们尝试使用 MLR 解决鸢尾花数据集的相同分类问题。首先，我们需要训练数据集来训练我们的模型。

在这里，我们将使用在 SVM 上一节中使用的相同的数据文件。现在我们有`iris-train.txt`和`iris-test.txt`，它们已经转换成了 LibSVM 格式。

以下代码片段显示了如何使用 MLR：

```java
package com.demo.flink.ml 

import org.apache.flink.api.scala._ 
import org.apache.flink.ml._ 
import org.apache.flink.ml.common.LabeledVector 
import org.apache.flink.ml.math.DenseVector 
import org.apache.flink.ml.math.Vector 
import org.apache.flink.ml.preprocessing.Splitter 
import org.apache.flink.ml.regression.MultipleLinearRegression 

object MLRJob { 
  def main(args: Array[String]) { 
    // set up the execution environment 
    val env = ExecutionEnvironment.getExecutionEnvironment 
    val trainingDataset = MLUtils.readLibSVM(env, "iris-train.txt") 
    val testingDataset = MLUtils.readLibSVM(env, "iris-test.txt").map { 
    lv => lv.vector } 
    val mlr = MultipleLinearRegression() 
      .setStepsize(1.0) 
      .setIterations(5) 
      .setConvergenceThreshold(0.001) 

    mlr.fit(trainingDataset) 

    // The fitted model can now be used to make predictions 
    val predictions = mlr.predict(testingDataset) 

    predictions.print() 

  } 
} 

```

完整的代码和数据文件可以在[`github.com/deshpandetanmay/mastering-flink/tree/master/chapter06`](https://github.com/deshpandetanmay/mastering-flink/tree/master/chapter06)上下载。我们还可以通过设置各种参数来微调结果：

| **参数** | **描述** |
| --- | --- |
| `Iterations` | 设置最大迭代次数。默认值为`10`。 |
| `Stepsize` | 梯度下降方法的步长。这个值控制了梯度下降方法在相反方向上可以移动多远。调整这个参数非常重要，以获得更好的结果。默认值为`0.1`。 |
| `Convergencethreshold` | 直到迭代停止的平方残差的相对变化的阈值。默认值为`None`。 |
| `Learningratemethod` | `Learningratemethod` 用于计算每次迭代的学习率。 |

### 优化框架

Flink 中的优化框架是一个开发者友好的包，可以用来解决优化问题。这不是一个解决确切问题的特定算法，而是每个机器学习问题的基础。

一般来说，它是关于找到一个模型，带有一组参数，通过最小化函数。FlinkML 支持**随机梯度下降**（**SGD**），并具有以下类型的正则化：

| **正则化函数** | **类名** |
| --- | --- |
| L1 正则化 | `GradientDescentL1` |
| L2 正则化 | `GradientDescentL2` |
| 无正则化 | `SimpleGradient` |

以下代码片段显示了如何使用 FlinkML 使用 SGD：

```java
// Create SGD solver 
val sgd = GradientDescentL1() 
  .setLossFunction(SquaredLoss()) 
  .setRegularizationConstant(0.2) 
  .setIterations(100) 
  .setLearningRate(0.01) 
  .setLearningRateMethod(LearningRateMethod.Xu(-0.75)) 

// Obtain data 
val trainingDS: DataSet[LabeledVector] = ... 

// Optimize the weights, according to the provided data 
val weightDS = sgd.optimize(trainingDS) 

```

我们还可以使用参数来微调算法：

| **参数** | **描述** |
| --- | --- |

| `LossFunction` | Flink 支持以下损失函数：

+   平方损失

+   铰链损失

+   逻辑损失

+   默认值为`None`

|

| `RegularizationConstant` | 要应用的正则化权重。默认值为`0.1`。 |
| --- | --- |
| `Iterations` | 要执行的最大迭代次数。默认值为`10`。 |
| `ConvergenceThreshold` | 直到迭代停止的残差平方和的相对变化阈值。默认值为`None`。 |
| `LearningRateMethod` | 用于计算每次迭代的学习率的方法。 |
| `LearningRate` | 这是梯度下降方法的初始学习率。 |
| `Decay` | 默认值为`0.0`。 |

## 推荐

推荐引擎是最有趣和最常用的机器学习技术之一，用于提供基于用户和基于项目的推荐。亚马逊等电子商务公司使用推荐引擎根据客户的购买模式和评论评分来个性化推荐。

Flink 还支持基于 ALS 的推荐。让我们更详细地了解 ALS。

### 交替最小二乘法

**交替最小二乘法**（**ALS**）算法将给定的矩阵*R*分解为两个因子*U*和*V*，使得 ![交替最小二乘法](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-flink/img/image_06_003.jpg)

为了更好地理解该算法的应用，让我们假设我们有一个包含用户*u*对书籍*b*提供的评分*r*的数据集。

这是一个样本数据格式（`user_id`，`book_id`，`rating)`：

```java
1  10 1 
1  11 2 
1  12 5 
1  13 5 
1  14 5 
1  15 4 
1  16 5 
1  17 1 
1  18 5 
2  10 1 
2  11 2 
2  15 5 
2  16 4.5 
2  17 1 
2  18 5 
3  11 2.5 
3  12 4.5 
3  13 4 
3  14 3 
3  15 3.5 
3  16 4.5 
3  17 4 
3  18 5 
4  10 5 
4  11 5 
4  12 5 
4  13 0 
4  14 2 
4  15 3 
4  16 1 
4  17 4 
4  18 1 

```

现在我们可以将这些信息提供给 ALS 算法，并开始从中获得推荐。以下是使用 ALS 的代码片段：

```java
package com.demo.chapter06 

import org.apache.flink.api.scala._ 
import org.apache.flink.ml.recommendation._ 
import org.apache.flink.ml.common.ParameterMap 

object MyALSApp { 
  def main(args: Array[String]): Unit = { 

    val env = ExecutionEnvironment.getExecutionEnvironment 
    val inputDS: DataSet[(Int, Int, Double)] = env.readCsvFile(Int,  
    Int, Double) 

    // Setup the ALS learner 
    val als = ALS() 
      .setIterations(10) 
      .setNumFactors(10) 
      .setBlocks(100) 
      .setTemporaryPath("tmp") 

    // Set the other parameters via a parameter map 
    val parameters = ParameterMap() 
      .add(ALS.Lambda, 0.9) 
      .add(ALS.Seed, 42L) 

    // Calculate the factorization 
    als.fit(inputDS, parameters) 

    // Read the testing dataset from a csv file 
    val testingDS: DataSet[(Int, Int)] = env.readCsvFile[(Int, Int)]   
    ("test-data.csv") 

    // Calculate the ratings according to the matrix factorization 
    val predictedRatings = als.predict(testingDS) 

    predictedRatings.writeAsCsv("output") 

    env.execute("Flink Recommendation App") 
  } 
} 

```

一旦您执行应用程序，您将获得推荐结果。与其他算法一样，您可以微调参数以获得更好的结果：

| **参数** | **描述** |
| --- | --- |
| `NumFactors` | 用于基础模型的潜在因子的数量。默认值为`10`。 |
| `Lambda` | 这是一个正则化因子；我们可以调整此参数以获得更好的结果。默认值为`1`。 |
| `Iterations` | 要执行的最大迭代次数。默认值为`10`。 |
| `Blocks` | 用户和项目矩阵分组的块数。块越少，发送的冗余数据就越少。默认值为`None`。 |
| `Seed` | 用于初始化项目矩阵生成器的种子值。默认值为`0`。 |
| `TemporaryPath` | 这是用于存储中间结果的路径。 |

## 无监督学习

现在让我们试着了解 FinkML 为无监督学习提供了什么。目前，它只支持一种算法，称为 k 最近邻接算法。

### k 最近邻接

**k 最近邻接**（**kNN**）算法旨在为另一个数据集中的每个对象找到 k 个最近邻居。它是许多数据挖掘算法中最常用的解决方案之一。kNN 是一项昂贵的操作，因为它是找到 k 个最近邻居并执行连接的组合。考虑到数据的量，很难在集中的单台机器上执行此操作，因此总是很好地拥有可以在分布式架构上工作的解决方案。FlinkML 算法提供了分布式环境下的 kNN。

### 注意

可以在这里找到一篇描述在分布式环境中实现 kNN 的研究论文：[`arxiv.org/pdf/1207.0141v1.pdf`](https://arxiv.org/pdf/1207.0141v1.pdf)。

在这里，想法是计算每个训练和测试点之间的距离，然后找到给定点的最近点。计算每个点之间的距离是一项耗时的活动，在 Flink 中通过实现四叉树来简化。

使用四叉树通过对数据集进行分区来减少计算。这将计算减少到仅对数据子集进行。以下图表显示了使用四叉树和不使用四叉树的计算：

![k 最近邻连接](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-flink/img/image_06_004.jpg)

您可以在这里找到有关使用四叉树计算最近邻居的详细讨论：[`danielblazevski.github.io/assets/player/KeynoteDHTMLPlayer.html`](http://danielblazevski.github.io/assets/player/KeynoteDHTMLPlayer.html)。

四叉树并不总是表现得更好。如果数据是空间的，四叉树可能是最糟糕的选择。但作为开发人员，我们不需要担心这一点，因为 FlinkML 会根据可用的数据来决定是否使用四叉树。

以下代码片段显示了如何在 FlinkML 中使用 kNN 连接：

```java
import org.apache.flink.api.common.operators.base.CrossOperatorBase.CrossHint 
import org.apache.flink.api.scala._ 
import org.apache.flink.ml.nn.KNN 
import org.apache.flink.ml.math.Vector 
import org.apache.flink.ml.metrics.distances.SquaredEuclideanDistanceMetric 

val env = ExecutionEnvironment.getExecutionEnvironment 

// prepare data 
val trainingSet: DataSet[Vector] = ... 
val testingSet: DataSet[Vector] = ... 

val knn = KNN() 
  .setK(3) 
  .setBlocks(10) 
  .setDistanceMetric(SquaredEuclideanDistanceMetric()) 
  .setUseQuadTree(false) 
  .setSizeHint(CrossHint.SECOND_IS_SMALL) 

// run knn join 
knn.fit(trainingSet) 
val result = knn.predict(testingSet).collect() 

```

以下是一些我们可以用来微调结果的参数：

| **参数** | **描述** |
| --- | --- |
| `K` | 要搜索的最近邻居的数量。默认值为`5`。 |
| `DistanceMetric` | 设置用于计算两点之间距离的距离度量。默认情况下，使用欧几里德距离度量。 |
| `Blocks` | 输入数据应该分成的块数。将此数字设置为并行度的理想值。 |
| `UseQuadTree` | 设置是否使用四叉树进行处理。默认值为`None`。如果未指定任何内容，算法会自行决定。 |

## 实用程序

FlinkML 支持各种可扩展的实用程序，在进行数据分析和预测时非常方便。其中一个实用程序是距离度量。Flink 支持一组可以使用的距离度量。以下链接显示了 Flink 支持的距离度量：[`ci.apache.org/projects/flink/flink-docs-release-1.2/dev/libs/ml/distance_metrics.html`](https://ci.apache.org/projects/flink/flink-docs-release-1.2/dev/libs/ml/distance_metrics.html)。

如果前面提到的算法都不能满足您的需求，您可以考虑编写自己的自定义距离算法。以下代码片段显示了如何实现：

```java
class MyDistance extends DistanceMetric { 
  override def distance(a: Vector, b: Vector) = ... // your implementation  
} 

object MyDistance { 
  def apply() = new MyDistance() 
} 

val myMetric = MyDistance() 

```

使用距离度量的一个很好的应用是 kNN 连接算法，您可以设置要使用的距离度量。

另一个重要的实用程序是`Splitter`，它可以用于交叉验证。在某些情况下，我们可能没有测试数据集来验证我们的结果。在这种情况下，我们可以使用`Splitter`来拆分训练数据集。

以下是一个示例：

```java
// A Simple Train-Test-Split 
val dataTrainTest: TrainTestDataSet = Splitter.trainTestSplit(data, 0.6, true) 

```

在前面的示例中，我们将训练数据集分成了实际数据的 60%和 40%的部分。

还有另一种获取更好结果的方法，称为`TrainTestHoldout`拆分。在这里，我们使用一部分数据进行训练，一部分进行测试，另一部分用于最终结果验证。以下代码片段显示了如何实现：

```java
// Create a train test holdout DataSet 
val dataTrainTestHO: trainTestHoldoutDataSet = Splitter.trainTestHoldoutSplit(data, Array(6.0, 3.0, 1.0)) 

```

我们可以使用另一种策略，称为 K 折拆分。在这种方法中，训练集被分成*k*个相等大小的折叠。在这里，为每个折叠创建一个算法，然后针对其测试集进行验证。以下代码显示了如何进行 K 折拆分：

```java
// Create an Array of K TrainTestDataSets 
val dataKFolded: Array[TrainTestDataSet] =  Splitter.kFoldSplit(data, 10) 

```

我们还可以使用**多随机拆分**；在这里，我们可以指定要创建多少个数据集以及原始数据的什么部分：

```java
// create an array of 5 datasets of 1 of 50%, and 5 of 10% each  
val dataMultiRandom: Array[DataSet[T]] = Splitter.multiRandomSplit(data, Array(0.5, 0.1, 0.1, 0.1, 0.1)) 

```

## 数据预处理和管道

Flink 支持 Python scikit-learn 风格的管道。FlinkML 中的管道是将多个转换器和预测器链接在一起的特性。一般来说，许多数据科学家希望轻松地查看和构建机器学习应用的流程。Flink 允许他们使用管道的概念来实现这一点。

一般来说，ML 管道有三个构建块：

+   **估计器：** 估计器使用`fit`方法对模型进行实际训练。例如，在线性回归模型中找到正确的权重。

+   **转换器：** 转换器正如其名称所示，具有一个`transform`方法，可以帮助进行输入缩放。

+   **预测器：** 预测器具有`predict`方法，该方法应用算法生成预测，例如，SVM 或 MLR。

管道是一系列估计器、转换器和预测器。预测器是管道的末端，在此之后不能再链接任何内容。

Flink 支持各种数据预处理工具，这将有助于我们提高结果。让我们开始了解细节。

### 多项式特征

多项式特征是一种将向量映射到* d *次多项式特征空间的转换器。多项式特征有助于通过改变函数的图形来解决分类问题。让我们通过一个例子来理解这一点：

+   考虑一个线性公式：*F(x,y) = 1*x + 2*y;*

+   想象我们有两个观察结果：

+   *x=12* 和 *y=2*

+   *x=5* 和 *y =5.5*

在这两种情况下，我们得到 *f() = 16*。如果这些观察结果属于两个不同的类别，那么我们无法区分这两个类别。现在，如果我们添加一个称为*z*的新特征，该特征是前两个特征的组合*z = x+y*。

现在 *f(x,y,z) = 1*x + 2*y + 3*z*

现在相同的观察结果将是

+   *(1*12)+ (2*2) + (3*24) = 88*

+   *(1*5)+ (2*5.5) + (3*27.5) = 98.5*

通过使用现有特征添加新特征的方式可以帮助我们获得更好的结果。Flink 多项式特征允许我们使用预构建函数做同样的事情。

为了在 Flink 中使用多项式特征，我们有以下代码：

```java
val polyFeatures = PolynomialFeatures() 
      .setDegree(3) 

```

### 标准缩放器

标准缩放器通过使用用户指定的均值和方差来缩放输入数据。如果用户没有指定任何值，则默认均值为`0`，标准差为`1`。标准缩放器是一个具有`fit`和`transform`方法的转换器。

首先，我们需要像下面的代码片段中所示定义均值和标准差的值：

```java
  val scaler = StandardScaler() 
      .setMean(10.0) 
      .setStd(2.0) 

```

接下来，我们需要让它了解训练数据集的均值和标准差，如下面的代码片段所示：

```java
scaler.fit(trainingDataset)
```

最后，我们使用用户定义的均值和标准差来缩放提供的数据，如下面的代码片段所示：

```java
val scaledDS = scaler.transform(trainingDataset)
```

现在我们可以使用这些缩放后的输入数据进行进一步的转换和分析。

### 最小-最大缩放器

最小-最大缩放器类似于标准缩放器，但唯一的区别是它确保每个特征的缩放位于用户定义的`min`和`max`值之间。

以下代码片段显示了如何使用它：

```java
val minMaxscaler = MinMaxScaler()
.setMin(1.0)
.setMax(3.0)
minMaxscaler.fit(trainingDataset)
val scaledDS = minMaxscaler.transform(trainingDataset)
```

因此，我们可以使用这些数据预处理操作来增强结果。这些还可以组合在管道中创建工作流程。

以下代码片段显示了如何在管道中使用这些数据预处理操作：

```java
// Create pipeline PolynomialFeatures -> MultipleLinearRegression
val pipeline = polyFeatures.chainPredictor(mlr)
// train the model
pipeline.fit(scaledDS)
// The fitted model can now be used to make predictions
val predictions = pipeline.predict(testingDataset)
predictions.print()
```

完整的代码可在 GitHub 上找到[`github.com/deshpandetanmay/mastering-flink/tree/master/chapter06`](https://github.com/deshpandetanmay/mastering-flink/tree/master/chapter06)。

# 摘要

在本章中，我们了解了不同类型的机器学习算法。我们看了各种监督和无监督算法，以及它们各自的示例。我们还看了 FlinkML 提供的各种实用工具，在数据分析过程中非常方便。后来我们看了数据预处理操作以及如何在管道中使用它们。

在接下来的章节中，我们将看一下 Flink 的图处理能力。
