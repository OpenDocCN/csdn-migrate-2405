# MySQL8 管理手册（四）

> 原文：[`zh.annas-archive.org/md5/D5BC20BC3D7872C6C7F5062A8EE852A4`](https://zh.annas-archive.org/md5/D5BC20BC3D7872C6C7F5062A8EE852A4)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：MySQL 8 中的分区

在前一章中，解释了 MySQL 8 中的复制。这包括复制、配置和实现的详细解释。该章还解释了组复制与集群，并涵盖了复制方法作为解决方案。

在本章中，我们将在 MySQL 8 中进行分区。分区是管理和维护具有特定操作的数据的概念，具有多个运算符，并定义了控制分区的规则。基本上，它提供了一个配置钩子，以指定的方式管理底层数据文件。

我们将在分区上涵盖以下主题：

+   分区概述

+   分区类型

+   分区管理

+   分区选择

+   分区修剪

+   分区中的限制和限制

# 分区概述

分区的概念与数据库中数据存储的物理方面相关。如果查看`SQL`标准，它们并没有提供关于这个概念的太多信息，`SQL`语言本身意图独立于用于存储信息或特定于不同模式、表、行或列的数据的媒体或数据结构。先进的数据库管理系统已经添加了指定用于数据存储的物理位置的方法，如硬件、文件系统或两者兼而有之。在 MySQL 中，`InnoDB`存储引擎通过`表空间`的概念支持这些目的。

分区使我们能够将个别表的部分分布为在文件系统中的不同位置存储为单独的表。此外，分布是通过用户指定的规则提供的，例如模数、哈希函数或与简单值或范围匹配，并且用户提供的表达式充当通常称为分区函数的参数。

在 MySQL 8 中，目前`InnoDB`是唯一支持分区的存储引擎。在`InnoDB`存储引擎中，不需要额外的规范来启用分区。分区不能与存储引擎`MyISAM`、`CSV`、`FEDERATED`、`MERGE`一起使用。在本章中给出的所有示例中，我们假设默认存储引擎是`InnoDB`。

创建分区表时，使用默认存储引擎，与创建表时相同，并且可以通过指定`STORAGE ENGINE`选项来覆盖，就像我们对任何表所做的那样。以下示例演示了创建一个分为四个分区的哈希表，所有分区都使用`InnoDB`存储引擎：

```sql
CREATE TABLE tp (tp_id INT, amt DECIMAL(5,2), trx_date DATE)
 ENGINE=INNODB
 PARTITION BY HASH ( MONTH (trx_date) )
 PARTITIONS 4;
```

分区适用于表的所有索引和所有数据。它不适用于索引或数据的任何一方，反之亦然。它可以同时适用于索引和数据，也不能应用于表的一部分。

上述表`tp`没有定义唯一键或主键，但在一般实践中，我们通常有主键、唯一键或两者作为表的一部分，分区列的选择取决于这些键是否存在。分区列的选择在*分区键、主键和唯一键*部分中有详细说明。为了简化分区的概念，所给出的示例可能不包括这些键。

# 分区类型

MySQL 8 支持多种分区类型，列举如下：

+   `RANGE 分区`：根据列值的范围将行分配到分区

+   `LIST 分区`：根据与给定一组值匹配的列值将行分配到分区

+   `COLUMNS 分区`：使用`RANGE`或`LIST`分区将行分配到具有多个列值的分区

+   `HASH 分区`：根据用户指定的表达式在列值上进行评估来分配分区

+   `KEY 分区`：除了`HASH`分区外，还允许使用多个列值

+   子分区：除了分区外，还允许在分区表中进行进一步的划分，也称为复合分区

表的不同行可以分配到不同的物理分区；这被称为水平分区。表的不同列可以分配到不同的物理分区；这被称为垂直分区。MySQL 8 目前支持水平分区。

对于列表、范围和线性哈希类型的分区，分区列的值被传递给分区函数。分区函数返回一个整数值，即记录应存储在其中的分区号。分区函数必须是非随机和非常数的。分区函数不能包含查询，并且可以使用返回整数或 NULL 的 SQL 表达式，其中整数 intval 必须遵循表达式-MAXVALUE <= intval <= MAXVALUE。这里，-MAXVALUE 表示整数类型值的下限，MAXVALUE 是整数类型值的上限。

存储引擎必须对同一表的所有分区相同，但是在同一数据库或 MySQL 服务器中的不同分区表中使用不同的存储引擎没有限制。

# 分区管理

有不同的方法可以使用 SQL 语句修改分区表并执行操作，例如添加、重新定义、合并、删除或拆分现有的分区表。还可以使用 SQL 语句获取有关分区表和分区的信息。

MIN_ROWS 和 MAX_ROWS 可用于配置分区表中存储的最大和最小行数。

# 分区选择和修剪

还提供了分区和子分区的显式选择。它使得行匹配到 where 子句中给定的条件。在分区中，所描述的修剪概念不会扫描可能不存在匹配值的分区，并且使用查询应用，而分区选择适用于查询和许多 DML 语句。

# 分区的限制和限制

存储过程或函数、用户定义函数或插件以及用户变量或声明的变量在分区表达式中受到限制。在详细部分中还有几个适用于分区的限制和限制。

请参阅以下列表，了解分区的一些优点：

+   分区有助于在一个表中存储比文件系统分区或单个磁盘能容纳的更多数据。

+   通过删除仅包含无用数据的分区或分区，可以轻松删除已经变得无用的数据。在某些情况下，需要单独添加特定数据，可以根据指定的规则轻松地在单个或多个分区中进行分区。

+   基于分区数据自动进行的查询优化，不会在不适用于 where 条件的分区中搜索数据。

+   除了分区修剪外，还支持显式的分区选择，其中 where 子句应用于指定的分区或多个分区。

+   通过将数据搜索分离到多个磁盘，可以实现更大的查询吞吐量。

# 分区类型

在本节中，您将了解不同类型的分区以及使用特定分区的目的。以下是 MySQL 8 中可用的分区类型列表：

+   范围分区

+   列表分区

+   列分区

+   哈希分区

+   键分区

+   子分区

除了上述列表，我们还将在 MySQL 8 分区的详细部分中看到对 NULL 的处理。

数据库分区的一个非常常见的用例是按日期对数据进行分隔。MySQL 8 不支持日期分区，一些数据库系统明确提供了日期分区，但可以使用日期、时间或日期时间列创建分区方案，或者基于日期/时间相关表达式创建分区方案，这些表达式评估这些列类型的值。

如果使用`KEY`或`LINEAR KEY`分区，可以使用日期、时间或日期时间类型作为分区列的列值，而不需要进行任何修改，而在其他分区类型中，需要使用返回整数或`NULL`值的表达式。

无论您使用哪种类型的分区，分区始终会自动以整数顺序编号，按照创建顺序对每个分区进行编号。例如，如果表使用四个分区，它们将按照创建顺序分别编号为 0、1、2 和 3。

当您指定分区的数量时，它必须评估为正的、非零的整数，没有前导零。不允许使用小数分数作为分区号。

分区的名称不区分大小写，应遵循约定或规则，就像其他 MySQL 标识符（如表）一样。分区定义中使用的选项已经由`CREATE TABLE`语法提供。

现在，让我们详细查看分区，并检查每种类型，以了解它们之间的不同之处。

# RANGE 分区

在这种类型的分区中，正如名称所示，`RANGE`是在一个表达式中给出的，该表达式评估值是否在给定范围内。范围是使用`VALUES LESS THAN`运算符定义的，它们不应该重叠且应该是连续的。

在接下来的几个示例中，假设我们正在创建一个表，用于保存 25 家食品店的员工个人记录。这些商店的编号从 1 到 25，是一家拥有 25 家食品店的连锁店，如下所示：

```sql
CREATE TABLE employee (
 employee_id INT NOT NULL,
 first_name VARCHAR(30),
    last_name VARCHAR(30),
    hired_date DATE NOT NULL DEFAULT '1990-01-01',
    termination_date DATE NOT NULL DEFAULT '9999-12-31',
 job_code INT NOT NULL,
 store_id INT NOT NULL
);
```

现在让我们对表进行分区，这样您就可以根据需要按范围对表进行分区。假设您考虑使用除法将数据分为五部分，以`store_id`范围进行分区。为此，表创建定义将如下所示：

```sql
CREATE TABLE employee (
 employee_id INT NOT NULL,
    first_name VARCHAR(30),
    last_name VARCHAR(30),
    hired_date DATE NOT NULL DEFAULT '1990-01-01',
 termination_date DATE NOT NULL DEFAULT '9999-12-31',
 job_code INT NOT NULL,
 store_id INT NOT NULL
)
PARTITION BY RANGE (store_id) (
    PARTITION p0 VALUES LESS THAN (6),
    PARTITION p1 VALUES LESS THAN (11),
    PARTITION p2 VALUES LESS THAN (16),
    PARTITION p3 VALUES LESS THAN (21),
 PARTITION p4 VALUES LESS THAN (26)
);
```

因此，根据上述分区方案，所有插入的行，其中包含在 1 到 5 号店工作的员工，都存储在`p0`分区中，1 到 10 号店工作的员工存储在`p1`分区中，依此类推。如果您查看分区定义，分区按照最低到最高的`store_id`列值排序，`PARTITION BY RANGE`语法看起来类似于编程语句`if… elseif…`语句，不是吗？

好吧，您可能会想知道如果一条记录带有`store_id` `26`会发生什么；这将导致错误，因为服务器不知道在哪里放置记录。有两种方法可以防止发生此错误：

1.  通过在`INSERT`语句中使用`IGNORE`关键字。

1.  使用`MAXVALUE`而不是指定范围（`26`）。

当然，您也可以使用`ALTER TABLE`语句扩展限制，为 26-30 号店、30-35 号店等添加新的分区。

与`store_id`类似，您还可以根据作业代码对表进行分区-基于列值的范围。假设管理职位使用 5 位代码，办公室和支持人员使用 4 位代码，普通工人使用 3 位代码，那么分区表创建定义将如下所示：

```sql
CREATE TABLE employee (
 employee_id INT NOT NULL,
    first_name VARCHAR(30),
    last_name VARCHAR(30),
    hired_date DATE NOT NULL DEFAULT '1990-01-01',
    termination_date DATE NOT NULL DEFAULT '9999-12-31',
    job_code INT NOT NULL,
    store_id INT NOT NULL
)
PARTITION BY RANGE (job_code) (
 PARTITION p0 VALUES LESS THAN (1000),
 PARTITION p1 VALUES LESS THAN (10000),
    PARTITION p2 VALUES LESS THAN (100000)
);
```

您还可以根据员工加入的年份进行分区，例如根据`YEAR(hired_date)`的值进行分区。现在表定义将如下所示：

```sql
CREATE TABLE employee (
 employee_id INT NOT NULL,
    first_name VARCHAR(30),
    last_name VARCHAR(30),
    hired_date DATE NOT NULL DEFAULT '1990-01-01',
    termination_date DATE NOT NULL DEFAULT '9999-12-31',
    job_code INT NOT NULL,
    store_id INT NOT NULL
)
PARTITION BY RANGE (YEAR(hired_date)) (
    PARTITION p0 VALUES LESS THAN (1996),
    PARTITION p1 VALUES LESS THAN (2001),
 PARTITION p2 VALUES LESS THAN (2006),
 PARTITION p3 VALUES LESS THAN MAXVALUE
);
```

根据这个方案，所有在`1996`年之前录用的员工记录将存储在分区`p0`中，然后在`2001`年之前录用的记录将存储在分区`p1`中，`2001`年到`2006`年之间的记录将存储在`p2`中，其余的记录将存储在分区`p3`中。

**基于时间间隔的分区方案**可以使用以下两个选项来实现：

1.  通过`RANGE`对表进行分区，并使用在日期、时间或日期时间列值上操作的函数返回整数值作为分区表达式

1.  通过`RANGE COLUMN`对表进行分区，并使用日期、时间或日期时间列作为分区列

`RANGE COLUMN` 在 MySQL 8 中得到支持，并在`COLUMN PARTITIONING`部分有详细描述。

# LIST partitioning

正如其名称所示，`LIST`分区使用列表进行表分区。列表是在使用`VALUES IN (value_list)`进行分区时定义的逗号分隔的整数值；这里，`value_list`指的是逗号分隔的整数文字。

`LIST`分区在许多方面类似于`RANGE`分区，但也有不同之处。每个分区中使用的运算符是不同的。该运算符使用逗号分隔的值列表与列值或评估为整数值的分区表达式进行匹配。

考虑员工表作为一个例子，使用创建表语法的基本定义如下：

```sql
CREATE TABLE employee (
 employee_id INT NOT NULL,
 first_name VARCHAR(30),
 last_name VARCHAR(30),
 hired_date DATE NOT NULL DEFAULT '1990-01-01',
 termination_date DATE NOT NULL DEFAULT '9999-12-31',
 job_code INT NOT NULL,
 store_id INT NOT NULL
);
```

假设您希望将这 25 家食品店分配到五个区域-北、南、东、西和中央，分别使用店铺 ID 号(1,2,11,12,21,22)、(3,4,13,14,23,24)、(5,6,15,16,25)、(7,8,17,18)和(9,10,19,20)。

使用区域列表对表进行分区将为表分区提供以下定义：

```sql
CREATE TABLE employee (
 employee_id INT NOT NULL,
 first_name VARCHAR(30),
 last_name VARCHAR(30),
 hired_date DATE NOT NULL DEFAULT '1990-01-01',
 termination_date DATE NOT NULL DEFAULT '9999-12-31',
 job_code INT NOT NULL,
 store_id INT NOT NULL
)
PARTITION BY LIST (store_id) (
 PARTITION pNorth VALUES IN (1,2,11,12,21,22),
 PARTITION pSouth VALUES IN (3,4,13,14,23,24),
 PARTITION pEast VALUES IN (5,6,15,16,25),
 PARTITION pWest VALUES IN (7,8,17,18),
 PARTITION pCentral VALUES IN (9,10,19,20)
);
```

如前面的陈述所示，按区域进行分区意味着可以很容易地根据特定分区内的区域更新商店的记录。假设组织将西区卖给另一家公司；那么您可能需要使用查询中的`pWest`分区来删除西区的所有员工记录。执行`ALTER TABLE` employee `TRUNCATE PARTITION pWest`比`DELETE`语句`DELETE from employee where store_id IN (7,8,17,18)`更容易和高效；此外，您还可以使用`DROP`语句来删除员工记录- `ALTER TABLE employee DROP PARTITION pWest`。除了前面的语句执行，您还将从表分区定义中删除`pWest PARTITION`，然后需要再次使用`ALTER`语句来添加`pWest PARTITION`并恢复先前的分区表方案。

与`RANGE`分区类似，您还可以使用哈希或键来使用`LIST`分区生成复合分区，这也被称为`子分区`。随后的`子分区`专门部分将更详细地介绍`子分区`。

在`LIST`分区中，没有像`MAXVALUE`这样可以包含所有可能值的捕获机制。相反，您必须在`values_list`中管理预期的值列表，否则`INSERT`语句将导致错误，例如在以下示例中，表中没有值为 9 的分区：

```sql
CREATE TABLE tpl (
 cl1 INT,
 cl2 INT
)
PARTITION BY LIST (cl1) (
 PARTITION p0 VALUES IN (1,3,4,5),
 PARTITION p1 VALUES IN (2,6,7,8)
);

INSERT INTO tpl VALUES (9,5) ;
```

如前面的`INSERT`语句所示，值 9 不是在分区模式中给定的列表的一部分，因此会出现错误。如果使用多个值插入语句，同样的错误可能导致所有插入失败，不会插入任何记录；而是使用`IGNORE`关键字来避免这样的错误，如以下`INSERT`语句示例：

```sql
INSERT IGNORE INTO tpl VALUES (1,2), (3,4), (5,6), (7,8), (9,11);
```

# COLUMNS partitioning

顾名思义，这种类型的分区使用列本身。我们可以使用两种版本的列分区。一种是`RANGE COLUMN`，另一种是`LIST COLUMN`。除了`RANGE COLUMN`和`LIST COLUMN`分区之外，MySQL 8 还支持使用非整数类型的列来定义值范围或列表值。允许的数据类型列表如下：

+   所有`INT`、`BIGINT`、`MEDIUMINT`、`SMALLINT`和`TINYINT`列类型都支持`RANGE`和`LIST`分区列，但不支持其他数值列类型，如`FLOAT`或`DECIMAL`

+   支持`DATE`和`DATETIME`，但不支持与日期和时间相关的其他列类型作为分区列

+   支持字符串列类型`BINARY`、`VARBINARY`、`CHAR`和`VARCHAR`，但不支持`TEXT`和`BLOB`列类型作为分区列

现在，让我们逐一详细查看`RANGE COLUMN`分区和`LIST COLUMN`分区。

# RANGE COLUMN 分区

顾名思义，您可以使用`RANGE`分区和`RANGE COLUMN`分区使用列定义范围，但不同之处在于您可以定义多个列提供范围，并且还可以选择除整数之外的列类型。

因此，`RANGE COLUMN`分区与`RANGE`分区在以下列出的方式上有所不同：

+   `RANGE COLUMNS`可以使用一个或多个列，比较发生在列值列表之间，而不是标量值之间

+   `RANGE COLUMNS`只能使用列名，而不能使用任何表达式

+   `RANGE COLUMNS`分区列类型不仅限于`INTEGER`列类型，还可以使用字符串、日期和日期时间列类型作为分区列。

通过`RANGE COLUMNS`对表进行分区具有以下基本语法：

```sql
CREATE TABLE table_name
PARTITION BY RANGE COLUMNS (column_list) (
 PARTITION partition_name VALUES LESS THAN (value_list) [,
 PARTITION partition_name VALUES LESS THAN (value_list) ] [,
...]
)
column_list:
 column_name[, column_name] [, ...]
value_list :
 value[, value][, ...]
```

在前面的语法中，`column_list`代表分区列列表，`value_list`代表分区定义值列表，并且对于每个分区定义，`value_list`必须给出，并且与`column_list`中定义的相同数量的值一起给出。简而言之，`COLUMNS`子句中的列数（`column_list`）必须与`VALUES LESS THAN`子句中的值数（`value_list`）相同。

以下示例清楚地说明了它是什么以及如何与表定义一起使用：

```sql
CREATE TABLE trc (
 p INT,
    q INT,
    r CHAR(3),
    s INT
)
PARTITION BY RANGE COLUMNS (p,s,r) (
 PARTITION p0 VALUES LESS THAN (5,10,'ppp'),
 PARTITION p1 VALUES LESS THAN (10,20,'sss'),
 PARTITION p2 VALUES LESS THAN (15,30,'rrr'),
 PARTITION p3 VALUES LESS THAN (MAXVALUE,MAXVALUE,MAXVALUE)
);
```

现在，您可以使用以下语句将记录插入到表`trc`中：

```sql
INSERT INTO trc VALUES (5,9,'aaa',2) , (5,10,'bbb',4) , (5,12,'ccc',6) ;
```

# LIST COLUMN 分区

在这种类型的分区中，表分区定义中使用列列表，并且与`RANGE COLUMN`相似，必须提供相应列的值列表。与`RANGE COLUMN`类似，除了整数类型之外，还可以使用其他列类型，即字符串、日期和日期时间列类型。

假设您有这样的要求，即业务遍布 12 个城市，并且出于营销目的，您将它们分为三个城市的四个区域，如下所示：

+   **Zone 1 with cities**: Ahmedabad, Surat, Mumbai

+   **Zone 2 with cities**: Delhi, Gurgaon, Punjab

+   **Zone 3 with cities**: Kolkata, Mizoram, Hyderabad

+   **Zone 4 with cities**: Bangalore, Chennai, Kochi

现在，为客户数据创建一个表，该表有四个对应区域的分区，并用客户所居住的城市的名称列出它们。表分区定义如下：

```sql
CREATE TABLE customer_z (
 first_name VARCHAR(30),
    last_name VARCHAR(30),
    street_1 VARCHAR(35),
    street_2 VARCHAR(35),
    city VARCHAR(15),
    renewal DATE
)
PARTITION BY LIST COLUMNS (city) (
 PARTITION pZone_1 VALUES IN ('Ahmedabad', 'Surat', 'Mumbai'),
 PARTITION pZone_2 VALUES IN ('Delhi', 'Gurgaon', 'Punjab'),
 PARTITION pZone_3 VALUES IN ('Kolkata', 'Mizoram', 'Hyderabad'),
 PARTITION pZone_4 VALUES IN ('Bangalore', 'Chennai', 'Kochi')

);
```

与`RANGE COLUMN`分区类似，不需要在`COLUMNS()`子句中提供任何将列值转换为整数字面值的表达式，除了列名列表本身之外，不允许提供任何其他内容。

# HASH 分区

引入`HASH`分区的主要目的是确保在定义的分区数量之间均匀分布数据。因此，使用`HASH`分区需要指定要对其进行分区的表的列值或评估列值的表达式，以及要将分区表划分为的分区数。

要在表中定义`HASH`分区，需要在表定义中指定`PARTITION BY HASH (expr)`子句，其中`expr`是将返回整数的表达式，并且还需要使用`PARTITIONS n`指定分区的数量，其中`n`是一个正整数，表示分区的数量。

以下定义创建了一个在`store_id`列上使用`HASH`分区的表，分成了五个分区：

```sql
CREATE TABLE employee (
 employee_id INT NOT NULL,
 first_name VARCHAR(30),
 last_name VARCHAR(30),
 hired_date DATE NOT NULL DEFAULT '1990-01-01',
 termination_date DATE NOT NULL DEFAULT '9999-12-31',
 job_code INT NOT NULL,
 store_id INT NOT NULL
)
PARTITION BY HASH (store_id)
PARTITIONS 4;
```

在上面的语句中，如果排除`PARTITIONS`子句，则分区的数量将自动默认为 1。

# 线性哈希分区

MySQL 8 支持线性哈希，它基于线性二次幂算法，而不是基于哈希函数值的模数的常规哈希。`LINEAR HASH`分区需要在`PARTITION BY`子句中使用`LINEAR`关键字，如下所示：

```sql
CREATE TABLE employee (
 employee_id INT NOT NULL,
 first_name VARCHAR(30),
 last_name VARCHAR(30),
 hired_date DATE NOT NULL DEFAULT '1990-01-01',
 termination_date DATE NOT NULL DEFAULT '9999-12-31',
 job_code INT NOT NULL,
 store_id INT NOT NULL
)
PARTITION BY LINEAR HASH ( YEAR(hired_date))
PARTITIONS 4;
```

使用线性哈希的优势是更快的分区操作，劣势是与常规哈希分区相比数据分布不均匀。

# KEY 分区

这种类型的分区与`HASH`分区类似，只是使用了用户定义的表达式而不是哈希函数。`KEY PARTITIONING`在分区定义的`CREATE TABLE`语句中使用`PARTITION BY KEY`子句。`KEY`分区的语法规则与`HASH`分区类似，因此让我们列出一些不同之处以便理解：

+   在分区时使用`KEY`而不是`HASH`。

在`KEY()`中取一个或多个列名列表，如果在`KEY`中没有定义列，但表具有定义的主键或带有`NOT NULL`约束的唯一键，该列将自动作为`KEY`的分区列：

```sql
CREATE TABLE tk1 (
 tk1_id INT NOT NULL PRIMARY KEY,
    note VARCHAR(50)
)
PARTITION BY KEY ()
PARTITIONS 2;
```

与其他分区类型不同，列类型不仅限于`NULL`或整数值：

```sql
CREATE TABLE tk2 (
 cl1 INT NOT NULL,
 cl2 CHAR(10),
 cl3 DATE
)
PARTITION BY LINEAR KEY (cl1)
PARTITIONS 3;
```

如前面的示例语句所示，与`HASH`分区类似，`KEY`分区也支持`LINEAR KEY`分区，并且与`LINEAR HASH`分区具有相同的效果。

# 子分区

子分区也被称为复合分区，正如其名称所示，它只是将每个分区分成一个分区表本身。请参阅以下语句：

```sql
CREATE TABLE trs (trs_id INT, sold DATE)
PARTITION BY RANGE ( YEAR(sold) )
    SUBPARTITION BY HASH ( TO_DAYS(sold) )
    SUBPARTITIONS 2 (
        PARTITION p0 VALUES LESS THAN (1991),
        PARTITION p1 VALUES LESS THAN (2001),
        PARTITION p2 VALUES LESS THAN MAXVALUE
);
```

如前面的示例语句所示，表`trs`有三个`RANGE`分区，每个分区`p0、p1、p2`进一步分成两个子分区。有效地，整个表分成了六个分区。

使用`RANGE`或`LIST`分区的表可以进行子分区，并且子分区可以使用`KEY`或`HASH`分区类型。子分区的语法规则与常规分区相同，唯一的例外是在`KEY`分区中指定默认列，因为它不会自动为子分区获取列。

在使用子分区时需要考虑以下几点：

+   每个定义的分区的分区数量必须相同。

+   必须在`SUBPARTITIONING`子句中指定名称，或者指定一个默认选项。

+   指定的子分区名称必须在整个表中是唯一的。

# 分区中的 NULL 处理

MySQL 8 没有特定于禁止`NULL`作为分区的列值、分区表达式或用户定义表达式的内容。即使`NULL`被允许作为一个值，表达式返回的值也必须是整数，因此 MySQL 8 对分区的实现是将`NULL`视为小于`ORDER BY`子句中的任何非`NULL`值。

`NULL`处理的行为在不同类型的分区中有所不同：

+   **在`RANGE`分区中处理`NULL`**：如果插入了包含`NULL`值的列，行将被插入到范围中指定的最低分区中。

+   **使用`LIST`分区处理`NULL`值**：如果表具有使用`LIST`分区定义的分区，并且其分区使用值列表明确指定`NULL`作为`value_list`中的值，则插入将成功；否则，将出现错误，因为表没有为`NULL`指定分区。

+   **使用`HASH`和`KEY`分区处理`NULL`值**：当使用`HASH`或`KEY`分区定义表分区时，`NULL`的处理方式不同，如果分区表达式返回`NULL`，它将被包装为零值。因此，根据分区插入操作将成功将记录插入到零分区。

# 分区管理

使用`SQL`语句修改分区表有很多方法——您可以使用`ALTER TABLE`语句删除、添加、合并、拆分或重新定义分区。还有一些方法可以检索分区表和分区信息。我们将在以下部分中看到每个方法：

+   `RANGE`和`LIST`分区管理

+   `HASH`和`KEY`分区管理

+   分区维护

+   获取分区信息

# RANGE 和 LIST 分区管理

对于`RANGE`和`LIST`分区类型，添加和删除分区的处理方式类似。可以使用`ALTER TABLE`语句的`DROP PARTITION`选项删除通过`RANGE`或`LIST`分区进行分区的表。

在执行`ALTER TABLE ... DROP PARTITION`语句之前，请确保您拥有`DROP`权限。`DROP PARTITION`将删除所有数据，并从表分区定义中删除分区。

以下示例说明了`ALTER TABLE`语句的`DROP PARTITION`选项：

```sql
SET @@SQL_MODE = '';
CREATE TABLE employee (
 id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
 first_name VARCHAR(25) NOT NULL,
 last_name VARCHAR(25) NOT NULL,
 store_id INT NOT NULL,
 department_id INT NOT NULL
) 
 PARTITION BY RANGE(id) (
 PARTITION p0 VALUES LESS THAN (5),
 PARTITION p1 VALUES LESS THAN (10),
 PARTITION p2 VALUES LESS THAN (15),
 PARTITION p3 VALUES LESS THAN MAXVALUE
);
INSERT INTO employee VALUES
 ('', 'Chintan', 'Mehta', 3, 2), ('', 'Bhumil', 'Raval', 1, 2),
 ('', 'Subhash', 'Shah', 3, 4), ('', 'Siva', 'Stark', 2, 4),
 ('', 'Chintan', 'Gajjar', 1, 1), ('', 'Mansi', 'Panchal', 2, 3),
 ('', 'Hetal', 'Oza', 2, 1), ('', 'Parag', 'Patel', 3, 1),
 ('', 'Pooja', 'Shah', 1, 3), ('', 'Samir', 'Bhatt', 2, 4),
 ('', 'Pritesh', 'Shah', 1, 4), ('', 'Jaymin', 'Patel', 3, 2),
 ('', 'Ruchek', 'Shah', 1, 2), ('', 'Chandni', 'Patel', 3, 3),
 ('', 'Mittal', 'Patel', 2, 3), ('', 'Shailesh', 'Patel', 2, 2),
 ('', 'Krutika', 'Dave', 3, 3), ('', 'Dinesh', 'Patel', 3, 2);

ALTER TABLE employee DROP PARTITION p2;
```

在执行`ALTER TABLE employee DROP PARTITION p2;`语句后，您可以看到所有数据都从分区`p2`中删除。如果您想删除所有数据但又需要保留表定义和分区方案，可以使用`TRUNCATE PARTITION`选项来实现类似的结果。

要向现有分区表添加新的`LIST`或`RANGE`分区，可以使用`ALTER TABLE ... ADD PARTITION`语句。

通过使用`SHOW CREATE TABLE`语句，您可以验证并查看`ALTER TABLE`语句对表定义和分区模式的影响是否符合预期。

# HASH 和 KEY 分区管理

`HASH`或`KEY`类型的表分区与`RANGE`或`LIST`类型的分区相似。如果表是通过`HASH`或`KEY`类型的分区进行分区，那么无法删除分区，但可以使用`ALTER TABLE ... COALESCE PARTITION`选项合并`HASH`或`KEY`分区。

假设您有一个客户表数据，通过`HASH`分区分割，分为十二个分区如下：

```sql
CREATE TABLE client (
 client_id INT,
 first_name VARCHAR(25),
 last_name VARCHAR(25),
 signed DATE
)
PARTITION BY HASH (MONTH (signed))
PARTITIONS 12;
```

在上述表分区模式中，如果您想将分区数量从十二个减少到八个，可以使用以下`ALTER TABLE`语句：

```sql
ALTER TABLE client COALESCE PARTITION 8;
```

在上述语句中，数字 8 表示要从表中删除的分区数量。您不能删除超过表分区模式中已存在的分区数量。同样，您可以使用`ALTER TABLE... ADD PARTITION`语句添加更多分区。

# 分区维护

有许多维护任务可以通过多个语句在多个表和分区上完成。可以使用`ANALYSE TABLE`、`CHECK TABLE`、`REPAIR TABLE`和`OPTIMIZE TABLE`等语句，这些语句专门用于支持分区表。

有许多`ALTER TABLE`的扩展可用于单个或多个分区表的操作，列举如下：

+   **重建分区**：此选项会删除分区中的所有记录并重新插入，因此在碎片整理过程中很有帮助。以下是一个示例：

```sql
 ALTER TABLE trp REBUILD  PARTITION p0, p1, p2;
```

+   **优化分区**：如果从表的一个或多个分区中删除了许多行，或者在可变长度列类型（如`VARCHAR`、`BLOB`、`TEXT`等）的大量数据中有许多行更改，可以执行`OPTIMIZE PARTITION`来回收分区数据文件中未使用的空间。以下是一个例子：

```sql
 ALTER TABLE top OPTIMIZE PARTITION p0, p1, p2;
```

`ALTER TABLE ... OPTIMIZE PARTITION`与`InnoDB`存储引擎不兼容，因此应改用`ALTER TABLE ... REBUILD PARTITION`和`ALTER TABLE ... ANALYZE PARTITION`。

+   **分析分区**：在此选项中，读取并存储分区的关键分布。以下是一个例子：

```sql
 ALTER TABLE tap ANALYZE  PARTITION p1, p2;
```

+   **修复分区**：仅在发现损坏的分区需要修复时使用。以下是一个例子：

```sql
 ALTER TABLE trp REPAIR PARTITION p3;
```

+   **检查分区**：此选项用于检查分区中的任何错误，例如在非分区表中使用的`CHECK TABLE`选项。以下是一个例子：

```sql
 ALTER TABLE tcp CHECK PARTITION p0;
```

在所有上述选项中，有一个选项可以使用`ALL`而不是特定分区，以便对所有分区执行操作。

# 获取分区信息

可以通过多种方式获取有关分区的信息，如下所示：

+   `SHOW CREATE TABLE`语句可用于查看包含分区表中所有分区子句的分区模式信息

+   `SHOW TABLE STATUS`语句可用于通过查看其状态检查表是否已分区

+   `EXPLAIN SELECT`语句可用于查看给定`SELECT`选项使用的分区

+   使用`INFORMATION_SCHEMA.PARTITIONS`表查询分区表信息。

以下是使用`SHOW CREATE TABLE`语句选项查看分区信息的示例：

```sql
SHOW CREATE TABLE employee;
```

从前述语句的输出中，可以看到分区模式的单独信息，包括表模式的常见信息。

同样，您可以从`INFORMATION_SCHEMA.PARTITIONS`表中检索有关分区的信息。

`EXPLAIN`选项提供了许多有关分区的信息。例如，它提供了从特定于分区的查询中获取的行数。分区将根据查询语句进行搜索。它还提供有关键的信息。

`EXPLAIN`也用于从非分区表中获取信息。如果没有分区，则不会出现任何错误，但在分区列中会给出一个`NULL`值。

# 分区选择和修剪

在本节中，您将看到分区如何通过称为分区修剪的优化器来优化`SQL`语句的执行，并使用`SQL`语句有效地选择分区数据并对分区进行修改操作。

# 分区修剪

分区修剪与分区中的优化概念相关。在分区修剪中，基于查询语句应用了“不要扫描可能不存在匹配值的分区”的概念。

假设有一个分区表`tp1`，使用以下语句创建：

```sql
CREATE TABLE tp1 (
 first_name VARCHAR (30) NOT NULL,
 last_name VARCHAR (30) NOT NULL,
 zone_code TINYINT UNSIGNED NOT NULL,
 doj DATE NOT NULL
)
PARTITION BY RANGE (zone_code) (
 PARTITION p0 VALUES LESS THAN (65),
 PARTITION p1 VALUES LESS THAN (129),
 PARTITION p2 VALUES LESS THAN (193),
 PARTITION p3 VALUES LESS THAN MAXVALUE
);
```

在前面的示例表`tp1`中，假设您想从以下`SELECT`语句中检索结果：

```sql
SELECT first_name, last_name , doj from tp1 where zone_code > 126 AND zone_code < 131;
```

现在，您可以从前述语句中看到，根据该语句，没有数据存在于分区`p0`或`p3`中，因此我们只需要在`p1`或`p2`中搜索匹配的数据。因此，通过限制搜索，可以在表的所有分区中花费更少的时间和精力进行匹配和搜索数据。这种去除不匹配分区的操作称为修剪。

优化器可以利用分区修剪来执行查询执行，与具有相同模式、数据和查询语句的非分区表相比，速度更快。

优化器可以根据`WHERE`条件的减少在以下情况下进行修剪：

+   `partition_column IN (constant1, constant2, ..., contantN)`

+   `partition_column = constant`

在第一种情况下，优化器评估列表中每个值的分区表达式，并创建在评估期间匹配的分区列表，然后只在此分区列表中执行扫描或搜索。

在第二种情况下，优化器仅根据给定的常量或特定值评估分区表达式，并确定哪个分区包含该值，并且只在此分区上执行搜索或扫描。在这种情况下，可以使用另一个算术比较而不是等于。

目前，修剪不支持`INSERT`语句，但支持`SELECT`，`UPDATE`和`DELETE`语句。

修剪也适用于优化器可以将范围转换为等效值列表的短范围。当分区表达式由可以减少为相等集的相等性或范围组成，或者分区表达式表示递增或递减关系时，可以应用优化器。

修剪也适用于使用`TO_DAYS()`或`YEAR()`函数进行分区的`DATE`或`DATETIME`列类型，并且如果这些表在其分区表达式中使用`TO_SECONDS()`函数，也适用。

假设您有一个表`tp2`，如下语句所示：

```sql
CREATE TABLE tp2 (
 first_name VARCHAR (30) NOT NULL,
 last_name VARCHAR (30) NOT NULL,
 zone_code TINYINT UNSIGNED NOT NULL,
 doj DATE NOT NULL
)
PARTITION BY RANGE (YEAR(doj)) (
 PARTITION p0 VALUES LESS THAN (1971),
 PARTITION p1 VALUES LESS THAN (1976),
 PARTITION p2 VALUES LESS THAN (1981),
 PARTITION p3 VALUES LESS THAN (1986),
 PARTITION p4 VALUES LESS THAN (1991),
 PARTITION p5 VALUES LESS THAN (1996),
 PARTITION p6 VALUES LESS THAN (2001),
 PARTITION p7 VALUES LESS THAN (2006),
 PARTITION p8 VALUES LESS THAN MAXVALUE
);
```

现在，在前面的语句中，以下语句可以从分区修剪中受益：

```sql
SELECT * FROM tp2  WHERE doj = '1982-06-24';
UPDATE tp2  SET region_code = 8 WHERE doj BETWEEN '1991-02-16' AND '1997-04-26';
DELETE FROM tp2  WHERE doj >= '1984-06-22' AND doj <= '1999-06-22';
```

对于最后一条语句，优化器可以采取以下行动：

1.  找到具有范围低端的分区为`YEAR('1984-06-22')`，得到值 1984，找到在`p3`分区中。

1.  找到具有范围高端的分区为`YEAR('1999-06-22')`，得到值 1999，找到在`p5`分区中。

1.  仅扫描上述两个确定的分区和它们之间的任何分区。

因此，在上述情况下，要扫描的分区仅为`p3`，`p4`和`p5`，而其余分区在匹配时可以忽略。

前面的示例使用了`RANGE`分区，但分区修剪也适用于其他类型的分区。假设您有表`tp3`的模式如下语句所示：

```sql
CREATE TABLE tp3 (
 first_name VARCHAR (30) NOT NULL,
 last_name VARCHAR (30) NOT NULL,
 zone_code TINYINT UNSIGNED NOT NULL,
 description VARCHAR (250),
 doj DATE NOT NULL
)
PARTITION BY LIST(zone_code) (
 PARTITION p0 VALUES IN (1, 3),
 PARTITION p1 VALUES IN (2, 5, 8),
 PARTITION p2 VALUES IN (4, 9),
 PARTITION p3 VALUES IN (6, 7, 10)
);
```

对于前面的表模式，请考虑是否要执行此语句`SELECT * FROM tp3 WHERE zone_code BETWEEN 1 AND 3`。优化器确定哪些分区可以具有值`1`，`2`和`3`，并找到`p1`和`p0`，因此跳过其余的分区`p3`和`p2`。

具有常量的列值可以被修剪，如以下示例语句：

```sql
UPDATE tp3 set description = 'This is description for Zone 5' WHERE zone_code = 5;
```

只有当范围的大小小于分区数时才执行优化。

# 分区选择

还支持显式选择分区和子分区，这使得行匹配到 where 子句中给定的条件 - 这称为分区选择。它与分区修剪非常相似，因为只有特定的分区用于匹配，但在以下两个关键方面有所不同：

+   要扫描的分区由发出语句的人指定，而不是像分区修剪那样自动进行。

+   分区修剪仅限于查询，而分区选择支持查询和多个`DML`语句

支持显式分区选择的 SQL 语句如下所示：

+   `INSERT`

+   `SELECT`

+   `UPDATE`

+   `REPLACE`

+   `LOAD DATA`

+   `LOAD XML`

+   `DELETE`

用于显式分区选择的`PARTITION`选项的以下语法：

```sql
PARTITION (partition_names)
partition_names :
 partition_name, ...
```

上述选项总是跟随它所属的表结构或表模式。`partition_names`代表分区或子分区的逗号分隔名称列表，将用于分区。`partition_names`中的分区和子分区名称可以是任何顺序，甚至可以重叠，但列表中的每个名称必须是特定表的现有分区或子分区名称，否则语句将失败，并显示错误消息`partition_name`不存在。

如果使用`PARTITION`选项，只有列出的分区和子分区才会被检查匹配的行。`PARTITION`选项也可以用于`SELECT`语句，以检索属于任何给定分区的行。

假设你使用以下语句创建了表`employee`：

```sql
SET @@SQL_MODE = '';
CREATE TABLE employee (
 id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
 first_name VARCHAR(25) NOT NULL,
 last_name VARCHAR(25) NOT NULL,
 store_id INT NOT NULL,
 department_id INT NOT NULL
) 
 PARTITION BY RANGE(id) (
 PARTITION p0 VALUES LESS THAN (5),
 PARTITION p1 VALUES LESS THAN (10),
 PARTITION p2 VALUES LESS THAN (15),
 PARTITION p3 VALUES LESS THAN MAXVALUE
);
INSERT INTO employee VALUES
 ('', 'Chintan', 'Mehta', 3, 2), ('', 'Bhumil', 'Raval', 1, 2),
 ('', 'Subhash', 'Shah', 3, 4), ('', 'Siva', 'Stark', 2, 4),
 ('', 'Chintan', 'Gajjar', 1, 1), ('', 'Mansi', 'Panchal', 2, 3),
 ('', 'Hetal', 'Oza', 2, 1), ('', 'Parag', 'Patel', 3, 1),
 ('', 'Pooja', 'Shah', 1, 3), ('', 'Samir', 'Bhatt', 2, 4),
 ('', 'Pritesh', 'Shah', 1, 4), ('', 'Jaymin', 'Patel', 3, 2),
 ('', 'Ruchek', 'Shah', 1, 2), ('', 'Chandni', 'Patel', 3, 3),
 ('', 'Mittal', 'Patel', 2, 3), ('', 'Shailesh', 'Patel', 2, 2),
 ('', 'Krutika', 'Dave', 3, 3), ('', 'Dinesh', 'Patel', 3, 2);
```

现在，如果你检查分区`p1`，你会看到以下输出，因为行添加到分区`p1`中：

```sql
mysql> SELECT * FROM employee PARTITION (p1);
+----+-----------+------------+----------+---------------+
| id | last_name | last_name | store_id | department_id |
+----+-----------+------------+----------+---------------+
| 5 | Chintan | Gajjar | 1 | 1 |
| 6 | Mansi | Panchal | 2 | 3 |
| 7 | Hetal | Oza | 2 | 1 |
| 8 | Parag | Patel | 3 | 1 |
| 9 | Pooja | Shah | 1 | 3 |
+----+-----------+------------+----------+---------------+
5 rows in set (0.00 sec) 
```

如果使用这个语句`SELECT * FROM employee WHERE id BETWEEN 5 AND 9;`，将得到相同的输出。

为了从多个分区中检索行，可以使用逗号分隔的分区名称列表。例如，`SELECT * FROM employee PARTITION (p1,p2)`，将得到来自分区`p1`和`p2`的所有行，并排除其余分区。

可以使用任何支持的分区类型来使用分区选择语句。当使用`LINEAR HASH`或`LINEAR KEY`分区类型创建表时，MySQL 8 会自动添加分区名称，而且这也适用于子分区。在对这个表执行`SELECT`语句时，可以指定 MySQL 8 生成的分区名称来检索特定分区的数据。

`PARTITION`选项也适用于`SELECT`语句，用于`INSERT ... SELECT`语句，可以插入从特定分区或子分区检索的数据。

`PARTITION`选项也适用于具有特定分区或子分区数据的表的连接查询的`SELECT`语句。

# 分区中的限制和限制

在本节中，您将看到 MySQL 8 分区中的限制和限制，涵盖了禁止的结构、性能考虑和与存储引擎和函数相关的限制方面的详细信息，以便从表分区中获得最佳效益。

# 分区键、主键和唯一键

分区键与主键和唯一键之间的关系对于分区模式结构设计非常重要。简而言之，规则是分区表中用于分区的所有列必须包括表的每个唯一键。因此，包括表上的主键列在内的每个唯一键都必须是分区表达式的一部分。看一下以下使用不符合规则的唯一键的`CREATE TABLE`语句的例子：

```sql
CREATE TABLE tk1 (
 cl1 INT NOT NULL,
 cl2 DATE NOT NULL,
 cl3 INT NOT NULL,
 cl4 INT NOT NULL,
 UNIQUE KEY (cl1, cl2)
)
PARTITION BY HASH(cl3)
PARTITIONS 4;

CREATE TABLE tk2 (
 cl1 INT NOT NULL,
 cl2 DATE NOT NULL,
 cl3 INT NOT NULL,
 cl4 INT NOT NULL,
 UNIQUE KEY (cl1),
 UNIQUE KEY (cl3)
)
PARTITION BY HASH(cl1 + cl3)
PARTITIONS 4;
```

在上述每个用于创建表`tk1`和`tk2`的语句中，建议的表可以至少有一个唯一键，该键不包括分区表达式中的所有列。

现在看一下以下修改后的表创建语句，这些语句已经可以工作，并且从无效变为有效：

```sql
CREATE TABLE tk1 (
 cl1 INT NOT NULL,
 cl2 DATE NOT NULL,
 cl3 INT NOT NULL,
 cl4 INT NOT NULL,
 UNIQUE KEY (cl1, cl2, cl3)
)
PARTITION BY HASH(cl3)
PARTITIONS 4;

CREATE TABLE tk2 (
 cl1 INT NOT NULL,
 cl2 DATE NOT NULL,
 cl3 INT NOT NULL,
 cl4 INT NOT NULL,
 UNIQUE KEY (cl1, cl3)
)
PARTITION BY HASH(cl1 + cl3)
PARTITIONS 4;
```

如果你看一下以下表结构，它根本无法分区，因为没有办法包含可以成为分区键列的唯一键列：

```sql
CREATE TABLE tk4 (
 cl1 INT NOT NULL,
 cl2 INT NOT NULL,
 cl3 INT NOT NULL,
 cl4 INT NOT NULL,
 UNIQUE KEY (cl1, cl3),
 UNIQUE KEY (cl2, cl4)
);
```

根据定义，每个主键都是唯一键。这个限制也适用于表的主键。以下是表`tk5`和`tk6`的两个无效语句的例子：

```sql
CREATE TABLE tk5 (
 cl1 INT NOT NULL,
 cl2 DATE NOT NULL,
 cl3 INT NOT NULL,
 cl4 INT NOT NULL,
 PRIMARY KEY(cl1, cl2)
)
PARTITION BY HASH(cl3)
PARTITIONS 4;

CREATE TABLE tk6 (
 cl1 INT NOT NULL,
 cl2 DATE NOT NULL,
 cl3 INT NOT NULL,
 cl4 INT NOT NULL,
 PRIMARY KEY(cl1, cl3),
 UNIQUE KEY(cl2)
)
PARTITION BY HASH( YEAR(cl2) )
PARTITIONS 4;
```

在上述两个语句中，所有引用的列都不包括相应的主键在分区表达式中。以下语句是有效的：

```sql
CREATE TABLE tk7 (
 cl1 INT NOT NULL,
 cl2 DATE NOT NULL,
 cl3 INT NOT NULL,
 cl4 INT NOT NULL,
 PRIMARY KEY(cl1, cl2)
)
PARTITION BY HASH(cl1 + YEAR(cl2))
PARTITIONS 4;

CREATE TABLE tk8 (
 cl1 INT NOT NULL,
 cl2 DATE NOT NULL,
 cl3 INT NOT NULL,
 cl4 INT NOT NULL,
 PRIMARY KEY(cl1, cl2, cl4),
 UNIQUE KEY(cl2, cl1)
)
PARTITION BY HASH(cl1 + YEAR(cl2))
PARTITIONS 4;
```

如果表没有唯一键或主键，则该限制不适用，并且可以根据分区类型的兼容列类型在分区表达式中使用任何列。所有上述限制也适用于`ALTER TABLE`语句。

# 与存储引擎相关的分区限制

分区支持不是由 MySQL 服务器提供的，而是来自 MySQL 8 中的存储引擎自己或本机分区处理程序。在 MySQL 8 中，`InnoDB`存储引擎只提供本机分区处理程序，因此分区表的创建不适用于任何其他存储引擎。

`ALTER TABLE ... OPTIMIZE PARTITION`在`InnoDB`存储引擎中无法正确工作，因此请改用`ALTER TABLE ... REBUILD PARTITION`和`ALTER TABLE ... ANALYZE PARTITION`操作。

# 与函数相关的分区限制

在分区表达式中，只有以下列出的 MySQL 8 函数是允许的：

+   `ABS()`: 它为给定参数提供了绝对值

+   `CEILING()`: 它为给定参数提供可能的最小整数

+   `DAY()`: 它为给定日期提供月份中的日期

+   `DAYOFMONTH()`: 它提供给定日期的月份中的日期，与`DAY()`相同

+   `DAYOFWEEK()`: 它为给定日期提供星期几的编号

+   `DAYOFYEAR()`: 它为给定日期提供一年中的日期

+   `DATEDIFF()`: 它提供两个给定日期之间的天数

+   `EXTRACT()`: 它提供给定参数的一部分

+   `FLOOR()`: 它为给定参数提供了可能的最大整数值

+   `HOUR()`: 它从给定参数中提供小时数

+   `MICROSECOND()`: 它从给定参数中提供微秒数

+   `MINUTE()`: 它从给定参数中提供分钟数

+   `MOD()`: 它执行模运算并提供`N`除以`M`的余数，其中`MOD(N,M)`

+   `MONTH()`: 它从给定参数中提供月份

+   `QUARTER()`: 它从给定参数中提供季度

+   `SECOND()`: 它从给定参数中提供秒数

+   `TIME_TO_SEC()`: 它从给定时间值参数中提供秒数

+   `TO_DAYS()`: 它为给定参数提供了从公元 0 年开始的天数

+   `TO_SECONDS()`: 它为给定参数提供从公元 0 年开始的秒数

+   `UNIX_TIMESTAMP() (with TIMESTAMP columns)`: 它为给定参数提供自'1970-01-01 00:00:00' UTC 以来的秒数

+   `WEEKDAY()`: 它为给定参数提供星期几的索引

+   `YEAR()`: 它为给定参数提供年份

+   `YEARWEEK()`: 它为给定参数提供年份和周数

分区修剪支持 MySQL 8 中的`TO_DAYS()`、`TO_SECONDS()`、`TO_YEAR()`和`UNIX_TIMESTAMP()`函数。

# 总结

在本章中，我们学习了不同类型的分区和分区的需求。我们还详细介绍了管理所有类型的分区的信息。我们学习了分区修剪和选择分区，这是优化器使用的。我们还讨论了在使用分区时需要考虑的适用限制和限制。

在下一章中，您将学习如何在 MySQL 8 中进行扩展，并了解在提供 MySQL 8 可扩展性时面临的常见挑战。您还将学习如何使 MySQL 服务器高度可用并实现高可用性。


# 第十章：MySQL 8 – 可扩展性和高可用性

在本章中，我们将涵盖 MySQL 8 可扩展性和高可用性的以下重要主题：

+   MySQL 8 中可扩展性和高可用性的概述

+   扩展 MySQL 8

+   MySQL 8 的扩展性挑战

+   实现高可用性

在我们继续详细讨论之前，让我们先来了解一下 MySQL 8 中的可扩展性和高可用性

# MySQL 8 中可扩展性和高可用性的概述

在任何类型的应用程序中，无论是移动、Web 门户、网站、社交、电子商务、企业还是云应用程序，数据都是业务的核心部分。数据可用性被认为是任何企业或组织的最重要关注点。数据丢失或应用程序的任何停机都可能导致严重的财务损失，也会影响公司在市场上的信誉。

如果我们考虑一个在线购物网站的例子，它在特定区域有一个良好覆盖的市场，有客户和良好的商业信誉。如果这家企业面临数据丢失或任何应用程序服务器或数据库服务器的停机问题，将影响整个业务。许多客户会失去对企业的信任，企业也会在财务和信用方面遭受损失。

没有一个单一的公式可以提供解决方案。不同的企业有他们自己的应用程序需求、业务需求、不同的流程、不同地点的不同基础设施和运营能力。在这些情况下，技术在实现高可用性方面起着重要作用。

根据可扩展性和高可用性的要求，MySQL 可以用于各种应用程序，并且根据需要能够克服故障，包括 MySQL 的故障、操作系统的故障或可能影响可用性的任何计划维护活动。简单来说，可扩展性具有在 MySQL 服务器之间分配数据库负载和应用程序查询的能力。

选择正确的高可用性解决方案时，重要的属性取决于系统可以被称为高可用性的程度，因此这些要求因系统而异。对于较小的应用程序，用户负载预计不会很高，设置复制或集群环境可能会导致非常高的成本。在这种情况下，提供正确的 MySQL 配置也足以减少应用程序负载。

以下部分简要描述了 MySQL 8 支持的主要高可用性解决方案。

# MySQL 复制

MySQL 复制允许将一个服务器上的数据复制到多个 MySQL 服务器上。MySQL 复制提供主从设计，因此组中的一个服务器充当主服务器，应用程序执行写操作，然后主服务器将数据复制到多个从服务器。复制是高可用性的一个成熟解决方案，被 Facebook、Twitter 等社交巨头使用。

# MySQL 集群

这是 MySQL 的另一个流行的高可用性解决方案。集群使数据能够自动共享到多个 MySQL 服务器上进行复制。它旨在提供更好的可用性和吞吐量。

# Oracle MySQL 云服务

Oracle MySQL 云服务提供了一种有效的方式来构建一个安全、具有成本效益的 MySQL 数据库服务，用于现代应用程序。与本地部署相比，它被证明是可扩展和成本效益的，资源利用率较低。

# 具有 Solaris 集群的 MySQL

MySQL 数据服务提供的 Sun Solaris 集群提供了有序启动和关闭、故障监控和 MySQL 服务的自动故障转移机制。Sun 集群 HA 保护的 MySQL 数据服务的以下 MySQL 组件。

使用第三方解决方案可以获得更多选项。用于实现高可用数据库服务的每种架构都因其提供的可用性水平而有所不同。这些架构可以分为三个主要类别：

+   数据复制

+   集群化和虚拟化系统

+   地理复制集群

根据问题的最佳答案，您可以选择适合您的应用程序的正确选项，以实现最低成本和高可用性解决方案。这次讨论为我们提供了 MySQL 8 高可用性的公平概述。

# MySQL 8 的扩展

可伸缩性是将任何应用程序查询的负载分布到各种 MySQL 实例的能力。对于某些情况，数据不能超过某个限制或用户数量不会超出范围是不可预测的。可扩展的数据库将是一个更可取的解决方案，以便在任何时候我们都能满足规模的意外需求。MySQL 是一个有回报的数据库系统，因为它具有可扩展性，可以在水平和垂直方面进行扩展；在数据方面，将客户端查询分布到各种 MySQL 实例是相当可行的。向 MySQL 集群添加性能非常容易，以处理负载。

实现高可用性（HA）和可伸缩性的要求可能因系统而异。每个系统都需要不同的配置才能实现这些能力。当我们考虑在 MySQL 中进行扩展时，会有许多问题，而在我们在 MySQL 中执行扩展操作时：

+   为什么需要扩展？

+   在 MySQL 中扩展的优势是什么？

+   在我们在 MySQL 中进行扩展时，需要牢记哪些要点？

+   如何进行扩展工作？

+   数据安全吗-它是否提供数据安全的保证？

+   还有很多...

让我们举一个实时例子来理解为什么我们需要在 MySQL 中进行扩展。我们有一个在线电子商务网站，它已经覆盖了一个小市场，用户和网站的点击量有限，只有一个数据库服务器。业务正在不断增长；业务的性能不断提高，用户数量也在增加，但我们的单个数据库服务器并不能始终满足所有请求和性能的扩展。这可能导致服务器崩溃，业务可能会在利润和市场信用方面遭受损失。为了避免这种情况，可伸缩性将发挥重要作用。如果由于任何原因客户的请求失败，或者节点宕机，其他节点将迅速处理并向客户提供适当的响应。

扩展是为了持续提高数据库响应时间的性能和提高产品的生产力。它将有助于最终产品在数据可伸缩性、性能和更好结果方面。集群和复制都是 MySQL 中可以用于扩展的关键功能。

# 使用集群进行扩展

基本集群架构分为四个不同的层：

+   客户端节点

+   应用节点

+   管理节点

+   数据节点

这些显示在以下图像中：

![](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mysql8-adm-gd/img/ef6c457f-cd0a-4f1e-99c4-762f718450e4.png)

# 客户端节点

客户端节点是发送来自不同设备（如计算机、手机、平板电脑等）的读取数据或写入数据的查询请求的最终用户或应用程序。

# 应用节点

应用节点旨在提供应用程序逻辑和包含 MySQL 数据的节点之间的桥梁。应用程序可以通过 SQL 访问存储在 MySQL 集群中的数据，使用 SQL 的一个或多个 MySQL 服务器。在应用程序中，我们有多种技术可以连接到 MySQL 服务器。我们使用标准的 MySQL 连接器连接 MySQL 服务器，这使我们能够与各种访问技术连接。

作为另一种选择，我们有 NDB API；一个高性能接口，可用于控制实时用户体验并提供更好的吞吐量。在 MySQL 中，我们有 NDB API，它在 NoSQL 接口之外添加了一层，具有直接访问集群的能力。应用节点可以从所有数据节点获取数据，因此故障的唯一原因可能是应用服务不可用，因为应用可以使用所有数据节点来执行数据操作。

# 管理节点

管理节点在其集群中发布相关的集群信息，以及节点管理。管理节点在所有节点希望加入 MySQL 集群以及需要重新配置系统时启动时起作用。管理节点可以停止并重新启动所有服务，而不会损害或影响正在进行的操作、执行或数据和应用节点的处理。

# 数据节点

数据节点存储数据。表在数据节点之间共享，这也有助于处理负载平衡、复制和高可用性故障转移。

数据节点是 MySQL 集群解决方案的主要节点。它提供以下功能和好处：

# 磁盘和内存数据的数据存储和管理

在共享无情景况下，数据存储在至少一个副本中，而无需使用共享磁盘空间。MySQL 创建数据库的一个副本，进行同步复制过程。如果任何数据节点由于任何特定原因失败，复制的数据将处理并提供相应的输出。它对节点进行同步复制，因此它包含与主节点数据相同的数据。

根据需求，我们可以将数据存储在内存中或部分存储在磁盘上。频繁更改的数据建议存储在内存中。内存中的数据会定期与本地磁盘进行检查，并协调将数据更新到其余数据节点。

# 表的自动和用户定义的分区或分片

MySQL 集群提供低延迟、高吞吐量、可伸缩性和高可用性。它采用水平扩展和自动分片来通过不同的 NoSQL 查询提供重载读/写操作。NDB 集群是一组不同的节点，每个任务在其自己的处理器上运行。

# 数据节点之间的同步数据复制

当我们为数据节点进行数据复制时，它遵循同步复制，因此任何时候所有节点数据都将同步。如果任何节点由于任何原因失败，其他节点具有相同的数据，因此将能够为查询提供数据。因此，MySQL 提供了完美的无数据响应停机时间的解决方案。

# 数据检索和事务

MySQL 支持可以映射的每个事务，因为它在主服务器上提交并应用于从服务器上。这种方法不是指`binlog`文件或`binlog`文件中的相关位置。`GTID`复制仅基于事务工作；很容易确定主服务器和从服务器是否同步。

# 自动故障转移

如果任何数据节点由于任何原因失败，其他节点将负责并响应请求。数据库的复制在停机或任何节点发生故障的关键情况下非常有帮助。

# 故障后自动重新同步进行自我修复。

如果任何节点失败，它将自动启动并再次对其余节点执行数据同步，并在节点中复制所有最新数据。在这种情况下，它对故障进行自我修复。

# 在 MySQL 8 中使用 memcached 进行扩展

在 MySQL 8 中，使用 memcached 是实现可伸缩性的一种方式。Memcached 是一种简单且高度可伸缩的解决方案，可以在内存可用时以键值形式将数据存储在缓存中。Memcached 通常用于快速访问数据。存储在内存中的数据不需要执行 I/O 操作来获取数据。

由于所有信息都存储在内存中，因此数据的访问速度比每次从磁盘加载要快得多，并且可以在数据库服务器上获得更好的查询执行时间。该插件还具有序列化功能，可以将二进制文件、代码块或任何其他对象转换为可以存储的字符串，并提供了检索这些对象的简单方法。在指定内存分配时，不应大于服务器可用的物理内存。

如果指定的值过大，那么为 memcached 分配的一些内存将使用交换空间而不是物理内存。这可能会导致存储和检索值时出现延迟，因为数据被交换到磁盘而不是直接存储在内存中。

![](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mysql8-adm-gd/img/1e6e6d77-6a4d-4480-ab5b-2e6faaf58d92.png)

前面的图片描述了 memcached 架构，显示了数据从 memcached 流向客户端或最终用户，或者从应用程序请求数据的流程。

在 memcached 中的数据永远不会存储在数据库中。它始终在内存中可用。如果其中一个 memcached 服务器失败，数据将从数据库中获取，因此不会影响最终用户的数据检索，也不会对应用程序产生重大性能影响。在使用 memcached 服务器时唯一需要牢记的是，与任何重要信息相关的数据，例如财务交易，不应放置在 memcached 中。在这种情况下，如果 memcached 发生故障，可能无法检索数据。在 memcached 服务器中，数据完整性不健康，因为它存储在内存中，因此在发生故障时最好不要将重要数据保存在 memcached 中。在配置 memcached 服务器时，内存大小是关键因素。如果配置不当，就可能会出现糟糕的情况。

通过这种方式，我们可以使用 memcached 来扩展 MySQL 服务器，以提高数据响应时间，并提供更快的性能。这将减轻 MySQL 服务器和多个服务器的负载作为缓存组的一部分，并为多种语言提供接口。建议在有大量读取操作时使用。

# NoSQL API

MySQL 集群提供了许多方法来帮助访问数据存储。最通用的方法之一是利用 SQL；然而，在实际用例中，我们也可以依赖于本机 API，它允许从数据库内部获取数据，而不会影响性能或增加进一步的复杂性，因为需要开发应用程序来转换 SQL。

# 使用复制进行扩展

复制是 MySQL 数据库的复制。MySQL 提供了不同的复制方法。MySQL 具有复制功能，提供了扩展解决方案、数据安全、远程数据分发等许多好处。我们在第八章中详细讨论了这一点，*MySQL 8 中的复制*。以下图片解释了 MySQL 中复制的基本架构：

![](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mysql8-adm-gd/img/9be2c06c-0f31-46ed-b91a-d69bc37f763c.png)

复制是 MySQL 的最佳功能之一。它简单地将数据复制到新服务器或另一台物理机器上，该服务器将从主服务器导入数据。每当需要数据时，它将填充准确的结果。它遵循主从复制的方法。主数据库是应用程序的实际数据库，从数据库是由 MySQL 在另一台物理服务器的数据库服务器中创建的，其中包含来自主服务器的复制数据。我们可以为特定操作配置从数据库，例如当查询涉及从数据库读取数据时，我们可以在从服务器上执行此操作。在这种情况下，主数据的负载将比以前少。假设我们有 40%的写入数据查询和 60%的读取数据查询比例；在这种情况下，如果我们有一台单独的服务器，它将处理与读写操作相关的所有操作。但是，如前图所定义，我们已经将数据库复制到两个不同的服务器中，并且读操作是在从服务器上执行的，因此我们可以利用其中一个从服务器来执行复杂的读查询。这使得在 MySQL 8 上进行数据分析报告成为可能，因为执行复杂的读查询不会影响整体应用程序性能。

在标准的 MySQL 复制中，主服务器创建二进制日志文件并维护日志文件的索引以维护和跟踪日志轮换。二进制日志文件用于记录更新，并发送到从服务器。当从服务器连接到主数据库服务器时，它会考虑它在日志文件中读取的最后位置，之后从服务器将接收自那时以来发生的任何更新。从服务器随后会阻塞并等待主服务器通知其进行进一步更新。

心中的问题是为什么我们需要复制？或者，复制的目的是什么？如果复制需要另一个数据库服务器、复杂性和额外的配置，它会增加维护和监控时间。尽管如此，对于企业和数据库管理员来说，我们仍然有许多额外的好处。

# 单服务器依赖

在任何情况下，如果主数据库服务器失败，我们可以轻松地将数据库连接切换到复制的从服务器，以在关键情况下提供稳定性。这包括网络故障、服务器故障、硬件问题等失败原因。

# 性能

性能是数据库的主要部分。当我们在多个服务器上拥有分布式数据库时，我们可以将不同的应用程序连接到不同的数据库服务器以提高性能。此功能减少了查询的响应时间。

# 备份和恢复

复制有助于备份主数据库。它比将数据库存储在磁盘上更有效。用户可以使用复制的数据库将数据库存储在主数据库中，作为备份，而不是挖掘备份文件。当需要恢复主服务器的数据时，用户可以轻松地从从服务器获取，而无需处理备份文件并寻找最后的更新和其他操作。

# 负载分布

通过使用数据库的复制负载，可以减少查询执行；我们可以将读写操作分割到不同的数据库中。如果我们在主数据库中执行写操作，并在从数据库中执行读操作，这将改善应用程序的响应时间。我们可以在 MySQL 中创建负载平衡的环境，以分享对数据库服务器的所有请求的负载。负载平衡器随后进一步将请求发送到可以处理每个事务的数据库，从而获得更好的吞吐量。

# 异步数据复制

异步数据复制意味着数据从一台机器复制到另一台机器，会有一定的延迟。这种延迟基于网络带宽、资源可用性或管理员在配置中设置的时间间隔。正确的配置和时间设置可以提供准确的响应结果。这是基于网络管理员的配置。同步数据复制意味着数据同时提交到一个或多个机器。

# 地理数据分布

组复制使得可以将主服务器的数据复制到位于远程位置的从服务器，并为一个独立的客户组执行读操作，而不会影响主服务器的操作。

# GTID 复制

**全局事务标识符**（**GTID**）使用基于事务的数据复制，而不是基于二进制日志文件的复制。除非在所有从服务器上存在在主服务器上操作和提交的事务，否则 GTID 不会考虑复制处于一致状态。

在 MySQL 8 中，复制可以在异步模式或半同步模式下进行。在异步模式下，写操作立即在主服务器上执行，而在从服务器上的复制是根据配置定期进行的。

在复制的半同步模式中，如果在主节点和至少一个从节点上启用了半同步配置，则主节点上的事务在获得事务超时之前会等待，直到半同步启用的节点确认已接收到所需的数据或更新。超时后，主节点再次寻找半同步从节点并执行复制。

MySQL 8 提供了一种新的复制方法，GTID，其中为在主服务器上保存或提交的每个事务创建并连接了一个唯一标识符。这些标识符的唯一性在创建它的服务器中的所有服务器以及复制的服务器中都是如此。GTID 在所有事务之间有一对一的映射。在启动新的从服务器创建或故障转移到新的 MySQL 主服务器时，不需要使用日志文件引用文件中的位置的概念。您可以在 GTID 中使用基于行或基于语句的复制。

使用全局事务 ID 主要提供了两个主要的好处：

+   **在故障转移期间很容易将主服务器更改为连接从服务器**：GTID 在复制组中的所有服务器中是唯一的。从服务器记住了来自旧主服务器的最后一个事件的全局事务 ID。这意味着很容易确定在新的 MySQL 主服务器上重新初始化复制的位置，因为全局事务 ID 在整个复制层次结构中都是已知的。

+   **从服务器的状态提供了一种崩溃安全的方法**：从服务器在`mysql.gtid_slave_pos`系统表中保存当前位置信息。如果该表使用事务性存储引擎（例如默认的`InnoDB`），则进一步的更新将在同一事务中进行。

GTID 是在主服务器上提交的每个事务（插入和更新操作）上创建并关联的唯一键。该键不仅对主服务器是唯一的，而且在复制的所有服务器中也是唯一的。

# ZFS 复制

ZFS 文件系统具有提供服务器文件的快照、将快照传输到另一台机器并提取快照以在不同服务器上重新创建文件系统的能力。用户可以随时创建快照，并可以根据需要创建多个快照。通过不断创建、传输和恢复快照，可以在一个或多个机器之间提供类似于 DRBD 的同步。

我们已经看到了使用不同技术在 MySQL 中扩展数据库的所有可能方法。根据业务需求和灵活性，我们可以通过数据库备份来进行扩展。扩展并不是一项容易的任务，但在 MySQL 8 中是可能的，只要具备对业务需求的正确理解和 MySQL 8 提供的配置。对于数据库扩展，我们必须对数据库的整个工作流程和通信方法有适当的理解。

# MySQL 8 扩展中的挑战

我们已经看到了扩展的工作原理以及扩展的优势和目的。当我们开始在 MySQL 8 中进行扩展时，我们将面临哪些挑战，以及在我们朝着扩展的方向努力时需要记住哪些步骤？我们必须考虑如果我们正在进行扩展并且主服务器失败，达到了限制，读写操作无法处理应用程序的请求，或者在重新平台化数据库时。扩展并不是一项容易的任务；它需要确保能够处理增加的交易而不会出现任何困难。在进行扩展时，我们需要记住许多要点，例如主服务器和从服务器中的写入和读取操作限制。数据库负载平衡是帮助减少交易流量的方法之一，但它需要完美，需要正确理解负载平衡配置。以下是我们进行扩展时面临的主要挑战。

# 业务类型和灵活性

这是在进行扩展时需要记住的第一点。业务类型或业务行为是核心部分；如果业务是电子商务，我们已经知道电子商务业务具有许多功能和关于客户的非常关键的数据，例如产品细节，业务的优惠和折扣的垄断。最重要的是客户细节和付款信息，如信用卡细节，借记卡细节和客户反馈。

在这种情况下，当我们在 MySQL 8 中进行扩展时，需要记住所有参数，例如数据库备份、安全性、数据库的角色/权限和扩展的向后兼容性。在通过集群进行扩展时，所有数据节点都需要保持一致。如果应用程序使用多种技术开发，并且我们为每个堆栈进行扩展，我们可以有不同的数据节点可用；在这种情况下，在进行扩展时需要确保数据库同步是最重要的事情之一。在设计扩展之前，应明确哪些类型的数据应该驻留在 memcached 的缓存内，哪些类型的数据应该驻留在磁盘上。

应用程序的行为从共享数据节点访问数据。如果我们有一个电子商务网站，并且我们对其进行分片，并且在某个特定级别上，客户端无法使用其他分片服务器的数据，那么在那时将需要跨节点事务。这完全取决于业务行为，并取决于业务在接受有关数据库扩展的变化时有多灵活。

# 了解服务器工作负载

为了灵活性、规模和性能的提高，在 MySQL 8 中有许多选项和操作。许多人在执行此类活动时会遇到问题，因为他们没有足够的理解或知识来处理各种技术堆栈和配置选项选择，这些选项可以改善应用程序和部署活动的可扩展性、性能、安全性和灵活性。这些配置选项包括集群、复制、分片、内存缓存、存储引擎等，可以很好地设计来处理应用程序的整个工作负载。数据库工作负载和业务行为有助于决定 MySQL 的配置。

# 读写操作限制

如果主数据库服务器的读写限制达到并且事务在增加，会发生什么情况。MySQL 有容量限制；例如，如果许多客户在进行读写操作的同时访问网站，而服务器或节点未同步，那么这将给最终用户带来困惑或误解。或者，在电子商务网站上，如果一个客户购买了最后一件库存中剩下的产品，并且同时另一个客户搜索相同的产品并且它仍然可用，那么在数据库的读写操作方面，这两个操作都不同步。

最后，其他客户可能会购买我们仓库中没有的同一产品。这会影响库存计算，并且客户对购买周期的过程产生疑虑。在这种情况下，我们将失去客户对业务的信任，业务的信用也会受到影响。

另一种方法是进行数据库分片。分片可以简单地理解为将数据库分成多个服务器的分区。分片有助于减轻单个数据库或主数据库的负载。如果我们在地理上进行数据库分片，并且对于不同的国家或地区，我们有不同的数据库服务器，我们可以解决 MySQL 服务器上读取和写入操作的限制问题。但是，我们用于分片的技术也决定了数据库的性能。我们已经在《第九章》*MySQL 8 中的分区*中详细了解了这一点。

# 维护

在 MySQL 8 中进行了扩展时，我们必须知道如何管理主服务器和从服务器，以及在执行扩展时需要哪些配置。在服务器处于关键阶段时需要注意哪些步骤？在分片、集群或数据库服务器复制时需要执行哪些步骤？

扩展是可能的，但并不是一项容易的操作。如果我们想要进行扩展，我们应该知道数据库可以处理更多的事务而不会出现任何问题。我们应该知道适当的配置来克服主服务器上写入和读取操作的默认限制。完成后，我们需要执行类似的步骤来配置从数据库服务器，该服务器应该只为最终用户提供读取操作，并且应始终与主数据库同步。

如果我们有多个服务器，那么服务器的维护也将成为一项昂贵的开销。所有服务器都需要保持一致，配置应该合理，服务器的成本也会影响业务。如果数据量不断增加，那么服务器空间也需要以适当的方式进行管理。

# 主服务器故障

如果主服务器失败并且在那时数据对客户不可用，最终用户会感到沮丧，业务将在市场信用和失去客户方面受到影响。业务将不得不承受损失。

# 同步

无论我们是通过集群还是复制来执行扩展，都需要确保同步。所有从服务器应该有与主服务器相同的数据库。如果在主服务器上执行写操作并在从服务器上执行读操作，那么所有数据都需要同步。所有结果应该是相同的，如果在数据未同步的情况下某个服务器在某个时间段内宕机，将会导致数据丢失的问题。

# 数据库安全。

如果我们有不同的服务器并且进行了分片，我们如何保护数据库？如果在不同地点有不同的数据库服务器，并且在那个时候数据库的访问不是特定用户专用的，那么数据泄漏是一个很有可能的问题。我们必须完全了解数据库服务器的 IP 配置的数据访问点，以及对执行各种活动的数据库用户的适当角色和权限。哪些 IP 有访问权限，哪些 IP 需要限制从服务器传输数据？在进行数据库的跨节点事务时，应该有准确的数据；不应该允许从服务器访问受限数据的权限。

# 跨节点事务

在进行扩展后，如果有多个节点并且一个节点需要其他节点的数据作为输入的一部分，则需要跨节点事务。例如，如果我们在不同地点有不同的节点，并且在那个时候所有地点都有单一的库存，那么当一个用户请求任何一个在那个时候不在数据节点上的产品时，就必须根据用户的请求与其他数据节点通信以获取产品的信息。

# 发展团队以进行开发

当应用程序可能有积极的响应并且其持续的成功增加了业务团队时，数据库管理员的扩展也将是必要的。当我们在 MySQL 8 中进行分片、扩展或复制时，需要具有适当知识和经验的团队成员来处理持续扩展和数据库服务器的管理。这不仅仅局限于设置数据库服务器；我们还需要关注服务器的维护并且持续监视服务器活动。

# 管理变更请求

当数据库结构发生变化并且我们已经进行了扩展或复制时，需要在变更请求的一部分中注意一些事项，或者如果我们添加了新功能或增强了功能。这包括更新分片键、修改节点的数据分布、更新查询以考虑复制延迟以避免正在管理分片时的陈旧数据、数据平衡，并确保新更新的数据可用。

# 扩展和扩展

扩展描述了最大化单个 MySQL 节点处理能力的过程。扩展的过程可能涉及优化调整数据库软件和选择正确的存储引擎，正如之前在第六章中讨论的*MySQL 8 存储引擎*，并选择适当的硬件。单个节点的扩展有一定的限制，这些限制由数据大小、模式复杂性、CPU 周期、系统内存和磁盘 IO 操作的某种组合确定。尽管由于需要处理日益庞大的数据集，扩展一直备受关注，但重要的是要记住，我们扩展得越好，我们就需要越少的扩展节点，因此我们在硬件上的开销就越少。

扩展可以用于提供涵盖几种不同用例的解决方案。其中一些最常见的用例是通过复制来增加读取容量，或者使用数据库分片来增加总数据库大小和整体事务吞吐量。

在扩展 MySQL 8 时面临的关键挑战。在进行 MySQL 8 数据库扩展时，需要考虑这些挑战。一个错误可能会让业务陷入我们都不想面对的境地。扩展是改善数据库性能的更好方式。

# 实现高可用性

高可用性指的是系统具有耐用性，并且可以在移动、网络门户、网站、社交、电子商务、企业和云应用程序的任何请求或响应所需的数据上执行操作而不受任何干扰。数据可用性被认为是任何企业或组织的最关注的问题。任何停机问题可能会影响业务信用，并且在某些情况下，企业可能会遭受财务损失。

例如，如果我们有一个单个数据库服务器的电子商务应用程序，如果由于硬件故障、网络问题、病毒或操作系统问题等原因，该服务器宕机，也会影响数据。电子商务应用程序可能会在同一时间有大量的客户访问，任何服务器无法为用户请求提供响应的故障都会影响用户；他们会寻找其他购买商品的选择。

MySQL 8 具有提供应用程序后端的能力，帮助实现高可用性和准备一个完全可扩展的系统。系统保持连接持久性的能力，以防止基础设施的一部分失败，以及系统从此类故障中恢复的能力被认为是高可用性。系统的故障可能是由系统的一部分进行维护活动，如硬件或软件升级，或者由安装的软件的故障引起的。

# 高可用性的目的

实现高可用性和可扩展性的要求可能因系统而异。每个系统都需要不同的配置才能实现这些能力。MySQL 8 还支持不同的方法，例如在多个 MySQL 服务器之间复制数据，或者根据地理位置准备多个数据中心，并从最接近客户位置的数据中心为客户请求提供服务。这样的解决方案可以用来实现 MySQL 的最高运行时间。

如今，在竞争激烈的市场中，组织的关键点是使其系统保持运行。任何故障或停机都会直接影响业务和收入。因此，高可用性是一个不容忽视的因素。MySQL 非常可靠，并且使用集群和复制配置始终可用。集群服务器可以立即处理故障，并管理故障转移部分，以使系统几乎始终可用。如果一个服务器宕机，它将重定向用户的请求到另一个节点，并执行所请求的操作。

# 数据可用性

数据在任何情况下都是可用的。在任何应用程序中，数据都是核心部分，实际上是应用程序所有者的财富。如果我们有一个医疗保健系统，在任何患者的医疗检查时，由于服务器宕机或其他原因，他们的数据不可用，可能会阻碍医生的进一步处理，在这种情况下会影响患者的生命。

# 数据安全

首先想到的是保护数据，因为如今数据变得非常宝贵，如果不满足法律义务，可能会影响业务的连续性；事实上，情况可能会很糟糕，甚至可能会迅速关闭您的业务。MySQL 是最安全可靠的数据库管理系统，被许多知名企业使用，如 Facebook、Twitter 和 Wikipedia。它确实提供了一个良好的安全层，可以保护敏感信息免受入侵者的侵害。MySQL 提供访问控制管理，因此在用户身上授予和撤销所需的访问权限很容易。还可以定义角色，并为用户授予或撤销权限列表。所有用户密码都以加密格式存储，使用特定的插件算法。

# 数据同步

当我们只有一个数据库服务器时，如果由于任何原因它宕机，我们将丢失整个数据库，如果我们备份数据库直到当天，我们可以恢复数据库直到那一天，但在这种情况下，所有当前事务也将丢失。那时最后的交易数据将不可用。

# 数据备份

当一个企业有任何基于服务器的应用程序，其中单个数据库服务器执行所有任务时，应该在计划中备份数据库直到最后一个事务。在进行高可用性时，需要在架构中包括备份和恢复操作的所有场景。

# 竞争激烈的市场

在市场上有许多竞争对手提供相同性质的业务。在这种情况下，如果一个企业在数据可用性方面出现问题，客户可能会选择另一个提供商而不是继续与该企业合作。这是业务连续性的一个重要部分。

# 性能

高可用性在数据操作的性能方面也很重要。如果我们只有一个服务器，并且所有操作都在该服务器上执行，那么在某个阶段它将达到其极限，服务器容量将耗尽。因此，在这种情况下，如果我们实施了高可用性架构，它将提供一种平衡事务和数据操作性能的手段。复制和集群使并发性更好，并管理工作负载。

# 系统更新

当任何在线站点或应用程序需要更新或计划进行任何新的生产发布时，它直接影响最终用户。如果一个应用程序在那个时候只有有限的用户，我们可以通过电子邮件或应用程序内的消息管理所有最终用户的更新。但是，在一个应用程序中有大量用户的情况下，这将影响业务。它将同时停止所有用户，由于这个正在运行的事务会受到影响。

# 选择解决方案

再次，我们必须考虑选择可用性的正确解决方案。在我们计划在 MySQL 中实现高可用性时，需要牢记许多事情。实现 HA 和可伸缩性的要求可能因系统而异。每个系统都需要不同的配置才能实现这些能力。

这样的解决方案可以用来实现 MySQL 在以下方面的最高运行时间：

+   所需的可用性级别

+   部署的应用程序类型

+   自己环境中的最佳实践

在 MySQL 中，复制和集群是实现高可用性的最佳选择。所有应用程序都有自己的架构，当我们选择任何技术来实现 MySQL 8 的高可用性时，需要考虑其业务性质。

# 高可用性的优势

当我们在 MySQL 中执行高可用性时，我们拥有以下优势：

+   MySQL 非常可靠，并且使用集群和复制配置具有持续的可用性。

+   集群服务器可以立即处理故障并管理故障转移部分，以使系统几乎始终可用。如果一个服务器宕机，它将重定向用户的请求到另一个节点并执行请求的操作。

+   系统保持连接持久的能力，即使基础设施的一部分失败，系统从此类故障中恢复的能力被视为高可用性。

+   MySQL 8 还支持不同的方法，例如在多个 MySQL 服务器之间复制数据，或者基于地理位置准备多个数据中心，并从最接近客户位置的数据中心提供客户请求。

+   MySQL 以最佳速度进行事务处理。它可以缓存结果，提高读取性能。

+   复制和集群使并发性更好，并管理工作负载。组复制基本上负责在大多数组复制成员已经同时确认事务已被接收时提交事务。如果写入的总数不超过组复制成员的容量，则可以创建更好的吞吐量。

+   集群使数据能够复制到多个 MySQL 服务器并进行自动共享。它旨在提供更好的可用性和吞吐量。

+   Memcached 去除了 SQL 层，直接访问 InnoDB 数据库表。因此，诸如 SQL 解析之类的开销操作将不再执行，这确实会影响性能。

+   Memcached 与 MySQL 还为您提供了一种使内存中的数据持久化的方法，以便我们可以在不丢失数据的情况下使用各种数据类型。

+   Memcached API 可用于不同的编程语言，如 Perl、Python、Java、PHP、C 和 Ruby。借助 Memcached API，应用程序可以与 Memcached 接口交互，存储和检索信息。

# 总结

在本章中，我们从 MySQL 8 的可伸缩性和高可用性概述开始，涵盖了各种可伸缩性需求、优势、方法以及在设计可伸缩性 MySQL 8 时需要注意的关键点。我们还讨论了在进行可伸缩性时通常遇到的缺点以及如何通过适当的解决方案克服挑战。我们学习了 MySQL 8 的扩展和扩展 MySQL 8 的故障排除挑战。我们还学习了在 MySQL 8 中实现高可用性的许多不同方法。

在接下来的章节中，我们将学习如何确保 MySQL 8 的安全性。我们将了解影响安全性的一般因素，核心 MySQL 8 文件的安全性，访问控制以及保护数据库系统本身。我们还将学习安全插件的详细信息，并深入了解关系数据库的数据库安全性。


# 第十一章：MySQL 8 - 安全性

在之前的章节中，我们学习了 MySQL 8 的可伸缩性以及在扩展 MySQL 8 时如何解决挑战。除此之外，我们还学习了如何使 MySQL 8 具有高可用性。现在，安全对于任何应用程序都很重要，对吧？当我们谈论安全时，它包括帐户管理、角色、权限等。考虑到这些方面，我们将在本章中涵盖所有这些主题。本章主要关注 MySQL 8 数据库安全及其相关功能。本章涵盖以下主题：

+   MySQL 8 的安全概述

+   常见安全问题

+   MySQL 8 中的访问控制

+   MySQL 8 中的帐户管理

+   MySQL 8 中的加密

+   安全插件

# MySQL 8 的安全概述

安全这个术语不局限于特定主题；它涵盖了与 MySQL 8 相关的各种主题。在开始对其进行详细讨论之前，让我们提到与安全相关的一些重要要点：

+   考虑数据库中的安全性，需要管理用户及其与各种数据库对象相关的权限。

+   用户的密码安全。

+   在安装过程中进行安全配置，包括各种类型的文件，如日志文件、数据文件等。这些文件必须受到保护，以防止读/写操作。

+   为处理系统级故障场景，您必须拥有备份和恢复计划。这包括所有必需的文件，如数据库文件、配置文件等。

+   管理安装了 MySQL 8 的系统的网络安全，允许有限数量的主机进行连接。

现在，您的旅程将开始另一个重要且非常有趣的主题。我们开始吧。

# 常见安全问题

在深入讨论复杂问题之前，您必须首先了解一些基本要点，这将有助于防止滥用或攻击。

# 一般指南

在 MySQL 8 中，用户执行的所有连接、查询和操作都基于**访问控制列表**（**ACLs**）安全。以下是与安全相关的一些一般指南：

+   不要允许任何用户访问`user`表，除了 root 帐户。使用`GRANT`和`REVOKE`语句管理用户权限。

+   在进行互联网数据传输时，使用加密协议，如 SSH 或 SSL。MySQL 8 支持 SSL 连接。

+   在客户端使用应用程序将数据输入 MySQL 时，使用适当的防御性编程技术。

+   使用哈希函数将密码存储到 MySQL 8 数据库中；不要将明文存储为密码。对于密码恢复，考虑一些字符串作为盐，并使用`hash(hash(password)+salt)`值。

+   使用适当的密码策略来防止密码被破解。这意味着您的系统应该只接受符合您规则/约定的密码。

+   使用防火墙可以减少 50%的故障几率，并为您的系统提供更多保护。将 MySQL 定义在一个非军事区或防火墙后面，以防止来自不信任主机的攻击。

+   基于 Linux 的系统提供了`tcpdump`命令，以更安全的方式执行传输任务。该命令在网络层上提供安全性。例如，使用以下命令，您可以检查 MySQL 数据流是否加密：

```sql
        shell> tcpdump -l -i eth0 -w - src or dst port 3306 | strings
```

# 安全密码的指南

在本节中，我们描述了关于不同用户的密码安全的指南，并介绍了如何在登录过程中进行管理。MySQL 8 提供了`validate_password`插件来定义可接受密码的策略。

# 最终用户的指南

本节描述了定义密码的各种方法，作为最终用户，以最安全的方式。它解释了如何使您的密码更安全。最安全的方法是在受保护的选项文件中定义密码，或在客户端程序中提示输入密码。请参阅以下不同的定义密码的方式：

+   使用以下选项在命令行中提供密码：

```sql
 cmd>mysql -u root --password=your_pwd
 --OR
 cmd> 
```

+   在前两个命令中，您必须在命令行中指定密码，这是不可取的。MySQL 8 提供了另一种安全的连接方式。执行以下命令，它将提示您输入密码。一旦输入密码，MySQL 会为每个密码字符显示星号（`*`）：

```sql
 cmd>mysql -u root -p
 Enter password: *********
```

这比前两种方法更安全，前两种方法中，您在命令行参数中定义密码：

+   使用`MYSQL_PWD`环境变量来定义您的密码。与其他方法相比，这种方法是不安全的，因为环境变量可能被其他用户访问。

+   使用`mysql_config_editor`实用程序定义密码，这是一种提供的选项，用于将密码存储到加密的登录路径文件中，命名为`named.mylogin.cnf`。 MySQL 8 稍后将使用此文件与 MySQL 服务器连接。

+   使用选项文件存储密码。在将凭据定义到文件中时，请确保其他用户无法访问该文件。例如，在基于 UNIX 的系统中，您可以在客户端部分的选项文件中定义密码，如下所示：

```sql
 [client]
 password=your_pass
```

要使文件安全或设置其访问模式，请执行以下命令：

```sql
shell> chmod 600 .my.cnf
```

# 管理员指南

对于数据库管理员，应遵循以下准则来保护密码：

+   使用`validate_password`来对接受的密码应用策略

+   MySQL 8 使用`mysql.user`表来存储用户密码，因此配置系统以使只有管理员用户可以访问此表

+   用户应该被允许在密码过期的情况下重置帐户密码

+   如果日志文件包含密码，请对其进行保护

+   管理对插件目录和`my.cnf`文件的访问，因为它可以修改插件提供的功能

# 密码和日志记录

MySQL 8 允许您在 SQL 语句中以纯文本形式编写密码，例如`CREATE USER`，`SET PASSWORD`和`GRANT`。如果我们执行这些语句，MySQL 8 将密码以文本形式写入日志文件，并且所有可以访问日志文件的用户都可以看到。为了解决这个问题，避免使用上述 SQL 语句直接更新授权表。

# 保护 MYSQL 8 免受攻击

为了保护 MySQL 8 免受攻击，请强烈考虑以下几点：

+   为所有 MySQL 帐户设置密码。永远不要定义没有密码的帐户，因为这允许任何用户访问您的帐户。

+   与 MySQL 8 建立连接时，使用安全协议/通道，例如压缩协议，MySQL 8 内部 SSL 连接或用于加密 TCP/IP 连接的 SSH。

+   对于基于 Unix 的系统，为运行`mysqld`的 Unix 帐户设置数据目录的读/写权限。不要使用 root 用户启动 MySQL 8 服务器。

+   使用`secure_file_priv`变量指定读写权限的目录。使用此变量，您可以限制非管理员用户访问重要目录。使用此变量设置`plugin_dir`的权限非常重要。同样，不要向所有用户提供`FILE`权限，因为这允许用户在系统中的任何位置写文件。

+   使用`max_user_connections`变量限制每个帐户的连接数。

+   在创建授权表条目时，正确使用通配符。最好使用 IP 而不是 DNS。

+   在存储过程和视图创建期间遵循安全准则。

# MySQL 8 提供的安全选项和变量

MySQL 8 提供了以下选项和变量以确保安全：

| **名称** | **命令行** | **选项文件** | **系统变量** | **状态变量** | **变量范围** | **动态** |
| --- | --- | --- | --- | --- | --- | --- |
| `allow-suspicious-udfs` | 是 | 是 |   |   |   |   |
| `automatic_sp_privileges` |   |   | 是 |   | 全局 | 是 |
| - `chroot` | 是 | 是 |   |   |   |   |
| - `des-key-file` | 是 | 是 |   |   |   |   |
| - `local_infile` |   |   | 是 |   | 全局 | 是 |
| - `old_passwords` |   |   | 是 |   | 两者 | 是 |
| - `safe-user-create` | 是 | 是 |   |   |   |   |
| - `secure-auth` | 是 | 是 |   |   | 全局 | 是 |
| - `- 变量：secure_auth` |   |   | 是 |   | 全局 | 是 |
| - `secure-file-priv` | 是 | 是 |   |   | 全局 | 否 |
| - `- 变量：secure_file_priv` |   |   | 是 |   | 全局 | 否 |
| - `skip-grant-tables` | 是 | 是 |   |   |   |   |
| - `skip-name-resolve` | 是 | 是 |   |   | 全局 | 否 |
| - `- 变量：skip_name_resolve` |   |   | 是 |   | 全局 | 否 |
| - `skip-networking` | 是 | 是 |   |   | 全局 | 否 |
| - `- 变量：skip_networking` |   |   | 是 |   | 全局 | 否 |
| - `skip-show-database` | 是 | 是 |   |   | 全局 | 否 |
| - `- 变量：skip_show_database` |   |   | 是 |   | 全局 | 否 |

参考：[`dev.mysql.com/doc/refman/8.0/en/security-options.html`](https://dev.mysql.com/doc/refman/8.0/en/security-options.html)

# 客户端编程的安全指南

不要相信应用程序用户输入的任何数据，因为用户有可能输入了针对 MySQL 数据库的`drop`或`delete`语句。因此，存在安全漏洞和数据丢失的风险。作为 MySQL 数据库的管理员，应遵循以下检查表：

+   在将数据传递给 MySQL 8 之前，必须检查数据的大小。

+   为使 MySQL 8 更加严格，启用严格的 MySQL 模式。

+   对于数字字段，应输入字符、特殊字符和空格，而不是数字本身。在将字段值发送到 MySQL 8 服务器之前，通过应用程序将其更改为原始形式。

+   使用两个不同的用户进行应用程序连接到数据库和数据库管理。

+   通过在动态 URL 和 Web 表单的情况下将数据类型从数字更改为字符类型并添加引号来修改数据类型。还在动态 URL 中添加%22（"）、%23（#）和%27（'）。

先前定义的功能内置于所有编程接口中。例如，Java JDBC 提供带占位符的预编译语句，Ruby DBI 提供`quote()`方法。

# MySQL 8 中的访问控制

特权主要用于验证用户并验证用户凭据，检查用户是否被允许进行请求的操作。当我们连接到 MySQL 8 服务器时，它将首先通过提供的主机和用户名检查用户的身份。连接后，当请求到来时，系统将根据用户的身份授予特权。基于这一理解，我们可以说在使用客户端程序连接到 MySQL 8 服务器时，访问控制包含两个阶段：

+   **阶段 1**：MySQL 服务器将根据提供的身份接受或拒绝连接

+   **阶段 2**：从 MySQL 服务器获取连接后，当用户发送执行任何操作的请求时，服务器将检查用户是否具有足够的权限

MySQL 8 特权系统存在一些限制：

+   不允许用户在特定对象（如表或例程）上设置密码。MySQL 8 允许在账户级别全局设置密码。

+   作为管理员用户，我们不能以允许创建/删除表但不允许创建/删除该表的数据库的方式指定权限。

不允许显式限制用户访问，这意味着无法显式匹配用户并拒绝其连接。MySQL 8 在内存中管理授予表的内容，因此在`INSERT`、`UPDATE`和`DELETE`语句的情况下，对授予表的执行需要服务器重新启动才能生效。为了避免服务器重新启动，MySQL 提供了一个刷新权限的命令。我们可以以三种不同的方式执行此命令：

1.  通过发出`FLUSH PRIVILEGES`。

1.  使用`mysqladmin reload`。

1.  使用`mysqladmin flush-privileges`。

当我们重新加载授予表时，它将按照以下提到的要点工作：

+   **表和列特权**：这些特权的更改将在下一个客户端请求中生效

+   **数据库特权**：这些特权的更改将在客户端执行`USE dbname`语句的下一次生效

+   **全局特权和密码**：这些特权的更改对连接的客户端不受影响；它将适用于随后的连接

# MySQL 8 提供的特权

特权定义了用户帐户可以执行哪些操作。根据操作的级别和应用的上下文，它将起作用。它主要分为以下几类：

+   **数据库特权**：应用于数据库及其内的所有对象。它可以授予单个数据库，也可以全局定义以应用于所有数据库。

+   **管理特权**：它在全局级别定义，因此不限于单个数据库。它使用户能够管理 MySQL 8 服务器的操作。

+   **数据库对象的特权**：用于定义对数据库对象（如表、视图、索引和存储例程）的特权。它可以应用于数据库的特定对象，可以应用于数据库中给定类型的所有对象，也可以全局应用于所有数据库中给定类型的所有对象。

MySQL 8 将帐户特权相关信息存储到授予表中，并在服务器启动时将这些表的内容存储到内存中，以提高性能。特权进一步分为静态和动态特权：

+   **静态特权**：这些特权内置于服务器中，无法注销。这些特权始终可供用户授予。

+   **动态特权**：这些特权可以在运行时注册或注销。如果特权未注册，则不可供用户帐户授予。

# 授予表

授予表包含与用户帐户和授予的特权相关的信息。当我们在数据库中执行任何帐户管理语句时，如`CREATE USER`，`GRANT`和`REVOKE`，MySQL 8 会自动将数据插入这些表中。MySQL 允许管理员用户在授予表上进行插入、更新或删除操作，但这并不是一个理想的方法。MySQL 8 数据库的以下表包含授予信息：

+   `user`：它包含与用户帐户、全局特权和其他非特权列相关的详细信息

+   `password_history`：它包含密码更改的历史记录

+   `columns_priv`：它包含列级特权

+   `procs_priv`：它包含与存储过程和函数相关的特权

+   `proxies_priv`：它包含代理用户的特权

+   `tables_priv`：它包含表级特权

+   `global_grants`：它包含与动态全局特权分配相关的详细信息

+   `role_edges`：它包含角色子图的边缘

+   `db`：它包含数据库级别的特权

+   `default_roles`：它包含与默认用户角色相关的详细信息

授予表包含范围和特权列：

+   **范围列**：此列定义表中行的范围，即行适用的上下文。

+   **特权列**：此列指示用户被允许执行哪些操作。MySQL 服务器从各种授予表中合并信息，以构建用户特权的完整详细信息。

从 MySQL 8.0 开始，授予表使用`InnoDB`存储引擎管理事务状态，但在此之前，MySQL 使用`MyISAM`引擎管理非事务状态。这种改变使用户能够以事务模式管理所有帐户管理语句，因此在多个语句的情况下，要么全部成功执行，要么全部不执行。

# 访问控制阶段的验证

MySQL 8 在两个不同的阶段执行访问控制检查。

# 第 1 阶段 - 连接验证

这是连接验证阶段，因此在验证后，MySQL 8 将接受或拒绝您的连接请求。将根据以下条件执行验证：

1.  基于用户的身份，以及其密码。

1.  用户账户是否被锁定。

如果这两种情况中的任何一种失败，服务器将拒绝访问。在这里，身份包含请求来源的用户名和主机名。MySQL 对用户表的`account_locked`列进行锁定检查，并对用户表范围的三列`Host`、`User`和`authentication_string`进行凭据检查。

# 第 2 阶段 - 请求验证

一旦与 MySQL 服务器建立连接，第 2 阶段就会出现，MySQL 服务器会检查您要执行的操作以及您是否有权限执行。为了进行此验证，MySQL 使用授权表的特权列；它可能来自`user`、`db`、`tables_priv`、`columns_priv`或`procs_priv`表。

# MySQL 8 中的账户管理

顾名思义，本主题描述了如何在 MySQL 8 中管理用户账户。我们将描述如何添加新账户，如何删除账户，如何为账户定义用户名和密码，以及更多。

# 添加和删除用户账户

MySQL 8 提供了创建账户的两种不同方式：

+   **使用账户管理语句**：这些语句用于创建用户并设置其特权；例如，使用`CREATE USER`和`GRANT`语句，通知服务器对授权表进行修改

+   **使用授权表的操作**：使用`INSERT`、`UPDATE`和`DELETE`语句，我们可以操作授权表

在这两种方法中，账户管理语句更可取，因为它们更简洁，更不容易出错。现在，让我们看一个使用命令的例子：

```sql
#1 mysql> CREATE USER 'user1'@'localhost' IDENTIFIED BY 'user1_password';
#2 mysql> GRANT ALL PRIVILEGES ON *.* TO 'user1'@'localhost' WITH GRANT OPTION;

#3 mysql> CREATE USER 'user2'@'%' IDENTIFIED BY 'user2_password';
#4 mysql> GRANT ALL PRIVILEGES ON *.* TO 'user2'@'%' WITH GRANT OPTION;

#5 mysql> CREATE USER 'adminuser'@'localhost' IDENTIFIED BY 'password';
#6 mysql> GRANT RELOAD,PROCESS ON *.* TO 'adminuser'@'localhost';

#7 mysql> CREATE USER 'tempuser'@'localhost';

#8 mysql> CREATE USER 'user4'@'host4.mycompany.com' IDENTIFIED BY 'password';
#9 mysql> GRANT SELECT,INSERT,UPDATE,DELETE,CREATE,DROP ON db1.* TO 'user4'@'host4\. mycompany.com';
```

前面的命令执行以下操作：

+   `#1`命令创建`'user1'`，命令`#2`为`'user1'`分配了完整的特权。但是`'user1'@'localhost'`表示`'user1'`只允许与`localhost`连接。

+   `#3`命令创建`'user2'`，命令`#4`为`'user2'`分配了完整的特权，与`'user1'`相同。但在#4 中，提到了`'user2'@'%'`，这表示`'user2'`可以与任何主机连接。

+   `#5`创建`'adminuser'`并允许它仅与`localhost`连接。在`#6`中，我们可以看到仅为`'adminuser'`提供了`RELOAD`和`PROCESS`特权。它允许`'adminuser'`执行`mysqladmin reload`、`mysqladmin refresh`、`mysqladmin flush-xxx`命令和`mysqladmin processlist`命令，但它无法访问任何数据库。

+   `#7`创建了没有密码的`'tempuser'`账户，并允许用户仅与`localhost`连接。但是没有为`'tempuser'`指定授权，因此此用户无法访问数据库，也无法执行任何管理命令。

+   `#8`创建`'user4'`并允许用户仅使用`'host4'`访问数据库。`#10`表示`'user4'`在`'db1'`上对所有提及的操作具有授权。

要删除用户账户，请执行`DROP USER`命令如下：

```sql
mysql> DROP USER 'user1'@'localhost';
```

此命令将从系统中删除`'user1'`账户。

# 使用角色的安全性

与用户账户角色具有特权一样，我们也可以说角色是特权的集合。作为管理员用户，我们可以向角色授予和撤销特权。MySQL 8 提供了以下与角色配置相关的命令、函数和变量。

# 设置角色

`SET ROLE`在当前会话中更改活动角色。参考以下与`SET ROLE`相关的命令：

```sql
mysql> SET ROLE NONE; SELECT CURRENT_ROLE();
+----------------+
| CURRENT_ROLE() |
+----------------+
| NONE |
+----------------+
mysql> SET ROLE 'developer_read'; SELECT CURRENT_ROLE();
+----------------+
| CURRENT_ROLE() |
+----------------+
| `developer_read`@`%` |
+----------------+
```

第一个命令将在当前会话中取消用户的所有角色。您可以使用`CURRENT_ROLE();`函数查看效果。在第二个命令中，我们将`'developer_read'`角色设置为默认角色，然后再次使用预定义函数检查当前角色。

# 创建角色

`CREATE ROLE`用于创建角色；参考以下命令，它将创建一个名为`'developer_role'`的角色：

```sql
CREATE ROLE 'developer_role';
```

# 删除角色

`DROP ROLE`用于删除角色。参考以下命令，它将删除`'developer_role'`角色：

```sql
DROP ROLE 'developer_role';
```

# 授予权限

`GRANT`分配权限给角色，并将角色分配给帐户。例如，以下命令将所有权限分配给开发人员角色：

```sql
GRANT ALL ON my_db.* TO 'developer_role';
```

同样，要将角色分配给用户帐户，请执行以下命令：

```sql
GRANT 'developer_role' TO 'developer1'@'localhost';
```

此命令将`'developer_role'`角色分配给`developer1`帐户。MySQL 8 还提供了从用户到用户和从角色到角色的`GRANT`分配功能。考虑以下示例：

```sql
CREATE USER 'user1';
CREATE ROLE 'role1';
GRANT SELECT ON mydb.* TO 'user1';
GRANT SELECT ON mydb.* TO 'role1';
CREATE USER 'user2';
CREATE ROLE 'role2';
GRANT 'user1', 'role1'TO 'user2';
GRANT 'user1', 'role1'TO 'role2';
```

在此示例中，通过使用`GRANT`命令以简单的方式在`user1`和`role1`上应用了`GRANT`。现在，对于`user2`和`role2`，我们已经分别从`user1`和`role1`应用了`GRANT`。

# 撤销

`REVOKE`用于从角色中删除权限，并从用户帐户中删除角色分配。参考以下命令：

```sql
REVOKE developer_role FROM user1;
REVOKE INSERT, UPDATE ON app_db.* FROM 'role1';
```

第一个命令用于删除`user1`的`'developer_role'`，第二个命令用于从`'app_db'`上的`'role1'`中删除插入和更新权限。

# 设置默认角色

`SET DEFAULT ROLE`指示默认情况下活动的角色，每当用户登录时，默认角色对用户可用。要设置默认根角色，请执行以下命令：

```sql
mysql>SET DEFAULT ROLE app_developer TO root@localhost;

mysql> SELECT CURRENT_ROLE();
+---------------------+
| CURRENT_ROLE() |
+---------------------+
| `app_developer`@`%` |
+---------------------+
1 row in set (0.04 sec)
```

设置默认角色后，重新启动服务器并执行`current_role()`函数，以检查是否分配了角色。

# 显示授予权限

`SHOW GRANTS`列出与帐户和角色相关的权限和角色分配。对于一个角色，执行以下命令：

```sql
mysql> show grants for app_developer;
+-------------------------------------------+
| Grants for app_developer@% |
+-------------------------------------------+
| GRANT USAGE ON *.* TO `app_developer`@`%` |
+-------------------------------------------+
1 row in set (0.05 sec)
```

此命令显示了`'app_developer'`角色上可用的授予权限。同样，要检查用户的授予权限，请执行以下命令：

```sql
mysql> show grants for root@localhost;
```

前面的命令列出了用户 root 拥有的所有访问权限：

+   `CURRENT_ROLE()`：此函数用于列出当前会话中的当前角色。如默认角色命令中所述，它显示用户当前分配的角色。

+   `activate_all_roles_on_login`：这是一个系统变量，用于在用户登录时自动激活所有授予的角色。默认情况下，角色的自动激活是禁用的。

+   `mandatory_roles`：这是一个系统变量，用于定义强制角色。请记住，定义为强制角色的角色不能使用`drop`命令删除。在服务器文件`my.cnf`中定义您的强制角色如下：

```sql
 [mysqld]
 mandatory_roles='app_developer'
```

要在运行时持久化和设置这些角色，请使用以下语句：

```sql
SET PERSIST mandatory_roles = 'app_developer';
```

此语句应用于运行中的 MySQL 8 实例的更改，并保存以供后续重新启动。如果要应用运行实例的更改而不是其他重新启动的更改，则使用关键字`GLOBAL`而不是`PERSIST`。

# 密码管理

MySQL 8 提供了以下与密码管理相关的功能：

+   **密码过期**：用于定义密码过期的时间段，以便用户可以定期更改密码。MySQL 8 允许为帐户手动设置密码过期，以及设置过期策略。对于过期策略，可以使用`mysql_native_password`、`sha256_password`或`caching_sha2_password`插件。要手动设置密码，请执行以下命令：

```sql
 ALTER USER 'testuser'@'localhost' PASSWORD EXPIRE;
```

这将标记指定用户的密码已过期。对于密码策略，您必须以天数为单位定义持续时间。MySQL 使用系统变量`default_password_lifetime`，其中包含一个正整数来定义天数。我们可以在`my.cnf`文件中定义它，也可以使用`PERSIST`选项在运行时定义它：

+   **密码重用限制**：用于防止再次使用旧密码。MySQL 8 基于两个参数定义此限制-更改次数和经过的时间；它们可以单独或结合使用。MySQL 8 分别定义了`password_history`和`password_reuse_interval`系统变量来应用限制。我们可以在`my.cnf`文件中定义这些变量，也可以使其持久化。

+   `password_history`：此变量表示新密码不能从旧密码设置/复制。在这里，根据指定的次数考虑最近的旧密码。

+   `password_reuse_interval`: 此变量表示密码不能从旧密码设置/复制。在这里，间隔定义了特定的时间段，MySQL 8 将检查用户在该时间段内所有密码与新密码是否匹配。例如，如果间隔设置为 20 天，则新密码在过去 20 天内的更改数据中不应存在。

+   **密码强度评估**：用于定义强密码。它使用`validate_password`插件实现。

# MySQL 8 中的加密

当需要在网络上传输数据时，必须使用加密进行连接。如果使用未加密数据，则可以轻松观察网络访问权限的人员查看客户端和服务器之间传输的所有流量，并查看传输的数据。为了保护您在网络上传输的数据，请使用加密。确保所使用的加密算法包含安全元素，以保护连接免受已知攻击，如更改消息顺序或在数据上重复两次。根据应用程序要求，可以选择加密或未加密类型的连接。MySQL 8 使用**传输层安全性**（**TLS**）协议对每个连接执行加密。

# 配置 MySQL 8 以使用加密连接

本节描述了如何配置服务器和客户端以进行加密连接。

# 服务器端配置加密连接

在服务器端，MySQL 8 使用`-ssl`选项来指定与加密相关的属性。以下选项用于在服务器端配置加密：

+   `--ssl-ca`：此选项指定**证书颁发机构**（**CA**）证书文件的路径名

+   `--ssl-cert`：此选项指定服务器公钥证书文件的路径名

+   `--ssl-key`：此选项指定服务器私钥文件的路径名

您可以通过在`my.cnf`文件中指定上述选项来使用这些选项：

```sql
[mysqld]
ssl-ca=ca.pem
ssl-cert=server-cert.pem
ssl-key=server-key.pem
```

`--ssl`选项默认启用，因此在服务器启动时，MySQL 8 将尝试在数据目录下查找证书和密钥文件，即使您没有在`my.cnf`文件中定义它。如果找到这些文件，MySQL 8 将提供加密连接，否则将继续不加密连接。

# 客户端端配置加密连接

在客户端，MySQL 使用与服务器端相同的`-ssl`选项来指定证书和密钥文件，但除此之外，还有`-ssl-mode`选项。默认情况下，如果服务器允许，客户端可以与服务器建立加密连接。为了进一步控制，客户端程序使用以下`-ssl-mode`选项：

+   `--ssl-mode=REQUIRED`：此选项表示必须建立加密连接，如果未建立则失败

+   `--ssl-mode=PREFFERED`：此选项表示客户端程序可以建立加密连接，如果服务器允许，否则建立未加密连接而不会失败

+   `--ssl-mode=DISABLED`：此选项表示客户端程序无法使用加密连接，只允许未加密连接

+   `--ssl-mode=VERIFY_CA`：此选项与`REQUIRED`相同，但除此之外，它还会验证 CA 证书与配置的 CA 证书匹配，并在找不到匹配项时返回失败

+   `--ssl-mode=VERIFY_IDENTITY`：与`VERIFY_CA`选项相同，但除此之外，它还将执行主机名身份验证

# 加密连接的命令选项

MySQL 8 提供了用于加密连接的几个选项。您可以在命令行上使用这些选项，也可以在选项文件中定义它们：

| **格式** | **描述** |
| --- | --- |
| `--skip-ssl` | 不使用加密连接 |
| `--ssl` | 启用加密连接 |
| `--ssl-ca` | 包含受信任的 SSL 证书颁发机构列表的文件 |
| `--ssl-capath` | 包含受信任的 SSL 证书颁发机构证书文件的目录 |
| `--ssl-cert` | 包含 X509 证书的文件 |
| `--ssl-cipher` | 连接加密的允许密码列表 |
| `--ssl-crl` | 包含证书吊销列表的文件 |
| `--ssl-crlpath` | 包含证书吊销列表文件的目录 |
| `--ssl-key` | 包含 X509 密钥的文件 |
| `--ssl-mode` | 与服务器连接的安全状态 |
| `--tls-version` | 允许加密连接的协议 |

参考：[`dev.mysql.com/doc/refman/8.0/en/encrypted-connection-options.html`](https://dev.mysql.com/doc/refman/8.0/en/encrypted-connection-options.html)

# 从 Windows 远程连接到 MySQL 8 并使用 SSH

要从 Microsoft Windows 系统远程连接到 MYSQL 8 并使用 SSH，执行以下步骤：

1.  在本地系统上安装 SSH 客户端。

1.  启动 SSH 客户端后，通过要连接到服务器的主机名和用户 ID 进行设置。

1.  配置端口转发如下并保存信息：

+   **对于远程转发配置**：`local_port:3306`，`remote_host:mysqlservername_or_ip`，`remote_port:3306`

+   **对于本地转发配置**：`local_port:3306`，`remote_host:localhost`，`remote_port:3306`

1.  使用创建的 SSH 会话登录服务器。

1.  在本地的 Microsoft Windows 机器上，启动任何 ODBC 应用程序，如 Microsoft Access。

1.  在本地系统中，创建新文件并尝试使用 ODBC 驱动程序链接到 MySQL 服务器。确保在连接中定义了`localhost`而不是`mysqlservername`。

# 安全插件

MySQL 8 提供了几个插件来实现安全性。这些插件提供了与身份验证协议、密码验证、安全存储等相关的各种功能。让我们详细讨论各种类型的插件。

# 认证插件

以下是认证插件的列表及其详细信息：

+   **本机可插拔身份验证**：为了实现本机身份验证，MySQL 8 使用`mysql_native_password`插件。此插件在服务器和客户端两侧都使用一个通用名称，并由 MySQL 8 为服务器和客户端程序提供内置支持。

+   SHA-256 可插拔身份验证

为了实现 SHA-256 哈希，MySQL 8 提供了两种不同的插件：

1.  `sha256_password`：此插件用于实现基本的 SHA-256 身份验证。

1.  `caching_sha2_password`：此插件实现了 SHA-256 身份验证，并具有缓存功能以提高性能，与基本插件相比具有一些附加功能。

此插件与 MySQL 8 服务器和客户端程序内置提供，名称相同为`sha256_password`。在客户端中，它位于`libmysqlclient`库下。要为帐户使用此插件，请执行以下命令：

```sql
CREATE USER 'testsha256user'@'localhost'
IDENTIFIED WITH sha256_password BY 'userpassword';
```

# SHA-2 可插拔身份验证

SHA-2 可插拔身份验证与 SHA-256 可插拔插件相同，只是其插件名称为`caching_sha2_password`**。**与`sha256_password`相比，此插件具有以下优点：

1.  如果使用 Unix 套接字文件和共享内存协议，则为客户端连接提供支持。

1.  SHA-2 插件中提供了内存缓存，为以前连接过的用户提供更快的重新认证。

1.  该插件提供了基于 RSA 的密码交换，可以在 MySQL 8 提供的 SSL 库无关的情况下工作。

# 客户端明文可插拔认证

该插件用于将密码发送到服务器而不进行哈希或加密。在客户端库中以`mysql_clear_password`的名称提供。MySQL 8 在客户端库中内置了它。

# 无登录可插拔认证

这是一个服务器端插件，用于阻止使用它的任何帐户的所有客户端连接。插件名称是`'mysql_no_login'`，它不是 MySQL 的内置插件，因此我们必须使用`mysql_no_login.so`库。要使其可用，首先将库文件放在插件目录下，然后执行以下步骤之一：

1.  通过在`my.cnf`文件中添加`--plugin-load-add`参数在服务器启动时加载插件：

```sql
 [mysqld]
 plugin-load-add=mysql_no_login.so
```

1.  要在运行时注册插件，请执行以下命令：

```sql
 INSTALL PLUGIN mysql_no_login SONAME 'mysql_no_login.so';
```

要卸载此插件，请执行以下命令：

1.  如果使用`--plugin-load-adoption`在服务器启动时安装了插件，则通过删除该选项重启服务器来卸载插件。

1.  如果使用`INSTALL PLUGIN`命令安装了插件，则使用卸载命令将其移除：

```sql
UNINSTALL PLUGIN mysql_no_login;
```

# 套接字对等凭证可插拔认证

名为`auth_socket`的服务器端插件用于对从本地主机使用 Unix 套接字文件连接的客户端进行身份验证。它仅用于支持`SO_PEERCRED`选项的系统。`SO_PEERCRED`用于获取有关运行客户端程序的用户的信息。这不是一个内置插件；我们必须使用`auth_socket.so`库来使用这个插件。要使其可用，首先将库文件放在插件目录下，然后执行以下步骤之一：

1.  通过在`my.cnf`文件中添加`--plugin-load-add`参数在服务器启动时加载插件：

```sql
 [mysqld]
 plugin-load-add=auth_socket.so
```

1.  通过执行以下命令在运行时注册插件：

```sql
 INSTALL PLUGIN auth_socket SONAME 'auth_socket.so';
```

要卸载此插件，请执行以下命令：

1.  如果使用`--plugin-load-addoption`在服务器启动时安装了插件，则通过删除该选项重启服务器来卸载插件。

1.  如果使用`INSTALL PLUGIN`命令安装了插件，则使用`UNINSTALL`命令将其移除：

```sql
 UNINSTALL PLUGIN auth_socket;
```

# 测试可插拔认证

MySQL 8 提供了一个测试插件，用于检查帐户凭据并在服务器日志中记录成功或失败。这不是一个内置插件，需要在使用之前安装。它适用于服务器端和客户端，分别命名为`test_plugin_server`和`auth_test_plugin`。MySQL 8 使用`auth_test_plugin.so`库来提供此插件。要安装和卸载此插件，请执行与前面插件中提到的相同的步骤。

# 连接控制插件

MySQL 8 使用这些插件在特定数量的连接尝试失败后向客户端的服务器响应中引入逐渐增加的延迟。MySQL 为连接控制提供了两个插件。

# CONNECTION_CONTROL

这个插件将检查所有传入连接的请求，并根据需要在服务器响应中添加延迟。该插件使用一些系统变量进行配置，并使用状态变量进行监视。它还使用其他一些插件、事件类和进程，比如审计插件、`MYSQL_AUDIT_CONNECTION_CLASSMASK`事件类、`MYSQL_AUDIT_CONNECTION_CONNECT`和`MYSQL_AUDIT_CONNECTION_CHANGE_USER`进程，以检查服务器是否应该在处理任何客户端连接之前添加延迟：

```sql
CONNECTION_CONTROL_FAILED_LOGIN_ATTEMPTS
```

该插件实现了对`INFORMATION_SCHEMA`表的使用，以提供有关失败连接监视的详细信息。

# 插件安装

我们必须使用`connection_control.so`库来使用这个插件。要使其可用，首先将库文件放在插件目录下，然后执行以下步骤之一：

1.  在`my.cnf`文件中添加`--plugin-load-add`参数，以在服务器启动时加载插件：

```sql
 [mysqld]
 plugin-load-add= connection_control.so
```

1.  在`my.cnf`文件中添加`--plugin-load-add`参数，以在服务器启动时加载插件：

```sql
 INSTALL PLUGIN CONNECTION_CONTROL SONAME 
          'connection_control.so';
 INSTALL PLUGIN CONNECTION_CONTROL_FAILED_LOGIN_ATTEMPTS SONAME 
          'connection_control.so';
```

# 与连接控制相关的变量

以下变量由`CONNECTION-CONTROL`插件提供：

+   `Connection_control_delay_generated`: 这是一个状态变量，主要用于管理计数器。它指示服务器在连接失败尝试时添加延迟的次数。它还取决于`connection_control_failed_connections_threshold`系统变量，因为除非尝试次数达到阈值变量定义的限制，否则此状态变量不会增加计数。

+   `connection_control_failed_connections_threshold`: 这是一个系统变量，指示在服务器对每次尝试添加延迟之前，客户端允许连续失败的尝试次数。

+   `connection_control_max_connection_delay`: 这是一个系统变量，定义了服务器在连接失败尝试时的最大延迟时间（以毫秒为单位）。一旦阈值变量包含一个大于零的值，MySQL 8 将考虑这个变量。

+   `connection_control_min_connection_delay`: 该系统变量定义了服务器对连接失败尝试的最小延迟时间（以毫秒为单位）。一旦阈值变量包含一个大于零的值，MySQL 8 将考虑这个变量。

# 密码验证插件

对于密码验证，MySQL 提供了一个名为`validate_password`的插件。它主要用于测试密码并提高安全性。以下是该插件的两个主要功能：

+   `VALIDATE_PASSWORD_STRENGTH()`: 一个 SQL 函数，用于查找密码的强度。它以密码作为参数，并返回一个介于 0 和 100 之间的整数值。这里，0 表示弱密码，100 表示强密码。

+   **按照 SQL 语句中的策略检查密码**：对于所有使用明文密码的 SQL 语句，插件将检查提供的密码是否符合密码策略，并根据此返回响应。对于弱密码，插件将返回一个`ER_NOT_VALID_PASSWORD`错误。如果密码在参数中以明文形式定义，`ALTER USER`、`CREATE USER`、`GRANT`、`SET PASSWORD`语句和`PASSWORD()`函数始终由该插件检查。

# 安装密码验证插件

我们必须使用`validate_password.so`库与该插件。要使其可用，首先将库文件放在插件目录下，然后执行以下步骤之一：

1.  在服务器启动时加载插件，通过在`my.cnf`文件中添加`--plugin-load-add`参数：

```sql
 [mysqld]
 plugin-load-add=validate_password.so
```

1.  在运行时注册插件，执行以下命令：

```sql
 INSTALL PLUGIN validate_password SONAME 'validate_password.so';
```

# 与密码验证插件相关的变量和选项

MySQL 8 提供了以下与密码验证插件相关的系统变量、状态变量和选项。

+   `validate_password_check_user_name`: 这是一个系统变量，在 MySQL 8 中默认启用。顾名思义，它用于将密码与当前有效用户的用户名进行比较。如果密码与用户名或其反转匹配，MySQL 8 将拒绝密码，而不管`VALIDATE_PASSWORD_STRENGTH()`函数的值如何。

+   `validate_password_dictionary_file`: 该系统变量包含了`validate_password`插件使用的目录的路径名。您可以在运行时设置它，无需重新启动服务器，并且一旦安装了插件，它就可用。如果您定义了用于密码检查的目录，将密码策略值设置为 2（强）。密码策略的可能值在`validate_password_policy`系统变量下描述。

+   `validate_password_length`: 一旦安装了插件，该系统变量可用于定义密码与`validate_password`插件进行检查所需的最小字符数。

+   `validate_password_mixed_case_count`：一旦安装了插件，此系统变量可用于定义密码检查中小写和大写字符的最小数量。

+   `validate_password_number_count`：一旦安装了插件，此系统变量可用于定义密码检查中数字的最小数量。

+   `validate_password_special_char_count`：一旦安装了插件，此系统变量可用于定义密码检查中非字母数字字符的最小数量。

+   `validate_password_policy`：一旦安装了插件，此系统变量可用，并指示插件在其他系统变量情况下应如何行为。此变量的以下值描述了`validate_password`插件的行为：

| **策略** | **执行的测试** |
| --- | --- |
| 0 或 LOW | 长度 |
| 1 或 MEDIUM | 长度；数字，小写/大写和特殊字符 |
| 2 或 STRONG | 长度；数字，小写/大写和特殊字符；字典文件 |

参考：[`dev.mysql.com/doc/refman/8.0/en/validate-password-options-variables.html`](https://dev.mysql.com/doc/refman/8.0/en/validate-password-options-variables.html)

+   `validate_password_dictionary_file_last_parsed`：这是一个状态变量，用于指示上次解析目录文件的时间。

+   `validate_password_dictionary_file_words_count`：这是一个状态变量，用于指示从目录文件中读取的单词数量。

+   `--validate-password[=value]`：此选项用于定义服务器在启动时如何加载`validate_password`插件。此选项仅在插件使用`INSTALL PLUGIN`注册或使用`--plugin-load-add`功能加载时可用。

# MySQL 8 keyring

MySQL 8 提供了一个 keyring 服务，允许 MySQL 服务器的内部组件和插件存储它们的敏感信息以供以后使用。对于此功能，MySQL 8 使用`keyring_file`插件，该插件将数据存储在服务器主机上的文件中。此插件在所有 MySQL 的发行版中都可用，如社区版和企业版。

# 安装 keyring 插件

我们必须使用`keyring_file.so`库与此插件。为了使其可用，首先将库文件放在插件目录下，然后执行以下步骤之一：

+   通过在`my.cnf`文件中添加`--plugin-load-add`参数，在服务器启动时加载插件：

```sql
 mysqld]
 plugin-load-add=keyring_file.so
```

+   通过执行以下命令在运行时注册插件：

```sql
 INSTALL PLUGIN keyring_file SONAME 'keyring_file.so';
```

# 与 keyring 插件相关的系统变量

MySQL 8 提供了以下与 keyring 插件相关的系统变量：

+   `keyring_file_data`：一旦安装了插件，此系统变量可用于定义`keyring_file`插件用于存储安全数据的数据文件的路径。Keyring 操作是事务性的，因此此插件在写操作期间使用备份文件来处理回滚情况。在这种情况下，备份文件的命名约定与`keyring_file_data`系统变量中定义的相同，并带有`.backup`后缀。

# 总结

在本章中，我们首先概述了安全性，然后介绍了 MySQL 8 安全相关的功能。首先我们讨论了一些常见的安全问题，然后展示了如何分配权限以及如何在 MySQL 8 中管理访问控制。本章还涵盖了加密，以保护您的敏感数据。最后，我们介绍了一些重要的安全插件，这些插件对于在 MySQL 8 中实现安全性非常有用。

现在是时候转到我们的下一章了，在那里我们将为优化配置 MySQL 8。对于优化，我们将涵盖数据库的不同领域，如优化查询，优化表，优化缓冲和缓存等等。除了服务器配置，它还涵盖了如何为优化配置客户端。
