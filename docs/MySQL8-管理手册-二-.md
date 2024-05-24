# MySQL8 管理手册（二）

> 原文：[`zh.annas-archive.org/md5/D5BC20BC3D7872C6C7F5062A8EE852A4`](https://zh.annas-archive.org/md5/D5BC20BC3D7872C6C7F5062A8EE852A4)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：MySQL 8 数据类型

在上一章中，我们学习了如何使用 MySQL 8 命令行程序和实用程序对 MySQL 8 数据库执行各种操作。拥有对命令行工具的掌握总是很好的。它提供了在非 GUI 环境中工作的灵活性。本章的重点是数据类型。了解编程语言支持的数据类型或存储引擎可以存储的数据类型是不是很有趣？这是任何编程语言或数据库的基本特性。同时，它也是最被忽视的话题。大多数程序员没有足够的时间来评估代码中使用的`变量`的存储需求。实际上，了解数据库支持的基本和自定义数据类型非常重要，这也是本章存在的原因。

以下是本章要涵盖的主题列表：

+   MySQL 8 数据类型概述

+   数值数据类型

+   日期和时间数据类型

+   字符串数据类型

+   JSON 数据类型

+   数据类型的存储要求

+   为列选择正确的数据类型

# MySQL 8 数据类型概述

MySQL 支持所有标准 SQL 数据类型。这些数据类型分为几个类别，如数值类型、字符串类型、日期和时间类型以及 JSON 数据类型。当我们为列分配数据类型时，必须遵循某些约定。这些约定对于 MySQL 允许在列中存储值是必要的：

+   **M**表示整数类型的最大显示宽度。对于浮点和定点类型，它是可以存储的总位数。对于字符串类型，它是最大长度。允许的最大值取决于数据类型。

+   **D** 适用于浮点和定点类型。它表示小数点后的位数。允许的最大值为 30，但必须小于或等于 M-2。

+   **fsp** 适用于日期和时间类型。它表示分数秒精度，即小数点后秒的小数部分的位数。

本概述简要介绍了每种数据类型的特性，详细描述将在后续主题中涵盖。

# 数值数据类型

MySQL 8 数值数据类型包括整数或精确数据类型、十进制或近似数据类型和位数据类型。

默认情况下，`REAL`数据类型的值存储为`DOUBLE`。如果我们在 MySQL 上设置了`REAL_AS_FLOAT`标志，`REAL`数据类型的值将存储为`FLOAT`。与`DOUBLE`相比，`FLOAT`占用的空间更小。

# 整数类型

MySQL 支持所有标准 SQL 整数类型。

以下是描述每种整数类型所需存储和范围的表。除了标准整数数据类型外，MySQL 还支持`TINYINT`、`MEDIUMINT`和`BIGINT`：

| **类型** | **存储（字节）** | **最小值** | **最大值** |
| --- | --- | --- | --- |
|  |  | **有符号/无符号** | **有符号/无符号** |
| `TINYINT` | 1 | -128 | 127 |
|  |  | 0 | 255 |
| `SMALLINT` | 2 | -32768 | 32767 |
|  |  | 0 | 65535 |
| `MEDIUMINT` | 3 | -8388608 | 8388607 |
|  |  | 0 | 16777215 |
| `INT` | 4 | -2147483648 | 2147483647 |
|  |  | 0 | 4294967295 |
| `BIGINT` | 8 | -9223372036854775808 | 9223372036854775807 |
|  |  | 0 | 18446744073709551615 |

参考：[`dev.mysql.com/doc/refman/8.0/en/integer-types.html`](https://dev.mysql.com/doc/refman/8.0/en/integer-types.html)

有符号数的范围包括负数和正数，而无符号数的范围仅包括正数。

以下是无符号整数列的列声明：

```sql
CREATE TABLE employees
(salary INTEGER(5) UNSIGNED);
```

`INT`和`INTEGER`可以互换使用。但是考虑一下，如果我们声明一个列：

```sql
CREATE TABLE employees
(id INT(255));
```

`INTEGER`列可以存储的最大值要么是 2147483647（对于有符号的`INTEGER`），要么是 4294967295（对于无符号的`INTEGER`）。这里的`255`定义了数字的可见长度。一方面，显示一个 255 位长的数字是不切实际的。另一方面，`INTEGER`支持最大值为 10 位数。因此，在前面的情况下，它将被转换为`INT(11)`。现在，这又引发了另一个问题：如果最大整数数字的位数为 10，那么为什么应该将其转换为`INT(11)`而不是`INT(10)`？原因是保留了一位数字用于存储符号。

`ZEROFILL`是一个属性，它表示如果数字值的长度小于列的长度，那么数字值应该以零填充。`CREATE`语句演示了声明带有`ZEROFILL`属性的列的方法。以下是一个例子：

```sql
CREATE TABLE documents
(document_no INT(5) ZEROFILL);
```

我们指定要存储的值为`111`；如果我们提供了`ZEROFILL`选项，它将被存储为`00111`。

# 固定点类型

固定点类型表示小数点或基数点后具有固定位数的数字。MySQL 有`DECIMAL`和`NUMERIC`作为固定点或精确值数据类型。这些值以二进制格式存储。固定点数据类型在存储货币值进行乘法和除法运算时特别有用。固定点数据类型的值是由特定因子缩放的整数。例如，值 1.11 可以以`111`的形式表示为固定点，缩放因子为 1/100。同样，1,110,000 可以以`1110`的形式表示，缩放因子为 1000。

以下代码块演示了`DECIMAL`数据类型的声明：

```sql
CREATE TABLE taxes
(tax_rate DECIMAL(3, 2));
```

在前面的例子中，`3`是精度，`2`是标度。一个例子值可以是 4.65，其中`4`是精度，`65`是标度。

+   **精度**：表示存储值的有效数字位数

+   **标度**：表示小数点后的数字位数

精度和标度定义了可以存储在列中的值的范围。因此，在前面的列声明中，`tax_rate`可以存储在-9.99 和 9.99 之间的值。

标准 SQL 中定义`DECIMAL`类型的语法如下：

```sql
DECIMAL(M)
```

在 MySQL 中，这相当于：

```sql
DECIMAL(M, 0)
```

在 MySQL 中，声明带有`DECIMAL`的列等同于`DECIMAL(M, 0)`。

在 MySQL 中，如果没有提供`M`，则`10`是`M`的默认值。

`DECIMAL`类型支持的最大数字位数为 65，包括精度和标度。我们可以通过精度和标度限制可以输入列的值的数字位数。如果用户输入的值的数字位数大于标度允许的数字位数，那么该值将被截断以匹配允许的标度。

`DECIMAL`通常被认为是`DOUBLE`或`FLOAT`的替代品。如前所述，`DECIMAL`数字是数学中`REAL`数字的精确表示。`DECIMAL`数据类型唯一的问题是，即使对于小数字，它也占用了更多的空间。例如，要存储值 0.000003，列声明应该将数据类型定义为`DECIMAL(7, 6)`。

如果标度为`0`，则列值没有小数点或分数值。

# 浮点类型

浮点数在计算中表示实数。实数对于测量连续值（如重量、高度或速度）非常有用。

MySQL 有两种用于存储近似值的浮点数据类型：`FLOAT`和`DOUBLE`。

对于浮点数，精度是一个重要因素。精度定义了准确度的度量。MySQL 支持单精度和双精度浮点数。使用`FLOAT`数据类型存储单精度浮点数需要四个字节，而使用`DOUBLE`数据类型存储双精度浮点数需要八个字节。

在 MySQL 中，`REAL`是`DOUBLE PRECISION`的同义词。如前所述，如果启用了`REAL_AS_FLOAT`，则使用`REAL`数据类型定义的列将类似于`FLOAT`。

前面的描述将`FLOAT`或`DOUBLE`描述为类似于`DECIMAL`。不，它不是。它们之间有很大的区别。如前所述，固定点数据类型如`DECIMAL`或`NUMERIC`可以存储精确值，直到小数点后的最大数字位数，而浮点数据类型如`FLOAT`或`DOUBLE`存储近似值。存储的值足够详细，但并非完全准确。仍然存在一些小的不准确性。

让我们通过以下代码示例来理解这一点：

```sql
mysql> CREATE TABLE typed_numbers(id TINYINT, float_values FLOAT, decimal_values DECIMAL(3, 2));

mysql> INSERT INTO typed_numbers VALUES(1, 1.1, 1.1), (2, 1.1, 1.1), (3, 1.1, 1.1);

mysql> SELECT * FROM typed_numbers;
+------+--------------+------------------+
| id   | float_values | decimal_values   |
+------+--------------+------------------+
|   1  |          1.1 |             1.10 |
|   2  |          1.1 |             1.10 |
|   3  |          1.1 |             1.10 |
+------+--------------+------------------+
mysql> SELECT SUM(float_values), SUM(decimal_values) FROM typed_numbers;
+--------------------+---------------------+
| SUM(float_values)  | SUM(decimal_values) |
+--------------------+---------------------+
| 3.3000000715255737 |                3.30 |
+--------------------+---------------------+
```

在前面的例子中：

1.  我们创建了一个包含`FLOAT`和`DECIMAL`类型列的表。

1.  我们在两个列中插入了相同的值，分别命名为`float_values`和`decimal_values`。

1.  我们执行了一个`select`查询来获取存储值的总和。

尽管值相同，输出却不同。`decimal_values`的总和看起来比`float_values`的更精确。`float_values`的总和看起来不够精确。这是因为 MySQL 引擎对浮点数据类型执行的内部舍入，导致存储的值是近似值。

标准 SQL 允许在定义`FLOAT`列时指定精度。精度是在关键字`FLOAT`后的括号内指定的位数。MySQL 也支持为`FLOAT`或`DOUBLE`指定精度值，但精度用于确定大小：

+   从 0 到 23 的精度会导致 4 字节单精度`FLOAT`列

+   从 24 到 53 的精度会导致 8 字节双精度`DOUBLE`列

以下是`FLOAT`列声明属性的示例：

```sql
FLOAT(M, D) 
where,
M - number of digits in total
D - number of digits may be after the decimal point
```

因此，定义为以下内容的列将存储值，例如 99.99：

```sql
FLOAT(4, 2)
```

在存储浮点值时，MySQL 执行舍入。因此，插入为 99.09 的值到`FLOAT(4, 2)`列可能会以 99.01 的近似结果存储。

尽管浮点列定义支持指定精度，但建议使用没有精度或数字位数的`FLOAT`或`DOUBLE PRECISION`，以便充分利用最大的灵活性和可移植性。

# 浮点值的问题

如前所述，浮点数据类型存储近似的实数。尝试存储精确值并在比较操作中考虑精确值可能会导致各种问题。此外，浮点值以平台和实现相关的方式进行解释。例如，不同的 CPU 或操作系统可能以不同的方式评估浮点数。这基本上意味着，打算存储在浮点数据类型列中的值可能与实际存储或内部表示的值不同。

当我们在比较中使用浮点数时，前面的观点变得至关重要。考虑以下例子：

```sql
mysql> CREATE TABLE temp(id INT, col1 DOUBLE, col2 DOUBLE);

mysql> INSERT INTO temp VALUES (1, 5.30, 2.30), (1, -3.00, 0.00),
 (2, 0.10, -10.00), (2, -15.20, 4.00), (2, 0.00, -7.10),
 (3, 0.00, 2.30), (3, 0.00, 0.00);

mysql> SELECT id, SUM(col1) as v1, SUM(col2) as v2 FROM temp
 GROUP BY id HAVING v1 <> v2;
+------+--------+--------+
|  id  |   v1   |   v2   |
+------+--------+--------+
|    1 |    2.3 |    2.3 |
|    2 |  -15.1 |  -13.1 |
|    3 |    0.0 |    2.3 |
+------+--------+--------+
```

在前面的例子中，输出的前两行似乎有相似的数字。在浮点类型的情况下可能不是这样。如果我们想要确保在前面的情况下，类似的值被认为是相似的，我们必须根据精度比较差异。例如，在前面的情况下，如果我们修改`HAVING`子句以检查条件`ABS(v1 - v2) > 0.1`，它将返回预期的输出。

由于浮点数的解释取决于平台，如果我们尝试插入超出浮点数据类型支持的值范围的值，可能会插入+- inf 或+- 0。

# 位值类型

您是否曾经遇到过存储数字的二进制表示的要求？您能想到这样的用例吗？这样的用例之一是存储一年中每周的工作日信息。我们稍后将在本节中介绍这个例子。

`BIT`数据类型用于存储二进制位或位值组。它也是存储布尔值、是/否或`0/1`值的选项之一。

`BIT`类型的列可以定义为：

```sql
column_name BIT
or
column_name BIT(m)
where m = number of bits to be stored
```

对于`BIT`数据类型，`m`可以从`1`变化到`64`。提供`m`是可选的。`m`的默认值为`1`。

以下是定义`BIT`列的示例：

```sql
CREATE TABLE working_days (
year INT,
week INT,
days BIT(7),
PRIMARY KEY (year, week));
```

在`BIT`数据类型列声明之后，接下来是在列中存储位值。位值是零（0）和一（1）的组合。使用`b'value'`表示法来指定位值。

以下是在`BIT`列中存储 11 和 55 的示例：

```sql
CREATE TABLE bit_values (val BIT(7));

INSERT INTO bit_values VALUES(b'1011');
INSERT INTO bit_values VALUES(b'110111');
```

如果存储在`BIT`列中的值少于列定义中指定的位数(`m`)，会发生什么？MySQL 将在数字左侧用 0 填充该值。因此，对于前面的示例，存储的值将分别为 0001011 和 0110111。

我们如何定义一个`BIT`列来存储`boolean_values`？以下代码块显示了这一点：

```sql
CREATE TABLE boolean_values (value BIT(1));
or
CREATE TABLE boolean_values (value BIT);

INSERT INTO boolean_values VALUES(b'0');
INSERT INTO boolean_values VALUES(b'1');
```

# 位值字面值

要在表列中存储位值，我们必须了解位字面值。如前所述，位字面值可以使用`b'val'`表示法编写。还有另一种表示法，即`0bval`表示法。

关于`b'val'`或`0bval`表示法的一个重要说明是，前导`b`的大小写不重要。我们可以指定`b`或`B`。前导的`0b`是大小写敏感的，不能用`0B`替换。

以下是合法和非法的位值字面值列表。

合法的位值字面值：

+   `b'10'`

+   `B'11'`

+   `0b10`

非法的位值字面值：

+   `b'3'`（`1`和`0`是唯一的二进制数字）

+   `0B01`（`0B`无效；应为`0b`）

作为默认值，位字面值是一个二进制字符串。我们可以通过查询来确认这一点，如下面的代码块所示：

```sql
mysql> SELECT b'1010110', CHARSET(b'1010110');
+--------------+----------------------+
| b'1010110'  | CHARSET(b'1010110') |
+--------------+----------------------+
|    V         |     binary           |
+--------------+----------------------+

mysql> SELECT 0b1100100, CHARSET(0b1100100);
+--------------+----------------------+
|  0b1100100   |  CHARSET(0b1100100)  |
+--------------+----------------------+
|    d         |     binary           |
+--------------+----------------------+
```

# BIT 的实际用途

让我们继续以一年中每周的工作日为例。请参考之前提供的`working_days`表模式。

我们如何指定`2017`年第`4`周的星期一和星期五为非工作日？以下是此操作的`INSERT`查询：

```sql
INSERT INTO working_days VALUES(2017, 4, 0111011);
```

如果我们使用`SELECT`查询获取`working_days`记录，输出如下：

```sql
mysql> SELECT year, week, days FROM working_days;
+--------+---------+--------+
|  year  |   week  |  days  |
+--------+---------+--------+
|   2017 |       4 |     59 |
+--------+---------+--------+
```

在前面的输出中，尽管日期是位数据类型，但显示的是整数值。我们如何在输出中显示位值呢？

答案是`BIN()` MySQL 函数。该函数将整数值转换为其二进制表示：

```sql
mysql> SELECT year, week, BIN(days) FROM working_days;
+--------+---------+------------+
|  year  |   week  |    days    |
+--------+---------+------------+
|   2017 |       4 |    111011  |
+--------+---------+------------+
```

如您所见，在输出中，日期的位值中的前导零被移除了。为了在输出中实现表示，除了`BIN`函数之外，我们还可以使用`LPAD` MySQL 函数：

```sql
mysql> SELECT year, week, LPAD(BIN(days), 7, '0') FROM working_days;
+--------+---------+------------+
|  year  |   week  |    days    |
+--------+---------+------------+
|   2017 |       4 |    0111011 |
+--------+---------+------------+
```

# 类型属性

如前所示，在定义整数列时，我们还可以指定一个可选的显示宽度属性。例如，`INT(5)`表示具有`5`位数字的整数。当此列在`SELECT`查询中使用时，输出将显示左填充空格的数字。因此，如果存储在`INT(5)`列中的值为`123`，则将显示为`__123`。`_`在实际输出中将是一个空格。

然而，显示宽度不限制可以存储在`INT(5)`列中的值的范围。那么问题来了：如果我们存储的值大于指定的显示宽度，会怎么样？显示宽度不会阻止比列的显示宽度更宽的值正确显示。因此，比列显示宽度更宽的值将以全宽显示，使用的数字数量超过了显示宽度指定的数量。

如前所述，MySQL 列定义提供了一个名为`ZEROFILL`的可选属性。当指定了这个可选属性时，它会用零替换左填充的空格。例如，对于以下定义的列，检索到的值为 00082：

```sql
INT(5) ZEROFILL
```

这个可选属性在需要正确格式化数字的情况下非常有用。

当列值用于表达式或`UNION`查询时，`ZEROFILL`属性将被忽略。

当在查询中使用复杂的连接来存储中间结果时，MySQL 会创建临时表。在这种情况下，如果我们指定了具有显示宽度的列，可能会遇到问题。在这些情况下，MySQL 认为数据值适合于显示宽度。

另一个重要的属性是`UNSIGNED`。`UNSIGNED`属性只允许在列中存储非负值。当我们需要支持相同数据类型的更大范围的值时，这也是非常有用的。

`UNSIGNED`也支持浮点类型和定点类型。

如果为列指定了`ZEROFILL`属性，`UNSIGNED`会自动添加到列中。

整数和浮点列的另一个重要属性是`AUTO_INCREMENT`。当我们在具有`AUTO_INCREMENT`属性的列中插入一个`NULL`值时，MySQL 会存储`value+1`而不是`NULL`。值为 0 将被视为`NULL`值，除非启用了`NO_AUTO_VALUE_ON_ZERO`模式。在这里，值是存储在列中的最大值。非常重要的是，列被定义为`NOT NULL`。否则，`NULL`值将被存储为`NULL`，即使提供了`AUTO_INCREMENT`属性。

# 溢出处理

当在 MySQL 中的数字类型列中存储超出范围的值时，存储的值取决于 MySQL 模式：

+   如果启用了`strict`模式，MySQL 将不接受该值并抛出错误。`insert`操作失败。

+   如果启用了`restrictive`模式，MySQL 会将值裁剪为适当的值，并将其存储在列中。

# 日期和时间数据类型

`DATE`、`TIME`、`DATETIME`、`TIMESTAMP`和`YEAR`构成了用于存储时间值的日期和时间数据类型组。每种类型都有一定范围的允许值。除了允许的值之外，还可以使用特殊的`零`值来指定 MySQL 无法表示的无效值。零值可以是 00-00-0000。MySQL 允许将此值存储在`date`列中。这有时比存储`NULL`值更方便。

在处理日期和时间类型时，我们必须注意以下一般考虑事项。

MySQL 对于日期或时间类型的存储和检索操作在格式的上下文中是不同的。基本上，对于存储在表中的日期或时间类型值，MySQL 以标准输出格式检索值。在输入日期或时间类型值的情况下，MySQL 尝试对提供的输入值应用不同的格式。因此，预期提供的值是有效的，否则如果使用不受支持的格式中的值，则可能会出现意外结果。

尽管 MySQL 可以解释多种不同格式的输入值，但日期值的部分必须以年-月-日的格式提供。例如，2017-10-22 或 16-02-14。

提供两位数年份会导致 MySQL 解释年份时出现歧义，因为世纪未知。以下是必须遵循的规则，使用这些规则，MySQL 解释两位数年份值：

+   70-99 年之间的年份值会被转换为 1970-1999

+   00-69 年之间的年份值会被转换为 2000-2069

可以按照一定的规则将一个时间类型的数值转换为另一个时间类型。我们将在本章后面讨论这些规则。

如果日期或时间数值在数值上下文中使用，MySQL 会自动将该数值转换为数字。

我们有一个有趣的用例。我们想要开发一个审计日志功能，用于存储用户输入的每个数值。假设在其中一个日期字段中，用户输入了一个无效的日期，2017-02-31。这会被存储在审计日志表中吗？当然不会。那么我们该如何完成这个功能呢？MySQL 有一个 `ALLOW_INVALID_DATES` 模式。如果启用了这个模式，它将允许存储无效的日期。启用了这个模式后，MySQL 会验证月份是否在 1-12 的范围内，日期是否在 1-31 的范围内。

由于 ODBC 无法处理日期或时间的零值，通过 Connector/ODBC 使用这些数值时会被转换为 `NULL`。

下表显示了不同数据类型的零值：

| **数据类型** | **零值** |
| --- | --- |
| `DATE` | 0000-00-00 |
| `TIME` | 00:00:00 |
| `DATETIME` | 0000-00-00 00:00:00 |
| `TIMESTAMP` | 0000-00-00 00:00:00 |
| `YEAR` | 0000 |

参考：[`dev.mysql.com/doc/refman/8.0/en/date-and-time-types.html`](https://dev.mysql.com/doc/refman/8.0/en/date-and-time-types.html)

上表显示了不同时间数据类型的零值。这些是特殊值，因为它们被 MySQL 允许，并且在某些情况下非常有用。我们还可以使用 `'0'` 或 `0` 来指定零值。MySQL 有一个有趣的模式配置：`NO_ZERO_DATE`。如果启用了这个配置，当时间类型的数值为零时，MySQL 会显示警告。

# DATE、DATETIME 和 TIMESTAMP 类型

本节描述了最常用的 MySQL 日期和时间数据类型：`DATE`、`DATETIME` 和 `TIMESTAMP`。本节解释了这些数据类型之间的相似之处和不同之处。

`DATE` 数据类型适用于我们希望存储的数值具有日期部分，但缺少时间部分的情况。标准的 MySQL 日期格式是 YYYY-MM-DD。日期数值在未应用 `DATE` 函数的情况下以标准格式检索和显示。MySQL 支持的数值范围是 1000-01-01 到 9999-12-31。这里的“支持”意味着这些数值可能有效，但不能保证。`DATETIME` 数据类型也是如此。

`DATETIME` 数据类型适用于包含日期和时间部分的数值。标准的 MySQL `DATETIME` 格式是 YYYY-MM-DD HH:MM:SS。支持的数值范围是 1000-01-01 00:00:00 到 9999-12-31 23:59:59。

与 `DATETIME` 类似，`TIMESTAMP` 数据类型也适用于包含日期和时间部分的数值。然而，`TIMESTAMP` 数据类型支持的数值范围是从 1970-01-01 00:00:01 UTC 到 2038-01-19 03:14:07 UTC。

尽管它们看起来相似，`DATETIME` 和 `TIMESTAMP` 数据类型有着显著的不同：

+   `TIMESTAMP` 数据类型需要 4 个字节来存储日期和时间数值。`DATETIME` 数据类型需要 5 个字节来存储日期和时间数值。

+   `TIMESTAMP` 可以存储值直到 2038-01-19 03:14:07 UTC。如果希望存储超过 2038 年的值，则应使用 `DATETIME` 数据类型。

+   `TIMESTAMP` 在存储数值时将 UTC 视为时区，`DATETIME` 则在存储数值时不考虑时区。

让我们通过一个例子来理解 `time_zone` 上下文中 `DATETIME` 和 `TIMESTAMP` 之间的差异。

假设初始的 `time_zone` 值设置为 `+00:00`：

```sql
SET time_zone = '+00:00';
```

让我们创建一个名为`datetime_temp`的表。该表有两列；一列是`DATETIME`，另一列是`TIMESTAMP`类型。我们将在两列中存储相同的日期和时间值。借助`SELECT`查询，我们将尝试了解输出中表示的差异：

```sql
mysql> CREATE TABLE datetime_temp(
 ts TIMESTAMP,
 dt DATETIME);

mysql> INSERT INTO datetime_temp
VALUES(NOW(), NOW());

mysql> SELECT ts, dt FROM datetime_temp;
+------------------------+-------------------------+
>|          ts            |            dt           |
+------------------------+-------------------------+
|  2017-10-14 18:10:25   |  2017-10-14 18:10:25    |
+------------------------+-------------------------+
```

在上面的例子中，`NOW()`是 MySQL 函数，它返回当前的日期和时间值。从输出来看，似乎`TIMESTAMP`和`DATETIME`的表示是相同的。这是因为`time_zone`值设置为 UTC。默认情况下，`TIMESTAMP`显示考虑 UTC `time_zone`的日期时间值。另一方面，`DATETIME`显示不带`time_zone`的日期时间。

让我们更改`time_zone`并观察输出：

```sql
mysql> SET time_zone = '+03:00';

mysql> SELECT ts, dt FROM datetime_temp;
+------------------------+-------------------------+
|          ts            |            dt           |
+------------------------+-------------------------+
|  2017-10-14 21:10:25   |  2017-10-14 18:10:25    |
+------------------------+-------------------------+
```

从输出来看，很明显`TIMESTAMP`考虑了 MySQL 中设置的`time_zone`值。因此，当我们更改时区时，`TIMESTAMP`值会调整。`DATETIME`不受影响，因此即使在更改时区后，输出也不会改变。

如果使用`TIMESTAMP`存储日期和时间值，我们在将数据迁移到位于不同时区的不同服务器时必须认真考虑它。

如果需要更高精度的时间值，`DATETIME`和`TIMESTAMP`可以包括最多微秒（六位数字）的尾随分数秒。因此，如果我们插入一个带有微秒值的日期时间值，它将存储在数据库中。格式，包括分数部分，是 YYYY-MM-DD HH:MM:SS[.fraction]，范围是从 1000-01-01 00:00:00.000000 到 9999-12-31 23:59:59.999999。`TIMESTAMP`的范围，包括分数，是 1970-01-01 00:00:01.000000 到 2038-01-19 03:14:07.999999。

时间值的小数部分通过小数点与时间值分隔，因为 MySQL 不识别其他分数秒的分隔符。

使用`TIMESTAMP`数据类型存储的日期和时间值会从服务器的时区转换为 UTC 进行存储，并从 UTC 转换为服务器的时区进行检索。如果我们存储了一个`TIMESTAMP`值，然后更改了服务器的时区并检索该值，则检索到的值将与我们存储的值不同。

以下是 MySQL 中日期值解释的属性列表：

+   MySQL 支持以字符串指定的值的宽松格式。在宽松格式中，任何标点字符都可以用作日期部分或时间部分之间的分隔符。这有点令人困惑。例如，值`10:11:12`可能看起来像一个时间值，因为使用了`:`，但被解释为`2010-11-12`日期。

+   在其余时间部分和分数秒部分之间的唯一识别分隔符是小数点。

+   预期月份和日期值是有效的。在禁用`strict`模式的情况下，无效日期将转换为相应的`zero`值，并显示警告消息。

+   在`TIMESTAMP`值中，如果日期或月份列中包含零，则不是有效日期。这条规则的例外是`zero`值。

如果 MySQL 以启用`MAXDB`模式运行，`TIMESTAMP`与`DATETIME`相同。如果在表创建时启用了此模式，则`TIMESTAMP`值将转换为`DATETIME`。

# MySQL DATETIME 函数

`NOW()`是用于获取系统当前日期和时间的函数：

```sql
mysql> SET @dt = NOW();
mysql> SELECT @dt;
+---------------------+
|       @dt           |
+---------------------+
| 2017-10-15 13:43:17 |
+---------------------+
```

`DATE()`函数用于从`DATETIME`值中提取日期信息：

```sql
mysql> SELECT DATE(@dt);
+------------------+
|    DATE(@dt)     |
+------------------+
|    2017-10-15    |
+------------------+
```

`TIME()`函数用于从日期时间值中提取时间信息：

```sql
mysql> SELECT TIME(@dt);
+------------------+
|    TIME(@dt)     |
+------------------+
|     13:43:17     |
+------------------+
```

当您希望基于日期或时间值显示或查询数据库表时，`DATE()`和`TIME()`函数非常有用，但表中存储的实际值包含日期和时间信息。

如果我们想从`DATETIME`或`TIMESTAMP`值中提取`YEAR`、`MONTH`、`DAY`、`QUARTER`、`WEEK`、`HOUR`、`MINUTE`和`SECOND`信息，相应的函数是可用的：

```sql
mysql> SELECT
 HOUR(@dt),
 MINUTE(@dt),
 SECOND(@dt),
 DAY(@dt),
 WEEK(@dt),
 MONTH(@dt),
 QUARTER(@dt),
 YEAR(@dt);
+-----------+-------------+-------------+---------+----------+
| HOUR(@dt) | MINUTE(@dt) | SECOND(@dt) | DAY(@dt)| WEEK(@dt)| 
+-----------+-------------+-------------+---------+----------+
+------------+--------------+-----------+
| MONTH(@dt) | QUARTER(@dt) | YEAR(@dt) |
+------------+--------------+-----------+
+-----------+-------------+-------------+---------+----------+
|        13 |          43 |          17 |      15 |       41 | 
+-----------+-------------+-------------+---------+----------+
+------------+--------------+-----------+
|         10 |            4 |      2017 |
+------------+--------------+-----------+
```

# TIME 类型

MySQL 的`DATETIME`或`TIMESTAMP`数据类型用于表示特定日期的特定时间。只存储一天中的时间或两个事件之间的时间差怎么办？MySQL 的`TIME`数据类型可以满足这一需求。

存储或显示`TIME`数据类型值的标准 MySQL 格式是`HH:MM:SS`。时间值表示一天中的时间，小于 24 小时，但是如前所述，`TIME`数据类型也可以用于存储经过的时间或两个事件之间的时间差。因此，`TIME`列可以存储大于 24 小时的值。

MySQL 的`TIME`列定义如下：

```sql
column_name TIME;
```

`TIME`数据类型列中可以存储的值的范围是-838:59:59 到 838:59:59。

MySQL 的`TIME`列还可以存储小数秒部分，最多可以达到微秒（六位数字），类似于`DATETIME`列。考虑到小数秒精度，值的范围从-838:59:59.000000 到 838:59:59.00000。

MySQL 的`TIME`列也可以有一个可选值：

```sql
column_name TIME(N);
where N represents number of fractional part, which is up to 6 digits.
```

`TIME`值通常需要 3 个字节来存储。在包括小数秒精度的`TIME`值的情况下，将需要额外的字节，取决于小数秒精度的数量。

以下表格显示了存储小数秒精度所需的额外字节数：

| **小数秒精度** | **存储（字节）** |
| --- | --- |
| 0 | 0 |
| 1, 2 | 1 |
| 3, 4 | 2 |
| 5, 6 | 3 |

MySQL 支持`TIME`列的缩写值。MySQL 有两种不同的方式来解释缩写值：

+   如果缩写值有冒号（`:`），MySQL 将其解释为一天中的时间。例如，11:12 被解释为 11:12:00，而不是 00:11:12。

+   如果缩写值没有冒号（`:`），MySQL 假定最右边的两位数字代表秒。这意味着该值被解释为经过的时间，而不是一天中的时间。例如，'1214'和 1214 被 MySQL 解释为 00:12:14。

MySQL 接受的唯一分隔符是小数点，用于将小数秒精度与时间值的其余部分分开。

MySQL 默认情况下，将超出允许值范围的值裁剪到范围的最近端点。例如，-880:00:00 和 880:00:00 存储为-838:59:59 和 838:59:59。无效的`TIME`值转换为 00:00:00。由于 00:00:00 本身是有效的`TIME`值，很难知道值 00:00:00 是有意存储的，还是从无效的`TIME`值转换而来。

MySQL 接受字符串和数字值作为`TIME`值。

# 时间函数

`CURRENT_TIME()`函数可用于查找服务器上的当前时间。还可以使用`ADDTIME`和`SUBTIME`函数添加或减去时间值。例如，以下示例将两小时添加到服务器的当前时间：

```sql
mysql> SELECT 
 CURRENT_TIME() AS 'CUR_TIME',
 ADDTIME(CURRENT_TIME(), 020000) AS 'ADDTIME',
 SUBTIME(CURRENT_TIME(), 020000) AS 'SUBTIME';

+----------+-----------+-----------+
| CUR_TIME |  ADDTIME  |  SUBTIME  |
+----------+-----------+-----------+
| 10:12:34 |  12:12:34 | 08:12:34  |
+----------+-----------+-----------+
```

`UTC_TIME()`函数可用于获取 UTC 时间。

# 年份类型

存储制造年份的首选数据类型是什么？MySQL 的答案是`YEAR`数据类型。`YEAR`数据类型需要 1 个字节来存储年份信息。

`YEAR`列可以声明为：

```sql
manufacturing_year YEAR
or
manufacturing_year YEAR(4)
```

值得注意的是，早期的 MySQL 版本支持`YEAR(2)`类型的列声明。从 MySQL 8 开始，不再支持`YEAR(2)`。可能需要将旧的 MySQL 数据库升级到 MySQL 8 数据库。在后面的部分中，我们将解释从`YEAR(2)`到`YEAR(4)`的迁移细节。

MySQL 以 YYYY 格式表示`YEAR`值。值的范围是从 1901 年到 2155 年和 0000 年。

以下是输入`YEAR`值支持的格式列表：

+   从 1901 年到 2155 年的四位数。

+   从 1901 年到 2155 年的四位字符串。

+   0 到 99 范围内的一位或两位数字。`YEAR`值从 1 到 69 转换为 2001 到 2069，从 70 到 99 转换为 1970 到 1999。

+   范围为 0 到 99 的一位或两位数字字符串。`YEAR`值从 1 到 69 转换为 2001 到 2069，从 70 到 99 转换为 1970 到 1999。

+   插入数字 0 的显示值为 0000，内部值为 0000。如果我们想要插入 0 并希望它被解释为 2000，我们应该将其指定为字符串 0 或 00。

+   返回可接受值`YEAR`上下文的函数的结果，例如`NOW()`。

MySQL 将无效的`YEAR`值转换为 0000。

# 将 YEAR(2)迁移到 YEAR(4)

如前所述，MySQL 8 不支持`YEAR(2)`类型。尝试创建一个数据类型为`YEAR(2)`的列将会产生以下错误：

```sql
mysql> CREATE TABLE temp(year YEAR(2));
ERROR 1818 (HY000): Supports only YEAR or YEAR(4) column.
```

重建表的`ALTER TABLE`查询将自动将`YEAR(2)`转换为`YEAR(4)`。在将数据库升级到 MySQL 8 数据库后，`YEAR(2)`列仍然保持为`YEAR(2)`，但查询会报错。

有多种方法可以从`YEAR(2)`迁移到`YEAR(4)`：

+   使用带有`FORCE`属性的`ALTER TABLE`查询将`YEAR(2)`列转换为`YEAR(4)`。但它不会转换值。如果`ALTER TABLE`查询应用于复制主机，复制从机将复制`ALTER TABLE`语句。因此，更改将在所有复制节点上可用。

+   使用二进制升级，无需转储或重新加载数据，是将`YEAR(2)`升级到`YEAR(4)`的另一种方法。随后运行`mysql_upgrade`会执行`REPAIR_TABLE`并将`YEAR(2)`转换为`YEAR(4`，而不更改值。与前一个替代方案类似，如果应用于复制主机，则会在复制从机中复制此更改。

需要注意的一点是，在升级时，我们不应该使用`mysqldump`转储`YEAR(2)`数据，并在升级后重新加载转储文件。这种方法有可能显著改变`YEAR(2)`的值。

在进行`YEAR(2)`到`YEAR(4)`迁移之前，必须审查应用程序代码：

+   选择以两位数字显示`YEAR`值的代码。

+   不处理数字`0`插入的代码。将`0`插入`YEAR(2)`会得到`2000`，而将`0`插入`YEAR(4)`会得到`0000`。

# 字符串数据类型

哪种数据类型是表示值最广泛需要和使用的？字符串还是字符数据类型；很容易，对吧？MySQL 支持各种字符串数据类型，以满足不同的存储需求。字符串数据类型分为两类：固定长度和可变长度。`CHAR`、`VARCHAR`、`BINARY`、`VARBINARY`、`BLOB`、`TEXT`、`ENUM`和`SET`是 MySQL 支持的字符串数据类型。每种数据类型的存储需求都不同，将在单独的部分中进行解释。

# CHAR 和 VARCHAR 数据类型

`CHAR`数据类型是 MySQL 中的固定长度字符串数据类型。`CHAR`数据类型通常声明为可以存储的最大字符数，如下所示：

```sql
data CHAR(20);
```

在前面的例子中，数据列可以存储能够存储最大字符的字符串值。

`CHAR`和`VARCHAR`在许多方面相似，但也有一些区别。如果要存储的字符串值是固定大小的，首选`CHAR`数据类型。与对固定大小字符串使用`VARCHAR`相比，它将提供更好的性能。

长度从 0 到 255 不等。`CHAR`列中的值不能超过表创建时声明的最大长度。如果字符串的长度小于允许的最大长度，MySQL 会在右侧添加填充以达到指定的长度。在检索时，尾随空格会被移除。以下是一个例子：

```sql
mysql> CREATE TABLE char_temp (
 data CHAR(3)
);

mysql> INSERT INTO char_temp(data) VALUES('abc'), (' a ');

mysql> SELECT data, LENGTH(data) 
 FROM char_temp;
+-------+--------------+
| data  | LENGTH(data) |
+-------+--------------+
|  abc  |      3       |
+-------+--------------+
|   a   |      2       |
+-------+--------------+
```

正如我们在前面的例子中所观察到的，第二条记录被插入为`' a '`, 但在输出中，尾随空格被移除。因此，长度显示为`2`而不是`3`。

大多数 MySQL 排序规则都有填充属性。它确定如何处理非二进制字符串的尾随空格进行比较。有两种类型的排序规则：`PAD SPACE`和`NO PAD`。在`PAD SPACE`排序规则的情况下，尾随空格在比较时不被考虑。字符串在不考虑尾随空格的情况下进行比较。

在`NO PAD`排序规则的情况下，尾随空格被视为任何其他字符。以下是一个示例：

```sql
mysql> CREATE TABLE employees (emp_name CHAR(10));

mysql> INSERT INTO employees VALUES ('Jack');

mysql> SELECT emp_name = 'Jack', emp_name = 'Jack ' FROM employees;
+-------------------+--------------------+ 
| emp_name = 'Jack' | emp_name = 'Jack ' | 
+-------------------+--------------------+ 
|                1  |                 1  | 
+-------------------+--------------------+ 
mysql> SELECT emp_name LIKE 'Jack', emp_name LIKE 'Jack ' FROM employees; 
+----------------------+------------------------+ 
| emp_name LIKE 'Jack' | emp_name LIKE 'Jack '  | 
+----------------------+------------------------+ 
|                    1 |                      0 | 
+----------------------+------------------------+
```

`LIKE`是 MySQL 中用于`WHERE`子句中的比较的运算符。它专门用于在字符串中进行模式搜索。在使用`LIKE`运算符比较字符串值时，尾随空格是重要的。

如果启用了`PAD_CHAR_TO_FULL_LENGTH`模式，在检索时，尾随空格将不会被移除。

MySQL `VARCHAR`数据类型是一个最大长度为 65,535 个字符的可变长度字符串数据类型。`VARCHAR`值由 MySQL 存储为一个或两个字节的长度前缀，以及实际数据。`VARCHAR`的实际最大长度取决于最大行大小，最大行大小为 65,536 字节，共享在所有列之间。

如果`VARCHAR`值需要的字节数少于 255 字节，则使用一个字节来确定长度前缀。如果值需要的字节数超过 255 字节，则使用两个字节来确定长度前缀。

如果启用了 MySQL 严格模式，并且要插入的`CHAR`或`VARCHAR`列值超过了最大长度，则会生成错误。如果禁用了严格模式，则该值将被截断为最大允许长度，并生成警告。

与`CHAR`数据类型不同，要存储在`VARCHAR`中的值不会填充。此外，检索值时也不会去除尾随空格。

# BINARY 和 VARBINARY 数据类型

另一组 MySQL 字符串数据类型是`BINARY`和`VARBINARY`。这些与`CHAR`和`VARCHAR`数据类型类似。`CHAR`/`VARCHAR`和`BINARY`/`VARBINARY`之间的一个重要区别是`BINARY`/`VARBINARY`数据类型包含的是二进制字符串而不是字符字符串。`BINARY`/`VARBINARY`使用二进制字符集和排序规则。`BINARY`/`VARBINARY`与`CHAR BINARY`和`VARCHAR BINARY`数据类型不同。基本区别在于所涉及的字符集和排序规则。

允许值的最大长度与`CHAR`和`VARCHAR`的最大长度类似。唯一的区别是`BINARY`和`VARBINARY`的长度是以字节而不是字符计算的。

MySQL 如何比较二进制值？答案是基于值中字节的数值进行比较。

与`CHAR`/`VARCHAR`数据类型类似，如果值的长度超过列长度，将截断值并生成警告（如果未启用`strict`模式）。如果启用了`strict`模式，将生成错误。

`BINARY`值在指定列长度右侧填充了填充值 0x00（零字节）。插入时添加填充值，但在检索时不会删除尾随字节。在比较`BINARY`值时，所有字节都被视为重要。这也适用于`ORDER BY`和`DISTINCT`运算符。当与*0x00 < space*进行比较时，零字节和空格是不同的。以下是插入二进制值的示例：

```sql
mysql> CREATE TABLE temp(
 data BINARY(3));

mysql> INSERT INTO temp(data) VALUES('a ');
```

在这种情况下，插入时`'a'`变成`'a\0'`。`'a\0'`转换为`'a\0\0'`。在检索时，值保持不变。

`VARBINARY`是一个可变长度字符串数据类型。与`BINARY`不同，`VARBINARY`在插入时不会添加填充，在检索时也不会去除字节。与`BINARY`类似，所有字节在比较`VARBINARY`时都是重要的。

如果表在列上有唯一索引，那么在列中插入仅在尾随填充字节数量上不同的值将导致重复键错误。例如，如果这样的列包含`'a '`，并且我们尝试插入`'a\0'`，将导致重复键错误。

以下示例解释了在比较中`BINARY`值的填充：

```sql
mysql> CREATE TABLE bin_temp (data BINARY(3));

mysql> INSERT INTO bin_temp(data) VALUES('c');

mysql> SELECT data = 'c', data = 'c\0\0' from bin_temp;
+------------+-------------------+
| data = 'c' |    data = 'c\0\0' |
+------------+-------------------+
|          0 |                 1 |
+------------+-------------------+
```

在需要检索与指定的相同值但不需要填充的情况下，最好使用`VARBINARY`。

如果检索的值必须与指定的存储值相同且不填充，可能更适合使用`VARBINARY`或`BLOB`数据类型之一。

# BLOB 和 TEXT 数据类型

在什么情况下我们可能需要将数据存储在**二进制大对象**（**BLOB**）列中？有任何想法吗？存储文件或图像，你说？这部分是正确的。在我们决定将图像或文件存储在数据库或文件系统之前，我们需要评估情况。如果文件存储在文件系统中并迁移到另一个操作系统，可能会导致文件指针损坏。这将需要额外的工作来修复文件指针。在这种情况下，将文件存储在数据库中更可取。但是，如果我们在数据库中存储大型拥挤的文件或图像数据，可能会影响性能。

`BLOB`是 MySQL 用于存储可变长度大型二进制信息的解决方案。MySQL 有四种`BLOB`类型：`TINYBLOB`，`BLOB`，`MEDIUMBLOB`和`LONGBLOB`。这些数据类型之间的唯一区别是我们可以存储的值的最大长度。这些数据类型的存储要求在本章后面的部分中有解释。

与`BLOB`类似，`TEXT`数据类型有`TINYTEXT`，`TEXT`，`MEDIUMTEXT`和`LONGTEXT`。它们具有与`BLOB`数据类型类似的最大长度和存储要求。

与`BINARY`数据类型一样，`BLOB`值被存储为字节字符串，并具有二进制字符集和排序。对列值的数字值进行比较和排序。`TEXT`值被存储为非二进制字符串。

对于`BLOB`或`TEXT`数据类型，如果值包含多余的尾随空格，MySQL 会截断并发出警告，无论 MySQL 模式如何。MySQL 在插入时不会填充`BLOB`或`TEXT`列的值，并且在检索时不会剥离字节。

对于索引的`TEXT`列，索引比较会在值的末尾添加尾随空格作为填充。因此，如果现有`TEXT`值和要插入的`TEXT`值之间的唯一区别在于尾随空格，则可能会在插入时发生重复键错误。`BLOB`可以被视为`VARBINARY`，`TEXT`可以被视为`VARCHAR`，对值的长度没有限制。

以下是`VARBINARY`，`VARCHAR`和`BLOB`，`TEXT`之间的区别：

+   在`BLOB`或`TEXT`列上创建索引时，必须指定索引前缀长度。

+   `BLOB`和`TEXT`不能有默认值

`BLOB`或`TEXT`值在内部表示为具有单独分配的对象，与其他数据类型不同，其他数据类型的存储是每列分配一次。

# ENUM 数据类型

MySQL 提供了一种数据类型，可以在创建表时预定义允许的值列表。该数据类型是`ENUM`。如果我们希望限制用户插入超出一定范围的值，应该定义数据类型为`ENUM`的列。MySQL 将用户输入的字符串值编码为`ENUM`数据类型的数字。

`ENUM`提供了以下提到的好处：

+   紧凑的数据存储

+   可读的查询和输出

以下是展示`ENUM`何时有用的示例：

```sql
mysql> CREATE TABLE subjects (
 name VARCHAR(40),
 stream ENUM('arts', 'commerce', 'science')
);

mysql> INSERT INTO subjects (name, stream) VALUES ('biology','science'), ('statistics','commerce'), ('history','arts');

```

```sql
mysql> SELECT name, stream FROM subjects WHERE stream = 'commerce';
+------------+----------+
|    name    |  stream  |
+------------+----------+
| statistics | commerce |
+------------+----------+

mysql> UPDATE subjects SET stream = 'science' WHERE stream = 'commerce';
```

`ENUM`值需要一个字节的存储。在这个表中存储一百万条这样的记录将需要一百万字节的存储空间，而不是`VARCHAR`列所需的六百万字节。

以下是需要考虑的重要限制：

+   `ENUM`值在内部存储为数字。因此，如果`ENUM`值看起来像数字，字面值可能会与其内部索引数字混淆。

+   在 `ORDER BY` 子句中使用 `ENUM` 列需要额外小心。`ENUM` 值根据列出顺序分配索引号。`ENUM` 值根据其索引号排序。因此，重要的是确保 `ENUM` 值列表按字母顺序排列。此外，列应按字母顺序而不是按索引号排序。 

+   `ENUM` 值必须是带引号的字符串文字。

+   每个 `ENUM` 值都有一个从 1 开始的索引。空字符串或错误值的索引为 0。我们可以通过在 `WHERE` 子句中查询具有 `enum_column_value = 0` 的表来找到无效的 `ENUM` 值。`NULL` 值的索引为 `NULL`。索引是指值在 `ENUM` 值列表中的位置。

+   在创建表时，MySQL 会自动删除 `ENUM` 成员值的尾随空格。检索时，`ENUM` 列中的值以列定义中使用的大小写显示。如果要在 `ENUM` 列中存储数字，则该数字将被视为可能值的索引。存储的值是具有该索引的 `ENUM` 值。对于带引号的数字值，如果在枚举值列表中没有匹配的字符串，则仍将其解释为索引。

+   如果声明 `ENUM` 列包含 `NULL` 值，则将考虑 `NULL` 值作为列的有效值，并且 `NULL` 成为默认值。如果不允许 `NULL`，则第一个 `ENUM` 值将成为默认值。

如果在数字上下文中使用 `ENUM` 值，则使用索引。以下是在数字上下文中使用 `ENUM` 值的示例查询：

```sql
mysql> SELECT stream+1 FROM subjects;
+--------------+
|   stream+1   |
+--------------+
|      4       |
|      3       |
|      2       |
+--------------+
```

# SET 数据类型

MySQL `SET` 是一种数据类型，可以具有零个或多个值。在创建表时指定了一个允许值列表。每个值必须来自允许值列表中。多个集合成员由逗号（`,`）分隔的值列表指定。`SET` 最多可以有 64 个不同的成员。如果启用了 `strict` 模式，则如果在列定义中发现重复的值，则会生成错误。

必须注意 `SET` 成员值不包含逗号；否则，它们将被解释为 `SET` 成员分隔符。

指定为 `SET('yes', 'no') NOT NULL` 的列可以具有以下任一值：

+   ''

+   '是'

+   '否'

+   '是，否'

`SET` 成员值会自动删除尾随空格。检索时，`SET` 列值将使用在列定义中使用的大小写显示。

以下是在 `SET` 数据类型中插入值的示例：

```sql
mysql> CREATE TABLE temp(
 hobbies SET('Travel', 'Sports', 'Fine Dining', 'Dancing'));

mysql> INSERT INTO temp(hobbies) VALUES(9);
```

`SET` 值存储在 MySQL 表中，其中每个元素由一个位表示。在前面的情况下，`SET` 中的每个元素都被分配一个位。如果行具有给定元素，则相关位将为一。由于这种方法，每个元素都有一个关联的十进制值。此外，由于位图，尽管只有四个值，`SET` 将占用一个字节。以下是解释这一点的表：

| **元素** | **SET 值** | **十进制值** |
| --- | --- | --- |
| 旅行 | 00000001 | 1 |
| 体育 | 00000010 | 2 |
| 精致餐饮 | 00000100 | 4 |
| 跳舞 | 00001000 | 8 |

可以通过添加它们的十进制值来表示多个 `SET` 元素。在前面的情况下，十进制值 9 被解释为旅行，跳舞。

`SET` 数据类型并不常用。这是因为虽然它是一个字符串数据类型，但在实现上有点复杂。可以存储的值限制为 64 个元素。我们不能将逗号作为 `SET` 值的一部分添加，因为逗号是标准的 `SET` 值分隔符。从数据库设计的角度来看，使用 `SET` 意味着数据库不是规范化的。

# JSON 数据类型

JSON 代表 JavaScript 对象表示法。假设我们想要在数据库中存储 Web 应用程序的用户偏好设置。通常，我们可能选择创建一个单独的表，其中包含`id`、`user_id`、`key`、`value`字段。这对于少量用户可能效果不错，但对于成千上万的用户来说，维护成本是无法承受的，与其增加 Web 应用程序的价值相比。

在 MySQL 中，我们可以利用 JSON 数据类型来满足这个需求。MySQL 支持原生的 JSON 数据类型，可以有效地存储 JSON 文档。MySQL 支持对存储在 JSON 列中的 JSON 文档进行自动验证。尝试存储无效的 JSON 文档会产生错误。存储在 JSON 列中的 JSON 文档会被转换为内部格式。该格式是二进制的，并且结构化，使服务器能够直接查找`subojbects`或嵌套值，通过键或数组索引，而无需读取其他值。

JSON 列不能有默认值。JSON 数据类型需要与`LONGTEXT`或`LONGBLOB`相似的存储。与其他字符串数据类型不同，JSON 列不会直接进行索引。

以下是在表中插入 JSON 值的示例：

```sql
mysql> CREATE TABLE users(
 user_id INT UNSIGNED NOT NULL,
 preferences JSON NOT NULL);

mysql> INSERT INTO users(user_id, preferences)
 VALUES(1, '{"page_size": 10, "hobbies": {"sports": 1}}');

mysql> SELECT preferences FROM users;
+---------------------------------------------------------+
|                   preferences                           |
+---------------------------------------------------------+
|    {"hobbies": {"sports": 1}, "page_size": 10}          |
+---------------------------------------------------------+
```

在前面的示例中，我们已经格式化了 JSON 值。作为替代，我们也可以使用内置的`JSON_OBJECT`函数。该函数接受一组键/值对并返回一个 JSON 对象。以下是一个示例：

```sql
mysql> INSERT INTO users(user_id, preferences)
 VALUES(2, JSON_OBJECT("page_size", 1, "network", JSON_ARRAY("GSM", "CDMA", "WIFI")));
```

前面的`INSERT`查询将插入 JSON 值`{"page_size": 1, "network": ["GSM", "CDMA", "WIFI"]}`。我们也可以使用嵌套的`JSON_OBJECT`函数。`JSON_ARRAY`函数在传递一组值时返回一个 JSON 数组。

如果多次指定相同的键，则只保留第一个键值对。在 JSON 数据类型的情况下，对象键会被排序，并且键值对之间的尾随空格会被移除。JSON 对象中的键必须是字符串。

只有在 JSON 文档有效的情况下，才能在 JSON 列中插入 JSON 值。如果 JSON 文档无效，MySQL 会产生错误。

MySQL 还有一个重要且有用的操作 JSON 值的函数。`JSON_MERGE`函数接受多个 JSON 对象并生成一个单一的聚合对象。

`JSON_TYPE`函数以 JSON 作为参数并尝试将其解析为 JSON 值。如果有效，则返回值的 JSON 类型，否则会产生错误。

# JSON 值的部分更新

如果我们想要更新存储在 JSON 数据类型列中的 JSON 文档中的值，我们应该怎么做？其中一种方法是删除旧文档并插入带有更新的新文档。这种方法似乎不太好，对吧？MySQL 8.0 支持对存储在 JSON 数据类型列中的 JSON 文档进行部分、就地更新。优化器要求更新必须满足以下条件：

+   列必须是 JSON 类型。

+   `JSON_SET()`、`JSON_REPLACE()`或`JSON_REMOVE()`三个函数中的一个可以用来更新列。MySQL 不允许直接对列值进行部分更新。

+   输入列和目标列必须相同。例如，像`UPDATE temp SET col1 = JSON_SET(col2, 'one', 10)`这样的语句不能作为部分更新执行。

+   更改只会更新现有数组或对象，不会向父对象或数组添加新元素。

+   替换值不能大于被替换的值。

# 数据类型的存储要求

本节解释了 MySQL 中不同数据类型的存储要求。存储要求取决于不同的因素。存储引擎以不同的方式表示数据类型并存储原始数据。

表的最大行大小为 65,535 字节，即使存储引擎能够支持更大的行。`BLOB`和`TEXT`数据类型被排除在外。

以下表格解释了数字数据类型的存储细节：

| **数据类型** | **所需存储空间** |
| --- | --- |
| `TINYINT` | 1 字节 |
| SMALLINT | 2 字节 |
| MEDIUMINT | 3 字节 |
| INT，INTEGER | 4 字节 |
| BIGINT | 8 字节 |
| FLOAT(p) | 如果*0<=p<=24*，则为 4 字节，如果*25<=p<=53*，则为 8 字节 |
| 浮点 | 4 字节 |
| DOUBLE [精度]，REAL | 8 字节 |
| DECIMAL(M, D)，NUMERIC(M, D) | 变化 |
| BIT(M) | 大约*(M+7)/8*字节 |

参考：[`dev.mysql.com/doc/refman/8.0/en/storage-requirements.html`](https://dev.mysql.com/doc/refman/8.0/en/storage-requirements.html)

以下表格解释了 DATE 和 TIME 数据类型的存储需求：

| 数据类型 | 存储需求 |
| --- | --- |
| YEAR | 1 字节 |
| 日期 | 3 字节 |
| 时间 | 3 字节 + 分数秒存储 |
| 日期时间 | 5 字节 + 分数秒存储 |
| TIMESTAMP | 4 字节 + 分数秒存储 |

以下表格解释了分数秒精度所需的存储空间：

| 分数秒精度 | 存储需求 |
| --- | --- |
| 0 | 0 字节 |
| 1, 2 | 1 字节 |
| 3, 4 | 2 字节 |
| 5, 6 | 3 字节 |

以下表格解释了字符串数据类型的存储需求：

| 数据类型 | 存储需求 |
| --- | --- |
| --- | --- |
| CHAR(M) | *M* × *w* 字节，*0 <= M <= 255*，其中*w*是字符集中最大长度字符所需的字节数 |
| BINARY(M) | *M* 字节，*0 <= M <= 255* |
| VARCHAR(M)，VARBINARY(M) | 如果列值需要 0 − 255 字节，则为*L* + 1 字节，如果值可能需要超过 255 字节，则为*L* + 2 字节 |
| TINYBLOB，TINYTEXT | *L* + 1 字节，其中*L* < 28 |
| BLOB，TEXT | *L* + 2 字节，其中*L* < 216 |
| `MEDIUMBLOB`，`MEDIUMTEXT` | *L* + 3 字节，其中*L* < 224 |
| LONGBLOB，LONGTEXT | *L* + 4 字节，其中***L*** < 232 |
| ENUM('value1','value2',...) | 取决于枚举值的数量，为 1 或 2 字节（最多 65,535 个值） |
| SET('value1','value2',...) | 取决于集合成员的数量，为 1、2、3、4 或 8 字节（最多 64 个成员） |

参考：[`dev.mysql.com/doc/refman/8.0/en/storage-requirements.html`](https://dev.mysql.com/doc/refman/8.0/en/storage-requirements.html)

在字符串数据类型的情况下，使用值的长度和长度前缀存储可变长度字符串。长度前缀根据数据类型的不同而变化，可以是一到四个字节。

JSON 数据类型的存储需求与 LONGBLOB 和 LONGTEXT 相似。然而，由于 JSON 文档以二进制表示存储，因此在存储 JSON 文档时会产生开销。

# 选择列的正确数据类型

作为一般惯例，我们应该使用最精确的类型来存储数据。例如，应该使用 CHAR 数据类型来存储长度从 1 到 255 个字符的字符串值。另一个例子是，应该使用 MEDIUMINT UNSIGNED 来存储从 1 到 99999 的数字。

基本操作，如`加法`，`减法`，`乘法`和`除法`，使用`DECIMAL`数据执行，精度为 65 个小数位。

根据准确性或速度的重要性，应选择使用 FLOAT 或 DOUBLE。存储在 BIGINT 中的定点值可用于更高的精度。

这些是一般指导方针，但是应该根据前面各数据类型单独解释的详细特性来决定使用正确的数据类型。

# 总结

这是一个有重要内容需要学习的有趣章节，对吧？在这一章中，我们了解了 MySQL 中数据类型的重要性。我们看到了 MySQL 数据类型被分类的不同类别。我们深入学习和了解了每种数据类型的特性和规格。我们还学习了 MySQL 数据操作函数，并了解了一些 MySQL 设置和模式。在本章的后面部分，我们学习了数据类型的存储需求。最后，我们学习了选择正确数据类型的一般指导方针。

进入下一章，我们将学习 MySQL 数据库管理。本章将重点介绍服务器管理，了解 MySQL 服务器的基本构建模块，如数据字典、系统数据库等。本章将解释如何在单台机器上运行多个服务器实例以及 MySQL 角色和权限。


# 第五章：MySQL 8 数据库管理

在上一章中，我们学习了 MySQL 8 数据类型，详细解释了可用的数据类型及其分类。每种数据类型都有各种属性，存储容量也因类型而异。上一章还为您提供了对 MySQL 8 数据类型的深入了解。现在是时候获得一些关于 MySQL 8 管理功能的实际知识了。了解更多关于 MySQL 8 管理功能的信息，如何为其进行配置等，这难道不是很有趣吗？对于管理员来说，详细了解 MySQL 8 的全球化工作原理、如何维护日志以及如何增强服务器的功能非常重要。现在，让我们从一些基本概念开始。

本章将涵盖以下主题：

+   MySQL 8 服务器管理

+   数据目录

+   系统数据库

+   在单台机器上运行多个实例

+   组件和插件管理

+   角色和权限

+   缓存技术

+   全球化

+   MySQL 8 服务器日志

# MySQL 8 服务器管理

MySQL 8 有许多可用的操作参数，其中所有必需的参数在安装过程中默认设置。安装后，您可以通过删除或添加特定参数设置行的注释符（`#`）来更改**选项文件**。用户还可以使用命令行参数或选项文件在运行时设置参数。

# 服务器选项和不同类型的变量

在本节中，我们将介绍 MySQL 8 启动时可用的**服务器选项**、**系统变量**和**状态变量**。

+   服务器选项：如前一章所述，MySQL 8 使用选项文件和命令行参数来设置启动参数。有关所有可用选项的详细信息，请参阅[`dev.mysql.com/doc/refman/8.0/en/mysqld-option-tables.html`](https://dev.mysql.com/doc/refman/8.0/en/mysqld-option-tables.html)。`mysqld`接受许多命令选项。要获得简要摘要，请执行以下命令：

```sql
 mysqld --help
```

要查看完整列表，请使用以下命令：

```sql
 mysqld –verbose --help
```

+   **服务器系统变量**：MySQL 服务器管理许多系统变量。MySQL 为每个系统变量提供默认值。系统变量可以使用命令行设置，也可以在选项文件中定义。MySQL 8 具有在运行时更改这些变量的灵活性，无需服务器启动或停止。有关更多详细信息，请参阅：[`dev.mysql.com/doc/refman/8.0/en/server-system-variables.html`](https://dev.mysql.com/doc/refman/8.0/en/server-system-variables.html)。

+   **服务器状态变量**：MySQL 服务器使用许多状态变量来提供有关其操作的信息。有关更多详细信息，请参阅：[`dev.mysql.com/doc/refman/8.0/en/server-status-variables.html`](https://dev.mysql.com/doc/refman/8.0/en/server-status-variables.html)。

# 服务器 SQL 模式

MySQL 8 提供了不同的模式，这些模式将影响 MySQL 支持和数据验证检查。此选项使用户更容易在不同环境中使用 MySQL。为了设置不同的模式，MySQL 提供了`sql_mode`系统变量，可以在全局或会话级别设置。详细了解模式的以下要点：

# 设置 SQL 模式

可以使用`--sql-mode="modes"`选项在启动时设置 SQL 模式。用户还可以在选项文件中定义此选项为`sql-mode="modes"`*。*您可以通过添加逗号分隔的值来定义多个节点。MySQL 8 默认使用以下模式：`ONLY_FULL_GROUP_BY`、`STRICT_TRANS_TABLES`、`NO_ZERO_IN_DATE`、`NO_ZERO_DATE`、`ERROR_FOR_DIVISION_BY_ZERO`*、*`NO_AUTO_CREATE_USER, NO_ENGINE_SUBSTITUTION`。要在运行时更改模式，请执行以下命令：

```sql
SET GLOBAL sql_mode = 'modes';
SET SESSION sql_mode = 'modes';
```

要检索这两个变量的值，请执行以下命令：

```sql
SELECT @@GLOBAL.sql_mode;
SELECT @@SESSION.sql_mode;
```

# 可用的 SQL 模式

此部分描述了所有可用的 SQL 模式。其中，前三个是最重要的 SQL 模式：

+   `ANSI`：此模式用于更改语法和行为，使其更接近标准 SQL。

+   `STRICT_TRANS_TABLES`：顾名思义，此模式与事务有关，主要用于事务存储引擎。当此模式对非事务表启用时，MySQL 8 将无效值转换为最接近的有效值，并将调整后的值插入列中。如果值丢失，则 MySQL 8 将插入与列数据类型相关的隐式默认值。在这种情况下，MySQL 8 将生成警告消息而不是错误消息，并继续执行语句而不中断。然而，在事务表的情况下，MySQL 8 会给出错误并中断执行。

+   `TRADITIONAL`：此模式通常表现得像传统的 SQL 数据库系统。它表示在将不正确的值插入列时产生错误而不是警告。

+   `ALLOW_INVALID_DATES`：此模式仅检查日期值的月份范围和日期范围。换句话说，月份范围必须在 1 到 12 之间，日期范围必须在 1 到 31 之间。此模式适用于`DATE`和`DATETIME`数据类型，而不适用于`timestamp`数据类型。

+   `ANSI_QUOTES`：用于将`"`视为标识符引用字符而不是字符串引用字符。当启用此模式时，您不能使用双引号引用字符串文字。

+   `ERROR_FOR_DIVISION_BY_ZERO`：用于处理除以零的情况。此模式的输出还取决于严格的 SQL 模式状态：

+   如果未启用此模式，除以零会插入`NULL`并且不会产生警告。

+   如果启用了此模式，除以零会插入`NULL`并产生警告。

+   如果启用了此模式和严格模式，除以零会产生错误，除非也给出了`IGNORE`。对于`INSERT IGNORE`和`UPDATE IGNORE`，除以零会插入`NULL`并产生警告。

+   `HIGH_NOT_PRECEDENCE`：此模式用于为`NOT`运算符设置高优先级。例如，当启用此模式时，表达式`NOT a BETWEEN b AND c`被解析为`NOT (a BETWEEN b AND c)`而不是`(NOT a) BETWEEN b AND c`。

+   `IGNORE_SPACE`：此模式适用于内置函数，而不适用于用户定义的函数或存储过程。

+   `NO_AUTO_CREATE_USER`：此模式用于防止通过自动创建新用户帐户的`GRANT`语句。

+   `NO_AUTO_VALUE_ON_ZERO`：此模式用于自动增量列。当找到 0 时，MySQL 为该字段创建一个新的序列号，这在加载转储时会造成问题。在重新加载转储之前启用此模式以解决此问题。

+   `NO_BACKSLASH_ESCAPES`：如果启用此模式，反斜杠将成为普通字符。

+   `NO_DIR_IN_CREATE`：此选项对于从属复制服务器非常有用，在表创建时会忽略`INDEX DIRECTORY`和`DATA DIRECTORY`指令。

+   `NO_ENGINE_SUBSTITUTION`：用于提供默认存储引擎的替换。当启用此模式并且所需的引擎不可用时，MySQL 会给出错误，表不会被创建。

+   `NO_FIELD_OPTIONS`：这表示，在`SHOW_CREATE_TABLE`的输出中不打印 MySQL 特定的列选项。

+   `NO_KEY_OPTIONS`：这表示，在`SHOW_CREATE_TABLE`的输出中不打印 MySQL 特定的索引选项。

+   `NO_TABLE_OPTIONS`：这表示，在`SHOW_CREATE_TABLE`的输出中不打印 MySQL 特定的表选项。

+   `NO_UNSIGNED_SUBTRACTION`：当启用此模式时，它确保减法结果必须是有符号值，即使操作数中的任何一个是无符号的。

+   `NO_ZERO_DATE`：此模式的效果取决于下面定义的严格模式：

+   如果未启用，允许使用 0000-00-00，MySQL 在插入时不会产生警告

+   如果启用此模式，则允许 0000-00-00，并且 MySQL 记录警告

+   如果同时启用此模式和严格模式，则不允许 0000-00-00，并且 MySQL 在插入时产生错误

+   `NO_ZERO_IN_DATE`：此模式的影响也取决于如下定义的严格模式：

+   如果未启用，允许具有零部分的日期，并且 MySQL 在插入时不会产生警告

+   如果启用此模式，则允许具有零部分的日期并产生警告

+   如果启用此模式和严格模式，则不允许具有零部分的日期，并且 MySQL 在插入时产生错误

+   `ONLY_FULL_GROUP_BY`：如果启用此模式，MySQL 将拒绝查询，其中`select`列表，`order by`列表和`HAVING`条件引用非聚合列。

+   `PAD_CHAR_TO_FULL_LENGTH`：此模式适用于数据类型设置为`CHAR`的列。启用此模式时，MySQL 通过填充以获取列值的完整长度。

+   `PIPES_AS_CONCAT`：当启用此模式时，`| |`将被视为字符串连接运算符，而不是`OR`。

+   `REAL_AS_FLOAT`：默认情况下，MySQL 8 将`REAL`视为`DOUBLE`的同义词，但当启用此标志时，MySQL 将`REAL`视为`FLOAT`的同义词。

+   `STRICT_ALL_TABLES`：在此模式下，无效的数据值将被拒绝。

+   `TIME_TRUNCATE_FRACTIONAL`：此模式指示是否允许对`TIME`，`DATE`和`TIMESTAMP`列进行截断。默认行为是对值进行四舍五入而不是截断。

# 组合 SQL 模式

MySQL 8 还提供了一些特殊模式，作为模式值的组合：

+   `ANSI`：它包括`REAL_AS_FLOAT`，`PIPES_AS_CONCAT`，`ANSI_QUOTES`，`IGNORE_SPACE`和`ONLY_FULL_GROUP_BY`模式的影响。

+   `DB2`：它包括`PIPES_AS_CONCAT`，`ANSI_QUOTES`，`IGNORE_SPACE`，`NO_KEY_OPTIONS`，`NO_TABLE_OPTIONS`和`NO_FIELD_OPTIONS`模式的影响。

+   `MAXDB`：它包括`PIPES_AS_CONCAT`，`ANSI_QUOTES`，`IGNORE_SPACE`，`NO_KEY_OPTIONS`，`NO_TABLE_OPTIONS`，`NO_FIELD_OPTIONS`和`NO_AUTO_CREATE_USER`的影响。

+   `MSSQL`：它包括`PIPES_AS_CONCAT`，`ANSI_QUOTES`，`IGNORE_SPACE`，`NO_KEY_OPTIONS`，`NO_TABLE_OPTIONS`和`NO_FIELD_OPTIONS`的影响。

+   `MYSQL323`：它包括`MYSQL323`和`HIGH_NOT_PRECEDENCE`模式的影响。

+   `MYSQL40`：它包括`MYSQL40`和`HIGH_NOT_PRECEDENCE`模式的影响。

+   `ORACLE`：它包括`PIPES_AS_CONCAT`，`ANSI_QUOTES`，`IGNORE_SPACE`，`NO_KEY_OPTIONS`，`NO_TABLE_OPTIONS`，`NO_FIELD_OPTIONS`和`NO_AUTO_CREATE_USER`模式的影响。

+   `POSTGRESQL`：它包括`PIPES_AS_CONCAT`，`ANSI_QUOTES`，`IGNORE_SPACE`，`NO_KEY_OPTIONS`，`NO_TABLE_OPTIONS`和`NO_FIELD_OPTIONS`模式的影响。

+   `TRADITIONAL`：它包括`STRICT_TRANS_TABLES`，`STRICT_ALL_TABLES`，`NO_ZERO_IN_DATE`，`NO_ZERO_DATE`，`ERROR_FOR_DIVISION_BY_ZERO`，`NO_AUTO_CREATE_USER`和`NO_ENGINE_SUBSTITUTION`模式的影响。

# 严格的 SQL 模式

**严格模式**用于管理*无效数据*或*丢失数据*。如果未启用严格模式，则 MySQL 将通过调整值和生成警告消息来管理插入和更新操作。我们可以通过启用`INSERT IGNORE`或`UPDATE IGNORE`选项在严格模式下执行相同的操作。让我们以一个键插入的例子来说明，其中键值超过了最大限制。如果启用了严格模式，MySQL 会产生错误并停止执行，而在相反的情况下，它会通过截断允许键值。同样，在`SELECT`语句的情况下，如果数据没有更改，MySQL 仍会产生错误，在严格模式下，如果存在无效值，则会生成警告消息。如果启用了`STRICT_ALL_TABLES`或`STRICT_TRANS_TABLES`选项，则严格模式生效。这两个选项在事务表的情况下行为类似，在非事务表的情况下行为不同。

+   **对于事务表**：如果启用了任一模式，则 MySQL 将在出现无效或缺少值的情况下产生错误并中止语句执行。

+   **对于非事务表**：当表是非事务性的时，MySQL 的行为将取决于以下因素：

+   `STRICT_ALL_TABLES`: 在这种情况下，将生成错误并停止执行。但仍然存在部分数据更新的可能性。为了避免这种错误情况，使用单行语句，如果在第一行插入/更新期间发生错误，将中止执行。

+   `STRICT_TRANS_TABLES`: 此选项提供了将无效值转换为最接近有效值的灵活性。在缺少值的情况下，MySQL 将数据类型的默认值插入到列中。在这里，MySQL 生成警告消息并继续执行。

严格模式影响对零的除法、零日期和日期中的零的处理，如前面的点中所述，使用`ERROR_FOR_DIVISION_BY_ZERO`、`NO_ZERO_DATE`和`NO_ZERO_IN_DATE`模式。

SQL 模式将应用于以下 SQL 语句：

```sql
ALTER TABLE
CREATE TABLE
CREATE TABLE ... SELECT
DELETE (both single table and multiple table)
INSERT
LOAD DATA
LOAD XML
SELECT SLEEP()
UPDATE (both single table and multiple table)
```

您可以访问：[`dev.mysql.com/doc/refman/8.0/en/sql-mode.html`](https://dev.mysql.com/doc/refman/8.0/en/sql-mode.html) 以获取 MySQL 中严格 SQL 模式相关错误的详细列表。

# IGNORE 关键字

MySQL 提供了一个可选的`IGNORE`关键字，用于语句执行。`IGNORE`关键字用于将错误降级为警告，并适用于多个语句。对于多行语句，`IGNORE`关键字允许您跳过特定行，而不是中止。以下语句支持`IGNORE`关键字：

+   `CREATE TABLE ... SELECT`: 单独的`CREATE`和`SELECT`语句不支持此关键字，但是当我们使用`SELECT`语句插入表时，具有唯一键值的行将被丢弃。

+   `DELETE`: 如果此语句执行`IGNORE`选项，MySQL 将避免执行期间发生的错误。

+   `INSERT`: 在行插入期间，此关键字将处理唯一键中的重复值和数据转换问题。MySQL 将在列中插入最接近的可能值并忽略错误。

+   `LOAD DATA`和`LOAD XML`: 在加载数据时，如果发现重复，该语句将丢弃它并继续插入剩余数据，如果定义了`IGNORE`关键字。

+   `UPDATE`: 在语句执行期间，如果唯一键发生重复键冲突，MySQL 将使用最接近的识别值更新列。

`IGNORE`关键字也适用于一些特定的错误，列在这里：[`dev.mysql.com/doc/refman/8.0/en/sql-mode.html`](https://dev.mysql.com/doc/refman/8.0/en/sql-mode.html)。

# IPv6 支持

MySQL 8 提供了对**IPv6**的支持，具有以下功能：

+   MySQL 服务器将接受来自具有 IPv6 连接性的客户端的 TCP/IP 连接

+   MySQL 8 帐户名称允许 IPv6 地址，这使得 DBA 可以为连接到服务器的客户端指定特权，使用 IPv6

+   IPv6 功能使字符串和内部 IPv6 地址格式之间的转换成为可能，并检查这些值是否表示有效的 IPv6 地址

# 服务器端帮助

MySQL 8 提供了`HELP`语句，以从 MySQL 参考手册中获取信息。为了管理这些信息，MySQL 使用系统数据库的几个表。为了初始化这些表，MySQL 提供了`fill_help_tables.sql`脚本。此脚本可在[`dev.mysql.com/doc/index-other.html`](https://dev.mysql.com/doc/index-other.html)下载并解压缩后，执行以下命令，以调用`HELP`函数：

```sql
mysql -u root mysql < fill_help_tables.sql
```

在安装过程中发生内容初始化。在升级的情况下，将执行上述命令。

# 服务器关闭过程

服务器关闭过程执行以下步骤：

1.  关闭过程已启动：有几种方法可以初始化关闭过程。执行`mysqladmin shutdown`命令，可以在任何平台上执行。还有一些特定于系统的方法来初始化关闭过程；例如，基于 Unix 的系统在接收到**SIGTERM**信号时将开始关闭。同样，基于 Windows 的系统将在服务管理器告知它们时开始关闭。

1.  如果需要，服务器将创建一个关闭线程：根据关闭初始化过程，服务器将决定是否创建新线程。如果客户端请求，将创建一个新线程。如果收到信号，则服务器可能会创建一个线程，或者自行处理。如果服务器尝试为关闭过程创建一个单独的线程，并且发生错误，则会在错误日志中产生以下消息：

```sql
 Error: Can't create thread to kill server
```

1.  服务器停止接受新连接：当关闭活动启动时，服务器将停止接受新的连接请求，使用网络接口的处理程序。服务器将使用 Windows 功能（如命名管道、TCP/IP 端口、Unix 套接字文件以及 Windows 上的共享内存）来监听新的连接请求。

1.  服务器终止当前活动：一旦关闭过程启动，服务器将开始与客户端断开连接。在正常情况下，连接线程将很快终止，但正在工作或处于进行中的活动阶段的线程将需要很长时间才能终止。因此，如果一个线程正在执行打开的事务，并且在执行过程中被回滚，那么用户可能只会得到部分更新的数据。另一方面，如果线程正在处理事务，服务器将等待直到事务完成。此外，用户可以通过执行`KILL QUERY`或`KILL CONNECTION`语句终止正在进行的事务。

1.  服务器关闭或关闭存储引擎：在此阶段，服务器刷新缓存并关闭所有打开的表。在这里，存储引擎执行所有必要的表操作。`InnoDB`刷新其缓冲池，将当前 LSN 写入表空间并终止其线程。`MyISAM`刷新挂起的索引。

1.  服务器退出：在此阶段，服务器将向管理进程提供以下值：

+   0 = 成功终止（未重新启动）

+   1 = 未成功终止（未重新启动）

+   2 = 未成功终止（已重新启动）

# 数据目录

数据目录是 MySQL 8 存储自身管理的所有信息的位置。数据目录的每个子目录代表一个数据库目录及其相关数据。所有 MySQL 安装都具有以下标准数据库：

+   `sys`目录：表示 sys 模式，其中包含用于性能模式信息解释的对象。

+   `performance schema`目录：此目录用于观察 MySQL 服务器在运行时的内部执行。

+   `mysql`目录：与 MySQL 系统数据库相关的目录，其中包含数据字典表和系统表。一旦 MySQL 服务器运行，它包含 MySQL 服务器所需的信息。

# 系统数据库

系统数据库主要包含存储对象元数据和其他操作目的的系统表的数据字典表。系统数据库包含许多系统表。我们将在接下来的部分中了解更多信息。

# 数据字典表

数据字典表包含有关数据对象的元数据。该目录中的表是不可见的，并且不会被一般的 SQL 查询（如`SELECT`、`SHOW TABLES`、`INFORMATION_SCHEMA.TABLES`等）读取。MySQL 主要使用`INFORMATION_SCHEMA`选项公开元数据。

# 授予系统表

这些表用于管理和提供用户、数据库和相关权限的授权信息。MySQL 8 使用授权表作为事务表，而不是非事务表（例如`MyISAM`），因此对事务的所有操作要么完成，要么失败；不会出现部分情况。

# 对象信息系统表

这些表包含与存储程序、组件和服务器端插件相关的信息。以下主要表用于存储信息：

+   **组件**: 作为服务器的注册表。MySQL 8 服务器在启动时加载此表列出的所有组件。

+   **Func**: 这个表包含与所有**用户定义函数**（**UDF**）相关的信息。MySQL 8 在服务器启动时加载此表中列出的所有 UDF。

+   **插件**: 包含与服务器端插件相关的信息。MySQL 8 服务器在启动时加载所有可用的插件。

# 日志系统表

这些表对记录和使用 csv 存储引擎很有用。例如，`general_log`和`slow_log`函数。

# 服务器端帮助系统表

这些表用于存储帮助信息。在这个类别中有以下表：

+   `help_category`: 提供关于帮助类别的信息

+   `help_keyword`: 提供与帮助主题相关的关键字

+   `help_relation`: 用于帮助关键字和主题之间的映射

+   `help_topic`: 帮助主题内容

# 时区系统表

这些表用于存储时区信息。在这个类别中有以下表：

+   `time_zone`: 提供时区 ID 以及它们是否使用闰秒

+   `time_zone_leap_second`: 当闰秒发生时会派上用场

+   `time_zone_name`: 用于时区 ID 和名称之间的映射

+   `time_zone_transition`和`time_zone_transition_type`: 时区描述

# 复制系统表

这些表对支持复制功能很有用。当配置为以下表中所述时，它有助于存储复制相关信息。在这个类别中有以下表：

+   `gtid_executed`: 用于创建存储 GTID 值的表

+   `ndb_binlog_index`: 为 MySQL 集群复制提供二进制日志信息

+   `slave_master_info`、`slave_relay_log_info`和`slave_worker_info`: 用于在从服务器上存储复制信息

# 优化器系统表

这些表对优化器很有用。在这个类别中有以下表：

+   `innodb_index_stats`和`innodb_table_stats`: 用于获取`InnoDB`持久优化器统计信息

+   `server_cost`: 包含了对一般服务器操作的优化器成本估算。

+   `engine_cost`: 包含特定存储引擎操作的估算

# 其他杂项系统表

不属于上述类别的表属于这个类别。在这个类别中有以下表：

+   `servers`: 被`FEDERATED`存储引擎使用

+   `innodb_dynamic_metadata`: 被`InnoDB`存储引擎用于存储快速变化的表元数据，如自增计数器值和索引树损坏标志

您可以在以下链接了解更多关于不同系统表的信息：[`dev.mysql.com/doc/refman/8.0/en/system-database.html`](https://dev.mysql.com/doc/refman/8.0/en/system-database.html)。

# 在单台机器上运行多个实例

可能会有一些情况需要在一台机器上安装多个实例。这可能是为了检查两个不同版本的性能，或者可能需要在不同的 MySQL 实例上管理两个单独的数据库。原因可能是任何，但是 MySQL 允许用户通过提供不同的配置值在同一台机器上执行多个实例。MySQL 8 允许用户使用命令行、选项文件或设置环境变量来配置参数。MySQL 8 用于此的主要资源是数据目录，对于两个实例，它必须是唯一的。我们可以使用`--datadir=dir_name`函数来定义相同的值。除了数据目录，我们还将为以下选项配置唯一的值：

+   `--port=port_num`

+   `--socket={file_name|pipe_name}`

+   `--shared-memory-base-name=name`

+   `--pid-file=file_name`

+   `--general_log_file=file_name`

+   `--log-bin[=file_name]`

+   ``--slow_query_log_file=file_name``

+   `--log-error[=file_name]`

+   `--tmpdir=dir_name`

# 设置多个数据目录

如上所述，每个 MySQL 实例必须有一个单独的数据目录。用户可以使用以下方法定义单独的目录：

+   **创建新的数据目录**：在这种方法中，我们必须遵循第二章中定义的相同过程，*安装和升级 MySQL*。对于 Microsoft Windows，当我们从 Zip 存档安装 MySQL 8 时，将其数据目录复制到要设置新实例的位置。在 MSI 软件包的情况下，连同数据目录一起，在安装目录下创建一个原始的`template`数据目录，命名为 data。安装完成后，复制数据目录以设置额外的实例。

+   **复制现有数据目录**：在这种方法中，我们将现有实例的数据目录复制到新实例的数据目录。要复制现有目录，请执行以下步骤：

1.  停止现有的 MySQL 实例。确保它被干净地关闭，以便磁盘中没有未决的更改。

1.  将数据目录复制到新位置。

1.  将现有实例使用的`my.cnf`或`my.ini`选项文件复制到新位置。

1.  根据新实例修改新选项。确保所有唯一的配置都正确完成。

1.  使用新的选项文件启动新实例。

# 在 Windows 上运行多个 MySQL 实例

用户可以通过使用命令行和传递值或通过窗口服务在单个 Windows 机器上运行多个 MySQL 实例。

+   **在 Windows 命令行上启动多个 MySQL 实例：**要使用命令行执行多个实例，我们可以在运行时指定选项，也可以在选项文件中设置它。选项文件是启动实例的更好选择，因为无需在启动时每次指定参数。要设置或配置选项文件，请按照[第二章](https://cdp.packtpub.com/mysql_8_administrator___s_guide/wp-admin/post.php?post=121&action=edit#post_26)中描述的相同步骤，*安装和升级 MySQL*。

+   **在 Windows 服务上启动多个 MySQL 实例：**要在 Windows 上启动多个实例作为服务，我们必须指定具有唯一名称的不同服务。如第二章中所述，*安装和升级 MySQL*，使用`–install`或`--install-manual`选项将 MySQL 定义为 Windows 服务。以下选项可用于将多个 MySQL 实例定义为 Windows 服务：

+   **方法 1**：为实例创建两个单独的选项文件，并在其中定义`mysqld`组。例如，使用函数`C:\my-opts1.cnf`。以下是相同代码供您参考：

```sql
 [mysqld]
 basedir = C:/mysql-5.5.5
 port = 3307
 enable-named-pipe
 socket = mypipe1
```

我们也可以使用`C:\my-opts2.cnf`函数来做同样的事情。以下代码描述了该过程：

```sql
 [mysqld]
 basedir = C:/mysql-8.0.1
 port = 3308
 enable-named-pipe
 socket = mypipe2
```

您可以使用以下命令安装 MySQL8 服务：

```sql
 C:\> C:\mysql-5.5.5\bin\mysqld --install mysqld1 --
                defaults-file=C:\my-opts1.cnf
 C:\> C:\mysql-8.0.1\bin\mysqld --install mysqld2 --
                defaults-file=C:\my-opts2.cnf
```

+   +   **方法 2**：为两个服务创建一个公共选项文件`C:\my.cnf`：

```sql
 # options for mysqld1 service
 [mysqld1]
 basedir = C:/mysql-5.5.5
 port = 3307
 enable-named-pipe
 socket = mypipe1

 # options for mysqld2 service
 [mysqld2]
 basedir = C:/mysql-8.0.1
 port = 3308
 enable-named-pipe
 socket = mypipe2
```

+   执行以下命令安装 MySQL 服务：

```sql
 C:\> C:\mysql-5.5.9\bin\mysqld --install mysqld1
 C:\> C:\mysql-8.0.4\bin\mysqld --install mysqld2
```

+   要启动 MySQL 服务，请执行以下命令：

```sql
 C:\> NET START mysqld1
 C:\> NET START mysqld2
```

# 组件和插件管理

MySQL 服务器支持基于组件的结构，以扩展服务器功能。MySQL 8 使用`INSTALL COMPONENT`和`UNINSTALL COMPONENT` SQL 语句在运行时加载和卸载组件。MySQL 8 将组件详细信息管理到`mysql.component`系统表中。因此，每次安装新组件时，MySQL 8 服务器都会执行以下任务：

+   将组件加载到服务器中以立即可用

+   将服务注册的组件加载到`mysql.component`系统表中。

当我们卸载任何组件时，MySQL 服务器将执行相同的步骤，但顺序相反。要查看可用的组件，请执行以下查询：

```sql
SELECT * FROM mysql.component;
```

# MySQL 8 服务器插件

MySQL 8 服务器具有插件 API，可用于创建服务器组件。使用 MySQL 8，您可以在运行时或启动时灵活安装插件。在接下来的主题中，我们将了解 MySQL 8 服务器插件的生命周期。

# 安装插件

插件的加载因其类型和特性而异。为了更清楚地了解这一点，让我们来看看以下内容：

+   **内置插件**：服务器知道内置插件并在启动时自动加载它们。用户可以通过任何激活状态来改变插件的状态，这将在下一节中讨论。

+   **在`mysql.plugin`系统表中注册的插件**：在启动时，MySQL 8 服务器将加载在`mysql.plugin`表中注册的所有插件。如果服务器使用`--skip-grant-tables`选项启动，则服务器将不加载那里列出的插件。

+   **使用命令行选项命名的插件**：MySQL 8 提供`--plugin-load`、`--plugin-load-add`和`--early-plugin-load`选项，用于在命令行加载插件。`--plugin-load`和`--plugin-load-add`选项在安装内置插件后在服务器启动时加载插件。但是，我们可以使用`--early-plugin-load`选项在初始化内置插件和存储引擎之前加载插件。

+   **使用`INSTALL PLUGIN`语句安装的插件**：这是一个永久的插件注册选项，它将在`mysql.plugin`表中注册插件信息。它还将加载插件库中的所有可用插件。

# 激活插件

要控制插件的状态（如激活或停用），MySQL 8 提供以下选项：

+   `--plugin_name=OFF`：禁用指定的插件。一些内置插件，如`asmysql_native_password`插件，不受此命令影响。

+   `--plugin_name[=ON]`：此命令启用指定的插件。如果在启动时插件初始化失败，MySQL 8 将以禁用插件的状态启动。

+   `--plugin_name=FORCE`：这与上述命令相同，只是服务器不会启动。这意味着如果在启动时提到了插件，它会强制服务器与插件一起启动。

+   `--plugin_name=FORCE_PLUS_PERMANENT`：与`FORCE`选项相同，但另外防止插件在运行时被卸载。

# 卸载插件

MySQL 8 使用`UNINSTALL PLUGIN`语句卸载插件，而不考虑它是在运行时还是在启动时安装的。但是，此语句不允许我们卸载内置插件和通过`--plugin_name=FORCE_PLUS_PERMANENT`选项安装的插件。此语句只是卸载插件并将其从`mysql.plugin`表中删除，因此需要`mysql.plugin`表上的额外*delete*权限。

# 获取已安装插件的信息

有多种方法可以获取有关已安装插件的信息。以下是其中一些，供您参考：

+   `INFORMATION_SCHEMA.PLUGINS`表包含插件的详细信息，如`PLUGIN_NAME`、`PLUGIN_VERSION`、`PLUGIN_STATUS`、`PLUGIN_TYPE`、`PLUGIN_LIBRARY`等等。该表的每一行都代表有关插件的信息：

```sql
 SELECT * FROM information_schema.PLUGINS;
```

+   `SHOW PLUGINS`语句显示了每个单独插件的名称、状态、类型、库和许可证详情。如果库的值为`NULL`，则表示它是一个内置插件，因此无法卸载。

```sql
 SHOW PLUGINS;
```

+   `mysql.plugin`表包含了所有通过`INSTALL PLUGIN`函数注册的插件的详细信息。

# 角色和权限

简而言之，*角色*是一组权限。在 MySQL 8 中创建角色，您必须具有全局的`CREATE ROLE`或`CREATE USER`权限。MySQL 8 提供了各种权限，可附加到角色和用户上。有关可用权限的更多详细信息，请参阅[`dev.mysql.com/doc/refman/8.0/en/privileges-provided.html`](https://dev.mysql.com/doc/refman/8.0/en/privileges-provided.html)。

现在，让我们举个例子来理解角色创建和权限分配的作用。假设我们已经在当前数据库中创建了一个`hr_employee`表，并且我们想要将这个表的访问权限赋予`hrdepartment`角色。这个困境可以通过使用以下代码来解决：

```sql
CREATE ROLE hrdepartment;
grant all on hr_employee to hrdepartment;
```

上述代码将帮助我们创建`hrdepartment`角色并授予它所有必要的访问权限。这个主题将在第十一章中详细介绍，*安全*。

# 缓存技术

缓存是一种用于提高性能的机制。MySQL 使用多种策略在缓冲区中缓存信息。MySQL 8 在存储引擎级别使用缓存来处理其操作。它还在准备好的语句和存储程序中应用缓存以提高性能。MySQL 8 引入了各种系统级变量来管理缓存，例如`binlog_stmt_cache_size`、`daemon_memcached_enable_binlog`、`daemon_memcached_w_batch_size`、`host_cache_size`等等。我们将在第十二章中详细介绍缓存，*优化 MySQL 8*。

# 全球化

全球化是一个功能，为应用程序提供多语言支持，比如启用本地语言的使用。用我们自己的母语理解消息要比其他语言容易得多，对吧？为了实现这一点，全球化就出现了。使用全球化，用户可以将数据存储、检索和更新为多种语言。在全球化中有一些参数需要考虑。我们将在接下来的章节中详细讨论它们。

# 字符集

在详细讨论字符集之前，需要了解字符集实际上是什么，以及它的相关术语，对吧？让我们从术语本身开始；字符集是一组符号和编码。与字符集相关的另一个重要术语是**校对规则**，用于比较字符。让我们举一个简单的例子来理解字符集和校对规则。考虑两个字母，*P*和*Q*，并为每个分配一个数字，使得*P=1*和*Q=2*。现在，假设*P*是一个符号，1 是它的编码。在这里，这两个字母及它们的编码的组合被称为字符集。现在假设我们想要比较这些值；最简单的方法是参考编码值。由于 1 小于 2，我们可以说*P*小于*Q*，这就是校对规则。这是一个简单的例子来理解字符集和校对规则，但在现实生活中，我们有许多字符，包括特殊字符，同样的校对规则也有许多规则。

# 字符集支持

MySQL 8 支持多种字符集，具有各种排序规则。字符集可以在列、表、数据库或服务器级别定义。我们可以在`InnoDB`、`MyISAM`和`Memory`存储引擎中使用字符集。要检查 MySQL 8 的所有可用字符集，请执行以下命令：

```sql
mysql> show character set;
+----------+---------------------------------+---------------------+--------+
| Charset | Description | Default collation | Maxlen |
+----------+---------------------------------+---------------------+--------+
| armscii8 | ARMSCII-8 Armenian | armscii8_general_ci | 1 |
| ascii | US ASCII | ascii_general_ci | 1 |
| big5 | Big5 Traditional Chinese | big5_chinese_ci | 2 | .........
.........
+----------+---------------------------------+---------------------+--------+
41 rows in set (0.01 sec)
```

同样，要查看字符的排序规则，请执行以下命令：

```sql
mysql> SHOW COLLATION WHERE Charset = 'ascii';
+------------------+---------+----+---------+----------+---------+---------------+
| Collation | Charset | Id | Default | Compiled | Sortlen | Pad_attribute |
+------------------+---------+----+---------+----------+---------+---------------+
| ascii_bin | ascii | 65 | | Yes | 1 | PAD SPACE |
| ascii_general_ci | ascii | 11 | Yes | Yes | 1 | PAD SPACE |
+------------------+---------+----+---------+----------+---------+---------------+
2 rows in set (0.00 sec)
```

排序规则将具有以下三个特征：

+   两个不同的字符集合不能具有相同的排序规则。

+   每个字符集都有一个默认的排序规则。如上所示，`show character set`命令显示了字符集的默认排序规则。

+   排序规则遵循预定义的命名约定，稍后将对其进行解释。

+   字符集合：**repertoire**是数据集中的字符集合。任何字符串表达式都将具有 repertoire 属性，并且将属于以下值之一：

+   ASCII：包含 Unicode 范围 U+0000 到 U+007F 的字符的表达式。

+   UNICODE：包含 Unicode 范围 U+0000 到 U+10FFFF 的字符的表达式。这包括**基本多语言平面**（**BMP**）范围（U+0000 到 U+FFFF）和 BMP 范围之外的补充字符（U+01000 到 U+10FFFF）。

从这两个值的范围中，我们可以确定 ASCII 是 UNICODE 范围的子集，我们可以安全地将 ASCII 值转换为 UNICODE 值而不会丢失数据。Repertoire 主要用于将表达式从一个字符集转换为另一个字符集。在某些转换情况下，MySQL 8 会抛出类似“illegal mix of collations”的错误；为了处理这些情况，需要 repertoire。要了解其用法，请考虑以下示例：

```sql
CREATE TABLE employee (
 firstname CHAR(10) CHARACTER SET latin1,
 lastname CHAR(10) CHARACTER SET ascii
);

INSERT INTO employee VALUES ('Mona',' Singh');

select concat(firstname,lastname) from employee;
+----------------------------+
| concat(firstname,lastname) |
+----------------------------+
| Mona Singh |
+----------------------------+
1 row in set (0.00 sec)
```

+   **用于元数据的 UTF-8**：元数据是关于数据的数据。在数据库方面，我们可以说描述数据库对象的任何内容都称为**元数据**。例如：列名，用户名等。MySQL 遵循以下两条元数据规则：

+   包括所有语言中的所有字符以用于元数据；这使用户可以使用自己的语言作为列名和表名。

+   为所有元数据管理一个共同的字符集合。否则，`INFORMATION_SCHEMA`中的表的`SHOW`和`SELECT`语句将无法正常工作。

为了遵循上述规则，MySQL 8 将元数据存储为 Unicode 格式。请注意，MySQL 函数（如`USER()`、`CURRENT_USER()`、`SESSION_USER()`、`SYSTEM_USER()`、`DATABASE()`和`VERSION()`）默认使用 UTF-8 字符集。MySQL 8 服务器已定义`character_set_system`来指定元数据的字符集。确保在 Unicode 中存储元数据并不意味着列标题和`DESCRIBE`函数将以元数据字符集的形式返回值。它将根据`character_set_results`系统变量工作。

# 添加字符集

本节介绍如何在 MySQL 8 中添加字符集。此方法可能因字符类型而异，可能简单或复杂。在 MySQL 8 中添加字符集需要以下四个步骤：

1.  将`<charset>`元素添加到`sql/share/charsets/Index.xml`文件中的`MYSET`。有关语法，请参考已定义的其他字符集文件。

1.  在此步骤中，简单字符集和复杂字符集的处理方式不同。对于简单字符集，创建一个配置文件`MYSET.xml`，描述字符集属性，放在`sql/share/charsets`目录中。对于复杂字符集，需要 C 源文件。例如，在 strings 目录中创建`ctype-MYSET.c`类型。对于每个`<collation>`元素，提供`ctype-MYSET.c`文件。

1.  修改配置信息：

1.  编辑`mysys/charset-def.c`，并*注册*新字符集的排序规则。将这些行添加到**declaration**部分：

```sql
 #ifdef HAVE_CHARSET_MYSET
 extern CHARSET_INFO my_charset_MYSET_general_ci;
 extern CHARSET_INFO my_charset_MYSET_bin;
 #endif
```

将这些行添加到**registration**部分：

```sql
 #ifdef HAVE_CHARSET_MYSET
 add_compiled_collation(&my_charset_MYSET_general_ci);
 add_compiled_collation(&my_charset_MYSET_bin);
 #endif
```

1.  1.  如果字符集使用`ctype-MYSET.c`，请编辑`strings/CMakeLists.txt`并将`ctype-MYSET.c`添加到`STRINGS_SOURCES`变量的定义中。

1.  编辑`cmake/character_sets.cmake`进行以下更改：

+   按字母顺序将`MYSET`添加到`CHARSETS_AVAILABLE`的值中。

+   按字母顺序将`MYSET`添加到`CHARSETS_COMPLEX`的值中。即使对于简单的字符集，也需要这样做，否则`CMake`将无法识别`DDEFAULT_CHARSET=MYSET`。

1.  重新配置、重新编译和测试。

# 配置字符集

MySQL 8 提供了`--character-set-server`和`--collation-server`选项来配置字符集。默认字符集已从`latin1`更改为`UTF8`。`UTF8`是主导字符集，尽管在 MySQL 的先前版本中它不是默认字符集。随着这些全球性变化的接受，字符集和排序规则

现在基于`UTF8`；一个常见的原因是因为`UTF8`支持大约 21 种不同的语言，这使得系统提供多语言支持。在配置排序规则之前，请参考[`dev.mysql.com/doc/refman/8.0/en/show-collation.html`](https://dev.mysql.com/doc/refman/8.0/en/show-collation.html)上提供的排序规则列表。

# 语言选择

MySQL 8 默认使用英语语言的错误消息，但允许用户选择其他几种语言。例如，俄语、西班牙语、瑞典语等。MySQL 8 使用`lc_messages_dir`和`lc_messages`两个系统变量来管理错误消息的语言，并具有以下属性：

+   `lc_messages_dir`：这是一个系统变量，在服务器启动时设置。它是全局变量，因此通常由所有客户端在运行时使用。

+   `lc_messages`：此变量在全局和会话级别上都被使用。允许个别用户使用不同的语言来显示错误消息。例如，如果在服务器启动时设置了`en_US`，但如果要使用法语，则执行以下命令：

```sql
 SET lc_messages = 'fr_FR';
```

MySQL 8 服务器遵循以下三条错误消息文件规则：

+   MySQL 8 将在由两个系统变量`lc_messages_dir`和`lc_messages`构成的位置找到文件。例如，如果使用以下命令启动 MySQL 8，则`mysqld`将将区域设置`nl_NL`映射到荷兰语，并在`/usr/share/mysql/dutch`目录中搜索错误文件。MySQL 8 将所有语言文件存储在`MySQL8 Base Directory/share/mysql/LANGUAGE`目录中。默认情况下，语言文件位于 MySQL 基目录下的`share/mysql/LANGUAGE`目录中。

```sql
 mysqld --lc_messages_dir=/usr/share/mysql --lc_messages=nl_NL
```

+   如果目录下不存在消息文件，则 MySQL 8 将忽略`lc_messages`变量的值，并将`lc_messages_dir`变量的值视为要查找的位置。

+   如果 MySQL 8 服务器找不到消息文件，则它会在错误日志文件中显示一条消息，并对消息使用英语。

# MySQL8 的时区设置

MySQL 8 服务器以三种不同的方式管理时区：

+   系统时区：这由`system_time_zone`系统变量管理，可以通过`--timezone=timezone_name`或在执行 mysqld 之前使用`TZ`环境变量来设置。

+   服务器当前时区：这由`time_zone`系统变量管理。`time_zone`变量的默认值是`SYSTEM`，这意味着服务器时区与系统时区相同。MySQL 8 允许用户在启动时通过在选项文件中指定`default-time-zone='*timezone*'`来设置`time_zone`全局变量的值，并在运行时使用以下命令：

```sql
 mysql> SET GLOBAL time_zone = timezone;
```

+   预连接时区：这由`time_zone`变量管理，特定于连接到 MySQL 8 服务器的客户端。此变量从全局`time_zone`变量获取其初始值，但 MySQL 8 允许用户通过执行以下命令在运行时更改它：

```sql
 mysql> SET time_zone = timezone;
```

此会话变量影响区域特定值的显示和存储。例如，由`NOW()`和`CURTIME()`函数返回的值。另一方面，此变量不会影响以 UTC 格式显示和存储的值，例如`UTC_TIMESTAMP()`函数。

# 区域设置支持

MySQL 8 使用`lc_time_names`系统变量来控制语言，这将影响显示的日期、月份名称和缩写。`DATE_FORMAT()`、`DAYNAME()`和`MONTHNAME()`函数的输出取决于`lc_time_names`变量的值。首先浮现在脑海中的问题是，这些区域设置是在哪里定义的，我们如何获取它们？不用担心，参考[`www.iana.org/assignments/language-subtag-registry`](http://www.iana.org/assignments/language-subtag-registry)。所有区域设置都由**互联网编号分配机构**（**IANA**）以语言和地区缩写定义。默认情况下，MySQL 8 将`en_US`设置为系统变量的区域设置。用户可以在服务器启动时设置值，或者如果具有`SYSTEM_VARIABLES_ADMIN`或`SUPER`特权，则可以设置`GLOBAL`。MySQL 8 允许用户检查和设置其连接的区域设置。执行以下命令在您的工作站上检查区域设置：

```sql
mysql> SET NAMES 'utf8';
Query OK, 0 rows affected (0.09 sec)

mysql> SELECT @@lc_time_names;
+-----------------+
| @@lc_time_names |
+-----------------+
| en_US |
+-----------------+
1 row in set (0.00 sec)

mysql> SELECT DAYNAME('2010-01-01'), MONTHNAME('2010-01-01');
+-----------------------+-------------------------+
| DAYNAME('2010-01-01') | MONTHNAME('2010-01-01') |
+-----------------------+-------------------------+
| Friday | January |
+-----------------------+-------------------------+
1 row in set (0.00 sec)

mysql> SELECT DATE_FORMAT('2010-01-01','%W %a %M %b');
+-----------------------------------------+
| DATE_FORMAT('2010-01-01','%W %a %M %b') |
+-----------------------------------------+
| Friday Fri January Jan |
+-----------------------------------------+
1 row in set (0.00 sec)

mysql> SET lc_time_names = 'nl_NL';
Query OK, 0 rows affected (0.00 sec)

mysql> SELECT @@lc_time_names;
+-----------------+
| @@lc_time_names |
+-----------------+
| nl_NL |
+-----------------+
1 row in set (0.00 sec)

mysql> SELECT DAYNAME('2010-01-01'), MONTHNAME('2010-01-01');
+-----------------------+-------------------------+
| DAYNAME('2010-01-01') | MONTHNAME('2010-01-01') |
+-----------------------+-------------------------+
| vrijdag | januari |
+-----------------------+-------------------------+
1 row in set (0.00 sec)

mysql> SELECT DATE_FORMAT('2010-01-01','%W %a %M %b');
+-----------------------------------------+
| DATE_FORMAT('2010-01-01','%W %a %M %b') |
+-----------------------------------------+
| vrijdag vr januari jan |
+-----------------------------------------+
1 row in set (0.00 sec)</strong>
```

# MySQL 8 服务器日志

MySQL 8 服务器提供了以下不同类型的日志，使用户能够跟踪服务器在各种情况下的活动：

| **日志类型** | **写入日志的信息** |
| --- | --- |
| 错误日志 | 启动、运行或停止`mysqld`时遇到的问题 |
| 通用查询日志 | 已建立的客户端连接和从客户端接收到的语句 |
| 二进制日志 | 更改数据的语句（也用于复制） |
| 中继日志 | 从复制主服务器接收到的数据更改 |
| 慢查询日志 | 执行时间超过`long_query_time`秒的查询 |
| DDL 日志（元数据日志） | DDL 语句执行的元数据操作 |

您可以在[`dev.mysql.com/doc/refman/8.0/en/server-logs.html`](https://dev.mysql.com/doc/refman/8.0/en/server-logs.html)了解有关不同类型日志的更多信息。

MySQL 8 不会生成 MySQL 8 中的日志，除非在 Windows 中的错误日志中启用。默认情况下，MySQL 8 将所有日志存储在数据目录下的文件中。当我们谈论文件时，会有很多问题涌入我们的脑海，对吧？例如；文件的大小是多少？会生成多少个文件？我们如何刷新日志文件？MySQL 8 提供了各种配置来管理日志文件；我们将在本章的后面部分看到所有这些配置。另一个重要的问题是我们在哪里存储日志？在表中还是在文件中？以下是一些描述表与文件相比的优点的要点：

+   如果日志存储在表中，则其内容可通过 SQL 语句访问。这意味着用户可以执行带有所需条件的选择查询，以获得特定的输出。

+   任何远程用户都可以连接到数据库并获取日志的详细信息。

+   日志条目由标准格式管理。您可以使用以下命令检查日志表的结构：

通用日志的代码：

```sql
SHOW CREATE TABLE mysql.general_log;
```

慢查询日志的代码：

```sql
SHOW CREATE TABLE mysql.slow_log;
```

# 错误日志

此日志用于记录从 MySQL 8 启动到结束期间发生的错误、警告和注释等诊断消息。MySQL 8 为用户提供了各种配置和组件，以便根据其要求生成日志文件。当我们开始写入文件时，会有一些基本问题涌入脑海；我们要写什么？我们如何写？我们要写到哪里？让我们从第一个问题开始。MySQL 8 使用`log_error_verbosity`系统变量，并分配以下过滤选项来决定应将哪种类型的消息写入错误日志文件：

+   ``仅错误``

+   `错误和警告`

+   `错误，警告和注释`

要在目的地位置写入 MySQL 使用以下格式，其中时间戳取决于`log_timestamps`系统变量：

```sql
timestamp thread_id [severity] message 
```

写入日志文件后，首先要考虑的问题是，我们如何刷新这些日志？为此，MySQL 8 提供了三种方法：`FLUSH ERROR LOGS`，`FLUSH LOGS`或`mysqladmin flush-logs`。这些命令将关闭并重新打开正在写入的日志文件。当我们谈论如何写入以及在哪里写入时，有很多事情要理解。

# 组件配置

MySQL 8 使用`log_error_services`系统变量来控制错误日志组件。它允许用户通过分号分隔的方式定义多个组件以进行执行。在这里，组件将按照定义的顺序执行。用户可以在以下约束条件下更改此变量的值：

+   安装组件：要启用任何日志组件，我们必须首先使用此命令安装它，然后通过在`log_error_services`系统变量中列出该组件来使用该组件。按照以下命令添加`log_sink_syseventlog`组件：

```sql
 INSTALL COMPONENT 'file://component_log_sink_syseventlog';
 SET GLOBAL log_error_services = 'log_filter_internal; 
          log_sink_syseventlog';
```

执行安装命令后，MySQL 8 将注册该组件到`mysql.component`系统表中，以便在每次启动时加载。

+   卸载组件：要禁用任何日志组件，首先从`log_error_services`系统变量列表中删除它，然后使用此命令卸载它。执行以下命令以卸载组件：

```sql
 UNINSTALL COMPONENT 'file://component_log_sink_syseventlog';
```

要在每次启动时启用错误日志组件，请在`my.cnf`文件中定义它，或使用`SET_PERSIST`。当我们在`my.cnf`中定义它时，它将从下一次重新启动开始生效，而`SET_PERSIST`将立即生效。使用以下命令进行`SET_PERSIST`：

```sql
 SET PERSIST log_error_services = 'log_filter_internal; 
          log_sink_internal; 
          log_sink_json'; 
```

MySQL 8 还允许用户将错误日志写入系统日志：对于 Microsoft，请考虑事件日志，对于基于 Unix 的系统，请考虑 syslog。要将错误日志记录到系统`logfibf`中，配置`log_filter_internal`和系统日志写入器`log_sink_syseventlog`组件，并按照上述说明执行相同的指令。另一种方法是将 JSON 字符串写入日志文件配置`log_sink_json`组件。关于 JSON 写入器的一个有趣的点是，它将通过添加 NN（两位数）来管理文件命名约定。例如，将文件名视为`file_name.00.json`，`file_name.01.json`等。

# 默认错误日志目的地配置

错误日志可以写入日志文件或控制台。本节描述了如何在不同环境中配置错误日志的目的地。

# Windows 上的默认错误日志目的地

+   `--console`：如果给出此选项，则控制台将被视为默认目的地。在定义了两者的情况下，`--console`优先于`--log-error`。如果默认位置是控制台，那么 MySQL 8 服务器将`log_error`变量的值设置为`stderror`。

+   `--log-error`：如果未给出此选项，或者给出但未命名文件，则默认文件名为`host_name.err`，并且该文件将在数据目录中创建，除非指定了`--pid-fileoption`。如果在`–pid-file`选项中指定了文件名，则命名约定将是数据目录中带有`.err`后缀的**PID**文件基本名称。

# Unix 和类 Unix 系统上的默认错误日志目的地

在 Unix 系统中，Microsoft Windows 中提到的所有上述情况将由`–log_error`选项管理。

+   `--log-error`：如果未给出此选项，则默认目的地是控制台。如果未给出文件名，则与 Windows 一样，它将在数据目录中创建一个名为`host_name.err`的文件。用户可以在`mysqld`或`mysqld_safe`部分的选项文件中指定`–log-error`。

# 一般查询日志

一般查询日志是一个通用日志，用于记录`mysqld`执行的所有操作。在此日志中，文件语句按接收顺序编写，但执行顺序可能与接收顺序不同。它从客户端连接开始记录，并持续到断开连接。除了 SQL 命令，它还记录了`connection_type`，即协议客户端连接的方式，例如 TCP/IP、SSL、Socket 等。由于它记录了`mysqld`执行的大部分操作，当我们想要查找客户端发生了什么错误时，它非常有用。

默认情况下，此日志被禁用。我们可以使用**`--general_log[={0|1}]`**命令来启用它。当我们不指定任何参数或将 1 定义为参数时，表示启用一般查询日志，而 0 表示禁用日志。此外，我们可以使用`--general_log_file=file_name`命令指定日志文件名。如果命令未指定文件名，则 MySQL 8 将考虑默认名称为`host_name.log`。设置日志文件名对日志记录没有影响，如果日志目的地值不包含`FILE`。服务器重新启动和日志刷新不会导致生成新的一般查询日志文件；您必须使用`rename`（对于 Microsoft Windows）或`mv`（对于 Linux）命令来创建新文件。MySQL 8 提供了第二种在运行时重命名文件的方法，方法是使用以下命令禁用日志：

```sql
SET GLOBAL general_log = 'OFF';
```

禁用日志后，使用`ON`选项重命名日志文件并再次启用日志。同样，要在特定连接的运行时启用或禁用日志，请使用会话`sql_log_off`变量和`ON`或`OFF`选项。另一个选项是与一般日志文件对齐的，即`--log-output`。通过使用此选项，我们可以指定日志输出的目的地；这并不意味着日志已启用。

此命令提供了以下三种不同的选项：

+   `TABLE`：记录到表中

+   `FILE`：记录到文件中

+   `NONE`：不记录到表或文件中。如果存在`NONE`，则优先于任何其他指定符。

如果省略了`--log-output`选项，则默认值为文件。

# 二进制日志

二进制日志是一个文件，其中包含描述数据库事件的所有事件，例如表创建、数据更新和表中的删除。它不用于`SELECT`和`SHOW`语句，因为它不会更新任何数据。二进制日志写入会稍微降低数据库操作的性能，但它使用户能够使用复制设置和操作还原。二进制日志的主要目的是：

1.  **用于主从架构的复制**：基于二进制文件的复制，主服务器执行插入和更新操作，这些操作在二进制日志文件中反映出来。现在，从节点被配置为读取这些二进制文件，并且相同的事件在从服务器的二进制文件中执行，以便将数据复制到从服务器上。

1.  **数据恢复操作**：一旦备份被还原到数据库中，二进制日志的事件将被记录，并以重新执行的形式执行这些事件，从而使数据库从备份点更新到最新状态。

二进制日志默认启用，这表明 log_bin 系统变量设置为 ON。要禁用此日志，请在启动时使用`--skip-log-bin`或`--disable-log-bin`选项。要删除所有二进制日志文件，请使用 RESET MASTER 语句，或者使用`PURGE BINARY LOGS`删除其中的一部分。MySQL 8 服务器使用以下三种日志格式将信息记录到二进制日志文件中：

1.  **基于语句的日志记录**：通过使用`--binlog-format=STATEMENT`命令启动服务器来使用此格式。这主要是 SQL 语句的传播。

1.  **基于行的日志记录**：在服务器启动时使用`--binlog-format=ROW`启用基于行的日志记录。此格式指示行受到的影响。这是默认选项。

1.  **混合日志记录**：使用`--binlog-format=MIXED`选项启动 MySQL 8 以启用混合日志记录。在此模式下，默认情况下可用语句基础日志记录，并且在某些情况下 MySQL 8 将自动切换到基于行的日志记录。

MySQL 8 允许用户在全局和会话范围内在运行时更改格式。全局格式适用于所有客户端，而会话格式适用于单个客户端。以下分别设置全局和会话范围的格式：

```sql
mysql> SET GLOBAL binlog_format = 'STATEMENT';
mysql> SET SESSION binlog_format = 'STATEMENT';
```

有两种特殊情况下我们无法更改格式：

+   在存储过程或函数中

+   在设置为行格式并且临时表处于打开状态的情况下

MySQL 8 具有`--binlog-row-event-max-size`变量，用于以字节为单位控制二进制日志文件的大小。将此变量的值分配为 256 的倍数；此选项的默认值为 8192。MySQL 8 的各个存储引擎都有其自己的日志记录能力。如果存储引擎支持基于行的日志记录，则称为**行日志**能力，如果存储引擎支持基于语句的日志记录，则称为**语句日志**能力。有关存储引擎日志记录能力的更多信息，请参考下表。

| 存储引擎 | 支持行日志记录 | 支持语句日志记录 |
| --- | --- | --- |
| `ARCHIVE` | 是 | 是 |
| `BLACKHOLE` | 是 | 是 |
| `CSV` | 是 | 是 |
| `EXAMPLE` | 是 | 否 |
| `FEDERATED` | 是 | 是 |
| `HEAP` | 是 | 是 |
| `InnoDB` | 是 | 当事务隔离级别为`REPEATABLE`、`READ`或`SERIALIZABLE`时为是；否则为否。 |
| `MyISAM` | 是 | 是 |
| `MERGE` | 是 | 是 |
| `NDB` | 是 | 否 |

如本节所述，二进制日志将根据语句类型（安全、不安全或二进制注入）、日志格式（`ROW`、`STATEMENT`或`MIXED`）以及存储引擎的日志功能（行可用、语句可用、两者都可用或两者都不可用）进行工作。要了解二进制日志记录的所有可能情况，请参考此链接中给出的表格：[`dev.mysql.com/doc/refman/8.0/en/binary-log-mixed.html`](https://dev.mysql.com/doc/refman/8.0/en/binary-log-mixed.html)。

# 慢查询日志

慢查询日志用于记录执行时间长的 SQL 语句。MySQL 8 为慢查询的时间配置定义了以下两个系统变量：

+   `long_query_time`：用于定义查询执行的理想时间。如果 SQL 语句的执行时间超过此时间，则被视为慢查询，并将语句记录到日志文件中。默认值为 10 秒。

+   `min_examined_row_limit`：执行每个查询所需的最短时间。默认值为 0 秒。

MySQL 8 不会将获取锁的初始时间计入执行时间，并且在所有锁释放并完成查询执行后将慢查询日志返回到文件中。当启动 MySQL 8 时，默认情况下禁用慢查询日志；要启动此日志，请使用`slow_query_log[={0|1}]`命令，其中`0`表示禁用慢查询日志，1 或无参数用于启用它。要记录不使用索引的管理语句和查询，请使用**`log_slow_admin_statements`**和**`log_queries_not_using_indexes`**变量。这里，管理语句包括`ALTER TABLE`、`ANALYZE TABLE`、`CHECK TABLE`、`CREATE INDEX`、`DROP INDEX`、`OPTIMIZE TABLE`和`REPAIR TABLE`。MySQL 8 允许用户使用`--slow_query_log_file=file_name`命令指定日志文件的名称。如果未指定文件名，则 MySQL 8 将在数据目录中使用`host_name-slow.log`命名约定创建文件。要将最少的信息写入此日志文件，请使用`--log-short-format`选项。

上述所有描述的参数由 MySQL 8 按以下顺序控制：

1.  查询必须不是管理语句，或者`log_slow_admin_statements`必须已启用

1.  查询必须至少花费`long_query_time`秒，或者启用了`log_queries_not_using_indexes`，并且查询必须没有使用索引进行行查找

1.  查询必须至少检查`min_examined_row_limit`行

1.  查询不应根据`log_throttle_queries_not_using_indexes`设置被抑制

`--log-output`选项也适用于此日志文件，并具有与通用日志相同的实现和效果。

# DDL 日志

正如名称所示，此日志文件用于记录所有与 DDL 语句执行相关的详细信息。MySQL 8 使用此日志文件来从在元数据操作执行期间发生的崩溃中恢复。让我们举一个例子来理解不同的情况：

+   **删除表 t1，t2**：我们必须确保 t1 和 t2 表都被删除

当我们执行任何 DDL 语句时，这些操作的记录将被写入 MySQL 8 数据目录下的`ddl_log.log`文件中。该文件是一个二进制文件，不是人类可读的格式。用户不允许更新此日志文件的内容。在 MySQL 服务器的正常执行中不需要记录元数据语句；只有在需要时才启用它。

# 服务器日志维护

为了维护日志文件，我们必须定期清理以管理磁盘空间。对于基于 RPM 的 Linux 系统，`mysql-log-rotate`脚本会自动提供。对于其他系统，没有这样的脚本，因此我们必须自己安装一个简短的脚本来管理日志文件。MySQL 8 提供了`expire_logs_days`系统变量，用于管理二进制日志文件。使用此变量，二进制日志文件将在指定期限后自动删除。

此变量的默认值为 30 天；您可以通过配置更改其值。二进制日志文件在服务器启动时或日志刷新时删除。在复制的情况下，您还可以使用`binlog_expire_logs_seconds`系统变量来管理主服务器和从服务器的日志。日志刷新执行以下任务：

+   如果启用了一般查询日志或慢查询日志到日志文件，服务器将关闭并重新打开查询日志文件

+   如果启用了二进制日志记录，服务器将关闭当前的二进制日志文件，并打开下一个序列号的新日志文件

+   如果服务器是使用`--log-error`选项启动的，以导致错误日志被写入文件，服务器将关闭并重新打开日志文件

在生成新的日志文件之前备份或重命名旧的日志文件，可以在 Unix 系统中使用`mv`（移动）命令，在 Windows 中使用`rename`函数。对于一般查询和慢查询日志文件，可以通过使用以下命令禁用日志来重命名文件：

```sql
SET GLOBAL general_log = 'OFF';
```

重命名日志文件后，使用以下命令启用日志：

```sql
SET GLOBAL general_log = 'ON';
```

# 总结

这对于任何 MySQL 8 用户来说都是一个有趣的章节，不是吗？在本章中，我们了解了 MySQL 8 如何管理不同的日志文件，以及在什么时候使用哪个日志文件。同时，我们还涵盖了许多管理功能，例如全球化、系统数据数据库和组件和插件配置，并解释了如何在单台机器上运行多个实例。本章的后半部分涵盖了日志维护。

接下来，我们将为您提供有关存储引擎的信息，例如不同类型的存储引擎是什么，哪种适合您的应用程序，以及如何为 MySQL 8 创建自定义存储引擎。
