# MySQL8 秘籍（二）

> 原文：[`zh.annas-archive.org/md5/F4A043A5A2DBFB9A7ADE5DAA21AA8E7F`](https://zh.annas-archive.org/md5/F4A043A5A2DBFB9A7ADE5DAA21AA8E7F)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三章：使用 MySQL（高级）

在本章中，我们将涵盖以下配方：

+   使用 JSON

+   公共表达式（CTE）

+   生成的列

+   窗口函数

# 介绍

在本章中，您将了解 MySQL 的新引入功能。

# 使用 JSON

正如您在上一章中所看到的，要在 MySQL 中存储数据，您必须定义数据库和表结构（模式），这是一个重大的限制。为了应对这一点，从 MySQL 5.7 开始，MySQL 支持**JavaScript 对象表示**（**JSON**）数据类型。以前没有单独的数据类型，它被存储为字符串。新的 JSON 数据类型提供了 JSON 文档的自动验证和优化的存储格式。

JSON 文档以二进制格式存储，这使得以下操作成为可能：

+   快速读取文档元素

+   当服务器再次读取 JSON 时，不需要从文本表示中解析值

+   直接通过键或数组索引查找子对象或嵌套值，而无需读取文档中它们之前或之后的所有值

# 如何做...

假设您想要存储有关员工的更多详细信息；您可以使用 JSON 保存它们：

```sql
CREATE TABLE emp_details( 
  emp_no int primary key, 
  details json 
);
```

# 插入 JSON

```sql
INSERT INTO emp_details(emp_no, details)
VALUES ('1',
'{ "location": "IN", "phone": "+11800000000", "email": "abc@example.com", "address": { "line1": "abc", "line2": "xyz street", "city": "Bangalore", "pin": "560103"} }'
);
```

# 检索 JSON

您可以使用`->`和`->>`运算符检索 JSON 列的字段：

```sql
mysql> SELECT emp_no, details->'$.address.pin' pin FROM emp_details;
+--------+----------+
| emp_no | pin      |
+--------+----------+
| 1      | "560103" |
+--------+----------+
1 row in set (0.00 sec)
```

要检索没有引号的数据，请使用`->>`运算符：

```sql
mysql> SELECT emp_no, details->>'$.address.pin' pin FROM emp_details;
+--------+--------+
| emp_no | pin    |
+--------+--------+
| 1      | 560103 |
+--------+--------+
1 row in set (0.00 sec)
```

# JSON 函数

MySQL 提供了许多处理 JSON 数据的函数。让我们看看最常用的函数。

# 漂亮的视图

要以漂亮的格式显示 JSON 值，请使用`JSON_PRETTY()`函数：

```sql
mysql> SELECT emp_no, JSON_PRETTY(details) FROM emp_details \G
*************************** 1\. row ***************************
 emp_no: 1
JSON_PRETTY(details): {
 "email": "abc@example.com",
 "phone": "+11800000000",
 "address": {
 "pin": "560103",
 "city": "Bangalore",
 "line1": "abc",
 "line2": "xyz street"
 },
 "location": "IN"
}
1 row in set (0.00 sec)
```

不漂亮的：

```sql
mysql> SELECT emp_no, details FROM emp_details \G
*************************** 1\. row ***************************
 emp_no: 1
details: {"email": "abc@example.com", "phone": "+11800000000", "address": {"pin": "560100", "city": "Bangalore", "line1": "abc", "line2": "xyz street"}, "location": "IN"}
1 row in set (0.00 sec)
```

# 搜索

您可以在`WHERE`子句中使用`col->>path`运算符引用 JSON 列：

```sql
mysql> SELECT emp_no FROM emp_details WHERE details->>'$.address.pin'="560103";
+--------+
| emp_no |
+--------+
| 1      |
+--------+
1 row in set (0.00 sec)
```

您还可以使用`JSON_CONTAINS`函数搜索数据。如果找到数据，则返回`1`，否则返回`0`：

```sql
mysql> SELECT JSON_CONTAINS(details->>'$.address.pin', "560103") FROM emp_details;
+----------------------------------------------------+
| JSON_CONTAINS(details->>'$.address.pin', "560103") |
+----------------------------------------------------+
| 1                                                  |
+----------------------------------------------------+
1 row in set (0.00 sec)
```

如何搜索键？假设您想要检查`address.line1`是否存在：

```sql
mysql> SELECT JSON_CONTAINS_PATH(details, 'one', "$.address.line1") FROM emp_details;
+--------------------------------------------------------------------------+
| JSON_CONTAINS_PATH(details, 'one', "$.address.line1")                    |
+--------------------------------------------------------------------------+
| 1                                                                        |
+--------------------------------------------------------------------------+
1 row in set (0.01 sec)
```

在这里，`one`表示至少应该存在一个键。假设您想要检查`address.line1`或`address.line2`是否存在：

```sql
mysql> SELECT JSON_CONTAINS_PATH(details, 'one', "$.address.line1", "$.address.line5") FROM emp_details;
+--------------------------------------------------------------------------+
| JSON_CONTAINS_PATH(details, 'one', "$.address.line1", "$.address.line2") |
+--------------------------------------------------------------------------+
| 1                                                                        |
+--------------------------------------------------------------------------+
```

如果要检查`address.line1`和`address.line5`是否都存在，可以使用`and`而不是`one`：

```sql
mysql> SELECT JSON_CONTAINS_PATH(details, 'all', "$.address.line1", "$.address.line5") FROM emp_details;
+--------------------------------------------------------------------------+
| JSON_CONTAINS_PATH(details, 'all', "$.address.line1", "$.address.line5") |
+--------------------------------------------------------------------------+
| 0                                                                        |
+--------------------------------------------------------------------------+
1 row in set (0.00 sec)
```

# 修改

您可以使用三种不同的函数修改数据：`JSON_SET()`，`JSON_INSERT()`，`JSON_REPLACE()`。在 MySQL 8 之前，我们需要对整个列进行完全更新，这不是最佳方式：

+   `JSON_SET`: 替换现有值并添加不存在的值。

假设您想要替换员工的邮政编码并添加昵称的详细信息：

```sql
mysql> UPDATE 
    emp_details 
SET 
    details = JSON_SET(details, "$.address.pin", "560100", "$.nickname", "kai")
WHERE 
    emp_no = 1;
Query OK, 1 row affected (0.03 sec)
Rows matched: 1 Changed: 1 Warnings: 0
```

+   `JSON_INSERT()`: 插入值而不替换现有值

假设您想要添加一个新列而不更新现有值；您可以使用`JSON_INSERT()`：

```sql
mysql> UPDATE emp_details SET details=JSON_INSERT(details, "$.address.pin", "560132", "$.address.line4", "A Wing") WHERE emp_no = 1;
Query OK, 1 row affected (0.00 sec)
Rows matched: 1 Changed: 1 Warnings: 0
```

在这种情况下，`pin`不会被更新；只会添加一个新的`address.line4`字段。

+   `JSON_REPLACE()`: 仅替换现有值

假设您只想替换字段而不添加新字段：

```sql
mysql> UPDATE emp_details SET details=JSON_REPLACE(details, "$.address.pin", "560132", "$.address.line5", "Landmark") WHERE 
emp_no = 1;
Query OK, 1 row affected (0.04 sec)
Rows matched: 1 Changed: 1 Warnings: 0
```

在这种情况下，`line5`不会被添加。只有`pin`会被更新。

# 删除

`JSON_REMOVE`从 JSON 文档中删除数据。

假设您不再需要地址中的`line5`：

```sql
mysql> UPDATE emp_details SET details=JSON_REMOVE(details, "$.address.line5") WHERE emp_no = 1;
Query OK, 1 row affected (0.04 sec)
Rows matched: 1 Changed: 1 Warnings: 0
```

# 其他函数

其他一些函数如下：

+   `JSON_KEYS()`: 获取 JSON 文档中的所有键：

```sql
mysql> SELECT JSON_KEYS(details) FROM emp_details WHERE emp_no = 1;
*************************** 1\. row ***************************
JSON_KEYS(details): ["email", "phone", "address", "nickname", "locatation"]
```

+   `JSON_LENGTH()`: 给出 JSON 文档中元素的数量：

```sql
mysql> SELECT JSON_LENGTH(details) FROM emp_details WHERE emp_no = 1;
*************************** 1\. row ***************************
JSON_LENGTH(details): 5
```

# 参见

您可以在[`dev.mysql.com/doc/refman/8.0/en/json-function-reference.html`](https://dev.mysql.com/doc/refman/8.0/en/json-function-reference.html)查看完整的函数列表。

# 公共表达式（CTE）

MySQL 8 支持公共表达式，包括非递归和递归。

公共表达式使得可以使用命名的临时结果集，通过允许在`SELECT`语句和某些其他语句之前使用`WITH`子句。

**为什么需要 CTE？**在同一查询中不可能引用派生表两次。因此，派生表会被评估两次或多次，这表明存在严重的性能问题。使用 CTE，子查询只评估一次。

# 如何做...

递归和非递归 CTE 将在以下部分中进行讨论。

# 非递归 CTE

**公共表达式**（**CTE**）就像派生表一样，但其声明放在查询块之前，而不是在`FROM`子句中。

**派生表**

```sql
SELECT... FROM (subquery) AS derived, t1 ...
```

**CTE**

```sql
SELECT... WITH derived AS (subquery) SELECT ... FROM derived, t1 ...
```

CTE 可以在`SELECT`/`UPDATE`/`DELETE`之前，包括子查询`WITH`派生`AS`（子查询），例如：

```sql
DELETE FROM t1 WHERE t1.a IN (SELECT b FROM derived);
```

假设您想要找出每年薪水相对于上一年的百分比增长。没有 CTE，您需要编写两个子查询，它们本质上是相同的。MySQL 不足够聪明，无法检测到这一点，并且子查询会执行两次：

```sql
mysql> SELECT 
    q1.year, 
    q2.year AS next_year, 
    q1.sum, 
    q2.sum AS next_sum, 
    100*(q2.sum-q1.sum)/q1.sum AS pct 
FROM 
    (SELECT year(from_date) as year, sum(salary) as sum FROM salaries GROUP BY year) AS q1,             (SELECT year(from_date) as year, sum(salary) as sum FROM salaries GROUP BY year) AS q2 
WHERE q1.year = q2.year-1;
+------+-----------+-------------+-------------+----------+
| year | next_year | sum         | next_sum    | pct      |
+------+-----------+-------------+-------------+----------+
| 1985 |      1986 | 972864875   | 2052895941  | 111.0155 |
| 1986 |      1987 | 2052895941  | 3156881054  | 53.7770  |
| 1987 |      1988 | 3156881054  | 4295598688  | 36.0710  |
| 1988 |      1989 | 4295598688  | 5454260439  | 26.9732  |
| 1989 |      1990 | 5454260439  | 6626146391  | 21.4857  |
| 1990 |      1991 | 6626146391  | 7798804412  | 17.6974  |
| 1991 |      1992 | 7798804412  | 9027872610  | 15.7597  |
| 1992 |      1993 | 9027872610  | 10215059054 | 13.1502  |
| 1993 |      1994 | 10215059054 | 11429450113 | 11.8882  |
| 1994 |      1995 | 11429450113 | 12638817464 | 10.5812  |
| 1995 |      1996 | 12638817464 | 13888587737 | 9.8883   |
| 1996 |      1997 | 13888587737 | 15056011781 | 8.4056   |
| 1997 |      1998 | 15056011781 | 16220495471 | 7.7343   |
| 1998 |      1999 | 16220495471 | 17360258862 | 7.0267   |
| 1999 |      2000 | 17360258862 | 17535667603 | 1.0104   |
| 2000 |      2001 | 17535667603 | 17507737308 | -0.1593  |
| 2001 |      2002 | 17507737308 | 10243358658 | -41.4924 |
+------+-----------+-------------+-------------+----------+
17 rows in set (3.22 sec)
```

使用非递归 CTE，派生查询仅执行一次并被重用：

```sql
mysql> 
WITH CTE AS 
    (SELECT year(from_date) AS year, SUM(salary) AS sum FROM salaries GROUP BY year) 
SELECT 
    q1.year, q2.year as next_year, q1.sum, q2.sum as next_sum, 100*(q2.sum-q1.sum)/q1.sum as pct FROM 
    CTE AS q1, 
    CTE AS q2 
WHERE 
    q1.year = q2.year-1;
+------+-----------+-------------+-------------+----------+
| year | next_year | sum         | next_sum    | pct      |
+------+-----------+-------------+-------------+----------+
| 1985 |      1986 | 972864875   | 2052895941  | 111.0155 |
| 1986 |      1987 | 2052895941  | 3156881054  | 53.7770  |
| 1987 |      1988 | 3156881054  | 4295598688  | 36.0710  |
| 1988 |      1989 | 4295598688  | 5454260439  | 26.9732  |
| 1989 |      1990 | 5454260439  | 6626146391  | 21.4857  |
| 1990 |      1991 | 6626146391  | 7798804412  | 17.6974  |
| 1991 |      1992 | 7798804412  | 9027872610  | 15.7597  |
| 1992 |      1993 | 9027872610  | 10215059054 | 13.1502  |
| 1993 |      1994 | 10215059054 | 11429450113 | 11.8882  |
| 1994 |      1995 | 11429450113 | 12638817464 | 10.5812  |
| 1995 |      1996 | 12638817464 | 13888587737 | 9.8883   |
| 1996 |      1997 | 13888587737 | 15056011781 | 8.4056   |
```

```sql
| 1997 |      1998 | 15056011781 | 16220495471 | 7.7343   |
| 1998 |      1999 | 16220495471 | 17360258862 | 7.0267   |
| 1999 |      2000 | 17360258862 | 17535667603 | 1.0104   |
| 2000 |      2001 | 17535667603 | 17507737308 | -0.1593  |
| 2001 |      2002 | 17507737308 | 10243358658 | -41.4924 |
+------+-----------+-------------+-------------+----------+
17 rows in set (1.63 sec)
```

您可能会注意到，使用 CTE，结果相同，查询时间提高了 50％；可读性很好，并且可以多次引用。

派生查询不能引用其他派生查询：

```sql
SELECT ...
 FROM (SELECT ... FROM ...) AS d1, (SELECT ... FROM d1 ...) AS d2 ...
ERROR: 1146 (42S02): Table ‘db.d1’ doesn’t exist 
```

CTEs 可以引用其他 CTEs：

```sql
WITH d1 AS (SELECT ... FROM ...), d2 AS (SELECT ... FROM d1 ...) 
SELECT
 FROM d1, d2 ... 
```

# 递归 CTE

递归 CTE 是一个带有引用自身名称的子查询的 CTE。`WITH`子句必须以`WITH RECURSIVE`开头。递归 CTE 子查询有两部分，种子查询和递归查询，由`UNION [ALL]`或`UNION DISTINCT`分隔。

种子`SELECT`执行一次以创建初始数据子集；递归`SELECT`被重复执行以返回数据子集，直到获得完整的结果集。当迭代不再生成任何新行时，递归停止。这对于深入研究层次结构（父/子或部分/子部分）非常有用：

```sql
WITH RECURSIVE cte AS
(SELECT ... FROM table_name /* seed SELECT */ 
UNION ALL 
SELECT ... FROM cte, table_name) /* "recursive" SELECT */ 
SELECT ... FROM cte;
```

假设您想打印从`1`到`5`的所有数字：

```sql
mysql> WITH RECURSIVE cte (n) AS 
( SELECT 1 /* seed query */
  UNION ALL 
  SELECT n + 1 FROM cte WHERE n < 5 /* recursive query */
) 
SELECT * FROM cte;
+---+
| n |
+---+
| 1 |
| 2 |
| 3 |
| 4 |
| 5 |
+---+
5 rows in set (0.00 sec)
```

在每次迭代中，`SELECT`生成一个新值的行，该值比上一行集合中的`n`值多 1。第一次迭代在初始行集（1）上操作，并产生*1+1=2*；第二次迭代在第一次迭代的行集（2）上操作，并产生*2+1=3*；依此类推。这将持续到递归结束，当`n`不再小于`5`时。

假设您想要对分层数据进行遍历，以生成每个员工的管理链的组织结构图（即从 CEO 到员工的路径）。使用递归 CTE！

创建一个带有`manager_id`的测试表：

```sql
mysql> CREATE TABLE employees_mgr (
 id INT PRIMARY KEY NOT NULL,
 name VARCHAR(100) NOT NULL,
 manager_id INT NULL,
 INDEX (manager_id),
FOREIGN KEY (manager_id) REFERENCES employees_mgr (id)
);
```

插入示例数据：

```sql
mysql> INSERT INTO employees_mgr VALUES
(333, "Yasmina", NULL), # Yasmina is the CEO (manager_id is NULL)
(198, "John", 333), # John has ID 198 and reports to 333 (Yasmina)
(692, "Tarek", 333),
(29, "Pedro", 198),
(4610, "Sarah", 29),
(72, "Pierre", 29),
(123, "Adil", 692);
```

执行递归 CTE：

```sql
mysql> WITH RECURSIVE employee_paths (id, name, path) AS
(
 SELECT id, name, CAST(id AS CHAR(200))
 FROM employees_mgr
 WHERE manager_id IS NULL
 UNION ALL
 SELECT e.id, e.name, CONCAT(ep.path, ',', e.id)
 FROM employee_paths AS ep JOIN employees_mgr AS e
 ON ep.id = e.manager_id
)
SELECT * FROM employee_paths ORDER BY path;
```

它产生以下结果：

```sql
+------+---------+-----------------+
| id   | name    | path            |
+------+---------+-----------------+
| 333  | Yasmina | 333             |
| 198  | John    | 333,198         |
| 29   | Pedro   | 333,198,29      |
| 4610 | Sarah   | 333,198,29,4610 |
| 72   | Pierre  | 333,198,29,72   |
| 692  | Tarek   | 333,692         |
| 123  | Adil    | 333,692,123     |
+------+---------+-----------------+
7 rows in set (0.00 sec)
```

`WITH RECURSIVE employee_paths（id，name，path）AS`是 CTE 的名称，列为（`id`，`name`，`path`）。

`SELECT id，name，CAST(id AS CHAR（200））FROM employees_mgr WHERE manager_id IS NULL`是选择 CEO 的种子查询（CEO 没有经理）。

`SELECT e.id，e.name，CONCAT(ep.path，'，'，e.id) FROM employee_paths AS ep JOIN employees_mgr AS e ON ep.id = e.manager_id`是递归查询。

递归查询生成的每一行都会找到直接向以前行生成的员工汇报的所有员工。对于这样的员工，该行包括员工 ID，名称和员工管理链。该链是经理的链，员工 ID 添加到末尾。

# 生成列

生成列也称为虚拟列或计算列。生成列的值是从列定义中包含的表达式计算出来的。有两种类型的生成列：

+   **虚拟**：当从表中读取记录时，该列将在读取时动态计算

+   **存储**：当在表中写入新记录时，将计算该列并将其存储在表中作为常规列

虚拟生成列比存储生成列更有用，因为虚拟列不占用任何存储空间。您可以使用触发器模拟存储生成列的行为。

# 如何做...

假设您的应用程序在从`employees`表中检索数据时使用`full_name`作为`concat('first_name'，' '，'last_name')`，而不是使用表达式，您可以使用虚拟列，该列在读取时计算`full_name`。您可以在表达式后面添加另一列：

```sql
mysql> CREATE TABLE `employees` (
  `emp_no` int(11) NOT NULL,
  `birth_date` date NOT NULL,
  `first_name` varchar(14) NOT NULL,
  `last_name` varchar(16) NOT NULL,
  `gender` enum('M','F') NOT NULL,
  `hire_date` date NOT NULL,
 `full_name` VARCHAR(30) AS (CONCAT(first_name,' ',last_name)),
  PRIMARY KEY (`emp_no`),
  KEY `name` (`first_name`,`last_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

请注意，您应该根据虚拟列修改插入语句。您可以选择使用完整的插入，如下所示：

```sql
mysql> INSERT INTO employees (emp_no, birth_date, first_name, last_name, gender, hire_date) VALUES (123456, '1987-10-02', 'ABC' , 'XYZ', 'F', '2008-07-28');
```

如果您想在`INSERT`语句中包含`full_name`，可以将其指定为`DEFAULT`。所有其他值都会抛出`ERROR 3105 (HY000):`错误。在`employees`表中指定生成列`full_name`的值是不允许的：

```sql
mysql> INSERT INTO employees (emp_no, birth_date, first_name, last_name, gender, hire_date, full_name) VALUES (123456, '1987-10-02', 'ABC' , 'XYZ', 'F', '2008-07-28', DEFAULT);
```

您可以直接从`employees`表中选择`full_name`：

```sql
mysql> SELECT * FROM employees WHERE emp_no=123456;
+--------+------------+------------+-----------+--------+------------+-----------+
| emp_no | birth_date | first_name | last_name | gender | hire_date  | full_name |
+--------+------------+------------+-----------+--------+------------+-----------+
| 123456 | 1987-10-02 | ABC        | XYZ       | F      | 2017-11-23 | ABC XYZ   |
+--------+------------+------------+-----------+--------+------------+-----------+
1 row in set (0.00 sec)
```

如果您已经创建了表并希望添加新的生成列，请执行 ALTER TABLE 语句，这将在*第十章* *表维护*中详细介绍

例子：

```sql
mysql> ALTER TABLE employees ADD hire_date_year YEAR AS (YEAR(hire_date)) VIRTUAL;
```

请参考[`dev.mysql.com/doc/refman/8.0/en/create-table-generated-columns.html`](https://dev.mysql.com/doc/refman/8.0/en/create-table-generated-columns.html)了解更多关于生成列的信息。您将在第十三章 *性能调优*中了解虚拟列的其他用途，在*添加索引*和*使用生成列为 JSON 添加索引*部分。

# 窗口函数

通过使用窗口函数，您可以对与该行相关的行执行计算。这是通过使用`OVER`和`WINDOW`子句来实现的。

以下是您可以进行的计算列表：

+   `CUME_DIST()`: 累积分布值

+   `DENSE_RANK()`: 在其分区内当前行的排名，没有间隙

+   `FIRST_VALUE()`: 窗口帧的第一行的参数值

+   `LAG()`: 分区内当前行的前一行的参数值

+   `LAST_VALUE()`: 窗口帧的第一行的参数值

+   `LEAD()`: 分区内当前行的后一行的参数值

+   `NTH_VALUE()`: 窗口帧的第*n*行的参数值

+   `NTILE()`: 在其分区内当前行的桶编号

+   `PERCENT_RANK()`: 百分比排名值

+   `RANK()`: 在其分区内当前行的排名，有间隙

+   `ROW_NUMBER()`: 在其分区内当前行的编号

# 如何做...

窗口函数可以以各种方式使用。让我们在以下部分了解每一个。为了使这些示例起作用，您需要添加 hire_date_year 虚拟列

```sql
mysql> ALTER TABLE employees ADD hire_date_year YEAR AS (YEAR(hire_date)) VIRTUAL;
```

# 行号

您可以为每一行获取行号以对结果进行排名：

```sql
mysql> SELECT CONCAT(first_name, " ", last_name) AS full_name, salary, ROW_NUMBER() OVER(ORDER BY salary DESC) AS 'Rank'  FROM employees JOIN salaries ON salaries.emp_no=employees.emp_no LIMIT 10;
+-------------------+--------+------+
| full_name         | salary | Rank |
+-------------------+--------+------+
| Tokuyasu Pesch    | 158220 |    1 |
| Tokuyasu Pesch    | 157821 |    2 |
| Honesty Mukaidono | 156286 |    3 |
| Xiahua Whitcomb   | 155709 |    4 |
| Sanjai Luders     | 155513 |    5 |
| Tsutomu Alameldin | 155377 |    6 |
| Tsutomu Alameldin | 155190 |    7 |
| Tsutomu Alameldin | 154888 |    8 |
| Tsutomu Alameldin | 154885 |    9 |
| Willard Baca      | 154459 |   10 |
+-------------------+--------+------+
10 rows in set (6.24 sec)
```

# 分区结果

您可以在`OVER`子句中对结果进行分区。假设您想要找出每年的薪水排名；可以按如下方式完成：

```sql
mysql> SELECT hire_date_year, salary, ROW_NUMBER() OVER(PARTITION BY hire_date_year ORDER BY salary DESC) AS 'Rank' FROM employees JOIN salaries ON salaries.emp_no=employees.emp_no ORDER BY salary DESC LIMIT 10;
+----------------+--------+------+
| hire_date_year | salary | Rank |
+----------------+--------+------+
|           1985 | 158220 |    1 |
|           1985 | 157821 |    2 |
|           1986 | 156286 |    1 |
|           1985 | 155709 |    3 |
|           1987 | 155513 |    1 |
|           1985 | 155377 |    4 |
|           1985 | 155190 |    5 |
|           1985 | 154888 |    6 |
|           1985 | 154885 |    7 |
|           1985 | 154459 |    8 |
+----------------+--------+------+
10 rows in set (8.04 sec)
```

您可以注意到，`1986`年和`1987`年的排名发生了变化，但`1985`年的排名保持不变。

# 命名窗口

您可以命名一个窗口，并且可以根据需要多次使用它，而不是每次重新定义它：

```sql
mysql> SELECT hire_date_year, salary, RANK() OVER w AS 'Rank' FROM employees join salaries ON salaries.emp_no=employees.emp_no WINDOW w AS (PARTITION BY hire_date_year ORDER BY salary DESC) ORDER BY salary DESC LIMIT 10;
+----------------+--------+------+
| hire_date_year | salary | Rank |
+----------------+--------+------+
|           1985 | 158220 |    1 |
|           1985 | 157821 |    2 |
|           1986 | 156286 |    1 |
|           1985 | 155709 |    3 |
|           1987 | 155513 |    1 |
|           1985 | 155377 |    4 |
|           1985 | 155190 |    5 |
|           1985 | 154888 |    6 |
|           1985 | 154885 |    7 |
|           1985 | 154459 |    8 |
+----------------+--------+------+
10 rows in set (8.52 sec)
```

# 第一个、最后一个和第 n 个值

您可以在窗口结果中选择第一个、最后一个和第 n 个值。如果行不存在，则返回`NULL`值。

假设您想要从窗口中找到第一个、最后一个和第三个值：

```sql
mysql> SELECT hire_date_year, salary, RANK() OVER w AS 'Rank', 
FIRST_VALUE(salary) OVER w AS 'first', 
NTH_VALUE(salary, 3) OVER w AS 'third', 
LAST_VALUE(salary) OVER w AS 'last' 
FROM employees join salaries ON salaries.emp_no=employees.emp_no 
WINDOW w AS (PARTITION BY hire_date_year ORDER BY salary DESC) 
ORDER BY salary DESC LIMIT 10;
+----------------+--------+------+--------+--------+--------+
| hire_date_year | salary | Rank | first  | third  | last   |
+----------------+--------+------+--------+--------+--------+
|           1985 | 158220 |    1 | 158220 |   NULL | 158220 |
|           1985 | 157821 |    2 | 158220 |   NULL | 157821 |
|           1986 | 156286 |    1 | 156286 |   NULL | 156286 |
|           1985 | 155709 |    3 | 158220 | 155709 | 155709 |
|           1987 | 155513 |    1 | 155513 |   NULL | 155513 |
|           1985 | 155377 |    4 | 158220 | 155709 | 155377 |
|           1985 | 155190 |    5 | 158220 | 155709 | 155190 |
|           1985 | 154888 |    6 | 158220 | 155709 | 154888 |
|           1985 | 154885 |    7 | 158220 | 155709 | 154885 |
|           1985 | 154459 |    8 | 158220 | 155709 | 154459 |
+----------------+--------+------+--------+--------+--------+
10 rows in set (12.88 sec)
```

要了解窗口函数的其他用例，请参考[`mysqlserverteam.com/mysql-8-0-2-introducing-window-functions`](https://mysqlserverteam.com/mysql-8-0-2-introducing-window-functions)和[`dev.mysql.com/doc/refman/8.0/en/window-function-descriptions.html#function_row-number`](https://dev.mysql.com/doc/refman/8.0/en/window-function-descriptions.html#function_row-number)。


# 第四章：配置 MySQL

在本章中，我们将涵盖以下配方：

+   使用配置文件

+   使用全局和会话变量

+   使用启动脚本的参数

+   配置参数

+   更改数据目录

# 介绍

MySQL 有两种类型的参数：

+   **静态**，在重新启动 MySQL 服务器后生效

+   **动态**，可以在不重新启动 MySQL 服务器的情况下进行更改

变量可以通过以下方式设置：

+   **配置文件**：MySQL 有一个配置文件，我们可以在其中指定数据的位置，MySQL 可以使用的内存，以及各种其他参数。

+   **启动脚本**：您可以直接将参数传递给`mysqld`进程。它仅在服务器的该调用中生效。

+   **使用 SET 命令**（仅动态变量）：这将持续到服务器重新启动。您还需要在配置文件中设置变量，以使更改在重新启动时持久。使更改持久的另一种方法是在变量名称之前加上`PERSIST`关键字或`@@persist`。

# 使用配置文件

默认配置文件为`/etc/my.cnf`（在 Red Hat 和 CentOS 系统上）和`/etc/mysql/my.cnf`（Debian 系统）。在您喜欢的编辑器中打开文件并根据需要修改参数。本章讨论了主要参数。

# 如何做...

配置文件由`section_name`指定的部分。所有与部分相关的参数都可以放在它们下面，例如：

```sql
[mysqld] <---section name <parameter_name> = <value> <---parameter values
[client] <parameter_name> = <value>
[mysqldump] <parameter_name> = <value>
[mysqld_safe] <parameter_name> = <value>
[server]
<parameter_name> = <value>
```

+   `[mysql]`：该部分由`mysql`命令行客户端读取

+   `[client]`：该部分由所有连接的客户端（包括`mysql cli`）读取

+   `[mysqld]`：该部分由`mysql`服务器读取

+   `[mysqldump]`：该部分由名为`mysqldump`的备份实用程序读取

+   `[mysqld_safe]`：由`mysqld_safe`进程（MySQL 服务器启动脚本）读取

除此之外，`mysqld_safe`进程从选项文件中的`[mysqld]`和`[server]`部分读取所有选项。

例如，`mysqld_safe`进程从`mysqld`部分读取`pid-file`选项。

```sql
shell> sudo vi /etc/my.cnf
[mysqld]
pid-file = /var/lib/mysql/mysqld.pid
```

在使用`systemd`的系统中，`mysqld_safe`将不会安装。要配置启动脚本，您需要在`/etc/systemd/system/mysqld.service.d/override.conf`中设置值。

例如：

```sql
[Service]
LimitNOFILE=max_open_files
PIDFile=/path/to/pid/file
LimitCore=core_file_limit
Environment="LD_PRELOAD=/path/to/malloc/library"
Environment="TZ=time_zone_setting"
```

# 使用全局和会话变量

正如您在前几章中所看到的，您可以通过连接到 MySQL 并执行`SET`命令来设置参数。

根据变量的范围，有两种类型的变量：

+   **全局**：适用于所有新连接

+   **会话**：仅适用于当前连接（会话）

# 如何做...

例如，如果您想记录所有慢于一秒的查询，可以执行：

```sql
mysql> SET GLOBAL long_query_time = 1;
```

要使更改在重新启动时持久，请使用：

```sql
mysql> SET PERSIST long_query_time = 1;
Query OK, 0 rows affected (0.01 sec)
```

或：

```sql
mysql> SET @@persist.long_query_time = 1;
Query OK, 0 rows affected (0.00 sec)
```

持久的全局系统变量设置存储在位于数据目录中的 mysqld-auto.cnf 中。

假设您只想记录此会话的查询，而不是所有连接的查询。您可以使用以下命令：

```sql
mysql> SET SESSION long_query_time = 1;
```

# 使用启动脚本的参数

假设您希望使用启动脚本启动 MySQL，而不是通过`systemd`，特别是用于测试或进行一些临时更改。您可以将变量传递给脚本，而不是在配置文件中更改它。

# 如何做...

```sql
shell> /usr/local/mysql/bin/mysqld --basedir=/usr/local/mysql --datadir=/usr/local/mysql/data --plugin-dir=/usr/local/mysql/lib/plugin --user=mysql --log-error=/usr/local/mysql/data/centos7.err --pid-file=/usr/local/mysql/data/centos7.pid --init-file=/tmp/mysql-init &
```

您可以看到`--init-file`参数被传递给服务器。服务器在启动之前执行该文件中的 SQL 语句。

# 配置参数

安装后，您需要配置的基本事项在本节中都有所涵盖。其余的都可以保持默认或根据负载稍后进行调整。

# 如何做...

让我们深入了解。

# 数据目录

由 MySQL 服务器管理的数据存储在一个名为`数据目录`的目录下。`数据目录`的每个子目录都是一个数据库目录，对应于服务器管理的数据库。默认情况下，

`数据目录`有三个子目录：

+   `mysql`：MySQL 系统数据库

+   `performance_schema`：提供了用于在运行时检查服务器内部执行的信息

+   `sys`：提供了一组对象，以帮助更轻松地解释性能模式信息

除此之外，`data directory`还包含日志文件、`InnoDB`表空间和`InnoDB`日志文件、SSL 和 RSA 密钥文件、`mysqld`的`pid`以及`mysqld-auto.cnf`，其中存储了持久化的全局系统变量设置。

要设置`data directory`的更改/添加`datadir`的值到配置文件。默认值为`/var/lib/mysql`：

```sql
shell> sudo vi /etc/my.cnf
[mysqld]
datadir = /data/mysql
```

你可以将其设置为任何你想要存储数据的地方，但你应该将`data directory`的所有权更改为`mysql`。

确保承载`data directory`的磁盘卷有足够的空间来容纳所有的数据。

# innodb_buffer_pool_size

这是决定`InnoDB`存储引擎可以使用多少内存来缓存数据和索引的最重要的调整参数。设置得太低会降低 MySQL 服务器的性能，设置得太高会增加 MySQL 进程的内存消耗。MySQL 8 最好的地方在于`innodb_buffer_pool_size`是动态的，这意味着你可以在不重新启动服务器的情况下改变`innodb_buffer_pool_size`。

以下是如何调整它的简单指南：

1.  查找数据集的大小。不要将`innodb_buffer_pool_size`的值设置得高于数据集的大小。假设你有 12GB 的 RAM 机器，你的数据集大小为 3GB；那么你可以将`innodb_buffer_pool_size`设置为 3GB。如果你预计数据会增长，你可以根据需要随时增加它，而无需重新启动 MySQL。

1.  通常，数据集的大小要比可用的 RAM 大得多。在总 RAM 中，你可以为操作系统、其他进程、MySQL 内部的每个线程缓冲区和`InnoDB`之外的 MySQL 服务器分配一些内存。剩下的可以分配给`InnoDB`缓冲池大小。

这是一个非常通用的表，为你提供了一个很好的起点，假设它是一个专用的 MySQL 服务器，所有的表都是`InnoDB`，每个线程的缓冲区都保持默认值。如果系统内存不足，你可以动态减少缓冲池。

| **RAM** | **缓冲池大小（范围）** |
| --- | --- |
| 4 GB | 1 GB-2 GB |
| 8 GB | 4 GB-6 GB |
| 12 GB | 6 GB-10 GB |
| 16 GB | 10 GB-12 GB |
| 32 GB | 24 GB-28 GB |
| 64 GB | 45 GB-56 GB |
| 128 GB | 108 GB-116 GB |
| 256 GB | 220 GB-245 GB |

# innodb_buffer_pool_instances

你可以将`InnoDB`缓冲池划分为单独的区域，以提高并发性，通过减少不同线程对缓存页面的读写而产生的争用。例如，如果缓冲池大小为 64GB，`innodb_buffer_pool_instances`为 32，那么缓冲池将被分割成 32 个每个 2GB 的区域。

如果缓冲池大小超过 16GB，你可以设置实例，以便每个区域至少获得 1GB 的空间。

# innodb_log_file_size

这是用于在数据库崩溃时重放已提交事务的重做日志空间的大小。默认值为 48MB，这对于生产工作负载可能不够。你可以先设置为 1GB 或 2GB。这个更改需要重新启动。停止 MySQL 服务器，并确保它在没有错误的情况下关闭。在`my.cnf`中进行更改并启动服务器。在早期版本中，你需要停止服务器，删除日志文件，然后启动服务器。在 MySQL 8 中，这是自动的。修改重做日志文件在第十一章中有解释，*管理表空间*，在*更改 InnoDB 重做日志文件的数量或大小*部分。

# 更改数据目录

你的数据可能会随着时间的推移而增长，当它超出文件系统时，你需要添加一个磁盘或将`data directory`移动到一个更大的卷中。

# 如何做...

1.  检查当前的`data directory`。默认情况下，`data directory`是`/var/lib/mysql`：

```sql
mysql> show variables like '%datadir%';
+---------------+-----------------+
| Variable_name | Value           |
+---------------+-----------------+
| datadir       | /var/lib/mysql/ |
+---------------+-----------------+
1 row in set (0.04 sec)
```

1.  停止`mysql`并确保它已成功停止：

```sql
shell> sudo systemctl stop mysql
```

1.  检查状态：

```sql
shell> sudo systemctl status mysql
```

应该显示`已停止 MySQL Community Server`。

1.  在新位置创建目录并将所有权更改为`mysql`：

```sql
shell> sudo mkdir -pv /data
shell> sudo chown -R mysql:mysql /data/
```

1.  将文件移动到新的`data 目录`：

```sql
shell> sudo rsync -av /var/lib/mysql /data
```

1.  在 Ubuntu 中，如果已启用 AppArmor，您需要配置访问控制：

```sql
shell> vi /etc/apparmor.d/tunables/alias
alias /var/lib/mysql/ -> /data/mysql/,
shell> sudo systemctl restart apparmor
```

1.  启动 MySQL 服务器并验证`data`目录已更改：

```sql
shell> sudo systemctl start mysql
mysql> show variables like '%datadir%'; 
+---------------+--------------+
| Variable_name | Value        |
+---------------+--------------+
| datadir       | /data/mysql/ |
+---------------+--------------+
1 row in set (0.00 sec)
```

1.  验证数据是否完好并删除旧的`data 目录`：

```sql
shell> sudo rm -rf /var/lib/mysql
```

如果 MySQL 启动失败并显示错误—`MySQL 数据目录在/var/lib/mysql 未找到，请创建一个`：

执行`sudo mkdir /var/lib/mysql/mysql -p`

如果显示`MySQL 系统数据库未找到`，运行`mysql_install_db`工具，该工具将创建所需的目录。


# 第五章：事务

在本章中，我们将涵盖以下示例：

+   执行事务

+   使用保存点

+   隔离级别

+   锁定

# 介绍

在接下来的示例中，我们将讨论 MySQL 中的事务和各种隔离级别。事务意味着一组应该一起成功或失败的 SQL 语句。事务还应该满足**原子性、一致性、隔离性和** **持久性**（**ACID**）属性。以一个非常基本的例子，从账户`A`转账到账户`B`。假设`A`有 600 美元，`B`有 400 美元，`B`希望从`A`转账 100 美元给自己。

银行将从`A`扣除 100 美元，并使用以下 SQL 代码将其添加到`B`（仅供说明）：

```sql
mysql> SELECT balance INTO @a.bal FROM account WHERE account_number='A';
```

以编程方式检查`@a.bal`是否大于或等于 100：

```sql
mysql> UPDATE account SET balance=@a.bal-100 WHERE account_number='A';
mysql> SELECT balance INTO @b.bal FROM account WHERE account_number='B';
```

以编程方式检查`@b.bal`是否`NOT NULL`：

```sql
mysql> UPDATE account SET balance=@b.bal+100 WHERE account_number='B';
```

这四行 SQL 应该是一个单独的事务，并满足以下 ACID 属性：

+   **原子性**：要么所有的 SQL 都应该成功，要么都应该失败。不应该有任何部分更新。如果不遵守这个属性，如果数据库在运行两个 SQL 后崩溃，那么`A`将会损失 100 美元。

+   一致性：事务必须以允许的方式仅改变受影响的数据。在这个例子中，如果带有`B`的`account_number`不存在，整个事务应该被回滚。

+   **隔离性**：同时发生的事务（并发事务）不应该导致数据库处于不一致的状态。每个事务应该被执行，就好像它是系统中唯一的事务一样。没有任何事务应该影响任何其他事务的存在。假设`A`在转账给`B`的同时完全转移了这 600 美元；两个事务应该独立运行，确保在转移金额之前的余额。

+   **持久性**：数据应该持久存在于磁盘上，不应该在任何数据库或系统故障时丢失。

`InnoDB`是 MySQL 中的默认存储引擎，支持事务，而 MyISAM 不支持事务。

# 执行事务

创建虚拟表和示例数据以理解这个示例：

```sql
mysql> CREATE DATABASE bank;
mysql> USE bank;
mysql> CREATE TABLE account(account_number varchar(10) PRIMARY KEY, balance int);
mysql> INSERT INTO account VALUES('A',600),('B',400);
```

# 如何做...

要开始一个事务（一组 SQL），执行`START TRANSACTION`或`BEGIN`语句：

```sql
mysql> START TRANSACTION;
or 
mysql> BEGIN;
```

然后执行所有希望在事务内部的语句，比如从`A`转账 100 到`B`：

```sql
mysql> SELECT balance INTO @a.bal FROM account WHERE account_number='A';

Programmatically check if @a.bal is greater than or equal to 100 
mysql> UPDATE account SET balance=@a.bal-100 WHERE account_number='A';
mysql> SELECT balance INTO @b.bal FROM account WHERE account_number='B';

Programmatically check if @b.bal IS NOT NULL 
mysql> UPDATE account SET balance=@b.bal+100 WHERE account_number='B';
```

确保所有 SQL 都成功执行后，执行`COMMIT`语句，完成事务并提交数据：

```sql
mysql> COMMIT;
```

如果在中间遇到任何错误并希望中止事务，可以发出`ROLLBACK`语句而不是`COMMIT`。

例如，如果`A`想要转账到一个不存在的账户而不是发送给`B`，你应该中止事务并将金额退还给`A`：

```sql
mysql> BEGIN;

mysql> SELECT balance INTO @a.bal FROM account WHERE account_number='A';

mysql> UPDATE account SET balance=@a.bal-100 WHERE account_number='A';

mysql> SELECT balance INTO @b.bal FROM account WHERE account_number='C';
Query OK, 0 rows affected, 1 warning (0.07 sec)

mysql> SHOW WARNINGS;
+---------+------+-----------------------------------------------------+
| Level   | Code | Message                                             |
+---------+------+-----------------------------------------------------+
| Warning | 1329 | No data - zero rows fetched, selected, or processed |
+---------+------+-----------------------------------------------------+
1 row in set (0.02 sec)

mysql> SELECT @b.bal;
+--------+
| @b.bal |
+--------+
| NULL   |
+--------+
1 row in set (0.00 sec)

mysql> ROLLBACK;
Query OK, 0 rows affected (0.01 sec)
```

# 自动提交

默认情况下，自动提交是`ON`，这意味着所有单独的语句在执行时都会被提交，除非它们在`BEGIN...COMMIT`块中。如果自动提交是`OFF`，你需要显式地发出`COMMIT`语句来提交一个事务。要禁用它，执行：

```sql
mysql> SET autocommit=0;
```

DDL 语句，比如数据库的`CREATE`或`DROP`，以及表或存储过程的`CREATE`、`DROP`或`ALTER`，不能被回滚。

有一些语句，比如 DDLs、`LOAD DATA INFILE`、`ANALYZE TABLE`、与复制相关的语句等会导致隐式的`COMMIT`。有关这些语句的更多细节，请参阅[`dev.mysql.com/doc/refman/8.0/en/implicit-commit.html`](https://dev.mysql.com/doc/refman/8.0/en/implicit-commit.html)。

# 使用保存点

使用保存点，你可以在事务中回滚到某些点，而不终止事务。你可以使用`SAVEPOINT identifier`来为事务设置一个名称，并使用`ROLLBACK TO identifier`语句来将事务回滚到指定的保存点，而不终止事务。

# 如何做...

假设`A`想要转账给多个账户；即使向一个账户的转账失败，其他账户也不应该被回滚：

```sql
mysql> BEGIN;
Query OK, 0 rows affected (0.00 sec)

mysql> SELECT balance INTO @a.bal FROM account WHERE account_number='A';
Query OK, 1 row affected (0.01 sec)

mysql> UPDATE account SET balance=@a.bal-100 WHERE account_number='A';
Query OK, 1 row affected (0.01 sec)
Rows matched: 1 Changed: 1 Warnings: 0

mysql> UPDATE account SET balance=balance+100 WHERE account_number='B';
Query OK, 1 row affected (0.00 sec)
Rows matched: 1 Changed: 1 Warnings: 0

mysql> SAVEPOINT transfer_to_b;
Query OK, 0 rows affected (0.00 sec)

mysql> SELECT balance INTO @a.bal FROM account WHERE account_number='A';
Query OK, 1 row affected (0.00 sec)

mysql> UPDATE account SET balance=balance+100 WHERE account_number='C';
Query OK, 0 rows affected (0.00 sec)
Rows matched: 0 Changed: 0 Warnings: 0

### Since there are no rows updated, meaning there is no account with 'C', you can rollback the transaction to SAVEPOINT where transfer to B is successful. Then 'A' will get back 100 which was deducted to transfer to C. If you wish not to use the save point, you should do these in two transactions.

mysql> ROLLBACK TO transfer_to_b;
Query OK, 0 rows affected (0.00 sec)

mysql> COMMIT;
Query OK, 0 rows affected (0.00 sec)

mysql> SELECT balance FROM account WHERE account_number='A';
+---------+
| balance |
+---------+
| 400     |
+---------+
1 row in set (0.00 sec)

mysql> SELECT balance FROM account WHERE account_number='B';
+---------+
| balance |
+---------+
| 600     |
+---------+
1 row in set (0.00 sec)
```

# 隔离级别

当两个或更多事务同时发生时，隔离级别定义了事务与其他事务所做的资源或数据修改隔离的程度。有四种隔离级别；要更改隔离级别，您需要设置动态的具有会话级范围的`tx_isolation`变量。

# 如何做...

要更改此级别，请执行`SET @@transaction_isolation = 'READ-COMMITTED';`。

# 读取未提交

当前事务可以读取另一个未提交事务写入的数据，这也称为**脏读**。

例如，`A`想要向他的账户添加一些金额并转账给`B`。假设两个交易同时发生；流程将如下。

`A`最初有 400 美元，想要在向`B`转账 500 美元后向他的账户添加 500 美元。

| **# 事务 1（添加金额）** | **# 事务 2（转账金额）** |
| --- | --- |

|

```sql
BEGIN;
```

|

```sql
BEGIN;
```

|

|

```sql
UPDATE account
 SET balance=balance+500
 WHERE account_number='A';
```

| -- |
| --- |
|  -- |

```sql
SELECT balance INTO @a.bal
 FROM account
 WHERE account_number='A';
 # A sees 900 here
```

|

|

```sql
ROLLBACK;
 # Assume due to some reason the
 transaction got rolled back
```

| -- |
| --- |
| -- |

```sql
# A transfers 900 to B since
 A has 900 in previous SELECT
 UPDATE account
 SET balance=balance-900
 WHERE account_number='A';
```

|

|  -- |
| --- |

```sql
# B receives the amount UPDATE account
 SET balance=balance+900
 WHERE account_number='B';
```

|

|  -- |
| --- |

```sql
# Transaction 2 completes successfully
COMMIT;
```

|

您可以注意到*事务 2*已经读取了未提交或回滚的*事务 1*的数据，导致此事务后账户`A`的余额变为负数，这显然是不希望的。

# 读取提交

当前事务只能读取另一个事务提交的数据，这也称为**不可重复读**。

再举一个例子，`A`有 400 美元，`B`有 600 美元。

| **# 事务 1（添加金额）** | **# 事务 2（转账金额）** |
| --- | --- |

|

```sql
BEGIN;
```

|

```sql
BEGIN;
```

|

|

```sql
UPDATE account SET balance=balance+500
WHERE account_number='A';
```

|  -- |
| --- |
| -- |

```sql
SELECT balance INTO @a.bal
FROM account
WHERE account_number='A';
# A sees 400 here because transaction 1 has not committed the data yet 
```

|

|

```sql
COMMIT;
```

| -- |
| --- |
| -- |

```sql
SELECT balance INTO @a.bal
FROM account
WHERE account_number='A';
# A sees 900 here because transaction 1 has committed the data. 
```

|

您可以注意到，在同一事务中，相同的`SELECT`语句获取了不同的结果。

# 可重复读

即使另一个事务已经提交了数据，事务仍将看到由第一个语句读取的相同数据。同一事务中的所有一致读取都读取第一次读取建立的快照。例外是可以读取同一事务中更改的数据的事务。

当事务开始并执行其第一次读取时，将创建一个读取视图，并保持打开直到事务结束。为了在事务结束之前提供相同的结果集，`InnoDB`使用行版本和`UNDO`信息。假设*事务 1*选择了一些行，另一个事务删除了这些行并提交了数据。如果*事务 1*仍然打开，它应该能够看到它一开始选择的行。已删除的行被保留在`UNDO`日志空间中以满足*事务 1*。一旦*事务 1*完成，这些行将被标记为从`UNDO`日志中删除。这称为**多版本并发控制**（**MVCC**）。

再举一个例子，`A`有 400 美元，`B`有 600 美元。

| **# 事务 1（添加金额）** | **# 事务 2（转账金额）** |
| --- | --- |

|

```sql
BEGIN;
```

|

```sql
BEGIN;
```

|

|  -- |
| --- |

```sql
SELECT balance INTO @a.bal
FROM account
WHERE account_number='A';
# A sees 400 here
```

|

|

```sql
UPDATE account
SET balance=balance+500
WHERE account_number='A';
```

| -- |
| --- |
| -- |

```sql
SELECT balance INTO @a.bal
FROM account
WHERE account_number='A';
# A sees still 400 even though transaction 1 is committed
```

|

|

```sql
COMMIT;
```

| -- |
| --- |
|  -- |

```sql
COMMIT;
```

|

|  -- |
| --- |

```sql
SELECT balance INTO @a.bal
FROM account
WHERE account_number='A';
# A sees 900 here because this is a fresh transaction
```

|

这仅适用于`SELECT`语句，不一定适用于 DML 语句。如果您插入或修改了一些行，然后提交该事务，来自另一个并发的`REPEATABLE READ`事务的`DELETE`或`UPDATE`语句可能会影响那些刚刚提交的行，即使会话无法查询它们。如果一个事务更新或删除了另一个事务提交的行，这些更改将对当前事务可见。

例如：

| **# 事务 1** | **# 事务 2** |
| --- | --- |

|

```sql
BEGIN;
```

|

```sql
BEGIN;
```

|

|

```sql
SELECT * FROM account;
# 2 rows are returned
```

|  -- |
| --- |
|  -- |

```sql
INSERT INTO account VALUES('C',1000);
# New account is created
```

|

|   -- |
| --- |

```sql
COMMIT;
```

|

|

```sql
SELECT * FROM account WHERE account_number='C';
# no rows are returned because of MVCC
```

|  -- |
| --- |

|

```sql
DELETE FROM account WHERE account_number='C';
# Surprisingly account C gets deleted
```

|  -- |
| --- |
|  -- |

```sql
SELECT * FROM account;
# 3 rows are returned because transaction 1 is not yet committed
```

|

|

```sql
COMMIT;
```

| -- |
| --- |
|  -- |

```sql
SELECT * FROM account;
# 2 rows are returned because transaction 1 is committed
```

|

这是另一个例子：

| **# 事务 1** | **# 事务 2** |
| --- | --- |

|

```sql
BEGIN;
```

|

```sql
BEGIN;
```

|

|

```sql
SELECT * FROM account;
# 2 rows are returned
```

|  -- |
| --- |
| -- |

```sql
INSERT INTO account VALUES('D',1000);
```

|

| -- |
| --- |

```sql
COMMIT;
```

|

|

```sql
SELECT * FROM account;
# 3 rows are returned because of MVCC
```

|  -- |
| --- |

|

```sql
UPDATE account SET balance=1000 WHERE account_number='D';
# Surprisingly account D gets updated
```

|  -- |
| --- |

|

```sql
SELECT * FROM account;
# Surprisingly 4 rows are returned
```

|  -- |
| --- |

# 可串行化

这提供了通过锁定所有被选中的行来提供最高级别的隔离。这个级别类似于`REPEATABLE READ`，但是如果禁用了自动提交，`InnoDB`会隐式地将所有普通的`SELECT`语句转换为`SELECT...LOCK IN SHARE MODE`。如果启用了自动提交，`SELECT`就是它自己的事务。

例如：

| **# 事务 1** | **# 事务 2** |
| --- | --- |

|

```sql
BEGIN;
```

|

```sql
BEGIN;
```

|

|

```sql
SELECT * FROM account WHERE account_number='A';
```

|  -- |
| --- |
|  -- |

```sql
UPDATE account SET balance=1000 WHERE account_number='A';
 # This will wait until the lock held by transaction 1
 on row A is released
```

|

|

```sql
COMMIT;
```

| -- |
| --- |
|  -- |

```sql
# UPDATE will be successful now
```

|

另一个例子：

| **# 事务 1** | **# 事务 2** |
| --- | --- |

|

```sql
BEGIN;
```

|

```sql
BEGIN;
```

|

|

```sql
SELECT * FROM account WHERE account_number='A';
# Selects values of A
```

|  -- |
| --- |
|  -- |

```sql
INSERT INTO account VALUES('D',2000);
# Inserts D
```

|

|

```sql
SELECT * FROM account WHERE account_number='D';
 # This will wait until the transaction 2 completes
```

| -- |
| --- |
|  -- |

```sql
COMMIT;
```

|

|

```sql
# Now the preceding select statement returns values of D
```

| -- |
| --- |

因此，可串行化等待锁，并始终读取最新提交的数据。

# 锁定

有两种类型的锁定：

+   **内部锁定**：MySQL 在服务器内部执行内部锁定，以管理多个会话对表内容的争用

+   **外部锁定**：MySQL 为客户会话提供了显式获取表锁的选项，以防止其他会话访问表。

**内部锁定**：主要有两种类型的锁：

+   **行级锁定**：锁定粒度到行级。只有访问的行被锁定。这允许多个会话同时写入访问，使它们适用于多用户、高并发和 OLTP 应用程序。只有`InnoDB`支持行级锁定。

+   **表级锁定**：MySQL 对`MyISAM`、`MEMORY`和`MERGE`表使用表级锁定，每次只允许一个会话更新这些表。这种锁定级别使这些存储引擎更适合只读、读多或单用户应用程序。

参考[`dev.mysql.com/doc/refman/8.0/en/internal-locking.html`](https://dev.mysql.com/doc/refman/8.0/en/internal-locking.html)和[`dev.mysql.com/doc/refman/8.0/en/innodb-locking.html`](https://dev.mysql.com/doc/refman/8.0/en/innodb-locking.html)以了解更多关于`InnoDB`锁的信息。

**外部锁定**：您可以使用`LOCK TABLE`和`UNLOCK TABLES`语句来控制锁。

对`READ`和`WRITE`的表锁定如下所述：

+   `READ`：当表被锁定为`READ`时，多个会话可以从表中读取数据而不需要获取锁。此外，多个会话可以在同一张表上获取锁，这就是为什么`READ`锁也被称为**共享锁**。当持有`READ`锁时，没有会话可以向表中写入数据（包括持有锁的会话）。如果有任何写入尝试，它将处于等待状态，直到`READ`锁被释放。

+   `WRITE`：当表被锁定为`WRITE`时，除了持有锁的会话外，没有其他会话可以从表中读取和写入数据。直到现有锁被释放，其他会话甚至无法获取任何锁。这就是为什么这被称为`独占锁`。如果有任何读/写尝试，它将处于等待状态，直到`WRITE`锁被释放。

当执行`UNLOCK TABLES`语句或会话终止时，所有锁都会被释放。

# 如何做...

语法如下：

```sql
mysql> LOCK TABLES table_name [READ | WRITE]
```

要解锁表，请使用：

```sql
mysql> UNLOCK TABLES;
```

要锁定所有数据库中的所有表，请执行以下语句。在对数据库进行一致快照时使用。它会冻结对数据库的所有写入：

```sql
mysql> FLUSH TABLES WITH READ LOCK;
```

# 锁定队列

除了共享锁（一张表可以有多个共享锁）外，一张表上不能同时持有两个锁。如果一张表已经有一个共享锁，而独占锁来了，它将被保留在队列中，直到共享锁被释放。当独占锁在队列中时，所有后续的共享锁也会被阻塞并保留在队列中。

`InnoDB`在从表中读取/写入时会获取元数据锁。如果第二个事务请求`WRITE LOCK`，它将被保留在队列中，直到第一个事务完成。如果第三个事务想要读取数据，它必须等到第二个事务完成。

**事务 1：**

```sql
mysql> BEGIN;
Query OK, 0 rows affected (0.00 sec)

mysql> SELECT * FROM employees LIMIT 10;
+--------+------------+------------+-----------+--------+------------+
| emp_no | birth_date | first_name | last_name | gender | hire_date  |
+--------+------------+------------+-----------+--------+------------+
|  10001 | 1953-09-02 | Georgi     | Facello   | M      | 1986-06-26 |
|  10002 | 1964-06-02 | Bezalel    | Simmel    | F      | 1985-11-21 |
|  10003 | 1959-12-03 | Parto      | Bamford   | M      | 1986-08-28 |
|  10004 | 1954-05-01 | Chirstian  | Koblick   | M      | 1986-12-01 |
|  10005 | 1955-01-21 | Kyoichi    | Maliniak  | M      | 1989-09-12 |
|  10006 | 1953-04-20 | Anneke     | Preusig   | F      | 1989-06-02 |
|  10007 | 1957-05-23 | Tzvetan    | Zielinski | F      | 1989-02-10 |
|  10008 | 1958-02-19 | Saniya     | Kalloufi  | M      | 1994-09-15 |
|  10009 | 1952-04-19 | Sumant     | Peac      | F      | 1985-02-18 |
|  10010 | 1963-06-01 | Duangkaew  | Piveteau  | F      | 1989-08-24 |
+--------+------------+------------+-----------+--------+------------+
10 rows in set (0.00 sec)
```

注意`COMMIT`没有被执行。事务保持打开状态。

**事务 2：**

```sql
mysql> LOCK TABLE employees WRITE;
```

此语句必须等到事务 1 完成。

**事务 3：**

```sql
mysql> SELECT * FROM employees LIMIT 10;
```

即使事务 3 也不会产生任何结果，因为一个排他锁在队列中（它在等待事务 2 完成）。此外，它会阻塞表上的所有操作。

您可以通过从另一个会话中检查`SHOW PROCESSLIST`来检查这一点：

```sql
mysql> SHOW PROCESSLIST;
+----+------+-----------+-----------+---------+------+---------------------------------+----------------------------------+
| Id | User | Host      | db        | Command | Time | State                           | Info                             |
+----+------+-----------+-----------+---------+------+---------------------------------+----------------------------------+
| 20 | root | localhost | employees | Sleep   |   48 |                                 | NULL                             |
| 21 | root | localhost | employees | Query   |   34 | Waiting for table metadata lock | LOCK TABLE employees WRITE       |
| 22 | root | localhost | employees | Query   |   14 | Waiting for table metadata lock | SELECT * FROM employees LIMIT 10 |
| 23 | root | localhost | employees | Query   |    0 | starting                        | SHOW PROCESSLIST                 |
+----+------+-----------+-----------+---------+------+---------------------------------+----------------------------------+
4 rows in set (0.00 sec)
```

您可以注意到事务 2 和事务 3 都在等待事务 1。

要了解有关元数据锁的更多信息，请参考[`dev.mysql.com/doc/refman/8.0/en/metadata-locking.html`](https://dev.mysql.com/doc/refman/8.0/en/metadata-locking.html)。在使用`FLUSH TABLES WITH READ LOCK`时也可以观察到相同的行为。

**事务 1：**

```sql
mysql> BEGIN;
Query OK, 0 rows affected (0.00 sec)

mysql> SELECT * FROM employees LIMIT 10;
+--------+------------+------------+-----------+--------+------------+
| emp_no | birth_date | first_name | last_name | gender | hire_date  |
+--------+------------+------------+-----------+--------+------------+
|  10001 | 1953-09-02 | Georgi     | Facello   | M      | 1986-06-26 |
|  10002 | 1964-06-02 | Bezalel    | Simmel    | F      | 1985-11-21 |
|  10003 | 1959-12-03 | Parto      | Bamford   | M      | 1986-08-28 |
|  10004 | 1954-05-01 | Chirstian  | Koblick   | M      | 1986-12-01 |
|  10005 | 1955-01-21 | Kyoichi    | Maliniak  | M      | 1989-09-12 |
|  10006 | 1953-04-20 | Anneke     | Preusig   | F      | 1989-06-02 |
|  10007 | 1957-05-23 | Tzvetan    | Zielinski | F      | 1989-02-10 |
|  10008 | 1958-02-19 | Saniya     | Kalloufi  | M      | 1994-09-15 |
|  10009 | 1952-04-19 | Sumant     | Peac      | F      | 1985-02-18 |
|  10010 | 1963-06-01 | Duangkaew  | Piveteau  | F      | 1989-08-24 |
+--------+------------+------------+-----------+--------+------------+
10 rows in set (0.00 sec)
```

请注意，`COMMIT`没有被执行。事务保持打开状态。

**事务 2：**

```sql
mysql> FLUSH TABLES WITH READ LOCK;
```

**事务 3：**

```sql
mysql> SELECT * FROM employees LIMIT 10;
```

即使事务 3 也不会产生任何结果，因为`FLUSH TABLES`在获取锁之前需要等待表上的所有操作完成。此外，它会阻塞表上的所有操作。

您可以通过从另一个会话中检查`SHOW PROCESSLIST`来检查这一点。

```sql
mysql> SHOW PROCESSLIST;
+----+------+-----------+-----------+---------+------+-------------------------+--------------------------------------------------+
| Id | User | Host      | db        | Command | Time | State                   | Info                                             |
+----+------+-----------+-----------+---------+------+-------------------------+--------------------------------------------------+
| 20 | root | localhost | employees | Query   |    7 | Creating sort index     | SELECT * FROM employees ORDER BY first_name DESC |
| 21 | root | localhost | employees | Query   |    5 | Waiting for table flush | FLUSH TABLES WITH READ LOCK                      |
| 22 | root | localhost | employees | Query   |    3 | Waiting for table flush | SELECT * FROM employees LIMIT 10                 |
| 23 | root | localhost | employees | Query   |    0 | starting                | SHOW PROCESSLIST                                 |
+----+------+-----------+-----------+---------+------+-------------------------+--------------------------------------------------+
4 rows in set (0.00 sec)
```

为了进行一致的备份，所有备份方法都使用`FLUSH TABLES WITH READ LOCK`，如果表上有长时间运行的事务，这可能非常危险。


# 第六章：二进制日志记录

在本章中，我们将介绍以下配方：

+   使用二进制日志记录

+   二进制日志格式

+   从二进制日志中提取语句

+   忽略数据库以写入二进制日志

+   重新定位二进制日志

# 介绍

二进制日志包含对数据库的所有更改的记录，包括数据和结构。二进制日志不用于不修改数据的语句，如`SELECT`或`SHOW`。运行启用二进制日志的服务器会略微影响性能。二进制日志是崩溃安全的。只有完整的事件或事务才会被记录或读取。

为什么要使用二进制日志？

+   **复制**：您可以使用二进制日志将对服务器所做的更改流式传输到另一个服务器。从服务器充当镜像副本，并可用于分发负载。接受写入的服务器称为主服务器，镜像副本服务器称为从服务器。

+   **时间点恢复**：假设您在星期日的 00:00 进行备份，而您的数据库在星期日的 8:00 崩溃。使用备份，您可以恢复到星期日的 00:00。使用二进制日志，您可以回放它们，以恢复到 08:00。

# 使用二进制日志记录

要启用`binlog`，必须设置`log_bin`和`server_id`并重新启动服务器。您可以在`log_bin`中提及路径和基本名称。例如，`log_bin`设置为`/data/mysql/binlogs/server1`，则二进制日志存储在`/data/mysql/binlogs`文件夹中，名称为`server1.000001`，`server1.000002`等。服务器每次启动或刷新日志或当前日志大小达到`max_binlog_size`时，都会创建一个新文件。它维护`server1.index`文件，其中包含每个二进制日志的位置。

# 如何做...

让我们看看如何处理日志。我相信您会喜欢学习它们。

# 启用二进制日志记录

1.  启用二进制日志记录并设置`server_id`。在您喜欢的编辑器中打开 MySQL `config`文件并追加以下行。选择`server_id`，使其对您基础架构中的每个 MySQL 服务器都是唯一的。

您还可以简单地将`log_bin`变量放在`my.cnf`中，而不设置任何值。在这种情况下，二进制日志将在`data directory`目录中创建，并使用`hostname`作为其名称。

```sql
shell> sudo vi /etc/my.cnf
[mysqld]
log_bin = /data/mysql/binlogs/server1
server_id = 100
```

1.  重新启动 MySQL 服务器：

```sql
shell> sudo systemctl restart mysql
```

1.  验证是否创建了二进制日志：

```sql
mysql> SHOW VARIABLES LIKE 'log_bin%';
+---------------------------------+-----------------------------------+
| Variable_name                   | Value                             |
+---------------------------------+-----------------------------------+
| log_bin                         | ON                                |
| log_bin_basename                | /data/mysql/binlogs/server1       |
| log_bin_index                   | /data/mysql/binlogs/server1.index |
| log_bin_trust_function_creators | OFF                               |
| log_bin_use_v1_row_events       | OFF                               |
+---------------------------------+-----------------------------------+
5 rows in set (0.00 sec)
```

```sql
mysql> SHOW MASTER LOGS;
+----------------+-----------+
| Log_name       | File_size |
+----------------+-----------+
| server1.000001 | 154       |
+----------------+-----------+
1 row in set (0.00 sec)
```

```sql
shell> sudo ls -lhtr /data/mysql/binlogs
total 8.0K
-rw-r----- 1 mysql mysql 34 Aug 15 05:01 server1.index
-rw-r----- 1 mysql mysql 154 Aug 15 05:01 server1.000001
```

1.  执行`SHOW BINARY LOGS;`或`SHOW MASTER LOGS;`以显示服务器的所有二进制日志。

1.  执行`SHOW MASTER STATUS;`命令以获取当前二进制日志位置：

```sql
mysql> SHOW MASTER STATUS;
+----------------+----------+--------------+------------------+------------------+++++++++++++++++++++++++++++++++++++-+
| File           | Position | Binlog_Do_DB | Binlog_Ignore_DB | Executed_Gtid_Set |
+----------------+----------+--------------+------------------+-------------------+
| server1.000002 |     3273 |              |                  |                   |
+----------------+----------+--------------+------------------+-------------------+
1 row in set (0.00 sec)
```

一旦`server1.000001`达到`max_binlog_size`（默认为 1GB），将创建一个新文件`server1.000002`并将其添加到`server1.index`中。您可以配置使用`SET @@global.max_binlog_size=536870912`动态设置`max_binlog_size`。

# 禁用会话的二进制日志记录

可能存在不希望将语句复制到其他服务器的情况。为此，可以使用以下命令禁用该会话的二进制日志记录：

```sql
mysql> SET SQL_LOG_BIN = 0;
```

在执行前一个语句后记录的所有 SQL 语句不会记录到二进制日志中。这仅适用于该会话。

要启用，可以执行以下操作：

```sql
mysql> SET SQL_LOG_BIN = 1;
```

# 移至下一个日志

您可以使用`FLUSH LOGS`命令关闭当前的二进制日志并打开一个新的：

```sql
mysql> SHOW BINARY LOGS;
+----------------+-----------+
| Log_name       | File_size |
+----------------+-----------+
| server1.000001 |       154 |
+----------------+-----------+
1 row in set (0.00 sec)

mysql> FLUSH LOGS;
Query OK, 0 rows affected (0.02 sec)

mysql> SHOW BINARY LOGS;
+----------------+-----------+
| Log_name       | File_size |
+----------------+-----------+
| server1.000001 |  198      |
| server1.000002 |  154      |
+----------------+-----------+
2 rows in set (0.00 sec)

```

# 过期二进制日志

基于写入次数，二进制日志会占用大量空间。将它们保持不变可能会在短时间内填满磁盘。清理它们是至关重要的：

1.  使用`binlog_expire_logs_seconds`和`expire_logs_days`设置日志的到期时间。

如果要设置以天为单位的到期时间，请设置`expire_logs_days`。例如，如果要删除两天前的所有二进制日志，`SET @@global.expire_logs_days=2`。将值设置为`0`会禁用自动到期。

如果您想要更细粒度，可以使用`binlog_expire_logs_seconds`变量，该变量设置二进制日志的过期时间（以秒为单位）。

此变量和`expire_logs_days`的效果是累积的。例如，如果`expire_logs_days`是`1`，`binlog_expire_logs_seconds`是`43200`，那么二进制日志将每 1.5 天清除一次。这与将`binlog_expire_logs_seconds`设置为`129600`并将`expire_logs_days`设置为 0 的结果相同。在 MySQL 8.0 中，`binlog_expire_logs_seconds`和`expire_logs_days`必须都设置为 0 才能禁用二进制日志的自动清除。

1.  要手动清除日志，请执行`PURGE BINARY LOGS TO '<file_name>'`。例如，如果有文件如`server1.000001`，`server1.000002`，`server1.000003`和`server1.000004`，如果您执行`PURGE BINARY LOGS TO 'server1.000004'`，则所有文件直到`server1.000003`将被删除，`server1.000004`不会被触及：

```sql
mysql> SHOW BINARY LOGS;
+----------------+-----------+
| Log_name      | File_size |
+----------------+-----------+
| server1.000001 |       198 |
| server1.000002 |       198 |
| server1.000003 |       198 |
| server1.000004 |       154 |
+----------------+-----------+
4 rows in set (0.00 sec)
```

```sql
mysql> PURGE BINARY LOGS TO 'server1.000004';
Query OK, 0 rows affected (0.00 sec)

```

```sql
mysql> SHOW BINARY LOGS;
+----------------+-----------+
| Log_name       | File_size |
+----------------+-----------+
| server1.000004 |       154 |
+----------------+-----------+
1 row in set (0.00 sec)

```

您还可以执行命令`PURGE BINARY LOGS BEFORE '2017-08-03 15:45:00'`，而不是指定日志文件。您还可以使用单词`MASTER`而不是`BINARY`。

`mysql> PURGE MASTER LOGS TO 'server1.000004'`也可以。

1.  要删除所有二进制日志并重新开始，请执行`RESET MASTER`：

```sql
mysql> SHOW BINARY LOGS;
+----------------+-----------+
| Log_name       | File_size |
+----------------+-----------|
| server1.000004 |       154 |
+----------------+-----------+
1 row in set (0.00 sec)
```

```sql
mysql> RESET MASTER;
Query OK, 0 rows affected (0.01 sec)
```

```sql
mysql> SHOW BINARY LOGS;
+----------------+-----------+
| Log_name       | File_size |
+----------------+-----------+
| server1.000001 |       154 |
+----------------+-----------+
1 row in set (0.00 sec)
```

如果您正在使用复制，清除或过期日志是一种非常不安全的方法。清除二进制日志的安全方法是使用`mysqlbinlogpurge`脚本，这将在第十二章 *管理日志*中介绍。

# 二进制日志格式

二进制日志可以以三种格式写入：

1.  `STATEMENT`：实际的 SQL 语句被记录。

1.  `ROW`：对每一行所做的更改都会被记录。

例如，更新语句更新了 10 行，所有 10 行的更新信息都被写入日志。而在基于语句的复制中，只有更新语句被写入。默认格式是`ROW`。

1.  `MIXED`：MySQL 根据需要从`STATEMENT`切换到`ROW`。

有些语句在不同服务器上执行时可能会导致不同的结果。例如，`UUID()`函数的输出因服务器而异。这些语句称为非确定性语句，对于基于语句的复制来说是不安全的。在这种情况下，当您设置`MIXED`格式时，MySQL 服务器会切换到基于行的格式。

请参阅[`dev.mysql.com/doc/refman/8.0/en/binary-log-mixed.html`](https://dev.mysql.com/doc/refman/8.0/en/binary-log-mixed.html)了解有关不安全语句和切换发生的更多信息。

# 如何做...

您可以使用动态变量`binlog_format`来设置格式，该变量具有全局和会话范围。在全局级别设置它会使所有客户端使用指定的格式：

```sql
mysql> SET GLOBAL binlog_format = 'STATEMENT';
```

或者：

```sql
mysql> SET GLOBAL binlog_format = 'ROW'; 
```

请参阅[`dev.mysql.com/doc/refman/8.0/en/replication-sbr-rbr.html`](https://dev.mysql.com/doc/refman/8.0/en/replication-sbr-rbr.html)了解各种格式的优缺点。

1.  MySQL 8.0 使用版本 2 的二进制日志行事件，这些事件不能被 MySQL 5.6.6 之前的版本读取。将`log-bin-use-v1-row-events`设置为`1`以使用版本 1，以便可以被 MySQL 5.6.6 之前的版本读取。默认值为`0`。

```sql
mysql> SET @@GLOBAL.log_bin_use_v1_row_events=0;
```

1.  当您创建存储函数时，必须声明它是确定性的或者不修改数据。否则，它可能对二进制日志记录不安全。默认情况下，要接受`CREATE FUNCTION`语句，必须显式指定`DETERMINISTIC`，`NO SQL`或`READS SQL DATA`中的至少一个。否则会发生错误：

```sql
ERROR 1418 (HY000): This function has none of DETERMINISTIC, NO SQL, or READS SQL DATA in its declaration and binary logging is enabled (you *might* want to use the less safe log_bin_trust_function_creators variable)
```

您可以在例程中写入非确定性语句，并且仍然声明为`DETERMINISTIC`（这不是一个好的做法），如果您想要复制未声明为`DETERMINISTIC`的例程，可以设置`log_bin_trust_function_creators`变量：

`mysql> SET GLOBAL log_bin_trust_function_creators = 1;`

# 另请参阅

请参阅[`dev.mysql.com/doc/refman/8.0/en/stored-programs-logging.html`](https://dev.mysql.com/doc/refman/8.0/en/stored-programs-logging.html)了解有关存储程序如何复制的更多信息。

# 从二进制日志中提取语句

您可以使用（随 MySQL 一起提供的）`mysqlbinlog`实用程序从二进制日志中提取内容并将其应用到其他服务器上。

# 准备工作

使用各种二进制格式执行几个语句。当您将`binlog_format`设置为`GLOBAL`级别时，您必须断开连接并重新连接以获取更改。如果您想保持连接，请设置为`SESSION`级别。

切换到**基于语句的复制**（**SBR**）：

```sql
mysql> SET @@GLOBAL.BINLOG_FORMAT='STATEMENT';
Query OK, 0 rows affected (0.00 sec)
```

更新几行：

```sql
mysql> BEGIN;
Query OK, 0 rows affected (0.00 sec)

mysql> UPDATE salaries SET salary=salary*2 WHERE emp_no<10002;
Query OK, 18 rows affected (0.00 sec)
Rows matched: 18  Changed: 18  Warnings: 0

mysql> COMMIT;
Query OK, 0 rows affected (0.00 sec)
```

切换到**基于行的复制**（**RBR**）：

```sql
mysql> SET @@GLOBAL.BINLOG_FORMAT='ROW';
Query OK, 0 rows affected (0.00 sec)
```

更新几行：

```sql
mysql> BEGIN;Query OK, 0 rows affected (0.00 sec)

mysql> UPDATE salaries SET salary=salary/2 WHERE emp_no<10002;Query OK, 18 rows affected (0.00 sec)
Rows matched: 18  Changed: 18  Warnings: 0

mysql> COMMIT;Query OK, 0 rows affected (0.00 sec)
```

切换到`MIXED`格式：

```sql
mysql> SET @@GLOBAL.BINLOG_FORMAT='MIXED';
Query OK, 0 rows affected (0.00 sec)
```

更新几行：

```sql
mysql> BEGIN;Query OK, 0 rows affected (0.00 sec)

mysql> UPDATE salaries SET salary=salary*2 WHERE emp_no<10002;Query OK, 18 rows affected (0.00 sec)
Rows matched: 18  Changed: 18  Warnings: 0

mysql> INSERT INTO departments VALUES('d010',UUID());Query OK, 1 row affected (0.00 sec)

mysql> COMMIT;Query OK, 0 rows affected (0.00 sec)
```

# 如何操作...

要显示`server1.000001`的内容，请执行以下操作：

```sql
shell> sudo mysqlbinlog /data/mysql/binlogs/server1.000001
```

您将获得类似以下内容的输出：

```sql
# at 226
#170815 12:49:24 server id 200  end_log_pos 312 CRC32 0x9197bf88  Query thread_id=5 exec_time=0 error_code=0
BINLOG '
~
~
```

在第一行中，`# at`后面的数字表示二进制日志文件中事件的起始位置（文件偏移量）。第二行包含语句在服务器上开始的时间戳。时间戳后面是`server id`、`end_log_pos`、`thread_id`、`exec_time`和`error_code`。

+   `server id`：是事件发生的服务器的`server_id`值（在本例中为`200`）。

+   `end_log_pos`：是下一个事件的起始位置。

+   `thread_id`：指示执行事件的线程。

+   `exec_time`：是在主服务器上执行事件所花费的时间。在从服务器上，它是从从服务器上的结束执行时间减去主服务器上的开始执行时间的差异。这个差异作为指示从服务器落后主服务器的程度的指标。

+   `error_code`：指示执行事件的结果。零表示没有发生错误。

# 观察

1.  您在基于语句的复制中执行了`UPDATE`语句，并且相同的语句记录在二进制日志中。除了服务器外，会话变量也保存在二进制日志中，以在从服务器上复制相同的行为：

```sql
# at 226
#170815 13:28:38 server id 200  end_log_pos 324 CRC32 0x9d27fc78  Query thread_id=8 exec_time=0 error_code=0
SET TIMESTAMP=1502803718/*!*/;
SET @@session.pseudo_thread_id=8/*!*/;
SET @@session.foreign_key_checks=1, @@session.sql_auto_is_null=0,
@@session.unique_checks=1, @@session.autocommit=1/*!*/;
SET @@session.sql_mode=1436549152/*!*/;
SET @@session.auto_increment_increment=1, @@session.auto_increment_offset=1/*!*/;
/*!\C utf8 *//*!*/;
SET @@session.character_set_client=33,@@session.collation_connection=33,@@session.collation_server=255/*!*/;
SET @@session.lc_time_names=0/*!*/;
SET @@session.collation_database=DEFAULT/*!*/;

```

```sql
BEGIN
/*!*/;
# at 324
#170815 13:28:38 server id 200  end_log_pos 471 CRC32 0x35c2ba45  Query thread_id=8 exec_time=0 error_code=0
use `employees`/*!*/;
SET TIMESTAMP=1502803718/*!*/;
UPDATE salaries SET salary=salary*2 WHERE emp_no<10002 /*!*/;
# at 471
#170815 13:28:40 server id 200  end_log_pos 502 CRC32 0xb84cfeda  Xid = 53
COMMIT/*!*/;

```

1.  当使用基于行的复制时，保存的不是语句，而是以二进制格式保存的`ROW`，您无法阅读。此外，您可以观察到，单个更新语句生成了如此多的数据。查看*提取行事件显示*部分，该部分解释了如何查看二进制格式。

```sql
BEGIN
/*!*/;
# at 660
#170815 13:29:02 server id 200  end_log_pos 722 CRC32 0xe0a2ec74  Table_map:`employees`.`salaries` mapped to number 165
# at 722
#170815 13:29:02 server id 200  end_log_pos 1298 CRC32 0xf0ef8b05  Update_rows: table id 165 flags: STMT_END_F

BINLOG '
HveSWRPIAAAAPgAAANICAAAAAKUAAAAAAAEACWVtcGxveWVlcwAIc2FsYXJpZXMABAMDCgoAAAEBAHTsouA=HveSWR/IAAAAQAIAABIFAAAAAKUAAAAAAAEAAgAE///wEScAAFSrAwDahA/ahg/wEScAAKrVAQDahA/ahg/wEScAAFjKAwDahg/ZiA/wEScAACzlAQDahg/ZiA/wEScAAGgIBADZiA/Zig/wEScAADQEAgDZiA/Zig/wEScAAJAQBADZig/ZjA/wEScAAEgIAgDZig/ZjA/wEScAAEQWBADZjA/Zjg/wEScAACILAgDZjA/Zjg/wEScAABhWBADZjg/YkA/wEScAAAwrAgDZjg/YkA/wEScAAHSJBADYkA/Ykg/wEScAALpEAgDYkA/Ykg/wEScAAFiYBADYkg/YlA/wEScAACxMAgDYkg/YlA/wEScAAGijBADYlA/Ylg/wEScAALRRAgDYlA/Ylg/wEScAAFCxBADYlg/XmA/wEScAAKhYAgDYlg/XmA/wEScAADTiBADXmA/Xmg/wEScAABpxAgDXmA/Xmg/wEScAAATyBADXmg/XnA/wEScAAAJ5AgDXmg/XnA/wEScAACTzBADXnA/Xng/wEScAAJJ5AgDXnA/Xng/wEScAANQuBQDXng/WoA/wEScAAGqXAgDXng/WoA/wEScAAOAxBQDWoA/Wog/wEScAAPCYAgDWoA/Wog/wEScAAKQxBQDWog/WpA/wEScAANKYAgDWog/WpA/wEScAAIAaBgDWpA8hHk7wEScAAEANAwDWpA8hHk7wEScAAIAaBgDSwg8hHk7wEScAAEANAwDSwg8hHk4Fi+/w '/*!*/;
# at 1298
#170815 13:29:02 server id 200  end_log_pos 1329 CRC32 0xa6dac5dc  Xid = 56
COMMIT/*!*/;
```

1.  当使用`MIXED`格式时，`UPDATE`语句被记录为 SQL，而`INSERT`语句以基于行的格式记录，因为`INSERT`具有不确定性的`UUID()`函数：

```sql
BEGIN
/*!*/;
# at 1499
#170815 13:29:27 server id 200  end_log_pos 1646 CRC32 0xc73d68fb  Query thread_id=8 exec_time=0 error_code=0
SET TIMESTAMP=1502803767/*!*/;
UPDATE salaries SET salary=salary*2 WHERE emp_no<10002 /*!*/;
# at 1646
#170815 13:29:50 server id 200  end_log_pos 1715 CRC32 0x03ae0f7e  Table_map: `employees`.`departments` mapped to number 166
# at 1715
#170815 13:29:50 server id 200  end_log_pos 1793 CRC32 0xa43c5dac  Write_rows: table id 166 flags: STMT_END_F
BINLOG 'TveSWRPIAAAARQAAALMGAAAAAKYAAAAAAAMACWVtcGxveWVlcwALZGVwYXJ0bWVudHMAAv4PBP4QoAAAAgP8/wB+D64DTveSWR7IAAAATgAAAAEHAAAAAKYAAAAAAAEAAgAC//wEZDAxMSRkMDNhMjQwZS04MWJkLTExZTctODQxMC00MjAxMGE5NDAwMDKsXTyk '/*!*/;
# at 1793
#170815 13:29:50 server id 200  end_log_pos 1824 CRC32 0x4f63aa2e  Xid = 59
COMMIT/*!*/;
```

提取的日志可以通过管道传输到 MySQL 以重放事件。在重放二进制日志时最好使用 force 选项，因为如果它卡在某一点，它不会停止执行。稍后，您可以找出错误并手动修复数据。

```sql
shell> sudo mysqlbinlog /data/mysql/binlogs/server1.000001 | mysql -f -h <remote_host> -u <username> -p
```

或者您可以保存到文件中，以后执行：

```sql
shell> sudo mysqlbinlog /data/mysql/binlogs/server1.000001 > server1.binlog_extract
shell> cat server1.binlog_extract | mysql -h <remote_host> -u <username> -p
```

# 基于时间和位置提取

您可以通过指定位置从二进制日志中提取部分数据。假设您想进行时间点恢复。假设在`2017-08-19 12:18:00`执行了`DROP DATABASE`命令，并且最新可用的备份是`2017-08-19 12:00:00`，您已经恢复了。现在，您需要从`12:00:01`到`2017-08-19 12:17:00`恢复数据。请记住，如果您提取完整的日志，它也将包含`DROP DATABASE`命令，并且会再次擦除您的数据。

您可以通过`--start-datetime`和`--stop-datatime`选项指定时间窗口来提取数据。

```sql
shell> sudo mysqlbinlog /data/mysql/binlogs/server1.000001 --start-datetime="2017-08-19 00:00:01"  --stop-datetime="2017-08-19 12:17:00" > binlog_extract
```

使用时间窗口的缺点是您将错过灾难发生时发生的事务。为了避免这种情况，您必须使用二进制日志文件中事件的文件偏移量。

一致的备份保存了已备份的二进制日志文件偏移量。一旦备份恢复，您必须从备份提供的偏移量提取二进制日志。您将在下一章中了解更多关于备份的内容。

假设备份给出了偏移量`471`，并且`DROP DATABASE`命令在偏移量`1793`处执行。您可以使用`--start-position`和`--stop-position`选项在偏移量之间提取日志：

```sql
shell> sudo mysqlbinlog /data/mysql/binlogs/server1.000001 --start-position=471  --stop-position=1793 > binlog_extract
```

确保提取的 binlog 中不再出现`DROP DATABASE`命令。

# 基于数据库提取

使用`--database`选项，您可以过滤特定数据库的事件。如果您多次使用此选项，则只会考虑最后一个选项。这对于基于行的复制非常有效。但对于基于语句的复制和`MIXED`，只有在选择默认数据库时才会输出。

以下命令从 employees 数据库中提取事件：

```sql
shell> sudo mysqlbinlog /data/mysql/binlogs/server1.000001 --database=employees > binlog_extract
```

如 MySQL 8 参考手册中所述，假设二进制日志是通过使用基于语句的日志记录执行这些语句创建的：

```sql
mysql>
INSERT INTO test.t1 (i) VALUES(100);
INSERT INTO db2.t2 (j)  VALUES(200);

USE test;
INSERT INTO test.t1 (i) VALUES(101);
INSERT INTO t1 (i) VALUES(102);
INSERT INTO db2.t2 (j) VALUES(201);

USE db2;
INSERT INTO test.t1 (i) VALUES(103);
INSERT INTO db2.t2 (j) VALUES(202);
INSERT INTO t2 (j) VALUES(203);
```

`mysqlbinlog --database=test`不会输出前两个`INSERT`语句，因为没有默认数据库。

它会输出`USE test`后面的三个`INSERT`语句，但不会输出`USE db2`后面的三个`INSERT`语句。

`mysqlbinlog --database=db2`不会输出前两个`INSERT`语句，因为没有默认数据库。

它不会输出`USE` test 后面的三个`INSERT`语句，但会输出`USE db2`后面的三个`INSERT`语句。

# 提取行事件显示

在基于行的复制中，默认情况下显示二进制格式。要查看`ROW`信息，您必须将`--verbose`或`-v`选项传递给`mysqlbinlog`。行事件的二进制格式显示为以`###`开头的行形式的伪 SQL 语句的注释。您可以看到单个`UPDATE`语句被重写为每行的`UPDATE`语句：

```sql
shell>  mysqlbinlog /data/mysql/binlogs/server1.000001 --start-position=660 --stop-position=1298 --verbose
~
~
# at 660
#170815 13:29:02 server id 200  end_log_pos 722 CRC32 0xe0a2ec74     Table_map: `employees`.`salaries` mapped to number 165
# at 722
#170815 13:29:02 server id 200  end_log_pos 1298 CRC32 0xf0ef8b05     Update_rows: table id 165 flags: STMT_END_F

BINLOG '
HveSWRPIAAAAPgAAANICAAAAAKUAAAAAAAEACWVtcGxveWVlcwAIc2FsYXJpZXMABAMDCgoAAAEB
AHTsouA=
~
~
'/*!*/;
### UPDATE `employees`.`salaries`
### WHERE
###   @1=10001
###   @2=240468
###   @3='1986:06:26'
###   @4='1987:06:26'
### SET
###   @1=10001
###   @2=120234
###   @3='1986:06:26'
###   @4='1987:06:26'
~
~
### UPDATE `employees`.`salaries`
### WHERE
###   @1=10001
###   @2=400000
###   @3='2017:06:18'
###   @4='9999:01:01'
### SET
###   @1=10001
###   @2=200000
###   @3='2017:06:18'
###   @4='9999:01:01'
SET @@SESSION.GTID_NEXT= 'AUTOMATIC' /* added by mysqlbinlog */ /*!*/;
DELIMITER ;
# End of log file
/*!50003 SET COMPLETION_TYPE=@OLD_COMPLETION_TYPE*/;
/*!50530 SET @@SESSION.PSEUDO_SLAVE_MODE=0*/;
```

如果您只想看到伪 SQL 而不包含二进制行信息，请指定`--base64-output="decode-rows"`以及`--verbose`：

```sql
shell>  sudo mysqlbinlog /data/mysql/binlogs/server1.000001 --start-position=660 --stop-position=1298 --verbose --base64-output="decode-rows"
/*!50530 SET @@SESSION.PSEUDO_SLAVE_MODE=1*/;
/*!50003 SET @OLD_COMPLETION_TYPE=@@COMPLETION_TYPE,COMPLETION_TYPE=0*/;
DELIMITER /*!*/;
# at 660
#170815 13:29:02 server id 200  end_log_pos 722 CRC32 0xe0a2ec74     Table_map: `employees`.`salaries` mapped to number 165
# at 722
#170815 13:29:02 server id 200  end_log_pos 1298 CRC32 0xf0ef8b05     Update_rows: table id 165 flags: STMT_END_F
### UPDATE `employees`.`salaries`
### WHERE
###   @1=10001
###   @2=240468
###   @3='1986:06:26'
###   @4='1987:06:26'
### SET
###   @1=10001
###   @2=120234
###   @3='1986:06:26'
###   @4='1987:06:26'
~
```

# 重写数据库名称

假设您希望将生产服务器上的`employees`数据库的二进制日志还原为开发服务器上的`employees_dev`。您可以使用`--rewrite-db='from_name->to_name'`选项。这将重写所有`from_name`到`to_name`的出现。

要转换多个数据库，请多次指定该选项：

```sql
shell> sudo mysqlbinlog /data/mysql/binlogs/server1.000001 --start-position=1499 --stop-position=1646 --rewrite-db='employees->employees_dev'
~
# at 1499
#170815 13:29:27 server id 200  end_log_pos 1646 CRC32 0xc73d68fb     Query    thread_id=8    exec_time=0    error_code=0
use `employees_dev`/*!*/;
~
~
UPDATE salaries SET salary=salary*2 WHERE emp_no<10002
/*!*/;
SET @@SESSION.GTID_NEXT= 'AUTOMATIC' /* added by mysqlbinlog */ /*!*/;
DELIMITER ;
# End of log file
~
```

您可以看到语句`use `employees_dev`/*!*/;`被使用。因此，在还原时，所有更改将应用于`employees_dev`数据库。

如 MySQL 参考手册中所述：

当与`--database`选项一起使用时，首先应用`--rewrite-db`选项，然后使用重写后的数据库名称应用`--database`选项。在这方面，提供选项的顺序没有任何区别。这意味着，例如，如果使用`--rewrite-db='mydb->yourdb' --database=yourdb`启动`mysqlbinlog`，则`mydb`和`yourdb`数据库中任何表的所有更新都包含在输出中。

另一方面，如果使用`--rewrite-db='mydb->yourdb' --database=mydb`启动，则`mysqlbinlog`根本不输出语句：因为在应用`--database`选项之前，对`mydb`的所有更新都首先被重写为对`yourdb`的更新，因此没有更新与`--database=mydb`匹配。

# 禁用二进制日志以进行恢复

在还原二进制日志时，如果您不希望`mysqlbinlog`进程创建二进制日志，您可以使用`--disable-log-bin`选项，以便不写入二进制日志：

```sql
shell> sudo mysqlbinlog /data/mysql/binlogs/server1.000001 --start-position=660 --stop-position=1298 --disable-log-bin > binlog_restore
```

您可以看到`SQL_LOG_BIN=0`被写入`binlog`还原文件，这将阻止创建 binlogs。

`/*!32316 SET @OLD_SQL_LOG_BIN=@@SQL_LOG_BIN, SQL_LOG_BIN=0*/;`

# 显示二进制日志文件中的事件

除了使用`mysqlbinlog`，您还可以使用`SHOW BINLOG EVENTS`命令来显示事件。

以下命令将显示`server1.000008`二进制日志中的事件。如果未指定`LIMIT`，则显示所有事件：

```sql
mysql> SHOW BINLOG EVENTS IN 'server1.000008' LIMIT 10; +----------------+-----+----------------+-----------+-------------+------------------------------------------+
| Log_name       | Pos | Event_type     | Server_id | End_log_pos | Info                                     |
+----------------+-----+----------------+-----------+-------------+------------------------------------------+
| server1.000008 |   4 | Format_desc    |       200 |         123 | Server ver: 8.0.3-rc-log, Binlog ver: 4 |
| server1.000008 | 123 | Previous_gtids |       200 |         154 |                                          |
| server1.000008 | 154 | Anonymous_Gtid |       200 |         226 | SET @@SESSION.GTID_NEXT= 'ANONYMOUS'     |
| server1.000008 | 226 | Query          |       200 |         336 | drop database company /* xid=4134 */     |
| server1.000008 | 336 | Anonymous_Gtid |       200 |         408 | SET @@SESSION.GTID_NEXT= 'ANONYMOUS'     |
| server1.000008 | 408 | Query          |       200 |         485 | BEGIN                                    |
| server1.000008 | 485 | Table_map      |       200 |         549 | table_id: 975 (employees.emp_details)    |
| server1.000008 | 549 | Write_rows     |       200 |         804 | table_id: 975 flags: STMT_END_F          |
| server1.000008 | 804 | Xid            |       200 |         835 | COMMIT /* xid=9751 */                    |
| server1.000008 | 835 | Anonymous_Gtid |       200 |         907 | SET @@SESSION.GTID_NEXT= 'ANONYMOUS'     |
+----------------+-----+----------------+-----------+-------------+------------------------------------------+
10 rows in set (0.00 sec)

```

您还可以指定位置和偏移量：

```sql
mysql> SHOW BINLOG EVENTS IN 'server1.000008' FROM 123 LIMIT 2,1; +----------------+-----+------------+-----------+-------------+--------------------------------------+
| Log_name       | Pos | Event_type | Server_id | End_log_pos | Info                                 |
+----------------+-----+------------+-----------+-------------+--------------------------------------+
| server1.000008 | 226 | Query      |       200 |         336 | drop database company /* xid=4134 */ |
+----------------+-----+------------+-----------+-------------+--------------------------------------+
1 row in set (0.00 sec)
```

# 忽略写入二进制日志的数据库

您可以通过在`my.cnf`中指定`--binlog-do-db=db_name`选项来选择应写入二进制日志的数据库。要指定多个数据库，*必须*使用此选项的多个实例。因为数据库名称可以包含逗号，如果提供逗号分隔的列表，该列表将被视为单个数据库的名称。您需要重新启动 MySQL 服务器才能生效。

# 如何操作...

打开`my.cnf`并添加以下行：

```sql
shell> sudo vi /etc/my.cnf
[mysqld]
binlog_do_db=db1
binlog_do_db=db2
```

`binlog-do-db`的行为从基于语句的日志记录更改为基于行的日志记录，就像`mysqlbinlog`实用程序中的`--database`选项一样。

在基于语句的日志记录中，只有那些默认数据库（即由`USE`选择的数据库）写入二进制日志的语句才会被写入。在使用基于语句的日志记录时，使用`binlog-do-db`选项时要非常小心，因为它的工作方式与您在使用基于语句的日志记录时所期望的方式不同。请参阅参考手册中提到的以下示例。

# 示例 1

如果服务器是使用`--binlog-do-db=sales`启动的，并且您发出以下语句，则`UPDATE`语句不会被记录：

```sql
mysql> USE prices;
mysql> UPDATE sales.january SET amount=amount+1000;
```

这种*只检查默认数据库*行为的主要原因是，仅从语句本身很难知道是否应该复制它。如果没有必要，仅检查默认数据库而不是所有数据库也更快。

# 示例 2

如果服务器是使用`--binlog-do-db=sales`启动的，则即使在设置`--binlog-do-db`时未包括价格，以下`UPDATE`语句也会被记录：

```sql
mysql> USE sales;
mysql> UPDATE prices.discounts SET percentage = percentage + 10;
```

当发出`UPDATE`语句时，因为销售是默认数据库，所以`UPDATE`被记录在日志中。

在基于行的日志记录中，它受到数据库`db_name`的限制。只有属于`db_name`的表的更改才会被记录；默认数据库对此没有影响。

`--binlog-do-db`在基于语句的日志记录中处理的另一个重要区别与基于行的日志记录有关，这涉及到引用多个数据库的语句。假设服务器是使用`--binlog-do-db=db1`启动的，并且执行了以下语句：

```sql
mysql> USE db1;
mysql> UPDATE db1.table1 SET col1 = 10, db2.table2 SET col2 = 20;
```

如果您使用基于语句的日志记录，则两个表的更新都将写入二进制日志。但是，使用基于行的格式时，只有`table1`的更改被记录；`table2`位于不同的数据库中，因此不会受到`UPDATE`的影响。

同样，您可以使用`--binlog-ignore-db=db_name`选项来忽略写入二进制日志的数据库。

有关更多信息，请参阅手册：[`dev.mysql.com/doc/refman/8.0/en/replication-rules.html`](https://dev.mysql.com/doc/refman/8.0/en/replication-rules.html)。

# 重新定位二进制日志

由于二进制日志占用更多空间，有时您可能希望更改二进制日志的位置，以下过程有所帮助。仅更改`log_bin`是不够的，您必须移动所有二进制日志并使用新位置更新索引文件。`mysqlbinlogmove`实用程序通过自动化这些任务来简化您的工作。

# 如何操作...

安装 MySQL Utilities 以使用`mysqlbinlogmove`脚本。有关安装步骤，请参阅第一章，*MySQL 8.0 – Installing and Upgrading*。

1.  停止 MySQL 服务器：

```sql
shell> sudo systemctl stop mysql
```

1.  启动`mysqlbinlogmove`实用程序。如果要将二进制日志从`/data/mysql/binlogs`更改为`/binlogs`，则应使用以下命令。如果您的基本名称不是默认值，则必须通过`--bin-log-base name`选项提及您的基本名称：

```sql
shell> sudo mysqlbinlogmove --bin-log-base name=server1  --binlog-dir=/data/mysql/binlogs /binlogs
#
# Moving bin-log files...
# - server1.000001
# - server1.000002
# - server1.000003
# - server1.000004
# - server1.000005
#
#...done.
#
```

1.  编辑`my.cnf`文件并更新`log_bin`的新位置：

```sql
shell> sudo vi /etc/my.cnf
[mysqld]
log_bin=/binlogs
```

1.  启动 MySQL 服务器：

```sql
shell> sudo systemctl start mysql
```

新位置在 AppArmor 或 SELinux 中得到更新。

如果有很多二进制日志，服务器的停机时间会很长。为了避免这种情况，您可以使用`--server`选项来重新定位除当前正在使用的日志之外的所有二进制日志（具有更高的序列号）。然后停止服务器，使用前面的方法，重新定位最后一个二进制日志，这将会快得多，因为只有一个文件在那里。然后您可以更改`my.cnf`并启动服务器。

例如：

```sql
shell> sudo mysqlbinlogmove --server=root:pass@host1:3306 /new/location
```
