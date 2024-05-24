# PHP、MySQL 和 JavaScript 快速 Web 开发（二）

> 原文：[`zh.annas-archive.org/md5/cfad008c082876a608d45b61650bee20`](https://zh.annas-archive.org/md5/cfad008c082876a608d45b61650bee20)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：测量和优化数据库性能

在本书的第一章中，我们使用 mysqlslap 工具学习了如何进行基本的 MySQL 基准测试。在本章中，我们将使用这个工具和其他工具来对我们的 MariaDB（MySQL）服务器进行更高级的基准测试。但首先，我们将学习查询优化技术，这些技术将使用 MySQL 的一些内置功能，以便更好地分析我们的 SQL 查询。

因此，我们将学习如何通过使用简单的测量技术来测量和优化数据库性能，例如查询优化。此外，我们将看到如何使用高级数据库基准测试工具，如 DBT2 和 SysBench。

因此，我们将涵盖以下几点：

+   测量和优化 SQL 查询性能

+   安装、配置和使用高级数据库基准测试工具

# SQL 查询性能

为了更好地理解 SQL 查询性能，我们必须首先了解索引是什么以及它们是如何构建的。

# 索引的结构

索引是表元素的有序列表。这些元素首先存储在物理上无序的双向链表中。该列表通过指向表条目和存储索引值的第二个结构的指针双向链接到表，以逻辑顺序、平衡树或 b 树存储索引值。因此，索引具有对数算法复杂度，平均读操作为 O(log n)，这意味着即使表中有大量条目，数据库引擎也应该保持速度。实际上，索引查找涉及三个步骤：

+   树遍历

+   搜索叶节点链

+   从表中获取数据

因此，当仅从 b 树中读取时，索引查找是很好的，因为你避免了线性的 O(n)完整表扫描。尽管如此，你永远无法避免由于在写入表时保持索引最新而引起的开销复杂性。

这带我们来到了关于查询优化的第一个考虑因素：表的数据的最终目的是什么？我们只是记录信息还是存储用户的购物车商品？我们查询的表大多是读取还是写入？这很重要，因为优化一个 SELECT 查询可能会减慢对同一表的整个系列其他 INSERT 或 UPDATE 查询的速度。

第二个考虑因素是表的数据的性质。例如，我们是否试图索引生成等价性的值，从而迫使数据库引擎在 b 树的叶节点中进行进一步查找，以确定真正满足特定查询期望的所有值？当等价性是一个问题时，我们可能会得到一个“慢索引”或者通常被称为“退化索引”。

第三个考虑因素是围绕查询表的效率的经济性。底层计算机有多强大？平均有多少用户在给定时间查询表？可伸缩性重要吗？

最后一个考虑因素是数据的存储大小。重要的是要知道，一般规则是，索引的大小平均增长到原始表大小的约 10%。因此，当表的大小很大时，预计表的索引也会更大。当然，索引越大，由于 I/O 延迟，等待的时间就越长。

这些考虑因素将决定要优化哪个查询以及如何优化它。有时，优化就是什么都不做。

现在我们更好地理解了索引，让我们开始分析简单的 SQL 查询，以了解数据库引擎执行计划。

# 执行计划

我们将通过分析简单的`WHERE`子句来开始理解执行计划。为此，我们将使用我们的第一个 Linux for PHP Docker 容器。在第一章中，我们将 Sakila 数据库加载到 MariaDB（MySQL）服务器中。现在我们将使用它来学习执行计划的工作原理以及何时使用查询优化技术。在容器的 CLI 上，输入以下命令：

```php
# mysql -uroot 
# MariaDB > USE sakila; 
# MariaDB > SELECT * FROM actor WHERE first_name = 'AL'; 
```

这些命令应该产生以下结果：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/c6ff4e46-8bc9-4631-a7e4-89980e967449.png)SELECT 语句的结果

乍一看，这个查询似乎很好，执行时间为 0.00 秒。但是，这真的是这样吗？要进一步分析这个查询，我们需要查看数据库引擎的执行计划。为此，在查询开头输入关键字`EXPLAIN`：

```php
 # MariaDB > EXPLAIN SELECT * FROM actor WHERE first_name = 'AL'; 
```

以下结果为我们提供了一些执行计划的信息：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/1958748c-a572-4ccb-b21f-ed4b2bf1d60b.png)相同 SELECT 语句的执行计划

让我们花时间来定义结果集的每一列：

+   `id`列告诉我们表的连接顺序。在这种情况下，只有一个表。

+   `select_type`是`SIMPLE`，这意味着执行此查询时没有子查询、联合或依赖查询类型。

+   `table`列给出了查询对象的表的名称。如果它是一个临时物化表，我们会在这一列看到表达式`<subquery#>`。

+   `type`列对于查询优化非常重要。它提供了关于表访问以及如何从表中找到和检索行的信息。在这种情况下，我们看到这一列的值是`ALL`，这是一个警告信号。要进一步了解这个非常重要的列的不同可能值，请参阅 MariaDB 手册[`mariadb.com/kb/en/library/explain/`](https://mariadb.com/kb/en/library/explain/)。

+   `possible_keys`列通知我们表中可以用来回答查询的键。在这个例子中，值为`NULL`。

+   `key`列指示实际使用的键。在这里，值再次为`NULL`。

+   `key_len`列中的值表示完成查询查找所使用的多列键的特定字节数。

+   `ref`列告诉我们用于与使用的索引进行比较的列或常量。当然，由于没有使用索引来执行此查询，因此这一列的值也是`NULL`。

+   `rows`列表示数据库引擎需要检查的行数以完成其执行计划。在这个例子中，引擎需要检查 200 行。如果表很大并且必须与前一个表连接，性能会迅速下降。

+   最后一列是`Extra`列。这一列将为我们提供有关执行计划的更多信息。在这个例子中，数据库引擎使用`WHERE`子句，因为它必须进行全表扫描。

# 基本查询优化

为了开始优化这个查询，我们必须经历我之前所说的查询优化的*初始考虑*。举例来说，让我们假设这个表将成为`READ`查询的对象，而不是`WRITE`查询，因为一旦写入表中，数据将保持相当静态。此外，重要的是要注意，在`actor`表的`first_name`列上创建索引将使索引容易产生由于该列中的非唯一值而产生的模糊性。此外，让我们假设可伸缩性很重要，因为我们打算每小时让许多用户查询这个表，并且表的大小应该在长期内保持可管理。

鉴于这一点，我们将在`actor`表的`first_name`列上创建一个索引：

```php
 # MariaDB > CREATE INDEX idx_first_name ON actor(first_name); 
```

完成后，MariaDB 确认了索引的创建：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/da6584c8-040d-4242-aecf-9778747dbeb5.png)确认索引已创建

现在索引已创建，当我们要求数据库引擎“解释”其执行计划时，我们得到了这个结果：

执行计划现在已经优化

`type`列的值现在是`ref`，`possible_keys`是`idx_first_name`，`key`是`idx_first_name`，`ref`是`const`，`rows`是`1`，`Extra`是`Using index condition`。正如我们所看到的，引擎现在已经将我们新创建的索引识别为可能使用的关键，并继续使用它。它使用查询中给定的常量值在索引中执行查找，并在访问表时只考虑一行。所有这些都很好，但正如我们在最初的考虑中所期望的那样，索引由非唯一值组成。表列的值之间可能的等价性可能会导致随着时间的推移出现退化的索引，因此访问类型为`ref`，额外信息指示引擎正在“使用索引条件”，这意味着`WHERE`子句被推送到表引擎以在索引级别进行优化。在这个例子中，根据我们最初的考虑，这是在绝对意义上我们可以做的最佳查询优化，因为在“actor”表的`first_name`列中不可能获得唯一值。但实际上，根据领域使用情况，可能存在一种优化。如果我们只希望使用演员的名字，那么我们可以通过只选择适当的列来进一步优化`Extra`列中的`Using index condition`，从而允许数据库引擎只访问索引：

```php
 # MariaDB > EXPLAIN SELECT first_name FROM actor WHERE first_name = 'AL'; 
```

数据库引擎随后确认它只在`Extra`列中使用索引：

“Extra”列现在包含信息“使用 where; 使用索引”

这一切又如何转化为整体性能呢？让我们运行一些基准测试，以衡量我们的更改的影响。

首先，我们将在没有索引的情况下运行基准测试。在容器的 CLI 上运行以下命令：

```php
# mysqlslap --user=root --host=localhost --concurrency=1000 --number-of-queries=10000 --create-schema=sakila --query="SELECT * FROM actor WHERE first_name = 'AL';" --delimiter=";" --verbose --iterations=2 --debug-info;
```

以下是不使用索引的结果：

不使用索引的基准测试结果

以及，使用索引的结果：

使用索引的基准测试结果

最后，让我们只选择适当的列运行相同的命令，从而将查找限制为仅使用索引：

```php
# mysqlslap --user=root --host=localhost --concurrency=1000 --number-of-queries=10000 --create-schema=sakila --query="SELECT first_name FROM actor WHERE first_name = 'AL';" --delimiter=";" --verbose --iterations=2 --debug-info; 
```

这是最后一个基准测试的结果：

使用索引的基准测试结果

基准测试结果清楚地显示，我们的查询优化确实满足了我们最初的可扩展性假设，特别是如果我们看到表的大小增长，随着时间的推移，我们的数据库变得更受欢迎，用户数量也在增长。

# 性能模式和高级查询优化

查询优化的艺术可以通过使用 MariaDB（MySQL）的性能模式来进一步推进。查询分析允许我们看到发生在幕后的情况，并进一步优化复杂的查询。

首先，让我们在数据库服务器上启用性能模式。为此，请在 Linux 的 PHP 容器的 CLI 上输入以下命令：

```php
# sed -i '/myisam_sort_buffer_size =/a performance_schema = ON' /etc/mysql/my.cnf  
# sed -i '/performance_schema =/a performance-schema-instrument = "stage/%=ON"' /etc/mysql/my.cnf 
# sed -i '/performance-schema-instrument =/a performance-schema-consumer-events-stages-current = ON' /etc/mysql/my.cnf 
# sed -i '/performance-schema-consumer-events-stages-current =/a performance-schema-consumer-events-stages-history = ON' /etc/mysql/my.cnf 
# sed -i '/performance-schema-consumer-events-stages-history =/a performance-schema-consumer-events-stages-history-long = ON' /etc/mysql/my.cnf 
# /etc/init.d/mysql restart 
# mysql -uroot 
# MariaDB > USE performance_schema; 
# MariaDB > UPDATE setup_instruments SET ENABLED = 'YES', TIMED = 'YES'; 
# MariaDB > UPDATE setup_consumers SET ENABLED = 'YES'; 
```

数据库引擎将确认在`performance_schema`数据库中已修改了一些行：

“performance_schema”数据库已被修改

我们现在可以检查性能模式是否已启用：

```php
# MariaDB > SHOW VARIABLES LIKE 'performance_schema'; 
```

数据库引擎应返回以下结果：

确认性能模式现已启用

现在，性能分析已经启用并准备就绪，让我们在 Sakila 数据库上运行一个复杂的查询。在使用`NOT IN`子句的子查询时，引擎通常会迭代地对主查询进行额外的检查。这些查询可以使用`JOIN`语句进行优化。我们将使用以下查询在我们的数据库服务器上运行：

```php
# MariaDB > SELECT film.film_id 
          > FROM film 
          > WHERE film.rating = 'G' 
          > AND film.film_id NOT IN ( 
              > SELECT film.film_id 
              > FROM rental 
              > LEFT JOIN inventory ON rental.inventory_id = inventory.inventory_id 
              > LEFT JOIN film ON inventory.film_id = film.film_id 
          > ); 
```

运行查询会产生以下结果：

SELECT 语句的结果

并且，在上一个查询上使用`EXPLAIN`语句时的结果如下：

同一 SELECT 语句的执行计划

正如我们所看到的，引擎正在进行全表扫描，并使用一个物化子查询来完成其查找。要了解底层发生了什么，我们将不得不查看分析器记录的有关此查询的事件。为此，请输入以下查询：

```php
# MariaDB > SELECT EVENT_ID, TRUNCATE(TIMER_WAIT/1000000000000,6) as Duration, SQL_TEXT 
          > FROM performance_schema.events_statements_history_long WHERE SQL_TEXT like 
 '%NOT IN%'; 
```

运行此查询后，您将获得原始查询的唯一标识符：

原始查询的标识符

这些信息允许我们运行以下查询，以获取运行原始查询时发生的底层事件列表：

```php
# MariaDB > SELECT event_name AS Stage, TRUNCATE(TIMER_WAIT/1000000000000,6) AS Duration 
          > FROM performance_schema.events_stages_history_long WHERE NESTING_EVENT_ID=43; 
```

这是 MariaDB 性能模式中关于我们原始查询的内容：

查询的概要显示了一个特别长的操作

这个结果显示`NOT IN`子句导致数据库引擎创建了一个物化子查询，因为内部查询被优化为半连接子查询。因此，在运行查询和物化子查询之前，引擎必须进行一些优化操作。此外，结果显示物化子查询是最昂贵的操作。

优化这些子查询的最简单方法是将它们替换为主查询中的适当`JOIN`语句，如下所示：

```php
# MariaDB > SELECT film.film_id 
#         > FROM rental 
#         > INNER JOIN inventory ON rental.inventory_id = inventory.inventory_id 
#         > RIGHT JOIN film ON inventory.film_id = film.film_id 
#         > WHERE film.rating = 'G' 
#         > AND rental.rental_id IS NULL 
#         > GROUP BY film.film_id; 
```

通过运行此查询，我们从数据库中获得相同的结果，但是`EXPLAIN`语句揭示了一个全新的执行计划，以获得完全相同的结果：

新的执行计划只显示了“SIMPLE”选择类型

子查询已经消失，变成了简单的查询。让我们看看性能模式这次记录了什么：

```php
# MariaDB > SELECT EVENT_ID, TRUNCATE(TIMER_WAIT/1000000000000,6) as Duration, SQL_TEXT 
          > FROM performance_schema.events_statements_history_long WHERE SQL_TEXT like '%GROUP BY%'; 
# MariaDB > SELECT event_name AS Stage, TRUNCATE(TIMER_WAIT/1000000000000,6) AS Duration 
          > FROM performance_schema.events_stages_history_long WHERE NESTING_EVENT_ID=22717; 
```

分析器记录了以下结果：

新查询的概要显示了相当大的性能改进

结果清楚地显示，在执行计划的初始化阶段发生的优化操作较少，并且查询执行本身大约快了七倍。并非所有物化子查询都可以以这种方式进行优化，但是，在优化查询时，物化子查询、依赖子查询或不可缓存的子查询应该总是激励我们问自己是否可以做得更好。

有关查询优化的更多信息，您可以收听 Michael Moussa 在*Nomad PHP*上关于此主题的出色演示（[`nomadphp.com/product/mysql-analysis-understanding-optimization-queries/`](https://nomadphp.com/product/mysql-analysis-understanding-optimization-queries/)）。

# 高级基准测试工具

到目前为止，我们使用了`mysqlslap`基准测试工具。但是，如果您需要更彻底地测试数据库服务器，还存在其他更高级的基准测试工具。我们将简要介绍其中两个工具：DBT2 和 SysBench。

# DBT2

这个基准测试工具用于针对 MySQL 服务器运行自动化基准测试。它允许您模拟大量的数据仓库。

要下载、编译和安装 DBT2，请在容器的 CLI 上输入以下命令：

```php
# cd /srv/www
# wget -O dbt2-0.37.tar.gz https://master.dl.sourceforge.net/project/osdldbt/dbt2/0.37/dbt2-0.37.tar.gz 
# tar -xvf dbt2-0.37.tar.gz 
# cd dbt2-0.37.tar.gz 
# ./configure --with-mysql 
# make 
# make install 
# cpan install Statistics::Descriptive 
# mkdir -p /srv/mysql/dbt2-tmp-data/dbt2-w3 
# ./src/datagen -w 3 -d /srv/mysql/dbt2-tmp-data/dbt2-w3 --mysql 
```

一旦数据仓库被创建，您应该看到以下消息：

确认数据库仓库已经创建。

现在，您需要使用 vi 编辑器修改文件`scripts/mysql/mysql_load_db.sh`：

```php
# vi scripts/mysql/mysql_load_db.sh 
```

进入编辑器后，输入`/LOAD DATA`并按*Enter*。将光标定位在此行的末尾，按`*I*`并输入大写的`IGNORE`。编辑完成后，您的文件应该是这样的：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/eaf14be8-ed22-41b0-8fa6-7e582f14ca29.png)在'mysql_load_db.sh'脚本的'LOAD DATA'行上插入字符串"Ignore"

完成后，按*Esc*键，然后输入`:wq`。这将保存更改并关闭 vi 编辑器。

现在，输入以下命令将测试数据加载到数据库中：

```php
# ./scripts/mysql/mysql_load_db.sh -d dbt2 -f /srv/mysql/dbt2-tmp-data/dbt2-w3 -s /run/mysqld/mysqld.sock -u root 
```

一旦数据加载到数据库中，您应该会看到以下消息：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/a892a632-2f5b-4892-8cce-6008167b2eb8.png)确认数据正在加载到数据库中

要启动测试，输入以下命令：

```php
# ./scripts/run_mysql.sh -n dbt2 -o /run/mysqld/mysqld.sock -u root -w 3 -t 300 -c 20 
```

输入命令后，您将首先看到这条消息：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/e1b03e63-3a1a-4d00-8d98-029e48929aac.png)确认测试已开始

您还会收到以下消息：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/c7de45f4-984c-4ee5-876c-e1da8f1af596.png)确认测试正在运行

大约五分钟后，您将得到基准测试的结果：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/c43b7135-035f-4634-b870-c451b74939a6.png)确认测试已完成

从给定的结果中，我们可以看到在大型数据仓库的背景下，我们可以对数据库服务器的性能有一个很好的了解。通过边缘案例测试，额外的测试可以轻松确认服务器的极限。让我们使用 SysBench 运行这样的测试。

# SysBench

SysBench 是另一个非常流行的开源基准测试工具。这个工具不仅允许您测试开源 RDBMS，还可以测试您的硬件（CPU、I/O 等）。

要下载、编译和安装 SysBench，请在 Linux for PHP Docker 容器中输入以下命令：

```php
# cd /srv/www
# wget -O sysbench-0.4.12.14.tar.gz https://downloads.mysql.com/source/sysbench-0.4.12.14.tar.gz 
# tar -xvf sysbench-0.4.12.14.tar.gz 
# cd sysbench-0.4.12.14 
# ./configure 
# make 
# make install 
```

现在，输入以下命令将创建一个包含 100 万行的表作为测试数据加载到数据库中：

```php
# sysbench --test=oltp --oltp-table-size=1000000 --mysql-db=test --mysql-user=root prepare 
```

一旦数据加载到数据库中，您应该会看到以下消息：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/0eb6eee6-2020-4ae0-8e10-7ac10fbe7a04.png)确认测试数据已加载到数据库中

现在，运行测试，输入以下命令：

```php
# sysbench --test=oltp --oltp-table-size=1000000 --mysql-db=test --mysql-user=root --max-time=60 --oltp-read-only=on --max-requests=0 --num-threads=8 run 
```

输入上一个命令后，您将首先收到以下消息：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/69a93d24-c499-4d1e-ae12-1e31dbf2de7d.png)确认测试正在运行

几分钟后，您应该会得到类似于以下结果：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/9914961f-d1d6-405e-9167-a12a46df3bb6.png)SysBench 测试结果

结果显示，我的计算机上的 MariaDB 服务器大约可以处理每秒约 2300 次事务和每秒约 33000 次读/写请求。这些边缘案例测试可以让我们对硬件和数据库服务器的一般性能水平有一个很好的了解。

# 摘要

在本章中，我们已经学会了如何通过简单的测量技术（如查询优化）来衡量和优化数据库性能。此外，我们还看到了如何使用高级数据库基准测试工具，如 DBT2 和 SysBench。

在下一章中，我们将看到如何使用现代 SQL 技术来优化非常复杂的 SQL 查询。


# 第六章：高效查询现代 SQL 数据库

现在，我们将学习如何使用现代 SQL 高效地查询 SQL 数据库。在本章中，我们将定义现代 SQL 是什么以及如何使用它。我们将从定义现代 SQL 的概念开始，了解它与传统 SQL 的区别，并描述许多其特点。因此，我们将了解如何将某些传统 SQL 查询转换为现代查询以及何时最好这样做。此外，通过这样做，我们将更好地了解现代 SQL 如何帮助我们以多种方式优化服务器性能。

因此，我们将涵盖以下内容：

+   了解现代 SQL 及其特点

+   学习如何使用`WITH`和`WITH RECURSIVE`、`CASE`、`OVER AND PARTITION BY`、`OVER AND ORDER BY`、GROUPING SETS、JSON 子句和函数、`FILTER`和`LATERAL`查询。

# 现代 SQL

现代 SQL 是什么，它与传统 SQL 有何不同？它的主要特点是什么？让我们从定义概念开始。

# 定义

正如 Markus Winand 在他的网站[`modern-sql.com`](https://modern-sql.com)上所述，现代 SQL 可以被定义为“*一种国际标准化、广泛可用且图灵完备的数据处理语言，支持关系和非关系数据模型*。”这个定义指的是 ISO 和 ANSI 组织多年来推广的一系列标准，并为 SQL 编程语言添加了新功能。自 SQL-92 以来，SQL 标准的许多新版本被采纳，并且这些标准引入了许多基于关系和非关系模型的新功能。以下是这些功能的简要列表，以及确认它们被采纳到 SQL 语言中的相应标准：

+   `WITH`和`WITH RECURSIVE`（SQL：1999）

+   `CASE`（SQL：1999 和 SQL：2003）

+   `OVER AND PARTITION BY`（SQL：2003 和 SQL：2011）

+   `OVER AND ORDER BY`（SQL：2003 和 SQL：2011）

+   GROUPING SETS（SQL：2011）

+   JSON 子句和函数（SQL：2016）

+   `FILTER`（SQL：2003）

+   `LATERAL`查询（SQL：1999）

值得注意的是，大多数这些功能直到最近才被大多数关系数据库管理系统（RDBMS）实现。大多数 RDBMS 仅为其用户提供了基于老化的 SQL-92 标准所推广的关系模型的传统 SQL 语言。直到最近几年，许多 RDBMS 才开始实现现代 SQL 功能。

此外，让我们提出警告：使用这些功能不会立即为您的数据库服务器带来巨大的性能提升。那么，在您的代码库中使用这些功能的意义是什么？目的是使您的代码库与未来的数据库引擎优化兼容，并避免大多数与慢查询执行相关的问题。

但在进一步了解新的 SQL 功能之前，我们将在我们的 Linux 中为 PHP 容器安装`phpMyAdmin`，以便以用户友好的方式查看我们查询的结果。为此，请在容器的 CLI 上输入以下命令：

```php
# rm /srv/www
# ln -s /srv/fasterweb/chapter_6 /srv/www
# cd /srv
# wget -O phpMyAdmin-4.7.7-all-languages.zip https://files.phpmyadmin.net/phpMyAdmin/4.7.7/phpMyAdmin-4.7.7-all-languages.zip
# unzip phpMyAdmin-4.7.7-all-languages.zip
# cp phpMyAdmin-4.7.7-all-languages/config.sample.inc.php phpMyAdmin-4.7.7-all-languages/config.inc.php
# sed -i "s/AllowNoPassword'] = false/AllowNoPassword'] = true/" phpMyAdmin-4.7.7-all-languages/config.inc.php
# cd fasterweb/chapter_6
# ln -s ../../phpMyAdmin-4.7.7-all-languages ./phpmyadmin  
```

这些命令应该可以让您通过 Web 界面访问数据库服务器，网址为`http://localhost:8181/phpmyadmin`。在您喜欢的浏览器中访问此地址时，您应该看到以下屏幕：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/a0aac6ea-6f8d-4787-a740-eb10c29e4428.png)在 phpMyAdmin 的登录页面上输入用户名和密码

安装`phpMyAdmin`后，您可以使用用户名`root`和空密码登录到数据库服务器。

现在，让我们更详细地了解每一个新的 SQL 功能。

# WITH 和 WITH RECURSIVE

第一个功能是所谓的**公共表达式**（**CTE**）。CTE 是一个临时结果集，允许您多次将相同的数据连接到自身。有两种类型的 CTE：非递归（`WITH`）和递归（`WITH RECURSIVE`）。

非递归类型的 CTE 就像派生表一样，允许您从临时结果集中`SELECT`。一个简单的例子，使用一个虚构的员工表，将是：

```php
WITH accountants AS (
  SELECT id, first_name, last_name
  FROM staff
  WHERE dept = 'accounting'
)
SELECT id, first_name, last_name
FROM accountants;
```

递归类型的 CTE 由两部分组成。查询的第一部分称为 CTE 的锚成员。锚的结果集被认为是基本结果集（T[0]）。第二部分是递归成员，它将以 T[i]作为输入和 T[i+1]作为输出运行，直到返回一个空的结果集。查询的最终结果集将是递归结果集（T[n）和锚（T[0]）之间的`UNION ALL`。

为了更好地理解递归 CTE 以及它们可以有多么有用，让我们举个例子。但在开始之前，让我们先将以下表加载到测试数据库中。在容器的 CLI 中，输入此命令：

```php
# mysql -uroot test < /srv/www/employees.sql 
```

完成后，您可以通过使用`phpMyAdmin`打开数据库来确保一切都加载正确，如下所示：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/5f8e9316-5aeb-4914-9e5d-428303e40b4c.png)测试数据库中员工表中找到的所有行

为了更好地理解 CTE，我们将从使用具有多个连接的基本查询开始，以获得分层结果集。为了仅基于数据库中员工记录中经理 ID 的存在来获取员工的整个层次结构，我们必须考虑使用多个连接到同一表的查询。在 SQL 选项卡中，输入此查询：

```php
SELECT CONCAT_WS('->', t1.last_name, t2.last_name, t3.last_name, t4.last_name, t5.last_name, t6.last_name) AS path
FROM employees AS t1
RIGHT JOIN employees AS t2 ON t2.superior = t1.id
RIGHT JOIN employees AS t3 ON t3.superior = t2.id
RIGHT JOIN employees AS t4 ON t4.superior = t3.id
RIGHT JOIN employees AS t5 ON t5.superior = t4.id
RIGHT JOIN employees AS t6 ON t6.superior = t5.id
WHERE t1.superior IS NULL
ORDER BY path;
```

您将获得这个结果集：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/c5516de5-df0b-41d3-8bff-c9321342231e.png)使用连接语句生成的所有员工的分层树

首先要注意的是，这个查询假设我们事先知道这个层次结构中的级别数量，这意味着我们之前做了一个查询来确认关于我们数据集的这个事实。第二件事是，为了检索整个结果集，必须重复`JOIN`子句的笨拙。递归 CTE 是优化这种查询的完美方式。要使用递归 CTE 获得完全相同的结果集，我们必须运行以下查询：

```php
WITH RECURSIVE hierarchy_list AS (
  SELECT id, superior, CONVERT(last_name, CHAR(100)) AS path
  FROM employees
  WHERE superior IS NULL
  UNION ALL
  SELECT child.id, child.superior, CONVERT(CONCAT(parent.path, '->', child.last_name), CHAR(100)) AS path
  FROM employees AS child
  INNER JOIN hierarchy_list AS parent ON (child.superior = parent.id)
)
SELECT path
FROM hierarchy_list
ORDER BY path;
```

如果我们通过运行它们针对 MariaDB 的性能模式来比较前两个查询，即使它们不提供有关我们层次结构中级别动态发现的相同功能，我们也会更好地了解底层发生了什么。

首先，让我们使用`EXPLAIN`语句运行多个连接查询：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/f4eb1ecc-c582-40ef-8fb8-f9e4e112e77a.png)MariaDB 的连接语句查询执行计划

现在来看一下 RDBMS 的性能模式：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/8fc22b94-631c-4e12-a209-4d3447747a98.png)多个连接导致数据库引擎中的 65 个操作

其次，让我们按照相同的步骤进行，但使用递归 CTE：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/f055c2ca-730c-4af5-b8e7-f9504a5793b2.png)MariaDB 的递归 CTE 查询执行计划

而性能模式应该产生以下结果：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/b0996943-fe99-42b8-8948-837863f9a63a.png)CTE 在数据库引擎中引起了 47 个操作

尽管这个递归 CTE 在我的电脑上比基本的多重连接查询慢了一点，但当所有选择的列都被索引时，它确实生成了更少的引擎操作。那么，为什么这更有效率呢？递归 CTE 将允许你避免创建存储过程或类似的东西，以便递归地发现你的层次树中的级别数量，例如。如果我们将这些操作添加到主查询中，多重连接查询肯定会慢得多。此外，递归 CTE 可能是一种派生表，不比视图快多少，比基本的多重连接查询稍慢一点，但在查询数据库时非常可扩展和有用，以便在休息时基于小的结果子集修改表内容，同时确保你更复杂的查询将免费受益于未来的引擎优化。此外，它将使你的开发周期更加高效，因为它将使你的代码对其他开发人员更易读，保持**DRY**（“**不要重复自己**”）。

让我们继续下一个特性，`CASE`表达式。

# 案例

尽管`CASE`表达式似乎让我们想起了诸如`IF`、`SWITCH`之类的命令式结构，但它仍不允许像这些命令式结构那样进行程序流控制，而是允许根据某些条件对值进行声明性评估。让我们看下面的例子，以更好地理解这个特性。

请在`phpMyAdmin`界面的测试数据库的 SQL 选项卡中输入以下查询：

```php
SELECT id, COUNT(*) as Total, COUNT(CASE WHEN superior IS NOT NULL THEN id END) as 'Number of superiors'
FROM employees
WHERE id = 2;
```

这个查询应该产生以下结果集：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/777459b1-42ce-4b2f-bf6f-7b9c17dbe087.png)包含 CASE 语句的查询结果集

正如结果所示，具有`id`值为`2`的行被从第二个`COUNT`函数的输入中过滤掉，因为`CASE`表达式应用了条件，即上级列必须不具有`NULL`值才能计算 id 列。使用这个现代 SQL 的特性，在很大程度上不是为了提高性能，而是为了尽可能地避免存储过程和控制执行流程，同时保持代码清晰、易读和可维护。

# OVER 和 PARTITION BY

`OVER`和`PARTITION BY`是窗口函数，允许对一组行进行计算。与聚合函数不同，窗口函数不会对结果进行分组。为了更好地理解这两个窗口函数，让我们花点时间在`phpMyAdmin`的 Web 界面上运行以下查询：

```php
SELECT DISTINCT superior AS manager_id, (SELECT last_name FROM employees WHERE id = manager_id) AS last_name, SUM(salary) OVER(PARTITION BY superior) AS 'payroll per manager'
FROM employees
WHERE superior IS NOT NULL
ORDER BY superior;
```

运行这个查询后，你应该看到以下结果：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/4c735583-b305-467f-9f6d-026e2f01ca5a.png)每个经理的工资单列表

正如我们所看到的，结果集显示了每个经理的工资单列，而不是对结果进行分组。这就是为什么我们必须使用`DISTINCT`语句，以避免对同一个经理出现多行。显然，窗口函数允许在当前行与某种关系的行子集上进行高效的查询和优化性能的聚合计算。

# OVER 和 ORDER BY

`OVER AND ORDER BY`窗口函数在对行子集进行排名、计算累积总数或简单地避免自连接时非常有用。

为了说明何时使用这个最有用的特性，我们将采用前面的例子，并通过执行这个查询来确定每个经理的每个工资单上薪水最高的员工：

```php
SELECT id, last_name, salary, superior AS manager_id, (SELECT last_name FROM employees WHERE id = manager_id) AS manager_last_name, SUM(salary) OVER(PARTITION BY superior ORDER BY manager_last_name, salary DESC, id) AS payroll_per_manager
FROM employees
WHERE superior IS NOT NULL
ORDER BY manager_last_name, salary DESC, id;
```

执行这个查询将得到以下结果集：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/7db91a77-1ede-437a-bbd5-7cad5cb5a5b1.png)每个经理的每个工资单上薪水最高的员工列表

返回的结果集使我们能够查看每个工资单的细分，并对每个子集中的每个员工进行排名。那么，允许我们获取关于这些数据子集的所有这些细节的底层执行计划是什么？答案是一个`SIMPLE`查询！在我们的查询中，存在一个依赖子查询，但这是因为我们正在获取每个经理的姓氏，以使结果集更有趣。

在删除依赖子查询后，这将是生成的查询：

```php
SELECT id, last_name, salary, superior AS manager_id, SUM(salary) OVER(PARTITION BY superior ORDER BY manager_id, salary DESC, id) AS payroll_per_manager
FROM employees
WHERE superior IS NOT NULL
ORDER BY manager_id, salary DESC, id;
```

这是相同查询版本的底层执行计划：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/cd90e410-83c9-43db-b954-62c9bf09cf54.png)避免获取经理姓氏时，查询执行计划是简单的

通过在没有返回每个经理姓氏的依赖子查询的情况下运行查询，我们的查询执行计划的`select_type`是`SIMPLE`。这将产生一个高效的查询，未来易于维护。

# GROUPING SETS

GROUPING SETS 使得可以在一个查询中应用多个`GROUP BY`子句。此外，这一新功能引入了`ROLLUP`的概念，它是结果集中添加的额外行，以先前返回的值的超级聚合形式给出结果的摘要。让我们在测试数据库的 employees 表中给出一个非常简单的例子。在`phpMyAdmin`的 Web 界面中执行以下查询：

```php
SELECT superior AS manager_id, SUM(salary)
FROM employees
WHERE superior IS NOT NULL
GROUP BY manager_id, salary;
```

执行后，您应该会看到这个结果：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/65ce923d-82e4-43dc-80bd-0ab65ea65110.png)GROUPING SETS 使得可以在一个查询中应用多个 GROUP BY 子句

多个`GROUP BY`子句使我们能够快速查看每个经理监督下每个员工的工资。如果现在将`ROLLUP`操作符添加到`GROUP BY`子句中，我们将获得这个结果：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/b0c388e6-2ed6-4a28-9db9-1cae7aa20bbf.png)在 GROUP BY 子句中添加 ROLLUP 操作符后的结果集

`ROLLUP`操作符添加了额外的行，其中包含每个子集和整个结果集的超级聚合结果。执行计划显示，底层的`select_type`再次是`SIMPLE`，而不是在此功能存在之前我们将使用`UNION`操作符将多个查询合并。再次，现代 SQL 为我们提供了一个高度优化的查询，将在未来多年内保持高度可维护性。

# JSON 子句和函数

SQL 语言的最新增强之一是 JSON 功能。这一系列新功能使得更容易从 SQL 本机函数中受益，将某些类型的非结构化和无模式数据（如 JSON 格式）以非常结构化和关系方式存储。这允许许多事情，例如对 JSON 文档中包含的某些 JSON 字段应用完整性约束，对某些 JSON 字段进行索引，轻松地将非结构化数据转换并返回为关系数据，反之亦然，并通过 SQL 事务的可靠性插入或更新非结构化数据。

为了充分欣赏这一系列新功能，让我们通过执行查询将一些数据插入测试数据库，将 JSON 数据转换为关系数据。

首先，请在容器的 CLI 上执行以下命令：

```php
# mysql -uroot test < /srv/www/json_example.sql 
```

新表加载到数据库后，您可以执行以下查询：

```php
SELECT id,
   JSON_VALUE(json, "$.name") AS name,
   JSON_VALUE(json, "$.roles[0]") AS main_role,
   JSON_VALUE(json, "$.active") AS active
FROM json_example
WHERE id = 1;
```

执行后，您应该会看到这个结果：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/902782e2-c7c8-4e12-8aaf-d1238df20da2.png)JSON 函数会自动将 JSON 数据转换为关系数据

正如我们所看到的，使用新的 JSON 函数将 JSON 非结构化数据转换为关系和结构化数据非常容易。将非结构化数据插入结构化数据库同样容易。此外，添加的约束将验证要插入的 JSON 字符串是否有效。为了验证这一功能，让我们尝试将无效的 JSON 数据插入我们的测试表中：

```php
INSERT INTO `json_example` (`id`, `json`) VALUES (NULL, 'test');
```

尝试执行查询时，我们将收到以下错误消息：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/ca660695-dede-40df-932e-b66f89a12210.png)JSON 约束确保要插入的 JSON 字符串是有效的

因此，现代 SQL 使得在 SQL 环境中轻松处理 JSON 格式的数据。这将极大地优化应用程序级别的性能，因为现在可以消除每次应用程序需要检索或存储 JSON 格式数据到关系数据库时都需要`json_encode()`和`json_decode()`的开销。

还有许多现代 SQL 功能，我们可以尝试更好地理解，但并非所有 RDBMS 都已实现，并且其中许多功能需要我们分析实现细节。我们将简单地看一下两个在 MariaDB 服务器中未实现但在 PostgreSQL 服务器中实现的功能。要启动和使用包含在 Linux for PHP 容器中的 PostgreSQL 服务器，请在容器的 CLI 上输入以下命令：

```php
# /etc/init.d/postgresql start 
# cd /srv 
# wget --no-check-certificate -O phpPgAdmin-5.1.tar.gz https://superb-sea2.dl.sourceforge.net/project/phppgadmin/phpPgAdmin%20%5Bstable%5D/phpPgAdmin-5.1/phpPgAdmin-5.1.tar.gz 
# tar -xvf phpPgAdmin-5.1.tar.gz 
# sed -i "s/extra_login_security'] = true/extra_login_security'] = false/" phpPgAdmin-5.1/conf/config.inc.php 
# cd fasterweb/chapter_6 
# ln -s ../../phpPgAdmin-5.1 ./phppgadmin # cd /srv/www
```

输入这些命令后，您应该能够通过`phpPgAdmin` Web 界面访问 PostgreSQL 服务器，网址为`http://localhost:8181/phppgadmin`。将浏览器指向此地址，并点击屏幕右上角的服务器图标，以查看以下界面：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/1c4e010d-a76d-4d51-9676-cae9bb368916.png)列出唯一可用的 PostgreSQL 服务器，并通过端口 5432 访问

在这里，点击页面中央的 PostgreSQL 链接，在登录页面上，将用户名输入为`postgres`，密码留空：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/c770642c-08c9-4ddb-a5a5-9b3468636b4f.png)在登录页面上，输入用户名'postgres'，并将密码框留空

然后，点击“登录”按钮，您应该能够访问服务器：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/6bf40f18-277d-4e62-ab10-6505c96eb23b.png)服务器显示 postgres 作为唯一可用的数据库

最后，我们将创建一个数据库，以便学习如何使用本书中将要介绍的最后两个现代 SQL 功能。在`phpPgAdmin`界面中，点击“创建数据库”链接，并填写表单以创建 test 数据库：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/b9e3abd9-2616-4dd0-8f9c-f17aa5ce963d.png)使用 template1 模板和 LATIN1 编码创建名为 test 的数据库

点击“创建”按钮，您将创建 test 数据库并将其与 postgres 数据库一起创建：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/347ae761-f294-471d-98b6-393bcdaa8114.png)现在，服务器显示 test 数据库和 postgres 数据库

完成后，在容器的 CLI 上输入以下命令：

```php
# su postgres 
# psql test < sales.sql 
# exit 
```

现在我们准备尝试`FILTER`子句。

# FILTER

现代 SQL 的另一个非常有趣的功能是`FILTER`子句。它可以将`WHERE`子句添加到聚合函数中。让我们通过在`phpPgAdmin`界面的 test 数据库的 SQL 选项卡中执行以下查询来尝试`FILTER`子句：

```php
SELECT
   SUM(total) as total,
   SUM(total) FILTER(WHERE closed IS TRUE) as transaction_complete,
   year
FROM sales
GROUP BY year;
```

您应该会得到以下结果：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/a84067cb-b25f-4409-bf2b-cdf8e447095a.png)包含 FILTER 语句的查询结果集

`FILTER`子句非常适合在查询的`WHERE`子句中生成报表而不会增加太多开销。

此外，`FILTER`子句非常适合数据透视表，其中按年和月进行分组更加复杂，因为必须生成一个跨越月份和年份的报表，这在两个不同的轴上（例如月份=*x*和年份=*y*）变得更加复杂。

让我们继续讨论最后一个现代 SQL 功能，`LATERAL`查询。

# LATERAL 查询

`LATERAL`查询允许您在相关子查询中选择多个列和一行以上。在创建 Top-N 子查询并尝试将表函数连接在一起时，这非常有用，从而使得解除嵌套成为可能。然后，可以将`LATERAL`查询视为一种 SQL `foreach`循环。

让我们举一个简单的例子来说明`LATERAL`查询是如何工作的。假设我们有两个假想的包含有关电影和演员数据的表：

```php
SELECT
    film.id,
    film.title,
    actor_bio.name,
    actor_bio.biography
FROM film,
    LATERAL (SELECT 
                 actor.name,
                 actor.biography
             FROM actor
             WHERE actor.film_id = film.id) AS actor_bio;
```

正如我们所看到的，`LATERAL`子查询从演员表中选择了多列（actor.name 和 actor.biography），同时仍然能够与电影表（film.id）相关联。许多优化，无论是性能优化还是代码可读性和可维护性，都成为了使用`LATERAL`查询的真正可能性。

有关现代 SQL 的更多信息，我邀请您查阅 Markus Winand 的优秀网站（https://modern-sql.com），并收听 Elizabeth Smith 在 Nomad PHP 上关于这个主题的精彩演讲（https://nomadphp.com/product/modern-sql/）。

# 总结

在本章中，我们学习了如何使用现代 SQL 高效地查询 SQL 数据库。我们定义了现代 SQL 是什么，以及我们如何使用它。我们学会了如何将某些传统的 SQL 查询转换为现代查询，以及何时最好这样做。此外，通过这样做，我们现在更好地理解了现代 SQL 如何帮助我们以多种方式优化服务器的性能。

在下一章中，我们将介绍一些 JavaScript 的优点和缺点，特别是与代码效率和整体性能有关的部分，以及开发人员应该如何始终编写安全、可靠和高效的 JavaScript 代码，主要是通过避免“危险驱动开发”。


# 第七章：JavaScript 和危险驱动开发

“在 JavaScript 中，有一种美丽、优雅、高度表达的语言，被一堆良好意图和失误所掩盖。”

- Douglas Crockford，《JavaScript：精粹》

这段引语基本上表达了优化 JavaScript 代码的全部内容。

开发人员常常被最新的闪亮功能所吸引，或者出于需要故意或假装展示自己的能力，他们的思维有时会陷入一种神秘的清醒睡眠状态，因此他们会被展示过于复杂的代码或者使用最新功能的欲望所克服，尽管他们心里清楚，这意味着他们将不得不牺牲长期稳定性和计算机程序的效率。这种构建应用程序的方式我们可以称之为“危险驱动开发”。JavaScript 有很多非常糟糕的部分，但也有足够多的好部分来抵消坏部分。话虽如此，危险驱动开发的问题在于开发人员听从 JavaScript 糟糕部分的诱惑，而忽视了最终用户的满意度。

在本章中，我们将涵盖一些 JavaScript 的最好和最坏的部分，特别是与代码效率和整体性能有关的部分，以及开发人员应该始终编写安全、可靠和高效的 JavaScript 代码，即使这样做并不像编写最新的闪亮代码那样迷人。

因此，我们将涵盖以下几点：

+   全局对象和局部变量

+   避免不良习惯，并密切关注非常糟糕的部分

+   高效使用 DOM

+   构建和加载 JavaScript 应用程序

# 全局对象和局部变量

JavaScript 的全局对象是所有全局变量的容器。任何编译单元的顶级变量都将存储在全局对象中。当全局对象未被正确使用时，全局对象是 JavaScript 中最糟糕的部分之一，因为它很容易因不需要的变量而膨胀，并且在 JavaScript 默认行为被大量依赖时，开发人员可能会无意中滥用它。以下是两个这种滥用的例子：

+   当运行一个简单的代码，比如`total = add(3, 4);`，实际上是在全局对象中创建了一个名为`total`的属性。这对性能来说并不是一件好事，因为您可能会在堆上保留大量变量，而其中大部分只在应用程序执行的某个时刻需要。

+   当忽略使用`new`关键字来创建对象时，JavaScript 将执行普通的函数调用，并将`this`变量绑定到全局对象。这是一件非常糟糕的事情，不仅出于安全原因，因为可能会破坏其他变量，而且出于性能原因，因为开发人员可能会认为他正在将值存储在对象的属性中，而实际上，他正在直接将这些值存储在全局对象中，从而使全局对象膨胀，并在代码的其他地方已经实例化了所需的对象的情况下，在两个不同的内存空间中存储这些值。

为了有效地使用全局对象，您应该将所有变量封装在一个单一的应用对象中，根据需要对其应用函数，在应用到应用对象的函数中强制执行类型验证，以确保它被正确实例化，并将全局对象视为一种不可变对象，并将其视为一种具有一些副作用函数的应用对象。

# 避免全局变量

全局变量可以在应用程序的任何作用域中进行读取或写入。它们是必要的恶。实际上，任何应用程序都需要组织其代码结构，以处理输入值并返回适当的响应或输出。当代码组织不良时，以及代码的任何部分因此可以修改应用程序的全局状态并修改程序的整体预期行为时，问题和错误开始出现。

首先，组织不良的代码意味着脚本引擎或解释器在尝试查找变量名时需要做更多的工作，因为它将不得不通过许多作用域直到在全局作用域中找到它。

其次，组织不良的代码意味着内存中的堆总是比运行相同功能所需的堆要大，因为许多多余的变量将一直保留在内存中，直到脚本执行结束。

解决这个问题的方法是尽量避免使用全局变量，并几乎始终使用命名空间变量。此外，使用局部作用域变量的额外优势是确保在丢失局部作用域时变量会自动取消设置。

以下示例（`chap7_js_variables_1.html`）向我们展示了全局变量的使用可能非常问题，并且最终非常低效，特别是在复杂应用程序中：

```php
<!DOCTYPE html>

<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>JS Variables</title>

    <meta name="viewport" content="width=device-width, initial-scale=1">
</head>

<body onload="myJS()" style="margin:0;">

<div id="main"></div>

<script type="text/javascript">

    function Sum(n1, n2)
    {
        // These will be global when called from the myJSAgain() function.
        this.number1 = Number(n1);
        this.number2 = Number(n2);

        return this.number1 + this.number2;
    }

    function myJS()
    {
        // Side-effect: creates a global variable named 'total'.
        total = new Sum(3, 4);
        alert( window.total ); // Object

        // Side-effect: modifies the global variable named 'total'.
        myJSAgain();

        // Global 'total' variable got clobbered.
        alert( window.total ); // 3
    }

    function myJSAgain()
    {
        // Missing 'new' keyword. Will clobber the global 'total' variable.
        total = Sum(1, 2);

        // There are now two sets of 'number1' and 'number2' variables!
        alert( window.number2 ); // 2
    }

</script>

</body>

</html>
```

简单的解决方案是通过使用模块和命名空间来组织代码。这可以通过将所有变量和函数包装在单个应用程序对象中来轻松实现，以强制在设置或修改变量时产生某种关联行为，并将应用程序的机密信息保留在全局对象中。闭包也可以用于隐藏全局作用域中的重要值。让我们在考虑命名空间的情况下修改我们之前的脚本：

```php
function myJS()
    {
        function MyJSObject(n1, n2)
        {
            let number1 = Number(n1);
            let number2 = Number(n2);

            return {
                set_number1: function (n1) {
                    number1 = Number(n1);
                },
                set_number2: function (n2) {
                    number2 = Number(n2);
                },
                sum: function ( ) {
                    return number1 + number2;
                }
            };
        }

        let oApp1 = new MyJSObject(3, 4);
        alert( oApp1.sum() ); // 7

        let app2 = MyJSObject(1, 2);
        alert( app2.sum() ); // 3
        alert( oApp1.sum() ); // 7
        alert( window.number1 ); // undefined
    }
```

通过这种方式使用`let`关键字，开发人员仍然可以获得正确的值，同时避免破坏全局变量并无意中修改整个应用程序的全局状态，即使他忘记使用`new`关键字。此外，通过避免不必要的膨胀和减少在命名空间查找中花费的时间，全局对象保持精简和高效。

# 评估局部变量

正如我们在前面的示例中所看到的，省略局部变量声明前的`let`或`var`关键字会使其变成全局变量。在所有情况下，函数和对象都不应该能够通过修改其局部作用域外的变量的值来创建功能性副作用。因此，在函数或结构的作用域内声明变量时，应始终使用`let`关键字。例如，将全局变量简单地移动到在本地循环中使用它们的函数的局部作用域中，可以使大多数浏览器的性能提高近 30%。

此外，使用`let`关键字声明变量时，可以使用块作用域，应尽可能使用。因此，在`for`循环中使用的变量在循环结束后不会保持在作用域内。这允许更好的变量封装和隔离，更有效的垃圾回收和更好的性能。

轻松跟踪变量声明的一种方法是使用 JavaScript 的严格模式。我们将在本章的下一节中更详细地解释这个 ES5 特性。

# 避免坏习惯并注意非常糟糕的部分

与大多数基于 C 的编程语言一样，最好避免某些常见的坏习惯，这些习惯经常导致代码效率低下和错误。

# 坏习惯

以下是一些应该被视为有问题的坏习惯：

+   在 JavaScript 中，首次使用时声明变量是一个坏主意，因为开发人员很可能会给变量全局范围，以便以后访问它。最好从项目开始组织代码，并使用直观和有意义的命名空间，以便在整个应用程序中组织变量的使用。

+   在任何情况下都应该避免以不明确或原本不打算的方式使用结构。例如，让`switch`语句穿透或在条件语句的条件中给变量赋值都是非常糟糕的习惯，不应该使用。

+   依赖自动分号插入是一个坏主意，可能导致代码被错误解释。应该始终避免。

+   数组和对象中的尾随逗号是一个坏主意，因为一些浏览器可能无法正确解释它们。

+   当使用一个带有一个单一命令行的`block`语句时，应该始终避免省略花括号。

当然，适当构造代码的艺术首先取决于对结构本身的良好了解。在 JavaScript 中有一些不好的结构应该在任何时候都避免。让我们花点时间来看看其中的一些。

# 不好的结构 - with 语句

这些不好的结构之一是`with`语句。`with`语句的最初意图是帮助开发人员在不必每次键入整个命名空间的情况下访问对象属性。它旨在成为一种`use`语句，就像我们在其他语言（如 PHP）中可能遇到的那样。例如，你可以以以下方式使用`with`语句：

```php
foo.bar.baz.myVar    = false;
foo.bar.baz.otherVar = false;

with (foo.bar.baz) {
    myVar = true;
    otherVar = true;
}
```

问题在于，当我们查看这段代码时，我们并不确定引擎是否会覆盖名为`myVar`和`otherVar`的全局变量。处理长命名空间的最佳方法是将它们分配给本地变量，然后在之后使用它们：

```php
let fBrBz = foo.bar.baz;

fBrBz.myVar = true;
fBrBz.otherVar = true;
```

# 不好的结构 - eval 语句

另一个不好的例子是`eval()`语句。这个语句不仅非常低效，而且大多数时候是没有用的。事实上，人们经常认为使用`eval()`语句是处理提供的字符串的正确方式。但事实并非如此。你可以简单地使用数组语法来做同样的事情。例如，我们可以以以下方式使用`eval()`语句：

```php
function getObjectProperty(oString)
{
    let oRef;
    eval("oRef = foo.bar.baz." + oString);
    return oRef;
}
```

要获得大幅度的速度提升（从 80%到 95%更快），你可以用以下代码替换前面的代码：

```php
function getObjectProperty(oString)
{
    return foo.bar.baz[oString];
}
```

# 不好的结构 - try-catch-finally 结构

重要的是要注意，应该避免在性能关键的函数内部使用 try-catch-finally 结构。原因与这个结构必须创建一个运行时变量来捕获异常对象有关。这种运行时创建是 JavaScript 中的一个特殊情况，并非所有浏览器都以相同的效率处理它，这意味着这个操作可能会在应用程序的关键路径上造成麻烦，特别是在性能至关重要的情况下。你可以用简单的测试条件替换这个结构，并在一个对象中插入错误消息，这个对象将作为应用程序的错误注册表。

# 避免低效的循环

嵌套循环是在 JavaScript 中编写这些类型结构时要避免的第一件事。

此外，大多数情况下，使用`for-in`循环也不是一个好主意，因为引擎必须创建一个可枚举属性的完整列表，这并不是非常高效的。大多数情况下，`for`循环会完美地完成任务。这在应用程序的关键路径上找到的性能关键函数中尤其如此。

此外，在处理循环时要注意隐式对象转换。通常，乍一看，很难看出在重复访问对象的`length`属性时发生了什么。但有些情况下，当对象没有事先被明确创建时，JavaScript 会在循环的每次迭代中创建一个对象。请参阅以下代码示例（`chap7_js_loops_1.html`）：

```php
function myJS()
{
    let myString = "abcdefg";

    let result = "";

    for(let i = 0; i < myString.length; i++) {
        result += i + " = " + myString.charAt(i) + ", ";
        console.log(myString);
    }

    alert(result);
}
```

在查看谷歌 Chrome 开发者工具中的控制台结果时，我们得到了以下结果：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/112011fe-7e2a-40e0-bd67-405ae2bd7eb2.png)总共创建了七个字符串对象，每次迭代都创建了一个

在 JavaScript 引擎内部，实际上是在循环的每次迭代中创建了一个字符串对象。为了避免这个问题，我们将在进入循环之前显式实例化一个字符串对象（`chap7_js_loops_2.html`）：

```php
function myJS()
{
    let oMyString = new String("abcdefg");

    let result = "";

    for(let i = 0; i < oMyString.length; i++) {
        result += i + " = " + oMyString.charAt(i) + ", ";
        console.log(oMyString);
    }

    alert(result);
}
```

新脚本的结果如下所示：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/864545b7-6a45-4ee7-82b7-7119adb29950.png)只创建了一个对象，并显示了七次

控制台现在显示了同一个对象七次。很容易理解这如何可以优化循环的性能，特别是当循环可能导致引擎创建数十、数百甚至数千个对象以完成其工作时。

# 代码检查工具和严格模式

JavaScript 中还有一些其他不好的部分，可能会在某些情况下导致性能问题。为了密切关注所有这些不好的部分，并用 JavaScript 的好部分替换它们，强烈建议您使用一个工具，即使在第一次运行代码之前，也可以找到代码的问题。这些工具就是代码检查工具。

*JSLint*、*ESLint*和*Prettier*是可以帮助您找到松散代码并修复它的工具，甚至在某些情况下可以自动修复。一些代码检查工具，如*ESLint*，甚至可以通过减少语句数量、通过函数和 Promises 替换结构的嵌套、识别圈复杂度（衡量单个结构代码的分支数量）来帮助您改进代码，也许还可以允许您用更功能性的代码替换这些结构性的代码，正如我们将在下一章中看到的那样。您可以在以下地址找到这些工具：

+   [`www.jslint.com/`](http://www.jslint.com/)

+   [`eslint.org/`](https://eslint.org/)

+   [`github.com/prettier/prettier`](https://github.com/prettier/prettier)

使用代码检查工具的一个额外好处是它们使 JavaScript 代码与 ES5 的严格模式兼容。在可能的情况下，应该使用严格模式。只需在脚本或函数的开头添加一个`use strict;`语句即可使用它。使用严格模式的许多好处之一是简化变量名称与变量定义的映射（优化的命名空间查找）、禁止`with`语句、通过`eval`语句防止意外引入变量到当前作用域、保护`this`变量免受"装箱"（强制实例化）的影响，当它不包含对象并且传递给函数时，可以大大减少性能成本，并消除大多数性能限制，例如访问函数调用者的变量和在运行时"遍历"JavaScript 堆栈。

Packt Publishing 出版了许多关于 JavaScript 性能的优秀书籍和视频，我强烈建议您阅读它们，以掌握所有这些优秀的工具。

# 高效使用 DOM

**文档对象模型**（**DOM**）操作仍然是 JavaScript 中成本最高的操作之一。事实上，应该尽量减少重绘或回流，以避免一般性能问题。

尽管如此，还有其他必须避免的陷阱，以保持脚本在需要 DOM 操作并导致重绘或回流时的速度。这些陷阱涉及如何修改文档树，如何更新不可见元素，如何进行样式更改，如何搜索节点，如何管理从一个文档到另一个文档的引用，以及在检查大量节点时该怎么做。

# 修改文档树

重要的是要知道，在遍历树时进行修改是非常昂贵的。最好创建一个临时集合来处理，而不是在循环遍历所有节点时直接修改树。

事实上，最好的方法是使用非显示的 DOM 树片段，一次性进行所有更改，然后一起显示它们。以下是一个理论示例，说明如何实现这一点：

```php
function myJS()
{
    let docFragment = document.createDocumentFragment();
    let element, content;

    for(let i = 0; i < list.length; i++) {
        element = document.createElement("p");
        content = document.createTextNode(list[i]);
        element.appendChild(content);
        docFragment.appendChild(element);
    }

    document.body.appendChild(docFragment);
}
```

还可以克隆一个元素，以便在触发页面回流之前完全修改它。以下代码显示了如何实现这一点：

```php
function myJS()
{
    let container = document.getElementById("container1");

    let cloned = container.cloneNode(true);

    cloned.setAttribute("width", "50%");

    let element, content;

    for(let i = 0; i < list.length; i++) {
        element = document.createElement("p");
        content = document.createTextNode(list[i]);
        element.appendChild(content);
        cloned.appendChild(element);
    }

    container.parentNode.replaceChild(cloned, container);
}
```

通过使用这些技术，开发人员可以避免 JavaScript 中一些性能方面最昂贵的操作。

# 更新不可见元素

另一种技术是将元素的显示样式设置为`none`。因此，在更改其内容时，它不需要重绘。以下是一个显示如何实现这一点的代码示例：

```php
function myJS()
{
    let container = document.getElementById("container1");

    container.style.display = "none";
    container.style.color = "red";
    container.appendChild(moreNodes);
    container.style.display = "block";
}
```

这是一种简单快速的方法，可以修改节点而避免多次重绘或回流。

# 进行样式更改

与我们提到如何在遍历 DOM 树时一次修改多个节点类似，也可以在文档片段上同时进行多个样式更改，以最小化重绘或回流的次数。以下代码片段是一个例子：

```php
function myJS()
{
    let container = document.getElementById("container1");
    let modifStyle = "background: " + newBackgound + ";" +
        "color: " + newColor + ";" +
        "border: " + newBorder + ";";
    if(typeof(container.style.cssText) != "undefined") {
        container.style.cssText = modifStyle;
    } else {
        container.setAttribute("style", modifStyle);
    }
}
```

正如我们所看到的，通过这种方式可以修改任意数量的样式属性，以便触发只有一个重绘或回流。

# 搜索节点

在整个 DOM 中搜索节点时，最好使用 XPath 来进行。通常会使用`for`循环，如下面的示例，其中正在搜索`h2`、`h3`和`h4`元素：

```php
function myJS()
{
    let elements = document.getElementsByTagName("*");

    for(let i = 0; i < elements.length; i++) {
        if(elements[i].tagName.match("/^h[2-4]$/i")) {
            // Do something with the node that was found
        }
    }
}
```

可以使用 XPath 迭代器对象来获取相同的结果，只是效率更高：

```php
function myJS()
{
    let allHeadings = document.evaluate("//h2|//h3|//h4", document, null, XPathResult.ORDERED_NODE_ITERATOR_TYPE, null);
    let singleheading;

    while(singleheading = allHeadings.iterateNext()) {
        // Do something with the node that was found
    }
}
```

在包含超过一千个节点的 DOM 中使用 XPath 肯定会在性能上有所不同。

# 检查大量节点

另一个要避免的陷阱是一次检查大量节点。更好的方法是将搜索范围缩小到特定的节点子集，然后使用内置方法找到所需的节点。例如，如果我们知道要查找的节点可以在特定的`div`元素内找到，那么我们可以使用以下代码示例：

```php
function myJS()
{
    let subsetElements = document.getElementById("specific-div").getElementsByTagName("*");

    for(let i = 0; i < subsetElements.length; i++) {
        if(subsetElements[i].hasAttribute("someattribute")) {
            // Do something with the node that was found...
            break;
        }
    }
}
```

因此，这种搜索将比我们在大量节点中搜索它要高效得多，并且返回结果更快。

# 管理从一个文档到另一个文档的引用

在 JavaScript 中管理对许多文档的引用时，当不再需要文档时，销毁这些引用是很重要的。例如，如果一个文档在弹出窗口中，在框架中，在内联框架中或在对象中，并且用户关闭了文档，则文档的节点将保留在内存中，并将继续膨胀 DOM。销毁这些未使用的引用可以显著提高性能。

# 缓存 DOM 值

当重复访问对象时，将其存储在本地变量中以便反复使用会更有效。例如，以下代码将对分组的 DOM 值进行本地复制，而不是分别访问每个值：

```php
function myJS()
{
    let group = document.getElementById("grouped");

    group.property1 = "value1";
    group.property2 = "value2";
    group.property3 = "value3";
    group.property4 = "value4";

    // Instead of:
    //
    // document.getElementById("grouped").property1 = "value1";
    // document.getElementById("grouped").property2 = "value2";
    // document.getElementById("grouped").property3 = "value3";
    // document.getElementById("grouped").property4 = "value4";

}
```

这样做将使您避免与动态查找相关的性能开销。

# 构建和加载 JavaScript 应用程序

在考虑如何构建和加载 JavaScript 应用程序时，重要的是要记住某些重要原则。

# 最小化昂贵的操作

在 JavaScript 中成本最高的操作是：

+   通过网络 I/O 请求资源

+   重绘，也称为重新绘制，由于动态内容更改，例如使元素可见。

+   重排，可能是由于窗口调整大小

+   DOM 操作或页面样式的动态更改

显然，最重要的是要尽量减少所有这些操作，以保持良好的性能。在处理执行速度过慢的脚本时，这些都是要在 Google Chrome 的时间轴工具中查找的最重要元素，可以通过 Chrome 的开发者工具访问，如本书的第一章 *更快的 Web-入门*中所述。

# 清理，缩小和压缩资源

当然，从捆绑包中排除未使用的导出，也称为摇树，通过清理死代码来缩小脚本，然后压缩脚本文件，在处理 JavaScript 性能时总是一个好事，特别是在处理网络延迟时。在这方面，*Webpack*（[`webpack.js.org/`](https://webpack.js.org/)）是一个非常好的工具，结合*UglifyJS*插件（[`github.com/webpack-contrib/uglifyjs-webpack-plugin`](https://github.com/webpack-contrib/uglifyjs-webpack-plugin)）和其压缩插件（[`github.com/webpack-contrib/compression-webpack-plugin`](https://github.com/webpack-contrib/compression-webpack-plugin)），它将摇树您的代码，通过删除任何未使用或死代码来缩小您的脚本，并压缩生成的文件。

摇树的优势主要体现在使用摇树的第三方依赖时。为了更好地理解如何使用这些工具，强烈建议您查看以下教程：

+   [`2ality.com/2015/12/webpack-tree-shaking.html`](http://2ality.com/2015/12/webpack-tree-shaking.html)

+   [`medium.com/@roman01la/dead-code-elimination-and-tree-shaking-in-javascript-build-systems-fb8512c86edf`](https://medium.com/@roman01la/dead-code-elimination-and-tree-shaking-in-javascript-build-systems-fb8512c86edf)

另一个优化 JavaScript 代码（摇树，缩小和压缩）的好工具是 Google 的*Closure*，尽管它是用 Java 构建的。您可以在以下地址找到这个工具：[`developers.google.com/closure/`](https://developers.google.com/closure/)。

# 加载页面资源

在 HTML 文档的头部加载脚本文件时，重要的是要避免阻塞页面的渲染。脚本应始终在 body 部分的末尾加载，以确保渲染不会依赖于在获取所需的 JavaScript 文件时可能发生的网络延迟。

此外，重要的是要知道最好将内联脚本放在 CSS 样式表之前，因为 CSS 通常会阻止脚本运行，直到它们完成下载。

此外，在为性能构建 JavaScript 应用程序时，拆分脚本文件负载和异步下载脚本都是必须考虑的技术。

此外，*Steve Souders*已经写了很多关于提升网页性能的优秀书籍和文章，您应该阅读这些书籍，以获取有关这些非常重要的技术和原则的更多信息（[`stevesouders.com/`](https://stevesouders.com/)）。

# 缓存页面资源

另一件重要的事情要记住，正如我们将在第九章 *提高 Web 服务器性能*中更详细地看到的，服务器端和客户端的缓存技术将帮助您显著提高网页的性能。利用这些技术将使您能够减少简单地一遍又一遍地获取相同的 JavaScript 文件所需的请求数量。

# 总结

在本章中，我们已经涵盖了一些 JavaScript 的优点和缺点，特别是可能导致性能问题的陷阱。我们已经看到，编写安全、可靠和高效的 JavaScript 代码可能并不像使用最新的闪亮特性或懒惰编码那样令人兴奋，但肯定会帮助任何 JavaScript 应用程序成为更快速的 Web 的一部分。

在下一章中，我们将看到 JavaScript 如何越来越成为一种函数式语言，以及这种编程范式将成为未来性能的一个向量。我们将快速了解即将推出的语言特性，这些特性将有助于改善 JavaScript 应用程序的性能。


# 第八章：函数式 JavaScript

JavaScript 的未来将是函数式的。事实上，过去几年对语言所做的许多更改都使得在使用函数式编程技术时更容易、更高效的实现成为可能。

在本章中，我们将看到 JavaScript 如何越来越成为一种函数式语言，以及这种编程范式如何成为性能的一个向量。我们将学习如何用简化的函数版本替换过于复杂的代码，以及如何使用不可变性和尾调用优化将有助于使 JavaScript 在长期内更加高效。因此，我们将涵盖以下几点：

+   简化函数

+   函数式编程技术

+   更多即将推出的 JavaScript 功能

# 简化函数

传统上，计算机科学学生被告知保持他们的函数简单。经常说一个函数应该对应一个单一的动作。事实上，函数的圈复杂度越高，它就越难以重用、维护和测试。函数变得越来越纯粹的逻辑实体，没有真实世界中清晰可识别的动作根源，它就越难以理解和与其他函数结合使用。

# 函数式编程原则

**函数式编程**（**FP**）范式通过将计算设计视为基于数学函数和状态和数据的不可变性而进一步推动这种推理。FP 的指导原则是整个计算机程序应该是一个单一的、引用透明的表达式。在其核心，FP 的概念要求函数是纯的、引用透明的，并且没有副作用。当给定相同的输入时，函数是纯的，它总是返回相同的输出。当其函数表达式可以在计算机程序的任何地方与其相应的值互换时，它是引用透明的。当它不修改其范围之外的应用程序状态时，它是没有副作用的。因此，例如，修改在其范围之外声明的变量或向屏幕回显消息被认为是必须尽可能避免的函数副作用。

纯函数的一个例子如下：

```php
function myJS()
{
    function add(n1, n2)
    {
        let number1 = Number(n1);
        let number2 = Number(n2);

        return number1 + number2;
    }

}
```

下一个函数不是纯的，因为有两个副作用：

```php
function myJS()
{
    function add(n1, n2)
    {
        // 1\. Modifies the global scope
        number1 = Number(n1);
        number2 = Number(n2);

        // 2\. The alert function
        alert( number1 + number2 );
    }

}
```

引用透明函数可以在代码的任何地方替换为等于函数表达式计算值的常量：

```php
4 === addTwo(2);
```

例如，这个函数不是引用透明的：

```php
function myJS()
{
    function addRandom(n1)
    {
        let number1 = Number(n1);

        return number1 + Math.random();
    }

}
```

在最显著的 JavaScript 函数中，不是引用透明的并且产生副作用的有：`Date`、`Math.random`、`delete`、`Object.assign`、`Array.splice`、`Array.sort`和`RegExp.exec`。

保持函数简单和纯净有许多优点。最重要的是：

+   简化关键路径，开发人员在尝试维护或更新应用程序时减少认知负担

+   更容易测试函数

+   免费编译器优化，编译器可能决定在编译时用相应的常量值替换函数表达式，而不是每次计算函数

+   未来由于运行时优化而提高的性能

+   通过避免应用程序状态的可变性而实现安全的多线程（JavaScript 目前是单线程的，但谁知道未来会发生什么）

# 函数作为一等公民

函数作为一等公民是一个原则，它规定函数应该被视为与任何其他数据类型一样。当语言允许这种情况时，函数可以成为高阶函数，其中任何函数都可以作为参数接收，并且可以从任何其他函数返回计算值，就像任何其他数据类型一样。

当函数是纯的并且引用透明时，它们可以更容易地被用作一等公民函数。因此，更容易将函数组合在一起以动态产生其他函数。这就是所谓的函数组合。柯里化是一种动态生成新函数的方法，将其单个参数的评估转换为具有多个参数的另一个函数，并且部分应用是一种新动态生成的函数，其参数数量较少将修复另一个函数的参数数量。正如我们将在本章后面看到的，ES2020 正准备将这些概念引入 JavaScript 编程语言中。

# 处理副作用

如果需要避免所有形式的副作用，我们应该如何处理输入和输出、网络、用户输入和用户界面？根据 FP 原则，与现实世界的这些交互应该封装在特殊的数据结构中。即使包含的值在运行时仍然是未知的，这些特殊的数据结构使得可以将函数映射到一个或多个包装值（函子），将包装函数映射到一个或多个包装值（应用程序）或将返回其自身数据结构类型实例的包装函数映射到一个或多个包装值（单子）。这样，副作用就与纯函数分离开来。

# 不可变性

FP 的另一个重要原则是不可变性。修改状态和数据会产生圈复杂度，并使任何计算机程序容易出现错误和低效。事实上，所有变量实际上都应该是不可变的。变量从分配到内存的时刻直到释放的时刻都不应该改变其值，以避免改变应用程序的状态。

自 ES6 以来，现在可以使用`const`关键字来定义常量或不可变变量。以下是一个示例：

```php
function myJS()
{
    const number = 7;

    try {
        number = 9;
    } catch(err) {
```

```php
        // TypeError: invalid assignment to const 'number'
        console.log(err);
    }
  }
```

这个新增的功能现在可以防止通过赋值修改变量。这样，就可以在整个运行时期保护 JavaScript 应用程序的状态免受突变的影响。

在可能的情况下，开发人员应始终优先使用`const`而不是`let`或`var`。尝试修改使用`const`关键字声明的变量将导致以下错误（`chap8_js_const_1.html`）：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/955b0b5c-7a4f-4818-bc13-9efe8dc21f06.png)给常量变量赋值会导致'TypeError'

# 函数式编程技术

自 ES6 以来，JavaScript 已经更容易使用 FP 实现软件解决方案。许多引擎优化已经添加，使得根据 FP 原则编程 JavaScript 时可以获得更好的性能。映射、过滤、减少和尾调用优化是其中的一些技术。

# 映射

映射是一种高阶函数，它允许我们将回调映射到集合的每个元素。当将数组的所有元素从一组值转换为另一组值时，它特别有用。以下是一个简单的代码示例：

```php
function myJS()
{
    let array = [1, 2, 3];

    let arrayPlusTwo = array.map(current => current + 2);

    // arrayPlusTwo == [3, 4, 5]

}
```

这种技术使得在简单修改数组的值时尽可能避免使用结构循环成为可能。

# 过滤

过滤是一种高阶函数，它允许我们根据布尔谓词区分和保留集合中的某些元素。当根据特定条件从集合中移除某些元素时，过滤当然是非常有用的。以以下代码为例：

```php
function myJS()
{
    let array = [1, 2, 3];

    let arrayEvenNumbers = array.filter(current => current % 2 == 0);

    // arrayEvenNumbers == [2]

}
```

过滤是避免循环和嵌套条件以提取所需数据集的一种很好的方法。

# 减少

Reduce 是一个高阶函数，它允许我们根据组合函数将集合的元素合并为一个返回值。当处理累积或连接值时，这种技术非常有用。在下面的例子中，我们正在计算数组元素的总和：

```php
function myJS()
{
    let array = [1, 2, 3];

    let sum = array.reduce((cumul, current) => cumul + current, 0);

    // sum == 6;

}
```

我们将再看一种 FP 技术，即尾调用优化。

# 尾调用优化

为了更好地理解**尾调用优化**（**TCO**）是什么，我们需要定义它是什么，了解它是如何工作的，并学习如何确定一个函数是否被尾调用。

# 什么是尾调用优化？

尾调用或尾递归是一种函数式编程技术，其中一个函数在返回控制权给自己的调用者之前调用一个子例程函数作为其最终过程。如果一个函数递归地调用自身，则发生直接递归。如果一个函数调用另一个函数，而另一个函数又调用原始函数，则递归是相互的或间接的。

因此，例如，当一个函数尾调用自身时，它会一遍又一遍地将自己堆叠，直到满足某个条件为止，此时它一定会返回，从而有效地弹出整个调用堆栈。

优化尾调用包括在执行尾调用之前从调用堆栈中弹出当前函数，并将当前函数的调用者地址保留为尾调用的返回地址。因此，堆栈的内存占用保持较小，实际上完全避免了堆栈溢出。

# 尾调用优化的工作原理

让我们比较两个堆栈帧，一个没有尾调用优化，另一个有尾调用优化。首先让我们看一下以下代码：

```php
function a(x)
{
    y = x + 2;
    return b(y);
}

function b(y)
{
    z = y + 3;
    return z;
}

console.log(a(1)); // 6
```

在没有使用尾调用优化的情况下，分配给内存后，前面代码的三个堆栈帧将如下图所示：

典型的后进先出（LIFO）调用堆栈

一旦将值 6 分配给变量`z`，堆栈帧就准备好被弹出。在这种情况下，堆栈帧**2**仅保留在内存中，只是为了保留`console.log()`的地址。这就是尾调用优化可以产生差异的地方。如果在调用`b()`之前，堆栈帧**2**被从堆栈中弹出，同时保持原始调用者的返回地址不变，那么在运行时只会有一个函数被堆叠，堆栈空间将会减少。

无论函数被尾调用多少次，整个堆栈只会计算两个堆栈帧。因此，经过尾调用优化的堆栈看起来会像这样：

尾调用优化的调用堆栈

一些人声称，在某些 JavaScript 实现中实现尾调用优化会是一个坏主意，因为这样做会破坏应用程序的实际执行流程，使调试变得更加困难，并且一般会破坏遥测软件。在某些 JavaScript 实现中，这可能是真的，但绝对不是绝对的。从技术上讲，由于某些 JavaScript 实现中存在技术债务，实现尾调用优化可能会很困难，但绝对不需要为某些应该在任何语言中都是隐含的东西而要求一个语法标志，特别是在使用严格模式标志时。

话虽如此，并非所有浏览器和 JavaScript 项目都已经实现了这个 ES6 功能，但它只是时间问题，他们迟早都得这么做，开发人员应该为这一重大变化做好准备。事实上，从结构范式到函数范式的这一变化将使得使用函数而不是众所周知的循环结构来制作非常高效的循环成为可能。根据这些新原则进行编程的主要优势将是：

+   通过消耗更少的内存和花费更少的时间来完成大型循环，从而提高效率

+   减少圈复杂度和简化关键路径

+   代码行数减少，开发人员的认知负担减轻

+   封装和组织良好的代码

+   一般来说，更好地测试代码

截至撰写本文时，只有 Safari 11、iOS 11、Kinoma XS6 和 Duktape 2.2 完全支持尾调用优化。

让我们来看看两个代码示例（`chap8_js_performance_1.html`和`chap8_js_performance_2.html`），以比较传统的`for`循环与尾调用优化函数的性能。以下是第一个示例：

```php
function myJS()
{
    "use strict";

    function incrementArrayBy2(myArray, len = 1, index = 0)
    {
        myArray[index] = index;
        myArray[index] += 2;
        return (index === len - 1) ? myArray : incrementArrayBy2(myArray, len, index + 
                                                                     1); // tail call
    }

    let myArray = [];

    for(let i = 0; i < 100000000; i++) {
        myArray[i] = i;
        myArray[i] += 2;
    }

    console.log(myArray);
}
```

以下是第二个：

```php
function myJS()
{
    "use strict";

    function incrementArrayBy2(myArray, len = 1, index = 0)
    {
        myArray[index] = index;
        myArray[index] += 2;
        return (index === len - 1) ? myArray :    
       incrementArrayBy2(myArray, len, index +  
                                                                     1); // tail call
    }

    let myArray = [];

    myArray = incrementArrayBy2(myArray, 100000000);

    console.log(myArray);
}

```

如果我们对这两个脚本进行基准测试，我们会注意到它们之间没有太大的区别，除了使用尾调用的那个更容易进行单元测试，具有非常简单的关键路径，并且即使出于明显的原因而不是纯的，它仍然可以很容易地进行记忆化。

以下是第一个脚本的结果：

使用结构化'for'循环时的结果

第二个脚本的结果是：

使用经过尾调用优化的堆叠函数时的结果

现在，让我们通过一些代码示例更好地了解这个 ES6 功能，以便更好地识别尾调用的不同用法。

# 识别尾调用

如前所述，尾调用发生在子例程被调用为当前函数的最后一个过程时。这种情况有很多种。

如果您以以下方式使用三元运算符，则`one()`和`two()`函数都是尾调用：

```php
function myFunction()
{
    // Both one() and two() are in tail positions
    return (x === 1) ? one() : two();
}
```

以下代码示例不是尾调用，因为被调用者是从函数体内部调用的，可以用于进一步计算，而不仅仅是返回给调用者：

```php
function myFunction()
{
    // Not in a tail position
    one();
}
```

以下是另一个示例，其中一个被调用者不处于尾调用位置：

```php
function myFunction()
{
    // Only two() is in a tail position
    const a = () => (one() , two());
}
```

原因是在这种情况下，`one()`函数可以与其他计算结合在一起，而`two()`函数不能，其返回值将简单地分配给`a`常量。如果我们使用逻辑运算符而不是逗号，那么同样的情况也会发生。

让我们继续了解其他即将推出的 JavaScript 功能。

# 更多即将推出的 JavaScript 功能

许多其他功能将很快添加到 JavaScript 中，这将进一步推动语言朝着功能性和异步编程的方向发展。让我们来看看其中的一些。

# 异步函数

由于异步编程，当生成器用于此目的时，对 FP 的需求将会更加迫切，避免竞争条件将变得比现在更加重要。

确实，ES2017 引入了`async` / `await`函数。这些函数将允许我们轻松创建一个`event`循环，并在循环内部进行异步 I/O 调用，以获得非阻塞代码。这将有许多实际应用，包括在渲染完成后异步下载补充的 JavaScript 文件以加快网页加载时间的可能性。以下是使用这些类型函数的代码示例：

```php
async function createEntity(req, res) {
    try {
        const urlResponse = await fetch(req.body.url)
        const html = await urlResponse.text()
        const entity = await Entity.post({ // POST request })
        // More stuff here
    } catch (error) {
        req.flash('error', `An error occurred : ${error.message}`)
        res.redirect('/entity/new')
    }
}
```

# 异步生成器和 for-await-of 循环

ES2018 定义了异步生成器和`for-await-of`循环的规范。这些功能已经在大多数浏览器中可用，并且在 JavaScript 中进行异步编程时将非常有帮助。它们将大大简化在异步请求上进行迭代时创建队列和循环。此外，使用异步迭代器、可迭代对象和生成器与异步调用将通过使用 promises 变得非常容易。以下是使用这些新功能的简单代码示例：

```php
async function* readLines(path) {
    let file = await fileOpen(path);

    try {
        while (!file.EOF) {
            yield await file.readLine();
        }
```

```php
    } finally {
        await file.close();
    }
}
```

# 管道操作符

ES2020 提案正在制定中，其中包括更多 FP 概念，例如使用管道操作符进行简单的函数链接。因此，链接函数将变得更加简单。而不是做类似于这样的事情：

```php
const text = capitalize(myClean(myTrim(' hAhaHAhA ')));
```

我们只需要这样做：

```php
const text = ' hAhaHAhA '
|> myTrim
|> myClean
|> capitalize
```

# 部分应用

ES2020 提案中还有一个非常重要的 FP 技术：部分应用。如前所述，这种 FP 技术可以通过生成一个参数更少的新动态生成的函数，来固定函数的一些参数。以下是一个简单的代码示例：

```php
function add(num1, num2) {
    return num1 + num2;
}

function add1(num2) {
    return add(1, num2);
}
```

ES2020 提案建议，可以通过以下方式执行部分应用：

```php
const add = (x, y) => x + y
const add1 = add(?, 1)
```

当然，我们还可以提到许多其他 FP 技术，这些技术可能会出现在 ES2020 规范中，比如函数绑定、柯里化和模式匹配，但必须知道的是，JavaScript 越来越成为一种函数式语言，并且许多未来的引擎优化将自动增强任何执行的代码的整体性能，如果它是根据 FP 原则编写的。

有关函数式编程和函数式 JavaScript 的更多信息，请阅读 Packt Publishing 近年来出版的许多优秀书籍和视频。

# 总结

我们现在更好地理解了为什么 JavaScript 越来越成为一种函数式语言，以及这种编程范式如何成为性能的一个向量。我们了解了如何用简化的函数式版本替换过于复杂的代码，以及如何使用不可变性和尾调用优化来提高 JavaScript 的效率。我们还简要了解了 JavaScript 语言即将推出的功能。

在下一章中，我们将看一些项目，这些项目多年来一直与谷歌的更快网络计划一起进行，并且我们将看到如何结合这些技术以提高整体网络服务器性能。


# 第九章：提升 Web 服务器性能

谷歌确定其更快 Web 计划的首要任务之一是更新老化的 Web 协议。全球范围内已经有许多项目正在进行，因为 Web 开发的新重点正在从为用户提供更多功能（即使这些功能很慢）转向提供与 Web 性能不相冲突的功能。谷歌的倡议有助于改变 Web 开发的优先事项，从而使现有项目得以光明，新项目得以创建。

在本章中，我们将介绍一些与谷歌新的 Web 倡议一起进行的项目。因此，我们将涵盖以下几点：

+   MOD_SPDY 和 HTTP/2

+   PHP-FPM 和 OPCache

+   ESI 和 Varnish Cache

+   客户端缓存

+   其他更快 Web 工具

# MOD_SPDY 和 HTTP/2

2009 年，谷歌宣布将寻找更新 HTTP 协议的方法，通过使用名为 SPDY（`SPeeDY`）的新会话协议。这个新的会话协议在底层 TLS 表示层上工作，并允许在应用层进行许多 HTTP 速度优化。使用 SPDY 就像激活 SSL 一样简单，在 Web 服务器上安装`mod_spdy`模块并激活它。为了从其功能中受益，不需要对网站进行任何修改。

此外，所有主要浏览器都支持它。SPDY 迅速成为更快 Web 的核心元素，并在 2012 年 11 月成为下一次重大 HTTP 协议修订的基础。然后，在 2015 年，它被弃用，改为使用新的 HTTP/2 协议。SPDY 引入的最重要的优化措施，并将其纳入新的 HTTP 协议规范的是多路复用和优先级流、服务器推送和头部压缩。在我们深入了解 HTTP/2 协议的一些具体内容之前，让我们更详细地看看这些优化措施中的每一个。

# 多路复用和优先级流

SPDY 的多路复用流功能允许将多个请求映射到单个连接上的多个流。这些流是双向的，可以由客户端或服务器（服务器推送功能）发起。在单个连接上打开多个流可以避免在每个客户端/服务器交换时建立新连接的开销，特别是在并行下载多个资源以完成单个页面的渲染时。因此，这个第一个功能使得在使用 HTTP/1 协议时摆脱了可能的连接数量限制：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/4607e136-5765-4972-8a01-6e09b4e07bb2.png)多路复用和优先级流的工作原理

此外，SPDY 的流是有优先级的。这个额外的功能允许客户端确定哪些资源应该首先发送到网络上。因此，SPDY 避免了在 HTTP/1 协议中进行服务器管线化（即`KeepAlive`指令）时出现的**先进先出**（FIFO）问题。

# 服务器推送

正如已经提到的，SPDY 的新流特性使得服务器能够在不响应客户端请求的情况下向客户端推送数据。这使得通信变得双向，并允许 Web 服务器预测客户端的需求。事实上，甚至在客户端解析 HTML 并确定渲染页面所需的所有文件之前，Web 服务器就可以将文件推送到客户端，从而减少客户端发送请求以获取所有必要资源的次数：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/a80f24cc-3844-42b5-aaba-961cbf9953c2.jpg)“服务器推送”功能的工作原理

通过了解许多研究显示，平均而言，大多数页面需要 70 到 100 个请求，涉及 20 到 30 个域名，才能完成其渲染，我们可以很容易地看出这个功能如何使 Web 变得更简洁，并显著减少网络延迟。

# 头部压缩

SPDY 的第三个重要特性是使用`gzip`进行标头压缩。通过压缩通常较多的 HTTP 标头，并将其平均减少 85%的原始大小，SPDY 可以在网络上将大多数 HTTP 事务的加载时间缩短整整一秒。尽管使用`gzip`动态压缩标头被发现是不安全的，但标头压缩的概念仍然存在，并且由于对整体网络性能的巨大益处，它在 HTTP/2 协议中得到了重新实现。

# HTTP/2

作为 RFC 7540 [1]于 2015 年 5 月发布的 HTTP/2 是 HTTP 协议的最新主要修订版。它主要基于 Google 的 SPDY 协议，并提供了一个新的二进制帧层，与 HTTP/1 不兼容。正如之前提到的，它的大部分功能是通过 SPDY 项目开发的。SPDY 和 HTTP/2 之间最显著的区别是新协议压缩其标头的方式。而 SPDY 依赖于使用`gzip`动态压缩标头，HTTP/2 协议使用了一种名为`HPACK`的新方法，该方法利用了固定的 Huffman 编码算法。为了避免 SPDY 发现的数据压缩导致可能泄露私人数据的问题，需要这种新方法。

尽管新协议将大多数网页的加载时间缩短了一倍，许多批评者对此表示失望，指出谷歌对更新 HTTP 协议项目施加的不切实际的最后期限使得新协议版本不可能基于其他任何东西而不是其 SPDY 项目，并因此错失了进一步改进新 HTTP 协议的许多机会。*Poul-Henning Kamp*，*Varnish Cache*的开发者，甚至表示 HTTP/2 是不一致的，过于复杂且不必要。此外，他指出它违反了协议分层的原则，通过复制应该在传输层正常进行的流量控制 [2]。最后，在这个新协议中发现了许多安全漏洞，其中最显著的是由网络安全公司 Imperva 在 2016 年 Black Hat USA 会议上披露的那些 [3]。这些漏洞包括慢速读取攻击、依赖循环攻击、流复用滥用和 HPACK 炸弹。基本上，所有这些攻击向量都可以用来通过提交**拒绝服务**（**DoS**）攻击或通过饱和其内存来使服务器下线。

尽管存在许多与加密相关的问题，但所有主要的网络服务器和浏览器都已经采用并提供了对其的支持。大多数情况下，如果您的网络服务器已经配置并编译了 HTTP/2 标志，您只需要在服务器的`/etc/httpd/httpd.conf`文件中激活模块即可开始使用它。在 Apache Web 服务器的情况下，您还必须在服务器的配置文件中添加`Protocols`指令。请注意，在服务器上激活 HTTP/2 协议将对资源消耗产生重大影响。例如，在 Apache Web 服务器上启用此功能将导致创建许多线程，因为服务器将通过创建专用工作程序来处理和流式传输结果以响应客户端的 HTTP/2 请求。以下是如何在 Apache 的`httpd.conf`和`httpd-ssl.conf`配置文件中启用 HTTP/2 模块的示例（假设`mod_ssl`模块也已启用）：

```php
# File: /etc/httpd/httpd.conf
[...]
LoadModule ssl_module /usr/lib/httpd/modules/mod_ssl.so
LoadModule http2_module /usr/lib/httpd/modules/mod_http2.so
[...]

# File: /etc/httpd/extra/httpd-ssl.conf
[...]
<VirtualHost _default_:443>

Protocols h2 http/1.1

#   General setup for the virtual host
DocumentRoot "/srv/www"
[...]
```

有关 HTTP/2 协议的更多信息，请访问以下网址：

+   [`developers.google.com/web/fundamentals/performance/http2/`](https://developers.google.com/web/fundamentals/performance/http2/)

要了解 Apache 对相同协议的实现更多信息，请访问以下链接：

+   [`httpd.apache.org/docs/2.4/howto/http2.html`](https://httpd.apache.org/docs/2.4/howto/http2.html)

+   [`httpd.apache.org/docs/2.4/mod/mod_http2.html`](https://httpd.apache.org/docs/2.4/mod/mod_http2.html)

最后，要了解 NGINX 提供的实现更多信息，请参阅他们的文档：

+   [`nginx.org/en/docs/http/ngx_http_v2_module.html`](http://nginx.org/en/docs/http/ngx_http_v2_module.html)

# PHP-FPM 和 OPCache

谈到更快的 Web 时，考虑如何确保 PHP 二进制本身在 Web 服务器上以优化的方式运行是非常重要的，考虑到 PHP 安装在全球 70%至 80%的服务器上。

# PHP-FPM

自 PHP 5.3 以来，PHP 现在包括一个 FastCGI 进程管理器，允许您在 Web 服务器上运行更安全、更快速和更可靠的 PHP 代码。在 PHP-FPM 之前，在 Web 服务器上运行 PHP 代码的默认方式通常是通过`mod_php`模块。PHP-FPM 如此有趣的原因在于它可以根据传入请求的数量自适应，并在工作池中生成新进程，以满足不断增长的需求。此外，以这种方式运行 PHP 允许更好的脚本终止、更优雅的服务器重启、更高级的错误报告和服务器日志记录，以及通过守护进程化 PHP 二进制对每个 PHP 工作池进行 PHP 环境的精细调整。

许多高流量网站报告称，他们在将生产服务器上的 `mod_php` 更改为 `PHP-FPM` 后，看到了高达 300%的速度提升。当然，正如 Ilia Alshanetsky 在他的一个演示中提到的那样[4]，在提供静态内容时，像 lighttpd、thttpd、Tux 或 Boa 这样的许多其他服务器，可能比 Apache 快 400%。但是，当涉及到动态内容时，没有任何服务器可以比 Apache 或 NGINX 更快，特别是当它们与 PHP-FPM 结合使用时。

在服务器上启用 PHP-FPM 就像在编译时使用 `--enable-fpm` 开关配置 PHP 一样简单。从那里开始，问题就是确定如何运行 PHP-FPM，这取决于性能和安全问题。例如，如果您在生产环境中，您可能决定在许多服务器上运行许多工作池的 PHP-FPM，以分发工作负载。此外，出于性能和安全原因，您可能更喜欢在服务器上通过 UNIX 套接字而不是网络环回(`127.0.0.1`)运行 PHP-FPM。事实上，在任何情况下，UNIX 套接字都更快，并且将提供更好的安全性，以防止本地网络攻击者，可能始终尝试使用域授权通过强制适当的访问控制来破坏环回的套接字监听器以确保连接机密性。

# Zend OPcache

自 PHP 5.5 以来，当在编译时向配置脚本添加 `--enable-opcache` 开关时，opcode 缓存现在可以在 PHP 的核心功能中使用。

一般来说，Zend OPcache 将使任何脚本的运行速度提高 8%至 80%。脚本的墙时间由 PHP 二进制引起的时间越长，OPcache 的差异就越大。但是，如果脚本的 PHP 代码非常基本，或者如果 PHP 由于 I/O 引起的延迟而减慢，例如对文件的流或对数据库的连接，OPcache 只会轻微提高脚本性能。

在所有情况下，Zend OPcache 将优化 PHP 脚本性能，并应默认在所有生产服务器上启用。

让我们看看如何配置运行 PHP 7.1.16 (NTS) 的 Linux 中包含的 PHP-FPM 服务器，以使用 UNIX 套接字而不是网络环回来建立 Apache 和 PHP 之间的连接。此外，让我们配置 PHP-FPM 以使用 Zend OPcache。

请确保您的容器仍在运行，并在其 CLI 上输入以下命令：

```php
# rm /srv/www
# ln -s /srv/fasterweb/chapter_9 /srv/www
# cd /srv/www
# cat >>/etc/php.ini << EOF 
> [OpCache] 
> zend_extension = $( php -i | grep extensions | awk '{print $3}' )/opcache.so 
> EOF 
# sed -i 's/;opcache.enable=1/opcache.enable=1/' /etc/php.ini 
# sed -i 's/Proxy "fcgi://127.0.0.1:9000"/Proxy "unix:/run/php-fpm.sock|fcgi://localhost/"/' /etc/httpd/httpd.conf 
# sed -i 's/# SetHandler "proxy:unix:/SetHandler "proxy:unix:/' /etc/httpd/httpd.conf 
# sed -i 's/SetHandler "proxy:fcgi:/# SetHandler "proxy:fcgi:/' /etc/httpd/httpd.conf 
# sed -i 's/listen = 127.0.0.1:9000/; listen = 127.0.0.1:9000nlisten = /run/php-fpm.sock/' /etc/php-fpm.d/www.conf 
# /etc/init.d/php-fpm restart 
# chown apache:apache /run/php-fpm.sock 
# /etc/init.d/httpd restart 
```

现在，您可以使用*vi*编辑器查看修改后的`php.ini`文件，以确保以前的设置不再被注释掉，并且新的`[OPcache]`部分已添加到文件中。然后，在您喜欢的浏览器中，当访问`http://localhost:8181/phpinfo.php`时，您应该会看到以下屏幕：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/4d7f8662-abf5-403b-8bfa-21105a6039a1.png)确认 Zend Opcache 已启用并正在运行

如果您看到上一个屏幕，那么您已成功将*Apache*服务器通过 UNIX 套接字连接到 PHP-FPM，并启用了*Zend OPcache*。

如果您希望在*Linux for PHP*基础镜像（`asclinux/linuxforphp-8.1:src`）中使用 FPM 和*OPCache*配置开关从头开始编译 PHP，请在新的终端窗口中输入以下命令：

```php
# docker run --rm -it -p 8383:80 asclinux/linuxforphp-8.1:src /bin/bash -c "cd ; wget -O tmp http://bit.ly/2jheBrr ; /bin/bash ./tmp 7.2.5 nts ; echo '<?php phpinfo();' > /srv/www/index.php ; /bin/bash"
```

如果您希望手动完成相同的操作，请访问*Linux for PHP*网站以获取进一步的说明（[`linuxforphp.net/cookbook/production`](https://linuxforphp.net/cookbook/production)）。

# ESI 和 Varnish 缓存

另一种更快的 Web 技术是**边缘包含**（**ESI**）标记语言和 HTTP 缓存服务器。

# 边缘包含（ESI）

最初作为**万维网联盟**（**W3C**）于 2001 年批准的规范，ESI 被认为是通过将边缘计算应用于 Web 基础设施扩展的一种方式。边缘计算是一种通过在数据源附近进行数据处理来优化云计算的方法，而不是将所有数据处理集中在数据中心。在 ESI 的情况下，想法是将 Web 页面内容分散到网络的逻辑极端，以避免每次都将所有内容请求发送到 Web 服务器。

规范要求新的 HTML 标记，这些标记将允许 HTTP 缓存服务器确定页面的某些部分是否需要从原始 Web 服务器获取，或者这些部分的缓存版本是否可以发送回客户端，而无需查询服务器。可以将 ESI 视为一种 HTML 包含功能，用于从不同的外部来源组装网页的动态内容。

许多 HTTP 缓存服务器开始使用新的标记语言。一些**内容交付网络**（**CDN**），如 Akamai，以及许多 HTTP 代理服务器，如 Varnish、Squid 和 Mongrel ESI，多年来开始实施该规范，尽管大多数并未实施整个规范。此外，一些服务器，如 Akamai，添加了原始规范中没有的其他功能。

此外，重要的 PHP 框架，如*Symfony*，开始在其核心配置中添加 ESI 功能，从而使 PHP 开发人员在开发应用程序时立即开始考虑 ESI。

此外，浏览器开始鼓励 ESI 的使用，通过在 Web 上保留所有获取的文件的本地缓存，并在其他网站请求相同文件时重复使用它们。因此，在您的网站上使用 CDN 托管的 JavaScript 文件可以减少客户端请求您的 Web 服务器的次数，只需一次获取相同的文件。

使用`esi:include`标记在 HTML 中开始缓存网页的部分非常容易。例如，您可以这样使用：

```php
<!DOCTYPE html>
<html>
    <body>
        ... content ...

        <!-- Cache part of the page here -->
        <esi:include src="http://..." />

        ... content continued ...
    </body>
</html>
```

另一个例子是使用 PHP 和*Symfony*框架自动生成 ESI 包含标记。这可以通过让*Symfony*信任*Varnish Cache*服务器，在 YAML 配置文件中启用 ESI，在其控制器方法中设置网页的共享最大年龄限制，并在相应的模板中添加所需的渲染辅助方法来轻松实现。让我们一步一步地进行这些步骤。

首先让*Symfony*信任*Varnish Cache*服务器。在*Symfony*的最新版本中，您必须调用`Request`类的静态`setTrustedProxies()`方法。在*Symfony*安装的`public/index.php`文件中，添加以下行：

```php
# public/index.php

[...]

$request = Request::createFromGlobals();

// Have Symfony trust your reverse proxy
Request::setTrustedProxies(

    // the IP address (or range) of your proxy
    ['192.0.0.1', '10.0.0.0/8'],

    // Trust the "Forwarded" header
    Request::HEADER_FORWARDED

    // or, trust *all* "X-Forwarded-*" headers
    // Request::HEADER_X_FORWARDED_ALL

    // or, trust headers when using AWS ELB
    // Request::HEADER_X_FORWARDED_AWS_ELB

); }

[...]
```

根据您使用的*Symfony*版本和*Varnish*版本，您可能需要遵循不同的步骤才能完成此操作。请参阅*Symfony*文档的以下页面以完成此第一步：[`symfony.com/doc/current/http_cache/varnish.html`](https://symfony.com/doc/current/http_cache/varnish.html)。

然后，将以下行添加到您的*Symfony*配置文件中：

```php
# config/packages/framework.yaml

framework:
    # ...
    esi: { enabled: true }
    fragments: { path: /_fragment }
```

完成后，修改一些控制器如下：

```php
# src/Controller/SomeController.php

namespace App\Controller;

...

class SomeController extends Controller
{
    public function indexAction()
    {
        $response = $this->render('static/index.html.twig');

        $response->setSharedMaxAge(600);

        return $response;
    }
}
```

第二个应该修改如下：

```php
# src/Controller/OtherController.php

namespace App\Controller;

...

class OtherController extends Controller
{
    public function recentAction($maxPerPage)
    {
        ...

        $response->setSharedMaxAge(30);

        return $response;
    }
}
```

最后，在您的 Twig 模板中执行以下修改：

```php
{# templates/static/index.html.twig #}

{{ render_esi(controller('App\Controller\OtherController::recent', { 'maxPerPage': 5 })) }}
```

现在，您应该能够在加载*Symfony*应用程序的页面时看到 ESI 的效果。

为了更好地理解 ESI 的内部工作原理，让我们尝试安装和运行部分实现 ESI 规范的 HTTP 反向代理服务器。

# Varnish Cache

部分实现 ESI 的 HTTP 反向代理服务器之一是*Varnish Cache*。这个 HTTP 缓存服务器最初是由其创始人*Poul-Henning Kamp*、*Anders Berg*和*Dag-Erling Smørgrav*构思的，作为* Squid *的一个非常需要的[5]替代品，* Squid *是一个著名的 HTTP 转发代理服务器（客户端代理）。*Squid*可以作为反向代理（服务器代理）工作，但很难设置它以这种方式工作。

导致创建*Varnish Cache*的原始会议于 2006 年 2 月在奥斯陆举行。该项目背后的基本概念是找到一种快速操纵从通过网络流量获取的字节的方法，以及确定何时何地以及何时缓存这些字节。多年后，*Varnish Cache*已成为 Web 上最重要的 HTTP 缓存服务器之一，几乎有三百万个网站在生产中使用它[6]。

为了更好地理解*Varnish Cache*的工作原理，让我们花点时间在 Linux for the PHP 基础容器中安装它。

在新的终端窗口中，请输入以下 Docker 命令：

```php
# docker run -it -p 6082:6082 -p 8484:80 asclinux/linuxforphp-8.1:src /bin/bash 
```

然后，输入以下命令：

```php
# pip install --upgrade pip
# pip install docutils sphinx
```

您现在应该在 CLI 上看到以下消息：

！[](assets/b7dd6cc4-a249-4d3e-aa18-52ff033a7293.png)确认所请求的 Python 模块已安装

然后，输入以下命令：

```php
# cd /tmp
# wget https://github.com/varnishcache/varnish-cache/archive/varnish-6.0.0.tar.gz
```

安装完成后，您应该看到类似于这样的屏幕：

！[](assets/93630a61-7072-4df1-865e-0fd84744a58c.png)下载包含 Varnish Cache 源代码的存档已完成

最后，请通过以下命令完成安装解压缩、配置和安装*Varnish Cache*：

```php
# tar -xvf varnish-6.0.0.tar.gz
# cd varnish-cache-varnish-6.0.0/
# sh autogen.sh
# sh configure
# make
# make install
# varnishd -a 0.0.0.0:80 -T 0.0.0.0:6082 -b [IP_ADDRESS_OR_DOMAIN_NAME_OF_WEB_SERVER]:80
```

完成后，您应该收到以下消息：

！[](assets/3a80a169-63f6-4e67-80d5-b349edbecf52.png)Varnish Cache 守护程序现在正在运行并等待连接

正如我们在本书的第二章“持续分析和监控”中提到的，当我们通过*Docker*容器安装*TICK*堆栈时，您可以通过发出此命令来获取两个容器（运行*Apache*服务器和运行*Varnish*服务器的新容器）的 IP 地址：

```php
# docker network inspect bridge 
```

获得结果后，您可以将前一个命令中的[IP_ADDRESS_OR_DOMAIN_NAME_OF_WEB_SERVER]占位符替换为运行*Apache*（*Linux for PHP*容器）的容器的 IP 地址。在我的情况下，*Apache* Web 服务器的 IP 地址是`172.17.0.2`，*Varnish Cache*服务器的 IP 地址是`172.17.0.3`。因此，命令将是：

```php
# varnishd -a 0.0.0.0:80 -T 0.0.0.0:6082 -b 172.17.0.2:80 
```

一旦启动，您可以将浏览器指向*Varnish Cache*服务器的 IP 地址，您应该会得到*Apache* Web 服务器的内容。在我的情况下，当我将浏览器指向`172.17.0.3`时，我得到了预期的结果：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/6b5f3e6e-eddb-4ccd-b8b4-6ad94f1877cd.png)Varnish 正在缓存并返回从 Apache 服务器获取的响应

我们可以通过在新的终端窗口中发出以下`curl`命令并将结果传输到`grep`来确认*Varnish Cache*服务器是否正在使用我们的*Apache* Web 服务器作为其后端，以查看请求和响应头：

```php
# curl -v 172.17.0.3 | grep Forwarded 
```

结果应该类似于以下截图：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/7049f671-29b2-466a-86bc-ec3ee7bc900b.png)Varnish Cache 头部被添加到 Apache 头部中

正如我们所看到的，头部显示*Apache*服务器正在通过*Varnish Cache*服务器响应。

因此，通过正确的 DNS 配置，将所有的网络流量重定向到*Varnish Cache*服务器，并将 Web 服务器仅用作其后端成为可能。

这个例子向我们展示了配置*Varnish Cache*服务器是多么容易，以及开始使用它并立即从中受益以快速提升 Web 服务器性能是多么简单。

# 客户端缓存

让我们继续介绍另一种更快的 Web 技术，即客户端缓存。这种形式的 HTTP 缓存专注于减少呈现页面所需的请求次数，以尽量避免网络延迟。事实上，大型响应通常需要在网络上进行多次往返。HTTP 客户端缓存试图最小化这些请求的数量，以完成页面的呈现。如今，所有主要浏览器都支持这些技术，并且在您的网站上启用这些技术就像发送一些额外的头部或使用已经在**内容交付网络**（**CDN**）上可用的库文件一样简单。让我们看看这两种技术：浏览器缓存头部和 CDN。

# 浏览器缓存

浏览器缓存的基本思想是，如果在一定时间内某些文件完全相同，就不必获取响应中包含的所有文件。它的工作方式是通过服务器发送给浏览器的头部，以指示浏览器在一定时间内避免获取某些页面或文件。因此，浏览器将显示保存在其缓存中的内容，而不是在一定时间内通过网络获取资源，或者直到资源发生变化。

因此，浏览器缓存依赖于缓存控制评估（过期模型）和响应验证（验证模型）。缓存控制评估被定义为一组指令，它们告知浏览器谁可以缓存响应，在什么情况下以及多长时间。响应验证依赖于哈希令牌，以确定响应的内容是否已更改。它还使浏览器能够避免再次获取结果，即使缓存控制指示缓存的内容已过期。实际上，收到来自服务器的响应，指示内容未被修改，基于发送的令牌在服务器上未更改的事实，浏览器只需更新缓存控制并重置到期前的时间延迟。

这是通过使用某些响应头部来实现的。这些是**Cache-Control**和**ETag**头部。以下是在响应中接收到的这些头部的示例：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/046b2eaf-8ccf-42c0-baf5-ee1c70ff042c.png)浏览器缓存的工作原理

在这个例子中，Cache-Control 指示**最大年龄**为**120**秒，并设置了值为**"e4563ff"**的**ETag**。有了这两个头部，浏览器就能够充分管理其缓存。因此，启用浏览器缓存就像将这些响应头部添加到 Web 服务器返回的响应中一样简单。对于*Apache*来说，只需确保 FileETag 指令已添加到服务器的配置文件中即可。

在 PHP 中，也可以直接使用*Symfony*框架设置 Cache-Control 和 Expires 头。具体来说，*Symfony*的响应对象允许您使用其`setCache()`方法设置所有 Cache-Control 头。以下是使用此方法的示例：

```php
# src/Controller/SomeController.php

...

class SomeController extends Controller
{
    public function indexAction()
    {
        $response = $this->render('index.html.twig');

        $response->setCache(array(
            'etag'          => $etag,
            'last_modified' => $date,
            'max_age'       => 10,
            's_maxage'      => 10,
            'public'        => true,
         // 'private'       => true,
        ));

        return $response;
    }
}
```

看到了开始使用浏览器 HTTP 缓存是多么容易和简单，让我们花点时间来看看当与 HTTP 反向代理服务器技术结合时，HTTP 缓存还有其他好处。

# 内容传送网络（CDN）

内容传送网络是分布式代理服务器网络，允许常见或流行的网页资源高可用和高性能分发。这些资源可以是文本、图像和脚本等网页对象，包括 CSS 和 JavaScript 库，可下载的对象，如文件和软件，以及实时流或点播流媒体。CDN 因此可以被用作一种互联网公共缓存。通过使用 CDN 托管所有库文件，您将浏览器 HTTP 缓存与 HTTP 反向代理缓存结合在一起。这意味着如果另一个网站或网页应用程序使用与您相同的库文件，您的用户浏览器将使用其缓存版本的库文件或提交一个请求到 CDN 而不是您的网页服务器来刷新文件。这不仅通过减少全球渲染相同内容所需的请求数量来减少网络延迟，还通过将刷新过期浏览器缓存的责任委托给 CDN 的反向代理缓存，从您的网页服务器中减轻了一部分工作负载。

这个更快的网络解决方案非常容易实现。通常只需要通过修改 DNS 配置将网页流量重定向到 CDN。例如，*Cloudflare* ([`www.cloudflare.com/`](https://www.cloudflare.com/)) 不需要对您的网页服务器配置进行任何更改就可以开始使用其 HTTP 反向代理缓存。一旦您在*Cloudflare*界面中注册了原始域名和您的网页服务器的 IP 地址，您只需要通过将域名指向*Cloudflare*服务器来修改您的 DNS 设置，就可以立即开始使用它。让我们使用 cURL 来查询使用*Cloudflare*的[`linuxforphp.net/`](https://linuxforphp.net/)网站：

```php
# curl -v https://linuxforphp.net 
```

查询网站应该产生以下结果，确认它现在只能通过*Cloudflare*访问：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/8c27ad15-75a7-45e9-8e00-64bd6dc6841b.png)确认 linuxforphp.net 网站可以通过 Cloudflare 访问

正如我们所看到的，*Cloudflare*确实已启用，并已将 Cache-Control 和 Expires 添加到响应头中。

# 其他更快的网络工具

还有许多其他更快的网络工具可以帮助您优化您的网页应用程序和网站的性能。在这些众多工具中，有一些是谷歌在其开发者更快的网络网站上建议的（[`developers.google.com/speed/`](https://developers.google.com/speed/)）。其中一个工具将帮助您进一步分析网页应用程序的性能问题，那就是*PageSpeed Insights*。

这个工具可以快速识别您的网页应用可能的性能优化，基于您提交的 URL。为了进一步分析在*Linux for PHP*网站上使用*Cloudflare*的效果，让我们把 URL 提交到*PageSpeed Insights*工具。

以下是在使用*Cloudflare*之前的初始结果：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/cf0b7345-24ff-490c-b506-dd8b55efa9ac.png)在不使用 Cloudflare 时对 linuxforphp.net 网站性能分析的结果

接下来是添加*Cloudflare*反向代理服务器后的结果：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/72ee142a-8bdc-4159-ab87-096d6923b2f6.png)使用 Cloudflare 时对 linuxforphp.net 网站性能分析的结果

我们不仅可以看到网站的总体性能要好得多，而且*PageSpeed Insights*还提出了关于如何进一步优化 Web 应用程序的建议。

在切换到*Cloudflare*之前，该工具的初始建议如下：

建议在不使用 Cloudflare 时优化 linuxforphp.net 网站的性能

然后，在切换到*Cloudflare*之后：

建议在使用 Cloudflare 时优化 linuxforphp.net 网站的性能

正如我们所看到的，优化建议的列表要短得多，但如果我们利用浏览器缓存特定的图像文件，消除一些阻塞渲染的 JavaScript 和 CSS，减小图像大小，并尝试减少服务器响应时间，我们肯定会得到一个完美的分数！

# 总结

在这一章中，我们涵盖了一些与*Google*的新倡议“更快的网络”相关的项目。我们已经了解了 HTTP/2 协议的内容以及 SPDY 项目是如何实现的，PHP-FPM 和 Zend OPCache 如何帮助您提高 PHP 脚本的性能，如何通过设置 Varnish Cache 服务器来使用 ESI 技术，如何使用客户端缓存，以及其他更快的网络工具在优化 Web 服务器性能时如何帮助您。

在下一章中，我们将看到即使一切似乎已经完全优化，我们仍然可以超越性能。

# 参考资料

[1] [`tools.ietf.org/html/rfc7540`](https://tools.ietf.org/html/rfc7540)

[2] [`queue.acm.org/detail.cfm?id=2716278`](https://queue.acm.org/detail.cfm?id=2716278)

[3] [`www.imperva.com/docs/Imperva_HII_HTTP2.pdf`](https://www.imperva.com/docs/Imperva_HII_HTTP2.pdf)

[4] [`ilia.ws/files/zend_performance.pdf`](https://ilia.ws/files/zend_performance.pdf)

[5][ https://varnish-cache.org/docs/trunk/phk/firstdesign.html](https://varnish-cache.org/docs/trunk/phk/firstdesign.html)

[6][ https://trends.builtwith.com/web-server](https://trends.builtwith.com/web-server)，2018 年 3 月。
