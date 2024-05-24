# MySQL8 管理手册（三）

> 原文：[`zh.annas-archive.org/md5/D5BC20BC3D7872C6C7F5062A8EE852A4`](https://zh.annas-archive.org/md5/D5BC20BC3D7872C6C7F5062A8EE852A4)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：MySQL 8 存储引擎

在上一章中，我们学习了如何设置新系统、数据字典和系统数据库。提供了有关缓存技术、全球化、不同类型组件和插件配置以及对管理非常重要的几种类型日志文件的详细信息。

本章详细介绍了 MySQL 8 存储引擎。它详细解释了`InnoDB`存储引擎及其特性，并提供了有关自定义存储引擎创建以及如何使其可插拔以便安装在 MySQL 8 中的实用指南。本章将涵盖以下主题：

+   存储引擎概述

+   多种类型的存储引擎

+   `InnoDB`存储引擎

+   创建自定义存储引擎

# 存储引擎概述

存储引擎是 MySQL 组件，用于处理不同类型表格中使用的 SQL 操作。MySQL 存储引擎旨在管理不同类型环境中的不同类型任务。了解并选择最适合系统或应用需求的存储引擎非常重要。在接下来的章节中，我们将详细了解存储引擎的类型、默认存储引擎以及自定义存储引擎的创建。

让我们来看看为什么存储引擎是数据库中非常重要的组件，包括 MySQL 8。存储引擎与数据库引擎一起在不同环境中执行各种类型的任务。它们以语句的形式在数据库中对数据执行创建、读取、更新和删除操作。当您在创建表语句中提供`ENGINE`参数时，看起来很简单，但对于每个通过 SQL 语句发送的请求，需要对数据执行大量操作的配置。它远不止是持久化数据 - 引擎还负责存储限制、事务、锁定粒度/级别、多版本并发控制、地理空间数据类型、地理空间索引、B 树索引、T 树索引、`Hash`索引、全文搜索索引、聚集索引、数据缓存、索引缓存、压缩数据、加密数据、集群数据库、复制、外键、备份、查询缓存以及更新数据字典的统计信息。

# MySQL 存储引擎架构

MySQL 存储引擎的可插拔架构允许数据库专业人员为任何特定应用程序选择任何存储引擎。MySQL 存储引擎架构提供了一个简单的应用模型和 API，具有一致性，可以隔离数据库管理员和应用程序员免受存储级别的所有底层实现细节的影响。因此，应用程序始终在不同存储引擎的不同功能之上运行。它提供了标准的管理和支持服务，适用于所有底层存储引擎。

存储引擎在物理服务器级别上对持久化数据执行活动。这种模块化和高效的架构为任何特定应用程序的特定需求提供了解决方案，例如事务处理、高可用性情况或数据仓库，并且同时具有独立于底层存储引擎的接口和服务的优势。

数据库管理员和应用程序员通过连接器 API 和服务与 MySQL 数据库进行交互，这些 API 和服务位于存储引擎之上。MySQL 服务器架构使应用程序免受存储引擎的详细级别复杂性的影响，通过提供易于使用的 API，这些 API 在所有存储引擎上都是一致的和适用的。如果应用程序需要更改底层存储引擎，或者添加一个或多个存储引擎以支持应用程序的需求，那么不需要进行重大的编码或流程更改即可使事情正常运行。

# 多种类型的存储引擎

现在我们知道了存储引擎的重要性，以及从众多可用的存储引擎中选择使用哪些存储引擎的关键决策。让我们看看有哪些可用的存储引擎以及它们的规格。当您开始考虑存储引擎时，`InnoDB`是您首先想到的名字，对吧？

InnoDB 是 MySQL 8 中的默认和最通用的存储引擎，Oracle 建议将其用于表以及特殊用例。MySQL 服务器具有可插拔的存储引擎架构，可以从已经运行的 MySQL 服务器中加载和卸载存储引擎。

在 MySQL 8 中，识别服务器支持的存储引擎非常容易。我们只需进入 MySQL shell 或提示符，并使用`SHOW ENGINES`语句。在提示时输入该语句，结果将是一列引擎，包括 Engine、Support、Transactions、Savepoints 和 Comment。

支持列中的值 DEFAULT、YES 和 NO 表示存储引擎是否可用，并当前设置为默认存储引擎。

# InnoDB 存储引擎概述

`InnoDB`是 MySQL 8 中默认的、最通用的存储引擎，提供高可靠性和高性能。

如果您没有配置不同的默认存储引擎，那么在 MySQL 8 中发出不带`ENGINE =`子句的 SQL 语句`CREATE TABLE`将创建一个具有存储引擎`InnoDB`作为默认引擎的表。

`InnoDB`存储引擎提供的功能和优势将在*InnoDB 存储引擎*部分中进行解释。

# 自定义存储引擎

MySQL 5.1 和所有后续版本以及 MySQL 8 中的存储引擎架构都利用了灵活的存储引擎架构。

存储引擎可插拔架构提供了创建和添加新存储引擎的能力，而无需重新编译服务器，直接添加到正在运行的 MySQL 服务器。这种架构使得开发和部署新的存储引擎到 MySQL 8 变得非常容易。

我们将在即将到来的*创建自定义存储引擎*部分中使用 MySQL 存储引擎架构的可插拔特性来开发一个新的存储引擎。

# 多种类型的存储引擎

在这一部分，我们将更仔细地查看 MySQL 8 支持的广泛使用的存储引擎。但在查看它们之前，让我们看看存储引擎架构是如何可插拔的，并提供了灵活性，以便在同一模式或服务器中使用多个存储引擎。

以下是 MySQL 8 支持的存储引擎列表。

+   `InnoDB`：MySQL 8 的默认存储引擎。它是一个符合`ACID`（事务安全）的存储引擎，具有提交、回滚和崩溃恢复，用于保护用户数据和`引用完整性`约束以维护数据完整性，等等。

+   `MyISAM`：具有小占用空间的表的存储引擎。它具有表级锁定，因此主要用于只读或读最多的数据工作负载，例如数据仓库和 Web 配置。

+   `Memory`：以前被称为`HEAP`引擎的存储引擎。它将数据保存在 RAM 中，提供更快的数据访问，主要用于非关键数据环境的快速查找。

+   `CSV`：这种存储引擎使用文本文件和表中的逗号分隔值作为表。它们没有索引，主要用于以`CSV`格式导入和转储数据。

+   `存档`：这种存储引擎包括紧凑的、无索引的表，旨在存储和检索大量历史、归档或安全审计数据。

+   `黑洞`：这种存储引擎包括用于复制配置的表。查询总是返回一个空集。`DML` SQL 语句被发送到从服务器。它接受数据，但数据不会被存储，就像在 Unix 的`/dev/null`设备中使用一样。

+   `合并`：这种存储引擎提供了将一系列相似的`MyISAM`表逻辑分组并将它们称为一个对象的能力，而不是单独的表。

+   `联合`：这种存储引擎可以将许多独立的物理 MySQL 服务器链接成一个逻辑数据库。它非常适合数据仓库或分布式环境。

+   `示例`：这种存储引擎什么也不做，只是作为一个`存根`。它主要由开发人员使用，用来演示如何在 MySQL 源代码中开始编写新的存储引擎。

MySQL 不限制在整个服务器或模式上使用相同的存储引擎；相反，在表级别指定引擎使其根据数据类型和应用程序的用例变得灵活。

# 可插拔存储引擎架构

MySQL 服务器使用可插拔存储引擎架构，可以从已运行的 MySQL 服务器中加载和卸载存储引擎：

+   **安装存储引擎**：在服务器中使用存储引擎之前，必须使用`INSTALL PLUGIN` SQL 语句将存储引擎插件共享库加载到 MySQL 中。如果您创建了一个名为`MyExample`的`MYEXAMPLE`引擎插件，并且共享库的名称为`MyExample.so`，那么您需要使用以下语句加载它们：

```sql
 mysql> INSTALL PLUGIN MyExample SONAME 'MyExample.so';
```

要安装存储引擎，发出前述语句的用户必须对`mysql.plugin`表具有`INSERT`权限，并且插件文件必须存在于 MySQL 插件目录中。共享库也必须存在于`plugin_dir`变量中给出的 MySQL 服务器插件目录中。

+   **卸载存储引擎**：在卸载存储引擎之前，请确保没有表在使用该存储引擎。如果卸载了一个存储引擎，并且任何现有表需要该存储引擎，那么这些表将变得不可访问，并且只会存在于适用的磁盘上。如果您卸载了名为`MyExample`的`MYEXAMPLE`引擎插件，然后执行以下语句来卸载存储引擎：

```sql
 mysql> UNINSTALL PLUGIN MyExample ;
```

# 常见的数据库服务器层

MySQL 可插拔存储引擎负责在实际数据上执行 I/O 操作，并满足特定应用程序的需求，包括在需要时启用和强制执行所需的功能。使用特定或单一存储引擎更有可能导致更高的效率和更高的数据库性能，因为该引擎仅启用特定应用程序所需的功能，从而减少数据库的系统开销。

存储引擎支持以下独特的基础设施组件或键：

+   **并发性**：一些应用程序对锁级别（如行级锁）的要求比其他应用程序更细粒度。选择正确/错误的锁定策略以及多版本并发控制或快照读取功能都可能影响整体性能和由于锁定而产生的开销。

+   **事务支持**：存在非常明确定义的要求，比如`ACID`兼容性，如果应用程序需要事务，则还有更多要求。

+   **引用完整性**：服务器可以使用`DDL`定义的外键来强制关系数据库引用完整性，如果需要的话。

+   **物理存储**：这包括从表和索引的页面大小到在物理磁盘上存储数据所使用的格式等一切。

+   **索引支持**：这包括基于应用程序需求的索引策略，因为每个存储引擎都有自己的索引方法。

+   **内存缓存**：这是基于应用程序需求的缓存策略，因为每个存储引擎都有自己的缓存方法，以及所有存储引擎的通用内存缓存。

+   **性能辅助**：这涉及到大量插入处理、数据库检查点、多个 I/O 线程进行并行操作、线程并发性等。

+   **其他目标特性**：这可能包括对某些数据操作的安全限制、地理空间操作和其他类似特性的支持。

前述的基础设施组件都是为了支持特定应用程序需求的一组特定功能而设计的，因此非常重要的是要非常仔细地了解应用程序的需求，并选择正确的存储引擎，因为这可能会影响整个系统的效率和性能。

# 设置存储引擎

当使用`CREATE TABLE`语句创建新表时，可以使用`ENGINE`表选项指定要为表使用的引擎。如果不指定`ENGINE`表选项，则将使用默认的存储引擎。`InnoDB`是 MySQL 8.0 的默认引擎。您还可以使用`ALTER TABLE`语句将表从一个存储引擎转换为另一个存储引擎，如下例所示：

```sql
CREATE TABLE table1 (i1 INT) ENGINE = INNODB;
CREATE TABLE table3 (i3 INT) ENGINE = MEMORY;
ALTER TABLE table3 ENGINE = InnoDB;
```

可以通过设置`default_storage_engine`变量为当前会话设置默认存储引擎，如下例所示：

```sql
SET default_storage_engine=MEMORY;
```

使用`CREATE TEMPORARY TABLE`创建`TEMPORARY`表的默认存储引擎可以通过在启动或运行时设置`default_tmp_storage_engine`变量来单独设置。

# `MyISAM`存储引擎

`MyISAM`存储引擎使用占用空间小的表。它实现了表级锁定，因此主要用于只读或读取大部分数据负载的情况，例如数据仓库和 Web 配置。每个`MyISAM`表都存储在磁盘上的两个文件中。文件名以表名和其扩展类型开头，一个带有`.MYD`扩展名的数据文件，另一个带有`.MYI`扩展名的索引文件。

对于`MyISAM`引擎，有几个在`mysqld`中指定的启动选项可以改变`MyISAM`表的行为；例如：

```sql
--myisam-recover-options=mode
```

此选项将设置在`MyISAM`中崩溃表的自动恢复模式。

在`MyISAM`中需要用于键的空间，`MyISAM`表使用`B-Tree`索引，并且在`String`索引中使用空间压缩。如果一个字符串是索引的第一部分，那么还会进行前缀压缩，这样整体使索引文件大小更小。前缀压缩有助于处理许多具有相似前缀的字符串。通过在`MyISAM`表中使用表选项`PACK_KEYS=1`，前缀压缩也可以应用于数字，如果有许多具有相似前缀的数字。

在 MySQL 8.0 中，不支持对`MyISAM`表进行分区。

`MyISAM`表的一些重要特性如下：

+   存储的所有数据值都以低字节优先顺序存储，这使得数据独立于机器和操作系统

+   所有数值键值都以高字节优先顺序存储，这允许更好的索引压缩

+   `MyISAM`表的行数限制为*(2³²)²(1.844E+19)*。

+   `MyISAM`表的最大索引数限制为 64 个

+   `MyISAM`表的列索引最大数限制为 16 个

+   在`MyISAM`中支持并发插入，如果表在数据文件中间没有空闲块

+   `MyISAM`中也可以对`TEXT`和`BLOB`类型的列进行索引

+   在索引列中，允许`NULL`值

+   每一列都可以有不同的字符集

+   它还支持真正的 VARCHAR 类型列，其起始长度存储为 1 或 2 个字节，具有固定或动态行长度的 VARCHAR 列，以及任意长度的 UNIQUE 约束

+   MyISAM 表存储格式：MyISAM 支持以下三种不同类型的存储格式：

+   静态表：MyISAM 存储引擎中表的默认格式，具有固定大小的列

+   动态表：顾名思义，包含可变大小列的格式，包括 VARCHAR、BLOB 或 TEXT

+   压缩表：用于在 MyISAM 存储引擎表中保存只读数据和压缩格式的表格格式

前两种格式，固定和动态，根据使用的列类型自动选择。压缩格式可以通过使用 myisampack 实用程序创建。

+   MyISAM 表问题：文件格式经过了广泛测试，但有些情况会导致数据库表损坏。让我们看看这些情况以及恢复这些表的方法。

在以下事件中可能会出现损坏的表：

+   如果 mysqld 进程在写入过程中被杀死

+   如果有意外的计算机关闭

+   如果有任何硬件故障

+   如果 MySQL 服务器和外部程序（如 myisamchk）同时修改表

+   MySQL 或 MyISAM 代码存在软件错误

使用 CHECK TABLE 语句检查表的健康状况，并尝试使用 REPAIR TABLE 语句修复任何损坏的 MyISAM 表。

MyISAM 表可能出现的问题是表没有被正确关闭。为了确定表是否被正确关闭，每个 MyISAM 索引文件在标头中保留一个计数器。在以下情况下，计数器可能不正确：

+   如果表在不发出 LOCK TABLES 和 FLUSH TABLES 的情况下被复制

+   MySQL 在更新期间最终关闭之前崩溃

+   mysqld 正在使用表，同时被另一个程序修改：myisamcheck --recover 或 myisamchk --update-state

# MEMORY 存储引擎

MEMORY 存储引擎，以前也称为 HEAP 引擎，将数据保存在 RAM 中，提供更快的数据访问。它主要用于快速查找非关键数据环境。它创建专用表，其中内容存储在内存中，但数据容易受到崩溃、停电和硬件问题的影响。因此，这些表用于临时工作区或在从其他表中提取数据后缓存只读数据。

您应该选择使用 MEMORY 还是 NDB Cluster。您应该检查应用程序是否需要重要的、高可用的或经常更新的数据，并考虑 NDB Cluster 是否是更好的选择。NDB Cluster 提供与 MEMORY 引擎相同的功能，但性能水平更高，并且具有 MEMORY 引擎不提供的其他功能。这些包括：

+   客户端之间的低争用通过多线程操作和行级锁定

+   包括写入的语句混合的可伸缩性

+   数据耐久性；它支持可选的磁盘支持操作

+   无共享架构，提供多主机操作而没有单点故障，为应用程序提供 99.999%的可用性

+   自动数据分布跨节点

+   支持可变长度数据类型，包括 BLOB 和 TEXT

MEMORY 表不支持分区

性能取决于服务器的繁忙程度以及单线程执行对更新处理期间的表锁开销的影响。在更新处理期间对表进行锁定会导致在 MEMORY 表上的多个会话的并发使用减慢。

**MEMORY 表特点**：表定义存储在 MySQL 数据字典中，并不在磁盘上创建任何文件。以下是表特性的亮点：

+   100%动态哈希用于插入，并且空间分配在小块中。

+   不需要额外的键空间、溢出区域或空闲列表的额外空间。通过将行放入链接列表中重用已删除的行来插入新记录。

+   固定长度行存储格式，`VARCHAR`，以固定长度存储。无法存储`BLOB`或`TEXT`列。

+   支持`AUTO_INCREMENT`列。

`MEMORY`存储引擎支持`HASH`和`BTREE`类型的索引。`MEMORY`表每个表最多有 64 个索引，每个索引最多有 16 列，最大键长度为 3,072 字节。`MEMORY`表也可以有`非唯一`键。

**用户创建和临时表**：服务器在处理查询时动态创建内部临时表。两种类型的表在存储转换上有所不同，其中`MEMORY`表不受转换的影响：

+   当内部临时表变得太大时，服务器会自动将其转换为磁盘存储

+   用户创建的`MEMORY`表不会被服务器转换

可以使用`--init-file`选项，使用`INSERT INTO ... SELECT`或`LOAD DATA INFILE`语句从任何持久性数据源加载数据，如果需要的话。

# CSV 存储引擎

该存储引擎以逗号分隔值的形式将数据存储在文本文件中。该引擎始终编译到 MySQL 服务器中，可以从 MySQL 分发的`storage/csv`目录中检查源代码。

服务器创建的数据文件以给定表和扩展名`.CSV`开头。数据文件是一个纯文本文件，以逗号分隔值格式包含数据。

MySQL 服务器创建一个与`CSV`表对应的元文件，该文件存储有关表状态和表中存在的行数的信息。元文件也与表名一起存储在以`.CSM`扩展名开头的位置。

+   **修复和检查**`CSV`**表**：存储引擎支持`CHECK`和`REPAIR`语句来验证并可能修复损坏的`CSV`表。您可以使用`CHECK TABLE`语句来验证或验证表，并使用`REPAIR TABLE`语句来修复从现有`CSV`数据文件复制有效行并用新复制/恢复的行替换现有文件的表。

在修复过程中，只有从`CSV`数据文件到第一个损坏的行的行被复制到新表或复制的数据文件中。损坏行后的其余行将从表中删除，包括有效行，因此建议您在进行修复之前对数据文件进行足够的备份。

`CSV`存储引擎不支持索引或分区，所有使用`CSV`存储引擎创建的表必须在所有列上具有`NOT NULL`属性。

# ARCHIVE 存储引擎

`ARCHIVE`存储引擎创建专用表，用于存储大量未索引数据，占用非常小的空间。

当创建`ARCHIVE`表时，它以表名开头，并以`.ARZ`扩展名结尾。在优化操作期间，可能会出现一个带有`.ARN`扩展名的文件。

引擎支持`AUTO_INCREMENT`列属性。它还支持`INSERT`、`REPLACE`、`SELECT`和`BLOB`列（除了空间数据类型），但不支持`DELETE`、`UPDATE`、`ORDER`或`BY`操作。

`ARCHIVE`存储引擎不支持分区：

+   **存储**：该引擎使用`zlib`进行无损数据压缩，并在插入时对行进行压缩。它支持`CHECK TABLE`操作。引擎使用几种插入类型：

+   `INSERT`语句将行发送到压缩缓冲区，并根据需要刷新缓冲区。压缩缓冲区中的插入受锁保护，只有在请求`SELECT`时才会发生刷新。

+   完成后可以看到一个批量缓冲区。只有在同时发生其他插入时才能看到。在加载任何正常插入时，刷新不会在`SELECT`时发生。

+   **检索**：检索后，根据请求解压行，并且不使用任何行缓存。对于`SELECT`操作执行完整的表扫描：

+   `SELECT`检查当前有多少行可用，并且只读取该数量的行。它作为一次一致的读操作执行。

+   `SHOW TABLE STATUS`报告的行数对于`ARCHIVE`表始终是准确的。

+   使用`OPTIMIZE TABLE`或`REPAIR TABLE`操作以实现更好的压缩。

# BLACKHOLE 存储引擎

`BLACKHOLE`存储引擎充当黑洞。它接受数据但不存储数据，查询总是返回空结果。

服务器只有在创建`BLACKHOLE`表并且没有文件与该表关联时，才会在全局数据字典中添加表定义。

`BLACKHOLE`存储引擎支持各种**索引**，因此可以在表定义中包含相同的内容。

`BLACKHOLE`存储引擎不支持分区。

对表的插入不会存储任何数据，但如果为语句启用了二进制日志记录，则会记录并复制到从服务器。这种机制可用作过滤器或中继器。

`BLACKHOLE`存储引擎有以下可能的用途：

+   转储文件语法验证

+   使用启用或禁用二进制日志记录的`BLACKHOLE`性能比较的开销测量

+   它还可用于查找任何性能瓶颈，除了存储引擎本身

**自增列**：由于该引擎是一个无操作引擎，它不会增加任何字段值，但它对复制有影响，这可能非常重要。考虑以下情况：

1.  主服务器具有带有主键的自增字段的`BLOCKHOLE`表

1.  从服务器上存在相同的表，但使用`MyISAM`引擎

1.  在`INSERT`语句中插入到主服务器的表中，而不设置任何自增值或使用`SET INSERT_ID`语句

在上述情况下，主键列上的复制将失败，因为有重复条目。

# MERGE 存储引擎

`MERGE`存储引擎，也称为`MRG_MyISAM`引擎，是一组类似的表，可以作为一个表来使用。这里的“类似”意味着所有表具有相似的列数据类型和索引信息。不可能合并列顺序不同的表，或者在各自列中具有相同的数据类型，或者以不同的顺序进行索引。

以下是不会限制合并的表中的差异列表：

+   各自列和索引的名称可能不同。

+   表，列和索引之间的注释可能不同。

+   `AVG_ROW_LENGTH`，`MAX_ROWS`或`PACK_KEYS`表选项可能不同。

创建`MERGE`表时，MySQL 还会在磁盘上创建一个`.MRG`文件，其中包含正在使用的`MyISAM`表的名称。表的格式存储在 MySQL 数据字典中，底层表不需要在与`MERGE`表相同的数据库中。

必须具有对与`MERGE`表映射的`MyISAM`表的`SELECT`，`UPDATE`和`DELETE`权限，因此可以使用`SELECT`，`INSERT`，`UPDATE`和`DELETE`语句对`MERGE`表进行操作。

在`MERGE`表上执行`DROP TABLE`语句将仅删除`MERGE`的规范，对底层表不会产生影响。

使用`MERGE`表存在以下安全问题。如果用户可以访问`MyISAM`表`t1`，那么用户可以创建可以访问`t1`的`MERGE`表`m1`。现在，如果用户对表`t1`的权限被撤销，用户仍然可以通过使用表`m1`继续访问表`t1`。

# FEDERATED 存储引擎

`FEDERATED`存储引擎可以将许多独立的物理 MySQL 服务器链接成一个逻辑数据库，因此可以让您访问远程 MySQL 服务器的数据，而无需使用复制或集群技术。

当我们查询本地`FEDERATED`表时，会自动从远程联合表中提取数据，不需要将数据存储在本地表中。

`FEDERATED`存储引擎不是 MySQL 服务器的默认支持，但是使用`--federated`选项启动服务器将启用`FEDERATED`引擎选项。

创建`FEDERATED`表时，表定义与其他表相同，但关联数据的物理存储是在远程服务器上处理的。`FEDERATED`表包括以下两个元素：

+   一个**远程服务器**，其中包含一个由表定义和相关表数据组成的数据库表。这种类型的表可以是远程服务器支持的任何类型，包括`MyISAM`或`InnoDB`。

+   一个**本地服务器**，其中包含一个由远程服务器上相同的表定义组成的数据库表。表定义存储在数据字典中，本地服务器上没有关联的数据文件存储。相反，除了表定义之外，它还保留一个指向远程表本身的连接字符串。

当在`FEDERATED`表上执行 SQL 语句时，本地服务器和远程服务器之间的信息流如下：

1.  该引擎检查表的每一列，并构建一个适当的 SQL 语句，引用远程表。

1.  MySQL 客户端 API 用于将 SQL 语句发送到远程服务器。

1.  该语句由远程服务器处理，并且本地服务器检索相应的结果。

# EXAMPLE 存储引擎

`EXAMPLE`存储引擎只是一个存根引擎，其目的是在 MySQL 源代码中提供示例，以帮助开发人员编写新的存储引擎。

要使用`EXAMPLE`引擎源代码，请查看 MySQL 源代码分发下载的`storage/example`目录。

如果使用`EXAMPLE`引擎创建表，则不会创建文件。数据不能存储在`EXAMPLE`引擎中，并且返回空结果。

`EXAMPLE`存储引擎不支持索引和分区。

# InnoDB 存储引擎

`InnoDB`是最通用的存储引擎，也是 MySQL 8 中的默认引擎，提供高可靠性和高性能。

`InnoDB`存储引擎提供的主要优势如下：

+   其`DML`操作遵循`ACID`模型，并且事务具有提交、回滚和崩溃恢复功能，以保护用户数据

+   `Oracle-style`提供一致的读取和行级锁定，增加了多用户并发性能

+   每个`InnoDB`表都有一个主键索引，称为聚簇索引，它按顺序在磁盘上排列数据，以优化基于主键的查询，并在主键查找期间最小化 I/O

+   通过支持外键，插入、删除和更新都会进行检查，以确保跨不同表的一致性，以维护数据完整性

使用`InnoDB`表的主要优势如下：

+   如果服务器由于任何硬件或软件问题而崩溃，无论当时服务器正在处理什么更改，重新启动服务器后都不需要进行任何特殊操作。它具有崩溃恢复系统，可以处理在服务器崩溃期间提交的更改。它将转到这些更改并从处理中断的地方开始。

+   引擎具有自己的缓冲池，用于根据访问的数据将表和索引数据缓存到内存中。经常使用的数据直接从缓存内存中获取，因此可以加快处理速度。在专用服务器中，它占用分配的物理内存的 80％用于缓冲池。

+   使用外键设置将相关数据拆分到表中，强制执行引用完整性，防止在没有主表中相应数据的情况下向辅助表插入任何不相关的数据。

+   如果内存或磁盘中存在损坏的数据，校验和机制会在我们使用之前提醒我们有损坏的数据。

+   更改缓冲区会自动优化`Insert`，`Update`和`Delete`。`InnoDB`还允许对同一表进行并发读写访问，并缓存数据更改以简化磁盘 I/O。

+   当从表中重复访问相同的数据行时，自适应哈希索引功能可以加快查找速度并提供性能优势。

+   允许在表和相关索引上进行压缩。

+   通过查询`INFORMATION_SCHEMA`或`Performance Schema`表，轻松监视存储引擎的内部工作和性能细节。

现在让我们看看存储引擎的每个区域，在这些区域中`InnoDB`被增强或优化以提供非常高效和增强的性能。

# ACID 模型

`ACID`模型是一组数据库设计原则，强调可靠性，这对于关键任务应用程序和业务数据至关重要。

MySQL 具有诸如`InnoDB`存储引擎之类的组件，严格遵循`ACID`模型。因此，即使在硬件故障或软件崩溃的特殊情况下，数据也是安全且不会损坏。

使用 MySQL 8，`InnoDB`支持原子`DDL`，确保即使在执行操作时服务器停止，`DDL`操作也会完全提交或回滚。现在`DDL`日志可以写入`mysql.innodb_ddl_log`配置以用于数据字典表，并启用`innodb_print_ddl_logs`配置选项以将`DDL`恢复日志打印到`stderr`。

# 多版本

InnoDB 是一种多版本存储引擎。这意味着它具有保留更改的旧版本行数据信息并支持事务特性（如并发性和回滚）的能力。信息存储在表空间、数据结构和命名回滚段中。

在内部，对于存储在数据库中的每一行，`InnoDB`创建三个字段：6 字节的`DB_TRX_ID`，7 字节的`DB_ROLL_PTR`（称为回滚指针）和 6 字节的`DB_ROW_ID`。有了这些字段，`InnoDB`创建了聚集索引，以保留数据库中更改的行数据信息。

# 架构

在本节中，我们将简要介绍`InnoDB`架构的主要组件：

+   缓冲池：主内存区域，用于缓存表和索引数据以加快处理速度

+   更改缓冲区：缓存对辅助索引页面的更改的特殊数据结构

+   自适应哈希索引：使内存数据库能够在具有平衡和适当组合的缓冲池内存和工作负载的系统上进行查找和操作

+   重做日志缓冲区：存储数据以便写入重做日志的内存区域

+   系统表空间：存储`doublewrite`缓冲区、撤销日志和更改缓冲区的存储区域，在 MySQL 8 数据字典信息之前存储

+   双写缓冲区：系统表空间中的存储区域，用于写入从缓冲池刷新的页面

+   **撤销日志**：与任何单个事务相关联的撤销日志记录的集合

+   **每个表的表空间**：添加到自己的数据文件的单表表空间

+   **通用表空间**：使用`CREATE TABLESPACE`语法创建的共享表空间

+   **撤销表空间**：一个或多个带有撤销日志的文件

+   **临时表空间**：用于非压缩临时表及其相关对象

+   **重做日志**：用于在崩溃恢复期间纠正不完整事务数据的基于磁盘的数据结构

在 MySQL 8 中，`InnoDB`存储引擎利用全局 MySQL 数据字典，而不是其自己的存储引擎特定数据字典。

# 锁定和事务模型

本节简要介绍了`InnoDB`使用的锁定和`InnoDB`实现的事务模型。`InnoDB`使用以下不同类型的锁定：

+   **共享和排他锁**：实现了两种标准的行级锁定。共享锁允许您将一行读取到不同的事务中；排他锁用于更新或删除一行，并且不允许您将该行读取到任何不同的事务中。

+   **意向锁**：表级锁，支持多粒度锁定，`InnoDB`实际上维护了行级锁和整个表级锁的共存。

+   **记录锁**：索引记录锁，防止任何其他事务插入、更新或删除记录。

+   **间隙锁**：锁定适用于索引记录之间的间隙（范围）。

+   **下一个键锁**：在前一个索引记录的间隙上组合索引记录锁和间隙锁。

+   **插入意向锁**：`INSERT`操作在插入行之前设置的一种间隙锁类型。

+   **AUTO-INC 锁**：用于插入具有`AUTO_INCREMENT`列的记录的特殊表级锁。

+   **空间索引的谓词锁**：对空间索引的锁定，使支持具有空间索引的表的隔离级别

遵循事务模型的目标是将传统的两阶段锁定与多版本数据库属性的最佳部分结合起来。执行行级锁定，并使用非锁定一致性读取运行查询。`InnoDB`负责事务隔离级别、自动提交、回滚和提交以及锁定读取。它允许根据需要进行非锁定一致性读取。`InnoDB`还使用一种机制来避免幻影行，并配置支持自动死锁检测。

# 配置

本节提供了有关`InnoDB`初始化启动中使用的配置和程序的简要信息，适用于不同的`InnoDB`组件：

+   `InnoDB` **启动配置**：包括指定启动选项、日志文件配置、存储考虑事项、系统表空间数据文件、撤销表空间、临时表空间、页面大小和内存配置

+   **用于只读操作的** `InnoDB`：使用`--innodb-read-only=1`选项，可以将 MySQL 实例配置为只读操作，当使用只读介质（如`CD`或`DVD`）时非常有用

+   `InnoDB` **缓冲池配置**：配置缓冲池大小、多个实例、刷新和监控

+   `InnoDB` **更改缓冲**：为辅助索引缓存配置更改缓冲选项

+   **`InnoDB`的线程并发性**：并发线程计数限制配置

+   **后台** `InnoDB` **I/O 线程的数量**：配置后台线程的数量，用于对数据页进行 I/O 读/写操作

+   在 Linux 上使用异步 I/O：在 Linux 上使用本机异步 I/O 子系统的配置

+   **`InnoDB`主线程 I/O 速率**：配置后台工作的主线程的整体 I/O 容量，负责多个任务

+   **自旋锁轮询**：配置自旋等待延迟周期，以控制多个线程之间频繁轮询以获取`mutexes`或`rw-locks`的最大延迟

+   `InnoDB` **清除调度**：为适用的可伸缩性配置清除线程。

+   **`InnoDB`的优化器统计信息**：配置持久和非持久的优化器统计参数。

+   **索引页的合并阈值**：配置`MERGE_THRESHOLD`以减少合并分裂行为。

+   **启用专用 MySQL 服务器的自动配置**：配置专用服务器选项`--innodb_dedicated_server`，以自动配置缓冲池大小和日志文件大小。

# 表空间

本节提供了关于表空间和在`InnoDB`中执行的表空间相关操作的简要信息：

+   **调整`InnoDB`系统表空间的大小**：在启动/重新启动 MySQL 服务器时，增加和减少系统表空间的大小。

+   **更改`InnoDB`重做日志文件的数量或大小**：在启动/重新启动 MySQL 服务器之前，分别配置`my.cnf`中的`innodb_log_files_in_group`和`innodb_log_file_size`值。

+   **使用原始磁盘分区作为系统表空间的数据文件**：配置原始磁盘分区以用作系统表空间中的数据文件。

+   `InnoDB` **每表表空间**：默认启用了`innodb_file_per_table`功能，确保每个表和相关索引都存储在单独的`.idb`数据文件中。

+   **配置撤消表空间**：配置设置撤消表空间的数量，其中撤消日志驻留。

+   **截断撤消表空间**：配置`innodb_undo_log_truncate`以启用截断超过`innodb_max_undo_log_size`定义的最大限制的撤消表空间文件。

+   `InnoDB` **通用表空间**：使用`CREATE TABLESPACE`语句创建的共享表空间。它类似于系统表空间。

+   `InnoDB` **表空间加密**：支持以文件为基础的表空间存储的表的数据加密，使用`AES`分块加密算法。

# 表和索引

本节提供了关于`InnoDB`表和索引以及它们相关操作的简要信息：

+   **创建`InnoDB`表**：使用`CREATE TABLE`语句创建表。

+   **`InnoDB`表的物理行结构**：取决于表创建时指定的行格式。如果未指定，则使用默认的`DYNAMIC`。

+   **移动或复制`InnoDB`表**：将一些或所有`InnoDB`表移动或复制到不同的实例或服务器的不同技术。

+   **将表从`MyISAM`转换为`InnoDB`**：在将`MyISAM`表转换为`InnoDB`表时考虑指南和提示，但不支持分区表，这在 MySQL 8 中不受支持。

+   `InnoDB`中的`AUTO_INCREMENT` **处理**：使用`innodb_autoinc_lock_mode`参数配置`AUTO_INCREMENT`的模式为 0、1 和 2，分别为传统、连续或交错，其中交错是 MySQL 8 的默认模式。

+   **`InnoDB`表的限制**：表最多可以包含 1,017 列，最多可以包含 64 个次要索引，以及基于页面大小、表大小和数据行格式定义的其他限制。

+   **聚集和次要索引**：`InnoDB`使用称为聚集索引的特殊索引。其余的索引称为次要索引。

+   **`InnoDB`索引的物理结构**：对于空间索引，`InnoDB`使用专门的数据结构`R-tree`。对于其他索引，使用`B-tree`数据结构。

+   **排序索引构建**：在创建或重建索引进行插入时进行批量加载。它们被称为排序索引构建，并且不支持空间索引。

+   `InnoDB` `FULLTEXT` **索引**：为基于文本的列（`char`，`varchar`或`text`类型）创建。它们有助于加快查询和搜索操作的速度。

# INFORMATION_SCHEMA 表

本节提供了`InnoDB` `INFORMATION_SCHEMA`表的用法示例和相关信息。

它提供了有关`InnoDB`存储引擎不同方面的元数据、统计和状态信息。

可以通过在`INFORMATION_SCHEMA`数据库上执行`SHOW TABLES`语句来检索`InnoDB` `INFORMATION_SCHEMA`表的列表：

```sql
mysql> SHOW TABLES FROM INFORMATION_SCHEMA LIKE 'INNODB%';
```

+   **关于压缩的表**：`INNODB_CMP`和`INNODB_CMP_RESET`表提供了有关压缩操作次数和压缩相关信息所花费的时间。在压缩期间的内存分配在`INNODB_CMPMEM`和`INNODB_CMPMEM_RESET`表中提供。

+   **事务和锁信息**：`INNODB_TRX`包含当前执行的事务信息，`Performance Schema`表中的`data_locks`和`data_lock_waits`表提供有关锁的信息。

+   **模式对象表**：提供有关`InnoDB`模式对象的元数据信息。

+   `FULLTEXT` **索引表**：提供有关`FULLTEXT`索引的元数据信息。

+   **缓冲池表**：提供有关缓冲池中页面的状态信息和元数据。

+   **指标表**：提供性能和资源相关信息。

+   **临时表信息表**：提供有关当前在`InnoDB`实例中活动的所有用户和系统创建的临时表的元数据信息。

+   **检索`InnoDB`表空间元数据**：提供有关`InnoDB`实例中所有类型的表空间的元数据信息。

已添加了一个新视图`INNODB_TABLESPACES_BRIEF`，用于提供名称、路径、标志、空间和空间类型数据。

已添加了一个新表`INNODB_CACHED_INDEXES`，用于提供缓冲池中每个索引的索引页数。

# Memcached 插件

MySQL 8 为您提供了名为`daemon_memcached`的`InnoDB` memcached 插件，可以帮助我们轻松管理数据。它将自动从`InnoDB`表中存储和检索数据，并提供`get`、`set`和`incr`操作，通过跳过 SQL 解析来消除性能开销，从而加快数据操作。`memcached`插件使用集成的`memcached`守护程序，自动从`InnoDB`表中检索和存储数据，使 MySQL 服务器能够快速将数据发送到`键值`存储。

使用`InnoDB memcached`插件的主要好处如下：

+   直接访问`InnoDB`存储引擎，减少解析和规划 SQL 开销

+   `memcached`使用与 MySQL 服务器相同的进程空间，减少了网络开销

+   以`memcached`协议编写或请求的数据会透明地从`InnoDB`表中写入或查询，减少了必须经过 SQL 层开销的情况

+   通过自动在磁盘和内存之间传输，简化应用逻辑

+   MySQL 数据库存储数据，以防止损坏、崩溃或中断

+   在主服务器上使用`daemon_memcached`插件和 MySQL 复制结合，确保高可用性

+   使用`InnoDB`缓冲池缓存重复的数据请求，提供高速处理

+   由于数据存储在`InnoDB`表中，数据一致性会自动执行

`InnoDB memcached`插件支持多个获取操作（在单个`memcached`查询中获取多个键/值对）和范围查询。

# 创建自定义存储引擎

MySQL AB 在 MySQL 5.1 中引入了可插拔存储引擎架构，包括 MySQL 8 在内的所有后续版本都利用了灵活的存储引擎架构。

存储引擎可插拔架构提供了在不重新编译服务器的情况下创建和添加新存储引擎的能力，直接添加到运行中的 MySQL 服务器。这种架构使得开发和部署新的存储引擎到 MySQL 8 变得非常容易。

在开发新的存储引擎时，需要注意为存储引擎工作的所有组件。这些包括安装处理程序、对表的操作（如创建、打开和关闭）、`DML`、索引等。

在本节中，我们将介绍如何可以在高层次基础上开始开发新的存储引擎，参考 MySQL 开发社区提供的文档。创建自定义存储引擎需要具备使用`C`和`CPP`进行开发的工作知识，以及使用`cmake`和`Visual Studio`进行编译。

# 创建存储引擎源文件

实现新存储引擎的最简单方法是通过复制和修改`EXAMPLE`存储引擎开始。文件`ha_example.cc`和`ha_example.h`可以在 MySQL 源分发的`storage/example`目录中找到。

在复制文件时，将名称从`ha_example.cc`和`ha_example.h`更改为适合您的存储引擎的名称，例如`ha_foo.cc`和`ha_foo.h`。

在复制和重命名文件后，必须将所有`EXAMPLE`和`example`的实例替换为您的存储引擎的名称。

# 添加特定于引擎的变量和参数

插件可以实现状态和系统变量，在本节中我们已经介绍了变量和参数的更改，以及适当的值和数据类型。

服务器插件接口使插件能够使用通用插件描述符的`status_vars`和`system_vars`成员公开状态和系统变量。

`status_vars`是通用插件描述符的成员。如果值不为 0，则指向一个`st_mysql_show_var`结构的数组，其中每个结构描述一个状态变量，后跟一个所有成员都设置为 0 的结构。`st_mysql_show_var`结构的定义如下：

```sql
struct st_mysql_show_var {   
  const char *name;   
  char *value;   
  enum enum_mysql_show_type type; 
};
```

插件安装后，插件名称和名称值用下划线连接，以形成`SHOW STATUS`语句显示的名称。

以下列表显示了允许的状态变量类型值以及相应的变量应该是什么：

+   `SHOW_BOOL`：这是一个指向`boolean`变量的指针

+   `SHOW_INT`：这是一个指向`integer`变量的指针

+   `SHOW_LONG`：这是一个指向长整型变量的指针

+   `SHOW_LONGLONG`：这是一个指向`longlong integer`变量的指针

+   `SHOW_CHAR`：这是一个`String`索引

+   `SHOW_CHAR_PTR`：这是一个指向`String`索引的指针

+   `SHOW_ARRAY`：这是一个指向另一个`st_mysql_show_var array`的指针

+   `SHOW_FUNC`：这是一个指向函数的指针

+   `SHOW_DOUBLE`：这是一个指向`double`的指针

所有会话和全局系统变量在使用之前都必须发布到`mysqld`。这是通过构建一个变量的`NULL`终止数组，并在插件公共接口中链接到它来实现的。

所有可变的和插件系统变量都存储在`HASH`结构中。

服务器命令行帮助文本的显示是通过编译所有相关变量的`DYNAMIC_ARRAY`，对其进行排序和迭代来显示每个选项。

在插件安装过程中，服务器处理命令行选项，插件成功加载后立即进行处理，但尚未调用插件初始化函数。

在`runtime`加载的插件不受任何配置选项的影响，必须具有可用的默认值。一旦安装，它们将在`mysqld`初始化时加载，并且可以在命令行或`my.cnf`中设置配置选项。

插件中的`thd`参数应被视为只读。

# 创建 handlerton

handlerton（处理程序单例的简称）定义了存储引擎。它包含指向应用于整个存储引擎的方法的方法指针，而不是在每个表上工作的方法。此类方法的示例包括处理提交和回滚操作的事务方法。

`EXAMPLE`存储引擎的示例如下：

```sql
handlerton example_hton= {
 "EXAMPLE", /* Name of the storage engine */
 SHOW_OPTION_YES, /* It should be displayed in options or not */
 "Example storage engine", /* Description of the storage engine */
 DB_TYPE_EXAMPLE_DB, /* Type of storage engine it should refer to */
 NULL, /* Initialize handlerton */
 0, /* slot  available */
 0, /* define savepoint size. */
 NULL, /* handle close_connection */
 NULL, /* handle savepoint */
 NULL, /* handle rollback to savepoint */
 NULL, /* handle release savepoint */
 NULL, /* handle commit */
 NULL, /* handle rollback */
 NULL, /* handle prepare */
 NULL, /* handle recover */
 NULL, /* handle commit_by_xid */
 NULL, /* handle rollback_by_xid */
 NULL, /* handle create_cursor_read_view */
 NULL, /* handle set_cursor_read_view */
 NULL, /* handle close_cursor_read_view */
 example_create_handler, /* Create a new handler instance */
 NULL, /* handle drop database */
 NULL, /* handle panic call */
 NULL, /* handle release temporary latches */
 NULL, /* Update relevant Statistics */
 NULL, /* Start Consistent Snapshot for reference */
 NULL, /* handle flush logs */
 NULL, /* handle show status */
 NULL, /* handle replication Report Sent to Binlog */
 HTON_CAN_RECREATE
};
```

有 30 个`handlerton`元素，其中只有少数是强制性的。

# 处理处理程序安装

这是创建新处理程序实例所需的存储引擎中的第一个方法调用。

在源文件中定义`handlerton`之前，必须在方法头中定义实例化方法。以下是`CSV`引擎显示实例化方法的示例：

```sql
static handler* tina_create_handler(TABLE *table);
```

如前面的示例所示，该方法接受一个指向表的指针。处理程序负责管理和返回处理程序对象。在方法头定义之后，使用方法指针在`create()` `handlerton`元素中命名方法。这将标识该方法负责在请求时生成新的处理程序实例。

以下示例显示了`MyISAM`存储引擎的实例化方法：

```sql
static handler *myisam_create_handler(TABLE *table)
 {
 return new ha_myisam(table);
 }
```

# 定义文件扩展名

存储引擎必须提供与给定表及其数据和索引相关的存储引擎使用的扩展名列表给 MySQL 服务器。

扩展应以空终止的字符串数组的形式给出，并且在调用[`custom-engine.html#custom-engine-api-reference-bas_ext bas_ext()`]方法时返回相同的内容，如下面的块所示：

```sql
const char **ha_tina::bas_ext() const
{
 return ha_tina_exts;
}
```

通过提供扩展信息，您还可以跳过实现`DROP TABLE`功能，因为 MySQL 服务器将通过关闭表并删除指定扩展名的所有文件来实现相同的功能。

# 创建表

在处理程序实例化之后，应该遵循创建表方法。存储引擎必须实现[`custom-engine.html#custom-engine-api-reference-create create()`]方法，如下面的块所示：

```sql
virtual int create(const char *name, TABLE *form, HA_CREATE_INFO *info)=0;
```

前面显示的方法应该创建所有必要的文件，但不会打开表。MySQL 服务器将单独调用打开表。

`*name`参数用于传递表的名称，`*form`参数用于传递`TABLE`结构。表结构定义了表，并匹配`tablename.frm`的内容。存储引擎不得修改`tablename.frm`文件，否则将导致错误或不可预测的问题。

`*info`参数是包含有关`CREATE TABLE`语句的信息的结构。它用于创建表，结构在`handler.h`文件中定义。以下是参考结构：

```sql
typedef struct st_ha_create_information
{
 CHARSET_INFO *table_charset, *default_table_charset; /* charset in table */
 LEX_STRING connect_string; /* connection string */
 const char *comment,*password; /* storing comments and password values */
 const char *data_file_name, *index_file_name; /* data and index file names */
 const char *alias; /* value pointer for alias */
 ulonglong max_rows,min_rows;
 ulonglong auto_increment_value;
 ulong table_options;
 ulong avg_row_length;
 ulong raid_chunksize;
 ulong used_fields;
 SQL_LIST merge_list;
 enum db_type db_type; /* value for db_type */
 enum row_type row_type; /* value for row_type */
 uint null_bits; /* NULL bits specified at start of record */
 uint options; /* OR of HA_CREATE_ options specification */
 uint raid_type,raid_chunks; /* raid type and chunks info */
 uint merge_insert_method;
 uint extra_size; /* length of extra data segments */
 bool table_existed; /* 1 in create if table existed */
 bool frm_only; /* 1 if no ha_create_table() */
 bool varchar; /* 1 if table has a VARCHAR */
} HA_CREATE_INFO;
```

存储引擎可以忽略`*info`和`*form`的内容，因为只有在存储引擎使用时才真正需要创建和初始化数据文件。

# 打开表

在对任何表执行任何读取或写入操作之前，MySQL 服务器调用[`custom-engine.html#custom-engine-api-reference-open handler::open()`]方法来打开表索引和数据文件：

```sql
int open(const char *name, int mode, int test_if_locked);
```

第一个参数是要打开的表的名称。第二个参数是要执行的文件操作。这些值在`handler.h`中定义：`O_RDONLY - 只读打开`，`O_RDWR - 读/写打开`。

最终选项决定处理程序在打开之前是否应检查表上的锁定。可以选择以下选项：

```sql
#define HA_OPEN_ABORT_IF_LOCKED 0 /* default */
#define HA_OPEN_WAIT_IF_LOCKED 1 /* wait if table is locked */
#define HA_OPEN_IGNORE_IF_LOCKED 2 /* ignore if locked */
#define HA_OPEN_TMP_TABLE 4 /* Table is a temp table */
#define HA_OPEN_DELAY_KEY_WRITE 8 /* Don't update index */
#define HA_OPEN_ABORT_IF_CRASHED 16
#define HA_OPEN_FOR_REPAIR 32 /* open even if crashed with repair */
```

典型的存储引擎将实现某种形式的共享访问控制，以防止在多线程环境中发生文件损坏。例如，查看`sql/example/ha_tina.cc`中的`get_share()`和`free_share()`方法来实现文件锁定。

# 实现基本表扫描

最基本的存储引擎实现了只读级别的表扫描，并且可能用于支持 SQL 查询，以请求从 MySQL 之外填充的日志和其他数据文件中获取信息。

方法的实现是创建高级存储引擎的第一步。以下显示了在`CSV`引擎的九行表扫描期间进行的方法调用：

```sql
ha_tina::store_lock
ha_tina::external_lock
ha_tina::info
ha_tina::rnd_init
ha_tina::extra - ENUM HA_EXTRA_CACHE Cache record in HA_rrnd()
ha_tina::rnd_next
ha_tina::rnd_next
ha_tina::rnd_next
ha_tina::rnd_next
ha_tina::rnd_next
ha_tina::rnd_next
ha_tina::rnd_next
ha_tina::rnd_next
ha_tina::rnd_next
ha_tina::extra - ENUM HA_EXTRA_NO_CACHE End caching of records (def)
ha_tina::external_lock
ha_tina::extra - ENUM HA_EXTRA_RESET Reset database to after open
```

可以实施以下方法来处理特定操作：

+   **实现** `store_lock()`: 此方法可以修改锁级别，忽略或为多个表添加锁

+   **实现** `external_lock()`: 当发出`LOCK TABLES`语句时调用此方法

+   **实现** `rnd_init()`: 此方法用于在表扫描中在表的开始处重置计数器和指针

+   **实现** `info(uinf flag)`: 此方法用于向优化器提供额外的表信息

+   **实现** `extra()`: 此方法用于向存储引擎提供额外的提示信息

+   **实现** `rnd_next()`: 此方法在扫描每一行直到达到`EOF`或满足搜索条件时调用

# 关闭表

当 MySQL 服务器完成与表的所有请求操作后，它将调用`custom-engine.html#custom-engine-api-reference-close close()`方法。它将关闭文件指针并释放所有相关资源。

使用共享访问方法的存储引擎在`CSV`引擎中可见。其他示例引擎必须从共享结构中删除相同的内容，如下所示：

```sql
int ha_tina::close(void)
 {
 DBUG_ENTER("ha_tina::close");
 DBUG_RETURN(free_share(share));
 }
```

存储引擎使用自己的共享管理系统。它们应使用所需的方法，以便从其处理程序中打开的相应表的共享中删除处理程序实例。

如果您的存储引擎编译为共享对象，在加载期间如果出现错误，例如`undefined symbol: _ZTI7handler`，则请确保使用与服务器相同的标志编译和链接您的扩展。此错误的常见原因是 LDFLAGS 缺少*-fno-rtti*选项。

# 高级自定义存储引擎的参考

我们已经详细介绍了前面的各个部分，为自定义存储引擎组件和所需的更改提供了高级信息。要在自定义存储引擎中实现`INSERT`、`UPDATE`、`DELETE`、索引等，需要具备使用`C/CPP`进行开发以及使用`cmake`和`Visual Studio`进行编译的工作知识。有关自定义存储引擎的高级开发，请参阅[`dev.mysql.com/doc/internals/en/custom-engine.html`](https://dev.mysql.com/doc/internals/en/custom-engine.html)中提供的详细信息

# 摘要

到目前为止，您已经了解了 MySQL 8 中可用的不同数据库引擎，以及我们为什么应该关注存储引擎和 MySQL 8 中可用的存储引擎选项。我们已经详细介绍了`InnoDB`存储引擎以及`InnoDB`存储引擎中已经提供的重要功能。现在，您实际上可以根据系统要求创建自定义存储引擎，并将其插入到 MySQL 8 中。选择适合您系统的存储引擎是一个重要方面，我们已经详细介绍了这一点。

在下一章中，您将了解 MySQL 8 中索引的工作原理，与索引相关的新功能，不同类型的索引以及如何在表中使用索引。除此之外，还将提供比较以及深入了解各种索引实现方式。


# 第七章：MySQL 8 中的索引

在上一章中，我们了解了存储引擎。现在我们知道了有哪些类型的存储引擎可用，以及哪些存储引擎适合我们的需求。上一章还详细介绍了`InnoDB`存储引擎，以及其他存储引擎信息。它还描述了如何定义用于使用的自定义存储引擎，并提供了一个实际示例。现在是时候了解 MySQL 8 的另一个重要功能，即索引。我们将涵盖不同类型的索引及其功能，这将鼓励您使用索引，并为您提供如何使用它们的指导。因此，您的索引之旅已经开始！让我们开始吧。

本章将涵盖以下主题：

+   索引概述

+   列级索引

+   B-Tree 索引

+   哈希索引

+   索引扩展

+   使用优化器进行索引

+   不可见和降序索引

# 索引概述

在表上定义索引是改善`SELECT`操作性能的最佳方式。索引就像表行的指针，允许查询根据`WHERE`条件快速指向匹配的行。MySQL 8 允许您在所有数据类型上创建索引。尽管索引在查询中提供了良好的性能，但建议以正确的方式定义它，因为不必要的索引会浪费空间和时间（MySQL 8 需要找到最佳使用的索引）。此外，索引还会增加`INSERT`、`UPDATE`和`DELETE`操作的成本，因为在这些操作期间，MySQL 8 将更新每个索引。

正如我们之前所描述的，索引是一种改善操作速度的数据结构。根据结构，索引分为两种主要形式——聚集索引和非聚集索引：

+   **聚集索引**：聚集索引定义了数据在表中的物理存储顺序。因此，每个表只允许一个聚集索引。当以顺序方式检索数据时，无论是相同顺序还是相反顺序，聚集索引都会大大提高检索速度。当选择一系列项目时，聚集索引也提供更好的性能。主键被定义为聚集索引。

+   **非聚集索引**：非聚集索引不定义数据物理存储的顺序。这意味着非聚集索引存储在一个地方，数据存储在另一个地方。因此，每个表允许有多个非聚集索引。它指的是非主键。

正如我们所知，主键代表从表中获取记录最广泛使用的列或列集。主键与之关联的索引用于快速查询性能。它提供了相对较快的性能，因为主键不允许`NULL`值，因此不需要对`NULL`值进行检查。建议如果您的表没有列或列集来定义为主键，那么为了更好的性能，您可以定义一个自动增量字段作为主键。另一方面，如果您的表包含许多列，并且需要执行带有多列组合的查询，则建议将不经常使用的数据转移到单独的表中。将所有单独的表与主键和外键引用相关联，这将帮助您管理数据，并且查询检索会提供良好的性能。

# MySQL 8 中索引的用途

索引主要用于在不迭代完整表的情况下找到特定值的行。如果未定义索引，则 MySQL 8 将从第一行开始搜索，然后读取整个表，这将导致昂贵的操作。MySQL 8 使用索引进行以下操作：

+   在对索引的最左前缀进行排序或分组时。这意味着如果所有键都为`DESC`子句定义，那么键将按相反顺序考虑，如果所有键后跟`ASC`，则键将按正向顺序考虑。

+   查找与`WHERE`子句匹配的行。

+   对于多列索引，可以使用索引的任何最左前缀来查找行。本章后面将以详细示例介绍此主题。

+   如果 MySQL 需要从多个选项中选择一个索引，则会选择具有最小行集的索引。

+   有时，查询会被优化以获取值而不是引用行。例如，如果查询仅使用包含在索引中的列，MySQL 8 将从索引树中获取所选值：

```sql
 SELECT key_part3 FROM table_name WHERE key_part1=10;
```

+   在执行连接时，如果列声明为相同的类型和大小，MySQL 8 将以更有效的方式使用索引。例如，`VARCHAR(15)`和`CHAR(15)`将被视为相同，但`VARCHAR(10)`和`CHAR(15)`将不被视为相同。

+   对于`MIN()`和`MAX()`函数，如果使用了索引列的一部分，优化器将检查索引列的所有其他部分是否在`WHERE`条件中可用。如果提到了，MySQL 8 将执行`MIN()`和`MAX()`函数的单个查找，并用常量替换它们。例如：

```sql
 SELECT MIN(key_part2), MAX(key_part2) FROM tble_name WHERE 
          key_part1=10;
```

# 与索引相关的 SQL 命令

MySQL 8 提供了两个与索引相关的主要命令。我们将在以下部分讨论这些命令。

# 创建 INDEX 命令

以下命令允许用户向现有表中添加索引。此命令也可与`CREATE TABLE`和`ALTER TABLE`一起使用以创建索引：

```sql
CREATE [UNIQUE|FULLTEXT|SPATIAL] INDEX index_name
 [index_type]
 ON tbl_name (index_col_name,...)
 [index_option]
 [algorithm_option | lock_option] ...
index_col_name:
 col_name [(length)] [ASC | DESC]
index_option:
 KEY_BLOCK_SIZE [=] value
 | index_type
 | WITH PARSER parser_name
 | COMMENT 'string'
 | {VISIBLE | INVISIBLE}
index_type:
 USING {BTREE | HASH}
algorithm_option:
 ALGORITHM [=] {DEFAULT|INPLACE|COPY}
lock_option:
 LOCK [=] {DEFAULT|NONE|SHARED|EXCLUSIVE}
```

使用`col_name(length)`语法，用户可以指定索引前缀长度，只考虑字符串值中指定数量的字符。在定义时，前缀考虑以下几点：

+   对于`CHAR`、`VARCHAR`、`BINARY`和`VARBINARY`列索引，前缀是可选的

+   在`BLOB`和`TEXT`列索引中必须指定前缀

+   MySQL 8 将考虑非二进制字符串类型（`CHAR`、`VARCHAR`、`TEXT`）的字符数和二进制类型（`BINARY`、`VARBINARY`、`BLOB`）的字节数作为前缀

+   空间列不允许前缀

在本章后面的*列索引*部分将详细介绍前缀选项的示例。`UNIQUE`索引是一个约束，表示索引中的所有值都将是唯一的。如果尝试添加已经存在的值，MySQL 8 会显示错误。所有类型的存储引擎都允许在`UNIQUE`索引中存在多个空值。在使用`NULL`值时，确保列值在前缀内是唯一的。如果索引前缀超出其大小，MySQL 8 将按以下方式处理索引：

+   **对于非唯一索引**：如果启用了严格的 SQL 模式，MySQL 8 会抛出错误，如果禁用了严格模式，则索引长度将减少到最大列数据类型大小，并产生警告。

+   **对于唯一索引**：在这种情况下，无论 SQL 模式如何，MySQL 8 都会产生错误，因为这可能会破坏列的唯一性。这意味着您定义了一个长度为 25 的列，并尝试在相同列上定义一个前缀长度为 27 的索引，那么 MySQL 8 会报错。

# 空间索引特性

MySQL 8 遵循以下规则来处理空间索引特性：

+   仅适用于`InnoDB`和`MyISAM`存储引擎；如果尝试用于其他存储引擎，MySQL 8 会报错。

+   不允许对索引列使用`NULL`值。

+   此列不允许使用前缀属性。索引将考虑全宽度。

# 非空间索引特性

MySQL 8 遵循以下规则，用于非空间索引特性：

+   对于 `InnoDB`、`MyISAM` 和 `MEMORY` 存储引擎，允许在索引列中使用 `NULL` 值。

+   在每个空间列的情况下，必须指定列前缀长度，如果它存在于非空间索引中。前缀长度将以字节为单位。

+   除了 `ARCHIVE`，它适用于所有支持空间列的存储引擎。

+   对于此索引，允许使用 `NULL` 值，除非它被定义为 `PRIMARY` 键。

+   对于 `InnoDB` 表，在创建表上的索引后，如果启用了 `innodb_stats_persistent` 设置，则运行 `ANALYZE TABLE` 语句。

+   索引类型将取决于存储引擎；目前使用 B-Tree。

+   只有在使用 `InnoDB` 和 `MyISAM` 表定义时，才允许在 `BLOB` 或 `TEXT` 列上使用非空间索引。

`index_col_name` 属性的默认值是升序的，对于具有此属性的 `HASH` 索引，不允许使用 `ASC` 或 `DESC` 值。MySQL 8 提供以下任何一个值与 `index_option`：

+   `KEY_BLOCK_SIZE [=]` value: 此参数定义了索引键块的大小（以字节为单位）。这是一个可选参数，其值被视为提示。如果需要，MySQL 8 可能会使用不同的大小。如果此参数在单个索引级别上定义，则它会覆盖表级别的 `KEY_BLOCK_SIZE` 值。`InnoDB` 引擎不支持此参数在索引级别上；它只允许在表级别上使用。

+   `index_type`：MySQL 8 允许用户在索引创建时定义索引类型。例如：

```sql
 create table employee (id int(11) not null,name varchar(50));
 CREATE INDEX emp_name_index ON employee (name) USING BTREE;
```

请参考以下表格，查找与存储引擎相关的允许的索引类型。在多种类型定义的情况下，将第一个索引类型视为默认类型。如果此表中未提及任何存储引擎，则表示该引擎不支持该索引类型。

| **存储引擎** | **允许的索引类型** |
| --- | --- |
| `InnoDB` | `BTREE` |
| `MyISAM` | `BTREE` |
| `MEMORY`/`HEAP` | `HASH`, `BTREE` |
| `NDB` | `HASH`, `BTREE` |

参考：[`dev.mysql.com/doc/refman/8.0/en/create-index.html`](https://dev.mysql.com/doc/refman/8.0/en/create-index.html)

如果尝试定义存储引擎不支持的索引类型，则 MySQL 8 将其视为支持的索引类型，而不会影响查询结果。请参考以下表格，了解基于存储类型的索引特性：

| **存储引擎** | **索引类型** | **索引类** | **存储 NULL 值** | **允许多个 NULL 值** | **IS NULL 扫描类型** | **IS NOT NULL 扫描类型** |
| --- | --- | --- | --- | --- | --- | --- |
| `InnoDB` | `BTREE` | Primary key | No | No | N/A | N/A |
| Unique | Yes | Yes | Index | Index |
| Key | Yes | Yes | Index | Index |
| 不适用 | `FULLTEXT` | Yes | Yes | Table | Table |
| 不适用 | SPATIAL | No | No | N/A | N/A |
| `MyISAM` | `BTREE` | Primary key | No | No | N/A | N/A |
| Unique | Yes | Yes | Index | Index |
| Key | Yes | Yes | Index | Index |
| 不适用 | `FULLTEXT` | Yes | Yes | Table | Table |
| 不适用 | SPATIAL | No | No | N/A | N/A |
| `MEMORY` | `HASH` | Primary key | No | No | N/A | N/A |
| Unique | Yes | Yes | Index | Index |
| Key | Yes | Yes | Index | Index |
| `BTREE` | Primary | No | No | N/A | N/A |
| Unique | Yes | Yes | Index | Index |
| Key | Yes | Yes | Index | Index |

参考：[`dev.mysql.com/doc/refman/8.0/en/create-index.html`](https://dev.mysql.com/doc/refman/8.0/en/create-index.html)

+   `WITH PARSER parser_name`：此选项仅适用于由 `InnoDB` 和 `MyISAM` 存储引擎支持的 `FULLTEXT` 索引。如果 `FULLTEXT` 索引和搜索操作需要特殊处理，则 MySQL 8 将使用索引的解析器插件。

+   `COMMENT 'string'`：此属性是可选的，允许在注释中使用最多 1024 个字符。此选项还支持`MERGE_THRESHOLD`参数，其默认值为 50。考虑以下命令来定义`MERGE_THRESHOLD`：

```sql
 CREATE INDEX name_index ON employee(name) COMMENT 
          'MERGE_THRESHOLD=40'; 
```

如果索引的页满百分比低于`MERGE_THRESHOLD`值，那么`InnoDB`存储引擎将会将索引页与相邻的索引页合并。

+   `VISIBLE`，`INVISIBLE`：此参数定义了索引的可见性。默认情况下，所有索引都是可见的。优化器在优化过程中不会使用不可见的索引。

当您尝试使用表进行读取或写入，并同时修改其索引时，`ALGORITHM`和`LOCK`属性将产生影响。

# 删除索引命令

以下命令从表中删除索引。我们也可以将此语句映射到`ALTER TABLE`以从表中删除索引：

```sql
DROP INDEX index_name ON tbl_name
 [algorithm_option | lock_option]...
algorithm_option:
 ALGORITHM [=] {DEFAULT|INPLACE|COPY}
lock_option:
 LOCK [=] {DEFAULT|NONE|SHARED|EXCLUSIVE}
```

在此命令中，只有两个选项可用：算法和锁。这两个选项在索引的并发访问和工作情况下非常有用，类似于`CREATE INDEX`命令。例如，要删除员工表的索引，请执行以下命令：

```sql
DROP INDEX name_index ON employee;
```

# 空间索引的创建和优化

MySQL 8 允许您在`InnoDB`和`MyISAM`存储引擎上使用与前述主题中提到的相同语法创建空间索引。标准命令中唯一的变化是在创建索引时使用关键字**spatial**。在定义空间索引时，请确保列声明为`NOT NULL`。以下代码演示了在表上创建空间索引的方法：

```sql
CREATE TABLE geom_data (data GEOMETRY NOT NULL, SPATIAL INDEX(data));
```

默认情况下，空间索引会创建一个 R-Tree 索引。从 MySQL 8.0.3 开始，优化器会检查索引列的**空间参考标识符**（**SRID**）属性，以找到用于比较和执行计算的**空间参考系统**（**SRS**）。对于比较，空间索引中的每个列必须受到 SRID 的限制。这意味着每个列定义必须包含一个 SRID 属性，并且所有列值必须具有相同的 SRID。基于 SRID，空间索引执行以下两个操作：

+   如果列被限制为**笛卡尔 SRID**，那么它会启用笛卡尔边界框计算

+   如果列被限制为**地理 SRID**，那么它会启用地理边界框计算

如上所述，MySQL 8 将忽略没有 SRID 属性的列上的`SPATIAL INDEX`，但 MySQL 仍会管理这些索引，如下所示：

+   这些类型的索引在表被使用`INSERT`，`UPDATE`或`DELETE`命令修改时会被更新。

+   这些索引在转储备份中被考虑，并且可以通过向后兼容性进行恢复。如前所述，没有受到 SRID 限制列的空间索引不会被优化器使用，因此在这种情况下，所有这些列必须被修改。要修改它们，请执行以下步骤：

1.  使用以下命令检查具有相同`ST_SRID`的列的所有值：

```sql
SELECT DISTINCT ST_SRID(column_name) FROM table_name;
```

如果查询返回多行，则表示该列包含混合的 SRID。如果是这样，请更改列的内容为相同的 SRID 值。

1.  为列定义一个显式的 SRID。

1.  重新创建`SPATIAL INDEX`。

# InnoDB 和 MyISAM 索引统计收集

MySQL 8 将根据值组对表统计信息进行考虑，这只是具有相同前缀值的一组行。存储引擎收集与表相关的统计信息，这些信息由优化器使用。从优化的角度来看，平均值组大小是一个重要的统计数据。如果组的平均值大小增加，那么索引就没有意义。因此，最好为每个索引定位少量行。这可以通过表基数来实现，即值组的数量。对于`InnoDB`和`MyISAM`表，MySQL 8 通过`myisam_stats_method`和`innodb_stats_method`系统变量提供了对统计信息的控制。以下是这些变量的可能值：

+   `nulls_ignored`：表示`NULL`值被忽略

+   `nulls_equal`：表示所有`NULL`值相同

+   `nulls_unequal`：表示所有`NULL`值不相同

`innodb_stats_method`系统变量具有全局值，而`myisam_stats_method`系统变量具有全局值和会话值。当我们设置变量的全局值时，它将影响相应存储引擎的表的统计信息收集。在会话值统计的情况下，仅对当前客户端连接可用。这意味着您必须为其他客户端重新生成表的统计信息，而不影响其他客户端，并且需要在会话值中设置它。要重新生成`MyISAM`统计信息，请使用以下方法之一：

+   执行`myisamchk --stats_method=method_name --analyze`命令

+   更改表以使其统计信息过时，然后设置`myisam_stats_method`并发出`ANALYZE TABLE`语句

在使用这两个变量之前，必须考虑一些要点：

+   这些变量仅适用于`InnoDB`和`MyISAM`表。对于其他存储引擎，只有一种方法可用于收集表统计信息，它非常接近`nulls_equal`方法。

+   MySQL 8 提供了一种明确为表生成统计信息的方法，但情况并非总是如此。有时，如果需要，MySQL 8 也会自动生成统计信息。例如，在任何操作的情况下，如果某些 SQL 语句修改了表数据，那么 MySQL 8 将自动收集统计信息。考虑批量插入或删除操作。

+   我们无法确定用于生成表统计信息的方法。

# 列级索引

MySQL 8 允许您在单个列上创建索引，也可以在多个列上创建索引。每个表的最大索引数和最大索引长度取决于存储引擎。大多数存储引擎允许每个表至少有 16 个索引和至少 256 个字节的总索引长度，但大多数存储引擎允许更高的限制。

# 列索引

这是定义只涉及单个列的索引的最常见方法。MySQL 8 将列值的副本存储在数据结构中，以便可以快速访问行。MySQL 8 使用**B-Tree**数据结构来快速访问值。 B-Tree 执行将基于在`where`条件中定义的操作符，例如`=`,`<`,`>`,`BETWEEN`,`IN`等。您可以在下一个主题中了解有关 B-Tree 数据结构及其执行的详细信息。我们将在接下来的部分讨论列索引的特点。

# 索引前缀

此选项允许用户在字符串的情况下指定用于索引的字符数。MySQL 8 在索引创建中提供了`column_name(N)`选项，用于指定字符数。索引优先考虑只指定的字符，这将使索引文件更小。因此，在`BLOB`和`TEXT`列的情况下，您必须为了更好的性能指定前缀长度。考虑以下示例，在`BLOB`类型上创建带有前缀长度的索引：

```sql
CREATE TABLE person (personal_data TEXT, INDEX(personal_data (8)));
```

此命令通过考虑前八个字符在`personal_data`列上创建索引。前缀长度根据存储引擎而变化。`InnoDB`存储引擎允许对`REDUNDANT`或`COMPACT`行格式最多有 767 字节的前缀长度，而对于`DYNAMIC`或`COMPRESSED`行格式，它允许最多 3072 字节。在`MyISAM`存储引擎的情况下，前缀最多可以定义为 1000 字节。

前缀长度将以字节为单位测量二进制字符串类型，例如`BINARY`，`VARBINARY`和`BLOB`，而对于非二进制字符串类型，它将被视为字符数。

# FULLTEXT 索引

正如其名称所示，`FULLTEXT`索引仅允许`CHAR`，`VARCHAR`和`TEXT`列。此索引受`InnoDB`和`MyISAM`存储引擎支持。在这种类型中，索引将在整个列上进行，而不是在前缀长度上。MySQL 8 在查询执行的优化阶段评估全文表达式。在进行执行计划的过程中，优化会在进行估计之前评估全文表达式。因此，全文查询的`EXPLAIN`查询比非全文查询慢。全文查询在以下情况下很有用：

+   当`FULLTEXT`查询返回文档 ID 或文档 ID 和搜索排名时

+   当`FULLTEXT`查询按降序对匹配行进行排序并使用`LIMIT`子句获取*N*行数时，只应用单个降序`ORDER BY`子句，并且不要在其中使用`WHERE`子句进行优化

+   当`FULLTEXT`查询从行中获取`COUNT(*)`值而没有任何额外的`WHERE`子句时，应用`WHERE`子句为`WHERE MATCH(text)` `AGAINST ('other_text')`，而不使用`>` 0 比较运算符

# 空间索引

MySQL 8 允许您在空间数据类型上创建索引。`InnoDB`和`MyISAM`存储引擎支持空间数据的 R-Tree，而其他存储引擎使用 B-Tree。自 MySQL 5.7 以来，空间索引在`MyISAM`和`InnoDB`数据库引擎中得到支持。

# 内存存储引擎中的索引

内存存储引擎支持`HASH`索引和 B-Tree 索引，但默认情况下，`MEMORY`存储引擎设置为`HASH`索引。

# 多列索引

MySQL 8 允许您在单个索引创建中使用多个列，这也被称为**复合索引**。它允许在复合索引中最多使用 16 列。在使用复合索引时，请确保遵循在索引创建期间提到的相同列的顺序。多列索引包含通过连接索引列的值生成的值。请考虑以下示例以了解多列索引：

```sql
CREATE TABLE Employee (
id INT NOT NULL,
lastname varchar(50) not null,
firstname varchar(50) not null,
PRIMARY KEY (id),
INDEX name (lastname, firstname)
);
```

如上所述，我们使用两列`lastname`和`firstname`定义了复合索引。以下查询使用了名称索引：

```sql
SELECT * FROM Employee WHERE lastname='Shah';
SELECT * FROM Employee WHERE lastname ='Shah' AND firstname ='Mona';
SELECT * FROM Employee WHERE lastname ='Shah' AND (firstname ='Michael' OR firstname ='Mona');
SELECT * FROM Employee WHERE lastname ='Shah' AND firstname >='M' AND firstname < 'N';
```

在所有前述的查询中，我们可以看到列的顺序在`WHERE`条件中保持不变，类似于索引声明的顺序。当我们仅在`WHERE`子句中定义`lastname`列时，索引也可以起作用，因为它是索引中定义的最左边的列。现在，有一些查询中复合索引将不起作用：

```sql
SELECT * FROM Employee WHERE firstname='Mona';
SELECT * FROM Employee WHERE lastname='Shah' OR firstname='Mona';
```

请记住，在多列索引的情况下，优化器可以使用索引的任何最左前缀来搜索行。例如，如果索引是按顺序定义的三列`column1`，`column2`和`column3`，那么您可以在`WHERE`子句中定义它，使用索引功能(`column1`, `column2`, `column3`), (`column1`), (`column1`, `column2`)。

# B-Tree 索引

B-Tree 索引的主要目的是减少物理读取操作的次数。B-Tree 索引是通过对搜索键进行排序并维护分层搜索数据结构来创建的，这有助于搜索正确的数据条目页。默认情况下，`InnoDB`和`MyISAM`存储引擎使用 B-Tree 索引。B-Tree 设法使所有叶节点到根节点的距离相等。这个索引加快了数据访问，因为不需要扫描整个数据来获取所需的输出。相反，它从根节点开始。根节点保存子节点的指针，存储引擎遵循这些指针以找到下一个路径。它通过考虑节点页中的值来找到正确的路径。节点页定义了子节点中值的上限和下限。在搜索过程结束时，存储引擎要么成功到达叶页，要么得出结论，即没有与搜索相关联的值。请记住，叶页指向索引数据，而不是其他页面。现在，让我们参考一个图表，以更详细地了解 B-Tree 索引：

以下是 B-Tree 无法使用的查询：

现在，让我们通过考虑以下表格来了解 B-Tree 索引在选择查询中的工作原理：

```sql
CREATE TABLE Employee (
 lastname varchar(50) not null,
 firstname varchar(50) not null,
 dob date not null,
 gender char(1) not null,
 key(lastname, firstname, dob)
 );
```

根据表定义，索引将包含三列`firstname`、`lastname`和`dob`的组合值。它将根据先前给定的顺序对值进行排序；这意味着如果某些员工具有相似的名称，则它们将按其出生日期进行排序。考虑以下类型的查询，这些查询将受益于 B-Tree 索引：

+   **匹配完整值**：查找名为 Mohan Patel 且出生于 1981 年 11 月 28 日的员工。

+   **精确匹配一部分并与另一列的范围匹配**：查找姓氏为 Patel 且名字以 A 开头的员工。

+   正如之前讨论的，当查询针对索引列执行时，MySQL 8 查询引擎从根节点开始，并通过中间节点到达叶节点。让我们举个例子，假设您想在索引列中找到值 89。在这种情况下，查询引擎会引用根节点以获取中间页的引用。因此，它将指向**1-100**。然后，它确定下一个中间级别，并指向值**51-100**。然后查询引擎转到第三页，即下一个中间级别，**76-100**。从那里，它将找到值 89 的叶节点。叶节点包含整行或指向该行的指针，具体取决于索引是聚集还是非聚集。

+   **与列前缀匹配**：查找姓氏以 M 开头的员工。它只使用索引中的第一列。

+   哈希索引

**匹配值范围**：查找姓氏为 Patel 和 Gupta 的员工。

+   **在范围条件之后不要使用任何条件**：例如，您已经放置了`WHERE`条件`lastname='Patel'`和`firstname`类似`‘A%'`和`dob=' 28/11/1981'`。在这里，只考虑前两列用于索引，因为`LIKE`是一个范围条件。

+   **不要跳过索引中定义的任何列**：这意味着您不允许使用`lastname`和`dob`来查找在`WHERE`条件中缺少`firstname`的员工。

+   查找不是从索引列的最左侧开始的：例如，如果您查找名为`Mohan`且`dob`在特定日期的员工，则索引将不起作用。在此查询中，定义的列不是索引中最左侧的列。同样，如果您查找姓氏以某些内容结尾的员工，则索引也不起作用。

# **匹配最左侧前缀**：查找所有有姓氏的员工。这些只使用索引中的第一列。

通过完整的树遍历多个级别来从大型数据库中找到单个值是非常困难的。为了克服这个问题，MySQL 提供了另一种索引类型，称为**哈希索引**。这个索引创建了一个哈希表，而不是 B-Tree 索引所具有的结构非常扁平。哈希主要使用哈希函数来生成数据的地址。与哈希相关的两个重要术语是：

+   **哈希函数**：映射函数，用于将搜索键与存储实际记录的地址进行映射。

+   **Bucket**：桶是哈希索引存储数据的存储单元。一个桶表示一个完整的磁盘块，可以存储一个或多个记录。

除了哈希机制之外，哈希索引还具有一些特殊特性，如下所述：

+   整个键用于搜索行。而在 B-Tree 的情况下，只使用键的最左前缀来查找行。

+   优化器不会使用哈希索引来加速`ORDER BY`操作。换句话说，这个索引永远不会用于查找下一个条目。

+   哈希索引用于使用`=`或`<=>`运算符进行相等比较。它永远不会使用返回一系列值的比较运算符。例如，`<`（小于）运算符。

+   范围优化器实际上无法估计两个值之间有多少行可用。而且，如果我们使用哈希索引的`MEMORY`表而不是`InnoDB`或`MyISAM`，那么它也可能影响查询。

# 索引扩展

索引扩展是 MySQL 8 通过附加主键扩展次要索引的功能。如果需要，`InnoDB`引擎会自动扩展次要索引。为了控制索引扩展的行为，MySQL 8 在`optimizer_switch`系统变量中定义了一个`use_index_extensions`标志。默认情况下，此选项已启用，但用户可以使用以下命令在运行时更改它：

```sql
SET optimizer_switch = 'use_index_extensions=off';
```

让我们看一个例子，以深入了解索引扩展。让我们创建一个表，并插入以下值：

```sql
CREATE TABLE table1 (
 c1 INT NOT NULL DEFAULT 0,
 c2 INT NOT NULL DEFAULT 0,
 d1 DATE DEFAULT NULL,
 PRIMARY KEY (c1, c2),
 INDEX key1 (d1)
) ENGINE = InnoDB;

--Insert values into table
INSERT INTO table1 VALUES
(1, 1, '1990-01-01'), (1, 2, '1991-01-01'),
(1, 3, '1992-01-01'), (1, 4, '1993-01-01'),
(1, 5, '1994-01-01'), (2, 1, '1990-01-01'),
(2, 2, '1991-01-01'), (2, 3, '1992-01-01'),
(2, 4, '1993-01-01'), (2, 5, '1994-01-01'),
(3, 1, '1990-01-01'), (3, 2, '1991-01-01'),
(3, 3, '1992-01-01'), (3, 4, '1993-01-01'),
(3, 5, '1994-01-01'), (4, 1, '1990-01-01'),
(4, 2, '1991-01-01'), (4, 3, '1992-01-01'),
(4, 4, '1993-01-01'), (4, 5, '1994-01-01'),
(5, 1, '1990-01-01'), (5, 2, '1991-01-01'),
(5, 3, '1992-01-01'), (5, 4, '1993-01-01'),
(5, 5, '1994-01-01');
```

这个表在列`c1`、`c2`上有一个主键，以及在列`d1`上有一个次要索引`key_d1`。现在，为了理解扩展效果，首先关闭它，然后执行以下带有解释命令的选择查询：

```sql
--Index extension is set as off
SET optimizer_switch = 'use_index_extensions=off';

--Execute select query with explain
EXPLAIN SELECT COUNT(*) FROM table1 WHERE c1 = 3 AND d1 = '1992-01-01';

--Output of explain query
*************************** 1\. row ***************************
 id: 1
 select_type: SIMPLE
 table: table1
 type: ref
possible_keys: PRIMARY,key1
 key: PRIMARY
 key_len: 4
 ref: const
 rows: 5
 Extra: Using where
```

同样，我们现在将打开扩展并再次执行解释计划查询以检查效果，使用以下代码：

```sql
--Index extension is set as on
SET optimizer_switch = 'use_index_extensions=on';

--Execute select query with explain
EXPLAIN SELECT COUNT(*) FROM table1 WHERE c1 = 3 AND d1 = '1992-01-01';

--Output of explain query
*************************** 1\. row ***************************
 id: 1
 select_type: SIMPLE
 table: table1
 type: ref
possible_keys: PRIMARY,key1
 key: key1
 key_len: 8
 ref: const,const
 rows: 1
 Extra: Using index
```

现在，我们将检查这两种方法之间的区别：

+   `key_len`值从 4 个字节变为 8 个字节，这表明键查找使用了列 d1 和 c1，而不仅仅是 d1。

+   `ref`值从`(const)`变为`(const, const)`，这表明键查找使用了两个键部分而不是一个。

+   `rows`计数从 5 变为 1，这表明`InnoDB`需要比第一种方法更少的行来生成结果。

+   `Extra`值从**Using where**变为**Using index**。这表明行可以通过仅使用索引来读取，而不需要查询数据行中的任何其他列。

# 使用索引的优化器

MySQL 8 允许您在生成列上创建索引。生成列是其值从列定义中包含的表达式计算出来的列。考虑以下示例，我们定义了一个生成列`c2`，并在该列上创建了一个索引：

```sql
CREATE TABLE t1 (c1 INT, c2 INT AS (c1 + 1) STORED, INDEX (c2));
```

根据表的先前定义，优化器将在执行计划中考虑生成列的索引。此外，如果我们在查询中使用`WHERE`、`GROUP BY`或`ORDER BY`子句中指定相同的表达式，那么优化器将使用生成列的索引。例如，如果我们执行以下查询，则优化器将使用生成列上定义的索引：

```sql
SELECT * FROM t1 WHERE c1 + 1 > 100;
```

在这里，优化器将识别表达式与列`c2`的定义相同。我们可以使用`EXPLAIN`命令来检查，如下所示：

```sql
mysql> explain SELECT * FROM t1 WHERE c1 + 1 > 100;
*************************** 1\. row ***************************
 id: 1
 select_type: SIMPLE
 table: t1
 partitions: NULL
 type: range
 possible_keys: c2
 key: c2
 key_len: 5
 ref: NULL
 rows: 1
 filtered: 100.00
 Extra: Using index condition
```

生成列索引有一些限制：

+   查询表达式必须与生成的列定义完全匹配。例如，如果我们在列定义中将表达式定义为`c1+1`，那么在查询中使用相同的表达式，而不是应用`1+c1`。

+   在生成列定义中使用 JSON 字符串时，使用`JSON_UNQUOTE()`从值中删除额外的引号。例如，不要使用以下列定义：

```sql
 name TEXTAS(JSON_EXTRACT(emp,'$.name'))STORED
```

+   我们将使用以下代码代替前面的代码：

```sql
 name TEXTAS(JSON_UNQUOTE(JSON_EXTRACT(emp,'$.name')))STORED
```

+   优化适用于这些运算符：`=`, `<`, `<=`, `>`, `>=`, `BETWEEN`和`IN()`。

+   在生成列表达式中不要仅使用其他列的引用。也就是说，不要使用以下代码：

```sql
 c2 INT AS (c1) STORED in column definition.
```

+   如果优化器尝试使用错误的索引，请使用索引提示，这将禁用它并强制优化器使用不同的选择

# 不可见和降序索引

**不可见索引**是一个特殊功能，它将索引标记为优化器不可用。MySQL 8 将维护不可见索引，并在数据修改时保持其最新状态。这将适用于主键以外的索引。我们知道，默认情况下索引是可见的；我们必须在创建时或使用`alter`命令时显式地将它们设置为不可见。MySQL 8 提供了`VISIBLE`和`INVISIBLE`关键字来维护索引的可见性。降序索引是按降序存储键值的方法。降序索引更有效，因为它可以按正向顺序扫描。让我们通过示例详细了解这些索引。

# 不可见索引

如前所述，优化器不使用不可见索引。那么这个索引有什么用呢？这个问题会出现在我们的脑海中，对吧？我们将向您解释一些不可见索引的用例：

+   当定义了许多索引，但不确定哪个索引未被使用时。在这种情况下，您可以使一个索引不可见并检查性能影响。如果有影响，那么您可以立即使该索引可见。

+   只有一个查询使用索引的特殊情况。在这种情况下，不可见索引是一个很好的解决方案。

在以下示例中，我们将使用`CREATE TABLE`、`CREATE INDEX`或`ALTER TABLE`命令创建一个不可见索引：

```sql
CREATE TABLE `employee` (
 `id` int(11) NOT NULL AUTO_INCREMENT,
 `department_id` int(11),
 `salary` int(11),
 PRIMARY KEY (`id`)
 ) ENGINE=InnoDB;

CREATE INDEX idx1 ON employee (department_id) INVISIBLE;
ALTER TABLE employee ADD INDEX idx2 (salary) INVISIBLE;
```

要更改索引的可见性，请使用以下命令：

```sql
 ALTER TABLE employee ALTER INDEX idx1 VISIBLE;
 ALTER TABLE employee ALTER INDEX idx1 INVISIBLE;
```

要获取有关索引的信息，请以以下方式执行`INFORMATION_SCHEMA.STATISTICStable`或`SHOW INDEX`命令：

```sql
mysql>SELECT * FROM information_schema.statistics WHERE is_visible='NO';
*************************** 1\. row ***************************
TABLE_CATALOG: def
TABLE_SCHEMA: db1
TABLE_NAME: employee
NON_UNIQUE: 1
INDEX_SCHEMA: db1
INDEX_NAME: idx1
SEQ_IN_INDEX: 1 
COLUMN_NAME: department_id
COLLATION: A 
CARDINALITY: 0 
SUB_PART: NULL 
PACKED: NULL 
NULLABLE: YES
INDEX_TYPE: BTREE 
COMMENT: 
INDEX_COMMENT: 
IS_VISIBLE: NO

mysql>SELECT INDEX_NAME, IS_VISIBLE FROM INFORMATION_SCHEMA.STATISTICS
 -> WHERE TABLE_SCHEMA = 'db1' AND TABLE_NAME = 'employee';
+------------+------------+
| INDEX_NAME | IS_VISIBLE |
+------------+------------+
| idx1 | NO |
| idx2 | NO |
| PRIMARY | YES |
+------------+------------+

mysql> SHOW INDEXES FROM employee;
*************************** 1\. row ***************************
Table:employee
Non_unique:1
Key_name:idx1
Seq_in_index:1
Column_name: department_id
Collation:A
Cardinality:0
Sub_part: NULL
Packed: NULL
Null:YES
Index_type: BTREE
Comment:
Index_comment:
Visible: NO
```

MySQL 8 在`optimizer_switch`系统变量中提供了一个`use_invisible_indexes`标志，用于控制查询优化器使用的不可见索引。如果此标志打开，则优化器在执行计划构建中使用不可见索引，而如果标志关闭，则优化器将忽略不可见索引。MySQL 8 提供了一个隐式主键的功能，如果您在`NOT NULL`列上定义了一个`UNIQUE`索引。一旦在此字段上定义了索引，MySQL 8 将不允许您将其设置为不可见。为了理解这种情况，让我们以以下表为例。让我们尝试执行以下命令，使`idx1`索引不可见：

```sql
CREATE TABLE table2 (
 field1 INT NOT NULL,
 field2 INT NOT NULL,
 UNIQUE idx1 (field1)
) ENGINE = InnoDB;
```

现在，服务器将会给出一个错误，如下所示的命令：

```sql
mysql> ALTER TABLE table2 ALTER INDEX idx1 INVISIBLE;
ERROR 3522 (HY000): A primary key index cannot be invisible
```

现在让我们使用以下命令将主键添加到表中：

```sql
ALTER TABLE table2 ADD PRIMARY KEY (field2);
```

现在，我们将尝试使`idex1`不可见。这次，服务器允许了，如下所示的命令：

```sql
mysql> ALTER TABLE table2 ALTER INDEX idx1 INVISIBLE;
Query OK, 0 rows affected (0.06 sec)
Records: 0 Duplicates: 0 Warnings: 0
```

# 降序索引

降序索引是按降序顺序存储键值的索引。这个索引按正向顺序扫描，与其他索引相比性能更好。降序索引允许用户定义组合升序和降序顺序的多列索引。实际知识总是比理论知识更容易理解，对吧？所以，让我们看一些例子，以深入了解降序索引。首先，创建一个具有以下定义的表：

```sql
CREATE TABLE t1 (
 a INT, b INT,
 INDEX idx1 (a ASC, b ASC),
 INDEX idx2 (a ASC, b DESC),
 INDEX idx3 (a DESC, b ASC),
 INDEX idx4 (a DESC, b DESC)
);
```

根据表定义，MySQL 8 将创建四个不同的索引，因此优化器对每个`ORDER BY`子句执行前向索引扫描。考虑以下不同版本的`ORDER BY`子句：

```sql
ORDER BY a ASC, b ASC -- optimizer can use idx1
ORDER BY a DESC, b DESC -- optimizer can use idx4
ORDER BY a ASC, b DESC -- optimizer can use idx2
ORDER BY a DESC, b ASC -- optimizer can use idx3
```

现在，让我们看一下相同表定义的第二种情况，它将描述与 MySQL 5.7.14 版本相比，降序索引对性能的影响。考虑以下选择查询以测量性能：

```sql
Query 1: SELECT * FROM t1 ORDER BY a DESC;
Query 2: SELECT * FROM t1 ORDER BY a ASC;
Query 3: SELECT * FROM t1 ORDER BY a DESC, b ASC;
Query 4: SELECT * FROM t1 ORDER BY a ASC, b DESC;
Query 5: SELECT * FROM t1 ORDER BY a DESC, b DESC;
Query 6: SELECT * FROM t1 ORDER BY a ASC, b ASC;
```

以下统计图是由 MySQL 8 提供的，针对先前提到的查询，有 1000 万行数据：

![](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mysql8-adm-gd/img/436dd2cc-a878-4a84-88b5-fe96a60311e9.jpg)

参考：[`mysqlserverteam.com/mysql-8-0-labs-descending-indexes-in-mysql/`](https://mysqlserverteam.com/mysql-8-0-labs-descending-indexes-in-mysql/)

在使用降序索引时，有一些重要的要点需要记住，如下所示：

+   所有升序索引支持的数据类型也支持降序索引。

+   降序索引支持`BTREE`，但不支持`HASH`、`FULLTEXT`和`SPATIAL`索引。如果您尝试为`HASH`、`FULLTEXT`和`SPATIAL`索引显式使用`ASC`和`DESC`关键字，那么 MySQL 8 将生成错误。

+   降序索引仅支持`InnoDB`存储引擎，但`InnoDB` SQL 解析器不使用降序索引。如果主键包括降序索引，则不支持对辅助索引的更改缓冲。

+   `DISTINCT`可以使用任何索引，包括降序键，但对于`MIN()`/`MAX()`，不使用降序键部分。

+   非生成和生成列都允许使用降序索引。

# 总结

当你了解它是如何工作的时候，一切都变得非常有趣，对吧？我们希望您在本章中对索引有相同的看法。我们已经涵盖了非常有用的信息，这将帮助您在正确的列上定义索引以获得更好的性能。除此之外，我们还描述了各种类型的索引及其存储结构。

在下一章中，我们将为您提供有关复制的信息。我们将详细解释复制的配置和实现。


# 第八章：MySQL 8 中的复制

在上一章中，我们深入探讨了 MySQL 8 索引。索引是任何数据库管理系统的重要实体。它们通过限制要访问的记录数量来提高 SQL 查询性能。致力于性能改进的数据库管理员必须了解这一重要技术。本章详细解释了索引的类型及其优势。本章还解释了 MySQL 8 中索引的工作原理。这将是一个非常信息丰富的章节！

沿着同样的线路继续前进，在本章中，我们将讨论数据库复制。我们已经对数据库复制有多少了解并不重要。本章涵盖了有关数据库复制的深入细节。如果您已经了解数据库复制，本章将为您增加更多知识。如果您第一次听说它，您将在本章中找到使其正常工作所需的每一个细节。那么，我们准备好开始了吗？以下是本章将涵盖的主题列表：

+   复制概述

+   配置复制

+   实施复制

+   组复制与集群

+   复制解决方案

# 复制概述

在本节中，我们将介绍数据库复制的基础知识。我们将了解复制是什么，它提供的优势以及复制可能有益的场景。

# 什么是 MySQL 复制？

假设您正在阅读本文有两个原因。您熟悉 MySQL 复制并愿意获取更多知识，也许您不熟悉 MySQL 复制并希望学习。

MySQL 复制对于服务许多不同的目的都是有用的。通常，当人们开始有更多的查询超过单个数据库服务器可以处理时，他们开始考虑 MySQL 复制。基于此，你对 MySQL 复制有什么猜测吗？复制是一种技术，可以设置多个数据库来为单个或多个客户端应用程序提供服务。客户端可以是最终用户或发送来自不同设备（如计算机、手机、平板电脑等）的读取数据或写入数据的任何查询请求的人。这些数据库是相同数据库的副本。这意味着参与数据库复制的所有数据库彼此完全相同。复制通过频繁地将数据从一个数据库复制到所有其他副本数据库来工作。这些数据库可以位于同一数据库服务器上、不同的数据库服务器上或完全不同的机器上。

如前所述，数据库复制有各种目的。这取决于为什么设置 MySQL 数据库复制。MySQL 复制是为了扩展数据库或由数据库支持的应用程序。它还用于维护数据库备份和报告目的。我们稍后将在本章中详细讨论这些问题。

MySQL 复制主要用于扩展读取。在任何 Web 应用程序中，读取操作的数量相对于写入数据库操作要高得多。大多数常见的 Web 应用程序都是读取密集型的。考虑一个社交网络网站的例子。如果我们导航到用户个人资料页面，我们会看到很多信息，如用户的个人信息、人口统计信息、社交关系、一些评分等等。如果仔细观察，我们会发现在数据库上执行的`SELECT`查询的数量要比`INSERT`、`UPDATE`或`DELETE`查询要高得多。通过 MySQL 数据库复制，我们可以将读取操作定向到特定的数据库上，以便实现更高的性能。

MySQL 复制看起来很简单，可以在几个小时内设置好，但很容易变得复杂。在新数据库上设置非常容易。相反，在生产数据库上设置它非常复杂。我们不应该将 MySQL 复制与分布式数据库系统混淆。在分布式数据库系统中，数据库保存不同的数据集。数据库操作根据一些关键信息路由到特定的数据库。

在传统的 MySQL 复制中，一个数据库充当主数据库，其余数据库充当从数据库。并不总是必须只有一个主数据库。我们可以在复制中有多个主数据库。这种技术称为多主复制。从服务器从主数据库复制数据。在传统的 MySQL 复制中，复制数据的过程是异步的。这意味着从数据库服务器与主数据库服务器并非永久连接。MySQL 支持不同级别的复制。我们可以将所有主数据库、选定的数据库或选定的主数据库中的表复制到从数据库中。

MySQL 8 提供了不同的数据库复制方法。MySQL 8 有一个二进制日志文件。文件的内容是描述数据库更改的事件。事件可以是“基于语句”的或“基于行”的类型。更改包括数据定义更改和数据操作更改，或者可能修改数据库的语句，如`DELETE`语句。二进制日志还包含每个 SQL 语句更新数据库所花费的时间的信息。传统的 MySQL 数据库复制方法基于主数据库服务器上的二进制日志文件同步数据库到从服务器。从服务器根据文件中日志记录的位置复制或复制主数据库服务器的二进制日志文件的内容。

MySQL 8 还支持基于二进制日志文件的数据库复制方法以及新的方法。在 MySQL 8 数据库服务器上提交的每个事务都被视为唯一的。每个在主数据库服务器上提交的事务都与唯一的全局事务标识符（GTID）相关联。正如其名称所示，全局标识符不仅仅是在创建它的主数据库服务器上唯一的，而且在参与 MySQL 8 复制的所有数据库中都是唯一的。因此，每个提交的事务和全局事务标识符之间存在一对一的映射。MySQL 复制的新方法基于 GTID。它极大地简化了复制过程，因为它不依赖于二进制日志文件及其位置的事件。GTID 表示为一对冒号（“：”）分隔的坐标，如下所示：

```sql
GTID = source_id:transaction_id
```

`source_id`是源自 GTID 的数据库服务器的标识符。通常，数据库服务器的`server_uuid`用作`source_id`。 `transaction_id`是事务在数据库服务器上提交的顺序号。例如，以下示例显示了第一个提交事务的 GTID：

```sql
1A22AF74-17AC-E111-393E-80C49AB653A2:1
```

提交的事务的序列号从`1`开始。它永远不可能是`0`。

基于 GTID 的 MySQL 复制方法是事务性的，这就是为什么它比基于二进制日志文件的复制方法更可靠。只要在主数据库服务器上提交的所有事务也在所有从数据库服务器上应用，GTID 就可以保证复制的准确性和一致性。

如前所述，MySQL 数据库复制通常是异步的。但是，MySQL 8 支持不同类型的复制同步。同步的常规方法是异步的。这意味着一个服务器充当主数据库服务器。它将所有事件写入二进制日志文件。其他数据库服务器充当从服务器。从服务器从主数据库服务器中读取和复制基于位置的事件记录。因此，它总是从主数据库服务器到从数据库服务器。MySQL 8 还支持半同步同步方法。在半同步复制方法中，任何在主数据库服务器上提交的事务都会被阻塞，直到主数据库服务器收到至少一个从数据库服务器已接收并记录了事务事件的确认。延迟复制是 MySQL 8 支持的另一种复制方法。在延迟复制中，从数据库服务器故意将事务事件记录在主数据库服务器之后一段时间。

# MySQL 复制的优势

现在我们已经熟悉了 MySQL 数据库复制是什么，是时候评估维护多个数据库服务器的增加复杂性是否值得了。

MySQL 8 数据库复制的优势如下：

1.  **扩展解决方案**：如前所述，通常 Web 应用程序是读密集型应用程序。读操作的数量远远高于写操作。这些应用程序提供需要在数据库服务器上执行复杂的 SQL 查询的功能。这些不是毫秒级执行的查询。这样复杂的查询可能需要几秒到几分钟的执行时间。执行这样的查询会给数据库服务器带来沉重的负载。在这种情况下，最好将这些读操作在主数据库服务器上执行而不是在主数据库服务器上执行。写数据库操作将始终在主数据库服务器上执行。你知道为什么吗？因为它触发数据库修改。这些修改的事件必须写入二进制日志文件，以便从从服务器进行复制同步。此外，同步是从主服务器到从服务器。因此，如果我们在从服务器上执行写数据库操作，这些操作将永远不会在主数据库服务器上可用。这种方法通过在多个从服务器上执行读操作来提高写操作的性能，并增加读操作的速度。

1.  **数据安全**：安全性通常是每个 Web 应用程序都需要的重要功能。安全性可以在应用程序层或数据库层上进行。数据安全性可防止数据丢失。通过定期备份数据库来实现数据安全性。如果没有设置复制，备份生产数据库需要将应用程序置于维护模式。这是必需的，因为应用程序和备份过程同时访问数据库可能会损坏数据。有了复制，我们可以使用其中一个从服务器进行备份。由于从数据库服务器始终与主数据库服务器同步，我们可以备份从数据库服务器。为此，我们可以使从数据库服务器在备份过程运行时停止从主数据库服务器复制。这不需要 Web 应用程序停止使用主数据库服务器。事实上，它不会以任何方式影响主数据库服务器。另一个数据安全性方面是为生产或主数据库服务器提供基于角色的访问。我们只能让少数角色从后端访问主数据库服务器。其余用户或角色可以访问从数据库服务器。这减少了由于人为错误而导致的意外数据丢失的风险。

1.  **分析**：分析和报告始终是数据库支持的应用程序的重要功能。这些功能需要频繁地从数据库中获取信息，以便对数据进行分析。如果设置了数据库复制，我们可以从从数据库服务器获取分析所需的数据，而不会影响主数据库服务器的性能。

1.  **远程数据分发**：应用程序开发人员通常需要在本地开发环境中复制生产数据。在启用数据库复制的基础设施中，可以使用从数据库服务器在开发数据库服务器上准备数据库副本，而无需经常访问主数据库服务器。

# 配置复制

在本节中，我们将学习不同类型的 MySQL 8 复制方法的配置。它包括逐步设置和配置复制的说明。

# 基于二进制日志文件的复制

MySQL 数据库复制最常见的传统方法之一是二进制日志文件位置方法。本节重点介绍了二进制日志文件位置复制的配置。在我们进入配置部分之前，最好复习和了解基于二进制日志位置的复制的基础知识。

如前所述，MySQL 数据库服务器之一充当主服务器，其余的 MySQL 数据库服务器成为从服务器。主数据库服务器是数据库更改的起点。主数据库服务器根据数据库的更新或更改在二进制日志文件中写入事件。写入二进制日志文件的信息记录的格式根据记录的数据库更改而变化。MySQL `REPLICATION SLAVE`数据库服务器被配置为从主数据库服务器读取二进制日志事件。从服务器在本地数据库二进制日志文件上执行事件。这样从服务器就可以将数据库与主数据库同步。当从数据库服务器从主数据库服务器读取二进制日志文件时，从服务器会获得整个二进制日志文件的副本。一旦接收到二进制日志文件，就由从服务器决定在从服务器二进制日志文件上执行哪些语句。可以指定应在从数据库服务器的二进制日志文件上执行来自主数据库服务器二进制日志文件的所有语句。也可以处理特定数据库或表过滤的事件。

只有从数据库服务器可以配置过滤来自主数据库服务器日志文件的事件。无法配置主数据库服务器仅记录特定事件。

MySQL 8 提供了一个系统变量，可以帮助唯一标识数据库服务器。参与 MySQL 复制的所有数据库服务器都必须配置为具有唯一的 ID。每个从数据库服务器都必须配置主数据库服务器的主机名、日志文件名和日志文件中的位置。设置完成后，可以在从数据库服务器上使用`CHANGE MASTER TO`语句在 MySQL 会话中修改这些细节。

当从数据库服务器从主数据库二进制日志文件中读取信息时，它会跟踪二进制日志坐标的记录。 二进制日志坐标包括文件名和文件内的位置，从主数据库服务器读取和处理。 从数据库服务器读取主数据库服务器的二进制日志文件的效率非常高，因为可以将多个从数据库服务器连接到主数据库服务器，并从主数据库服务器处理二进制日志文件的不同部分。 主数据库服务器的操作保持不变，因为从主数据库服务器连接和断开从数据库服务器的控制由从服务器自己控制。 如前所述，每个从数据库服务器都会跟踪二进制日志文件中的当前位置。 因此，从数据库服务器可以断开连接并重新连接到主数据库服务器，并恢复二进制日志文件处理。

MySQL 中提供了多种设置数据库复制的方法。 复制的确切方法取决于数据库中是否已存在数据以及如何设置复制。 以下各节中的每个部分都是配置 MySQL 复制的步骤。

# 复制主配置

在设置复制主数据库服务器之前，必须确保数据库服务器已建立唯一 ID 并启用了二进制日志记录。 可能需要在进行这些配置后重新启动数据库服务器。 主数据库服务器二进制日志是 MySQL 8 数据库复制的基础。

要启用二进制日志记录，应将`log_bin`系统变量设置为`ON`。 默认情况下，MySQL 数据库服务器启用了二进制日志记录。 如果使用`mysqld`手动使用`--initialize`或`--initialize-insecure`选项初始化数据目录，则默认情况下禁用了二进制日志记录。 必须通过指定`--log-bin`选项来启用它。 `--log-bin`选项指定要用于二进制日志文件的基本名称。

如果启动选项未指定文件名，则二进制日志文件名将基于数据库服务器主机名进行设置。 建议使用`--log-bin`选项指定二进制日志文件名。 如果使用`--log_bin=old_host_name-bin`指定日志文件名，则即使更改数据库服务器主机，日志文件名也将保留。

要设置主数据库服务器，请在主数据库服务器上打开 MySQL 配置文件：

```sql
sudo vim /etc/mysql/my.cnf
```

在配置文件中进行以下更改。

首先，找到将服务器绑定到 localhost 的部分：

```sql
bind-address = 127.0.0.1
```

用实际数据库服务器 IP 地址替换本地 IP 地址。 这一步很重要，因为从服务器可以使用主数据库服务器的公共 IP 地址访问主数据库服务器：

```sql
bind-address = 175.100.170.1
```

需要对主数据库服务器进行配置以配置唯一 ID。 还包括设置主二进制日志文件所需的配置：

```sql
[mysqld]
log-bin=/var/log/mysql/mysql-bin.log
server-id=1
```

现在，让我们配置数据库在从数据库服务器上进行复制。 如果需要在从数据库服务器上复制多个数据库，则多次重复以下行：

```sql
binlog_do_db = database_master_one
binlog_do_db = database_master_two
```

完成这些更改后，使用以下命令重新启动数据库服务器：

```sql
sudo service mysql restart
```

现在，我们已经设置好了主数据库服务器。 下一步是授予从用户权限如下：

```sql
mysql> mysql -u root -p
mysql> CREATE USER 'slaveone'@'%' IDENTIFIED BY 'password';
mysql> GRANT REPLICATION SLAVE ON *.* TO 'slaveone'@'%' IDENTIFIED BY 'password';
```

上述命令创建了从用户，在主数据库服务器上授予了权限，并刷新了数据库缓存的权限。

现在，我们必须备份要复制的数据库。 我们将使用`mysqldump`命令备份数据库。 此数据库将用于创建`slave`数据库。 主状态输出显示要复制的二进制日志文件名、当前位置和数据库名称：

```sql
mysql> USE database_master_one;
mysql> FLUSH TABLES WITH READ LOCK;
mysql> SHOW MASTER STATUS;
+------------------+----------+---------------------+------------------+ 
|       File       | Position |     Binlog_Do_DB    | Binlog_Ignore_DB | 
+------------------+----------+---------------------+------------------+ 
| mysql-bin.000001 |    102   | database_master_one |                  | 
+------------------+----------+---------------------+------------------+ 
1 row in set (0.00 sec)

mysqldump -u root -p database_master_one > database_master_one_dump.sql
```

在使用`mysqldump`命令进行数据库备份之前，我们必须锁定数据库以检查当前位置。稍后将使用此信息设置从数据库服务器。

数据库转储完成后，应使用以下命令解锁数据库：

```sql
mysql> UNLOCK TABLES;
mysql> QUIT;
```

我们已经完成了设置复制主数据库服务器所需的所有配置，并使其可以被`REPLICATION SLAVE`数据库服务器访问。

以下选项对主数据库服务器设置产生影响：

1.  `innodb_flush_log_at_trx_commit=1`和`sync_binlog=1`选项应该设置为实现更高的耐久性和一致性。这些选项可以在`my.cnf`配置文件中设置。

1.  `skip-networking`选项不能被启用。如果启用了，从服务器就无法与主服务器通信，数据库复制将失败。

# REPLICATION SLAVE 配置

与主数据库服务器类似，每个从数据库服务器必须有一个唯一的 ID。设置完成后，这将需要数据库服务器重启：

```sql
[mysqld]
server-id=2
```

要设置多个从数据库服务器，必须配置一个唯一的非零`server-id`，该 ID 与主服务器或任何其他从数据库服务器不同。不需要在从数据库服务器上启用二进制日志记录以设置复制。如果启用了，在从数据库服务器上的二进制日志文件可以用于数据库备份和崩溃恢复。

现在，创建一个新的数据库，它将成为主数据库的副本，并从主数据库的数据库转储中导入数据库如下：

```sql
mysql> CREATE DATABASE database_slave_one;
mysql> QUIT;

# mysql -u root -p database_slave_one &lt; /path/to/database_master_one_dump.sql
```

现在，我们必须在`my.cnf`文件中配置其他一些选项。与二进制日志类似，中继日志由带有数据库更改事件的编号文件组成。它还包含一个索引文件，其中包含所有已使用的中继日志文件的名称。以下配置设置了中继日志文件、二进制日志文件和从服务器数据库的名称，该名称是主数据库的副本，如下所示：

```sql
relay-log = /var/log/mysql/mysql-relay-bin.log
log_bin = /var/log/mysql/mysql-bin.log
binlog_do_db = database_slave_one
```

在进行此配置更改后，需要重新启动数据库服务器。下一步是在 MySQL shell 提示符中启用从服务器复制。执行以下命令设置`slave`数据库服务器所需的`master`数据库信息：

```sql
mysql> CHANGE MASTER TO MASTER_HOST='12.34.56.789', MASTER_USER='slaveone', MASTER_PASSWORD='password', MASTER_LOG_FILE='mysql-bin.000001', MASTER_LOG_POS= 103;
```

作为最后一步，激活从服务器：

```sql
mysql> START SLAVE;
```

如果在`slave`数据库服务器上启用了二进制日志记录，从服务器可以参与复杂的复制策略。在这样的复制设置中，数据库服务器`A`充当数据库服务器`B`的主服务器。`B`充当`A`的`master`数据库服务器的从服务器。现在，`B`反过来可以充当`C`的`slave`数据库服务器的主数据库服务器。类似的情况如下所示：

```sql
A -> B -> C
```

# 添加从服务器进行复制

可以向现有的复制配置中添加一个新的从数据库服务器。这不需要停止主数据库服务器。方法是复制现有的`slave`数据库服务器。复制后，我们必须修改`server-id`配置选项的值。

以下说明设置了一个新的从数据库服务器到现有的复制配置。首先，应该关闭现有的从数据库服务器如下：

```sql
mysql> mysqladmin shutdown
```

现在，应该将现有从服务器的数据目录复制到新的从数据库服务器。除了数据目录，还必须复制二进制日志和中继日志文件。建议为新的从数据库服务器使用与现有从数据库服务器相同的`--relay-log`值。

如果主信息和中继日志信息存储库使用文件，则必须从现有的从数据库服务器复制这些文件到新的从数据库服务器。这些文件保存了主服务器的当前二进制日志坐标和从服务器的中继日志。

现在，启动之前停止的现有从服务器。

现在，我们应该能够启动新的从服务器。如果尚未设置，必须在启动新的从服务器之前配置唯一的`server-id`。

# 基于全局事务标识符的复制

本节重点介绍基于全局事务标识符的复制。它解释了在 MySQL 服务器中如何定义、创建和表示 GTID。它描述了设置和启动基于 GTID 的复制的过程。

使用基于 GTID 的复制，每个事务在提交到原始数据库服务器时都被分配一个唯一的事务 ID，称为**GTID**。这个唯一标识符是全局的，这意味着它在参与复制的所有数据库服务器中是唯一的。使用 GTID，更容易跟踪和处理每个事务在提交到`master`数据库服务器时。使用这种复制方法，不需要依赖日志文件来同步`master`和`slave`数据库。也更容易确定`master`和`slave`数据库是否一致，因为这种复制方法是基于事务的。只要在`master`数据库上提交的所有事务也在从服务器上应用，`master`和`slave`数据库之间的一致性就是有保证的。可以使用基于语句或基于行的复制与 GTID。如前所述，GTID 用由冒号(`:`)分隔的一对坐标表示，如下例所示：

```sql
GTID = source_id:transaction_id
```

使用基于 GTID 的复制方法的优点是：

1.  通过这种复制方法，可以在服务器故障转移的情况下切换主数据库服务器。全局事务标识符在所有参与的数据库服务器上是唯一的。从服务器使用 GTID 跟踪最后执行的事务。这意味着如果主数据库服务器切换到新的数据库服务器，从服务器更容易继续使用新的主数据库服务器并恢复复制处理。

1.  从服务器数据库服务器的状态以一种崩溃安全的方式维护。使用更新的复制技术，`slave`数据库服务器在名为`mysql.gtid_slave_pos`的系统表中跟踪当前位置。使用诸如`InnoDB`之类的事务存储引擎，状态的更新记录在与数据库操作相同的事务中。因此，如果从服务器崩溃，重新启动后，从服务器将启动崩溃恢复，并确保记录的复制位置与复制的更改匹配。这在传统的基于二进制日志文件的复制中是不可能的，因为中继日志文件独立于实际数据库更改而更新，如果从服务器崩溃，很容易出现不同步。

在深入了解基于 GTID 的复制配置之前，让我们先了解一些其他术语。

`gtid_set`是一组全局事务标识符。它在以下示例中表示：

```sql
gtid_set:
 uuid_set [, uuid_set] ...
 | ''

uuid_set:
 uuid:interval[:interval]...

uuid:
 hhhhhhhh-hhhh-hhhh-hhhh-hhhhhhhhhhhh

h:
 [0-9|A-F]

interval:
 n[-n]
 (n >= 1)
```

GTID 集的使用方式有几种。系统变量`gtid_executed`和`gtid_purged`用 GTID 集表示。MySQL 函数`GTID_SUBSET()`和`GTID_SUBTRACT()`需要 GTID 集作为输入参数。

主数据库服务器和从数据库服务器都保留 GTID。一旦在一个服务器上使用一个 GTID 提交了一个事务，那个服务器就会忽略任何后续具有相似 GTID 的事务。这意味着在`master`数据库服务器上提交的事务只能在`slave`数据库服务器上提交或应用一次。这有助于保持`master`和`slave`数据库之间的一致性。

以下是 GTID 的生命周期摘要：

1.  事务在主数据库服务器上执行并提交。使用主服务器的 UUID 为该事务分配一个 GTID。GTID 被写入主数据库服务器的二进制日志文件。

1.  一旦二进制日志文件被从服务器接收并记录在从服务器的中继日志中，从服务器会将`gtid_next`系统变量的值设置为读取的 GTID。这表示给`slave`指示下一个要执行的事务是具有此 GTID 的事务。

1.  `slave`数据库服务器在二进制日志文件中维护其已处理事务的 GTID 集。在应用由`gtid_next`指示的事务之前，它会检查二进制日志文件中是否记录了或记录了该 GTID。如果在二进制日志文件中找不到 GTID，则从服务器会处理与 GTID 相关联的事务，并将 GTID 写入二进制日志文件。这样，从服务器可以保证同一个事务不会被执行多次。

现在，让我们转到基于 GTID 的 MySQL 复制的主配置。首先，打开`my.cnf`文件并进行以下更改：

```sql
[mysqld]
server-id = 1
log-bin = mysql-bin 
binlog_format = ROW 
gtid_mode = on 
enforce_gtid_consistency 
log_slave_updates
```

这些配置更改需要服务器重启。前面的配置是不言自明的。`gtid_mode`选项启用了基于 GTID 的数据库复制。

1.  现在，在从服务器上为访问主数据库创建一个用户。同时，使用`mysqldump`命令进行数据库备份。数据库备份将用于设置从服务器。

```sql
 > CREATE USER 'slaveuser'@'%' IDENTIFIED BY 'password'; 
 > GRANT REPLICATION SLAVE ON *.* TO 'slaveuser'@'%' IDENTIFIED 
          BY 'password';
 > mysqldump -u root -p databaseName > databaseName.sql
```

这就是主数据库配置的全部内容。让我们继续进行从服务器端的配置。

1.  在`slave`数据库服务器的 shell 提示符上，按照以下步骤从`master`数据库服务器备份中导入数据库：

```sql
 > mysql -u root -p databaseName &lt; /path/to/databaseName.sql
```

1.  现在，在从服务器的`my.cnf`文件中添加以下配置：

```sql
 [mysqld]
 server_id = 2
 log_bin = mysql-bin
 binlog_format = ROW
 skip_slave_start
 gtid_mode = on
 enforce_gtid_consistency
 log_slave_updates
```

1.  完成这些配置后，使用以下命令重新启动数据库服务器：

```sql
 sudo service mysql restart
```

1.  下一步是在`slave`数据库服务器上使用`CHANGE MASTER TO`命令设置主数据库服务器信息：

```sql
 > CHANGE MASTER TO MASTER_HOST='170.110.117.12', MASTER_PORT=3306, 
 MASTER_USER='slaveuser', MASTER_PASSWORD='password', MASTER_AUTO_POSITION=1;
```

1.  现在，启动`slave`服务器：

```sql
 START SLAVE;
```

在这种复制方法中，主数据库备份已经包含了 GTID 信息。因此，我们只需要提供从服务器应该开始同步的位置。

1.  这是通过设置`GTID_PURGED`系统变量来完成的：

```sql
 -- -- GTID state at the beginning of the backup -- 
 mysql> SET @@GLOBAL.GTID_PURGED='b9b4712a-df64-11e3-b391-60672090eb04:1-7';
```

# MySQL 多源复制

本节重点介绍了并行从多个主服务器复制的方法。这种方法称为**多源复制**。使用多源复制，`REPLICATION SLAVE`可以同时从多个源接收事务。每个`master`都会为`REPLICATION SLAVE`创建一个通道，从中接收事务。

多源复制配置需要至少配置两个主服务器和一个从服务器。主服务器可以使用基于二进制日志位置的复制或基于 GTID 的复制进行配置。复制存储库存储在`FILE`或`TABLE`存储库中。`TABLE`存储库是崩溃安全的。MySQL 多源复制需要`TABLE`存储库。设置`TABLE`存储库有两种方法。

一种是使用以下选项启动`mysqld`：

```sql
mysqld —master-info-repostiory=TABLE && –relay-log-info-repository=TABLE
```

另一种做法是修改`my.cnf`文件如下：

```sql
[mysqld] 
master-info-repository = TABLE 
relay-log-info-repository = TABLE
```

可以修改正在使用`FILE`存储库的现有`REPLICATION SLAVE`以使用`TABLE`存储库。以下命令动态转换现有存储库：

```sql
STOP SLAVE; 
SET GLOBAL master_info_repository = 'TABLE'; 
SET GLOBAL relay_log_info_repository = 'TABLE';
```

以下命令可用于将基于 GTID 的新复制主服务器添加到现有的多源`REPLICATION SLAVE`。它将主服务器添加到现有的从服务器通道：

```sql
CHANGE MASTER TO MASTER_HOST='newmaster', MASTER_USER='masteruser', MASTER_PORT=3451, MASTER_PASSWORD='password', MASTER_AUTO_POSITION = 1 FOR CHANNEL 'master-1';
```

以下命令可用于将基于二进制日志文件位置的新复制主服务器添加到现有的多源`REPLICATION SLAVE`。它将主服务器添加到现有的从服务器通道：

```sql
CHANGE MASTER TO MASTER_HOST='newmaster', MASTER_USER='masteruser', MASTER_PORT=3451, MASTER_PASSWORD='password' MASTER_LOG_FILE='master1-bin.000006', MASTER_LOG_POS=628 FOR CHANNEL 'master-1';
```

以下命令`START`/`STOP`/`RESET`所有配置的复制通道：

```sql
START SLAVE thread_types; -- To start all channels
STOP SLAVE thread_types; -- To stop all channels
RESET SLAVE thread_types; -- To reset all channels
```

以下命令使用`FOR CHANNEL`子句`START`/`STOP`/`RESET`命名通道：

```sql
START SLAVE thread_types FOR CHANNEL channel;
STOP SLAVE thread_types FOR CHANNEL channel;
RESET SLAVE thread_types FOR CHANNEL channel;

```

# 复制管理任务

本节描述了一些常见的 MySQL 复制管理任务。通常情况下，一旦设置好，MySQL 复制就不需要定期监控。

最常见的任务之一是确保主数据库服务器和从数据库服务器之间的复制没有错误。使用`SHOW SLAVE STATUS` MySQL 语句进行如下检查：

```sql
mysql> SHOW SLAVE STATUS\G
*************************** 1\. row ***************************
 Slave_IO_State: Waiting for master to send event
 Master_Host: master1
 Master_User: root
 Master_Port: 3306
 Connect_Retry: 60
 Master_Log_File: mysql-bin.000004
 Read_Master_Log_Pos: 931
 Relay_Log_File: slave1-relay-bin.000056
 Relay_Log_Pos: 950
 Relay_Master_Log_File: mysql-bin.000004
 Slave_IO_Running: Yes
 Slave_SQL_Running: Yes
 Replicate_Do_DB:
 Replicate_Ignore_DB:
 Replicate_Do_Table:
 Replicate_Ignore_Table:
 Replicate_Wild_Do_Table:
 Replicate_Wild_Ignore_Table:
 Last_Errno: 0
 Last_Error:
 Skip_Counter: 0
 Exec_Master_Log_Pos: 931
 Relay_Log_Space: 1365
 Until_Condition: None
 Until_Log_File:
 Until_Log_Pos: 0
 Master_SSL_Allowed: No
 Master_SSL_CA_File:
 Master_SSL_CA_Path:
 Master_SSL_Cert:
 Master_SSL_Cipher:
 Master_SSL_Key:
 Seconds_Behind_Master: 0
Master_SSL_Verify_Server_Cert: No
 Last_IO_Errno: 0
 Last_IO_Error:
 Last_SQL_Errno: 0
 Last_SQL_Error:
 Replicate_Ignore_Server_Ids: 0
```

在前面的输出中，以下是一些关键字段的解释：

+   `Slave_IO_State`：从服务器的当前状态

+   `Slave_IO_Running`：指示读取主日志文件的 I/O 线程是否正在运行

+   `Slave_SQL_Running`：指示执行事件的 SQL 线程是否正在运行

+   `Last_IO_Error, Last_SQL_Error`：I/O 或 SQL 线程处理中继线程报告的最后错误

+   `Seconds_Behind_Master`**：**指示从服务器 SQL 线程运行落后于主服务器处理主二进制日志的秒数

我们可以使用`SHOW_PROCESSLIST`语句来检查连接的从服务器的状态：

```sql
mysql> SHOW PROCESSLIST \G;
*************************** 4\. row ***************************
 Id: 10
 User: root
 Host: slave1:58371
 db: NULL
Command: Binlog Dump
 Time: 777
 State: Has sent all binlog to slave; waiting for binlog to be updated
 Info: NULL
```

当在主服务器上执行`SHOW_SLAVE_HOSTS`语句时，提供关于从服务器的信息如下：

```sql
mysql> SHOW SLAVE HOSTS;
+-----------+--------+------+-------------------+-----------+
| Server_id |  Host  | Port | Rpl_recovery_rank | Master_id |
+-----------+--------+------+-------------------+-----------+
|     10    | slave1 | 3306 |         0         |      1    |
+-----------+--------+------+-------------------+-----------+
1 row in set (0.00 sec)
```

另一个重要的复制管理任务是能够在`slave`数据库服务器上启动或停止复制。以下命令用于执行此操作：

```sql
mysql> STOP SLAVE;
mysql> START SLAVE;
```

还可以通过指定线程的类型来停止和启动单个线程，如下所示：

```sql
mysql> STOP SLAVE IO_THREAD; 
mysql> STOP SLAVE SQL_THREAD;

mysql> START SLAVE IO_THREAD; 
mysql> START SLAVE SQL_THREAD;

```

# 实施复制

复制的基础是主数据库服务器跟踪主数据库上发生的所有更改。这些更改以事件的形式在二进制日志文件中进行跟踪，自服务器启动以来。`SELECT`操作不会被记录，因为它们既不修改数据库也不修改内容。每个`REPLICATION SLAVE`从`master`拉取二进制日志文件的副本，而不是主数据库推送日志文件到`slave`。从服务器依次执行从主二进制日志文件中读取的事件。这保持了`master`和`slave`服务器之间的一致性。在 MySQL 复制中，每个`slave`都独立于`master`和其他`slave`服务器。因此，从服务器可以在不影响`master`或`slave`功能的情况下，在方便的时候请求主的二进制日志文件。

本章节的重点是 MySQL 复制的详细信息。我们已经了解了基础知识，这将帮助我们理解深入的细节。

# 复制格式

正如我们现在已经知道的那样，MySQL 复制是基于从主服务器生成的二进制日志中的事件进行复制的。稍后，这些事件将被从服务器读取和处理。我们还不知道的是这些事件以何种格式记录在二进制日志文件中。复制格式是本节的重点。

当事件记录在主二进制日志文件中时，使用的复制格式取决于使用的二进制日志格式。基本上，存在两种二进制日志格式：基于语句和基于行。

使用基于语句的二进制日志记录，SQL 语句被写入主二进制日志文件。从服务器上的复制通过在`slave`数据库上执行 SQL 语句来工作。这种方法称为**基于语句**复制。它对应于 MySQL 基于语句的二进制日志格式。这是直到 MySQL 版本 5.1.4 和更早版本存在的唯一传统格式。

使用基于行的二进制日志记录，主二进制日志中写入的事件指示单个表行如何更改。在这种情况下，复制是通过从服务器复制表示表行更改的事件来工作的。这称为基于行的复制。基于行的日志记录是默认的 MySQL 复制方法。

MySQL 支持配置以混合基于语句和基于行的日志记录。使用日志格式的决定取决于被记录的更改。这被称为混合格式日志记录。当使用混合格式日志记录时，基于语句的日志记录是默认格式。根据使用的语句类型和存储引擎，日志会自动切换到基于行的格式。基于混合日志格式的复制被称为混合格式复制。

`binlog_format`系统变量控制着运行中的 MySQL 服务器中使用的日志格式。在会话或全局范围设置`binlog_format`系统变量需要`SYSTEM_VARIABLES_ADMIN`或`SUPER`权限。

# 基于语句与基于行的复制

在前面的部分中，我们学习了三种不同的日志格式。每种格式都有其自己的优点和缺点。通常情况下，混合格式应该提供最佳的完整性和性能组合。然而，要从基于语句或基于行的复制中获得最佳性能，本节中描述的优点和缺点是有帮助的。

与基于行的复制相比，基于语句的复制是一种传统且经过验证的技术。日志文件中记录的记录或事件数量较少。如果一个语句影响了许多行，只有一个语句将被写入二进制日志文件。在基于行的复制中，对于每个修改的表行，都将输入一条记录，尽管作为单个语句的一部分。实质上，这意味着基于语句的复制需要更少的存储空间用于日志文件。这也意味着备份、恢复或复制事件的速度更快。

除了前面描述的优点之外，基于语句的复制也有缺点。由于复制是基于 SQL 语句的，因此可能无法使用基于语句的复制复制修改数据的所有语句。以下是一些示例：

+   SQL 语句依赖于用户定义的函数，当这些用户定义的函数返回的值依赖于除了提供给它的参数之外的因素时，它是不确定的。

+   带有`LIMIT`子句但没有`ORDER BY`子句的`UPDATE`和`DELETE`语句是不确定的，因为在复制过程中可能已经改变了顺序。

+   使用`NOWAIT`或`SKIP LOCKED`选项的`FOR UPDATE`或`FOR SHARE`锁定读取语句。

+   用户定义的函数必须应用于从数据库。

+   使用函数的 SQL 语句，如`LOAD_FILE()`，`UUID()`，`USER()`，`UUID_SHORT()`，`FOUND_ROWS()`，`SYSDATE()`，`GET_LOCK()`等，无法使用基于语句的复制正确地进行复制。

+   `INSERT`或`SELECT`语句需要更多的行级锁。

+   使用表扫描的`UPDATE`需要锁定更多的行。

+   复杂的 SQL 语句必须在从数据库服务器上执行和评估，然后再插入或更新行。

让我们看看基于行的复制提供的优势。基于行的复制是最安全的复制形式，因为它不依赖于 SQL 语句，而是依赖于表行中存储的值。因此，每个更改都可以被复制。在`INSERT...SELECT`语句中需要更少的行锁。不使用键的`UPDATE`和`DELETE`语句需要更少的行级锁。

基于行的复制的主要缺点是它生成了更多必须记录的数据。使用基于语句的复制，一个 DML SQL 语句就足够记录，尽管它修改了许多行。在基于行的复制中，需要为每个更改的行记录日志。基于行的复制的二进制日志文件增长非常快。复制确定性用户定义的函数生成大型`BLOB`值需要更长的时间。

# 复制实现细节

在 MySQL 中，有三个线程参与实现复制。这三个线程中，一个在主服务器上，另外两个在`slave`数据库服务器上。让我们深入了解这些线程的细节：

+   **Binlog 转储线程：** 当从属数据库服务器请求二进制日志文件时，主服务器负责将内容发送到从属数据库服务器。为了实现这一点，当从属数据库服务器连接到主数据库服务器时，主数据库服务器会创建一个线程。`binlog`转储线程将二进制日志内容发送到从属数据库服务器。在主数据库服务器上执行`SHOW PROCESSLIST`命令的输出中，可以将此线程标识为`Binlog Dump`线程。`binlog`转储线程锁定主服务器上的二进制日志文件，以便读取要发送到从属数据库服务器的每个事件。一旦事件被读取，锁就会被释放，甚至在发送到从属数据库服务器之前。

+   **从属 I/O 线程：** 从属 I/O 线程的主要责任是从主数据库服务器请求二进制日志更新。当执行`START SLAVE`命令时，从属数据库服务器会创建 I/O 线程。该线程连接到主数据库服务器，并请求从二进制日志发送更新。一旦主服务器的`binlog`转储线程发送内容，从属 I/O 线程读取内容并将其复制到本地文件，包括从属的中继日志。可以通过`SHOW SLAVE STATUS`或`SHOW STATUS`命令获取此线程的状态。

+   **从属 SQL 线程：** 从属 I/O 线程将事件写入从属的中继日志。从属 SQL 线程负责在从属数据库服务器上执行这些事件。从属 SQL 线程读取从属 I/O 线程写入的中继日志中的事件并执行它们。

根据前述描述，每个主从连接对都会创建三个线程。如果主服务器有多个`slave`数据库服务器，它会为每个当前连接的从属创建一个专用的二进制日志转储线程。另一方面，每个从属都会创建自己的 I/O 和 SQL 线程。从属数据库服务器为什么要创建两个单独的线程，一个用于写入事件，另一个用于执行事件？原因是通过这种方法，读取语句的任务不会被执行语句所减慢。考虑到从属服务器没有运行，其 I/O 线程在`slave`服务器启动时会快速从主数据库获取所有二进制日志，而不管 SQL 线程是否落后。此外，如果`slave`数据库服务器在 SQL 线程执行所有这些语句之前停止，这些语句将记录在从属中继日志中。因此，当从属再次启动时，SQL 线程可以执行这些语句。因此，中继日志作为从主数据库服务器读取的语句的安全副本。

`SHOW PROCESSLIST`语句提供了关于`master`或`slave`数据库服务器上发生的情况的信息。在`master`数据库服务器上执行该语句时的输出如下所示：

```sql
mysql> SHOW PROCESSLIST\G
*************************** 1\. row ***************************
 Id: 2
 User: root
 Host: localhost:32931
 db: NULL
Command: Binlog Dump
 Time: 94
 State: Has sent all binlog to slave; waiting for binlog to be updated
 Info: NULL
```

前述输出显示线程 2 是主服务器的`binlog`转储线程。状态表明所有最近的更新都已发送到从属。

当在从属数据库服务器上执行`SHOW PROCESSLIST`语句时，输出如下所示：

```sql
mysql> SHOW PROCESSLIST\G
*************************** 1\. row ***************************
 Id: 10
 User: system user
 Host:
 db: NULL
Command: Connect
 Time: 11
 State: Waiting for master to send event
 Info: NULL
*************************** 2\. row ***************************
 Id: 11
 User: system user
 Host:
 db: NULL
Command: Connect
 Time: 11
 State: Has read all relay log; waiting for the slave I/O thread to update it
 Info: NULL
```

在输出中，线程 10 是从属的 I/O 线程，线程 11 是从属的 SQL 线程。I/O 线程正在等待主服务器的`binlog`转储线程发送二进制日志内容。SQL 线程已经读取了在`slave`中继日志中记录的所有语句。从`Time`列可以确定`slave`落后于`master`的速度有多慢。

# 复制通道

复制通道是从主服务器到从服务器的事务流路径。本节解释了通道在复制中的使用方式。MySQL 服务器在启动时会自动创建一个名为`""`（空字符串）的默认通道。默认通道始终存在，用户无法创建或销毁。如果没有创建其他通道，则复制语句将在默认通道上执行。本节描述了在至少存在一个命名通道时应用于复制通道的语句。

在多源复制中，`slave`数据库服务器打开多个通道，每个通道对应一个主服务器。每个通道都有自己的中继日志和 SQL 线程。复制通道具有主机名和端口关联。多个通道可以分配给相同的主机名和端口组合。在 MySQL 8 中，多源复制拓扑结构中的一个从服务器最多可以添加 256 个通道。通道必须具有非空的唯一名称。

`FOR CHANNEL`子句与各种 MySQL 语句一起使用，用于在单个通道上执行复制操作。该子句可应用于以下语句：

+   `CHANGE MASTER TO`

+   `START SLAVE`

+   `STOP SLAVE`

+   `RESET SLAVE`

+   `SHOW RELAYLOG EVENTS`

+   刷新中继日志

+   `SHOW SLAVE STATUS`

除此之外，以下函数具有额外的通道参数：

+   `MASTER_POS_WAIT()`

+   `WAIT_UNTIL_SQL_THREAD_AFTER_GTIDS()`

为使多源复制正常工作，必须配置以下启动选项：

+   --relay-log-info-repository：如前所述，对于多源复制，必须设置为`TABLE`。在 MySQL 8 中，`FILE`选项已被弃用，`TABLE`是默认选项。

+   --master-info-repository：必须设置为`TABLE`。

+   --log-slave-updates：从主服务器接收的事务写入二进制日志。

+   --relay-log-purge：每个通道自动清除自己的中继日志。

+   --slave-transaction-retries：所有通道的 SQL 线程重试事务。

+   --skip-slave-start：任何通道上都不启动复制线程。

+   --slave-skip-errors：所有通道继续执行并跳过错误。

+   --max-relay-log-size=size：中继日志文件在达到最大大小后进行轮换。

+   --relay-log-space-limit=size：每个单独通道的所有中继日志的总大小上限。

+   --slave-parallel-workers=value：每个通道的从服务器并行工作者数量。

+   --slave-checkpoint-group：I/O 线程的等待时间。

+   --relay-log-index=filename：每个通道的中继日志索引文件名。

+   --relay-log=filename：每个通道的中继日志文件名。

+   --slave-net-timeout=N：每个通道等待 N 秒以检查断开的连接。

+   --slave-skip-counter=N：每个通道从主服务器跳过 N 个事件。

# 复制中继和状态日志

`REPLICATION SLAVE`服务器创建保存从主数据库服务器发送的二进制日志事件的日志。记录有关中继日志的当前状态和位置的信息。在此过程中使用三种类型的日志：

1.  **中继日志**：中继日志包含从主服务器二进制日志发送的事件。这些事件由从服务器的 I/O 线程写入。从服务器的中继日志中的事件由从服务器的 SQL 线程执行。

1.  **主服务器信息日志**：主服务器信息日志包含有关从服务器连接到主数据库服务器的状态和当前配置的信息。主服务器信息日志中包含的信息包括主机名、登录凭据以及指示从服务器在读取主服务器二进制日志时的位置的坐标。这些日志写入`mysql.slave_master_info`表中。

1.  **中继日志信息日志**：中继日志信息日志存储有关从服务器中继日志内执行点的信息。中继日志信息日志写入`mysql.slave_relay_log_info`表中。

不应尝试手动在`slave_master_info`或`slave_relay_log_info`表中插入或更新行。这可能会导致意外行为。在 MySQL 复制中不支持这样做。

从服务器中继日志由一个索引文件和一组编号的日志文件组成。索引文件包含所有中继日志文件的名称。MySQL 数据目录是中继日志文件的默认位置。中继日志文件指的是包含事件的单独编号文件。而中继日志指的是一组编号的中继日志文件和一个索引文件的集合。中继日志文件的格式与二进制日志文件相同。中继日志的索引文件名默认为`host_name-relay-bin.index`，用于默认通道，对于非默认复制通道，默认的中继日志文件和中继日志索引文件的位置可以通过`--relay-log`和`--relay-log-index`服务器启动选项进行覆盖。如果在设置了复制后更改了从服务器的主机名，并且从服务器使用默认基于主机名的中继日志文件名，可能会在中继日志初始化期间抛出错误，例如**无法打开中继日志**和**找不到目标日志**。这可能会导致复制失败。可以通过使用`--relay-log`和`--relay-log-index`选项来明确指定中继日志文件名来避免此类错误。在从服务器设置上使用这些选项将使名称与服务器主机名无关。

# 评估复制过滤规则

本节重点介绍了过滤规则以及服务器如何评估这些规则。基本上，如果主服务器不记录语句，则从服务器不会复制该语句。如果主服务器在其二进制日志文件中记录了该语句，则从服务器会接收该语句。但是，从服务器数据库服务器是否处理该语句或忽略它取决于从服务器启动时使用的`--replicate-*`选项。一旦从服务器启动，`CHANGE REPLICATION FILTER`语句可以用于动态设置选项。

所有复制过滤选项都遵循与数据库和表的名称大小写敏感性相同的规则，包括`lower_case_table_names`系统变量。

# 组复制

本章节解释了组复制是什么，如何设置组复制，配置和监控组复制。基本上，MySQL 组复制是一个插件，使我们能够创建弹性、高可用、容错的复制拓扑。

组复制的目的是创建一个容错系统。为了创建一个容错系统，组件应该是冗余的。组件应该在不影响系统操作方式的情况下被移除。设置这样的系统存在挑战。这样一个系统的复杂性是不同层次的。复制的数据库需要维护和管理多个服务器，而不仅仅是一个。服务器合作创建一个组，这带来了与网络分区和脑裂场景相关的问题。因此，最终的挑战是让多个服务器就系统和数据的状态在每次对系统应用更改后达成一致意见。这意味着服务器需要作为分布式状态机运行。

MySQL 组复制可以提供具有服务器之间强协调的分布式状态机复制。属于同一组的服务器会自动协调。在一个组中，一次只有一个服务器接受更新。主服务器的选举是自动进行的。这种模式称为单主模式。

MySQL 提供了一个组成员服务，负责保持组的视图一致并对所有服务器可用。当服务器加入或离开组时，视图会得到更新。如果有任何服务器意外离开组，故障检测机制会通知组视图发生变化。这种行为是自动的。

大多数组成员必须就事务在全局事务序列中的顺序达成一致意见。决定是否提交或中止事务取决于各个服务器，但所有服务器都做出相同的决定。如果由于网络分区而导致无法达成一致意见，系统将不会继续进行。这意味着系统具有内置的自动分裂脑保护机制。所有这些都是由**组通信系统**（**GCS**）协议完成的。它提供了故障检测机制、组成员服务、安全和完全有序的消息传递。Paxos 算法的实现是这项技术的核心，它充当了组通信引擎。

# 主从复制与组复制

这一部分侧重于复制工作的一些背景细节。这将有助于理解组复制的要求以及它与经典的异步 MySQL 复制有何不同。

以下图展示了传统的异步主从复制是如何工作的。主服务器是主服务器，从服务器是连接到主服务器的一个或多个从服务器，如下图所示：

![](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mysql8-adm-gd/img/c962f92a-671d-4742-8fc1-ea98b5b2f01a.png)

图 1. MySQL 异步复制

MySQL 还支持半同步复制，其中**主服务器**等待至少一个从服务器确认事务接收：

![](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mysql8-adm-gd/img/b0c8f60a-a410-4436-83c2-d95c133dec8c.png)

图 2. MySQL 半同步复制

图中的蓝色箭头表示服务器和客户端应用程序之间传递的消息。

通过组复制，提供了一个通信层，保证了原子消息和总序消息传递。所有读写事务只有在组批准后才提交。只读事务立即提交，因为它不需要协调。因此，在组复制中，提交事务的决定并不是由发起服务器单方面做出的。当事务准备提交时，发起服务器广播写入值和相应的写入集。所有服务器以相同的顺序接收相同的事务集。因此，所有服务器以相同的顺序应用相同的事务。这样所有服务器在组内保持一致：

![](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mysql8-adm-gd/img/e67efdc9-e8c3-4196-ab3f-6207e02ddd58.png)

图 3. MySQL 组复制协议

# 组复制配置

这一部分侧重于配置组复制。

首先，打开`my.cnf`配置文件，并在`mysqld`部分中添加以下条目：

```sql
[mysqld] 
gtid_mode = ON 
enforce_gtid_consistency = ON 
master_info_repository = TABLE 
relay_log_info_repository = TABLE 
binlog_checksum = NONE 
log_slave_updates = ON 
log_bin = binlog 
binlog_format = ROW 
transaction_write_set_extraction = XXHASH64 
loose-group_replication_bootstrap_group = OFF 
loose-group_replication_start_on_boot = OFF 
loose-group_replication_ssl_mode = REQUIRED 
loose-group_replication_recovery_use_ssl = 1
```

这些是与组复制相关的全局事务 ID 和二进制日志记录所需的一般配置。

接下来的步骤是设置组复制配置。这些配置包括组 UUID、组成员白名单和指示种子成员：

```sql
# Shared replication group configuration 
loose-group_replication_group_name = "929ce641-538d-415d-8164-ca00181be227" 
loose-group_replication_ip_whitelist = "177.110.117.1,177.110.117.2,177.110.117.3"
loose-group_replication_group_seeds = "177.110.117.1:33061,177.110.117.2:33061,177.110.117.3:33061"
 . . . Choosing
```

为决定是设置单主组还是多主组，需要以下配置。要启用多主组，取消注释

`loose-group_replication_single_primary_mode`和

`loose-group_replication_enforce_update_everywhere_checks`指令。它将设置多主或多主组：

```sql
. . . 
# Single or Multi-primary mode? Uncomment these two lines 
# for multi-primary mode, where any host can accept writes
loose-group_replication_single_primary_mode = OFF 
loose-group_replication_enforce_update_everywhere_checks = ON
```

必须确保所有服务器上的这些配置都相同。对这些配置的任何更改都需要重新启动 MySQL 组。

以下配置在组中的每台服务器上都不同：

```sql
. . . 
# Host specific replication configuration 
server_id = 1 
bind-address = "177.110.117.1" 
report_host = "177.110.117.1" 
loose-group_replication_local_address = "177.110.117.1:33061"
```

`server-id`必须在组中的所有服务器上是唯一的。端口 33061 是成员用于协调组复制的端口。在进行这些更改后需要重新启动 MySQL 服务器。

如果尚未完成，我们必须使用以下命令允许访问这些端口：

```sql
sudo ufw allow 33061 
sudo ufw allow 3306
```

下一步是创建复制用户并启用复制插件。每个服务器都需要复制用户来建立组复制。在复制用户创建过程中，我们需要关闭二进制日志记录，因为每个服务器的用户都不同，如下所示：

```sql
SET SQL_LOG_BIN=0; 
CREATE USER 'mysql_user'@'%' IDENTIFIED BY 'password' REQUIRE SSL;
GRANT REPLICATION SLAVE ON *.* TO 'mysql_user'@'%'; 
FLUSH PRIVILEGES; 
SET SQL_LOG_BIN=1;
```

现在，使用`CHANGE MASTER TO`来配置服务器使用`group_replication_recovery`通道的凭据：

```sql
CHANGE MASTER TO MASTER_USER='mysql_user', MASTER_PASSWORD='password' FOR CHANNEL 'group_replication_recovery';
```

现在，我们已经准备好安装插件了。连接到服务器并执行以下命令：

```sql
INSTALL PLUGIN group_replication SONAME 'group_replication.so';
```

使用以下语句验证插件是否已激活：

```sql
SHOW PLUGINS;
```

下一步是启动组。在组的一个成员上执行以下语句：

```sql
SET GLOBAL group_replication_bootstrap_group=ON; 
START GROUP_REPLICATION; 
SET GLOBAL group_replication_bootstrap_group=OFF;
```

现在，我们可以在另一台服务器上启动组复制：

```sql
START GROUP_REPLICATION;
```

我们可以使用以下 SQL 查询检查组成员列表：

```sql
mysql> SELECT * FROM performance_schema.replication_group_members; 
+---------------------------+--------------------------------------+
|        CHANNEL_NAME       |                MEMBER_ID             |
+---------------------------+--------------------------------------+
| group_replication_applier | 13324ab7-1b01-11e7-9dd1-22b78adaa992 |
| group_replication_applier | 1ae4b211-1b01-11e7-9d89-ceb93e1d5494 |
| group_replication_applier | 157b597a-1b01-11e7-9d83-566a6de6dfef |
+---------------------------+--------------------------------------+
+---------------+-------------+--------------+ 
|   MEMBER_HOST | MEMBER_PORT | MEMBER_STATE | 
+---------------+-------------+--------------+
| 177.110.117.1 |     3306    |     ONLINE   | 
| 177.110.117.2 |     3306    |     ONLINE   | 
| 177.110.117.3 |     3306    |     ONLINE   | 
+---------------+-------------+--------------+ 
3 rows in set (0.01 sec)
```

# 组复制用例

MySQL 组复制功能提供了一种通过在一组服务器上复制系统状态来构建容错系统的方法。只要大多数服务器正常运行，组复制系统就会保持可用，即使其中一些服务器出现故障。服务器故障由组成员服务跟踪。组成员服务依赖于分布式故障检测器，如果任何服务器离开组（自愿或由于意外停机），则会发出信号。分布式恢复过程确保服务器加入组时会自动更新。因此，使用 MySQL 组复制可以保证持续的数据库服务。不过，存在一个问题。尽管数据库服务可用，但连接到它的客户端在服务器崩溃时必须被重定向到另一台服务器。组复制不会尝试解决这个问题。这应该由连接器、负载均衡器、路由器或其他中间件来处理。

以下是 MySQL 组复制的典型用例：

1.  **弹性复制**：组复制适用于服务器数量在流动环境中动态增长或缩减，且副作用最小的情况。例如，云数据库服务。

1.  **高度可用的分片**：MySQL 组复制可用于实现高度可用的写扩展分片，其中每个复制组映射到一个分片。

1.  **主从复制的替代方案**：组复制可以是单主服务器复制中出现争用问题的解决方案。

1.  **自主系统**：MySQL 组复制可以用于复制协议内置的自动化。

# 复制解决方案

MySQL 复制在许多不同的场景中都很有用，以满足各种目的。本节重点介绍特定的用例，并提供有关如何使用复制的一般信息。

其中一个主要用例是将复制用于备份目的。`master`的数据可以在`slave`数据库服务器上复制，然后可以备份`slave`上的数据。`slave`数据库服务器可以关闭而不影响`master`数据库服务器上运行的操作。

另一个用例是处理`REPLICATION SLAVE`的意外停止。为了实现这一点，一旦`slave`重新启动，I/O 线程必须能够恢复有关已接收事务和 SQL 线程执行的事务的信息。这些信息存储在 `InnoDB` 表中。由于 `InnoDB` 存储引擎是事务性的，它总是可恢复的。正如前面提到的，为了使 MySQL 8 复制使用表，`relay_log_info_repository` 和 `master_info_repository` 必须设置为 `TABLE`。

在基于行的复制中，可以通过性能模式工具阶段来监视从服务器的 SQL 线程的当前进度。要跟踪所有三种基于行的复制事件类型的进度，使用以下语句启用三个性能模式阶段：

```sql
mysql> UPDATE performance_schema.setup_instruments SET ENABLED = 'YES' WHERE NAME LIKE 'stage/sql/Applying batch of row changes%';
```

MySQL 8 复制过程可以工作，即使主服务器上的源表和从服务器上的目标表使用不同的引擎类型。`default_storage_engine` 系统变量不会被复制。这是复制中的一个巨大优势，不同的引擎类型可以用于不同的复制场景。一个例子是扩展场景，我们希望所有读操作在从数据库服务器上执行，而所有写操作应在主数据库服务器上执行。在这种情况下，我们可以在主服务器上使用事务性的 `InnoDB` 引擎，在从数据库服务器上使用非事务性的 `MyISAM` 引擎类型。

考虑一个想要将销售数据分发给不同部门以分担数据分析负载的组织的例子。MySQL 复制可以用于让单个主服务器将不同的数据库复制到不同的从服务器。这可以通过在每个从服务器上使用 `--replicate-wild-do-table` 配置选项来限制二进制日志语句来实现。

一旦设置了 MySQL 复制，随着连接到主服务器的从服务器数量的增加，负载也会增加。主服务器上的网络负载也会增加，因为每个从服务器都应该接收二进制日志的完整副本。主数据库服务器也忙于处理请求。在这种情况下，提高性能变得必要。提高性能的解决方案之一是创建更深层次的复制结构，使主服务器只复制到一个从服务器。其余的从服务器连接到主从服务器进行操作。

# 总结

在本章中，我们了解了关于 MySQL 8 复制的深刻细节，复制是什么，以及它如何帮助解决特定问题。我们还学习了如何设置基于语句和基于行的复制类型。在此过程中，我们还了解了复制的系统变量和服务器启动选项。在本章的后半部分，我们深入探讨了组复制以及它与传统的 MySQL 复制方法的不同之处。我们还学习了日志记录和复制格式。最后但并非最不重要的是，我们简要了解了不同的复制解决方案。我们涵盖了很多东西，是吧？

现在是时候进入我们的下一章了，在那里我们将设置几种类型的分区，并探索分区的选择和分区的修剪。它还解释了在分区时如何应对限制和限制。读者将能够根据需求了解哪种类型的分区适合某种情况。
