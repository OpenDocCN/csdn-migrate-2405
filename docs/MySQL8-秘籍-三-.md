# MySQL8 秘籍（三）

> 原文：[`zh.annas-archive.org/md5/F4A043A5A2DBFB9A7ADE5DAA21AA8E7F`](https://zh.annas-archive.org/md5/F4A043A5A2DBFB9A7ADE5DAA21AA8E7F)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：备份

在本章中，我们将介绍以下内容：

+   使用 mysqldump 进行备份

+   使用 mysqlpump 进行备份

+   使用 mydumper 进行备份

+   使用平面文件进行备份

+   使用 XtraBackup 进行备份

+   备份实例

+   二进制日志备份

# 介绍

设置数据库后，下一个重要的事情是设置备份。在本章中，您将学习如何设置各种类型的备份。执行备份有两种主要方式。一种是逻辑备份，它将所有数据库、表结构、数据和存储例程导出为一组 SQL 语句，可以再次执行以重新创建数据库的状态。另一种类型是物理备份，它包含系统上数据库用于存储所有数据库实体的所有文件：

+   **逻辑备份工具**：`mysqldump`、`mysqlpump`和`mydumper`（未随 MySQL 一起提供）

+   **物理备份工具**：XtraBackup（未随 MySQL 一起提供）和平面文件备份

对于时间点恢复，备份应能够提供备份所涉及的二进制日志位置。这称为**一致备份**。

强烈建议从从属机器上的 filer 进行备份。

# 使用 mysqldump 进行备份

`mysqldump`是一个广泛使用的逻辑备份工具。它提供了各种选项，可以包括或排除数据库，选择要备份的特定数据，仅备份架构而不包括数据，或者仅备份存储例程而不包括其他内容等。

# 如何做...

`mysqldump`实用程序随`mysql`二进制文件一起提供，因此您无需单独安装它。本节涵盖了大多数生产场景。

语法如下：

```sql
shell> mysqldump [options]
```

在选项中，您可以指定用户名、密码和主机名以连接到数据库，如下所示：

```sql
--user <user_name> --password <password>
or
-u <user_name> -p<password>
```

在本章中，每个示例中都没有提到`--user`和`--password`，以便读者专注于其他重要选项。

# 所有数据库的完整备份

可以通过以下方式完成：

```sql
shell> mysqldump --all-databases > dump.sql
```

`--all-databases`选项备份所有数据库和所有表。`>`运算符将输出重定向到`dump.sql`文件。在 MySQL 8 之前，存储过程和事件存储在`mysql.proc`和`mysql.event`表中。从 MySQL 8 开始，相应对象的定义存储在`数据字典`表中，但这些表不会被转储。要在使用`--all-databases`进行转储时包括存储例程和事件，请使用`--routines`和`--events`选项。

包括例程和事件：

```sql
shell> mysqldump --all-databases --routines --events > dump.sql
```

您可以打开`dump.sql`文件查看其结构。前几行是转储时的会话变量。接下来是`CREATE DATABASE`语句，然后是`USE DATABASE`命令。接下来是`DROP TABLE IF EXISTS`语句，然后是`CREATE TABLE`；然后我们有实际的`INSERT`语句插入数据。由于数据存储为 SQL 语句，因此称为**逻辑备份**。

您会注意到，当您恢复转储时，`DROP TABLE`语句将在创建表之前清除所有表。

# 时间点恢复

为了获得时间点恢复，您应该指定`--single-transaction`和`--master-data`。

`--single-transaction`选项通过将事务隔离模式更改为`REPEATABLE READ`并在进行备份之前执行`START TRANSACTION`来提供一致的备份。仅在使用事务表（如`InnoDB`）时才有用，因为它会在不阻止任何应用程序的情况下转储发出`START TRANSACTION`时数据库的一致状态。

`--master-data`选项将服务器的二进制日志坐标打印到`dump`文件中。如果`--master-data=2`，它将作为注释打印。这还使用`FLUSH TABLES WITH READ LOCK`语句来获取二进制日志的快照。正如在第五章“事务”中所解释的那样，在存在任何长时间运行的事务时，这可能非常危险：

```sql
shell> mysqldump --all-databases --routines --events --single-transaction --master-data > dump.sql
```

# 转储主二进制坐标

备份始终在从服务器上进行。要获取备份时主服务器的二进制日志坐标，可以使用`--dump-slave`选项。如果要从主服务器获取二进制日志备份，请使用此选项。否则，请使用`--master-data`选项：

```sql
shell> mysqldump --all-databases --routines --events --single-transaction --dump-slave > dump.sql
```

输出将如下所示：

```sql
--
-- Position to start replication or point-in-time recovery from (the master of this slave)
--
CHANGE MASTER TO MASTER_LOG_FILE='centos7-bin.000001', MASTER_LOG_POS=463;
```

# 特定数据库和表

要仅备份特定数据库，请执行以下操作：

```sql
shell> mysqldump --databases employees > employees_backup.sql
```

要仅备份特定表，请执行以下操作：

```sql
shell> mysqldump --databases employees --tables employees > employees_backup.sql
```

# 忽略表

要忽略某些表，可以使用`--ignore-table=database.table`选项。要指定要忽略的多个表，请多次使用该指令：

```sql
shell> mysqldump --databases employees --ignore-table=employees.salary > employees_backup.sql
```

# 特定行

`mysqldump`可帮助您过滤备份的数据。假设您要备份 2000 年后加入的员工的备份：

```sql
shell> mysqldump --databases employees --tables employees --databases employees --tables employees  --where="hire_date>'2000-01-01'" > employees_after_2000.sql
```

您可以使用`LIMIT`子句来限制结果：

```sql
shell> mysqldump --databases employees --tables employees --databases employees --tables employees  --where="hire_date >= '2000-01-01' LIMIT 10" > employees_after_2000_limit_10.sql
```

# 从远程服务器备份

有时，您可能无法访问数据库服务器的 SSH（例如云实例，如 Amazon RDS）。在这种情况下，您可以使用`mysqldump`从远程服务器备份到本地服务器。为此，您需要使用`--hostname`选项提到`hostname`。确保用户具有适当的权限以连接和执行备份：

```sql
shell> mysqldump --all-databases --routines --events --triggers --hostname <remote_hostname> > dump.sql
```

# 备份以重建具有不同模式的另一个服务器

可能会出现这样的情况，您希望在另一台服务器上具有不同的模式。在这种情况下，您必须转储和还原模式，根据需要更改模式，然后转储和还原数据。根据您拥有的数据量，更改带有数据的模式可能需要很长时间。请注意，此方法仅在修改后的模式与插入兼容时才有效。修改后的表可以有额外的列，但应该具有原始表中的所有列。

# 仅模式，无数据

您可以使用`--no-data`仅转储模式：

```sql
shell> mysqldump --all-databases --routines --events --triggers --no-data > schema.sql
```

# 仅数据，无模式

您可以使用以下选项仅获取数据转储，而不包括模式。

`--complete-insert`将在`INSERT`语句中打印列名，这将在修改后的表中有额外列时有所帮助：

```sql
shell> mysqldump --all-databases --no-create-db --no-create-info --complete-insert > data.sql
```

# 备份以与其他服务器合并数据

您可以以任何一种方式备份以替换旧数据或在冲突发生时保留旧数据。

# 使用新数据替换

假设您希望将生产数据库中的数据还原到已经存在一些数据的开发机器。如果要将生产中的数据与开发中的数据合并，可以使用`--replace`选项，该选项将使用`REPLACE INTO`语句而不是`INSERT`语句。您还应该包括`--skip-add-drop-table`选项，该选项不会将`DROP TABLE`语句写入`dump`文件。如果表的数量和结构相同，还可以包括`--no-create-info`选项，该选项将跳过`dump`文件中的`CREATE TABLE`语句：

```sql
shell> mysqldump --databases employees --skip-add-drop-table --no-create-info --replace > to_development.sql
```

如果生产环境中有一些额外的表，那么在还原时上述转储将失败，因为开发服务器上不存在该表。在这种情况下，您不应添加`--no-create-info`选项，并在还原时使用`force`选项。否则，还原将在`CREATE TABLE`时失败，说表已经存在。不幸的是，`mysqldump`没有提供`CREATE TABLE IF NOT EXISTS`选项。

# 忽略数据

您可以在写入`dump`文件时使用`INSERT IGNORE`语句代替`REPLACE`。这将保留服务器上的现有数据并插入新数据。

# 使用 mysqlpump 进行备份

`mysqlpump`是一个与`mysqldump`非常相似的程序，具有一些额外的功能。

# 如何做...

有很多方法可以做到这一点。让我们详细看看每种方法。

# 并行处理

通过指定线程数（基于 CPU 数量）可以加快转储过程。例如，使用八个线程进行完整备份：

```sql
shell> mysqlpump --default-parallelism=8 > full_backup.sql
```

您甚至可以为每个数据库指定线程数。在我们的情况下，`employees`数据库与`company`数据库相比非常大。因此，您可以为`employees`生成四个线程，并为`company`数据库生成两个线程：

```sql
shell> mysqlpump -u root --password --parallel-schemas=4:employees --default-parallelism=2 > full_backup.sql
Dump progress: 0/6 tables, 250/331145 rows
Dump progress: 0/34 tables, 494484/3954504 rows
Dump progress: 0/42 tables, 1035414/3954504 rows
Dump progress: 0/45 tables, 1586055/3958016 rows
Dump progress: 0/45 tables, 2208364/3958016 rows
Dump progress: 0/45 tables, 2846864/3958016 rows
Dump progress: 0/45 tables, 3594614/3958016 rows
Dump completed in 6957
```

另一个例子是将线程分配给`db1`和`db2`的三个线程，`db3`和`db4`的两个线程，以及其余数据库的四个线程：

```sql
shell> mysqlpump --parallel-schemas=3:db1,db2 --parallel-schemas=2:db3,db4 --default-parallelism=4 > full_backup.sql
```

您会注意到有一个进度条，可以帮助您估计时间。

# 使用正则表达式排除/包含数据库对象

备份以`prod`结尾的所有数据库：

```sql
shell> mysqlpump --include-databases=%prod --result-file=db_prod.sql
```

假设某些数据库中有一些测试表，您希望将它们从备份中排除；您可以使用`--exclude-tables`选项指定，该选项将在所有数据库中排除名称为`test`的表：

```sql
shell> mysqlpump --exclude-tables=test --result-file=backup_excluding_test.sql
```

每个包含和排除选项的值都是适当对象类型的名称的逗号分隔列表。通配符字符允许在对象名称中使用：

+   `%`匹配零个或多个字符的任何序列

+   `_`匹配任何单个字符

除了数据库和表之外，您还可以包括或排除触发器、例程、事件和用户，例如，`--include-routines`、`--include-events`和`--exclude-triggers`。

要了解更多关于包含和排除选项的信息，请参阅[`dev.mysql.com/doc/refman/8.0/en/mysqlpump.html#mysqlpump-filtering`](https://dev.mysql.com/doc/refman/8.0/en/mysqlpump.html#mysqlpump-filtering)。

# 备份用户

在`mysqldump`中，您将不会在`CREATE USER`或`GRANT`语句中获得用户的备份；相反，您必须备份`mysql.user`表。使用`mysqlpump`，您可以将用户帐户作为帐户管理语句（`CREATE USER`和`GRANT`）而不是插入到`mysql`系统数据库中：

```sql
shell> mysqlpump --exclude-databases=% --users > users_backup.sql
```

您还可以通过指定`--exclude-users`选项来排除一些用户：

```sql
shell> mysqlpump --exclude-databases=% --exclude-users=root --users > users_backup.sql
```

# 压缩备份

您可以压缩备份以减少磁盘空间和网络带宽。您可以使用`--compress-output=lz4`或`--compress-output=zlib`。

请注意，您应该具有适当的解压缩实用程序：

```sql
shell> mysqlpump -u root -pxxxx --compress-output=lz4 > dump.lz4
```

要解压缩，请执行此操作：

```sql
shell> lz4_decompress dump.lz4 dump.sql
```

使用`zlib`执行此操作：

```sql
shell> mysqlpump -u root -pxxxx --compress-output=zlib > dump.zlib
```

要解压缩，请执行此操作：

```sql
shell> zlib_decompress dump.zlib dump.sql
```

# 更快的重新加载

您会注意到在输出中，从`CREATE TABLE`语句中省略了次要索引。这将加快恢复过程。索引将使用`ALTER TABLE`语句在`INSERT`的末尾添加。

索引将在第十三章，*性能调整*中进行讨论。

以前，可以在`mysql`系统数据库中转储所有表。从 MySQL 8 开始，`mysqldump`和`mysqlpump`仅转储该数据库中的非“数据字典”表。

# 使用 mydumper 进行备份

`mydumper`是一个类似于`mysqlpump`的逻辑备份工具。

`mydumper`相对于`mysqldump`具有以下优点：

+   并行性（因此，速度）和性能（避免昂贵的字符集转换例程，并且整体代码效率高）。

+   一致性。它在所有线程中保持快照，提供准确的主从日志位置等。 `mysqlpump`不能保证一致性。

+   更容易管理输出（为表和转储的元数据分别创建文件，并且很容易查看/解析数据）。 `mysqlpump`将所有内容写入一个文件，这限制了加载选择性数据库对象的选项。

+   使用正则表达式包含和排除数据库对象。

+   终止长时间运行的事务以阻止备份和所有后续查询的选项。

`mydumper`是一个开源备份工具，您需要单独安装。本节将介绍 Debian 和 Red Hat 系统上的安装步骤以及`mydumper`的使用。

# 如何做...

让我们从安装开始，然后我们将学习与备份相关的许多事项，这些事项在本食谱中列出的每个子部分中都有。

# 安装

安装先决条件：

在 Ubuntu/Debain 上：

```sql
shell> sudo apt-get install libglib2.0-dev libmysqlclient-dev zlib1g-dev libpcre3-dev cmake git
```

在 Red Hat/CentOS/Fedora 上：

```sql
shell> yum install glib2-devel mysql-devel zlib-devel pcre-devel cmake gcc-c++ git
shell> cd /opt
shell> git clone https://github.com/maxbube/mydumper.git
shell> cd mydumper
shell> cmake .

shell> make
Scanning dependencies of target mydumper
[ 25%] Building C object CMakeFiles/mydumper.dir/mydumper.c.o
[ 50%] Building C object CMakeFiles/mydumper.dir/server_detect.c.o
[ 75%] Building C object CMakeFiles/mydumper.dir/g_unix_signal.c.o

shell> make install
[ 75%] Built target mydumper
[100%] Built target myloader
Linking C executable CMakeFiles/CMakeRelink.dir/mydumper
Linking C executable CMakeFiles/CMakeRelink.dir/myloader
Install the project...
-- Install configuration: ""
-- Installing: /usr/local/bin/mydumper
-- Installing: /usr/local/bin/myloader
```

或者，您可以使用 YUM 或 APT，在此处找到发布版本：[`github.com/maxbube/mydumper/releases`](https://github.com/maxbube/mydumper/releases)

```sql
#YUM
shell> sudo yum install -y "https://github.com/maxbube/mydumper/releases/download/v0.9.3/mydumper-0.9.3-41.el7.x86_64.rpm"

#APT
shell> wget "https://github.com/maxbube/mydumper/releases/download/v0.9.3/mydumper_0.9.3-41.jessie_amd64.deb"

shell> sudo dpkg -i mydumper_0.9.3-41.jessie_amd64.deb
shell> sudo apt-get install -f
```

# 完整备份

以下命令将所有数据库备份到`/backups`文件夹中：

```sql
shell> mydumper -u root --password=<password> --outputdir /backups
```

在`/backups`文件夹中创建了多个文件。每个数据库都有其`CREATE DATABASE`语句，格式为`<database_name>-schema-create.sql`，每个表都有自己的模式和数据文件。模式文件存储为`<database_name>.<table>-schema.sql`，数据文件存储为`<database_name>.<table>.sql`。

视图存储为`<database_name>.<table>-schema-view.sql`。存储的例程，触发器和事件存储为`<database_name>-schema-post.sql`（如果目录未创建，请使用`sudo mkdir –pv /backups`）：

```sql
shell> ls -lhtr /backups/company*
-rw-r--r-- 1 root root 69 Aug 13 10:11 /backups/company-schema-create.sql
-rw-r--r-- 1 root root 180 Aug 13 10:11 /backups/company.payments.sql
-rw-r--r-- 1 root root 239 Aug 13 10:11 /backups/company.new_customers.sql
-rw-r--r-- 1 root root 238 Aug 13 10:11 /backups/company.payments-schema.sql
-rw-r--r-- 1 root root 303 Aug 13 10:11 /backups/company.new_customers-schema.sql
-rw-r--r-- 1 root root 324 Aug 13 10:11 /backups/company.customers-schema.sql
```

如果有任何超过 60 秒的查询，`mydumper`将以以下错误失败：

```sql
** (mydumper:18754): CRITICAL **: There are queries in PROCESSLIST running longer than 60s, aborting dump,
 use --long-query-guard to change the guard value, kill queries (--kill-long-queries) or use  different server for dump

```

为了避免这种情况，您可以传递`--kill-long-queries`选项或将`--long-query-guard`设置为更高的值。

`--kill-long-queries`选项会杀死所有大于 60 秒或由`--long-query-guard`设置的值的查询。请注意，由于错误（[`bugs.launchpad.net/mydumper/+bug/1713201`](https://bugs.launchpad.net/mydumper/+bug/1713201)），`--kill-long-queries`也会杀死复制线程：

```sql
shell> sudo mydumper --kill-long-queries --outputdir /backups** (mydumper:18915): WARNING **: Using trx_consistency_only, binlog coordinates will not be accurate if you are writing to non transactional tables.
** (mydumper:18915): WARNING **: Killed a query that was running for 368s
```

# 一致备份

备份目录中的元数据文件包含一致备份的二进制日志坐标。

在主服务器上，它捕获二进制日志位置：

```sql
shell> sudo cat /backups/metadata 
Started dump at: 2017-08-20 12:44:09
SHOW MASTER STATUS:
    Log: server1.000008
    Pos: 154
    GTID:
```

在从服务器上，它捕获主服务器和从服务器的二进制日志位置：

```sql
shell> cat /backups/metadataStarted dump at: 2017-08-26 06:26:19
SHOW MASTER STATUS:
 Log: server1.000012
 Pos: 154
 GTID:
SHOW SLAVE STATUS:
 Host: 35.186.158.188
 Log: master-bin.000013
```

```sql
 Pos: 4633
 GTID:
Finished dump at: 2017-08-26 06:26:24
```

# 单表备份

以下命令将`employees`数据库的`employees`表备份到`/backups`目录中：

```sql
shell> mydumper -u root --password=<password> -B employees -T employees --triggers --events --routines  --outputdir /backups/employee_table
```

```sql
shell> ls -lhtr /backups/employee_table/
total 17M
-rw-r--r-- 1 root root 71 Aug 13 10:35 employees-schema-create.sql
-rw-r--r-- 1 root root 397 Aug 13 10:35 employees.employees-schema.sql
-rw-r--r-- 1 root root 3.4K Aug 13 10:35 employees-schema-post.sql
-rw-r--r-- 1 root root 75 Aug 13 10:35 metadata
-rw-r--r-- 1 root root 17M Aug 13 10:35 employees.employees.sql
```

文件的约定如下：

+   `employees-schema-create.sql`包含`CREATE DATABASE`语句

+   `employees.employees-schema.sql`包含`CREATE TABLE`语句

+   `employees-schema-post.sql`包含`ROUTINES`，`TRIGGERS`和`EVENTS`

+   `employees.employees.sql`包含`INSERT`语句形式的实际数据

# 使用正则表达式备份特定数据库

您可以使用`regex`选项包括/排除特定数据库。以下命令将从备份中排除`mysql`和`test`数据库：

```sql
shell> mydumper -u root --password=<password> --regex '^(?!(mysql|test))' --outputdir /backups/specific_dbs
```

# 使用 mydumper 备份大表

为了加快大表的转储和恢复速度，您可以将其分成小块。块大小可以通过它包含的行数来指定，每个块将被写入单独的文件中：

```sql
shell> mydumper -u root --password=<password> -B employees -T employees --triggers --events --routines --rows=10000 -t 8 --trx-consistency-only --outputdir /backups/employee_table_chunks
```

+   `-t`：指定线程数

+   `--trx-consistency-only`：如果只使用事务表，例如`InnoDB`，使用此选项将最小化锁定

+   `--rows`：将表拆分为此行数的块

对于每个块，将创建一个文件，格式为`<database_name>.<table_name>.<number>.sql`；数字用五个零填充：

```sql
shell> ls -lhr /backups/employee_table_chunks
total 17M
-rw-r--r-- 1 root root 71 Aug 13 10:45 employees-schema-create.sql
-rw-r--r-- 1 root root 75 Aug 13 10:45 metadata
-rw-r--r-- 1 root root 397 Aug 13 10:45 employees.employees-schema.sql
-rw-r--r-- 1 root root 3.4K Aug 13 10:45 employees-schema-post.sql
-rw-r--r-- 1 root root 633K Aug 13 10:45 employees.employees.00008.sql
-rw-r--r-- 1 root root 634K Aug 13 10:45 employees.employees.00002.sql
-rw-r--r-- 1 root root 1.3M Aug 13 10:45 employees.employees.00006.sql
-rw-r--r-- 1 root root 1.9M Aug 13 10:45 employees.employees.00004.sql
-rw-r--r-- 1 root root 2.5M Aug 13 10:45 employees.employees.00000.sql
-rw-r--r-- 1 root root 2.5M Aug 13 10:45 employees.employees.00001.sql
-rw-r--r-- 1 root root 2.6M Aug 13 10:45 employees.employees.00005.sql
-rw-r--r-- 1 root root 2.6M Aug 13 10:45 employees.employees.00009.sql
-rw-r--r-- 1 root root 2.6M Aug 13 10:45 employees.employees.00010.sql
```

# 非阻塞备份

为了提供一致的备份，`mydumper`通过执行`FLUSH TABLES WITH READ LOCK`获取`GLOBAL LOCK`。

如果有任何长时间运行的事务（在第五章“事务”中解释）使用`FLUSH TABLES WITH READ LOCK`是多么危险。为了避免这种情况，您可以传递`--kill-long-queries`选项来杀死阻塞查询，而不是中止`mydumper`。

+   `--trx-consistency-only`：这相当于`mysqldump`的`--single-transaction`，但带有`binlog`位置。显然，此位置仅适用于事务表。使用此选项的优点之一是全局读锁仅用于线程协调，因此一旦事务开始，它就会被释放。

+   --use-savepoints 减少元数据锁定问题（需要`SUPER`权限）。

# 压缩备份

您可以指定`--compress`选项来压缩备份：

```sql
shell> mydumper -u root --password=<password> -B employees -T employees -t 8 --trx-consistency-only --compress --outputdir /backups/employees_compress
```

```sql
shell> ls -lhtr /backups/employees_compress
total 5.3M
-rw-r--r-- 1 root root 91 Aug 13 11:01 employees-schema-create.sql.gz
-rw-r--r-- 1 root root 263 Aug 13 11:01 employees.employees-schema.sql.gz
-rw-r--r-- 1 root root 75 Aug 13 11:01 metadata
-rw-r--r-- 1 root root 5.3M Aug 13 11:01 employees.employees.sql.gz
```

# 仅备份数据

您可以使用`--no-schemas`选项跳过模式并进行仅数据备份：

```sql
shell> mydumper -u root --password=<password> -B employees -T employees -t 8 --no-schemas --compress --trx-consistency-only --outputdir /backups/employees_data
```

# 使用平面文件进行备份

这是一种物理备份方法，通过直接复制`data directory`中的文件来进行备份。由于在复制文件时会写入新数据，因此备份将是不一致的，无法使用。为了避免这种情况，您必须关闭 MySQL，复制文件，然后启动 MySQL。这种方法不适用于日常备份，但在维护窗口期间进行升级、降级或进行主机交换时非常合适。

# 如何做...

1.  关闭 MySQL 服务器：

```sql
shell> sudo service mysqld stop
```

1.  将文件复制到`data directory`（您的目录可能不同）：

```sql
shell> sudo rsync -av /data/mysql /backups
or do rsync over ssh to remote server
shell> rsync -e ssh -az /data/mysql/ backup_user@remote_server:/backups
```

1.  启动 MySQL 服务器：

```sql
shell> sudo service mysqld start
```

# 使用 XtraBackup 进行备份

XtraBackup 是由 Percona 提供的开源备份软件。它在不关闭服务器的情况下复制平面文件，但为了避免不一致性，它使用重做日志文件。许多公司将其作为标准备份工具广泛使用。其优点是与逻辑备份工具相比非常快，恢复速度也非常快。

这是 Percona XtraBackup 的工作原理（摘自 Percona XtraBackup 文档）：

1.  它会复制您的`InnoDB`数据文件，这将导致数据在内部不一致；然后它会对文件执行崩溃恢复，使它们成为一致的可用数据库。

1.  这是因为`InnoDB`维护着一个重做日志，也称为事务日志。这包含了对`InnoDB`数据的每一次更改的记录。当`InnoDB`启动时，它会检查数据文件和事务日志，并执行两个步骤。它将已提交的事务日志条目应用于数据文件，并对修改数据但未提交的任何事务执行撤消操作。

1.  Percona XtraBackup 在启动时通过记住**日志序列号**（**LSN**）来工作，然后复制数据文件。这需要一些时间，因此如果文件在更改，则它们反映了数据库在不同时间点的状态。同时，Percona XtraBackup 运行一个后台进程，监视事务日志文件，并从中复制更改。Percona XtraBackup 需要不断执行此操作，因为事务日志是以循环方式写入的，并且一段时间后可以被重用。自执行以来，Percona XtraBackup 需要事务日志记录，以获取自开始执行以来对数据文件的每次更改。

# 如何做...

在撰写本文时，Percona XtraBackup 不支持 MySQL 8。最终，Percona 将发布支持 MySQL 8 的新版本 XtraBackup；因此只涵盖了安装部分。

# 安装

安装步骤在以下部分中。 

# 在 CentOS/Red Hat/Fedora 上

1.  安装`mysql-community-libs-compat`：

```sql
shell> sudo yum install -y mysql-community-libs-compat
```

1.  安装 Percona 存储库：

```sql
shell> sudo yum install http://www.percona.com/downloads/percona-release/redhat/0.1-4/percona-release-0.1-4.noarch.rpm
```

您应该看到以下输出：

```sql
Retrieving http://www.percona.com/downloads/percona-release/redhat/0.1-4/percona-release-0.1-4.noarch.rpm
Preparing...                ########################################### [100%]
   1:percona-release        ########################################### [100%]
```

1.  测试存储库：

```sql
shell> yum list | grep xtrabackup
holland-xtrabackup.noarch 1.0.14-3.el7 epel 
percona-xtrabackup.x86_64 2.3.9-1.el7 percona-release-x86_64
percona-xtrabackup-22.x86_64 2.2.13-1.el7 percona-release-x86_64
percona-xtrabackup-22-debuginfo.x86_64 2.2.13-1.el7 percona-release-x86_64
percona-xtrabackup-24.x86_64 2.4.8-1.el7 percona-release-x86_64
percona-xtrabackup-24-debuginfo.x86_64 2.4.8-1.el7 percona-release-x86_64
percona-xtrabackup-debuginfo.x86_64 2.3.9-1.el7 percona-release-x86_64
percona-xtrabackup-test.x86_64 2.3.9-1.el7 percona-release-x86_64
percona-xtrabackup-test-22.x86_64 2.2.13-1.el7 percona-release-x86_64
percona-xtrabackup-test-24.x86_64 2.4.8-1.el7 percona-release-x86_64
```

1.  安装 XtraBackup：

```sql
shell> sudo yum install percona-xtrabackup-24
```

# 在 Debian/Ubuntu 上

1.  从 Percona 获取存储库软件包：

```sql
shell> wget https://repo.percona.com/apt/percona-release_0.1-4.$(lsb_release -sc)_all.deb
```

1.  使用`dpkg`安装下载的软件包。为此，请以`root`或`sudo`身份运行以下命令：

```sql
shell> sudo dpkg -i percona-release_0.1-4.$(lsb_release -sc)_all.deb
```

安装此软件包后，应该添加 Percona 存储库。您可以在`/etc/apt/sources.list.d/percona-release.list`文件中检查存储库设置。

1.  记得更新本地缓存：

```sql
shell> sudo apt-get update
```

1.  之后，您可以安装软件包：

```sql
shell> sudo apt-get install percona-xtrabackup-24
```

# 锁定备份实例

从 MySQL 8 开始，您可以锁定实例以进行备份，这将允许在线备份期间进行 DML，并阻止可能导致不一致快照的所有操作。

# 如何做...

在开始备份之前，请锁定实例以进行备份：

```sql
mysql> LOCK INSTANCE FOR BACKUP;
```

执行备份，完成后解锁实例：

```sql
mysql> UNLOCK INSTANCE;
```

# 二进制日志备份

您知道二进制日志对于时点恢复是必需的。在本节中，您将了解如何备份二进制日志。该过程将二进制日志从数据库服务器流式传输到远程备份服务器。您可以从从服务器或主服务器中获取二进制日志备份。如果您从主服务器获取二进制日志备份，并且从从服务器获取实际备份，您应该使用`--dump-slave`来获取相应的主日志位置。如果您使用`mydumper`或 XtraBackup，它会提供主服务器和从服务器的二进制日志位置。

# 如何做到这一点...

1.  在服务器上创建一个复制用户。创建一个强密码：

```sql
mysql> GRANT REPLICATION SLAVE ON *.* TO 'binlog_user'@'%' IDENTIFIED BY 'binlog_pass';Query OK, 0 rows affected, 1 warning (0.03 sec)
```

1.  检查服务器上的二进制日志：

```sql
mysql> SHOW BINARY LOGS;+----------------+-----------+
| Log_name       | File_size |
+----------------+-----------+
| server1.000008 |      2451 |
| server1.000009 |       199 |
| server1.000010 |      1120 |
| server1.000011 |       471 |
| server1.000012 |       154 |
+----------------+-----------+
5 rows in set (0.00 sec)
```

您可以在服务器上找到第一个可用的二进制日志；从这里，您可以开始备份。在这种情况下，它是`server1.000008`。

1.  登录到备份服务器并执行以下命令。这将从 MySQL 服务器复制二进制日志到备份服务器。您可以开始使用`nohup`或`disown`：

```sql
shell> mysqlbinlog -u <user> -p<pass> -h <server> --read-from-remote-server --stop-never 
--to-last-log --raw server1.000008 &
shell> disown -a
```

1.  验证二进制日志是否已备份：

```sql
shell> ls -lhtr server1.0000*-rw-r-----. 1 mysql mysql 2.4K Aug 25 12:22 server1.000008
-rw-r-----. 1 mysql mysql  199 Aug 25 12:22 server1.000009
-rw-r-----. 1 mysql mysql 1.1K Aug 25 12:22 server1.000010
-rw-r-----. 1 mysql mysql  471 Aug 25 12:22 server1.000011
-rw-r-----. 1 mysql mysql  154 Aug 25 12:22 server1.000012 
```


# 第八章：恢复数据

在本章中，我们将介绍以下配方：

+   从 mysqldump 和 mysqlpump 中恢复

+   使用 myloader 从 mydumper 恢复

+   从平面文件备份中恢复

+   执行时间点恢复

# 介绍

在本章中，您将了解各种备份恢复方法。假设备份和二进制日志在服务器上可用。

# 从 mysqldump 和 mysqlpump 中恢复

逻辑备份工具`mysqldump`和`mysqlpump`将数据写入单个文件。

# 如何做...

登录到备份可用的服务器：

```sql
shell> cat /backups/full_backup.sql | mysql -u <user> -p
or
shell> mysql -u <user> -p < /backups/full_backup.sql
```

要在远程服务器上恢复，可以提到`-h <hostname>`选项：

```sql
shell> cat /backups/full_backup.sql | mysql -u <user> -p -h <remote_hostname>
```

在恢复备份时，备份语句将记录到二进制日志中，这可能会减慢恢复过程。如果不希望恢复过程写入二进制日志，可以在会话级别使用`SET SQL_LOG_BIN=0;`选项禁用它：

```sql
shell> (echo "SET SQL_LOG_BIN=0;";cat /backups/full_backup.sql) | mysql -u <user> -p -h <remote_hostname>
```

或使用：

```sql
mysql> SET SQL_LOG_BIN=0; SOURCE full_backup.sql
```

# 还有更多...

1.  由于备份恢复需要很长时间，建议在屏幕会话内启动恢复过程，以便即使失去与服务器的连接，恢复也将继续。

1.  有时，在恢复过程中可能会出现故障。如果将`--force`选项传递给 MySQL，恢复将继续：

```sql
shell> (echo "SET SQL_LOG_BIN=0;";cat /backups/full_backup.sql) | mysql -u <user> -p -h <remote_hostname> -f
```

# 使用 myloader 从 mydumper 恢复

`myloader`是用于使用`mydumper`获取的备份的多线程恢复的工具。 `myloader`与`mydumper`一起提供，您无需单独安装它。在本节中，您将学习恢复备份的各种方法。

# 如何做...

`myloader`的常见选项是要连接的 MySQL 服务器的主机名（默认值为`localhost`），用户名，密码和端口。

# 恢复完整数据库

```sql
shell> myloader --directory=/backups --user=<user> --password=<password> --queries-per-transaction=5000 --threads=8 --compress-protocol --overwrite-tables
```

选项解释如下：

+   `--overwrite-tables`：此选项如果表已经存在，则删除表

+   `--compress-protocol`：此选项在 MySQL 连接上使用压缩

+   `--threads`：此选项指定要使用的线程数；默认值为`4`

+   `--queries-per-transaction`：此选项指定每个事务的查询数；默认值为`1000`

+   `--directory`：指定要导入的转储目录

# 恢复单个数据库

您可以指定`--source-db <db_name>`仅恢复单个数据库。

假设您要恢复`company`数据库：

```sql
shell> myloader --directory=/backups --queries-per-transaction=5000 --threads=6 --compress-protocol --user=<user> --password=<password> --source-db company --overwrite-tables
```

# 恢复单个表

`mydumper`将每个表的备份写入单独的`.sql`文件。您可以拾取`.sql`文件并恢复：

```sql
shell> mysql -u <user> -p<password> -h <hostname> company -A -f < company.payments.sql
```

如果表被分成多个块，可以将所有块和与表相关的信息复制到一个目录中并指定位置。

复制所需的文件：

```sql
shell> sudo cp /backups/employee_table_chunks/employees.employees.* \
/backups/employee_table_chunks/employees.employees-schema.sql \
/backups/employee_table_chunks/employees-schema-create.sql \
/backups/employee_table_chunks/metadata \
/backups/single_table/
```

使用`myloader`进行加载；它将自动检测块并加载它们：

```sql
shell> myloader --directory=/backups/single_table/ --queries-per-transaction=50000 --threads=6 --compress-protocol --overwrite-tables
```

# 从平面文件备份中恢复

从平面文件恢复需要停止 MySQL 服务器，替换所有文件，更改权限，然后启动 MySQL。

# 如何做...

1.  停止 MySQL 服务器：

```sql
 shell> sudo systemctl stop mysql
```

1.  将文件移动到`数据目录`：

```sql
 shell> sudo mv /backup/mysql /var/lib
```

1.  更改所有权为`mysql`：

```sql
 shell> sudo chown -R mysql:mysql /var/lib/mysql
```

1.  启动 MySQL：

```sql
 shell> sudo systemctl start mysql
```

为了最小化停机时间，如果磁盘上有足够的空间，可以将备份复制到`/var/lib/mysql2`。然后停止 MySQL，重命名目录，然后启动服务器：

```sql
shell> sudo mv /backup/mysql /var/lib/mysql2
shell> sudo systemctl stop mysql
shell> sudo mv /var/lib/mysql2 /var/lib/mysql
shell> sudo chown -R mysql:mysql /var/lib/mysql
shell> sudo systemctl start mysql
```

# 执行时间点恢复

一旦完整备份恢复完成，您需要恢复二进制日志以进行时间点恢复。备份提供了直到备份可用的二进制日志坐标。

如第七章中所解释的，*备份*，在*锁定备份实例*部分，您应该根据`--dump-slave`或`--master-data`选项从正确的服务器选择二进制日志备份`mysqldump`。

# 如何做...

让我们深入了解如何做。这里有很多东西要学习。

# mysqldump 或 mysqlpump

二进制日志信息存储在 SQL 文件中，作为基于您传递给`mysqldump`/`mysqlpump`的选项的`CHANGE MASTER TO`命令。

1.  如果您使用了`--master-data`，您应该使用从服务器的二进制日志：

```sql
shell> head -30 /backups/dump.sql
-- MySQL dump 10.13  Distrib 8.0.3-rc, for Linux (x86_64)
--
-- Host: localhost    Database: 
-- ------------------------------------------------------
-- Server version 8.0.3-rc-log
/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!50606 SET @OLD_INNODB_STATS_AUTO_RECALC=@@INNODB_STATS_AUTO_RECALC */;
/*!50606 SET GLOBAL INNODB_STATS_AUTO_RECALC=OFF */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;
--
-- Position to start replication or point-in-time recovery from --
CHANGE MASTER TO MASTER_LOG_FILE='server1.000008', MASTER_LOG_POS=154;
```

在这种情况下，您应该从从服务器上位置`154`的`server1.000008`文件开始恢复。

```sql
shell> mysqlbinlog --start-position=154 --disable-log-bin /backups/binlogs/server1.000008 | mysql -u<user> -p -h <host> -f
```

1.  如果您使用了`--dump-slave`，您应该使用主服务器的二进制日志：

```sql
--
-- Position to start replication or point-in-time recovery from (the master of this slave)
--
CHANGE MASTER TO MASTER_LOG_FILE='centos7-bin.000001', MASTER_LOG_POS=463;
```

在这种情况下，您应该从主服务器上位置`463`的`centos7-bin.000001`文件开始恢复。

```sql
shell> mysqlbinlog --start-position=463  --disable-log-bin /backups/binlogs/centos7-bin.000001 | mysql -u<user> -p -h <host> -f
```

# mydumper

二进制日志信息可在元数据中找到。

```sql
shell> sudo cat /backups/metadata Started dump at: 2017-08-26 06:26:19
SHOW MASTER STATUS:
 Log: server1.000012
 Pos: 154
</span> GTID:
SHOW SLAVE STATUS:
 Host: 35.186.158.188
 Log: centos7-bin.000001
 Pos: 463
 GTID:
Finished dump at: 2017-08-26 06:26:24 
```

如果您已经从从服务器上获取了二进制日志备份，您应该从位置`154`的`server1.000012`文件开始恢复（`SHOW MASTER STATUS`）：

```sql
shell> mysqlbinlog --start-position=154  --disable-log-bin /backups/binlogs/server1.000012 | mysql -u<user> -p -h <host> -f
```

如果您从主服务器上有二进制日志备份，您应该从位置`463`的`centos7-bin.000001`文件开始恢复（`SHOW SLAVE STATUS`）：

```sql
shell> mysqlbinlog --start-position=463  --disable-log-bin /backups/binlogs/centos7-bin.000001 | mysql -u<user> -p -h <host> -f
```


# 第九章：复制

在这一章中，我们将涵盖以下内容：

+   设置复制

+   设置主-主复制

+   设置多源复制

+   设置复制过滤器

+   将从主-从复制切换到链式复制

+   将从链式复制切换到主-从复制

+   设置延迟复制

+   设置 GTID 复制

+   设置半同步复制

# 介绍

如第六章中所解释的，*二进制日志*，复制使得来自一个 MySQL 数据库服务器（主服务器）的数据被复制到一个或多个 MySQL 数据库服务器（从服务器）。复制默认是异步的；从服务器不需要永久连接以接收来自主服务器的更新。您可以配置复制所有数据库、选定的数据库，甚至是数据库中的选定表。

在这一章中，您将学习如何设置传统复制；复制选定的数据库和表；以及设置多源复制、链式复制、延迟复制和半同步复制。

在高层次上，复制的工作原理是这样的：在一个服务器上执行的所有 DDL 和 DML 语句（**主服务器**）都被记录到二进制日志中，这些日志被连接到它的服务器（称为**从服务器**）拉取。二进制日志简单地被复制到从服务器并保存为中继日志。这个过程由一个叫做**IO 线程**的线程来处理。还有一个叫做**SQL 线程**的线程，按顺序执行中继日志中的语句。

复制的工作原理在这篇博客中得到了很清楚的解释：

[`www.percona.com/blog/2013/01/09/how-does-mysql-replication-really-work/`](https://www.percona.com/blog/2013/01/09/how-does-mysql-replication-really-work/)

复制的优点（摘自手册，网址为[`dev.mysql.com/doc/refman/8.0/en/replication.html`](https://dev.mysql.com/doc/refman/8.0/en/replication.html)）：

+   **扩展解决方案**：将负载分散在多个从服务器上以提高性能。在这种环境中，所有的写入和更新必须在主服务器上进行。然而，读取可以在一个或多个从服务器上进行。这种模式可以提高写入的性能（因为主服务器专门用于更新），同时大大提高了在越来越多的从服务器上的读取速度。

+   **数据安全**：因为数据被复制到从服务器并且从服务器可以暂停复制过程，所以可以在从服务器上运行备份服务而不会破坏相应的主服务器数据。

+   **分析**：可以在主服务器上创建实时数据，而信息的分析可以在从服务器上进行，而不会影响主服务器的性能。

+   **远程数据分发**：您可以使用复制在远程站点创建数据的本地副本，而无需永久访问主服务器。

# 设置复制

有许多复制拓扑结构。其中一些是传统的主-从复制、链式复制、主-主复制、多源复制等。

**传统复制** 包括一个主服务器和多个从服务器。

![](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mysql8-cb/img/00005.jpeg)

**链式复制** 意味着一个服务器从另一个服务器复制，而另一个服务器又从另一个服务器复制。中间服务器被称为中继主服务器（主服务器 ---> 中继主服务器 ---> 从服务器）。

![](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mysql8-cb/img/00006.jpeg)

这主要用于当您想在两个数据中心之间设置复制时。主服务器和其从服务器将位于一个数据中心。次要主服务器（中继）从另一个数据中心的主服务器进行复制。另一个数据中心的所有从服务器都从次要主服务器进行复制。

**主-主复制**：在这种拓扑结构中，两个主服务器都接受写入并在彼此之间进行复制。

![](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mysql8-cb/img/00007.jpeg)

**多源复制**：在这种拓扑结构中，一个从服务器将从多个主服务器而不是一个主服务器进行复制。

![](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mysql8-cb/img/00008.jpeg)

如果要设置链式复制，可以按照此处提到的相同步骤进行，将主服务器替换为中继主服务器。

# 如何做...

在本节中，解释了单个从服务器的设置。相同的原则可以应用于设置链式复制。通常在设置另一个从服务器时，备份是从从服务器中获取的。

大纲：

1.  在主服务器上启用二进制日志记录

1.  在主服务器上创建一个复制用户

1.  在从服务器上设置唯一的`server_id`

1.  从主服务器备份

1.  在从服务器上恢复备份

1.  执行`CHANGE MASTER TO`命令

1.  开始复制

步骤：

1.  **在主服务器上**：在主服务器上启用二进制日志记录并设置`SERVER_ID`。参考第六章，*二进制日志记录*，了解如何启用二进制日志记录。

1.  **在主服务器上**：创建一个复制用户。从服务器使用这个帐户连接到主服务器：

```sql
mysql> GRANT REPLICATION SLAVE ON *.* TO 'binlog_user'@'%' IDENTIFIED BY 'binlog_P@ss12';Query OK, 0 rows affected, 1 warning (0.00 sec)
```

1.  **在从服务器上**：设置唯一的`SERVER_ID`选项（它应该与主服务器上设置的不同）：

```sql
mysql> SET @@GLOBAL.SERVER_ID = 32;
```

1.  **在从服务器上**：通过远程连接从主服务器备份。您可以使用`mysqldump`或`mydumper`。不能使用`mysqlpump`，因为二进制日志位置不一致。

`mysqldump`：

```sql
shell> mysqldump -h <master_host> -u backup_user --password=<pass> --all-databases --routines --events --single-transaction --master-data  > dump.sql

```

当从另一个从服务器备份时，您必须传递`--slave-dump`选项。`mydumper`：

```sql
shell> mydumper -h <master_host> -u backup_user --password=<pass> --use-savepoints  --trx-consistency-only --kill-long-queries --outputdir /backups
```

1.  **在从服务器上**：备份完成后，恢复备份。参考第八章，*恢复数据*，了解恢复方法。

`mysqldump`：

```sql
shell> mysql -u <user> -p -f < dump.sql
```

`mydumper`：

```sql
shell> myloader --directory=/backups --user=<user> --password=<password> --queries-per-transaction=5000 --threads=8 --overwrite-tables
```

1.  **在从服务器上**：在恢复备份后，您必须执行以下命令：

```sql
mysql> CHANGE MASTER TO MASTER_HOST='<master_host>', MASTER_USER='binlog_user', MASTER_PASSWORD='binlog_P@ss12', MASTER_LOG_FILE='<log_file_name>', MASTER_LOG_POS=<position>
```

`mysqldump`：备份转储文件中包含`<log_file_name>`和`<position>`。例如：

```sql
shell> less dump.sql
--
-- Position to start replication or point-in-time recovery from (the master of this slave)
--
CHANGE MASTER TO MASTER_LOG_FILE='centos7-bin.000001', MASTER_LOG_POS=463;
```

`mydumper`：`<log_file_name>`和`<position>`存储在元数据文件中：

```sql
shell> cat metadata
Started dump at: 2017-08-26 06:26:19
SHOW MASTER STATUS:
    Log: server1.000012
    Pos: 154122
    GTID:
SHOW SLAVE STATUS:
    Host: xx.xxx.xxx.xxx
    Log: centos7-bin.000001
    Pos: 463223
    GTID:
Finished dump at: 2017-08-26 06:26:24
```

如果您从一个从服务器或主服务器备份以设置另一个从服务器，您必须使用`SHOW SLAVE STATUS`中的位置。如果要设置链式复制，可以使用`SHOW MASTER STATUS`中的位置。

1.  在从服务器上，执行`START SLAVE`命令：

```sql
mysql> START SLAVE;
```

1.  您可以通过执行以下命令来检查复制的状态：

```sql
mysql> SHOW SLAVE STATUS\G
*************************** 1\. row ***************************
 Slave_IO_State: Waiting for master to send event
                  Master_Host: xx.xxx.xxx.xxx
                  Master_User: binlog_user
                  Master_Port: 3306
                Connect_Retry: 60
              Master_Log_File: server1-bin.000001
          Read_Master_Log_Pos: 463
               Relay_Log_File: server2-relay-bin.000004
                Relay_Log_Pos: 322
        Relay_Master_Log_File: server1-bin.000001
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
          Exec_Master_Log_Pos: 463
              Relay_Log_Space: 1957
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
  Replicate_Ignore_Server_Ids: 
             Master_Server_Id: 32
                  Master_UUID: b52ef45a-7ff4-11e7-9091-42010a940003
             Master_Info_File: /var/lib/mysql/master.info
                    SQL_Delay: 0
          SQL_Remaining_Delay: NULL
      Slave_SQL_Running_State: Slave has read all relay log; waiting for more updates
           Master_Retry_Count: 86400
                  Master_Bind: 
      Last_IO_Error_Timestamp: 
     Last_SQL_Error_Timestamp: 
               Master_SSL_Crl: 
           Master_SSL_Crlpath: 
           Retrieved_Gtid_Set: 
            Executed_Gtid_Set: 
                Auto_Position: 0
         Replicate_Rewrite_DB: 
                 Channel_Name: 
           Master_TLS_Version: 
1 row in set (0.00 sec)
```

您应该查找`Seconds_Behind_Master`，它显示了复制的延迟。如果是`0`，表示从服务器与主服务器同步；任何非零值表示延迟的秒数，如果是`NULL`，表示复制没有发生。

# 设置主-主复制

这个教程会吸引很多人，因为我们中的许多人都尝试过这样做。让我们深入了解一下。

# 如何做...

假设主服务器是`master1`和`master2`。

步骤：

1.  按照第九章*复制*中描述的方法在`master1`和`master2`之间设置复制。

1.  使`master2`成为只读：

```sql
mysql> SET @@GLOBAL.READ_ONLY=ON;
```

1.  在`master2`上，检查当前的二进制日志坐标。

```sql
mysql> SHOW MASTER STATUS;
+----------------+----------+--------------+------------------+-------------------+
| File           | Position | Binlog_Do_DB | Binlog_Ignore_DB | Executed_Gtid_Set |
+----------------+----------+--------------+------------------+-------------------+
| server1.000017 |      473 |              |                  |                   |
+----------------+----------+--------------+------------------+-------------------+
1 row in set (0.00 sec)
```

从前面的输出中，您可以从`server1.000017`和位置`473`开始在`master1`上启动复制。

1.  根据前面步骤中的位置，在`master1`上执行`CHANGE MASTER TO`命令：

```sql
mysql> CHANGE MASTER TO MASTER_HOST='<master2_host>', MASTER_USER='binlog_user', MASTER_PASSWORD='binlog_P@ss12', MASTER_LOG_FILE='<log_file_name>', MASTER_LOG_POS=<position>
```

1.  在`master1`上启动从服务器：

```sql
mysql> START SLAVE;
```

1.  最后，您可以使`master2`成为读写，应用程序可以开始向其写入。

```sql
 mysql> SET @@GLOBAL.READ_ONLY=OFF;
```

# 设置多源复制

MySQL 多源复制使得复制从服务器能够同时接收来自多个源的事务。多源复制可用于将多个服务器备份到单个服务器，合并表分片，并将来自多个服务器的数据合并到单个服务器。多源复制在应用事务时不实现任何冲突检测或解决，如果需要，这些任务将留给应用程序。在多源复制拓扑中，从服务器为应该接收事务的每个主服务器创建一个复制通道。

在本节中，您将学习如何设置具有多个主服务器的从服务器。这种方法与在通道上设置传统复制相同。

# 如何做...

假设您要将`server3`设置为`server1`和`server2`的从服务器。您需要从`server1`到`server3`创建传统复制通道，并从`server2`到`server3`创建另一个通道。为了确保从服务器上的数据一致，请确保复制不同的数据库集或应用程序处理冲突。

开始之前，请从 server1 备份并在`server3`上恢复；类似地，从`server2`备份并在`server3`上恢复，如第九章“复制”中所述。

1.  在`server3`上，将复制存储库从`FILE`修改为`TABLE`。您可以通过运行以下命令动态更改它：

```sql
mysql> STOP SLAVE; //If slave is already running
mysql> SET GLOBAL master_info_repository = 'TABLE';
mysql> SET GLOBAL relay_log_info_repository = 'TABLE';
```

还要更改配置文件：

```sql
shell> sudo vi /etc/my.cnf
[mysqld]
master-info-repository=TABLE 
relay-log-info-repository=TABLE
```

1.  在`server3`上，执行`CHANGE MASTER TO`命令，使其成为`server1`的从服务器，通道名为`master-1`。您可以随意命名：

```sql
mysql> CHANGE MASTER TO MASTER_HOST='server1', MASTER_USER='binlog_user', MASTER_PORT=3306, MASTER_PASSWORD='binlog_P@ss12', MASTER_LOG_FILE='server1.000017', MASTER_LOG_POS=788 FOR CHANNEL 'master-1';
```

1.  在`server3`上，执行`CHANGE MASTER TO`命令，使其成为`server2`的从服务器，通道为`master-2`：

```sql
mysql> CHANGE MASTER TO MASTER_HOST='server2', MASTER_USER='binlog_user', MASTER_PORT=3306, MASTER_PASSWORD='binlog_P@ss12', MASTER_LOG_FILE='server2.000014', MASTER_LOG_POS=75438 FOR CHANNEL 'master-2';
```

1.  对于每个通道，执行`START SLAVE FOR CHANNEL`语句如下：

```sql
mysql> START SLAVE FOR CHANNEL 'master-1';
Query OK, 0 rows affected (0.01 sec)

mysql> START SLAVE FOR CHANNEL 'master-2';
Query OK, 0 rows affected (0.00 sec)
```

1.  通过执行`SHOW SLAVE STATUS`语句验证从服务器的状态：

```sql
mysql> SHOW SLAVE STATUS\G
*************************** 1\. row ***************************
               Slave_IO_State: Waiting for master to send event
                  Master_Host: server1
                  Master_User: binlog_user
                  Master_Port: 3306
                Connect_Retry: 60
              Master_Log_File: server1.000017
          Read_Master_Log_Pos: 788
               Relay_Log_File: server3-relay-bin-master@002d1.000002
                Relay_Log_Pos: 318
        Relay_Master_Log_File: server1.000017
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
          Exec_Master_Log_Pos: 788
              Relay_Log_Space: 540
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
  Replicate_Ignore_Server_Ids: 
             Master_Server_Id: 32
                  Master_UUID: 7cc7fca7-4deb-11e7-a53e-42010a940002
             Master_Info_File: mysql.slave_master_info
                    SQL_Delay: 0
          SQL_Remaining_Delay: NULL
      Slave_SQL_Running_State: Slave has read all relay log; waiting for more updates
           Master_Retry_Count: 86400
                  Master_Bind: 
      Last_IO_Error_Timestamp: 
     Last_SQL_Error_Timestamp: 
               Master_SSL_Crl: 
           Master_SSL_Crlpath: 
           Retrieved_Gtid_Set: 
            Executed_Gtid_Set: 
                Auto_Position: 0
         Replicate_Rewrite_DB: 
                 Channel_Name: master-1
           Master_TLS_Version: 
*************************** 2\. row ***************************
               Slave_IO_State: Waiting for master to send event
                  Master_Host: server2
                  Master_User: binlog_user
                  Master_Port: 3306
                Connect_Retry: 60
              Master_Log_File: server2.000014
          Read_Master_Log_Pos: 75438
               Relay_Log_File: server3-relay-bin-master@002d2.000002
                Relay_Log_Pos: 322
        Relay_Master_Log_File: server2.000014
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
          Exec_Master_Log_Pos: 75438
              Relay_Log_Space: 544
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
  Replicate_Ignore_Server_Ids: 
             Master_Server_Id: 32
                  Master_UUID: b52ef45a-7ff4-11e7-9091-42010a940003
             Master_Info_File: mysql.slave_master_info
                    SQL_Delay: 0
          SQL_Remaining_Delay: NULL
      Slave_SQL_Running_State: Slave has read all relay log; waiting for more updates
           Master_Retry_Count: 86400
                  Master_Bind: 
      Last_IO_Error_Timestamp: 
     Last_SQL_Error_Timestamp: 
               Master_SSL_Crl: 
           Master_SSL_Crlpath: 
           Retrieved_Gtid_Set: 
            Executed_Gtid_Set: 
                Auto_Position: 0
         Replicate_Rewrite_DB: 
                 Channel_Name: master-2
           Master_TLS_Version: 
2 rows in set (0.00 sec)
```

1.  要获取特定通道的从服务器状态，请执行：

```sql
mysql> SHOW SLAVE STATUS FOR CHANNEL 'master-1' \G
```

1.  这是您可以使用性能模式监视指标的另一种方法：

```sql
mysql> SELECT * FROM performance_schema.replication_connection_status\G
*************************** 1\. row ***************************
                                      CHANNEL_NAME: master-1
                                        GROUP_NAME: 
                                       SOURCE_UUID: 7cc7fca7-4deb-11e7-a53e-42010a940002
                                         THREAD_ID: 36
                                     SERVICE_STATE: ON
                         COUNT_RECEIVED_HEARTBEATS: 73
                          LAST_HEARTBEAT_TIMESTAMP: 2017-09-15 12:42:10.910051
                          RECEIVED_TRANSACTION_SET: 
                                 LAST_ERROR_NUMBER: 0
                                LAST_ERROR_MESSAGE: 
                              LAST_ERROR_TIMESTAMP: 0000-00-00 00:00:00.000000
                           LAST_QUEUED_TRANSACTION: 
 LAST_QUEUED_TRANSACTION_ORIGINAL_COMMIT_TIMESTAMP: 0000-00-00 00:00:00.000000
LAST_QUEUED_TRANSACTION_IMMEDIATE_COMMIT_TIMESTAMP: 0000-00-00 00:00:00.000000
     LAST_QUEUED_TRANSACTION_START_QUEUE_TIMESTAMP: 0000-00-00 00:00:00.000000
       LAST_QUEUED_TRANSACTION_END_QUEUE_TIMESTAMP: 0000-00-00 00:00:00.000000
                              QUEUEING_TRANSACTION: 
    QUEUEING_TRANSACTION_ORIGINAL_COMMIT_TIMESTAMP: 0000-00-00 00:00:00.000000
   QUEUEING_TRANSACTION_IMMEDIATE_COMMIT_TIMESTAMP: 0000-00-00 00:00:00.000000
        QUEUEING_TRANSACTION_START_QUEUE_TIMESTAMP: 0000-00-00 00:00:00.000000
*************************** 2\. row ***************************
                                      CHANNEL_NAME: master-2
                                        GROUP_NAME: 
                                       SOURCE_UUID: b52ef45a-7ff4-11e7-9091-42010a940003
                                         THREAD_ID: 38
                                     SERVICE_STATE: ON
                         COUNT_RECEIVED_HEARTBEATS: 73
                          LAST_HEARTBEAT_TIMESTAMP: 2017-09-15 12:42:13.986271
                          RECEIVED_TRANSACTION_SET: 
                                 LAST_ERROR_NUMBER: 0
                                LAST_ERROR_MESSAGE: 
                              LAST_ERROR_TIMESTAMP: 0000-00-00 00:00:00.000000
                           LAST_QUEUED_TRANSACTION: 
 LAST_QUEUED_TRANSACTION_ORIGINAL_COMMIT_TIMESTAMP: 0000-00-00 00:00:00.000000
LAST_QUEUED_TRANSACTION_IMMEDIATE_COMMIT_TIMESTAMP: 0000-00-00 00:00:00.000000
     LAST_QUEUED_TRANSACTION_START_QUEUE_TIMESTAMP: 0000-00-00 00:00:00.000000
       LAST_QUEUED_TRANSACTION_END_QUEUE_TIMESTAMP: 0000-00-00 00:00:00.000000
                              QUEUEING_TRANSACTION: 
    QUEUEING_TRANSACTION_ORIGINAL_COMMIT_TIMESTAMP: 0000-00-00 00:00:00.000000
   QUEUEING_TRANSACTION_IMMEDIATE_COMMIT_TIMESTAMP: 0000-00-00 00:00:00.000000
        QUEUEING_TRANSACTION_START_QUEUE_TIMESTAMP: 0000-00-00 00:00:00.000000
2 rows in set (0.00 sec)
```

您可以通过附加`FOR CHANNEL 'channel_name'`指定通道的所有与从服务器相关的命令：

```sql
mysql> STOP SLAVE FOR CHANNEL 'master-1';
mysql> RESET SLAVE FOR CHANNEL 'master-2';
```

# 设置复制过滤器

您可以控制要复制的表或数据库。在主服务器上，您可以使用`--binlog-do-db`和`--binlog-ignore-db`选项控制要为其记录更改的数据库，如第六章“二进制日志”中所述。更好的方法是在从服务器端进行控制。您可以使用`--replicate-*`选项或通过创建复制过滤器动态地执行或忽略从主服务器接收的语句。

# 如何做...

要创建过滤器，您需要执行`CHANGE REPLICATION FILTER`语句。

# 仅复制数据库

假设您只想复制`db1`和`db2`。使用以下语句创建复制过滤器。

```sql
mysql> CHANGE REPLICATION FILTER REPLICATE_DO_DB = (db1, db2);
```

请注意，您应该在括号内指定所有数据库。

# 复制特定表

您可以使用`REPLICATE_DO_TABLE`指定要复制的表：

```sql
mysql> CHANGE REPLICATION FILTER REPLICATE_DO_TABLE = ('db1.table1'); 
```

假设您想要对表使用正则表达式；您可以使用`REPLICATE_WILD_DO_TABLE`选项：

```sql
mysql> CHANGE REPLICATION FILTER REPLICATE_WILD_DO_TABLE = ('db1.imp%'); 
```

您可以使用各种`IGNORE`选项使用正则表达式提及一些数据库或表。

# 忽略数据库

就像您可以选择复制数据库一样，您可以使用`REPLICATE_IGNORE_DB`忽略复制中的数据库：

```sql
mysql> CHANGE REPLICATION FILTER REPLICATE_IGNORE_DB = (db1, db2);
```

# 忽略特定表

您可以使用`REPLICATE_IGNORE_TABLE`和`REPLICATE_WILD_IGNORE_TABLE`选项忽略某些表。`REPLICATE_WILD_IGNORE_TABLE`选项允许使用通配符字符，而`REPLICATE_IGNORE_TABLE`仅接受完整的表名：

```sql
mysql> CHANGE REPLICATION FILTER REPLICATE_IGNORE_TABLE = ('db1.table1'); 
mysql> CHANGE REPLICATION FILTER REPLICATE_WILD_IGNORE_TABLE = ('db1.new%', 'db2.new%'); 
```

您还可以通过指定通道名称为通道设置过滤器：

```sql
mysql> CHANGE REPLICATION FILTER REPLICATE_DO_DB = (d1) FOR CHANNEL 'master-1';
```

# 另请参阅

有关复制过滤器的更多详细信息，请参阅[`dev.mysql.com/doc/refman/8.0/en/change-replication-filter.html`](https://dev.mysql.com/doc/refman/8.0/en/change-replication-filter.html)。如果您使用多个过滤器，请参阅[`dev.mysql.com/doc/refman/8.0/en/replication-rules.html`](https://dev.mysql.com/doc/refman/8.0/en/replication-rules.html)以了解有关 MySQL 如何评估过滤器的更多信息。

# 将从主从复制切换到链式复制

如果您设置了主从复制，服务器 B 和 C 从服务器 A 复制：服务器 A -->（服务器 B，服务器 C），并且您希望将服务器 C 设置为服务器 B 的从服务器，则必须在服务器 B 和服务器 C 上停止复制。然后使用`START SLAVE UNTIL`命令将它们带到相同的主日志位置。之后，您可以从服务器 B 获取主日志坐标，并在服务器 C 上执行`CHANGE MASTER TO`命令。

# 如何做...

1.  **在服务器 C 上**：停止从服务器并注意`SHOW SLAVE STATUS\G`命令中的`Relay_Master_Log_File`和`Exec_Master_Log_Pos`位置：

```sql
mysql> STOP SLAVE;
Query OK, 0 rows affected (0.01 sec)

mysql> SHOW SLAVE STATUS\G
*************************** 1\. row ***************************
               Slave_IO_State: 
                  Master_Host: xx.xxx.xxx.xxx
                  Master_User: binlog_user
                  Master_Port: 3306
                Connect_Retry: 60
              Master_Log_File: server_A-bin.000023
          Read_Master_Log_Pos: 2604
               Relay_Log_File: server_C-relay-bin.000002
                Relay_Log_Pos: 1228
 Relay_Master_Log_File: server_A-bin.000023
~
 Exec_Master_Log_Pos: 2604
              Relay_Log_Space: 1437
              Until_Condition: None
               Until_Log_File: 
                Until_Log_Pos: 0
~
1 row in set (0.00 sec)
```

1.  **在服务器 B 上**：停止从服务器并注意`SHOW SLAVE STATUS\G`命令中的`Relay_Master_Log_File`和`Exec_Master_Log_Pos`位置：

```sql
mysql> STOP SLAVE;
Query OK, 0 rows affected (0.01 sec)

mysql> SHOW SLAVE STATUS\G
*************************** 1\. row ***************************
               Slave_IO_State: 
                  Master_Host: xx.xxx.xxx.xxx
                  Master_User: binlog_user
                  Master_Port: 3306
                Connect_Retry: 60
              Master_Log_File: server_A-bin.000023
          Read_Master_Log_Pos: 8250241
               Relay_Log_File: server_B-relay-bin.000002
                Relay_Log_Pos: 1228
 Relay_Master_Log_File: server_A-bin.000023
~
 Exec_Master_Log_Pos: 8250241
              Relay_Log_Space: 8248167
              Until_Condition: None
               Until_Log_File: 
                Until_Log_Pos: 0
~
1 row in set (0.00 sec)
```

1.  比较服务器 B 的日志位置和服务器 C，找出与服务器 A 最新的同步。通常，由于您首先在服务器 C 上停止了从服务器，服务器 B 将领先。在我们的情况下，日志位置是：

服务器 C：（`server_A-bin.000023`，`2604`）

服务器 B：（`server_A-bin.000023`，`8250241`）

服务器 B 领先，所以我们必须将服务器 C 带到服务器 B 的位置。

1.  **在服务器 C 上**：使用`START SLAVE UNTIL`语句同步到服务器 B 的位置：

```sql
mysql> START SLAVE UNTIL MASTER_LOG_FILE='centos7-bin.000023', MASTER_LOG_POS=8250241;
Query OK, 0 rows affected, 1 warning (0.03 sec)

mysql> SHOW WARNINGS\G
*************************** 1\. row ***************************
  Level: Note
   Code: 1278
Message: It is recommended to use --skip-slave-start when doing step-by-step replication with START SLAVE UNTIL; otherwise, you will get problems if you get an unexpected slave's mysqld restart
1 row in set (0.00 sec)
```

1.  **在服务器 C 上**：等待服务器 C 追上，通过检查`SHOW SLAVE STATUS`输出中的`Exec_Master_Log_Pos`和`Until_Log_Pos`（两者应该相同）：

```sql
mysql> SHOW SLAVE STATUS\G
*************************** 1\. row ***************************
               Slave_IO_State: Waiting for master to send event
                  Master_Host: xx.xxx.xxx.xxx
                  Master_User: binlog_user
                  Master_Port: 3306
                Connect_Retry: 60
              Master_Log_File: server_A-bin.000023
          Read_Master_Log_Pos: 8250241
               Relay_Log_File: server_C-relay-bin.000003
                Relay_Log_Pos: 8247959
        Relay_Master_Log_File: server_A-bin.000023
             Slave_IO_Running: Yes
            Slave_SQL_Running: No
~
                   Last_Errno: 0
                   Last_Error: 
                 Skip_Counter: 0
 Exec_Master_Log_Pos: 8250241
              Relay_Log_Space: 8249242
              Until_Condition: Master
               Until_Log_File: server_A-bin.000023
 Until_Log_Pos: 8250241
           Master_SSL_Allowed: No
           Master_SSL_CA_File: 
           Master_SSL_CA_Path: 
              Master_SSL_Cert: 
            Master_SSL_Cipher: 
               Master_SSL_Key: 
 Seconds_Behind_Master: NULL
~
1 row in set (0.00 sec)
```

1.  **在服务器 B 上**：查找主状态，启动从服务器，并确保它正在复制：

```sql
mysql> SHOW MASTER STATUS;
+---------------------+----------+--------------+------------------+-------------------+
| File                | Position | Binlog_Do_DB | Binlog_Ignore_DB | Executed_Gtid_Set |
+---------------------+----------+--------------+------------------+-------------------+
| server_B-bin.000003 | 36379324 |              |                  |                   |
+---------------------+----------+--------------+------------------+-------------------+
1 row in set (0.00 sec)

mysql> START SLAVE;
Query OK, 0 rows affected (0.02 sec)

mysql> SHOW SLAVE STATUS\G
*************************** 1\. row ***************************
               Slave_IO_State: 
                  Master_Host: xx.xxx.xxx.xxx
                  Master_User: binlog_user
                  Master_Port: 3306
                Connect_Retry: 60
              Master_Log_File: server_A-bin.000023
          Read_Master_Log_Pos: 8250241
               Relay_Log_File: server_B-relay-bin.000002
                Relay_Log_Pos: 1228
 Relay_Master_Log_File: server_A-bin.000023
~
 Exec_Master_Log_Pos: 8250241
              Relay_Log_Space: 8248167
              Until_Condition: None
               Until_Log_File: 
                Until_Log_Pos: 0
~
1 row in set (0.00 sec)
```

1.  **在服务器 C 上**：停止从服务器，执行`CHANGE MASTER TO`命令，并指向服务器 B。您必须使用从上一步中获得的位置：

```sql
mysql> STOP SLAVE;
Query OK, 0 rows affected (0.04 sec)

mysql> CHANGE MASTER TO MASTER_HOST = 'Server B', MASTER_USER = 'binlog_user', MASTER_PASSWORD = 'binlog_P@ss12', MASTER_LOG_FILE='server_B-bin.000003', MASTER_LOG_POS=36379324;
Query OK, 0 rows affected, 1 warning (0.04 sec)
```

1.  **在服务器 C 上**：启动复制并验证从服务器状态：

```sql
mysql> START SLAVE;
Query OK, 0 rows affected (0.00 sec)

mysql> SHOW SLAVE STATUS\G
Query OK, 0 rows affected, 1 warning (0.00 sec)

*************************** 1\. row ***************************
               Slave_IO_State: Waiting for master to send event
                  Master_Host: xx.xxx.xxx.xx
                  Master_User: binlog_user
                  Master_Port: 3306
                Connect_Retry: 60
              Master_Log_File: server_B-bin.000003
          Read_Master_Log_Pos: 36380416
               Relay_Log_File: server_C-relay-bin.000002
                Relay_Log_Pos: 1413
        Relay_Master_Log_File: server_B-bin.000003
             Slave_IO_Running: Yes
            Slave_SQL_Running: Yes
 ~
          Exec_Master_Log_Pos: 36380416
              Relay_Log_Space: 1622
 ~
        Seconds_Behind_Master: 0
Master_SSL_Verify_Server_Cert: No
                Last_IO_Errno: 0
                Last_IO_Error: 
               Last_SQL_Errno: 0
               Last_SQL_Error: 
  Replicate_Ignore_Server_Ids: 
~
1 row in set (0.00 sec)
```

# 将从链式复制切换为主从复制

如果您设置了链式复制（例如服务器 A --> 服务器 B --> 服务器 C）并且希望使服务器 C 成为服务器 A 的直接从服务器，则必须在服务器 B 上停止复制，让服务器 C 追上服务器 B，然后找到服务器 A 对应于服务器 B 停止位置的坐标。使用这些坐标，您可以在服务器 C 上执行`CHANGE MASTER TO`命令，并使其成为服务器 A 的从服务器。

# 如何做...

1.  **在服务器 B 上**：停止从服务器并记录主状态：

```sql
mysql> STOP SLAVE;
Query OK, 0 rows affected (0.04 sec)

mysql> SHOW MASTER STATUS;
+---------------------+----------+--------------+------------------+-------------------+
| File                | Position | Binlog_Do_DB | Binlog_Ignore_DB | Executed_Gtid_Set |
+---------------------+----------+--------------+------------------+-------------------+
| server_B-bin.000003 | 44627878 |              |                  |                   |
+---------------------+----------+--------------+------------------+-------------------+
1 row in set (0.00 sec)
```

1.  **在服务器 C 上**：确保从服务器延迟已经追上。`Relay_Master_Log_File`和`Exec_Master_Log_Pos`应该等于服务器 B 上主状态的输出。一旦延迟追上，停止从服务器：

```sql
mysql> SHOW SLAVE STATUS\G
*************************** 1\. row ***************************
               Slave_IO_State: Waiting for master to send event
                  Master_Host: 35.186.157.16
                  Master_User: repl
                  Master_Port: 3306
                Connect_Retry: 60
              Master_Log_File: server_B-bin.000003
          Read_Master_Log_Pos: 44627878
               Relay_Log_File: ubuntu2-relay-bin.000002
                Relay_Log_Pos: 8248875
 Relay_Master_Log_File: server_B-bin.000003
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
 Exec_Master_Log_Pos: 44627878
              Relay_Log_Space: 8249084
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
~
1 row in set (0.00 sec)
```

```sql
mysql> STOP SLAVE;
Query OK, 0 rows affected (0.01 sec)
```

1.  **在服务器 B 上**：从`SHOW SLAVE STATUS`输出中获取服务器 A 的坐标（注意`Relay_Master_Log_File`和`Exec_Master_Log_Pos`）并启动从服务器：

```sql
mysql> SHOW SLAVE STATUS\G
*************************** 1\. row ***************************
               Slave_IO_State: 
                  Master_Host: xx.xxx.xxx.xxx
                  Master_User: repl
                  Master_Port: 3306
                Connect_Retry: 60
              Master_Log_File: server_A-bin.000023
          Read_Master_Log_Pos: 16497695
               Relay_Log_File: server_B-relay-bin.000004
                Relay_Log_Pos: 8247776
 Relay_Master_Log_File: server_A-bin.000023
             Slave_IO_Running: No
            Slave_SQL_Running: No
              Replicate_Do_DB: 
          Replicate_Ignore_DB: 
           Replicate_Do_Table: 
       Replicate_Ignore_Table: 
      Replicate_Wild_Do_Table: 
  Replicate_Wild_Ignore_Table: 
                   Last_Errno: 0
                   Last_Error: 
                 Skip_Counter: 0
 Exec_Master_Log_Pos: 16497695
              Relay_Log_Space: 8248152
              Until_Condition: None
               Until_Log_File: 
                Until_Log_Pos: 0
           Master_SSL_Allowed: No
           Master_SSL_CA_File: 
           Master_SSL_CA_Path: 
              Master_SSL_Cert: 
            Master_SSL_Cipher: 
               Master_SSL_Key: 
        Seconds_Behind_Master: NULL
```

```sql
mysql> START SLAVE;
Query OK, 0 rows affected (0.01 sec)
```

1.  **在服务器 C 上**：停止从服务器并执行`CHANGE MASTER TO COMMAND`指向服务器 A。使用从上一步中记录的位置（`server_A-bin.000023`和`16497695`）。最后启动从服务器并验证从服务器状态：

```sql
mysql> STOP SLAVE;
Query OK, 0 rows affected (0.07 sec)
```

```sql
mysql> CHANGE MASTER TO MASTER_HOST = 'Server A', MASTER_USER = 'binlog_user', MASTER_PASSWORD = 'binlog_P@ss12', MASTER_LOG_FILE='server_A-bin.000023', MASTER_LOG_POS=16497695;
Query OK, 0 rows affected, 1 warning (0.02 sec)
```

```sql
mysql> START SLAVE;
Query OK, 0 rows affected (0.07 sec)

mysql> SHOW SLAVE STATUS\G
*************************** 1\. row ***************************
               Slave_IO_State: 
                  Master_Host: xx.xxx.xxx.xxx
                  Master_User: binlog_user
                  Master_Port: 3306
                Connect_Retry: 60
              Master_Log_File: server_A-bin.000023
          Read_Master_Log_Pos: 16497695
               Relay_Log_File: server_C-relay-bin.000001
                Relay_Log_Pos: 4
        Relay_Master_Log_File: server_A-bin.000023
             Slave_IO_Running: No
            Slave_SQL_Running: No
  ~
                 Skip_Counter: 0
          Exec_Master_Log_Pos: 16497695
              Relay_Log_Space: 154
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
~
1 row in set (0.00 sec)
```

# 设置延迟复制

有时，您需要一个延迟的从服务器用于灾难恢复目的。假设主服务器上执行了灾难性语句（如`DROP DATABASE`命令）。您必须使用备份的*时间点恢复*来恢复数据库。这将导致巨大的停机时间，具体取决于数据库的大小。为了避免这种情况，您可以使用延迟的从服务器，它将始终比主服务器延迟一定的时间。如果发生灾难并且该语句未被延迟的从服务器应用，您可以停止从服务器并启动直到灾难性语句，以便灾难性语句不会被执行。然后将其提升为主服务器。

该过程与设置正常复制完全相同，只是在`CHANGE MASTER TO`命令中指定`MASTER_DELAY`。

**延迟是如何衡量的？**

在 MySQL 8.0 之前的版本中，延迟是基于`Seconds_Behind_Master`值来衡量的。在 MySQL 8.0 中，它是基于`original_commit_timestamp`和`immediate_commit_timestamp`来衡量的，这些值写入了二进制日志。

`original_commit_timestamp`是事务写入（提交）到原始主服务器的二进制日志时距离时代开始的微秒数。

`immediate_commit_timestamp`是事务写入（提交）到直接主服务器的二进制日志时距离时代开始的微秒数。

# 如何做...

1.  停止从服务器：

```sql
mysql> STOP SLAVE;
Query OK, 0 rows affected (0.06 sec)
```

1.  执行`CHANGE MASTER TO MASTER_DELAY =`并启动从服务器。假设您想要 1 小时的延迟，您可以将`MASTER_DELAY`设置为`3600`秒：

```sql
mysql> CHANGE MASTER TO MASTER_DELAY = 3600;
Query OK, 0 rows affected (0.04 sec)

mysql> START SLAVE;
Query OK, 0 rows affected (0.00 sec)
```

1.  在从服务器状态中检查以下内容：

`SQL_Delay`: 从服务器必须滞后主服务器的秒数。

`SQL_Remaining_Delay`: 延迟剩余的秒数。当存在延迟时，此值为 NULL。

`Slave_SQL_Running_State`: SQL 线程的状态。

```sql
mysql> SHOW SLAVE STATUS\G
*************************** 1\. row ***************************
               Slave_IO_State: Waiting for master to send event
                  Master_Host: 35.186.158.188
                  Master_User: repl
                  Master_Port: 3306
                Connect_Retry: 60
              Master_Log_File: server_A-bin.000023
          Read_Master_Log_Pos: 24745149
               Relay_Log_File: server_B-relay-bin.000002
                Relay_Log_Pos: 322
        Relay_Master_Log_File: server_A-bin.000023
             Slave_IO_Running: Yes
            Slave_SQL_Running: Yes
~
                   Last_Errno: 0
                   Last_Error: 
                 Skip_Counter: 0
          Exec_Master_Log_Pos: 16497695
              Relay_Log_Space: 8247985
              Until_Condition: None
               Until_Log_File: 
                Until_Log_Pos: 0
~
 Seconds_Behind_Master: 52
Master_SSL_Verify_Server_Cert: No
                Last_IO_Errno: 0
                Last_IO_Error: 
               Last_SQL_Errno: 0
               Last_SQL_Error: 
~
 SQL_Delay: 3600
 SQL_Remaining_Delay: 3549
 Slave_SQL_Running_State: Waiting until MASTER_DELAY seconds after master executed event
           Master_Retry_Count: 86400
                  Master_Bind: 
      Last_IO_Error_Timestamp: 
     Last_SQL_Error_Timestamp: 
~
1 row in set (0.00 sec)
```

请注意，一旦延迟被维持，`Seconds_Behind_Master`将显示为`0`。

# 设置 GTID 复制

**全局事务标识符**（**GTID**）是在原始服务器（主服务器）上提交的每个事务创建并关联的唯一标识符。此标识符不仅对于其起源服务器是唯一的，而且对于给定复制设置中的所有服务器也是唯一的。所有事务和所有 GTID 之间存在一对一的映射关系。

GTID 表示为一对坐标，用冒号（`:`）分隔。

```sql
GTID = source_id:transaction_id
```

`source_id`选项标识了原始服务器。通常，服务器的`server_uuid`选项用于此目的。`transaction_id`选项是由事务在此服务器上提交的顺序确定的序列号。例如，第一个提交的事务其`transaction_id`为`1`，在同一原始服务器上提交的第十个事务被分配了`transaction_id`为`10`。

正如您在之前的方法中所看到的，您必须在复制的起点上提到二进制日志文件和位置。如果您要将一个从服务器从一个主服务器切换到另一个主服务器，特别是在故障转移期间，您必须从新主服务器获取位置以同步从服务器，这可能很痛苦。为了避免这些问题，您可以使用基于 GTID 的复制，MySQL 会自动使用 GTID 检测二进制日志位置。

# 如何操作...

如果服务器之间已经设置了复制，请按照以下步骤操作：

1.  在`my.cnf`中启用 GTID：

```sql
shell> sudo vi /etc/my.cnf [mysqld]gtid_mode=ON
enforce-gtid-consistency=true
skip_slave_start
```

1.  将主服务器设置为只读，并确保所有从服务器与主服务器保持同步。这非常重要，因为主服务器和从服务器之间不应该存在任何数据不一致。

```sql
On master mysql> SET @@global.read_only = ON; On Slaves (if replication is already setup) mysql> SHOW SLAVE STATUS\G
```

1.  重新启动所有从服务器以使 GTID 生效。由于在配置文件中给出了`skip_slave_start`，从服务器在指定`START SLAVE`命令之前不会启动。如果启动从服务器，它将失败，并显示此错误——`The replication receiver thread cannot start because the master has GTID_MODE = OFF and this server has GTID_MODE = ON`。

```sql
shell> sudo systemctl restart mysql
```

1.  重新启动主服务器。重新启动主服务器后，它将以读写模式开始，并在 GTID 模式下开始接受写操作：

```sql
shell> sudo systemctl restart mysql
```

1.  执行`CHANGE MASTER TO`命令以设置 GTID 复制：

```sql
mysql> CHANGE MASTER TO MASTER_HOST = <master_host>, MASTER_PORT = <port>, MASTER_USER = 'binlog_user', MASTER_PASSWORD = 'binlog_P@ss12', MASTER_AUTO_POSITION = 1;
```

您可以观察到二进制日志文件和位置未给出；相反，给出了`MASTER_AUTO_POSITION`，它会自动找到已执行的 GTID。

1.  在所有从服务器上执行`START SLAVE`：

```sql
mysql> START SLAVE;
```

1.  验证从服务器是否正在复制：

```sql
mysql> SHOW SLAVE STATUS\G
*************************** 1\. row ***************************
               Slave_IO_State: Waiting for master to send event
                  Master_Host: xx.xxx.xxx.xxx
                  Master_User: binlog_user
                  Master_Port: 3306
                Connect_Retry: 60
              Master_Log_File: server1-bin.000002
          Read_Master_Log_Pos: 345
               Relay_Log_File: server2-relay-bin.000002
                Relay_Log_Pos: 562
        Relay_Master_Log_File: server1-bin.000002
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
          Exec_Master_Log_Pos: 345
              Relay_Log_Space: 770
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
  Replicate_Ignore_Server_Ids: 
             Master_Server_Id: 32
                  Master_UUID: b52ef45a-7ff4-11e7-9091-42010a940003
             Master_Info_File: /var/lib/mysql/master.info
                    SQL_Delay: 0
          SQL_Remaining_Delay: NULL
      Slave_SQL_Running_State: Slave has read all relay log; waiting for more updates
           Master_Retry_Count: 86400
                  Master_Bind: 
      Last_IO_Error_Timestamp: 
     Last_SQL_Error_Timestamp: 
               Master_SSL_Crl: 
           Master_SSL_Crlpath: 
           Retrieved_Gtid_Set: b52ef45a-7ff4-11e7-9091-42010a940003:1
            Executed_Gtid_Set: b52ef45a-7ff4-11e7-9091-42010a940003:1
 Auto_Position: 1
         Replicate_Rewrite_DB: 
                 Channel_Name: 
           Master_TLS_Version: 
1 row in set (0.00 sec)
```

要了解有关 GTID 的更多信息，请参阅[`dev.mysql.com/doc/refman/5.6/en/replication-gtids-concepts.html`](https://dev.mysql.com/doc/refman/5.6/en/replication-gtids-concepts.html)。

# 设置半同步复制

默认情况下，复制是异步的。主服务器不知道写操作是否已到达从服务器。如果主服务器和从服务器之间存在延迟，并且主服务器崩溃，那么尚未到达从服务器的数据将会丢失。为了克服这种情况，您可以使用半同步复制。

在半同步复制中，主服务器会等待至少一个从服务器接收写操作。默认情况下，`rpl_semi_sync_master_wait_point`的值为`AFTER_SYNC`；这意味着主服务器将事务同步到从服务器消耗的二进制日志中。

之后，从服务器向主服务器发送确认，然后主服务器提交事务并将结果返回给客户端。因此，如果写入已到达中继日志，则从服务器无需提交事务。您可以通过将变量`rpl_semi_sync_master_wait_point`更改为`AFTER_COMMIT`来更改此行为。在这种情况下，主服务器将事务提交给存储引擎，但不将结果返回给客户端。一旦从服务器上提交了事务，主服务器将收到事务的确认，然后将结果返回给客户端。

如果要在更多从服务器上确认事务，可以增加动态变量`rpl_semi_sync_master_wait_for_slave_count`的值。您还可以通过动态变量`rpl_semi_sync_master_timeout`设置主服务器必须等待从服务器确认的毫秒数；默认值为`10`秒。

在完全同步复制中，主服务器会等待直到所有从服务器都提交了事务。要实现这一点，您必须使用 Galera Cluster。

# 如何做…

在高层次上，您需要在主服务器和所有希望进行半同步复制的从服务器上安装和启用半同步插件。您必须重新启动从服务器 IO 线程以使更改生效。您可以根据您的网络和应用程序调整`rpl_semi_sync_master_timeout`的值。`1`秒的值是一个很好的起点：

1.  在主服务器上，安装`rpl_semi_sync_master`插件：

```sql
mysql> INSTALL PLUGIN rpl_semi_sync_master SONAME 'semisync_master.so';
Query OK, 0 rows affected (0.86 sec)
```

验证插件是否已激活：

```sql
mysql> SELECT PLUGIN_NAME, PLUGIN_STATUS FROM INFORMATION_SCHEMA.PLUGINS WHERE PLUGIN_NAME LIKE '%semi%';
+----------------------+---------------+
| PLUGIN_NAME          | PLUGIN_STATUS |
+----------------------+---------------+
| rpl_semi_sync_master | ACTIVE        |
+----------------------+---------------+
1 row in set (0.01 sec)
```

1.  在主服务器上，启用半同步复制并调整超时时间（比如 1 秒）：

```sql
mysql> SET @@GLOBAL.rpl_semi_sync_master_enabled=1;
Query OK, 0 rows affected (0.00 sec)

mysql> SHOW VARIABLES LIKE 'rpl_semi_sync_master_enabled';
+------------------------------+-------+
| Variable_name                | Value |
+------------------------------+-------+
| rpl_semi_sync_master_enabled | ON    |
+------------------------------+-------+
1 row in set (0.00 sec)

mysql> SET @@GLOBAL.rpl_semi_sync_master_timeout=1000;
Query OK, 0 rows affected (0.00 sec)

mysql> SHOW VARIABLES LIKE 'rpl_semi_sync_master_timeout';
+------------------------------+-------+
| Variable_name                | Value |
+------------------------------+-------+
| rpl_semi_sync_master_timeout | 1000  |
+------------------------------+-------+
1 row in set (0.00 sec)
```

1.  在从服务器上，安装`rpl_semi_sync_slave`插件：

```sql
mysql> INSTALL PLUGIN rpl_semi_sync_slave SONAME 'semisync_slave.so';
Query OK, 0 rows affected (0.22 sec)

mysql> SELECT PLUGIN_NAME, PLUGIN_STATUS FROM INFORMATION_SCHEMA.PLUGINS WHERE PLUGIN_NAME LIKE '%semi%';
+---------------------+---------------+
| PLUGIN_NAME         | PLUGIN_STATUS |
+---------------------+---------------+
| rpl_semi_sync_slave | ACTIVE        |
+---------------------+---------------+
1 row in set (0.08 sec)
```

1.  在从服务器上，启用半同步复制并重新启动从服务器 IO 线程：

```sql
mysql> SET GLOBAL rpl_semi_sync_slave_enabled = 1;
Query OK, 0 rows affected (0.00 sec)

mysql> STOP SLAVE IO_THREAD;
Query OK, 0 rows affected (0.02 sec)

mysql> START SLAVE IO_THREAD;
Query OK, 0 rows affected (0.00 sec)
```

1.  您可以通过以下方式监视半同步复制的状态：

要查找连接为半同步的客户端数量，请在主服务器上执行：

```sql
mysql> SHOW STATUS LIKE 'Rpl_semi_sync_master_clients';
+------------------------------+-------+
| Variable_name                | Value |
+------------------------------+-------+
| Rpl_semi_sync_master_clients | 1     |
+------------------------------+-------+
1 row in set (0.01 sec)
```

当超时发生并且从服务器赶上时，主服务器在异步和半同步复制之间切换。要检查主服务器正在使用的复制类型，请检查`Rpl_semi_sync_master_status`的状态（打开表示半同步，关闭表示异步）：

```sql
mysql> SHOW STATUS LIKE 'Rpl_semi_sync_master_status';
+-----------------------------+-------+
| Variable_name               | Value |
+-----------------------------+-------+
| Rpl_semi_sync_master_status | ON    |
+-----------------------------+-------+
1 row in set (0.00 sec)
```

您可以使用此方法验证半同步复制：

1.  停止从服务器：

```sql
mysql> STOP SLAVE;
Query OK, 0 rows affected (0.01 sec)
```

1.  在主服务器上，执行任何语句：

```sql
mysql> USE employees;
Database changed

mysql> DROP TABLE IF EXISTS employees_test;
Query OK, 0 rows affected, 1 warning (0.00 sec)
```

您会注意到主服务器已经切换到异步复制，因为即使在 1 秒后（`rpl_semi_sync_master_timeout`的值），它仍未收到从从服务器的任何确认：

```sql
mysql> SHOW STATUS LIKE 'Rpl_semi_sync_master_status';
+-----------------------------+-------+
| Variable_name               | Value |
+-----------------------------+-------+
| Rpl_semi_sync_master_status | ON    |
+-----------------------------+-------+
1 row in set (0.00 sec)

mysql> DROP TABLE IF EXISTS employees_test;
Query OK, 0 rows affected (1.02 sec)
```

```sql

mysql> SHOW STATUS LIKE 'Rpl_semi_sync_master_status';
+-----------------------------+-------+
| Variable_name               | Value |
+-----------------------------+-------+
| Rpl_semi_sync_master_status | OFF   |
+-----------------------------+-------+
1 row in set (0.01 sec
```

1.  启动从服务器：

```sql
mysql> START SLAVE;
Query OK, 0 rows affected (0.02 sec)
```

1.  在主服务器上，您会注意到主服务器已经切换回半同步复制。

```sql
mysql> SHOW STATUS LIKE 'Rpl_semi_sync_master_status';
+-----------------------------+-------+
| Variable_name               | Value |
+-----------------------------+-------+
| Rpl_semi_sync_master_status | ON    |
+-----------------------------+-------+
1 row in set (0.00 sec)
```
