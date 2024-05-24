# PHP7 高性能开发学习手册（二）

> 原文：[`zh.annas-archive.org/md5/57463751f7ad4ac2a29e3297fd76591c`](https://zh.annas-archive.org/md5/57463751f7ad4ac2a29e3297fd76591c)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：提高数据库性能

数据库在动态网站中扮演着关键角色。所有进出数据都存储在数据库中。因此，如果 PHP 应用程序的数据库设计和优化不好，将会极大地影响应用程序的性能。在本章中，我们将探讨优化 PHP 应用程序数据库的方法。本章将涵盖以下主题：

+   MySQL

+   查询缓存

+   MyISAM 和 InnoDB 存储引擎

+   Percona DB 和 Percona XtraDB 存储引擎

+   MySQL 性能监控工具

+   Redis

+   内存缓存

# MySQL 数据库

MySQL 是 Web 上最常用的关系型数据库管理系统（RDMS）。它是开源的，有免费的社区版本。它提供了企业级数据库可以提供的所有功能。

MySQL 安装提供的默认设置可能对性能不太好，总是有方法可以微调这些设置以获得更好的性能。另外，记住你的数据库设计在性能方面起着重要作用。设计不良的数据库会影响整体性能。

在本节中，我们将讨论如何提高 MySQL 数据库的性能。

### 注意

我们将修改 MySQL 配置的`my.cnf`文件。这个文件在不同的操作系统中位于不同的位置。另外，如果您在 Windows 上使用 XAMPP、WAMP 或任何其他跨平台 Web 服务器解决方案堆栈包，这个文件将位于相应的文件夹中。无论使用哪个操作系统，只要提到`my.cnf`，就假定文件是打开的。

## 查询缓存

查询缓存是 MySQL 的一个重要性能特性。它缓存`SELECT`查询以及结果数据集。当出现相同的`SELECT`查询时，MySQL 会从内存中获取数据，以便查询执行得更快，从而减少数据库的负载。

要检查 MySQL 服务器上是否启用了查询缓存，请在 MySQL 命令行中输入以下命令：

```php
**SHOW VARIABLES LIKE 'have_query_cache';**

```

上述命令将显示以下输出：

![查询缓存](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_04_01.jpg)

上一个结果集显示查询缓存已启用。如果查询缓存被禁用，值将为`NO`。

要启用查询缓存，打开`my.cnf`文件并添加以下行。如果这些行已经存在并被注释掉了，就取消注释：

```php
query_cache_type = 1
query_cache_size = 128MB
query_cache_limit = 1MB
```

保存`my.cnf`文件并重新启动 MySQL 服务器。让我们讨论一下前面三个配置的含义：

+   `query_cache_type`：这起着一种令人困惑的作用。

+   如果`query_cache_type`设置为`1`，`query_cache_size`为 0，则不分配内存，查询缓存被禁用。

如果`query_cache_size`大于 0，则查询缓存已启用，分配了内存，并且所有不超过`query_cache_limit`值或使用`SQL_NO_CACHE`选项的查询都被缓存。

+   如果`query_cache_type`的值为 0，`query_cache_size`为`0`，则不分配内存，缓存被禁用。

如果`query_cache_size`大于 0，则分配了内存，但没有缓存——即缓存被禁用。

+   `query_cache_size`：`query_cache_size`：这表示将分配多少内存。有些人认为使用的内存越多，效果就越好，但这是一个误解。这完全取决于数据库大小、查询类型和读写比例、硬件、数据库流量和其他因素。`query_cache_size`的一个好值在 100MB 到 200MB 之间；然后，您可以监视性能和其他影响查询缓存的变量，并调整大小。我们在一个中等流量的 Magento 网站上使用了 128MB，效果非常好。将此值设置为`0`以禁用查询缓存。

+   `query_cache_limit`：这定义了要缓存的查询数据集的最大大小。如果查询数据集的大小大于此值，则不会被缓存。可以通过找出最大的`SELECT`查询和其返回数据集的大小来猜测此配置的值。

# 存储引擎

存储引擎（或表类型）是 MySQL 核心的一部分，负责处理表上的操作。MySQL 提供了几种存储引擎，其中最常用的是 MyISAM 和 InnoDB。这两种存储引擎都有各自的优缺点，但总是优先考虑 InnoDB。从 5.5 开始，MySQL 开始使用 InnoDB 作为默认存储引擎。

### 注意

MySQL 提供了一些其他具有自己目的的存储引擎。在数据库设计过程中，可以决定哪个表应该使用哪种存储引擎。MySQL 5.6 的存储引擎的完整列表可以在[`dev.mysql.com/doc/refman/5.6/en/storage-engines.html`](http://dev.mysql.com/doc/refman/5.6/en/storage-engines.html)找到。

可以在数据库级别设置存储引擎，然后将其用作每个新创建的表的默认存储引擎。请注意，存储引擎是表的基础，单个数据库中的不同表可以具有不同的存储引擎。如果已经创建了一个表并且想要更改其存储引擎怎么办？很容易。假设我们的表名是`pkt_users`，其存储引擎是 MyISAM，我们想将其更改为 InnoDB；我们将使用以下 MySQL 命令：

```php
**ALTER TABLE pkt_users ENGINE=INNODB;**

```

这将把表的存储引擎值更改为`INNODB`。

现在，让我们讨论两种最常用的存储引擎 MyISAM 和 InnoDB 之间的区别。

## MyISAM 存储引擎

以下是 MyISAM 支持或不支持的功能的简要列表：

+   MyISAM 旨在提高速度，最适合与`SELECT`语句一起使用。

+   如果表更加静态，即该表中的数据更新/删除较少，大部分情况下只是获取数据，那么 MyISAM 是该表的最佳选项。

+   MyISAM 支持表级锁定。如果需要对表中的数据执行特定操作，那么可以锁定整个表。在此锁定期间，无法对该表执行任何操作。如果表更加动态，即该表中的数据经常更改，这可能会导致性能下降。

+   MyISAM 不支持外键。

+   MyISAM 支持全文搜索。

+   MyISAM 不支持事务。因此，不支持`COMMIT`和`ROLLBACK`。如果对表执行查询，则执行查询，没有回头的余地。

+   支持数据压缩、复制、查询缓存和数据加密。

+   不支持集群数据库。

## InnoDB 存储引擎

以下是 InnoDB 支持或不支持的功能的简要列表：

+   InnoDB 旨在在处理大量数据时具有高可靠性和高性能。

+   InnoDB 支持行级锁定。这是一个很好的特性，对性能非常有利。与 MyISAM 锁定整个表不同，它仅锁定`SELECT`、`DELETE`或`UPDATE`操作的特定行，在这些操作期间，该表中的其他数据可以被操作。

+   InnoDB 支持外键并强制外键约束。

+   支持事务。可以进行 COMMIT 和 ROLLBACK，因此可以从特定事务中恢复数据。

+   支持数据压缩、复制、查询缓存和数据加密。

+   InnoDB 可以在集群环境中使用，但它并没有完全支持。然而，InnoDB 表可以通过将表引擎更改为 NDB 来转换为 MySQL 集群中使用的 NDB 存储引擎。

在接下来的部分中，我们将讨论与 InnoDB 相关的一些性能特性。以下配置的值在`my.cnf`文件中设置。

### innodb_buffer_pool_size

此设置定义了用于 InnoDB 数据和加载到内存中的索引的内存量。对于专用的 MySQL 服务器，推荐值是服务器上安装内存的 50-80%。如果此值设置得太高，操作系统和 MySQL 的其他子系统，如事务日志，将没有内存。因此，让我们打开我们的`my.cnf`文件，搜索`innodb_buffer_pool_size`，并将值设置在推荐值（即 RAM 的 50-80%）之间。

### innodb_buffer_pool_instances

这个特性并不是那么广泛使用。它使多个缓冲池实例能够共同工作，以减少 64 位系统和`innodb_buffer_pool_size`较大值的内存争用的机会。

有不同的选择来计算`innodb_buffer_pool_instances`的值。一种方法是每 GB 的`innodb_buffer_pool_size`使用一个实例。因此，如果`innodb_bufer_pool_size`的值为 16GB，我们将把`innodb_buffer_pool_instances`设置为 16。

### innodb_log_file_size

`innodb_log_file_size`是存储执行的每个查询信息的日志文件的大小。对于专用服务器，最多可以设置为 4GB，但如果日志文件太大，崩溃恢复所需的时间可能会增加。因此，在最佳实践中，它保持在 1 到 4GB 之间。

# Percona Server - MySQL 的一个分支

根据 Percona 网站的说法，Percona 是一个免费、完全兼容、增强、开源的 MySQL 替代品，提供卓越的性能、可伸缩性和工具。

Percona 是一个具有增强性能功能的 MySQL 分支。MySQL 中可用的所有功能在 Percona 中也是可用的。Percona 使用一个名为 XtraDB 的增强存储引擎。根据 Percona 网站的说法，这是 MySQL 的 InnoDB 存储引擎的增强版本，具有更多功能，在现代硬件上具有更快的性能和更好的可伸缩性。Percona XtraDB 在高负载环境中更有效地使用内存。

如前所述，XtraDB 是 InnoDB 的一个分支，因此 InnoDB 中可用的所有功能在 XtraDB 中也是可用的。

## 安装 Percona Server

Percona 目前仅适用于 Linux 系统。目前不支持 Windows。在本书中，我们将在 Debian 8 上安装 Percona Server。对于 Ubuntu 和 Debian，安装过程是相同的。

### 注意

要在其他 Linux 版本上安装 Percona Server，请查看 Percona 安装手册[`www.percona.com/doc/percona-server/5.5/installation.html`](https://www.percona.com/doc/percona-server/5.5/installation.html)。目前，他们提供了 Debian、Ubuntu、CentOS 和 RHEL 的安装说明。他们还提供了从源代码和 Git 安装 Percona Server 的说明。

现在，让我们通过以下步骤安装 Percona Server：

1.  使用终端中的以下命令打开您的源列表文件：

```php
**sudo nano /etc/apt/sources.list** 

```

如果提示输入密码，请输入您的 Debian 密码。文件将被打开。

1.  现在，将以下存储库信息放在`sources.list`文件的末尾：

```php
deb http://repo.percona.com/apt jessie main
deb-src http://repo.percona.com/apt jessie main
```

1.  按下*CTRL* + *O*保存文件，按下*CTRL* + *X*关闭文件。

1.  使用终端中的以下命令更新系统：

```php
**sudo apt-get update**

```

1.  通过在终端中发出以下命令开始安装：

```php
**sudo apt-get install percona-server-server-5.5**

```

1.  安装将开始。该过程与安装 MySQL 服务器的过程相同。在安装过程中，将要求输入 Percona Server 的 root 密码；您只需输入即可。安装完成后，您将可以像使用 MySQL 一样使用 Percona Server。

1.  根据之前的章节配置和优化 Percona Server。

# MySQL 性能监控工具

始终需要监视数据库服务器的性能。为此，有许多可用的工具，使监视 MySQL 服务器和性能变得容易。其中大多数是开源和免费的，并且一些提供了图形界面。命令行工具更加强大，是最好的选择，尽管需要一点时间来理解和习惯它们。我们将在这里讨论一些。 

## phpMyAdmin

这是最著名的基于 Web 的开源免费工具，用于管理 MySQL 数据库。除了管理 MySQL 服务器外，它还提供了一些很好的工具来监视 MySQL 服务器。如果我们登录到 phpMyAdmin，然后点击顶部的**状态**选项卡，我们将看到以下屏幕：

![phpMyAdmin](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_04_02.jpg)

**服务器**选项卡向我们显示了关于 MySQL 服务器的基本数据，例如启动时间，自上次启动以来处理的流量量，连接信息等。

接下来是**查询统计**。这部分提供了关于所有执行的查询的完整统计信息。它还提供了一个饼图，可视化显示每种查询类型的百分比，如下面的截图所示。

如果我们仔细观察图表，我们会发现我们有 54%的`SELECT`查询正在运行。如果我们使用某种缓存，比如 Memcached 或 Redis，这些`SELECT`查询不应该这么高。因此，这个图表和统计信息为我们提供了分析我们的缓存系统的手段。

![phpMyAdmin](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_04_03.jpg)

下一个选项是**所有状态变量**，列出了所有 MySQL 变量及其当前值。在这个列表中，可以很容易地找出 MySQL 的配置情况。在下面的截图中，显示了我们的查询缓存变量及其值：

![phpMyAdmin](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_04_04.jpg)

phpMyAdmin 提供的下一个选项是**监视器**。这是一个非常强大的工具，以图形方式实时显示服务器资源及其使用情况。

![phpMyAdmin](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_04_05.jpg)

如前面的截图所示，我们可以在一个漂亮的图形界面中看到**问题**、**连接/进程**、**系统 CPU 使用率**、**流量**、**系统内存**和**系统交换**。

最后一个重要部分是**顾问**。它为我们提供有关性能设置的建议。它尽可能多地为您提供细节，以便调整 MySQL 服务器以提高性能。以下截图显示了顾问部分的一个小节：

![phpMyAdmin](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_04_06.jpg)

如果应用了所有这些建议，就可以获得一些性能提升。

## MySQL 工作台

这是 MySQL 的桌面应用程序，配备了管理和监控 MySQL 服务器的工具。它为我们提供了一个性能仪表板，可以以美观和图形的方式查看与服务器相关的所有数据，如下面的截图所示：

![The MySQL workbench](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_04_07.jpg)

## Percona Toolkit

之前提到的所有工具都很好，并提供了一些关于我们数据库服务器的可视化信息。然而，它们还不足以向我们显示一些更有用的信息或提供更多可以简化我们生活的功能。为此，还有另一个命令行工具包可用，名为 Percona Toolkit。

Percona Toolkit 是一套包括用于分析慢查询、存档、优化索引等的 30 多个命令行工具。

### 注意

Percona Toolkit 是免费开源的，可在 GPL 下使用。它的大多数工具在 Linux/Unix 系统上运行，但也有一些可以在 Windows 上运行。安装指南可以在[`www.percona.com/doc/percona-toolkit/2.2/installation.html`](https://www.percona.com/doc/percona-toolkit/2.2/installation.html)找到。完整的工具集可以在[`www.percona.com/doc/percona-toolkit/2.2/index.html`](https://www.percona.com/doc/percona-toolkit/2.2/index.html)找到。

现在，让我们在接下来的小节中讨论一些工具。

### pt-query-digest

该工具分析来自慢查询、一般查询和二进制日志文件的查询。它生成有关查询的复杂报告。让我们使用以下命令对慢查询运行此工具：

```php
**Pt-query-digest /var/log/mysql/mysql-slow.log**

```

在终端中输入上述命令后，我们将看到一个很长的报告。在这里，我们将讨论报告的一小部分，如下屏幕截图所示：

![pt-query-digest](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_04_08.jpg)

在前面的屏幕截图中，慢查询按最慢的顺序列出。第一个查询是一个`SELECT`查询，花费最长的时间，大约占总时间的 12%。第二个查询也是一个`SELECT`查询，占总时间的 11.5%。从这份报告中，我们可以看到哪些查询很慢，以便优化它们以获得最佳性能。

此外，pt-query-digest 显示每个查询的信息，如下屏幕截图所示。屏幕截图中提到了第一个查询的数据，包括总时间；时间百分比（pct）；最小、最大和平均时间；发送的字节数；以及其他一些参数：

![pt-query-digest](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_04_09.jpg)

### pt-duplicate-key-checker

该工具查找指定表集或完整数据库中的重复索引和重复外键。让我们在终端中使用以下命令再次执行此工具：

```php
**Pt-duplicate-key-checker –user packt –password dbPassword –database packt_pub**

```

执行时，将打印以下输出：

![pt-duplicate-key-checker](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_04_10.jpg)

在报告末尾，显示了指标摘要，这是不言自明的。此工具还打印出每个重复索引的`ALTER`查询，可以作为 MySQL 查询执行以修复索引，如下所示：

```php
**Pt-variable-advisor**

```

该工具显示每个查询的 MySQL 配置信息和建议。这是一个可以帮助我们正确设置 MySQL 配置的好工具。我们可以通过运行以下命令来执行此工具：

```php
**Pt-variable-advisor –user packt –password DbPassword localhost**

```

执行后，将显示以下输出：

![pt-duplicate-key-checker](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_04_11.jpg)

Percona Toolkit 还提供了许多其他工具，超出了本书的范围。但是，[`www.percona.com/doc/percona-toolkit/2.2/index.html`](https://www.percona.com/doc/percona-toolkit/2.2/index.html)上的文档非常有帮助且易于理解。它为每个工具提供了完整的详细信息，包括描述和风险，如何执行以及其他选项（如果有）。如果您希望了解 Percona Toolkit 中的任何工具，这份文档值得一读。

# Percona XtraDB Cluster（PXC）

Percona XtraDB Cluster 提供了一个高性能的集群环境，可以帮助轻松配置和管理多台服务器上的数据库。它使数据库可以使用二进制日志相互通信。集群环境有助于在不同的数据库服务器之间分担负载，并在服务器宕机时提供故障安全性。

要设置集群，我们需要以下服务器：

+   一台带有 IP 10.211.55.1 的服务器，我们将其称为 Node1

+   第二台带有 IP 10.211.55.2 的服务器，我们将其称为 Node2

+   第三台带有 IP 10.211.55.3 的服务器，我们将其称为 Node3

由于我们已经在我们的资源中有 Percona 存储库，让我们开始安装和配置 Percona XtraDB Cluster，也称为 PXC。执行以下步骤：

1.  首先，在终端中发出以下命令在 Node1 上安装 Percona XtraDB Cluster：

```php
**apt-get install percona-xtradb-cluster-56**

```

安装将类似于正常的 Percona Server 安装开始。在安装过程中，还将要求设置 root 用户的密码。

1.  安装完成后，我们需要创建一个具有复制权限的新用户。在登录到 MySQL 终端后，发出以下命令：

```php
**CREATE USER 'sstpackt'@'localhost' IDENTIFIED BY 'sstuserpassword';**
**GRANT RELOAD, LOCK TABLES, REPLICATION CLIENT ON *.* TO 'sstpackt'@'localhost';**
**FLUSH PRIVILEGES;**

```

第一个查询创建一个用户名为`sstpackt`，密码为`sstuserpassword`的用户。用户名和密码可以是任何内容，但建议使用一个好的和强大的密码。第二个查询为我们的新用户设置适当的权限，包括锁定表和复制。第三个查询刷新权限。

1.  现在，打开位于`/etc/mysql/my.cnf`的 MySQL 配置文件。然后，在`mysqld`块中放置以下配置：

```php
#Add the galera library
wsrep_provider=/usr/lib/libgalera_smm.so

#Add cluster nodes addresses
wsrep_cluster_address=gcomm://10.211.55.1,10.211.55.2,10.211.55.3

#The binlog format should be ROW. It is required for galera to work properly
binlog_format=ROW

#default storage engine for mysql will be InnoDB
default_storage_engine=InnoDB

#The InnoDB auto increment lock mode should be 2, and it is required for galera
innodb_autoinc_lock_mode=2

#Node 1 address
wsrep_node_address=10.211.55.1

#SST method
wsrep_sst_method=xtrabackup

#Authentication for SST method. Use the same user name and password created in above step 2
wsrep_sst_auth="sstpackt:sstuserpassword"

#Give the cluster a name
wsrep_cluster_name=packt_cluster
```

在添加上述配置后保存文件。

1.  现在，通过发出以下命令启动第一个节点：

```php
**/etc/init.d/mysql bootstrap-pxc**

```

这将引导第一个节点。引导意味着启动初始集群并定义哪个节点具有正确的信息，其他所有节点都应该同步到哪个节点。由于 Node1 是我们的初始集群节点，并且我们在这里创建了一个新用户，因此我们只需引导 Node1。

### 注意

**SST**代表**State Snapshot Transfer**。它负责从一个节点复制完整数据到另一个节点。仅在向集群添加新节点并且此节点必须从现有节点获取完整的初始数据时使用。`Percona XtraDB Cluster`中有三种 SST 方法，`mysqldump`、`rsync`和`xtrabackup`。

1.  在第一个节点上登录 MySQL 终端，并发出以下命令：

```php
**SHOW STATUS LIKE '%wsrep%';**

```

将显示一个非常长的列表。以下是其中的一些：

![Percona XtraDB Cluster (PXC)](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_04_12.jpg)

1.  现在，对所有节点重复步骤 1 和步骤 3。每个节点需要更改的唯一配置是`wsrep_node_address`，它应该是节点的 IP 地址。编辑所有节点的`my.cnf`配置文件，并将节点地址放在`wsrep_node_address`中。

1.  通过在终端中发出以下命令来启动两个新节点：

```php
**/etc/init.d/mysql start**

```

现在可以通过重复步骤 7 来验证每个节点。

要验证集群是否正常工作，请在一个节点中创建一个数据库，并向表中添加一些表和数据。之后，检查其他节点是否有新创建的数据库、表和每个表中输入的数据。我们将把所有这些数据同步到每个节点。

# Redis - 键值缓存存储

Redis 是一个开源的内存键值数据存储，广泛用于数据库缓存。根据 Redis 网站（[www.Redis.io](http://www.Redis.io)）的说法，Redis 支持诸如字符串、哈希、列表、集合和排序列表等数据结构。此外，Redis 支持复制和事务。

### 注意

Redis 安装说明可以在[`redis.io/topics/quickstart`](http://redis.io/topics/quickstart)找到。

要检查 Redis 在服务器上是否正常工作，请在终端中运行以下命令启动 Redis 服务器实例：

```php
**redis server**

```

然后在不同的终端窗口中发出以下命令：

```php
**redis-cli ping**

```

如果上述命令的输出如下，则 Redis 服务器已准备就绪：

![Redis - 键值缓存存储](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_04_13.jpg)

Redis 提供了一个命令行，其中提供了一些有用的命令。在 Redis 服务器上执行命令有两种方法。您可以使用以前的方法，也可以只输入`redis-cli`并按*Enter*；然后我们将看到 Redis 命令行，然后我们可以输入要执行的 Redis 命令。

默认情况下，Redis 使用 IP 127.0.0.1 和端口 6379。虽然不允许远程连接，但可以启用远程连接。Redis 存储已在数据库中创建的数据。数据库名称是整数，如 0、1、2 等。

我们不会在这里详细讨论 Redis，但我们将讨论一些值得注意的命令。请注意，所有这些命令都可以以前面的方式执行，或者我们可以只输入`redis-cli`命令窗口并输入命令，而不输入`redis-cli`。此外，以下命令可以直接在 PHP 中执行，这样就可以直接从我们的 PHP 应用程序中清除缓存：

+   `选择`：此命令更改当前数据库。默认情况下，redis-cli 将在数据库 0 打开。因此，如果我们想要转到数据库 1，我们将运行以下命令：

```php
**SELECT 1**

```

+   `FLUSHDB`：此命令刷新当前数据库。当前数据库中的所有键或数据将被删除。

+   `FLUSHALL`：此命令刷新所有数据库，无论在哪个数据库中执行。

+   `KEYS`：此命令列出与模式匹配的当前数据库中的所有键。以下命令列出当前数据库中的所有键。

```php
**KEYS ***

```

现在，是时候在 PHP 中与 Redis 进行一些操作了。

### 注意

在撰写本主题时，PHP 7 尚未内置对 Redis 的支持。为了本书的目的，我们为 PHP 7 编译了 PHPRedis 模块，并且它运行得非常好。该模块可以在[`github.com/phpredis/phpredis`](https://github.com/phpredis/phpredis)找到。

## 与 Redis 服务器连接

如前所述，默认情况下，Redis 服务器在 IP 127.0.0.1 和端口 6379 上运行。因此，为了建立连接，我们将使用这些详细信息。请看以下代码：

```php
$redisObject = new Redis();
if( !$redisObject->connect('127.0.0.1', 6379))
  die("Can't connect to Redis Server");
```

在第一行中，我们通过名称`redisObject`实例化了一个 Redis 对象，然后在第二行中使用它连接到 Redis 服务器。主机是本地 IP 地址 127.0.0.1，端口是 6379。`connect()`方法如果连接成功则返回`TRUE`；否则返回`FALSE`。

## 从 Redis 服务器存储和获取数据

现在，我们已连接到我们的 Redis 服务器。让我们在 Redis 数据库中保存一些数据。例如，我们想要在 Redis 数据库中存储一些字符串数据。代码如下：

```php
//Use same code as above for connection.
//Save Data in to Redis database.
$rdisObject->set('packt_title', 'Packt Publishing');

//Lets get our data from database
echo $redisObject->get('packt_title');
```

`set`方法将数据存储到当前 Redis 数据库，并接受两个参数：键和值。键可以是任何唯一名称，值是我们需要存储的内容。因此，我们的键是`packt_title`，值是`Packt Publishing`。除非显式设置，否则默认数据库始终设置为 0（零）。因此，上述`set`方法将保存我们的数据到数据库 0，并使用`packt_title`键。

现在，`get`方法用于从当前数据库中获取数据。它以键作为参数。因此，上述代码的输出将是我们保存的字符串数据`Packt Publishing`。

那么，来自数据库的数组或一组数据怎么办？我们可以以多种方式在 Redis 中存储它们。让我们首先尝试正常的字符串方式，如下所示：

```php
//Use same connection code as above.

/* This $array can come from anywhere, either it is coming from database or user entered form data or an array defined in code */

$array = ['PHP 5.4', PHP 5.5, 'PHP 5.6', PHP 7.0];

//Json encode the array
$encoded = json_encode($array);

//Select redis database 1
$redisObj->select(1);

//store it in redis database 1
$redisObject->set('my_array', $encoded);

//Now lets fetch it
$data = $redisObject->get('my_array');

//Decode it to array
$decoded = json_decode($data, true);

print_r($decoded); 
```

上述代码的输出将是相同的数组。为了测试目的，我们可以注释掉`set`方法，并检查`get`方法是否获取数据。请记住，在上述代码中，我们将数组存储为`json`字符串，然后将其作为`json`字符串获取，并解码为数组。这是因为我们使用了字符串数据类型可用的方法，不可能将数组存储在字符串数据类型中。

此外，我们使用`select`方法选择另一个数据库并在 0 之外使用它。这些数据将存储在数据库 1 中，如果我们在数据库 0，则无法获取它们。

### 注意

对 Redis 的完整讨论超出了本书的范围。因此，我们提供了一个简介。请注意，如果您使用任何框架，都可以轻松使用 Redis 提供的内置库，并且可以轻松使用任何数据类型。

## Redis 管理工具

Redis 管理工具提供了一种简单的方式来管理 Redis 数据库。这些工具提供了功能，以便可以轻松检查每个键并清除缓存。Redis 自带一个默认工具，称为 Redis-cli，我们之前已经讨论过。现在，让我们讨论一个视觉工具，非常好用，叫做**Redis Desktop Manage**（**RDM**）。RDM 的主窗口的屏幕截图如下所示：

![Redis 管理工具](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_04_14.jpg)

RDM 提供以下功能：

+   它连接到远程多个 Redis 服务器

+   以不同格式显示特定键中的数据

+   它向所选数据库添加新键

+   它向选定的键添加更多数据

+   它编辑/删除键和它们的名称

+   它支持 SSH 和 SSL，并且可以在云中使用

还有一些其他工具可以使用，但 RDM 和 Redis-cli 是最好和最容易使用的。

# Memcached 键值缓存存储

根据 Memcached 官方网站的说法，它是一个免费、开源、高性能、分布式内存对象缓存系统。Memcached 是一个内存中的键值存储，可以存储来自数据库或 API 调用的数据集。

与 Redis 类似，Memcached 也在加速网站方面有很大帮助。它将数据（字符串或对象）存储在内存中。这使我们能够减少与外部资源（如数据库或 API）的通信。

### 注意

我们假设 Memcached 已经安装在服务器上。同时，也假设 PHP 7 的 PHP 扩展也已安装。

现在，让我们在 PHP 中稍微玩一下 Memcachd。看一下下面的代码：

```php
//Instantiate Memcached Object
$memCached = new Memcached();

//Add server
$memCached->addServer('127.0.0.1', 11211);

//Lets get some data
$data = $memCached->get('packt_title');

//Check if data is available
if($data)
{
  echo $data;
}
else
{
  /*No data is found. Fetch your data from any where and add to   memcached */

  $memCached->set('packt_title', 'Packt Publishing');

}
```

上面的代码是一个非常简单的使用 Memcached 的例子。每行代码都有注释，很容易理解。在实例化一个 Memcached 对象之后，我们必须添加一个 Memcached 服务器。默认情况下，Memcached 服务器在本地主机 IP 上运行，即 127.0.0.1，端口号为 11211。之后，我们使用一个键来检查一些数据，如果数据可用，我们可以处理它（在这种情况下，我们将其显示出来，也可以返回它，或者进行其他所需的处理）。如果数据不可用，我们可以直接添加它。请注意，数据可以来自远程服务器 API 或数据库。

### 注意

我们刚刚介绍了 Memcached 以及它如何帮助我们存储数据和提高性能。在本标题中无法进行完整的讨论。关于 Memcached 的一本好书是 Packt Publishing 出版的《Getting Started with Memcached》。

# 摘要

在本章中，我们涵盖了 MySQL 和 Percona Server。此外，我们详细讨论了查询缓存和其他 MySQL 性能配置选项。我们提到了不同的存储引擎，比如 MyISAM、InnoDB 和 Percona XtraDB。我们还在三个节点上配置了 Percona XtraDB 集群。我们讨论了不同的监控工具，比如 PhpMyAdmin 监控工具、MySQL Workbench 性能监控和 Percona Toolkit。我们还讨论了 Redis 和 Memcached 对 PHP 和 MySQL 的缓存。

在下一章中，我们将讨论基准测试和不同的工具。我们将使用 XDebug、Apache JMeter、ApacheBench 和 Siege 来对不同的开源系统进行基准测试，比如 WordPress、Magento、Drupal 以及不同版本的 PHP，并将它们与 PHP 7 的性能进行比较。


# 第五章：调试和性能分析

在开发过程中，每个开发人员都会遇到问题，不清楚到底发生了什么，以及为什么会产生问题。大多数时候，这些问题可能是逻辑性的或者与数据有关。要找到这样的问题总是很困难。调试是一个找到这样的问题并解决它们的过程。同样，我们经常需要知道脚本消耗了多少资源，包括内存消耗，CPU 以及执行所需的时间。

在本章中，我们将涵盖以下主题：

+   Xdebug

+   使用 Sublime Text 3 进行调试

+   使用 Eclipse 进行调试

+   使用 Xdebug 进行性能分析

+   PHP DebugBar

# Xdebug

Xdebug 是 PHP 的一个扩展，为 PHP 脚本提供调试和性能分析信息。Xdebug 显示错误的完整堆栈跟踪信息，包括函数名称，行号和文件名。此外，它提供了使用不同 IDE（如 Sublime Text，Eclipse，PHP Storm 和 Zend Studio）交互式调试脚本的能力。

要检查 Xdebug 是否已安装并在我们的 PHP 安装中启用，我们需要检查 phpinfo（）的详细信息。在 phpinfo 详细信息页面上搜索 Xdebug，您应该看到类似以下屏幕截图的详细信息：

！[Xdebug]（graphics / B05225_05_01.jpg）

这意味着我们的 PHP 安装已经安装了 Xdebug。现在，我们需要配置 Xdebug。Xdebug 配置要么在`php.ini`文件中，要么有自己的单独的`.ini`文件。在我们的安装中，我们将在`/etc/php/7.0/fpm/conf.d/`路径下放置一个单独的`20-xdebug.ini`文件。

### 注意

为了本书的目的，我们将使用 Laravel 的 Homestead Vagrant 框。它在 Ubuntu 14.04 LTS 安装中提供了完整的工具，包括带有 Xdebug 的 PHP7，NGINX 和 MySQL。对于开发目的，这个 Vagrant 框是一个完美的解决方案。更多信息可以在[https://laravel.com/docs/5.1/homestead]（https://laravel.com/docs/5.1/homestead）找到。

现在，打开`20-xdebug.ini`文件并将以下配置放入其中：

```php
zend_extension = xdebug.so
xdebug.remote_enable = on
xdebug.remote_connect_back = on
xdebug.idekey = "vagrant"
```

上述是我们应该使用的最低配置，它们启用了远程调试并设置了 IDE 密钥。现在，通过在终端中发出以下命令来重新启动 PHP：

```php
**sudo service php-fpm7.0 restart**

```

现在我们准备调试一些代码。

## 使用 Sublime Text 进行调试

Sublime Text 编辑器有一个插件，可以用来使用 Xdebug 调试 PHP 代码。首先，让我们为 Sublime Text 安装`xdebug`包。

### 注意

对于这个主题，我们将使用仍处于 beta 阶段的 Sublime Text 3。使用版本 2 还是 3 是你自己的选择。

首先，转到**工具** | **命令面板**。将显示类似于以下内容的弹出窗口：

！[使用 Sublime Text 进行调试]（graphics / B05225_05_02.jpg）

选择**Package Control：Install Package**，将显示类似于以下屏幕截图的弹出窗口：

！[使用 Sublime Text 进行调试]（graphics / B05225_05_03.jpg）

键入`xdebug`，将显示**Xdebug Client**包。单击它，等待一会直到安装完成。

现在，在 Sublime Text 中创建一个项目并保存它。打开 Sublime Text 项目文件并插入以下代码：

```php
{
  "folders":
  [
    {
    "follow_symlinks": true,
    "path": "."
  }
],

**"settings": {**
 **"xdebug": {**
 **"path_mapping": {**
 **"full_path_on_remote_host" : "full_path_on_local_host"**
 **},**
 **"url" : http://url-of-application.com/,**
 **"super_globals" : true,**
 **"close_on_stop" : true,**
 **}**
 **}**
}
```

突出显示的代码很重要，必须输入 Xdebug。路径映射是最重要的部分。它应该有远程主机应用程序根目录的完整路径和本地主机应用程序根目录的完整路径。

现在，让我们开始调试。在项目的根目录创建一个文件，命名为`index.php`，并将以下代码放入其中：

```php
$a = [1,2,3,4,5];
$b = [4,5,6,7,8];

$c = array_merge($a, $b);
```

现在，在编辑器中右键单击一行，然后选择**Xdebug**。然后，单击**添加/删除断点**。让我们按照以下屏幕截图中显示的方式添加一些断点：

！[使用 Sublime Text 进行调试]（graphics / B05225_05_04.jpg）

当在一行上添加断点时，将在左侧靠近行号处显示一个填充的圆圈，如前面的屏幕截图所示。

现在我们已经准备好调试我们的 PHP 代码了。转到**工具** | **Xdebug** | **开始调试（在浏览器中启动）**。浏览器窗口将打开应用程序，并附带 Sublime Text 调试会话参数。浏览器窗口将处于加载状态，因为一旦到达第一个断点，执行就会停止。浏览器窗口将类似于以下内容：

![使用 Sublime Text 进行调试](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_05_05.jpg)

一些新的小窗口也会在 Sublime Text 编辑器中打开，显示调试信息以及所有可用的变量，如下面的屏幕截图所示：

![使用 Sublime Text 进行调试](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_05_06.jpg)

在上面的屏幕截图中，我们的`$a`，`$b`和`$c`数组未初始化，因为执行光标位于第 22 行，并且停在那里。此外，所有服务器变量、cookie、环境变量、请求数据以及 POST 和 GET 数据都可以在这里看到。这样，我们可以调试各种变量、数组和对象，并检查每个变量、对象或数组在某个特定点上持有的数据。这使我们有可能找出那些在没有调试的情况下很难检测到的错误。

现在，让我们将执行光标向前移动。在编辑器代码部分右键单击，然后转到**Xdebug** | **步入**。光标将向前移动，变量数据可能会根据下一行而改变。可以在以下屏幕截图中注意到这一点：

![使用 Sublime Text 进行调试](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_05_07.jpg)

单击**工具** | **Xdebug** | **停止调试**即可停止调试。

## 使用 Eclipse 进行调试

Eclipse 是最自由和功能强大的广泛使用的 IDE。它支持几乎所有主要的编程语言，包括 PHP。我们将讨论如何配置 Eclipse 以使用 Xdebug 进行调试。

首先，在 Eclipse 中打开项目。然后，单击工具栏中小虫图标右侧的向下箭头，如下面的屏幕截图所示：

![使用 Eclipse 进行调试](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_05_08.jpg)

之后，单击**调试配置**菜单，将打开以下窗口：

![使用 Eclipse 进行调试](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_05_09.jpg)

在左侧面板中选择**PHP Web 应用程序**，然后单击左上角的**添加新**图标。这将添加一个新的配置，如上面的屏幕截图所示。给配置命名。现在，我们需要向配置中添加一个 PHP 服务器。单击右侧面板上的**新建**按钮，将打开以下窗口： 

![使用 Eclipse 进行调试](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_05_10.jpg)

我们将服务器名称输入为`PHP 服务器`。服务器名称可以是任何用户友好的名称，只要以后可以识别。在**基本 URL**字段中，输入应用程序的完整 URL。**文档根**应该是应用程序根目录的本地路径。输入所有有效数据后，单击**下一步**按钮，我们将看到以下窗口：

![使用 Eclipse 进行调试](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_05_11.jpg)

在**调试器**下拉列表中选择**XDebug**，其余字段保持不变。单击**下一步**按钮，我们将进入路径映射窗口。将正确的本地路径映射到正确的远程路径非常重要。单击**添加**按钮，我们将看到以下窗口：

![使用 Eclipse 进行调试](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_05_12.jpg)

在远程服务器上输入应用程序的文档根的完整路径。然后，选择**文件系统中的路径**，并输入应用程序文档根的本地路径。单击**确定**，然后单击路径映射窗口中的**完成**按钮。然后，在下一个窗口中单击**完成**，以完成添加 PHP 服务器。

现在，我们的配置已经准备好。首先，我们将通过点击行号栏上的小蓝点来向我们的 PHP 文件添加一些断点，如下截图所示。现在，点击工具栏上的小虫子图标，选择**Debug As**，然后点击**PHP Web Application**。调试过程将开始，并且浏览器中将打开一个窗口。它将处于加载状态，就像我们在 Sublime Text 调试中看到的一样。此外，Eclipse 中将打开 Debug 视图，如下所示：

![使用 Eclipse 进行调试](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_05_13.jpg)

当我们点击右侧边栏中的小(**X**)=图标时，我们将看到所有的变量。还可以编辑任何变量数据，甚至是任何数组的元素值、对象属性和 cookie 数据。修改后的数据将在当前调试会话中保留。

要进入下一行，我们只需按下*F5*，执行光标将移动到下一行。要跳出到下一个断点，我们将按下*F6*。

# 使用 Xdebug 进行分析

分析提供了有关应用程序中执行的每个脚本或任务的成本的信息。它有助于提供有关任务花费多少时间的信息，因此我们可以优化我们的代码以减少时间消耗。

Xdebug 有一个默认情况下被禁用的分析器。要启用分析器，打开配置文件并在其中放置以下两行：

```php
xdebug.profiler_enable=on
xdebug.profiler_output_dir=/var/xdebug/profiler/
```

第一行启用了分析器。我们定义了分析器文件的输出目录的第二行非常重要。在这个目录中，当分析器执行时，Xdebug 将存储输出文件。输出文件以`cachegrind.out.id`的名称存储。这个文件包含了所有的分析数据，以简单的文本格式。

现在，我们准备对 Laravel 应用程序主页的简单安装进行分析。这个安装是全新的和干净的。现在，让我们在浏览器中打开应用程序，并在末尾添加`?XDEBUG_PROFILE=on`，如下所示：

`http://application_url.com?XDEBUG_PROFILE=on`

在加载完这个页面后，将在指定位置生成一个`cachegrind`文件。现在，当我们在文本编辑器中打开文件时，我们将只看到一些文本数据。

### 注意

`cachegrind`文件可以用不同的工具打开。Windows 的一个工具是 WinCacheGrind。对于 Mac，我们有 qcachegrind。这些应用程序中的任何一个都将以一种可以轻松分析的交互形式查看文件数据。此外，PHP Storm 有一个用于 cachegrind 的良好分析器。在这个主题中，我们使用了 PHP Storm IDE。

在 PHP Storm 中打开文件后，我们将得到一个类似以下截图的窗口：

![使用 Xdebug 进行分析](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_05_14.jpg)

如前面的截图所示，我们在上面的窗格中有执行统计信息，显示了每个调用脚本单独花费的时间（以毫秒为单位），以及它被调用的次数。在下面的窗格中，我们有调用了这个脚本的调用者。

我们可以分析哪个脚本花费了更多的时间，然后优化这个脚本以减少执行时间。此外，我们可以找出在某个特定点是否需要调用特定的脚本。如果不需要，那么我们可以删除这个调用。

# PHP DebugBar

PHP DebugBar 是另一个很棒的工具，它在页面底部显示一个漂亮且完整的信息栏。它可以显示为了调试目的而添加的自定义消息，以及包括`$_COOKIE`、`$_SERVER`、`$_POST`和`$_GET`数组在内的完整请求信息，以及它们的数据（如果有的话）。此外，PHP DebugBar 还显示了异常的详细信息，执行的数据库查询及其详细信息。它还显示了脚本占用的内存和页面加载的时间。

根据 PHP Debug 网站，DebugBar 可以轻松集成到任何应用项目中，并显示来自应用程序任何部分的调试和分析数据。

它的安装很容易。您可以下载完整的源代码，将其放在应用程序的某个地方，并设置自动加载器来加载所有类，或者使用 composer 来安装它。我们将使用 composer，因为这是安装它的简单和干净的方式。

### 注意

Composer 是一个用于管理项目依赖关系的 PHP 工具。它是用 PHP 编写的，并且可以从[`getcomposer.org/`](https://getcomposer.org/)免费获取。我们假设 composer 已经安装在您的机器上。

在项目的`composer.json`文件中，在所需的部分中放置以下代码：

```php
"maximebf/debugbar" : ">=1.10.0"
```

保存文件，然后发出以下命令：

```php
**composer update**

```

Composer 将开始更新依赖项并安装 composer。此外，它将生成自动加载器文件和/或 DebugBar 所需的其他依赖项。

### 注意

前面的 composer 命令只有在系统上全局安装了 composer 才能工作。如果没有，我们必须使用以下命令：

```php
php composer.phar update
```

前面的命令应该在放置`composer.phar`的文件夹中执行。

安装后，DebugBar 的项目树可能如下：

![PHP DebugBar](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_05_15.jpg)

目录结构可能有点不同，但通常会如我们之前所述。`src`目录包含了 DebugBar 的完整源代码。`vendor`目录包含了一些可能需要的第三方模块或 PHP 工具。还要注意`vendor`文件夹中有自动加载器来自动加载所有类。

让我们现在检查我们的安装，看看它是否工作。在项目根目录中创建一个新文件，命名为`index.php`。之后，在其中放置以下代码：

```php
<?php
require "vendor/autoloader.php";
use Debugbar\StandardDebugBar;
$debugger = new StandardDebugBar();
$debugbarRenderer = $debugbar->getJavascriptRenderer();

//Add some messages
$debugbar['messages']->addMessage('PHP 7 by Packt');
$debugbar['messages']->addMessage('Written by Altaf Hussain');

?>

<html>
  <head>
    <?php echo $debugbarRenderer->renderHead(); ?>
  </head>
  <title>Welcome to Debug Bar</title>
  <body>
    <h1>Welcome to Debug Bar</h1>

  <!—- display debug bar here -->
  <?php echo $debugbarRenderer->render();  ?>

  </body>
</html>
```

在前面的代码中，我们首先包含了我们的自动加载器，这是由 composer 为我们生成的，用于自动加载所有类。然后，我们使用了`DebugBar\StandardDebugbar`命名空间。之后，我们实例化了两个对象：`StandardDebugBar`和`getJavascriptRenderer`。`StandardDebugBar`对象是一个对象数组，其中包含了不同收集器的对象，例如消息收集器等。`getJavascriptRenderer`对象负责在页眉处放置所需的 JavaScript 和 CSS 代码，并在页面底部显示栏。

我们使用`$debugbar`对象向消息收集器添加消息。收集器负责从不同来源收集数据，例如数据库、HTTP 请求、消息等。

在 HTML 代码的头部，我们使用了`$debugbarRenderer`的`renderHead`方法来放置所需的 JavaScript 和 CSS 代码。之后，在`<body>`块的末尾之前，我们使用了相同对象的`render`方法来显示调试栏。

现在，在浏览器中加载应用程序，如果您注意到浏览器底部有一个栏，如下面的屏幕截图所示，那么恭喜！DebugBar 已正确安装并且运行正常。

![PHP DebugBar](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_05_16.jpg)

在右侧，我们有应用程序消耗的内存和加载时间。

如果我们点击**消息**选项卡，我们将看到我们添加的消息，如下面的屏幕截图所示：

![PHP DebugBar](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_05_17.jpg)

DebugBar 提供数据收集器，用于从不同来源收集数据。这些被称为*基本收集器*，以下是一些数据收集器：

+   消息收集器收集日志消息，如前面的示例所示

+   TimeData 收集器收集总执行时间以及特定操作的执行时间

+   异常收集器显示所有发生的异常

+   PDO 收集器记录 SQL 查询

+   RequestData 收集器收集 PHP 全局变量的数据，例如`$_SERVER`、`$_POST`、`$_GET`等。

+   配置收集器用于显示数组的任何键值对

此外，还有一些收集器可以从 Twig、Swift Mailer、Doctrine 等第三方框架中收集数据。这些收集器被称为桥接收集器。PHP DebugBar 也可以轻松集成到著名的 PHP 框架，如 Laravel 和 Zend Framework 2 中。

### 注

本书无法对 PHP DebugBar 进行全面讨论。因此，这里只提供了一个简单的介绍。PHP DebugBar 有一个很好的文档，其中提供了完整的详细信息和示例。文档可以在[`phpdebugbar.com/docs/readme.html`](http://phpdebugbar.com/docs/readme.html)找到。

# 总结

在本章中，我们讨论了调试 PHP 应用程序的不同工具。我们使用 Xdebug、Sublime Text 3 和 Eclipse 来调试我们的应用程序。然后，我们使用 Xdebug 分析器来分析应用程序，以找出执行统计信息。最后，我们讨论了 PHP DebugBar 来调试应用程序。

在下一章中，我们将讨论负载测试工具，我们可以使用这些工具在我们的应用程序上放置负载或虚拟访问者，以对其进行负载测试，并找出我们的应用程序能承受多少负载，以及它如何影响性能。


# 第六章：压力/负载测试 PHP 应用程序

在应用程序开发、测试、调试和分析之后，是时候将其投入生产了。但是，在投入生产之前，最好的做法是对应用程序进行压力/负载测试。这项测试将为我们提供一个关于服务器在运行应用程序时可以处理多少请求的大致结果。利用这些结果，我们可以优化应用程序、Web 服务器、数据库和缓存工具，以获得更好的结果并处理更多的请求。

在本章中，我们将对 PHP 5.6 和 PHP 7 上的不同开源工具进行负载测试，并比较这些应用程序在 PHP 的两个版本上的性能。

我们将涵盖以下主题：

+   Apache JMeter

+   ApacheBench (ab)

+   Seige

+   在 PHP 5.6 和 PHP 7 上对 Magento 2 进行负载测试

+   在 PHP 5.6 和 PHP 7 上对 WordPress 进行负载测试

+   在 PHP 5.6 和 PHP 7 上对 Drupal 8 进行负载测试

# Apache JMeter

Apache JMeter 是一个图形化的开源工具，用于对服务器的性能进行负载测试。JMeter 完全由 Java 编写，因此与安装了 Java 的所有操作系统兼容。JMeter 拥有一套完整的广泛工具，可用于各种负载测试，从静态内容到动态资源和 Web 服务。

安装很简单。我们需要从 JMeter 网站下载它，然后运行应用程序。如前所述，它将需要在计算机上安装 Java。

### 注意

JMeter 可以测试 FTP 服务器、邮件服务器、数据库服务器、查询等等。在本书中，我们无法涵盖所有这些主题，因此我们只会对 Web 服务器进行负载测试。Apache JMeter 的功能列表可以在[`jmeter.apache.org/`](http://jmeter.apache.org/)找到。

当我们首次运行应用程序时，将看到以下窗口：

![Apache JMeter](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_06_01.jpg)

要运行任何类型的测试，首先需要创建一个测试计划。测试计划包含执行此测试所需的所有组件。默认情况下，JMeter 有一个名为 Test Plan 的测试计划。让我们将其命名为我们自己的计划，`Packt Publisher Test Plan`，如下面的屏幕截图所示：

![Apache JMeter](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_06_02.jpg)

现在，保存测试计划，JMeter 将创建一个`.jmx`文件。将其保存在适当的位置。

下一步是添加一个线程组。*线程组定义了测试计划的一些基本属性，这些属性可以在所有类型的测试中通用*。要添加线程组，请右键单击左侧面板中的计划，然后导航到**Add** | **Threads (Users)** | **Thread Group**。将显示以下窗口：

![Apache JMeter](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_06_03.jpg)

线程组具有以下重要属性：

+   **线程数**：这是虚拟用户的数量。

+   **渐进周期**：这告诉 JMeter 它应该花多长时间才能达到线程数的最大容量。例如，在前面的屏幕截图中，我们有 40 个线程和 80 秒的渐进时间；在这里，JMeter 将花 80 秒的时间完全启动 40 个线程，每个线程启动需要 2 秒。

+   **循环计数**：这告诉 JMeter 运行此线程组需要多长时间。

+   **调度程序**：这用于安排稍后执行线程组。

现在，我们需要添加 HTTP 请求默认值。右键单击**Packt Thread Group**，然后转到**Add** | **Config Element** | **HTTP Request Defaults**。将出现类似以下的窗口：

![Apache JMeter](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_06_04.jpg)

在前面的窗口中，我们只需输入应用程序的 URL 或 IP 地址。如果 Web 服务器使用 cookie，我们还可以添加 HTTP Cookie Manager，在其中可以添加用户定义的 cookie 及其所有数据，如名称、值、域、路径等。

接下来，我们将通过右键单击并导航到**Packt Thread Group** | **Add** | **Sampler** | **HTTP Request**来添加一个 HTTP 请求，然后将出现以下窗口：

![Apache JMeter](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_06_05.jpg)

这里的重要字段是**路径**。我们只想针对主页运行测试，所以对于这个 HTTP 请求，我们只需在**路径**字段中添加一个斜杠（`/`）。如果我们想测试另一个路径，比如"联系我们"，我们需要添加另一个 HTTP 请求采样器，如上面的屏幕截图所示。然后，在路径中，我们将添加`path/contact-us`。

HTTP 请求采样器也可以用于测试表单，可以通过在**方法**字段中选择 POST 方法来向 URL 发送 POST 请求。还可以模拟文件上传。

接下来的步骤是添加一些监听器。*监听器提供了一些强大的视图来显示结果*。结果可以显示在表格视图中，并且不同类型的图表可以保存在文件中。对于这个线程组，我们将添加三个监听器：在表中查看结果，响应时间图和图表结果。每个监听器视图显示不同类型的数据。通过右键单击**Packt Thread Group**，然后导航到**添加** | **监听器**来添加所有前面的监听器。我们将有一个所有可用监听器的完整列表。逐个添加所有三个监听器。我们左侧的 JMeter 上的最终**Packt Publisher Test Plan**面板将类似于以下内容：

![Apache JMeter](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_06_06.jpg)

现在，我们可以通过点击上方工具栏中的**开始**按钮来运行我们的测试计划，如下面的屏幕截图所示：

![Apache JMeter](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_06_07.jpg)

一旦我们点击**开始**按钮（指向右侧的绿色箭头），JMeter 将启动我们的测试计划。现在，如果我们在左侧面板上点击**在表中查看结果**监听器，我们将看到每个请求的数据在表中显示，如下面的屏幕截图所示：

![Apache JMeter](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_06_08.jpg)

上述屏幕截图显示了一些有趣的数据，如样本时间、状态、字节和延迟。

**样本时间**是服务器提供完整请求所用的毫秒数。**状态**是请求的状态。它可以是成功、警告或错误。**字节**是请求接收的字节数。**延迟**是 JMeter 从服务器接收到初始响应所用的毫秒数。

现在，如果我们点击**响应时间图**，我们将看到响应时间的可视图表，类似于以下内容：

![Apache JMeter](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_06_09.jpg)

现在，如果我们点击**图表结果**，我们将看到响应时间数据以及平均值、中位数、偏差和吞吐量图表，如下图所示：

![Apache JMeter](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_06_10.jpg)

Apache JMeter 提供了非常强大的工具，可以通过模拟用户来对我们的 Web 服务器进行负载测试。它可以为我们提供关于使我们的 Web 服务器响应变慢的负载量的数据，并且使用这些数据，我们可以优化我们的 Web 服务器和应用程序。

# ApacheBench (ab)

ApacheBench (ab)也由 Apache 提供，是一个命令行工具。这是一个非常适合命令行爱好者的工具。这个工具通常默认安装在大多数 Linux 发行版上。此外，它也随 Apache 一起安装，所以如果你安装了 Apache，你可能也会安装 ab。

ab 命令的基本语法如下：

```php
**ab –n <Number_Requests> -c <Concurrency> <Address>:<Port><Path>**

```

让我们讨论上述命令的每个部分的含义：

+   `n`：这是测试的请求数。

+   `c`：这是并发数，即同时发出的请求数。

+   `地址`：这是 Web 服务器的应用程序 URL 或 IP 地址。

+   `端口`：这是应用程序运行的端口号。

+   `路径`：这是我们可以用来测试的应用程序的 Web 路径。斜杠（`/`）用于主页。

现在，让我们通过发出以下命令使用 ab 工具进行测试：

```php
**ab –n 500 –c 10 packtpub.com/**

```

由于 Web 服务器的默认端口是 80，因此不需要提及它。请注意末尾的斜杠；这是必需的，因为它是路径的一部分。

执行上述命令后，我们将获得类似以下内容的输出：

![ApacheBench (ab)](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_06_11.jpg)

我们可以在这里看到一些有用的信息，包括每秒请求的数量，为**490.3**；测试所用的总时间，为**1.020 秒**；最短请求为**20 毫秒**；最长请求为**52 毫秒**。

可以通过增加请求数量和并发级别并检查 Web 服务器的性能来找到服务器负载限制。

# Siege

Siege 是另一个命令行开源工具，用于测试负载和性能。Siege 是一个 HTTP/FTP 负载测试工具和基准测试实用程序。它旨在供开发人员和管理员在负载下测量其应用程序的性能。它可以向服务器发送可配置数量的并发请求，并且这些请求会使服务器处于围攻状态。

它的安装简单而容易。对于 Linux 和 Mac OS X，首先通过在终端中发出以下命令来下载 Siege：

```php
**wget http://download.joedog.org/siege/siege-3.1.4.tar.gz**

```

它将下载 Siege TAR 压缩文件。现在，通过发出以下命令来解压缩它：

```php
**tar –xvf siege-3.1.4.tar.gz**

```

现在，所有文件都将位于`siege-3.1.4`文件夹中。通过在终端中依次发出以下命令来构建和安装它：

```php
**cd siege-3.1.4**
**./configure**
**make**
**make install**

```

现在，Siege 已安装。要确认这一点，请发出以下命令以检查 Siege 版本：

```php
**siege –V**

```

如果显示带有其他信息的版本，则 Siege 已成功安装。

### 注意

在撰写本书时，当前的 Siege 稳定版本是 3.1.4。此外，Siege 不原生支持 Windows，当然，可以使用 Siege 测试和基准测试 Windows 服务器。

现在，让我们进行一次负载测试。可以通过运行以下命令来执行基本的负载测试：

```php
**siege some_url_or_ip**

```

然后 Siege 将开始测试。我们必须输入要进行负载测试的应用程序 URL 或服务器 IP。要停止测试，请按*Ctrl* + *C*，然后我们将获得类似以下内容的输出：

![Siege](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_06_12.jpg)

在上述屏幕截图中，我们可以看到**事务**、**响应时间**和**事务速率**，以及**最长事务**和**最短事务**。

默认情况下，Siege 创建 15 个并发用户。可以通过使用`-c`选项进行更改，方法是在命令中进行以下更改：

```php
**siege url_or_ip –c 100**

```

但是，Siege 对并发用户有限制，对于每个操作系统可能不同。这可以在 Siege 配置文件中设置。要找出`config`文件位置和并发用户限制，请在终端中发出以下命令：

```php
**siege -C**

```

将显示配置选项列表。还将显示资源文件或`config`文件位置。打开该文件，找到配置并将其值设置为适当的值。

Siege 的另一个重要功能是可以使用包含所有需要测试的 URL 的文件。该文件每行应包含一个 URL。使用`-f`标志与 Siege 一起使用如下：

```php
**siege -f /path/to/url/file.txt –c 120**

```

Siege 将加载文件并开始对每个 URL 进行负载测试。

Siege 的另一个有趣的功能是互联网模式，可以使用以下命令中的`-i`标志进入：

```php
**siege –if path_to_urls_file –c 120**

```

在互联网模式下，每个 URL 都会随机访问，并模拟真实生活中无法预测哪个 URL 会被访问的情况。

### 注意

Siege 有很多有用的标志和功能。详细列表可以在官方文档中找到[`www.joedog.org/siege-manual/`](https://www.joedog.org/siege-manual/)。

# 负载测试真实应用

在本章中，我们研究了三种工具进行负载测试。现在，是时候对一些真实世界的应用进行负载测试了。在本节中，我们将测试 Magento 2、Drupal 8 和 WordPress 4。所有这些开源工具都将使用它们的默认数据。

我们有三个配置了 NGINX 作为 Web 服务器的 VPS。一个 VPS 安装了 PHP 5.5-FPM，第二个安装了 PHP 5.6-FPM，第三个安装了 PHP 7-FPM。所有三个 VPS 的硬件规格相同，我们将测试的所有应用程序都将具有相同的数据和相同的版本。

这样，我们将使用 PHP 5.5、PHP 5.6 和 PHP 7 对这些应用程序进行基准测试，并查看它们在不同版本的 PHP 上运行的速度。

### 注意

在本主题中，我们不会涉及配置带有 NGINX、PHP 和数据库的服务器。我们将假设 VPS 已配置，并且在其上安装了 Magento 2、Drupal 8 和 WordPress 4。

## Magento 2

Magento 2 安装在所有 VPS 上，并且为 Magento 启用了所有缓存。还启用了 PHP OPcache。在运行测试后，我们得到了所有三个 Magento 2 安装的平均结果，如下图所示：

![Magento 2](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_06_13.jpg)

在上图中，垂直线或 Y 轴显示每秒事务数。如图所示，Magento 2 在 PHP 7 上每秒有 29 个事务，而在相同硬件上使用 PHP 5.6 的同一 Magento 2 安装每秒有 12 个事务。此外，在 PHP 5.5 上，相同的 Magento 安装每秒有 9 个事务。因此，在这种情况下，Magento 在 PHP 7 上的运行速度比在 PHP 5.6 上快约 241%，比在 PHP 5.5 上快约 320%。这是 PHP 7 在 PHP 5.6 和 PHP 5.5 上的非常巨大的改进。

## WordPress 4

WordPress 安装在所有三个 VPS 上。不幸的是，WordPress 中没有默认缓存，我们也不会安装任何第三方模块，因此不使用缓存。结果仍然很好，如下图所示。启用了 PHP OPcache。

![WordPress 4](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_06_14.jpg)

如前图所示，WordPress 在 PHP 7 上运行速度比在 PHP 5.6 上快 135%，比在 PHP 5.5 上快 182%。

## Drupal 8

我们在同一台 VPS 上使用了 PHP 5.5、PHP 5.6 和 PHP 7。默认启用了 Drupal 8 缓存。在对 Drupal 8 的默认主页进行负载测试后，我们得到了以下结果：

![Drupal 8](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_06_15.jpg)

上图显示，Drupal 8 在 PHP 7 上的运行速度比在 PHP 5.6 上快 178%，比在 PHP 5.5 上快 205%。

### 注意

在上述图表中，所有这些值都是近似值。如果使用低性能硬件，则会生成较小的值。如果我们使用具有 Web 服务器和数据库优化的更强大的多处理器专用服务器，我们将获得更高的值。需要考虑的一点是，我们在 PHP 7 上始终会获得比 PHP 5.6 更好的性能。

这里显示了一个合并的图表，显示了不同应用程序在 PHP 7 上相对于 PHP 5.5 和 PHP 5.6 的性能改进：

![Drupal 8](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_06_16.jpg)

# 总结

在本章中，我们讨论了一些负载测试和基准测试工具，如 JMeter、ApacheBench（ab）和 Siege。我们使用每个工具进行负载测试，并讨论了输出及其含义。最后，我们对三个著名的开源应用程序进行了负载测试，分别是 Magento 2、WordPress 4 和 Drupal 8，并为每个应用程序在 PHP 7 和 PHP 5.6 中的每秒事务创建了图表。

在下一章中，我们将讨论 PHP 开发的最佳实践。这些实践不仅限于 PHP，还可以用于任何编程语言。


# 第七章：PHP 编程的最佳实践

到目前为止，我们讨论了与性能相关的主题。现在，在本章中，我们将学习 PHP 应用程序开发和部署的最佳实践。这是一个广泛的主题，但我们将简要介绍。PHP 为所有级别的程序员提供了编写高质量代码的能力。然而，当应用程序变得更加复杂时，我们忘记了遵循最佳实践。为了开发高性能的 PHP 应用程序，有必要在代码的每一行都考虑性能。

我们将涵盖以下主题：

+   编码风格

+   设计模式

+   面向服务的架构（SOA）

+   测试驱动开发（TDD）和 PHPUnit 测试

+   PHP 框架

+   版本控制系统和 Git

+   部署

# 编码风格

有太多的编码风格，比如 PSR-0、PSR-1、PSR-2、PSR-3 等等。程序员可以按照自己的意愿使用不同的标准，但有必要遵循已经在库或框架中使用的标准，以使代码更易读。例如，Laravel 使用 PSR-1 和 PSR-4 编码标准，所以如果我们在 Laravel 中开发，就应该遵循这些编码标准。一些 PHP 框架，比如 Yii 2 和 Zend Framework 2，遵循 PSR-2 编码标准。然而，这些框架都没有坚持单一标准；大多数都根据自己的需求遵循混合标准。

重要的是要遵循应用程序中使用的库的标准。组织也可以为内部目的使用自己的编码标准。这不是编码的要求，而是可读性和产生他人可以理解的高质量代码的要求。

PHP Framework Interop Group（PHP-FIG）是一个成员定义了 PHP 编码标准的团体。有关 PSR 标准的详细信息可以在他们的网站上找到[`www.php-fig.org/`](http://www.php-fig.org/)。

与讨论特定编码标准不同，让我们讨论 PHP 编码风格的最佳实践：

+   类名中每个单词的首字母必须大写。大括号应该在类声明后的行上，结束括号应该在类结束行的下一行。这是一个例子：

```php
class Foo
{
  …
  …
  …
}
```

+   类方法和函数名应遵循驼峰命名约定。起始大括号应该在类声明的下一行，结束括号应该在函数定义的最后一行。方法名和括号之间不应有空格。此外，参数和括号之间不应有空格，参数的逗号之后应有一个空格，但逗号和下一个参数之间应有一个空格。这是一个例子：

```php
public function phpBook($arg1, $arg2, $arg3)
{
  …
  …
  …
}
```

+   如果有命名空间声明，声明后必须有一个空行。如果有使用声明，所有使用声明都必须放在该命名空间声明之后。每行必须有一个使用声明，并且在使用块之后必须有一个空格。此外，`extends`和`implements`关键字必须与类声明在同一行上。这是一个例子：

```php
namespace Packt\Videos;

use Packt\Books;
use Packt\Presentations;

class PacktClass extends VideosClass implements BaseClass
{
  …
  …
  …
}
```

+   所有属性都必须声明可见性，并且属性必须使用驼峰命名法。此外，私有或受保护的属性不得以下划线开头。看下面的例子：

```php
class PacktClass
{
  public $books;
  private $electronicBooks;
  …
  …
  …
}
```

+   如果有`abstract`关键字，它必须在类关键字之前出现，对于方法，`final`关键字必须在方法的可见性之前出现。另一方面，`static`关键字必须在方法可见性之后出现。看一个例子：

```php
abstract class PacktClass
{
  final public static function favoriteBooks()
  {
    …
    …
    …
  }
}
```

+   所有 PHP 关键字必须使用小写，包括`true`和`false`关键字。常量必须以大写形式声明和使用。

+   对于所有控制结构，关键字后必须有一个空格。如果有一个表达式用于这个控制结构，那么括号中不应该有空格，后面跟着的代码块也不应该有空格。括号和开始的大括号之间必须有一个空格。开始的大括号必须在同一行上。结束的大括号必须在主体结束的下一行。参考以下代码以更好地理解：

```php
if ($book == "PHP 7") {
  …
  …
  …
} else {
  …
  …
  …
}
```

+   在循环的情况下，空格必须如下例所示：

```php
for ($h = 0; $h < 10; $h++) {
  …
  …
  …
}

foreach ($books as $key => $value) {
  …
  …
  …
}

while ($book) {
  …
  …
  …
}
```

为了本书的目的，我没有遵循大括号在控制结构声明的同一行上的规则，并且总是在声明的下一行使用它。我觉得这样做并不更清晰；这是个人选择，任何人都可以遵循这里提到的标准。

遵循标准是很好的，因为它们使代码更易读和专业。但是，永远不要试图发明自己的新标准；总是遵循已经被社区发明和遵循的标准。

# 测试驱动开发（TDD）

测试驱动开发是在开发过程中测试应用程序的每个方面。测试可以在开发之前定义，然后进行开发以通过这些测试，或者构建类和库然后进行测试。测试应用程序非常重要，没有测试就启动应用程序就像从 30 层楼高的建筑物上跳下而没有降落伞。

PHP 没有提供任何内置功能来进行测试，但有其他测试框架可以用于此目的。其中最广泛使用的框架或库之一是 PHPUnit。它是一个非常强大的工具，提供了许多功能。现在，让我们来看看它。

PHPUnit 的安装很容易。只需下载并将其放在项目的根目录中，以便可以从命令行访问。

### 注意

PHPUnit 的安装和基本细节，包括功能和示例，可以在[`phpunit.de/`](https://phpunit.de/)找到。

让我们举一个简单的例子。我们有一个`Book`类，如下所示：

```php
class Book 
{
  public $title;
  public function __construct($title)
  {
    $this->title = $title;
}

  public function getBook()
  {
    return $this->title;
  }
}
```

这是一个简单类的示例，当类被实例化时初始化`title`属性。当调用`getBook`方法时，它返回书的标题。

现在，我们想要进行一个测试，检查`getBook`方法是否返回`PHP 7`作为标题。因此，执行以下步骤创建测试：

1.  在项目的根目录下创建一个`tests`目录。在`tests`目录中创建一个`BookTest.php`文件。

1.  现在，将以下代码放入`BookTest.php`文件中：

```php
include (__DIR__.'/../Book.php');

class BookTest extends PHPUnit_Framework_TestCase 
{
  public function testBookClass()
  {
    $expected = 'PHP 7';
    $book = new Book('PHP 7');
    $actual = $book->getBook();
    $this->assertEquals($expected, $book);
  }
}
```

1.  现在，我们已经编写了我们的第一个测试。请注意，我们将我们的类命名为`BookTest`，它继承了`PHPUnit_Framework_TestCase`类。我们可以随意命名我们的测试类。但是，名称应该容易识别，这样我们就知道这是为需要测试的类编写的。

1.  然后，我们添加了一个名为`testBookClass`的方法。我们也可以自由选择给这个方法任何名称，但是它应该以单词`test`开头。如果不是，PHPUnit 将不会执行该方法，并会发出警告——在我们的情况下，对于前面的测试类，没有找到任何测试。

在`testBookClass`方法中，我们创建了一个`Book`类的对象，并将`PHP 7`作为我们的标题传递。然后，我们使用`Book`类的`getBook`方法获取标题。重要的部分是`testBookClass`方法的最后一行，它执行断言并检查从`getBook`返回的数据是否是期望的数据。

1.  现在，我们准备运行我们的第一个测试。在项目的根目录中打开命令行或终端，并发出以下命令：

```php
**php phpunit.phar tests/BookTest.php**

```

当命令被执行时，我们将得到类似以下截图的输出：

![测试驱动开发（TDD）](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_07_01.jpg)

我们的测试成功执行，因为它满足了我们测试中定义的标准。

1.  现在，让我们稍微改变我们的类，并将`PHP`传递给`Book`类，如下面的代码所示：

```php
public function testBookClass()
{
  $book = new Book('PHP');
  $title = $book->getBook();
  $this->assertEquals('PHP 7', $book);
}
```

1.  现在，我们正在寻找 PHP 7，我们的`Book`类返回`PHP`，所以它没有通过我们的测试。执行此测试后，我们将会失败，如下面的截图所示：![测试驱动开发（TDD）](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_07_02.jpg)

如前面的截图所示，我们期望得到`PHP 7`，而实际结果是`PHP 7`。`-`符号显示了期望值，`+`符号显示了实际值。

### 注意

在前面的主题中，我们讨论了如何对我们的库执行测试。我们只讨论了一个简单的基本测试。PHPUnit 不仅限于这些简单的测试，但完全覆盖 PHPUnit 超出了本书的范围。一本关于 PHPUnit 的很好的书是 Packt Publishing 出版的*PHPUnit Essentials*。

# 设计模式

设计模式解决特定问题。它不是一个工具；它只是描述或模板，描述如何解决特定问题。设计模式很重要，在编写清晰的代码方面起着很好的作用。

在 PHP 社区中最广泛使用的设计模式之一是**模型视图控制器**（**MVC**）模式。大多数 PHP 框架都建立在这种模式之上。MVC 建议将业务逻辑和数据操作（即模型）与表示（视图）分开。控制器只是在模型和视图之间充当中间人的角色，并使它们之间的通信成为可能。模型和视图之间没有直接的通信。如果视图需要任何类型的数据，它会向控制器发送请求。控制器知道如何处理这个请求，并在需要时调用模型对数据进行任何操作（获取、插入、验证、删除等）。然后最后，控制器向视图发送响应。

在最佳实践中，使用肥模型和瘦控制器。这意味着控制器仅用于对请求执行特定操作，而不做其他事情。甚至在一些现代框架中，验证被移出控制器，并在模型层执行。这些模型执行所有数据操作。在现代框架中，模型被视为一个层，可以有多个部分，如业务逻辑、**创建读取更新删除**（**CRUD**）数据库操作、数据映射器模式和服务等。因此，模型和控制器的全部负载只是坐在那里，享受懒惰的工作负载。

另一个广泛使用的设计模式是工厂设计模式。这种模式简单地创建需要使用的对象。另一个好的模式是观察者模式，其中一个对象在特定事件或任务上调用不同的观察者。这主要用于事件处理。另一个广泛使用的模式是单例模式，当需要在应用程序执行期间仅使用类的单个对象时使用。单例对象无法序列化和克隆。

# 面向服务的架构（SOA）

在面向服务的架构中，应用程序的组件在定义的协议上为彼此提供服务。每个组件之间松散耦合，它们之间的通信方式是通过它们提供的服务。

在 PHP 中，Symfony 提供了拥有 SOA 的最佳方式，因为它主要是一个以 HTTP 为中心的框架。Symfony 是最成熟、经过充分测试的库集合，被其他 PHP 框架广泛使用，如 Zend Framework、Yii、Laravel 等。

让我们考虑一个情景，我们有一个网站和一个移动应用的后端和前端。通常，在大多数应用程序中，后端和前端在同一代码库和单一访问点上运行，并且为移动应用构建了一个 API 或 Web 服务来与后端通信。这很好，但我们需要更好。因此，对于高性能和可扩展的应用程序，各个组件独立运行。如果它们需要相互通信，它们通过 Web 服务进行通信。

Web 服务是前端和后端之间以及后端和移动应用之间的中心通信点。后端是数据和任何其他业务逻辑的主要枢纽。它可以独立运行，并使用任何编程语言构建，比如 PHP。前端可以使用普通的 HTML/CSS、AngularJS、Node.js、jQuery 或任何其他前端技术构建。同样，移动应用可以是原生的，也可以基于跨平台技术构建。后端不关心前端和移动应用是基于什么构建的。

# 始终是面向对象和可重用的

对于一个小型的单页应用程序来说，这可能看起来很困难，只有少数事情发生，但事实并非如此。类很容易处理，代码始终清晰。此外，类将应用程序逻辑与视图分离。这使得事情更加合乎逻辑。在早期使用结构化代码和必须在视图文件或单独文件中创建一堆函数时，这将变得太容易。然而，当应用程序变得更加复杂时，处理起来就更加困难。

始终尝试创建松耦合的类，使它们在其他应用程序中更具重用性。此外，始终在类的每个方法中执行单个任务。

# PHP 框架

我们都知道框架，并且它们对程序员的生活并非必不可少。有很多框架，每个框架在某些功能上都有其自身的优势。所有框架都很好，但使框架不适合应用程序的是应用程序的需求。

假设我们想构建一个企业级的 CRM 应用程序，哪种框架最适合我们？这是最重要、最令人困惑和最浪费时间的问题。首先，我们需要了解 CRM 应用程序的完整需求、使用容量、功能、数据安全性和性能。

# 版本控制系统（VCS）和 Git

版本控制系统提供了灵活性，可以正确地维护应用程序的代码、更改和版本。使用 VCS，整个团队可以共同在一个应用程序上工作，他们可以从系统中拉取其他团队成员的更改和自己的更改，而不会有太大的麻烦。在灾难发生时，VCS 提供了回退到旧的、更稳定版本的应用程序的能力。

哦等等！我们在谈论版本控制系统吗？我们提到了 Git 吗？没有！所以，让我们从 Git 开始。

Git 是一个强大的工具。它监视分支中每个文件的更改，当推送到远程分支时，只上传更改的文件。Git 保留文件更改的历史记录，并提供您比较更改文件的能力。

### 注意

关于 Git 的一本非常信息丰富且优秀的书是 Packt Publishing 出版的*Git Essentials*。此外，关于 Git 的官方免费书籍可以在[`git-scm.com/book/en/v2`](https://git-scm.com/book/en/v2)找到。

# 部署和持续集成（CI）

FTP 已经过时。对于今天来说不可行，它会使事情变慢，而且普通的 FTP 连接是不安全的。团队使用 FTP 部署其更改是困难的，因为它会在他们的代码中造成巨大的冲突，这可能会在上传更改时造成问题，并且可能会覆盖彼此的更改。

使用 Git 版本控制系统，如 GitHub、GitLab 和 Bitbucket，我们可以使部署自动化。不同的开发人员使用不同的自动部署设置，这完全取决于他们自己的选择和便利性。使用自动部署的一般规则是使团队易于使用，并且不使用 FTP。

以下是部署设置的一般流程图：

![部署和持续集成（CI）](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_07_03.jpg)

如前面的流程图所示，我们有两个服务器：暂存或测试服务器和生产服务器。在暂存服务器上，我们有网站的精确副本，用于测试新功能和其他内容，而生产服务器则有我们的实时网站。

现在，我们有一个具有两个主要分支的存储库：主分支和生产分支。主分支用于开发和测试目的，而生产分支用于最终生产功能。请注意，生产分支应仅接受合并，不应接受提交，以便生产环境完全安全。

现在，假设我们想要向我们的应用程序添加客户注册功能。我们将执行以下步骤：

1.  首先，也是最重要的是从生产分支头部创建一个新分支。让我们将此分支命名为`customer-registration`。

1.  现在，将所有新功能添加到`customer-registration`分支，并在本地开发服务器上验证后，将此分支合并到本地主分支。

1.  将新分支合并到本地主分支后，将主分支推送到远程主分支。成功推送将导致新功能移动到暂存服务器。

1.  现在，在暂存服务器上测试所有新功能。

1.  当一切正常时，将远程主分支与远程生产分支合并。这将导致所有更改移动到生产分支，并且此合并将导致所有新更改移动到生产服务器。

1.  类似于前面的设置，一个理想的设置使部署非常容易，整个团队可以在不同的地理位置工作应用程序。如果在部署过程中出现任何问题，可以轻松地回退到旧版本的生产分支。

**持续集成**（**CI**）是一种技术，团队的所有成员都必须将其代码集成到共享存储库中，然后团队成员的每次检查都经过自动构建进行验证，以捕获早期阶段的错误和问题。

有几种用于 PHP 的 CI 工具；其中一些是 PHPCI、Jenkins、Travis CI 等。

# 总结

在本章中，我们讨论了一些最佳实践，包括编码标准和风格、PHP 框架、设计模式、Git 和部署。此外，我们还讨论了 PHPUnit 框架，用于对类和库进行测试。此外，我们还讨论了面向服务的设计，在为应用程序创建 API 方面发挥了重要作用。

在本书中，我们研究了设置开发环境，包括 Linux 服务器，特别是 Debian 和 Ubuntu，我们还讨论了 Vagrant。还列出了 PHP 的新功能，并附有示例代码。您可以详细了解我们可以使用的工具，以提高应用程序和数据库的性能。此外，我们还讨论了调试和应力或负载测试我们的应用程序以及编写高质量代码的一些最佳实践。

我们主要总结了工具和技术，并提供了简单的示例，向读者介绍这些工具和技术。每种工具和技术都有可能有自己的书籍，用于更高级的用途。我们建议您跟进这些工具和技术，并进行更多的研究以了解其高级用途。祝您 Php-ing 好运！


# 附录 A. 使生活更轻松的工具

我们在本书中涵盖了许多内容，从 PHP 7 中的新功能开始，到编程中的最佳技术结束。在每一章中，我们都使用并讨论了一些工具，但由于章节和书籍的有限长度，我们没有对这些工具进行太多详细介绍。在这个附录中，我们将更详细地讨论其中三个工具。我们将讨论的工具如下：

+   Composer

+   Git

+   Grunt watch

所以，让我们开始吧。

# Composer – PHP 的依赖管理器

Composer 是 PHP 的依赖管理工具，它使我们能够为 PHP 应用程序定义依赖关系，并安装/更新它们。Composer 完全由 PHP 编写，并且是 PHP 存档（PHAR）格式的应用程序。

### 注意

Composer 从[`packagist.org/`](https://packagist.org/)下载依赖项。只要在 Packagist 上可用，就可以通过 Composer 安装应用程序的任何依赖项。此外，如果在 Packagist 上可用，还可以通过 Composer 安装完整的应用程序。

## Composer 安装

Composer 是一个命令行工具，可以在操作系统中全局安装，或者可以将`composer.phar`文件放在应用程序的根目录中，然后从命令行执行。对于 Windows，提供了一个可执行的安装程序文件，可以用于全局安装 Composer。对于本书，我们将遵循 Debian/Ubuntu 全局安装的说明。执行以下步骤：

1.  发出以下命令以下载 Composer 安装程序。文件名为`installer`，安装后只能通过以下代码使用 PHP 执行：

```php
**Wget https://getcomposer.org/installer**

```

1.  发出以下命令在 Debian 或 Ubuntu 上全局安装它：

```php
**Php install --install-dir=/usr/local/bin --filename=composer**

```

此命令将下载 Composer 并将其安装在`/usr/local/bin`目录中，文件名为`composer`。现在，我们将能够全局运行 Composer。

1.  通过在终端中发出以下命令来验证 Composer 安装：

```php
**Composer --version**

```

如果显示 Composer 版本，则 Composer 已成功全局安装。

### 注意

如果 Composer 是安装在应用程序本地的，那么我们将有一个`composer.phar`文件。命令是相同的，但所有命令都应该使用 PHP 执行。例如，`php composer.phar --version`将显示 Composer 版本。

现在，Composer 已成功安装并且正在工作；是时候使用它了。

## 使用 Composer

要在我们的项目中使用 Composer，我们将需要一个`composer.json`文件。该文件包含项目所需的所有依赖项和一些其他元数据。Composer 使用此文件来安装和更新不同的库。

假设我们的应用程序需要以不同的方式记录不同的信息。为此，我们可以使用`monolog`库。首先，在应用程序的根目录中创建一个`composer.json`文件，并添加以下代码：

```php
{
  "require": {
    "monolog/monolog": "1.0.*"
  }
}
```

保存文件后，执行以下命令安装应用程序的依赖项：

```php
Composer install
```

此命令将下载依赖项并将它们放在`vendor`目录中，如下面的屏幕截图所示：

![使用 Composer](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_appendix_a_01.jpg)

如前面的屏幕截图所示，下载了 monolog 版本 1.0.2，并创建了一个`vendor`目录。`monolog`库放在这个目录中。此外，如果一个包需要自动加载信息，Composer 会将库放在 Composer 自动加载器中，该自动加载器也放在`vendor`目录中。因此，在应用程序执行期间，任何新的库或依赖项都将自动加载。

还可以看到一个新文件，名为`composer.lock`。当 Composer 下载和安装任何依赖项时，确切的版本和其他信息将写入此文件，以锁定应用程序到这些依赖项的特定版本。这确保所有团队成员或任何想要设置应用程序的人将使用相同的依赖项版本，从而减少使用不同版本的依赖项的可能性。

如今，Composer 被广泛用于包管理。大型开源项目，如 Magento、Zend Framework、Laravel、Yii 等，都可以通过 Composer 轻松安装。我们将在下一个附录中使用 Composer 安装其中一些。

# Git-版本控制系统

Git 是最广泛使用的版本控制系统。根据 Git 官方网站，它是一个分布式版本控制系统，能够处理从小型到大型项目的一切事务，并具有速度和效率。

## Git 安装

Git 适用于所有主要操作系统。对于 Windows，提供了一个可执行的安装程序文件，可以用于安装 Git 并在命令行中使用它。在 OS X 上，Git 已经安装好了，但如果找不到，可以从官方网站下载。要在 Debian/Ubuntu 上安装 Git，只需在终端中发出以下命令：

```php
**sudo apt-get install git**

```

安装完成后，发出以下命令检查是否已正确安装：

```php
**git –version**

```

然后，我们将查看 Git 的当前安装版本。

## 使用 Git

为了更好地理解 Git，我们将从一个测试项目开始。我们的测试项目名称是`packt-git`。对于这个项目，我们还创建了一个名为`packt-git`的 GitHub 存储库，我们将在其中推送我们的项目文件。

首先，我们将通过发出以下命令在我们的项目中初始化 Git：

```php
**git init**

```

上述命令将在我们的项目根目录中初始化一个空的 Git 存储库，并将头保留在主分支上，这是每个 Git 存储库的默认分支。它将创建一个名为`.git`的隐藏目录，其中包含有关存储库的所有信息。接下来，我们将添加一个远程存储库，我们将在 GitHub 上创建。我在 GitHub 上创建了一个测试存储库，其 URL 为[`github.com/altafhussain10/packt-git.git`](https://github.com/altafhussain10/packt-git.git)。

现在，发出以下命令将 GitHub 存储库添加到我们的空存储库中：

```php
**git remote add origion https://github.com/altafhussain10/packt-git.git**

```

现在，在项目根目录创建一个`README.md`文件，并向其中添加一些内容。`README.md`文件用于显示存储库信息和有关 Git 存储库的其他详细信息。该文件还用于显示有关如何使用创建此存储库的项目的存储库和/或项目的说明。

现在，发出以下命令来查看我们的 Git 存储库的状态：

```php
**git status**

```

这个命令将显示存储库的状态，如下面的屏幕截图所示：

![使用 Git](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_appendix_a_02.jpg)

如前面的屏幕截图所示，我们的存储库中有一个未跟踪的文件尚未提交。首先，我们将通过在终端中发出以下命令来添加要跟踪的文件：

```php
**git add README.md** 

```

`git add`命令使用当前工作树中找到的当前内容更新索引。此命令将添加对路径所做的所有更改。有一些选项可用于添加一些特定更改。我们之前使用的命令将只将`README.md`文件添加到存储库中进行跟踪。因此，如果我们想要跟踪所有文件，那么我们将使用以下命令：

```php
**git add**

```

这将开始跟踪当前工作目录中的所有文件或当前分支的根目录。现在，如果我们想要跟踪一些特定的文件，比如所有带有`.php`扩展名的文件，那么我们可以使用如下方式：

```php
**git add '*.php**

```

这将添加所有带有`.php`扩展名的文件进行跟踪。

接下来，我们将使用以下命令提交对我们的存储库的更改或添加：

```php
**git commit –m "Initial Commit"**

```

`git commit`命令将所有更改提交到本地存储库。`-m`标志指定要`commit`的任何日志消息。请记住，更改只提交到本地存储库。

现在，我们将使用以下命令将更改推送到我们的远程存储库：

```php
**git push –u origion master**

```

上述命令将把本地存储库中的所有更改推送到远程存储库或原始存储库。`-u`标志用于设置上游，它将我们的本地存储库链接到我们的远程中央存储库。因为我们第一次推送了更改，所以我们必须使用`-u`选项。之后，我们只需使用以下命令：

```php
**git push**

```

这将把所有更改推送到我们当前所在的主分支的主存储库。

## 创建新分支和合并

在开发过程中总是需要新分支。如果需要任何更改，最好为这些更改创建一个新分支。然后，在此分支上进行所有更改，最后提交、合并并推送到远程存储库。

为了更好地理解这一点，让我们假设我们想要修复登录页面上的问题。问题是关于验证错误的。我们将为我们的新分支命名为`login_validation_errors_fix`。给分支起一个更易理解的名字是一个好习惯。此外，我们希望从主分支头部创建这个新分支。这意味着我们希望新分支继承主分支的所有数据。因此，如果我们不在主分支上，我们必须使用以下命令切换到主分支：

```php
**git checkout master**

```

上述命令将无论我们在哪个分支，都会将我们切换到主分支。要创建分支，在终端中发出以下命令：

```php
**git branch login_validation_errors_fix**

```

现在，我们的新分支是从主分支头部创建的，因此所有更改都应该在这个新分支上进行。完成所有更改和修复后，我们必须将更改提交到本地和远程存储库。请注意，我们没有在远程存储库中创建新分支。现在，让我们使用以下命令提交更改：

```php
**git commit -a -m "Login validation errors fix"**

```

请注意，我们没有使用`git add`来添加更改或新添加。为了自动提交我们的更改，我们在`commit`中使用了`-a`选项，这将自动添加所有文件。如果使用了`git add`，则在`commit`中就不需要使用`-a`选项。现在，我们的更改已经提交到本地存储库。我们需要将更改推送到远程存储库。在终端中发出以下命令：

```php
**git push -u origion login_validation_errors_fix**

```

上述命令将在远程存储库创建一个新分支，将相同的本地分支跟踪到远程分支，并将所有更改推送到远程存储库。

现在，我们想要将更改与我们的主分支合并。首先，我们需要使用以下命令切换到我们的主分支：

```php
**git checkout master**

```

接下来，我们将发出以下命令，将我们的新分支`login_validation_errors_fix`与主分支合并：

```php
**git checkout master**
**git merge login_validation_errors_fix** 
**git push**

```

重要的是要切换到我们想要合并新分支的分支。之后，我们需要使用`git merge branch_to_merge`语法将此分支与当前分支合并。最后，我们只需推送到远程存储库。现在，如果我们查看远程存储库，我们将看到新分支以及主分支中的更改。

## 克隆存储库

有时，我们需要在托管在存储库上的项目上工作。为此，我们将首先克隆此存储库，这将把完整的存储库下载到我们的本地系统，并为此远程存储库创建一个本地存储库。其余的工作与我们之前讨论的一样。要克隆存储库，我们应该首先知道远程存储库的网址。假设我们想要克隆`PHPUnit`存储库。如果我们转到 PHPUnit 的 GitHub 存储库，我们将在右上角看到存储库的网址，如下面的截图所示：

![克隆存储库](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_appendix_a_03.jpg)

**HTTPS**按钮后面的 URL 是此存储库的网址。复制此 URL 并使用以下命令克隆此存储库：

```php
**git clone https://github.com/sebastianbergmann/phpunit.git**

```

这将开始下载存储库。完成后，我们将有一个`PHPUnit`文件夹，其中包含存储库及其所有文件。现在，可以执行前面主题中提到的所有操作。

## Webhooks

Git 最强大的功能之一是 webhooks。Webhooks 是在存储库上发生特定操作时触发的事件。如果对`Push`请求进行了事件或挂钩，那么每次向此存储库进行推送时都会触发此挂钩。

要向存储库添加 webhook，请单击右上角的**设置**链接。在新页面中，左侧将有一个**Webhooks and Services**链接。单击它，我们将看到类似以下页面的页面：

![Webhooks](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_appendix_a_04.jpg)

如前面的屏幕截图所示，我们必须输入有效负载 URL，每次选择的事件触发时都会调用它。在**内容类型**中，我们将选择将有效负载发送到我们的 URL 的数据格式。在事件部分，我们可以选择是否只想要推送事件或所有事件；我们可以选择多个事件，希望此挂钩被触发。保存此挂钩后，每次发生所选事件时都会触发它。

Webhooks 主要用于部署。当更改被推送并且推送事件有一个 webhook 时，将调用特定的 URL。然后，此 URL 执行一些命令来下载更改并在本地服务器上处理它们，并将它们放置在适当的位置。此外，webhooks 用于持续集成和部署到云服务。

## 管理存储库的桌面工具

有几种工具可用于管理 Git 存储库。GitHub 提供了自己的名为 GitHub Desktop 的工具，可用于管理 GitHub 存储库。它可用于创建新存储库，查看历史记录，并推送、拉取和克隆存储库。它提供了我们可以在命令行中使用的每个功能。接下来的屏幕截图显示了我们的测试`packt-git`存储库：

![管理存储库的桌面工具](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_appendix_a_05.jpg)

### 注意

GitHub Desktop 可以从[`desktop.github.com/`](https://desktop.github.com/)下载，仅适用于 Mac 和 Windows。此外，GitHub Desktop 只能与 GitHub 一起使用，除非使用一些技巧使其与其他存储库（如 GitLab 或 Bitbucket）一起工作。

另一个强大的工具是 SourceTree。SourceTree 可以轻松与 GitHub、GitLab 和 Bitbucket 一起使用。它提供了完整的功能来管理存储库，包括拉取、推送、提交、合并和其他操作。SourceTree 为分支和提交提供了一个非常强大和美观的图形工具。以下是用于连接到我们的`packt-git`测试存储库的 SourceTree 的屏幕截图：

![管理存储库的桌面工具](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_appendix_a_06.jpg)

除了前面介绍的两个好工具外，每个开发 IDE 都提供完整支持的版本控制系统，并提供诸如不同颜色表示修改和新添加文件等功能。

### 注意

Git 是一个强大的工具；这个附录无法涵盖它。有几本书可供选择，但 Git Book 是一个很好的起点。可以从[`git-scm.com/book/en/v2`](https://git-scm.com/book/en/v2)以不同格式下载，也可以在线阅读。

# Grunt watch

我们在第三章中学习了 Grunt，*改进 PHP 7 应用程序性能*。我们只用它来合并 CSS 和 JavaScript 文件并对其进行缩小。然而，Grunt 不仅用于此目的。它是一个 JavaScript 任务运行器，可以通过监视特定文件的更改或手动运行任务来运行任务。我们学习了如何手动运行任务，现在我们将学习如何使用 grunt watch 在进行一些更改时运行特定任务。

Grunt watch 非常有用，可以节省大量时间，因为它会自动运行特定任务，而不是每次更改时手动运行任务。

让我们回顾一下第三章中的例子，*改进 PHP 7 应用程序性能*。我们使用 Grunt 来合并和压缩 CSS 和 JavaScript 文件。为此，我们创建了四个任务。一个任务是合并所有 CSS 文件，第二个任务是合并所有 JavaScript 文件，第三个任务是压缩 CSS 文件，第四个任务是压缩所有 JavaScript 文件。如果我们每次进行一些更改都要手动运行所有这些任务，那将会非常耗时。Grunt 提供了一个名为 watch 的功能，它会监视不同的目标文件夹以检测文件更改，如果发生任何更改，它会执行在 watch 中定义的任务。

首先，检查`grunt watch`模块是否已安装。检查`node_modules`目录，看看是否有另一个名为`grunt-contrib-watch`的目录。如果有这个目录，那么 watch 已经安装。如果没有这个目录，那么只需在项目根目录中包含`GruntFile.js`的终端中发出以下命令：

```php
**npm install grunt-contrib-watch**

```

上面的命令将安装 Grunt watch，`grunt-contrib-watch`目录将与`watch`模块一起可用。

现在，我们将修改`GruntFile.js`文件以添加`watch`模块，它将监视我们定义的目录中的所有文件，如果发生任何更改，它将自动运行这些任务。这将节省大量时间，不再需要手动执行这些任务。看一下以下代码；高亮显示的代码是修改后的部分：

```php
module.exports = function(grunt) {
  /*Load the package.json file*/
  pkg: grunt.file.readJSON('package.json'),
  /*Define Tasks*/
  grunt.initConfig({
    concat: {
      css: {
      src: [
        'css/*' //Load all files in CSS folder
],
      dest: 'dest/combined.css' //Destination of the final combined file.

      },//End of CSS
js: {
      src: [
        'js/*' //Load all files in js folder
],
       dest: 'dest/combined.js' //Destination of the final combined file.

      }, //End of js

}, //End of concat
cssmin:  {
  css: {
    src : 'dest/combined.css',
    dest : 'dest/combined.min.css' 
}
}, //End of cssmin
uglify: {
  js: {
        files: {
        'dest/combined.min.js' : ['dest/combined.js']//destination Path : [src path]
}
}
}, //End of uglify

//The watch starts here
**watch: {**
 **mywatch: {**
 **files: ['css/*', 'js/*', 'dist/*'],**
 **tasks: ['concat', 'cssmin', 'uglify']**
 **},**
**},**
}); //End of initConfig

**grunt.loadNpmTasks('grunt-contrib-watch'); //Include watch module**
grunt.loadNpmTasks('grunt-contrib-concat');
grunt.loadNpmTasks('grunt-contrib-uglify');
grunt.loadNpmTasks('grunt-contrib-cssmin');
grunt.registerTask('default', ['concat:css', 'concat:js', 'cssmin:css', 'uglify:js']);
}; //End of module.exports
```

在上面的高亮代码中，我们添加了一个`watch`块。`mywatch`标题可以是任何名称。`files`块是必需的，它接受一个源路径的数组。Grunt watch 会监视这些目的地的更改，并执行在 tasks 块中定义的任务。此外，tasks 块中提到的任务已经在`GruntFile.js`中创建。此外，我们必须使用`grunt.loadNpmTasks`加载`watch`模块。

现在，在项目根目录打开终端，其中包含`GruntFile.js`，并运行以下命令：

```php
**grunt watch**

```

Grunt 将开始监视源文件的更改。现在，在`GruntFile.js`中的`files`块中修改任何文件，并保存该文件。一旦保存文件，任务将被执行，并且任务的输出将显示在终端中。以下截图中可以看到示例输出：

![Grunt watch](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_appendix_a_07.jpg)

在`watch`块中可以监视尽可能多的任务，但是这些任务应该存在于`GruntFile.js`中。

# 总结

在本附录中，我们讨论了 Composer 以及如何使用它来安装和更新软件包。此外，我们详细讨论了 Git，包括推送、拉取、提交、创建分支和合并不同的分支。此外，我们还讨论了 Git 钩子。最后，我们讨论了 Grunt watch，并创建了一个监视器，每当`GruntFile.js`中定义的文件路径发生更改时，就会执行四个任务。


# 附录 B. MVC 和框架

我们在不同章节中提到了一些框架的名称，但没有讨论它们。在今天的世界中，我们不会重新发明轮子；我们会在已经构建、测试和广泛使用的工具基础上进行构建。因此，作为最佳实践，如果没有可用的工具来满足需求，我们可以使用最适合需求的框架来构建它。

我们将涵盖以下主题：

+   MVC 设计模式

+   Laravel

+   Lumen

+   Apigility

# MVC 设计模式

**模型视图控制器**（**MVC**）是一种广泛应用于不同编程语言中的设计模式。大多数 PHP 框架使用这种设计模式。这种模式将应用程序分为三层：模型、视图和控制器。每个层都有不同的任务，并且它们都相互连接。MVC 有不同的视觉表示，但是可以在以下图表中看到一个整体和简单的表示：

![MVC 设计模式](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_AppendixB_01.jpg)

现在，让我们讨论 MVC 设计模式的每个部分。

## 模型

模型层是应用程序的支柱，处理数据逻辑。大多数情况下，认为模型负责对数据库进行 CRUD 操作，这可能是真实的，也可能不是。正如我们之前提到的，模型负责数据逻辑，这意味着数据验证操作也可以在这里执行。简单地说，模型为数据提供了一个抽象。其余的应用层不知道或不关心数据来自何处，或者如何对数据执行操作。这是模型的责任，负责处理所有数据逻辑。

在当今复杂的框架结构中，整体 MVC 结构已经改变，不仅模型处理数据操作，而且每个其他应用逻辑也由模型处理。遵循的方法是“胖模型，瘦控制器”，这意味着将所有应用逻辑放在模型中，使控制器尽可能清晰。

## 视图

视图是最终用户可见的内容。与此用户和公众相关的所有数据都显示在视图中，因此视图可以被称为模型的视觉表示。视图需要数据来显示。它向控制器请求一些特定的数据或操作。视图不知道或不想知道控制器从何处获取这些数据；它只是要求控制器获取它。控制器知道要向谁请求这些特定的数据，并与特定的模型进行通信。这意味着视图没有直接连接到模型。然而，在早期的图表中，我们直接将模型与视图连接起来。这是因为在现今的先进系统中，视图可以直接从模型获取数据。例如，Magento 控制器无法将数据发送回视图。对于数据（即直接从数据库获取数据）和/或与模型通信，视图与块和辅助类进行通信。在现代实践中，视图可以直接连接到模型。

## 控制器

控制器响应用户在视图中执行的操作，并响应视图。例如，用户填写表单并提交。在这里，控制器介入并开始对表单的提交采取行动。现在，控制器将首先检查用户是否被允许发出此请求。然后，控制器将采取适当的行动，例如与模型或任何其他操作进行通信。简单地说，控制器是视图和模型之间的中间人。正如我们之前在模型部分提到的，控制器应该是精简的。因此，大多数情况下，控制器仅用于处理请求并与模型和视图进行通信。所有类型的数据操作都在模型中执行。

MVC 设计模式的唯一工作是分离应用程序中不同部分的责任。因此，模型用于管理应用程序数据。控制器用于对用户输入进行操作，视图负责数据的视觉表示。正如我们之前提到的，MVC 分离了每个部分的责任，因此无论是从控制器还是视图访问模型都无关紧要；唯一重要的是视图和控制器不应该用于对数据执行操作，因为这是模型的责任，控制器也不应该用于查看任何类型的数据，因为这是视图的责任。

# Laravel

Laravel 是最流行的 PHP 框架之一，根据 Laravel 官方网站的说法，它是一个面向 Web 工匠的框架。Laravel 美观、强大，并且拥有大量功能，可以让开发人员编写高效和高质量的代码。Laravel 官方文档写得很好，非常容易理解。所以，让我们来玩一下 Laravel 吧。

## 安装

安装非常简单。让我们使用 Composer 来安装 Laravel。我们在附录 A 中讨论了 Composer。在终端中输入以下命令来安装并创建一个 Laravel 项目：

```php
**composer create-project --prefer-dist laravel/laravel packt**

```

如果系统上没有全局安装 Composer，将`composer.phar`放在应该安装 Laravel 的目录中，并在该目录的根目录下在终端中输入以下命令：

```php
**php composer.phar create-project --prefer-dist laravel/laravel packt**

```

现在，Laravel 将被下载，并将创建一个名为`packt`的新项目。此外，Composer 将下载并安装项目的所有依赖项。

打开浏览器，转到项目的 URL，我们将受到一个简单的页面，上面写着**Laravel 5**。

### 注意

截至撰写本书时，Laravel 5.2.29 是最新版本。但是，如果使用 Composer，则每次使用`composer update`命令时，Laravel 和所有其他组件都将自动更新。

## 功能

Laravel 提供了大量的功能，我们在这里只讨论一些。

### 路由

Laravel 提供了强大的路由。路由可以分组，并且可以为路由组定义前缀、命名空间和中间件。此外，Laravel 支持所有 HTTP 方法，包括`POST`、`GET`、`DELETE`、`PUT`、`OPTIONS`和`PATCH`。所有路由都在应用程序的`app`文件夹中的`routes.php`文件中定义。看一下以下示例：

```php
Route::group(['prefix' => 'customer', 'namespace' => 'Customer', 'middleware' => 'web'], function() {
    Route::get('/', 'CustomerController@index');
    Route::post('save', 'CustomerController@save');
    Route::delete('delete/{id}', 'CustomerController@delete');
});
```

在上面的代码片段中，我们创建了一个新的路由组。只有当 URL 有一个前缀为 customer 时才会使用这个组。例如，如果 URL 类似于`domain.com/customer`，则将使用此组。我们还使用了一个 customer 命名空间。命名空间允许我们使用标准的 PHP 命名空间并将文件分割成子文件夹。在上面的示例中，所有 customer 控制器可以放在`Controllers`目录中的 Customer 子文件夹中，并且控制器将如下创建：

```php
namespace App\Http\Controllers\Customer

use App\Http\{
Controllers\Controller,
Requests,
};
use Illuminate\Http\Request;

Class CustomerController extends Controller
{
  …
  …
}
```

因此，对路由组进行命名空间使我们能够将控制器文件放在易于管理的子文件夹中。此外，我们使用了 web 中间件。中间件提供了一种在进入应用程序之前过滤请求的方法，这使我们可以使用它来检查用户是否已登录，CSRF 保护，或者是否有任何其他需要在请求发送到应用程序之前执行的中间件操作。Laravel 带有一些中间件，包括`web`、`api`、`auth`等。

如果路由定义为`GET`，则不能向该路由发送`POST`请求。这非常方便，使我们不必担心请求方法过滤。但是，HTML 表单不支持`DELETE`、`PATCH`和`PUT`等 HTTP 方法。为此，Laravel 提供了方法欺骗，其中使用带有`name _method`和 HTTP 方法值的隐藏表单字段，以使此请求成为可能。例如，在我们的路由组中，为了使删除路由的请求成为可能，我们需要一个类似于以下的表单：

```php
<form action="/customer/delete" method="post">
  {{ method_field('DELETE') }}
  {{ csrf_field() }}
</form>
```

当提交上述表单时，它将起作用，并且将使用删除路由。此外，我们创建了一个 CSRF 隐藏字段，用于 CSRF 保护。

### 注意

Laravel 路由非常有趣，是一个大的话题。更深入的细节可以在[`laravel.com/docs/5.2/routing`](https://laravel.com/docs/5.2/routing)找到。

## Eloquent ORM

Eloquent ORM 提供了与数据库交互的活动记录。要使用 Eloquent ORM，我们只需从 Eloquent 模型扩展我们的模型。让我们看一个简单的用户模型，如下所示：

```php
namespace App;

use Illuminate\Database\Eloquent\Model;

class user extends Model
{
  //protected $table = 'customer';
  //protected $primaryKey = 'id_customer';
  …
  …
}
```

就是这样；我们现在有一个可以处理所有 CRUD 操作的模型。请注意，我们已经注释了`$table 属性`，并对`$primaryKey`做了相同的操作。这是因为 Laravel 使用类的复数名称来查找表，除非表是使用受保护的`$table 属性`定义的。在我们的情况下，Laravel 将查找表名 users 并使用它。但是，如果我们想使用名为`customers`的表，我们只需取消注释该行，如下所示：

```php
protected $table = 'customers';
```

同样，Laravel 认为表将具有列名`id`的主键。但是，如果需要另一列，我们可以覆盖默认的主键，如下所示：

```php
protected $primaryKey = 'id_customer';
```

优雅的模型也使时间戳变得容易。默认情况下，如果表具有`created_at`和`updated_at`字段，则这两个日期将自动生成并保存。如果不需要时间戳，可以禁用如下：

```php
protected $timestamps = false;
```

将数据保存到表中很容易。表列被用作模型的属性，因此，如果我们的`customer`表具有诸如`name`、`email`、`phone`等列，我们可以在路由部分提到的`customer`控制器中设置它们，如下所示：

```php
namespace App\Http\Controllers\Customer

use App\Http\{
Controllers\Controller,
Requests,
};
use Illuminate\Http\Request;
use App\Customer

Class CustomerController extends Controller
{
  public function save(Request $request)
  {
    $customer = new Customer();
    $customer->name = $request->name;
    $customer->email = $request->email;
    $customer->phone = $request->phone;

    $customer->save();

  }
}
```

在上面的示例中，我们向我们的控制器添加了`save`操作。现在，如果提交了`POST`或`GET`请求以及表单数据，Laravel 将所有表单提交的数据分配给一个 Request 对象，作为与表单字段相同名称的属性。然后，使用此请求对象，我们可以访问通过`POST`或`GET`提交的所有数据。在将所有数据分配给模型属性（与表列的名称相同）之后，我们只需调用 save 方法。现在，我们的模型没有任何保存方法，但是其父类，即 Eloquent 模型，已经定义了此方法。但是，如果需要此方法中的其他功能，我们可以在我们的`model`类中覆盖此`save`方法。

从 Eloquent 模型中获取数据也很容易。让我们尝试一个例子。向`customer`控制器添加一个新操作，如下所示：

```php
public function index()
{
  $customers = Customer::all();
}
```

我们在模型中使用了`all()`静态方法，它基本上是在 Eloquent 模型中定义的，反过来获取了我们的`customers`表中的所有数据。现在，如果我们想要通过主键获取单个客户，我们可以使用`find($id)`方法，如下所示：

```php
$customer = Customer::find(3);
```

这将获取 ID 为`3`的客户。

更新很简单，使用相同的`save()`方法，如下所示：

```php
$customer = Customer::find(3);
$customer->name = 'Altaf Hussain';

$customer->save();
```

这将更新 ID 为`3`的客户。首先，我们加载了`customer`，然后我们为其属性分配了新数据，然后调用了相同的`save()`方法。删除模型简单易行，可以按如下方式完成：

```php
$customer = Customer::find(3);
$customer->delete();
```

我们首先加载了 ID 为`3`的客户，然后调用了`delete`方法，这将删除 ID 为`3`的客户。

### 注意

Laravel 的 Eloquent 模型非常强大，并提供了许多功能。这些在文档中有很好的解释，网址为[`laravel.com/docs/5.2/eloquent`](https://laravel.com/docs/5.2/eloquent)。Laravel 数据库部分也值得阅读，网址为[`laravel.com/docs/5.2/database`](https://laravel.com/docs/5.2/database)。

## Artisan CLI

Artisan 是 Laravel 提供的命令行界面，它有一些很好的命令可以用于更快的操作。它有很多命令，可以使用以下命令查看完整列表：

```php
**php artisan list**

```

这将列出所有可用的选项和命令。

### 注意

`php artisan`命令应该在`artisan`文件所在的同一目录中运行。它被放置在项目的根目录下。

一些基本命令如下：

+   `make:controller`: 这个命令在`Controllers`文件夹中创建一个新的控制器。可以如下使用：

```php
**php artisan make:controller MyController**

```

如果需要一个有命名空间的控制器，就像之前的`Customer`命名空间一样，可以如下操作：

```php
**php artisan make:controller Customer/CustomerController**

```

这个命令将在`Customer`文件夹中创建`CustomerController`。如果`Customer`文件夹不存在，它也将创建该文件夹。

+   `make:model`: 这在`app`文件夹中创建一个新的模型。语法与`make:controller`命令相同，如下：

```php
**php artisan make:model Customer**

```

对于有命名空间的模型，可以如下使用：

```php
**php artisan make:model Customer/Customer**

```

这将在`Customer`文件夹中创建`Customer`模型，并为其使用`Customer`命名空间。

+   `make:event`: 这在`Events`文件夹中创建一个新的`event`类。可以如下使用：

```php
**php artisan make:event MyEvent**

```

+   `make:listener`: 这个命令为事件创建一个新的监听器。可以如下使用：

```php
**php artisan make:listener MyListener --event MyEvent**

```

上述命令将为我们的`MyEvent`事件创建一个新的监听器。我们必须始终使用`--event`选项提及我们需要创建监听器的事件。

+   `make:migration`: 这个命令在 database/migrations 文件夹中创建一个新的迁移。

+   `php artisan migrate`: 这将运行所有尚未执行的可用迁移。

+   `php artisan optimize`: 这个命令优化框架以获得更好的性能。

+   `php artisan down`: 这将把应用程序置于维护模式。

+   `php artisan up`: 这个命令将应用程序从维护模式中恢复。

+   `php artisan cache:clear`: 这个命令清除应用程序缓存。

+   `php artisan db:seed`: 这个命令用记录填充数据库。

+   `php artisan view:clear`: 这将清除所有已编译的视图文件。

### 注意

有关 Artisan 控制台或 Artisan CLI 的更多详细信息可以在文档中找到，网址为[`laravel.com/docs/5.2/homestead`](https://laravel.com/docs/5.2/homestead)。

## 迁移

迁移是 Laravel 中的另一个强大功能。在迁移中，我们定义数据库模式——它是创建表、删除表或在表中添加/更新列。迁移在部署中非常方便，并且作为数据库的版本控制。让我们为我们的数据库中尚不存在的 customer 表创建一个迁移。要创建一个迁移，在终端中发出以下命令：

```php
**php artisan make:migration create_custmer_table**

```

在`database/migrations`文件夹中将创建一个新文件，文件名为当前日期和唯一 ID 前缀的`create_customer_table`。类被创建为`CreateCustomerTable`。这是一个如下的类：

```php
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class CreateCustomerTable extends Migrations
{
  //Run the migrations

  public function up()
  {
    //schemas defined here
  }

  public function down()
  {
    //Reverse migrations
  }
}
```

类将有两个公共方法：`up()`和`down()`。`up()`方法应该包含表的所有新模式。`down()`方法负责撤销已执行的迁移。现在，让我们将`customers`表模式添加到`up()`方法中，如下：

```php
public function up()
{
  Schema::create('customers', function (Blueprint $table)
  {
    $table->increments('id', 11);
    $table->string('name', 250)
    $table->string('email', 50);
    $table->string('phone', 20);
    $table->timestamps();
  });
}
public function down()
{
  Schema::drop('customers');
}
```

在`up()`方法中，我们定义了模式和表名。表的列是单独定义的，包括列大小。`increments()`方法定义了自动增量列，在我们的例子中是`id`列。接下来，我们为`name`、`email`和`phone`创建了三个字符串列。然后，我们使用了`timestamps()`方法，它创建了`created_at`和`updated_at`时间戳列。在`down()`方法中，我们只是使用了`Schema`类的`drop()`方法来删除`customers`表。现在，我们需要使用以下命令运行我们的迁移：

```php
**php artisan migrate**

```

上述命令不仅会运行我们的迁移，还会运行尚未执行的所有迁移。当执行迁移时，Laravel 会将迁移名称存储在一个名为`migrations`的表中，从中决定要执行哪些迁移以及要跳过哪些迁移。

现在，如果我们需要回滚最近执行的迁移，我们可以使用以下命令：

```php
**php artisan migrate:rollback**

```

这将回滚到最后一批迁移。要回滚应用程序的所有迁移，我们可以使用 reset 命令，如下所示：

```php
**php artisan migrate:reset**

```

这将回滚完整的应用程序迁移。

迁移使部署变得容易，因为我们不需要每次在表或数据库中创建一些新的更改时上传数据库模式。我们只需创建迁移并上传所有文件，之后我们只需执行迁移命令，所有模式将被更新。

## Blade 模板

Laravel 自带了自己的模板语言 Blade。此外，Blade 模板文件支持普通的 PHP 代码。Blade 模板文件被编译为普通的 PHP 文件，并在更改之前被缓存。Blade 还支持布局。例如，以下是我们在 Blade 中的主页面布局，放在`resources/views/layout`文件夹中，名为`master.blade.php`。看一下以下代码：

```php
<!DOCTYPE html>
<html>
  <head>
    <title>@yield('title')</title>
  </head>
  <body>
    @section('sidebar')
      Our main sidebar
      @show

      <div class="contents">
        @yield('content')
      </div>
  </body>
</html>
```

在上面的例子中，我们有一个定义`content`部分的侧边栏。此外，我们有`@yield`，它显示部分的内容。现在，如果我们想要使用这个布局，我们需要在子模板文件中扩展它。让我们在`resources/views/`文件夹中创建`customers.blade.php`文件，并将以下代码放入其中：

```php
@extend('layouts.master')
  @section('title', 'All Customers')
  @section('sidebar')
  This will be our side bar contents
  @endsection
  @section('contents')
    These will be our main contents of the page
  @endsection
```

如前面的代码所示，我们扩展了`master`布局，然后在`master`布局的每个部分放置了内容。此外，还可以在另一个模板中包含不同的模板。例如，让我们在`resources/views/includes`文件夹中有两个文件，`sidebar.blade.php`和`menu.blade.php`。然后，我们可以在任何模板中包含这些文件，如下所示：

```php
@include(includes.menu)
@include(includes.sidebar)
```

我们使用`@include`来包含一个模板。点(`.`)表示文件夹分隔。我们可以轻松地从我们的控制器或路由器向 Blade 模板或视图发送数据。我们只需将数据作为数组传递给视图，如下所示：

```php
return view('customers', ['count => 5]);
```

现在，在我们的`customers`视图文件中可以访问`count`，如下所示：

```php
Total Number of Customers: {{ count }}
```

是的，Blade 使用双花括号来输出变量。对于控制结构和循环，让我们举一个例子。让我们向`customers`视图发送数据，如下所示：

```php
return view('customers', ['customers' => $allCustomers]);
```

现在，如果我们想要显示所有`customers`数据，我们的`customers`视图文件将类似于以下内容：

```php
…
…
@if (count($customers) > 0)
{{ count($customers) }} found. <br />
@foreach ($customers as $customer)
{{ $customer->name }} {{ $customer->email }} {{ $customer->phone }} <br>
@endforeach

@else
Now customers found.
@endif;
…
…
```

所有上述语法看起来很熟悉，因为它几乎与普通的 PHP 相同。但是，要显示一个变量，我们必须使用双花括号`{{}}`。

### 注意

可以在[`laravel.com/docs/5.2/blade`](https://laravel.com/docs/5.2/blade)找到一个易于阅读的 Blade 模板文档。

## 其他特性

在上一节中，我们只讨论了一些基本功能。Laravel 还有许多其他功能，例如身份验证和授权，提供了一种简单的方式来对用户进行身份验证和授权。此外，Laravel 提供了强大的缓存系统，支持基于文件的缓存、Memcached 和 Redis 缓存。Laravel 还为这些事件提供了事件和监听器，当我们想执行特定操作时以及特定事件发生时，这是非常方便的。Laravel 支持本地化，可以使用本地化内容和多种语言。Laravel 还支持任务调度和队列，我们可以在特定时间安排一些任务运行，并在轮到它们时排队运行一些任务。

# Lumen

Lumen 是由 Laravel 提供的微框架。Lumen 主要用于创建无状态 API，并具有 Laravel 的最小功能集。此外，Lumen 与 Laravel 兼容，这意味着如果我们只是将我们的 Lumen 应用程序复制到 Laravel 中，它将正常工作。安装很简单。只需使用以下 Composer 命令创建一个 Lumen 项目，它将下载包括 Lumen 在内的所有依赖项：

```php
**composer create-project --prefer-dist laravel/lumen api**

```

上述命令将下载 Lumen，然后创建我们的 API 应用程序。完成后，将`.env.example`重命名为`.env`。还要创建一个 32 个字符长的应用程序密钥，并将其放入`.env`文件中。现在，基本应用程序已准备好使用和创建 API。

### 注意

Lumen 与 Laravel 几乎相同，但默认情况下不包括一些 Laravel 功能。更多细节可以在[`lumen.laravel.com/docs/5.2`](https://lumen.laravel.com/docs/5.2)找到。

# Apigility

Apigility 是由 Zend 在 Zend Framework 2 中构建和开发的。Apigility 提供了一个易于使用的 GUI 来创建和管理 API。它非常易于使用，并能够创建复杂的 API。让我们从使用 Composer 安装 Apigility 开始。在终端中输入以下命令：

```php
**composer create-project -sdev zfcampus/zf-apigility-skeleton packt**

```

上述命令将下载 Apigility 及其依赖项，包括 Zend Framework 2，并将设置我们的名为`packt`的项目。现在，发出以下命令以启用开发模式，以便我们可以访问 GUI：

```php
**php public/index.php development enable**

```

现在，打开 URL [yourdomain.com/packt/public](http://yourdomain.com/packt/public)，我们将看到一个漂亮的 GUI，如下面的屏幕截图所示：

![Apigility](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_AppendixB_02.jpg)

现在，让我们创建我们的第一个 API。我们将称此 API 为“`books`”，它将返回一本书的列表。单击前面图片中显示的**New API**按钮，将显示一个弹出窗口。在文本框中输入`books`作为 API 名称，然后单击`Create`按钮；新 API 将被创建。创建 API 后，我们将看到以下屏幕：

![Apigility](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_AppendixB_03.jpg)

Apigility 提供了设置 API 的其他属性的简单方法，例如版本控制和身份验证。现在，通过单击左侧边栏中的**New Service**按钮来创建一个 RPC 服务。此外，我们可以在前面的屏幕截图中的**RPC**部分单击**Create a new one**链接。我们将看到以下屏幕：

![Apigility](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_AppendixB_04.jpg)

如前面的屏幕截图所示，我们在`books`API 中创建了一个名为`get`的 RPC 服务。输入的路由 URI 是`/books/get`，将用于调用此 RPC 服务。当我们单击`Create service`按钮时，将显示 API 创建成功的消息，并且还将显示以下屏幕：

![Apigility](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_AppendixB_05.jpg)

如前面的屏幕截图所示，此服务的允许 HTTP 方法仅为**GET**。让我们保持原样，但我们可以选择全部或任何一个。此外，我们希望将**内容协商选择器**保持为`Json`，并且我们的服务将以 JSON 格式接受/接收所有内容。此外，我们可以选择不同的媒体类型和内容类型。

接下来，我们应该为我们的服务添加一些将要使用的字段。点击**字段**选项卡，我们将看到**字段**屏幕。点击**新建字段**按钮，我们将看到以下弹出窗口：

![Apigility](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_AppendixB_06.jpg)

如前面的屏幕截图所示，我们可以为字段设置所有属性，如**名称**、**描述**、是否必填等，以及一些其他设置，包括验证失败时的错误消息。在创建了两个字段**title**和**author**之后，我们将看到类似以下的屏幕：

![Apigility](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_AppendixB_07.jpg)

如前面的屏幕所示，我们也可以为每个单独的字段添加验证器和过滤器。

### 注意

由于这只是 Apigility 的入门主题，我们将不会在本书中涵盖验证器、过滤器和其他一些主题。

下一个主题是文档。当我们点击**文档**选项卡时，我们将看到以下屏幕：

![Apigility](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_AppendixB_08.jpg)

在这里，我们将记录我们的服务，添加一些描述，还可以为文档目的生成响应主体。这非常重要，因为它将使其他人更好地理解我们的 API 和服务。

现在，我们需要从某个地方获取所有的书。可以是从数据库中获取，也可以是从另一个服务或其他来源获取。然而，现在，我们只是为了测试目的，将使用一组书的数组。如果我们点击**来源**选项卡，我们会发现我们服务的代码放在`module/books/src/books/V1/Rpc/Get/GetController.php`中。Apigility 为我们的 API`books`创建了一个模块，然后根据 API 的版本（默认为 V1），将所有源代码放在这个模块的不同文件夹中。我们可以为我们的 API 添加更多版本，如 V2 和 V3。现在，如果我们打开`GetController`文件，我们会发现一些代码和一个根据我们的路由 URI 命名为`getAction`的操作。代码如下，高亮显示的是我们添加的代码：

```php
namespace books\V1\Rpc\Get;

use Zend\Mvc\Controller\AbstractActionController;
**use ZF\ContentNegotiation\ViewModel;**

class GetController extends AbstractActionController
{
  public function getAction()
  {
    **$books = [ 'success' => [**
 **[**
 **'title' => 'PHP 7 High Performance',**
 **'author' => 'Altaf Hussain'**
 **],**
 **[**
 **'title' => 'Magento 2',**
 **'author' => 'Packt Publisher'**
 **],**
 **]**
 **];**

 **return new ViewModel($books);**
  }
}
```

在上面的代码中，我们使用了`ContentNegotiation\ViewModel`，它负责以我们在服务设置中选择的格式（在我们的情况下是 JSON）响应数据。然后，我们创建了一个简单的`$books`数组，其中包含我们为服务创建的字段名，并为它们分配了值。然后，我们使用`ViewModel`对象返回它们，该对象处理响应数据转换为 JSON。

现在，让我们测试我们的 API。由于我们的服务可以接受`GET`请求，我们只需在浏览器中输入带有`books/get` URI 的 URL，就会看到 JSON 响应。最好使用 RestClient 或 Google Chrome 的 Postman 等工具来检查 API，这些工具提供了一个易于使用的界面，可以向 API 发出不同类型的请求。我们使用 Postman 进行了测试，并得到了以下截图中显示的响应：

![Apigility](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_AppendixB_09.jpg)

还要注意，我们将我们的服务设置为仅接受`GET`请求。因此，如果我们发送的请求不是`GET`，我们将收到`HTTP 状态码 405 方法不允许`的错误。

Apigility 非常强大，提供了许多功能，如 RESTFul API、HTTP 身份验证、与易于创建的数据库连接器连接的数据库服务，以及服务的表格选择。在使用 Apigility 时，我们不需要担心 API、服务结构安全性和其他事情，因为 Apigility 会为我们处理这些。我们只需要专注于 API 和服务的业务逻辑。

### 注意

Apigility 无法在本附录中完全涵盖。Apigility 有很多功能，可以在一本完整的书中进行介绍。Apigility 的官方文档网址[`apigility.org/documentation`](https://apigility.org/documentation)是一个很好的起点，可以了解更多信息。

# 摘要

在本附录中，我们讨论了 MVC 设计模式的基础知识。我们还讨论了 Laravel 框架及其一些优秀特性。我们向你介绍了基于 Laravel 的微框架 Lumen。最后，我们对 Apigility 进行了简要介绍，并创建了一个测试 API 和 Web 服务。

在 IT 领域，事物很快就会过时。总是需要学习升级的工具，寻找编程中最佳方法的新途径和技术。因此，完成本书后不应该停止学习，而是开始研究新的主题，以及本书中未完全涵盖的主题。到这一点，你将拥有知识，可以用来建立高性能应用程序的高性能环境。祝你在 PHP 编程中好运和成功！
