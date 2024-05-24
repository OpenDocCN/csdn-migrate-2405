# Storm 和 Cassandra 实时分析（二）

> 原文：[`zh.annas-archive.org/md5/7C24B06720C9BE51000AF16D45BAD7FF`](https://zh.annas-archive.org/md5/7C24B06720C9BE51000AF16D45BAD7FF)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：将 NoSQL 持久性添加到 Storm

在本章中，我们将毕业于理解 Storm 的下一步——我们将为我们的拓扑添加持久性。我们选择了 Cassandra，原因是非常明显的，这将在本章中详细阐述。我们的目的是让您了解 Cassandra 数据存储如何与 Storm 拓扑集成。

本章将涵盖以下主题：

+   Cassandra 的优势

+   列式数据库和列族设计基础知识的介绍

+   设置 Cassandra 集群

+   介绍 CQLSH、CLI 和连接器 API

+   Storm 拓扑与 Cassandra 存储相连

+   理解持久性的机制

+   Storm Cassandra 应用程序的最佳实践

# Cassandra 的优势

这是任何人都会问的第一个和最明显的问题，“为什么我们要使用 NoSQL？”嗯，对于选择 NoSQL 而不是传统数据存储的非常快速的答案与为什么世界正在转向大数据是一样的——低成本、高可扩展性和可靠的解决方案，可以存储无限量的数据。

现在，下一个问题是为什么选择 Cassandra，而不是 NoSQL 堆栈中的其他任何东西。答案在于我们正在尝试实现的问题和解决方案方法的性质。嗯，我们正在处理实时分析，我们需要的一切都应该准确、安全可靠和极快速。因此，Cassandra 是最佳选择，因为：

+   它在其同行中（如 HBase 等）拥有最快的写入速度

+   它具有点对点设计的线性可扩展性

+   没有单点故障

+   读写请求可以在不影响彼此性能的情况下处理

+   处理包含数百万交易和极快速度的搜索查询

+   具有复制因子的故障安全和高可用性

+   在 NoSQL 数据库的 CAP 定理上保证最终一致性

+   列族设计以处理各种格式

+   没有或很低的许可成本

+   较少的开发运维或运营成本

+   它可以扩展以集成各种其他大数据组件

# 列式数据库基础知识

开始使用 NoSQL 数据存储最重要的一点是了解列式数据库的基础知识；或者更确切地说，让我们使用实际术语——列族。

这是一个在不同的 NoSQL 数据库中有各种实现的概念，例如：

+   **Cassandra**：这是一个基于键值对的 NoSQL 数据库

+   **Mongo DB**：这是一个基于文档的 NoSQL 数据库

+   **Neo4J**：这是一个图形数据库

它们在以下方面与传统的面向行的关系数据库系统不同：

+   性能

+   存储可扩展性

+   容错性

+   低或没有许可成本

但是，尽管已经列举了所有 NoSQL 数据库的差异和优势，您必须清楚地理解，转向 NoSQL 是对数据存储、可用性和访问的整个范式的转变，它们并不是关系数据库的替代品。

在关系数据库管理系统的世界中，我们都习惯于创建表，但在 Cassandra 中，我们创建列族，其中定义了列的元数据，但列实际上存储为行。每行可以有不同的列集，因此整个列族相对不太结构化和可扩展。

## 列族的类型

有两种类型的列族：

+   **静态列族**：顾名思义，它具有静态的列集，并且非常接近所有众所周知的关系数据库表，除了一些由于其 NoSQL 传统而产生的差异。以下是静态列族的一个示例：

| 行键 | 列 |
| --- | --- |
| Raman | 名字 | 电子邮件 | 电话号码 | 年龄 |
| | Raman Subramanian | aa@yahoo.com | 9999999999 | 20 |
| Edison | 名字 | 电子邮件 | 电话号码 | 年龄 |
| | Edison Weasley | bb@yahoo.com | 88888888888 | 30 |
| Amey | 名字 | 电子邮件 | 电话号码 | 年龄 |
| | Amey Marriot | cc@yahoo.com | 7777777777 | 40 |
| Sriman | 名字 | 电子邮件 | | |
| | Sriman Mishra | dd@yahoo.com | | |

+   **动态列族**：这个真正体现了无结构和无模式的真正本质。在这里，我们不使用与列族关联的预定义列，而是可以由客户端应用程序在插入数据时动态生成和提供。在创建或定义动态列族时，我们可以通过定义比较器和验证器来定义有关列名和值的信息。以下是动态列族的一个示例：

| 行键 | 列 |
| --- | --- |
| Raman | 名字 | 电子邮件 | 电话号码 | 年龄 |
|   |   |   |   |
| Edison | 地址 | 州 | 领土 |   |
|   |   |   |   |
| Amey | 国家 | 性别 | 电话号码 | 年龄 |
|   |   |   |   |
| Sriman | 国籍 |   |   |   |
|   |   |   |   |

## 列的类型

Cassandra 支持各种列：

+   **标准列**：这些列包含一个名称；这是由写入应用程序静态或动态设置的。这里显示了一个值（实际上是存储数据的属性）和时间戳：

| 列名 |
| --- |
| 值 |
| 时间戳 |

Cassandra 利用与列相关联的时间戳来查找列的最后更新。当从 Cassandra 查询数据时，它按照这个时间戳排序，并始终返回最近的值。

+   **复合列**：Cassandra 利用这种存储机制来处理聚类行。这是一种处理所有逻辑行的独特方式，这些逻辑行共享相同的分区键，形成一个单个的物理宽行。这使得 Cassandra 能够完成存储每行 20 亿列的传奇壮举。例如，假设我想创建一个表，其中捕获来自一些社交网络站点的实时状态更新：

```scala
CREATE TABLE statusUpdates(
  update_id uuid PRIMARY KEY,
  username varchar,
  mesage varchar
  );

CREATE TABLE timeseriesTable (
  user_id varchar,
  udate_id uuid,
  username varchar,
  mesage varchar,
  PRIMARY KEY user_id , update_id )
);
```

实时更新记录在`StatusUpdates`表下，该表具有`username`，`message`和`update_id`（实际上是 UUID）属性。

在设计 Cassandra 列族时，应充分利用 UUID 提供的功能，这可以用于对数据进行排序。

来自`timeseriesTable`的`user_id`和`update_id`属性的组合可以唯一标识时间顺序中的一行。

Cassandra 使用主键中定义的第一列作为分区键；这也被称为行键。

+   **过期列**：这些是 Cassandra 的特殊类型列，它们与时间到期（TTL）相关联；存储在这些列中的值在 TTL 过去后会自动删除或擦除。这些列用于我们不希望保留超过规定时间间隔的数据的用例；例如，如果我们不需要 24 小时前的数据。在我们的列族中，我会将每个插入的列关联一个 24 小时的 TTL，并且这些数据将在插入后的 24 小时内被 Cassandra 自动删除。

+   **计数列**：这些又是专门的功能列，用于递增存储数字。它们有一个特殊的实现和专门的用途，用于我们使用计数器的情况；例如，如果我需要计算事件发生的次数。

# 设置 Cassandra 集群

Cassandra 是一个非常可扩展的键值存储。它承诺最终一致性，其分布式基于环形的架构消除了集群中的任何单点故障，因此使其高度可用。它被设计和开发用于支持对大量数据进行非常快速的读写。这种快速的写入和读取能力使其成为用于支持大型业务智能系统的在线事务处理（OLTP）应用的一个非常强大的竞争者。

Cassandra 提供了基于列族的数据模型，比典型的键值系统更灵活。

## 安装 Cassandra

Cassandra 需要部署的最稳定版本的 Java 1.6，最好是 Oracle 或 Sun JVM。执行以下步骤安装 Cassandra：

1.  从 Apache Cassandra 网站下载最新的稳定版本（写作时的版本为 1.1.6）。

1.  在`/usr/local`下创建一个 Cassandra 目录，如下所示：

```scala
sudo mkdir /usr/local/cassandra

```

1.  将下载的 TAR 文件提取到`/usr/local`位置。使用以下命令：

```scala
sudo tar –xvf apache-cassandra-1.1.6-bin.tar.gz -C  /usr/local/cassandra

```

1.  Cassandra 需要一个目录来存储其数据、日志文件和缓存文件。创建`/usr/local/cassandra/tmp`来存储这些数据：

```scala
sudo mkdir –p /usr/local/cassandra/tmp

```

1.  更新`/usr/local/Cassandra/apache-cassandra-1.1.6/conf`下的`Cassandra.yaml`配置文件。

以下属性将进入其中：

```scala
cluster_name: 'MyClusterName'
seeds: <IP of Node-1><IP of Node-2>(IP address of each node  go into it)
listen_address: <IP of Current Node>
```

1.  使用以下脚本为每个节点计算一个 token，并通过在`Cassandra.yaml`中添加唯一 token 值来更新每个节点的`initial_token`属性：

```scala
#! /usr/bin/python
import sys
if (len(sys.argv) > 1):
  num=int(sys.argv[1])
else:
  num=int(raw_input("How many nodes are in your cluster? "))
for i in range(0, num):
  print 'node %d: %d' % (i, (i*(2**127)/num))
```

1.  更新`conf/log4j-server.properties`文件中的以下属性。在`cassandra`下创建`temp`目录：

```scala
Log4j.appender.R.File=/usr/local/cassandra/temp/system.log

```

1.  增加`Cassandra.yaml`中的`rpc_timeout`属性（如果此超时非常小且网络延迟很高，Cassandra 可能会假定节点已死亡，而没有等待足够长的时间来传播响应）。

1.  在`/usr/local/Cassandra/apache-cassandra-1.1.6`上运行 Cassandra 服务器，使用`bin/Cassandra -f`。

1.  在`/usr/local/Cassandra/apache-cassandra-1.1.6`上使用`bin/Cassandra-cli`和主机和端口运行 Cassandra 客户端。

1.  使用`/usr/local/Cassandra/apache-cassandra-1.1.6`下的`bin/nodetool` ring 实用程序验证正确连接的集群：

```scala
bin/nodetool –host <ip-adress> -p <port number> ring 
192.168.1.30 datacenter1 rack1 Up    Normal 755.25 MB  25.00% 0
192.168.1.31 datacenter1 rack1 Up    Normal 400.62 MB  25.00% 42535295865117307932921825928970
192.168.1.51 datacenter1 rack1 Up    Normal 400.62 MB  25.00% 42535295865117307932921825928971
192.168.1.32 datacenter1 rack1 Up    Normal 793.06 MB  25.00% 85070591730234615865843651857941
```

前面的输出显示了一个连接的集群。此配置显示它已正确配置和连接。

以下是输出的屏幕截图：

![安装 Cassandra](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/rt-anlt-storm-csdr/img/00046.jpeg)

# 多个数据中心

在实际场景中，我们希望将 Cassandra 集群分布在不同的数据中心，以便系统更可靠和更具抗灾性，以应对局部网络故障和物理灾难。

## 设置多个数据中心的先决条件

以下是设置多个数据中心时应使用的一组先决条件：

+   在每个节点上安装 Cassandra

+   在集群中每个节点的 IP 地址

+   确定集群名称

+   确定种子节点

+   确定要使用的 snitch

## 安装 Cassandra 数据中心

以下是设置 Cassandra 数据中心的一组步骤：

1.  让我们假设我们已经在以下节点上安装了 Cassandra：

10.188.66.41（seed1）

10.196.43.66

10.188.247.41

10.196.170.59（seed2）

10.189.61.170

10.189.30.138

1.  使用前一节中定义的 token 生成 Python 脚本为每个前面的节点分配 token。

1.  假设我们将节点及其 token 分布对齐到以下分布：

| 节点 | IP 地址 | Token | 数据中心 |
| --- | --- | --- | --- |
| node0 | 10.188.66.41 | 0 | Dc1 |
| node1 | 10.196.43.66 | 56713727820156410577229101238628035245 | Dc1 |
| node2 | 10.188.247.41 | 113427455640312821154458202477256070488 | Dc1 |
| node3 | 10.196.170.59 | 10 | Dc2 |
| node4 | 10.189.61.170 | 56713727820156410577229101238628035255 | Dc2 |
| node5 | 10.189.30.138 | 113427455640312821154458202477256070498 | Dc2 |

1.  停止节点上的 Cassandra 并清除 Cassandra 的`data_dir`中的数据：

```scala
$ ps auwx | grep cassandra 

```

此命令查找 Cassandra Java 进程 ID（PID）：

```scala
$ sudo kill <pid> 

```

这是用指定的 PID 杀死进程的命令：

```scala
$ sudo rm -rf /var/lib/cassandra/*

```

上述命令清除了 Cassandra 的默认目录中的数据。

1.  为每个节点修改`cassandra.yaml`文件中的以下属性设置：

```scala
endpoint_snitch <provide the name of snitch> 
  initial_token: <provide the value of token from previous  step>
  seeds: <provide internal IP_address of each seed node>
  listen_address: <provide localhost IP address>
```

更新后的配置如下：

```scala
node0:
end_point_snitch:  org.apache.cassandra.locator.PropertyFileSnitch
initial_token: 0
seed_provider:
  - class_name:  org.apache.cassandra.locator.SimpleSeedProvider
  parameters:
  - seeds: "10.188.66.41,10.196.170.59"
  listen_address: 10.196.43.66
  node1 to node5
```

所有这些节点的属性与前面的`node0`定义的属性相同，除了`initial_token`和`listen_address`属性。

1.  接下来，我们将不得不为每个数据中心及其机架分配名称；例如，`Dc1`，`Dc2`和`Rc1`，`Rc2`。 

1.  转到`cassandra-topology.properties`文件，并针对每个节点的 IP 地址添加数据中心和机架名称的赋值。例如：

```scala
# Cassandra Node IP=Data Center:Rack
10.188.66.41=Dc1:Rc1
10.196.43.66=Dc2:Rc1
10.188.247.41=Dc1:Rc1
10.196.170.59=Dc2:Rc1
10.189.61.170=Dc1:Rc1
10.199.30.138=Dc2:Rc1
```

1.  下一步是逐个启动种子节点，然后启动所有其他节点。

1.  检查您的环是否正常运行。

# CQLSH 介绍

既然我们已经完成了 Cassandra 的设置，让我们熟悉一下 shell 和一些基本命令：

1.  在`/usr/local/Cassandra/apache-cassandra-1.1.6`上使用`bin/cqlsh`运行 CQL，带有主机和端口：

```scala
bin/cqlsh  –host <ip-adress> -p <port number>

```

1.  在 Cassandra 客户端或 CQL 中创建一个 keyspace，如下所示：

```scala
create keyspace <keyspace_name>; 

```

1.  在 Cassandra 客户端或 CQL 中创建一个列族，如下所示：

```scala
use <keyspace_name>;
create column family <columnfamily name>;

```

例如，创建以下表：

```scala
CREATE TABLE appUSers (
 user_name varchar,
 Dept varchar,
 email varchar,
 PRIMARY KEY (user_name));

```

1.  从命令行插入一些记录到列族中：

```scala
INSERT INTO appUSers (user_name, Dept, email)
 VALUES ('shilpi', 'bigdata, 'shilpisaxena@yahoo.com');

```

1.  从列族中检索数据：

```scala
SELECT * FROM appUSers LIMIT 10;

```

# CLI 介绍

本节让您熟悉了另一个用于与 Cassandra 进程交互的工具——CLI shell。

以下步骤用于使用 CLI shell 与 Cassandra 进行交互：

1.  以下是连接到 Cassandra CLI 的命令：

```scala
Cd Cassandra-installation-dir/bin
cassandra-cli -host localhost -port 9160

```

1.  创建一个 keyspace：

```scala
[default@unknown] CREATE KEYSPACE myKeySpace
with placement_strategy = 'SimpleStrategy'
and strategy_options = {replication_factor:1};

```

1.  使用以下命令验证 keyspace 的创建：

```scala
[default@unknown] SHOW KEYSPACES;
 Durable Writes: true
 Options: [replication_factor:3]
 Column Families:
 ColumnFamily: MyEntries
 Key Validation Class:  org.apache.cassandra.db.marshal.UTF8Type
 Default column value validator:  org.apache.cassandra.db.marshal.UTF8Type
 Columns sorted by:  org.apache.cassandra.db.marshal.ReversedType (org.apache.cassandra.db.marshal.TimeUUIDType)
 GC grace seconds: 0
 Compaction min/max thresholds: 4/32
 Read repair chance: 0.1
 DC Local Read repair chance: 0.0
 Replicate on write: true
 Caching: KEYS_ONLY
 Bloom Filter FP chance: default
 Built indexes: []
 Compaction Strategy:  org.apache.cassandra.db.compaction. SizeTieredCompactionStrategy
 Compression Options:
 sstable_compression:  org.apache.cassandra.io.compress.SnappyCompressor
 ColumnFamily: MYDevicesEntries
 Key Validation Class:  org.apache.cassandra.db.marshal.UUIDType
 Default column value validator:  org.apache.cassandra.db.marshal.UTF8Type
 Columns sorted by:  org.apache.cassandra.db.marshal.UTF8Type
 GC grace seconds: 0
 Compaction min/max thresholds: 4/32
 Read repair chance: 0.1
 DC Local Read repair chance: 0.0
 Replicate on write: true
 Caching: KEYS_ONLY
 Bloom Filter FP chance: default
 Built indexes:  [sidelinedDevicesEntries. sidelinedDevicesEntries_date_created_idx,  sidelinedDevicesEntries. sidelinedDevicesEntries_event_type_idx]
 Column Metadata:
 Column Name: event_type
 Validation Class:  org.apache.cassandra.db.marshal.UTF8Type
 Index Name: sidelinedDevicesEntries_event_type_idx
 Index Type: KEYS
 Index Options: {}
 Column Name: date_created
 Validation Class:  org.apache.cassandra.db.marshal.DateType
 Index Name: sidelinedDevicesEntries_date_created_idx
 Index Type: KEYS
 Index Options: {}
 Column Name: event
 Validation Class:  org.apache.cassandra.db.marshal.UTF8Type
 Compaction Strategy:  org.apache.cassandra.db.compaction. SizeTieredCompactionStrategy
 Compression Options:
 sstable_compression:  org.apache.cassandra.io.compress.SnappyCompressor

```

1.  创建一个列族：

```scala
[default@unknown] USE myKeySpace;
 [default@demo] CREATE COLUMN FAMILY appUsers
 WITH comparator = UTF8Type
 AND key_validation_class=UTF8Type
 AND column_metadata = [
 {column_name:user_name, validation_class: UTF8Type}
 {column_name: Dept, validation_class: UTF8Type}
 {column_name: email, validation_class: UTF8Type}
];

```

1.  将数据插入到列族中：

```scala
[default@demo] SET appUsers['SS'][user_name']='shilpi';
 [default@demo] SET appUsers['ss'][Dept]='BigData';
 [default@demo] SET  appUsers['ss']['email']=shilpisaxena@yahoo.com';

```

### 注意

在这个例子中，代码`ss`是我的行键。

1.  从 Cassandra 列族中检索数据：

```scala
GET appUsers[utf8('ss')][utf8('user_name')];
List appUsers;

```

# 使用不同的客户端 API 访问 Cassandra

现在我们已经熟悉了 Cassandra，让我们继续下一步，我们将以编程方式访问（插入或更新）数据到集群中。一般来说，我们谈论的 API 是在核心 Thrift API 上编写的包装器，它提供了使用程序员友好的包进行 Cassandra 集群上的各种 CRUD 操作。

用于访问 Cassandra 的客户端 API 如下：

+   **Thrift 协议**：访问 Cassandra 的最基本的 API 是**远程过程调用**（**RPC**）协议，它提供了一个语言中立的接口，因此可以使用 Python、Java 等进行通信。请注意，我们将讨论的几乎所有其他 API 都在内部使用**Thrift**。它使用简单，并且提供了基本的功能，如环形发现和本地访问。然而，它不支持重试、连接池等复杂功能。然而，有许多库扩展了 Thrift 并添加了这些必要的功能，我们将在本章中介绍一些广泛使用的库。

+   **Hector**：这是用于 Java 客户端应用程序访问 Cassandra 的最稳定和广泛使用的 API 之一。如前所述，它在内部使用 Thrift，因此基本上不能提供 Thrift 协议不支持的任何功能或功能。它被广泛使用的原因是它具有许多基本功能，可以直接使用并且可用：

+   它具有连接池的实现

+   它具有环形发现功能，并附带自动故障转移支持

+   它在 Cassandra 环中具有对宕机主机的重试选项。

+   **Datastax Java driver**：这是最近添加到 Cassandra 客户端访问选项堆栈中的一个选项，因此与较新版本的 Cassandra 兼容。以下是它的显著特点：

+   连接池

+   重新连接策略

+   负载均衡

+   游标支持

+   **Astyanax**：这是 Cassandra 客户端 API 花束的最新添加，由 Netflix 开发，这使它比其他更加神秘。让我们看看它的凭证，看看它是否符合条件：

+   它支持 Hector 的所有功能，并且使用起来更加容易

+   它承诺比 Hector 更好地支持连接池

+   它比 Hector 更擅长处理故障转移

+   它提供了一些开箱即用的类似数据库的功能（这是个大新闻）。在 API 级别上，它提供了称为 Recipes 的功能，其中包括：

并行行查询执行

消息队列功能

对象存储

分页

+   它具有许多经常需要的实用程序，如 JSON Writer 和 CSV Importer

# Storm 拓扑连接到 Cassandra 存储

现在您已经了解并知道为什么应该使用 Cassandra。您已经学会了设置 Cassandra 和列族创建，并且甚至涵盖了可编程访问 Cassandra 数据存储的各种客户端/协议选项。正如前面提到的，Hector 目前是访问 Cassandra 最广泛使用的 API，尽管`Datastax`和`Astyanax`驱动程序正在迅速赶上。对于我们的练习，我们将使用 Hector API。

我们要实现的用例是使用 Cassandra 支持实时的电信数据的即时报告，这些数据正在使用 Storm 拓扑进行整理、解析和丰富。

![Storm 拓扑连接到 Cassandra 存储](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/rt-anlt-storm-csdr/img/00047.jpeg)

如前图所示，用例需要使用数据收集组件（为了练习，我们可以使用样本记录和模拟器 shell 脚本来模拟实时 CDR 数据）进行实时电信**通话详单**（**CDR**）捕获。整理的实时数据被推送到 RabbitMQ 代理，然后被 Storm 拓扑消费。

对于拓扑，我们有一个 AMQP spout 作为消费者，它读取队列的数据并将其推送到拓扑的 bolt；在这里，我们已经连接了 bolt 来解析消息并将其转换为**普通旧 Java 对象**（**POJO**）。然后，我们在我们的拓扑中有一个新的条目，即 Cassandra bolt，它实际上将数据存储在 Cassandra 集群中。

从 Cassandra 集群中，基于用户定义的搜索查询，UI 界面的消费者检索数据，从而提供即时的、实时的报告。

为了我们的实现，我们将像这里所示从 CLI/CQLSH 查询数据：

1.  创建一个键空间：

```scala
create keyspace my_keyspace with placement_strategy = 'SimpleStrategy' and strategy_options = {replication_factor : 3} and durable_writes = true;
 use my_keyspace;

```

1.  创建列族：

```scala
create column family my_columnfamily
  with column_type = 'Standard'
  and comparator = 'UTF8Type'
  and default_validation_class = 'BytesType'
  and key_validation_class = 'TimeUUIDType'
  and read_repair_chance = 0.1
  and dclocal_read_repair_chance = 0.0
  and gc_grace = 0
  and min_compaction_threshold = 4
  and max_compaction_threshold = 32
  and replicate_on_write = true
  and compaction_strategy =  'org.apache.cassandra.db.compaction. SizeTieredCompactionStrategy'
  and caching = 'KEYS_ONLY'
  and bloom_filter_fp_chance = 0.5
  and column_metadata = [
{column_name : 'cellnumber',
  validation_class : Int32Type },
  {column_name : 'tollchrg',
  validation_class : UTF8Type},
{column_name : 'msgres',
  validation_class : UTF8Type},

{column_name : 'servicetype',
  validation_class : UTF8Type}]
  and compression_options = {'sstable_compression' :  'org.apache.cassandra.io.compress.SnappyCompressor'
};
```

1.  需要对项目中的`pom.xml`进行以下更改。应该将 Hector 依赖项添加到`pom.xml`文件中，以便在构建时获取并添加到`m2`存储库，如下所示：

```scala
  <dependency>
    <groupId>me.prettyprint</groupId>
    <artifactId>hector-core</artifactId>
    <version>0.8.0-2</version>
  </dependency>
```

如果您正在使用非 Maven 项目，请遵循通常的协议——下载 Hector 核心 JAR 文件并将其添加到项目构建路径，以满足所有所需的依赖关系。

1.  接下来，我们需要在我们的 Storm 拓扑中放置组件。我们将首先创建一个`CassandraController` Java 组件，它将保存所有与 Cassandra 相关的功能，并且将从拓扑中的`CassandraBolt`类中调用以将数据持久化到 Cassandra 中：

```scala
public class CassandraController {

  private static final Logger logger =  LogUtils.getLogger(CassandraManager.class);
  //various serializers are declared in here
  UUIDSerializer timeUUIDSerializer = UUIDSerializer.get();
  StringSerializer stringSerializer =  StringSerializer.get();
  DateSerializer dateSerializer = DateSerializer.get();
  LongSerializer longSerializer = LongSerializer.get();

  public CassandraController() {
      //list of IPs of Cassandra node in ring
      String nodes =  "10.3.1.41,10.3.1.42,10.3.1.44,10.3.1.45";
      String clusterName = "mycluster";
      //creating a new configurator
      CassandraHostConfigurator hostConfigurator = new  CassandraHostConfigurator(nodes);
      hostConfigurator.setCassandraThriftSocketTimeout(0);
      cluster = HFactory.getOrCreateCluster(clusterName,  hostConfigurator);

      String[] nodeList = nodes.split(",");
      if (nodeList != null && nodeList.length ==  cluster.getConnectionManager(). getDownedHosts().size()) {
        logger.error("All cassandra nodes are down. " +  nodes);
      }

      //setting up read and write consistencies
      ConfigurableConsistencyLevel consistency = new  ConfigurableConsistencyLevel();
      consistency.setDefaultWriteConsistencyLevel (HConsistencyLevel.ONE);
      consistency.setDefaultReadConsistencyLevel (HConsistencyLevel.ONE);
      keySpaceObj = HFactory.createKeyspace ("my_keyspace", cluster, consistency);
      stringMutator = HFactory.createMutator(keySpaceObj, stringSerializer);
      uuidMutator = HFactory.createMutator (keySpaceObj, timeUUIDSerializer);

      logger.info("Cassandra data store initialized,  Nodes=" + nodes + ", " + "cluster name=" +  clusterName + ", " + "keyspace=" + keyspace + ", " +  "consistency=" + writeConsistency);
    }
    //defining the mutator 
  public Mutator < Composite > getCompositeMutator() {
    return compositeMutator;
  }

  public void setCompositeMutator(Mutator < Composite >  compositeMutator) {
      this.compositeMutator = compositeMutator;
    }
    //getter and setters for all mutators and serializers

  public StringSerializer getStringSerializer() {
    return stringSerializer;
  }

  public Keyspace getKeyspace() {
    return keySpaceObj;
  }
}
```

1.  我们拓扑中最后一个组件实际上是将数据写入 Cassandra 的组件，这是一个 Storm bolt，它将利用之前创建的`CassandraController`来将实时数据写入 Cassandra：

```scala
public class CassandraBolt extends BaseBasicBolt {
  private static final Logger logger =  LogUtils.getLogger(CassandraBolt.class);

  public void prepare(Map stormConf, TopologyContext  context) {

    logger.debug("Cassandra bolt, prepare()");
    try {
      cassandraMngr = new CassandraController();
      myCf = "my_columnfamily";
      );

    } catch (Exception e) {
      logger.error("Error while instantiating  CassandraBolt", e);
      throw new RuntimeException(e);
    }
  }

  @Override
  public void execute(Tuple input, BasicOutputCollector  collector) {
    logger.debug("execute method :: Start ");
      Calendar tCalendar = null;
      long eventts = eventObj.getEventTimestampMillis();
      com.eaio.uuid.UUID uuid = new  com.eaio.uuid.UUID(getTimeForUUID(eventts),  clockSeqAndNode);

  java.util.UUID keyUUID =  java.util.UUID.fromString(uuid.toString());

  /*
  * Persisting to my CF
  */

  try {
    if (keyUUID != null) {
        cassandraMngrTDR.getUUIDMutator().addInsertion(
            keyUUID,
            myCf,
            HFactory.createColumn("eventts",
                new Timestamp(tCalendar.getTimeInMillis()),  -1, cassandraMngr.getStringSerializer(),
                cassandraMngr.getDateSerializer()));
     }

  cassandraMngrTDR.getUUIDMutator().addInsertion(
    keyUUID,
    myCf,
    HFactory.createColumn("cellnumber",  eventObj.getCellnumber(), -1,  cassandraMngr.getStringSerializer(),
      cassandraMngr.getLongSerializer()));
      cassandraMngr.getUUIDMutator().execute();
  logger.debug("CDR event with key = " + keyUUID + "  inserted into Cassandra cf " + myCf);

  } else {
  logger.error("Record not saved. Error while parsing date  to generate KEY for cassandra data store, column family -  " + myCf);
    }
  }

  catch (Exception excep) {
  logger.error("Record not saved. Error while saving data  to cassandra data store, column family - " + myCf,  excep);
  }

   logger.debug("execute method :: End ");
  }
}
```

所以我们完成了最后一块拼图；现在我们可以使用 Storm 实时将数据流入 Cassandra。一旦您执行了整个拓扑，您可以使用 CLI/CQLSH 上的 select 或 list 命令验证 Cassandra 中的数据。

# Storm/Cassandra 应用程序的最佳实践

在处理具有 24/7 运行 SLA、非常高速和微小平均处理时间的分布式应用程序时，某些方面变得极为重要：

+   网络延迟在实时应用程序中起着重要作用，可能会成败产品，因此在数据中心或跨数据中心中放置各种节点时，要做出非常明智和有意识的决定，通常建议将 ping 延迟保持在最低限度。

+   Cassandra 的复制因子应该在三左右。

+   压缩应该是常规 Cassandra 维护的一部分。

# 测验时间

Q.1. 判断以下陈述是真是假：

1.  Cassandra 是基于文档的 NoSQL。

1.  Cassandra 有单点故障。

1.  Cassandra 在键分发时使用一致性哈希。

1.  Cassandra 工作在主从架构上。

Q.2. 填空：

1.  Cassandra 遵循 CAP 定理的 _______________ 属性。

1.  _______________ 是使 Cassandra 成为与 Storm 一起使用的有力竞争者的显著特点。

1.  Cassandra 是使用 Java 客户端访问 Cassandra 的 API，并且是希腊神话中的角色-卡桑德拉的兄弟。

Q.3. 完成本章提到的用例，并演示将数据填充到 Cassandra 中的端到端执行。

# 总结

在本章中，您已经涵盖了 NoSQL 的基础知识，特别是 Cassandra。您已经亲身体验了设置 Cassandra 集群，并了解了各种 API、驱动程序和协议，这些提供了对 Cassandra 的编程访问。我们还将 Cassandra 集成为我们的 Storm 拓扑的数据存储，用于数据插入。

在下一章中，我们将涉及 Cassandra 的一些重要方面，特别是一致性和可用性。


# 第七章：Cassandra 分区、高可用性和一致性

在本章中，你将了解 Cassandra 的内部，学习数据分区是如何实现的，你将了解 Cassandra 的键集分布上采用的哈希技术。我们还将深入了解复制以及它的工作原理，以及暗示的传递特性。我们将涵盖以下主题：

+   数据分区和一致性哈希；我们将看一些实际例子

+   复制、一致性和高可用性

# 一致性哈希

在你理解它在 Cassandra 中的含义和应用之前，让我们先了解一致性哈希作为一个概念。

一致性哈希按照其名称的概念工作——即*哈希*，正如我们所知，对于一个给定的哈希算法，相同的键将始终返回相同的哈希码——因此，这种方法在本质和实现上都是非常确定的。当我们将这种方法用于在集群中的节点之间进行分片或划分键时，一致性哈希是一种确定哪个节点存储在集群中的哪个节点的技术。

看一下下面的图表，理解一致性哈希的概念；想象一下下面图表中所描述的环代表 Cassandra 环，这里标记的节点是用字母标记的，实际上标记了要映射到环上的对象（倒三角形）。

![一致性哈希](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/rt-anlt-storm-csdr/img/00048.jpeg)

Cassandra 集群的一致性哈希

要计算对象所属的节点的所有权，只需要顺时针遍历，遇到下一个节点即可。跟随数据项（倒三角形）的节点就是拥有该对象的节点，例如：

+   **1**属于节点**A**

+   **2**属于节点**B**

+   **3**属于节点**C**

+   **4**属于节点**C**

+   **5**属于节点**D**

+   **6**属于节点**E**

+   **7**属于节点**F**

+   **8**属于节点**H**

+   **9**属于节点**H**

所以你看，这使用简单的哈希来计算环中键的所有权，基于拥有的标记范围。

让我们看一个一致性哈希的实际例子；为了解释这一点，让我们以一个样本列族为例，其中分区键值是名称。

假设以下是列值数据：

| 名字 | 性别 |
| --- | --- |
| Jammy | M |
| Carry | F |
| Jesse | M |
| Sammy | F |

这是哈希映射的样子：

| 分区键 | 哈希值 |
| --- | --- |
| Jim | 2245462676723220000.00 |
| Carol | 7723358927203680000.00 |
| Johnny | 6723372854036780000.00 |
| Suzy | 1168604627387940000.00 |

假设我有四个节点，具有以下范围；数据将如何分布：

| 节点 | 起始范围 | 结束范围 | 分区键 | 哈希值 |
| --- | --- | --- | --- | --- |
| A | 9223372036854770000.00 | 4611686018427380000.00 | Jammy | 6723372854036780000.00 |
| B | 4611686018427380000.00 | 1.00 | Jesse | 2245462676723220000.00 |
| C | 0.00 | 4611686018427380000.00 | suzy | 1168604627387940000.00 |
| D | 4611686018427380000.00 | 9223372036854770000.00 | Carry | 7723358927203680000.00 |

现在你已经理解了一致性哈希的概念，让我们来看看一个或多个节点宕机并重新启动的情况。

## 一个或多个节点宕机

我们目前正在看一个非常常见的情况，即我们设想一个节点宕机；例如，在这里我们捕捉到两个节点宕机：**B**和**E**。现在会发生什么？嗯，没什么大不了的，我们会像以前一样按照相同的模式进行，顺时针移动以找到下一个活动节点，并将值分配给该节点。

所以在我们的情况下，分配将改变如下：

![一个或多个节点宕机](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/rt-anlt-storm-csdr/img/00049.jpeg)

在前面图中的分配如下：

+   **1**属于**A**

+   **2**，**3**和**4**属于**C**

+   **5**属于**D**

+   **6**，**7**属于**F**

+   **8**，**9**属于**H**

## 一个或多个节点重新上线

现在让我们假设一个场景，节点 **2** 再次上线；那么接下来的情况与之前的解释相同，所有权将重新建立如下：

+   **1** 属于 **A**

+   **2** 属于 **B**

+   **3** 和 **4** 属于 **C**

+   **5** 属于 **D**

+   **6** 和 **7** 属于 **F**

+   **8** 和 **9** 属于 **H**

因此，我们已经证明了这种技术适用于所有情况，这就是为什么它被使用的原因。

# Cassandra 中的复制和策略

复制意味着创建一个副本。这个副本使数据冗余，因此即使一个节点失败或宕机，数据也是可用的。在 Cassandra 中，您可以选择在创建 keyspace 的过程中指定复制因子，或者稍后修改它。在这种情况下需要指定的属性如下：

+   **复制因子**：这是指定副本数量的数字值

+   **策略**：这可以是简单策略或拓扑策略；这决定了在集群中的副本放置

在内部，Cassandra 使用行键在集群的各个节点上存储数据的副本或复制。复制因子 *n* 意味着数据在 *n* 个不同节点上有 *n* 个副本。复制有一些经验法则，它们如下：

+   复制因子不应该大于集群中节点的数量，否则由于副本不足，Cassandra 将开始拒绝写入和读取，尽管复制因子将继续不间断地进行

+   如果复制因子太小，那么如果一个奇数节点宕机，数据将永远丢失

**Snitch** 用于确定节点的物理位置，例如彼此的接近程度等，在大量数据需要复制和来回移动时具有价值。在所有这些情况下，网络延迟都起着非常重要的作用。Cassandra 目前支持的两种策略如下：

+   **简单**：这是 Cassandra 为所有 keyspaces 提供的默认策略。它使用一个数据中心。它的操作非常简单直接；正如其名称所示，分区器检查键值对与节点范围的关系，以确定第一个副本的放置位置。然后，后续的副本按顺时针顺序放置在下一个节点上。因此，如果数据项 "A" 的复制因子为 "3"，并且分区器根据键和所有权决定了第一个节点，那么在这个节点上，后续的副本将按顺时针顺序创建。

+   **网络**：这是当我们的 Cassandra 集群分布在多个数据中心时使用的拓扑。在这里，我们可以规划我们的副本放置，并定义我们想要在每个数据中心放置多少副本。这种方法使数据地理冗余，因此在整个数据中心崩溃的情况下更加安全。在选择跨数据中心放置副本时，应考虑以下两个因素：

+   每个数据中心都应该是自给自足的，以满足请求

+   故障转移或崩溃情况

如果在一个数据中心中有 *2 个数据副本*，那么我们就有四份数据副本，每个数据中心对一节点故障有一份数据的容忍度，以保持一致性 `ONE`。如果在一个数据中心中有 *3 个数据副本*，那么我们就有六份数据副本，每个数据中心对多个节点故障有一份数据的容忍度，以保持一致性 `ONE`。这种策略也允许不对称复制。

# Cassandra 一致性

正如我们在前面的章节中所说，Cassandra 最终变得一致，并遵循 CAP 定理的 AP 原则。一致性指的是 Cassandra 集群中所有数据副本的信息有多新。Cassandra 最终保证一致性。现在让我们仔细看一下；假设我有一个由五个节点组成的 Cassandra 集群，复制因子为 3。这意味着如果我有一个*数据项 1*，它将被复制到三个节点，比如节点 1、节点 2 和节点 3；假设这个数据的键是*键 1*。现在，如果要重写此键的值，并且在节点 1 上执行写操作，那么 Cassandra 会在内部将值复制到其他副本，即节点 2 和节点 3。但此更新是在后台进行的，不是立即的；这就是最终一致性的机制。

Cassandra 提供了向（读和写）客户端应用程序提供决定使用何种一致性级别来读取和写入数据存储的概念。

## 写一致性

让我们仔细检查一下 Cassandra 中的写操作。当在 Cassandra 中执行写操作时，客户端可以指定操作应执行的一致性级别。

这意味着，如果复制因子为*x*，并且使用一致性为*y*（其中 y 小于 x）执行写操作，那么 Cassandra 将在成功写入*y*个节点后，才向客户端返回成功的确认，并标记操作为完成。对于剩余的*x-y*个副本，数据将由 Cassandra 进程在内部传播和复制。

以下表格显示了各种一致性级别及其含义，其中`ANY`具有最高可用性和最低一致性的优势，而`ALL`提供最高一致性但最低可用性。因此，作为客户端，在决定选择哪种一致性之前，必须审查使用情况。以下是一张包含一些常见选项及其含义的表格：

| 一致性级别 | 含义 |
| --- | --- |
| ANY | 当数据写入至少一个节点时，写操作将返回成功，其中节点可以是副本节点或非副本节点 |
| ONE | 当数据写入至少一个副本节点时，写操作将返回成功 |
| TWO | 当数据写入至少两个副本节点时，写操作将返回成功 |
| QUORUM | 当数据写入副本节点的法定副本数（法定副本数为 n/2+1，n 为复制因子）时，写操作将返回成功 |
| ALL | 当数据写入所有副本节点时，写操作将返回成功 |

以下图表描述了在具有复制因子**3**和一致性**2**的四节点集群上的写操作：

![写一致性](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/rt-anlt-storm-csdr/img/00050.jpeg)

因此，正如您所看到的，写操作分为三个步骤：

+   从客户端发出写操作

+   写操作在**副本 1**上执行并完成

+   写操作在**副本 2**上执行并完成

+   当写操作成功完成时，向客户端发出确认

## 读一致性

读一致性类似于写一致性，它表示在将结果返回给查询 Cassandra 数据存储的客户端之前，应有多少副本响应或确认其与返回的数据的一致性。这意味着，如果在具有复制因子*x*的*N*节点集群上，使用读一致性*y*（y 小于 x）发出读查询，则 Cassandra 将检查*y*个副本，然后返回结果。结果将根据使用最新数据来满足请求，并通过与每个列关联的时间戳进行验证。

以下**Cassandra 查询语言**（**CQL**），使用四分一一致性从列族中获取数据如下：

```scala
SELECT * FROM mytable USING CONSISTENCY QUORUM WHERE name='shilpi';

```

CQL 的功能如下：

| 一致性级别 | 含义 |
| --- | --- |
| ONE | 读请求由最近的副本的响应服务 |
| TWO | 读请求由最近的两个副本中的一个最新响应服务 |
| THREE | 此级别从最近的三个副本返回最新的数据 |
| QUORUM | 读请求由大多数副本的最新响应服务 |
| ALL | 读请求由所有副本的最新响应服务 |

## 一致性维护功能

在前一节中，我们深入讨论了读取和写入一致性，清楚的一点是 Cassandra 在执行读取或写入操作时不提供或不努力实现总一致性；它根据客户端的一致性规范执行并完成请求。另一个特性是*最终一致性*，它强调了在幕后有一些魔法，保证最终所有数据将是一致的。现在这个魔法是由 Cassandra 内部的某些组件执行的，其中一些如下所述：

+   **读修复**：此服务确保所有副本之间的数据是最新的。这样，行就是一致的，并且已经使用最新的值更新了所有副本。此操作由作业执行。Cassandra 正在运行以执行由协调员发出的读修复操作。

+   **反熵修复服务**：此服务确保不经常读取的数据，或者当一个宕机的主机重新加入时，处于一致的状态。这是一个常规的集群维护操作。

+   **提示性交接**：这是 Cassandra 上另一个独特而奇妙的操作。当执行写操作时，协调员向所有副本发出写操作，而不管指定的一致性，并等待确认。一旦确认计数达到操作的一致性上提到的值，线程就完成了，并且客户端被通知其成功。在剩余的副本上，使用提示性交接写入值。当一些节点宕机时，提示性交接方法是一个救世主。假设其中一个副本宕机，并且使用`ANY`的一致性执行写操作；在这种情况下，一个副本接受写操作并提示给当前宕机的相邻副本。当宕机的副本恢复时，然后从活动副本获取提示将值写回它们。

# 测验时间

Q.1\. 判断以下陈述是真还是假：

1.  Cassandra 有一个默认的`ALL`一致性。

1.  `QUORUM`是提供最高可用性的一致性级别。

1.  Cassandra 使用一个 snitch 来识别节点的接近程度。

1.  Cassandra 的读写特性默认具有一致性级别 1。

Q.2\. 填空：

1.  _______________ 用于确定节点的物理接近程度。

1.  _______________ 是提供最高可用性和最低可用性的一致性。

1.  _______________ 是确保宕机一段时间的节点正确更新为最新更改的服务。

Q.3\. 执行以下用例以查看 Cassandra 的高可用性和复制：

1.  创建一个四节点的 Cassandra 集群。

1.  创建一个副本因子为 3 的键空间。

1.  在这个键空间下的列族中添加一些数据。

1.  尝试使用`ALL`在选择查询中使用读一致性来检索数据。

1.  关闭一个节点上的 Cassandra 守护程序，并从其他三个活动节点重复第 4 步。

1.  关闭一个节点上的 Cassandra 守护程序，并使用`ANY`的一致性从其他三个活动节点重复第 4 步。

1.  关闭两个节点并使用`ANY`的写一致性更新现有值。

1.  尝试使用`ANY`进行读取。

1.  将宕机的节点恢复并从所有四个节点上使用一致性`ALL`执行`read`操作。

# 摘要

在本章中，您已经了解了 Cassandra 中的复制和数据分区的概念。我们还了解了复制策略和最终一致性的概念。本章末尾的练习是一个很好的实践练习，可以帮助您以实际方式理解本章涵盖的概念。

在下一章中，我们将讨论八卦协议、Cassandra 集群维护和管理特性。


# 第八章：Cassandra 管理和维护

在本章中，我们将学习 Cassandra 的八卦协议。然后，我们将深入了解 Cassandra 管理和管理，以了解扩展和可靠性的实际情况。这将使您能够处理您不希望遇到但在生产中确实发生的情况，例如处理可恢复节点、滚动重启等。

本章将涵盖以下主题：

+   Cassandra——八卦协议

+   Cassandra 扩展——向集群添加新节点

+   替换节点

+   复制因子更改

+   节点工具命令

+   滚动重启和容错

+   Cassandra 监控工具

因此，本章将帮助您了解 Cassandra 的基础知识，以及维护和管理 Cassandra 活动所需的各种选项。

# Cassandra - 八卦协议

八卦是一种协议，其中节点定期与其他节点交换关于它们所知道的节点的信息；这样，所有节点都通过这种点对点通信机制获取关于彼此的信息。这与现实世界和社交媒体世界的八卦非常相似。

Cassandra 每秒执行一次这个机制，一个节点能够与集群中最多三个节点交换八卦信息。所有这些八卦消息都有与之关联的版本，以跟踪时间顺序，旧的八卦交互更新会被新的覆盖。

既然我们知道 Cassandra 的八卦在很高的层面上是什么样子，让我们更仔细地看看它，并了解这个多嘴的协议的目的。以下是通过实施这个协议所达到的两个广泛目的：

+   引导

+   故障场景处理——检测和恢复

让我们了解它们在实际行动中的意义以及它们对 Cassandra 集群的健康和稳定性的贡献。

## 引导

引导是在集群中触发的一个过程，当一个节点第一次加入环时。我们在`Cassandra.yaml`配置文件下定义的种子节点帮助新节点获取有关集群、环、密钥集和分区范围的信息。建议您在整个集群中保持类似的设置；否则，您可能会在集群内遇到分区。一个节点在重新启动后会记住它与哪些节点进行了八卦。关于种子节点还有一点要记住，那就是它们的目的是在引导时为节点提供服务；除此之外，它既不是单点故障，也不提供任何其他目的。

## 故障场景处理——检测和恢复

好吧，八卦协议是 Cassandra 自己有效地知道何时发生故障的方式；也就是说，整个环都通过八卦知道了一个宕机的主机。相反的情况是，当一个节点加入集群时，同样的机制被用来通知环中的所有节点。

一旦 Cassandra 检测到环中的节点故障，它就会停止将客户端请求路由到该节点——故障确实对集群的整体性能产生了一定影响。然而，除非我们有足够的副本以确保一致性提供给客户端，否则它永远不会成为阻碍。

关于八卦的另一个有趣事实是，它发生在各个层面——Cassandra 的八卦，就像现实世界的八卦一样，可能是二手或三手等等；这是间接八卦的表现。

节点的故障可能是实际的或虚拟的。这意味着节点可能由于系统硬件故障而实际失败，或者故障可能是虚拟的，即在一段时间内，网络延迟非常高，以至于似乎节点没有响应。后一种情况大多数情况下是自我恢复的；也就是说，一段时间后，网络恢复正常，节点再次在环中被检测到。活动节点会定期尝试对失败的节点进行 ping 和 gossip，以查看它们是否正常。如果要将节点声明为永久离开集群，我们需要一些管理员干预来明确地从环中删除节点。

当节点在相当长时间后重新加入集群时，可能会错过一些写入（插入/更新/删除），因此，节点上的数据远非根据最新数据状态准确。建议使用`nodetool repair`命令运行修复。

# Cassandra 集群扩展-添加新节点

Cassandra 非常容易扩展，并且无需停机。这是它被选择而不是许多其他竞争者的原因之一。步骤非常简单明了：

1.  您需要在要添加的节点上设置 Cassandra。但是先不要启动 Cassandra 进程；首先按照以下步骤操作：

1.  在`seed_provider`下的`Cassandra.yaml`中更新种子节点。

1.  确保`tmp`文件夹是干净的。

1.  在`Cassandra.yaml`中添加`auto_bootstrap`并将其设置为`true`。

1.  在`Cassandra.yaml`中更新`cluster_name`。

1.  更新`Cassandra.yaml`中的`listen_address`/`broadcast_address`。

1.  逐个启动所有新节点，每两次启动之间至少暂停 5 分钟。

1.  一旦节点启动，它将根据自己拥有的标记范围宣布其数据份额并开始流式传输。可以使用`nodetoolnetstat`命令进行验证，如下面的代码所示：

```scala
mydomain@my-cass1:/home/ubuntu$ /usr/local/cassandra/apache- cassandra-1.1.6/bin/nodetool -h 10.3.12.29 netstats | grep - v 0%
Mode: JOINING
Not sending any streams.
Streaming from: /10.3.12.179
my_keyspace:  /var/lib/cassandra/data/my_keyspace/mycf/my_keyspace-my-hf- 461279-Data.db sections=1  progress=2382265999194/3079619547748 - 77%
Pool Name                    Active   Pending      Completed
Commands                        n/a         0             33
Responses                       n/a         0       13575829
mydomain@my-cass1:/home/ubuntu$

```

1.  在所有节点加入集群后，强烈建议在所有节点上运行`nodetool cleanup`命令。这是为了让它们放弃以前由它们拥有但现在属于已加入集群的新节点的键的控制。以下是命令和执行输出：

```scala
mydomain@my-cass3:/usr/local/cassandra/apache-cassandra- 1.1.6/bin$ sudo -bE ./nodetool -h 10.3.12.178 cleanup  my_keyspacemycf_index
mydomain@my-cass3:/usr/local/cassandra/apache-cassandra- 1.1.6/bin$ du -h   /var/lib/cassandra/data/my_keyspace/mycf_index/
53G  /var/lib/cassandra/data/my_keyspace/mycf_index/
mydomain@my-cass3:/usr/local/cassandra/apache-cassandra- 1.1.6/bin$ jps
27389 Jps
26893 NodeCmd
17925 CassandraDaemon

```

1.  请注意，`NodeCmd`进程实际上是 Cassandra 守护程序的清理过程。在前一个节点上清理后回收的磁盘空间显示在这里：

```scala
Size before cleanup – 57G
Size after cleanup – 30G

```

# Cassandra 集群-替换死节点

本节涵盖了可能发生并导致 Cassandra 集群故障的各种情况和场景。我们还将为您提供处理这些情况的知识并讨论相关步骤。这些情况特定于版本 1.1.6，但也适用于其他版本。

假设问题是这样的：您正在运行一个 n 节点，例如，假设有三个节点集群，其中一个节点宕机；这将导致不可恢复的硬件故障。解决方案是：用新节点替换死节点。

以下是实现解决方案的步骤：

1.  使用`nodetool ring`命令确认节点故障：

```scala
bin/nodetool ring -h hostname

```

1.  死节点将显示为`DOWN`；假设`node3`已宕机：

```scala
192.168.1.54 datacenter1rack1 Up  Normal 755.25 MB 50.00% 0
192.168.1.55 datacenter1rack1 Down Normal 400.62 MB 25.00%  42535295865117307932921825928971026432
192.168.1.56 datacenter1rack1 Up  Normal 793.06 MB 25.00%  85070591730234615865843651857942052864

```

1.  在替换节点上安装和配置 Cassandra。确保使用以下命令从替换的 Cassandra 节点中删除旧安装（如果有）：

```scala
sudorm -rf /var/lib/cassandra/*

```

在这里，`/var/lib/cassandra`是 Cassandra 的数据目录的路径。

1.  配置`Cassandra.yaml`，使其具有与现有 Cassandra 集群相同的非默认设置。

1.  在替换节点的`cassandra.yaml`文件中，将`initial_token`范围设置为死节点的标记 1 的值，即`42535295865117307932921825928971026431`。

1.  启动新节点将在环中死节点的前一个位置加入集群：

```scala
192.168.1.54 datacenter1rack1 Up    Normal 755.25 MB 50.00% 0
192.168.1.51 datacenter1rack1 Up    Normal 400.62 MB 0.00%  42535295865117307932921825928971026431
192.168.1.55 datacenter1rack1 Down     Normal 793.06 MB 25.00%  42535295865117307932921825928971026432
192.168.1.56 datacenter1rack1 Up    Normal 793.06 MB 25.00%  85070591730234615865843651857942052864

```

1.  我们快要完成了。只需在每个 keyspace 的每个节点上运行`nodetool repair`：

```scala
nodetool repair -h 192.168.1.54 keyspace_name -pr
nodetool repair -h 192.168.1.51 keyspace_name -pr
nodetool repair -h 192.168.1.56 keyspace_name–pr

```

1.  使用以下命令从环中删除死节点的令牌：

```scala
nodetoolremovetoken 85070591730234615865843651857942052864

```

这个命令需要在所有剩余的节点上执行，以确保所有活动节点知道死节点不再可用。

1.  这将从集群中删除死节点；现在我们完成了。

# 复制因子

偶尔，我们会遇到需要改变复制因子的情况。例如，我开始时使用较小的集群，所以将复制因子保持为 2。后来，我从 4 个节点扩展到 8 个节点，为了使整个设置更加安全，我将复制因子增加到 4。在这种情况下，需要按照以下步骤进行操作：

1.  以下是用于更新复制因子和/或更改策略的命令。在 Cassandra CLI 上执行这些命令：

```scala
ALTER KEYSPACEmy_keyspace WITH REPLICATION = { 'class' :  'SimpleStrategy', 'replication_factor' : 4 };

```

1.  一旦命令已更新，您必须依次在每个节点上执行`nodetool`修复，以确保所有键根据新的复制值正确复制：

```scala
sudo -bE ./nodetool -h 10.3.12.29 repair my_keyspacemycf -pr
6
mydomain@my-cass3:/home/ubuntu$ sudo -E  /usr/local/cassandra/apache-cassandra-1.1.6/bin/nodetool -h  10.3.21.29 compactionstats
pending tasks: 1
compaction type  keyspace         column family bytes  compacted      bytes total  progress
Validation       my_keyspacemycf  1826902206  761009279707   0.24%
Active compaction remaining time :        n/a
mydomain@my-cass3:/home/ubuntu$

```

以下`compactionstats`命令用于跟踪`nodetool repair`命令的进度。

# nodetool 命令

Cassandra 中的`nodetool`命令是 Cassandra 管理员手中最方便的工具。它具有所有类型的节点各种情况处理所需的工具和命令。让我们仔细看看一些广泛使用的命令：

+   `Ring`：此命令描述节点的状态（正常、关闭、离开、加入等）。令牌范围的所有权和键的百分比所有权以及数据中心和机架详细信息如下：

```scala
bin/nodetool -host 192.168.1.54 ring

```

输出将类似于以下内容：

```scala
192.168.1.54 datacenter1rack1 Up    Normal 755.25 MB 50.00% 0
192.168.1.51 datacenter1rack1 Up    Normal 400.62 MB 0.00%  42535295865117307932921825928971026431
192.168.1.55 datacenter1rack1 Down    Normal 793.06 MB 25.00%  42535295865117307932921825928971026432
192.168.1.56 datacenter1rack1 Up    Normal 793.06 MB 25.00%  85070591730234615865843651857942052864

```

+   `Join`：这是您可以与`nodetool`一起使用的选项，需要执行以将新节点添加到集群中。当新节点加入集群时，它开始从其他节点流式传输数据，直到根据环中的令牌确定的所有键都到达其指定的所有权。可以使用`netsat`命令检查此状态：

```scala
mydomain@my-cass3:/home/ubuntu$ /usr/local/cassandra/apache- cassandra-1.1.6/bin/nodetool -h 10.3.12.29 netstats | grep - v 0%
Mode: JOINING
Not sending any streams.
Streaming from: /10.3.12.179
my_keyspace:  /var/lib/cassandra/data/my_keyspace/mycf/my_keyspace-mycf- hf-46129-Data.db sections=1  progress=238226599194/307961954748 - 77%
Pool Name                    Active   Pending      Completed
Commands                        n/a         0             33
Responses                       n/a         0       13575829

```

+   `Info`：此`nodetool`选项获取有关以下命令指定的节点的所有必需信息：

```scala
bin/nodetool -host 10.176.0.146 info
Token(137462771597874153173150284137310597304)
Load Info        : 0 bytes.
Generation No    : 1
Uptime (seconds) : 697595
Heap Memory (MB) : 28.18 / 759.81

```

+   `Cleanup`：这通常是在扩展集群时使用的选项。添加新节点，因此现有节点需要放弃现在属于集群中新成员的键的控制权：

```scala
mydomain@my-cass3:/usr/local/cassandra/apache-cassandra- 1.1.6/bin$ sudo -bE ./nodetool -h 10.3.12.178 cleanup  my_keyspacemycf_index
mydomain@my-cass3:/usr/local/cassandra/apache-cassandra- 1.1.6/bin$ du -h  /var/lib/cassandra/data/my_keyspace/mycf_index/
53G  /var/lib/cassandra/data/my_keyspace/mycf_index/
aeris@nrt-prod-cass3-C2:/usr/local/cassandra/apache-cassandra- 1.1.6/bin$ sudo `which jps
27389 Jps
26893 NodeCmd
17925 CassandraDaemon
mydomain@my-cass3:/usr/local/cassandra/apache-cassandra- 1.1.6/bin$ du -h  /var/lib/cassandra/data/my_keyspace/mycf_index/
53G  /var/lib/cassandra/data/my_keyspace/mycf_index/

```

+   `Compaction`：这是最有用的工具之一。它用于明确向 Cassandra 发出`compact`命令。这可以在整个节点、键空间或列族级别执行：

```scala
sudo -bE /usr/local/cassandra/apache-cassandra- 1.1.6/bin/nodetool -h 10.3.1.24 compact
mydomain@my-cass3:/home/ubuntu$ sudo -E  /usr/local/cassandra/apache-cassandra-1.1.6/bin/nodetool -h  10.3.1.24 compactionstats
pending tasks: 1
compaction type keyspace column family bytes compacted bytes  total progress
Compaction my_keyspacemycf 1236772 1810648499806 0.00%
Active compaction remaining time:29h58m42s
mydomain@my-cass3:/home/ubuntu$

```

Cassandra 有两种类型的压缩：小压缩和大压缩。小压缩周期在创建新的`sstable`数据时执行，以删除所有墓碑（即已删除的条目）。

主要压缩是手动触发的，使用前面的`nodetool`命令。这可以应用于节点、键空间和列族级别。

+   `Decommission`：这在某种程度上是引导的相反，当我们希望节点离开集群时触发。一旦活动节点接收到命令，它将停止接受新的权限，刷新`memtables`，并开始从自身流式传输数据到将成为当前拥有键范围的新所有者的节点：

```scala
bin/nodetool -h 192.168.1.54 decommission

```

+   `Removenode`：当节点死亡，即物理不可用时，执行此命令。这通知其他节点节点不可用。Cassandra 复制开始工作，通过根据新的环所有权创建数据的副本来恢复正确的复制：

```scala
bin/nodetoolremovenode<UUID>
bin/nodetoolremovenode force

```

+   `修复`：执行此`nodetool repair`命令以修复任何节点上的数据。这是确保数据一致性以及在一段时间后重新加入集群的节点存在的非常重要的工具。假设有一个由四个节点组成的集群，这些节点通过风暴拓扑不断进行写入。在这里，其中一个节点下线并在一两个小时后重新加入环。现在，在此期间，该节点可能错过了一些写入；为了修复这些数据，我们应该在节点上执行`repair`命令：

```scala
bin/nodetool repair

```

# Cassandra 容错

使用 Cassandra 作为数据存储的主要原因之一是其容错能力。它不是由典型的主从架构驱动的，其中主节点的故障成为系统崩溃的单一点。相反，它采用环模式的概念，因此没有单一故障点。在需要时，我们可以重新启动节点，而不必担心将整个集群带下线；在各种情况下，这种能力都非常方便。

有时需要重新启动 Cassandra，但 Cassandra 的环架构使管理员能够在不影响整个集群的情况下无缝进行此操作。这意味着在需要重新启动 Cassandra 集群的情况下，例如需要逐个重新启动节点而不是将整个集群带下线然后重新启动的情况下，Cassandra 管理员可以逐个重新启动节点：

+   使用内存配置更改启动 Cassandra 守护程序

+   在已运行的 Cassandra 集群上启用 JMX

+   有时机器需要例行维护和重新启动

# Cassandra 监控系统

现在我们已经讨论了 Cassandra 的各种管理方面，让我们探索 Cassandra 集群的各种仪表板和监控选项。现在有各种免费和许可的工具可用，我们将在下面讨论。

## JMX 监控

您可以使用基于`jconsole`的一种监控 Cassandra 的类型。以下是使用`jconsole`连接到 Cassandra 的步骤：

1.  在命令提示符中，执行`jconsole`命令：![JMX 监控](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/rt-anlt-storm-csdr/img/00051.jpeg)

1.  在下一步中，您必须指定 Cassandra 节点的 IP 和端口以进行连接：![JMX 监控](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/rt-anlt-storm-csdr/img/00052.jpeg)

1.  一旦连接，JMX 提供各种图形和监控实用程序：![JMX 监控](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/rt-anlt-storm-csdr/img/00053.jpeg)

开发人员可以使用 jconsole 的**内存**选项卡监视堆内存使用情况。这将帮助您了解节点资源的利用情况。

jconsole 的限制在于它执行特定于节点的监控，而不是基于 Cassandra 环的监控和仪表板。让我们在这个背景下探索其他工具。

## Datastax OpsCenter

这是一个由 Datastax 提供的实用程序，具有图形界面，可以让用户从一个中央仪表板监视和执行管理活动。请注意，免费版本仅适用于非生产用途。

Datastax Ops Center 为各种重要的系统**关键性能指标**（**KPI**）提供了许多图形表示，例如性能趋势、摘要等。其用户界面还提供了对单个数据点的历史数据分析和深入分析能力。OpsCenter 将其所有指标存储在 Cassandra 本身中。OpsCenter 实用程序的主要特点如下：

+   基于 KPI 的整个集群监控

+   警报和报警

+   配置管理

+   易于设置

您可以使用以下简单步骤安装和设置 OpsCenter：

1.  运行以下命令开始：

```scala
$ sudo service opscenterd start

```

1.  在 Web 浏览器中连接到 OpsCenter，网址为`http://localhost:8888`。

1.  您将获得一个欢迎屏幕，在那里您将有选项生成一个新集群或连接到现有集群。

1.  接下来，配置代理；一旦完成，OpsCenter 即可使用。

这是应用程序的屏幕截图：

![Datastax OpsCenter](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/rt-anlt-storm-csdr/img/00054.jpeg)

在这里，我们选择要执行的度量标准以及操作是在特定节点上执行还是在所有节点上执行。以下截图捕捉了 OpsCenter 启动并识别集群中的各个节点的情况：

![Datastax OpsCenter](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/rt-anlt-storm-csdr/img/00055.jpeg)

以下截图捕捉了集群读写、整体集群延迟、磁盘 I/O 等方面的各种关键绩效指标：

![Datastax OpsCenter](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/rt-anlt-storm-csdr/img/00056.jpeg)

# 测验时间

Q.1. 判断以下陈述是真还是假。

1.  Cassandra 存在单点故障。

1.  Cassandra 环中立即检测到死节点。

1.  Gossip 是一种数据交换协议。

1.  `decommission`和`removenode`命令是相同的。

Q.2. 填空。

1.  _______________ 是运行压缩的命令。

1.  _______________ 是获取有关活动节点信息的命令。

1.  ___________ 是显示整个集群信息的命令。

Q.3. 执行以下用例以查看 Cassandra 的高可用性和复制：

1.  创建一个 4 节点的 Cassandra 集群。

1.  创建一个副本因子为 3 的键空间。

1.  关闭一个节点上的 Cassandra 守护程序。

1.  在每个节点上执行`nestat`以查看数据流。

# 总结

在本章中，您了解了疏散协议的概念和用于各种场景的适应工具，例如扩展集群、替换死节点、压缩和修复 Cassandra 上的操作。

在下一章中，我们将讨论风暴集群的维护和运营方面。


# 第九章：风暴管理和维护

在本章中，您将了解 Storm 集群的扩展。您还将看到如何调整 Storm 拓扑的工作节点和并行性。

我们将涵盖以下主题：

+   添加新的监督员节点

+   设置工作节点和并行性以增强处理

+   故障排除

# 扩展 Storm 集群-添加新的监督员节点

在生产中，最常见的情况之一是处理需求超过了集群的大小。此时需要进行扩展；有两种选择：我们可以进行垂直扩展，在其中可以添加更多的计算能力，或者我们可以使用水平扩展，在其中添加更多的节点。后者更具成本效益，也使集群更加健壮。

以下是要执行的步骤，以将新节点添加到 Storm 集群中：

1.  下载并安装 Storm 的 0.9.2 版本，因为它是集群中其余部分使用的，通过解压下载的 ZIP 文件。

1.  创建所需的目录：

```scala
sudo mkdir –p /usr/local/storm/tmp

```

1.  所有 Storm 节点、Nimbus 节点和监督员都需要一个位置来存储与本地磁盘上的配置相关的少量数据。请确保在所有 Storm 节点上创建目录并分配读/写权限。

1.  创建日志所需的目录，如下所示：

```scala
sudo mkdir –p /mnt/app_logs/storm/storm_logs

```

1.  更新`storm.yaml`文件，对 Nimbus 和 Zookeeper 进行必要的更改：

```scala
#storm.zookeeper.servers: This is a list of the hosts in the  Zookeeper cluster for Storm cluster
storm.zookeeper.servers: 
  - "<IP_ADDRESS_OF_ZOOKEEPER_ENSEMBLE_NODE_1>"
  - "<IP_ADDRESS_OF_ZOOKEEPER_ENSEMBLE_NODE_2>"
#storm.zookeeper.port: Port on which zookeeper cluster is running.
  storm.zookeeper.port: 2182
#For our installation, we are going to create this directory in  /usr/local/storm/tmp location.
storm.local.dir: "/usr/local/storm/tmp"
#nimbus.host: The nodes need to know which machine is the #master  in order to download topology jars and confs. This #property is  used for the same purpose.
nimbus.host: "<IP_ADDRESS_OF_NIMBUS_HOST>"
#storm.messaging.netty configurations: Storm's Netty-based  #transport has been overhauled to significantly improve  #performance through better utilization of thread, CPU, and  #network resources, particularly in cases where message sizes  #are small. In order to provide netty support, following  #configurations need to be added :
storm.messaging.transport:"backtype.storm.messaging.netty.Context"
storm.messaging.netty.server_worker_threads:1
storm.messaging.netty.client_worker_threads:1
storm.messaging.netty.buffer_size:5242880
storm.messaging.netty.max_retries:100
storm.messaging.netty.max_wait_ms:1000
storm.messaging.netty.min_wait_ms:100
```

监督员端口的插槽值如下：

| `supervisor.slots.ports` |
| --- |
| - 6700 |
| - 6701 |
| - 6702 |
| - 6703 |

1.  在`~/.bashrc`文件中设置`STORM_HOME`环境，并将 Storm 的`bin`目录添加到`PATH`环境变量中。这样可以从任何位置执行 Storm 二进制文件。要添加的条目如下：

```scala
STORM_HOME=/usr/local/storm
PATH=$PATH:$STORM_HOME/bin

```

1.  在以下每台机器和节点上更新`/etc/hosts`：

+   nimbus 机器：这是为了为正在添加的新监督员添加条目

+   所有现有的监督员机器：这是为了为正在添加的新监督员添加条目

+   新的监督员节点：这是为了添加 nimbus 条目，为所有其他监督员添加条目，并为 Zookeeper 节点添加条目

```scala
sup-flm-1.mydomain.com host:
```

```scala
10.192.206.160    sup-flm-2\. mydomain.net
10.4.27.405       nim-zkp-flm-3\. mydomain.net
```

一旦监督员被添加，启动进程，它应该在 UI 上可见，如下面的截图所示：

![扩展 Storm 集群-添加新的监督员节点](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/rt-anlt-storm-csdr/img/00057.jpeg)

请注意，前面截图中的第一行指向新添加的监督员；它总共有 16 个插槽，目前使用`0`个插槽，因为它刚刚添加到集群中。

# 扩展 Storm 集群和重新平衡拓扑

一旦添加了新的监督员，下一个明显的步骤将是重新平衡在集群上执行的拓扑，以便负载可以在新添加的监督员之间共享。

## 使用 GUI 重新平衡

重新平衡选项在 Nimbus UI 上可用，您可以选择要重新平衡的拓扑，然后使用 GUI 中的选项。拓扑会根据指定的超时时间排空。在此期间，它停止接受来自 spout 的任何消息，并处理内部队列中的消息，一旦完全清除，工作节点和任务将重新分配。用户还可以使用重新平衡选项增加或减少各种螺栓和 spout 的并行性。以下截图描述了如何使用 Storm UI 选项重新平衡拓扑：

![使用 GUI 重新平衡](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/rt-anlt-storm-csdr/img/00058.jpeg)

## 使用 CLI 重新平衡

重新平衡的第二个选项是使用 Storm CLI。其命令如下：

```scala
storm rebalance mystormtopology -n 5 -e my-spout=3 -e my-bolt=10

```

在这里，`-n`指定了重新平衡后分配给拓扑的工作器数量，`-e my-spout`指的是分配给 spout 的并行性，同样`-e my-bolt`指的是要分配给螺栓的并行性。在前面的命令中，我们从 Storm 安装 JAR 的`bin`目录下执行了 Storm shell，并在重新平衡 Storm 拓扑时同时改变了 spout 和螺栓的并行性。

可以从 Storm UI 验证对前面命令的执行更改。

# 设置工作器和并行性以增强处理

Storm 是一个高度可扩展、分布式和容错的实时并行处理计算框架。请注意，重点是可扩展性、分布式和并行处理——好吧，我们已经知道 Storm 以集群模式运行，因此在基本性质上是分布式的。可扩展性在前一节中已经涵盖了；现在，让我们更仔细地看看并行性。我们在早些时候的章节中向您介绍了这个概念，但现在我们将让您了解如何调整它以实现所需的性能。以下几点是实现这一目标的关键标准：

+   拓扑在启动时被分配了一定数量的工作器。

+   拓扑中的每个组件（螺栓和 spout）都有指定数量的执行者与之关联。这些执行者指定了拓扑的每个运行组件的并行性数量或程度。

+   Storm 的整体效率和速度因素都受 Storm 的并行性特性驱动，但我们需要明白一件事：所有归因于并行性的执行者都在拓扑分配的有限工作器集合内运行。因此，需要理解增加并行性只能在一定程度上提高效率，但超过这一点后，执行者将争夺资源。超过这一点增加并行性将无法提高效率，但增加分配给拓扑的工作器将使计算更加高效。

在效率方面，另一个需要理解的点是网络延迟；我们将在接下来的部分中探讨这一点。

## 场景 1

以下图示了一个简单的拓扑，有三个移动组件：一个 spout 和两个螺栓。在这里，所有组件都在集群中的不同节点上执行，因此每个元组必须经过两次网络跳转才能完成执行。

![场景 1](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/rt-anlt-storm-csdr/img/00059.jpeg)

假设我们对吞吐量不满意，并决定增加并行性。一旦我们尝试采用这种技术，就会出现一个问题，即在哪里增加以及增加多少。这可以根据螺栓的容量来计算，这应该可以从 Storm UI 中看到。以下截图说明了这一点：

![场景 1](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/rt-anlt-storm-csdr/img/00060.jpeg)

在这里，圈出的值是第二个螺栓的容量，大约为 0.9，已经是红色的，这意味着这个螺栓超负荷工作，增加并行性应该有所帮助。任何拓扑实际上都会在螺栓容量超过`1`时中断并停止确认。为了解决这个问题，让我们看看下一个场景，为这个问题提供一个解决方案。

## 场景 2

在这里，我们已经意识到**Bolt B**超负荷，并增加了并行性，如下图所示：

![场景 2](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/rt-anlt-storm-csdr/img/00061.jpeg)

前面的图描述了一个场景，捕捉了集群中不同节点上各种螺栓和 spout 实例的分布。在这里，我们已经意识到一个螺栓超负荷，并观察了容量，通过强制手段，只增加了该螺栓的并行性。

现在，做到了这一点，我们已经实现了所需的并行性；现在让我们来看看网络延迟，即元组在节点之间移动的数量（节点间通信是分布式计算设置中的一个必要元素）：

+   50％的流量在**Machine 1**和**Machine 2**之间跳转

+   50％的流量在**Machine 1**和**Machine 3**之间跳转

+   100％的流量在**Machine 2**和**Machine 3**之间跳转

现在让我们看另一个示例，稍微改变并行性。

## 场景 3

场景 3 是在示例设置中可能出现的最佳场景，我们可以非常有效地使用网络和并行性，如下图所示：

![场景 3](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/rt-anlt-storm-csdr/img/00062.jpeg)

现在，上图是一个示例，展示了我们如何最大程度地利用并行性。如果您看一下上图，您会发现我们已经实现了效率，没有网络跳数；两全其美。

我试图说明的是，并行性应该在考虑网络延迟、跳数和本地处理速度的影响下进行审慎更改。

# Storm 故障排除

作为开发人员，我们需要接受现实，事情确实会出错，需要调试。本节将使您能够有效和高效地处理这种情况。首先要理解编程世界的两个根本口诀：

+   假设一切可能出问题的地方都会出问题

+   任何可能出现问题的地方都可以修复

接受现实，首先通过了解可能出现问题的地方，然后清楚地了解我们应该从哪里开始分析，以帮助我们处理 Storm 集群中的任何情况。让我们了解一下各种指针，显示出问题，并引导我们找到潜在的解决方案。

## Storm UI

首先，让我们了解 UI 本身存在哪些统计数据和指标。最新的 UI 有大量指标，让我们洞悉集群中正在发生的事情以及可能出现问题的地方（以防出现故障）。

让我们看一下 Storm UI，其中**Cluster Summary**包括，例如，`http:// nimbus 的 IP:8080`在我的情况下是`http://10.4.2.122:8080`，我的 UI 进程在具有此 IP 的 nimbus 机器上执行：10.4.2.122。

![Storm UI](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/rt-anlt-storm-csdr/img/00063.jpeg)

在前面的屏幕截图中，我们可以看到以下参数：

+   使用的 Storm 版本在第一列中。

+   Nimbus 的正常运行时间（第二列）告诉我们自上次重启以来 Nimbus 节点已经运行了多长时间。正如我们所知，Nimbus 只在拓扑被提交时或监督者或工作人员下线并且任务再次被委派时才需要。在拓扑重平衡期间，Nimbus 也是必需的。

+   第三列给出了集群中监督者的数量。

+   第四、五和六列显示了 Storm 监督者中已使用的工作槽的数量、空闲工作槽的数量和工作槽的总数。这是一个非常重要的统计数据。在任何生产级别的集群中，应该始终为一些工作人员下线或一两个监督者被杀死做好准备。因此，我建议您始终在集群上有足够的空闲槽，以容纳这种突发故障。

+   第七列和第八列指定了拓扑中正在移动的任务，即系统中运行的任务和执行者的数量。

让我们看一下 Storm UI 开启页面上的第二部分；这部分捕获了拓扑摘要：

![Storm UI](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/rt-anlt-storm-csdr/img/00064.jpeg)

本节描述了 Storm 在拓扑级别捕获和显示的各种参数：

+   第一列和第二列分别显示了拓扑的**Name**字段和拓扑的**Id**字段。

+   第三列显示了拓扑的状态，对于正在执行和处理的拓扑来说，状态是**ACTIVE**。

+   第四列显示了自拓扑启动以来的正常运行时间。

+   接下来的三列显示**Numworkers**，**Num tasks**和**Num executors**；这些是拓扑性能的非常重要的方面。在调整性能时，人们必须意识到仅仅增加**Num tasks**和**Num executors**字段的值可能不会导致更高的效率。如果工作人员的数量很少，而我们只增加执行器和任务的数量，那么由于工作人员数量有限，资源的匮乏会导致拓扑性能下降。

同样，如果我们将太多的工作人员分配给一个拓扑结构，而没有足够的执行器和任务来利用所有这些工作人员，我们将浪费宝贵的资源，因为它们被阻塞和空闲。

另一方面，如果我们有大量的工作人员和大量的执行器和任务，那么由于网络延迟，性能可能会下降。

在陈述了这些事实之后，我想强调性能调优应该谨慎和审慎地进行，以确定适用于我们正在尝试实施的用例的数量。

以下截图捕获了有关监督者的详细信息，以及相应信息的统计数据：

![The Storm UI](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/rt-anlt-storm-csdr/img/00065.jpeg)

+   第一列是**Id**字段，用于监督者，第二列是运行监督者进程的**hosts**字段的名称。

+   第三列显示了监督者运行的时间。

+   第五列和第六列分别捕获了监督者上可用插槽的数量和已使用的插槽的数量。这两个数字在判断和理解监督者的运行容量以及它们处理故障情况的带宽方面提供了非常重要的指标；例如，我的所有监督者都以 100%的容量运行，所以在这种情况下，我的集群无法处理任何故障。

以下截图是从 Storm UI 中捕获的，显示了监督者及其属性：

![The Storm UI](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/rt-anlt-storm-csdr/img/00066.jpeg)

前面的部分为我们提供了有关监督者插槽、超时等的详细信息。这些值在`storm.yaml`中指定，但可以从 UI 中验证。例如，在我的情况下，`http:// nimbus 的 IP:8080`是`http://10.4.2.122:8080`，我的 UI 进程在具有此 IP 的 Nimbus 机器上执行：10.4.2.122，如下图所示：

![The Storm UI](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/rt-anlt-storm-csdr/img/00067.jpeg)

现在，在下面的截图所示的部分中，可以通过在 Storm UI 上单击任何拓扑名称来深入了解拓扑详细信息。这一部分包含了有关拓扑组件的详细信息，包括螺栓、喷口的级别以及有关它们的详细信息，如下图所示：

![The Storm UI](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/rt-anlt-storm-csdr/img/00068.jpeg)

前面的截图显示了有关每个组件分配的执行器或任务数量，以及螺栓或喷口发射的元组数量以及传输到**有向无环图**（**DAG**）中下一个组件的元组数量。

拓扑详细页面上应该注意的其他重要细节如下：

+   过去 10 分钟内螺栓的**容量**：这个值应该远低于 1。

+   **执行延迟**以毫秒为单位：这决定了通过该组件执行元组所需的时间。如果这个值太高，那么我们可能希望将执行分成两个或更多的螺栓，以利用并行性并提高效率。

+   **已执行**：这个值存储了该组件成功执行的元组数量。

+   **处理延迟**：这个值显示了组件执行元组所需的平均总时间。这个值应该与执行延迟一起分析。以下是可能发生的实际情况：

+   **执行延迟**和**处理延迟**都很低（这是最理想的情况）

+   **执行延迟**很低，但**处理延迟**非常高（这意味着实际执行时间较短，与总执行时间相比较高，并且增加并行性可能有助于提高效率）

+   **执行延迟**和**处理延迟**都很高（再次增加并行性可能有所帮助）

## Storm 日志

如果事情不如预期，下一个调试的地方就是 Storm 日志。首先，需要知道 Storm 日志的位置，还需要在`cluster.xml`的`storm-0.9.2-incubating.zip\apache-storm-0.9.2-incubating\logback\cluster.xml`中更新路径：

```scala
<appender class="ch.qos.logback.core.rolling.RollingFileAppender"  name="A1">
  <!—update this as below  <file>${storm.home}/logs/${logfile.name}</file> -->
 <file>/mnt/app_logs/storm/storm_logs/${logfile.name}</file>
  <rollingPolicy  class="ch.qos.logback.core.rolling.FixedWindowRollingPolicy">
    <fileNamePattern>${storm.home}/logs/${logfile.name}.%i </fileNamePattern>
    <minIndex>1</minIndex>
    <maxIndex>9</maxIndex>
</rollingPolicy>
<triggeringPolicy  class="ch.qos.logback.core.rolling.SizeBasedTriggeringPolicy">
    <maxFileSize>100MB</maxFileSize>
</triggeringPolicy>
  <encoder>
    <pattern>%d{yyyy-MM-dd HH:mm:ss} %c{1} [%p] %m%n</pattern>
  </encoder>
</appender>
```

现在粗体字的那一行会告诉你 Storm 日志将被创建的路径/位置。让我们仔细看看不同 Storm 守护程序创建了哪些类型的日志。

可以使用以下命令在 shell 上获取 Nimbus 节点日志：

```scala
Cd /mnt/my_logs/strom/storm_logs
ls-lart

```

Nimbus 日志目录的列表如下截图所示：

![Storm logs](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/rt-anlt-storm-csdr/img/00069.jpeg)

注意我们有`nimbus.log`，其中包含有关 Nimbus 启动、错误和信息日志的详细信息；`ui.log`是在启动 Storm UI 应用程序的节点上创建的。

可以使用以下命令在 shell 上获取监督者节点的日志：

```scala
Cd /mnt/my_logs/strom/storm_logs
ls-lart

```

监督者日志目录的列表如下截图所示：

![Storm logs](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/rt-anlt-storm-csdr/img/00070.jpeg)

可以查看监督者日志和工作日志。监督者日志记录了监督者启动的详细信息，任何错误等。工作日志是开发人员拓扑日志和各种螺栓和喷口的 Storm 日志所在的地方。

因此，如果我们想要调试 Storm 守护进程，我们会查看`nimbus.log`和`supervisor.log`。如果你遇到问题，那么你需要使用相应的工作日志进行调试。Nimbus 和工作节点故障的情况已在第四章中进行了介绍，*集群模式下的 Storm*。

现在让我们想象一个场景。我是一个开发人员，我的拓扑结构表现不如预期，我怀疑其中一个螺栓的功能不如预期。因此，我们需要调试工作日志并找出根本原因。现在我们需要找出多个监督者和众多工作日志中要查看哪个工作日志；我们将从 Storm UI 中获取这些信息。执行以下步骤：

1.  打开**Storm UI**并点击有问题的拓扑。

1.  点击拓扑的疑似螺栓或喷口。屏幕上会出现与此截图相似的内容：![Storm logs](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/rt-anlt-storm-csdr/img/00071.jpeg)

这是调试这个螺栓发生的情况的线索；我将查看`Supervisor5`和`Supervisor6`，`supervisor5`和`supervisor6`上的`worker-6705.log`。

# 测验时间

Q.1\. 判断以下陈述是真还是假：

1.  在执行拓扑的情况下，无法将 Storm 节点添加到集群中。

1.  拓扑无法在 Storm 节点故障时生存。

1.  Storm 日志在集群中的每个节点上创建。

1.  Storm 日志创建的位置是可配置的。

Q.2\. 填空：

1.  _______________ 是集群的心跳跟踪器。

1.  _______________ 是拓扑提交和重平衡所必需的守护程序。

1.  ___________ 文件保存了拓扑的工作配置。

Q.3\. 执行以下用例以查看 Storm 的内部情况：

1.  启动 Nimbus 并检查`nimbus.log`，查看成功启动的情况。

1.  启动监督者并检查`Supervisor.log`，查看成功启动的情况。

1.  提交拓扑，比如一个简单的`WordCount`拓扑，并找出`worker.log`文件的创建情况。

1.  更新`log4j.properties`以更改日志级别并验证其影响。

# 摘要

在本章中，我们已经涵盖了 Storm 的维护概念，包括添加新节点、重新平衡和终止拓扑。我们已经了解并调整了诸如`numtasks`和并行性与`numworkers`和网络延迟相结合的内部机制。您学会了定位和解读 Storm 组件的日志。您还了解了 Storm UI 的指标及其对拓扑性能的影响。

在下一章中，我们将讨论 Storm 的高级概念，包括微批处理和 Trident API。


# 第十章：风暴中的高级概念

在本章中，我们将涵盖以下主题：

+   构建 Trident 拓扑

+   理解 Trident API

+   示例和插图

在本章中，我们将学习事务性拓扑和 Trident API。我们还将探讨微批处理的方面以及它在 Storm 拓扑中的实现。

# 构建 Trident 拓扑

Trident 为 Storm 计算提供了批处理边缘。它允许开发人员在 Storm 框架上使用抽象层进行计算，从而在分布式查询中获得有状态处理和高吞吐量的优势。

嗯，Trident 的架构与 Storm 相同；它是建立在 Storm 之上的，以在 Storm 之上添加微批处理功能和执行类似 SQL 的函数的抽象层。

为了类比，可以说 Trident 在概念上很像 Pig 用于批处理。它支持连接、聚合、分组、过滤、函数等。

Trident 具有基本的批处理功能，例如一致处理和对元组的执行逻辑进行一次性处理。

现在要理解 Trident 及其工作原理；让我们看一个简单的例子。

我们选择的例子将实现以下功能：

+   对句子流进行单词计数（标准的 Storm 单词计数拓扑）

+   用于获取一组列出的单词计数总和的查询实现

这是解剖的代码：

```scala
FixedBatchSpout myFixedspout = new FixedBatchSpout(new  Fields("sentence"), 3,
new Values("the basic storm topology do a great job"),
new Values("they get tremendous speed and guaranteed processing"),
new Values("that too in a reliable manner "),
new Values("the new trident api over storm gets user more features  "),
new Values("it gets micro batching over storm "));
myFixedspout.setCycle(true);
```

```scala
myFixedspout cycles over the set of sentences added as values. This snippet ensures that we have an endless flow of data streams into the topology and enough points to perform all micro-batching functions that we intend to.
```

现在我们已经确保了连续的输入流，让我们看下面的片段：

```scala
//creating a new trident topology
TridentTopology myTridentTopology = new TridentTopology();
//Adding a spout and configuring the fields and query 
TridentState myWordCounts = topology.newStream("myFixedspout",  spout)
  .each(new Fields("sentence"), new Split(), new Fields("word"))
  .groupBy(new Fields("word"))
  .persistentAggregate(new MemoryMapState.Factory(), new Count(),  new Fields("count"))
  .parallelismHint(6);
```

```scala
Now the micro-batching; who does it and how? Well the Trident framework stores the state for each source (it kind of remembers what input data it has consumed so far). This state saving is done in the Zookeeper cluster. The tagging *spout* in the preceding code is actually a znode, which is created in the Zookeeper cluster to save the state metadata information.
```

这些元数据信息存储在小批处理中，其中批处理大小是根据传入元组的速度变化的变量；它可以是几百到数百万个元组，具体取决于每秒的事件**事务数**（**tps**）。

现在我的喷口读取并将流发射到标记为`sentence`的字段中。在下一行，我们将句子分割成单词；这正是我们在前面提到的`wordCount`拓扑中部署的相同功能。

以下是捕捉`split`功能工作的代码上下文：

```scala
public class Split extends BaseFunction {
  public void execute(TridentTuple tuple, TridentCollector  collector) {
      String sentence = tuple.getString(0);
      for(String word: sentence.split(" ")) {
          collector.emit(new Values(word));
      }
  }
}
```

```scala
Trident with Storm is so popular because it guarantees the processing of all tuples in a fail-safe manner in exactly one semantic. In situations where retry is necessary because of failures, it does that exactly once and once only, so as a developer I don't end up updating the table storage multiple times on occurrence of a failure.

```

在前面的代码片段中，我们使用`myTridentTopology`创建了一个 DRPC 流，此外，我们还有一个名为`word`的函数。

+   我们将参数流分割成其组成的单词；例如，我的参数`storm trident topology`被分割成诸如`storm`、`trident`和`topology`等单词* 然后，传入的流被按`word`分组* 接下来，状态查询操作符用于查询由拓扑的第一部分生成的 Trident 状态对象：

+   状态查询接收拓扑先前部分计算的单词计数。

+   然后它执行作为 DRPC 请求的一部分指定的函数来查询数据。

+   在这种情况下，我的拓扑正在执行查询的`MapGet`函数，以获取每个单词的计数；在我们的情况下，DRPC 流以与拓扑前一部分中的`TridentState`完全相同的方式分组。这种安排确保了每个单词的所有计数查询都被定向到`TridentState`对象的相同 Trident 状态分区，该对象将管理单词的更新。

+   `FilterNull`确保没有计数的单词被过滤掉* 然后求和聚合器对所有计数求和以获得结果，结果会自动返回给等待的客户端

在理解开发人员编写的代码执行之后，让我们看看 Trident 的样板文件以及当这个框架执行时自动发生的事情。

+   在我们的 Trident 单词计数拓扑中有两个操作，它们从状态中读取或写入——`persistentAggregate`和`stateQuery`。Trident 具有自动批处理这些操作的能力，以便将它们批处理到状态。例如，当前处理需要对数据库进行 10 次读取和写入；Trident 会自动将它们一起批处理为一次读取和一次写入。这为您提供了性能和计算的便利，优化由框架处理。

+   Trident 聚合器是框架的其他高效和优化组件。它们不遵循将所有元组传输到一台机器然后进行聚合的规则，而是通过在可能的地方执行部分聚合，然后将结果传输到网络来优化计算，从而节省网络延迟。这里采用的方法类似于 MapReduce 世界中的组合器。

# 理解 Trident API

Trident API 支持五大类操作：

+   用于操作本地数据分区的操作，无需网络传输

+   与流重新分区相关的操作（涉及通过网络传输流数据）

+   流上的数据聚合（此操作作为操作的一部分进行网络传输）

+   流中字段的分组

+   合并和连接

## 本地分区操作

正如其名称所示，这些操作在每个节点上对批处理进行本地操作，不涉及网络流量。以下功能属于此类别。

### 函数

+   此操作接受单个输入值，并将零个或多个元组作为输出发射

+   这些函数操作的输出附加到原始元组的末尾，并发射到流中

+   在函数不发射输出元组的情况下，框架也会过滤输入元组，而在其他情况下，输入元组会被复制为每个输出元组

让我们通过一个示例来说明这是如何工作的：

```scala
public class MyLocalFunction extends BaseFunction {
  public void execute(TridentTuple myTuple, TridentCollector  myCollector) {
      for(int i=0; i < myTuple.getInteger(0); i++) {
          myCollector.emit(new Values(i));
      }
  }
}
```

现在假设，变量`myTridentStream`中的输入流具有以下字段`["a"，"b"，"c"]`，流中的元组如下所示：

```scala
[10, 2, 30]
[40, 1, 60]
[30, 0, 80]
```

```scala
mystream.each(new Fields("b"), new MyLocalFunction(), new  Fields("d")))
```

这里期望的输出是根据函数应该返回`["a"，"b"，"c"，"d"]`，所以对于流中的前面的元组，我将得到以下输出：

```scala
//for input tuple [10, 2, 30] loop in the function executes twice  //value of b=2
[10, 2, 30, 0]
[10, 2, 30, 1]
//for input tuple [4, 1, 6] loop in the function executes once  value //of b =1
[4, 1, 6, 0]
//for input tuple [3, 0, 8]
//no output because the value of field b is zero and the for loop  //would exit in first iteration itself value of b=0
```

### 过滤器

过滤器并非名不副实；它们的执行与其名称所示完全相同：它们帮助我们决定是否保留元组，它们确切地做到了过滤器的作用，即根据给定的条件删除不需要的内容。

让我们看下面的片段，以查看过滤函数的工作示例：

```scala
public class MyLocalFilterFunction extends BaseFunction {
    public boolean isKeep(TridentTuple tuple) {
      return tuple.getInteger(0) == 1 && tuple.getInteger(1) == 2;
    }
}
```

让我们看看输入流上的示例元组，字段为`["a"，"b"，"c"]`：

```scala
[1,2,3]
[2,1,1]
[2,3,4]
```

我们执行或调用函数如下：

```scala
mystream.each(new Fields("b", "a"), new MyLocalFilterFunction())
```

输出将如下所示：

```scala
//for tuple 1 [1,2,3]
// no output because valueof("field b") ==1 && valueof("field a")  ==2 //is not satisfied 
//for tuple 1 [2,1,1]
// no output because valueof("field b") ==1 && valueof("field a")  ==2 [2,1,1]
//for tuple 1 [2,3,4]
// no output because valueof("field b") ==1 && valueof("field a")  ==2 //is not satisfied
```

### partitionAggregate

`partitionAggregate`函数对一批元组的每个分区进行操作。与迄今为止执行的本地函数相比，此函数之间存在行为差异，它对输入元组发射单个输出元组。

以下是可以用于在此框架上执行各种聚合的其他函数。

#### Sum 聚合

以下是对 sum 聚合器函数的调用方式：

```scala
mystream.partitionAggregate(new Fields("b"), new Sum(), new Fields("sum"))
```

假设输入流具有`["a"，"b"]`字段，并且以下是元组：

```scala
Partition 0:
["a", 1]
["b", 2]
Partition 1:
["a", 3]
["c", 8]
Partition 2:
["e", 1]
["d", 9]
["d", 10]
```

输出将如下所示：

```scala
Partition 0:
[3]
Partition 1:
[11]
Partition 2:
[20]
```

#### CombinerAggregator

Trident API 提供的此接口的实现返回一个带有单个字段的单个元组作为输出；在内部，它对每个输入元组执行 init 函数，然后将值组合，直到只剩下一个值，然后将其作为输出返回。如果组合器函数遇到没有任何值的分区，则发射"0"。

以下是接口定义及其合同：

```scala
public interface CombinerAggregator<T> extends Serializable {
    T init(TridentTuple tuple);
    T combine(T val1, T val2);
    T zero();
}
```

以下是计数功能的实现：

```scala
public class myCount implements CombinerAggregator<Long> {
    public Long init(TridentTuple mytuple) {
        return 1L;
    }
public Long combine(Long val1, Long val2) {
        return val1 + val2;
    }

    public Long zero() {
        return 0L;
    }
}
```

这些`CombinerAggregators`函数相对于`partitionAggregate`函数的最大优势在于，它是一种更高效和优化的方法，因为它在通过网络传输结果之前执行部分聚合。

#### ReducerAggregator

正如其名称所示，此函数生成一个`init`值，然后迭代处理输入流中的每个元组，以生成包含单个字段和单个元组的输出。

以下是`ReducerAggregate`接口的接口契约：

```scala
public interface ReducerAggregator<T> extends Serializable {
    T init();
    T reduce(T curr, TridentTuple tuple);
}
```

以下是计数功能的接口实现：

```scala
public class myReducerCount implements ReducerAggregator<Long> {
    public Long init() {
        return 0L;
    }

    public Long reduce(Long curr, TridentTuple tuple) {
        return curr + 1;
    }
}
```

#### Aggregator

`Aggregator`函数是最常用和多功能的聚合器函数。它有能力发出一个或多个元组，每个元组可以有任意数量的字段。它们具有以下接口签名：

```scala
public interface Aggregator<T> extends Operation {
    T init(Object batchId, TridentCollector collector);
    void aggregate(T state, TridentTuple tuple, TridentCollector  collector);
    void complete(T state, TridentCollector collector);
}
```

执行模式如下：

+   `init`方法是每个批次处理之前的前导。它在处理每个批次之前被调用。完成后，它返回一个持有批次状态表示的对象，并将其传递给后续的聚合和完成方法。

+   与`init`方法不同，`aggregate`方法对批次分区中的每个元组调用一次。该方法可以存储状态，并根据功能要求发出结果。

+   complete 方法类似于后处理器；当批次分区被聚合完全处理时执行。

以下是计数作为聚合器函数的实现：

```scala
public class CountAggregate extends BaseAggregator<CountState> {
    static class CountState {
        long count = 0;
    }
    public CountState init(Object batchId, TridentCollector  collector) {
        return new CountState();
    }
    public void aggregate(CountState state, TridentTuple tuple,  TridentCollector collector) {
        state.count+=1;
    }
    public void complete(CountState state, TridentCollector  collector) {
        collector.emit(new Values(state.count));
    }
}
```

许多时候，我们遇到需要同时执行多个聚合器的实现。在这种情况下，链接的概念就派上了用场。由于 Trident API 中的这个功能，我们可以构建一个聚合器的执行链，以便在传入流元组的批次上执行。以下是这种链的一个例子：

```scala
myInputstream.chainedAgg()
        .partitionAggregate(new Count(), new Fields("count"))
        .partitionAggregate(new Fields("b"), new Sum(), new  Fields("sum"))
        .chainEnd()
```

此链的执行将在每个分区上运行指定的`sum`和`count`聚合器函数。输出将是一个单个元组，其中包含`sum`和`count`的值。

## 与流重新分区相关的操作

正如其名称所示，这些流重新分区操作与执行函数来改变任务之间的元组分区有关。这些操作涉及网络流量，结果重新分发流，并可能导致整体分区策略的变化，从而影响多个分区。

以下是 Trident API 提供的重新分区函数：

+   `Shuffle`: 这执行一种重新平衡的功能，并采用随机轮询算法，以实现元组在分区之间的均匀重新分配。

+   `Broadcast`: 这就像其名称所示的那样；它将每个元组广播和传输到每个目标分区。

+   `partitionBy`: 这个函数基于一组指定字段的哈希和模运算工作，以便相同的字段总是移动到相同的分区。类比地，可以假设这个功能的运行方式类似于最初在 Storm 分组中学到的字段分组。

+   `global`: 这与 Storm 中流的全局分组相同，在这种情况下，所有批次都选择相同的分区。

+   `batchGlobal`: 一个批次中的所有元组都被发送到同一个分区（所以它们在某种程度上是粘在一起的），但不同的批次可以被发送到不同的分区。

## 流上的数据聚合

Storm 的 Trident 框架提供了两种执行聚合的操作：

+   `aggregate`: 我们在之前的部分中已经涵盖了这个，它在隔离的分区中工作，而不涉及网络流量

+   `persistentAggregate`: 这在分区间执行聚合，但不同之处在于它将结果存储在状态源中

## 流中字段的分组

分组操作的工作方式类似于关系模型中的分组操作，唯一的区别在于 Storm 框架中的分组操作是在输入源的元组流上执行的。

让我们通过以下图更仔细地了解这一点：

![在流中对字段进行分组](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/rt-anlt-storm-csdr/img/00073.jpeg)

Storm Trident 中的这些操作在几个不同分区的元组流上运行。

## 合并和连接

合并和连接 API 提供了合并和连接各种流的接口。可以使用以下多种方式来实现这一点：

+   `合并`: 正如其名称所示，`merge`将两个或多个流合并在一起，并将合并后的流作为第一个流的输出字段发出：

```scala
myTridentTopology.merge(stream1,stream2,stream3);

```

+   `连接`: 此操作与传统的 SQL `join`函数相同，但不同之处在于它适用于小批量而不是从喷口输出的整个无限流

例如，考虑一个连接函数，其中 Stream 1 具有诸如`["key", "val1", "val2"]`的字段，Stream 2 具有`["x", "val1"]`，并且从这些函数中我们执行以下代码：

```scala
myTridentTopology.join(stream1, new Fields("key"), stream2, new  Fields("x"), new Fields("key", "a", "b", "c"));
```

结果，Stream 1 和 Stream 2 将使用`key`和`x`进行连接，其中`key`将连接 Stream 1 的字段，`x`将连接 Stream 2 的字段。

从连接中发出的输出元组将如下所示：

+   所有连接字段的列表；在我们的情况下，它将是 Stream 1 的`key`和 Stream 2 的`x`。

+   所有参与连接操作的流中不是连接字段的字段列表，顺序与它们传递给`join`操作的顺序相同。在我们的情况下，对于 Stream 1 的`val1`和`val2`，分别是`a`和`b`，对于 Stream 2 的`val1`是`c`（请注意，此步骤还会消除流中存在的任何字段名称的歧义，我们的情况下，`val1`字段在两个流之间是模棱两可的）。

当在拓扑中从不同的喷口中提供的流上发生像连接这样的操作时，框架确保喷口在批量发射方面是同步的，以便每个连接计算可以包括来自每个喷口的批量元组。

# 示例和插图

Trident 的另一个开箱即用且流行的实现是 reach 拓扑，它是一个纯 DRPC 拓扑，可以根据需要找到 URL 的可达性。在我们深入研究之前，让我们先了解一些行话。

Reach 基本上是暴露给 URL 的 Twitter 用户数量的总和。

Reach 计算是一个多步骤的过程，可以通过以下示例实现：

+   获取曾经发推特的 URL 的所有用户

+   获取每个用户的追随者树

+   组装之前获取的大量追随者集

+   计算集合

好吧，看看之前的骨架算法，你会发现它超出了单台机器的能力，我们需要一个分布式计算引擎来实现它。这是 Storm Trident 框架的理想候选，因为您可以在整个集群中的每个步骤上执行高度并行的计算。

+   我们的 Trident reach 拓扑将从两个大型数据银行中吸取数据

+   银行 A 是 URL 到发起者银行，其中将存储所有 URL 以及曾经发推特的用户的名称。

+   银行 B 是用户追随者银行；这个数据银行将为所有 Twitter 用户提供用户追随映射

拓扑将定义如下：

```scala
TridentState urlToTweeterState =  topology.newStaticState(getUrlToTweetersState());
TridentState tweetersToFollowerState =  topology.newStaticState(getTweeterToFollowersState());

topology.newDRPCStream("reach")
       .stateQuery(urlToTweeterState, new Fields("args"), new  MapGet(), new Fields("tweeters"))
       .each(new Fields("tweeters"), new ExpandList(), new  Fields("tweeter"))
       .shuffle()
       .stateQuery(tweetersToFollowerState, new Fields("tweeter"),  new MapGet(), new Fields("followers"))
       .parallelismHint(200)
       .each(new Fields("followers"), new ExpandList(), new  Fields("follower"))
       .groupBy(new Fields("follower"))
       .aggregate(new One(), new Fields("one"))
       .parallelismHint(20)
       .aggregate(new Count(), new Fields("reach"));
```

在前述拓扑中，我们执行以下步骤：

1.  为两个数据银行（URL 到发起者银行 A 和用户到追随银行 B）创建一个`TridentState`对象。

1.  `newStaticState`方法用于实例化数据银行的状态对象；我们有能力在之前创建的源状态上运行 DRPC 查询。

1.  在执行中，当要计算 URL 的可达性时，我们使用数据银行 A 的 Trident 状态执行查询，以获取曾经发推特的所有用户的列表。

1.  `ExpandList`函数为查询 URL 的每个推特者创建并发出一个元组。

1.  接下来，我们获取先前获取的每个推特者的追随者。这一步需要最高程度的并行性，因此我们在这里使用洗牌分组，以便在所有螺栓实例之间均匀分配负载。在我们的 reach 拓扑中，这是最密集的计算步骤。

1.  一旦我们有了 URL 推特者的追随者列表，我们执行类似于筛选唯一追随者的操作。

1.  我们通过将追随者分组在一起，然后使用`one`聚合器来得到唯一的追随者。后者简单地为每个组发出`1`，然后在下一步将所有这些计数在一起以得出影响力。

1.  然后我们计算追随者（唯一），从而得出 URL 的影响力。

# 测验时间

1. 状态是否以下陈述是真是假：

1.  DRPC 是一个无状态的，Storm 处理机制。

1.  如果 Trident 拓扑中的元组执行失败，整个批次将被重放。

1.  Trident 允许用户在流数据上实现窗口函数。

1.  聚合器比分区聚合器更有效。

2. 填空：

1.  _______________ 是 RPC 的分布式版本。

1.  _______________ 是 Storm 的基本微批处理框架。

1.  ___________________ 函数用于根据特定标准或条件从流批次中删除元组。

3. 创建一个 Trident 拓扑，以查找在过去 5 分钟内发表最多推文的推特者。

# 总结

在本章中，我们几乎涵盖了关于 Storm 及其高级概念的一切，并让您有机会亲自体验 Trident 和 DRPC 拓扑。您了解了 Trident 及其需求和应用，DRPC 拓扑以及 Trident API 中提供的各种功能。

在下一章中，我们将探索与 Storm 紧密配合并且对于使用 Storm 构建端到端解决方案必不可少的其他技术组件。我们将涉及分布式缓存和与 Storm 一起使用 memcache 和 Esper 进行**复杂事件处理**（CEP）的领域。
