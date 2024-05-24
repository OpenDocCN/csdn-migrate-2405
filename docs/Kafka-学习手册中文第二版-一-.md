# Kafka 学习手册中文第二版（一）

> 原文：[`zh.annas-archive.org/md5/9368A278A76E09A26C164319C7ADCDCA`](https://zh.annas-archive.org/md5/9368A278A76E09A26C164319C7ADCDCA)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

本书旨在帮助您熟悉 Apache Kafka，并解决与发布者-订阅者架构中数百万条消息消耗相关的挑战。它旨在让您开始使用 Kafka 进行编程，以便您将有一个坚实的基础，深入研究不同类型的 Kafka 生产者和消费者的实现和集成。

除了解释 Apache Kafka 之外，我们还花了一章的时间探索 Kafka 与其他技术（如 Apache Hadoop 和 Apache Storm）的集成。我们的目标不仅是让您了解 Apache Kafka 是什么，还要让您了解如何将其作为更广泛技术基础设施的一部分来使用。最后，我们将带您了解 Kafka 的操作，我们还将谈论管理问题。

# 本书涵盖的内容

第一章，“介绍 Kafka”，讨论了组织如何意识到数据的真正价值，并正在改进收集和处理数据的机制。它还描述了如何使用不同版本的 Scala 安装和构建 Kafka 0.8.x。

第二章，“设置 Kafka 集群”，描述了设置单个或多个经纪人 Kafka 集群所需的步骤，并分享了 Kafka 经纪人属性列表。

第三章，“Kafka 设计”，讨论了用于构建 Kafka 坚实基础的设计概念。它还详细讨论了 Kafka 如何处理消息压缩和复制。

第四章，“编写生产者”，提供了有关如何编写基本生产者和使用消息分区的一些高级 Java 生产者的详细信息。

第五章，“编写消费者”，提供了有关如何编写基本消费者和使用消息分区的一些高级 Java 消费者的详细信息。

第六章，“Kafka 集成”，简要介绍了 Storm 和 Hadoop，并讨论了 Kafka 如何与 Storm 和 Hadoop 集成，以满足实时和批处理需求。

第七章，“操作 Kafka”，描述了集群管理和集群镜像所需的 Kafka 工具的信息，并分享了如何将 Kafka 与 Camus、Apache Camel、Amazon Cloud 等集成的信息。

# 本书所需内容

在最简单的情况下，一个安装了 JDK 1.6 的基于 Linux（CentOS 6.x）的单台机器将为您提供一个平台，以探索本书中几乎所有练习。我们假设您熟悉命令行 Linux，因此任何现代发行版都足够。

一些示例需要多台机器才能看到工作情况，因此您需要至少访问三台这样的主机；虚拟机适用于学习和探索。

由于我们还讨论了大数据技术，如 Hadoop 和 Storm，您通常需要一个地方来运行您的 Hadoop 和 Storm 集群。

# 这本书适合谁

这本书是为那些想要了解 Apache Kafka 的人准备的；主要受众是具有软件开发经验但没有接触过 Apache Kafka 或类似技术的人。

这本书也适合企业应用程序开发人员和大数据爱好者，他们曾经使用其他基于发布者-订阅者系统，并且现在想要探索作为未来可扩展解决方案的 Apache Kafka。

# 约定

在本书中，您将找到许多文本样式，用于区分不同类型的信息。以下是一些这些样式的示例，以及它们的含义解释。

文本中的代码词显示如下：“从 Oracle 的网站下载`jdk-7u67-linux-x64.rpm`版本。”

代码块设置如下：

```java
String messageStr = new String("Hello from Java Producer");
KeyedMessage<Integer, String> data = new KeyedMessage<Integer, String>(topic, messageStr);
producer.send(data);
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```java
Properties props = new Properties();
props.put("metadata.broker.list","localhost:9092");
props.put("serializer.class","kafka.serializer.StringEncoder");
props.put("request.required.acks", "1");
ProducerConfig config = new ProducerConfig(props); 
Producer<Integer, String> producer = new Producer<Integer, 
    String>(config);
```

任何命令行输入或输出都以以下形式书写：

```java
[root@localhost kafka-0.8]# java SimpleProducer kafkatopic Hello_There

```

**新术语**和**重要单词**以粗体显示。

### 注意

警告或重要说明会以这样的方式出现在方框中。

### 提示

提示和技巧会以这种形式出现。


# 第一章：介绍 Kafka

在当今世界，实时信息不断由应用程序（商业、社交或任何其他类型）生成，并且这些信息需要可靠快速地路由到多种类型的接收方。大多数情况下，生成信息的应用程序和消费此信息的应用程序相距甚远，彼此无法访问。这些异构应用程序导致了为它们之间提供集成点的重新开发。因此，需要一种机制来无缝集成来自生产者和消费者的信息，以避免任何一端的应用程序重写。

# 欢迎来到 Apache Kafka 的世界

在当前的大数据时代，第一个挑战是收集数据，因为数据量巨大，第二个挑战是分析数据。这种分析通常包括以下类型的数据以及更多：

+   用户行为数据

+   应用程序性能跟踪

+   以日志形式的活动数据

+   事件消息

消息发布是一种通过消息连接各种应用程序的机制，例如通过消息代理（如 Kafka）。Kafka 是解决任何软件解决方案的实时问题的解决方案；也就是说，处理实时信息量并快速路由到多个消费者。Kafka 提供了生产者和消费者信息之间的无缝集成，而不会阻塞信息的生产者，也不会让生产者知道最终的消费者是谁。

Apache Kafka 是一个开源的、分布式的、分区的、复制的基于提交日志的发布-订阅消息系统，主要具有以下特点：

+   **持久化消息**：为了从大数据中获得真正的价值，不能承受任何信息丢失。Apache Kafka 设计了 O(1)磁盘结构，即使存储的消息量达到 TB 级别，也能提供恒定的性能。使用 Kafka，消息被持久化在磁盘上，并在集群内复制，以防止数据丢失。

+   **高吞吐量**：考虑到大数据，Kafka 被设计为在商品硬件上运行，并且能够处理来自大量客户端的每秒数百 MB 的读写。

+   **分布式**：Apache Kafka 以其集群中心的设计明确支持 Kafka 服务器上的消息分区，并在维护每个分区的顺序语义的同时，在消费者机器集群上分发消费。Kafka 集群可以在没有任何停机时间的情况下弹性地透明地增长。

+   **多客户端支持**：Apache Kafka 系统支持轻松集成来自不同平台的客户端，如 Java、.NET、PHP、Ruby 和 Python。

+   **实时**：生产者线程产生的消息应立即对消费者线程可见；这个特性对于基于事件的系统（如**复杂事件处理**（**CEP**）系统）至关重要。

Kafka 提供了一个实时的发布-订阅解决方案，克服了消费实时和批量数据量的挑战，这些数据量可能增长到比真实数据更大的数量级。Kafka 还支持在 Hadoop 系统中进行并行数据加载。

以下图表显示了 Apache Kafka 消息系统支持的典型大数据聚合和分析场景：

欢迎来到 Apache Kafka 的世界

在生产方面，有不同类型的生产者，例如以下类型：

+   生成应用程序日志的前端 Web 应用程序

+   生成网络分析日志的生产者代理

+   生成转换日志的生产者适配器

+   生成调用跟踪日志的生产者服务

在消费方面，有不同类型的消费者，例如以下类型：

+   消费消息并将其存储在 Hadoop 或传统数据仓库中进行离线分析的离线消费者

+   消费者几乎实时地消费消息并将其存储在任何 NoSQL 数据存储中，例如 HBase 或 Cassandra，以进行几乎实时的分析

+   实时消费者，如 Spark 或 Storm，在内存中过滤消息并触发相关组的警报事件

# 我们为什么需要 Kafka？

任何形式的网络或设备活动都会产生大量数据。数据是这些基于互联网的系统中的新成分之一，通常包括用户活动；与登录对应的事件；页面访问；点击；社交网络活动，如点赞、分享和评论；以及操作和系统指标。由于吞吐量高（每秒数百万条消息），这些数据通常由日志记录和传统的日志聚合解决方案处理。这些传统解决方案是为向离线分析系统（如 Hadoop）提供日志数据而设计的可行解决方案。然而，这些解决方案对于构建实时处理系统来说非常有限。

根据互联网应用的新趋势，活动数据已成为生产数据的一部分，并用于实时运行分析。这些分析可以是：

+   基于相关性的搜索

+   基于流行度、共现或情感分析的推荐

+   向大众投放广告

+   互联网应用程序安全，防止垃圾邮件或未经授权的数据抓取

+   设备传感器发送高温警报

+   任何异常的用户行为或应用程序黑客攻击

由于收集和处理的数据量大，从生产系统中收集的这些多组数据的实时使用已经成为一个挑战。

Apache Kafka 旨在通过提供在 Hadoop 系统中进行并行加载的机制以及在一组机器的集群上对实时消费进行分区的能力，统一离线和在线处理。Kafka 可以与 Scribe 或 Flume 进行比较，因为它对于处理活动流数据非常有用；但从架构的角度来看，它更接近于传统的消息系统，如 ActiveMQ 或 RabitMQ。

# Kafka 的用例

Kafka 可以在任何架构中以多种方式使用。本节讨论了 Apache Kafka 的一些热门用例以及采用 Kafka 的知名公司。以下是热门的 Kafka 用例：

+   日志聚合：这是从服务器收集物理日志文件并将它们放在一个中心位置（文件服务器或 HDFS）进行处理的过程。使用 Kafka 提供了对日志或事件数据的干净抽象，作为一系列消息流，从而消除了对文件细节的任何依赖。这还提供了更低的延迟处理和对多个数据源和分布式数据消费的支持。

+   流处理：Kafka 可用于收集的数据在多个阶段进行处理的用例，一个例子是从主题消耗的原始数据，并对其进行丰富或转换为新的 Kafka 主题以供进一步消费。因此，这种处理也被称为流处理。

+   提交日志：Kafka 可用于表示任何大规模分布式系统的外部提交日志。Kafka 集群上的复制日志帮助失败的节点恢复其状态。

+   点击流跟踪：Kafka 的另一个非常重要的用例是捕获用户点击流数据，例如页面浏览，搜索等，作为实时发布订阅源。这些数据以每种活动类型一个主题的形式发布到中央主题，因为数据量非常大。这些主题可供订阅，由许多消费者用于各种应用，包括实时处理和监控。

+   消息传递：消息代理用于将数据处理与数据生产者解耦。Kafka 可以取代许多流行的消息代理，因为它提供更好的吞吐量、内置分区、复制和容错性。

一些正在使用 Apache Kafka 的公司及其各自的用例如下：

+   LinkedIn（www.linkedin.com）：Apache Kafka 在 LinkedIn 用于活动数据和运营指标的流式传输。这些数据支持 LinkedIn 新闻动态和 LinkedIn 今日等各种产品，以及 Hadoop 等离线分析系统。

+   DataSift（www.datasift.com）：在 DataSift，Kafka 用作事件监视器的收集器，以及实时跟踪用户对数据流的消耗。

+   Twitter（www.twitter.com）：Twitter 将 Kafka 作为其 Storm 流处理基础设施的一部分使用。

+   Foursquare（www.foursquare.com）：Kafka 在 Foursquare 的在线到在线和在线到离线消息传递中发挥作用。它用于将 Foursquare 监控和生产系统与基于 Foursquare 和 Hadoop 的离线基础设施集成。

+   Square（www.squareup.com）：Square 使用 Kafka 作为*总线*，将所有系统事件通过 Square 的各个数据中心传输。这包括指标、日志、自定义事件等。在消费者端，它输出到 Splunk、Graphite 或类似实时警报的 Esper 中。

### 注意

上述信息的来源是 https://cwiki.apache.org/confluence/display/KAFKA/Powered+By。

# 安装 Kafka

Kafka 是一个 Apache 项目，其当前版本 0.8.1.1 可作为稳定版本使用。与旧版本（0.8.x 之前）相比，Kafka 0.8.x 提供了许多高级功能。其一些进步如下：

+   在 0.8.x 之前，如果代理失败，主题中的任何未消耗分区都可能会丢失。现在，分区提供了一个复制因子。这确保了任何已提交的消息不会丢失，因为至少有一个副本可用。

+   先前的功能还确保所有生产者和消费者都具有复制意识（复制因子是可配置属性）。默认情况下，生产者的消息发送请求会被阻塞，直到消息提交到所有活动副本；但是，生产者也可以配置为将消息提交到单个代理。

+   与 Kafka 生产者一样，Kafka 消费者的轮询模型变为长轮询模型，并在从生产者获取可用的已提交消息之前被阻塞，从而避免频繁轮询。

+   此外，Kafka 0.8.x 还配备了一套管理工具，例如受控集群关闭和领导副本选举工具，用于管理 Kafka 集群。

Kafka 0.8.x 的主要限制是它无法替换 0.8 之前的版本，因为它不向后兼容。

回到安装 Kafka，作为第一步，我们需要下载可用的稳定版本（所有过程都在 64 位 CentOS 6.4 操作系统上进行了测试，可能在其他基于内核的操作系统上有所不同）。现在让我们看看安装 Kafka 需要遵循哪些步骤。

## 安装先决条件

Kafka 是用 Scala 实现的，并使用构建工具 Gradle 构建 Kafka 二进制文件。Gradle 是 Scala、Groovy 和 Java 项目的构建自动化工具，需要 Java 1.7 或更高版本。

## 安装 Java 1.7 或更高版本

执行以下步骤安装 Java 1.7 或更高版本：

1.  从 Oracle 的网站下载`jdk-7u67-linux-x64.rpm`版本：http://www.oracle.com/technetwork/java/javase/downloads/index.html。

1.  更改文件模式如下：

```java
[root@localhost opt]#chmod +x jdk-7u67-linux-x64.rpm 

```

1.  切换到要执行安装的目录。为此，请键入以下命令：

```java
[root@localhost opt]# cd <directory path name>

```

例如，要在`/usr/java/`目录中安装软件，请键入以下命令：

```java
[root@localhost opt]# cd /usr/java

```

1.  使用以下命令运行安装程序：

```java
[root@localhost java]# rpm -ivh jdk-7u67-linux-x64.rpm 

```

1.  最后，添加环境变量`JAVA_HOME`。以下命令将`JAVA_HOME`环境变量写入包含系统范围环境配置的文件`/etc/profile`：

```java
[root@localhost opt]# echo "export JAVA_HOME=/usr/java/jdk1.7.0_67 " >> /etc/profile

```

## 下载 Kafka

执行以下步骤下载 Kafka 0.8.1.1 版本：

1.  下载当前的 Kafka（0.8）beta 版本到文件系统上的文件夹中（例如，`/opt`），使用以下命令：

```java
[root@localhost opt]#wget http://apache.tradebit.com/pub/kafka/0.8.1.1/kafka_2.9.2-0.8.1.1.tgz

```

### 注意

上述 URL 可能会更改。请在[`kafka.apache.org/downloads.html`](http://kafka.apache.org/downloads.html)检查正确的下载版本和位置。

1.  使用以下命令解压下载的`kafka_2.9.2-0.8.1.1.tgz`文件：

```java
[root@localhost opt]# tar xzf kafka_2.9.2-0.8.1.1.tgz

```

1.  解压`kafka_2.9.2-0.8.1.1.tgz`文件后，Kafka 0.8.1.1 的目录结构如下所示：![下载 Kafka](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-kafka-2e/img/3090OS_01_02.jpg)

1.  最后，将 Kafka bin 文件夹添加到`PATH`中，如下所示：

```java
[root@localhost opt]# export KAFKA_HOME=/opt/kafka_2.9.2-0.8.1.1
[root@localhost opt]# export PATH=$PATH:$KAFKA_HOME/bin

```

## 构建 Kafka

用于构建 Kafka 0.8.1.1 版本的默认 Scala 版本是 Scala 2.9.2，但 Kafka 源代码也可以从其他 Scala 版本编译，比如 2.8.0、2.8.2、2.9.1 或 2.10.1。使用以下命令构建 Kafka 源代码：

```java
[root@localhost opt]# ./gradlew -PscalaVersion=2.9.1 jar

```

在 Kafka 8.x 及以后的版本中，Gradle 工具用于编译 Kafka 源代码（包含在`kafka-0.8.1.1-src.tgz`中）并构建 Kafka 二进制文件（JAR 文件）。类似于 Kafka JAR，单元测试或源代码 JAR 也可以使用 Gradle 构建工具构建。有关构建相关说明的更多信息，请参阅[`github.com/apache/kafka/blob/0.8.1/README.md`](https://github.com/apache/kafka/blob/0.8.1/README.md)。

# 摘要

在本章中，我们已经看到公司如何演变收集和处理应用生成的数据的机制，并学会了通过对其进行分析来利用这些数据的真正力量。

您还学会了如何安装 0.8.1.x。以下章节讨论了设置单个或多个 broker Kafka 集群所需的步骤。


# 第二章：设置 Kafka 集群

现在我们准备使用 Apache Kafka 发布者-订阅者消息系统。使用 Kafka，我们可以创建多种类型的集群，例如以下：

+   单节点-单 broker 集群

+   单节点-多 broker 集群

+   多节点-多 broker 集群

Kafka 集群主要有五个主要组件：

+   **主题**：主题是消息生产者发布消息的类别或源名称。在 Kafka 中，主题被分区，每个分区由有序的不可变消息序列表示。Kafka 集群为每个主题维护分区日志。分区中的每条消息都被分配一个称为*偏移量*的唯一顺序 ID。

+   **Broker**：Kafka 集群由一个或多个服务器组成，每个服务器可能运行一个或多个服务器进程，并称为 broker。主题是在 broker 进程的上下文中创建的。

+   **Zookeeper**：ZooKeeper 充当 Kafka broker 和消费者之间的协调接口。Hadoop Wiki 网站上给出的 ZooKeeper 概述如下（[`wiki.apache.org/hadoop/ZooKeeper/ProjectDescription`](http://wiki.apache.org/hadoop/ZooKeeper/ProjectDescription)）：

> *"ZooKeeper 允许分布式进程通过共享的分层数据寄存器（我们称这些寄存器为 znodes）协调彼此，就像文件系统一样。"*

ZooKeeper 和标准文件系统之间的主要区别在于每个 znode 都可以与其关联数据，并且 znode 的数据量是有限的。ZooKeeper 旨在存储协调数据：状态信息、配置、位置信息等。

+   **生产者**：生产者通过选择主题内的适当分区向主题发布数据。为了负载平衡，可以以循环方式或使用自定义定义的函数将消息分配给主题分区。

+   **消费者**：消费者是订阅主题并处理发布消息的应用程序或进程。

让我们从一个非常基本的集群设置开始。

# 单节点-单 broker 集群

这是学习 Kafka 的起点。在上一章中，我们在单台机器上安装了 Kafka。现在是时候设置一个基于单节点-单 broker 的 Kafka 集群，如下图所示：

![单节点-单 broker 集群](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-kafka-2e/img/3090OS_02_01.jpg)

## 启动 ZooKeeper 服务器

Kafka 提供了默认和简单的 ZooKeeper 配置文件，用于启动单个本地 ZooKeeper 实例，尽管在设置 Kafka 集群时也可以进行单独的 ZooKeeper 安装。首先使用以下命令启动本地 ZooKeeper 实例：

```java
[root@localhost kafka_2.9.2-0.8.1.1]# bin/zookeeper-server-start.sh  config/zookeeper.properties

```

您应该得到如下屏幕截图中显示的输出：

![启动 ZooKeeper 服务器](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-kafka-2e/img/3090OS_02_02.jpg)

### 注意

Kafka 带有定义单个 broker-单节点集群所需的最小属性的必需属性文件。

`zookeeper.properties`中定义的重要属性如下所示：

```java
# Data directory where the zookeeper snapshot is stored.
dataDir=/tmp/zookeeper

# The port listening for client request
clientPort=2181
# disable the per-ip limit on the number of connections since this is a non-production config
maxClientCnxns=0
```

默认情况下，ZooKeeper 服务器将侦听`*:2181/tcp`。有关如何设置多个 ZooKeeper 服务器的详细信息，请访问[`zookeeper.apache.org/`](http://zookeeper.apache.org/)。

## 启动 Kafka broker

现在使用以下命令在新的控制台窗口中启动 Kafka broker：

```java
[root@localhost kafka_2.9.2-0.8.1.1]# bin/kafka-server-start.sh config/server.properties

```

现在您应该看到如下屏幕截图中显示的输出：

![启动 Kafka broker](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-kafka-2e/img/3090OS_02_03.jpg)

`server.properties`文件定义了 Kafka broker 所需的以下重要属性：

```java
# The id of the broker. This must be set to a unique integer for each broker.
Broker.id=0

# The port the socket server listens on
port=9092

# The directory under which to store log files
log.dir=/tmp/kafka8-logs

# The default number of log partitions per topic. 
num.partitions=2

# Zookeeper connection string 
zookeeper.connect=localhost:2181
```

本章的最后一部分定义了 Kafka broker 可用的一些其他重要属性。

## 创建 Kafka 主题

Kafka 提供了一个命令行实用程序，在 Kafka 服务器上创建主题。让我们使用此实用程序创建一个名为`kafkatopic`的主题，该主题只有一个分区和一个副本：

```java
[root@localhost kafka_2.9.2-0.8.1.1]#bin/kafka-topics.sh --create --zookeeper localhost:2181 --replication-factor 1 --partitions 1 --topic kafkatopic

Created topic "kafkatopic".

```

您应该会在 Kafka 服务器窗口上得到如下截图所示的输出：

![创建 Kafka 主题](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-kafka-2e/img/3090OS_02_04.jpg)

`kafka-topics.sh`实用程序将创建一个主题，将默认的分区数从两个覆盖为一个，并显示成功创建消息。它还需要 ZooKeeper 服务器信息，如在本例中：`localhost:2181`。要在任何 Kafka 服务器上获取主题列表，请在新的控制台窗口中使用以下命令：

```java
[root@localhost kafka_2.9.2-0.8.1.1]# bin/kafka-topics.sh --list --zookeeper localhost:2181
kafkatopic

```

## 启动生产者以发送消息

Kafka 为用户提供了一个命令行生产者客户端，可以从命令行接受输入，并将其作为消息发布到 Kafka 集群。默认情况下，每输入一行被视为一个新消息。以下命令用于在新的控制台窗口中启动基于控制台的生产者以发送消息：

```java
[root@localhost kafka_2.9.2-0.8.1.1]# bin/kafka-console-producer.sh --broker-list localhost:9092 --topic kafkatopic

```

输出将如下截图所示：

![启动生产者以发送消息](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-kafka-2e/img/3090OS_02_05.jpg)

在启动生产者的命令行客户端时，需要以下参数：

+   `broker-list`

+   `topic`

`broker-list`参数指定要连接的代理为`<node_address:port>`—即`localhost:9092`。`kafkatopic`主题是在*创建 Kafka 主题*部分创建的。要将消息发送到订阅了相同主题`kafkatopic`的一组特定消费者，需要主题名称。

现在在控制台窗口上键入以下消息：

+   键入`欢迎来到 Kafka`并按*Enter*

+   键入`这是单个代理集群`并按*Enter*

您应该会看到如下截图所示的输出：

![启动生产者以发送消息](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-kafka-2e/img/3090OS_02_06.jpg)

尝试一些更多的消息。消费者的默认属性在`producer.properties`中定义。重要的属性是：

```java
# list of brokers used for bootstrapping knowledge about the rest of the cluster
# format: host1:port1,host2:port2 ...
metadata.broker.list=localhost:9092

# specify the compression codec for all data generated: none , gzip, snappy.
compression.codec=none
```

有关如何为 Kafka 编写生产者和生产者属性的详细信息将在第四章中讨论，*编写生产者*。

## 启动消费者以消费消息

Kafka 还为消息消费提供了一个命令行消费者客户端。以下命令用于启动基于控制台的消费者，一旦订阅了 Kafka 代理中创建的主题，就会在命令行上显示输出：

```java
[root@localhost kafka_2.9.2-0.8.1.1]# bin/kafka-console-consumer.sh --zookeeper localhost:2181 --topic kafkatopic --from-beginning

```

在执行上一个命令时，您应该会得到如下截图所示的输出：

![启动消费者以消费消息](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-kafka-2e/img/3090OS_02_07.jpg)

消费者的默认属性在`/config/consumer.properties`中定义。重要的属性是：

```java
# consumer group id (A string that uniquely identifies a set of consumers # within the same consumer group)
group.id=test-consumer-group
```

有关如何为 Kafka 编写消费者和消费者属性的详细信息将在第五章中讨论，*编写消费者*。

通过在不同的终端中运行所有四个组件（`zookeeper`，`broker`，`producer`和`consumer`），您将能够从生产者的终端输入消息，并在订阅的消费者的终端中看到它们出现。

可以通过不带参数运行命令来查看生产者和消费者命令行工具的使用信息。

# 单节点 - 多代理集群

现在我们已经来到 Kafka 集群的下一个级别。让我们现在设置一个单节点 - 多代理的 Kafka 集群，如下图所示：

![单节点 - 多代理集群](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-kafka-2e/img/3090OS_02_08.jpg)

## 启动 ZooKeeper

在启动 ZooKeeper 的第一步对于这种类型的集群是相同的。

## 启动 Kafka 代理

要在单个节点上设置多个代理，需要为每个代理准备不同的服务器属性文件。每个属性文件将为以下属性定义唯一的不同值：

+   `broker.id`

+   `port`

+   `log.dir`

例如，在用于`broker1`的`server-1.properties`中，我们定义如下：

+   `broker.id=1`

+   `port=9093`

+   `log.dir=/tmp/kafka-logs-1`

同样，对于`broker2`使用的`server-2.properties`，我们定义如下：

+   `broker.id=2`

+   `port=9094`

+   `log.dir=/tmp/kafka-logs-2`

所有新代理都遵循类似的过程。在定义属性时，我们已更改端口号，因为所有附加代理仍将在同一台机器上运行，但在生产环境中，代理将在多台机器上运行。现在，我们使用以下命令在单独的控制台窗口中启动每个新代理：

```java
[root@localhost kafka_2.9.2-0.8.1.1]# bin/kafka-server-start.sh config/server-1.properties
[root@localhost kafka_2.9.2-0.8.1.1]# bin/kafka-server-start.sh config/server-2.properties
…

```

## 使用命令行创建 Kafka 主题

使用 Kafka 服务器上的命令行实用程序创建主题，让我们创建一个名为`replicated-kafkatopic`的主题，其中包含两个分区和两个副本：

```java
[root@localhost kafka_2.9.2-0.8.1.1]# bin/kafka-topics.sh --create --zookeeper localhost:2181 --replication-factor 3 --partitions 1 --topic replicated-kafkatopic
Created topic "replicated-kafkatopic".

```

## 启动生产者发送消息

如果我们使用单个生产者连接到所有代理，我们需要传递代理的初始列表，并且剩余代理的信息是通过查询传递给`broker-list`的代理来识别的，如下命令所示。此元数据信息基于主题名称：

```java
--broker-list localhost:9092, localhost:9093

```

使用以下命令启动生产者：

```java
[root@localhost kafka_2.9.2-0.8.1.1]# bin/kafka-console-producer.sh --broker-list localhost:9092, localhost:9093 --topic replicated-kafkatopic

```

如果我们有多个生产者连接到不同组合的代理的要求，我们需要为每个生产者指定代理列表，就像在多个代理的情况下所做的那样。

## 启动消费者以消费消息

与上一个示例中一样的消费者客户端将在此过程中使用。就像以前一样，它在订阅 Kafka 代理中创建的主题后立即在命令行上显示输出：

```java
[root@localhost kafka_2.9.2-0.8.1.1]# bin/kafka-console-consumer.sh --zookeeper localhost:2181 --from-beginning --topic replicated-kafkatopic

```

# 多个节点-多个代理集群

这本书没有详细讨论此集群方案，但是，就像在单节点-多代理 Kafka 集群的情况下，在每个节点上设置多个代理一样，我们应该在集群的每个节点上安装 Kafka，并且来自不同节点的所有代理都需要连接到相同的 ZooKeeper。

出于测试目的，所有命令将保持与我们在单节点-多代理集群中使用的命令相同。

下图显示了在多个节点（在本例中为节点 1 和节点 2）上配置多个代理的集群方案，生产者和消费者以不同的组合连接：

![多节点-多代理集群](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-kafka-2e/img/3090OS_02_09.jpg)

# Kafka 经纪人属性列表

以下是可以为 Kafka 代理配置的一些重要属性列表。有关完整列表，请访问[`kafka.apache.org/documentation.html#brokerconfig`](http://kafka.apache.org/documentation.html#brokerconfig)。

| 属性名称 | 描述 | 默认值 |
| --- | --- | --- |
| `broker.id` | 每个代理都由非负整数 ID 唯一标识。此 ID 用作代理的名称，并允许将代理移动到不同的主机/端口而不会使消费者困惑。 | `0` |
| `log.dirs` | 这些是存储日志数据的目录。创建的每个新分区将放置在当前具有最少分区的目录中。 | `/tmp/kafka-logs` |
| `zookeeper.connect` | 这指定了 ZooKeeper 的连接字符串，格式为`hostname:port/chroot`。在这里，`chroot`是一个基本目录，它被预先添加到所有路径操作（这有效地为所有 Kafka znode 命名空间，以允许与 ZooKeeper 集群上的其他应用程序共享）。 | `localhost:2181` |
| `host.name` | 这是代理的主机名。如果设置了这个，它将只绑定到这个地址。如果没有设置，它将绑定到所有接口，并发布到 ZooKeeper。 | `Null` |
| `num.partitions` | 如果在创建主题时没有给出分区计数，则这是每个主题的默认分区数。 | `1` |
| `auto.create.topics.enable` | 这启用了服务器上主题的自动创建。如果设置为 true，则尝试生成、消费或获取不存在的主题的元数据将自动使用默认的复制因子和分区数创建它。 | `True` |
| `default.replication.factor` | 这是自动创建主题的默认复制因子。 | `1` |

# 摘要

在本章中，您学习了如何在单个节点上设置具有单个/多个代理的 Kafka 集群，运行命令行生产者和消费者，并交换一些消息。我们还讨论了 Kafka 代理的重要设置。

在下一章中，我们将看一下 Kafka 的内部设计。


# 第三章：Kafka 设计

在我们开始编写 Kafka 生产者和消费者的代码之前，让我们快速讨论一下 Kafka 的内部设计。

在本章中，我们将重点关注以下主题：

+   Kafka 设计基础

+   Kafka 中的消息压缩

+   Kafka 中的复制

由于与 JMS 及其各种实现相关的开销以及缩放架构的限制，LinkedIn（[www.linkedin.com](http://www.linkedin.com)）决定构建 Kafka 来满足其对监控活动流数据和操作指标（如 CPU、I/O 使用情况和请求时间）的需求。

在开发 Kafka 时，主要关注以下内容：

+   为生产者和消费者提供支持自定义实现的 API

+   网络和存储的低开销，消息在磁盘上持久化

+   支持发布和订阅数百万条消息的高吞吐量，例如实时日志聚合或数据源

+   分布式和高度可扩展的架构，以处理低延迟传递

+   在故障情况下自动平衡多个消费者

+   在服务器故障的情况下保证容错

# Kafka 设计基础

Kafka 既不是一个消息队列平台，消息在其中由消费者池中的单个消费者接收，也不是一个发布-订阅平台，消息在其中发布给所有消费者。在一个非常基本的结构中，生产者将消息发布到 Kafka 主题（与“消息队列”同义）。主题也被视为消息类别或订阅名称，消息被发布到其中。Kafka 主题在充当 Kafka 服务器的 Kafka 代理上创建。Kafka 代理还在需要时存储消息。然后消费者订阅 Kafka 主题（一个或多个）以获取消息。在这里，代理和消费者使用 Zookeeper 获取状态信息和分别跟踪消息偏移量。这在下图中描述：

![Kafka 设计基础](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-kafka-2e/img/3090OS_03_01.jpg)

在上图中，显示了单节点-单代理架构，其中一个主题有四个分区。在组件方面，上图显示了 Kafka 集群的所有五个组件：Zookeeper、代理、主题、生产者和消费者。

在 Kafka 主题中，每个分区都映射到一个逻辑日志文件，表示为相等大小的一组段文件。每个分区都是有序的、不可变的消息序列；每次将消息发布到分区时，代理将消息附加到最后一个段文件。这些段文件在发布可配置数量的消息后或经过一定时间后被刷新到磁盘。刷新段文件后，消息就可以供消费者消费了。

所有消息分区都被分配一个称为*偏移量*的唯一顺序号，用于标识分区内的每条消息。每个分区可以选择在可配置数量的服务器上进行复制，以实现容错。

每个服务器上的每个分区都充当*领导者*，并且有零个或多个服务器充当*跟随者*。在这里，领导者负责处理分区的所有读写请求，而跟随者异步地从领导者复制数据。Kafka 动态地维护一组**同步副本**（**ISR**），这些副本已经追赶上了领导者，并且始终将最新的 ISR 集合持久化到 ZooKeeper。如果领导者失败，其中一个跟随者（同步副本）将自动成为新的领导者。在 Kafka 集群中，每个服务器都扮演双重角色；它既是一些分区的领导者，也是其他分区的跟随者。这确保了 Kafka 集群内的负载平衡。

Kafka 平台是基于从传统平台学到的东西构建的，并且具有消费者组的概念。在这里，每个消费者都表示为一个进程，并且这些进程组织在称为**消费者组**的组中。

主题中的消息由消费者组内的单个进程（消费者）消费，如果要求是单个消息由多个消费者消费，则所有这些消费者都需要保持在不同的消费者组中。消费者始终按顺序从特定分区消费消息，并确认消息偏移量。这种确认意味着消费者已经消费了所有先前的消息。消费者向代理发出包含要消费的消息偏移量的异步拉取请求，并获取字节缓冲区。

与 Kafka 的设计一致，代理是无状态的，这意味着任何消费的消息的状态都在消息消费者内部维护，Kafka 代理不会记录谁消费了什么。如果实现不好，消费者最终会多次读取相同的消息。如果消息从代理中被删除（因为代理不知道消息是否被消费），Kafka 定义了基于时间的 SLA（服务级别协议）作为消息保留策略。根据这个策略，如果消息在代理中保留的时间超过了定义的 SLA 期限，消息将被自动删除。这个消息保留策略使消费者能够有意地倒带到旧的偏移量并重新消费数据，尽管与传统的消息系统一样，这违反了与消费者的排队合同。

让我们讨论 Kafka 在生产者和消费者之间提供的消息传递语义。有多种可能的消息传递方式，例如：

+   消息永远不会被重新传递，但可能会丢失

+   消息可能会被重新传递，但永远不会丢失

+   消息只会被传递一次

在发布时，消息被提交到日志中。如果生产者在发布时遇到网络错误，它永远无法确定此错误是在消息提交之前还是之后发生的。一旦提交，只要复制写入该消息的分区的任何代理仍然可用，消息就不会丢失。对于保证消息发布，生产者端提供了配置，如获取确认和等待消息提交的时间。

从消费者的角度来看，副本具有完全相同的日志和相同的偏移量，消费者控制其在此日志中的位置。对于消费者，Kafka 保证消息将至少被读取一次，通过读取消息、处理消息，最后保存它们的位置。如果消费者进程在处理消息后崩溃，但在保存它们的位置之前崩溃，另一个消费者进程将接管主题分区，并可能接收已经处理的前几条消息。

# 日志压缩

日志压缩是一种实现更精细的、基于每条消息的保留，而不是粗粒度的、基于时间的保留的机制。它确保了主题分区日志中每条消息键的最后已知值必须保留，方法是删除具有相同主键的更近更新的记录。日志压缩还解决了系统故障情况或系统重新启动等问题。

在 Kafka 集群中，保留策略可以根据每个主题进行设置，例如基于时间、基于大小或基于日志压缩。日志压缩确保以下内容：

+   消息的顺序始终保持不变

+   消息将具有顺序偏移量，偏移量永远不会改变

+   从偏移量 0 开始读取，或者从日志开头开始的消费者，将至少看到按写入顺序的所有记录的最终状态

日志压缩由一组后台线程处理，它们重新复制日志段文件，删除出现在日志头部的键的记录。

以下要点总结了重要的 Kafka 设计事实：

+   Kafka 的基本支柱是消息缓存和存储在文件系统中。在 Kafka 中，数据立即写入操作系统内核页面。数据缓存和刷新到磁盘是可配置的。

+   Kafka 提供了更长时间的消息保留，即使在消费后，也允许消费者重新消费。

+   Kafka 使用消息集来组合消息，以减少网络开销。

+   与大多数消息系统不同，在 Kafka 中，消费消息的状态是在消费者级别维护的，而不是在服务器级别维护的。这也解决了诸如：

+   由于故障而丢失消息

+   同一消息的多次传递

默认情况下，消费者将状态存储在 Zookeeper 中，但 Kafka 也允许将其存储在用于在线事务处理（OLTP）应用程序的其他存储系统中。

+   在 Kafka 中，生产者和消费者采用传统的推送和拉取模型工作，其中生产者将消息推送到 Kafka 代理，消费者从代理拉取消息。

+   Kafka 没有任何主节点的概念，并将所有代理视为对等体。这种方法使得可以在任何时候添加和删除 Kafka 代理，因为代理的元数据在 Zookeeper 中进行维护并与消费者共享。

+   生产者还可以选择异步或同步模式将消息发送到代理。

# Kafka 中的消息压缩

对于网络带宽成为瓶颈的情况，Kafka 提供了消息组压缩功能，以实现高效的消息传递。Kafka 通过允许递归消息集来支持高效的压缩，其中压缩消息可能相对于其中的消息具有无限深度。高效的压缩需要将多个消息一起压缩并发送到代理。压缩消息集的网络开销减少，解压缩也吸引了非常少的额外开销。

在 Kafka 的早期版本 0.7 中，消息的压缩批次在日志文件中保持压缩状态，并且作为单个消息呈现给稍后对其进行解压缩的消费者。因此，解压缩的额外开销仅存在于消费者端。

在 Kafka 0.8 中，对代理处理消息偏移量的方式进行了更改；这也可能导致在压缩消息的情况下降低代理性能。

### 注意

在 Kafka 0.7 中，消息是通过分区日志中的物理字节偏移量进行寻址的，而在 Kafka 0.8 中，每条消息都是通过一个不可比较的、逻辑偏移量进行寻址的，这个偏移量对每个分区是唯一的——也就是说，第一条消息的偏移量为`1`，第十条消息的偏移量为`10`，依此类推。在 Kafka 0.8 中，对偏移量管理的更改简化了消费者重置消息偏移量的能力。

在 Kafka 0.8 中，领导代理负责通过为每条消息分配唯一的逻辑偏移量来为分区提供消息，然后将其附加到日志中。在压缩数据的情况下，领导代理必须解压消息集以便为压缩消息集中的消息分配偏移量。一旦偏移量被分配，领导者再次压缩数据，然后将其附加到磁盘上。领导代理对其接收到的每个压缩消息集都遵循此过程，这会导致 Kafka 代理的 CPU 负载。

在 Kafka 中，数据由消息生产者使用 GZIP 或 Snappy 压缩协议进行压缩。需要提供以下生产者配置以在生产者端使用压缩。

| 属性名称 | 描述 | 默认值 |
| --- | --- | --- |
| `compression.codec` | 此参数指定此生产者生成的所有数据的压缩编解码器。有效值为`none`、`gzip`和`snappy`。 | `none` |
| `compressed.topics` | 此参数允许您设置是否应为特定主题打开压缩。如果压缩编解码器不是`none`，则仅为指定的主题启用压缩。如果压缩主题列表为空，则为所有主题启用指定的压缩编解码器。如果压缩编解码器是`none`，则为所有主题禁用压缩。 | `null` |

代表消息集的`ByteBufferMessageSet`类可能包含未压缩和压缩数据。为了区分压缩和未压缩的消息，在消息头中引入了一个压缩属性字节。在这个压缩字节中，最低的两位用于表示用于压缩的压缩编解码器，这两位的值为 0 表示未压缩的消息。

使用 Kafka 在数据中心之间镜像数据时，消息压缩技术非常有用，其中大量数据以压缩格式从活动数据中心传输到被动数据中心。

# Kafka 中的复制

在我们讨论 Kafka 中的复制之前，让我们先谈谈消息分区。在 Kafka 中，消息分区策略是在 Kafka 代理端使用的。关于消息如何分区的决定由生产者做出，代理存储消息的顺序与它们到达的顺序相同。可以为 Kafka 代理中的每个主题配置分区数。

Kafka 复制是 Kafka 0.8 中引入的非常重要的功能之一。尽管 Kafka 具有高度可扩展性，但为了更好地保证消息的耐久性和 Kafka 集群的高可用性，复制保证了即使在经纪人故障的情况下（可能由任何原因引起），消息也将被发布和消费。Kafka 中的生产者和消费者都具有复制意识。以下图解释了 Kafka 中的复制：

![Kafka 中的复制](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-kafka-2e/img/3090OS_03_02.jpg)

让我们详细讨论前面的图表。

在复制中，消息的每个分区都有*n*个副本，并且可以承受*n-1*个故障以保证消息传递。在*n*个副本中，一个副本充当其余副本的领导副本。Zookeeper 保存有关领导副本和当前跟随者**同步副本**（**ISR**）的信息。领导副本维护所有同步跟随者副本的列表。

每个副本将其消息的一部分存储在本地日志和偏移量中，并定期同步到磁盘。这个过程还确保消息要么被写入所有副本，要么一个也没有被写入。

Kafka 支持以下复制模式：

+   **同步复制**：在同步复制中，生产者首先从 ZooKeeper 中识别领导副本并发布消息。一旦消息发布，它就会被写入领导副本的日志，并且所有领导的跟随者开始拉取消息；通过使用单个通道，确保消息的顺序。每个跟随者副本在将消息写入其各自的日志后向领导副本发送确认。一旦复制完成并收到所有预期的确认，领导副本会向生产者发送确认。在消费者方面，所有消息的拉取都是从领导副本进行的。

+   **异步复制**：这种模式的唯一区别是，一旦领导副本将消息写入其本地日志，它会向消息客户端发送确认，而不会等待来自跟随者副本的确认。但是，作为缺点，这种模式在经纪人故障的情况下不能确保消息传递。

如果任何追随者的同步副本失败，领导者将在配置的超时期后从其 ISR 列表中删除失败的追随者，并且写操作将继续在剩余的 ISR 中进行。每当失败的追随者回来时，它首先将其日志截断到最后一个检查点（最后提交消息的偏移量），然后开始从领导者那里赶上所有消息，从检查点开始。一旦追随者与领导者完全同步，领导者将其重新添加到当前的 ISR 列表中。

如果领导复制品在将消息分区写入其本地日志之前或在向消息生产者发送确认之前失败，消息分区将由生产者重新发送到新的领导代理。

选择新的领导复制品的过程涉及所有追随者的 ISR 向 Zookeeper 注册自己。第一个注册的复制品成为新的领导复制品，其**日志结束偏移量**（**LEO**）成为最后提交消息的偏移量（也称为**高水位标记**（**HW**））。其余注册的复制品成为新选举领导者的追随者。每个复制品在 Zookeeper 中注册一个监听器，以便在发生任何领导者更改时得到通知。每当选举出新的领导者并且被通知的复制品不是领导者时，它会将其日志截断到最后提交消息的偏移量，然后开始从新的领导者那里赶上。新选举的领导者等待直到经过配置的时间或直到所有活动的复制品同步，然后领导者将当前的 ISR 写入 Zookeeper，并对消息的读写都开放。

Kafka 中的复制确保更强的耐用性和更高的可用性。它保证任何成功发布的消息都不会丢失，并且即使在经纪人故障的情况下也会被消费。

### 注意

有关 Kafka 复制实现的更多见解，请访问[`cwiki.apache.org/confluence/display/KAFKA/kafka+Detailed+Replication+Design+V3`](https://cwiki.apache.org/confluence/display/KAFKA/kafka+Detailed+Replication+Design+V3)。

# 摘要

在本章中，您了解了构建 Kafka 坚实基础所使用的设计概念。您还了解了 Kafka 中消息压缩和复制的实现方式。

在下一章中，我们将重点介绍如何使用提供的 API 编写 Kafka 生产者。


# 第四章：编写生产者

生产者是创建消息并将其发布到 Kafka 代理以供进一步消费的应用程序。这些生产者可以是不同的性质；例如，前端应用程序、后端服务、代理应用程序、适配器到传统系统以及用于 Hadoop 的生产者。这些生产者也可以用不同的语言实现，比如 Java、C 和 Python。

在本章中，我们将重点关注以下主题：

+   消息生产者的 Kafka API

+   基于 Java 的 Kafka 生产者

+   使用自定义消息分区的基于 Java 的生产者

在本章的最后，我们还将探讨 Kafka 生产者所需的一些重要配置。

让我们开始。以下图解释了 Kafka 生产者在生成消息时的高级工作原理：

![编写生产者](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-kafka-2e/img/3090OS_04_01.jpg)

生产者连接到任何存活的节点，并请求有关主题分区的领导者的元数据。这允许生产者直接将消息放到分区的领导代理中。

Kafka 生产者 API 通过允许生产者指定一个键进行语义分区来公开接口，并使用此键进行哈希分区。因此，生产者可以完全控制将消息发布到哪个分区；例如，如果选择客户 ID 作为键，则给定客户的所有数据将被发送到同一个分区。这也允许数据消费者对客户数据进行局部性假设。

为了在 Kafka 中实现高效，生产者还可以以批处理方式发布消息，只能在异步模式下工作。在异步模式下，生产者可以使用生产者配置中定义的固定消息数量或固定延迟（例如 10 秒或 50 条消息）工作。数据在生产者端在内存中累积，并以批处理方式在单个请求中发布。异步模式还会带来风险，即在生产者崩溃时会丢失未发布的内存中的数据。

### 注意

对于异步生产者，提议将回调方法功能用于将来的发布；这将用于注册处理程序以捕获发送的错误。

在接下来的几节中，我们将讨论 Kafka 为编写基于 Java 的自定义生产者提供的 API。

# Java 生产者 API

让我们首先了解导入的重要类，以便为 Kafka 集群编写基本的基于 Java 的生产者：

+   `Producer`：Kafka 提供了`kafka.javaapi.producer.Producer`类（`class Producer<K, V>`）用于为单个或多个主题创建消息，消息分区是一个可选功能。默认的消息分区器是基于键的哈希值。在这里，`Producer`是一种在 Scala 中编写的 Java 泛型（[`en.wikipedia.org/wiki/Generics_in_Java`](http://en.wikipedia.org/wiki/Generics_in_Java)），我们需要指定参数的类型；`K`和`V`分别指定分区键和消息值的类型。以下是类图及其解释：![Java 生产者 API](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-kafka-2e/img/3090OS_04_02.jpg)

+   `KeyedMessage`：`kafka.producer.KeyedMessage`类接受需要从生产者传递的主题名称、分区键和消息值。

```java
class KeyedMessageK, V 
```

在这里，`KeyedMessage`是一种在 Scala 中编写的 Java 泛型，我们需要指定参数的类型；`K`和`V`分别指定分区键和消息值的类型，而主题始终是`String`类型。

+   `ProducerConfig`：`kafka.producer.ProducerConfig`类封装了与代理建立连接所需的值，例如代理列表、消息分区类、消息的序列化器类和分区键。

生产者 API 包装了同步（默认行为）和异步生产者的低级生产者实现，这些实现是基于生产者配置`producer.type`选择的。例如，在异步生产者的情况下，`kafka.producer.Producer`类处理生产者数据的缓冲，然后将数据序列化并分派到适当的 Kafka 经纪人分区。在内部，`kafka.producer.async.ProducerSendThread`实例出列消息批次，`kafka.producer.EventHandler`序列化并分派数据。Kafka 生产者配置`event.handler`还提供了定义自定义事件处理程序的能力。

### 注意

所有示例都是为多经纪人集群（单个或多个节点）开发和测试的。有关如何设置单节点 - 多经纪人集群的更多信息，请参阅第二章，“设置 Kafka 集群”。

# 简单的 Java 生产者

现在我们将开始编写一个简单的基于 Java 的生产者，将消息传输到经纪人。这个`SimpleProducer`类用于为特定主题创建消息，并使用默认的消息分区传输它。

## 导入类

作为第一步，我们需要导入以下类：

```java
import kafka.javaapi.producer.Producer;
import kafka.producer.KeyedMessage;
import kafka.producer.ProducerConfig;
```

## 定义属性

在编写生产者的下一步中，我们需要定义用于与 Kafka 经纪人建立连接的属性，并将这些属性传递给 Kafka 生产者：

```java
Properties props = new Properties();
props.put("metadata.broker.list","localhost:9092, localhost:9093, localhost:9094");
props.put("serializer.class","kafka.serializer.StringEncoder");
props.put("request.required.acks", "1");
ProducerConfig config = new ProducerConfig(props); 
Producer<String, String> producer = new Producer<String, String> (config);
```

现在让我们看看代码中提到的主要属性：

+   `metadata.broker.list`：此属性指定生产者需要连接的经纪人列表（以`[<node:port>, <node:port>]`格式）。Kafka 生产者会自动确定主题的主要经纪人，通过提出元数据请求对其进行分区，并在发布任何消息之前连接到正确的经纪人。

+   `serializer.class`：此属性指定在从生产者到经纪人传输消息时需要使用的`serializer`类。在本例中，我们将使用 Kafka 提供的字符串编码器。默认情况下，密钥和消息的`serializer`类相同，但我们也可以通过扩展基于 Scala 的`kafka.serializer.Encoder`实现来实现自定义`serializer`类。生产者配置`key.serializer.class`用于设置自定义编码器。

+   `request.required.acks`：此属性指示 Kafka 经纪人在接收到消息时向生产者发送确认。值`1`表示一旦主副本接收到数据，生产者就会收到确认。此选项提供更好的耐久性，因为生产者会等到经纪人确认请求成功。默认情况下，生产者以“发送并忘记”的模式工作，在消息丢失的情况下不会收到通知。

## 构建消息并发送

作为最后一步，我们需要构建消息并将其发送到经纪人，如下所示的代码：

```java
String runtime = new Date().toString();;
String msg = "Message Publishing Time - " + runtime;
KeyedMessage<String, String> data = new KeyedMessage<String, String> (topic, msg);
producer.send(data); 
```

完整的程序如下所示：

```java
package kafka.examples.ch4;

import java.util.Date;
import java.util.Properties;

import kafka.javaapi.producer.Producer;
import kafka.producer.KeyedMessage;
import kafka.producer.ProducerConfig;

public class SimpleProducer {
  private static Producer<String, String> producer;

  public SimpleProducer() {
    Properties props = new Properties();

    // Set the broker list for requesting metadata to find the lead broker
    props.put("metadata.broker.list",
            "192.168.146.132:9092, 192.168.146.132:9093, 192.168.146.132:9094");

    //This specifies the serializer class for keys 
    props.put("serializer.class", "kafka.serializer.StringEncoder");

    // 1 means the producer receives an acknowledgment once the lead replica 
    // has received the data. This option provides better durability as the 
    // client waits until the server acknowledges the request as successful.
    props.put("request.required.acks", "1");

    ProducerConfig config = new ProducerConfig(props);
    producer = new Producer<String, String>(config);
  }

  public static void main(String[] args) {
    int argsCount = args.length;
    if (argsCount == 0 || argsCount == 1)
      throw new IllegalArgumentException(
        "Please provide topic name and Message count as arguments");

    // Topic name and the message count to be published is passed from the
    // command line 
    String topic = (String) args[0];
    String count = (String) args[1];
    int messageCount = Integer.parseInt(count);
    System.out.println("Topic Name - " + topic);
    System.out.println("Message Count - " + messageCount);

    SimpleProducer simpleProducer = new SimpleProducer();
    simpleProducer.publishMessage(topic, messageCount);
  }

  private void publishMessage(String topic, int messageCount) {
    for (int mCount = 0; mCount < messageCount; mCount++) {
      String runtime = new Date().toString();

      String msg = "Message Publishing Time - " + runtime;
      System.out.println(msg);
      // Creates a KeyedMessage instance
      KeyedMessage<String, String> data = 
        new KeyedMessage<String, String>(topic, msg);

      // Publish the message
      producer.send(data);
    }
    // Close producer connection with broker.
    producer.close();
  }
}
```

在运行之前，请确保您已经创建了主题`kafkatopic`，可以使用 API 或命令行创建，如下所示：

```java
[root@localhost kafka_2.9.2-0.8.1.1]#bin/kafka-topics.sh --create --zookeeper localhost:2181 --replication-factor 1 --partitions 3 --topic kafkatopic

```

### 注意

在控制台中编译和运行基于 Java 的 Kafka 程序之前，请确保您从[`www.slf4j.org/download.html`](http://www.slf4j.org/download.html)下载`slf4j-1.7.7.tar.gz`文件，并将其中包含的`slf4j-log4j12-1.7.7.jar`复制到`/opt/kafka_2.9.2-0.8.1.1/libs`目录。添加`KAFKA_LIB`环境变量，并使用以下命令将`/opt/kafka_2.9.2-0.8.1.1/libs`中的所有库添加到类路径中：

```java
[root@localhost kafka_2.9.2-0.8.1.1]# export KAFKA_LIB=/opt/kafka_2.9.2-0.8.1.1/libs
[root@localhost kafka_2.9.2-0.8.1.1]# export CLASSPATH=.:$KAFKA_LIB/jopt-simple-3.2.jar:$KAFKA_LIB/kafka_2.9.2-0.8.1.1.jar:$KAFKA_LIB/log4j-1.2.15.jar:$KAFKA_LIB/metrics-core-2.2.0.jar:$KAFKA_LIB/scala-library-2.9.2.jar:$KAFKA_LIB/slf4j-api-1.7.2.jar:$KAFKA_LIB/slf4j-log4j12-1.7.7.jar:$KAFKA_LIB/snappy-java-1.0.5.jar:$KAFKA_LIB/zkclient-0.3.jar:$KAFKA_LIB/zookeeper-3.3.4.jar

```

使用以下命令编译上述程序：

```java
[root@localhost kafka_2.9.2-0.8.1.1]# javac -d . kafka/examples/ch4/SimpleProducer.java

```

使用以下命令运行简单的生产者：

```java
[root@localhost kafka_2.9.2-0.8.1.1]# java kafka.examples.ch4.SimpleProducer kafkatopic 10

```

`SimpleProducer`类需要两个参数；首先是主题名称，其次是要发布的消息数量。一旦生产者成功执行并开始将消息发布到代理程序，就运行命令行消费者来消费消息，因为它订阅了在 Kafka 代理程序中创建的主题：

```java
[root@localhost kafka_2.9.2-0.8.1.1]# bin/kafka-console-consumer.sh --zookeeper localhost:2181 --from-beginning --topic kafkatopic

```

# 使用自定义分区创建 Java 生产者

先前的示例是一个在单节点、多代理程序集群上运行的基本`Producer`类的非常基本的示例，没有明确对消息进行分区。跳到下一个级别，让我们编写另一个程序，该程序使用自定义消息分区。在这个例子中，捕获并发布了来自任何 IP 地址的网站访问的日志消息。这条日志消息有三个部分：

+   网站点击的时间戳

+   网站的名称本身

+   正在访问网站的 IP 地址

让我们从编码开始。

## 导入类

首先导入以下类：

```java
import java.util.Date;
import java.util.Properties;
import java.util.Random;

import kafka.javaapi.producer.Producer;
import kafka.producer.KeyedMessage;
import kafka.producer.ProducerConfig;
```

## 定义属性

作为下一步，我们需要定义用于与 Kafka 代理程序建立连接的属性，如下面的代码所示，并将这些属性传递给 Kafka 生产者：

```java
Properties props = new Properties();
props.put("metadata.broker.list","localhost:9092, localhost:9093, localhost:9094");
props.put("serializer.class","kafka.serializer.StringEncoder"); 
props.put("partitioner.class", "kafka.examples.ch4.SimplePartitioner");
props.put("request.required.acks", "1");
ProducerConfig config = new ProducerConfig(props); 
Producer<Integer, String> producer = new Producer<Integer, String>(config);
```

在先前的属性列表中唯一的更改是添加了`partitioner.class`配置。

`partitioner.class`属性定义了用于确定消息需要发送到的主题中的分区的类。如果键为空，Kafka 将使用键的哈希值。

## 实现 Partitioner 类

接下来，我们需要通过实现`Partitioner`类（Scala 中编写的一个抽象类）来开发自定义分区类`SimplePartitioner`，该类需要接受在本例中是 IP 地址的键。然后找到最后一个八位并对 Kafka 为主题定义的分区数量进行模运算。以下是`SimplePartitioner`类的代码：

```java
package kafka.examples.ch4;

import kafka.producer.Partitioner;

public class SimplePartitioner implements Partitioner {

  public SimplePartitioner (VerifiableProperties props) {

  }

  /*
   * The method takes the key, which in this case is the IP address, 
   * It finds the last octet and does a modulo operation on the number 
   * of partitions defined within Kafka for the topic.
   * 
   * @see kafka.producer.Partitioner#partition(java.lang.Object, int)
   */
  public int partition(Object key, int a_numPartitions) {
    int partition = 0;
    String partitionKey = (String) key;
    int offset = partitionKey.lastIndexOf('.');
    if (offset > 0) {
      partition = Integer.parseInt(partitionKey.substring(offset + 1))
          % a_numPartitions;
    }
    return partition;
  }
}
```

## 构建消息并发送

作为最后一步，我们需要构建消息并将其发送到代理程序。以下是程序的完整列表：

```java
package kafka.examples.ch4;

import java.util.Date;
import java.util.Properties;
import java.util.Random;

import kafka.javaapi.producer.Producer;
import kafka.producer.KeyedMessage;
import kafka.producer.ProducerConfig;

public class CustomPartitionProducer {
  private static Producer<String, String> producer;

  public CustomPartitionProducer() {
    Properties props = new Properties();

    // Set the broker list for requesting metadata to find the lead broker
    props.put("metadata.broker.list",
          "192.168.146.132:9092, 192.168.146.132:9093, 192.168.146.132:9094");

    // This specifies the serializer class for keys 
    props.put("serializer.class", "kafka.serializer.StringEncoder");

    // Defines the class to be used for determining the partition 
    // in the topic where the message needs to be sent.
    props.put("partitioner.class", "kafka.examples.ch4.SimplePartitioner");

    // 1 means the producer receives an acknowledgment once the lead replica 
    // has received the data. This option provides better durability as the 
    // client waits until the server acknowledges the request as successful.
    props.put("request.required.acks", "1");

    ProducerConfig config = new ProducerConfig(props);
    producer = new Producer<String, String>(config);
  }

  public static void main(String[] args) {
    int argsCount = args.length;
    if (argsCount == 0 || argsCount == 1)
      throw new IllegalArgumentException(
        "Please provide topic name and Message count as arguments");

    // Topic name and the message count to be published is passed from the
    // command line
    String topic = (String) args[0];
    String count = (String) args[1];
    int messageCount = Integer.parseInt(count);

    System.out.println("Topic Name - " + topic);
    System.out.println("Message Count - " + messageCount);

    CustomPartitionProducer simpleProducer = new CustomPartitionProducer();
    simpleProducer.publishMessage(topic, messageCount);
  }

  private void publishMessage(String topic, int messageCount) {
    Random random = new Random();
    for (int mCount = 0; mCount < messageCount; mCount++) {

    String clientIP = "192.168.14." + random.nextInt(255); 
    String accessTime = new Date().toString();

    String message = accessTime + ",kafka.apache.org," + clientIP; 
      System.out.println(message);

      // Creates a KeyedMessage instance
      KeyedMessage<String, String> data = 
        new KeyedMessage<String, String>(topic, clientIP, message);

      // Publish the message
      producer.send(data);
    }
    // Close producer connection with broker.
    producer.close();
  }
}
```

在运行此之前，请确保您已从命令行创建了主题`website-hits`：

```java
[root@localhost kafka_2.9.2-0.8.1.1]# bin/kafka-topics.sh --create --zookeeper localhost:2181 --replication-factor 3 --partitions 5 --topic website-hits

```

还有，如前面的示例中所指定的，如果尚未完成，请进行类路径设置。现在使用以下命令编译分区器类和前面的生产者程序：

```java
[root@localhost kafka_2.9.2-0.8.1.1]# javac -d . kafka/examples/ch4/SimplePartitioner.java

[root@localhost kafka_2.9.2-0.8.1.1]# javac -d . kafka/examples/ch4/CustomPartitionProducer.java

```

使用以下命令运行自定义分区生产者：

```java
[root@localhost kafka_2.9.2-0.8.1.1]# java kafka.examples.ch4.CustomPartitionProducer website-hits 100

```

`CustomPartitionProducer`程序需要两个参数；首先是主题名称，其次是要发布的日志消息数量。一旦生产者成功执行并开始将消息发布到代理程序，就运行命令行消费者来消费消息，因为它订阅了在 Kafka 代理程序中创建的主题：

```java
[root@localhost kafka_2.9.2-0.8.1.1]# bin/kafka-console-consumer.sh --zookeeper localhost:2181 --from-beginning --topic kafkatopic

```

在前面的示例中，使用自定义分区逻辑的好处是，为同一客户端 IP 地址生成的所有日志消息最终都将进入同一个分区。此外，同一个分区可能具有不同 IP 地址的批量日志消息。

### 注意

分区逻辑也需要为消费者所知，以便消费者可以消费为所需 IP 地址发布的消息。这部分在第五章*编写消费者*中有所涵盖。

# Kafka 生产者属性列表

以下表格显示了可以为 Kafka 生产者配置的一些重要属性列表。Scala 类`kafka.producer.ProducerConfig`提供了生产者配置的实现级别细节。有关完整列表，请访问[`kafka.apache.org/documentation.html#producerconfigs`](http://kafka.apache.org/documentation.html#producerconfigs)。

| 属性名称 | 描述 | 默认值 |
| --- | --- | --- |
| `metadata.broker.list` | 生产者使用此属性来获取元数据（主题、分区和副本）。根据元数据返回的代理信息，将建立用于发送实际数据的套接字连接。格式为 `host1:port1,host2:port2`。 |   |
| `serializer.class` | 这指定了消息的 `serializer` 类。默认编码器接受一个字节并返回相同的字节。 | `kafka.serializer.DefaultEncoder` |

`producer.type` | 此属性指定消息将如何发送：

+   `async` 用于异步发送（与消息批处理一起使用）

+   `sync` 用于同步发送

| `sync` |
| --- |

| `request.required.acks` | 此值控制生产者请求何时被视为完成以及生产者是否从代理接收确认：

+   `0` 表示生产者永远不会等待来自代理的确认。这用于最低延迟，但耐久性最弱。

+   `1` 表示一旦主副本接收到数据，生产者将收到确认。此选项提供更好的耐久性，因为客户端会等待服务器确认请求成功。

+   `-1` 表示一旦所有同步副本接收到数据，生产者将收到确认。此选项提供了最佳的耐久性。

| `0` |
| --- |
| `key.serializer.class` | 这指定了键的序列化程序类。 | `${serializer.class}` |
| `partitioner.class` | 这是用于在子主题之间分区消息的分区器类。默认的分区器基于键的哈希值。 | `kafka.producer.DefaultPartitioner` |
| `compression.codec` | 此参数指定此生产者生成的所有数据的压缩编解码器。有效值为 `none`、`gzip` 和 `snappy`。 | `none` |
| `batch.num.messages` | 当使用异步模式时，此属性指定要在一批中发送的消息数量。生产者将等待，直到准备发送此数量的消息或达到 `queue.buffer.max.ms`。 | `200` |

# 摘要

在本章中，我们学习了如何编写基本的生产者和一些使用消息分区的高级 Java 生产者。我们还介绍了 Kafka 生产者的属性细节。

在下一章中，我们将学习如何编写基于 Java 的消费者来消费消息。


# 第五章：编写消费者

消费者是消费 Kafka 生产者发布的消息并处理从中提取的数据的应用程序。与生产者一样，消费者也可以是不同性质的，例如进行实时或准实时分析的应用程序、具有 NoSQL 或数据仓库解决方案的应用程序、后端服务、用于 Hadoop 的消费者或其他基于订阅者的解决方案。这些消费者也可以用不同的语言实现，如 Java、C 和 Python。

在本章中，我们将重点关注以下主题：

+   Kafka 消费者 API

+   基于 Java 的 Kafka 消费者

+   基于 Java 的 Kafka 消费者消费分区消息

在本章末尾，我们将探讨一些可以为 Kafka 消费者设置的重要属性。所以，让我们开始吧。

![编写消费者](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-kafka-2e/img/3090OS_05_01.jpg)

前面的图解释了 Kafka 消费者在消费消息时的高级工作原理。消费者订阅来自 Kafka 经纪人特定主题的消息消费。然后，消费者通过指定消息偏移量（消息偏移量的起始位置）向领导经纪人发出获取请求以消费消息分区。因此，Kafka 消费者以拉模型工作，并始终在 Kafka 日志（Kafka 内部数据表示）中当前位置之后拉取所有可用的消息。

在订阅时，消费者连接到任何活动节点，并请求有关主题分区领导者的元数据。这允许消费者直接与接收消息的领导经纪人通信。Kafka 主题被分成一组有序的分区，每个分区只能被一个消费者消费。一旦分区被消费，消费者就会将消息偏移量更改为下一个要消费的分区。这代表了已经被消费的状态，并且还提供了有意地倒带到旧偏移量并重新消费分区的灵活性。在接下来的几节中，我们将讨论 Kafka 为编写基于 Java 的自定义消费者提供的 API。

### 注意

本书中提到的所有 Kafka 类实际上都是用 Scala 编写的。

# Kafka 消费者 API

Kafka 为 Java 消费者提供了两种类型的 API：

+   高级 API

+   低级 API

## 高级消费者 API

当只需要数据而不需要处理消息偏移量时，使用高级消费者 API。此 API 将经纪人的细节隐藏在消费者之外，并通过提供对低级实现的抽象来轻松与 Kafka 集群通信。高级消费者在 Zookeeper 中存储最后的偏移量（消费者离开消费消息的消息分区内的位置），并且基于在进程开始时提供给 Kafka 的消费者组名称存储此偏移量。

消费者组名称在 Kafka 集群中是唯一且全局的，任何具有正在使用的消费者组名称的新消费者可能会导致系统中的模糊行为。当使用现有的消费者组名称启动新进程时，Kafka 会在消费者组的新旧进程线程之间触发重新平衡。重新平衡后，一些意图用于新进程的消息可能会发送到旧进程，导致意外结果。为避免这种模糊行为，在启动现有消费者组名称的新消费者之前，应关闭任何现有的消费者。

以下是导入的类，用于使用 Kafka 集群的高级消费者 API 编写基于 Java 的基本消费者：

+   `ConsumerConnector`：Kafka 提供了`ConsumerConnector`接口（`interface ConsumerConnector`），该接口由`ZookeeperConsumerConnector`类（`kafka.javaapi.consumer.ZookeeperConsumerConnector`）进一步实现。该类负责消费者与 ZooKeeper 的所有交互。

以下是`ConsumerConnector`类的类图：

![高级消费者 API](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-kafka-2e/img/3090OS_05_02.jpg)

+   `KafkaStream`：`kafka.consumer.KafkaStream`类的对象是由`ConsumerConnector`实现的`createMessageStreams`调用返回的。这些`KafkaStream`对象的列表是为每个主题返回的，可以进一步在流中创建迭代器。以下是基于 Scala 的类声明：

```java
class KafkaStreamK,V
```

这里，参数`K`和`V`分别指定了分区键和消息值的类型。

在`ConsumerConnector`类的 create 调用中，客户端可以指定所需流的数量，其中每个流对象用于单线程处理。这些流对象可以表示多个唯一分区的合并。

+   `ConsumerConfig`：`kafka.consumer.ConsumerConfig`类封装了与 ZooKeeper 建立连接所需的属性值，例如 ZooKeeper URL、ZooKeeper 会话超时和 ZooKeeper 接收时间。它还包含了消费者所需的属性值，例如组 ID 等。

在下一节之后将讨论基于高级 API 的工作消费者示例。

## 低级消费者 API

高级 API 不允许消费者控制与代理的交互。低级消费者 API 也称为“简单消费者 API”，它是无状态的，并且提供了对 Kafka 代理和消费者之间通信的精细控制。它允许消费者在向代理发出的每个请求中设置消息偏移量，并在消费者端维护元数据。这个 API 可以被在线和离线消费者（如 Hadoop）使用。这些类型的消费者也可以对同一消息执行多次读取，或者管理事务以确保消息只被消费一次。

与高级消费者 API 相比，开发人员需要付出额外的努力来获得消费者内的低级控制，例如跟踪偏移量、找出主题和分区的领导代理、处理领导代理变更等。

在低级消费者 API 中，消费者首先查询活动代理以了解有关领导代理的详细信息。有关活动代理的信息可以通过属性文件或命令行传递给消费者。`kafka.javaapi.TopicMetadataResponse`类的`topicsMetadata()`方法用于从领导代理那里找到感兴趣的主题的元数据。对于消息分区读取，`kafka.api.OffsetRequest`类定义了两个常量：`EarliestTime`和`LatestTime`，用于查找日志中数据的开始和新消息流。这些常量还帮助消费者跟踪已经读取的消息。

低级消费者 API 中使用的主要类是`SimpleConsumer`（`kafka.javaapi.consumer.SimpleConsumer`）类。以下是`SimpleConsumer`类的类图：

![低级消费者 API](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-kafka-2e/img/3090OS_05_03.jpg)

简单消费者类提供了与领导代理建立连接以从主题获取消息以及获取主题元数据和偏移量列表的方法。

用于构建不同请求对象的几个重要类是`FetchRequest`（`kafka.api.FetchRequest`）、`OffsetRequest`（`kafka.javaapi.OffsetRequest`）、`OffsetFetchRequest`（`kafka.javaapi.OffsetFetchRequest`）、`OffsetCommitRequest`（`kafka.javaapi.OffsetCommitRequest`）和`TopicMetadataRequest`（`kafka.javaapi.TopicMetadataRequest`）。

### 注意

本章中的所有示例都是基于高级消费者 API 的。有关基于低级消费者 API 的示例，请参阅[`cwiki.apache.org/confluence/display/KAFKA/0.8.0+SimpleConsumer+Example`](https://cwiki.apache.org/confluence/display/KAFKA/0.8.0+SimpleConsumer+Example)。

# 简单 Java 消费者

现在我们将开始编写一个使用高级消费者 API 开发的单线程简单的 Java 消费者，用于从主题中消费消息。`SimpleHLConsumer` 类用于从特定主题获取消息并消费它，假设主题内有一个单个分区。

## 导入类

首先，我们需要导入以下类：

```java
import kafka.consumer.ConsumerConfig;
import kafka.consumer.ConsumerIterator;
import kafka.consumer.KafkaStream;
import kafka.javaapi.consumer.ConsumerConnector;
```

## 定义属性

作为下一步，我们需要定义用于与 Zookeeper 建立连接的属性，并使用以下代码将这些属性传递给 Kafka 消费者：

```java
Properties props = new Properties();
props.put("zookeeper.connect", "localhost:2181");
props.put("group.id", "testgroup");
props.put("zookeeper.session.timeout.ms", "500");
props.put("zookeeper.sync.time.ms", "250");
props.put("auto.commit.interval.ms", "1000");
new ConsumerConfig(props);
```

现在让我们看一下代码中提到的主要属性：

+   `zookeeper.connect`：此属性指定了用于在集群中查找运行的 Zookeeper 实例的 ZooKeeper `<node:port>` 连接详细信息。在 Kafka 集群中，Zookeeper 用于存储此消费者组消费的特定主题和分区的偏移量。

+   `group.id`：此属性指定了消费者组的名称，该组由组内的所有消费者共享。这也是 Zookeeper 用于存储偏移量的进程名称。

+   `zookeeper.session.timeout.ms`：此属性指定了 Zookeeper 会话超时时间（以毫秒为单位），表示 Kafka 等待 Zookeeper 响应请求的时间量，然后放弃并继续消费消息。

+   `zookeeper.sync.time.ms`：此属性指定了 ZooKeeper 领导者和跟随者之间的 ZooKeeper 同步时间（以毫秒为单位）。

+   `auto.commit.interval.ms`：此属性定义了消费者偏移量提交到 Zookeeper 的频率（以毫秒为单位）。

# 从主题中读取消息并打印它们

最后一步，我们需要使用以下代码读取消息：

```java
Map<String, Integer> topicMap = new HashMap<String, Integer>();
// 1 represents the single thread
topicCount.put(topic, new Integer(1));

Map<String, List<KafkaStream<byte[], byte[]>>> consumerStreamsMap = consumer.createMessageStreams(topicMap);

// Get the list of message streams for each topic, using the default decoder.
List<KafkaStream<byte[], byte[]>>streamList =  consumerStreamsMap.get(topic);

for (final KafkaStream <byte[], byte[]> stream : streamList) {
ConsumerIterator<byte[], byte[]> consumerIte = stream.iterator();
  while (consumerIte.hasNext())
    System.out.println("Message from Single Topic :: "
    + new String(consumerIte.next().message()));
} 
```

因此，完整的程序将如下代码所示：

```java
package kafka.examples.ch5;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import kafka.consumer.ConsumerConfig;
import kafka.consumer.ConsumerIterator;
import kafka.consumer.KafkaStream;
import kafka.javaapi.consumer.ConsumerConnector;

public class SimpleHLConsumer {
  private final ConsumerConnector consumer;
  private final String topic;

  public SimpleHLConsumer(String zookeeper, String groupId, String topic) {
    consumer = kafka.consumer.Consumer
        .createJavaConsumerConnector(createConsumerConfig(zookeeper,
            groupId));
    this.topic = topic;
  }

  private static ConsumerConfig createConsumerConfig(String zookeeper,
        String groupId) {
    Properties props = new Properties();
    props.put("zookeeper.connect", zookeeper);
    props.put("group.id", groupId);
    props.put("zookeeper.session.timeout.ms", "500");
    props.put("zookeeper.sync.time.ms", "250");
    props.put("auto.commit.interval.ms", "1000");

    return new ConsumerConfig(props);

  }

  public void testConsumer() {

    Map<String, Integer> topicMap = new HashMap<String, Integer>();

    // Define single thread for topic
    topicMap.put(topic, new Integer(1));

    Map<String, List<KafkaStream<byte[], byte[]>>> consumerStreamsMap = 
        consumer.createMessageStreams(topicMap);

    List<KafkaStream<byte[], byte[]>> streamList = consumerStreamsMap
        .get(topic);

    for (final KafkaStream<byte[], byte[]> stream : streamList) {
      ConsumerIterator<byte[], byte[]> consumerIte = stream.iterator();
      while (consumerIte.hasNext())
        System.out.println("Message from Single Topic :: "
          + new String(consumerIte.next().message()));
    }
    if (consumer != null)
      consumer.shutdown();
  }

  public static void main(String[] args) {

    String zooKeeper = args[0];
    String groupId = args[1];
    String topic = args[2];
    SimpleHLConsumer simpleHLConsumer = new SimpleHLConsumer(
          zooKeeper, groupId, topic);
    simpleHLConsumer.testConsumer();
  }

}
```

在运行此命令之前，请确保您已从命令行创建了主题 `kafkatopic`：

```java
[root@localhost kafka_2.9.2-0.8.1.1]#bin/kafka-topics.sh --create --zookeeper localhost:2181 --replication-factor 1 --partitions 3 --topic kafkatopic

```

### 注意

在控制台中编译和运行基于 Java 的 Kafka 程序之前，请确保您从 [`www.slf4j.org/download.html`](http://www.slf4j.org/download.html) 下载了 `slf4j-1.7.7.tar.gz` 文件，并将 `slf4j-1.7.7.tar.gz` 中包含的 `slf4j-log4j12-1.7.7.jar` 复制到 `/opt/kafka_2.9.2-0.8.1.1/libs` 目录。还要使用以下命令将 `/opt/kafka_2.9.2-0.8.1.1/libs` 中的所有库添加到类路径中：

```java
[root@localhost kafka_2.9.2-0.8.1.1]# export KAFKA_LIB=/opt/kafka_2.9.2-0.8.1.1/libs
[root@localhost kafka_2.9.2-0.8.1.1]# export CLASSPATH=.:$KAFKA_LIB/jopt-simple-3.2.jar:$KAFKA_LIB/kafka_2.9.2-0.8.1.1.jar:$KAFKA_LIB/log4j-1.2.15.jar:$KAFKA_LIB/metrics-core-2.2.0.jar:$KAFKA_LIB/scala-library-2.9.2.jar:$KAFKA_LIB/slf4j-api-1.7.2.jar:$KAFKA_LIB/slf4j-log4j12-1.7.7.jar:$KAFKA_LIB/snappy-java-1.0.5.jar:$KAFKA_LIB/zkclient-0.3.jar:$KAFKA_LIB/zookeeper-3.3.4.jar

```

还要运行在第四章 *编写生产者* 中开发的 `SimpleProducer` 类，它需要两个参数：第一个是主题名称，第二个是要发布的消息数量，如下所示：

```java
[root@localhost kafka_2.9.2-0.8.1.1]# java kafka.examples.ch4.SimpleProducer kafkatopic 100

```

使用以下命令编译上述的 `SimpleHLConsumer` 类：

```java
[root@localhost kafka_2.9.2-0.8.1.1]# javac -d . kafka/examples/ch5/SimpleHLConsumer.java

```

在单独的控制台窗口中使用以下命令运行简单的高级消费者：

```java
[root@localhost kafka_2.9.2-0.8.1.1]# java kafka.examples.ch5.SimpleHLConsumer localhost:2181 testgroup kafkatopic

```

为了成功执行，`SimpleHLConsumer` 类需要三个参数：第一个是 Zookeeper 连接字符串 `<host:port>`；第二个是唯一的组 ID；第三个是 Kafka 主题名称。

# 多线程 Java 消费者

上一个例子是一个非常基本的消费者示例，它从单个代理消费消息，主题内没有明确的消息分区。让我们跳到下一个级别，编写另一个程序，从单个/多个主题连接到多个分区来消费消息。

基于多线程、高级、基于消费者 API 的设计通常基于主题中的分区数，并遵循线程与主题内分区之间的一对一映射方法。例如，如果为任何主题定义了四个分区，作为最佳实践，应该使用消费者应用程序启动只有四个线程，否则可能会发生一些冲突行为，例如线程永远不会接收到消息或线程从多个分区接收消息。此外，接收多个消息不会保证消息按顺序放置。例如，一个线程可能从第一个分区接收两条消息，从第二个分区接收三条消息，然后从第一个分区再接收三条消息，然后再从第一个分区接收更多消息，即使第二个分区有可用数据。

让我们继续前进。

## 导入类

作为第一步，我们需要导入以下类：

```java
import kafka.consumer.ConsumerConfig;
import kafka.consumer.ConsumerIterator;
import kafka.consumer.KafkaStream;
import kafka.javaapi.consumer.ConsumerConnector;
```

## 定义属性

作为下一步，我们需要为与 Zookeeper 建立连接定义属性，并使用以下代码将这些属性传递给 Kafka 消费者：

```java
Properties props = new Properties();
props.put("zookeeper.connect", "localhost:2181");
props.put("group.id", "testgroup");
props.put("zookeeper.session.timeout.ms", "500");
props.put("zookeeper.sync.time.ms", "250");
props.put("auto.commit.interval.ms", "1000");
new ConsumerConfig(props);
```

前面的属性已经在前面的示例中讨论过。有关 Kafka 消费者属性的更多详细信息，请参阅本章的最后一节。

## 从线程中读取消息并打印它

此部分与上一部分的唯一区别在于我们首先创建一个线程池，并在线程池内的每个线程中获取与每个线程相关联的 Kafka 流，如下面的代码所示：

```java
// Define thread count for each topic
topicMap.put(topic, new Integer(threadCount));

// Here we have used a single topic but we can also add
// multiple topics to topicCount MAP
Map<String, List<KafkaStream<byte[], byte[]>>> consumerStreamsMap 
           = consumer.createMessageStreams(topicMap);

List<KafkaStream<byte[], byte[]>> streamList = consumerStreamsMap.get(topic);

// Launching the thread pool
executor = Executors.newFixedThreadPool(threadCount);
```

基于 Kafka 高级消费者 API 的多线程 Kafka 消费者的完整程序列表如下：

```java
package kafka.examples.ch5;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import kafka.consumer.ConsumerConfig;
import kafka.consumer.ConsumerIterator;
import kafka.consumer.KafkaStream;
import kafka.javaapi.consumer.ConsumerConnector;

public class MultiThreadHLConsumer {

  private ExecutorService executor;
  private final ConsumerConnector consumer;
  private final String topic;

  public MultiThreadHLConsumer(String zookeeper, String groupId, String topic) {
    consumer = kafka.consumer.Consumer
        .createJavaConsumerConnector(createConsumerConfig(zookeeper, groupId));
    this.topic = topic;
  }

  private static ConsumerConfig createConsumerConfig(String zookeeper,
        String groupId) {
    Properties props = new Properties();
    props.put("zookeeper.connect", zookeeper);
    props.put("group.id", groupId);
    props.put("zookeeper.session.timeout.ms", "500");
    props.put("zookeeper.sync.time.ms", "250");
    props.put("auto.commit.interval.ms", "1000");

    return new ConsumerConfig(props);

  }

  public void shutdown() {
    if (consumer != null)
      consumer.shutdown();
    if (executor != null)
      executor.shutdown();
  }

  public void testMultiThreadConsumer(int threadCount) {

    Map<String, Integer> topicMap = new HashMap<String, Integer>();

    // Define thread count for each topic
    topicMap.put(topic, new Integer(threadCount));

    // Here we have used a single topic but we can also add
    // multiple topics to topicCount MAP
    Map<String, List<KafkaStream<byte[], byte[]>>> consumerStreamsMap = 
        consumer.createMessageStreams(topicMap);

    List<KafkaStream<byte[], byte[]>> streamList = consumerStreamsMap
        .get(topic);

    // Launching the thread pool
    executor = Executors.newFixedThreadPool(threadCount);

    // Creating an object messages consumption
    int count = 0;
    for (final KafkaStream<byte[], byte[]> stream : streamList) {
      final int threadNumber = count;
      executor.submit(new Runnable() {
      public void run() {
      ConsumerIterator<byte[], byte[]> consumerIte = stream.iterator();
      while (consumerIte.hasNext())
        System.out.println("Thread Number " + threadNumber + ": "
        + new String(consumerIte.next().message()));
        System.out.println("Shutting down Thread Number: " + 
        threadNumber);
        }
      });
      count++;
    }
    if (consumer != null)
      consumer.shutdown();
    if (executor != null)
      executor.shutdown();
  }

  public static void main(String[] args) {

    String zooKeeper = args[0];
    String groupId = args[1];
    String topic = args[2];
    int threadCount = Integer.parseInt(args[3]);
    MultiThreadHLConsumer multiThreadHLConsumer = 
        new MultiThreadHLConsumer(zooKeeper, groupId, topic);
    multiThreadHLConsumer.testMultiThreadConsumer(threadCount);
    try {
      Thread.sleep(10000);
    } catch (InterruptedException ie) {

    }
    multiThreadHLConsumer.shutdown();

  }
}
```

编译上述程序，并在运行之前阅读以下提示。

### 提示

在运行此程序之前，我们需要确保我们的集群作为多代理集群（包括单个或多个节点）正在运行。有关如何设置单节点-多代理集群的更多信息，请参阅第二章, *设置 Kafka 集群*。

一旦您的多代理集群启动，使用以下命令创建一个具有四个分区并将复制因子设置为`2`的主题，然后运行此程序：

```java
[root@localhost kafka-0.8]# bin/kafka-topics.sh --zookeeper localhost:2181 --create --topic kafkatopic --partitions 4 --replication-factor 2

```

此外，运行在第四章中开发的`SimpleProducer`类，*编写生产者*，它需要两个参数：首先是主题名称，其次是要发布的消息数量，如下所示：

```java
[root@localhost kafka_2.9.2-0.8.1.1]# java kafka.examples.ch4.SimpleProducer kafkatopic 100

```

使用以下命令编译前述`MultiThreadHLConsumer`类：

```java
[root@localhost kafka_2.9.2-0.8.1.1]# javac -d . kafka/examples/ch5/MultiThreadHLConsumer.java

```

现在在单独的控制台窗口中使用以下命令运行多线程高级消费者：

```java
[root@localhost kafka_2.9.2-0.8.1.1]# java kafka.examples.ch5.MultiThreadHLConsumer localhost:2181 testgroup kafkatopic 4

```

为了成功执行，`SimpleHLConsumer`类需要四个参数：

+   Zookeeper 连接字符串`<host:port>`

+   唯一的组 ID

+   Kafka 主题名称

+   线程计数

此程序将打印与每个线程相关联的所有消息的所有分区。

# Kafka 消费者属性列表

以下是一些可以为基于高级消费者 API 的 Kafka 消费者配置的重要属性列表。Scala 类`kafka.consumer.ConsumerConfig`提供了消费者配置的实现级细节。要获取完整列表，请访问[`kafka.apache.org/documentation.html#consumerconfigs`](http://kafka.apache.org/documentation.html#consumerconfigs)。

| 属性名称 | 描述 | 默认值 |
| --- | --- | --- |
| `group.id` | 此属性为同一消费者组内的一组消费者定义了唯一标识。 |   |
| `consumer.id` | 此属性为 Kafka 消费者指定，如果未定义，则会自动生成。 | `null` |
| `zookeeper.connect` | 此属性指定 Zookeeper 连接字符串，`<hostname:port/chroot/path>`。Kafka 使用 Zookeeper 来存储消费者组对特定主题和分区消耗的消息的偏移量。`/chroot/path`定义了全局 zookeeper 命名空间中的数据位置。 |   |
| `client.id` | 每个请求都由 Kafka 客户端指定 `client.id` 值，并用于标识发出请求的客户端。 | `${group.id}` |
| `zookeeper.session.timeout.ms` | 此属性定义了 Kafka 消费者在等待 Zookeeper 脉冲之前的时间（以毫秒为单位），在此时间内如果没有脉冲，消费者将被声明为死亡并启动重新平衡。 | `6000` |
| `zookeeper.connection.timeout.ms` | 此值定义了客户端与 ZooKeeper 建立连接的最长等待时间（以毫秒为单位）。 | `6000` |
| `zookeeper.sync.time.ms` | 此属性定义了将 Zookeeper 跟随者与 Zookeeper 领导者同步所需的时间（以毫秒为单位）。 | `2000` |
| `auto.commit.enable` | 此属性启用了定期将消费者已获取的消息偏移量提交到 Zookeeper。在消费者故障的情况下，这些提交的偏移量将被新的消费者用作起始位置。 | `true` |
| `auto.commit.interval.ms` | 此属性定义了将消费的偏移量提交到 ZooKeeper 的频率（以毫秒为单位）。 | `60 * 1000` |

| `auto.offset.reset` | 此属性定义了如果在 Zookeeper 中有初始偏移量或偏移量超出范围时的偏移值。可能的值有：

+   `largest`: 重置为最大偏移量

+   `smallest`: 重置为最小偏移量

+   其他任何值：抛出异常

| `largest` |
| --- |
| `consumer.timeout.ms` | 如果在指定的时间间隔后没有消息可供消费，此属性将向消费者抛出异常。 | `-1` |

# 摘要

在本章中，我们已经学习了如何编写基本的消费者，并了解了一些从分区消费消息的高级 Java 消费者。

在下一章中，我们将学习如何将 Kafka 与 Storm 和 Hadoop 集成。


# 第六章：Kafka 集成

考虑一个网站的用例，其中需要跟踪连续的安全事件，例如用户身份验证和授权以访问安全资源，并且需要实时做出决策以应对任何安全漏洞。使用任何典型的面向批处理的数据处理系统，例如 Hadoop，需要首先收集所有数据，然后进行处理以揭示模式，这将使得判断是否存在对 Web 应用程序的安全威胁变得太晚。因此，这是实时数据处理的经典用例。

让我们考虑另一个用例，即通过网站使用生成的原始点击流被捕获和预处理。处理这些点击流可以为客户偏好提供有价值的见解，这些见解可以稍后与营销活动和推荐引擎相结合，以提供对消费者的分析。因此，我们可以简单地说，存储在 Hadoop 上的大量点击流数据将通过 Hadoop MapReduce 作业以批处理模式而不是实时模式进行处理。

在本章中，我们将探讨如何将 Kafka 与以下技术集成，以解决不同的用例，例如使用 Storm 进行实时处理，使用 Spark Streaming 进行批处理：

+   Kafka 与 Storm 的集成

+   Kafka 与 Hadoop 的集成

让我们开始吧。

# Kafka 与 Storm 的集成

使用诸如**Java 消息服务**（**JMS**）之类的技术实时处理少量数据从未是一个挑战；然而，当处理大量流数据时，这些处理系统显示出性能限制。此外，这些系统不是良好的横向可扩展的解决方案。

# 介绍 Storm

**Storm**是一个用于实时处理大量数据流的开源、分布式、可靠和容错系统。它支持许多用例，如实时分析、在线机器学习、连续计算和**ETL**（**Extract Transformation Load**）范式。

有各种组件一起工作进行流数据处理，如下所示：

+   **Spout**：这是连续的日志数据流。

+   **Bolt**：spout 将数据传递给一个名为**bolt**的组件。Bolt 可以消耗任意数量的输入流，进行一些处理，并可能发出新的流。例如，通过处理一系列推文来发出趋势分析流。

以下图表显示了 Storm 架构中的 spout 和 bolt：

![介绍 Storm](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-kafka-2e/img/3090OS_06_01.jpg)

我们可以假设 Storm 集群是一系列螺栓组件的链，其中每个螺栓对由 spout 流的数据进行某种转换。除了 spout 和 bolts 之外，还有一些其他组件，如下所示：

+   元组：这是 Storm 使用的本机数据结构（任何数据类型的名称列表值）。

+   流：这代表一系列元组。

+   Workers：这些代表 Storm 进程。

+   执行器：由 Storm 工作启动的 Storm 线程。在这里，工作可能运行一个或多个执行器，执行器可能运行一个或多个来自 spout 或 bolt 的 Storm 作业。

接下来在 Storm 集群中，作业通常被称为**拓扑**；唯一的区别是这些拓扑永远运行。对于 Storm 上的实时计算，通常会创建计算图形的拓扑。通常，拓扑定义了数据如何从 spouts 流经 bolts。这些拓扑可以是事务性的或非事务性的。

### 注意

有关 Storm 的完整信息可以在[`storm-project.net/`](http://storm-project.net/)找到。

如果您已经使用过 Storm 或对 Storm 有工作知识，下面的部分将会很有用。

## 集成 Storm

我们已经在之前的章节中学习到，Kafka 是一个具有高性能的基于发布-订阅的消息系统，具有高度可扩展的特性。Kafka spout 可用于将 Storm 与 Kafka 集群集成。

Kafka spout 是一个常规的 spout 实现，用于从 Kafka 集群中读取数据。这个 Kafka spout 之前可以在[`github.com/wurstmeister/storm-kafka-0.8-plus`](https://github.com/wurstmeister/storm-kafka-0.8-plus)找到，现在已经合并到核心 Storm 项目版本 0.9.2-incubating 中，并且可以在[`github.com/apache/storm/tree/master/external/storm-kafka`](https://github.com/apache/storm/tree/master/external/storm-kafka)找到。这个 storm-kafka spout 提供了关键功能，比如支持动态发现 Kafka 经纪人和“仅一次”元组处理。除了常规的 Kafka Storm spout，它还提供了 Kafka 的 Trident spout 实现。在本节中，我们将重点放在常规的 storm-kafka spout 上。

### 注意

Trident 是一个高级抽象，用于在 Storm 之上进行实时计算。它允许我们无缝地混合高吞吐量（每秒数百万条消息）、有状态的流处理和低延迟的分布式查询。更多信息请参见[`storm.apache.org/documentation/Trident-tutorial.html`](https://storm.apache.org/documentation/Trident-tutorial.html)。

两个 spout 实现都使用`BrokerHost`接口来跟踪 Kafka 经纪人主机到分区的映射和`KafkaConfig`参数。`ZkHosts`和`StaticHosts`提供了`BrokerHost`接口的两个实现。

`ZkHosts`实现用于动态跟踪 Kafka 经纪人到分区的映射，借助 Kafka 的 zookeeper 条目：

```java
public ZkHosts(String brokerZkStr, String brokerZkPath) 
public ZkHosts(String brokerZkStr)
```

前面的构造函数用于创建`ZkHosts`的实例。在这里，`brokerZkStr`可以是`localhost:9092`，`brokerZkPath`是存储所有主题和分区信息的根目录。`brokerZkPath`的默认值是`/brokers`。

`StaticHosts`实现用于静态分区信息，如：

```java
//localhost:9092\. Uses default port as 9092.
Broker brokerPartition0 = new Broker("localhost");

//localhost:9092\. Takes the port explicitly
Broker brokerPartition1 = new Broker("localhost", 9092);    

//localhost:9092 specified as one string.
Broker brokerPartition2 = new Broker("localhost:9092");    

GlobalPartitionInformation partitionInfo = new GlobalPartitionInformation();

//mapping form partition 0 to brokerPartition0
partitionInfo.addPartition(0, brokerPartition0);

//mapping form partition 1 to brokerPartition1
partitionInfo.addPartition(1, brokerPartition1);    

//mapping form partition 2 to brokerPartition2
partitionInfo.addPartition(2, brokerPartition2);

StaticHosts hosts = new StaticHosts(partitionInfo);
```

要创建`StaticHosts`实例，首先需要创建`GlobalPartitionInformation`的第一个实例，如前面的代码所示。接下来，需要创建`KafkaConfig`实例来构建 Kafka spout：

```java
public KafkaConfig(BrokerHosts hosts, String topic)
public KafkaConfig(BrokerHosts hosts, String topic, String clientId)
```

前面的构造函数需要以下参数：

+   Kafka 经纪人列表

+   用于读取消息的主题名称

+   客户端 ID，作为 Zookeeper 路径的一部分，其中 spout 作为消费者存储当前的消费偏移量。

`KafkaConfig`类还有一堆公共变量，用于控制应用程序的行为以及 spout 如何从 Kafka 集群中获取消息：

```java
  public int fetchSizeBytes = 1024 * 1024;
  public int socketTimeoutMs = 10000;
  public int fetchMaxWait = 10000;
  public int bufferSizeBytes = 1024 * 1024;
  public MultiScheme scheme = new RawMultiScheme();
  public boolean forceFromStart = false;
  public long startOffsetTime = 
        kafka.api.OffsetRequest.EarliestTime();
  public long maxOffsetBehind = Long.MAX_VALUE;
  public boolean useStartOffsetTimeIfOffsetOutOfRange = true;
  public int metricsTimeBucketSizeInSecs = 60;
```

`Spoutconfig`类扩展了`KafkaConfig`类，以支持`zkroot`和`id`两个额外的值：

```java
public SpoutConfig(BrokerHosts hosts, String topic, String zkRoot, String id);
```

前面的构造函数还需要以下内容：

+   在 Zookeeper 中的根路径，spout 存储消费者偏移量。

+   spout 的唯一标识

以下代码示例显示了使用先前参数初始化`KafkaSpout`类实例：

```java
// Creating instance for BrokerHosts interface implementation
BrokerHosts hosts = new ZkHosts(brokerZkConnString);

// Creating instance of SpoutConfig
SpoutConfig spoutConfig = new SpoutConfig(brokerHosts, topicName, "/" + topicName, UUID.randomUUID().toString());

// Defines how the byte[] consumed from kafka gets transformed into // a storm tuple
spoutConfig.scheme = new SchemeAsMultiScheme(new StringScheme());

// Creating instance of KafkaSpout
KafkaSpout kafkaSpout = new KafkaSpout(spoutConfig);
```

以下图表显示了 Kafka Storm 工作模型的高级集成视图：

![Integrating Storm](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-kafka-2e/img/3090OS_06_02.jpg)

Kafka spout 使用与 Apache Storm 相同的 Zookeeper 实例来存储消息偏移和段消费跟踪的状态，如果它被消费。这些偏移量存储在 Zookeeper 指定的根路径下。Kafka spout 使用这些偏移量在下游故障或超时的情况下重放元组。尽管它也有一个重新回到先前偏移的规定，而不是从最后保存的偏移开始，Kafka 会选择在指定时间戳周围写入的最新偏移量：

```java
spoutConfig.forceStartOffsetTime(TIMESTAMP);
```

这里的值`-1`强制 Kafka spout 从最新的偏移重新启动，`-2`强制 spout 从最早的偏移重新启动。

这个 storm-kafka spout 也有一个，因为它不支持 Kafka 0.7x 经纪人，只支持 Kafka 0.8.1.x 及以上版本。

### 注意

要运行 Kafka 与 Storm，需要设置并运行 Storm 和 Kafka 的集群。Storm 集群设置超出了本书的范围。

# Kafka 与 Hadoop 集成

资源共享、稳定性、可用性和可扩展性是分布式计算的许多挑战之一。如今，另一个挑战是处理 TB 或 PB 级别的极大数据量。

## 介绍 Hadoop

Hadoop 是一个大规模分布式批处理框架，可以在许多节点上并行处理数据，并解决了分布式计算，包括大数据的挑战。

Hadoop 基于 MapReduce 框架的原则（由 Google 引入），为大规模计算的并行化和分布提供了一个简单的接口。Hadoop 有自己的分布式数据文件系统称为**Hadoop 分布式文件系统**（**HDFS**）。在任何典型的 Hadoop 集群中，HDFS 将数据分割成小块（称为**块**）并将其分发到所有节点。HDFS 还复制这些小数据块并存储它们，以确保如果任何节点宕机，数据可以从另一个节点获取。

以下图显示了多节点 Hadoop 集群的高级视图：

![介绍 Hadoop](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-kafka-2e/img/3090OS_06_03.jpg)

Hadoop 有以下主要组件：

+   **名称节点**：这是 HDFS 的交互单点。名称节点存储有关分布在节点上的数据小块（块）的信息。

+   **辅助名称节点**：此节点存储编辑日志，有助于在名称节点故障的情况下恢复 HDFS 的最新更新状态。

+   **数据节点**：这些节点存储名称节点分发的实际数据块，并存储来自其他节点的复制数据。

+   **作业跟踪器**：这负责将 MapReduce 作业拆分为较小的任务。

+   **任务跟踪器**：任务跟踪器负责执行由作业跟踪器拆分的任务。

数据节点和任务跟踪器共享相同的机器和 MapReduce 作业拆分；任务的执行是基于名称节点提供的数据存储位置信息完成的。

现在在讨论 Kafka 与 Hadoop 集成之前，让我们快速在伪分布式模式下设置单节点 Hadoop 集群。

### 注意

Hadoop 集群可以在三种不同的模式下设置：

+   本地模式

+   伪分布式模式

+   完全分布式模式

本地模式和伪分布式模式在单节点集群上运行。在本地模式下，所有 Hadoop 主要组件在单个 JVM 实例中运行；而在伪分布式模式下，每个组件在单个节点上的单独 JVM 实例中运行。伪分布式模式主要由开发人员用作开发环境。在完全分布式模式下，所有组件都在单独的节点上运行，并且用于测试和生产环境。

以下是用于创建伪分布式模式集群的步骤：

1.  安装和配置 Java。参考第一章中的*安装 Java 1.7 或更高版本*部分，*介绍 Kafka*。

1.  从[`www.apache.org/dyn/closer.cgi/hadoop/common/`](http://www.apache.org/dyn/closer.cgi/hadoop/common/)下载当前稳定的 Hadoop 分发包。

1.  在`/opt`中解压下载的 Hadoop 分发包，并将 Hadoop 的`bin`目录添加到路径中，如下所示：

```java
 # Assuming your installation directory is /opt/Hadoop-2.6.0
 [root@localhost opt]#export HADOOP_HOME=/opt/hadoop-2.6.0
 [root@localhost opt]#export PATH=$PATH:$HADOOP_HOME/bin
```

1.  添加以下配置：

```java
etc/hadoop/core-site.xml:
<configuration>
    <property>
        <name>fs.defaultFS</name>
        <value>hdfs://localhost:9000</value>
    </property>
</configuration>

 etc/hadoop/hdfs-site.xml:
<configuration>
    <property>
        <name>dfs.replication</name>
        <value>1</value>
    </property>
</configuration>
```

1.  在本地主机上设置 ssh，无需密码短语：

```java
[root@localhost opt]# ssh localhost
```

如果 ssh-to-localhost 在没有密码短语的情况下无法工作，请执行以下命令：

```java
[root@localhost opt]# ssh-keygen -t dsa -P '' -f ~/.ssh/id_dsa [root@localhost opt]# cat ~/.ssh/id_dsa.pub >> ~/.ssh/authorized_keys

```

1.  格式化文件系统：

```java
[root@localhost opt]# bin/hdfs namenode -format

```

1.  启动 NameNode 守护程序和 DataNode 守护程序：

```java
[root@localhost opt]# sbin/start-dfs.sh

```

一旦成功设置了 Hadoop 集群，请在`http://localhost:50070/`上浏览 NameNode 的 Web 界面。

## 集成 Hadoop

如果您已经使用过 Hadoop 或对 Hadoop 有工作经验，本节将非常有用。

对于实时发布-订阅用例，Kafka 用于构建可用于实时处理或监控的管道，并将数据加载到 Hadoop、NoSQL 或数据仓库系统中进行离线处理和报告。

Kafka 在其`contrib`目录下提供了 Hadoop 生产者和消费者的源代码。

## Hadoop 生产者

Hadoop 生产者提供了从 Hadoop 集群向 Kafka 发布数据的桥梁，如下图所示：

![Hadoop 生产者](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-kafka-2e/img/3090OS_06_04.jpg)

对于 Kafka 生产者，Kafka 主题被视为 URI，并且为了连接到特定的 Kafka 代理，URI 被指定如下：

```java
kafka://<kafka-broker>/<kafka-topic>
```

Hadoop 生产者代码提出了从 Hadoop 获取数据的两种可能方法：

+   **使用 Pig 脚本并以 Avro 格式编写消息**：在这种方法中，Kafka 生产者使用 Pig 脚本以二进制 Avro 格式编写数据，其中每行表示单个消息。对于将数据推送到 Kafka 集群，`AvroKafkaStorage`类（它扩展了 Pig 的`StoreFunc`类）将 Avro 模式作为其第一个参数，并连接到 Kafka URI。使用`AvroKafkaStorage`生产者，我们还可以在同一个基于 Pig 脚本的作业中轻松写入多个主题和代理。在编写 Pig 脚本时，还需要注册所需的 Kafka JAR 文件。以下是示例 Pig 脚本：

```java
    REGISTER hadoop-producer_2.8.0-0.8.0.jar;
    REGISTER avro-1.4.0.jar;
    REGISTER piggybank.jar;
    REGISTER kafka-0.8.0.jar;
    REGISTER jackson-core-asl-1.5.5.jar;
    REGISTER jackson-mapper-asl-1.5.5.jar;
    REGISTER scala-library.jar;

member_info = LOAD 'member_info.tsv' AS (member_id : int, name : chararray);

names = FOREACH member_info GENERATE name;

STORE member_info INTO 'kafka://localhost:9092/member_info' USING kafka.bridge.AvroKafkaStorage('"string"');
```

在上述脚本中，Pig 的`StoreFunc`类利用 Piggybank 中的`AvroStorage`将数据从 Pig 的数据模型转换为指定的 Avro 模式。

+   **使用作业的 Kafka OutputFormat 类**：在这种方法中，Kafka 的`OutputFormat`类（它扩展了 Hadoop 的`OutputFormat`类）用于将数据发布到 Kafka 集群。使用 0.20 MapReduce API，这种方法将消息作为字节发布，并通过使用低级别的发布方法来控制输出。Kafka 的`OutputFormat`类使用`KafkaRecordWriter`类（它扩展了 Hadoop 的`RecordWriter`类）来将记录（消息）写入 Hadoop 集群。

对于 Kafka 生产者，我们还可以通过在作业配置中加上`kafka.output`前缀来配置 Kafka 生产者参数。例如，要更改压缩编解码器，添加`kafka.output.compression.codec`参数（例如，在 Pig 脚本中添加`SET kafka.output.compression.codec 0`表示不压缩）。除了这些值，Kafka 代理信息（`kafka.metadata.broker.list`）、主题（`kafka.output.topic`）和模式（`kafka.output.schema`）也被注入到作业的配置中。

## Hadoop 消费者

Hadoop 消费者是从 Kafka 代理中拉取数据并将其推送到 HDFS 的 Hadoop 作业。以下图表显示了 Kafka 消费者在架构模式中的位置：

![Hadoop 消费者](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/lrn-kafka-2e/img/3090OS_06_05.jpg)

一个 Hadoop 作业执行从 Kafka 到 HDFS 的并行加载，加载数据的 mapper 数量取决于输入目录中文件的数量。输出目录包含来自 Kafka 的数据和更新的主题偏移量。单独的 mapper 在 map 任务结束时将最后消费的消息的偏移量写入 HDFS。如果作业失败并且作业重新启动，每个 mapper 都会从 HDFS 中存储的偏移量重新启动。

`Kafka-0.8.1.1-src/contrib/hadoop-consumer`目录中提供的 ETL 示例演示了从 Kafka 中提取数据并将其加载到 HDFS。例如，它需要来自配置文件的以下输入，例如`test/test.properties`：

+   `kafka.etl.topic`：要获取的主题。

+   `kafka.server.uri`：Kafka 服务器 URI。

+   `input`：包含由`DataGenerator`生成的主题偏移量的输入目录。此目录中的文件数量决定了 Hadoop 作业中的 mapper 数量。

+   `output`：包含 Kafka 数据和更新的主题偏移量的输出目录。

+   `kafka.request.limit`：用于限制获取的事件数量。

在卡夫卡消费者中，`KafkaETLRecordReader`实例是与`KafkaETLInputFormat`相关联的记录读取器。它从服务器获取卡夫卡数据，从提供的偏移量（由`input`指定）开始，并在达到最大可用偏移量或指定限制（由`kafka.request.limit`指定）时停止。`KafkaETLJob`还包含一些辅助函数来初始化作业配置，`SimpleKafkaETLJob`设置作业属性并提交 Hadoop 作业。一旦作业启动，`SimpleKafkaETLMapper`将卡夫卡数据转储到 HDFS（由`output`指定）。

# 摘要

在本章中，我们主要学习了卡夫卡如何与现有的开源框架在实时/批处理数据处理领域集成。在实时数据处理领域，卡夫卡与使用现有的 Storm spout 的 Storm 集成。至于批处理数据处理，卡夫卡带来了基于 Hadoop 的数据生产者和消费者，使数据可以发布到 HDFS，使用 MapReduce 进行处理，然后消费。

在下一章中，也是本书的最后一章，我们将看一些关于卡夫卡的其他重要事实。
