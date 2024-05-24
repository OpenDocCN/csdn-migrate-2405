# 精通 Storm（一）

> 原文：[`zh.annas-archive.org/md5/5A2D98C1AAE9E2E2F9D015883F441239`](https://zh.annas-archive.org/md5/5A2D98C1AAE9E2E2F9D015883F441239)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

实时数据处理不再是少数大公司的奢侈品，而已经成为希望竞争的企业的必需品，而 Apache Storm 是开发实时处理管道的事实标准之一。Storm 的关键特性是它具有水平可扩展性，容错性，并提供了保证的消息处理。Storm 可以解决各种类型的分析问题：机器学习、日志处理、图分析等。

精通 Storm 将作为一本*入门指南*，面向经验不足的开发人员，也是有经验的开发人员实施高级用例的参考。在前两章中，您将学习 Storm 拓扑的基础知识和 Storm 集群的各种组件。在后面的章节中，您将学习如何构建一个可以与各种其他大数据技术进行交互的 Storm 应用程序，以及如何创建事务性拓扑。最后，最后两章涵盖了日志处理和机器学习的案例研究。我们还将介绍如何使用 Storm 调度程序将精细的工作分配给精细的机器。

# 本书涵盖内容

第一章，*实时处理和 Storm 介绍*，介绍了 Storm 及其组件。

第二章，*Storm 部署、拓扑开发和拓扑选项*，涵盖了将 Storm 部署到集群中，在 Storm 集群上部署示例拓扑，以及如何使用 Storm UI 监视 storm 管道以及如何动态更改日志级别设置。

第三章，*Storm 并行性和数据分区*，涵盖了拓扑的并行性，如何在代码级别配置并行性，保证消息处理以及 Storm 内部生成的元组。

第四章，*Trident 介绍*，介绍了 Trident 的概述，对 Trident 数据模型的理解，以及如何编写 Trident 过滤器和函数。本章还涵盖了 Trident 元组上的重新分区和聚合操作。

第五章，*Trident 拓扑和用途*，介绍了 Trident 元组分组、非事务性拓扑和一个示例 Trident 拓扑。该章还介绍了 Trident 状态和分布式 RPC。

第六章，*Storm 调度程序*，介绍了 Storm 中可用的不同类型的调度程序：默认调度程序、隔离调度程序、资源感知调度程序和自定义调度程序。

第七章，*Storm 集群的监控*，涵盖了通过编写使用 Nimbus 发布的统计信息的自定义监控 UI 来监控 Storm。我们解释了如何使用 JMXTrans 将 Ganglia 与 Storm 集成。本章还介绍了如何配置 Storm 以发布 JMX 指标。

第八章，*Storm 和 Kafka 的集成*，展示了 Storm 与 Kafka 的集成。本章从 Kafka 的介绍开始，涵盖了 Storm 的安装，并以 Storm 与 Kafka 的集成来解决任何实际问题。

第九章，*Storm 和 Hadoop 集成*，概述了 Hadoop，编写 Storm 拓扑以将数据发布到 HDFS，Storm-YARN 的概述，以及在 YARN 上部署 Storm 拓扑。

第十章，*Storm 与 Redis、Elasticsearch 和 HBase 集成*，教您如何将 Storm 与各种其他大数据技术集成。

第十一章，*使用 Storm 进行 Apache 日志处理*，介绍了一个示例日志处理应用程序，其中我们解析 Apache Web 服务器日志并从日志文件中生成一些业务信息。

第十二章，*Twitter 推文收集和机器学习*，将带您完成一个案例研究，实现了 Storm 中的机器学习拓扑。

# 您需要为这本书做好准备

本书中的所有代码都在 CentOS 6.5 上进行了测试。它也可以在其他 Linux 和 Windows 变体上运行，只需在命令中进行适当的更改。

我们已经尝试使各章节都是独立的，并且每章中都包括了该章节中使用的所有软件的设置和安装。这些是本书中使用的软件包：

+   CentOS 6.5

+   Oracle JDK 8

+   Apache ZooKeeper 3.4.6

+   Apache Storm 1.0.2

+   Eclipse 或 Spring Tool Suite

+   Elasticsearch 2.4.4

+   Hadoop 2.2.2

+   Logstash 5.4.1

+   Kafka 0.9.0.1

+   Esper 5.3.0

# 这本书是为谁写的

如果您是一名 Java 开发人员，并且渴望进入使用 Apache Storm 进行实时流处理应用的世界，那么这本书适合您。本书从基础知识开始，不需要之前在 Storm 方面的经验。完成本书后，您将能够开发不太复杂的 Storm 应用程序。

# 约定

在本书中，您将找到许多文本样式，用于区分不同类型的信息。以下是一些这些样式的示例及其含义的解释。文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下：“在 Nimbus 机器的 `storm.yaml` 文件中添加以下行以在 Nimbus 节点上启用 JMX。”

代码块设置如下：

```scala
<dependency>
  <groupId>org.apache.storm</groupId>
  <artifactId>storm-core</artifactId>
  <version>1.0.2</version>
  <scope>provided<scope>
</dependency>
```

任何命令行输入或输出都将按如下方式编写：

```scala
cd $ZK_HOME/conf touch zoo.cfg
```

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的单词，例如菜单或对话框中的单词，会在文本中显示为：“现在，单击“连接”按钮以查看监督节点的指标。”

警告或重要说明看起来像这样。

技巧和窍门看起来像这样。


# 第一章：实时处理和 Storm 介绍

随着生成的数据量呈指数级增长和先进的数据捕获能力，企业面临着从这些海量原始数据中获取信息的挑战。在批处理方面，Hadoop 已成为处理大数据的首选框架。直到最近，当人们寻找构建实时流处理应用程序的框架时，一直存在空白。这些应用程序已成为许多企业的重要组成部分，因为它们使企业能够迅速响应事件并适应不断变化的情况。其例子包括监视社交媒体以分析公众对您推出的任何新产品的反应，并根据与选举相关的帖子的情绪来预测选举结果。

组织正在从外部来源收集大量数据，并希望实时评估/处理数据以获取市场趋势、检测欺诈、识别用户行为等。实时处理的需求日益增加，我们需要一个支持以下功能的实时系统/平台：

+   **可扩展**：平台应具有水平可扩展性，无需任何停机时间。

+   **容错性**：即使集群中的一些节点出现故障，平台也应能够处理数据。

+   **无数据丢失**：平台应提供消息的可靠处理。

+   **高吞吐量**：系统应能够支持每秒数百万条记录，并支持任何大小的消息。

+   **易于操作**：系统应具有易于安装和操作的特点。此外，集群的扩展应是一个简单的过程。

+   **多语言**：平台应支持多种语言。最终用户应能够用不同的语言编写代码。例如，用户可以用 Python、Scala、Java 等编写代码。此外，我们可以在一个集群中执行不同语言的代码。

+   **集群隔离**：系统应支持隔离，以便为处理分配专用进程到专用机器。

# Apache Storm

Apache Storm 已成为行业领袖开发分布式实时数据处理平台的首选平台。它提供了一组原语，可用于开发可以高度可扩展地实时处理大量数据的应用程序。

风暴对实时处理就像 Hadoop 对批处理一样重要。它是开源软件，由 Apache 软件基金会管理。它已经被 Twitter、Yahoo!和 Flipboard 等公司部署，以满足实时处理的需求。Storm 最初是由 BackType 的 Nathan Marz 开发的，BackType 是一家提供社交搜索应用的公司。后来，BackType 被 Twitter 收购，成为其基础设施的关键部分。Storm 可以用于以下用例：

+   **流处理**：Storm 用于处理数据流并实时更新各种数据库。这种处理是实时的，处理速度需要与输入数据速度匹配。

+   **持续计算**：Storm 可以对数据流进行持续计算，并实时将结果传输给客户端。这可能需要在每条消息到达时进行处理，或者在短时间内创建小批处理。持续计算的一个例子是将 Twitter 上的热门话题流式传输到浏览器中。

+   **分布式 RPC**：Storm 可以并行处理复杂查询，以便您可以实时计算它。

+   **实时分析**：Storm 可以分析并响应来自不同数据源的实时数据。

在本章中，我们将涵盖以下主题：

+   什么是 Storm？

+   Storm 的特点

+   Storm 集群的架构和组件

+   Storm 的术语

+   编程语言

+   操作模式

# Storm 的特点

以下是一些使 Storm 成为实时处理数据流的完美解决方案的特点：

+   **快速**：据报道，Storm 每个节点每秒可以处理高达 100 万个元组/记录。

+   **横向可扩展**：快速是构建高容量/高速数据处理平台的必要特性，但单个节点对其每秒处理事件数量有上限。节点代表设置中的单台机器，执行 Storm 应用程序。作为分布式平台，Storm 允许您向 Storm 集群添加更多节点，并增加应用程序的处理能力。此外，它是线性可扩展的，这意味着通过增加节点可以使处理能力加倍。

+   **容错**：Storm 集群中的工作单元由工作进程执行。当工作进程死掉时，Storm 将重新启动该工作进程，如果运行该工作进程的节点死掉，Storm 将在集群中的其他节点上重新启动该工作进程。这个特性将在第三章中详细介绍，*Storm 并行性和数据分区*。

+   **数据处理保证**：Storm 提供强有力的保证，即进入 Storm 进程的每条消息至少会被处理一次。在发生故障时，Storm 将重放丢失的元组/记录。此外，它可以配置为每条消息只被处理一次。

+   **易于操作**：Storm 部署和管理都很简单。一旦部署了集群，就需要很少的维护。

+   **编程语言无关**：尽管 Storm 平台在**Java 虚拟机**（**JVM**）上运行，但在其上运行的应用程序可以用任何能够读写标准输入和输出流的编程语言编写。

# Storm 组件

Storm 集群遵循主从模型，其中主和从进程通过 ZooKeeper 协调。以下是 Storm 集群的组件。

# Nimbus

Nimbus 节点是 Storm 集群中的主节点。它负责在各个工作节点之间分发应用程序代码，将任务分配给不同的机器，监视任务是否出现故障，并在需要时重新启动它们。

Nimbus 是无状态的，它将所有数据存储在 ZooKeeper 中。在 Storm 集群中只有一个 Nimbus 节点。如果活动节点宕机，那么备用节点将成为活动节点。它被设计为快速失败，因此当活动 Nimbus 宕机时，备用节点将成为活动节点，或者宕机的节点可以重新启动而不会对工作节点上已经运行的任务产生任何影响。这与 Hadoop 不同，如果 JobTracker 宕机，所有正在运行的作业都会处于不一致状态，需要重新执行。即使所有 Nimbus 节点都宕机，Storm 工作节点也可以正常工作，但用户无法向集群提交任何新作业，或者集群将无法重新分配失败的工作节点到另一个节点。

# 主管节点

主管节点是 Storm 集群中的工作节点。每个主管节点运行一个主管守护进程，负责创建、启动和停止工作进程以执行分配给该节点的任务。与 Nimbus 一样，主管守护进程也是快速失败的，并将其所有状态存储在 ZooKeeper 中，以便可以在不丢失状态的情况下重新启动。通常，单个主管守护进程会处理在该机器上运行的多个工作进程。

# ZooKeeper 集群

在任何分布式应用程序中，各种进程需要相互协调并共享一些配置信息。ZooKeeper 是一个应用程序，以可靠的方式提供所有这些服务。作为一个分布式应用程序，Storm 也使用 ZooKeeper 集群来协调各种进程。与 ZooKeeper 中的所有状态和提交给 Storm 的各种任务相关的所有数据都存储在 ZooKeeper 中。Nimbus 和监督节点不直接相互通信，而是通过 ZooKeeper。由于所有数据都存储在 ZooKeeper 中，因此 Nimbus 和监督守护程序都可以突然被杀死而不会对集群产生不利影响。

以下是一个 Storm 集群的架构图：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-storm/img/00005.jpeg)

# Storm 数据模型

Storm 应用程序可以处理的基本数据单元称为元组。每个元组由预定义的字段列表组成。每个字段的值可以是字节、字符、整数、长整数、浮点数、双精度浮点数、布尔值或字节数组。Storm 还提供了一个 API 来定义自己的数据类型，这些数据类型可以作为元组中的字段进行序列化。

元组是动态类型的，也就是说，您只需要定义元组中字段的名称而不需要它们的数据类型。动态类型的选择有助于简化 API 并使其易于使用。此外，由于 Storm 中的处理单元可以处理多种类型的元组，因此声明字段类型并不实际。

元组中的每个字段都可以通过其名称`getValueByField(String)`或其位置索引`getValue(int)`来访问。元组还提供了方便的方法，例如`getIntegerByField(String)`，可以使您免于对对象进行类型转换。例如，如果您有一个表示分数的*Fraction (numerator, denominator)*元组，那么您可以通过使用`getIntegerByField("numerator")`或`getInteger(0)`来获取分子的值。

您可以在位于[`storm.apache.org/releases/1.0.2/javadocs/org/apache/storm/tuple/Tuple.html`](https://storm.apache.org/releases/1.0.2/javadocs/org/apache/storm/tuple/Tuple.html)的 Java 文档中查看`org.apache.storm.tuple.Tuple`支持的完整操作集。

# Storm 拓扑的定义

在 Storm 术语中，拓扑是定义计算图的抽象。您可以创建一个 Storm 拓扑并将其部署到 Storm 集群中以处理数据。拓扑可以用有向无环图表示，其中每个节点都进行某种处理并将其转发到流程中的下一个节点。以下图是一个示例 Storm 拓扑：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-storm/img/00006.jpeg)

以下是 Storm 拓扑的组件：

+   **Tuple**：在拓扑的不同实例之间流动的单个消息/记录称为元组。

+   **Stream**：Storm 中的关键抽象是流。流是一系列可以由 Storm 并行处理的元组。每个流可以由单个或多个类型的 bolt（Storm 中的处理单元，在本节后面定义）并行处理。因此，Storm 也可以被视为转换流的平台。在前面的图中，流用箭头表示。Storm 应用程序中的每个流都被赋予一个 ID，bolt 可以根据其 ID 从这些流中产生和消费元组。每个流还有一个与其流经的元组相关的模式。

+   **Spout**：Spout 是 Storm 拓扑中元组的来源。它负责从外部来源读取或监听数据，例如从日志文件中读取或监听队列中的新消息并发布它们--在 Storm 术语中发射到流中。Spout 可以发射多个流，每个流具有不同的模式。例如，它可以从日志文件中读取包含 10 个字段的记录，并将它们作为包含七个字段元组和四个字段元组的不同流发射出去。

`org.apache.storm.spout.ISpout`接口是用于定义喷口的接口。如果您在 Java 中编写拓扑，则应使用`org.apache.storm.topology.IRichSpout`，因为它声明了与`TopologyBuilder`API 一起使用的方法。每当喷口发射一个元组时，Storm 会跟踪处理此元组时生成的所有元组，当源元组的图中所有元组的执行完成时，它将向喷口发送确认。只有在发射元组时提供了消息 ID 时才会发生此跟踪。如果使用 null 作为消息 ID，则不会发生此跟踪。

还可以为拓扑定义元组处理超时，如果元组在指定的超时时间内未被处理，将向喷口发送失败消息。再次强调，只有在定义消息 ID 时才会发生这种情况。通过跳过发射元组时的消息 ID 来禁用消息确认，可以从 Storm 中获得一些小的性能提升，但也会有一些数据丢失的风险。

喷口的重要方法有：

+   +   `nextTuple()`: Storm 调用此方法从输入源获取下一个元组。在此方法内部，您将具有从外部源读取数据并将其发射到`org.apache.storm.spout.ISpoutOutputCollector`实例的逻辑。可以使用`org.apache.storm.topology.OutputFieldsDeclarer`的`declareStream`方法声明流的模式。

如果喷口希望向多个流发射数据，可以使用`declareStream`方法声明多个流，并在发射元组时指定流 ID。如果此时没有更多的元组要发射，此方法将不会被阻塞。此外，如果此方法不发射元组，则 Storm 将在再次调用它之前等待 1 毫秒。可以使用`topology.sleep.spout.wait.strategy.time.ms`设置来配置此等待时间。

+   +   `ack(Object msgId)`: 当具有给定消息 ID 的元组被拓扑完全处理时，Storm 将调用此方法。在这一点上，用户应标记消息已处理，并进行必要的清理，例如从消息队列中删除消息，以便不再处理它。

+   `fail(Object msgId)`: 当 Storm 识别出具有给定消息 ID 的元组未能成功处理或超时配置的时间间隔时，将调用此方法。在这种情况下，用户应进行必要的处理，以便通过`nextTuple`方法再次发射消息。一个常见的做法是将消息放回传入消息队列。

+   `open()`: 当喷口初始化时，只调用一次此方法。如果需要连接到外部源以获取输入数据，应在 open 方法中定义连接到外部源的逻辑，然后在`nextTuple`方法中不断从外部源获取数据以进一步发射它。

在编写喷口时需要注意的另一点是，不能阻塞任何方法，因为 Storm 在同一线程中调用所有方法。每个喷口都有一个内部缓冲区，用于跟踪到目前为止发射的元组的状态。喷口将保留这些元组在缓冲区中，直到它们被确认或失败，分别调用`ack`或`fail`方法。只有当此缓冲区不满时，Storm 才会调用`nextTuple`方法。

+   **Bolt**: 一个 bolt 是 Storm 拓扑的处理引擎，负责转换流。理想情况下，拓扑中的每个 bolt 都应该对元组进行简单的转换，许多这样的 bolt 可以相互协调，展示复杂的转换。

`org.apache.storm.task.IBolt`接口通常用于定义 bolt，如果拓扑是用 Java 编写的，则应该使用`org.apache.storm.topology.IRichBolt`接口。Bolt 可以订阅拓扑中其他组件（spouts 或其他 bolts）的多个流，同样也可以向多个流发出输出。可以使用`org.apache.storm.topology.OutputFieldsDeclarer`的`declareStream`方法声明输出流。

一个 bolt 的重要方法有：

+   +   `execute(Tuple input)`: 对于通过订阅的输入流传入的每个元组，将执行此方法。在此方法中，您可以对元组进行所需的任何处理，然后以发出更多元组到声明的输出流的形式，或者其他操作，比如将结果持久化到数据库。

在调用此方法时，您不需要立即处理元组，可以将元组保留直到需要。例如，在连接两个流时，当一个元组到达时，您可以将其保留，直到其对应的元组也到达，然后您可以发出连接的元组。

与元组相关的元数据可以通过`Tuple`接口中定义的各种方法来检索。如果元组关联了消息 ID，则 execute 方法必须使用`OutputCollector`为 bolt 发布`ack`或`fail`事件，否则 Storm 将不知道元组是否被成功处理。`org.apache.storm.topology.IBasicBolt`接口是一个方便的接口，在 execute 方法完成后会自动发送确认。如果要发送失败事件，此方法应该抛出`org.apache.storm.topology.FailedException`。

+   +   `prepare(Map stormConf, TopologyContext context, OutputCollector collector)`: 在 Storm 拓扑中，一个 bolt 可以由多个 worker 执行。Bolt 的实例在客户端机器上创建，然后序列化并提交给 Nimbus。当 Nimbus 为拓扑创建 worker 实例时，它会将这个序列化的 bolt 发送给 worker。worker 将解序列化 bolt 并调用`prepare`方法。在这个方法中，您应该确保 bolt 被正确配置以执行元组。您希望保持的任何状态可以存储为 bolt 的实例变量，稍后可以进行序列化/反序列化。

# Storm 中的操作模式

操作模式指示了拓扑在 Storm 中的部署方式。Storm 支持两种类型的操作模式来执行 Storm 拓扑：

+   **本地模式**：在本地模式下，Storm 拓扑在单个 JVM 中在本地机器上运行。这种模式模拟了单个 JVM 中的 Storm 集群，并用于拓扑的测试和调试。

+   **远程模式**：在远程模式下，我们将使用 Storm 客户端将拓扑提交给主节点，以及执行拓扑所需的所有必要代码。Nimbus 将负责分发您的代码。

在下一章中，我们将更详细地介绍本地模式和远程模式，以及一个示例。

# 编程语言

Storm 从一开始就被设计为可用于任何编程语言。Storm 的核心是用于定义和提交拓扑的 thrift 定义。由于 thrift 可以在任何语言中使用，因此可以用任何语言定义和提交拓扑。

同样，spouts 和 bolts 可以用任何语言定义。非 JVM spouts 和 bolts 通过`stdin`/`stdout`上的基于 JSON 的协议与 Storm 通信。实现这种协议的适配器存在于 Ruby、Python、JavaScript 和 Perl 中。您可以参考[`github.com/apache/storm/tree/master/storm-multilang`](https://github.com/apache/storm/tree/master/storm-multilang)了解这些适配器的实现。

Storm-starter 有一个示例拓扑，[`github.com/apache/storm/tree/master/examples/storm-starter/multilang/resources`](https://github.com/apache/storm/tree/master/examples/storm-starter/multilang/resources)，其中使用 Python 实现了其中一个 bolt。

# 总结

在本章中，我们向您介绍了 Storm 的基础知识以及构成 Storm 集群的各种组件。我们看到了 Storm 集群可以操作的不同部署/运行模式的定义。

在下一章中，我们将建立一个单节点和三节点的 Storm 集群，并看看如何在 Storm 集群上部署拓扑。我们还将看到 Storm 支持的不同类型的流分组以及 Storm 提供的消息语义保证。


# 第二章：Storm 部署、拓扑开发和拓扑选项

本章中，我们将从在多个节点（三个 Storm 和三个 ZooKeeper）集群上部署 Storm 开始。这一章非常重要，因为它关注了我们如何设置生产 Storm 集群以及为什么我们需要 Storm Supervisor、Nimbus 和 ZooKeeper 的高可用性（因为 Storm 使用 ZooKeeper 来存储集群、拓扑等元数据）。

以下是本章将要涵盖的关键点：

+   Storm 集群的部署

+   程序和部署词频统计示例

+   Storm UI 的不同选项——kill、active、inactive 和 rebalance

+   Storm UI 的演练

+   动态日志级别设置

+   验证 Nimbus 的高可用性

# Storm 的先决条件

在开始部署 Storm 集群之前，您应该安装 Java JDK 和 ZooKeeper 集群。

# 安装 Java SDK 7

执行以下步骤在您的机器上安装 Java SDK 7。您也可以选择 JDK 1.8：

1.  从 Oracle 网站（[`www.oracle.com/technetwork/java/javase/downloads/index.html`](http://www.oracle.com/technetwork/java/javase/downloads/index.html)）下载 Java SDK 7 RPM。

1.  使用以下命令在您的 CentOS 机器上安装 Java `jdk-7u<version>-linux-x64.rpm`文件：

```scala
sudo rpm -ivh jdk-7u<version>-linux-x64.rpm 
```

1.  在`~/.bashrc`文件中添加以下环境变量：

```scala
export JAVA_HOME=/usr/java/jdk<version>
```

1.  将 JDK 的`bin`目录的路径添加到`PATH`系统环境变量中，添加到`~/.bashrc`文件中：

```scala
export PATH=$JAVA_HOME/bin:$PATH 
```

1.  运行以下命令在当前登录终端重新加载`bashrc`文件：

```scala
source ~/.bashrc
```

1.  检查 Java 安装如下：

```scala
java -version  
```

上述命令的输出如下：

```scala
java version "1.7.0_71"
Java(TM) SE Runtime Environment (build 1.7.0_71-b14)
Java HotSpot(TM) 64-Bit Server VM (build 24.71-b01, mixed mode) 
```

# ZooKeeper 集群的部署

在任何分布式应用程序中，各种进程需要相互协调并共享配置信息。ZooKeeper 是一个应用程序，以可靠的方式提供所有这些服务。作为一个分布式应用程序，Storm 也使用 ZooKeeper 集群来协调各种进程。与集群相关的所有状态和提交给 Storm 的各种任务都存储在 ZooKeeper 中。本节描述了如何设置 ZooKeeper 集群。我们将部署一个由三个节点组成的 ZooKeeper 集群，可以处理一个节点故障。以下是三个节点 ZooKeeper 集群的部署图：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-storm/img/00007.jpeg)

在 ZooKeeper 集群中，集群中的一个节点充当领导者，而其余的节点充当跟随者。如果 ZooKeeper 集群的领导者节点死亡，那么在剩余的活动节点中进行新的领导者选举，并选举出一个新的领导者。来自客户端的所有写请求都会被转发到领导者节点，而跟随者节点只处理读请求。此外，我们无法通过增加节点数量来增加 ZooKeeper 集合的写性能，因为所有写操作都经过领导者节点。

建议运行奇数个 ZooKeeper 节点，因为只要大多数节点（活动节点数大于*n/2*，其中*n*为部署节点数）在运行，ZooKeeper 集群就会继续工作。因此，如果我们有一个由四个 ZooKeeper 节点组成的集群（*3 > 4/2*；只能有一个节点死亡），那么我们只能处理一个节点故障，而如果我们在集群中有五个节点（*3 > 5/2*；可以处理两个节点故障），那么我们可以处理两个节点故障。

步骤 1 到 4 需要在每个节点上执行以部署 ZooKeeper 集群：

1.  从 ZooKeeper 网站（[`zookeeper.apache.org/releases.html`](http://zookeeper.apache.org/releases.html)）下载最新的稳定 ZooKeeper 版本。在撰写本文时，最新版本是 ZooKeeper 3.4.6。

1.  一旦你下载了最新版本，解压它。现在，我们设置`ZK_HOME`环境变量以使设置更容易。

1.  将`ZK_HOME`环境变量指向解压后的目录。使用以下命令在`$ZK_HOME/conf`目录中创建配置文件`zoo.cfg`：

```scala
cd $ZK_HOME/conf 
touch zoo.cfg 
```

1.  将以下属性添加到`zoo.cfg`文件中：

```scala
tickTime=2000 
dataDir=/var/zookeeper 
clientPort=2181 
initLimit=5 
syncLimit=2 
server.1=zoo1:2888:3888 
server.2=zoo2:2888:3888 
server.3=zoo3.2888.3888  
```

这里，`zoo1`、`zoo2`和`zoo3`是 ZooKeeper 节点的 IP 地址。以下是每个属性的定义：

+   +   `tickTime`：这是 ZooKeeper 中以毫秒为单位使用的基本时间单位。它用于发送心跳，最小会话超时将是`tickTime`值的两倍。

+   `dataDir`：这是用于存储内存数据库快照和事务日志的目录。

+   `clientPort`：这是用于监听客户端连接的端口。

+   `initLimit`：这是允许跟随者连接和同步到领导者节点所需的`tickTime`值的数量。

+   `syncLimit`：这是一个跟随者可以用来与领导者节点同步的`tickTime`值的数量。如果同步在此时间内未发生，跟随者将从集合中删除。

`server.id=host:port:port`格式的最后三行指定了集群中有三个节点。在集合中，每个 ZooKeeper 节点必须具有 1 到 255 之间的唯一 ID 号。通过在每个节点的`dataDir`目录中创建名为`myid`的文件来定义此 ID。例如，ID 为 1 的节点（`server.1=zoo1:2888:3888`）将在目录`/var/zookeeper`中具有一个`myid`文件，其中包含`1`。

对于此集群，在三个位置创建`myid`文件，如下所示：

```scala
At zoo1 /var/zookeeper/myid contains 1 
At zoo2 /var/zookeeper/myid contains 2 
At zoo3 /var/zookeeper/myid contains 3  
```

1.  在每台机器上运行以下命令以启动 ZooKeeper 集群：

```scala
bin/zkServer.sh start  
```

通过执行以下步骤检查 ZooKeeper 节点的状态：

1.  在`zoo1`节点上运行以下命令以检查第一个节点的状态：

```scala
bin/zkServer.sh status 
```

以下信息显示：

```scala
JMX enabled by default 
Using config: /home/root/zookeeper-3.4.6/bin/../conf/zoo.cfg 
Mode: follower   
```

第一个节点以`follower`模式运行。

1.  通过执行以下命令检查第二个节点的状态：

```scala
bin/zkServer.sh status  
```

以下信息显示：

```scala
JMX enabled by default 
Using config: /home/root/zookeeper-3.4.6/bin/../conf/zoo.cfg 
Mode: leader  
```

第二个节点以`leader`模式运行。

1.  通过执行以下命令检查第三个节点的状态：

```scala
bin/zkServer.sh status

```

以下信息显示：

```scala
JMX enabled by default 
Using config: /home/root/zookeeper-3.4.6/bin/../conf/zoo.cfg 
Mode: follower  
```

第三个节点以`follower`模式运行。

1.  在领导者机器上运行以下命令以停止领导者节点：

```scala
bin/zkServer.sh stop  
```

现在，通过执行以下步骤检查剩余两个节点的状态：

1.  使用以下命令检查第一个节点的状态：

```scala
bin/zkServer.sh status  
```

以下信息显示：

```scala
JMX enabled by default 
Using config: /home/root/zookeeper-3.4.6/bin/../conf/zoo.cfg 
Mode: follower   
```

第一个节点再次以`follower`模式运行。

1.  使用以下命令检查第二个节点的状态：

```scala
bin/zkServer.sh status   
```

以下信息显示：

```scala
JMX enabled by default 
Using config: /home/root/zookeeper-3.4.6/bin/../conf/zoo.cfg 
Mode: leader  
```

第三个节点被选举为新的领导者。

1.  现在，使用以下命令重新启动第三个节点：

```scala
bin/zkServer.sh status  
```

这是一个快速介绍，介绍了如何设置 ZooKeeper，可用于开发；但是，不适合生产。有关 ZooKeeper 管理和维护的完整参考，请参阅 ZooKeeper 网站上的在线文档[`zookeeper.apache.org/doc/trunk/zookeeperAdmin.html`](http://zookeeper.apache.org/doc/trunk/zookeeperAdmin.html)。

# 设置 Storm 集群

在本章中，我们将学习如何设置一个三节点 Storm 集群，其中一个节点将是活动的主节点（Nimbus），另外两个将是工作节点（supervisors）。

以下是我们三个节点 Storm 集群的部署图：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-storm/img/00008.gif)

以下是设置三节点 Storm 集群所需执行的步骤：

1.  安装并运行 ZooKeeper 集群。有关安装 ZooKeeper 的步骤在前一节中提到。

1.  从[`storm.apache.org/downloads.html`](https://storm.apache.org/downloads.html)下载最新稳定的 Storm 版本；在撰写本文时，最新版本是 Storm 1.0.2。

1.  一旦你下载了最新版本，在所有三台机器上复制并解压。现在，我们将在每台机器上设置`$STORM_HOME`环境变量，以便更轻松地进行设置。`$STORM_HOME`环境变量包含 Storm `home`文件夹的路径（例如，导出`STORM_HOME=/home/user/storm-1.0.2`）。

1.  在主节点的`$STORM_HOME/conf`目录中，向`storm.yaml`文件添加以下行：

```scala
storm.zookeeper.servers: 
- "zoo1" 
- "zoo2" 
- "zoo3" 
storm.zookeeper.port: 2181 
nimbus.seeds: "nimbus1,nimbus2" 
storm.local.dir: "/tmp/storm-data"  
```

我们正在安装两个主节点。

1.  在每个工作节点的`$STORM_HOME/conf`目录中，向`storm.yaml`文件添加以下行：

```scala
storm.zookeeper.servers: 
- "zoo1" 
- "zoo2" 
- "zoo3" 
storm.zookeeper.port: 2181 
nimbus.seeds: "nimbus1,nimbus2" 
storm.local.dir: "/tmp/storm-data" 
supervisor.slots.ports: 
- 6700 
- 6701 
- 6702 
- 6703  
```

如果你计划在同一台机器上执行 Nimbus 和 supervisor，则也在 Nimbus 机器上添加`supervisor.slots.ports`属性。

1.  在主节点的`$STORM_HOME`目录中执行以下命令来启动主守护进程：

```scala
$> bin/storm nimbus &  
```

1.  在每个工作节点（或 supervisor 节点）的`$STORM_HOME`目录中执行以下命令来启动工作守护进程：

```scala
$> bin/storm supervisor &  
```

# 开发 hello world 示例

在开始开发之前，你应该在你的项目中安装 Eclipse 和 Maven。这里解释的样本拓扑将涵盖如何创建一个基本的 Storm 项目，包括一个 spout 和 bolt，以及如何构建和执行它们。

通过使用`com.stormadvance`作为`groupId`和`storm-example`作为`artifactId`创建一个 Maven 项目。

在`pom.xml`文件中添加以下 Maven 依赖项：

```scala
<dependency> 
  <groupId>org.apache.storm</groupId> 
  <artifactId>storm-core</artifactId> 
  <version>1.0.2</version> 
  <scope>provided<scope> 
</dependency> 
```

确保 Storm 依赖的范围是提供的，否则你将无法在 Storm 集群上部署拓扑。

在`pom.xml`文件中添加以下 Maven `build`插件：

```scala
<build> 
  <plugins> 
    <plugin> 
      <artifactId>maven-assembly-plugin</artifactId> 
      <version>2.2.1</version> 
      <configuration> 
        <descriptorRefs> 
          <descriptorRef>jar-with-dependencies 
          </descriptorRef> 
        </descriptorRefs> 
        <archive> 
          <manifest> 
            <mainClass /> 
          </manifest> 
        </archive> 
      </configuration> 
      <executions> 
        <execution> 
          <id>make-assembly</id> 
          <phase>package</phase> 
          <goals> 
            <goal>single</goal> 
          </goals> 
        </execution> 
      </executions> 
    </plugin> 
  </plugins> 
</build> 
```

通过在`com.stormadvance.storm_example`包中创建`SampleSpout`类来编写你的第一个样本 spout。`SampleSpout`类扩展了序列化的`BaseRichSpout`类。这个 spout 不连接到外部源来获取数据，而是随机生成数据并发出连续的记录流。以下是`SampleSpout`类的源代码及其解释：

```scala
public class SampleSpout extends BaseRichSpout { 
  private static final long serialVersionUID = 1L; 

  private static final Map<Integer, String> map = new HashMap<Integer, String>(); 
  static { 
    map.put(0, "google"); 
    map.put(1, "facebook"); 
    map.put(2, "twitter"); 
    map.put(3, "youtube"); 
    map.put(4, "linkedin"); 
  } 
  private SpoutOutputCollector spoutOutputCollector; 

  public void open(Map conf, TopologyContext context, SpoutOutputCollector spoutOutputCollector) { 
    // Open the spout 
    this.spoutOutputCollector = spoutOutputCollector; 
  } 

  public void nextTuple() { 
    // Storm cluster repeatedly calls this method to emita continuous 
    // stream of tuples. 
    final Random rand = new Random(); 
    // generate the random number from 0 to 4\. 
    int randomNumber = rand.nextInt(5); 
    spoutOutputCollector.emit(new Values(map.get(randomNumber))); 
    try{ 
      Thread.sleep(5000); 
    }catch(Exception e) { 
      System.out.println("Failed to sleep the thread"); 
    } 
  } 

  public void declareOutputFields(OutputFieldsDeclarer declarer) { 

  // emit the tuple with field "site" 
  declarer.declare(new Fields("site")); 
  } 
} 
```

通过在同一包中创建`SampleBolt`类来编写你的第一个样本 bolt。`SampleBolt`类扩展了序列化的`BaseRichBolt`类。这个 bolt 将消耗`SampleSpout` spout 发出的元组，并在控制台上打印`site`字段的值。以下是`SampleStormBolt`类的源代码及其解释：

```scala
public class SampleBolt extends BaseBasicBolt { 
  private static final long serialVersionUID = 1L; 

  public void execute(Tuple input, BasicOutputCollector collector) { 
    // fetched the field "site" from input tuple. 
    String test = input.getStringByField("site"); 
    // print the value of field "site" on console. 
    System.out.println("######### Name of input site is : " + test); 
  } 

  public void declareOutputFields(OutputFieldsDeclarer declarer) { 
  } 
} 
```

在同一包中创建一个主`SampleStormTopology`类。这个类创建了一个 spout 和 bolt 的实例以及类，并使用`TopologyBuilder`类将它们链接在一起。这个类使用`org.apache.storm.LocalCluster`来模拟 Storm 集群。`LocalCluster`模式用于在部署到 Storm 集群之前在开发者机器上进行调试/测试拓扑。以下是主类的实现：

```scala
public class SampleStormTopology { 
  public static void main(String[] args) throws AlreadyAliveException, InvalidTopologyException { 
    // create an instance of TopologyBuilder class 
    TopologyBuilder builder = new TopologyBuilder(); 
    // set the spout class 
    builder.setSpout("SampleSpout", new SampleSpout(), 2); 
    // set the bolt class 
    builder.setBolt("SampleBolt", new SampleBolt(), 4).shuffleGrouping("SampleSpout"); 
    Config conf = new Config(); 
    conf.setDebug(true); 
    // create an instance of LocalCluster class for 
    // executing topology in local mode. 
    LocalCluster cluster = new LocalCluster(); 
    // SampleStormTopology is the name of submitted topology 
    cluster.submitTopology("SampleStormTopology", conf, builder.createTopology()); 
    try { 
      Thread.sleep(100000); 
    } catch (Exception exception) { 
      System.out.println("Thread interrupted exception : " + exception); 
    } 
    // kill the SampleStormTopology 
    cluster.killTopology("SampleStormTopology"); 
    // shutdown the storm test cluster 
    cluster.shutdown(); 
  } 
} 
```

转到你的项目主目录，并运行以下命令以在本地模式下执行拓扑：

```scala
$> cd $STORM_EXAMPLE_HOME 
$> mvn compile exec:java -Dexec.classpathScope=compile -Dexec.mainClass=com.stormadvance.storm_example.SampleStormTopology 
```

现在为在实际 Storm 集群上部署拓扑创建一个新的拓扑类。在同一包中创建一个主`SampleStormClusterTopology`类。这个类还创建了一个 spout 和 bolt 的实例以及类，并使用`TopologyBuilder`类将它们链接在一起。

```scala
public class SampleStormClusterTopology { 
  public static void main(String[] args) throws AlreadyAliveException, InvalidTopologyException { 
    // create an instance of TopologyBuilder class 
    TopologyBuilder builder = new TopologyBuilder(); 
    // set the spout class 
    builder.setSpout("SampleSpout", new SampleSpout(), 2); 
    // set the bolt class 
    builder.setBolt("SampleBolt", new SampleBolt(), 4).shuffleGrouping("SampleSpout"); 
    Config conf = new Config(); 
    conf.setNumWorkers(3); 
    // This statement submit the topology on remote 
    // args[0] = name of topology 
    try { 
      StormSubmitter.submitTopology(args[0], conf, builder.createTopology()); 
    } catch (AlreadyAliveException alreadyAliveException) { 
      System.out.println(alreadyAliveException); 
    } catch (InvalidTopologyException invalidTopologyException) { 
      System.out.println(invalidTopologyException); 
    } catch (AuthorizationException e) { 
      // TODO Auto-generated catch block 
      e.printStackTrace(); 
    } 
  } 
} 
```

通过在项目的主目录上运行以下命令来构建你的 Maven 项目：

```scala
mvn clean install  
```

上述命令的输出如下：

```scala
    ------------------------------------------------------------------ ----- 
    [INFO] ----------------------------------------------------------- ----- 
    [INFO] BUILD SUCCESS 
    [INFO] ----------------------------------------------------------- ----- 
    [INFO] Total time: 58.326s 
    [INFO] Finished at: 
    [INFO] Final Memory: 14M/116M 
    [INFO] ----------------------------------------------------------- ----

```

我们可以使用以下 Storm 客户端命令将拓扑部署到集群：

```scala
bin/storm jar jarName.jar [TopologyMainClass] [Args] 
```

上述命令使用参数`arg1`和`arg2`运行`TopologyMainClass`。`TopologyMainClass`的主要功能是定义拓扑并将其提交到 Nimbus 机器。`storm jar`部分负责连接到 Nimbus 机器并上传 JAR 部分。

登录到 Storm Nimbus 机器并执行以下命令：

```scala
$> cd $STORM_HOME
$> bin/storm jar ~/storm_example-0.0.1-SNAPSHOT-jar-with-dependencies.jar com.stormadvance.storm_example.SampleStormClusterTopology storm_example  
```

在上述代码中，`~/storm_example-0.0.1-SNAPSHOT-jar-with-dependencies.jar`是我们在 Storm 集群上部署的`SampleStormClusterTopology` JAR 的路径。

显示以下信息：

```scala
702  [main] INFO  o.a.s.StormSubmitter - Generated ZooKeeper secret payload for MD5-digest: -8367952358273199959:-5050558042400210383
793  [main] INFO  o.a.s.s.a.AuthUtils - Got AutoCreds []
856  [main] INFO  o.a.s.StormSubmitter - Uploading topology jar /home/USER/storm_example-0.0.1-SNAPSHOT-jar-with-dependencies.jar to assigned location: /tmp/storm-data/nimbus/inbox/stormjar-d3007821-f87d-48af-8364-cff7abf8652d.jar
867  [main] INFO  o.a.s.StormSubmitter - Successfully uploaded topology jar to assigned location: /tmp/storm-data/nimbus/inbox/stormjar-d3007821-f87d-48af-8364-cff7abf8652d.jar
868  [main] INFO  o.a.s.StormSubmitter - Submitting topology storm_example in distributed mode with conf {"storm.zookeeper.topology.auth.scheme":"digest","storm.zookeeper.topology.auth.payload":"-8367952358273199959:-5050558042400210383","topology.workers":3}
 1007 [main] INFO  o.a.s.StormSubmitter - Finished submitting topology: storm_example  
```

运行`jps`命令，查看运行的 JVM 进程数量如下：

```scala
jps   
```

前面命令的输出是：

```scala
26827 worker 
26530 supervisor 
26824 worker 
26468 nimbus 
26822 worker  
```

在上述代码中，`worker`是为`SampleStormClusterTopology`拓扑启动的 JVM。

# Storm 拓扑的不同选项

此部分涵盖了用户可以在 Storm 集群上执行的以下操作：

+   停用

+   激活

+   重新平衡

+   杀死

+   动态日志级别设置

# 停用

Storm 支持停用拓扑。在停用状态下，spout 不会向管道中发射任何新的元组，但已经发射的元组的处理将继续。以下是停用运行中拓扑的命令：

```scala
$> bin/storm deactivate topologyName 
```

使用以下命令停用`SampleStormClusterTopology`：

```scala
bin/storm deactivate SampleStormClusterTopology 
```

显示以下信息：

```scala
0 [main] INFO backtype.storm.thrift - Connecting to Nimbus at localhost:6627 
76 [main] INFO backtype.storm.command.deactivate - Deactivated topology: SampleStormClusterTopology  
```

# 激活

Storm 还支持激活拓扑。当拓扑被激活时，spout 将重新开始发射元组。以下是激活拓扑的命令：

```scala
$> bin/storm activate topologyName  
```

使用以下命令激活`SampleStormClusterTopology`：

```scala
bin/storm activate SampleStormClusterTopology
```

显示以下信息：

```scala
0 [main] INFO backtype.storm.thrift - Connecting to Nimbus at localhost:6627 
65 [main] INFO backtype.storm.command.activate - Activated topology: SampleStormClusterTopology  
```

# 重新平衡

在运行时更新拓扑并行度的过程称为**重新平衡**。有关此操作的更详细信息可以在第三章中找到，*Storm 并行性和数据分区*。

# 杀死

Storm 拓扑是永无止境的进程。要停止一个拓扑，我们需要杀死它。被杀死后，拓扑首先进入停用状态，处理已经发射到其中的所有元组，然后停止。运行以下命令杀死`SampleStormClusterTopology`：

```scala
$> bin/storm kill SampleStormClusterTopology  
```

显示以下信息：

```scala
0 [main] INFO backtype.storm.thrift - Connecting to Nimbus at localhost:6627 
80 [main] INFO backtype.storm.command.kill-topology - Killed topology: SampleStormClusterTopology

```

现在，再次运行`jps`命令，查看剩余的 JVM 进程如下：

```scala
jps  
```

前面命令的输出是：

```scala
26530 supervisor 
27193 Jps 
26468 nimbus  
```

# 动态日志级别设置

这允许用户在不停止拓扑的情况下更改拓扑的日志级别。此操作的详细信息可以在本章末尾找到。

# Storm UI 的演练

此部分将向您展示如何启动 Storm UI 守护程序。但是，在启动 Storm UI 守护程序之前，我们假设您已经有一个运行中的 Storm 集群。Storm 集群部署步骤在本章的前几节中有提到。现在，转到 Storm 主目录（`cd $STORM_HOME`）在领导 Nimbus 机器上，并运行以下命令启动 Storm UI 守护程序：

```scala
$> cd $STORM_HOME
$> bin/storm ui &  
```

默认情况下，Storm UI 在启动的机器的`8080`端口上启动。现在，我们将浏览到`http://nimbus-node:8080`页面，查看 Storm UI，其中 Nimbus 节点是 Nimbus 机器的 IP 地址或主机名。

以下是 Storm 主页的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-storm/img/00009.jpeg)

# 集群摘要部分

Storm UI 的这一部分显示了在集群中部署的 Storm 版本、Nimbus 节点的正常运行时间、空闲工作插槽数量、已使用的工作插槽数量等。在向集群提交拓扑时，用户首先需要确保空闲插槽列的值不为零；否则，拓扑将不会获得任何用于处理的工作进程，并将在队列中等待，直到有工作进程空闲为止。

# Nimbus 摘要部分

Storm UI 的这一部分显示了在 Storm 集群中运行的 Nimbus 进程数量。该部分还显示了 Nimbus 节点的状态。状态为`Leader`的节点是活动主节点，而状态为`Not a Leader`的节点是被动主节点。

# 监督摘要部分

Storm UI 的这一部分显示了运行在集群中的监督节点的列表，以及它们的 Id、主机、正常运行时间、插槽和已使用插槽列。

# Nimbus 配置部分

Storm UI 的此部分显示了 Nimbus 节点的配置。一些重要的属性是：

+   `supervisor.slots.ports`

+   `storm.zookeeper.port`

+   `storm.zookeeper.servers`

+   `storm.zookeeper.retry.interval`

+   `worker.childopts`

+   `supervisor.childopts`

以下是 Nimbus 配置的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-storm/img/00010.jpeg)

# 拓扑摘要部分

Storm UI 的此部分显示了在 Storm 集群中运行的拓扑列表，以及它们的 ID，分配给拓扑的工作进程数量，执行器数量，任务数量，正常运行时间等。

让我们通过运行以下命令在远程 Storm 集群中部署示例拓扑（如果尚未运行）：

```scala
$> cd $STORM_HOME
$> bin/storm jar ~/storm_example-0.0.1-SNAPSHOT-jar-with-dependencies.jar com.stormadvance.storm_example.SampleStormClusterTopology storm_example  
```

我们通过定义三个工作进程、两个执行器用于`SampleSpout`和四个执行器用于`SampleBolt`创建了`SampleStormClusterTopology`拓扑。

在 Storm 集群上提交`SampleStormClusterTopology`后，用户必须刷新 Storm 主页。

以下屏幕截图显示在拓扑摘要部分为`SampleStormClusterTopology`添加了一行。拓扑部分包含拓扑的名称，拓扑的唯一 ID，拓扑的状态，正常运行时间，分配给拓扑的工作进程数量等。状态字段的可能值为`ACTIVE`，`KILLED`和`INACTIVE`。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-storm/img/00011.jpeg)

让我们单击`SampleStormClusterTopology`以查看其详细统计信息。有两个屏幕截图。第一个包含有关分配给`SampleStormClusterTopology`拓扑的工作进程、执行器和任务数量的信息。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-storm/img/00012.jpeg)

下一个屏幕截图包含有关喷口和螺栓的信息，包括分配给每个喷口和螺栓的执行器和任务数量：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-storm/img/00013.jpeg)

前面屏幕截图中显示的信息如下：

+   拓扑统计：此部分将提供有关在 10 分钟、3 小时、1 天和自拓扑启动以来的窗口内发出的元组数量、传输数量、确认数量、容量延迟等信息。

+   喷口（所有时间）：此部分显示拓扑内所有运行的喷口的统计信息

+   Bolts（所有时间）：此部分显示拓扑内所有运行的螺栓的统计信息

+   拓扑操作：此部分允许我们通过 Storm UI 直接对拓扑执行激活、停用、重平衡、杀死等操作：

+   停用：单击停用以停用拓扑。一旦拓扑停用，喷口停止发出元组，并且在 Storm UI 上拓扑的状态变为 INACTIVE。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-storm/img/00014.jpeg)

停用拓扑不会释放 Storm 资源。

+   +   激活：单击激活按钮以激活拓扑。一旦拓扑被激活，喷口将再次开始发出元组。

+   Kill：单击 Kill 按钮销毁/杀死拓扑。一旦拓扑被杀死，它将释放分配给该拓扑的所有 Storm 资源。在杀死拓扑时，Storm 将首先停用喷口，并等待警报框中提到的杀死时间，以便螺栓有机会完成喷口发出的元组的处理，然后再执行杀命令。以下屏幕截图显示了如何通过 Storm UI 杀死拓扑：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-storm/img/00015.jpeg)

让我们转到 Storm UI 的主页，以查看`SampleStormClusterToplogy`的状态，如下图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-storm/img/00016.jpeg)

# 动态日志级别设置

动态日志级别允许我们从 Storm CLI 和 Storm UI 在运行时更改拓扑的日志级别设置。

# 从 Storm UI 更新日志级别

按照以下步骤从 Storm UI 更新日志级别：

1.  如果`SampleStormClusterTopology`没有运行，请在 Storm 集群上再次部署。

1.  浏览 Storm UI，网址为`http://nimbus-node:8080/`。

1.  单击`storm_example`拓扑。

1.  现在点击“更改日志级别”按钮来更改拓扑的`ROOT`记录器，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-storm/img/00017.jpeg)

1.  配置以下屏幕截图中提到的条目，将`ROOT`记录器更改为 ERROR：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-storm/img/00018.jpeg)

1.  如果您计划将日志级别更改为 DEBUG，则必须指定该日志级别的超时（过期时间），如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-storm/img/00019.jpeg)

1.  一旦到达超时时间中提到的时间，日志级别将恢复为默认值：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-storm/img/00020.jpeg)

1.  操作列中提到的清除按钮将清除日志设置，并且应用将再次设置默认的日志设置。

# 从 Storm CLI 更新日志级别

我们可以从 Storm CLI 修改日志级别。以下是用户必须从 Storm 目录执行的命令，以更新运行时的日志设置：

```scala
bin/storm set_log_level [topology name] -l [logger name]=[LEVEL]:[TIMEOUT] 
```

在上述代码中，`topology name`是拓扑的名称，`logger name`是我们想要更改的记录器。如果要更改`ROOT`记录器，则将`ROOT`用作`logger name`的值。`LEVEL`是您要应用的日志级别。可能的值包括`DEBUG`、`INFO`、`ERROR`、`TRACE`、`ALL`、`WARN`、`FATAL`和`OFF`。

`TIMEOUT`是以秒为单位的时间。超时时间后，日志级别将恢复为正常。如果要将日志级别设置为`DEBUG`/`ALL`，则`TIMEOUT`的值是必需的。

以下是更改`storm_example`拓扑的日志级别设置的命令：

```scala
$> bin/storm set_log_level storm_example -l ROOT=DEBUG:30  
```

以下是清除日志级别设置的命令：

```scala
$> ./bin/storm set_log_level storm_example -r ROOT 
```

# 总结

在本章中，我们已经涵盖了 Storm 和 ZooKeeper 集群的安装，Storm 集群上拓扑的部署，Nimbus 节点的高可用性，以及通过 Storm UI 进行拓扑监控。我们还介绍了用户可以在运行中的拓扑上执行的不同操作。最后，我们重点关注了如何改变运行中拓扑的日志级别。

在下一章中，我们将重点关注在多个 Storm 机器/节点上分发拓扑。


# 第三章：Storm 并行性和数据分区

在前两章中，我们已经介绍了 Storm 的概述、Storm 的安装以及开发一个示例拓扑。在本章中，我们将专注于将拓扑分布在多个 Storm 机器/节点上。本章涵盖以下内容：

+   拓扑的并行性

+   如何在代码级别配置并行性

+   Storm 集群中不同类型的流分组

+   消息处理保证

+   Tick tuple

# 拓扑的并行性

并行性意味着将作业分布在多个节点/实例上，每个实例可以独立工作并有助于数据的处理。让我们首先看一下负责 Storm 集群并行性的进程/组件。

# 工作进程

Storm 拓扑在 Storm 集群中的多个监督节点上执行。集群中的每个节点可以运行一个或多个称为**工作进程**的 JVM，负责处理拓扑的一部分。

工作进程特定于特定的拓扑，并且可以执行该拓扑的多个组件。如果同时运行多个拓扑，它们中的任何一个都不会共享任何工作进程，因此在拓扑之间提供了一定程度的隔离。

# 执行器

在每个工作进程中，可以有多个线程执行拓扑的部分。这些线程中的每一个都被称为**执行器**。执行器只能执行拓扑中的一个组件，即拓扑中的任何 spout 或 bolt。

每个执行器作为一个单独的线程，只能按顺序执行分配给它的任务。在拓扑运行时，可以动态更改为 spout 或 bolt 定义的执行器数量，这意味着您可以轻松控制拓扑中各个组件的并行度。

# 任务

这是 Storm 中任务执行的最细粒度单位。每个任务都是 spout 或 bolt 的一个实例。在定义 Storm 拓扑时，可以为每个 spout 和 bolt 指定任务的数量。一旦定义，组件的任务数量就不能在运行时更改。每个任务可以单独执行，也可以与相同类型的另一个任务或相同 spout 或 bolt 的另一个实例一起执行。

以下图表描述了工作进程、执行器和任务之间的关系。在下图中，每个组件有两个执行器，每个执行器承载不同数量的任务。

此外，您可以看到为一个组件定义了两个执行器和八个任务（每个执行器承载四个任务）。如果您对这个配置没有获得足够的性能，您可以轻松地将组件的执行器数量更改为四个或八个，以增加性能，并且任务将在该组件的所有执行器之间均匀分布。以下图表显示了执行器、任务和工作进程之间的关系：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-storm/img/00021.jpeg)

# 在代码级别配置并行性

Storm 提供了一个 API 来在代码级别设置工作进程的数量、执行器的数量和任务的数量。以下部分展示了我们如何在代码级别配置并行性。

我们可以通过使用`org.apache.storm.Config`类的`setNumWorkers`方法在代码级别设置工作进程的数量。以下是代码片段，展示了这些设置的实际应用：

```scala
Config conf = new Config(); 
conf.setNumWorkers(3); 
```

在上一章中，我们将工作进程的数量配置为三。Storm 将为`SampleStormTopology`和`SampleStormClusterTopology`拓扑分配三个工作进程。

我们可以通过在`org.apache.storm.topology.TopologyBuilder`类的`setSpout(args,args,parallelism_hint)`或`setBolt(args,args,parallelism_hint)`方法中传递`parallelism_hint`参数来在代码级别设置执行器的数量。以下是代码片段，展示了这些设置的实际应用：

```scala
builder.setSpout("SampleSpout", new SampleSpout(), 2); 
// set the bolt class 
builder.setBolt("SampleBolt", new SampleBolt(), 4).shuffleGrouping("SampleSpout"); 
```

在上一章中，我们为`SampleSpout`设置了`parallelism_hint=2`，为`SampleBolt`设置了`parallelism_hint=4`。在执行时，Storm 将为`SampleSpout`分配两个执行器，为`SampleBolt`分配四个执行器。

我们可以配置在执行器内部可以执行的任务数量。以下是展示这些设置的代码片段：

```scala
builder.setSpout("SampleSpout", new SampleSpout(), 2).setNumTasks(4); 
```

在上述代码中，我们已经配置了`SampleSpout`的两个执行器和四个任务。对于`SampleSpout`，Storm 将为每个执行器分配两个任务。默认情况下，如果用户在代码级别不设置任务数量，Storm 将为每个执行器运行一个任务。

# Worker 进程、执行器和任务分布

假设为拓扑设置的 worker 进程数量为三，`SampleSpout`的执行器数量为三，`SampleBolt`的执行器数量为三。此外，`SampleBolt`的任务数量为六，这意味着每个`SampleBolt`执行器将有两个任务。以下图表显示了拓扑在运行时的样子：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-storm/img/00022.jpeg)

# 重新平衡拓扑的并行性

在上一章中已经解释过，Storm 的一个关键特性是它允许我们在运行时修改拓扑的并行性。在运行时更新拓扑并行性的过程称为**rebalance**。

有两种重新平衡拓扑的方式：

+   使用 Storm Web UI

+   使用 Storm CLI

在上一章中介绍了 Storm Web UI。本节介绍了如何使用 Storm CLI 工具重新平衡拓扑。以下是我们需要在 Storm CLI 上执行的命令：

```scala
> bin/storm rebalance [TopologyName] -n [NumberOfWorkers] -e [Spout]=[NumberOfExecutos] -e [Bolt1]=[NumberOfExecutos] [Bolt2]=[NumberOfExecutos]
```

`rebalance`命令将首先在消息超时期间停用拓扑，然后在 Storm 集群中均匀重新分配 worker。几秒钟或几分钟后，拓扑将恢复到之前的激活状态，并重新开始处理输入流。

# 重新平衡 SampleStormClusterTopology 拓扑的并行性

首先通过在 supervisor 机器上运行`jps`命令来检查 Storm 集群中运行的 worker 进程的数量：

在 supervisor-1 上运行`jps`命令：

```scala
> jps
24347 worker
23940 supervisor
24593 Jps
24349 worker  
```

两个 worker 进程分配给 supervisor-1 机器。

现在，在 supervisor-2 上运行`jps`命令：

```scala
> jps
24344 worker
23941 supervisor
24543 Jps
```

一个 worker 进程分配给 supervisor-2 机器。

Storm 集群上运行着三个 worker 进程。

让我们尝试重新配置`SampleStormClusterTopology`，使用两个 worker 进程，`SampleSpout`使用四个执行器，`SampleBolt`使用四个执行器：

```scala
> bin/storm rebalance SampleStormClusterTopology -n 2 -e SampleSpout=4 -e SampleBolt=4

0     [main] INFO  backtype.storm.thrift  - Connecting to Nimbus at nimbus.host.ip:6627
58   [main] INFO  backtype.storm.command.rebalance  - Topology SampleStormClusterTopology is rebalancing
```

重新运行 supervisor 机器上的`jps`命令，查看 worker 进程的数量。

在 supervisor-1 上运行`jps`命令：

```scala
> jps
24377 worker
23940 supervisor
24593 Jps 
```

在 supervisor-2 上运行`jps`命令：

```scala
> jps
24353 worker
23941 supervisor
24543 Jps  
```

在这种情况下，之前显示了两个 worker 进程。第一个 worker 进程分配给 supervisor-1，另一个分配给 supervisor-2。worker 的分布可能会根据系统上运行的拓扑数量和每个 supervisor 上可用的插槽数量而有所不同。理想情况下，Storm 会尝试在所有节点之间均匀分配负载。

# Storm 集群中不同类型的流分组

在定义拓扑时，我们创建了一个计算图，其中包含了多个 bolt 处理流。在更细粒度的层面上，每个 bolt 在拓扑中执行多个任务。因此，特定 bolt 的每个任务只会从订阅的流中获取一部分元组。

Storm 中的流分组提供了对如何在订阅流的许多任务之间对元组进行分区的完全控制。可以在使用`org.apache e.storm.topology.TopologyBuilder.setBolt`方法定义 bolt 时，通过`org.apache.storm.topology.InputDeclarer`的实例来定义 bolt 的分组。

Storm 支持以下类型的流分组。

# Shuffle 分组

Shuffle 分组以均匀随机的方式在任务之间分发元组。每个任务将处理相等数量的元组。当您希望在任务之间均匀分配处理负载，并且不需要任何数据驱动的分区时，这种分组是理想的。这是 Storm 中最常用的分组之一。

# 字段分组

此分组使您能够根据元组中的某些字段对流进行分区。例如，如果您希望特定用户的所有推文都发送到一个任务，则可以使用字段分组按用户名对推文流进行分区：

```scala
builder.setSpout("1", new TweetSpout()); 
builder.setBolt("2", new TweetCounter()).fieldsGrouping("1", new Fields("username")) 
```

由于字段分组是*hash（字段）%（任务数）*，它不能保证每个任务都会获得要处理的元组。例如，如果您对字段应用了字段分组，比如*X*，只有两个可能的值，*A*和*B*，并为 bolt 创建了两个任务，那么*hash（A）%2*和*hash（B）%2*可能返回相等的值，这将导致所有元组都被路由到一个任务，另一个任务完全空闲。

字段分组的另一个常见用途是连接流。由于分区仅基于字段值而不是流类型，因此我们可以使用任何公共连接字段连接两个流。字段的名称不需要相同。例如，在订单处理领域，我们可以连接`Order`流和`ItemScanned`流以查看何时完成订单：

```scala
builder.setSpout("1", new OrderSpout()); 
builder.setSpount("2", new ItemScannedSpout()); 
builder.setBolt("joiner", new OrderJoiner()) 
.fieldsGrouping("1", new Fields("orderId")) 
.fieldsGrouping("2", new Fields("orderRefId")); 
```

由于流上的连接因应用程序而异，您将自己定义连接的定义，比如在时间窗口上进行连接，可以通过组合字段分组来实现。

# 所有分组

所有分组是一种特殊的分组，不会对元组进行分区，而是将它们复制到所有任务中，也就是说，每个元组将被发送到 bolt 的每个任务进行处理。

所有分组的一个常见用例是向 bolt 发送信号。例如，如果您对流进行某种过滤，可以通过向所有 bolt 的任务发送这些参数的流来传递或更改过滤参数，并使用所有分组进行订阅。另一个例子是向聚合 bolt 中的所有任务发送重置消息。

# 全局分组

全局分组不会对流进行分区，而是将完整的流发送到具有最小 ID 的 bolt 任务。这种情况的一般用例是在拓扑中需要减少阶段的情况，其中您希望将拓扑中以前步骤的结果合并到单个 bolt 中。

全局分组乍看起来可能是多余的，因为如果只有一个输入流，您可以通过将 bolt 的并行度定义为 1 来实现相同的结果。但是，当您有多个数据流通过不同路径传入时，您可能希望只有一个流被减少，而其他流被并行处理。

例如，考虑以下拓扑。在这种情况下，您可能希望将来自**Bolt C**的所有元组组合在一个**Bolt D**任务中，而您可能仍希望将来自**Bolt E**到**Bolt D**的元组并行处理：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-storm/img/00023.jpeg)

# 直接分组

在直接分组中，发射器决定每个元组将在哪里进行处理。例如，假设我们有一个日志流，我们希望根据资源类型将每个日志条目处理为特定的 bolt 任务。在这种情况下，我们可以使用直接分组。

直接分组只能与直接流一起使用。要声明一个流为直接流，请使用`backtype.storm.topology.OutputFieldsDeclarer.declareStream`方法，该方法带有一个`boolean`参数。一旦有了要发射的直接流，请使用`backtype.storm.task.OutputCollector.emitDirect`而不是 emit 方法来发射它。`emitDirect`方法带有一个`taskId`参数来指定任务。您可以使用`backtype.storm.task.TopologyContext.getComponentTasks`方法获取组件的任务数。

# 本地或 shuffle 分组

如果 tuple 源和目标 bolt 任务在同一个 worker 中运行，使用此分组将仅在同一 worker 上运行的目标任务之间起到洗牌分组的作用，从而最大程度地减少任何网络跳数，提高性能。

如果源 worker 进程上没有运行目标 bolt 任务，这种分组将类似于前面提到的 shuffle 分组。

# None 分组

当您不关心 tuple 在各个任务之间如何分区时，可以使用 None 分组。从 Storm 0.8 开始，这相当于使用 shuffle 分组。

# 自定义分组

如果前面的分组都不适合您的用例，您可以通过实现`backtype.storm.grouping.CustomStreamGrouping`接口来定义自己的自定义分组。

以下是一个基于 tuple 中的类别对流进行分区的示例自定义分组：

```scala
public class CategoryGrouping implements CustomStreamGrouping, Serializable { 
  private static final Map<String, Integer> categories = ImmutableMap.of 
  ( 
    "Financial", 0,  
    "Medical", 1,  
    "FMCG", 2,  
    "Electronics", 3 
  ); 

  private int tasks = 0; 

  public void prepare(WorkerTopologyContext context, GlobalStreamId stream, List<Integer> targetTasks)  
  { 
    tasks = targetTasks.size(); 
  } 

  public List<Integer> chooseTasks(int taskId, List<Object> values) { 
    String category = (String) values.get(0); 
    return ImmutableList.of(categories.get(category) % tasks); 
  } 
} 
```

以下图表以图形方式表示了 Storm 分组：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-storm/img/00024.jpeg)

# 保证消息处理

在 Storm 拓扑中，spout 发出的单个 tuple 可能会导致拓扑后期生成多个 tuple。例如，考虑以下拓扑：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-storm/img/00025.jpeg)

在这里，**Spout A**发出一个 tuple **T(A)**，由**bolt B**和**bolt C**处理，它们分别发出 tuple **T(AB)**和**T(AC)**。因此，当作为 tuple **T(A)**结果产生的所有 tuple--即 tuple 树**T(A)**，**T(AB)**和**T(AC)**--都被处理时，我们说该 tuple 已完全处理。

当 tuple 树中的一些 tuple 由于某些运行时错误或每个拓扑可配置的超时而未能处理时，Storm 将视其为失败的 tuple。

Storm 需要以下六个步骤来保证消息处理：

1.  用唯一的消息 ID 标记 spout 发出的每个 tuple。这可以通过使用`org.apache.storm.spout.SpoutOutputColletor.emit`方法来实现，该方法带有一个`messageId`参数。Storm 使用此消息 ID 来跟踪由此 tuple 生成的 tuple 树的状态。如果您使用不带`messageId`参数的 emit 方法之一，Storm 将不会跟踪它以进行完全处理。当消息完全处理时，Storm 将使用发出 tuple 时使用的相同`messageId`发送确认。

1.  spout 实现的通用模式是，它们从消息队列（例如 RabbitMQ）中读取消息，将 tuple 生成到拓扑中进行进一步处理，然后一旦收到 tuple 已完全处理的确认，就将消息出队。

1.  当拓扑中的一个 bolt 在处理消息过程中需要生成一个新的 tuple 时，例如前面拓扑中的**bolt B**，那么它应该发出新的 tuple，并用它从 spout 获取的原始 tuple 进行关联。这可以通过使用`org.apache.storm.task.OutputCollector`类中带有 anchor tuple 参数的重载 emit 方法来实现。如果您从同一个输入 tuple 发出多个 tuple，则要为每个输出的 tuple 进行关联。

1.  每当您在 bolt 的 execute 方法中处理完一个 tuple 时，使用`org.apache.storm.task.OutputCollector.ack`方法发送确认。当确认到达发射的 spout 时，您可以安全地将消息标记为已处理，并从消息队列中出队（如果有的话）。

1.  同样，如果在处理元组时出现问题，应该使用`org.apache.storm.task.OutputCollector.fail`方法发送失败信号，以便 Storm 可以重放失败的消息。

1.  在 Storm bolt 中处理的一般模式之一是在 execute 方法的末尾处理一个元组，发出新的元组，并在 execute 方法的末尾发送确认。Storm 提供了`org.apache.storm.topology.base.BasicBasicBolt`类，它会在 execute 方法的末尾自动发送确认。如果要发出失败信号，请在 execute 方法中抛出`org.apache.storm.topology.FailedException`。

这种模型导致至少一次消息处理语义，并且你的应用程序应该准备好处理一些消息会被多次处理的情况。Storm 还提供了一次消息处理语义，我们将在第五章 *Trident Topology and Uses*中讨论。

尽管可以通过这里提到的方法在 Storm 中实现一些消息处理的保证，但你是否真正需要它，这总是一个需要考虑的问题，因为你可以通过冒一些消息不被 Storm 完全处理来获得很大的性能提升。这是在设计应用程序时可以考虑的一个权衡。

# Tick 元组

在某些用例中，一个 bolt 需要在执行某些操作之前缓存数据几秒钟，比如在每 5 秒清理缓存或者在单个请求中插入一批记录到数据库中。

tick 元组是系统生成（由 Storm 生成）的元组，我们可以在每个 bolt 级别进行配置。开发人员可以在编写 bolt 时在代码级别配置 tick 元组。

我们需要在 bolt 中重写以下方法以启用 tick 元组：

```scala
@Override 
public Map<String, Object> getComponentConfiguration() { 
  Config conf = new Config(); 
  int tickFrequencyInSeconds = 10; 
  conf.put(Config.TOPOLOGY_TICK_TUPLE_FREQ_SECS, 
  tickFrequencyInSeconds); 
  return conf; 
} 
```

在前面的代码中，我们已经将 tick 元组的时间配置为 10 秒。现在，Storm 将在每 10 秒开始生成一个 tick 元组。

此外，我们需要在 bolt 的 execute 方法中添加以下代码以识别元组的类型：

```scala
@Override 
public void execute(Tuple tuple) { 
  if (isTickTuple(tuple)) { 
    // now you can trigger e.g. a periodic activity 
  } 
  else { 
    // do something with the normal tuple 
  } 
} 

private static boolean isTickTuple(Tuple tuple) { 
  return
  tuple.getSourceComponent().equals(Constants.SYSTEM_COMPONENT_ID) && tuple.getSourceStreamId().equals(Constants.SYSTEM_TICK_STREAM_ID); 
} 
```

如果`isTickTuple()`方法的输出为 true，则输入元组是一个 tick 元组。否则，它是由前一个 bolt 发出的普通元组。

请注意，tick 元组会像普通元组一样发送到 bolt/spout，这意味着它们将排在 bolt/spout 即将通过其`execute()`或`nextTuple()`方法处理的其他元组之后。因此，你为 tick 元组配置的时间间隔在实践中是尽力而为的。例如，如果一个 bolt 受到高执行延迟的影响--例如，由于被常规非 tick 元组的传入速率压倒--那么你会观察到在 bolt 中实现的周期性活动会比预期触发得晚。

# 总结

在本章中，我们已经介绍了如何定义 Storm 的并行性，如何在多个节点之间分发作业，以及如何在多个 bolt 实例之间分发数据。本章还涵盖了两个重要特性：消息处理的保证和 tick 元组。

在下一章中，我们将介绍 Storm 上的 Trident 高级抽象。Trident 主要用于解决实时事务问题，这是无法通过普通的 Storm 解决的。


# 第四章：Trident 介绍

在前几章中，我们介绍了 Storm 的架构、拓扑、bolt、spout、元组等。在本章中，我们介绍了 Trident，它是 Storm 的高级抽象。

本章涵盖了以下内容：

+   Trident 介绍

+   理解 Trident 的数据模型

+   编写 Trident 函数、过滤器和投影

+   Trident 重新分区操作

+   Trident 聚合器

+   何时使用 Trident

# Trident 介绍

Trident 是建立在 Storm 之上的高级抽象。Trident 支持有状态的流处理，而纯 Storm 是一个无状态的处理框架。使用 Trident 的主要优势在于它保证每个进入拓扑的消息只被处理一次，这在纯 Storm 中很难实现。Trident 的概念类似于高级批处理工具，如 Cascading 和 Pig，它们是在 Hadoop 上开发的。为了实现精确一次处理，Trident 会将输入流分批处理。我们将在第五章的*Trident 拓扑和用途*、*Trident 状态*部分详细介绍。

在前三章中，我们了解到，在 Storm 的拓扑中，spout 是元组的来源。元组是 Storm 应用程序可以处理的数据单元，而 bolt 是我们编写转换逻辑的处理引擎。但在 Trident 拓扑中，bolt 被更高级的函数、聚合、过滤器和状态的语义所取代。

# 理解 Trident 的数据模型

Trident 元组是 Trident 拓扑的数据模型。Trident 元组是可以被 Trident 拓扑处理的数据的基本单元。每个元组由预定义的字段列表组成。每个字段的值可以是字节、字符、整数、长整型、浮点数、双精度浮点数、布尔值或字节数组。在构建拓扑时，对元组执行操作，这些操作要么向元组添加新字段，要么用一组新字段替换元组。

元组中的每个字段都可以通过名称`(getValueByField(String))`或其位置索引`(getValue(int))`来访问。Trident 元组还提供了方便的方法，如`getIntegerByField(String)`，可以避免您对对象进行类型转换。

# 编写 Trident 函数、过滤器和投影

本节介绍了 Trident 函数、过滤器和投影的定义。Trident 函数、过滤器和投影用于根据特定条件修改/过滤输入元组。本节还介绍了如何编写 Trident 函数、过滤器和投影。

# Trident 函数

Trident 函数包含修改原始元组的逻辑。Trident 函数接收元组的一组字段作为输入，并输出一个或多个元组。输出元组的字段与输入元组的字段合并，形成完整的元组，然后传递给拓扑中的下一个操作。如果 Trident 函数没有输出与输入元组对应的元组，则该元组将从流中移除。

我们可以通过扩展`storm.trident.operation.BaseFunction`类并实现`execute(TridentTuple tuple, TridentCollector collector)`方法来编写自定义的 Trident 函数。

让我们编写一个示例的 Trident 函数，它将返回一个名为`sum`的新字段：

```scala
public class SumFunction extends BaseFunction { 

  private static final long serialVersionUID = 5L; 

  public void execute(TridentTuple tuple, TridentCollector collector) { 
    int number1 = tuple.getInteger(0); 
    int number2 = tuple.getInteger(1); 
    int sum = number1+number2; 
    // emit the sum of first two fields 
    collector.emit(new Values(sum)); 

  } 

} 
```

假设我们将`dummyStream`作为输入，其中包含四个字段`a`、`b`、`c`、`d`，并且只有字段`a`和`b`作为输入字段传递给`SumFunction`函数。`SumFunction`类会发出一个新字段`sum`。`SumFunction`类的`execute`方法发出的`sum`字段与输入元组合并，形成完整的元组。因此，输出元组中的字段总数为`5 (a, b, c, d, sum)`。以下是一个示例代码片段，展示了如何将输入字段和新字段的名称传递给 Trident 函数：

```scala
dummyStream.each(new Fields("a","b"), new SumFunction (), new Fields("sum")) 
```

以下图显示了输入元组，`SumFunction`和输出元组。输出元组包含五个字段，`a`，`b`，`c`，`d`和`sum`：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-storm/img/00026.gif)

# Trident 过滤器

Trident 过滤器以一组字段作为输入，并根据某种条件是否满足返回 true 或 false。如果返回 true，则元组保留在输出流中；否则，元组从流中移除。

我们可以通过扩展`storm.trident.operation.BaseFilter`类并实现`isKeep(TridentTuple tuple)`方法来编写自定义的 Trident 过滤器。

让我们编写一个示例 Trident 过滤器，检查输入字段的和是偶数还是奇数。如果和是偶数，则 Trident 过滤器发出 true；否则发出 false：

```scala
public static class CheckEvenSumFilter extends BaseFilter{ 

  private static final long serialVersionUID = 7L; 

  public boolean isKeep(TridentTuple tuple) { 
    int number1 = tuple.getInteger(0); 
    int number2 = tuple.getInteger(1); 
    int sum = number1+number2; 
    if(sum % 2 == 0) { 
      return true; 
    } 
    return false; 
  } 

} 
```

假设我们得到了名为`dummyStream`的输入，其中包含四个字段，`a`，`b`，`c`，`d`，并且只有字段`a`和`b`作为输入字段传递给`CheckEvenSumFilter`过滤器。`CheckEvenSumFilter`类的`execute`方法将仅发出那些`a`和`b`的和为偶数的元组。以下是一段示例代码，展示了如何为 Trident 过滤器定义输入字段：

```scala
dummyStream.each(new Fields("a","b"), new CheckEvenSumFilter ()) 
```

以下图显示了输入元组，`CheckEvenSumFilter`和输出元组。`outputStream`仅包含那些字段`a`和`b`的和为偶数的元组：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-storm/img/00027.jpeg)

# Trident 投影

Trident 投影仅保留流中在投影操作中指定的字段。假设输入流包含三个字段，`x`，`y`和`z`，并且我们将字段`x`传递给投影操作，那么输出元组将包含一个字段`x`。以下是一段代码，展示了如何使用投影操作：

```scala
mystream.project(new Fields("x")) 
```

以下图显示了 Trident 投影：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-storm/img/00028.gif)

# Trident 重新分区操作

通过执行重新分区操作，用户可以将元组分布在多个任务中。重新分区操作不会对元组的内容进行任何更改。此外，元组只会通过网络进行重新分区操作。以下是不同类型的重新分区操作。

# 利用 shuffle 操作

这种重新分区操作以一种均匀随机的方式将元组分布在多个任务中。当我们希望在任务之间均匀分配处理负载时，通常会使用这种重新分区操作。以下图显示了如何使用`shuffle`操作重新分区输入元组：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-storm/img/00029.gif)

以下是一段代码，展示了如何使用`shuffle`操作：

```scala
mystream.shuffle().each(new Fields("a","b"), new myFilter()).parallelismHint(2) 
```

# 利用 partitionBy 操作

这种重新分区操作使您能够根据元组中的字段对流进行分区。例如，如果您希望来自特定用户的所有推文都发送到同一个目标分区，则可以通过以下方式对推文流进行分区，即应用`partitionBy`到`username`字段：

```scala
mystream.partitionBy(new Fields("username")).each(new Fields("username","text"), new myFilter()).parallelismHint(2) 
```

`partitionBy`操作应用以下公式来决定目标分区：

*目标分区 = 哈希(字段) % (目标分区数)*

如前面的公式所示，`partitionBy`操作计算输入字段的哈希以决定目标分区。因此，它不能保证所有任务都会得到元组进行处理。例如，如果您对一个字段应用了`partitionBy`，比如`X`，只有两个可能的值，`A`和`B`，并为`MyFilter`过滤器创建了两个任务，那么可能会出现哈希(`A`) % 2 和哈希(`B`) % 2 相等的情况，这将导致所有元组都被路由到一个任务，而其他元组完全空闲。

以下图显示了如何使用`partitionBy`操作重新分区输入元组：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-storm/img/00030.gif)

如前图所示，**Partition 0**和**Partition 2**包含一组元组，但**Partition 1**为空。

# 利用全局操作

这种重新分配操作将所有元组路由到同一分区。因此，流中所有批次都选择相同的目标分区。以下是一个显示如何使用`global`操作重新分配元组的图表：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-storm/img/00031.gif)

以下是一段代码，显示了如何使用`global`操作：

```scala
mystream.global().each(new Fields("a","b"), new myFilter()).parallelismHint(2) 
```

# 利用 broadcast 操作

`broadcast`操作是一种特殊的重新分配操作，不会对元组进行分区，而是将它们复制到所有分区。以下是一个显示元组如何通过网络发送的图表：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-storm/img/00032.gif)

以下是一段代码，显示了如何使用`broadcast`操作：

```scala
mystream.broadcast().each(new Fields("a","b"), new myFilter()).parallelismHint(2) 
```

# 利用 batchGlobal 操作

这种重新分配操作将属于同一批次的所有元组发送到同一分区。同一流的其他批次可能会进入不同的分区。正如其名称所示，此重新分配在批次级别是全局的。以下是一个显示如何使用`batchGlobal`操作重新分配元组的图表：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-storm/img/00033.gif)

以下是一段代码，显示了如何使用`batchGlobal`操作：

```scala
mystream.batchGlobal().each(new Fields("a","b"), new myFilter()).parallelismHint(2) 
```

# 利用分区操作

如果前面的重新分配都不适合您的用例，您可以通过实现`org.apche.storm.grouping.CustomStreamGrouping`接口来定义自己的自定义重新分配函数。

以下是一个示例自定义重新分配，根据`country`字段的值对流进行分区：

```scala
public class CountryRepartition implements CustomStreamGrouping, Serializable { 

  private static final long serialVersionUID = 1L; 

  private static final Map<String, Integer> countries = ImmutableMap.of ( 
    "India", 0,  
    "Japan", 1,  
    "United State", 2,  
    "China", 3, 
    "Brazil", 4 
  ); 

  private int tasks = 0; 

  public void prepare(WorkerTopologyContext context, GlobalStreamId stream, List<Integer> targetTasks)  
    { 
      tasks = targetTasks.size(); 
    } 

  public List<Integer> chooseTasks(int taskId, List<Object> values) { 
    String country = (String) values.get(0);    
    return ImmutableList.of(countries.get(country) % tasks); 
  } 
} 
```

`CountryRepartition`类实现了`org.apache.storm.grouping.CustomStreamGrouping`接口。`chooseTasks()`方法包含重新分配逻辑，用于确定拓扑中输入元组的下一个任务。`prepare()`方法在开始时被调用，并执行初始化活动。

# Trident 聚合器

Trident 聚合器用于对输入批次、分区或输入流执行聚合操作。例如，如果用户想要计算每个批次中元组的数量，则可以使用计数聚合器来计算每个批次中元组的数量。聚合器的输出完全替换输入元组的值。Trident 中有三种可用的聚合器：

+   `partitionAggregate`

+   `aggregate`

+   `persistenceAggregate`

让我们详细了解每种类型的聚合器。

# partitionAggregate

正如其名称所示，`partitionAggregate`在每个分区上工作，而不是整个批次。`partitionAggregate`的输出完全替换输入元组。此外，`partitionAggregate`的输出包含一个单字段元组。以下是一段代码，显示了如何使用`partitionAggregate`：

```scala
mystream.partitionAggregate(new Fields("x"), new Count() ,new new Fields("count")) 
```

例如，我们得到一个包含字段`x`和`y`的输入流，并对每个分区应用`partitionAggregate`函数；输出元组包含一个名为`count`的字段。`count`字段表示输入分区中元组的数量：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-storm/img/00034.gif)

# aggregate

`aggregate`在每个批次上工作。在聚合过程中，首先使用全局操作对元组进行重新分配，将同一批次的所有分区合并为单个分区，然后对每个批次运行聚合函数。以下是一段代码，显示了如何使用`aggregate`：

```scala
mystream.aggregate(new Fields("x"), new Count() ,new new Fields("count")) 
```

Trident 中有三种可用的聚合器接口：

+   `ReducerAggregator`

+   `Aggregator`

+   `CombinerAggregator`

这三种聚合器接口也可以与`partitionAggregate`一起使用。

# ReducerAggregator

`ReducerAggregator`首先对输入流运行全局重新分配操作，将同一批次的所有分区合并为单个分区，然后对每个批次运行聚合函数。`ReducerAggregator<T>`接口包含以下方法：

+   `init()`: 此方法返回初始值

+   `Reduce(T curr, TridentTuple tuple)`: 此方法遍历输入元组，并发出一个具有单个值的单个元组

此示例显示了如何使用`ReducerAggregator`实现`Sum`：

```scala
public static class Sum implements ReducerAggregator<Long> { 

  private static final long serialVersionUID = 1L; 
  /** return the initial value zero     
  */ 
  public Long init() { 
    return 0L; 
  } 
  /** Iterates on the input tuples, calculate the sum and   
  * produce the single tuple with single field as output. 
  */ 
  public Long reduce(Long curr, TridentTuple tuple) {                       
    return curr+tuple.getLong(0);              
  } 

} 
```

# 聚合器

`Aggregator`首先在输入流上运行全局重分区操作，将同一批次的所有分区组合成单个分区，然后在每个批次上运行聚合函数。根据定义，`Aggregator`与`ReduceAggregator`非常相似。`BaseAggregator<State>`包含以下方法：

+   `init(Object batchId, TridentCollector collector)`: 在开始处理批次之前调用`init()`方法。此方法返回将用于保存批次状态的`State`对象。此对象由`aggregate()`和`complete()`方法使用。

+   `aggregate (State s, TridentTuple tuple, TridentCollector collector)`: 此方法迭代给定批次的每个元组。此方法在处理每个元组后更新`State`对象中的状态。

+   `complete(State state, TridentCollector tridentCollector)`: 如果给定批次的所有元组都已处理完毕，则调用此方法。此方法返回与每个批次对应的单个元组。

以下是一个示例，展示了如何使用`BaseAggregator`实现求和：

```scala
public static class SumAsAggregator extends BaseAggregator<SumAsAggregator.State> { 

  private static final long serialVersionUID = 1L; 
  // state class 
  static class State { 
    long count = 0; 
  } 
  // Initialize the state 
  public State init(Object batchId, TridentCollector collector) { 
    return new State(); 
  } 
  // Maintain the state of sum into count variable.   
  public void aggregate(State state, TridentTuple tridentTuple, TridentCollector tridentCollector) { 
    state.count = tridentTuple.getLong(0) + state.count; 
  } 
  // return a tuple with single value as output  
  // after processing all the tuples of given batch.       
  public void complete(State state, TridentCollector tridentCollector) { 
    tridentCollector.emit(new Values(state.count)); 
  } 

} 
```

# CombinerAggregator

`CombinerAggregator`首先在每个分区上运行`partitionAggregate`，然后运行全局重分区操作，将同一批次的所有分区组合成单个分区，然后在最终分区上重新运行`aggregator`以发出所需的输出。与其他两个聚合器相比，这里的网络传输较少。因此，`CombinerAggregator`的整体性能优于`Aggregator`和`ReduceAggregator`。

`CombinerAggregator<T>`接口包含以下方法：

+   `init()`: 此方法在每个输入元组上运行，以从元组中检索字段的值。

+   `combine(T val1, T val2)`: 此方法组合元组的值。此方法发出具有单个字段的单个元组作为输出。

+   `zero()`: 如果输入分区不包含元组，则此方法返回零。

此示例显示了如何使用`CombinerAggregator`实现`Sum`：

```scala
public class Sum implements CombinerAggregator<Number> { 

  private static final long serialVersionUID = 1L; 

  public Number init(TridentTuple tridentTuple) { 
    return (Number) tridentTuple.getValue(0); 
  } 

  public Number combine(Number number1, Number number2) { 
    return Numbers.add(number1, number2); 
  } 

  public Number zero() { 
    return 0; 
  } 

} 
```

# persistentAggregate

`persistentAggregate`适用于流中所有批次的所有元组，并将聚合结果持久化到状态源（内存、Memcached、Cassandra 或其他数据库）中。以下是一些代码，展示了如何使用`persistentAggregate`：

```scala
mystream.persistentAggregate(new MemoryMapState.Factory(),new Fields("select"),new Count(),new Fields("count")); 
```

我们将在第五章 *Trident Topology and Uses*，*Trident state*部分进行更详细的讨论。

# 聚合器链接

Trident 提供了一种功能，可以将多个聚合器应用于同一输入流，这个过程称为**聚合器链接**。以下是一段代码，展示了如何使用聚合器链接：

```scala
mystream.chainedAgg() 
        .partitionAggregate(new Fields("b"), new Average(), new Fields("average")) 
        .partitionAggregate(new Fields("b"), new Sum(), new Fields("sum")) 
        .chainEnd(); 
```

我们已将`Average()`和`Sum()`聚合器应用于每个分区。`chainedAgg()`的输出包含与每个输入分区对应的单个元组。输出元组包含两个字段，`sum`和`average`。

以下图表显示了聚合器链接的工作原理：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-storm/img/00035.gif)

# 利用 groupBy 操作

`groupBy`操作不涉及任何重分区。`groupBy`操作将输入流转换为分组流。`groupBy`操作的主要功能是修改后续聚合函数的行为。以下图表显示了`groupBy`操作如何对单个分区的元组进行分组：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-storm/img/00036.gif)

`groupBy`的行为取决于其使用的位置。可能有以下行为：

+   如果在`partitionAggregate`之前使用`groupBy`操作，则`partitionAggregate`将在分区内创建的每个组上运行`aggregate`。

+   如果在聚合之前使用`groupBy`操作，同一批次的元组首先被重新分区到一个单一分区，然后`groupBy`被应用于每个单一分区，最后对每个组执行`aggregate`操作。

# 何时使用 Trident

使用 Trident 拓扑非常容易实现一次性处理，并且 Trident 就是为此目的而设计的。使用原始的 Storm 很难实现一次性处理，因此当我们需要一次性处理时，Trident 会很有用。

Trident 并不适用于所有用例，特别是对于高性能的用例，因为 Trident 会给 Storm 增加复杂性并管理状态。

# 总结

在本章中，我们主要集中讨论了 Trident 作为 Storm 的高级抽象，并学习了 Trident 的过滤器、函数、聚合器和重新分区操作。

在下一章中，我们将涵盖非事务拓扑、Trident 拓扑和使用分布式 RPC 的 Trident 拓扑。


# 第五章：Trident 拓扑和用途

在上一章中，我们介绍了 Trident 的概述。在本章中，我们将介绍 Trident 拓扑的开发。以下是本章将要涵盖的重点：

+   Trident `groupBy`操作

+   非事务拓扑

+   Trident hello world 拓扑

+   Trident 状态

+   分布式 RPC

+   何时使用 Trident

# Trident groupBy 操作

`groupBy`操作不涉及任何重分区。`groupBy`操作将输入流转换为分组流。`groupBy`操作的主要功能是修改后续聚合函数的行为。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-storm/img/00037.gif)

# 在分区聚合之前进行分组

如果在`partitionAggregate`之前使用`groupBy`操作，则`partitionAggregate`将在分区内创建的每个组上运行`aggregate`。

# 在聚合之前进行分组

如果在`aggregate`之前使用`groupBy`操作，则首先对输入元组进行重分区，然后对每个组执行`aggregate`操作。

# 非事务拓扑

在非事务拓扑中，spout 发出一批元组，并不保证每个批次中有什么。通过处理机制，我们可以将管道分为两类：

+   **至多一次处理**：在这种类型的拓扑中，失败的元组不会被重试。因此，spout 不会等待确认。

+   **至少一次处理**：处理管道中的失败元组将被重试。因此，这种类型的拓扑保证进入处理管道的每个元组至少被处理一次。

我们可以通过实现`org.apache.storm.trident.spout.IBatchSpout`接口来编写一个非事务 spout。

这个例子展示了如何编写一个 Trident spout：

```scala
public class FakeTweetSpout implements IBatchSpout{ 

   private static final long serialVersionUID = 10L; 
   private intbatchSize; 
   private HashMap<Long, List<List<Object>>>batchesMap = new HashMap<Long, List<List<Object>>>(); 
   public FakeTweetSpout(intbatchSize) { 
         this.batchSize = batchSize; 
   } 

   private static final Map<Integer, String> TWEET_MAP = new HashMap<Integer, String>(); 
   static { 
         TWEET_MAP.put(0, "#FIFA worldcup"); 
         TWEET_MAP.put(1, "#FIFA worldcup"); 
         TWEET_MAP.put(2, "#FIFA worldcup"); 
         TWEET_MAP.put(3, "#FIFA worldcup"); 
         TWEET_MAP.put(4, "#Movie top 10"); 
   } 

   private static final Map<Integer, String> COUNTRY_MAP = new HashMap<Integer, String>(); 
   static { 
         COUNTRY_MAP.put(0, "United State"); 
         COUNTRY_MAP.put(1, "Japan"); 
         COUNTRY_MAP.put(2, "India"); 
         COUNTRY_MAP.put(3, "China"); 
         COUNTRY_MAP.put(4, "Brazil"); 
   } 

   private List<Object>recordGenerator() { 
         final Random rand = new Random(); 
         intrandomNumber = rand.nextInt(5); 
         int randomNumber2 = rand.nextInt(5); 
         return new Values(TWEET_MAP.get(randomNumber),COUNTRY_MAP.get(randomNumber2)); 
   } 

   public void ack(long batchId) { 
         this.batchesMap.remove(batchId); 

   } 

   public void close() { 
         // Here we should close all the external connections 

   } 

   public void emitBatch(long batchId, TridentCollector collector) { 
         List<List<Object>> batches = this.batchesMap.get(batchId); 
         if(batches == null) { 
               batches = new ArrayList<List<Object>>();; 
               for (inti=0;i<this.batchSize;i++) { 
                     batches.add(this.recordGenerator()); 
               } 
               this.batchesMap.put(batchId, batches); 
         } 
         for(List<Object>list : batches){ 
collector.emit(list); 
        } 

   } 

   public Map getComponentConfiguration() { 
         // TODO Auto-generated method stub 
         return null; 
   } 

   public Fields getOutputFields() { 
         return new Fields("text","Country"); 
   } 

   public void open(Map arg0, TopologyContext arg1) { 
         // TODO Auto-generated method stub 

   } 

} 
```

`FakeTweetSpout`类实现了`org.apache.storm.trident.spout.IBatchSpout`接口。`FakeTweetSpout(intbatchSize)`的构造以`batchSize`作为参数。如果`batchSize`为`3`，则`FakeTweetSpout`类发出的每个批次包含三个元组。`recordGenerator`方法包含生成虚假推文的逻辑。以下是示例虚假推文：

```scala
["Adidas #FIFA World Cup Chant Challenge", "Brazil"] 
["The Great Gatsby is such a good movie","India"] 
```

`getOutputFields`方法返回两个字段，`text`和`Country`。`emitBatch(long batchId, TridentCollector collector)`方法使用`batchSize`变量来决定每个批次中的元组数量，并将一批发出到处理管道中。

`batchesMap`集合包含`batchId`作为键和元组批次作为值。`emitBatch(long batchId, TridentCollector collector)`发出的所有批次将被添加到`batchesMap`中。

`ack(long batchId)`方法接收`batchId`作为确认，并将从`batchesMap`中删除相应的批次。

# Trident hello world 拓扑

本节解释了如何编写 Trident hello world 拓扑。执行以下步骤创建 Trident hello world 拓扑：

1.  使用`com.stormadvance`作为`groupId`和`storm_trident`作为`artifactId`创建一个 Maven 项目。

1.  将以下依赖项和存储库添加到`pom.xml`文件中：

```scala
         <dependencies> 
         <dependency> 
               <groupId>junit</groupId> 
               <artifactId>junit</artifactId> 
               <version>3.8.1</version> 
               <scope>test</scope> 
         </dependency> 
         <dependency> 
               <groupId>org.apache.storm</groupId> 
               <artifactId>storm-core</artifactId> 
               <version>1.0.2</version> 
               <scope>provided</scope> 
         </dependency> 
   </dependencies> 
```

1.  在`com.stormadvance.storm_trident`包中创建一个`TridentUtility`类。这个类包含我们将在 Trident hello world 示例中使用的 Trident 过滤器和函数：

```scala
public class TridentUtility { 
   /** 
    * Get the comma separated value as input, split the field by comma, and 
    * then emits multiple tuple as output. 
    *  
    */ 
   public static class Split extends BaseFunction { 

         private static final long serialVersionUID = 2L; 

         public void execute(TridentTuple tuple, TridentCollector collector) { 
               String countries = tuple.getString(0); 
               for (String word :countries.split(",")) { 
                     // System.out.println("word -"+word); 
                     collector.emit(new Values(word)); 
               } 
         } 
   } 

   /** 
    * This class extends BaseFilter and contain isKeep method which emits only 
    * those tuple which has #FIFA in text field. 
    */ 
   public static class TweetFilter extends BaseFilter { 

         private static final long serialVersionUID = 1L; 

         public booleanisKeep(TridentTuple tuple) { 
               if (tuple.getString(0).contains("#FIFA")) { 
                     return true; 
               } else { 
                     return false; 
               } 
         } 

   } 

   /** 
    * This class extends BaseFilter and contain isKeep method which will print 
    * the input tuple. 
    *  
    */ 
   public static class Print extends BaseFilter { 

         private static final long serialVersionUID = 1L; 

         public booleanisKeep(TridentTuple tuple) { 
               System.out.println(tuple); 
               return true; 
         } 

   } 
} 
```

`TridentUtility`类包含三个内部类：`Split`、`TweetFilter`和`Print`。

`Split`类扩展了`org.apache.storm.trident.operation.BaseFunction`类，并包含`execute(TridentTuple tuple, TridentCollector collector)`方法。`execute()`方法以逗号分隔的值作为输入，拆分输入值，并将多个元组作为输出发出。

`TweetFilter`类扩展了`org.apache.storm.trident.operation.BaseFilter`类，并包含`isKeep(TridentTuple tuple)`方法。`isKeep()`方法以元组作为输入，并检查输入元组的`text`字段是否包含值`#FIFA`。如果元组的`text`字段包含`#FIFA`，则该方法返回 true。否则，返回 false。

`Print`类扩展了`org.apache.storm.trident.operation.BaseFilter`类，并包含`isKeep(TridentTuple tuple)`方法。`isKeep()`方法打印输入元组并返回 true。

1.  在`com.stormadvance.storm_trident`包中创建一个`TridentHelloWorldTopology`类。该类定义了 hello world Trident 拓扑：

```scala
public class TridentHelloWorldTopology {   
   public static void main(String[] args) throws Exception { 
         Config conf = new Config(); 
         conf.setMaxSpoutPending(20); 
         if (args.length == 0) { 
               LocalCluster cluster = new LocalCluster(); 
               cluster.submitTopology("Count", conf, buildTopology()); 
         } else { 
               conf.setNumWorkers(3); 
               StormSubmitter.submitTopology(args[0], conf, buildTopology()); 
         } 
   } 

   public static StormTopologybuildTopology() { 

         FakeTweetSpout spout = new FakeTweetSpout(10); 
         TridentTopology topology = new TridentTopology(); 

         topology.newStream("spout1", spout) 
                     .shuffle() 
                     .each(new Fields("text", "Country"), 
                                 new TridentUtility.TweetFilter()) 
                     .groupBy(new Fields("Country")) 
                     .aggregate(new Fields("Country"), new Count(), 
                                 new Fields("count")) 
                     .each(new Fields("count"), new TridentUtility.Print()) 
                     .parallelismHint(2); 

         return topology.build(); 
   } 
} 
```

让我们逐行理解代码。首先，我们创建了一个`TridentTopology`类的对象来定义 Trident 计算。

`TridentTopology`包含一个名为`newStream()`的方法，该方法将以输入源作为参数。在本例中，我们使用在非事务性拓扑部分创建的`FakeTweetSpout`作为输入源。与 Storm 一样，Trident 也在 ZooKeeper 中维护每个输入源的状态。在这里，`FakeTweetSpout`字符串指定了 Trident 在 ZooKeeper 中维护元数据的节点。

喷口发出一个具有两个字段`text`和`Country`的流。

我们正在使用`shuffle`操作重新分区输入源发出的元组批量。拓扑定义的下一行对每个元组应用`TweetFilter`。`TweetFilter`过滤掉所有不包含`#FIFA`关键字的元组。

`TweetFilter`的输出按`Country`字段分组。然后，我们应用`Count`聚合器来计算每个国家的推文数量。最后，我们应用`Print`过滤器来打印`aggregate`方法的输出。

这是`TridentHelloWorldTopology`类的控制台输出：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-storm/img/00038.jpeg)

这是显示 hello world Trident 拓扑执行的图表：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-storm/img/00039.gif)

# Trident 状态

Trident 提供了一个从有状态源读取和写入结果的抽象。我们可以将状态维护在拓扑内部（内存）或者存储在外部源（Memcached 或 Cassandra）中。

让我们考虑一下，我们正在将之前的 hello world Trident 拓扑的输出保存在数据库中。每次处理元组时，元组中的国家计数都会在数据库中增加。我们无法通过仅在数据库中维护计数来实现精确一次的处理。原因是，如果在处理过程中任何元组失败，那么失败的元组将会重试。这给我们带来了一个问题，因为我们不确定这个元组的状态是否已经更新过。如果元组在更新状态之前失败，那么重试元组将会增加数据库中的计数并使状态一致。但如果元组在更新状态之后失败，那么重试相同的元组将再次增加数据库中的计数并使状态不一致。因此，仅通过在数据库中维护计数，我们无法确定这个元组是否已经被处理过。我们需要更多的细节来做出正确的决定。我们需要按照以下步骤来实现精确一次的处理语义：

1.  以小批量处理元组。

1.  为每个批次分配一个唯一 ID（事务 ID）。如果批次重试，它将获得相同的唯一 ID。

1.  批量之间的状态更新是有序的。例如，批量 2 的状态更新在批量 1 的状态更新完成之前是不可能的。

如果我们使用上述三种语义创建一个拓扑，那么我们可以轻松地判断元组是否已经被处理过。

# 分布式 RPC

分布式 RPC 用于即时查询和检索 Trident 拓扑的结果。Storm 有一个内置的分布式 RPC 服务器。分布式 RPC 服务器接收来自客户端的 RPC 请求，并将其传递给 Storm 拓扑。拓扑处理请求并将结果发送到分布式 RPC 服务器，然后由分布式 RPC 服务器重定向到客户端。

我们可以通过在`storm.yaml`文件中使用以下属性来配置分布式 RPC 服务器：

```scala
drpc.servers: 
     - "nimbus-node" 
```

在这里，`nimbus-node`是分布式 RPC 服务器的 IP。

现在，在`nimbus-node`机器上运行以下命令以启动分布式 RPC 服务器：

```scala
> bin/storm drpc 
```

假设我们正在将 hello world Trident 拓扑的计数聚合存储在数据库中，并且想要即时检索给定国家的计数。我们需要使用分布式 RPC 功能来实现这一点。这个例子展示了如何在前一节创建的 hello world Trident 拓扑中整合分布式 RPC：

我们正在创建一个包含`buildTopology()`方法的`DistributedRPC`类：

```scala
public class DistributedRPC { 

  public static void main(String[] args) throws Exception { 
    Config conf = new Config(); 
    conf.setMaxSpoutPending(20); 
    LocalDRPCdrpc = new LocalDRPC(); 
    if (args.length == 0) { 

      LocalCluster cluster = new LocalCluster(); 
      cluster.submitTopology("CountryCount", conf, buildTopology(drpc)); 
      Thread.sleep(2000); 
      for(inti=0; i<100 ; i++) { 
        System.out.println("Result - "+drpc.execute("Count", "Japan India Europe")); 
        Thread.sleep(1000); 
      } 
    } else { 
      conf.setNumWorkers(3); 
      StormSubmitter.submitTopology(args[0], conf, buildTopology(null)); 
      Thread.sleep(2000); 
      DRPCClient client = new DRPCClient(conf, "RRPC-Server", 1234); 
      System.out.println(client.execute("Count", "Japan India Europe")); 
    } 
  } 

  public static StormTopologybuildTopology(LocalDRPCdrpc) { 

    FakeTweetSpout spout = new FakeTweetSpout(10); 
    TridentTopology topology = new TridentTopology(); 
    TridentStatecountryCount = topology.newStream("spout1", spout) 
                     .shuffle() 
                     .each(new Fields("text","Country"), new TridentUtility.TweetFilter()).groupBy(new Fields("Country")) 
                     .persistentAggregate(new MemoryMapState.Factory(),new Fields("Country"), new Count(), new Fields("count")) 
                     .parallelismHint(2); 

    try { 
      Thread.sleep(2000); 
    } catch (InterruptedException e) { 
    } 

    topology.newDRPCStream("Count", drpc) 
         .each(new Fields("args"), new TridentUtility.Split(), new Fields("Country"))                        
         .stateQuery(countryCount, new Fields("Country"), new MapGet(), 
                     new Fields("count")).each(new Fields("count"), 
                             new FilterNull()); 

    return topology.build(); 
  } 
} 
```

让我们逐行理解这段代码。

我们使用`FakeTweetSpout`作为输入源，并使用`TridentTopology`类来定义 Trident 计算。

在下一行中，我们使用`persistentAggregate`函数来表示所有批次的计数聚合。`MemoryMapState.Factory()`用于维护计数状态。`persistentAggregate`函数知道如何在源状态中存储和更新聚合：

```scala
persistentAggregate(new MemoryMapState.Factory(),new Fields("Country"), new Count(), new Fields("count")) 
```

内存数据库将国家名称存储为键，聚合计数存储为值，如下所示：

```scala
India 124 
United State 145 
Japan 130 
Brazil 155 
China 100 
```

`persistentAggregate`将流转换为 Trident `State`对象。在这种情况下，Trident `State`对象表示迄今为止每个国家的计数。

拓扑的下一部分定义了一个分布式查询，以即时获取每个国家的计数。分布式 RPC 查询以逗号分隔的国家列表作为输入，并返回每个国家的计数。以下是定义分布式查询部分的代码片段：

```scala
topology.newDRPCStream("Count", drpc) 
         .each(new Fields("args"), new TridentUtility.Split(), new Fields("Country"))                        
         .stateQuery(countryCount, new Fields("Country"), new MapGet(), 
                     new Fields("count")).each(new Fields("count"), 
                             new FilterNull()); 
```

`Split`函数用于拆分逗号分隔的国家列表。我们使用了`stateQuery()`方法来查询拓扑的第一部分中定义的 Trident `State`对象。`stateQuery()`接受状态源（在本例中是拓扑的第一部分计算出的国家计数）和用于查询此函数的函数。我们使用了`MapGet()`函数，用于获取每个国家的计数。最后，每个国家的计数作为查询输出返回。

以下是一段代码，展示了我们如何将输入传递给本地分布式 RPC：

```scala
System.out.println(drpc.execute("Count", "Japan,India,Europe")); 
```

我们已经创建了一个`backtype.storm.LocalDRPC`的实例来模拟分布式 RPC。

如果正在运行分布式 RPC 服务器，则需要创建分布式 RPC 客户端的实例来执行查询。以下是展示如何将输入传递给分布式 RPC 服务器的代码片段：

```scala
DRPCClient client = new DRPCClient(conf,"RRPC-Server", 1234); 
System.out.println(client.execute("Count", "Japan,India,Europe")); 
```

Trident 分布式 RPC 查询的执行方式类似于普通的 RPC 查询，只是这些查询是并行运行的。

以下是`DistributedRPC`类的控制台输出：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-storm/img/00040.jpeg)

# 何时使用 Trident

使用 Trident 拓扑非常容易实现精确一次处理，Trident 也是为此而设计的。另一方面，在普通的 Storm 中实现精确一次处理会比较困难。因此，Trident 将对需要精确一次处理的用例非常有用。

Trident 并不适用于所有用例，特别是高性能用例，因为 Trident 会增加 Storm 的复杂性并管理状态。

# 摘要

在本章中，我们主要集中在 Trident 示例拓扑、Trident `groupBy`操作和非事务性拓扑上。我们还介绍了如何使用分布式 RPC 即时查询 Trident 拓扑。

在下一章中，我们将介绍不同类型的 Storm 调度程序。
