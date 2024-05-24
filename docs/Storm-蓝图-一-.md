# Storm 蓝图（一）

> 原文：[`zh.annas-archive.org/md5/770BD43D187DC246E15A42C26D059632`](https://zh.annas-archive.org/md5/770BD43D187DC246E15A42C26D059632)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

对及时可行的信息的需求正在推动软件系统在更短的时间内处理越来越多的数据。此外，随着连接设备数量的增加，以及这些设备应用于越来越广泛的行业，这种需求变得越来越普遍。传统的企业运营系统被迫处理最初只与互联网规模公司相关的数据规模。这一巨大的转变迫使更传统的架构和方法崩溃，这些架构和方法曾将在线交易系统和离线分析分开。相反，人们正在重新想象从数据中提取信息的含义。框架和基础设施也在发展以适应这一新愿景。

具体来说，数据生成现在被视为一系列离散事件。这些事件流与数据流相关，一些是操作性的，一些是分析性的，但由一个共同的框架和基础设施处理。

风暴是实时流处理最流行的框架。它提供了在高容量、关键任务应用中所需的基本原语和保证。它既是集成技术，也是数据流和控制机制。许多大公司都将风暴作为其大数据平台的支柱。

使用本书的设计模式，您将学会开发、部署和操作能够处理数十亿次交易的数据处理流。

《风暴蓝图：分布式实时计算模式》涵盖了广泛的分布式计算主题，不仅包括设计和集成模式，还包括技术立即有用和常用的领域和应用。本书通过真实世界的例子向读者介绍了风暴，从简单的风暴拓扑开始。示例逐渐复杂，引入了高级风暴概念以及更复杂的部署和运营问题。

# 本书涵盖的内容

第一章，“分布式词频统计”，介绍了使用风暴进行分布式流处理的核心概念。分布式词频统计示例演示了更复杂计算所需的许多结构、技术和模式。在本章中，我们将对风暴计算结构有基本的了解。我们将建立开发环境，并了解用于调试和开发风暴应用的技术。

第二章，“配置风暴集群”，深入探讨了风暴技术栈以及设置和部署到风暴集群的过程。在本章中，我们将使用 Puppet provisioning 工具自动化安装和配置多节点集群。

第三章，“Trident 拓扑和传感器数据”，涵盖了 Trident 拓扑。Trident 在风暴之上提供了更高级的抽象，抽象了事务处理和状态管理的细节。在本章中，我们将应用 Trident 框架来处理、聚合和过滤传感器数据以检测疾病爆发。

第四章，“实时趋势分析”，介绍了使用风暴和 Trident 的趋势分析技术。实时趋势分析涉及识别数据流中的模式。在本章中，您将与 Apache Kafka 集成，并实现滑动窗口来计算移动平均值。

第五章，“实时图分析”，涵盖了使用 Storm 进行图分析，将数据持久化到图数据库并查询数据以发现关系。图数据库是将数据存储为图结构的数据库，具有顶点、边和属性，并主要关注实体之间的关系。在本章中，您将使用 Twitter 作为数据源，将 Storm 与流行的图数据库 Titan 整合。

第六章，“人工智能”，将 Storm 应用于通常使用递归实现的人工智能算法。我们揭示了 Storm 的一些局限性，并研究了适应这些局限性的模式。在本章中，使用**分布式远程过程调用**（**DRPC**），您将实现一个 Storm 拓扑，能够为同步查询提供服务，以确定井字游戏中的下一步最佳移动。

第七章，“集成 Druid 进行金融分析”，演示了将 Storm 与非事务系统集成的复杂性。为了支持这样的集成，本章介绍了一种利用 ZooKeeper 管理分布式状态的模式。在本章中，您将把 Storm 与 Druid 整合，Druid 是一个用于探索性分析的开源基础设施，用于提供可配置的实时分析金融事件的系统。

第八章，“自然语言处理”，介绍了 Lambda 架构的概念，将实时和批处理配对，创建一个用于分析的弹性系统。在第七章，“集成 Druid 进行金融分析”的基础上，您将整合 Hadoop 基础设施，并研究 MapReduce 作业，以在主机故障时在 Druid 中回填分析。

第九章，“在 Hadoop 上部署 Storm 进行广告分析”，演示了将现有的在 Hadoop 上运行的 Pig 脚本批处理过程转换为实时 Storm 拓扑的过程。为此，您将利用 Storm-YARN，它允许用户利用 YARN 来部署和运行 Storm 集群。在 Hadoop 上运行 Storm 允许企业 consoliolidate operations and utilize the same infrastructure for both real time and batch processing.

第十章，“云中的 Storm”，涵盖了在云服务提供商托管环境中运行和部署 Storm 的最佳实践。具体来说，您将利用 Apache Whirr，一组用于云服务的库，来部署和配置 Storm 及其支持技术，以在通过**亚马逊网络服务**（**AWS**）**弹性计算云**（**EC2**）提供的基础设施上进行部署。此外，您将利用 Vagrant 创建用于开发和测试的集群环境。

# 您需要本书的什么

以下是本书使用的软件列表：

| 章节编号 | 需要的软件 |
| --- | --- |
| 1 | Storm（0.9.1） |
| 2 | Zookeeper（3.3.5）Java（1.7）Puppet（3.4.3）Hiera（1.3.1） |
| 3 | 三叉戟（通过 Storm 0.9.1） |
| 4 | Kafka（0.7.2）OpenFire（3.9.1） |
| 5 | Twitter4J（3.0.3）Titan（0.3.2）Cassandra（1.2.9） |
| 6 | 没有新软件 |
| 7 | MySQL（5.6.15）Druid（0.5.58） |
| 8 | Hadoop（0.20.2） |
| 9 | Storm-YARN（1.0-alpha）Hadoop（2.1.0-beta） |
| 10 | Whirr（0.8.2）Vagrant（1.4.3） |

# 这本书是为谁准备的

*Storm Blueprints: Patterns for Distributed Real-time Computation*通过描述基于真实示例应用的广泛适用的分布式计算模式，使初学者和高级用户都受益。本书介绍了 Storm 和 Trident 中的核心原语以及成功部署和操作所需的关键技术。

尽管该书主要关注使用 Storm 进行 Java 开发，但这些模式适用于其他语言，书中描述的技巧、技术和方法适用于架构师、开发人员、系统和业务运营。 

对于 Hadoop 爱好者来说，这本书也是对 Storm 的很好介绍。该书演示了这两个系统如何相互补充，并提供了从批处理到实时分析世界的潜在迁移路径。

该书提供了将 Storm 应用于各种问题和行业的示例，这应该可以转化为其他面临处理大型数据集的问题的领域。因此，解决方案架构师和业务分析师将受益于这些章节介绍的高级系统架构和技术。

# 约定

在本书中，您会发现一些文本样式，用于区分不同类型的信息。以下是一些这些样式的示例，以及它们的含义解释。

文本中的代码单词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下：“所有 Hadoop 配置文件都位于`$HADOOP_CONF_DIR`中。例如，此示例的三个关键配置文件是：`core-site.xml`、`yarn-site.xml`和`hdfs-site.xml`。”

一块代码设置如下：

```scala
<configuration>
    <property>
        <name>fs.default.name</name>
        <value>hdfs://master:8020</value>
    </property>
</configuration>
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```scala
13/10/09 21:40:10 INFO yarn.StormAMRMClient: Use NMClient to launch supervisors in container.  
13/10/09 21:40:10 INFO impl.ContainerManagementProtocolProxy: Opening proxy : slave05:35847 
13/10/09 21:40:12 INFO yarn.StormAMRMClient: Supervisor log: http://slave05:8042/node/containerlogs/container_1381197763696_0004_01_000002/boneill/supervisor.log 
13/10/09 21:40:14 INFO yarn.MasterServer: HB: Received allocated containers (1) 13/10/09 21:40:14 INFO yarn.MasterServer: HB: Supervisors are to run, so queueing (1) containers... 
13/10/09 21:40:14 INFO yarn.MasterServer: LAUNCHER: Taking container with id (container_1381197763696_0004_01_000004) from the queue. 
13/10/09 21:40:14 INFO yarn.MasterServer: LAUNCHER: Supervisors are to run, so launching container id (container_1381197763696_0004_01_000004) 
13/10/09 21:40:16 INFO yarn.StormAMRMClient: Use NMClient to launch supervisors in container.  13/10/09 21:40:16 INFO impl.ContainerManagementProtocolProxy: Opening proxy : dlwolfpack02.hmsonline.com:35125 
13/10/09 21:40:16 INFO yarn.StormAMRMClient: Supervisor log: http://slave02:8042/node/containerlogs/container_1381197763696_0004_01_000004/boneill/supervisor.log

```

任何命令行输入或输出都是这样写的：

```scala
hadoop fs -mkdir /user/bone/lib/
hadoop fs -copyFromLocal ./lib/storm-0.9.0-wip21.zip /user/bone/lib/

```

**新术语**和**重要单词**以粗体显示。例如，屏幕上看到的单词，菜单或对话框中的单词等，会在文本中以这种方式出现：“在页面顶部的**筛选器**下拉菜单中选择**公共图像**。”

### 注意

警告或重要说明会出现在这样的框中。

### 提示

技巧和窍门看起来像这样。


# 第一章：分布式单词计数

在本章中，我们将介绍使用 Storm 创建分布式流处理应用程序涉及的核心概念。我们通过构建一个简单的应用程序来计算连续句子流的运行单词计数来实现这一点。单词计数示例涉及许多用于更复杂计算所需的结构、技术和模式，但它简单且易于理解。

我们将从 Storm 的数据结构概述开始，然后实现组成完整 Storm 应用程序的组件。在本章结束时，您将对 Storm 计算的结构、设置开发环境以及开发和调试 Storm 应用程序的技术有了基本的了解。

本章涵盖以下主题：

+   Storm 的基本构造 - 拓扑、流、喷口和螺栓

+   设置 Storm 开发环境

+   实现基本的单词计数应用程序

+   并行化和容错

+   通过并行化计算任务进行扩展

# 介绍 Storm 拓扑的元素 - 流、喷口和螺栓

在 Storm 中，分布式计算的结构被称为**拓扑**，由数据流、喷口（流生产者）和螺栓（操作）组成。Storm 拓扑大致类似于 Hadoop 等批处理系统中的作业。然而，批处理作业具有明确定义的起点和终点，而 Storm 拓扑会永远运行，直到明确终止或取消部署。

![介绍 Storm 拓扑的元素 - 流、喷口和螺栓](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/storm-bp/img/8294OS_01_01.jpg)

Storm 拓扑

## 流

Storm 中的核心数据结构是*元组*。元组只是具有命名值（键值对）的列表，而流是元组的无界序列。如果您熟悉**复杂事件处理**（**CEP**），您可以将 Storm 元组视为*事件*。

## 喷口

喷口代表数据进入 Storm 拓扑的主要入口点。喷口充当连接到数据源的适配器，将数据转换为元组，并将元组作为流发出。

正如您将看到的，Storm 提供了一个简单的 API 来实现喷口。开发喷口主要是编写代码以从原始来源或 API 中获取数据。潜在的数据来源包括：

+   来自基于 Web 或移动应用程序的点击流

+   Twitter 或其他社交网络的信息源

+   传感器输出

+   应用程序日志事件

由于喷口通常不实现任何特定的业务逻辑，它们通常可以在多个拓扑中重复使用。

## 螺栓

螺栓可以被视为您计算的*运算符*或*函数*。它们接受任意数量的流作为输入，处理数据，并可选择发出一个或多个流。螺栓可以订阅喷口或其他螺栓发出的流，从而可以创建一个复杂的流转换网络。

螺栓可以执行任何想象得到的处理，就像喷口 API 一样，螺栓接口简单而直接。螺栓通常执行的典型功能包括：

+   过滤元组

+   连接和聚合

+   计算

+   数据库读取/写入

# 介绍单词计数拓扑的数据流

我们的单词计数拓扑（如下图所示）将由一个连接到三个下游螺栓的喷口组成。

![介绍单词计数拓扑的数据流](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/storm-bp/img/8294OS_01_02.jpg)

单词计数拓扑

## 句子喷口

`SentenceSpout`类将简单地发出一个单值元组流，键名为`"sentence"`，值为字符串（句子），如下面的代码所示：

```scala
{ "sentence":"my dog has fleas" }
```

为了保持简单，我们的数据源将是一个静态的句子列表，我们将循环遍历，为每个句子发出一个元组。在现实世界的应用程序中，喷口通常会连接到动态来源，例如从 Twitter API 检索的推文。

### 介绍拆分句子螺栓

拆分句子螺栓将订阅句子 spout 的元组流。对于接收到的每个元组，它将查找`"sentence"`对象的值，将该值拆分为单词，并为每个单词发出一个元组：

```scala
{ "word" : "my" }
{ "word" : "dog" }
{ "word" : "has" }
{ "word" : "fleas" }
```

### 介绍单词计数螺栓

单词计数螺栓订阅`SplitSentenceBolt`类的输出，持续计算它见过特定单词的次数。每当它接收到一个元组时，它将增加与单词关联的计数器并发出一个包含单词和当前计数的元组：

```scala
{ "word" : "dog", "count" : 5 }
```

### 介绍报告螺栓

报告螺栓订阅`WordCountBolt`类的输出，并维护所有单词及其对应计数的表，就像`WordCountBolt`一样。当它接收到一个元组时，它会更新表并将内容打印到控制台。

# 实现单词计数拓扑

现在我们已经介绍了基本的 Storm 概念，我们准备开始开发一个简单的应用程序。目前，我们将在本地模式下开发和运行 Storm 拓扑。Storm 的本地模式在单个 JVM 实例中模拟了一个 Storm 集群，使得在本地开发环境或 IDE 中开发和调试 Storm 拓扑变得容易。在后面的章节中，我们将向您展示如何将在本地模式下开发的 Storm 拓扑部署到完全集群化的环境中。

## 设置开发环境

创建一个新的 Storm 项目只是将 Storm 库及其依赖项添加到 Java 类路径的问题。然而，正如您将在第二章中了解到的那样，*配置 Storm 集群*，将 Storm 拓扑部署到集群环境中需要对编译类和依赖项进行特殊打包。因此，强烈建议您使用构建管理工具，如 Apache Maven、Gradle 或 Leinengen。对于分布式单词计数示例，我们将使用 Maven。

让我们开始创建一个新的 Maven 项目：

```scala
$ mvn archetype:create -DgroupId=storm.blueprints 
-DartifactId=Chapter1 -DpackageName=storm.blueprints.chapter1.v1

```

接下来，编辑`pom.xml`文件并添加 Storm 依赖项：

```scala
<dependency>
    <groupId>org.apache.storm</groupId>
    <artifactId>storm-core</artifactId>
    <version>0.9.1-incubating</version>
</dependency>
```

然后，使用以下命令构建项目来测试 Maven 配置：

```scala
$ mvn install

```

### 注意

**下载示例代码**

您可以从[`www.packtpub.com`](http://www.packtpub.com)的帐户中下载您购买的所有 Packt 图书的示例代码文件。如果您在其他地方购买了本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，以便直接通过电子邮件接收文件。

Maven 将下载 Storm 库及其所有依赖项。有了项目设置好了，我们现在准备开始编写我们的 Storm 应用程序。

## 实现句子 spout

为了简化问题，我们的`SentenceSpout`实现将通过创建一个静态的句子列表来模拟数据源。每个句子都作为一个单字段元组发出。完整的 spout 实现在*示例 1.1*中列出。

**示例 1.1：SentenceSpout.java**

```scala
public class SentenceSpout extends BaseRichSpout {

    private SpoutOutputCollector collector;
    private String[] sentences = {
        "my dog has fleas",
        "i like cold beverages",
        "the dog ate my homework",
        "don't have a cow man",
        "i don't think i like fleas"
    };
    private int index = 0;

    public void declareOutputFields(OutputFieldsDeclarer declarer) {
        declarer.declare(new Fields("sentence"));
    }

    public void open(Map config, TopologyContext context, 
            SpoutOutputCollector collector) {
        this.collector = collector;
    }

    public void nextTuple() {
        this.collector.emit(new Values(sentences[index]));
        index++;
        if (index >= sentences.length) {
            index = 0;
        }
        Utils.waitForMillis(1);
    }
}
```

`BaseRichSpout`类是`ISpout`和`IComponent`接口的方便实现，并为我们在这个例子中不需要的方法提供了默认实现。使用这个类可以让我们只关注我们需要的方法。

`declareOutputFields()`方法在所有 Storm 组件（spouts 和 bolts）必须实现的`IComponent`接口中定义，并用于告诉 Storm 组件将发出哪些流以及每个流的元组将包含哪些字段。在这种情况下，我们声明我们的 spout 将发出一个包含单个字段（`"sentence"`）的元组的单个（默认）流。

`open（）`方法在`ISpout`接口中定义，并在初始化 spout 组件时调用。`open（）`方法接受三个参数：包含 Storm 配置的映射，提供有关拓扑中放置的组件的信息的`TopologyContext`对象，以及提供发出元组方法的`SpoutOutputCollector`对象。在这个例子中，我们在初始化方面不需要做太多，所以`open（）`实现只是将对`SpoutOutputCollector`对象的引用存储在一个实例变量中。

`nextTuple（）`方法代表任何 spout 实现的核心。Storm 调用此方法请求 spout 向输出收集器发出元组。在这里，我们只发出当前索引处的句子，并增加索引。

## 实现拆分句子螺栓

`SplitSentenceBolt`的实现在*示例 1.2*中列出。

**示例 1.2 - SplitSentenceBolt.java**

```scala
public class SplitSentenceBolt extends BaseRichBolt{
    private OutputCollector collector;

    public void prepare(Map config, TopologyContext context,
 OutputCollector collector) {
        this.collector = collector;
    }

    public void execute(Tuple tuple) {
        String sentence = tuple.getStringByField("sentence");
        String[] words = sentence.split(" ");
        for(String word : words){
            this.collector.emit(new Values(word));
        }
    }

    public void declareOutputFields(OutputFieldsDeclarer declarer) {
        declarer.declare(new Fields("word"));
    }
}
```

`BaseRichBolt`类是另一个方便的类，它实现了`IComponent`和`IBolt`接口。扩展此类使我们不必实现我们不关心的方法，并让我们专注于我们需要的功能。

`IBolt`接口定义的`prepare（）`方法类似于`ISpout`的`open（）`方法。这是您在螺栓初始化期间准备资源（例如数据库连接）的地方。与`SentenceSpout`类一样，`SplitSentenceBolt`类在初始化方面不需要太多，因此`prepare（）`方法只是保存对`OutputCollector`对象的引用。

在`declareOutputFields（）`方法中，`SplitSentenceBolt`类声明了一个包含一个字段（`"word"`）的元组流。

`SplitSentenceBolt`类的核心功能包含在`IBolt`定义的`execute（）`方法中。每次螺栓从其订阅的流接收元组时，都会调用此方法。在这种情况下，它查找传入元组的“句子”字段的值作为字符串，将该值拆分为单词，并为每个单词发出一个新元组。

## 实现单词计数螺栓

`WordCountBolt`类（示例 1.3）实际上是维护单词计数的拓扑组件。在螺栓的`prepare（）`方法中，我们实例化了一个`HashMap<String，Long>`的实例，该实例将存储所有单词及其相应的计数。在`prepare（）`方法中实例化大多数实例变量是常见做法。这种模式背后的原因在于拓扑部署时，其组件 spouts 和 bolts 会被序列化并通过网络发送。如果一个 spout 或 bolt 在序列化之前实例化了任何不可序列化的实例变量（例如在构造函数中创建），将抛出`NotSerializableException`，拓扑将无法部署。在这种情况下，由于`HashMap<String，Long>`是可序列化的，我们可以安全地在构造函数中实例化它。然而，一般来说，最好将构造函数参数限制为基本类型和可序列化对象，并在`prepare（）`方法中实例化不可序列化的对象。

在`declareOutputFields（）`方法中，`WordCountBolt`类声明了一个元组流，其中包含接收到的单词和相应的计数。在`execute（）`方法中，我们查找接收到的单词的计数（必要时将其初始化为`0`），增加并存储计数，然后发出由单词和当前计数组成的新元组。将计数作为流发出允许拓扑中的其他螺栓订阅该流并执行其他处理。

**示例 1.3 - WordCountBolt.java**

```scala
public class WordCountBolt extends BaseRichBolt{
    private OutputCollector collector;
    private HashMap<String, Long> counts = null;

    public void prepare(Map config, TopologyContext context, 
            OutputCollector collector) {
        this.collector = collector;
        this.counts = new HashMap<String, Long>();
    }

    public void execute(Tuple tuple) {
        String word = tuple.getStringByField("word");
        Long count = this.counts.get(word);
        if(count == null){
            count = 0L;
        }
        count++;
        this.counts.put(word, count);
        this.collector.emit(new Values(word, count));
    }

    public void declareOutputFields(OutputFieldsDeclarer declarer) {
        declarer.declare(new Fields("word", "count"));
    }
}
```

## 实现报告螺栓

`ReportBolt`类的目的是生成每个单词的计数报告。与`WordCountBolt`类一样，它使用`HashMap<String，Long>`对象记录计数，但在这种情况下，它只存储从计数螺栓接收到的计数。

到目前为止，我们编写的报告 bolt 与其他 bolt 之间的一个区别是它是一个终端 bolt - 它只接收元组。因为它不发出任何流，所以`declareOutputFields()`方法为空。

报告 bolt 还引入了`IBolt`接口中定义的`cleanup()`方法。当 bolt 即将关闭时，Storm 会调用此方法。我们在这里利用`cleanup()`方法作为在拓扑关闭时输出最终计数的便捷方式，但通常，`cleanup()`方法用于释放 bolt 使用的资源，如打开的文件或数据库连接。

在编写 bolt 时，要牢记`IBolt.cleanup()`方法的一点是，当拓扑在集群上运行时，Storm 不保证会调用它。我们将在下一章讨论 Storm 的容错机制时讨论这背后的原因。但是在这个示例中，我们将在开发模式下运行 Storm，其中保证会调用`cleanup()`方法。

`ReportBolt`类的完整源代码在示例 1.4 中列出。

**示例 1.4 - ReportBolt.java**

```scala
public class ReportBolt extends BaseRichBolt {

    private HashMap<String, Long> counts = null;

    public void prepare(Map config, TopologyContext context, OutputCollector collector) {
        this.counts = new HashMap<String, Long>();
    }

    public void execute(Tuple tuple) {
        String word = tuple.getStringByField("word");
        Long count = tuple.getLongByField("count");
        this.counts.put(word, count);
    }

    public void declareOutputFields(OutputFieldsDeclarer declarer) {
        // this bolt does not emit anything
    }

    public void cleanup() {
        System.out.println("--- FINAL COUNTS ---");
        List<String> keys = new ArrayList<String>();
        keys.addAll(this.counts.keySet());
        Collections.sort(keys);
        for (String key : keys) {
            System.out.println(key + " : " + this.counts.get(key));
        }
        System.out.println("--------------");
    }
}
```

## 实现单词计数拓扑

现在我们已经定义了组成我们计算的 spout 和 bolts，我们准备将它们连接到一个可运行的拓扑中（参考*示例 1.5*）。

**示例 1.5 - WordCountTopology.java**

```scala
public class WordCountTopology {

    private static final String SENTENCE_SPOUT_ID = "sentence-spout";
    private static final String SPLIT_BOLT_ID = "split-bolt";
    private static final String COUNT_BOLT_ID = "count-bolt";
    private static final String REPORT_BOLT_ID = "report-bolt";
    private static final String TOPOLOGY_NAME = "word-count-topology";

    public static void main(String[] args) throws Exception {

        SentenceSpout spout = new SentenceSpout();
        SplitSentenceBolt splitBolt = new SplitSentenceBolt();
        WordCountBolt countBolt = new WordCountBolt();
        ReportBolt reportBolt = new ReportBolt();

        TopologyBuilder builder = new TopologyBuilder();

        builder.setSpout(SENTENCE_SPOUT_ID, spout);
        // SentenceSpout --> SplitSentenceBolt
        builder.setBolt(SPLIT_BOLT_ID, splitBolt)
                .shuffleGrouping(SENTENCE_SPOUT_ID);
        // SplitSentenceBolt --> WordCountBolt
        builder.setBolt(COUNT_BOLT_ID, countBolt)
                .fieldsGrouping(SPLIT_BOLT_ID, new Fields("word"));
        // WordCountBolt --> ReportBolt
        builder.setBolt(REPORT_BOLT_ID, reportBolt)
                .globalGrouping(COUNT_BOLT_ID);

        Config config = new Config();

        LocalCluster cluster = new LocalCluster();

        cluster.submitTopology(TOPOLOGY_NAME, config, builder.createTopology());
        waitForSeconds(10);
        cluster.killTopology(TOPOLOGY_NAME);
        cluster.shutdown();
    }
}
```

Storm 拓扑通常在 Java 的`main()`方法中定义和运行（或者如果拓扑正在部署到集群，则提交）。在这个示例中，我们首先定义了字符串常量，它们将作为我们 Storm 组件的唯一标识符。我们通过实例化我们的 spout 和 bolts 并创建`TopologyBuilder`的实例来开始`main()`方法。`TopologyBuilder`类提供了一种流畅的 API，用于定义拓扑中组件之间的数据流。我们首先注册了句子 spout 并为其分配了一个唯一的 ID：

```scala
builder.setSpout(SENTENCE_SPOUT_ID, spout);
```

下一步是注册`SplitSentenceBolt`并订阅`SentenceSpout`类发出的流：

```scala
builder.setBolt(SPLIT_BOLT_ID, splitBolt)
                .shuffleGrouping(SENTENCE_SPOUT_ID);
```

`setBolt()`方法使用`TopologyBuilder`类注册一个 bolt，并返回一个`BoltDeclarer`的实例，该实例公开了定义 bolt 的输入源的方法。在这里，我们将为`SentenceSpout`对象定义的唯一 ID 传递给`shuffleGrouping()`方法来建立关系。`shuffleGrouping()`方法告诉 Storm 对`SentenceSpout`类发出的元组进行洗牌，并将它们均匀分布在`SplitSentenceBolt`对象的实例之间。我们将在 Storm 的并行性讨论中很快详细解释流分组。

下一行建立了`SplitSentenceBolt`类和`WordCountBolt`类之间的连接：

```scala
builder.setBolt(COUNT_BOLT_ID, countBolt)
                .fieldsGrouping(SPLIT_BOLT_ID, new Fields("word"));
```

正如您将了解的那样，有时候有必要将包含特定数据的元组路由到特定的 bolt 实例。在这里，我们使用`BoltDeclarer`类的`fieldsGrouping()`方法，以确保所有包含相同`"word"`值的元组都被路由到同一个`WordCountBolt`实例。

定义我们数据流的最后一步是将`WordCountBolt`实例发出的元组流路由到`ReportBolt`类。在这种情况下，我们希望`WordCountBolt`发出的所有元组都路由到单个`ReportBolt`任务。这种行为由`globalGrouping()`方法提供，如下所示：

```scala
builder.setBolt(REPORT_BOLT_ID, reportBolt)
                .globalGrouping(COUNT_BOLT_ID);
```

随着我们定义的数据流，运行单词计数计算的最后一步是构建拓扑并将其提交到集群：

```scala
Config config = new Config();

LocalCluster cluster = new LocalCluster();

        cluster.submitTopology(TOPOLOGY_NAME, config, builder.createTopology());
        waitForSeconds(10);
        cluster.killTopology(TOPOLOGY_NAME);
        cluster.shutdown();
```

在这里，我们使用 Storm 的`LocalCluster`类在本地模式下运行 Storm，以模拟在本地开发环境中完整的 Storm 集群。本地模式是一种方便的方式来开发和测试 Storm 应用程序，而不需要部署到分布式集群中的开销。本地模式还允许您在 IDE 中运行 Storm 拓扑，设置断点，停止执行，检查变量并以更加耗时或几乎不可能的方式对应用程序进行分析，而不需要部署到 Storm 集群。

在这个例子中，我们创建了一个`LocalCluster`实例，并使用拓扑名称、`backtype.storm.Config`的实例以及`TopologyBuilder`类的`createTopology()`方法返回的`Topology`对象调用了`submitTopology()`方法。正如你将在下一章中看到的，用于在本地模式部署拓扑的`submitTopology()`方法与用于在远程（分布式）模式部署拓扑的方法具有相同的签名。

Storm 的`Config`类只是`HashMap<String, Object>`的扩展，它定义了一些 Storm 特定的常量和方便的方法，用于配置拓扑的运行时行为。当一个拓扑被提交时，Storm 将其预定义的默认配置值与传递给`submitTopology()`方法的`Config`实例的内容合并，结果将传递给拓扑 spouts 和 bolts 的`open()`和`prepare()`方法。在这个意义上，`Config`对象代表了一组对拓扑中所有组件都是全局的配置参数。

现在我们准备运行`WordCountTopology`类。`main()`方法将提交拓扑，在其运行时等待十秒，终止（取消部署）拓扑，最后关闭本地集群。当程序运行完成时，您应该看到类似以下的控制台输出：

```scala
--- FINAL COUNTS ---
a : 1426
ate : 1426
beverages : 1426
cold : 1426
cow : 1426
dog : 2852
don't : 2851
fleas : 2851
has : 1426
have : 1426
homework : 1426
i : 4276
like : 2851
man : 1426
my : 2852
the : 1426
think : 1425
-------------- 
```

# 在 Storm 中引入并行性

回顾一下介绍中提到的，Storm 允许计算通过将计算分成多个独立的*任务*并行执行在集群中的多台机器上进行水平扩展。在 Storm 中，任务简单地是在集群中某处运行的 spout 或 bolt 的实例。

要理解并行性是如何工作的，我们必须首先解释在 Storm 集群中执行拓扑涉及的四个主要组件：

+   **节点（机器）**：这些只是配置为参与 Storm 集群并执行拓扑部分的机器。Storm 集群包含执行工作的一个或多个节点。

+   **工作者（JVMs）**：这些是在节点上运行的独立 JVM 进程。每个节点配置为运行一个或多个工作者。一个拓扑可以请求分配给它一个或多个工作者。

+   **执行器（线程）**：这些是在工作者 JVM 进程中运行的 Java 线程。可以将多个任务分配给单个执行器。除非明确覆盖，否则 Storm 将为每个执行器分配一个任务。

+   **任务（bolt/spout 实例）**：任务是 spout 和 bolt 的实例，其`nextTuple()`和`execute()`方法由执行器线程调用。

## WordCountTopology 并行性

到目前为止，在我们的单词计数示例中，我们并没有显式地使用 Storm 的并行性 API；相反，我们允许 Storm 使用其默认设置。在大多数情况下，除非被覆盖，否则 Storm 将默认大多数并行性设置为一个因子。

在更改我们拓扑的并行性设置之前，让我们考虑一下我们的拓扑将如何在默认设置下执行。假设我们有一台机器（节点），已经为拓扑分配了一个 worker，并允许 Storm 为每个执行器分配一个任务，我们的拓扑执行将如下所示：

![WordCountTopology 并行性](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/storm-bp/img/8294OS_01_03.jpg)

拓扑执行

正如您所看到的，我们唯一的并行性是在线程级别。每个任务在单个 JVM 内的不同线程上运行。我们如何增加并行性以更有效地利用我们手头的硬件呢？让我们从增加分配给运行我们拓扑的工作进程和执行器的数量开始。

### 向拓扑添加工作进程

分配额外的工作进程是增加拓扑的计算能力的一种简单方法，Storm 提供了通过 API 和纯配置来实现这一点的方法。无论我们选择哪种方法，我们的组件 spouts 和 bolts 都不需要改变，可以原样重用。

在之前的单词计数拓扑的版本中，我们介绍了`Config`对象，在部署时传递给`submitTopology()`方法，但基本上没有使用。要增加分配给拓扑的工作进程数量，我们只需调用`Config`对象的`setNumWorkers()`方法：

```scala
    Config config = new Config();
    config.setNumWorkers(2);
```

这将为我们的拓扑分配两个工作进程，而不是默认的一个。虽然这将为我们的拓扑增加计算资源，但为了有效利用这些资源，我们还需要调整拓扑中执行器的数量以及每个执行器的任务数量。

### 配置执行器和任务

正如我们所见，Storm 默认为拓扑中定义的每个组件创建一个任务，并为每个任务分配一个执行器。Storm 的并行性 API 通过允许你设置每个任务的执行器数量以及每个执行器的任务数量来控制这种行为。

在定义流分组时，通过设置并行性提示来配置给定组件分配的执行器数量。为了说明这个特性，让我们修改我们的拓扑定义，使`SentenceSpout`并行化，分配两个任务，并且每个任务分配自己的执行器线程：

```scala
builder.setSpout(SENTENCE_SPOUT_ID, spout, 2);
```

如果我们使用一个工作进程，我们拓扑的执行现在看起来像下面这样：

![配置执行器和任务](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/storm-bp/img/8294OS_01_04.jpg)

两个 spout 任务

接下来，我们将设置拆分句子的 bolt 以四个任务执行，每个任务有两个执行器。每个执行器线程将被分配两个任务来执行（4/2=2）。我们还将配置单词计数 bolt 以四个任务运行，每个任务都有自己的执行器线程：

```scala
builder.setBolt(SPLIT_BOLT_ID, splitBolt, 2)
              .setNumTasks(4)
                .shuffleGrouping(SENTENCE_SPOUT_ID);

builder.setBolt(COUNT_BOLT_ID, countBolt, 4)
                .fieldsGrouping(SPLIT_BOLT_ID, new Fields("word"));
```

有了两个工作进程，拓扑的执行现在看起来像下面的图表：

![配置执行器和任务](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/storm-bp/img/8294OS_01_05.jpg)

使用多个工作进程的并行性

随着拓扑并行性的增加，运行更新的`WordCountTopology`类应该会产生每个单词的更高总计数：

```scala
--- FINAL COUNTS ---
a : 2726
ate : 2722
beverages : 2723
cold : 2723
cow : 2726
dog : 5445
don't : 5444
fleas : 5451
has : 2723
have : 2722
homework : 2722
i : 8175
like : 5449
man : 2722
my : 5445
the : 2727
think : 2722
--------------
```

由于 spout 会无限发出数据，并且只有在拓扑被终止时才会停止，实际的计数会根据您的计算机速度和其他正在运行的进程而变化，但您应该会看到发出和处理的单词数量总体上增加。

重要的是要指出，增加工作进程的数量在本地模式下运行拓扑时没有任何效果。在本地模式下运行的拓扑始终在单个 JVM 进程中运行，因此只有任务和执行器并行性设置才会产生任何效果。Storm 的本地模式提供了对集群行为的一个不错的近似，并且对开发非常有用，但在移动到生产环境之前，您应该始终在真正的集群环境中测试您的应用程序。

# 理解流分组

根据之前的例子，你可能会想知道为什么我们没有费心增加`ReportBolt`的并行性。答案是这样做没有任何意义。要理解原因，你需要理解 Storm 中流分组的概念。

流分组定义了流的元组在拓扑中的 bolt 任务之间如何分布。例如，在单词计数拓扑的并行化版本中，`SplitSentenceBolt`类在拓扑中被分配了四个任务。流分组确定了哪个任务会接收给定的元组。

风暴定义了七种内置的流分组：

+   **随机分组**：这会随机分发元组到目标 bolt 任务的任务，以便每个 bolt 都会收到相同数量的元组。

+   **字段分组**：根据分组中指定字段的值将元组路由到 bolt 任务。例如，如果流根据`"word"`字段分组，具有相同`"word"`字段值的元组将始终路由到同一个 bolt 任务。

+   **全部分组**：这会将元组流复制到所有 bolt 任务中，以便每个任务都会收到元组的副本。

+   **全局分组**：这会将流中的所有元组路由到单个任务，选择具有最低任务 ID 值的任务。请注意，当使用全局分组时，在 bolt 上设置并行性提示或任务数量是没有意义的，因为所有元组都将路由到同一个 bolt 任务。全局分组应谨慎使用，因为它会将所有元组路由到单个 JVM 实例，可能会在集群中创建瓶颈或压倒特定的 JVM/机器。

+   **无分组**：无分组在功能上等同于随机分组。它已被保留以供将来使用。

+   **直接分组**：使用直接分组，源流通过调用`emitDirect()`方法决定哪个组件将接收给定的元组。它只能用于已声明为直接流的流。

+   **本地或随机分组**：本地或随机分组类似于随机分组，但会在同一工作进程中运行的 bolt 任务之间随机传输元组，如果有的话。否则，它将回退到随机分组的行为。根据拓扑的并行性，本地或随机分组可以通过限制网络传输来提高拓扑性能。

除了预定义的分组，您还可以通过实现`CustomStreamGrouping`接口来定义自己的流分组：

```scala
public interface CustomStreamGrouping extends Serializable {

void prepare(WorkerTopologyContext context, 
GlobalStreamId stream, List<Integer> targetTasks);

List<Integer> chooseTasks(int taskId, List<Object> values); 
}
```

`prepare()`方法在运行时调用，以使用分组实现可以用来决定如何将元组分组到接收任务的信息。`WorkerTopologyContext`对象提供有关拓扑的上下文信息，`GlobalStreamId`对象提供有关正在分组的流的元数据。最有用的参数是`targetTasks`，它是需要考虑的所有任务标识符的列表。通常，您会希望将`targetTasks`参数存储为一个实例变量，以便在`chooseTasks()`方法的实现中进行参考。

`chooseTasks()`方法返回应将元组发送到的任务标识符列表。它的参数是发出元组的组件的任务标识符和元组的值。

为了说明流分组的重要性，让我们在拓扑中引入一个 bug。首先修改`SentenceSpout`的`nextTuple()`方法，使其只发出每个句子一次：

```scala
public void nextTuple() {
        if(index < sentences.length){
            this.collector.emit(new Values(sentences[index]));
            index++;
        }
        Utils.waitForMillis(1);
    }
```

现在运行拓扑以获得以下输出：

```scala
--- FINAL COUNTS ---
a : 2
ate : 2
beverages : 2
cold : 2
cow : 2
dog : 4
don't : 4
fleas : 4
has : 2
have : 2
homework : 2
i : 6
like : 4
man : 2
my : 4
the : 2
think : 2
--------------
```

现在将`CountBolt`参数上的字段分组更改为随机分组，并重新运行拓扑：

```scala
builder.setBolt(COUNT_BOLT_ID, countBolt, 4)
                .shuffleGrouping(SPLIT_BOLT_ID);
```

输出应该如下所示：

```scala
--- FINAL COUNTS ---
a : 1
ate : 2
beverages : 1
cold : 1
cow : 1
dog : 2
don't : 2
fleas : 1
has : 1
have : 1
homework : 1
i : 3
like : 1
man : 1
my : 1
the : 1
think : 1
--------------
```

我们的计数不准确，因为`CountBolt`参数是有状态的：它会维护每个单词的计数。在这种情况下，我们的计算准确性取决于在组件被并行化时基于元组内容进行分组的能力。我们引入的 bug 只有在`CountBolt`参数的并行性大于一时才会显现。这凸显了使用不同并行性配置测试拓扑的重要性。

### 提示

一般来说，您应该避免在 bolt 中存储状态信息，因为每当一个 worker 失败和/或其任务被重新分配时，该信息将丢失。一种解决方案是定期将状态信息快照到持久存储中，例如数据库，以便在任务重新分配时可以恢复。

# 保证处理

Storm 提供了一个 API，允许您保证喷嘴发出的元组被完全处理。到目前为止，在我们的示例中，我们并不担心失败。我们已经看到，喷嘴流可以被分割，并且可以根据下游螺栓的行为在拓扑中生成任意数量的流。在发生故障时会发生什么？例如，考虑一个将信息持久化到基于数据库的元组数据的螺栓。我们如何处理数据库更新失败的情况？

## 喷嘴的可靠性

在 Storm 中，可靠的消息处理始于喷嘴。支持可靠处理的喷嘴需要一种方式来跟踪它发出的元组，并准备好在下游处理该元组或任何子元组失败时重新发出元组。子元组可以被认为是源自喷嘴的元组的任何派生元组。另一种看待它的方式是将喷嘴的流视为元组树的主干（如下图所示）：

![喷嘴的可靠性](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/storm-bp/img/8294OS_01_06.jpg)

元组树

在前面的图中，实线代表喷嘴发出的原始主干元组，虚线代表从原始元组派生的元组。结果图表示元组**树**。通过可靠处理，树中的每个螺栓都可以确认（`ack`）或失败一个元组。如果树中的所有螺栓都确认从主干元组派生的元组，喷嘴的`ack`方法将被调用以指示消息处理已完成。如果树中的任何螺栓明确失败一个元组，或者如果元组树的处理超过了超时期限，喷嘴的`fail`方法将被调用。

Storm 的`ISpout`接口定义了可靠性 API 中涉及的三种方法：`nextTuple`，`ack`和`fail`。

```scala
public interface ISpout extends Serializable {
    void open(Map conf, TopologyContext context, SpoutOutputCollector collector);
    void close();
    void nextTuple();
    void ack(Object msgId);
    void fail(Object msgId);
}
```

正如我们之前所看到的，当 Storm 请求喷嘴发出一个元组时，它会调用`nextTuple()`方法。实现可靠处理的第一步是为出站元组分配一个唯一的 ID，并将该值传递给`SpoutOutputCollector`的`emit()`方法：

```scala
collector.emit(new Values("value1", "value2") , msgId);
```

分配元组的消息 ID 告诉 Storm，喷嘴希望在元组树完成或在任何时候失败时接收通知。如果处理成功，喷嘴的`ack()`方法将使用分配给元组的消息 ID 进行调用。如果处理失败或超时，喷嘴的`fail`方法将被调用。

## 螺栓的可靠性

参与可靠处理的螺栓的实现涉及两个步骤：

1.  在发出派生元组时锚定到传入的元组。

1.  确认或失败已成功或不成功处理的元组。

锚定到元组意味着我们正在创建一个链接，使传入的元组和派生的元组之间建立联系，以便任何下游的螺栓都应该参与元组树，确认元组，失败元组，或允许其超时。

您可以通过调用`OutputCollector`的重载的`emit`方法将锚定到元组（或元组列表）：

```scala
collector.emit(tuple, new Values(word));
```

在这里，我们将锚定到传入的元组，并发出一个新的元组，下游的螺栓应该承认或失败。`emit`方法的另一种形式将发出未锚定的元组：

```scala
collector.emit(new Values(word));));
```

未锚定的元组不参与流的可靠性。如果未锚定的元组在下游失败，它不会导致原始根元组的重播。

成功处理一个元组并可选地发出新的或派生的元组后，处理可靠流的螺栓应该确认传入的元组：

```scala
this.collector.ack(tuple);
```

如果元组处理失败，以至于喷嘴必须重播（重新发出）元组，螺栓应该显式失败元组：

```scala
this.collector.fail(tuple)
```

如果元组处理因超时或显式调用`OutputCollector.fail()`方法而失败，将通知发出原始元组的喷嘴，从而允许它重新发出元组，您很快就会看到。

## 可靠的字数统计

为了进一步说明可靠性，让我们从增强`SentenceSpout`类开始，使其支持保证交付。它将需要跟踪所有发出的元组，并为每个元组分配一个唯一的 ID。我们将使用`HashMap<UUID, Values>`对象来存储待处理的元组。对于我们发出的每个元组，我们将分配一个唯一的标识符，并将其存储在我们的待处理元组映射中。当我们收到确认时，我们将从待处理列表中删除元组。在失败时，我们将重放元组：

```scala
public class SentenceSpout extends BaseRichSpout {

    private ConcurrentHashMap<UUID, Values> pending;
    private SpoutOutputCollector collector;
    private String[] sentences = {
        "my dog has fleas",
        "i like cold beverages",
        "the dog ate my homework",
        "don't have a cow man",
        "i don't think i like fleas"
    };
    private int index = 0;

    public void declareOutputFields(OutputFieldsDeclarer declarer) {
        declarer.declare(new Fields("sentence"));
    }

    public void open(Map config, TopologyContext context, 
            SpoutOutputCollector collector) {
        this.collector = collector;
        this.pending = new ConcurrentHashMap<UUID, Values>();
    }

    public void nextTuple() {
        Values values = new Values(sentences[index]);
        UUID msgId = UUID.randomUUID();
        this.pending.put(msgId, values);
        this.collector.emit(values, msgId);
        index++;
        if (index >= sentences.length) {
            index = 0;
        }
        Utils.waitForMillis(1);
    }

    public void ack(Object msgId) {
        this.pending.remove(msgId);
    }

    public void fail(Object msgId) {
        this.collector.emit(this.pending.get(msgId), msgId);
    }    
}
```

修改螺栓以提供保证的处理只是简单地将出站元组锚定到传入的元组，然后确认传入的元组：

```scala
public class SplitSentenceBolt extends BaseRichBolt{
    private OutputCollector collector;

    public void prepare(Map config, TopologyContext context, OutputCollector collector) {
        this.collector = collector;
    }

    public void execute(Tuple tuple) {
        String sentence = tuple.getStringByField("sentence");
        String[] words = sentence.split(" ");
        for(String word : words){
            this.collector.emit(tuple, new Values(word));
        }
        this.collector.ack(tuple);
    }

    public void declareOutputFields(OutputFieldsDeclarer declarer) {
        declarer.declare(new Fields("word"));
    }
}
```

# 总结

在本章中，我们使用 Storm 的核心 API 构建了一个简单的分布式计算应用程序，并涵盖了 Storm 的大部分功能集，甚至没有安装 Storm 或设置集群。Storm 的本地模式在生产力和开发便利性方面非常强大，但要看到 Storm 的真正力量和水平可伸缩性，您需要将应用程序部署到一个真正的集群中。

在下一章中，我们将步入安装和设置集群 Storm 环境以及在分布式环境中部署拓扑的过程。


# 第二章：配置 Storm 集群

在这一章中，您将深入了解 Storm 技术栈、其软件依赖关系以及设置和部署到 Storm 集群的过程。

我们将从在伪分布模式下安装 Storm 开始，其中所有组件都位于同一台机器上，而不是分布在多台机器上。一旦您了解了安装和配置 Storm 所涉及的基本步骤，我们将继续使用 Puppet 配置工具自动化这些过程，这将大大减少设置多节点集群所需的时间和精力。

具体来说，我们将涵盖：

+   组成集群的各种组件和服务

+   Storm 技术栈

+   在 Linux 上安装和配置 Storm

+   Storm 的配置参数

+   Storm 的命令行界面

+   使用 Puppet 配置工具自动化安装

# 介绍 Storm 集群的解剖

Storm 集群遵循类似于 Hadoop 等分布式计算技术的主/从架构，但语义略有不同。在主/从架构中，通常有一个主节点，可以通过配置静态分配或在运行时动态选举。Storm 使用前一种方法。虽然主/从架构可能会被批评为引入单点故障的设置，但我们将展示 Storm 对主节点故障具有一定的容错性。

Storm 集群由一个主节点（称为**nimbus**）和一个或多个工作节点（称为**supervisors**）组成。除了 nimbus 和 supervisor 节点外，Storm 还需要一个 Apache ZooKeeper 的实例，它本身可能由一个或多个节点组成，如下图所示：

![介绍 Storm 集群的解剖](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/storm-bp/img/8294OS_02_01.jpg)

nimbus 和 supervisor 进程都是 Storm 提供的守护进程，不需要从单独的机器中隔离出来。事实上，可以在同一台机器上运行 nimbus、supervisor 和 ZooKeeper 进程，从而创建一个单节点伪集群。

## 了解 nimbus 守护程序

nimbus 守护程序的主要责任是管理、协调和监视在集群上运行的拓扑，包括拓扑部署、任务分配以及在失败时重新分配任务。

将拓扑部署到 Storm 集群涉及*提交*预打包的拓扑 JAR 文件到 nimbus 服务器以及拓扑配置信息。一旦 nimbus 收到拓扑归档，它会将 JAR 文件分发给必要数量的 supervisor 节点。当 supervisor 节点收到拓扑归档时，nimbus 会为每个 supervisor 分配任务（spout 和 bolt 实例）并向它们发出信号，以生成执行分配任务所需的工作节点。

Nimbus 跟踪所有 supervisor 节点的状态以及分配给每个节点的任务。如果 nimbus 检测到特定的 supervisor 节点未能心跳或变得不可用，它将重新分配该 supervisor 的任务到集群中的其他 supervisor 节点。

如前所述，nimbus 在严格意义上并不是单点故障。这一特性是因为 nimbus 并不参与拓扑数据处理，而仅仅管理拓扑的初始部署、任务分配和监视。事实上，如果 nimbus 守护程序在拓扑运行时死机，只要分配任务的 supervisors 和 workers 保持健康，拓扑将继续处理数据。主要的警告是，如果 nimbus 宕机时 supervisor 失败，数据处理将失败，因为没有 nimbus 守护程序将失败的 supervisor 任务重新分配到另一个节点。

## 与监督守护程序一起工作

supervisor 守护程序等待来自 nimbus 的任务分配，并生成和监视工作进程（JVM 进程）来执行任务。supervisor 守护程序和它生成的工作进程都是单独的 JVM 进程。如果由 supervisor 生成的工作进程由于错误意外退出（甚至如果进程被强制使用 UNIX 的`kill -9`或 Windows 的`taskkill`命令终止），supervisor 守护程序将尝试重新生成工作进程。

此时，您可能想知道 Storm 的可靠交付功能如何适应其容错模型。如果一个 worker 甚至整个 supervisor 节点失败，Storm 如何保证在故障发生时正在处理的元组的交付？

答案在于 Storm 的元组锚定和确认机制。启用可靠交付后，路由到失败节点上的任务的元组将不会被确认，并且原始元组最终将在超时后由 spout 重新播放。这个过程将重复，直到拓扑已经恢复并且正常处理已经恢复。

## 介绍 Apache ZooKeeper

ZooKeeper 提供了在分布式环境中维护集中信息的服务，使用一小组基本原语和组服务。它具有简单而强大的分布式同步机制，允许客户端应用程序监视或订阅单个数据或数据集，并在创建、更新或修改数据时接收通知。使用常见的 ZooKeeper 模式或配方，开发人员可以实现分布式应用程序所需的许多不同构造，如领导者选举、分布式锁和队列。

Storm 主要使用 ZooKeeper 来协调任务分配、worker 状态和集群中 nimbus 和 supervisor 之间的拓扑指标等状态信息。Nimbus 和 supervisor 节点之间的通信主要通过 ZooKeeper 的状态修改和监视通知来处理。

Storm 对 ZooKeeper 的使用设计上相对轻量，并不会产生沉重的资源负担。对于较重的数据传输操作，例如拓扑 JAR 文件的一次性（在部署时）传输，Storm 依赖于 Thrift 进行通信。正如我们将看到的，拓扑中组件之间的数据传输操作——在性能最重要的地方——是在低级别处理并针对性能进行了优化。

## 使用 Storm 的 DRPC 服务器

Storm 应用程序中常见的模式涉及利用 Storm 的并行化和分布式计算能力，其中客户端进程或应用程序在请求-响应范式中提交请求并同步等待响应。虽然这样的范式似乎与典型 Storm 拓扑的高度异步、长寿命的特性相悖，但 Storm 包括了一种事务能力，可以实现这样的用例。

使用 Storm 的 DRPC 服务器

为了启用这个功能，Storm 使用了额外的服务（Storm DRPC）和一个专门的 spout 和 bolt，它们共同提供了高度可扩展的分布式 RPC 功能。

Storm 的 DRPC 功能的使用是完全可选的。只有当 Storm 应用程序利用此功能时，才需要 DRPC 服务器节点。

## 介绍 Storm UI

Storm UI 是一个可选的，但非常有用的服务，它提供了一个基于 Web 的 GUI，用于监视 Storm 集群并在一定程度上管理运行中的拓扑。Storm UI 为给定的 Storm 集群及其部署的拓扑提供统计信息，在监视和调整集群和拓扑性能时非常有用。

介绍 Storm UI

Storm UI 只报告从 nimbus thrift API 获取的信息，并不向 Storm 集群提供任何其他功能。Storm UI 服务可以随时启动和停止，而不会影响任何拓扑或集群功能，在这方面它是完全无状态的。它还可以配置为启动、停止、暂停和重新平衡拓扑，以便进行简单的管理。

# 介绍 Storm 技术栈

在我们开始安装 Storm 之前，让我们先看看 Storm 和拓扑构建的技术。

## Java 和 Clojure

Storm 在 Java 虚拟机上运行，并且大致上由 Java 和 Clojure 的组合编写。Storm 的主要接口是用 Java 定义的，核心逻辑大部分是用 Clojure 实现的。除了 JVM 语言，Storm 还使用 Python 来实现 Storm 可执行文件。除了这些语言，Storm 还是一种高度多语言友好的技术，部分原因是它的一些接口使用了 Apache Thrift。

Storm 拓扑的组件（spouts 和 bolts）可以用安装它的操作系统支持的几乎任何编程语言编写。JVM 语言实现可以本地运行，其他实现可以通过 JNI 和 Storm 的多语言协议实现。

## Python

所有 Storm 守护程序和管理命令都是从一个用 Python 编写的单个可执行文件运行的。这包括 nimbus 和 supervisor 守护程序，以及我们将看到的所有部署和管理拓扑的命令。因此，在参与 Storm 集群的所有机器上以及用于管理目的的任何工作站上都需要安装一个正确配置的 Python 解释器。

# 在 Linux 上安装 Storm

Storm 最初设计为在类 Unix 操作系统上运行，但从版本 0.9.1 开始，它也支持在 Windows 上部署。

为了我们的目的，我们将使用 Ubuntu 12.04 LTS，因为它相对容易使用。我们将使用服务器版本，默认情况下不包括图形用户界面，因为我们不需要也不会使用它。Ubuntu 12.04 LTS 服务器可以从[`releases.ubuntu.com/precise/ubuntu-12.04.2-server-i386.iso`](http://releases.ubuntu.com/precise/ubuntu-12.04.2-server-i386.iso)下载。

接下来的指令在实际硬件和虚拟机上同样有效。为了学习和开发的目的，如果你没有准备好的网络计算机，使用虚拟机会更加方便。

虚拟化软件可以在 OSX，Linux 和 Windows 上轻松获得。我们推荐以下任何一种软件选项：

+   VMWare（OSX，Linux 和 Windows）

这个软件需要购买。它可以在[`www.vmware.com`](http://www.vmware.com)上获得。

+   VirtualBox（OSX，Linux 和 Windows）

这个软件是免费提供的。它可以在[`www.virtualbox.org`](https://www.virtualbox.org)上获得。

+   Parallels Desktop（OSX）

这个软件需要购买。它可以在[`www.parallels.com`](http://www.parallels.com)上获得。

## 安装基本操作系统

你可以从 Ubuntu 安装光盘（或光盘镜像）启动，并按照屏幕上的指示进行基本安装。当**Package Selection**屏幕出现时，选择安装 OpenSSH Server 选项。这个软件包将允许你使用`ssh`远程登录服务器。在其他情况下，除非你选择对硬件进行特定修改，否则可以接受默认选项。

在 Ubuntu 下，默认情况下，主要用户将具有管理（sudo）权限。如果你使用不同的用户账户或 Linux 发行版，请确保你的账户具有管理权限。

## 安装 Java

首先，安装 JVM。已知 Storm 可以与来自开源 OpenJDK 和 Oracle 的 Java 1.6 和 1.7 JVM 一起工作。在这个例子中，我们将更新 apt 存储库信息并安装 Java 1.6 的 OpenJDK 发行版：

```scala
sudo apt-get update
sudo apt-get --yes install openjdk-6-jdk

```

## ZooKeeper 安装

对于我们的单节点伪集群，我们将在所有其他 Storm 组件旁边安装 ZooKeeper。Storm 目前需要版本 3.3.x，因此我们将安装该版本而不是最新版本，使用以下命令：

```scala
sudo apt-get --yes install zookeeper=3.3.5* zookeeperd=3.3.5*

```

这个命令将安装 ZooKeeper 二进制文件以及启动和停止 ZooKeeper 的服务脚本。它还将创建一个定期清除旧的 ZooKeeper 事务日志和快照文件的 cron 作业，如果不定期清除，这些文件将迅速占用大量磁盘空间，因为这是 ZooKeeper 的默认行为。

## 风暴安装

Storm 的二进制发行版可以从 Storm 网站([`storm.incubator.apache.org`](http://storm.incubator.apache.org))下载。二进制存档的布局更适合开发活动，而不是运行生产系统，因此我们将对其进行一些修改，以更紧密地遵循 UNIX 约定（例如将日志记录到`/var/log`而不是 Storm 的主目录）。

我们首先创建一个 Storm 用户和组。这将允许我们以特定用户而不是默认或根用户运行 Storm 守护进程：

```scala
sudo groupadd storm
sudo useradd --gid storm --home-dir /home/storm --create-home --shell /bin/bash storm

```

接下来，下载并解压 Storm 分发版。我们将在`/usr/share`中安装 Storm，并将特定版本的目录链接到`/usr/share/storm`。这种方法可以让我们轻松安装其他版本，并通过更改单个符号链接来激活（或恢复）新版本。我们还将 Storm 可执行文件链接到`/usr/bin/storm`：

```scala
sudo wget [storm download URL]
sudo unzip -o apache-storm-0.9.1-incubating.zip -d /usr/share/
sudo ln -s /usr/share/apache-storm-0.9.1-incubating /usr/share/storm
sudo ln -s /usr/share/storm/bin/storm /usr/bin/storm

```

默认情况下，Storm 将日志信息记录到`$STORM_HOME/logs`而不是大多数 UNIX 服务使用的`/var/log`目录。要更改这一点，执行以下命令在`/var/log/`下创建`storm`目录，并配置 Storm 将其日志数据写入那里：

```scala
sudo mkdir /var/log/storm
sudo chown storm:storm /var/log/storm

sudo sed -i 's/${storm.home}\/logs/\/var\/log\/storm/g' /usr/share/storm/log4j/storm.log.properties

```

最后，我们将 Storm 的配置文件移动到`/etc/storm`并创建一个符号链接，以便 Storm 可以找到它：

```scala
sudo mkdir /etc/storm
sudo chown storm:storm /etc/storm
sudo mv /usr/share/storm/conf/storm.yaml /etc/storm/
sudo ln -s /etc/storm/storm.yaml /usr/share/storm/conf/storm.yaml

```

安装了 Storm 后，我们现在可以配置 Storm 并设置 Storm 守护进程，使它们可以自动启动。

## 运行 Storm 守护进程

所有 Storm 守护进程都是设计为失败快速的，这意味着每当发生意外错误时，进程将停止。这允许各个组件安全失败并成功恢复，而不影响系统的其他部分。

这意味着 Storm 守护进程需要在它们意外死机时立即重新启动。这种技术称为在*监督*下运行进程，幸运的是有许多可用的实用程序来执行这个功能。事实上，ZooKeeper 也是一个失败快速的系统，而 ZooKeeper Debian 发行版（Ubuntu 是基于 Debian 的发行版）中包含的基于 upstart 的`init`脚本提供了这个功能——如果 ZooKeeper 进程在任何时候异常退出，upstart 将确保它重新启动，以便集群可以恢复。

虽然 Debian 的 upstart 系统非常适合这种情况，但其他 Linux 发行版上也有更简单的选择。为了简化事情，我们将使用大多数发行版上都可以找到的 supervisor 软件包。不幸的是，supervisor 名称与 Storm 的 supervisor 守护进程的名称冲突。为了澄清这一区别，我们将在文本中将非 Storm 进程监督守护进程称为*supervisord*（注意末尾添加的*d*），即使示例代码和命令将使用正确的名称而不添加*d*。

在基于 Debian 的 Linux 发行版中，`supervisord`软件包被命名为 supervisor，而其他发行版如 Red Hat 使用 supervisord 这个名字。要在 Ubuntu 上安装它，请使用以下命令：

```scala
sudo apt-get --yes install supervisor

```

这将安装并启动 supervisord 服务。主配置文件将位于`/etc/supervisor/supervisord.conf`。Supervisord 的配置文件将自动包括`/etc/supervisord/conf.d/`目录中与模式`*.conf`匹配的任何文件，并且这就是我们将放置`config`文件以便在 supervision 下运行 Storm 守护进程的地方。

对于我们想要在监督下运行的每个 Storm 守护进程命令，我们将创建一个包含以下内容的配置文件：

+   用于监督服务的唯一（在 supervisord 配置中）名称。

+   运行的命令。

+   运行命令的工作目录。

+   命令/服务是否应在退出时自动重新启动。对于失败快速的服务，这应该始终为 true。

+   将拥有该进程的用户。在这种情况下，我们将使用 Storm 用户运行所有 Storm 守护进程作为进程所有者。

创建以下三个文件以设置 Storm 守护进程自动启动（并在意外故障时重新启动）：

+   `/etc/supervisord/conf.d/storm-nimbus.conf`

使用以下代码创建文件：

```scala
[program:storm-nimbus]
command=storm nimbus
directory=/home/storm
autorestart=true
user=storm
```

+   `/etc/supervisord/conf.d/storm-supervisor.conf`

使用以下代码创建文件：

```scala
[program:storm-supervisor]
command=storm supervisor
directory=/home/storm
autorestart=true
user=storm
```

+   `/etc/supervisord/conf.d/storm-ui.conf`

使用以下代码创建文件：

```scala
[program:storm-ui]
command=storm ui
directory=/home/storm
autorestart=true
user=storm
```

创建了这些文件后，使用以下命令停止并启动 supervisord 服务：

```scala
sudo /etc/init.d/supervisor stop
sudo /etc/init.d/supervisor start

```

supervisord 服务将加载新的配置并启动 Storm 守护进程。等待一两分钟，然后通过在 Web 浏览器中访问以下 URL（用实际机器的主机名或 IP 地址替换`localhost`）来验证 Storm 伪集群是否已启动并运行：

`http://localhost:8080`

这将启动 Storm UI 图形界面。它应指示集群已经启动，有一个监督节点正在运行，有四个可用的工作槽，并且没有拓扑正在运行（我们稍后将向集群部署拓扑）。

如果由于某种原因 Storm UI 没有启动或未显示集群中的活动监督员，请检查以下日志文件以查找错误：

+   **Storm UI**：检查`/var/log/storm`下的`ui.log`文件以查找错误

+   **Nimbus**：检查`/var/log/storm`下的`nimbus.log`文件以查找错误

+   **Supervisor**：检查`/var/log/storm`下的`supervisor.log`文件以查找错误

到目前为止，我们一直依赖默认的 Storm 配置，该配置默认使用`localhost`作为许多集群主机名参数的值，例如 ZooKeeper 主机以及 nimbus 主节点的位置。这对于单节点伪集群是可以的，其中所有内容都在同一台机器上运行，但是设置真正的多节点集群需要覆盖默认值。接下来，我们将探讨 Storm 提供的各种配置选项以及它们对集群及其拓扑行为的影响。

## 配置 Storm

Storm 的配置由一系列 YAML 属性组成。当 Storm 守护进程启动时，它会加载默认值，然后加载`storm.yaml`（我们已经将其符号链接到`/etc/storm/storm.yaml`）文件在`$STORM_HOME/conf/`下，用默认值替换找到的任何值。

以下列表提供了一个最小的`storm.yaml`文件，其中包含您必须覆盖的条目：

```scala
# List of hosts in the zookeeper cluster
storm.zookeeper.servers:
 - "localhost"

# hostname of the nimbus node
nimbus.host: "localhost"

# supervisor worker ports
supervisor.slots.ports:
 - 6700
 - 6701
 - 6702
 - 6703

# where nimbus and supervisors should store state data
storm.local.dir: "/home/storm"

# List of hosts that are Storm DRPC servers (optional)
# drpc.servers:
#    - "localhost"

```

## 强制设置

以下设置是配置工作的多主机 Storm 集群的强制设置。

+   `storm.zookeeper.servers`：此设置是 ZooKeeper 集群中主机名的列表。由于我们在与其他 Storm 守护进程相同的机器上运行单节点 ZooKeeper，因此`localhost`的默认值是可以接受的。

+   `nimbus.host`：这是集群 nimbus 节点的主机名。工作节点需要知道哪个节点是主节点，以便下载拓扑 JAR 文件和配置。

+   `supervisor.slots.ports`: 此设置控制在 supervisor 节点上运行多少个工作进程。它被定义为工作进程将监听的端口号列表，列出的端口号数量将控制 supervisor 节点上可用的工作槽位数量。例如，如果我们有一个配置了三个端口的三个 supervisor 节点的集群，那么集群将有总共九个（3 * 3 = 9）工作槽位。默认情况下，Storm 将使用端口 6700-6703，每个 supervisor 节点有四个槽位。

+   `storm.local.dir`: nimbus 和 supervisor 守护程序都存储少量临时状态信息以及工作进程所需的 JAR 和配置文件。此设置确定 nimbus 和 supervisor 进程将存储该信息的位置。此处指定的目录必须存在，并具有适当的权限，以便进程所有者（在我们的情况下是 Storm 用户）可以读取和写入该目录。该目录的内容必须在集群运行期间持久存在，因此最好避免使用`/tmp`，因为其中的内容可能会被操作系统删除。

## 可选设置

除了对操作集群必需的设置之外，还有一些其他设置可能需要覆盖。Storm 配置设置遵循点分命名约定，其中前缀标识了设置的类别；这在下表中有所体现：

| 前缀 | 类别 |
| --- | --- |
| `storm.*` | 通用配置 |
| `nimbus.*` | Nimbus 配置 |
| `ui.*` | Storm UI 配置 |
| `drpc.*` | DRPC 服务器配置 |
| `supervisor.*` | Supervisor 配置 |
| `worker.*` | Worker 配置 |
| `zmq.*` | ZeroMQ 配置 |
| `topology.*` | 拓扑配置 |

要查看可用的默认配置设置的完整列表，请查看 Storm 源代码中的`defaults.yaml`文件（[`github.com/nathanmarz/storm/blob/master/conf/defaults.yaml`](https://github.com/nathanmarz/storm/blob/master/conf/defaults.yaml)）。以下是一些经常被覆盖的设置：

+   `nimbus.childopts` (默认值: "-Xmx1024m"): 这是在启动 nimbus 守护程序时将添加到 Java 命令行的 JVM 选项列表。

+   `ui.port` (默认值: 8080): 这指定了 Storm UI web 服务器的监听端口。

+   `ui.childopts` (默认值: "-Xmx1024m"): 这指定了在启动 Storm UI 服务时将添加到 Java 命令行的 JVM 选项。

+   `supervisor.childopts` (默认值: "-Xmx1024m"): 这指定了在启动 supervisor 守护程序时将添加到 Java 命令行的 JVM 选项。

+   `worker.childopts` (默认值: "-Xmx768m"): 这指定了在启动 worker 进程时将添加到 Java 命令行的 JVM 选项。

+   `topology.message.timeout.secs` (默认值: 30): 这配置了元组在被确认（完全处理）之前的最长时间（以秒为单位），在此时间内未确认的元组将被视为失败（超时）。将此值设置得太低可能会导致元组被重复重放。要使此设置生效，必须配置 spout 以发出锚定元组。

+   `topology.max.spout.pending` (默认值: null): 默认值为 null 时，Storm 将从 spout 尽可能快地流出元组。根据下游 bolt 的执行延迟，默认行为可能会使拓扑不堪重负，导致消息超时。将此值设置为大于 0 的非 null 数字将导致 Storm 暂停从 spout 流出元组，直到未完成的元组数量下降到该数字以下，从而限制了 spout 的流量。在调整拓扑性能时，此设置与`topology.message.timeout.secs`一起是最重要的两个参数之一。

+   `topology.enable.message.timeouts`（默认值：true）：这设置了锚定元组的超时行为。如果为 false，则锚定元组不会超时。谨慎使用此设置。在将其设置为 false 之前，请考虑修改`topology.message.timeout.secs`。要使此设置生效，必须配置一个 spout 以发射锚定元组。

## Storm 可执行文件

Storm 可执行文件是一个多用途命令，用于从启动 Storm 守护程序到执行拓扑管理功能，例如将新的拓扑部署到集群中，或者在开发和测试阶段以本地模式运行拓扑。

Storm 命令的基本语法如下：

```scala
storm [command] [arguments...]
```

## 在工作站上设置 Storm 可执行文件

对于运行连接到远程集群的 Storm 命令，您需要在本地安装 Storm 分发版。在工作站上安装分发版很简单；只需解压 Storm 分发版存档，并将 Storm bin 目录（`$STORM_HOME/bin`）添加到您的`PATH`环境变量中。接下来，在`~/.storm/`下创建`storm.yaml`文件，其中包含一行告诉 Storm 在哪里找到要与之交互的集群的 nimbus 服务器：

```scala
Sample: ~/.storm/storm.yaml file.
nimbus.host: "nimbus01."

```

### 提示

为了使 Storm 集群正常运行，必须正确设置 IP 地址名称解析，可以通过 DNS 系统或`/etc`下的`hosts`文件进行设置。

虽然在 Storm 的配置中可以使用 IP 地址代替主机名，但最好使用 DNS 系统。

## 守护程序命令

Storm 的守护程序命令用于启动 Storm 服务，并且应该在监督下运行，以便在发生意外故障时重新启动。启动时，Storm 守护程序从`$STORM_HOME/conf/storm.yaml`读取配置。此文件中的任何配置参数都将覆盖 Storm 的内置默认值。

### Nimbus

用法：`storm nimbus`

这将启动 nimbus 守护程序。

### Supervisor

用法：`storm supervisor`

这将启动监督守护程序。

### UI

用法：`storm ui`

这将启动提供用于监视 Storm 集群的基于 Web 的 UI 的 Storm UI 守护程序。

### DRPC

用法：`storm drpc`

这将启动 DRPC 守护程序。

## 管理命令

Storm 的管理命令用于部署和管理在集群中运行的拓扑。管理命令通常从 Storm 集群外的工作站运行。它们与 nimbus Thrift API 通信，因此需要知道 nimbus 节点的主机名。管理命令从`~/.storm/storm.yaml`文件中查找配置，并将 Storm 的 jar 附加到类路径上。唯一必需的配置参数是 nimbus 节点的主机名：

```scala
nimbus.host: "nimbus01"

```

### Jar

用法：`storm jar topology_jar topology_class [arguments...]`

`jar`命令用于将拓扑提交到集群。它运行`topology_class`的`main()`方法，并使用指定的参数上传`topology_jar`文件到 nimbus 以分发到集群。一旦提交，Storm 将激活拓扑并开始处理。

拓扑类中的`main()`方法负责调用`StormSubmitter.submitTopology()`方法，并为拓扑提供一个在集群中唯一的名称。如果集群中已经存在具有该名称的拓扑，则`jar`命令将失败。通常的做法是在命令行参数中指定拓扑名称，以便在提交时为拓扑命名。

### Kill

用法：`storm kill topology_name [-w wait_time]`

`kill`命令用于取消部署。它会杀死名为`topology_name`的拓扑。Storm 将首先停用拓扑的喷口，持续时间为拓扑配置的`topology.message.timeout.secs`，以允许所有正在处理的元组完成。然后，Storm 将停止工作进程，并尝试清理任何保存的状态。使用`-w`开关指定等待时间将覆盖`topology.message.timeout.secs`为指定的间隔。

`kill`命令的功能也可以在 Storm UI 中使用。

### 停用

用法：`storm deactivate topology_name`

`deactivate`命令告诉 Storm 停止从指定拓扑的喷口流元组。

也可以从 Storm UI 停用拓扑。

### 激活

用法：`storm activate topology_name`

`activate`命令告诉 Storm 从指定拓扑的喷口恢复流元组。

也可以从 Storm UI 重新激活拓扑。

### 重新平衡

用法：`storm rebalance topology_name [-w wait_time] [-n worker_count] [-e component_name=executer_count]`...

`rebalance`命令指示 Storm 在集群中重新分配任务，而无需杀死和重新提交拓扑。例如，当向集群添加新的监督节点时，可能需要这样做——因为它是一个新节点，现有拓扑的任何任务都不会分配给该节点上的工作进程。

`rebalance`命令还允许您使用`-n`和`-e`开关更改分配给拓扑的工作进程数量，并分别更改分配给给定任务的执行器数量。

运行`rebalance`命令时，Storm 将首先停用拓扑，等待配置的时间以完成未完成的元组处理，然后在监督节点之间均匀重新分配工作进程。重新平衡后，Storm 将拓扑返回到其先前的激活状态（也就是说，如果它被激活了，Storm 将重新激活它，反之亦然）。

以下示例将使用等待时间为 15 秒重新平衡名为`wordcount-topology`的拓扑，为该拓扑分配五个工作进程，并分别设置`sentence-spout`和`split-bolt`使用 4 和 8 个执行线程：

```scala
storm rebalance wordcount-topology -w 15 -n 5 -e sentence-spout=4 -e split-bolt=8
```

### Remoteconfvalue

用法：`storm remoteconfvalue conf-name`

`remoteconfvalue`命令用于查找远程集群上的配置参数。请注意，这适用于全局集群配置，并不考虑在拓扑级别进行的个别覆盖。

## 本地调试/开发命令

Storm 的本地命令是用于调试和测试的实用程序。与管理命令一样，Storm 的调试命令读取`~/.storm/storm.yaml`并使用这些值来覆盖 Storm 的内置默认值。

### REPL

用法：`storm repl`

`repl`命令打开一个配置了 Storm 本地类路径的 Clojure REPL 会话。

### 类路径

用法：`storm classpath`

`classpath`命令打印 Storm 客户端使用的类路径。

### 本地配置值

用法：`storm localconfvalue conf-name`

`localconfvalue`命令从合并配置中查找配置键，即从`~/.storm/storm.yaml`和 Storm 的内置默认值中查找。

# 向 Storm 集群提交拓扑

现在我们有了一个运行中的集群，让我们重新审视之前的单词计数示例，并修改它，以便我们可以将其部署到集群，并在本地模式下运行。之前的示例使用了 Storm 的`LocalCluster`类在本地模式下运行：

```scala
LocalCluster cluster = new LocalCluster();
            cluster.submitTopology(TOPOLOGY_NAME, config, builder.createTopology());
```

向远程集群提交拓扑只是使用 Storm 的`StormSubmitter`类的方法，该方法具有相同的名称和签名：

```scala
StormSubmitter.submitTopology(TOPOLOGY_NAME, config, builder.createTopology());
```

在开发 Storm 拓扑时，通常不希望更改代码并重新编译它们以在本地模式和部署到集群之间切换。处理这种情况的标准方法是添加一个 if/else 块，根据命令行参数来确定。在我们更新的示例中，如果没有命令行参数，我们在本地模式下运行拓扑；否则，我们使用第一个参数作为拓扑名称并将其提交到集群，如下面的代码所示：

```scala
public class WordCountTopology {

    private static final String SENTENCE_SPOUT_ID = "sentence-spout";
    private static final String SPLIT_BOLT_ID = "split-bolt";
    private static final String COUNT_BOLT_ID = "count-bolt";
    private static final String REPORT_BOLT_ID = "report-bolt";
    private static final String TOPOLOGY_NAME = "word-count-topology";

    public static void main(String[] args) throws Exception {

        SentenceSpout spout = new SentenceSpout();
        SplitSentenceBolt splitBolt = new SplitSentenceBolt();
        WordCountBolt countBolt = new WordCountBolt();
        ReportBolt reportBolt = new ReportBolt();

        TopologyBuilder builder = new TopologyBuilder();

        builder.setSpout(SENTENCE_SPOUT_ID, spout, 2);
        // SentenceSpout --> SplitSentenceBolt
        builder.setBolt(SPLIT_BOLT_ID, splitBolt, 2)
                .setNumTasks(4)
                .shuffleGrouping(SENTENCE_SPOUT_ID);
        // SplitSentenceBolt --> WordCountBolt
        builder.setBolt(COUNT_BOLT_ID, countBolt, 4)
                .fieldsGrouping(SPLIT_BOLT_ID, new Fields("word"));
        // WordCountBolt --> ReportBolt
        builder.setBolt(REPORT_BOLT_ID, reportBolt)
                .globalGrouping(COUNT_BOLT_ID);

        Config config = new Config();
        config.setNumWorkers(2);

        if(args.length == 0){
            LocalCluster cluster = new LocalCluster();
            cluster.submitTopology(TOPOLOGY_NAME, config, builder.createTopology());
            waitForSeconds(10);
            cluster.killTopology(TOPOLOGY_NAME);
            cluster.shutdown();
        } else{
            StormSubmitter.submitTopology(args[0], config, builder.createTopology());
        }
    }
}
```

要将更新的单词计数拓扑部署到运行的集群中，首先在`第二章`源代码目录中执行 Maven 构建：

```scala
mvn clean install

```

接下来，运行`storm jar`命令来部署拓扑：

```scala
storm jar ./target/Chapter1-1.0-SNAPSHOT.jar storm.blueprints.chapter1.WordCountTopology wordcount-topology

```

当命令完成时，您应该在 Storm UI 中看到拓扑变为活动状态，并能够点击拓扑名称进行详细查看和查看拓扑统计信息。

![将拓扑提交到 Storm 集群](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/storm-bp/img/8294OS_02_04.jpg)

# 自动化集群配置

到目前为止，我们已经从命令行手动配置了单节点伪集群。虽然这种方法在小集群中当然有效，但随着集群规模的增加，它将很快变得不可行。考虑需要配置由数十、数百甚至数千个节点组成的集群的情况。配置任务可以使用 shell 脚本自动化，但即使是基于 shell 脚本的自动化解决方案在可扩展性方面也是值得怀疑的。

幸运的是，有许多技术可用于解决大量受管服务器的配置和配置问题。Chef 和 Puppet 都提供了一种声明性的配置方法，允许您定义**状态**（即安装了哪些软件包以及它们如何配置）以及机器的**类**（例如，*Apache web 服务器*类机器需要安装 Apache `httpd`守护程序）。

自动化服务器的配置和配置过程是一个非常广泛的主题，远远超出了本书的范围。为了我们的目的，我们将使用 Puppet 并利用其功能的一个子集，希望它能够提供对该主题的基本介绍，并鼓励进一步探索。

# Puppet 的快速介绍

Puppet ([`puppetlabs.com`](https://puppetlabs.com))是一个 IT 自动化框架，它帮助系统管理员使用灵活的声明性方法管理大型网络基础设施资源。

Puppet 的核心是描述基础设施资源期望状态的*清单*概念。在 Puppet 术语中，状态可以包括以下内容：

+   安装了哪些软件包

+   哪些服务正在运行，哪些没有

+   软件配置细节

## Puppet 清单

Puppet 使用声明性基于 Ruby 的 DSL 来描述文件集合中的系统配置，这些文件集合称为清单。ZooKeeper 的一个示例 Puppet 清单如下所示：

```scala
    package { 'zookeeper':
        ensure => "3.3.5*",
    }
    package { 'zookeeperd':
        ensure => "3.3.5*",
        require => Package["zookeeper"],
    }

    service { 'zookeeperd':
        ensure => 'running',
        require => Package["zookeeperd"],
    }
```

这个简单的清单可以用来确保 ZooKeeper 作为服务安装并且服务正在运行。第一个软件包块告诉 Puppet 使用操作系统的软件包管理器（例如，Ubuntu/Debian 的 apt-get，Red Hat 的 yum 等）来确保安装 zookeeper 软件包的 3.3.5 版本。第二个软件包块确保安装了 zookeeperd 软件包；它要求 zookeeper 软件包已经安装。最后，`service`块告诉 Puppet 应该确保 zookeeperd 系统服务正在运行，并且该服务需要 zookeeperd 软件包已安装。

为了说明 Puppet 清单如何转换为已安装的软件和系统状态，让我们安装 Puppet 并使用前面的示例来安装和启动 zookeeperd 服务。

要获取 Puppet 的最新版本，我们需要配置 apt-get 以使用 Puppet 实验室存储库。执行以下命令来这样做并安装最新版本的 puppet：

```scala
wget http://apt.puppetlabs.com/puppetlabs-release-precise.deb
sudo dpkg -i puppetlabs-release-precise.deb
sudo apt-get update
```

接下来，将前面的示例清单保存到名为`init.pp`的文件中，并使用 Puppet 应用该清单：

```scala
sudo puppet apply init.pp

```

命令完成后，检查 zookeeper 服务是否实际在运行：

```scala
service zookeeper status

```

如果我们手动停止 zookeeper 服务并重新运行`puppet apply`命令，Puppet 不会再次安装包（因为它们已经存在）；然而，它会重新启动 zookeeper 服务，因为清单中定义的状态将服务定义为*运行*。

## Puppet 类和模块

虽然独立的 Puppet 清单使得定义单个资源的状态变得容易，但当您管理的资源数量增加时，这种方法很快就会变得难以控制。

幸运的是，Puppet 有类和模块的概念，可以更好地组织和隔离特定的配置细节。

考虑一种 Storm 的情况，我们有多个节点类。例如，Storm 集群中的一个节点可能是 nimbus 节点、supervisor 节点或两者兼有。Puppet 类和模块提供了一种区分多个配置角色的方法，您可以混合和匹配以轻松定义执行多个角色的网络资源。

为了说明这种能力，让我们重新审视一下我们用来安装 zookeeper 包的清单，并重新定义它为一个可以被重复使用并包含在多个类类型和清单中的类：

```scala
class zookeeper {

    include 'jdk'

    package { 'zookeeper':
        ensure => "3.3.5*",
    }
    package { 'zookeeperd':
        ensure => "3.3.5*",
        require => Package["zookeeper"],
    }

    service { 'zookeeperd':
        ensure => 'running',
        require => Package["zookeeperd"],
    }
}
```

在前面的示例中，我们重新定义了 zookeeper 清单为一个`puppet`类，可以在其他类和清单中使用。在第二行，`zookeeper`类包含另一个类`jdk`，它将包含一个资源的类定义，该资源将包含需要 Java JDK 的机器的状态。

## Puppet 模板

Puppet 还利用了 Ruby ERB 模板系统，允许您为将在 Puppet 应用清单文件时填充的各种文件定义模板。Puppet ERB 模板中的占位符是将在 Puppet 运行时评估和替换的 Ruby 表达式和结构。ERB 模板中的 Ruby 代码可以完全访问清单文件中定义的 Puppet 变量。

考虑以下 Puppet 文件声明，用于生成`storm.yaml`配置文件：

```scala
    file { "storm-etc-config":
        path => "/etc/storm/storm.yaml",
        ensure => file,
        content => template("storm/storm.yaml.erb"),
        require => [File['storm-etc-config-dir'], File['storm-share-symlink']],
    }
```

此声明告诉 Puppet 从`storm.yaml.erb`模板创建文件`storm.yaml`，放在`/etc/storm/`下：

```scala
storm.zookeeper.servers:
<% @zookeeper_hosts.each do |host| -%>
     - <%= host %>
<% end -%>

nimbus.host: <%= @nimbus_host %>

storm.local.dir: <%= @storm_local_dir %>

<% if @supervisor_ports != 'none' %>
supervisor.slots.ports:
<% @supervisor_ports.each do |port| -%>
    - <%= port %>
<% end -%>
<% end %>

<% if @drpc_servers != 'none' %>
<% @drpc_servers.each do |drpc| -%>
    - <%= drpc %>
<% end -%>
<% end %>
```

模板中的条件逻辑和变量扩展允许我们定义一个可以用于许多环境的单个文件。例如，如果我们正在配置的环境没有任何 Storm DRPC 服务器，那么生成的`storm.yaml`文件的`drpc.servers`部分将被省略。

## 使用 Puppet Hiera 管理环境

我们简要介绍了 Puppet 清单、类和模板的概念。此时，您可能想知道如何在 puppet 类或清单中定义变量。在`puppet`类或清单中定义变量非常简单；只需在清单或类定义的开头定义如下：

```scala
$java_version = "1.6.0"

```

一旦定义，`java_version`变量将在整个类或清单定义以及任何 ERB 模板中可用；然而，这里存在一个可重用性的缺点。如果我们硬编码诸如版本号之类的信息，实际上就限制了我们的类的重用，使其固定在一个硬编码的值上。如果我们能够将所有可能频繁更改的变量外部化，使配置管理更易于维护，那将更好。这就是 Hiera 发挥作用的地方。

## 介绍 Hiera

Hiera 是一个键值查找工具，已集成到 Puppet 框架的最新版本中。Hiera 允许您定义键值层次结构（因此得名），使得父定义源中的键可以被子定义源覆盖。

例如，考虑这样一种情况，我们正在为将参与 Storm 集群的多台机器定义配置参数。所有机器将共享一组常见的键值，例如我们想要使用的 Java 版本。因此，我们将在一个名为“`common.yaml`”的文件中定义这些值。

从那里开始，事情开始分歧。我们可能有单节点伪集群的环境，也可能有多节点的环境。因此，我们希望将特定于环境的配置值存储在诸如“`single-node.yaml`”和“`cluster.yaml`”之类的单独文件中。

最后，我们希望将真实的特定于主机的信息存储在遵循命名约定“**[hostname].yaml**”的文件中。

![介绍 Hiera](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/storm-bp/img/8294OS_02_05.jpg)

Puppet 的 Hiera 集成允许您这样做，并使用内置的 Puppet 变量来适当地解析文件名。

`第二章`源代码目录中的示例演示了如何实现这种组织形式。

一个典型的`common.yaml`文件可能定义了所有主机共有的全局属性，如下所示：

```scala
storm.version: apache-storm-0.9.1-incubating

# options are oracle-jdk, openjdk
jdk.vendor: openjdk
# options are 6, 7, 8
jdk.version: 7
```

在环境级别，我们可能希望区分*独立*和*集群*配置，这种情况下，`cluster.yaml`文件可能如下所示：

```scala
# hosts entries for name resolution (template params for /etc/hosts)
hosts:
   nimbus01: 192.168.1.10
   zookeeper01: 192.168.1.11
   supervisor01: 192.168.1.12
   supervisor02: 192.168.1.13
   supervisor04: 192.168.1.14

storm.nimbus.host: nimbus01

storm.zookeeper.servers:
     - zookeeper01

storm.supervisor.slots.ports:
     - 6700
     - 6701
     - 6702
     - 6703
     - 6705
```

最后，我们可能希望在使用命名约定[hostname].yaml 的文件中定义特定于主机的参数，并定义应该应用于该节点的 Puppet 类。

对于`nimbus01.yaml`，请使用以下代码：

```scala
# this node only acts as a nimus node
classes:
    - nimbus
```

对于`zookeeper01.yaml`，请使用以下代码：

```scala
# this node is strictly a zookeeper node
classes:
    - zookeeper
```

我们只是触及了 Puppet 和 Hiera 可能性的表面。`第二章`源代码目录包含了有关如何使用 Puppet 自动化部署和配置任务的其他示例和文档。

# 总结

在这一章中，我们已经介绍了在单节点（伪分布式）配置以及完全分布式多节点配置中安装和配置 Storm 所需的步骤。我们还向您介绍了用于部署和管理运行拓扑的 Storm 守护程序和命令行实用程序。

最后，我们简要介绍了 Puppet 框架，并展示了如何使用它来管理多个环境配置。

我们鼓励您探索附带下载中包含的附加代码和文档。

在下一章中，我们将介绍 Trident，这是一个在 Storm 之上用于事务和状态管理的高级抽象层。


# 第三章：Trident 拓扑结构和传感器数据

在本章中，我们将探讨 Trident 拓扑结构。Trident 在 Storm 之上提供了一个更高级的抽象。Trident 抽象了事务处理和状态管理的细节。具体来说，Trident 将元组批处理成一组离散的事务。此外，Trident 提供了允许拓扑对数据执行操作的抽象，如函数、过滤器和聚合。

我们将使用传感器数据作为示例，以更好地理解 Trident。通常，传感器数据形成从许多不同位置读取的流。一些传统的例子包括天气或交通信息，但这种模式延伸到各种来源。例如，运行在手机上的应用程序会生成大量的事件信息。处理来自手机的事件流是传感器数据处理的另一个实例。

传感器数据包含许多设备发出的事件，通常形成一个永无止境的流。这是 Storm 的一个完美用例。

在本章中，我们将涵盖：

+   Trident 拓扑结构

+   Trident 喷泉

+   Trident 操作-过滤器和函数

+   Trident 聚合器-组合器和减少器

+   Trident 状态

# 审查我们的用例

为了更好地理解 Trident 拓扑结构以及使用传感器数据的 Storm，我们将实现一个 Trident 拓扑结构，用于收集医疗报告以识别疾病的爆发。

拓扑结构将处理包含以下信息的诊断事件：

| 纬度 | 经度 | 时间戳 | 诊断代码（ICD9-CM） |
| --- | --- | --- | --- |
| 39.9522 | -75.1642 | 2013 年 3 月 13 日下午 3:30 | 320.0（血友病性脑膜炎） |
| 40.3588 | -75.6269 | 2013 年 3 月 13 日下午 3:50 | 324.0（颅内脓肿） |

每个事件将包括发生地点的全球定位系统（GPS）坐标。纬度和经度以十进制格式指定。事件还包含 ICD9-CM 代码，表示诊断和事件的时间戳。完整的 ICD-9-CM 代码列表可在以下网址找到：

[`www.icd9data.com/`](http://www.icd9data.com/.) .

为了检测疫情爆发，系统将计算在指定时间段内特定疾病代码在地理位置内的发生次数。为了简化这个例子，我们将每个诊断事件映射到最近的城市。在一个真实的系统中，你很可能会对事件进行更复杂的地理空间聚类。

同样，对于这个例子，我们将按小时自纪元以来对发生次数进行分组。在一个真实的系统中，你很可能会使用滑动窗口，并计算相对移动平均值的趋势。

最后，我们将使用一个简单的阈值来确定是否有疫情爆发。如果某个小时的发生次数大于某个阈值，系统将发送警报并派遣国民警卫队。

为了保持历史记录，我们还将持久化每个城市、小时和疾病的发生次数。

# 介绍 Trident 拓扑结构

为了满足这些要求，我们需要在我们的拓扑中计算发生的次数。在使用标准 Storm 拓扑时，这可能会有挑战，因为元组可能会被重放，导致重复计数。正如我们将在接下来的几节中看到的那样，Trident 提供了解决这个问题的基本方法。

我们将使用以下拓扑：

![介绍 Trident 拓扑结构](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/storm-bp/img/8294OS_03_01.jpg)

前述拓扑的代码如下：

```scala
public class OutbreakDetectionTopology {

    public static StormTopology buildTopology() {
    TridentTopology topology = new TridentTopology();
    DiagnosisEventSpout spout = new DiagnosisEventSpout();
    Stream inputStream = topology.newStream("event", spout);
    inputStream
    // Filter for critical events.
.each(new Fields("event"), new DiseaseFilter()))

            // Locate the closest city
         .each(new Fields("event"),
               new CityAssignment(), new Fields("city"))

         // Derive the hour segment
         .each(new Fields("event", "city"),
               new HourAssignment(), new Fields("hour",
               "cityDiseaseHour"))

         // Group occurrences in same city and hour
         .groupBy(new Fields("cityDiseaseHour"))

         // Count occurrences and persist the results.
         .persistentAggregate(new OutbreakTrendFactory(),
                              new Count(),
                              new Fields("count"))

         .newValuesStream()

         // Detect an outbreak
         .each(new Fields("cityDiseaseHour", "count"),
               new OutbreakDetector(), new Fields("alert"))

         // Dispatch the alert
         .each(new Fields("alert"),
               new DispatchAlert(), new Fields());

}
}
```

前面的代码显示了不同 Trident 函数之间的连接。首先，`DiagnosisEventSpout`函数发出事件。然后，`DiseaseFilter`函数对事件进行过滤，过滤掉我们不关心的疾病发生。之后，事件与`CityAssignment`函数中的城市相关联。然后，`HourAssignment`函数为事件分配一个小时，并向元组添加一个键，该键包括城市、小时和疾病代码。然后，我们按照这个键进行分组，这使得在拓扑中的`persistAggregate`函数步骤中对这些计数进行计数和持久化。然后，这些计数传递给`OutbreakDetector`函数，该函数对计数进行阈值处理，当超过阈值时发出警报。最后，`DispatchAlert`函数接收警报，记录一条消息，并终止程序。在接下来的部分中，我们将更深入地研究每个步骤。

# 介绍 Trident spout

让我们首先看一下拓扑中的 spout。与 Storm 相比，Trident 引入了**批次**的概念。与 Storm 的 spout 不同，Trident 的 spout 必须以批次形式发出元组。

每个批次都有自己独特的事务标识符。spout 根据其合同的约束确定批次的组成。spout 有三种类型的合同：**非事务性**，**事务性**和**不透明**。

非事务性 spout 对批次的组成不提供任何保证，并且可能重叠。两个不同的批次可能包含相同的元组。事务性 spout 保证批次不重叠，并且相同的批次始终包含相同的元组。不透明 spout 保证批次不重叠，但批次的内容可能会改变。

这在以下表中表示出来：

| Spout 类型 | 批次可能重叠 | 批次内容可能改变 |
| --- | --- | --- |
| 非事务性 | X | X |
| 不透明 |   | X |
| 事务性 |   |   |

spout 的接口如下代码片段所示：

```scala
public interface ITridentSpout<T> extends Serializable {

   BatchCoordinator<T> getCoordinator(String txStateId,
                              Map conf, TopologyContext context);
   Emitter<T> getEmitter(String txStateId, Map conf,
                         TopologyContext context);

   Map getComponentConfiguration();

   Fields getOutputFields();
}
```

在 Trident 中，spout 实际上并不发出元组。相反，工作在`BatchCoordinator`和`Emitter`函数之间进行分解。`Emitter`函数负责发出元组，而`BatchCoordinator`函数负责批处理管理和元数据，以便`Emitter`函数可以正确重播批次。

`TridentSpout`函数只是提供了对`BatchCoordinator`和`Emitter`函数的访问器方法，并声明了 spout 将发出的字段。以下是我们示例中的`DiagnosisEventSpout`函数的列表：

```scala
public class DiagnosisEventSpout implements ITridentSpout<Long> {
 private static final long serialVersionUID = 1L;
 SpoutOutputCollector collector;
 BatchCoordinator<Long> coordinator = new DefaultCoordinator();
 Emitter<Long> emitter = new DiagnosisEventEmitter();

 @Override
 public BatchCoordinator<Long> getCoordinator(
         String txStateId, Map conf, TopologyContext context) {
     return coordinator;
 }

 @Override
 public Emitter<Long> getEmitter(String txStateId, Map conf,
                                TopologyContext context) {
     return emitter;
 }

 @Override
 public Map getComponentConfiguration() {
     return null;
 }

 @Override
 public Fields getOutputFields() {
     return new Fields("event");
 }
}
```

如前面代码中的`getOutputFields()`方法所示，在我们的示例拓扑中，spout 发出一个名为`event`的单个字段，其中包含`DiagnosisEvent`类。

`BatchCoordinator`类实现了以下接口：

```scala
public interface BatchCoordinator<X> {
   X initializeTransaction(long txid, X prevMetadata);
   void success(long txid);
   boolean isReady(long txid);
   void close();
}
```

`BatchCoordinator`类是一个通用类。通用类是重播批次所需的元数据。在我们的示例中，spout 发出随机事件，因此元数据被忽略。然而，在现实世界的系统中，元数据可能包含组成批次的消息或对象的标识符。有了这些信息，不透明和事务性的 spout 可以遵守它们的合同，并确保批次的内容不重叠，并且在事务性 spout 的情况下，批次内容不会改变。

`BatchCoordinator`类被实现为一个在单个线程中运行的 Storm Bolt。Storm 将元数据持久化在 Zookeeper 中。它在每个事务完成时通知协调器。

对于我们的示例，如果我们不进行协调，那么在`DiagnosisEventSpout`类中使用的协调如下：

```scala
public class DefaultCoordinator implements BatchCoordinator<Long>,
                                              Serializable {
   private static final long serialVersionUID = 1L;
private static final Logger LOG = 
             LoggerFactory.getLogger(DefaultCoordinator.class);

@Override
public boolean isReady(long txid) {
   return true;
}

@Override
public void close() {
}

@Override
public Long initializeTransaction(long txid,
                                  Long prevMetadata) {
   LOG.info("Initializing Transaction [" + txid + "]");
   return null;
   }

@Override
public void success(long txid) {
   LOG.info("Successful Transaction [" + txid + "]");
}
}
```

Trident spout 的第二个组件是`Emitter`函数。`Emitter`函数使用收集器发出元组，执行 Storm spout 的功能。唯一的区别是它使用`TridentCollector`类，并且元组必须包含在由`BatchCoordinator`类初始化的批次中。

`Emitter`函数的接口如下代码片段所示：

```scala
public interface Emitter<X> {
void emitBatch(TransactionAttempt tx, X coordinatorMeta,
               TridentCollector collector);
void close();
}
```

如前面的代码所示，`Emitter`函数只有一个任务-为给定的批次发出元组。为此，函数被传递了由协调器构建的批次的元数据，事务的信息以及收集器，`Emitter`函数使用它来发出元组。`DiagnosisEventEmitter`类的列表如下：

```scala
public class DiagnosisEventEmitter implements Emitter<Long>, Serializable {

private static final long serialVersionUID = 1L;
AtomicInteger successfulTransactions = new AtomicInteger(0);

@Override
public void emitBatch(TransactionAttempt tx, Long
                coordinatorMeta, TridentCollector collector) {
   for (int i = 0; i < 10000; i++) {
       List<Object> events = new ArrayList<Object>();
       double lat = 
             new Double(-30 + (int) (Math.random() * 75));
       double lng = 
             new Double(-120 + (int) (Math.random() * 70));
       long time = System.currentTimeMillis();
       String diag = new Integer(320 + 
                       (int) (Math.random() * 7)).toString();
       DiagnosisEvent event = 
                    new DiagnosisEvent(lat, lng, time, diag);
       events.add(event);
       collector.emit(events);
   }
}

@Override
public void success(TransactionAttempt tx) {
   successfulTransactions.incrementAndGet();
}

@Override
public void close() {
}
}
```

工作是在`emitBatch()`方法中执行的。在这个示例中，我们将随机分配一个纬度和经度，大致保持在美国境内，并且我们将使用`System.currentTimeMillis()`方法来为诊断的时间戳。

在现实生活中，ICD-9-CM 代码在 000 到 999 之间稀疏地填充了一个范围。在这个示例中，我们将只使用 320 到 327 之间的诊断代码。这些代码如下所示：

| 代码 | 描述 |
| --- | --- |
| 320 | 细菌性脑膜炎 |
| 321 | 由其他生物引起的脑膜炎 |
| 322 | 未指明原因的脑膜炎 |
| 323 | 脑炎、脊髓炎和脑脊髓炎 |
| 324 | 颅内和脊髓脓肿 |
| 325 | 静脉窦血栓性静脉炎和静脉炎 |
| 326 | 颅内脓肿或化脓感染的后遗症 |
| 327 | 有机性睡眠障碍 |

其中一个诊断代码被随机分配给了事件。

在这个示例中，我们将使用一个对象来封装诊断事件。同样地，我们可以将每个组件作为元组中的单独字段发出。对象封装和元组字段的使用之间存在一种平衡。通常，将字段数量保持在可管理的范围内是一个好主意，但也有道理将用于控制流和/或分组的数据作为元组中的字段包含进来。

在我们的示例中，`DiagnosisEvent`类是拓扑操作的关键数据。该对象如下代码片段所示：

```scala
public class DiagnosisEvent implements Serializable {
    private static final long serialVersionUID = 1L;
    public double lat;
    public double lng;
    public long time;
    public String diagnosisCode;

    public DiagnosisEvent(double lat, double lng,
                       long time, String diagnosisCode) {
   super();
   this.time = time;
   this.lat = lat;
   this.lng = lng;
   this.diagnosisCode = diagnosisCode;
    }
}
```

该对象是一个简单的 JavaBean。时间以长变量的形式存储，这是自纪元以来的时间。纬度和经度分别以双精度存储。`diagnosisCode`类以字符串形式存储，以防系统需要能够处理不基于 ICD-9 的其他类型的代码，比如字母数字代码。

此时，拓扑能够发出事件。在实际实现中，我们可能会将拓扑集成到医疗索赔处理引擎或电子健康记录系统中。

# 引入 Trident 操作-过滤器和函数

现在我们已经生成了事件，下一步是添加实现业务流程的逻辑组件。在 Trident 中，这些被称为**操作**。在我们的拓扑中，我们使用了两种不同类型的操作：过滤器和函数。

通过`Stream`对象上的方法将操作应用于流。在这个示例中，我们在`Stream`对象上使用以下方法：

```scala
public class Stream implements IAggregatableStream {
public Stream each(Fields inputFields, Filter filter) {
...
}

public IAggregatableStream each(Fields inputFields,
Function function,
Fields functionFields){
   ...
}

public GroupedStream groupBy(Fields fields) {
   ...
   }

public TridentState persistentAggregate(
StateFactory stateFactory,
CombinerAggregator agg, 
Fields functionFields) {
        ...
}
}
```

请注意，前面代码中的方法返回`Stream`对象或`TridentState`的形式，可以用来创建额外的流。通过这种方式，操作可以使用流畅的 Java 链接在一起。

让我们再来看一下我们示例拓扑中的关键线路：

```scala
   inputStream.each(new Fields("event"), new DiseaseFilter())
      .each(new Fields("event"), new CityAssignment(),
               new Fields("city"))

      .each(new Fields("event", "city"),
               new HourAssignment(),
             new Fields("hour", "cityDiseaseHour"))

      .groupBy(new Fields("cityDiseaseHour"))

      .persistentAggregate(new OutbreakTrendFactory(),
              new Count(), new Fields("count")).newValuesStream()

      .each(new Fields("cityDiseaseHour", "count"),
               new OutbreakDetector(), new Fields("alert"))

      .each(new Fields("alert"), new DispatchAlert(),
               new Fields());
```

通常，通过声明一组输入字段和一组输出字段，也称为**函数字段**，来应用操作。在前面代码的拓扑的第二行声明，我们希望`CityAssignment`在流中的每个元组上执行。从该元组中，`CityAssignment`将操作`event`字段并发出一个标记为`city`的函数字段，该字段将附加到元组中。

每个操作都有略有不同的流畅式语法，这取决于操作需要的信息。在接下来的部分中，我们将介绍不同操作的语法和语义的细节。

## 引入 Trident 过滤器

我们拓扑中的第一条逻辑是一个**过滤器**，它会忽略那些不相关的疾病事件。在这个例子中，系统将专注于脑膜炎。从之前的表中，脑膜炎的唯一代码是 320、321 和 322。

为了根据代码过滤事件，我们将利用 Trident 过滤器。Trident 通过提供`BaseFilter`类来使这变得容易，我们可以对不关心的元组进行子类化以过滤元组。`BaseFilter`类实现了`Filter`接口，如下代码片段所示：

```scala
public interface Filter extends EachOperation {
    boolean isKeep(TridentTuple tuple);
}
```

要过滤流中的元组，应用程序只需通过扩展`BaseFilter`类来实现这个接口。在这个例子中，我们将使用以下过滤器来过滤事件：

```scala
public class DiseaseFilter extends BaseFilter {
private static final long serialVersionUID = 1L;
private static final Logger LOG = 
LoggerFactory.getLogger(DiseaseFilter.class);

@Override
public boolean isKeep(TridentTuple tuple) {
   DiagnosisEvent diagnosis = (DiagnosisEvent) tuple.getValue(0);
   Integer code = Integer.parseInt(diagnosis.diagnosisCode);
   if (code.intValue() <= 322) {
       LOG.debug("Emitting disease [" + 
diagnosis.diagnosisCode + "]");
       return true;
   } else {
       LOG.debug("Filtering disease [" + 
diagnosis.diagnosisCode + "]");
       return false;
   }
}
}
```

在前面的代码中，我们将从元组中提取`DiagnosisEvent`类并检查疾病代码。由于所有的脑膜炎代码都小于或等于 322，并且我们不发出任何其他代码，我们只需检查代码是否小于 322 来确定事件是否与脑膜炎有关。

从`Filter`操作中返回`True`将导致元组流向下游操作。如果方法返回`False`，元组将不会流向下游操作。

在我们的拓扑中，我们使用`each(inputFields, filter)`方法将过滤器应用于流中的每个元组。我们的拓扑中的以下一行将过滤器应用于流：

```scala
   inputStream.each(new Fields("event"), new DiseaseFilter())
```

## 引入 Trident 函数

除了过滤器，Storm 还提供了一个通用函数的接口。函数类似于 Storm 的 bolt，它们消耗元组并可选择发出新的元组。一个区别是 Trident 函数是增量的。函数发出的值是添加到元组中的字段。它们不会删除或改变现有字段。

函数的接口如下代码片段所示：

```scala
public interface Function extends EachOperation {
void execute(TridentTuple tuple, TridentCollector collector);
}
```

与 Storm 的 bolt 类似，函数实现了一个包含该函数逻辑的单个方法。函数实现可以选择使用`TridentCollector`来发出传入函数的元组。这样，函数也可以用来过滤元组。

我们拓扑中的第一个函数是`CityAssignment`函数，代码如下：

```scala
public class CityAssignment extends BaseFunction {
private static final long serialVersionUID = 1L;
private static final Logger LOG = LoggerFactory.getLogger(CityAssignment.class);

private static Map<String, double[]> CITIES = 
                        new HashMap<String, double[]>();

    { // Initialize the cities we care about.
        double[] phl = { 39.875365, -75.249524 };
        CITIES.put("PHL", phl);
        double[] nyc = { 40.71448, -74.00598 };
        CITIES.put("NYC", nyc);
        double[] sf = { -31.4250142, -62.0841809   };
        CITIES.put("SF", sf);
        double[] la = { -34.05374, -118.24307 };
        CITIES.put("LA", la);
    }

    @Override
    public void execute(TridentTuple tuple, 
TridentCollector collector) {
       DiagnosisEvent diagnosis = 
                           (DiagnosisEvent) tuple.getValue(0);
       double leastDistance = Double.MAX_VALUE;
       String closestCity = "NONE";

       // Find the closest city.
       for (Entry<String, double[]> city : CITIES.entrySet()) {
          double R = 6371; // km
          double x = (city.getValue()[0] - diagnosis.lng) * 
             Math.cos((city.getValue()[0] + diagnosis.lng) / 2);
          double y = (city.getValue()[1] - diagnosis.lat);
          double d = Math.sqrt(x * x + y * y) * R;
          if (d < leastDistance) {
          leastDistance = d;
          closestCity = city.getKey();
          }
      }

      // Emit the value.
      List<Object> values = new ArrayList<Object>();
      Values.add(closestCity);
      LOG.debug("Closest city to lat=[" + diagnosis.lat + 
                "], lng=[" + diagnosis.lng + "] == ["
                + closestCity + "], d=[" + leastDistance + "]");
      collector.emit(values);
    }
}
```

在这个函数中，我们使用静态初始化器来创建我们关心的城市的地图。对于示例数据，该函数有一个包含费城（PHL）、纽约市（NYC）、旧金山（SF）和洛杉矶（LA）坐标的地图。

在`execute()`方法中，函数循环遍历城市并计算事件与城市之间的距离。在真实系统中，地理空间索引可能更有效。

一旦函数确定了最近的城市，它会在方法的最后几行发出该城市的代码。请记住，在 Trident 中，函数不是声明它将发出哪些字段，而是在操作附加到流时作为函数调用中的第三个参数声明字段。

声明的函数字段数量必须与函数发出的值的数量对齐。如果它们不对齐，Storm 将抛出`IndexOutOfBoundsException`。

我们拓扑中的下一个函数`HourAssignment`用于将时间戳转换为自纪元以来的小时，然后可以用于在时间上对事件进行分组。`HourAssignment`的代码如下：

```scala
public class HourAssignment extends BaseFunction {
private static final long serialVersionUID = 1L;
private static final Logger LOG =    
               LoggerFactory.getLogger(HourAssignment.class);

@Override
public void execute(TridentTuple tuple,
                   TridentCollector collector) {
   DiagnosisEvent diagnosis = (DiagnosisEvent) tuple.getValue(0);
   String city = (String) tuple.getValue(1);

   long timestamp = diagnosis.time;
   long hourSinceEpoch = timestamp / 1000 / 60 / 60;

   LOG.debug("Key =  [" + city + ":" + hourSinceEpoch + "]");
   String key = city + ":" + diagnosis.diagnosisCode + ":" + 

                hourSinceEpoch;

   List<Object> values = new ArrayList<Object>();
   values.add(hourSinceEpoch);
   values.add(key);
   collector.emit(values);
}
}
```

我们通过发出*小时*以及由城市、诊断代码和小时组成的复合键来略微重载此函数。实际上，这充当了每个聚合计数的唯一标识符，我们将在详细讨论。

我们拓扑中的最后两个函数检测爆发并通知我们。`OutbreakDetector`类的代码如下：

```scala
public class OutbreakDetector extends BaseFunction {
    private static final long serialVersionUID = 1L;
    public static final int THRESHOLD = 10000;

    @Override
    public void execute(TridentTuple tuple,
                         TridentCollector collector) {
   String key = (String) tuple.getValue(0);
   Long count = (Long) tuple.getValue(1);

   if (count > THRESHOLD) {
       List<Object> values = new ArrayList<Object>();
       values.add("Outbreak detected for [" + key + "]!");
       collector.emit(values);
   }
}
}
```

此函数提取特定城市、疾病和小时的计数，并查看是否超过了阈值。如果是，它会发出一个包含警报的新字段。在上述代码中，请注意，这个函数实际上充当了一个过滤器，但由于我们想要向包含警报的元组添加一个额外的字段，因此实现为函数。由于过滤器不会改变元组，我们必须使用一个允许我们不仅过滤而且添加新字段的函数。

我们拓扑中的最后一个函数只是分发警报（并终止程序）。此拓扑的清单如下：

```scala
public class DispatchAlert extends BaseFunction {
    private static final long serialVersionUID = 1L;

    @Override
    public void execute(TridentTuple tuple, 
                     TridentCollector collector) {
   String alert = (String) tuple.getValue(0);
   Log.error("ALERT RECEIVED [" + alert + "]");
   Log.error("Dispatch the national guard!");
   System.exit(0);
   }
}
```

这个函数很简单。它只是提取警报，记录消息，并终止程序。

# 介绍 Trident 聚合器-组合器和减少器

与函数类似，**聚合器**允许拓扑结构组合元组。与函数不同，它们替换元组字段和值。有三种不同类型的聚合器：`CombinerAggregator`，`ReducerAggregator`和`Aggregator`。

## CombinerAggregator

`CombinerAggregator`用于将一组元组组合成一个单一字段。它具有以下签名：

```scala
public interface CombinerAggregator {
   T init (TridentTuple tuple);
   T combine(T val1, T val2);
   T zero();
}
```

Storm 对每个元组调用`init()`方法，然后重复调用`combine()`方法，直到分区被处理。传递到`combine()`方法的值是部分聚合，是通过调用`init()`返回的值的组合结果。分区将在后续会话中更详细地讨论，但分区实际上是流元组的子集，驻留在同一主机上。在处理元组的值后，Storm 将组合这些值的结果作为单个新字段发出。如果分区为空，则 Storm 会发出`zero()`方法返回的值。

## ReducerAggregator

`ReducerAggregator`具有稍微不同的签名：

```scala
public interface ReducerAggregator<T> extends Serializable {
    T init();
    T reduce(T curr, TridentTuple tuple);
}
```

Storm 调用`init()`方法来检索初始值。然后，对每个元组调用`reduce()`，直到分区完全处理。传递到`reduce()`方法的第一个参数是累积的部分聚合。实现应返回将元组合并到该部分聚合中的结果。

## Aggregator

最一般的聚合操作是`Aggregator`。`Aggregator`的签名如下：

```scala
public interface Aggregator<T> extends Operation {
    T init(Object batchId, TridentCollector collector);
    void aggregate(T val, TridentTuple tuple,
TridentCollector collector);
 void complete(T val, TridentCollector collector);
}
```

`Aggregator`接口的`aggregate()`方法类似于`Function`接口的`execute()`方法，但它还包括一个值的参数。这允许`Aggregator`在处理元组时累积一个值。请注意，使用`Aggregator`，由于收集器被传递到`aggregate()`方法和`complete()`方法中，您可以发出任意数量的元组。

在我们的示例拓扑中，我们利用了一个名为`Count`的内置聚合器。`Count`的实现如下代码片段所示：

```scala
public class Count implements CombinerAggregator<Long> {
    @Override
    public Long init(TridentTuple tuple) {
        return 1L;
    }

    @Override
    public Long combine(Long val1, Long val2) {
        return val1 + val2;
    }

    @Override
    public Long zero() {
        return 0L;
    }
}
```

在我们的示例拓扑中，我们应用了分组和计数来计算特定城市附近特定小时内疾病发生的次数。实现这一目标的具体行为如下：

```scala
.groupBy(new Fields("cityDiseaseHour"))
.persistentAggregate(new OutbreakTrendFactory(), 
   new Count(), new Fields("count")).newValuesStream()
```

回想一下，Storm 将流分区到可用的主机上。这在下图中显示：

![Aggregator](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/storm-bp/img/8294OS_03_02.jpg)

`groupBy()`方法强制对数据进行重新分区。它将所有具有相同命名字段值的元组分组到同一分区中。为此，Storm 必须将相似的元组发送到同一主机。以下图表显示了根据我们的`groupBy()`方法对前述数据进行的重新分区：

![聚合器](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/storm-bp/img/8294OS_03_03.jpg)

重新分区后，在每个分区内的每个组上运行`aggregate`函数。在我们的示例中，我们按城市、小时和疾病代码（使用键）进行分组。然后，在每个组上执行`Count`聚合器，进而为下游消费者发出发生次数。

# 引入 Trident 状态

现在我们已经得到了每个聚合的计数，我们希望将该信息持久化以供进一步分析。在 Trident 中，持久化首先从状态管理开始。Trident 具有一级状态的原始形式，但与 Storm API 一样，它对存储为状态或状态如何持久化做出了一些假设。在最高级别，Trident 公开了一个`State`接口，如下所示：

```scala
public interface State {
   void beginCommit(Long transactionId); 
   void commit(Long transactionId);
}
```

如前所述，Trident 将元组分组为批处理。每个批处理都有自己的事务标识符。在前面的接口中，Trident 在状态被提交时通知`State`对象，以及何时应完成提交。

与函数一样，在`Stream`对象上有一些方法将基于状态的操作引入拓扑。更具体地说，Trident 中有两种类型的流：`Stream`和`GroupedStream`。`GroupedStream`是执行`groupBy`操作的结果。在我们的拓扑中，我们通过`HourAssignment`函数生成的键进行分组。

在`Stream`对象上，以下方法允许拓扑读取和写入状态信息：

```scala
public class Stream implements IAggregatableStream {
    ...
    public Stream stateQuery(TridentState state, Fields inputFields,
            QueryFunction function, Fields functionFields) {
   ...
 }

public TridentState partitionPersist(StateFactory stateFactory,
Fields inputFields, StateUpdater updater,
Fields functionFields) {
   ...
}

public TridentState partitionPersist(StateSpec stateSpec,
Fields inputFields, StateUpdater updater,
Fields functionFields) {
   ...
}

public TridentState partitionPersist(StateFactory stateFactory,
Fields inputFields, StateUpdater updater) {
   ...
   }

public TridentState partitionPersist(StateSpec stateSpec,
Fields inputFields, StateUpdater updater) {
    ...
}
...
}
```

`stateQuery()`方法从状态创建输入流，`partitionPersist()`方法的各种变种允许拓扑从流中的元组更新状态信息。`partitionPersist()`方法在每个分区上操作。

除了`Stream`对象上的方法之外，`GroupedStream`对象允许拓扑从一组元组中聚合统计信息，并同时将收集到的信息持久化到状态。以下是`GroupedStream`类上与状态相关的方法：

```scala
public class GroupedStream implements IAggregatableStream,
GlobalAggregationScheme<GroupedStream> {
...
   public TridentState persistentAggregate(
StateFactory stateFactory, CombinerAggregator agg,
Fields functionFields) {
...
}

public TridentState persistentAggregate(StateSpec spec,
CombinerAggregator agg, Fields functionFields) {
...
}

public TridentState persistentAggregate(
StateFactory stateFactory, Fields inputFields,
CombinerAggregator agg, Fields functionFields) {
...
}

public TridentState persistentAggregate(StateSpec spec,
Fields inputFields, CombinerAggregator agg,
Fields functionFields) {
...
}

public TridentState persistentAggregate(
StateFactory stateFactory, Fields inputFields,
ReducerAggregator agg, Fields functionFields) {
...
}

public TridentState persistentAggregate(StateSpec spec, Fields inputFields, ReducerAggregator agg, Fields functionFields) {
...
}

public Stream stateQuery(TridentState state, Fields inputFields,
QueryFunction function, Fields functionFields) {
...
}    

public TridentState persistentAggregate(
StateFactory stateFactory, ReducerAggregator agg,
Fields functionFields) {
...
}

public TridentState persistentAggregate(StateSpec spec,
ReducerAggregator agg, Fields functionFields) {
...
}    

public Stream stateQuery(TridentState state,
   QueryFunction function, Fields functionFields) {
...
}
}
```

像基本的`Stream`对象一样，`stateQuery()`方法从状态创建输入流。各种`persistAggregate()`的变种允许拓扑从流中的元组更新状态信息。请注意，`GroupedStream`方法采用`Aggregator`，它首先应用然后将信息写入`State`对象。

现在让我们考虑将这些函数应用到我们的示例中。在我们的系统中，我们希望按城市、疾病代码和小时持久化发生次数。这将使报告类似于以下表格：

| 疾病 | 城市 | 日期 | 时间 | 发生次数 |
| --- | --- | --- | --- | --- |
| 细菌性脑膜炎 | 旧金山 | 2013 年 3 月 12 日 | 下午 3:00 | 12 |
| 细菌性脑膜炎 | 旧金山 | 2013 年 3 月 12 日 | 下午 4:00 | 50 |
| 细菌性脑膜炎 | 旧金山 | 2013 年 3 月 12 日 | 下午 5:00 | 100 |
| 天花 | 纽约 | 2013 年 3 月 13 日 | 下午 5:00 | 6 |

为了实现这一点，我们希望持久化我们在聚合中生成的计数。我们可以使用`groupBy`函数返回的`GroupedStream`接口（如前所示），并调用`persistAggregate`方法。具体来说，以下是我们在示例拓扑中进行的调用：

```scala
 persistentAggregate(new OutbreakTrendFactory(), 
   new Count(), new Fields("count")).newValuesStream()
```

要理解持久化，我们首先将关注此方法的第一个参数。Trident 使用工厂模式生成`State`的实例。`OutbreakTrendFactory`是我们的拓扑提供给 Storm 的工厂。`OutbreakTrendFactory`的清单如下：

```scala
public class OutbreakTrendFactory implements StateFactory {
private static final long serialVersionUID = 1L;

@Override
public State makeState(Map conf, IMetricsContext metrics,
int partitionIndex, int numPartitions) {
   return new OutbreakTrendState(new OutbreakTrendBackingMap());
}
}
```

工厂返回 Storm 用于持久化信息的`State`对象。在 Storm 中，有三种类型的状态。每种类型在下表中描述：

| **状态类型** | 描述 |
| --- | --- |
| **非事务性** | 对于没有回滚能力的持久性机制，更新是永久的，提交被忽略。 |
| **重复事务** | 对于幂等性的持久性，只要批次包含相同的元组。 |
| **不透明事务** | 更新基于先前的值，这使得持久性对批次组成的更改具有弹性。 |

为了支持在分布式环境中对批次进行重播的计数和状态更新，Trident 对状态更新进行排序，并使用不同的状态更新模式来容忍重播和故障。这些在以下部分中描述。

## 重复事务状态

对于重复事务状态，最后提交的批处理标识符与数据一起存储。只有在应用的批处理标识符是下一个顺序时，状态才会更新。如果它等于或低于持久标识符，则更新将被忽略，因为它已经被应用过了。

为了说明这种方法，考虑以下批次序列，其中状态更新是该键出现次数的聚合计数，如我们的示例中所示：

| 批次 # | 状态更新 |
| --- | --- |
| 1 | {SF:320:378911 = 4} |
| 2 | {SF:320:378911 = 10} |
| 3 | {SF:320:378911 = 8} |

然后批次按以下顺序完成处理：

1 à 2 à 3 à 3 (重播)

这将导致以下状态修改，其中中间列是批次标识符的持久性，指示状态中最近合并的批次：

| 完成的批次 # | 状态 |
| --- | --- |
| 1 | { 批次 = 1 } | { SF:320:378911 = 4 } |
| 2 | { 批次 = 2 } | { SF:320:378911 = 14 } |
| 3 | { 批次 = 3 } | { SF:320:378911 = 22 } |
| 3 (重播) | { 批次 = 3 } | { SF:320:378911 = 22 } |

请注意，当批次 #3 完成重播时，它对状态没有影响，因为 Trident 已经在状态中合并了它的更新。为了使重复事务状态正常工作，批次内容在重播之间不能改变。

## 不透明状态

重复事务状态所使用的方法依赖于批次组成保持不变，如果系统遇到故障，则可能不可能。如果喷口从可能存在部分故障的源发出，那么初始批次中发出的一些元组可能无法重新发出。不透明状态允许通过存储当前状态和先前状态来改变批次组成。

假设我们有与前面示例中相同的批次，但是这次当批次 3 重播时，聚合计数将不同，因为它包含了不同的元组集，如下表所示：

| 批次 # | 状态更新 |
| --- | --- |
| 1 | {SF:320:378911 = 4} |
| 2 | {SF:320:378911 = 10} |
| 3 | {SF:320:378911 = 8} |
| 3 (重播) | {SF:320:378911 = 6} |

对于不透明状态，状态将如下更新：

| 完成的批次 # | 批次已提交 | 先前状态 | 当前状态 |
| --- | --- | --- | --- |
| 1 | 1 | {} | { SF:320:378911 = 4 } |
| 2 | 2 | { SF:320:378911 = 4 } | { SF:320:378911 = 14 } |
| 3 (应用) | 3 | { SF:320:378911 = 14 } | { SF:320:378911 = 22 } |
| 3 (重播) | 3 | { SF:320:378911 = 14 } | { SF:320:378911 = 20 } |

请注意，不透明状态存储了先前的状态信息。因此，当批次 #3 被重播时，它可以使用新的聚合计数重新转换状态。

也许你会想为什么我们会重新应用已经提交的批次。我们关心的情景是，状态更新成功，但下游处理失败。在我们的示例拓扑中，也许警报发送失败了。在这种情况下，Trident 会重试批次。现在，在最坏的情况下，当喷口被要求重新发出批次时，一个或多个数据源可能不可用。

在 Transactional spout 的情况下，它需要等待直到所有的源再次可用。不透明的 Transactional spout 将能够发出可用的批次部分，处理可以继续进行。由于 Trident 依赖于对状态的批次的顺序应用，因此至关重要的是不要延迟任何一个批次，因为这会延迟系统中的所有处理。

鉴于这种方法，状态的选择应该基于 spout，以保证幂等行为，不会过度计数或损坏状态。以下表格显示了保证幂等行为的可能配对：

| Spout 类型 | 非事务状态 | 不透明状态 | 重复事务状态 |
| --- | --- | --- | --- |
| 非事务 spout |   |   |   |
| 不透明 spout |   | X |   |
| 事务 spout |   | X | X |

幸运的是，Storm 提供了地图实现，可以将持久性层屏蔽在状态管理的复杂性之外。具体来说，Trident 提供了`State`实现，可以维护额外的信息，以遵守先前概述的保证。这些对象的命名很合适：`NonTransactionalMap`，`TransactionalMap`和`OpaqueMap`。

回到我们的示例，由于我们没有事务保证，我们选择使用`NonTransactionalMap`作为我们的`State`对象。

`OutbreakTrendState`对象如下代码片段所示：

```scala
public class OutbreakTrendState extends NonTransactionalMap<Long> {
protected OutbreakTrendState(
OutbreakTrendBackingMap outbreakBackingMap) {
   super(outbreakBackingMap);
}
}
```

如前面的代码所示，要利用`MapState`对象，我们只需传递一个支持映射。在我们的示例中，这是`OutbreakTrendBackingMap`。该对象的代码如下：

```scala
public class OutbreakTrendBackingMap implements IBackingMap<Long> {
    private static final Logger LOG = 
LoggerFactory.getLogger(OutbreakTrendBackingMap.class);
 Map<String, Long> storage = 
new ConcurrentHashMap<String, Long>();

 @Override
 public List<Long> multiGet(List<List<Object>> keys) {
    List<Long> values = new ArrayList<Long>();
    for (List<Object> key : keys) {
        Long value = storage.get(key.get(0));
        if (value==null){
            values.add(new Long(0));
        } else {
            values.add(value);
        }
    }
    return values;
}

@Override
public void multiPut(List<List<Object>> keys, List<Long> vals) {
    for (int i=0; i < keys.size(); i++) {
        LOG.info("Persisting [" + keys.get(i).get(0) + "] ==> [" 
+ vals.get(i) + "]");
        storage.put((String) keys.get(i).get(0), vals.get(i));
    }
}
}
```

在我们的示例拓扑中，我们实际上并不持久化值。我们只是把它们放在`ConcurrentHashMap`中。显然，这在多个主机上是行不通的。然而，`BackingMap`是一个巧妙的抽象。只需改变我们传递给`MapState`对象构造函数的支持映射实例，就可以改变持久性层。我们将在后面的章节中看到这一点。

# 执行拓扑

`OutbreakDetectionTopology`类有以下主要方法：

```scala
public static void main(String[] args) throws Exception {
    Config conf = new Config();
    LocalCluster cluster = new LocalCluster();
    cluster.submitTopology("cdc", conf, buildTopology());
    Thread.sleep(200000);
    cluster.shutdown();
}
```

执行此方法将拓扑提交到本地集群。spout 将立即开始发出诊断事件，`Count`聚合器将收集。`OutbreakDetector`类中的阈值设置得很快就会超过阈值，此时程序将终止，并显示以下一系列命令：

```scala
INFO [Thread-18] DefaultCoordinator.success(31) | Successful Transaction [8]
INFO [Thread-18] DefaultCoordinator.initializeTransaction(25) | Initializing Transaction [9]
...
INFO [Thread-24] OutbreakTrendBackingMap.multiPut(34) | Persisting [SF:320:378951] ==> [10306]
INFO [Thread-24] OutbreakTrendBackingMap.multiPut(34) | Persisting [PHL:320:378951] ==> [893]
INFO [Thread-24] OutbreakTrendBackingMap.multiPut(34) | Persisting [NYC:322:378951] ==> [1639]
INFO [Thread-24] OutbreakTrendBackingMap.multiPut(34) | Persisting [SF:322:378951] ==> [10254]
INFO [Thread-24] OutbreakTrendBackingMap.multiPut(34) | Persisting [SF:321:378951] ==> [10386]
...
00:04 ERROR: ALERT RECEIVED [Outbreak detected for [SF:320:378951]!]
00:04 ERROR: Dispatch the National Guard!

```

请注意，协调器在批次成功完成时会收到通知，几个批次后，阈值被超过，系统会用错误消息`Dispatch the National Guard!`指示我们。

# 摘要

在本章中，我们创建了一个拓扑，处理诊断信息以识别异常情况，这可能表明有疫情爆发。这些相同的数据流可以应用于任何类型的数据，包括天气、地震信息或交通数据。我们运用了 Trident 中的基本原语来构建一个系统，即使批次被重放，也能够计数事件。在本书的后面，我们将利用这些相同的结构和模式来执行类似的功能。
