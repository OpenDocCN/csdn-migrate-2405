# Storm 和 Cassandra 实时分析（一）

> 原文：[`zh.annas-archive.org/md5/7C24B06720C9BE51000AF16D45BAD7FF`](https://zh.annas-archive.org/md5/7C24B06720C9BE51000AF16D45BAD7FF)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

风暴最初是 Twitter 公司的一个项目，已经毕业并加入 Apache 联盟，因此从 Twitter 风暴改名。这是 Nathan Marz 的心血结晶，现在被 Cloudera 的包括 Apache Hadoop（CDH）和 Hortonworks 数据平台（HDP）等联盟所采用。

Apache Storm 是一个高度可扩展、分布式、快速、可靠的实时计算系统，旨在处理非常高速的数据。Cassandra 通过提供闪电般快速的读写能力来补充计算能力，这是目前与风暴一起提供的最佳数据存储组合。

风暴计算和卡桑德拉存储的结合正在帮助技术传道者解决涉及复杂和大数据量情况的各种业务问题，例如实时客户服务、仪表板、安全性、传感器数据分析、数据货币化等等。

本书将使用户能够利用风暴的处理能力与 Cassandra 的速度和可靠性相结合，开发实时用例的生产级企业解决方案。

# 本书内容

第一章，“让我们了解风暴”，让您熟悉需要分布式计算解决方案的问题。它将带您了解风暴及其出现的过程。

第二章，“开始您的第一个拓扑”，教您如何设置开发者环境——沙盒，并执行一些代码示例。

第三章，“通过示例了解风暴内部”，教您如何准备风暴的喷嘴和自定义喷嘴。您将了解风暴提供的各种分组类型及其在实际问题中的应用。

第四章，“集群模式下的风暴”，教您如何设置多节点风暴集群，使用户熟悉分布式风暴设置及其组件。本章还将让您熟悉风暴 UI 和各种监控工具。

第五章，“风暴高可用性和故障转移”，将风暴拓扑与 RabbitMQ 代理服务相结合，并通过各种实际示例探讨风暴的高可用性和故障转移场景。

第六章，“向风暴添加 NoSQL 持久性”，向您介绍 Cassandra，并探讨可用于与 Cassandra 一起工作的各种包装 API。我们将使用 Hector API 连接风暴和 Cassandra。

第七章，“Cassandra 分区”、“高可用性和一致性”，带您了解 Cassandra 的内部。您将了解并应用高可用性、暗示的转交和最终一致性的概念，以及它们在 Cassandra 中的上下文中的应用。

第八章，“Cassandra 管理和维护”，让您熟悉 Cassandra 的管理方面，如扩展集群、节点替换等，从而为您提供处理 Cassandra 实际情况所需的全部经验。

第九章，“风暴管理和维护”，让您熟悉风暴的管理方面，如扩展集群、设置并行性和故障排除风暴。

第十章，*Storm 中的高级概念*，让您了解 Trident API。您将使用一些示例和说明来构建 Trident API。

第十一章，*使用 Storm 进行分布式缓存和 CEP*，让您了解分布式缓存，其需求以及在 Storm 中解决实际用例的适用性。它还将教育您关于 Esper 作为 CEP 与 Storm 结合使用。

附录，*测验答案*，包含对真假陈述和填空部分问题的所有答案。

*奖励章节*，*使用 Storm 和 Cassandra 解决实际用例*，解释了一些实际用例和使用诸如 Storm 和 Cassandra 等技术解决这些用例的蓝图。这一章节可以在[`www.packtpub.com/sites/default/files/downloads/Bonus_Chapter.pdf`](https://www.packtpub.com/sites/default/files/downloads/Bonus_Chapter.pdf)上找到。

# 您需要本书的什么

对于本书，您将需要 Linux/Ubuntu 操作系统、Eclipse 和 8GB 的 RAM。有关设置其他组件（如 Storm、RabbitMQ、Cassandra、内存缓存、Esper 等）的步骤在相应主题的章节中有所涵盖。

# 这本书适合谁

本书适用于希望使用 Storm 开始进行近实时分析的 Java 开发人员。这将作为开发高可用性和可扩展解决方案以解决复杂实时问题的专家指南。除了开发，本书还涵盖了 Storm 和 Cassandra 的管理和维护方面，这是任何解决方案投入生产的强制要求。

# 约定

在本书中，您会发现一些文本样式，用于区分不同类型的信息。以下是一些这些样式的示例，以及它们的含义解释。

文本中的代码单词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下："在 Storm 中定义的`NumWorker`配置或`TOPOLOGY_WORKERS`配置"。

代码块设置如下：

```scala
// instantiates the new builder object
TopologyBuilder builder = new TopologyBuilder();
// Adds a new spout of type "RandomSentenceSpout" with a  parallelism hint of 5
builder.setSpout("spout", new RandomSentenceSpout(), 5);
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目会被突出显示：

```scala
  public void execute(Tuple tuple) {
      String sentence = tuple.getString(0);
      for(String word: sentence.split(" ")) {
          _collector.emit(tuple, new Values(word)); //1
      }
      _collector.ack(tuple); //2
  }
  public void declareOutputFields(OutputFieldsDeclarer  declarer) {
      declarer.declare(new Fields("word")); //3
  }
}
```

任何命令行输入或输出都以以下方式编写：

```scala
sudo apt-get -qy install rabbitmq-server

```

**新术语**和**重要单词**以粗体显示。例如，屏幕上看到的菜单或对话框中的单词会以这种方式出现在文本中："转到**管理**选项卡，选择**策略**，然后单击**添加策略**"。

### 注意

警告或重要说明会以这样的方式出现在一个框中。

### 提示

提示和技巧是这样显示的。


# 第一章：让我们了解风暴

在本章中，您将熟悉需要分布式计算解决方案的问题，并了解创建和管理此类解决方案可能变得多么复杂。我们将研究解决分布式计算的可用选项。

本章将涵盖以下主题：

+   熟悉需要分布式计算解决方案的一些问题

+   现有解决方案的复杂性

+   提供实时分布式计算的技术

+   对 Storm 各个组件的高层次视图

+   飞机通信寻址和报告系统的内部快速查看

在本章结束时，您将能够了解 Apache Storm 的实时场景和应用。您应该了解市场上提供的解决方案以及 Storm 仍然是最佳开源选择的原因。

# 分布式计算问题

让我们深入了解一些需要分布式解决方案的问题。在我们今天生活的世界中，我们对现在的力量如此敏感，这就产生了分布式实时计算的需求。银行、医疗保健、汽车制造等领域是实时计算可以优化或增强解决方案的中心。

## 实时商业解决方案，用于信用卡或借记卡欺诈检测

让我们熟悉以下图中描述的问题；当我们使用塑料货币进行任何交易并刷卡进行付款时，银行必须在五秒内验证或拒绝交易。在不到五秒的时间内，数据或交易细节必须加密，通过安全网络从服务银行到发卡银行，然后在发卡银行计算交易的接受或拒绝的整个模糊逻辑，并且结果必须通过安全网络返回。

实时商业解决方案，用于信用卡或借记卡欺诈检测

实时信用卡欺诈检测

挑战，如网络延迟和延迟，可以在一定程度上进行优化，但要在 5 秒内实现前述特性交易，必须设计一个能够处理大量数据并在 1 到 2 秒内生成结果的应用程序。

## 飞机通信寻址和报告系统

飞机通信寻址和报告系统（ACAR）展示了另一个典型的用例，如果没有可靠的实时处理系统，就无法实现。这些飞机通信系统使用卫星通信（SATCOM），根据以下图，它们实时收集来自飞行各个阶段的语音和数据包数据，并能够实时生成分析和警报。

飞机通信寻址和报告系统

让我们以前述案例中的图为例。飞行遭遇一些真正危险的天气，比如航线上的电暴，然后通过卫星链路和语音或数据网关将该信息发送给空中管制员，后者实时检测并发出警报，以便所有通过该区域的其他航班改变航线。

## 医疗保健

在这里，让我们向您介绍医疗保健的另一个问题。

这是另一个非常重要的领域，实时分析高容量和速度数据，为医疗保健专业人员提供准确和精确的实时信息，以采取知情的挽救生命行动。

医疗保健

前面的图表描述了医生可以采取明智行动来处理患者的医疗情况的用例。数据来自历史患者数据库、药物数据库和患者记录。一旦数据被收集，它就被处理，患者的实时统计数据和关键参数被绘制到相同的汇总数据上。这些数据可以用来进一步生成报告和警报，以帮助医护人员。

## 其他应用

还有各种其他应用，实时计算的力量可以优化或帮助人们做出明智的决定。它已成为以下行业的重要工具和辅助：

+   **制造业**：实时的缺陷检测机制可以帮助优化生产成本。通常，在制造业领域，质量控制是在生产后进行的，由于货物中存在类似的缺陷，整批货物就会被拒绝。

+   **交通运输行业**：基于实时交通和天气数据，运输公司可以优化其贸易路线，节省时间和金钱。

+   **网络优化**：基于实时网络使用警报，公司可以设计自动扩展和自动缩减系统，以适应高峰和低谷时段。

# 复杂分布式用例的解决方案

现在我们了解了实时解决方案可以在各个行业垂直领域发挥的作用，让我们探索并找出我们在处理大量数据时产生的各种选择。

## Hadoop 解决方案

Hadoop 解决方案是解决需要处理海量数据问题的解决方案之一。它通过在集群设置中执行作业来工作。

MapReduce 是一种编程范例，我们通过使用一个处理键和值对的 mapper 函数来处理大数据集，从而生成中间输出，再次以键值对的形式。然后，减速函数对 mapper 输出进行操作，并合并与相同中间键相关联的值，并生成结果。

![Hadoop 解决方案](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/rt-anlt-storm-csdr/img/00005.jpeg)

在前面的图中，我们演示了简单的单词计数 MapReduce 作业，其中使用 MapReduce 演示了简单的单词计数作业，其中：

+   有一个巨大的大数据存储，可以达到赫兹或皮字节。

+   输入数据集或文件被分割成配置大小的块，并根据复制因子在 Hadoop 集群中的多个节点上复制每个块。

+   每个 mapper 作业计算分配给它的数据块上的单词数。

+   一旦 mapper 完成，单词（实际上是键）及其计数存储在 mapper 节点上的本地文件中。然后，减速器启动减速功能，从而生成结果。

+   Reducer 将 mapper 输出合并，生成最终结果。

大数据，正如我们所知，确实提供了一种处理和生成结果的解决方案，但这主要是一个批处理系统，在实时使用情况下几乎没有用处。

## 一个定制的解决方案

在这里，我们谈论的是在我们拥有可扩展框架（如 Storm）之前在社交媒体世界中使用的解决方案。问题的一个简化版本可能是，您需要实时统计每个用户的推文数量；Twitter 通过遵循图中显示的机制解决了这个问题：

![一个定制的解决方案](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/rt-anlt-storm-csdr/img/00006.jpeg)

以下是前述机制的详细信息：

+   一个定制的解决方案创建了一个消防软管或队列，所有推文都被推送到这个队列上。

+   一组工作节点从队列中读取数据，解析消息，并维护每个用户的推文计数。该解决方案是可扩展的，因为我们可以增加工作人员的数量来处理系统中的更多负载。但是，用于将数据随机分布在这些工作节点中的分片算法应该确保数据均匀分布给所有工作节点。

+   这些工作人员将第一级计数合并到下一组队列中。

+   从这些队列（在第 1 级提到的队列）中，第二级工作人员从这些队列中挑选。在这里，这些工作人员之间的数据分布既不均匀，也不随机。负载平衡或分片逻辑必须确保来自同一用户的推文始终应该发送到同一个工作人员，以获得正确的计数。例如，假设我们有不同的用户——"A、K、M、P、R 和 L"，我们有两个工作人员"工作人员 A"和"工作人员 B"。来自用户"A、K 和 M"的推文总是发送到"工作人员 A"，而来自"P、R 和 L 用户"的推文发送到"工作人员 B"；因此"A、K 和 M"的推文计数始终由"工作人员 A"维护。最后，这些计数被转储到数据存储中。

在前面的点中描述的队列工作解决方案对我们的特定用例效果很好，但它有以下严重的限制：

+   这是非常复杂的，具体到使用情况

+   重新部署和重新配置是一项巨大的任务

+   扩展非常繁琐

+   系统不具备容错性

## 有许可的专有解决方案

在开源 Hadoop 和自定义队列工作解决方案之后，让我们讨论市场上的有许可选项的专有解决方案，以满足分布式实时处理的需求。

大公司的**阿拉巴马州职业治疗协会**（**ALOTA**）已经投资于这类产品，因为他们清楚地看到计算的未来发展方向。他们可以预见到这类解决方案的需求，并在几乎每个垂直领域支持它们。他们已经开发了这样的解决方案和产品，让我们进行复杂的批处理和实时计算，但这需要付出沉重的许可成本。一些公司的解决方案包括：

+   **IBM**：IBM 开发了 InfoSphere Streams，用于实时摄入、分析和数据相关性。

+   **Oracle**：Oracle 有一个名为**实时决策**（**RTD**）的产品，提供实时环境下的分析、机器学习和预测

+   **GigaSpaces**：GigaSpaces 推出了一个名为**XAP**的产品，提供内存计算以提供实时结果

## 其他实时处理工具

还有一些其他技术具有一些类似的特征和功能，如雅虎的 Apache Storm 和 S4，但它缺乏保证处理。Spark 本质上是一个批处理系统，具有一些微批处理的功能，可以用作实时处理。

# Storm 各个组件的高级视图

在本节中，我们将让您了解 Storm 的各个组件，它们的作用以及它们在 Storm 集群中的分布。

Storm 集群有三组节点（可以共同定位，但通常分布在集群中），分别是：

+   Nimbus

+   Zookeeper

+   监督者

以下图显示了这些节点的集成层次结构：

![Storm 各个组件的高级视图](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/rt-anlt-storm-csdr/img/00007.jpeg)

集成层次结构的详细解释如下：

+   **Nimbus 节点**（类似于 Hadoop-JobTracker 的主节点）：这是 Storm 集群的核心。你可以说这是负责以下工作的主要守护进程：

+   上传和分发各种任务到集群中

+   上传和分发拓扑 JAR 作业到各个监督者

+   根据分配给监督者节点的端口启动工作人员

+   监视拓扑执行并在必要时重新分配工作人员

+   Storm UI 也在同一节点上执行

+   **Zookeeper 节点**：Zookeeper 可以被指定为 Storm 集群中的簿记员。一旦拓扑作业从 Nimbus 节点提交并分发，即使 Nimbus 死亡，拓扑也会继续执行，因为只要 Zookeeper 还活着，可工作状态就会被它们维护和记录。这个组件的主要责任是维护集群的运行状态，并在需要从某些故障中恢复时恢复运行状态。它是 Storm 集群的协调者。

+   **监督者节点**：这些是 Storm 拓扑中的主要处理室；所有操作都在这里进行。这些是守护进程，通过 Zookeeper 与 Nimbus 通信，并根据 Nimbus 的信号启动和停止工作进程。

# 深入了解 Storm 的内部

现在我们知道了 Storm 集群中存在哪些物理组件，让我们了解拓扑提交时各种 Storm 组件内部发生了什么。当我们说拓扑提交时，意味着我们已经向 Storm Nimbus 提交了一个分布式作业，以在监督者集群上执行。在本节中，我们将解释 Storm 拓扑在各种 Storm 组件中执行时所执行的各种步骤：

+   拓扑被提交到 Nimbus 节点。

+   Nimbus 在所有监督者上上传代码 jar，并指示监督者根据 Storm 中定义的`NumWorker`配置或`TOPOLOGY_WORKERS`配置启动工作进程。

+   在同一时间段内，所有 Storm 节点（Nimbus 和监督者）不断与 Zookeeper 集群协调，以维护工作进程及其活动的日志。

根据以下图，我们已经描述了拓扑结构和拓扑组件的分布，这在所有集群中都是相同的：

![深入了解 Storm 的内部](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/rt-anlt-storm-csdr/img/00008.jpeg)

在我们的情况下，假设我们的集群由一个 Nimbus 节点、一个 Zookeeper 集群中的三个 Zookeeper 和一个监督者节点组成。

默认情况下，每个监督者分配了四个插槽，因此每个 Storm 监督者节点将启动四个工作进程，除非进行了配置调整。

假设所描述的拓扑分配了四个工作进程，并且每个工作进程都有两个并行度的螺栓和一个并行度为四的喷口。因此，总共有八个任务要分配到四个工作进程中。

因此，拓扑将被执行为：每个监督者上有两个工作进程，每个工作进程内有两个执行器，如下图所示：

![深入了解 Storm 的内部](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/rt-anlt-storm-csdr/img/00009.jpeg)

# 测验时间

Q.1 尝试围绕以下领域的实时分析提出一个问题陈述：

+   网络优化

+   流量管理

+   远程感知

# 总结

在本章中，您已经通过探索不同垂直领域和领域中的各种用例，了解了分布式计算的需求。我们还向您介绍了处理这些问题的各种解决方案，以及为什么 Storm 是开源世界中的最佳选择。您还了解了 Storm 组件以及这些组件在工作时的内部操作。

在下一章中，我们将介绍设置方面，并通过简单的拓扑使您熟悉 Storm 中的编程结构。


# 第二章：开始您的第一个拓扑

本章致力于指导您完成为执行 Storm 拓扑设置环境的步骤。目的是准备用户沙盒，并引导您执行一些示例代码，并了解各个组件的工作原理。所有概念都将附有代码片段和“自己动手试一试”部分，以便您能够以实际方式理解组件，并准备好探索和利用这一美妙技术的力量。

本章将涵盖的主题如下：

+   Storm 拓扑和组件

+   执行示例 Storm 拓扑

+   在分布式模式下执行拓扑

在本章结束时，您将能够理解拓扑中的组件和数据流，理解简单的单词计数拓扑，并在本地和分布式模式下执行它。您还将能够调整启动器项目拓扑，以添加自己的风格。

# 设置 Storm 的先决条件

列出了执行设置和执行步骤的先决条件：

+   对于本地模式设置，您需要 Maven、Git、Eclipse 和 Java

+   对于分布式设置，您需要以下内容：

+   Linux 或 Ubuntu 设置或分布式设置可以在 Windows 系统上使用 PowerShell 或 Cygwin

+   使用 VMware player 的多个系统或虚拟机会有所帮助

您可以参考以下链接，并按照书中所述的过程设置所需的各种开源组件，以设置 Storm 并部署本书段中解释的组件： 

+   对于 Java，[`java.com/en/download/index.jsp`](https://java.com/en/download/index.jsp)

+   对于 Eclipse，[`www.eclipse.org/downloads/`](https://www.eclipse.org/downloads/)

+   对于 Cygwin，[`cygwin.com/install.html`](http://cygwin.com/install.html)

+   对于 Git，[`help.github.com/articles/set-up-git`](https://help.github.com/articles/set-up-git)

# Storm 拓扑的组件

Storm 拓扑由两个基本组件组成：一个喷口和一个或多个螺栓。这些构件使用流连接在一起；正是通过这些流，无尽的元组流动。

让我们用一个简单的类比来讨论拓扑，如图所示，并在此后进行解释：

![Storm 拓扑的组件](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/rt-anlt-storm-csdr/img/00010.jpeg)

在我们的示例拓扑中，我们有一个用于烤薯片的大型处理单元，其中输入的*生土豆*由喷口消耗，还有各种螺栓，如去皮螺栓、切片螺栓和烘烤螺栓，执行其名称所示的任务。有各种装配线或工人将薯片从去皮单元移动到切片机等等；在我们的情况下，我们有流来连接和连接喷口和螺栓。现在，去皮机和切片机之间的交换基本单元是去皮的土豆，切片机和烘烤机之间的交换基本单元是切片的土豆。这类似于元组，是喷口和螺栓之间信息交换的数据。

让我们更仔细地看看 Storm 拓扑的构件。

### 注意

Storm 中数据交换的基本单元称为*元组*；有时也称为*事件*。

## 喷口

喷口是拓扑的收集漏斗；它将事件或元组馈送到拓扑中。它可以被视为 Storm 处理单元——拓扑的输入源。

spout 从外部源（如队列、文件、端口等）读取消息。同时，spout 将它们发射到流中，然后将它们传递给螺栓。Storm spout 的任务是跟踪每个事件或元组在其处理过程中通过**有向无环图**（**DAG**）的整个过程。然后，Storm 框架根据拓扑中元组的执行结果发送和生成确认或失败通知。这种机制为 Storm 提供了保证处理的特性。根据所需的功能，spouts 可以被编程或配置为可靠或不可靠。可靠的 spout 将失败的事件重新播放到拓扑中。

下面的图表以图形方式描述了相同的流程：

![Spouts](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/rt-anlt-storm-csdr/img/00011.jpeg)

所有的 Storm spouts 都被实现为能够在一个或多个流螺栓上发射元组。就像前面的图表中，一个 spout 可以发射元组到螺栓**A**和**C**。

每个 spout 都应该实现**IRichSpout**接口。以下是与 spout 相关的重要方法：

+   `nextTuple()`: 这是一个不断轮询外部源以获取新事件的方法；例如，前面示例中的队列。在每次轮询时，如果方法发现一个事件，它会通过流发射到拓扑结构中，如果没有新事件，方法会简单地返回。

+   `ack()`: 当 spout 发射的元组被拓扑成功处理时调用这个方法。

+   `fail()`: 当 spout 发射的元组在指定的超时内没有成功处理时，调用这个方法。在这种情况下，对于可靠的 spouts，spout 使用`messageIds`事件跟踪和追踪每个元组，然后重新发射到拓扑中进行重新处理。例如，在前面的图表中，失败的元组被再次发射。

对于不可靠的 spouts，元组不使用`messageIds`进行跟踪，而`ack()`和`fail()`等方法对于 spout 没有任何价值，因为 spout 不跟踪成功处理的元组。这些拓扑被标识为不可靠的。

### 注意

IRichSpout 是 Storm 提供的一个接口，提供了拓扑 spout 需要实现的合同或方法的详细信息。

## 螺栓

螺栓是拓扑的处理单元。它们是拓扑的组件，执行以下一个或多个任务：

+   解析

+   转换

+   聚合

+   连接

+   数据库交互

拓扑执行的整个过程通常被分解为更小的任务和子任务，最好由不同的螺栓执行，以利用 Storm 的并行分布式处理的能力。

让我们看一下下面的图表，捕捉一个实时用例，其中来自各种飞机的位置坐标被跟踪和处理，以确定它们是否在正确的轨迹上移动：

![Bolts](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/rt-anlt-storm-csdr/img/00012.jpeg)

在这里，飞行位置坐标由飞机上的传感器发送，这些传感器被整理到日志服务器并输入到 Storm 拓扑中。Storm 拓扑被分解成以下螺栓，可以对 spout 发射的元组进行操作：

+   解析事件螺栓：这个螺栓过滤和转换 spout 发射的事件。它将信息转换为可解密的格式。

+   位置螺栓：这是从解析螺栓接收的元组中提取位置坐标然后将它们发送到下一个螺栓的螺栓。

+   验证螺栓：这是验证飞机预定义轨迹与位置螺栓发送的位置坐标是否一致的螺栓，如果检测到偏差，它会向警报螺栓发送一个元组。

+   警报螺栓：这个螺栓是通知外部系统（例如我们的情况下的空中交通管制）有关飞行路径中检测到的异常或偏差的行为者。

由于实时使用案例的性质，比如前面图中所示的案例，计算的速度和准确性至关重要，这也是使 Storm 成为实现这类解决方案的强大技术选择的原因。

总体处理逻辑被分解为在 bolt 中执行的较小任务；在 bolt 中配置任务和并行性让工程师们获得解决方案的正确性能。

一个 bolt 可以监听多个流，也可以在不同的流上向多个其他 bolt 发射。如*Sprouts*部分的图所示：

+   Bolt-A 向 Bolt-B 和 Bolt-C 发射

+   Bolt-D 订阅来自 Bolt-C 和 Bolt-B 的流

Storm 提供的用户定义的 bolt 要实现的常见接口如下：

+   IRichBolt

+   IBasicBolt

这两个接口的区别取决于是否需要可靠的消息传递和事务支持。

bolt 使用的主要方法如下：

+   `prepare()`: 这是在 bolt 初始化时调用的方法。基本上，Storm 拓扑会一直运行，一旦初始化，bolt 就不会在拓扑被终止之前终止。这个方法通常用于初始化连接和读取其他在整个 bolt 生命周期中需要的静态信息。

+   `execute()`: 这是在 bolt 上执行定义的功能和处理逻辑的方法。它为每个元组执行一次。

## 流

流可以被定义为无界的元组或事件序列。这些流通常以并行和分布的方式在拓扑中创建。流可以被称为从喷口到 bolt 之间的布线或信息流通道。它们是未处理、半处理和已处理信息的载体，用于各种执行任务的组件，如 bolt 和喷口之间的信息传递。在对拓扑进行编码时，流是使用模式配置的，该模式为流的元组命名字段。

## 元组-Storm 中的数据模型

元组是 Storm 中的基本和组成数据结构。它是从喷口开始旅程的命名值列表。然后从流到 bolt 发射，然后从 bolt 到其他 bolt，执行各种处理阶段。在成功完成所有预期的处理后，根据拓扑定义，元组被确认发送回喷口。

# 执行一个样本 Storm 拓扑-本地模式

在我们开始本节之前，假设您已经完成了先决条件并安装了预期的组件。

## 来自 Storm-starter 项目的 WordCount 拓扑结构

为了理解前一节中描述的组件，让我们下载 Storm-starter 项目并执行一个样本拓扑：

1.  可以使用以下 Git 命令下载 Storm-starter 项目：

```scala
Linux-command-Prompt $ sudo git clone git://github.com/apache/incubator-storm.git && cd incubator-storm/examples/storm-starter

```

1.  接下来，您需要将项目导入到 Eclipse 工作区中：

1.  启动 Eclipse。

1.  单击**文件**菜单，然后选择**导入**向导。

1.  从**导入**向导中，选择**现有 Maven 项目**。![来自 Storm-starter 项目的 WordCount 拓扑结构](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/rt-anlt-storm-csdr/img/00013.jpeg)

1.  在 Storm-starter 项目中选择**pom.xml**，并将其指定为`<download-folder>/starter/incubator-storm/examples/storm-starter`。

1.  一旦项目成功导入，Eclipse 文件夹结构将如下屏幕截图所示：![来自 Storm-starter 项目的 WordCount 拓扑结构](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/rt-anlt-storm-csdr/img/00014.jpeg)

1.  使用 run 命令执行拓扑，您应该能够看到如下屏幕截图中显示的输出：

![来自 Storm-starter 项目的 WordCount 拓扑结构](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/rt-anlt-storm-csdr/img/00015.jpeg)

为了理解拓扑的功能，让我们看一下代码，并了解拓扑中每个组件的流程和功能：

```scala
// instantiates the new builder object
TopologyBuilder builder = new TopologyBuilder();
// Adds a new spout of type "RandomSentenceSpout" with a  parallelism hint of 5
builder.setSpout("spout", new RandomSentenceSpout(), 5);
```

```scala
TopologyBuilder object and used the template to perform the following:
```

+   `setSpout –RandomSentenceSpout`：这会生成随机句子。请注意，我们使用了一个称为并行性提示的属性，在这里设置为`5`。这是标识在提交拓扑时将生成多少个此组件实例的属性。在我们的示例中，将有五个 spout 实例。

+   `setBolt`：我们使用这个方法向拓扑中添加两个 bolt：`SplitSentenceBolt`，将句子拆分为单词，和`WordCountBolt`，对单词进行计数。

+   在前面的代码片段中，其他值得注意的项目是`suffleGrouping`和`fieldsGrouping`；我们将在下一章详细讨论这些；现在，了解这些是控制元组路由到拓扑中各个 bolt 的组件。

# 在分布式模式下执行拓扑

要在分布式模式下设置 Storm，需要执行以下步骤。

## 为 Storm 设置 Zookeeper（V 3.3.5）

Storm 拓扑的协调由 Zookeeper 集群维护。Zookeeper 的利用率并不是很高，因为它只是维护 Storm 集群的可运行状态。在大多数情况下，单个 Zookeeper 节点应该足够了，但在生产场景中，建议至少使用一个由三个节点组成的 Zookeeper 集群，以防止单个节点成为单点故障。

为了可靠的 Zookeeper 服务，将 Zookeeper 部署在一个称为**集合**的集群中。只要集合中的大多数机器正常运行，服务就会可用。集合中的一个节点会自动被选为领导者，其他节点会成为跟随者。如果领导者宕机，其中一个跟随者节点会成为领导者。

在所有将成为 Zookeeper 集合一部分的机器上执行以下步骤，以设置 Zookeeper 集群：

1.  从 Apache Zookeeper 网站下载最新的稳定版本（版本 3.3.5）。

1.  在`/usr/local`下创建一个`zookeeper`目录：

```scala
sudo mkdir /usr/local/zookeeper

```

1.  将下载的 TAR 文件提取到`/usr/local`位置。使用以下命令：

```scala
sudo tar -xvf zookeeper-3.3.5.tar.gz -C /usr/local/zookeeper

```

1.  Zookeeper 需要一个目录来存储其数据。创建`/usr/local/zookeeper/tmp`来存储这些数据：

```scala
sudo mkdir –p /usr/local/zookeeper/tmp

```

1.  在`/usr/local/zookeeper/zookeeper-3.3.5/conf`下创建一个名为`zoo.cfg`的配置文件。以下属性将放入其中：

+   `tickTime`：这是每个滴答的毫秒数（例如，2000）。

+   `initLimit`：这是初始同步阶段可以花费的滴答数（例如，5）。

+   `syncLimit`：这是在发送请求和获得确认之间可以经过的滴答数（例如，2）。

+   `dataDir`：这是快照存储的目录（例如，`/usr/local/zookeeper/tmp`）。

+   `clientPort`：这是 Zookeeper 客户端将连接到的端口（例如，2182）。

+   `server.id=host:port:port`：Zookeeper 集合中的每台机器都应该知道集合中的其他每台机器。这是通过`server.id=host:port:port`形式的一系列行来实现的（例如，`server.1:<ZOOKEEPER_NODE_1 的 IP 地址>:2888:3888`）。

1.  重复前面的步骤或将分发复制到将成为 Zookeeper 集群一部分的其他机器上。

1.  在由`datadir`属性指定的目录中创建名为`myid`的文件。`myid`文件包含一行文本，只包含该机器的 ID 的文本（服务器上的 1 和`zoo.cfg`中的 1）。因此，服务器 1 的`myid`将包含文本`1`，没有其他内容。ID 必须在集合中是唯一的，并且应该在 1 到 255 之间。在这种情况下，`myid`文件的路径是`vi /usr/local/zookeeper/tmp/myid`。

1.  编辑`~/.bashrc`文件，并添加一个 Zookeeper 主目录的环境变量，并将其 bin 目录添加到`PATH`环境变量中：![为 Storm 设置 Zookeeper（V 3.3.5）](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/rt-anlt-storm-csdr/img/00016.jpeg)

1.  在进行更改后，对`~/`.`bashrc`文件进行源操作。这一步是为了确保对`bashrc`所做的更改应用到当前的终端会话中：

```scala
source ~/.bashrc

```

1.  通过从`$ZOOKEEPER_HOME`执行以下命令在每个节点上启动 Zookeeper 守护进程：

```scala
sudo –E bin/zkServer.sh start

```

1.  通过从`$ZOOKEEPER_HOME`执行以下命令在每个节点上停止 Zookeeper 守护进程：

```scala
sudo –E bin/zkServer.sh stop

```

1.  可以通过从`$ZOOKEEPER_HOME`运行以下命令来检查 Zookeeper 状态：

```scala
sudo –E bin/zkServer.sh status

```

不同模式的输出如下：

+   如果在独立模式下运行（Zookeeper 集群中只有一台机器），将在控制台上看到以下输出：![为 Storm 设置 Zookeeper（V 3.3.5）](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/rt-anlt-storm-csdr/img/00017.jpeg)

+   如果在集群模式下运行，将在领导节点上看到以下输出：![为 Storm 设置 Zookeeper（V 3.3.5）](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/rt-anlt-storm-csdr/img/00018.jpeg)

+   如果在集群模式下运行，将在 follower 节点上看到以下输出：![为 Storm 设置 Zookeeper（V 3.3.5）](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/rt-anlt-storm-csdr/img/00019.jpeg)

默认情况下，Zookeeper 日志（`zookeeper.out`）将在启动其实例的相同位置创建。这完成了 Zookeeper 集群的设置。

## 在分布式模式下设置 Storm

执行以下步骤设置分布式模式下的 Storm：

1.  从 GitHub Storm 网站下载`Storm-0.9.2-incubating.zip`包。

1.  在`/usr/local`下创建`storm`和`storm/tmp`目录：

```scala
sudo mkdir –p /usr/local/storm/tmp

```

1.  为日志创建以下目录：

```scala
sudo mkdir –p /mnt/abc_logs/storm/storm_logs

```

1.  在 Nimbus 和工作机器上的`/usr/local`目录中解压 ZIP 文件：

```scala
sudo unzip -d /usr/local/storm/ storm-0.9.2 -incubating.zip

```

1.  在`/usr/local/storm/storm-0.9.2-incubating/conf/storm.yaml`中进行以下更改：

+   `storm.zookeeper.servers`：这是 Storm 集群中 Zookeeper 集群中主机的列表：

```scala
storm.zookeeper.servers:
 "<IP_ADDRESS_OF_ZOOKEEPER_ENSEMBLE_NODE_1>"
 "<IP_ADDRESS_OF_ZOOKEEPER_ENSEMBLE_NODE_2>"
```

+   `storm.zookeeper.port`：这是 Zookeeper 集群运行的端口：

```scala
storm.zookeeper.port: 2182
```

+   `storm.local.dir`：Nimbus 和 Supervisor 需要本地磁盘上的位置来存储与拓扑的配置和执行细节相关的少量数据。请确保在所有 Storm 节点上创建该目录并分配读/写权限。对于我们的安装，我们将在`/usr/local/storm/tmp`位置创建此目录：

```scala
storm.local.dir: "/usr/local/storm/tmp"
```

+   `nimbus.host`：节点需要知道哪台机器是主节点，以便下载拓扑 jar 包和配置文件。此属性用于此目的：

```scala
nimbus.host: "<IP_ADDRESS_OF_NIMBUS_HOST>"
```

+   `java.library.path`：这是 Storm 使用的本地库（ZeroMQ 和 JZMQ）的加载路径。对于大多数安装来说，默认值`/usr/local/lib:/opt/local/lib:/usr/lib`应该是可以的，所以在继续之前验证前面提到的位置中的库。

+   `storm.messaging.netty`：Storm 的基于 Netty 的传输已经进行了大幅改进，通过更好地利用线程、CPU 和网络资源，特别是在消息大小较小的情况下，显着提高了性能。为了提供 Netty 支持，需要添加以下配置：

```scala
storm.messaging.transport:"backtype.storm.messaging.netty.Context"
           storm.messaging.netty.server_worker_threads:1
           storm.messaging.netty.client_worker_threads:1
           storm.messaging.netty.buffer_size:5242880
           storm.messaging.netty.max_retries:100
           storm.messaging.netty.max_wait_ms:1000
           storm.messaging.netty.min_wait_ms:100
```

+   我们的 Storm 集群安装中的`storm.yaml`片段如下：

```scala
#To be filled in for a storm configuration
storm.zookeeper.servers:
     - "nim-zkp-flm-3.abc.net"
storm.zookeeper.port: 2182
storm.local.dir: "/usr/local/storm/tmp"
nimbus.host: "nim-zkp-flm-3.abc.net"
topology.message.timeout.secs: 60
topology.debug: false
topology.optimize: true
topology.ackers: 4

storm.messaging.transport: "backtype.storm.messaging.netty.Context"
storm.messaging.netty.server_worker_threads: 1
storm.messaging.netty.client_worker_threads: 1
storm.messaging.netty.buffer_size: 5242880
storm.messaging.netty.max_retries: 100
storm.messaging.netty.max_wait_ms: 1000
storm.messaging.netty.min_wait_ms: 100
```

1.  在`~/.bashrc`文件中设置`STORM_HOME`环境，并将 Storm 的`bin`目录添加到`PATH`环境变量中。这样可以在任何位置执行 Storm 二进制文件。

1.  使用以下命令将`Storm.yaml`文件复制到 Nimbus 机器上 Storm 安装的`bin`文件夹中：

```scala
sudo cp /usr/local/storm/storm-0.9.2- incubating/conf/storm.yaml /usr/local/storm/storm-0.8.2/bin/

```

## 启动 Storm 守护进程

现在 Storm 集群已经设置好，我们需要在各自的 Storm 节点上启动三个进程。它们如下：

+   **Nimbus:** 通过从`$STORM_HOME`运行以下命令在被识别为主节点的机器上作为后台进程启动 Nimbus：

```scala
sudo –bE bin/storm nimbus

```

+   **Supervisor:** 可以像启动 Nimbus 一样启动 Supervisors。从`$STORM_HOME`运行以下命令：

```scala
sudo –bE bin/storm supervisor

```

+   **UI:** Storm UI 是一个 Web 应用程序，用于检查 Storm 集群，其中包含 Nimbus/Supervisor 状态。它还列出了所有运行中的拓扑及其详细信息。可以通过以下命令从`$STORM_HOME`启用 UI：

```scala
sudo –bE bin/storm ui

```

可以通过`http://<IP_ADDRESS_OF_NIMBUS>:8080`访问 UI。

# 从命令提示符执行拓扑

一旦 UI 可见并且所有守护程序都已启动，就可以使用以下命令在 Nimbus 上提交拓扑：

```scala
storm jar storm-starter-0.0.1-SNAPSHOT-jar-with-dependencies.jar  storm.starter.WordCountTopology WordCount -c nimbus.host=localhost

```

在这里显示了以分布式模式运行的带有`WordCount`拓扑的 Storm UI。它显示了拓扑状态、正常运行时间和其他详细信息（我们将在后面的章节中详细讨论 UI 的特性）。我们可以从 UI 中终止拓扑。

![从命令提示符执行拓扑](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/rt-anlt-storm-csdr/img/00020.jpeg)

## 调整 WordCount 拓扑以自定义它

现在我们已经以分布式模式部署了`WordCount`拓扑，让我们稍微调整螺栓中的代码，以将`WordCount`写入文件。为了实现这一点，我们将按照以下步骤进行：

1.  我们打算创建一个新的螺栓`FileWriterBolt`，以实现这一目标。打开`WordCountTopology.java`并将以下片段添加到`WordCountTopology.java`中：

```scala
public static class FileWriterBolt extends BaseBasicBolt {
    Map<String, Integer> counts = new HashMap<String,  Integer>();
    @Override
    public void execute(Tuple tuple, BasicOutputCollector  collector) {
        String word = tuple.getString(0);
        Integer count = counts.get(word);
        if(count==null) {count = 0;
        count = 0;
    }
        count++;
        counts.put(word, count);
        OutputStream ostream;
        try {
            ostream = new  FileOutputStream("~/wordCount.txt", true);
            ostream.write(word.getBytes());
            ostream.close();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        collector.emit(new Values(word, count));
    }

    @Override
    public void declareOutputFields(OutputFieldsDeclarer  declarer) {
        declarer.declare(new Fields("word", "count"));
    }
```

1.  接下来，我们必须更改`main()`方法，以使用这个新的螺栓，而不是`WordCount Bolt()`；以下是片段：

```scala
// instantiates the new builder object 
TopologyBuilder builder = new TopologyBuilder();
// Adds a new spout of type "RandomSentenceSpout" with a  parallelism hint of 5 
builder.setSpout("spout", new RandomSentenceSpout(), 5);
//Adds a new bolt to the  topology of type "SplitSentence"  with parallelism of 8
builder.setBolt("split", new SplitSentence(),  8).shuffleGrouping("spout");
//Adds a new bolt to the  topology of type "SplitSentence"  with parallelism of 8
//builder.setBolt("count", new FileWriterBolt()(),  12).fieldsGrouping("split", new Fields("word"));
```

1.  接下来，您可以使用 Eclipse 执行拓扑，将其作为 Java 运行，输出将保存到名为`wordCount.txt`的文件中，保存在您的主目录中。

1.  要以分布式模式运行，请使用以下步骤：

1.  编译拓扑更改以生成新的 Storm-starter 项目，使用以下命令行：

```scala
mvn clean install

```

1.  从 starter 项目的目标文件夹中复制`storm-starter-0.0.1-SNAPSHOT-jar-with-dependencies.jar`到 Nimbus，比如在`/home/admin/topology/`。

1.  使用以下命令提交拓扑：

```scala
storm jar /home/admin/topology/storm-starter-0.0.1-SNAPSHOT- jar-with-dependencies.jar storm.starter.WordCountTopology  WordCount -c nimbus.host=localhost

```

1.  输出将与前一节中图中执行的`WordCount`拓扑相同。

# 测验时间

Q.1\. 判断以下陈述是真还是假：

1.  所有 Storm 拓扑都是可靠的。

1.  一个拓扑通常有多个喷口。

1.  一个拓扑通常有多个螺栓。

1.  一个螺栓只能在一个流上发射。

Q.2\. 填空：

1.  _______________ 是创建拓扑的模板。

1.  _______________ 指定了特定螺栓或喷嘴的实例数量。

1.  Storm 的 _______________ 守护程序类似于 Hadoop 的作业跟踪器。

Q.3\. 执行以下任务：

1.  对 Storm-starter 项目的`WordCount`拓扑进行更改，以便它能够从指定位置的文件中读取句子。

# 摘要

在本章中，我们已经设置了 Storm 集群。您已经了解了 Storm 拓扑的各种构建模块，如螺栓、喷口和布线模板-拓扑构建器。我们执行并了解了`WordCount`拓扑，并对其进行了一些修正。

在下一章中，您将阅读并了解有关流分组、锚定和确认的内容。这也将引导我们了解 Storm 框架下拓扑中的可靠和非可靠机制。


# 第三章：通过示例了解 Storm 内部

本书的这一章节致力于让您了解 Storm 的内部工作原理，并通过实际示例来说明它的工作方式。目的是让您习惯于编写自己的喷口，了解可靠和不可靠的拓扑，并熟悉 Storm 提供的各种分组。

本章将涵盖以下主题：

+   Storm 喷口和自定义喷口

+   锚定和确认

+   不同的流分组

在本章结束时，您应该能够通过使用锚定来理解各种分组和可靠性的概念，并能够创建自己的喷口。

# 自定义 Storm 喷口

您已经在之前的章节中探索和了解了 Storm-starter 项目提供的`WordCount`拓扑。现在是时候我们继续下一步，使用 Storm 进行自己的实践；让我们迈出下一步，用我们自己的喷口从各种来源读取。

## 创建 FileSpout

在这里，我们将创建自己的喷口，从文件源读取事件或元组并将它们发射到拓扑中；我们将在上一章的`WordCount`拓扑中使用`RandomSentenceSpout`的位置替换为喷口。

首先，将我们在第二章中创建的项目复制到一个新项目中，并对`RandomSentenceSpout`进行以下更改，以在 Storm-starter 项目中创建一个名为`FileSpout`的新类。

现在我们将更改`FileSpout`，使其从文件中读取句子，如下面的代码所示：

```scala
public class FileSpout extends BaseRichSpout {
  //declaration section
  SpoutOutputCollector _collector;
  DataInputStream in ;
  BufferedReader br;
  Queue qe;

  //constructor
    public FileSpout() {
        qe = new LinkedList();
    }

  // the messageId builder method
  private String getMsgId(int i) {
    return (new StringBuilder("#@#MsgId")).append(i).toString();
    }

  //The function that is called at every line being read by  readFile
  //method and adds messageId at the end of each line and then add
  // the line to the linked list
    private void queueIt() {
      int msgId = 0;
      String strLine;
      try {
          while ((strLine = br.readLine()) != null) {
              qe.add((new  StringBuilder(String.valueOf(strLine))).append("#@#"  + getMsgId(msgId)).toString());
              msgId++;
          }
      } catch (IOException e) {
          e.printStackTrace();
      } catch (Exception e) {
          e.printStackTrace();
      }
    }

  //function to read line from file at specified location 
  private void readFile() {
        try {
          FileInputStream fstream = new  FileInputStream("/home/mylog"); in =  new DataInputStream(fstream);
          br = new BufferedReader(new InputStreamReader( in ));
          queueIt();
          System.out.println("FileSpout file reading done");
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
    }

  //open function that is called at the time of spout  initialization
  // it calls the readFile method that reads the file , adds  events 
  // to the linked list to be fed to the spout as tuples
  @
    Override
    public void open(Map conf, TopologyContext context,  SpoutOutputCollector  collector) {
      _collector = collector;
      readFile();
    }

  //this method is called every 100 ms and it polls the list
  //for message which is read off as next tuple and emit the spout  to
  //the topology. When queue doesn't have any events, it reads the
  //file again calling the readFile method
    @
    Override
    public void nextTuple() {
      Utils.sleep(100);
      String fullMsg = (String) qe.poll();
      String msg[] = (String[]) null;
      if (fullMsg != null) {
          msg = (new String(fullMsg)).split("#@#");
          _collector.emit(new Values(msg[0]));
          System.out.println((new StringBuilder("nextTuple done  ")).append(msg[1]).toString());
      } else {
          readFile();
      }
    }

  @
  Override
  public void ack(Object id) {}

  @
  Override
  public void fail(Object id) {}

  @
  Override
  public void declareOutputFields(OutputFieldsDeclarer declarer) {
      declarer.declare(new Fields("word"));
  }
}
```

### 提示

**下载示例代码**

您可以从[`www.packtpub.com`](http://www.packtpub.com)的帐户中下载您购买的所有 Packt 图书的示例代码文件。如果您在其他地方购买了这本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，以便直接将文件发送到您的电子邮件。

### 调整 WordCount 拓扑以使用 FileSpout

现在我们需要将`FileSpout`适应到我们的`WordCount`拓扑中并执行它。为此，您需要在`WordCount`拓扑中更改一行代码，并在`TopologyBuilder`中实例化`FileSpout`而不是`RandomSentenceSpout`，如下所示：

```scala
public static void main(String[] args) throws Exception {
  TopologyBuilder builder = new TopologyBuilder();
//builder.setSpout("spout", new RandomSentenceSpout(), 5);
  builder.setSpout("spout", new FileSpout(), 1);
```

这一行更改将处理从指定文件`/home/mylog`中读取的新喷口的实例化（请在执行程序之前创建此文件）。以下是您参考的输出的屏幕截图：

![调整 WordCount 拓扑以使用 FileSpout](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/rt-anlt-storm-csdr/img/00021.jpeg)

### SocketSpout 类

为了更好地理解喷口，让我们创建一个`SocketSpout`类。假设您擅长编写 Socket 服务器或生产者，我将带您了解创建自定义`SocketSpout`类以在 Storm 拓扑中消耗套接字输出的过程：

```scala
public class SocketSpout extends BaseRichSpout{
  static SpoutOutputCollector collector;
  //The socket
    static Socket myclientSocket;
    static ServerSocket myserverSocket;
    static int myport;

  public SocketSpout(int port){
    myport=port;
  }

  public void open(Map conf,TopologyContext context,  SpoutOutputCollector collector){
    _collector=collector;
    myserverSocket=new ServerSocket(myport);
  }

  public void nextTuple(){
    myclientSocket=myserverSocket.accept();
    InputStream incomingIS=myclientSocket.getInputStream();
    byte[] b=new byte[8196];
    int len=b.incomingIS.read(b);
    _collector.emit(new Values(b));
  }
}
```

# 锚定和确认

我们已经谈到了为执行 Storm 拓扑创建的 DAG。现在，当您设计拓扑以满足可靠性时，有两个需要添加到 Storm 的项目：

+   每当 DAG 添加新的链接，即新的流时，它被称为锚定

+   当元组完全处理时，称为确认

当 Storm 知道这些先前的事实时，它可以在元组处理过程中对它们进行评估，并根据它们是否完全处理而失败或确认元组。

让我们看一下以下`WordCount`拓扑螺栓，以更好地理解 Storm API 的锚定和确认：

+   `SplitSentenceBolt`：这个螺栓的目的是将句子分割成不同的单词并发射它。现在让我们详细检查这个螺栓的输出声明者和执行方法（特别是高亮显示的部分），如下面的代码所示：

```scala
  public void execute(Tuple tuple) {
      String sentence = tuple.getString(0);
      for(String word: sentence.split(" ")) {
          _collector.emit(tuple, new Values(word)); //1
      }
      _collector.ack(tuple); //2
  }
  public void declareOutputFields(OutputFieldsDeclarer  declarer) {
      declarer.declare(new Fields("word")); //3
  }
}
```

上述代码的输出声明功能如下所述：

+   `_collector.emit`: 这里，由 bolt 在名为`word`的流上发射的每个元组（第二个参数）都使用方法的第一个参数（元组）进行了定位。在这种安排下，如果发生故障，树的根部定位的元组将由 spout 重新播放。

+   `collector.ack`: 这里我们通知 Storm 该元组已被这个 bolt 成功处理。在发生故障时，程序员可以显式调用`fail`方法，或者 Storm 在超时事件的情况下会内部调用它，以便可以重放。

+   `declarer.declare`: 这是用来指定成功处理的元组将被发射的流的方法。请注意，我们在`_collector.emit`方法中使用了相同的`word`流。同样，如果你查看`WordCount`拓扑的`Builder`方法，你会发现另一个关于`word`流整体集成的部分，如下所示：

```scala
  builder.setBolt("count", new WordCount(), 12).fieldsGrouping("split", new Fields("word"));
```

## 不可靠的拓扑

现在让我们看看相同拓扑的不可靠版本。在这里，如果元组未能被 Storm 完全处理，框架不会重放。我们之前在这个拓扑中使用的代码会像这样：

```scala
java _collector.emit(new Values(word));
```

因此，未定位的元组由 bolt 发射。有时，由于编程需要处理各种问题，开发人员会故意创建不可靠的拓扑。

# 流分组

接下来，我们需要熟悉 Storm 提供的各种流分组（流分组基本上是定义 Storm 如何在 bolt 任务之间分区和分发元组流的机制），这为开发人员处理程序中的各种问题提供了很大的灵活性。

## 本地或 shuffle 分组

```scala
WordCount topology (which we reated earlier), which demonstrates the usage of shuffle grouping:
```

```scala
TopologyBuilder myBuilder = new TopologyBuilder();
builder.setSpout("spout", new RandomSentenceSpout(), 5);
builder.setBolt("split", new SplitSentence(),  8).shuffleGrouping("spout");
builder.setBolt("count", new WordCount(),  12).fieldsGrouping("split", new Fields("word"));
```

在下图中，显示了 shuffle 分组：

![本地或 shuffle 分组](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/rt-anlt-storm-csdr/img/00022.jpeg)

在这里，**Bolt A**和**Bolt B**都有两个并行度，因此 Storm 框架会生成每个这些 bolt 的两个实例。这些 bolt 通过*shuffle grouping*连接在一起。我们现在将讨论事件的分发。

来自**Bolt A**的**Instance 1**的 50%事件将发送到**Bolt B**的**Instance 1**，剩下的 50%将发送到**Bolt B**的**Instance 2**。同样，**Bolt B**的**Instance 2**发射的 50%事件将发送到**Bolt B**的**Instance 1**，剩下的 50%将发送到**Bolt B**的**Instance 2**。

## 字段分组

在这种分组中，我们指定了两个参数——流的来源和字段。字段的值实际上用于控制元组路由到各种 bolt 的过程。这种分组保证了对于相同字段的值，元组将始终路由到同一个 bolt 的实例。

在下图中，**Bolt A**和**Bolt B**之间显示了字段分组，并且每个 bolt 都有两个实例。根据字段分组参数的值，注意事件的流动。

![字段分组](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/rt-anlt-storm-csdr/img/00023.jpeg)

来自**Bolt A**的**Instance 1**和**Instance 2**的所有事件，其中**Field**的值为**P**，都发送到**Bolt B**的**Instance 1**。

来自**Bolt A**的**Instance 1**和**Instance 2**的所有事件，其中**Field**的值为**Q**，都发送到**Bolt B**的**Instance 2**。

## 所有分组

所有分组是一种广播分组，可用于需要将相同消息发送到目标 bolt 的所有实例的情况。在这里，每个元组都发送到所有 bolt 的实例。

这种分组应该在非常特定的情况下使用，针对特定的流，我们希望相同的信息被复制到所有下游的 bolt 实例中。让我们来看一个使用情况，其中包含与国家及其货币价值相关的一些信息，而后续的 bolts 需要这些信息进行货币转换。现在每当*currency* bolt 有任何更改时，它使用*all*分组将其发布到所有后续 bolts 的实例中：

![所有分组](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/rt-anlt-storm-csdr/img/00024.jpeg)

这里我们有一个图解表示*所有*分组，其中来自**Bolt A**的所有元组都被发送到**Bolt B**的所有实例。

## 全局分组

全局分组确保来自源组件（spout 或 bolt）的整个流都发送到目标 bolt 的单个实例，更准确地说是发送到具有最低 ID 的目标 bolt 实例。让我们通过一个例子来理解这个概念，假设我的拓扑如下：

![全局分组](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/rt-anlt-storm-csdr/img/00025.jpeg)

我将为组件分配以下并行性：

![全局分组](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/rt-anlt-storm-csdr/img/00026.jpeg)

另外，我将使用以下流分组：

![全局分组](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/rt-anlt-storm-csdr/img/00027.jpeg)

然后，框架将所有来自*myboltA*流实例的数据，都发送到*myboltB*流的一个实例，这个实例是 Storm 在实例化时分配了较低 ID 的实例：

![全局分组](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/rt-anlt-storm-csdr/img/00028.jpeg)

如前图所示，在全局分组的情况下，来自**Bolt A**的两个实例的所有元组都会发送到**Bolt B**的**Instance 1**，假设它的 ID 比**Bolt B**的**Instance 2**的 ID 更低。

### 注意

Storm 基本上为拓扑中创建的每个 bolt 或 spout 实例分配 ID。在全局分组中，分配是指向从 Storm 分配的 ID 较低的实例。

## 自定义分组

Storm 作为一个可扩展的框架，为开发人员提供了创建自己的流分组的功能。这可以通过为`backtype.storm.grouping.CustomStreamGroupinginterface`类提供实现来实现。

## 直接分组

在这种分组中，Storm 框架提供了发送者的能力

组件（spout 或 bolt）来决定消费者 bolt 的哪个任务会接收元组，而发送组件正在向流中发射元组。

必须使用特殊的`emitDirect`方法将元组发送到流中，并且必须指定消费组件的任务（注意可以使用`TopologyContext`方法获取任务）。

# 测验时间

Q.1 判断以下陈述是真是假：

1.  可靠拓扑的所有组件都使用锚定。

1.  在发生故障时，所有元组都会被重新播放。

1.  Shuffle 分组进行负载均衡。

1.  全局分组就像广播一样。

Q.2 填空：

1.  _______________ 是告诉框架元组已成功处理的方法。

1.  _______________ 方法指定流的名称。

1.  ___________ 方法用于将元组推送到 DAG 中的下游。

对 Storm-starter 项目的`WordCount`拓扑进行更改，以创建自定义分组，使得以特定字母开头的所有单词始终发送到`WordCount` bolt 的同一个实例。

# 总结

在本章中，我们已经了解了 Storm spout 的复杂性。我们还创建了一个自定义文件 spout，并将其与`WordCount`拓扑集成。我们还向您介绍了可靠性、确认和锚定的概念。当前版本的 Storm 提供的各种分组知识进一步增强了用户探索和实验的能力。

在下一章中，我们将让您熟悉 Storm 的集群设置，并为您提供有关集群模式的各种监控工具的见解。


# 第四章：集群模式下的风暴

我们现在已经到达了我们与风暴的旅程的下一步，也就是理解风暴及其相关组件的集群模式设置。我们将浏览风暴和 Zookeeper 中的各种配置，并理解它们背后的概念。

本章将涵盖的主题如下：

+   设置风暴集群

+   了解集群的配置及其对系统功能的影响

+   风暴 UI 和理解 UI 参数

+   为生产设置提供和监视应用程序

到本章结束时，您应该能够理解风暴和 Zookeeper 节点的配置。此外，您应该能够理解风暴 UI，并设置风暴集群，并使用各种工具监视它们。

# 风暴集群设置

在第二章中，我们设置了风暴和 Zookeeper 参考集群，如下图所示，*开始使用您的第一个拓扑*。

我们为一个三节点风暴集群（其中有一个 Nimbus 和两个监督者）设置了三节点 Zookeeper 集群。

我们正在使用推荐的三节点 Zookeeper 集群，以避免风暴设置中的单点故障。

Zookeeper 集群应该有奇数个节点。这个要求的原因是 Zookeeper 选举逻辑要求领导者拥有奇数个选票，只有在奇数节点在法定人数中时才可能出现这种组合，如下图所示：

![风暴集群设置](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/rt-anlt-storm-csdr/img/00029.jpeg)

# Zookeeper 配置

假设您已在所有三个 Zookeeper 节点上安装了 Zookeeper；现在我们将带您浏览配置，以便更好地理解它们。

在我们的情况下，`zoo.cfg`的摘录位于`<zookeeper_installation_dir>/ zookeeper-3.4.5/conf/`。Zookeeper 的配置如下：

+   `dataDir=/usr/local/zookeeper/tmp`：这是 Zookeeper 存储其快照的路径；这些快照实际上是状态日志，用于维护当前集群状态以进行协调。在发生故障时，这些快照用于将集群恢复到最后稳定状态。这个目录还包含一个包含单个条目`myID`的文件。这个值从`1`开始，对于每个 Zookeeper 节点都是不同的，所以我们将保持如下：

```scala
zkp-1.mydomain.net – value of myId =1
zkp-2.mydomain.net – value of myId =2
zkp-3.mydomain.net – value of myId =3
```

每当您想要从头开始，或者当您升级或降级风暴或 Zookeeper 集群时，建议您清理这个`local.dir`文件，以便清除陈旧的数据。

+   `clientPort=2182`：这个配置指定了客户端与 Zookeeper 建立连接的端口：

```scala
server.1=zkp-1.mydomain.net:2888:3888
server.2=zkp-2\. mydomain.net:2888:3888
server.3=zkp-3\. mydomain.net:2888:3888
```

在前面的代码中，这三行实际上指定了组成 Zookeeper 集群一部分的服务器的 IP 或名称。在这个配置中，我们创建了一个三节点 Zookeeper 集群。

+   `maxClientCnxns=30l`：这个数字指定了单个客户端可以与这个 Zookeeper 节点建立的最大连接数。在我们的情况下，计算将如下进行：

一个监督者可以建立的最大连接数是 30 个，与一个 Zookeeper 节点。因此，一个监督者可以与三个 Zookeeper 节点创建的最大连接数是 90（即 30*3）。

以下截图显示了从风暴 UI 中捕获的已使用、可用和空闲插槽：

![Zookeeper 配置](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/rt-anlt-storm-csdr/img/00030.jpeg)

### 注意

风暴集群中的工作人员数量与 Zookeeper 集群中可用的连接数量有关。如果 Zookeeper 集群连接不足，风暴监督者将无法启动。

## 清理 Zookeeper

我们已经看到 Zookeeper 如何以快照的形式将其所有协调数据存储在`dataDir`配置中指定的路径中。这需要定期清理或归档以删除旧的快照，以免消耗整个磁盘空间。这是一个需要在所有 Zookeeper 节点上配置的小型清理脚本：

```scala
numBackUps=3
dataDir=/usr/local/zookeeper/tmp
logDir=/mnt/my_logs/
echo `date`' Time to clean up StormZkTxn logs' >>  $logDir/cleanStormZk.out
java -cp /usr/local/zookeeper/zookeeper-3.4.5/zookeeper- 3.4.5.jar:/usr/local/zookeeper/zookeeper-3.4.5/lib/log4j- 1.2.15.jar:/usr/local/zookeeper/zookeeper-3.4.5/lib/slf4j-api- 1.6.1.jar org.apache.zookeeper.server.PurgeTxnLog $dataDir -n  $numBackUps >> $logDir/cleanStormZk.out
```

这里有以下清理脚本：

+   `numBackUps`：在这里，我们指定了清理后要保留多少个快照；最少为三个，最多可以根据需求变化。

+   `dataDir`：在这里，我们指定了需要清理快照的数据目录的路径。

+   `logDir`：这是清理脚本将存储其日志的路径。

+   `org.apache.zookeeper.server.PurgeTxnLog`：这是一个实用类，清除除了最后三个快照之外的所有快照，如`numBackups`中所述。

# Storm 配置

我们将查看 Storm 守护进程和守护进程周围的配置。对于 Nimbus 节点，在`storm.yaml`中有以下配置设置。让我们根据以下代码中给出的配置来理解这些配置：

```scala
storm.zookeeper.servers:
- "zkp-1.mydomain.net "
- "zkp-2.mydomain.net "
- "zkp-3.mydomain.net "

storm.zookeeper.port: 2182
storm.local.dir: "/usr/local/storm/tmp"
nimbus.host: "nim-zkp-flm-3.mydomain.net"
topology.message.timeout.secs: 60
topology.debug: false

supervisor.slots.ports:
    - 6700
    - 6701
    - 6702
    - 6703
```

在前面的代码中使用的配置的功能如下：

+   `storm.zookeeper.servers`：在这里，我们指定了 Zookeeper 集群中 Zookeeper 服务器的名称或 IP 地址；请注意，我们在前一节的`zoo.cfg`配置中使用了与之前相同的主机名。

+   `storm.zookeeper.port`：在这里，我们指定了 Storm 节点连接的 Zookeeper 节点上的端口。同样，我们在前一节中在`zoo.cfg`中指定了相同的端口。

+   `storm.local.dir`：Storm 有自己的临时数据存储在本地目录中。这些数据会自动清理，但每当您想要从头开始，或者当您扩展或缩小 Storm 或 Zookeeper 集群时，建议您清理此`local.dir`配置，以清除陈旧数据。

+   `nimbus.host`：这指定了要设置为 Nimbus 的主机名或 IP 地址。

+   `topology.message.timeout.secs`：此值指定拓扑处理的元组在经过一定秒数后被声明为超时并丢弃的持续时间。此后，根据拓扑是可靠还是不可靠，它会被重放或不会。应谨慎设置此值；如果设置得太低，所有消息最终都会超时。如果设置得太高，可能永远不会知道拓扑中的性能瓶颈。

+   `topology.debug`：此参数表示是否要在调试模式或节点中运行拓扑。调试模式是指打印所有调试日志，建议在开发和暂存模式下使用，但在生产模式下不建议使用，因为此模式下 I/O 非常高，从而影响整体性能。

+   `supervisor.slots.ports`：此参数指定了主管工作进程的端口。这个数字直接关联到主管上可以生成的工作进程的数量。当拓扑被生成时，必须指定要分配的工作进程的数量，这又与分配给拓扑的实际资源相关联。工作进程的数量非常重要，因为它们实际上确定了集群上可以运行多少个拓扑，从而确定了可以实现多少并行性。例如，默认情况下，每个主管有四个插槽，所以在我们的集群中，我们将有*总插槽数/工作进程= 4*2 = 8*。每个工作进程从系统中获取一定数量的 CPU 和 RAM 资源，因此在主管上生成多少个工作进程取决于系统配置。

## Storm 日志配置

现在我们将查看 Storm 的日志配置。它们使用 Log4J 的`logback`实现，其配置可以在`<storm-installation-dir>/apache-storm-0.9.2-incubating/logback`中的`cluster.xml`中找到并进行调整，使用以下代码：

```scala
<appender name="A1"  class="ch.qos.logback.core.rolling.RollingFileAppender">
    <file>${storm.log.dir}/${logfile.name}</file>
    <rollingPolicy  class="ch.qos.logback.core.rolling.FixedWindowRollingPolicy">
      <fileNamePattern>${storm.log.dir}/${logfile.name}.%i</fileNamePattern >
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

  <root level="INFO">
    <appender-ref ref="A1"/>
  </root>
```

在上面的片段中，有几个部分被突出显示，我们将逐一进行更详细的讨论。它们如下：

+   `<file>`：这个标签保存了 Storm 框架生成的日志的日志目录路径和文件名。

+   `<filenamepattern>`：这是文件形成和滚动的模式；例如，使用前面的代码模式，我们有 worker 日志文件`worker-6700.log`和`worker-6700.1.log`。

+   `<minIndex>和<maxIndex>`：这些非常重要，用于指定我们想要保留多少个文件在这个滚动 appender 中；在这种情况下，我们将有九个备份文件，编号从一到九，还有一个运行日志文件。

+   `maxFileSize`：这个参数指定文件应该在什么大小时滚动，例如，在我们的情况下，它是 100MB；这意味着当工作日志文件达到这个大小时，它将滚动到下一个索引。

+   `根级别`：这指定了日志级别；在我们的情况下，我们已将其指定为*Info*，这意味着`Info`和以上的日志将被打印到日志文件中，但是低于`Info`级别的日志将不会被写入日志。以下是供参考的日志级别层次结构：

+   `关闭`

+   `致命`

+   `错误`

+   `警告`

+   `信息`

+   `调试`

+   `TRACE`

+   `全部`

## Storm UI

```scala
word-count, is the name of that topology:

```

cluster.submitTopology("word-count", conf, builder.createTopology());

```scala

In our preceding sample screenshot, **AAA-topology-1407803669812** is the name of the topology.**ID**: This is the Storm-generated unique ID that is a combination of the topology name, timestamp, and ID, which is used by Storm to identify and differentiate the topology.**Status**: This denotes the state of the topology, which could be *active* for a live topology, *killed* when a topology is killed using the UI or CLI, *inactive* for a deactivated topology, and *rebalancing* for a topology where the rebalance command is executed wherein the number of workers allocated to the topology is increased or decreased.**Uptime**: As the name suggests, this mentions the duration for which the topology has been running. For example, our sample topology has been running for 8 days 15 hours 6 months 16 seconds.**Num workers**: This specifies how many workers are allocated to the topology. Again, if we refer to `WordCountTopology.java`, we will see this snippet where it is declared as `3`:

```

conf.setNumWorkers(3);

```scala

**Num executors**: This specifies the sum total of the number of executors in the topology. This is connected to the parallelism hint that is specified during the overall integration of the topology in the topology builder as follows:

```

builder.setSpout("spout", new RandomSentenceSpout(), 5);

```scala

Here, in our `WordCount` topology, we have specified the parallelism of the spout as `5`, so five instances of the spout will be spawned in the topology.

**Num tasks**: This gains the sum total of another parameter that is specified at the time of overall integration in the topology, as shown:

```

builder.setSpout("spout", new RandomSentenceSpout(), 5).setNumTasks(10);

```scala

Here, we are specifying that for `5` executors dedicated to the spout, the total value of `numtasks` is `10`, so two tasks each will be spawned on each of the executors.

What we see on the UI is a total of all `numtasks`  values across all topology components.

```

### 第二部分

这一部分包含了可以在拓扑上执行的各种操作：

+   **激活**：UI 提供了一个功能，可以重新激活之前被暂停的拓扑。一旦激活，它可以再次开始从 spout 消费消息并处理它们。

+   **停用**：当执行此操作时，拓扑立即关闭 spout，也就是说，不会从 spout 读取新消息并将其推送到 DAG 下游。已经在各种 bolt 中处理的现有消息将被完全处理。

+   **重新平衡**：当对活动拓扑的 worker 分配发生变化时执行此操作。

+   **终止**：顾名思义，用于向 Storm 框架发送拓扑的终止信号。建议提供合理的终止时间，以便拓扑完全排空并能够在终止之前清理流水线事件。

### 第三部分

这一部分显示了时间轴上处理的消息数量的截图。它有以下关键部分：

+   **窗口**：这个字段指定了以下时间段的时间段：最近 10 分钟，最近 3 小时，过去一天，或者一直。拓扑的进展是根据这些时间段来捕获的。 

+   **发射**：这捕获了 spout 在各个时间段发射的元组数量。

+   **传输**：这指定了发送到拓扑中其他组件的元组数量。请注意，发射的元组数量可能与传输的元组数量相等，也可能不相等，因为前者是 spout 的 emit 方法执行的确切次数，而后者是基于使用的分组而传输的数量；例如，如果我们将一个 spout 绑定到一个具有两个元组并行度的 bolt，使用 all 分组，那么对于 spout 发射的每个`x`个元组，将传输`2x`个元组。 

+   **完整延迟**（**ms**）：这是元组在整个拓扑中执行所花费的平均总时间。

+   **已确认**：这个字段保存了成功处理的已确认事件的数量。

+   **失败**：这是处理失败的事件数量。

### 第四部分

这一部分与*第三部分*相同，唯一的区别是这里的术语显示在组件级别，即 spouts 和 bolts，而在*第三部分*中是在拓扑级别。UI 上还有一些术语需要介绍给你。它们如下：

+   **容量**：这是微调拓扑时要查看的最重要的指标之一。它指示螺栓在最后十分钟内执行元组所花费的时间的百分比。任何接近或超过一的值都表明需要增加此螺栓的并行性。它使用以下公式计算：

```scala
Capacity = (Number of tuples Executed*Average execute  latency)/Window_Size*1000)
```

+   **执行延迟**：这是元组在处理过程中在螺栓的执行方法中花费的平均时间。

+   **处理延迟**：处理延迟是元组从螺栓接收到到被确认（表示成功处理）的平均时间。

### 可视化部分

Storm 0.9.2 中的一个改进是拓扑的可视化描述。以下图是 Storm UI 中样本拓扑的描述：

![可视化部分](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/rt-anlt-storm-csdr/img/00033.jpeg)

在前面的截图中，您可以看到拓扑上由各种螺栓和喷口可视标记的所有流，以及延迟和其他关键属性。

Storm UI 提供了一个非常丰富的界面，用户可以从非常高的级别开始，并深入到特定领域，就像在*Storm 集群设置*部分的截图中所看到的那样，我们讨论了 Storm 集群级属性；在第二级中，我们移动到特定的拓扑。接下来，在拓扑内，您可以单击任何螺栓或工作程序，组件级别的详细信息将呈现给您。在集群设置中，以下截图中突出显示的一个项目对于调试和日志解密非常重要——工作程序 ID。如果某个组件的喷口或螺栓给我们带来问题，并且我们想要了解其工作原理，首先要查看的地方是日志。要能够查看日志，需要知道有问题的螺栓在哪个监督者上执行以及哪个工作程序；这可以通过钻取该组件并查看执行器部分来推断：

![可视化部分](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/rt-anlt-storm-csdr/img/00034.jpeg)

Storm UI 捕获监督者端口

在这里，主机告诉您此组件正在哪个监督者上运行，端口告诉您有关工作程序，因此，如果我想查找此组件的日志，我将在`logdir`中查找`sup-flm-dev-1.mydomain.net`下的`worker-6711.log`日志目录。

# Storm 监控工具

像 Storm 这样的集群设置需要不断监控，因为它们通常是为支持实时系统而开发的，其中停机可能会对**服务级别协议**（**SLA**）构成问题。市场上有很多工具可用于监控 Storm 集群并发出警报。一些 Storm 监控工具如下：

+   **Nagios**：这是一个非常强大的监控系统，可以扩展以生成电子邮件警报。它可以监控各种进程和系统 KPI，并可以通过编写自定义脚本和插件来在发生故障时重新启动某些组件。![Storm 监控工具](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/rt-anlt-storm-csdr/img/00035.jpeg)

Nagios 服务控制台

在前面的 Storm 集群与 Nagios 监控的截图中，您可以看到各种可以监控的进程和其他系统级 KPI，如 CPU、内存、延迟、硬盘使用率等。

+   **Ganglia**：这是另一个广泛使用的开源工具，可以为 Storm 集群设置监控框架。![Storm 监控工具](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/rt-anlt-storm-csdr/img/00036.jpeg)

如前面的截图所示，我们有很多钻取选项；我们可以看到负载和 CPU 级别的详细信息，以及其他系统和集群级 KPI 来捕获和绘制集群的健康状态。

+   **SupervisorD**：这是另一个广泛使用的开源监控系统，通常与 Storm 一起使用以捕获和保持集群的健康状态。SupervisorD 还有助于配置和启动 Storm 服务，并且可以在发生故障时配置以重新启动它们。![Storm 监控工具](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/rt-anlt-storm-csdr/img/00037.jpeg)

+   **Ankush**：这是另一个可以用于 Storm 和其他大数据集群设置和管理的供应和监控系统。它有付费和开源版本（[`github.com/impetus-opensource/ankush`](https://github.com/impetus-opensource/ankush)）。它具有以下显著特点：

| **供应** | **此应用程序支持的环境****物理节点****云上的虚拟节点（AWS 或本地）** |
| --- | --- |
| 单一技术集群 |
| 多技术集群 |
| 基于模板的集群创建 |
| 重新部署出错的集群 |
| 机架支持 |
| 在部署前增强节点验证 |
| **监控** | 热图 |
| 服务监控 |
| 基于技术的监控 |
| 丰富的图表 |
| 关键事件的警报和通知 |
| 集中式日志视图 |
| 审计追踪 |
| 仪表板和电子邮件上的警报 |

以下截图是 Ankush 的仪表板截图。所有系统级 KPI（如 CPU、负载、网络、内存等）都被很好地捕获。

![Storm 监控工具](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/rt-anlt-storm-csdr/img/00038.jpeg)

# 测验时间

Q.1\. 判断以下陈述是真还是假：

1.  Storm 配置存储在`cluster.xml`中。

1.  每个监督者只能分配四个工作节点。

1.  Zookeeper 集群始终有奇数个节点。

1.  Zookeeper 需要至少三个快照才能从故障中恢复其状态。

1.  如果 Nimbus 和监督者死亡，拓扑可以继续执行。

Q.2\. 填空：

1.  _______________ 是元组被处理和确认所花费的平均时间。

1.  _______________ 是元组在执行方法中花费的平均时间。

1.  在故障发生时，__________ 组件负责恢复 Storm 集群。

Q.3\. 在一个三节点的 Storm 集群（一个 Nimbus 和两个监督者）上执行`WordCount`拓扑，然后执行以下任务：

+   在拓扑运行时终止 Nimbus 节点—观察拓扑不会失败，它将继续不受影响。

+   在拓扑运行时终止监督者—观察拓扑不会失败，它将继续不受影响。工作节点将继续执行，并与 Zookeeper 协调。

+   尝试从 Storm UI 进行重新平衡和停用等各种操作。

# 摘要

在本章中，您详细了解了 Storm 和 Zookeeper 的配置。我们探索并向您介绍了 Storm UI 及其属性。完成了集群设置后，我们简要介绍了 Storm 中可用于运营生产支持的各种监控工具。

在下一章中，我们将介绍 RabbitMQ 及其与 Storm 的集成。


# 第五章：Storm 高可用性和故障转移

本章将带您进入 Storm 的旅程的下一个级别，在这里我们将让您熟悉 Storm 与生态系统中其他必要组件的集成。我们将实际涵盖高可用性和可靠性的概念。

本章是理解 Storm 及其相关组件的集群模式设置的下一步。我们将了解 Storm 和 Zookeeper 中的各种配置以及它们背后的概念。

本章将涵盖以下主题：

+   设置 RabbitMQ（单实例和集群模式）

+   开发 AMQP 喷流以集成 Storm 和 RabbitMQ

+   创建 RabbitMQ 饲料器组件

+   为 RabbitMQ 和 Storm 集群构建高可用性

+   Storm 调度程序

通过本章结束时，您将能够设置和理解 RabbitMQ，并将 Storm 与 RabbitMQ 集成。此外，您将能够测试 Storm 集群的高可用性和可靠处理。

# RabbitMQ 概述

RabbitMQ 的要点是*消息传递只是起作用*。

RabbitMQ 是 AMQP 消息协议最广泛使用的实现之一，它提供了一个用于接收和传递消息的平台。这个内存队列还有能力保存和保留消息，直到它们被消费者消耗。这种灵活的代理系统非常易于使用，并且适用于大多数操作系统，如 Windows、UNIX 等。

RabbitMQ 是**高级消息队列协议**（**AMQP**）的实现。如下图所示，RabbitMQ 的关键组件是**交换**和**队列**：

![RabbitMQ 概述](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/rt-anlt-storm-csdr/img/00039.jpeg)

发布者和消费者是两个重要的角色；前者生成消息并将其发布到交换，后者根据其类型将消息从发布者发布到队列，然后从队列发布到消费者，消费者接收消息。

需要注意的是，这里的发布者与交换进行交互，而不是队列。RabbitMQ 支持各种类型的交换，如直接、扇出、主题等。交换的任务是根据交换的类型和与消息关联的路由键，将消息路由到一个或多个队列。因此，如果是直接交换，消息将被传递到与交换绑定的一个队列，其路由键与消息中的路由键匹配。如果是扇出交换，那么消息将被传递到与交换绑定的所有队列，路由完全被忽略。

# 安装 RabbitMQ 集群

RabbitMQ 是一个消息代理-消息的中间人。它为您的应用程序提供了一个发送和接收消息的共同平台，并为您的消息提供了一个安全的存放处，直到它们被接收。

## 设置 RabbitMQ 的先决条件

确保您已经注意到短名称也包括在`/etc/hosts`文件中，如下面的代码所示：

```scala
<ip address1>     <hostname1> <shortname1> 
<ip address2>     <hostname2> <shortname2> 
```

### 注意

在 RabbitMQ 集群中，`/etc/hosts`中的短名称是强制性的，因为节点间的通信是使用这些短名称进行的。

例如，我们的集群中有两台机器，具有以下提到的 IP 和主机名；RabbitMQ 守护程序在启动集群时使用这些信息：

```scala
10.191.206.83     rmq-flc-1.mydomain.net rmq-flc-1 
10.73.10.63       rmq-flc-2.mydomain.net rmq-flc-2
```

如果未设置短名称，您将看到此错误：**系统未运行以使用完全限定的主机名**。

## 设置 RabbitMQ 服务器

Ubuntu 附带了 RabbitMQ，但通常不是最新版本。最新版本可以从 RabbitMQ 的 Debian 存储库中检索。应在 Ubuntu 上运行以下 shell 脚本以安装 RabbitMQ：

```scala
#!/bin/sh
sudo cat <<EOF > /etc/apt/sources.list.d/rabbitmq.list
sudo deb http://www.rabbitmq.com/debian/ testing main
EOF

sudo curl http://www.rabbitmq.com/rabbitmq-signing-key-public.asc -o  /tmp/rabbitmq-signing-key-public.asc
sudo apt-key add /tmp/rabbitmq-signing-key-public.asc
sudo rm /tmp/rabbitmq-signing-key-public.asc

sudo apt-get -qy update
sudo apt-get -qy install rabbitmq-server

```

## 测试 RabbitMQ 服务器

以下步骤将为您提供在 Ubuntu 终端上执行的命令，以启动 RabbitMQ 服务器并对其进行测试。它们如下：

1.  通过在 shell 上运行以下命令启动 RabbitMQ 服务器：

```scala
sudo service rabbitmq-server start

```

![测试 RabbitMQ 服务器](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/rt-anlt-storm-csdr/img/00040.jpeg)

1.  通过运行以下命令检查服务器状态：

```scala
sudo service rabbitmq-server status

```

![测试 RabbitMQ 服务器](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/rt-anlt-storm-csdr/img/00041.jpeg)

1.  在每个 RabbitMQ 实例上，要启用 RabbitMQ 管理控制台，请执行以下命令，并使用以下命令重新启动该实例上运行的 RabbitMQ 服务器：

```scala
sudo rabbitmq-plugins enable rabbitmq_management

```

1.  要启用 RabbitMQ 插件，请转到`/usr/lib/rabbitmq/bin`并在两个节点上执行以下命令，然后重新启动它们：

```scala
sudo rabbitmq-plugins enable rabbitmq_management

```

1.  启动、关闭和错误日志将在`/var/log/rabbitmq`目录下创建。

### 创建 RabbitMQ 集群

以下是设置两个（或更多）节点 RabbitMQ 集群所需执行的步骤：

1.  考虑到`rmq-flc-1`和`rmq-flc-2`是两个实例的短主机名，我们将使用以下命令在两个实例上启动独立的 RabbitMQ 服务器：

```scala
sudo service rabbitmq-server start

```

1.  在`rmq-flc-2`上，我们将停止 RabbitMQ 应用程序，重置节点，加入集群，并使用以下命令重新启动 RabbitMQ 应用程序（所有这些都是在`rmq-flc-1`上的 RabbitMQ 服务器正在运行时完成的）：

```scala
sudo rabbitmqctl stop_app
sudo rabbitmqctl join_cluster rabbit@rmq-flc-1
sudo rabbitmqctl start_app

```

1.  通过在任何一台机器上运行以下命令来检查集群状态：

```scala
sudo service rabbitmq-server status

```

1.  应该看到以下输出：![创建 RabbitMQ 集群](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/rt-anlt-storm-csdr/img/00042.jpeg)

1.  集群已成功设置。

如果启用了 UI，可以在`http:/` `/<hostip>:15672`（用户名：`guest`，密码：`guest`）访问集群。

### 启用 RabbitMQ UI

执行以下步骤以启用 RabbitMQ UI：

1.  执行以下命令：

```scala
sudo /usr/lib/rabbitmq/bin/rabbitmq-plugins enable  rabbitmq_management

```

1.  上述命令将产生以下输出：

```scala
The following plugins have been enabled:
mochiweb
webmachine
rabbitmq_mochiweb
amqp_client
rabbitmq_management_agent
rabbitmq_management
Plugin configuration has changed. Restart RabbitMQ for changes to take effect.

```

1.  在集群的所有节点上重复前面的步骤。

1.  使用以下命令重新启动每个节点：

```scala
sudo service rabbitmq-server restart 

```

1.  使用`http:``//<hostip>:15672`链接访问 UI。默认用户名和密码是`guest`。

### 为高可用性创建镜像队列

在本节中，我们将讨论一种特殊类型的队列，它保证了 RabbitMQ 默认队列的高可用性。默认情况下，我们创建的队列位于单个节点上，根据它们声明的顺序，这可能成为单点故障。让我们看一个例子。我有一个由两个 RabbitMQ 节点`rabbit1`和`rabbit2`组成的集群，并在我的集群上声明了一个交换机，比如`myrabbitxchange`。假设按照执行顺序，在`rabbit1`上创建了队列。现在，如果`rabbit1`宕机，那么队列就消失了，客户端将无法发布到它。

因此，为了避免情况，我们需要高可用性队列；它们被称为镜像队列，在集群中的所有节点上都有副本。镜像队列有一个主节点和多个从节点，最老的节点是主节点，如果它不可用，则可用节点中最老的节点成为主节点。消息被发布到所有从节点。这增强了可用性，但不会分配负载。要创建镜像队列，请使用以下步骤：

1.  可以通过使用 Web UI 添加策略来启用镜像。转到**管理**选项卡，选择**策略**，然后单击**添加策略**。

1.  指定策略**名称**、**模式**、**定义**，然后单击**添加策略**，如下面的截图所示：![为高可用性创建镜像队列](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/rt-anlt-storm-csdr/img/00043.jpeg)

# 将 Storm 与 RabbitMQ 集成

现在我们已经安装了 Storm，下一步将是将 RabbitMQ 与 Storm 集成，为此我们将不得不创建一个名为 RabbitMQ spout 的自定义 spout。这个 spout 将从指定队列中读取消息；因此，它将提供一个消费者的角色，然后将这些消息推送到下游拓扑。

以下是 spout 代码的样子：

```scala
public class AMQPRecvSpout implements IRichSpout{

//The constructor where we set initialize all properties
  public AMQPRecvSpout(String host, int port, String username,  String password, String vhost, boolean requeueOnFail, boolean  autoAck) {
    this.amqpHost = host;
    this.amqpPort = port;
    this.amqpUsername = username;
    this.amqpPasswd = password;
    this.amqpVhost = vhost;
    this.requeueOnFail = requeueOnFail;
    this.autoAck = autoAck;
  }
/*
Open method of the spout , here we initialize the prefetch count ,  this parameter specified how many messages would be prefetched  from the queue by the spout – to increase the efficiency of the  solution */
  public void open(@SuppressWarnings("rawtypes") Map conf,  TopologyContext context, SpoutOutputCollector collector) {
    Long prefetchCount = (Long) conf.get(CONFIG_PREFETCH_COUNT);
    if (prefetchCount == null) {
      log.info("Using default prefetch-count");
      prefetchCount = DEFAULT_PREFETCH_COUNT;
    } else if (prefetchCount < 1) {
      throw new IllegalArgumentException(CONFIG_PREFETCH_COUNT + "  must be at least 1");
    }
    this.prefetchCount = prefetchCount.intValue();

    try {
      this.collector = collector;
      setupAMQP();
    } catch (IOException e) {
      log.error("AMQP setup failed", e);
      log.warn("AMQP setup failed, will attempt to reconnect...");
      Utils.sleep(WAIT_AFTER_SHUTDOWN_SIGNAL);
      reconnect();
    }
  }

  /**
   * Reconnect to an AMQP broker.in case the connection breaks at  some point
   */
  private void reconnect() {
    log.info("Reconnecting to AMQP broker...");
    try {
      setupAMQP();
    } catch (IOException e) {
      log.warn("Failed to reconnect to AMQP broker", e);
    }
  }
  /**
   * Set up a connection with an AMQP broker.
   * @throws IOException
   *This is the method where we actually connect to the queue  using AMQP client APIs
   */
  private void setupAMQP() throws IOException{
    final int prefetchCount = this.prefetchCount;
    final ConnectionFactory connectionFactory = new  ConnectionFactory() {
      public void configureSocket(Socket socket)
          throws IOException {
        socket.setTcpNoDelay(false);
        socket.setReceiveBufferSize(20*1024);
        socket.setSendBufferSize(20*1024);
      }
    };

    connectionFactory.setHost(amqpHost);
    connectionFactory.setPort(amqpPort);
    connectionFactory.setUsername(amqpUsername);
    connectionFactory.setPassword(amqpPasswd);
    connectionFactory.setVirtualHost(amqpVhost);

    this.amqpConnection = connectionFactory.newConnection();
    this.amqpChannel = amqpConnection.createChannel();
    log.info("Setting basic.qos prefetch-count to " +  prefetchCount);
    amqpChannel.basicQos(prefetchCount);
    amqpChannel.exchangeDeclare(Constants.EXCHANGE_NAME,  "direct");
    amqpChannel.queueDeclare(Constants.QUEUE_NAME, true, false,  false, null);
    amqpChannel.queueBind(Constants.QUEUE_NAME,  Constants.EXCHANGE_NAME, "");
    this.amqpConsumer = new QueueingConsumer(amqpChannel);
    assert this.amqpConsumer != null;
    this.amqpConsumerTag =  amqpChannel.basicConsume(Constants.QUEUE_NAME, this.autoAck,  amqpConsumer);
  }

  /* 
   * Cancels the queue subscription, and disconnects from the AMQP  broker.
   */
  public void close() {
    try {
      if (amqpChannel != null) {
        if (amqpConsumerTag != null) {
          amqpChannel.basicCancel(amqpConsumerTag);
        }
        amqpChannel.close();
      }
    } catch (IOException e) {
      log.warn("Error closing AMQP channel", e);
    }

    try {
      if (amqpConnection != null) {
        amqpConnection.close();
      }
    } catch (IOException e) {
      log.warn("Error closing AMQP connection", e);
    }
  }
  /* 
   * Emit message received from queue into collector
   */
  public void nextTuple() {
    if (spoutActive && amqpConsumer != null) {
      try {
        final QueueingConsumer.Delivery delivery =  amqpConsumer.nextDelivery(WAIT_FOR_NEXT_MESSAGE);
        if (delivery == null) return;
        final long deliveryTag =  delivery.getEnvelope().getDeliveryTag();
        String message = new String(delivery.getBody());

        if (message != null && message.length() > 0) {
          collector.emit(new Values(message), deliveryTag);
        } else {
          log.debug("Malformed deserialized message, null or zero- length. " + deliveryTag);
          if (!this.autoAck) {
            ack(deliveryTag);
          }
        }
      } catch (ShutdownSignalException e) {
        log.warn("AMQP connection dropped, will attempt to  reconnect...");
        Utils.sleep(WAIT_AFTER_SHUTDOWN_SIGNAL);
        reconnect();
      } catch (ConsumerCancelledException e) {
        log.warn("AMQP consumer cancelled, will attempt to  reconnect...");
        Utils.sleep(WAIT_AFTER_SHUTDOWN_SIGNAL);
        reconnect();
      } catch (InterruptedException e) {
        log.error("Interrupted while reading a message, with  Exception : " +e);
      }
    }
  }
  /* 
   * ack method to acknowledge the message that is successfully  processed 
*/

  public void ack(Object msgId) {
    if (msgId instanceof Long) {
      final long deliveryTag = (Long) msgId;
      if (amqpChannel != null) {
        try {
          amqpChannel.basicAck(deliveryTag, false);
        } catch (IOException e) {
          log.warn("Failed to ack delivery-tag " + deliveryTag,  e);
        } catch (ShutdownSignalException e) {
          log.warn("AMQP connection failed. Failed to ack  delivery-tag " + deliveryTag, e);
        }
      }
    } else {
      log.warn(String.format("don't know how to ack(%s: %s)",  msgId.getClass().getName(), msgId));
    }
  }

  public void fail(Object msgId) {
    if (msgId instanceof Long) {
      final long deliveryTag = (Long) msgId;
      if (amqpChannel != null) {
        try {
          if (amqpChannel.isOpen()) {
            if (!this.autoAck) {
              amqpChannel.basicReject(deliveryTag, requeueOnFail);
            }
          } else {
            reconnect();
          }
        } catch (IOException e) {
          log.warn("Failed to reject delivery-tag " + deliveryTag,  e);
        }
      }
    } else {
      log.warn(String.format("don't know how to reject(%s: %s)",  msgId.getClass().getName(), msgId));
    }
  }

public void declareOutputFields(OutputFieldsDeclarer declarer) {
    declarer.declare(new Fields("messages"));
  }
}
```

需要在项目`pom.xml`中引入 AMQP Maven 依赖项，如下所示：

```scala
    <dependency>
      <groupId>com.rabbitmq</groupId>
      <artifactId>amqp-client</artifactId>
      <version>3.2.1</version>
    </dependency>
```

## 创建 RabbitMQ 饲料器组件

现在我们已经安装了 RabbitMQ 集群，我们所需要做的就是开发一个发布者组件，它将把消息发布到 RabbitMQ。这将是一个简单的 Java 组件，模拟向 RabbitMQ 发布实时数据。这个组件的基本代码片段如下：

```scala
public class FixedEmitter {
  private static final String EXCHANGE_NAME = "MYExchange";
  public static void main(String[] argv) throws Exception {
    /*we are creating a new connection factory for builing  connections with exchange*/
    ConnectionFactory factory = new ConnectionFactory();
    /* we are specifying the RabbitMQ host address and port here  in */

    Address[] addressArr = {
      new Address("localhost", 5672)
    }; //specify the IP if the queue is not on local node where  this program would execute 
    Connection connection = factory.newConnection(addressArr);
    //creating a channel for rabbitMQ
    Channel channel = connection.createChannel();
    //Declaring the queue and routing key
    String queueName = "MYQueue";
    String routingKey = "MYQueue";
    //Declaring the Exchange
    channel.exchangeDeclare(EXCHANGE_NAME, "direct", false);
    Map < String, Object > args = new HashMap < String, Object >  ();
    //defining the queue policy
    args.put("x-ha-policy", "all");
    //declaring and binding the queue to the exchange
    channel.queueDeclare(queueName, true, false, false, args);
    channel.queueBind(queueName, EXCHANGE_NAME, routingKey);
    String stoppedRecord;
    int i = 0;
    //emitting sample records
    while (i < 1) {
      try {
        myRecord = "MY Sample record";
        channel.basicPublish(EXCHANGE_NAME, routingKey,
          MessageProperties.PERSISTENT_TEXT_PLAIN,
          myRecord.getBytes());
        System.out.println(" [x] Sent '" + myRecord + "' sent at "  + new Date());
        i++;
        Thread.sleep(2);
      } catch (Exception e) {
        e.printStackTrace();
      }
    }
    channel.close();
    connection.close();
  }
}
```

## 为 AMQP spout 连接拓扑

现在我们已经准备好了集群队列设置，放置了 AMQP spout 和 feeder 组件；让我们放置最后一个部分，即 Storm 拓扑的整体集成。

让我们再次使用我们的`WordCount`拓扑，而不是`RandomSentenceSpout`，我们将使用在上一节中设计的`AMQPRecvSpout`，*将 Storm 与 RabbitMQ 集成*。

需要修改以下代码块：

```scala
builder.setSpout("spout", new RandomSentenceSpout(), 5);
builder.setBolt("split", new SplitSentence(),  8).shuffleGrouping("spout");
We will use the new spout instead, as follows:

builder.setSpout("queue_reader", new  AMQPRecvSpout(Constants.RMQ_ADDRESS, 5672, "guest", "guest",  "/"));
```

# 构建组件的高可用性

现在我们正处于寻找集群中各个组件的高可用性的合适时机。我们将通过一系列练习来完成这一点，假设每个组件都以集群模式安装，并且在生态系统中存在多个实例。

只有在设置了镜像队列之后，才能检查 RabbitMQ 的高可用性。假设：

+   我们在 RabbitMQ 集群中有两个节点：node1 和 node2

+   `MyExchange`是为此练习创建的交换的名称

+   `MyQueue`是为此练习创建的镜像队列

接下来，我们将运行我们在*创建 RabbitMQ feeder 组件*部分创建的`fixedEmitter`代码。现在进行 Litmus 测试：

+   假设队列`MyQueue`有 100 条消息

+   现在关闭 node2（这意味着集群中的一个节点宕机）

+   所有 100 条消息将被保留，并且在控制台上可见；当 node2 缺席时，node1 填充。

这种行为确保即使集群中的一个节点宕机，服务也不会中断。

## Storm 集群的高可用性

现在让我们看一下 Storm 中故障转移或高可用性的演示。Storm 框架的构建方式使其可以继续执行，只要：

+   它具有所需数量的 Zookeeper 连接

+   它具有所需数量的工作进程在一个或多个监督者上

那么前面的陈述实际上是什么意思呢？好吧，让我们通过一个例子来理解。假设我在 Storm 集群上执行`WordCount`拓扑。这个集群的配置如下：

+   有两个 Storm 监督者，每个 Storm 监督者有四个工作进程，所以集群中总共有八个工作进程

+   有三个 Zookeeper 节点（最大连接数 30），所以总共有 30*2*3=180 个连接

+   一个拓扑分配了三个工作进程

假设当我们将这个拓扑提交到集群时，任务和进程会像下面的截图所示一样生成：

![Storm 集群的高可用性](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/rt-anlt-storm-csdr/img/00044.jpeg)

上图以图表方式描述了集群，灰色的工作进程是分配给拓扑的。现在我们已经准备好尝试 Storm 和 Zookeeper 的高可用性测试。Storm 和 Zookeeper 的测试如下：

+   **测试 1**（所有组件都正常运行）：在提交拓扑后关闭 Nimbus 节点；您会注意到拓扑将继续正常执行。

+   **测试 2**（所有组件都正常运行）：关闭一个 Zookeeper 节点，您会注意到拓扑将继续正常执行，因为其他两个可用的 Zookeeper 有足够的资源来保持 Storm 集群正常运行。

+   **测试 3**（所有组件都正常运行）：关闭两个 Zookeeper 节点，您会注意到拓扑将继续正常执行，因为其他两个可用的 Zookeeper 有足够的资源来保持 Storm 集群正常运行。

+   **测试 4**（所有组件都正常运行，拓扑正在运行）：杀死监督者 2；现在这个节点上有一个灰色的工作节点。因此当这个节点宕机时，灰色的工作节点会死掉，然后因为第二个监督者不可用，它会再次生成，这次在监督者 1 上。因此，拓扑的所有工作节点现在将在一个单独的监督者上执行，但系统将继续以有限的资源执行，但不会失败。

## Storm 集群的保证处理

本节讨论的下一个主题是看*Storm 的保证消息处理如何运作*。我们在之前的章节中讨论过这个概念，但为了实际理解它，我没有深入讨论，因为我想先向大家介绍 AMQP spout。现在让我们回到我们在第二章中讨论的例子，*开始你的第一个拓扑*。

现在如下图所示，虚线箭头流显示未能处理的事件被重新排队到队列中：

![Storm 集群的保证处理](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/rt-anlt-storm-csdr/img/00045.jpeg)

现在让我们稍微调整一下我们的`wordCount`拓扑，我们在其中添加了`AMQPRecvSpout`来使事件失败，并看看它们实际上出现在哪里。假设我使用`FixedEmitter`向队列中发出 10 个事件。现在我调整我的`wordCount` bolt，并在执行方法中引入人为的休眠，使每个事件在那里停留五分钟（使用`Thread.sleep(300)`）。这将导致它的超时，因为默认事件超时时间为 60 秒。

现在当你运行拓扑时，你将能够看到事件通过 UI 重新排队回 RabbitMQ。

# Storm 隔离调度程序

Storm 隔离调度程序是在 Storm 版本 0.8.2 中发布的。自从发布以来，这是一个非常方便的功能，非常积极地被使用，特别是在共享 Storm 集群的情况下。让我们通过一个例子来了解它的工作和能力；假设我们有一个由四个监督者节点组成的 Storm 集群，每个节点有四个插槽，所以总共有 16 个插槽。现在我想在这里使用三个 Storm 拓扑，比如 Topo1、Topo2 和 Topo3；每个拓扑都分配了四个工作节点。

因此，按照可能的默认设置，Storm 分发的调度行为将如下所示：

|   | 监督者 1 | 监督者 2 | 监督者 3 | 监督者 4 |
| --- | --- | --- | --- | --- |
| **Topo1** | Worker 1 | Worker 2 | Worker 3 | Worker 4 |
| **Topo2** | Worker 2 | Worker 1 | Worker 1 | Worker 1 |
| **Topo3** | Worker 3 | Worker 3 | Worker 2 | Worker 2 |

Storm 将尊重负载分配，并在每个节点上生成每个拓扑的一个工作节点。

现在让我们稍微调整一下情景，并引入一个要求，即 Topo1 是一个非常资源密集型的拓扑结构。（我想要将一个监督者完全专门用于这个，这样我就可以节省网络跳数。）这可以通过使用隔离调度程序来实现。

我们需要在集群中每个 Storm 节点（Nimbus 和监督者）的`storm.yaml`文件中进行以下条目的设置：

```scala
isolation.scheduler.machines: 
    "Topol": 2
```

需要重新启动集群才能使此设置生效。这个设置意味着我们已经将两个监督者节点专门用于 Topo1，并且它将不再与提交到集群的其他拓扑共享。这也将确保在生产中遇到的多租户问题有一个可行的解决方案。

其他两个监督者将被 Topo2 和 Topo3 共享。可能的分配将如下所示：

|   | 监督者 1 | 监督者 2 | 监督者 3 | 监督者 4 |
| --- | --- | --- | --- | --- |
| **Topo1** | Worker 1Worker 2 | Worker 1Worker 2 |   |   |
| **Topo2** |   |   | Worker 1Worker 2 | Worker 1Worker 2 |
| **Topo3** |   |   | Worker 3Worker 4 | Worker 3Worker 4 |

因此，从上表可以明显看出，Topo1 将被隔离到监督者 1 和 2，而 Top2 和 Topo3 将共享监督者 3 和 4 上的其余八个插槽。

# 测验时间

Q.1 判断以下句子是真是假：

1.  AMQP 是 STOMP 协议。

1.  RabbitMQ 不是故障安全的。

1.  需要 AMQP 客户端来发布到 RabbitMQ。

1.  镜像队列可以从集群中节点的故障中恢复。

Q.2 填空：

1.  _______________ 是根据路由键传递消息的交换机。

1.  _______________ 是消息被广播的交换机。

1.  _______________ 是 AMQP 消费者协议上 Storm spout 的实现。

Q.3 在一个三节点的 Storm 集群（一个 nimbus 和两个 supervisor 节点）上执行`WordCount`拓扑，与一个两节点的 RabbitMQ 集群结合在一起：

+   尝试各种在*构建组件的高可用性*部分提到的故障场景

+   在消息处理中引入人工延迟，以校准 Storm 拓扑的保证处理

# 总结

在本章中，您已经了解了 AMQP 协议的 RabbitMQ 实现。我们完成了集群设置，并将 Storm 拓扑的输出与队列集成在一起。我们还探索并实际测试了 RabbitMQ 和 Storm 的高可用性和可靠性场景。我们通过涉及 Storm 调度器来结束了本章。在下一章中，我们将了解使用 Cassandra 的 Storm 持久化。
