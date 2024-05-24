# Storm 蓝图（三）

> 原文：[`zh.annas-archive.org/md5/770BD43D187DC246E15A42C26D059632`](https://zh.annas-archive.org/md5/770BD43D187DC246E15A42C26D059632)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：集成 Druid 进行金融分析

在本章中，我们将扩展 Trident 的使用，创建一个实时金融分析仪表板。该系统将处理金融消息，以在不同粒度上随时间提供股票定价信息。该系统将展示与非事务性系统的集成，使用自定义状态实现。

在前面的例子中，我们使用 Trident 来统计随时间变化的事件总数。对于分析数据的简单用例来说已经足够了，但是架构设计并不灵活。要引入新的维度需要 Java 开发和部署新代码。

传统上，数据仓库技术和商业智能平台用于计算和存储维度分析。数据仓库作为**On-line Analytics Processing** (**OLAP**)系统的一部分部署，与**On-line Transaction Processing** (**OLTP**)分开。数据传播到 OLAP 系统，但通常有一定的滞后。这对于回顾性分析是足够的，但在需要实时分析的情况下不够。

同样，其他方法使用批处理技术来赋予数据科学家能力。数据科学家使用诸如 PIG 之类的语言来表达他们的查询。然后，这些查询编译成在大量数据集上运行的作业。幸运的是，它们在分布式处理的平台上运行，如 Hadoop，但这仍然引入了相当大的延迟。

这两种方法对于金融系统来说都不够，金融系统无法承受分析数据的可用性出现滞后。仅仅启动批处理作业的开销可能对金融系统实时需求造成太大延迟。

在本章中，我们将扩展我们对 Storm 的使用，以提供一个灵活的系统，只需要很少的工作就可以引入新的维度，同时提供实时分析。这意味着数据摄入和维度分析的可用性之间只有很短的延迟。

在本章中，我们将涵盖以下主题：

+   自定义状态实现

+   与非事务性存储的集成

+   使用 ZooKeeper 进行分布式状态

+   Druid 和实时聚合分析

# 用例

在我们的用例中，我们将利用金融系统中股票订单的信息。利用这些信息，我们将随时间提供定价信息，这些信息可以通过**REpresentational State Transfer** (**REST**)接口获得。

金融行业中的规范消息格式是**Financial Information eXchange** (**FIX**)格式。该格式的规范可以在[`www.fixprotocol.org/`](http://www.fixprotocol.org/)找到。

一个 FIX 消息的示例如下：

```scala
23:25:1256=BANZAI6=011=135215791235714=017=520=031=032=037=538=1000039=054=155=SPY150=2151=010=2528=FIX.4.19=10435=F34=649=BANZAI52=20121105-
```

FIX 消息本质上是键值对流。ASCII 字符 01，即**Start of Header** (**SOH**)，分隔这些键值对。FIX 将键称为标签。如前面的消息所示，标签由整数标识。每个标签都有一个关联的字段名和数据类型。要查看标签类型的完整参考，请转到[`www.fixprotocol.org/FIXimate3.0/en/FIX.4.2/fields_sorted_by_tagnum.html`](http://www.fixprotocol.org/FIXimate3.0/en/FIX.4.2/fields_sorted_by_tagnum.html)。

我们用例中的重要字段显示在以下表格中：

| 标签 ID | 字段名 | 描述 | 数据类型 |
| --- | --- | --- | --- |
| `11` | `CIOrdID` | 这是消息的唯一标识符。 | 字符串 |
| `35` | `MsgType` | 这是 FIX 消息的类型。 | 字符串 |
| `44` | `价格` | 这是每股股票的股价。 | 价格 |
| `55` | `符号` | 这是股票符号。 | 字符串 |

FIX 是 TCP/IP 协议的一层。因此，在实际系统中，这些消息是通过 TCP/IP 接收的。为了与 Storm 轻松集成，系统可以将这些消息排队在 Kafka 中。然而，在我们的示例中，我们将简单地摄取一个填满 FIX 消息的文件。FIX 支持多种消息类型。有些用于控制消息（例如，登录，心跳等）。我们将过滤掉这些消息，只传递包含价格信息的类型到分析引擎。

# 集成非事务系统

为了扩展我们之前的示例，我们可以开发一个配置框架，允许用户指定他们想要对事件进行聚合的维度。然后，我们可以在我们的拓扑中使用该配置来维护一组内存数据集来累积聚合，但任何内存存储都容易出现故障。为了解决容错性，我们可以将这些聚合持久存储在数据库中。

我们需要预期并支持用户想要执行的所有不同类型的聚合（例如，总和，平均，地理空间等）。这似乎是一项重大的努力。

幸运的是，有实时分析引擎的选项。一个流行的开源选项是 Druid。以下文章摘自他们在[`static.druid.io/docs/druid.pdf`](http://static.druid.io/docs/druid.pdf)找到的白皮书：

> Druid 是一个开源的、实时的分析数据存储，支持对大规模数据集进行快速的自由查询。该系统结合了列导向的数据布局、共享无内容架构和先进的索引结构，允许对十亿行表进行任意探索，延迟在亚秒级。Druid 可以水平扩展，是 Metamarkets 数据分析平台的核心引擎。

从上述摘录中，Druid 正好符合我们的要求。现在，挑战是将其与 Storm 集成。

Druid 的技术堆栈自然地适应了基于 Storm 的生态系统。与 Storm 一样，它使用 ZooKeeper 在其节点之间进行协调。Druid 还支持与 Kafka 的直接集成。对于某些情况，这可能是合适的。在我们的示例中，为了演示非事务系统的集成，我们将直接将 Druid 与 Storm 集成。

我们将在这里简要介绍 Druid。但是，有关 Druid 的更详细信息，请参阅以下网站：

[`github.com/metamx/druid/wiki`](https://github.com/metamx/druid/wiki)

Druid 通过其**实时**节点收集信息。根据可配置的粒度，**实时**节点将事件信息收集到永久存储在深度存储机制中的段中。Druid 持久地将这些段的元数据存储在 MySQL 中。**主**节点识别新段，根据规则为该段识别**计算**节点，并通知**计算**节点拉取新段。**代理**节点坐在**计算**节点前面，接收来自消费者的`REST`查询，并将这些查询分发给适当的**计算**节点。

因此，将 Storm 与 Druid 集成的架构看起来与以下图表所示的类似：

![集成非事务系统](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/storm-bp/img/8294OS_07_01.jpg)

如前图所示，涉及三种数据存储机制。**MySQL**数据库是一个简单的元数据存储库。它包含所有段的所有元数据信息。**深度存储**机制包含实际的段信息。每个段包含根据配置文件中定义的维度和聚合而基于特定时间段的事件的合并索引。因此，段可以很大（例如，2GB 的 blob）。在我们的示例中，我们将使用 Cassandra 作为我们的深度存储机制。

最后，第三种数据存储机制是 ZooKeeper。ZooKeeper 中的存储是瞬态的，仅用于控制信息。当一个新的段可用时，Master 节点会在 ZooKeeper 中写入一个临时节点。Compute 节点订阅相同的路径，临时节点触发 Compute 节点拉取新的段。在成功检索段后，Compute 节点会从 ZooKeeper 中删除临时节点。

对于我们的示例，事件的整个序列如下：

![集成非事务性系统](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/storm-bp/img/8294OS_07_02.jpg)

前面的图表展示了从 Storm 下游的事件处理。在许多实时分析引擎中，重要的是要认识到无法撤销事务。分析系统被高度优化以处理速度和聚合。牺牲的是事务完整性。

如果重新审视 Trident 的状态分类，有三种不同的状态：事务性、不透明和非事务性。事务状态要求每个批次的内容随时间保持不变。不透明事务状态可以容忍随时间变化的批次组合。最后，非事务状态无法保证确切的一次语义。

总结`storm.trident.state.State`对象的 Javadoc，有三种不同类型的状态：

| **非事务状态** | 在这种状态下，提交被忽略。无法回滚。更新是永久的。 |
| --- | --- |
| **重复事务状态** | 只要所有批次都是相同的，系统就是幂等的。 |
| **不透明事务状态** | 状态转换是增量的。在重播事件中，先前的状态与批次标识符一起存储以容忍批次组合的变化。 |

重要的是要意识到，将状态引入拓扑实际上会将任何写入存储的顺序化。这可能会对性能产生重大影响。在可能的情况下，最好的方法是确保整个系统是幂等的。如果所有写入都是幂等的，那么你根本不需要引入事务性存储（或状态），因为架构自然容忍元组重播。

通常，如果状态持久性由你控制架构的数据库支持，你可以调整架构以添加额外的信息来参与事务：重复事务的最后提交批次标识符和不透明事务的上一个状态。然后，在状态实现中，你可以利用这些信息来确保你的状态对象与你正在使用的 spout 类型相匹配。

然而，这并不总是适用，特别是在执行计数、求和、平均值等聚合的系统中。Cassandra 中的计数器机制正是具有这种约束。无法撤销对计数器的增加，也无法使增加幂等。如果元组被重播，计数器将再次递增，你很可能在系统中过度计数元素。因此，任何由 Cassandra 计数器支持的状态实现都被视为非事务性的。

同样，Druid 是非事务性的。一旦 Druid 消费了一个事件，该事件就无法撤销。因此，如果 Storm 中的一个批次被 Druid 部分消费，然后重新播放批次，或者组合发生变化，聚合维度分析就无法恢复。因此，考虑 Druid 和 Storm 之间的集成，以及我们可以采取的步骤来解决重播的问题，以及这种耦合的力量，这是很有趣的。

简而言之，要将 Storm 连接到 Druid，我们将利用事务 spout 的特性，以最小化连接到非事务状态机制（如 Druid）时的过度计数的风险。

# 拓扑结构

有了架构概念，让我们回到用例。为了将重点放在集成上，我们将保持拓扑的简单。以下图表描述了拓扑结构：

![拓扑结构](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/storm-bp/img/8294OS_07_03.jpg)

**FIX 喷口**发出包含简单 FIX 消息的元组。然后过滤器检查消息的类型，过滤包含定价信息的股票订单。然后，这些经过过滤的元组流向`DruidState`对象，它是与 Druid 连接的桥梁。

这个简单拓扑的代码如下所示：

```scala
public class FinancialAnalyticsTopology {

    public static StormTopology buildTopology() {
    TridentTopology topology = new TridentTopology();
    FixEventSpout spout = new FixEventSpout();
    Stream inputStream = 
topology.newStream("message", spout);
    inputStream.each(new Fields("message"),
new MessageTypeFilter())
        .partitionPersist(new DruidStateFactory(),
new Fields("message"), new DruidStateUpdater());
    return topology.build();
    }

}
```

## 喷口

FIX 消息格式有许多解析器。在喷口中，我们将使用 FIX 解析器，这是一个 Google 项目。关于这个项目的更多信息，您可以参考[`code.google.com/p/fixparser/`](https://code.google.com/p/fixparser/)。

就像前一章一样，喷口本身很简单。它只是返回一个协调器和一个发射器的引用，如下面的代码所示：

```scala
package com.packtpub.storm.trident.spout;

@SuppressWarnings("rawtypes")
public class FixEventSpout implements ITridentSpout<Long> {
    private static final long serialVersionUID = 1L;
    SpoutOutputCollector collector;
    BatchCoordinator<Long> coordinator = new DefaultCoordinator();
    Emitter<Long> emitter = new FixEventEmitter();
    ...
    @Override
    public Fields getOutputFields() {
        return new Fields("message");
    }
}
```

如前面的代码所示，`Spout`声明了一个单一的输出字段：`message`。这将包含`Emitter`生成的`FixMessageDto`对象，如下面的代码所示：

```scala
package com.packtpub.storm.trident.spout;

public class FixEventEmitter implements Emitter<Long>,
Serializable {
    private static final long serialVersionUID = 1L;
    public static AtomicInteger successfulTransactions = 
new AtomicInteger(0);
    public static AtomicInteger uids = new AtomicInteger(0);

    @SuppressWarnings("rawtypes")
    @Override
    public void emitBatch(TransactionAttempt tx,
    Long coordinatorMeta, TridentCollector collector) {
    InputStream inputStream = null;
    File file = new File("fix_data.txt");
    try {
        inputStream = 
new BufferedInputStream(new FileInputStream(file));
        SimpleFixParser parser = new SimpleFixParser(inputStream);
        SimpleFixMessage msg = null;
        do {
        msg = parser.readFixMessage();
        if (null != msg) {
            FixMessageDto dto = new FixMessageDto();
            for (TagValue tagValue : msg.fields()) {
                if (tagValue.tag().equals("6")) { // AvgPx
                    // dto.price = 
//Double.valueOf((String) tagValue.value());
                    dto.price = new Double((int) (Math.random() * 100));
                } else if (tagValue.tag().equals("35")) {
                    dto.msgType = (String)tagValue.value();
                } else if (tagValue.tag().equals("55")) {
                   dto.symbol = (String) tagValue.value();
                } else if (tagValue.tag().equals("11")){
                   // dto.uid = (String) tagValue.value();
                   dto.uid = Integer.toString(uids.incrementAndGet());
                }
            }
            new ObjectOutputStream(
            new ByteArrayOutputStream()).writeObject(dto);
                List<Object> message = new ArrayList<Object>();
                message.add(dto);
                collector.emit(message);
        }
    } while (msg != null);
    } catch (Exception e) {
        throw new RuntimeException(e);
    } finally {
        IoUtils.closeSilently(inputStream);
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

从前面的代码中，您可以看到我们为每个批次重新解析文件。正如我们之前所述，在实时系统中，我们可能会通过 TCP/IP 接收消息，并将它们排队在 Kafka 中。然后，我们将使用 Kafka 喷口发出这些消息。这是一个偏好问题；但是，为了完全封装 Storm 中的数据处理，系统很可能会排队原始消息文本。在这种设计中，我们将在一个函数中解析文本，而不是在喷口中。

尽管这个“喷口”只适用于这个例子，但请注意每个批次的组成是相同的。具体来说，每个批次包含文件中的所有消息。由于我们的状态设计依赖于这一特性，在一个真实的系统中，我们需要使用`TransactionalKafkaSpout`。

## 过滤器

与喷口一样，过滤器也很简单。它检查`msgType`对象并过滤掉不是填单的消息。填单实际上是股票购买收据。它们包含了该交易执行的平均价格和所购买股票的符号。以下代码是这种消息类型的过滤器：

```scala
package com.packtpub.storm.trident.operator;

public class MessageTypeFilter extends BaseFilter {
    private static final long serialVersionUID = 1L;

    @Override
    public boolean isKeep(TridentTuple tuple) {
        FixMessageDto message = (FixMessageDto) tuple.getValue(0);
    if (message.msgType.equals("8")) {
        return true;
    }
    return false;
    }
}
```

这为我们提供了一个很好的机会来指出 Storm 中可序列化性的重要性。请注意，在前面的代码中，过滤器操作的是一个`FixMessageDto`对象。使用`SimpleFixMessage`对象可能更容易，但`SimpleFixMessage`不可序列化。这在本地集群上运行时不会造成任何问题。然而，在 Storm 中进行数据处理时，元组在主机之间交换，元组中的所有元素都必须是可序列化的。

### 提示

开发人员经常对不可序列化的元组中的数据对象进行更改。这会导致下游部署问题。为了确保元组中的所有对象保持可序列化，添加一个验证对象可序列化的单元测试。这个测试很简单，使用以下代码：

```scala
new ObjectOutputStream(
new ByteArrayOutputStream()).
writeObject(YOUR_OBJECT);
```

## 状态设计

现在，让我们继续讨论这个例子最有趣的方面。为了将 Druid 与 Storm 集成，我们将在我们的拓扑中嵌入一个实时的 Druid 服务器，并实现必要的接口将元组流连接到它。为了减轻连接到非事务性系统的固有风险，我们利用 ZooKeeper 来持久化状态信息。这种持久化不会防止由于故障而导致的异常，但它将有助于确定故障发生时哪些数据处于风险之中。

高级设计如下所示：

![状态设计](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/storm-bp/img/8294OS_07_04.jpg)

在高层次上，Storm 通过使用工厂在 worker JVM 进程中创建状态对象。为批次中的每个分区创建一个状态对象。状态工厂对象确保在返回任何状态对象之前，实时服务器正在运行，并在服务器未运行时启动服务器。然后状态对象缓冲这些消息，直到 Storm 调用 commit。当 Storm 调用 commit 时，状态对象解除 Druid **Firehose**的阻塞。这向 Druid 发送信号，表明数据已准备好进行聚合。然后，在 commit 方法中阻塞 Storm，而实时服务器通过**Firehose**开始拉取数据。

为了确保每个分区最多被处理一次，我们将分区标识符与每个分区关联起来。分区标识符是批次标识符和分区索引的组合，可以唯一标识一组数据，因为我们使用了事务性 spout。

**Firehose**将标识符持久化在**ZooKeeper**中以维护分区的状态。

**ZooKeeper**中有三种状态：

| 状态 | 描述 |
| --- | --- |
| inProgress | 这个`Zookeeper`路径包含了 Druid 正在处理的分区标识符。 |
| Limbo | 这个`Zookeeper`路径包含了 Druid 完全消耗但可能尚未提交的分区标识符。 |
| 完成 | 这个`Zookeeper`路径包含了 Druid 成功提交的分区标识符。 |

在处理批次时，**Firehose**将分区标识符写入 inProgress 路径。当 Druid 完全拉取了 Storm 分区的全部数据时，分区标识符被移动到**Limbo**，我们释放 Storm 继续处理，同时等待 Druid 的提交消息。

收到 Druid 的提交消息后，**Firehose**将分区标识符移动到**Completed**路径。此时，我们假设数据已写入磁盘。然而，在磁盘故障的情况下，我们仍然容易丢失数据。但是，如果我们假设可以使用批处理重建聚合，那么这很可能是可以接受的风险。

以下状态机捕捉了处理的不同阶段：

![状态设计](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/storm-bp/img/8294OS_07_05.jpg)

如图所示，在**缓冲消息**和**聚合消息**之间存在一个循环。主控制循环在这两种状态之间快速切换，将其时间分配给 Storm 处理循环和 Druid 聚合循环。这些状态是互斥的：系统要么在聚合一个批次，要么在缓冲下一个批次。

第三种状态是当 Druid 将信息写入磁盘时触发的。当发生这种情况（稍后我们将看到），**Firehose**会收到通知，我们可以更新我们的持久化机制，以指示批次已安全处理。在调用 commit 之前，Druid 消耗的批次必须保持在**Limbo**中。

在**Limbo**中，不能对数据做任何假设。Druid 可能已经聚合了记录，也可能没有。

在发生故障时，Storm 可能利用其他`TridentState`实例来完成处理。因此，对于每个分区，**Firehose**必须执行以下步骤：

1.  **Firehose**必须检查分区是否已经完成。如果是，那么分区是一个重播，可能是由于下游故障。由于批次保证与之前相同，可以安全地忽略，因为 Druid 已经聚合了其内容。系统可能会记录警告消息。

1.  **Firehose**必须检查分区是否处于悬空状态。如果是这种情况，那么 Druid 完全消耗了分区，但从未调用 commit，或者在调用 commit 之后但在**Firehose**更新**ZooKeeper**之前系统失败了。系统应该发出警报。它不应该尝试完成批处理，因为它已被 Druid 完全消耗，我们不知道聚合的状态。它只是返回，使 Storm 可以继续进行下一批处理。

1.  **Firehose**必须检查分区是否正在进行中。如果是这种情况，那么由于某种原因，在网络的某个地方，分区正在被另一个实例处理。这在普通处理过程中不应该发生。在这种情况下，系统应该为该分区发出警报。在我们简单的系统中，我们将简单地继续进行，留待离线批处理来纠正聚合。

在许多大规模实时系统中，用户愿意容忍实时分析中的轻微差异，只要偏差不经常发生并且可以很快得到纠正。

重要的是要注意，这种方法成功的原因是我们使用了事务性 spout。事务性 spout 保证每个批次具有相同的组成。此外，为了使这种方法有效，批处理中的每个分区必须具有相同的组成。只有在拓扑中的分区是确定性的情况下才成立。有了确定性的分区和事务性 spout，即使在重放的情况下，每个分区也将包含相同的数据。如果我们使用了洗牌分组，这种方法就不起作用。我们的示例拓扑是确定性的。这保证了批处理标识符与分区索引结合表示了随时间一致的数据集。

# 实施架构

有了设计之后，我们可以将注意力转向实施。实施的序列图如下所示：

![实施架构](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/storm-bp/img/8294OS_07_06.jpg)

前面的图实现了设计中显示的状态机。一旦实时服务器启动，Druid 使用`hasMore()`方法轮询`StormFirehose`对象。与 Druid 的合同规定，`Firehose`对象的实现应该在数据可用之前阻塞。当 Druid 在轮询而`Firehose`对象在阻塞时，Storm 将元组传递到`DruidState`对象的消息缓冲区中。当批处理完成时，Storm 调用`DruidState`对象的`commit()`方法。在那时，PartitionStatus 被更新。分区被放置在进行中，并且实现解除`StormFirehose`对象的阻塞。

Druid 开始通过`nextRow()`方法从`StormFirehose`对象中拉取数据。当`StormFirehose`对象耗尽分区的内容时，它将分区置于悬空状态，并将控制权释放给 Storm。

最后，当在 StormFirehose 上调用 commit 方法时，实现会返回一个`Runnable`，这是 Druid 用来通知 Firehose 分区已持久化的方式。当 Druid 调用`run()`时，实现会将分区移动到完成状态。

## DruidState

首先，我们将看一下风暴方面的情况。在上一章中，我们扩展了`NonTransactionalMap`类以持久化状态。这种抽象使我们免受顺序批处理细节的影响。我们只需实现`IBackingMap`接口来支持`multiGet`和`multiPut`调用，超类就会处理其余部分。

在这种情况下，我们需要比默认实现提供的更多对持久化过程的控制。相反，我们需要自己实现基本的`State`接口。以下类图描述了类层次结构：

![DruidState](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/storm-bp/img/8294OS_07_07.jpg)

正如图中所示，`DruidStateFactory`类管理嵌入式实时节点。可以提出一个论点，认为更新程序管理嵌入式服务器。然而，由于每个 JVM 应该只有一个实时服务器实例，并且该实例需要在任何状态对象之前存在，因此嵌入式服务器的生命周期管理似乎更自然地适合工厂。

以下代码片段包含了`DruidStateFactory`类的相关部分：

```scala
public class DruidStateFactory implements StateFactory {
    private static final long serialVersionUID = 1L;
    private static final Logger LOG = 
LoggerFactory.getLogger(DruidStateFactory.class);
    private static RealtimeNode rn = null;

    private static synchronized void startRealtime() {
    if (rn == null) {
        final Lifecycle lifecycle = new Lifecycle();
        rn = RealtimeNode.builder().build();
        lifecycle.addManagedInstance(rn);
        rn.registerJacksonSubtype(
        new NamedType(StormFirehoseFactory.class, "storm"));

        try {
            lifecycle.start();
        } catch (Throwable t) {

        }
    }
    }

    @Override
    public State makeState(Map conf, IMetricsContext metrics,
        int partitionIndex, int numPartitions) {
            DruidStateFactory.startRealtime();
            return new DruidState(partitionIndex);
    }
}
```

不详细介绍，前面的代码如果尚未启动实时节点，则启动一个实时节点。此外，它将`StormFirehoseFactory`类注册到该实时节点。

工厂还实现了来自 Storm 的`StateFactory`接口，允许 Storm 使用此工厂创建新的`State`对象。`State`对象本身非常简单：

```scala
public class DruidState implements State {
private static final Logger LOG = 
LoggerFactory.getLogger(DruidState.class);
private Vector<FixMessageDto> messages = 
new Vector<FixMessageDto>();
    private int partitionIndex;

public DruidState(int partitionIndex){
    this.partitionIndex = partitionIndex;
}

@Override
    public void beginCommit(Long batchId) {
}

@Override
public void commit(Long batchId) {
    String partitionId = batchId.toString() + "-" + partitionIndex;
    LOG.info("Committing partition [" + 
        partitionIndex + "] of batch [" + batchId + "]");
    try {
        if (StormFirehose.STATUS.isCompleted(partitionId)) {
        LOG.warn("Encountered completed partition [" 
            + partitionIndex + "] of batch [" + batchId 
                + "]");
        return;
    } else if (StormFirehose.STATUS.isInLimbo(partitionId)) {
        LOG.warn("Encountered limbo partition [" + partitionIndex 
                 + "] of batch [" + batchId + 
                 "] : NOTIFY THE AUTHORITIES!");
        return;
    } else if (StormFirehose.STATUS.isInProgress(partitionId)) {
              LOG.warn("Encountered in-progress partition [\" + 
              partitionIndex + \"] of batch [" + batchId + 
              "] : NOTIFY THE AUTHORITIES!");
        return;
    }
    StormFirehose.STATUS.putInProgress(partitionId);
    StormFirehoseFactory.getFirehose()
        .sendMessages(partitionId, messages);
    } catch (Exception e) {
            LOG.error("Could not start firehose for [" + 
                      partitionIndex + "] of batch [" + 
                      batchId + "]", e);
    }
    }

public void aggregateMessage(FixMessageDto message) {
    messages.add(message);
}
}
```

如前面的代码所示，`State`对象是一个消息缓冲区。它将实际的提交逻辑委托给`Firehose`对象，我们将很快进行检查。然而，在这个类中有一些关键的行，实现了我们之前概述的故障检测。

`State`对象上`commit()`方法中的条件逻辑检查 ZooKeeper 状态，以确定此分区是否已成功处理（`inCompleted`），未能提交（`inLimbo`）或在处理过程中失败（`inProgress`）。当我们检查`DruidPartitionStatus`对象时，我们将更深入地了解状态存储。

还要注意的是，`commit()`方法由 Storm 直接调用，但`aggregateMessage()`方法由更新程序调用。即使 Storm 不应该同时调用这些方法，我们还是选择使用线程安全的向量。

DruidStateUpdater 代码如下：

```scala
public class DruidStateUpdater implements StateUpdater<DruidState> {
...
@Override
public void updateState(DruidState state, 
List<TridentTuple> tuples, TridentCollector collector) {
for (TridentTuple tuple : tuples) {
   	   FixMessageDto message = (FixMessageDto) tuple.getValue(0);
      state.aggregateMessage(message);
   }
}
}
```

如前面的代码所示，更新程序只是简单地循环遍历元组，并将它们传递给状态对象进行缓冲。

## 实现 StormFirehose 对象

在我们转向 Druid 实现的一侧之前，我们可能应该退一步，更详细地讨论一下 Druid。Druid 的数据源是通过一个规范文件进行配置的。在我们的示例中，这是`realtime.spec`，如下面的代码所示：

```scala
[{
    "schema": {
        "dataSource": "stockinfo",
        "aggregators": [
            { "type": "count", "name": "orders"},
            { "type": "doubleSum", "fieldName": "price", "name":"totalPrice" }
        ],
        "indexGranularity": "minute",
        "shardSpec": {"type": "none"}
    },

    "config": {
        "maxRowsInMemory": 50000,
        "intermediatePersistPeriod": "PT30s"
    },

    "firehose": {
        "type": "storm",
        "sleepUsec": 100000,
        "maxGeneratedRows": 5000000,
        "seed": 0,
        "nTokens": 255,
        "nPerSleep": 3
    },

    "plumber": {
        "type": "realtime",
        "windowPeriod": "PT30s",
        "segmentGranularity": "minute",
        "basePersistDirectory": "/tmp/example/rand_realtime/basePersist"
    }
}]
```

对于我们的示例，在前面的规范文件中，重要的元素是`schema`和`firehose`。`schema`元素定义了数据和 Druid 应该对该数据执行的聚合。在我们的示例中，Druid 将计算我们在`orders`字段中看到股票符号的次数，并跟踪`totalPrice`字段中支付的总价格。`totalPrice`字段将用于计算随时间变化的股票价格平均值。此外，您需要指定一个`indexGranularity`对象，该对象指定索引的时间粒度。

`firehose`元素包含`Firehose`对象的配置。正如我们在`StateFactory`接口中看到的，实现在实时服务器启动时向 Druid 注册了一个`FirehoseFactory`类。该工厂被注册为`Jackson`子类型。当解析实时规范文件时，JSON 中`firehose`元素中的类型用于链接回适用于数据流的适当`FirehoseFactory`。

有关 JSON 多态性的更多信息，请参考以下网站：

[`wiki.fasterxml.com/JacksonPolymorphicDeserialization`](http://wiki.fasterxml.com/JacksonPolymorphicDeserialization)

有关规范文件的更多信息，请参考以下网站：

[`github.com/metamx/druid/wiki/Realtime`](https://github.com/metamx/druid/wiki/Realtime)

现在，我们可以把注意力转向 Druid 实现的一侧。`Firehose`是必须实现的主要接口，以将数据贡献到 Druid 实时服务器中。

我们的`StormFirehoseFactory`类的代码如下：

```scala
@JsonTypeName("storm")
public class StormFirehoseFactory implements FirehoseFactory {
    private static final StormFirehose FIREHOSE = 
    new StormFirehose();
    @JsonCreator
    public StormFirehoseFactory() {
    }

    @Override
    public Firehose connect() throws IOException {
        return FIREHOSE;
    }

    public static StormFirehose getFirehose(){
        return FIREHOSE;
    }
}
```

工厂实现很简单。在这种情况下，我们只返回一个静态的单例对象。请注意，该对象带有`@JsonTypeName`和`@JsonCreator`注解。如前面的代码所述，`Jackson`是`FirehoseFactory`对象注册的手段。因此，`@JsonTypeName`指定的名称必须与规范文件中指定的类型一致。

实现的核心在`StormFirehose`类中。在这个类中，有四个关键方法，我们将逐一检查：`hasMore()`，`nextRow()`，`commit()`和`sendMessages()`。

`sendMessages()`方法是进入`StormFirehose`类的入口点。这实际上是 Storm 和 Druid 之间的交接点。该方法的代码如下：

```scala
public synchronized void sendMessages(String partitionId, 
                     List<FixMessageDto> messages) {
    BLOCKING_QUEUE = 
    new ArrayBlockingQueue<FixMessageDto>(messages.size(), 
    false, messages);
    TRANSACTION_ID = partitionId;
    LOG.info("Beginning commit to Druid. [" + messages.size() + 
    "] messages, unlocking [START]");
    synchronized (START) {
        START.notify();
    }
    try {
        synchronized (FINISHED) {
        FINISHED.wait();
        }
    } catch (InterruptedException e) {
        LOG.error("Commit to Druid interrupted.");
    }
    LOG.info("Returning control to Storm.");
}
```

该方法是同步的，以防止并发问题。请注意，它除了将消息缓冲区复制到队列中并通知`hasMore()`方法释放批处理外，不做任何其他操作。然后，它会阻塞等待 Druid 完全消耗批处理。

然后，流程继续到`nextRow()`方法，如下所示：

```scala
    @Override
    public InputRow nextRow() {
        final Map<String, Object> theMap = 
        Maps.newTreeMap(String.CASE_INSENSITIVE_ORDER);
        try {
        FixMessageDto message = null;
        message = BLOCKING_QUEUE.poll();

        if (message != null) {
        LOG.info("[" + message.symbol + "] @ [" +
         message.price + "]");
        theMap.put("symbol", message.symbol);
        theMap.put("price", message.price);
        }

        if (BLOCKING_QUEUE.isEmpty()) {
        STATUS.putInLimbo(TRANSACTION_ID);
        LIMBO_TRANSACTIONS.add(TRANSACTION_ID);
        LOG.info("Batch is fully consumed by Druid. " 
        + "Unlocking [FINISH]");
        synchronized (FINISHED) {
            FINISHED.notify();

        }
        }
    } catch (Exception e) {
        LOG.error("Error occurred in nextRow.", e);
        System.exit(-1);
    }
    final LinkedList<String> dimensions = 
    new LinkedList<String>();
    dimensions.add("symbol");
    dimensions.add("price");
    return new MapBasedInputRow(System.currentTimeMillis(), 
                                dimensions, theMap);
    }
```

该方法从队列中取出一条消息。如果不为空，则将数据添加到一个映射中，并作为`MapBasedInputRow`方法传递给 Druid。如果队列中没有剩余消息，则释放前面代码中检查的`sendMessages()`方法。从 Storm 的角度来看，批处理已完成。Druid 现在拥有数据。但是，从系统的角度来看，数据处于悬而未决状态，因为 Druid 可能尚未将数据持久化到磁盘。在硬件故障的情况下，我们有丢失数据的风险。

然后 Druid 将轮询`hasMore()`方法，如下所示：

```scala
@Override
public boolean hasMore() {
    if (BLOCKING_QUEUE != null && !BLOCKING_QUEUE.isEmpty())
        return true;
    try {
        synchronized (START) {
        START.wait();
        }
    } catch (InterruptedException e) {
        LOG.error("hasMore() blocking interrupted!");
    }
    return true;
}
```

由于队列为空，该方法将阻塞，直到再次调用`sendMessage()`。

现在只剩下一个谜题的部分，`commit()`方法。它在以下代码中显示：

```scala
    @Override
    public Runnable commit() {
	List<String> limboTransactions = new ArrayList<String>();
	LIMBO_TRANSACTIONS.drainTo(limboTransactions);
	return new StormCommitRunnable(limboTransactions);
    }
```

这个方法返回`Runnable`，在 Druid 完成持久化消息后被调用。尽管`Firehose`对象中的所有其他方法都是从单个线程调用的，但`Runnable`是从不同的线程调用的，因此必须是线程安全的。因此，我们将悬而未决的事务复制到一个单独的列表中，并将其传递给`Runnable`对象的构造函数。如下代码所示，`Runnable`除了将事务移动到`Zookeeper`中的已完成状态外，什么也不做。

```scala
public class StormCommitRunnable implements Runnable {
    private List<String> partitionIds = null;

    public StormCommitRunnable(List<String> partitionIds){
        this.partitionIds = partitionIds;
    }

    @Override
    public void run() {
    try {
        StormFirehose.STATUS.complete(partitionIds);
    } catch (Exception e) {
        Log.error("Could not complete transactions.", e);
    }
}
}
```

## 在 ZooKeeper 中实现分区状态

现在我们已经检查了所有的代码，我们可以看一下状态如何在 ZooKeeper 中持久化。这使得系统能够协调分布式处理，特别是在发生故障时。

该实现利用 ZooKeeper 来持久化分区处理状态。ZooKeeper 是另一个开源项目。更多信息，请参考[`zookeeper.apache.org/`](http://zookeeper.apache.org/)。

ZooKeeper 维护一个节点树。每个节点都有一个关联的路径，就像文件系统一样。实现使用 ZooKeeper 通过一个叫做 Curator 的框架。更多信息，请参考[`curator.incubator.apache.org/`](http://curator.incubator.apache.org/)。

通过 Curator 连接到 ZooKeeper 时，您提供一个命名空间。实际上，这是应用数据存储在其中的顶级节点。在我们的实现中，命名空间是`stormdruid`。然后应用在其中维护三个路径，用于存储批处理状态信息。

路径对应于设计中描述的状态，如下所示：

+   `/stormdruid/current`：这对应于当前状态

+   `/stormdruid/limbo`：这对应于悬而未决的状态

+   `/stormdruid/completed`：这对应于已完成的状态

在我们的实现中，所有关于分区状态的 ZooKeeper 交互都通过`DruidPartitionStatus`类运行。

该类的代码如下：

```scala
public class DruidBatchStatus {
    private static final Logger LOG = 
LoggerFactory.getLogger(DruidBatchStatus.class);
    final String COMPLETED_PATH = "completed";
    final String LIMBO_PATH = "limbo";
    final String CURRENT_PATH = "current";
    private CuratorFramework curatorFramework;

    public DruidBatchStatus() {
    try {
curatorFramework = 
    CuratorFrameworkFactory.builder()
    .namespace("stormdruid")
    .connectString("localhost:2181")
    .retryPolicy(new RetryNTimes(1, 1000))
    .connectionTimeoutMs(5000)
            .build();
        curatorFramework.start();

        if (curatorFramework.checkExists()
    .forPath(COMPLETED_PATH) == null) {
        curatorFramework.create().forPath(COMPLETED_PATH);
        }

    }catch (Exception e) {
        LOG.error("Could not establish connection to Zookeeper", 
                  e);
    }
    }

    public boolean isInLimbo(String paritionId) throws Exception {
        return (curatorFramework.checkExists().forPath(LIMBO_PATH + "/" + paritionId) != null);
    }

    public void putInLimbo(Long paritionId) throws Exception {
    curatorFramework.inTransaction().
        delete().forPath(CURRENT_PATH + "/" + paritionId)
        .and().create().forPath(LIMBO_PATH + "/" + 
                                paritionId).and().commit();
    }
}
```

出于空间考虑，我们只显示了构造函数和与 limbo 状态相关的方法。在构造函数中，客户端连接到 ZooKeeper 并创建了前面代码中描述的三个基本路径。然后，它提供了查询方法来测试事务是否正在进行中、处于 limbo 状态或已完成。它还提供了将事务在这些状态之间移动的方法。

# 执行实现

够了，不要再看代码了，让我们进行演示吧！我们使用`FinancialAnalyticsTopology`类的主方法启动拓扑。为了更好的演示，我们引入了零到一百之间的随机价格。（参考`Emitter`代码。）

一旦拓扑启动，您将看到以下输出：

```scala
2014-02-16 09:47:15,479-0500 | INFO [Thread-18] DefaultCoordinator.initializeTransaction(24) | Initializing Transaction [1615]
2014-02-16 09:47:15,482-0500 | INFO [Thread-22] DruidState.commit(28) | Committing partition [0] of batch [1615]
2014-02-16 09:47:15,484-0500 | INFO [Thread-22] StormFirehose.sendMessages(82) | Beginning commit to Druid. [7996] messages, unlocking [START]
2014-02-16 09:47:15,511-0500 | INFO [chief-stockinfo] StormFirehose.nextRow(58) | Batch is fully consumed by Druid. Unlocking [FINISH]
2014-02-16 09:47:15,511-0500 | INFO [Thread-22] StormFirehose.sendMessages(93) | Returning control to Storm.
2014-02-16 09:47:15,513-0500 | INFO [Thread-18] DefaultCoordinator.success(30) | Successful Transaction [1615] 
```

您可以从多个维度对处理进行审查。

使用 ZooKeeper 客户端，您可以检查事务的状态。看一下下面的列表；它显示了事务/批处理标识符及其状态：

```scala
[zk: localhost:2181(CONNECTED) 50] ls /stormdruid/current
[501-0]
[zk: localhost:2181(CONNECTED) 51] ls /stormdruid/limbo
[486-0, 417-0, 421-0, 418-0, 487-0, 485-0, 484-0, 452-0, ...
[zk: localhost:2181(CONNECTED) 82] ls /stormdruid/completed
[zk: localhost:2181(CONNECTED) 52] ls /stormdruid/completed
[59-0, 321-0, 296-0, 357-0, 358-0, 220-0, 355-0,
```

对于警报和监控，请注意以下内容：

+   如果`current`路径中有多个批处理，那么应该发出警报

+   如果`limbo`中有不连续的批处理标识符，或者明显落后于当前标识符，应该发出警报

要清理 ZooKeeper 中的状态，您可以执行以下代码：

```scala
zk: localhost:2181(CONNECTED) 83] rmr /stormdruid
```

要监控段的传播，您可以使用 MySQL 客户端。使用默认模式，您可以通过以下代码从`prod_segments`表中选择出段：

```scala
mysql> select * from prod_segments;
```

# 审查分析

现在，我们一直在等待的时刻到了；我们可以通过 Druid 提供的 REST API 看到随时间变化的平均股价。要使用 REST API，不需要运行一个完整的 Druid 集群。您只能查询单个嵌入式实时节点看到的数据，但每个节点都能够处理请求，这使得测试更容易。使用 curl，您可以使用以下命令查询实时节点：

```scala
curl -sX POST "http://localhost:7070/druid/v2/?pretty=true" -H 'content-type: application/json'  -d @storm_query

```

`curl`语句的最后一个参数引用一个文件，该文件的内容将作为`POST`请求的正文包含在其中。该文件包含以下细节：

```scala
{
    "queryType": "groupBy",
    "dataSource": "stockinfo",
    "granularity": "minute",
    "dimensions": ["symbol"],
    "aggregations":[
        { "type": "longSum", "fieldName": "orders",
         "name": "cumulativeCount"},
        { "type": "doubleSum", "fieldName": "totalPrice",
         "name": "cumulativePrice" }
    ],
    "postAggregations":[
    {  "type":"arithmetic",
        "name":"avg_price",
        "fn":"/",
        "fields":[ {"type":"fieldAccess","name":"avgprice",
        "fieldName":"cumulativePrice"},
                   {"type":"fieldAccess","name":"numrows",
        "fieldName":"cumulativeCount"}]}
    ],
    "intervals":["2012-10-01T00:00/2020-01-01T00"]
}
```

Druid 中有两种聚合类型。索引过程中发生的聚合和查询时发生的聚合。索引期间发生的聚合在规范文件中定义。如果你还记得，我们在规范文件中有两种聚合：

```scala
"aggregators": [
{ "type": "count", "name": "orders"},
   { "type": "doubleSum", "fieldName": "price",
"name": "totalPrice" }
],
```

我们正在聚合的事件有两个字段：`symbol`和`price`。前面的聚合是在索引时间应用的，并引入了两个额外的字段：`totalPrice`和`orders`。请记住，`totalPrice`是该时间段内每个事件的价格总和。`orders`字段包含了该时间段内事件的总数。

然后，在执行查询时，Druid 根据`groupBy`语句应用了第二组聚合。在我们的查询中，我们按分钟对`symbol`进行分组。然后聚合引入了两个新字段：`cumulativeCount`和`cumulativePrice`。这些字段包含了前面聚合的总和。

最后，我们引入了一个`postaggregation`方法来计算该时间段的平均值。该`postaggregation`方法将两个累积字段进行除法（“fn”：“/”），得到一个新的`avg_price`字段。

向运行中的服务器发出`curl`语句会得到以下响应：

```scala
[ {
  "version" : "v1",
  "timestamp" : "2013-05-15T22:31:00.000Z",
  "event" : {
    "cumulativePrice" : 3464069.0,
    "symbol" : "MSFT",
    "cumulativeCount" : 69114,
    "avg_price" : 50.12108979367422
  }
}, {
  "version" : "v1",
  "timestamp" : "2013-05-15T22:31:00.000Z",
  "event" : {
    "cumulativePrice" : 3515855.0,
    "symbol" : "ORCL",
    "cumulativeCount" : 68961,
    "avg_price" : 50.98323690201708
  }
...
 {
  "version" : "v1",
  "timestamp" : "2013-05-15T22:32:00.000Z",
  "event" : {
    "cumulativePrice" : 1347494.0,
    "symbol" : "ORCL",
    "cumulativeCount" : 26696,
    "avg_price" : 50.47550194785736
  }
}, {
  "version" : "v1",
  "timestamp" : "2013-05-15T22:32:00.000Z",
  "event" : {
    "cumulativePrice" : 707317.0,
    "symbol" : "SPY",
    "cumulativeCount" : 13453,
    "avg_price" : 52.576897346316805
  }
} ]
```

自从我们更新了代码以生成零到一百之间的随机价格，平均价格大约是五十。（哇呼！）

# 总结

在本章中，我们更加深入地了解了 Trident State API。我们创建了`State`和`StateUpdater`接口的直接实现，而不是依赖于默认实现。具体来说，我们实现了这些接口来弥合事务型 spout 和非事务型系统（即 Druid）之间的差距。虽然在非事务型存储中无法确保精确一次语义，但我们已经采取了机制来在系统遇到问题时发出警报。显然，一旦失败，我们可以使用批处理机制来重建任何可疑的聚合段。

为了未来的调查，建立 Storm 和 Druid 之间的幂等接口将是有益的。为了做到这一点，我们可以在 Storm 中为每个批次发布一个单独的段。由于在 Druid 中段的传播是原子的，这将为我们提供一种机制，将每个批次原子地提交到 Druid 中。此外，批次可以并行处理，从而提高吞吐量。Druid 支持日益扩大的查询类型和聚合机制。它非常强大，Storm 和 Druid 的结合是非常强大的。


# 第八章：自然语言处理

有些人认为随着对实时分析和数据处理的需求增加，Storm 最终会取代 Hadoop。在本章中，我们将看到 Storm 和 Hadoop 实际上是如何互补的。

尽管 Storm 模糊了传统 OLTP 和 OLAP 之间的界限，但它可以处理大量交易，同时执行通常与数据仓库相关的聚合和维度分析。通常情况下，您仍然需要额外的基础设施来执行历史分析，并支持整个数据集的临时查询。此外，批处理通常用于纠正 OLTP 系统无法在故障发生时确保一致性的异常情况。这正是我们在 Storm-Druid 集成中遇到的情况。

出于这些原因，批处理基础设施通常与实时基础设施配对使用。Hadoop 为我们提供了这样一个批处理框架。在本章中，我们将实现一个支持历史和临时分析的架构，通过批处理。

本章涵盖以下主题：

+   CAP 定理

+   Lambda 架构

+   OLTP 和 OLAP 集成

+   Hadoop 简介

# 激发 Lambda 架构

首先，从逻辑角度来看，让我们看一下 Storm-Druid 集成。Storm，特别是 Trident，能够执行分布式分析，因为它隔离了状态转换。为了做到这一点，Storm 对状态的基础持久性机制做出了一些假设。Storm 假设持久性机制既是*一致的*又是*可用的*。具体来说，Storm 假设一旦进行了状态转换，新状态就会被共享，在所有节点上保持一致，并立即可用。

根据 CAP 定理，我们知道任何分布式系统要同时提供以下三个保证是困难的：

+   一致性：所有节点上的状态相同

+   可用性：系统可以对查询做出成功或失败的响应

+   分区容错性：系统在通信丢失或部分系统故障的情况下仍能做出响应

越来越多的 Web 规模架构集成了对一致性采取宽松态度的持久性机制，以满足可用性和分区容错性的要求。通常，这些系统这样做是因为在大型分布式系统中提供整个系统的事务一致性所需的协调变得不可行。性能和吞吐量更重要。

Druid 也做出了同样的权衡。如果我们看一下 Druid 的持久性模型，我们会看到几个不同的阶段：

![激发 Lambda 架构](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/storm-bp/img/8294OS_08_01.jpg)

首先，Druid 通过`Firehose`接口消耗数据并将数据放入内存。其次，数据被持久化到磁盘，并通过`Runnable`接口通知`Firehose`实现。最后，这些数据被推送到**深度存储**，使数据对系统的其他部分可用。

现在，如果我们考虑不一致数据对容错性的影响，我们会发现数据在持久存储之前是有风险的。如果我们丢失了某个节点，我们就会失去该节点上所有数据的分析，因为我们已经确认了元组。

解决这个问题的一个明显的方法是在承认 Storm 中的元组之前将段推送到深度存储。这是可以接受的，但它会在 Storm 和 Druid 之间创建一个脆弱的关系。具体来说，批处理大小和超时需要与段大小和 Druid 的段推送到深度存储的时间保持一致。换句话说，我们的事务处理系统的吞吐量将受到限制，并与我们用于分析处理的系统密切相关。最终，这很可能是我们不想要的依赖关系。

然而，我们仍然希望进行实时分析，并愿意容忍在部分系统故障的情况下，这些分析可能会缺少一部分数据。从这个角度来看，这种集成是令人满意的。但理想情况下，我们希望有一种机制来纠正和恢复任何故障。为此，我们将引入离线批处理机制，以在发生故障时恢复和纠正数据。

为了使这项工作，我们将首先在将数据发送到 Druid 之前持久化数据。我们的批处理系统将离线从持久性机制中读取数据。批处理系统将能够纠正/更新系统在实时处理期间可能丢失的任何数据。通过结合这些方法，我们可以在实时处理中实现所需的吞吐量，并且分析结果准确，直到系统发生故障，并且有一种机制可以在发生故障时纠正这些分析。

分布式批处理的事实标准是 Hadoop。因此，我们将在这里使用 Hadoop 进行历史（即非实时）分析。以下图表描述了我们将在这里使用的模式：

激励 Lambda 架构

前面的模式显示了我们如何成功地集成 OLTP 和 OLAP 系统，同时在大部分情况下提供一致和完整的实时高吞吐量、可用性和分区分析。它同时提供了解决部分系统故障的机制。

这种方法填补的另一个空白是能够将新的分析引入系统。由于 Storm-Druid 集成侧重于实时问题，因此没有简单的方法将新的分析引入系统。 Hadoop 填补了这个空白，因为它可以在历史数据上运行以填充新的维度或执行额外的聚合。

Storm 的原始作者 Nathan Marz 将这种方法称为**Lambda 架构**。

# 检查我们的用例

现在，让我们将这种模式应用到**自然语言处理**（**NLP**）领域。在这个用例中，我们将搜索 Twitter 上与短语（例如“Apple Jobs”）相关的推文。然后系统将处理这些推文，试图找到最相关的单词。使用 Druid 来聚合这些术语，我们将能够随时间趋势最相关的单词。

让我们更详细地定义问题。给定搜索短语*p*，使用 Twitter API，我们将找到最相关的一组推文*T*。对于*T*中的每条推文*t*，我们将计算每个单词*w*的出现次数。我们将比较推文中该单词的频率与英文文本样本*E*中该单词的频率。然后系统将对这些单词进行排名，并显示前 20 个结果。

从数学上讲，这相当于以下形式：

查看我们的用例

在这里，语料库*C*中单词*w*的频率如下：

检查我们的用例

由于我们只关心相对频率，并且*T*中的单词总数和*E*中的单词总数在所有单词中都是恒定的，我们可以在方程中忽略它们，从而降低问题的复杂性，简化为以下形式：

检查我们的用例

对于分母，我们将使用以下链接中的免费可用单词频率列表：

[`invokeit.wordpress.com/frequency-word-lists/`](http://invokeit.wordpress.com/frequency-word-lists/)

我们将使用 Storm 来处理 Twitter 搜索的结果，并使用计数信息为分母来丰富元组。然后 Druid 将对分子进行计数，并使用后聚合函数来执行实际的相关性计算。

# 实现 Lambda 架构

对于这个用例，我们专注于一个分布式计算模式，它将实时处理平台（即 Storm）与分析引擎（即 Druid）集成起来；然后将其与离线批处理机制（即 Hadoop）配对，以确保我们拥有准确的历史指标。

虽然这仍然是重点，但我们试图实现的另一个关键目标是持续可用性和容错。更具体地说，系统应该能够容忍节点或者甚至数据中心的永久丢失。为了实现这种可用性和容错，我们需要更多地关注持久性。

在一个实时系统中，我们会使用分布式存储机制进行持久化，理想情况下是支持跨数据中心复制的存储机制。因此，即使在灾难情况下，一个数据中心完全丢失，系统也能够在不丢失数据的情况下恢复。在与持久存储交互时，客户端将要求一个一致性级别，该级别在事务中复制数据到多个数据中心。

在这次讨论中，假设我们使用 Cassandra 作为我们的持久化机制。对于 Cassandra，具有可调一致性的写入将使用`EACH_QUORUM`一致性级别。这确保了数据的副本一致地写入到所有数据中心。当然，这会在每次写入时引入数据中心间通信的开销。对于不太关键的应用程序，`LOCAL_QUORUM`可能是可以接受的，它避免了数据中心间通信的延迟。

使用 Cassandra 等分布式存储引擎的另一个好处是，可以为离线/批处理设置一个单独的环/集群。然后 Hadoop 可以使用该环作为输入，使系统能够重新摄入历史数据而不影响事务处理。考虑以下架构图：

![实现 Lambda 架构](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/storm-bp/img/8294OS_08_03.jpg)

在上图中，我们有两个物理数据中心，每个数据中心都有一个为 Storm 提供事务处理的 Cassandra 集群。这确保了拓扑中的任何写入都会实时复制到数据中心，无论是在元组被确认之前（如果我们使用`EACH_QUORUM`一致性）还是在懒惰地（如果我们使用`LOCAL_QUORUM`）。

此外，我们有第三个*虚拟*数据中心支持离线批处理。**Ring 3**是一个 Cassandra 集群，物理上与**Ring 1**相邻，但在 Cassandra 中配置为第二个数据中心。当我们运行 Hadoop 作业处理历史指标时，我们可以使用`LOCAL_QUORUM`。由于本地四分位数试图在本地数据中心内获得共识，来自 Hadoop 的读取流量不会跨越到我们的事务处理集群。

总的来说，如果你的组织有数据科学家/数据管理者在对数据进行分析，部署这种模式是一个很好的选择。通常，这些工作对数据要求很高。将这种工作负载与事务系统隔离开是很重要的。

此外，和我们在系统中容忍故障的能力一样重要的是，这种架构使我们能够在数据摄入时没有的情况下引入新的分析。Hadoop 可以使用新的分析配置运行所有相关的历史数据，以填充新的维度或执行额外的聚合。

# 为我们的用例设计拓扑

在这个例子中，我们将再次使用 Trident，并在前一章中构建的拓扑的基础上进行扩展。Trident 拓扑如下所示：

![为我们的用例设计拓扑](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/storm-bp/img/8294OS_08_04.jpg)

`TwitterSpout` 定期针对 Twitter API 进行搜索，将返回的 tweets 发射到 Trident 流中。`TweetSplitterFunction` 然后解析 tweets，并为每个单词发射一个元组。`WordFrequencyFunction` 为每个单词的元组添加来自英语语言的随机样本的计数。最后，我们让 Druid 消费这些信息，以执行随时间的聚合。Druid 将数据分区为时间切片，并像之前描述的那样持久化数据。

在这种情况下，因为持久化机制是我们解决容错/系统故障的手段，所以持久化机制应该分发存储，并提供一致性和高可用性。此外，Hadoop 应该能够使用持久化机制作为 map/reduce 作业的输入。

由于其可调整的一致性和对 Hadoop 的支持，Cassandra 是这种模式的理想持久化机制。由于 Cassandra 和多语言持久化已在其他地方进行了介绍，我们将保持这个例子简单，并使用本地文件存储。

# 实施设计

让我们首先从 spout 开始，逐步分析实时部分，直到 Druid 持久化。拓扑很简单，模仿了我们在前几章中编写的拓扑。

以下是拓扑的关键行：

```scala
TwitterSpout spout = new TwitterSpout();
Stream inputStream = topology.newStream("nlp", spout);
try {
inputStream.each(new Fields("tweet"), new TweetSplitterFunction(), new Fields("word"))
          .each(new Fields("searchphrase", "tweet", "word"), new WordFrequencyFunction(), new Fields("baseline"))
          .each(new Fields("searchphrase", "tweet", "word", "baseline"), new PersistenceFunction(), new Fields())	
          .partitionPersist(new DruidStateFactory(), new Fields("searchphrase", "tweet", "word", "baseline"), new DruidStateUpdater());
} catch (IOException e) {
throw new RuntimeException(e);
}
return topology.build();
```

最后，在解析和丰富之后，元组有四个字段，如下表所示：

| 字段名称 | 用途 |
| --- | --- |
| `searchphrase` | 这个字段包含正在被摄取的搜索短语。这是发送到 Twitter API 的短语。在现实中，系统很可能会同时监视多个搜索短语。在这个系统中，这个值是硬编码的。 |
| `tweet` | 这个字段包含在搜索 Twitter API 时返回的 tweets。`searchphrase` 和 `tweet` 之间是一对多的关系。 |
| `word` | 解析后，这个字段包含在 tweets 中找到的单词。`tweet` 和 `word` 之间是一对多的关系。 |
| `baseline` | 这个字段包含普通抽样文本中与单词相关的计数。`word` 和 `baseline` 之间是一对一的关系。 |

## TwitterSpout/TweetEmitter

现在，让我们来看看 spout/emitter。在这个例子中，我们将使用 Twitter4J API，`Emitter` 函数不过是该 API 和 Storm API 之间的薄胶层。如前所示，它只是使用 Twitter4J 调用 Twitter API，并将所有结果作为一个批次在 Storm 中发射。

在更复杂的情况下，一个可能还会接入 `Twitter Firehose` 并使用队列来缓冲实时更新，然后将其发射到 Storm 中。以下是 spout 的 `Emitter` 部分的关键行：

```scala
   query = new Query(SEARCH_PHRASE);
   query.setLang("en");
   result = twitter.search(query);
   ...
   for (Status status : result.getTweets()) {
       List<Object> tweets = new ArrayList<Object>();
       tweets.add(SEARCH_PHRASE);
       tweets.add(status.getText());
       collector.emit(tweets);
   }
```

## 函数

本节涵盖了拓扑中使用的函数。在这个例子中，所有的函数都可以有副作用（例如持久化），或者它们可以为元组添加字段和值。

### TweetSplitterFunction

tweet 经过的第一个函数是 `TweetSplitterFunction`。这个函数简单地解析 tweet，并为 tweet 中的每个单词发射一个元组。该函数的代码如下：

```scala
@Override
public void execute(TridentTuple tuple, TridentCollector collector) {
String tweet = (String) tuple.getValue(0);
LOG.debug("SPLITTING TWEET [" + tweet + "]");
Pattern p = Pattern.compile("[a-zA-Z]+");
Matcher m = p.matcher(tweet);
List<String> result = new ArrayList<String>();
   while (m.find()) {
       String word = m.group();
       if (word.length() > 0) {
         List<Object> newTuple = new ArrayList<Object>();
         newTuple.add(word);
         collector.emit(newTuple);
       }
   }
}
```

在一个更复杂的 NLP 系统中，这个函数将不仅仅是通过空格分割推文。NLP 系统很可能会尝试解析推文，为单词分配词性并将它们与彼此关联起来。尽管即时消息和推文通常缺乏解析器训练的传统语法结构，系统仍可能使用诸如单词之间距离之类的基本关联。在这种系统中，系统使用 n-gram 频率而不是单词频率，其中每个 n-gram 包括多个单词。

要了解 n-gram 的使用，请访问[`books.google.com/ngrams`](http://books.google.com/ngrams)。

### WordFrequencyFunction

现在我们转向`WordFrequencyFunction`。这个函数用`baseline`计数丰富了元组。这是单词在随机抽样文本中遇到的次数。

该函数的关键代码如下所示：

```scala
public static final long DEFAULT_BASELINE = 10000;
private Map<String, Long> wordLikelihoods = 
new HashMap<String, Long>();

public WordFrequencyFunction() throws IOException {
File file = new File("src/main/resources/en.txt");
BufferedReader br = new BufferedReader(new FileReader(file));
String line;
while ((line = br.readLine()) != null) {
String[] pair = line.split(" ");
   long baseline = Long.parseLong(pair[1]);
   LOG.debug("[" + pair[0] + "]=>[" + baseline + "]");
   wordLikelihoods.put(pair[0].toLowerCase(), baseline);
   i++;
}
br.close();
}

@Override
public void execute(TridentTuple tuple,
TridentCollector collector) {
String word = (String) tuple.getValue(2);
Long baseline = this.getLikelihood(word);
List<Object> newTuple = new ArrayList<Object>();
newTuple.add(baseline);
collector.emit(newTuple);
}

public long getLikelihood(String word){
Long baseline = this.wordLikelihoods.get(word);
if (baseline == null)
return DEFAULT_BASELINE;
else
   return baseline;
}
```

代码中的构造函数将单词计数加载到内存中。 `en.txt`的文件格式如下：

```scala
you 4621939
the 3957465
i 3476773
to 2873389
...
of 1531878
that 1323823
in 1295198
is 1242191
me 1208959
what 1071825
```

每行包含单词和该单词的频率计数。同样，由于我们只关心相对计数，因此无需考虑语料库中的总计数。但是，如果我们正在计算真实的可能性，我们还需要考虑总体单词计数。

函数的`execute`方法很简单，只是将基线计数添加到元组中。但是，如果我们检查从`HashMap`类中检索计数的方法，注意它包括一个`DEFAULT_BASELINE`。这是系统遇到原始语料库中没有的单词时使用的值。

由于 Twitter 动态包含许多缩写词、首字母缩写词和其他通常在标准文本中找不到的术语，`DEFAULT_BASELINE`成为一个重要的配置参数。在某些情况下，独特的单词很重要，因为它们涉及到`searchphrase`字段。其他单词是异常的，因为样本语料库与目标语料库不同。

理想情况下，原始基线计数应该来自分析的目标相同来源。在这种情况下，最好使用整个`Twitter Firehose`计算单词和 n-gram 计数。

### PersistenceFunction

我们不会在这里详细介绍完整的多数据中心 Cassandra 部署。相反，对于这个例子，我们将保持简单并使用本地文件存储。 `PersistenceFunction`的代码如下：

```scala
@Override
public void execute(TridentTuple tuple, 
   TridentCollector collector) {
writeToLog(tuple);
collector.emit(tuple);
}

synchronized public void writeToLog(TridentTuple tuple) {
DateTime dt = new DateTime();
DateTimeFormatter fmt = ISODateTimeFormat.dateTime();
StringBuffer sb = new StringBuffer("{ ");
sb.append(String.format("\"utcdt\":\"%s\",", fmt.print(dt)));
sb.append(String.format("\"searchphrase\":\"%s\",", tuple.getValue(0)));
sb.append(String.format("\"word\":\"%s\",", tuple.getValue(2)));
sb.append(String.format("\"baseline\":%s", tuple.getValue(3)));
sb.append("}");
BufferedWriter bw;
try {
bw = new BufferedWriter(new FileWriter("nlp.json", true));
bw.write(sb.toString());
   bw.newLine();
   bw.close();
} catch (IOException e) {
   throw new RuntimeException(e);
}
}
```

在上述代码中，该函数只是以 Druid 期望在 Hadoop 索引作业中使用的本机格式保存元组。这段代码效率低下，因为我们每次都要打开文件进行写入。或者，我们可以实现额外的`StateFactory`和`State`对象来持久化元组；然而，由于这只是一个例子，我们可以容忍低效的文件访问。

另外，请注意我们在这里生成了一个时间戳，但没有与元组一起重新发出。理想情况下，我们会生成一个时间戳并将其添加到元组中，然后由 Druid 在下游使用以对齐时间分区。在这个例子中，我们将接受这种差异。

### 提示

即使这个函数根本不丰富元组，它仍然必须重新发出元组。由于函数也可以充当过滤器，函数有义务声明哪些元组被传递到下游。

该函数将以下行写入`nlp.json`文件：

```scala
{ "utcdt":"2013-08-25T14:47:38.883-04:00","searchphrase":"apple jobs","word":"his","baseline":279134}
{ "utcdt":"2013-08-25T14:47:38.884-04:00","searchphrase":"apple jobs","word":"annual","baseline":839}
{ "utcdt":"2013-08-25T14:47:38.885-04:00","searchphrase":"apple jobs","word":"salary","baseline":1603}
{ "utcdt":"2013-08-25T14:47:38.886-04:00","searchphrase":"apple jobs","word":"from","baseline":285711}
{ "utcdt":"2013-08-25T14:47:38.886-04:00","searchphrase":"apple jobs","word":"Apple","baseline":10000}
```

# 检查分析

Druid 集成与上一章中使用的相同。简而言之，此集成包括`StateFactory`、`StateUpdater`和`State`实现。然后，`State`实现与`StormFirehoseFactory`实现和 Druid 的`StormFirehose`实现进行通信。在此实现的核心是`StormFirehose`实现，它将元组映射到 Druid 的输入行。此方法的清单如下所示：

```scala
@Override
public InputRow nextRow() {
   final Map<String, Object> theMap =
Maps.newTreeMap(String.CASE_INSENSITIVE_ORDER);
try {
TridentTuple tuple = null;
   tuple = BLOCKING_QUEUE.poll();
   if (tuple != null) {
String phrase = (String) tuple.getValue(0);
      String word = (String) tuple.getValue(2);
      Long baseline = (Long) tuple.getValue(3);
      theMap.put("searchphrase", phrase);
      theMap.put("word", word);
      theMap.put("baseline", baseline);
}

   if (BLOCKING_QUEUE.isEmpty()) {
      STATUS.putInLimbo(TRANSACTION_ID);
      LIMBO_TRANSACTIONS.add(TRANSACTION_ID);
      LOG.info("Batch is fully consumed by Druid. Unlocking [FINISH]");
      synchronized (FINISHED) {
          FINISHED.notify();
      }
   }
} catch (Exception e) {
LOG.error("Error occurred in nextRow.", e);
}
final LinkedList<String> dimensions = new LinkedList<String>();
dimensions.add("searchphrase");
dimensions.add("word");
return new MapBasedInputRow(System.currentTimeMillis(), 
dimensions, theMap); 
}
```

查看此方法时，有两个关键数据结构：`theMap`和`dimensions`。第一个包含行的数据值。第二个包含该行的维度，这是 Druid 用来执行聚合的，也决定了您可以针对数据运行哪些查询。在这种情况下，我们将使用`searchphrase`和`word`字段作为维度。这将允许我们在查询中执行计数和分组，我们马上就会看到。

首先，让我们看一下用于摄取数据的 Druid 配置。我们将主要使用与上一章中使用的嵌入式实时服务器相同的配置。段将被推送到 Cassandra 进行深度存储，而 MySQL 用于编写段元数据。

以下是`runtime.properties`中的关键配置参数：

```scala
druid.pusher.cassandra=true
druid.pusher.cassandra.host=localhost:9160 
druid.pusher.cassandra.keyspace=druid
druid.zk.service.host=localhost
druid.zk.paths.base=/druid
druid.host=127.0.0.1
druid.database.segmentTable=prod_segments
druid.database.user=druid
druid.database.password=druid
druid.database.connectURI=jdbc:mysql://localhost:3306/druid
druid.zk.paths.discoveryPath=/druid/discoveryPath
druid.realtime.specFile=./src/main/resources/realtime.spec
druid.port=7272
druid.request.logging.dir=/tmp/druid/realtime/log
```

此配置指向`realtime.spec`文件，该文件指定了实时服务器执行的分析的详细信息。以下是此用例的`realtime.spec`文件：

```scala
[{
    "schema": {
        "dataSource": "nlp",
        "aggregators": [
            { "type": "count", "name": "wordcount" },
            { "type": "max", "fieldName": "baseline", 
name" : "maxbaseline" }
        ],
        "indexGranularity": "minute",
        "shardSpec": {"type": "none"}
    },

    "config": {
        "maxRowsInMemory": 50000,
        "intermediatePersistPeriod": "PT30s"
    },

    "firehose": {
        "type": "storm",
        "sleepUsec": 100000,
        "maxGeneratedRows": 5000000,
        "seed": 0,
        "nTokens": 255,
        "nPerSleep": 3
    },

    "plumber": {
        "type": "realtime",
        "windowPeriod": "PT10s",
        "segmentGranularity": "minute",
        "basePersistDirectory": "/tmp/nlp/basePersist"
    }
}]
```

除了时间粒度，我们还在此文件中指定了聚合器。这告诉 Druid 如何在行之间聚合指标。没有聚合器，Druid 无法合并数据。在此用例中，有两个聚合器：`wordcount`和`maxbaseline`。

`wordcount`字段计算具有相同维度值的行的实例。回顾`StormFirehose`实现，两个维度是`searchphrase`和`word`。因此，Druid 可以合并行，添加一个名为`wordcount`的字段，其中将包含该单词在该`searchphrase`和时间片段中找到的实例总数。

`maxbaseline`字段包含该单词的基线。实际上，每行的值都是相同的。我们只是使用`max`作为一个方便的函数，将该值传播到我们在查询系统时可以使用的聚合中。

现在，让我们来看看查询。以下是我们用来检索最相关单词的查询：

```scala
{
     "queryType": "groupBy",
     "dataSource": "nlp",
     "granularity": "minute",
     "dimensions": ["searchphrase", "word"],
     "aggregations":[
        { "type": "longSum", "fieldName":"wordcount", 
"name": "totalcount"},
        { "type": "max", "fieldName":"maxbaseline", 
"name": "totalbaseline"}
     ],
     "postAggregations": [{
       "type": "arithmetic",
       "name": "relevance",
       "fn": "/",
       "fields": [
            { "type": "fieldAccess", "fieldName": "totalcount" },
            { "type": "fieldAccess", "fieldName": "totalbaseline" }
       ]
     }],
     "intervals":["2012-10-01T00:00/2020-01-01T00"]
 }
```

查询需要与`realtime.spec`文件对齐。在查询的底部，我们指定我们感兴趣的时间间隔。在文件的顶部，我们指定我们感兴趣的维度，然后是允许 Druid 将行折叠以匹配所请求的粒度的聚合。在此用例中，聚合与我们实时索引数据时执行的聚合完全匹配。

具体来说，我们引入了`totalcount`字段，其中包含`wordcount`的总和。因此，它将包含观察到的该`word`和`searchphrase`组合的实例总数。此外，我们使用`baseline`进行相同的技巧来传递该值。

最后，在此查询中，我们包括一个后聚合，它将聚合结果组合成相关分数。后聚合将观察到的推文总数除以基线频率。

以下是一个简单的 Ruby 文件，用于处理查询结果并返回前 20 个单词：

```scala
...
url="http://localhost:7272/druid/v2/?pretty=true"
response = RestClient.post url, File.read("realtime_query"), :accept => :json, :content_type => 'appplication/json'
#puts(response)
result = JSON.parse(response.to_s)

word_relevance = {}
result.each do |slice|
  event = slice['event']
  word_relevance[event['word']]=event['relevance']
end

count = 0
word_relevance.sort_by {|k,v| v}.reverse.each do |word, relevance|
  puts("#{word}->#{relevance}")
  count=count+1
  if(count == 20) then
    break
  end
end
```

请注意，我们用于访问服务器的 URL 是嵌入式实时服务器的端口。在生产中，查询会通过代理节点进行。

执行此脚本将产生以下代码片段：

```scala
claiming->31.789579158316634
apple->27.325982081323225
purchase->20.985449735449734
Jobs->20.618
Steve->17.446
shares->14.802238805970148
random->13.480033984706882
creation->12.7524115755627
Apple->12.688
acts->8.82582081246522
prevent->8.702687877125618
farmer->8.640522875816993
developed->8.62642740619902
jobs->8.524986566362172
bottles->8.30523560209424
technology->7.535137701804368
current->7.21418826739427
empire->6.924050632911392
```

### 提示

如果更改您正在捕获的维度或指标，请务必删除实时服务器用于缓存数据的本地目录。否则，实时服务器可能会重新读取旧数据，这些数据没有需要满足查询的维度和/或指标；此外，查询将失败，因为 Druid 无法找到必需的指标或维度。

# 批处理/历史分析

现在，让我们把注意力转向批处理机制。为此，我们将使用 Hadoop。虽然完整描述 Hadoop 远远超出了本节的范围，但我们将在 Druid 特定设置的同时对 Hadoop 进行简要概述。

Hadoop 提供了两个主要组件：分布式文件系统和分布式处理框架。分布式文件系统的名称是**Hadoop 分布式文件系统**（**HDFS**）。分布式处理框架称为 MapReduce。由于我们选择在假设的系统架构中利用 Cassandra 作为存储机制，我们将不需要 HDFS。但是，我们将使用 Hadoop 的 MapReduce 部分来将处理分布到所有历史数据中。

在我们的简单示例中，我们将运行一个读取我们`PersistenceFunction`中编写的本地文件的本地 Hadoop 作业。Druid 附带了一个我们将在本示例中使用的 Hadoop 作业。

# Hadoop

在我们开始加载数据之前，有必要简要介绍一下 MapReduce。尽管 Druid 预先打包了一个方便的 MapReduce 作业来适应历史数据，但一般来说，大型分布式系统将需要自定义作业来对整个数据集执行分析。

## MapReduce 概述

MapReduce 是一个将处理分为两个阶段的框架：map 阶段和 reduce 阶段。在 map 阶段，一个函数被应用于整个输入数据集，每次处理一个元素。每次应用`map`函数都会产生一组元组，每个元组包含一个键和一个值。具有相似键的元组然后通过`reduce`函数组合。`reduce`函数通常会发出另一组元组，通过组合与键相关联的值。

MapReduce 的经典“Hello World”示例是单词计数。给定一组包含单词的文档，计算每个单词的出现次数。（讽刺的是，这与我们的 NLP 示例非常相似。）

以下是 Ruby 函数，用于表达单词计数示例的`map`和`reduce`函数。`map`函数如下代码片段所示：

```scala
def map(doc)
   result = []
doc.split(' ').each do |word|
result << [word, 1]
   end
   return result
end
```

给定以下输入，`map`函数产生以下输出：

```scala
map("the quick fox jumped over the dog over and over again")
 => [["the", 1], ["quick", 1], ["fox", 1], ["jumped", 1], ["over", 1], ["the", 1], ["dog", 1], ["over", 1], ["and", 1], ["over", 1], ["again", 1]]
```

相应的`reduce`函数如下代码片段所示：

```scala
def reduce(key, values)
   sum = values.inject { |sum, x| sum + x }
   return [key, sum]
end
```

然后，MapReduce 函数将为每个键分组值，并将它们传递给前面的`reduce`函数，如下所示，从而得到总的单词计数：

```scala
reduce("over", [1,1,1])
 => ["over", 3]

```

## Druid 设置

有了 Hadoop 作为背景，让我们来看看我们为 Druid 设置的情况。为了让 Druid 从 Hadoop 作业中获取数据，我们需要启动**Master**和**Compute**节点（也称为**Historical**节点）。为此，我们将创建一个目录结构，该目录结构的根目录包含 Druid 自包含作业，子目录包含 Master 和 Compute 服务器的配置文件。

此目录结构如下代码片段所示：

```scala
druid/druid-indexing-hadoop-0.5.39-SNAPSHOT.jar
druid/druid-services-0.5.39-SNAPSHOT-selfcontained.jar
druid/config/compute/runtime.properties
druid/config/master/runtime.properties
druid/batchConfig.json
```

Master 和 Compute 节点的运行时属性与实时节点基本相同，但有一些显著的区别。它们都包括用于缓存段的设置，如下所示的代码片段：

```scala
# Path on local FS for storage of segments; 
# dir will be created if needed
druid.paths.indexCache=/tmp/druid/indexCache
# Path on local FS for storage of segment metadata; 
# dir will be created if needed
druid.paths.segmentInfoCache=/tmp/druid/segmentInfoCache
```

另外，请注意，如果您在同一台机器上运行 Master 和 Compute 服务器，您需要更改端口，以避免冲突，如下所示：

```scala
druid.port=8082
```

Druid 将所有服务器组件及其依赖项打包到一个单独的自包含 JAR 文件中。使用这个 JAR 文件，您可以使用以下命令启动 Master 和 Compute 服务器。

对于 Compute 节点，我们使用以下代码片段：

```scala
java -Xmx256m -Duser.timezone=UTC -Dfile.encoding=UTF-8 \
-classpath ./druid-services-0.5.39-SNAPSHOT-selfcontained.jar:config/compute \
com.metamx.druid.http.ComputeMain
```

对于 Master 节点，我们使用以下代码片段：

```scala
java -Xmx256m -Duser.timezone=UTC -Dfile.encoding=UTF-8 \
-classpath ./druid-services-0.5.39-SNAPSHOT-selfcontained.jar:config/compute \
com.metamx.druid.http.ComputeMain
```

一旦两个节点都运行起来，我们就可以使用 Hadoop 作业加载数据。

### HadoopDruidIndexer

在我们的服务器正常运行后，我们可以检查 Druid MapReduce 作业的内部。`HadoopDruidIndexer`函数使用一个类似`realtime.spec`文件的 JSON 配置文件。

文件在启动 Hadoop 作业时通过命令行指定，如下面的代码片段所示：

```scala
java -Xmx256m -Duser.timezone=UTC -Dfile.encoding=UTF-8 \
-Ddruid.realtime.specFile=realtime.spec -classpath druid-services-0.5.39-SNAPSHOT-selfcontained.jar:druid-indexing-hadoop-0.5.39-SNAPSHOT.jar \
com.metamx.druid.indexer.HadoopDruidIndexerMain batchConfig.json
```

以下是我们在这个例子中使用的`batchConfig.json`文件：

```scala
{
  "dataSource": "historical",
  "timestampColumn": "utcdt",
  "timestampFormat": "iso",
  "dataSpec": {
    "format": "json",
    "dimensions": ["searchphrase", "word"]
  },
  "granularitySpec": {
    "type":"uniform",
    "intervals":["2013-08-21T19/PT1H"],
    "gran":"hour"
  },
  "pathSpec": { "type": "static",
                "paths": "/tmp/nlp.json" },
  "rollupSpec": {
            "aggs": [ { "type": "count", "name": "wordcount" },
                         { "type": "max", "fieldName": "baseline", 
                                       "name" : "maxbaseline" } ],
      "rollupGranularity": "minute"},
      "workingPath": "/tmp/working_path",
  "segmentOutputPath": "/tmp/segments",
  "leaveIntermediate": "false",
  "partitionsSpec": {
    "targetPartitionSize": 5000000
  },
  "updaterJobSpec": {
    "type":"db",
    "connectURI":"jdbc:mysql://localhost:3306/druid",
    "user":"druid",
    "password":"druid",
    "segmentTable":"prod_segments"
  }
}
```

许多配置看起来很熟悉。特别感兴趣的两个字段是`pathSpec`和`rollupSpec`字段。`pathSpec`字段包含了由`PersistenceFunction`编写的文件的位置。`rollupSpec`字段包含了我们在事务处理期间在`realtime.spec`文件中包含的相同聚合函数。

另外，请注意指定了时间戳列和格式，这与我们在持久化文件中输出的字段相一致：

```scala
{ "utcdt":"2013-08-25T14:47:38.883-04:00","searchphrase":"apple jobs","word":"his","baseline":279134}
{ "utcdt":"2013-08-25T14:47:38.884-04:00","searchphrase":"apple jobs","word":"annual","baseline":839}
{ "utcdt":"2013-08-25T14:47:38.885-04:00","searchphrase":"apple jobs","word":"salary","baseline":1603}
{ "utcdt":"2013-08-25T14:47:38.886-04:00","searchphrase":"apple jobs","word":"from","baseline":285711}
{ "utcdt":"2013-08-25T14:47:38.886-04:00","searchphrase":"apple jobs","word":"Apple","baseline":10000}
```

`HadoopDruidIndexer`函数加载前述配置文件，并执行`map`/`reduce`函数来构建索引。如果我们更仔细地查看该作业，我们可以看到它正在运行的具体函数。

Hadoop 作业是使用 Hadoop 作业类启动的。Druid 运行了一些作业来索引数据，但我们将专注于`IndexGeneratorJob`。在`IndexGeneratorJob`中，Druid 使用以下行配置作业：

```scala
job.setInputFormatClass(TextInputFormat.class);
job.setMapperClass(IndexGeneratorMapper.class);
job.setMapOutputValueClass(Text.class);
...
job.setReducerClass(IndexGeneratorReducer.class);
job.setOutputKeyClass(BytesWritable.class);
job.setOutputValueClass(Text.class);
job.setOutputFormatClass(IndexGeneratorOutputFormat.class);
FileOutputFormat.setOutputPath(job,config.makeIntermediatePath());
config.addInputPaths(job);
config.intoConfiguration(job);
...
job.setJarByClass(IndexGeneratorJob.class);
job.submit();
```

几乎所有 Hadoop 作业都设置了上述属性。它们为处理的每个阶段设置了输入和输出类以及实现`Mapper`和`Reducer`接口的类。

有关 Hadoop 作业配置的完整描述，请访问以下网址：[`hadoop.apache.org/docs/r0.18.3/mapred_tutorial.html#Job+Configuration`](http://hadoop.apache.org/docs/r0.18.3/mapred_tutorial.html#Job+Configuration)

作业配置还指定了输入路径，指定了要处理的文件或其他数据源。在对`config.addInputPaths`的调用中，Druid 将`pathSpec`字段中的文件添加到 Hadoop 配置中进行处理，如下面的代码片段所示：

```scala
  @Override
  public Job addInputPaths(HadoopDruidIndexerConfig config, 
Job job) throws IOException {
    log.info("Adding paths[%s]", paths);
    FileInputFormat.addInputPaths(job, paths);
    return job;
  }
```

您可以看到，Druid 只支持`FileInputFormat`的实例。作为读者的练习，可以尝试增强`DruidHadoopIndexer`函数，以支持直接从 Cassandra 读取，就像在假设的架构中设想的那样。

回顾作业配置，Druid 使用的`Mapper`类是`IndexGeneratorMapper`类，而`Reducer`类是`IndexGeneratorReducer`类。

让我们首先看一下`IndexGeneratorMapper`类中的`map`函数。`IndexGeneratorMapper`类实际上是从`HadoopDruidIndexerMapper`继承的，其中包含了`map`方法的实现，将其委托给`IndexGeneratorMapper`类来发出实际的值，就像我们在下面的代码中看到的那样。

在`HadoopDruidIndexerMapper`中，我们看到`map`方法的实现如下：

```scala
@Override
protected void map(LongWritable key, Text value, Context context
  ) throws IOException, InterruptedException
  {
    try {
      final InputRow inputRow;
      try {
        inputRow = parser.parse(value.toString());
      }
      catch (IllegalArgumentException e) {
        if (config.isIgnoreInvalidRows()) {
          context.getCounter(HadoopDruidIndexerConfig.IndexJobCounters.INVALID_ROW_COUNTER).increment(1);
          return; // we're ignoring this invalid row
        } else {
          throw e;
        }
      }
      if(config.getGranularitySpec().bucketInterval(new DateTime(inputRow.getTimestampFromEpoch())).isPresent()) {
        innerMap(inputRow, value, context);
      }
    }
    catch (RuntimeException e) {
      throw new RE(e, "Failure on row[%s]", value);
    }
  }
```

我们可以看到超类`map`方法处理无法解析的行，将它们标记为无效，并检查行是否包含执行`map`所需的必要数据。具体来说，超类确保行包含时间戳。`map`需要时间戳，因为它将数据分区为时间片（即桶），就像我们在对`innerMap`的`abstract`方法调用中看到的那样，如下所示：

```scala
@Override
protected void innerMap(InputRow inputRow,
        Text text,
        Context context
    ) throws IOException, InterruptedException{

 // Group by bucket, sort by timestamp
final Optional<Bucket> bucket = getConfig().getBucket(inputRow);

if (!bucket.isPresent()) {
throw new ISE("WTF?! No bucket found for row: %s", inputRow);
}

context.write(new SortableBytes(
              bucket.get().toGroupKey(),
              Longs.toByteArray(inputRow.getTimestampFromEpoch())
          ).toBytesWritable(),text);
}
```

该方法中的关键行以及任何基于 Hadoop 的`map`函数中的关键行是对`context.write`的调用，它从`map`函数中发出元组。在这种情况下，`map`函数发出的是`SortableBytes`类型的键，它表示度量的桶和从输入源读取的实际文本作为值。

在此时，映射阶段完成后，我们已解析了文件，构建了我们的存储桶，并将数据分区到这些存储桶中，按时间戳排序。然后，通过调用`reduce`方法处理每个存储桶，如下所示：

```scala
@Override
protected void reduce(BytesWritable key, Iterable<Text> values,
final Context context
    ) throws IOException, InterruptedException{
SortableBytes keyBytes = SortableBytes.fromBytesWritable(key);
Bucket bucket = Bucket.fromGroupKey(keyBytes.getGroupKey()).lhs;

final Interval interval =
config.getGranularitySpec().bucketInterval(bucket.time).get();
final DataRollupSpec rollupSpec = config.getRollupSpec();
final AggregatorFactory[] aggs = rollupSpec.getAggs().toArray(
          new AggregatorFactory[rollupSpec.getAggs().size()]);

IncrementalIndex index = makeIncrementalIndex(bucket, aggs);
...
for (final Text value : values) {
context.progress();
   final InputRow inputRow =
index.getSpatialDimensionRowFormatter()
.formatRow(parser.parse(value.toString()));
        allDimensionNames.addAll(inputRow.getDimensions());
      ...
IndexMerger.persist(index, interval, file, 
index = makeIncrementalIndex(bucket, aggs);
      ...
   }
   ...
);
...
serializeOutIndex(context, bucket, mergedBase,
 Lists.newArrayList(allDimensionNames));
...
}
```

正如您所看到的，`reduce`方法包含了分析的核心内容。它根据汇总规范中的聚合和批处理配置文件中指定的维度构建索引。该方法的最后几行将段写入磁盘。

最后，当您运行`DruidHadoopIndexer`类时，您将看到类似以下代码片段的内容：

```scala
2013-08-28 04:07:46,405 INFO [main] org.apache.hadoop.mapred.JobClient -   Map-Reduce Framework
2013-08-28 04:07:46,405 INFO [main] org.apache.hadoop.mapred.JobClient -     Reduce input groups=1
2013-08-28 04:07:46,405 INFO [main] org.apache.hadoop.mapred.JobClient -     Combine output records=0
2013-08-28 04:07:46,405 INFO [main] org.apache.hadoop.mapred.JobClient -     Map input records=201363
2013-08-28 04:07:46,405 INFO [main] org.apache.hadoop.mapred.JobClient -     Reduce shuffle bytes=0
2013-08-28 04:07:46,406 INFO [main] org.apache.hadoop.mapred.JobClient -     Reduce output records=0
2013-08-28 04:07:46,406 INFO [main] org.apache.hadoop.mapred.JobClient -     Spilled Records=402726
2013-08-28 04:07:46,406 INFO [main] org.apache.hadoop.mapred.JobClient -     Map output bytes=27064165
2013-08-28 04:07:46,406 INFO [main] org.apache.hadoop.mapred.JobClient -     Combine input records=0
2013-08-28 04:07:46,406 INFO [main] org.apache.hadoop.mapred.JobClient -     Map output records=201363
2013-08-28 04:07:46,406 INFO [main] org.apache.hadoop.mapred.JobClient -     Reduce input records=201363
2013-08-28 04:07:46,433 INFO [main] com.metamx.druid.indexer.IndexGeneratorJob - Adding segment historical_2013-08-28T04:00:00.000Z_2013-08-28T05:00:00.000Z_2013-08-28T04:07:32.243Z to the list of published segments
2013-08-28 04:07:46,708 INFO [main] com.metamx.druid.indexer.DbUpdaterJob - Published historical_2013-08-28T04:00:00.000Z_2013-08-28T05:00:00.000Z_2013-08-28T04:07:32.243Z
2013-08-28 04:07:46,754 INFO [main] com.metamx.druid.indexer.IndexGeneratorJob - Adding segment historical_2013-08-28T04:00:00.000Z_2013-08-28T05:00:00.000Z_2013-08-28T04:07:32.243Z to the list of published segments
2013-08-28 04:07:46,755 INFO [main] com.metamx.druid.indexer.HadoopDruidIndexerJob - Deleting path[/tmp/working_path/historical/2013-08-28T040732.243Z]
```

请注意，添加的段名为`historical`。要查询由`historical` /批处理机制加载的数据，请更新查询以指定历史数据源，并使用计算节点的端口。如果一切加载正确，您将收到我们最初在实时服务器上看到的聚合结果；示例如下：

```scala
{
  "version" : "v1",
  "timestamp" : "2013-08-28T04:06:00.000Z",
  "event" : {
    "totalcount" : 171,
    "totalbaseline" : 28719.0,
    "searchphrase" : "apple jobs",
    "relevance" : 0.005954246317768724,
    "word" : "working"
  }
}
```

现在，如果我们定期安排 Hadoop 作业运行，历史索引将滞后于实时索引，但将持续更新索引，纠正错误并解决任何系统故障。

# 总结

在本章中，我们看到将批处理机制与 Storm 等实时处理引擎配对，提供了更完整和强大的整体解决方案。

我们研究了实施 Lambda 架构的方法。这种方法提供了由批处理系统支持的实时分析，可以对分析进行追溯性修正。此外，我们还看到了如何配置多数据中心系统架构，以将离线处理与事务系统隔离开来，并通过分布式存储提供持续可用性和容错性。

本章还介绍了 Hadoop，并以 Druid 的实现为例。

在下一章中，我们将采用现有的利用 Pig 和 Hadoop 的批处理过程，并演示将其转换为实时系统所需的步骤。同时，我们还将演示如何使用 Storm-YARN 将 Storm 部署到 Hadoop 基础架构上。


# 第九章：在 Hadoop 上部署风暴进行广告分析

在前两章中，我们看到了如何将 Storm 与实时分析系统集成。然后我们扩展了该实现，支持批处理的实时系统。在本章中，我们将探讨相反的情况。

我们将研究一个批处理系统，计算广告活动的有效性。我们将把建立在 Hadoop 上的系统转换成实时处理系统。

为此，我们将利用雅虎的 Storm-YARN 项目。Storm-YARN 项目允许用户利用 YARN 来部署和运行 Storm 集群。在 Hadoop 上运行 Storm 允许企业 consoli 操作并利用相同的基础设施进行实时和批处理。

本章涵盖以下主题：

+   Pig 简介

+   YARN（Hadoop v2 的资源管理）

+   使用 Storm-YARN 部署 Storm

# 审查用例

在我们的用例中，我们将处理广告活动的日志，以确定最有效的广告活动。批处理机制将使用 Pig 脚本处理单个大型平面文件。Pig 是一种高级语言，允许用户执行数据转换和分析。Pig 类似于 SQL，并编译成通常部署和运行在 Hadoop 基础设施上的 map/reduce 作业。

在本章中，我们将把 Pig 脚本转换成拓扑，并使用 Storm-YARN 部署该拓扑。这使我们能够从批处理方法过渡到能够摄取和响应实时事件的方法（例如，点击横幅广告）。

在广告中，印象是代表广告显示在用户面前的广告事件，无论是否被点击。对于我们的分析，我们将跟踪每个印象，并使用一个字段来指示用户是否点击了广告。

每一行的平面文件包含四个字段，描述如下：

| 字段 | 描述 |
| --- | --- |
| cookie | 这是来自浏览器的唯一标识符。我们将使用它来表示系统中的用户。 |
| campaign | 这是代表特定广告内容集的唯一标识符。 |
| 产品 | 这是正在广告的产品的名称。 |
| 点击 | 这是布尔字段，表示用户是否点击了广告：如果用户点击了广告，则为 true；否则为 false。 |

通常，广告商会为产品运行广告活动。一个广告活动可能有一组特定的内容与之相关联。我们想计算每个产品的最有效广告活动。

在这种情况下，我们将通过计算不同点击次数占总体印象的百分比来计算广告活动的有效性。我们将以以下格式提供报告：

| 产品 | 广告活动 | 不同点击次数 | 印象 |
| --- | --- | --- | --- |
| X | Y | 107 | 252 |

印象的数量只是产品和广告活动的印象总数。我们不区分印象，因为我们可能多次向同一用户展示相同的广告以获得单次点击。由于我们很可能按印象付费，我们希望使用印象的总数来计算驱动兴趣所需的成本。兴趣表示为点击。

# 建立架构

我们在上一章中提到了 Hadoop，但主要关注了 Hadoop 中的 map/reduce 机制。在本章中，我们将做相反的事情，关注**Hadoop 文件系统**（**HDFS**）和**Yet Another Resource Negotiator**（**YARN**）。我们将利用 HDFS 来分阶段数据，并利用 YARN 来部署将托管拓扑的 Storm 框架。

Hadoop 内的最新组件化允许任何分布式系统使用它进行资源管理。在 Hadoop 1.0 中，资源管理嵌入到 MapReduce 框架中，如下图所示：

![建立架构](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/storm-bp/img/8294OS_09_01.jpg)

Hadoop 2.0 将资源管理分离为 YARN，允许其他分布式处理框架在 Hadoop 伞下管理的资源上运行。在我们的情况下，这允许我们在 YARN 上运行 Storm，如下图所示：

![建立架构](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/storm-bp/img/8294OS_09_02.jpg)

如前图所示，Storm 实现了与 MapReduce 相同的功能。它提供了分布式计算的框架。在这个特定的用例中，我们使用 Pig 脚本来表达我们想要对数据执行的 ETL/分析。我们将将该脚本转换为执行相同功能的 Storm 拓扑，然后我们将检查执行该转换涉及的一些复杂性。

为了更好地理解这一点，值得检查 Hadoop 集群中的节点以及在这些节点上运行的进程的目的。假设我们有一个如下图所示的集群：

![建立架构](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/storm-bp/img/8294OS_09_03.jpg)

图中显示了两个不同的组件/子系统。第一个是 YARN，这是 Hadoop 2.0 引入的新资源管理层。第二个是 HDFS。让我们首先深入研究 HDFS，因为自 Hadoop 1.0 以来它并没有发生太大变化。

## 检查 HDFS

HDFS 是一个分布式文件系统。它在一组从节点上分发数据块。NameNode 是目录。它维护目录结构和指示哪些节点具有什么信息的元数据。NameNode 本身不存储任何数据，它只协调分布式文件系统上的 **创建、读取、更新和删除**（CRUD）操作。存储发生在运行 DataNode 进程的每个从节点上。DataNode 进程是系统中的工作马。它们彼此通信以重新平衡、复制、移动和复制数据。它们对客户端的 CRUD 操作做出反应和响应。

## 检查 YARN

YARN 是资源管理系统。它监视每个节点的负载，并协调将新作业分配给集群中的从节点。 **ResourceManager** 收集来自 **NodeManagers** 的状态信息。ResourceManager 还为客户端的作业提交提供服务。

YARN 中的另一个抽象概念是 **ApplicationMaster**。ApplicationMaster 管理特定应用程序的资源和容器分配。ApplicationMaster 与 ResourceManager 协商分配资源。一旦分配了资源，ApplicationMaster 就会与 NodeManagers 协调实例化 **容器**。容器是实际执行工作的进程的逻辑持有者。

ApplicationMaster 是一个特定于处理框架的库。Storm-YARN 提供了在 YARN 上运行 Storm 进程的 ApplicationMaster。HDFS 分发 ApplicationMaster 以及 Storm 框架本身。目前，Storm-YARN 需要外部 ZooKeeper。当应用程序部署时，Nimbus 启动并连接到 ZooKeeper。

以下图表描述了通过 Storm-YARN 在 Hadoop 基础设施上运行 Storm：

![检查 YARN](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/storm-bp/img/8294OS_09_04.jpg)

如前图所示，YARN 用于部署 Storm 应用程序框架。在启动时，Storm Application Master 在 YARN 容器内启动。然后，它创建了一个 Storm Nimbus 和 Storm UI 的实例。

之后，Storm-YARN 在单独的 YARN 容器中启动监督员。这些监督员进程中的每一个都可以在其容器内生成工作人员。

应用程序主节点和 Storm 框架都是通过 HDFS 分发的。Storm-YARN 提供了命令行实用程序来启动 Storm 集群，启动监督者，并配置 Storm 以进行拓扑部署。我们将在本章后面看到这些设施。

为了完成建筑图，我们需要分层处理批处理和实时处理机制：分别是 Pig 和 Storm 拓扑。我们还需要描述实际数据。

通常会使用诸如 Kafka 之类的排队机制来为 Storm 集群排队工作。为了简化，我们将使用存储在 HDFS 中的数据。以下描述了我们在使用案例中使用 Pig、Storm、YARN 和 HDFS，为了清晰起见省略了基础设施的元素。为了充分实现从 Pig 转换到 Storm 的价值，我们将转换拓扑以从 Kafka 而不是 HDFS 中获取数据，如下图所示：

![检查 YARN](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/storm-bp/img/8294OS_09_05.jpg)

如前图所示，我们的数据将存储在 HDFS 中。虚线表示用于分析的批处理过程，实线表示实时系统。在每个系统中，以下步骤都会发生：

| 步骤 | 目的 | Pig 等效 | Storm-Yarn 等效 |
| --- | --- | --- | --- |
| 1 | 处理框架已部署 | MapReduce 应用程序主节点已部署并启动 | Storm-YARN 启动应用程序主节点并分发 Storm 框架 |
| 2 | 特定的分析已启动 | Pig 脚本被编译为 MapReduce 作业并提交为一个作业 | 拓扑被部署到集群 |
| 3 | 资源已保留 | 在 YARN 容器中创建 Map 和 reduce 任务 | 监督者与工作人员一起实例化 |
| 4 | 分析从存储中读取数据并执行分析 | Pig 从 HDFS 中读取数据 | Storm 通常从 Kafka 中读取工作，但在这种情况下，拓扑从一个平面文件中读取它 |

Pig 和 Trident 之间也可以进行类比。Pig 脚本编译成 MapReduce 作业，而 Trident 拓扑编译成 Storm 拓扑。

有关 Storm-YARN 项目的更多信息，请访问以下网址：

[`github.com/yahoo/storm-yarn`](https://github.com/yahoo/storm-yarn)

# 配置基础设施

首先，我们需要配置基础设施。由于 Storm 将在 YARN 基础设施上运行，我们将首先配置 YARN，然后展示如何配置 Storm-YARN 以部署在该集群上。

## Hadoop 基础设施

要配置一组机器，您需要在它们中的每一台上都有一个 Hadoop 的副本或者可以访问到的副本。首先，下载最新的 Hadoop 副本并解压缩存档。在本例中，我们将使用版本 2.1.0-beta。

假设您已将存档解压缩到`/home/user/hadoop`，在集群中的每个节点上添加以下环境变量：

```scala
export HADOOP_PREFIX=/home/user/hadoop
export HADOOP_YARN_HOME=/home/user/hadoop
export HADOOP_CONF_DIR=/home/user/hadoop/etc/Hadoop
```

将 YARN 添加到执行路径中，如下所示：

```scala
export PATH=$PATH:$HADOOP_YARN_HOME/bin
```

所有 Hadoop 配置文件都位于`$HADOOP_CONF_DIR`中。本例中的三个关键配置文件是：`core-site.xml`、`yarn-site.xml`和`hdfs-site.xml`。

在本例中，我们假设有一个名为`master`的主节点和四个名为`slave01-04`的从节点。

通过执行以下命令行来测试 YARN 配置：

```scala
$ yarn version
You should see output similar to the following:
Hadoop 2.1.0-beta
Subversion https://svn.apache.org/repos/asf/hadoop/common -r 1514472
Compiled by hortonmu on 2013-08-15T20:48Z
Compiled with protoc 2.5.0
From source with checksum 8d753df8229fd48437b976c5c77e80a
This command was run using /Users/bone/tools/hadoop-2.1.0-beta/share/hadoop/common/hadoop-common-2.1.0-beta.jar

```

## 配置 HDFS

根据架构图，要配置 HDFS，您需要启动 NameNode，然后连接一个或多个 DataNode。

### 配置 NameNode

要启动 NameNode，您需要指定主机和端口。通过使用以下元素在`core-site.xml`文件中配置主机和端口：

```scala
<configuration>
    <property>
        <name>fs.default.name</name>
        <value>hdfs://master:8020</value>
    </property>
</configuration>
```

另外，配置 NameNode 存储其元数据的位置。此配置存储在`hdfs-site.xml`文件中的`dfs.name.dir`变量中。

为了使示例简单，我们还将在分布式文件系统上禁用安全性。为此，我们将`dfs.permissions`设置为`False`。在进行这些编辑之后，HDFS 配置文件看起来像以下代码片段：

```scala
<configuration>
   <property>
       <name>dfs.name.dir</name>
       <value>/home/user/hadoop/name/data</value>
   </property>
   <property>
       <name>dfs.permissions</name>
       <value>false</value>
   </property>
</configuration>
```

在启动 NameNode 之前的最后一步是格式化分布式文件系统。使用以下命令进行此操作：

```scala
hdfs namenode -format <cluster_name>

```

最后，我们准备启动 NameNode。使用以下命令：

```scala
$HADOOP_PREFIX/sbin/hadoop-daemon.sh --config $HADOOP_CONF_DIR --script hdfs start namenode

```

启动的最后一行将指示日志的位置：

```scala
starting namenode, logging to /home/user/hadoop/logs/hadoop-master.hmsonline.com.out

```

### 提示

尽管消息如此，但日志实际上将位于另一个具有相同名称但后缀为`log`而不是`out`的文件中。

还要确保您在配置中声明的名称目录存在；否则，您将在日志文件中收到以下错误：

```scala
org.apache.hadoop.hdfs.server.common.InconsistentFSStateException: Directory /home/user/hadoop-2.1.0-beta/name/data is in an inconsistent state: storage directory does not exist or is not accessible.
```

使用以下代码片段验证 NameNode 是否已启动：

```scala
boneill@master:~-> jps
30080 NameNode
```

此外，您应该能够在 Web 浏览器中导航到 UI。默认情况下，服务器在端口 50070 上启动。在浏览器中导航到`http://master:50070`。您应该看到以下截图：

![配置 NameNode](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/storm-bp/img/8294OS_09_06.jpg)

点击**Live Nodes**链接将显示可用的节点以及每个节点的空间分配，如下截图所示：

![配置 NameNode](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/storm-bp/img/8294OS_09_07.jpg)

最后，从主页，您还可以通过点击**浏览文件系统**来浏览文件系统。

### 配置 DataNode

一般来说，最容易在集群中的节点之间共享核心配置文件。数据节点将使用`core-site.xml`文件中定义的主机和端口来定位 NameNode 并连接到它。

此外，每个 DataNode 需要配置本地存储的位置。这在`hdfs-site.xml`文件中的以下元素中定义：

```scala
<configuration>
   <property>
       <name>dfs.datanode.data.dir</name>
       <value>/vol/local/storage/</value>
   </property>
</configuration>
```

如果这个位置在从节点上是一致的，那么这个配置文件也可以共享。设置好后，您可以使用以下命令启动 DataNode：

```scala
$HADOOP_PREFIX/sbin/hadoop-daemon.sh --config $HADOOP_CONF_DIR --script hdfs start datanode

```

再次使用`jps`验证 DataNode 是否正在运行，并监视任何错误日志。在几分钟内，DataNode 应该会出现在 NameNode 的**Live Nodes**屏幕上，就像之前显示的那样。

### 配置 YARN

HDFS 已经运行起来了，现在是时候把注意力转向 YARN 了。与我们在 HDFS 中所做的类似，我们将首先运行 ResourceManager，然后通过运行 NodeManager 来连接从节点。

#### 配置 ResourceManager

ResourceManager 有各种子组件，每个子组件都充当需要在其上运行的主机和端口的服务器。所有服务器都在`yarn-site.xml`文件中配置。

对于这个例子，我们将使用以下 YARN 配置：

```scala
<configuration>
   <property>
       <name>yarn.resourcemanager.address</name>
       <value>master:8022</value>
   </property>
   <property>
       <name>yarn.resourcemanager.admin.address</name>
       <value>master:8033</value>
   </property>
   <property>
       <name>yarn.resourcemanager.resource-tracker.address</name>
        <value>master:8025</value>
   </property>
   <property>
       <name>yarn.resourcemanager.scheduler.address</name>
       <value>master:8030</value>
   </property>
   <property>
       <name>yarn.acl.enable</name>
       <value>false</value>
   </property>
   <property>
       <name>yarn.nodemanager.local-dirs</name>
       <value>/home/user/hadoop_work/mapred/nodemanager</value>
       <final>true</final>
   </property>
   <property>
     <name>yarn.nodemanager.aux-services</name>
     <value>mapreduce.shuffle</value>
   </property>
</configuration>
```

在前面的配置文件中，前四个变量分配了子组件的主机和端口。将`yarn.acl.enable`变量设置为`False`会禁用 YARN 集群上的安全性。`yarn.nodemanager.local-dirs`变量指定了 YARN 将数据放置在本地文件系统的位置。

最后，`yarn.nodemanager.aux-services`变量在 NodeManager 的运行时内启动一个辅助服务，以支持 MapReduce 作业。由于我们的 Pig 脚本编译成 MapReduce 作业，它们依赖于这个变量。

像 NameNode 一样，使用以下命令启动 ResourceManager：

```scala
$HADOOP_YARN_HOME/sbin/yarn-daemon.sh --config $HADOOP_CONF_DIR start resourcemanager

```

再次使用`jps`检查进程是否存在，监视异常日志，然后您应该能够导航到默认运行在端口 8088 上的 UI。

UI 显示在以下截图中：

![配置 ResourceManager](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/storm-bp/img/8294OS_09_08.jpg)

### 配置 NodeManager

NodeManager 使用相同的配置文件（`yarn-site.xml`）来定位相应的服务器。因此，在集群中的节点之间可以安全地复制或共享该文件。

使用以下命令启动 NodeManager：

```scala
$HADOOP_YARN_HOME/sbin/yarn-daemon.sh --config $HADOOP_CONF_DIR start nodemanager

```

在所有 NodeManagers 向 ResourceManager 注册之后，您将能够在 ResourceManager UI 中点击**Nodes**后看到它们，如下截图所示：

![配置 NodeManager](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/storm-bp/img/8294OS_09_09.jpg)

# 部署分析

有了 Hadoop，我们现在可以专注于我们将用于分析的分布式处理框架。

## 使用 Pig 基础设施执行批量分析

我们将要检查的第一个分布式处理框架是 Pig。Pig 是一个用于数据分析的框架。它允许用户用简单的高级语言表达分析。然后这些脚本编译成 MapReduce 作业。

尽管 Pig 可以从几个不同的系统（例如 S3）中读取数据，但在本例中，我们将使用 HDFS 作为我们的数据存储机制。因此，我们分析的第一步是将数据复制到 HDFS 中。

为此，我们发出以下 Hadoop 命令：

```scala
hadoop fs -mkdir /user/bone/temp
hadoop fs -copyFromLocal click_thru_data.txt /user/bone/temp/

```

上述命令创建了一个数据文件目录，并将点击数据文件复制到该目录中。

要执行 Pig 脚本对该数据，我们需要安装 Pig。为此，我们只需下载 Pig 并在配置了 Hadoop 的机器上展开存档。在这个例子中，我们将使用版本 0.11.1。

就像我们在 Hadoop 中所做的那样，我们将向我们的环境添加以下环境变量：

```scala
export PIG_CLASSPATH=/home/user/hadoop/etc/hadoop
export PIG_HOME=/home/user/pig
export PATH=PATH:$HOME/bin:$PIG_HOME/bin:$HADOOP_YARN_HOME/bin
```

`PIG_CLASSPATH`变量告诉 Pig 在哪里找到 Hadoop。

在您的环境中有了这些变量之后，您应该能够使用以下命令测试您的 Pig 安装：

```scala
boneill@master:~-> pig
2013-10-07 23:35:41,179 [main] INFO  org.apache.pig.Main - Apache Pig version 0.11.1 (r1459641) compiled Mar 22 2013, 02:13:53
...
2013-10-07 23:35:42,639 [main] INFO  org.apache.pig.backend.hadoop.executionengine.HExecutionEngine - Connecting to hadoop file system at: hdfs://master:8020
grunt>

```

默认情况下，Pig 将读取 Hadoop 配置并连接到分布式文件系统。您可以在先前的输出中看到。它连接到我们的分布式文件系统`hdfs://master:8020`。

通过 Pig，您可以与 HDFS 进行交互，方式与常规文件系统相同。例如，`ls`和`cat`都可以像以下代码片段中所示那样工作：

```scala
grunt> ls /user/bone/temp/
hdfs://master:8020/user/bone/temp/click_thru_data.txt<r 3>	157

grunt> cat /user/bone/temp/click_thru_data.txt
boneill campaign7 productX true
lisalis campaign10 productX false
boneill campaign6 productX true
owen campaign6 productX false
collin campaign7 productY true
maya campaign8 productY true
boneill campaign7 productX true
owen campaign6 productX true
olive campaign6 productX false
maryanne campaign7 productY true
dennis campaign7 productY true
patrick campaign7 productX false
charity campaign10 productY false
drago campaign7 productY false
```

## 使用 Storm-YARN 基础设施执行实时分析

现在我们已经为批处理工作建立了基础设施，让我们利用完全相同的基础设施进行实时处理。Storm-YARN 使得重用 Hadoop 基础设施进行 Storm 变得容易。

由于 Storm-YARN 是一个新项目，最好是根据源代码构建并使用`README`文件中的说明创建分发，该文件位于以下 URL：

[`github.com/yahoo/storm-yarn`](https://github.com/yahoo/storm-yarn)

构建分发后，您需要将 Storm 框架复制到 HDFS。这允许 Storm-YARN 将框架部署到集群中的每个节点。默认情况下，Storm-YARN 将在 HDFS 上启动用户目录中的 Storm 库作为 ZIP 文件。Storm-YARN 在其分发的`lib`目录中提供了一个兼容的 Storm 的副本。

假设您在 Storm-YARN 目录中，您可以使用以下命令将 ZIP 文件复制到正确的 HDFS 目录中：

```scala
hadoop fs -mkdir /user/bone/lib/
hadoop fs -copyFromLocal ./lib/storm-0.9.0-wip21.zip /user/bone/lib/

```

然后，您可以通过 Hadoop 管理界面浏览文件系统来验证 Storm 框架是否在 HDFS 中。您应该看到以下截图：

![使用 Storm-YARN 基础设施执行实时分析](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/storm-bp/img/8294OS_09_10.jpg)

在 HDFS 上暂存了 Storm 框架后，下一步是为 Storm-YARN 配置本地 YAML 文件。与 Storm-YAML 一起使用的 YAML 文件是 Storm-YAML 和 Storm 的配置。YAML 文件中的 Storm 特定参数将传递给 Storm。

以下代码片段显示了 YAML 文件的示例：

```scala
master.host: "master"
master.thrift.port: 9000
master.initial-num-supervisors: 2
master.container.priority: 0
master.container.size-mb: 5120
master.heartbeat.interval.millis: 1000
master.timeout.secs: 1000
yarn.report.wait.millis: 10000
nimbusui.startup.ms: 10000

ui.port: 7070

storm.messaging.transport: "backtype.storm.messaging.netty.Context"
storm.messaging.netty.buffer_size: 1048576
storm.messaging.netty.max_retries: 100
storm.messaging.netty.min_wait_ms: 1000
storm.messaging.netty.max_wait_ms: 5000

storm.zookeeper.servers:
     - "zkhost"
```

许多参数都是自描述的。但特别注意最后一个变量。这是 ZooKeeper 主机的位置。尽管现在可能并非总是如此，但目前 Storm-YARN 假设您有一个预先存在的 ZooKeeper。

### 提示

要监视 Storm-YARN 是否仍然需要预先存在的 ZooKeeper 实例，请查看以下链接中提供的信息：

[`github.com/yahoo/storm-yarn/issues/22`](https://github.com/yahoo/storm-yarn/issues/22)

使用 HDFS 中的 Storm 框架和配置的 YAML 文件，启动 YARN 上的 Storm 的命令行如下：

```scala
storm-yarn launch ../your.yaml --queue default -appname storm-yarn-2.1.0-deta-demo --stormZip lib/storm-0.9.0-wip21.zip

```

您指定 YAML 文件的位置，YARN 队列，应用程序的名称以及 ZIP 文件的位置，相对于用户目录，除非指定了完整路径。

### 提示

YARN 中的队列超出了本讨论的范围，但默认情况下，YARN 配置了一个默认队列，该队列在上述命令行中使用。如果您在现有集群上运行 Storm，请检查 YARN 配置中的`capacity-scheduler.xml`以查找潜在的队列名称。

执行上述命令行后，您应该会在 YARN 管理屏幕上看到应用程序部署，如下截图所示：

![使用 Storm-YARN 基础设施进行实时分析](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/storm-bp/img/8294OS_09_11.jpg)

单击应用程序显示应用程序主管部署的位置。检查 Application Master 的节点值。这就是您将找到 Storm UI 的地方，如下截图所示：

![使用 Storm-YARN 基础设施进行实时分析](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/storm-bp/img/8294OS_09_12.jpg)

再深入一级，您将能够看到 Storm 的日志文件，如下截图所示：

![使用 Storm-YARN 基础设施进行实时分析](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/storm-bp/img/8294OS_09_13.jpg)

幸运的话，日志将显示 Nimbus 和 UI 成功启动。检查标准输出流，您将看到 Storm-YARN 启动监督者：

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

上述输出中的关键行已经突出显示。如果导航到这些 URL，您将看到各自实例的监督者日志。回顾我们用于启动 Storm-YARN 的 YAML 文件，注意我们指定了以下内容：

```scala
 master.initial-num-supervisors: 2

```

使用托管 ApplicationMaster 的节点导航到 UI，然后导航到用于启动的 YAML 文件中指定的 UI 端口（`ui.port: 7070`）。

在浏览器中打开`http://node:7070/`，其中 node 是 Application Master 的主机。您应该会看到熟悉的 Storm UI，如下截图所示：

![使用 Storm-YARN 基础设施进行实时分析](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/storm-bp/img/8294OS_09_14.jpg)

基础设施现在已经准备就绪。要在 YARN 上终止 Storm 部署，可以使用以下命令：

```scala
./storm-yarn shutdown -appId application_1381197763696_0002

```

在上述语句中，`appId`参数对应于分配给 Storm-YARN 的`appId`参数，并且在 Hadoop 管理屏幕上可见。

### 提示

Storm-YARN 将使用本地 Hadoop 配置来定位主 Hadoop 节点。如果您是从不属于 Hadoop 集群的机器启动的，您将需要使用 Hadoop 环境变量和配置文件配置该机器。具体来说，它通过 ResourceManager 启动。因此，您需要在`yarn-site.xml`中配置以下变量：

`yarn.resourcemanager.address`

# 执行分析

有了批处理和实时基础设施，我们可以专注于分析。首先，我们将看一下 Pig 中的处理，然后将 Pig 脚本转换为 Storm 拓扑。

## 执行批量分析

对于批量分析，我们使用 Pig。Pig 脚本通过计算点击次数和总曝光次数之间的不同客户数量的比率来计算活动的有效性。

Pig 脚本如下所示：

```scala
click_thru_data = LOAD '../click_thru_data.txt' using PigStorage(' ')
  AS (cookie_id:chararray,
      campaign_id:chararray,
      product_id:chararray,
      click:chararray);

click_thrus = FILTER click_thru_data BY click == 'true';
distinct_click_thrus = DISTINCT click_thrus;
distinct_click_thrus_by_campaign = GROUP distinct_click_thrus BY campaign_id;
count_of_click_thrus_by_campaign = FOREACH distinct_click_thrus_by_campaign GENERATE group, COUNT($1);
-- dump count_of_click_thrus_by_campaign;

impressions_by_campaign = GROUP click_thru_data BY campaign_id;
count_of_impressions_by_campaign = FOREACH impressions_by_campaign GENERATE group, COUNT($1);
-- dump count_of_impressions_by_campaign;

joined_data = JOIN count_of_impressions_by_campaign BY $0 LEFT OUTER, count_of_click_thrus_by_campaign BY $0 USING 'replicated';
-- dump joined_data;

result = FOREACH joined_data GENERATE $0 as campaign, ($3 is null ? 0 : $3) as clicks, $1 as impressions, (double)$3/(double)$1 as effectiveness:double;
dump result;
```

让我们更仔细地看一下上述代码。

第一个`LOAD`语句指定了数据的位置和用于加载数据的模式。通常，Pig 加载非规范化数据。数据的位置是一个 URL。在本地模式下操作时，如前所示，这是一个相对路径。在 MapReduce 模式下运行时，URL 很可能是 HDFS 中的位置。在针对**亚马逊网络服务**（**AWS**）运行 Pig 脚本时，这很可能是一个 S3 URL。

在`Load`语句之后的后续行中，脚本计算了所有不同的点击次数。在第一行中，它过滤了仅在该列中为`True`的行的数据集，这表示印象导致了点击次数。过滤后，行被过滤为仅包含不同条目。然后，按广告系列对行进行分组，并计算每个广告系列的不同点击次数。这项分析的结果存储在别名`count_of_click_thrus_by_campaign`中。

然后，在后续行中计算了问题的第二个维度。不需要过滤，因为我们只想要按广告系列计算印象的计数。这些结果存储在别名`count_of_impressions_by_campaign`中。

执行 Pig 脚本会产生以下输出：

```scala
(campaign6,2,4,0.5)
(campaign7,4,7,0.5714285714285714)
(campaign8,1,1,1.0)
(campaign10,0,2,)
```

输出中的第一个元素是广告系列标识符。接着是所有不同的点击次数和总印象次数。最后一个元素是效果，即所有不同的点击次数与总印象次数的比率。

## 执行实时分析

现在，让我们将批处理分析转化为实时分析。对 Pig 脚本的严格解释可能会导致以下拓扑：

```scala
Stream inputStream = topology.newStream("clickthru", spout);
Stream click_thru_stream = inputStream.each(
new Fields("cookie", "campaign", "product", "click"), 
new Filter("click", "true"))
.each(new Fields("cookie", "campaign", "product", "click"), 
new Distinct())
                .groupBy(new Fields("campaign"))              
                .persistentAggregate(
new MemoryMapState.Factory(), new Count(), 
new Fields("click_thru_count"))
                .newValuesStream();

Stream impressions_stream = inputStream.groupBy(
new Fields("campaign"))
                .persistentAggregate(
new MemoryMapState.Factory(), new Count(), 
new Fields("impression_count"))
                .newValuesStream();

topology.join(click_thru_stream, new Fields("campaign"),
impressions_stream, new Fields("campaign"), 
  new Fields("campaign", "click_thru_count", "impression_count"))
                .each(new Fields("campaign", 
"click_thru_count", "impression_count"), 
new CampaignEffectiveness(), new Fields(""));
```

在前述拓扑中，我们将流分成两个独立的流：`click_thru_stream`和`impressions_stream`。`click_thru_stream`包含不同印象的计数。`impressions_stream`包含印象的总计数。然后使用`topology.join`方法将这两个流连接起来。

前述拓扑的问题在于连接。在 Pig 中，由于集合是静态的，它们可以很容易地连接。Storm 中的连接是基于每个批次进行的。这不一定是个问题。然而，连接也是内连接，这意味着只有在流之间存在对应元组时才会发出记录。在这种情况下，我们正在从`click_thru_stream`中过滤记录，因为我们只想要不同的记录。因此，该流的基数小于`impressions_stream`的基数，这意味着在连接过程中会丢失元组。

### 提示

对于离散集合，诸如连接之类的操作是明确定义的，但不清楚如何将它们的定义转化为无限事件流的实时世界。有关更多信息，请访问以下 URL：

+   [`cwiki.apache.org/confluence/display/PIG/Pig+on+Storm+Proposal`](https://cwiki.apache.org/confluence/display/PIG/Pig+on+Storm+Proposal)

+   [`issues.apache.org/jira/browse/PIG-3453`](https://issues.apache.org/jira/browse/PIG-3453)

相反，我们将使用 Trident 的状态构造来在流之间共享计数。

这在以下图表中显示了更正后的拓扑：

![执行实时分析](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/storm-bp/img/8294OS_09_15.jpg)

此拓扑的代码如下：

```scala
StateFactory clickThruMemory = new MemoryMapState.Factory();
ClickThruSpout spout = new ClickThruSpout();
Stream inputStream = topology.newStream("clithru", spout);
TridentState clickThruState = inputStream.each(
new Fields("cookie", "campaign", "product", "click"),
new Filter("click", "true"))
   .each(new Fields("cookie", "campaign", "product", "click"),
new Distinct())
   .groupBy(new Fields("campaign"))
   .persistentAggregate(clickThruMemory, new Count(),
new Fields("click_thru_count"));

inputStream.groupBy(new Fields("campaign"))
.persistentAggregate(new MemoryMapState.Factory(),
new Count(), new Fields("impression_count"))
.newValuesStream()
.stateQuery(clickThruState, new Fields("campaign"),
new MapGet(), new Fields("click_thru_count"))
.each(new Fields("campaign", "impression_count",
      "click_thru_count"),
new CampaignEffectiveness(), new Fields(""));
```

让我们先看看 spout。它简单地读取文件，解析行，并发出元组，如下面的代码片段所示：

```scala
public class ClickThruEmitter
implements Emitter<Long>, Serializable {
...
@Override
public void emitBatch(TransactionAttempt tx,
Long coordinatorMeta, TridentCollector collector) {
     File file = new File("click_thru_data.txt");
     try {
         BufferedReader br = 
new BufferedReader(new FileReader(file));
         String line = null;
         while ((line = br.readLine()) != null) {
          String[] data = line.split(" ");
          List<Object> tuple = new ArrayList<Object>();
          tuple.add(data[0]); // cookie
          tuple.add(data[1]); // campaign
          tuple.add(data[2]); // product
          tuple.add(data[3]); // click
          collector.emit(tuple);
         }
         br.close();
     } catch (Exception e) {
         throw new RuntimeException(e);
     }
}
     ...
}
```

在真实系统中，前述 spout 很可能会从 Kafka 队列中读取。或者，如果我们想要重新创建批处理机制正在执行的操作，spout 可以直接从 HDFS 中读取。

### 提示

有一些关于可以从 HDFS 读取的 spout 的初步工作；请查看以下 URL 以获取更多信息：

[`github.com/jerrylam/storm-hdfs`](https://github.com/jerrylam/storm-hdfs)

为了计算所有点击次数的不同计数，拓扑首先过滤流，仅保留导致点击次数的印象。

此过滤器的代码如下：

```scala
public class Filter extends BaseFilter {
    private static final long serialVersionUID = 1L;
    private String fieldName = null;
    private String value = null;

    public Filter(String fieldName, String value){
        this.fieldName = fieldName;
        this.value = value;        
    }

    @Override
    public boolean isKeep(TridentTuple tuple) {
        String tupleValue = tuple.getStringByField(fieldName); 
        if (tupleValue.equals(this.value)) {
          return true;
        }
        return false;
    }
}
```

然后，流仅过滤出不同的点击次数。在这个例子中，它使用内存缓存来过滤不同的元组。实际上，这应该使用分布式状态和/或分组操作来将相似的元组定向到同一主机。没有持久存储，该示例最终会在 JVM 中耗尽内存。

### 提示

正在积极研究算法来近似数据流中的不同集合。有关**Streaming Quotient Filter**（**SQF**）的更多信息，请查看以下网址：

[`www.vldb.org/pvldb/vol6/p589-dutta.pdf`](http://www.vldb.org/pvldb/vol6/p589-dutta.pdf)

对于我们的示例，`Distinct`函数显示在以下代码片段中：

```scala
public class Distinct extends BaseFilter {
    private static final long serialVersionUID = 1L;
    private Set<String> distincter = Collections.synchronizedSet(new HashSet<String>());

    @Override
    public boolean isKeep(TridentTuple tuple) {        
        String id = this.getId(tuple);
   return distincter.add(id);
    }

    public String getId(TridentTuple t){
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < t.size(); i++){
           sb.append(t.getString(i));
        }
        return sb.toString();
    }
}
```

一旦获得所有不同的点击量，Storm 会使用`persistAggregate`调用将该信息持久化到 Trident 状态中。这通过使用`Count`运算符来折叠流。在示例中，我们使用了 MemoryMap。然而，在实际系统中，我们很可能会应用分布式存储机制，如 Memcache 或 Cassandra。

处理初始流的结果是一个包含按广告系列标识符分组的所有不同点击量的`TridentState`对象。*连接*两个流的关键行如下所示：

```scala
.stateQuery(clickThruState, new Fields("campaign"),
new MapGet(), new Fields("click_thru_count"))
```

这将将初始流中开发的状态合并到第二个流中开发的分析中。实际上，第二个流查询状态机制以获取该广告系列的所有不同点击量，并将其作为字段添加到在此流程中处理的元组中。然后可以利用该字段进行效果计算，该计算封装在以下类中：

```scala
public class CampaignEffectiveness extends BaseFunction {
    private static final long serialVersionUID = 1L;

    @Override
    public void execute(TridentTuple tuple, TridentCollector collector) {
   String campaign = (String) tuple.getValue(0);
        Long impressions_count = (Long) tuple.getValue(1);
        Long click_thru_count = (Long) tuple.getValue(2);
        if (click_thru_count == null) 
            click_thru_count = new Long(0);
        double effectiveness = (double) click_thru_count / (double) impressions_count;
   Log.error("[" + campaign + "," + String.valueOf(click_thru_count) + "," + impressions_count + ", " + effectiveness + "]");
   List<Object> values = new ArrayList<Object>();
   values.add(campaign);
   collector.emit(values);
    }
}
```

如前面的代码所示，该类通过计算包含总计数的字段与状态查询引入的字段之间的比率来计算效果。

# 部署拓扑

要部署前面的拓扑，必须首先使用以下命令检索 Storm-YAML 配置：

```scala
storm-yarn getStormConfig ../your.yaml --appId application_1381197763696_0004 --output output.yaml

```

前面的命令与指定的 Storm-YARN 应用程序实例交互，以检索可以使用标准机制部署拓扑的`storm.yaml`文件。只需将`output.yaml`文件复制到适当的位置（通常为`~/.storm/storm.yaml`），然后使用标准的`storm jar`命令进行部署，如下所示：

```scala
storm jar <appJar>
```

# 执行拓扑

执行前面的拓扑将产生以下输出：

```scala
00:00 ERROR: [campaign10,0,2, 0.0]
00:00 ERROR: [campaign6,2,4, 0.5]
00:00 ERROR: [campaign7,4,7, 0.5714285714285714]
00:00 ERROR: [campaign8,1,1, 1.0]
```

请注意，这些值与 Pig 发出的值相同。如果让拓扑运行，最终会看到效果得分逐渐降低，如下面的输出所示：

```scala
00:03 ERROR: [campaign10,0,112, 0.0]
00:03 ERROR: [campaign6,2,224, 0.008928571428571428]
00:03 ERROR: [campaign7,4,392, 0.01020408163265306]
00:03 ERROR: [campaign8,1,56, 0.017857142857142856]
```

这是有道理的，因为我们现在有了一个实时系统，它不断地消耗相同的印象事件。由于我们只计算所有不同的点击量，并且整个点击量集已经在计算中被考虑，效果将继续下降。

# 总结

在本章中，我们看到了一些不同的东西。首先，我们看到了将利用 Pig 的批处理机制转换为在 Storm 中实现的实时系统的蓝图。我们看到了直接翻译该脚本将不起作用的原因，因为实时系统中联接的限制，传统的联接操作需要有限的数据集。为了解决这个问题，我们使用了带有分叉流的共享状态模式。

其次，也许最重要的是，我们研究了 Storm-YARN；它允许用户重用 Hadoop 基础设施来部署 Storm。这不仅为现有的 Hadoop 用户提供了快速过渡到 Storm 的途径，还允许用户利用 Hadoop 的云机制，如亚马逊的**弹性 Map Reduce**（**EMR**）。使用 EMR，Storm 可以快速部署到云基础设施，并根据需求进行扩展。

最后，作为未来的工作，社区正在探索直接在 Storm 上运行 Pig 脚本的方法。这将允许用户直接将其现有的分析移植到 Storm 上。

要监视这项工作，请访问[`cwiki.apache.org/confluence/display/PIG/Pig+on+Storm+Proposal.`](https://cwiki.apache.org/confluence/display/PIG/Pig+on+Storm+Proposal.)

在下一章中，我们将探讨使用 Apache Whirr 在云中自动部署 Storm。虽然没有明确提到，但下一章中的技术可以用于云部署。
