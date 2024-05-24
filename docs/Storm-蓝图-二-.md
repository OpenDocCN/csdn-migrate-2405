# Storm 蓝图（二）

> 原文：[`zh.annas-archive.org/md5/770BD43D187DC246E15A42C26D059632`](https://zh.annas-archive.org/md5/770BD43D187DC246E15A42C26D059632)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：实时趋势分析

在本章中，我们将介绍使用 Storm 和 Trident 的趋势分析技术。实时趋势分析涉及识别数据流中的模式，例如识别特定事件的发生率或计数达到一定阈值时。常见的例子包括社交媒体中的热门话题，例如特定标签在 Twitter 上变得流行，或者识别搜索引擎中的热门搜索词。Storm 最初是一个在 Twitter 数据上执行实时分析的项目，并且提供了许多用于分析计算所需的核心原语。

在前几章中，spout 实现主要是使用静态样本数据或随机生成的数据的模拟。在本章中，我们将介绍一个开源的 spout，它从队列（Apache Kafka）发出数据，并支持 Trident spout 事务的所有三种类型（非事务、重复事务和不透明事务）。我们还将实现一种简单的通用方法，用于使用流行的日志框架填充 Kafka 队列，从而使您能够快速开始对现有应用程序和数据进行实时分析，几乎不需要进行任何源代码修改。

在本章中，我们将涵盖以下主题：

+   将日志数据记录到 Apache Kafka 并将其流式传输到 Storm

+   将现有应用程序的日志数据流式传输到 Storm 进行分析

+   实施指数加权移动平均 Trident 函数

+   使用 XMPP 协议与 Storm 发送警报和通知

# 使用案例

在我们的用例中，我们有一个应用程序或一组应用程序（网站，企业应用程序等），它们使用流行的 logback 框架（[`logback.qos.ch`](http://logback.qos.ch)）将结构化消息记录到磁盘（访问日志，错误等）。目前，对该数据进行分析的唯一方法是使用类似 Hadoop 的东西批处理处理文件。该过程引入的延迟大大减慢了我们的反应时间；从日志数据中获取的模式通常要在特定事件发生后数小时，有时甚至数天后才出现，错失了采取响应行动的机会。更希望在模式出现后立即被主动通知，而不是事后才得知。

这个用例代表了一个常见的主题，并在许多业务场景中有广泛的应用，包括以下应用：

+   应用程序监控：例如，在某些网络错误达到一定频率时通知系统管理员

+   入侵检测：例如，检测到失败的登录尝试增加等可疑活动

+   供应链管理：例如，识别特定产品销售量的激增，并相应调整及时交付

+   在线广告：例如，识别热门趋势和动态更改广告投放

# 架构

我们的应用程序的架构如下图所示，并将包括以下组件：

![架构](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/storm-bp/img/8294OS_04_01.jpg)

## 源应用程序

源应用程序组件是使用 logback 框架记录任意日志消息的任何应用程序。对于我们的目的，我们将创建一个简单的应用程序，以在特定间隔记录结构化消息。但是，正如您将看到的，任何现有应用程序使用 logback 或 slf4j 框架都可以通过简单的配置更改来替换。

## logback Kafka appender

logback 框架具有扩展机制，允许您向其配置添加附加器。logback 附加器只是一个接收日志事件并对其进行处理的 Java 类。最常用的附加器是几个`FileAppender`子类之一，它们只是将日志消息格式化并写入磁盘上的文件。其他附加器实现将日志数据写入网络套接字、关系数据库和 SMTP 以进行电子邮件通知。为了我们的目的，我们将实现一个将日志消息写入 Apache Kafka 队列的附加器。

## Apache Kafka

Apache Kafka ([`kafka.apache.org`](http://kafka.apache.org)) 是一个开源的分布式发布-订阅消息系统。Kafka 专门设计和优化用于高吞吐量、持久的实时流。与 Storm 一样，Kafka 被设计为在通用软件上水平扩展，以支持每秒数十万条消息。

## Kafka spout

Kafka spout 从 Kafka 队列中读取数据并将其发射到 Storm 或 Trident 拓扑。Kafka spout 最初由 Nathan Marz 编写，并且仍然是 GitHub 上 storm-contrib 项目的一部分 ([`github.com/nathanmarz/storm-contrib`](https://github.com/nathanmarz/storm-contrib))。Kafka spout 的预构建二进制文件可从`clojars.org` Maven 存储库 ([`clojars.org/storm/storm-kafka`](https://clojars.org/storm/storm-kafka)) 获取。我们将使用 Kafka spout 从 Kafka 队列中读取消息并将其流入我们的拓扑。

我们的拓扑将由一系列内置和自定义的 Trident 组件（函数、过滤器、状态等）组成，用于检测源数据流中的模式。当检测到模式时，拓扑将向一个函数发出元组，该函数将向 XMPP 服务器发送 XMPP 消息，以通过**即时消息** (**IM**) 通知最终用户。

## XMPP 服务器

**可扩展消息和出席协议** (**XMPP**) ([`xmpp.org`](http://xmpp.org)) 是一种基于 XML 的即时消息、出席信息和联系人列表维护的标准。许多即时消息客户端，如 Adium（用于 OSX）([`adium.im`](http://adium.im))和 Pidgin（用于 OSX、Linus 和 Windows）([`www.pidgin.im`](http://www.pidgin.im))支持 XMPP 协议，如果您曾经使用过 Google Talk 进行即时消息传递，那么您已经使用过 XMPP。

我们将使用开源的 OpenFire XMPP 服务器 ([`www.igniterealtime.org/projects/openfire/`](http://www.igniterealtime.org/projects/openfire/))，因为它易于设置并且与 OSX、Linux 和 Windows 兼容。

# 安装所需软件

我们将首先安装必要的软件：Apache Kafka 和 OpenFire。虽然 Kafka 是一个分布式消息系统，但作为单节点安装，甚至作为开发环境的一部分本地安装都可以正常工作。在生产环境中，您需要根据扩展需求设置一个或多个机器的集群。OpenFire 服务器不是一个集群系统，可以安装在单个节点或本地。

## 安装 Kafka

Kafka 依赖于 ZooKeeper 来存储某些状态信息，就像 Storm 一样。由于 Storm 对 ZooKeeper 的负载相对较轻，在许多情况下可以接受在 Kafka 和 Storm 之间共享相同的 ZooKeeper 集群。由于我们已经在第二章中介绍了 ZooKeeper 的安装，*配置 Storm 集群*，这里我们只介绍与 Kafka 一起提供的本地 ZooKeeper 服务器的运行，适用于开发环境。

首先从以下网站下载 Apache Kafka 的 0.7.x 版本：

[`kafka.apache.org/downloads.html`](http://kafka.apache.org/downloads.html)

接下来，解压源分发并将现有目录更改为以下目录：

```scala
tar -zxf kafka-0.7.2-incubating-src.tgz
cd kafka-0.7.2-incubating-src
```

Kafka 是用 Scala JVM 语言（[`www.scala-lang.org`](http://www.scala-lang.org)）编写的，并使用`sbt`（**Scala Build Tool**）（[`www.scala-sbt.org`](http://www.scala-sbt.org)）进行编译和打包。幸运的是，Kafka 源代码分发包括`sbt`，可以使用以下命令构建：

```scala
./sbt update package
```

在启动 Kafka 之前，除非您已经运行了 ZooKeeper 服务，否则您需要使用以下命令启动与 Kafka 捆绑的 ZooKeeper 服务：

```scala
./bin/zookeeper-server-start.sh ./config/zookeeper.properties
```

最后，在一个单独的终端窗口中，使用以下命令启动 Kafka 服务：

```scala
./bin/kafka-server-start.sh ./config/server.properties
```

Kafka 服务现在可以使用了。

## 安装 OpenFire

OpenFire 可作为 OSX 和 Windows 的安装程序以及各种 Linux 发行版的软件包提供，并且可以从以下网站下载：

[`www.igniterealtime.org/downloads/index.jsp`](http://www.igniterealtime.org/downloads/index.jsp)

要安装 OpenFire，请下载适用于您操作系统的安装程序，并按照以下网站上找到的适当安装说明进行操作：

[`www.igniterealtime.org/builds/openfire/docs/latest/documentation/index.html`](http://www.igniterealtime.org/builds/openfire/docs/latest/documentation/index.html)

# 介绍示例应用程序

应用组件是一个简单的 Java 类，使用**Simple Logging Facade for Java**（**SLF4J**）（[`www.slf4j.org`](http://www.slf4j.org)）记录消息。我们将模拟一个应用程序，开始以相对较慢的速率生成警告消息，然后切换到以更快的速率生成警告消息的状态，最后返回到慢速状态，如下所示：

+   每 5 秒记录一次警告消息，持续 30 秒（慢速状态）

+   每秒记录一次警告消息，持续 15 秒（快速状态）

+   每 5 秒记录一次警告消息，持续 30 秒（慢速状态）

该应用程序的目标是生成一个简单的模式，我们的风暴拓扑可以识别并在出现特定模式和状态变化时发送通知，如下面的代码片段所示：

```scala
public class RogueApplication {
    private static final Logger LOG = LoggerFactory.getLogger(RogueApplication.class);

    public static void main(String[] args) throws Exception {
        int slowCount = 6;
        int fastCount = 15;
        // slow state
        for(int i = 0; i < slowCount; i++){
            LOG.warn("This is a warning (slow state).");
            Thread.sleep(5000);
        }
        // enter rapid state
        for(int i = 0; i < fastCount; i++){
            LOG.warn("This is a warning (rapid state).");
            Thread.sleep(1000);
        }
        // return to slow state
        for(int i = 0; i < slowCount; i++){
            LOG.warn("This is a warning (slow state).");
            Thread.sleep(5000);
        }
    }
}
```

## 将日志消息发送到 Kafka

logback 框架提供了一个简单的扩展机制，允许您插入附加的附加器。在我们的情况下，我们想要实现一个可以将日志消息数据写入 Kafka 的附加器。

Logback 包括`ch.qos.logback.core.AppenderBase`抽象类，使得实现`Appender`接口变得容易。`AppenderBase`类定义了一个抽象方法如下：

```scala
  abstract protected void append(E eventObject);
```

`eventObject`参数表示日志事件，并包括事件日期、日志级别（`DEBUG`、`INFO`、`WARN`等）以及日志消息本身等属性。我们将重写`append()`方法，将`eventObject`数据写入 Kafka。

除了`append()`方法之外，`AppenderBase`类还定义了两个我们需要重写的附加生命周期方法：

```scala
 public void start();
 public void stop();
```

`start()`方法在 logback 框架初始化期间调用，`stop()`方法在去初始化时调用。我们将重写这些方法来建立和拆除与 Kafka 服务的连接。

`KafkaAppender`类的源代码如下所示：

```scala
public class KafkaAppender extends AppenderBase<ILoggingEvent> {

    private String topic;
    private String zookeeperHost;
    private Producer<String, String> producer;
    private Formatter formatter;

    // java bean definitions used to inject
    // configuration values from logback.xml
    public String getTopic() {
        return topic;
    }

    public void setTopic(String topic) {
        this.topic = topic;
    }

    public String getZookeeperHost() {
        return zookeeperHost;
    }

    public void setZookeeperHost(String zookeeperHost) {
        this.zookeeperHost = zookeeperHost;
    }

    public Formatter getFormatter() {
        return formatter;
    }

    public void setFormatter(Formatter formatter) {
        this.formatter = formatter;
    }

    // overrides
    @Override
    public void start() {
        if (this.formatter == null) {
            this.formatter = new MessageFormatter();
        }
        super.start();
        Properties props = new Properties();
        props.put("zk.connect", this.zookeeperHost);
        props.put("serializer.class", "kafka.serializer.StringEncoder");
        ProducerConfig config = new ProducerConfig(props);
        this.producer = new Producer<String, String>(config);
    }

    @Override
    public void stop() {
        super.stop();
        this.producer.close();
    }

    @Override
    protected void append(ILoggingEvent event) {
        String payload = this.formatter.format(event);
        ProducerData<String, String> data = new ProducerData<String, String>(this.topic, payload);
        this.producer.send(data);
    }

}
```

正如您将看到的，这个类中的 JavaBean 风格的访问器允许我们在 logback 框架初始化时通过依赖注入配置相关值。`zookeeperHosts`属性的 setter 和 getter 用于初始化`KafkaProducer`客户端，配置它以发现已在 ZooKeeper 注册的 Kafka 主机。另一种方法是提供一个静态的 Kafka 主机列表，但为了简单起见，使用自动发现机制更容易。`topic`属性用于告诉`KafkaConsumer`客户端应该从哪个 Kafka 主题读取。

`Formatter`属性有些特殊。这是一个我们定义的接口，提供了处理结构化（即可解析的）日志消息的扩展点，如下面的代码片段所示：

```scala
public interface Formatter {
    String format(ILoggingEvent event);
}
```

`Formatter`实现的工作是将`ILoggingEvent`对象转换为可被消费者处理的机器可读字符串。下面的简单实现只是返回日志消息，丢弃任何额外的元数据：

```scala
public class MessageFormatter implements Formatter {

    public String format(ILoggingEvent event) {
        return event.getFormattedMessage();
    }
}
```

以下的 logback 配置文件展示了 appender 的使用。这个例子没有定义自定义的`Formatter`实现，所以`KafkaAppender`类将默认使用`MessageFormatter`类，只会将日志消息数据写入 Kafka 并丢弃日志事件中包含的任何额外信息，如下面的代码片段所示：

```scala
<?xml version="1.0" encoding="UTF-8" ?>
<configuration>
    <appender name="KAFKA"
        class="com.github.ptgoetz.logback.kafka.KafkaAppender">
        <topic>mytopic</topic>
        <zookeeperHost>localhost:2181</zookeeperHost>
    </appender>
    <root level="debug">
        <appender-ref ref="KAFKA" />
    </root>
</configuration>
```

我们正在构建的 Storm 应用程序是时间敏感的：如果我们正在跟踪每个事件发生的速率，我们需要准确知道事件发生的时间。一个天真的方法是当数据进入我们的拓扑时，简单地使用`System.currentTimeMillis()`方法为事件分配一个时间。然而，Trident 的批处理机制不能保证元组以与接收到的速率相同的速率传递到拓扑。

为了应对这种情况，我们需要在事件发生时捕获事件的时间并在写入 Kafka 队列时包含在数据中。幸运的是，`ILoggingEvent`类包括一个时间戳，表示事件发生时距离纪元的毫秒数。

为了包含`ILoggingEvent`中包含的元数据，我们将创建一个自定义的`Formatter`实现，将日志事件数据编码为 JSON 格式，如下所示：

```scala
public class JsonFormatter implements Formatter {
    private static final String QUOTE = "\"";
    private static final String COLON = ":";
    private static final String COMMA = ",";

    private boolean expectJson = false;

    public String format(ILoggingEvent event) {
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        fieldName("level", sb);
        quote(event.getLevel().levelStr, sb);
        sb.append(COMMA);
        fieldName("logger", sb);
        quote(event.getLoggerName(), sb);
        sb.append(COMMA);
        fieldName("timestamp", sb);
        sb.append(event.getTimeStamp());
        sb.append(COMMA);
        fieldName("message", sb);
        if (this.expectJson) {
            sb.append(event.getFormattedMessage());
        } else {
            quote(event.getFormattedMessage(), sb);
        }

        sb.append("}");
        return sb.toString();
    }

    private static void fieldName(String name, StringBuilder sb) {
        quote(name, sb);
        sb.append(COLON);
    }

    private static void quote(String value, StringBuilder sb) {
        sb.append(QUOTE);
        sb.append(value);
        sb.append(QUOTE);
    }

    public boolean isExpectJson() {
        return expectJson;
    }

    public void setExpectJson(boolean expectJson) {
        this.expectJson = expectJson;
    }
}
```

`JsonMessageFormatter`类的大部分代码使用`java.lang.StringBuilder`类从`ILoggingEvent`对象创建 JSON。虽然我们可以使用 JSON 库来完成工作，但我们生成的 JSON 数据很简单，添加额外的依赖只是为了生成 JSON 会显得过度。

`JsonMessageFormatter`公开的一个 JavaBean 属性是`expectJson`布尔值，用于指定传递给`Formatter`实现的日志消息是否应被视为 JSON。如果设置为`False`，日志消息将被视为字符串并用双引号括起来，否则消息将被视为 JSON 对象（`{...}`）或数组（`[...]`）。

以下是一个示例的 logback 配置文件，展示了`KafkaAppender`和`JsonFormatter`类的使用：

```scala
<?xml version="1.0" encoding="UTF-8" ?>
<configuration>
    <appender name="KAFKA"
        class="com.github.ptgoetz.logback.kafka.KafkaAppender">
        <topic>foo</topic>
        <zookeeperHost>localhost:2181</zookeeperHost>
        <!-- specify a custom formatter -->
        <formatter class="com.github.ptgoetz.logback.kafka.formatter.JsonFormatter">
            <!-- 
            Whether we expect the log message to be JSON encoded or not.
            If set to "false", the log message will be treated as a string, and wrapped in quotes. Otherwise it will be treated as a parseable JSON object.
            -->
            <expectJson>false</expectJson>
        </formatter>
    </appender>
	<root level="debug">
		<appender-ref ref="KAFKA" />
	</root>
</configuration>
```

由于我们正在构建的分析拓扑更关注事件时间而不是消息内容，我们生成的日志消息将是字符串，因此我们将`expectJson`属性设置为`False`。

# 介绍日志分析拓扑

有了将日志数据写入 Kafka 的手段，我们准备将注意力转向实现一个 Trident 拓扑来执行分析计算。拓扑将执行以下操作：

1.  接收并解析原始 JSON 日志事件数据。

1.  提取并发出必要的字段。

1.  更新指数加权移动平均函数。

1.  确定移动平均是否越过了指定的阈值。

1.  过滤掉不代表状态改变的事件（例如，速率移动超过/低于阈值）。

1.  发送即时消息（XMPP）通知。

拓扑结构如下图所示，三叉戟流操作位于顶部，流处理组件位于底部：

![介绍日志分析拓扑](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/storm-bp/img/8294OS_04_02.jpg)

## Kafka spout

创建日志分析拓扑的第一步是配置 Kafka spout，将从 Kafka 接收的数据流入我们的拓扑，如下所示：

```scala
        TridentTopology topology = new TridentTopology();

        StaticHosts kafkaHosts = KafkaConfig.StaticHosts.fromHostString(Arrays.asList(new String[] { "localhost" }), 1);
        TridentKafkaConfig spoutConf = new TridentKafkaConfig(kafkaHosts, "log-analysis");
        spoutConf.scheme = new StringScheme();
        spoutConf.forceStartOffsetTime(-1);
        OpaqueTridentKafkaSpout spout = new OpaqueTridentKafkaSpout(spoutConf);

        Stream spoutStream = topology.newStream("kafka-stream", spout);
```

这段代码首先创建了一个新的`TridentTopology`实例，然后使用 Kafka Java API 创建了一个 Kafka 主机列表，用于连接（因为我们在本地运行单个、非集群的 Kafka 服务，所以我们指定了一个主机：`localhost`）。接下来，我们创建了`TridentKafkaConfig`对象，将主机列表和唯一标识符传递给它。

我们的应用程序写入 Kafka 的数据是一个简单的 Java 字符串，因此我们使用 Storm-Kafka 内置的`StringScheme`类。`StringScheme`类将从 Kafka 读取数据作为字符串，并将其输出到名为`str`的元组字段中。

默认情况下，在部署时，Kafka spout 将尝试从 Kafka 队列中上次离开的地方读取状态信息。这种行为可以通过调用`TridentKafkaConfig`类的`forceOffsetTime(long time)`方法来覆盖。时间参数可以是以下三个值之一：

+   **-2（最早的偏移）**：spout 将*倒带*并从队列的开头开始读取

+   **-1（最新的偏移）**：spout 将*快进*并从队列的末尾读取

+   **以毫秒为单位的时间**：给定特定日期的毫秒数（例如，`java.util.Date.getTime()`），spout 将尝试从那个时间点开始读取

在设置好 spout 配置之后，我们创建了一个*Opaque Transactional* Kafka spout 的实例，并设置了相应的 Trident 流。

## JSON 项目函数

来自 Kafka spout 的数据流将包含一个字段（`str`），其中包含来自日志事件的 JSON 数据。我们将创建一个 Trident 函数来解析传入的数据，并输出或投影请求的字段作为元组值，如下面的代码片段所示：

```scala
public class JsonProjectFunction extends BaseFunction {

    private Fields fields;

    public JsonProjectFunction(Fields fields) {
        this.fields = fields;
    }

    public void execute(TridentTuple tuple, TridentCollector collector) {
        String json = tuple.getString(0);
        Map<String, Object> map = (Map<String, Object>)  
            JSONValue.parse(json);
        Values values = new Values();
        for (int i = 0; i < this.fields.size(); i++) {
            values.add(map.get(this.fields.get(i)));
        }
        collector.emit(values);
    }

}
```

`JsonProjectFunction`构造函数接受一个`Fields`对象参数，该参数将确定要作为要查找的键名称列表从 JSON 中发出的值。当函数接收到一个元组时，它将解析元组的`str`字段中的 JSON，迭代`Fields`对象的值，并从输入 JSON 中发出相应的值。

以下代码创建了一个`Fields`对象，其中包含要从 JSON 中提取的字段名称列表。然后，它从 spout 流创建了一个新的`Stream`对象，选择`str`元组字段作为`JsonProjectFunction`构造函数的输入，构造了`JsonProjectFunction`构造函数，并指定从 JSON 中选择的字段也将从函数中输出：

```scala
        Fields jsonFields = new Fields("level", "timestamp", "message", "logger");
        Stream parsedStream = spoutStream.each(new Fields("str"), new JsonProjectFunction(jsonFields), jsonFields);
```

考虑到以下 JSON 消息是从 Kafka spout 接收到的：

```scala
{
  "message" : "foo",
  "timestamp" : 1370918376296,
  "level" : "INFO",
  "logger" : "test"
}
```

这意味着该函数将输出以下元组值：

```scala
[INFO, 1370918376296, test, foo]
```

## 计算移动平均

为了计算日志事件发生的速率，而无需存储过多的状态，我们将实现一个函数，执行统计学中所谓的**指数加权移动平均**。

移动平均计算经常用于平滑短期波动，并暴露时间序列数据中的长期趋势。移动平均的最常见的例子之一是在股票市场价格波动的图表中使用，如下面的屏幕截图所示：

![计算移动平均](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/storm-bp/img/8294OS_04_03.jpg)

移动平均的平滑效果是通过在计算中考虑历史值来实现的。移动平均计算可以以非常少量的状态执行。对于时间序列，我们只需要保留上一个事件的时间和上一个计算的平均值。

在伪代码中，计算看起来像以下代码片段：

```scala
diff = currentTime - lastEventTime
currentAverage = (1.0 - alpha) * diff + alpha * lastAverage
```

上述计算中的`alpha`值是介于`0`和`1`之间的常量值。`alpha`值确定随时间发生的平滑程度。`alpha`值越接近`1`，历史值对当前平均值的影响就越大。换句话说，`alpha`值越接近`0`，平滑效果就越小，移动平均值就越接近当前值。`alpha`值越接近`1`，效果就相反。当前平均值受到的波动影响就越小，历史值在确定当前平均值时的权重就越大。

## 添加一个滑动窗口

在某些情况下，我们可能希望打折历史值以减少它们对移动平均值的影响，例如，如果在接收事件之间经过了很长时间，我们可能希望重置平滑效果。在低 alpha 值的情况下，这可能是不必要的，因为平滑效果很小。然而，在高 alpha 值的情况下，抵消平滑效果可能是可取的。

考虑以下示例。

我们有一个（例如网络错误等）偶尔发生的事件。偶尔会出现小的频率波动，但通常没关系。因此，我们希望消除小的波动。我们希望被通知的是如果发生了*持续*的波动。

如果事件平均每周发生一次（远低于我们的通知阈值），但有一天在一个小时内发生了多次（超过我们的通知阈值），高 alpha 的平滑效果可能会抵消波动，以至于永远不会触发通知。

为了抵消这种影响，我们可以在移动平均值计算中引入**滑动窗口**的概念。由于我们已经在跟踪上一个事件的时间和当前平均值，因此实现滑动窗口就像在以下伪代码中所示的那样简单：

```scala
if (currentTime - lastEventTime) > slidingWindowInterval
    currentAverage = 0
end if
```

指数加权移动平均的实现如下所示：

```scala
public class EWMA implements Serializable {

    public static enum Time {
        MILLISECONDS(1), SECONDS(1000), MINUTES(SECONDS.getTime() * 60), HOURS(MINUTES.getTime() * 60), DAYS(HOURS
                .getTime() * 24), WEEKS(DAYS.getTime() * 7);

        private long millis;

        private Time(long millis) {
            this.millis = millis;
        }

        public long getTime() {
            return this.millis;
        }
    }

    // Unix load average-style alpha constants
    public static final double ONE_MINUTE_ALPHA = 1 - Math.exp(-5d / 60d / 1d);
    public static final double FIVE_MINUTE_ALPHA = 1 - Math.exp(-5d / 60d / 5d);
    public static final double FIFTEEN_MINUTE_ALPHA = 1 - Math.exp(-5d / 60d / 15d);

    private long window;
    private long alphaWindow;
    private long last;
    private double average;
    private double alpha = -1D;
    private boolean sliding = false;

    public EWMA() {
    }

    public EWMA sliding(double count, Time time) {
        return this.sliding((long) (time.getTime() * count));
    }

    public EWMA sliding(long window) {
        this.sliding = true;
        this.window = window;
        return this;
    }

    public EWMA withAlpha(double alpha) {
        if (!(alpha > 0.0D && alpha <= 1.0D)) {
            throw new IllegalArgumentException("Alpha must be between 0.0 and 1.0");
        }
        this.alpha = alpha;
        return this;
    }

    public EWMA withAlphaWindow(long alphaWindow) {
        this.alpha = -1;
        this.alphaWindow = alphaWindow;
        return this;
    }

    public EWMA withAlphaWindow(double count, Time time) {
        return this.withAlphaWindow((long) (time.getTime() * count));
    }

    public void mark() {
        mark(System.currentTimeMillis());
    }

    public synchronized void mark(long time) {
        if (this.sliding) {
            if (time - this.last > this.window) {
                // reset the sliding window
                this.last = 0;
            }
        }
        if (this.last == 0) {
            this.average = 0;
            this.last = time;
        }
        long diff = time - this.last;
        double alpha = this.alpha != -1.0 ? this.alpha : Math.exp(-1.0 * ((double) diff / this.alphaWindow));
        this.average = (1.0 - alpha) * diff + alpha * this.average;
        this.last = time;
    }

    public double getAverage() {
        return this.average;
    }

    public double getAverageIn(Time time) {
        return this.average == 0.0 ? this.average : this.average / time.getTime();
    }

    public double getAverageRatePer(Time time) {
        return this.average == 0.0 ? this.average : time.getTime() / this.average;
    }

}
```

`EWMA`实现定义了三个有用的常量`alpha`值：`ONE_MINUTE_ALPHA`，`FIVE_MINUTE_ALPHA`和`FIFTEEN_MINUTE_ALPHA`。这些对应于 UNIX 中用于计算负载平均值的标准`alpha`值。`alpha`值也可以手动指定，或者作为*alpha*窗口的函数。

该实现使用流畅的*构建器*API。例如，您可以创建一个具有一分钟滑动窗口和等效于 UNIX 一分钟间隔的`alpha`值的`EWMA`实例，如下面的代码片段所示：

```scala
EWMA ewma = new EWMA().sliding(1.0, Time.MINUTES).withAlpha(EWMA.ONE_MINUTE_ALPHA);
```

`mark（）`方法用于更新移动平均值。如果没有参数，`mark（）`方法将使用当前时间来计算平均值。因为我们想要使用日志事件的原始时间戳，我们重载`mark（）`方法以允许指定特定时间。

`getAverage（）`方法以毫秒为单位返回`mark（）`调用之间的平均时间。我们还添加了方便的`getAverageIn（）`方法，它将返回指定时间单位（秒，分钟，小时等）的平均值。`getAverageRatePer（）`方法返回特定时间测量中`mark（）`调用的速率。

正如您可能注意到的那样，使用指数加权移动平均值可能有些棘手。找到合适的 alpha 值以及可选滑动窗口的正确值在很大程度上取决于特定用例，并且找到正确的值在很大程度上是一个反复试验的问题。

## 实现移动平均函数

要在 Trident 拓扑中使用我们的`EWMA`类，我们将创建 Trident 的`BaseFunction`抽象类的子类，命名为`MovingAverageFunction`，它包装了一个`EWMA`实例，如下面的代码片段所示：

```scala
public class MovingAverageFunction extends BaseFunction {
    private static final Logger LOG = LoggerFactory.getLogger(BaseFunction.class);

    private EWMA ewma;
    private Time emitRatePer;

    public MovingAverageFunction(EWMA ewma, Time emitRatePer){
        this.ewma = ewma;
        this.emitRatePer = emitRatePer;
    }

    public void execute(TridentTuple tuple, TridentCollector collector) {
        this.ewma.mark(tuple.getLong(0));
        LOG.debug("Rate: {}", this.ewma.getAverageRatePer(this.emitRatePer));
        collector.emit(new Values(this.ewma.getAverageRatePer(this.emitRatePer)));
    }
}
```

`MovingAverage.execute()`方法获取传入元组的第一个字段的`Long`值，使用该值调用`mark()`方法来更新当前平均值，并发出当前平均速率。Trident 中的函数是累加的，这意味着它们将值添加到流中的元组中。因此，例如，考虑传入我们函数的元组如下代码片段所示：

```scala
[INFO, 1370918376296, test, foo]
```

这意味着在处理后，元组可能看起来像下面的代码片段：

```scala
[INFO, 1370918376296, test, foo, 3.72234]
```

在这里，新值代表了新的平均速率。

为了使用该函数，我们创建了一个`EWMA`类的实例，并将其传递给`MovingAverageFunction`构造函数。我们使用`each()`方法将该函数应用于流，选择`timestamp`字段作为输入，如下面的代码片段所示：

```scala
        EWMA ewma = new EWMA().sliding(1.0, Time.MINUTES).withAlpha(EWMA.ONE_MINUTE_ALPHA);
        Stream averageStream = parsedStream.each(new Fields("timestamp"),
                new MovingAverageFunction(ewma, Time.MINUTES), new Fields("average"));
```

## 阈值过滤

对于我们的用例，我们希望能够定义一个触发通知的速率阈值。当超过阈值时，我们还希望在平均速率再次低于该阈值时收到通知（即恢复正常）。我们可以使用额外的函数和简单的 Trident 过滤器的组合来实现这个功能。

函数的作用是确定平均速率字段的新值是否越过了阈值，并且它是否代表了与先前值的变化（即它是否从*低于阈值*变为*高于阈值*或反之）。如果新的平均值代表了状态变化，函数将发出布尔值`True`，否则它将发出`False`。我们将利用该值来过滤掉不代表状态变化的事件。我们将在`ThresholdFilterFunction`类中实现阈值跟踪功能，如下面的代码片段所示：

```scala
public class ThresholdFilterFunction extends BaseFunction {
    private static final Logger LOG = LoggerFactory.getLogger(ThresholdFilterFunction.class);

    private static enum State {
        BELOW, ABOVE;
    }

    private State last = State.BELOW;
    private double threshold;

    public ThresholdFilterFunction(double threshold){
        this.threshold = threshold;
    }

    public void execute(TridentTuple tuple, TridentCollector collector) {
        double val = tuple.getDouble(0);
        State newState = val < this.threshold ? State.BELOW : State.ABOVE;
        boolean stateChange = this.last != newState;
        collector.emit(new Values(stateChange, threshold));
        this.last = newState;
        LOG.debug("State change? --> {}", stateChange);
    }
}
```

`ThresholdFilterFunction`类定义了一个内部枚举来表示状态（高于阈值或低于阈值）。构造函数接受一个双精度参数，用于建立我们要比较的阈值。在`execute()`方法中，我们获取当前速率值，并确定它是低于还是高于阈值。然后，我们将其与上一个状态进行比较，看它是否已经改变，并将该值作为布尔值发出。最后，我们将内部的高于/低于状态更新为新计算的值。

通过`ThresholdFilterFunction`类后，输入流中的元组将包含一个新的布尔值，我们可以使用它来轻松过滤掉不触发状态变化的事件。为了过滤掉非状态变化的事件，我们将使用一个简单的`BooleanFilter`类，如下面的代码片段所示：

```scala
public class BooleanFilter extends BaseFilter {

    public boolean isKeep(TridentTuple tuple) {
        return tuple.getBoolean(0);
    }
}
```

`BooleanFilter.isKeep()`方法只是从元组中读取一个字段作为布尔值并返回该值。任何包含输入值为`False`的元组将被过滤出结果流。

以下代码片段说明了`ThresholdFilterFuncation`类和`BooleanFilter`类的用法：

```scala
        ThresholdFilterFunction tff = new ThresholdFilterFunction(50D);
        Stream thresholdStream = averageStream.each(new Fields("average"), tff, new Fields("change", "threshold"));

        Stream filteredStream = thresholdStream.each(new Fields("change"), new BooleanFilter());
```

第一行创建了一个具有阈值`50.0`的`ThresholdFilterFunction`实例。然后，我们使用`averageStream`作为输入创建了一个新的流，并选择`average`元组字段作为输入。我们还为函数添加的字段分配了名称（`change`和`threshold`）。最后，我们应用`BooleanFilter`类创建一个新的流，该流将只包含代表阈值比较变化的元组。

此时，我们已经有了实现通知所需的一切。我们创建的`filteredStream`将只包含代表阈值状态变化的元组。

## 使用 XMPP 发送通知

XMPP 协议提供了即时消息标准中所期望的所有典型功能：

+   花名册（联系人列表）

+   在线状态（知道其他人何时在线以及他们的可用状态）

+   用户之间的即时消息

+   群聊

XMPP 协议使用 XML 格式进行通信，但有许多高级客户端库可以处理大部分低级细节，并提供简单的 API。我们将使用 Smack API（[`www.igniterealtime.org/projects/smack/`](http://www.igniterealtime.org/projects/smack/)），因为它是最直接的 XMPP 客户端实现之一。

以下代码片段演示了使用 Smack API 向另一个用户发送简单即时消息的用法：

```scala
        // connect to XMPP server and login
        ConnectionConfiguration config = new
            ConnectionConfiguration("jabber.org");
        XMPPConnection client = new XMPPConnection(config);
        client.connect();
        client.login("username", "password");

        // send a message to another user
        Message message =
           new Message("myfriend@jabber.org", Type.normal);
        message.setBody("How are you today?");
        client.sendPacket(message);
```

该代码连接到[jabber.org](http://jabber.org)的 XMPP 服务器，并使用用户名和密码登录。在幕后，Smack 库处理与服务器的低级通信。当客户端连接并进行身份验证时，它还向服务器发送了一个出席消息。这允许用户的联系人（在其 XMPP 花名册中列出的其他用户）收到通知，表明该用户现在已连接。最后，我们创建并发送一个简单的消息，地址为`"myfriend@jabber.org"`。

基于这个简单的例子，我们将创建一个名为`XMPPFunction`的类，当它接收到 Trident 元组时，会发送 XMPP 通知。该类将在`prepare()`方法中建立与 XMPP 服务器的长连接。此外，在`execute()`方法中，它将根据接收到的元组创建一个 XMPP 消息。

为了使`XMPPFunction`类更具可重用性，我们将引入`MessageMapper`接口，该接口定义了一种方法，用于将 Trident 元组的数据格式化为适合即时消息通知的字符串，如下所示的代码片段所示：

```scala
public interface MessageMapper extends Serializable {
    public String toMessageBody(TridentTuple tuple);
}
```

我们将在`XMPPFunction`类中委托消息格式化给一个`MessageMapper`实例，如下所示的代码片段所示：

```scala
public class XMPPFunction extends BaseFunction {
    private static final Logger LOG = LoggerFactory.getLogger(XMPPFunction.class);

    public static final String XMPP_TO = "storm.xmpp.to";
    public static final String XMPP_USER = "storm.xmpp.user";
    public static final String XMPP_PASSWORD = "storm.xmpp.password";
    public static final String XMPP_SERVER = "storm.xmpp.server";

    private XMPPConnection xmppConnection;
    private String to;
    private MessageMapper mapper;

    public XMPPFunction(MessageMapper mapper) {
        this.mapper = mapper;
    }

    @Override
    public void prepare(Map conf, TridentOperationContext context) {
        LOG.debug("Prepare: {}", conf);
        super.prepare(conf, context);
        this.to = (String) conf.get(XMPP_TO);
        ConnectionConfiguration config = new ConnectionConfiguration((String) conf.get(XMPP_SERVER));
        this.xmppConnection = new XMPPConnection(config);
        try {
            this.xmppConnection.connect();
            this.xmppConnection.login((String) conf.get(XMPP_USER), (String) conf.get(XMPP_PASSWORD));
        } catch (XMPPException e) {
            LOG.warn("Error initializing XMPP Channel", e);
        }
    }

    public void execute(TridentTuple tuple, TridentCollector collector) {
        Message msg = new Message(this.to, Type.normal);
        msg.setBody(this.mapper.toMessageBody(tuple));
        this.xmppConnection.sendPacket(msg);

    }

}
```

`XMPPFunction`类首先定义了几个字符串常量，用于从传递给`prepare()`方法的 Storm 配置中查找值，然后声明了实例变量，当函数激活时我们将填充这些变量。该类的构造函数接受一个`MessageMapper`实例作为参数，该实例将在`execute()`方法中用于格式化通知消息的正文。

在`prepare()`方法中，我们查找`XMPPConnection`类的配置参数（`server`、`username`、`to address`等），并打开连接。当部署使用此函数的拓扑时，`XMPP`客户端将发送出席数据包，其他用户如果在其花名册（好友列表）中有配置的用户，则会收到通知，指示该用户现在在线。

我们通知机制的最后一个必要部分是实现一个`MessageMapper`实例，将元组的内容格式化为人类可读的消息正文，如下所示的代码片段所示：

```scala
public class NotifyMessageMapper implements MessageMapper {

    public String toMessageBody(TridentTuple tuple) {
        StringBuilder sb = new StringBuilder();
        sb.append("On " + new Date(tuple.getLongByField("timestamp")) + " ");
        sb.append("the application \"" + tuple.getStringByField("logger") + "\" ");
        sb.append("changed alert state based on a threshold of " + tuple.getDoubleByField("threshold") + ".\n");
        sb.append("The last value was " + tuple.getDoubleByField("average") + "\n");
        sb.append("The last message was \"" + tuple.getStringByField("message") + "\"");
        return sb.toString();
    }
}
```

# 最终的拓扑结构

现在我们已经拥有构建日志分析拓扑所需的所有组件，如下所示：

```scala
public class LogAnalysisTopology {

    public static StormTopology buildTopology() {
        TridentTopology topology = new TridentTopology();

        StaticHosts kafkaHosts = KafkaConfig.StaticHosts.fromHostString(Arrays.asList(new String[] { "localhost" }), 1);
        TridentKafkaConfig spoutConf = new TridentKafkaConfig(kafkaHosts, "log-analysis");
        spoutConf.scheme = new StringScheme();
        spoutConf.forceStartOffsetTime(-1);
        OpaqueTridentKafkaSpout spout = new OpaqueTridentKafkaSpout(spoutConf);

        Stream spoutStream = topology.newStream("kafka-stream", spout);

        Fields jsonFields = new Fields("level", "timestamp", "message", "logger");
        Stream parsedStream = spoutStream.each(new Fields("str"), new JsonProjectFunction(jsonFields), jsonFields);

        // drop the unparsed JSON to reduce tuple size
        parsedStream = parsedStream.project(jsonFields);

        EWMA ewma = new EWMA().sliding(1.0, Time.MINUTES).withAlpha(EWMA.ONE_MINUTE_ALPHA);
        Stream averageStream = parsedStream.each(new Fields("timestamp"),
                new MovingAverageFunction(ewma, Time.MINUTES), new Fields("average"));

        ThresholdFilterFunction tff = new ThresholdFilterFunction(50D);
        Stream thresholdStream = averageStream.each(new Fields("average"), tff, new Fields("change", "threshold"));

        Stream filteredStream = thresholdStream.each(new Fields("change"), new BooleanFilter());

        filteredStream.each(filteredStream.getOutputFields(), new XMPPFunction(new NotifyMessageMapper()), new Fields());

        return topology.build();
    }

    public static void main(String[] args) throws Exception {
        Config conf = new Config();
        conf.put(XMPPFunction.XMPP_USER, "storm@budreau.local");
        conf.put(XMPPFunction.XMPP_PASSWORD, "storm");
        conf.put(XMPPFunction.XMPP_SERVER, "budreau.local");
        conf.put(XMPPFunction.XMPP_TO, "tgoetz@budreau.local");

        conf.setMaxSpoutPending(5);
        if (args.length == 0) {
            LocalCluster cluster = new LocalCluster();
            cluster.submitTopology("log-analysis", conf, buildTopology());

        } else {
            conf.setNumWorkers(3);
            StormSubmitter.submitTopology(args[0], conf, buildTopology());
        }
    }
}
```

然后，`buildTopology()`方法创建 Kafka spout 和我们的 Trident 函数和过滤器之间的所有流连接。然后，`main()`方法将拓扑提交到集群：如果拓扑在本地模式下运行，则提交到本地集群，如果在分布式模式下运行，则提交到远程集群。

我们首先配置 Kafka spout 以从我们的应用程序配置为写入日志事件的相同主题中读取。因为 Kafka 会持久化它接收到的所有消息，并且因为我们的应用程序可能已经运行了一段时间（因此记录了许多事件），我们告诉 spout 通过调用`forceStartOffsetTime()`方法并使用值`-1`来快进到 Kafka 队列的末尾。这将避免重放我们可能不感兴趣的所有旧消息。使用值`-2`将强制 spout 倒带到队列的开头，并使用毫秒级的特定日期将强制它倒带到特定时间点。如果没有调用`forceFromStartTime()`方法，spout 将尝试通过在 ZooKeeper 中查找偏移量来恢复上次离开的位置。

接下来，我们设置`JsonProjectFunction`类来解析从 Kafka 接收到的原始 JSON，并发出我们感兴趣的值。请记住，Trident 函数是可加的。这意味着我们的元组流，除了从 JSON 中提取的所有值之外，还将包含原始未解析的 JSON 字符串。由于我们不再需要这些数据，我们调用`Stream.project()`方法，提供我们想要保留的字段列表。`project()`方法对于将元组流减少到只包含基本字段非常有用，尤其是在重新分区具有大量数据的流时非常重要。

现在生成的流只包含我们需要的数据。我们使用一个滑动窗口为一分钟的`EWMA`实例，并配置`MovingAverageFunction`类以发出每分钟的当前速率。我们使用值`50.0`创建`ThresholdFunction`类，因此每当平均速率超过或低于每分钟 50 个事件时，我们都会收到通知。

最后，我们应用`BooleanFilter`类，并将生成的流连接到`XMPPFunction`类。

拓扑的`main()`方法只是用所需的属性填充一个`Config`对象，并提交拓扑。

# 运行日志分析拓扑

要运行分析拓扑，首先确保 ZooKeeper、Kafka 和 OpenFire 都已经按照本章前面概述的步骤启动并运行。然后，运行拓扑的`main()`方法。

当拓扑激活时，*storm* XMPP 用户将连接到 XMPP 服务器并触发存在事件。如果您使用 XMPP 客户端登录到同一服务器，并且在好友列表中有*storm*用户，您将看到它变为可用。如下面的屏幕截图所示：

![运行日志分析拓扑](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/storm-bp/img/8294OS_04_04.jpg)

接下来，运行`RogueApplication`类并等待一分钟。您应该收到即时消息通知，指示已超过阈值，随后将收到一条指示返回正常（低于阈值）的消息，如下面的屏幕截图所示：

![运行日志分析拓扑](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/storm-bp/img/8294OS_04_05.jpg)

# 摘要

在本章中，我们通过创建一个简单但功能强大的拓扑介绍了实时分析，该拓扑可以适应各种应用程序。我们构建的组件是通用的，可以轻松地在其他项目中重用和扩展。最后，我们介绍了一个真实世界的 spout 实现，可以用于多种目的。

虽然实时分析的主题非常广泛，而且诚然，我们在本章中只能触及表面，但我们鼓励您探索本书其他章节中提出的技术，并考虑如何将它们纳入您的分析工具箱中。

在下一章中，我们将通过构建一个应用程序，将 Storm 处理的数据持续写入图形数据库，向您介绍 Trident 的分布式状态机制。 


# 第五章：实时图分析

在本章中，我们将介绍使用 Storm 进行图分析，将数据持久化到图数据库并查询数据以发现关系。图数据库是将数据存储为顶点、边和属性的图结构的数据库，主要关注实体之间的关系。

随着 Twitter、Facebook 和 LinkedIn 等社交媒体网站的出现，社交图已经变得无处不在。分析人与人之间的关系、他们购买的产品、他们做出的推荐，甚至他们使用的词语，都可以被分析以揭示传统数据模型难以发现的模式。例如，当 LinkedIn 显示你与另一个人相隔四步时，基于你的网络，当 Twitter 提供关注的人的建议时，或者当亚马逊建议你可能感兴趣的产品时，它们都在利用他们对你的关系图的了解。图数据库就是为这种关系分析而设计的。

在本章中，我们将构建一个应用程序，摄取 Twitter firehose 的一个子集（Twitter 用户发布的所有推文的实时源），并根据每条消息的内容，在图数据库中创建节点（顶点）和关系（边），然后进行分析。在 Twitter 中最明显的图结构是基于用户之间的关注/被关注关系，但是我们可以通过超越这些显式关系来推断出额外的关系。通过查看消息的内容，我们可以使用消息元数据（标签、用户提及等）来识别例如提到相同主题或发布相关标签的用户。在本章中，我们将涵盖以下主题：

+   基本图数据库概念

+   TinkerPop 图形 API

+   图数据建模

+   与 Titan 分布式图数据库交互

+   编写由图数据库支持的 Trident 状态实现

# 用例

今天的社交媒体网站捕获了大量的信息。许多社交媒体服务，如 Twitter、Facebook 和 LinkedIn，主要基于人际关系：你关注谁，与谁交友，或者与谁有业务联系。除了明显和显式的关系之外，社交媒体互动还会产生一组持久的隐式连接，这些连接很容易被忽视。例如，对于 Twitter 来说，明显的关系包括关注的人和被关注的人。不太明显的关系是通过使用服务而可能无意中创建的连接。你在 Twitter 上直接给某人发过私信吗？如果是，那么你们之间就建立了连接。发过 URL 的推文吗？如果是，也是一种连接。在 Facebook 上点赞产品、服务或评论吗？连接。甚至在推文或帖子中使用特定词语或短语也可以被视为创建连接。通过使用那个词，你正在与它建立连接，并且通过反复使用它，你正在加强那个连接。

如果我们将数据视为“一切都是连接”，那么我们可以构建一个结构化的数据集并对其进行分析，以揭示更广泛的模式。如果 Bob 不认识 Alice，但 Bob 和 Alice 都发推文相同的 URL，我们可以从这个事实推断出一个连接。随着我们的数据集增长，其价值也将随着网络中连接的数量增加而增长（类似于梅特卡夫定律：[`en.wikipedia.org/wiki/Metcalfe's_law`](http://en.wikipedia.org/wiki/Metcalfe's_law)）。

当我们开始查询我们的数据集时，将很快意识到将数据存储在图数据库中的价值，因为我们可以从不断增长的连接网络中获取模式。我们进行的图分析适用于许多现实世界的用例，包括以下内容：

+   定向广告

+   推荐引擎

+   情感分析

# 架构

我们应用程序的架构相对简单。我们将创建一个 Twitter 客户端应用程序，读取 Twitter firehose 的子集，并将每条消息作为 JSON 数据结构写入 Kafka 队列。然后，我们将使用 Kafka spout 将数据输入到我们的 storm 拓扑中。最后，我们的 storm 拓扑将分析传入的消息并填充图数据库。

![架构](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/storm-bp/img/8294_05_01.jpg)

## Twitter 客户端

Twitter 提供了一个全面的 RESTful API，除了典型的请求-响应接口外，还提供支持长连接的流 API。Twitter4J Java 库 ([`twitter4j.org/`](http://twitter4j.org/)) 完全兼容最新版本的 Twitter API，并通过清晰的 Java API 处理所有底层细节（连接管理、OAuth 认证和 JSON 解析）。我们将使用 Twitter4J 连接到 Twitter 流 API。

## Kafka spout

在前一章中，我们开发了一个 Logback Appender 扩展，使我们能够轻松地将数据发布到 Kafka 队列，并且我们使用了 Nathan Marz 的 Kafka spout ([`github.com/nathanmarz/storm-contrib`](https://github.com/nathanmarz/storm-contrib)) 来消费 Storm 拓扑中的数据。虽然使用 Twitter4J 和 Twitter 流 API 编写 Storm spout 会很容易，但使用 Kafka 和 Kafka Spout 可以给我们提供事务性、精确一次语义和内置的容错性，否则我们将不得不自己实现。有关安装和运行 Kafka 的更多信息，请参阅第四章 *实时趋势分析*。

## Titan 分布式图数据库

Titan 是一个优化用于存储和查询图结构的分布式图数据库。像 Storm 和 Kafka 一样，Titan 数据库可以作为集群运行，并且可以水平扩展以容纳不断增加的数据量和用户负载。Titan 将其数据存储在三种可配置的存储后端之一：Apache Cassandra、Apache HBase 和 Oracle Berkely 数据库。存储后端的选择取决于 CAP 定理的哪两个属性是期望的。就数据库而言，CAP 定理规定分布式系统不能同时满足以下所有保证：

+   **一致性**：所有客户端看到当前数据，无论修改如何

+   **可用性**：系统在节点故障时仍然按预期运行

+   **分区容错性**：系统在网络或消息故障时仍然按预期运行

![Titan 分布式图数据库](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/storm-bp/img/8294_05_02.jpg)

对于我们的用例，一致性对我们的应用程序并不重要。我们更关心的是可伸缩性和容错性。如果我们看一下 CAP 定理三角形，在前面的图中显示，就会清楚地看到 Cassandra 是首选的存储后端。

# 图数据库简介

图是一个对象（顶点）的网络，它们之间有定向连接（边）。下图说明了一个简单的社交图，类似于在 Twitter 上找到的图：

![图数据库简介](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/storm-bp/img/8294_05_03.jpg)

在这个例子中，用户由顶点（节点）表示，关系表示为边（连接）。请注意，图中的边是有向的，允许额外的表达度。例如，这允许表达 Bob 和 Alice 互相关注，Alice 关注 Ted 但 Ted 不关注 Alice。如果没有有向边，这种关系将更难建模。

许多图数据库遵循属性图模型。属性图通过允许一组属性（键值对）分配给顶点和边来扩展基本图模型，如下图所示：

![图数据库简介](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/storm-bp/img/8294_05_04.jpg)

在图模型中将属性元数据与对象和关系关联起来，为图算法和查询提供了强大的支持元数据。例如，将**Follows**边缘添加**since**属性将使我们能够有效地查询在特定年份开始关注特定用户的所有用户。

与关系数据库相比，图数据库中的关系是显式的，而不是隐式的。图数据库中的关系是完整的数据结构，而不是暗示的连接（即外键）。在底层，图数据库的基础数据结构经过了大量优化，用于图遍历。虽然在关系数据库中完全可以对图进行建模，但通常比图中心模型效率低。在关系数据模型中，遍历图结构可能会涉及连接许多表，因此计算成本高昂。在图数据库中，遍历节点之间的链接是一个更自然的过程。

## 访问图 - TinkerPop 堆栈

TinkerPop 是一组专注于图技术的开源项目，如数据库访问、数据流和图遍历。Blueprints 是 TinkerPop 堆栈的基础，是一个通用的 Java API，用于与属性图进行交互，方式与 JDBC 提供关系数据库的通用接口类似。堆栈中的其他项目在该基础上添加了额外的功能，以便它们可以与实现 Blueprints API 的任何图数据库一起使用。

![访问图 - TinkerPop 堆栈](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/storm-bp/img/8294_05_05.jpg)

TinkerPop 堆栈的组件包括以下内容：

+   **Blueprints**：图 API Blueprints 是一组接口，提供对属性图数据模型的访问。可用于包括 Titan、Neo4J、MongoDB 等图数据库的实现。

+   **Pipes**：数据流处理管道是一个用于定义和连接各种数据操作的数据流框架。使用 Pipes 的基本操作与 Storm 中的数据处理非常相似。Pipes 数据流是**有向无环图**（**DAG**），就像 Storm 拓扑结构一样。

+   **Gremlin**：Gremlin 是一种图遍历语言。它是用于图遍历、查询、分析和操作的基于 Java 的**领域特定语言**（**DSL**）。Gremlin 分发版附带了一个基于 Groovy 的 shell，允许对 Blueprints 图进行交互式分析和修改。

+   **Frames**：Frames 是一个对象到图映射框架，类似于 ORM，但专为图设计。

+   **Furnace**：Furnace 项目旨在为 Blueprints 属性图提供许多常见图算法的实现。

+   **Rexster**：Rexster 是一个通过 REST API 和二进制协议公开 Blueprints 图的图服务器。

对于我们的目的，我们将专注于使用 Blueprints API 从 Storm 拓扑中填充图以及使用 Gremlin 进行图查询和分析。

## 使用 Blueprints API 操作图

Blueprints API 非常简单。以下代码清单使用 Blueprints API 创建了前面图表中所示的图：

```scala
    Graph graph = new TinkerGraph();

    Vertex bob = graph.addVertex(null);
    bob.setProperty("name", "Bob");
    bob.setProperty("born", 1980);
    bob.setProperty("state", "Vermont");

    Vertex alice = graph.addVertex(null);
    alice.setProperty("name", "Alice");
    alice.setProperty("born", 1965);
    alice.setProperty("state", "New York");

    Vertex ted = graph.addVertex(null);
    ted.setProperty("name", "Ted");
    ted.setProperty("born", 1970);
    ted.setProperty("state", "Texas");

    Edge bobToAlice = graph.addEdge(null, bob, alice, "Follows");
    bobToAlice.setProperty("since", 2012);

    Edge aliceToBob = graph.addEdge(null, alice, bob, "Follows");
    aliceToBob.setProperty("since", 2011);

    Edge aliceToTed = graph.addEdge(null, alice, ted, "Follows");
    aliceToTed.setProperty("since", 2010);

    graph.shutdown();
```

代码的第一行实例化了`com.tinkerpop.blueprints.Graph`接口的实现。在这种情况下，我们创建了一个内存中的玩具图（`com.tinkerpop.blueprints.impls.tg.TinkerGraph`）进行探索。稍后，我们将演示如何连接到分布式图数据库。

### 提示

您可能想知道为什么我们将`null`作为参数传递给`addVertex()`和`addEdge()`方法的第一个参数。这个参数实质上是对底层 Blueprints 实现提供对象的唯一 ID 的建议。将`null`作为 ID 传递只是让底层实现为新对象分配一个 ID。

## 使用 Gremlin shell 操作图

Gremlin 是建立在 Pipes 和 Blueprints API 之上的高级 Java API。除了 Java API 外，Gremlin 还包括基于 Groovy 的 API，并附带一个交互式 shell（或 REPL），允许您直接与 Blueprints 图交互。Gremlin shell 允许您创建和/或连接到 shell，并查询几乎任何 Blueprints 图。以下代码清单说明了执行 Gremlin shell 的过程：

```scala
./bin/gremlin.sh

         \,,,/
         (o o)
-----oOOo-(_)-oOOo-----
gremlin>
gremlin> g.V('name', 'Alice').outE('Follows').count()
==>2
```

除了查询图之外，使用 Gremlin 还可以轻松创建和操作图。以下代码清单包括将创建与前面图示相同的图的 Gremlin Groovy 代码，是 Java 代码的 Groovy 等价物：

```scala
g = new TinkerGraph()
bob = g.addVertex()
bob.name = "Bob"
bob.born = 1980
bob.state = "Vermont"
alice = g.addVertex()
alice.name = "Alice"
alice.born=1965
alice.state = "New York"
ted = g.addVertex()
ted.name = "Ted"
ted.born = 1970
ted.state = "Texas"
bobToAlice = g.addEdge(bob, alice, "Follows")
bobToAlice.since = 2012
aliceToBob = g.addEdge(alice, bob, "Follows")
aliceToBob.since = 2011
aliceToTed = g.addEdge(alice, ted, "Follows")
aliceToTed.since = 2010
```

一旦我们构建了一个拓扑图来填充图并准备好分析图数据，您将在本章后面学习如何使用 Gremlin API 和 DSL。

# 软件安装

我们正在构建的应用程序将利用 Apache Kafka 及其依赖项（Apache ZooKeeper）。如果您还没有这样做，请根据第二章中“ZooKeeper 安装”部分的说明设置 ZooKeeper 和 Kafka，以及第四章中“安装 Kafka”部分的说明，进行配置风暴集群和实时趋势分析。

## Titan 安装

要安装 Titan，请从 Titan 的下载页面（[`github.com/thinkaurelius/titan/wiki/Downloads`](https://github.com/thinkaurelius/titan/wiki/Downloads)）下载 Titan 0.3.x 完整包，并使用以下命令将其提取到方便的位置：

```scala
wget http://s3.thinkaurelius.com/downloads/titan/titan-all-0.3.2.zip
unzip titan-all-0.3.2.zip

```

Titan 的完整分发包包括运行 Titan 所需的一切支持的存储后端：Cassandra、HBase 和 BerkelyDB。如果您只对使用特定存储后端感兴趣，还有特定于后端的分发。

### 注意

Storm 和 Titan 都使用 Kryo（[`code.google.com/p/kryo/`](https://code.google.com/p/kryo/)）库进行 Java 对象序列化。在撰写本文时，Storm 和 Titan 使用不同版本的 Kryo 库，这将在两者同时使用时引起问题。

为了正确启用 Storm 和 Titan 之间的序列化，需要对 Titan 进行补丁，将 Titan 分发中的`kryo.jar`文件替换为 Storm 提供的`kryo.jar`文件：

```scala
cd titan-all-0.3.2/lib
rm kryo*.jar
cp $STORM_HOME/lib/kryo*.jar ./

```

此时，您可以通过运行 Gremlin shell 来测试安装：

```scala
$ cd titan
$ ./bin/gremlin.sh
 \,,,/
 (o o)
-----oOOo-(_)-oOOo-----
gremlin> g = GraphOfTheGodsFactory.create('/tmp/storm-blueprints')
==>titangraph[local:/tmp/storm-blueprints]
gremlin> g.V.map
==>{name=saturn, age=10000, type=titan}
==>{name=sky, type=location}
==>{name=sea, type=location}
==>{name=jupiter, age=5000, type=god}
==>{name=neptune, age=4500, type=god}
==>{name=hercules, age=30, type=demigod}
==>{name=alcmene, age=45, type=human}
==>{name=pluto, age=4000, type=god}
==>{name=nemean, type=monster}
==>{name=hydra, type=monster}
==>{name=cerberus, type=monster}
==>{name=tartarus, type=location}
gremlin>

```

`GraphOfTheGodsFactory`是 Titan 中包含的一个类，它将使用样本图创建和填充一个 Titan 数据库，该图表示罗马万神殿中角色和地点之间的关系。将目录路径传递给`create()`方法将返回一个 Blueprints 图实现，具体来说是一个使用 BerkelyDB 和 Elasticsearch 组合作为存储后端的`com.thinkaurelius.titan.graphdb.database.StandardTitanGraph`实例。由于 Gremlin shell 是一个 Groovy REPL，我们可以通过查看`g`变量的类轻松验证这一点：

```scala
gremlin> g.class.name
==>com.thinkaurelius.titan.graphdb.database.StandardTitanGraph

```

# 设置 Titan 以使用 Cassandra 存储后端

我们已经看到 Titan 支持不同的存储后端。探索所有三个选项超出了本章的范围（您可以在[`thinkaurelius.github.io/titan/`](http://thinkaurelius.github.io/titan/)了解有关 Titan 及其配置选项的更多信息），因此我们将专注于使用 Cassandra（[`cassandra.apache.org`](http://cassandra.apache.org)）存储后端。

## 安装 Cassandra

为了下载和运行 Cassandra，我们需要执行以下命令：

```scala
wget http://www.apache.org/dyn/closer.cgi?path=/cassandra/1.2.9/apache-cassandra-1.2.9-bin.tar.gz
tar -zxf ./cassandra-1.2.9.bin.tar.gz
cd cassandra-1.2.9
./bin/cassandra -f

```

Cassandra 分发的默认文件将创建一个在本地运行的单节点 Cassandra 数据库。如果在启动过程中出现错误，您可能需要通过编辑`${CASSANDRA_HOME}/conf/cassandra.yaml`和/或`${CASSANDRA_HOME}/conf/log4j-server.properties`文件来配置 Cassandra。最常见的问题通常与在`/var/lib/cassandra`（默认情况下，Cassandra 存储其数据的位置）和`/var/log/cassandra`（默认 Cassandra 日志位置）上缺乏文件写入权限有关。

## 使用 Cassandra 后端启动 Titan

要使用 Cassandra 运行 Titan，我们需要配置它连接到我们的 Cassandra 服务器。创建一个名为`storm-blueprints-cassandra.yaml`的新文件，内容如下：

```scala
storage.backend=cassandra
storage.hostname=localhost

```

正如你可能推测的那样，这配置 Titan 连接到本地运行的 Cassandra 实例。

### 注意

对于这个项目，我们可能不需要实际运行 Titan 服务器。由于我们使用的是 Cassandra，Storm 和 Gremlin 应该能够在没有任何问题的情况下共享后端。

有了 Titan 后端配置，我们准备创建我们的数据模型。

# 图数据模型

我们数据模型中的主要实体是 Twitter 用户。当发布一条推文时，Twitter 用户可以执行以下关系形成的操作：

+   使用一个单词

+   提及一个标签

+   提及另一个用户

+   提及 URL

+   转推另一个用户

![图数据模型](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/storm-bp/img/8294_05_06.jpg)

这个概念非常自然地映射到图模型中。在模型中，我们将有四种不同的实体类型（顶点）：

+   用户：这代表了一个 Twitter 用户账户

+   **单词**：这代表推文中包含的任何单词

+   **URL**：这代表推文中包含的任何 URL

+   **标签**：这代表推文中包含的任何标签

关系（边）将包括以下操作：

+   **提及用户**：使用此操作，用户提及另一个用户

+   **转推用户**：使用此操作，用户转推另一个用户的帖子

+   **关注用户**：使用此操作，用户关注另一个用户

+   **提及标签**：使用此操作，用户提及一个标签

+   **使用单词**：使用此操作，用户在推文中使用特定的单词

+   **提及 URL**：使用此操作，用户推文特定的 URL

用户顶点模拟了用户的 Twitter 账户信息，如下表所示：

| 用户 [顶点] |
| --- |
| 类型 | 字符串 | `"用户"` |
| 用户 | 字符串 | Twitter 用户名 |
| 名称 | 字符串 | Twitter 名称 |
| 位置 | 字符串 | Twitter 位置 |

URL 顶点提供了唯一 URL 的参考点：

| URL [顶点] |
| --- |
| 类型 | 字符串 | `"url"` |
| 值 | 字符串 | URL |

标签顶点允许我们存储唯一的标签：

| 标签 [顶点] |
| --- |
| 类型 | 字符串 | `"标签"` |
| 值 | 字符串 |   |

我们在单词顶点中存储单个单词：

| 单词 [顶点] |
| --- |
| 类型 | 字符串 | `"单词"` |
| 值 | 字符串 |   |

`提及用户`边用于用户对象之间的关系：

| 提及用户 [边] |
| --- |
| 用户 | 字符串 | 被提及用户的 ID |

`提及 URL`边表示用户和 URL 对象之间的关系：

| 提及 URL [边] |
| --- |
| 用户 | 字符串 | 被提及用户的 ID |

# 连接到 Twitter 流

为了连接到 Twitter API，我们必须首先生成一组 OAuth 令牌，这将使我们的应用程序能够与 Twitter 进行身份验证。这是通过创建一个与您的账户关联的 Twitter 应用程序，然后授权该应用程序访问您的账户来完成的。如果您还没有 Twitter 账户，请立即创建一个并登录。登录到 Twitter 后，按照以下步骤生成 OAuth 令牌：

1.  前往[`dev.twitter.com/apps/new`](https://dev.twitter.com/apps/new)，如果需要，请登录。

1.  为你的应用程序输入一个名称和描述。

1.  在我们的情况下，输入一个应用程序的 URL 是不重要的，因为我们不是在创建一个像移动应用程序那样会被分发的应用程序。在这里输入一个占位符 URL 是可以的。

1.  提交表单。下一页将显示您的应用程序的 OAuth 设置的详细信息。请注意**消费者密钥**和**消费者密钥**的值，因为我们需要这些值用于我们的应用程序。

1.  在页面底部，点击**创建我的访问令牌**按钮。这将生成一个 OAuth 访问令牌和一个密钥，允许应用程序代表您访问您的帐户。我们也需要这些值用于我们的应用程序。不要分享这些值，因为它们会允许其他人以您的身份进行认证。

## 设置 Twitter4J 客户端

Twitter4J 客户端被分解为许多不同的模块，可以根据我们的需求组合在一起。对于我们的目的，我们需要`core`模块，它提供了基本功能，如 HTTP 传输、OAuth 和对基本 Twitter API 的访问。我们还将使用`stream`模块来访问流 API。这些模块可以通过添加以下 Maven 依赖项包含在项目中：

```scala
    <dependency>
      <groupId>org.twitter4j</groupId>
      <artifactId>twitter4j-core</artifactId>
      <version>3.0.3</version>
    </dependency>
    <dependency>
      <groupId>org.twitter4j</groupId>
      <artifactId>twitter4j-stream</artifactId>
      <version>3.0.3</version>
    </dependency>
```

## OAuth 配置

默认情况下，Twitter4J 将在类路径中搜索`twitter4j.properties`文件，并从该文件加载 OAuth 令牌。这样做的最简单方法是在 Maven 项目的`resources`文件夹中创建该文件。将之前生成的令牌添加到这个文件中：

```scala
oauth.consumerKey=[your consumer key]
oauth.consumerSecret=[your consumer secret]
oauth.accessToken=[your access token]
oauth.accessTokenSecret=[your access token secret]
```

我们现在准备使用 Twitter4J 客户端连接到 Twitter 的流 API，实时消费推文。

### TwitterStreamConsumer 类

我们的 Twitter 客户端的目的很简单；它将执行以下功能：

+   连接到 Twitter 流 API

+   请求通过一组关键字过滤的推文流

+   根据状态消息创建一个 JSON 数据结构

+   将 JSON 数据写入 Kafka 以供 Kafka spout 消费

`TwitterStreamConsumer`类的`main()`方法创建一个`TwitterStream`对象，并注册`StatusListener`的一个实例作为监听器。`StatusListener`接口用作异步事件处理程序，每当发生与流相关的事件时就会通知它：

```scala
    public static void main(String[] args) throws TwitterException, IOException {

        StatusListener listener = new TwitterStatusListener();
        TwitterStream twitterStream = new TwitterStreamFactory().getInstance();
        twitterStream.addListener(listener);

        FilterQuery query = new FilterQuery().track(args);
        twitterStream.filter(query);

    }
```

注册监听器后，我们创建一个`FilterQuery`对象来根据一组关键字过滤流。为了方便起见，我们使用程序参数作为关键字列表，因此过滤条件可以很容易地从命令行更改。

### TwitterStatusListener 类

`TwitterStatusListener`类在我们的应用程序中承担了大部分的重活。`StatusListener`类定义了几个回调方法，用于在流的生命周期中可能发生的事件。我们主要关注`onStatus()`方法，因为这是每当有新推文到达时调用的方法。以下是`TwitterStatusListener`类的代码：

```scala
    public static class TwitterStatusListener implements StatusListener {
        public void onStatus(Status status) {

            JSONObject tweet = new JSONObject();
            tweet.put("user", status.getUser().getScreenName());
            tweet.put("name", status.getUser().getName());
            tweet.put("location", status.getUser().getLocation());
            tweet.put("text", status.getText());

            HashtagEntity[] hashTags = status.getHashtagEntities();
            System.out.println("# HASH TAGS #");
            JSONArray jsonHashTags = new JSONArray();
            for (HashtagEntity hashTag : hashTags) {
                System.out.println(hashTag.getText());
                jsonHashTags.add(hashTag.getText());
            }
            tweet.put("hashtags", jsonHashTags);

            System.out.println("@ USER MENTIONS @");
            UserMentionEntity[] mentions = status.getUserMentionEntities();
            JSONArray jsonMentions = new JSONArray();
            for (UserMentionEntity mention : mentions) {
                System.out.println(mention.getScreenName());
                jsonMentions.add(mention.getScreenName());
            }
            tweet.put("mentions", jsonMentions);

            URLEntity[] urls = status.getURLEntities();
            System.out.println("$ URLS $");
            JSONArray jsonUrls = new JSONArray();
            for (URLEntity url : urls) {
                System.out.println(url.getExpandedURL());
                jsonUrls.add(url.getExpandedURL());
            }
            tweet.put("urls", jsonUrls);

            if (status.isRetweet()) {
                JSONObject retweetUser = new JSONObject();
                retweetUser.put("user", status.getUser().getScreenName());
                retweetUser.put("name", status.getUser().getName());
                retweetUser.put("location", status.getUser().getLocation());
                tweet.put("retweetuser", retweetUser);
            }
            KAFKA_LOG.info(tweet.toJSONString());
        }

        public void onDeletionNotice(StatusDeletionNotice statusDeletionNotice) {
        }

        public void onTrackLimitationNotice(int numberOfLimitedStatuses) {

            System.out.println("Track Limitation Notice: " + numberOfLimitedStatuses);
        }

        public void onException(Exception ex) {
            ex.printStackTrace();
        }

        public void onScrubGeo(long arg0, long arg1) {
        }

        public void onStallWarning(StallWarning arg0) {

        }
    }
```

除了状态消息的原始文本之外，`Status`对象还包括方便的方法，用于访问所有相关的元数据，例如包含在推文中的用户信息、标签、URL 和用户提及。我们的`onStatus()`方法的大部分内容在最终通过 Logback Kafka Appender 将其记录到 Kafka 队列之前构建 JSON 结构。

# Twitter 图拓扑

Twitter 图拓扑将从 Kafka 队列中读取原始推文数据，解析出相关信息，然后在 Titan 图数据库中创建节点和关系。我们将使用 Trident 的事务机制实现一个 trident 状态实现，以便批量执行持久性操作，而不是为每个接收到的元组单独写入图数据库。

这种方法提供了几个好处。首先，对于支持事务的图数据库，比如 Titan，我们可以利用这个能力提供额外的一次性处理保证。其次，它允许我们执行批量写入，然后进行批量提交（如果支持）来处理整个批处理的元组，而不是对每个单独的元组进行写入提交操作。最后，通过使用通用的 Blueprints API，我们的 Trident 状态实现将在很大程度上对基础图数据库实现保持不可知，从而可以轻松地替换任何 Blueprints 图数据库后端。

![Twitter graph topology](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/storm-bp/img/8294_05_07.jpg)

拓扑的第一个组件包括我们在第七章中开发的`JSONProjectFunction`，*集成 Druid 进行金融分析*，它简单地解析原始 JSON 数据，提取我们感兴趣的信息。在这种情况下，我们主要关注消息的时间戳和 Twitter 状态消息的 JSON 表示。

## JSONProjectFunction 类

以下是一个解释`JSONProjectFunction`类的代码片段：

```scala
public class JsonProjectFunction extends BaseFunction {

    private Fields fields;

    public JsonProjectFunction(Fields fields) {
        this.fields = fields;
    }

    public void execute(TridentTuple tuple, TridentCollector collector) {
        String json = tuple.getString(0);
        Map<String, Object> map = (Map<String, Object>) JSONValue.parse(json);
        Values values = new Values();
        for (int i = 0; i < this.fields.size(); i++) {
            values.add(map.get(this.fields.get(i)));
        }
        collector.emit(values);
    }

}
```

# 实现 GraphState

拓扑的核心将是一个 Trident 状态实现，负责将 Trident 元组转换为图结构并将其持久化。回想一下，Trident 状态实现由三个组件组成：

+   `StateFactory`：`StateFactory`接口定义了 Trident 用来创建持久`State`对象的方法。

+   `State`：Trident `State`接口定义了在 Trident 批处理分区写入到后端存储之前和之后调用的`beginCommit()`和`commit()`方法。如果写入成功（即，所有元组都被处理而没有错误），Trident 将调用`commit()`方法。

+   `StateUpdater`：`StateUpdater`接口定义了`updateState()`方法，用于更新状态，假设有一批元组。Trident 将三个参数传递给这个方法：要更新的`State`对象，代表批处理的`TridentTuple`对象列表，以及可以用来可选地发出额外元组的`TridentCollector`实例作为状态更新的结果。

除了 Trident 提供的这些抽象，我们还将介绍两个额外的接口，支持任何 Blueprints 图数据库的使用（`GraphFactory`），并隔离任何特定用例的业务逻辑（`GraphTupleProcessor`）。在深入研究 Trident 状态实现之前，让我们快速看一下这些接口。

## GraphFactory

`GraphFactory`接口的合同很简单：给定一个代表风暴和拓扑配置的`Map`对象，返回一个`com.tinkerpop.blueprints.Graph`实现。

```scala
GraphFactory.java
public interface GraphFactory {
    public Graph makeGraph(Map conf);
}
```

这个接口允许我们通过提供`makeGraph()`方法的实现来简单地插入任何兼容 Blueprints 的图实现。稍后，我们将实现这个接口，返回到 Titan 图数据库的连接。

## GraphTupleProcessor

`GraphTupleProcessor`接口在 Trident 状态实现和任何特定用例的业务逻辑之间提供了一个抽象。

```scala
public interface GraphTupleProcessor {

    public void process(Graph g, TridentTuple tuple, TridentCollector collector);

}
```

给定一个图对象、`TridentTuple`和`TridentCollector`，操作图并可选择发出额外的元组是`GraphTupleProcessor`的工作。在本章后面，我们将实现这个接口，根据 Twitter 状态消息的内容填充图。

## GraphStateFactory

Trident 的`StateFactory`接口代表了状态实现的入口点。当使用状态组件的 Trident 拓扑（通过`Stream.partitionPersist()`和`Stream.persistentAggregate()`方法）初始化时，Storm 调用`StateFactory.makeState()`方法为每个批处理分区创建一个状态实例。批处理分区的数量由流的并行性确定。Storm 通过`numPartitions`和`partitionIndex`参数将这些信息传递给`makeState()`方法，允许状态实现在必要时执行特定于分区的逻辑。

在我们的用例中，我们不关心分区，所以`makeState()`方法只是使用`GraphFactory`实例来实例化一个用于构建`GraphState`实例的`Graph`实例。

```scala
GraphStateFactory.java
public class GraphStateFactory implements StateFactory {

    private GraphFactory factory;

    public GraphStateFactory(GraphFactory factory){
        this.factory = factory;
    }

    public State makeState(Map conf, IMetricsContext metrics, int partitionIndex, int numPartitions) {
        Graph graph = this.factory.makeGraph(conf);
        State state = new GraphState(graph);
        return state;
    }

}
```

## GraphState

我们的`GraphState`类提供了`State.beginCommit()`和`State.commit()`方法的实现，当批处理分区即将发生和成功完成时将被调用。在我们的情况下，我们重写`commit()`方法来检查内部的`Graph`对象是否支持事务，如果是，就调用`TransactionalGraph.commit()`方法来完成事务。

### 注意

如果在 Trident 批处理中出现故障并且批处理被重播，`State.beginCommit()`方法可能会被多次调用，而`State.commit()`方法只会在所有分区状态更新成功完成时被调用一次。

`GraphState`类的代码片段如下：

```scala
GraphState.java
public class GraphState implements State {

    private Graph graph;

    public GraphState(Graph graph){
        this.graph = graph;
    }

    @Override
    public void beginCommit(Long txid) {}

    @Override
    public void commit(Long txid) {
        if(this.graph instanceof TransactionalGraph){
            ((TransactionalGraph)this.graph).commit();
        }
    }

    public void update(List<TridentTuple> tuples, TridentCollector collector, GraphTupleProcessor processor){
        for(TridentTuple tuple : tuples){
            processor.process(this.graph, tuple, collector);
        }
    }

}
```

`GraphState.update()`方法在调用`State.beginCommit()`和`State.commit()`方法之间进行事务的核心处理。如果`update()`方法对所有批处理分区都成功，Trident 事务将完成，并且将调用`State.commit()`方法。

请注意，实际更新图状态的`update()`方法只是`GraphState`类的一个公共方法，而不是被覆盖。正如您将看到的，我们将有机会在我们的`StateUpdater`实现中直接调用这个方法。

## GraphUpdater

`GraphUpdater`类实现了 Storm 将调用的`updateState()`方法（在批处理失败/重播的情况下可能会重复调用）。`StateUpdater.updateState()`方法的第一个参数是我们用来调用`GraphState.update()`方法的 Java 泛型类型实例。

```scala
GraphUpdater.java
public class GraphUpdater extends BaseStateUpdater<GraphState> {

    private GraphTupleProcessor processor;

    public GraphUpdater(GraphTupleProcessor processor){
        this.processor = processor;
    }

    public void updateState(GraphState state, List<TridentTuple> tuples, TridentCollector collector) {
        state.update(tuples, collector, this.processor);
    }

}
```

# 实现 GraphFactory

我们之前定义的`GraphFactory`接口创建了一个 TinkerPop 图实现，其中`Map`对象表示了一个 Storm 配置。以下代码说明了如何创建由 Cassandra 支持的`TitanGraph`：

```scala
TitanGraphFactory.java
public class TitanGraphFactory implements GraphFactory {

    public static final String STORAGE_BACKEND = "titan.storage.backend";
    public static final String STORAGE_HOSTNAME = "titan.storage.hostname";

    public Graph makeGraph(Map conf) {
        Configuration graphConf = new BaseConfiguration();
        graphConf.setProperty("storage.backend", conf.get(STORAGE_BACKEND));
        graphConf.setProperty("storage.hostname", conf.get(STORAGE_HOSTNAME));

        return TitanFactory.open(graphConf);
    }
}
```

# 实现 GraphTupleProcessor

为了用从 Twitter 状态消息中获取的关系填充图数据库，我们需要实现`GraphTupleProcessor`接口。以下代码说明了解析 Twitter 状态消息的 JSON 对象并创建带有`"mentions"`关系的`"user"`和`"hashtag"`顶点。

```scala
TweetGraphTupleProcessor.java
public class TweetGraphTupleProcessor implements GraphTupleProcessor {
    @Override
    public void process(Graph g, TridentTuple tuple, TridentCollector collector) {
        Long timestamp = tuple.getLong(0);
        JSONObject json = (JSONObject)tuple.get(1);

        Vertex user = findOrCreateUser(g, (String)json.get("user"), (String)json.get("name"));

        JSONArray hashtags = (JSONArray)json.get("hashtags");
        for(int i = 0; i < hashtags.size(); i++){
            Vertex v = findOrCreateVertex(g, "hashtag", ((String)hashtags.get(i)).toLowerCase());
            createEdgeAtTime(g, user, v, "mentions", timestamp);
        }

    }
}
```

# 将所有内容放在一起 - TwitterGraphTopology 类

创建我们的最终拓扑包括以下步骤：

+   从 Kafka 喷嘴中消耗原始 JSON

+   提取和投影我们感兴趣的数据

+   构建并连接 Trident 的`GraphState`实现到我们的流

## TwitterGraphTopology 类

让我们详细看一下 TwitterGraphTopology 类。

```scala
public class TwitterGraphTopology {
    public static StormTopology buildTopology() {
        TridentTopology topology = new TridentTopology();

        StaticHosts kafkaHosts = StaticHosts.fromHostString(Arrays.asList(new String[] { "localhost" }), 1);
        TridentKafkaConfig spoutConf = new TridentKafkaConfig(kafkaHosts, "twitter-feed");
        spoutConf.scheme = new StringScheme();
        spoutConf.forceStartOffsetTime(-2);
        OpaqueTridentKafkaSpout spout = new OpaqueTridentKafkaSpout(spoutConf);

        Stream spoutStream = topology.newStream("kafka-stream", spout);

        Fields jsonFields = new Fields("timestamp", "message");
        Stream parsedStream = spoutStream.each(spoutStream.getOutputFields(), new JsonProjectFunction(jsonFields), jsonFields);
        parsedStream = parsedStream.project(jsonFields);
        // Trident State
        GraphFactory graphFactory = new TitanGraphFactory();
        GraphUpdater graphUpdater = new GraphUpdater(new TweetGraphTupleProcessor());

        StateFactory stateFactory = new GraphStateFactory(graphFactory);
        parsedStream.partitionPersist(stateFactory, parsedStream.getOutputFields(), graphUpdater, new Fields());

        return topology.build();
    }

    public static void main(String[] args) throws Exception {
        Config conf = new Config();
        conf.put(TitanGraphFactory.STORAGE_BACKEND, "cassandra");
        conf.put(TitanGraphFactory.STORAGE_HOSTNAME, "localhost");

        conf.setMaxSpoutPending(5);
        if (args.length == 0) {
            LocalCluster cluster = new LocalCluster();
            cluster.submitTopology("twitter-analysis", conf, buildTopology());

        } else {
            conf.setNumWorkers(3);
            StormSubmitter.submitTopology(args[0], conf, buildTopology());
        }
    }
}
```

要运行应用程序，首先执行`TwitterStreamConsumer`类，传入您想要用来查询 Twitter firehose 的关键字列表。例如，如果我们想要构建一个讨论大数据的用户图，我们可以使用`bigdata`和`hadoop`作为查询参数：

```scala
java TwitterStreamConsumer bigdata hadoop
```

`TwitterStreamConsumer`类将连接到 Twitter Streaming API 并开始将数据排队到 Kafka。运行`TwitterStreamConsumer`应用程序后，我们可以部署`TwitterGraphTopology`来开始填充 Titan 数据库。

让`TwitterStreamConsumer`和`TwitterGraphTopology`运行一段时间。根据查询使用的关键词的流行程度，数据集可能需要一些时间才能增长到一个有意义的水平。然后我们可以使用 Gremlin shell 连接到 Titan 来分析图查询中的数据。

# 使用 Gremlin 查询图形

要查询图形，我们需要启动 Gremlin shell 并创建连接到本地 Cassandra 后端的`TitanGraph`实例：

```scala
$ cd titan
$ ./bin/gremlin.sh
          \,,,/
         (o o)
-----oOOo-(_)-oOOo-----
gremlin> conf = new BaseConfiguration()
gremlin> conf.setProperty('storage.backend', 'cassandra')
gremlin> conf.setProperty('storage.hostname', 'localhost')
gremlin> g = TitanFactory.open(conf)
```

`g`变量现在包含一个我们可以使用来发出图遍历查询的`Graph`对象。以下是一些示例查询，您可以使用它们来开始：

+   要查找所有发推`#hadoop 标签`的用户，并显示他们这样做的次数，请使用以下代码：

```scala
gremlin> g.V('type', 'hashtag').has('value', 'hadoop').in.userid.groupCount.cap

```

+   要计算`#hadoop 标签`被发推文的次数，请使用以下代码：

```scala
gremlin> g.V.has('type', 'hashtag').has('value', 'java').inE.count()

```

Gremlin DSL 非常强大；覆盖完整 API 可能需要填满整整一章（甚至一本整书）。要进一步探索 Gremlin 语言，我们鼓励您探索以下在线文档：

+   官方 Gremlin Wiki 在[`github.com/tinkerpop/gremlin/wiki`](https://github.com/tinkerpop/gremlin/wiki)

+   GremlinDocs 参考指南在[`gremlindocs.com`](http://gremlindocs.com)

+   SQL2Gremlin（示例 SQL 查询及其 Gremlin 等效查询）在[`sql2gremlin.com`](http://sql2gremlin.com)

# 总结

在本章中，我们通过创建一个监视 Twitter firehose 子集并将信息持久化到 Titan 图数据库以供进一步分析的拓扑图，向您介绍了图数据库。我们还演示了通过使用早期章节的通用构建块（如 Logback Kafka appender）来重复使用通用组件。

虽然图数据库并非适用于每种用例，但它们代表了您多语言持久性工具库中的强大武器。多语言持久性是一个经常用来描述涉及多种数据存储类型（如关系型、键值、图形、文档等）的软件架构的术语。多语言持久性是关于为正确的工作选择正确的数据库。在本章中，我们向您介绍了图形数据模型，并希望激发您探索图形可能是支持特定用例的最佳数据模型的情况。在本书的后面，我们将创建一个 Storm 应用程序，将数据持久化到多个数据存储中，每个存储都有特定的目的。


# 第六章：人工智能

在之前的章节中，我们看到了一种模式，它将使用 Storm 进行实时分析与使用 Hadoop 进行批处理相结合。在本章中，我们将朝着另一个方向前进。我们将把 Storm 纳入一个操作系统中，这个系统必须实时响应最终用户的查询。

Storm 的典型应用集中在永无止境的数据流上。数据通常被排队，并由持久拓扑尽可能快地处理。系统包括一个队列，以容纳不同数量的负载。在轻负载时，队列为空。在重负载时，队列将保留数据以供以后处理。

即使是未经训练的眼睛也会认识到这样的系统并不能提供真正的实时数据处理。Storm 监视元组超时，但它专注于 spout 发出数据后元组的处理时间。

为了更完全地支持实时场景，必须从接收数据到响应交付的时间监控超时和服务级别协议（SLA）。如今，请求通常通过基于 HTTP 的 API 接收，并且响应时间 SLA 必须在亚秒级别。

HTTP 是一种同步协议。它经常引入一个像队列这样的异步机制，使系统变得复杂，并引入额外的延迟。因此，当通过 HTTP 公开功能和函数时，我们通常更喜欢与涉及的组件进行同步集成。

在本章中，我们将探讨 Storm 在暴露 Web 服务 API 的架构中的位置。具体来说，我们将构建世界上最好的井字游戏人工智能（AI）系统。我们的系统将包括同步和异步子系统。系统的异步部分将不断工作，探索游戏状态的最佳选项。同步组件公开了一个 Web 服务接口，根据游戏状态返回可能的最佳移动。

本章涵盖以下主题：

+   Storm 中的递归

+   分布式远程过程调用（DRPC）

+   分布式读写前范式

# 为我们的用例设计

人工智能世界的“hello world”是井字游戏。遵循传统，我们也将以此作为我们的主题游戏，尽管架构和方法远远超出了这个简单的例子（例如，全球热核战争；对于其他用例，请参考约翰·巴德姆的《战争游戏》）。

井字游戏是一个 X 和 O 的两人游戏。棋盘是一个 3 x 3 的网格。一个玩家有符号 O，另一个有符号 X，并且轮流进行。在一个回合中，玩家将他们的符号放在网格中的任何空单元格中。如果通过放置他们的符号，完成了三个连续符号的水平、垂直或对角线，那个玩家就赢了。如果所有单元格都填满了而没有形成三个连线，那么游戏就是平局。

为交替轮次的游戏开发人工智能程序的常见方法是递归地探索游戏树，寻找对当前玩家评估最佳的游戏状态（或对对手更糟糕的状态）。游戏树是一个节点为游戏状态的树结构。节点的直接子节点是通过从该节点的游戏状态进行合法移动而可以达到的游戏状态。

井字游戏的一个示例游戏树如下图所示：

![为我们的用例设计](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/storm-bp/img/8294OS_06_01.jpg)

遍历游戏树寻找最佳移动的最简单算法是极小化极大化（Minimax）算法。该算法对每个棋盘进行递归评分，并返回找到的最佳分数。对于这个算法，我们假设对手的好分数对于当前玩家来说是坏分数。因此，该算法实际上在最大化和最小化当前棋盘的分数之间交替。极小化极大化算法可以用以下伪代码总结：

```scala
miniMax (board, depth, maximizing)
   if (depth <= 0) 
      return score (board)
   else
      children = move(board)
      if (maximizing)
         bestValue = -∞
      for (child : children)
         value = miniMax (child, depth-1, false)
         if (value > bestValue)
            bestValue = value
         end
end
return bestValue
      else // minimizing
         bestValue = ∞
      for (child : children)
         value = miniMax (child, depth-1, false)
         if (value < bestValue)
            bestValue = value
         end
end
return bestValue
end
end
```

客户端使用游戏状态、深度和布尔变量调用算法，该变量指示算法是否应该寻求最大化或最小化得分。在我们的用例中，游戏状态由棋盘完全封装，棋盘是一个部分填充有 X 和 O 的 3 x 3 网格。

该算法是递归的。代码的前几行是基本情况。这确保了算法不会无休止地递归。这取决于深度变量。在交替轮次的游戏中，深度表示算法应该探索多少轮。

在我们的用例中，风暴拓扑结构不需要跟踪深度。我们将让风暴拓扑结构无休止地探索（或直到从“移动”方法返回没有新棋盘为止）。

通常，每个玩家都会被分配一定的时间，并且必须在规定的时间内进行移动。由于我们更可能有焦躁不安的人类玩家与人工智能竞争，让我们假设系统需要在 200 毫秒内做出响应。

在算法检查基本情况之后，它调用“move（）”方法，该方法返回所有可能移动的棋盘。然后算法循环遍历所有可能的子棋盘。如果最大化，算法找到导致最高得分的子棋盘。如果最小化，算法找到导致最低得分的棋盘。

### 提示

Negamax 算法通过交替得分的符号更简洁地实现了相同的目标。此外，在现实场景中，我们可能会应用 Alpha-Beta 剪枝，该剪枝试图修剪探索的树的分支。算法只考虑落在阈值内的分支。在我们的用例中，这是不必要的，因为搜索空间小到足以完全探索。

在我们简单的用例中，可以枚举整个游戏树。在更复杂的游戏中，比如国际象棋，游戏树是无法枚举的。在极端情况下，比如围棋，专家们已经计算出合法棋盘的数量超过 2 x 10170。

Minimax 算法的目标是遍历游戏树并为每个节点分配得分。在我们的风暴拓扑结构中，对于任何非叶节点的得分只是其后代的最大值（或最小值）。对于叶节点，我们必须将游戏状态解释为相应的得分。在我们简单的用例中，有三种可能的结果：我们赢了，对手赢了，或者游戏是平局。

然而，在我们的同步系统中，我们很可能在到达叶节点之前就用完了时间。在这种情况下，我们需要根据当前棋盘状态计算得分。评分启发式通常是开发 AI 应用程序最困难的部分。

对于我们简单的用例，我们将通过考虑网格中的线来计算任何棋盘的得分。有八条线需要考虑：三条水平线，三条垂直线和两条对角线。每条线根据以下表格对得分有贡献：

| 状态 | 得分 |
| --- | --- |
| --- | --- |
| 当前玩家三排一个 | +1000 |
| 当前玩家两排一个 | +10 |
| 当前玩家一排一个 | +1 |
| 对手三排一个 | -1000 |
| 对手两排一个 | -10 |
| 对手一排一个 | -1 |

前面的表格仅在线中剩余的单元格为空时适用。虽然有改进前面的启发式，但对于这个例子来说已经足够了。而且，由于我们希望风暴能够持续处理我们的游戏树，我们希望不要太依赖启发式。相反，我们将直接依赖叶子得分的最小值（或最大值），这将始终是赢（+1000），输（-1000）或平局（0）。

最后，有了方法、算法和评分函数，我们就能继续进行架构和设计了。

# 建立架构

审查前面的算法，有许多有趣的设计和架构考虑，特别是考虑到 Storm 当前的状态。该算法需要递归。我们还需要一种同步处理请求的方法。Storm 中的递归是一个不断发展的话题，虽然 Storm 提供了一种与拓扑同步交互的方法，但结合对递归的需求，这带来了一些独特和有趣的挑战。

## 审查设计挑战

最初，原生 Storm 提供了一种服务异步过程调用的机制。这个功能就是**分布式远程过程调用**（**DRPC**）。DRPC 允许客户端通过直接向拓扑提交数据来向拓扑发出请求。使用 DRPC，一个简单的 RPC 客户端充当 spout。

随着 Trident 的出现，DRPC 在原生 Storm 中已经被弃用，现在只在 Trident 中得到官方支持。

尽管已经进行了一些探索性工作，探讨了递归/非线性 DRPC，这正是我们在这里需要的，但这并不是一个主流功能（[`groups.google.com/forum/#!topic/storm-user/hk3opTiv3Kc`](https://groups.google.com/forum/#!topic/storm-user/hk3opTiv3Kc)）。

此外，这项工作将依赖于 Storm 中已弃用的类。因此，我们需要找到替代手段来创建一个递归结构，而不依赖于 Storm。

一旦我们找到一种构造来实现递归，我们需要能够同步调用相同的功能。寻求利用 Storm 提供的功能意味着将 DRPC 调用纳入我们的架构中。

## 实现递归

如果我们将我们的算法直接映射到 Storm 构造中，我们会期望一种允许流将数据反馈到自身的方法。我们可以想象一个类似以下逻辑数据流的拓扑：

![实现递归](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/storm-bp/img/8294OS_06_02.jpg)

`BoardSpout`函数在`currentBoard`字段中发出一个棋盘（例如，3 x 3 数组），并使用名为`parents`的第二个字段来存储所有父节点。`parents`字段最初将为空。

`isLeaf`过滤器决定这是否是一个结束状态（例如，胜利、失败或平局）。如果`currentBoard`字段不是一个结束状态，`GenerateBoards`函数会发出所有新的棋盘，用子棋盘替换`currentBoard`字段的值，并将`currentBoard`字段添加到`parents`字段中的节点列表中。`GenerateBoards`函数可以通过 spout 将元组发回，也可以直接进入`isLeaf`过滤器，绕过 spout。

如果`isLeaf`过滤器确定这是一个结束状态，我们需要对`currentBoard`字段进行评分，然后更新所有父节点以反映新的分数。`ScoreFunction`计算棋盘的得分，并将其持久化到`GameTree State`中。

为了更新父节点，我们遍历每个父节点，并查询该节点的当前最大值（或最小值）。如果子节点的得分是新的最大值（或最小值），那么我们将持久化新值。

### 提示

这只是一个逻辑数据流。构建这样的拓扑不仅是不可能的，而且基于以下部分描述的原因也不建议这样做。

您已经可以看到，这个数据流并不像我们的伪代码那样直接。在 Trident 和 Storm 中有一些约束，这些约束迫使我们引入额外的复杂性，而且并非所有在数据流中表达的操作都在 Storm/Trident 中可用。让我们更仔细地检查这个数据流。

### 访问函数的返回值

首先，注意到我们被迫维护自己的调用堆栈，以父节点列表的形式，因为 Storm 和 Trident 没有任何机制可以访问拓扑中下游函数的结果。在经典递归中，递归方法调用的结果立即在函数内部可用，并且可以并入该方法的结果。因此，前面的数据流类似于对问题的更迭方法。

### 不可变元组字段值

其次，在前面的数据流中，我们调用了一个神奇的能力来替换字段的值。我们在`GenerateBoards`函数中进行了递归发出。用新的棋盘替换`currentBoard`字段是不可能的。此外，将`currentBoard`字段添加到父节点列表中将需要更新`parents`字段的值。在 Trident 中，元组是不可变的。

### 前期字段声明

为了解决元组的不可变性，我们可以始终向元组添加额外的字段——每个递归层都要添加一个字段——但 Trident 要求在部署之前声明所有字段。

### 递归中的元组确认

在考虑这个数据流中的元组确认时，我们还有其他问题。在什么时候确认触发处理的初始元组？从逻辑数据流的角度来看，直到该节点的所有子节点都被考虑并且游戏树状态反映了这些分数之前，初始元组都不应该被确认。然而，计算任何非平凡游戏的大部分游戏树子部分的处理时间很可能会超过任何元组超时。

### 输出到多个流

拓扑的另一个问题是从`isLeaf`过滤器发出的多条路径。目前，在 Trident 中没有办法在多个流中输出。增强功能可以在[`issues.apache.org/jira/browse/STORM-68`](https://issues.apache.org/jira/browse/STORM-68)找到。

正如我们将看到的，您可以通过在两个流上分叉并将决策作为过滤器影响这一点。

### 写入前读取

最后，因为我们无法访问返回值，更新父节点分数需要一个读取前写入的范式。这在任何分布式系统中都是一种反模式。以下序列图演示了在缺乏锁定机制的情况下读取前写入构造中出现的问题：

![写入前读取](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/storm-bp/img/8294OS_06_03.jpg)

在上图中，有两个独立操作的线程。在我们的用例中，当多个子节点同时完成并尝试同时解析父节点的最大分数时，就会发生这种情况。

第一个线程正在解析子节点的分数为**7**。第二个线程正在解析子节点的分数为**15**。它们都在解析同一个节点。在过程结束时，新的最大值应该是**15**，但由于线程之间没有协调，最大分数变成了**7**。

第一个线程读取节点的当前最大分数，返回**5**。然后，第二个线程从状态中读取，也收到**5**。两个线程将当前最大值与它们各自的子节点分数进行比较，并用新值更新最大值。由于第二个线程的更新发生在第一个之后，结果是父节点的最大值不正确。

在下一节中，我们将看到如何正确解决前面的约束，以产生一个功能性的系统。

## 解决挑战

为了适应前面部分概述的约束，我们将拓扑分成两部分。第一个拓扑将执行实际的递归。第二个拓扑将解析分数。这在下图中显示：

![解决挑战](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/storm-bp/img/8294OS_06_04.jpg)

系统分为两个拓扑：“递归拓扑”和“评分拓扑”。递归拓扑尝试枚举系统中的所有棋盘。评分拓扑尝试对递归拓扑枚举的所有棋盘进行评分。

为了影响递归，我们在系统中引入了两个队列。第一个队列，“工作队列”，包含我们需要访问的节点列表。递归拓扑通过“工作喷口”从该队列中获取。如果节点不是叶子节点，拓扑将排队子节点的棋盘。工作队列上的消息格式如下：

```scala
(board, parents[])
```

每个`board`都是一个 3x3 的数组。`parents`数组包含所有父棋盘。

如果节点是叶子节点，棋盘将使用相同的消息格式排队到“评分队列”上。评分拓扑通过“评分喷口”从评分队列中读取。评分函数对节点进行评分。棋盘必然是叶子节点，因为这是排队进行评分的唯一类型的节点。然后，评分函数对当前节点和每个父节点发出一个元组。

然后我们需要更新状态。由于我们之前概述的竞争条件，查询和写入范式被封装在一个函数中。在接下来的设计中，我们将演示如何适应读写之前引入的竞争条件。

然而，在我们继续设计之前，请注意，因为我们引入了队列，我们清楚地划定了可以确认元组的线路。在第一个拓扑中，当以下情况之一为真时，元组被确认：

+   拓扑已经枚举并排队了节点的后代

+   拓扑已经将节点排队进行评分

在第二个拓扑中，当当前棋盘及其所有父节点都已更新以反映叶子节点中的值时，元组被确认。

还要注意的是，在处理过程中我们不需要引入新的字段或改变现有字段。第一个拓扑中使用的唯一字段是`board`和`parents`。第二个拓扑相同，但添加了一个额外的字段来捕获分数。

还要注意，我们分叉了从工作喷口出来的流。这是为了适应我们不能从单个函数中发出多个流的事实。相反，`GenerateBoards`和`IsEndGame`都必须确定游戏是否已经结束并做出相应反应。在`GenerateBoards`中，元组被过滤以避免无限递归。在`IsEndGame`中，元组被传递以进行评分。当函数能够发出到不同的流时，我们将能够将此函数合并为一个单一的“决策”过滤器，选择元组应该继续的流。

# 实施架构

现在让我们深入了解实现的细节。为了举例说明，以下代码假设拓扑在本地运行。我们使用内存队列而不是持久队列，并使用哈希映射作为我们的存储机制。在真正的生产实现中，我们很可能会使用诸如 Kafka 之类的持久队列系统和诸如 Cassandra 之类的分布式存储机制。

## 数据模型

我们将深入研究每个拓扑，但首先，让我们看看数据模型。为了简化，我们将游戏逻辑和数据模型封装到两个类中：`Board`和`GameState`。

以下是`Board`类的列表：

```scala
public class Board implements Serializable {
public static final String EMPTY = ' ';
   public String[][] board = { { EMPTY, EMPTY, EMPTY },
{ EMPTY, EMPTY, EMPTY }, { EMPTY, EMPTY, EMPTY } };

public List<Board> nextBoards(String player) {
        List<Board> boards = new ArrayList<Board>();
        for (int i = 0; i < 3; i++) {
            for (int j = 0; j < 3; j++) {
                if (board[i][j].equals(EMPTY)) {
                    Board newBoard = this.clone();
                    newBoard.board[i][j] = player;
                    boards.add(newBoard);
                }
            }
        }
        return boards;
    }

    public boolean isEndState() {
        return (nextBoards('X').size() == 0 
|| Math.abs(score('X')) > 1000);
    }

    public int score(String player){
        return scoreLines(player) – 
            scoreLines(Player.next(player));
    }

    public int scoreLines(String player) {
        int score = 0;
        // Columns
        score += scoreLine(board[0][0], board[1][0], board[2][0], player);
        score += scoreLine(board[0][1], board[1][1], board[2][1], player);
        score += scoreLine(board[0][2], board[1][2], board[2][2], player);

        // Rows
        score += scoreLine(board[0][0], board[0][1], board[0][2], player);
        score += scoreLine(board[1][0], board[1][1], board[1][2], player);
        score += scoreLine(board[2][0], board[2][1], board[2][2], player);

       // Diagonals
        score += scoreLine(board[0][0], board[1][1], board[2][2], player);
        score += scoreLine(board[2][0], board[1][1], board[0][2], player);
        return score;
    }

    public int scoreLine(String pos1, String pos2, String pos3, String player) {
        int score = 0;
        if (pos1.equals(player) && pos2.equals(player) && pos3.equals(player)) {
            score = 10000;
        } else if ((pos1.equals(player) && pos2.equals(player) && pos3.equals(EMPTY)) ||
                (pos1.equals(EMPTY) && pos2.equals(player) && pos3.equals(player)) ||
                (pos1.equals(player) && pos2.equals(EMPTY) && pos3.equals(player))) {
            score = 100;
        } else {
            if (pos1.equals(player) && pos2.equals(EMPTY) && pos3.equals(EMPTY) ||
                    pos1.equals(EMPTY) && pos2.equals(player) && pos3.equals(EMPTY) ||
                    pos1.equals(EMPTY) && pos2.equals(EMPTY) && pos3.equals(player)){
                score = 10;
            }
        }
        return score;
    }
...
    public String toKey() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 3; i++) {
            for (int j = 0; j < 3; j++) {
                sb.append(board[i][j]);
            }
        }
        return sb.toString();
    }
}
```

`Board`类提供了三个主要函数。`Board`类封装了棋盘本身，作为成员变量以多维字符串数组的形式存在。然后它提供将生成子棋盘的函数（例如，`nextBoards()`），确定游戏是否已经结束（例如，`isEndState()`），最后，提供一个计算棋盘得分的方法，当提供了一个玩家时（例如，`nextBoards(player)`及其支持方法）。

还要注意`Board`类提供了一个`toKey()`方法。这个键唯一地表示了棋盘，这是我们在访问我们的持久性机制时将使用的唯一标识符。在这种情况下，唯一标识符只是棋盘网格中的值的串联。

为了完全表示游戏状态，我们还需要知道当前轮到哪个玩家。因此，我们有一个封装了棋盘和当前玩家的高级对象。这是`GameState`对象，其清单如下所示：

```scala
public class GameState implements Serializable {
private Board board;
    private List<Board> history;
    private String player;

...

    public String toString(){
        StringBuilder sb = new StringBuilder('GAME [');
        sb.append(board.toKey()).append(']');
        sb.append(': player(').append(player).append(')\n');
        sb.append('   history [');
        for (Board b : history){
            sb.append(b.toKey()).append(',');
        }
        sb.append(']');
        return sb.toString();
    }
}
```

在这个类中没有什么特别令人惊讶的，除了`history`变量。这个成员变量跟踪了这条游戏树路径上的所有先前的棋盘状态。这是更新游戏树以获得叶节点得分所需的面包屑路径。

最后，我们用`Player`类表示游戏中的玩家，如下所示：

```scala
public class Player {
    public static String next(String current){
        if (current.equals('X')) return 'O';
        else return 'X';
    }
}
```

## 检查递归拓扑

有了之前概述的数据模型，我们可以创建一个递归下棋树的拓扑结构。在我们的实现中，这是`RecursiveTopology`类。拓扑的代码如下所示：

```scala
public class RecursiveTopology {

    public static StormTopology buildTopology() {
        LOG.info('Building topology.');
        TridentTopology topology = new TridentTopology();

        // Work Queue / Spout
        LocalQueueEmitter<GameState> workSpoutEmitter = 
new LocalQueueEmitter<GameState>('WorkQueue');
        LocalQueueSpout<GameState> workSpout = 
new LocalQueueSpout<GameState>(workSpoutEmitter);
        GameState initialState = 
new GameState(new Board(),
new ArrayList<Board>(), 'X');
        workSpoutEmitter.enqueue(initialState);

        // Scoring Queue / Spout
        LocalQueueEmitter<GameState> scoringSpoutEmitter = 
new LocalQueueEmitter<GameState>('ScoringQueue');

        Stream inputStream = 
topology.newStream('gamestate', workSpout);

        inputStream.each(new Fields('gamestate'),
new isEndGame())
                .each(new Fields('gamestate'),
                    new LocalQueuerFunction<GameState>(scoringSpoutEmitter),  new Fields(''));

        inputStream.each(new Fields('gamestate'),
new GenerateBoards(),
new Fields('children'))
            .each(new Fields('children'),
                    new LocalQueuerFunction<GameState>(workSpoutEmitter),
                    new Fields());

        return topology.build();
    }
...
}
```

第一部分配置了工作和评分的内存队列。输入流是从一个单个 spout 配置的，该 spout 从工作队列中工作。这个队列被初始化为初始游戏状态。

然后将流分叉。叉的第一个叉齿仅用于终局棋盘，然后将其传递到评分队列。叉的第二个叉齿生成新的棋盘并将后代排队。

## 队列交互

对于这个示例实现，我们使用了内存队列。在真实的生产系统中，我们会依赖 Kafka spout。`LocalQueueEmitter`类的清单如下所示。请注意，队列是`BlockingQueue`实例的实例，位于一个映射内，将队列名称链接到`BlockingQueue`实例。这是一个方便的类，用于测试使用单个队列作为输入和输出的拓扑（即递归拓扑）：

```scala
public class LocalQueueEmitter<T> implements Emitter<Long>, Serializable {
public static final int MAX_BATCH_SIZE=1000;
public static AtomicInteger successfulTransactions = 
new AtomicInteger(0);
    private static Map<String, BlockingQueue<Object>> queues =
 new HashMap<String, BlockingQueue<Object>>();
private static final Logger LOG = 
LoggerFactory.getLogger(LocalQueueEmitter.class);
    private String queueName;

    public LocalQueueEmitter(String queueName) {
        queues.put(queueName, new LinkedBlockingQueue<Object>());
        this.queueName = queueName;
    }

    @Override
    public void emitBatch(TransactionAttempt tx,
 Long coordinatorMeta, TridentCollector collector) {
        int size=0;
        LOG.debug('Getting batch for [' +
 tx.getTransactionId() + ']');
        while (getQueue().peek() != null && 
size <= MAX_BATCH_SIZE) {
            List<Object> values = new ArrayList<Object>();
            try {
                LOG.debug('Waiting on work from [' +
 this.queueName + ']:[' + 
getQueue().size() + ']');
                values.add(getQueue().take());
                LOG.debug('Got work from [' + 
this.queueName + ']:[' + 
getQueue().size() + ']');
            } catch (InterruptedException ex) {
                // do something smart
            }
            collector.emit(values);
            size++;
        }
        LOG.info('Emitted [' + size + '] elements in [' + 
            tx.getTransactionId() + '], [' + getQueue().size()
+ '] remain in queue.');
    }
...
    public void enqueue(T work) {
        LOG.debug('Adding work to [' + this.queueName +
 ']:[' + getQueue().size() + ']');
        if (getQueue().size() % 1000 == 0)
            LOG.info('[' + this.queueName + '] size = [' + 
			getQueue().size() + '].');
        this.getQueue().add(work);
    }

    public BlockingQueue<Object> getQueue() {
        return LocalQueueEmitter.queues.get(this.queueName);
    }
...
}
```

该类中的主要方法是`Emitter`接口的`emitBatch`实现。这只是在队列中有数据且未达到最大批量大小时读取。

还要注意，该类提供了一个`enqueue()`方法。`enqueue()`方法由我们的`LocalQueueFunction`类用于完成递归。`LocalQueueFunction`类的清单如下所示：

```scala
public class LocalQueuerFunction<T>  extends BaseFunction {
    private static final long serialVersionUID = 1L;
    LocalQueueEmitter<T> emitter;

    public LocalQueuerFunction(LocalQueueEmitter<T> emitter){
        this.emitter = emitter;
    }

    @SuppressWarnings('unchecked')
    @Override
    public void execute(TridentTuple tuple, TridentCollector collector) {
        T object = (T) tuple.get(0);
        Log.debug('Queueing [' + object + ']');
        this.emitter.enqueue(object);
    }
}
```

请注意，函数实际上是使用 spout 使用的`emitter`函数实例化的。这允许函数直接将数据排入 spout。同样，这种构造在开发递归拓扑时很有用，但是真实的生产拓扑很可能会使用持久存储。没有持久存储，存在数据丢失的可能性，因为元组在处理（递归）完成之前就被确认。

## 函数和过滤器

现在，我们将注意力转向与此拓扑特定的函数和过滤器。首先是一个简单的过滤器，用于过滤出终局棋盘。`IsEndGame`过滤器的代码如下所示：

```scala
public class IsEndGame extends BaseFilter {
...
    @Override
    public boolean isKeep(TridentTuple tuple) {
        GameState gameState = (GameState) tuple.get(0);
        boolean keep = (gameState.getBoard().isEndState());
        if (keep){
            LOG.debug('END GAME [' + gameState + ']');
        }
        return keep;
    }
}
```

请注意，如果 Trident 支持从单个函数向不同流发出元组，则此类是不必要的。在以下`IsEndGame`函数的清单中，它执行相同的检查/过滤功能：

```scala
public class GenerateBoards extends BaseFunction {

    @Override
    public void execute(TridentTuple tuple,
TridentCollector collector) {
        GameState gameState = (GameState) tuple.get(0);
        Board currentBoard = gameState.getBoard();
        List<Board> history = new ArrayList<Board>();
        history.addAll(gameState.getHistory());
        history.add(currentBoard);

        if (!currentBoard.isEndState()) {
            String nextPlayer = 
			Player.next(gameState.getPlayer());
            List<Board> boards = 
			gameState.getBoard().nextBoards(nextPlayer);
            Log.debug('Generated [' + boards.size() + 
'] children boards for [' + gameState.toString() +
']');
            for (Board b : boards) {
                GameState newGameState = 
new GameState(b, history, nextPlayer);
                List<Object> values = new ArrayList<Object>();
                values.add(newGameState);
                collector.emit(values);
            }
        } else {
            Log.debug('End game found! [' + currentBoard + ']');
        }
    }
}
```

该函数将当前棋盘添加到历史列表中，然后排队一个新的`GameState`对象，带有子棋盘位置。

### 提示

或者，我们可以将`IsEndGame`实现为一个函数，添加另一个字段来捕获结果；然而，使用这个作为一个例子来激励函数内部具有多个流能力更有建设性。

以下是递归拓扑的示例输出：

```scala
2013-12-30 21:53:40,940-0500 | INFO [Thread-28] IsEndGame.isKeep(20) | END GAME [GAME [XXO X OOO]: player(O)
   history [         ,      O  ,    X O  ,    X OO ,X   X OO ,X O X OO ,XXO X OO ,]]
2013-12-30 21:53:40,940-0500 | INFO [Thread-28] IsEndGame.isKeep(20) | END GAME [GAME [X OXX OOO]: player(O)
   history [         ,      O  ,    X O  ,    X OO ,X   X OO ,X O X OO ,X OXX OO ,]]
2013-12-30 21:53:40,940-0500 | INFO [Thread-28] LocalQueueEmitter.enqueue(61) | [ScoringQueue] size = [42000]
```

## 检查评分拓扑

评分拓扑结构更直接，因为它是线性的。复杂的方面是状态的更新，以避免读写竞争条件。

拓扑结构的代码如下：

```scala
public static StormTopology buildTopology() {
TridentTopology topology = new TridentTopology();

GameState exampleRecursiveState =
 GameState.playAtRandom(new Board(), 'X');
LOG.info('SIMULATED STATE : [' + exampleRecursiveState + ']');

// Scoring Queue / Spout
LocalQueueEmitter<GameState> scoringSpoutEmitter = 
new LocalQueueEmitter<GameState>('ScoringQueue');
scoringSpoutEmitter.enqueue(exampleRecursiveState);
LocalQueueSpout<GameState> scoringSpout = 
new LocalQueueSpout<GameState>(scoringSpoutEmitter);

Stream inputStream = 
topology.newStream('gamestate', scoringSpout);

inputStream.each(new Fields('gamestate'), new IsEndGame())
                .each(new Fields('gamestate'),
                        new ScoreFunction(),
                        new Fields('board', 'score', 'player'))
                .each(new Fields('board', 'score', 'player'), 
new ScoreUpdater(), new Fields());
return topology.build();
}
```

只有两个函数：`ScoreFunction` 和 `ScoreUpdater`。`ScoreFunction` 为历史上的每个棋盘评分并发出该得分。

`ScoreFunction` 的列表如下代码片段所示：

```scala
public class ScoreFunction extends BaseFunction {

@Override
public void execute(TridentTuple tuple, 
TridentCollector collector) {
        GameState gameState = (GameState) tuple.get(0);
        String player = gameState.getPlayer();
        int score = gameState.score();

        List<Object> values = new ArrayList<Object>();
        values.add(gameState.getBoard());
        values.add(score);
        values.add(player);
        collector.emit(values);

        for (Board b : gameState.getHistory()) {
            player = Player.next(player);
            values = new ArrayList<Object>();
            values.add(b);
            values.add(score);
            values.add(player);
            collector.emit(values);
        }
    }
}
```

该函数简单地为当前棋盘评分并为当前棋盘发出一个元组。然后，该函数循环遍历玩家，为每个棋盘发出元组，并在每轮中交换玩家。

最后，我们有`ScoreUpdater` 函数。同样，我们为示例保持简单。以下是该类的代码：

```scala
public class ScoreUpdater extends BaseFunction {
...
private static final Map<String, Integer> scores =
 new HashMap<String, Integer>();
private static final String MUTEX = 'MUTEX';

@Override
public void execute(TridentTuple tuple,
TridentCollector collector) {
    Board board = (Board) tuple.get(0);
    int score = tuple.getInteger(1);
    String player = tuple.getString(2);
    String key = board.toKey();
    LOG.debug('Got (' + board.toKey() + ') => [' + score +
 '] for [' + player + ']');

    // Always compute things from X's perspective
    // We'll flip things when we interpret it if it is O's turn.
    synchronized(MUTEX){
         Integer currentScore = scores.get(key);
         if (currentScore == null ||
(player.equals('X') && score > currentScore)){
                updateScore(board, score);
            } else if (player.equals('O') &&
score > currentScore){
                updateScore(board, score);
            }
        }
    }

    public void updateScore(Board board, Integer score){
        scores.put(board.toKey(), score);
        LOG.debug('Updating [' + board.toString() + 
']=>[' + score + ']');
    }
}
```

### 解决读写问题

请注意，在前面的代码中，我们使用互斥锁来对得分的更新进行排序，从而消除了之前提到的竞争条件。这仅在我们在单个/本地 JVM 中运行时才有效。当此拓扑结构部署到真实集群时，这将不起作用；但是，我们有一些选项来解决这个问题。

#### 分布式锁定

正如我们在其他章节中看到的，可以利用分布式锁定机制，例如 ZooKeeper。在这种方法中，ZooKeeper 提供了一种在多个主机之间维护互斥锁的机制。这当然是一种可行的方法，但分布式锁定会带来性能成本。每个操作都会产生开销，以适应现实中可能是不经常发生的情况。

#### 过时时重试

可能有用的另一种模式是*过时时重试*方法。在这种情况下，除了数据之外，我们还会拉回一个版本号、时间戳或校验和。然后，我们执行条件更新，包括版本/时间戳/校验和信息在一个子句中，如果元数据发生了变化（例如，在 SQL/CQL 范式中将`WHERE`子句添加到`UPDATE`语句中），则更新将失败。如果元数据发生了变化，表示我们基于的值现在已经过时，我们应该重新选择数据。

显然，这些方法之间存在权衡。在重试中，如果存在大量争用，一个线程可能需要重试多次才能提交更新。然而，使用分布式锁定时，如果单个线程被卡住、与服务器失去通信或完全失败，可能会遇到超时问题。

### 提示

最近，在这个领域已经有了一些进展。我建议您查看 Paxos 和 Cassandra 在以下 URL 中使用该算法来影响条件更新：

+   [`research.microsoft.com/en-us/um/people/lamport/pubs/paxos-simple.pdf`](http://research.microsoft.com/en-us/um/people/lamport/pubs/paxos-simple.pdf)

+   [`www.datastax.com/dev/blog/lightweight-transactions-in-cassandra-2-0`](http://www.datastax.com/dev/blog/lightweight-transactions-in-cassandra-2-0)

在我们的简单情况中，我们非常幸运，实际上可以直接将逻辑合并到更新中。考虑以下 SQL 语句：

```scala
UPDATE gametree SET score=7 WHERE
boardkey = '000XX OXX' AND score <=7;
```

由于我们已经解决了读写问题，拓扑结构适合对递归拓扑结构排队的所有棋盘进行评分。该拓扑结构为终局状态分配一个值，并将该值传播到游戏树上，将适当的得分与相应的游戏状态持久化。在真实的生产系统中，我们将从 DRPC 拓扑结构访问该状态，以便能够提前多回合。

#### 执行拓扑结构

以下是评分拓扑结构的示例输出：

```scala
2013-12-31 13:19:14,535-0500 | INFO [main] ScoringTopology.buildTopology(29) | SIMULATED LEAF NODE : [
---------
|X||O||X|
---------
|O||O||X|
---------
|X||X||O|
---------
] w/ state [GAME [XOXOOXXXO]: player(O)
 history [         ,  X      , OX      , OX  X   , OX  X  O, OX  XX O, OXO XX O, OXO XXXO, OXOOXXXO,]]
2013-12-31 13:19:14,536-0500 | INFO [main] LocalQueueEmitter.enqueue(61) | [ScoringQueue] size = [0].
2013-12-31 13:19:14,806-0500 | INFO [main] ScoringTopology.main(52) | Topology submitted.
2013-12-31 13:19:25,566-0500 | INFO [Thread-24] DefaultCoordinator.initializeTransaction(25) | Initializing Transaction [1]
2013-12-31 13:19:25,570-0500 | DEBUG [Thread-30] LocalQueueEmitter.emitBatch(37) | Getting batch for [1]
2013-12-31 13:19:25,570-0500 | DEBUG [Thread-30] LocalQueueEmitter.emitBatch(41) | Waiting on work from [ScoringQueue]:[1]
2013-12-31 13:19:25,570-0500 | DEBUG [Thread-30] LocalQueueEmitter.emitBatch(43) | Got work from [ScoringQueue]:[0]
2013-12-31 13:19:25,571-0500 | DEBUG [Thread-30] LocalQueueEmitter.emitBatch(41) | Waiting on work from [ScoringQueue]:[0]
2013-12-31 13:19:25,571-0500 | INFO [Thread-28] IsEndGame.isKeep(20) | END GAME [GAME [XOXOOXXXO]: player(O)
 history [         ,  X      , OX      , OX  X   , OX  X  O, OX  XX O, OXO XX O, OXO XXXO, OXOOXXXO,]]
...
 ScoreUpdater.updateScore(43) | Updating [
---------
| ||O||X|
---------
|O|| ||X|
---------
|X||X||O|
---------
]=>[0]
2013-12-31 13:19:25,574-0500 | DEBUG [Thread-28] ScoreUpdater.execute(27) | Got ( OXOOXXXO) => [0] for [X]
2013-12-31 13:19:25,574-0500 | DEBUG [Thread-28] ScoreUpdater.updateScore(43) | Updating [
---------
| ||O||X|
---------
|O||O||X|
---------
|X||X||O|
---------
]=>[0]

```

它正在解决列表开头显示的平局叶节点。之后，您可以看到该值在那之后通过父节点传播，更新这些节点的当前得分。

### 枚举游戏树

将递归拓扑与评分拓扑相结合的最终结果是一组拓扑不断协作，以尽可能多地枚举问题空间。很可能，这个过程将与启发式算法相结合，只存储关键节点。此外，我们将使用启发式算法修剪搜索空间，以减少我们需要评估的板的数量。然而，无论如何，我们都需要通过接口与系统进行交互，以确定在当前游戏状态下的最佳移动。这将是我们下一节要解决的问题。

## 分布式远程过程调用（DRPC）

现在我们有一个功能正常的递归拓扑，它将不断寻求计算整个游戏树，让我们来看看同步调用。Storm 提供的 DRPC 功能已被移植到 Trident，并在 Storm 中已被弃用。这是在本例中使用 Trident 的主要动机。

使用 DRPC，您构建拓扑的方式与异步情况下的方式非常相似。以下图表显示了我们的 DRPC 拓扑：

![分布式远程过程调用（DRPC）](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/storm-bp/img/8294OS_06_05.jpg)

DRPC 客户端充当一个喷口。客户端的输出经过`ArgsFunction`，它规范化输入，以便我们可以重用现有的函数：`GenerateBoards`和`ScoreFunction`。然后，我们使用`.groupBy(state)`并使用`Aggregator`类的`FindBestMove`来聚合结果。然后，我们执行一个简单的投影，只将最佳移动返回给客户端。

### 提示

您可能还想看一下 Spring Breeze，它允许您将 POJO 连接到 Storm 拓扑中。这是另一种获得重用的方法，因为这些相同的 POJO 可以通过 Web 服务公开而不引入 DRPC。

[`github.com/internet-research-network/breeze`](https://github.com/internet-research-network/breeze)

首先，我们将看一下拓扑的代码：

```scala
public static void main(String[] args) throws Exception {
final LocalCluster cluster = new LocalCluster();
final Config conf = new Config();

LocalDRPC client = new LocalDRPC();
TridentTopology drpcTopology = new TridentTopology();

drpcTopology.newDRPCStream('drpc', client)
                .each(new Fields('args'),
new ArgsFunction(),
new Fields('gamestate'))
                .each(new Fields('gamestate'),
new GenerateBoards(),
new Fields('children'))
                .each(new Fields('children'),
new ScoreFunction(),
new Fields('board', 'score', 'player'))
                .groupBy(new Fields('gamestate'))
                .aggregate(new Fields('board', 'score'),
new FindBestMove(), new Fields('bestMove'))
                .project(new Fields('bestMove'));

cluster.submitTopology('drpcTopology', conf,
         drpcTopology.build());

Board board = new Board();
board.board[1][1] = 'O';
board.board[2][2] = 'X';
board.board[0][1] = 'O';
board.board[0][0] = 'X';
LOG.info('Determining best move for O on:' + 
               board.toString());
LOG.info('RECEIVED RESPONSE [' + 
client.execute('drpc', board.toKey()) + ']');
}
```

对于这个例子，我们使用了一个`LocalDRPC`客户端。这作为`newDRPCStream`调用的参数传入，这是 DRPC 拓扑的关键。从那里开始，拓扑函数就像一个普通的拓扑一样运行。

通过`client.execute()`方法，您可以看到实际的远程过程调用发生。目前，该方法的签名仅接受和返回字符串。有一个未解决的增强请求来更改这个签名。您可以在[`issues.apache.org/jira/browse/STORM-42`](https://issues.apache.org/jira/browse/STORM-42)找到该增强请求。

由于当前签名只接受字符串，我们需要对输入进行编组。这发生在`ArgsFunction`中，如下面的代码片段所示：

```scala
    @Override
    public void execute(TridentTuple tuple, 
TridentCollector collector) {
        String args = tuple.getString(0);
        Log.info('Executing DRPC w/ args = [' + args + ']');
        Board board = new Board(args);
        GameState gameState = 
new GameState(board, new ArrayList<Board>(), 'X');
        Log.info('Emitting [' + gameState + ']');

        List<Object> values = new ArrayList<Object>();
        values.add(gameState);
        collector.emit(values);
    }
```

我们对`client.execute()`的调用的第二个参数是一个包含我们输入的字符串。在这种情况下，您可以在拓扑代码中看到我们传入了板的键。这是一个 3x3 的网格，其中单元格被串联为一个字符串。为了将该字符串编组为一个板，我们向`Board`类添加了一个解析字符串为板的构造函数，如下面的代码片段所示：

```scala
    public Board(String key) {
        for (int i = 0; i < 3; i++) {
            for (int j = 0; j < 3; j++) {
                this.board[i][j] = '' + key.charAt(i*3+j);
            }
        }
    }
```

在 DRPC 拓扑中应用的下两个函数演示了通过利用 DRPC 作为同步接口可以实现的重用。在这种情况下，我们是独立利用这些函数，但您可以想象您也可以重用更复杂的数据流。

使用`GenerateBoard`函数，我们发出当前板的所有子板。然后，`ScoreFunction`对每个板进行评分。

与评分拓扑一样，`ScoreFunction`的输出是`board`、`score`和`player`的三元组。这些是每个子板的分数。为了确定我们的下一个最佳移动，我们只需要最大化（或最小化）这个值。这可以通过一个简单的`Aggregator`来实现。我们创建了一个名为`FindBestMove`的聚合函数，如下面的代码片段所示：

```scala
public class FindBestMove extends BaseAggregator<BestMove> {
    private static final long serialVersionUID = 1L;

    @Override
    public BestMove init(Object batchId, 
TridentCollector collector) {
        Log.info('Batch Id = [' + batchId + ']');
        return new BestMove();
    }

    @Override
    public void aggregate(BestMove currentBestMove, 
TridentTuple tuple, TridentCollector collector) {  
        Board board = (Board) tuple.get(0);
        Integer score = tuple.getInteger(1);
        if (score > currentBestMove.score){
            currentBestMove.score = score;
            currentBestMove.bestMove = board;
        }
    }

    @Override
    public void complete(BestMove bestMove, 
TridentCollector collector) {
        collector.emit(new Values(bestMove));        
    }

}
```

这个聚合扩展了`BaseAggregator`，它是一个 Java 泛型。在这种情况下，我们希望发出最佳的移动，结合它的得分。因此，我们使用`BestMove`类参数化`BaseAggregator`类，它的简单定义如下：

```scala
public class BestMove {
    public Board bestMove;
    public Integer score = Integer.MIN_VALUE;

    public String toString(){
        return bestMove.toString() + '[' + score + ']';
    }
}
```

如果你回忆一下，对于聚合，Trident 最初调用`init()`方法，该方法返回初始的聚合值。在我们的情况下，我们只是用最差的移动来初始化`BestMove`类。注意`BestMove`类的得分变量被初始化为绝对最小值。然后，Trident 调用`aggregate()`方法，允许函数将元组合并到聚合值中。聚合也可以在这里发出值，但由于我们只关心最终的最佳移动，所以我们不从`aggregate()`方法中发出任何东西。最后，Trident 在所有元组的值都被聚合后调用`complete()`方法。在这个方法中，我们发出最终的最佳移动。

以下是拓扑结构的输出：

```scala
2013-12-31 13:53:42,979-0500 | INFO [main] DrpcTopology.main(43) | Determining best move for O on:
---------
|X||O|| |
---------
| ||O|| |
---------
| || ||X|
---------

00:00  INFO: Executing DRPC w/ args = [XO  O   X]
00:00  INFO: Emitting [GAME [XO  O   X]: player(X)
 history []]
00:00  INFO: Batch Id = [storm.trident.spout.RichSpoutBatchId@1e8466d2]
2013-12-31 13:53:44,092-0500 | INFO [main] DrpcTopology.main(44) | RECEIVED RESPONSE [[[
---------
|X||O|| |
---------
| ||O|| |
---------
| ||O||X|
---------
[10000]]]]

```

在这个例子中，轮到 O 方了，他或她有一个得分机会。你可以看到拓扑正确地识别了得分机会，并将其作为最佳移动返回（带有适当的得分值）。

### 远程部署

我们展示的是 DRPC 拓扑的本地调用。要调用远程拓扑，你需要启动 DRPC 服务器。你可以通过执行带有`drpc`参数的 Storm 脚本来实现这一点，如下面的代码片段所示：

```scala
bin/storm drpc
```

Storm 集群将连接到 DRPC 服务器接收调用。为了做到这一点，它需要知道 DRPC 服务器的位置。这些位置在`storm.yaml`文件中指定如下：

```scala
drpc.servers: 
- 'drpchost1 ' 
- 'drpchost2'

```

配置好服务器并启动 DRPC 服务器后，拓扑就像任何其他拓扑一样被提交，DRPC 客户端可以从任何需要大规模同步分布式处理的 Java 应用程序中使用。要从本地 DRPC 客户端切换到远程客户端，唯一需要更改的是 DRPC 客户端的实例化。你需要使用以下行：

```scala
DRPCClient client = new DRPCClient('drpchost1', 3772);
```

这些参数指定了 DRPC 服务器的主机和端口，并应与 YAML 文件中的配置匹配。

# 总结

在本章中，我们处理了一个人工智能用例。在这个领域中有许多问题利用了树和图数据结构，而对于这些数据结构最合适的算法通常是递归的。为了演示这些算法如何转化为 Storm，我们使用了 Minimax 算法，并使用 Storm 的构造实现了它。

在这个过程中，我们注意到了 Storm 中的一些约束条件，使得它比预期的更加复杂，我们也看到了能够绕过这些约束条件并产生可工作/可扩展系统的模式和方法。

此外，我们介绍了 DRPC。DRPC 可以用于向客户端公开同步接口。DRPC 还允许设计在同步和异步接口之间重用代码和数据流。

将同步和异步拓扑与共享状态结合起来，不仅对于人工智能应用而言是一个强大的模式，对于分析也是如此。通常，新数据持续在后台到达，但用户通过同步接口查询这些数据。当你将 DRPC 与其他章节介绍的 Trident 状态能力结合起来时，你应该能够构建一个能够满足实时分析用例的系统。

在下一章中，我们将 Storm 与非事务实时分析系统 Druid 集成。我们还将更深入地研究 Trident 和 ZooKeeper 的分布式状态管理。
