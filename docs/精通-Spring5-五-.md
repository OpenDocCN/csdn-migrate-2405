# 精通 Spring5（五）

> 原文：[`zh.annas-archive.org/md5/73290E1F786F5BAA832E07A902070E3F`](https://zh.annas-archive.org/md5/73290E1F786F5BAA832E07A902070E3F)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十章：Spring Cloud Data Flow

Spring Data Flow 将微服务架构引入了典型的数据流和事件流场景。我们将在本章后面更多地讨论这些场景。基于其他 Spring 项目，如 Spring Cloud Stream、Spring Integration 和 Spring Boot，Spring Data Flow 使得使用基于消息的集成定义和扩展数据和事件流的用例变得容易。

在本章中，我们将讨论以下主题：

+   我们为什么需要异步通信？

+   什么是 Spring Cloud Stream？它如何构建在 Spring Integration 之上？

+   我们为什么需要 Spring Data Flow？

+   Spring Data Flow 中的重要概念是什么？

+   Spring Data Flow 有哪些有用的用例？

我们还将实现一个简单的事件流场景，其中有三个微服务充当源（生成事件的应用程序）、处理器和汇（消费事件的应用程序）。我们将使用 Spring Cloud Stream 实现这些微服务，并使用 Spring Cloud Data Flow 在消息代理上建立它们之间的连接。

# 基于消息的异步通信

在集成应用程序时有两个选项：

+   **同步**：服务消费者调用服务提供者并等待响应。

+   **异步**：服务消费者通过将消息放在消息代理上调用服务提供者，但不等待响应。

我们在*第五章，使用 Spring Boot 构建微服务*中构建的服务（`random`服务，`add`服务）是同步集成的示例。这些是典型的通过 HTTP 公开的 Web 服务。服务消费者调用服务并等待响应。下一次调用只有在前一个服务调用完成后才会进行。

这种方法的一个重要缺点是期望服务提供者始终可用。如果服务提供者宕机，或者由于某种原因服务执行失败，服务消费者将需要重新执行服务。

另一种方法是使用基于消息的异步通信。服务消费者将消息放在消息代理上。服务提供者在消息代理上监听，一旦有消息可用，就会处理它。

一个优点是，即使服务提供者暂时宕机，它可以在恢复时处理消息代理上的消息。服务提供者不需要一直可用。虽然可能会有延迟，但数据最终会保持一致。

以下图显示了基于异步消息的通信的示例：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/e4e968de-1d77-43b1-bd60-0ce412b12ac0.png)

异步通信改善可靠性的两种情况：

+   如果服务提供者宕机，那么消息将在消息代理中排队。当服务提供者恢复时，它将处理这些消息。因此，即使服务提供者宕机，消息也不会丢失。

+   如果消息处理出现错误，服务提供者将把消息放入错误通道。当错误被分析和修复后，消息可以从错误通道移动到输入通道，并排队等待重新处理。

重要的一点是，在前面的两种情况中，服务消费者不需要担心服务提供者是否宕机或消息处理失败。服务消费者发送消息后就可以忘记它了。消息架构确保消息最终会成功处理。

基于消息的异步通信通常用于事件流和数据流：

+   **事件流**：这涉及基于事件的处理逻辑。例如，新客户事件、股价变动事件或货币变动事件。下游应用程序将在消息代理上监听事件并对其做出反应。

+   **数据流**：这涉及通过多个应用程序增强的数据，并最终存储到数据存储中。

在功能上，数据流架构之间交换的消息内容与事件流架构不同。但从技术上讲，它只是从一个系统发送到另一个系统的另一条消息。在本章中，我们不会区分事件和数据流。Spring Cloud 数据流可以处理所有这些流--尽管只有数据流在名称中。我们可以互换使用事件流、数据流或消息流来指示不同应用程序之间的消息流。

# 异步通信的复杂性

虽然前面的示例是两个应用程序之间的简单通信，但在现实世界的应用程序中，典型的流程可能要复杂得多。

下图显示了涉及消息流的三个不同应用程序的示例场景。源应用程序生成事件。处理器应用程序处理事件并生成另一条消息，将由接收应用程序处理：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/1ef4605f-eba9-4a16-b50c-6be64bf87b15.png)

另一个示例场景涉及一个事件被多个应用程序消耗。例如，当客户注册时，我们希望给他们发送电子邮件、欢迎包和邮件。该场景的简单消息架构如下图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/d1fa3516-aa1e-4224-a9eb-2d92f5b566c8.png)

要实现上述场景，涉及许多不同的步骤：

1.  配置消息代理。

1.  在消息代理上创建不同的通道。

1.  编写应用程序代码以连接到消息代理上的特定通道。

1.  在应用程序中安装必要的绑定器以连接到消息代理。

1.  建立应用程序与消息代理之间的连接。

1.  构建和部署应用程序。

考虑这样一个场景，其中流程中的一些应用程序必须处理大量的消息负载。我们需要根据负载创建多个这样的应用程序实例。实现复杂性变得多方面。这些是 Spring Cloud 数据流和 Spring Cloud Stream 旨在解决的挑战。

在下一节中，我们将看看不同的 Spring 项目--Spring Cloud Stream（构建在 Spring 集成之上）和 Spring Cloud 数据流如何使我们能够进行基于消息的集成，而无需进行大量配置。

# 用于异步消息的 Spring 项目

在本节中，我们将看看 Spring 提供的不同项目，以实现应用程序之间基于消息的通信。我们将从 Spring 集成开始，然后转向在云上甚至能够实现基于消息的集成的项目--Spring Cloud Stream 和 Spring Cloud 数据流。

# Spring 集成

Spring 集成有助于在消息代理上无缝集成微服务。它允许程序员专注于业务逻辑，并将技术基础设施的控制（使用什么消息格式？如何连接到消息代理？）交给框架。Spring 集成通过定义良好的接口和消息适配器提供了各种配置选项。Spring 集成网站（[`projects.spring.io/spring-integration/`](https://projects.spring.io/spring-integration/)）：

扩展 Spring 编程模型以支持众所周知的企业集成模式。Spring 集成使 Spring 应用程序内部实现轻量级消息传递，并通过声明性适配器支持与外部系统的集成。这些适配器提供了对 Spring 支持远程调用、消息传递和调度的更高级抽象。Spring 集成的主要目标是提供一个简单的模型来构建企业集成解决方案，同时保持关注点的分离，这对于生成可维护、可测试的代码至关重要。

Spring Integration 提供的功能包括以下内容：

+   企业集成模式的简单实现

+   聚合来自多个服务的响应

+   从服务中过滤结果

+   服务消息转换

+   多协议支持--HTTP、FTP/SFTP、TCP/UDP、JMS

+   支持不同风格的 Web 服务（SOAP 和 REST）

+   支持多个消息代理，例如 RabbitMQ

在上一章中，我们使用了 Spring Cloud 来使我们的微服务成为云原生--部署在云中并利用云部署的所有优势。

然而，使用 Spring Integration 构建的应用程序，特别是与消息代理交互的应用程序，需要大量配置才能部署到云中。这阻止它们利用云的典型优势，例如自动扩展。

我们希望扩展 Spring Integration 提供的功能，并在云上提供这些功能。我们希望我们的微服务云实例能够自动与消息代理集成。我们希望能够自动扩展我们的微服务云实例，而无需手动配置。这就是 Spring Cloud Stream 和 Spring Cloud Data Flow 的用武之地。

# Spring Cloud Stream

Spring Cloud Stream 是构建面向云的消息驱动微服务的首选框架。

Spring Cloud Stream 允许程序员专注于围绕事件处理的业务逻辑构建微服务，将这里列出的基础设施问题留给框架处理：

+   消息代理配置和通道创建

+   针对消息代理的特定转换

+   创建绑定器以连接到消息代理

Spring Cloud Stream 完美地融入了微服务架构。在事件处理或数据流的用例中，可以设计具有明确关注点分离的典型微服务。单独的微服务可以处理业务逻辑，定义输入/输出通道，并将基础设施问题留给框架。

典型的流应用程序涉及事件的创建、事件的处理和存储到数据存储中。Spring Cloud Stream 提供了三种简单的应用程序类型来支持典型的流程：

+   **Source**：Source 是事件的创建者，例如触发股价变动事件的应用程序。

+   **Processor**：Processor 消耗事件，即处理消息，对其进行一些处理，并创建带有结果的事件。

+   **Sink**：Sink 消耗事件。它监听消息代理并将事件存储到持久数据存储中。

Spring Cloud Stream 用于在数据流中创建单独的微服务。Spring Cloud Stream 微服务定义业务逻辑和连接点，即输入和/或输出。Spring Cloud Data Flow 有助于定义流程，即连接不同的应用程序。

# Spring Cloud Data Flow

Spring Cloud Data Flow 有助于在使用 Spring Cloud Stream 创建的不同类型的微服务之间建立消息流。

基于流行的开源项目，**Spring XD** 简化了数据管道和工作流的创建--特别是针对大数据用例。然而，Spring XD 在适应与数据管道相关的新要求（例如金丝雀部署和分布式跟踪）方面存在挑战。Spring XD 架构基于运行时依赖于多个外围设备。这使得调整集群规模成为一项具有挑战性的任务。Spring XD 现在被重新命名为 Spring Cloud Data Flow。Spring Cloud Data Flow 的架构基于可组合的微服务应用程序。

Spring Cloud Data Flow 中的重要特性如下：

+   配置流，即数据或事件如何从一个应用程序流向另一个应用程序。Stream DSL 用于定义应用程序之间的流程。

+   建立应用程序与消息代理之间的连接。

+   提供围绕应用程序和流的分析。

+   将在流中定义的应用程序部署到目标运行时。

+   支持多个目标运行时。几乎每个流行的云平台都得到支持。

+   在云上扩展应用程序。

+   创建和调用任务。

有时，术语可能会有点混淆。流是流的另一种术语。重要的是要记住，Spring Cloud Stream 实际上并没有定义整个流。它只有助于创建整个流中涉及的微服务之一。正如我们将在接下来的部分中看到的，流实际上是使用 Spring Cloud Data Flow 中的 Stream DSL 来定义的。

# Spring Cloud Stream

Spring Cloud Stream 用于创建涉及流的单个微服务，并定义与消息代理的连接点。

Spring Cloud Stream 是建立在两个重要的 Spring 项目之上的：

+   **Spring Boot**：使微服务能够创建适用于生产的微服务

+   **Spring Integration**：使微服务能够通过消息代理进行通信

Spring Cloud Stream 的一些重要特性如下：

+   将微服务连接到消息代理的最低配置。

+   支持各种消息代理--RabbitMQ、Kafka、Redis 和 GemFire。

+   支持消息的持久性--如果服务宕机，它可以在恢复后开始处理消息。

+   支持消费者组--在负载较重的情况下，您需要多个相同微服务的实例。您可以将所有这些微服务实例分组到一个消费者组中，以便消息只被可用实例中的一个接收。

+   支持分区--可能存在这样的情况，您希望确保一组特定的消息由同一个实例处理。分区允许您配置标准来识别由同一分区实例处理的消息。

# Spring Cloud Stream 架构

以下图显示了典型 Spring Cloud Stream 微服务的架构。源只有一个输入通道，处理器既有输入通道又有输出通道，而汇则只有一个输出通道：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/4a31fe0b-fb4e-420d-9a05-a11cdff9254a.png)

应用程序声明它们想要什么样的连接--输入和/或输出。Spring Cloud Stream 将建立连接应用程序与消息代理所需的一切。

Spring Cloud Stream 将执行以下操作：

+   将输入和/或输出通道注入到应用程序中

+   通过特定于消息代理的绑定器建立与消息代理的连接。

绑定器为 Spring Cloud Stream 应用程序带来了可配置性。一个 Spring Cloud Stream 应用程序只声明通道。部署团队可以在运行时配置通道连接到哪个消息代理（Kafka 或 RabbitMQ）。Spring Cloud Stream 使用自动配置来检测类路径上可用的绑定器。要连接到不同的消息代理，我们只需要改变项目的依赖。另一个选项是在类路径中包含多个绑定器，并在运行时选择要使用的绑定器。

# 事件处理-股票交易示例

让我们想象一个场景。一位股票交易员对他/她投资的股票的重大股价变动感兴趣。以下图显示了使用 Spring Cloud Stream 构建的这样一个应用程序的简单架构：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/07fb81a0-b47c-43c0-91de-bf6dedf0db93.png)

需要注意的重要事项如下：

+   **重要股价变动微服务**：每当交易所上市的任何股票的价格发生重大变动时，它会在消息代理上触发一个事件。这是**源**应用程序。

+   **股票智能微服务**：这个微服务监听股价变化事件的消息代理。当有新消息时，它会检查股票库存并将有关用户当前持仓的信息添加到消息中，并将另一条消息放在消息代理上。这是**处理器**应用程序。

+   **事件存储微服务**：这个微服务在消息代理上监听投资股票警报的股价变化。当有新消息时，它将其存储在数据存储中。这是**接收器**应用程序。

前面的架构为我们提供了在不进行重大更改的情况下增强系统的灵活性：

+   电子邮件微服务和短信微服务在消息代理上监听投资股票警报的股价变化，并发送电子邮件/短信警报。

+   股票交易员可能希望对他们没有投资的其他股票进行重大更改。股票智能微服务可以进一步增强。

正如我们之前讨论的，Spring Cloud Stream 帮助我们构建流的基本构建模块，也就是微服务。我们将使用 Spring Cloud Stream 创建三个微服务。我们稍后将使用这三个微服务并使用 Spring Cloud Data Flow 创建一个流，也就是使用 Spring Cloud Data Flow 在应用程序之间创建一个流程。

我们将从下一节开始使用 Spring Cloud Stream 创建微服务。在开始源、处理器和接收器流应用程序之前，我们将设置一个简单的模型项目：

# 股票交易示例的模型

`StockPriceChangeEvent`类包含股票的代码、股票的旧价格和股票的新价格：

```java
    public class StockPriceChangeEvent {
      private final String stockTicker;
      private final BigDecimal oldPrice;
      private final BigDecimal newPrice;
      //Setter, Getters and toString()
    }
```

`StockPriceChangeEventWithHoldings`类扩展了`StockPriceChangeEvent`。它有一个额外的属性--`holdings`。`holdings`变量用于存储交易员当前拥有的股票数量：

```java
    public class StockPriceChangeEventWithHoldings 
    extends StockPriceChangeEvent {
      private Integer holdings;
      //Setter, Getters and toString()
    }
```

`StockTicker`枚举存储应用程序支持的股票列表：

```java
    public enum StockTicker {
      GOOGLE, FACEBOOK, TWITTER, IBM, MICROSOFT
    }
```

# 源应用程序

源应用程序将是股价变化事件的生产者。它将定义一个输出通道并将消息放在消息代理上。

让我们使用 Spring Initializr（[`start.spring.io`](https://start.spring.io)）来设置应用程序。提供这里列出的详细信息，然后点击生成项目：

+   组：`com.mastering.spring.cloud.data.flow`

+   Artifact：`significant-stock-change-source`

+   依赖项：`Stream Rabbit`

以下是`pom.xml`文件中的一些重要依赖项：

```java
    <dependency>
      <groupId>org.springframework.cloud</groupId>
      <artifactId>spring-cloud-starter-stream-rabbit</artifactId>
    </dependency>
```

使用以下代码更新`SpringBootApplication`文件：

```java
    @EnableBinding(Source.class)
    @SpringBootApplication
    public class SignificantStockChangeSourceApplication {
      private static Logger logger = LoggerFactory.getLogger 
     (SignificantStockChangeSourceApplication.class);
     // psvm - main method
     @Bean
     @InboundChannelAdapter(value = Source.OUTPUT, 
     poller = @Poller(fixedDelay = "60000", maxMessagesPerPoll = "1"))
     public MessageSource<StockPriceChangeEvent>
     stockPriceChangeEvent()     {
       StockTicker[] tickers = StockTicker.values();
       String randomStockTicker = 
       tickers[ThreadLocalRandom.current().nextInt(tickers.length)] 
      .name();
       return () - > {
        StockPriceChangeEvent event = new         
        StockPriceChangeEvent(randomStockTicker,
        new BigDecimal(getRandomNumber(10, 20)), new   
        BigDecimal(getRandomNumber(10, 20)));
        logger.info("sending " + event);
        return MessageBuilder.withPayload(event).build();
        };
      }
     private int getRandomNumber(int min, int max) {
       return ThreadLocalRandom.current().nextInt(min, max + 1);
     }
    }
```

需要注意的一些重要事项如下：

+   `@EnableBinding(Source.class)`：`EnableBinding`注解使类与它需要的相应通道进行绑定--输入和/或输出。源类用于注册一个具有一个输出通道的 Cloud Stream。

+   `@Bean @InboundChannelAdapter(value = Source.OUTPUT, poller = @Poller(fixedDelay = "60000", maxMessagesPerPoll = "1"))`：`InboundChannelAdapter`注解用于指示该方法可以创建要放在消息代理上的消息。value 属性用于指示消息要放置的通道的名称。`Poller`用于调度消息的生成。在这个例子中，我们使用`fixedDelay`每分钟生成一次消息（60 * 1000 ms）。

+   `private int getRandomNumber(int min, int max)`：这个方法用于在传递的范围内创建一个随机数。

`Source`接口定义了一个输出通道，如下面的代码所示：

```java
    public abstract interface 
    org.springframework.cloud.stream.messaging.Source {
      public static final java.lang.String OUTPUT = "output";
      @org.springframework.cloud.stream.
      annotation.Output(value="output")
      public abstract org.springframework.
      messaging.MessageChannel   output();
     }
```

# 处理器

处理器应用程序将从消息代理的输入通道接收消息。它将处理消息并将其放在消息代理的输出通道上。在这个特定的例子中，处理包括将当前持仓的位置添加到消息中。

让我们使用 Spring Initializr（[`start.spring.io`](https://start.spring.io)）来设置应用程序。提供这里列出的详细信息，然后点击生成项目：

+   组：`com.mastering.spring.cloud.data.flow`

+   构件：`stock-intelligence-processor`

+   依赖：`Stream Rabbit`

使用以下代码更新`SpringBootApplication`文件：

```java
    @EnableBinding(Processor.class)@SpringBootApplication
    public class StockIntelligenceProcessorApplication {
      private static Logger logger = 
      LoggerFactory.getLogger
      (StockIntelligenceProcessorApplication.class);
      private static Map < StockTicker, Integer > holdings =
        getHoldingsFromDatabase();
        private static Map < StockTicker,
        Integer > getHoldingsFromDatabase() {
          final Map < StockTicker,
          Integer > holdings = new HashMap < >();
          holdings.put(StockTicker.FACEBOOK, 10);
          holdings.put(StockTicker.GOOGLE, 0);
          holdings.put(StockTicker.IBM, 15);
          holdings.put(StockTicker.MICROSOFT, 30);
          holdings.put(StockTicker.TWITTER, 50);
          return holdings;
        }
        @Transformer(inputChannel = Processor.INPUT,
        outputChannel = Processor.OUTPUT)
        public Object addOurInventory(StockPriceChangeEvent event) {
          logger.info("started processing event " + event);
          Integer holding =  holdings.get(
            StockTicker.valueOf(event.getStockTicker()));
          StockPriceChangeEventWithHoldings eventWithHoldings =
            new StockPriceChangeEventWithHoldings(event, holding);
          logger.info("ended processing eventWithHoldings " 
            + eventWithHoldings);
          return eventWithHoldings;
        }
        public static void main(String[] args) {
          SpringApplication.run(
            StockIntelligenceProcessorApplication.class,args);
        }
    }
```

需要注意的一些重要事项如下：

+   `@EnableBinding(Processor.class)`: `EnableBinding`注解用于将类与其所需的相应通道绑定--输入和/或输出。`Processor`类用于注册一个具有一个输入通道和一个输出通道的 Cloud Stream。

+   `private static Map<StockTicker, Integer> getHoldingsFromDatabase()`: 这个方法处理消息，更新持有量，并返回一个新对象，该对象将作为新消息放入输出通道。

+   `@Transformer(inputChannel = Processor.INPUT, outputChannel = Processor.OUTPUT)`: `Transformer`注解用于指示一个能够将一种消息格式转换/增强为另一种消息格式的方法。

如下所示，`Processor`类扩展了`Source`和`Sink`类。因此，它定义了输出和输入通道：

```java
   public abstract interface 
   org.springframework.cloud.stream.messaging.Processor extends 
   org.springframework.cloud.stream.messaging.Source, 
   org.springframework.cloud.stream.messaging.Sink {
  }
```

# Sink

Sink 将从消息代理中提取消息并处理它。在这个例子中，我们将提取消息并记录它。Sink 只定义了一个输入通道。

让我们使用 Spring Initializr ([`start.spring.io`](https://start.spring.io))来设置应用程序。提供这里列出的细节，然后点击生成项目：

+   组：`com.mastering.spring.cloud.data.flow`

+   构件：`event-store-sink`

+   依赖：`Stream Rabbit`

使用以下代码更新`SpringBootApplication`文件：

```java
    @EnableBinding(Sink.class)@SpringBootApplication
    public class EventStoreSinkApplication {
      private static Logger logger = 
      LoggerFactory.getLogger(EventStoreSinkApplication.class);
      @StreamListener(Sink.INPUT)
      public void loggerSink(StockPriceChangeEventWithHoldings event) {
      logger.info("Received: " + event);
    }
    public static void main(String[] args) {
      SpringApplication.run(EventStoreSinkApplication.class, args);
    }
   }
```

需要注意的一些重要事项如下：

+   `@EnableBinding(Sink.class)`: `EnableBinding`注解用于将类与其所需的相应通道绑定--输入和/或输出。`Sink`类用于注册一个具有一个输入通道的 Cloud Stream。

+   `public void loggerSink(StockPriceChangeEventWithHoldings event)`: 这个方法通常包含将消息存储到数据存储的逻辑。在这个例子中，我们将消息打印到日志中。

+   `@StreamListener(Sink.INPUT)`: `StreamListener`注解用于监听传入消息的通道。在这个例子中，`StreamListener`配置为监听默认输入通道。

如下代码所示，`Sink`接口定义了一个输入通道：

```java
    public abstract interface   
    org.springframework.cloud.stream.messaging.Sink {
      public static final java.lang.String INPUT = "input";
      @org.springframework.cloud.stream.annotation.Input(value="input")
      public abstract org.springframework.messaging.SubscribableChannel 
      input();
    }
```

现在我们有了三个流应用程序准备好了，我们需要连接它们。在下一节中，我们将介绍 Spring Cloud Data Flow 如何帮助连接不同的流。

# Spring Cloud Data Flow

Spring Cloud Data Flow 有助于建立使用 Spring Cloud Stream 创建的不同类型的微服务之间的消息流。通过 Spring Cloud Data Flow 服务器部署的所有微服务都应该是定义了适当通道的 Spring Boot 微服务。

Spring Cloud Data Flow 提供了接口来定义应用程序，并使用 Spring DSL 定义它们之间的流。Spring Data Flow 服务器理解 DSL 并在应用程序之间建立流。

通常，这涉及多个步骤：

+   使用应用程序名称和应用程序的可部署单元之间的映射来从存储库下载应用程序构件。Spring Data Flow Server 支持 Maven 和 Docker 存储库。

+   将应用程序部署到目标运行时。

+   在消息代理上创建通道。

+   建立应用程序和消息代理通道之间的连接。

Spring Cloud Data Flow 还提供了在需要时扩展所涉及的应用程序的选项。部署清单将应用程序映射到目标运行时。部署清单需要回答的一些问题如下：

+   需要创建多少个应用程序实例？

+   每个应用程序实例需要多少内存？

数据流服务器理解部署清单并按照指定的方式创建目标运行时。Spring Cloud Data Flow 支持各种运行时：

+   云原生

+   Apache YARN

+   Kubernetes

+   Apache Mesos

+   用于开发的本地服务器

本章中的示例将使用本地服务器。

# 高级架构

在前面的示例中，我们有三个需要在数据流中连接的微服务。以下图表示使用 Spring Cloud Data Flow 实现解决方案的高级架构：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/60d12ed9-8204-48cf-a89f-6c162c9e5427.png)

在前面的图中，源、接收器和处理器是使用 Spring Cloud Stream 创建的 Spring Boot 微服务：

+   源微服务定义了一个输出通道

+   处理器微服务定义了输入和输出通道

+   接收器微服务定义了一个输入通道

# 实施 Spring Cloud Data Flow

实施 Spring Cloud Data Flow 涉及五个步骤：

1.  设置 Spring Cloud Data Flow 服务器。

1.  设置 Data Flow Shell 项目。

1.  配置应用程序。

1.  配置流。

1.  运行流。

# 设置 Spring Cloud Data Flow 服务器

让我们使用 Spring Initializr（[`start.spring.io`](https://start.spring.io)）来设置应用程序。提供这里列出的详细信息，然后单击“生成项目”：

+   组：`com.mastering.spring.cloud.data.flow`

+   Artifact：`local-data-flow-server`

+   依赖项：`本地 Data Flow 服务器`

以下是`pom.xml`文件中一些重要的依赖项：

```java
    <dependency>
      <groupId>org.springframework.cloud</groupId>
      <artifactId>spring-cloud-starter-dataflow-server-
      local</artifactId>
    </dependency>
```

更新`SpringBootApplication`文件，使用以下代码：

```java
    @EnableDataFlowServer
    @SpringBootApplication
    public class LocalDataFlowServerApplication {
      public static void main(String[] args) {
        SpringApplication.run(LocalDataFlowServierApplication.class,
        args);
      }
    }
```

`@EnableDataFlowServer`注解用于激活 Spring Cloud Data Flow 服务器实现。

在运行本地 Data Flow 服务器之前，请确保消息代理 RabbitMQ 正在运行。

以下是在启动`LocalDataFlowServerApplication`时的启动日志中的重要摘录：

```java
Tomcat initialized with port(s): 9393 (http)
Starting H2 Server with URL: jdbc:h2:tcp://localhost:19092/mem:dataflow
Adding dataflow schema classpath:schema-h2-common.sql for h2 database
Adding dataflow schema classpath:schema-h2-streams.sql for h2 database
Adding dataflow schema classpath:schema-h2-tasks.sql for h2 database
Adding dataflow schema classpath:schema-h2-deployment.sql for h2 database
Executed SQL script from class path resource [schema-h2-common.sql] in 37 ms.
Executed SQL script from class path resource [schema-h2-streams.sql] in 2 ms.
Executed SQL script from class path resource [schema-h2-tasks.sql] in 3 ms.
Executing SQL script from class path resource [schema-h2-deployment.sql]
Executed SQL script from class path resource [schema-h2-deployment.sql] in 3 ms.
Mapped "{[/runtime/apps/{appId}/instances]}" onto public org.springframework.hateoas.PagedResources
Mapped "{[/runtime/apps/{appId}/instances/{instanceId}]}" onto public 
Mapped "{[/streams/definitions/{name}],methods=[DELETE]}" onto public void org.springframework.cloud.dataflow.server.controller.StreamDefinitionController.delete(java.lang.String)
Mapped "{[/streams/definitions],methods=[GET]}" onto public org.springframework.hateoas.PagedResources
Mapped "{[/streams/deployments/{name}],methods=[POST]}" onto public void org.springframework.cloud.dataflow.server.controller.StreamDeploymentController.deploy(java.lang.String,java.util.Map<java.lang.String, java.lang.String>)
Mapped "{[/runtime/apps]}" onto public org.springframework.hateoas.PagedResources<org.springframework.cloud.dataflow.rest.resource.AppStatusResource> org.springframework.cloud.dataflow.server.controller.RuntimeAppsController.list(org.springframework.data.domain.Pageable,org.springframework.data.web.PagedResourcesAssembler<org.springframework.cloud.deployer.spi.app.AppStatus>) throws java.util.concurrent.ExecutionException,java.lang.InterruptedException
Mapped "{[/tasks/executions],methods=[GET]}" onto public org.springframework.hateoas.PagedResources
```

需要注意的一些重要事项如下：

+   Spring Cloud Data Flow 服务器的默认端口是`9393`。可以通过在`application.properties`中指定不同的端口`server.port`来更改这一点。

+   Spring Cloud Data Flow 服务器使用内部模式存储所有应用程序、任务和流的配置。在本例中，我们尚未配置任何数据库。因此，默认情况下使用`H2`内存数据库。Spring Cloud Data Flow 服务器支持各种数据库，包括 MySQL 和 Oracle，用于存储配置。

+   由于使用了`H2`内存数据库，您可以看到在启动期间设置了不同的模式，并且还执行了不同的 SQL 脚本来设置数据。

+   Spring Cloud Data Flow 服务器公开了许多围绕其配置、应用程序、任务和流的 API。我们将在后面的部分更多地讨论这些 API。

以下屏幕截图显示了 Spring Cloud Data Flow 的启动屏幕，网址为`http://localhost:9393/dashboard`：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/077ee2c6-bf62-4989-824f-c19fb814bed1.png)

有不同的选项卡可用于查看和修改应用程序、流和任务。在下一步中，我们将使用命令行界面--Data Flow Shell 来设置应用程序和流。

# 设置 Data Flow Shell 项目

Data Flow Shell 提供了使用命令配置 Spring Data Flow 服务器中的流和其他内容的选项。

让我们使用 Spring Initializr（[`start.spring.io`](https://start.spring.io)）来设置应用程序。提供这里列出的详细信息，然后单击“生成项目”：

+   组：`com.mastering.spring.cloud.data.flow`

+   Artifact：`data-flow-shell`

+   依赖项：`Data Flow Shell`

以下是`pom.xml`文件中一些重要的依赖项：

```java
    <dependency>
      <groupId>org.springframework.cloud</groupId>
      <artifactId>spring-cloud-dataflow-shell</artifactId>
    </dependency>
```

更新`SpringBootApplication`文件，使用以下代码：

```java
    @EnableDataFlowShell
    @SpringBootApplication
    public class DataFlowShellApplication {
      public static void main(String[] args) {
      SpringApplication.run(DataFlowShellApplication.class, args);
     }
    }
```

`@EnableDataFlowShell`注解用于激活 Spring Cloud Data Flow shell。

以下屏幕截图显示了启动 Data Flow Shell 应用程序时显示的消息。我们可以在命令提示符中输入命令：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/fc3c5ba3-ba93-471c-baf6-5189345a510c.png)

您可以尝试`help`命令以获取支持的命令列表。以下屏幕截图显示了执行`help`命令时打印的一些命令：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/3593bc81-bec4-4e65-8a50-c3637dcce671.png)

当您执行以下任何命令时，您会发现打印出空列表，因为我们尚未配置这些：

+   `app list`

+   `stream list`

+   `task list`

+   `runtime apps`

# 配置应用程序

在开始配置流之前，我们需要注册构成流的应用程序。我们有三个应用程序要注册--源、处理器和接收器。

要在 Spring Cloud Data Flow 中注册应用程序，您需要访问应用程序可部署。Spring Cloud Data Flow 提供了从 Maven 存储库中获取应用程序可部署的选项。为了简化，我们将从本地 Maven 存储库中获取应用程序。

在使用 Spring Cloud Stream 创建的三个应用程序上运行`mvn clean install`：

+   `significant-stock-change-source`

+   `stock-intelligence-processor`

+   `event-store-sink`

这将确保所有这些应用程序都构建并存储在您的本地 Maven 存储库中。

从 Maven 存储库注册应用的命令语法如下所示：

```java
app register —-name {{NAME_THAT_YOU_WANT_TO_GIVE_TO_APP}} --type source --uri maven://{{GROUP_ID}}:{{ARTIFACT_ID}}:jar:{{VERSION}}
```

三个应用程序的 Maven URI 如下所示：

```java
maven://com.mastering.spring.cloud.data.flow:significant-stock-change-source:jar:0.0.1-SNAPSHOT
maven://com.mastering.spring.cloud.data.flow:stock-intelligence-processor:jar:0.0.1-SNAPSHOT
maven://com.mastering.spring.cloud.data.flow:event-store-sink:jar:0.0.1-SNAPSHOT
```

创建应用程序的命令在此处列出。这些命令可以在 Data Flow Shell 应用程序上执行：

```java
app register --name significant-stock-change-source --type source --uri maven://com.mastering.spring.cloud.data.flow:significant-stock-change-source:jar:0.0.1-SNAPSHOT

app register --name stock-intelligence-processor --type processor --uri maven://com.mastering.spring.cloud.data.flow:stock-intelligence-processor:jar:0.0.1-SNAPSHOT

app register --name event-store-sink --type sink --uri maven://com.mastering.spring.cloud.data.flow:event-store-sink:jar:0.0.1-SNAPSHOT
```

当成功注册应用程序时，您将看到此处显示的消息：

```java
Successfully registered application 'source:significant-stock-change-source'

Successfully registered application 'processor:stock-intelligence-processor'

Successfully registered application 'sink:event-store-sink'
```

您还可以在 Spring Cloud Data Flow 仪表板上查看已注册的应用程序，如下图所示：`http://localhost:9393/dashboard`

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/c6e3de16-73b2-40f4-9082-5cc2b80f568c.png)

我们还可以使用仪表板注册应用程序，如下图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/15363632-47c4-45e1-822d-cf56cbe4ba9e.png)

# 配置流

Stream DSL 可用于配置流--这里显示了一个简单的示例，用于连接`app1`到`app2`。由`app1`放在输出通道上的消息将在`app2`的输入通道上接收：

```java
app1 | app2
```

我们希望连接这三个应用程序。以下代码片段显示了用于连接前述应用程序的 DSL 的示例：

```java
#source | processor | sink

significant-stock-change-source|stock-intelligence-processor|event-store-sink
```

这表示以下内容：

+   源的输出通道应链接到处理器的输入通道

+   处理器的输出通道应链接到接收器的输入通道

创建流的完整命令如下所示：

```java
stream create --name process-stock-change-events --definition significant-stock-change-source|stock-intelligence-processor|event-store-sink
```

如果成功创建流，则应看到以下输出：

```java
Created new stream 'process-stock-change-events'
```

您还可以在 Spring Cloud Data Flow 仪表板的 Streams 选项卡上查看已注册的流，如下图所示：`http://localhost:9393/dashboard`

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/bbeb68d5-8170-4ce3-8230-3559120b0a4c.png)

# 部署流

要部署流，可以在 Data Flow Shell 上执行以下命令：

```java
stream deploy --name process-stock-change-events
```

当发送请求创建流时，您将看到此处显示的消息：

```java
Deployment request has been sent for stream 'process-stock-change-events'
```

以下摘录显示了本地数据流服务器日志中的一部分：

```java
o.s.c.d.spi.local.LocalAppDeployer : deploying app process-stock-change-events.event-store-sink instance 0

Logs will be in /var/folders/y_/x4jdvdkx7w94q5qsh745gzz00000gn/T/spring-cloud-dataflow-3084432375250471462/process-stock-change-events-1492100265496/process-stock-change-events.event-store-sink

o.s.c.d.spi.local.LocalAppDeployer : deploying app process-stock-change-events.stock-intelligence-processor instance 0

Logs will be in /var/folders/y_/x4jdvdkx7w94q5qsh745gzz00000gn/T/spring-cloud-dataflow-3084432375250471462/process-stock-change-events-1492100266448/process-stock-change-events.stock-intelligence-processor

o.s.c.d.spi.local.LocalAppDeployer : deploying app process-stock-change-events.significant-stock-change-source instance 0

Logs will be in /var/folders/y_/x4jdvdkx7w94q5qsh745gzz00000gn/T/spring-cloud-dataflow-3084432375250471462/process-stock-change-events-1492100267242/process-stock-change-events.significant-stock-change-source
```

以下是一些需要注意的重要事项：

+   当部署流时，Spring Cloud Data Flow 将部署流中的所有应用程序，并通过消息代理设置应用程序之间的连接。应用程序代码独立于消息代理。Kafka 与 RabbitMQ 相比具有不同的消息代理设置。Spring Cloud Data Flow 会处理它。如果要从 RabbitMQ 切换到 Kafka，则应用程序代码无需更改。

+   本地数据流服务器日志包含所有应用程序的日志路径--源、处理器和接收器。

# 日志消息 - 设置与消息工厂的连接

以下代码片段显示了与从`Source`、`Transformer`和`Sink`应用程序设置消息代理相关的摘录：

```java
#Source Log
CachingConnectionFactory : Created new connection: SimpleConnection@725b3815 [delegate=amqp://guest@127.0.0.1:5672/, localPort= 58373]

#Transformer Log
o.s.i.endpoint.EventDrivenConsumer : Adding {transformer:stockIntelligenceProcessorApplication.addOurInventory.transformer} as a subscriber to the 'input' channel

o.s.integration.channel.DirectChannel : Channel 'application:0.input' has 1 subscriber(s).

o.s.i.endpoint.EventDrivenConsumer : started stockIntelligenceProcessorApplication.addOurInventory.transformer

o.s.i.endpoint.EventDrivenConsumer : Adding {message-handler:inbound.process-stock-change-events.significant-stock-change-source.process-stock-change-events} as a subscriber to the 'bridge.process-stock-change-events.significant-stock-change-source' channel

o.s.i.endpoint.EventDrivenConsumer : started inbound.process-stock-change-events.significant-stock-change-source.process-stock-change-events

#Sink Log

c.s.b.r.p.RabbitExchangeQueueProvisioner : declaring queue for inbound: process-stock-change-events.stock-intelligence-processor.process-stock-change-events, bound to: process-stock-change-events.stock-intelligence-processor

o.s.a.r.c.CachingConnectionFactory : Created new connection: SimpleConnection@3de6223a [delegate=amqp://guest@127.0.0.1:5672/, localPort= 58372]
```

以下是一些需要注意的事项：

+   `创建新连接：SimpleConnection@725b3815 [delegate=amqp://guest@127.0.0.1:5672/, localPort= 58373]`：由于我们将`spring-cloud-starter-stream-rabbit`添加到了三个应用程序的类路径中，所以使用的消息代理是 RabbitMQ。

+   `将{transformer:stockIntelligenceProcessorApplication.addOurInventory.transformer}添加为“input”通道的订阅者`：类似于此，每个应用程序的输入和/或输出通道在消息代理上设置。源和处理器应用程序在通道上监听传入消息。

# 日志消息-事件流程

有关处理消息的提取如下所示：

```java
#Source Log
SignificantStockChangeSourceApplication : sending StockPriceChangeEvent [stockTicker=MICROSOFT, oldPrice=15, newPrice=12]

#Transformer Log
.f.StockIntelligenceProcessorApplication : started processing event StockPriceChangeEvent [stockTicker=MICROSOFT, oldPrice=18, newPrice=20]

.f.StockIntelligenceProcessorApplication : ended processing eventWithHoldings StockPriceChangeEventWithHoldings [holdings=30, toString()=StockPriceChangeEvent [stockTicker=MICROSOFT, oldPrice=18, newPrice=20]]

#Sink Log
c.m.s.c.d.f.EventStoreSinkApplication : Received: StockPriceChangeEventWithHoldings [holdings=30, toString()=StockPriceChangeEvent [stockTicker=MICROSOFT, oldPrice=18, newPrice=20]]
```

源应用程序发送`StockPriceChangeEvent`。`Transformer`应用程序接收事件，将持有添加到消息中，并创建新的`StockPriceChangeEventWithHoldings`事件。接收器应用程序接收并记录此消息。

# Spring Cloud Data Flow REST API

Spring Cloud Data Flow 提供了围绕应用程序、流、任务、作业和指标的 RESTful API。可以通过向`http://localhost:9393/`发送`GET`请求来获取完整列表。

以下屏幕截图显示了`GET`请求的响应：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/317bf00f-c9e2-4511-b441-bbe455c25296.png)

所有 API 都是不言自明的。让我们看一个向`http://localhost:9393/streams/definitions`发送`GET`请求的示例：

```java
{  
  "_embedded":{  
  "streamDefinitionResourceList":[  
         {  
            "name":"process-stock-change-events"
            "dslText":"significant-stock-change-source|stock-
            intelligence-processor|event-store-sink",
            "status":"deployed",
            "statusDescription":"All apps have been successfully
             deployed",
            "_links":{  
               "self":{  
                  "href":"http://localhost:9393/streams/definitions/
                   process-stock-change-events"
               }
            }
         }
      ]
   },
   "_links":{  
      "self":{  
         "href":"http://localhost:9393/streams/definitions"
      }
   },
   "page":{
      "size":20,
      "totalElements":1,
      "totalPages":1,
      "number":0
   }
}
```

需要注意的重要事项如下：

+   API 是 RESTful 的。`_embedded`元素包含请求的数据。`_links`元素包含 HATEOAS 链接。页面元素包含分页信息。

+   `_embedded.streamDefinitionResourceList.dslText`包含流的定义`"significant-stock-change-source|stock-intelligence-processor|event-store-sink"`。

+   `_embedded.streamDefinitionResourceList.status`

# Spring Cloud Task

Spring Cloud Data Flow 还可以用于创建和调度批处理应用程序。在过去的十年中，Spring Batch 一直是开发批处理应用程序的首选框架。Spring Cloud Task 扩展了这一点，并使批处理程序可以在云上执行。

让我们使用 Spring Initializr ([`start.spring.io`](https://start.spring.io))来设置应用程序。提供此处列出的详细信息，然后单击“生成项目”：

+   组：`com.mastering.spring.cloud.data.flow`

+   构件：`simple-logging-task`

+   依赖项：`Cloud Task`

使用以下代码更新`SimpleLoggingTaskApplication`类：

```java
@SpringBootApplication
@EnableTask

public class SimpleLoggingTaskApplication {

@Bean
public CommandLineRunner commandLineRunner() {
  return strings -> System.out.println(
  "Task execution :" + new SimpleDateFormat().format(new Date()));
  }
public static void main(String[] args) {
  SpringApplication.run(SimpleLoggingTaskApplication.class, args);
  }
}
```

此代码只是将当前时间戳与 sysout 放在一起。`@EnableTask`注解在 Spring Boot 应用程序中启用任务功能。

我们可以使用以下命令在数据流 shell 上注册任务：

```java
app register --name simple-logging-task --type task --uri maven://com.mastering.spring.cloud.data.flow:simple-logging-task:jar:0.0.1-SNAPSHOT
task create --name simple-logging-task-definition --definition "simple-logging-task"
```

这些命令与用于注册我们之前创建的流应用程序的命令非常相似。我们正在添加一个任务定义，以便能够执行该任务。

可以使用以下命令启动任务：

```java
task launch simple-logging-task-definition
```

任务执行也可以在 Spring Cloud Flow 仪表板上触发和监视。

# 摘要

Spring Cloud Data Flow 为数据流和事件流带来了云原生功能。它使得在云上创建和部署流变得容易。在本章中，我们介绍了如何使用 Spring Cloud Stream 设置事件驱动流中的单个应用程序。我们以 1000 英尺的视角来创建具有 Spring Cloud Task 的任务。我们使用 Spring Cloud Data Flow 来设置流，还执行简单任务。

在下一章中，我们将开始了解构建 Web 应用程序的新方法--响应式风格。我们将了解为什么非阻塞应用程序备受推崇，以及如何使用 Spring Reactive 构建响应式应用程序。


# 第十一章：响应式编程

在前一章中，我们讨论了使用 Spring Cloud Data Flow 在微服务中实现典型的数据流使用案例。

函数式编程标志着从传统的命令式编程转向更声明式的编程风格。响应式编程建立在函数式编程之上，提供了一种替代的风格。

在本章中，我们将讨论响应式编程的基础知识。

微服务架构促进基于消息的通信。响应式编程的一个重要原则是围绕事件（或消息）构建应用程序。我们需要回答一些重要的问题，包括以下内容：

+   什么是响应式编程？

+   典型的使用案例是什么？

+   Java 为响应式编程提供了什么样的支持？

+   Spring WebFlux 中的响应式特性是什么？

# 响应式宣言

几年前的大多数应用程序都有以下的奢侈条件：

+   多秒级的响应时间

+   多个小时的离线维护

+   较小的数据量

时代已经改变。新设备（手机、平板等）和新的方法（基于云的）已经出现。在今天的世界中，我们正在谈论：

+   亚秒级的响应时间

+   100%的可用性

+   数据量呈指数增长

在过去几年中出现了不同的方法来应对这些新兴挑战。虽然响应式编程并不是一个真正新的现象，但它是成功应对这些挑战的方法之一。

响应式宣言（[`www.reactivemanifesto.org`](http://www.reactivemanifesto.org)）旨在捕捉共同的主题。

我们相信需要一个连贯的系统架构方法，并且我们相信所有必要的方面已经被单独认可：我们希望系统具有响应性、弹性、弹性和消息驱动。我们称这些为响应式系统。

构建为响应式系统的系统更加灵活、松散耦合和可扩展。这使得它们更容易开发和适应变化。它们对故障更具有容忍性，当故障发生时，它们以优雅的方式而不是灾难性地应对。响应式系统具有高度的响应性，为用户提供有效的交互反馈。

虽然响应式宣言清楚地阐述了响应式系统的特性，但对于响应式系统的构建方式并不是很清晰。

# 响应式系统的特点

以下图显示了响应式系统的重要特点：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/9d3c539b-22ee-49c8-a5e4-6b23bd5a740c.png)

重要特点如下：

+   **响应性**：系统对用户做出及时的响应。设置了明确的响应时间要求，并且系统在所有情况下都满足这些要求。

+   **弹性**：分布式系统是使用多个组件构建的。任何一个组件都可能发生故障。响应式系统应该被设计成在局部空间内包含故障，例如在每个组件内。这可以防止整个系统在局部故障的情况下崩溃。

+   **弹性**：响应式系统在不同负载下保持响应。在高负载下，这些系统可以添加额外的资源，而在负载减少时释放资源。弹性是通过使用通用硬件和软件实现的。

+   **消息驱动**：响应式系统由消息（或事件）驱动。这确保了组件之间的低耦合。这保证了系统的不同组件可以独立扩展。使用非阻塞通信确保线程的生存时间更短。

响应式系统对不同类型的刺激做出响应。一些例子如下：

+   **对事件做出反应**：基于消息传递构建，响应式系统对事件做出快速响应。

+   **对负载做出反应**：响应式系统在不同负载下保持响应。在高负载下使用更多资源，在较低负载下释放资源。

+   **对故障做出反应**：反应式系统可以优雅地处理故障。反应式系统的组件被构建为局部化故障。外部组件用于监视组件的可用性，并在需要时复制组件。

+   **对用户做出反应**：反应式系统对用户做出响应。当消费者未订阅特定事件时，它们不会浪费时间执行额外的处理。

# 反应式用例 - 股票价格页面

虽然反应式宣言帮助我们理解反应式系统的特性，但它并不能真正帮助我们理解反应式系统是如何构建的。为了理解这一点，我们将考虑构建一个简单用例的传统方法，并将其与反应式方法进行比较。

我们要构建的用例是一个显示特定股票价格的股票价格页面。只要页面保持打开状态，我们希望在页面上更新股票的最新价格。

# 传统方法

传统方法使用轮询来检查股票价格是否发生变化。以下的序列图展示了构建这样一个用例的传统方法：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/e04c7836-703e-4344-a494-edd4c03f1f71.png)

页面渲染后，会定期向股票价格服务发送获取最新价格的 AJAX 请求。这些调用必须进行，无论股票价格是否发生变化，因为网页不知道股票价格的变化。

# 反应式方法

反应式方法涉及连接不同的组件，以便能够对事件做出反应。

当股票价格网页加载时，网页会注册股票价格服务的事件。当股票价格变化事件发生时，会触发一个事件。最新的股票价格会更新在网页上。以下的序列图展示了构建股票价格页面的反应式方法：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/47c7ae5a-4b29-4a4c-b5f7-276764b31395.png)

反应式方法通常包括三个步骤：

1.  订阅事件。

1.  事件的发生。

1.  注销。

当股票价格网页最初加载时，它会订阅股票价格变化事件。订阅的方式根据使用的反应式框架和/或消息代理（如果有）而有所不同。

当特定股票的股票价格变化事件发生时，会为所有订阅者触发一个新的事件。监听器确保网页上显示最新的股票价格。

一旦网页关闭（或刷新），订阅者会发送注销请求。

# 传统方法和反应式方法之间的比较

传统方法非常简单。反应式方法需要实现反应式订阅和事件链。如果事件链涉及消息代理，它会变得更加复杂。

在传统方法中，我们轮询变化。这意味着每分钟（或指定的间隔）都会触发整个序列，无论股票价格是否发生变化。在反应式方法中，一旦我们注册了事件，只有当股票价格发生变化时才会触发序列。

传统方法中线程的生命周期更长。线程使用的所有资源会被锁定更长时间。考虑到服务器同时为多个请求提供服务的整体情况，线程和它们的资源会有更多的竞争。在反应式方法中，线程的生命周期较短，因此资源的竞争较少。

传统方法中的扩展涉及扩展数据库并创建更多的 Web 服务器。由于线程的寿命很短，反应式方法可以处理更多用户。虽然反应式方法具有传统方法的所有扩展选项，但它提供了更多的分布式选项。例如，股价变动事件的触发可以通过消息代理与应用程序通信，如下图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/35f65ad1-5374-4f11-ae12-452937d91766.png)

这意味着 Web 应用程序和股价变动触发的应用程序可以独立扩展。这在需要时提供了更多的扩展选项。

# Java 中的反应式编程

Java 8 没有内置对反应式编程的支持。许多框架提供了反应式功能。我们将在后续章节中讨论反应式流、Reactor 和 Spring WebFlux。

# 反应式流

反应式流是一项旨在提供异步流处理和非阻塞背压标准的倡议。这包括针对运行时环境（JVM 和 JavaScript）以及网络协议的努力。

需要注意的一些重要事项如下：

+   反应式流旨在定义一组最小的接口、方法和协议，以实现反应式编程

+   反应式流旨在成为一种与语言无关的方法，实现在 Java（基于 JVM）和 JavaScript 语言中

+   支持多个传输流（TCP、UDP、HTTP 和 WebSockets）

反应式流的 Maven 依赖关系如下所示：

```java
    <dependency>
      <groupId>org.reactivestreams</groupId>
      <artifactId>reactive-streams</artifactId>
      <version>1.0.0</version>
    </dependency>

    <dependency>
      <groupId>org.reactivestreams</groupId>
      <artifactId>reactive-streams-tck</artifactId>
      <version>1.0.0</version>
      <scope>test</scope>
    </dependency>
```

在 Reactive Streams 中定义的一些重要接口如下所示：

```java
    public interface Subscriber<T> {
      public void onSubscribe(Subscription s);
      public void onNext(T t);
      public void onError(Throwable t);
      public void onComplete();
    }
   public interface Publisher<T> {
     public void subscribe(Subscriber<? super T> s);
   }
   public interface Subscription {
     public void request(long n);
     public void cancel();
  }
```

需要注意的一些重要事项如下：

+   **接口发布者**：`Publisher`根据其订阅者的需求提供元素流。一个发布者可以为任意数量的订阅者提供服务。订阅者数量可能会随时间变化。

+   **接口订阅者**：`Subscriber`注册以监听事件流。订阅是一个两步过程。第一步是调用 Publisher.subscribe(Subscriber)。第二步涉及调用 Subscription.request(long)。完成这些步骤后，订阅者可以使用`onNext(T t)`方法开始处理通知。`onComplete()`方法表示通知的结束。每当`Subscriber`实例能够处理更多时，可以通过 Subscription.request(long)发出需求信号。

+   **接口订阅**：`Subscription`表示`Subscriber`和其`Publisher`之间的链接。订阅者可以使用`request(long n)`请求更多数据。它可以使用`cancel()`方法取消通知的订阅。

# Reactor

Reactor 是 Spring Pivotal 团队的一个反应式框架。它建立在 Reactive Streams 之上。正如我们将在本章后面讨论的那样，Spring Framework 5.0 使用 Reactor 框架来实现反应式 Web 功能。

Reactor 的依赖关系如下所示：

```java
    <dependency>
      <groupId>io.projectreactor</groupId>
      <artifactId>reactor-core</artifactId>
      <version>3.0.6.RELEASE</version>
   </dependency>
   <dependency>
     <groupId>io.projectreactor.addons</groupId>
     <artifactId>reactor-test</artifactId>
     <version>3.0.6.RELEASE</version>
  </dependency>
```

Reactor 在`Subscriber`、`Consumer`和`Subscriptions`术语的基础上增加了一些重要的内容。

+   **Flux**：Flux 表示发出 0 到*n*个元素的反应式流

+   **Mono**：Mono 表示发出零个或一个元素的反应式流

在后续的示例中，我们将创建存根 Mono 和 Flux 对象，这些对象将预先配置为在特定时间间隔内发出元素。我们将创建消费者（或观察者）来监听这些事件并对其做出反应。

# Mono

创建 Mono 非常简单。以下 Mono 在 5 秒延迟后发出一个元素。

```java
   Mono<String> stubMonoWithADelay = 
   Mono.just("Ranga").delayElement(Duration.ofSeconds(5));
```

我们希望从 Mono 中监听事件并将其记录到控制台。我们可以使用此处指定的语句来实现：

```java
    stubMonoWithADelay.subscribe(System.out::println);
```

但是，如果您在以下代码中以`Test`注释运行程序，并运行前面两个语句，您会发现控制台上没有打印任何内容：

```java
    @Test
    public void monoExample() throws InterruptedException {
      Mono<String> stubMonoWithADelay =   
      Mono.just("Ranga").delayElement(Duration.ofSeconds(5));
      stubMonoWithADelay.subscribe(System.out::println);
     }
```

由于`Test`执行在 Mono 在 5 秒后发出元素之前结束，因此不会打印任何内容到控制台。为了防止这种情况，让我们使用`Thread.sleep`延迟`Test`的执行：

```java
    @Test
    public void monoExample() throws InterruptedException {
      Mono<String> stubMonoWithADelay = 
      Mono.just("Ranga").delayElement(Duration.ofSeconds(5));
      stubMonoWithADelay.subscribe(System.out::println);
      Thread.sleep(10000);
    }
```

当我们使用`stubMonoWithADelay.subscribe(System.out::println)`创建一个订阅者时，我们使用了 Java 8 引入的函数式编程特性。`System.out::println`是一个方法定义。我们将方法定义作为参数传递给一个方法。

这是因为有一个特定的函数接口叫做`Consumer`。函数接口是只有一个方法的接口。`Consumer`函数接口用于定义接受单个输入参数并返回无结果的操作。`Consumer`接口的概要显示在以下代码片段中：

```java
     @FunctionalInterface
     public interface Consumer<T> {
       void accept(T t); 
     }
```

我们可以明确定义`Consumer`，而不是使用 lambda 表达式。以下代码片段显示了重要细节：

```java
    class SystemOutConsumer implements Consumer<String> {
      @Override
      public void accept(String t) {
        System.out.println("Received " + t + " at " + new Date());
      }
    }
    @Test
    public void monoExample() throws InterruptedException {
      Mono<String> stubMonoWithADelay = 
      Mono.just("Ranga").delayElement(Duration.ofSeconds(5));
      stubMonoWithADelay.subscribe(new SystemOutConsumer());
      Thread.sleep(10000);
     }
```

重要事项如下：

+   `class SystemOutConsumer implements Consumer<String>`：我们创建了一个实现函数接口`Consumer`的`SystemOutConsumer`类。输入类型为`String`。

+   `public void accept(String t)`：我们定义 accept 方法来将字符串的内容打印到控制台。

+   `stubMonoWithADelay.subscribe(new SystemOutConsumer())`：我们创建了一个`SystemOutConsumer`的实例来订阅事件。

输出显示在以下截图中：

！[](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/3b65fe68-87d9-492d-92c8-e84f58c56aa0.png)

我们可以有多个订阅者监听来自 Mono 或 Flux 的事件。以下代码片段显示了如何创建额外的订阅者：

```java
    class WelcomeConsumer implements Consumer<String> {
      @Override
      public void accept(String t) {
        System.out.println("Welcome " + t);
      } 
    }
    @Test
    public void monoExample() throws InterruptedException {
      Mono<String> stubMonoWithADelay = 
      Mono.just("Ranga").delayElement(Duration.ofSeconds(5));
      stubMonoWithADelay.subscribe(new SystemOutConsumer());
      stubMonoWithADelay.subscribe(new WelcomeConsumer());
      Thread.sleep(10000);
    }
```

重要事项如下：

+   `class WelcomeConsumer implements Consumer<String>`：我们正在创建另一个 Consumer 类，`WelcomeConsumer`

+   `stubMonoWithADelay.subscribe(new WelcomeConsumer())`：我们将`WelcomeConsumer`的一个实例添加为 Mono 事件的订阅者

输出显示在以下截图中：

！[](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/7891d557-00d5-4703-8345-60f1c0a992c7.png)

# Flux

Flux 代表一个发出 0 到*n*个元素的响应流。以下代码片段显示了一个简单的 Flux 示例：

```java
    @Test
    public void simpleFluxStream() {
      Flux<String> stubFluxStream = Flux.just("Jane", "Joe");
      stubFluxStream.subscribe(new SystemOutConsumer());  
    }
```

重要事项如下：

+   `Flux<String> stubFluxStream = Flux.just("Jane", "Joe")`：我们使用`Flux.just`方法创建了一个 Flux。它可以创建包含硬编码元素的简单流。

+   `stubFluxStream.subscribe(new SystemOutConsumer())`：我们在 Flux 上注册了一个`SystemOutConsumer`的实例作为订阅者。

输出显示在以下截图中：

！[](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/f724d985-4bd0-47c0-8f7e-d1557589bc63.png)

以下代码片段显示了一个具有两个订阅者的 Flux 的更复杂的示例：

```java
    private static List<String> streamOfNames = 
    Arrays.asList("Ranga", "Adam", "Joe", "Doe", "Jane");
    @Test
    public void fluxStreamWithDelay() throws InterruptedException {
      Flux<String> stubFluxWithNames = 
      Flux.fromIterable(streamOfNames)
     .delayElements(Duration.ofMillis(1000));
      stubFluxWithNames.subscribe(new SystemOutConsumer());
      stubFluxWithNames.subscribe(new WelcomeConsumer());
      Thread.sleep(10000);
    }
```

重要事项如下：

+   `Flux.fromIterable(streamOfNames).delayElements(Duration.ofMillis(1000))`：从指定的字符串列表创建一个 Flux。元素在指定的 1000 毫秒延迟后发出。

+   `stubFluxWithNames.subscribe(new SystemOutConsumer())`和`stubFluxWithNames.subscribe(new WelcomeConsumer())`：我们在 Flux 上注册了两个订阅者。

+   `Thread.sleep(10000)`：与第一个 Mono 示例类似，我们引入了 sleep 来使程序等待直到 Flux 发出的所有元素都被发出。

输出显示在以下截图中：

！[](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/b955cd0f-3580-4d92-8759-2b6755b67939.png)

# Spring Web Reactive

**Spring Web Reactive**是 Spring Framework 5 中的一个重要新功能。它为 Web 应用程序带来了响应式能力。

Spring Web Reactive 基于与 Spring MVC 相同的基本编程模型。以下表格提供了两个框架的快速比较：

| . | **Spring MVC** | **Spring Web Reactive** |
| --- | --- | --- |
| **用途** | 传统的 Web 应用程序 | 响应式 Web 应用程序 |
| **编程模型** | `@Controller` with `@RequestMapping` | 与 Spring MVC 相同 |
| **基本 API** | Servlet API | 响应式 HTTP |
| **运行在** | Servlet 容器 | Servlet 容器（>3.1）、Netty 和 Undertow |

在随后的步骤中，我们希望为 Spring Web Reactive 实现一个简单的用例。

以下是涉及的重要步骤：

+   使用 Spring Initializr 创建项目

+   创建返回事件流（Flux）的反应式控制器

+   创建 HTML 视图

# 使用 Spring Initializr 创建项目

让我们从使用 Spring Initializr（[`start.spring.io/`](http://start.spring.io/)）创建一个新项目开始。以下屏幕截图显示了详细信息：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/52db8feb-2324-4a34-b015-2a5662b71f89.png)

需要注意的几点如下：

+   组：`com.mastering.spring.reactive`

+   Artifact：`spring-reactive-example`

+   依赖项：`ReactiveWeb`（用于构建反应式 Web 应用程序）和`DevTools`（用于在应用程序代码更改时进行自动重新加载）

下载项目并将其作为 Maven 项目导入到您的 IDE 中。

`pom.xml`文件中的重要依赖项如下所示：

```java
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter</artifactId>
    </dependency>

    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-devtools</artifactId>
   </dependency>

   <dependency>
     <groupId>org.springframework.boot</groupId>
     <artifactId>spring-boot-starter-webflux</artifactId>
   </dependency>

   <dependency>
     <groupId>org.springframework.boot</groupId>
     <artifactId>spring-boot-starter-test</artifactId>
     <scope>test</scope>
   </dependency>
```

`spring-boot-starter-webflux`依赖项是 Spring Web Reactive 的最重要的依赖项。快速查看`spring-boot-starter-webflux`的`pom.xml`文件，可以看到 Spring Reactive 的构建块--`spring-webflux`、`spring-web`和`spring-boot-starter-reactor-netty`。

**Netty**是默认的嵌入式反应式服务器。以下代码段显示了依赖项：

```java
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter</artifactId>
    </dependency>

    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-reactor-netty</artifactId>
    </dependency>

    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
    </dependency>

    <dependency>
      <groupId>org.hibernate</groupId>
      <artifactId>hibernate-validator</artifactId>
    </dependency>

    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-web</artifactId>
    </dependency>

    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-webflux</artifactId>
    </dependency>
```

# 创建一个反应式控制器

创建 Spring Reactive Controller 与创建 Spring MVC Controller 非常相似。基本结构相同：`@RestController`和不同的`@RequestMapping`注解。以下代码段显示了一个名为`StockPriceEventController`的简单反应式控制器：

```java
    @RestController
    public class StockPriceEventController {
      @GetMapping("/stocks/price/{stockCode}")
      Flux<String> retrieveStockPriceHardcoded
      (@PathVariable("stockCode") String stockCode) {
        return Flux.interval(Duration.ofSeconds(5))
        .map(l -> getCurrentDate() + " : " 
        + getRandomNumber(100, 125))
        .log();
      }
     private String getCurrentDate() {
       return (new Date()).toString();
     }
     private int getRandomNumber(int min, int max) {
       return ThreadLocalRandom.current().nextInt(min, max + 1);
     }
    }
```

需要注意的几点如下：

+   `@RestController`和`@GetMapping("/stocks/price/{stockCode}")`：基本结构与 Spring MVC 相同。我们正在创建一个映射到指定 URI 的映射。

+   `Flux<String> retrieveStockPriceHardcoded(@PathVariable("stockCode") String stockCode)`：Flux 表示 0 到*n*个元素的流。返回类型`Flux<String>`表示该方法返回表示股票当前价格的值的流。

+   `Flux.interval().map(l -> getCurrentDate() + " : " + getRandomNumber(100, 125))`：我们正在创建一个硬编码的 Flux，返回一系列随机数。

+   `Duration.ofSeconds(5)`: 每 5 秒返回一次流元素。

+   `Flux.<<****>>.log()`: 在 Flux 上调用`log()`方法有助于观察所有 Reactive Streams 信号并使用 Logger 支持对其进行跟踪。

+   `private String getCurrentDate()`：将当前时间作为字符串返回。

+   `private int getRandomNumber(int min, int max)`：返回`min`和`max`之间的随机数。

# 创建 HTML 视图

在上一步中，我们将 Flux 流映射到`"/stocks/price/{stockCode}"` URL。在这一步中，让我们创建一个视图来在屏幕上显示股票的当前价值。

我们将创建一个简单的静态 HTML 页面（`resources/static/stock-price.html`），其中包含一个按钮，用于开始从流中检索。以下代码段显示了 HTML：

```java
    <p>
      <button id="subscribe-button">Get Latest IBM Price</button>
      <ul id="display"></ul>
    </p>
```

我们想要创建一个 JavaScript 方法来注册到流中，并将新元素附加到特定的 div。以下代码段显示了 JavaScript 方法：

```java
    function registerEventSourceAndAddResponseTo(uri, elementId) {
      var stringEvents = document.getElementById(elementId); 
      var stringEventSource = new (uri);
      stringEventSource.onmessage = function(e) {
        var newElement = document.createElement("li");
        newElement.innerHTML = e.data;
        stringEvents.appendChild(newElement);
      }
    }
```

`EventSource`接口用于接收服务器发送的事件。它通过 HTTP 连接到服务器，并以 text/event-stream 格式接收事件。当它接收到一个元素时，将调用`onmessage`方法。

以下代码段显示了注册获取最新 IBM 价格按钮的 onclick 事件的代码：

```java
    addEvent("click", document.getElementById('subscribe-button'), 
    function() {
            registerEventSourceAndAddResponseTo("/stocks/price/IBM", 
            "display"); 
          }
     );
     function addEvent(evnt, elem, func) {
       if (typeof(EventSource) !== "undefined") {
         elem.addEventListener(evnt,func,false);
       }
       else { // No much to do
         elem[evnt] = func;
       }
    }
```

# 启动 SpringReactiveExampleApplication

将应用类`SpringReactiveExampleApplication`作为 Java 应用程序启动。在启动日志中，您将看到的最后一条消息之一是`Netty started on port(s): 8080`。Netty 是 Spring Reactive 的默认嵌入式服务器。

当您导航到`localhost:8080/static/stock-price.html` URL 时，以下屏幕截图显示了浏览器：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/e5a1fb94-6573-425e-a03e-2efad2b35747.png)

当点击“获取最新的 IBM 价格”按钮时，`EventSource`开始注册从`"/stocks/price/IBM"`接收事件。一旦接收到元素，它就会显示在屏幕上。

下一个截图显示了在接收到一些事件后屏幕上的情况。您可以观察到每隔 5 秒接收到一个事件：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/25d0acd5-4d9f-44b8-b61d-1dc74e9bc9ad.png)

下一个截图显示了在关闭浏览器窗口后日志中的一部分内容：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/f6cdc3b3-48f9-4155-b2e3-364ead91bfa5.png)

您可以观察到一系列`onNext`方法调用，这些调用会在元素可用时触发。当关闭浏览器窗口时，将调用`cancel()`方法来终止流。

在这个例子中，我们创建了一个控制器返回一个事件流（作为`Flux`），并且一个网页使用`EventSource`注册到事件流。在下一个例子中，让我们看看如何将事件流的范围扩展到数据库。

# 响应式数据库

所有普通数据库操作都是阻塞的；也就是说，线程会等待直到从数据库接收到响应。

为了充分利用响应式编程，端到端的通信必须是响应式的，也就是基于事件流的。

**ReactiveMongo**旨在是响应式的，避免阻塞操作。所有操作，包括选择、更新或删除，都会立即返回。数据可以使用事件流流入和流出数据库。

在本节中，我们将使用 Spring Boot 响应式 MongoDB 启动器创建一个简单的示例，连接到 ReactiveMongo。

涉及以下步骤：

1.  集成 Spring Boot 响应式 MongoDB 启动器。

1.  创建股票文档的模型对象。

1.  创建`reactiveCrudRepository`。

1.  使用命令行运行器初始化股票数据。

1.  在 Rest Controller 中创建响应式方法。

1.  更新视图以订阅事件流。

# 集成 Spring Boot 响应式 MongoDB 启动器

为了连接到 ReactiveMongo 数据库，Spring Boot 提供了一个启动项目--Spring Boot 响应式 MongoDB 启动器。让我们将其添加到我们的`pom.xml`文件中：

```java
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-data-mongodb-
        reactive</artifactId>
    </dependency>
```

`spring-boot-starter-data-mongodb-reactive`启动器引入了`spring-data-mongodb`、`mongodb-driver-async`和`mongodb-driver-reactivestreams`依赖项。以下代码片段显示了`spring-boot-starter-data-mongodb-reactive`启动器中的重要依赖项：

```java
    <dependency>
      <groupId>org.springframework.data</groupId>
      <artifactId>spring-data-mongodb</artifactId>
      <exclusions>
       <exclusion>
         <groupId>org.mongodb</groupId>
         <artifactId>mongo-java-driver</artifactId>
       </exclusion>
      <exclusion>
        <groupId>org.slf4j</groupId>
        <artifactId>jcl-over-slf4j</artifactId>
      </exclusion>
     </exclusions>
    </dependency>
    <dependency>
     <groupId>org.mongodb</groupId>
     <artifactId>mongodb-driver</artifactId>
    </dependency>
    <dependency>
     <groupId>org.mongodb</groupId>
     <artifactId>mongodb-driver-async</artifactId>
    </dependency>
    <dependency>
     <groupId>org.mongodb</groupId>
     <artifactId>mongodb-driver-reactivestreams</artifactId>
    </dependency>
    <dependency>
     <groupId>io.projectreactor</groupId>
     <artifactId>reactor-core</artifactId>
    </dependency>
```

`EnableReactiveMongoRepositories`注解启用了 ReactiveMongo 的功能。以下代码片段显示了它被添加到`SpringReactiveExampleApplication`类中：

```java
    @SpringBootApplication
    @EnableReactiveMongoRepositories
    public class SpringReactiveExampleApplication {
```

# 创建一个模型对象 - 一个股票文档

我们将创建`Stock`文档类，如下所示。它包含三个成员变量--`code`、`name`和`description`：

```java
    @Document
    public class Stock {
      private String code;
      private String name;
      private String description;
        //Getters, Setters and Constructor  
    }
```

# 创建一个 ReactiveCrudRepository

传统的 Spring Data 存储库是阻塞的。Spring Data 引入了一个新的存储库用于与响应式数据库交互。以下代码显示了`ReactiveCrudRepository`接口中声明的一些重要方法：

```java
    @NoRepositoryBean
    public interface ReactiveCrudRepository<T, ID extends Serializable> 
    extends Repository<T, ID> {
      <S extends T> Mono<S> save(S entity);
      Mono<T> findById(ID id);
      Mono<T> findById(Mono<ID> id);
      Mono<Boolean> existsById(ID id);
      Flux<T> findAll();
      Mono<Long> count();
      Mono<Void> deleteById(ID id);
      Mono<Void> deleteAll();  
     }
```

在前面的接口中的所有方法都是非阻塞的。它们返回的是 Mono 或 Flux，可以在触发事件时用来检索元素。

我们想要为股票文档对象创建一个存储库。以下代码片段显示了`StockMongoReactiveCrudRepository`的定义。我们使用`Stock`作为被管理的文档，并且键的类型为`String`来扩展`ReactiveCrudRepository`：

```java
    public interface StockMongoReactiveCrudRepository 
    extends ReactiveCrudRepository<Stock, String> { 
     }
```

# 使用命令行运行器初始化股票数据

让我们使用命令行运行器向 ReactiveMongo 插入一些数据。以下代码片段显示了添加到`SpringReactiveExampleApplication`的详细信息：

```java
    @Bean
    CommandLineRunner initData(
    StockMongoReactiveCrudRepository mongoRepository) {
      return (p) -> {
      mongoRepository.deleteAll().block();
      mongoRepository.save(
      new Stock("IBM", "IBM Corporation", "Desc")).block();
      mongoRepository.save(
      new Stock("GGL", "Google", "Desc")).block();
      mongoRepository.save(
      new Stock("MST", "Microsoft", "Desc")).block();
     };
    }
```

`mongoRepository.save()`方法用于将`Stock`文档保存到 ReactiveMongo。`block()`方法确保在执行下一条语句之前保存操作已完成。

# 在 Rest Controller 中创建响应式方法

现在我们可以添加控制器方法来使用`StockMongoReactiveCrudRepository`检索详细信息：

```java
    @RestController
    public class StockPriceEventController {
      private final StockMongoReactiveCrudRepository repository;
      public StockPriceEventController(
      StockMongoReactiveCrudRepository repository) {
        this.repository = repository;
     }

   @GetMapping("/stocks")
   Flux<Stock> list() {
     return this.repository.findAll().log();
   }

   @GetMapping("/stocks/{code}")
   Mono<Stock> findById(@PathVariable("code") String code) {
     return this.repository.findById(code).log();
   }
  }
```

以下是一些重要事项需要注意：

+   `private final StockMongoReactiveCrudRepository repository`：`StockMongoReactiveCrudRepository`通过构造函数注入。

+   `@GetMapping("/stocks") Flux<Stock> list()`：公开一个`GET`方法来检索股票列表。返回一个 Flux，表示这将是一个股票流。

+   `@GetMapping("/stocks/{code}") Mono<Stock> findById(@PathVariable("code") String code)`：`findById`返回一个 Mono，表示它将返回 0 或 1 个股票元素。

# 更新视图以订阅事件流

我们希望更新视图，添加新按钮来触发事件以列出所有股票并显示特定股票的详细信息。以下代码显示了要添加到`resources\static\stock-price.html`的代码：

```java
    <button id="list-stocks-button">List All Stocks</button>
    <button id="ibm-stock-details-button">Show IBM Details</button>
```

以下代码片段启用了新按钮的点击事件，触发与它们各自事件的连接：

```java
    <script type="application/javascript">
    addEvent("click", 
    document.getElementById('list-stocks-button'), 
    function() {
      registerEventSourceAndAddResponseTo("/stocks","display"); 
     }
    );
    addEvent("click", 
    document.getElementById('ibm-stock-details-button'), 
    function() {
      registerEventSourceAndAddResponseTo("/stocks/IBM","display"); 
    }
    );
    </script>
```

# 启动 SpringReactiveExampleApplication

启动 MongoDB 和`SpringReactiveExampleApplication`类。以下截图显示了在`http://localhost:8080/static/stock-price.html`加载页面时的屏幕：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/199706d3-6975-4d2b-b217-cdb3cb27bfb5.png)

以下截图显示了单击股票列表时的屏幕：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/4ceb45db-e838-4032-9e23-feda1864ec97.png)

以下截图显示了单击`显示 IBM 详细信息按钮`时的屏幕：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/90b80425-9787-40f4-b9c4-a9fd336c9ad2.png)

# 总结

在本章中，我们快速了解了响应式编程的世界。我们讨论了 Java 响应式世界中的重要框架--Reactive Streams、Reactor 和 Spring Web Flux。我们使用事件流实现了一个简单的网页。

响应式编程并非万能之策。虽然它可能并非所有用例的正确选择，但它是您应该评估的可能选择。它的语言、框架支持和响应式编程的使用处于初期阶段。

在下一章中，我们将继续讨论使用 Spring Framework 开发应用程序的最佳实践。


# 第十二章：Spring 最佳实践

在前几章中，我们讨论了一些 Spring 项目--Spring MVC、Spring Boot、Spring Cloud、Spring Cloud Data Flow 和 Spring Reactive。企业应用程序开发的挑战并不仅仅是选择正确的框架。最大的挑战之一是正确使用这些框架。

在本章中，我们将讨论使用 Spring 框架进行企业应用程序开发的最佳实践。我们将讨论以下相关的最佳实践：

+   企业应用程序的结构

+   Spring 配置

+   管理依赖版本

+   异常处理

+   单元测试

+   集成测试

+   会话管理

+   缓存

+   日志记录

# Maven 标准目录布局

Maven 为所有项目定义了标准目录布局。一旦所有项目采用了这种布局，开发人员就可以轻松地在项目之间切换。

以下截图显示了一个 Web 项目的示例目录布局：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/77e1c8cb-2c06-43ea-9210-4edd6be11c53.png)

以下是一些重要的标准目录：

+   `src/main/java`：所有与应用程序相关的源代码

+   `src/main/resources`：所有与应用程序相关的资源--Spring 上下文文件、属性文件、日志配置等

+   `src/main/webapp`：与 Web 应用程序相关的所有资源--视图文件（JSP、视图模板、静态内容等）

+   `src/test/java`：所有单元测试代码

+   `src/test/resources`：所有与单元测试相关的资源

# 分层架构

**关注点分离**（SoC）是核心设计目标之一。无论应用程序或微服务的大小如何，创建分层架构都是一种良好的实践。

分层架构中的每一层都有一个关注点，并且应该很好地实现它。分层应用程序还有助于简化单元测试。每个层中的代码可以通过模拟以下层来完全进行单元测试。以下图显示了典型微服务/ Web 应用程序中一些重要的层：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/e19c9390-8813-4d6b-8ecb-9ae44c96be43.png)

前面图表中显示的层如下：

+   **呈现层**：在微服务中，呈现层是 Rest 控制器所在的地方。在典型的 Web 应用程序中，该层还包含与视图相关的内容--JSP、模板和静态内容。呈现层与服务层交互。

+   **服务层**：这充当业务层的外观。不同的视图--移动、Web 和平板电脑，可能需要不同类型的数据。服务层了解它们的需求，并根据呈现层提供正确的数据。

+   **业务层**：这是所有业务逻辑的地方。另一个最佳实践是将大部分业务逻辑放入领域模型中。业务层与数据层交互以获取数据，并在其上添加业务逻辑。

+   **持久层**：负责从数据库中检索和存储数据。该层通常包含 JPA 映射或 JDBC 代码。

# 推荐实践

建议为每个层使用不同的 Spring 上下文。这有助于分离每个层的关注点。这也有助于针对特定层的单元测试代码。

应用程序`context.xml`可用于从所有层导入上下文。这可以是在应用程序运行时加载的上下文。以下是一些可能的 Spring 上下文名称：

+   `application-context.xml`

+   `presentation-context.xml`

+   `services-context.xml`

+   `business-context.xml`

+   `persistence-context.xml`

# 重要层的 API 和实现分离

确保应用程序层之间松耦合的另一个最佳实践是在每个层中拥有单独的 API 和实现模块。以下截图显示了具有两个子模块--API 和 impl 的数据层：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/51c87159-b8f4-442c-ad92-f7a2f3e9774d.png)

数据`pom.xml`定义了两个子模块：

```java
    <modules>
      <module>api</module>
      <module>impl</module>
    </modules>
```

`api`模块用于定义数据层提供的接口。`impl`模块用于创建实现。

业务层应该使用数据层的 API 进行构建。业务层不应该依赖于数据层的实现（`impl`模块）。这有助于在两个层之间创建清晰的分离。数据层的实现可以更改而不影响业务层。

以下片段显示了业务层`pom.xml`文件中的一部分内容：

```java
    <dependency>
      <groupId>com.in28minutes.example.layering</groupId>
      <artifactId>data-api</artifactId>
    </dependency>

    <dependency>
      <groupId>com.in28minutes.example.layering</groupId>
      <artifactId>data-impl</artifactId>
      <scope>runtime</scope>
    </dependency>
```

虽然`data-api`依赖项具有默认范围--compile--，但`data-impl`依赖项具有运行时范围。这确保了在编译业务层时`data-impl`模块不可用。

虽然可以为所有层实现单独的`API`和`impl`，但建议至少在业务层中使用。

# 异常处理

有两种类型的异常：

+   **已检查的异常**：当服务方法抛出此异常时，所有使用者方法应该处理或抛出异常

+   **未经检查的异常**：使用者方法不需要处理或抛出服务方法抛出的异常

`RuntimeException`及其所有子类都是未经检查的异常。所有其他异常都是已检查的异常。

已检查的异常会使您的代码难以阅读。请看以下示例：

```java
    PreparedStatement st = null;
    try {
        st = conn.prepareStatement(INSERT_TODO_QUERY);
        st.setString(1, bean.getDescription());
        st.setBoolean(2, bean.isDone());
        st.execute();
        } catch (SQLException e) {
          logger.error("Failed : " + INSERT_TODO_QUERY, e);
          } finally {
            if (st != null) {
              try {
                st.close();
                } catch (SQLException e) {
                // Ignore - nothing to do..
                }
          }
      }
```

`PreparedStatement`类中 execute 方法的声明如下所示：

```java
    boolean execute() throws SQLException
```

`SQLException`是一个已检查的异常。因此，调用`execute()`方法的任何方法都应该处理异常或抛出异常。在前面的示例中，我们使用`try-catch`块处理异常。

# Spring 对异常处理的方法

Spring 对这个问题采取了不同的方法。它使大多数异常变成了未经检查的。代码变得简单：

```java
    jdbcTemplate.update(INSERT_TODO_QUERY, 
    bean.getDescription(),bean.isDone());
```

`JDBCTemplate`中的 update 方法不声明抛出任何异常。

# 推荐的方法

我们建议采用与 Spring 框架类似的方法。在决定从方法中抛出什么异常时，始终要考虑方法的使用者。

方法的使用者是否能对异常做些什么？

在前面的示例中，如果查询执行失败，`consumer`方法将无法做任何事情，除了向用户显示错误页面。在这种情况下，我们不应该复杂化事情并强制使用者处理异常。

我们建议在应用程序中采用以下异常处理方法：

+   考虑使用者。如果方法的使用者除了记录日志或显示错误页面外无法做任何有用的事情，就将其设置为未经检查的异常。

+   在最顶层，通常是表示层，要有`catch all`异常处理来显示错误页面或向使用者发送错误响应。有关实现`catch all`异常处理的更多详细信息，请参阅第三章中的*使用 Spring MVC 构建 Web 应用程序*中的`@ControllerAdvice`。

# 保持 Spring 配置的轻量级

Spring 在注解之前的一个问题是应用程序上下文 XML 文件的大小。应用程序上下文 XML 文件有时会有数百行（有时甚至有数千行）。然而，使用注解后，就不再需要这样长的应用程序上下文 XML 文件了。

我们建议您使用组件扫描来定位和自动装配 bean，而不是在 XML 文件中手动装配 bean。保持应用程序上下文 XML 文件非常小。我们建议您在需要一些与框架相关的配置时使用 Java `@Configuration`。

# 在 ComponentScan 中使用 basePackageClasses 属性

在使用组件扫描时，建议使用`basePackageClasses`属性。以下片段显示了一个示例：

```java
    @ComponentScan(basePackageClasses = ApplicationController.class) 
    public class SomeApplication {
```

`basePackageClasses`属性是`basePackages()`的类型安全替代，用于指定要扫描注释组件的包。将扫描每个指定类的包。

这将确保即使包被重命名或移动，组件扫描也能正常工作。

# 在模式引用中不使用版本号

Spring 可以从依赖项中识别出正确的模式版本。因此，在模式引用中不再需要使用版本号。类片段显示了一个例子：

```java
    <?xml version="1.0" encoding="UTF-8"?>
    <beans 

      xsi:schemaLocation="http://www.springframework.org/schema/beans
      http://www.springframework.org/schema/beans/spring-beans.xsd
      http://www.springframework.org/schema/context/
      http://www.springframework.org/schema/context/spring-
      context.xsd">
      <!-- Other bean definitions-->
    </beans>
```

# 优先使用构造函数注入而不是 setter 注入进行强制依赖项

bean 有两种依赖项：

+   **强制依赖项**：这些是您希望对 bean 可用的依赖项。如果依赖项不可用，您希望上下文加载失败。

+   **可选依赖项**：这些是可选的依赖项。它们并不总是可用。即使这些依赖项不可用，加载上下文也是可以的。

我们建议您使用构造函数注入而不是 setter 注入来连接强制依赖项。这将确保如果缺少强制依赖项，则上下文将无法加载。以下片段显示了一个例子：

```java
    public class SomeClass {
      private MandatoryDependency mandatoryDependency
      private OptionalDependency optionalDependency;
      public SomeClass(MandatoryDependency mandatoryDependency) {
      this.mandatoryDependency = mandatoryDependency;
    }
    public void setOptionalDependency(
    OptionalDependency optionalDependency) {
      this.optionalDependency = optionalDependency;
    }
    //All other logic
   }
```

Spring 文档的摘录（[`docs.spring.io/spring/docs/current/spring-framework-reference/htmlsingle/#beans-constructor-injection`](https://docs.spring.io/spring/docs/current/spring-framework-reference/htmlsingle/#beans-constructor-injection)）如下所示：

Spring 团队通常倡导构造函数注入，因为它使我们能够将应用程序组件实现为不可变对象，并确保所需的依赖项不为空。此外，构造函数注入的组件始终以完全初始化的状态返回给客户端（调用）代码。另外，大量的构造函数参数是糟糕的代码味道，意味着该类可能具有太多的责任，应该进行重构以更好地处理关注点的分离。主要应该仅将 setter 注入用于可以在类内分配合理默认值的可选依赖项。否则，代码使用依赖项的地方必须执行非空检查。setter 注入的一个好处是 setter 方法使该类的对象能够在以后重新配置或重新注入。因此，通过[JMX MBeans](https://docs.spring.io/spring/docs/current/spring-framework-reference/htmlsingle/#jmx)进行管理是 setter 注入的一个引人注目的用例。

# 为 Spring 项目管理依赖项版本

如果您正在使用 Spring Boot，则管理依赖项版本的最简单选项是将`spring-boot-starter-parent`用作父 POM。这是我们在本书中所有项目示例中使用的选项：

```java
    <parent>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-parent</artifactId>
      <version>${spring-boot.version}</version>
      <relativePath /> <!-- lookup parent from repository -->
    </parent>
```

`spring-boot-starter-parent`管理了 200 多个依赖项的版本。在 Spring Boot 发布之前，确保这些依赖项的所有版本能够很好地协同工作。以下是一些受管依赖项的版本：

```java
<activemq.version>5.14.3</activemq.version>
 <ehcache.version>2.10.3</ehcache.version>
 <elasticsearch.version>2.4.4</elasticsearch.version>
 <h2.version>1.4.193</h2.version>
 <jackson.version>2.8.7</jackson.version>
 <jersey.version>2.25.1</jersey.version>
 <junit.version>4.12</junit.version>
 <mockito.version>1.10.19</mockito.version>
 <mongodb.version>3.4.2</mongodb.version>
 <mysql.version>5.1.41</mysql.version>
 <reactor.version>2.0.8.RELEASE</reactor.version>
 <reactor-spring.version>2.0.7.RELEASE</reactor-spring.version>
 <selenium.version>2.53.1</selenium.version>
 <spring.version>4.3.7.RELEASE</spring.version>
 <spring-amqp.version>1.7.1.RELEASE</spring-amqp.version>
 <spring-cloud-connectors.version>1.2.3.RELEASE</spring-cloud-connectors.version>
 <spring-batch.version>3.0.7.RELEASE</spring-batch.version>
 <spring-hateoas.version>0.23.0.RELEASE</spring-hateoas.version>
 <spring-kafka.version>1.1.3.RELEASE</spring-kafka.version>
 <spring-restdocs.version>1.1.2.RELEASE</spring-restdocs.version>
 <spring-security.version>4.2.2.RELEASE</spring-security.version>
<thymeleaf.version>2.1.5.RELEASE</thymeleaf.version>
```

建议您不要覆盖项目 POM 文件中受管依赖项的任何版本。这样可以确保当我们升级 Spring Boot 版本时，我们将获得所有依赖项的最新版本升级。

有时，您必须使用自定义公司 POM 作为父 POM。以下片段显示了如何在这种情况下管理依赖项版本：

```java
    <dependencyManagement>
      <dependencies>
        <dependency>
          <groupId>org.springframework.boot</groupId>
          <artifactId>spring-boot-dependencies</artifactId>
          <version>${spring-boot.version}</version>
          <type>pom</type>
          <scope>import</scope>
        </dependency>
      </dependencies>
    </dependencyManagement>
```

如果您没有使用 Spring Boot，则可以使用 Spring BOM 管理所有基本的 Spring 依赖项：

```java
    <dependencyManagement>
      <dependencies>
        <dependency>
          <groupId>org.springframework</groupId>
          <artifactId>spring-framework-bom</artifactId>
          <version>${org.springframework-version}</version>
          <type>pom</type>
          <scope>import</scope>
        </dependency>
      </dependencies>
    </dependencyManagement>
```

# 单元测试

虽然单元测试的基本目的是查找缺陷，但各层编写单元测试的方法是不同的。在本节中，我们将快速查看各层的单元测试示例和最佳实践。

# 业务层

在为业务层编写测试时，我们建议您避免在单元测试中使用 Spring 框架。这将确保您的测试是框架无关的，并且运行速度更快。

以下是一个在不使用 Spring 框架的情况下编写的单元测试的示例：

```java
    @RunWith(MockitoJUnitRunner.class)
    public class BusinessServiceMockitoTest {
      private static final User DUMMY_USER = new User("dummy");
      @Mock
      private DataService dataService;
      @InjectMocks
      private BusinessService service = new BusinessServiceImpl();
      @Test
      public void testCalculateSum() {
        BDDMockito.given(dataService.retrieveData(
        Matchers.any(User.class)))
        .willReturn(Arrays.asList(
        new Data(10), new Data(15), new Data(25)));
        long sum = service.calculateSum(DUMMY_USER);
        assertEquals(10 + 15 + 25, sum);
       }
     }
```

Spring 框架用于在运行应用程序中连接依赖关系。然而，在您的单元测试中，使用`@InjectMocks` Mockito 注解与`@Mock`结合使用是最佳选择。

# Web 层

Web 层的单元测试涉及测试控制器--REST 和其他。

我们建议以下操作：

+   在构建在 Spring MVC 上的 Web 层中使用 Mock MVC

+   Jersey 测试框架是使用 Jersey 和 JAX-RS 构建的 REST 服务的不错选择

设置 Mock MVC 框架的一个快速示例如下所示：

```java
    @RunWith(SpringRunner.class)
    @WebMvcTest(TodoController.class)
    public class TodoControllerTest {
      @Autowired
      private MockMvc mvc;
      @MockBean
      private TodoService service;
      //Tests
    }
```

使用`@WebMvcTest`将允许我们使用自动装配`MockMvc`并执行 Web 请求。`@WebMVCTest`的一个很棒的特性是它只实例化控制器组件。所有其他 Spring 组件都预期被模拟，并可以使用`@MockBean`进行自动装配。

# 数据层

Spring Boot 为数据层单元测试提供了一个简单的注解`@DataJpaTest`。一个简单的示例如下所示：

```java
    @DataJpaTest
    @RunWith(SpringRunner.class)
    public class UserRepositoryTest {
      @Autowired
      UserRepository userRepository;
      @Autowired
      TestEntityManager entityManager;
     //Test Methods
    }
```

`@DataJpaTest`也可能注入一个`TestEntityManager` bean，它提供了一个专门为测试设计的替代标准 JPA `entityManager`。

如果您想在`@DataJpaTest`之外使用`TestEntityManager`，您也可以使用`@AutoConfigureTestEntityManager`注解。

数据 JPA 测试默认针对嵌入式数据库运行。这确保了测试可以运行多次而不影响数据库。

# 其他最佳实践

我们建议您遵循测试驱动开发（TDD）的方法来开发代码。在编写代码之前编写测试可以清楚地了解正在编写的代码单元的复杂性和依赖关系。根据我的经验，这会导致更好的设计和更好的代码。

我参与的最好的项目认识到单元测试比源代码更重要。应用程序会不断发展。几年前的架构今天已经是遗留的。通过拥有出色的单元测试，我们可以不断重构和改进我们的项目。

一些指导方针列如下：

+   单元测试应该易读。其他开发人员应该能够在不到 15 秒的时间内理解测试。力求编写作为代码文档的测试。

+   单元测试只有在生产代码中存在缺陷时才应该失败。这似乎很简单。然而，如果单元测试使用外部数据，它们可能会在外部数据更改时失败。随着时间的推移，开发人员对单元测试失去信心。

+   单元测试应该运行得很快。慢测试很少运行，失去了单元测试的所有好处。

+   单元测试应该作为持续集成的一部分运行。一旦在版本控制中提交，构建（包括单元测试）应该运行并在失败时通知开发人员。

# 集成测试

虽然单元测试测试特定层，但集成测试用于测试多个层中的代码。为了保持测试的可重复性，我们建议您在集成测试中使用嵌入式数据库而不是真实数据库。

我们建议您为使用嵌入式数据库的集成测试创建一个单独的配置文件。这样可以确保每个开发人员都有自己的数据库来运行测试。让我们看几个简单的例子。

`application.properties`文件：

```java
    app.profiles.active: production
```

`application-production.properties`文件：

```java
    app.jpa.database: MYSQL
    app.datasource.url: <<VALUE>>
    app.datasource.username: <<VALUE>>
    app.datasource.password: <<VALUE>>
```

`application-integration-test.properties`文件：

```java
    app.jpa.database: H2
    app.datasource.url=jdbc:h2:mem:mydb
    app.datasource.username=sa
    app.datasource.pool-size=30
```

我们需要在测试范围内包含 H2 驱动程序依赖项，如下面的代码片段所示：

```java
    <dependency>
      <groupId>mysql</groupId>
      <artifactId>mysql-connector-java</artifactId>
      <scope>runtime</scope>
   </dependency>

   <dependency>
     <groupId>com.h2database</groupId>
     <artifactId>h2</artifactId>
     <scope>test</scope>
   </dependency>
```

使用`@ActiveProfiles("integration-test")`的集成测试示例如下所示。集成测试现在将使用嵌入式数据库运行：

```java
    @ActiveProfiles("integration-test")
    @RunWith(SpringRunner.class)
    @SpringBootTest(classes = Application.class, webEnvironment =    
    SpringBootTest.WebEnvironment.RANDOM_PORT)
    public class TodoControllerIT {
      @LocalServerPort
      private int port;
      private TestRestTemplate template = new TestRestTemplate();
      //Tests
    }
```

集成测试对于能够持续交付可工作软件至关重要。Spring Boot 提供的功能使得实现集成测试变得容易。

# Spring Session

管理会话状态是分发和扩展 Web 应用程序中的重要挑战之一。HTTP 是一种无状态协议。用户与 Web 应用程序的交互状态通常在 HttpSession 中管理。

在会话中尽可能少地保存数据是很重要的。专注于识别和删除会话中不需要的数据。

考虑一个具有三个实例的分布式应用程序，如下所示。每个实例都有自己的本地会话副本：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/78a17650-50c7-4644-b871-65f467952a99.png)

想象一下，用户当前正在从`App Instance 1`提供服务。假设`App Instance 1`关闭，负载均衡器将用户发送到`App Instance 2`。`App Instance 2`不知道`App Instance 1`中可用的会话状态。用户必须重新登录并重新开始。这不是一个良好的用户体验。

Spring Session 提供了将会话存储外部化的功能。Spring Session 提供了将会话状态存储到不同数据存储的替代方法，而不是使用本地 HttpSession：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/1befe8b9-05f2-45a6-8a0a-fb71a5e8e655.png)

Spring Session 还提供了明确的关注点分离。无论使用哪种会话数据存储，应用程序代码都保持不变。我们可以通过配置在会话数据存储之间切换。

# 示例

在此示例中，我们将连接 Spring Session 以使用 Redis 会话存储。虽然将数据放入会话的代码保持不变，但数据将存储到 Redis 而不是 HTTP 会话中。

涉及三个简单的步骤：

1.  添加 Spring Session 的依赖项。

1.  配置过滤器以用 Spring Session 替换 HttpSession。

1.  通过扩展`AbstractHttpSessionApplicationInitializer`启用 Tomcat 的过滤。

# 添加 Spring Session 的依赖项

连接到 Redis 存储的 Spring Session 所需的依赖项是`spring-session-data-redis`和`lettuce-core`：

```java
    <dependency>
      <groupId>org.springframework.session</groupId>
      <artifactId>spring-session-data-redis</artifactId>
      <type>pom</type>
    </dependency>

   <dependency>
     <groupId>io.lettuce</groupId>
     <artifactId>lettuce-core</artifactId>
   </dependency>
```

# 配置过滤器以用 Spring Session 替换 HttpSession

以下配置创建了一个 Servlet 过滤器，用 Spring Session 中的会话实现替换`HTTPSession`--在此示例中为 Redis 数据存储：

```java
    @EnableRedisHttpSession 
    public class ApplicationConfiguration {
      @Bean 
      public LettuceConnectionFactory connectionFactory() {
        return new LettuceConnectionFactory(); 
      } 
   }
```

# 通过扩展 AbstractHttpSessionApplicationInitializer 启用 Tomcat 的过滤

在上一步中，需要在每个请求到 Servlet 容器（Tomcat）上启用 Servlet 过滤器。以下代码段显示了涉及的代码：

```java
    public class Initializer 
    extends AbstractHttpSessionApplicationInitializer {
      public Initializer() {
        super(ApplicationConfiguration.class); 
      }
    }
```

这就是您需要的所有配置。Spring Session 的好处在于，您的应用程序代码与`HTTPSession`通信不会改变！您可以继续使用 HttpSession 接口，但在后台，Spring Session 确保会话数据存储到外部数据存储--在此示例中为 Redis：

```java
    req.getSession().setAttribute(name, value);
```

Spring Session 提供了连接到外部会话存储的简单选项。在外部会话存储上备份会话可以确保用户即使在一个应用程序实例关闭时也能故障转移。

# 缓存

缓存是构建高性能应用程序的必要条件。您不希望一直访问外部服务或数据库。不经常更改的数据可以被缓存。

Spring 提供了透明的机制来连接和使用缓存。启用应用程序缓存涉及以下步骤：

1.  添加 Spring Boot Starter Cache 依赖项。

1.  添加缓存注释。

让我们详细讨论这些。

# 添加 Spring Boot Starter Cache 依赖项

以下代码段显示了`spring-boot-starter-cache`依赖项。它引入了配置缓存所需的所有依赖项和自动配置：

```java
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-cache</artifactId>
    </dependency>
```

# 添加缓存注释

下一步是添加缓存注释，指示何时需要向缓存中添加或删除内容。以下代码段显示了一个示例：

```java
    @Component
    public class ExampleRepository implements Repository {
      @Override
      @Cacheable("something-cache-key")
      public Something getSomething(String id) {
          //Other code
      }
    }
```

支持的一些注释如下：

+   可缓存：用于缓存方法调用的结果。默认实现根据传递给方法的参数构造键。如果在缓存中找到值，则不会调用该方法。

+   `CachePut`：类似于 `@Cacheable`。一个重要的区别是该方法总是被调用，并且结果被放入缓存中。

+   `CacheEvict`：触发从缓存中清除特定元素。通常在元素被删除或更新时执行。

关于 Spring 缓存的另外一些重要事项如下：

+   默认使用的缓存是 ConcurrentHashMap

+   Spring 缓存抽象符合 JSR-107 标准

+   可以自动配置的其他缓存包括 EhCache、Redis 和 Hazelcast

# 日志记录

Spring 和 Spring Boot 依赖于 Commons Logging API。它们不依赖于任何其他日志记录框架。Spring Boot 提供了 starter 来简化特定日志记录框架的配置。

# Logback

Starter `spring-boot-starter-logging` 是使用 Logback 框架所需的全部内容。这个依赖是大多数 starter 中包含的默认日志记录。包括 `spring-boot-starter-web`。依赖关系如下所示：

```java
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-logging</artifactId>
    </dependency>
```

以下片段显示了 `spring-boot-starter-logging` 中包含的 logback 和相关依赖项：

```java
    <dependency>
      <groupId>ch.qos.logback</groupId>
      <artifactId>logback-classic</artifactId>
    </dependency>

    <dependency>
      <groupId>org.slf4j</groupId>
      <artifactId>jcl-over-slf4j</artifactId>
    </dependency>

    <dependency>
      <groupId>org.slf4j</groupId>
      <artifactId>jul-to-slf4j</artifactId>
    </dependency>

    <dependency>
      <groupId>org.slf4j</groupId>
      <artifactId>log4j-over-slf4j</artifactId>
    </dependency>
```

# Log4j2

要使用 Log4j2，我们需要使用 starter `spring-boot-starter-log4j2`。当我们使用 `spring-boot-starter-web` 等 starter 时，我们需要确保在 `spring-boot-starter-logging` 中排除该依赖项。以下片段显示了详细信息：

```java
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter</artifactId>
      <exclusions>
        <exclusion>
          <groupId>org.springframework.boot</groupId>
          <artifactId>spring-boot-starter-logging</artifactId>
        </exclusion>
       </exclusions>
    </dependency>

    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-log4j2</artifactId>
    </dependency>
```

以下片段显示了 `spring-boot-starter-log4j2` starter 中使用的依赖项：

```java
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-slf4j-impl</artifactId>
    </dependency>

   <dependency>
     <groupId>org.apache.logging.log4j</groupId>
     <artifactId>log4j-api</artifactId>
   </dependency>

   <dependency>
     <groupId>org.apache.logging.log4j</groupId>
     <artifactId>log4j-core</artifactId>
   </dependency>

  <dependency>
    <groupId>org.slf4j</groupId>
    <artifactId>jul-to-slf4j</artifactId>
  </dependency>
```

# 框架独立配置

无论使用哪种日志记录框架，Spring Boot 都允许在应用程序属性中进行一些基本配置选项。一些示例如下所示：

```java
   logging.level.org.springframework.web=DEBUG
   logging.level.org.hibernate=ERROR 
   logging.file=<<PATH_TO_LOG_FILE>>
```

在微服务时代，无论您使用哪种框架进行日志记录，我们建议您将日志记录到控制台（而不是文件），并使用集中式日志存储工具来捕获所有微服务实例的日志。

# 摘要

在本章中，我们介绍了开发基于 Spring 的应用程序的一些最佳实践。我们涵盖了在项目结构化方面的最佳实践--分层、遵循 Maven 标准目录布局，并使用`api`和 implementation 模块。我们还讨论了如何将 Spring 配置保持最小化的最佳实践。我们还讨论了与日志记录、缓存、会话管理和异常处理相关的最佳实践。
