# Spring5 高性能实用指南（三）

> 原文：[`zh.annas-archive.org/md5/40194AF6586468BFD8652280B650BA1F`](https://zh.annas-archive.org/md5/40194AF6586468BFD8652280B650BA1F)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：优化 Spring 消息

在上一章中，我们学习了使用**对象关系映射**（**ORM**）框架（如 Hibernate）访问数据库的不同高级方法。我们还学习了在使用 ORM 时如何以最佳方式改进数据库访问。我们研究了 Spring Data 来消除实现**数据访问对象**（**DAO**）接口的样板代码。在本章末尾，我们看到了 Hibernate 的最佳实践。

在本章中，我们将学习 Spring 对消息传递的支持。消息传递是一种非常强大的技术，有助于扩展应用程序，并鼓励我们解耦架构。

Spring 框架提供了广泛的支持，通过简化使用**Java 消息服务**（**JMS**）API 来将消息系统集成到我们的应用程序中，以异步接收消息。消息解决方案可用于从应用程序中的一个点发送消息到已知点，以及从应用程序中的一个点发送消息到许多其他未知点。这相当于面对面分享和通过扩音器向一群人分享东西。如果我们希望将消息发送到一组未知的客户端，那么我们可以使用队列将消息广播给正在监听的人。

以下是本章将涵盖的主题：

+   什么是消息传递？

+   AMQP 是什么？

+   我们为什么需要 AMQP？

+   RabbitMQ

+   Spring 消息配置

# 什么是消息传递？

消息传递是软件组件或应用程序之间交互的一种模式，其中客户端可以向任何其他客户端发送消息，并从任何其他客户端接收消息。

这种消息交换可以使用一个名为**broker**的组件来完成。broker 提供了所有必要的支持和服务来交换消息，同时具有与其他接口交互的能力。这些接口被称为**消息导向中间件**（**MOM**）。以下图表描述了基于 MOM 的消息系统：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-hiperf-spr5/img/68019515-1a5a-4dcd-95fa-0b68d6dfd438.jpg)

使用 AMQP、STOMP 和 XMPP 协议减少开发分布式应用程序的复杂性的消息系统。让我们详细讨论它们：

+   **AMQP**：AMQP 是一种开放的、标准的异步消息系统应用层协议。在 AMQP 中，消息应以二进制格式传输。

+   **STOMP**：**STOMP**代表**简单文本导向消息协议**。STOMP 提供了一个兼容的介质，允许系统与几乎所有可用的消息代理进行通信。

+   **XMPP**：**XMPP**代表**可扩展消息和出席协议**。这是一种基于 XML 的开放标准通信协议，用于消息导向中间件。

# 什么是 AMQP？

**高级消息队列协议**（**AMQP**）是一种开放的标准应用层协议。传输的每个字节都是指定的，这使得它可以在许多其他语言和操作系统架构中使用。因此，这使得它成为一个跨平台兼容的协议。AMQP 受到多个消息代理的支持，如 RabbitMQ、ActiveMQ、Qpid 和 Solace。Spring 提供了基于 AMQP 的消息实现解决方案。Spring 提供了一个模板，用于通过消息代理发送和接收消息。

# JMS API 的问题

JMS API 用于在 Java 平台上发送和接收消息。Spring 通过在 JMS 层周围提供额外的层来支持简化使用 JMS API 的方法。这一层改进了发送和接收消息的过程，还处理连接对象的创建和释放。

开发人员广泛使用 JMS API 来创建基于 Java 的消息系统。使用 JMS API 的主要缺点是平台矛盾，这意味着我们可以使用 JMS API 来开发与基于 Java 的应用程序兼容的消息系统。JMS API 不支持其他编程语言。

# 我们为什么需要 AMQP？

AMQP 是解决 JMS API 问题的解决方案。使用 AMQP 的基本优势在于，它支持消息的交换，不受平台兼容性和消息代理的影响。我们可以使用任何编程语言开发消息系统，仍然可以使用基于 AMQP 的消息代理与每个系统进行通信。

# AMQP 和 JMS API 之间的区别

以下是 AMQP 和 JMS API 之间的一些重要区别：

+   平台兼容性

+   消息模型

+   消息数据类型

+   消息结构

+   消息路由

+   工作流策略

这些在以下部分中有更详细的解释。

# 平台兼容性

JMS 应用程序可以与任何操作系统一起工作，但它们仅支持 Java 平台。如果我们想要开发一个可以与多个系统通信的消息系统，那么所有这些系统都应该使用 Java 编程语言开发。

在使用 AMQP 时，我们可以开发一个可以与不同技术的任何系统进行通信的消息系统。因此，不需要目标系统使用相同的技术进行开发。

# 消息模型

JMS API 提供两种消息模型，即点对点和发布-订阅，用于不同平台系统之间的异步消息传递。

AMQP 支持以下交换类型：直接、主题、扇出和页眉。

# 消息数据类型

JMS API 支持五种标准消息类型：

+   `StreamMessage`

+   `MapMessage`

+   `TextMessage`

+   `ObjectMessage`

+   `BytesMessage`

AMQP 仅支持一种类型的消息——二进制消息；消息必须以二进制格式传输。

# 消息结构

JMS API 消息具有基本结构，包括头部、属性和正文三个部分。它定义了一个标准形式，应该在所有 JMS 提供程序中可移植。

AMQP 消息包括四个部分：头部、属性、正文和页脚。

# 消息路由

对于消息路由，AMQP 也可以用于复杂的路由方案，这是通过路由键和基于目标匹配标准实现的。

JMS API 基于更复杂的路由方案，这些方案基于分层主题和客户端消息选择过滤器。

# 工作流策略

在 AMQP 中，生产者首先需要将消息发送到交换，然后才会转移到队列，而在 JMS 中，不需要交换，因为消息可以直接发送到队列或主题。

# 交换、队列和绑定是什么？

AMQP 处理发布者和消费者。**发布者**发送消息，**消费者**接收消息。消息代理负责这个机制，以确保来自发布者的消息传递到正确的消费者。消息代理使用的两个关键元素是交换和队列。以下图表说明了发布者如何连接到消费者：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-hiperf-spr5/img/181f17de-7122-4001-86b0-ee9ba0b1ec8d.jpg)

让我们了解一下交换、队列和绑定的术语。

# 交换

交换负责接收消息并将其路由到零个或多个队列。每个代理的交换都有一个唯一的名称，以及虚拟主机中的其他一些属性。所使用的消息路由算法取决于交换类型和绑定。正如我们之前提到的，有四种不同类型的交换：直接、主题、扇出和页眉。

# 队列

队列是消息消费者接收消息的组件。队列有一个唯一的名称，以便系统可以引用它们。队列名称可以由应用程序定义，也可以在请求时由代理生成。我们不能使用以`amq.`开头的队列名称，因为它被代理保留用于内部使用。

# 绑定

绑定用于连接队列和交换机。有一些称为**路由键**头的标准头部，经纪人使用它们将消息与队列匹配。每个队列都有一个特定的绑定键，如果该键与路由键头的值匹配，队列将接收消息。

# 介绍 RabbitMQ

RabbitMQ 基于 AMQP，是最广泛使用的轻量级、可靠、可扩展、便携和强大的消息代理之一，使用 Erlang 编写。RabbitMQ 之所以受欢迎的重要原因是它易于设置，并且适合云规模。RabbitMQ 是开源的，并受大多数操作系统和平台支持。使用 RabbitMQ 的应用程序可以通过一个平台中立的、线级协议——AMQP 与其他系统通信。现在，让我们来了解如何配置 RabbitMQ。

# 设置 RabbitMQ 服务器

在开发消息系统之前，我们需要设置一个消息代理，用于处理发送和接收消息。RabbitMQ 是 AMQP 服务器，可以在[`www.rabbitmq.com/download.html`](http://www.rabbitmq.com/download.html)免费下载。

安装 RabbitMQ 服务器后，根据安装路径，您将不得不使用`RABBITMQ_HOME`设置以下系统变量：

```java
RABBITMQ_HOME=D:\Apps\RabbitMQ Server\rabbitmq_server-3.6.0
```

设置好一切后，您可以通过`http://localhost:15672/`访问 RabbitMQ 控制台。

您将看到默认的登录屏幕，您需要输入`guest`作为默认用户名和`guest`作为密码：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-hiperf-spr5/img/bb1ca8ba-d204-4e14-a689-9a788a0d0cd1.png)

登录后，您将看到 RabbitMQ 服务器主页，您可以在那里管理队列、交换和绑定：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-hiperf-spr5/img/cab357f7-c683-4cbb-9d07-2ac6fb4df032.png)

现在，我们将通过一个示例来了解 Spring 应用程序中的消息配置。

# Spring 消息配置

在开始示例之前，我们需要了解配置消息应用程序的基本设置要求。我们将创建一个 RabbitMQ 消息应用程序，并了解配置的不同部分。在 Spring 应用程序中设置消息涉及以下步骤：

1.  配置 RabbitMQ 的 Maven 依赖项

1.  配置 RabbitMQ

1.  创建一个组件来发送和接收消息

# 为 RabbitMQ 配置 Maven 依赖项

让我们从向`pom.xml`添加 RabbitMQ 的依赖开始。以下代码显示了要配置的依赖项：

```java
<dependency>
    <groupId>org.springframework.amqp</groupId>
    <artifactId>spring-rabbit</artifactId>
    <version>${rabbitmq.version}</version>
</dependency>
```

我们已经为 RabbitMQ 添加了依赖项。现在，让我们创建一个类来配置队列、交换和它们之间的绑定。

# 配置 RabbitMQ

现在，我们将通过配置部分来清楚地了解`ConnectionFactory`、`RabbitTemplate`、`Queue`、`Exchange`、`Binding`、消息监听容器和消息转换器的配置。

# 配置 ConnectionFactory

对于`ConnectionFactory`接口，有一个具体的实现`CachingConnectionFactory`，默认情况下创建一个可以由整个应用程序共享的单个连接代理。用于创建`CachingConnectionFactory`的代码如下：

```java
@Bean
public ConnectionFactory connectionFactory() {
        CachingConnectionFactory connectionFactory = new 
        CachingConnectionFactory("localhost");
        connectionFactory.setUsername("guest");
        connectionFactory.setPassword("guest");
        return connectionFactory;
}
```

我们还可以使用`CachingConnectionFactory`配置缓存连接，以及仅通道。我们需要将`cacheMode`属性设置为`CacheMode.CONNECTION`，使用`setCacheMode()`。我们还可以通过使用`setConnectionLimit()`限制允许的连接总数。当设置了此属性并且超过了限制时，`channelCheckoutTimeLimit`用于等待连接变为空闲。

# 配置队列

现在，我们将使用`Queue`类配置一个队列。以下代码创建了一个具有特定名称的队列：

```java
@Bean
public Queue queue() {
    return new Queue(RABBIT_MESSAGE_QUEUE, true);
}
```

上述的`queue()`方法使用`RABBIT_MESSAGE_QUEUE`常量声明了一个具有特定名称的 AMQP 队列。我们还可以使用`durable`标志设置持久性。我们需要将它作为布尔类型与第二个构造函数参数一起传递。

# 配置交换

现在，我们需要创建一个 AMQP 交换，消息生产者将向其发送消息。`Exchange`接口表示一个 AMQP 交换。`Exchange`接口类型有四种实现：`DirectExchange`、`TopicExchange`、`FanoutExchange`和`HeadersExchange`。根据我们的需求，我们可以使用任何交换类型。我们将使用以下代码使用`DirectExchange`：

```java
@Bean
public DirectExchange exchange() {
    return new DirectExchange(RABBIT_MESSAGE_EXCHANGE);
}
```

`exchange()`方法使用在`RABBIT_MESSAGE_EXCHANGE`下定义的特定名称创建`DirectExchange`。我们还可以使用持久性标志设置持久性。我们需要将它作为布尔类型与第二个构造函数参数一起传递。

# 配置绑定

现在，我们需要使用`BindingBuilder`类创建一个绑定，将`queue`连接到`Exchange`。以下代码用于创建绑定：

```java
@Bean
Binding exchangeBinding(DirectExchange directExchange, Queue queue) {
    return BindingBuilder.bind(queue).
        to(directExchange)
        .with(ROUTING_KEY);
}
```

`exchangeBinding()`方法使用`ROUTING_KEY`路由键值创建`queue`和`Exchange`的绑定。

# 配置 RabbitAdmin

`RabbitAdmin`用于声明在启动时需要准备好的交换、队列和绑定。`RabbitAdmin`自动声明队列、交换和绑定。这种自动声明的主要好处是，如果由于某种原因连接断开，它们将在重新建立连接时自动应用。以下代码配置了`RabbitAdmin`：

```java
@Bean
public RabbitAdmin rabbitAdmin() {
    RabbitAdmin admin = new RabbitAdmin(connectionFactory());
    admin.declareQueue(queue());
    admin.declareExchange(exchange());
    admin.declareBinding(exchangeBinding(exchange(), queue()));
    return admin;
}
```

`rabbitAdmin()`将声明`Queue`、`Exchange`和`Binding`。`RabbitAdmin`构造函数使用`connectionFactory()` bean 创建一个实例，它不能为`null`。

`RabbitAdmin`仅在`CachingConnectionFactory`缓存模式为`CHANNEL`（默认情况下）时执行自动声明。这种限制的原因是因为可能会将独占和自动删除队列绑定到连接。

# 配置消息转换器

在监听器接收到消息的确切时间，会发生两个变化步骤。在初始步骤中，传入的 AMQP 消息会使用`MessageConverter`转换为 Spring 消息`Message`。在第二步中，当执行目标方法时，如果需要，消息的有效负载会转换为参数类型。默认情况下，在初始步骤中，使用`MessageConverter`作为 Spring AMQP 的`SimpleMessageConverter`，它处理转换为 String 和`java.io.Serializable`。

在第二步中，默认情况下使用`GenericMessageConverter`进行转换。我们在以下代码中使用了`Jackson2JsonMessageConverter`：

```java
@Bean
public MessageConverter messageConverter() {
    return new Jackson2JsonMessageConverter();
}
```

在下一节中，我们将使用这个消息转换器作为属性来更改默认的消息转换器，同时配置`RabbitTemplate`。

# 创建一个 RabbitTemplate

Spring AMQP 的`RabbitTemplate`提供了基本的 AMQP 操作。以下代码使用`connectionFactory`创建了`RabbitTemplate`的实例：

```java
@Bean
public RabbitTemplate rabbitTemplate() {
    RabbitTemplate template = new RabbitTemplate(connectionFactory());
    template.setRoutingKey(ROUTING_KEY);
    template.setExchange(RABBIT_MESSAGE_EXCHANGE);
    template.setMessageConverter(messageConverter());
    return template;
}
```

`RabbitTemplate`充当生产者发送消息和消费者接收消息的辅助类。

# 配置监听器容器

要异步接收消息，最简单的方法是使用注释的监听器端点。我们将使用`@RabbitListener`注释作为消息`listener`端点。要创建这个`listener`端点，我们必须使用`SimpleRabbitListenerContainerFactory`类配置消息`listener`容器，这是`RabbitListenerContainerFactory`接口的实现。以下代码用于配置`SimpleRabbitListenerContainerFactory`：

```java
@Bean
public SimpleRabbitListenerContainerFactory listenerContainer() {
    SimpleRabbitListenerContainerFactory factory = new 
    SimpleRabbitListenerContainerFactory();
    factory.setConnectionFactory(connectionFactory());
    factory.setMaxConcurrentConsumers(5);
    return factory;
}
```

`listenerContainer()`方法将实例化`SimpleRabbitListenerContainerFactory`。您可以使用`setMaxConcurrentConsumers()`方法的`maxConcurrentConsumers`属性设置最大消费者数量。

以下是包含所有先前讨论的配置方法的类：

```java
@Configuration
@ComponentScan("com.packt.springhighperformance.ch7.bankingapp")
@EnableRabbit
public class RabbitMqConfiguration {

  public static final String RABBIT_MESSAGE_QUEUE = 
  "rabbit.queue.name";
  private static final String RABBIT_MESSAGE_EXCHANGE =     
  "rabbit.exchange.name";
  private static final String ROUTING_KEY = "messages.key";

  @Bean
  public ConnectionFactory connectionFactory() {
    CachingConnectionFactory connectionFactory = new 
    CachingConnectionFactory("127.0.0.1");
    connectionFactory.setUsername("guest");
    connectionFactory.setPassword("guest");
    return connectionFactory;
  }

  @Bean
  public Queue queue() {
    return new Queue(RABBIT_MESSAGE_QUEUE, true);
  }

  @Bean
  public DirectExchange exchange() {
    return new DirectExchange(RABBIT_MESSAGE_EXCHANGE);
  }

  @Bean
  Binding exchangeBinding(DirectExchange directExchange, Queue queue) {
    return 
    BindingBuilder.bind(queue).to(directExchange).with(ROUTING_KEY);
  }

  @Bean
  public RabbitAdmin rabbitAdmin() {
    RabbitAdmin admin = new RabbitAdmin(connectionFactory());
    admin.declareQueue(queue());
    admin.declareExchange(exchange());
    admin.declareBinding(exchangeBinding(exchange(), queue()));
    return admin;
  }

  @Bean
  public MessageConverter messageConverter() {
    return new Jackson2JsonMessageConverter();
  }

  @Bean
  public RabbitTemplate rabbitTemplate() {
    RabbitTemplate template = new RabbitTemplate(connectionFactory());
    template.setRoutingKey(ROUTING_KEY);
    template.setExchange(RABBIT_MESSAGE_EXCHANGE);
    template.setMessageConverter(messageConverter());
    return template;
  }

  @Bean
  public SimpleRabbitListenerContainerFactory listenerContainer() {
    SimpleRabbitListenerContainerFactory factory = new 
    SimpleRabbitListenerContainerFactory();
    factory.setConnectionFactory(connectionFactory());
    factory.setMaxConcurrentConsumers(5);
    return factory;
  }

}
```

# 创建消息接收器

现在，我们将创建一个带有`@RabbitListener`注释方法的`Consumer`监听器类，该方法将从 RabbitMQ 接收消息：

```java
@Service
public class Consumer {

  private static final Logger LOGGER = 
  Logger.getLogger(Consumer.class);

  @RabbitListener(containerFactory = "listenerContainer",
  queues = RabbitMqConfiguration.RABBIT_MESSAGE_QUEUE)
  public void onMessage(Message message) {
      LOGGER.info("Received Message: " + 
      new String(message.getBody()));
    }
}
```

这是消息`listenerContainer`类。每当生产者向`queue`发送消息时，这个类将接收到它，只有带有`@RabbitListener(containerFactory = "listenerContainer", queues = RabbitMqConfiguration.RABBIT_MESSAGE_QUEUE)`注解的方法才会接收到消息。在这个注解中，我们提到了`containerFactory`属性，它指向了在`listenerContainer` bean 中定义的消息监听器工厂。

# 创建消息生产者

为了运行这个应用程序，我们将使用`RabbitTemplate.convertAndSend()`方法来发送消息。这个方法还将自定义的 Java 对象转换为 AMQP 消息，并发送到直接交换。以下`BankAccount`类被创建为一个自定义类来填充消息属性：

```java
public class BankAccount {

    private int accountId;
    private String accountType;

    public BankAccount(int accountId, String accountType) {
        this.accountId = accountId;
        this.accountType = accountType;
    }

    public int getAccountId() {
        return accountId;
    }

    public String getAccountType() {
        return accountType;
    }

    @Override
    public String toString() {
        return "BankAccount{" +
                "Account Id=" + accountId +
                ", Account Type='" + accountType + '\'' +
                '}';
    }
}
```

在下一个类中，我们将使用一些适当的值初始化前面的类，并使用`RabbitTemplate.convertAndSend()`将其发送到交换：

```java
public class Producer {

  private static final Logger LOGGER = 
  Logger.getLogger(Producer.class);

  @SuppressWarnings("resource")
  public static void main(String[] args) {
        ApplicationContext ctx = new 
        AnnotationConfigApplication
        Context(RabbitMqConfiguration.class);
        RabbitTemplate rabbitTemplate = 
        ctx.getBean(RabbitTemplate.class);
        LOGGER.info("Sending bank account information....");
        rabbitTemplate.convertAndSend(new BankAccount(100, "Savings 
        Account"));
        rabbitTemplate.convertAndSend(new BankAccount(101, "Current 
        Account"));

    }

}
```

当我们运行上述代码时，生产者将使用`convertAndSend()`方法发送两个`BankAccount`对象，并显示以下输出：

```java
2018-05-13 19:46:58 INFO Producer:17 - Sending bank account information....
2018-05-13 19:46:58 INFO Consumer:17 - Received Message: {"accountId":100,"accountType":"Savings Account"}
2018-05-13 19:46:58 INFO Consumer:17 - Received Message: {"accountId":101,"accountType":"Current Account"}
```

# 最大化 RabbitMQ 的吞吐量

以下是与最大消息传递吞吐量相关的最佳性能配置选项：

+   保持队列短

+   避免使用懒惰队列

+   避免持久化消息

+   创建多个队列和消费者

+   将队列分成不同的核心

+   禁用确认

+   禁用不必要的插件

# RabbitMQ 的性能和可伸缩性

有许多重要的要点，我们应该考虑实现与 RabbitMQ 的最佳性能：

+   有效载荷消息大小

+   交换管理

+   正确配置预取

+   RabbitMQ HiPE

+   节点的集群

+   禁用 RabbitMQ 统计信息

+   更新 RabbitMQ 库

# 总结

在本章中，我们学习了消息传递的概念。我们还了解了使用消息系统的优势。我们学习了 AMQP。我们通过理解 JMS API 问题了解了 AMQP 的需求。我们还看到了 AMQP 和 JMS API 之间的区别。我们学习了与 AMQP 相关的交换、队列和绑定。我们还学习了 RabbitMQ 的设置方面以及与 Spring 应用程序相关的不同配置。

在下一章中，我们将学习 Java 线程的核心概念，然后我们将转向`java.util.concurrent`包提供的高级线程支持。我们还将学习`java.util.concurrent`的各种类和接口。我们将学习如何使用 Java 线程池来提高性能。我们将学习 Spring 框架提供的有用功能，如任务执行、调度和异步运行。最后，我们将研究 Spring 事务管理与线程以及线程的各种最佳编程实践。


# 第八章：多线程和并发编程

在上一章中，我们学习了如何优化 Spring 消息传递。我们还学习了各种配置技巧，帮助我们提高应用程序的性能。我们还研究了监视和配置 JMS 和 RabbitMQ 以实现最佳性能。

在本章中，我们将介绍 Java 线程的核心概念，然后将转向`java.util.concurrent`包提供的高级线程支持。对于这个包，我们将看到各种类和接口，帮助我们编写多线程和并发编程。我们还将学习如何使用 Java 线程池来提高性能。我们将介绍 Spring 框架提供的有用功能，如任务执行、调度和异步运行。最后，我们将探讨 Spring 事务管理与线程以及线程的各种最佳编程实践。

本章将涵盖以下主题：

+   Java 经典线程

+   `java.util.concurrent`包

+   使用线程池进行异步处理

+   Spring 任务执行和调度

+   Spring 异步

+   Spring 和线程-事务

+   Java 线程最佳编程实践

# Java 经典线程

Java 应用程序通过线程执行，线程是程序内部的独立执行路径。任何 Java 程序至少有一个线程，称为主线程，由 Java 虚拟机（JVM）创建。Java 是一个多线程应用程序，允许在任何特定时间执行多个线程，并且这些线程可以并发地运行，无论是异步还是同步。当多个线程执行时，每个线程的路径可以与其他线程的路径不同。

JVM 为每个线程提供自己的堆栈，以防止线程相互干扰。单独的堆栈帮助线程跟踪它们要执行的下一个指令，这可以与其他线程不同。堆栈还为线程提供了方法参数、局部变量和返回值的副本。

线程存在于一个进程中，并与进程的其他线程共享资源，如内存和打开的文件。在不同线程之间共享资源的能力使它们更容易受到性能要求的影响。在 Java 中，每个线程都是由`java.lang.Thread`类和`java.lang.Runnable`接口创建和控制的。

# 创建线程

线程是 Java 语言中的对象。可以使用以下机制创建线程：

+   创建一个实现`Runnable`接口的类

+   创建一个扩展`Thread`类的类

有两种创建`Runnable`对象的方法。第一种方法是创建一个实现`Runnable`接口的类，如下所示：

```java
public class ThreadExample {
  public static void main(String[] args) {
    Thread t = new Thread(new MyThread());
    t.start();
  }
}
class MyThread implements Runnable {
  private static final Logger LOGGER =     
  Logger.getLogger(MyThread.class);
  public void run() {
    //perform some task
    LOGGER.info("Hello from thread...");
  }
}
```

在 Java 8 之前，我们只能使用这种方式创建`Runnable`对象。但自 Java 8 以来，我们可以使用 Lambda 表达式创建`Runnable`对象。

创建`Runnable`对象后，我们需要将其传递给接受`Runnable`对象作为参数的`Thread`构造函数：

```java
Runnable runnable = () -> LOGGER.info("Hello from thread...");
Thread t = new Thread(runnable);
```

有些构造函数不接受`Runnable`对象作为参数，比如`Thread()`。在这种情况下，我们需要采取另一种方法来创建线程：

```java
public class ThreadExample1 {
  public static void main(String[] args) {
    MyThread t = new MyThread1();
    t.start();
  }

}
class MyThread1 extends Thread {
  private static final Logger LOGGER = 
  Logger.getLogger(MyThread1.class);
  public void run() {
    LOGGER.info("Hello from thread...");
  }
}
```

# 线程生命周期和状态

在处理线程和多线程环境时，了解线程生命周期和状态非常重要。在前面的例子中，我们看到了如何使用`Thread`类和`Runnable`接口创建 Java 线程对象。但是要启动线程，我们必须首先创建线程对象，并调用其`start()`方法来执行`run()`方法作为线程。

以下是 Java 线程生命周期的不同状态：

+   **New**：使用`new`运算符创建线程时，线程处于新状态。在这个阶段，线程还没有启动。

+   **可运行**：当我们调用线程对象的`start()`方法时，线程处于可运行状态。在这个阶段，线程调度程序仍然没有选择它来运行。

+   **运行**：当线程调度程序选择了线程时，线程状态从可运行变为运行。

+   **阻塞/等待**：当线程当前不具备运行资格时，线程状态为阻塞/等待。

+   **终止/死亡**：当线程执行其运行方法时，线程状态被终止/死亡。在这个阶段，它被认为是不活动的。

# 更高级的线程任务

我们已经看到了线程的生命周期和其状态，但线程也支持一些高级任务，比如睡眠、加入和中断。让我们讨论一下：

+   **睡眠**：`sleep()`线程方法可以用来暂停当前线程的执行，指定的时间量。

+   **加入**：`join()`线程方法可以用来暂停当前线程的执行，直到它加入的线程完成其任务。

+   **中断**：`interrupt()`线程方法可以用来打破线程的睡眠或等待状态。如果线程处于睡眠或等待状态，它会抛出`InterruptedException`，否则，它不会中断线程，但会将中断标志设置为 true。

# 同步线程

在多线程应用程序中，可能会出现多个线程尝试访问共享资源并产生错误和意外结果的情况。我们需要确保资源只能被一个线程使用，这可以通过同步来实现。`synchronized`关键字用于实现同步；当我们在 Java 中定义任何同步块时，只有一个线程可以访问该块，其他线程被阻塞，直到在该块内的线程退出该块。

`synchronized`关键字可以与以下不同类型的块一起使用：

+   实例方法

+   静态方法

+   实例方法内的代码块

+   静态方法内的代码块

在 Java 中，同步块会降低性能。我们必须在需要时使用`synchronized`关键字，否则，我们应该只在需要的关键部分使用同步块。

# 多线程问题

多线程是一种非常强大的机制，可以帮助我们更好地利用系统资源，但在读写多个线程共享的数据时，我们需要特别小心。多线程编程有两个基本问题——可见性问题和访问问题。可见性问题发生在一个线程的效果可以被另一个线程看到时。访问问题可能发生在多个线程同时访问相同的共享资源时。

由于可见性和访问问题，程序不再做出反应，导致死锁或生成不正确的数据。

# java.util.concurrent 包

在前一节中，我们专注于 Java 对线程的低级支持。在本节中，我们将继续查看`java.util.concurrent`包提供的 Java 高级线程支持。这个包有各种类和接口，提供非常有用的功能，帮助我们实现多线程和并发编程。在本节中，我们将主要关注这个包的一些最有用的实用工具。

以下图表显示了`java.util.concurrent` API 的高级概述：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-hiperf-spr5/img/bc28c2a8-acac-4718-a085-9dab2fe53a72.png)

让我们详细讨论接口。

# 执行者

`Executor`提供了一个抽象层，用于管理所有内部线程管理任务，并管理线程的整个并发执行流程。`Executor`是一个执行提供的任务的对象。

Java 并发 API 提供了以下三个基本接口用于执行者：

+   `Executor`：这是一个简单的接口，用于启动一个新任务。它不严格要求执行是异步的。

+   `ExecutorService`：这是`Executor`接口的子接口。它允许我们异步地将任务传递给线程执行。它提供了管理先前提交的任务终止的方法，如`shutdown()`、`shutdownNow()`和`awaitTermination(long timeout, TimeUnit unit)`。它还提供了返回`Future`对象以跟踪一个或多个异步任务进度的方法。

+   `ScheduledExecutorService`：这是`ExecutorService`的子接口。它提供了各种关键方法，如`schedule()`、`scheduleAtFixedRate()`和`scheduleWithFixedDelay()`。所有调度方法都可以接受相对延迟和周期作为参数，这有助于我们安排任务在给定延迟或周期后执行。

以下是一个简单示例，演示了如何创建`Executor`以执行`Runnable`任务：

```java
public class ExecutorExample {
    private static final Logger LOGGER = 
    Logger.getLogger(ExecutorExample.class);

    public static void main(String[] args) {
        ExecutorService pool = Executors.newSingleThreadExecutor();

            Runnable task = new Runnable() {
            public void run() {
                LOGGER.info(Thread.currentThread().getName());
            }
        }; 

        pool.execute(task); 
        pool.shutdown();
    }
}
```

在前面的示例中，通过匿名类创建了一个`Runnable`对象，并通过单线程`Executor`接口执行任务。当我们编译和运行上述类时，将得到以下输出：

```java
pool-1-thread-1
```

# ThreadFactory

`ThreadFactory`接口用于按需创建新线程，还帮助我们消除创建线程的大量样板代码。

以下示例显示了如何使用`ThreadFactory`接口创建新线程：

```java
public class ThreadFactoryExample implements ThreadFactory {
  private static final Logger LOGGER =   
  Logger.getLogger(ThreadFactoryExample.class);

  public static void main(String[] args) {
    ThreadFactoryExample factory = new ThreadFactoryExample();

    Runnable task = new Runnable() {
      public void run() {
        LOGGER.info(Thread.currentThread().getName());
      }
    };
    for (int i = 0; i < 5; i++) {
      Thread t = factory.newThread(task);
      t.start();
    }
  }

  @Override
  public Thread newThread(Runnable r) {
    Thread t = new Thread(r);
    return t;
  }
}
```

当我们编译和运行上述类时，将得到以下输出：

```java
Thread-0
Thread-1
```

# 同步器

Java 提供了`synchronized`关键字来编写同步代码，但仅通过`synchronized`关键字正确编写同步代码是困难的。`java.util.concurrent`包提供了各种实用程序类，如`CountDownLatch`、`CyclicBarrier`、`Exchanger`、`Semaphore`和`Phaser`，它们被称为同步器。同步器是提供线程同步的并发实用程序，而无需使用`wait()`和`notify()`方法。让我们看看以下类：

+   `CountDownLatch`：这允许一个线程在一个或多个线程完成之前等待。

+   `CyclicBarrier`：这与`CountdownLatch`非常相似，但它允许多个线程在开始处理之前等待彼此。

+   `信号量`：这维护了一组许可证，用于限制可以访问共享资源的线程数量。线程在访问共享资源之前需要从`信号量`获取许可证。它提供了两个主要方法`acquire()`和`release()`，分别用于获取和释放许可证。

+   `Exchanger`：这提供了一个同步点，线程可以在其中交换对象。

+   `Phaser`：这提供了类似于`CyclicBarrier`和`CountDownLatch`的线程同步机制，但支持更灵活的使用。它允许一组线程在障碍上等待，然后在最后一个线程到达后继续，并且还支持多个执行阶段。

# 并发集合类

并发集合类提供了比其他集合类（如`HashMap`或`Hashtable`）更好的可伸缩性和性能。以下是`java.util.concurrent`包中提供的有用并发类：

+   `ConcurrentHashMap`：这类似于`HashMap`和`Hashtable`，但它被设计为在并发编程中工作，而无需显式同步。`Hashtable`和`ConcurrentHashMap`都是线程安全的集合，但`ConcurrentHashMap`比`Hashtable`更先进。它不会锁定整个集合进行同步，因此在有大量更新和较少并发读取时非常有用。

+   `BlockingQueue`：生产者-消费者模式是异步编程中最常见的设计模式，`BlockingQueue`数据结构在这些异步场景中非常有用。

+   `DelayQueue`：这是一个无限大小的阻塞队列，其中的元素只有在其延迟到期时才能被取出。如果多个元素延迟到期，那么延迟到期时间最长的元素将首先被取出。

# 锁

`Lock`接口提供了比`synchronized`块更高级的锁定机制。`synchronized`块和`Lock`之间的主要区别是`synchronized`块完全包含在一个方法中，而`Lock`接口有单独的`lock()`和`unlock()`方法，可以在不同的方法中调用。

# 可调用和未来

`Callable`接口类似于`Runnable`对象，但它可以返回任何类型的对象，这有助于我们从`Callable`任务中获取结果或状态。

`Callable`任务返回`Future`对象，用于获取异步操作的结果。它的用途包括提供一对方法来检查异步执行是否已完成，并检索计算的结果。

# 原子变量

原子变量是在`java.util.concurrent.atomic`包中引入的非阻塞算法。使用原子变量的主要好处是我们不需要担心同步。在多线程环境中，原子变量是避免数据不一致的必要性。它支持对单个变量进行无锁、线程安全的操作。

# 使用线程池进行异步处理

线程池是多线程编程中的核心概念，用于提供一组空闲线程，可用于执行任务。线程池可以重用先前创建的线程来执行当前任务，以便在请求到达时线程已经可用，这可以减少线程创建的时间并提高应用程序的性能。通常，线程池可以用于 Web 服务器来处理客户端请求，还可以维护到数据库的开放连接。

我们可以配置池中并发线程的最大数量，这对于防止过载很有用。如果所有线程都在执行任务，那么新任务将被放置在队列中，等待线程可用。

Java 并发 API 支持以下类型的线程池：

+   固定线程池：具有固定数量线程的线程池。只有在有线程可用时任务才会执行，否则会在队列中等待。使用`Executors.newFixedThreadPool()`方法来创建固定线程池。

+   缓存线程池：我们可以根据需要创建新线程，但也可以重用先前创建的线程。如果线程空闲了 60 秒，它将被终止并从池中移除。使用`Executors.newCachedThreadPool()`方法来创建缓存线程池。

+   单线程池：一个线程的线程池。它逐个执行任务。使用`Executors.newSingleThreadExecutor()`方法来创建单线程池。

+   分支/合并池：用于更快地执行重型任务的线程池，通过递归地将任务分割成较小的片段。要创建分支/合并池，我们需要创建`ForkJoinPool`类的实例。

以下是固定线程池的一个简单示例：

```java
public class ThreadPoolExample {
  private static final Logger LOGGER = 
  Logger.getLogger(ThreadPoolExample.class);
  public static void main(String[] args) {
    ExecutorService executor = Executors.newFixedThreadPool(3);

    for (int i = 1; i <= 6; i++) {
      Runnable task = new Task(" " + i);
      executor.execute(task);
    }
    executor.shutdown();
    while (!executor.isTerminated()) {
    }
    LOGGER.info("All threads finished");
  }
}
```

以下演示了任务的实现方式：

```java
public class Task implements Runnable {
  private static final Logger LOGGER = Logger.getLogger(Task.class);
  private String taskNumber;

  public Task(String taskNumber) {
    this.taskNumber = taskNumber;
  }

  @Override
  public void run() {
    LOGGER.info(Thread.currentThread().getName() + ", Execute Task = " 
    + taskNumber);
    taskProcess();
    LOGGER.info(Thread.currentThread().getName() + ", End");
  }

  private void taskProcess() {
    try {
      Thread.sleep(2000);
    } catch (InterruptedException e) {
      e.printStackTrace();
    }
  }
}
```

在前面的示例中，我们创建了一个最多有三个并发线程的池，并向`executor`对象提交了`6`个任务。当我们编译和运行前面的类时，我们知道只有三个线程执行任务。

以下是输出：

```java
pool-1-thread-1, Execute Task = 1
pool-1-thread-2, Execute Task = 2
pool-1-thread-3, Execute Task = 3
pool-1-thread-1, End
pool-1-thread-1, Execute Task = 4
pool-1-thread-3, End
pool-1-thread-2, End
pool-1-thread-2, Execute Task = 5
pool-1-thread-3, Execute Task = 6
pool-1-thread-1, End
pool-1-thread-2, End
pool-1-thread-3, End
All threads finished
```

# Spring 任务执行和调度

在任何 Web 应用程序中使用线程处理长时间运行的任务并不容易。有时，我们需要异步运行任务或在特定延迟后运行任务，这可以通过 Spring 的任务执行和调度来实现。Spring 框架引入了用于异步执行和任务调度的抽象，使用`TaskExecutor`和`TaskScheduler`接口。

# TaskExecutor

Spring 提供了`TaskExecutor`接口作为处理`Executor`的抽象。`TaskExecutor`的实现类如下：

+   `SimpleAsyncTaskExecutor`：这启动一个新线程并异步执行。它不重用线程。

+   `SyncTaskExecutor`：这在调用线程中同步执行每个任务。它不重用线程。

+   `ConcurrentTaskExecutor`：这公开了用于配置`java.util.concurrent.Executor`的 bean 属性。

+   `SimpleThreadPoolTaskExecutor`：这是`Quartz`的`SimpleThreadPool`的子类，它监听 Spring 的生命周期回调。

+   `ThreadPoolTaskExecutor`：这公开了用于配置`java.util.concurrent.ThreadPoolExecutor`的 bean 属性，并将其包装在`TaskExecutor`中。

+   `TimerTaskExecutor`：这实现了一个`TimerTask`类作为其后备实现。它在单独的线程中同步执行方法。

+   `WorkManagerTaskExecutor`：这使用`CommonJ`的`WorkManager`接口作为其后备实现。

让我们看一个在 Spring 应用程序中使用`SimpleAsyncTaskExecutor`执行任务的简单示例。它为每个任务提交创建一个新线程并异步运行。

这是配置文件：

```java
@Configuration
public class AppConfig {
  @Bean
  AsyncTask myBean() {
    return new AsyncTask();
  }
  @Bean
  AsyncTaskExecutor taskExecutor() {
    SimpleAsyncTaskExecutor t = new SimpleAsyncTaskExecutor();
    return t;
  }
}
```

这是一个 bean 类，我们已经将`5`个任务分配给了`TaskExecutor`：

```java
public class AsyncTask {
  @Autowired
  private AsyncTaskExecutor executor;
  public void runTasks() throws Exception {
    for (int i = 1; i <= 5; i++) {
      Runnable task = new Task(" " + i);
      executor.execute(task);
    }
  }
}
```

以下是从`main`方法执行任务的代码：

```java
public class TaskExecutorExample {
  public static void main(String[] args) throws Exception {
    ApplicationContext context = new 
    AnnotationConfigApplicationContext(AppConfig.class);
    AsyncTask bean = context.getBean(AsyncTask.class);
    bean.runTasks();
  }
}
```

当我们编译并运行上述类时，将得到以下输出。在这里，我们可以看到创建了五个线程，并且它们异步执行任务：

```java
SimpleAsyncTaskExecutor-1, Execute Task = 1
SimpleAsyncTaskExecutor-4, Execute Task = 4
SimpleAsyncTaskExecutor-3, Execute Task = 3
SimpleAsyncTaskExecutor-2, Execute Task = 2
SimpleAsyncTaskExecutor-5, Execute Task = 5
SimpleAsyncTaskExecutor-2, End
SimpleAsyncTaskExecutor-1, End
SimpleAsyncTaskExecutor-4, End
SimpleAsyncTaskExecutor-3, End
SimpleAsyncTaskExecutor-5, End
```

# TaskScheduler

有时，我们需要按固定间隔执行任务，这可以通过 Spring 调度程序框架实现。在本节中，我们将看到如何使用一些注解在 Spring 中安排任务。

让我们看一个在 Spring 应用程序中安排任务的简单示例：

```java
@Configuration
@EnableScheduling
public class SpringSchedulingExample {
    private static final Logger LOGGER =                                                     
    Logger.getLogger(SpringSchedulingExample.class);
    @Scheduled(fixedDelay = 2000)
    public void scheduledTask() {
        LOGGER.info("Execute task " + new Date());
    }

    public static void main(String[] args) {
        AnnotationConfigApplicationContext context = new 
        AnnotationConfigApplicationContext(
        SpringSchedulingExample.class);
        String scheduledAnnotationProcessor =         
        "org.springframework.context.annotation.
        internalScheduledAnnotationProcessor";
        LOGGER.info("ContainsBean : " + scheduledAnnotationProcessor + 
        ": " + context.containsBean(scheduledAnnotationProcessor));
        try {
            Thread.sleep(12000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        } finally {
            context.close();
        }
    }
} 
```

在 Spring 中，我们可以通过`@EnableScheduling`注解启用任务调度。一旦启用任务调度，Spring 将自动注册一个内部 bean 后处理器，该处理器将在 Spring 管理的 bean 上找到`@Scheduled`注解的方法。

在上一个示例中，我们使用`@Scheduled`注解将`scheduledTask()`方法与`fixedDelay`属性一起注释，以便每`2`秒调用一次。我们还可以使用其他属性，如`fixedRate`和`cron`：

```java
@Scheduled(fixedRate = 2000)
@Scheduled(cron = "*/2 * * * * SAT,SUN,MON")
```

当我们编译并运行上一个类时，将得到以下输出：

```java
Execute task Thu May 10 20:18:04 IST 2018
ContainsBean : org.springframework.context.annotation.internalScheduledAnnotationProcessor: true
Execute task Thu May 10 20:18:06 IST 2018
Execute task Thu May 10 20:18:08 IST 2018
Execute task Thu May 10 20:18:10 IST 2018
Execute task Thu May 10 20:18:12 IST 2018
Execute task Thu May 10 20:18:14 IST 2018
```

# Spring Async

在本节中，我们将看到 Spring 中的异步执行支持。在某些情况下，我们需要异步执行一些任务，因为该任务的结果不需要用户，所以我们可以在单独的线程中处理该任务。异步编程的主要好处是我们可以提高应用程序的性能和响应能力。

Spring 通过`@EnableAsync`和`@Async`提供了异步方法执行的注解支持。让我们详细讨论它们。

# @EnableAsync 注解

我们可以通过简单地将`@EnableAsync`添加到配置类来启用异步处理，如下所示：

```java
@Configuration
@EnableAsync
public class AppConfig {
  @Bean
  public AsyncTask asyncTask() {
    return new AsyncTask();
  }
}
```

在上面的代码中，我们没有将`TaskExecutor`作为 bean 提供，因此 Spring 将隐式地使用默认的`SimpleAsyncTaskExecutor`。

# @Async 注解

一旦启用了异步处理，那么用`@Async`注解标记的方法将异步执行。

以下是`@Async`注解的简单示例：

```java
public class AsyncTask {
  private static final Logger LOGGER = 
  Logger.getLogger(AsyncTask.class);
  @Async
  public void doAsyncTask() {
    try {
      LOGGER.info("Running Async task thread : " + 
      Thread.currentThread().getName());
    } catch (Exception e) {
    }
  }
}
```

我们还可以将`@Async`注解添加到具有返回类型的方法中，如下所示：

```java
@Async
  public Future<String> doAsyncTaskWithReturnType() {
    try 
    {
      return new AsyncResult<String>("Running Async task thread : " + 
      Thread.currentThread().getName());
    } 
    catch (Exception e) { 
    }
    return null;
  }
```

在上面的代码中，我们使用了实现`Future`的`AsyncResult`类。这可以用于获取异步方法执行的结果。

以下是从`main`方法调用异步方法的代码：

```java
public class asyncExample {
  private static final Logger LOGGER = 
  Logger.getLogger(asyncExample.class);
  public static void main(String[] args) throws InterruptedException {
    AnnotationConfigApplicationContext ctx = new 
    AnnotationConfigApplicationContext();
    ctx.register(AppConfig.class);
    ctx.refresh();
    AsyncTask task = ctx.getBean(AsyncTask.class);
    LOGGER.info("calling async method from thread : " + 
    Thread.currentThread().getName());
    task.doAsyncTask();
    LOGGER.info("Continue doing something else. ");
    Thread.sleep(1000);
  }
}
```

当我们编译并运行上述类时，将得到以下输出：

```java
calling async method from thread : main
Continue doing something else. 
Running Async Task thread : SimpleAsyncTaskExecutor-1
```

# @Async 与 CompletableFuture

在上一节中，我们看到了如何使用`java.util.Future`来获取异步方法执行的结果。它提供了一个`isDone()`方法来检查计算是否完成，以及一个`get()`方法在计算完成时检索计算结果。但是使用`Future` API 存在一定的限制：

+   假设我们编写了代码，通过远程 API 从电子商务系统中获取最新的产品价格。这个任务很耗时，所以我们需要异步运行它，并使用`Future`来获取该任务的结果。现在，当远程 API 服务宕机时，问题就会出现。这时，我们需要手动完成`Future`，使用产品的最后缓存价格，这是`Future`无法实现的。

+   `Future`只提供一个`get()`方法，当结果可用时通知我们。我们无法将回调函数附加到`Future`，并在`Future`结果可用时自动调用它。

+   有时我们有需求，比如需要将长时间运行任务的结果发送给另一个长时间运行的任务。我们无法使用`Future`创建这样的异步工作流。

+   我们无法并行运行多个`Future`。

+   `Future` API 没有任何异常处理。

由于这些限制，Java 8 引入了比`java.util.Future`更好的抽象，称为`CompletableFuture`。我们可以使用以下无参构造函数简单地创建`CompletableFuture`：

```java
CompletableFuture<String> completableFuture = new CompletableFuture<String>();
```

以下是`CompletableFuture`提供的方法列表，帮助我们解决`Future`的限制：

+   `complete()`方法用于手动完成任务。

+   `runAsync()`方法用于异步运行不返回任何内容的后台任务。它接受一个`Runnable`对象并返回`CompletableFuture<Void>`。

+   `supplyAsync()`方法用于异步运行后台任务并返回一个值。它接受`Supplier<T>`并返回`CompletableFuture<T>`，其中`T`是供应商提供的值的类型。

+   `thenApply()`、`thenAccept()`和`thenRun()`方法用于将回调附加到`CompletableFuture`。

+   `thenCompose()`方法用于将两个依赖的`CompletableFuture`组合在一起。

+   `thenCombine()`方法用于将两个独立的`CompletableFuture`组合在一起。

+   `allOf()`和`anyOf()`方法用于将多个`CompletableFuture`组合在一起。

+   `exceptionally()`方法用于从`Future`获取生成的错误。我们可以记录错误并设置默认值。

+   `handle()`方法用于处理异常。

# Spring 和线程-事务

Spring 框架为数据库事务管理提供了广泛的 API。Spring 负责所有基本的事务管理控制，并为不同的事务 API 提供了一致的编程模型，如 JDBC、Hibernate、Java Transaction API（JTA）、Java Persistence API（JPA）和 Java Data Objects（JDO）。Spring 提供了两种类型的事务：一种是声明式的，另一种是编程式的事务管理。声明式的层次很高，而编程式的更高级但更灵活。

Spring 事务管理在单个线程中运行得很好。但它无法管理跨多个线程的事务。如果我们尝试在多个线程中使用事务，我们的程序会给出运行时错误或意外结果。

要理解为什么 Spring 事务在多个线程中失败，首先，我们需要了解 Spring 如何处理事务。Spring 将所有事务信息存储在`org.springframework.transaction.support.TransactionSynchronizationManager`类内的`ThreadLocal`变量中：

```java
public abstract class TransactionSynchronizationManager {
  private static final Log logger =         
  LogFactory.getLog(TransactionSynchronizationManager.class);
  private static final ThreadLocal<Map<Object, Object>> resources = new  
  NamedThreadLocal("Transactional resources");
  private static final ThreadLocal<Set<TransactionSynchronization>> 
  synchronizations = new NamedThreadLocal("Transaction 
  synchronizations");
  private static final ThreadLocal<String> currentTransactionName = new 
  NamedThreadLocal("Current transaction name");
  private static final ThreadLocal<Boolean> currentTransactionReadOnly 
  = new NamedThreadLocal("Current transaction read-only status");
  private static final ThreadLocal<Integer> 
  currentTransactionIsolationLevel = new NamedThreadLocal("Current 
  transaction isolation level");
  private static final ThreadLocal<Boolean> actualTransactionActive = 
  new NamedThreadLocal("Actual transaction active");
}
```

线程的局部变量仅保存特定事务的信息，仅限于单个线程，不能被另一个线程访问。因此，正在进行的事务信息不会传递给新创建的线程。结果将是一个错误，指示事务丢失。

现在我们能够理解 Spring 事务在多个线程中的问题。Spring 无法将事务状态保持到旧线程，以便从新创建的线程中访问。为了解决多线程的事务问题，我们需要手动将线程的局部变量值传递给新创建的线程。

# Java 线程最佳编程实践

使用多线程和并发编程的目的是提高性能，但我们需要始终记住速度是在正确性之后。Java 编程语言从语言到 API 级别提供了大量的同步和并发支持，但这取决于个人在编写无错误的 Java 并发代码方面的专业知识。以下是 Java 并发和多线程的最佳实践，这有助于我们在 Java 中编写更好的并发代码：

+   **使用不可变类**：在多线程编程中，我们应该始终优先使用不可变类，因为不可变类确保在操作中值不会在没有使用同步块的情况下更改。例如，在不可变类中，如`java.lang.String`，对`String`的任何修改，如添加内容或转换为大写，总是创建另一个字符串对象，保持原始对象不变。

+   **使用局部变量**：始终尝试使用局部变量而不是实例或类级变量，因为局部变量永远不会在线程之间共享。

+   **使用线程池**：线程池可以重用先前创建的线程，并消除线程创建的时间，从而提高应用程序的性能。

+   **使用同步工具**：在这里，我们可以使用同步工具而不是`wait`和`notify`方法。`java.util.concurrent`包提供了更好的同步工具，如`CycicBariier`、`CountDownLatch`、`Sempahore`和`BlockingQueue`。使用`CountDownLatch`等待五个线程完成任务比使用`wait`和`notify`方法实现相同的工具更容易。使用`BlockingQueue`更容易实现生产者-消费者设计，而不是使用`wait`和`notify`方法。

+   **使用并发集合而不是同步集合**：并发集合是使用`Lock`接口提供的新锁定机制实现的，并且设计成这样，我们可以利用底层硬件和 JVM 提供的本机并发构造。并发集合比它们的同步对应物具有更好的可伸缩性和性能。如果有许多并发更新和较少读取，`ConcurrentHashMap`比同步的`HashMap`或`Hashtable`类提供更好的性能。

+   **最小化锁定范围**：我们应该尽量减少锁定范围，因为锁定块不会同时执行，并且会影响应用程序的性能。如果我们的需求无法满足，首先尝试使用原子和易失性变量来实现我们的同步需求，然后需要使用`Lock`接口提供的功能。我们还可以减少锁定范围，使用同步块而不是同步方法。

+   **使用 Java Executor 框架**：它在 Java 线程框架上提供了一个抽象层，并在多线程环境中创建和执行线程方面提供了更好的控制。

# 摘要

在这一章中，我们探讨了 Java 线程，并学习了如何利用`java.util.concurrent`包实现多线程和并发编程。我们还学习了如何在应用程序中使用线程池来提高性能。我们看到了 Spring 提供的任务执行和调度功能，还学习了 Spring 的`@Async`支持，可以提高应用程序的性能和响应能力。我们回顾了 Spring 事务管理在处理多线程时可能出现的问题，并了解了多线程和并发编程的最佳编程实践。

在下一章中，我们将学习如何对应用程序进行性能分析，以找出性能问题。这对于识别性能问题非常有用。我们还将学习日志记录，这是识别应用程序问题的重要工具。


# 第九章：性能分析和日志记录

在上一章中，我们深入研究了多线程和并发编程的细节。我们查看了`java.util.concurrent`包的 API。本章涵盖了用于异步编程的线程池、Spring 任务执行、调度和 Spring Async API。在本章的后半部分，我们将 Spring Async 与`CompletableFuture`进行了比较。

在类似的情况下，本章将重点关注分析和日志记录。本章首先定义了分析和日志记录，以及它们如何有助于评估应用程序性能。在本章的后半部分，重点将放在学习可以用来研究应用程序性能的软件工具上。

本章将涵盖以下主题：

+   性能分析

+   应用程序日志记录和监控

+   性能分析工具

# 性能分析

本节将重点关注性能和应用程序性能分析。分析是应用程序开发和部署生命周期中的重要步骤。它帮助我们执行以下两件事：

1.  定义预期性能结果的基准

1.  衡量并比较当前性能结果与基准

第二步定义了进一步的行动，以将性能提升到基准水平。

# 应用程序性能

性能在软件应用程序方面对不同的人有不同的含义。它必须有一些上下文才能更好地理解。应用程序性能根据两组性能指标进行衡量。应用程序用户实际观察或体验到的性能仍然是衡量应用程序性能的最重要指标之一。这包括在高峰和正常负载期间的平均响应时间。与平均响应时间相关的测量包括应用程序响应用户操作（例如页面刷新、导航或按钮点击）所需的时间。它们还包括执行某些操作（例如排序、搜索或加载数据）所需的时间。

本节旨在为技术团队提供一些配置和内部方面的视角，这些配置和内部方面可以进行设置或更改，以优化效果，从而提高应用程序的性能。通常情况下，技术团队在没有遇到性能问题时很少关注应用程序使用的内存或 CPU 利用率。应用程序事务包括应用程序每秒接收的请求、每秒数据库事务和每秒提供的页面。系统的负载通常是以应用程序处理的交易量来衡量的。

还有另一组测量，涉及测量应用程序在执行操作时所利用的计算资源。这是一个很好的方法，可以确定应用程序是否有足够的资源来承受给定的负载。它还有助于确定应用程序是否利用的资源超出了预期。如果是这样，可以得出结论应用程序在性能方面没有进行优化。云托管应用程序如今很受欢迎。在这个时代，用户在云端部署的应用程序、非云基础设施上以及本地环境上应该有相同的体验是很重要的。

只要应用程序按预期运行，应用程序性能监控和改进可能并不是必要的。然而，在应用程序开发生命周期的一部分，会出现新的需求，添加新功能，并且应用程序变得日益复杂。这开始影响应用程序的性能，因为主要关注点放在了新功能开发上。当性能达不到标准时，因为没有人真正致力于应用程序性能的提升。

# 应用程序日志记录和监控

本节重点关注应用程序运行时记录重要信息。它有助于从各个方面调试应用程序，我们将详细了解。本节涵盖的另一个重要方面是应用程序监控。在某些情况下，应用程序监控被认为与应用程序性能分析没有区别；这些在应用程序性能测量中肯定是不同的方面。

# 应用程序日志

在我们深入了解 Java 应用程序日志的细节之前，了解日志和记录是强制性的。**日志**是显示信息以帮助我们了解应用程序状态的语句。日志语句以应用程序特定的格式写入日志文件。日志语句可能包括诸如特定语句执行的日期和时间、各种变量的值以及对象的状态等信息。将日志语句写入日志文件的过程称为**记录**。

每个应用程序都会出于各种目的生成日志。应用程序生成日志以跟踪应用程序事件，包括与访问相关的事件、登录和注销事件、应用程序发生错误时的事件以及系统配置修改。操作系统也会生成日志文件。日志文件可以被处理以分离所需的信息。**记录**是软件应用程序中最基本的部分之一。良好编写的日志和良好设计的记录机制对开发人员和管理员来说是巨大的实用工具。对于从事应用程序支持活动的团队来说，这是非常有用的。良好设计的记录可以为开发和支持团队节省大量时间。随着前端程序的执行，系统以一种隐形的方式构建日志文件。

以下是通常在应用程序中生成的常见日志文件：

+   **错误/异常日志**：应用程序流程中的任何意外情况都被称为**错误**。错误可能出现的原因各不相同。错误根据严重性和对应用程序的影响进行分类。如果用户无法在应用程序中继续操作，这样的错误被归类为**阻塞**。如果网页没有适当的标签，它被归类为低严重性问题。错误日志是应用程序执行时发生的关键错误的记录。几乎不存在没有错误的应用程序。在 Java 中，不需要记录所有异常。Java 支持受控异常，可以加以处理并作为警告或错误消息抛出给用户。这可能是验证错误或用户输入错误，可以使用受控异常抛出。

+   **访问日志**：在抽象层面上，任何发送到 Web 应用程序的请求都可以被视为对 Web 应用程序服务器上资源的请求。资源可以是 Web 页面、服务器上的 PDF 文件、图像文件或数据库中数据的报告。从安全性的角度来看，每个资源都必须受到访问权限的保护。访问权限定义了谁可以从 Web 应用程序访问资源。访问日志是关于谁尝试访问哪个资源的书面信息。它们还可能包括有关访问资源的位置的信息。访问日志为进入 Web 应用程序的每个请求写入访问信息。访问日志还可以用于查找有关访问者数量、首次访问应用程序的访问者数量、特定位置的访问者数量、特定页面的请求数量以及应用程序使用模式的信息。

+   **事务日志**：事务与数据库相关。为了保持原子性和数据库完整性而执行的一系列数据库命令或语句被称为**事务**。事务用于保证在崩溃或故障时的保护。**事务日志**是记录或写入所有这些事务的文件。在特定时间，如果发现数据库不一致，那么事务日志在调试问题时会有所帮助。事务日志还可以用于记录执行的任何回滚操作。通常，事务日志还记录数据库语句的执行时间以及传递的参数。这些信息对于分析数据库性能问题非常有帮助。

+   **审计日志**：**审计**是检查应用程序的使用情况的过程。它检查正在使用的应用程序资源，访问或使用应用程序资源的用户以及用户的身份验证和授权信息。**审计日志**记录应用程序通过的每个事件，以及前面提到的详细信息。

# 日志记录最佳实践

在描述了应该记录的内容和常见的日志信息之后，本节详细介绍了日志记录的最佳实践：

+   为每个日志语句分配适当的日志级别非常重要。

+   在集群环境中也应考虑日志记录。我们可以使用相同类型的日志文件，文件名后缀为集群节点名称。这将防止在分析日志时覆盖或错误地考虑日志条目。

+   构建日志文件会影响应用程序的性能。如果应用程序开始记录每个细小的信息，应用程序的性能将变慢。我们必须确保日志文件的大小和写入日志条目的频率较低。

+   除了验证和输入错误之外，所有异常都必须记录。异常消息必须以清晰地突出问题的方式记录。最佳实践是让框架记录所有异常。

+   日志必须用户友好且易于解析。日志可以以两种方式使用。一种方式是用户阅读日志以建立理解。另一种方式是实用程序根据日志格式解析应用程序日志，以过滤掉不重要的信息。

+   每个日志条目必须与其他日志条目不同，尽管它们代表相同的信息。每个日志条目都可以有一个唯一的标识符，通常基于时间戳，可以用来区分它与其他日志。

+   不应在日志文件中记录敏感信息。密码、凭据和身份验证密钥是一些例子。

在大多数情况下，最佳实践作为一般指导方针，并可以根据项目以定制化的方式进行遵循。

# 日志记录工具

在本章的前几节中，我们了解了日志记录的重要性。我们还学习了日志记录的最佳实践。现在是时候将日志记录工具添加到我们的技能集中了。本节重点介绍日志记录工具。日志记录工具很有帮助，因为它们提供了各种功能。在过去，日志文件由以纯文本格式编写的日志语句组成。纯文本日志文件在特定情况下仍然有用，比如分析基础设施数据，但它们已经不再足以记录应用程序的信息。Java 内置支持`java.util.logging` API 的标准日志记录。Log4j 是 Java 社区中另一个知名且广泛使用的日志记录工具。

在我们深入了解日志工具的细节之前，了解日志机制的关键要素是很重要的。以下是关键的日志记录组件：

+   **日志级别：** Java 日志级别用于控制日志输出。它们提供了在启用或禁用各种日志级别方面的灵活性。这使得可以选择在日志文件中显示哪些日志。通过这种方式，可能在生产环境中运行的应用程序与在暂存环境中运行的相同应用程序具有不同的日志级别。启用一个级别的日志将使所有更高级别的日志在日志文件中打印。以下是 Java 日志记录 API 的日志级别和有效日志级别：

| **请求级别** | **有效日志级别** |
| --- | --- |
| `SEVERE` | `WARNING` | `INFO` | `CONFIG` | `FINE` | `FINER` | `FINEST` |
| `SEVERE` | 是 | 是 | 是 | 是 | 是 | 是 | 是 |
| `WARNING` | 否 | 是 | 是 | 是 | 是 | 是 | 是 |
| `INFO` | 否 | 否 | 是 | 是 | 是 | 是 | 是 |
| `CONFIG` | 否 | 否 | 否 | 是 | 是 | 是 | 是 |
| `FINE` | 否 | 否 | 否 | 否 | 是 | 是 | 是 |
| `FINER` | 否 | 否 | 否 | 否 | 否 | 是 | 是 |
| FINEST | 否 | 否 | 否 | 否 | 否 | 否 | 是 |

+   **Logger：** `Logger`对象的工作是记录应用程序消息。应用程序可以创建匿名记录器，这些记录器与`Logger`命名空间中的记录器存储方式不同。应用程序必须确保保留对`Logger`对象的引用，因为`Logger`可能随时被垃圾回收。`Logger`对象与父`Logger`对象相关联，父对象是`Logger`命名空间中最近的祖先。在记录过程中，日志消息被发送到`Handler`对象。`Handler`对象将日志消息转发到文件、日志或控制台。每个`Logger`对象都有与之关联的日志级别。它指示`Logger`将为其打印日志的最低级别。

+   **处理程序：** `Handler`对象的责任是从`Logger`对象获取日志消息，并将这些日志消息发送到适当的目的地进行打印。例如，将日志消息写入控制台、将日志消息写入文件或将日志消息写入网络日志记录服务。可以启用或禁用`Handler`，从本质上讲，这会停止在输出介质上打印这些日志。

+   **格式化程序：** 日志`Formatter`在将日志消息写入输出介质之前对其进行格式化。Java 支持两种类型的`Formatter`对象：`SimpleFormatter`和`XMLFormatter`。`XMLFormatter`对象需要在格式化记录周围包含头和尾。还可以创建自定义的`Formatter`对象。

+   **LogManager：** `LogManager`是一个单例对象，用于维护日志记录器和日志服务的共享状态。除此之外，`LogManager`对象还管理日志记录属性和`Logger`命名空间。`LogManager`对象在类初始化时被实例化。对象不能随后更改。`LogManager`默认从`lib/logging.properties`文件中读取初始配置，该文件可以进行修改。

以下图表显示了具有一个`Handler`的日志记录过程：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-hiperf-spr5/img/e1514066-4a73-4e46-a089-666099b86b62.jpg)

以下图表显示了具有多个处理程序的日志记录过程：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-hiperf-spr5/img/7f4ab92e-aa5a-4dd1-a80e-423270789732.jpg)

# Java 标准日志记录

本节介绍了 Java 的内置日志记录机制。Java 日志记录 API 由`java.util.logging`包组成。核心包包括支持将纯文本或 XML 日志条目写入输出流、文件、内存、控制台或套接字。日志 API 还能够与操作系统上已存在的日志记录服务进行交互。

以下代码示例用于使用标准日志记录 API 打印日志消息：

```java
package com.packt.springhighperformance.ch9.logging;

import java.io.FileInputStream;
import java.io.IOException;
import java.sql.Timestamp;
import java.util.logging.Level;
import java.util.logging.LogManager;
import java.util.logging.Logger;

public class SampleLoggingOne {
  private static Logger logger = 
  Logger.getLogger("com.packt.springhighperformance.ch4.logging");

  public static void main(String argv[]) throws SecurityException, 
  IOException {
    FileInputStream fis = new FileInputStream("D:\\projects\\spring-    
    high-performance\\SampleProject\\src\\main\\resources
    \\logging.properties");
    LogManager.getLogManager().readConfiguration(fis);
    Timestamp tOne = new Timestamp(System.currentTimeMillis());
    for(int i=0; i < 100000; i++) {
        logger.fine("doing stuff");
    }
    Timestamp tTwo = new Timestamp(System.currentTimeMillis());
    System.out.println("Time: " + (tTwo.getTime() - tOne.getTime()));
    try {
      Bird.fly();
    } catch (Exception ex) {
      logger.log(Level.WARNING, "trouble flying", ex);
    }
    logger.fine("done");
  }
}
```

以下是前面示例中引用的`logging.properties`文件的示例：

```java
# Logging
handlers = java.util.logging.ConsoleHandler
.level = ALL

# Console Logging
java.util.logging.ConsoleHandler.level = ALL
```

执行前面示例后的输出如下：

```java
Feb 19, 2018 12:35:58 AM com.packt.springhighperformance.ch9.logging.SampleLoggingOne main
FINE: doing stuff
Feb 19, 2018 12:35:58 AM com.packt.springhighperformance.ch9.logging.SampleLoggingOne main
FINE: done
```

使用 Java 标准日志记录的好处是，您不需要安装项目中的单独的 JAR 依赖项。尽管日志记录与我们在服务器上遇到的故障排除问题有关，但我们还必须确保日志记录不会以负面方式影响应用程序性能。必须注意以下几点，以确保日志记录不会影响应用程序性能：

+   `Logger.log`方法用于通过`Handler`在输出介质上打印日志记录。我们可以使用`Logger.isLoggable`来确保`Logger`已启用日志级别。如果我们将自定义对象作为参数传递给`Logger.log`方法，则将从库类的深处调用自定义对象的`toString`方法。因此，如果我们想要执行繁重的操作以准备对象进行日志记录，我们应该在检查`Logger.isLoggable`的块内部，或者在对象的`toString`方法内部执行。

+   我们不得调用任何对象的`toString`方法以获取日志消息内容。我们也不得将`toString`方法调用作为参数传递给`Logger.log`。`Logger`对象和日志记录框架负责调用自定义对象的`toString`方法。

+   必须避免格式字符串连接和日志参数的混合。应用程序用户可能会以错误的意图破坏日志并访问用户未被允许访问的数据，使用恶意连接的字符串是可能的。

Java 标准日志记录的一个主要缺点是性能比较低。标准日志记录所需的时间比其他基于 Java 的日志记录框架（如 Apache Log4j 2、commons logging 或**Simple Logging Facade for Java**（**SLF4J**））更长。

# Apache Log4j 2

Apache Log4j 是 Java 社区中最广泛使用的日志记录框架之一。它是用 Java 编写的，并在 Apache 软件许可下分发。Apache Log4j 2 是早期版本的修订版。最显著的功能包括线程安全性、性能优化、命名记录器层次结构和国际化支持。

为了设置 Log4j 2，必须在 Maven `pom.xml`文件中添加以下 Maven 依赖项：

```java
<dependency>
  <groupId>org.apache.logging.log4j</groupId>
  <artifactId>log4j-core</artifactId>
  <version>2.7</version>
</dependency>

<dependency>
  <groupId>org.apache.logging.log4j</groupId>
  <artifactId>log4j-core</artifactId>
  <version>2.7</version>
  <type>test-jar</type>
  <scope>test</scope>
</dependency>
```

为了获得测试命名配置文件所需的上下文规则，我们必须在 Maven `pom.xml`文件中包含`test` JAR，以及主要的`log4j-core`包。

Log4j 2 有三个主要的日志记录组件：

+   `Loggers`**：**`Loggers`负责捕获日志信息。

+   `Appenders`**：**这些与 Java 标准日志记录中的`Handler`对象类似。`Appenders`负责将日志信息或消息广播到配置的输出介质。

+   `Layouts`**：**`Layouts`负责将日志消息格式化为配置的样式。

以下是`log4j2.xml`文件的示例：

```java
<?xml version="1.0" encoding="UTF-8"?>
<Configuration status="WARN">
  <Appenders>
    <Console name="ConsoleAppender" target="SYSTEM_OUT">
      <PatternLayout pattern="%d [%t] %-5level %logger{36} - 
      %msg%n%throwable" />
    </Console>
  </Appenders>
  <Loggers>
    <Root level="ERROR">
      <AppenderRef ref="ConsoleAppender" />
    </Root>
  </Loggers>
</Configuration>
```

以下是 Log4j 2 Java 代码示例：

```java
package com.packt.springhighperformance.ch9.logging;

import org.apache.log4j.Logger;

public class SampleLog4j2Example {
  private static Logger logger = 
  Logger.getLogger(SampleLog4j2Example.class);

  public static void main(String argv[]) {
    logger.info("example info log");
    try {
      Bird.fly();
    } catch (Exception ex) {
      logger.error("example error log", ex);
    }
    logger.warn("example warning log");
  }
}
```

执行上述示例时，将产生以下输出：

```java
2018-02-22 01:18:09 INFO SampleLog4j2Example:9 - example info log
2018-02-22 01:18:09 WARN SampleLog4j2Example:15 - example warning log
```

Apache Log4j 2 具有超出常见日志级别的额外日志级别。这些是`ALL`和`OFF`级别。当我们想要启用`ALL`日志级别时，使用`ALL`日志级别。如果配置了`ALL`日志级别，则不考虑级别。`OFF`日志级别是`ALL`日志级别的相反。它禁用所有日志记录。

# 应用程序监控

如前所述，应用程序性能被认为是任何软件应用程序生命周期中最重要的里程碑之一。还需要应用程序能够持续良好地运行。这是我们确保应用程序用户将获得最佳体验的一种方式。这也意味着应用程序正常运行。应用程序性能监控工具跟踪应用程序中进出的每个请求和响应，处理来自请求的信息，并在图形用户界面中响应和显示。这意味着监控工具为管理员提供了快速发现、隔离和解决影响性能的问题所需的数据。

监控工具通常收集有关 CPU 利用率、内存需求、带宽和吞吐量的数据。可以为不同的监控系统设置多个监控系统。任何应用程序性能监控的重要方面之一是将这些监控系统的数据合并到统计分析引擎中，并在仪表板上显示。仪表板使数据日志易于阅读和分析。应用程序监控工具帮助管理员监控应用程序服务器，以便遵守**服务级别协议**（**SLA**）。设置业务规则以在出现问题时向管理员发送警报。这确保了业务关键功能和应用程序被视为更高优先级。在快速变化的环境中，快速部署在生产系统中变得非常重要。快速部署意味着引入影响系统架构的错误或减慢系统运行的机会更多。

基于这些基本概念，有许多实现和工具可用。应用程序监控工具市场庞大而拥挤，包括行业领先和知名工具，如 AppDynamics、New Relic 和 Dynatrace。除了这些知名工具，还存在开源应用程序监控工具。开源工具包括 Stagemonitor、Pinpoint、MoSKito、Glowroot、Kamon 等。我们将在以下部分详细介绍这些工具。

# Stagemonitor

Stagemonitor 具有支持集群应用程序堆栈的监控代理。该工具的目的是监控在多台服务器上运行的应用程序，这是一个常见的生产场景。Stagemonitor 经过优化，可与时间序列数据库集成。它经过优化，用于时间序列数据管理，包括按时间索引的数字数组。这些数据库包括 elasticsearch、graphite 和 InfluxDB。Stagemonitor 也可以在私有网络中设置。它使用开放跟踪 API 来关联分布式系统中的请求。它具有定义指标阈值的功能。Stagemonitor 还支持创建新插件和集成第三方插件。

Stagemonitor 包含一个基于 Java 的代理。代理位于 Java 应用程序中。代理连接到中央数据库，并发送指标、请求跟踪和统计信息。Stagemonitor 需要一个实例来监控所有应用程序、实例和主机。

在浏览器中，在监控端，我们可以看到集群的历史或当前数据。我们还可以创建自定义警报。还可以为每个指标定义阈值。Stagemonitor 有一个仪表板。该仪表板用于可视化和分析不同的感兴趣的指标和请求。Stagemonitor 支持创建自定义仪表板、编写自定义插件和使用第三方插件。它还支持浏览器小部件，而无需后端，并自动注入到受监视的网页中。

以下是 Stagemonitor 仪表板的屏幕截图供参考：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-hiperf-spr5/img/d0794e01-e0a1-4ea6-960f-75e0265f5883.jpg)

Stagemonitor 仪表板视图（来源：http://www.stagemonitor.org/）

# Pinpoint

Pinpoint 与 Stagemonitor 不同之处在于，它是针对大规模应用程序开发的。它是在 Dapper（由 Google 开发的分布式系统跟踪基础设施）之后开发的，旨在为开发人员提供有关复杂分布式系统行为的更多信息。

Pinpoint 有助于分析整个系统结构以及系统不同组件之间的相互关系。Pinpoint 通过跟踪分布式应用程序中的事务来实现这一点。它旨在解释每个事务的执行方式，跟踪组件之间的流动以及潜在的瓶颈和问题区域。

Pinpoint 类似于 Stagemonitor，具有用于可视化的仪表板。该仪表板有助于可视化组件之间的相互关系。该仪表板还允许用户在特定时间点监视应用程序中的活动线程。Pinpoint 具有跟踪请求计数和响应模式的功能。这有助于识别潜在问题。它支持查看关键信息，包括 CPU 利用率、内存利用率、垃圾收集和 JVM 参数。

Pinpoint 由四个组件组成，分别是 Collector、Web、Sample TestApp 和 HBase。我们可以通过分别为每个组件执行脚本来运行一个实例。

以下是参考的 Pinpoint 仪表板：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-hiperf-spr5/img/3f5c17c7-6333-4d01-95c2-9d8112fb6d06.jpg)

Pinpoint 仪表板参考视图（来源：http://www.testingtoolsguide.net/tools/pinpoint-apm/）

# MoSKito

MoSKito 是三个工具的组合：

+   **MoSKito-Essential**：这个独立项目是 MoSKito 的核心。它使监视应用程序成为可能。

+   **MoSKito-Central**：这是一个集中式存储服务器。它存储所有与性能相关的信息。

+   **MoSKito-Control**：这个工具适用于多节点 Web 应用程序。它提供了对多节点 Web 应用程序的监视支持。

要设置 MoSKito，我们需要在应用程序的`WEB-INF/lib`目录中安装一个 JAR 文件，这是一个常用的存放 API 库的文件夹。也可以通过在`web.xml`文件中添加一个新的部分来设置。

该工具能够收集所有应用程序性能指标，包括内存、线程、存储、缓存、注册、付款、转换、SQL、服务、负载分布等等。它不需要用户在应用程序中进行任何代码更改。它支持所有主要的应用服务器，包括 Tomcat、Jetty、JBoss 和 Weblogic。它将数据存储在本地。

MoSKito 还具有通知功能，当达到阈值时会广播警报。它还记录用户的操作，这可能对监视目的有所帮助。MoSKito 提供了一个用于在移动设备上监视应用程序的移动应用程序。它还具有基于 Web 的仪表板。

MoSKito 的一个显著特点是它在 Java 社区中非常稳定和知名。它得到了社区和团队的支持，包括付费支持。

以下是 MoSKito 仪表板的参考：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-hiperf-spr5/img/e8b1aab2-b6ba-4033-a50e-c379a733b6fd.jpg)

MoSKito 仪表板视图（来源：https://confluence.opensource.anotheria.net/display/MSK/Javaagent+light+and+multiple+java+processes）

# Glowroot

Glowroot 是一种快速、干净、简单的应用程序性能监控工具。它具有一个功能，允许跟踪慢请求和错误。使用 Glowroot，还可以记录每个用户操作所花费的时间。Glowroot 支持 SQL 捕获和聚合。Glowroot 提供的历史数据滚动和保留配置是其提供的附加功能之一。

Glowroot 支持在图表中可视化响应时间的分解和响应时间百分位数。它具有响应灵敏的用户界面，允许用户使用移动设备以及桌面系统监视应用程序，无需进行任何额外的安装。

Glowroot 以 ZIP 文件捆绑提供。要开始使用 Glowroot，我们必须下载并解压 ZIP 文件捆绑。Glowroot 需要更改应用程序的 JVM 参数。我们必须在应用程序的 JVM 参数中添加`-javaagent:<path to glowroot.jar>`。

Glowroot 一旦设置并运行，就提供了带有过滤的持续性能分析。我们还可以设置响应时间百分位数和 MBean 属性的警报。Glowroot 还支持跨多个线程的异步请求。在应用服务器方面，Glowroot 支持 Tomcat、Jetty、JBoss、Wildfly 和 Glassfish。

以下是 Glowroot JVM 仪表板供参考：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-hiperf-spr5/img/97ae8f5c-5592-4717-9892-d546f6a56d44.png)

Glowroot JVM 仪表板视图（来源：https://demo.glowroot.org）

# New Relic

New Relic 是 Java 社区中另一个广泛使用的应用程序性能监控工具。New Relic 为应用程序和网络性能统计提供了分组视图。这有助于快速诊断域级问题。它还提供了针对特定请求的深入功能，以查看响应时间、数据传输大小和吞吐量的性能指标。

New Relic 支持使用 Java、Scala、Ruby、Python、PHP、.NET 和 Node.js 开发的应用程序。New Relic 提供了四种不同的后端监控方法：

+   **应用程序性能管理**：在应用程序性能管理中，New Relic 提供高级指标，并能够深入到代码级别，以查看应用程序的性能。在仪表板上，New Relic 显示响应时间图表。New Relic 使用 Apdex 指数评分方法将指标转化为性能指标。New Relic 要求用户手动设置阈值。

+   **服务器监控**：New Relic 关注应用程序服务器运行的硬件。测量包括 CPU 使用率、内存利用率、磁盘 I/O 和网络 I/O。New Relic 提供了堆内存和垃圾回收属性的简要详情。

+   **数据库监控**：在 New Relic 中，数据库仪表板是应用程序性能管理仪表板的一部分。可以通过插件查看数据库监控指标。

+   **洞察和分析**：New Relic 具有内置的、可选择的数据库，用于存储统计数据并实现对数据库的查询。

以下是 New Relic 仪表板供参考：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-hiperf-spr5/img/a9255a23-618e-4fb8-828c-4b5007fcd6c5.jpg)

New Relic 仪表板视图（来源：https://newrelic.com/）

# 性能分析工具

性能分析工具，或者分析器，是应用程序开发人员用来调查和识别代码特征和问题的软件工具。性能分析工具还有助于识别性能问题。性能分析工具回答问题，比如 JVM 参数设置是什么，堆内存的状态如何，基于代的内存利用情况如何，哪些线程是活跃的等等。一些分析器还跟踪代码中的方法，以了解 SQL 语句调用的频率，或者 Web 服务调用的频率。

与应用程序性能监控工具类似，市场上有许多性能分析工具。VisualVM、JConsole 和 HeapAnalyzer 是其中的几个。我们将在接下来的部分详细讨论每个性能分析工具。

# VisualVM

VisualVM 是一个 Java 性能分析和性能分析工具。它具有可视化界面，用于分析在本地和远程环境中在 JVM 上运行的 Java 应用程序的详细信息。它集成并利用了 JDK 提供的命令行工具，如`jstack`，`jconsole`，`jmap`，`jstat`和`jinfo`。这些工具是标准 JDK 分发的一部分。VisualVM 在解决运行时问题方面非常重要，具有堆转储和线程分析等功能。它有助于识别应用程序性能以及其与基准的比较情况。它还有助于确保最佳的内存使用。它进一步有助于监视垃圾收集器，分析 CPU 使用情况，分析堆数据和跟踪内存泄漏。以下是 VisualVM 使用的每个命令行工具的目的：

+   `jstack`**：**这个工具用于捕获 Java 应用程序的线程转储

+   `jmap`**：**这个工具打印给定进程的共享对象内存映射和堆内存详细信息

+   `jstat`**：**这个工具显示运行应用程序的 JVM 的性能统计信息

+   `jinfo`**：**这个工具打印 Java 配置信息

VisualVM 是标准 JDK 捆绑包的一部分。它首次与 JDK 平台捆绑在 JDK 版本 6，更新 7 中。它也可以单独安装。让我们详细看看每个部分：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-hiperf-spr5/img/000eb193-e61d-4572-89d6-df59d25a9cc2.png)

VisualVM 的应用程序窗口视图

如前面的屏幕截图所示，在窗口的左侧有一个应用程序窗口。应用程序窗口具有节点和子节点。可以展开节点和子节点以查看配置的应用程序和保存的文件。通过右键单击节点并从弹出菜单中选择项目，可以查看其他信息或执行操作。弹出菜单选项因所选节点而异。

在应用程序窗口内，我们可以看到一个本地节点的菜单。本地节点显示有关在与 VisualVM 相同的计算机上运行的 Java 进程的进程名称和进程标识符的信息。启动 VisualVM 后，当展开本地根节点时，本地节点会自动填充。VisualVM 始终加载为本地节点之一。服务终止时，节点会自动消失。如果我们对应用程序进行线程转储和堆转储，这些将显示为子节点。

可以使用 VisualVM 连接到在远程计算机上运行的 JVM。所有这些运行的进程或应用程序都显示在远程节点下。与远程节点建立连接后，可以展开远程节点以查看在远程计算机上运行的所有 Java 应用程序。

如果应用程序在 Linux 或 Solaris 操作系统上运行，则 VM Coredumps 节点仅可见。在 VisualVM 中打开核心转储文件时，VM Coredumps 节点显示打开的核心转储文件。这是一个包含有关机器运行时状态的二进制文件。

应用程序窗口中的最后一个部分标有快照。快照部分显示在应用程序运行时拍摄的所有保存的快照。

VisualVM 中的本地或远程应用程序的数据以选项卡的形式呈现。在查看应用程序数据时，默认情况下打开概述选项卡。概述选项卡显示的信息包括进程 ID，系统位置，应用程序的主类，Java 安装路径，传递的 JVM 参数，JVM 标志和系统属性。

列表中的下一个选项卡是监视选项卡。监视选项卡可用于查看有关堆内存，永久代堆内存以及类和线程数量的实时信息。这里的类表示加载到虚拟机中的类。应用程序监视过程的开销较低。

监视选项卡上的堆图显示了总堆大小和当前使用的堆大小。在 PermGen 图中显示了永久代区域随时间的变化。类图显示了加载和共享类的总数。线程部分显示了活动线程和守护线程的数量信息。VisualVM 可以用于获取线程转储，显示特定时间的线程的确切信息。

在监视选项卡中，我们可以强制执行垃圾回收。该操作将立即运行垃圾回收。还可以从监视选项卡中捕获堆转储：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-hiperf-spr5/img/60038421-778a-43a9-8075-aa2b08bb0880.png)

VisualVM 在线程选项卡中显示实时线程活动。默认情况下，线程选项卡显示当前线程活动的时间轴。通过单击特定线程，可以在详细信息选项卡中查看有关该特定线程的详细信息。

时间轴部分显示了带有实时线程状态的时间轴。我们可以通过选择下拉菜单中的适当值来过滤显示的线程类型。在上述屏幕截图中，显示了活动线程的时间轴。我们还可以通过从下拉菜单中选择来查看所有线程或已完成线程。

在应用程序运行时，我们可以选择获取应用程序的线程转储。打印线程转储时，会显示包括 Java 应用程序的线程状态的线程堆栈。

分析器选项卡使得可以启动和停止应用程序的分析会话。结果显示在分析器选项卡中。可以进行 CPU 分析或内存分析。启动分析会话后，VisualVM 连接到应用程序开始收集分析数据。一旦结果可用，它们将自动显示在分析器选项卡中。

# JConsole

JConsole 是另一个 Java 分析工具。它符合**Java 管理扩展**（**JMX**）规范。JConsole 广泛使用 JVM 中的仪器来收集和显示运行在 Java 平台上的应用程序的性能和资源消耗的信息。JConsole 在 Java SE 6 中更新为 GNOME 和 Windows 外观。

与 VisualVM 类似，JConsole 与 Java 开发工具包捆绑在一起。JConsole 的可执行文件可以在`JDK_HOME/bin`目录中找到。可以使用以下命令从命令提示符或控制台窗口启动 JConsole：

```java
jconsole
```

执行上述命令后，JConsole 会向用户显示系统上运行的所有 Java 应用程序的选择。我们可以选择连接到任何正在运行的应用程序。

如果我们知道要连接到的 Java 应用程序的进程 ID，也可以提供进程 ID。以下是启动 JConsole 并连接到特定 Java 应用程序的命令：

```java
jconsole <process-id>
```

可以使用以下命令连接到在远程计算机上运行的 Java 应用程序：

```java
jconsole hostname:portnumber
```

JConsole 在以下选项卡中显示信息：

+   概述：此选项卡显示有关 JVM 和要监视的值的信息。它以图形监视格式呈现信息。信息包括有关 CPU 使用情况、内存使用情况、线程计数以及 JVM 中加载的类数量的概述细节。

+   内存：此选项卡显示有关内存消耗和使用情况的信息。内存选项卡包含一个执行 GC 按钮，可以单击以立即启动垃圾回收。对于 HotSpot Java VM，内存池包括伊甸园空间、幸存者空间、老年代、永久代和代码缓存。可以显示各种图表来描述内存池的消耗情况。

+   线程：此选项卡显示有关线程使用情况的信息。线程包括活动线程、活动线程和所有线程。图表的表示显示了线程的峰值数量和两条不同线上的活动线程数量。MXBean 提供了线程选项卡未涵盖的其他信息。使用 MXBean，可以检测到死锁线程。

+   类：此选项卡显示了 Java 虚拟机中加载的类的信息。类信息包括迄今为止加载的类的总数，包括后来卸载的类以及当前加载的类的数量。

+   VM：此选项卡显示有关 Java 虚拟机的统计信息。摘要包括正常运行时间，表示 JVM 启动以来的时间量；进程 CPU 时间，表示 JVM 自启动以来消耗的 CPU 时间量；以及总编译时间，表示用于编译过程的时间。

+   MBeans：此选项卡显示有关 MBeans 的信息。MBeans 包括当前正在运行的 MBeans。我们可以通过选择 MBean 来获取`MBeanInfo`描述符信息。

以下截图显示了 JConsole 仪表板的外观：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-hiperf-spr5/img/43734b6d-8df0-4662-be7d-258c92879688.jpg)

# 总结

本章充满了有关应用程序性能测量技术的信息。本章对于致力于应用程序性能增强任务的开发团队非常有用。同时，技术团队在设置其应用程序日志记录机制时也可以参考本章。

本章从性能分析和日志记录的简介细节开始。继续前进，我们了解了特定应用程序性能监控和应用程序日志记录。我们了解了日志记录的关键要素是什么。我们还研究了日志记录工具，如标准 Java 日志记录和 Log4j。在本章的后半部分，我们了解了 VisualVM 作为性能分析工具。VisualVM 是最广泛使用的基于 Java 的性能分析工具之一，作为标准 Java 分发包提供。就是这样了。

下一章将重点关注优化应用程序性能。在进行性能优化时，可以利用本章提供的知识和信息。本章为下一章提供了基础。下一章涵盖了识别性能问题症状、性能调优生命周期和 Spring 中的 JMX 支持的详细信息。非常令人兴奋，不是吗？


# 第十章：应用性能优化

在上一章中，我们重点介绍了如何对应用程序进行分析以找出应用程序的性能问题。我们还涵盖了日志记录，这是识别应用程序问题的有用工具。这是一个重要的部分，并且在我们处理 Spring 应用程序时将成为我们日常工作的一部分。

现在让我们看看本章内容。这是本书中的一个关键章节；它为您提供了改善应用性能的方法。在本章中，我们将讨论应用性能优化的基本方法，这对于任何应用程序都是关键的，包括基于 Spring 的应用程序。我们将讨论 Spring 对 Java 管理扩展（JMX）的支持，数据库交互的改进以及 Spring 应用程序的性能调优。通过本章结束时，您将能够识别 Spring 应用程序中的性能瓶颈并解决它们。

让我们以结构化的方式来看应用性能优化的重要方面。我们将涵盖以下主题：

+   性能问题症状

+   性能调优生命周期

+   性能调优模式和反模式

+   迭代性能调优过程

+   Spring 对 JMX 的支持

# 性能问题症状

让我们从性能问题症状开始。这是一个明显的起点，就像咨询医生一样，首先讨论症状，然后做出诊断。应用性能是用户在速度、交付内容的准确性和最高负载下的平均响应时间方面所经历的行为。负载是指应用程序每单位时间处理的交易数量。响应时间是应用程序在这样的负载下响应用户操作所需的时间。

每当性能需要改进时，首先想到的是影响我们应用程序性能的问题。要找出性能问题，我们需要寻找一些症状，这些症状可以引导我们找到问题。

在 Spring 应用中可能观察到的一些常见症状如下：

+   超时

+   工作线程不足

+   线程等待类加载器

+   即使在正常负载下，加载类所花费的大量时间

+   类加载器尝试加载不存在的类

在接下来的章节中，我们将通过一个示例情境来理解这些症状。这些细节将帮助我们在发生时识别症状。

# 超时

超时以两种不同的方式发生。一种是请求超时，由 HTTP 响应状态码 408 表示。另一种超时是网关超时，由 HTTP 响应状态码 504 表示。

请求超时表示服务器未能在指定时间内从客户端接收完整的请求。在这种情况下，服务器选择与客户端关闭连接。请求超时是服务器直接的错误消息。

网关超时表示网关或代理服务器在处理请求时超时。在大多数情况下，这是因为代理或网关未能及时从上游的实际服务器接收到响应。

# 工作线程不足

以银行为例；银行拥有一个带有监控系统的 Web 应用程序。监控系统关注 JVM 的强度。测量参数包括内存、CPU、I/O、堆内存和其他各种属性。监控系统提供了独特的仪表板，显示并突出显示了上述属性的测量结果。还有一个附带的仪表板，显示了银行应用程序中执行的活动组。该仪表板还确定了 JVM 在访问专门的应用程序资源（如线程）时开始运行低的活动组。该应用程序在多个 JVM 环境中运行。以下是一个示例仪表板的屏幕截图，仅供参考：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-hiperf-spr5/img/c373a988-ca43-4519-83e1-858dba4aa7e3.png)

监控系统配置了阈值。例如，JVM 一次使用的最大线程数不应超过 250 个。当 JVM 一次使用的线程少于 150 个时，仪表板中相应的 JVM 指示灯为绿色。当 JVM 开始使用超过 150 个线程时，监控系统会将该 JVM 指示为红色。这是一个症状，表明可能会发生故障或性能受到异常影响。

以下是一个基于时间线的屏幕截图，显示了 JVM 的工作线程达到最大值：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-hiperf-spr5/img/bb3eb73b-7e96-45ee-944a-f4820cc2478a.png)

# 线程在类加载器上等待

继续使用前一节中描述的相同示例，首先出现的问题是，这些线程有什么问题？深入研究线程并分解状态后发现，这些线程（大约 250 个中的 242 个）正在寻找服务器的`CompoundClassLoader`。这些线程正在堆叠额外的对象，这就是它们正在寻找类加载器的原因。由于大量线程试图访问这个共享资源——类加载器，大多数线程都陷入了暂停状态。

监控显示了等待`CompoundClassLoader`的线程数量：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-hiperf-spr5/img/deab9529-89de-4cb5-acf7-2a91ed0379f6.png)

# 在类加载活动上花费的时间

在监控系统中进行的分析还表明，线程大部分时间都花在类加载活动上。以下是突出显示这一点的监控系统截图：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-hiperf-spr5/img/fc724071-fc1d-43cc-8a32-b241274c1ab0.png)

从监控系统的先前屏幕截图来看，很明显，无论当前负载如何，与请求处理生命周期中的其他活动相比，类加载活动都需要相当长的时间。这是性能问题的指标或症状，因为它会增加整体响应时间。在银行的情况下，可以通过评估平均响应时间来确认。

# 类加载器尝试加载不存在的类

一个问题出现了：类堆叠是否非常重要？深入挖掘并查看处理的请求，表明每个请求都试图堆叠一个不存在的类。应用服务器正在提示大量的`ClassNotFoundException`类。问题的主要驱动因素是该类无法被有效地堆叠，但应用服务器继续尝试为每个请求堆叠它。这对于快速和中等请求和功能来说不应该是一个问题。对于每个传入请求或功能的这种细节水平可能会占用稀缺资源——类加载器，并因此影响请求的响应时间。

监控系统的能力、适应性和容量是捕捉每个请求和响应以及有关堆叠类数据的关键。以下屏幕截图显示了应用框架中的一个这样的场景：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-hiperf-spr5/img/9881ec25-1c27-499d-bd7a-158e8cf8ba1d.png)

现在应该清楚了潜在性能问题的症状。这特别适用于任何基于 JVM 的 Web 应用程序，而不仅仅是基于 Spring 的 Web 应用程序。以下截图显示了基本上可以帮助我们识别性能问题影响的指针。

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-hiperf-spr5/img/2c99527f-9e1b-4148-9ea7-f400f5f6c078.png)

性能不佳的应用对企业非常重要，因为它们因应用性能而导致销售额下降。应用也可能因性能问题而导致生产率或业务损失。

让我们通过一个基本示例来了解性能问题对业务的影响：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-hiperf-spr5/img/9425db8d-afef-400b-8c3a-f2d273f73661.jpg)

从上图可以理解，糟糕的应用行为会影响业务，可能导致项目成本高、转化率下降、重复访问减少、客户保留率低、销售额下降、生产率下降、客户流失、项目成本增加，以及利润和投资回报的延迟或下降。性能对企业非常重要。

我们需要做什么来避免或解决性能问题？不要等待性能问题发生。提前进行架构、设计和代码审查，并计划进行负载测试、调优和基准测试。如今，在竞争激烈的市场中，组织的关键是确保其系统以最佳性能运行。任何故障或停机都直接影响业务和收入；应用程序的性能是一个不容忽视的因素。由于技术的广泛应用，数据量日益增长。因此，负载平均值正在飙升。在某些情况下，无法保证数据不会超出限制或用户数量不会超出范围。

在任何时候，我们都可能遇到意想不到的扩展需求。对于任何组织来说，其应用程序提供可伸缩性、性能、可用性和安全性非常重要。在多个服务器上分布数据库以满足不同应用程序查询的应用程序可伸缩性，无论是水平扩展还是垂直扩展，都是相当可行的。向集群添加计算能力以处理负载非常容易。集群服务器可以立即处理故障并管理故障转移部分，以保持系统几乎一直可用。如果一个服务器宕机，它将重定向用户的请求到另一个节点并执行所请求的操作。如今，在竞争激烈的市场中，组织的关键是确保其系统正常运行。任何故障或停机都直接影响业务和收入；高可用性是一个不容忽视的因素。

以下图表显示了我们可能遇到的一些常见性能问题：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-hiperf-spr5/img/f5deff9a-aecd-42c7-85d3-b708660ee1b5.png)

现在，让我们来看看性能调优生命周期的各个阶段。

# 性能调优生命周期

速度是每个企业的核心。在这个超连接的现代世界中，大多数人着迷的是速度；无论是最快的汽车、最快的计算机处理器，甚至是最快的网站。网站性能已经成为每个企业的最高优先级。用户的期望比以往任何时候都更高。如果您的网站不能立即响应，很有可能用户会转向竞争对手。

沃尔玛的一项研究发现，每提高 1 秒的页面性能，转化率就会增加 2%。

Akamai 的一项研究发现：

+   47%的人期望网页在两秒内加载完成

+   如果一个网页加载时间超过三秒，40%的人会放弃访问

+   52%的在线购物者表示快速页面加载对他们对网站的忠诚度很重要

2007 年，亚马逊报告称，亚马逊（[`www.amazon.com/`](https://www.amazon.com/)）的加载时间每增加 100 毫秒，销售额就会减少 1%。

借助以下图，我们可以轻松理解性能调优生命周期的不同阶段：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-hiperf-spr5/img/0d791f68-7d97-47f3-a077-4fc430654185.jpg)

在大多数情况下，通过在适当的时候审查以下工件，可以避免性能问题：

+   架构

+   设计

+   代码

+   聘请专家顾问在适当的时候进行应用程序审查

+   在开发阶段完成之前的任何时间进行审查

+   强烈建议提前识别性能优化问题，这可以在架构阶段完成之前开始

+   在向用户提供应用程序之前，最好预防性能问题

+   进行各种审查和测试，以避免生产中的性能问题

+   性能调优生命周期也可以在投入生产后或在生产环境中面临性能问题时进行

为了调整 Spring 应用程序的性能，以下部分描述的策略可能非常有用。

# 连接池

**连接池**是一种帮助应用程序执行的策略，其中打开和管理数据库的*N*个连接在池中。应用程序只需请求连接，使用它，然后将其放回池中。当应用程序请求连接时，准备好的连接保持可用以供池中使用。池管理连接的生命周期，以至于开发人员实际上不必等待连接并筛选过时的连接。

Hibernate 利用其魔力来识别要使用的连接池提供程序 - 基于您配置的属性。

以下是 c3p0 连接池的属性配置：

```java
<property name="hibernate.c3p0.min_size">5</property>
<property name="hibernate.c3p0.max_size">20</property>
<property name="hibernate.c3p0.timeout">300</property>
<property name="hibernate.c3p0.max_statements">50</property>
<property name="hibernate.c3p0.idle_test_period">3000</property>
```

以下是 Apache Commons DBCP 的连接池属性配置示例：

```java
<property name="hibernate.dbcp.initialSize">8</property>
<property name="hibernate.dbcp.maxActive">20</property>
<property name="hibernate.dbcp.maxIdle">20</property>
<property name="hibernate.dbcp.minIdle">0</property>
```

在使用任何连接池机制时，我们必须手动将 JAR 依赖项放置在服务器类路径中，或者使用 Maven 等依赖管理工具。

还可以使用`hibernate.connection.provider_class`属性明确指定连接提供程序，尽管这不是强制性的。

如果我们不使用 Hibernate 配置连接池，默认会使用。当启动应用程序时，可以在日志或控制台输出中看到：

```java
org.hibernate.engine.jdbc.connections.internal.DriverManagerConnectionProviderImpl configure
```

Hibernate 的默认连接池对于开发环境是一个不错的选择，但是在生产环境中，建议根据要求和用例配置连接池。

如果您使用应用程序服务器，可能希望使用内置池（通常使用**Java 命名和目录接口**（**JNDI**）获取连接）。

要使用服务器的内置池与使用 JNDI 配置的 Hibernate 会话，我们需要在 Hibernate 配置文件中设置以下属性：

```java
hibernate.connection.datasource=java:/comp/env/jdbc/AB_DB
```

假设`AB_DB`是 Tomcat JDBC 连接池`DataSource`的 JNDI 名称。

如果您不能或不希望使用应用程序服务器内置的连接池，Hibernate 支持其他几种连接池，例如：

+   c3p0

+   Proxool

在 Apache DBCP 之后，第二受欢迎的连接池实现是 c3p0，它可以轻松集成 Hibernate，并且据说性能良好。

# Hibernate

连接池机制确保应用程序在需要时不会耗尽数据库连接。Hibernate 是 Java 应用程序的最佳 ORM 框架之一。在使用时，必须进行性能优化。

# 事务

Hibernate 只在需要时进行脏检查，以考虑执行成本。当特定实体具有与大量列对应的表时，成本会增加。为了尽量减少脏检查成本，最好我们通过指定一个交易来帮助 Spring 进行读取，这将进一步提高执行效率，消除了任何脏检查的需求。

以下是`@Transactional`注解的一个示例用法，该注解表示该方法在 Hibernate 事务中运行：

```java
@Transactional(readOnly=true)
public void someBusinessMethod() {
    ....
}
```

# 定期清除 Hibernate 会话

在数据库中包含/调整信息时，Hibernate 会维护会话。在会话中，它存储了将要保存的实例的形式。如果在会话关闭之前修改了这些实例或记录，这就被称为**脏检查**。然而，我们可以让 Hibernate 不要在其会话中保存元素的时间比实际需要的时间长。因此，一旦需求完成，我们就不必再在会话中保存实例。在这种情况下，我们可以安全地刷新和清除`EntityManager`，以调整数据库中元素的状态并将实例从会话中移除。这将使应用程序远离内存需求，并且肯定会对执行产生积极影响。

以下是一段代码，可以用来`flush()`和`clear()` Hibernate 会话：

```java
entityManager.flush();
entityManager.clear();
```

# 懒加载

如果您正在使用 Hibernate，您应该注意适当使用`IN`语句。它只在需要时才懒惰加载记录。当这些自定义记录被不高效地加载到内存中时，每个记录将被单独加载并单独使用。因此，如果内存中加载了太多实例，那么将依次执行许多查询，这可能导致严重的执行问题。

# 基于构造函数的 HQLs

在正常情况下，当应用程序使用 Hibernate 时，我们不会尝试检索整个内容及其所有属性，尽管我们不需要它们用于特定用例。一个实体可能有 30 个属性，而我们可能只需要其中几个在我们的功能中设置或显示给用户。在这种情况下，将使用查询从数据库中检索大量记录。考虑到未使用的字段与应用程序粘合在一起，这将最终导致巨大的执行或性能问题。

为了解决这个问题，HQL/JPA 为我们提供了一个 select new 构造函数调用，通常用于制定查询，这也使开发人员能够选择聚合值。

# 实体和查询缓存

如果每次为特定实体调用相同的查询，并且表数据对于特定可用性不会发生变化，我们可以使用 Hibernate 存储查询和实体。

如果应用了查询缓存，那么对于执行，后续的 SQL 语句将不会发送到数据库。如果查询缓存或一级缓存找不到基于标识符的元素，那么将使用存储的元素标识符来访问 Hibernate 的二级缓存，其中存储了相应的实际元素。这对响应时间有很大影响。当我们这样做时，我们也关心缓存何时刷新自身。我们可以通过一些简单的设置轻松实现这一点。

# 本地查询

尽管本地查询有缺点，但在执行方面它们是最快的。当 HQL 更改无法改善应用程序的执行时，本地查询可以显著提高执行效率，大约提高 40%。

# 主键生成

在将 Hibernate 注释指示到实体类或编写`.hbm`文件时，我们应该避免使用自动键生成方法，这会导致大量的序列调用。

以下是定义密钥生成策略的示例代码：

```java
@Id
@GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "your_key_generator")
private Long id;
```

通过这个简单的改变，在插入密集型应用程序中可以注意到 10-20%的改进，基本上不需要代码更改。

# 数据库

一旦完成了 Hibernate 性能优化生命周期，下一步将是在数据库级别执行优化生命周期。以下部分定义了数据库组件的性能改进技术。

# 索引

如果查询涉及的表具有大量列，则列表成为一个重要因素。此外，当复杂的数据库查询被应用程序终止时，它也会产生影响。获取所需索引建议的最佳方法是检查查询执行计划。在分析用于索引的 SQL 查询时，我们必须分别预期每一个真实的查询。

在使用索引时，必须注意以下几点：

+   索引可能会减慢插入和更新，因此在经常更新的列上谨慎应用它们

+   索引旨在加速使用查询中的`WHERE`和`ORDER BY`子句的搜索操作

# 视图

数据库视图是我们在高度围绕较长的执行时间问题时探索或考虑的另一种过程。直到 SQL Server 2000，视图仅用于便利，而不是速度。SQL Server 的后续版本包括一个称为索引视图的特殊功能，据说可以大大提高性能，但必须使用一套规则创建索引视图。

# Spring Security

Spring Security 对于任何应用程序都是最重要的方面之一，特别是那些在互联网上运行的应用程序。虽然 Spring Security 为应用程序提供了安全外观并防止应用程序被非法访问，但如果管理不当，它会增加很多额外负担。我们将在接下来的部分重点介绍 Spring Security 的最佳实践。

# 认证缓存

Spring Security 执行是偶尔出现的担忧之一，当需求处理时间被认为过高，因此不可接受。有时你会发现真正的需求处理大约需要 120 毫秒，而 Spring Security 验证/验证又需要另外 500-600 毫秒。

# LDAP 自定义权限

这可能不是你需要考虑的方法，但它确实为你提供了另一种增强 Spring Security 实现执行的选择。

在这种方法中，我们使用自己的自定义方式设置用户权限，而不是从 LDAP 进行确认。这样做有几个很好的理由，应用程序的执行是其中之一。

# 本地 LDAP

Spring Security 为我们提供了最标准和可靠的 LDAP 验证实现。通过中心 Spring LDAP，方法变得有点糟糕，但显示出了优化改进的迹象。最后一种方法（使用中心 Spring LDAP）被看到与 Spring Security 相比，极大地提高了应用程序的执行。这不是首选的方法，但我们可以考虑它作为发展的选择之一。

# 多线程

现在每个应用程序都是多线程的，这意味着它能够同时执行多个操作。

对于每一个可能的优化，对应用程序的单次点击可能看起来令人满意。然而，在应用程序遭受多个同时点击的负载测试时，应用程序的执行开始受到阻碍。在这种高度并发的情况下，您可能需要调整 Tomcat 服务器上的线程默认设置。如果存在高度并发性，HTTP 请求将被挂起，直到线程处理它。在更极端的情况下，等待队列会升高，请求会超时。

默认服务器线程使用可以通过在业务逻辑内部使用代理结构来进一步补充，以便在单个线程执行流中进一步进行并发非同步调用。

# 性能调优模式和反模式

性能调优是改变系统执行情况。通常在计算机系统中，这样做的动机被称为性能问题，可以是真实的或假设的。大多数系统会对增加的负载做出一定程度的执行降低。系统接受更高负载的能力称为可扩展性，调整系统以处理更高负载等同于性能调优。

性能调优包括以下步骤：

1.  问题应该根据预期的数字计数进行评估和检查以满足要求。

1.  修改前测量系统的执行情况。

1.  识别系统中关键的部分以改善执行情况。这被称为**瓶颈**。

1.  修改系统的部分以消除瓶颈。

1.  修改后测量框架的执行情况。

1.  如果调整改善了执行情况，请接受它。如果改变恶化了执行情况，请将其恢复到原样。

# 反模式

与模式一样，软件开发中也存在反模式。模式有助于确保应用程序在性能、可扩展性和优化处理方面的改进。另一方面，代码中存在反模式表明应用程序执行存在挑战。反模式以与模式类似的程度影响应用程序，但是以负面方式。性能反模式大多会降低应用程序的性能。我们讨论反模式，是因为除了遵循模式和最佳实践外，我们还必须确保不遵循或使用反模式。

# 架构反模式

架构中存在许多类型的性能反模式。多层反模式描述了一种试图通过尽可能多的独立的逻辑应用层来实现高抽象的架构。作为开发人员，这样的架构很快就会因为大部分时间花在映射和转换数据上而变得可识别，并且从界面到数据库的简单传递变得复杂。

这种架构通常出现是因为应用程序应该尽可能灵活，以便可以轻松快速地交换 GUI，并且对其他系统和组件的依赖性可以保持较低。层的解耦导致在映射和数据交换过程中出现性能损失，特别是如果层也是物理上分离的，并且数据交换通过远程技术进行，例如**简单对象访问协议**（**SOAP**）或**远程方法调用**（**RMI**），**Internet 对象请求代理协议**（**IIOP**）。

许多映射和转换操作也可能导致更高的垃圾收集活动，这被称为循环对象问题。作为解决这种反模式的方法，应该仔细审查架构驱动程序，澄清需要什么灵活性和解耦。新的框架方法，如 JBoss Seam，已经解决了这个问题，并尽量避免映射数据。

另一个架构反模式是所谓的**会话缓存**。这样做，应用程序的 Web 会话被误用为大型数据缓存，严重限制了应用程序的可扩展性。调整工作中经常测量到会话大小远远大于 1MB，在大多数情况下，没有团队成员知道会话的确切内容。大型会话会导致 Java 堆非常繁忙，只能容纳少量并行用户。特别是在使用会话复制进行集群应用时，根据所使用的技术，由于序列化和数据传输而导致的性能损失非常严重。一些项目帮助获取新的硬件和更多内存，但从长远来看，这是一个非常昂贵和风险的解决方案。

会话缓存的产生是因为应用程序的架构没有清楚地定义哪些数据是会话相关的，哪些是持久的，即随时可恢复的。在开发过程中，所有数据都很快地存储在会话中，因为这是一个非常方便的解决方案——通常这些数据不再从会话中删除。要解决这个问题，首先应该使用生产堆转储对会话进行内存分析，并清理不是会话相关的数据。如果获取数据的过程对性能至关重要，例如数据库访问，缓存可以对性能产生积极影响。在最佳情况下，缓存对开发人员来说应该是透明的，嵌入在框架中。例如，Hibernate 提供了一级和二级缓存来优化对数据的访问，但要小心；这些框架的配置和调优应该由专家来完成，否则你很快就会遇到新的性能反模式。

# 实施反模式

有许多 Java 性能反模式和调优技巧可用，但这些技术反模式的问题在于它们严重依赖于 Java 版本和制造商，特别是用例。一个非常常见的反模式是被低估的前端。对于 Web 应用程序，前端通常是性能的软肋。HTML 和 JavaScript 开发经常让真正的应用程序开发人员感到困扰，因此通常对性能进行了低优化。即使在越来越多地使用 DSL 的情况下，连接通常仍然是一个瓶颈，特别是如果是通过**通用移动通信系统**（**UMTS**）或**通用分组无线业务**（**GPRS**）的移动连接。Web 应用程序变得越来越复杂，受到 Web 2.0 炒作的推动，并且越来越接近桌面应用程序。

这种便利导致了延长的等待时间和通过许多服务器往返和大页面增加了更高的服务器和网络负载。有一整套解决方案来优化基于 Web 的界面。使用 GZip 压缩 HTML 页面可以显著减少传输的数据量，并且自 HTTP 1.1 以来所有浏览器都支持。例如，Apache 等 Web 服务器有模块（`mod_gzip`）可以在不改变应用程序的情况下执行压缩。然而，通过一致使用 CSS 并将 CSS 和 JavaScript 源代码交换到自己的文件中，可以快速减小 HTML 页面的大小，以便浏览器更好地缓存。此外，如果正确使用，AJAX 可以显著提高性能，因为可以节省完全重新加载网页的过程；例如，只重新传输列表的内容。

但即使在分析中，通过将页面内容调整到用户的要求，页面的性能也可以得到显着改善。例如，如果页面上只显示 80% 的时间需要的字段，平均传输速率可以显著降低；被删除的字段被卸载到单独的页面上。例如，在许多 Web 应用程序中，有超过 30 个输入字段的表单。在用户填写这些表单的 90% 的情况下，他们只为两个字段填写值，但我们在列表页面或报告中显示了所有这些 30 个字段，包括选择框的所有列表。另一个常见的反模式是**幻影日志**，几乎所有项目中都可以找到。幻影日志生成实际上不必在活动日志级别中创建的日志消息。以下代码是问题的一个例子：

```java
logger.debug ("one log message" + param_1 + "text" + param_2);
```

尽管消息不会在`INFO`级别中记录，但字符串被组装。根据调试和跟踪消息的数量和复杂性，这可能导致巨大的性能损失，特别是如果对象具有重写和昂贵的`toString()`方法。解决方案很简单：

```java
if (logger.isDebugEnabled ()) {
  logger.debug ("One log message" + param_1 + "Text" + param_2);
}
```

在这种情况下，首先查询日志级别，只有在`DEBUG`日志级别处于活动状态时才生成日志消息。为了避免在开发过程中出现性能瓶颈，特别应正确理解所使用的框架。大多数商业和开源解决方案都有足够的性能文档，并且应定期咨询专家以实施解决方案。即使在分析中发现了框架中的瓶颈，也并不意味着问题出现在框架内。在大多数情况下，问题是误用或配置。

# 迭代性能调优过程

迭代性能调优过程是一组指南，将帮助大幅提高应用程序的性能。这些指南可以在迭代中应用，直到达到期望的输出。这些指南也可以应用于各种 Web 应用程序，无论使用何种技术构建应用程序。

任何应用程序的第一个和最重要的部分是静态内容的渲染。静态内容的传递是最常见的性能瓶颈之一。静态内容包括图像、标志、浏览器可执行脚本、级联样式表和主题。由于这些内容始终保持不变，因此无需动态提供这些内容。相反，应该配置 Web 服务器（如 Apache）在向响应提供静态资源时具有长时间的浏览器缓存时间。静态内容传递的改进可以显著提高应用程序的整体性能。Web 服务器还必须配置为压缩静态资源。可以使用 Web 加速器来缓存 Web 资源。对于内容驱动的公共门户，强烈建议通过 Web 加速器缓存整个页面。Varnish 是一种开源的 Web 加速器工具。

服务器资源监控必须作为迭代性能分析的一部分。原因是随着应用程序的增长，它开始在特定时间占用更多资源。对服务器资源的更高需求，如 CPU、内存和磁盘 I/O，可能导致超出操作系统限制并容易发生故障。监控系统必须设置以观察资源利用情况。资源监控通常包括：

+   Web 服务器

+   应用服务器

+   进程-最大与实际

+   线程-最大与实际

+   内存使用

+   CPU 利用率

+   堆内存作为单独的测量

+   磁盘 I/O 操作

+   数据库连接-最大与繁忙

+   JVM 垃圾回收

+   数据库慢查询

+   缓存

+   缓存命中-从缓存中找到结果的次数

+   缓存未命中-未从缓存中找到结果的次数

为了监视资源，可以使用以下工具：

+   `jconsole`和`jvisualvm`与标准的**Java 开发工具包**（**JDK**）捆绑在一起。使用这些工具，我们可以监视 JVM、垃圾收集执行、缓存统计、线程、CPU 使用率、内存使用率和数据库连接池统计。

+   `mpstat`和`vmstat`在基于 Linux 的操作系统上可用。这两者都是命令行工具，用于收集和报告与处理器相关的统计信息。

+   `ifstat`和`iostat`对于监视系统的输入/输出操作很有用。

可能会有一个问题，为什么我们要在遵循最佳实践的同时进行这个迭代的性能调优过程。迭代性能调优过程的目标如下：

+   在各个级别识别系统性能瓶颈

+   根据期望改善门户的性能

+   找到解决方案和方法

+   将解决方案工作流程放在适当的位置

+   了解系统性能的痛点

+   为应用程序定义性能策略

+   根据技术选择性能测量工具

+   了解应用程序的关键用户场景

+   记录关键场景

+   准备足够的数据，在单次执行中对所有风味产生可观的分布式负载

+   定制和组合负载测试脚本，以准备可用于任何单个风味或同时用于所有风味的性能测试套件

+   使用不同场景和负载组合执行性能脚本，以识别响应时间的瓶颈

迭代性能调优过程在应用程序开发生命周期的所有阶段都得到遵循。以下表格演示了正在审查的项目以及输入和输出期望：

| **审查项目** | **输入** | **输出** |
| --- | --- | --- |

| 架构

+   高可用性

+   可扩展性

+   缓存

+   集成

+   网络

+   搜索引擎

+   数据库

| 系统架构图 | 最佳实践建议 |
| --- | --- |
| 用户界面 |

+   前端代码

+   现有技术选择标准

|

+   代码审查

+   更改建议

|

| 硬件配置 |
| --- |

+   Web 服务器细节

+   应用服务器细节

+   数据库细节

+   服务器类型（虚拟或物理）

+   CPU 数量

+   硬盘空间

+   内存配置

| 建议在硬件配置中进行的更改 |
| --- |
| 软件配置 |

+   框架配置

+   依赖模块/集成配置，如果有的话

| 配置更改建议 |
| --- |
| 应用服务器配置 |

+   应用服务器配置文件

| 配置更改建议 |
| --- |
| Web 服务器配置 |

+   Web 服务器配置文件

+   缓存控制设置

+   静态资源处理设置

| 配置更改建议 |
| --- |
| 部署架构 |

+   部署图

+   软件安装细节

+   配置细节

| 部署架构更改建议 |
| --- |
| 代码和数据库 |

+   代码审查

+   数据库设计审查

+   代码重复

+   代码模块化

+   任何第三方库/ API

+   实施的编码标准

+   循环和条件

+   数据规范化

+   索引

+   长时间运行的查询

+   表之间的关系

|

+   代码审查结果

+   改进建议

|

# Spring 对 JMX 的支持

JMX 是 Java 平台中的标准组件。它首次发布于 J2SE 5.0。基本上，JMX 是为应用程序和网络管理定义的一组规范。它使开发人员能够为应用程序中使用的 Java 对象分配管理属性。通过分配管理属性，它使 Java 对象能够与正在使用的网络管理软件一起工作。它为开发人员提供了一种标准的方式来管理应用程序、设备和服务。

JMX 具有三层架构。这三层在这里定义：

+   **探针或仪表层**：此层包含托管的 bean。要管理的应用程序资源已启用 JMX。

+   **代理或 MBeanServer 层**：这一层构成了 JMX 的核心。它作为托管 bean 和应用程序之间的中介。

+   **远程管理层**：此层使远程应用程序能够使用连接器或适配器连接到和访问`MBeanServer`。连接器提供对`mBeanServer`的完全访问权限，而适配器则适应 API。

以下图表显示了 JMX 的架构：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-hiperf-spr5/img/f6d6ebb6-fe47-46b9-b712-2de301215c30.png)

来源：https://www.ibm.com/support/knowledgecenter/en/SSAW57_8.5.5/com.ibm.websphere.nd.multiplatform.doc/ae/cxml_javamanagementx.html

# 托管 bean

托管 bean 是一种 Java bean。它专门用于 JMX 技术，并且是使用**依赖注入**（**DI**）技术创建的。在 JMX 中，资源被表示为**托管 bean**（**MBean**）。这些托管 bean 被注册到核心托管 bean 服务器中。因此，托管 bean 可以被视为 Java 服务、组件或设备的包装器。由于所有托管组件都注册到 MBeans 服务器，因此它用于管理所有托管 bean。托管 bean 服务器允许服务器组件连接并找到托管 bean。典型的 JMX 代理由托管 bean 服务器和与托管 bean 交互所需的服务组成。

JMX 规范描述了标准连接器。这些连接器也被称为**JMX 连接器**。JMX 连接器允许我们从远程管理应用程序访问 JMX 代理。连接器可以使用不同的协议与相同的管理接口一起工作。

以下是为什么应该使用 JMX 的原因：

+   它提供了一种在不同设备上管理应用程序的方法

+   它提供了一种标准的管理 Java 应用程序和网络的方法

+   它可以用来管理 JVM

+   它提供了一个可扩展和动态的管理接口

通过对 JMX 的基本理解，让我们继续检查它在 Spring 中的支持。Spring 对 JMX 的支持使我们能够很容易地将 Spring 应用程序转换为 JMX 架构。

Spring 的 JMX 支持提供的功能如下：

+   自动将 Spring bean 注册为托管 bean

+   用于控制 Spring beans 的管理接口的灵活结构

+   远程连接器上托管 bean 的声明性方法

+   本地和远程托管 bean 资源的代理

这些功能可以在不与 Spring 或 JMX 的类或接口耦合的情况下工作。Spring JMX 支持有一个名为`MBeanExporter`的类。这个类负责收集 Spring beans 并将它们注册到托管的 beans 服务器中。

以下是 Spring bean 的示例：

```java
package com.springhighperformance.jmx;

public class Calculator {
  private String name;
  private int lastCalculation;

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

  public int getLastCalculation() {
    return lastCalculation;
  }

  public void calculate(int x, int y) {
    lastCalculation = x + y;
  }
}
```

为了将此 bean 及其属性公开为托管属性和操作，应在配置文件中进行以下配置：

```java
<beans>
  <bean id="exporter"     
    class="org.springframework.jmx.export.MBeanExporter
    " lazy-init="false">
    <property name="beans">
      <map>
        <entry key="bean:name=calculatorBean1" value-
        ref="calculatorBean"/>
      </map>
    </property>
  </bean>

  <bean id="calculatorBean" 
    class="com.springhighperformance.jmx.Calculator">
    <property name="name" value="Test"/>
    <property name="lastCalculation" value="10"/>
  </bean>
</beans>
```

从前面的配置中，要查找的一个重要的 bean 定义是导出器 bean。导出器 bean 的 beans map 属性指示要将哪些 Spring beans 暴露为 JMX beans 到 JMX 托管的 beans 服务器。

通过上述配置，假设托管 bean 服务器必须在 Spring 应用程序可访问的环境中运行。如果托管 bean 服务器或`MBeanServer`正在运行，Spring 将尝试找到它并注册所有 bean。当应用程序在 Tomcat 或 IBM WebSphere 中运行时，这种默认行为是有用的，因为它有捆绑的`MBeanServer`。

在其他情况下，我们必须创建一个`MBeanServer`实例，如下所示：

```java
<beans>
  <bean id="mbeanServer" class="org.springframework.jmx.support.
    MBeanServerFactoryBean"/>

  <bean id="exporter" 
   class="org.springframework.jmx.export.MBeanExporter">
    <property name="beans">
      <map>
        <entry key="bean:name=calculatorBean1" value-
         ref="calculatorBean"/>
      </map>
    </property>
    <property name="server" ref="mbeanServer"/>
  </bean>

  <bean id="calculatorBean" 
   class="com.springhighperformance.jmx.Calculator">
    <property name="name" value="Test"/>
    <property name="lastCalculation" value="10"/>
  </bean>
</beans>
```

我们必须在`MBeanExporter` bean 上指定 server 属性，以将其与已创建的`MBeanServer`关联起来。

随着 JDK 5.0 中注解的引入，Spring 使得可以使用注解将 Spring beans 注册为 JMX beans。

以下是使用`@ManagedResource`注解定义的`Calculator` bean 的示例：

```java
package com.springhighperformance.jmx;

import org.springframework.jmx.export.annotation.ManagedAttribute;
import org.springframework.jmx.export.annotation.ManagedOperation;
import org.springframework.jmx.export.annotation.ManagedOperationParameter;
import org.springframework.jmx.export.annotation.ManagedOperationParameters;
import org.springframework.jmx.export.annotation.ManagedResource;

  @ManagedResource(objectName = "Examples:type=JMX,name=Calculator",
    description = "A calculator to demonstrate JMX in the 
    SpringFramework")
  public class Calculator {
  private String name;
  private int lastCalculation;

  @ManagedAttribute(description = "Calculator name")
  public String getName() {
    return name;
  }

  @ManagedAttribute(description = "Calculator name")
  public void setName(String name) {
    this.name = name;
  }

  @ManagedAttribute(description = "The last calculation")
  public int getLastCalculation() {
    return lastCalculation;
  }

  @ManagedOperation(description = "Calculate two numbers")
  @ManagedOperationParameters({
      @ManagedOperationParameter(name = "x",
          description = "The first number"),
      @ManagedOperationParameter(name = "y",
          description = "The second number") })
  public void calculate(int x, int y) {
    lastCalculation = x + y;
  }
}
```

`@ManagedAttribute`和`@ManagedOperation`注解用于将 bean 的属性和方法暴露给管理 bean 服务器。

以下是实例化受管 bean 的客户端代码，可以通过诸如 JConsole 或 VisualVM 之类的工具进行监视：

```java
package com.springhighperformance.jmx;
import java.util.Random;

import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.EnableMBeanExport;

@Configuration
@EnableMBeanExport
public class JmxSpringMain {
  private static final Random rand = new Random();

    @Bean
    public Resource jmxResource() {
        return new Resource();
    }

    @Bean
    public Calculator calculator() {
        return new Calculator();
    }

    public static void main(String[] args) throws InterruptedException {
        ApplicationContext context = new 
        AnnotationConfigApplicationContext(JmxSpringMain.class);
        do {
          Calculator cal = context.getBean(Calculator.class);
          cal.calculate(rand.nextInt(), rand.nextInt());
          Thread.sleep(Long.MAX_VALUE);
        } while(true);
    }
}
```

一旦暴露为受管 bean，这些资源可以通过诸如 JConsole 或 VisualVM 之类的工具监视各种参数，例如对象数量、对象占用的内存以及对象占用的堆内存空间。

以下是 Java VisualVM 的屏幕截图，突出显示了`Calculator`作为受管 bean 的暴露：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-hiperf-spr5/img/ba6700e0-0402-417d-a4ae-1bdb5413c631.jpg)

# 摘要

这是本书中最重要的章节之一。它专注于性能测量和增强策略。本章类似于现实生活中的健康检查场景。如果一个人不舒服，第一步是识别症状以便诊断和治疗疾病。同样，本章从识别性能下降的症状开始，然后进入性能调优生命周期。描述了性能调优模式和反模式，类似于应遵循的最佳实践。接着是迭代性能调优过程和 Spring 框架中的 JMX 支持。我们看到了 Spring bean 被转换为 JMX 受管 bean 的示例。

下一章重点介绍 JVM 的微调。这不是针对 Spring 应用程序特定的调整，而是适用于在 JVM 上运行的任何应用程序。本章将深入探讨 JVM 的内部细节，这些细节对开发人员来说并不是很熟悉。让我们准备好深入 JVM。
