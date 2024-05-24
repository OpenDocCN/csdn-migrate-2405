# Java8 反应式编程学习指南（三）

> 原文：[`zh.annas-archive.org/md5/A4E30A017482EBE61466A691985993DC`](https://zh.annas-archive.org/md5/A4E30A017482EBE61466A691985993DC)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：点对点网络

**点对点**（**P2P**）计算机网络指的是一种架构，其节点经常充当服务器和客户端。P2P 系统的主要目标是消除需要单独的服务器来管理系统的需求。P2P 网络的配置将随着节点以不可预测的方式加入和离开网络而动态变化。节点可能在处理速度、带宽支持和存储能力等因素上有所不同。对等方这个术语意味着节点之间的平等性。

对 P2P 网络有各种定义和解释。它们可以被描述为分散的、不断变化的、自我调节的架构。服务器倾向于提供服务，而客户端请求服务。P2P 节点通常两者兼而有之。纯 P2P 网络不会有被指定为客户端或服务器的节点。实际上，这些网络很少见。大多数 P2P 网络依赖于中央设施，如 DNS 服务器，提供支持。

某些网络可能是客户端/服务器架构和更纯粹的 P2P 架构之间的混合体，在这种情况下，从不会有特定的节点充当“主”服务器。例如，文件共享 P2P 可能使用网络的节点来下载文件，而服务器可能提供额外的支持信息。

P2P 可以以多种方式分类。我们将使用一些常见的分类类别，有助于理解 P2P 网络的性质。一个分类是基于**索引**的执行过程，即找到一个节点的过程：

+   **集中式**：这是指一个中央服务器跟踪对等方之间数据位置的过程

+   **本地**：这是指每个对等方跟踪自己的数据的情况

+   **分布式**：这是指数据引用由多个对等方维护的情况

混合 P2P 网络使用集中式索引方案。纯 P2P 网络使用本地或分布式索引。

算法用于确定系统中信息的位置。系统是分散的，没有执行算法的主服务器。该算法支持一个自组织的系统，随着节点的加入和移除而动态重新配置自身。此外，这些系统理想情况下会在网络成员变化时平衡负载和资源。

在本章中，我们将涵盖：

+   P2P 的概念和术语

+   Java 对 P2P 网络的支持

+   分布式哈希表的性质

+   FreePastry 如何支持 P2P 应用程序

### 注意

P2P 应用程序提供了传统客户端/服务器架构的灵活替代方案。

# P2P 功能/特征

理解 P2P 网络的一种方式是审视其特征。这些特征包括以下内容：

+   向系统提供资源的节点，包括：

+   数据存储

+   计算资源

+   它们提供一系列服务的支持

+   它们非常可扩展和容错

+   它们支持资源的负载平衡

+   它们可能支持有限的匿名性

P2P 系统的性质是用户可能无法访问特定节点以使用服务或资源。随着节点随机加入和离开系统，特定节点可能不可用。算法将决定系统如何响应请求。

P2P 系统的基本功能包括：

+   对等方在网络中的注册

+   对等方发现-确定哪个对等方拥有感兴趣的信息的过程

+   对等方之间的消息传递

并非所有对等方都执行所有这些功能。

P2P 系统的资源使用**全局唯一标识符**（**GUID**）进行标识，通常使用安全哈希函数生成，我们将在 DHT 组件中进行讨论。GUID 不打算供人类阅读。它是一个随机生成的值，几乎没有冲突的机会。

P2P 的节点使用**路由** **覆盖**进行组织。这是一种将请求路由到适当节点的**中间件**类型。覆盖指的是位于物理网络之上的网络，由 IP 地址标识资源。我们可以将网络构想为由一系列基于 IP 的节点组成。然而，覆盖是这些节点的一个子集，通常专注于单一任务。

路由覆盖将考虑因素，例如用户和资源之间的节点数量，以及连接的带宽，以确定哪个节点应该满足请求。资源经常会被复制或甚至分布在多个节点之间。路由覆盖将尝试提供到资源的最佳路径。

随着节点加入和离开系统，路由覆盖需要考虑这些变化。当一个节点加入系统时，可能会被要求承担一些责任。当一个节点离开时，系统的其他部分可能需要承担一些离开节点的责任。

在本章中，我们将解释通常作为系统一部分嵌入的各种概念。我们将简要概述不同的 P2P 应用程序，然后讨论 Java 对这种架构的支持。我们演示了分布式哈希表的使用，并深入研究了 FreePastry，这将使我们了解许多 P2P 框架的工作原理。

在适当的情况下，我们将说明如何手动实现一些这些概念。虽然不需要使用这些实现来使用系统，但它们将提供对这些基本概念的更深入的理解。

# 基于应用程序的 P2P 网络

有许多基于 P2P 网络的应用程序。它们可以用于以下用途：

+   **内容分发**：这是文件共享（文件、音乐、视频、图像）

+   **分布式计算**：这是将问题分解为较小任务并以并行方式执行的情况

+   **Collaboration**：这是用户共同解决共同问题时的情况

+   **平台**：这些是构建 P2P 应用程序的系统，如 JXTA 和 Pastry

分布式计算利用更多数量的较小计算机的能力来执行任务。这种方法适用的问题需要被分解成较小的单元，然后并行在多台机器上执行。然后需要将这些较小任务的结果组合起来产生最终结果。

P2P 网络支持许多应用程序，例如以下应用程序：

+   **Skype**：这是一个视频会议应用程序

+   **Freecast**：这是一个点对点的流媒体音频程序

+   **BitTorrent**：这是一个流行的点对点文件共享系统

+   **Tor**：这个程序可以保护用户的身份

+   **Haihaisoft**：用于分发预先录制的电视节目

+   **WoW**：这使用 P2P 进行游戏更新

+   **YaCy**：这是一个搜索引擎和网络爬虫

+   **Octoshape**：支持实时电视

在[`p2peducation.pbworks.com/w/page/8897427/FrontPage`](http://p2peducation.pbworks.com/w/page/8897427/FrontPage)上可以找到对 P2P 应用程序的很好概述。

# Java 对 P2P 应用程序的支持

Java 支持超出了在早期章节中详细介绍的低级套接字支持，包括各种框架。这些框架从众所周知的框架（如 JXTA）到小型的功能有限的协议都有。这些框架为更专业的应用程序提供了基础。

下表列出了几个这些框架：

| P2P framework | URL |
| --- | --- |
| TomP2P | [`tomp2p.net/`](http://tomp2p.net/) |
| JXTA | [`jxta.kenai.com/`](https://jxta.kenai.com/) |
| Hive2Hive | [`github.com/Hive2Hive/Hive2Hive`](https://github.com/Hive2Hive/Hive2Hive) |
| jnmp2p | [`code.google.com/p/jnmp2p/`](https://code.google.com/p/jnmp2p/) |
| FlexGP | [`flexgp.github.io/flexgp/javalibrary.html`](http://flexgp.github.io/flexgp/javalibrary.html) |
| JMaay | [`sourceforge.net/projects/jmaay/`](http://sourceforge.net/projects/jmaay/) |
| P2P-MPI | [`grid.u-strasbg.fr/p2pmpi/`](http://grid.u-strasbg.fr/p2pmpi/) |
| Pastry | [`www.freepastry.org/`](http://www.freepastry.org/) |

这些框架使用算法在对等方之间路由消息。哈希表经常构成这些框架的基础，如下所讨论的。

# 分布式哈希表

**分布式哈希表**（**DHT**）使用键/值对在网络中定位资源。这个映射函数分布在对等方之间，使其分布式。这种架构使得 P2P 网络可以轻松扩展到大量节点，并且可以处理对等方随机加入和离开网络。DHT 是支持核心 P2P 服务的基础。许多应用使用 DHT，包括 BitTorrent、Freenet 和 YaCy。

以下图示了将键映射到值。键通常是包含资源标识的字符串，比如书名；值是用来表示资源的数字。这个数字可以用来在网络中定位资源，并且可以对应于节点的标识符。

![分布式哈希表](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-net-prog-java/img/B04915_05_01.jpg)

P2P 网络已经使用了一段时间。这些网络的演变反映在资源如何被映射，如 Napster、Gnutella 和 Freenet 所体现的那样。

+   Napster ([`en.wikipedia.org/wiki/Napster`](https://en.wikipedia.org/wiki/Napster))是第一个大规模 P2P 内容传送系统。它使用服务器来跟踪网络中的节点。节点保存实际数据。当客户端需要这些数据时，服务器将查找保存数据的当前节点集，并将该节点的位置发送回客户端。然后客户端将联系保存数据的节点。这使得它容易受到攻击，并最终通过诉讼导致了它的消亡。

+   Gnutella ([`web.archive.org/web/20080525005017`](https://web.archive.org/web/20080525005017), [`www.gnutella.com/`](http://www.gnutella.com/))不使用中央服务器，而是向网络中的每个节点广播。这导致网络被消息淹没，并且这种方法在后来的版本中被修改。

+   Freenet ([`freenetproject.org/`](https://freenetproject.org/))使用启发式基于键的路由方案，专注于审查和匿名问题。然而，DHS 使用更结构化的基于键的路由方法，导致以下结果：

+   去中心化

+   容错性

+   可伸缩性

+   效率

然而，DHT 不支持精确匹配搜索。如果需要这种类型的搜索，就必须添加。

## DHT 组件

**键空间**是一组用于标识元素的 160 位字符串（键）。**键空间分区**是将键空间分割成网络节点的过程。覆盖网络连接节点。

常用的哈希算法是**安全哈希算法**（**SHA-1**）([`en.wikipedia.org/wiki/SHA-1`](https://en.wikipedia.org/wiki/SHA-1))。SHA-1 是由 NSA 设计的，生成一个称为消息摘要的 160 位哈希值。大多数 P2P 不需要开发人员显式执行哈希函数。但是，了解如何执行是有益的。以下是使用 Java 创建摘要的示例。

`MessageDigest`类的`getInstance`方法接受一个指定要使用的算法的字符串，并返回一个`MessageDigest`实例。它的`update`方法需要一个包含要哈希的键的字节数组。在这个例子中，使用了一个字符串。`digest`方法返回一个包含哈希值的字节数组。然后将字节数组显示为十六进制数：

```java
        String message = "String to be hashed";
        try {
            MessageDigest messageDigest = 
                MessageDigest.getInstance("SHA-1");
            messageDigest.update(message.getBytes());
            byte[] digest = messageDigest.digest();

            StringBuffer buffer = new StringBuffer();
            for (byte element : digest) {
                buffer.append(Integer
                    .toString((element & 0xff) + 0x100, 16)
                    .substring(1));
            }
            System.out.println("Hex format : " + 
                buffer.toString());

        } catch (NoSuchAlgorithmException ex) {
            // Handle exceptions
        }
```

执行这个序列将产生以下输出：

**十六进制格式：434d902b6098ac050e4ed79b83ad93155b161d72**

要存储数据，比如文件，我们可以使用文件名创建一个键。然后使用 put 类型函数来存储数据：

```java
put(key, data) 
```

要检索与密钥对应的数据，使用 get 类型函数：

```java
data = get(key)
```

覆盖中的每个节点都包含由密钥表示的数据，或者它是更接近包含数据的节点的节点。路由算法确定了前往包含数据的节点的下一个节点。

## DHT 实现

有几种 Java 实现的 DHT，如下表所示：

| 实现 | URL |
| --- | --- |
| openkad | [`code.google.com/p/openkad/`](https://code.google.com/p/openkad/) |
| Open Chord | [`open-chord.sourceforge.net/`](http://open-chord.sourceforge.net/) |
| TomP2P | [`tomp2p.net/`](http://tomp2p.net/) |
| JDHT | [`dks.sics.se/jdht/`](http://dks.sics.se/jdht/) |

我们将使用**Java 分布式哈希表**（**JDHT**）来说明 DHT 的使用。

## 使用 JDHT

为了使用 JDHT，您需要以下表中列出的 JAR 文件。`dks.jar`文件是主要的 jar 文件。但是，JDHT 还使用其他两个 JAR 文件。`dks.jar`文件的备用来源如下所示：

| JAR | 网站 |
| --- | --- |
| `dks.jar` |

+   [`dks.sics.se/jdht/`](http://dks.sics.se/jdht/)

+   [`www.ac.upc.edu/projects/cms/browser/cms/trunk/lib/dks.jar?rev=2`](https://www.ac.upc.edu/projects/cms/browser/cms/trunk/lib/dks.jar?rev=2)

|

| `xercesImpl.jar` | [`www.java2s.com/Code/Jar/x/DownloadxercesImpljar.htm`](http://www.java2s.com/Code/Jar/x/DownloadxercesImpljar.htm) |
| --- | --- |
| Apache log4j 1.2.17 | [`logging.apache.org/log4j/1.2/download.html`](https://logging.apache.org/log4j/1.2/download.html) |

以下示例已经改编自网站上的示例。首先，我们创建一个`JDHT`实例。JDHT 使用端口`4440`作为其默认端口。有了这个实例，我们可以使用它的`put`方法将键/值对添加到表中：

```java
    try {
        JDHT DHTExample = new JDHT();
        DHTExample.put("Java SE API", 
           "http://docs.oracle.com/javase/8/docs/api/");
        ...
    } catch (IOException ex) {
        // Handle exceptions
    }
```

为了使客户端能够连接到此实例，我们需要获取对此节点的引用。如下所示实现：

```java
    System.out.println(((JDHT) DHTExample).getReference());
```

以下代码将使程序保持运行，直到用户终止它。然后使用`close`方法关闭表：

```java
    Scanner scanner = new Scanner(System.in);
    System.out.println("Press Enter to terminate application: ");
    scanner.next();
    DHTExample.close();
```

当程序执行时，您将获得类似以下的输出：

**dksref://192.168.1.9:4440/0/2179157225/0/1952355557247862269**

**按 Enter 键终止应用程序：**

客户端应用程序描述如下。使用不同的端口创建一个新的 JDHT 实例。第二个参数是对第一个应用程序的引用。您需要复制引用并将其粘贴到客户端中。每次执行第一个应用程序时，都会生成一个不同的引用：

```java
    try {
        JDHT myDHT = new JDHT(5550, "dksref://192.168.1.9:4440" 
            + "/0/2179157225/0/1952355557247862269");
        ...
    } catch (IOException | DKSTooManyRestartJoins | 
             DKSIdentifierAlreadyTaken | DKSRefNoResponse ex) {
        // Handle exceptions
    }
```

接下来，我们使用`get`方法检索与密钥关联的值。然后显示该值并关闭应用程序：

```java
    String value = (String) myDHT.get("Java SE API");
    System.out.println(value);
    myDHT.close();
```

输出如下：

**http://docs.oracle.com/javase/8/docs/api/**

这个简单的演示说明了分布式哈希表的基础知识。

# 使用 FreePastry

Pastry（[`www.freepastry.org/`](http://www.freepastry.org/)）是一个 P2P 路由覆盖系统。FreePastry（[`www.freepastry.org/FreePastry/`](http://www.freepastry.org/FreePastry/)）是 Pastry 的开源实现，足够简单，可以用来说明 P2P 系统的许多特性。Pastry 将在*O(log n)*步骤中路由具有*n*节点网络的消息。也就是说，给定一个节点网络，最多需要*log2 n*步骤才能到达该节点。这是一种高效的路由方法。但是，虽然只需要遍历三个节点就可以获得资源，但可能需要大量的 IP 跳数才能到达它。

Pastry 在路由过程中使用**叶集**的概念。每个节点都有一个叶集。叶集是此节点数字上最接近的节点的 GUIDS 和 IP 地址的集合。节点在逻辑上排列成一个圆圈，如下所示。

在下图中，每个点代表一个带有标识符的节点。这里使用的地址范围从`0`到`FFFFFF`。真实地址范围从`0`到`2128`。如果代表请求的消息起源于地址`9341A2`并且需要发送到地址`E24C12`，那么基于数字地址，覆盖路由器可能通过中间节点路由消息，如箭头所示：

![使用 FreePastry](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-net-prog-java/img/B04915_05_02.jpg)

其他应用程序已构建在 FreePastry 之上，包括：

+   **SCRIBE**：这是一个支持发布者/订阅者范式的组通信和事件通知系统

+   **PAST**：这是一个存档存储实用程序系统

+   **SplitStream**：该程序支持内容流和分发

+   **Pastiche**：这是备份系统

每个应用程序都使用 API 来支持它们的使用。

## FreePastry 演示

为了演示 FreePastry 如何支持 P2P 应用程序，我们将创建一个基于[`trac.freepastry.org/wiki/FreePastryTutorial`](https://trac.freepastry.org/wiki/FreePastryTutorial)中找到的 FreePastry 教程的应用程序。在这个演示中，我们将创建两个节点，并演示它们如何发送和接收消息。演示使用三个类：

+   `FreePastryExample`：这用于引导网络

+   `FreePastryApplication`：这执行节点的功能

+   `PastryMessage`：这是在节点之间发送的消息

让我们从引导应用程序开始。

### 了解 FreePastryExample 类

有几个组件与 FreePastry 应用程序一起使用。这些包括：

+   **环境**：这个类代表应用程序的环境

+   **绑定端口**：这代表应用程序将绑定到的本地端口

+   **引导端口**：这是用于节点的`InetAddress`的引导端口

+   **引导地址**：这是引导节点的 IP 地址

接下来定义`FreePastryExample`类。它包含一个主方法和一个构造函数：

```java
public class FreePastryExample {
    ...
}
```

我们将从`main`方法开始。首先创建`Environment`类的实例。这个类保存节点的参数设置。接下来，将 NAT 搜索策略设置为从不，这样我们就可以在本地 LAN 中使用程序而不会有困难：

```java
    public static void main(String[] args) throws Exception {
        Environment environment = new Environment();
        environment.getParameters()
            .setString("nat_search_policy", "never");
        ...
    }
```

端口和`InetSocketAddress`实例被初始化。我们将此时两个端口设置为相同的数字。我们使用 IP 地址`192.168.1.14`来实例化`InetAddress`对象。您需要使用您的机器的地址。这是一个本地 LAN 地址。不要使用`127.0.0.1`，因为它将无法正常工作。`InetAddress`对象以及`bootPort`值用于创建`InetSocketAddress`实例。所有这些都放在 try 块中来处理异常：

```java
    try {
        int bindPort = 9001;
        int bootPort = 9001;
        InetAddress bootInetAddress = 
            InetAddress.getByName("192.168.1.14"); 
        InetSocketAddress bootAddress = 
                new InetSocketAddress(bootInetAddress, bootPort);
        System.out.println("InetAddress: " + bootInetAddress);
        ...
    } catch (Exception e) {
        // Handle exceptions
    }
```

最后一个任务是通过调用构造函数创建`FreePastryExample`类的实例：

```java
    FreePastryExample freePastryExample = 
        new FreePastryExample(bindPort, bootAddress, environment);
```

构造函数将创建并启动节点的应用程序。为了实现这一点，我们需要创建一个`PastryNode`实例，并将应用程序附加到它上面。为了创建节点，我们将使用一个工厂。

每个节点都需要一个唯一的 ID。`RandomNodeIdFactory`类根据当前环境生成 ID。使用此对象与绑定端口和环境，创建`SocketPastryNodeFactory`的实例。使用此工厂调用`newNode`方法来创建我们的`PastryNode`实例：

```java
    public FreePastryExample(int bindPort, 
            InetSocketAddress bootAddress, 
            Environment environment) throws Exception {
        NodeIdFactory nidFactory = 
            new RandomNodeIdFactory(environment);
        PastryNodeFactory factory = 
            new SocketPastryNodeFactory(
                nidFactory, bindPort, environment);
        PastryNode node = factory.newNode();
        ...
    }
```

接下来，创建`FreePastryApplication`类的实例，并使用`boot`方法启动节点：

```java
    FreePastryApplication application = 
        new FreePastryApplication(node);
    node.boot(bootAddress);
    ...
```

然后显示节点的 ID，如下一个代码序列所示。由于网络中会有多个节点，我们暂停 10 秒钟，以便其他节点启动。我们使用 FreePastry 计时器来实现这种延迟。创建一个随机节点 ID，并调用应用程序的`routeMessage`消息将消息发送到该节点：

```java
    System.out.println("Node " + node.getId().toString() + " created");
    environment.getTimeSource().sleep(10000);
    Id randomId = nidFactory.generateNodeId();
    application.routeMessage (randomId);
```

在执行程序之前，我们需要开发应用程序类。

### 了解 FreePastryApplication 类

`FreePastryApplication`类实现了`Application`接口，并实现了节点的功能。构造函数创建并注册了一个`Endpoint`实例，并初始化了一个消息。节点使用`Endpoint`实例来发送消息。以下是类和构造函数的示例：

```java
public class FreePastryApplication implements Application {
    protected Endpoint endpoint;
    private final String message;
    private final String instance = " Instance ID";

    public FreePastryApplication(Node node) {
        this.endpoint = node.buildEndpoint(this, instance);
        this.message = "Hello there! from Instance: "
                + instance + " Sent at: [" + getCurrentTime() 
                + "]";
        this.endpoint.register();
    }

    ...
}
```

当这段代码被编译时，您可能会收到“在构造函数中泄漏 this”的警告。这是由于使用`this`关键字将构造函数的对象引用作为参数传递给`buildEndpoint`方法。这是一个潜在的不良实践，因为在传递时对象可能尚未完全构造。另一个线程可能会在对象准备好之前尝试对其进行操作。如果它被传递给执行常见初始化的包私有方法，那么这不会是太大的问题。在这种情况下，它不太可能引起问题。

`Application`接口要求实现三种方法：

+   `deliver`：当接收到消息时调用

+   `forward`：用于转发消息

+   `update`：通知应用程序一个节点已加入或离开了一组本地节点

我们只对这个应用程序中的`deliver`方法感兴趣。此外，我们将添加`getCurrentTime`和`routeMessage`方法到应用程序中。我们将使用`getCurrentTime`方法来显示我们发送和接收消息的时间。`routeMessage`方法将向另一个节点发送消息。

`getCurrentTime`方法如下。它使用`EndPoint`对象来访问节点的环境，然后获取时间：

```java
    private long getCurrentTime() {
        return this.endpoint
                .getEnvironment()
                .getTimeSource()
                .currentTimeMillis();
    }
```

`routeMessage`方法传递了目标节点的标识符。消息文本是通过添加端点和时间信息来构造的。使用端点标识符和消息文本创建了一个`PastryMessage`实例。然后调用`route`方法来发送这条消息：

```java
    public void routeMessage(Id id) {
        System.out.println(
                "Message Sent\n\tCurrent Node: " +
                   this.endpoint.getId()
                + "\n\tDestination: " + id
                + "\n\tTime: " + getCurrentTime());
        Message msg = new PastryMessage(endpoint.getId(), 
            id, message);
        endpoint.route(id, msg, null);
    }
```

当节点接收到消息时，将调用`deliver`方法。该方法的实现如下。显示了端点标识符、消息和到达时间。这将帮助我们理解消息是如何发送和接收的：

```java
    public void deliver(Id id, Message message) {
        System.out.println("Message Received\n\tCurrent Node: " 
            + this.endpoint.getId() + "\n\tMessage: " 
            + message + "\n\tTime: " + getCurrentTime());
    }
```

`PastryMessage`类实现了`Message`接口，如下所示。构造函数接受目标、源和消息：

```java
public class PastryMessage implements Message {
  private final Id from;
  private final Id to;
  private final String messageBody;

  public PastryMessage(Id from, Id to, String messageBody) {
    this.from = from;
    this.to = to;
    this.messageBody = messageBody;
  }

    ...
}
```

`Message`接口拥有一个需要被重写的`getPriority`方法。在这里，我们返回一个低优先级，以便它不会干扰底层的 P2P 维护流量：

```java
  public int getPriority() {
    return Message.LOW_PRIORITY;
  }
```

`toString`方法被重写以提供消息的更详细描述：

```java
  public String toString() {
    return "From: " + this.from 
            + " To: " + this.to 
            + " [" + this.messageBody + "]";
  }
```

现在，我们准备执行示例。执行`FreePastryExample`类。初始输出将包括以下输出。显示了缩写的节点标识符，本例中为`<0xB36864..>`。您得到的标识符将会不同：

**InetAddress：/192.168.1.14 节点<0xB36864..>已创建**

之后，发送一个暂停消息，随后当前节点接收到该消息。这条消息是在`FreePastryExample`类中创建的，以下是重复的代码以供您参考：

```java
    Id randomId = nidFactory.generateNodeId();
    application.routeMessage(randomId);
```

使用了一个随机标识符，因为我们没有特定的节点来发送消息。当消息被发送时，将生成以下输出。本次运行的随机标识符是`<0x83C7CD..>`：

**消息已发送**

**当前节点：<0xB36864..>**

**目标：<0x83C7CD..>**

**时间：1441844742906**

**消息已接收**

**当前节点：<0xB36864..>**

**消息：从：<0xB36864..> 到：<0x83C7CD..> [你好！来自实例：实例 ID 发送于：[1441844732905]]**

**时间：1441844742915**

发送和接收消息之间的时间是最短的。如果 P2P 网络由更大的节点集合组成，将会出现更显著的延迟。

在先前的输出中，节点地址被截断了。我们可以使用`toStringFull`方法，如下所示，来获取完整的地址：

```java
    System.out.println("Node " + node.getId().toStringFull() 
       + " created");
```

这将产生类似以下的输出：

**节点 B36864DE0C4F9E9C1572CBCC095D585EA943B1B4 已创建**

我们没有为消息提供特定的地址。相反，我们随机生成了地址。这个应用程序演示了 FreePastry 应用程序的基本元素。其他层用于促进节点之间的通信，比如 Scribe 支持的发布者/提供者范式。

我们可以使用相同的程序启动第二个节点，但我们需要使用不同的绑定端口以避免绑定冲突。任一节点发送的消息不一定会被另一个节点接收。这是 FreePastry 生成的路由的结果。

### 向特定节点发送消息

要直接向节点发送消息，我们需要其标识符。要获取远程节点的标识符，我们需要使用叶集。这个集合不严格地是一个集合，因为对于小型网络（比如我们正在使用的网络），同一个节点可能会出现两次。

`LeafSet`类代表这个集合，并且有一个`get`方法，将为每个节点返回一个`NodeHandle`实例。如果我们有这个节点句柄，我们可以向节点发送消息。

为了演示这种方法，将以下方法添加到`FreePastryApplication`类中。这类似于`routeMessage`方法，但它使用节点句柄作为`route`方法的参数：

```java
    public void routeMessageDirect(NodeHandle nh) {
        System.out.println("Message Sent Direct\n\tCurrent Node: "
                + this.endpoint.getId() + " Destination: " + nh
                + "\n\tTime: " + getCurrentTime());
        Message msg = 
            new PastryMessage(endpoint.getId(), nh.getId(),
                "DIRECT-" + message);
        endpoint.route(null, msg, nh);
    }
```

将以下代码序列添加到`FreePastryExample`构造函数的末尾。可选择注释掉使用`routeMessage`方法的先前代码。首先，我们暂停 10 秒，以便其他节点加入网络：

```java
    environment.getTimeSource().sleep(10000);

```

接下来，我们创建`LeafSet`类的一个实例。`getUniqueSet`方法返回叶集，不包括当前节点。然后，for-each 语句将使用`routeMessageDirect`变量将消息发送到集合的节点：

```java
    LeafSet leafSet = node.getLeafSet();
    Collection<NodeHandle> collection = leafSet.getUniqueSet();
    for (NodeHandle nodeHandle : collection) {
        application.routeMessageDirect(nodeHandle);
        environment.getTimeSource().sleep(1000);
    }

```

使用绑定端口`9001`启动`FreePastryExample`类。然后，将绑定端口更改为`9002`，并再次启动该类。几秒钟后，您将看到类似以下输出。第一组输出对应应用程序的第一个实例，而第二组对应第二个实例。每个实例将向另一个实例发送一条消息。请注意消息发送和接收时使用的时间戳：

```java
InetAddress: /192.168.1.9
Node <0xA5BFDA..> created
Message Sent Direct
 Current Node: <0xA5BFDA..> Destination: [SNH: <0x2C6D18..>//192.168.1.9:9002]
 Time: 1441849240310
Message Received
 Current Node: <0xA5BFDA..>
 Message: From: <0x2C6D18..> To: <0xA5BFDA..> [DIRECT-Hello there! from Instance: Instance ID Sent at: [1441849224879]]
 Time: 1441849245038

InetAddress: /192.168.1.9
Node <0x2C6D18..> created
Message Received
 Current Node: <0x2C6D18..>
 Message: From: <0xA5BFDA..> To: <0x2C6D18..> [DIRECT-Hello there! from Instance: Instance ID Sent at: [1441849220308]]
 Time: 1441849240349
Message Sent Direct
 Current Node: <0x2C6D18..> Destination: [SNH: <0xA5BFDA..>//192.168.1.9:9001]
 Time: 1441849245020

```

FreePastry 还有很多内容，我们无法在这里详细说明。然而，这些示例提供了 P2P 应用程序开发性质的感觉。其他 P2P 框架以类似的方式工作。

# 总结

在本章中，我们探讨了 P2P 网络的性质和用途。这种架构将所有节点视为平等，避免使用中央服务器。节点使用覆盖网络进行映射，有效地在 IP 地址空间中创建了一个节点的子网络。这些节点的能力各不相同，会以随机的方式加入和离开网络。

我们看到了分布式哈希表如何支持在网络中识别和定位节点。路由算法使用这个表来通过节点之间的消息传递来满足请求。我们演示了 Java 分布式哈希表来说明 DHT 的使用。

有几个基于 Java 的开源 P2P 框架可用。我们使用 FreePastry 来演示 P2P 网络的工作原理。具体来说，我们向您展示了节点如何加入网络以及消息如何在节点之间发送。这提供了对这些框架如何运作的更好理解。

在下一章中，我们将探讨 UDP 协议的性质以及它如何支持多播。


# 第六章：UDP 和多播

**用户数据报协议**（**UDP**）位于 IP 之上，提供了 TCP 的不可靠对应。UDP 在网络中的两个节点之间发送单独的数据包。UDP 数据包不知道其他数据包，并且不能保证数据包实际到达其预期目的地。当发送多个数据包时，不能保证到达顺序。UDP 消息只是被发送然后被遗忘，因为没有来自接收方的确认。

UDP 是一种无连接的协议。两个节点之间没有消息交换来促进数据包传输。关于连接的状态信息不会被维护。

UDP 适用于需要高效传递的服务，且不需要传递保证的情况。例如，它用于**域名系统**（**DNS**）服务，**网络时间协议**（**NTP**）服务，**语音传输**（**VOIP**），P2P 网络的网络通信协调，以及视频流媒体。如果视频帧丢失，那么如果丢失不频繁，则观看者可能永远不会注意到。

有几种使用 UDP 的协议，包括：

+   **实时流媒体协议（RTSP）**：该协议用于控制媒体的流媒体

+   **路由信息协议（RIP）**：该协议确定用于传输数据包的路由

+   **域名系统（DNS）**：该协议查找互联网域名并返回其 IP 地址

+   **网络时间协议（NTP）**：该协议在互联网上同步时钟

UDP 数据包由 IP 地址和端口号组成，用于标识其目的地。UDP 数据包具有固定大小，最大可达 65,353 字节。然而，每个数据包使用最少 20 字节的 IP 头和 8 字节的 UDP 头，限制了消息的大小为 65,507 字节。如果消息大于这个大小，那么就需要发送多个数据包。

UDP 数据包也可以进行多播。这意味着数据包被发送到属于 UDP 组的每个节点。这是一种有效的方式，可以将信息发送到多个节点，而无需明确地针对每个节点。相反，数据包被发送到一个负责捕获其组数据包的组。

在本章中，我们将说明 UDP 协议如何被用于：

+   支持传统的客户端/服务器模型

+   使用 NIO 通道执行 UDP 操作

+   多播数据包到组成员

+   向客户端流媒体，如音频或视频

我们将从 Java 对 UDP 的支持概述开始，并提供更多 UDP 协议的细节。

# Java 对 UDP 的支持

Java 使用`DatagramSocket`类在节点之间形成套接字连接。`DatagramPacket`类表示数据包。简单的发送和接收方法将在网络中传输数据包。

UDP 使用 IP 地址和端口号来标识节点。UDP 端口号范围从`0`到`65535`。端口号分为三种类型：

+   知名端口（`0`到`1023`）：这些是用于相对常见服务的端口号。

+   注册端口（`1024`到`49151`）：这些是由 IANA 分配给进程的端口号。

+   动态/私有端口（`49152`到`65535`）：这些在连接初始化时动态分配给客户端。这些通常是临时的，不能由 IANA 分配。

以下表格是 UDP 特定端口分配的简要列表。它们说明了 UDP 被广泛用于支持许多不同的应用和服务。TCP/UDP 端口号的更完整列表可在[`en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers`](https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers)找到：

| 知名端口（0 到 1023） | 用途 |
| --- | --- |
| `7` | 这是回显协议 |
| `9` | 这意味着远程唤醒 |
| `161` | 这是**简单** **网络管理协议**（**SNMP**） |
| `319` | 这些是**精密时间协议**（**PTP**）事件消息 |
| `320` | 这些是 PTP 通用消息 |
| `513` | 这表示用户是谁 |
| `514` | 这是 syslog—用于系统日志 |
| `520` | 这是**路由信息协议**（**RIP**） |
| `750` | 这是`kerberos-iv`，Kerberos 第四版 |
| `944` | 这是网络文件系统服务 |
| `973` | 这是 IPv6 上的网络文件系统服务 |

以下表格列出了注册端口及其用途：

| 注册端口（1024 到 49151） | 用途 |
| --- | --- |
| `1534` | 用于 Eclipse**目标通信框架**（**TCF**） |
| `1581` | 用于 MIL STD 2045-47001 VMF |
| `1589` | 用于思科**虚拟局域网查询协议**（**VQP**）/ VMPS |
| `2190` | 用于 TiVoConnect Beacon |
| `2302` | 用于 Halo：战斗进化多人游戏 |
| `3000` | 用于 BitTorrent 同步 |
| `4500` | 用于 IPSec NAT 穿透 |
| `5353` | 用于**多播 DNS**（**mDNS**） |
| `9110` | 用于 SSMP 消息协议 |
| `27500`到`27900` | 用于 id Software 的 QuakeWorld |
| `29900`到`29901` | 用于任天堂 Wi-Fi 连接 |
| `36963` | 用于虚幻软件多人游戏 |

# TCP 与 UDP

TCP 和 UDP 之间存在几个区别。这些区别包括以下内容：

+   可靠性：TCP 比 UDP 更可靠

+   **顺序**：TCP 保证数据包传输的顺序将被保留

+   **头部大小**：UDP 头部比 TCP 头部小

+   **速度**：UDP 比 TCP 更快

当使用 TCP 发送数据包时，数据包保证会到达。如果丢失，则会重新发送。UDP 不提供此保证。如果数据包未到达，则不会重新发送。

TCP 保留了发送数据包的顺序，而 UDP 则没有。如果 TCP 数据包到达目的地的顺序与发送时不同，TCP 将重新组装数据包以恢复其原始顺序。而 UDP 则不保留此顺序。

创建数据包时，会附加头信息以帮助传递数据包。使用 UDP 时，头部由 8 个字节组成。TCP 头部的通常大小为 32 个字节。

由于较小的头部大小和缺少确保可靠性的开销，UDP 比 TCP 更有效率。此外，创建连接需要的工作量更少。这种效率使其成为流媒体的更好选择。

让我们从支持传统客户端/服务器架构的 UDP 示例开始。

# UDP 客户端/服务器

UDP 客户端/服务器应用程序的结构与 TCP 客户端/服务器应用程序所使用的结构类似。在服务器端，创建了一个 UDP 服务器套接字，等待客户端请求。客户端将创建相应的 UDP 套接字，并使用它向服务器发送消息。服务器随后可以处理请求并发送回响应。

UDP 客户端/服务器将使用`DatagramSocket`类作为套接字，使用`DatagramPacket`来保存消息。消息的内容类型没有限制。在我们的示例中，我们将使用文本消息。

## UDP 服务器应用程序

接下来定义我们的服务器。构造函数将执行服务器的工作：

```java
public class UDPServer {
    public UDPServer() {
        System.out.println("UDP Server Started");
        ...
        System.out.println("UDP Server Terminating");
    }

    public static void main(String[] args) {
        new UDPServer();
    }
}
```

在构造函数的 try-with-resources 块中，我们创建了`DatagramSocket`类的实例。我们将使用的一些方法可能会抛出`IOException`异常，必要时将被捕获：

```java
        try (DatagramSocket serverSocket = 
                new DatagramSocket(9003)) {
            ...
            }
        } catch (IOException ex) {
            //Handle exceptions
        }
```

创建套接字的另一种方法是使用`bind`方法，如下所示。使用`null`作为参数创建`DatagramSocket`实例。然后使用`bind`方法分配端口：

```java
        DatagramSocket serverSocket = new DatagramSocket(null); 
        serverSocket.bind(new InetSocketAddress(9003)); 
```

两种方法都将使用端口`9003`创建`DatagramSocket`实例。

发送消息的过程包括以下步骤：

+   创建字节数组

+   创建`DatagramPacket`实例

+   使用`DatagramSocket`实例等待消息到达

该过程被包含在一个循环中，如下所示，以允许处理多个请求。接收到的消息将简单地回显到客户端程序。使用字节数组及其长度创建`DatagramPacket`实例。它作为`DatagramSocket`类的`receive`方法的参数。此时数据包不包含任何信息。此方法将阻塞，直到有请求发出，然后数据包将被填充：

```java
        while (true) {
            byte[] receiveMessage = new byte[1024];
            DatagramPacket receivePacket = new DatagramPacket(
                receiveMessage, receiveMessage.length);
            serverSocket.receive(receivePacket);
            ...
        }
```

当方法返回时，数据包将被转换为字符串。如果发送了其他数据类型，则需要其他转换。然后显示发送的消息：

```java
        String message = new String(receivePacket.getData());
        System.out.println("Received from client: [" + message
               + "]\nFrom: " + receivePacket.getAddress());
```

要发送响应，需要客户端的地址和端口号。这些分别使用`getAddress`和`getPort`方法从拥有这些信息的数据包中获取。我们将在讨论客户端时看到这一点。还需要的是表示为字节数组的消息，`getBytes`方法提供了这个消息：

```java
        InetAddress inetAddress = receivePacket.getAddress();
        int port = receivePacket.getPort();
        byte[] sendMessage;
        sendMessage = message.getBytes();
```

使用消息、其长度和客户端的地址和端口号创建一个新的`DatagramPacket`实例。`send`方法将数据包发送到客户端：

```java
        DatagramPacket sendPacket = 
            new DatagramPacket(sendMessage,
                sendMessage.length, inetAddress, port);
        serverSocket.send(sendPacket);
```

定义了服务器，现在让我们来看看客户端。

## UDP 客户端应用程序

客户端应用程序将提示用户输入要发送的消息，然后将消息发送到服务器。它将等待响应，然后显示响应。在这里声明：

```java
class UDPClient {
    public UDPClient() {
        System.out.println("UDP Client Started");
        ...
        }
        System.out.println("UDP Client Terminating ");
    }

    public static void main(String args[]) {
        new UDPClient();
    }
}
```

`Scanner`类支持获取用户输入。try-with-resources 块创建了一个`DatagramSocket`实例并处理异常：

```java
        Scanner scanner = new Scanner(System.in);
        try (DatagramSocket clientSocket = new DatagramSocket()) {
            ...
            }
            clientSocket.close();
        } catch (IOException ex) {
            // Handle exceptions
        }
```

使用`getByName`方法访问客户端的当前地址，并声明一个字节数组的引用。此地址将用于创建数据包：

```java
        InetAddress inetAddress = 
            InetAddress.getByName("localhost");
        byte[] sendMessage;
```

使用无限循环提示用户输入消息。当用户输入“quit”时，应用程序将终止，如下所示：

```java
        while (true) {
            System.out.print("Enter a message: ");
            String message = scanner.nextLine();
            if ("quit".equalsIgnoreCase(message)) {
                 break;
            }
        ...
        }
```

要创建一个包含消息的`DatagramPacket`实例，其构造函数需要一个表示消息的字节数组，其长度以及客户端的地址和端口号。在下面的代码中，服务器的端口是`9003`。`send`方法将数据包发送到服务器：

```java
            sendMessage = message.getBytes();
            DatagramPacket sendPacket = new DatagramPacket(
                sendMessage, sendMessage.length, 
                inetAddress, 9003);
            clientSocket.send(sendPacket);
```

为了接收响应，创建一个接收数据包，并与在服务器中处理方式相同地使用`receive`方法。此方法将阻塞，直到服务器响应，然后显示消息：

```java
            byte[] receiveMessage = new byte[1024];
            DatagramPacket receivePacket = new DatagramPacket(
                    receiveMessage, receiveMessage.length);
            clientSocket.receive(receivePacket);
            String receivedSentence = 
                new String(receivePacket.getData());
            System.out.println("Received from server [" 
                + receivedSentence + "]\nfrom "
                + receivePacket.getSocketAddress());
```

现在，让我们看看这些应用程序是如何工作的。

## UDP 客户端/服务器在运行

首先启动服务器。它将显示以下消息：

**UDP 服务器已启动**

接下来，启动客户端应用程序。它将显示以下消息：

**UDP 客户端已启动**

**输入消息：**

输入一条消息，例如以下消息：

**输入消息：早上好**

服务器将显示已收到消息，如下所示。您将看到几行空白的输出。这是用于保存消息的 1024 字节数组的内容。然后将消息回显到客户端：

从客户端收到：[早上好**

**...**

**]**

**来自：/127.0.0.1**

在客户端端，显示了响应。在这个例子中，用户然后输入“quit”来终止应用程序：

从服务器收到：[早上好**

**...**

**]**

**来自/127.0.0.1:9003**

**输入消息：quit**

**UDP 客户端终止**

由于我们正在发送和接收测试消息，当显示消息时，可以使用`trim`方法简化消息的显示，如下所示。此代码可以在服务器和客户端两侧使用：

```java
        System.out.println("Received from client: [" 
                + message.trim()
                + "]\nFrom: " + receivePacket.getAddress());
```

输出将更容易阅读，如下所示：

**从客户端收到：[早上好]**

**来自：/127.0.0.1**

这个客户端/服务器应用程序可以通过多种方式进行增强，包括使用线程，以使其能够更好地与多个客户端一起工作。此示例说明了在 Java 中开发 UDP 客户端/服务器应用程序的基础知识。在下一节中，我们将看到通道如何支持 UDP。

# UDP 的通道支持

`DatagramChannel`类提供了对 UDP 的额外支持。它可以支持非阻塞交换。`DatagramChannel`类是从`SelectableChannel`类派生的，使多线程应用程序更容易。我们将在第七章中研究它的用法，*网络可扩展性*。

`DatagramSocket`类将通道绑定到端口。使用此类后，将不再直接使用。使用`DatagramChannel`类意味着我们不必直接使用数据报包。相反，数据是使用`ByteBuffer`类的实例进行传输。该类提供了几种方便的方法来访问其数据。

为了演示`DatagramChannel`类的用法，我们将开发一个回显服务器和客户端应用程序。服务器将等待来自客户端的消息，然后将其发送回客户端。

## UDP 回显服务器应用程序

UDP 回显服务器应用程序声明如下，并使用端口`9000`。在`main`方法中，使用 try-with-resources 块打开通道并创建套接字。`DatagramChannel`类没有公共构造函数。要创建通道，我们使用`open`方法，它返回`DatagramChannel`类的实例。通道的`socket`方法为通道创建一个`DatagramSocket`实例：

```java
public class UDPEchoServer {

    public static void main(String[] args) {
        int port = 9000;
        System.out.println("UDP Echo Server Started");
        try (DatagramChannel channel = DatagramChannel.open();
            DatagramSocket socket = channel.socket();){
                ...
            }
        }
        catch (IOException ex) {
            // Handle exceptions
        }
        System.out.println("UDP Echo Server Terminated");
    }
}
```

创建后，我们需要将其与端口关联。首先通过创建`SocketAddress`类的实例来完成，该类表示套接字地址。`InetSocketAddress`类是从`SocketAddress`类派生的，并实现了 IP 地址。在以下代码序列中的使用将其与端口`9000`关联。`DatagramSocket`类的`bind`方法将此地址绑定到套接字：

```java
            SocketAddress address = new InetSocketAddress(port);
            socket.bind(address);
```

`ByteBuffer`类是使用数据报通道的核心。我们在第三章中讨论了它的创建，*NIO 支持网络*。在下一个语句中，使用`allocateDirect`方法创建了该类的一个实例。此方法将尝试直接在缓冲区上使用本机操作系统支持。这可能比使用数据报包方法更有效。在这里，我们创建了一个具有可能的最大大小的缓冲区：

```java
            ByteBuffer buffer = ByteBuffer.allocateDirect(65507);
```

添加以下无限循环，它将接收来自客户端的消息，显示消息，然后将其发送回去：

```java
            while (true) {
                // Get message
                // Display message
                // Return message
            }
```

`receive`方法应用于通道以获取客户端的消息。它将阻塞直到消息被接收。它的单个参数是用于保存传入数据的字节缓冲区。如果消息超过缓冲区的大小，额外的字节将被静默丢弃。

`flip`方法使缓冲区可以被处理。它将缓冲区的限制设置为缓冲区中的当前位置，然后将位置设置为`0`。随后的获取类型方法将从缓冲区的开头开始：

```java
        SocketAddress client = channel.receive(buffer);
        buffer.flip();
```

虽然对于回显服务器来说并非必需，但接收到的消息会显示在服务器上。这样可以验证消息是否已接收，并建议如何修改消息以实现更多功能，而不仅仅是回显消息。

为了显示消息，我们需要使用`get`方法逐个获取每个字节，然后将其转换为适当的类型。回显服务器旨在回显简单的字符串。因此，在显示之前，需要将字节转换为字符。

然而，`get`方法修改了缓冲区中的当前位置。在将消息发送回客户端之前，我们需要将位置恢复到其原始状态。缓冲区的`mark`和`reset`方法用于此目的。

所有这些都在以下代码序列中执行。`mark`方法在当前位置设置标记。使用`StringBuilder`实例重新创建客户端发送的字符串。缓冲区的`hasRemaining`方法控制 while 循环。消息被显示，`reset`方法将位置恢复到先前标记的值：

```java
        buffer.mark();
        System.out.print("Received: [");
        StringBuilder message = new StringBuilder();
        while (buffer.hasRemaining()) {
            message.append((char) buffer.get());
        }
        System.out.println(message + "]");
        buffer.reset();
```

最后一步是将字节缓冲区发送回客户端。`send`方法执行此操作。显示消息指示消息已发送，然后是`clear`方法。因为我们已经完成了缓冲区的使用，所以使用此方法。它将位置设置为 0，将缓冲区的限制设置为其容量，并丢弃标记：

```java
        channel.send(buffer, client);
        System.out.println("Sent: [" + message + "]");
        buffer.clear();
```

当服务器启动时，我们将看到此效果的消息，如下所示：

**UDP 回声服务器已启动**

我们现在准备看看客户端是如何实现的。

## UDP 回显客户端应用程序

UDP 回显客户端的实现简单，并使用以下步骤：

+   与回声服务器建立连接

+   创建一个字节缓冲区来保存消息

+   缓冲区被发送到服务器

+   客户端阻塞，直到消息被发送回来

客户端的实现细节与服务器的类似。我们从应用程序的声明开始，如下所示：

```java
public class UDPEchoClient {

    public static void main(String[] args) {
        System.out.println("UDP Echo Client Started");
        try {
            ...
        }
        catch (IOException ex) {
            // Handle exceptions
        }
        System.out.println("UDP Echo Client Terminated");
    }
}
```

在服务器端，单参数`InetSocketAddress`构造函数将端口`9000`与当前 IP 地址关联。在客户端中，我们需要指定服务器的 IP 地址和端口。否则，它将无法确定要发送消息的位置。这是在以下语句中使用类的两个参数构造函数来实现的。我们使用地址`127.0.0.1`，假设客户端和服务器在同一台机器上：

```java
        SocketAddress remote = 
            new InetSocketAddress("127.0.0.1", 9000);
```

然后使用`open`方法创建通道，并使用`connect`方法连接到套接字地址：

```java
        DatagramChannel channel = DatagramChannel.open();
        channel.connect(remote);
```

在下一个代码序列中，创建消息字符串，并分配字节缓冲区。将缓冲区的大小设置为字符串的长度。然后，`put`方法将消息分配给缓冲区。由于`put`方法需要一个字节数组，我们使用`String`类的`getBytes`方法获取与消息内容对应的字节数组：

```java
        String message = "The message";
        ByteBuffer buffer = ByteBuffer.allocate(message.length());
        buffer.put(message.getBytes());
```

在将缓冲区发送到服务器之前，调用`flip`方法。它将设置限制为当前位置，并将位置设置为 0。因此，当服务器接收时，可以进行处理：

```java
        buffer.flip();
```

要将消息发送到服务器，调用通道的`write`方法，如下所示。这将直接将底层数据包发送到服务器。但是，此方法仅在通道的套接字已连接时才有效，这是之前实现的：

```java
        channel.write(buffer);
        System.out.println("Sent: [" + message + "]");
```

接下来，清除缓冲区，允许我们重用缓冲区。`read`方法将接收缓冲区，并且缓冲区将使用与服务器中使用的相同的过程显示：

```java
        buffer.clear();
        channel.read(buffer);
        buffer.flip();
        System.out.print("Received: [");
        while(buffer.hasRemaining()) {
            System.out.print((char)buffer.get());
        }
        System.out.println("]");
```

我们现在准备与服务器一起使用客户端。

## UDP 回显客户端/服务器正在运行

首先需要启动服务器。我们将看到初始服务器消息，如下所示：

**UDP 回声服务器已启动**

接下来，启动客户端。将显示以下输出，显示客户端发送消息，然后显示返回的消息：

**UDP 回显客户端已启动**

**发送：[消息]**

**接收：[消息]**

**UDP 回显客户端终止**

在服务器端，我们将看到消息被接收，然后被发送回客户端：

**接收：[消息]**

**发送：[消息]**

使用`DatagramChannel`类可以使 UDP 通信更快。

# UDP 多播

多播是将消息同时发送给多个客户端的过程。每个客户端将接收相同的消息。为了参与此过程，客户端需要加入多播组。当发送消息时，其目标地址指示它是多播消息。多播组是动态的，客户端可以随时加入和离开组。

多播是旧的 IPv4 CLASS D 空间，使用地址`224.0.0.0`到`239.255.255.255`。IPv4 多播地址空间注册表列出了多播地址分配，并可在[`www.iana.org/assignments/multicast-addresses/multicast-addresses.xml`](http://www.iana.org/assignments/multicast-addresses/multicast-addresses.xml)找到。*IP 多播主机扩展*文档可在[`tools.ietf.org/html/rfc1112`](http://tools.ietf.org/html/rfc1112)找到。它定义了支持多播的实现要求。

## UDP 多播服务器

接下来声明服务器应用程序。这个服务器是一个时间服务器，每秒广播当前日期和时间。这是多播消息的一个很好的用途，因为可能有几个客户端对相同的信息感兴趣，可靠性不是一个问题。try 块将处理异常：

```java
public class UDPMulticastServer {

    public UDPMulticastServer() {
        System.out.println("UDP Multicast Time Server Started");
        try {
            ...
        } catch (IOException | InterruptedException ex) {
            // Handle exceptions
        }
        System.out.println(
            "UDP Multicast Time Server Terminated");
    }

    public static void main(String args[]) {
        new UDPMulticastServer();
    }
}
```

需要`MulticastSocket`类的一个实例，以及保存多播 IP 地址的`InetAddress`实例。在本例中，地址`228.5.6.7`代表多播组。使用`joinGroup`方法加入此多播组，如下所示：

```java
    MulticastSocket multicastSocket = new MulticastSocket();
    InetAddress inetAddress = InetAddress.getByName("228.5.6.7");
    multicastSocket.joinGroup(inetAddress);
```

为了发送消息，我们需要一个字节数组来保存消息和一个数据包。如下所示声明：

```java
    byte[] data;
    DatagramPacket packet;
```

服务器应用程序将使用无限循环每秒广播一个新的日期和时间。线程暂停一秒，然后使用`Data`类创建一个新的日期和时间。使用此信息创建`DatagramPacket`实例。为此服务器分配端口`9877`，客户端需要知道该端口。`send`方法将数据包发送给感兴趣的客户端：

```java
    while (true) {
        Thread.sleep(1000);
        String message = (new Date()).toString();
        System.out.println("Sending: [" + message + "]");
        data = message.getBytes();
        packet = new DatagramPacket(data, message.length(), 
                inetAddress, 9877);
        multicastSocket.send(packet);
    }
```

接下来讨论客户端应用程序。

## UDP 多播客户端

此应用程序将加入由地址`228.5.6.7`定义的多播组。它将阻塞直到接收到消息，然后显示消息。应用程序定义如下：

```java
public class UDPMulticastClient {

    public UDPMulticastClient() {
        System.out.println("UDP Multicast Time Client Started");
        try {
            ...
        } catch (IOException ex) {
            ex.printStackTrace();
        }

        System.out.println(
            "UDP Multicast Time Client Terminated");
    }

    public static void main(String[] args) {
        new UDPMulticastClient();
    }
}
```

使用端口号`9877`创建`MulticastSocket`类的实例。这是必需的，以便它可以连接到 UDP 多播服务器。使用多播地址`228.5.6.7`创建`InetAddress`实例。然后客户端使用`joinGroup`方法加入多播组。

```java
    MulticastSocket multicastSocket = new MulticastSocket(9877);
    InetAddress inetAddress = InetAddress.getByName("228.5.6.7");
    multicastSocket.joinGroup(inetAddress);
```

需要一个`DatagramPacket`实例来接收发送到客户端的消息。创建一个字节数组并用于实例化此数据包，如下所示：

```java
    byte[] data = new byte[256];
    DatagramPacket packet = new DatagramPacket(data, data.length);
```

然后客户端应用程序进入无限循环，在`receive`方法处阻塞，直到服务器发送消息。一旦消息到达，消息将被显示：

```java
    while (true) {
        multicastSocket.receive(packet);
        String message = new String(
            packet.getData(), 0, packet.getLength());
        System.out.println("Message from: " + packet.getAddress() 
            + " Message: [" + message + "]");
    }
```

接下来，我们将演示客户端和服务器是如何交互的。

## UDP 多播客户端/服务器正在运行

启动服务器。服务器的输出将类似于以下内容，但日期和时间将不同：

**UDP 多播时间服务器已启动**

发送：[2015 年 9 月 19 日周六 13:48:42 CDT]

发送：[2015 年 9 月 19 日周六 13:48:43 CDT]

发送：[2015 年 9 月 19 日周六 13:48:44 CDT]

发送：[2015 年 9 月 19 日周六 13:48:45 CDT]

发送：[2015 年 9 月 19 日周六 13:48:46 CDT]

发送：[2015 年 9 月 19 日周六 13:48:47 CDT]

**...**

接下来启动客户端应用程序。它将开始接收类似以下内容的消息：

**UDP 多播时间客户端已启动**

来自：/192.168.1.7 消息：[2015 年 9 月 19 日周六 13:48:44 CDT]

来自：/192.168.1.7 消息：[2015 年 9 月 19 日周六 13:48:45 CDT]

来自：/192.168.1.7 消息：[2015 年 9 月 19 日周六 13:48:46 CDT]

**...**

### 注意

如果程序在 Mac 上执行，可能会出现套接字异常。如果发生这种情况，请使用`-Djava.net.preferIPv4Stack=true VM`选项。

如果启动后续客户端，每个客户端将接收相同系列的服务器消息。

# 使用通道的 UDP 多播

我们还可以使用通道进行多播。我们将使用 IPv6 来演示这个过程。这个过程类似于我们之前使用`DatagramChannel`类的过程，只是我们需要使用多播组。为此，我们需要知道哪些网络接口是可用的。在我们进入使用通道进行多播的具体细节之前，我们将演示如何获取机器的网络接口列表。

`NetworkInterface`类表示网络接口。这个类在第二章中讨论过，*网络寻址*。以下是该章节中演示的方法的变体。它已经增强，以显示特定接口是否支持多播，如下所示：

```java
        try {
            Enumeration<NetworkInterface> networkInterfaces;
            networkInterfaces = 
                NetworkInterface.getNetworkInterfaces();
            for (NetworkInterface networkInterface : 
                    Collections.list(networkInterfaces)) {
                displayNetworkInterfaceInformation(
                    networkInterface);
            }
        } catch (SocketException ex) {
            // Handle exceptions
        }
```

接下来显示`displayNetworkInterfaceInformation`方法。这种方法是从[`docs.oracle.com/javase/tutorial/networking/nifs/listing.html`](https://docs.oracle.com/javase/tutorial/networking/nifs/listing.html)中改编的：

```java
    static void displayNetworkInterfaceInformation(
            NetworkInterface networkInterface) {
        try {
            System.out.printf("Display name: %s\n", 
                networkInterface.getDisplayName());
            System.out.printf("Name: %s\n", 
                networkInterface.getName());
            System.out.printf("Supports Multicast: %s\n", 
                networkInterface.supportsMulticast());
            Enumeration<InetAddress> inetAddresses = 
                networkInterface.getInetAddresses();
            for (InetAddress inetAddress : 
                    Collections.list(inetAddresses)) {
                System.out.printf("InetAddress: %s\n", 
                    inetAddress);
            }
            System.out.println();
        } catch (SocketException ex) {
            // Handle exceptions
        }
    }
```

当执行此示例时，您将获得类似以下的输出：

**显示名称：软件环回接口 1**

**名称：lo**

**支持多播：true**

**InetAddress：/127.0.0.1**

**InetAddress：/0:0:0:0:0:0:0:1**

**显示名称：Microsoft Kernel 调试网络适配器**

名称：eth0

**支持多播：true**

**显示名称：Realtek PCIe FE Family Controller**

**名称：eth1**

**支持多播：true**

**InetAddress：/fe80:0:0:0:91d0:8e19:31f1:cb2d%eth1**

**显示名称：Realtek RTL8188EE 802.11 b/g/n Wi-Fi 适配器**

**名称：wlan0**

**支持多播：true**

**InetAddress：/192.168.1.7**

**InetAddress：/2002:42be:6659:0:0:0:0:1001**

**InetAddress：/fe80:0:0:0:9cdb:371f:d3e9:4e2e%wlan0**

**...**

对于我们的客户端/服务器，我们将使用`eth0`接口。您需要选择最适合您平台的接口。例如，在 Mac 上，这可能是`en0`或`awdl0`。

## UDP 通道多播服务器

UDP 通道多播服务器将：

+   设置通道和多播组

+   创建包含消息的缓冲区

+   使用无限循环来发送和显示组消息

服务器的定义如下：

```java
public class UDPDatagramMulticastServer {

    public static void main(String[] args) {
        try {
            ...
            }
        } catch (IOException | InterruptedException ex) {
            // Handle exceptions
        }
    }

}
```

第一个任务使用`System`类的`setProperty`方法指定要使用 IPv6。然后创建一个`DatagramChannel`实例，并创建`eth0`网络接口。`setOption`方法将通道与用于标识组的网络接口相关联。该组由一个`InetSocketAddress`实例表示，使用 IPv6 节点本地范围的多播地址，如下所示。有关*IPv6 多播地址空间注册表*文档的更多详细信息，请访问[`www.iana.org/assignments/ipv6-multicast-addresses/ipv6-multicast-addresses.xhtml`](http://www.iana.org/assignments/ipv6-multicast-addresses/ipv6-multicast-addresses.xhtml)：

```java
            System.setProperty(
                "java.net.preferIPv6Stack", "true");
            DatagramChannel channel = DatagramChannel.open();
            NetworkInterface networkInterface = 
                NetworkInterface.getByName("eth0");
            channel.setOption(StandardSocketOptions.
                IP_MULTICAST_IF, 
                networkInterface);
            InetSocketAddress group = 
                new InetSocketAddress("FF01:0:0:0:0:0:0:FC", 
                        9003);
```

然后创建一个基于消息字符串的字节缓冲区。缓冲区的大小设置为字符串的长度，并使用`put`和`getBytes`方法的组合进行分配：

```java
            String message = "The message";
            ByteBuffer buffer = 
                ByteBuffer.allocate(message.length());
            buffer.put(message.getBytes());
```

在 while 循环内，缓冲区被发送到组成员。为了清楚地看到发送了什么，使用了与*UDP 回显服务器应用程序*部分中使用的相同代码来显示缓冲区的内容。缓冲区被重置，以便可以再次使用。应用程序暂停一秒钟，以避免对这个例子产生过多的消息：

```java
            while (true) {
                channel.send(buffer, group);
                System.out.println("Sent the multicast message: " 
                    + message);
                buffer.clear();

                buffer.mark();
                System.out.print("Sent: [");
                StringBuilder msg = new StringBuilder();
                while (buffer.hasRemaining()) {
                    msg.append((char) buffer.get());
                }
                System.out.println(msg + "]");
                buffer.reset();

                Thread.sleep(1000);
        }
```

我们现在准备好客户端应用程序。

## UDP 通道多播客户端

UDP 通道多播客户端将加入组，接收消息，显示消息，然后终止。正如我们将看到的，`MembershipKey`类表示对多播组的成员资格。

应用程序声明如下。首先，我们指定要使用 IPv6。然后声明网络接口，这是服务器使用的相同接口：

```java
public class UDPDatagramMulticastClient {
    public static void main(String[] args) throws Exception {
        System.setProperty("java.net.preferIPv6Stack", "true");
        NetworkInterface networkInterface = 
            NetworkInterface.getByName("eth0");
        ...
    }
}
```

接下来创建`DatagramChannel`实例。该通道绑定到端口`9003`，并与网络接口实例相关联：

```java
        DatagramChannel channel = DatagramChannel.open()
                .bind(new InetSocketAddress(9003))
                .setOption(StandardSocketOptions.IP_MULTICAST_IF, 
                    networkInterface);
```

然后基于服务器使用的相同 IPv6 地址创建组，并使用通道的`join`方法创建一个`MembershipKey`实例，如下所示。为了说明客户端的工作原理，显示密钥和等待消息：

```java
        InetAddress group = 
            InetAddress.getByName("FF01:0:0:0:0:0:0:FC");
        MembershipKey key = channel.join(group, networkInterface);
        System.out.println("Joined Multicast Group: " + key);
        System.out.println("Waiting for a  message...");
```

创建一个大小为`1024`的字节缓冲区。这个大小对于这个例子来说足够了，然后调用`receive`方法，该方法将阻塞直到接收到消息：

```java
        ByteBuffer buffer = ByteBuffer.allocate(1024);
        channel.receive(buffer);
```

为了显示缓冲区的内容，我们需要将其翻转。内容将如之前所做的那样显示：

```java
        buffer.flip();
        System.out.print("Received: [");
        StringBuilder message = new StringBuilder();
        while (buffer.hasRemaining()) {
            message.append((char) buffer.get());
        }
        System.out.println(message + "]");
```

当我们完成一个成员资格密钥时，应该使用`drop`方法指示我们不再对接收组消息感兴趣：

```java
        key.drop();
```

如果有待处理的数据包，消息仍然可能到达。

## UDP 通道组播客户端/服务器正在运行

首先启动服务器。该服务器将每秒显示一系列消息，如下所示：

**发送组播消息：消息**

**发送：[消息]**

**发送组播消息：消息**

**发送：[消息]**

**发送组播消息：消息**

**发送：[消息]**

**...**

接下来，启动客户端应用程序。它将显示组播组，等待消息，然后显示消息，如下所示：

**加入组播组：<ff01:0:0:0:0:0:0:fc,eth1>**

**等待消息...**

**接收：[消息]**

使用通道可以提高 UDP 组播消息的性能。

# UDP 流

使用 UDP 来流式传输音频或视频是常见的。它是高效的，任何数据包的丢失或乱序都会导致最小的问题。我们将通过实时音频流来说明这种技术。UDP 服务器将捕获麦克风的声音并将其发送给客户端。UDP 客户端将接收音频并在系统扬声器上播放。

UDP 流服务器的概念是将流分解为一系列数据包，然后发送给 UDP 客户端。客户端将接收这些数据包并使用它们来重建流。

为了说明流式音频，我们需要了解一些关于 Java 处理音频流的知识。音频由`javax.sound.sampled`包中的一系列类处理。用于捕获和播放音频的主要类包括以下内容：

+   `AudioFormat`：这个类指定所使用的音频格式的特性。由于有几种音频格式可用，系统需要知道使用的是哪一种。

+   `AudioInputStream`：这个类代表正在录制或播放的音频。

+   `AudioSystem`：这个类提供对系统音频设备和资源的访问。

+   `DataLine`：这个接口控制应用于流的操作，比如启动和停止流。

+   `SourceDataLine`：这代表声音的目的地，比如扬声器。

+   `TargetDataLine`：这代表声音的来源，比如麦克风。

`SourceDataLine`和`TargetDataLine`接口的术语可能有点令人困惑。这些术语是从线路和混音器的角度来看的。

## UDP 音频服务器实现

`AudioUDPServer`类的声明如下。它使用`TargetDataLine`实例作为音频的来源。它被声明为实例变量，因为它在多个方法中被使用。构造函数使用`setupAudio`方法来初始化音频，并使用`broadcastAudio`方法将音频发送给客户端：

```java
public class AudioUDPServer {
    private final byte audioBuffer[] = new byte[10000];
    private TargetDataLine targetDataLine;

    public AudioUDPServer() {
        setupAudio();
        broadcastAudio();
    }
    ...
    public static void main(String[] args) {
        new AudioUDPServer();
    }
}
```

以下是`getAudioFormat`方法，它在服务器和客户端中都被用来指定音频流的特性。模拟音频信号每秒采样 1,600 次。每个样本是一个带符号的 16 位数字。`channels`变量被赋值为`1`，意味着音频是单声道。样本中字节的顺序很重要，设置为大端序：

```java
    private AudioFormat getAudioFormat() {
        float sampleRate = 16000F;
        int sampleSizeInBits = 16;
        int channels = 1;
        boolean signed = true;
        boolean bigEndian = false;
        return new AudioFormat(sampleRate, sampleSizeInBits, 
            channels, signed, bigEndian);
    }
```

大端和小端是指字节的顺序。大端意味着一个字的最高有效字节存储在最小的内存地址，最低有效字节存储在最大的内存地址。小端颠倒了这个顺序。不同的计算机架构使用不同的顺序。

`setupAudio`方法初始化音频。`DataLine.Info`类使用音频格式信息创建代表音频的线路。`AudioSystem`类的`getLine`方法返回与麦克风对应的数据线。该线路被打开并启动：

```java
    private void setupAudio() {
        try {
            AudioFormat audioFormat = getAudioFormat();
            DataLine.Info dataLineInfo = 
                new DataLine.Info(TargetDataLine.class, 
                        audioFormat);
            targetDataLine =  (TargetDataLine) 
                AudioSystem.getLine(dataLineInfo);
            targetDataLine.open(audioFormat);
            targetDataLine.start();
        } catch (Exception ex) {
            ex.printStackTrace();
            System.exit(0);
        }
    }
```

`broadcastAudio`方法创建了 UDP 数据包。使用端口`8000`创建了一个套接字，并为当前机器创建了一个`InetAddress`实例：

```java
    private void broadcastAudio() {
        try {
            DatagramSocket socket = new DatagramSocket(8000);
            InetAddress inetAddress = 
                InetAddress.getByName("127.0.0.1");
            ...
        } catch (Exception ex) {
            // Handle exceptions
        }
    }
```

进入一个无限循环，`read`方法填充`audioBuffer`数组并返回读取的字节数。对于大于`0`的计数，使用缓冲区创建一个新的数据包，并发送到监听端口`9786`的客户端：

```java
    while (true) {
        int count = targetDataLine.read(
            audioBuffer, 0, audioBuffer.length);
        if (count > 0) {
            DatagramPacket packet = new DatagramPacket(
            audioBuffer, audioBuffer.length, inetAddress, 9786);
            socket.send(packet);
        }
    }
```

执行时，来自麦克风的声音被作为一系列数据包发送到客户端。

## UDP 音频客户端实现

接下来声明了`AudioUDPClient`应用程序。在构造函数中，调用了一个`initiateAudio`方法来开始从服务器接收数据包的过程：

```java
public class AudioUDPClient {
    AudioInputStream audioInputStream;
    SourceDataLine sourceDataLine;
    ...
    public AudioUDPClient() {
        initiateAudio();
    }

    public static void main(String[] args) {
        new AudioUDPClient();
    }
}
```

`initiateAudio`方法创建一个绑定到端口`9786`的套接字。创建一个字节数组来保存 UDP 数据包中包含的音频数据：

```java
    private void initiateAudio() {
        try {
            DatagramSocket socket = new DatagramSocket(9786);
            byte[] audioBuffer = new byte[10000];
            ...
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
```

一个无限循环将从服务器接收数据包，创建一个`AudioInputStream`实例，然后调用`playAudio`方法来播放声音。以下代码创建数据包，然后阻塞直到接收到数据包：

```java
    while (true) {
        DatagramPacket packet
            = new DatagramPacket(audioBuffer, audioBuffer.length);
        socket.receive(packet);
        ...
    }
```

接下来，创建音频流。从数据包中提取一个字节数组。它被用作`ByteArrayInputStream`构造函数的参数，该构造函数与音频格式信息一起用于创建实际的音频流。这与`SourceDataLine`实例相关联，该实例被打开并启动。调用`playAudio`方法来播放声音：

```java
        try {
            byte audioData[] = packet.getData();
            InputStream byteInputStream = 
                new ByteArrayInputStream(audioData);
            AudioFormat audioFormat = getAudioFormat();
            audioInputStream =  new AudioInputStream(
                byteInputStream, 
                audioFormat, audioData.length / 
                audioFormat.getFrameSize());
            DataLine.Info dataLineInfo = new DataLine.Info(
                SourceDataLine.class, audioFormat);
            sourceDataLine = (SourceDataLine) 
                AudioSystem.getLine(dataLineInfo);
            sourceDataLine.open(audioFormat);
            sourceDataLine.start();
            playAudio();
        } catch (Exception e) {
            // Handle exceptions
        }
```

使用`getAudioFormat`方法，该方法与`AudioUDPServer`应用程序中声明的方法相同。接下来是`playAudio`方法。`AudioInputStream`的`read`方法填充一个缓冲区，然后写入源数据线。这有效地在系统扬声器上播放声音：

```java
    private void playAudio() {
        byte[] buffer = new byte[10000];
        try {
            int count;
            while ((count = audioInputStream.read(
                   buffer, 0, buffer.length)) != -1) {
                if (count > 0) {
                    sourceDataLine.write(buffer, 0, count);
                }
            }
        } catch (Exception e) {
            // Handle exceptions
        }
    }
```

服务器运行时，启动客户端将播放来自服务器的声音。可以通过在服务器和客户端中使用线程来处理声音的录制和播放来增强播放。为简化示例，这些细节已被省略。

在这个例子中，连续的模拟声音被数字化并分成数据包。然后将这些数据包发送到客户端，在那里它们被转换回声音并播放。

在其他几个框架中还有对 UDP 流的额外支持。**Java 媒体框架**（**JMF**）([`www.oracle.com/technetwork/articles/javase/index-jsp-140239.html`](http://www.oracle.com/technetwork/articles/javase/index-jsp-140239.html))支持音频和视频媒体的处理。**实时传输协议**（**RTP**）([`en.wikipedia.org/wiki/Real-time_Transport_Protocol`](https://en.wikipedia.org/wiki/Real-time_Transport_Protocol))用于在网络上发送音频和视频数据。

# 摘要

在本章中，我们研究了 UDP 协议的性质以及 Java 如何支持它。我们对比了 TCP 和 UDP，以提供一些指导，帮助决定哪种协议对于特定问题最合适。

我们从一个简单的 UDP 客户端/服务器开始，以演示`DatagramPacket`和`DatagramSocket`类的使用方式。我们看到了`InetAddress`类是如何用来获取套接字和数据包使用的地址的。

`DatagramChannel`类支持在 UDP 环境中使用 NIO 技术，这可能比使用`DatagramPacket`和`DatagramSocket`方法更有效。该方法使用字节缓冲区来保存服务器和客户端之间发送的消息。这个例子展示了第三章中开发的许多技术，即*网络的 NIO 支持*。

接下来讨论了 UDP 多播的工作原理。这提供了一种简单的技术，可以向组成员广播消息。演示了`MulticastSocket`、`DatagramChannel`和`MembershipKey`类的使用。当使用`DatagramChannel`类时，后者类用于建立一个组。

最后，我们举了一个 UDP 用于支持音频流的例子。我们详细介绍了`javax.sound.sampled`包中几个类的使用，包括`AudioFormat`和`TargetDataLine`类用于收集和播放音频。我们使用了`DatagramSocket`和`DatagramPacket`类来传输音频。

在下一章中，我们将探讨可用于改善客户端/服务器应用程序可伸缩性的技术。


# 第七章：网络可扩展性

网络可扩展性涉及以一种方式构建应用程序，以便在应用程序上施加更多需求时，它可以调整以处理压力。需求可以以更多用户、增加的请求数量、更复杂的请求和网络特性的变化形式出现。

以下列出了几个关注的领域：

+   服务器容量

+   多线程

+   网络带宽和延迟

+   执行环境

通过增加更多的服务器、使用适当数量的线程、改进执行环境的性能以及增加网络带宽来消除瓶颈，可以实现可扩展性。

增加更多的服务器将有助于实现服务器之间的负载平衡。但是，如果网络带宽或延迟是问题，那么这将帮助不大。网络管道只能推送有限的数据。

线程经常用于提高系统的性能。为系统使用适当数量的线程允许一些线程执行，而其他线程被阻塞。被阻塞的线程可能正在等待 IO 发生或用户响应。在一些线程被阻塞时允许其他线程执行可以增加应用程序的吞吐量。

执行环境包括底层硬件、操作系统、JVM 和应用程序本身。这些领域中的每一个都有改进的可能性。我们不会涉及硬件环境，因为那超出了我们的控制范围。操作系统也是如此。虽然可以实现一些性能改进，但我们不会涉及这些领域。将识别可能影响网络性能的 JVM 参数。

我们将研究代码改进的机会。我们的大部分讨论涉及线程的使用，因为我们对这个架构特性有更多的控制。我们将在本章中说明几种改进应用程序可扩展性的方法。这些包括以下内容：

+   多线程服务器

+   线程池

+   Futures 和 callables

+   选择器（TCP/UDP）

我们将探讨使用简单线程/池的细节，因为您可能会在工作中遇到它们，并且由于平台限制可能无法使用一些新技术。线程池在许多情况下具有重复使用线程的优势。Futures 和 callables 是一种线程变体，其中可以传递和返回数据。选择器允许单个线程处理多个通道。

# 多线程服务器概述

多线程服务器的主要优势是长时间运行的客户端请求不会阻塞服务器接受其他客户端请求。如果不创建新线程，那么当前请求将被处理。只有在请求被处理后才能接受新请求。为请求使用单独的线程意味着连接及其相关的请求可以同时处理。

在使用多线程服务器时，有几种配置线程的方式如下：

+   每个请求一个线程

+   每个连接一个线程

+   每个对象一个线程

在每个请求一个线程的模型中，到达服务器的每个请求都被分配一个新线程。虽然这是一种简单的方法，但可能会导致大量线程的创建。此外，每个请求通常意味着将创建一个新连接。

这种模型在以前的客户端请求不需要保留的环境中运行得很好。例如，如果服务器的唯一目的是响应特定股票报价的请求，那么线程不需要知道任何以前的请求。

这种方法如下图所示。发送到服务器的每个客户端请求都分配给一个新线程。

![多线程服务器概述](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-net-prog-java/img/B04915_07_01.jpg)

在每个连接一个线程的模型中，客户端连接在会话期间保持。一个会话包括一系列的请求和响应。会话要么通过特定命令终止，要么在经过一段超时时间后终止。这种方法允许在请求之间维护状态信息。

这种方法在下图中有所说明。虚线表示同一客户端的多个请求由同一个线程处理。

![多线程服务器概述](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-net-prog-java/img/B04915_07_02.jpg)

每个对象一个线程的方法将相关请求与可以处理请求的特定对象排队。对象及其方法被放置在一个处理请求的线程中。请求与线程排队。虽然我们在这里不会演示这种方法，但它经常与线程池一起使用。

创建和删除连接的过程可能是昂贵的。如果客户端提交了多个请求，那么打开和关闭连接变得昂贵，应该避免。

为了解决线程过多的问题，经常使用线程池。当需要处理请求时，请求被分配给一个现有的未使用的线程来处理请求。一旦响应被发送，那么线程就可以用于其他请求。这假设不需要维护状态信息。

# 采用每个请求一个线程的方法

在第一章中，*开始网络编程*，我们演示了一个简单的多线程回显服务器。这种方法在这里重新介绍，为本章剩余部分中线程的使用提供了基础。

## 每个请求一个线程的服务器

在这个例子中，服务器将接受给定零件名称的价格请求。实现将使用支持对零件名称和价格进行并发访问的`ConcurrentHashMap`类。在多线程环境中，并发数据结构，如`ConcurrentHashMap`类，处理操作而不会出现数据损坏的可能性。此外，这个映射是缓存的一个例子，可以用来提高应用程序的性能。

我们从服务器的声明开始如下。地图被声明为静态，因为服务器只需要一个实例。静态初始化块初始化地图。`main`方法将使用`ServerSocket`类来接受来自客户端的请求。它们将在`run`方法中处理。`clientSocket`变量将保存对客户端套接字的引用：

```java
public class SimpleMultiTheadedServer implements Runnable {
    private static ConcurrentHashMap<String, Float> map;
    private Socket clientSocket;

    static {
        map = new ConcurrentHashMap<>();
        map.put("Axle", 238.50f);
        map.put("Gear", 45.55f);
        map.put("Wheel", 86.30f);
        map.put("Rotor", 8.50f);
    }

    SimpleMultiTheadedServer(Socket socket) {
        this.clientSocket = socket;
    }

    public static void main(String args[]) {
        ...
    }

    public void run() {
        ...
    }
}
```

`main`方法如下，服务器套接字等待客户端请求，然后创建一个新线程，将客户端套接字传递给线程来处理它。显示消息，显示连接被接受：

```java
    public static void main(String args[]) {
        System.out.println("Multi-Threaded Server Started");
        try {
            ServerSocket serverSocket = new ServerSocket(5000);
            while (true) {
                System.out.println(
                    "Listening for a client connection");
                Socket socket = serverSocket.accept();
                System.out.println("Connected to a Client");
                new Thread(new 
                    SimpleMultiTheadedServer(socket)).start();
            }
        } catch (IOException ex) {
            ex.printStackTrace();
        }
        System.out.println("Multi-Threaded Server Terminated");
    }
```

如下所示，`run`方法处理请求。从客户端套接字获取输入流，并读取零件名称。地图的`get`方法使用这个名称来检索价格。输入流将价格发送回客户端，并显示操作的进度：

```java
    public void run() {
        System.out.println("Client Thread Started");
        try (BufferedReader bis = new BufferedReader(
                new InputStreamReader(
                    clientSocket.getInputStream()));
             PrintStream out = new PrintStream(
                clientSocket.getOutputStream())) {

            String partName = bis.readLine();
            float price = map.get(partName);
            out.println(price);
            NumberFormat nf = NumberFormat.getCurrencyInstance();
            System.out.println("Request for " + partName
                    + " and returned a price of "
                    + nf.format(price));

            clientSocket.close();
            System.out.println("Client Connection Terminated");
        } catch (IOException ex) {
            ex.printStackTrace();
        }
        System.out.println("Client Thread Terminated");
    }
```

现在，让我们为服务器开发一个客户端。

## 每个请求一个线程的客户端

如下所示，客户端应用程序将连接到服务器，发送请求，等待响应，然后显示价格。对于这个例子，客户端和服务器都驻留在同一台机器上：

```java
public class SimpleClient {

    public static void main(String args[]) {
        System.out.println("Client Started");
        try {
            Socket socket = new Socket("127.0.0.1", 5000);
            System.out.println("Connected to a Server");
            PrintStream out = 
                new PrintStream(socket.getOutputStream());
            InputStreamReader isr = 
                new InputStreamReader(socket.getInputStream());
            BufferedReader br = new BufferedReader(isr);

            String partName = "Axle";
            out.println(partName);
            System.out.println(partName + " request sent");
            System.out.println("Response: " + br.readLine());
                        socket.close();
        } catch (IOException ex) {
            ex.printStackTrace();
        }
        System.out.println("Client Terminated");
    }
}
```

现在，让我们看看客户端和服务器是如何交互的。

## 每个请求一个线程的应用程序在运行

首先启动服务器，将显示以下输出：

**多线程服务器已启动**

**正在监听客户端连接**

接下来，启动客户端应用程序。将显示以下输出：

**客户端已启动**

**连接到服务器**

**轴请求已发送**

**响应：238.5**

**客户端已终止**

服务器将显示以下输出。您会注意到**客户端线程已启动**输出跟在**正在监听客户端连接**输出之后。这是因为线程启动前有轻微延迟：

**已连接到客户端**

**正在监听客户端连接**

**客户端线程已启动**

**请求轴并返回价格为$238.50**

**客户端连接已终止**

**客户端线程已终止**

客户端线程已启动，处理了请求，然后终止。

在关闭操作之前，将以下代码添加到客户端应用程序以发送第二个价格请求到服务器：

```java
            partName = "Wheel";
            out.println(partName);
            System.out.println(partName + " request sent");
            System.out.println("Response: " + br.readLine());
```

当客户端执行时，将得到以下输出。第二个字符串的响应为 null。这是因为在第一个请求得到答复后，服务器的响应线程已终止：

**客户端已启动**

**已连接到服务器**

**请求轴已发送**

**响应：238.5**

**发送轮子请求**

**响应：null**

**客户端已终止**

使用这种方法处理多个请求，需要重新打开连接并发送单独的请求。以下代码说明了这种方法。删除发送第二个请求的代码段。在套接字关闭后，将以下代码添加到客户端。在这个顺序中，重新打开套接字，重新创建 IO 流，并重新发送消息：

```java
            socket = new Socket("127.0.0.1", 5000);
            System.out.println("Connected to a Server");
            out = new PrintStream(socket.getOutputStream());
            isr = new InputStreamReader(socket.getInputStream());
            br = new BufferedReader(isr);

            partName = "Wheel";
            out.println(partName);
            System.out.println(partName + " request sent");
            System.out.println("Response: " + br.readLine());
            socket.close();
```

当客户端执行时，将产生以下输出，反映了两个请求及其响应：

**客户端已启动**

**已连接到服务器**

**请求轴已发送**

**响应：238.5**

**已连接到服务器**

**发送轮子请求**

**响应：86.3**

**客户端已终止**

在服务器端，我们将得到以下输出。已创建两个线程来处理请求：

**多线程服务器已启动**

**正在监听客户端连接**

**已连接到客户端**

**正在监听客户端连接**

**客户端线程已启动**

**已连接到客户端**

**正在监听客户端连接**

**客户端线程已启动**

**请求轴并返回价格为$238.50**

**客户端连接已终止**

**客户端线程已终止**

**请求轮子并返回价格为$86.30**

**客户端连接已终止**

**客户端线程已终止**

连接的打开和关闭可能很昂贵。在下一节中，我们将解决这种类型的问题。但是，如果只有单个请求，那么每个请求一个线程的方法将起作用。

# 每个连接一个线程的方法

在这种方法中，使用单个线程来处理客户端的所有请求。这种方法将需要客户端发送某种通知，表明它没有更多的请求。如果没有明确的通知，可能需要设置超时来在足够长的时间后自动断开客户端连接。

## 每个连接一个线程的服务器

通过注释掉 try 块中处理请求和向客户端发送响应的大部分代码段，修改服务器的`run`方法。用以下代码替换。在无限循环中，读取命令请求。如果请求是`quit`，则退出循环。否则，处理请求的方式与以前相同：

```java
            while(true) {
                String partName = bis.readLine();
                if("quit".equalsIgnoreCase(partName)) {
                    break;
                }
                float price = map.get(partName);
                out.println(price);
                NumberFormat nf = 
                    NumberFormat.getCurrencyInstance();
                System.out.println("Request for " + partName
                        + " and returned a price of "
                        + nf.format(price));
            } 
```

这是服务器需要修改的全部内容。

## 每个连接一个线程的客户端

在客户端中，在创建缓冲读取器后，用以下代码替换原代码。这将向服务器发送三个请求：

```java
            String partName = "Axle";
            out.println(partName);
            System.out.println(partName + " request sent");
            System.out.println("Response: " + br.readLine());

            partName = "Wheel";
            out.println(partName);
            System.out.println(partName + " request sent");
            System.out.println("Response: " + br.readLine());

            partName = "Quit";
            out.println(partName);
            socket.close();
```

只有一个连接被打开来处理所有三个请求。

## 连接的每个请求一个线程的应用程序

当客户端执行时，将得到以下输出：

**客户端已启动**

**已连接到服务器**

**请求轴已发送**

**响应：238.5**

**发送轮子请求**

**响应：86.3**

**客户端已终止**

在服务器端，将生成以下输出。您会注意到只创建了一个线程来处理多个请求：

**多线程服务器已启动**

**正在监听客户端连接**

**已连接到客户端**

**正在监听客户端连接**

**客户端线程已启动**

**请求轮轴并返回价格为$238.50**

**请求轮毂并返回价格为$86.30**

**客户端连接已终止**

**客户端线程已终止**

这是一个更有效的架构，当客户端发出多个请求时。

# 线程池

当需要限制创建的线程数量时，线程池非常有用。使用线程池不仅可以控制创建多少线程，还可以消除重复创建和销毁线程的需要，这通常是一项昂贵的操作。

以下图表描述了一个线程池。请求被分配给池中的线程。如果没有未使用的线程可用，一些线程池将创建新线程。其他线程池将限制可用线程的数量。这可能导致一些请求被阻塞。

![线程池](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-net-prog-java/img/B04915_07_03.jpg)

我们将使用`ThreadPoolExecutor`类演示线程池。该类还提供了提供有关线程执行状态信息的方法。

虽然`ThreadPoolExecutor`类具有多个构造函数，但`Executors`类提供了一种创建`ThreadPoolExecutor`类实例的简单方法。我们将演示其中两种方法。首先，我们将使用`newCachedThreadPool`方法。此方法创建的线程池将重用线程。需要时会创建新线程。但是，这可能导致创建太多线程。第二种方法`newFixedThreadPool`创建了一个固定大小的线程池。

## ThreadPoolExecutor 类的特性

创建此类的实例后，它将接受新任务，这些任务将传递给线程池。但是，池不会自动关闭。如果空闲，它将等待提交新任务。要终止池，需要调用`shutdown`或`shutdownNow`方法。后者立即关闭池，并且不会处理待处理的任务。

`ThreadPoolExecutor`类有许多方法提供额外的信息。例如，`getPoolSize`方法返回池中当前的线程数。`getActiveCount`方法返回活动线程的数量。`getLargestPoolSize`方法返回池中曾经的最大线程数。还有其他几种可用的方法。

## 简单线程池服务器

我们将使用的服务器来演示线程池，当给出零件名称时，将返回零件的价格。每个线程将访问一个包含零件信息的`ConcurrentHashMap`实例。我们使用哈希映射的并发版本，因为它可能会被多个线程访问。

接下来声明了`ThreadPool`类。`main`方法使用`WorkerThread`类执行实际工作。在`main`方法中，调用`newCachedThreadPool`方法创建线程池：

```java
public class ThreadPool {

    public static void main(String[] args) {
        System.out.println("Thread Pool Server Started");
        ThreadPoolExecutor executor = (ThreadPoolExecutor) 
            Executors.newCachedThreadPool();
        ...
        executor.shutdown();
        System.out.println("Thread Pool Server Terminated");
    }
}
```

接下来，使用 try 块来捕获和处理可能发生的任何异常。在 try 块内，创建了一个服务器套接字，其`accept`方法会阻塞，直到有客户端连接请求。建立连接后，使用客户端套接字创建了一个`WorkerThread`实例，如下面的代码所示：

```java
        try {
            ServerSocket serverSocket = new ServerSocket(5000);
            while (true) {
                System.out.println(
                    "Listening for a client connection");
                Socket socket = serverSocket.accept();
                System.out.println("Connected to a Client");
                WorkerThread task = new WorkerThread(socket);
                System.out.println("Task created: " + task);
                executor.execute(task);
            }
        } catch (IOException ex) {
            ex.printStackTrace();
        }
```

现在，让我们来看一下接下来显示的`WorkerThread`类。在这里声明了`ConcurrentHashMap`实例，其中使用字符串作为键，存储的对象是浮点数。哈希映射在静态初始化块中进行了初始化：

```java
public class WorkerThread implements Runnable {
    private static final ConcurrentHashMap<String, Float> map;
    private final Socket clientSocket;

    static {
        map = new ConcurrentHashMap<>();
        map.put("Axle", 238.50f);
        map.put("Gear", 45.55f);
        map.put("Wheel", 86.30f);
        map.put("Rotor", 8.50f);
    }
    ...
}
```

类的构造函数将客户端套接字分配给`clientSocket`实例变量以供以后使用，如下所示：

```java
    public WorkerThread(Socket clientSocket) {
        this.clientSocket = clientSocket;
    }
```

`run`方法处理请求。从客户端套接字获取输入流，并用于获取零件名称。将此名称用作哈希映射的`get`方法的参数，以获取相应的价格。将此价格发送回客户端，并显示一个显示响应的消息：

```java
    @Override
    public void run() {
        System.out.println("Worker Thread Started");
        try (BufferedReader bis = new BufferedReader(
                new InputStreamReader(
                    clientSocket.getInputStream()));
                PrintStream out = new PrintStream(
                        clientSocket.getOutputStream())) {

            String partName = bis.readLine();
            float price = map.get(partName);
            out.println(price);
            NumberFormat nf = NumberFormat.getCurrencyInstance();
            System.out.println("Request for " + partName
                    + " and returned a price of "
                    + nf.format(price));
            clientSocket.close();
            System.out.println("Client Connection Terminated");
        } catch (IOException ex) {
            ex.printStackTrace();
        }
        System.out.println("Worker Thread Terminated");
    }
```

现在我们准备讨论客户端应用程序。

## 简单线程池客户端

此应用程序使用`Socket`类建立与服务器的连接。输入和输出流用于发送和接收响应。这种方法在第一章中讨论过，*网络编程入门*。以下是客户端应用程序。与服务器建立连接，并向服务器发送部件价格的请求。获取并显示响应。

```java
public class SimpleClient {

    public static void main(String args[]) {
        System.out.println("Client Started");
        try (Socket socket = new Socket("127.0.0.1", 5000)) {
            System.out.println("Connected to a Server");
            PrintStream out = 
                new PrintStream(socket.getOutputStream());
            InputStreamReader isr = 
                new InputStreamReader(socket.getInputStream());
            BufferedReader br = new BufferedReader(isr);

            String partName = "Axle";
            out.println(partName);
            System.out.println(partName + " request sent");
            System.out.println("Response: " + br.readLine());
            socket.close();

        } catch (IOException ex) {
            ex.printStackTrace();
        }
        System.out.println("Client Terminated");
    }
}
```

现在我们准备看它们如何一起工作。

## 线程池客户端/服务器正在运行

首先启动服务器应用程序。您将看到以下输出：

线程池服务器已启动

正在监听客户端连接

接下来，启动客户端。它将产生以下输出，发送轴价格请求，然后接收到`238.5`的响应：

客户端已启动

已连接到服务器

轴请求已发送

响应：238.5

客户端已终止

在服务器端，您将看到类似以下输出。线程已创建，并显示请求和响应数据。然后线程终止。您会注意到线程的名称前面有字符串“packt”。这是应用程序的包名称：

已连接到客户端

任务已创建：packt.WorkerThread@33909752

正在监听客户端连接

工作线程已启动

请求轴并返回价格为 238.50 美元

客户端连接已终止

工作线程已终止

如果启动第二个客户端，服务器将产生类似以下输出。您会注意到为每个请求创建了一个新线程：

线程池服务器已启动

正在监听客户端连接

已连接到客户端

任务已创建：packt.WorkerThread@33909752

正在监听客户端连接

工作线程已启动

请求轴并返回价格为 238.50 美元

客户端连接已终止

工作线程已终止

已连接到客户端

任务已创建：packt.WorkerThread@3d4eac69

正在监听客户端连接

工作线程已启动

请求轴并返回价格为 238.50 美元

客户端连接已终止

工作线程已终止

## 使用 Callable 的线程池

使用`Callable`和`Future`接口提供了另一种支持多线程的方法。`Callable`接口支持需要返回结果的线程。`Runnable`接口的`run`方法不返回值。对于某些线程，这可能是一个问题。`Callable`接口具有一个`call`方法，返回一个值，可以代替`Runnable`接口。

`Future`接口与`Callable`对象结合使用。其思想是调用`call`方法，当前线程继续执行其他任务。当`Callable`对象完成后，使用`get`方法来检索结果。必要时，此方法将阻塞。

### 使用 Callable

我们将使用`Callable`接口来补充我们之前创建的`WorkerThread`类。我们将部件名称哈希映射移到一个名为`WorkerCallable`的类中，我们将重写`call`方法以返回价格。这实际上是对此应用程序的额外工作，但它说明了使用`Callable`接口的一种方式。它演示了如何从`Callable`对象返回一个值。

下面声明的`WorkerCallable`类使用相同的代码来创建和初始化哈希映射：

```java
public class WorkerCallable implements Callable<Float> {

    private static final ConcurrentHashMap<String, Float> map;
    private String partName;

    static {
        map = new ConcurrentHashMap<>();
        map.put("Axle", 238.50f);
        map.put("Gear", 45.55f);
        map.put("Wheel", 86.30f);
        map.put("Rotor", 8.50f);
    }
    ...
}
```

构造函数将初始化部件名称，如下所示：

```java
    public WorkerCallable(String partName) {
        this.partName = partName;
    }
```

接下来显示了`call`方法。地图获取价格，我们显示然后返回：

```java
    @Override
    public Float call() throws Exception {
        float price = map.get(this.partName);
        System.out.println("WorkerCallable returned " + price);
        return price;
    }
```

接下来，通过删除以下语句修改`WorkerThread`类：

```java
        float price = map.get(partName);
```

用以下代码替换它。使用客户端请求的零件名称创建一个新的`WorkerCallable`实例。立即调用`call`方法，并返回相应零件的价格：

```java
        float price = 0.0f;
        try {
            price = new WorkerCallable(partName).call();
        } catch (Exception ex) {
            ex.printStackTrace();
        }
```

应用程序将产生与以前相同的输出，只是您将看到消息指示`WorkerCallable`类的`call`方法已执行。虽然创建了另一个线程，但我们将阻塞，直到`call`方法返回。

这个例子并没有完全展示这种方法的威力。`Future`接口将改进这种技术。

### 使用 Future

`Future`接口表示已完成的`call`方法的结果。使用此接口，我们可以调用`Callable`对象，而不必等待其返回。假设计算零件价格的过程比仅在表中查找要复杂。可以想象需要多个步骤来计算价格，每个步骤可能都很复杂，可能需要一些时间来完成。还假设这些单独的步骤可以并发执行。

用以下代码替换上一个示例。我们创建一个新的`ThreadPoolExecutor`实例，将两个代表两步价格确定过程的`Callable`对象分配给它。这是使用`submit`方法完成的，该方法返回一个`Future`实例。`call`方法的实现分别返回`1.0`和`2.0`，以保持示例简单：

```java
        float price = 0.0f;
        ThreadPoolExecutor executor = (ThreadPoolExecutor) 
            Executors.newCachedThreadPool();
        Future<Float> future1 = 
                executor.submit(new Callable<Float>() {
            @Override
            public Float call() {
                // Compute first part
                return 1.0f;
            }
        });
        Future<Float> future2 = 
                executor.submit(new Callable<Float>() {
            @Override
            public Float call() {
                // Compute second part
                return 2.0f;
            }
        });
```

接下来，添加以下 try 块，使用`get`方法获取价格的两个部分。这些用于确定零件的价格。如果相应的`Callable`对象尚未完成，则`get`方法将阻塞：

```java
            try {
                Float firstPart = future1.get();
                Float secondPart = future2.get();
                price = firstPart + secondPart;
            } catch (InterruptedException|ExecutionException ex) {
                ex.printStackTrace();
            }
```

执行此代码时，您将获得零件的价格为 3.0。 `Callable`和`Future`接口的组合提供了一种处理返回值的线程的简单技术。

# 使用 HttpServer 执行程序

我们在第四章中介绍了`HTTPServer`类。当 HTTP 服务器接收到请求时，默认情况下会使用在调用`start`方法时创建的线程。但是，也可以使用不同的线程。`setExecutor`方法指定了如何将这些请求分配给线程。

此方法的参数是一个`Executor`对象。我们可以为此参数使用几种实现中的任何一种。在以下顺序中，使用了一个缓存的线程池：

```java
        server.setExecutor(Executors.newCachedThreadPool());
```

为了控制服务器使用的线程数量，我们可以使用大小为`5`的固定线程池，如下所示：

```java
        server.setExecutor(Executors.newFixedThreadPool(5));
```

在调用`HTTPServer`的`start`方法之前必须调用此方法。然后所有请求都将提交给执行程序。以下是在第四章中开发的`HTTPServer`类中复制的，并向您展示了`setExecutor`方法的用法：

```java
public class MyHTTPServer {

    public static void main(String[] args) throws Exception {
        System.out.println("MyHTTPServer Started");
        HttpServer server = HttpServer.create(
            new InetSocketAddress(80), 0);
        server.createContext("/index", new OtherHandler());
        server.setExecutor(Executors.newCachedThreadPool());
        server.start();
    }
    ...
}
```

服务器将以与以前相同的方式执行，但将使用缓存的线程池。

# 使用选择器

选择器用于 NIO 应用程序，允许一个线程处理多个通道。选择器协调多个通道及其事件。它标识了准备处理的通道。如果我们每个通道使用一个线程，那么我们会经常在线程之间切换。这种切换过程可能很昂贵。使用单个线程处理多个通道可以避免部分开销。

以下图示了这种架构。一个线程被注册到一个选择器中。选择器将识别准备处理的通道和事件。

![使用选择器](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-net-prog-java/img/B04915_07_04.jpg)

选择器由两个主要类支持：

+   `Selector`：提供主要功能

+   `SelectionKey`：这标识了准备处理的事件类型

要使用选择器，请执行以下操作：

+   创建选择器

+   使用选择器注册通道

+   选择一个通道以在可用时使用

让我们更详细地检查每个步骤。

## 创建选择器

没有公共的 `Selector` 构造函数。要创建 `Selector` 对象，请使用静态的 `open` 方法，如下所示：

```java
    Selector selector = Selector.open();
```

还有一个 `isOpen` 方法来确定选择器是否打开，以及一个 `close` 方法在不再需要时关闭它。

## 注册通道

`register` 方法使用选择器注册通道。任何注册到选择器的通道必须处于非阻塞模式。例如，`FileChannel` 对象不能注册，因为它不能放置在非阻塞模式。使用 `configureBlocking` 方法并将 `false` 作为其参数来将通道置于非阻塞模式，如下所示：

```java
    socketChannel.configureBlocking(false);
```

`register` 方法如下。这是 `ServerSocketChannel` 和 `SocketChannel` 类的方法。在下面的示例中，它与 `SocketChannel` `实例` 一起使用：

```java
    socketChannel.register(selector, SelectionKey.OP_WRITE, null);
```

`Channel` 类的 `register` 方法具有三个参数：

+   用于注册的选择器

+   感兴趣的事件类型

+   要与通道关联的数据

事件类型指定应用程序感兴趣处理的通道事件类型。例如，如果通道有准备好读取的数据，我们可能只想被通知事件。

有四种可用的事件类型，如下表所列：

| 类型 | 事件类型常量 | 意义 |
| --- | --- | --- |
| 连接 | `SelectionKey.OP_CONNECT` | 这表示通道已成功连接到服务器 |
| 接受 | `SelectionKey.OP_ACCEPT` | 这表示服务器套接字通道已准备好接受来自客户端的连接请求 |
| 读取 | `SelectionKey.OP_READ` | 这表示通道有准备好读取的数据 |
| 写入 | `SelectionKey.OP_WRITE` | 这表示通道已准备好进行写操作 |

这些类型被称为兴趣集。在下面的语句中，通道与读取兴趣类型相关联。该方法返回一个 `SelectionKey` 实例，其中包含许多有用的属性：

```java
    SelectionKey key = channel.register(selector, 
        SelectionKey.OP_READ);
```

如果有多个感兴趣的事件，我们可以使用 OR 运算符创建这些事件的组合，如下所示：

```java
    int interestSet = SelectionKey.OP_READ | 
        SelectionKey.OP_WRITE;
    SelectionKey key = channel.register(selector, interestSet);
```

`SelectionKey` 类具有几个属性，将有助于处理通道。其中包括以下内容：

+   兴趣集：这包含了感兴趣的事件。

+   就绪集：这是通道准备处理的操作集。

+   通道：`channel` 方法返回与选择键相关联的通道。

+   选择器：`selector` 方法返回与选择键相关联的选择器。

+   附加对象：可以使用 `attach` 方法附加更多信息。稍后使用 `attachment` 方法访问此对象。

`interestOps` 方法返回一个整数，表示感兴趣的事件，如下所示：

```java
    int interestSet = selectionKey.interestOps();
```

我们将使用这个来处理事件。

要确定哪些事件已准备就绪，我们可以使用以下任何方法之一：

+   `readOps`：这返回一个包含准备好的事件的整数

+   `isAcceptable`：这表示接受事件已准备就绪

+   `isConnectable`：这表示连接事件已准备就绪

+   `isReadable`：这表示读事件已准备就绪

+   `isWritable`：这表示写事件已准备就绪

现在，让我们看看这些方法如何运作。

## 使用选择器支持时间客户端/服务器

我们将开发一个时间服务器来说明 `Selector` 类和相关类的使用。该服务器和时间客户端是从 第三章 中的时间服务器和客户端应用程序改编而来，*NIO 支持网络*。这里的重点将放在选择器的使用上。通道和缓冲区操作将不在这里讨论，因为它们已经在之前讨论过。

### 通道时间服务器

时间服务器将接受客户端应用程序的连接，并每秒向客户端发送当前日期和时间。当我们讨论客户端时，客户端可能无法接收所有这些消息。

时间服务器使用内部静态类`SelectorHandler`来处理选择器并发送消息。这个类实现了`Runnable`接口，并将成为选择器的线程。

在`main`方法中，服务器套接字接受新的通道连接并将它们注册到选择器中。`Selector`对象被声明为静态实例变量，如下所示。这允许它从`SelectorHandler`线程和主应用程序线程中访问。共享此对象将导致潜在的同步问题，我们将解决这些问题：

```java
public class ServerSocketChannelTimeServer {
    private static Selector selector;

    static class SelectorHandler implements Runnable {
        ...
    }

    public static void main(String[] args) {
        ...
    }
}
```

让我们从`main`方法开始。创建一个使用端口`5000`的服务器套接字通道。异常在 try 块中捕获，如下所示：

```java
    public static void main(String[] args) {
        System.out.println("Time Server started");
        try {
            ServerSocketChannel serverSocketChannel = 
                ServerSocketChannel.open();
            serverSocketChannel.socket().bind(
                new InetSocketAddress(5000));
            ...
            }
        } catch (ClosedChannelException ex) {
            ex.printStackTrace();
        } catch (IOException ex) {
            ex.printStackTrace();
        }
    }
```

选择器被创建，并启动了一个`SelectorHandler`实例的线程：

```java
            selector = Selector.open();
            new Thread(new SelectorHandler()).start();
```

无限循环将接受新的连接。显示一条消息，指示已建立连接：

```java
            while (true) {
                SocketChannel socketChannel
                        = serverSocketChannel.accept();
                System.out.println("Socket channel accepted - " 
                    + socketChannel);
                ...
            }
```

有了一个良好的通道，将调用`configureBlocking`方法，唤醒选择器，并将通道注册到选择器。线程可能会被`select`方法阻塞。使用`wakeup`方法将导致`select`方法立即返回，从而允许`register`方法解除阻塞：

```java
                if (socketChannel != null) {
                    socketChannel.configureBlocking(false);
                    selector.wakeup();
                    socketChannel.register(selector, 
                        SelectionKey.OP_WRITE, null);
                }
```

一旦通道已经注册到选择器，我们就可以开始处理与该通道关联的事件。

`SelectorHandler`类将使用选择器对象标识事件的发生，并将它们与特定通道关联起来。它的`run`方法完成所有工作。如下所示，一个无限循环使用`select`方法标识事件的发生。`select`方法使用`500`作为参数，指定 500 毫秒的超时。它返回一个整数，指定有多少个密钥准备好被处理：

```java
    static class SelectorHandler implements Runnable {

        @Override
        public void run() {
            while (true) {
                try {
                    System.out.println("About to select ...");
                    int readyChannels = selector.select(500);
                    ...
                } catch (IOException | InterruptedException ex) {
                    ex.printStackTrace();
                }
            }
        }
    }
```

如果`select`方法超时，它将返回值`0`。当这种情况发生时，我们会显示相应的消息，如下所示：

```java
        if (readyChannels == 0) {
            System.out.println("No tasks available");
        } else {
            ...
        }
```

如果有准备好的密钥，那么`selectedKeys`方法将返回这个集合。然后使用迭代器逐个处理每个密钥：

```java
        Set<SelectionKey> keys = selector.selectedKeys();
        Iterator<SelectionKey> keyIterator = keys.iterator();
        while (keyIterator.hasNext()) {
            ...
        }
```

检查每个`SelectionKey`实例，以查看发生了哪种事件类型。在以下实现中，只处理可写事件。处理完后，线程休眠一秒。这将延迟至少一秒发送日期和时间消息。需要`remove`方法来从迭代器列表中删除事件：

```java
            SelectionKey key = keyIterator.next();
            if (key.isAcceptable()) {
                // Connection accepted
            } else if (key.isConnectable()) {
                // Connection established
            } else if (key.isReadable()) {
                // Channel ready to read
            } else if (key.isWritable()) {
                ...
            }
            Thread.sleep(1000);
            keyIterator.remove();
```

如果是可写事件，则发送日期和时间，如下所示。`channel`方法返回事件的通道，并将消息发送给该客户端。显示消息，显示消息已发送：

```java
            String message = "Date: "
                + new Date(System.currentTimeMillis());

            ByteBuffer buffer = ByteBuffer.allocate(64);
            buffer.put(message.getBytes());
            buffer.flip();
            SocketChannel socketChannel = null;
            while (buffer.hasRemaining()) {
                socketChannel = (SocketChannel) key.channel();
                socketChannel.write(buffer);
            }
            System.out.println("Sent: " + message + " to: " 
                + socketChannel);
```

服务器准备就绪后，我们将开发我们的客户端应用程序。

### 日期和时间客户端应用程序

客户端应用程序几乎与第三章中开发的应用程序相同，*NIO 支持网络*。主要区别在于它将在随机间隔请求日期和时间。当我们使用多个客户端与我们的服务器时，将看到这种效果。应用程序的实现如下：

```java
public class SocketChannelTimeClient {

    public static void main(String[] args) {
        Random random = new Random();
        SocketAddress address = 
            new InetSocketAddress("127.0.0.1", 5000);
        try (SocketChannel socketChannel = 
                SocketChannel.open(address)) {
            while (true) {
                ByteBuffer byteBuffer = ByteBuffer.allocate(64);
                int bytesRead = socketChannel.read(byteBuffer);
                while (bytesRead > 0) {
                    byteBuffer.flip();
                    while (byteBuffer.hasRemaining()) {
                        System.out.print((char) byteBuffer.get());
                    }
                    System.out.println();
                    bytesRead = socketChannel.read(byteBuffer);
                }
                Thread.sleep(random.nextInt(1000) + 1000);
            }
        } catch (ClosedChannelException ex) {
            // Handle exceptions
        }catch (IOException | InterruptedException ex) {
            // Handle exceptions
        } 
    }
}
```

我们现在准备好看看服务器和客户端如何一起工作。

### 正在运行的日期和时间服务器/客户端

首先，启动服务器。它将产生以下输出：

**时间服务器已启动**

**即将选择...**

**没有可用的任务**

**即将选择...**

**没有可用的任务**

**即将选择...**

**没有可用的任务**

**...**

这个序列将重复，直到客户端连接到服务器。

接下来，启动客户端。在客户端上，您将获得类似以下输出：

**日期：2015 年 10 月 07 日星期三 17:55:43 CDT**

**日期：2015 年 10 月 07 日星期三 17:55:45 CDT**

**日期：2015 年 10 月 07 日星期三 17:55:47 CDT**

**日期：2015 年 10 月 07 日星期三 17:55:49 CDT**

在服务器端，您将看到反映连接和请求的输出，如下所示。您会注意到端口号`58907`标识了这个客户端：

**...**

**已发送：日期：2015 年 10 月 07 日星期三 17:55:43 CDT 至：java.nio.channels.SocketChannel[connected local=/127.0.0.1:5000 remote=/127.0.0.1:58907]**

**...**

**已发送：日期：2015 年 10 月 07 日星期三 17:55:45 CDT 至：java.nio.channels.SocketChannel[connected local=/127.0.0.1:5000 remote=/127.0.0.1:58907]**

启动第二个客户端。您将看到类似的连接消息，但端口号不同。一个可能的连接消息是显示一个端口号为`58908`的客户端：

**已接受套接字通道 - java.nio.channels.SocketChannel[connected local=/127.0.0.1:5000 remote=/127.0.0.1:58908]**

然后，您将看到日期和时间消息被发送到两个客户端。

# 处理网络超时

当应用程序部署在现实世界中时，可能会出现在局域网开发时不存在的新网络问题。问题，比如网络拥塞、慢速连接和网络链路丢失可能导致消息的延迟或丢失。检测和处理网络超时是很重要的。 

有几个套接字选项可以对套接字通信进行一些控制。`SO_TIMEOUT`选项用于设置读操作的超时时间。如果指定的时间过去，那么将抛出`SocketTimeoutException`异常。

在下面的语句中，套接字将在三秒后过期：

```java
    Socket socket = new ...
    socket.setSoTimeout(3000);
```

选项必须在阻塞读操作发生之前设置。超时时间为零将永远不会超时。处理超时是一个重要的设计考虑。

# 总结

在本章中，我们研究了几种应对应用程序可扩展性的方法。可扩展性是指应用程序在承受增加负载的能力。虽然我们的例子侧重于将这些技术应用于服务器，但它们同样适用于客户端。

我们介绍了三种线程架构，并重点介绍了其中的两种：每个请求一个线程和每个连接一个线程。每个请求一个线程的模型为到达服务器的每个请求创建一个新线程。这适用于客户端一次或可能一次性发出几个请求的情况。

每个连接一个线程的模型将创建一个线程来处理来自客户端的多个请求。这样可以避免多次重新连接客户端，避免产生多个线程的成本。这种方法适用于需要维护会话和可能状态信息的客户端。

线程池支持一种避免创建和销毁线程的方法。线程池管理一组线程。未被使用的线程可以被重新用于不同的请求。线程池的大小可以受到控制，因此可以根据应用程序和环境的要求进行限制。`Executor`类被用来创建和管理线程池。

NIO 的`Selector`类被说明了。这个类使得更容易处理线程和 NIO 通道。通道和与通道相关的事件被注册到选择器中。当事件发生时，比如通道可用于读操作时，选择器提供对通道和事件的访问。这允许一个单独的线程管理多个通道。

我们简要地重新审视了在第四章中介绍的`HttpServer`类，*客户端/服务器开发*。我们演示了如何轻松地添加线程池以提高服务器的性能。我们还研究了网络超时的性质以及如何处理它们。当网络无法及时支持应用程序之间的通信时，这些问题可能会发生。

在下一章中，我们将探讨网络安全威胁以及我们如何解决这些问题。
