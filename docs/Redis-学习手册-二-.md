# Redis 学习手册（二）

> 原文：[`zh.annas-archive.org/md5/5363559C03089BFE85663EC2113016AB`](https://zh.annas-archive.org/md5/5363559C03089BFE85663EC2113016AB)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：在 Redis 中处理数据

业务中的数据定义了业务。这意味着我们定义、存储、解释和使用数据的方式构成了我们业务的数据平台。很少有单独的数据具有意义；只有当与其他数据结合时，它才构成业务功能。因此，重要的是将数据连接、分组和过滤，以便同一数据集可以用于业务的各个方面。

为了拥有一个能够满足未来需求的平台，我们有必要以一种方式定义和分类数据，这种方式能够给我们指示我们对数据的期望。数据有许多方面，重要的是要了解这些方面，以从中提取出完整的商业价值。例如，公司的股票价格对于实时系统来说很重要，以决定是买入还是卖出，在几秒或几毫秒后就失去了重要性。然而，对于分析系统来说，预测其趋势变得重要。因此，在不同的时间点上，相同的数据具有不同的用途。因此，在制定数据架构时，考虑数据的各种期望是一个良好的做法。

# 分类数据

人们普遍倾向于只考虑适合关系模型的数据模型。这可能是某些类别数据的良好模型，但对于另一类数据可能会证明是无效的。由于本书是关于 Redis 的，我们将尝试根据某些行为对数据进行分类，并尝试看看 Redis 适用于哪些情况：

+   **消息和事件数据**：在业务中分类为消息数据的数据具有以下特性：

+   **数据复杂性**：消息数据具有低数据复杂性，因为它们通常是扁平结构的

+   **数据数量**：消息数据通常具有大量数据

+   **持久性**：消息数据可以存储在磁盘和内存中

+   **CAP 属性**：消息数据至少需要可用和分区容错

+   **可用性**：消息数据可以在实时、软实时和离线中使用，并显示出重写入和低读取的特性

如果消息数据的需求是实时和软实时活动，并且数据量不是很大，那么可以使用 Redis 及其消息传递能力。

+   **缓存数据**：在业务中分类为缓存数据的数据具有以下特性：

+   **数据复杂性**：缓存数据具有低数据复杂性，大多以名称值对的形式存储

+   **数据数量**：缓存数据通常具有较少到中等的数据量

+   **持久性**：数据可以存储在缓存内存中

+   **CAP 属性**：缓存数据至少需要可用和一致

+   **可用性**：缓存数据可以在实时中使用，并显示低写入和高读取

Redis 是缓存数据的完美选择，因为它提供了可以直接被程序用于存储数据的数据结构。此外，Redis 中的键具有生存时间选项，可以用于定期清理 Redis 中的数据。

+   **元数据**：在业务中分类为元数据的数据具有以下特性：

+   **数据复杂性**：元数据具有低数据复杂性，大多以名称值对的形式存储

+   **数据数量**：元数据通常具有较少的数据量

+   **持久性**：元数据可以存储在内存中

+   **CAP 属性**：元数据至少需要可用和一致

+   **可用性**：元数据可以在实时中使用，并且通常显示出低写入和低到高读取的特性

Redis 是元数据的完美选择，因为它提供了可以直接被程序用于存储数据的数据结构。由于 Redis 速度快且具有消息传递能力，因此可以用于运行时操作元数据，并且还可以作为中央元数据存储库。以下图表示了 Redis 如何作为元数据存储使用：

![分类数据](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/0123OS_05_01.jpg)

Redis 作为元数据存储

+   **事务数据**：在业务中分类为事务数据的数据显示以下属性：

+   **数据复杂性**：事务数据具有中等到高的数据复杂性，大多是关系型的

+   **数据量**：事务数据通常具有中等到高的数据量

+   **持久性**：事务数据可以存储在内存和磁盘中

+   **CAP 属性**：事务数据至少需要是一致的和分区容错的

+   **可用性**：事务数据需要显示`CRUD`行为，而 Redis 没有这些功能

Redis 不是这种类型数据的正确数据存储。我们还可以看到，无论何时需要 CAP 特性的分区容错，都不应该使用 Redis。

+   **分析数据**：在业务中分类为分析数据的数据显示以下属性：

+   **数据复杂性**：数据复杂性可以根据在线分析和离线分析进一步分离。在线分析数据的数据复杂性低至中等，因为它们可能包含类似图形的关系。离线分析具有非常高的数据复杂性。

+   **数据量**：这里的数据通常具有低到高的数据量，取决于我们想要的分析类型。与离线分析相比，在线分析的数据量可能较低。

+   **持久性**：数据可以存储在磁盘和内存中。如果需要在线分析，则数据存储在内存中，但如果分析是离线的，则数据需要持久存储在磁盘中。

+   **CAP 属性**：在离线分析的情况下，数据至少需要是可用的和分区容错的，在在线分析的情况下，数据需要是可用的和一致的。

+   **可用性**：消息数据可以在实时、软实时和离线中使用。

如果要进行在线分析，可以使用 Redis，前提是数据的复杂性较低。

在前面对数据的分类中，我们看到了 Redis 适合的一些领域以及应该避免使用 Redis 的领域。但是，要使 Redis 在业务解决方案环境中受到认真对待，它必须具备容错和故障管理、复制等能力。在接下来的部分中，我们将深入研究如何处理冗余和故障管理。

# 主从数据复制

在任何业务应用程序中，数据以复制的方式保存是至关重要的，因为硬件随时可能损坏而不会发出任何警告。为了保持业务的连续性，当主数据库崩溃时，可以使用复制的数据库，这在某种程度上保证了服务的质量。拥有复制数据的另一个优势是当一个数据库的流量增加并且对解决方案的性能产生负面影响时。为了提供性能，重要的是要平衡流量并减少每个节点的负载。

诸如 Cassandra 之类的数据存储提供了主-主配置，其中拓扑中的所有节点都像主节点一样，并且数据的复制是基于基于密钥生成的令牌哈希进行的，为了实现这一点，拓扑中的节点根据令牌范围进行分区。

与主主数据存储系统不同，Redis 具有更简单的主从安排。这意味着主节点将写入所有数据，然后将数据复制到所有从节点。复制是异步进行的，这意味着一旦数据被写入主节点，从节点并不会同步写入，而是由一个单独的过程异步写入，因此更新并不是立即的；换句话说是**最终一致性**。但是这种安排在性能方面有优势。如果复制是同步的，那么当对主节点进行更新时，主节点必须更新所有从节点，然后更新才会被标记为成功。因此，如果有更多的从节点，更新就会变得更加耗时。

下图表示了 Redis 中主从复制的过程。为了更好地理解这个过程，假设在时间**T0**，由**Msg**表示的 Set 的值在主节点以及所有从节点（**S1**，**S2**，**S3**）中都是**"Hello"**。在时间**T1**进行插入命令**SADD**插入值（**"Hello again"**）到 Set 中，那么在时间**T2**，值**Msg**变成了**Hello Hello again**，但是从节点的**Msg**值仍然是**"Hello"**。新值成功插入到主节点，并且成功插入的回复代码被发送回客户端。与此同时，主节点将开始向所有从节点插入新值，这发生在时间**T3**。因此，在时间**T3**，所有节点（主节点和从节点）都更新为新值。主节点更新和从节点更新之间的时间差非常小（毫秒级）。

为了更好地理解 Redis 中主从是如何工作的，让我们回顾一下之前讨论的 Redis 中实时消息传递的章节。为了在这种情况下应用相同的功能，我们可以认为所有的从节点都已经订阅了主节点，当主节点更新时，它会将新数据发布到所有的从节点。

![主从数据复制](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/0123OS_05_02.jpg)

主从数据复制

那么，当从节点宕机并且主节点发生更新时会发生什么呢？在这种情况下，特定的从节点会错过更新，仍然保留旧值。然而，当从节点再次连接到主节点时，它首先会向主节点发送一个`SYNC`命令。这个命令将数据发送到从节点，从而使其更新自身。

## 设置主节点和从节点

在 Redis 中设置主从节点非常简单。我们在本地机器上为 Redis 设置一个主节点和一个从节点。我们首先要做的是将 Redis 文件夹（在我们的例子中是`redis 2.6`）复制到一个合适的位置。现在我们在两个不同的位置有了 Redis 分发。

![设置主节点和从节点](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/0123OS_05_03.jpg)

主节点文件夹和从节点文件夹

为了更好地理解，我们将**Redis-2.6**称为主节点，**Redis-2.6.slave**称为从节点。现在打开主节点，转到`bin/release`文件夹并启动 Redis-server。这将在本地主机上以端口地址 6379 启动 Redis 服务器。现在打开从节点，并在适当的文本编辑器中打开`Redis.conf`文件。至少需要更改两个属性才能启动从节点。需要编辑的第一个属性是`port`。在我们的情况下，让我们将值从 6379 更改为 6380。由于主节点将在 6379 端口监听请求，从节点必须在不同的端口监听请求（我们将从同一台机器上启动主节点和从节点）。需要进行的第二个属性更改是`slaveof`，其值将是`127.0.0.1 6379`。这基本上告诉从节点主节点在何处以及在哪个端口运行。这很有帮助，因为从节点将使用此地址向主节点发送`SYNC`和其他命令。进行这些最小更改后，我们就可以开始了。现在转到从节点的`bin/release`文件夹并启动 Redis-server。

### 注意

当启动 Redis-server 时，请提供从节点的`Redis.conf`路径，即 Redis-server `F:\path\to\config-file\Redis.conf`。

当我们启动从节点时，我们会看到的第一件事是它会尝试连接到主节点。从其`Redis.conf`中，从节点将找出主节点的主机和端口。Redis 与其他数据存储相比的另一件事是，它使用一个端口来处理业务请求，同时还使用`SYNC`和其他端口来处理从节点的类似请求。这主要是因为 Redis 是单线程服务器，线程只监听传入套接字的消息。

以下图表示从节点启动时命令提示符的外观（请确保主节点正在运行）：

![设置主节点和从节点](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/0123OS_05_04.jpg)

从节点在端口 6380 启动

这里有几件事需要注意。第一件事是，从节点启动时，它会向主节点发送`SYNC`命令。该命令是非阻塞命令，这意味着单个线程不会阻止其他请求以满足此请求。主要是主节点将其放入该连接的请求堆栈中，并将其与其他连接的时间片进行切割，当该连接的命令活动完成时（在我们的情况下是从节点的`SYNC`），它将其发送到从节点。在这种情况下，它发送回的是命令和从节点需要的数据，以使其与主节点保持一致。该命令与数据一起执行，然后随后加载到从节点的数据库中。主节点发送的所有命令都是更改数据而不是获取数据的命令。主用于连接到从节点的协议是**Redis 协议**。

让我们看一些场景，并看看 Redis 在主从模式下的行为：

+   主节点正在运行，telnet 会话连接到主节点：

1.  确保 Redis 主节点正在运行。

1.  确保主 Redis 客户端正在运行。

1.  打开命令提示符，并使用命令`telnet 127.0.0.1 6379`连接到主机。

1.  在 telnet 客户端中键入`SYNC`命令。命令提示符中应出现以下文本：![设置主节点和从节点](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/0123OS_05_05.jpg)

主节点 ping telnet 客户端

1.  转到主客户端提示符，并键入命令`SET MSG "Learning Redis master slave replication"`并执行它。立即切换到 telnet 命令提示符，您将看到以下输出：![设置主节点和从节点](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/0123OS_05_06.jpg)

主节点向 telnet 客户端发送数据

1.  现在在主节点的客户端提示符中执行`GET MSG`命令

+   主节点已启动，从节点首次连接：

1.  从节点控制台与上一图类似。

1.  从主节点的 Redis-cli 中发出命令`SET MSG "学习 Redis"`。

1.  从从节点的 Redis-cli 中发出命令`GET MSG`。

1.  确保您提供主机和端口地址；在我们的情况下，因为我们已将其配置为 localhost 并且端口配置为 6380，命令看起来像`Redis-cli.exe -h localhost -p 6380`。

1.  结果应该是`“学习 Redis”`。

+   主节点已启动，从节点再次连接：

1.  杀死从节点和客户端。

1.  转到主节点的客户端命令提示符并编写命令`SET MSG "从节点已关闭"`。

1.  现在启动从节点及其客户端（提供主机和端口信息）。

1.  从从节点的客户端命令提示符执行命令`GET MSG`，结果应该是`“从节点已关闭”`。

+   主节点已启动并正在执行管道命令，我们正在从从节点读取值：

1.  确保主节点和从节点正在运行。

1.  在从节点客户端的命令提示符中写入`SCARD MSG`命令，但不要执行它。我们将得到集合`MSG`中成员的数量。

1.  打开您的 Java 客户端并编写以下程序：

```sql
package org.learningRedis.chapter.five;
import Redis.clients.jedis.Jedis;
import Redis.clients.jedis.Pipeline;
public class PushDataMaster {
          public static void main(String[] args) {
            PushDataMaster test = new PushDataMaster();
            test.pushData();
          }
          private void pushData() {
            Jedis jedis = new Jedis("localhost",6379);
            Pipeline pipeline = jedis.pipelined();
for(int nv=0;nv<900000;nv++){
              pipeline.sadd("MSG", ",data-"+nv);
            }
            pipeline.sync();
          }
}
```

1.  执行此命令，立即切换到从节点客户端命令提示符并执行您编写的命令。结果将类似于下图所示。它告诉我们的是，当在更改数据集的主节点中执行命令时，主节点开始缓冲这些命令并将它们发送到从节点。在我们的情况下，当我们对集合执行`SCARD`时，我们以递增的方式看到结果。![设置主节点和从节点](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/0123OS_05_07.jpg)

从节点上`SCARD`命令的结果

1.  主节点已启动，并正在执行事务命令，我们正在从从节点读取值。

+   当主节点关闭并重新启动为从节点时提升从节点为主节点：

1.  启动主节点和从节点 Redis 服务器。

1.  从您的 IDE 执行以下 Java 程序：

```sql
package org.learningRedis.chapter.five.masterslave;
import Redis.clients.jedis.Jedis;
public class MasterSlaveTest {
  public static void main(String[] args) throws InterruptedException {
    MasterSlaveTest test = new MasterSlaveTest();
    test.masterslave();
  }
  private void masterslave() throws InterruptedException {
    Jedis master = new Jedis("localhost",6379);
    Jedis slave = new Jedis("localhost",6380);
    master.append("msg", "Learning Redis");
    System.out.println("Getting message from master: " + master.get("msg"));
    System.out.println("Getting message from slave : " + slave.get("msg"));
    master.shutdown();
    slave.slaveofNoOne();
    slave.append("msg", " slave becomes the master");
    System.out.println("Getting message from slave turned master : " + slave.get("msg"));
    Thread.currentThread().sleep(20000);
    master = new Jedis("localhost",6379);
    master.slaveof("localhost", 6380);
    Thread.currentThread().sleep(20000);
    System.out.println("Getting message from master turned slave : " + master.get("msg"));
    master.append("msg", "throw some exceptions !!");
  }
}
```

1.  当程序第一次进入睡眠状态时，快速转到主节点的命令提示符并重新启动它（不要触摸从节点）。允许程序完成，输出将类似于以下图像：![设置主节点和从节点](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/0123OS_05_08.jpg)

主节点变为从节点，从节点变为主节点

1.  程序中的第二次睡眠是为了主节点与新主节点同步。

1.  当旧主节点尝试写入密钥时，它会失败，因为从节点无法写入。

1.  服务器消息，旧奴隶成为新主人时。![设置主节点和从节点](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/0123OS_05_09.jpg)

从奴隶变成主人

1.  旧主节点作为新从节点启动时的服务器消息。我们还可以看到，旧主节点重新启动时，作为从节点的第一件事是与新主节点同步并更新其数据集。![设置主节点和从节点](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/0123OS_05_10.jpg)

主节点变为从节点

1.  如果在程序中不给第二次睡眠，旧主节点将没有时间与新主节点同步，如果有客户端请求一个密钥，那么它将最终显示密钥的旧值

到目前为止，我们已经了解了 Redis 的主从能力以及在主节点关闭或从节点关闭时它的行为。我们还讨论了主节点向从节点发送数据并复制数据集。但问题仍然是，当 Redis 主节点必须向从节点发送数据时，它发送了什么？为了找出答案，让我们进行一个小实验，这将澄清幕后的活动。

### 性能模式 - 高读取

在生产环境中，当并发性高时，拥有某种策略变得很重要。采用复制模式肯定有助于在环境中分发负载。在这种模式中遵循的复制模式是向主节点写入并从从节点读取。

![性能模式 - 高读取](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/0123OS_05_11.jpg)

主节点和从节点中的复制策略

我们将运行的示例不会是之前提到的解决方案的正确复制，因为主节点和从节点将从同一台机器（我的笔记本电脑）运行。通过在同一台机器上运行主节点和从节点，我们利用了共同的内存和处理能力。此外，客户端程序也使用相同的资源。但仍然会观察到差异，因为服务器 I/O 在两个不同的端口上发生，这意味着至少有两个独立的服务器线程（Redis 是单线程服务器）处理读取请求时绑定到两个独立的套接字内存。

在生产环境中，最好是每个节点都在自己的核心上工作，因为 Redis 无法利用多核。

在这个示例中，我们将使用一个主节点和两个从节点。在第一个用例中，我们将使用主节点写入数据，并使用从节点读取数据。我们将记录仅读取所需的总时间，并将其与完全在主节点上进行读取的情况进行比较。

为了准备示例，我们需要准备环境，以下图表简要描述了这个示例的设置应该是什么。在这里请注意，所有资源都来自一台单独的机器：

![性能模式 - 高读取](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/0123OS_05_12.jpg)

示例设置

以下编写的程序可以适应之前讨论过的两种情况。要在**USECASE-1**模式下工作（从主节点写入并从主节点读取），请调用以下函数：

1.  在第一次运行中调用`test.setup()`。

1.  在第二次运行中调用`test.readFromMasterNode()`

1.  请注释以下函数调用，这将不允许**USECASE-2**运行`// test.readFromSlaveNodes();`。

要在**USECASE-2**模式下工作（从主节点写入并从两个从节点读取），请调用以下函数，但在此之前，执行`FLUSHDB`命令清理数据，或者不执行`test.setup();`函数：

1.  在第一次运行中调用`test.setup();`（可选）。

1.  在第二次运行中调用`test.readFromSlaveNodes();`

1.  请注释以下函数调用，这将不允许**USECASE-1**运行`// test.readFromMasterNode();`。

代码有三个简单的类，类的简要描述如下：

+   `MasterSlaveLoadTest`：这个类具有以下特点：

+   这是主类

+   这个类协调**USECASE-1**和**USECASE-2**的流程

+   这个类负责为**USECASE-1**和**USECASE-2**创建线程

+   以下是`MasterSlaveLoadTest`的代码：

```sql
package org.learningRedis.chapter.five.highreads;
import java.util.ArrayList;
import java.util.List;
import Redis.clients.jedis.Jedis;
public class MasterSlaveLoadTest {
  private List<Thread> threadList = new ArrayList<Thread>();
  public static void main(String[] args) throws InterruptedException {
    MasterSlaveLoadTest test = new MasterSlaveLoadTest();
    test.setup();
//make it sleep so that the master finishes writing the //values in the datastore otherwise reads will have either //null values
//Or old values.
    Thread.currentThread().sleep(40000); 
    test.readFromMasterNode();
    test.readFromSlaveNodes();
  }
  private void setup() {
    Thread pumpData = new Thread(new PumpData());
    pumpData.start();
  }
  private void readFromMasterNode() {
    long starttime = System.currentTimeMillis();
    for(int number=1;number<11;number++){
      Thread thread = new Thread(new FetchData(number,starttime,"localhost",6379));
      threadList.add(thread);
    }
    for(int number=0;number<10;number++){
      Thread thread =threadList.get(number);
      thread.start();
    }
  }
  private void readFromSlaveNodes() {
    long starttime0 = System.currentTimeMillis();
    for(int number=1;number<6;number++){
      Thread thread = new Thread(new FetchData(number,starttime0,"localhost",6381));
      threadList.add(thread);
    }
    long starttime1 = System.currentTimeMillis();
    for(int number=6;number<11;number++){
      Thread thread = new Thread(new FetchData(number,starttime1,"localhost",6380));
      threadList.add(thread);
    }
    for(int number=0;number<10;number++){
      Thread thread =threadList.get(number);
      thread.start();
    }
  }
}
```

+   `PumpData`：这个类具有以下特点：

+   这个类负责将数据推送到主节点

+   数据推送是单线程的

+   `PumpData`的代码如下：

```sql
package org.learningRedis.chapter.five.highreads;
import Redis.clients.jedis.Jedis;
public class PumpData implements Runnable {
  @Override
  public void run() {
    Jedis jedis = new Jedis("localhost",6379);
    for(int index=1;index<1000000;index++){
      jedis.append("mesasge-"+index, "my dumb value "+ index);
    }
  }
}
```

+   `FetchData`：这个类具有以下特点：

+   这个类负责从 Redis 节点中获取数据

+   这个类以多线程模式调用

+   这个类在启动时传递，因此返回的最后结果将指示执行所花费的总时间

+   `FetchData`的代码如下：

```sql
package org.learningRedis.chapter.five.highreads;
import Redis.clients.jedis.Jedis;
import Redis.clients.jedis.JedisPool;
public class FetchData implements Runnable {
  int endnumber  = 0;
  int startnumber= 0;
  JedisPool jedisPool = null;
  long starttime=0;
  public FetchData(int number, long starttime, String localhost, int port) {
    endnumber   = number*100000;
    startnumber = endnumber-100000;
    this.starttime = starttime;
    jedisPool = new JedisPool(localhost,port);
  }
  @Override
  public void run() {
    Jedis jedis = jedisPool.getResource();
    for(int index=startnumber;index<endnumber;index++){
      System.out.println("printing values for index = message"+index+" = "+jedis.get("mesasge-"+index));
      long endtime = System.currentTimeMillis();
      System.out.println("TOTAL TIME" + (endtime-starttime));
    }
  }
}
```

+   运行前面的程序几次，并取出最好和最差的记录，然后取出平均结果。在我运行的迭代中，我得到了以下结果：

+   对于 USECASE-1，平均时间为 95609 毫秒

+   对于 USECASE-2，平均时间为 72622 毫秒

+   尽管在您的机器上结果可能不同，但结果将是相似的。这清楚地表明从从节点读取并写入主节点明显更好。

### 性能模式 - 高写入

在生产环境中，当对写入的并发需求很高时，有一种策略变得很重要。复制模式确实有助于在环境中分发负载，但是当对写入的并发需求很高时，仅有复制模式是不够的。此外，在 Redis 中，从节点无法进行写入。为了使数据库中的数据写入高并发，重要的是在环境中将数据集分片到许多数据库节点上。许多数据库都具有内置的能力，可以根据需要在节点之间分片数据。除了写入的高并发性外，将数据集分片的优势在于提供部分故障容忍的机制。换句话说，即使其中一个节点宕机，它将使其中包含的数据不可用，但其他节点仍然可以处理它们持有的数据的请求。

作为数据库，Redis 缺乏在许多节点之间分片数据的能力。但是可以在 Redis 之上构建某种智能，来完成分片的工作，从而实现对 Redis 的高并发写入。整个想法是将责任从 Redis 节点中移出，并保留在一个单独的位置。

![性能模式-高写入](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/0123OS_05_13.jpg)

基于分片逻辑在节点之间分发数据

可以在 Redis 之上构建各种逻辑，用于分发写入负载。逻辑可以基于循环轮询，其中数据可以在顺序排列的节点上分发；例如，数据将会先到**M1**，然后到**M2**，然后到**M3**，依此类推。但是这种机制的问题在于，如果其中一个节点宕机，循环轮询逻辑无法考虑到丢失的节点，它将继续向有问题的节点发送数据，导致数据丢失。即使我们构建逻辑来跳过有问题的节点并将数据放入后续的节点，这种策略将导致该节点拥有自己的数据份额，并且有问题的节点的数据将迅速填满其内存资源。

一致性哈希是一种算法，可以在节点之间平均分发数据时非常有用。基本上，我们根据算法生成一个哈希，将密钥平均分布在整个可用的 Redis 服务器集合中。

Java 的 Redis 客户端已经内置了一致性哈希算法来分发写入。具体如下：

```sql
package org.learningRedis.chapter.five.sharding;
import java.util.ArrayList;
import java.util.List;
import org.apache.commons.pool.impl.GenericObjectPool.Config;
import Redis.clients.jedis.Jedis;
import Redis.clients.jedis.JedisSentinelPool;
import Redis.clients.jedis.JedisShardInfo;
import Redis.clients.jedis.ShardedJedis;
import Redis.clients.jedis.ShardedJedisPool;
public class MyShards {
  List<JedisShardInfo> shards = new ArrayList<JedisShardInfo>();
  public static void main(String[] args) {
    MyShards test = new MyShards();
    test.setup();
    test.putdata();
  }
  private void setup() {
    JedisShardInfo master0 = new JedisShardInfo("localhost", 6379);
    JedisShardInfo master1 = new JedisShardInfo("localhost", 6369);
    shards.add(master0);
    shards.add(master1);
  }
  private void putdata() {
    ShardedJedisPool pool = new ShardedJedisPool(new Config(), shards);
    for(int index=0;index<10;index++){
      ShardedJedis jedis = pool.getResource();
      jedis.set("mykey"+index, "my value is " + index);
      pool.returnResource(jedis);
    }
    for(int index=0;index<10;index++){
      ShardedJedis jedis = pool.getResource();
      System.out.println("The value for the key is "+ jedis.get("mykey"+index));
      System.out.println("The following information is from master running on port : " + jedis.getShardInfo("mykey"+index).getPort());
      pool.returnResource(jedis);
    }
  }
}
```

# Redis 中的持久化处理

Redis 提供了各种持久化数据的选项。这些机制有助于决定我们的数据需要什么样的持久化模型，这完全取决于我们想要在 Redis 中存储的数据类型。Redis 中有四种选项：

+   通过 RDB 选项进行持久化

+   通过 AOF 选项进行持久化

+   通过 AOF 和 RDB 选项的组合进行持久化

+   根本不进行持久化

让我们运行一个简单的程序，看看持久化机制的重要性，因为只有这样我们才能意识到持久化的重要性。按照步骤操作，亲自看看缺乏持久化会导致数据丢失：

1.  启动 Redis 服务器。

1.  打开 Redis 客户端命令提示符。

1.  执行命令`SET msg 'temporary value'`。

1.  手动快速关闭 Redis 服务器，可以在 Linux 中使用**Kill-9**选项，也可以在 Windows 的命令提示符中使用**close**选项。

1.  重新启动 Redis 服务器。

1.  执行命令`get msg`。

没有持久化处理的 msg

## 通过 RDB 选项进行持久化

**Redis 数据库文件**（**RDB**）是 Redis 服务器在定期间隔内持久化数据集的选项，换句话说，定期间隔内在内存中对数据进行快照。该格式是一个单一的、非常紧凑的文件，对于保留数据作为备份非常有用。在灾难发生时，该文件可以充当救命稻草，因此非常重要。Redis 服务器可以配置为在各种间隔内拍摄快照。从性能的角度来看，这种持久化数据的方式将导致更高的性能，因为 Redis 服务器将 fork 一个子进程以非阻塞的方式执行此操作。另一个优点是，由于 RDB 文件中仅存储数据集，因此在 RDB 文件的情况下，服务器的启动非常快。但是，将数据集存储在 RDB 中也有其缺点，因为如果 Redis 在两个快照之间失败，可能会发生数据丢失的可能性。如果数据集的体积非常大，可能会出现另一个问题，因为在这种情况下，Redis 服务器的 fork 子进程将花费时间来加载数据，而这段时间可能会阻塞客户端请求。在生产场景中，这个问题不会出现，因为服务器重新启动和服务器处理客户端请求之间总是有时间差的。从硬件的角度来看，具有更快处理器的机器总是可以解决问题的。

### 为 RDB 持久性配置 Redis

在这里，我们将学习如何将数据持久化到 RDB 文件中。在 Redis 中，可以通过编辑`Redis.conf`文件或通过客户端提示来配置 RDB 持久性机制。当我们打开我们的`Redis.conf`文件并转到`快照`部分时，我们会看到以下选项：

+   `Save 900 1`：如果一个键已更改，则在 15 分钟内保存

+   `Save 300 10`：如果 10 个键已更改，则在 5 分钟内保存

+   `Save 60 10000`：如果有 10,000 个键已更改，则在 1 分钟内保存

除了这些预配置的选项之外，我们还可以通过调整`Redis.conf`文件中的值来添加我们自己的选项。客户端还可以用于在运行时为数据集快照添加配置。例如，`CONFIG SET SAVE "900 2 300 10"`将设置快照为`如果 2 个键已更改，则在 15 分钟内保存`，`如果一个键已更改，则在 10 分钟内保存`，这将覆盖先前的值。

让我们运行一个简单的程序，就像之前的程序一样，我们会看到由于缺乏持久性而导致的数据丢失，我们将配置 Redis 以具有持久性机制：

1.  启动您的 Redis 服务器。

1.  打开一个 Redis 客户端命令提示符。

1.  执行命令`Set msg 'temp value'`。

1.  快速手动关闭 Redis 服务器，可以通过 Linux 中的**Kill-9**选项或 Windows 命令提示符中的**close**选项。

1.  重新启动您的 Redis 服务器。

1.  执行命令`get msg`。![为 RDB 持久性配置 Redis](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/0123OS_05_15.jpg)

没有持久性处理的获取 msg

1.  现在执行命令`CONFIG SET SAVE "60 1"`，这告诉 Redis 服务器，如果一个键已更改，则在一分钟内保存数据。

1.  执行命令`Set msg 'temp value'`。

1.  等待一分钟或去拿您最喜欢的饮料。

1.  关闭服务器。

1.  重新启动您的 Redis 服务器。

1.  打开一个新的客户端连接并执行命令`get msg`，将显示如下内容：![为 RDB 持久性配置 Redis](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/0123OS_05_16.jpg)

获取 msg RDB 持久性处理

1.  您也可以使用`save`命令，而不是等待一分钟，该命令将立即将内存中的数据推送到 RDB 文件中。

1.  将您需要注意的参数为了将数据持久化到 RDB 文件中，如下所示：

+   `dbfilename`：给出您的 RDB 文件的名称

+   `dir`：只给出 RDB 文件的路径

+   `rdbchecksum yes`：这是默认值，它在文件末尾添加 CRC64 校验和，以使其抵抗损坏，但在服务器重新启动时会有轻微的性能损失

### 使用 RDB 持久性的用例

Redis 可以在数据是无状态的情况下配置 RDB 持久化机制。我想要传达的是，如果数据是一条信息，与之前存储的数据或即将存储的数据没有关系，那么它就是 RDB 持久化的完美候选者。此外，关系可以是序列、时间、排名等，或者数据本身可以包含状态信息。例如，存储的数据是`START`、`PAUSE`、`RESUME`和`STOP`。在这种情况下，如果我们在快照期间丢失`PAUSE`或`RESUME`等数据，那么可能会使整个系统变得不稳定。

让我们来看一个使用情况，网站记录用户在浏览会话中访问的 URL。这些数据被分析以对用户行为进行个人资料化，以便为用户提供更好的服务。在这种情况下，访问的页面的 URL 与之前存储的数据或将来存储的数据没有关系，因此它没有状态。因此，即使在两个快照之间发生故障，如果丢失了一些数据，也不会影响整体分析。

另一个可以使用 RDB 持久化的使用情况是当我们想要将 Redis 用作缓存引擎时，数据写入较少，而数据读取非常频繁。

## 通过 AOF 选项进行持久化

**追加文件**（**AOF**）是在 Redis 数据存储中存储数据的持久机制。启用 AOF 后，Redis 将追加所有写入数据集的命令和相关数据，因此当 Redis 服务器重新启动时，它将重建数据集到正确的状态。这种持久性模式在存储具有状态的数据时非常有用。这是因为当我们进行状态管理或者数据集与状态相关联时，在服务器关闭的情况下，存储在内存中的信息（状态信息）将会丢失。这反过来会导致某种状态不匹配。假设我们有一条信息处于状态 A，并且随后对该信息进行的活动将其状态从 A 变为 B，从 B 变为 C，依此类推。现在从用户的角度来看，最后的状态变化将信息带入了 D 状态，这个状态原则上应该在内存中，并且在服务器关闭（崩溃）的情况下，信息将会丢失，因此状态变化信息 D 也将会丢失。因此，当服务器重新启动时，如果用户将该信息的状态更改为 E，状态变化历史将看起来像 A 到 B，B 到 C，C 到 E。在某些情况下，这可能导致数据损坏。AOF 持久化方式解决了由此可能引起的问题。

### 配置 Redis 进行 AOF 持久化

可以通过更改`Redis.conf`文件来启用 AOF。需要将属性`appendonly`设置为`yes`。通过将其设置为 true，我们告诉 Redis 记录写命令和数据到一个文件中，当服务器重新启动时，它将重新加载这些数据，使其恢复到关闭之前的状态。

Redis 提供了三种策略来缓解由不一致状态引起的问题。第一种策略是记录 AOF 文件中的每个写入事件。这种机制是最安全的，但性能不是很好。可以通过`appendfsync always`来实现这一点。

第二种机制是基于时间的，我们指示 Redis 服务器缓冲每个写入命令，并安排每秒进行一次 AOF 追加。这种技术更有效，因为它是每秒发生一次，而不是在每次写入时。可以通过告诉 Redis`appendfsync everysec`来实现这一点。在这种机制中，状态丢失的可能性非常小。

第三种机制更像是一种委托，其中将附加控制权交给底层操作服务器，以将写命令从缓冲区刷新到 AOF 文件。附加的频率是每隔几秒一次（在基于 Linux 的机器上，频率接近每 30 秒一次）。这种技术的性能是最快的，因为这是每 30 秒发生一次。然而，在这种机制中，数据丢失的机会和数量也很高。可以通过告诉 Redis `appendfsync no` 来实现这种附加方式。

让我们运行一个简单的程序，就像之前的程序一样，其中由于缺乏持久性而导致数据丢失，我们将配置 Redis 以具有 AOF 持久性机制：

1.  启动 Redis 服务器。

1.  打开 Redis 客户端命令提示符。

1.  执行命令`Set msg 'temp value'`。

1.  快速手动关闭 Redis 服务器，可以在 Linux 中使用**Kill-9**选项，或者在 Windows 命令提示符中使用**close**选项。

1.  重新启动 Redis 服务器。

1.  执行命令`get msg`。![为 AOF 持久性配置 Redis](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/0123OS_05_17.jpg)

没有持久性处理的获取消息

1.  打开您的`Redis.conf`文件，转到`APPEND ONLY MODE`部分，并将`appendonly no`更改为`appendonly yes`。

1.  取消注释`appendfilename appendonly.aof`属性。在这里，您可以选择提供自己的名称，但默认名称是`appendonly.aof`。

1.  将附加机制更改为`appendfsync always`。

1.  使用以下参数启动 Redis 服务器 `--appendonly yes --appendfilename C:\appendonly.aof`（如果不想在`Redis.conf`文件中进行更改，则使用此技术）。

1.  执行命令`Set msg 'temp value'`。

1.  快速手动关闭 Redis 服务器，可以在 Linux 中使用**Kill-9**选项，或者在 Windows 命令提示符中使用**close**选项。

1.  使用以下参数重新启动 Redis 服务器 `--appendonly yes --appendfilename C:\appendonly.aof`（如果不想在`Redis.conf`文件中进行更改，则使用此技术）。

1.  执行命令`get msg`。![为 AOF 持久性配置 Redis](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/0123OS_05_18.jpg)

使用 AOF 持久性处理获取消息

1.  从`C:\appendonly.aof`打开文件并查看以下内容：![为 AOF 持久性配置 Redis](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/0123OS_05_19.jpg)

打开`appendonly.aof`

这里可以观察到的一件事是，没有记录`get`命令，因为它们不会改变数据集。需要记住的一个问题是，如果写入非常频繁，那么 AOF 文件将变得越来越大，服务器重新启动将需要更长的时间。

### 使用 AOF 持久性的用例

Redis 可以配置为在数据是有状态时具有 AOF 持久性机制。我想在这里传达的是，如果数据是与之前存储的数据有关，或者下一个要存储的数据与之有关，那么它就成为 AOF 持久性的完美候选者。假设我们正在构建一个工作流引擎，其中每个状态都负责下一个状态；在这种情况下，使用 AOF 持久性是最佳选择。

# Redis 中的数据集处理命令

我们已经看到客户端程序使用的命令，要么设置数据，要么获取 Redis 中的数据，但是还有一些有用的命令需要处理 Redis 作为数据存储。这些命令有助于在生产环境中维护 Redis，并且通常是 Redis 管理的领域。由于这些命令对 Redis 中存储的数据产生影响，因此在执行它们时应该小心。以下是一些命令：

+   `FLUSHDB`：此命令删除所选数据库中的所有键（及其保存的数据）。正如我们所见，在 Redis 中，我们可以创建一个更像是 SILO 的数据库，可以以分离的方式存储数据（更像是关注点的分离）。此命令永远不会失败。

+   `FLUSHALL`：此命令删除 Redis 节点中所有数据库中的所有键。此命令永远不会失败。

+   `监视器`：这个命令是一个调试命令，它传递了 Redis 服务器正在处理的所有命令。您可以使用 Redis-cli 或 telnet 来监视服务器正在执行的操作。![Redis 中的数据集处理命令](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/0123OS_05_20.jpg)

使用 telnet 监视命令

在这里，我们使用 telnet 来监视 Redis 服务器，并且客户端发出的任何命令都会在这里复制。监视命令可以让我们深入了解 Redis 的工作方式，但会有性能损失。您可以使用此命令来监视从节点。

+   `SAVE`：这是一个同步阻塞调用，将内存中的所有数据保存到 RDB 文件中。在生产环境中，应谨慎使用此命令，因为它会阻塞每个客户端命令并执行此任务。

+   `BGSAVE`：这个命令更像是后台保存。之前的`SAVE`命令是一个阻塞调用，但是这个命令不会阻塞客户端调用。通过发出这个命令，Redis 会 fork 另一个进程，该进程开始在后台持久化数据到 RDB 文件中。发出此命令会立即返回`OK`代码，但客户端可以通过发出`LASTSAVE`命令来检查结果。让我们尝试一个小例子，看看它是否有效：

1.  启动 Redis 服务器和一个客户端。

1.  从客户端执行`LASTSAVE`命令；在我的情况下，它显示的值是整数**1391918354**，但在您的情况下可能显示不同的时间。

1.  打开您的 telnet 提示符并执行`MONITOR`命令（这是故意为了减缓 Redis 服务器的性能）。

1.  打开您的 Java 编辑器，并输入以下程序，它将向 Redis 服务器插入大量值：

```sql
package org.learningRedis.chapter.five;
import Redis.clients.jedis.Jedis;
public class PushLotsOfData {
  public static void main(String[] args) {
    PushLotsOfData test = new PushLotsOfData();
    test.pushData();
  }
  private void pushData() {
    Jedis jedis = new Jedis("localhost",6379);
    for(int nv=0;nv<900000;nv++){
      jedis.sadd("MSG-0", ",data-"+nv);
    }
  }
}
```

1.  在客户端提示符中，我发出了以下命令，结果如下：

![Redis 中的数据集处理命令](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/0123OS_05_21.jpg)

检查 BGSAVE 的非阻塞特性

我在`BGSAVE`命令之后发出了`TIME`命令，但当我发出`LASTSAVE`时，我得到的时间比`BGSAVE`命令晚。所以我们可以得出结论，`BGSAVE`是一种非阻塞保存数据的方式。由于`FLUSHALL`命令操作整个数据集，它在执行后会自动调用`SAVE`命令。查看`LASTSAVE`命令，显示时间为**1391920265**，以及在`FLUSHALL`之前的上一个`LASTSAVE`，显示时间为**1391920077**，证明了`FLUSHALL`确实进行了保存。

+   `LASTSAVE`：这个命令类似于`BGSAVE`命令，它显示了数据上次持久化到 RDB 文件的时间。

+   `SHUTDOWN SAVE`/`NOSAVE`：这个命令基本上退出服务器，但在这之前会关闭整个客户端集合的连接并执行一个阻塞保存，然后如果启用了 AOF，会刷新 AOF。

+   `DBSIZE`：返回数据库中键的数量。

+   `BGREWRITEAOF`：这指示 Redis 服务器启动后台写入 AOF。如果此指令失败，旧的 AOF 文件将被保留。

+   `CLIENT SETNAME`：这个命令设置客户端的名称，当我们执行`CLIENT LIST`时可以看到设置的名称。在客户端提示符中执行以下命令`CLIENT SETNAME "myclient"`，您应该看到类似以下图像的东西:![Redis 中的数据集处理命令](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/0123OS_05_22.jpg)

给客户端命名

+   `CLIENT LIST`：获取连接到 IP 地址和`PORT`地址的客户端列表。让我们做一个简单的实验：

1.  使用`telnet localhost 6379`打开到 Redis 服务器的 telnet 客户端，并执行`MONITOR`命令。

1.  打开 Redis 服务器主节点客户端提示符并执行`CLIENT LIST`命令。命令提示符应该类似于以下图像：

![Redis 中的数据集处理命令](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/0123OS_05_23.jpg)

获取客户端列表

+   `CLIENTKILL`：这个命令杀死客户端。现在，对于之前的实验，在我们打开的客户端中发出以下命令：

1.  执行命令`CLIENT KILL 127.0.0.1:1478`。

1.  执行`CLIENT LIST`命令，我们将看到显示的行数减少了一行。

+   `DEBUG sEGFAULT`：这会导致 Redis 服务器崩溃。该实用程序可用于在开发过程中模拟错误。此命令可用于模拟我们想要通过故意使 Redis 服务器宕机来检查系统的容错性的场景。有趣的是看到从节点的行为，客户端如何处理容错等。

+   `SLOWLOG`：此命令显示执行过程中哪些命令花费了时间。执行你在*性能模式 - 高读取*部分编写的程序，并在执行后打开主机的客户端并执行此命令。以下图像中所见的结果是一个快照，不是您在命令提示符中可能得到的完整结果：![Redis 中的数据集处理命令](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/0123OS_05_24.jpg)

Slowlog 命令

# 总结

在这一章中，我们看到并学习了如何在 Redis 中处理整个数据集。除此之外，我们还学习了在生产环境中提高性能的模式。我们还学习了管理 Redis 服务器生态系统的命令。

在下一章中，我们将应用我们到目前为止学到的知识来开发 Web 编程中的常见组件，并看看 Redis 如何成为解决这一领域中一些问题的强大工具。


# 第六章：Web 应用中的 Redis

在当前情况下，Web 是世界今天进行交流的普遍平台。从简单的门户到大规模可扩展的电子商务，协作网站，银行业，社交媒体，移动网络上的 Web 应用等等，每个人都使用 Web 协议作为与外部世界交互的接口。我们通常看到的 Web 平台只是 Web 操作下的一个小部分应用，后端 Web 应用，如供应链管理，订单管理，在线，离线分析等等，也是 Web 应用，或者使用 Web 协议进行集成，例如 HTTP，SOAP，REST 等等。

Web 成功的原因之一是其有效的简单性，开放标准以及多个渠道的操作。它的流行正在迫使人们和公司提出简单，成本效益高，性能卓越，易于维护和开发的解决方案。这种新型软件应该具有内在或外在的能力来扩展和表现良好。

Redis，这种更像瑞士军刀的数据存储，是多面手，是我们在前几章中看到的那些能力的证明。在本章中，我们将扩展和映射 Redis 的能力，用于 Web 领域中使用的组件，并为任何 Web 应用程序的固有部分创建一些概念验证。

为了更好地理解 Redis 的概念，让我们制作一个示例 Web 应用程序，并将 Redis 用作数据存储。这个示例 Web 应用程序无论如何都不是一个完整的端到端 Web 应用程序，但意在突出 Redis 可以派上用场的领域。解决方案本身在功能上并不完整，但意在成为一个从业者可以继续扩展的演示。

**Simple E-Commerce**，正如我们打算称呼这个演示网站，是一个由 Redis 支持的网站，它没有网页，而是通过简单的服务进行通信。这个想法是暴露简单的服务，而不是引入网页（包含 HTML，CSS 等），以将服务与呈现层解耦。随着我们更多地向单页面应用的时代迈进，我们需要采取一种方法，其中驻留在客户端浏览器内存中的应用程序进行所有协调，而传统的 Web 服务器则通过其提供的服务来处理请求。这种机制的优势在于开发和测试变得容易，因为每个服务都独立于其他服务，并且与 Web 应用程序的呈现方面没有紧密耦合。由于我们都曾经参与过 Web 开发，我们可以理解当我们看到一个错误时所面临的挫败感，以及当花费大量时间来调试问题是因为客户端代码还是它调用的业务方法。随着单页面应用程序的能力不断增强，这个问题在很大程度上可以得到解决，因为业务方法被公开为独立的服务，并且可以与呈现组件分开测试。单页面应用程序的一个显着特点是它将大量的计算活动从服务器端转移到客户端（浏览器），这导致服务器获得更多的计算资源。

# 简单的电子商务-一个由 Redis 支持的电子商务网站

这个示例电子商务网站，像其他电子商务网站一样，有产品，注册用户可以浏览，购买等等。该网站还根据用户的浏览和购买习惯推荐产品。同时，该网站实时统计网站上发生的活动，并提供实时和软实时分析的功能。因此，让我们开始构建这个网站，就像在任何设计中一样，让我们将需求分成命令，列举如下：

+   会话和目录管理：以下命令作为服务提供：

+   **注册用户**：命令名称为`register`；此命令将用户注册到系统中。

+   **查看我的数据**：命令名称为`mydata`；此命令将允许用户查看自己的数据。

+   **编辑我的数据**：命令名称为`editmydata`；此命令将允许用户编辑自己的数据。

+   **登录用户**：命令名称为`login`；此命令将登录用户并为用户生成会话 ID，以便与服务器通信。

+   **重新登录用户**：命令名称为`relogin`；此命令将再次登录用户，但会话 ID 将保持不变。用户的所有会话或配置文件数据也将保持不变。

+   **注销用户**：命令名称为`logout`；此命令将注销用户并终止其会话或配置文件数据。

+   **加入购物车**：命令名称为`add2cart`；此命令将商品添加到购物车中。

+   **查看我的购物车**：命令名称为`showmycart`；此命令将显示购物车中的商品。

+   **编辑我的购物车**：命令名称为`editcart`；此命令将编辑用户在购物车中的偏好设置。

+   **购买产品**：命令名称为`buy`；此命令将购买用户购物车中的商品。对于当前应用程序，我们不会将您带到某个商家的网站，而是为您生成一个样本收据。理念是进行分析，所以当有人购买产品时，我们为该产品提供信用积分，这将有助于我们的推荐服务。购买的信用积分为`10`。

+   **委托产品**：命令名称为`commission`；此命令将委托产品并在系统中创建其配置文件。

+   **显示产品**：命令名称为`display`；此命令将显示产品。

+   **浏览产品**：命令名称为`browse`；此命令将记录用户当前浏览的产品。理念是当有人浏览产品时，我们为该产品提供信用积分，这将有助于我们的推荐服务。浏览的信用积分为`1`。

+   **在线分析**：以下命令属于此类：

+   **推荐**：命令名称为`recommendbyproduct`；此命令将根据用户正在浏览的产品的热度推荐其他类似产品。

+   **用户统计**：命令名称为`stats`；此命令将显示用户的统计信息。

+   **按类别显示**：命令名称为`displaytag`；此命令将显示某一类别下的产品。

+   **按类别显示历史记录**：命令名称为`taghistory`；此命令将按类别显示历史记录。

+   **书籍访问量**：命令名称为`visittoday`；这将给出一天内独立访客的总数。

+   **购买书籍**：命令名称为`purchasestoday`；这将给出一天内购买该物品的独立访客总数。

为这个简单的电子商务网站保持了非常简单的设计。要了解整个应用程序，请查看以下图表：

![简单电子商务-基于 Redis 的电子商务网站](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/0123OS_06_01.jpg)

简单设计适用于我们简单的电子商务网站

此练习的先决条件如下：

+   **客户端**：任何带有`REST`插件或 HTTP 客户端插件的浏览器。我将使用带有名为`POSTMAN`的`REST`客户端插件的 Chrome 浏览器。如果您对其他插件感到满意，也可以使用其他插件。如果我们将此客户端替换为纯 Java 程序，例如 Apache Http Client，应用程序将可以正常工作。此简单电子商务应用程序中的服务是基于`Get`的。在生产系统中，我们应该使用`POST`，但出于显示目的，这里选择了`Get`。

+   **服务器**：任何 Web 应用程序服务器。我们将使用 Tomcat。您可以使用您选择的任何 Web 应用程序服务器，但应相应地创建 Servlet。如果您想使用类似 Node.js 的东西，那么代码将相应更改，但设计理念将保持不变。

+   **数据存储**：毋庸置疑，Redis 将是这里的数据存储。

在我们深入代码之前，了解导致我们使用 Redis 的演变过程是很重要的。如前所述，基于这个 Web 应用程序被分为两类，如下所述：

+   会话和目录管理

+   在线分析

让我们花点时间了解它们是如何随着时间的推移发展的，以及 Redis 是如何出现的。之后我们将了解这个应用程序的代码。

# 会话管理

每个 Web 应用程序都以某种方式具有会话。会话管理捕获用户活动的信息，这些信息可以被用户使用，也可以被用户使用。购物车或愿望清单的信息可以被用户使用，后端系统也可以使用相同的信息来分析用户偏好，并将促销和活动管理方案传递给用户。这是电子商务平台中的常见用例之一。存储在会话管理中的信息始终是最新的信息，最终用户期望围绕它进行性能，换句话说，用户将他最近的记忆外包给系统，并期望系统照顾好它。最终用户可能不知道幕后发生的详细和活动水平，但期望会话中存储的信息能够快速和高效地被处理。

在某些情况下，用户的期望甚至超出了他的大脑可以处理的范围；无论是购物车购买，还是把物品放入愿望清单，或者提醒他某个可能已经忘记的活动。换句话说，与任何其他数据相比，最终用户最接近这些数据。他们记住这些数据，并期望系统与之匹配，这导致用户与系统或网站的更个性化的参与。

![会话管理](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/0123OS_06_02.jpg)

用户及其与电子商务平台的互动

上图是用户与系统（网站）互动的表示。当用户浏览网站时，他/她知道自己在寻找什么。比如在我们的案例中，他正在寻找一些音乐，搜索音乐后，用户将音乐曲目放入购物车。用户也可能对同一流派的其他音乐 CD 感兴趣，或者对*评论部分*的其他买家的评论感兴趣。在这一点上，用户可能有兴趣购买他/她的音乐 CD，或者将其放在购物车中以便将来购买。用户在这里期望的一件事是，当他再次登录系统时，系统应该记住他放在购物车中的产品。

这里发生了几件事。首先，用户与系统互动，系统通过存储用户的选择、记录用户的活动等方式做出响应。其次，用户已经推送了他可能会感兴趣的信息，从而为他提供了广泛的选择，同时也教育他关于其他人对产品的评论，从而帮助他做出决定。在这一部分，我们将更多地讨论用户存储信息的部分，并称之为会话管理。

会话数据非常重要，留存在用户的记忆中，但这些数据的生命周期很短（直到产品交付或者注意力转移到另一个产品为止）。这就是会话管理的作用所在，在本节中，我们将深入探讨 Redis 如何帮助我们解决这个非常关键的问题。

为了处理会话数据，最早和最简单的选择是使用应用服务器本身的内存。在过去，Web 应用程序的能力有限，提供的服务也有限。使用应用服务器内存是当时的常规。但随着 Web 变得更加普及，人们开始在日常生活中更多地使用 Web，网站迅速增长，为了在 Web 应用程序之间生存下来，必须具备更多的计算和内存资源。

![会话管理](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/0123OS_06_03.jpg)

使用内存存储会话数据来扩展 Web 应用程序

常见的技术是复制数据并平衡系统，以便所有 Web 服务器处于相同状态，并且可以从任何 Web 应用程序中处理请求。这种技术存在一些问题，因为会话管理与 Web 服务器紧密耦合，它提供了有限的可扩展性，当并发性增加时，这种模式变成了反模式。这种技术的另一个局限性是，随着会话管理中的数据增长，这种模式变得有问题，因为会话数据存储在内存中，而为会话管理分配的内存量受到业务逻辑内存需求的限制。

下一个合乎逻辑的步骤是将会话管理与执行业务逻辑的 Web 应用程序服务器分离。这一步是正确的，因为现在它提供了更多的可扩展性，因为 Web 服务器不再需要进行会话管理，这需要频繁地与对等方同步状态。

![会话管理](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/0123OS_06_04.jpg)

使用 RDBMS 存储会话数据来扩展 Web 应用程序

尽管这种方法是朝着正确的方向发展的，但也存在一些问题，主要是选择使用的数据存储。RDBMS 用于存储关系数据，并且在处理这些类型的数据时非常高效。另一方面，会话数据更像是键值对，而不具有事务数据所期望的那种关系。将会话数据存储在 RDBMS 中的问题在于性能受到影响，因为 RDBMS 从未为这种类型的数据而设计，尽管 Web 应用程序服务器的扩展更加容易。

这个演进过程的下一步是使用一个既提供可扩展性又提供性能的数据存储。显而易见的选择是使用一个缓存引擎，它将信息存储在内存中，以便性能更快，可扩展性保持良好，因为会话数据与 Web 应用程序服务器分离。

![会话管理](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/0123OS_06_05.jpg)

使用缓存作为前端，通过 RDBMS 存储会话数据来扩展 Web 应用程序

这种方法的问题在于功能需求和可维护性的角度。从可维护性的角度来看，缓存引擎依赖于 RDBMS 进行数据持久化，因为大多数缓存引擎没有磁盘持久性，并依赖于 RDBMS 进行故障管理。有一些缓存引擎提供持久性机制，但从功能的角度来看，存在一个大问题，因为它们将所有内容存储为键值，其中值是一个字符串。程序的责任是将字符串数据转换为他们感兴趣的信息模式，然后取出值。例如，存储在用户配置文件中的值，其中会话数据中存储了数百个属性。如果用户想要取出一些属性，那么用户必须获取整个数据集，构造对象，然后获取所需的属性。另一个问题是，很多时候我们需要会话数据在固定的时间段内可用，之后数据的可用性就不存在了。在这种情况下，缓存引擎和 RDBMS 都不会证明有益，因为它们没有内置的数据存储的*生存时间*机制。为了实现这个功能，我们必须编写触发器来从 RDBMS 和缓存中清除数据。

Redis 在这些情况下非常方便，因为它提供了存储信息的方式，可以根据我们的需求使用数据结构来保存值。在会话管理的情况下，我们可以使用映射来逻辑地将属性分组在一起。如果我们需要取出值，我们可以选择要更改的值或向其添加更多属性。此外，Redis 中的性能方面也使其适用于会话管理。Redis 还具有称为**生存时间**（**TTL**）的功能，以在时间结束后清除数据。这样，我们可以根据需求为所需的键设置单独的 TTL，并且可以在运行时更改 TTL。Redis 可用于具有可扩展和高性能的会话管理。

![会话管理](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/0123OS_06_06.jpg)

使用缓存作为前端的 Web 应用程序扩展 RDBMS 以存储会话数据

# 目录管理

目录管理是关于网站希望提供的产品和项目的信息。目录管理下存储的信息可以是产品的成本、尺寸、颜色等，即产品的元信息。与会话信息不同，目录数据是以读为中心的。但与会话数据一样，目录数据也经历了演变，从 RDBMS 系统开始，当时由于缺乏存储数据的选择，RDBMS 系统是当时的自然选择。RDBMS 系统的问题在于它没有提供性能。此外，固定的基于模式的系统也增加了问题，因为产品的元信息随着产品本身的变化而变化。一些产品有颜色、长度、宽度和高度，而一些产品有作者、页数和 ISBN。创建适应这一需求的模式总是很麻烦，而且在某个时候我们都面临过这个问题。

![目录管理](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/0123OS_06_07.jpg)

使用 RDBMS 作为数据存储的目录管理

克服固定模式问题的自然演化过程是以 XML 格式存储信息，并将此信息缓存到某个缓存引擎中。这种机制帮助设计师和架构师克服了固定模式和性能的问题。但这种技术也带来了自己的问题；在 XML 中的数据在使用之前必须转换为编程语言对象。另一个问题是，如果要更改属性值，那么要么首先在 XML 中更改值，然后在关系数据库管理系统中更改值，要么首先在关系数据库管理系统中更改值，然后在缓存中更改值。这些技术在维护关系数据库管理系统和缓存引擎之间的一致状态方面存在问题，特别是如果属性与产品成本相关。

![目录管理](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/0123OS_06_08.jpg)

在缓存引擎和关系数据库管理系统之间处理状态管理

Redis 再次派上用场，用于存储目录数据。Redis 是无模式的，作为数据存储提供了数据结构，比如可以用来存储产品所需的许多属性的映射。除此之外，它还提供了改变、添加和读取属性的能力，而无需将整个数据集带到工作中。拥有 Redis 的另一个优势是我们无需进行*对象到数据*的转换，反之亦然，因为这消除了系统中需要数百个数据对象的必要性；从而使代码库更小，开发更快。

# 在线分析

在线分析或实时分析是一个相对较新的需求，正在变得流行。在线分析的整个理念是为用户提供更丰富和吸引人的用户体验。在线分析的工作方式是实时收集、分析和处理数据。

在早期的网络革命时代，分析只有一个主要的利益相关者，那就是网站管理团队。他们过去会在离线模式下收集数据并进行分析，然后应用于业务。离线分析技术仍然是必要的。然而，在今天的世界，当一切都与社交媒体相连时，用户的观点、他/她的社交群体和他/她的意见应该反映在他/她的购物体验中。例如，假设一个用户及其社交群体对某种音乐或书籍持有积极看法。当用户登录到他最喜欢的电子商务网站时，该网站的主页上会在推荐部分显示这种产品。这很可能会导致用户最终购买该产品。这种程度的个性化对于网站的成功非常重要。

在这种情况下发生的分析是软实时的，也就是当用户与他的社交群体互动时，数据同时被处理并创建上下文，网站利用这一上下文为用户创建个性化的购物体验。

另一种发生的分析是基于用户在网站浏览产品时创建的上下文。这种上下文的创建是协作性的，尽管用户可能对此并不知情。搜索某种产品或购买某种产品的用户数量越多，该产品就越受欢迎。这种类型的分析的复杂性在于它是实时的，性能至关重要。

从某种意义上说，如果我们将离线分析引擎与实时分析进行比较，不同之处在于，原本不属于业务逻辑范围的分析引擎实际上成为业务逻辑的一部分，实际上共享相同的计算资源。另一个不同之处在于，实时分析的数据量相对较小，但从用户的购物角度来看，它的上下文数据对于业务来说非常重要。以下图表简明地解释了离线和在线（实时）分析之间的差异：

![在线分析](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/0123OS_06_09.jpg)

Web 应用程序中的离线和在线分析

现在，如果要使用 RDBMS 等数据存储来进行实时处理，问题将在于性能，因为这种处理将消耗大量的计算资源，并且并行执行的其他业务用例可能会受到影响。例如，Oracle 等 RDBMS 可以提供扩展的能力，但它们的价格相当昂贵。

Redis 可以是一个非常好的数据存储，可以用于在线分析。由于 Redis 是基于内存的，它非常快速，并且在 Redis 中实现可伸缩性要容易得多。此外，Redis 提供了诸如 Set 和 Sorted set 之类的数据结构，对于实时分析来说非常有帮助。

Redis 提供的另一个优势是它是开源的，而且 Redis 的运行时资源需求非常少。此外，Redis 在处理并发调用方面的能力非常令人印象深刻。

在我们将开发的示例应用程序中，我们将看到一些实时分析，例如基于其流行度推荐产品的推荐引擎。

## 实施-简单的电子商务

让我们从一些代码开始，以便清楚地了解如何使用 Redis 进行会话、目录管理和在线分析。但在这之前，让我们确定要创建的存储数据的桶：

+   “<username>@userdata”桶：该桶将存储用户配置文件数据，例如姓名、电子邮件、电话号码、地址等。从应用程序的角度来看，这个桶将是用户的`sessionID`，它将把这个桶与`"<sessionID>@sessiondata"`绑定在一起。这里使用的数据结构是 Map。

+   “<sessionID>@sessiondata”桶：该桶将存储用户的会话数据，例如上次登录和登录状态。除了会话数据，这里还将存储用户名，因为这是将`"<username>@userdata"`桶绑定到该桶的关键。这里使用的数据结构是 Map。

+   “<sessionID>@browsinghistory”桶：该桶将根据用户的会话 ID 存储用户的浏览历史。这里使用的数据结构是 Sorted Set。

+   “<name>@purchasehistory”桶：这将提供用户的购买历史。这里使用的数据结构是 Sorted Set。

+   “<sessionID>@shoppingcart”桶：该桶将存储用户的购物车项目。这里使用的数据结构是 Map。

+   “sessionIdTracker”桶：这将跟踪系统中的用户总数。这里使用的数据结构是 Bitmap。

+   “<productname>”桶：这将存储产品属性。由于无模式，它可以存储产品的任意数量的属性。这里使用的数据结构是 Map。

+   “<tags>”桶：这将存储与该标签相关联的产品。例如，“学习 Redis”可以被标记为 Redis、NoSQL、数据库等标签。这里使用的数据结构是 Sorted Set。

+   “<productname>@visit”桶：这将存储独立访问者的数量。在生产系统中，这可以每天进行一次，以便统计每天有多少人访问了该产品，并帮助计算每月有多少人访问了该网站。这里使用的数据结构是 Bitmap。

+   **Bucket name "<productname>@purchase"**：这将存储购买产品的独立访问者数量。与之前的桶一样，可以每天制作这个桶，以便为一周或一个月提供聚合计数。这里使用的数据结构是位图。

现在我们已经了解了我们的数据库将会是什么样子，让我们来看看将要接受来自浏览器的服务请求并向客户端发送 HTTP 响应的 servlet。

在这个简单的电子商务网站中有两个 servlet。它们将接受所有命令，并列在下面：

+   **UserApp servlet**：这将处理与用户相关的所有命令

+   **ProductApp servlet**：这将处理与用户相关的所有命令

我们必须记住的一件事是，执行的顺序不依赖于 servlet 或 servlet 中的命令的顺序。例如，除非我们在系统中提供了一些产品，否则注册或登录是没有意义的，或者除非我们浏览或购买了一些产品，否则查看推荐是没有意义的，因为这将为推荐创建图形数据。

让我们先了解一下在本章节的其余部分中将在代码清单中使用的所有实用类。所有这些类的列表如下：

+   **Commands**：这是所有将在应用程序中实现的命令的父类和抽象类：

```sql
package org.learningRedis.web;
import org.learningRedis.web.util.Argument;
public abstract class Commands {
  private Argument argument;
  public Commands(Argument argument) {
    this.argument = argument;
  }
  public abstract String execute();
  public Argument getArgument() {
    return argument;
  }
}
```

+   **默认命令**：这是默认命令，如果 URL 中传递的命令未被应用程序识别，将会执行该命令：

```sql
package org.learningRedis.web;
import org.learningRedis.web.util.Argument;
public class DefaultCommand extends Commands {
  public DefaultCommand(Argument argument) {
    super(argument);
  }
  @Override
  public String execute() {
    return "Command Not Recognized !!";
  }
}
```

+   **Argument**：这个类的主要目标是封装请求中传入的所有名称值属性，并将其放入一个地图中，以便以后在程序中使用：

```sql
package org.learningRedis.web.util;
import java.util.HashMap;
import java.util.Map;
public class Argument {
  Map<String, String> argumentMap = new HashMap<String, String>();
  public Argument(String args) {
    String[] arguments = args.split(":");
    for (String argument : arguments) {
      String key = argument.split("=")[0];
      String value = argument.split("=")[1];
      argumentMap.put(key, value);
    }
  }
  public String getValue(String key) {
    return argumentMap.get(key);
  }
  public Map<String, String> getAttributes() {
    return argumentMap;
  }
}
```

现在我们已经涵盖了应用程序中的所有实用类，让我们来看看将对应用程序形成的类。

## ProductApp

ProductApp servlet 将包含围绕产品管理的命令。ProductApp servlet 的代码如下：

```sql
package org.learningRedis.web;
import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.learningRedis.web.analytics.commands.PurchasesCommand;
import org.learningRedis.web.analytics.commands.VisitTodayCommand;
import org.learningRedis.web.productmgmt.commands.CommissionProductCommand;
import org.learningRedis.web.productmgmt.commands.DisplayTagCommand;
import org.learningRedis.web.productmgmt.commands.DisplayCommand;
import org.learningRedis.web.productmgmt.commands.TagHistoryCommand;
import org.learningRedis.web.productmgmt.commands.UpdateTagCommand;
import org.learningRedis.web.util.Argument;
public class ProductApp extends HttpServlet {
  public ProductApp() {
    super();
  }
  protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    String command = request.getParameter("command");
    Argument argument = new Argument(request.getParameter("args"));
    PrintWriter out = response.getWriter();
    switch (command.toLowerCase()) {
    case "commission":
      Commands commission = new CommissionProductCommand(argument);
      out.println(commission.execute());
      break;
    case "display":
      Commands display = new DisplayCommand(argument);
      out.println(display.execute());
      break;
    case "displaytag":
      Commands displaytag = new DisplayTagCommand(argument);
      out.println(displaytag.execute());
      break;
    case "updatetag":
      Commands updatetag = new UpdateTagCommand(argument);
      out.println(updatetag.execute());
      break;
    case "visitstoday":
      Commands visittoday = new VisitTodayCommand(argument);
      out.println(visittoday.execute());
      break;
    case "purchasestoday":
      Commands purchasestoday = new PurchasesTodayCommand (argument);
      out.println(purchasestoday.execute());
      break;
    case "taghistory":
      Commands taghistory = new TagHistoryCommand(argument);
      out.println(taghistory.execute());
      break;
    default:
      Commands defaultUC = new DefaultCommand(argument);
      out.println(defaultUC.execute());
      break;
    }
  }
}
```

现在我们已经准备好了第一个 servlet，让我们来看看我们为此实现的命令：

+   `CommisionProductCommand`：这将实现`委托`命令。命令的实现如下：

```sql
package org.learningRedis.web.productmgmt.commands;
import java.util.Map;
import org.learningRedis.web.Commands;
import org.learningRedis.web.util.Argument;
import org.learningRedis.web.util.ProductDBManager;
public class CommissionProductCommand extends Commands {
    public CommissionProductCommand(Argument argument) {
    super(argument);
  }
  @Override
  public String execute() {
    System.out.println(this.getClass().getSimpleName() + ":  " + " Entering the execute function");
    Map<String, String> productAttributes = this.getArgument().getAttributes();
    boolean commisioning_result = ProductDBManager.singleton.commisionProduct(productAttributes);
    boolean tagging_result = ProductDBManager.singleton.enterTagEntries(productAttributes.get("name"),
        productAttributes.get("tags"));
    if (commisioning_result & tagging_result) {
      return "commisioning successful";
    } else {
      return "commisioning not successful";
    }
  }
}
```

测试 URL：`http://localhost:8080/simple-ecom/productApp?command=commission&args=name=Redisbook-1:cost=10:catagory=book:author=vinoo:tags=Redis@5,NoSql@3,database@2,technology@1`。

描述：出于所有原因，这应该是第一个应该调用的命令，因为这个命令将在系统中提供产品。需要关注 URL 中的两个部分，即等于`commission`的`command`和`args`部分。这里`args`包含书的属性，例如`name=Redisbook-1`。属性`tags`表示书将关联的单词。这本书的标签是`Redis@5`，`NoSQl@3`，`database@2`和`technology@1`。标签与权重相关，当推荐引擎启动时，权重将发挥作用。每当用户浏览`Redisbook-1`时，他将看到更多关于 Redis 书籍的推荐。在这里，用户将看到关于 Redis 的五本书，关于 NoSQL 的三本书，依此类推。为了简化这个应用程序，权重的总和应该是 10。

![ProductApp](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/0123OS_06_10.jpg)

成功产品委托的截图

为了创建测试数据，使用不同权重委托几本测试书籍，其中一些具有相同的标签，另一些具有略有不同的标签。确保权重的总和等于 10。

+   `显示命令`：这将实现`显示`命令。命令的实现如下：

```sql
package org.learningRedis.web.productmgmt.commands;
import org.learningRedis.web.Commands;
import org.learningRedis.web.util.Argument;
import org.learningRedis.web.util.ProductDBManager;
public class DisplayCommand extends Commands {
  public DisplayCommand(Argument argument) {
    super(argument);
  }
  @Override
  public String execute() {
    String display = ProductDBManager.singleton.getProductInfo(this.getArgument().getValue("name"));
    return display;
  }
}
```

测试 URL：`http://localhost:8080/simple-ecom/productApp?command=display&args=name=Redisbook-1`。

描述：该程序将显示书的属性。需要关注 URL 中的两个部分，即等于显示的命令和参数部分，即 args。这里，args 包含一个名为 name 的属性。

![ProductApp](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/0123OS_06_11.jpg)

成功显示产品属性的屏幕截图

+   `DisplayTagCommand`：这将实现`browse`命令。命令的实现如下：

```sql
package org.learningRedis.web.productmgmt.commands;
import org.learningRedis.web.Commands;
import org.learningRedis.web.util.Argument;
import org.learningRedis.web.util.ProductDBManager;
public class DisplayTagCommand extends Commands {
  public DisplayTagCommand(Argument argument) {
    super(argument);
  }
  @Override
  public String execute() {
    System.out.println(this.getClass().getSimpleName() + ":  " + " Entering the execute function");
    String tagName = this.getArgument().getValue("tagname");
    String details = ProductDBManager.singleton.getTagValues(tagName);
    return details;
  }
}
```

测试 URL：`http://localhost:8080/simple-com/productApp?command=displaytag&args=tagname=nosql`。

描述：该程序将根据书的点击量显示书籍。需要关注 URL 中的两个部分，即`command`，等于`displaytag`，以及参数部分，即`args`。这里`args`包含一个名为`tagname`的属性。由于我已经将一本书委托给系统，输出如下图所示。当用户开始浏览产品时，请稍后访问此标签；当您执行相同的命令时，顺序将发生变化。

![ProductApp](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/0123OS_06_12.jpg)

成功显示属于 NoSQL 标签的产品的屏幕截图

+   `UpdateTag`：这将实现`UpdateTagCommand`命令。命令的实现如下：

```sql
package org.learningRedis.web.productmgmt.commands;
import org.learningRedis.web.Commands;
import org.learningRedis.web.util.AnalyticsDBManager;
import org.learningRedis.web.util.Argument;
import org.learningRedis.web.util.ProductDBManager;
public class UpdateTagCommand extends Commands {
  public UpdateTagCommand(Argument argument) {
    super(argument);
  }
  @Override
  public String execute() {
    System.out.println(this.getClass().getSimpleName() + ":  " + " Entering the execute function");
    String sessionid = this.getArgument().getValue("sessionid");
    String productname = this.getArgument().getValue("productname");
    String details = this.getArgument().getValue("details");
    String actionType = this.getArgument().getValue("action");
    switch (actionType.toLowerCase()) {
    case "browse":
      if (productname != null & ProductDBManager.singleton.keyExist(productname)) {
        AnalyticsDBManager.singleton.updateRatingInTag(productname, 1);
        AnalyticsDBManager.singleton.updateProductVisit(sessionid, productname);
      }
      break;
    case "buy":
      System.out.println("Buying the products in the shopping cart !! ");
      String[] products = details.split(",");
      for (String product : products) {
        if (product != null & !product.trim().equals("")) {
          AnalyticsDBManager.singleton.updateRatingInTag(product, 10);
          AnalyticsDBManager.singleton.updateProductPurchase(sessionid, product);
        }
      }
      break;
    default:
      System.out.println("The URL cannot be acted uppon  ");
      break;
    }
    return "";
  }
}
```

测试 URL：`http://localhost:8080/simple-ecom/productApp?command=updatetag&args=sessionid=<用户的 sessionID>:productname=<用户正在浏览或已购买的产品名称>:action=<浏览或购买>`。

描述：当用户浏览产品或购买产品时，将调用此命令。该命令背后的想法是，当用户浏览产品或购买产品时，该产品正在变得受欢迎，因此，该产品在同一标签下的其他产品中的受欢迎程度应该相应增加。简而言之，它有助于计算其类别（标签）中最受欢迎的产品。要测试此命令，请确保创建一些虚拟用户并使其登录系统，然后点击`browse`命令 URL 或`buy`命令 URL。

+   `VisitTodayCommand`：这将实现`browse`命令。命令的实现如下：

```sql
package org.learningRedis.web.analytics.commands;
import org.learningRedis.web.Commands;
import org.learningRedis.web.util.AnalyticsDBManager;
import org.learningRedis.web.util.Argument;
public class VisitTodayCommand extends Commands {
  public VisitTodayCommand(Argument argument) {
    super(argument);
  }
  @Override
  public String execute() {
    System.out.println(this.getClass().getSimpleName() + ":  " + "Entering the execute function");
    String productName = this.getArgument().getValue("productname");
    Integer visitCount = AnalyticsDBManager.singleton.getVisitToday(productName);
    System.out.println(this.getClass().getSimpleName() + ":  " + "Printing the result for execute function");
    System.out.println("Result = " + "Total Unique Visitors are: " + visitCount.toString());
    return "Total Unique Visitors are: " + visitCount.toString();
  }
}
```

测试 URL：`http://localhost:8080/simple-ecom/productApp?command=visitstoday&args=productname=Redisbook-1`。

描述：如果我们想要检查有多少独立用户访问了该产品，可以执行此命令。实现此用例的数据结构是位图。 Redis 中的位图具有一致的性能，不受其持有的数据影响。

![ProductApp](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/0123OS_06_13.jpg)

显示产品 redisbook-1 每天的观看者总数的屏幕截图

+   `PurchasesTodayCommand`：这将实现`purchasestoday`命令。命令的实现如下：

```sql
package org.learningRedis.web.analytics.commands;
import org.learningRedis.web.Commands;
import org.learningRedis.web.util.Argument;
import org.learningRedis.web.util.ProductDBManager;
public class PurchasesTodayCommand extends Commands {
  public PurchasesTodayCommand(Argument argument) {
    super(argument);
  }
  @Override
  public String execute() {
    System.out.println(this.getClass().getSimpleName() + ":  " + "Entering the execute function");
    String productName = this.getArgument().getValue("productname");
    Integer purchaseCount = ProductDBManager.singleton.getPurchaseToday(productName);
    System.out.println(this.getClass().getSimpleName() + ":  " + "Printing the result for execute function");
    System.out.println("Result = " + "Total Unique Customers are: " + purchaseCount.toString());
    return "Total Unique Customers are: " + purchaseCount.toString();
  }
}
```

测试 URL：`http://localhost:8080/simple-ecom/productApp?command=purchasestoday&args=productname=Redisbook-1`。

描述：如果我们想要检查有多少独立用户购买了给定的产品，可以执行此命令。实现此用例的数据结构是位图。 Redis 中的位图具有一致的性能，不受其持有的数据影响。

![ProductApp](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/0123OS_06_14.jpg)

显示产品 redisbook-1 每天的买家总数的屏幕截图

+   `TagHistoryCommand`：这将实现`browse`命令。命令的实现如下：

```sql
package org.learningRedis.web.productmgmt.commands;
import org.learningRedis.web.Commands;
import org.learningRedis.web.util.AnalyticsDBManager;
import org.learningRedis.web.util.Argument;
public class TagHistoryCommand extends Commands {
  public TagHistoryCommand(Argument argument) {
    super(argument);
  }
  @Override
  public String execute() {
    String tagname = this.getArgument().getValue("tagname");
    String tagHistory = AnalyticsDBManager.singleton.getTagHistory(tagname);
    return tagHistory;
    }
    }
```

测试 URL：`http://localhost:8080/simple-ecom/productApp?command=taghistory&args=tagname=Redis`。

描述：如果我们想要查看产品的标签历史记录，可以执行此命令。产品的排名基于属于该标签的各个产品积累的积分。在以下示例中，我们显示了标签`Redis`的排名：

![ProductApp](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/0123OS_06_15.jpg)

显示标签 redis 的标签历史的屏幕截图

测试 URL：`http://localhost:8080/simple-ecom/productApp?command=taghistory&args=tagname=nosql`。

描述：如果我们想要查看产品的标签历史记录，可以执行此命令。产品的排名基于属于该标签的各个产品积累的积分。在以下示例中，我们展示了标签`nosql`的排名以展示差异：

![ProductApp](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/0123OS_06_16.jpg)

显示标签`nosql`的历史记录的屏幕截图

## UserApp

UserApp servlet 将包含围绕用户管理和用户分析的命令。UserApp servlet 的代码如下：

```sql
package org.learningRedis.web;
import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.learningRedis.web.analytics.commands.MyStatusCommand;
import org.learningRedis.web.analytics.commands.RecomendByProduct;
import org.learningRedis.web.sessionmgmt.commands.Add2CartCommand;
import org.learningRedis.web.sessionmgmt.commands.BrowseCommand;
import org.learningRedis.web.sessionmgmt.commands.BuyCommand;
import org.learningRedis.web.sessionmgmt.commands.EditCartCommand;
import org.learningRedis.web.sessionmgmt.commands.EditMyDataCommand;
import org.learningRedis.web.sessionmgmt.commands.LoginCommand;
import org.learningRedis.web.sessionmgmt.commands.LogoutCommand;
import org.learningRedis.web.sessionmgmt.commands.MyDataCommand;
import org.learningRedis.web.sessionmgmt.commands.MyPurchaseHistory;
import org.learningRedis.web.sessionmgmt.commands.RegistrationCommand;
import org.learningRedis.web.sessionmgmt.commands.ReloginCommand;
import org.learningRedis.web.sessionmgmt.commands.ShowMyCartCommand;
import org.learningRedis.web.util.Argument;
public class UserApp extends HttpServlet {
  private static final long serialVersionUID = 1L;
  public UserApp() {
    super();
  }
  protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    String command = request.getParameter("command");
    Argument argument = new Argument(request.getParameter("args"));
    PrintWriter out = response.getWriter();
    switch (command.toLowerCase()) {
    case "register":
      Commands register = new RegistrationCommand(argument);
      out.println(register.execute());
      break;
    case "login":
      Commands login = new LoginCommand(argument);
      out.println(login.execute());
      break;
    case "mydata":
      Commands mydata = new MyDataCommand(argument);
      out.println(mydata.execute());
      break;
    case "editmydata":
      Commands editMyData = new EditMyDataCommand(argument);
      out.println(editMyData.execute());
      break;
    case "recommendbyproduct":
      Commands recommendbyproduct = new RecomendByProductCommand (argument);
      String recommendbyproducts = recommendbyproduct.execute();
      out.println(recommendbyproducts);
      break;
    case "browse":
      Commands browse = new BrowseCommand(argument);
      String result = browse.execute();
      out.println(result);
      String productname = argument.getValue("browse");
      String sessionid = argument.getValue("sessionid");
      request.getRequestDispatcher(
          "/productApp?command=updatetag&args=sessionid=" + sessionid + ":productname=" + productname
              + ":action=browse").include(request, response);
      break;
    case "buy":
      Commands buy = new BuyCommand(argument);
      String[] details = buy.execute().split("#");
      out.println(details[0]);
      String sessionID = argument.getValue("sessionid");
      request.getRequestDispatcher(
          "/productApp?command=updatetag&args=sessionid=" + sessionID + ":action=buy:details=" + details[1])
          .include(request, response);
      break;
    case "stats":
      Commands stats = new MyStatusCommand(argument);
      out.println(stats.execute());
      break;
    case "add2cart":
      Commands add2cart = new Add2CartCommand(argument);
      out.println(add2cart.execute());
      break;
    case "showmycart":
      Commands showmycart = new ShowMyCartCommand(argument);
      out.println(showmycart.execute());
      break;
    case "editcart":
      Commands editCard = new EditCartCommand(argument);
      out.println(editCard.execute());
      break;
    case "relogin":
      Commands relogin = new ReloginCommand(argument);
      out.println(relogin.execute());
      break;
    case "logout":
      Commands logout = new LogoutCommand(argument);
      out.println(logout.execute());
      break;
    case "mypurchasehistory":
      Commands mypurchasehistory = new MyPurchaseHistoryCommand (argument);
      out.println(mypurchasehistory.execute());
      break;
    default:
      Commands defaultUC = new DefaultCommand(argument);
      out.println(defaultUC.execute());
      break;
    }
  }
}
```

现在我们已经准备好了第一个 servlet，让我们来看看我们为此实现的命令：

+   `RegistrationCommand`：这将实现`register`命令。命令的代码如下：

```sql
package org.learningRedis.web.sessionmgmt.commands;
import org.learningRedis.web.Commands;
import org.learningRedis.web.util.Argument;
import org.learningRedis.web.util.UserDBManager;
public class RegistrationCommand extends Commands {
  public RegistrationCommand(Argument argument) {
    super(argument);
  }
  public String execute() {
    System.out.println(this.getClass().getSimpleName() + ":  " + " Entering the execute function");
    String name = this.getArgument().getValue("name");
    if (!UserDBManager.singleton.doesUserExist(name)) {
      UserDBManager.singleton.createUser(this.getArgument().getAttributes());
    } else {
      return "user already registered in ";
    }
    return "successful registeration  -> " + name;
  }
}
```

测试 URL：`http://localhost:8080/simple-ecom/userApp?command=register&args=name=vinoo:password=******:address=test address`。

描述：此命令将用户注册到系统中。需要关注 URL 中的两个部分，即`command`，等于`register`，以及参数部分，即`args`。这代表了键值对中的属性。下图表示注册成功的情况。下一个逻辑步骤将是登录用户。

![UserApp](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/0123OS_06_17.jpg)

显示用户注册的屏幕截图

+   `LoginCommand`：这将实现`login`命令。命令的代码如下：

```sql
package org.learningRedis.web.sessionmgmt.commands;
import java.util.HashMap;
import java.util.Map;
import org.learningRedis.web.Commands;
import org.learningRedis.web.util.AnalyticsDBManager;
import org.learningRedis.web.util.Argument;
import org.learningRedis.web.util.ProductDBManager;
import org.learningRedis.web.util.UserDBManager;
public class LoginCommand extends Commands {
  public LoginCommand(Argument argument) {
    super(argument);
  }
  @Override
  public String execute() {
    System.out.println(this.getClass().getSimpleName() + ":  " + " Entering the execute function");
    String name = this.getArgument().getValue("name");
    String password = this.getArgument().getValue("password");
    if (UserDBManager.singleton.doesUserExist(name)) {
      if (UserDBManager.singleton.getUserPassword(name).equals(password)
          & UserDBManager.singleton.getUserSessionId(name).equals("null")) {
        String sessionID = ProductDBManager.getRandomSessionID();
        UserDBManager.singleton.login(sessionID, name);
        Map<String, String> map = new HashMap<String, String>();
        map.put("sessionID", sessionID);
        UserDBManager.singleton.setRegistrationMap(name, map);
        System.out.println("login map : " + map);
        AnalyticsDBManager.singleton.registerInSessionTracker(sessionID);
        return "Login successful \n" + name + " \n use the following session id : " + sessionID;
      } else if (UserDBManager.singleton.getUserPassword(name).equals(password)
          & !UserDBManager.singleton.getUserSessionId(name).equals("null")) {
        return " Login failed ...u r already logged in \n please logout to login again \n or try relogin command ";
      } else {
        return " Login failed ...invalid password ";
      }
    } else {
      return " please register before executing command for login ";
    }
  }
}
```

测试 URL：`http://localhost:8080/simple-ecom/userApp?command=login&args=name=vinoo:password=******`。

描述：此命令将用户登录到系统中。需要关注 URL 中的两个部分，即`command`，等于`login`，以及参数部分，即`args`。参数将包含名称和密码。需要关注的重要部分是，执行此命令将返回一个会话 ID 代码。大多数用户将执行的命令都需要此会话 ID。因此，如果您正在运行此命令的示例，请确保将此数字存储在文本文件中以供以后使用。在生产系统中，可以将其存储在浏览器或客户端的内存中。下图告诉我为我生成的会话 ID 是**26913441**。我将在执行的其余示例中使用它：

![UserApp](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/0123OS_06_18.jpg)

显示用户登录和用户会话 ID 的屏幕截图

+   `MyDataCommand`：这将实现`mydata`命令。命令的代码如下：

```sql
package org.learningRedis.web.sessionmgmt.commands;
import java.util.Map;
import org.learningRedis.web.Commands;
import org.learningRedis.web.util.Argument;
import org.learningRedis.web.util.UserDBManager;
public class MyDataCommand extends Commands {
  public MyDataCommand(Argument argument) {
    super(argument);
  }
  @Override
  public String execute() {
    System.out.println(this.getClass().getSimpleName() + ":  " + " Entering the execute function");
    String sessionid = this.getArgument().getValue("sessionid");
    String name = UserDBManager.singleton.getUserName(sessionid);
    Map<String, String> map = UserDBManager.singleton.getRegistrationMap(name);
    return map.toString();
  }
}
```

测试 URL：`http://localhost:8080/simple-ecom/userApp?command=mydata&args=sessionid=26913441`。

描述：此命令将显示系统中用户的数据。需要关注 URL 中的两个部分，即`command`，等于`mydata`，以及参数部分，即`args`。参数在 URL 中只有会话 ID 作为键值对。下图显示了命令的结果。由于某些属性无法在图中显示，因此未显示。

![UserApp](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/0123OS_06_19.jpg)

显示用户数据的屏幕截图

+   `EditMyDataCommand`：这将实现`editmydata`命令。命令的代码如下：

```sql
package org.learningRedis.web.sessionmgmt.commands;
import java.util.Map;
import org.learningRedis.web.Commands;
import org.learningRedis.web.util.Argument;
import org.learningRedis.web.util.UserDBManager;
public class EditMyDataCommand extends Commands {
  public EditMyDataCommand(Argument argument) {
    super(argument);
  }
  @Override
  public String execute() {
    System.out.println(this.getClass().getSimpleName() + ":  " + " Entering the execute function");
    Map<String, String> editMap = this.getArgument().getAttributes();
    boolean result = UserDBManager.singleton.editRegistrationMap(editMap);
    if (result) {
      return "Edit is Done....";
    } else {
      return "Edit not Done.... please check sessionid and name combination";
    }
  }
}
```

测试 URL：`http://localhost:8080/simple-ecom/userApp?command=editmydata&args=name=vinoo:password=******:address=changed address:phone=9111111119:sessionid=26913441`。

描述：此命令将显示系统中用户的数据。需要关注 URL 中的两个部分，即`command`，等于`mydata`，以及参数部分，即`args`。参数具有新的和编辑后的键值对。确保 URL 中的会话 ID 是正确的。下图是您应该在输出中看到的内容。现在您可以随时返回并执行以前的`mydata`命令，这将显示更新后的值。

![UserApp](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/0123OS_06_20.jpg)

成功编辑用户数据的屏幕截图

+   `BrowseCommand`：这将实现`browse`命令。命令的实现如下：

```sql
package org.learningRedis.web.sessionmgmt.commands;
import org.learningRedis.web.Commands;
import org.learningRedis.web.util.AnalyticsDBManager;
import org.learningRedis.web.util.Argument;
import org.learningRedis.web.util.ProductDBManager;
public class BrowseCommand extends Commands {
  public BrowseCommand(Argument argument) {
    super(argument);
  }
  @Override
  public String execute() {
    System.out.println(this.getClass().getSimpleName() + ":  " + " Entering the execute function");
    String productname = this.getArgument().getValue("browse");
    if (ProductDBManager.singleton.keyExist(productname)) {
      AnalyticsDBManager.singleton.updateBrowsingHistory(this.getArgument().getValue("sessionid"), productname);
      StringBuffer stringBuffer = new StringBuffer();
      stringBuffer.append("You are browsing the following product = " + productname + "\n");
      stringBuffer.append(ProductDBManager.singleton.getProductInfo(productname));
      return stringBuffer.toString();
    } else {
      return "Error: The product you are trying to browse does not exist i.e. " + productname;
    }
  }
}
```

测试 URL：`http://localhost:8080/simple-ecom/userApp?command=browse&args=sessionid=26913441:browse=Redisbook-1`。

描述：此命令将显示系统中产品的数据。需要关注的 URL 中的两个部分是`command`，它等于`browse`，以及参数部分，即`args`。参数包含用户的会话 ID 和用户正在浏览的产品的名称。这里发生了几件事情。用户可以查看产品详情，同时后台会发送请求到`updatetag`命令，以增加相应产品的热度。在我们的案例中，产品是`Redisbook-1`。为了测试，多次浏览您已经委托到系统中的所有产品。

![UserApp](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/0123OS_06_21.jpg)

用户想要浏览产品并查看其详情时的屏幕截图

+   `RecommendByProductCommand`：这将实现`recommendbyproduct`命令。命令的代码如下：

```sql
package org.learningRedis.web.analytics.commands;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.learningRedis.web.Commands;
import org.learningRedis.web.util.AnalyticsDBManager;
import org.learningRedis.web.util.Argument;
import org.learningRedis.web.util.ProductDBManager;
public class RecomendByProductCommand extends Commands {
  int totalrecomendations = 10;
  public RecomendByProductCommand(Argument argument) {
    super(argument);
  }
  @Override
  public String execute() {
    System.out.println(this.getClass().getSimpleName() + ":  " + " Entering the execute function");
    StringBuffer buffer = new StringBuffer();
    String productname = this.getArgument().getValue("productname");
    buffer.append("If you are lookinging into " + productname + " you might also find the following \n");
    buffer.append("products interseting... \n");
    Map<String, Integer> tags = ProductDBManager.singleton.getProductTags(productname);
    // Lets get total sum of weights
    int totalweight = 0;
    Set<String> keys = tags.keySet();
    for (String key : keys) {
      totalweight = totalweight + tags.get(key);
    }
    for (String key : keys) {
      int slotfortag = Math.round(totalrecomendations * tags.get(key) / totalweight);
      List<String> productnames = AnalyticsDBManager.singleton.getTopProducts(slotfortag, key);
      for (String product : productnames) {
        if (!product.equals(productname)) {
          buffer.append("For tag = " + key + " the recomended product is " + product);
          buffer.append("\n");
        }
      }
    }
    System.out.println(this.getClass().getSimpleName() + ":  " + "Printing the result for execute function");
    System.out.println("Result = " + buffer.toString());
    return buffer.toString();
  }
}
```

测试 URL：`http://localhost:8080/simple-ecom/userApp?command=recommendbyproduct&args=sessionid=26913441:productname=Redisbook-1`。

描述：此命令将基于正在浏览的产品为用户推荐产品。需要关注的 URL 中的两个部分是`command`，它等于`recommendbyproduct`，以及参数部分，即`args`。参数包含用户的会话 ID 和产品`Redisbook-1`。

该命令将基于产品的购买和浏览历史为用户推荐热门产品。这将考虑产品所属的类别以及需要考虑产品展示的权重。这在用户浏览产品时是实时在线分析的一种方式。在图中，最大数量的结果是`Redis`标签，因为该标签具有最大权重。在生产中，需要对可能出现相似产品的重复结果进行一些过滤。这种过滤可以在客户端完成，从而节省服务器端的计算资源。

![UserApp](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/0123OS_06_22.jpg)

用户想要浏览产品并查看其他推荐产品时的屏幕截图

+   `Add2CartCommand`：这将实现`add2cart`命令。命令的实现如下：

```sql
package org.learningRedis.web.sessionmgmt.commands;
import java.util.HashMap;
import java.util.Map;
import org.learningRedis.web.Commands;
import org.learningRedis.web.util.Argument;
import org.learningRedis.web.util.ShoppingCartDBManager;
import org.learningRedis.web.util.UserDBManager;
public class Add2CartCommand extends Commands {
  public Add2CartCommand(Argument argument) {
    super(argument);
  }
  @Override
  public String execute() {
    System.out.println(this.getClass().getSimpleName() + ":  " + " Entering the execute function");
    String result = "did not update the shopping cart";
    String sessionid = this.getArgument().getValue("sessionid");
    String product = this.getArgument().getValue("product");
    String[] productList = product.split(",");
    Map<String, String> productQtyMap = new HashMap<String, String>();
    for (String _product : productList) {
      String[] nameQty = _product.split("@");
      productQtyMap.put(nameQty[0], nameQty[1]);
    }
    if (UserDBManager.singleton.doesSessionExist(sessionid)) {
      result = ShoppingCartDBManager.singleton.addToShoppingCart(sessionid, productQtyMap);
    }
    return "Result : " + result;
  }
}
```

测试 URL：`http://localhost:8080/simple-ecom/userApp?command=add2cart&args=sessionid=26913441:product=Redisbook-1@2,Redisbook-4@1`。

描述：此命令将产品及其数量放入购物车。需要关注的 URL 中的两个部分是`command`，它等于`add2cart`，以及参数部分，即`args`。参数包含两个键值对。第一个是会话 ID，第二个是产品的名称和数量，用特殊字符`@`分隔。以下图显示了我已成功将产品添加到购物车中：

![UserApp](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/0123OS_06_23.jpg)

用户想要将产品添加到购物车时的屏幕截图

+   `ShowMyCartCommand`：这将实现`showmycart`命令。命令的实现如下：

```sql
package org.learningRedis.web.sessionmgmt.commands;
import java.util.Map;
import java.util.Set;
import org.learningRedis.web.Commands;
import org.learningRedis.web.util.Argument;
import org.learningRedis.web.util.ShoppingCartDBManager;
public class ShowMyCartCommand extends Commands {
  public ShowMyCartCommand(Argument argument) {
    super(argument);
  }
  @Override
  public String execute() {
    System.out.println(this.getClass().getSimpleName() + ":  " + " Entering the execute function");
    String sessionid = this.getArgument().getValue("sessionid");
    Map<String, String> productMap = ShoppingCartDBManager.singleton.myCartInfo(sessionid);
    StringBuffer stringBuffer = new StringBuffer();
    if (!productMap.isEmpty()) {
      stringBuffer.append("Your shopping cart contains the following : ");
      stringBuffer.append("\n");
      Set<String> set = productMap.keySet();
      int i = 1;
      for (String str : set) {
        stringBuffer.append("[" + i + "] product name = " + str + " Qty = " + productMap.get(str) + "\n");
        i++;
      }
      return stringBuffer.toString();
    } else {
      return " your shopping cart is empty.";
    }
  }
}
```

测试 URL：`http://localhost:8080/simple-ecom/userApp?command=showmycart&args=sessionid=26913441`。

描述：此命令将产品及其数量放入购物车。需要关注的 URL 中的两个部分是`command`，它等于`showmycart`，以及参数部分，即`args`。参数只包含会话 ID。以下图显示了我的购物车：

![UserApp](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/0123OS_06_24.jpg)

用户想要查看他的购物车时的屏幕截图

+   `EditCartCommand`：这将实现`editcart`命令。命令的实现如下：

```sql
package org.learningRedis.web.sessionmgmt.commands;
import java.util.HashMap;
import java.util.Map;
import org.learningRedis.web.Commands;
import org.learningRedis.web.util.Argument;
import org.learningRedis.web.util.ShoppingCartDBManager;
import org.learningRedis.web.util.UserDBManager;
public class EditCartCommand extends Commands {
  public EditCartCommand(Argument argument) {
    super(argument);
  }
  @Override
  public String execute() {
    System.out.println(this.getClass().getSimpleName() + ":  " + " Entering the execute function");
    String result = "did not edit the shopping cart";
    String sessionID = this.getArgument().getValue("sessionid");
    String product = this.getArgument().getValue("product");
    String[] productList = product.split(",");
    Map<String, String> productQtyMap = new HashMap<String, String>();
    for (String _product : productList) {
      String[] nameQty = _product.split("@");
      productQtyMap.put(nameQty[0], nameQty[1]);
    }
    if (UserDBManager.singleton.doesSessionExist(sessionID)) {
      result = ShoppingCartDBManager.singleton.editMyCart(sessionID, productQtyMap);
    }
    return "result : " + result;
  }
}
```

测试 URL：`http://localhost:8080/simple-ecom/userApp?command=editcart&args=sessionid=26913441:product=Redisbook-4@0,Redisbook-2@1`。

描述：此命令将编辑购物车中的产品和它们的数量。需要关注 URL 中的两个部分，一个是`command`，等于`editcart`，另一个是参数部分，即`args`。参数包含产品及其新数量的键值对。如果数量标记为`0`，则产品将从购物车中移除。再次执行`showmycart`命令，购物车应该反映出更新的值。以下图显示了更新的值：

![UserApp](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/0123OS_06_25.jpg)

用户在编辑购物车后想要查看购物车的屏幕截图

+   `BuyCommand`：这将实现`browse`命令。命令的实现如下：

```sql
package org.learningRedis.web.sessionmgmt.commands;
import org.learningRedis.web.Commands;
import org.learningRedis.web.util.Argument;
import org.learningRedis.web.util.ShoppingCartDBManager;
public class BuyCommand extends Commands {
  public BuyCommand(Argument argument) {
    super(argument);
  }
  @Override
  public String execute() {
    System.out.println(this.getClass().getSimpleName() + ":  " + " Entering the execute function");
    String sessionid = this.getArgument().getValue("sessionid");
    String shoppingdetails = ShoppingCartDBManager.singleton.buyItemsInTheShoppingCart(sessionid);
    return shoppingdetails;
  }
}
```

测试 URL：`http://localhost:8080/simple-ecom/userApp?command=buy&args=sessionid=26913441`。

描述：此命令将购买购物车中的产品。由于这是一个演示网站，与支付网关没有连接，但拥有此命令的意图是在进行购买时增加“点击”计数器。购买产品时，推荐引擎的点数会增加 10 个，而在浏览产品时只增加 1 个：

![UserApp](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/0123OS_06_26.jpg)

进行虚拟购买

此时，回顾`recommendbyproduct`命令将会非常有趣。产品显示的顺序会改变，因为每次购买都会给产品的受欢迎程度增加 10 个点。`recommendbyproduct`是针对产品`Redisbook-1`的。测试 URL 如下：`http://localhost:8080/simple-ecom/userApp?command=recommendbyproduct&args=sessionid=26913441:productname=Redisbook-1`。

![UserApp](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/0123OS_06_27.jpg)

成功购买后重新排列产品列表的屏幕截图（在线分析）

+   `MyStatusCommand`：这将实现`stats`命令。命令的实现如下：

```sql
package org.learningRedis.web.analytics.commands;
import java.util.Iterator;
import java.util.Set;
import org.learningRedis.web.Commands;
import org.learningRedis.web.util.AnalyticsDBManager;
import org.learningRedis.web.util.Argument;
import org.learningRedis.web.util.UserDBManager;
public class MyStatusCommand extends Commands {
  public MyStatusCommand(Argument argument) {
    super(argument);
  }
  @Override
  public String execute() {
    System.out.println(this.getClass().getSimpleName() + ":  " + "Entering the execute function");
    String sessionID = this.getArgument().getValue("sessionid");
    if (UserDBManager.singleton.doesSessionExist(sessionID)) {
      Set<String> browsingHistory = AnalyticsDBManager.singleton.getBrowsingHistory(sessionID);
      StringBuffer buffer = new StringBuffer();
      buffer.append(" View your browsing history where the one on top is the least visited product");
      buffer.append("\n and the product at the bottom is the most frequented product ");
      buffer.append("\n");
      Iterator<String> iterator = browsingHistory.iterator();
      int i = 1;
      while (iterator.hasNext()) {
        buffer.append("[" + i + "] " + iterator.next() + "\n");
        i++;
      }
      System.out.println(this.getClass().getSimpleName() + ":  " + "Printing the result for execute function");
      System.out.println("Result = " + buffer.toString());
      return buffer.toString();
    } else {
      return "history is not available";
    }
  }
}
```

测试 URL：`http://localhost:8080/simple-ecom/userApp?command=stats&args=sessionid=26913441`。

描述：此命令将给出用户的浏览历史。结果将根据用户重新访问特定产品的频率列出。需要关注 URL 中的两个部分，一个是`command`，等于`stats`，另一个是参数部分，即`args`。参数包含用户的会话 ID。以下图表示了具有会话 ID **26913441** 的用户的浏览历史：

![UserApp](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/0123OS_06_28.jpg)

查看用户的浏览历史的屏幕截图

+   `MyPurchaseHistoryCommand`：这将实现`mypurchasehistory`命令。命令的实现如下：

```sql
package org.learningRedis.web.sessionmgmt.commands;
import java.util.List;
import org.learningRedis.web.Commands;
import org.learningRedis.web.util.AnalyticsDBManager;
import org.learningRedis.web.util.Argument;
public class MyPurchaseHistoryCommand extends Commands {
  public MyPurchaseHistoryCommand(Argument argument) {
    super(argument);
  }
  @Override
  public String execute() {
    System.out.println(this.getClass().getSimpleName() + ":  " + " Entering the execute function");
    StringBuffer report = new StringBuffer();
    String sessionid = this.getArgument().getValue("sessionid");
    List<String> purchasehistory = AnalyticsDBManager.singleton.getMyPurchaseHistory(sessionid);
    report.append("Your purchase history is as follows : \n");
    int i = 0;
    for (String purchase : purchasehistory) {
      report.append("[" + i + "] You purchased " + purchase);
      report.append("\n");
      i++;
    }
    return report.toString();
  }
}
```

测试 URL：`http://localhost:8080/simple-ecom/userApp?command=mypurchasehistory&args=sessionid=26913441`。

描述：此命令将给出用户的购买历史。结果将根据用户购买特定产品的日期列出。需要关注 URL 中的两个部分，一个是`command`，等于`stats`，另一个是参数部分，即`args`。参数是用户的会话 ID：

![UserApp](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/0123OS_06_29.jpg)

查看用户的购买历史的屏幕截图

+   `ReloginCommand`：这将实现`relogin`命令。命令的实现如下：

```sql
package org.learningRedis.web.sessionmgmt.commands;
import org.learningRedis.web.Commands;
import org.learningRedis.web.util.Argument;
import org.learningRedis.web.util.UserDBManager;
public class ReloginCommand extends Commands {
  public ReloginCommand(Argument argument) {
    super(argument);
  }
  @Override
  public String execute() {
    System.out.println(this.getClass().getSimpleName() + ":  " + " Entering the execute function");
    String name = this.getArgument().getValue("name");
    String password = this.getArgument().getValue("password");
    if (UserDBManager.singleton.doesUserExist(name)) {
      if (UserDBManager.singleton.getUserPassword(name).equals(password)) {
        String sessionID = UserDBManager.singleton.getUserSessionId(name);
        return "ReLogin successful \n" + name + " \n use the following session id : " + sessionID;
      } else {
        return " ReLogin failed ...invalid password ";
      }
    } else {
      return " please register before executing command for login ";
    }
  }
}
```

测试 URL：`http://localhost:8080/simple-ecom/userApp?command=relogin&args=name=vinoo:password=******`。

描述：此命令将再次检查用户和用户的密码，并返回用户关联的会话 ID。想要有一个会话，可以存在用户的许多购物和浏览会话。

+   `LogoutCommand`：这将实现`logout`命令。命令的实现如下：

```sql
package org.learningRedis.web.sessionmgmt.commands;
import org.learningRedis.web.Commands;
import org.learningRedis.web.util.Argument;
import org.learningRedis.web.util.UserDBManager;
public class LogoutCommand extends Commands {
  public LogoutCommand(Argument argument) {
    super(argument);
  }
  @Override
  public String execute() {
    System.out.println(this.getClass().getSimpleName() + ":  " + " Entering the execute function");
    String sessionid = this.getArgument().getValue("sessionid");
    if (UserDBManager.singleton.expireSession(sessionid)) {
      return "logout was clean";
    } else {
      return "logout was not clean";
    }
  }
}
```

测试 URL：`http://localhost:8080/simple-ecom/userApp?command=logout&args=sessionid=26913441`。

描述：此命令将登出用户系统，并根据会话 ID 删除用户的所有数据存储，如购买历史记录、购物车和浏览历史记录。

现在我们已经掌握了命令，让我们来看看这个包，它将负责管理连接和其他与 Redis 的功能调用。

## RedisDBManager

这个类是这个应用程序的支撑，它负责与数据库连接和管理连接池。它还有一些实用功能。实现如下代码片段所示：

```sql
package org.learningRedis.web.util;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import Redis.clients.jedis.Jedis;
import Redis.clients.jedis.JedisPool;
public class RedisDBManager {
  private static Date date = new Date();
  private static int minimum = 1;
  private static int maximum = 100000000;
  // going with the default pool.
  private static JedisPool connectionPool = new JedisPool("localhost", 6379);
  public Jedis getConnection() {
    return connectionPool.getResource();
  }
  public void returnConnection(Jedis jedis) {
    connectionPool.returnResource(jedis);
  }
  public static String getDate() {
    DateFormat dateFormat = new SimpleDateFormat("dd-MM-yyyy");
    String dateValue = dateFormat.format(date);
    return dateValue;
  }
  public static String getRandomSessionID() {
    int randomNum = minimum + (int) (Math.random() * maximum);
    return new Integer(randomNum).toString();
  }
}
```

## ProductDBManager

这个类扩展了`RedisDBManager`，负责向数据库发出与产品相关的功能调用。该类的实现如下：

```sql
package org.learningRedis.web.util;
import java.util.ArrayList;
import java.util.BitSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import Redis.clients.jedis.Jedis;
public class ProductDBManager extends RedisDBManager {
  private ProductDBManager() {
  }
  public static ProductDBManager singleton = new ProductDBManager();
  public boolean commisionProduct(Map<String, String> productAttributes) {
    Jedis jedis = this.getConnection();
    String productCreationResult = jedis.hmset(productAttributes.get("name"), productAttributes);
    if (productCreationResult.toLowerCase().equals("ok")) {
      this.returnConnection(jedis);
      return true;
    } else {
      this.returnConnection(jedis);
      return false;
    }
  }
  public boolean enterTagEntries(String name, String string) {
    Jedis jedis = this.getConnection();
    String[] tags = string.split(",");
    boolean boolResult = false;
    List<String> tagList = new ArrayList<String>();
    for (String tag : tags) {
      String[] tagAndRating = tag.split("@");
      tagList.add(tagAndRating[0]);
    }
    for (String tag : tagList) {
      long result = jedis.zadd(tag.toLowerCase(), 0, name);
      if (result == 0) {
        break;
      } else {
        boolResult = true;
      }
    }
    this.returnConnection(jedis);
    return boolResult;
  }
  public String getProductInfo(String name) {
    Jedis jedis = this.getConnection();
    Map<String, String> map = jedis.hgetAll(name);
    StringBuffer stringBuffer = new StringBuffer();
    stringBuffer.append("Following are the product attributes for  " + name);
    stringBuffer.append("\n");
    Set<String> keys = map.keySet();
    int i = 1;
    for (String key : keys) {
      stringBuffer.append("[" + i + "] . " + key + " value : " + map.get(key));
      stringBuffer.append("\n");
      i++;
    }
    this.returnConnection(jedis);
    return stringBuffer.toString();
  }
  public String getTagValues(String tagName) {
    Jedis jedis = this.getConnection();
    StringBuffer stringBuffer = new StringBuffer();
    Set<String> sortedTagList = jedis.zrange(tagName.toLowerCase(), 0, 10000);
    stringBuffer.append("The following products are listed as per the hit rate \n");
    int i = 1;
    for (String tagname : sortedTagList) {
      stringBuffer.append(" [" + i + "] " + tagname + "\n");
      i++;
    }
    this.returnConnection(jedis);
    return stringBuffer.toString();
  }
  public boolean keyExist(String keyName) {
    Jedis jedis = this.getConnection();
    boolean result = jedis.exists(keyName);
    this.returnConnection(jedis);
    return result;
  }
  public int getPurchaseToday(String productName) {
    Jedis jedis = this.getConnection();
    if (jedis.get(productName + "@purchase:" + getDate()) != null) {
      BitSet users = BitSet.valueOf(jedis.get(productName + "@purchase:" + getDate()).getBytes());
      this.returnConnection(jedis);
      return users.cardinality();
    } else {
      this.returnConnection(jedis);
      return 0;
    }
  }
  public Map<String, Integer> getProductTags(String productname) {
    Jedis jedis = this.getConnection();
    String producttags = jedis.hget(productname, "tags");
    Map<String, Integer> map = new HashMap<String, Integer>();
    String[] tagAndweights = producttags.split(",");
    for (String tagAndWeight : tagAndweights) {
      map.put(tagAndWeight.split("@")[0], new Integer(tagAndWeight.split("@")[1]));
    }
    this.returnConnection(jedis);
    return map;
  }
}
```

## AnalyticsDBManager

这个类扩展了`RedisDBManager`，负责向数据库发出与分析相关的功能调用。该类的实现如下：

```sql
package org.learningRedis.web.util;
import java.util.ArrayList;
import java.util.BitSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import Redis.clients.jedis.Jedis;
public class AnalyticsDBManager extends RedisDBManager {
  private AnalyticsDBManager() {
  }
  public static AnalyticsDBManager singleton = new AnalyticsDBManager();
  public void registerInSessionTracker(String sessionID) {
    Jedis jedis = this.getConnection();
    Long sessionvalue = new Long(sessionID);
    jedis.setbit("sessionIdTracker", sessionvalue, true);
    this.returnConnection(jedis);
  }
  public void updateBrowsingHistory(String sessionID, String productname) {
    Jedis jedis = this.getConnection();
    jedis.zincrby(sessionID + "@browsinghistory", 1.0, productname);
    this.returnConnection(jedis);
  }
  public Set<String> getBrowsingHistory(String sessionID) {
    Jedis jedis = this.getConnection();
    Set<String> range = jedis.zrange(sessionID + "@browsinghistory", 0, 1000000);
    this.returnConnection(jedis);
    return range;
  }
  public int getVisitToday(String productName) {
    Jedis jedis = this.getConnection();
    if (jedis.get(productName + "@visit:" + getDate()) != null) {
      BitSet users = BitSet.valueOf(jedis.get(productName + "@visit:" + getDate()).getBytes());
      this.returnConnection(jedis);
      return users.cardinality();
    } else {
      this.returnConnection(jedis);
      return 0;
    }
  }
  public void updateProductVisit(String sessionid, String productName) {
    Jedis jedis = this.getConnection();
    jedis.setbit(productName + "@visit:" + getDate(), new Long(sessionid), true);
    this.returnConnection(jedis);
  }
  public void updateProductPurchase(String sessionid, String productName) {
    Jedis jedis = this.getConnection();
    jedis.setbit(productName + "@purchase:" + getDate(), new Long(sessionid), true);
    this.returnConnection(jedis);
  }
  public void updateRatingInTag(String productname, double rating) {
    Jedis jedis = this.getConnection();
    String string = jedis.hget(productname, "tags");
    String[] tags = string.split(",");
    List<String> tagList = new ArrayList<String>();
    for (String tag : tags) {
      String[] tagAndRating = tag.split("@");
      tagList.add(tagAndRating[0]);
    }
    for (String tag : tagList) {
      jedis.zincrby(tag.toLowerCase(), rating, productname);
    }
    this.returnConnection(jedis);
  }
  public List<String> getMyPurchaseHistory(String sessionid) {
    Jedis jedis = this.getConnection();
    String name = jedis.hget(sessionid + "@sessiondata", "name");
    List<String> purchaseHistory = jedis.lrange(name + "@purchasehistory", 0, 100);
    this.returnConnection(jedis);
    return purchaseHistory;
  }
  public String getTagHistory(String tagname) {
    Jedis jedis = this.getConnection();
    Set<String> sortedProductList = jedis.zrange(tagname.toLowerCase(), 0, 10000);
    StringBuffer stringBuffer = new StringBuffer();
    stringBuffer.append("The following products are listed as per the hit rate \n");
    int i = 1;
    for (String productname : sortedProductList) {
      stringBuffer.append(" [" + i + "] " + productname + " and the score is "
          + jedis.zscore(tagname.toLowerCase(), productname) + "\n");
      i++;
    }
    this.returnConnection(jedis);
    return stringBuffer.toString();
  }
  public List<String> getTopProducts(int slotfortag, String tag) {
    Jedis jedis = this.getConnection();
    Set<String> sortedProductList = jedis.zrevrange(tag.toLowerCase(), 0, 100000000);
    List<String> topproducts = new ArrayList<String>();
    Iterator<String> iterator = sortedProductList.iterator();
    int index = 0;
    while (iterator.hasNext()) {
      if (index <= slotfortag) {
        topproducts.add(iterator.next());
        index++;
      } else {
        break;
      }
    }
    this.returnConnection(jedis);
    return topproducts;
  }
}
```

## ShoppingCartDBManager

这个类扩展了`RedisDBManager`，负责向数据库发出与购物车相关的功能调用。实现如下：

```sql
package org.learningRedis.web.util;
import java.util.Map;
import java.util.Set;
import Redis.clients.jedis.Jedis;
public class ShoppingCartDBManager extends RedisDBManager {
  private ShoppingCartDBManager() {
  }
  public static ShoppingCartDBManager singleton = new ShoppingCartDBManager();
  public String addToShoppingCart(String sessionid, Map<String, String> productQtyMap) {
    Jedis jedis = this.getConnection();
    String result = jedis.hmset(sessionid + "@shoppingcart", productQtyMap);
    this.returnConnection(jedis);
    return result;
  }
  public Map<String, String> myCartInfo(String sessionid) {
    Jedis jedis = this.getConnection();
    Map<String, String> shoppingcart = jedis.hgetAll(sessionid + "@shoppingcart");
    this.returnConnection(jedis);
    return shoppingcart;
  }
  public String editMyCart(String sessionID, Map<String, String> productQtyMap) {
    Jedis jedis = this.getConnection();
    String result = "";
    if (jedis.exists(sessionID + "@shoppingcart")) {
      Set<String> keySet = productQtyMap.keySet();
      for (String key : keySet) {
        if (jedis.hexists(sessionID + "@shoppingcart", key)) {
          Integer intValue = new Integer(productQtyMap.get(key)).intValue();
          if (intValue == 0) {
            jedis.hdel(sessionID + "@shoppingcart", key);
          } else if (intValue > 0) {
            jedis.hset(sessionID + "@shoppingcart", key, productQtyMap.get(key));
          }
        }
      }
      result = "Updated the shopping cart for user";
    } else {
      result = "Could not update the shopping cart for the user !! ";
    }
    this.returnConnection(jedis);
    return result;
  }
  public String buyItemsInTheShoppingCart(String sessionid) {
    Jedis jedis = this.getConnection();
    Map<String, String> cartInfo = jedis.hgetAll(sessionid + "@shoppingcart");
    Set<String> procductNameList = cartInfo.keySet();
    StringBuffer stringBuffer = new StringBuffer();
    stringBuffer.append("RECEIPT: You have purchased the following \n");
    stringBuffer.append("-----------------------------------" + "\n");
    int i = 1;
    for (String productname : procductNameList) {
      String unitCost = jedis.hget(productname, "cost");
      int unitCostValue = new Integer(unitCost).intValue();
      String quantity = cartInfo.get(productname);
      int quantityValue = new Integer(quantity).intValue();
      stringBuffer.append("[" + i + "] Name of item : " + productname + " and quantity was : " + quantity
          + " the total cost is = " + quantityValue * unitCostValue + "\n");
      i++;
    }
    stringBuffer.append("-----------------------------------------");
    stringBuffer.append("#");
    for (String productname : procductNameList) {
      stringBuffer.append(productname);
      stringBuffer.append(",");
    }
    // Update the user purchase history:
    String name = jedis.hget(sessionid + "@sessiondata", "name");
    for (String productname : procductNameList) {
      jedis.lpush(name + "@purchasehistory", productname + " on " + getDate());
    }
    this.returnConnection(jedis);
    return stringBuffer.toString();
  }
}
```

## UserCartDBManager

这个类扩展了`RedisDBManager`，负责向数据库发出与用户相关的功能调用。实现如下：

```sql
package org.learningRedis.web.util;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import Redis.clients.jedis.Jedis;
public class UserDBManager extends RedisDBManager {
  private UserDBManager() {
  }
  public static UserDBManager singleton = new UserDBManager();
  public String getUserName(String sessionID) {
    Jedis jedis = this.getConnection();
    String name = jedis.hget(sessionID + "@sessiondata", "name");
    this.returnConnection(jedis);
    return name;
  }
  public void createUser(Map<String, String> attriuteMap) {
    Jedis jedis = this.getConnection();
    Map<String, String> map = attriuteMap;
    map.put("creation-time", new Date().toString());
    map.put("sessionID", "null");
    jedis.hmset(attriuteMap.get("name") + "@userdata", map);
    this.returnConnection(jedis);
  }
  public Map<String, String> getRegistrationMap(String name) {
    Jedis jedis = this.getConnection();
    Map<String, String> attributeMap = new HashMap<String, String>();
    attributeMap = jedis.hgetAll(name + "@userdata");
    this.returnConnection(jedis);
    return attributeMap;
  }
  public boolean doesUserExist(String name) {
    Jedis jedis = this.getConnection();
    String value = jedis.hget(name + "@userdata", "name");
    this.returnConnection(jedis);
    if (value == null) {
      return false;
    } else if (value != null & value.equals(name)) {
      return true;
    } else {
      return false;
    }
  }
  public void setRegistrationMap(String name, Map<String, String> attributeMap) {
    Jedis jedis = this.getConnection();
    jedis.hmset(name + "@userdata", attributeMap);
    this.returnConnection(jedis);
  }
  public String getUserPassword(String name) {
    Jedis jedis = this.getConnection();
    String password = jedis.hget(name + "@userdata", "password");
    this.returnConnection(jedis);
    return password;
  }
  public void login(String sessionID, String name) {
    Jedis jedis = this.getConnection();
    Map<String, String> loginMap = new HashMap<String, String>();
    loginMap.put("LastLogin", new Date().toString());
    loginMap.put("loginstatus", "LoggedIn");
    loginMap.put("sessionID", sessionID);
    loginMap.put("name", name);
    jedis.hmset(sessionID + "@sessiondata", loginMap);
    this.returnConnection(jedis);
  }
  public boolean editRegistrationMap(Map<String, String> editMap) {
    Jedis jedis = this.getConnection();
    if (jedis.hget(editMap.get("name") + "@userdata", "sessionID").equals(editMap.get("sessionid"))) {
      jedis.hmset(editMap.get("name") + "@userdata", editMap);
      this.returnConnection(jedis);
      return true;
    } else {
      this.returnConnection(jedis);
      return false;
    }
  }
  public String getUserSessionId(String name) {
    Jedis jedis = this.getConnection();
    String sessionID = jedis.hget(name + "@userdata", "sessionID");
    this.returnConnection(jedis);
    return sessionID;
  }
  public boolean expireSession(String sessionid) {
    // Get name from session data structure
    Jedis jedis = this.getConnection();
    String name = jedis.hget(sessionid + "@sessiondata", "name");
    // remove session id from userdata
    if (name != null) {
      Long sessionvalue = new Long(jedis.hget(name + "@userdata", "sessionID"));
      jedis.hset(name + "@userdata", "sessionID", "null");
      // remove session data : use TTL
      if (jedis.exists(sessionid + "@sessiondata")) {
        jedis.expire(sessionid + "@sessiondata", 1);
      }
      // remove browsing history : use TTL
      if (jedis.exists(sessionid + "@browsinghistory")) {
        jedis.expire(sessionid + "@browsinghistory", 1);
      }
      // remove shopping cart : use TTL
      if (jedis.exists(sessionid + "@shoppingcart")) {
        jedis.expire(sessionid + "@shoppingcart", 1);
      }
      // make the value at offset as '0'
      jedis.setbit("sessionIdTracker", sessionvalue, false);
      this.returnConnection(jedis);
      return true;
    } else {
      this.returnConnection(jedis);
      return false;
    }
  }
  public boolean doesSessionExist(String sessionid) {
    Jedis jedis = this.getConnection();
    if (jedis.hexists(sessionid + "@sessiondata", "name")) {
      this.returnConnection(jedis);
      return true;
    } else {
      this.returnConnection(jedis);
      return false;
    }
  }
}
```

# 总结

因此，在本章中，我们学习了如何使用 Redis 作为其支撑构建一个简单的电子商务网站。此外，我们还学习了 Redis 如何在进行在线分析时变得方便。这个示例网站缺乏我们在之前章节中学到的可扩展性功能。我建议读者将这种能力添加到这个代码库中作为一种练习，并且享受这个令人敬畏的数据存储。

在下一章中，我将透露如何在业务应用程序中使用 Redis，并制作一些在所有业务应用程序中常用的应用程序。
