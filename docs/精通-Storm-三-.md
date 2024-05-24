# 精通 Storm（三）

> 原文：[`zh.annas-archive.org/md5/5A2D98C1AAE9E2E2F9D015883F441239`](https://zh.annas-archive.org/md5/5A2D98C1AAE9E2E2F9D015883F441239)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：Storm 和 Hadoop 集成

到目前为止，我们已经看到了 Storm 如何用于开发实时流处理应用程序。一般来说，这些实时应用程序很少单独使用；它们更常用于与其他批处理操作结合使用。

开发批处理作业的最常见平台是 Apache Hadoop。在本章中，我们将看到如何使用 Apache Storm 构建的应用程序可以借助 Storm-YARN 框架在现有的 Hadoop 集群上进行部署，以优化资源的使用和管理。我们还将介绍如何通过在 Storm 中创建一个 HDFS bolt 来将处理数据写入 HDFS。

在本章中，我们将涵盖以下主题：

+   Apache Hadoop 及其各个组件概述

+   设置 Hadoop 集群

+   将 Storm 拓扑写入 HDFS 以持久化数据

+   Storm-YARN 概述

+   在 Hadoop 上部署 Storm-YARN

+   在 Storm-YARN 上运行 storm 应用程序。

# Hadoop 简介

Apache Hadoop 是一个用于开发和部署大数据应用程序的开源平台。最初是在 Yahoo!上开发的，基于 Google 发布的 MapReduce 和 Google 文件系统论文。在过去几年里，Hadoop 已成为旗舰大数据平台。

在本节中，我们将讨论 Hadoop 集群的关键组件。

# Hadoop 通用

这是其他 Hadoop 模块基于的基本库。它提供了一个操作系统和文件系统操作的抽象，使得 Hadoop 可以部署在各种平台上。

# Hadoop 分布式文件系统

通常被称为**HDFS**，**Hadoop 分布式文件系统**是一种可扩展的、分布式的、容错的文件系统。HDFS 充当了 Hadoop 生态系统的存储层。它允许在 Hadoop 集群中的各个节点之间共享和存储数据和应用程序代码。

在设计 HDFS 时，做出了以下关键假设：

+   它应该可以部署在一组廉价硬件的集群上。

+   硬件故障是预期的，它应该能够容忍这些故障。

+   它应该可扩展到数千个节点。

+   它应该针对高吞吐量进行优化，即使牺牲延迟。

+   大多数文件都会很大，因此应该针对大文件进行优化。

+   存储是廉价的，因此使用复制来保证可靠性。

+   它应该具有位置感知能力，以便对数据请求的计算可以在实际数据所在的物理节点上执行。这将导致较少的数据移动，从而降低网络拥塞。

一个 HDFS 集群有以下组件。

# Namenode

Namenode 是 HDFS 集群中的主节点。它负责管理文件系统的元数据和操作。它不存储任何用户数据，只存储集群中所有文件的文件系统树。它还跟踪文件的块的物理位置。

由于 namenode 将所有数据保存在 RAM 中，因此应该部署在具有大量 RAM 的机器上。此外，不应该在托管 namenode 的机器上托管其他进程，以便所有资源都专门用于它。

Namenode 是 HDFS 集群中的单点故障。如果 namenode 死机，HDFS 集群上将无法进行任何操作。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-storm/img/00054.jpeg)

图 1：HDFS 集群

# Datanode

Datanode 负责在 HDFS 集群中存储用户数据。在 HDFS 集群中可以有多个 datanode。Datanode 将数据存储在托管 datanode 的系统上的物理磁盘上。不建议将 datanode 数据存储在 RAID 配置的磁盘上，因为 HDFS 通过在 datanode 之间复制数据来实现数据保护。

# HDFS 客户端

HDFS 客户端是一个客户端库，可用于与 HDFS 集群交互。它通常与 namenode 通信，执行元操作，如创建新文件等，而 datanodes 提供实际的数据读写请求。

# 次要名称节点

辅助 namenode 是 HDFS 中命名不当的组件之一。尽管它的名字是这样，但它并不是 namenode 的备用。要理解它的功能，我们需要深入了解 namenode 的工作原理。

Namenode 将文件系统元数据保存在主内存中。为了持久性，它还将这些元数据以镜像文件的形式写入本地磁盘。当 namenode 启动时，它读取这个 fs 镜像快照文件，以重新创建内存数据结构来保存文件系统数据。文件系统的任何更新都会应用到内存数据结构，但不会应用到镜像中。这些更改会被写入称为编辑日志的单独文件中。当 namenode 启动时，它将这些编辑日志合并到镜像中，以便下次重新启动将会很快。在生产环境中，由于 namenode 不经常重新启动，编辑日志可能会变得非常大。这可能导致 namenode 在重新启动时启动时间非常长。

辅助 namenode 负责将 namenode 的编辑日志与镜像合并，以便下次 namenode 启动更快。它从 namenode 获取镜像快照和编辑日志，然后将它们合并，然后将更新后的镜像快照放在 namenode 机器上。这减少了 namenode 在重新启动时需要进行的合并量，从而减少了 namenode 的启动时间。

以下截图展示了辅助 namenode 的工作原理：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-storm/img/00055.jpeg)

图 2：辅助 Namenode 的功能

到目前为止，我们已经看到了 Hadoop 的存储部分。接下来我们将看一下处理组件。

# YARN

YARN 是一个集群资源管理框架，它使用户能够向 Hadoop 集群提交各种作业，并管理可伸缩性、容错性、作业调度等。由于 HDFS 提供了大量数据的存储层，YARN 框架为编写大数据处理应用程序提供了所需的基础设施。

以下是 YARN 集群的主要组件。

# ResourceManager（RM）

ResourceManager 是 YARN 集群中应用程序的入口点。它是集群中负责管理所有资源的主进程。它还负责调度提交到集群的各种作业。这种调度策略是可插拔的，用户可以根据需要支持新类型的应用程序进行自定义。

# NodeManager（NM）

在集群中的每个处理节点上部署了一个 NodeManager 代理。它是与节点级别的 ResourceManager 对应的。它与 ResourceManager 通信，更新节点状态并接收来自 ResourceManager 的任何作业请求。它还负责生命周期管理和向 ResourceManager 报告各种节点指标。

# ApplicationMaster（AM）

一旦 ResourceManager 调度了作业，它就不再跟踪其状态和进度。这使得 ResourceManager 能够支持集群中完全不同类型的应用程序，而不必担心应用程序的内部通信和逻辑。

每当提交一个应用程序时，ResourceManager 都会为该应用程序创建一个新的 ApplicationMaster，然后负责与 ResourceManager 协商资源，并与 NodeMangers 通信以获取资源。NodeManager 以资源容器的形式提供资源，这是资源分配的抽象，您可以告诉需要多少 CPU、内存等。

一旦应用程序在集群中的各个节点上开始运行，ApplicationMaster 就会跟踪各种作业的状态，并在失败时重新运行这些作业。作业完成后，它将释放资源给 ResourceManager。

以下截图展示了 YARN 集群中的各种组件：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-storm/img/00056.jpeg)

图 3：YARN 组件

# Hadoop 安装

现在我们已经看到了 Hadoop 集群的存储和处理部分，让我们开始安装 Hadoop。在本章中，我们将使用 Hadoop 2.2.0。请注意，此版本与 Hadoop 1.X 版本不兼容。

我们将在单节点上设置一个集群。在开始之前，请确保您的系统上已安装以下内容：

+   JDK 1.7

+   `ssh-keygen`

如果您没有`wget`或`ssh-keygen`，请使用以下命令进行安装：

```scala
# yum install openssh-clients  
```

接下来，我们需要在此计算机上设置无密码 SSH，因为这对于 Hadoop 是必需的。

# 设置无密码 SSH

以下是设置无密码 SSH 的步骤：

1.  通过执行以下命令生成您的 SSH 密钥对：

```scala
    $ ssh-keygen -t rsa -P ''
    Generating public/private rsa key pair.
    Enter file in which to save the key (/home/anand/.ssh/id_rsa): 
    Your identification has been saved in /home/anand/.ssh/id_rsa.
    Your public key has been saved in /home/anand/.ssh/id_rsa.pub.
    The key fingerprint is:
    b7:06:2d:76:ed:df:f9:1d:7e:5f:ed:88:93:54:0f:24 anand@localhost.localdomain
    The key's randomart image is:
    +--[ RSA 2048]----+
    |                 |
    |            E .  |
    |             o   |
    |         . .  o  |
    |        S + .. o |
    |       . = o.   o|
    |          o... .o|
    |         .  oo.+*|
    |            ..ooX|
    +-----------------+

```

1.  接下来，我们需要将生成的公钥复制到当前用户的授权密钥列表中。要做到这一点，执行以下命令：

```scala
$ cp ~/.ssh/id_rsa.pub ~/.ssh/authorized_keys  
```

1.  现在，我们可以通过以下命令连接到 localhost 检查无密码 SSH 是否正常工作：

```scala
$ ssh localhost
Last login: Wed Apr  2 09:12:17 2014 from localhost  
```

由于我们能够在本地主机上使用 SSH 而无需密码，我们的设置现在正在工作，我们现在将继续进行 Hadoop 设置。

# 获取 Hadoop 捆绑包并设置环境变量

以下是设置 Hadoop 的步骤：

1.  从 Apache 网站下载 Hadoop 2.2.0 [`hadoop.apache.org/releases.html#Download`](http://hadoop.apache.org/releases.html#Download)。

1.  在我们想要安装 Hadoop 的位置解压存档。我们将称此位置为`$HADOOP_HOME`：

```scala
$ tar xzf hadoop-2.2.0.tar.gz
$ cd hadoop-2.2.0  
```

1.  接下来，我们需要设置环境变量和 Hadoop 的路径，将以下条目添加到您的`~/.bashrc`文件中。确保根据您的系统提供 Java 和 Hadoop 的路径：

```scala
    export JAVA_HOME=/usr/java/jdk1.7.0_45
    export HADOOP_HOME=/home/anand/opt/hadoop-2.2.0
    export HADOOP_COMMON_HOME=/home/anand/opt/hadoop-2.2.0
    export HADOOP_HDFS_HOME=$HADOOP_COMMON_HOME
    export HADOOP_MAPRED_HOME=$HADOOP_COMMON_HOME
    export HADOOP_YARN_HOME=$HADOOP_COMMON_HOME
    export HADOOP_CONF_DIR=$HADOOP_COMMON_HOME/etc/hadoop
    export HADOOP_COMMON_LIB_NATIVE_DIR=$HADOOP_COMMON_HOME/lib/native
    export HADOOP_OPTS="-Djava.library.path=$HADOOP_COMMON_HOME/lib"

    export PATH=$PATH:$JAVA_HOME/bin:$HADOOP_COMMON_HOME/bin:$HADOOP_COMMON_HOME/sbin

```

1.  刷新您的`~/.bashrc`文件：

```scala
$ source ~/.bashrc  
```

1.  现在让我们用以下命令检查路径是否正确配置：

```scala
$ hadoop version
Hadoop 2.2.0
Subversion https://svn.apache.org/repos/asf/hadoop/common -r 1529768
Compiled by hortonmu on 2013-10-07T06:28Z
Compiled with protoc 2.5.0
From source with checksum 79e53ce7994d1628b240f09af91e1af4
This command was run using /home/anand/opt/hadoop-
2.2.0/share/hadoop/common/hadoop-common-2.2.0.jar  
```

在前面的片段中，我们可以看到路径已正确设置。现在我们将在系统上设置 HDFS。

# 设置 HDFS

按照以下步骤设置 HDFS：

1.  创建用于保存 namenode 和 datanode 数据的目录：

```scala
$ mkdir -p ~/mydata/hdfs/namenode
$ mkdir -p ~/mydata/hdfs/datanode  
```

1.  通过在`$HADOOP_CONF_DIR/core-site.xml`文件的`<configuration>`标记中添加以下属性来指定 namenode 端口：

```scala
<property> 
        <name>fs.default.name</name> 
        <value>hdfs://localhost:19000</value> 
   <!-- The default port for HDFS is 9000, but we are using 19000 Storm-Yarn uses port 9000 for its application master --> 
</property> 
```

1.  通过在`$HADOOP_CONF_DIR/hdfs-site.xml`文件的`<configuration>`标记中添加以下属性来指定 namenode 和 datanode 目录：

```scala
<property> 
        <name>dfs.replication</name> 
        <value>1</value> 
   <!-- Since we have only one node, we have replication factor=1 --> 
</property> 
<property> 
        <name>dfs.namenode.name.dir</name> 
        <value>file:/home/anand/hadoop-data/hdfs/namenode</value> 
   <!-- specify absolute path of the namenode directory --> 
</property> 
<property> 
        <name>dfs.datanode.data.dir</name> 
        <value>file:/home/anand/hadoop-data/hdfs/datanode</value> 
   <!-- specify absolute path of the datanode directory --> 
</property> 
```

1.  现在我们将格式化 namenode。这是一个一次性的过程，只需要在设置 HDFS 时执行：

```scala
    $ hdfs namenode -format
    14/04/02 09:03:06 INFO namenode.NameNode: STARTUP_MSG: 
    /*********************************************************
    STARTUP_MSG: Starting NameNode
    STARTUP_MSG:   host = localhost.localdomain/127.0.0.1
    STARTUP_MSG:   args = [-format]
    STARTUP_MSG:   version = 2.2.0
    ... ...
    14/04/02 09:03:08 INFO namenode.NameNode: SHUTDOWN_MSG: 
    /*********************************************************
    SHUTDOWN_MSG: Shutting down NameNode at localhost.localdomain/127.0.0.1
    ********************************************************/

```

1.  现在，我们已经完成了配置，我们将启动 HDFS：

```scala
    $ start-dfs.sh 
    14/04/02 09:27:13 WARN util.NativeCodeLoader: Unable to load native-hadoop library for your platform... using builtin-java classes where applicable
    Starting namenodes on [localhost]
    localhost: starting namenode, logging to /home/anand/opt/hadoop-2.2.0/logs/hadoop-anand-namenode-localhost.localdomain.out
    localhost: starting datanode, logging to /home/anand/opt/hadoop-2.2.0/logs/hadoop-anand-datanode-localhost.localdomain.out
    Starting secondary namenodes [0.0.0.0]
    0.0.0.0: starting secondarynamenode, logging to /home/anand/opt/hadoop-2.2.0/logs/hadoop-anand-secondarynamenode-localhost.localdomain.out
    14/04/02 09:27:32 WARN util.NativeCodeLoader: Unable to load native-hadoop library for your platform... using builtin-java classes where applicable

```

1.  现在，执行`jps`命令查看所有进程是否正常运行：

```scala
$ jps
50275 NameNode
50547 SecondaryNameNode
50394 DataNode
51091 Jps  
```

在这里，我们可以看到所有预期的进程都在运行。

1.  现在，您可以通过在浏览器中打开`http://localhost:50070`来检查 HDFS 的状态。您应该看到类似以下的内容：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-storm/img/00057.jpeg)

图 4：Namenode web UI

1.  您可以使用`hdfs dfs`命令与 HDFS 进行交互。在控制台上运行`hdfs dfs`以获取所有选项，或者参考[`hadoop.apache.org/docs/r2.2.0/hadoop-project-dist/hadoop-common/FileSystemShell.html`](http://hadoop.apache.org/docs/r2.2.0/hadoop-project-dist/hadoop-common/FileSystemShell.html)上的文档。

现在 HDFS 已部署，我们将接下来设置 YARN。

# 设置 YARN

以下是设置 YARN 的步骤：

1.  从模板`mapred-site.xml.template`创建`mapred-site.xml`文件：

```scala
$ cp $HADOOP_CONF_DIR/mapred-site.xml.template $HADOOP_CONF_DIR/mapred-
site.xml  
```

1.  通过在`$HADOOP_CONF_DIR/mapred-site.xml`文件的`<configuration>`标记中添加以下属性来指定我们正在使用 YARN 框架：

```scala
<property> 
        <name>mapreduce.framework.name</name> 
        <value>yarn</value> 
</property> 
```

1.  在`$HADOOP_CONF_DIR/yarn-site.xml`文件中配置以下属性：

```scala
<property> 
        <name>yarn.nodemanager.aux-services</name> 
        <value>mapreduce_shuffle</value> 
</property> 

<property> 
        <name>yarn.scheduler.minimum-allocation-mb</name> 
        <value>1024</value> 
</property> 

<property> 
        <name>yarn.nodemanager.resource.memory-mb</name> 
        <value>4096</value> 
</property> 

<property> 
        <name>yarn.nodemanager.aux-services.mapreduce.shuffle.class</name> 
   <value>org.apache.hadoop.mapred.ShuffleHandler</value> 
</property> 
<property> 
        <name>yarn.nodemanager.vmem-pmem-ratio</name> 
        <value>8</value> 
</property> 
```

1.  使用以下命令启动 YARN 进程：

```scala
$ start-yarn.sh 
starting yarn daemons
starting resourcemanager, logging to /home/anand/opt/hadoop-2.2.0/logs/yarn-anand-resourcemanager-localhost.localdomain.out
localhost: starting nodemanager, logging to /home/anand/opt/hadoop-2.2.0/logs/yarn-anand-nodemanager-localhost.localdomain.out  
```

1.  现在，执行`jps`命令查看所有进程是否正常运行：

```scala
$ jps
50275 NameNode
50547 SecondaryNameNode
50394 DataNode
51091 Jps
50813 NodeManager
50716 ResourceManager  
```

在这里，我们可以看到所有预期的进程都在运行。

1.  现在，您可以通过在浏览器中打开`http://localhost:8088/cluster`来检查 YARN 的状态，使用 ResourceManager web UI。您应该会看到类似以下内容的内容：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-storm/img/00058.jpeg)

图 5：ResourceManager web UI

1.  您可以使用`yarn`命令与 YARN 进行交互。在控制台上运行`yarn`或参考[`hadoop.apache.org/docs/r2.2.0/hadoop-yarn/hadoop-yarn-site/YarnCommands.html`](http://hadoop.apache.org/docs/r2.2.0/hadoop-yarn/hadoop-yarn-site/YarnCommands.html)获取所有选项。要获取当前在 YARN 上运行的所有应用程序，请运行以下命令：

```scala
    $ yarn application -list
    14/04/02 11:41:42 WARN util.NativeCodeLoader: Unable to load native-hadoop library for your platform... using builtin-java classes where applicable
    14/04/02 11:41:42 INFO client.RMProxy: Connecting to ResourceManager at /0.0.0.0:8032
    Total number of applications (application-types: [] and states: [SUBMITTED, ACCEPTED, RUNNING]):0
                    Application-Id          Application-Name        Application-Type          User       Queue               State             Final-State             Progress                          Tracking-URL

```

通过这样，我们已经完成了在单节点上部署 Hadoop 集群。接下来我们将看到如何在此集群上运行 Storm 拓扑。

# 将 Storm 拓扑写入 HDFS 以持久化数据

在本节中，我们将介绍如何编写 HDFS bolt 以将数据持久化到 HDFS 中。在本节中，我们将重点介绍以下几点：

+   从 Kafka 消费数据

+   将数据存储到 HDFS 的逻辑

+   在预定义的时间或大小后将文件旋转到 HDFS

执行以下步骤来创建将数据存储到 HDFS 的拓扑：

1.  创建一个新的 maven 项目，groupId 为`com.stormadvance`，artifactId 为`storm-hadoop`。

1.  在`pom.xml`文件中添加以下依赖项。我们在`pom.xml`中添加 Kafka Maven 依赖项以支持 Kafka 消费者。请参考前一章节，在那里我们将从 Kafka 消费数据并存储在 HDFS 中：

```scala
         <dependency> 
               <groupId>org.codehaus.jackson</groupId> 
               <artifactId>jackson-mapper-asl</artifactId> 
               <version>1.9.13</version> 
         </dependency> 

         <dependency> 
               <groupId>org.apache.hadoop</groupId> 
               <artifactId>hadoop-client</artifactId> 
               <version>2.2.0</version> 
               <exclusions> 
                     <exclusion> 
                           <groupId>org.slf4j</groupId> 
                           <artifactId>slf4j-log4j12</artifactId> 
                     </exclusion> 
               </exclusions> 
         </dependency> 
         <dependency> 
               <groupId>org.apache.hadoop</groupId> 
               <artifactId>hadoop-hdfs</artifactId> 
               <version>2.2.0</version> 
               <exclusions> 
                     <exclusion> 
                           <groupId>org.slf4j</groupId> 
                           <artifactId>slf4j-log4j12</artifactId> 
                     </exclusion> 
               </exclusions> 
         </dependency> 
         <!-- Dependency for Storm-Kafka spout --> 
         <dependency> 
               <groupId>org.apache.storm</groupId> 
               <artifactId>storm-kafka</artifactId> 
               <version>1.0.2</version> 
               <exclusions> 
                     <exclusion> 
                           <groupId>org.apache.kafka</groupId> 
                           <artifactId>kafka-clients</artifactId> 
                     </exclusion> 
               </exclusions> 
         </dependency> 

         <dependency> 
               <groupId>org.apache.kafka</groupId> 
               <artifactId>kafka_2.10</artifactId> 
               <version>0.9.0.1</version> 
               <exclusions> 
                     <exclusion> 
                           <groupId>com.sun.jdmk</groupId> 
                           <artifactId>jmxtools</artifactId> 
                     </exclusion> 
                     <exclusion> 
                           <groupId>com.sun.jmx</groupId> 
                           <artifactId>jmxri</artifactId> 
                     </exclusion> 
               </exclusions> 
         </dependency> 

         <dependency> 
               <groupId>org.apache.storm</groupId> 
               <artifactId>storm-core</artifactId> 
               <version>1.0.2</version> 
               <scope>provided</scope> 
         </dependency> 
   </dependencies> 
   <repositories> 
         <repository> 
               <id>clojars.org</id> 
               <url>http://clojars.org/repo</url> 
         </repository> 
   </repositories> 
```

1.  编写一个 Storm Hadoop 拓扑来消费 HDFS 中的数据并将其存储在 HDFS 中。以下是`com.stormadvance.storm_hadoop.topology.StormHDFSTopology`类的逐行描述：

1.  使用以下代码行从 Kafka 消费数据：

```scala
         // zookeeper hosts for the Kafka cluster 
         BrokerHosts zkHosts = new ZkHosts("localhost:2181"); 

         // Create the KafkaReadSpout configuartion 
         // Second argument is the topic name 
         // Third argument is the zookeeper root for Kafka 
         // Fourth argument is consumer group id 
         SpoutConfig kafkaConfig = new SpoutConfig(zkHosts, "dataTopic", "", 
                     "id7"); 

         // Specify that the kafka messages are String 
         kafkaConfig.scheme = new SchemeAsMultiScheme(new StringScheme()); 

         // We want to consume all the first messages in the topic everytime 
         // we run the topology to help in debugging. In production, this 
         // property should be false 
         kafkaConfig.startOffsetTime = kafka.api.OffsetRequest.EarliestTime(); 

         // Now we create the topology 
         TopologyBuilder builder = new TopologyBuilder(); 

         // set the kafka spout class 
         builder.setSpout("KafkaReadSpout", new KafkaSpout(kafkaConfig), 1); 
```

1.  使用以下代码行定义 HDFS Namenode 的详细信息和 HDFS 数据目录的名称，以将数据存储到 HDFS 中，在每存储 5MB 数据块后创建一个新文件，并在每存储 1,000 条记录后将最新数据同步到文件中：

```scala
         // use "|" instead of "," for field delimiter 
         RecordFormat format = new DelimitedRecordFormat() 
                     .withFieldDelimiter(","); 

         // sync the filesystem after every 1k tuples 
         SyncPolicy syncPolicy = new CountSyncPolicy(1000); 

         // rotate files when they reach 5MB 
         FileRotationPolicy rotationPolicy = new FileSizeRotationPolicy(5.0f, 
                     Units.MB); 

         FileNameFormat fileNameFormatHDFS = new DefaultFileNameFormat() 
                     .withPath("/hdfs-bolt-output/"); 

         HdfsBolt hdfsBolt2 = new HdfsBolt().withFsUrl("hdfs://127.0.0.1:8020") 
                     .withFileNameFormat(fileNameFormatHDFS) 
                     .withRecordFormat(format).withRotationPolicy(rotationPolicy) 
                     .withSyncPolicy(syncPolicy); 
```

1.  使用以下代码将 Spout 连接到 HDFS bolt：

```scala
HdfsBolt hdfsBolt2 = new HdfsBolt().withFsUrl("hdfs://127.0.0.1:8020") 
                     .withFileNameFormat(fileNameFormatHDFS) 
                     .withRecordFormat(format).withRotationPolicy(rotationPolicy) 
                     .withSyncPolicy(syncPolicy); 
```

# 将 Storm 与 Hadoop 集成

开发和运行大数据应用程序的组织已经部署了 Hadoop 集群的可能性非常高。此外，他们也很可能已经部署了实时流处理应用程序，以配合在 Hadoop 上运行的批处理应用程序。

如果可以利用已部署的 YARN 集群来运行 Storm 拓扑，那将是很好的。这将通过只管理一个集群而不是两个来减少维护的操作成本。

Storm-YARN 是 Yahoo!开发的一个项目，它可以在 YARN 集群上部署 Storm 拓扑。它可以在 YARN 管理的节点上部署 Storm 进程。

以下图表说明了 Storm 进程如何部署在 YARN 上：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-storm/img/00059.gif)

图 6：YARN 上的 Storm 进程

在接下来的部分，我们将看到如何设置 Storm-YARN。

# 设置 Storm-YARN

由于 Storm-YARN 仍处于 alpha 阶段，我们将继续使用`git`存储库的基础主分支。确保您的系统上已安装了`git`。如果没有，请运行以下命令：

```scala
# yum install git-core  
```

还要确保您的系统上已安装了 Apache Zookeeper 和 Apache Maven。有关其设置说明，请参考前面的章节。

部署 Storm-YARN 的步骤如下：

1.  使用以下命令克隆`storm-yarn`存储库：

```scala
$ cd ~/opt
$ git clone https://github.com/yahoo/storm-yarn.git
$ cd storm-yarn  
```

1.  通过运行以下`mvn`命令构建`storm-yarn`：

```scala
    $ mvn package
    [INFO] Scanning for projects...
    [INFO] 
    [INFO] ----------------------------------------------------
    [INFO] Building storm-yarn 1.0-alpha
    [INFO] ----------------------------------------------------
    ...
    [INFO] ----------------------------------------------------
    [INFO] BUILD SUCCESS
    [INFO] ----------------------------------------------------
    [INFO] Total time: 32.049s
    [INFO] Finished at: Fri Apr 04 09:45:06 IST 2014
    [INFO] Final Memory: 14M/152M
    [INFO] ----------------------------------------------------

```

1.  使用以下命令将`storm.zip`文件从`storm-yarn/lib`复制到 HDFS：

```scala
$ hdfs dfs -mkdir -p  /lib/storm/1.0.2-wip21
$ hdfs dfs -put lib/storm.zip /lib/storm/1.0.2-wip21/storm.zip  
```

确切的版本在您的情况下可能与`1.0.2-wip21`不同。

1.  创建一个目录来保存我们的 Storm 配置：

```scala
$ mkdir -p ~/storm-data
$ cp lib/storm.zip ~/storm-data/
$ cd ~/storm-data/
$ unzip storm.zip  
```

1.  在`~/storm-data/storm-1.0.2-wip21/conf/storm.yaml`文件中添加以下配置：

```scala
storm.zookeeper.servers: 
     - "localhost" 

nimbus.host: "localhost" 

master.initial-num-supervisors: 2 
master.container.size-mb: 128 
```

如有需要，根据您的设置更改值。

1.  通过将以下内容添加到`~/.bashrc`文件中，将`storm-yarn/bin`文件夹添加到您的路径中：

```scala
export PATH=$PATH:/home/anand/storm-data/storm-1.0.2-wip21/bin:/home/anand/opt/storm-yarn/bin 
```

1.  刷新`~/.bashrc`：

```scala
$ source ~/.bashrc  
```

1.  确保 Zookeeper 在您的系统上运行。如果没有，请运行以下命令启动 ZooKeeper：

```scala
$ ~/opt/zookeeper-3.4.5/bin/zkServer.sh start  
```

1.  使用以下命令启动`storm-yarn`：

```scala
    $ storm-yarn launch ~/storm-data/storm-1.0.2-wip21/conf/storm.yaml 
    14/04/15 10:14:49 INFO client.RMProxy: Connecting to ResourceManager at /0.0.0.0:8032
    14/04/15 10:14:49 INFO yarn.StormOnYarn: Copy App Master jar from local filesystem and add to local environment
    ... ... 
    14/04/15 10:14:51 INFO impl.YarnClientImpl: Submitted application application_1397537047058_0001 to ResourceManager at /0.0.0.0:8032
    application_1397537047058_0001

```

Storm-YARN 应用程序已经提交，应用程序 ID 为`application_1397537047058_0001`。

1.  我们可以使用以下`yarn`命令检索应用程序的状态：

```scala
    $ yarn application -list
    14/04/15 10:23:13 INFO client.RMProxy: Connecting to ResourceManager at /0.0.0.0:8032
    Total number of applications (application-types: [] and states: [SUBMITTED, ACCEPTED, RUNNING]):1
                    Application-Id          Application-Name        Application-Type          User       Queue               State             Final-State             Progress                          Tracking-URL
    application_1397537047058_0001             Storm-on-Yarn                    YARN         anand    default             RUNNING               UNDEFINED                  50%                                   N/A

```

1.  我们还可以在 ResourceManager web UI 上看到`storm-yarn`运行在`http://localhost:8088/cluster/`。您应该能够看到类似以下内容：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-storm/img/00060.jpeg)

图 7：ResourceManager web UI 上的 Storm-YARN

您可以通过单击 UI 上的各种链接来探索各种公开的指标。

1.  Nimbus 现在也应该在运行中，您应该能够通过 Nimbus web UI 看到它，网址为`http://localhost:7070/`：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-storm/img/00061.jpeg)

图 8：Nimbus web UI 在 YARN 上运行

1.  现在我们需要获取将在 YARN 上的 Storm 集群上部署拓扑时使用的 Storm 配置。为此，请执行以下命令：

```scala
    $ mkdir ~/.storm
    $ storm-yarn getStormConfig --appId application_1397537047058_0001 --output ~/.storm/storm.yaml
    14/04/15 10:32:01 INFO client.RMProxy: Connecting to ResourceManager at /0.0.0.0:8032
    14/04/15 10:32:02 INFO yarn.StormOnYarn: application report for application_1397537047058_0001 :localhost.localdomain:9000
    14/04/15 10:32:02 INFO yarn.StormOnYarn: Attaching to localhost.localdomain:9000 to talk to app master application_1397537047058_0001
    14/04/15 10:32:02 INFO yarn.StormMasterCommand: storm.yaml downloaded into /home/anand/.storm/storm.yaml  
```

确保将正确的应用程序 ID（在第 9 步中检索）传递给`-appId`参数。

现在我们已经成功部署了 Storm-YARN，我们将看到如何在这个 storm 集群上运行我们的拓扑。

# 在 Storm-YARN 上运行 Storm-Starter 拓扑

在本节中，我们将看到如何在`storm-yarn`上部署 Storm-Starter 拓扑。Storm-Starter 是一组随 Storm 一起提供的示例拓扑。

按照以下步骤在 Storm-YARN 上运行拓扑：

1.  克隆`storm-starter`项目：

```scala
$ git clone https://github.com/nathanmarz/storm-starter
$ cd storm-starter  
```

1.  使用以下`mvn`命令打包拓扑：

```scala
$ mvn package -DskipTests  
```

1.  使用以下命令在`storm-yarn`上部署拓扑：

```scala
    $ storm jar target/storm-starter-0.0.1-SNAPSHOT.jar storm.starter.WordCountTopology word-cout-topology
    545  [main] INFO  backtype.storm.StormSubmitter - Jar not uploaded to master yet. Submitting jar...
    558  [main] INFO  backtype.storm.StormSubmitter - Uploading topology jar target/storm-starter-0.0.1-SNAPSHOT.jar to assigned location: storm-local/nimbus/inbox/stormjar-9ab704ff-29f3-4b9d-b0ac-e9e41d4399dd.jar
    609  [main] INFO  backtype.storm.StormSubmitter - Successfully uploaded topology jar to assigned location: storm-local/nimbus/inbox/stormjar-9ab704ff-29f3-4b9d-b0ac-e9e41d4399dd.jar
    609  [main] INFO  backtype.storm.StormSubmitter - Submitting topology word-cout-topology in distributed mode with conf {"topology.workers":3,"topology.debug":true}
    937  [main] INFO  backtype.storm.StormSubmitter - Finished submitting topology: word-cout-topology

```

1.  现在我们可以在 Nimbus web UI 上看到部署的拓扑，网址为`http://localhost:7070/`：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-storm/img/00062.jpeg)

图 9：Nimbus web UI 显示了 YARN 上的单词计数拓扑

1.  要查看如何与在`storm-yarn`上运行的拓扑进行交互，请运行以下命令：

```scala
$ storm-yarn  
```

1.  它将列出与各种 Storm 进程交互和启动新监督者的所有选项。

因此，在本节中，我们构建了一个 Storm-started 拓扑，并在`storm-yarn`上运行它。

# 摘要

在本章中，我们介绍了 Apache Hadoop 以及 HDFS、YARN 等各种组件，这些组件是 Hadoop 集群的一部分。我们还看到了 HDFS 和 YARN 集群的子组件以及它们之间的交互。然后我们演示了如何设置单节点 Hadoop 集群。

我们还介绍了 Storm-YARN，这是本章的重点。Storm-YARN 使您能够在 Hadoop 集群上运行 Storm 拓扑。从可管理性和运维角度来看，这对我们很有帮助。最后，我们看到了如何在 YARN 上运行的 Storm 上部署拓扑。

在下一章中，我们将看到 Storm 如何与其他大数据技术（如 HBase、Redis 等）集成。


# 第十章：Storm 与 Redis、Elasticsearch 和 HBase 的集成

在上一章中，我们介绍了 Apache Hadoop 及其各个组件的概述。我们还介绍了 Storm-YARN 的概述，并介绍了如何在 Apache Hadoop 上部署 Storm-YARN。

在本章中，我们将解释如何将 Storm 与其他数据库集成以存储数据，以及如何在 Storm bolt 中使用 Esper 来支持窗口操作。

以下是本章将要涵盖的关键点：

+   将 Storm 与 HBase 集成

+   将 Storm 与 Redis 集成

+   将 Storm 与 Elasticsearch 集成

+   将 Storm 与 Esper 集成以执行窗口操作

# 将 Storm 与 HBase 集成

如前几章所述，Storm 用于实时数据处理。然而，在大多数情况下，您需要将处理后的数据存储在数据存储中，以便将存储的数据用于进一步的批量分析，并在存储的数据上执行批量分析查询。本节解释了如何将 Storm 处理的数据存储在 HBase 中。

在实施之前，我想简要介绍一下 HBase 是什么。HBase 是一个 NoSQL、多维、稀疏、水平可扩展的数据库，模型类似于**Google** **BigTable**。HBase 建立在 Hadoop 之上，这意味着它依赖于 Hadoop，并与 MapReduce 框架很好地集成。Hadoop 为 HBase 提供以下好处：

+   在通用硬件上运行的分布式数据存储

+   容错

我们假设您已经在系统上安装并运行了 HBase。您可以参考[HBase 安装文章](https://hbase.apache.org/cygwin.html)。

我们将创建一个示例 Storm 拓扑，演示如何使用以下步骤将 Storm 处理的数据存储到 HBase：

1.  使用`com.stormadvance`作为组 ID 和`stormhbase`作为 artifact ID 创建一个 Maven 项目。

1.  将以下依赖项和存储库添加到`pom.xml`文件中：

```scala
    <repositories> 
        <repository> 
            <id>clojars.org</id> 
            <url>http://clojars.org/repo</url> 
        </repository> 
    </repositories> 
    <dependencies> 
        <dependency> 
            <groupId>org.apache.storm</groupId> 
            <artifactId>storm-core</artifactId> 
            <version>1.0.2</version> 
            <scope>provided</scope> 
        </dependency> 
        <dependency> 
            <groupId>org.apache.hadoop</groupId> 
            <artifactId>hadoop-core</artifactId> 
            <version>1.1.1</version> 
        </dependency> 
        <dependency> 
            <groupId>org.slf4j</groupId> 
            <artifactId>slf4j-api</artifactId> 
            <version>1.7.7</version> 
        </dependency> 

        <dependency> 
            <groupId>org.apache.hbase</groupId> 
            <artifactId>hbase</artifactId> 
            <version>0.94.5</version> 
            <exclusions> 
                <exclusion> 
                    <artifactId>zookeeper</artifactId> 
                    <groupId>org.apache.zookeeper</groupId> 
                </exclusion> 

            </exclusions> 
        </dependency> 

        <dependency> 
            <groupId>junit</groupId> 
            <artifactId>junit</artifactId> 
            <version>4.10</version> 
        </dependency> 
    </dependencies> 
    <build> 
        <plugins> 
            <plugin> 
                <groupId>org.apache.maven.plugins</groupId> 
                <artifactId>maven-compiler-plugin</artifactId> 
                <version>2.5.1</version> 
                <configuration> 
                    <source>1.6</source> 
                    <target>1.6</target> 
                </configuration> 
            </plugin> 
            <plugin> 
                <artifactId>maven-assembly-plugin</artifactId> 
                <version>2.2.1</version> 
                <configuration> 
                    <descriptorRefs> 
                        <descriptorRef>jar-
                        with-dependencies</descriptorRef> 
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

1.  在`com.stormadvance.stormhbase`包中创建一个`HBaseOperations`类。`HBaseOperations`类包含两个方法：

+   `createTable(String tableName, List<String> ColumnFamilies)`: 此方法将表名和 HBase 列族列表作为输入，以在 HBase 中创建表。

+   `insert(Map<String, Map<String, Object>> record, String rowId)`: 此方法将记录及其`rowID`参数作为输入，并将输入记录插入 HBase。以下是输入记录的结构：

```scala
{  

  "columnfamily1":  
  {  
    "column1":"abc",  
    "column2":"pqr"  
  },  
  "columnfamily2":  
  {  
    "column3":"bc",  
    "column4":"jkl"  
  }  
}  
```

这里，`columnfamily1`和`columnfamily2`是 HBase 列族的名称，`column1`、`column2`、`column3`和`column4`是列的名称。

`rowId`参数是 HBase 表行键，用于唯一标识 HBase 中的每条记录。

`HBaseOperations`类的源代码如下：

```scala
public class HBaseOperations implements Serializable{ 

    private static final long serialVersionUID = 1L; 

    // Instance of Hadoop Cofiguration class 
    Configuration conf = new Configuration(); 

    HTable hTable = null; 

    public HBaseOperations(String tableName, List<String> ColumnFamilies, 
            List<String> zookeeperIPs, int zkPort) { 
        conf = HBaseConfiguration.create(); 
        StringBuffer zookeeperIP = new StringBuffer(); 
        // Set the zookeeper nodes 
        for (String zookeeper : zookeeperIPs) { 
            zookeeperIP.append(zookeeper).append(","); 
        } 
        zookeeperIP.deleteCharAt(zookeeperIP.length() - 1); 

        conf.set("hbase.zookeeper.quorum", zookeeperIP.toString()); 

        // Set the zookeeper client port 
        conf.setInt("hbase.zookeeper.property.clientPort", zkPort); 
        // call the createTable method to create a table into HBase. 
        createTable(tableName, ColumnFamilies); 
        try { 
            // initilaize the HTable.  
            hTable = new HTable(conf, tableName); 
        } catch (IOException e) { 
            throw new RuntimeException("Error occure while creating instance of HTable class : " + e); 
        } 
    } 

    /** 
     * This method create a table into HBase 
     *  
     * @param tableName 
     *            Name of the HBase table 
     * @param ColumnFamilies 
     *            List of column famallies 
     *  
     */ 
    public void createTable(String tableName, List<String> ColumnFamilies) { 
        HBaseAdmin admin = null; 
        try { 
            admin = new HBaseAdmin(conf); 
            // Set the input table in HTableDescriptor 
            HTableDescriptor tableDescriptor = new HTableDescriptor( 
                    Bytes.toBytes(tableName)); 
            for (String columnFamaliy : ColumnFamilies) { 
                HColumnDescriptor columnDescriptor = new HColumnDescriptor( 
                        columnFamaliy); 
                // add all the HColumnDescriptor into HTableDescriptor 
                tableDescriptor.addFamily(columnDescriptor); 
            } 
            /* execute the creaetTable(HTableDescriptor tableDescriptor) of HBaseAdmin 
             * class to createTable into HBase. 
            */  
            admin.createTable(tableDescriptor); 
            admin.close(); 

        }catch (TableExistsException tableExistsException) { 
            System.out.println("Table already exist : " + tableName); 
            if(admin != null) { 
                try { 
                admin.close();  
                } catch (IOException ioException) { 
                    System.out.println("Error occure while closing the HBaseAdmin connection : " + ioException); 
                } 
            } 

        }catch (MasterNotRunningException e) { 
            throw new RuntimeException("HBase master not running, table creation failed : "); 
        } catch (ZooKeeperConnectionException e) { 
            throw new RuntimeException("Zookeeper not running, table creation failed : "); 
        } catch (IOException e) { 
            throw new RuntimeException("IO error, table creation failed : "); 
        } 
    } 

    /** 
     * This method insert the input record into HBase. 
     *  
     * @param record 
     *            input record 
     * @param rowId 
     *            unique id to identify each record uniquely. 
     */ 
    public void insert(Map<String, Map<String, Object>> record, String rowId) { 
        try { 
        Put put = new Put(Bytes.toBytes(rowId));         
        for (String cf : record.keySet()) { 
            for (String column: record.get(cf).keySet()) { 
                put.add(Bytes.toBytes(cf), Bytes.toBytes(column), Bytes.toBytes(record.get(cf).get(column).toString())); 
            }  
        } 
        hTable.put(put); 
        }catch (Exception e) { 
            throw new RuntimeException("Error occure while storing record into HBase"); 
        } 

    } 

    public static void main(String[] args) { 
        List<String> cFs = new ArrayList<String>(); 
        cFs.add("cf1"); 
        cFs.add("cf2"); 

        List<String> zks = new ArrayList<String>(); 
        zks.add("192.168.41.122"); 
        Map<String, Map<String, Object>> record = new HashMap<String, Map<String,Object>>(); 

        Map<String, Object> cf1 = new HashMap<String, Object>(); 
        cf1.put("aa", "1"); 

        Map<String, Object> cf2 = new HashMap<String, Object>(); 
        cf2.put("bb", "1"); 

        record.put("cf1", cf1); 
        record.put("cf2", cf2); 

        HBaseOperations hbaseOperations = new HBaseOperations("tableName", cFs, zks, 2181); 
        hbaseOperations.insert(record, UUID.randomUUID().toString()); 

    } 
} 
```

1.  在`com.stormadvance.stormhbase`包中创建一个`SampleSpout`类。此类生成随机记录并将其传递给拓扑中的下一个操作（bolt）。以下是`SampleSpout`类生成的记录的格式：

```scala
["john","watson","abc"]  
```

`SampleSpout`类的源代码如下：

```scala
public class SampleSpout extends BaseRichSpout { 
    private static final long serialVersionUID = 1L; 
    private SpoutOutputCollector spoutOutputCollector; 

    private static final Map<Integer, String> FIRSTNAMEMAP = new HashMap<Integer, String>(); 
    static { 
        FIRSTNAMEMAP.put(0, "john"); 
        FIRSTNAMEMAP.put(1, "nick"); 
        FIRSTNAMEMAP.put(2, "mick"); 
        FIRSTNAMEMAP.put(3, "tom"); 
        FIRSTNAMEMAP.put(4, "jerry"); 
    } 

    private static final Map<Integer, String> LASTNAME = new HashMap<Integer, String>(); 
    static { 
        LASTNAME.put(0, "anderson"); 
        LASTNAME.put(1, "watson"); 
        LASTNAME.put(2, "ponting"); 
        LASTNAME.put(3, "dravid"); 
        LASTNAME.put(4, "lara"); 
    } 

    private static final Map<Integer, String> COMPANYNAME = new HashMap<Integer, String>(); 
    static { 
        COMPANYNAME.put(0, "abc"); 
        COMPANYNAME.put(1, "dfg"); 
        COMPANYNAME.put(2, "pqr"); 
        COMPANYNAME.put(3, "ecd"); 
        COMPANYNAME.put(4, "awe"); 
    } 

    public void open(Map conf, TopologyContext context, 
            SpoutOutputCollector spoutOutputCollector) { 
        // Open the spout 
        this.spoutOutputCollector = spoutOutputCollector; 
    } 

    public void nextTuple() { 
        // Storm cluster repeatedly call this method to emit the continuous // 
        // stream of tuples. 
        final Random rand = new Random(); 
        // generate the random number from 0 to 4\. 
        int randomNumber = rand.nextInt(5); 
        spoutOutputCollector.emit (new Values(FIRSTNAMEMAP.get(randomNumber),LASTNAME.get(randomNumber),COMPANYNAME.get(randomNumber))); 
    } 

    public void declareOutputFields(OutputFieldsDeclarer declarer) { 
        // emits the field  firstName , lastName and companyName. 
        declarer.declare(new Fields("firstName","lastName","companyName")); 
    } 
} 

```

1.  在`com.stormadvance.stormhbase`包中创建一个`StormHBaseBolt`类。此 bolt 接收`SampleSpout`发出的元组，然后调用`HBaseOperations`类的`insert()`方法将记录插入 HBase。`StormHBaseBolt`类的源代码如下：

```scala
public class StormHBaseBolt implements IBasicBolt { 

    private static final long serialVersionUID = 2L; 
    private HBaseOperations hbaseOperations; 
    private String tableName; 
    private List<String> columnFamilies; 
    private List<String> zookeeperIPs; 
    private int zkPort; 
    /** 
     * Constructor of StormHBaseBolt class 
     *  
     * @param tableName 
     *            HBaseTableNam 
     * @param columnFamilies 
     *            List of column families 
     * @param zookeeperIPs 
     *            List of zookeeper nodes 
     * @param zkPort 
     *            Zookeeper client port 
     */ 
    public StormHBaseBolt(String tableName, List<String> columnFamilies, 
            List<String> zookeeperIPs, int zkPort) { 
        this.tableName =tableName; 
        this.columnFamilies = columnFamilies; 
        this.zookeeperIPs = zookeeperIPs; 
        this.zkPort = zkPort; 

    } 

    public void execute(Tuple input, BasicOutputCollector collector) { 
        Map<String, Map<String, Object>> record = new HashMap<String, Map<String, Object>>(); 
        Map<String, Object> personalMap = new HashMap<String, Object>(); 
        // "firstName","lastName","companyName") 
        personalMap.put("firstName", input.getValueByField("firstName")); 
        personalMap.put("lastName", input.getValueByField("lastName")); 

        Map<String, Object> companyMap = new HashMap<String, Object>(); 
        companyMap.put("companyName", input.getValueByField("companyName")); 

        record.put("personal", personalMap); 
        record.put("company", companyMap); 
        // call the inset method of HBaseOperations class to insert record into 
        // HBase 
        hbaseOperations.insert(record, UUID.randomUUID().toString()); 
    } 

    public void declareOutputFields(OutputFieldsDeclarer declarer) { 

    } 

    public Map<String, Object> getComponentConfiguration() { 
        // TODO Auto-generated method stub 
        return null; 
    } 

    public void prepare(Map stormConf, TopologyContext context) { 
        // create the instance of HBaseOperations class 
        hbaseOperations = new HBaseOperations(tableName, columnFamilies, 
                zookeeperIPs, zkPort); 
    } 

    public void cleanup() { 
        // TODO Auto-generated method stub 

    } 

} 
```

`StormHBaseBolt`类的构造函数以 HBase 表名、列族列表、ZooKeeper IP 地址和 ZooKeeper 端口作为参数，并设置类级变量。`StormHBaseBolt`类的`prepare()`方法将创建`HBaseOperatons`类的实例。

`StormHBaseBolt`类的`execute()`方法以输入元组作为参数，并将其转换为 HBase 结构格式。它还使用`java.util.UUID`类生成 HBase 行 ID。

1.  在`com.stormadvance.stormhbase`包中创建一个`Topology`类。这个类创建`spout`和`bolt`类的实例，并使用`TopologyBuilder`类将它们链接在一起。以下是主类的实现：

```scala
public class Topology {
    public static void main(String[] args) throws AlreadyAliveException, 
            InvalidTopologyException { 
        TopologyBuilder builder = new TopologyBuilder(); 

        List<String> zks = new ArrayList<String>(); 
        zks.add("127.0.0.1"); 

        List<String> cFs = new ArrayList<String>(); 
        cFs.add("personal"); 
        cFs.add("company"); 

        // set the spout class 
        builder.setSpout("spout", new SampleSpout(), 2); 
        // set the bolt class 
        builder.setBolt("bolt", new StormHBaseBolt("user", cFs, zks, 2181), 2) 
                .shuffleGrouping("spout"); 
        Config conf = new Config(); 
        conf.setDebug(true); 
        // create an instance of LocalCluster class for 
        // executing topology in local mode. 
        LocalCluster cluster = new LocalCluster(); 

        // LearningStormTopolgy is the name of submitted topology. 
        cluster.submitTopology("StormHBaseTopology", conf, 
                builder.createTopology()); 
        try { 
            Thread.sleep(60000); 
        } catch (Exception exception) { 
            System.out.println("Thread interrupted exception : " + exception); 
        } 
        System.out.println("Stopped Called : "); 
        // kill the LearningStormTopology 
        cluster.killTopology("StormHBaseTopology"); 
        // shutdown the storm test cluster 
        cluster.shutdown(); 

    } 
} 

```

在本节中，我们介绍了如何将 Storm 与 NoSQL 数据库 HBase 集成。在下一节中，我们将介绍如何将 Storm 与 Redis 集成。

# 将 Storm 与 Redis 集成

Redis 是一个键值数据存储。键值可以是字符串、列表、集合、哈希等。它非常快，因为整个数据集存储在内存中。以下是安装 Redis 的步骤：

1.  首先，您需要安装`make`、`gcc`和`cc`来编译 Redis 代码，使用以下命令：

```scala
    sudo yum -y install make gcc cc
```

1.  下载、解压并制作 Redis，并使用以下命令将其复制到`/usr/local/bin`：

```scala
    cd /home/$USER 
    Here, $USER is the name of the Linux user. 
    http://download.redis.io/releases/redis-2.6.16.tar.gz 
    tar -xvf redis-2.6.16.tar.gz 
    cd redis-2.6.16 
    make 
    sudo cp src/redis-server /usr/local/bin 
    sudo cp src/redis-cli /usr/local/bin
```

1.  执行以下命令将 Redis 设置为服务：

```scala
    sudo mkdir -p /etc/redis 
    sudo mkdir -p /var/redis 
    cd /home/$USER/redis-2.6.16/ 
    sudo cp utils/redis_init_script /etc/init.d/redis 
    wget https://bitbucket.org/ptylr/public-stuff/raw/41d5c8e87ce6adb3 
    4aa16cd571c3f04fb4d5e7ac/etc/init.d/redis 
    sudo cp redis /etc/init.d/redis 
    cd /home/$USER/redis-2.6.16/ 
    sudo cp redis.conf /etc/redis/redis.conf
```

1.  现在，运行以下命令将服务添加到`chkconfig`，设置为自动启动，并实际启动服务：

```scala
    chkconfig --add redis 
    chkconfig redis on 
    service redis start
```

1.  使用以下命令检查 Redis 的安装情况：

```scala
    redis-cli ping
```

如果测试命令的结果是`PONG`，则安装已成功。

我们假设您已经启动并运行了 Redis 服务。

接下来，我们将创建一个示例 Storm 拓扑，以解释如何将 Storm 处理的数据存储在 Redis 中。

1.  使用`com.stormadvance`作为`groupID`，`stormredis`作为`artifactID`创建一个 Maven 项目。

1.  在`pom.xml`文件中添加以下依赖和存储库：

```scala
<repositories> 
        <repository> 
            <id>central</id> 
            <name>Maven Central</name> 
            <url>http://repo1.maven.org/maven2/</url> 
        </repository> 
        <repository> 
            <id>cloudera-repo</id> 
            <name>Cloudera CDH</name> 
            <url>https://repository.cloudera.com/artifactory/cloudera-
            repos/</url> 
        </repository> 
        <repository> 
            <id>clojars.org</id> 
            <url>http://clojars.org/repo</url> 
        </repository> 
    </repositories> 
    <dependencies> 
        <dependency> 
            <groupId>storm</groupId> 
            <artifactId>storm</artifactId> 
            <version>0.9.0.1</version> 
        </dependency> 
                <dependency> 
            <groupId>com.fasterxml.jackson.core</groupId> 
            <artifactId>jackson-core</artifactId> 
            <version>2.1.1</version> 
        </dependency> 

        <dependency> 
            <groupId>com.fasterxml.jackson.core</groupId> 
            <artifactId>jackson-databind</artifactId> 
            <version>2.1.1</version> 
        </dependency> 
        <dependency> 
            <groupId>junit</groupId> 
            <artifactId>junit</artifactId> 
            <version>3.8.1</version> 
            <scope>test</scope> 
        </dependency> 
        <dependency> 
            <groupId>redis.clients</groupId> 
            <artifactId>jedis</artifactId> 
            <version>2.4.2</version> 
        </dependency> 
    </dependencies> 
```

1.  在`com.stormadvance.stormredis`包中创建一个`RedisOperations`类。`RedisOperations`类包含以下方法：

+   `insert(Map<String, Object> record, String id)`: 此方法接受记录和 ID 作为输入，并将输入记录插入 Redis。在`insert()`方法中，我们将首先使用 Jackson 库将记录序列化为字符串，然后将序列化记录存储到 Redis 中。每个记录必须具有唯一的 ID，因为它用于从 Redis 中检索记录。

以下是`RedisOperations`类的源代码：

```scala
public class RedisOperations implements Serializable { 

    private static final long serialVersionUID = 1L; 
    Jedis jedis = null; 

    public RedisOperations(String redisIP, int port) { 
        // Connecting to Redis on localhost 
        jedis = new Jedis(redisIP, port); 
    } 

    public void insert(Map<String, Object> record, String id) { 
        try { 
            jedis.set(id, new ObjectMapper().writeValueAsString(record)); 
        } catch (Exception e) { 
            System.out.println("Record not persist into datastore : "); 
        } 
    } 
} 
```

我们将使用在*将 Storm 与 HBase 集成*部分中创建的相同的`SampleSpout`类。

1.  在`com.stormadvance.stormredis`包中创建一个`StormRedisBolt`类。这个 bolt 接收`SampleSpout`类发出的元组，将它们转换为 Redis 结构，然后调用`RedisOperations`类的`insert()`方法将记录插入 Redis。以下是`StormRedisBolt`类的源代码：

```scala
    public class StormRedisBolt implements IBasicBolt{ 

    private static final long serialVersionUID = 2L; 
    private RedisOperations redisOperations = null; 
    private String redisIP = null; 
    private int port; 
    public StormRedisBolt(String redisIP, int port) { 
        this.redisIP = redisIP; 
        this.port = port; 
    } 

    public void execute(Tuple input, BasicOutputCollector collector) { 
        Map<String, Object> record = new HashMap<String, Object>(); 
        //"firstName","lastName","companyName") 
        record.put("firstName", input.getValueByField("firstName")); 
        record.put("lastName", input.getValueByField("lastName")); 
        record.put("companyName", input.getValueByField("companyName")); 
        redisOperations.insert(record, UUID.randomUUID().toString()); 
    } 

    public void declareOutputFields(OutputFieldsDeclarer declarer) { 

    } 

    public Map<String, Object> getComponentConfiguration() { 
        return null; 
    } 

    public void prepare(Map stormConf, TopologyContext context) { 
        redisOperations = new RedisOperations(this.redisIP, this.port); 
    } 

    public void cleanup() { 

    } 

} 

```

在`StormRedisBolt`类中，我们使用`java.util.UUID`类生成 Redis 键。

1.  在`com.stormadvance.stormredis`包中创建一个`Topology`类。这个类创建`spout`和`bolt`类的实例，并使用`TopologyBuilder`类将它们链接在一起。以下是主类的实现：

```scala
public class Topology { 
    public static void main(String[] args) throws AlreadyAliveException, 
            InvalidTopologyException { 
        TopologyBuilder builder = new TopologyBuilder(); 

        List<String> zks = new ArrayList<String>(); 
        zks.add("192.168.41.122"); 

        List<String> cFs = new ArrayList<String>(); 
        cFs.add("personal"); 
        cFs.add("company"); 

        // set the spout class 
        builder.setSpout("spout", new SampleSpout(), 2); 
        // set the bolt class 
        builder.setBolt("bolt", new StormRedisBolt("192.168.41.122",2181), 2).shuffleGrouping("spout"); 

        Config conf = new Config(); 
        conf.setDebug(true); 
        // create an instance of LocalCluster class for 
        // executing topology in local mode. 
        LocalCluster cluster = new LocalCluster(); 

        // LearningStormTopolgy is the name of submitted topology. 
        cluster.submitTopology("StormRedisTopology", conf, 
                builder.createTopology()); 
        try { 
            Thread.sleep(10000); 
        } catch (Exception exception) { 
            System.out.println("Thread interrupted exception : " + exception); 
        } 
        // kill the LearningStormTopology 
        cluster.killTopology("StormRedisTopology"); 
        // shutdown the storm test cluster 
        cluster.shutdown(); 
} 
} 
```

在本节中，我们介绍了 Redis 的安装以及如何将 Storm 与 Redis 集成。

# 将 Storm 与 Elasticsearch 集成

在本节中，我们将介绍如何将 Storm 与 Elasticsearch 集成。Elasticsearch 是一个基于 Lucene 开发的开源分布式搜索引擎平台。它提供了多租户能力、全文搜索引擎功能。

我们假设 Elasticsearch 正在您的环境中运行。如果您没有任何正在运行的 Elasticsearch 集群，请参考[`www.elastic.co/guide/en/elasticsearch/reference/2.3/_installation.html`](https://www.elastic.co/guide/en/elasticsearch/reference/2.3/_installation.html)在任何一个框中安装 Elasticsearch。按照以下步骤将 Storm 与 Elasticsearch 集成：

1.  使用`com.stormadvance`作为`groupID`，`storm_elasticsearch`作为`artifactID`创建一个 Maven 项目。

1.  在`pom.xml`文件中添加以下依赖和存储库：

```scala
<dependencies> 
        <dependency> 
            <groupId>org.elasticsearch</groupId> 
            <artifactId>elasticsearch</artifactId> 
            <version>2.4.4</version> 
        </dependency> 
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

1.  在`com.stormadvance.storm_elasticsearch`包中创建一个`ElasticSearchOperation`类。`ElasticSearchOperation`类包含以下方法：

+   `insert(Map<String, Object> data, String indexName, String indexMapping, String indexId)`: 这个方法以记录数据、`indexName`、`indexMapping`和`indexId`作为输入，并将输入记录插入 Elasticsearch。

以下是`ElasticSearchOperation`类的源代码：

```scala
public class ElasticSearchOperation { 

    private TransportClient client; 

    public ElasticSearchOperation(List<String> esNodes) throws Exception { 
        try { 
            Settings settings = Settings.settingsBuilder() 
                    .put("cluster.name", "elasticsearch").build(); 
            client = TransportClient.builder().settings(settings).build(); 
            for (String esNode : esNodes) { 
                client.addTransportAddress(new InetSocketTransportAddress( 
                        InetAddress.getByName(esNode), 9300)); 
            } 

        } catch (Exception e) { 
            throw e; 
        } 

    } 

    public void insert(Map<String, Object> data, String indexName, String indexMapping, String indexId) { 
        client.prepareIndex(indexName, indexMapping, indexId) 
                .setSource(data).get(); 
    } 

    public static void main(String[] s){ 
        try{ 
            List<String> esNodes = new ArrayList<String>(); 
            esNodes.add("127.0.0.1"); 
            ElasticSearchOperation elasticSearchOperation  = new ElasticSearchOperation(esNodes); 
            Map<String, Object> data = new HashMap<String, Object>(); 
            data.put("name", "name"); 
            data.put("add", "add"); 
            elasticSearchOperation.insert(data,"indexName","indexMapping",UUID.randomUUID().toString()); 
        }catch(Exception e) { 
            e.printStackTrace(); 
            //System.out.println(e); 
        } 
    } 

} 
```

我们将使用在*将 Storm 与 HBase 集成*部分中创建的相同的`SampleSpout`类。

1.  在`com.stormadvance.storm_elasticsearch`包中创建一个`ESBolt`类。这个 bolt 接收`SampleSpout`类发出的元组，将其转换为`Map`结构，然后调用`ElasticSearchOperation`类的`insert()`方法将记录插入 Elasticsearch。以下是`ESBolt`类的源代码：

```scala
public class ESBolt implements IBasicBolt { 

    private static final long serialVersionUID = 2L; 
    private ElasticSearchOperation elasticSearchOperation; 
    private List<String> esNodes; 

    /** 
     *  
     * @param esNodes 
     */ 
    public ESBolt(List<String> esNodes) { 
        this.esNodes = esNodes; 

    } 

    public void execute(Tuple input, BasicOutputCollector collector) { 
        Map<String, Object> personalMap = new HashMap<String, Object>(); 
        // "firstName","lastName","companyName") 
        personalMap.put("firstName", input.getValueByField("firstName")); 
        personalMap.put("lastName", input.getValueByField("lastName")); 

        personalMap.put("companyName", input.getValueByField("companyName")); 
        elasticSearchOperation.insert(personalMap,"person","personmapping",UUID.randomUUID().toString()); 
    } 

    public void declareOutputFields(OutputFieldsDeclarer declarer) { 

    } 

    public Map<String, Object> getComponentConfiguration() { 
        // TODO Auto-generated method stub 
        return null; 
    } 

    public void prepare(Map stormConf, TopologyContext context) { 
        try { 
            // create the instance of ESOperations class 
            elasticSearchOperation = new ElasticSearchOperation(esNodes); 
        } catch (Exception e) { 
            throw new RuntimeException(); 
        } 
    } 

    public void cleanup() { 

    } 

} 
```

1.  在`com.stormadvance.storm_elasticsearch`包中创建一个`ESTopology`类。这个类创建了`spout`和`bolt`类的实例，并使用`TopologyBuilder`类将它们链接在一起。以下是主类的实现：

```scala
public class ESTopology {
    public static void main(String[] args) throws AlreadyAliveException, 
            InvalidTopologyException { 
        TopologyBuilder builder = new TopologyBuilder(); 

        //ES Node list 
        List<String> esNodes = new ArrayList<String>(); 
        esNodes.add("10.191.209.14"); 

        // set the spout class 
        builder.setSpout("spout", new SampleSpout(), 2); 
        // set the ES bolt class 
        builder.setBolt("bolt", new ESBolt(esNodes), 2) 
                .shuffleGrouping("spout"); 
        Config conf = new Config(); 
        conf.setDebug(true); 
        // create an instance of LocalCluster class for 
        // executing topology in local mode. 
        LocalCluster cluster = new LocalCluster(); 

        // ESTopology is the name of submitted topology. 
        cluster.submitTopology("ESTopology", conf, 
                builder.createTopology()); 
        try { 
            Thread.sleep(60000); 
        } catch (Exception exception) { 
            System.out.println("Thread interrupted exception : " + exception); 
        } 
        System.out.println("Stopped Called : "); 
        // kill the LearningStormTopology 
        cluster.killTopology("StormHBaseTopology"); 
        // shutdown the storm test cluster 
        cluster.shutdown(); 

    } 
} 
```

在本节中，我们介绍了如何通过在 Storm bolts 内部与 Elasticsearch 节点建立连接来将数据存储到 Elasticsearch 中。

# 将 Storm 与 Esper 集成

在本节中，我们将介绍如何在 Storm 中使用 Esper 进行窗口操作。Esper 是一个用于**复杂事件处理**（**CEP**）的开源事件序列分析和事件关联引擎。

请参阅[`www.espertech.com/products/esper.php`](http://www.espertech.com/products/esper.php)了解更多关于 Esper 的详细信息。按照以下步骤将 Storm 与 Esper 集成：

1.  使用`com.stormadvance`作为`groupID`，`storm_esper`作为`artifactID`创建一个 Maven 项目。

1.  在`pom.xml`文件中添加以下依赖项和存储库：

```scala
    <dependencies>
        <dependency>
            <groupId>com.espertech</groupId>
            <artifactId>esper</artifactId>
            <version>5.3.0</version>
        </dependency>
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

1.  在`com.stormadvance.storm_elasticsearch`包中创建一个`EsperOperation`类。`EsperOperation`类包含以下方法：

+   `esperPut(Stock stock)`: 这个方法以股票 bean 作为输入，将事件发送给 Esper 监听器。

`EsperOperation`类的构造函数初始化了 Esper 监听器并设置了 Esper 查询。Esper 查询在 5 分钟内缓冲事件并返回每个产品在 5 分钟窗口期内的总销售额。在这里，我们使用了固定批处理窗口。

以下是`EsperOperation`类的源代码：

```scala
public class EsperOperation { 

    private EPRuntime cepRT = null; 

    public EsperOperation() { 
        Configuration cepConfig = new Configuration(); 
        cepConfig.addEventType("StockTick", Stock.class.getName()); 
        EPServiceProvider cep = EPServiceProviderManager.getProvider( 
                "myCEPEngine", cepConfig); 
        cepRT = cep.getEPRuntime(); 

        EPAdministrator cepAdm = cep.getEPAdministrator(); 
        EPStatement cepStatement = cepAdm 
                .createEPL("select sum(price),product from " 
                        + "StockTick.win:time_batch(5 sec) " 
                        + "group by product"); 

        cepStatement.addListener(new CEPListener()); 
    } 

    public static class CEPListener implements UpdateListener { 

        public void update(EventBean[] newData, EventBean[] oldData) { 
            try { 
                System.out.println("#################### Event received: 
                "+newData); 
                for (EventBean eventBean : newData) { 
                    System.out.println("************************ Event 
                     received 1: " + eventBean.getUnderlying()); 
                } 

            } catch (Exception e) { 
                e.printStackTrace(); 
                System.out.println(e); 
            } 
        } 
    } 

    public void esperPut(Stock stock) { 
        cepRT.sendEvent(stock); 
    } 

    private static Random generator = new Random(); 

    public static void main(String[] s) throws InterruptedException { 
        EsperOperation esperOperation = new EsperOperation(); 
        // We generate a few ticks... 
        for (int i = 0; i < 5; i++) { 
            double price = (double) generator.nextInt(10); 
            long timeStamp = System.currentTimeMillis(); 
            String product = "AAPL"; 
            Stock stock = new Stock(product, price, timeStamp); 
            System.out.println("Sending tick:" + stock); 
            esperOperation.esperPut(stock); 
        } 
        Thread.sleep(200000); 
    } 

} 
```

1.  在`com.stormadvance.storm_esper`包中创建一个`SampleSpout`类。这个类生成随机记录并将它们传递给拓扑中的下一个操作（bolt）。以下是`SampleSpout`类生成的记录的格式：

```scala
    ["product type","price","sale date"] 
```

以下是`SampleSpout`类的源代码：

```scala
public class SampleSpout extends BaseRichSpout { 
    private static final long serialVersionUID = 1L; 
    private SpoutOutputCollector spoutOutputCollector; 

    private static final Map<Integer, String> PRODUCT = new 
    HashMap<Integer, String>(); 
    static { 
        PRODUCT.put(0, "A"); 
        PRODUCT.put(1, "B"); 
        PRODUCT.put(2, "C"); 
        PRODUCT.put(3, "D"); 
        PRODUCT.put(4, "E"); 
    } 

    private static final Map<Integer, Double> price = new 
    HashMap<Integer, Double>(); 
    static { 
        price.put(0, 500.0); 
        price.put(1, 100.0); 
        price.put(2, 300.0); 
        price.put(3, 900.0); 
        price.put(4, 1000.0); 
    } 

    public void open(Map conf, TopologyContext context, 
            SpoutOutputCollector spoutOutputCollector) { 
        // Open the spout 
        this.spoutOutputCollector = spoutOutputCollector; 
    } 

    public void nextTuple() { 
        // Storm cluster repeatedly call this method to emit the 
        continuous // 
        // stream of tuples. 
        final Random rand = new Random(); 
        // generate the random number from 0 to 4\. 
        int randomNumber = rand.nextInt(5); 

        spoutOutputCollector.emit (new 
        Values(PRODUCT.get(randomNumber),price.get(randomNumber), 
        System.currentTimeMillis())); 
        try { 
            Thread.sleep(1000); 
        } catch (InterruptedException e) { 
            // TODO Auto-generated catch block 
            e.printStackTrace(); 
        } 
    } 

    public void declareOutputFields(OutputFieldsDeclarer declarer) { 
        // emits the field  firstName , lastName and companyName. 
        declarer.declare(new Fields("product","price","timestamp")); 
    } 
} 
```

1.  在`com.stormadvance.storm_esper`包中创建一个`EsperBolt`类。这个 bolt 接收`SampleSpout`类发出的元组，将其转换为股票 bean，然后调用`EsperBolt`类的`esperPut()`方法将数据传递给 Esper 引擎。以下是`EsperBolt`类的源代码：

```scala
public class EsperBolt implements IBasicBolt { 

    private static final long serialVersionUID = 2L; 
    private EsperOperation esperOperation; 

    public EsperBolt() { 

    } 

    public void execute(Tuple input, BasicOutputCollector collector) { 

        double price = input.getDoubleByField("price"); 
        long timeStamp = input.getLongByField("timestamp"); 
        //long timeStamp = System.currentTimeMillis(); 
        String product = input.getStringByField("product"); 
        Stock stock = new Stock(product, price, timeStamp); 
        esperOperation.esperPut(stock); 
    } 

    public void declareOutputFields(OutputFieldsDeclarer declarer) { 

    } 

    public Map<String, Object> getComponentConfiguration() { 
        // TODO Auto-generated method stub 
        return null; 
    } 

    public void prepare(Map stormConf, TopologyContext context) { 
        try { 
            // create the instance of ESOperations class 
            esperOperation = new EsperOperation(); 
        } catch (Exception e) { 
            throw new RuntimeException(); 
        } 
    } 

    public void cleanup() { 

    } 
} 
```

1.  在`com.stormadvance.storm_esper`包中创建一个`EsperTopology`类。这个类创建了`spout`和`bolt`类的实例，并使用`TopologyBuilder`类将它们链接在一起。以下是主类的实现：

```scala
public class EsperTopology { 
    public static void main(String[] args) throws AlreadyAliveException, 
            InvalidTopologyException { 
        TopologyBuilder builder = new TopologyBuilder(); 

        // set the spout class 
        builder.setSpout("spout", new SampleSpout(), 2); 
        // set the ES bolt class 
        builder.setBolt("bolt", new EsperBolt(), 2) 
                .shuffleGrouping("spout"); 
        Config conf = new Config(); 
        conf.setDebug(true); 
        // create an instance of LocalCluster class for 
        // executing topology in local mode. 
        LocalCluster cluster = new LocalCluster(); 

        // EsperTopology is the name of submitted topology. 
        cluster.submitTopology("EsperTopology", conf, 
                builder.createTopology()); 
        try { 
            Thread.sleep(60000); 
        } catch (Exception exception) { 
            System.out.println("Thread interrupted exception : " + exception); 
        } 
        System.out.println("Stopped Called : "); 
        // kill the LearningStormTopology 
        cluster.killTopology("EsperTopology"); 
        // shutdown the storm test cluster 
        cluster.shutdown(); 

    } 
} 
```

# 总结

在本章中，我们主要关注了 Storm 与其他数据库的集成。此外，我们还介绍了如何在 Storm 中使用 Esper 执行窗口操作。

在下一章中，我们将介绍 Apache 日志处理案例研究。我们将解释如何通过 Storm 处理日志文件来生成业务信息。


# 第十一章：使用 Storm 进行 Apache 日志处理

在上一章中，我们介绍了如何将 Storm 与 Redis、HBase、Esper 和 Elasticsearch 集成。

在本章中，我们将介绍 Storm 最流行的用例，即日志处理。

本章涵盖以下主要部分：

+   Apache 日志处理元素

+   安装 Logstash

+   配置 Logstash 以将 Apache 日志生成到 Kafka

+   拆分 Apache 日志文件

+   计算国家名称、操作系统类型和浏览器类型

+   识别网站的搜索关键词

+   持久化处理数据

+   Kafka spout 和定义拓扑

+   部署拓扑

+   将数据存储到 Elasticsearch 并生成报告

# Apache 日志处理元素

日志处理正在成为每个组织的必需品，因为他们需要从日志数据中收集业务信息。在本章中，我们基本上是在讨论如何使用 Logstash、Kafka、Storm 和 Elasticsearch 来处理 Apache 日志数据，以收集业务信息。

以下图示了我们在本章中开发的所有元素：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-storm/img/00063.jpeg)

图 11.1：日志处理拓扑

# 使用 Logstash 在 Kafka 中生成 Apache 日志

如第八章中所解释的，*Storm 和 Kafka 的集成*，Kafka 是一个分布式消息队列，可以与 Storm 很好地集成。在本节中，我们将向您展示如何使用 Logstash 来读取 Apache 日志文件并将其发布到 Kafka 集群中。我们假设您已经运行了 Kafka 集群。Kafka 集群的安装步骤在第八章中概述。

# 安装 Logstash

在继续安装 Logstash 之前，我们将回答以下问题：什么是 Logstash？为什么我们要使用 Logstash？

# 什么是 Logstash？

Logstash 是一个用于收集、过滤/解析和发送数据以供将来使用的工具。收集、解析和发送分为三个部分，称为输入、过滤器和输出：

+   **input**部分用于从外部来源读取数据。常见的输入来源是文件、TCP 端口、Kafka 等。

+   **filter**部分用于解析数据。

+   **output**部分用于将数据发送到某些外部来源。常见的外部来源是 Kafka、Elasticsearch、TCP 等。

# 为什么我们要使用 Logstash？

在 Storm 开始实际处理之前，我们需要实时读取日志数据并将其存储到 Kafka 中。我们使用 Logstash 是因为它非常成熟地读取日志文件并将日志数据推送到 Kafka 中。

# 安装 Logstash

在安装 Logstash 之前，我们应该在 Linux 服务器上安装 JDK 1.8，因为我们将使用 Logstash 5.4.1，而 JDK 1.8 是此版本的最低要求。以下是安装 Logstash 的步骤：

1.  从[`artifacts.elastic.co/downloads/logstash/logstash-5.4.1.zip`](https://artifacts.elastic.co/downloads/logstash/logstash-5.4.1.zip)下载 Logstash 5.4.1。

1.  将设置复制到所有你想要发布到 Kafka 的 Apache 日志的机器上。

1.  通过运行以下命令提取设置：

```scala
> unzip logstash-5.4.1.zip
```

# Logstash 的配置

现在，我们将定义 Logstash 配置来消耗 Apache 日志并将其存储到 Kafka 中。

创建一个`logstash.conf`文件并添加以下行：

```scala
input {
  file {
    path => "PATH_TO_APACHE_LOG"
    start_position => "beginning"
  }
}
output {
  kafka {
    topic_id => "TOPIC_NAME"
    bootstrap_servers => "KAFKA_IP:KAFKA_PORT"
  }
}
```

我们应该更改前述配置中的以下参数：

+   `TOPIC_NAME`：替换为您要用于存储 Apache 日志的 Kafka 主题

+   `KAFKA_IP`和`KAFKA_PORT`：指定所有 Kafka 节点的逗号分隔列表

+   `PATH_TO_APACHE_LOG`：Logstash 机器上 Apache 日志文件的位置

转到 Logstash 主目录并执行以下命令以开始读取日志并发布到 Kafka：

```scala
$ bin/logstash agent -f logstash.conf
```

现在，实时日志数据正在进入 Kafka 主题。在下一节中，我们将编写 Storm 拓扑来消费日志数据，处理并将处理数据存储到数据库中。

# 为什么在 Logstash 和 Storm 之间使用 Kafka？

众所周知，Storm 提供了可靠的消息处理，这意味着每条消息进入 Storm 拓扑都将至少被处理一次。在 Storm 中，数据丢失只可能发生在 spout 端，如果 Storm spout 的处理能力小于 Logstash 的生产能力。因此，为了避免数据在 Storm spout 端丢失，我们通常会将数据发布到消息队列（Kafka），Storm spout 将使用消息队列作为数据源。

# 分割 Apache 日志行

现在，我们正在创建一个新的拓扑，它将使用`KafkaSpout` spout 从 Kafka 中读取数据。在本节中，我们将编写一个`ApacheLogSplitter` bolt，它具有从 Apache 日志行中提取 IP、状态码、引用来源、发送的字节数等信息的逻辑。由于这是一个新的拓扑，我们必须首先创建新项目。

1.  创建一个新的 Maven 项目，`groupId`为`com.stormadvance`，`artifactId`为`logprocessing`。

1.  在`pom.xml`文件中添加以下依赖项：

```scala
       <dependency> 
             <groupId>org.apache.storm</groupId> 
             <artifactId>storm-core</artifactId> 
             <version>1.0.2</version> 
             <scope>provided</scope> 
       </dependency> 

       <!-- Utilities --> 
       <dependency> 
             <groupId>commons-collections</groupId> 
             <artifactId>commons-collections</artifactId> 
             <version>3.2.1</version> 
       </dependency> 
       <dependency> 
             <groupId>com.google.guava</groupId> 
             <artifactId>guava</artifactId> 
             <version>15.0</version> 
       </dependency> 
```

1.  我们将在`com.stormadvance.logprocessing`包中创建`ApacheLogSplitter`类。这个类包含了从 Apache 日志行中提取不同元素（如 IP、引用来源、用户代理等）的逻辑。

```scala
/** 
 * This class contains logic to Parse an Apache log file with Regular 
 * Expressions 
 */ 
public class ApacheLogSplitter { 

 public Map<String,Object> logSplitter(String apacheLog) { 

       String logEntryLine = apacheLog; 
       // Regex pattern to split fetch the different properties from log lines. 
       String logEntryPattern = "^([\\d.]+) (\\S+) (\\S+) \\[([\\w-:/]+\\s[+\\-]\\d{4})\\] \"(.+?)\" (\\d{3}) (\\d+) \"([^\"]+)\" \"([^\"]+)\""; 

       Pattern p = Pattern.compile(logEntryPattern); 
       Matcher matcher = p.matcher(logEntryLine); 
       Map<String,Object> logMap = new HashMap<String, Object>(); 
       if (!matcher.matches() || 9 != matcher.groupCount()) { 
             System.err.println("Bad log entry (or problem with RE?):"); 
             System.err.println(logEntryLine); 
             return logMap; 
       } 
       // set the ip, dateTime, request, etc into map. 
       logMap.put("ip", matcher.group(1)); 
       logMap.put("dateTime", matcher.group(4)); 
       logMap.put("request", matcher.group(5)); 
       logMap.put("response", matcher.group(6)); 
       logMap.put("bytesSent", matcher.group(7)); 
       logMap.put("referrer", matcher.group(8)); 
       logMap.put("useragent", matcher.group(9)); 
       return logMap; 
 } 
```

1.  `logSplitter(String apacheLog)`方法的输入是：

```scala
98.83.179.51 - - [18/May/2011:19:35:08 -0700] \"GET /css/main.css HTTP/1.1\" 200 1837 \"http://www.safesand.com/information.htm\" \"Mozilla/5.0 (Windows NT 6.0; WOW64; rv:2.0.1) Gecko/20100101 Firefox/4.0.1\" 
```

1.  `logSplitter(String apacheLog)`方法的输出是：

```scala
{response=200, referrer=http://www.safesand.com/information.htm, bytesSent=1837, useragent=Mozilla/5.0 (Windows NT 6.0; WOW64; rv:2.0.1) Gecko/20100101 Firefox/4.0.1, dateTime=18/May/2011:19:35:08 -0700, request=GET /css/main.css HTTP/1.1, ip=98.83.179.51}  
```

1.  现在我们将在`com.stormadvance.logprocessing`包中创建`ApacheLogSplitterBolt`类。`ApacheLogSplitterBolt`扩展了`org.apache.storm.topology.base.BaseBasicBolt`类，并将`ApacheLogSplitter`类生成的字段集传递给拓扑中的下一个 bolt。以下是`ApacheLogSplitterBolt`类的源代码：

```scala
/** 
 *  
 * This class call the ApacheLogSplitter class and pass the set of fields (ip, 
 * referrer, user-agent, etc) to next bolt in Topology. 
 */ 

public class ApacheLogSplitterBolt extends BaseBasicBolt { 

 private static final long serialVersionUID = 1L; 
 // Create the instance of ApacheLogSplitter class. 
 private static final ApacheLogSplitter apacheLogSplitter = new ApacheLogSplitter(); 
 private static final List<String> LOG_ELEMENTS = new ArrayList<String>(); 
 static { 
       LOG_ELEMENTS.add("ip"); 
       LOG_ELEMENTS.add("dateTime"); 
       LOG_ELEMENTS.add("request"); 
       LOG_ELEMENTS.add("response"); 
       LOG_ELEMENTS.add("bytesSent"); 
       LOG_ELEMENTS.add("referrer"); 
       LOG_ELEMENTS.add("useragent"); 
 } 

 public void execute(Tuple input, BasicOutputCollector collector) { 
       // Get the Apache log from the tuple 
       String log = input.getString(0); 

       if (StringUtils.isBlank(log)) { 
             // ignore blank lines 
             return; 
       } 
       // call the logSplitter(String apachelog) method of ApacheLogSplitter 
       // class. 
       Map<String, Object> logMap = apacheLogSplitter.logSplitter(log); 
       List<Object> logdata = new ArrayList<Object>(); 
       for (String element : LOG_ELEMENTS) { 
             logdata.add(logMap.get(element)); 
       } 
       // emits set of fields (ip, referrer, user-agent, bytesSent, etc) 
       collector.emit(logdata); 

 } 

 public void declareOutputFields(OutputFieldsDeclarer declarer) { 
       // specify the name of output fields. 
       declarer.declare(new Fields("ip", "dateTime", "request", "response", 
                   "bytesSent", "referrer", "useragent")); 
 } 
} 

```

`ApacheLogSplitterBolt`类的输出包含七个字段。这些字段是`ip`，`dateTime`，`request`，`response`，`bytesSent`，`referrer`和`useragent`。

# 从日志文件中识别国家、操作系统类型和浏览器类型

本节解释了如何通过分析 Apache 日志行来计算用户国家名称、操作系统类型和浏览器类型。通过识别国家名称，我们可以轻松地确定我们网站受到更多关注的地点以及我们受到较少关注的地点。让我们执行以下步骤来计算 Apache 日志文件中的国家名称、操作系统和浏览器：

1.  我们使用开源的`geoip`库来从 IP 地址计算国家名称。在`pom.xml`文件中添加以下依赖项：

```scala
       <dependency> 
             <groupId>org.geomind</groupId> 
             <artifactId>geoip</artifactId> 
             <version>1.2.8</version> 
       </dependency> 
```

1.  在`pom.xml`文件中添加以下存储库：

```scala
        <repository> 
             <id>geoip</id> 
             <url>http://snambi.github.com/maven/</url> 
       </repository> 
```

1.  我们将在`com.stormadvance.logprocessing`包中创建`IpToCountryConverter`类。这个类包含了带有`GeoLiteCity.dat`文件位置作为输入的参数化构造函数。你可以在`logprocessing`项目的资源文件夹中找到`GeoLiteCity.dat`文件。`GeoLiteCity.dat`文件的位置在所有 Storm 节点中必须相同。`GeoLiteCity.dat`文件是我们用来从 IP 地址计算国家名称的数据库。以下是`IpToCountryConverter`类的源代码：

```scala
/** 
 * This class contains logic to calculate the country name from IP address 
 *  
 */ 
public class IpToCountryConverter { 

 private static LookupService cl = null; 

 /** 
  * An parameterised constructor which would take the location of 
  * GeoLiteCity.dat file as input. 
  *  
  * @param pathTOGeoLiteCityFile 
  */ 
 public IpToCountryConverter(String pathTOGeoLiteCityFile) { 
       try { 
             cl = new LookupService("pathTOGeoLiteCityFile", 
                         LookupService.GEOIP_MEMORY_CACHE); 
       } catch (Exception exception) { 
             throw new RuntimeException( 
                         "Error occurs while initializing IpToCountryConverter class : "); 
       } 
 } 

 /** 
  * This method takes ip address an input and convert it into country name. 
  *  
  * @param ip 
  * @return 
  */ 
 public String ipToCountry (String ip) { 
       Location location = cl.getLocation(ip); 
       if (location == null) { 
             return "NA"; 
       } 
       if (location.countryName == null) { 
             return "NA"; 
       } 
       return location.countryName; 
 } 
} 
```

1.  现在从[`code.google.com/p/ndt/source/browse/branches/applet_91/Applet/src/main/java/edu/internet2/ndt/UserAgentTools.java?r=856`](https://code.google.com/p/ndt/source/browse/branches/applet_91/Applet/src/main/java/edu/internet2/ndt/UserAgentTools.java?r=856)下载`UserAgentTools`类。这个类包含了从用户代理中计算操作系统和浏览器类型的逻辑。你也可以在`logprocessing`项目中找到`UserAgentTools`类。

1.  让我们在`com.stormadvance.logprocessing`包中编写`UserInformationGetterBolt`类。这个 bolt 使用`UserAgentTools`和`IpToCountryConverter`类来计算国家名称、操作系统和浏览器。

```scala
 /** 
 * This class use the IpToCountryConverter and UserAgentTools class to calculate 
 * the country, os and browser from log line. 
 *  
 */ 
public class UserInformationGetterBolt extends BaseRichBolt { 

 private static final long serialVersionUID = 1L; 
 private IpToCountryConverter ipToCountryConverter = null; 
 private UserAgentTools userAgentTools = null; 
 public OutputCollector collector; 
 private String pathTOGeoLiteCityFile; 

 public UserInformationGetterBolt(String pathTOGeoLiteCityFile) { 
       // set the path of GeoLiteCity.dat file. 
       this.pathTOGeoLiteCityFile = pathTOGeoLiteCityFile; 
 } 

 public void declareOutputFields(OutputFieldsDeclarer declarer) { 
       declarer.declare(new Fields("ip", "dateTime", "request", "response", 
                   "bytesSent", "referrer", "useragent", "country", "browser", 
                   "os")); 
 } 

 public void prepare(Map stormConf, TopologyContext context, 
             OutputCollector collector) { 
       this.collector = collector; 
       this.ipToCountryConverter = new IpToCountryConverter( 
                   this.pathTOGeoLiteCityFile); 
       this.userAgentTools = new UserAgentTools(); 

 } 

 public void execute(Tuple input) { 

       String ip = input.getStringByField("ip").toString(); 

       // calculate the country from ip 
       Object country = ipToCountryConverter.ipToCountry(ip); 
       // calculate the browser from useragent. 
       Object browser = userAgentTools.getBrowser(input.getStringByField( 
                   "useragent").toString())[1]; 
       // calculate the os from useragent. 
       Object os = userAgentTools.getOS(input.getStringByField("useragent") 
                   .toString())[1]; 
       collector.emit(new Values(input.getString(0), input.getString(1), input 
                   .getString(2), input.getString(3), input.getString(4), input 
                   .getString(5), input.getString(6), country, browser, os)); 

 } 
} 
```

1.  `UserInformationGetterBolt`类的输出包含 10 个字段。这些字段是`ip`、`dateTime`、`request`、`response`、`bytesSent`、`referrer`、`useragent`、`country`、`browser`和`os`。

# 计算搜索关键词

本节解释了如何从引荐 URL 计算搜索关键词。假设引荐 URL 是[`www.google.co.in/#q=learning+storm`](https://www.google.co.in/#q=learning+storm)。我们将把这个引荐 URL 传递给一个类，这个类的输出将是*learning storm*。通过识别搜索关键词，我们可以轻松地确定用户搜索关键词以到达我们的网站。让我们执行以下步骤来计算引荐 URL 中的关键词：

1.  我们在`com.stormadvance.logprocessing`包中创建一个`KeywordGenerator`类。这个类包含从引荐 URL 生成搜索关键词的逻辑。以下是`KeywordGenerator`类的源代码：

```scala
/** 
 * This class takes referrer URL as input, analyze the URL and return search 
 * keyword as output. 
 *  
 */ 
public class KeywordGenerator { 
 public String getKeyword(String referer) { 

       String[] temp; 
       Pattern pat = Pattern.compile("[?&#]q=([^&]+)"); 
       Matcher m = pat.matcher(referer); 
       if (m.find()) { 
             String searchTerm = null; 
             searchTerm = m.group(1); 
             temp = searchTerm.split("\\+"); 
             searchTerm = temp[0]; 
             for (int i = 1; i < temp.length; i++) { 
                   searchTerm = searchTerm + " " + temp[i]; 
             } 
             return searchTerm; 
       } else { 
             pat = Pattern.compile("[?&#]p=([^&]+)"); 
             m = pat.matcher(referer); 
             if (m.find()) { 
                   String searchTerm = null; 
                   searchTerm = m.group(1); 
                   temp = searchTerm.split("\\+"); 
                   searchTerm = temp[0]; 
                   for (int i = 1; i < temp.length; i++) { 
                         searchTerm = searchTerm + " " + temp[i]; 
                   } 
                   return searchTerm; 
             } else { 
                   // 
                   pat = Pattern.compile("[?&#]query=([^&]+)"); 
                   m = pat.matcher(referer); 
                   if (m.find()) { 
                         String searchTerm = null; 
                         searchTerm = m.group(1); 
                         temp = searchTerm.split("\\+"); 
                         searchTerm = temp[0]; 
                         for (int i = 1; i < temp.length; i++) { 
                               searchTerm = searchTerm + " " + temp[i]; 
                         } 
                         return searchTerm; 
                   }  else { 
                               return "NA"; 
                         } 
                   } 
       } 
 } 

} 
```

1.  如果`KeywordGenerator`类的输入是：[`in.search.yahoo.com/search;_ylt=AqH0NZe1hgPCzVap0PdKk7GuitIF?p=india+live+score&toggle=1&cop=mss&ei=UTF-8&fr=yfp-t-704`](https://in.search.yahoo.com/search;_ylt=AqH0NZe1hgPCzVap0PdKk7GuitIF?p=india+live+score&toggle=1&cop=mss&ei=UTF-8&fr=yfp-t-704)

1.  然后，`KeywordGenerator`类的输出是：

```scala
india live score
```

1.  我们在`com.stormadvance.logprocessing`包中创建一个`KeyWordIdentifierBolt`类。这个类调用`KeywordGenerator`来从引荐 URL 生成关键词。以下是`KeyWordIdentifierBolt`类的源代码：

```scala
/** 
 * This class use the KeywordGenerator class to generate the search keyword from 
 * referrer URL. 
 *  
 */ 
public class KeyWordIdentifierBolt extends BaseRichBolt { 

 private static final long serialVersionUID = 1L; 
 private KeywordGenerator keywordGenerator = null; 
 public OutputCollector collector; 

 public KeyWordIdentifierBolt() { 

 } 

 public void declareOutputFields(OutputFieldsDeclarer declarer) { 
       declarer.declare(new Fields("ip", "dateTime", "request", "response", 
                   "bytesSent", "referrer", "useragent", "country", "browser", 
                   "os", "keyword")); 
 } 

 public void prepare(Map stormConf, TopologyContext context, 
             OutputCollector collector) { 
       this.collector = collector; 
       this.keywordGenerator = new KeywordGenerator(); 

 } 

 public void execute(Tuple input) { 

       String referrer = input.getStringByField("referrer").toString(); 
       // call the getKeyword(String referrer) method KeywordGenerator class to 
       // generate the search keyword. 
       Object keyword = keywordGenerator.getKeyword(referrer); 
       // emits all the field emitted by previous bolt + keyword 
       collector.emit(new Values(input.getString(0), input.getString(1), input 
                   .getString(2), input.getString(3), input.getString(4), input 
                   .getString(5), input.getString(6), input.getString(7), input 
                   .getString(8), input.getString(9), keyword)); 

 } 
} 
```

1.  `KeyWordIdentifierBolt`类的输出包含 11 个字段。这些字段是`ip`、`dateTime`、`request`、`response`、`bytesSent`、`referrer`、`useragent`、`country`、`browser`、`os`和`keyword`。

# 持久化处理数据

本节将解释如何将处理数据持久化到数据存储中。我们在日志处理用例中使用 MySQL 作为数据存储。我假设您已经在您的 centOS 机器上安装了 MySQL，或者您可以按照[`www.rackspace.com/knowledge_center/article/installing-mysql-server-on-centos`](http://www.rackspace.com/knowledge_center/article/installing-mysql-server-on-centos)上的博客来安装 MySQL。让我们执行以下步骤将记录持久化到 MySQL 中：

1.  将以下依赖项添加到`pom.xml`：

```scala

       <dependency> 
             <groupId>mysql</groupId> 
             <artifactId>mysql-connector-java</artifactId> 
             <version>5.1.6</version> 
       </dependency> 
```

1.  我们在`com.stormadvance.logprocessing`包中创建一个`MySQLConnection`类。这个类包含`getMySQLConnection(String ip, String database, String user, String password)`方法，该方法返回 MySQL 连接。以下是`MySQLConnection`类的源代码：

```scala
/** 
 *  
 * This class return the MySQL connection. 
 */ 
public class MySQLConnection { 

 private static Connection connect = null; 

 /** 
  * This method return the MySQL connection. 
  *  
  * @param ip 
  *            ip of MySQL server 
  * @param database 
  *            name of database 
  * @param user 
  *            name of user 
  * @param password 
  *            password of given user 
  * @return MySQL connection 
  */ 
 public static Connection getMySQLConnection(String ip, String database, String user, String password) { 
       try { 
             // this will load the MySQL driver, each DB has its own driver 
             Class.forName("com.mysql.jdbc.Driver"); 
             // setup the connection with the DB. 
             connect = DriverManager 
                         .getConnection("jdbc:mysql://"+ip+"/"+database+"?" 
                                     + "user="+user+"&password="+password+""); 
             return connect; 
       } catch (Exception e) { 
             throw new RuntimeException("Error occurs while get mysql connection : "); 
       } 
 } 
} 
```

1.  现在，我们在`com.stormadvance.logprocessing`包中创建一个`MySQLDump`类。这个类有一个带参数的构造函数，它以 MySQL 的`服务器 ip、数据库名称、用户和密码`作为参数。这个类调用`MySQLConnection`类的`getMySQLConnection(ip,database,user,password)`方法来获取 MySQL 连接。`MySQLDump`类包含`persistRecord(Tuple tuple)`记录方法，这个方法将输入元组持久化到 MySQL 中。以下是`MySQLDump`类的源代码：

```scala
/** 
 * This class contains logic to persist record into MySQL database. 
 *  
 */ 
public class MySQLDump { 
 /** 
  * Name of database you want to connect 
  */ 
 private String database; 
 /** 
  * Name of MySQL user 
  */ 
 private String user; 
 /** 
  * IP of MySQL server 
  */ 
 private String ip; 
 /** 
  * Password of MySQL server 
  */ 
 private String password; 

 public MySQLDump(String ip, String database, String user, String password) { 
       this.ip = ip; 
       this.database = database; 
       this.user = user; 
       this.password = password; 
 } 

 /** 
  * Get the MySQL connection 
  */ 
 private Connection connect = MySQLConnection.getMySQLConnection(ip,database,user,password); 

 private PreparedStatement preparedStatement = null; 

 /** 
  * Persist input tuple. 
  * @param tuple 
  */ 
 public void persistRecord(Tuple tuple) { 
       try { 

             // preparedStatements can use variables and are more efficient 
             preparedStatement = connect 
                         .prepareStatement("insert into  apachelog values (default, ?, ?, ?,?, ?, ?, ?, ? , ?, ?, ?)"); 

             preparedStatement.setString(1, tuple.getStringByField("ip")); 
             preparedStatement.setString(2, tuple.getStringByField("dateTime")); 
             preparedStatement.setString(3, tuple.getStringByField("request")); 
             preparedStatement.setString(4, tuple.getStringByField("response")); 
             preparedStatement.setString(5, tuple.getStringByField("bytesSent")); 
             preparedStatement.setString(6, tuple.getStringByField("referrer")); 
             preparedStatement.setString(7, tuple.getStringByField("useragent")); 
             preparedStatement.setString(8, tuple.getStringByField("country")); 
             preparedStatement.setString(9, tuple.getStringByField("browser")); 
             preparedStatement.setString(10, tuple.getStringByField("os")); 
             preparedStatement.setString(11, tuple.getStringByField("keyword")); 

             // Insert record 
             preparedStatement.executeUpdate(); 

       } catch (Exception e) { 
             throw new RuntimeException( 
                         "Error occurs while persisting records in mysql : "); 
       } finally { 
             // close prepared statement 
             if (preparedStatement != null) { 
                   try { 
                         preparedStatement.close(); 
                   } catch (Exception exception) { 
                         System.out 
                                     .println("Error occurs while closing PreparedStatement : "); 
                   } 
             } 
       } 

 } 
 public void close() { 
       try { 
       connect.close(); 
       }catch(Exception exception) { 
             System.out.println("Error occurs while clossing the connection"); 
       } 
 } 
} 
```

1.  让我们在`com.stormadvance.logprocessing`包中创建一个`PersistenceBolt`类。这个类实现了`org.apache.storm.topology.IBasicBolt`。这个类调用`MySQLDump`类的`persistRecord(Tuple tuple)`方法来将记录/事件持久化到 MySQL。以下是`PersistenceBolt`类的源代码：

```scala
/** 
 * This Bolt call the getConnectionn(....) method of MySQLDump class to persist 
 * the record into MySQL database. 
 *  
 * @author Admin 
 *  
 */ 
public class PersistenceBolt implements IBasicBolt { 

 private MySQLDump mySQLDump = null; 
 private static final long serialVersionUID = 1L; 
 /** 
  * Name of database you want to connect 
  */ 
 private String database; 
 /** 
  * Name of MySQL user 
  */ 
 private String user; 
 /** 
  * IP of MySQL server 
  */ 
 private String ip; 
 /** 
  * Password of MySQL server 
  */ 
 private String password; 

 public PersistenceBolt(String ip, String database, String user, 
             String password) { 
       this.ip = ip; 
       this.database = database; 
       this.user = user; 
       this.password = password; 
 } 

 public void declareOutputFields(OutputFieldsDeclarer declarer) { 
 } 

 public Map<String, Object> getComponentConfiguration() { 
       return null; 
 } 

 public void prepare(Map stormConf, TopologyContext context) { 

       // create the instance of MySQLDump(....) class. 
       mySQLDump = new MySQLDump(ip, database, user, password); 
 } 

 /** 
  * This method call the persistRecord(input) method of MySQLDump class to 
  * persist record into MySQL. 
  */ 
 public void execute(Tuple input, BasicOutputCollector collector) { 
       System.out.println("Input tuple : " + input); 
       mySQLDump.persistRecord(input); 
 } 

 public void cleanup() { 
       // Close the connection 
       mySQLDump.close(); 
 } 

} 
```

在本节中，我们已经介绍了如何将输入元组插入数据存储中。

# Kafka spout 和定义拓扑

本节将解释如何从 Kafka 主题中读取 Apache 日志。本节还定义了将在前面各节中创建的所有 bolt 链接在一起的`LogProcessingTopology`。让我们执行以下步骤来消费来自 Kafka 的数据并定义拓扑：

1.  在`pom.xml`文件中添加以下 Kafka 的依赖和仓库：

```scala
       <dependency> 
             <groupId>org.apache.storm</groupId> 
             <artifactId>storm-kafka</artifactId> 
             <version>1.0.2</version> 
             <exclusions> 
                   <exclusion> 
                         <groupId>org.apache.kafka</groupId> 
                         <artifactId>kafka-clients</artifactId> 
                   </exclusion> 
             </exclusions> 
       </dependency> 

       <dependency> 
             <groupId>org.apache.kafka</groupId> 
             <artifactId>kafka_2.10</artifactId> 
             <version>0.9.0.1</version> 
             <exclusions> 
                   <exclusion> 
                         <groupId>com.sun.jdmk</groupId> 
                         <artifactId>jmxtools</artifactId> 
                   </exclusion> 
                   <exclusion> 
                         <groupId>com.sun.jmx</groupId> 
                         <artifactId>jmxri</artifactId> 
                   </exclusion> 
             </exclusions> 
       </dependency> 
```

1.  在`pom.xml`文件中添加以下`build`插件。这将让我们使用 Maven 执行`LogProcessingTopology`：

```scala
       <build> 
       <plugins> 
             <plugin> 
                   <artifactId>maven-assembly-plugin</artifactId> 
                   <configuration> 
                         <descriptorRefs> 
                               <descriptorRef>jar-with-
                               dependencies</descriptorRef> 
                         </descriptorRefs> 
                         <archive> 
                               <manifest> 
                                     <mainClass></mainClass> 
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

             <plugin> 
                   <groupId>org.codehaus.mojo</groupId> 
                   <artifactId>exec-maven-plugin</artifactId> 
                   <version>1.2.1</version> 
                   <executions> 
                         <execution> 
                               <goals> 
                                     <goal>exec</goal> 
                               </goals> 
                         </execution> 
                   </executions> 
                   <configuration> 
                         <executable>java</executable> 
                    <includeProjectDependencies>true</includeProjectDependencies> 
                    <includePluginDependencies>false</includePluginDependencies> 
                         <classpathScope>compile</classpathScope> 
                         <mainClass>${main.class}</mainClass> 
                   </configuration> 
             </plugin> 

             <plugin> 
                   <groupId>org.apache.maven.plugins</groupId> 
                   <artifactId>maven-compiler-plugin</artifactId> 
             </plugin> 

       </plugins> 
 </build> 
```

1.  在`com.stormadvance.logprocessing`包中创建一个`LogProcessingTopology`类。该类使用`org.apache.storm.topology.TopologyBuilder`类来定义拓扑。以下是`LogProcessingTopology`类的源代码及解释：

```scala
public class LogProcessingTopology { 
 public static void main(String[] args) throws Exception { 

       // zookeeper hosts for the Kafka cluster 
       BrokerHosts zkHosts = new ZkHosts("ZK:2183"); 

       // Create the KafkaSpout configuartion 
       // Second argument is the topic name 
       // Third argument is the zookeepr root for Kafka 
       // Fourth argument is consumer group id 
       SpoutConfig kafkaConfig = new SpoutConfig(zkHosts, "apache_log", "", 
                   "id2"); 

       // Specify that the Kafka messages are String 
       kafkaConfig.scheme = new SchemeAsMultiScheme(new StringScheme()); 

       // We want to consume all the first messages in the topic everytime 
       // we run the topology to help in debugging. In production, this 
       // property should be false 

       kafkaConfig.startOffsetTime = kafka.api.OffsetRequest 
                   .EarliestTime(); 

       // Now we create the topology 
       TopologyBuilder builder = new TopologyBuilder(); 

       // set the Kafka spout class 
       builder.setSpout("KafkaSpout", new KafkaSpout(kafkaConfig), 2); 

       // set the LogSplitter, IpToCountry, Keyword and PersistenceBolt bolts 
       // class. 
       builder.setBolt("LogSplitter", new ApacheLogSplitterBolt(), 1) 
                   .globalGrouping("KafkaSpout"); 

       builder.setBolt( 
                   "IpToCountry", 
                   new UserInformationGetterBolt( 
                               args[0]), 1) 
                   .globalGrouping("LogSplitter"); 
       builder.setBolt("Keyword", new KeyWordIdentifierBolt(), 1) 
                   .globalGrouping("IpToCountry"); 
       builder.setBolt("PersistenceBolt", 
                   new PersistenceBolt(args[1], args[2], args[3], args[4]), 
                   1).globalGrouping("Keyword"); 

       if (args.length == 6) { 
             // Run the topology on remote cluster. 
             Config conf = new Config(); 
             conf.setNumWorkers(4); 
             try { 
                   StormSubmitter.submitTopology(args[4], conf, 
                               builder.createTopology()); 
             } catch (AlreadyAliveException alreadyAliveException) { 
                   System.out.println(alreadyAliveException); 
             } catch (InvalidTopologyException invalidTopologyException) { 
                   System.out.println(invalidTopologyException); 
             } 
       } else { 
             // create an instance of LocalCluster class for executing topology 
             // in local mode. 
             LocalCluster cluster = new LocalCluster(); 
             Config conf = new Config(); 
             conf.setDebug(true); 
             // Submit topology for execution 
             cluster.submitTopology("KafkaToplogy1", conf, 
                         builder.createTopology()); 

             try { 
                   // Wait for sometime before exiting 
                   System.out 
                               .println("**********************Waiting to consume from kafka"); 
                   Thread.sleep(100000); 
                   System.out.println("Stopping the sleep thread"); 

             } catch (Exception exception) { 
                   System.out 
                               .println("******************Thread interrupted exception : " 
                                           + exception); 
             } 

             // kill the KafkaTopology 
             cluster.killTopology("KafkaToplogy1"); 

             // shutdown the storm test cluster 
             cluster.shutdown(); 

       } 

 } 
} 
```

本节介绍了如何将不同类型的 bolt 链接成拓扑。我们还介绍了如何从 Kafka 消费数据。在下一节中，我们将解释如何部署拓扑。

# 部署拓扑

本节将解释如何部署`LogProcessingTopology`。执行以下步骤：

1.  在 MySQL 控制台上执行以下命令定义数据库架构：

```scala
mysql> create database apachelog; 
mysql> use apachelog; 
mysql> create table apachelog( 
       id INT NOT NULL AUTO_INCREMENT, 
       ip VARCHAR(100) NOT NULL, 
       dateTime VARCHAR(200) NOT NULL, 
       request VARCHAR(100) NOT NULL, 
       response VARCHAR(200) NOT NULL, 
       bytesSent VARCHAR(200) NOT NULL, 
        referrer VARCHAR(500) NOT NULL, 
       useragent VARCHAR(500) NOT NULL, 
       country VARCHAR(200) NOT NULL, 
       browser VARCHAR(200) NOT NULL, 
       os VARCHAR(200) NOT NULL, 
       keyword VARCHAR(200) NOT NULL, 
       PRIMARY KEY (id) 
 ); 
```

1.  我假设您已经通过 Logstash 在`apache_log`主题上产生了一些数据。

1.  进入项目主目录并运行以下命令构建项目：

```scala
> mvn clean install -DskipTests 
```

1.  执行以下命令以在本地模式下启动日志处理拓扑：

```scala
> java -cp target/logprocessing-0.0.1-SNAPSHOT-jar-with-dependencies.jar:$STORM_HOME/storm-core-0.9.0.1.jar:$STORM_HOME/lib/* com.stormadvance.logprocessing.LogProcessingTopology path/to/GeoLiteCity.dat localhost apachelog root root 
```

1.  现在，进入 MySQL 控制台，检查`apachelog`表中的行：

```scala
mysql> select * from apachelog limit 2 
    -> ; 
+----+----------------+--------------------------+----------------+----------+-----------+-----------------------------------------+-----------------------------------------------------------------------------------------+---------------+----------------+-------+---------+ 
| id | ip             | dateTime                 | request        | response | bytesSent | referrer                                | useragent                                                                               | country       | browser        | os    | keyword | 
+----+----------------+--------------------------+----------------+----------+-----------+-----------------------------------------+-----------------------------------------------------------------------------------------+---------------+----------------+-------+---------+ 
|  1 | 24.25.135.19   | 1-01-2011:06:20:31 -0500 | GET / HTTP/1.1 | 200      | 864       | http://www.adeveloper.com/resource.html | Mozilla/5.0 (Windows; U; Windows NT 5.1; hu-HU; rv:1.7.12) Gecko/20050919 Firefox/1.0.7 | United States | Gecko(Firefox) | WinXP | NA      | 
|  2 | 180.183.50.208 | 1-01-2011:06:20:31 -0500 | GET / HTTP/1.1 | 200      | 864       | http://www.adeveloper.com/resource.html | Mozilla/5.0 (Windows; U; Windows NT 5.1; hu-HU; rv:1.7.12) Gecko/20050919 Firefox/1.0.7 | Thailand      | Gecko(Firefox) | WinXP | NA      | 
+----+----------------+--------------------------+----------------+----------+-----------+-----------------------------------------+-----------------------------------------------------------------------------------------+---------------+----------------+-------+---------+ 
```

在本节中，我们介绍了如何部署日志处理拓扑。下一节将解释如何从 MySQL 中存储的数据生成统计信息。

# MySQL 查询

本节将解释如何分析或查询存储数据以生成一些统计信息。我们将涵盖以下内容：

+   计算每个国家的页面点击量

+   计算每个浏览器的数量

+   计算每个操作系统的数量

# 计算每个国家的页面点击量

在 MySQL 控制台上运行以下命令，计算每个国家的页面点击量：

```scala
mysql> select country, count(*) from apachelog group by country; 
+---------------------------+----------+ 
| country                   | count(*) | 
+---------------------------+----------+ 
| Asia/Pacific Region       |        9 | 
| Belarus                   |       12 | 
| Belgium                   |       12 | 
| Bosnia and Herzegovina    |       12 | 
| Brazil                    |       36 | 
| Bulgaria                  |       12 | 
| Canada                    |      218 | 
| Europe                    |       24 | 
| France                    |       44 | 
| Germany                   |       48 | 
| Greece                    |       12 | 
| Hungary                   |       12 | 
| India                     |      144 | 
| Indonesia                 |       60 | 
| Iran, Islamic Republic of |       12 | 
| Italy                     |       24 | 
| Japan                     |       12 | 
| Malaysia                  |       12 | 
| Mexico                    |       36 | 
| NA                        |       10 | 
| Nepal                     |       24 | 
| Netherlands               |      164 | 
| Nigeria                   |       24 | 
| Puerto Rico               |       72 | 
| Russian Federation        |       60 | 
| Singapore                 |      165 | 
| Spain                     |       48 | 
| Sri Lanka                 |       12 | 
| Switzerland               |        7 | 
| Taiwan                    |       12 | 
| Thailand                  |       12 | 
| Ukraine                   |       12 | 
| United Kingdom            |       48 | 
| United States             |     5367 | 
| Vietnam                   |       12 | 
| Virgin Islands, U.S.      |      129 | 
+---------------------------+----------+ 
36 rows in set (0.08 sec) 
```

# 计算每个浏览器的数量

在 MySQL 控制台上运行以下命令，计算每个浏览器的数量：

```scala
mysql> select browser, count(*) from apachelog group by browser; 
+----------------+----------+ 
| browser        | count(*) | 
+----------------+----------+ 
| Gecko(Firefox) |     6929 | 
+----------------+----------+ 
1 row in set (0.00 sec)  
```

# 计算每个操作系统的数量

在 MySQL 控制台上运行以下命令，计算每个操作系统的数量：

```scala
mysql> select os,count(*) from apachelog group by os; 
+-------+----------+ 
| os    | count(*) | 
+-------+----------+ 
| WinXP |     6929 | 
+-------+----------+ 
1 row in set (0.00 sec) 
```

# 总结

在本章中，我们向您介绍了如何处理 Apache 日志文件，如何通过分析日志文件识别 IP 的国家名称，如何通过分析日志文件识别用户操作系统和浏览器，以及如何通过分析引荐字段识别搜索关键字。

在下一章中，我们将学习如何通过 Storm 解决机器学习问题。
