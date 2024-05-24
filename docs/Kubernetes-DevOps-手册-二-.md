# Kubernetes DevOps 手册（二）

> 原文：[`zh.annas-archive.org/md5/55C804BD2C19D0AE8370F4D1F28719E7`](https://zh.annas-archive.org/md5/55C804BD2C19D0AE8370F4D1F28719E7)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：处理存储和资源

在第三章 *开始使用 Kubernetes*中，我们介绍了 Kubernetes 的基本功能。一旦您开始通过 Kubernetes 部署一些容器，您需要考虑应用程序的数据生命周期和 CPU/内存资源管理。

在本章中，我们将讨论以下主题：

+   容器如何处理卷

+   介绍 Kubernetes 卷功能

+   Kubernetes 持久卷的最佳实践和陷阱

+   Kubernetes 资源管理

# Kubernetes 卷管理

Kubernetes 和 Docker 默认使用本地主机磁盘。Docker 应用程序可以将任何数据存储和加载到磁盘上，例如日志数据、临时文件和应用程序数据。只要主机有足够的空间，应用程序有必要的权限，数据将存在于容器存在的时间内。换句话说，当容器关闭时，应用程序退出、崩溃并重新分配容器到另一个主机时，数据将丢失。

# 容器卷的生命周期

为了理解 Kubernetes 卷管理，您需要了解 Docker 卷的生命周期。以下示例是当容器重新启动时 Docker 的行为：

```
//run CentOS Container
$ docker run -it centos

# ls
anaconda-post.log  dev  home  lib64       media  opt   root  sbin  sys  usr
bin                etc  lib   lost+found  mnt    proc  run   srv   tmp  var

//create one file (/I_WAS_HERE) at root directory
# touch /I_WAS_HERE
# ls /
I_WAS_HERE         bin  etc   lib    lost+found  mnt  proc  run   srv  tmp  var
anaconda-post.log  dev  home  lib64  media       opt  root  sbin  sys  usr 

//Exit container
# exit
exit 

//re-run CentOS Container
# docker run -it centos 

//previous file (/I_WAS_HERE) was disappeared
# ls /
anaconda-post.log  dev  home  lib64       media  opt   root  sbin  sys  usr
bin                etc  lib   lost+found  mnt    proc  run   srv   tmp  var  
```

在 Kubernetes 中，还需要关心 pod 的重新启动。在资源短缺的情况下，Kubernetes 可能会停止一个容器，然后在同一个或另一个 Kubernetes 节点上重新启动一个容器。

以下示例显示了当资源短缺时 Kubernetes 的行为。当收到内存不足错误时，一个 pod 被杀死并重新启动：

```

//there are 2 pod on the same Node
$ kubectl get pods
NAME                          READY     STATUS    RESTARTS   AGE
Besteffort                    1/1       Running   0          1h
guaranteed                    1/1       Running   0          1h 

//when application consumes a lot of memory, one Pod has been killed
$ kubectl get pods
NAME                          READY     STATUS    RESTARTS   AGE
Besteffort                    0/1       Error     0          1h
guaranteed                    1/1       Running   0          1h 

//clashed Pod is restarting
$ kubectl get pods
NAME                          READY     STATUS             RESTARTS   AGE
Besteffort                    0/1       CrashLoopBackOff   0          1h
guaranteed                    1/1       Running            0          1h

//few moment later, Pod has been restarted 
$ kubectl get pods
NAME                          READY     STATUS    RESTARTS   AGE
Besteffort                    1/1       Running   1          1h
guaranteed                    1/1       Running   0          1h

```

# 在一个 pod 内部在容器之间共享卷

第三章 *开始使用 Kubernetes*描述了同一个 Kubernetes pod 中的多个容器可以共享相同的 pod IP 地址、网络端口和 IPC，因此，应用程序可以通过本地网络相互通信；但是，文件系统是分隔的。

以下图表显示了**Tomcat**和**nginx**在同一个 pod 中。这些应用程序可以通过本地主机相互通信。但是，它们无法访问彼此的`config`文件：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00046.jpeg)

一些应用程序不会影响这些场景和行为，但有些应用程序可能有一些使用案例，需要它们使用共享目录或文件。因此，开发人员和 Kubernetes 管理员需要了解不同类型的无状态和有状态应用程序。

# 无状态和有状态的应用程序

就无状态应用程序而言，在这种情况下使用临时卷。容器上的应用程序不需要保留数据。虽然无状态应用程序可能会在容器存在时将数据写入文件系统，但在应用程序的生命周期中并不重要。

例如，`tomcat`容器运行一些 Web 应用程序。它还在`/usr/local/tomcat/logs/`下写入应用程序日志，但如果丢失`log`文件，它不会受到影响。

但是，如果您开始分析应用程序日志呢？需要出于审计目的保留吗？在这种情况下，Tomcat 仍然可以是无状态的，但可以将`/usr/local/tomcat/logs`卷与 Logstash 等另一个容器共享（[`www.elastic.co/products/logstash`](https://www.elastic.co/products/logstash)）。然后 Logstash 将日志发送到所选的分析存储，如 Elasticsearch（[`www.elastic.co/products/elasticsearch`](https://www.elastic.co/products/elasticsearch)）。

在这种情况下，`tomcat`容器和`logstash`容器*必须在同一个 Kubernetes pod 中*，并共享`/usr/local/tomcat/logs`卷，如下所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00047.jpeg)

上图显示了 Tomcat 和 Logstash 如何使用 Kubernetes 的`emptyDir`卷共享`log`文件（[`kubernetes.io/docs/concepts/storage/volumes/#emptydir)`](https://kubernetes.io/docs/concepts/storage/volumes/)。

Tomcat 和 Logstash 没有通过 localhost 使用网络，而是通过 Kubernetes 的`emptyDir`卷在 Tomcat 容器的`/usr/local/tomcat/logs`和 Logstash 容器的`/mnt`之间共享文件系统：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00048.jpeg)

让我们创建`tomcat`和`logstash` pod，然后看看 Logstash 是否能在`/mnt`下看到 Tomcat 应用程序日志：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00049.jpeg)

在这种情况下，最终目的地的 Elasticsearch 必须是有状态的。有状态意味着使用持久卷。即使容器重新启动，Elasticsearch 容器也必须保留数据。此外，您不需要在同一个 pod 中配置 Elasticsearch 容器和 Tomcat/Logstash。因为 Elasticsearch 应该是一个集中的日志数据存储，它可以与 Tomcat/Logstash pod 分开，并独立扩展。

一旦确定您的应用程序需要持久卷，就有一些不同类型的卷和不同的管理持久卷的方法。

# Kubernetes 持久卷和动态配置

Kubernetes 支持各种持久卷。例如，公共云存储，如 AWS EBS 和 Google 持久磁盘。它还支持网络（分布式）文件系统，如 NFS，GlusterFS 和 Ceph。此外，它还可以支持诸如 iSCSI 和光纤通道之类的块设备。根据环境和基础架构，Kubernetes 管理员可以选择最匹配的持久卷类型。

以下示例使用 GCP 持久磁盘作为持久卷。第一步是创建一个 GCP 持久磁盘，并将其命名为`gce-pd-1`。

如果使用 AWS EBS 或 Google 持久磁盘，则 Kubernetes 节点必须位于 AWS 或 Google 云平台中。![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00050.jpeg)

然后在`Deployment`定义中指定名称`gce-pd-1`：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00051.jpeg)

它将从 GCE 持久磁盘挂载到`/usr/local/tomcat/logs`，可以持久保存 Tomcat 应用程序日志。

# 持久卷索赔抽象层

将持久卷直接指定到配置文件中，这将与特定基础架构紧密耦合。在先前的示例中，这是谷歌云平台，也是磁盘名称（`gce-pd-1`）。从容器管理的角度来看，pod 定义不应该锁定到特定环境，因为基础架构可能会根据环境而不同。理想的 pod 定义应该是灵活的，或者抽象出实际的基础架构，只指定卷名称和挂载点。

因此，Kubernetes 提供了一个抽象层，将 pod 与持久卷关联起来，称为**持久卷索赔**（**PVC**）。它允许我们与基础架构解耦。Kubernetes 管理员只需预先分配必要大小的持久卷。然后 Kubernetes 将在持久卷和 PVC 之间进行绑定：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00052.jpeg)

以下示例是使用 PVC 的 pod 的定义；让我们首先重用之前的例子（`gce-pd-1`）在 Kubernetes 中注册：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00053.jpeg)

然后，创建一个与持久卷（`pv-1`）关联的 PVC。

请注意，将其设置为`storageClassName: ""`意味着它应明确使用静态配置。一些 Kubernetes 环境，如**Google 容器引擎**（**GKE**），已经设置了动态配置。如果我们不指定`storageClassName: ""`，Kubernetes 将忽略现有的`PersistentVolume`，并在创建`PersistentVolumeClaim`时分配新的`PersistentVolume`。![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00054.jpeg)

现在，`tomcat`设置已经与特定卷“`pvc-1`”解耦：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00055.jpeg)

# 动态配置和 StorageClass

PVC 为持久卷管理提供了一定程度的灵活性。然而，预先分配一些持久卷池可能不够成本效益，特别是在公共云中。

Kubernetes 还通过支持持久卷的动态配置来帮助这种情况。Kubernetes 管理员定义了持久卷的*provisioner*，称为`StorageClass`。然后，持久卷索赔要求`StorageClass`动态分配持久卷，然后将其与 PVC 关联起来：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00056.jpeg)

在下面的例子中，AWS EBS 被用作`StorageClass`，然后，在创建 PVC 时，`StorageClass`动态创建 EBS 并将其注册到 Kubernetes 持久卷，然后附加到 PVC：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00057.jpeg)

一旦`StorageClass`成功创建，就可以创建一个不带 PV 的 PVC，但要指定`StorageClass`的名称。在这个例子中，这将是"`aws-sc`"，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00058.jpeg)

然后，PVC 要求`StorageClass`在 AWS 上自动创建持久卷，如下所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00059.jpeg)

请注意，诸如 kops（[`github.com/kubernetes/kops`](https://github.com/kubernetes/kops)）和 Google 容器引擎（[`cloud.google.com/container-engine/`](https://cloud.google.com/container-engine/)）等 Kubernetes 配置工具默认会创建`StorageClass`。例如，kops 在 AWS 环境上设置了默认的 AWS EBS `StorageClass`。Google 容器引擎在 GKE 上设置了 Google Cloud 持久磁盘。有关更多信息，请参阅第九章，*在 AWS 上使用 Kubernetes*和第十章，*在 GCP 上使用 Kubernetes*：

```
//default Storage Class on AWS
$ kubectl get sc
NAME            TYPE
default         kubernetes.io/aws-ebs
gp2 (default)   kubernetes.io/aws-ebs

//default Storage Class on GKE
$ kubectl get sc
NAME                 TYPE
standard (default)   kubernetes.io/gce-pd   
```

# 临时和持久设置的问题案例

您可能会将您的应用程序确定为无状态，因为`datastore`功能由另一个 pod 或系统处理。然而，有时应用程序实际上存储了您不知道的重要文件。例如，Grafana（[`grafana.com/grafana`](https://grafana.com/grafana)），它连接时间序列数据源，如 Graphite（[`graphiteapp.org`](https://graphiteapp.org)）和 InfluxDB（[`www.influxdata.com/time-series-database/`](https://www.influxdata.com/time-series-database/)），因此人们可以确定 Grafana 是否是一个无状态应用程序。

然而，Grafana 本身也使用数据库来存储用户、组织和仪表板元数据。默认情况下，Grafana 使用 SQLite3 组件，并将数据库存储为`/var/lib/grafana/grafana.db`。因此，当容器重新启动时，Grafana 设置将被全部重置。

以下示例演示了 Grafana 在临时卷上的行为：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00060.jpeg)

让我们创建一个名为`kubernetes org`的 Grafana `organizations`，如下所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00061.jpeg)

然后，看一下`Grafana`目录，有一个数据库文件（`/var/lib/grafana/grafana.db`）的时间戳，在创建 Grafana `organization`之后已经更新：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00062.jpeg)

当 pod 被删除时，ReplicaSet 将启动一个新的 pod，并检查 Grafana `organization`是否存在：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00063.jpeg)

看起来`sessions`目录已经消失，`grafana.db`也被 Docker 镜像重新创建。然后，如果您访问 Web 控制台，Grafana `organization`也会消失：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00064.jpeg)

仅使用持久卷来处理 Grafana 呢？但是使用带有持久卷的 ReplicaSet，它无法正确地复制（扩展）。因为所有的 pod 都试图挂载相同的持久卷。在大多数情况下，只有第一个 pod 可以挂载持久卷，然后另一个 pod 会尝试挂载，如果无法挂载，它将放弃。如果持久卷只能支持 RWO（只能有一个 pod 写入），就会发生这种情况。

在以下示例中，Grafana 使用持久卷挂载`/var/lib/grafana`；但是，它无法扩展，因为 Google 持久磁盘是 RWO：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00065.jpeg)

即使持久卷具有 RWX（多个 pod 可以同时挂载以读写），比如 NFS，如果多个 pod 尝试绑定相同的卷，它也不会抱怨。但是，我们仍然需要考虑多个应用程序实例是否可以使用相同的文件夹/文件。例如，如果将 Grafana 复制到两个或更多的 pod 中，它将与尝试写入相同的`/var/lib/grafana/grafana.db`的多个 Grafana 实例发生冲突，然后数据可能会损坏，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00066.jpeg)

在这种情况下，Grafana 必须使用后端数据库，如 MySQL 或 PostgreSQL，而不是 SQLite3。这样可以使多个 Grafana 实例正确读写 Grafana 元数据。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00067.jpeg)

因为关系型数据库基本上支持通过网络连接多个应用程序实例，因此，这种情况非常适合多个 pod 使用。请注意，Grafana 支持使用关系型数据库作为后端元数据存储；但是，并非所有应用程序都支持关系型数据库。

对于使用 MySQL/PostgreSQL 的 Grafana 配置，请访问在线文档：

[`docs.grafana.org/installation/configuration/#database`](http://docs.grafana.org/installation/configuration/#database)。

因此，Kubernetes 管理员需要仔细监视应用程序在卷上的行为。并且要了解，在某些情况下，仅使用持久卷可能无法帮助，因为在扩展 pod 时可能会出现问题。

如果多个 pod 需要访问集中式卷，则考虑使用先前显示的数据库（如果适用）。另一方面，如果多个 pod 需要单独的卷，则考虑使用 StatefulSet。

# 使用 StatefulSet 复制具有持久卷的 pod

StatefulSet 在 Kubernetes 1.5 中引入；它由 Pod 和持久卷之间的绑定组成。当扩展增加或减少 Pod 时，Pod 和持久卷会一起创建或删除。

此外，Pod 的创建过程是串行的。例如，当请求 Kubernetes 扩展两个额外的 StatefulSet 时，Kubernetes 首先创建**持久卷索赔 1**和**Pod 1**，然后创建**持久卷索赔 2**和**Pod 2**，但不是同时进行。如果应用程序在应用程序引导期间注册到注册表，这将有助于管理员：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00068.jpeg)

即使一个 Pod 死掉，StatefulSet 也会保留 Pod 的位置（Pod 名称、IP 地址和相关的 Kubernetes 元数据），并且持久卷也会保留。然后，它会尝试重新创建一个容器，重新分配给同一个 Pod 并挂载相同的持久卷。

使用 Kubernetes 调度程序有助于保持 Pod/持久卷的数量和应用程序保持在线：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00069.jpeg)

具有持久卷的 StatefulSet 需要动态配置和`StorageClass`，因为 StatefulSet 可以进行扩展。当添加更多的 Pod 时，Kubernetes 需要知道如何配置持久卷。

# 持久卷示例

在本章中，介绍了一些持久卷示例。根据环境和场景，Kubernetes 管理员需要正确配置 Kubernetes。

以下是使用不同角色节点构建 Elasticsearch 集群以配置不同类型的持久卷的一些示例。它们将帮助您决定如何配置和管理持久卷。

# Elasticsearch 集群场景

Elasticsearch 能够通过使用多个节点来设置集群。截至 Elasticsearch 版本 2.4，有几种不同类型的节点，如主节点、数据节点和协调节点（[`www.elastic.co/guide/en/elasticsearch/reference/2.4/modules-node.html`](https://www.elastic.co/guide/en/elasticsearch/reference/2.4/modules-node.html)）。每个节点在集群中有不同的角色和责任，因此相应的 Kubernetes 配置和持久卷应该与适当的设置保持一致。

以下图表显示了 Elasticsearch 节点的组件和角色。主节点是集群中唯一管理所有 Elasticsearch 节点注册和配置的节点。它还可以有一个备用节点（有资格成为主节点的节点），可以随时充当主节点：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00070.jpeg)

数据节点在 Elasticsearch 中保存和操作数据存储。协调节点处理来自其他应用程序的 HTTP 请求，然后进行负载均衡/分发到数据节点。

# Elasticsearch 主节点

主节点是集群中唯一的节点。此外，其他节点需要指向主节点进行注册。因此，主节点应该使用 Kubernetes StatefulSet 来分配一个稳定的 DNS 名称，例如`es-master-1`。因此，我们必须使用 Kubernetes 服务以无头模式分配 DNS，直接将 DNS 名称分配给 pod IP 地址。

另一方面，如果不需要持久卷，因为主节点不需要持久化应用程序的数据。

# Elasticsearch 有资格成为主节点的节点

有资格成为主节点的节点是主节点的备用节点，因此不需要创建另一个`Kubernetes`对象。这意味着扩展主 StatefulSet 分配`es-master-2`、`es-master-3`和`es-master-N`就足够了。当主节点不响应时，在有资格成为主节点的节点中进行主节点选举，选择并提升一个节点为主节点。

# Elasticsearch 数据节点

Elasticsearch 数据节点负责存储数据。此外，如果需要更大的数据容量和/或更多的查询请求，我们需要进行横向扩展。因此，我们可以使用带有持久卷的 StatefulSet 来稳定 pod 和持久卷。另一方面，不需要有 DNS 名称，因此也不需要为 Elasticsearch 数据节点设置 Kubernetes 服务。

# Elasticsearch 协调节点

协调节点是 Elasticsearch 中的负载均衡器角色。因此，我们需要进行横向扩展以处理来自外部来源的 HTTP 流量，并且不需要持久化数据。因此，我们可以使用带有 Kubernetes 服务的 Kubernetes ReplicaSet 来将 HTTP 暴露给外部服务。

以下示例显示了我们在 Kubernetes 中创建所有上述 Elasticsearch 节点时使用的命令：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00071.jpeg)

此外，以下截图是我们在创建上述实例后获得的结果：

！[](../images/00072.jpeg)![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00073.jpeg)

在这种情况下，外部服务（Kubernetes 节点：`30020`）是外部应用程序的入口点。为了测试目的，让我们安装`elasticsearch-head`（[`github.com/mobz/elasticsearch-head`](https://github.com/mobz/elasticsearch-head)）来可视化集群信息。

将 Elasticsearch 协调节点连接到安装`elasticsearch-head`插件：

！[](../images/00074.jpeg)

然后，访问任何 Kubernetes 节点，URL 为`http://<kubernetes-node>:30200/_plugin/head`。以下 UI 包含集群节点信息：

！[](../images/00075.jpeg)

星形图标表示 Elasticsearch 主节点，三个黑色子弹是数据节点，白色圆形子弹是协调节点。

在这种配置中，如果一个数据节点宕机，不会发生任何服务影响，如下面的片段所示：

```
//simulate to occur one data node down 
$ kubectl delete pod es-data-0
pod "es-data-0" deleted
```

！[](../images/00076.jpeg)

几分钟后，新的 pod 挂载相同的 PVC，保留了`es-data-0`的数据。然后 Elasticsearch 数据节点再次注册到主节点，之后集群健康状态恢复为绿色（正常），如下面的截图所示：

！[](../images/00077.jpeg)

由于 StatefulSet 和持久卷，应用程序数据不会丢失在`es-data-0`上。如果需要更多的磁盘空间，增加数据节点的数量。如果需要支持更多的流量，增加协调节点的数量。如果需要备份主节点，增加主节点的数量以使一些主节点有资格。

总的来说，StatefulSet 的持久卷组合非常强大，可以使应用程序灵活和可扩展。

# Kubernetes 资源管理

第三章，*开始使用 Kubernetes*提到 Kubernetes 有一个调度程序来管理 Kubernetes 节点，然后确定在哪里部署一个 pod。当节点有足够的资源，如 CPU 和内存时，Kubernetes 管理员可以随意部署应用程序。然而，一旦达到资源限制，Kubernetes 调度程序根据其配置行为不同。因此，Kubernetes 管理员必须了解如何配置和利用机器资源。

# 资源服务质量

Kubernetes 有**资源 QoS**（**服务质量**）的概念，它可以帮助管理员通过不同的优先级分配和管理 pod。根据 pod 的设置，Kubernetes 将每个 pod 分类为：

+   Guaranteed pod

+   Burstable pod

+   BestEffort pod

优先级将是 Guaranteed > Burstable > BestEffort，这意味着如果 BestEffort pod 和 Guaranteed pod 存在于同一节点中，那么当其中一个 pod 消耗内存并导致节点资源短缺时，将终止其中一个 BestEffort pod 以保存 Guaranteed pod。

为了配置资源 QoS，您必须在 pod 定义中设置资源请求和/或资源限制。以下示例是 nginx 的资源请求和资源限制的定义：

```
$ cat burstable.yml  
apiVersion: v1 
kind: Pod 
metadata: 
  name: burstable-pod 
spec: 
  containers: 
  - name: nginx 
    image: nginx 
    resources: 
      requests: 
        cpu: 0.1 
        memory: 10Mi 
      limits: 
        cpu: 0.5 
        memory: 300Mi 
```

此示例指示以下内容：

| **资源定义类型** | **资源名称** | **值** | **含义** |
| --- | --- | --- | --- |
| `requests` | `cpu` | `0.1` | 至少 10%的 1 个 CPU 核心 |
|  | `memory` | `10Mi` | 至少 10 兆字节的内存 |
| `limits` | `cpu` | `0.5` | 最大 50%的 1 个 CPU 核心 |
|  | `memory` | `300Mi` | 最大 300 兆字节的内存 |

对于 CPU 资源，可接受的值表达式为核心（0.1、0.2……1.0、2.0）或毫核（100m、200m……1000m、2000m）。1000m 相当于 1 个核心。例如，如果 Kubernetes 节点有 2 个核心 CPU（或 1 个带超线程的核心），则总共有 2.0 个核心或 2000 毫核，如下所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00078.jpeg)

如果运行 nginx 示例（`requests.cpu: 0.1`），它至少占用 0.1 个核心，如下图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00079.jpeg)

只要 CPU 有足够的空间，它可以占用最多 0.5 个核心（`limits.cpu: 0.5`），如下图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00080.jpeg)

您还可以使用`kubectl describe nodes`命令查看配置，如下所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00081.jpeg)

请注意，它显示的百分比取决于前面示例中 Kubernetes 节点的规格；如您所见，该节点有 1 个核心和 600 MB 内存。

另一方面，如果超出了内存限制，Kubernetes 调度程序将确定该 pod 内存不足，然后它将终止一个 pod（`OOMKilled`）：

```

//Pod is reaching to the memory limit
$ kubectl get pods
NAME            READY     STATUS    RESTARTS   AGE
burstable-pod   1/1       Running   0          10m

//got OOMKilled
$ kubectl get pods
NAME            READY     STATUS      RESTARTS   AGE
burstable-pod   0/1       OOMKilled   0          10m

//restarting Pod
$ kubectl get pods
NAME            READY     STATUS      RESTARTS   AGE
burstable-pod   0/1       CrashLoopBackOff   0   11m 

//restarted
$ kubectl get pods
NAME            READY     STATUS    RESTARTS   AGE
burstable-pod   1/1       Running   1          12m  
```

# 配置 BestEffort pod

BestEffort pod 在资源 QoS 配置中具有最低的优先级。因此，在资源短缺的情况下，该 pod 将是第一个被终止的。使用 BestEffort 的用例可能是无状态和可恢复的应用程序，例如：

+   Worker process

+   代理或缓存节点

在资源短缺的情况下，该 pod 应该将 CPU 和内存资源让给其他优先级更高的 pod。为了将 pod 配置为 BestEffort pod，您需要将资源限制设置为 0，或者不指定资源限制。例如：

```
//no resource setting
$ cat besteffort-implicit.yml 
apiVersion: v1
kind: Pod
metadata:
 name: besteffort
spec:
 containers:
 - name: nginx
 image: nginx

//resource limit setting as 0
$ cat besteffort-explicit.yml 
apiVersion: v1
kind: Pod
metadata:
 name: besteffort
spec:
 containers:
 - name: nginx
 image: nginx
 resources:
 limits:
      cpu: 0
      memory: 0
```

请注意，资源设置是由`namespace default`设置继承的。因此，如果您打算使用隐式设置将 pod 配置为 BestEffort pod，如果命名空间具有以下默认资源设置，则可能不会配置为 BestEffort：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00082.jpeg)

在这种情况下，如果您使用隐式设置部署到默认命名空间，它将应用默认的 CPU 请求，如`request.cpu: 0.1`，然后它将变成 Burstable。另一方面，如果您部署到`blank-namespace`，应用`request.cpu: 0`，然后它将变成 BestEffort。

# 配置为 Guaranteed pod

Guaranteed 是资源 QoS 中的最高优先级。在资源短缺的情况下，Kubernetes 调度程序将尽力保留 Guaranteed pod 到最后。

因此，Guaranteed pod 的使用将是诸如任务关键节点之类的节点：

+   带有持久卷的后端数据库

+   主节点（例如 Elasticsearch 主节点和 HDFS 名称节点）

为了将其配置为 Guaranteed pod，明确设置资源限制和资源请求为相同的值，或者只设置资源限制。然而，再次强调，如果命名空间具有默认资源设置，可能会导致不同的结果：

```
$ cat guaranteed.yml 
apiVersion: v1
kind: Pod
metadata:
 name: guaranteed-pod
spec:
 containers:
   - name: nginx
     image: nginx
     resources:
      limits:
       cpu: 0.3
       memory: 350Mi
      requests:
       cpu: 0.3
       memory: 350Mi

$ kubectl get pods
NAME             READY     STATUS    RESTARTS   AGE
guaranteed-pod   1/1       Running   0          52s

$ kubectl describe pod guaranteed-pod | grep -i qos
QoS Class:  Guaranteed
```

因为 Guaranteed pod 必须设置资源限制，如果您对应用程序的必要 CPU/内存资源不是 100%确定，特别是最大内存使用量；您应该使用 Burstable 设置一段时间来监视应用程序的行为。否则，即使节点有足够的内存，Kubernetes 调度程序也可能终止 pod（`OOMKilled`）。

# 配置为 Burstable pod

Burstable pod 的优先级高于 BestEffort，但低于 Guaranteed。与 Guaranteed pod 不同，资源限制设置不是强制性的；因此，在节点资源可用时，pod 可以尽可能地消耗 CPU 和内存。因此，它适用于任何类型的应用程序。

如果您已经知道应用程序的最小内存大小，您应该指定请求资源，这有助于 Kubernetes 调度程序分配到正确的节点。例如，有两个节点，每个节点都有 1GB 内存。节点 1 已经分配了 600MB 内存，节点 2 分配了 200MB 内存给其他 pod。

如果我们创建一个请求内存资源为 500 MB 的 pod，那么 Kubernetes 调度器会将此 pod 分配给节点 2。但是，如果 pod 没有资源请求，结果将在节点 1 或节点 2 之间变化。因为 Kubernetes 不知道这个 pod 将消耗多少内存：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00083.jpeg)

还有一个重要的资源 QoS 行为需要讨论。资源 QoS 单位的粒度是 pod 级别，而不是容器级别。这意味着，如果您配置了一个具有两个容器的 pod，您打算将容器 A 设置为保证的（请求/限制值相同），容器 B 是可突发的（仅设置请求）。不幸的是，Kubernetes 会将此 pod 配置为可突发，因为 Kubernetes 不知道容器 B 的限制是多少。

以下示例表明未能配置为保证的 pod，最终配置为可突发的：

```
// supposed nginx is Guaranteed, tomcat as Burstable...
$ cat guaranteed-fail.yml 
apiVersion: v1
kind: Pod
metadata:
 name: burstable-pod
spec:
  containers:
  - name: nginx
    image: nginx
    resources:
     limits:
       cpu: 0.3
       memory: 350Mi
     requests:
       cpu: 0.3
       memory: 350Mi
  - name: tomcat
    image: tomcat
    resources:
      requests:
       cpu: 0.2
       memory: 100Mi

$ kubectl create -f guaranteed-fail.yml 
pod "guaranteed-fail" created

//at the result, Pod is configured as Burstable
$ kubectl describe pod guaranteed-fail | grep -i qos
QoS Class:  Burstable
```

即使改为仅配置资源限制，但如果容器 A 只有 CPU 限制，容器 B 只有内存限制，那么结果也会再次变为可突发，因为 Kubernetes 只知道限制之一：

```
//nginx set only cpu limit, tomcat set only memory limit
$ cat guaranteed-fail2.yml 
apiVersion: v1
kind: Pod
metadata:
 name: guaranteed-fail2
spec:
 containers:
  - name: nginx
    image: nginx
    resources:
      limits:
       cpu: 0.3
  - name: tomcat
    image: tomcat
    resources:
      requests:
       memory: 100Mi

$ kubectl create -f guaranteed-fail2.yml 
pod "guaranteed-fail2" created

//result is Burstable again
$ kubectl describe pod |grep -i qos
QoS Class:  Burstable
```

因此，如果您打算将 pod 配置为保证的，必须将所有容器设置为保证的。

# 监控资源使用

当您开始配置资源请求和/或限制时，由于资源不足，您的 pod 可能无法被 Kubernetes 调度器部署。为了了解可分配资源和可用资源，请使用 `kubectl describe nodes` 命令查看状态。

以下示例显示一个节点有 600 MB 内存和一个核心 CPU。因此，可分配资源如下：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00084.jpeg)

然而，这个节点已经运行了一些可突发的 pod（使用资源请求）如下：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00085.jpeg)

可用内存约为 20 MB。因此，如果您提交了请求超过 20 MB 的可突发的 pod，它将永远不会被调度，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00086.jpeg)

错误事件可以通过 `kubectl describe pod` 命令捕获：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00087.jpeg)

在这种情况下，您需要添加更多的 Kubernetes 节点来支持更多的资源。

# 总结

在本章中，我们已经涵盖了使用临时卷或持久卷的无状态和有状态应用程序。当应用程序重新启动或 pod 扩展时，两者都存在缺陷。此外，Kubernetes 上的持久卷管理已经得到增强，使其更容易，正如您可以从 StatefulSet 和动态配置等工具中看到的那样。

此外，资源 QoS 帮助 Kubernetes 调度器根据优先级基于请求和限制将 pod 分配给正确的节点。

下一章将介绍 Kubernetes 网络和安全性，这将使 pod 和服务的配置更加简单，并使它们更具可扩展性和安全性。


# 第五章：网络和安全

我们已经学会了如何在 Kubernetes 中部署具有不同资源的容器，在第三章 *开始使用 Kubernetes*中，以及如何使用卷来持久化数据，动态配置和不同的存储类。接下来，我们将学习 Kubernetes 如何路由流量，使所有这些成为可能。网络在软件世界中始终扮演着重要角色。我们将描述从单个主机上的容器到多个主机，最终到 Kubernetes 的网络。

+   Docker 网络

+   Kubernetes 网络

+   入口

+   网络策略

# Kubernetes 网络

在 Kubernetes 中，您有很多选择来实现网络。Kubernetes 本身并不关心您如何实现它，但您必须满足其三个基本要求：

+   所有容器应该彼此可访问，无需 NAT，无论它们在哪个节点上

+   所有节点应该与所有容器通信

+   IP 容器应该以其他人看待它的方式看待自己

在进一步讨论之前，我们首先会回顾默认容器网络是如何工作的。这是使所有这些成为可能的网络支柱。

# Docker 网络

在深入研究 Kubernetes 网络之前，让我们回顾一下 Docker 网络。在第二章 *使用容器进行 DevOps*中，我们学习了容器网络的三种模式，桥接，无和主机。

桥接是默认的网络模型。Docker 创建并附加虚拟以太网设备（也称为 veth），并为每个容器分配网络命名空间。

**网络命名空间**是 Linux 中的一个功能，它在逻辑上是网络堆栈的另一个副本。它有自己的路由表、arp 表和网络设备。这是容器网络的基本概念。

Veth 总是成对出现，一个在网络命名空间中，另一个在桥接中。当流量进入主机网络时，它将被路由到桥接中。数据包将被分派到它的 veth，并进入容器内部的命名空间，如下图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00088.jpeg)

让我们仔细看看。在以下示例中，我们将使用 minikube 节点作为 docker 主机。首先，我们必须使用`minikube ssh`来 ssh 进入节点，因为我们还没有使用 Kubernetes。进入 minikube 节点后，让我们启动一个容器与我们进行交互：

```
// launch a busybox container with `top` command, also, expose container port 8080 to host port 8000.
# docker run -d -p 8000:8080 --name=busybox busybox top
737e4d87ba86633f39b4e541f15cd077d688a1c8bfb83156d38566fc5c81f469 
```

让我们看看容器内部的出站流量实现。`docker exec <container_name or container_id>`可以在运行中的容器中运行命令。让我们使用`ip link list`列出所有接口：

```
// show all the network interfaces in busybox container
// docker exec <container_name> <command>
# docker exec busybox ip link list
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue qlen 1
 link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: sit0@NONE: <NOARP> mtu 1480 qdisc noop qlen 1
 link/sit 0.0.0.0 brd 0.0.0.0
53**: **eth0@if54**: <BROADCAST,MULTICAST,UP,LOWER_UP,M-DOWN> 
    mtu 1500 qdisc noqueue
 link/ether 02:42:ac:11:00:07 brd ff:ff:ff:ff:ff:ff  
```

我们可以看到`busybox`容器内有三个接口。其中一个是 ID 为`53`的接口，名称为`eth0@if54`。`if`后面的数字是配对中的另一个接口 ID。在这种情况下，配对 ID 是`54`。如果我们在主机上运行相同的命令，我们可以看到主机中的 veth 指向容器内的`eth0`。

```
// show all the network interfaces from the host
# ip link list
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue  
   state UNKNOWN mode DEFAULT group default qlen 1
 link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc 
   pfifo_fast state UP mode DEFAULT group default qlen  
   1000
 link/ether 08:00:27:ca:fd:37 brd ff:ff:ff:ff:ff:ff
...
54**: **vethfeec36a@if53**: <BROADCAST,MULTICAST,UP,LOWER_UP> 
    mtu 1500 qdisc noqueue master docker0 state UP mode  
    DEFAULT group default
 link/ether ce:25:25:9e:6c:07 brd ff:ff:ff:ff:ff:ff link-netnsid 5  
```

主机上有一个名为`vethfeec36a@if53`的 veth**。**它与容器网络命名空间中的`eth0@if54`配对。veth 54 连接到`docker0`桥接口，并最终通过 eth0 访问互联网。如果我们查看 iptables 规则，我们可以找到 Docker 为出站流量创建的伪装规则（也称为 SNAT），这将使容器可以访问互联网：

```
// list iptables nat rules. Showing only POSTROUTING rules which allows packets to be altered before they leave the host.
# sudo iptables -t nat -nL POSTROUTING
Chain POSTROUTING (policy ACCEPT)
target     prot opt source               destination
...
MASQUERADE  all  --  172.17.0.0/16        0.0.0.0/0
...  
```

另一方面，对于入站流量，Docker 在预路由上创建自定义过滤器链，并动态创建`DOCKER`过滤器链中的转发规则。如果我们暴露一个容器端口`8080`并将其映射到主机端口`8000`，我们可以看到我们正在监听任何 IP 地址（`0.0.0.0/0`）的端口`8000`，然后将其路由到容器端口`8080`：

```
// list iptables nat rules
# sudo iptables -t nat -nL
Chain PREROUTING (policy ACCEPT)
target     prot opt source               destination
...
DOCKER     all  --  0.0.0.0/0            0.0.0.0/0            ADDRTYPE match dst-type LOCAL
...
Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination
DOCKER     all  --  0.0.0.0/0           !127.0.0.0/8          ADDRTYPE match dst-type LOCAL
...
Chain DOCKER (2 references)
target     prot opt source               destination
RETURN     all  --  0.0.0.0/0            0.0.0.0/0
...
DNAT       tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:8000 to:172.17.0.7:8080
...  
```

现在我们知道数据包如何进出容器。让我们看看 pod 中的容器如何相互通信。

# 容器间通信

Kubernetes 中的 Pod 具有自己的真实 IP 地址。Pod 中的容器共享网络命名空间，因此它们将彼此视为*localhost*。这是默认情况下由**网络容器**实现的，它充当桥接口以为 pod 中的每个容器分发流量。让我们看看以下示例中的工作原理。让我们使用第三章中的第一个示例，*开始使用 Kubernetes*，其中包括一个 pod 中的两个容器，`nginx`和`centos`：

```
#cat 5-1-1_pod.yaml
apiVersion: v1
kind: Pod
metadata:
 name: example
spec:
 containers:
 - name: web
 image: nginx
 - name: centos
 image: centos
 command: ["/bin/sh", "-c", "while : ;do curl http://localhost:80/; sleep 10; done"]

// create the Pod
#kubectl create -f 5-1-1_pod.yaml
pod "example" created  
```

然后，我们将描述 pod 并查看其容器 ID：

```
# kubectl describe pods example
Name:       example
Node:       minikube/192.168.99.100
...
Containers:
 web:
 Container ID: docker:// **d9bd923572ab186870284535044e7f3132d5cac11ecb18576078b9c7bae86c73
 Image:        nginx
...
centos:
 Container ID: docker: **//f4c019d289d4b958cd17ecbe9fe22a5ce5952cb380c8ca4f9299e10bf5e94a0f
 Image:        centos
...  
```

在这个例子中，`web` 的容器 ID 是 `d9bd923572ab`，`centos` 的容器 ID 是 `f4c019d289d4`。如果我们使用 `docker ps` 进入节点 `minikube/192.168.99.100`，我们可以检查 Kubernetes 实际启动了多少个容器，因为我们在 minikube 中，它启动了许多其他集群容器。通过 `CREATED` 列可以查看最新的启动时间，我们会发现有三个刚刚启动的容器：

```
# docker ps
CONTAINER ID        IMAGE                                      COMMAND                  CREATED             STATUS              PORTS                                      NAMES
f4c019d289d4        36540f359ca3                               "/bin/sh -c 'while : "   2 minutes ago        Up 2 minutes k8s_centos_example_default_9843fc27-677b-11e7-9a8c-080027cafd37_1
d9bd923572ab        e4e6d42c70b3                               "nginx -g 'daemon off"   2 minutes ago        Up 2 minutes k8s_web_example_default_9843fc27-677b-11e7-9a8c-080027cafd37_1
4ddd3221cc47        gcr.io/google_containers/pause-amd64:3.0   "/pause"                 2 minutes ago        Up 2 minutes  
```

还有一个额外的容器 `4ddd3221cc47` 被启动了。在深入了解它是哪个容器之前，让我们先检查一下我们的 `web` 容器的网络模式。我们会发现我们示例中的 pod 中的容器是在映射容器模式下运行的：

```
# docker inspect d9bd923572ab | grep NetworkMode
"NetworkMode": "container:4ddd3221cc4792207ce0a2b3bac5d758a5c7ae321634436fa3e6dd627a31ca76",  
```

`4ddd3221cc47` 容器在这种情况下被称为网络容器，它持有网络命名空间，让 `web` 和 `centos` 容器加入。在同一网络命名空间中的容器共享相同的 IP 地址和网络配置。这是 Kubernetes 中实现容器间通信的默认方式，这也是对第一个要求的映射。

# Pod 间的通信

无论它们位于哪个节点，Pod IP 地址都可以从其他 Pod 中访问。这符合第二个要求。我们将在接下来的部分描述同一节点内和跨节点的 Pod 通信。

# 同一节点内的 Pod 通信

同一节点内的 Pod 间通信默认通过桥接完成。假设我们有两个拥有自己网络命名空间的 pod。当 pod1 想要与 pod2 通信时，数据包通过 pod1 的命名空间传递到相应的 veth 对 **vethXXXX**，最终到达桥接设备。桥接设备然后广播目标 IP 以帮助数据包找到它的路径，**vethYYYY** 响应。数据包然后到达 pod2：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00089.jpeg)

然而，Kubernetes 主要是关于集群。当 pod 在不同的节点上时，流量是如何路由的呢？

# 节点间的 Pod 通信

根据第二个要求，所有节点必须与所有容器通信。Kubernetes 将实现委托给**容器网络接口**（**CNI**）。用户可以选择不同的实现，如 L2、L3 或覆盖。覆盖网络是常见的解决方案之一，被称为**数据包封装**。它在离开源之前包装消息，然后传递并在目的地解包消息。这导致覆盖增加了网络延迟和复杂性。只要所有容器可以跨节点相互访问，您可以自由使用任何技术，如 L2 邻接或 L3 网关。有关 CNI 的更多信息，请参阅其规范（[`github.com/containernetworking/cni/blob/master/SPEC.md`](https://github.com/containernetworking/cni/blob/master/SPEC.md)）：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00090.jpeg)

假设我们有一个从 pod1 到 pod4 的数据包。数据包从容器接口离开并到达 veth 对，然后通过桥接和节点的网络接口。网络实现在第 4 步发挥作用。只要数据包能够路由到目标节点，您可以自由使用任何选项。在下面的示例中，我们将使用`--network-plugin=cni`选项启动 minikube。启用 CNI 后，参数将通过节点中的 kubelet 传递。Kubelet 具有默认的网络插件，但在启动时可以探测任何支持的插件。在启动 minikube 之前，如果已经启动，您可以首先使用`minikube stop`，或者在进一步操作之前使用`minikube delete`彻底删除整个集群。尽管 minikube 是一个单节点环境，可能无法完全代表我们将遇到的生产场景，但这只是让您对所有这些工作原理有一个基本的了解。我们将在第九章的*在 AWS 上的 Kubernetes*和第十章的*在 GCP 上的 Kubernetes*中学习网络选项的部署。

```
// start minikube with cni option
# minikube start --network-plugin=cni
...
Kubectl is now configured to use the cluster.  
```

当我们指定`network-plugin`选项时，它将在启动时使用`--network-plugin-dir`中指定的目录中的插件。在 CNI 插件中，默认的插件目录是`/opt/cni/net.d`。集群启动后，让我们登录到节点并通过`minikube ssh`查看内部设置：

```
# minikube ssh
$ ifconfig 
...
mybridge  Link encap:Ethernet  HWaddr 0A:58:0A:01:00:01
 inet addr:10.1.0.1  Bcast:0.0.0.0  
          Mask:255.255.0.0
...  
```

我们会发现节点中有一个新的桥接，如果我们再次通过`5-1-1_pod.yml`创建示例 pod，我们会发现 pod 的 IP 地址变成了`10.1.0.x`，它连接到了`mybridge`而不是`docker0`。

```
# kubectl create -f 5-1-1_pod.yaml
pod "example" created
# kubectl describe po example
Name:       example
Namespace:  default
Node:       minikube/192.168.99.100
Start Time: Sun, 23 Jul 2017 14:24:24 -0400
Labels:           <none>
Annotations:      <none>
Status:           Running
IP:         10.1.0.4  
```

为什么会这样？因为我们指定了要使用 CNI 作为网络插件，而不使用`docker0`（也称为**容器网络模型**或**libnetwork**）。CNI 创建一个虚拟接口，将其连接到底层网络，并最终设置 IP 地址和路由，并将其映射到 pod 的命名空间。让我们来看一下位于`/etc/cni/net.d/`的配置：

```
# cat /etc/cni/net.d/k8s.conf
{
 "name": "rkt.kubernetes.io",
 "type": "bridge",
 "bridge": "mybridge",
 "mtu": 1460,
 "addIf": "true",
 "isGateway": true,
 "ipMasq": true,
 "ipam": {
 "type": "host-local",
 "subnet": "10.1.0.0/16",
 "gateway": "10.1.0.1",
 "routes": [
      {
       "dst": "0.0.0.0/0"
      }
 ]
 }
}
```

在这个例子中，我们使用桥接 CNI 插件来重用用于 pod 容器的 L2 桥接。如果数据包来自`10.1.0.0/16`，目的地是任何地方，它将通过这个网关。就像我们之前看到的图表一样，我们可以有另一个启用了 CNI 的节点，使用`10.1.2.0/16`子网，这样 ARP 数据包就可以传输到目标 pod 所在节点的物理接口上。然后实现节点之间的 pod 到 pod 通信。

让我们来检查 iptables 中的规则：

```
// check the rules in iptables 
# sudo iptables -t nat -nL
... 
Chain POSTROUTING (policy ACCEPT)
target     prot opt source               destination
KUBE-POSTROUTING  all  --  0.0.0.0/0            0.0.0.0/0            /* kubernetes postrouting rules */
MASQUERADE  all  --  172.17.0.0/16        0.0.0.0/0
CNI-25df152800e33f7b16fc085a  all  --  10.1.0.0/16          0.0.0.0/0            /* name: "rkt.kubernetes.io" id: "328287949eb4d4483a3a8035d65cc326417ae7384270844e59c2f4e963d87e18" */
CNI-f1931fed74271104c4d10006  all  --  10.1.0.0/16          0.0.0.0/0            /* name: "rkt.kubernetes.io" id: "08c562ff4d67496fdae1c08facb2766ca30533552b8bd0682630f203b18f8c0a" */  
```

所有相关规则都已切换到`10.1.0.0/16` CIDR。

# pod 到 service 的通信

Kubernetes 是动态的。Pod 不断地被创建和删除。Kubernetes 服务是一个抽象，通过标签选择器定义一组 pod。我们通常使用服务来访问 pod，而不是明确指定一个 pod。当我们创建一个服务时，将创建一个`endpoint`对象，描述了该服务中标签选择器选择的一组 pod IP。

在某些情况下，创建服务时不会创建`endpoint`对象。例如，没有选择器的服务不会创建相应的`endpoint`对象。有关更多信息，请参阅第三章中没有选择器的服务部分，*开始使用 Kubernetes*。

那么，流量是如何从一个 pod 到 service 后面的 pod 的呢？默认情况下，Kubernetes 使用 iptables 通过`kube-proxy`执行这个魔术。这在下图中有解释。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00091.jpeg)

让我们重用第三章中的`3-2-3_rc1.yaml`和`3-2-3_nodeport.yaml`的例子，*开始使用 Kubernetes*，来观察默认行为：

```
// create two pods with nginx and one service to observe default networking. Users are free to use any other kind of solution.
# kubectl create -f 3-2-3_rc1.yaml
replicationcontroller "nginx-1.12" created
# kubectl create -f 3-2-3_nodeport.yaml
service "nginx-nodeport" created  
```

让我们观察 iptables 规则，看看它是如何工作的。如下所示，我们的服务 IP 是`10.0.0.167`，下面的两个 pod IP 地址分别是`10.1.0.4`和`10.1.0.5`。

```
// kubectl describe svc nginx-nodeport
Name:             nginx-nodeport
Namespace:        default
Selector:         project=chapter3,service=web
Type:             NodePort
IP:               10.0.0.167
Port:             <unset>     80/TCP
NodePort:         <unset>     32261/TCP
Endpoints:        10.1.0.4:80,10.1.0.5:80
...  
```

让我们通过`minikube ssh`进入 minikube 节点并检查其 iptables 规则：

```
# sudo iptables -t nat -nL
...
Chain KUBE-SERVICES (2 references)
target     prot opt source               destination
KUBE-SVC-37ROJ3MK6RKFMQ2B  tcp  --  0.0.0.0/0            **10.0.0.167**           /* default/nginx-nodeport: cluster IP */ tcp dpt:80
KUBE-NODEPORTS  all  --  0.0.0.0/0            0.0.0.0/0            /* kubernetes service nodeports; NOTE: this must be the last rule in this chain */ ADDRTYPE match dst-type LOCAL

Chain **KUBE-SVC-37ROJ3MK6RKFMQ2B** (2 references)
target     prot opt source               destination
KUBE-SEP-SVVBOHTYP7PAP3J5**  all  --  0.0.0.0/0            0.0.0.0/0            /* default/nginx-nodeport: */ statistic mode random probability 0.50000000000
KUBE-SEP-AYS7I6ZPYFC6YNNF**  all  --  0.0.0.0/0            0.0.0.0/0            /* default/nginx-nodeport: */
Chain **KUBE-SEP-SVVBOHTYP7PAP3J5** (1 references)
target     prot opt source               destination
KUBE-MARK-MASQ  all  --  10.1.0.4             0.0.0.0/0            /* default/nginx-nodeport: */
DNAT       tcp  --  0.0.0.0/0            0.0.0.0/0            /* default/nginx-nodeport: */ tcp to:10.1.0.4:80
Chain KUBE-SEP-AYS7I6ZPYFC6YNNF (1 references)
target     prot opt source               destination
KUBE-MARK-MASQ  all  --  10.1.0.5             0.0.0.0/0            /* default/nginx-nodeport: */
DNAT       tcp  --  0.0.0.0/0            0.0.0.0/0            /* default/nginx-nodeport: */ tcp to:10.1.0.5:80
...  
```

这里的关键点是服务将集群 IP 暴露给来自目标`KUBE-SVC-37ROJ3MK6RKFMQ2B`的外部流量，该目标链接到两个自定义链`KUBE-SEP-SVVBOHTYP7PAP3J5`和`KUBE-SEP-AYS7I6ZPYFC6YNNF`，统计模式为随机概率 0.5。这意味着，iptables 将生成一个随机数，并根据概率分布 0.5 调整目标。这两个自定义链的`DNAT`目标设置为相应的 pod IP。`DNAT`目标负责更改数据包的目标 IP 地址。默认情况下，当流量进入时，启用 conntrack 来跟踪连接的目标和源。所有这些都导致了一种路由行为。当流量到达服务时，iptables 将随机选择一个 pod 进行路由，并将目标 IP 从服务 IP 修改为真实的 pod IP，并取消 DNAT 以返回全部路由。

# 外部到服务的通信

为了能够为 Kubernetes 提供外部流量是至关重要的。Kubernetes 提供了两个 API 对象来实现这一点：

+   **服务**: 外部网络负载均衡器或 NodePort（L4）

+   **入口:** HTTP(S)负载均衡器（L7）

对于入口，我们将在下一节中学到更多。我们先专注于 L4。根据我们对节点间 pod 到 pod 通信的了解，数据包在服务和 pod 之间进出的方式。下图显示了它的工作原理。假设我们有两个服务，一个服务 A 有三个 pod（pod a，pod b 和 pod c），另一个服务 B 只有一个 pod（pod d）。当流量从负载均衡器进入时，数据包将被分发到其中一个节点。大多数云负载均衡器本身并不知道 pod 或容器。它只知道节点。如果节点通过了健康检查，那么它将成为目的地的候选者。假设我们想要访问服务 B，它目前只在一个节点上运行一个 pod。然而，负载均衡器将数据包发送到另一个没有我们想要的任何 pod 运行的节点。流量路由将如下所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00092.jpeg)

数据包路由的过程将是：

1.  负载均衡器将选择一个节点来转发数据包。在 GCE 中，它根据源 IP 和端口、目标 IP 和端口以及协议的哈希选择实例。在 AWS 中，它基于循环算法。

1.  在这里，路由目的地将被更改为 pod d（DNAT），并将其转发到另一个节点，类似于节点间的 pod 到 pod 通信。

1.  然后，服务到 Pod 的通信。数据包到达 Pod d，响应相应地。

1.  Pod 到服务的通信也受 iptables 控制。

1.  数据包将被转发到原始节点。

1.  源和目的地将被解除 DNAT 并发送回负载均衡器和客户端。

在 Kubernetes 1.7 中，服务中有一个名为**externalTrafficPolicy**的新属性。您可以将其值设置为 local，然后在流量进入节点后，Kubernetes 将路由该节点上的 Pod（如果有）。

# Ingress

Kubernetes 中的 Pod 和服务都有自己的 IP；然而，通常不是您提供给外部互联网的接口。虽然有配置了节点 IP 的服务，但节点 IP 中的端口不能在服务之间重复。决定将哪个端口与哪个服务管理起来是很麻烦的。此外，节点来去匆匆，将静态节点 IP 提供给外部服务并不明智。

Ingress 定义了一组规则，允许入站连接访问 Kubernetes 集群服务。它将流量带入集群的 L7 层，在每个 VM 上分配和转发一个端口到服务端口。这在下图中显示。我们定义一组规则，并将它们作为源类型 ingress 发布到 API 服务器。当流量进来时，ingress 控制器将根据 ingress 规则履行和路由 ingress。如下图所示，ingress 用于通过不同的 URL 将外部流量路由到 kubernetes 端点：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00093.jpeg)

现在，我们将通过一个示例来看看这是如何工作的。在这个例子中，我们将创建两个名为`nginx`和`echoserver`的服务，并配置 ingress 路径`/welcome`和`/echoserver`。我们可以在 minikube 中运行这个。旧版本的 minikube 默认不启用 ingress；我们需要先启用它：

```
// start over our minikube local
# minikube delete && minikube start

// enable ingress in minikube
# minikube addons enable ingress
ingress was successfully enabled 

// check current setting for addons in minikube
# minikube addons list
- registry: disabled
- registry-creds: disabled
- addon-manager: enabled
- dashboard: enabled
- default-storageclass: enabled
- kube-dns: enabled
- heapster: disabled
- ingress: **enabled
```

在 minikube 中启用 ingress 将创建一个 nginx ingress 控制器和一个`ConfigMap`来存储 nginx 配置（参考[`github.com/kubernetes/ingress/blob/master/controllers/nginx/README.md`](https://github.com/kubernetes/ingress/blob/master/controllers/nginx/README.md)），以及一个 RC 和一个服务作为默认的 HTTP 后端，用于处理未映射的请求。我们可以通过在`kubectl`命令中添加`--namespace=kube-system`来观察它们。接下来，让我们创建我们的后端资源。这是我们的 nginx `Deployment`和`Service`：

```
# cat 5-2-1_nginx.yaml
apiVersion: apps/v1beta1
kind: Deployment
metadata:
 name: nginx
spec:
 replicas: 2
 template:
 metadata:
 labels:
 project: chapter5
 service: nginx
 spec:
 containers:
 - name: nginx
 image: nginx
 ports:
 - containerPort: 80
---
kind: Service
apiVersion: v1
metadata:
 name: nginx
spec:
 type: NodePort
  selector:
 project: chapter5
 service: nginx
 ports:
 - protocol: TCP
 port: 80
 targetPort: 80
// create nginx RS and service
# kubectl create -f 5-2-1_nginx.yaml
deployment "nginx" created
service "nginx" created
```

然后，我们将创建另一个带有 RS 的服务：

```
// another backend named echoserver
# cat 5-2-1_echoserver.yaml
apiVersion: apps/v1beta1
kind: Deployment
metadata:
 name: echoserver
spec:
 replicas: 1
 template:
 metadata:
 name: echoserver
 labels:
 project: chapter5
 service: echoserver
 spec:
 containers:
 - name: echoserver
 image: gcr.io/google_containers/echoserver:1.4
 ports:
 - containerPort: 8080
---

kind: Service
apiVersion: v1
metadata:
 name: echoserver
spec:
 type: NodePort
 selector:
 project: chapter5
 service: echoserver
 ports:
 - protocol: TCP
 port: 8080
 targetPort: 8080

// create RS and SVC by above configuration file
# kubectl create -f 5-2-1_echoserver.yaml
deployment "echoserver" created
service "echoserver" created  
```

接下来，我们将创建 ingress 资源。有一个名为`ingress.kubernetes.io/rewrite-target`的注释。如果服务请求来自根 URL，则需要此注释。如果没有重写注释，我们将得到 404 作为响应。有关 nginx ingress 控制器中更多支持的注释，请参阅[`github.com/kubernetes/ingress/blob/master/controllers/nginx/configuration.md#annotations`](https://github.com/kubernetes/ingress/blob/master/controllers/nginx/configuration.md#annotations)。

```
# cat 5-2-1_ingress.yaml
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
 name: ingress-example
 annotations:
 ingress.kubernetes.io/rewrite-target: /
spec:
 rules:
 - host: devops.k8s
 http:
 paths:
 - path: /welcome
 backend:
 serviceName: nginx
 servicePort: 80
 - path: /echoserver
 backend:
 serviceName: echoserver
 servicePort: 8080

// create ingress
# kubectl create -f 5-2-1_ingress.yaml
ingress "ingress-example" created
```

在一些云提供商中，支持服务负载均衡器控制器。它可以通过配置文件中的`status.loadBalancer.ingress`语法与 ingress 集成。有关更多信息，请参阅[`github.com/kubernetes/contrib/tree/master/service-loadbalancer`](https://github.com/kubernetes/contrib/tree/master/service-loadbalancer)。

由于我们的主机设置为`devops.k8s`，只有在从该主机名访问时才会返回。您可以在 DNS 服务器中配置 DNS 记录，或者在本地修改 hosts 文件。为简单起见，我们将在主机文件中添加一行，格式为`ip hostname`：

```
// normally host file located in /etc/hosts in linux
# sudo sh -c "echo `minikube ip` devops.k8s >> /etc/hosts"  
```

然后我们应该能够直接通过 URL 访问我们的服务：

```
# curl http://devops.k8s/welcome
...
<title>Welcome to nginx!</title>
...
// check echoserver 
# curl http://devops.k8s/echoserver
CLIENT VALUES:
client_address=172.17.0.4
command=GET
real path=/
query=nil
request_version=1.1
request_uri=http://devops.k8s:8080/  
```

Pod ingress 控制器根据 URL 路径分发流量。路由路径类似于外部到服务的通信。数据包在节点和 Pod 之间跳转。Kubernetes 是可插拔的。正在进行许多第三方实现。我们在这里只是浅尝辄止，而 iptables 只是一个默认和常见的实现。网络在每个发布版本中都有很大的发展。在撰写本文时，Kubernetes 刚刚发布了 1.7 版本。

# 网络策略

网络策略作为 pod 的软件防火墙。默认情况下，每个 pod 都可以在没有任何限制的情况下相互通信。网络策略是您可以应用于 pod 的隔离之一。它通过命名空间选择器和 pod 选择器定义了谁可以访问哪个端口的哪个 pod。命名空间中的网络策略是累加的，一旦 pod 启用了策略，它就会拒绝任何其他入口（也称为默认拒绝所有）。

目前，有多个网络提供商支持网络策略，例如 Calico ([`www.projectcalico.org/calico-network-policy-comes-to-kubernetes/`](https://www.projectcalico.org/calico-network-policy-comes-to-kubernetes/))、Romana ([`github.com/romana/romana`](https://github.com/romana/romana)))、Weave Net ([`www.weave.works/docs/net/latest/kube-addon/#npc)`](https://www.weave.works/docs/net/latest/kube-addon/#npc))、Contiv ([`contiv.github.io/documents/networking/policies.html)`](http://contiv.github.io/documents/networking/policies.html))和 Trireme ([`github.com/aporeto-inc/trireme-kubernetes`](https://github.com/aporeto-inc/trireme-kubernetes))。用户可以自由选择任何选项。为了简单起见，我们将使用 Calico 与 minikube。为此，我们将不得不使用`--network-plugin=cni`选项启动 minikube。在这一点上，Kubernetes 中的网络策略仍然是相当新的。我们正在运行 Kubernetes 版本 v.1.7.0，使用 v.1.0.7 minikube ISO 来通过自托管解决方案部署 Calico ([`docs.projectcalico.org/v1.5/getting-started/kubernetes/installation/hosted/`](http://docs.projectcalico.org/v1.5/getting-started/kubernetes/installation/hosted/))。首先，我们需要下载一个`calico.yaml` ([`github.com/projectcalico/calico/blob/master/v2.4/getting-started/kubernetes/installation/hosted/calico.yaml`](https://github.com/projectcalico/calico/blob/master/v2.4/getting-started/kubernetes/installation/hosted/calico.yaml)))文件来创建 Calico 节点和策略控制器。需要配置`etcd_endpoints`。要找出 etcd 的 IP，我们需要访问 localkube 资源。

```
// find out etcd ip
# minikube ssh -- "sudo /usr/local/bin/localkube --host-ip"
2017-07-27 04:10:58.941493 I | proto: duplicate proto type registered: google.protobuf.Any
2017-07-27 04:10:58.941822 I | proto: duplicate proto type registered: google.protobuf.Duration
2017-07-27 04:10:58.942028 I | proto: duplicate proto type registered: google.protobuf.Timestamp
localkube host ip:  10.0.2.15  
```

etcd 的默认端口是`2379`。在这种情况下，我们将在`calico.yaml`中修改`etcd_endpoint`，从`http://127.0.0.1:2379`改为`http://10.0.2.15:2379`：

```
// launch calico
# kubectl apply -f calico.yaml
configmap "calico-config" created
secret "calico-etcd-secrets" created
daemonset "calico-node" created
deployment "calico-policy-controller" created
job "configure-calico" created

// list the pods in kube-system
# kubectl get pods --namespace=kube-system
NAME                                        READY     STATUS    RESTARTS   AGE
calico-node-ss243                           2/2       Running   0          1m
calico-policy-controller-2249040168-r2270   1/1       Running   0          1m  
```

让我们重用`5-2-1_nginx.yaml`作为示例：

```
# kubectl create -f 5-2-1_nginx.yaml
replicaset "nginx" created
service "nginx" created
// list the services
# kubectl get svc
NAME         CLUSTER-IP   EXTERNAL-IP   PORT(S)        AGE
kubernetes   10.0.0.1     <none>        443/TCP        47m
nginx        10.0.0.42    <nodes>       80:31071/TCP   5m
```

我们将发现我们的 nginx 服务的 IP 是`10.0.0.42`。让我们启动一个简单的 bash 并使用`wget`来看看我们是否可以访问我们的 nginx：

```
# kubectl run busybox -i -t --image=busybox /bin/sh
If you don't see a command prompt, try pressing enter.
/ # wget --spider 10.0.0.42 
Connecting to 10.0.0.42 (10.0.0.42:80)  
```

`--spider`参数用于检查 URL 是否存在。在这种情况下，busybox 可以成功访问 nginx。接下来，让我们将`NetworkPolicy`应用到我们的 nginx pod 中：

```
// declare a network policy
# cat 5-3-1_networkpolicy.yaml
kind: NetworkPolicy
apiVersion: networking.k8s.io/v1
metadata:
 name: nginx-networkpolicy
spec:
 podSelector:
 matchLabels:
 service: nginx
 ingress:
 - from:
 - podSelector:
 matchLabels:
 project: chapter5  
```

我们可以在这里看到一些重要的语法。`podSelector`用于选择 pod，应该与目标 pod 的标签匹配。另一个是`ingress[].from[].podSelector`，用于定义谁可以访问这些 pod。在这种情况下，所有具有`project=chapter5`标签的 pod 都有资格访问具有`server=nginx`标签的 pod。如果我们回到我们的 busybox pod，现在我们无法再联系 nginx，因为 nginx pod 现在已经有了 NetworkPolicy。默认情况下，它是拒绝所有的，所以 busybox 将无法与 nginx 通信。

```
// in busybox pod, or you could use `kubectl attach <pod_name> -c busybox -i -t` to re-attach to the pod 
# wget --spider --timeout=1 10.0.0.42
Connecting to 10.0.0.42 (10.0.0.42:80)
wget: download timed out  
```

我们可以使用`kubectl edit deployment busybox`将标签`project=chaper5`添加到 busybox pod 中。

如果忘记如何操作，请参考第三章中的标签和选择器部分，*开始使用 Kubernetes*。

之后，我们可以再次联系 nginx pod：

```
// inside busybox pod
/ # wget --spider 10.0.0.42 
Connecting to 10.0.0.42 (10.0.0.42:80)  
```

通过前面的例子，我们了解了如何应用网络策略。我们还可以通过调整选择器来应用一些默认策略，拒绝所有或允许所有。例如，拒绝所有的行为可以通过以下方式实现：

```
# cat 5-3-1_np_denyall.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
 name: default-deny
spec:
 podSelector:  
```

这样，所有不匹配标签的 pod 将拒绝所有其他流量。或者，我们可以创建一个`NetworkPolicy`，其入口列表来自任何地方。然后，运行在这个命名空间中的 pod 可以被任何其他人访问。

```
# cat 5-3-1_np_allowall.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
 name: allow-all
spec:
 podSelector:
 ingress:
 - {}  
```

# 总结

在这一章中，我们学习了容器之间如何进行通信是至关重要的，并介绍了 pod 与 pod 之间的通信工作原理。Service 是一个抽象概念，可以将流量路由到任何匹配标签选择器的 pod 下面。我们学习了 service 如何通过 iptables 魔术与 pod 配合工作。我们了解了数据包如何从外部路由到 pod 以及 DNAT、un-DAT 技巧。我们还学习了新的 API 对象，比如*ingress*，它允许我们使用 URL 路径来路由到后端的不同服务。最后，还介绍了另一个对象`NetworkPolicy`。它提供了第二层安全性，充当软件防火墙规则。通过网络策略，我们可以使某些 pod 只与某些 pod 通信。例如，只有数据检索服务可以与数据库容器通信。所有这些都使 Kubernetes 更加灵活、安全和强大。

到目前为止，我们已经学习了 Kubernetes 的基本概念。接下来，我们将通过监控集群指标和分析 Kubernetes 的应用程序和系统日志，更清楚地了解集群内部发生了什么。监控和日志工具对于每个 DevOps 来说都是必不可少的，它们在 Kubernetes 等动态集群中也扮演着极其重要的角色。因此，我们将深入了解集群的活动，如调度、部署、扩展和服务发现。下一章将帮助您更好地了解在现实世界中操作 Kubernetes 的行为。


# 第六章：监控和日志记录

监控和日志记录是站点可靠性的重要组成部分。我们已经学会了如何利用各种控制器来管理我们的应用程序，以及如何利用服务和 Ingress 一起为我们的 Web 应用程序提供服务。接下来，在本章中，我们将学习如何通过以下主题跟踪我们的应用程序：

+   获取容器的状态快照

+   Kubernetes 中的监控

+   通过 Prometheus 汇总 Kubernetes 的指标

+   Kubernetes 中日志记录的概念

+   使用 Fluentd 和 Elasticsearch 进行日志记录

# 检查一个容器

每当我们的应用程序表现异常时，我们肯定会想知道发生了什么，通过各种手段，比如检查日志、资源使用情况、进程监视器，甚至直接进入运行的主机来排查问题。在 Kubernetes 中，我们有`kubectl get`和`kubectl describe`可以查询部署状态，这将帮助我们确定应用程序是否已崩溃或按预期工作。

此外，如果我们想要了解应用程序的输出发生了什么，我们还有`kubectl logs`，它将容器的`stdout`重定向到我们的终端。对于 CPU 和内存使用统计，我们还可以使用类似 top 的命令`kubectl top`。`kubectl top node`提供了节点资源使用情况的概览，`kubectl top pod <POD_NAME>`显示了每个 pod 的使用情况：

```
# kubectl top node
NAME        CPU(cores)   CPU%      MEMORY(bytes)  MEMORY% 
node-1      42m          4%        273Mi           12% 
node-2      152m         15%       1283Mi          75% 

# kubectl top pod mypod-name-2587489005-xq72v
NAME                         CPU(cores)   MEMORY(bytes) 
mypod-name-2587489005-xq72v   0m           0Mi            
```

要使用`kubectl top`，您需要在集群中部署 Heapster。我们将在本章后面讨论这个问题。

如果我们遗留了一些日志在容器内而没有发送到任何地方怎么办？我们知道有一个`docker exec`在运行的容器内执行命令，但我们不太可能每次都能访问节点。幸运的是，`kubectl`允许我们使用`kubectl exec`命令做同样的事情。它的用法类似于 Docker。例如，我们可以像这样在 pod 中的容器内运行一个 shell：

```
$ kubectl exec -it mypod-name-2587489005-xq72v /bin/sh
/ # 
/ # hostname
mypod-name-2587489005-xq72v  
```

这与通过 SSH 登录主机几乎相同，并且它使我们能够使用我们熟悉的工具进行故障排除，就像我们在非容器世界中所做的那样。

# Kubernetes 仪表板

除了命令行实用程序之外，还有一个仪表板，它在一个体面的 Web-UI 上汇总了我们刚刚讨论的几乎所有信息：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00094.jpeg)

实际上，它是 Kubernetes 集群的通用图形用户界面，因为它还允许我们创建、编辑和删除资源。部署它非常容易；我们所需要做的就是应用一个模板：

```
$ kubectl create -f \ https://raw.githubusercontent.com/kubernetes/dashboard/v1.6.3/src/deploy/kubernetes-dashboard.yaml  
```

此模板适用于启用了**RBAC**（基于角色的访问控制）的 Kubernetes 集群。如果您需要其他部署选项，请查看仪表板的项目存储库（[`github.com/kubernetes/dashboard`](https://github.com/kubernetes/dashboard)）。关于 RBAC，我们将在第八章中讨论，*集群管理*。许多托管的 Kubernetes 服务（例如 Google 容器引擎）在集群中预先部署了仪表板，因此我们不需要自行安装。要确定仪表板是否存在于我们的集群中，请使用`kubectl cluster-info`。

如果已安装，我们将看到 kubernetes-dashboard 正在运行...。使用默认模板部署的仪表板服务或由云提供商提供的服务通常是 ClusterIP。为了访问它，我们需要在我们的终端和 Kubernetes 的 API 服务器之间建立代理，使用`kubectl proxy`。一旦代理启动，我们就能够在`http://localhost:8001/ui`上访问仪表板。端口`8001`是`kubectl proxy`的默认端口。

与`kubectl top`一样，您需要在集群中部署 Heapster 才能查看 CPU 和内存统计信息。

# Kubernetes 中的监控

由于我们现在知道如何在 Kubernetes 中检查我们的应用程序，所以我们应该有一种机制来不断地这样做，以便在第一次发生任何事件时检测到。换句话说，我们需要一个监控系统。监控系统从各种来源收集指标，存储和分析接收到的数据，然后响应异常。在应用程序监控的经典设置中，我们至少会从基础设施的三个不同层面收集指标，以确保我们服务的可用性和质量。

# 应用程序

我们在这个层面关心的数据涉及应用程序的内部状态，这可以帮助我们确定服务内部发生了什么。例如，以下截图来自 Elasticsearch Marvel（[`www.elastic.co/guide/en/marvel/current/introduction.html`](https://www.elastic.co/guide/en/marvel/current/introduction.html)），从版本 5 开始称为**监控**，这是 Elasticsearch 集群的监控解决方案。它汇集了关于我们集群的信息，特别是 Elasticsearch 特定的指标：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00095.jpeg)

此外，我们将利用性能分析工具与跟踪工具来对我们的程序进行仪器化，这增加了我们检查服务的细粒度维度。特别是在当今，一个应用可能以分布式方式由数十个服务组成。如果不使用跟踪工具，比如 OpenTracing（[`opentracing.io`](http://opentracing.io)）的实现，要识别性能问题可能会非常困难。

# 主机

在主机级别收集任务通常是由监控框架提供的代理完成的。代理提取并发送有关主机的全面指标，如负载、磁盘、连接或进程状态等，以帮助确定主机的健康状况。

# 外部资源

除了上述两个组件之外，我们还需要检查依赖组件的状态。例如，假设我们有一个消耗队列并执行相应任务的应用；我们还应该关注一些指标，比如队列长度和消耗速率。如果消耗速率低而队列长度不断增长，我们的应用可能遇到了问题。

这些原则也适用于 Kubernetes 上的容器，因为在主机上运行容器几乎与运行进程相同。然而，由于 Kubernetes 上的容器和传统主机上利用资源的方式之间存在微妙的区别，当采用监控策略时，我们仍需要考虑这些差异。例如，Kubernetes 上的应用的容器可能分布在多个主机上，并且也不总是在同一主机上。如果我们仍在采用以主机为中心的监控方法，要对一个应用进行一致的记录将会非常困难。因此，我们不应该仅观察主机级别的资源使用情况，而应该在我们的监控堆栈中增加一个容器层。此外，由于 Kubernetes 实际上是我们应用的基础设施，我们绝对应该考虑它。

# 容器

正如前面提到的，容器级别收集的指标和主机级别得到的指标基本上是相同的，特别是系统资源的使用情况。尽管看起来有些多余，但这正是帮助我们解决监控移动容器困难的关键。这个想法非常简单：我们需要将逻辑信息附加到指标上，比如 pod 标签或它们的控制器名称。这样，来自不同主机上的容器的指标可以被有意义地分组。考虑下面的图表；假设我们想知道**App 2**上传输的字节数（**tx**），我们可以对**App 2**标签上的**tx**指标求和，得到**20 MB**：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00096.jpeg)

另一个区别是，CPU 限制的指标仅在容器级别上报告。如果在某个应用程序遇到性能问题，但主机上的 CPU 资源是空闲的，我们可以检查是否受到了相关指标的限制。

# Kubernetes

Kubernetes 负责管理、调度和编排我们的应用程序。因此，一旦应用程序崩溃，Kubernetes 肯定是我们想要查看的第一个地方。特别是在部署新版本后发生崩溃时，相关对象的状态将立即在 Kubernetes 上反映出来。

总之，应该监控的组件如下图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00097.jpeg)

# 获取 Kubernetes 的监控要点

对于监控堆栈的每一层，我们总是可以找到相应的收集器。例如，在应用程序级别，我们可以手动转储指标；在主机级别，我们会在每个主机上安装一个指标收集器；至于 Kubernetes，有用于导出我们感兴趣的指标的 API，至少我们手头上有`kubectl`。

当涉及到容器级别的收集器时，我们有哪些选择？也许在我们的应用程序镜像中安装主机指标收集器可以胜任，但我们很快就会意识到，这可能会使我们的容器在大小和资源利用方面变得过于笨重。幸运的是，已经有了针对这种需求的解决方案，即 cAdvisor（[`github.com/google/cadvisor`](https://github.com/google/cadvisor)），这是容器级别的指标收集器的答案。简而言之，cAdvisor 汇总了机器上每个运行容器的资源使用情况和性能统计。请注意，cAdvisor 的部署是每个主机一个，而不是每个容器一个，这对于容器化应用程序来说更为合理。在 Kubernetes 中，我们甚至不需要关心部署 cAdvisor，因为它已经嵌入到 kubelet 中。

cAdvisor 可以通过每个节点的端口`4194`访问。在 Kubernetes 1.7 之前，cAdvisor 收集的数据也可以通过 kubelet 端口（`10250`/`10255`）进行收集。要访问 cAdvisor，我们可以通过实例端口`4194`或通过`kubectl proxy`在`http://localhost:8001/api/v1/nodes/<nodename>:4194/proxy/`访问，或直接访问`http://<node-ip>:4194/`。

以下截图是来自 cAdvisor Web UI。一旦连接，您将看到类似的页面。要查看 cAdvisor 抓取的指标，请访问端点`/metrics`。

>![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00098.jpeg)

监控管道中的另一个重要组件是 Heapster（[`github.com/kubernetes/heapster`](https://github.com/kubernetes/heapster)）。它从每个节点检索监控统计信息，特别是处理节点上的 kubelet，并在之后写入外部接收器。它还通过 REST API 公开聚合指标。Heapster 的功能听起来与 cAdvisor 有些多余，但在实践中它们在监控管道中扮演不同的角色。Heapster 收集集群范围的统计信息；cAdvisor 是一个主机范围的组件。也就是说，Heapster 赋予 Kubernetes 集群基本的监控能力。以下图表说明了它如何与集群中的其他组件交互：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00099.jpeg)

事实上，如果您的监控框架提供了类似的工具，也可以从 kubelet 中抓取指标，那么安装 Heapster 就不是必需的。然而，由于它是 Kubernetes 生态系统中的默认监控组件，许多工具都依赖于它，例如前面提到的 `kubectl top` 和 Kubernetes 仪表板。

在部署 Heapster 之前，请检查您正在使用的监控工具是否作为此文档中的 Heapster sink 支持：[`github.com/kubernetes/heapster/blob/master/docs/sink-configuration.md`](https://github.com/kubernetes/heapster/blob/master/docs/sink-configuration.md)。

如果没有，我们可以使用独立的设置，并通过应用此模板使仪表板和 `kubectl top` 工作：

```
$ kubectl create -f \
    https://raw.githubusercontent.com/kubernetes/heapster/master/deploy/kube-config/standalone/heapster-controller.yaml  
```

如果启用了 RBAC，请记得应用此模板：

```
$ kubectl create -f \ https://raw.githubusercontent.com/kubernetes/heapster/master/deploy/kube-config/rbac/heapster-rbac.yaml
```

安装完 Heapster 后，`kubectl top` 命令和 Kubernetes 仪表板应该正确显示资源使用情况。

虽然 cAdvisor 和 Heapster 关注物理指标，但我们也希望在监控仪表板上显示对象的逻辑状态。kube-state-metrics ([`github.com/kubernetes/kube-state-metrics`](https://github.com/kubernetes/kube-state-metrics)) 是完成我们监控堆栈的重要组成部分。它监视 Kubernetes 主节点，并将我们从 `kubectl get` 或 `kubectl describe` 中看到的对象状态转换为 Prometheus 格式的指标 ([`prometheus.io/docs/instrumenting/exposition_formats/`](https://prometheus.io/docs/instrumenting/exposition_formats/))。只要监控系统支持这种格式，我们就可以将状态抓取到指标存储中，并在诸如无法解释的重启计数等事件上收到警报。要安装 kube-state-metrics，首先在项目存储库的 `kubernetes` 文件夹中下载模板([`github.com/kubernetes/kube-state-metrics/tree/master/kubernetes`](https://github.com/kubernetes/kube-state-metrics/tree/master/kubernetes))，然后应用它们：

```
$ kubectl apply -f kubernetes
```

之后，我们可以在其服务端点的指标中查看集群内的状态：

`http://kube-state-metrics.kube-system:8080/metrics`

# 实际监控

到目前为止，我们已经学到了很多关于在 Kubernetes 中制造一个无懈可击的监控系统的原则，现在是时候实施一个实用的系统了。因为绝大多数 Kubernetes 组件都在 Prometheus 格式的传统路径上公开了他们的仪表盘指标，所以只要工具理解这种格式，我们就可以自由地使用我们熟悉的任何监控工具。在本节中，我们将使用一个开源项目 Prometheus（[`prometheus.io`](https://prometheus.io)）来设置一个示例，它是一个独立于平台的监控工具。它在 Kubernetes 生态系统中的流行不仅在于其强大性，还在于它得到了**Cloud Native Computing Foundation**（[`www.cncf.io/`](https://www.cncf.io/)）的支持，后者也赞助了 Kubernetes 项目。

# 遇见 Prometheus

Prometheus 框架包括几个组件，如下图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00100.jpeg)

与所有其他监控框架一样，Prometheus 依赖于从系统组件中抓取统计数据的代理，这些代理位于图表左侧的出口处。除此之外，Prometheus 采用了拉取模型来收集指标，这意味着它不是被动地接收指标，而是主动地从出口处拉取数据。如果一个应用程序公开了指标的出口，Prometheus 也能够抓取这些数据。默认的存储后端是嵌入式 LevelDB，可以切换到其他远程存储，比如 InfluxDB 或 Graphite。Prometheus 还负责根据预先配置的规则发送警报给**Alert manager**。**Alert manager**负责发送警报任务。它将接收到的警报分组并将它们分发给实际发送消息的工具，比如电子邮件、Slack、PagerDuty 等等。除了警报，我们还希望可视化收集到的指标，以便快速了解我们的系统情况，这时 Grafana 就派上用场了。

# 部署 Prometheus

我们为本章准备的模板可以在这里找到：

[`github.com/DevOps-with-Kubernetes/examples/tree/master/chapter6`](https://github.com/DevOps-with-Kubernetes/examples/tree/master/chapter6)

在 6-1_prometheus 下是本节的清单，包括 Prometheus 部署、导出器和相关资源。它们将在专用命名空间`monitoring`中安装，除了需要在`kube-system`命名空间中工作的组件。请仔细查看它们，现在让我们按以下顺序创建资源。

```
$ kubectl apply -f monitoring-ns.yml
$ kubectl apply -f prometheus/config/prom-config-default.yml
$ kubectl apply -f prometheus  
```

资源的使用限制在提供的设置中相对较低。如果您希望以更正式的方式使用它们，建议根据实际要求调整参数。在 Prometheus 服务器启动后，我们可以通过`kubectl port-forward`连接到端口`9090`的 Web-UI。如果相应地修改其服务（`prometheus/prom-svc.yml`），我们可以使用 NodePort 或 Ingress 连接到 UI。当进入 UI 时，我们将看到 Prometheus 的表达式浏览器，在那里我们可以构建查询和可视化指标。在默认设置下，Prometheus 将从自身收集指标。所有有效的抓取目标都可以在路径`/targets`下找到。要与 Prometheus 交流，我们必须对其语言**PromQL**有一些了解。

# 使用 PromQL

PromQL 有三种数据类型：即时向量、范围向量和标量。即时向量是经过采样的数据时间序列；范围向量是一组包含在一定时间范围内的时间序列；标量是一个数值浮点值。存储在 Prometheus 中的指标通过指标名称和标签进行识别，我们可以通过表达式浏览器旁边的下拉列表找到任何收集的指标名称。如果我们使用指标名称，比如`http_requests_total`，我们会得到很多结果，因为即时向量匹配名称但具有不同的标签。同样，我们也可以使用`{}`语法仅查询特定的标签集。例如，查询`{code="400",method="get"}`表示我们想要任何具有标签`code`，`method`分别等于`400`和`get`的指标。在查询中结合名称和标签也是有效的，比如`http_requests_total{code="400",method="get"}`。PromQL 赋予了我们检查应用程序或系统的侦探能力，只要相关指标被收集。

除了刚才提到的基本查询之外，PromQL 还有很多其他内容，比如使用正则表达式和逻辑运算符查询标签，使用函数连接和聚合指标，甚至在不同指标之间执行操作。例如，以下表达式给出了`kube-system`命名空间中`kube-dns`部署消耗的总内存：

```
sum(container_memory_usage_bytes{namespace="kube-system", pod_name=~"kube-dns-(\\d+)-.*"} ) / 1048576
```

更详细的文档可以在 Prometheus 的官方网站找到（[`prometheus.io/docs/querying/basics/`](https://prometheus.io/docs/querying/basics/)），它肯定会帮助您释放 Prometheus 的力量。

# 在 Kubernetes 中发现目标

由于 Prometheus 只从它知道的端点中提取指标，我们必须明确告诉它我们想要从哪里收集数据。在路径`/config`下是列出当前配置的目标以进行提取的页面。默认情况下，会有一个任务来收集有关 Prometheus 本身的当前指标，它位于传统的抓取路径`/metrics`中。如果连接到端点，我们会看到一个非常长的文本页面：

```
$ kubectl exec -n monitoring prometheus-1496092314-jctr6 -- \
wget -qO - localhost:9090/metrics

# HELP go_gc_duration_seconds A summary of the GC invocation durations.
# TYPE go_gc_duration_seconds summary
go_gc_duration_seconds{quantile="0"} 2.4032e-05
go_gc_duration_seconds{quantile="0.25"} 3.7359e-05
go_gc_duration_seconds{quantile="0.5"} 4.1723e-05
...
```

这只是我们已经多次提到的 Prometheus 指标格式。下次当我们看到这样的页面时，我们会知道这是一个指标端点。

抓取 Prometheus 的默认作业被配置为静态目标。然而，考虑到 Kubernetes 中的容器是动态创建和销毁的事实，要找出容器的确切地址，更不用说在 Prometheus 上设置它，真的很麻烦。在某些情况下，我们可以利用服务 DNS 作为静态指标目标，但这仍然不能解决所有情况。幸运的是，Prometheus 通过其发现 Kubernetes 内部服务的能力帮助我们克服了这个问题。

更具体地说，它能够查询 Kubernetes 有关正在运行的服务的信息，并根据情况将其添加或删除到目标配置中。目前支持四种发现机制：

+   **节点**发现模式为每个节点创建一个目标，默认情况下目标端口将是 kubelet 的端口。

+   **服务**发现模式为每个`service`对象创建一个目标，并且服务中定义的所有端口都将成为抓取目标。

+   **pod**发现模式的工作方式与服务发现角色类似，也就是说，它为每个 pod 创建目标，并且对于每个 pod，它会公开所有定义的容器端口。如果在 pod 的模板中没有定义端口，它仍然会只创建一个带有其地址的抓取目标。

+   **端点**模式发现了由服务创建的`endpoint`对象。例如，如果一个服务由三个具有两个端口的 pod 支持，那么我们将有六个抓取目标。此外，对于一个 pod，不仅会发现暴露给服务的端口，还会发现其他声明的容器端口。

以下图表说明了四种发现机制：左侧是 Kubernetes 中的资源，右侧是 Prometheus 中创建的目标：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00101.jpeg)

一般来说，并非所有暴露的端口都作为指标端点提供服务，因此我们当然不希望 Prometheus 抓取集群中的所有内容，而只收集标记的资源。为了实现这一点，Prometheus 利用资源清单上的注释来区分哪些目标应该被抓取。注释格式如下：

+   **在 pod 上**：如果一个 pod 是由 pod 控制器创建的，请记住在 pod 规范中设置 Prometheus 注释，而不是在 pod 控制器中：

+   `prometheus.io/scrape`：`true`表示应该拉取此 pod。

+   `prometheus.io/path`：将此注释设置为公开指标的路径；只有在目标 pod 使用除`/metrics`之外的路径时才需要设置。

+   `prometheus.io/port`：如果定义的端口与实际指标端口不同，请使用此注释进行覆盖。

+   **在服务上**：由于端点大多数情况下不是手动创建的，端点发现使用从服务继承的注释。也就是说，服务上的注释同时影响服务和端点发现模式。因此，我们将使用`prometheus.io/scrape: 'true'`来表示由服务创建的端点应该被抓取，并使用`prometheus.io/probe: 'true'`来标记具有指标的服务。此外，`prometheus.io/scheme`指定了使用`http`还是`https`。除此之外，路径和端口注释在这里也起作用。

以下模板片段指示了 Prometheus 的端点发现角色，但选择在`9100/prom`上创建目标的服务发现角色。

```
apiVersion: v1 
kind: Service 
metadata: 
  annotations: 
    prometheus.io/scrape: 'true' 
    prometheus.io/path: '/prom' 
... 
spec: 
  ports: 
 - port: 9100 
```

我们的示例存储库中的模板`prom-config-k8s.yml`包含了为 Prometheus 发现 Kubernetes 资源的配置。使用以下命令应用它：

```
$ kubectl apply -f prometheus/config/prom-config-k8s.yml  
```

因为它是一个 ConfigMap，需要几秒钟才能变得一致。之后，通过向进程发送`SIGHUP`来重新加载 Prometheus：

```
$ kubectl exec -n monitoring ${PROM_POD_NAME} -- kill -1 1
```

提供的模板基于 Prometheus 官方存储库中的示例；您可以在这里找到更多用法：

[`github.com/prometheus/prometheus/blob/master/documentation/examples/prometheus-kubernetes.yml`](https://github.com/prometheus/prometheus/blob/master/documentation/examples/prometheus-kubernetes.yml)

此外，文档页面详细描述了 Prometheus 配置的工作原理：

[`prometheus.io/docs/operating/configuration/`](https://prometheus.io/docs/operating/configuration/)

# 从 Kubernetes 中收集数据

现在，实施之前在 Prometheus 中讨论的五个监控层的步骤已经非常清晰：安装导出器，使用适当的标签对其进行注释，然后在自动发现的端点上收集它们。

Prometheus 中的主机层监控是由节点导出器（[`github.com/prometheus/node_exporter`](https://github.com/prometheus/node_exporter)）完成的。它的 Kubernetes 清单可以在本章的示例中找到，其中包含一个带有抓取注释的 DaemonSet。使用以下命令安装它：

```
$ kubectl apply -f exporters/prom-node-exporter.yml
```

其相应的配置将由 pod 发现角色创建。

容器层收集器应该是 cAdvisor，并且已经安装在 kubelet 中。因此，发现它并使用节点模式是我们需要做的唯一的事情。

Kubernetes 监控是由 kube-state-metrics 完成的，之前也有介绍。更好的是，它带有 Prometheus 注释，这意味着我们无需进行任何额外的配置。

到目前为止，我们已经基于 Prometheus 建立了一个强大的监控堆栈。关于应用程序和外部资源的监控，Prometheus 生态系统中有大量的导出器来支持监控系统内部的各种组件。例如，如果我们需要我们的 MySQL 数据库的统计数据，我们可以安装 MySQL Server Exporter（[`github.com/prometheus/mysqld_exporter`](https://github.com/prometheus/mysqld_exporter)），它提供了全面和有用的指标。

除了已经描述的那些指标之外，还有一些来自 Kubernetes 组件的其他有用的指标，在各种方面起着重要作用：

+   **Kubernetes API 服务器**：API 服务器在`/metrics`上公开其状态，并且此目标默认启用。

+   **kube-controller-manager**：这个组件在端口`10252`上公开指标，但在一些托管的 Kubernetes 服务上是不可见的，比如**Google Container Engine**（**GKE**）。如果您在自托管的集群上，应用"`kubernetes/self/kube-controller-manager-metrics-svc.yml`"会为 Prometheus 创建端点。

+   **kube-scheduler**：它使用端口`10251`，在 GKE 集群上也是不可见的。"`kubernetes/self/kube-scheduler-metrics-svc.yml`"是创建一个指向 Prometheus 的目标的模板。

+   **kube-dns**：kube-dns pod 中有两个容器，`dnsmasq`和`sky-dns`，它们的指标端口分别是`10054`和`10055`。相应的模板是`kubernetes/self/ kube-dns-metrics-svc.yml`。

+   **etcd**：etcd 集群也在端口`4001`上有一个 Prometheus 指标端点。如果您的 etcd 集群是自托管的并由 Kubernetes 管理，您可以将"`kubernetes/self/etcd-server.yml`"作为参考。

+   **Nginx ingress controller**：nginx 控制器在端口`10254`发布指标。但是这些指标只包含有限的信息。要获取诸如按主机或路径计算的连接计数等数据，您需要在控制器中激活`vts`模块以增强收集的指标。

# 使用 Grafana 查看指标

表达式浏览器有一个内置的图形面板，使我们能够看到可视化的指标，但它并不是设计用来作为日常例行工作的可视化仪表板。Grafana 是 Prometheus 的最佳选择。我们已经在第四章中讨论了如何设置 Grafana，*与存储和资源一起工作*，我们还为本章提供了模板；这两个选项都能胜任工作。

要在 Grafana 中查看 Prometheus 指标，我们首先必须添加一个数据源。连接到我们的 Prometheus 服务器需要以下配置：

+   类型："Prometheus"

+   网址：`http://prometheus-svc.monitoring:9090`

+   访问：代理

一旦连接上，我们就可以导入一个仪表板来看到实际的情况。在 Grafana 的共享页面（[`grafana.com/dashboards?dataSource=prometheus`](https://grafana.com/dashboards?dataSource=prometheus)）上有丰富的现成仪表板。以下截图来自仪表板`#1621`：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00102.jpeg)

因为图形是由 Prometheus 的数据绘制的，只要我们掌握 PromQL，我们就能绘制任何我们关心的数据。

# 记录事件

使用系统状态的定量时间序列进行监控，能够迅速查明系统中哪些组件出现故障，但仍然不足以诊断出症候的根本原因。因此，一个收集、持久化和搜索日志的日志系统对于通过将事件与检测到的异常相关联来揭示出出现问题的原因是非常有帮助的。

一般来说，日志系统中有两个主要组件：日志代理和日志后端。前者是一个程序的抽象层。它收集、转换和分发日志到日志后端。日志后端存储接收到的所有日志。与监控一样，为 Kubernetes 构建日志系统最具挑战性的部分是确定如何从容器中收集日志到集中的日志后端。通常有三种方式将日志发送到程序：

+   将所有内容转储到`stdout`/`stderr`

+   编写`log`文件

+   将日志发送到日志代理或直接发送到日志后端；只要我们了解日志流在 Kubernetes 中的流动方式，Kubernetes 中的程序也可以以相同的方式发出日志

# 聚合日志的模式

对于直接向日志代理或后端记录日志的程序，它们是否在 Kubernetes 内部并不重要，因为它们在技术上并不通过 Kubernetes 输出日志。至于其他情况，我们将使用以下两种模式来集中日志。

# 每个节点使用一个日志代理收集日志

我们知道通过`kubectl logs`检索到的消息是从容器的`stdout`/`stderr`重定向的流，但显然使用`kubectl logs`收集日志并不是一个好主意。实际上，`kubectl logs`从 kubelet 获取日志，kubelet 将日志聚合到主机路径`/var/log/containers/`中，从容器引擎下方获取。

因此，在每个节点上设置日志代理并配置它们尾随和转发路径下的`log`文件，这正是我们需要的，以便汇聚运行容器的标准流，如下图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00103.jpeg)

在实践中，我们还会配置一个日志代理来从系统和 Kubernetes 的组件下的`/var/log`中尾随日志，比如在主节点和节点上的：

+   `kube-proxy.log`

+   `kube-apiserver.log`

+   `kube-scheduler.log`

+   `kube-controller-manager.log`

+   `etcd.log`

除了`stdout`/`stderr`之外，如果应用程序的日志以文件形式存储在容器中，并通过`hostPath`卷持久化，节点日志代理可以将它们传递给节点。然而，对于每个导出的`log`文件，我们必须在日志代理中自定义它们对应的配置，以便它们可以被正确分发。此外，我们还需要适当命名`log`文件，以防止任何冲突，并自行处理日志轮换，这使得它成为一种不可扩展和不可管理的日志记录机制。

# 运行一个旁路容器来转发日志

有时修改我们的应用程序以将日志写入标准流而不是`log`文件是困难的，我们也不想面对使用`hostPath`卷带来的麻烦。在这种情况下，我们可以运行一个旁路容器来处理一个 pod 内的日志。换句话说，每个应用程序 pod 都将有两个共享相同`emptyDir`卷的容器，以便旁路容器可以跟踪应用程序容器的日志并将它们发送到他们的 pod 外部，如下图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00104.jpeg)

虽然我们不再需要担心管理`log`文件，但是配置每个 pod 的日志代理并将 Kubernetes 的元数据附加到日志条目中仍然需要额外的工作。另一个选择是利用旁路容器将日志输出到标准流，而不是运行一个专用的日志代理，就像下面的 pod 一样；应用容器不断地将消息写入`/var/log/myapp.log`，而旁路容器则在共享卷中跟踪`myapp.log`。

```
---6-2_logging-sidecar.yml--- 
apiVersion: v1 
kind: Pod 
metadata: 
  name: myapp 
spec: 
  containers: 
  - image: busybox 
    name: application 
    args: 
     - /bin/sh 
     - -c 
     - > 
      while true; do 
        echo "$(date) INFO hello" >> /var/log/myapp.log ; 
        sleep 1; 
      done 
    volumeMounts: 
    - name: log 
      mountPath: /var/log 
  - name: sidecar 
    image: busybox 
    args: 
     - /bin/sh 
     - -c 
     - tail -fn+1 /var/log/myapp.log 
    volumeMounts: 
    - name: log 
      mountPath: /var/log 
  volumes: 
  - name: log 
emptyDir: {}  
```

现在我们可以使用`kubectl logs`查看已写入的日志：

```
$ kubectl logs -f myapp -c sidecar
Tue Jul 25 14:51:33 UTC 2017 INFO hello
Tue Jul 25 14:51:34 UTC 2017 INFO hello
...
```

# 摄取 Kubernetes 事件

我们在`kubectl describe`的输出中看到的事件消息包含有价值的信息，并补充了 kube-state-metrics 收集的指标，这使我们能够了解我们的 pod 或节点发生了什么。因此，它应该是我们日志记录基本要素的一部分，连同系统和应用程序日志。为了实现这一点，我们需要一些东西来监视 Kubernetes API 服务器，并将事件聚合到日志输出中。而 eventer 正是我们需要的事件处理程序。

Eventer 是 Heapster 的一部分，目前支持 Elasticsearch、InfluxDB、Riemann 和 Google Cloud Logging 作为其输出。Eventer 也可以直接输出到`stdout`，以防我们使用的日志系统不受支持。

部署 eventer 类似于部署 Heapster，除了容器启动命令，因为它们打包在同一个镜像中。每种 sink 类型的标志和选项可以在这里找到：([`github.com/kubernetes/heapster/blob/master/docs/sink-configuration.md`](https://github.com/kubernetes/heapster/blob/master/docs/sink-configuration.md))。

我们为本章提供的示例模板还包括 eventer，并且它已配置为与 Elasticsearch 一起工作。我们将在下一节中进行描述。

# 使用 Fluentd 和 Elasticsearch 进行日志记录

到目前为止，我们已经讨论了我们在现实世界中可能遇到的日志记录的各种条件，现在是时候动手制作一个日志系统，应用我们所学到的知识了。

日志系统和监控系统的架构在某些方面基本相同--收集器、存储和用户界面。我们将要设置的相应组件是 Fluentd/eventer、Elasticsearch 和 Kibana。此部分的模板可以在`6-3_efk`下找到，并且它们将部署到前一部分的命名空间`monitoring`中。

Elasticsearch 是一个强大的文本搜索和分析引擎，这使它成为持久化、处理和分析我们集群中运行的所有日志的理想选择。本章的 Elasticsearch 模板使用了一个非常简单的设置来演示这个概念。如果您想要为生产使用部署 Elasticsearch 集群，建议使用 StatefulSet 控制器，并根据我们在第四章中讨论的适当配置来调整 Elasticsearch。让我们使用以下模板部署 Elasticsearch ([`github.com/DevOps-with-Kubernetes/examples/tree/master/chapter6/6-3_efk/`](https://github.com/DevOps-with-Kubernetes/examples/tree/master/chapter6/6-3_efk/))：

```
$ kubectl apply -f elasticsearch/es-config.yml
$ kubectl apply -f elasticsearch/es-logging.yml
```

如果从`es-logging-svc:9200`收到响应，则 Elasticsearch 已准备就绪。

下一步是设置节点日志代理。由于我们会在每个节点上运行它，因此我们肯定希望它在节点资源使用方面尽可能轻量化，因此选择了 Fluentd（[www.fluentd.org](http://www.fluentd.org)）。Fluentd 具有较低的内存占用，这使其成为我们需求的一个有竞争力的日志代理。此外，由于容器化环境中的日志记录要求非常专注，因此有一个类似的项目，Fluent Bit（`fluentbit.io`），旨在通过修剪不会用于其目标场景的功能来最小化资源使用。在我们的示例中，我们将使用 Fluentd 镜像用于 Kubernetes（[`github.com/fluent/fluentd-kubernetes-daemonset`](https://github.com/fluent/fluentd-kubernetes-daemonset)）来执行我们之前提到的第一个日志模式。

该图像已配置为转发容器日志到`/var/log/containers`下，以及某些系统组件的日志到`/var/log`下。如果需要，我们绝对可以进一步定制其日志配置。这里提供了两个模板：`fluentd-sa.yml`是 Fluentd DaemonSet 的 RBAC 配置，`fluentd-ds.yml`是：

```
$ kubectl apply -f fluentd/fluentd-sa.yml
$ kubectl apply -f fluentd/fluentd-ds.yml  
```

另一个必不可少的日志记录组件是 eventer。这里我们为不同条件准备了两个模板。如果您使用的是已部署 Heapster 的托管 Kubernetes 服务，则在这种情况下使用独立 eventer 的模板`eventer-only.yml`。否则，考虑在同一个 pod 中运行 Heapster 和 eventer 的模板：

```
$ kubectl apply -f heapster-eventer/heapster-eventer.yml
or
$ kubectl apply -f heapster-eventer/eventer-only.yml
```

要查看发送到 Elasticsearch 的日志，我们可以调用 Elasticsearch 的搜索 API，但有一个更好的选择，即 Kibana，这是一个允许我们与 Elasticsearch 交互的 Web 界面。Kibana 的模板是`elasticsearch/kibana-logging.yml`，位于[`github.com/DevOps-with-Kubernetes/examples/tree/master/chapter6/6-3_efk/`](https://github.com/DevOps-with-Kubernetes/examples/tree/master/chapter6/6-3_efk/)下。

```
$ kubectl apply -f elasticsearch/kibana-logging.yml  
```

在我们的示例中，Kibana 正在监听端口`5601`。在将服务暴露到集群外并使用任何浏览器连接后，您可以开始从 Kubernetes 搜索日志。由 eventer 发送的日志的索引名称是`heapster-*`，而由 Fluentd 转发的日志的索引名称是`logstash-*`。以下截图显示了 Elasticsearch 中日志条目的外观。

该条目来自我们之前的示例`myapp`，我们可以发现该条目已经在 Kubernetes 上附带了方便的元数据标记。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00105.jpeg)

# 从日志中提取指标

我们在 Kubernetes 上构建的围绕我们应用程序的监控和日志系统如下图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00106.jpeg)

监控部分和日志部分看起来像是两条独立的轨道，但日志的价值远不止一堆短文本。它们是结构化数据，并像往常一样带有时间戳；因此，将日志转换为时间序列数据的想法是有前途的。然而，尽管 Prometheus 非常擅长处理时间序列数据，但它无法在没有任何转换的情况下摄取文本。

来自 HTTPD 的访问日志条目如下：

`10.1.8.10 - - [07/Jul/2017:16:47:12 0000] "GET /ping HTTP/1.1" 200 68`。

它包括请求的 IP 地址、时间、方法、处理程序等。如果我们根据它们的含义划分日志段，计数部分就可以被视为一个指标样本，如下所示：`"10.1.8.10": 1, "GET": 1, "/ping": 1, "200": 1`。

诸如 mtail（[`github.com/google/mtail`](https://github.com/google/mtail)）和 Grok Exporter（[`github.com/fstab/grok_exporter`](https://github.com/fstab/grok_exporter)）之类的工具会计算日志条目并将这些数字组织成指标，以便我们可以在 Prometheus 中进一步处理它们。

# 摘要

在本章的开始，我们描述了如何通过内置函数（如`kubectl`）快速获取运行容器的状态。然后，我们扩展了对监控的概念和原则的讨论，包括为什么需要进行监控，要监控什么以及如何进行监控。随后，我们以 Prometheus 为核心构建了一个监控系统，并设置了导出器来收集来自 Kubernetes 的指标。还介绍了 Prometheus 的基础知识，以便我们可以利用指标更好地了解我们的集群以及其中运行的应用程序。在日志部分，我们提到了日志记录的常见模式以及在 Kubernetes 中如何处理它们，并部署了一个 EFK 堆栈来汇聚日志。本章中构建的系统有助于我们服务的可靠性。接下来，我们将继续在 Kubernetes 中建立一个持续交付产品的流水线。


# 第七章：持续交付

到目前为止，我们讨论的主题使我们能够在 Kubernetes 中运行我们的服务。通过监控系统，我们对我们的服务更有信心。我们接下来想要实现的下一件事是如何在 Kubernetes 中持续交付我们的最新功能和改进我们的服务，并且我们将在本章的以下主题中学习它：

+   更新 Kubernetes 资源

+   建立交付流水线

+   改进部署过程的技术

# 更新资源

持续交付的属性就像我们在第一章中描述的那样，是一组操作，包括**持续集成**（**CI**）和随后的部署任务。CI 流程包括版本控制系统、构建和不同级别的自动化测试等元素。实现 CI 功能的工具通常位于应用程序层，可以独立于基础架构，但是在实现部署时，由于部署任务与我们的应用程序运行的平台紧密相关，理解和处理基础架构是不可避免的。在软件运行在物理或虚拟机上的环境中，我们会利用配置管理工具、编排器和脚本来部署我们的软件。然而，如果我们在像 Heroku 这样的应用平台上运行我们的服务，甚至是在无服务器模式下，设计部署流水线将是完全不同的故事。总之，部署任务的目标是确保我们的软件在正确的位置正常工作。在 Kubernetes 中，这涉及如何正确更新资源，特别是 Pod。

# 触发更新

在第三章中，*开始使用 Kubernetes*，我们已经讨论了部署中 Pod 的滚动更新机制。让我们回顾一下在更新过程触发后会发生什么：

1.  部署根据更新后的清单创建一个新的`ReplicaSet`，其中包含`0`个 Pod。

1.  新的`ReplicaSet`逐渐扩展，同时先前的`ReplicaSet`不断缩小。

1.  所有旧的 Pod 被替换后，该过程结束。

Kubernetes 会自动完成这样的机制，使我们免于监督更新过程。要触发它，我们只需要通知 Kubernetes 更新 Deployment 的 pod 规范，也就是修改 Kubernetes 中一个资源的清单。假设我们有一个 Deployment `my-app`（请参阅本节示例目录下的`ex-deployment.yml`），我们可以使用`kubectl`的子命令修改清单如下：

+   `kubectl patch`：根据输入的 JSON 参数部分地修补对象的清单。如果我们想将`my-app`的镜像从`alpine:3.5`更新到`alpine:3.6`，可以这样做：

```
$ kubectl patch deployment my-app -p '{"spec":{"template":{"spec":{"containers":[{"name":"app","image":"alpine:3.6"}]}}}}'
```

+   `kubectl set`：更改对象的某些属性。这是直接更改某些属性的快捷方式，其中支持的属性之一是 Deployment 的镜像：

```
$ kubectl set image deployment my-app app=alpine:3.6
```

+   `kubectl edit`：打开编辑器并转储当前的清单，以便我们可以进行交互式编辑。修改后的清单在保存后立即生效。

+   `kubectl replace`：用另一个提交的模板文件替换一个清单。如果资源尚未创建或包含无法更改的属性，则会产生错误。例如，在我们的示例模板`ex-deployment.yml`中有两个资源，即 Deployment `my-app`及其 Service `my-app-svc`。让我们用一个新的规范文件替换它们：

```
$ kubectl replace -f ex-deployment.yml
deployment "my-app" replaced
The Service "my-app-svc" is invalid: spec.clusterIP: Invalid value: "": field is immutable
$ echo $?
1
```

替换后，即使结果符合预期，我们会看到错误代码为`1`，也就是说，更新的是 Deployment 而不是 Service。特别是在为 CI/CD 流程编写自动化脚本时，应该注意这种行为。

+   `kubectl apply`：无论如何都应用清单文件。换句话说，如果资源存在于 Kubernetes 中，则会被更新，否则会被创建。当使用`kubectl apply`创建资源时，其功能大致相当于`kubectl create --save-config`。应用的规范文件将相应地保存到注释字段`kubectl.kubernetes.io/last-applied-configuration`中，我们可以使用子命令`edit-last-applied`、`set-last-applied`和`view-last-applied`来操作它。例如，我们可以查看之前提交的模板，无论`ex-deployment.yml`的实际内容如何。

```
$ kubectl apply -f ex-deployment.yml view-last-applied
```

保存的清单信息将与我们发送的完全相同，不同于通过`kubectl get -o yaml/json`检索的清单，后者包含对象的实时状态，以及规范。

尽管在本节中我们只关注操作部署，但这里的命令也适用于更新所有其他 Kubernetes 资源，如 Service、Role 等。

对 `ConfigMap` 和 secret 的更改通常需要几秒钟才能传播到 pods。

与 Kubernetes 的 API 服务器进行交互的推荐方式是使用 `kubectl`。如果您处于受限制的环境中，还可以使用 REST API 来操作 Kubernetes 的资源。例如，我们之前使用的 `kubectl patch` 命令将变为如下所示：

```
$ curl -X PATCH -H 'Content-Type: application/strategic-merge-patch+json' --data '{"spec":{"template":{"spec":{"containers":[{"name":"app","image":"alpine:3.6"}]}}}}' 'https://$KUBEAPI/apis/apps/v1beta1/namespaces/default/deployments/my-app'
```

这里的变量 `$KUBEAPI` 是 API 服务器的端点。有关更多信息，请参阅 API 参考：[`kubernetes.io/docs/api-reference/v1.7/`](https://kubernetes.io/docs/api-reference/v1.7/)。

# 管理部署

一旦触发了滚动更新过程，Kubernetes 将在幕后默默完成所有任务。让我们进行一些实际的实验。同样，即使我们使用了之前提到的命令修改了一些内容，滚动更新过程也不会被触发，除非相关的 pod 规范发生了变化。我们准备的示例是一个简单的脚本，它会响应任何请求并显示其主机名和其运行的 Alpine 版本。我们首先创建 Deployment，并在另一个终端中不断检查其响应：

```
$ kubectl apply -f ex-deployment.yml
deployment "my-app" created
service "my-app-svc" created
$ kubectl proxy
Starting to serve on 127.0.0.1:8001
// switch to another terminal #2
$ while :; do curl localhost:8001/api/v1/proxy/namespaces/default/services/my-app-svc:80/; sleep 1; 

done
my-app-3318684939-pwh41-v-3.5.2 is running...
my-app-3318684939-smd0t-v-3.5.2 is running...
...
```

现在我们将其图像更改为另一个版本，看看响应是什么：

```
$ kubectl set image deployment my-app app=alpine:3.6
deployment "my-app" image updated
// switch to terminal #2
my-app-99427026-7r5lr-v-3.6.2 is running...
my-app-3318684939-pwh41-v-3.5.2 is running...
...
```

来自版本 3.5 和 3.6 的消息在更新过程结束之前交错显示。为了立即确定来自 Kubernetes 的更新进程状态，而不是轮询服务端点，有 `kubectl rollout` 用于管理滚动更新过程，包括检查正在进行的更新的进度。让我们看看使用子命令 `status` 进行的滚动更新的操作：

```
$ kubectl rollout status deployment my-app
Waiting for rollout to finish: 3 of 5 updated replicas are available...
Waiting for rollout to finish: 3 of 5 updated replicas are available...
Waiting for rollout to finish: 4 of 5 updated replicas are available...
Waiting for rollout to finish: 4 of 5 updated replicas are available...
deployment "my-app" successfully rolled out
```

此时，终端 #2 的输出应该全部来自版本 3.6。子命令 `history` 允许我们审查 `deployment` 的先前更改：

```
$ kubectl rollout history deployment my-app
REVISION    CHANGE-CAUSE
1           <none>
2           <none>  
```

然而，`CHANGE-CAUSE` 字段没有显示任何有用的信息，帮助我们了解修订的详细信息。为了利用它，在导致更改的每个命令之后添加一个标志 `--record`，就像我们之前介绍的那样。当然，`kubectl create` 也支持记录标志。

让我们对部署进行一些更改，比如修改`my-app`的 pod 的环境变量`DEMO`。由于这会导致 pod 规范的更改，部署将立即开始。这种行为允许我们触发更新而无需构建新的镜像。为了简单起见，我们使用`patch`来修改变量：

```
$ kubectl patch deployment my-app -p '{"spec":{"template":{"spec":{"containers":[{"name":"app","env":[{"name":"DEMO","value":"1"}]}]}}}}' --record
deployment "my-app" patched
$ kubectl rollout history deployment my-app
deployments "my-app"
REVISION    CHANGE-CAUSE
1           <none>
2           <none>
3           kubectl patch deployment my-app --
patch={"spec":{"template":{"spec":{"containers":
[{"name":"app","env":[{"name":"DEMO","value":"1"}]}]}}}} --record=true  
```

`REVISION 3`的`CHANGE-CAUSE`清楚地记录了提交的命令。尽管如此，只有命令会被记录下来，这意味着任何通过`edit`/`apply`/`replace`进行的修改都不会被明确标记。如果我们想获取以前版本的清单，只要我们的更改是通过`apply`进行的，我们就可以检索保存的配置。

出于各种原因，有时我们希望回滚我们的应用，即使部署在一定程度上是成功的。可以通过子命令`undo`来实现：

```
$ kubectl rollout undo deployment my-app
deployment "my-app" rolled back
```

整个过程基本上与更新是相同的，即应用先前的清单，然后执行滚动更新。此外，我们可以利用标志`--to-revision=<REVISION#>`回滚到特定版本，但只有保留的修订版本才能回滚。Kubernetes 根据部署对象中的`revisionHistoryLimit`参数确定要保留多少修订版本。

更新的进度由`kubectl rollout pause`和`kubectl rollout resume`控制。正如它们的名称所示，它们应该成对使用。部署的暂停不仅意味着停止正在进行的部署，还意味着冻结任何滚动更新，即使规范被修改，除非它被恢复。

# 更新 DaemonSet 和 StatefulSet

Kubernetes 支持各种方式来编排不同类型的工作负载的 pod。除了部署外，还有`DaemonSet`和`StatefulSet`用于长时间运行的非批处理工作负载。由于它们生成的 pod 比部署有更多的约束，我们应该了解处理它们的更新时的注意事项

# DaemonSet

`DaemonSet`是一个专为系统守护程序设计的控制器，正如其名称所示。因此，`DaemonSet`在每个节点上启动和维护一个 Pod，也就是说，`DaemonSet`的总 Pod 数量符合集群中节点的数量。由于这种限制，更新`DaemonSet`不像更新 Deployment 那样直接。例如，Deployment 有一个`maxSurge`参数（`.spec.strategy.rollingUpdate.maxSurge`），用于控制更新期间可以创建多少超出所需数量的冗余 Pod。但是我们不能对`DaemonSet`的 Pod 采用相同的策略，因为`DaemonSet`通常占用主机的资源，如端口。如果在一个节点上同时有两个或更多的系统 Pod，可能会导致错误。因此，更新的形式是在主机上终止旧的 Pod 后创建一个新的 Pod。

Kubernetes 为`DaemonSet`实现了两种更新策略，即`OnDelete`和`rollingUpdate`。一个示例演示了如何编写`DaemonSet`的模板，位于`7-1_updates/ex-daemonset.yml`。更新策略设置在路径`.spec.updateStrategy.type`处，默认情况下在 Kubernetes 1.7 中为`OnDelete`，在 Kubernetes 1.8 中变为`rollingUpdate`：

+   `OnDelete`：只有在手动删除 Pod 后才会更新。

+   `rollingUpdate`：它实际上的工作方式类似于`OnDelete`，但是 Kubernetes 会自动执行 Pod 的删除。有一个可选参数`.spec.updateStrategy.rollingUpdate.maxUnavailable`，类似于 Deployment 中的参数。其默认值为`1`，这意味着 Kubernetes 会逐个节点替换一个 Pod。

滚动更新过程的触发与 Deployment 的相同。此外，我们还可以利用`kubectl rollout`来管理`DaemonSet`的滚动更新。但是不支持`pause`和`resume`。

`DaemonSet`的滚动更新仅适用于 Kubernetes 1.6 及以上版本。

# StatefulSet

`StatefulSet`和`DaemonSet`的更新方式基本相同——它们在更新期间不会创建冗余的 Pod，它们的更新策略也表现出类似的行为。在`7-1_updates/ex-statefulset.yml`中还有一个模板文件供练习。更新策略的选项设置在路径`.spec.updateStrategy.type`处：

+   `OnDelete`：只有在手动删除 Pod 后才会更新。

+   `rollingUpdate`：像每次滚动更新一样，Kubernetes 以受控的方式删除和创建 Pod。但是 Kubernetes 知道在`StatefulSet`中顺序很重要，所以它会按照相反的顺序替换 Pod。假设我们在`StatefulSet`中有三个 Pod，它们分别是`my-ss-0`、`my-ss-1`、`my-ss-2`。然后更新顺序从`my-ss-2`开始到`my-ss-0`。删除过程不遵守 Pod 管理策略，也就是说，即使我们将 Pod 管理策略设置为`Parallel`，更新仍然会逐个执行。

类型`rollingUpdate`的唯一参数是分区（`.spec.updateStrategy.rollingUpdate.partition`）。如果指定了分区，任何序数小于分区号的 Pod 将保持其当前版本，不会被更新。例如，在具有 3 个 Pod 的`StatefulSet`中将其设置为 1，只有 pod-1 和 pod-2 会在发布后进行更新。该参数允许我们在一定程度上控制进度，特别适用于等待数据同步、使用金丝雀进行测试发布，或者我们只是想分阶段进行更新。

Pod 管理策略和滚动更新是 Kubernetes 1.7 及更高版本中实现的两个功能。

# 构建交付流水线

为容器化应用程序实施持续交付流水线非常简单。让我们回顾一下到目前为止我们对 Docker 和 Kubernetes 的学习，并将它们组织成 CD 流水线。假设我们已经完成了我们的代码、Dockerfile 和相应的 Kubernetes 模板。要将它们部署到我们的集群，我们需要经历以下步骤：

1.  `docker build`：生成一个可执行的不可变构件。

1.  `docker run`：验证构建是否通过了一些简单的测试。

1.  `docker tag`：如果构建成功，为其打上有意义的版本标签。

1.  `docker push`：将构建移动到构件存储库以进行分发。

1.  `kubectl apply`：将构建部署到所需的环境中。

1.  `kubectl rollout status`：跟踪部署任务的进展。

这就是一个简单但可行的交付流水线。

# 选择工具

为了使流水线持续交付构建，我们至少需要三种工具，即版本控制系统、构建服务器和用于存储容器构件的存储库。在本节中，我们将基于前几章介绍的 SaaS 工具设置一个参考 CD 流水线。它们是*GitHub* ([`github.com`](https://github.com))、*Travis CI* ([`travis-ci.org`](https://travis-ci.org))和*Docker Hub* ([`hub.docker.com`](https://hub.docker.com))，它们都对开源项目免费。我们在这里使用的每个工具都有许多替代方案，比如 GitLab 用于 VCS，或者托管 Jenkins 用于 CI。以下图表是基于前面三个服务的 CD 流程：

>![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00107.jpeg)

工作流程始于将代码提交到 GitHub 上的存储库，提交将调用 Travis CI 上的构建作业。我们的 Docker 镜像是在这个阶段构建的。同时，我们经常在 CI 服务器上运行不同级别的测试，以确保构建的质量稳固。此外，由于使用 Docker Compose 或 Kubernetes 运行应用程序堆栈比以往任何时候都更容易，我们能够在构建作业中运行涉及许多组件的测试。随后，经过验证的镜像被打上标识并推送到公共 Docker Registry 服务 Docker Hub。

我们的流水线中没有专门用于部署任务的块。相反，我们依赖 Travis CI 来部署我们的构建。事实上，部署任务仅仅是在镜像推送后，在某些构建上应用 Kubernetes 模板。最后，在 Kubernetes 的滚动更新过程结束后，交付就完成了。

# 解释的步骤

我们的示例`my-app`是一个不断回显`OK`的 Web 服务，代码以及部署文件都提交在我们在 GitHub 上的存储库中：([`github.com/DevOps-with-Kubernetes/my-app`](https://github.com/DevOps-with-Kubernetes/my-app))。

在配置 Travis CI 上的构建之前，让我们首先在 Docker Hub 上创建一个镜像存储库以备后用。登录 Docker Hub 后，点击右上角的 Create Repository，然后按照屏幕上的步骤创建一个。用于推送和拉取的`my-app`镜像注册表位于`devopswithkubernetes/my-app` ([`hub.docker.com/r/devopswithkubernetes/my-app/`](https://hub.docker.com/r/devopswithkubernetes/my-app/))。

将 Travis CI 与 GitHub 存储库连接起来非常简单，我们只需要授权 Travis CI 访问我们的 GitHub 存储库，并在个人资料页面启用 Travis CI 构建存储库即可([`travis-ci.org/profile`](https://travis-ci.org/profile))。

Travis CI 中作业的定义是在同一存储库下放置的`.travis.yml`文件中配置的。它是一个 YAML 格式的模板，由一系列告诉 Travis CI 在构建期间应该做什么的 shell 脚本块组成。我们的`.travis.yml`文件块的解释如下：([`github.com/DevOps-with-Kubernetes/my-app/blob/master/.travis.yml`](https://github.com/DevOps-with-Kubernetes/my-app/blob/master/.travis.yml))

# env

这个部分定义了在整个构建过程中可见的环境变量：

```
DOCKER_REPO=devopswithkubernetes/my-app     BUILD_IMAGE_PATH=${DOCKER_REPO}:b${TRAVIS_BUILD_NUMBER}
RELEASE_IMAGE_PATH=${DOCKER_REPO}:${TRAVIS_TAG}
RELEASE_TARGET_NAMESPACE=default  
```

在这里，我们设置了一些可能会更改的变量，比如命名空间和构建图像的 Docker 注册表路径。此外，还有关于构建的元数据从 Travis CI 以环境变量的形式传递，这些都在这里记录着：[`docs.travis-ci.com/user/environment-variables/#Default-Environment- Variables`](https://docs.travis-ci.com/user/environment-variables/#Default-Environment-Variables)。例如，`TRAVIS_BUILD_NUMBER`代表当前构建的编号，我们将其用作标识符来区分不同构建中的图像。

另一个环境变量的来源是在 Travis CI 上手动配置的。因为在那里配置的变量会被公开隐藏，所以我们在那里存储了一些敏感数据，比如 Docker Hub 和 Kubernetes 的凭据：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00108.jpeg)

每个 CI 工具都有自己处理密钥的最佳实践。例如，一些 CI 工具也允许我们在 CI 服务器中保存变量，但它们仍然会在构建日志中打印出来，所以在这种情况下我们不太可能在 CI 服务器中保存密钥。

# 脚本

这个部分是我们运行构建和测试的地方：

```
docker build -t my-app .
docker run --rm --name app -dp 5000:5000 my-app
sleep 10
CODE=$(curl -IXGET -so /dev/null -w "%{http_code}" localhost:5000)
'[ ${CODE} -eq 200 ] && echo "Image is OK"'
docker stop app  
```

因为我们使用 Docker，所以构建只需要一行脚本。我们的测试也很简单——使用构建的图像启动一个容器，并对其进行一些请求以确定其正确性和完整性。当然，在这个阶段我们可以做任何事情，比如添加单元测试、进行多阶段构建，或者运行自动化集成测试来改进最终的构件。

# 成功后

只有前一个阶段没有任何错误结束时，才会执行这个块。一旦到了这里，我们就可以发布我们的图像了：

```
docker login -u ${CI_ENV_REGISTRY_USER} -p "${CI_ENV_REGISTRY_PASS}"
docker tag my-app ${BUILD_IMAGE_PATH}
docker push ${BUILD_IMAGE_PATH}
if [[ ${TRAVIS_TAG} =~ ^rel.*$ ]]; then
 docker tag my-app ${RELEASE_IMAGE_PATH}
 docker push ${RELEASE_IMAGE_PATH}
fi
```

我们的镜像标签在 Travis CI 上简单地使用构建编号，但使用提交的哈希或版本号来标记镜像也很常见。然而，强烈不建议使用默认标签`latest`，因为这可能导致版本混淆，比如运行两个不同的镜像，但它们有相同的名称。最后的条件块是在特定分支标签上发布镜像，实际上并不需要，因为我们只是想保持在一个单独的轨道上构建和发布。在推送镜像之前，请记得对 Docker Hub 进行身份验证。

Kubernetes 决定是否应该拉取镜像的`imagePullPolicy`：[`kubernetes.io/docs/concepts/containers/images/#updating-images`](https://kubernetes.io/docs/concepts/containers/images/#updating-images)。

因为我们将项目部署到实际机器上只在发布时，构建可能会在那一刻停止并返回。让我们看看这个构建的日志：[`travis-ci.org/DevOps-with-Kubernetes/my-app/builds/268053332`](https://travis-ci.org/DevOps-with-Kubernetes/my-app/builds/268053332)。日志保留了 Travis CI 执行的脚本和脚本每一行的输出：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00109.jpeg)

正如我们所看到的，我们的构建是成功的，所以镜像随后在这里发布：

[`hub.docker.com/r/devopswithkubernetes/my-app/tags/`](https://hub.docker.com/r/devopswithkubernetes/my-app/tags/)。

构建引用标签`b1`，我们现在可以在 CI 服务器外运行它：

```
$ docker run --name test -dp 5000:5000 devopswithkubernetes/my-app:b1
72f0ef501dc4c86786a81363e278973295a1f67555eeba102a8d25e488831813
$ curl localhost:5000
OK
```

# 部署

尽管我们可以实现端到端的完全自动化流水线，但由于业务原因，我们经常会遇到需要暂停部署构建的情况。因此，我们告诉 Travis CI 只有在发布新版本时才运行部署脚本。

在 Travis CI 中从我们的 Kubernetes 集群中操作资源，我们需要授予 Travis CI 足够的权限。我们的示例使用了一个名为`cd-agent`的服务账户，在 RBAC 模式下代表我们创建和更新部署。后面的章节将对 RBAC 进行更多描述。创建账户和权限的模板在这里：[`github.com/DevOps-with-Kubernetes/examples/tree/master/chapter7/7-2_service-account-for-ci-tool`](https://github.com/DevOps-with-Kubernetes/examples/tree/master/chapter7/7-2_service-account-for-ci-tool)。该账户是在`cd`命名空间下创建的，并被授权在各个命名空间中创建和修改大多数类型的资源。

在这里，我们使用一个能够读取和修改跨命名空间的大多数资源，包括整个集群的密钥的服务账户。由于安全问题，始终鼓励限制服务账户对实际使用的资源的权限，否则可能存在潜在的漏洞。

因为 Travis CI 位于我们的集群之外，我们必须从 Kubernetes 导出凭据，以便我们可以配置我们的 CI 任务来使用它们。在这里，我们提供了一个简单的脚本来帮助导出这些凭据。脚本位于：[`github.com/DevOps-with-Kubernetes/examples/blob/master/chapter7/get-sa-token.sh`](https://github.com/DevOps-with-Kubernetes/examples/blob/master/chapter7/get-sa-token.sh)。

```
$ ./get-sa-token.sh --namespace cd --account cd-agent
API endpoint:
https://35.184.53.170
ca.crt and sa.token exported
$ cat ca.crt | base64
LS0tLS1C...
$ cat sa.token
eyJhbGci...
```

导出的 API 端点、`ca.crt` 和 `sa.token` 的对应变量分别是 `CI_ENV_K8S_MASTER`、`CI_ENV_K8S_CA` 和 `CI_ENV_K8S_SA_TOKEN`。客户端证书（`ca.crt`）被编码为 base64 以实现可移植性，并且将在我们的部署脚本中解码。

部署脚本（[`github.com/DevOps-with-Kubernetes/my-app/blob/master/deployment/deploy.sh`](https://github.com/DevOps-with-Kubernetes/my-app/blob/master/deployment/deploy.sh)）首先下载 `kubectl`，并根据环境变量配置 `kubectl`。之后，当前构建的镜像路径被填入部署模板中，并且模板被应用。最后，在部署完成后，我们的部署就完成了。

让我们看看整个流程是如何运作的。

一旦我们在 GitHub 上发布一个版本：

[`github.com/DevOps-with-Kubernetes/my-app/releases/tag/rel.0.3`](https://github.com/DevOps-with-Kubernetes/my-app/releases/tag/rel.0.3)

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00110.jpeg)

Travis CI 在那之后开始构建我们的任务：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00111.jpeg)

一段时间后，构建的镜像被推送到 Docker Hub 上：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00112.jpeg)

在这一点上，Travis CI 应该开始运行部署任务，让我们查看构建日志以了解我们部署的状态：

[`travis-ci.org/DevOps-with-Kubernetes/my-app/builds/268107714`](https://travis-ci.org/DevOps-with-Kubernetes/my-app/builds/268107714)

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00113.jpeg)

正如我们所看到的，我们的应用已经成功部署，应该开始用 `OK` 欢迎每个人：

```
$ kubectl get deployment
NAME      DESIRED   CURRENT   UP-TO-DATE   AVAILABLE   AGE
my-app    3         3         3            3           30s
$ kubectl proxy &
$ curl localhost:8001/api/v1/namespaces/default/services/my-app-svc:80/proxy/
OK
```

我们在本节中构建和演示的流水线是在 Kubernetes 中持续交付代码的经典流程。然而，由于工作风格和文化因团队而异，为您的团队设计一个量身定制的持续交付流水线将带来效率提升的回报。

# 深入了解 pod

尽管在 pod 的生命周期中，出生和死亡仅仅是一瞬间，但它们是服务最脆弱的时刻。在现实世界中，常见的情况，如将请求路由到未准备就绪的盒子，或者残酷地切断所有正在进行的连接到终止的机器，都是我们要避免的。因此，即使 Kubernetes 为我们处理了大部分事情，我们也应该知道如何正确配置它，以便在部署时更加自信。

# 启动一个 pod

默认情况下，Kubernetes 在 pod 启动后立即将其状态转换为 Running。如果 pod 在服务后面，端点控制器会立即向 Kubernetes 注册一个端点。稍后，kube-proxy 观察端点的变化，并相应地向 iptables 添加规则。外部世界的请求现在会发送到 pod。Kubernetes 使得 pod 的注册速度非常快，因此有可能在应用程序准备就绪之前就已经发送请求到 pod，尤其是在处理庞大软件时。另一方面，如果 pod 在运行时失败，我们应该有一种自动的方式立即将其移除。

Deployment 和其他控制器的`minReadySeconds`字段不会推迟 pod 的就绪状态。相反，它会延迟 pod 的可用性，在部署过程中具有意义：只有当所有 pod 都可用时，部署才算成功。

# 活跃性和就绪性探针

探针是对容器健康状况的指示器。它通过定期对容器执行诊断操作来判断健康状况，通过 kubelet 进行：

+   **活跃性探针**：指示容器是否存活。如果容器在此探针上失败，kubelet 会将其杀死，并根据 pod 的`restartPolicy`可能重新启动它。

+   **就绪性探针**：指示容器是否准备好接收流量。如果服务后面的 pod 尚未准备就绪，其端点将在 pod 准备就绪之前不会被创建。

`retartPolicy`指示 Kubernetes 在失败或终止时如何处理 pod。它有三种模式：`Always`，`OnFailure`或`Never`。默认设置为`Always`。

可以配置三种类型的操作处理程序来针对容器执行：

+   `exec`：在容器内执行定义的命令。如果退出代码为`0`，则被视为成功。

+   `tcpSocket`：通过 TCP 测试给定端口，如果端口打开则成功。

+   `httpGet`：对目标容器的 IP 地址执行`HTTP GET`。要发送的请求中的标头是可定制的。如果状态码满足：`400 > CODE >= 200`，则此检查被视为健康。

此外，有五个参数来定义探针的行为：

+   `initialDelaySeconds`：第一次探测之前 kubelet 应等待多长时间。

+   `successThreshold`：当连续多次探测成功通过此阈值时，容器被视为健康。

+   `failureThreshold`：与前面相同，但定义了负面。

+   `timeoutSeconds`：单个探测操作的时间限制。

+   `periodSeconds`：探测操作之间的间隔。

以下代码片段演示了就绪探针的用法，完整模板在这里：[`github.com/DevOps-with-Kubernetes/examples/blob/master/chapter7/7-3_on_pods/probe.yml`](https://github.com/DevOps-with-Kubernetes/examples/blob/master/chapter7/7-3_on_pods/probe.yml)

```
...
 containers:
 - name: main
 image: devopswithkubernetes/my-app:b5
 readinessProbe:
 httpGet:
 path: /
 port: 5000
 periodSeconds: 5
 initialDelaySeconds: 10
 successThreshold: 2
 failureThreshold: 3 
 timeoutSeconds: 1
 command:
...
```

探针的行为如下图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00114.jpeg)

上方时间线是 pod 的真实就绪情况，下方的另一条线是 Kubernetes 视图中的就绪情况。第一次探测在 pod 创建后 10 秒执行，经过 2 次探测成功后，pod 被视为就绪。几秒钟后，由于未知原因，pod 停止服务，并在接下来的三次失败后变得不可用。尝试部署上述示例并观察其输出：

```
...
Pod is created at 1505315576
starting server at 1505315583.436334
1505315586.443435 - GET / HTTP/1.1
1505315591.443195 - GET / HTTP/1.1
1505315595.869020 - GET /from-tester
1505315596.443414 - GET / HTTP/1.1
1505315599.871162 - GET /from-tester
stopping server at 1505315599.964793
1505315601 readiness test fail#1
1505315606 readiness test fail#2
1505315611 readiness test fail#3
...
```

在我们的示例文件中，还有另一个名为`tester`的 pod，它不断地向我们的服务发出请求，而我们服务中的日志条目`/from-tester`是由该测试人员引起的。从测试人员的活动日志中，我们可以观察到从`tester`发出的流量在我们的服务变得不可用后停止了：

```
$ kubectl logs tester
1505315577 - nc: timed out
1505315583 - nc: timed out
1505315589 - nc: timed out
1505315595 - OK
1505315599 - OK
1505315603 - HTTP/1.1 500
1505315607 - HTTP/1.1 500
1505315612 - nc: timed out
1505315617 - nc: timed out
1505315623 - nc: timed out
...
```

由于我们没有在服务中配置活动探针，除非我们手动杀死它，否则不健康的容器不会重新启动。因此，通常情况下，我们会同时使用这两种探针，以使治疗过程自动化。

# 初始化容器

尽管`initialDelaySeconds`允许我们在接收流量之前阻塞 Pod 一段时间，但仍然有限。想象一下，如果我们的应用程序正在提供一个从其他地方获取的文件，那么就绪时间可能会根据文件大小而有很大的不同。因此，在这里初始化容器非常有用。

初始化容器是一个或多个在应用容器之前启动并按顺序完成的容器。如果任何容器失败，它将受到 Pod 的`restartPolicy`的影响，并重新开始，直到所有容器以代码`0`退出。

定义初始化容器类似于常规容器：

```
...
spec:
 containers:
 - name: my-app
 image: <my-app>
 initContainers:
 - name: init-my-app
 image: <init-my-app>
...
```

它们只在以下方面有所不同：

+   初始化容器没有就绪探针，因为它们会运行到完成

+   初始化容器中定义的端口不会被 Pod 前面的服务捕获

+   资源的请求/限制是通过`max(sum(regular containers), max(init containers))`计算的，这意味着如果一个初始化容器设置了比其他初始化容器以及所有常规容器的资源限制之和更高的资源限制，Kubernetes 会根据初始化容器的资源限制来调度 Pod

初始化容器的用处不仅仅是阻塞应用容器。例如，我们可以利用它们通过在初始化容器和应用容器之间共享`emptyDir`卷来配置一个镜像，而不是构建另一个仅在基础镜像上运行`awk`/`sed`的镜像，挂载并在初始化容器中使用秘密而不是在应用容器中使用。

# 终止一个 Pod

关闭事件的顺序类似于启动 Pod 时的事件。在接收到删除调用后，Kubernetes 向要删除的 Pod 发送`SIGTERM`，Pod 的状态变为 Terminating。与此同时，如果 Pod 支持服务，Kubernetes 会删除该 Pod 的端点以停止进一步的请求。偶尔会有一些 Pod 根本不会退出。这可能是因为 Pod 不遵守`SIGTERM`，或者仅仅是因为它们的任务尚未完成。在这种情况下，Kubernetes 会在终止期间之后强制发送`SIGKILL`来强制杀死这些 Pod。终止期限的长度在 Pod 规范的`.spec.terminationGracePeriodSeconds`下设置。尽管 Kubernetes 已经有机制来回收这些 Pod，我们仍然应该确保我们的 Pod 能够正确关闭。

此外，就像启动一个 pod 一样，这里我们还需要注意一个可能影响我们服务的情况，即在 pod 中为请求提供服务的进程在相应的 iptables 规则完全删除之前关闭。

# 处理 SIGTERM

优雅终止不是一个新的想法，在编程中是一个常见的做法，特别是对于业务关键任务而言尤为重要。

实现主要包括三个步骤：

1.  添加一个处理程序来捕获终止信号。

1.  在处理程序中执行所有必需的操作，比如返回资源、释放分布式锁或关闭连接。

1.  程序关闭。我们之前的示例演示了这个想法：在`graceful_exit_handler`处理程序中关闭`SIGTERM`上的控制器线程。代码可以在这里找到([`github.com/DevOps-with-Kubernetes/my-app/blob/master/app.py`](https://github.com/DevOps-with-Kubernetes/my-app/blob/master/app.py))。

事实上，导致优雅退出失败的常见陷阱并不在程序方面：

# SIGTERM 不会转发到容器进程

在第二章 *使用容器进行 DevOps*中，我们已经学习到在编写 Dockerfile 时调用我们的程序有两种形式，即 shell 形式和 exec 形式，而在 Linux 容器上运行 shell 形式命令的默认 shell 是`/bin/sh`。让我们看看以下示例([`github.com/DevOps-with-Kubernetes/examples/tree/master/chapter7/7-3_on_pods/graceful_docker`](https://github.com/DevOps-with-Kubernetes/examples/tree/master/chapter7/7-3_on_pods/graceful_docker))：

```
--- Dockerfile.shell-sh ---
FROM python:3-alpine
EXPOSE 5000
ADD app.py .
CMD python -u app.py
```

我们知道发送到容器的信号将被容器内的`PID 1`进程捕获，所以让我们构建并运行它。

```
$ docker run -d --rm --name my-app my-app:shell-sh
8962005f3722131f820e750e72d0eb5caf08222bfbdc5d25b6f587de0f6f5f3f 
$ docker logs my-app
starting server at 1503839211.025133
$ docker kill --signal TERM my-app
my-app
$ docker ps --filter name=my-app --format '{{.Names}}'
my-app
```

我们的容器还在那里。让我们看看容器内发生了什么：

```
$ docker exec my-app ps
PID   USER     TIME    COMMAND
1     root      0:00  /bin/sh -c python -u app.py
5     root      0:00  python -u app.py
6     root      0:00  ps  
```

`PID 1`进程本身就是 shell，并且显然不会将我们的信号转发给子进程。在这个例子中，我们使用 Alpine 作为基础镜像，它使用`ash`作为默认 shell。如果我们用`/bin/sh`执行任何命令，实际上是链接到`ash`的。同样，Debian 家族的默认 shell 是`dash`，它也不会转发信号。仍然有一个转发信号的 shell，比如`bash`。为了利用`bash`，我们可以安装额外的 shell，或者将基础镜像切换到使用`bash`的发行版。但这两种方法都相当繁琐。

此外，仍然有解决信号问题的选项，而不使用`bash`。其中一个是以 shell 形式在`exec`中运行我们的程序：

```
CMD exec python -u app.py
```

我们的进程将替换 shell 进程，从而成为`PID 1`进程。另一个选择，也是推荐的选择，是以 EXEC 形式编写`Dockerfile`：

```
CMD [ "python", "-u", "app.py" ] 
```

让我们再试一次以 EXEC 形式的示例：

```
---Dockerfile.exec-sh---
FROM python:3-alpine
EXPOSE 5000
ADD app.py .
CMD [ "python", "-u", "app.py" ]
---
$ docker run -d --rm --name my-app my-app:exec-sh
5114cabae9fcec530a2f68703d5bc910d988cb28acfede2689ae5eebdfd46441
$ docker exec my-app ps
PID   USER     TIME   COMMAND
1     root       0:00  python -u app.py
5     root       0:00  ps
$ docker kill --signal TERM my-app && docker logs -f my-app
my-app
starting server at 1503842040.339449
stopping server at 1503842134.455339 
```

EXEC 形式运行得很好。正如我们所看到的，容器中的进程是我们预期的，我们的处理程序现在正确地接收到`SIGTERM`。

# SIGTERM 不会调用终止处理程序

在某些情况下，进程的终止处理程序不会被`SIGTERM`触发。例如，向 nginx 发送`SIGTERM`实际上会导致快速关闭。要优雅地关闭 nginx 控制器，我们必须使用`nginx -s quit`发送`SIGQUIT`。

nginx 信号上支持的所有操作的完整列表在这里列出：[`nginx.org/en/docs/control.html`](http://nginx.org/en/docs/control.html)。

现在又出现了另一个问题——在删除 pod 时，我们如何向容器发送除`SIGTERM`之外的信号？我们可以修改程序的行为来捕获 SIGTERM，但对于像 nginx 这样的流行工具，我们无能为力。对于这种情况，生命周期钩子能够解决问题。

# 容器生命周期钩子

生命周期钩子是针对容器执行的事件感知操作。它们的工作方式类似于单个 Kubernetes 探测操作，但它们只会在容器的生命周期内的每个事件中至少触发一次。目前，支持两个事件：

+   `PostStart`：在容器创建后立即执行。由于此钩子和容器的入口点是异步触发的，因此不能保证在容器启动之前执行该钩子。因此，我们不太可能使用它来初始化容器的资源。

+   `PreStop`：在向容器发送`SIGTERM`之前立即执行。与`PostStart`钩子的一个区别是，`PreStop`钩子是同步调用，换句话说，只有在`PreStop`钩子退出后才会发送`SIGTERM`。

因此，我们的 nginx 关闭问题可以通过`PreStop`钩子轻松解决：

```
...
 containers:
 - name: main
 image: nginx
 lifecycle:
 preStop:
 exec:
 command: [ "nginx", "-s", "quit" ]
... 
```

此外，钩子的一个重要属性是它们可以以某种方式影响 pod 的状态：除非其`PostStart`钩子成功退出，否则 pod 不会运行；在删除时，pod 立即设置为终止，但除非`PreStop`钩子成功退出，否则不会发送`SIGTERM`。因此，对于我们之前提到的情况，容器在删除之前退出，我们可以通过`PreStop`钩子来解决。以下图示了如何使用钩子来消除不需要的间隙：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00115.jpeg)

实现只是添加一个休眠几秒钟的钩子：

```
...
 containers:
 - name: main
 image: my-app
 lifecycle:
 preStop:
 exec:
 command: [ "/bin/sh", "-c", "sleep 5" ]
...
```

# 放置 pod

大多数情况下，我们并不真的关心我们的 pod 运行在哪个节点上，因为调度 pod 是 Kubernetes 的一个基本特性。然而，当调度 pod 时，Kubernetes 并不知道节点的地理位置、可用区域或机器类型等因素。此外，有时我们希望在一个隔离的实例组中部署运行测试构建的 pod。因此，为了完成调度，Kubernetes 提供了不同级别的亲和性，允许我们积极地将 pod 分配给特定的节点。

pod 的节点选择器是手动放置 pod 的最简单方式。它类似于服务的 pod 选择器。pod 只会放置在具有匹配标签的节点上。该字段设置在`.spec.nodeSelector`中。例如，以下 pod `spec`的片段将 pod 调度到具有标签`purpose=sandbox,disk=ssd`的节点上。

```
...
 spec:
 containers:
 - name: main
 image: my-app
 nodeSelector:
 purpose: sandbox
 disk: ssd
...
```

检查节点上的标签与我们在 Kubernetes 中检查其他资源的方式相同：

```
$ kubectl describe node gke-my-cluster-ins-49e8f52a-lz4l
Name:       gke-my-cluster-ins-49e8f52a-lz4l
Role:
Labels:   beta.kubernetes.io/arch=amd64
 beta.kubernetes.io/fluentd-ds-ready=true
 beta.kubernetes.io/instance-type=g1-small
 beta.kubernetes.io/os=linux
 cloud.google.com/gke-nodepool=ins
 failure-domain.beta.kubernetes.io/region=us-  
          central1
 failure-domain.beta.kubernetes.io/zone=us-
          central1-b
 kubernetes.io/hostname=gke-my-cluster-ins- 
          49e8f52a-lz4l
... 
```

正如我们所看到的，我们的节点上已经有了标签。这些标签是默认设置的，默认标签如下：

+   `kubernetes.io/hostname`

+   `failure-domain.beta.kubernetes.io/zone`

+   `failure-domain.beta.kubernetes.io/region`

+   `beta.kubernetes.io/instance-type`

+   `beta.kubernetes.io/os`

+   `beta.kubernetes.io/arch`

如果我们想要标记一个节点以使我们的示例 pod 被调度，我们可以更新节点的清单，或者使用快捷命令`kubectl label`：

```
$ kubectl label node gke-my-cluster-ins-49e8f52a-lz4l \
 purpose=sandbox disk=ssd
node "gke-my-cluster-ins-49e8f52a-lz4l" labeled
$ kubectl get node --selector purpose=sandbox,disk=ssd
NAME                               STATUS    AGE       VERSION
gke-my-cluster-ins-49e8f52a-lz4l   Ready     5d        v1.7.3
```

除了将 pod 放置到节点上，节点也可以拒绝 pod，即*污点和容忍*，我们将在下一章学习它。

# 摘要

在本章中，我们不仅讨论了构建持续交付流水线的话题，还讨论了加强每个部署任务的技术。pod 的滚动更新是一个强大的工具，可以以受控的方式进行更新。要触发滚动更新，我们需要更新 pod 的规范。虽然更新由 Kubernetes 管理，但我们仍然可以使用`kubectl rollout`来控制它。

随后，我们通过`GitHub/DockerHub/Travis-CI`创建了一个可扩展的持续交付流水线。接下来，我们将学习更多关于 pod 的生命周期，以防止任何可能的故障，包括使用就绪和存活探针来保护 pod，使用 Init 容器初始化 pod，通过以 exec 形式编写`Dockerfile`来正确处理`SIGTERM`，利用生命周期钩子来延迟 pod 的就绪以及终止，以便在正确的时间删除 iptables 规则，并使用节点选择器将 pod 分配给特定的节点。

在下一章中，我们将学习如何在 Kubernetes 中使用逻辑边界来分割我们的集群，以更稳定和安全地共享资源。
