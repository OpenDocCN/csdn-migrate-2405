# Docker 学习手册第二版（五）

> 原文：[`zh.annas-archive.org/md5/4FF7CBA6C5E093012874A6BAC2B803F8`](https://zh.annas-archive.org/md5/4FF7CBA6C5E093012874A6BAC2B803F8)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十四章：零停机部署和 Secrets

在上一章中，我们详细探讨了 Docker Swarm 及其资源。我们学习了如何在本地和云中构建高可用的 swarm。然后，我们深入讨论了 Swarm 服务和堆栈。最后，我们在 swarm 中创建了服务和堆栈。

在本章中，我们将向您展示如何在 Docker Swarm 中更新服务和堆栈而不中断其可用性。这被称为零停机部署。我们还将介绍 swarm secrets 作为一种安全地向服务的容器提供敏感信息的手段。

在本章中，我们将涵盖以下主题：

+   零停机部署

+   在 swarm 中存储配置数据

+   使用 Docker Secrets 保护敏感数据

完成本章后，您将能够做到以下事情：

+   列举两到三种常用的部署策略，用于在不中断的情况下更新服务。

+   批量更新服务而不会造成服务中断。

+   为服务定义回滚策略，如果更新失败则使用。

+   使用 Docker 配置存储非敏感配置数据。

+   使用 Docker secret 与服务。

+   更新 secret 的值而不会造成停机时间。

# 技术要求

本章的代码文件可以在 GitHub 上找到[`github.com/PacktPublishing/Learn-Docker---Fundamentals-of-Docker-19.x-Second-Edition`](https://github.com/PacktPublishing/Learn-Docker---Fundamentals-of-Docker-19.x-Second-Edition)。如果您已经按照第二章中指示的*设置工作环境*检出了存储库，那么您可以在`~/fod-solution/ch14`找到代码。

# 零停机部署

需要频繁更新的关键应用程序最重要的一个方面是能够以完全无中断的方式进行更新。我们称之为零停机部署。更新后的应用程序必须始终完全可操作。

# 流行的部署策略

有各种方法可以实现这一点。其中一些如下：

+   滚动更新

+   蓝绿部署

+   金丝雀发布

Docker Swarm 支持开箱即用的滚动更新。其他两种部署类型需要我们额外的努力才能实现。

# 滚动更新

在关键任务应用中，每个应用服务必须以多个副本运行。根据负载的大小，副本可以少至两到三个实例，多至数十、数百或数千个实例。在任何给定时间，我们希望所有服务实例的运行都有明确的多数。因此，如果我们有三个副本，我们希望至少有两个副本一直在运行。如果我们有 100 个副本，我们可以满足于至少有 90 个副本可用。通过这样做，我们可以定义一个批量大小的副本，我们可以关闭以进行升级。在第一种情况下，批量大小将为 1，在第二种情况下，将为 10。

当我们关闭副本时，Docker Swarm 将自动将这些实例从负载均衡池中移除，所有流量将在剩余的活动实例之间进行负载均衡。因此，这些剩余实例将暂时经历流量的轻微增加。在下图中，在滚动更新开始之前，如果**Task A3**想要访问**Service B**，它可能已经被 SwarmKit 负载均衡到**Service B**的任何三个任务中的一个。一旦滚动更新开始，SwarmKit 将关闭**Task B1**进行更新。自动地，这个任务就被从目标池中移除。因此，如果**Task A3**现在请求连接到**Service B**，负载均衡将只从剩余的任务中选择，即**B2**和**B3**。因此，这两个任务可能暂时经历更高的负载：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/b5692dbe-f8b2-4050-bc4b-04147a063825.png)

**Task B1**被关闭以进行更新

然后停止实例，用新版本的应用服务的等效数量的新实例替换它们。一旦新实例正常运行，我们可以让 Swarm 在一定时间内观察它们，确保它们健康。如果一切正常，那么我们可以继续关闭下一批实例，并用新版本的实例替换它们。这个过程重复进行，直到所有应用服务的实例都被替换。

在下图中，我们可以看到**Service B**的**Task B1**已更新为版本 2。**Task B1**的容器被分配了一个新的**IP**地址，并部署到另一个具有空闲资源的工作节点上：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/2e0094c4-5dce-4763-8401-394a87cc79b3.png)

正在进行滚动更新的第一批

重要的是要理解，当服务的任务被更新时，在大多数情况下，它会被部署到与其原来所在的不同的工作节点上。但只要相应的服务是无状态的，这应该没问题。如果我们有一个有状态的服务，它是位置或节点感知的，并且我们想要对其进行更新，那么我们必须调整我们的方法，但这超出了本书的范围。

现在，让我们看看如何实际指示 Swarm 执行应用服务的滚动更新。当我们在堆栈文件中声明一个服务时，我们可以定义在这种情况下相关的多个选项。让我们看一个典型堆栈文件的片段：

```
version: "3.5"
services:
 web:
   image: nginx:alpine
   deploy:
     replicas: 10
     update_config:
       parallelism: 2
       delay: 10s
...
```

在这个片段中，我们可以看到一个名为`update_config`的部分，其中包含`parallelism`和`delay`属性。`parallelism`定义了在滚动更新期间一次要更新多少个副本的批处理大小。`delay`定义了 Docker Swarm 在更新单个批次之间要等待多长时间。在前面的例子中，我们有`10`个副本，每次更新两个实例，并且在每次成功更新之间，Docker Swarm 等待`10`秒。

让我们测试这样一个滚动更新。导航到我们`labs`文件夹的`ch14`子文件夹，并使用`stack.yaml`文件创建一个已配置为滚动更新的 web 服务。该服务使用基于 Alpine 的 Nginx 镜像，版本为`1.12-alpine`。我们将把服务更新到一个更新的版本，即`1.13-alpine`。

首先，我们将把这个服务部署到我们在 VirtualBox 中本地创建的 Swarm。让我们来看一下：

1.  首先，我们需要确保我们的终端窗口已配置，以便我们可以访问我们集群的主节点之一。让我们选择领导者，即`node-1`：

```
$ eval $(docker-machine env node-1)
```

1.  现在，我们可以使用堆栈文件部署服务：

```
$ docker stack deploy -c stack.yaml web
```

上述命令的输出如下：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/1f326e7f-883f-4cc7-b643-3844164cc739.png)部署 web 堆栈

1.  服务部署后，我们可以使用以下命令对其进行监视：

```
$ watch docker stack ps web
```

我们将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/909a831e-a9a3-4ae8-98b1-addeb1ac75a7.png)运行在 Swarm 中的 web 堆栈的 web 服务，有 10 个副本。如果您在 macOS 机器上工作，您需要确保您安装了 watch 工具。使用`brew install watch`命令来安装。

上述命令将持续更新输出，并为我们提供滚动更新期间发生的情况的良好概述。

现在，我们需要打开第二个终端，并为我们的 Swarm 的管理节点配置远程访问。一旦我们完成了这一步，我们可以执行`docker`命令，它将更新堆栈的`web`服务的镜像，也称为`web`：

```
$ docker service update --image nginx:1.13-alpine web_web
```

上述命令导致以下输出，指示滚动更新的进度：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/80e17241-6cbe-414b-b393-b874ba9f475a.png)显示滚动更新进度的屏幕

上述输出表明，前两批每批两个任务已成功，并且第三批正在准备中。

在观看堆栈的第一个终端窗口中，我们现在应该看到 Docker Swarm 如何以`10 秒`的间隔逐批更新服务。第一批之后，它应该看起来像以下截图：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/0c203143-48d9-4eb6-8207-bf098224f2d8.png)Docker Swarm 中服务的滚动更新

在上述截图中，我们可以看到前两个任务`8`和`9`已经更新。Docker Swarm 正在等待`10 秒`后继续下一批。

有趣的是，在这种特殊情况下，SwarmKit 将任务的新版本部署到与先前版本相同的节点。这是偶然的，因为我们有五个节点，每个节点上有两个任务。SwarmKit 始终尝试在节点之间均匀平衡工作负载。因此，当 SwarmKit 关闭一个任务时，相应的节点的工作负载小于所有其他节点，因此新实例被调度到该节点。通常情况下，您不能期望在同一节点上找到任务的新实例。只需尝试通过删除具有`docker stack rm web`并将副本数更改为例如七个，然后重新部署和更新来自己尝试。

一旦所有任务都已更新，我们的`docker stack ps web`命令的输出将类似于以下截图：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/4def2ed1-1be6-4416-9e98-041b0ec8d8d6.png)所有任务已成功更新

请注意，SwarmKit 不会立即从相应节点中删除任务的先前版本的容器。这是有道理的，因为我们可能希望，例如，检索这些容器的日志以进行调试，或者我们可能希望使用`docker container inspect`检索它们的元数据。SwarmKit 在清除旧实例之前会保留最近的四个终止任务实例，以防止它用未使用的资源堵塞系统。

我们可以使用`--update-order`参数指示 Docker 在停止旧容器之前启动新的容器副本。这可以提高应用程序的可用性。有效值为`"start-first"`和`"stop-first"`。后者是默认值。

完成后，我们可以使用以下命令拆除堆栈：

```
$ docker stack rm web
```

虽然使用堆栈文件来定义和部署应用程序是推荐的最佳实践，但我们也可以在服务`create`语句中定义更新行为。如果我们只想部署单个服务，这可能是做事情的首选方式。让我们看看这样一个`create`命令：

```
$ docker service create --name web \
 --replicas 10 \
 --update-parallelism 2 \
 --update-delay 10s \
 nginx:alpine
```

这个命令定义了与前面的堆栈文件相同的期望状态。我们希望服务以`10`个副本运行，并且我们希望滚动更新以每次两个任务的批次进行，并且在连续批次之间间隔 10 秒。

# 健康检查

为了做出明智的决定，例如在滚动更新 Swarm 服务期间，关于刚安装的新服务实例批次是否正常运行，或者是否需要回滚，SwarmKit 需要一种了解系统整体健康状况的方式。SwarmKit（和 Docker）本身可以收集相当多的信息。但是有限制。想象一个包含应用程序的容器。从外部看，容器可能看起来绝对健康，可以正常运行。但这并不一定意味着容器内部运行的应用程序也很好。例如，应用程序可能陷入无限循环或处于损坏状态，但仍在运行。但只要应用程序运行，容器就运行，并且从外部看，一切都看起来完美。

因此，SwarmKit 提供了一个接口，我们可以在其中提供一些帮助。我们，即运行在集群容器内部的应用程序服务的作者，最了解我们的服务是否处于健康状态。SwarmKit 给了我们定义一个命令的机会，该命令针对我们的应用程序服务进行健康测试。这个命令具体做什么对 Swarm 来说并不重要；命令只需要返回`OK`、`NOT OK`或`超时`。后两种情况，即`NOT OK`或`超时`，将告诉 SwarmKit 正在调查的任务可能不健康。

在这里，我故意写了一些东西，稍后我们会看到原因：

```
FROM alpine:3.6
...
HEALTHCHECK --interval=30s \
    --timeout=10s
    --retries=3
    --start-period=60s
    CMD curl -f http://localhost:3000/health || exit 1
...
```

在来自 Dockerfile 的前面的片段中，我们可以看到关键字 HEALTHCHECK。它有一些选项或参数和一个实际的命令，即 CMD。让我们讨论一下选项：

+   --interval：定义健康检查之间的等待时间。因此，在我们的情况下，编排器每 30 秒执行一次检查。

+   --timeout：此参数定义 Docker 在健康检查不响应时应等待多长时间，直到超时出现错误。在我们的示例中，这是 10 秒。现在，如果一个健康检查失败，SwarmKit 会重试几次，直到放弃并声明相应的任务不健康，并打开 Docker 杀死该任务并用新实例替换的机会。

+   重试次数由--retries 参数定义。在前面的代码中，我们希望有三次重试。

+   接下来，我们有启动周期。有些容器需要一些时间来启动（虽然这不是一种推荐的模式，但有时是不可避免的）。在这个启动时间内，服务实例可能无法响应健康检查。有了启动周期，我们可以定义 SwarmKit 在执行第一次健康检查之前等待多长时间，从而给应用程序初始化的时间。为了定义启动时间，我们使用--start-period 参数。在我们的情况下，我们在 60 秒后进行第一次检查。启动时间需要多长取决于应用程序及其启动行为。建议是从相对较低的值开始，如果有很多错误的阳性和任务被多次重启，可能需要增加时间间隔。

+   最后，我们在最后一行用 CMD 关键字定义了实际的探测命令。在我们的情况下，我们正在定义对端口 3000 的 localhost 的/health 端点的请求作为探测命令。这个调用有三种可能的结果：

+   命令成功。

+   命令失败。

+   命令超时。

SwarmKit 将后两者视为相同。这是编排器告诉我们相应的任务可能不健康。我故意说*可能*，因为 SwarmKit 并不立即假设最坏的情况，而是假设这可能只是任务的暂时故障，并且它将从中恢复。这就是为什么我们有一个`--retries`参数的原因。在那里，我们可以定义 SwarmKit 在可以假定任务确实不健康之前应重试多少次，因此杀死它并在另一个空闲节点上重新安排此任务的另一个实例以调和服务的期望状态。

*为什么我们可以在我们的探测命令中使用 localhost？*这是一个非常好的问题，原因是因为当 SwarmKit 在 Swarm 中运行的容器进行探测时，它在容器内执行这个`探测`命令（也就是说，它做了类似`docker container exec <containerID> <probing command>`的事情）。因此，该命令在与容器内运行的应用程序相同的网络命名空间中执行。在下图中，我们可以看到服务任务的生命周期：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/04607fa9-4a95-4188-9437-5db991b5d3b1.png)

具有瞬态健康失败的服务任务

首先，SwarmKit 等待到启动期结束才进行探测。然后，我们进行第一次健康检查。不久之后，任务在探测时失败。它连续失败两次，但然后恢复。因此，**健康检查 4**成功了，SwarmKit 让任务继续运行。

在这里，我们可以看到一个永久失败的任务：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/69eb3697-f61f-446c-b5cc-3c5d36bbe6d0.png)

任务的永久失败

我们刚刚学习了如何在服务的镜像的`Dockerfile`中定义健康检查。但这并不是我们可以做到这一点的唯一方式。我们还可以在用于将我们的应用程序部署到 Docker Swarm 中的堆栈文件中定义健康检查。以下是这样一个堆栈文件的简短片段：

```
version: "3.5"
services:
  web:
    image: example/web:1.0
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 60s
...
```

在上述片段中，我们可以看到健康检查相关信息是如何在堆栈文件中定义的。首先，首先要意识到的是，我们必须为每个服务单独定义健康检查。没有应用程序或全局级别的健康检查。

与我们之前在 `Dockerfile` 中定义的类似，SwarmKit 用于执行健康检查的命令是 `curl -f http://localhost:3000/health`。我们还定义了 `interval`、`timeout`、`retries` 和 `start_period`。这四个键值对的含义与我们在 `Dockerfile` 中使用的相应参数相同。如果镜像中定义了与健康检查相关的设置，那么堆栈文件中定义的设置将覆盖 `Dockerfile` 中的设置。

现在，让我们尝试使用一个定义了健康检查的服务。在我们的 `lab` 文件夹中，有一个名为 `stack-health.yaml` 的文件，内容如下：

```
version: "3.5"
services:
  web:
    image: nginx:alpine
    healthcheck:
      test: ["CMD", "wget", "-qO", "-", "http://localhost"]
      interval: 5s
      timeout: 2s
      retries: 3
      start_period: 15s
```

让我们部署这个：

```
$ docker stack deploy -c stack-health.yaml myapp
```

我们可以使用 `docker stack ps myapp` 命令找出单个任务部署到了哪里。在特定的节点上，我们可以列出所有容器，找到我们的其中一个堆栈。在我的例子中，任务已经部署到了 `node-3`：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/b39744ac-ae71-456f-b8d1-3b34c99837e2.png)显示运行任务实例的健康状态

这张截图中有趣的地方是 `STATUS` 列。Docker，或者更准确地说，SwarmKit，已经识别出服务有一个健康检查函数定义，并且正在使用它来确定服务的每个任务的健康状况。

# 回滚

有时，事情并不如预期。应用发布的最后一分钟修复可能无意中引入了一个新的 bug，或者新版本显著降低了组件的吞吐量，等等。在这种情况下，我们需要有一个备用计划，这在大多数情况下意味着能够将更新回滚到之前的良好版本。

与更新一样，回滚必须以不会导致应用中断的方式进行。它需要零停机时间。从这个意义上讲，回滚可以被看作是一个反向更新。我们正在安装一个新版本，但这个新版本实际上是之前的版本。

与更新行为一样，我们可以在堆栈文件或 Docker 服务 `create` 命令中声明系统在需要执行回滚时应该如何行为。在这里，我们有之前使用的堆栈文件，但这次有一些与回滚相关的属性：

```
version: "3.5"
services:
  web:
    image: nginx:1.12-alpine
    ports:
      - 80:80
    deploy:
      replicas: 10
      update_config:
        parallelism: 2
        delay: 10s

        failure_action: rollback
        monitor: 10s

    healthcheck:
      test: ["CMD", "wget", "-qO", "-", "http://localhost"]
      interval: 2s
      timeout: 2s
      retries: 3
      start_period: 2s
```

在这个堆栈文件中，我们定义了关于滚动更新、健康检查和回滚期间行为的详细信息。健康检查被定义为，在初始等待时间为`2`秒后，编排器开始每`2`秒在`http://localhost`上轮询服务，并在考虑任务不健康之前重试`3`次。

如果我们做数学计算，那么如果由于错误而导致任务不健康，那么至少需要 8 秒才能停止任务。因此，现在在部署下，我们有一个名为`monitor`的新条目。该条目定义了新部署的任务应该被监视多长时间以确保其健康，并且是否继续进行滚动更新的下一批任务。在这个示例中，我们给了它`10`秒。这比我们计算出的 8 秒稍微长一些，可以发现已部署的有缺陷的服务，所以这很好。

我们还有一个新条目，`failure_action`，它定义了在滚动更新过程中遇到失败时编排器将采取的行动，例如服务不健康。默认情况下，动作只是停止整个更新过程，并使系统处于中间状态。系统并没有宕机，因为它是一个滚动更新，至少一些健康的服务实例仍然在运行，但运维工程师最好能够查看并解决问题。

在我们的情况下，我们已经定义了动作为`rollback`。因此，在失败的情况下，SwarmKit 将自动将所有已更新的任务回滚到它们的先前版本。

# 蓝绿部署

在第九章中，*分布式应用架构*，我们以抽象的方式讨论了蓝绿部署是什么。事实证明，在 Docker Swarm 上，我们不能真正为任意服务实现蓝绿部署。在 Docker Swarm 中运行的两个服务之间的服务发现和负载均衡是 Swarm 路由网格的一部分，不能（轻松地）定制。

如果**Service A**想要调用**Service B**，那么 Docker 会隐式地执行这个操作。给定目标服务的名称，Docker 将使用 Docker **DNS**服务将此名称解析为**虚拟 IP**（**VIP**）地址。然后，当请求针对**VIP**时，Linux **IPVS**服务将在 Linux 内核 IP 表中使用**VIP**进行另一个查找，并将请求负载均衡到**VIP**所代表的服务的任务的物理 IP 地址之一，如下图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/f7103312-f96e-4301-8f61-6a75c5c74a43.png)

Docker Swarm 中的服务发现和负载均衡是如何工作的

不幸的是，目前还没有简单的方法来拦截这种机制并用自定义行为替换它。但这是需要的，以便允许对我们示例中的目标服务**Service B**进行真正的蓝绿部署。正如我们将在第十六章中看到的那样，*使用 Kubernetes 部署、更新和保护应用程序*，Kubernetes 在这个领域更加灵活。

也就是说，我们总是可以以蓝绿方式部署面向公众的服务。我们可以使用 interlock 2 及其第 7 层路由机制来实现真正的蓝绿部署。

# 金丝雀发布

从技术上讲，滚动更新是金丝雀发布的一种形式。但由于它们缺乏接口，无法将自定义逻辑插入系统中，滚动更新只是金丝雀发布的一个非常有限的版本。

真正的金丝雀发布要求我们对更新过程有更精细的控制。此外，真正的金丝雀发布在将 100%的流量引导到新版本之前不会关闭旧版本的服务。在这方面，它们被视为蓝绿部署。

在金丝雀发布的情况下，我们不仅希望使用诸如健康检查之类的因素来决定是否将更多的流量引导到新版本的服务中；我们还希望考虑决策过程中的外部输入，例如由日志聚合器收集和聚合的指标或跟踪信息。可以作为决策者的一个示例是符合**服务级别协议**（**SLA**），即如果服务的新版本显示出超出容忍范围的响应时间。如果我们向现有服务添加新功能，但这些新功能降低了响应时间，就会发生这种情况。

# 在 swarm 中存储配置数据

如果我们想在 Docker Swarm 中存储诸如配置文件之类的非敏感数据，那么我们可以使用 Docker 配置。Docker 配置与 Docker 秘密非常相似，我们将在下一节中讨论。主要区别在于配置值在静止状态下没有加密，而秘密有。Docker 配置只能在 Docker Swarm 中使用，也就是说，它们不能在非 Swarm 开发环境中使用。Docker 配置直接挂载到容器的文件系统中。配置值可以是字符串，也可以是二进制值，最大大小为 500 KB。

通过使用 Docker 配置，您可以将配置与 Docker 镜像和容器分离。这样，您的服务可以轻松地使用特定于环境的值进行配置。生产 swarm 环境的配置值与分期 swarm 的配置值不同，而后者又与开发或集成环境的配置值不同。

我们可以向服务添加配置，也可以从运行中的服务中删除配置。配置甚至可以在 swarm 中运行的不同服务之间共享。

现在，让我们创建一些 Docker 配置：

1.  首先，我们从一个简单的字符串值开始：

```
$ echo "Hello world" | docker config create hello-config - rrin36epd63pu6w3gqcmlpbz0
```

上面的命令创建了`Hello world`配置值，并将其用作名为`hello-config`的配置的输入。此命令的输出是存储在 swarm 中的这个新配置的唯一`ID`。

1.  让我们看看我们得到了什么，并使用列表命令来这样做：

```
$ docker config ls ID                         NAME           CREATED              UPDATED
rrin36epd63pu6w3gqcmlpbz0  hello-config   About a minute ago   About a minute ago
```

列表命令的输出显示了我们刚刚创建的配置的`ID`和`NAME`，以及其`CREATED`和（最后）更新时间。但由于配置是非机密的，我们可以做更多的事情，甚至输出配置的内容，就像这样：

```
$ docker config docker config inspect hello-config
[
    {
        "ID": "rrin36epd63pu6w3gqcmlpbz0",
        "Version": {
            "Index": 11
        },
        "CreatedAt": "2019-11-30T07:59:20.6340015Z",
        "UpdatedAt": "2019-11-30T07:59:20.6340015Z",
        "Spec": {
            "Name": "hello-config",
            "Labels": {},
            "Data": "SGVsbG8gd29ybGQK"
        }
    }
]
```

嗯，有趣。在前面的 JSON 格式输出的`Spec`子节点中，我们有一个`Data`键，其值为`SGVsbG8gd29ybGQK`。我们不是刚说过配置数据在静止状态下没有加密吗？原来这个值只是我们的字符串编码为`base64`，我们可以很容易地验证：

```
$ echo 'SGVsbG8gd29ybGQK' | base64 -d
Hello world
```

到目前为止，一切都很好。

现在，让我们定义一个稍微复杂一些的 Docker 配置。假设我们正在开发一个 Java 应用程序。Java 传递配置数据给应用程序的首选方式是使用所谓的“属性”文件。`属性`文件只是一个包含键值对列表的文本文件。让我们来看一下：

1.  让我们创建一个名为`my-app.properties`的文件，并将以下内容添加到其中：

```
username=pguser
database=products
port=5432
dbhost=postgres.acme.com
```

1.  保存文件并从中创建一个名为`app.properties`的 Docker 配置：

```
$ docker config create app.properties ./my-app.properties
2yzl73cg4cwny95hyft7fj80u
```

现在，我们可以使用这个（有些牵强的）命令来获取我们刚刚创建的配置的明文值：

```
$ docker config inspect app.properties | jq .[].Spec.Data | xargs echo | base64 -d username=pguser
database=products
port=5432
dbhost=postgres.acme.com
```

这正是我们预期的。

1.  现在，让我们创建一个使用前述配置的 Docker 服务。为简单起见，我们将使用 nginx 镜像来实现：

```
$ docker service create \
 --name nginx \
 --config source=app.properties,target=/etc/my-app/conf/app.properties,mode=0440 \
 nginx:1.13-alpine

p3f686vinibdhlnrllnspqpr0
overall progress: 1 out of 1 tasks
1/1: running [==================================================>]
verify: Service converged
```

在前面的服务`create`命令中有趣的部分是包含`--config`的那一行。通过这一行，我们告诉 Docker 使用名为`app.properties`的配置，并将其挂载为一个文件到容器内的`/etc/my-app/conf/app.properties`。此外，我们希望该文件具有`0440`的模式。

让我们看看我们得到了什么：

```
$ docker service ps nginx
ID            NAME     IMAGE              NODE DESIRED    STATE    CURRENT STATE ...
b8lzzwl3eg6y  nginx.1  nginx:1.13-alpine  node-1  Running  Running 2 minutes ago
```

在前面的输出中，我们可以看到服务的唯一实例正在节点`node-1`上运行。在这个节点上，我现在可以列出容器以获取 nginx 实例的`ID`：

```
$ docker container ls
CONTAINER ID   IMAGE               COMMAND                  CREATED         STATUS         PORTS ...
bde33d92cca7   nginx:1.13-alpine   "nginx -g 'daemon of…"   5 minutes ago   Up 5 minutes   80/tcp ...
```

最后，我们可以`exec`进入该容器并输出`/etc/my-app/conf/app.properties`文件的值：

```
$ docker exec bde33 cat /etc/my-app/conf/app.properties
username=pguser
database=products
port=5432
dbhost=postgres.acme.com
```

毫无意外；这正是我们预期的。

当然，Docker 配置也可以从集群中移除，但前提是它们没有被使用。如果我们尝试移除之前使用过的配置，而没有先停止和移除服务，我们会得到以下输出：

```
$ docker config rm app.properties
Error response from daemon: rpc error: code = InvalidArgument desc = config 'app.properties' is in use by the following service: nginx
```

我们收到了一个错误消息，其中 Docker 友好地告诉我们该配置正在被我们称为`nginx`的服务使用。这种行为与我们在使用 Docker 卷时所习惯的有些相似。

因此，首先我们需要移除服务，然后我们可以移除配置：

```
$ docker service rm nginx
nginx
$ docker config rm app.properties
app.properties
```

需要再次注意的是，Docker 配置绝不应该用于存储诸如密码、秘钥或访问密钥等机密数据。在下一节中，我们将讨论如何处理机密数据。

# 使用 Docker secrets 保护敏感数据

秘密用于以安全的方式处理机密数据。Swarm 秘密在静态和传输中是安全的。也就是说，当在管理节点上创建新的秘密时，它只能在管理节点上创建，其值会被加密并存储在 raft 一致性存储中。这就是为什么它在静态时是安全的。如果一个服务被分配了一个秘密，那么管理节点会从存储中读取秘密，解密它，并将其转发给请求秘密的 swarm 服务的所有容器实例。由于 Docker Swarm 中的节点之间通信使用了**传输层安全**（**TLS**），即使解密了，秘密值在传输中仍然是安全的。管理节点只将秘密转发给服务实例正在运行的工作节点。然后，秘密被挂载为文件到目标容器中。每个秘密对应一个文件。秘密的名称将成为容器内文件的名称，秘密的值将成为相应文件的内容。秘密永远不会存储在工作节点的文件系统上，而是使用`tmpFS`挂载到容器中。默认情况下，秘密被挂载到容器的`/run/secrets`目录中，但您可以将其更改为任何自定义文件夹。

需要注意的是，在 Windows 节点上，秘密不会被加密，因为没有类似于`tmpfs`的概念。为了达到在 Linux 节点上获得的相同安全级别，管理员应该加密相应 Windows 节点的磁盘。

# 创建秘密

首先，让我们看看我们实际上如何创建一个秘密：

```
$ echo "sample secret value" | docker secret create sample-secret - 
```

这个命令创建了一个名为`sample-secret`的秘密，其值为`sample secret value`。请注意`docker secret create`命令末尾的连字符。这意味着 Docker 期望从标准输入获取秘密的值。这正是我们通过将`sample secret value`值传输到`create`命令中所做的。

或者，我们可以使用文件作为秘密值的来源：

```
$ docker secret create other-secret ~/my-secrets/secret-value.txt
```

在这里，具有名称`other-secret`的秘密的值是从名为`~/my-secrets/secret-value.txt`的文件中读取的。一旦创建了一个秘密，就没有办法访问它的值。例如，我们可以列出所有的秘密来获取以下输出：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/2b31dcdd-9f1d-44eb-ac20-1d8263bf8f1c.png)所有秘密的列表

在这个列表中，我们只能看到秘密的`ID`和`名称`，以及一些其他元数据，但秘密的实际值是不可见的。我们也可以对秘密使用`inspect`，例如，获取有关`other-secret`的更多信息：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/82cad794-8a35-44db-81d7-51a9bbd67b29.png)检查集群秘密

即使在这里，我们也无法获取秘密的值。当然，这是有意的：秘密是秘密，因此需要保密。如果我们愿意，我们可以为秘密分配标签，甚至可以使用不同的驱动程序来加密和解密秘密，如果我们对 Docker 默认提供的不满意的话。

# 使用秘密

秘密被用于在集群中运行的服务。通常，秘密在创建服务时分配。因此，如果我们想要运行一个名为`web`的服务并分配一个名为`api-secret-key`的秘密，语法如下：

```
$ docker service create --name web \
 --secret api-secret-key \
 --publish 8000:8000 \
 fundamentalsofdocker/whoami:latest
```

该命令基于`fundamentalsofdocker/whoami:latest`镜像创建了一个名为`web`的服务，将容器端口`8000`发布到所有集群节点的端口`8000`，并分配了名为`api-secret-key`的秘密。

只有在集群中定义了名为`api-secret-key`的秘密时，这才有效；否则，将生成一个带有文本`secret not found: api-secret-key`的错误。因此，让我们现在创建这个秘密：

```
$ echo "my secret key" | docker secret create api-secret-key -
```

现在，如果我们重新运行服务`create`命令，它将成功：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/4dd798d2-4a33-41b6-ae25-39f71d55386e.png)使用秘密创建服务

现在，我们可以使用`docker service ps web`来找出唯一服务实例部署在哪个节点上，然后`exec`进入这个容器。在我的情况下，该实例已部署到`node-3`，所以我需要`SSH`进入该节点：

```
$ docker-machine ssh node-3
```

然后，我列出该节点上的所有容器，找到属于我的服务的一个实例并复制其`容器 ID`。然后，我们可以运行以下命令，确保秘密确实在容器内以明文形式的预期文件名中可用：

```
$ docker exec -it <container ID> cat /run/secrets/api-secret-key
```

再次强调，在我的情况下，这看起来是这样的：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/397cb02b-4760-4f21-9a10-0364294c20b9.png)容器看到的秘密

如果由于某种原因，Docker 在容器内部挂载秘密的默认位置不可接受，您可以定义一个自定义位置。在下面的命令中，我们将秘密挂载到`/app/my-secrets`：

```
$ docker service create --name web \
 --name web \
 -p 8000:8000 \
 --secret source=api-secret-key,target=/run/my-secrets/api-secret-key \
 fundamentalsofdocker/whoami:latest
```

在这个命令中，我们使用了扩展语法来定义一个包括目标文件夹的秘密。

# 在开发环境中模拟秘密

在开发中，我们通常在本地没有一个 swarm。但是秘密只在 swarm 中起作用。*我们能做什么呢*？幸运的是，这个答案非常简单。由于秘密被视为文件，我们可以轻松地将包含秘密的卷挂载到容器中的预期位置，这个位置默认为`/run/secrets`。

假设我们在本地工作站上有一个名为`./dev-secrets`的文件夹。对于每个秘密，我们都有一个与秘密名称相同且具有未加密值的文件作为文件内容。例如，我们可以通过在工作站上执行以下命令来模拟一个名为`demo-secret`的秘密，其秘密值为`demo secret value`：

```
$ echo "demo secret value" > ./dev-secrets/sample-secret
```

然后，我们可以创建一个容器，挂载这个文件夹，就像这样：

```
$ docker container run -d --name whoami \
 -p 8000:8000 \
 -v $(pwd)/dev-secrets:/run/secrets \
 fundamentalsofdocker/whoami:latest
```

容器内运行的进程将无法区分这些挂载的文件和来自秘密的文件。因此，例如，`demo-secret`在容器内作为名为`/run/secrets/demo-secret`的文件可用，并具有预期值`demo secret value`。让我们在以下步骤中更详细地看一下这个情况：

1.  为了测试这一点，我们可以在前面的容器中`exec`一个 shell：

```
$ docker container exec -it whoami /bin/bash
```

1.  现在，我们可以导航到`/run/secrets`文件夹，并显示`demo-secret`文件的内容：

```
/# cd /run/secrets
/# cat demo-secret
demo secret value
```

接下来，我们将研究秘密和遗留应用程序。

# 秘密和遗留应用程序

有时，我们希望将无法轻松或不想更改的遗留应用程序容器化。这个遗留应用程序可能希望将秘密值作为环境变量可用。*那么我们现在该怎么办呢？* Docker 将秘密呈现为文件，但应用程序期望它们以环境变量的形式存在。

在这种情况下，定义一个在容器启动时运行的脚本是有帮助的（称为入口点或启动脚本）。这个脚本将从相应的文件中读取秘密值，并定义一个与文件名相同的环境变量，将新变量赋予从文件中读取的值。对于一个名为`demo-secret`的秘密，其值应该在名为`DEMO_SECRET`的环境变量中可用，这个启动脚本中必要的代码片段可能如下所示：

```
export DEMO_SECRET=$(cat /run/secrets/demo-secret)
```

类似地，假设我们有一个旧应用程序，它期望将秘密值作为一个条目存在于位于`/app/bin`文件夹中的一个名为`app.config`的 YAML 配置文件中，其相关部分如下所示：

```
...
```

```

secrets:
  demo-secret: "<<demo-secret-value>>"
  other-secret: "<<other-secret-value>>"
  yet-another-secret: "<<yet-another-secret-value>>"
...
```

我们的初始化脚本现在需要从`secret`文件中读取秘密值，并用`secret`值替换配置文件中的相应占位符。对于`demo-secret`，这可能看起来像这样：

```
file=/app/bin/app.conf
demo_secret=$(cat /run/secret/demo-secret)
sed -i "s/<<demo-secret-value>>/$demo_secret/g" "$file"
```

在上面的片段中，我们使用`sed`工具来替换占位符为实际值。我们可以使用相同的技术来处理配置文件中的其他两个秘密。

我们将所有的初始化逻辑放入一个名为`entrypoint.sh`的文件中，使该文件可执行，并将其添加到容器文件系统的根目录。然后，在`Dockerfile`中将此文件定义为`ENTRYPOINT`，或者我们可以在`docker container run`命令中覆盖镜像的现有`ENTRYPOINT`。

让我们做一个示例。假设我们有一个旧应用程序运行在由`fundamentalsofdocker/whoami:latest`镜像定义的容器中，该应用程序期望在应用程序文件夹中的一个名为`whoami.conf`的文件中定义一个名为`db_password`的秘密。让我们看看这些步骤：

1.  我们可以在本地机器上定义一个名为`whoami.conf`的文件，其中包含以下内容：

```
database:
  name: demo
  db_password: "<<db_password_value>>"
others:
  val1=123
  val2="hello world"
```

这个片段的第 3 行是重要的部分。它定义了启动脚本必须放置秘密值的位置。

1.  让我们在本地文件夹中添加一个名为`entrypoint.sh`的文件，其中包含以下内容：

```
file=/app/whoami.conf
db_pwd=$(cat /run/secret/db-password)
sed -i "s/<<db_password_value>>/$db_pwd/g" "$file"

/app/http
```

上述脚本中的最后一行源自于原始`Dockerfile`中使用的启动命令。

1.  现在，将此文件的模式更改为可执行：

```
$ sudo chmod +x ./entrypoint.sh
```

现在，我们定义一个继承自`fundamentalsofdocker/whoami:latest`镜像的`Dockerfile`。

1.  在当前文件夹中添加一个名为`Dockerfile`的文件，其中包含以下内容：

```
FROM fundamentalsofdocker/whoami:latest
COPY ./whoami.conf /app/
COPY ./entrypoint.sh /
CMD ["/entrypoint.sh"]
```

1.  让我们从这个`Dockerfile`构建镜像：

```
$ docker image build -t secrets-demo:1.0 .
```

1.  构建完镜像后，我们可以从中运行一个服务。但在这之前，我们需要在 Swarm 中定义秘密：

```
$ echo "passw0rD123" | docker secret create demo-secret -
```

1.  现在，我们可以创建一个使用以下秘密的服务：

```
$ docker service create --name demo \
 --secret demo-secret \
 secrets-demo:1.0
```

# 更新秘密

有时，我们需要更新运行中的服务中的秘密，因为秘密可能会泄露给公众，或者被恶意人士，如黑客，窃取。在这种情况下，我们需要更改我们的机密数据，因为一旦它泄露给不受信任的实体，它就必须被视为不安全。

更新秘密，就像任何其他更新一样，必须以零停机的方式进行。Docker SwarmKit 在这方面支持我们。

首先，在 Swarm 中创建一个新的秘密。建议在这样做时使用版本控制策略。在我们的例子中，我们使用版本作为秘密名称的后缀。我们最初使用名为`db-password`的秘密，现在这个秘密的新版本被称为`db-password-v2`：

```
$ echo "newPassw0rD" | docker secret create db-password-v2 -
```

让我们假设使用该秘密的原始服务是这样创建的：

```
$ docker service create --name web \
 --publish 80:80
 --secret db-password
 nginx:alpine
```

容器内运行的应用程序能够访问`/run/secrets/db-password`处的秘密。现在，SwarmKit 不允许我们在运行中的服务中更新现有的秘密，因此我们必须删除现在过时的秘密版本，然后添加新的秘密。让我们从以下命令开始删除：

```
$ docker service update --secret-rm db-password web
```

现在，我们可以使用以下命令添加新的秘密：

```
$ docker service update \
 --secret-add source=db-password-v2,target=db-password \
 web
```

请注意`--secret-add`的扩展语法，其中包括`source`和`target`参数。

# 摘要

在本章中，我们学习了 SwarmKit 如何允许我们更新服务而不需要停机。我们还讨论了 SwarmKit 在零停机部署方面的当前限制。在本章的第二部分，我们介绍了秘密作为一种以高度安全的方式向服务提供机密数据的手段。

在下一章中，我们将介绍目前最流行的容器编排器 Kubernetes。我们将讨论用于在 Kubernetes 集群中定义和运行分布式、弹性、健壮和高可用应用程序的对象。此外，本章还将使我们熟悉 MiniKube，这是一个用于在本地部署 Kubernetes 应用程序的工具，并演示 Kubernetes 与 Docker for macOS 和 Docker for Windows 的集成。

# 问题

为了评估您对本章讨论的主题的理解，请回答以下问题：

1.  用简洁的语句向一个感兴趣的外行解释什么是零停机部署。

1.  SwarmKit 如何实现零停机部署？

1.  与传统的（非容器化）系统相反，为什么 Docker Swarm 中的回滚可以正常工作？用简短的句子解释一下。

1.  描述 Docker 秘密的两到三个特征。

1.  您需要推出`inventory`服务的新版本。您的命令是什么样的？以下是更多信息：

+   新镜像名为`acme/inventory:2.1`。

+   我们希望使用批量大小为两个任务的滚动更新策略。

+   我们希望系统在每个批次之后等待一分钟。

1.  您需要更新名为`inventory`的现有服务的密码，该密码通过 Docker secret 提供。新的秘密称为`MYSQL_PASSWORD_V2`。服务中的代码期望秘密被称为`MYSQL_PASSWORD`。更新命令是什么样子？（请注意，我们不希望更改服务的代码！）

# 更多阅读

以下是一些外部来源的链接：

+   对服务应用滚动更新，网址为[`dockr.ly/2HfGjlD`](https://dockr.ly/2HfGjlD)

+   使用 Docker secrets 管理敏感数据，网址为[`dockr.ly/2vUNbuH`](https://dockr.ly/2vUNbuH)

+   介绍 Docker secrets 管理，网址为[`dockr.ly/2k7zwzE`](https://dockr.ly/2k7zwzE)

+   从环境变量到 Docker secrets，网址为[`bit.ly/2GY3UUB`](https://bit.ly/2GY3UUB)


# 第四部分：Docker、Kubernetes 和云

在本节中，您将成功地在 Kubernetes 中部署、运行、监控和解决高度分布式的应用程序，无论是在本地还是在云中。

本节包括以下章节：

+   第十五章，Kubernetes 简介

+   第十六章，使用 Kubernetes 部署、更新和保护应用程序

+   第十七章，监控和解决在生产环境中运行的应用程序

+   第十八章，在云中运行容器化应用程序


# 第十五章：Kubernetes 简介

在上一章中，我们学习了 SwarmKit 如何使用滚动更新来实现零停机部署。我们还介绍了 Docker 配置文件，用于在集群中存储非敏感数据并用于配置应用程序服务，以及 Docker 秘密，用于与在 Docker Swarm 中运行的应用程序服务共享机密数据。

在本章中，我们将介绍 Kubernetes。Kubernetes 目前是容器编排领域的明显领导者。我们将从高层次概述 Kubernetes 集群的架构开始，然后讨论 Kubernetes 中用于定义和运行容器化应用程序的主要对象。

本章涵盖以下主题：

+   Kubernetes 架构

+   Kubernetes 主节点

+   集群节点

+   MiniKube 简介

+   Docker for Desktop 中的 Kubernetes 支持

+   Pod 简介

+   Kubernetes ReplicaSet

+   Kubernetes 部署

+   Kubernetes 服务

+   基于上下文的路由

+   比较 SwarmKit 和 Kubernetes

完成本章后，您将能够做到以下事项：

+   在餐巾纸上起草 Kubernetes 集群的高层架构

+   解释 Kubernetes pod 的三到四个主要特征

+   用两三句话描述 Kubernetes ReplicaSets 的作用

+   解释 Kubernetes 服务的两三个主要职责

+   在 Minikube 中创建一个 pod

+   配置 Docker for Desktop 以使用 Kubernetes 作为编排器

+   在 Docker for Desktop 中创建一个部署

+   创建一个 Kubernetes 服务，将应用程序服务在集群内（或外部）暴露出来

# 技术要求

本章的代码文件可以在 GitHub 上找到：[`github.com/PacktPublishing/Learn-Docker---Fundamentals-of-Docker-19.x-Second-Edition`](https://github.com/PacktPublishing/Learn-Docker---Fundamentals-of-Docker-19.x-Second-Edition)。或者，如果您在计算机上克隆了伴随本书的 GitHub 存储库，如第二章中所述，*设置工作环境*，那么您可以在`~/fod-solution/ch15`找到代码。

# Kubernetes 架构

Kubernetes 集群由一组服务器组成。这些服务器可以是虚拟机或物理服务器。后者也被称为**裸金属**。集群的每个成员可以扮演两种角色中的一种。它要么是 Kubernetes 主节点，要么是（工作）节点。前者用于管理集群，而后者将运行应用程序工作负载。我在工作节点中加了括号，因为在 Kubernetes 术语中，只有在谈论运行应用程序工作负载的服务器时才会谈论节点。但在 Docker 术语和 Swarm 中，相当于的是*工作节点*。我认为工作节点这个概念更好地描述了服务器的角色，而不仅仅是一个*节点*。

在一个集群中，你会有少量奇数个的主节点和所需数量的工作节点。小集群可能只有几个工作节点，而更现实的集群可能有数十甚至数百个工作节点。从技术上讲，集群可以拥有无限数量的工作节点；但实际上，当处理数千个节点时，你可能会在一些管理操作中遇到显著的减速。集群的所有成员都需要通过一个物理网络连接，即所谓的**底层网络**。

Kubernetes 为整个集群定义了一个扁平网络。Kubernetes 不会提供任何开箱即用的网络实现；相反，它依赖于第三方的插件。Kubernetes 只是定义了**容器网络接口**（CNI），并将实现留给其他人。CNI 非常简单。它基本上规定了集群中运行的每个 pod 必须能够在不经过任何**网络地址转换**（NAT）的情况下到达集群中运行的任何其他 pod。集群节点和 pod 之间也必须是如此，也就是说，直接在集群节点上运行的应用程序或守护程序必须能够到达集群中的每个 pod，反之亦然。

下图说明了 Kubernetes 集群的高级架构：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/8f31f291-f723-4876-8ff9-349f2c42d114.jpg)Kubernetes 的高级架构图

前面的图解释如下：

+   在顶部中间，我们有一组**etcd**节点。**etcd**是一个分布式键值存储，在 Kubernetes 集群中用于存储集群的所有状态。**etcd**节点的数量必须是奇数，根据 Raft 共识协议的规定，该协议规定了用于彼此协调的节点。当我们谈论**集群状态**时，我们不包括集群中运行的应用程序产生或消耗的数据；相反，我们谈论的是集群拓扑的所有信息，正在运行的服务，网络设置，使用的密钥等。也就是说，这个**etcd**集群对整个集群非常关键，因此，在生产环境或需要高可用性的任何环境中，我们永远不应该只运行单个**etcd**服务器。

+   然后，我们有一组 Kubernetes **master**节点，它们也形成一个**共识组**，类似于**etcd**节点。主节点的数量也必须是奇数。我们可以使用单个主节点运行集群，但在生产或关键系统中绝不能这样做。在那里，我们应该始终至少有三个主节点。由于主节点用于管理整个集群，我们也在谈论管理平面。主节点使用**etcd**集群作为其后备存储。在主节点前面放置一个**负载均衡器**（**LB**）是一个良好的做法，具有一个众所周知的**完全合格的域名**（**FQDN**），例如`https://admin.example.com`。用于管理 Kubernetes 集群的所有工具都应该通过这个 LB 访问，而不是使用其中一个主节点的公共 IP 地址。这在上图的左上方显示。

+   图表底部，我们有一组**worker**节点。节点数量可以低至一个，没有上限。Kubernetes 的主节点和工作节点之间进行通信。这是一种双向通信，与我们从 Docker Swarm 中所知的通信方式不同。在 Docker Swarm 中，只有管理节点与工作节点通信，而不是相反。访问集群中运行的应用程序的所有入口流量都应该通过另一个**负载均衡器**。这是应用程序**负载均衡器**或反向代理。我们永远不希望外部流量直接访问任何工作节点。

现在我们对 Kubernetes 集群的高级架构有了一个概念，让我们深入一点，看看 Kubernetes 的主节点和工作节点。

# Kubernetes 主节点

Kubernetes 主节点用于管理 Kubernetes 集群。以下是这样一个主节点的高级图表：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/36896fcb-357f-497a-822d-6d08c3a72c1e.png)

Kubernetes 主节点

在上图的底部，我们有**基础设施**，它可以是本地或云端的虚拟机，也可以是本地或云端的服务器（通常称为裸金属）。目前，Kubernetes 主节点只能在**Linux**上运行。支持最流行的 Linux 发行版，如 RHEL、CentOS 和 Ubuntu。在这台 Linux 机器上，我们至少运行以下四个 Kubernetes 服务：

+   **API 服务器**：这是 Kubernetes 的网关。所有对集群中任何资源进行列出、创建、修改或删除的请求都必须通过这个服务。它暴露了一个 REST 接口，像`kubectl`这样的工具用来管理集群和集群中的应用程序。

+   **控制器**：控制器，或者更准确地说是控制器管理器，是一个控制循环，通过 API 服务器观察集群的状态并进行更改，试图将当前状态或有效状态移向期望的状态，如果它们不同。

+   **调度器**：调度器是一个服务，它尽力在考虑各种边界条件时将 pod 调度到工作节点上，例如资源需求、策略、服务质量需求等。

+   **集群存储**：这是一个 etcd 的实例，用于存储集群状态的所有信息。

更准确地说，作为集群存储使用的 etcd 不一定要安装在与其他 Kubernetes 服务相同的节点上。有时，Kubernetes 集群配置为使用独立的 etcd 服务器集群，就像在前一节的架构图中所示。但使用哪种变体是一个高级管理决策，超出了本书的范围。

我们至少需要一个主节点，但为了实现高可用性，我们需要三个或更多的主节点。这与我们所学习的 Docker Swarm 的管理节点非常相似。在这方面，Kubernetes 的主节点相当于 Swarm 的管理节点。

Kubernetes 主节点从不运行应用负载。它们的唯一目的是管理集群。Kubernetes 主节点构建 Raft 一致性组。Raft 协议是一种标准协议，用于需要做出决策的成员组的情况。它被用于许多知名软件产品，如 MongoDB、Docker SwarmKit 和 Kubernetes。有关 Raft 协议的更详细讨论，请参见*进一步阅读*部分中的链接。

正如我们在前一节中提到的，Kubernetes 集群的状态存储在 etcd 中。如果 Kubernetes 集群应该是高可用的，那么 etcd 也必须配置为 HA 模式，这通常意味着我们至少有三个运行在不同节点上的 etcd 实例。

让我们再次声明，整个集群状态存储在 etcd 中。这包括所有集群节点的所有信息，所有副本集、部署、秘密、网络策略、路由信息等等。因此，对于这个键值存储，我们必须有一个强大的备份策略。

现在，让我们来看看将运行集群实际工作负载的节点。

# 集群节点

集群节点是 Kubernetes 调度应用负载的节点。它们是集群的工作马。Kubernetes 集群可以有少数、几十个、上百个，甚至上千个集群节点。Kubernetes 是从头开始构建的，具有高可扩展性。不要忘记，Kubernetes 是模仿 Google Borg 而建立的，Google Borg 多年来一直在运行数万个容器：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/995b10fd-c87a-4b18-b291-104acf1bd1e8.png)

Kubernetes 工作节点

工作节点可以在虚拟机、裸机、本地或云上运行。最初，工作节点只能在 Linux 上配置。但自 Kubernetes 1.10 版本以来，工作节点也可以在 Windows Server 上运行。在混合集群中拥有 Linux 和 Windows 工作节点是完全可以的。

在每个节点上，我们需要运行三个服务，如下：

+   **Kubelet**：这是第一个，也是最重要的服务。Kubelet 是主要的节点代理。kubelet 服务使用 pod 规范来确保相应 pod 的所有容器都在运行并且健康。Pod 规范是以 YAML 或 JSON 格式编写的文件，它们以声明方式描述一个 pod。我们将在下一节了解什么是 pod。Pod 规范主要通过 API 服务器提供给 kubelet。

+   **容器运行时**：每个工作节点上需要存在的第二个服务是容器运行时。Kubernetes 默认从 1.9 版本开始使用`containerd`作为其容器运行时。在那之前，它使用 Docker 守护程序。其他容器运行时，如 rkt 或 CRI-O，也可以使用。容器运行时负责管理和运行 pod 中的各个容器。

+   **kube-proxy**：最后，还有 kube-proxy。它作为一个守护进程运行，是一个简单的网络代理和负载均衡器，用于运行在该特定节点上的所有应用服务。

现在我们已经了解了 Kubernetes 的架构、主节点和工作节点，是时候介绍一下我们可以用来开发针对 Kubernetes 的应用程序的工具了。

# Minikube 简介

Minikube 是一个工具，它在 VirtualBox 或 Hyper-V 中创建一个单节点 Kubernetes 集群（其他虚拟化程序也支持），可以在开发容器化应用程序期间使用。在第二章《设置工作环境》中，我们了解了如何在我们的 macOS 或 Windows 笔记本电脑上安装 Minikube 和`kubectl`。正如在那里所述，Minikube 是一个单节点 Kubernetes 集群，因此该节点同时也是 Kubernetes 主节点和工作节点。

让我们确保 Minikube 正在运行，使用以下命令：

```
$ minikube start
```

一旦 Minikube 准备就绪，我们可以使用`kubectl`访问它的单节点集群。我们应该会看到类似以下的内容：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/ee27b902-c2d7-4d1f-8c7d-8412d06b788b.png)列出 Minikube 中的所有节点

正如我们之前提到的，我们有一个名为`minikube`的单节点集群。Minikube 使用的 Kubernetes 版本是`v1.16.2`（在我的情况下）。

现在，让我们尝试将一个 pod 部署到这个集群中。现在不要担心 pod 是什么；我们将在本章后面深入了解所有细节。暂时就按原样进行。

我们可以使用`labs`文件夹中`ch15`子文件夹中的`sample-pod.yaml`文件来创建这样一个 pod。它的内容如下：

```
apiVersion: v1
kind: Pod
metadata:
  name: nginx
spec:
  containers:
  - name: nginx
    image: nginx:alpine
    ports:
    - containerPort: 80
    - containerPort: 443
```

使用以下步骤运行 pod：

1.  首先，导航到正确的文件夹：

```
$ cd ~/fod/ch15
```

1.  现在，让我们使用名为`kubectl`的 Kubernetes CLI 来部署这个 pod：

```
$ kubectl create -f sample-pod.yaml
pod/nginx created
```

如果我们现在列出所有的 pod，我们应该会看到以下内容：

```
$ kubectl get pods
NAME    READY   STATUS    RESTARTS   AGE
nginx   1/1     Running   0          51s
```

1.  为了能够访问这个 pod，我们需要创建一个服务。让我们使用名为`sample-service.yaml`的文件，它的内容如下：

```
apiVersion: v1
kind: Service
metadata:
  name: nginx-service
spec:
  type: LoadBalancer
  ports:
  - port: 8080
    targetPort: 80
    protocol: TCP
  selector:
    app: nginx
```

1.  再次强调，现在不用担心服务是什么。我们稍后会解释这个。让我们创建这个服务：

```
$ kubectl create -f sample-service.yaml
```

1.  现在，我们可以使用`curl`来访问服务：

```
$ curl -4 http://localhost
```

我们应该收到 Nginx 欢迎页面作为答案。

1.  在继续之前，请删除刚刚创建的两个对象：

```
$ kubectl delete po/nginx
$ kubectl delete svc/nginx-service
```

# Docker for Desktop 中的 Kubernetes 支持

从版本 18.01-ce 开始，Docker for macOS 和 Docker for Windows 已经开始默认支持 Kubernetes。想要将其容器化应用程序部署到 Kubernetes 的开发人员可以使用这个编排器，而不是 SwarmKit。Kubernetes 支持默认关闭，必须在设置中启用。第一次启用 Kubernetes 时，Docker for macOS 或 Windows 需要一些时间来下载创建单节点 Kubernetes 集群所需的所有组件。与 Minikube 相反，后者也是单节点集群，Docker 工具提供的版本使用所有 Kubernetes 组件的容器化版本：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/bf2e24ff-9110-43ac-8e4a-b30f0c5d2df5.png)Docker for macOS 和 Windows 中的 Kubernetes 支持

上图大致概述了 Kubernetes 支持是如何添加到 Docker for macOS 和 Windows 中的。Docker for macOS 使用 hyperkit 来运行基于 LinuxKit 的 VM。Docker for Windows 使用 Hyper-V 来实现结果。在 VM 内部，安装了 Docker 引擎。引擎的一部分是 SwarmKit，它启用了**Swarm-Mode**。Docker for macOS 或 Windows 使用**kubeadm**工具在 VM 中设置和配置 Kubernetes。以下三个事实值得一提：Kubernetes 将其集群状态存储在**etcd**中，因此我们在此 VM 上运行**etcd**。然后，我们有组成 Kubernetes 的所有服务，最后，一些支持从**Docker CLI**部署 Docker 堆栈到 Kubernetes 的服务。这项服务不是官方 Kubernetes 发行版的一部分，但它是特定于 Docker 的。

所有 Kubernetes 组件都在**LinuxKit VM**中以容器形式运行。这些容器可以通过 Docker for macOS 或 Windows 中的设置进行隐藏。在本节的后面，我们将提供在您的笔记本电脑上运行的所有 Kubernetes 系统容器的完整列表，如果您启用了 Kubernetes 支持。为避免重复，从现在开始，我将只谈论 Docker for Desktop 而不是 Docker for macOS 和 Docker for Windows。我将要说的一切同样适用于两个版本。

启用 Docker Desktop 的 Kubernetes 的一个很大优势是，它允许开发人员使用单个工具构建、测试和运行针对 Kubernetes 的容器化应用程序。甚至可以使用 Docker Compose 文件将多服务应用程序部署到 Kubernetes。

现在，让我们动手：

1.  首先，我们必须启用 Kubernetes。在 macOS 上，点击菜单栏中的 Docker 图标；或者在 Windows 上，转到命令托盘并选择“首选项”。在打开的对话框中，选择 Kubernetes，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/53d9153e-43f2-4b1c-ab52-bf08d8889001.png)在 Docker Desktop 中启用 Kubernetes

1.  然后，选中“启用 Kubernetes”复选框。还要选中“默认情况下将 Docker 堆叠部署到 Kubernetes”和“显示系统容器（高级）”复选框。然后，点击“应用并重启”按钮。安装和配置 Kubernetes 需要几分钟。现在，是时候休息一下，享受一杯好茶了。

1.  安装完成后（Docker 通过在设置对话框中显示绿色状态图标来通知我们），我们可以进行测试。由于我们现在在笔记本电脑上运行了两个 Kubernetes 集群，即 Minikube 和 Docker Desktop，我们需要配置`kubectl`以访问后者。

首先，让我们列出所有我们拥有的上下文：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/ca14801c-00eb-46cc-8edc-0b3edaba44f4.png)kubectl 的上下文列表

在这里，我们可以看到，在我的笔记本电脑上，我有之前提到的两个上下文。当前，Minikube 上下文仍然处于活动状态，在`CURRENT`列中标有星号。我们可以使用以下命令切换到`docker-for-desktop`上下文：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/903685b8-ecdb-455e-85a1-03188389f5c1.png)更改 Kubernetes CLI 的上下文

现在，我们可以使用`kubectl`来访问 Docker Desktop 刚刚创建的集群。我们应该看到以下内容：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/d3b65b94-4772-4584-9d06-3fa88a05a0eb.png)Docker Desktop 创建的单节点 Kubernetes 集群

好的，这看起来非常熟悉。这几乎与我们在使用 Minikube 时看到的一样。我的 Docker Desktop 使用的 Kubernetes 版本是`1.15.5`。我们还可以看到节点是主节点。

如果我们列出当前在 Docker Desktop 上运行的所有容器，我们将得到下面截图中显示的列表（请注意，我使用`--format`参数来输出容器的`Container ID`和`Names`）：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/6837f756-ac8a-41a7-b8af-6357e140ea1c.png)Kubernetes 系统容器

在前面的列表中，我们可以识别出组成 Kubernetes 的所有熟悉组件，如下所示：

+   API 服务器

+   etcd

+   Kube 代理

+   DNS 服务

+   Kube 控制器

+   Kube 调度程序

还有一些容器中带有`compose`一词。这些是特定于 Docker 的服务，允许我们将 Docker Compose 应用程序部署到 Kubernetes 上。Docker 将 Docker Compose 语法进行转换，并隐式创建必要的 Kubernetes 对象，如部署、Pod 和服务。

通常，我们不希望在容器列表中混杂这些系统容器。因此，我们可以在 Kubernetes 的设置中取消选中“显示系统容器（高级）”复选框。

现在，让我们尝试将 Docker Compose 应用程序部署到 Kubernetes。转到`~/fod`文件夹的`ch15`子文件夹。我们使用`docker-compose.yml`文件将应用程序部署为堆栈：

```
$ docker stack deploy -c docker-compose.yml app
```

我们应该看到以下内容：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/c712f4fd-1771-4475-a125-e9286974bdb6.png)将堆栈部署到 Kubernetes

我们可以使用`curl`来测试应用程序，并且会发现它按预期运行：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/86a7e757-6c9f-4706-b38d-1d13096cb908.png)在 Docker 桌面上的 Kubernetes 中运行的宠物应用程序

现在，让我们看看在执行`docker stack deploy`命令时 Docker 到底做了什么。我们可以使用`kubectl`来找出：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/d4a81014-a75b-40c2-8c45-56412e93455d.png)列出由 docker stack deploy 创建的所有 Kubernetes 对象

Docker 为`web`服务创建了一个部署，为`db`服务创建了一个有状态集。它还自动为`web`和`db`创建了 Kubernetes 服务，以便它们可以在集群内部访问。它还创建了 Kubernetes `svc/web-published`服务，用于外部访问。

这相当酷，至少可以说，极大地减少了团队在开发过程中针对 Kubernetes 作为编排平台时的摩擦

在继续之前，请从集群中删除堆栈：

```
$ docker stack rm app
```

还要确保将`kubectl`的上下文重置回 Minikube，因为我们将在本章中使用 Minikube 进行所有示例：

```
$ kubectl config use-context minikube
```

现在，我们已经介绍了用于开发最终将在 Kubernetes 集群中运行的应用程序的工具，是时候了解用于定义和管理这样的应用程序的所有重要 Kubernetes 对象了。我们将从 Pod 开始。

# Pod 简介

与 Docker Swarm 中可能的情况相反，在 Kubernetes 集群中不能直接运行容器。在 Kubernetes 集群中，您只能运行 Pod。Pod 是 Kubernetes 中部署的原子单位。Pod 是一个或多个共同定位的容器的抽象，它们共享相同的内核命名空间，如网络命名空间。在 Docker SwarmKit 中不存在等价物。多个容器可以共同定位并共享相同的网络命名空间的事实是一个非常强大的概念。下图说明了两个 Pod：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/81cd2bb8-23c9-4034-9ad3-eb03b5d6a1ba.png)Kubernetes pods

在上图中，我们有两个 Pod，**Pod 1**和**Pod 2**。第一个 Pod 包含两个容器，而第二个 Pod 只包含一个容器。每个 Pod 都由 Kubernetes 分配一个 IP 地址，在整个 Kubernetes 集群中是唯一的。在我们的情况下，它们的 IP 地址分别是：`10.0.12.3`和`10.0.12.5`。它们都是由 Kubernetes 网络驱动程序管理的私有子网的一部分。

一个 Pod 可以包含一个到多个容器。所有这些容器共享相同的 Linux 内核命名空间，特别是它们共享网络命名空间。这是由包围容器的虚线矩形表示的。由于在同一个 Pod 中运行的所有容器共享网络命名空间，因此每个容器都需要确保使用自己的端口，因为在单个网络命名空间中不允许重复端口。在这种情况下，在**Pod 1**中，**主容器**使用端口`80`，而**支持容器**使用端口`3000`。

来自其他 Pod 或节点的请求可以使用 Pod 的 IP 地址和相应的端口号来访问各个容器。例如，您可以通过`10.0.12.3:80`访问**Pod 1**中主容器中运行的应用程序。

# 比较 Docker 容器和 Kubernetes Pod 网络

现在，让我们比较一下 Docker 的容器网络和 Kubernetes 的 Pod 网络。在下图中，我们将前者放在左侧，后者放在右侧：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/23036596-986c-43b4-83db-2732000cfad9.png)Pod 中的容器共享相同的网络命名空间

当创建一个 Docker 容器并且没有指定特定的网络时，Docker 引擎会创建一个**虚拟以太网**（veth）端点。第一个容器得到**veth0**，下一个得到**veth1**，以此类推。这些虚拟以太网端点连接到 Linux 桥**docker0**，Docker 在安装时自动创建。流量从**docker0**桥路由到每个连接的**veth**端点。每个容器都有自己的网络命名空间。没有两个容器使用相同的命名空间。这是有意为之，目的是隔离容器内运行的应用程序。

对于 Kubernetes pod，情况是不同的。在创建一个新的 pod 时，Kubernetes 首先创建一个所谓的**pause**容器，其唯一目的是创建和管理 pod 将与所有容器共享的命名空间。除此之外，它没有任何有用的功能；它只是在睡觉。**pause**容器通过**veth0**连接到**docker0**桥。任何随后成为 pod 一部分的容器都使用 Docker 引擎的一个特殊功能，允许它重用现有的网络命名空间。这样做的语法看起来像这样：

```
$ docker container create --net container:pause ... 
```

重要的部分是`--net`参数，它使用`container:<container name>`作为值。如果我们以这种方式创建一个新容器，那么 Docker 不会创建一个新的 veth 端点；容器使用与`pause`容器相同的端点。

多个容器共享相同的网络命名空间的另一个重要后果是它们相互通信的方式。让我们考虑以下情况：一个包含两个容器的 pod，一个在端口`80`上监听，另一个在端口`3000`上监听。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/55170356-9c32-42bb-bbcd-a9f51f59017e.png)Pod 中的容器通过 localhost 通信

当两个容器使用相同的 Linux 内核网络命名空间时，它们可以通过 localhost 相互通信，类似于当两个进程在同一主机上运行时，它们也可以通过 localhost 相互通信。这在前面的图表中有所说明。从主容器中，其中的容器化应用程序可以通过`http://localhost:3000`访问支持容器内运行的服务。

# 共享网络命名空间

在所有这些理论之后，你可能会想知道 Kubernetes 是如何实际创建一个 Pod 的。Kubernetes 只使用 Docker 提供的内容。那么，*这个网络命名空间共享是如何工作的呢？*首先，Kubernetes 创建所谓的`pause`容器，如前所述。这个容器除了保留内核命名空间给该 Pod 并保持它们的活动状态外，没有其他功能，即使 Pod 内没有其他容器在运行。然后，我们模拟创建一个 Pod。我们首先创建`pause`容器，并使用 Nginx 来实现这个目的：

```
$ docker container run -d --name pause nginx:alpine
```

现在，我们添加一个名为`main`的第二个容器，将其附加到与`pause`容器相同的网络命名空间：

```
$ docker container run --name main -dit \
 --net container:pause \
 alpine:latest /bin/sh
```

由于`pause`和示例容器都是同一个网络命名空间的一部分，它们可以通过`localhost`相互访问。为了证明这一点，我们必须`exec`进入主容器：

```
$ docker exec -it main /bin/sh
```

现在，我们可以测试连接到运行在`pause`容器中并监听端口`80`的 Nginx。如果我们使用`wget`工具来做到这一点，我们会得到以下结果：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/ccfdb453-ac21-47bd-a2af-716d7c2bcb1e.png)两个共享相同网络命名空间的容器

输出显示我们确实可以在`localhost`上访问 Nginx。这证明了这两个容器共享相同的命名空间。如果这还不够，我们可以使用`ip`工具来显示两个容器内部的`eth0`，我们将得到完全相同的结果，具体来说，相同的 IP 地址，这是 Pod 的特征之一，所有容器共享相同的 IP 地址：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/ad510dd1-a0ea-4767-ac14-94eecd16c1a3.png)使用`ip`工具显示`eth0`的属性

如果我们检查`bridge`网络，我们会看到只有`pause`容器被列出。另一个容器没有在`Containers`列表中得到条目，因为它正在重用`pause`容器的端点：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/e553023b-c1e7-4abf-893c-b8cb75208b13.png)检查 Docker 默认桥接网络

接下来，我们将研究 Pod 的生命周期。

# Pod 的生命周期

在本书的前面，我们学到了容器有一个生命周期。容器被初始化，运行，最终退出。当一个容器退出时，它可以以退出码零的方式优雅地退出，也可以以错误终止，这相当于非零的退出码。

同样，一个 Pod 也有一个生命周期。由于一个 Pod 可以包含多个容器，因此其生命周期比单个容器的生命周期稍微复杂一些。Pod 的生命周期可以在下图中看到：

Kubernetes Pod 的生命周期

当在集群节点上创建一个**Pod**时，它首先进入**pending**状态。一旦所有的 Pod 容器都启动并运行，Pod 就会进入**running**状态。只有当所有容器成功运行时，Pod 才会进入这个状态。如果要求 Pod 终止，它将请求所有容器终止。如果所有容器以退出码零终止，那么 Pod 就会进入**succeeded**状态。这是一条顺利的路径。

现在，让我们看一些导致 Pod 处于 failed 状态的情景。有三种可能的情景：

+   如果在 Pod 启动过程中，至少有一个容器无法运行并失败（即以非零退出码退出），Pod 将从**pending**状态转换为**failed**状态。

+   如果 Pod 处于 running 状态，而其中一个容器突然崩溃或以非零退出码退出，那么 Pod 将从 running 状态转换为 failed 状态。

+   如果要求 Pod 终止，并且在关闭过程中至少有一个容器以非零退出码退出，那么 Pod 也会进入 failed 状态。

现在，让我们来看一下 Pod 的规范。

# Pod 规范

在 Kubernetes 集群中创建一个 Pod 时，我们可以使用命令式或声明式方法。我们之前在本书中讨论过这两种方法的区别，但是，重申最重要的一点，使用声明式方法意味着我们编写一个描述我们想要实现的最终状态的清单。我们将略去编排器的细节。我们想要实现的最终状态也被称为**desired state**。一般来说，在所有已建立的编排器中，声明式方法都是强烈推荐的，Kubernetes 也不例外。

因此，在本章中，我们将专注于声明式方法。Pod 的清单或规范可以使用 YAML 或 JSON 格式编写。在本章中，我们将专注于 YAML，因为它对我们人类来说更容易阅读。让我们看一个样本规范。这是`pod.yaml`文件的内容，可以在我们的`labs`文件夹的`ch12`子文件夹中找到：

```
apiVersion: v1
kind: Pod
metadata:
  name: web-pod
spec:
  containers:
  - name: web
    image: nginx:alpine
    ports:
    - containerPort: 80
```

Kubernetes 中的每个规范都以版本信息开头。Pods 已经存在了相当长的时间，因此 API 版本是`v1`。第二行指定了我们要定义的 Kubernetes 对象或资源的类型。显然，在这种情况下，我们要指定一个`Pod`。接下来是包含元数据的块。至少，我们需要给 pod 一个名称。在这里，我们称其为`web-pod`。接下来跟随的是`spec`块，其中包含 pod 的规范。最重要的部分（也是这个简单示例中唯一的部分）是这个 pod 中所有容器的列表。我们这里只有一个容器，但是多个容器是可能的。我们为容器选择的名称是`web`，容器镜像是`nginx:alpine`。最后，我们定义了容器正在暴露的端口列表。

一旦我们编写了这样的规范，我们就可以使用 Kubernetes CLI `kubectl`将其应用到集群中。在终端中，导航到`ch15`子文件夹，并执行以下命令：

```
$ kubectl create -f pod.yaml
```

这将回应`pod "web-pod" created`。然后我们可以使用`kubectl get pods`列出集群中的所有 pod：

```
$ kubectl get pods
NAME      READY   STATUS    RESTARTS   AGE
web-pod   1/1     Running   0          2m
```

正如预期的那样，我们在运行状态中有一个 pod。该 pod 被称为`web-pod`，如所定义。我们可以使用`describe`命令获取有关运行中 pod 的更详细信息：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/99fb4f13-8084-40a5-a7c5-773f47e056e2.png)描述运行在集群中的 pod

请注意在前面的`describe`命令中的`pod/web-pod`表示法。其他变体也是可能的；例如，`pods/web-pod`，`po/web-pod`。`pod`和`po`是`pods`的别名。`kubectl`工具定义了许多别名，使我们的生活变得更加轻松。

`describe`命令为我们提供了关于 pod 的大量有价值的信息，其中包括发生的事件列表，以及影响了这个 pod 的事件。列表显示在输出的末尾。

`Containers`部分中的信息与`docker container inspect`输出中的信息非常相似。

我们还可以看到`Volumes`部分中有一个`Secret`类型的条目。我们将在下一章讨论 Kubernetes secrets。另一方面，卷将在下一章讨论。

# Pods 和 volumes

在第五章中，*数据卷和配置*，我们学习了卷及其目的：访问和存储持久数据。由于容器可以挂载卷，Pod 也可以这样做。实际上，实际上是 Pod 内的容器挂载卷，但这只是一个语义细节。首先，让我们看看如何在 Kubernetes 中定义卷。Kubernetes 支持大量的卷类型，所以我们不会深入讨论这个问题。让我们通过隐式定义一个名为`my-data-claim`的`PersistentVolumeClaim`来创建一个本地卷：

```
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: my-data-claim
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 2Gi
```

我们已经定义了一个请求 2GB 数据的声明。让我们创建这个声明：

```
$ kubectl create -f volume-claim.yaml
```

我们可以使用`kubectl`列出声明（`pvc`是`PersistentVolumeClaim`的快捷方式）：

在集群中列出持久存储声明对象

在输出中，我们可以看到声明已经隐式创建了一个名为`pvc-<ID>`的卷。我们现在准备在 Pod 中使用声明创建的卷。让我们使用之前使用的 Pod 规范的修改版本。我们可以在`ch12`文件夹中的`pod-with-vol.yaml`文件中找到这个更新的规范。让我们详细看一下这个规范：

```
apiVersion: v1
kind: Pod
metadata:
  name: web-pod
spec:
  containers:
  - name: web
    image: nginx:alpine
    ports:
    - containerPort: 80
    volumeMounts:
    - name: my-data
      mountPath: /data
  volumes:
  - name: my-data
    persistentVolumeClaim:
      claimName: my-data-claim
```

在最后四行中，在`volumes`块中，我们定义了我们想要为这个 Pod 使用的卷的列表。我们在这里列出的卷可以被 Pod 的任何一个容器使用。在我们的特定情况下，我们只有一个卷。我们指定我们有一个名为`my-data`的卷，这是一个持久卷声明，其声明名称就是我们刚刚创建的。然后，在容器规范中，我们有`volumeMounts`块，这是我们定义我们想要使用的卷以及容器内部的（绝对）路径的地方，卷将被挂载到容器文件系统的`/data`文件夹。让我们创建这个 Pod：

```
$ kubectl create -f pod-with-vol.yaml
```

然后，我们可以通过`exec`进入容器，通过导航到`/data`文件夹，创建一个文件，并退出容器来再次检查卷是否已挂载：

```
$ kubectl exec -it web-pod -- /bin/sh
/ # cd /data
/data # echo "Hello world!" > sample.txt
/data # exit
```

如果我们是正确的，那么这个容器中的数据必须在 Pod 的生命周期之外持续存在。因此，让我们删除 Pod，然后重新创建它并进入其中，以确保数据仍然存在。这是结果：

存储在卷中的数据在 Pod 重新创建时仍然存在

现在我们对 pod 有了很好的理解，让我们来看看如何借助 ReplicaSets 来管理这些 pod。

# Kubernetes ReplicaSet

在具有高可用性要求的环境中，单个 pod 是不够的。如果 pod 崩溃了怎么办？如果我们需要更新 pod 内运行的应用程序，但又不能承受任何服务中断怎么办？这些问题等等表明单独的 pod 是不够的，我们需要一个可以管理多个相同 pod 实例的更高级概念。在 Kubernetes 中，ReplicaSet 用于定义和管理在不同集群节点上运行的相同 pod 的集合。除其他事项外，ReplicaSet 定义了在 pod 内运行的容器使用哪些容器镜像，以及集群中将运行多少个 pod 实例。这些属性和许多其他属性被称为所需状态。

ReplicaSet 负责始终协调所需的状态，如果实际状态偏离所需状态。这是一个 Kubernetes ReplicaSet：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/7f6cc3c9-2f46-4517-8b87-372a24c0c8bc.png)Kubernetes ReplicaSet

在前面的图表中，我们可以看到一个名为 rs-api 的 ReplicaSet，它管理着一些 pod。这些 pod 被称为 pod-api。ReplicaSet 负责确保在任何给定时间，始终有所需数量的 pod 在运行。如果其中一个 pod 因任何原因崩溃，ReplicaSet 会在具有空闲资源的节点上安排一个新的 pod。如果 pod 的数量超过所需数量，那么 ReplicaSet 会终止多余的 pod。通过这种方式，我们可以说 ReplicaSet 保证了一组 pod 的自愈和可伸缩性。ReplicaSet 可以容纳多少个 pod 没有限制。

# ReplicaSet 规范

与我们对 pod 的学习类似，Kubernetes 也允许我们以命令式或声明式方式定义和创建 ReplicaSet。由于在大多数情况下，声明式方法是最推荐的方法，我们将集中讨论这种方法。以下是一个 Kubernetes ReplicaSet 的样本规范：

```
apiVersion: apps/v1
kind: ReplicaSet
metadata:
  name: rs-web
spec:
  selector:
    matchLabels:
      app: web
  replicas: 3
  template: 
    metadata:
      labels:
        app: web
    spec:
      containers:
      - name: nginx
        image: nginx:alpine
        ports:
        - containerPort: 80
```

这看起来非常像我们之前介绍的 Pod 规范。让我们集中精力关注不同之处。首先，在第 2 行，我们有`kind`，它曾经是`Pod`，现在是`ReplicaSet`。然后，在第 6-8 行，我们有一个选择器，它确定将成为`ReplicaSet`一部分的 Pods。在这种情况下，它是所有具有`app`标签值为`web`的 Pods。然后，在第 9 行，我们定义了我们想要运行的 Pod 的副本数量；在这种情况下是三个。最后，我们有`template`部分，首先定义了`metadata`，然后定义了`spec`，它定义了在 Pod 内运行的容器。在我们的情况下，我们有一个使用`nginx:alpine`镜像并导出端口`80`的单个容器。

真正重要的元素是副本的数量和选择器，它指定了由`ReplicaSet`管理的 Pod 集合。

在我们的`ch15`文件夹中，有一个名为`replicaset.yaml`的文件，其中包含了前面的规范。让我们使用这个文件来创建`ReplicaSet`：

```
$ kubectl create -f replicaset.yaml
replicaset "rs-web" created
```

如果我们列出集群中的所有 ReplicaSets，我们会得到以下结果（`rs`是`replicaset`的缩写）：

```
$ kubectl get rs
NAME     DESIRED   CURRENT   READY   AGE
rs-web   3         3         3       51s
```

在上面的输出中，我们可以看到我们有一个名为`rs-web`的单个 ReplicaSet，其期望状态为三（个 Pods）。当前状态也显示了三个 Pods，并告诉我们所有三个 Pods 都已准备就绪。我们还可以列出系统中的所有 Pods。这将导致以下输出：

```
$ kubectl get pods
NAME           READY   STATUS    RESTARTS   AGE
rs-web-6qzld   1/1     Running   0          4m
rs-web-frj2m   1/1     Running   0          4m
rs-web-zd2kt   1/1     Running   0          4m
```

在这里，我们可以看到我们期望的三个 Pods。Pods 的名称使用 ReplicaSet 的名称，并为每个 Pod 附加了唯一的 ID。在`READY`列中，我们可以看到在 Pod 中定义了多少个容器以及其中有多少个是就绪的。在我们的情况下，每个 Pod 只有一个容器，并且每种情况下都已准备就绪。因此，Pod 的整体状态是`Running`。我们还可以看到每个 Pod 需要重新启动的次数。在我们的情况下，我们没有任何重新启动。

# 自愈

现在，让我们测试自愈`ReplicaSet`的魔力，随机杀死其中一个 Pod 并观察发生了什么。让我们从前面的列表中删除第一个 Pod：

```
$ kubectl delete po/rs-web-6qzld
pod "rs-web-6qzld" deleted
```

现在，让我们再次列出所有的 Pods。我们期望只看到两个 Pods，*对吗*？错了：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/71366fbf-4638-484c-b2f6-dab56b41f5f4.png)杀死 ReplicaSet 中一个 Pod 后的 Pod 列表

好的；显然，列表中的第二个 Pod 已经被重新创建，我们可以从`AGE`列中看到。这就是自动修复的工作。让我们看看如果我们描述 ReplicaSet 会发现什么：

描述 ReplicaSet

确实，在“事件”下我们找到了一个条目，告诉我们 ReplicaSet 创建了名为 rs-web-q6cr7 的新 pod。

# Kubernetes 部署

Kubernetes 非常严肃地遵循单一责任原则。所有 Kubernetes 对象都被设计成只做一件事，并且它们被设计得非常出色。在这方面，我们必须了解 Kubernetes 的 ReplicaSets 和 Deployments。正如我们所学到的，ReplicaSet 负责实现和协调应用服务的期望状态。这意味着 ReplicaSet 管理一组 pod。

部署通过在 ReplicaSet 的基础上提供滚动更新和回滚功能来增强 ReplicaSet。在 Docker Swarm 中，Swarm 服务结合了 ReplicaSet 和部署的功能。在这方面，SwarmKit 比 Kubernetes 更加单片化。下图显示了部署与 ReplicaSet 的关系：

Kubernetes 部署

在上图中，ReplicaSet 定义和管理一组相同的 pod。ReplicaSet 的主要特点是它是自愈的、可扩展的，并且始终尽最大努力协调期望状态。而 Kubernetes 部署则为此添加了滚动更新和回滚功能。在这方面，部署实际上是对 ReplicaSet 的包装对象。

我们将在第十六章《使用 Kubernetes 部署、更新和保护应用程序》中学习滚动更新和回滚。

在下一节中，我们将更多地了解 Kubernetes 服务以及它们如何实现服务发现和路由。

# Kubernetes 服务

一旦我们开始处理由多个应用服务组成的应用程序，我们就需要服务发现。下图说明了这个问题：

服务发现

在上图中，我们有一个需要访问其他三个服务的**Web API**服务：**支付**，**运输**和**订购**。**Web API**不应该关心如何以及在哪里找到这三个服务。在 API 代码中，我们只想使用我们想要到达的服务的名称和端口号。一个示例是以下 URL `http://payments:3000`，用于访问支付服务的一个实例。

在 Kubernetes 中，支付应用程序服务由一组 Pod 的 ReplicaSet 表示。由于高度分布式系统的性质，我们不能假设 Pod 具有稳定的端点。一个 Pod 可能随心所欲地出现和消失。但是，如果我们需要从内部或外部客户端访问相应的应用程序服务，这就是一个问题。如果我们不能依赖于 Pod 端点的稳定性，*我们还能做什么呢？*

这就是 Kubernetes 服务发挥作用的地方。它们旨在为 ReplicaSets 或 Deployments 提供稳定的端点，如下所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/09cdd19a-e492-480c-9df1-f65ffc600f9d.png)Kubernetes 服务为客户端提供稳定的端点

在上图中，中心位置有一个这样的 Kubernetes **Service**。它提供了一个**可靠的**集群范围**IP**地址，也称为**虚拟 IP**（**VIP**），以及整个集群中唯一的**可靠**端口。Kubernetes 服务代理的 Pod 由服务规范中定义的**选择器**确定。选择器总是基于标签。每个 Kubernetes 对象都可以分配零个或多个标签。在我们的情况下，**选择器**是**app=web**；也就是说，所有具有名为 app 且值为 web 的标签的 Pod 都被代理。

在接下来的部分，我们将学习更多关于基于上下文的路由以及 Kubernetes 如何减轻这项任务。

# 基于上下文的路由

通常，我们希望为我们的 Kubernetes 集群配置基于上下文的路由。Kubernetes 为我们提供了各种方法来做到这一点。目前，首选和最可扩展的方法是使用**IngressController**。以下图尝试说明这个 IngressController 是如何工作的：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/bc913d65-7d30-4339-b876-5d1c0201e3f5.png)

使用 Kubernetes Ingress Controller 进行基于上下文的路由

在上图中，我们可以看到当使用**IngressController**（如 Nginx）时，基于上下文（或第 7 层）的路由是如何工作的。在这里，我们部署了一个名为**web**的应用服务。该应用服务的所有 pod 都具有以下标签：**app=web**。然后，我们有一个名为**web**的 Kubernetes 服务，为这些 pod 提供了一个稳定的端点。该服务具有一个（虚拟）**IP**为`52.14.0.13`，并暴露端口`30044`。也就是说，如果任何 Kubernetes 集群的节点收到对**web**名称和端口`30044`的请求，那么它将被转发到该服务。然后该服务将请求负载均衡到其中一个 pod。

到目前为止，一切都很好，*但是客户端对`http[s]://example.com/web`*的 Ingress 请求是如何路由到我们的 web 服务的呢？*首先，我们必须定义从基于上下文的请求到相应的`<service name>/<port>请求`的路由。这是通过一个**Ingress**对象完成的：

1.  在**Ingress**对象中，我们将**Host**和**Path**定义为源和（服务）名称，端口定义为目标。当 Kubernetes API 服务器创建此 Ingress 对象时，运行在`IngressController`中的一个进程会捕捉到这个变化。

1.  该进程修改了 Nginx 反向代理的配置文件。

1.  通过添加新路由，然后要求 Nginx 重新加载其配置，从而能够正确地将任何传入请求路由到`http[s]://example.com/web`。

在接下来的部分，我们将通过对比每个编排引擎的一些主要资源来比较 Docker SwarmKit 和 Kubernetes。

# 比较 SwarmKit 和 Kubernetes

现在我们已经学习了关于 Kubernetes 中最重要的资源的许多细节，通过匹配重要资源来比较两个编排器 SwarmKit 和 Kubernetes 是有帮助的。让我们来看一下：

| **SwarmKit** | **Kubernetes** | **描述** |
| --- | --- | --- |
| Swarm | 集群 | 由各自编排器管理的一组服务器/节点。 |
| 节点 | 集群成员 | Swarm/集群的单个主机（物理或虚拟）。 |
| 管理节点 | 主节点 | 管理 Swarm/集群的节点。这是控制平面。 |
| 工作节点 | 节点 | 运行应用程序工作负载的 Swarm/集群成员。 |
| 容器 | 容器** | 在节点上运行的容器镜像的实例。**注意：在 Kubernetes 集群中，我们不能直接运行容器。 |
| 任务 | Pod | 在节点上运行的服务（Swarm）或 ReplicaSet（Kubernetes）的实例。一个任务管理一个容器，而一个 Pod 包含一个到多个共享相同网络命名空间的容器。 |
| 服务 | 副本集 | 定义并协调由多个实例组成的应用服务的期望状态。 |
| 服务 | 部署 | 部署是一个带有滚动更新和回滚功能的 ReplicaSet。 |
| 路由网格 | 服务 | Swarm 路由网格使用 IPVS 提供 L4 路由和负载平衡。Kubernetes 服务是一个抽象，定义了一组逻辑 pod 和可用于访问它们的策略。它是一组 pod 的稳定端点。 |
| 堆栈 | 堆栈 ** | 由多个（Swarm）服务组成的应用程序的定义。**注意：虽然堆栈不是 Kubernetes 的本机功能，但 Docker 的工具 Docker for Desktop 将它们转换为部署到 Kubernetes 集群上的功能。 |
| 网络 | 网络策略 | Swarm 的软件定义网络（SDN）用于防火墙容器。Kubernetes 只定义了一个单一的平面网络。除非明确定义了网络策略来限制 pod 之间的通信，否则每个 pod 都可以访问每个其他 pod 和/或节点。 |

# 总结

在本章中，我们了解了 Kubernetes 的基础知识。我们概述了其架构，并介绍了在 Kubernetes 集群中定义和运行应用程序的主要资源。我们还介绍了 Minikube 和 Docker for Desktop 中的 Kubernetes 支持。

在下一章中，我们将在 Kubernetes 集群中部署一个应用程序。然后，我们将使用零停机策略更新此应用程序的其中一个服务。最后，我们将使用机密信息对在 Kubernetes 中运行的应用程序服务进行仪器化。敬请关注！

# 问题

请回答以下问题以评估您的学习进度：

1.  用几句简短的话解释一下 Kubernetes 主节点的作用。

1.  列出每个 Kubernetes（工作）节点上需要存在的元素。

1.  我们不能在 Kubernetes 集群中运行单独的容器。

A. 是

B. 否

1.  解释为什么 pod 中的容器可以使用`localhost`相互通信。

1.  所谓的暂停容器在 pod 中的目的是什么？

1.  鲍勃告诉你：“我们的应用由三个 Docker 镜像组成：`web`、`inventory`和`db`。由于我们可以在 Kubernetes pod 中运行多个容器，我们将在一个单独的 pod 中部署我们应用的所有服务。”列出三到四个这样做是个坏主意的原因。

1.  用自己的话解释为什么我们需要 Kubernetes ReplicaSets。

1.  在什么情况下我们需要 Kubernetes 部署？

1.  列出至少三种 Kubernetes 服务类型，并解释它们的目的和区别。

# 进一步阅读

以下是一些包含更多关于我们在本章讨论的各种主题的详细信息的文章列表：

+   Raft 一致性算法：[`raft.github.io/`](https://raft.github.io/)

+   使用 Docker 桌面版的 Docker Compose 和 Kubernetes：[`dockr.ly/2G8Iqb9`](https://dockr.ly/2G8Iqb9)

+   Kubernetes 文档：[`kubernetes.io/docs/home/`](https://kubernetes.io/docs/home/)


# 第十六章：使用 Kubernetes 部署、更新和保护应用程序

在上一章中，我们了解了容器编排器 Kubernetes 的基础知识。我们对 Kubernetes 的架构有了高层次的概述，并且学到了很多关于 Kubernetes 用于定义和管理容器化应用程序的重要对象。

在本章中，我们将学习如何将应用程序部署、更新和扩展到 Kubernetes 集群中。我们还将解释如何实现零停机部署，以实现对关键任务应用程序的无干扰更新和回滚。最后，我们将介绍 Kubernetes 秘密作为配置服务和保护敏感数据的手段。

本章涵盖以下主题：

+   部署第一个应用程序

+   定义活动性和就绪性

+   零停机部署

+   Kubernetes 秘密

通过本章的学习，您将能够做到以下事情：

+   将多服务应用程序部署到 Kubernetes 集群中

+   为您的 Kubernetes 应用程序服务定义活动性和就绪性探测

+   在不造成停机的情况下更新在 Kubernetes 中运行的应用程序服务

+   在 Kubernetes 集群中定义秘密

+   配置应用程序服务以使用 Kubernetes 秘密

# 技术要求

在本章中，我们将在本地计算机上使用 Minikube。有关如何安装和使用 Minikube 的更多信息，请参阅第二章，*设置工作环境*。

本章的代码可以在此处找到：[`github.com/PacktPublishing/Learn-Docker---Fundamentals-of-Docker-19.x-Second-Edition/tree/master/ch16/probes`](https://github.com/PacktPublishing/Learn-Docker---Fundamentals-of-Docker-19.x-Second-Edition/tree/master/ch16/probes)。

请确保您已经克隆了本书的 GitHub 存储库，如第二章中所述，*设置工作环境*。

在终端中，导航到`~/fod/ch16`文件夹。

# 部署第一个应用程序

我们将把我们在第十一章中首次介绍的宠物应用程序，*Docker Compose*，部署到 Kubernetes 集群中。我们的集群将是 Minikube，正如您所知，它是一个单节点集群。但是，从部署的角度来看，集群的大小以及集群在云中的位置、公司的数据中心或个人工作站并不重要。

# 部署 web 组件

作为提醒，我们的应用程序由两个应用程序服务组成：基于 Node 的 web 组件和支持的 PostgreSQL 数据库。在上一章中，我们了解到我们需要为要部署的每个应用程序服务定义一个 Kubernetes Deployment 对象。首先让我们为 web 组件做这个。就像本书中的所有内容一样，我们将选择声明性的方式来定义我们的对象。以下是为 web 组件定义 Deployment 对象的 YAML：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/f43630a9-a410-44cf-a9f1-bcd87d583f54.png)用于 web 组件的 Kubernetes 部署定义

前面的部署定义可以在`~/fod/ch16`文件夹中的`web-deployment.yaml`文件中找到。代码行如下：

+   在第 4 行：我们为我们的`Deployment`对象定义了名称为`web`。

+   在第 6 行：我们声明我们想要运行一个`web`组件的实例。

+   从第 8 行到第 10 行：我们定义了哪些 pod 将成为我们部署的一部分，即那些具有`app`和`service`标签，其值分别为`pets`和`web`的 pod。

+   在第 11 行：在从第 11 行开始的 pod 模板中，我们定义每个 pod 将被应用`app`和`service`标签。

+   从第 17 行开始：我们定义将在 pod 中运行的单个容器。容器的镜像是我们熟悉的`fundamentalsofdocker/ch11-web:2.0`镜像，容器的名称将是`web`。

+   `ports`：最后，我们声明容器为 TCP 类型流量公开端口`3000`。

请确保您已将 kubectl 的上下文设置为 Minikube。有关如何执行此操作的详细信息，请参见第二章，“设置工作环境”。

我们可以使用 kubectl 部署这个 Deployment 对象：

```
$ kubectl create -f web-deployment.yaml
```

我们可以使用我们的 Kubernetes CLI 再次检查部署是否已创建。我们应该看到以下输出：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/b631548b-c83b-4421-a037-a931a77b9ba7.png)列出在 Minikube 中运行的所有资源

在前面的输出中，我们可以看到 Kubernetes 创建了三个对象-部署、相关的 ReplicaSet 和一个单独的 pod（请记住，我们指定了我们只想要一个副本）。当前状态与所有三个对象的期望状态相对应，所以到目前为止一切都很好。

现在，web 服务需要暴露给公众。为此，我们需要定义一个`NodePort`类型的 Kubernetes `Service`对象。以下是定义，可以在`~/fod/ch16`文件夹中的`web-service.yaml`文件中找到：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/aa181850-9aab-492a-a132-e99ecbb7f102.png)为我们的 web 组件定义的 Service 对象

上述代码的前几行如下：

+   在第`4`行：我们将这个`Service`对象的`name`设置为`web`。

+   在第`6`行：我们定义了我们正在使用的`Service`对象的`type`。由于 web 组件必须从集群外部访问，这不能是`ClusterIP`类型的`Service`对象，必须是`NodePort`或`LoadBalancer`类型的。我们在上一章讨论了各种类型的 Kubernetes 服务，所以不会再详细讨论这个问题。在我们的示例中，我们使用了`NodePort`类型的服务。

+   在第`8`行和`9`行：我们指定我们要通过`TCP`协议公开端口`3000`。Kubernetes 将自动将容器端口`3000`映射到 30,000 到 32,768 范围内的空闲主机端口。Kubernetes 实际上选择的端口可以在创建后使用`kubectl get service`或`kubectl describe`命令来确定服务。

+   从第`10`行到`12`行：我们为这个服务定义筛选标准，以确定这个服务将作为哪些 pod 的稳定端点。在这种情况下，它是所有具有`app`和`service`标签的 pod，分别具有`pets`和`web`值。

现在我们有了一个`Service`对象的规范，我们可以使用`kubectl`来创建它：

```
$ kubectl create -f web-service.yaml
```

我们可以列出所有的服务来查看前面命令的结果：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/68357689-66d7-4587-97d9-369552a5fe75.png)为 web 组件创建的 Service 对象

在前面的输出中，我们可以看到一个名为`web`的服务已经被创建。为这个服务分配了一个唯一的`clusterIP`为`10.99.99.133`，并且容器端口`3000`已经发布到所有集群节点的端口`31331`上。

如果我们想测试这个部署，我们需要找出 Minikube 的 IP 地址，然后使用这个 IP 地址来访问我们的 web 服务。以下是我们可以用来做这件事的命令：

```
$ IP=$(minikube ip)
$ curl -4 $IP:31331/
Pets Demo Application
```

好的，响应是`Pets Demo Application`，这是我们预期的。web 服务在 Kubernetes 集群中已经启动。接下来，我们要部署数据库。

# 部署数据库

数据库是一个有状态的组件，必须与无状态的组件（如我们的 web 组件）有所不同对待。我们在第九章和第十二章中详细讨论了分布式应用架构中有状态和无状态组件的区别，以及编排器。

Kubernetes 为有状态的组件定义了一种特殊类型的 ReplicaSet 对象。这个对象被称为 StatefulSet。让我们使用这种对象来部署我们的数据库。定义可以在~fod/ch16/db-stateful-set.yaml 文件中找到。详细信息如下：

！[](assets/a0e35643-c85e-4f8d-8e9c-b62a372a42dd.png)DB 组件的 StatefulSet

好的，这看起来有点可怕，但其实并不是。由于我们还需要定义一个卷，让 PostgreSQL 数据库可以存储数据，所以它比 web 组件的部署定义要长一些。卷索赔定义在第 25 到 33 行。我们想要创建一个名为 pets-data 的卷，最大大小为 100MB。在第 22 到 24 行，我们使用这个卷并将其挂载到容器中的/var/lib/postgresql/data 目录，PostgreSQL 期望它在那里。在第 21 行，我们还声明 PostgreSQL 正在 5432 端口监听。

一如既往，我们使用 kubectl 来部署 StatefulSet：

```
$ kubectl create -f db-stateful-set.yaml
```

现在，如果我们列出集群中的所有资源，我们将能够看到已创建的附加对象。

！[](assets/65326383-101f-44f5-a370-5e936b3933fd.png)

StatefulSet 及其 pod

在这里，我们可以看到已经创建了一个 StatefulSet 和一个 pod。对于这两者，当前状态与期望状态相符，因此系统是健康的。但这并不意味着 web 组件此时可以访问数据库。服务发现到目前为止还不起作用。请记住，web 组件希望以 db 的名称访问 db 服务。

为了使服务发现在集群内部工作，我们还必须为数据库组件定义一个 Kubernetes Service 对象。由于数据库只能从集群内部访问，我们需要的 Service 对象类型是 ClusterIP。以下是规范，可以在~/fod/ch16/db-service.yaml 文件中找到：

！[](assets/50834c86-6427-4c33-b811-089547e1aef2.png)数据库的 Kubernetes Service 对象定义

数据库组件将由此 Service 对象表示，并且可以通过名称`db`访问，这是服务的名称，如第 4 行所定义。数据库组件不必是公开访问的，因此我们决定使用 ClusterIP 类型的 Service 对象。第 10 到 12 行的选择器定义了该服务代表具有相应标签的所有 Pod 的稳定端点，即`app: pets`和`service: db`。

让我们使用以下命令部署此服务：

```
$ kubectl create -f db-service.yaml
```

现在，我们应该准备好测试应用程序了。这次我们可以使用浏览器来欣赏美丽的动物图片：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/5a43f3ff-7ac5-4b0e-af24-e2ceb59bf180.png)在 Kubernetes 中运行宠物应用程序的测试

`172.29.64.78`是我的 Minikube 的 IP 地址。使用`minikube ip`命令验证您的地址。端口号`32722`是 Kubernetes 自动为我的`web`服务对象选择的端口号。将此数字替换为 Kubernetes 分配给您的服务的端口。您可以使用`kubectl get services`命令获取该数字。

现在，我们已成功将宠物应用程序部署到了 Minikube，这是一个单节点的 Kubernetes 集群。为此，我们必须定义四个工件，它们如下：

+   Web 组件的 Deployment 和 Service 对象

+   数据库组件的 StatefulSet 和 Service 对象

从集群中删除应用程序，我们可以使用以下小脚本：

```
kubectl delete svc/web
kubectl delete deploy/web
kubectl delete svc/db
kubectl delete statefulset/db
```

接下来，我们将简化部署。

# 简化部署

到目前为止，我们已经创建了四个需要部署到集群的工件。这只是一个非常简单的应用程序，由两个组件组成。想象一下拥有一个更复杂的应用程序。它很快就会变成一个维护的噩梦。幸运的是，我们有几种选项可以简化部署。我们将在这里讨论的方法是在 Kubernetes 中定义构成应用程序的所有组件的可能性在单个文件中。

超出本书范围的其他解决方案可能包括使用 Helm 等软件包管理器。

如果我们的应用程序由许多 Kubernetes 对象（如`Deployment`和`Service`对象）组成，那么我们可以将它们全部放在一个单独的文件中，并通过三个破折号分隔各个对象的定义。例如，如果我们想要在单个文件中为`web`组件定义`Deployment`和`Service`，则如下所示：

```
apiVersion: extensions/v1beta1
kind: Deployment
metadata:
  name: web
spec:
  replicas: 1
  selector:
    matchLabels:
      app: pets
      service: web
  template:
    metadata:
      labels:
        app: pets
        service: web
    spec:
      containers:
      - image: fundamentalsofdocker/ch11-web:2.0
        name: web
        ports:
        - containerPort: 3000
          protocol: TCP
---
apiVersion: v1
kind: Service
metadata:
  name: web
spec:
  type: NodePort
  ports:
  - port: 3000
    protocol: TCP
  selector:
    app: pets
    service: web
```

在这里，我们已经在`~/fod/ch16/pets.yaml`文件中收集了`pets`应用程序的所有四个对象定义，并且我们可以一次性部署该应用程序：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/76a4ab56-40ed-4d1b-b372-5267d4702597.png)使用单个脚本部署宠物应用程序

同样，我们创建了一个名为`~/fod/ch16/remove-pets.sh`的脚本，用于从 Kubernetes 集群中删除宠物应用程序的所有构件：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/5670017a-1e32-4999-8ee1-79d171f3830b.png)从 Kubernetes 集群中删除宠物

通过这种方式，我们已经将我们在第十一章中介绍的宠物应用程序，*Docker Compose*，并定义了部署此应用程序到 Kubernetes 集群所必需的所有 Kubernetes 对象。在每个步骤中，我们确保获得了预期的结果，一旦所有构件存在于集群中，我们展示了运行中的应用程序。

# 定义存活和就绪

诸如 Kubernetes 和 Docker Swarm 之类的容器编排系统大大简化了部署、运行和更新高度分布式、使命关键的应用程序。编排引擎自动化了许多繁琐的任务，如扩展或缩减规模，确保始终保持所需状态等。

但是，编排引擎并不能自动完成所有事情。有时，我们开发人员需要提供一些只有我们才知道的信息来支持引擎。那么，我是什么意思呢？

让我们看一个单个的应用服务。假设它是一个微服务，我们称之为**服务 A**。如果我们在 Kubernetes 集群上容器化运行服务 A，那么 Kubernetes 可以确保我们在服务定义中需要的五个实例始终运行。如果一个实例崩溃，Kubernetes 可以快速启动一个新实例，从而保持所需的状态。但是，如果服务的一个实例并没有崩溃，而是不健康或者还没有准备好提供服务呢？显然，Kubernetes 应该知道这两种情况。但它不能，因为从应用服务的角度来看，健康与否是编排引擎无法知道的。只有我们应用开发人员知道我们的服务何时是健康的，何时不是。

例如，应用服务可能正在运行，但由于某些错误，其内部状态可能已经损坏，它可能陷入无限循环或死锁状态。同样，只有我们应用开发人员知道我们的服务是否准备好工作，或者它是否仍在初始化。虽然建议微服务的初始化阶段尽可能短，但如果某个特定服务需要较长的时间才能准备好运行，通常是无法避免的。处于初始化状态并不等同于不健康。初始化阶段是微服务或任何其他应用服务生命周期的预期部分。

因此，如果我们的微服务处于初始化阶段，Kubernetes 不应该试图终止它。但是，如果我们的微服务不健康，Kubernetes 应该尽快终止它，并用新实例替换它。

Kubernetes 有一个探针的概念，提供编排引擎和应用程序开发人员之间的接口。Kubernetes 使用这些探针来了解正在处理的应用服务的内部状态。探针在每个容器内部本地执行。有一个用于服务健康（也称为活跃性）的探针，一个用于启动的探针，以及一个用于服务就绪的探针。让我们依次来看看它们。

# Kubernetes 活跃性探针

Kubernetes 使用活跃探针来决定何时需要终止一个容器，以及何时应该启动另一个实例。由于 Kubernetes 在 pod 级别操作，如果其至少一个容器报告为不健康，相应的 pod 将被终止。或者，我们可以说反过来：只有当一个 pod 的所有容器报告为健康时，该 pod 才被认为是健康的。

我们可以在 pod 的规范中定义活跃探针如下：

```
apiVersion: v1
kind: Pod
metadata:
 ...
spec:
 containers:
 - name: liveness-demo
 image: postgres:12.10
 ...
 livenessProbe:
 exec:
 command: nc localhost 5432 || exit -1
 initialDelaySeconds: 10
 periodSeconds: 5
```

相关部分在`livenessProbe`部分。首先，我们定义一个命令，Kubernetes 将在容器内部执行作为探针。在我们的例子中，我们有一个 PostresSQL 容器，并使用`netcat` Linux 工具来探测 TCP 端口`5432`。一旦 Postgres 监听到它，`nc localhost 5432`命令就会成功。

另外两个设置，`initialDelaySeconds`和`periodSeconds`，定义了 Kubernetes 在启动容器后应该等待多长时间才首次执行探针，以及之后探针应该以多频率执行。在我们的例子中，Kubernetes 在启动容器后等待 10 秒才执行第一次探针，然后每 5 秒执行一次探针。

也可以探测 HTTP 端点，而不是使用命令。假设我们正在从一个镜像`acme.com/my-api:1.0`运行一个微服务，它有一个名为`/api/health`的端点，如果微服务健康则返回状态`200（OK）`，如果不健康则返回`50x（Error）`。在这里，我们可以定义活跃探针如下：

```
apiVersion: v1
kind: Pod
metadata:
  ...
spec:
  containers:
  - name: liveness
    image: acme.com/my-api:1.0
    ...
    livenessProbe:
 httpGet:
 path: /api/health
 port: 3000
 initialDelaySeconds: 5
 periodSeconds: 3
```

在上面的片段中，我已经定义了活跃探针，以便它使用 HTTP 协议，并在本地主机的端口`5000`上执行`GET`请求到`/api/health`端点。记住，探针是在容器内执行的，这意味着我可以使用本地主机。

我们也可以直接使用 TCP 协议来探测容器上的端口。但等一下，我们刚刚在我们的第一个示例中做过这个，我们使用了基于任意命令的通用活跃探针？是的，你说得对，我们做了。但我们必须依赖容器中`netcat`工具的存在才能这样做。我们不能假设这个工具总是存在。因此，依赖 Kubernetes 来为我们执行基于 TCP 的探测是有利的。修改后的 pod 规范如下：

```
apiVersion: v1kind: Pod
metadata:
 ...
spec:
 containers:
 - name: liveness-demo
   image: postgres:12.10
   ...
 livenessProbe:
 tcpSocket:
 port: 5432
 initialDelaySeconds: 10
 periodSeconds: 5
```

这看起来非常相似。唯一的变化是探针的类型已从`exec`更改为`tcpSocket`，而不是提供一个命令，我们提供了要探测的`port`。

让我们试一试：

1.  转到`~/fod/ch16/probes`文件夹，并使用以下命令构建 Docker 镜像：

```
$ docker image build -t fundamentalsofdocker/probes-demo:2.0 .
```

1.  使用`kubectl`部署在`probes-demo.yaml`中定义的示例 pod：

```
$ kubectl apply -f probes-demo.yaml
```

1.  描述 pod，特别分析输出的日志部分：

```
$ kubectl describe pods/probes-demo
```

在接下来的半分钟左右，你应该会得到以下输出：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/fe42b23f-d21f-4e2a-bd16-6f14c31d71b4.png)

健康 pod 的日志输出

1.  等待至少 30 秒，然后再次描述 pod。这次，你应该看到以下输出：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/bb3c27de-375c-4cf1-8e23-81762ff9447f.png)将 pod 的状态更改为`Unhealthy`后的日志输出

最后两行表明了探针的失败以及 pod 将要重新启动的事实。

如果你获取 pod 列表，你会看到该 pod 已经重新启动了多次：

```
$ kubectl get pods
NAME         READY   STATUS    RESTARTS   AGE
probes-demo  1/1     Running   5          7m22s
```

当你完成示例后，使用以下命令删除 pod：

```
$ kubectl delete pods/probes-demo
```

接下来，我们将看一下 Kubernetes 的就绪探针。

# Kubernetes 就绪探针

Kubernetes 使用就绪探针来决定服务实例（即容器）何时准备好接受流量。现在，我们都知道 Kubernetes 部署和运行的是 pod 而不是容器，因此谈论 pod 的就绪性是有意义的。只有当 pod 中的所有容器报告准备就绪时，pod 才被认为是准备就绪的。如果一个 pod 报告未准备就绪，那么 Kubernetes 会将其从服务负载均衡器中移除。

就绪探针的定义方式与活跃性探针完全相同：只需将 pod 规范中的`livenessProbe`键切换为`readinessProbe`。以下是使用我们之前的 pod 规范的示例：

```
 ...
spec:
 containers:
 - name: liveness-demo
   image: postgres:12.10
   ...
   livenessProbe:
     tcpSocket:
       port: 5432
     failureThreshold: 2
     periodSeconds: 5

   readinessProbe:
 tcpSocket:
 port: 5432
 initialDelaySeconds: 10
 periodSeconds: 5
```

请注意，在这个例子中，我们不再需要活跃性探针的初始延迟，因为现在有了就绪探针。因此，我用一个名为`failureThreshold`的条目替换了活跃性探针的初始延迟条目，该条目指示 Kubernetes 在失败的情况下应重复探测多少次，直到假定容器不健康。

# Kubernetes 启动探针

对于 Kubernetes 来说，了解服务实例何时启动通常是有帮助的。如果我们为容器定义了启动探针，那么只要容器的启动探针不成功，Kubernetes 就不会执行活跃性或就绪性探针。再次强调，Kubernetes 会查看 pod，并且只有当所有 pod 容器的启动探针成功时，才会开始执行活跃性和就绪性探针。

在什么情况下会使用启动探测，考虑到我们已经有了存活性和就绪性探测？可能会出现需要考虑异常长的启动和初始化时间的情况，比如将传统应用程序容器化时。我们可以在技术上配置就绪性或存活性探测来考虑这一事实，但这将违背这些探测的目的。后者的探测旨在为 Kubernetes 提供有关容器健康和可用性的快速反馈。如果我们配置长时间的初始延迟或周期，那么这将抵消预期的结果。

毫不奇怪，启动探测的定义方式与就绪性和存活性探测完全相同。以下是一个例子：

```
spec:
  containers:
    ..
    startupProbe:
 tcpSocket:
 port: 3000
 failureThreshold: 30
 periodSeconds: 5
  ...
```

确保定义`failureThreshold * periodSeconds`产品，以便足够大以考虑最坏的启动时间。

在我们的示例中，最大启动时间不应超过 150 秒。

# 零停机部署

在关键任务环境中，应用程序始终保持运行是非常重要的。如今，我们不能再容忍任何停机时间。Kubernetes 给了我们各种手段来实现这一点。在集群中对应用程序执行不会导致停机的更新称为零停机部署。在本节中，我们将介绍两种实现这一目标的方法。这些方法如下：

+   滚动更新

+   蓝绿部署

让我们从讨论滚动更新开始。

# 滚动更新

在上一章中，我们了解到 Kubernetes 的 Deployment 对象与 ReplicaSet 对象的区别在于它在后者的功能基础上增加了滚动更新和回滚功能。让我们使用我们的 web 组件来演示这一点。显然，我们将不得不修改 web 组件的部署清单或描述。

我们将使用与上一节相同的部署定义，但有一个重要的区别 - 我们将有五个 web 组件的副本在运行。以下定义也可以在`~/fod/ch16/web-deploy-rolling-v1.yaml`文件中找到：

```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  replicas: 5
  selector:
    matchLabels:
      app: pets
      service: web
  template:
    metadata:
      labels:
        app: pets
        service: web
    spec:
      containers:
      - image: fundamentalsofdocker/ch11-web:2.0
        name: web
        ports:
        - containerPort: 3000
          protocol: TCP
```

现在，我们可以像往常一样创建这个部署，同时也创建使我们的组件可访问的服务：

```
$ kubectl create -f web-deploy-rolling-v1.yaml
$ kubectl create -f web-service.yaml
```

一旦我们部署了 pod 和服务，我们可以使用以下命令测试我们的 web 组件：

```
$ PORT=$(kubectl get svc/web -o yaml | grep nodePort | cut -d' ' -f5)
$ IP=$(minikube ip)
$ curl -4 ${IP}:${PORT}/
Pets Demo Application
```

我们可以看到，应用程序正在运行，并返回预期的消息`Pets Demo Application`。

现在，我们的开发人员已经创建了一个新版本 2.1 的`web`组件。新版本的`web`组件的代码可以在`~/fod/ch16/web`文件夹中找到，唯一的更改位于`server.js`文件的第 12 行：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/70fa34d3-69f4-4f3a-a7ae-593b02df74f6.png)Web 组件 2.0 版本的代码更改

开发人员已经按以下方式构建了新的镜像：

```
$ docker image build -t fundamentalsofdocker/ch16-web:2.1 web
```

随后，他们将镜像推送到 Docker Hub，如下所示：

```
$ docker image push fundamentalsofdocker/ch16-web:2.1
```

现在，我们想要更新`web`部署对象中的 pod 所使用的镜像。我们可以使用`kubectl`的`set image`命令来实现这一点：

```
$ kubectl set image deployment/web \
 web=fundamentalsofdocker/ch16-web:2.1
```

如果我们再次测试应用程序，我们将得到一个确认，更新确实已经发生：

```
$ curl -4 ${IP}:${PORT}/
Pets Demo Application v2
```

现在，我们如何知道在此更新过程中没有发生任何停机时间？更新确实是以滚动方式进行的吗？滚动更新到底意味着什么？让我们来调查一下。首先，我们可以通过使用`rollout status`命令从 Kubernetes 那里得到确认，部署确实已经发生并且成功了：

```
$ kubectl rollout status deploy/web
deployment "web" successfully rolled out
```

如果我们用`kubectl describe deploy/web`描述部署 web，我们会在输出的最后得到以下事件列表：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/5fd7c6ba-dbce-4d6e-8d77-f6296c87dc06.png)Web 组件部署描述输出中找到的事件列表

第一个事件告诉我们，在创建部署时，一个名为`web-769b88f67`的 ReplicaSet 被创建，有五个副本。然后，我们执行了更新命令。列表中的第二个事件告诉我们，这意味着创建一个名为`web-55cdf67cd`的新 ReplicaSet，最初只有一个副本。因此，在那个特定的时刻，系统上存在六个 pod：五个初始 pod 和一个具有新版本的 pod。但是，由于部署对象的期望状态指定我们只想要五个副本，Kubernetes 现在将旧的 ReplicaSet 缩减到四个实例，我们可以在第三个事件中看到。

然后，新的 ReplicaSet 再次扩展到两个实例，随后，旧的 ReplicaSet 缩减到三个实例，依此类推，直到我们有了五个新实例，所有旧实例都被废弃。虽然我们无法看到确切的时间（除了 3 分钟），这发生的顺序告诉我们整个更新是以滚动方式进行的。

在短时间内，对 web 服务的一些调用可能会得到来自组件的旧版本的答复，而一些调用可能会得到来自组件的新版本的答复，但是服务从未中断。

我们还可以列出集群中的 ReplicaSet 对象，并确认我在前面部分所说的内容：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/3a04d23d-d8d2-4f3b-a4d2-4235bac45448.png)列出集群中的所有 ReplicaSet 对象

在这里，我们可以看到新的 ReplicaSet 有五个实例在运行，而旧的 ReplicaSet 已被缩减为零个实例。旧的 ReplicaSet 对象仍然存在的原因是 Kubernetes 为我们提供了回滚更新的可能性，在这种情况下，将重用该 ReplicaSet。

为了回滚图像的更新，以防一些未被检测到的错误潜入新代码，我们可以使用`rollout undo`命令：

```
$ kubectl rollout undo deploy/web
deployment "web"
$ curl -4 ${IP}:${PORT}/
Pets Demo Application
```

我还在前面的片段中列出了使用`curl`进行测试的命令，以验证回滚确实发生了。如果我们列出 ReplicaSets，我们将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/7ef8b322-07e3-43e1-81a1-9bd7af4d1a3d.png)回滚后列出 ReplicaSet 对象

这证实了旧的 ReplicaSet（`web-769b88f67`）对象已被重用，新的 ReplicaSet 已被缩减为零个实例。

然而，有时我们不能或不想容忍旧版本与新版本共存的混合状态。我们希望采取“全有或全无”的策略。这就是蓝绿部署发挥作用的地方，接下来我们将讨论这个问题。

# 蓝绿部署

如果我们想要为宠物应用程序的 web 组件执行蓝绿部署，那么我们可以通过创造性地使用标签来实现。首先，让我们回顾一下蓝绿部署的工作原理。以下是一个大致的逐步说明：

1.  部署`web`组件的第一个版本为`blue`。我们将使用`color: blue`标签为 pod 打上标签。

1.  使用`color: blue`标签在选择器部分为这些 pod 部署 Kubernetes 服务。

1.  现在，我们可以部署版本 2 的 web 组件，但是这一次，pod 的标签是`color: green`。

1.  我们可以测试服务的绿色版本，以检查它是否按预期工作。

1.  现在，我们通过更新 web 组件的 Kubernetes 服务，将流量从蓝色切换到绿色。我们修改选择器，使其使用`color: green`标签。

让我们为版本 1（蓝色）定义一个 Deployment 对象：

Web 组件的蓝色部署规范

前面的定义可以在`~/fod/ch16/web-deploy-blue.yaml`文件中找到。请注意第 4 行，我们在那里定义了部署的名称为`web-blue`，以区分它与即将到来的部署`web-green`。还要注意，我们在第 11 行和第 17 行添加了标签`color: blue`。其他一切与以前一样。

现在，我们可以为 Web 组件定义 Service 对象。它将与之前使用的相同，但有一个小改变，如下面的屏幕截图所示：

Kubernetes 服务支持蓝绿部署的 Web 组件

关于我们在本章前面使用的服务定义的唯一区别是第 13 行，它在选择器中添加了`color: blue`标签。我们可以在`~/fod/ch16/web-svc-blue-green.yaml`文件中找到前面的定义。

然后，我们可以使用以下命令部署 Web 组件的蓝色版本：

```
$ kubectl create -f web-deploy-blue.yaml
$ kubectl create -f web-svc-blue-green.yaml
```

一旦服务启动运行，我们可以确定其 IP 地址和端口号并进行测试：

```
$ PORT=$(kubectl get svc/web -o yaml | grep nodePort | cut -d' ' -f5)
$ IP=$(minikube ip)
$ curl -4 ${IP}:${PORT}/
Pets Demo Application
```

正如预期的那样，我们得到了“宠物演示应用程序”的响应。现在，我们可以部署 Web 组件的绿色版本。其部署对象的定义可以在`~/fod/ch16/web-deploy-green.yaml`文件中找到，如下所示：

部署绿色 Web 组件的规范

有趣的行如下：

+   第 4 行：命名为`web-green`以区分它与`web-blue`并允许并行安装

+   第 11 行和第 17 行：颜色为绿色

+   第 20 行：现在使用图像的 2.1 版本

现在，我们准备部署这个绿色版本的服务。它应该与蓝色服务分开运行。

```
$ kubectl create -f web-deploy-green.yaml
```

我们可以确保两个部署共存如下：

显示在集群中运行的部署对象列表

正如预期的那样，蓝色和绿色都在运行。我们可以验证蓝色仍然是活动服务：

```
$ curl -4 ${IP}:${PORT}/
Pets Demo Application
```

现在是有趣的部分。我们可以通过编辑 Web 组件的现有服务将流量从蓝色切换到绿色。为此，请执行以下命令：

```
$ kubectl edit svc/web
```

将标签颜色的值从蓝色更改为绿色。然后保存并退出编辑器。Kubernetes CLI 将自动更新服务。现在再次查询 web 服务时，我们会得到这个：

```
$ curl -4 ${IP}:${PORT}/
Pets Demo Application v2
```

这证实了流量确实已经切换到 web 组件的绿色版本（注意响应`curl`命令末尾的`v2`）。

如果我们意识到我们的绿色部署出了问题，新版本有缺陷，我们可以通过再次编辑服务 web 并将标签颜色的值替换为蓝色，轻松地切换回蓝色版本。这种回滚是瞬时的，应该总是有效的。然后，我们可以移除有问题的绿色部署并修复组件。当我们纠正了问题后，我们可以再次部署绿色版本。

一旦组件的绿色版本按预期运行并表现良好，我们可以停用蓝色版本：

```
$ kubectl delete deploy/web-blue
```

当我们准备部署新版本 3.0 时，这个版本成为蓝色版本。我们相应地更新`~/fod/ch16/web-deploy-blue.yaml`文件并部署它。然后，我们将服务 web 从绿色切换到蓝色，依此类推。

我们已经成功地演示了在 Kubernetes 集群中如何实现蓝绿部署，使用了宠物应用程序的 web 组件。

# Kubernetes 秘密

有时，我们希望在 Kubernetes 集群中运行的服务必须使用诸如密码、秘密 API 密钥或证书等机密数据。我们希望确保这些敏感信息只能被授权或专用服务看到。集群中运行的所有其他服务都不应该访问这些数据。

因此，Kubernetes 引入了秘密。秘密是一个键值对，其中键是秘密的唯一名称，值是实际的敏感数据。秘密存储在 etcd 中。Kubernetes 可以配置为在休息时加密秘密，即在 etcd 中，以及在传输时，即当秘密从主节点传输到运行使用该秘密的服务的工作节点时。

# 手动定义秘密

我们可以像在 Kubernetes 中创建任何其他对象一样，声明性地创建一个秘密。以下是这样一个秘密的 YAML：

```
apiVersion: v1
kind: Secret
metadata:
  name: pets-secret
type: Opaque
data:
  username: am9obi5kb2UK
  password: c0VjcmV0LXBhc1N3MHJECg==
```

前面的定义可以在`~/fod/ch16/pets-secret.yaml`文件中找到。现在，你可能想知道这些值是什么。这些是真实的（未加密）值吗？不，不是。它们也不是真正加密的值，而只是 base64 编码的值。因此，它们并不是真正安全的，因为 base64 编码的值可以很容易地恢复为明文值。我是如何得到这些值的？很简单：按照以下步骤：

1.  使用`base64`工具如下编码值：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/bbd59476-831a-40c9-b69e-96b1cacfe2f1.png)创建秘密的 base64 编码值

1.  使用前面的值，我们可以创建秘密并描述它：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/df5c56b3-47a4-4ad5-9724-dc08beca28e5.png)创建和描述 Kubernetes 秘密

1.  在秘密的描述中，值是隐藏的，只给出了它们的长度。所以，也许现在秘密是安全的？不，不是真的。我们可以很容易地使用`kubectl get`命令解码这个秘密：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/75e781a7-6783-47aa-afe0-d26ff4e7e7b6.png)Kubernetes 秘密解码

正如我们在前面的截图中看到的，我们恢复了我们的原始秘密值。

1.  解码之前获得的值：

```
$ echo "c0VjcmV0LXBhc1N3MHJECg==" | base64 --decode
sEcret-pasSw0rD
```

因此，这种创建 Kubernetes 的方法的后果是不应该在除了开发环境之外的任何环境中使用，我们在那里处理非敏感数据。在所有其他环境中，我们需要更好的方法来处理秘密。

# 使用 kubectl 创建秘密

定义秘密的一个更安全的方法是使用`kubectl`。首先，我们创建包含 base64 编码的秘密值的文件，类似于我们在前面的部分所做的，但是这次，我们将值存储在临时文件中：

```
$ echo "sue-hunter" | base64 > username.txt
$ echo "123abc456def" | base64 > password.txt
```

现在，我们可以使用`kubectl`从这些文件中创建一个秘密，如下所示：

```
$ kubectl create secret generic pets-secret-prod \
 --from-file=./username.txt \
 --from-file=./password.txt
secret "pets-secret-prod" created
```

秘密可以像手动创建的秘密一样使用。

你可能会问，为什么这种方法比另一种方法更安全？首先，没有定义秘密并存储在一些源代码版本控制系统（如 GitHub）中的 YAML，许多人都可以访问并查看和解码秘密。只有被授权知道秘密的管理员才能看到它们的值并直接在（生产）集群中创建秘密。集群本身受基于角色的访问控制的保护，因此未经授权的人员无法访问它，也无法解码集群中定义的秘密。

现在，让我们看看我们如何实际使用我们定义的秘密。

# 在 pod 中使用秘密

假设我们想要创建一个`Deployment`对象，其中`web`组件使用我们在前一节中介绍的秘密`pets-secret`。我们可以使用以下命令在集群中创建秘密：

```
$ kubectl create -f pets-secret.yaml
```

在`~/fod/ch16/web-deploy-secret.yaml`文件中，我们可以找到`Deployment`对象的定义。我们不得不添加从第`23`行开始的部分到`Deployment`对象的原始定义中：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/f52d1a33-412d-4270-8f9c-8bc86346e616.png)带有秘密的 web 组件的部署对象

在第`27`到`30`行，我们定义了一个名为`secrets`的卷，来自我们的秘密`pets-secret`。然后，我们在容器中使用这个卷，如第`23`到`26`行所述。我们在容器文件系统中挂载秘密到`/etc/secrets`，并且以只读模式挂载卷。因此，秘密值将作为文件出现在容器中的文件夹中。文件的名称将对应于键名，文件的内容将是相应键的值。这些值将以未加密的形式提供给容器内运行的应用程序。

在我们的情况下，由于我们在秘密中有`username`和`password`键，我们将在容器文件系统的`/etc/secrets`文件夹中找到两个文件，名为`username`和`password`。`username`文件应包含值`john.doe`，`password`文件应包含值`sEcret-pasSw0rD`。这是确认：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/1c911dec-f905-45e6-adff-8df72c62b729.png)确认秘密在容器内可用

在前面输出的第`1`行，我们`exec`进入 web 组件运行的容器。然后，在第`2`到`5`行，我们列出了`/etc/secrets`文件夹中的文件，最后，在第`6`到`8`行，我们显示了两个文件的内容，毫不奇怪地显示了明文的秘密值。

由于任何语言编写的应用程序都可以读取简单的文件，因此使用秘密的这种机制非常向后兼容。甚至一个老的 Cobol 应用程序也可以从文件系统中读取明文文件。

然而，有时应用程序希望秘密以环境变量的形式可用。让我们看看 Kubernetes 在这种情况下为我们提供了什么。

# 环境变量中的秘密值

假设我们的 web 组件期望在环境变量`PETS_USERNAME`中找到用户名，在`PETS_PASSWORD`中找到密码。如果是这种情况，我们可以修改我们的部署 YAML 文件，使其如下所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/30bcf71f-93a0-4fd9-855c-808380d22767.png)部署映射秘密值到环境变量

在第 23 到 33 行，我们定义了两个环境变量`PETS_USERNAME`和`PETS_PASSWORD`，并将`pets-secret`的相应键值对映射到它们。

请注意，我们不再需要卷；相反，我们直接将`pets-secret`的各个键映射到容器内部有效的相应环境变量中。以下命令序列显示了秘密值确实在容器内部作为相应的环境变量可用：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/e8372fc5-eb69-49c9-be2d-3fe7570f0b74.png)秘密值映射到环境变量

在本节中，我们向您展示了如何在 Kubernetes 集群中定义秘密，并如何在作为部署的一部分运行的容器中使用这些秘密。我们展示了两种在容器内部映射秘密的变体，第一种使用文件，第二种使用环境变量。

# 总结

在本章中，我们学习了如何将应用程序部署到 Kubernetes 集群中，以及如何为该应用程序设置应用程序级别的路由。此外，我们还学习了如何在 Kubernetes 集群中运行的应用程序服务中进行更新而不会造成任何停机时间。最后，我们使用秘密来向运行在集群中的应用程序服务提供敏感信息。

在下一章中，我们将学习有关用于监视在 Kubernetes 集群上运行的单个服务或整个分布式应用程序的不同技术。我们还将学习如何在生产环境中运行的应用程序服务进行故障排除，而不会改变集群或运行服务的集群节点。敬请关注。

# 问题

为了评估你的学习进度，请回答以下问题：

1.  你有一个由两个服务组成的应用程序，第一个是 web API，第二个是一个数据库，比如 Mongo DB。你想将这个应用程序部署到 Kubernetes 集群中。简要解释一下你会如何进行。

1.  描述一下你需要哪些组件才能为你的应用程序建立第 7 层（或应用程序级）路由。

1.  列出实施简单应用服务的蓝绿部署所需的主要步骤。避免过多细节。

1.  您将通过 Kubernetes 秘密向应用服务提供三到四种类型的信息。

1.  Kubernetes 在创建秘密时接受哪些来源的名称。

# 进一步阅读

以下是一些链接，提供了本章讨论的主题的更多信息：

+   执行滚动更新：[`bit.ly/2o2okEQ`](https://bit.ly/2o2okEQ)

+   蓝绿部署：[`bit.ly/2r2IxNJ`](https://bit.ly/2r2IxNJ)

+   Kubernetes 中的秘密：[`bit.ly/2C6hMZF`](https://bit.ly/2C6hMZF)
