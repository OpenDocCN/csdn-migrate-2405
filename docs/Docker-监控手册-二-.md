# Docker 监控手册（二）

> 原文：[`zh.annas-archive.org/md5/90AFB362E78E33672A01E1BE9B0E27CA`](https://zh.annas-archive.org/md5/90AFB362E78E33672A01E1BE9B0E27CA)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：从容器内收集应用程序日志

监控中最容易被忽视的部分之一是应用程序或服务生成的日志文件，例如 NGINX、MySQL、Apache 等。到目前为止，我们已经看过了记录容器中进程的 CPU 和 RAM 利用率的各种方法，现在是时候为日志文件做同样的事情了。

如果您将容器作为牛或鸡运行，那么处理销毁和重新启动容器的问题的方式，无论是手动还是自动，都很重要。虽然这可以解决眼前的问题，但它并不能帮助您追踪问题的根本原因，如果您不知道问题的根本原因，又如何尝试解决它，以便它不再发生。

在本章中，我们将看看如何将运行在容器中的应用程序的日志文件内容传输到中央位置，以便它们可用，即使您必须销毁和替换容器。本章我们将涵盖以下主题：

+   如何查看容器日志？

+   使用 Docker 容器堆栈部署“ELK”堆栈以将日志发送到

+   审查您的日志

+   有哪些第三方选项可用？

# 查看容器日志

与`docker top`命令一样，查看日志的方法非常基本。当您使用`docker logs`命令时，实际上是在查看容器内运行的进程的`STDOUT`和`STDERR`。

### 注意

有关标准流的更多信息，请参阅[`en.wikipedia.org/wiki/Standard_streams`](https://en.wikipedia.org/wiki/Standard_streams)。

如您从以下截图中所见，您所需做的最简单的事情就是运行`docker logs`，然后加上您的容器名称：

![查看容器日志](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/mnt-dkr/img/00059.jpeg)

要在自己的主机上查看此内容，请使用以下命令启动`chapter05`中的 WordPress 安装：

```
cd /monitoring_docker/chapter05/wordpress/
docker-compose up –d
docker logs wordpress_wordpress1_1

```

您可以通过在容器名称之前添加以下标志来扩展`docker logs`命令：

+   `-f`或`--follow`将实时流式传输日志

+   `-t`或`--timestamps`将在每行开头显示时间戳

+   `--tail="5"`将显示最后*x*行

+   `--since="5m00s"`将仅显示最近 5 分钟的条目

使用我们刚刚启动的 WordPress 安装，尝试运行以下命令：

```
docker logs --tail="2" wordpress_wordpress1_1

```

这将显示日志的最后两行，您可以使用以下命令添加时间戳：

```
docker logs --tail="2" –timestamps wordpress_wordpress1_1

```

如下终端输出所示，您还可以将命令串联在一起，形成一个非常基本的查询语言：

![查看容器日志](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/mnt-dkr/img/00060.jpeg)

使用`docker logs`的缺点与使用`docker top`完全相同，即它仅在本地可用，日志仅在容器存在的时间内存在，您可以查看已停止容器的日志，但一旦容器被移除，日志也会被移除。

# ELK Stack

与本书中涵盖的一些技术类似，ELK 堆栈确实值得一本书；事实上，每个构成 ELK 堆栈的元素都有专门的书籍，这些元素包括：

+   Elasticsearch 是一个功能强大的搜索服务器，它是针对现代工作负载开发的。

+   Logstash 位于数据源和 Elasticsearch 服务之间；它实时转换您的数据为 Elasticsearch 可以理解的格式。

+   Kibana 位于您的 Elasticsearch 服务前面，并允许您在功能丰富的基于 Web 的仪表板中查询数据。

ELK 堆栈中有许多组件，为了简化事情，我们将使用一个预构建的堆栈进行测试；但是，您可能不希望在生产中使用此堆栈。

## 启动堆栈

让我们启动一个新的 vagrant 主机来运行 ELK 堆栈：

```
[russ@mac ~]$ cd ~/Documents/Projects/monitoring-docker/vagrant-centos/
[russ@mac ~]$ vagrant up
Bringing machine 'default' up with 'virtualbox' provider...
==> default: Importing base box 'russmckendrick/centos71'...
==> default: Matching MAC address for NAT networking...
==> default: Checking if box 'russmckendrick/centos71' is up to date...

.....

==> default: => Installing docker-engine ...
==> default: => Configuring vagrant user ...
==> default: => Starting docker-engine ...
==> default: => Installing docker-compose ...
==> default: => Finished installation of Docker
[russ@mac ~]$ vagrant ssh

```

现在，我们有一个干净的主机正在运行，我们可以通过运行以下命令来启动堆栈：

```
[vagrant@docker ~]$ cd /monitoring_docker/chapter07/elk/
[vagrant@docker elk]$ docker-compose up -d

```

您可能已经注意到，它不仅仅是下载了一些镜像；发生的事情是：

+   使用官方镜像[`hub.docker.com/_/elasticsearch/`](https://hub.docker.com/_/elasticsearch/)启动了一个 Elasticsearch 容器。

+   使用官方镜像[`hub.docker.com/_/logstash/`](https://hub.docker.com/_/logstash/)启动了一个 Logstash 容器，它还使用我们自己的配置启动，这意味着我们的安装监听来自 Logspout 的日志（稍后会详细介绍）。

+   使用官方镜像[`hub.docker.com/_/kibana/`](https://hub.docker.com/_/kibana/)构建了一个自定义的 Kibana 镜像。它所做的只是添加了一个小脚本，以确保 Kibana 在我们的 Elasticsearch 容器完全启动和运行之前不会启动。然后使用自定义配置文件启动了它。

+   使用来自[`hub.docker.com/r/gliderlabs/logspout/`](https://hub.docker.com/r/gliderlabs/logspout/)的官方镜像构建了一个自定义的 Logspout 容器，然后我们添加了一个自定义模块，以便 Logspout 可以与 Logstash 通信。

一旦`docker-compose`完成构建和启动堆栈，运行`docker-compose ps`时，您应该能够看到以下内容：

![启动堆栈](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/mnt-dkr/img/00061.jpeg)

我们现在的 ELK 堆栈已经运行起来了，您可能已经注意到，有一个额外的容器正在运行并为我们提供 ELK-L 堆栈，那么 Logspout 是什么？

## Logspout

如果我们要启动 Elasticsearch、Logstash 和 Kibana 容器，我们应该有一个正常运行的 ELK 堆栈，但是我们需要做很多配置才能将容器日志输入 Elasticsearch。

自 Docker 1.6 以来，您已经能够配置日志驱动程序，这意味着可以启动一个容器，并让它将其`STDOUT`和`STDERR`发送到 Syslog 服务器，在我们的情况下将是 Logstash；然而，这意味着每次启动容器时都必须添加类似以下选项的内容：

```
--log-driver=syslog --log-opt syslog-address=tcp://elk_logstash_1:5000

```

这就是 Logspout 的作用，它被设计用来通过拦截 Docker 进程收集的消息来收集主机上的所有`STDOUT`和`STDERR`消息，然后将它们路由到我们的 Logstash 实例中，以 Elasticsearch 理解的格式。

就像日志驱动程序一样，它支持开箱即用的 Syslog；然而，有一个第三方模块将输出转换为 Logstash 理解的 JSON。作为我们构建的一部分，我们下载、编译和配置了该模块。

您可以在以下位置了解有关 Logspout 和日志驱动程序的更多信息：

+   官方 Logspout 镜像：[`hub.docker.com/r/gliderlabs/logspout/`](https://hub.docker.com/r/gliderlabs/logspout/)

+   Logspout 项目页面：[`github.com/gliderlabs/logspout`](https://github.com/gliderlabs/logspout)

+   Logspout Logstash 模块：[`github.com/looplab/logspout-logstash`](https://github.com/looplab/logspout-logstash)

+   Docker 1.6 发布说明：[`blog.docker.com/2015/04/docker-release-1-6/`](https://blog.docker.com/2015/04/docker-release-1-6/)

+   Docker 日志驱动程序：[`docs.docker.com/reference/logging/overview/`](https://docs.docker.com/reference/logging/overview/)

## 审查日志

现在，我们的 ELK 正在运行，并且已经有了一种机制，可以将容器生成的所有`STDOUT`和`STDERR`消息流式传输到 Logstash，然后将数据路由到 Elasticsearch。现在是时候在 Kibana 中查看日志了。要访问 Kibana，请在浏览器中输入`http://192.168.33.10:8080/`；当您访问页面时，将要求您**配置索引模式**，默认的索引模式对我们的需求来说是可以的，所以只需点击**创建**按钮。

一旦您这样做，您将看到索引模式的列表，这些直接取自 Logspout 输出，并且您应该注意索引中的以下项目：

+   `docker.name`：容器的名称

+   `docker.id`：完整的容器 ID

+   `docker.image`：用于启动图像的名称

从这里，如果您点击顶部菜单中的**发现**，您将看到类似以下页面的内容：

![审查日志](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/mnt-dkr/img/00062.jpeg)

在屏幕截图中，您将看到我最近启动了 WordPress 堆栈，并且我们一直在整本书中使用它，使用以下命令：

```
[vagrant@docker elk]$ cd /monitoring_docker/chapter05/wordpress/
[vagrant@docker wordpress]$ docker-compose up –d

```

为了让您了解正在记录的内容，这里是从 Elasticseach 获取的运行 WordPress 安装脚本的原始 JSON：

```
{
  "_index": "logstash-2015.10.11",
  "_type": "logs",
  "_id": "AVBW8ewRnBVdqUV1XVOj",
  "_score": null,
  "_source": {
    "message": "172.17.0.11 - - [11/Oct/2015:12:48:26 +0000] \"POST /wp-admin/install.php?step=1 HTTP/1.1\" 200 2472 \"http://192.168.33.10/wp-admin/install.php\" \"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11) AppleWebKit/601.1.56 (KHTML, like Gecko) Version/9.0 Safari/601.1.56\"",
    "docker.name": "/wordpress_wordpress1_1",
    "docker.id": "0ba42876867f738b9da0b9e3adbb1f0f8044b7385ce9b3a8a3b9ec60d9f5436c",
    "docker.image": "wordpress",
    "docker.hostname": "0ba42876867f",
    "@version": "1",
    "@timestamp": "2015-10-11T12:48:26.641Z",
    "host": "172.17.0.4"
  },
  "fields": {
    "@timestamp": [
      1444567706641
    ]
  },
  "sort": [
    1444567706641
  ]
}
```

从这里，您可以开始使用自由文本搜索框，并构建一些相当复杂的查询，以深入了解容器的`STDOUT`和`STDERR`日志。

## 生产环境怎么样？

如本节顶部所述，您可能不希望使用附带本章的`docker-compose`文件来运行生产 ELK 堆栈。首先，您希望将 Elasticsearch 数据存储在持久卷上，并且很可能希望您的 Logstash 服务具有高可用性。

有许多指南可以指导您如何配置高可用性 ELK 堆栈，以及 Elastic 的托管服务，Elasticsearch 的创建者，以及亚马逊 Web 服务，该服务提供 Elasticsearch 服务：

+   ELK 教程：[`www.youtube.com/watch?v=ge8uHdmtb1M`](https://www.youtube.com/watch?v=ge8uHdmtb1M)

+   从 Elastic 发现：[`www.elastic.co/found`](https://www.elastic.co/found)

+   亚马逊 Elasticsearch 服务：[`aws.amazon.com/elasticsearch-service/`](https://aws.amazon.com/elasticsearch-service/)

# 查看第三方选项

在为容器托管的中央日志记录提供托管时，有一些选项。其中一些是：

+   日志条目：[`logentries.com/`](https://logentries.com/)

+   Loggly：[`www.loggly.com/`](https://www.loggly.com/)

这两项服务都提供免费套餐。Log Entries 还提供了一个“Logentries DockerFree”账户，你可以在[`logentries.com/docker/`](https://logentries.com/docker/)了解更多信息。

### 注意

如*探索第三方选项*章节所建议的，在评估第三方服务时最好使用云服务。本章的其余部分假设你正在运行云主机。

让我们来看看如何在外部服务器上配置日志条目，首先你需要在[`logentries.com/`](https://logentries.com/)注册一个账户。注册完成后，你会被带到一个页面，你的日志最终会在这里显示。

首先，点击页面右上角的**添加新日志**按钮，然后点击**平台**部分的 Docker 标志。

你必须在**选择集**部分为你的日志集命名。现在你可以选择使用来自[`github.com/logentries/docker-logentries`](https://github.com/logentries/docker-logentries)的 Docker 文件来本地构建你自己的容器：

```
git clone https://github.com/logentries/docker-logentries.git
cd docker-logentries
docker build -t docker-logentries .

```

运行上述命令后，你会得到以下输出：

![查看第三方选项](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/mnt-dkr/img/00063.jpeg)

在启动容器之前，你需要通过点击**生成日志令牌**来生成日志集的访问令牌。一旦你拥有了这个令牌，你可以使用以下命令启动本地构建的容器（用你刚生成的令牌替换原来的令牌）：

```
docker run -d -v /var/run/docker.sock:/var/run/docker.sock docker-logentries -t wn5AYlh-jRhgn3shc-jW14y3yO-T09WsF7d -j

```

你可以通过运行以下命令直接从 Docker hub 下载镜像：

```
docker run -d -v /var/run/docker.sock:/var/run/docker.sock logentries/docker-logentries -t wn5AYlh-jRhgn3shc-jW14y3yO-T09WsF7d –j

```

值得指出的是，Log Entries 自动生成的指令会在前台启动容器，而不是像前面的指令那样在启动后与容器分离。

一旦你的`docker-logentries`容器启动并运行，你应该开始实时看到来自容器的日志流到你的仪表板上：

![查看第三方选项](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/mnt-dkr/img/00064.jpeg)

从这里，你可以查询你的日志，创建仪表板，并根据你选择的账户选项创建警报。

# 摘要

在本章中，我们已经介绍了如何使用 Docker 内置工具查询容器的`STDOUT`和`STDERR`输出，如何将消息发送到外部源，我们的 ELK 堆栈，以及如何在容器终止后仍存储消息。最后，我们还看了一些第三方服务，它们提供服务，您可以将日志流式传输到这些服务。

为什么要付出这么多努力呢？监控不仅仅是为了保持和查询 CPU、RAM、HDD 和网络利用率指标；如果您在一个小时前知道有 CPU 峰值，但在那个时候没有访问日志文件来查看是否生成了任何错误，那就没有意义。

本章涵盖的服务为我们提供了对可能迅速变得复杂的数据集的最快速和最有效的洞察。

在下一章中，我们将研究本书涵盖的所有服务和概念，并将它们应用到一些真实场景中。


# 第八章：下一步是什么？

在这最后一章中，我们将探讨您可以采取的监视容器的下一步措施，讨论将警报添加到您的监视中的好处。此外，我们还将涵盖一些不同的场景，以及哪种类型的监视适用于其中的每种情况：

+   常见问题（性能、可用性等）以及哪种类型的监视最适合您的情况。

+   您正在收集的指标上发出警报的好处是什么，有哪些选项？

# 一些场景

查看您可能想要为基于容器的应用程序实施哪种类型的监视，我们应该通过一些不同的示例配置来了解您的基于容器的应用程序可能部署的情况。首先，让我们提醒自己关于宠物、牛、鸡和雪花。

## 宠物、牛、鸡和雪花

回到第一章*Docker 监视简介*，在那一章中，我们谈到了宠物、牛、鸡和雪花；在那一章中，我们描述了这些术语在现代云部署中的含义。在这里，我们将更详细地讨论这些术语如何适用于您的容器。

### 宠物

要将您的容器视为宠物，您很可能会在指定的主机上运行单个或少量固定容器。

这些容器中的每一个都可以被视为单点故障；如果它们中的任何一个出现问题，很可能会导致应用程序出现错误。更糟糕的是，如果主机出现任何问题，您的整个应用程序将处于离线状态。

这是我们在 Docker 的最初步骤中的典型部署方法，绝不应该被视为不好、不受欢迎或不推荐；只要您意识到了限制，您就会没问题。

这种模式也可以用来描述大多数开发环境，因为您不断地审查其健康状况并根据需要进行调整。

您很可能会在本地计算机上或在 DigitalOcean（[`www.digitalocean.com/`](https://www.digitalocean.com/)）等托管服务上托管该机器。

### 牛

对于大部分生产或业务关键的部署，你应该在一个允许它们在故障后自动恢复，或者在需要更多容量时启动额外容器并在扩展事件结束时终止它们的配置中启动你的容器。

你很可能会使用以下公共云服务：

+   亚马逊 EC2 容器服务: [`aws.amazon.com/ecs/`](https://aws.amazon.com/ecs/)

+   Google 容器引擎: [`cloud.google.com/container-engine/`](https://cloud.google.com/container-engine/)

+   Joyent Triton: [`www.joyent.com/blog/understanding-triton-containers/`](https://www.joyent.com/blog/understanding-triton-containers/)

或者，你将在自己的服务器上托管，使用一个友好于 Docker 并且具有集群意识的操作系统，如下：

+   CoreOS: [`coreos.com/`](https://coreos.com/)

+   RancherOS: [`rancher.com/rancher-os/`](http://rancher.com/rancher-os/)

你不会太在乎容器在主机集群中的启动位置，只要你能将流量路由到它。为了增加集群的容量，当需要时你将启动额外的主机，并在不需要时将它们从集群中移除以节省成本。

### 鸡

很可能你会使用容器来启动、处理数据，然后终止。这可能随时发生，从每天一次到每分钟几次。你将使用分布式调度器如下：

+   Google 的 Kubernetes: [`kubernetes.io/`](http://kubernetes.io/)

+   Apache Mesos: [`mesos.apache.org/`](http://mesos.apache.org/)

因此，你将在你的集群中启动和终止大量的容器；你绝对不会在乎容器在哪里启动，甚至不会在乎流量如何路由到它，只要你的数据被正确处理并传递回你的应用程序。

就像“牛”部分描述的集群一样，主机将会自动添加和删除，可能是为了响应计划内的高峰，比如月末报告或季节性销售等。

### 雪花

我希望你从第一章中得到的一个观点是，如果你有任何你认为是雪花的服务器或服务，那么你应该尽快采取措施将它们退役。

幸运的是，由于应用程序容器化的方式，您永远不应该能够使用 Docker 创建 Snowflake，因为您的容器化环境应始终是可重现的，要么是因为您有 Docker 文件（每个人都会备份，对吧？），要么是因为您已经使用内置工具将容器作为整体导出为工作副本。

### 注意

有时可能无法使用 Docker 文件创建容器。相反，您可以使用导出命令备份或迁移容器。有关导出容器的更多信息，请参阅以下网址：

[`docs.docker.com/reference/commandline/export/`](https://docs.docker.com/reference/commandline/export/)

如果您发现自己处于这种位置，请让我第一个祝贺您通过将您的 Snowflake 提升为宠物甚至是牲畜，从而在任何问题出现之前减轻了未来的灾难。

### 提示

**仍在运行 Snowflake 吗？**

如果您发现自己仍在运行 Snowflake 服务器或服务，我再次强调，您应尽快查看文档、迁移或更新 Snowflake。监视可能无法恢复的服务是没有意义的。请记住，如果您确实需要运行它们，旧技术（如 PHP4）也有容器。

## 情景一

您正在使用 Docker Hub 上的官方容器运行个人 WordPress 网站；容器是使用类似于我们在本书中多次使用的 Docker Compose 文件启动的。

您将 Docker Compose 文件存储在 GitHub 存储库中，并且可以对主机机器进行快照作为备份。由于这是您自己的博客，因此在单个基于云的主机上运行它是可以的。

适当的监控将如下所示：

+   Docker stats

+   Docker top

+   Docker 日志

+   cAdvisor

+   Sysdig

由于您正在运行一个将其视为备份的单个主机，因此您无需将日志文件发送到中央位置，因为您的主机机器的运行时间可能会达到数月甚至数年，就像容器一样。

很可能您不需要深入了解容器的历史性能统计数据，因为大多数调整和故障排除将在实时发生问题时进行。

使用建议的监控工具，您将能够实时了解容器内发生的情况，并获得关于消耗过多 RAM 和 CPU 的进程以及容器内的任何错误消息的充分信息。

您可能希望启用像 Pingdom（https://www.pingdom.com/）或 Uptime Robot（http://uptimerobot.com/）这样的服务。这些服务每隔几分钟轮询您的网站，以确保您为其配置的 URL 在特定时间内或完全加载。如果它们检测到页面加载速度变慢或失败，它们可以配置为发送初始警报，以通知您存在潜在问题，例如上述两项服务都有免费套餐。

## 情景二

您正在运行一个需要高可用性并且在高峰时期需要扩展的自定义电子商务应用程序。您正在使用公共云服务及其工具集来启动容器并将流量路由到它们。

适当的监控将如下所示：

+   cAdvisor + Prometheus

+   Zabbix

+   Sysdig Cloud

+   新的遗产服务器监控

+   Datadog

+   ELK + Logspout

+   Log Entries

+   Loggly

在这种情况下，不仅需要通知容器和主机故障，还需要将监控数据和日志保存在远离主机服务器的地方，以便您可以正确地查看历史信息。您可能还需要保留一段固定时间的日志以符合 PCI 合规性或内部审计要求。

根据您的预算，您可以在基础设施的某个地方托管自己的监控（Zabbix 和 Prometheus）和中央日志（ELK）堆栈。

您还可以选择运行一些不同的第三方工具，例如结合监控性能的工具，例如 Sysdig Cloud 或 Datadog，以及中央日志服务，例如 Log Entries 或 Loggly。

如果适用，您还可以运行自托管和第三方工具的组合。

虽然自托管选项可能看起来是最符合预算的选择，但还有一些需要考虑的因素，如下所示：

+   您的监控需要远离您的应用程序。在与应用程序相同的主机上安装监控是没有意义的；如果主机失败，谁会通知您呢？

+   你的监控需要高可用性；你有这样的基础设施吗？如果你的应用程序需要高可用性，那么你的监控也需要。

+   你需要有足够的容量。你有足够的容量来存储一个月、六个月或一年的日志文件和指标吗？

如果你将不得不投资于前述任何选项，那么权衡投资于基础设施和自己的监控解决方案管理成本与使用第三方服务提供前述选项的成本将是值得的。

如果你正在使用诸如 CoreOS 或 RancherOS 之类的仅容器操作系统，那么你将需要选择一个服务，其代理或收集器可以在容器内执行，因为你将无法直接在操作系统上安装代理二进制文件。

你还需要确保你的主机配置为在启动时启动代理/收集器。这将确保一旦主机加入集群（通常是容器开始在主机上弹出时），它已经向你选择的监控服务发送指标。

## 情景三

每次从前端应用程序调用 API 时，你的应用程序会启动一个容器；容器会从数据库中获取用户输入，处理它，然后将结果返回给前端应用程序。一旦数据被成功处理，容器就会被终止。你正在使用分布式调度系统来启动这些容器。

适当的监控将如下所示：

+   Zabbix

+   Sysdig Cloud

+   Datadog

+   ELK + Logspout

+   Log Entries

+   Loggly

在这种情况下，你很可能不想监控诸如 CPU 和内存利用率之类的东西。毕竟，这些容器只会存在几分钟，而且你的调度器将在有足够容量执行任务的主机上启动容器。

相反，你可能会想要保留一份记录，以验证容器是否按预期启动和终止。你还需要确保在容器处于活动状态时记录`STDOUT`和`STDERR`，因为一旦容器被终止，你将无法再获取这些消息。

通过前面列出的工具，你应该能够构建一些非常有用的查询，以深入了解你的短期进程的性能。

例如，你将能够获得容器的平均生命周期，因为你知道容器启动和终止的时间；知道这一点将允许你设置触发器，如果任何容器的存在时间超出你预期的时间，就会收到警报。

# 关于警报的更多信息

本书中我们看过的很多工具都提供了基本的警报功能；百万美元的问题是你应该启用它吗？

很大程度上取决于你运行的应用程序的类型以及容器的部署方式。正如我们在本章中已经多次提到的，你不应该真的有一个雪花容器；这让我们剩下了宠物、牛和鸡。

## 鸡

正如前一节已经讨论过的，你可能不需要担心在配置为运行鸡的集群上收到关于 RAM、CPU 和硬盘性能的警报。

你的容器不应该运行足够长的时间来遇到任何真正的问题；然而，如果出现任何意外的波动，你的调度器可能会有足够的智能来将你的容器分配到那些在那个时候有最多可用资源的主机上。

你需要知道你的任何容器是否运行时间超过你预期的时间；例如，一个容器中的进程通常不会超过 60 秒，但在 5 分钟后仍在运行。

这不仅意味着存在潜在问题，也意味着你发现自己在运行只包含过时容器的主机。

## 牛和宠物

在设置牛或宠物的警报时，你有几个选项。

你很可能希望基于主机机器和容器的 CPU 和 RAM 利用率收到警报，因为这可能表明潜在问题，可能导致应用程序减速和业务损失。

如前所述，如果你的应用程序开始提供意外的内容，你可能也希望收到警报。例如，主机和容器可能会愉快地提供应用程序错误。

你可以使用 Pingdom、Zabbix 或 New Relic 等服务加载页面并检查页脚中的内容；如果缺少这些内容，就会发送警报。

根据您的基础架构的灵活性，在 Cattle 配置中，您可能希望在容器启动和关闭时收到警报，因为这将表明高流量/交易期间。

## 发送警报

发送警报对于每个工具都有所不同，例如，警报可以简单地发送电子邮件通知您存在问题，也可以在容器的 CPU 负载超过五或主机负载超过 10 时，在**网络运营中心**（**NOC**）发出听得见的警报。

对于那些需要警报的人，我们所涵盖的大多数软件都具有某种程度的集成警报聚合服务，例如 PagerDuty（[`www.pagerduty.com`](https://www.pagerduty.com)）。

这些聚合服务要么拦截您的警报电子邮件，要么允许服务向它们发出 API 调用。当触发时，它们可以配置为打电话、发送短信，甚至在可定义的时间内未标记警报时升级到次要的值班技术员。

我想不出任何情况，您不应该考虑启用警报，毕竟最好在最终用户之前了解可能影响您的应用程序的任何事情。

您启用多少警报实际上取决于您使用容器的用途；然而，我建议您定期审查所有警报，并积极调整您的配置。

您不希望出现产生太多误报或太过敏感的配置，因为您不希望接收您的警报的团队对您生成的警报产生麻木不仁的感觉。

例如，如果由于定期作业而每 30 分钟触发一次关键 CPU 警报，那么您可能需要审查警报的敏感性，否则工程师很容易会简单地忽略关键警报而不加思考地认为“这个警报每半小时就会好，几分钟就没事了”，而您的整个应用程序可能会无响应。

# 跟进

虽然 Docker 是建立在诸如**Linux 容器**（**LXC**）之类的成熟技术之上的，但这些技术传统上很难配置和管理，特别是对于非系统管理员来说。

Docker 几乎消除了所有的入门障碍，使得每个有一点命令行经验的人都能够启动和管理自己基于容器的应用程序。

这迫使许多支持工具也降低了他们的准入门槛。一些以前需要仔细规划才能部署的软件，比如我们在本书中介绍的一些监控工具，现在可以在几分钟内部署和配置，而不是几个小时。

Docker 也是一种发展迅速的技术；虽然它已经被认为是生产就绪的一段时间了，但新功能正在不断增加，并且现有功能也在定期更新中得到改进。

到目前为止，在 2015 年，Docker Engine 已经发布了 11 个版本；其中只有六个是修复错误的次要更新，其余的都是主要更新。每个版本的详细信息可以在项目的 Changelog 中找到，网址为[`github.com/docker/docker/blob/master/CHANGELOG.md`](https://github.com/docker/docker/blob/master/CHANGELOG.md)。

由于 Docker 的快速发展，重要的是您也要更新您部署的任何监控工具。这不仅是为了跟上新功能，还要确保您不会因 Docker 工作方式的变化而丢失任何功能。

更新监控客户端/工具的这种态度对于一些管理员来说可能有点变化，以前他们可能会在服务器上配置一个监控代理，然后就不再考虑它了。

# 总结

正如本章所讨论的，Docker 是一种发展迅速的技术。在本书生产期间，从 1.7 到 1.9 已经发布了三个主要版本；随着每个版本的发布，Docker 变得更加稳定和强大。

在本章中，我们已经看到了实施前几章讨论过的技术的不同方法。到目前为止，您应该已经有了一个合适的方法来监控您的容器和主机，无论是针对您的应用程序还是使用 Docker 部署应用程序的方式。

无论您选择采取哪种方法，重要的是您要及时了解 Docker 的发展以及新的监控技术，以下链接是保持自己信息化的好起点：

+   Docker 工程博客：[`blog.docker.com/category/engineering/`](http://blog.docker.com/category/engineering/)

+   Docker 的 Twitter 账号：[`twitter.com/docker`](https://twitter.com/docker)

+   Docker 的 Reddit 页面：[`www.reddit.com/r/docker`](https://www.reddit.com/r/docker)

+   Docker 在 Stack Overflow 上：[`stackoverflow.com/questions/tagged/docker`](http://stackoverflow.com/questions/tagged/docker)

Docker 项目受到开发人员、系统管理员甚至企业公司的欢迎的原因之一是，它能够以快速的速度前进，同时增加更多功能，并非常令人印象深刻地保持其易用性和灵活性。

在接下来的 12 个月里，这项技术将变得更加普遍；确保您从容器中捕获有用的性能指标和日志的重要性将变得更加关键，我希望这本书能帮助您开始监控 Docker 的旅程。
