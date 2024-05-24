# Kubernetes 开发指南（三）

> 原文：[`zh.annas-archive.org/md5/DCD16B633B67524B76A687C2FBCAAD70`](https://zh.annas-archive.org/md5/DCD16B633B67524B76A687C2FBCAAD70)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：监控和指标

在之前的章节中，我们调查了 Kubernetes 对象和资源中使用的声明性结构。以 Kubernetes 帮助我们运行软件为最终目标，在本章中，我们将看看在更大规模运行应用程序时，如何获取更多信息，以及我们可以用于此目的的一些开源工具。Kubernetes 已经在收集和使用有关集群节点利用情况的一些信息，并且在 Kubernetes 内部有越来越多的能力开始收集特定于应用程序的指标，甚至使用这些指标作为管理软件的控制点。

在本章中，我们将深入探讨基本可观察性的这些方面，并介绍如何为您的本地开发使用设置它们，以及如何利用它们来收集、聚合和公开软件运行的详细信息，当您扩展它时。本章的主题将包括：

+   内置指标与 Kubernetes

+   Kubernetes 概念-服务质量

+   使用 Prometheus 捕获指标

+   安装和使用 Grafana

+   使用 Prometheus 查看应用程序指标

# 内置指标与 Kubernetes

Kubernetes 内置了一些基本的仪表来了解集群中每个节点消耗了多少 CPU 和内存。确切地捕获了什么以及如何捕获它在最近的 Kubernetes 版本（1.5 到 1.9）中正在迅速发展。许多 Kubernetes 安装将捕获有关底层容器使用的资源的信息，使用一个名为 cAdvisor 的程序。这段代码是由 Google 创建的，用于收集、聚合和公开容器的操作指标，作为能够知道最佳放置新容器的关键步骤，基于节点的资源和资源可用性。

Kubernetes 集群中的每个节点都将运行并收集信息的 cAdvisor，并且这反过来又被*kubelet*使用，这是每个节点上负责启动、停止和管理运行容器所需的各种资源的本地代理。

cAdvisor 提供了一个简单的基于 Web 的 UI，您可以手动查看任何节点的详细信息。如果您可以访问节点的端口`4194`，那么这是默认位置，可以公开 cAdvisor 的详细信息。根据您的集群设置，这可能不容易访问。在使用 Minikube 的情况下，它很容易直接可用。

如果您已安装并运行 Minikube，可以使用以下命令：

```
minikube ip
```

获取运行单节点 Kubernetes 集群的开发机器上虚拟机的 IP 地址，可以访问运行的 cAdvisor，然后在浏览器中导航到该 IP 地址的`4194`端口。例如，在运行 Minikube 的 macOS 上，您可以使用以下命令：

```
open http://$(minikube ip):4194/
```

然后您将看到一个简单的 UI，显示类似于这样的页面：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-dev/img/07b5bff8-6ca7-4575-95f9-453e7e300d7e.png)

向下滚动一点，您将看到一些仪表和信息表：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-dev/img/1385db01-d5e4-46dd-b882-9904088ced18.png)

下面是一组简单的图表，显示了 CPU、内存、网络和文件系统的使用情况。这些图表和表格将在您观看时更新和自动刷新，并代表了 Kubernetes 正在捕获的有关集群的基本信息。

Kubernetes 还通过其自己的 API 提供有关自身（其 API 服务器和相关组件）的指标。在通过`kubectl`代理使 API 可用后，您可以使用`curl`命令直接查看这些指标：

```
kubectl proxy
```

并在单独的终端窗口中：

```
curl http://127.0.0.1:8001/metrics
```

许多 Kubernetes 的安装都使用一个叫做 Heapster 的程序来从 Kubernetes 和每个节点的 cAdvisor 实例中收集指标，并将它们存储在诸如 InfluxDB 之类的时间序列数据库中。从 Kubernetes 1.9 开始，这个开源项目正在从 Heapster 进一步转向可插拔的解决方案，常见的替代方案是 Prometheus，它经常用于短期指标捕获。

如果您正在使用 Minikube，可以使用`minikube`插件轻松将 Heapster 添加到本地环境中。与仪表板一样，这将在其自己的基础设施上运行 Kubernetes 的软件，这种情况下是 Heapster、InfluxDB 和 Grafana。

这将在 Minikube 中启用插件，您可以使用以下命令：

```
minikube addons enable heapster
heapster was successfully enabled
```

在后台，Minikube 将启动并配置 Heapster、InfluxDB 和 Grafana，并将其创建为一个服务。您可以使用以下命令：

```
minikube addons open heapster
```

这将打开一个到 Grafana 的浏览器窗口。该命令将在设置容器时等待，但当服务端点可用时，它将打开一个浏览器窗口：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-dev/img/c588d346-eee6-4972-84bb-a6d7559cb24d.png)

Grafana 是一个用于显示图表和从常见数据源构建仪表板的单页面应用程序。在 Minikube Heapster 附加组件创建的版本中，Grafana 配置了两个仪表板：集群和 Pods。如果在默认视图中选择标记为“主页”的下拉菜单，您可以选择其他仪表板进行查看。

在 Heapster、InfluxDB 和 Grafana 协调收集和捕获环境的一些基本指标之前，可能需要一两分钟，但相当快地，您可以转到其他仪表板查看正在运行的信息。例如，我在本书的前几章中部署了所有示例应用程序，并转到了集群仪表板，大约 10 分钟后，视图看起来像这样：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-dev/img/08832507-6a28-453a-b701-7623903350b0.png)

通过仪表板向下滚动，您将看到节点的 CPU、内存、文件系统和网络使用情况，以及整个集群的视图。您可能会注意到 CPU 图表有三条线被跟踪——使用情况、限制和请求——它们与实际使用的资源、请求的数量以及对 pod 和容器设置的任何限制相匹配。

如果切换到 Pods 仪表板，您将看到该仪表板中有当前在集群中运行的所有 pod 的选择，并提供每个 pod 的详细视图。在这里显示的示例中，我选择了我们部署的`flask`示例应用程序的 pod：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-dev/img/ee592f34-3aa0-4a4f-95e9-6573b8a6c755.png)

向下滚动，您可以看到包括内存、CPU、网络和磁盘利用率在内的图表。Heapster、Grafana 和 InfluxDB 的集合将自动记录您创建的新 pod，并且您可以在 Pods 仪表板中选择命名空间和 pod 名称。

# Kubernetes 概念-服务质量

当在 Kubernetes 中创建一个 pod 时，它也被分配了一个服务质量类，这是基于请求时提供的有关 pod 的数据。这在调度过程中提供了一些前期保证，并在后续管理 pod 本身时使用。支持的三种类别是：

+   `保证`

+   `可突发`

+   `最佳努力`

分配给您的 Pod 的类别是基于您在 Pod 内的容器中报告的 CPU 和内存利用率的资源限制和请求。在先前的示例中，没有一个容器被分配请求或限制，因此当它们运行时，所有这些 Pod 都被分类为`BestEffort`。

资源请求和限制在 Pod 内的每个容器上进行定义。如果我们为容器添加请求，我们要求 Kubernetes 确保集群具有足够的资源来运行我们的 Pod（内存、CPU 或两者），并且它将作为调度的一部分验证可用性。如果我们添加限制，我们要求 Kubernetes 监视 Pod，并在容器超出我们设置的限制时做出反应。对于限制，如果容器尝试超出 CPU 限制，容器将被简单地限制到定义的 CPU 限制。如果超出了内存限制，容器将经常被终止，并且您可能会在终止的容器的`reason`描述中看到错误消息`OOM killed`。

如果设置了请求，Pod 通常被设置为“可突发”的服务类别，但有一个例外，即当同时设置了限制，并且该限制的值与请求相同时，将分配“保证”服务类别。作为调度的一部分，如果 Pod 被认为属于“保证”服务类别，Kubernetes 将在集群内保留资源，并且在超载时，会倾向于首先终止和驱逐`BestEffort`容器，然后是“可突发”容器。集群通常需要预期会失去资源容量（例如，一个或多个节点失败）。在这些情况下，一旦将“保证”类别的 Pod 调度到集群中，它将在面对此类故障时具有最长的寿命。

我们可以更新我们的`flask`示例 Pod，以便它将以“保证”的服务质量运行，方法是为 CPU 和内存都添加请求和限制：

```
 spec: containers: - name: flask image: quay.io/kubernetes-for-developers/flask:0.4.0 resources: limits: memory: "100Mi" cpu: "500m" requests: memory: "100Mi" cpu: "500m"
```

这为 CPU 和内存都设置了相同值的请求和限制，例如，100 MB 的内存和大约半个核心的 CPU 利用率。

通常认为，在生产模式下运行的所有容器和 Pod，至少应该定义请求，并在最理想的情况下也定义限制，这被认为是最佳实践。

# 为您的容器选择请求和限制

如果您不确定要使用哪些值来设置容器的请求和/或限制，确定这些值的最佳方法是观察它们。使用 Heapster、Prometheus 和 Grafana，您可以看到每个 pod 消耗了多少资源。

有一个三步过程，您可以使用您的代码来查看它所占用的资源：

1.  运行您的代码并查看空闲时消耗了多少资源

1.  为您的代码添加负载并验证负载下的资源消耗

1.  设置了约束条件后，再运行一个持续一段时间的负载测试，以确保您的代码符合定义的边界

第一步（空闲时审查）将为您提供一个良好的起点。利用 Grafana，或者利用您集群节点上可用的 cAdvisor，并简单地部署相关的 pod。在前面的示例中，我们在本书的早期示例中使用 `flask` 示例进行了这样的操作，您可以看到一个空闲的 flask 应用程序大约消耗了 3 毫核（.003% 的核心）和大约 35 MB 的 RAM。这为请求 CPU 和内存提供了一个预期值。

第二步通常最好通过运行**逐渐增加的负载测试**（也称为**坡道负载测试**）来查看您的 pod 在负载下的反应。通常，您会看到负载随请求线性增加，然后产生一个弯曲或拐点，开始变得瓶颈。您可以查看相同的 Grafana 或 cAdvisor 面板，以显示负载期间的利用率。

如果您想生成一些简单的负载，可以使用诸如 Apache benchmark（[`httpd.apache.org/docs/2.4/programs/ab.html`](https://httpd.apache.org/docs/2.4/programs/ab.html)）之类的工具生成一些特定的负载点。例如，要运行一个与 Flask 应用程序配合使用的交互式容器，可以使用以下命令：

```
kubectl run -it --rm --restart=Never \
--image=quay.io/kubernetes-for-developers/ab quicktest -- sh
```

此镜像已安装了 `curl` 和 `ab`，因此您可以使用此命令验证您是否可以与我们在早期示例中创建的 Flask 服务进行通信：

```
curl -v http://flask-service.default:5000/
```

这应该返回一些冗长的输出，显示连接和基本请求如下：

```
* Trying 10.104.90.234...
* TCP_NODELAY set
* Connected to flask-service.default (10.104.90.234) port 5000 (#0)
> GET / HTTP/1.1
> Host: flask-service.default:5000
> User-Agent: curl/7.57.0
> Accept: */*
>
* HTTP 1.0, assume close after body
< HTTP/1.0 200 OK
< Content-Type: text/html; charset=utf-8
< Content-Length: 10
< Server: Werkzeug/0.13 Python/3.6.3
< Date: Mon, 08 Jan 2018 02:22:26 GMT
<
* Closing connection 0
```

一旦您验证了一切都按您的预期运行，您可以使用 `ab` 运行一些负载：

```
ab -c 100 -n 5000 http://flask-service.default:5000/ 
This is ApacheBench, Version 2.3 <$Revision: 1807734 $>
Copyright 1996 Adam Twiss, Zeus Technology Ltd, http://www.zeustech.net/
Licensed to The Apache Software Foundation, http://www.apache.org/

Benchmarking flask-service.default (be patient)
Completed 500 requests
Completed 1000 requests
Completed 1500 requests
Completed 2000 requests
Completed 2500 requests
Completed 3000 requests
Completed 3500 requests
Completed 4000 requests
Completed 4500 requests
Completed 5000 requests
Finished 5000 requests
Server Software: Werkzeug/0.13 Server Hostname: flask-service.default
Server Port: 5000
Document Path: /
Document Length: 10 bytes
Concurrency Level: 100
Time taken for tests: 3.454 seconds
Complete requests: 5000
Failed requests: 0
Total transferred: 810000 bytes
HTML transferred: 50000 bytes
Requests per second: 1447.75 [#/sec] (mean)
Time per request: 69.072 [ms] (mean)
Time per request: 0.691 [ms] (mean, across all concurrent requests)
Transfer rate: 229.04 [Kbytes/sec] received

Connection Times (ms)
 min mean[+/-sd] median max
Connect: 0 0 0.3 0 3
Processing: 4 68 7.4 67 90
Waiting: 4 68 7.4 67 90
Total: 7 68 7.2 67 90

Percentage of the requests served within a certain time (ms)
 50% 67
 66% 69
 75% 71
 80% 72
 90% 77
 95% 82
 98% 86
 99% 89
 100% 90 (longest request)
```

您将看到 cAdvisor 中资源使用量的相应增加，或者大约一分钟后，在 Heapster 中看到 Grafana。为了在 Heapster 和 Grafana 中获得有用的值，您将希望运行更长时间的负载测试，因为这些数据正在被聚合——最好是在几分钟内运行负载测试，因为一分钟是 Grafana 与 Heapster 聚合的基本级别。

cAdvisor 将更快地更新，如果您正在查看交互式图表，您将会看到它们随着负载测试的进行而更新：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-dev/img/5e3a3c74-1d06-41a8-8589-b8b18fefcdc1.png)

在这种情况下，您会看到我们的内存使用量基本保持在 36 MB 左右，而我们的 CPU 在负载测试期间达到峰值（这是您可能会预期到的应用程序行为）。

如果我们应用了前面的请求和限制示例，并更新了 flask 部署，那么当 CPU 达到大约 1/2 核心 CPU 限制时，您会看到负载趋于平稳。

这个过程的第三步主要是验证您对 CPU 和内存需求的评估是否符合长时间运行的负载测试。通常情况下，您会运行一个较长时间的负载（至少几分钟），并设置请求和限制来验证容器是否能够提供预期的流量。这种评估中最常见的缺陷是在进行长时间负载测试时看到内存缓慢增加，导致容器被 OOM 杀死（因超出内存限制而被终止）。

我们在示例中使用的 100 MiB RAM 比这个容器实际需要的内存要多得多，因此我们可以将其减少到 40 MiB 并进行最终验证步骤。

在设置请求和限制时，您希望选择最有效地描述您的需求的值，但不要浪费保留的资源。要运行更长时间的负载测试，请输入：

```
ab -c 100 -n 50000 http://flask-service.default:5000/
```

Grafana 的输出如下：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-dev/img/965cf39b-d505-4897-abea-4bfbac400e5d.png)

# 使用 Prometheus 捕获指标

Prometheus 是一个用于监控的知名开源工具，它与 Kubernetes 社区之间正在进行相当多的共生工作。Kubernetes 应用程序指标以 Prometheus 格式公开。该格式包括*counter*、*gauge*、*histogram*和*summary*的数据类型，以及一种指定与特定指标相关联的标签的方法。随着 Prometheus 和 Kubernetes 的发展，Prometheus 的指标格式似乎正在成为该项目及其各个组件中的事实标准。

有关此格式的更多信息可在 Prometheus 项目的文档中在线获取：

+   [`prometheus.io/docs/concepts/data_model/`](https://prometheus.io/docs/concepts/data_model/)

+   [`prometheus.io/docs/concepts/metric_types/`](https://prometheus.io/docs/concepts/metric_types/)

+   [`prometheus.io/docs/instrumenting/exposition_formats/`](https://prometheus.io/docs/instrumenting/exposition_formats/)

除了指标格式外，Prometheus 作为自己的开源项目提供了相当多样的功能，并且在 Kubernetes 之外也被使用。该项目的架构合理地展示了其主要组件：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-dev/img/2531e4a8-92de-4873-9164-9c5c23ec7806.png)

Prometheus 服务器本身是我们将在本章中研究的内容。在其核心，它定期地扫描多个远程位置，从这些位置收集数据，将其存储在短期时间序列数据库中，并提供一种查询该数据库的方法。Prometheus 的扩展允许系统将这些时间序列指标导出到其他系统以进行长期存储。此外，Prometheus 还包括一个警报管理器，可以配置为根据从时间序列指标中捕获和派生的信息发送警报，或更一般地调用操作。

Prometheus 并不打算成为指标的长期存储，并且可以与各种其他系统一起工作，以在长期内捕获和管理数据。常见的 Prometheus 安装保留数据 6 至 24 小时，可根据安装进行配置。

Prometheus 的最小安装包括 Prometheus 服务器本身和服务的配置。但是，为了充分利用 Prometheus，安装通常更加广泛和复杂，为 Alertmanager 和 Prometheus 服务器分别部署，可选地为推送网关部署（允许其他系统主动向 Prometheus 发送指标），以及一个 DaemonSet 来从集群中的每个节点捕获数据，将信息暴露和导出到 Prometheus 中，利用 cAdvisor。

更复杂的软件安装可以通过管理一组 YAML 文件来完成，就像我们在本书中之前所探讨的那样。有其他选项可以管理和安装一组部署、服务、配置等等。我们将利用这类工作中更常见的工具之一，Helm，而不是记录所有的部分，Helm 与 Kubernetes 项目密切相关，通常被称为*Kubernetes 的包管理器*。

您可以在项目的文档网站[`helm.sh`](https://helm.sh)上找到有关 Helm 的更多信息。

# 安装 Helm

Helm 是一个由命令行工具和在 Kubernetes 集群中运行的软件组成的双重系统，命令行工具与之交互。通常，您需要的是本地的命令行工具，然后再用它来安装所需的组件到您的集群中。

有关安装 Helm 命令行工具的文档可在项目网站上找到：[`github.com/kubernetes/helm/blob/master/docs/install.md.`](https://github.com/kubernetes/helm/blob/master/docs/install.md)

如果您在本地使用 macOS，则可以通过 Homebrew 获得，并且可以使用以下命令进行安装：

```
brew install kubernetes-helm
```

或者，如果您是从 Linux 主机工作，Helm 项目提供了一个脚本，您可以使用它来安装 Helm：

```
curl https://raw.githubusercontent.com/kubernetes/helm/master/scripts/get > get_helm.sh
chmod 700 get_helm.sh
./get_helm.sh
```

安装 Helm 后，您可以使用`helm init`命令在集群中安装运行的组件（称为 Tiller）。您应该会看到如下输出：

```
$HELM_HOME has been configured at /Users/heckj/.helm.

Tiller (the Helm server-side component) has been installed into your Kubernetes Cluster.
Happy Helming!
```

除了为其使用设置一些本地配置文件之外，这还在`kube-system`命名空间中为其集群端组件**Tiller**进行了部署。如果您想更详细地查看它，可以查看该部署：

```
kubectl describe deployment tiller-deploy -n kube-system
```

此时，您已经安装了 Helm，并且可以使用命令 Helm version 验证安装的版本（包括命令行和集群上的版本）。这与`kubectl` version 非常相似，报告了其版本以及与之通信的系统的版本。

```
helm version 
Client: &amp;version.Version{SemVer:"v2.7.2", GitCommit:"8478fb4fc723885b155c924d1c8c410b7a9444e6", GitTreeState:"clean"}
Server: &amp;version.Version{SemVer:"v2.7.2", GitCommit:"8478fb4fc723885b155c924d1c8c410b7a9444e6", GitTreeState:"clean"}
```

现在，我们可以继续设置 Helm 的原因：安装 Prometheus。

# 使用 Helm 安装 Prometheus

Helm 使用一组配置文件来描述安装需要什么，以什么顺序以及使用什么参数。这些配置称为图表，并在 GitHub 中维护，其中维护了默认的 Helm 存储库。

您可以使用命令`helm repo list`查看 Helm 正在使用的存储库。

```
helm repo list 
NAME URL
stable https://kubernetes-charts.storage.googleapis.com
local http://127.0.0.1:8879/charts
```

此默认值是围绕 GitHub 存储库的包装器，您可以在[`github.com/kubernetes/charts`](https://github.com/kubernetes/charts)上查看存储库的内容。查看所有可用于使用的图表的另一种方法是使用命令`helm search`。

确保您拥有存储库的最新缓存是个好主意。您可以使用命令`helm repo update`将缓存更新到最新状态，以在 GitHub 中镜像图表。

更新后的结果应该报告成功，并输出类似于：

```
help repo update

Hang tight while we grab the latest from your chart repositories...
...Skip local chart repository
...Successfully got an update from the "stable" chart repository
Update Complete.  Happy Helming!
```

我们将使用 stable/Prometheus 图表（托管在[`github.com/kubernetes/charts/tree/master/stable/prometheus`](https://github.com/kubernetes/charts/tree/master/stable/prometheus)）。我们可以使用 Helm 将该图表拉取到本地，以便更详细地查看它。

```
helm fetch --untar stable/prometheus 
```

此命令从默认存储库下载图表并在名为 Prometheus 的目录中本地解压缩。查看目录，您应该会看到几个文件和一个名为`templates`的目录：

```
.helmignore
Chart.yaml
README.md
templates
values.yaml
```

这是图表的常见模式，其中`Chart.yaml`描述了将由图表安装的软件。`values.yaml`是一组默认配置值，这些值在将要创建的各种 Kubernetes 资源中都会使用，并且模板目录包含了将被渲染出来以安装集群中所需的所有 Kubernetes 资源的模板文件集合。通常，`README.md`将包括`values.yaml`中所有值的描述，它们的用途以及安装建议。

现在，我们可以安装`prometheus`，我们将利用 Helm 的一些选项来设置一个发布名称并使用命名空间来进行安装。

```
helm install prometheus -n monitor --namespace monitoring
```

这将安装`prometheus`目录中包含的图表，将所有组件安装到命名空间`monitoring`中，并使用发布名称`monitor`为所有对象添加前缀。如果我们没有指定这些值中的任何一个，Helm 将使用默认命名空间，并生成一个随机的发布名称来唯一标识安装。

调用此命令时，您将看到相当多的输出，描述了在过程开始时创建的内容及其状态，然后是提供有关如何访问刚刚安装的软件的信息的注释部分：

```
NAME: monitor
LAST DEPLOYED: Sun Jan 14 15:00:40 2018
NAMESPACE: monitoring
STATUS: DEPLOYED
RESOURCES:
==> v1/ConfigMap
NAME DATA AGE
monitor-prometheus-alertmanager 1 1s
monitor-prometheus-server 3 1s

==> v1/PersistentVolumeClaim
NAME STATUS VOLUME CAPACITY ACCESS MODES STORAGECLASS AGE
monitor-prometheus-alertmanager Bound pvc-be6b3367-f97e-11e7-92ab-e697d60b4f2f 2Gi RWO standard 1s
monitor-prometheus-server Bound pvc-be6b8693-f97e-11e7-92ab-e697d60b4f2f 8Gi RWO standard 1s

==> v1/Service
NAME TYPE CLUSTER-IP EXTERNAL-IP PORT(S) AGE
monitor-prometheus-alertmanager ClusterIP 10.100.246.164 <none> 80/TCP 1s
monitor-prometheus-kube-state-metrics ClusterIP None <none> 80/TCP 1s
monitor-prometheus-node-exporter ClusterIP None <none> 9100/TCP 1s
monitor-prometheus-pushgateway ClusterIP 10.97.187.101 <none> 9091/TCP 1s
monitor-prometheus-server ClusterIP 10.110.247.151 <none> 80/TCP 1s

==> v1beta1/DaemonSet
NAME DESIRED CURRENT READY UP-TO-DATE AVAILABLE NODE SELECTOR AGE
monitor-prometheus-node-exporter 1 1 0 1 0 <none> 1s

==> v1beta1/Deployment
NAME DESIRED CURRENT UP-TO-DATE AVAILABLE AGE
monitor-prometheus-alertmanager 1 1 1 0 1s
monitor-prometheus-kube-state-metrics 1 1 1 0 1s
monitor-prometheus-pushgateway 1 1 1 0 1s
monitor-prometheus-server 1 1 1 0 1s

==> v1/Pod(related)
NAME READY STATUS RESTARTS AGE
monitor-prometheus-node-exporter-bc9jp 0/1 ContainerCreating 0 1s
monitor-prometheus-alertmanager-6c59f855d-bsp7t 0/2 ContainerCreating 0 1s
monitor-prometheus-kube-state-metrics-57747bc8b6-l7pzw 0/1 ContainerCreating 0 1s
monitor-prometheus-pushgateway-5b99967d9c-zd7gc 0/1 ContainerCreating 0 1s
monitor-prometheus-server-7895457f9f-jdvch 0/2 Pending 0 1s

NOTES:
The prometheus server can be accessed via port 80 on the following DNS name from within your cluster:
monitor-prometheus-server.monitoring.svc.cluster.local

Get the prometheus server URL by running these commands in the same shell:
 export POD_NAME=$(kubectl get pods --namespace monitoring -l "app=prometheus,component=server" -o jsonpath="{.items[0].metadata.name}")
 kubectl --namespace monitoring port-forward $POD_NAME 9090

The prometheus alertmanager can be accessed via port 80 on the following DNS name from within your cluster:
monitor-prometheus-alertmanager.monitoring.svc.cluster.local

Get the Alertmanager URL by running these commands in the same shell:
 export POD_NAME=$(kubectl get pods --namespace monitoring -l "app=prometheus,component=alertmanager" -o jsonpath="{.items[0].metadata.name}")
 kubectl --namespace monitoring port-forward $POD_NAME 9093

The prometheus PushGateway can be accessed via port 9091 on the following DNS name from within your cluster:
monitor-prometheus-pushgateway.monitoring.svc.cluster.local

Get the PushGateway URL by running these commands in the same shell:
 export POD_NAME=$(kubectl get pods --namespace monitoring -l "app=prometheus,component=pushgateway" -o jsonpath="{.items[0].metadata.name}")
 kubectl --namespace monitoring port-forward $POD_NAME 9093

For more information on running prometheus, visit:
https://prometheus.io/
```

`helm list`将显示您已安装的当前发布：

```
NAME REVISION UPDATED STATUS CHART NAMESPACE
monitor 1 Sun Jan 14 15:00:40 2018 DEPLOYED prometheus-4.6.15 monitoring
```

您可以使用`helm status`命令，以及发布的名称，来获取图表创建的所有 Kubernetes 资源的当前状态：

```
helm status monitor
```

注释部分包含在模板中，并在每次状态调用时重新呈现，通常编写以包括有关如何访问软件的说明。

您可以安装图表而无需显式先检索它。Helm 首先使用任何本地图表，但会回退到搜索其可用存储库，因此我们可以只使用以下命令安装相同的图表：

`**helm install stable/prometheus -n monitor --namespace monitoring**`

您还可以让 Helm 混合`values.yaml`和其模板，以呈现出它将创建的所有对象并简单显示它们，这对于查看所有部件将如何组合在一起很有用。执行此操作的命令是`helm template`，要呈现用于创建 Kubernetes 资源的 YAML，命令将是：

```
helm template prometheus -n monitor --namespace monitoring
```

`helm template`命令确实需要图表在本地文件系统上可用，因此，虽然`helm install`可以从远程存储库中工作，但您需要使用`helm fetch`将图表本地化，以便利用`helm template`命令。

# 使用 Prometheus 查看指标

使用注释中提供的详细信息，您可以设置端口转发，就像我们在本书中之前所做的那样，并直接访问 Prometheus。从注释中显示的信息如下：

```
export POD_NAME=$(kubectl get pods --namespace monitoring -l "app=prometheus,component=server" -o jsonpath="{.items[0].metadata.name}")

kubectl --namespace monitoring port-forward $POD_NAME 9090
```

这将允许您直接使用浏览器访问 Prometheus 服务器。在终端中运行这些命令，然后打开浏览器并导航到`http://localhost:9090/`。

您可以通过查看`http://localhost:9090/targets`上的目标列表来查看 Prometheus 正在监视的当前状态：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-dev/img/207a582a-322b-4fbf-9b78-88134b726460.png)

切换到 Prometheus 查询/浏览器，网址为`http://localhost:9090/graph`，以查看 Prometheus 收集的指标。收集了大量的指标，我们特别感兴趣的是与之前在 cAdvisor 和 Heapster 中看到的信息匹配的指标。在 Kubernetes 1.7 版本及更高版本的集群中，这些指标已经移动，并且是由我们在屏幕截图中看到的`kubernetes-nodes-cadvisor`作业专门收集的。

在查询浏览器中，您可以开始输入指标名称，它将尝试自动完成，或者您可以使用下拉菜单查看所有可能的指标列表。输入指标名称`container_memory_usage_bytes`，然后按*Enter*以以表格形式查看这些指标的列表。

良好指标的一般形式将具有一些指标的标识符，并且通常以单位标识符结尾，在本例中为字节。查看表格，您可以看到收集的指标以及每个指标的相当密集的键值对。

这些键值对是指标上的标签，并且在整体上类似于 Kubernetes 中的标签和选择器的工作方式。

一个示例指标，重新格式化以便更容易阅读，如下所示：

```
container_memory_usage_bytes{
  beta_kubernetes_io_arch="amd64",
  beta_kubernetes_io_os="linux",
  container_name="POD",
  id="/kubepods/podf887aff9-f981-11e7-92ab-e697d60b4f2f/25fa74ef205599036eaeafa7e0a07462865f822cf364031966ff56a9931e161d",
  image="gcr.io/google_containers/pause-amd64:3.0",
  instance="minikube",
  job="kubernetes-nodes-cadvisor",
  kubernetes_io_hostname="minikube",
  name="k8s_POD_flask-5c7d884fcc-2l7g9_default_f887aff9-f981-11e7-92ab-e697d60b4f2f_0",
  namespace="default",
  pod_name="flask-5c7d884fcc-2l7g9"
}  249856
```

在查询中，我们可以通过在查询中包含与这些标签匹配的内容来过滤我们感兴趣的指标。例如，与特定容器相关联的所有指标都将具有`image`标签，因此我们可以仅过滤这些指标：

```
container_memory_usage_bytes{image!=""}
```

您可能已经注意到，命名空间和 pod 名称也包括在内，我们也可以进行匹配。例如，只查看与我们部署示例应用程序的默认命名空间相关的指标，我们可以添加`namespace="default"`：

```
container_memory_usage_bytes{image!="",namespace="default"}
```

这开始变得更合理了。虽然表格将向您显示最近的值，但我们感兴趣的是这些值的历史记录。如果您选择当前查询上的图形按钮，它将尝试呈现出您选择的指标的单个图形，例如：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-dev/img/fbccdafc-027d-4fae-ac33-27b56dde19fa.png)

由于指标还包括`container_name`以匹配部署，您可以将其调整为单个容器。例如，查看与我们的`flask`部署相关的内存使用情况：

```
container_memory_usage_bytes{image!="",namespace="default",container_name="flask"}
```

如果我们增加`flask`部署中副本的数量，它将为每个容器创建新的指标，因此为了不仅查看单个容器而且一次查看多个集合，我们可以利用 Prometheus 查询语言中的聚合运算符。一些最有用的运算符包括`sum`、`count`、`count_values`和`topk`。

我们还可以使用这些相同的聚合运算符将指标分组在一起，其中聚合集合具有不同的标签值。例如，在将`flask`部署的副本增加到三个后，我们可以查看部署的总内存使用情况：

```
sum(container_memory_usage_bytes{image!="",
namespace="default",container_name="flask"})
```

然后再次按照 Pod 名称将其分解为每个容器：

```
sum(container_memory_usage_bytes{image!="",
namespace="default",container_name="flask"}) by (name)
```

图形功能可以为您提供一个良好的视觉概览，包括堆叠值，如下所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-dev/img/2b9ea59d-0862-40c8-a304-1fd6932379de.png)

随着图形变得更加复杂，您可能希望开始收集您认为最有趣的查询，以及组合这些图形的仪表板，以便能够使用它们。这将引导我们进入另一个开源项目 Grafana，它可以很容易地在 Kubernetes 上托管，提供仪表板和图形。

# 安装 Grafana

Grafana 本身并不是一个复杂的安装，但配置它可能会很复杂。Grafana 可以插入多种不同的后端系统，并为它们提供仪表板和图形。在我们的示例中，我们希望它从 Prometheus 提供仪表板。我们将设置一个安装，然后通过其用户界面进行配置。

我们可以再次使用 Helm 来安装 Grafana，由于我们已经将 Prometheus 放在监控命名空间中，我们将用相同的方式处理 Grafana。我们可以使用`helm fetch`并安装来查看图表。在这种情况下，我们将直接安装它们：

```
helm install stable/grafana -n viz --namespace monitoring
```

在生成的输出中，您将看到一个秘密、ConfigMap 和部署等资源被创建，并且在注释中会有类似以下内容：

```
NOTES:
1\. Get your 'admin' user password by running:

kubectl get secret --namespace monitoring viz-grafana -o jsonpath="{.data.grafana-admin-password}" | base64 --decode ; echo

2\. The Grafana server can be accessed via port 80 on the following DNS name from within your cluster:

viz-grafana.monitoring.svc.cluster.local

Get the Grafana URL to visit by running these commands in the same shell:

export POD_NAME=$(kubectl get pods --namespace monitoring -l "app=viz-grafana,component=grafana" -o jsonpath="{.items[0].metadata.name}")
 kubectl --namespace monitoring port-forward $POD_NAME 3000

3\. Login with the password from step 1 and the username: admin
```

注释首先包括有关检索秘密的信息。这突出了一个功能，您将看到在几个图表中使用：当它需要一个机密密码时，它将生成一个唯一的密码并将其保存为秘密。这个秘密直接可供访问命名空间和`kubectl`的人使用。

使用提供的命令检索 Grafana 界面的密码：

```
kubectl get secret --namespace monitoring viz-grafana -o jsonpath="{.data.grafana-admin-password}" | base64 --decode ; echo
```

然后打开终端并运行这些命令以访问仪表板：

```
export POD_NAME=$(kubectl get pods --namespace monitoring -l "app=viz-grafana,component=grafana" -o jsonpath="{.items[0].metadata.name}")

kubectl --namespace monitoring port-forward $POD_NAME 3000
```

然后，打开浏览器窗口，导航至`https://localhost:3000/`，这将显示 Grafana 登录窗口：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-dev/img/56c2c32b-f460-4561-b192-3e2a24c4a6b8.png)

现在，使用用户名`admin`登录；密码是您之前检索到的秘密。这将带您进入 Grafana 中的主页仪表板，您可以在那里配置数据源并将图形组合成仪表板：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-dev/img/229ace04-bb99-4ac2-b282-cdc03ef23b21.png)

点击“添加数据源”，您将看到一个带有两个选项卡的窗口：配置允许您设置数据源的位置，仪表板允许您导入仪表板配置。

在配置下，将数据源的类型设置为 Prometheus，在名称处，您可以输入`prometheus`。在类型之后命名数据源有点多余，如果您的集群上有多个 Prometheus 实例，您会希望为它们分别命名，并且特定于它们的目的。在 URL 中添加我们的 Prometheus 实例的 DNS 名称，以便 Grafana 可以访问它：`http://monitor-prometheus-server.monitoring.svc.cluster.local`。在使用 Helm 安装 Prometheus 时，这个相同的名称在注释中列出了。

点击“仪表板”选项卡，并导入 Prometheus 统计信息和 Grafana 指标，这将为 Prometheus 和 Grafana 本身提供内置仪表板。点击返回到“配置”选项卡，向下滚动，并点击“添加”按钮设置 Prometheus 数据源。当您添加时，您应该会看到“数据源正在工作”。

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-dev/img/9c2bdd4a-b03e-4fdb-a19f-4cd7946cef4b.png)

现在，您可以导航到内置仪表板并查看一些信息。网页用户界面的顶部由下拉菜单组成，左上角导航到整体 Grafana 配置，下一个列出了您设置的仪表板，通常从主页仪表板开始。选择我们刚刚导入的 Prometheus Stats 仪表板，您应该会看到有关 Prometheus 的一些初始信息：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-dev/img/8fc15a8e-3e4b-4a7b-ac73-78c26e24e863.png)

Grafana 项目维护了一系列仪表板，您可以搜索并直接使用，或者用作灵感来修改和创建自己的仪表板。您可以搜索已共享的仪表板，例如，将其限制为来自 Prometheus 并与 Kubernetes 相关的仪表板。您将看到各种各样的仪表板可供浏览，其中一些包括屏幕截图，网址为[`grafana.com/dashboards?dataSource=prometheus&amp;search=kubernetes`](https://grafana.com/dashboards?dataSource=prometheus&search=kubernetes)。

您可以使用仪表板编号将其导入到 Grafana 的实例中。例如，仪表板 1621 和 162 是用于监视整个集群健康状况的常见仪表板：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-dev/img/ee7702a3-ee8c-4556-9a53-292187d189f7.png)

这些仪表板的最佳价值在于向您展示如何配置自己的图形并制作自己的仪表板。在每个仪表板中，您可以选择图形并选择编辑以查看使用的查询和显示选择，并根据您的值进行微调。每个仪表板也可以共享回 Grafana 托管站点，或者您可以查看配置的 JSON 并将其保存在本地。

Prometheus 运营商正在努力使启动 Prometheus 和 Grafana 变得更容易，预先配置并运行以监视您的集群和集群内的应用程序。如果您有兴趣尝试一下，请参阅 CoreOS 托管的项目 README [`github.com/coreos/prometheus-operator/tree/master/helm`](https://github.com/coreos/prometheus-operator/tree/master/helm)，也可以使用 Helm 进行安装。

现在您已经安装了 Grafana 和 Prometheus，您可以使用它们来遵循类似的过程，以确定您自己软件的 CPU 和内存利用率，同时运行负载测试。在本地运行 Prometheus 的一个好处是它提供了收集有关您的应用程序的指标的能力。

# 使用 Prometheus 查看应用程序指标

虽然您可以在 Prometheus 中添加作业以包括从特定端点抓取 Prometheus 指标的配置，但我们之前进行的安装包括一个将根据 Pod 上的注释动态更新其查看内容的配置。 Prometheus 的一个好处是它支持根据注释自动检测集群中的更改，并且可以查找支持服务的 Pod 的端点。

由于我们使用 Helm 部署了 Prometheus，您可以在`values.yaml`文件中找到相关的配置。查找 Prometheus 作业`kubernetes-service-endpoints`，您将找到配置和一些关于如何使用它的文档。如果您没有本地文件，可以在[`github.com/kubernetes/charts/blob/master/stable/prometheus/values.yaml#L747-L776`](https://github.com/kubernetes/charts/blob/master/stable/prometheus/values.yaml#L747-L776)上查看此配置。

此配置查找集群中具有注释`prometheus.io/scrape`的服务。如果设置为`true`，那么 Prometheus 将自动尝试将该端点添加到其正在监视的目标列表中。默认情况下，它将尝试访问 URI`/metrics`上的指标，并使用与服务相同的端口。您可以使用其他注释来更改这些默认值，例如，`prometheus.io/path = "/alternatemetrics"`将尝试从路径`/alternatemetrics`读取指标。

通过使用服务作为组织指标收集的手段，我们有一个机制，它将根据 Pod 的数量自动扩展。而在其他环境中，您可能需要每次添加或删除实例时重新配置监控，Prometheus 和 Kubernetes 无缝协作捕获这些数据。

这种能力使我们能够轻松地从我们的应用程序中公开自定义指标，并让 Prometheus 捕获这些指标。这可以有几种用途，但最明显的是更好地了解应用程序的运行情况。有了 Prometheus 收集指标和 Grafana 作为仪表板工具，您还可以使用这种组合来创建自己的应用程序仪表板。

Prometheus 项目支持多种语言的客户端库，使其更容易收集和公开指标。我们将使用其中一些库来向您展示如何为我们的 Python 和 Node.js 示例进行仪器化。在直接使用这些库之前，非常值得阅读 Prometheus 项目提供的有关如何编写指标导出器以及其对指标名称的预期约定的文档。您可以在项目网站找到这些文档：[`prometheus.io/docs/instrumenting/writing_exporters/`](https://prometheus.io/docs/instrumenting/writing_exporters/)。

# 使用 Prometheus 的 Flask 指标

您可以在[`github.com/prometheus/client_python`](https://github.com/prometheus/client_python)找到从 Python 公开指标的库，并可以使用以下命令使用`pip`进行安装：

```
pip install prometheus_client
```

根据您的设置，您可能需要使用`**sudo pip install prometheus_client**`使用`pip`安装客户端。

对于我们的`flask`示例，您可以从[`github.com/kubernetes-for-developers/kfd-flask`](https://github.com/kubernetes-for-developers/kfd-flask)的 0.5.0 分支下载完整的示例代码。获取此更新示例的命令如下：

```
git clone https://github.com/kubernetes-for-developers/kfd-flask -b 0.5.0
```

如果您查看`exampleapp.py`，您可以看到我们使用两个指标的代码，即直方图和计数器，并使用 flask 框架在请求开始和请求结束时添加回调，并捕获该时间差：

```
FLASK_REQUEST_LATENCY = Histogram('flask_request_latency_seconds', 'Flask Request Latency',
 ['method', 'endpoint'])
FLASK_REQUEST_COUNT = Counter('flask_request_count', 'Flask Request Count',
 ['method', 'endpoint', 'http_status'])

def before_request():
   request.start_time = time.time()

def after_request(response):
   request_latency = time.time() - request.start_time
   FLASK_REQUEST_LATENCY.labels(request.method, request.path).observe(request_latency)
   FLASK_REQUEST_COUNT.labels(request.method, request.path, response.status_code).inc()
   return response
```

该库还包括一个辅助应用程序，使得生成 Prometheus 要抓取的指标非常容易：

```
@app.route('/metrics')
def metrics():
   return make_response(generate_latest())
```

该代码已制作成容器映像`quay.io/kubernetes-for-developers/flask:0.5.0`。有了这些添加，我们只需要将注释添加到`flask-service`：

```
kind: Service
apiVersion: v1
metadata:
   name: flask-service
   annotations:
       prometheus.io/scrape: "true"
spec:
  type: NodePort
  ports:
  - port: 5000
  selector:
      app: flask
```

从示例目录中使用`kubectl apply -f deploy/`部署后，该服务将由单个 pod 支持，并且 Prometheus 将开始将其作为目标。如果您使用`kubectl proxy`命令，您可以查看此生成的特定指标响应。在我们的情况下，pod 的名称是`flask-6596b895b-nqqqz`，因此可以轻松查询指标`http://localhost:8001/api/v1/proxy/namespaces/default/pods/flask-6596b895b-nqqqz/metrics`。

这些指标的示例如下：

```
flask_request_latency_seconds_bucket{endpoint="/",le="0.005",method="GET"} 13.0 flask_request_latency_seconds_bucket{endpoint="/",le="0.01",method="GET"} 13.0 flask_request_latency_seconds_bucket{endpoint="/",le="0.025",method="GET"} 13.0 flask_request_latency_seconds_bucket{endpoint="/",le="0.05",method="GET"} 13.0 flask_request_latency_seconds_bucket{endpoint="/",le="0.075",method="GET"} 13.0 flask_request_latency_seconds_bucket{endpoint="/",le="0.1",method="GET"} 13.0 flask_request_latency_seconds_bucket{endpoint="/",le="0.25",method="GET"} 13.0 flask_request_latency_seconds_bucket{endpoint="/",le="0.5",method="GET"} 13.0 flask_request_latency_seconds_bucket{endpoint="/",le="0.75",method="GET"} 13.0 flask_request_latency_seconds_bucket{endpoint="/",le="1.0",method="GET"} 13.0 flask_request_latency_seconds_bucket{endpoint="/",le="2.5",method="GET"} 13.0 flask_request_latency_seconds_bucket{endpoint="/",le="5.0",method="GET"} 13.0 flask_request_latency_seconds_bucket{endpoint="/",le="7.5",method="GET"} 13.0 flask_request_latency_seconds_bucket{endpoint="/",le="10.0",method="GET"} 13.0 flask_request_latency_seconds_bucket{endpoint="/",le="+Inf",method="GET"} 13.0 flask_request_latency_seconds_count{endpoint="/",method="GET"} 13.0 flask_request_latency_seconds_sum{endpoint="/",method="GET"} 0.0012879371643066406 
# HELP flask_request_count Flask Request Count 
# TYPE flask_request_count counter flask_request_count{endpoint="/alive",http_status="200",method="GET"} 645.0 flask_request_count{endpoint="/ready",http_status="200",method="GET"} 644.0 flask_request_count{endpoint="/metrics",http_status="200",method="GET"} 65.0 flask_request_count{endpoint="/",http_status="200",method="GET"} 13.0
```

您可以在此示例中看到名为`flask_request_latency_seconds`和`flask_request_count`的指标，并且您可以在 Prometheus 浏览器界面中查询相同的指标。

# 使用 Prometheus 的 Node.js 指标

JavaScript 具有与 Python 类似的客户端库。实际上，使用`express-prom-bundle`来为 Node.js express 应用程序提供仪表板甚至更容易，该库反过来使用`prom-client`。您可以使用以下命令安装此库以供您使用：

```
npm install express-prom-bundle --save
```

然后您可以在您的代码中使用它。以下内容将为 express 设置一个中间件：

```
const promBundle = require("express-prom-bundle");
const metricsMiddleware = promBundle({includeMethod: true});
```

然后，您只需包含中间件，就像您正在设置此应用程序一样：

```
app.use(metricsMiddleware)
```

[`github.com/kubernetes-for-developers/kfd-nodejs`](https://github.com/kubernetes-for-developers/kfd-nodejs)上的示例代码已经更新，您可以使用以下命令从 0.5.0 分支检查此代码：

```
git clone https://github.com/kubernetes-for-developers/kfd-nodejs -b 0.5.0
```

与 Python 代码一样，Node.js 示例包括使用注释`prometheus.io/scrape: "true"`更新服务：

```
kind: Service
apiVersion: v1
metadata:
 name: nodejs-service
 annotations:
   prometheus.io/scrape: "true"
spec:
 ports:
 - port: 3000
   name: web
 clusterIP: None
 selector:
   app: nodejs
```

# Prometheus 中的服务信号

您可以通过三个关键指标来了解您服务的健康和状态。服务仪表板通常会基于这些指标进行仪表化和构建，作为了解您的服务运行情况的基线，这已经相对普遍。

这些网络服务的关键指标是：

+   错误率

+   响应时间

+   吞吐量

错误率可以通过使用`http_request_duration_seconds_count`指标中的标签来收集，该指标包含在`express-prom-bundle`中。我们可以在 Prometheus 中使用的查询。我们可以匹配响应代码的格式，并计算 500 个响应与所有响应的增加数量。

Prometheus 查询可以是：

```
sum(increase(http_request_duration_seconds_count{status_code=~"⁵..$"}[5m])) / sum(increase(http_request_duration_seconds_count[5m]))
```

在我们自己的示例服务上几乎没有负载，可能没有错误，这个查询不太可能返回任何数据点，但你可以用它作为一个示例来探索构建你自己的错误响应查询。

响应时间很难测量和理解，特别是对于繁忙的服务。我们通常包括一个用于处理请求所需时间的直方图指标的原因是为了能够查看这些请求随时间的分布。使用直方图，我们可以在一个窗口内聚合请求，然后查看这些请求的速率。在我们之前的 Python 示例中，`flask_request_latency_seconds`是一个直方图，每个请求都带有它在直方图桶中的位置标签，使用的 HTTP 方法和 URI 端点。我们可以使用这些标签聚合这些请求的速率，并使用以下 Prometheus 查询查看中位数、95^(th)和 99^(th)百分位数：

中位数:

```
histogram_quantile(0.5, sum(rate(flask_request_latency_seconds_bucket[5m])) by (le, method, endpoint))
```

95^(th)百分位数：

```
histogram_quantile(0.95, sum(rate(flask_request_latency_seconds_bucket[5m])) by (le, method, endpoint))
```

99^(th)百分位数：

```
histogram_quantile(0.99, sum(rate(flask_request_latency_seconds_bucket[5m])) by (le, method, endpoint))
```

吞吐量是关于在给定时间范围内测量请求总数的，可以直接从`flask_request_latency_seconds_count`中派生，并针对端点和方法进行查看：

```
sum(rate(flask_request_latency_seconds_count[5m])) by (method, endpoint)
```

# 总结

在本章中，我们介绍了 Prometheus，并展示了如何安装它，使用它从您的 Kubernetes 集群中捕获指标，并展示了如何安装和使用 Grafana 来提供仪表板，使用在 Prometheus 中临时存储的指标。然后，我们看了一下如何从您自己的代码中暴露自定义指标，并利用 Prometheus 来捕获它们，以及一些您可能有兴趣跟踪的指标的示例，如错误率、响应时间和吞吐量。

在下一章中，我们将继续使用工具来帮助我们捕获日志和跟踪，以便观察我们的应用程序。


# 第八章：日志和跟踪

当我们最初开始使用容器和 Kubernetes 时，我们展示了如何使用`kubectl log`命令从任何一个容器中获取日志输出。随着我们希望获取信息的容器数量增加，轻松找到相关日志的能力变得越来越困难。在上一章中，我们看了如何聚合和收集指标，在本章中，我们扩展了相同的概念，看看如何聚合日志并更好地了解容器如何与分布式跟踪一起工作。

本章的主题包括：

+   一个 Kubernetes 概念- DaemonSet

+   安装 Elasticsearch，Fluentd 和 Kibana

+   使用 Kibana 查看日志

+   使用 Jeager 进行分布式跟踪

+   将跟踪添加到您的应用程序的一个例子

# 一个 Kubernetes 概念- DaemonSet

我们现在使用的一个 Kubernetes 资源（通过 Helm）是 DaemonSet。这个资源是围绕 pod 的一个包装，与 ReplicaSet 非常相似，但其目的是在集群中的每个节点上运行一个 pod。当我们使用 Helm 安装 Prometheus 时，它创建了一个 DaemonSet，在 Kubernetes 集群中的每个节点上运行 node-collector。

在应用程序中运行支持软件有两种常见模式：第一种是使用 side-car 模式，第二种是使用 DaemonSet。side-car 是指在您的 pod 中包含一个容器，其唯一目的是与主要应用程序一起运行并提供一些支持，但是外部的角色。一个有用的 side-car 的例子可能是缓存，或某种形式的代理服务。运行 side-car 应用程序显然会增加 pod 所需的资源，如果 pod 的数量相对较低，或者与集群的规模相比它们是稀疏的，那么这将是提供支持软件的最有效方式。

当您运行的支持软件在单个节点上可能被复制多次，并且提供的服务相当通用（例如日志聚合或指标收集）时，在集群中的每个节点上运行一个单独的 pod 可能会更有效。这正是 DaemonSet 的用武之地。

我们之前使用 DaemonSet 的示例是在集群中的每个节点上运行一个 node-collector 实例。node-collector DaemonSet 的目的是收集有关每个节点操作的统计数据和指标。Kubernetes 还使用 DaemonSet 来运行自己的服务，例如在集群中的每个节点上运行的 kube-proxy。如果您正在使用覆盖网络连接您的 Kubernetes 集群，例如 Weave 或 Flannel，它也经常使用 DaemonSet 运行。另一个常见的用例是我们将在本章中更多地探讨的用例，即收集和转发日志。

DaemonSet 规范的必需字段与部署或作业类似；除了`apiVersion`、`kind`和`metadata`之外，DaemonSet 还需要一个包含模板的 spec，该模板用于在每个节点上创建 pod。此外，模板可以具有`nodeSelector`来匹配一组或子集可用的节点。

查看 Helm 在安装`prometheus`时创建的 YAML。您可以了解到 DaemonSet 的数据是如何布局的。以下输出来自命令：

```
helm template prometheus -n monitor --namespace monitoring
```

Helm 生成的 DaemonSet 规范如下：

```
apiVersion: extensions/v1beta1 kind: DaemonSet metadata:
  labels:
  app: prometheus
  chart: prometheus-4.6.17
  component: "node-exporter"
  heritage: Tiller
  release: monitor
  name: monitor-prometheus-node-exporter spec:
  updateStrategy:
  type: OnDelete   template:
  metadata:
  labels:
  app: prometheus
  component: "node-exporter"
  release: monitor
  spec:
  serviceAccountName: "default"
  containers:
 - name: prometheus-node-exporter
  image: "prom/node-exporter:v0.15.0"
  imagePullPolicy: "IfNotPresent"
  args:
 - --path.procfs=/host/proc
 - --path.sysfs=/host/sys
  ports:
 - name: metrics
  containerPort: 9100
  hostPort: 9100
  resources:
 {}  volumeMounts:
 - name: proc
  mountPath: /host/proc
  readOnly: true
 - name: sys
  mountPath: /host/sys
  readOnly: true
  hostNetwork: true
  hostPID: true
  volumes:
 - name: proc
  hostPath:
  path: /proc
 - name: sys
  hostPath:
  path: /sys
```

这个 DaemonSet 在每个节点上运行一个单一的容器，使用镜像`prom/node-exporter:0.15`，从卷挂载点（`/proc`和`/sys`非常特定于 Linux）收集指标，并在端口`9100`上公开它们，以便`prometheus`通过 HTTP 请求进行抓取。

# 安装和使用 Elasticsearch、Fluentd 和 Kibana

Fluentd 是经常用于收集和聚合日志的软件。托管在[`www.fluentd.org`](https://www.fluentd.org)，就像 prometheus 一样，它是由**Cloud Native Computing Foundation** (**CNCF**)管理的开源软件。在谈论聚合日志时，问题早在容器出现之前就存在，ELK 是一个常用的缩写，代表了一个解决方案，即 Elasticsearch、Logstash 和 Kibana 的组合。在使用容器时，日志来源的数量增加，使得收集所有日志的问题变得更加复杂，Fluentd 发展成为支持与 Logstash 相同领域的软件，专注于使用 JSON 格式的结构化日志，路由和支持处理日志的插件。Fluentd 是用 Ruby 和 C 编写的，旨在比 LogStash 更快，更高效，而 Fluent Bit ([`fluentbit.io`](http://fluentbit.io))也延续了相同的模式，具有更小的内存占用。您甚至可能会看到 EFK 的引用，它代表 Elasticsearch、Fluentd 和 Kibana 的组合。

在 Kubernetes 社区中，捕获和聚合日志的常见解决方案之一是 Fluentd，甚至在 Minikube 的最新版本中作为可以使用的插件之一内置。

如果您正在使用 Minikube，可以通过启用 Minikube 插件来轻松尝试 EFK。尽管 Fluentd 和 Kibana 在资源需求方面相对较小，但 Elasticsearch 的资源需求较高，即使是用于小型演示实例。Minikube 使用的默认 VM 用于创建单节点 Kubernetes 集群，分配了 2GB 的内存，这对于运行 EFK 和任何其他工作负载是不够的，因为 ElasticSearch 在初始化和启动时需要使用 2GB 的内存。

幸运的是，您可以要求 Minikube 启动并为其创建的 VM 分配更多内存。要了解 Elasticsearch、Kibana 和 Fluentd 如何协同工作，您应该至少为 Minikube 分配 5GB 的 RAM 启动，可以使用以下命令完成：

```
minikube start --memory 5120
```

然后，您可以使用 Minikube add-ons 命令查看 Minikube 启用和禁用的插件。例如：

```
minikube addons list
```

```
- addon-manager: enabled
- coredns: enabled
- dashboard: enabled
- default-storageclass: enabled
- efk: disabled
- freshpod: disabled
- heapster: disabled
- ingress: disabled
- kube-dns: disabled
- registry: disabled
- registry-creds: disabled
- storage-provisioner: enabled
```

启用 EFK 只需使用以下命令即可：

```
 minikube addons enable efk
```

```
efk was successfully enabled
```

`enabled`并不意味着立即运行。FluentD 和 Kibana 会很快启动，但 ElasticSearch 需要更长的时间。作为附加组件意味着 Kubernetes 内的软件将管理 kube-system 命名空间内的容器，因此获取有关这些服务当前状态的信息不会像`kubectl get pods`那样简单。您需要引用`-n kube-system`或使用选项`--all-namespaces`：

```
kubectl get all --all-namespaces
```

```
NAMESPACE NAME DESIRED CURRENT UP-TO-DATE AVAILABLE AGE
kube-system deploy/coredns 1 1 1 1 5h
kube-system deploy/kubernetes-dashboard 1 1 1 1 5h
```

```
NAMESPACE NAME DESIRED CURRENT READY AGE
kube-system rs/coredns-599474b9f4 1 1 1 5h
kube-system rs/kubernetes-dashboard-77d8b98585 1 1 1 5h
```

```
NAMESPACE NAME DESIRED CURRENT UP-TO-DATE AVAILABLE AGE
kube-system deploy/coredns 1 1 1 1 5h
kube-system deploy/kubernetes-dashboard 1 1 1 1 5h
```

```
NAMESPACE NAME DESIRED CURRENT READY AGE
kube-system rs/coredns-599474b9f4 1 1 1 5h
kube-system rs/kubernetes-dashboard-77d8b98585 1 1 1 5h
```

```
NAMESPACE NAME READY STATUS RESTARTS AGE
kube-system po/coredns-599474b9f4-6fp8z 1/1 Running 0 5h
kube-system po/elasticsearch-logging-4zbpd 0/1 PodInitializing 0 3s
kube-system po/fluentd-es-hcngp 1/1 Running 0 3s
kube-system po/kibana-logging-stlzf 1/1 Running 0 3s
kube-system po/kube-addon-manager-minikube 1/1 Running 0 5h
kube-system po/kubernetes-dashboard-77d8b98585-qvwlv 1/1 Running 0 5h
kube-system po/storage-provisioner 1/1 Running 0 5h
```

```
NAMESPACE NAME DESIRED CURRENT READY AGE
kube-system rc/elasticsearch-logging 1 1 0 3s
kube-system rc/fluentd-es 1 1 1 3s
kube-system rc/kibana-logging 1 1 1 3s
```

```
NAMESPACE NAME TYPE CLUSTER-IP EXTERNAL-IP PORT(S) AGE
default svc/kubernetes ClusterIP 10.96.0.1 <none> 443/TCP 5h
kube-system svc/elasticsearch-logging ClusterIP 10.109.100.36 <none> 9200/TCP 3s
kube-system svc/kibana-logging NodePort 10.99.88.146 <none> 5601:30003/TCP 3s
kube-system svc/kube-dns ClusterIP 10.96.0.10 <none> 53/UDP,53/TCP,9153/TCP 5h
kube-system svc/kubernetes-dashboard NodePort 10.98.230.226 <none> 80:30000/TCP 5h
```

你可以看到 Minikube 附加管理器将 EFK 作为三个 ReplicaSets 加载，每个运行一个单独的 pod，并且使用从虚拟机暴露为 NodePort 的服务进行前端。使用 Minikube，您还可以使用以下命令查看服务列表：

```
minikube service list
```

```
|-------------|-----------------------|----------------------------|
| NAMESPACE   | NAME                  | URL                        |
|-------------|-----------------------|----------------------------|
| default     | kubernetes            | No node port               |
| kube-system | elasticsearch-logging | No node port               |
| kube-system | kibana-logging        | http://192.168.64.32:30003 |
| kube-system | kube-dns              | No node port               |
| kube-system | kubernetes-dashboard  | http://192.168.64.32:30000 |
|-------------|-----------------------|----------------------------|
```

# 使用 EFK 进行日志聚合。

Fluentd 作为从所有容器收集日志的源开始。它使用与命令`kubectl logs`相同的底层来源。在集群内，每个正在运行的容器都会生成日志，这些日志以某种方式由容器运行时处理，其中最常见的是 Docker，它在每个主机上为每个容器维护日志文件。

设置 Fluentd 的 Minikube 附加组件使用`ConfigMap`，它引用了加载这些日志文件的位置，并包含了用于注释来自 Kubernetes 的信息的附加规则。当 Fluentd 运行时，它会跟踪这些日志文件，从每个容器中读取更新的数据，将日志文件输出解析为 JSON 格式的数据结构，并添加 Kubernetes 特定的信息。相同的配置还详细说明了输出的处理方式，在 Minikube 附加组件的情况下，它指定了一个端点，即`elasticsearch-logging`服务，用于发送这些结构化的 JSON 数据。

Elasticsearch 是一个流行的开源数据和搜索索引，得到了[Elastic.co](https://www.elastic.co/)的企业支持。虽然它需要相当多的资源来运行，但它的扩展性非常好，并且对于添加各种数据源并为这些数据提供搜索界面具有非常灵活的结构。您可以在[`github.com/elastic/elasticsearch`](https://github.com/elastic/elasticsearch)的 GitHub 存储库中获取有关 ElasticSearch 工作原理的更多详细信息。

Kibana 是这个三部曲的最后一部分，为搜索存储在 Elasticsearch 中的内容提供了基于 Web 的用户界面。由[Elastic.co](https://www.elastic.co/)维护，它提供了一些仪表板功能和 Elasticsearch 的交互式查询界面。您可以在[`www.elastic.co/products/kibana`](https://www.elastic.co/products/kibana)上找到更多关于 Kibana 的信息。

在使用 Minikube 时，集群中的所有内容都在单个节点上，因此在较大的集群中使用相同类型的框架会有限制和差异。如果您正在使用具有多个节点的远程集群，您可能需要查看类似 Helm 这样的工具来安装 Elasticsearch、Fluentd 和 Kibana。许多支持 Kubernetes 的服务提供商也已经设置了类似的机制和服务，用于聚合、存储和提供容器日志的可搜索索引。Google Stackdriver、Datadog 和 Azure 都提供了类似的机制和服务，专门针对其托管解决方案。

# 使用 Kibana 查看日志

在本书中，我们将探讨如何使用 Kibana，并将其作为 Minikube 的附加组件。启用后，当 pod 完全可用并报告为“就绪”时，您可以使用以下命令访问 Kibana：

```
minikube service kibana-logging -n kube-system
```

这将打开一个由`kibana-logging`服务支持的网页。首次访问时，网页将要求您指定一个默认索引，该索引将用于 Elasticsearch 构建其搜索索引：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-dev/img/055a41ee-3d69-408e-8cca-7be39e12a8e6.png)

点击“创建”，采用提供的默认设置。`logstash-*`的默认索引模式并不意味着它必须来自`logstash`作为数据源，而已经从 Fluentd 发送到 ElasticSearch 的数据将直接可访问。

一旦您定义了默认索引，下一个显示的页面将向您展示已添加到 Elasticsearch 中的所有字段，因为 Fluentd 已经从容器日志和 Kubernetes 元数据中获取了数据：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-dev/img/de9d0ee0-d8ed-4ce1-b285-572b2f6ee971.png)

您可以浏览此列表，查看按字段名称捕获的内容，这将让您对可供浏览和搜索的内容有一点了解。

要查看从系统流出的日志，网页左上角的“发现”按钮将带您进入一个由我们刚刚创建的这些索引构建的视图，默认情况下将反映 Fluentd 正在收集的所有日志：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-dev/img/91c5976e-53e7-4849-9fea-fc73fd985733.png)

您看到的日志主要来自 Kubernetes 基础架构本身。为了更好地了解如何使用日志记录，启动我们之前创建的示例，并将它们扩展到多个实例以查看输出。

我们将从[`github.com/kubernetes-for-developers/kfd-flask`](https://github.com/kubernetes-for-developers/kfd-flask)获取 Flask 和 Redis 的两层示例应用程序。

```
git clone https://github.com/kubernetes-for-developers/kfd-flask -b 0.5.0
```

```
kubectl apply -f kfd-flask/deploy/
```

这将部署我们之前的 Python 和 Redis 示例，每个示例只有一个实例。一旦这些 pod 处于活动状态，返回并刷新带有 Kibana 的浏览器，它应该会更新以显示最新的日志。您可以在窗口顶部设置 Kibana 正在总结的时间段，并且如果需要，可以将其设置为定期自动刷新。

最后，让我们将 Flask 部署扩展到多个实例，这将使学习如何使用 Kibana 变得更容易：

```
kubectl scale deploy/flask --replicas=3
```

# 按应用程序筛选

有效使用 Kibana 的关键是筛选出您感兴趣的数据。默认的发现视图设置为让您了解特定来源的日志有多大，我们可以使用筛选来缩小我们想要查看的范围。

在查看数据时，从左侧滚动列表中滚动下去，每个字段都可以用作筛选器。如果您点击其中一个，例如 Kubernetes.labels.app，Kibana 将为您总结此字段在您正在查看的时间跨度内收集了哪些不同的值。

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-dev/img/cc31781e-ae3c-406b-8345-61bce34cad64.png)

在前面的示例中，您可以看到在时间跨度内的两个`app`标签是`flask`和`kubernetes-dashboard`。我们可以通过点击带有加号的放大镜图标来将其限制为仅包含这些值的日志项：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-dev/img/f3188d31-ab4c-43f0-b66b-5ff37bb2e83e.png)

带有减号符号的放大镜图标用于设置排除筛选器。由于我们之前使用`kubectl scale`命令创建了多个实例，您可以在字段列表中向下滚动到`kubernetes.pod_name`，并查看列出的并报告与第一个筛选器匹配的 pod：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-dev/img/127983ae-ea49-434c-a0bd-adf3a0d47235.png)

您现在可以将过滤器细化为仅包括其中一个，或排除其中一个 pod，以查看所有剩余的日志。随着您添加过滤器，它们将出现在屏幕顶部，通过单击该引用，您可以删除、固定或暂时禁用该过滤器。

# Lucene 查询语言

您还可以使用 Lucene 查询语言，这是 ElasticSearch 默认使用的语言，以便将搜索细化到字段内的数据，制作更复杂的过滤器，或以更精确的方式跟踪数据。Lucene 查询语言超出了本书的范围，但您可以在 Kibana 文档中获得很好的概述。

Lucene 的搜索语言是围绕搜索非结构化文本数据而设计的，因此搜索单词就像输入一个单词那样简单。多个单词被视为单独的搜索，因此如果您要搜索特定短语，请将短语放在引号中。搜索解析器还将理解简单布尔搜索的显式 OR 和 AND。

查询语法的默认设置是搜索所有字段，您可以指定要搜索的字段。要这样做，命名字段，后跟冒号，然后是搜索词。例如，要在字段`log`中搜索`error`，您可以使用此搜索查询：

```
log:error
```

此搜索查询还支持通配符搜索，使用字符`?`表示任何单个未知字符，`*`表示零个或多个字符。您还可以在查询中使用正则表达式，通过用`/`字符包装查询，例如：

```
log:/*error*/
```

这将在日志字段中搜索`error`或`errors`。

注意：因为 Lucene 会分解字段，正则表达式会应用于字符串中的每个单词，而不是整个字符串。因此，当您想要搜索组合词而不是包含空格的短语或字符串时，最好使用正则表达式。

Lucene 查询语言还包括一些高级搜索选项，可以容纳拼写错误和轻微变化，这可能非常有用。语法包括使用`~`字符作为通配符进行模糊搜索，允许拼写的轻微变化，转置等。短语还支持使用~作为变体指示符，并用于进行接近搜索，即短语中两个单词之间的最大距离。要了解这些特定技术的工作原理以及如何使用它们，请查阅[ElasticSearch 查询 DSL 文档](https://www.elastic.co/guide/en/elasticsearch/reference/6.2/query-dsl-query-string-query.html#_fuzziness)。

# 在生产环境中运行 Kibana

Kibana 还有各种其他功能，包括设置仪表板，制作数据可视化，甚至使用简单的机器学习来搜索日志数据中的异常。这些功能超出了本书的范围。您可以在 Kibana 用户指南中了解更多信息[`www.elastic.co/guide/en/kibana/current/`](https://www.elastic.co/guide/en/kibana/current/)。

运行更复杂的开发者支持工具，如 Elasticsearch，Fluentd 和 Kibana，是一项比我们在本书中所涵盖的更复杂的任务。有一些关于使用 Fluentd 和 Elasticsearch 作为附加组件的文档，就像你之前在 Minikube 示例中看到的那样。EFK 是一个需要管理的复杂应用程序。有几个 Helm 图表可能适合您的需求，或者您可能希望考虑利用云提供商的解决方案，而不是自己管理这些组件。

# 使用 Jaeger 进行分布式跟踪

当您将服务分解为多个容器时，最难理解的是请求的流动和路径，以及容器之间的交互方式。随着您扩展并使用更多容器来支持系统中的组件，了解哪些容器是哪些以及它们如何影响请求的性能将成为一个重大挑战。对于简单的系统，您通常可以添加日志记录并通过日志文件查看。当您进入由数十甚至数百个不同容器组成的服务时，这个过程变得不太可行。

这个问题的一个解决方案被称为分布式跟踪，它是一种追踪容器之间请求路径的方法，就像性能分析器可以追踪单个应用程序内的请求一样。这涉及使用支持跟踪库的库或框架来创建和传递信息，以及一个外部系统来收集这些信息并以可用的形式呈现出来。最早的例子可以在谷歌系统 Dapper 的研究论文中找到，受 Dapper 启发的早期开源实现被称为 Zipkin，由 Twitter 的工作人员制作。相同的概念已经重复出现多次，2016 年，一群人开始合作进行各种跟踪尝试。他们成立了 OpenTracing，现在是 Cloud Native Compute Foundation 的一部分，用于指定在各种系统和语言之间共享跟踪的格式。

Jaeger 是 OpenTracing 标准的一个实现，受 Dapper 和 Zipkin 启发，由 Uber 的工程师创建，并捐赠给 Cloud Native Compute Foundation。Jaeger 的完整文档可在[`jaeger.readthedocs.io/`](http://jaeger.readthedocs.io/)上找到。Jaeger 于 2017 年发布，目前正在积极开发和使用中。

还有其他跟踪平台，特别是 OpenZipkin（[`zipkin.io`](https://zipkin.io)），也可用，因此 Jaeger 并不是这个领域的唯一选择。

# 跨度和跟踪

在分布式跟踪中，有两个常见的术语，你会反复看到：跨度和跟踪。跨度是在分布式跟踪中被追踪的最小单位，代表一个接收请求并返回响应的单个过程。当该过程向其他服务发出请求以完成其工作时，它会将信息与请求一起传递，以便被请求的服务可以创建自己的跨度并引用请求的跨度。这些跨度中的每一个都被收集并从每个过程中导出，然后可以进行分析。所有共同工作的跨度的完整集合被称为跟踪。

添加、收集和传输所有这些额外信息对每个服务都是额外的开销。虽然这些信息很有价值，但它也可能产生大量信息，如果每个交互的服务都创建并发布每个跟踪，处理跟踪系统所需的数据处理量将呈指数级增长。为了为跟踪提供价值，跟踪系统已经实施了抽样，以便不是每个请求都被跟踪，但是有一个合理的数量，仍然有足够的信息来获得系统整体操作的良好表示。

不同的跟踪系统处理方式不同，服务之间传递的数据量和数据类型仍然在不断变化。此外，不遵循请求/响应模式的服务（如后台队列或扇出处理）并不容易被当前的跟踪系统所表示。数据仍然可以被捕获，但呈现处理的一致视图可能会更加复杂。

当您查看跟踪的详细信息时，通常会看到一个火焰图样式的输出，显示了每个跟踪花费的时间以及正在处理它的服务。例如，这是 Jaeger 文档中的一个跟踪详细视图示例：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-dev/img/f3ff52a5-e84b-4000-a533-5d4dae94754e.png)

# Jaeger 分布式跟踪的架构

与 Elasticsearch、Fluentd 和 Kibana（EFK）类似，Jaeger 是一个收集和处理大量信息的复杂系统。它在这里展示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-dev/img/9d20266c-5139-4f29-ada1-597a40a57514.png)

这是 Jaeger 在 2017 年在 Uber 工作的架构。配置使用了我们之前提到的 side-car 模式，每个容器都运行一个附近的容器，使用 UDP 收集来自仪器的跨度，然后将这些跨度转发到基于 Cassandra 的存储系统。设置 Cassandra 集群以及单独的收集器和查询引擎远比在本地开发环境中容易创建的要多得多。

幸运的是，Jaeger 还有一个全包选项，可以用来尝试和学习如何使用 Jaeger 以及它的功能。全包选项将代理、收集器、查询引擎和 UI 放在一个单一的容器映像中，不会持久存储任何信息。

Jaeger 项目有一体化选项，以及利用 Elasticsearch 进行持久化的 Helm 图表和变体，这些都在 GitHub 上进行了记录和存储，网址为[`github.com/jaegertracing/jaeger-kubernetes`](https://github.com/jaegertracing/jaeger-kubernetes)。事实上，Jaeger 项目通过利用 Kubernetes 来测试他们对 Jaeger 和每个组件的开发。

# 尝试 Jaeger

您可以通过使用 Jaeger 的一体化开发设置来尝试当前版本。由于他们在 GitHub 上维护这个版本，您可以直接使用以下命令从那里运行：

```
kubectl create -f https://raw.githubusercontent.com/jaegertracing/jaeger-kubernetes/master/all-in-one/jaeger-all-in-one-template.yml
```

这将创建一个部署和一些服务前端：

```
deployment "jaeger-deployment" created
service "jaeger-query" created
service "jaeger-collector" created
service "jaeger-agent" created
service "zipkin" created
```

当`jaeger-deployment` pod 报告准备就绪时，您可以使用以下命令访问 Jaeger 查询界面：

```
minikube service jaeger-query
```

生成的网页应该如下所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-dev/img/2aef79e3-c902-4065-bd20-776ff57c1d9a.png)

默认情况下，Jaeger 系统正在报告自己的操作，因此当您使用查询界面时，它也会生成自己的跟踪，您可以开始调查。窗口左侧的“查找跟踪”面板应该显示在服务 jaeger-query 上，如果您点击底部的“查找跟踪”按钮，它将根据默认参数进行搜索：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-dev/img/aa36c7cb-5d2f-492d-b685-81d5e7875ba0.png)

此页面显示了找到的所有跟踪的时间以及它们所花费的时间，允许您通过 API 端点（在此用户界面中称为操作）深入挖掘它们，限制时间跨度，并提供了一个大致表示查询处理时间的粗略表示。

这些跟踪都由单个 span 组成，因此非常简单。您可以选择其中一个 span 并查看跟踪详细信息，包括展开它捕获和传递的信息以及这些跟踪。查看完全展开的详细信息应该显示如下：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-dev/img/be759bdd-3762-4a4e-8c90-5ce79b4eb911.png)

让我们看看如何向您自己的应用程序添加追踪。

# 示例-向您的应用程序添加追踪

我们需要做几件事情来启用我们示例应用程序的追踪：

+   添加库和代码以生成跟踪

+   向您的 pod 添加一个追踪收集器边车

让我们先看看如何启用追踪边车，我们将使用之前在本书中构建的 Python Flask 示例。

这个例子的代码在线上的 GitHub 项目中[`github.com/kubernetes-for-developers/kfd-flask`](https://github.com/kubernetes-for-developers/kfd-flask)，这个添加的分支是`0.6.0`。您可以使用以下命令在本地获取此项目的代码：

```
git clone https://github.com/kubernetes-for-developers/kfd-flask -b 0.6.0
```

# 向您的 pod 添加跟踪收集器

实现 open-tracing 的库通常使用非常轻量级的网络连接，比如 UDP，来从我们的代码发送跟踪信息。UDP 不能保证连接，这也意味着如果网络过于拥挤，跟踪信息可能会丢失。OpenTracing 和 Jaeger 通过利用 Kubernetes 的一个保证来最小化这种情况：同一个 pod 中的两个容器将被放置在同一个节点上，共享相同的网络空间。如果我们在 pod 中的另一个容器中运行一个捕获 UDP 数据包的进程，网络连接将全部在同一个节点上，并且干扰的可能性非常小。

Jaeger 项目有一个镜像，它监听各种端口以捕获这些跟踪信息，并将其转发到存储和查询系统。容器`jaegertracing/jaeger-agent`发布到 DockerHub，并保持非常小的镜像大小（版本 1.2 为 5 MB）。这个小尺寸和靠近我们应用程序的好处使它非常适合作为一个辅助容器运行：在我们的 pod 中支持主要进程的另一个容器。

我们可以通过向我们 flask 部署（`deploy/flask.yaml`）中定义的 pod 添加另一个容器来实现这一点：

```
 - name: jaeger-agent
   image: jaegertracing/jaeger-agent
   ports:
   - containerPort: 5775
     protocol: UDP
   - containerPort: 5778
   - containerPort: 6831
     protocol: UDP
   - containerPort: 6832
     protocol: UDP
   command:
   - "/go/bin/agent-linux"
   - "--collector.host-port=jaeger-collector:14267"
```

这个例子是基于 Jaeger [部署文档](https://jaeger.readthedocs.io/en/latest/deployment/)，它提供了如何在 Docker 中使用它的示例，但不是直接在 Kubernetes 中使用。

重要的是要注意我们在这个容器中的命令。默认情况下，容器运行`/go/bin/agent-linux`，但没有任何选项。为了将数据发送到我们本地安装的 Jaeger，我们需要告诉收集器要发送到哪里。目的地由选项`--collector.host-port`定义。

在这种情况下，我们将 Jaeger all-in-one 安装到默认命名空间中，并包括一个名为`jaeger-collector`的服务，因此该服务将直接可用于此 pod。如果您在集群中安装了更强大的 Jaeger，您可能还将其定义在不同的命名空间中。例如，Jaeger 的 Helm 安装将安装到一个名为`jaeger-infra`的命名空间中，在这种情况下，`collector.host-port`选项的值需要更改以反映这一点：`jaeger-collector.jaeger-infra.svc:14267`。

这里 Jaeger 还使用了多个端口，故意允许代理从备用语言使用的多种传统机制中收集。我们将使用 UDP 端口`6382`用于`python jaeger-tracing`客户端库。

# 添加生成跟踪的库和代码

我们首先为跟踪添加了两个库到我们的项目中：`jaeger-client`和`flask_opentracing`。`flask-opentracing`将跟踪添加到 Flask 项目中，以便您可以轻松地自动跟踪所有 HTTP 端点。OpenTracing 项目不包括任何收集器，因此我们还需要一个库来收集和发送跟踪数据到某个地方，这里是 jaeger-client。

该示例还添加了 requests 库，因为在这个示例中，我们将添加一个进行远程请求、处理响应并返回值的 HTTP 端点，并对该序列进行跟踪。

导入库并初始化跟踪器非常简单：

```
import opentracing
from jaeger_client import Config
from flask_opentracing import FlaskTracer

# defaults to reporting via UDP, port 6831, to localhost
def initialize_tracer():
    config = Config(
        config={
            'sampler': {
                'type': 'const',
                'param': 1
            },
            'logging': True
        },
        service_name='flask-service'
    )
    # also sets opentracing.tracer
    return config.initialize_tracer() 

```

Jeager 建议您间接使用一种方法来初始化跟踪器，如前所示。在这种情况下，配置将采样器设置为转发所有请求；在生产中使用时，您需要仔细考虑这一配置选项，因为在高负载服务中跟踪每个请求可能会很繁重。

在创建 Flask 应用程序后立即初始化跟踪器：

```
app = Flask(__name__)flask_tracer = FlaskTracer(initialize_tracer, True, app, ["url_rule"])
```

这将与 Flask 一起使用，为所有`@app.routes`添加跟踪，每个路由将被标记为基于 Python 函数名称的操作。您还可以使用不同的配置设置仅跟踪特定路由，并在 Flask 路由上添加跟踪注释。

重建 Flask 图像并部署它将立即开始生成跟踪，并且在侧车中运行 jaeger-agent 的情况下，本地`jaeger dev`实例将立即显示跟踪。您应该看到一个名为`flask-service`的服务，基于我们的应用程序名称，并且它应该在其中列出多个操作：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-dev/img/ec715a4c-c36b-4f60-81f2-fd0e0365c833.png)

活动，就绪和指标操作是启用以支持活动性和就绪性探针以及`prometheus`指标的 Flask 路由，这已在我们的示例 pod 上定义，它们正在获得一致的连接，从而生成与请求相关的跟踪。

这本身就很有用，但尚未告诉您方法中的哪个部分花费了更多或更少的时间。您可以使用`flask-opentracing`安装的`opentracing`库在您感兴趣的方法或代码段周围添加跟踪 span，以下代码片段显示了如何使用跟踪 span 包装我们在就绪探针中使用的对 Redis 的调用，以便它将单独显示出来：

```
@app.route('/ready')
def ready():
  parent_span = flask_tracer.get_span()
  with opentracing.tracer.start_span('redis-ping', child_of=parent_span) as span:
    result = redis_store.ping()
    span.set_tag("redis-ping", result)
  if result:
    return "Yes"
  else:
    abort(500)
```

关键在于获取我们为每个请求生成的当前跟踪 span，使用`flask_tracer.get_span()`，然后在`with`语句中使用它，这将在该上下文中执行的代码块中添加 span。我们还可以在 span 上使用方法，该方法在该代码块中可用。我们使用`set_tag`方法添加一个带有 ping 结果值的标签，以便在特定的跟踪输出中可用。

我们将继续添加一个`@app.route`称为`/remote`，以进行对 GitHub 的远程 HTTP 请求，并在其周围添加跟踪以将其显示为子 span：

```
@app.route('/remote')
def pull_requests():
    parent_span = flask_tracer.get_span()
    github_url = "https://api.github.com/repos/opentracing/opentracing-python/pulls"

    with opentracing.tracer.start_span('github-api', child_of=parent_span) as span:
        span.set_tag("http.url",github_url)
        r = requests.get(github_url)
        span.set_tag("http.status_code", r.status_code)

    with opentracing.tracer.start_span('parse-json', child_of=parent_span) as span:
        json = r.json()
        span.set_tag("pull_requests", len(json))
        pull_request_titles = map(lambda item: item['title'], json)
    return 'PRs: ' + ', '.join(pull_request_titles)
```

这个例子类似于就绪探针，只是我们在不同的代码段中包装不同的部分，并明确命名它们：`github-api` 和 `parse-json`。

在添加代码时，您可以使用`kubectl delete`和`kubectl apply`等命令来重新创建部署并将其构建并推送到您的容器注册表。对于这些示例，我的模式是从项目的主目录运行以下命令：

```
kubectl delete deploy/flask
docker build -t quay.io/kubernetes-for-developers/flask:0.6.0 .
docker push quay.io/kubernetes-for-developers/flask
kubectl apply -f deploy/
```

您将需要用项目中的值替换图像注册表引用和 Docker 标记。

然后，使用以下命令检查部署的状态：

```
kubectl get pods 
```

```
NAME                              READY STATUS RESTARTS AGE
flask-76f8c9767-56z4f             0/2   Init:0/1 0 6s
jaeger-deployment-559c8b9b8-jrq6c 1/1   Running 0 5d
redis-master-75c798658b-cxnmp     1/1   Running 0 5d
```

一旦它完全在线，您将看到它报告为就绪：

```
NAME                              READY STATUS RESTARTS AGE
flask-76f8c9767-56z4f             2/2   Running 0 1m
jaeger-deployment-559c8b9b8-jrq6c 1/1   Running 0 5d
redis-master-75c798658b-cxnmp     1/1   Running 0 5d
```

2/2 显示有两个容器正在运行 Flask pod，我们的主要代码和 jaeger-agent side-car。

如果您使用 Minikube，还可以使用服务命令轻松在浏览器中打开这些端点：

```
minikube service list
```

```

|-------------|----------------------|----------------------------|
| NAMESPACE   | NAME                 | URL                        |
|-------------|----------------------|----------------------------|
| default     | flask-service        | http://192.168.64.33:30676 |
| default     | jaeger-agent         | No node port               |
| default     | jaeger-collector     | No node port               |
| default     | jaeger-query         | http://192.168.64.33:30854 |
| default     | kubernetes           | No node port               |
| default     | redis-service        | No node port               |
| default     | zipkin               | No node port               |
| kube-system | kube-dns             | No node port               |
| kube-system | kubernetes-dashboard | http://192.168.64.33:30000 |
| kube-system | tiller-deploy        | No node port               |
|-------------|----------------------|----------------------------|
```

任何具有节点端口设置的服务都可以通过诸如以下命令轻松在本地打开：

```
minikube service flask-service
```

```
minikube service jaeger-query
```

添加、构建和部署此代码后，您可以在 Jaeger 中看到跟踪。将浏览器定向到`/remote`发出一些请求以从请求生成跨度，并且在 Jaeger 查询浏览器中，您应该看到类似以下内容：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-dev/img/a8091b4e-1492-4e78-8a35-e54de9554fa2.png)

Jaeger 查询窗口的顶部将显示表示查询时间和相对持续时间的点，您将看到它找到的各种跟踪列表-在我们的情况下有四个。如果选择一个跟踪，您可以进入详细视图，其中将包括子跨度。单击跨度以从中获取更多详细信息：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-dev/img/f21aaceb-4f92-4027-bca9-3ba531a43300.png)

通过跨度详细视图，您可以查看在代码中设置的任何标签，并且您可以看到`github-api`调用在响应`/remote`请求时花费了大部分时间（265/266 毫秒）。

# 添加跟踪的考虑事项

跟踪是一个非常强大的工具，但也伴随着成本。每个跟踪都会（虽然很小）增加一些处理和管理的开销。您可能会很兴奋地将跟踪添加到应用程序中的每个方法，或者将其构建到一个库中，该库会将跟踪和跨度创建附加到每个方法调用中。这是可以做到的，但您很快会发现您的基础设施被跟踪信息所淹没。

跟踪也是一个工具，当直接与运行代码的责任直接相关时，它具有最大的好处。请注意，随着您添加跟踪，还会添加许多辅助处理，以捕获、存储和查询跟踪生成的数据。

处理权衡的一个好方法是有意识地、迭代地和缓慢地添加跟踪-以获得您需要的可见性。

OpenTracing 作为一个标准得到了许多供应商的支持。OpenTracing 也是一个不断发展的标准。在撰写本书时，人们正在讨论如何最好地共享和处理跨进程请求中携带的跨度数据（通常称为“行李”）。像追踪本身一样，添加数据可以增加价值，但这也带来了更大的请求成本和更多的处理需求来捕获和处理信息。

# 总结

在本章中，我们介绍了使用 Fluentd 和 Jaeger 进行日志记录和跟踪。我们展示了如何部署它并使用它，在代码运行时捕获和聚合数据。我们演示了如何使用 Elasticsearch 查询数据。我们还看了如何查看 Jaeger 跟踪以及如何向代码添加跟踪。

在下一章中，我们将探讨如何使用 Kubernetes 来支持和运行集成测试，以及如何将其与持续集成一起使用。


# 第九章：集成测试

到目前为止，我们已经了解了如何在 Kubernetes 中运行代码并描述服务。我们还研究了如何利用其他工具来获取有关代码在每个 pod 和整体上运行情况的信息。本章将在此基础上，探讨如何使用 Kubernetes 来验证代码，以及不同验证测试的示例，以及如何利用 Kubernetes 进行验证测试的建议。

本章的主题包括：

+   使用 Kubernetes 的测试策略

+   使用 Bats 进行简单验证

+   示例 - 使用 Python 测试代码

+   示例 - 使用 Node.js 测试代码

+   使用 Kubernetes 进行持续集成

# 使用 Kubernetes 的测试策略

在软件工程中，开发和验证过程中使用了各种测试。在这个分类中，有一些测试类型非常适合利用 Kubernetes 的优势。与测试相关的术语可能含糊不清，令人困惑，因此为了清晰起见，我们将简要回顾我将使用的术语以及这些测试类型之间的区别。这里没有详细介绍这些主题的更多变体，但为了描述 Kubernetes 最有效的地方，这个列表已经足够：

+   单元测试：单元测试是测试的最低级别；它侧重于应用程序中的接口、实现和模块。单元测试通常意味着仅对测试重点的组件进行隔离测试。这些测试通常旨在非常快速，可以直接在开发人员的系统上运行，并且通常不需要访问相关代码可能依赖的外部服务。这些测试通常不涉及状态或持久性，主要关注业务逻辑和接口验证。

+   功能测试：功能测试是从单元测试中提升的下一步，意味着代码库针对其基础系统进行测试，而无需伪装、模拟或其他层，否则会假装像远程依赖一样运行。这种测试通常应用于服务的子集，测试和验证完整的服务，并使用即时依赖项（通常是数据库或持久性存储）。功能测试通常意味着对持久性存储中的状态进行验证，以及在代码运行过程中如何改变。

+   **集成测试**：集成测试将软件的所有必需部分组合在一起，并验证各个组件以及组件之间的工作和交互。系统的状态通常在集成测试中被定义或设置为关键设置，因为状态在系统中被表示和验证，所以测试往往是有序和更线性的，通常使用组合交互来验证代码的工作方式（以及失败方式）。

功能测试和集成测试之间存在模糊的界限，前者通常专注于验证整体服务的子集，而后者代表着服务的大部分或整个系统。

+   **端到端测试**：集成测试可能意味着测试系统的一部分，而端到端测试则特指测试和验证整个系统及其所有依赖关系。通常，端到端测试和集成测试是可以互换使用的。

+   **性能测试**：在先前的术语中，重点是代码和任何相关依赖项之间的验证范围，性能测试侧重于验证类型而不是范围。这些测试意在衡量代码和服务的效率或利用率；它们利用了多少 CPU 和内存，以及在给定一组基础资源的情况下它们的响应速度。它们不是专注于代码的正确性，而是专注于规模和基础服务需求的验证。性能测试通常需要依赖系统不仅正常运行，而且需要充分资源以提供准确的结果，并且在某种程度上具有期望隔离，以防止外部资源限制人为地限制结果。

+   **交互/探索性测试**：交互测试，有时也被称为探索性测试，再次不是关于范围的术语，而是意味着一种意图。这些测试通常需要系统的至少一部分处于运行状态，并且通常意味着整个系统处于运行状态，如果不是为了支持高水平的请求。这些测试侧重于让人们与系统进行交互，而不需要预定义或结构化的事件流，这种设置通常也用于接受验证或其他测试类型的改进，作为验证测试本身的手段。

# 审查测试所需的资源

当我们遍历测试的分类时，运行测试所需的计算资源和时间通常会增长并变得更加重要。根据正在开发的软件的范围，很可能需要比单台机器可以容纳的资源更多。而低级别的测试通常可以优化以利用计算机内的所有可能资源，端到端测试的串行性质往往效率较低，并且在验证过程中需要更多时间。

在建立测试时，您需要意识到验证软件所需的计算资源的大小。这可能对应于确定给定 pod 需要多少内存和 CPU 的过程，并且需要意识到基于您正在测试和想要实现的内容，所有依赖项的所有资源。

在大多数示例中，我们一直在使用 Minikube，但是现代开发和依赖关系很容易超出 Minikube 单节点集群所能提供的资源量。

在测试中使用 Kubernetes 最有效的地方是，您希望设置和使用与集成测试和测试场景相对应的环境的大部分内容，并且期望具有所有依赖项运行的完整系统。

当您专注于集成、端到端以及先前概述的分类的后续部分时，您当然可以在开发过程中使用 Kubernetes 运行诸如单元测试或功能测试之类的测试，尽管您可能会发现，在集成、端到端以及先前概述的分类的后续部分时，从 Kubernetes 中获得更多的好处。

由于 Kubernetes 擅长描述服务的期望状态并保持其运行，因此在您希望设置大部分或许多服务相互交互的地方，它可以被非常有效地使用。此外，如果您期望测试需要更多时间和资源，Kubernetes 也是一个很好的选择，因为它要求您将代码锁定到离散的、有版本的容器中，这也可能需要大量的时间和处理。

# 使用 Kubernetes 进行测试的模式

有很多种方式可以使用 Kubernetes 进行测试，而您需要确定的第一件事情之一是，您正在运行被测试系统的位置，以及您正在运行将验证该系统的测试的位置。

# 在 Kubernetes 中测试本地和系统测试

最常见的模式，特别是在开发测试时，是从开发机器上运行测试，针对在 Kubernetes 中运行的代码。创建测试后，可以使用相同的模式来针对托管代码的 Kubernetes 集群运行测试，从而实现持续集成服务。当您开始进行开发时，您可能能够在本地开发机器上运行所有这些操作，使用 Minikube。总的来说，这种模式是一个很好的开始方式，并解决了通过在您想要获得反馈的地方运行测试来获得反馈的问题——无论是在您自己的开发系统上，还是在代表您运行的 CI 系统上。

# 在之前的模式中，以及本书中大多数示例中，我们使用了默认命名空间，但所有命令都可以通过简单地在 kubectl 命令中添加`-n <namespace>`来包括一个命名空间作为选项。

如果您测试的系统超出了 Minikube 的支持范围，常见的解决方案是开始使用远程集群，无论是由您、您的 IT 团队还是云提供商管理。当您开始使用远程计算时，共享和隔离变得重要，特别是对于依赖于系统状态的测试，其中对该状态的控制对于理解验证是否正确非常关键。Kubernetes 通常具有良好的隔离性，并且利用命名空间的工作方式可以使代码的设置和测试变得更加容易。您可以通过在单个命名空间中运行相关的 pod 和服务，并通过利用每个服务的短 DNS 名称在它们之间进行一致引用来利用命名空间。这可以被视为一个堆栈，您可以有效地并行部署许多这样的堆栈。

命名空间支持各种资源的配额，您会想要查看定义的内容并验证您是否设置了足够的配额。特别是在共享环境中，使用配额来限制消耗是常见的。

# Kubernetes 中的测试和 Kubernetes 命名空间中的系统

主题的一个变化是在 Kubernetes 中打包和运行您的测试 - 无论是在相同的命名空间中，还是在与您的被测系统不同的命名空间中。这比在本地运行测试要慢，因为它要求您将测试打包到容器中，就像您对代码所做的那样。权衡是拥有非常一致的方式来运行这些测试并与被测系统进行交互。

如果您在一个非常多样化的开发环境中工作，每个人的设置都略有不同，那么这种模式可以整合测试，以便每个人都有相同的体验。此外，当本地测试需要通过暴露的服务（例如使用 Minikube 的 NodePort，或者在提供程序上使用`LoadBalancer`）访问远程 Kubernetes 时，您可以通过使用服务名称来简化访问，无论是在相同的命名空间中还是在包含命名空间的较长的服务名称中。

在 Kubernetes 中运行测试的另一个挑战是获取结果。虽然完全可以收集结果并将其发布到远程位置，但这种模式并不常见。使用这种模式时更常见的解决方案是拥有一个专门用于测试的集群，其中还包括一些持续集成基础设施，可以作为集群的一部分，或者与集群并行并具有专用访问权限，然后运行测试并捕获结果作为测试自动化的一部分。我们将在本章后面更深入地研究持续集成。

# 使用 Bats 进行简单验证

一个相当普遍的愿望是简单地部署所有内容并进行一些查询，以验证生成的系统是否可操作。当您执行这些操作时，它们经常被捕获在 Makefiles 或 shell 脚本中，作为验证功能基线的简单程序。几年前，开发了一个名为 Bats 的系统，它代表 Bash 自动化测试系统，旨在使使用 shell 脚本运行测试变得更加方便。

有几个示例使用 Bats 来测试部署在 Kubernetes 中的系统。这些测试通常很简单易懂，易于扩展和使用。您可以在其 GitHub 主页[`github.com/sstephenson/bats`](https://github.com/sstephenson/bats)上找到更多关于 Bats 的信息。您可能也会在一些与 Kubernetes 相关的项目中看到 Bats 的使用，用于简单验证。

Bitnami 已经建立了一个示例 GitHub 存储库，用作使用 Bats 和 Minikube 的起点，并且设计为与 Travis.CI 等外部 CI 系统一起使用。您可以在[`github.com/bitnami/kubernetes-travis`](https://github.com/bitnami/kubernetes-travis)找到示例。

如果您使用 Bats，您将需要有辅助脚本来设置您的部署，并等待相关部署报告就绪，或者在设置时失败测试。在 Bitnami 示例中，脚本`cluster_common.bash`和`libtest.bash`具有这些辅助函数。如果您想使用这条路径，可以从他们的存储库中开始，并更新和扩展它们以匹配您的需求。

集成测试从加载库和创建本地集群开始，然后部署正在测试的系统：

```
# __main__ () {
. scripts/cluster_common.bash
. scripts/libtest.bash
# Create the 'minikube' or 'dind' cluster
create_k8s_cluster ${TEST_CONTEXT}
# Deploy our stack
bats tests/deploy-stack.bats
```

`deploy-stacks.bats`可以表示为一个 Bats 测试，在 Bitnami 示例中，它验证了 Kubernetes 工具在本地是否都已定义，然后将部署本身封装为一个测试：

这是来自示例[`github.com/bitnami/kubernetes-travis/blob/master/tests/deploy-stack.bats`](https://github.com/bitnami/kubernetes-travis/blob/master/tests/deploy-stack.bats)：

```
# Bit of sanity
@test "Verify needed kubernetes tools installed" {
 verify_k8s_tools
}
@test "Deploy stack" {
# Deploy the stack we want to test
./scripts/deploy.sh delete >& /dev/null || true
./scripts/deploy.sh create
   k8s_wait_for_pod_running --namespace=kube-system -lname=traefik-ingress-lb
   k8s_wait_for_pod_running -lapp=my-nginx
}
```

脚本`deploy.sh`设置为删除或创建和加载清单，就像我们在本书中早些时候所做的那样，使用`kubectl create`，`kubectl delete`或`kubectl apply`命令。

完成后，集成测试继续获取对集群的访问。在 Bitnami 示例中，他们使用 Kubernetes Ingress 来一致地访问集群，并设置脚本来捕获和返回访问底层系统的 IP 地址和 URL 路径通过`Ingress`。您也可以使用`kubectl port-forward`或`kubectl proxy`，就像我们在本书中早些时候展示的那样：

```
# Set env vars for our test suite
# INGRESS_IP: depend on the deployed cluster (dind or minikube)
INGRESS_IP=$(get_ingress_ip ${TEST_CONTEXT})
# URL_PATH: Dynamically find it from 1st ingress rule
URL_PATH=$(kubectl get ing -ojsonpath='{.items[0].spec.rules[0].http.paths[0].path}')
# Verify no empty vars:
: ${INGRESS_IP:?} ${URL_PATH:?}
```

设置完成后，再次使用 Bats 调用集成测试，并捕获整个过程的退出代码，并用于反映测试是否成功或失败：

```
# With the stack ready, now run the tests thru bats:
export SVC_URL="http://my-nginx.default.svc${URL_PATH:?}"
export ING_URL="${INGRESS_IP:?}${URL_PATH:?}"
bats tests/integration-tests.bats
exit_code=$?

[[ ${exit_code} == 0 ]] && echo "TESTS: PASS" || echo "TESTS: FAIL"
exit ${exit_code}
# }
```

虽然这很容易入门，但在 bash 中编程很快就成为了自己的专业领域，而基本的 bash 使用频繁且易于理解，但在该示例中的一些更复杂的辅助功能可能需要一些挖掘才能完全理解。

如果您在使用 shell 脚本时遇到问题，常见的调试解决方案是在脚本顶部附近添加`set -x`。在 bash 中，这会打开命令回显，以便将脚本中的所有命令回显到标准输出，以便您可以看到发生了什么。

一个很好的模式是使用您熟悉的语言编写测试。您经常可以利用这些语言的测试框架来帮助您。您可能仍然希望使用像 Bitnami 示例那样的 shell 脚本来设置和部署代码到您的集群，并且对于测试，使用您更熟悉的语言的逻辑和结构。

# 示例 - 使用 Python 进行集成测试

在 Python 的情况下，这里的示例代码使用 PyTest 作为测试框架。示例代码可以在 GitHub 上找到，位于存储库的 0.7.0 分支中[`github.com/kubernetes-for-developers/kfd-flask/`](https://github.com/kubernetes-for-developers/kfd-flask/)。

您可以使用以下命令下载示例：

```
git clone https://github.com/kubernetes-for-developers/kfd-flask/ -b 0.7.0
```

在这个示例中，我改变了代码结构，将应用程序本身的所有 Python 代码移动到`src`目录下，遵循了 PyTest 的推荐模式。如果您以前没有使用过 PyTest，请查看他们的最佳实践[`docs.pytest.org/en/latest/goodpractices.html`](https://docs.pytest.org/en/latest/goodpractices.html)，这是非常值得的。

如果您查看代码或下载它，您还会注意到一个新文件`test-dependencies.txt`，其中定义了一些特定于测试的依赖项。Python 没有一个将生产环境的依赖项与开发或测试中使用的依赖项分开的清单，所以我自己分开了这些依赖项：

```
pytest
pytest-dependency
kubernetes
requests
```

实际的集成测试存放在`e2e_tests`目录下，主要作为一个模式，让您在正常开发过程中可以有一个本地目录用于创建任何单元测试或功能测试。

我在这个示例中使用的模式是利用我们在 Kubernetes 中的代码，并在集群外部访问它，利用 Minikube。如果您的环境需要比您本地开发机器上可用的资源更多，同样的模式也可以很好地与托管在 AWS、Google 或 Azure 中的集群配合使用。

`e2e_tests`中的`README`文件显示了如何运行测试的示例。我利用`pip`和`virtualenv`来设置本地环境，安装依赖项，然后使用 PyTest 直接运行测试：

```
virtualenv .venv
source .venv/bin/activate
pip3 install -r test-requirements.txt
pytest -v
```

如果你运行这些测试，你应该会看到类似以下的输出：

```
======= test session starts =======
platform darwin -- Python 3.6.4, pytest-3.4.2, py-1.5.2, pluggy-0.6.0 -- /Users/heckj/src/kfd-flask/e2e_tests/.venv/bin/python3.6
cachedir: .pytest_cache
rootdir: /Users/heckj/src/kfd-flask/e2e_tests, inifile:
plugins: dependency-0.3.2
collected 7 items

tests/test_smoke.py::test_kubernetes_components_healthy PASSED [ 14%]
tests/test_smoke.py::test_deployment PASSED [ 28%]
tests/test_smoke.py::test_list_pods PASSED [ 42%]
tests/test_smoke.py::test_deployment_ready PASSED [ 57%]
tests/test_smoke.py::test_pods_running PASSED [ 71%]
tests/test_smoke.py::test_service_response PASSED [ 85%]
tests/test_smoke.py::test_python_client_service_response PASSED [100%]

======= 7 passed in 1.27 seconds =======
```

PyTest 包括大量的插件，包括一种以 JUnit XML 格式导出测试结果的方法。您可以通过使用`--junitxml`选项调用 PyTest 来获得这样的报告：

```
pytest --junitxml=results.xml
```

这些测试中的代码利用了我们迄今为止构建的示例：我们的部署 YAML 和我们用代码在存储库中制作的图像。测试对集群的可用性和健康进行了简单的验证（以及我们是否可以与其通信），然后使用`kubectl`来部署我们的代码。然后等待代码部署，定义了最大超时时间，然后继续与服务交互并获得简单的响应。

这个例子主要是为了向您展示如何与远程 Kubernetes 集群交互，包括使用`python-kubernetes`客户端库。

# PyTest 和 pytest-dependency

PyTest 首先是一个单元测试框架。单元测试框架通常对集成测试有不同的需求，幸运的是，PyTest 有一种方法允许开发人员指定一个测试需要在另一个测试之前运行和完成。这是通过`pytest-dependency`插件完成的。在代码中，您会看到一些测试用例被标记为依赖标记。要使用这个插件，您需要定义哪些测试可以成为依赖目标，以及任何需要在其后运行的测试，您需要定义它们依赖的测试：

```
@pytest.mark.dependency()
def test_kubernetes_components_healthy(kube_v1_client):
    # iterates through the core kuberneters components to verify the cluster is reporting healthy
    ret = kube_v1_client.list_component_status()
    for item in ret.items:
        assert item.conditions[0].type == "Healthy"
        print("%s: %s" % (item.metadata.name, item.conditions[0].type))
```

这个测试检查集群是否可访问并且响应正常。这个测试不依赖于其他任何测试，所以它只有基本的注释，而下面的测试将指定这个测试需要在运行之前完成，使用这个注释：

```
@pytest.mark.dependency(depends=["test_kubernetes_components_healthy"])
```

这可能会使测试注释非常冗长，但允许您明确定义执行顺序。默认情况下，大多数单元测试框架不保证特定的执行顺序，当您测试包含状态和对该状态的更改的系统时，这可能是至关重要的——这正是我们进行集成测试的内容。

# PyTest 固定装置和 python-kubernetes 客户端

前面的示例还利用了一个简单的文本 fixture，为我们提供了一个 Python Kubernetes 客户端的实例，以便与集群进行交互。Python 客户端可能难以使用，因为它是从 OpenAPI 规范生成的，并且对于每个 API 端点都有类设置，而这些端点有好几个。特别是，随着 Kubernetes API 的各个部分通过 alpha、beta 和最终发布阶段的演变，这些 API 端点将移动，这意味着您使用的客户端代码可能需要随着您与之交互的 Kubernetes 集群版本的升级而更改。

`python-kubernetes`客户端确实带有现成的源代码和所有方法的生成索引，我建议如果您要使用客户端，最好随时准备好这些。代码存放在[`github.com/kubernetes-client/python`](https://github.com/kubernetes-client/python)，发布版本存储在分支中。我使用的版本是 5.0，与 Kubernetes 版本 1.9 配对，并支持早期版本。包含所有 OpenAPI 生成方法文档的`README`可在[`github.com/kubernetes-client/python/blob/release-5.0/kubernetes/README.md`](https://github.com/kubernetes-client/python/blob/release-5.0/kubernetes/README.md)找到。

一个 PyTest fixture 为其他测试设置了客户端：

```
@pytest.fixture
def kube_v1_client():
    kubernetes.config.load_kube_config()
    v1 = kubernetes.client.CoreV1Api()
    return v1
```

在这种情况下，客户端加载本地可用的`kubeconfig`以访问集群。根据您的开发环境，您可能需要调查其他身份验证到集群的替代方法。

虽然可以使用 python-kubernetes 客户端进行部署，但示例还展示了如何使用本地`kubectl`命令行与集群进行交互。在这种情况下，与在 Python 中定义要部署的完整定义相比，代码行数要少得多：

```
@pytest.mark.dependency(depends=["test_kubernetes_components_healthy"])
def test_deployment():
    # https://docs.python.org/3/library/subprocess.html#subprocess.run
    # using check=True will throw an exception if a non-zero exit code is returned, saving us the need to assert
    # using timeout=10 will throw an exception if the process doesn't return within 10 seconds
    # Enables the deployment
    process_result = subprocess.run('kubectl apply -f ../deploy/', check=True, shell=True, timeout=10)
```

如果您想利用其他工具部署您的代码，这种机制可能非常有价值，并且在编写集成测试时始终是一个有用的后备。还要注意，这个测试依赖于我们之前提到的测试，强制它在集群健康验证测试之后运行。

请注意，当系统失败时调试这些命令可能会更加困难，因为很多事情都发生在实际测试之外，比如这样的命令。您需要了解调用测试的进程，它相对于您的环境的权限等。

# 等待状态变化

部署后，我们期望部署和服务都变为活动状态，但这并不是瞬间发生的。根据您的环境，它可能会发生得非常快，也可能会发生得相当慢。集成测试的问题在于无法知道何时完成某些操作，并通过调用`sleep()`来解决问题，等待更长时间。在这个例子中，我们明确检查状态，而不是只等待任意时间，希望系统已准备就绪：

```
@pytest.mark.dependency(depends=["test_deployment_ready"])
def test_pods_running(kube_v1_client):
    TOTAL_TIMEOUT_SECONDS = 300
    DELAY_BETWEEN_REQUESTS_SECONDS = 5
    now = time.time()
    while (time.time() < now+TOTAL_TIMEOUT_SECONDS):
        pod_list = kube_v1_client.list_namespaced_pod("default")
        print("name\tphase\tcondition\tstatus")
        for pod in pod_list.items:
            for condition in pod.status.conditions:
                print("%s\t%s\t%s\t%s" % (pod.metadata.name, pod.status.phase, condition.type, condition.status))
                if condition.type == 'Ready' and condition.status == 'True':
                    return
        time.sleep(DELAY_BETWEEN_REQUESTS_SECONDS)
    assert False
```

此示例的部署最大超时时间为`300`秒，包括在继续之前请求环境状态的短暂延迟。如果超过总超时时间，测试将报告失败，并且通过使用`pytest-dependency`，所有依赖于此的后续测试都不会运行，从而中断测试过程以报告失败。

# 访问部署

最后两个测试突出了与集群内运行的代码交互的两种方式。

第一个示例期望设置并运行提供对测试之外的集群的访问，并简单地使用 Python 的`requests`库直接发出 HTTP 请求：

```
@pytest.mark.dependency(depends=["test_deployment_ready"])
def test_service_response(kubectl_proxy):
    NAMESPACE="default"
    SERVICE_NAME="flask-service"
    URI = "http://localhost:8001/api/v1/namespaces/%s/services/%s/proxy/" % (NAMESPACE, SERVICE_NAME)
    print("requesting %s" % (URI))
    r = requests.get(URI)
    assert r.status_code == 200
```

这是一个非常基本的测试，而且相当脆弱。它使用了代码中早期定义的 PyTest 夹具来设置`kubectl proxy`的调用，以提供对集群的访问：

```
@pytest.fixture(scope="module")
def kubectl_proxy():
    # establish proxy for kubectl communications
    # https://docs.python.org/3/library/subprocess.html#subprocess-replacements
    proxy = subprocess.Popen("kubectl proxy &", stdout=subprocess.PIPE, shell=True)
    yield
    # terminate the proxy
    proxy.kill()
```

虽然这通常有效，但当事情失败时，要追踪问题就更难了，而且在设置（和拆除）分叉 shell 命令中，夹具机制并不完全可靠。

第二个示例使用 python-kubernetes 客户端通过一系列方法访问服务，这些方法允许您通过 Kubernetes 附带的代理轻松调用 HTTP 请求。客户端配置负责对集群进行身份验证，并且您可以通过直接利用客户端而不是使用外部代理来访问代码，通过代理访问：

```
@pytest.mark.dependency(depends=["test_deployment_ready"]) def test_python_client_service_response(kube_v1_client):
    from pprint import pprint
    from kubernetes.client.rest import ApiException
    NAMESPACE="default"
    SERVICE_NAME="flask-service"
    try:
        api_response = kube_v1_client.proxy_get_namespaced_service(SERVICE_NAME, NAMESPACE)
        pprint(api_response)
        api_response = kube_v1_client.proxy_get_namespaced_service_with_path(SERVICE_NAME, NAMESPACE, "/metrics")
        pprint(api_response)
    except ApiException as e:
        print("Exception when calling CoreV1Api->proxy_get_namespaced_service: %s\n" % e)
```

如果您不需要在 HTTP 请求中操纵标头或以其他方式复杂化，这种机制非常适用，当使用通用的 Python 客户端（如`requests`）时更易于访问。有一整套支持各种 HTTP/REST 风格调用的方法，所有这些方法都以`proxy`为前缀：

+   `proxy_get`

+   `proxy_delete`

+   `proxy_head`

+   `proxy_options`

+   `proxy_patch`

+   ``proxy_put``

每个都映射到以下端点：

+   `namespaced_pod`

+   `namespaced_pod_with_path`

+   `namespaced_service`

+   `namespaced_service_with_path`

这使您可以在标准的 REST 命令中发送命令，直接发送到 pod 或服务端点。`with_path`选项允许您定义与 pod 或服务上交互的特定 URI。

# 示例-使用 Node.js 进行集成测试

Node.js 示例与 Python 示例类似，使用了 mocha、chai、supertest 和 JavaScript kubernetes 客户端。示例代码可以在 GitHub 上找到，位于存储库的 0.7.0 分支中[`github.com/kubernetes-for-developers/kfd-nodejs/`](https://github.com/kubernetes-for-developers/kfd-nodejs/)。

您可以使用以下命令下载示例：

```
git clone https://github.com/kubernetes-for-developers/kfd-nodejs/ -b 0.7.0
```

我利用了 Node.js 的机制，将开发依赖项与生产依赖项分开，并将大部分这些依赖项添加到了`package.json`中。我还继续在`test`目录中直接设置了一个简单的单元测试，并在`e2e-tests`目录中设置了一个单独的集成测试。我还设置了命令，以便您可以通过`npm`运行这些测试：

```
npm test
```

对于单元测试，代码在本地运行，并利用`supertest`来访问本地计算机上的 JavaScript 运行时中的所有内容。这不包括任何远程服务或系统（例如与依赖于 Redis 的端点进行交互）：

```
> kfd-nodejs@0.0.0 test /Users/heckj/src/kfd-nodejs
> mocha --exit

express app
GET / 200 283.466 ms - 170
 ✓ should respond at the root (302ms)
GET /probes/alive 200 0.930 ms - 3
 ✓ should respond at the liveness probe point

 2 passing (323ms)
```

在`e2e_tests`目录中，有一个类似于 Python 测试的模拟，用于验证集群是否正常运行，设置部署，然后访问该代码。可以使用以下命令调用此模拟：

```
npm run integration
```

调用测试将显示类似以下内容：

```
> kfd-nodejs@0.0.0 integration /Users/heckj/src/kfd-nodejs
> mocha e2e_tests --exit

kubernetes
 cluster
 ✓ should have a healthy cluster
 ✓ should deploy the manifests (273ms)
 should repeat until the pods are ready
 - delay 5 seconds...
 ✓ check to see that all pods are reporting ready (5016ms)
 should interact with the deployed services
 ✓ should access by pod...

 4 passing (5s)
```

# 使用 mocha 和 chai 的 Node.js 测试和依赖项

测试代码本身位于`e2e_tests/integration_test.js`，我利用 mocha 和 chai 以 BDD 风格的结构布置了测试。使用 mocha 和 chai 的 BDD 结构的一个便利的副作用是，测试可以由`describe`和`it`包装，这样结构化了测试的运行方式。`describe`块内的任何内容都没有保证的顺序，但您可以嵌套`describe`块以获得所需的结构。

# 验证集群健康

JavaScript Kubernetes 客户端与 Python 客户端以类似的方式生成，从 OpenAPI 定义中映射到 Kubernetes 的发布版本。你可以在[`github.com/kubernetes-client/javascript`](https://github.com/kubernetes-client/javascript)找到客户端，尽管这个存储库没有与 Python 客户端相同级别的生成文档。相反，开发人员已经花了一些精力用 TypeScript 反映了客户端中的类型，这导致编辑器和 IDE 在编写测试时能够做一定程度的自动代码补全：

```
const k8s = require('@kubernetes/client-node');
var chai = require('chai')
 , expect = chai.expect
 , should = chai.should();

var k8sApi = k8s.Config.defaultClient();

describe('kubernetes', function() {
  describe('cluster', function() {
    it('should have a healthy cluster', function() {
       return k8sApi.listComponentStatus()
       .then((res) => {
         // console.log(util.inspect(res.body));
         res.body.items.forEach(function(component) {
         // console.log(util.inspect(value));
         expect(component.conditions[0].type).to.equal("Healthy");
         expect(component.conditions[0].status).to.equal("True");
       })
     }, (err) => {
        expect(err).to.be.null;
     });
   }) // it
```

代码的嵌套可能会使缩进和跟踪正确级别变得相当棘手，因此测试代码利用 promise 来简化回调结构。前面的示例使用了一个 Kubernetes 客户端，它会自动从运行它的环境中获取凭据，这是几个这些客户端的特性，因此如果你希望安排特定的访问，要注意这一点。

Python 客户端有一个方法`list_component_status`，而 JavaScript 模式则使用 CamelCase 格式将名称紧凑在一起，因此这里的调用是`listComponentStatus`。然后结果通过一个 promise 传递，我们遍历各种元素来验证集群组件是否都报告为健康状态。

示例中留下了一些被注释掉的代码，用于检查返回的对象。由于外部文档很少，我发现在开发测试时查看返回的内容很方便，常见的技巧是使用`util.inspect`函数并将结果记录到`STDOUT`中：

```
const util = require('util');
console.log(util.inspect(res.body));
```

# 使用 kubectl 部署

在 Python 示例之后，我在命令行上使用`kubectl`部署代码，从集成测试中调用它：

```
it('should deploy the manifests', function() {
  var manifest_directory = path.normalize(path.join(path.dirname(__filename), '..', '/deploy'))
  const exec = util.promisify(require('child_process').exec);
  return exec('kubectl apply -f '+manifest_directory)
  .then((res) => {
    // console.log(util.inspect(res));
    expect(res.stdout).to.not.be.null;
    expect(res.stderr).to.be.empty;
  }, (err) => {
    expect(err).to.be.null;
  })
})
```

这段特定的代码取决于你在哪里有这个测试用例，以及它相对于存储清单的部署目录的位置，就像前面的示例一样，它使用 promises 来链接调用的执行的验证。

# 等待 pod 变得可用

等待和重试的过程在 Node.js、promises 和 callbacks 中更加棘手。在这种情况下，我利用了 mocha 测试库的一个功能，允许对测试进行重试，并操纵测试结构的整体超时，以获得相同的结果：

```
describe('should repeat until the pods are ready', function() {
  // Mocha supports a retry mechanism limited by number of retries...
  this.retries(30);
  // an a default timeout of 20,000ms that we can increase
  this.timeout(300000);

it('check to see that all pods are reporting ready', function() {
   return new Promise(function(resolve, reject) {
       console.log(' - delay 5 seconds...')
       setTimeout(() => resolve(1), 5000);
   }).then(function(result) {
       return k8sApi.listNamespacedPod('default')
      .then((res) => {
         res.body.items.forEach(function(pod) {
           var readyCondition = _.filter(pod.status.conditions, { 'type': 'Ready' })
          //console.log("checking: "+pod.metadata.name+" ready: "+readyCondition[0].status);
          expect(readyCondition[0].status).to.equal('True')
        }) // pod forEach
    })
  })
}) // it

}) // describe pods available
```

通过在测试中返回 promises，每个测试已经是异步的，并且具有 mocha 提供的预设超时为`20`秒。在每个`describe`中，您可以调整 mocha 运行测试的方式，例如将整体超时设置为五分钟，并断言测试最多可以重试`30`次。为了减慢检查迭代，我还包括了一个超时 promise，它在调用集群检查之前引入了五秒的延迟。

# 与部署进行交互

与 Python 示例相比，与部署进行交互的代码更简单，利用了 Kubernetes 客户端和代理：

```
describe('should interact with the deployed services', function() {
  // path to access the port through the kubectl proxy:
  // http://localhost:8001/api/v1/namespaces/default/services/nodejs-service:web/proxy/
 it('should access by pod...', function() {
   return k8sApi.proxyGETNamespacedServiceWithPath("nodejs-service:web", "default", "/")
   .then(function(res) {
      // console.log(util.inspect(res,{depth:1}));
      expect(res.body).to.not.be.null;
    });
  })
}) // interact with the deployed services
```

在这个分支中，我将运行的代码从有状态集更改为部署，因为获取对无头端点的代理访问证明很复杂。有状态集可以通过 DNS 轻松从集群内部访问，但在当前客户端代码中似乎不容易支持映射到外部。

与 Python 代码一样，有一系列调用可以通过客户端进行 REST 风格的请求：

+   `proxyGET`

+   `proxyDELETE`

+   `proxyHEAD`

+   `proxyOPTIONS`

+   `proxyPATCH`

+   `proxyPUT`

并且每个都映射到端点：

+   `namespacedPod`

+   `namespacedPodWithPath`

+   `namespacedService`

+   `namespacedServiceWithPath`

这为您提供了一些灵活性，可以将标准的 REST 命令发送到 Pod 直接或服务端点。与 Python 代码一样，`withPath`选项允许您定义与 Pod 或服务上交互的特定 URI。

如果您在诸如 Visual Studio Code 之类的编辑器中编写这些测试，代码完成将帮助提供一些在文档中否则缺失的细节。以下是代码完成显示`method`选项的示例：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-dev/img/6ccc784d-e1e6-4d88-8c5f-7a1265ae5400.png)

当您选择一种方法时，TypeScript 注释也可用于显示 JavaScript 方法期望的选项：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-dev/img/b9556730-dee8-4b4b-ae6a-a9b11dbd364e.png)

# 与 Kubernetes 的持续集成

一旦您有集成测试，获取一些操作来验证这些测试非常重要。如果您不运行测试，它们实际上是无用的-因此在开发过程中始终调用测试的方法非常重要。通常会看到持续集成为开发做了大量自动化工作。

开发团队有许多选项可帮助您进行持续集成，甚至是更高级的持续部署。以下工具是在撰写时可用的概述，并且由使用容器和/或 Kubernetes 中的代码的开发人员使用：

+   Travis.CI：Travis.CI（[`travis-ci.org/`](https://travis-ci.org/)）是一个托管的持续集成服务，因为该公司提供了免费服务，并且可以轻松地与 GitHub 对接以用于公共和开源存储库。相当多的开源项目利用 Travis.CI 进行基本测试验证。

+   Drone.IO：Drone.IO（[`drone.io/`](https://drone.io/)）是一个托管或本地的持续集成选项，也是开源软件本身，托管在[`github.com/drone/drone`](https://github.com/drone/drone)。Drone 拥有广泛的插件库，包括一个 Helm 插件（[`github.com/ipedrazas/drone-helm`](https://github.com/ipedrazas/drone-helm)），这使得它对一些使用 Helm 部署软件的开发团队很有吸引力。

+   Gitlab：Gitlab（[`about.gitlab.com/`](https://about.gitlab.com/)）是一个开源的源代码控制解决方案，包括持续集成。与 Drone 一样，它可以在您的本地环境中使用，或者您可以使用托管版本。之前的选项对源代码控制机制是不可知的，Gitlab CI 与 Gitlab 紧密绑定，有效地使其只有在您愿意使用 Gitlab 时才有用。

+   Jenkins：Jenkins（[`jenkins.io/`](https://jenkins.io/)）是 CI 解决方案的鼻祖，最初被称为 Hudson，并且在各种环境中被广泛使用。一些提供商提供了 Jenkins 的托管版本，但它主要是一个您需要自己部署和管理的开源解决方案。它有大量（也许是压倒性的）插件和选项可供选择，特别是一个 Kubernetes 插件（[`github.com/jenkinsci/kubernetes-plugin`](https://github.com/jenkinsci/kubernetes-plugin)），可以让 Jenkins 实例在 Kubernetes 集群中运行其测试。

+   **Concourse**：Concourse（[`concourse-ci.org/`](https://concourse-ci.org/)），类似于 Jenkins，是一个开源项目，而不是一个托管解决方案，它是在 CloudFoundry 项目中构建的，专注于部署管道作为一种第一类概念（对于一些较老的项目，如 Jenkins，它相对较新）。与 Drone 一样，它被设置为一个持续交付管道，并且是您开发过程的一个重要部分。

# 示例-在 Travis.CI 中使用 Minikube

之前的示例展示了使用 Bats 运行测试，是由 Bitnami 团队创建的，并且他们还利用了相同的示例存储库来构建和部署代码到托管在 Travis.CI 上的 Minikube 实例。他们的示例存储库在线上[`github.com/bitnami/kubernetes-travis`](https://github.com/bitnami/kubernetes-travis)，它安装了 Minikube 以及其他工具来构建和部署到一个小的 Kubernetes 实例。

Travis.CI 通过一个`.travis.yml`文件进行配置，有关如何配置以及可用选项的文档托管在[`docs.travis-ci.com`](https://docs.travis-ci.com)上。Travis.CI 默认情况下会尝试理解正在使用的语言，并将其构建脚本定位到该语言，主要专注于对每个拉取请求和合并到存储库的构建进行运行。

Node.js 示例添加了一个示例`.travis.yml`，用于设置和运行当前的集成测试：

```
language: node_js
node_js:
 - lts/*
cache:
 directories:

 - "node_modules"
sudo: required
services:
 - docker
env:
- CHANGE_MINIKUBE_NONE_USER=true

before_script:
- curl -Lo kubectl https://storage.googleapis.com/kubernetes-release/release/v1.9.0/bin/linux/amd64/kubectl && chmod +x kubectl && sudo mv kubectl /usr/local/bin/
- curl -Lo minikube https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64 && chmod +x minikube && sudo mv minikube /usr/local/bin/
- sudo minikube start --vm-driver=none --kubernetes-version=v1.9.0
- minikube update-context
- JSONPATH='{range .items[*]}{@.metadata.name}:{range @.status.conditions[*]}{@.type}={@.status};{end}{end}'; until kubectl get nodes -o jsonpath="$JSONPATH" 2>&1 | grep -q "Ready=True"; do sleep 1; done

script:
- npm run integration
```

键`language`在我们的示例中设置为`nodejs`，它定义了 Travis 的运行方式的很大一部分。我们定义了使用哪些版本的 Node.js（`lts/*`），默认情况下系统会使用`npm`，运行`npm test`来验证我们的构建。这将运行我们的单元测试，但不会调用我们的集成测试。

您可以通过操纵键`before_script`和`script`下的值来扩展测试之前发生的事情以及测试使用的内容。在前面的示例中，我们通过从它们的发布位置下载它们来预加载`minikube`和`kubectl`，然后启动 Minikube 并等待直到命令`kubectl get nodes`返回正面结果。

通过在关键脚本下添加`npm run integration`，我们覆盖了默认的 Node.js 行为，而是运行我们的集成测试。当示例被开发时，更新被推送到了 0.7.0 分支，该分支作为主存储库的拉取请求是开放的。这些更新的结果被发布到托管解决方案，可在[`travis-ci.org/kubernetes-for-developers/kfd-nodejs`](https://travis-ci.org/kubernetes-for-developers/kfd-nodejs)上找到。例如，以下是一个显示成功构建的构建页面：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-dev/img/cfdc6e56-9507-4163-a667-4afa57807b67.png)

# 下一步

这个示例构建并不涵盖从源代码到容器再到部署的整个过程。相反，它依赖于在源代码控制中管理的预构建镜像，并在部署清单中设置了标签。Travis.CI 确实包括使用 Docker 构建镜像的能力，并有关于如何利用 Docker 测试单个容器的文档，网址为[`docs.travis-ci.com/user/docker/`](https://docs.travis-ci.com/user/docker/)。

Travis 还具有存储凭据以构建和推送 Docker 镜像到镜像存储库的能力，并最近增加了分阶段构建的能力，这样您就可以在容器构建中进行流水线处理，然后在集成测试中利用它。

您需要更新 Kubernetes 声明以使用相关镜像，而这个示例并没有展示这个过程。启用这种功能的常见模式涉及对我们在示例中存储在 deploy 目录中的清单进行模板化，并使用传入的特定变量进行渲染。

Helm ([`docs.helm.sh/`](https://docs.helm.sh/)) 是实现这一需求的一种方式：我们可以有一个`charts`目录，而不是一个带有清单的`deploy`目录，并将清单编写为模板。 Helm 使用`values`文件，可以根据需要创建，以提供用于渲染模板的变量，并在创建带有标签的 Docker 镜像后，该标签值可以添加到`values`文件中并用于部署。

另一个选择是一个名为 ksonnet 的新项目([`ksonnet.io`](https://ksonnet.io))，它构建在一个开源库[`jsonnet.org/`](http://jsonnet.org/)上，以提供一个基于原型的可组合模板样式语言，用于构建 Kubernetes。ksonnet 相对较新，仍在建立中。使用 Helm，您可以利用 Go 模板，并且在创建图表时需要对该格式有一定的了解。ksonnet 有自己的模板编写风格，您可以在项目网站上找到教程和示例：[`ksonnet.io/tour/welcome`](https://ksonnet.io/tour/welcome)。

# 示例-使用 Jenkins 和 Kubernetes 插件

虽然不是托管解决方案，但 Jenkins 是最常用的持续集成工具之一。在 Kubernetes 集群上运行 Jenkins 实例非常简单，并且由于 Kubernetes 特定插件的存在，它还可以在 Kubernetes 集群中进行所有构建。

以这种方式安装 Jenkins 的最快方法之一是使用 Helm。默认的 Helm 存储库包括一个维护的图表，用于运行 Jenkins，以及使用 Jenkins Kubernetes 插件的配置。我们将使用的图表可在 GitHub 上找到[`github.com/kubernetes/charts/tree/master/stable/jenkins`](https://github.com/kubernetes/charts/tree/master/stable/jenkins)。您还可以在该图表安装的 Jenkins Kubernetes 插件的详细信息[`wiki.jenkins.io/display/JENKINS/Kubernetes+Plugin`](https://wiki.jenkins.io/display/JENKINS/Kubernetes+Plugin)。

# 使用 Helm 安装 Jenkins

在这个示例中，我将演示如何在 Minikube 集群上设置和安装 Jenkins 到您的本地机器，以便进行实验。您可以使用非常类似的过程安装到任何 Kubernetes 集群，但是您需要根据目标集群进行一些修改。

如果您的笔记本电脑上尚未安装 Helm，可以按照项目网站上的说明进行安装：[`docs.helm.sh/using_helm/#installing-helm`](https://docs.helm.sh/using_helm/#installing-helm)。一旦在本地系统上安装了命令行客户端，您就可以启动其余的工作。

第一步是将 Helm 安装到您的集群并更新存储库。这可以通过运行两个命令来完成：

```
helm init
```

输出将非常简洁，类似于以下内容：

```
$HELM_HOME has been configured at /Users/heckj/.helm.

Tiller (the Helm server-side component) has been installed into your Kubernetes Cluster.

Please note: by default, Tiller is deployed with an insecure 'allow unauthenticated users' policy.
For more information on securing your installation see: https://docs.helm.sh/using_helm/#securing-your-helm-installation
Happy Helming!
```

正如它提到的那样，Tiller 是 Helm 的服务器端组件，负责协调从`helm`命令行工具调用的安装。默认情况下，`helm init`将 Tiller 安装到`kube-system`命名空间中，因此您可以使用以下命令在集群中查看它：

```
kubectl get pods -n kube-system
```

```
NAME READY STATUS RESTARTS AGE
coredns-599474b9f4-gh99f 1/1 Running 0 3m
kube-addon-manager-minikube 1/1 Running 0 3m
kubernetes-dashboard-77d8b98585-f4qh9 1/1 Running 0 3m
storage-provisioner 1/1 Running 0 3m
tiller-deploy-865dd6c794-5b9g5 1/1 Running 0 3m
```

一旦处于`Running`状态，最好加载最新的存储库索引。它已经安装了许多图表，但是图表会定期更新，这将确保您拥有最新的图表：

```
helm repo update
```

更新过程通常非常快，返回类似以下内容：

```
Hang tight while we grab the latest from your chart repositories...
...Skip local chart repository
...Successfully got an update from the "stable" chart repository
Update Complete. ⎈ Happy Helming!⎈
```

它提到的`stable`图表存储库是托管在 GitHub 上的 Kubernetes 项目的一个：[`github.com/kubernetes/charts`](https://github.com/kubernetes/charts)。在该存储库中，有一个包含所有图表的`stable`目录。如果您使用`helm search`命令，它将显示图表和相关版本的列表，与 GitHub 存储库匹配。

使用`helm search jenkins`命令将显示我们将要使用的目标：

```
NAME CHART VERSION APP VERSION DESCRIPTION
stable/jenkins 0.14.1 2.73 Open source continuous integration server. It s...
```

请注意，图表除了报告的*应用程序版本*外，还有图表版本。许多图表包装现有的开源项目，并且图表与它们部署的系统分开维护。Kubernetes 项目中的`stable`存储库中的图表力求成为构建图表的示例，并且对整个社区有用。在这种情况下，图表版本是`0.14.1`，并且报告部署 Jenkins 版本为`2.73`。

您可以使用`helm inspect`命令获取有关特定图表的更多详细信息，例如：

```
 helm inspect stable/jenkins
```

这将向您显示大量的输出，从以下内容开始：

```
appVersion: "2.73"
description: Open source continuous integration server. It supports multiple SCM tools
 including CVS, Subversion and Git. It can execute Apache Ant and Apache Maven-based
 projects as well as arbitrary scripts.
home: https://jenkins.io/
icon: https://wiki.jenkins-ci.org/download/attachments/2916393/logo.png
maintainers:
- email: lachlan.evenson@microsoft.com
 name: lachie83
- email: viglesias@google.com
 name: viglesiasce
name: jenkins
sources:
- https://github.com/jenkinsci/jenkins
- https://github.com/jenkinsci/docker-jnlp-slave
version: 0.14.1

---
# Default values for jenkins.
# This is a YAML-formatted file.
# Declare name/value pairs to be passed into your templates.
# name: value

## Overrides for generated resource names
# See templates/_helpers.tpl
# nameOverride:
# fullnameOverride:

Master:
 Name: jenkins-master
 Image: "jenkins/jenkins"
 ImageTag: "lts"
 ImagePullPolicy: "Always"
# ImagePullSecret: jenkins
 Component: "jenkins-master"
 UseSecurity: true
```

顶部是输入图表存储库索引的信息，用于提供`helm search`命令的结果，之后的部分是图表支持的配置选项。

大多数图表都力求具有并使用良好的默认值，但是预期您可能会在适当的地方提供覆盖的值。在将 Jenkins 部署到 Minikube 的情况下，我们将要这样做，因为图表使用的默认`values.yaml`期望使用`LoadBalancer`，而 Minikube 不支持。

您可以在`helm inspect`的扩展输出中查看`values.yaml`的完整详细信息。在使用 Helm 安装任何内容之前，最好看看它代表您做了什么，以及它提供了哪些配置值。

我们将创建一个小的`yaml`文件来覆盖默认值之一：`Master.ServiceType`。如果您扫描`helm inspect`命令的输出，您将看到将其更改以在 Minikube 上安装的引用。

创建一个名为`jenkins.yaml`的文件，内容如下：

```
Master:
  ServiceType: NodePort
```

现在，我们可以看到当我们要求其安装时 Helm 将创建什么，使用`--dry-run`和`--debug`选项获取详细输出：

```
helm install stable/jenkins --name j \
-f jenkins.yaml --dry-run --debug
```

运行此命令将向您的终端屏幕转储大量信息，即 Helm 将代表您安装的所有内容的呈现清单。您可以看到部署、秘密、配置映射和服务。

您可以通过运行完全相同的命令来开始安装过程，减去`--dry-run`和`--debug`选项：

```
helm install stable/jenkins --name j -f jenkins.yaml
```

这将为您提供它创建的所有 Kubernetes 对象的列表，然后是一些注释：

```
NAME: j
LAST DEPLOYED: Sun Mar 11 20:33:34 2018
NAMESPACE: default
STATUS: DEPLOYED

RESOURCES:
==> v1/Pod(related)
NAME READY STATUS RESTARTS AGE
j-jenkins-6ff797cc8d-qlhbk 0/1 Init:0/1 0 0s
==> v1/Secret
NAME TYPE DATA AGE
j-jenkins Opaque 2 0s
==> v1/ConfigMap
NAME DATA AGE
j-jenkins 3 0s
j-jenkins-tests 1 0s
==> v1/PersistentVolumeClaim
NAME STATUS VOLUME CAPACITY ACCESS MODES STORAGECLASS AGE
j-jenkins Bound pvc-24a90c2c-25a6-11e8-9548-0800272e7159 8Gi RWO standard 0s
==> v1/Service
NAME TYPE CLUSTER-IP EXTERNAL-IP PORT(S) AGE
j-jenkins-agent ClusterIP 10.107.112.29 <none> 50000/TCP 0s
j-jenkins NodePort 10.106.245.61 <none> 8080:30061/TCP 0s
==> v1beta1/Deployment
NAME DESIRED CURRENT UP-TO-DATE AVAILABLE AGE
j-jenkins 1 1 1 0 0s

NOTES:
1\. Get your 'admin' user password by running:
 printf $(kubectl get secret --namespace default j-jenkins -o jsonpath="{.data.jenkins-admin-password}" | base64 --decode);echo
2\. Get the Jenkins URL to visit by running these commands in the same shell:
 export NODE_PORT=$(kubectl get --namespace default -o jsonpath="{.spec.ports[0].nodePort}" services j-jenkins)
 export NODE_IP=$(kubectl get nodes --namespace default -o jsonpath="{.items[0].status.addresses[0].address}")
 echo http://$NODE_IP:$NODE_PORT/login

3\. Login with the password from step 1 and the username: admin

For more information on running Jenkins on Kubernetes, visit:
https://cloud.google.com/solutions/jenkins-on-container-engine
```

生成的注释被呈现为模板，并通常提供有关如何访问服务的说明。您始终可以使用`helm status`命令重复获取相同的信息。

当我们调用 Helm 时，我们将此命名为`release j`以使其简短和简单。要获取有关此版本当前状态的信息，请使用以下命令：

```
helm status j
```

这是一个相当大的安装，安装需要一段时间。您可以使用诸如`kubectl get events -w`之类的命令观看从此安装中滚出的事件。这将随着部署的进行而更新事件，输出看起来类似于以下内容：

```
2018-03-11 20:08:23 -0700 PDT 2018-03-11 20:08:23 -0700 PDT 1 minikube.151b0d76e3a375e1 Node Normal NodeReady kubelet, minikube Node minikube status is now: NodeReady

2018-03-11 20:38:28 -0700 PDT 2018-03-11 20:38:28 -0700 PDT 1 j-jenkins-6ff797cc8d-qlhbk.151b0f1b339a1485 Pod spec.containers{j-jenkins} Normal Pulling kubelet, minikube pulling image "jenkins/jenkins:lts"

2018-03-11 20:38:29 -0700 PDT 2018-03-11 20:38:29 -0700 PDT 1 j-jenkins-6ff797cc8d-qlhbk.151b0f1b7a153b09 Pod spec.containers{j-jenkins} Normal Pulled kubelet, minikube Successfully pulled image "jenkins/jenkins:lts"

2018-03-11 20:38:29 -0700 PDT 2018-03-11 20:38:29 -0700 PDT 1 j-jenkins-6ff797cc8d-qlhbk.151b0f1b7d270e5e Pod spec.containers{j-jenkins} Normal Created kubelet, minikube Created container

2018-03-11 20:38:30 -0700 PDT 2018-03-11 20:38:30 -0700 PDT 1 j-jenkins-6ff797cc8d-qlhbk.151b0f1b8359a5e4 Pod spec.containers{j-jenkins} Normal Started kubelet, minikube Started container
```

一旦部署完全可用，您可以开始使用注释中的说明访问它。

# 访问 Jenkins

图表和图像一起制作一些秘密，因为部署正在进行中，以保存诸如访问 Jenkins 的密码之类的东西。注释包括一个命令，用于从 Kubernetes 获取此密码并在您的终端上显示它：

```
printf $(kubectl get secret --namespace default j-jenkins -o jsonpath="{.data.jenkins-admin-password}" | base64 --decode);echo
```

运行该命令并复制输出，因为我们需要它来登录到您的 Jenkins 实例。接下来的命令告诉您如何获取访问 Jenkins 的 URL。您可以使用这些命令获取信息并打开浏览器访问 Jenkins。如果您将其部署到 Minikube，还可以使用 Minikube 打开相关服务的浏览器窗口：

```
minikube service j-jenkins
```

第一页将为您提供凭据请求。使用`admin`作为用户名和您在前面命令中读取的密码：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-dev/img/e3fafc03-9858-4270-bfa6-e33828d6519e.png)

然后，登录应该为您提供对 Jenkins 的管理访问权限：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-dev/img/1cdf14f1-5fdf-48be-ad3b-4fbf3b4cd0bb.png)

# 更新 Jenkins

当您连接时，在前面的示例中，您可能会看到一个红色菜单项和一个数字。这是 Jenkins 提醒您应立即考虑更新的方式。我强烈建议您单击该数字并查看它所呈现的内容：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-dev/img/51ee8772-f058-4a34-b1ca-41d41c6928bf.png)

虽然图表和基本图像是维护的，但无法提前确定的更新或考虑因素可能会变得可用。特别是，Jenkins 的插件可能会得到更新，并且 Jenkins 会审查现有的插件以进行可能的更新。您可以单击此页面上的按钮来运行更新，重新启动 Jenkins，或了解更多关于其建议的信息。

Jenkins 图表包括一个`persistent-volume-claim`，用于存储插件更新，因此，除非您禁用它，您可以安全地加载 Jenkins 插件的更新，并告诉它重新启动以使这些插件更新生效。

# 示例管道

安装的一个好处是，您创建的作业可以运行完全在 Kubernetes 集群内构建和运行的管道。管道可以被定义为您在 Jenkins 内部使用工具构建的东西，您可以直接输入它们，或者您可以从源代码控制中加载它们。

Python/Flask 应用程序的示例代码具有基本的 Jenkinsfile，以向您展示这如何工作。 Jenkinsfile 已添加到 0.7.0 分支，您可以在[`github.com/kubernetes-for-developers/kfd-flask/blob/0.7.0/Jenkinsfile`](https://github.com/kubernetes-for-developers/kfd-flask/blob/0.7.0/Jenkinsfile)上在线查看。

管道设置为从源代码控制中使用，构建 Docker 镜像，并与 Kubernetes 交互。示例不会将图像推送到存储库或部署图像，与之前的 Travis.CI 示例遵循相同的模式。

要在 Jenkins 的实例中启用此示例，您需要导航到 Jenkins 的首页并选择 New Item。然后，选择 Multibranch Pipeline 并将作业命名为`kfd-flask-pipeline`：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-dev/img/6f374ec3-fe39-4455-b37f-6ea631365d5e.png)

创建后，输入的关键项目是来自源代码控制的内容位置。您可以输入`https://github.com/kubernetes-for-developers/kfd-flask`来使用此示例：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-dev/img/5e672215-e2bc-44c9-90e6-b3bee02439b9.png)

保存配置，它应该构建示例，连接到 GitHub，获取管道，然后配置并运行它。

加载各种图像可能需要相当长的时间，一旦完成，结果将在 Jenkins 中可用：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-dev/img/bad25e3c-e8af-4fe0-a602-092d2ca7d17e.png)

在管道示例中，它从源代码控制中检出，使用基于分支和`git commit`的标签名称构建新的 Docker 镜像，然后与 Kubernetes 交互，向您显示正在运行的集群中当前活动的 Pod 的列表。

Jenkins 与我们的 Travis.CI 示例有相同的需求，例如更改清单以运行完整的序列，您可以通过使用 Helm 或者 ksonnet 来构建前面的示例来解决这个问题。

# 管道的下一步

您可以使用 Jenkins 管道做的事情远远超出了我们在这里可以涵盖的范围，但是管道和 Kubernetes 插件附加功能的完整文档都可以在线获得：

+   [`jenkins.io/doc/book/pipeline/syntax/`](https://jenkins.io/doc/book/pipeline/syntax/)提供了有关管道语法、如何编写管道以及默认内置选项的文档。

+   [`github.com/jenkinsci/kubernetes-plugin`](https://github.com/jenkinsci/kubernetes-plugin)提供了 Jenkins Kubernetes 插件的详细信息以及其操作方式，还包括如何在 GitHub 存储库中使用一些示例管道的示例：[`github.com/jenkinsci/kubernetes-plugin/tree/master/examples`](https://github.com/jenkinsci/kubernetes-plugin/tree/master/examples)。

+   一般的 Jenkins 文档非常广泛，可在[`jenkins.io/doc/`](https://jenkins.io/doc/)找到，以及有关如何创建和使用 Jenkinsfile 的更多详细信息[`jenkins.io/doc/book/pipeline/jenkinsfile/`](https://jenkins.io/doc/book/pipeline/jenkinsfile/)。使用 Jenkinsfile 的一个重要好处是，您可以将管道应该执行的声明与源代码一起存储在源代码控制中。

+   [`jenkins.io/doc/pipeline/steps/credentials-binding/`](https://jenkins.io/doc/pipeline/steps/credentials-binding/)详细介绍了一种公开秘密和凭据的方法，以便您可以在流水线中使用它们，例如，将图像更新推送到 DockerHub、Quay 或您自己的私有图像存储库。

# 总结

在本章中，我们深入探讨了在测试代码时如何使用 Kubernetes。我们研究了您可能在集成测试中探索的模式。我们指出了使用 shell 脚本在 Kubernetes 中运行集成测试的简单示例，然后更深入地探讨了使用 Python 和 Node.js 的示例，这些示例使用 Kubernetes 运行集成测试。最后，我们总结了本章，概述了可以使用集群的持续集成的可用选项，并探讨了两个选项：使用 Travis.CI 作为托管解决方案以及如何在自己的 Kubernetes 集群上使用 Jenkins。

在下一章中，我们将看看如何将我们探索过的多个部分汇集在一起，并展示如何在 Kubernetes 上运行代码的基准测试。
