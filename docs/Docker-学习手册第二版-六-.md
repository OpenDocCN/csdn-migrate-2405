# Docker 学习手册第二版（六）

> 原文：[`zh.annas-archive.org/md5/4FF7CBA6C5E093012874A6BAC2B803F8`](https://zh.annas-archive.org/md5/4FF7CBA6C5E093012874A6BAC2B803F8)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十七章：监控和故障排除在生产环境中运行的应用程序

在上一章中，我们学习了如何将多服务应用程序部署到 Kubernetes 集群中。我们为应用程序配置了应用程序级别的路由，并使用了零停机策略更新了其服务。最后，我们使用 Kubernetes Secrets 为运行的服务提供了机密数据。

在本章中，您将学习用于监视在 Kubernetes 集群上运行的单个服务或整个分布式应用程序的不同技术。您还将学习如何在生产环境中运行的应用服务进行故障排除，而不会更改集群或运行服务的集群节点。

本章涵盖以下主题：

+   监视单个服务

+   使用 Prometheus 监视您的分布式应用程序

+   故障排除在生产环境中运行的服务

通过完成本章，您将能够执行以下操作：

+   为服务配置应用程序级别的监控。

+   使用 Prometheus 收集和集中聚合相关的应用程序指标。

+   使用特殊工具容器来故障排除在生产环境中运行的服务。

# 技术要求

在本章中，我们将在本地计算机上使用 Minikube。有关如何安装和使用 Minikube 的更多信息，请参阅 第二章 *设置工作环境*。

本章的代码可以在以下网址找到：[`github.com/PacktPublishing/Learn-Docker---Fundamentals-of-Docker-19.x-Second-Edition/tree/master/ch17`](https://github.com/PacktPublishing/Learn-Docker---Fundamentals-of-Docker-19.x-Second-Edition/tree/master/ch17)[.](https://github.com/fundamentalsofdocker/labs/tree/2nd-edition/ch16/probes)

请确保您已经克隆了 GitHub 存储库，如 第二章 *设置工作环境* 中所述。

在终端中，导航到 `~/fod/ch17` 文件夹。

# 监视单个服务

当在生产环境或任何类似生产环境中使用分布式的关键任务应用程序时，尽可能多地了解这些应用程序的内部运作是至关重要的。你有没有机会看过飞机驾驶舱或核电站的指挥中心？飞机和发电厂都是提供关键任务服务的高度复杂系统的样本。如果飞机坠毁或发电厂意外关闭，至少可以说很多人会受到负面影响。因此，驾驶舱和指挥中心都装满了显示系统某个部分当前或过去状态的仪器。你看到的是系统的一些战略部分放置的传感器的视觉表示，它们不断收集数据，比如温度或流速。

与飞机或发电厂类似，我们的应用程序需要安装“传感器”，这些传感器可以感知应用服务或其运行基础设施的“温度”。我用双引号括起来的温度只是一个占位符，用于表示应用程序中重要的事物，比如给定 RESTful 端点每秒的请求次数，或者对同一端点的请求的平均延迟。

我们收集的结果数值或读数，比如请求的平均延迟，通常被称为指标。我们的目标应该是尽可能多地公开我们构建的应用服务的有意义的指标。指标可以是功能性的，也可以是非功能性的。功能性指标是关于应用服务的与业务相关的数值，比如如果服务是电子商务应用程序的一部分，每分钟执行多少次结账，或者如果我们谈论的是流媒体应用程序，过去 24 小时内最受欢迎的五首歌曲是哪些。

非功能性指标是重要的数值，它们与应用程序所用于的业务类型无关，比如特定网页请求的平均延迟是多少，或者另一个端点每分钟返回多少个`4xx`状态代码，或者给定服务使用了多少 RAM 或多少 CPU 周期。

在一个分布式系统中，每个部分都暴露指标的情况下，一些全面的服务应该定期从每个组件中收集和聚合值。或者，每个组件应该将其指标转发到一个中央指标服务器。只有当我们高度分布式系统的所有组件的指标都可以在一个中央位置进行检查时，它们才有任何价值。否则，监控系统将变得不可能。这就是为什么飞机的飞行员在飞行期间从不必亲自检查飞机的各个关键部件；所有必要的读数都被收集并显示在驾驶舱中。

如今，最受欢迎的用于暴露、收集和存储指标的服务之一是 Prometheus。它是一个开源项目，并已捐赠给**Cloud Native Computing Foundation**（**CNCF**）。Prometheus 与 Docker 容器、Kubernetes 和许多其他系统和编程平台具有一流的集成。在本章中，我们将使用 Prometheus 来演示如何对暴露重要指标的简单服务进行仪表化。

# 基于 Node.js 的服务仪表化

在本节中，我们想要学习如何通过以下步骤对 Node Express.js 编写的微服务进行仪表化：

1.  创建一个名为`node`的新文件夹并导航到它：

```
$ mkdir node && cd node
```

1.  在这个文件夹中运行`npm init`，并接受除了**入口点**之外的所有默认值，将其从默认的`index.js`更改为`server.js`。

1.  我们需要使用以下命令将`express`添加到我们的项目中：

```
$ npm install --save express
```

1.  现在我们需要使用以下命令为 Node Express 安装 Prometheus 适配器：

```
$ npm install --save prom-client 
```

1.  在文件夹中添加一个名为`server.js`的文件，并包含以下内容：

```
const app = require("express")();

app.get('/hello', (req, res) => {
  const { name = 'World' } = req.query;
  res.json({ message: `Hello, ${name}!` });
});

app.listen(port=3000, () => {
  console.log(`Example api is listening on http://localhost:3000`);
}); 
```

这是一个非常简单的 Node Express 应用程序，只有一个端点：`/hello`。

1.  在上述代码中，添加以下片段以初始化 Prometheus 客户端：

```
const client = require("prom-client");
const register = client.register;
const collectDefaultMetrics = client.collectDefaultMetrics;
collectDefaultMetrics({ register });
```

1.  接下来，添加一个端点来暴露指标：

```
app.get('/metrics', (req, res) => {
  res.set('Content-Type', register.contentType);
  res.end(register.metrics());
});
```

1.  现在让我们运行这个示例微服务：

```
$ npm start

> node@1.0.0 start C:\Users\Gabriel\fod\ch17\node
> node server.js

Example api is listening on http://localhost:3000
```

我们可以在前面的输出中看到，服务正在端口`3000`上监听。

1.  现在让我们尝试访问在代码中定义的`/metrics`端点上的指标：

```
$ curl localhost:3000/metrics
...
process_cpu_user_seconds_total 0.016 1577633206532

# HELP process_cpu_system_seconds_total Total system CPU time spent in seconds.
# TYPE process_cpu_system_seconds_total counter
process_cpu_system_seconds_total 0.015 1577633206532

# HELP process_cpu_seconds_total Total user and system CPU time spent in seconds.
# TYPE process_cpu_seconds_total counter
process_cpu_seconds_total 0.031 1577633206532
...
nodejs_version_info{version="v10.15.3",major="10",minor="15",patch="3"} 1
```

我们得到的输出是一个相当长的指标列表，可以被 Prometheus 服务器消费。

这很容易，不是吗？通过添加一个节点包并在应用程序启动中添加几行微不足道的代码，我们已经获得了大量的系统指标访问权限。

现在让我们定义我们自己的自定义指标。让它是一个`Counter`对象：

1.  将以下代码片段添加到`server.js`中，以定义名为`my_hello_counter`的自定义计数器：

```
const helloCounter = new client.Counter({ 
  name: 'my_hello_counter', 
  help: 'Counts the number of hello requests',
});
```

1.  在现有的`/hello`端点中，添加代码以增加计数器：

```
app.get('/hello', (req, res) => {
  helloCounter.inc();
  const { name = 'World' } = req.query;
  res.json({ message: `Hello, ${name}!` });
});
```

1.  使用`npm start`重新运行应用程序。

1.  为了测试新的计数器，让我们两次访问我们的`/hello`端点：

```
$ curl localhost:3000/hello?name=Sue
```

1.  当访问`/metrics`端点时，我们将获得以下输出：

```
$ curl localhost:3000/metrics

...
# HELP my_hello_counter Counts the number of hello requests 
# TYPE my_hello_counter counter
my_hello_counter 2
```

我们在代码中定义的计数器显然有效，并且输出了我们添加的`HELP`文本。

现在我们知道如何为 Node Express 应用程序添加仪表，让我们为基于.NET Core 的微服务做同样的事情。

# 为.NET Core 服务添加仪表

让我们首先创建一个基于 Web API 模板的简单.NET Core 微服务。

1.  创建一个新的`dotnet`文件夹，并导航到其中：

```
$ mkdir dotnet && cd dotnet
```

1.  使用`dotnet`工具来创建一个名为`sample-api`的新微服务：

```
$ dotnet new webapi --output sample-api
```

1.  我们将使用.NET 的 Prometheus 适配器，该适配器作为名为`prometheus-net.AspNetCore`的 NuGet 软件包提供给我们。使用以下命令将此软件包添加到`sample-api`项目中：

```
$ dotnet add sample-api package prometheus-net.AspNetCore
```

1.  在您喜欢的代码编辑器中打开项目；例如，当使用 VS Code 时，执行以下操作：

```
$ code .
```

1.  找到`Startup.cs`文件，并打开它。在文件开头添加一个`using`语句：

```
using Prometheus; 
```

1.  然后在`Configure`方法中，将`endpoints.MapMetrics()`语句添加到端点的映射中。您的代码应如下所示：

```
public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
{
    ...
    app.UseEndpoints(endpoints =>
    {
        endpoints.MapControllers();
        endpoints.MapMetrics();
    });
}
```

请注意，以上内容适用于.NET Core 3.x 版本。如果您使用的是早期版本，则配置略有不同。请查阅以下存储库以获取更多详细信息，网址为[`github.com/prometheus-net/prometheus-net.`](https://github.com/prometheus-net/prometheus-net)

1.  有了这个，Prometheus 组件将开始发布 ASP.NET Core 的请求指标。让我们试试。首先，使用以下命令启动应用程序：

```
$ dotnet run --project sample-api

info: Microsoft.Hosting.Lifetime[0]
 Now listening on: https://localhost:5001 
info: Microsoft.Hosting.Lifetime[0]
 Now listening on: http://localhost:5000 
...
```

上述输出告诉我们微服务正在`https://localhost:5001`上监听。

1.  现在我们可以使用`curl`调用服务的指标端点：

```
$ curl --insecure https://localhost:5001/metrics 

# HELP process_private_memory_bytes Process private memory size
# TYPE process_private_memory_bytes gauge
process_private_memory_bytes 55619584
# HELP process_virtual_memory_bytes Virtual memory size in bytes. 
# TYPE process_virtual_memory_bytes gauge
process_virtual_memory_bytes 2221930053632
# HELP process_working_set_bytes Process working set
# TYPE process_working_set_bytes gauge
process_working_set_bytes 105537536
...
dotnet_collection_count_total{generation="1"} 0
dotnet_collection_count_total{generation="0"} 0
dotnet_collection_count_total{generation="2"} 0
```

我们得到的是我们微服务的系统指标列表。这很容易：我们只需要添加一个 NuGet 软件包和一行代码就可以让我们的服务被仪表化！

如果我们想要添加我们自己的（功能性）指标怎么办？这同样很简单。假设我们想要测量对我们的`/weatherforecast`端点的并发访问次数。为此，我们定义一个`gauge`并使用它来包装适当端点中的逻辑。我们可以通过以下步骤来实现这一点：

1.  定位`Controllers/WeatherForecastController.cs`类。

1.  在文件顶部添加`using Prometheus;`。

1.  在`WeatherForecastController`类中定义一个`Gauge`类型的私有实例变量：

```
private static readonly Gauge weatherForecastsInProgress = Metrics
    .CreateGauge("myapp_weather_forecasts_in_progress", 
                 "Number of weather forecast operations ongoing.");
```

1.  使用`using`语句包装`Get`方法的逻辑：

```
[HttpGet]
public IEnumerable<WeatherForecast> Get()
{
    using(weatherForecastsInProgress.TrackInProgress())
 {
...
 }
}
```

1.  重新启动微服务。

1.  使用`curl`调用`/weatherforecast`端点几次：

```
$ curl --insecure https://localhost:5001/weatherforecast
```

1.  使用`curl`获取指标，就像本节前面所述的那样：

```
$ curl --insecure https://localhost:5001/metrics 

# HELP myapp_weather_forecasts_in_progress Number of weather forecast operations ongoing.
# TYPE myapp_weather_forecasts_in_progress gauge
myapp_weather_forecasts_in_progress 0
...
```

您会注意到现在列表中有一个名为`myapp_weather_forecasts_in_progress`的新指标。它的值将为零，因为目前您没有针对被跟踪端点运行任何请求，而`gauge`类型指标只测量正在进行的请求的数量。

恭喜，您刚刚定义了您的第一个功能性指标。这只是一个开始；还有许多更复杂的可能性可以供您使用。

基于 Node.js 或.NET Core 的应用服务并不特殊。用其他语言编写的服务同样简单易懂，比如 Java、Python 或 Go。

学会了如何为应用服务添加重要指标，现在让我们看看如何使用 Prometheus 来收集和聚合这些值，以便我们可以监控分布式应用。

# 使用 Prometheus 监控分布式应用

现在我们已经学会了如何为应用服务添加 Prometheus 指标，现在是时候展示如何收集这些指标并将其转发到 Prometheus 服务器，所有指标将被聚合和存储。然后我们可以使用 Prometheus 的（简单）Web 界面或类似 Grafana 这样更复杂的解决方案来在仪表板上显示重要的指标。

与大多数用于收集应用服务和基础设施组件指标的工具不同，Prometheus 服务器承担了工作负载，并定期抓取所有定义的目标。这样应用程序和服务就不需要担心转发数据。您也可以将此描述为拉取指标与推送指标。这使得 Prometheus 服务器非常适合我们的情况。

现在我们将讨论如何将 Prometheus 部署到 Kubernetes，然后是我们的两个示例应用服务。最后，我们将在集群中部署 Grafana，并使用它在仪表板上显示我们的客户指标。

# 架构

让我们快速概述一下计划系统的架构。如前所述，我们有我们的微服务、Prometheus 服务器和 Grafana。此外，一切都将部署到 Kubernetes。以下图显示了它们之间的关系：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/567104a5-741d-48cd-9a0f-c6cb04042413.png)

使用 Prometheus 和 Grafana 监控应用程序的高级概述

在图的中上部，我们有 Prometheus，它定期从左侧显示的 Kubernetes 中抓取指标。它还定期从我们在上一节中创建和记录的 Node.js 和.NET 示例服务中抓取指标。最后，在图的右侧，我们有 Grafana，它定期从 Prometheus 中获取数据，然后在图形仪表板上显示出来。

# 部署 Prometheus 到 Kubernetes

如上所示，我们首先通过在 Kubernetes 上部署 Prometheus 来开始。首先，我们需要定义一个 Kubernetes YAML 文件，以便我们可以使用它来执行此操作。首先，我们需要定义一个 Kubernetes `Deployment`，它将创建一个 Prometheus 服务器实例的`ReplicaSet`，然后我们将定义一个 Kubernetes 服务来向我们公开 Prometheus，以便我们可以从浏览器标签内访问它，或者 Grafana 可以访问它。让我们来做吧：

1.  创建一个`ch17/kube`文件夹，并导航到其中：

```
$ mkdir -p ~/fod/ch17/kube && cd ~/fod/ch17/kube
```

1.  在此文件夹中添加一个名为`prometheus.yaml`的文件。

1.  将以下代码片段添加到此文件中；它为 Prometheus 定义了`Deployment`：

```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: prometheus-deployment
  labels:
    app: prometheus
    purpose: monitoring-demo
spec:
  replicas: 2
  selector:
    matchLabels:
      app: prometheus
      purpose: monitoring-demo
  template:
    metadata:
      labels:
        app: prometheus
        purpose: monitoring-demo
    spec:
      containers:
      - name: prometheus
        image: prom/prometheus
        volumeMounts:
          - name: config-volume
            mountPath: /etc/prometheus/prometheus.yml
            subPath: prometheus.yml
        ports:
        - containerPort: 9090
      volumes:
        - name: config-volume
          configMap:
           name: prometheus-cm
```

我们正在定义一个包含两个 Prometheus 实例的副本集。每个实例被分配两个标签：`app: prometheus`和`purpose: monitoring-demo`，用于识别目的。有趣的部分在于容器规范的`volumeMounts`。在那里，我们将一个名为`prometheus-cm`的 Kubernetes `ConfigMap`对象，其中包含 Prometheus 配置，挂载到容器中，以便 Prometheus 可以在其中找到其配置文件。`ConfigMap`类型的卷在上述代码片段的最后四行中定义。

请注意，我们将在稍后定义`config`映射。

1.  现在让我们为 Prometheus 定义 Kubernetes 服务。将此代码片段附加到文件中：

```
---
kind: Service
apiVersion: v1
metadata:
  name: prometheus-svc
spec:
  type: NodePort
  selector:
    app: prometheus
    purpose: monitoring-demo
  ports:
  - name: promui
    protocol: TCP
    port: 9090
    targetPort: 9090
```

请注意，代码片段开头的三个破折号(`---`)是必需的，用于在我们的 YAML 文件中分隔单个对象定义。

我们将我们的服务称为`prometheus-svc`，并将其设置为`NodePort`（而不仅仅是`ClusterIP`类型的服务），以便能够从主机访问 Prometheus Web UI。

1.  现在我们可以为 Prometheus 定义一个简单的配置文件。这个文件基本上指示 Prometheus 服务器从哪些服务中抓取指标以及多久抓取一次。首先，创建一个`ch17/kube/config`文件夹：

```
$ mkdir -p ~/fod/ch17/kube/config
```

1.  请在最后一个文件夹中添加一个名为`prometheus.yml`的文件，并将以下内容添加到其中：

```
scrape_configs:
    - job_name: 'prometheus'
      scrape_interval: 5s
      static_configs:
        - targets: ['localhost:9090']

    - job_name: dotnet
      scrape_interval: 5s
      static_configs:
        - targets: ['dotnet-api-svc:5000']

    - job_name: node
      scrape_interval: 5s
      static_configs:
        - targets: ['node-api-svc:3000']
          labels:
            group: 'production'
```

在前面的文件中，我们为 Prometheus 定义了三个作业：

+   +   第一个称为`prometheus`，每五秒从 Prometheus 服务器本身抓取指标。它在`localhost:9090`目标找到这些指标。请注意，默认情况下，指标应该在`/metrics`端点公开。

+   第二个作业称为`dotnet`，从`dotnet-api-svc:5000`服务中抓取指标，这将是我们之前定义和配置的.NET Core 服务。

+   最后，第三个作业也为我们的 Node 服务做同样的事情。请注意，我们还为这个作业添加了一个`group: 'production'`标签。这允许进一步对作业或任务进行分组。

1.  现在我们可以在我们的 Kubernetes 集群中定义`ConfigMap`对象，使用下一个命令。在`ch17/kube`文件夹中执行以下命令：

```
$ kubectl create configmap prometheus-cm \
 --from-file config/prometheus.yml
```

1.  现在我们可以使用以下命令将 Prometheus 部署到我们的 Kubernetes 服务器：

```
$ kubectl apply -f prometheus.yaml deployment.apps/prometheus-deployment created
service/prometheus-svc created
```

1.  让我们再次确认部署成功：

```
$ kubectl get all

NAME                                        READY  STATUS   RESTARTS  AGE
pod/prometheus-deployment-779677977f-727hb  1/1    Running  0         24s
pod/prometheus-deployment-779677977f-f5l7k  1/1    Running  0         24s

NAME                    TYPE       CLUSTER-IP      EXTERNAL-IP  PORT(S)         AGE
service/kubernetes      ClusterIP  10.96.0.1       <none>       443/TCP         28d
service/prometheus-svc  NodePort   10.110.239.245  <none>       9090:31962/TCP  24s

NAME                                   READY  UP-TO-DATE  AVAILABLE  AGE
deployment.apps/prometheus-deployment  2/2    2           2          24s

NAME                                              DESIRED  CURRENT  READY  AGE
replicaset.apps/prometheus-deployment-779677977f  2        2        2      24s
```

密切关注 pod 的列表，并确保它们都正常运行。还请注意`prometheus-svc`对象的端口映射。在我的情况下，`9090`端口映射到`31962`主机端口。在你的情况下，后者可能不同，但也会在`3xxxx`范围内。

1.  现在我们可以访问 Prometheus 的 Web UI。打开一个新的浏览器标签，并导航到`http://localhost:<port>/targets`，在我的情况下，`<port>`是`31962`。你应该看到类似这样的东西：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/75ab2089-88ea-4bb2-b5c3-37e6e7c90d18.png)

Prometheus Web UI 显示配置的目标

在最后的截图中，我们可以看到我们为 Prometheus 定义了三个目标。列表中只有第三个目标是可用的，并且可以被 Prometheus 访问。这是我们在作业的配置文件中定义的端点，用于从 Prometheus 本身抓取指标。其他两个服务目前没有运行，因此它们的状态是 down。

1.  现在通过单击 UI 顶部菜单中的相应链接，导航到 Graph。

1.  打开指标下拉列表，并检查 Prometheus 找到的所有列出的指标。在这种情况下，只有由 Prometheus 服务器本身定义的指标列表：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/73ba9c62-5f75-4962-8fff-84911faec999.png)

Prometheus web UI 显示可用的指标

有了这个，我们准备将之前创建的.NET 和 Node 示例服务部署到 Kubernetes 上。

# 将我们的应用服务部署到 Kubernetes

在我们可以使用之前创建的示例服务并将它们部署到 Kubernetes 之前，我们必须为它们创建 Docker 镜像并将它们推送到容器注册表。在我们的情况下，我们将它们推送到 Docker Hub。

让我们从.NET Core 示例开始：

1.  找到.NET 项目中的`Program.cs`文件并打开它。

1.  修改`CreateHostBuilder`方法，使其看起来像这样：

```
Host.CreateDefaultBuilder(args)
    .ConfigureWebHostDefaults(webBuilder =>
    {
        webBuilder.UseStartup<Startup>();
        webBuilder.UseUrls("http://*:5000");
    });
```

1.  在`ch17/dotnet/sample-api`项目文件夹中添加以下内容的`Dockerfile`：

```
FROM mcr.microsoft.com/dotnet/core/aspnet:3.1 AS base
WORKDIR /app
EXPOSE 5000

FROM mcr.microsoft.com/dotnet/core/sdk:3.1 AS builder
WORKDIR /src
COPY sample-api.csproj ./
RUN dotnet restore
COPY . .
RUN dotnet build -c Release -o /src/build

FROM builder AS publisher
RUN dotnet publish -c Release -o /src/publish

FROM base AS final
COPY --from=publisher /src/publish .
ENTRYPOINT ["dotnet", "sample-api.dll"]
```

1.  在`dotnet/sample-api`项目文件夹中使用以下命令创建一个 Docker 镜像：

```
$ docker image build -t fundamentalsofdocker/ch17-dotnet-api:2.0 .
```

注意，您可能需要在前后命令中用您自己的 Docker Hub 用户名替换`fundamentalsofdocker`。

1.  将镜像推送到 Docker Hub：

```
$ docker image push fundamentalsofdocker/ch17-dotnet-api:2.0
```

现在我们对 Node 示例 API 做同样的操作：

1.  在`ch17/node`项目文件夹中添加以下内容的`Dockerfile`：

```
FROM node:13.5-alpine
WORKDIR /app
COPY package.json ./
RUN npm install
COPY . .
EXPOSE 3000
CMD ["npm", "start"]
```

1.  在`ch17/node`项目文件夹中使用以下命令创建一个 Docker 镜像：

```
$ docker image build -t fundamentalsofdocker/ch17-node-api:2.0 .
```

再次注意，您可能需要在前后命令中用您自己的 Docker Hub 用户名替换`fundamentalsofdocker`。

1.  将镜像推送到 Docker Hub：

```
$ docker image push fundamentalsofdocker/ch17-node-api:2.0
```

有了这个，我们准备为部署这两个服务定义必要的 Kubernetes 对象。定义有些冗长，可以在存储库的`~/fod/ch17/kube/app-services.yaml`文件中找到。请打开该文件并分析其内容。

让我们使用这个文件来部署服务：

1.  使用以下命令：

```
$ kubectl apply -f app-services.yaml

deployment.apps/dotnet-api-deployment created
service/dotnet-api-svc created
deployment.apps/node-api-deployment created
service/node-api-svc created
```

1.  使用`kubectl get all`命令双重检查服务是否正常运行。确保 Node 和.NET 示例 API 服务的所有 pod 都正常运行。

1.  列出所有 Kubernetes 服务，找出每个应用服务的主机端口：

```
$ kubectl get services

NAME             TYPE        CLUSTER-IP       EXTERNAL-IP   PORT(S)          AGE
dotnet-api-svc   NodePort    10.98.137.249    <none>        5000:30822/TCP   5m29s
grafana-svc      NodePort    10.107.232.211   <none>        8080:31461/TCP   33m
kubernetes       ClusterIP   10.96.0.1        <none>        443/TCP          28d
node-api-svc     NodePort    10.110.15.131    <none>        5000:31713/TCP   5m29s
prometheus-svc   NodePort    10.110.239.245   <none>        9090:31962/TCP   77m
```

在我的情况下，.NET API 映射到端口`30822`，Node API 映射到端口`31713`。您的端口可能不同。

1.  使用`curl`访问两个服务的`/metrics`端点：

```
$ curl localhost:30822/metrics # HELP process_working_set_bytes Process working set
# TYPE process_working_set_bytes gauge
process_working_set_bytes 95236096
# HELP process_private_memory_bytes Process private memory size
# TYPE process_private_memory_bytes gauge
process_private_memory_bytes 186617856
...

$ curl localhost:31713/metrics
# HELP process_cpu_user_seconds_total Total user CPU time spent in seconds.
# TYPE process_cpu_user_seconds_total counter
process_cpu_user_seconds_total 1.0394399999999997 1578294999302
# HELP process_cpu_system_seconds_total Total system CPU time spent in seconds.
# TYPE process_cpu_system_seconds_total counter
process_cpu_system_seconds_total 0.3370890000000001 1578294999302
...
```

1.  在 Prometheus 中双重检查`/targets`端点，确保这两个微服务现在是可达的：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/9500692f-aabe-4ceb-822b-71ef7c743735.png)

Prometheus 显示所有目标都正常运行

1.  为了确保我们为 Node.js 和.NET 服务定义和公开的自定义指标被定义和公开，我们需要至少访问每个服务一次。因此，使用`curl`多次访问各自的端点：

```
# access the /weatherforecast endpoint in the .NET service
$ curl localhost:31713/weatherforecast

# and access the /hello endpoint in the Node service 
$ curl localhost:30822/hello
```

最后一步是将 Grafana 部署到 Kubernetes，这样我们就能够创建复杂和外观吸引人的仪表板，显示我们应用服务和/或基础设施组件的关键指标。

# 将 Grafana 部署到 Kubernetes

现在让我们也将 Grafana 部署到我们的 Kubernetes 集群中，这样我们就可以像分布式应用程序的所有其他组件一样管理这个工具。作为一个允许我们为监控应用程序创建仪表板的工具，Grafana 可以被认为是使命关键的，因此需要这种对待。

将 Grafana 部署到集群中非常简单。让我们按照以下步骤进行：

1.  在`ch17/kube`文件夹中添加一个名为`grafana.yaml`的新文件。

1.  在这个文件中，为 Kubernetes 的 Grafana`Deployment`添加定义：

```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: grafana-deployment
  labels:
    app: grafana
    purpose: monitoring-demo
spec:
  replicas: 1
  selector:
    matchLabels:
      app: grafana
      purpose: monitoring-demo
  template:
    metadata:
      labels:
        app: grafana
        purpose: monitoring-demo
    spec:
      containers:
      - name: grafana
        image: grafana/grafana
```

在这个定义中没有什么意外。在这个例子中，我们运行了一个单独的 Grafana 实例，并且它使用`app`和`purpose`标签进行识别，类似于我们用于 Prometheus 的方式。这次不需要特殊的卷映射，因为我们只使用默认设置。

1.  我们还需要暴露 Grafana，因此需要将以下片段添加到前面的文件中，以定义 Grafana 的服务：

```
---
kind: Service
apiVersion: v1
metadata:
  name: grafana-svc
spec:
  type: NodePort
  selector:
    app: grafana
    purpose: monitoring-demo
  ports:
  - name: grafanaui
    protocol: TCP
    port: 3000
    targetPort: 3000
```

再次，我们使用`NodePort`类型的服务，以便能够从我们的主机访问 Grafana UI。

1.  现在我们可以使用这个命令部署 Grafana：

```
$ kubectl apply -f grafana.yaml deployment.apps/grafana-deployment created
service/grafana-svc created
```

1.  让我们找出我们可以访问 Grafana 的端口号是多少：

```
$ kubectl get services

NAME             TYPE        CLUSTER-IP      EXTERNAL-IP   PORT(S)          AGE
dotnet-api-svc   NodePort    10.100.250.40   <none>        5000:30781/TCP   16m
grafana-svc      NodePort    10.102.239.176  <none>        3000:32379/TCP   11m
kubernetes       ClusterIP   10.96.0.1       <none>        443/TCP          28d
node-api-svc     NodePort    10.100.76.13    <none>        3000:30731/TCP   16m
prometheus-svc   NodePort    10.104.205.217  <none>        9090:31246/TCP   16m
```

1.  打开一个新的浏览器标签，并导航到`http://localhost:<port>`，其中`<port>`是您在上一步中确定的端口，在我的情况下是`32379`。您应该会看到类似于这样的东西：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/bddbf845-8092-4f22-9777-19b297470767.png)

Grafana 的登录界面

1.  使用默认的`admin`用户名登录，密码也是`admin`。当要求更改密码时，现在点击跳过链接。您将被重定向到主页仪表板。

1.  在主页仪表板上，点击创建您的第一个数据源，然后从数据源列表中选择 Prometheus。

1.  为 Prometheus 的 URL 添加`http://prometheus-svc:9090`，然后点击绿色的保存和测试按钮。

1.  在 Grafana 中，返回到主页仪表板，然后选择新仪表板。

1.  单击“添加查询”，然后从指标下拉菜单中选择我们在.NET 示例服务中定义的自定义指标：

！[](assets/cc959094-a62e-4d8d-9af7-fb6b43dcfcfe.png)

在 Grafana 中选择.NET 自定义指标

1.  将相对时间的值从`1h`更改为`5m`（五分钟）。

1.  更改视图右上角找到的仪表板刷新率为`5s`（五秒）。

1.  对 Node 示例服务中定义的自定义指标执行相同操作，这样您的新仪表板上将有两个面板。

1.  通过查阅[`grafana.com/docs/grafana/latest/guides/getting_started/`](https://grafana.com/docs/grafana/latest/guides/getting_started/)中的文档，修改仪表板及其面板以满足您的喜好。

1.  使用`curl`访问示例服务的两个端点，并观察仪表板。它可能看起来像这样：

！[](assets/40be8912-dc9f-4b36-a80b-970944799afa.png)

具有两个自定义指标的 Grafana 仪表板

总之，我们可以说 Prometheus 非常适合监视我们的微服务，因为我们只需要公开一个指标端口，因此不需要增加太多复杂性或运行额外的服务。然后，Prometheus 负责定期抓取配置的目标，这样我们的服务就不需要担心发出它们。

# 故障排除正在生产中运行的服务

推荐的最佳实践是为生产创建最小的镜像，不包含任何绝对不需要的内容。这包括通常用于调试和故障排除应用程序的常用工具，例如 netcat、iostat、ip 或其他工具。理想情况下，生产系统只安装了容器编排软件（如 Kubernetes）和最小的操作系统（如 Core OS）的集群节点。应用程序容器理想情况下只包含绝对必要的二进制文件。这最小化了攻击面和处理漏洞的风险。此外，小型镜像具有快速下载、在磁盘和内存上使用更少空间以及显示更快启动时间的优势。

但是，如果我们 Kubernetes 集群上运行的应用服务之一显示出意外行为，甚至可能崩溃，这可能会成为一个问题。有时，我们无法仅从生成和收集的日志中找到问题的根本原因，因此我们可能需要在集群节点上对组件进行故障排除。

我们可能会想要 SSH 进入给定的集群节点并运行一些诊断工具。但这是不可能的，因为集群节点只运行一个没有安装此类工具的最小 Linux 发行版。作为开发人员，我们现在可以要求集群管理员安装我们打算使用的所有 Linux 诊断工具。但这不是一个好主意。首先，这将为潜在的脆弱软件打开大门，现在这些软件驻留在集群节点上，危及运行在该节点上的所有其他 pod，并且为黑客打开了可以利用的集群本身的大门。此外，无论您有多么信任您的开发人员，直接让开发人员访问生产集群的节点都是一个坏主意。只有有限数量的集群管理员才能够这样做。

更好的解决方案是让集群管理员代表开发人员运行所谓的堡垒容器。这个堡垒或故障排除容器安装了我们需要的所有工具，可以帮助我们找出应用服务中 bug 的根本原因。还可以在主机的网络命名空间中运行堡垒容器；因此，它将完全访问容器主机的所有网络流量。

# netshoot 容器

前 Docker 员工 Nicola Kabar 创建了一个方便的 Docker 镜像，名为`nicolaka/netshoot`，Docker 的现场工程师经常使用它来排查在 Kubernetes 或 Docker Swarm 上运行的生产应用程序。我们为本书创建了该镜像的副本，可在`fundamentalsofdocker/netshoot`上找到。创建者的这个容器的目的如下：

“目的：Docker 和 Kubernetes 网络故障排除可能变得复杂。通过对 Docker 和 Kubernetes 网络工作原理的适当理解以及正确的工具集，您可以解决这些网络问题。`netshoot`容器具有一组强大的网络故障排除工具，可用于解决 Docker 网络问题。” - *Nicola Kabar*

要将此容器用于调试目的，我们可以按照以下步骤进行：

1.  使用以下命令在 Kubernetes 上启动一个一次性的堡垒容器进行调试：

```
$ kubectl run tmp-shell --generator=run-pod/v1 --rm -i --tty \
 --image fundamentalsofdocker/netshoot \
 --command -- bash

 bash-5.0#
```

1.  您现在可以在此容器中使用`ip`等工具：

```
bash-5.0# ip a
```

在我的机器上，如果我在 Windows 上的 Docker 上运行 pod，结果会类似于以下内容：

```
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
 link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
 inet 127.0.0.1/8 scope host lo
 valid_lft forever preferred_lft forever
 2: sit0@NONE: <NOARP> mtu 1480 qdisc noop state DOWN group default qlen 1000
 link/sit 0.0.0.0 brd 0.0.0.0
 4: eth0@if263: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default
 link/ether 52:52:9d:1d:fd:cc brd ff:ff:ff:ff:ff:ff link-netnsid 0
 inet 10.1.0.71/16 scope global eth0
 valid_lft forever preferred_lft forever
```

1.  要离开这个故障排除容器，只需按下*Ctrl* + *D*或输入`exit`然后按*Enter*。

1.  如果我们需要深入一点，并在与 Kubernetes 主机相同的网络命名空间中运行容器，那么我们可以使用这个命令：

```
$ kubectl run tmp-shell --generator=run-pod/v1 --rm -i --tty \
 --overrides='{"spec": {"hostNetwork": true}}' \
 --image fundamentalsofdocker/netshoot \
 --command -- bash
```

1.  如果我们在这个容器中再次运行`ip`，我们将看到容器主机也能看到的所有`veth`端点。

`netshoot`容器安装了工程师在解决与网络相关的问题时所需的所有常用工具。其中一些更常见的工具有`ctop`、`curl`、`dhcping`、`drill`、`ethtool`、`iftop`、`iperf`和`iproute2`。

# 摘要

在本章中，您学习了一些用于监视在 Kubernetes 集群上运行的单个服务或整个分布式应用程序的技术。此外，您还调查了在生产环境中运行的应用服务的故障排除，而无需更改集群或运行服务的集群节点。

在本书的下一章中，您将了解在云中运行容器化应用程序的一些最流行的方式。本章包括如何自行托管和使用托管解决方案的示例，并讨论它们的优缺点。微软 Azure 和谷歌云引擎等供应商的完全托管服务也会被简要讨论。

# 问题

为了评估你的学习进度，请回答以下问题：

1.  为什么为您的应用服务进行仪器化是重要的？

1.  你能向一个感兴趣的门外汉描述一下 Prometheus 是什么吗？

1.  导出 Prometheus 指标很容易。你能用简单的话描述一下如何为 Node.js 应用程序做到这一点吗？

1.  您需要在生产环境中调试在 Kubernetes 上运行的服务。不幸的是，这个服务产生的日志本身并不能提供足够的信息来准确定位根本原因。您决定直接在相应的 Kubernetes 集群节点上对该服务进行故障排除。您该如何进行？

# 进一步阅读

以下是一些链接，提供了本章讨论的主题的额外信息：

+   使用 Prometheus 进行 Kubernetes 监控*:* [`sysdig.com/blog/kubernetes-monitoring-prometheus/`](https://sysdig.com/blog/kubernetes-monitoring-prometheus/)

+   Prometheus 客户端库：[`prometheus.io/docs/instrumenting/clientlibs/`](https://prometheus.io/docs/instrumenting/clientlibs/)

+   netshoot 容器：[`github.com/nicolaka/netshoot`](https://github.com/nicolaka/netshoot)


# 第十八章：在云中运行容器化应用程序

在上一章中，我们学习了如何在生产环境中部署、监控和排除故障。

在本章中，我们将概述在云中运行容器化应用程序的一些最流行的方法。我们将探讨自托管和托管解决方案，并讨论它们的优缺点。我们将简要讨论来自供应商如 Microsoft Azure 和 Google Cloud Engine 的完全托管的解决方案。

以下是本章将讨论的主题：

+   在**Amazon Web Services** (**AWS**)上部署和使用 Docker **Enterprise Edition** (**EE**)

+   探索 Microsoft 的**Azure Kubernetes Service** (**AKS**)

+   了解**Google Kubernetes Engine** (**GKE**)

阅读完本章后，您将能够做到以下几点：

+   使用 Docker EE 在 AWS 中创建一个 Kubernetes 集群

+   在 AWS 上部署和运行一个简单的分布式应用程序的 Docker EE 集群

+   在 Microsoft 的 AKS 上部署和运行一个简单的分布式应用程序

+   在 GKE 上部署和运行一个简单的分布式应用程序

# 技术要求

在本章中，我们将使用 AWS、Microsoft Azure 和 Google Cloud。因此，需要为每个平台拥有一个账户。如果您没有现有账户，可以要求这些云服务提供商提供试用账户。

我们还将使用 GitHub 上我们的`labs`仓库中`~/fod-solution/ch18`文件夹中的文件，网址为[`github.com/PacktPublishing/Learn-Docker---Fundamentals-of-Docker-19.x-Second-Edition/tree/master/ch18`](https://github.com/PacktPublishing/Learn-Docker---Fundamentals-of-Docker-19.x-Second-Edition/tree/master/ch18)。

# 在 AWS 上部署和使用 Docker EE

在这一部分，我们将安装 Docker **Universal Control Plane** (**UCP**) 版本 3.0。UCP 是 Docker 企业套件的一部分，支持两种编排引擎，Docker Swarm 和 Kubernetes。UCP 可以在云端或本地安装。甚至可以在 UCP 中使用混合云。

要尝试这个，您需要一个 Docker EE 的有效许可证，或者您可以在 Docker Store 上申请免费测试许可证。

# 基础设施的规划

在这一部分，我们将设置安装 Docker UCP 所需的基础设施。如果您对 AWS 有一定了解，这相对比较简单。让我们按照以下步骤来做：

1.  在 AWS 中使用 Ubuntu 16.04 服务器 AMI 创建一个**自动扩展组**（**ASG**）。配置 ASG 包含三个大小为`t2.xlarge`的实例。这是此操作的结果：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/3aef6cd3-8664-4019-8eff-5ef9712222f7.png)AWS 上准备好 Docker EE 的 ASG

一旦 ASG 创建完成，并且在继续之前，我们需要稍微打开**安全组**（**SG**）（我们的 ASG 是其中的一部分），以便我们可以通过 SSH 从我们的笔记本访问它，也以便**虚拟机**（**VMs**）可以相互通信。

1.  转到您的 SG 并添加两个新的入站规则，如下所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/00df1c32-a142-4c54-9890-8f69a6fa1a88.png)AWS SG 设置

在上面的屏幕截图中，第一个规则允许来自我的个人笔记本（IP 地址为`70.113.114.234`）的任何流量访问 SG 中的任何资源。第二个规则允许 SG 内部的任何流量。这些设置不适用于生产环境，因为它们太过宽松。但是，对于此演示环境，它们效果很好。

接下来，我们将向您展示如何在我们刚准备好的虚拟机上安装 Docker。

# 安装 Docker

在配置完集群节点之后，我们需要在每个节点上安装 Docker。按照以下步骤可以轻松实现：

1.  SSH 进入所有三个实例并安装 Docker。使用下载的密钥，SSH 进入第一台机器：

```
$ ssh -i pets.pem ubuntu@<IP address>
```

在这里，`<IP 地址>`是我们要 SSH 进入的 VM 的公共 IP 地址。

1.  现在我们可以安装 Docker 了。有关详细说明，请参阅[`dockr.ly/2HiWfBc`](https://dockr.ly/2HiWfBc)。我们在`~/fod/ch18/aws`文件夹中有一个名为`install-docker.sh`的脚本可以使用。

1.  首先，我们需要将`labs` GitHub 存储库克隆到虚拟机中：

```
$ git clone https://github.com/PacktPublishing/Learn-Docker---Fundamentals-of-Docker-19.x-Second-Edition.git ~/fod
$ cd ~/fod/ch18/aws
```

1.  然后，我们运行脚本来安装 Docker：

```
$ ./install-docker.sh
```

1.  脚本完成后，我们可以使用`sudo docker version`验证 Docker 是否已安装。对其他两个 VM 重复前面的代码。

`sudo`只在下一个 SSH 会话打开到此 VM 之前是必要的，因为我们已将`ubuntu`用户添加到`docker`组中。因此，我们需要退出当前的 SSH 会话并重新连接。这次，`sudo`不应与`docker`一起使用。

接下来，我们将展示如何在我们刚准备好的基础设施上安装 Docker UCP。

# 安装 Docker UCP

我们需要设置一些环境变量，如下所示：

```
$ export UCP_IP=<IP address>
$ export UCP_FQDN=<FQDN>
$ export UCP_VERSION=3.0.0-beta2
```

在这里，`<IP 地址>`和`<FQDN>`是我们在 UCP 中安装的 AWS EC2 实例的公共 IP 地址和公共 DNS 名称。

之后，我们可以使用以下命令下载 UCP 需要的所有镜像：

```
$ docker run --rm docker/ucp:${UCP_VERSION} images --list \
 | xargs -L 1 docker pull
```

最后，我们可以安装 UCP：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/cd7dc52c-302c-4bee-8746-89a1bde6a8da.png)在 AWS 的 VM 中安装 UCP 3.0.0-beta2

现在，我们可以打开浏览器窗口并导航到`https://<IP 地址>`。使用您的用户名`admin`和密码`adminadmin`登录。当要求许可证时，上传您的许可证密钥或按照链接获取试用许可证。

登录后，在左侧的“共享资源”部分下，选择“节点”，然后单击“添加节点”按钮：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/fbd3044c-9c09-4899-ab0b-8dd5ba14112b.png)向 UCP 添加新节点

在随后的“添加节点”对话框中，请确保节点类型为 Linux，并选择“工作节点”角色。然后，复制对话框底部的`docker swarm join`命令。SSH 进入您创建的另外两个 VM 并运行此命令，使相应的节点加入 Docker Swarm 作为工作节点：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/a45a4a6d-6e7d-4c02-be40-c3175c9511b8.png)将节点作为工作节点加入到 UCP 集群

回到 UCP 的 Web UI 中，您应该看到我们现在有三个准备好的节点，如下所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/ee9b3da4-5b1e-4a53-be1a-72c52291bd58.png)UCP 集群中的节点列表

默认情况下，工作节点被配置为只能运行 Docker Swarm 工作负载。但是，这可以在节点详细信息中更改。在此，有三种设置可能：仅 Swarm、仅 Kubernetes 或混合工作负载。让我们从 Docker Swarm 作为编排引擎开始，并部署我们的宠物应用程序。

# 使用远程管理员管理 UCP 集群

为了能够从我们的笔记本电脑远程管理我们的 UCP 集群，我们需要从 UCP 中创建并下载一个所谓的**客户端包**。按照以下步骤进行：

1.  在 UCP Web UI 中，在左侧的“管理员”下，选择“我的个人资料”选项。

1.  在随后的对话中，选择“新客户端包”选项，然后生成客户端包：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/e6dd0c9c-f925-4ae3-a78f-5113da2f806d.png)生成并下载 UCP 客户端包

1.  在您的磁盘上找到并解压下载的包。

1.  在新的终端窗口中，导航到该文件夹并源化`env.sh`文件：

```
$ source env.sh
```

您应该会得到类似于这样的输出：

```
Cluster "ucp_34.232.53.86:6443_admin" set.
User "ucp_34.232.53.86:6443_admin" set.
Context "ucp_34.232.53.86:6443_admin" created.
```

现在，我们可以验证我们确实可以远程访问 UCP 集群，例如，列出集群的所有节点：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/8d630be3-12cd-4a63-9a0b-d9b2a8aab377.png)列出远程 UCP 集群的所有节点

在下一节中，我们将看看如何使用 Docker Swarm 作为编排引擎将宠物应用程序部署为堆栈。

# 部署到 Docker Swarm

现在是时候将我们的分布式应用程序部署到由 Docker Swarm 编排的集群了。按照以下步骤进行操作：

1.  在终端中，导航到`〜/fod/ch18/ucp`文件夹，并使用`stack.yml`文件创建`pets`堆栈：

将宠物堆栈部署到 UCP 集群

1.  在 UCP Web UI 中，我们可以验证已创建堆栈：

UCP Web UI 中的宠物堆栈列表

1.  为了测试应用程序，我们可以在主菜单的 Swarm 下导航到 Services。集群中运行的服务列表将显示如下：

宠物堆栈的“web”服务的详细信息

在上述截图中，我们看到了`pets`堆栈的两个服务`web`和`db`。如果我们点击`web`服务，它的详细信息将显示在右侧。在那里，我们找到了一个条目，发布的端点。

1.  单击链接，我们的`pets`应用程序应该显示在浏览器中。

完成后，使用以下命令从控制台中删除堆栈：

```
$ docker stack rm pets
```

或者，您可以尝试从 UCP Web UI 中删除该堆栈。

# 部署到 Kubernetes

从用于远程访问 UCP 集群以使用 Docker Swarm 作为编排引擎部署宠物应用程序的堆栈的同一终端，我们现在可以尝试使用 Kubernetes 作为编排引擎将宠物应用程序部署到 UCP 集群。

确保您仍然在`〜/fod/ch18/ucp`文件夹中。使用`kubectl`部署宠物应用程序。首先，我们需要测试是否可以使用 Kubernetes CLI 获取集群的所有节点：

使用 Kubernetes CLI 获取 UCP 集群的所有节点

显然，我的环境已正确配置，并且`kubectl`确实可以列出 UCP 集群中的所有节点。这意味着我现在可以使用`pets.yaml`文件中的定义部署宠物应用程序：

使用 Kubernetes CLI 在 UCP 集群中创建宠物应用程序

使用`kubectl get all`可以列出通过创建的对象。然后在浏览器中，我们可以导航到`http://<IP 地址>:<端口>`来访问宠物应用程序，其中`<IP 地址>`是 UCP 集群节点之一的公共 IP 地址，`<端口>`是`web` Kubernetes 服务发布的端口。

我们在 AWS ASG 中创建了一个由三个 VM 组成的集群，并在其中安装了 Docker 和 UCP 3.0。然后我们将我们著名的宠物应用程序部署到 UCP 集群中，一次使用 Docker Swarm 作为编排引擎，一次使用 Kubernetes。

Docker UCP 是一个平台无关的容器平台，可以在任何云和本地、裸机或虚拟化环境中提供安全的企业级软件供应链。甚至在编排引擎方面也提供了选择的自由。用户可以在 Docker Swarm 和 Kubernetes 之间进行选择。还可以在同一集群中在两个编排器中运行应用程序。

# 探索微软的 Azure Kubernetes 服务（AKS）

要在 Azure 中尝试微软的与容器相关的服务，我们需要在 Azure 上拥有一个帐户。您可以创建一个试用帐户或使用现有帐户。您可以在此处获取免费试用帐户：https://azure.microsoft.com/en-us/free/。

微软在 Azure 上提供了不同的与容器相关的服务。最容易使用的可能是 Azure 容器实例，它承诺在 Azure 中以最快最简单的方式运行容器，而无需预配任何虚拟机，也无需采用更高级别的服务。如果您想在托管环境中运行单个容器，这项服务确实非常有用。设置非常简单。在 Azure 门户（portal.azure.com）中，您首先创建一个新的资源组，然后创建一个 Azure 容器实例。您只需要填写一个简短的表单，包括容器的名称、要使用的镜像和要打开的端口等属性。容器可以在公共或私有 IP 地址上提供，并且如果崩溃，将自动重新启动。还有一个不错的管理控制台可用，例如用于监视 CPU 和内存等资源消耗。

第二种选择是 Azure 容器服务（ACS），它提供了一种简化创建、配置和管理预配置为运行容器化应用程序的虚拟机集群的方式。ACS 使用 Docker 镜像，并提供了三种编排器选择：Kubernetes、Docker Swarm 和 DC/OS（由 Apache Mesos 提供支持）。微软声称他们的服务可以扩展到数万个容器。ACS 是免费的，您只需要为计算资源付费。

在本节中，我们将集中讨论基于 Kubernetes 的最受欢迎的服务。它被称为 AKS，可以在这里找到：[`azure.microsoft.com/en-us/services/kubernetes-service/`](https://azure.microsoft.com/en-us/services/kubernetes-service/)。AKS 使您能够轻松将应用程序部署到云中，并在 Kubernetes 上运行它们。所有繁琐和困难的管理任务都由微软处理，您可以完全专注于您的应用程序。这意味着您永远不必处理诸如安装和管理 Kubernetes、升级 Kubernetes 或升级底层 Kubernetes 节点操作系统等任务。所有这些都由微软 Azure 的专家处理。此外，您永远不必处理`etc`或 Kubernetes 主节点。这些都对您隐藏，您唯一需要与之交互的是运行您的应用程序的 Kubernetes 工作节点。

# 准备 Azure CLI

也就是说，让我们开始吧。我们假设您已经创建了一个免费试用账户，或者您正在使用 Azure 上的现有账户。与 Azure 账户交互的方式有很多种。我们将使用在本地计算机上运行的 Azure CLI。我们可以在本地计算机上本地下载和安装 Azure CLI，也可以在本地 Docker for Desktop 上运行容器中的 Azure CLI。由于本书都是关于容器的，让我们选择后一种方法。

Azure CLI 的最新版本可以在 Docker Hub 上找到。让我们拉取它：

```
$ docker image pull mcr.microsoft.com/azure-cli:latest
```

我们将从此 CLI 运行一个容器，并在容器内部运行所有后续命令。现在，我们需要克服一个小问题。这个容器将不会安装 Docker 客户端。但我们也将运行一些 Docker 命令，所以我们必须创建一个从前面的镜像派生出来的自定义镜像，其中包含一个 Docker 客户端。需要的`Dockerfile`可以在`~/fod/ch18`文件夹中找到，内容如下：

```
FROM mcr.microsoft.com/azure-cli:latest
RUN apk update && apk add docker
```

在第 2 行，我们只是使用 Alpine 软件包管理器`apk`来安装 Docker。然后我们可以使用 Docker Compose 来构建和运行这个自定义镜像。相应的`docker-compose.yml`文件如下：

```
version: "2.4"
services:
    az:
        image: fundamentalsofdocker/azure-cli
        build: .
        command: tail -F anything
        working_dir: /app
        volumes:
            - /var/run/docker.sock:/var/run/docker.sock
            - .:/app
```

请注意用于保持容器运行的命令，以及在`volumes`部分中挂载 Docker 套接字和当前文件夹的命令。如果您在 Windows 上运行 Docker for Desktop，则需要定义`COMPOSE_CONVERT_WINDOWS_PATHS`环境变量以能够挂载 Docker 套接字。使用

从 Bash shell 执行`export COMPOSE_CONVERT_WINDOWS_PATHS=1`，或者在运行 PowerShell 时执行`$Env:COMPOSE_CONVERT_WINDOWS_PATHS=1`。请参考以下链接获取更多详情：[`github.com/docker/compose/issues/4240`](https://github.com/docker/compose/issues/4240)。

现在，让我们构建并运行这个容器：

```
$ docker-compose up --build -d
```

然后，让我们进入`az`容器，并在其中运行一个 Bash shell，命令如下：

```
$ docker-compose exec az /bin/bash

bash-5.0#
```

我们将发现自己在容器内部的 Bash shell 中运行。让我们首先检查 CLI 的版本：

```
bash-5.0# az --version
```

这应该会产生类似于以下内容的输出（缩短版）：

```
azure-cli 2.0.78
...
Your CLI is up-to-date.
```

好的，我们正在运行版本`2.0.78`。接下来，我们需要登录到我们的账户。执行以下命令：

```
bash-5.0# az login
```

您将收到以下消息：

```
To sign in, use a web browser to open the page https://microsoft.com/devicelogin and enter the code <code> to authenticate.
```

按照说明通过浏览器登录。一旦您成功验证了您的 Azure 账户，您可以回到您的终端，您应该已经登录了，这将由您得到的输出所指示：

```
[
  {
    "cloudName": "AzureCloud",
    "id": "<id>",
    "isDefault": true,
    "name": "<account name>",
    "state": "Enabled",
    "tenantId": "<tenant-it>",
    "user": {
      "name": "xxx@hotmail.com",
      "type": "user"
    }
  }
]
```

现在，我们准备首先将我们的容器映像移动到 Azure。

# 在 Azure 上创建一个容器注册表

首先，我们创建一个名为`animal-rg`的新资源组。在 Azure 中，资源组用于逻辑地组合一组相关的资源。为了获得最佳的云体验并保持延迟低，重要的是您选择一个靠近您的地区的数据中心。您可以使用以下命令列出所有地区：

```
bash-5.0# az account list-locations 
[
  {
    "displayName": "East Asia",
    "id": "/subscriptions/186760ad-9152-4499-b317-c9bff441fb9d/locations/eastasia",
    "latitude": "22.267",
    "longitude": "114.188",
    "name": "eastasia",
    "subscriptionId": null
  },
  ...
]
```

这将为您提供一个相当长的列表，列出了您可以选择的所有可能区域。使用`name`，例如`eastasia`，来标识您选择的区域。在我的情况下，我将选择`westeurope`。请注意，并非所有列出的位置都适用于资源组。

创建资源组的命令很简单；我们只需要为组和位置命名：

```
bash-5.0# az group create --name animals-rg --location westeurope

{
  "id": "/subscriptions/186760ad-9152-4499-b317-c9bff441fb9d/resourceGroups/animals-rg",
  "location": "westeurope",
  "managedBy": null,
  "name": "animals-rg",
  "properties": {    
    "provisioningState": "Succeeded"
  },
  "tags": null,
  "type": "Microsoft.Resources/resourceGroups"
}
```

确保您的输出显示`"provisioningState": "Succeeded"`。

在生产环境中运行容器化应用程序时，我们希望确保可以自由地从容器注册表中下载相应的容器图像。到目前为止，我们一直从 Docker Hub 下载我们的图像。但这通常是不可能的。出于安全原因，生产系统的服务器通常无法直接访问互联网，因此无法访问 Docker Hub。让我们遵循这个最佳实践，并假设我们即将创建的 Kubernetes 集群也是如此。

那么，我们能做什么呢？嗯，解决方案是使用一个靠近我们集群的容器镜像注册表，并且处于相同的安全上下文中。在 Azure 中，我们可以创建一个**Azure 容器注册表**（**ACR**）并在那里托管我们的图像。让我们首先创建这样一个注册表：

```
bash-5.0# az acr create --resource-group animals-rg --name <acr-name> --sku Basic
```

请注意，`<acr-name>`需要是唯一的。在我的情况下，我选择了名称`fodanimalsacr`。输出（缩短版）如下所示：

```
{
 "adminUserEnabled": false,
 "creationDate": "2019-12-22T10:31:14.848776+00:00",
 "id": "/subscriptions/186760ad...",
 "location": "westeurope",
 "loginServer": "fodanimalsacr.azurecr.io",
 "name": "fodanimalsacr",
 ...
 "provisioningState": "Succeeded",
```

成功创建容器注册表后，我们需要使用以下命令登录到该注册表：

```
bash-5.0# az acr login --name <acr-name> 
Login Succeeded
WARNING! Your password will be stored unencrypted in /root/.docker/config.json.
Configure a credential helper to remove this warning. See
https://docs.docker.com/engine/reference/commandline/login/#credentials-store
```

一旦我们成功登录到 Azure 上的容器注册表，我们需要正确标记我们的容器，以便我们可以将它们推送到 ACR。接下来将描述标记和推送图像到 ACR。

# 将我们的图像推送到 ACR

一旦我们成功登录到 ACR，我们就可以标记我们的图像，以便它们可以推送到注册表。为此，我们需要获取我们 ACR 实例的 URL。我们可以使用以下命令来实现：

```
$ az acr list --resource-group animals-rg \
 --query "[].{acrLoginServer:loginServer}" \
 --output table

AcrLoginServer
------------------------
fodanimalsacr.azurecr.io
```

现在我们使用前面的 URL 来标记我们的图像：

```
bash-5.0# docker image tag fundamentalsofdocker/ch11-db:2.0 fodanimalsacr.azurecr.io/ch11-db:2.0
bash-5.0# docker image tag fundamentalsofdocker/ch11-web:2.0 fodanimalsacr.azurecr.io/ch11-web:2.0
```

然后，我们可以将它们推送到我们的 ACR 中：

```
bash-5.0# docker image push fodanimalsacr.azurecr.io/ch11-db:2.0
bash-5.0# docker image push fodanimalsacr.azurecr.io/ch11-web:2.0
```

为了再次检查我们的图像确实在我们的 ACR 中，我们可以使用这个命令：

```
bash-5.0# az acr repository  list --name  <acr-name> --output **table 
Result
--------
ch11-db
ch11-web 
```

实际上，我们刚刚推送的两个图像已列出。有了这个，我们就可以创建我们的 Kubernetes 集群了。

# 创建 Kubernetes 集群

我们将再次使用我们的自定义 Azure CLI 来创建 Kubernetes 集群。我们必须确保集群可以访问我们刚刚创建的 ACR 实例，那里存放着我们的容器映像。因此，创建一个名为`animals-cluster`的集群，带有两个工作节点的命令如下：

```
bash-5.0# az aks create \
 --resource-group animals-rg \
 --name animals-cluster \
 --node-count 2 \
 --generate-ssh-keys \
 --attach-acr <acr-name>
```

这个命令需要一段时间，但几分钟后，我们应该会收到一些 JSON 格式的输出，其中包含了关于新创建的集群的所有细节。

要访问集群，我们需要`kubectl`。我们可以使用这个命令在我们的 Azure CLI 容器中轻松安装它：

```
bash-5.0# az aks install-cli
```

安装了`kubectl`之后，我们需要必要的凭据来使用这个工具在 Azure 中操作我们的新 Kubernetes 集群。我们可以用这个命令获取必要的凭据：

```
bash-5.0# az aks get-credentials --resource-group animals-rg --name animals-cluster 
Merged "animals-cluster" as current context in /root/.kube/config
```

在上一个命令成功执行后，我们可以列出集群中的所有节点：

```
bash-5.0# kubectl get nodes NAME                                STATUS   ROLES   AGE     VERSION
aks-nodepool1-12528297-vmss000000   Ready    agent   4m38s   v1.14.8
aks-nodepool1-12528297-vmss000001   Ready    agent   4m32s   v1.14.8
```

正如预期的那样，我们有两个工作节点正在运行。这些节点上运行的 Kubernetes 版本是`1.14.8`。

现在我们已经准备好将我们的应用程序部署到这个集群中。在下一节中，我们将学习如何做到这一点。

# 将我们的应用程序部署到 Kubernetes 集群

要部署应用程序，我们可以使用`kubectl apply`命令：

```
bash-5.0# kubectl apply -f animals.yaml 
```

上一个命令的输出应该类似于这样：

```
deployment.apps/web created
service/web created
deployment.apps/db created
service/db created
```

现在，我们想要测试这个应用程序。记住，我们为 web 组件创建了一个`LoadBalancer`类型的服务。这个服务将应用程序暴露给互联网。这个过程可能需要一些时间，因为 AKS 除了其他任务外，还需要为这个服务分配一个公共 IP 地址。我们可以用以下命令观察到这一点：

```
bash-5.0# kubectl get service web --watch
```

请注意上一个命令中的`--watch`参数。它允许我们随着时间监视命令的进展。最初，我们应该看到类似于这样的输出：

```
NAME TYPE        CLUSTER-IP  EXTERNAL-IP  PORT(S)         AGE
web LoadBalancer 10.0.124.0  <pending>    3000:32618/TCP  5s
```

公共 IP 地址标记为待定。几分钟后，应该会变成这样：

```
NAME TYPE        CLUSTER-IP  EXTERNAL-IP    PORT(S)         AGE
web LoadBalancer 10.0.124.0  51.105.229.192 3000:32618/TCP  63s
```

我们的应用程序现在准备就绪，位于 IP 地址`51.105.229.192`和端口号`3000`。请注意，负载均衡器将内部端口`32618`映射到外部端口`3000`；这在第一次对我来说并不明显。

让我们来检查一下。在新的浏览器标签中，导航至`http://51.105.229.192:3000/pet`，你应该能看到我们熟悉的应用程序：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/f45ab4b8-610f-4909-b6ce-4fce569200c8.png)

我们在 AKS 上运行的示例应用程序

有了这个，我们已成功将我们的分布式应用部署到了 Azure 中托管的 Kubernetes。我们不必担心安装或管理 Kubernetes；我们可以专注于应用本身。

现在我们已经完成了对应用程序的实验，我们不应忘记在 Azure 上删除所有资源，以避免产生不必要的成本。我们可以通过删除资源组来删除所有创建的资源，方法如下：

```
bash-5.0# az group delete --name animal-rg --yes --no-wait 
```

Azure 在容器工作负载方面有一些引人注目的提供，由于 Azure 主要提供开源编排引擎（如 Kubernetes、Docker Swarm、DC/OS 和 Rancher），因此与 AWS 相比，锁定不太明显。从技术上讲，如果我们最初在 Azure 中运行我们的容器化应用程序，然后决定迁移到另一个云提供商，我们仍然可以保持灵活性。成本应该是有限的。

值得注意的是，当您删除资源组时，AKS 集群使用的 Azure Active Directory 服务主体不会被删除。有关如何删除服务主体的详细信息，请参考在线帮助。

接下来是谷歌和他们的 Kubernetes Engine。

# 了解 GKE

谷歌是 Kubernetes 的发明者，迄今为止，也是其背后的推动力。因此，您会期望谷歌在托管 Kubernetes 方面有一个引人注目的提供。现在让我们来看一下。要继续，您需要在谷歌云上拥有现有帐户或在此创建一个测试帐户：[`console.cloud.google.com/freetrial`](https://console.cloud.google.com/freetrial)。按照以下步骤进行：

1.  在主菜单中，选择 Kubernetes Engine。第一次这样做时，Kubernetes 引擎初始化需要一些时间。

1.  接下来，创建一个新项目并将其命名为`massai-mara`；这可能需要一些时间。

1.  一旦准备就绪，我们可以通过点击弹出窗口中的 Create Cluster 来创建一个集群。

1.  在表单的左侧选择**Your first cluster**模板。

1.  将集群命名为`animals-cluster`，选择离您最近的区域或区域，将创建 Kubernetes 集群表单中的所有其他设置保持为默认值，并在表单底部点击 Create。

这将再次花费一些时间为我们提供集群。一旦集群创建完成，我们可以通过点击视图右上角的 shell 图标来打开 Cloud Shell。这应该看起来类似于以下截图：

第一个 Kubernetes 集群已准备就绪，并且 Cloud Shell 在 GKE 中打开

现在，我们可以使用以下命令将我们的`labs`GitHub 存储库克隆到这个环境中：

```
$ git clone https://github.com/PacktPublishing/Learn-Docker---  Fundamentals-of-Docker-19.x-Second-Edition.git ~/fod
$ cd ~/fod/ch18/gce
```

现在，我们应该在当前文件夹中找到一个`animals.yaml`文件，我们可以使用它来将动物应用程序部署到我们的 Kubernetes 集群中。看一下这个文件：

```
$ less animals.yaml
```

它的内容基本与我们在上一章中使用的文件相同。两个不同之处在于：

+   我们使用`LoadBalancer`类型的服务（而不是`NodePort`）来公开`web`组件。

+   我们不使用卷来配置 PostgreSQL 数据库，因为在 GKE 上正确配置 StatefulSets 比在 Minikube 中更复杂一些。这样做的后果是，如果`db` pod 崩溃，我们的动物应用程序将不会保持状态。如何在 GKE 上使用持久卷超出了本书的范围。

另外，请注意，我们不是使用 Google 容器注册表来托管容器映像，而是直接从 Docker Hub 拉取它们。在 Google Cloud 中创建这样的容器注册表非常简单，类似于我们在 AKS 部分学到的内容。

在继续之前，我们需要设置`gcloud`和`kubectl`凭据：

```
$ gcloud container clusters get-credentials animals-cluster --zone europe-west1-b 
Fetching cluster endpoint and auth data.
kubeconfig entry generated for animals-cluster.
```

完成这些操作后，现在是部署应用程序的时候了：

```
$ kubectl create -f animals.yaml 
deployment.apps/web created
service/web created
deployment.apps/db created
service/db created
```

创建对象后，我们可以观察`LoadBalancer`服务`web`，直到它被分配一个公共 IP 地址：

```
$ kubectl get svc/web --watch NAME   TYPE           CLUSTER-IP   EXTERNAL-IP     PORT(S)          AGE
web    LoadBalancer   10.0.5.222   <pending>       3000:32139/TCP   32s
web    LoadBalancer   10.0.5.222   146.148.23.70   3000:32139/TCP   39s
```

输出中的第二行显示了负载均衡器创建仍在等待的情况，第三行显示了最终状态。按*Ctrl* + *C*退出`watch`命令。显然，我们得到了分配的公共 IP 地址`146.148.23.70`，端口为`3000`。

然后，我们可以使用此 IP 地址并导航至`http://<IP 地址>:3000/pet`，我们应该会看到熟悉的动物图像。

完成应用程序的操作后，请删除 Google Cloud 控制台中的集群和项目，以避免不必要的成本。

我们在 GKE 中创建了一个托管的 Kubernetes 集群。然后，我们使用 GKE 门户提供的 Cloud Shell 首先克隆了我们的`labs`GitHub 存储库，然后使用`kubectl`工具将动物应用程序部署到 Kubernetes 集群中。

在研究托管的 Kubernetes 解决方案时，GKE 是一个引人注目的选择。它非常容易上手，而且由于 Google 是 Kubernetes 背后的主要推动力，我们可以放心地利用 Kubernetes 的全部功能。

# 总结

在本书的最后一章中，你首先快速了解了如何安装和使用 Docker 的 UCP，这是 Docker 在 AWS 上的企业产品的一部分。然后，你学会了如何在 AKS 上创建一个托管的 Kubernetes 集群，并在其上运行动物应用程序，接着是在 Google 自己的托管 Kubernetes 解决方案 GKE 上做同样的操作。

我很荣幸你选择了这本书，我想感谢你陪伴我一起探索 Docker 容器和容器编排引擎的旅程。我希望这本书对你的学习之旅有所帮助。祝你在当前和未来的项目中使用容器时一切顺利并取得成功。

# 问题

为了评估你的知识，请回答以下问题：

1.  请提供所需的任务高级描述，以在 AWS 上配置和运行 Docker UPC。

1.  列举一些选择托管的 Kubernetes 解决方案（如 Microsoft 的 AKS 或 Google 的 GKE）来在 Kubernetes 上运行应用程序的原因。

1.  列举两个使用托管的 Kubernetes 解决方案（如 AKS 或 GKE）时，考虑将容器映像托管在相应云提供商的容器注册表的原因。

# 进一步阅读

以下文章为你提供了一些与本章讨论的主题相关的更多信息：

+   在 Linux 服务器上安装单独的 Docker EE 组件 [`dockr.ly/2vH5dpN`](https://dockr.ly/2vH5dpN)

+   Azure 容器服务（AKS）at [`bit.ly/2JglX9d`](https://bit.ly/2JglX9d)

+   Google Kubernetes Engine at [`bit.ly/2I8MjJx`](https://bit.ly/2I8MjJx)


# 第十九章：评估

# 第一章

以下是本章提出的问题的一些示例答案：

1.  正确答案是**D**和**E**。

1.  Docker 容器对 IT 来说就像运输业的集装箱一样。它定义了如何打包货物的标准。在这种情况下，货物是开发人员编写的应用程序。供应商（在这种情况下是开发人员）负责将货物打包到集装箱中，并确保一切都符合预期。一旦货物被打包到集装箱中，它就可以被运输。由于它是一个标准的集装箱，承运人可以标准化他们的运输方式，如卡车、火车或船只。承运人并不真正关心集装箱里装的是什么。此外，从一种运输方式到另一种运输方式（例如，从火车到船）的装卸过程可以高度标准化。这极大地提高了运输的效率。类似于这一点的是 IT 中的运维工程师，他可以接收开发人员构建的软件容器，并以高度标准化的方式将其运输到生产系统并在那里运行，而不必担心容器里装的是什么。它会正常工作。

1.  容器改变游戏规则的一些原因如下：

+   容器是自包含的，因此如果它们在一个系统上运行，它们就可以在任何容器可以运行的地方运行。

+   容器可以在本地和云端以及混合环境中运行。这对于今天的典型企业非常重要，因为它允许顺利地从本地过渡到云端。

+   容器镜像是由最了解的人构建或打包的-开发人员。

+   容器镜像是不可变的，这对于良好的发布管理非常重要。

+   容器是基于封装（使用 Linux 命名空间和 cgroups）、秘密、内容信任和镜像漏洞扫描的安全软件供应链的推动者。

1.  任何给定的容器之所以可以在任何容器可以运行的地方运行，是因为：

+   +   容器是自包含的黑匣子。它们不仅封装了应用程序，还包括所有的依赖项，如库和框架、配置数据、证书等。

+   容器是基于广泛接受的标准，如 OCI。

1.  答案是**B**。容器对于现代应用程序以及将传统应用程序容器化都非常有用。对企业来说，后者的好处是巨大的。据报道，维护传统应用程序的成本节约了 50%或更多。这些传统应用程序发布新版本的时间可以减少高达 90%。这些数字是由真实的企业客户公开报道的。

1.  50%或更多。

1.  容器基于 Linux 命名空间（网络、进程、用户等）和 cgroups（控制组）。

# 第二章

以下是本章中提出的问题的一些示例答案：

1.  `docker-machine`可用于以下情景：

1.  在各种提供商上创建一个 VM，例如 VirtualBox、Hyper-V、AWS、MS Azure 或 Google Compute Engine，该 VM 将用作 Docker 主机。

1.  启动、停止或终止先前生成的 VM。

1.  通过此工具创建的本地或远程 Docker 主机 VM 进行 SSH。

1.  重新生成用于安全使用 Docker 主机 VM 的证书。

1.  A. 是的，使用 Docker for Windows，您可以开发和运行 Linux 容器。还可以使用此版本的 Docker for Desktop 开发和运行本机 Windows 容器，但本书中未讨论。使用 macOS 版本，您只能开发和运行 Linux 容器。

1.  脚本用于自动化流程，从而避免人为错误。构建、测试、共享和运行 Docker 容器是应该始终自动化以增加其可靠性和可重复性的任务。

1.  以下 Linux 发行版已获得 Docker 认证：RedHat Linux（RHEL）、CentOS、Oracle Linux、Ubuntu 等。

1.  以下 Windows 操作系统已获得 Docker 认证：Windows 10 专业版，Windows Server 2016 和 Windows Server 2019

# 第三章

以下是本章中提出的问题的一些示例答案：

1.  Docker 容器的可能状态如下：

+   `已创建`：已创建但尚未启动的容器

+   `重新启动`：正在重新启动的容器

+   `运行`：当前正在运行的容器

+   `暂停`：进程已暂停的容器

+   `退出`：运行并完成的容器

+   `死亡`：Docker 引擎尝试但未能停止的容器

1.  我们可以使用`docker container ls`（或旧的更短版本`docker ps`）来列出当前在 Docker 主机上运行的所有容器。请注意，这不会列出已停止的容器，对于这些容器，您需要额外的参数`--all`（或`-a`）。

1.  要列出所有容器的 ID，无论是运行还是停止，我们可以使用`docker container ls -a -q`，其中`-q`表示仅输出 ID。

# 第四章

以下是本章中提出的问题的一些示例答案：

1.  `Dockerfile`可能是这样的：

```
FROM ubuntu:19.04
RUN apt-get update && \
    apt-get install -y iputils-ping
CMD ping 127.0.0.1
```

请注意，在 Ubuntu 中，`ping`工具是`iputils-ping`包的一部分。构建名为`pinger`的镜像，例如，使用`docker image build -t my-pinger`。

2. `Dockerfile`可能是这样的：

```
FROM alpine:latest
RUN apk update && \
    apk add curl
```

使用`docker image build -t my-alpine:1.0`构建镜像。

3. 用于 Go 应用程序的`Dockerfile`可能是这样的：

```
FROM golang:alpine
WORKDIR /app
ADD . /app
RUN cd /app && go build -o goapp
ENTRYPOINT ./goapp
```

您可以在`~/fod/ch04/answer03`文件夹中找到完整的解决方案。

4. Docker 镜像具有以下特征：

1. 它是不可变的。

2. 它由一到多个层组成。

3. 它包含打包应用程序运行所需的文件和文件夹。

5. **C.** 首先，您需要登录 Docker Hub；然后，使用用户名正确标记您的镜像；最后，推送镜像。

# 第五章

以下是本章中提出的问题的一些示例答案：

玩弄卷的最简单方法是使用 Docker Toolbox，因为当直接使用 Docker for Desktop 时，卷存储在 Docker for Desktop 透明使用的（有点隐藏的）Linux VM 中。

因此，我们建议以下操作：

```
$ docker-machine create --driver virtualbox volume-test
$ docker-machine ssh volume-test
```

现在您在名为`volume-test`的 Linux VM 中，可以进行以下练习：

1.  创建一个命名卷，运行以下命令：

```
$ docker volume create my-products
```

1.  执行以下命令：

```
$ docker container run -it --rm \
 -v my-products:/data:ro \
 alpine /bin/sh
```

1.  要获取卷在主机上的路径，请使用此命令：

```
$ docker volume inspect my-products | grep Mountpoint
```

（如果您使用`docker-machine`和 VirtualBox）应该导致这样：

```
"Mountpoint": "/mnt/sda1/var/lib/docker/volumes/myproducts/_data"
```

现在执行以下命令：

```
$ sudo su
$ cd /mnt/sda1/var/lib/docker/volumes/my-products/_data
$ echo "Hello world" > sample.txt
$ exit
```

1.  执行以下命令：

```
$ docker run -it --rm -v my-products:/data:ro alpine /bin/sh
/ # cd /data
/data # cat sample.txt
```

在另一个终端中，执行此命令：

```
$ docker run -it --rm -v my-products:/app-data alpine /bin/sh
/ # cd /app-data
/app-data # echo "Hello other container" > hello.txt
/app-data # exit
```

1.  执行这样的命令：

```
$ docker container run -it --rm \
 -v $HOME/my-project:/app/data \
 alpine /bin/sh
```

1.  退出两个容器，然后回到主机上，执行此命令：

```
$ docker volume prune
```

1.  答案是 B。每个容器都是一个沙盒，因此具有自己的环境。

1.  收集所有环境变量及其相应的值到一个配置文件中，然后在`docker run`命令中使用`--env-file`命令行参数将其提供给容器，就像这样：

```
$ docker container run --rm -it \
 --env-file ./development.config \
 alpine sh -c "export"
```

# 第六章

以下是本章中提出的问题的一些示例答案：

1.  可能的答案：a) 在容器中挂载源代码；b) 使用工具，在检测到代码更改时自动重新启动容器内运行的应用程序；c) 为远程调试配置容器。

1.  您可以在容器中将包含源代码的文件夹挂载到主机上。

1.  如果你无法轻松地通过单元测试或集成测试覆盖某些场景，如果观察到的应用程序行为无法在主机上重现。另一种情况是由于缺乏必要的语言或框架，无法直接在主机上运行应用程序的情况。

1.  一旦应用程序在生产环境中运行，作为开发人员，我们无法轻易访问它。如果应用程序出现意外行为甚至崩溃，日志通常是我们唯一的信息来源，帮助我们重现情况并找出错误的根本原因。

# 第七章

以下是本章提出的问题的一些示例答案：

1.  优缺点：

+   优点：我们不需要在主机上安装任务所需的特定 shell、工具或语言。

+   优点：我们可以在任何 Docker 主机上运行，从树莓派到大型计算机；唯一的要求是主机能够运行容器。

+   优点：成功运行后，当容器被移除时，工具会从主机上完全清除痕迹。

+   缺点：我们需要在主机上安装 Docker。

+   缺点：用户需要对 Docker 容器有基本的了解。

+   缺点：使用该工具比直接在本机使用要间接一些。

1.  在容器中运行测试具有以下优点：

+   它们在开发者机器上和测试或 CI 系统上同样运行良好。

+   更容易以相同的初始条件开始每次测试运行。

+   所有使用代码的开发人员使用相同的设置，例如库和框架的版本。

1.  在这里，我们期望看到一个图表，显示开发人员编写代码并将其检入，例如 GitHub。然后我们希望在图中看到一个自动化服务器，比如 Jenkins 或 TeamCity，它要么定期轮询 GitHub 进行更改，要么 GitHub 触发自动化服务器（通过 HTTP 回调）创建新的构建。图表还应显示自动化服务器然后运行所有测试以针对构建的工件，如果所有测试都成功，则部署应用程序或服务到集成系统，在那里再次进行测试，例如进行一些 smoke 测试。再次，如果这些测试成功，自动化服务器应该要么要求人类批准部署到生产环境（这相当于持续交付），要么自动部署到生产环境（持续部署）。

# 第八章

以下是本章提出的问题的一些示例答案：

1.  您可能正在使用资源或功能有限的工作站工作，或者您的工作站可能被公司锁定，以便您不被允许安装任何未经官方批准的软件。有时，您可能需要使用公司尚未批准的语言或框架进行概念验证或实验（但如果概念验证成功，可能将来会被批准）。

1.  将 Docker 套接字绑定到容器是当容器化应用程序需要自动执行一些与容器相关的任务时的推荐方法。这可以是一个应用程序，比如您正在使用它来构建、测试和部署 Docker 镜像的自动化服务器，比如 Jenkins。

1.  大多数商业应用程序不需要根级授权来完成其工作。从安全的角度来看，强烈建议以尽可能少的访问权限来运行这些应用程序。任何不必要的提升权限都可能被黑客利用进行恶意攻击。通过以非根用户身份运行应用程序，可以使潜在黑客更难以 compromise 您的系统。

1.  卷包含数据，数据的寿命往往需要远远超出容器或应用程序的生命周期。数据通常是至关重要的，并且需要安全地存储数天、数月，甚至数年。当您删除一个卷时，您将不可逆地删除与其关联的数据。因此，在删除卷时，请确保知道自己在做什么。

# 第九章

以下是本章提出的问题的一些示例答案：

1.  在分布式应用架构中，软件和基础设施的每个部分在生产环境中都需要冗余，因为应用的持续运行时间至关重要。高度分布式的应用程序由许多部分组成，其中一个部分失败或行为不当的可能性随着部分数量的增加而增加。可以保证，足够长的时间后，每个部分最终都会失败。为了避免应用中断，我们需要在每个部分都有冗余，无论是服务器、网络交换机还是在容器中运行的集群节点上的服务。

1.  在高度分布式、可扩展和容错的系统中，应用程序的各个服务可能会因为扩展需求或组件故障而移动。因此，我们不能将不同的服务硬编码在一起。需要访问服务 B 的服务 A 不应该知道诸如服务 B 的 IP 地址之类的细节，而应该依赖于提供此信息的外部提供者。DNS 就是这样一个位置信息的提供者。服务 A 只需告诉 DNS 它想要与服务 B 通信，DNS 服务将找出详细信息。

1.  断路器是避免级联故障的一种手段，如果分布式应用程序中的一个组件失败或行为不当。类似于电气布线中的断路器，软件驱动的断路器会切断客户端与失败服务之间的通信。如果调用了失败的服务，断路器将直接向客户端组件报告错误。这为系统提供了从故障中恢复或修复的机会。

1.  单体应用程序比多服务应用程序更容易管理，因为它由单个部署包组成。另一方面，单体应用程序很难扩展以满足增加的需求。在分布式应用程序中，每个服务都可以单独扩展，并且每个服务都可以在优化的基础设施上运行，而单体应用程序需要在适用于其实现的所有或大多数功能的基础设施上运行。维护和更新单体应用程序比多服务应用程序要困难得多，因为每个服务都可以独立更新和部署。单体通常是一堆复杂且紧密耦合的代码。小的修改可能会产生意想不到的副作用。另一方面，（微）服务是自包含的、简单的组件，其行为类似于黑匣子。依赖服务对服务的内部工作一无所知，因此不依赖于它。

1.  蓝绿部署是一种软件部署形式，允许无零停机部署应用程序或应用程序服务的新版本。例如，如果服务 A 需要使用新版本进行更新，那么我们称当前运行的版本为蓝色。服务的新版本部署到生产环境，但尚未与应用程序的其余部分连接。这个新版本被称为绿色。一旦部署成功并且冒烟测试表明它已经准备就绪，将负责将流量引导到蓝色的路由器重新配置为切换到绿色。观察绿色的行为一段时间，如果一切正常，蓝色将被废弃。另一方面，如果绿色造成困难，路由器可以简单地切换回蓝色，然后修复绿色并稍后重新部署。

# 第十章

以下是本章中提出的一些问题的样本答案：

1.  三个核心元素是**沙盒**、**端点**和**网络**。

1.  执行此命令：

```
$ docker network create --driver bridge frontend
```

1.  运行此命令：

```

$ docker container run -d --name n1 \
 --network frontend -p 8080:80 nginx:alpine
$ docker container run -d --name n2 \
 --network frontend -p 8081:80 nginx:alpine
```

测试两个 NGINX 实例是否正常运行：

```
$ curl -4 localhost:8080
$ curl -4 localhost:8081
```

在这两种情况下，您应该看到 NGINX 的欢迎页面。

1.  要获取所有已附加容器的 IP，请运行此命令：

```
$ docker network inspect frontend | grep IPv4Address
```

您应该看到类似以下内容：

```
"IPv4Address": "172.18.0.2/16",
"IPv4Address": "172.18.0.3/16",
```

要获取网络使用的子网，请使用以下命令（例如）：

```
$ docker network inspect frontend | grep subnet
```

您应该收到类似以下内容的信息（从上一个示例中获得）：

```
"Subnet": "172.18.0.0/16",
```

1.  “主机”网络允许我们在主机的网络命名空间中运行容器。

1.  仅在调试目的或构建系统级工具时使用此网络。永远不要在运行生产环境的应用程序容器中使用`host`网络！

1.  `none`网络基本上表示容器未连接到任何网络。它应该用于不需要与其他容器通信并且不需要从外部访问的容器。

1.  例如，`none`网络可以用于在容器中运行的批处理过程，该过程只需要访问本地资源，例如可以通过主机挂载卷访问的文件。

1.  Traefik 可用于提供第 7 层或应用程序级别的路由。如果要从单体中分离功能并具有明确定义的 API，则这将非常有用。在这种情况下，您需要重新路由某些 HTTP 调用到新的容器/服务。这只是可能的使用场景之一，但也是最重要的一个。另一个可能是将 Traefik 用作负载均衡器。

# 第十一章

以下是本章提出的问题的一些示例答案：

1.  以下代码可用于以分离或守护程序模式运行应用程序：

```
$ docker-compose up -d
```

1.  执行以下命令以显示运行服务的详细信息：

```
$ docker-compose ps
```

这应该导致以下输出：

```
Name               Command               State  Ports
-------------------------------------------------------------------
mycontent_nginx_1  nginx -g daemon off;  Up     0.0.0.0:3000->80/tcp
```

1.  以下命令可用于扩展 Web 服务：

```
$ docker-compose up --scale web=3
```

# 第十二章

以下是本章提出的问题的一些示例答案：

1.  作为高度分布式的关键任务，高可用性应用程序实现为相互连接的应用程序服务系统，这些系统过于复杂，无法手动监视、操作和管理。容器编排器在这方面有所帮助。它们自动化了大部分典型任务，例如协调所需状态，或收集和聚合系统的关键指标。人类无法快速反应，以使这样的应用程序具有弹性或自我修复能力。软件支持是必要的，这就是所提到的容器编排器的形式。

1.  容器编排器使我们摆脱了以下繁琐和繁重的任务：

+   扩展服务的规模

+   负载均衡请求

+   将请求路由到所需的目标

+   监视服务实例的健康状况

+   保护分布式应用程序

1.  在这个领域的赢家是 Kubernetes，它是由 CNCF 开源并拥有。它最初是由 Google 开发的。我们还有 Docker Swarm，它是专有的，并由 Docker 开发。AWS 提供了一个名为 ECS 的容器服务，它也是专有的，并且与 AWS 生态系统紧密集成。最后，微软提供了 AKS，它与 AWS ECS 具有相同的优缺点。

# 第十三章

以下是本章中提出的一些问题的样本答案：

1.  正确答案如下：

```
$ docker swarm init [--advertise-addr <IP address>]
```

`--advertise-addr`是可选的，只有在主机有多个 IP 地址时才需要。

1.  在要移除的工作节点上执行以下命令：

```
 $ docker swarm leave
```

在其中一个主节点上执行命令`$ docker node rm -f<node ID>`，其中`<node ID>`是要移除的工作节点的 ID。

1.  正确答案如下：

```
$ docker network create \
 --driver overlay \
 --attachable \
 front-tier
```

1.  正确答案如下：

```
$ docker service create --name web \
 --network front-tier \
 --replicas 5 \
 -p 3000:80 \
 nginx:alpine
```

1.  正确答案如下：

```
$ docker service update --replicas 3 web
```

# 第十四章

以下是本章中提出的一些问题的样本答案：

1.  零停机部署意味着在分布式应用程序中，服务的新版本可以更新到新版本，而无需停止应用程序的运行。通常情况下，使用 Docker SwarmKit 或 Kubernetes（如我们将看到的那样），这是以滚动方式完成的。一个服务由多个实例组成，这些实例会分批更新，以确保大多数实例始终处于运行状态。

1.  默认情况下，Docker SwarmKit 使用滚动更新策略来实现零停机部署。

1.  容器是部署的自包含单元。如果部署的服务的新版本不如预期地工作，我们（或系统）只需要回滚到以前的版本。服务的以前版本也是以自包含容器的形式部署的。在概念上，向前（更新）或向后（回滚）滚动没有区别。一个容器的版本被另一个版本替换。主机本身不会受到这些变化的任何影响。

1.  Docker secrets 在静止状态下是加密的。它们只会传输给使用这些秘密的服务和容器。秘密之间的通信是加密的，因为 swarm 节点之间的通信使用相互 TLS。秘密从未在工作节点上物理存储。

1.  实现此目的的命令如下：

```
$ docker service update --image acme/inventory:2.1 \
 --update-parallelism 2 \
 --update-delay 60s \
 inventory
```

6.首先，我们需要从服务中删除旧的秘密，然后将新版本添加到其中（直接更新秘密是不可能的）：

```
$ docker service update \
 --secret-rm MYSQL_PASSWORD \
 inventory
$ docker service update \
 --secret-add source=MYSQL_PASSWORD_V2, target=MYSQL_PASSWORD \
 inventory
```

# 第十五章

以下是本章中提出的问题的一些示例答案：

1.  Kubernetes 主节点负责管理集群。所有创建对象、重新调度 pod、管理 ReplicaSets 等请求都在主节点上进行。主节点不会在生产或类似生产的集群中运行应用程序工作负载。

1.  在每个工作节点上，我们都有 kubelet、代理和容器运行时。

1.  答案是 A。**是**。你不能在 Kubernetes 集群上运行独立的容器。Pods 是这样一个集群中部署的原子单位。

1.  在一个 pod 内运行的所有容器共享相同的 Linux 内核网络命名空间。因此，所有在这些容器内运行的进程可以通过`localhost`相互通信，类似于直接在主机上运行的进程或应用程序可以通过`localhost`相互通信的方式。

1.  `pause`容器的唯一作用是为在其中运行的容器保留 pod 的命名空间。

1.  这是一个坏主意，因为一个 pod 的所有容器都是共同定位的，这意味着它们运行在同一个集群节点上。此外，如果多个容器在同一个 pod 中运行，它们只能一起扩展或缩减。然而，应用程序的不同组件（即`web`、`inventory`和`db`）通常在可伸缩性或资源消耗方面有非常不同的要求。`web`组件可能需要根据流量进行扩展或缩减，而`db`组件则对存储有特殊要求，而其他组件则没有。如果我们将每个组件都运行在自己的 pod 中，我们在这方面会更加灵活。

1.  我们需要一种机制来在集群中运行多个 pod 实例，并确保实际运行的 pod 数量始终与期望的数量相对应，即使个别 pod 由于网络分区或集群节点故障而崩溃或消失。 ReplicaSet 是为任何应用程序服务提供可伸缩性和自愈能力的机制。

1.  每当我们想要在 Kubernetes 集群中更新应用程序服务而不会导致服务中断时，我们都需要部署对象。部署对象为 ReplicaSets 添加了滚动更新和回滚功能。

1.  Kubernetes 服务对象用于使应用程序服务参与服务发现。它们为一组 pod 提供了一个稳定的端点（通常由 ReplicaSet 或部署管理）。Kube 服务是定义了一组逻辑 pod 和访问它们的策略的抽象。有四种类型的 Kube 服务：

+   **ClusterIP**：在集群内部的 IP 地址上公开服务；这是一个虚拟 IP（VIP）。

+   **NodePort**：在每个集群节点上发布 30,000-32,767 范围内的端口。

+   **LoadBalancer**：这种类型使用云提供商的负载均衡器（如 AWS 上的 ELB）来外部公开应用程序服务。

+   **ExternalName**：当您需要为集群的外部服务（如数据库）定义代理时使用。

# 第十六章

以下是本章中提出的问题的一些示例答案：

1.  假设我们在两个应用程序服务的注册表中有一个 Docker 镜像，web API 和 Mongo DB，然后我们需要做以下操作：

+   使用 StatefulSet 为 Mongo DB 定义一个部署；让我们称之为`db-deployment`。StatefulSet 应该有一个副本（复制 Mongo DB 需要更多的工作，超出了本书的范围）。

+   为`db-deployment`定义一个名为`db`的 Kubernetes 服务，类型为`ClusterIP`。

+   为 web API 定义一个部署；让我们称之为`web-deployment`。将这个服务扩展到三个实例。

+   为`web-deployment`定义一个名为`api`的 Kubernetes 服务，类型为`NodePort`。

+   如果我们使用 secrets，那么使用 kubectl 直接在集群中定义这些 secrets。

+   使用 kubectl 部署应用程序。

1.  为了实现应用程序的第 7 层路由，我们理想情况下使用 IngressController。IngressController 是一个反向代理，比如 Nginx，它有一个 sidecar 监听 Kubernetes Server API 的相关变化，并更新反向代理的配置，如果检测到变化，则重新启动。然后，我们需要在集群中定义 Ingress 资源，定义路由，例如基于上下文的路由，比如`https://example.com/pets`到`<服务名称>/<端口>`，或者一对，比如`api/32001`。一旦 Kubernetes 创建或更改了这个 Ingress 对象，IngressController 的 sidecar 就会接收并更新代理的路由配置。

1.  假设这是一个集群内部的库存服务，那么我们需要做以下操作：

+   在部署版本 1.0 时，我们定义了一个名为`inventory-deployment-blue`的部署，并使用`color: blue`的标签标记 pod。

+   我们部署了 Kubernetes 服务的`ClusterIP`类型，称为 inventory，前面的部署中包含选择器`color: blue`。

+   当我们准备部署支付服务的新版本时，我们为服务的 2.0 版本定义一个部署，并称其为`inventory-deployment-green`。我们向 pod 添加了`color: green`的标签。

+   现在我们可以对“green”服务进行冒烟测试，当一切正常时，我们可以更新 inventory 服务，以便选择器包含`color: green`。

1.  一些机密的信息形式应通过 Kubernetes secrets 提供给服务，包括密码、证书、API 密钥 ID、API 密钥密钥和令牌。

1.  秘密值的来源可以是文件或 base64 编码的值。

# 第十七章

以下是本章中提出的问题的一些示例答案：

1.  出于性能和安全原因，我们不能在生产系统上进行任何实时调试。这包括交互式或远程调试。然而，应用服务可能会因代码缺陷或其他基础设施相关问题（如网络故障或不可用的外部服务）而表现出意外行为。为了快速找出服务的异常行为或失败的原因，我们需要尽可能多的日志信息。这些信息应该给我们一个线索，并引导我们找到错误的根本原因。当我们对服务进行仪器化时，我们确实做到了这一点——以日志条目和发布的指标的形式产生尽可能多的信息。

1.  Prometheus 是一个用于收集其他基础设施服务和最重要的应用服务提供的功能或非功能指标的服务。由于 Prometheus 本身定期从所有配置的服务中拉取这些指标，因此服务本身不必担心发送数据。Prometheus 还定义了生产者呈现指标的格式。

1.  要对基于 Node.js 的应用服务进行仪器化，我们需要执行以下四个步骤：

1.  向项目添加 Prometheus 适配器。Prometheus 的维护者推荐使用名为`siimon/prom-client`的库。

1.  在应用程序启动期间配置 Prometheus 客户端。这包括定义一个指标注册表。

1.  公开一个 HTTP GET 端点/度量标准，返回度量标准注册表中定义的度量集合。

1.  最后，我们定义`counter`、`gauge`或`histogram`类型的自定义度量标准，并在我们的代码中使用它们；例如，每次调用特定端点时，我们增加`counter`类型的度量标准。

1.  通常在生产环境中，Kubernetes 集群节点只包含最小的操作系统，以尽可能限制其攻击面，并且不浪费宝贵的资源。因此，我们不能假设通常用于排除应用程序或进程的工具在相应的主机上可用。排除故障的一种强大且推荐的方法是作为临时 Pod 的一部分运行特殊工具或排除故障容器。然后，该容器可以用作我们可以调查受困扰的服务的网络和其他问题的堡垒。许多 Docker 现场工程师在客户现场成功使用的容器是`netshoot`。

# 第十八章

以下是本章中提出的问题的一些示例答案：

1.  要在 AWS 中安装 UCP，我们执行以下操作：

+   创建具有子网和 SG 的 VPC。

+   然后，提供一组 Linux VM 的集群，可能作为 ASG 的一部分。支持许多 Linux 发行版，如 CentOS、RHEL 和 Ubuntu。

+   然后，在每个 VM 上安装 Docker。

+   最后，选择一个 VM 来安装 UCP，使用`docker/ucp`镜像。

+   安装 UCP 后，将其他 VM 加入集群，作为工作节点或管理节点。

1.  以下是考虑托管 Kubernetes 的一些原因：

+   您不希望或没有资源来安装和管理 Kubernetes 集群。

+   您希望专注于为您的业务带来价值的内容，这在大多数情况下是应该在 Kubernetes 上运行的应用程序，而不是 Kubernetes 本身。

+   您更喜欢按需付费的成本模型。

+   您的 Kubernetes 集群节点会自动打补丁和更新。

+   升级 Kubernetes 版本而无需停机时间非常简单和直接。

1.  将容器镜像托管在云提供商的容器注册表（例如 Microsoft Azure 上的 ACR）的两个主要原因是：

+   镜像地理位置靠近您的 Kubernetes 集群，因此延迟和传输网络成本最小。

+   生产或类似生产的集群理想情况下应该与互联网隔离，因此 Kubernetes 集群节点无法直接访问 Docker Hub。
