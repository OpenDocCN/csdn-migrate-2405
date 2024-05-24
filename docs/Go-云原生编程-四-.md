# Go 云原生编程（四）

> 原文：[`zh.annas-archive.org/md5/E4B340F53EAAF54B7D4EF0AD6F8B1333`](https://zh.annas-archive.org/md5/E4B340F53EAAF54B7D4EF0AD6F8B1333)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十章：监控您的应用程序

在之前的章节中，您学习了如何使用 Go 编程语言构建微服务应用程序，以及如何（持续）将其部署到各种环境中。

然而，我们的工作还没有完成。当您在生产环境中运行应用程序时，您需要确保它保持运行并且表现出您作为开发人员预期的行为。这就是监控的作用。

在本章中，我们将向您介绍**Prometheus**，这是一款开源监控软件，它在监控基于云的分布式应用程序方面迅速赢得了人气。它通常与**Grafana**一起使用，后者是用于可视化 Prometheus 收集的指标数据的前端。这两个应用程序都是根据 Apache 许可证授权的。您将学习如何设置 Prometheus 和 Grafana，以及如何将它们集成到您自己的应用程序中。

在本章中，我们将涵盖以下主题：

+   安装和使用 Prometheus

+   安装 Grafana

+   从您自己的应用程序向 Prometheus 导出指标

# 设置 Prometheus 和 Grafana

在我们自己的应用程序中使用 Prometheus 和 Grafana 之前，让我们先看一下 Prometheus 的工作原理。

# Prometheus 的基础知识

与其他监控解决方案不同，Prometheus 通过定期从客户端拉取数据（在 Prometheus 行话中称为**指标**）来工作。这个过程称为**抓取**。被 Prometheus 监控的客户端必须实现一个 HTTP 端点，可以被 Prometheus 定期抓取（默认为 1 分钟）。然后，这些指标端点可以以预定义的格式返回特定于应用程序的指标。

例如，一个应用程序可以在`/metrics`上提供一个 HTTP 端点，响应`GET`请求并返回以下内容：

```go
memory_consumption_bytes 6168432 
http_requests_count{path="/events",method="get"} 241 
http_requests_count{path="/events",method="post"} 5 
http_requests_count{path="/events/:id",method="get"} 125 
```

此文档公开了两个指标——`memory_consumption_bytes`和`http_requests_count`。每个指标都与一个值相关联（例如，当前内存消耗为 6,168,432 字节）。由于 Prometheus 以固定间隔从您的应用程序抓取这些指标，它可以使用这些瞬时值来构建此指标的时间序列。

Prometheus 指标也可以有标签。在前面的示例中，您可能注意到`http_request_count`指标实际上具有不同组合的`path`和`method`标签的三个不同值。稍后，您将能够使用这些标签使用自定义查询语言**PromQL**从 Prometheus 查询数据。

应用程序导出到 Prometheus 的指标可能会变得非常复杂。例如，使用标签和不同的指标名称，客户端可以导出一个直方图，其中数据聚合在不同的桶中：

```go
http_request_duration_seconds_bucket{le="0.1"} 6835 
http_request_duration_seconds_bucket{le="0.5"} 79447 
http_request_duration_seconds_bucket{le="1"} 80700 
http_request_duration_seconds_bucket{le="+Inf"} 80953 
http_request_duration_seconds_sum 46135 
http_request_duration_seconds_count 80953 
```

前面的指标描述了您的应用程序的 HTTP 响应时间的直方图。在这种情况下，处理了 6,835 个响应时间小于 0.1 秒的请求；79,447 个响应时间小于 0.5 秒的请求（包括前面的 6,835 个请求）；等等。最后两个指标导出了处理的 HTTP 请求总数和处理这些请求所需的时间总和。这两个值可以一起用于计算平均请求持续时间。

不用担心，您不需要自己构建这些复杂的直方图指标；这就是 Prometheus 客户端库的作用。然而，首先，让我们通过实际设置一个 Prometheus 实例来开始。

# 创建初始的 Prometheus 配置文件

在我们自己的应用程序中使用 Prometheus 和 Grafana 之前，我们需要先设置它。幸运的是，您可以在 Docker Hub 上找到这两个应用程序的 Docker 镜像。在启动我们自己的 Prometheus 容器之前，我们只需要创建一个配置文件，然后将其注入到容器中。

首先，在本地机器上创建一个新目录，并在其中放置一个新的`prometheus.yml`文件：

```go
global: 
  scrape_interval: 15s 

scrape_configs: 
  - job_name: prometheus 
    static_configs: 
      - targets: ["localhost:9090"] 
```

此配置定义了全局的抓取间隔为 15 秒（默认值为 1 分钟），并且已经配置了第一个抓取目标，即 Prometheus 本身（是的，您读对了；Prometheus 导出 Prometheus 指标，然后您可以使用 Prometheus 监控）。

稍后，我们将向`scape_configs`属性添加更多配置项。目前，这就足够了。

# 在 Docker 上运行 Prometheus

创建配置文件后，我们可以使用卷挂载将此配置文件注入我们即将启动的 Docker 容器中。

在此示例中，我们假设您在本地机器上的 Docker 容器中运行了 MyEvents 应用程序，并且这些容器连接到名为`myevents`的容器网络（无论您是手动创建容器还是通过 Docker Compose 创建都无关紧要）。

因此，启动这两个应用程序非常容易。我们将首先为监控组件定义一个单独的容器网络：

```go
$ docker network create monitoring 
```

接下来，创建一个新的卷，Prometheus 服务器可以在其中存储其数据：

```go
$ docker volume create prometheus-data 
```

现在，您可以使用新创建的网络和卷来创建一个 Prometheus 容器：

```go
$ docker container run \ 
    --name prometheus \ 
    --network monitoring \ 
    --network myevents \ 
    -v $PWD/prometheus.yml:/etc/prometheus/prometheus.yml 
    -v prometheus-data:/prometheus 
    -p 9090:9090 
    prom/prometheus:v1.6.1 
```

请注意，在上面的示例中，我们将`prometheus`容器连接到`myevents`和`monitoring`网络。这是因为稍后，Prometheus 服务器将需要通过网络访问 MyEvents 服务，以从中抓取指标。

启动 Prometheus 容器后，您可以通过在浏览器中导航到[`localhost:9090`](http://localhost:9090/)来打开 Prometheus Web UI：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/3ad455d1-5604-4c92-9d13-6137d85c1a60.png)

Prometheus Web UI

在我们的配置文件中，我们已经配置了第一个抓取目标——Prometheus 服务器本身。您可以通过选择“状态”菜单项，然后选择“目标”项来查看所有配置的抓取目标的概述：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/46a650c2-6df3-4475-bb76-3d038e7dd0fb.png)

在 Prometheus Web UI 中的目标项

如前面的截图所示，Prometheus 报告了抓取目标的当前状态（在本例中为 UP）以及上次抓取的时间。

您现在可以使用“图形”菜单项来检查 Prometheus 已经收集的有关自身的指标。在那里，将`go_memstats_alloc_bytes`输入到表达式输入字段中，然后单击“执行”。之后，切换到“图形”选项卡。Prometheus 现在将打印其过去 1 小时的内存使用情况。您可以使用图表上方的控件更改观察期。默认情况下，Prometheus 将保留其时间序列数据 2 周：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/c64c97ef-6549-4af0-807b-eea5ad923242.png)

Prometheus Web UI 图形

Prometheus 还支持更复杂的表达式。例如，考虑`process_cpu_seconds_total`指标。当将其显示为图形时，您会注意到它是单调递增的。这是因为该特定指标描述了程序在其整个生命周期内使用的所有 CPU 秒数的总和（根据定义，这必须始终是递增的）。然而，出于监控目的，了解进程的当前 CPU 使用情况通常更有趣。为此，PromQL 提供了`rate()`方法，用于计算时间序列的每秒平均增加量。尝试使用以下表达式：

```go
rate(process_cpu_seconds_total[1m]) 
```

在图形视图中，您现在将找到每秒的 1 分钟平均 CPU 使用率（这可能是一个比所有已使用的 CPU 秒数总和更易理解的指标）：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/ae1cd1d5-19fd-4c3c-bf9c-5e27cd34d623.png)

Prometheus Web UI 非常适合快速分析和临时查询。但是，Prometheus 不支持保存查询以供以后使用，也不支持在同一页上呈现多个图形。这就是 Grafana 发挥作用的地方。

# 在 Docker 上运行 Grafana

运行 Grafana 与运行 Prometheus 一样简单。首先设置一个用于持久存储的卷：

```go
$ docker volume create grafana-data 
```

然后，启动实际容器并将其附加到`monitoring`网络（而不是`myevents`网络；Grafana 需要与 Prometheus 服务器通信，但不需要直接与您的后端服务通信）：

```go
$ docker container run \ 
    -v grafana-data \ 
    -p 3000:3000 \ 
    --name grafana \ 
    --network monitoring \ 
    grafana/grafana:4.2.0 
```

之后，您将能够在浏览器中访问`http://localhost:3000`上的 Grafana。默认凭据是用户名`admin`和密码`admin`。

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/2e0ae6ea-2552-419b-99ea-0f89751f2a43.png)

Gafana 主页

在您第一次访问时，您将被提示为 Grafana 实例配置数据源。单击“添加数据源”按钮，并在下一页配置访问您的 Prometheus 服务器。在那里，选择 Prometheus 作为*类型*，输入`http://prometheus:9090`作为 URL，并选择代理*作为*访问模式。

添加数据源后，继续创建仪表板（选择左上角的按钮，选择仪表板，然后选择新建）。然后，通过单击相应按钮向仪表板添加新图形。添加图形面板后，单击面板标题并选择编辑以编辑面板：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/92a7aafc-85bf-4350-9aeb-47c78c673dec.png)

面板

然后，在指标选项卡中，将之前的 CPU 使用率查询输入到查询输入字段中。为了进一步自定义面板，您可能希望输入`{{ job }}`作为图例，以使图例更易理解，并将 Y 轴格式（在轴选项卡，左 Y 部分和单位字段）更改为百分比（0.0-1.0）：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/0b35c2ab-936f-4eb0-b813-6503c27ca6d3.png)

Gafana 新仪表板

关闭编辑面板，并通过单击保存按钮或按*Ctrl* + *S*保存您的仪表板。您的仪表板现在已保存。您可以在以后的时间点查看它，其中包括更新的指标，或与其他用户共享此仪表板。

您还可以通过向仪表板添加更多面板来进行实验，以可视化其他指标（默认情况下，Prometheus 已经导出了大量关于自身的指标，您可以进行实验）。有关 Prometheus 查询语言的详细参考，请参阅以下网址的官方文档：[`prometheus.io/docs/querying/basics/`](https://prometheus.io/docs/querying/basics/)。

现在我们已经有了一个正常运行的 Prometheus 和 Grafana 设置，我们可以看看如何将您自己的应用程序的指标导入到 Prometheus 中。

# 导出指标

如已经显示的那样，从您自己的应用程序导出指标在原则上是很容易的。您的应用程序只需要提供一个返回任意指标的 HTTP 端点，然后可以将这些指标保存在 Prometheus 中。实际上，这变得更加困难，特别是当您关心 Go 运行时的状态时（例如，CPU 和内存使用情况，Goroutine 计数等）。因此，通常最好使用 Go 的 Prometheus 客户端库，该库负责收集所有可能的 Go 运行时指标。

事实上，Prometheus 本身是用 Go 编写的，并且还使用自己的客户端库来导出有关 Go 运行时的指标（例如，您之前使用过的`go_memstats_alloc_bytes`或`process_cpu_seconds_total`指标）。

# 在您的 Go 应用程序中使用 Prometheus 客户端

您可以使用`go get`获取 Prometheus 客户端库，如下所示：

```go
$ go get -u github.com/prometheus/client_golang 
```

如果您的应用程序使用依赖管理工具（例如我们在前一章中介绍的 Glide），您可能还希望在您的`glide.yaml`文件中声明此新依赖项，并将稳定版本添加到应用程序的`vendor/`目录中。要一次完成所有这些操作，只需在应用程序目录中运行`glide get`而不是`go get`：

```go
$ glide get github.com/prometheus/client_golang 
$ glide update 
```

出于安全原因，我们将在与事件服务和预订服务的 REST API 不同的 TCP 端口上公开我们的指标 API。否则，意外地将指标 API 暴露给外部世界将太容易了。

让我们从事件服务开始。设置指标 API 不需要太多的代码，所以我们将直接在`main.go`文件中进行。在调用`rest.ServeAPI`方法之前，将以下代码添加到主函数中：

```go
import "net/http" 
import "github.com/prometheus/client_golang/prometheus/promhttp" 
// ... 

func main() { 
  // ... 

  go func() { 
    fmt.Println("Serving metrics API") 

    h := http.NewServeMux() 
    h.Handle("/metrics", promhttp.Handler()) 

    http.ListenAndServe(":9100", h) 
  }() 

  fmt.Println("Serving API") 
  // ... 
} 
```

现在，编译您的应用程序并运行它。尝试在浏览器中打开地址`http://localhost:9100/metrics`，您应该会看到新端点返回大量的指标：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/ecb16ed5-5998-4cd1-a67a-0f501e2c0952.png)

在 localhost:9100/metrics 显示的页面

现在，对预订服务进行相同的调整。还要记得在两个服务的 Dockerfile 中添加`EXPOSE 9100`语句，并使用更新后的镜像和`-p 9100:9100`标志（或`-p 9101:9100`以防止端口冲突）重新创建任何容器。

# 配置 Prometheus 抓取目标

现在我们有两个正在运行并公开 Prometheus 指标的服务，我们可以配置 Prometheus 来抓取这些服务。为此，我们可以修改之前创建的`prometheus.yml`文件。将以下部分添加到`scrape_configs`属性中：

```go
global: 
  scrape_interval: 15s 

scrape_configs: 
  - job_name: prometheus 
    static_configs: 
      - targets: ["localhost:9090"] 
  - job_name: eventservice 
    static_configs: 
      - targets: ["events:9090"] 
  - job_name: bookingservice 
    static_configs: 
      - targets: ["bookings:9090"] 
```

添加新的抓取目标后，通过运行`docker container restart prometheus`来重新启动 Prometheus 容器。之后，这两个新的抓取目标应该会显示在 Prometheus web UI 中：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/9c508298-984f-4e2a-8280-ce15c5b80974.png)

Prometheus web UI targets

现在，最好的部分——还记得之前几节创建的 Grafana 仪表板吗？现在您已经添加了两个新服务以供 Prometheus 抓取，再看一下它：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/fbf352c1-0262-4a68-a2ef-12daf019ee5e.png)

Gafana

正如您所看到的，Grafana 和 Prometheus 立即从新服务中获取指标。这是因为我们到目前为止使用的`process_cpu_seconds_total`和`go_memstats_alloc_bytes`指标实际上是由我们的三个服务中的所有服务导出的，因为它们都使用 Prometheus Go 客户端库。但是，Prometheus 为每个被抓取的指标添加了一个额外的作业标签；这允许 Prometheus 和 Grafana 区分来自不同抓取目标的相同指标并相应地呈现它们。

# 导出自定义指标

当然，您也可以使用 Prometheus 客户端库导出自己的指标。这些不需要是反映 Go 运行时某些方面的技术指标（如 CPU 使用率和内存分配），而可以是业务指标。一个可能的例子是每个事件的不同标签的预订票数。

例如，在`todo.com/myevents/bookingservice/rest`包中，您可以添加一个新文件——让我们称之为`metrics.go`*——*声明并注册一个新的 Prometheus 指标：

```go
package rest 

import "github.com/prometheus/client_golang/prometheus" 

var bookingCount = prometheus.NewCounterVec( 
  prometheus.CounterOpts{ 
    Name:      "bookings_count", 
    Namespace: "myevents", 
    Help:      "Amount of booked tickets", 
  }, 
  []string{"eventID", "eventName"}, 
) 

func init() { 
  prometheus.MustRegister(bookingCount) 
} 
```

Prometheus 客户端库在一个包中跟踪所有创建的指标对象，这是一个全局注册表，会自动初始化。通过调用`prometheus.MustRegister`函数，您可以将新的指标添加到此注册表中。当 Prometheus 服务器抓取`/metrics`端点时，所有注册的指标将自动暴露出来。

`NewCounterVec`函数创建了一个名为`myevents_bookings_count`的指标集合，但通过两个标签`eventID`和`eventName`进行区分（实际上，这些是功能相关的，您不需要两者都需要；但在 Grafana 中可视化此指标时，将事件名称作为标签非常方便）。当抓取时，这些指标可能看起来像这样：

```go
myevents_bookings_count{eventID="507...",eventName="Foo"} 251 
myevents_bookings_count{eventID="508...",eventName="Bar} 51 
```

Prometheus 客户端库知道不同类型的指标。我们在前面的代码中使用的 Counter 是其中较简单的一种。在之前的某个部分中，您看到了一个复杂的直方图是如何表示为多个不同的指标的。这在 Prometheus 客户端库中也是可能的。为了演示，让我们添加另一个指标——这次是一个直方图：

```go
var seatsPerBooking = prometheus.NewHistogram( 
  prometheus.HistogramOpts{ 
    Name: "seats_per_booking", 
    Namespace: "myevents", 
    Help: "Amount of seats per booking", 
    Buckets: []float64{1,2,3,4} 
  } 
) 

func init() { 
  prometheus.MustRegister(bookingCount) 
  prometheus.MustRegister(seatsPerBooking) 
} 
```

在被抓取时，此直方图将导出为七个单独的指标：您将获得五个直方图桶（*具有一个或更少座位的预订数量* 到*具有四个或更少座位* 和*具有无限多座位或更少*），以及一个用于所有座位和所有观察的总和的指标：

```go
myevents_seats_per_booking_bucket{le="1"} 1 
myevents_seats_per_booking_bucket{le="2"} 8 
myevents_seats_per_booking_bucket{le="3"} 18 
myevents_seats_per_booking_bucket{le="4"} 20 
myevents_seats_per_booking_bucket{le="+Inf"} 22 
myevents_seats_per_booking_sum 72 
myevents_seats_per_booking_count 22 
```

当然，我们需要告诉 Prometheus 库在被 Prometheus 服务器抓取时应该导出哪些指标值。由于这两个指标（预订数量和每个预订的座位数量）只有在进行新预订时才会改变，因此我们可以将此代码添加到处理`/events/{id}/bookings`路由上的 POST 请求的 REST 处理程序函数中。

在`booking_create.go`文件中，在原始请求处理后的某个位置添加以下代码（例如，在事件发射器上发出`EventBooked`事件之后）：

```go
h.eventEmitter.emit(&msg) 

bookingCount. 
  WithLabelValues(eventID, event.Name). 
  Add(float64(request.Seats)) 
seatsPerBooking. 
  Observe(float64(bookingRequest.Seats)) 

h.database.AddBookingForUser(
   // ... 
```

第一条语句将预订的座位数量（`request.Seats`）添加到计数器指标中。由于在`CounterVec`声明中定义了一个名为`event`的标签，因此您需要使用相应的标签值调用`WithLabelValues`方法（如果指标声明包含两个标签，则需要将两个参数传递给`WithLabelValues`）。

第二条语句向直方图添加了一个新的`observation`。它将自动找到正确的桶并将其增加一个（例如，如果使用相同预订添加了三个座位，则`myevents_seats_per_booking_bucket{le="3"}`指标将增加一个）。

现在，启动您的应用程序，并确保 Prometheus 定期对其进行抓取。花点时间向您的应用程序添加一些示例记录。还在预订服务中添加一些事件预订；确保您不是一次创建它们。之后，您可以使用`myevents_bookings_count`指标在 Grafana 仪表板中创建一个新图表：

>![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/a6a1c84f-56d9-4b27-9cab-92b427f8b42a.png)

Gafana 图表

默认情况下，Prometheus 将为每个抓取实例创建一个时间序列。这意味着当您有多个预订服务实例时，您将获得多个时间序列，每个时间序列都有不同的`job`标签：

```go
myevents_bookings_count{eventName="Foo",job="bookingservice-0"} 1 
myevents_bookings_count{eventName="Foo",job="bookingservice-1"} 3 
myevents_bookings_count{eventName="Bar",job="bookingservice-0"} 2 
myevents_bookings_count{eventName="Bar",job="bookingservice-1"} 1 
```

在显示业务指标（例如，售出的门票数量）时，您可能实际上并不关心每个特定预订是在哪个实例上放置的，并且更喜欢在所有实例上使用聚合时间序列。为此，构建仪表板时可以使用 PromQL 函数`sum()`：

```go
sum(myevents_bookings_count) by (eventName) 
```

# 在 Kubernetes 上运行 Prometheus

到目前为止，我们通过将它们添加到`prometheus.yml`配置文件中手动配置了 Prometheus 的所有抓取目标。这对于测试很有效，但在更大的生产设置中很快变得乏味（并且在引入自动缩放等功能后完全没有意义）。

在 Kubernetes 集群中运行应用程序时，Prometheus 为此提供了一种一站式解决方案——使用`prometheus.yml`配置文件，您实际上可以配置 Prometheus 自动从 Kubernetes API 加载其抓取目标。例如，如果为您的预订服务定义了一个部署，Prometheus 可以自动找到由此部署管理的所有 Pod，并对它们进行抓取。如果扩展了部署，附加实例将自动添加到 Prometheus 中。

在以下示例中，我们将假设您在本地计算机上运行 Minikube VM 或在云环境中的某个 Kubernetes 集群。我们将首先部署 Prometheus 服务器。为了管理 Prometheus 配置文件，我们将使用一个以前未使用过的 Kubernetes 资源——`ConfigMap`。`ConfigMap`基本上只是一个您可以保存在 Kubernetes 中的任意键值映射。在创建 Pod（或部署或 StatefulSet）时，您可以将这些值挂载到容器中作为文件，这使得`ConfigMaps`非常适合管理配置文件：

```go
apiVersion: v1 
kind: ConfigMap 
name: prometheus-config 
data: 
  prometheus.yml: | 
    global: 
      scrape_config: 15s 

    scrape_configs: 
    - job_name: prometheus 
      static_configs: 
      - targets: ["localhost:9090"] 
```

您可以像保存其他资源一样创建`ConfigMap`，将其保存到`.yaml`文件中，然后在该文件上调用`kubectl apply -f`。当您修改了`.yaml`文件时，也可以使用相同的命令来更新`ConfigMap`。

创建了`ConfigMap`后，让我们部署实际的 Prometheus 服务器。由于 Prometheus 是一个有状态的应用程序，我们将其部署为`StatefulSet`：

```go
apiVersion: apps/v1beta1 
kind: StatefulSet 
metadata: 
  name: prometheus 
spec: 
  serviceName: prometheus 
  replicas: 1 
  template: 
    metadata: 
      labels: 
        app: prometheus 
    spec: 
      containers: 
      - name: prometheus 
        image: prom/prometheus:v1.6.1 
        ports: 
        - containerPort: 9090 
          name: http 
        volumeMounts: 
        - name: data 
          mountPath: /prometheus 
        - name: config 
          mountPath: /etc/prometheus 
      volumes: 
      - name: config 
        configMap: 
          name: prometheus-config 
  volumeClaimTemplates: 
  - metadata: 
      name: data 
      annotations: 
        volume.alpha.kubernetes.io/storage-class: standard 
    spec: 
      accessModes: ["ReadWriteOnce"] 
      resources: 
        requests: 
          storage: 5Gi 
```

还要创建相关的`Service`：

```go
apiVersion: v1 
kind: Service 
metadata: 
  name: prometheus 
spec: 
  clusterIP: None 
  selector: 
    app: prometheus 
  ports: 
  - port: 9090 
    name: http 
```

现在，您在 Kubernetes 集群内运行了一个 Prometheus 服务器；但是，目前该服务器只抓取自己的指标端点，而尚未抓取集群中运行的任何其他 Pod。

要启用对 Pod 的自动抓取，请将以下部分添加到`prometheus.yml`文件的`ConfigMap`中的`scrape_configs`部分：

```go
scrape_configs: 
  # ... 
  - job_name: kubernetes-pods 
    kubernetes_sd_configs: 
    - role: pod 
  relabel_configs: 
  - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_scrape] 
    action: keep 
    regex: true 
  - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_path] 
    action: replace 
    target_label: __metrics_path__ 
    regex: (.+) 
  - source_labels: [__address__, __meta_kubernetes_pod_annotation_prometheus_io_port] 
    action: replace 
    regex: ([^:]+)(?::\d+)?;(\d+) 
    replacement: $1:$2 
    target_label: __address__ 
  - action: labelmap 
    regex: __meta_kubernetes_pod_label_(.+) 
  - source_labels: [__meta_kubernetes_namespace] 
    action: replace 
    target_label: kubernetes_namespace 
  - source_labels: [__meta_kubernetes_pod_name] 
    action: replace 
    target_label: kubernetes_pod_name 
```

是的，这是相当多的配置，但不要惊慌。大多数这些配置是为了将已知 Kubernetes Pod 的属性（例如用户定义的 Pod 名称和标签）映射到将附加到从这些 Pod 中抓取的所有指标的 Prometheus 标签。

请注意，在更新`ConfigMap`后，您可能需要销毁您的 Prometheus Pod，以使更新后的配置生效。不用担心；即使您删除了 Pod，`StatefulSet`控制器也会立即创建一个新的：

```go
$ kubectl delete pod -l app=prometheus 
```

此配置还定义了 Prometheus 将抓取集群中具有名为`prometheus.io/scrape`的注释的所有 Pod。在定义 Pod 模板时可以设置此注释，例如在部署中。此外，您现在可以调整您的事件服务部署如下（记得将 TCP 端口`9100`添加到暴露端口列表中）：

```go
apiVersion: apps/v1beta1 
kind: Deployment 
metadata: 
  name: eventservice 
spec: 
  replicas: 2 
  template: 
    metadata: 
      labels: 
        myevents/app: events 
        myevents/tier: api 
      annotations: 
        prometheus.io/scrape: true 
        prometheus.io/port: 9100 
    spec: 
      containers: 
      - name: api 
        image: myevents/eventservice 
        imagePullPolicy: Never 
        ports: 
        - containerPort: 8181 
          name: http 
        - containerPort: 9100 
          name: metrics 
        # ... 
```

更新部署后，Kubernetes 应该会自动开始重新创建事件服务 Pod。一旦创建了带有`prometheus.io/scrape`注释的新 Pod，Prometheus 将自动捕获并抓取它们的指标。如果它们再次被删除（例如在更新或缩减部署后），Prometheus 将保留从这些 Pod 中收集的指标，但停止抓取它们。

通过让 Prometheus 根据注释自动捕获新的抓取目标，管理 Prometheus 服务器变得非常容易；在初始设置之后，您可能不需要再次编辑配置文件。

# 总结

在本章中，您学习了如何使用 Prometheus 和 Grafana 来设置监控堆栈，以监视应用程序在技术层面上的健康状况（通过关注系统指标，如 RAM 和 CPU 使用情况）以及自定义的应用程序特定指标，例如，在这种情况下，预订票数的数量。

在本书的过程中，我们几乎涵盖了典型 Go 云应用程序的整个生命周期，从架构和实际编程开始，构建容器映像，不断在各种云环境中部署它们，并监视您的应用程序。

在接下来的章节中，我们将有机会详细回顾我们迄今为止取得的成就，并指出接下来要做什么。


# 第十一章：迁移

欢迎来到我们学习云原生编程和 Go 语言世界的第十一章。在本章中，我们将涵盖一些实用的技术，以将应用程序从单片架构迁移到微服务架构。我们已经在第二章中涵盖了单片和微服务架构，*使用 Rest API 构建微服务。*但是，我们将从实际定义单片和微服务架构开始本章，以防您单独阅读本章。

在本章中，我们将涵盖以下主题：

+   单片应用程序和微服务架构的回顾

+   从单片应用程序迁移到微服务应用程序的技术

+   高级微服务设计模式

+   微服务架构中的数据一致性

# 什么是单片应用程序？

**单片应用程序**只是一个软件，可以同时执行多个独立的任务。让我们以在线商店应用程序为例。在单片架构中，我们将有一个单一的软件来处理客户、他们的订单、数据库连接、网站、库存以及在线商店成功所需的任何其他任务。

一个软件执行所有任务似乎是软件设计的一种低效方法，在某些情况下确实如此。然而，重要的是要提到，单片应用程序并不总是不好的。在一些情况下，一个单一的软件服务执行所有工作是可以接受的。这包括最小可行产品或 MVP，我们试图快速构建一些东西供测试用户尝试。这还包括预期没有太多数据负载或流量的使用情况，比如面向传统棋盘游戏爱好者的在线商店。

# 什么是微服务？

**微服务架构**与单片应用程序相比，构建软件采用了不同的方法。在微服务架构中，任务分布在多个较小的软件服务中，这些服务被称为微服务。在设计良好的微服务架构中，每个微服务应该是自包含的、可部署的和可扩展的。设计良好的微服务还享有干净的 API，允许其他微服务与它们通信。独立的软件服务共同努力实现共同目标的概念并不新鲜；它在过去作为**面向服务的架构**（**SOA**）存在。然而，现代微服务架构通过坚持软件服务相对较小、独立和完全自包含的概念，将这个想法推向了更远。

让我们回到在线商店的例子。在微服务架构的情况下，我们会有一个用于处理客户的微服务，一个用于处理库存的微服务，依此类推。

典型的微服务内部包含多个必要的层，用于处理日志记录、配置、与其他微服务通信的 API 以及持久性。还有微服务的核心代码，涵盖了服务应该执行的主要任务。以下是微服务内部应该看起来的样子：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/0b75db61-3b04-471c-a000-60aa8f4b3a33.png)

微服务的内部外观

当涉及可伸缩性和灵活性时，微服务架构比单片应用程序具有重大优势。微服务允许您无限扩展，利用多种编程语言的功能，并优雅地容忍故障。

# 从单片应用程序迁移到微服务

现在，假设你有一个单片应用，你的业务正在增长，你的客户要求更多功能，你需要迁移到既灵活又可扩展的架构。是时候使用微服务了。迁移时需要牢记的第一个关键原则是，没有一套黄金步骤可以确保从单片应用成功迁移到微服务。我们需要遵循的步骤因情况而异，因组织而异。话虽如此，本章中有一些非常有用的概念和想法，可以帮助您做出明智的决策。

# 人与技术

从单片应用转向微服务时最容易被忽视的因素之一是**人员因素**。我们通常考虑技术和架构，但是谁来编写代码、管理项目和重新设计应用的团队呢？从单片应用转向微服务是一个需要在组织中进行适当规划的范式转变。

在决定转向微服务后，我们需要考虑的第一件事是参与开发过程的团队结构。通常，以下是负责单片应用的团队：

+   开发人员习惯于在单一编程语言中工作的特定部分的应用中工作

+   IT 基础设施团队通常只需更新托管单片应用及其数据库的少数服务器，部署就完成了。

+   团队负责人拥有应用的一部分，而不是从 A 到 Z 的整个软件服务

如前所述，微服务迁移代表了一种范式转变。这意味着在转向微服务架构时，组织需要采用一种新的思维方式。考虑以下内容：

+   开发人员需要分成较小的团队，每个团队应负责一个或多个微服务。开发人员需要习惯于负责整个软件服务，而不是一堆软件模块或类。当然，如果组织足够大，你仍然可以让开发人员负责微服务中的特定模块。然而，如果开发人员接受培训，将产品视为整个微服务，这将产生更好设计的微服务。开发人员还需要习惯于使用适合工作的编程语言。例如，Java 对于数据处理和流水线很重要，Go 非常适合构建快速可靠的微服务，C#适用于 Windows 服务，等等。

+   IT 基础设施团队需要了解水平扩展、冗余、可扩展的云平台以及部署大量服务所涉及的规划过程。

+   团队负责人将承担从 A 到 Z 的整个软件服务的责任。他们需要考虑实施细节，比如如何扩展服务、是否与其他服务共享数据库或拥有自己的数据库，以及服务如何与其他服务通信。

# 将单片应用切割成片

现在我们已经讨论了迁移的人员方面，让我们深入了解技术细节。几乎每个人都同意的一个黄金法则是，从头开始编写所有内容，忽略现有单片应用中的所有代码（也称为大爆炸重写）并不是一个好主意。相反，从单片应用迁移到微服务的最佳方法是随着时间的推移逐步削减单片应用。每个分离的部分都成为一个微服务。对于每个新的微服务，我们需要确保它仍然可以与单片应用以及其他新的微服务进行通信。如果这种方法进行顺利，单片应用将随着时间的推移不断缩小，直到成为一个微服务。

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/78cdb5a4-136f-4f38-991d-f5659b14fdc3.png)

单片应用随时间缩小

这听起来很简单；然而，在现实生活中，通常并不是那么直截了当。让我们讨论一些规划策略，使逐步逐步的方法更具可执行性。

# 我们如何分解代码？

我们需要问的一个关键技术问题是，我们应该如何精确地分解单片应用的代码？以下是一些重要的要点：

+   如果一个应用程序编写得很好，不同类或软件模块之间会有清晰明显的分离。这使得切割代码变得更容易。

+   另一方面，如果代码中没有清晰的分离，我们需要在开始将代码片段移动到新的微服务之前对现有代码进行一些重构。

+   通常最好的做法是，不要在单片应用中添加新的代码或功能，而是尝试将新功能分离成一个新的微服务。

# 粘合代码

为了使新的微服务适应原始应用而不破坏其功能，微服务需要能够与原始应用交换信息。为了实现这一点，我们可能需要编写一些粘合代码，将新代码与旧代码链接起来。粘合代码通常包括一些 API 接口，作为原始应用和微服务之间的通信渠道。粘合代码还将包括使新的微服务与现有应用程序配合工作所需的任何代码：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/d6662e58-ee72-4ea8-92ed-ae2c223656de.png)

粘合代码

粘合代码可能是临时的，也可能是永久的，这取决于我们的应用程序。有时，粘合代码可能需要进行一些数据建模转换或与旧数据库进行通信以使事情正常运行。

如果您的应用程序是一个 Web 应用程序，粘合代码可能包括一个临时的 Web HTTP API，可以将您新分离的微服务与您的视图层连接起来。

# 微服务设计模式

在本节中，我们将讨论一些重要的设计模式和架构方法，这些方法可以帮助我们构建强大而有效的云就绪微服务。让我们开始吧。

# 牺牲性架构

**牺牲性架构**是一个重要的设计方法，通常没有得到应有的关注。Martin Folwer 在 2014 年提到了这一点，可以在[`martinfowler.com/bliki/SacrificialArchitecture.html`](https://martinfowler.com/bliki/SacrificialArchitecture.html)找到。

牺牲架构的核心思想是，我们应该以一种易于在未来替换的方式编写我们的软件。为了更好地理解前面的陈述，让我们考虑一个例子情景。假设几年前，我们构建了一个计算机网络应用程序，该应用程序利用我们的开发人员设计的自定义数据序列化格式。今天，我们需要用更现代的编程语言重写该应用程序，以处理更多的数据负载和用户请求。这个任务无论如何都不会有趣或容易，因为我们的应用程序依赖于只有应用程序的原始开发人员才能理解的自定义序列化和通信协议。

现在，如果我们使用了更标准化的序列化格式，比如协议缓冲区，那会怎么样？重写或更新应用程序的任务将变得更加容易和高效，因为协议缓冲区受到广泛的编程语言和框架支持。使用标准序列化格式构建我们的应用程序，而不是自定义的格式，这就是牺牲架构的意义所在。

当我们设计我们的软件时考虑到牺牲架构，升级、重构和/或演变我们的应用程序的任务变得更加简单。如果我们的单片应用程序设计时考虑到了牺牲架构，将应用程序的部分分离成微服务就变得容易了。

如果我们在编写我们的粘合代码时考虑到了牺牲架构，那么在未来演变粘合代码或完全摆脱它并用其他东西替换它将变得更加容易。如果我们在构建新的微服务时考虑到了牺牲架构，我们就给自己快速、无痛和高效地增长和演变微服务的能力。

# 一个四层的参与平台

**四层参与平台**是一种以整个应用程序为目标的架构方法。它在 Forrester 研究中被描述为[`go.forrester.com/blogs/13-11-20-mobile_needs_a_four_tier_engagement_platform/`](https://go.forrester.com/blogs/13-11-20-mobile_needs_a_four_tier_engagement_platform/)。这种架构非常适合面向移动和网络时代的现代应用程序。该架构允许可伸缩性、灵活性和性能。它还使得集成云服务和内部微服务变得非常容易和高效。

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/3ac4697f-dd63-4e40-b05a-573ca35e2f76.png)

四层参与架构

这种架构背后的主要思想是，整个应用程序应该分为四个主要层或层：

+   **客户层**：这一层负责用户体验；它根据用户的上下文环境定制用户体验。上下文环境包括用户设备类型、用户位置、时间等。例如，如果您的产品用户使用智能手表，那么客户层应该呈现适合智能手表的内容。如果他们使用平板电脑，那么适合平板电脑的用户界面将迎接用户。如果用户正在查看来自中国的数据，客户层需要以中文显示信息。如果用户正在查看来自加拿大的数据，信息需要以英文显示。

+   **交付层**：交付层负责按照客户层的要求向用户交付优化的数据。这是通过进行即时优化来实现的，例如图像压缩或带宽减少。该层可以利用监控工具来跟踪用户活动，然后利用算法利用这些信息来提供更好的客户体验。这一层也是我们使用缓存算法和技术来确保为我们的客户提供更好性能的地方。

+   **聚合层：**这一层是将来自不同来源的数据聚合成稳定和统一的数据模型的地方，然后将其交给前面的层。这一层的任务包括以下内容：

+   在层之间充当 API 中心，提供服务可发现性和数据访问给前面的层。

+   集成来自内部服务（例如内部微服务）和外部服务（例如 AWS 云服务）的输出。

+   从不同来源类型合并数据，例如，从一个来源读取 base64 编码的消息，从另一个来源读取 JSON 编码的消息，然后将它们链接在一起形成统一的数据模型。

+   将数据编码为适合交付给用户的格式。

+   指定基于角色的数据访问。

+   **服务层：**这一层由我们的外部和内部服务组成。它为各层提供原始数据和功能。这些层由一组可部署的内部和外部服务组成。服务层是我们与数据库（如 MySQL 或 DynamoDB）通信的地方；我们会在这里使用第三方服务，如 AWS S3 或 Twilio。这一层应该被设计为可插拔的，这意味着我们可以随意地向其中添加或移除服务。

如果我们使用上述的架构模式设计我们的现代应用程序，我们将获得无限的灵活性和可扩展性。例如，我们可以在客户端层针对新的用户设备类型，而无需在其他层中改变太多代码。我们可以在服务层中添加或移除微服务或云服务，而无需在其上层改变太多代码。我们可以在聚合层中支持新的编码格式，如 Thrift 或协议缓冲区，而无需在其他层上改变太多代码。四层参与平台目前正在被 Netflix 和 Uber 等公司使用。

# 领域驱动设计中的有界上下文

**领域驱动设计**（**DDD**）是一种流行的设计模式，我们可以用它来内部设计微服务。领域驱动设计通常针对可能会随着时间呈指数增长的复杂应用程序。如果您的单片应用程序已经通过 DDD 设计，那么迁移到微服务架构将是直接的。否则，如果您期望新的微服务在范围和复杂性上增长，那么考虑 DDD 可能是一个好主意。

领域驱动设计是一个庞大的主题。维基百科文章可以在[`en.wikipedia.org/wiki/Domain-driven_design`](https://en.wikipedia.org/wiki/Domain-driven_design)找到。然而，为了本节的目的，我们将介绍一些简要的概念，这些概念可以帮助我们获得对 DDD 的实际理解。然后，从那里，您将了解为什么这种设计方法对于复杂的微服务架构是有益的。

领域驱动设计的理念是，一个复杂的应用程序应该被视为在一个*领域*内运行。领域简单地定义为知识或活动的范围。我们软件应用程序的领域可以被描述为与软件目的相关的一切。因此，例如，如果我们软件应用程序的主要目标是促进社交活动的规划，那么规划社交活动就成为我们的领域。

一个域包含*上下文*；每个上下文代表域的一个逻辑部分，人们在其中使用相同的语言。在上下文中使用的语言只能根据它所属的上下文来理解。

根据我的经验，没有例子很难理解上下文是什么。所以，让我们举一个简单的例子。假设社交活动应用背后的组织是一个大型组织，拥有销售部门、营销部门和支持部门。这意味着这个组织的领域驱动设计可能需要包括以下三个主要上下文：销售上下文、营销上下文和支持上下文。

销售人员使用的一些语言只对销售人员相关。例如，销售漏斗、销售机会或销售管道的概念对销售非常重要，但对支持部门可能并不相关。这就是为什么销售上下文可以包括销售漏斗的概念，但在支持上下文中你不会经常找到这种语言或概念。

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/9124a64c-1f1b-404b-829f-138e696490c4.png)

领域

领域还包含模型。每个模型都是描述领域中独立概念的抽象。模型最终会被转化为软件模块或对象。模型通常存在于上下文中。例如，在销售上下文中，我们需要模型来表示销售合同、销售漏斗、销售机会、销售管道和客户等，而在支持上下文中，我们需要模型来显示工单、客户和缺陷。以下是一个简单的图表，显示了销售上下文和支持上下文中的一些模型：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/44d6aaf1-7ead-42a0-8734-56590e1576e1.png)

销售和支持上下文

不同的上下文可以共享相同的语言或概念，但关注不同的方面。在我们的大型组织示例中，销售人员使用的一个词可能并不总是对支持人员来说意味着相同的词。例如，对于销售部门来说，*客户*代表着一个可能从组织购买产品但尚未购买的客户。另一方面，对于支持部门来说，客户可能是已经购买产品、购买了支持合同并且正在遇到产品问题的客户。因此，这两个上下文共享客户的概念；然而，当涉及到这个概念时，它们关心的是不同的事情。

同一种语言在不同环境中可能意味着不同的事情，这引入了领域驱动设计世界中的一个关键概念，即有界上下文。有界上下文是共享概念的上下文，但它们实现了自己的概念模型。例如，*客户*的概念在销售上下文中由一个模型表示，反映了销售部门关心的客户版本。客户的概念也根据支持上下文中的版本进行建模。虽然它们是两个模型，但它们仍然是相互关联的。这是因为，归根结底，它们都代表了社交活动策划公司的客户。以下是一个简单的图表，显示了这种情况：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/39d9dcb0-771c-417f-8376-5d520ae9d179.png)

销售和支持上下文

上下文和有界上下文是领域驱动设计和微服务相遇的地方。这是复杂现代微服务的关键设计因素，因为上下文可以很容易地映射到微服务。如果你试图定义有界上下文，你会发现自己不仅在实践中定义了微服务应该是什么，还在定义应该在微服务之间共享什么信息来构建整个应用程序。有界上下文的简单定义是它是一个作为更大应用程序一部分的自包含逻辑块。这个定义也可以毫无添加地应用于描述一个设计良好的微服务。有时，一个有界上下文可以被划分为多个服务，但这通常取决于应用程序的复杂程度。

在我们的例子中，我们最终会有一个处理销售操作的微服务和一个处理支持操作的微服务。

如果您的单体应用程序已经根据 DDD 原则进行了设计，那么迁移到微服务架构会变得更容易。这是因为从形成界限上下文的代码过渡到自包含的微服务会是有意义的。

另一方面，如果您的单体应用程序没有以这种方式设计，但应用程序复杂且不断增长，那么可以利用 DDD 原则来构建未来的微服务。

# 数据一致性

支撑应用程序的数据库是一个至关重要的组成部分，在迁移到微服务架构时必须极其小心谨慎地处理和尊重。在单体应用程序的世界中，您可能会处理连接到单体应用程序的少量数据库（一个或两个）通过一个庞大的数据处理层，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/3866d74d-1919-4e48-bd36-f0ec9e61446c.png)

单体应用程序与数据库

然而，在微服务和分布式云架构的情况下，情况可能大不相同。这是因为架构可能包括更广泛的数据模型和数据库引擎，以满足分布式微服务的需求。微服务可以拥有自己的数据库，与其他应用程序共享数据库，或同时使用多个数据库。在现代微服务架构中，数据一致性和建模是一个非常棘手的挑战，我们需要在失控之前通过良好的应用程序设计来解决。

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/26f79828-f779-40ec-8730-d7f9d3ed3c27.png)

在接下来的部分中，我们将讨论一些策略，以便在从单体应用程序范式到微服务中打破数据模型时牢记。

# 数据一致性的事件驱动架构

我们可以利用的关键设计模式之一，用于保护微服务架构中的数据一致性的是事件驱动设计。微服务中数据一致性难以维护的原因是，每个微服务通常负责整个应用程序的一部分数据。应用程序微服务处理的数据存储的总和代表了应用程序的总状态。因此，这意味着当一个微服务更新其数据库时，受此数据更改影响的其他微服务需要知道这一点，以便它们可以采取适当的行动并更新自己的状态。

让我们以本章的界限上下文部分中的销售和支持微服务示例为例。如果一个新客户购买了产品，销售微服务将需要更新自己的数据库，以反映新客户的状态，即实际付费客户，而不仅仅是潜在客户。这个事件还需要通知支持微服务，以便它可以更新自己的数据库，以反映有一个新的付费客户，无论何时需要都应该得到客户或技术支持。

这种微服务之间的事件通信就是微服务世界中的事件驱动设计。微服务之间的消息队列或消息代理可以用来在微服务之间通信事件消息。消息代理在第四章中详细讨论，*使用消息队列的异步微服务架构*。需要在某个事件发生时通知的微服务将必须订阅这些事件。

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/e3f1de3a-32a3-41a1-a6a4-84b5641089af.png)

例如，支持服务将需要订阅消息队列上代表客户购买产品的事件主题。销售微服务在客户购买产品时触发此事件。由于支持服务订阅了该事件，它将在不久后收到事件的通知，其中将包括新客户的信息。从那里，支持服务将能够执行自己的逻辑，以确保支持组织随时为客户提供帮助，甚至可能为新客户触发欢迎邮件。

现在，这听起来都很好，但如果支持微服务在接收新客户事件之前失败了怎么办？这意味着支持服务最终将不知道新客户的情况，因此不会对新客户的相关信息进行任何逻辑处理，也不会将其添加到支持数据库中。这是否意味着当客户以后寻求帮助时，支持团队不会帮助，因为他们在系统中看不到客户？显然，我们不希望发生这种情况。一种方法是拥有一个存储客户数据的中央数据库，该数据库将在不同的微服务之间共享，但如果我们寻求一种灵活的设计，每个微服务都完全负责自己的整个状态，该怎么办。这就是事件溯源和 CQRS 概念出现的地方。

# 事件溯源

事件溯源的基本思想是，我们需要利用记录的事件流来形成状态，而不是完全依赖于本地数据库来读取状态。为了使其工作，我们需要存储所有当前和过去的事件，以便以后可以检索它们。

我们需要一个例子来巩固这个理论定义。假设支持服务在接收新客户事件之前失败并崩溃了。如果支持服务不使用事件溯源，那么当它重新启动时，它将在自己的数据库中找不到客户信息，也永远不会知道这个客户。然而，如果它使用事件溯源，那么它不仅会查看本地数据库，还会查看与所有其他微服务共享的事件存储。事件存储将记录我们的微服务之间触发的任何事件。在事件存储中，支持服务将能够重放最近触发的新客户事件，并且会发现这个客户目前不存在于本地支持微服务数据库中。支持服务可以将这些信息处理为正常情况。

再次强调，这种设计能够成功的关键技巧是永远不要丢弃任何事件，无论是过去的还是新的。这是通过将它们保存在事件存储中来实现的；以下是它的样子：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/2b39e000-6ae9-46f8-abcb-9d68c15174f3.png)

实现事件存储有多种方法；它可以是 SQL 数据库、NoSQL 数据库，甚至是支持永久保存事件的消息队列。Kafka 就是一个消息队列的例子，它声称也是事件溯源的良好引擎。

处理事件溯源有多种方法；我们在本节中涵盖的场景代表了一种使用事件存储和快照的方法。在这种情况下，快照是支持微服务本地数据库，它也试图保持快照状态。然而，最终状态仍然预期在事件存储中。

还有其他实现事件溯源的方法，其中不使用快照，整个状态始终必须从事件存储中派生。

事件溯源的缺点是它可能在复杂性上呈指数级增长。这是因为在某些环境中，我们可能需要重放大量事件，以构建系统的当前状态，这需要大量的处理和复杂性。我们需要运行的查询以形成从不同重放事件中联接数据的数据模型可能会变得非常痛苦。

控制事件溯源复杂性的一种流行方法是 CQRS。

# CQRS

**命令查询责任分离**（**CQRS**）的基本理念是，命令（指与更改数据相关的任何操作，如添加、更新或删除）应该与查询（指与读取数据相关的任何操作）分开。在微服务架构中，这意味着一些服务应该负责命令，而其他服务应该负责查询。

CQRS 的一个关键优势是关注点的分离。这是因为我们将写入关注点与读取关注点分开，并允许它们独立扩展。例如，假设我们使用一个复杂的应用程序，我们需要不同的数据视图可用。我们希望将所有客户数据存储在弹性搜索集群中，以便能够高效地搜索并检索它们的信息。与此同时，我们希望将所有客户数据存储在图数据库中，因为我们希望以图形方式查看数据。

在这种情况下，我们将创建微服务，负责从事件流（消息队列）中查询客户事件，然后通过事件溯源在接收到新的客户事件时更新弹性搜索和图数据库。这些服务将成为 CQRS 的查询部分。另一方面，我们将有其他微服务负责在需要时触发新事件。这些服务最终将成为 CQRS 的命令部分。

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/3211dba1-7403-49a0-b56a-c008bd94cfd5.png)

这些读写微服务然后可以与我们的其他服务一起工作，形成我们的应用程序。

# 摘要

在本章中，我们深入探讨了从单体应用程序迁移到微服务应用程序的实际方面。我们仔细研究了一些高级设计模式和架构，可以利用它们来从单体应用程序切换到微服务应用程序。本章结束了我们对本书的学习之旅。

在下一章中，我们将讨论一些技术和主题，您可以在掌握本书中的知识后开始探索。


# 第十二章：接下来该去哪里？

欢迎来到我们学习 Go 语言云原生编程的最后一章。到目前为止，你应该已经掌握了足够的知识来构建生产级别的微服务，设计复杂的分布式架构，利用亚马逊云服务的强大功能，为你的软件赋予容器的力量，等等。

然而，云原生编程的主题非常深入和广泛。这意味着你仍然可以学习一些主题，丰富你在这个领域的知识和技能。本章的目的是为你提供一些实用的概述，让你在吸收了本书中的知识之后，能够继续探索一些本书未涵盖的强大主题。

在这一章中，我们将涵盖以下主题：

+   其他微服务通信模式和协议，比如协议缓冲区和 GRPC

+   云提供商提供的更多有用功能

+   其他云提供商（Azure、GCP 和 OpenStack）

+   无服务器计算

# 微服务通信

在本书中，我们涵盖了微服务相互通信的两种方法：

+   第一种方法是通过 RESTful API，其中一个 Web HTTP 层将被构建到一个微服务中，有效地允许微服务与任何 Web 客户端进行通信，无论这个 Web 客户端是另一个微服务还是一个 Web 浏览器。这种方法的一个优点是它赋予了微服务在需要时与外部世界通信的能力，因为 HTTP 现在是一个被所有软件堆栈支持的通用协议。然而，这种方法的缺点是 HTTP 可能是一个具有多层的重型协议，在内部微服务之间需要快速高效的通信时可能不是最佳选择。

+   第二种方法是通过消息队列，其中消息代理软件（如 RabbitMQ 或 Kafka）将促进微服务之间的消息交换。消息代理接收来自发送微服务的消息，将消息排队，然后将其传递给之前表明对这些消息感兴趣的微服务。这种方法的一个主要优势是它可以巩固大规模分布式微服务架构中的数据一致性，如第十一章 *迁移*中所解释的那样。这种方法使得事件驱动的分布式架构成为可能，比如事件溯源和 CQRS。然而，如果我们的扩展需求相对简单，这种方法可能对我们的需求来说过于复杂。这是因为它要求我们维护一个带有所有配置和后端的消息代理软件。在这些情况下，直接的微服务之间的通信可能就是我们所需要的一切。

如果你还没有注意到，这两种方法的一个明显的缺点是它们都不能提供直接高效的微服务之间的通信。我们可以采用两种流行的技术来实现直接的微服务通信：协议缓冲区和 GRPC。

# 协议缓冲区

在它们的官方文档中，协议缓冲区被定义为一种语言中立、平台中立的序列化结构化数据的机制。让我们看一个例子，帮助建立协议缓冲区是什么的清晰图景。

假设您的应用程序中有两个微服务；第一个微服务（服务 1）已经收集了有关新客户的信息，并希望将其发送给第二个微服务（服务 2）。这些数据被视为结构化数据，因为它包含结构化信息，如客户姓名、年龄、工作和电话号码。发送这些数据的一种方式是将其作为 JSON 文档（我们的数据格式）通过 HTTP 从服务 1 发送到服务 2。然而，如果我们想更快地以更小的形式发送这些数据呢？这就是协议缓冲区的作用。在服务 1 内部，协议缓冲区将获取客户对象，然后将其序列化为紧凑形式。然后，我们可以将这个编码后的紧凑数据发送到服务 2，通过高效的通信协议，如 TCP 或 UDP。

请注意，在前面的例子中，我们将协议缓冲区描述为服务内部。这是因为协议缓冲区是作为软件库提供的，我们可以导入并包含在我们的代码中。有许多编程语言的协议缓冲区包（Go、Java、C#、C++、Ruby、Python 等）。

协议缓冲区的工作方式如下：

1.  您在一个特殊的文件中定义您的数据，称为`proto`文件。

1.  您使用一个名为协议缓冲区编译器的软件来将 proto 文件编译成您选择的编程语言的代码文件。

1.  您使用生成的代码文件与您选择的编程语言的协议缓冲区软件包结合起来构建您的软件。

这就是协议缓冲区的要点。要更深入地了解协议缓冲区，请访问[`developers.google.com/protocol-buffers/`](https://developers.google.com/protocol-buffers/)，那里有很好的文档可以帮助您开始使用这项技术。

目前有两个常用的协议缓冲区版本：协议缓冲区 2 和协议缓冲区 3。当前在线可用的大部分培训资源都覆盖了最新版本，协议缓冲区 3。如果您正在寻找协议缓冲区版本 2 的资源，您可以在我的网站上查看这篇文章[`www.minaandrawos.com/2014/05/27/practical-guide-protocol-buffers-protobuf-go-golang/`](http://www.minaandrawos.com/2014/05/27/practical-guide-protocol-buffers-protobuf-go-golang/)。

# GRPC

协议缓冲区技术缺少的一个关键特性是通信部分。协议缓冲区擅长将数据编码和序列化为紧凑形式，以便与其他微服务共享。然而，当协议缓冲区的概念最初被构想时，只考虑了序列化，而没有考虑实际将数据发送到其他地方的部分。因此，开发人员过去常常需要自己动手实现 TCP 或 UDP 应用层来在服务之间交换编码数据。然而，如果我们没有时间和精力来担心一个高效的通信层呢？这就是 GRPC 的作用。

GRPC 可以简单地描述为在协议缓冲区之上加上一个 RPC 层。**远程过程调用**（**RPC**）层是一种软件层，允许不同的软件部分，如微服务，通过高效的通信协议（如 TCP）进行交互。使用 GRPC，您的微服务可以通过协议缓冲区版本 3 序列化您的结构化数据，然后能够与其他微服务通信，而无需担心实现通信层。

如果您的应用程序架构需要微服务之间的高效快速交互，同时又不能使用消息队列或 Web API，那么请考虑在下一个应用程序中使用 GRPC。

要开始使用 GRPC，请访问[`grpc.io/`](https://grpc.io/)。与协议缓冲区类似，GRPC 支持多种编程语言。

# 更多关于 AWS

在本书中，我们专门介绍了 AWS 基础知识的两章内容，重点介绍了如何编写能够轻松适应亚马逊云的 Go 微服务。然而，AWS 是一个非常深入的话题，值得一整本书来覆盖，而不仅仅是几章。在本节中，我们将简要介绍一些有用的 AWS 技术，这些技术我们在本书中没有涉及到。您可以将以下部分作为学习 AWS 的下一步的介绍。

# DynamoDB 流

在第八章中，*AWS II - S3、SQS、API Gateway 和 DynamoDB*，我们介绍了流行的 AWS DynamoDB 服务。我们了解了 DynamoDB 是什么，它如何对数据进行建模，以及如何编写能够利用 DynamoDB 功能的 Go 应用程序。

在本书中，有一个强大的 DynamoDB 功能我们没有机会介绍，那就是 DynamoDB 流。DynamoDB 流允许我们捕获 DynamoDB 表中项目发生的更改，同时发生更改。实际上，这意味着我们可以实时地对数据库中发生的数据更改做出反应。和往常一样，让我们举个例子来巩固其含义。

假设我们正在构建云原生分布式微服务应用程序，为大型多人游戏提供支持。假设我们使用 DynamoDB 作为应用程序的数据库后端，并且我们的某个微服务向数据库添加了新玩家。如果我们在应用程序中使用 DynamoDB 流，其他感兴趣的微服务将能够在新玩家添加后不久捕获新玩家的信息。这使得其他微服务可以根据这些新信息采取相应的行动。例如，如果其中一个其他微服务负责在游戏地图中定位玩家，它将把新玩家附加到游戏地图上的起始位置。

DynamoDB 流的工作方式很简单。它们按顺序捕获发生在 DynamoDB 表项上的更改。信息被存储在一个长达 24 小时的日志中。我们编写的其他应用程序可以访问此日志并捕获数据更改。

换句话说，如果一个项目被创建、删除或更新，DynamoDB 流将存储项目的主键和发生的数据修改。

需要在需要监控的表上启用 DynamoDB 流。如果由于任何原因，表不再需要监控，我们也可以在现有表上禁用 DynamoDB 流。DynamoDB 流与 DynamoDB 表并行操作，这基本上意味着使用它们不会对性能产生影响。

要开始使用 DynamoDB 流，请查看[`docs.aws.amazon.com/amazondynamodb/latest/developerguide/Streams.html`](http://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Streams.html)。

要开始使用 Go 编程语言中的 DynamoDB 流支持，请查看[`docs.aws.amazon.com/sdk-for-go/api/service/dynamodbstreams/`](https://docs.aws.amazon.com/sdk-for-go/api/service/dynamodbstreams/)。

# AWS 上的自动扩展

由于 AWS 从一开始就设计用于与大规模分布式微服务应用程序一起使用，AWS 具有内置功能，允许这些大型应用程序的开发人员在云中自动扩展其应用程序，尽可能少地进行手动干预。

在 AWS 的世界中，自动扩展这个词有三个主要含义：

+   能够自动替换不健康的应用程序或不良的 EC2 实例，无需您的干预。

+   能够自动创建新的 EC2 实例来处理微服务应用程序的增加负载，无需您的干预。然后，能够在应用程序负载减少时关闭 EC2 实例。

+   当应用程序负载增加时，自动增加可用于应用程序的云服务资源的能力。AWS 云资源不仅限于 EC2。根据您的需求，可以自动增加或减少的云服务资源的一个示例是 DynamoDB 读取和写入吞吐量。

为了满足自动缩放的广泛定义，AWS 自动缩放服务提供了三个主要功能：

+   EC2 实例的车队管理：此功能允许您监视运行中的 EC2 实例的健康状况，自动替换不良实例而无需手动干预，并在配置了多个区域时在多个区域之间平衡 Ec2 实例。

+   动态缩放：此功能允许您首先配置跟踪策略，以调整应用程序的负载量。例如，监视 CPU 利用率或捕获传入请求的数量。然后，动态缩放功能可以根据您配置的目标限制自动添加或删除 EC2 实例。

+   应用程序自动缩放：此功能允许您根据应用程序的需求动态扩展超出 EC2 的 AWS 服务资源。

要开始使用 AWS 自动缩放服务，请访问[`aws.amazon.com/autoscaling/`](https://aws.amazon.com/autoscaling/)。

# 亚马逊关系数据库服务

在第八章中，*AWS II - S3、SQS、API Gateway 和 DynamoDB*，当我们涵盖 AWS 世界中的数据库服务时，我们专门涵盖了 DynamoDB。 DynamoDB 是亚马逊在 AWS 上提供的托管 NoSQL 数据库服务。如果您对数据库引擎有足够的技术专长，您可能会问一个显而易见的问题：关系数据库呢？难道也不应该有一个托管的 AWS 服务吗？

上述两个问题的答案是肯定的，它被称为 Amazon 关系数据库服务（RDS）。 AWS RDS 允许开发人员轻松在云上配置、操作、扩展和部署关系数据库引擎。

Amazon RDS 支持许多开发人员使用和喜爱的知名关系数据库引擎。这包括 PostgreSQL、MySQL、MariaDB、Oracle 和 Microsoft SQL Server。除了 RDS，亚马逊还提供一个名为数据库迁移服务的服务，允许您轻松地将现有数据库迁移到 Amazon RDS 或复制到 Amazon RDS。

要开始使用 AWS RDS，请访问[`aws.amazon.com/rds/`](https://aws.amazon.com/rds/)。要构建能够与 RDS 交互的 Go 应用程序，请访问[`docs.aws.amazon.com/sdk-for-go/api/service/rds/`](https://docs.aws.amazon.com/sdk-for-go/api/service/rds/)。

# 其他云提供商

到目前为止，我们已经专注于 AWS 作为云提供商。当然，还有其他提供商提供类似的服务，其中最大的两个是微软 Azure 云和谷歌云平台。除此之外，还有许多其他提供商也提供基于开源平台 OpenStack 的 IaaS 解决方案。

所有云提供商都采用类似的概念，因此如果您对其中一个有经验，您可能会在其他云提供商中找到自己的路。出于这个原因，我们决定不在本书中深入涵盖它们中的每一个，而是专注于 AWS，并简要展望其他提供商以及它们的不同之处。

# 微软 Azure

您可以在[`azure.microsoft.com/en-us/free/`](https://azure.microsoft.com/en-us/free/)上注册 Azure 云。与 AWS 一样，Azure 提供多个区域和可用性区域，您可以在其中运行您的服务。此外，大多数 Azure 核心服务的工作方式类似于 AWS，尽管它们通常被命名为不同的名称：

+   管理虚拟机的服务（在 AWS 术语中为 EC2）就是**虚拟机**。创建虚拟机时，您需要选择一个镜像（支持 Linux 和 Windows 镜像），提供一个 SSH 公钥，并选择一个机器大小。其他核心概念的命名方式类似。您可以使用**网络安全组**配置网络访问规则，使用**Azure 负载均衡器**（在 AWS 中称为弹性负载均衡器）负载平衡流量，并使用**VM 规模集**管理自动扩展。

+   关系型数据库（由 AWS 的关系数据库服务管理）由**Azure SQL 数据库**管理。但是，在撰写本书时，仅支持 Microsoft SQL 数据库。对 MySQL 和 PostgreSQL 数据库的支持仅作为预览服务提供。

+   类似于 DynamoDB 的 NoSQL 数据库以**Azure Cosmos DB**的形式提供。

+   提供类似于简单队列服务的消息队列服务的是**队列存储**服务。

+   可以使用**应用程序网关**访问您的服务提供的 API。

要从 Go 应用程序中使用 Azure 服务，可以使用**Azure SDK for Go**，可在[`github.com/Azure/azure-sdk-for-go`](https://github.com/Azure/azure-sdk-for-go)上获得。您可以使用通常的`go get`命令进行安装：

```go
$ go get -u github.com/Azure/azure-sdk-for-go/...
```

Azure SDK for Go 目前仍在积极开发中，应谨慎使用。为了不受 SDK 中的任何重大更改的影响，请确保使用依赖管理工具（如*Glide*）将此库的一个版本放入您的*vendor/directory*中（正如您在第九章中学到的，*持续交付*）。

# Google Cloud Platform

**Google Cloud Platform**（**GCP**）是 Google 提供的 IaaS。您可以在[`console.cloud.google.com/freetrial`](https://console.cloud.google.com/freetrial)上注册。与 Azure 云一样，您会发现许多核心功能，尽管名称不同：

+   您可以使用**Google 计算引擎**管理虚拟实例。与往常一样，每个实例都是从一个镜像、一个选择的机器类型和一个 SSH 公钥创建的。您可以使用**防火墙规则**而不是安全组，并且自动缩放组称为**托管实例组**。

+   **Cloud SQL**服务提供关系型数据库。GCP 支持 MySQL 和 PostgreSQL 实例。

+   对于 NoSQL 数据库，您可以使用**Cloud Datastore**服务。

+   **Cloud Pub/Sub**服务提供了实现复杂的发布/订阅架构的可能性（事实上，超越了 AWS 提供的 SQS 的可能性）。

由于两者都来自 Google，可以毫不夸张地说 GCP 和 Go 是密不可分的（双关语）。您可以通过通常的`go get`命令安装 Go SDK：

```go
$ go get -u cloud.google.com/go
```

# OpenStack

还有许多云提供商在开源云管理软件 OpenStack（[`www.openstack.org`](https://www.openstack.org)）上构建其产品。OpenStack 是一个高度模块化的软件，基于它构建的云可能在设置上有很大差异，因此很难对它们做出普遍有效的陈述。典型的 OpenStack 安装可能包括以下服务：

+   Nova 管理虚拟机实例，Neutron 管理网络。在管理控制台中，您会在“实例”和“网络”标签下找到这些功能。

+   **Zun**和**Kuryr**管理容器。由于这些组件相对较新，可能更常见的是在 OpenStack 云中找到托管的 Kubernetes 集群。

+   **Trove**为关系型和非关系型数据库（如 MySQL 或 MongoDB）提供数据库服务。

+   **Zaqar**提供类似于 SQS 的消息服务。

如果您想从 Go 应用程序访问 OpenStack 功能，则有多个库可供选择。首先，有官方客户端库 - [github.com/openstack/golang-client](http://github.com/openstack/golang-client) - 但目前尚不建议用于生产。在撰写本书时，OpenStack 的最成熟的 Go 客户端库是[github.com/gophercloud/gophercloud](http://github.com/openstack/golang-client)库。

# 在云中运行容器

在第六章中，*在容器中部署您的应用程序*，我们深入了解了如何使用现代容器技术部署 Go 应用程序。当涉及将这些容器部署到云环境时，您有多种不同的方法可以做到这一点。

部署容器化应用程序的一种可能性是使用诸如**Kubernetes**之类的编排引擎。当您使用 Microsoft Azure 云或 Google Cloud Platform 时，这尤其容易。这两个提供商都提供 Kubernetes 作为托管服务，尽管不是以这个名称; 寻找**Azure 容器服务**（**AKS**）或**Google 容器引擎**（**GKE**）。

尽管 AWS 不提供托管的 Kubernetes 服务，但他们有一个类似的服务称为**EC2 容器服务**（**ECS**）。由于 ECS 是 AWS 独家提供的服务，它与其他 AWS 核心服务紧密集成，这既是优势也是劣势。当然，您可以使用在 VM、网络和存储形式提供的构建块在 AWS 上设置自己的 Kubernetes 集群。这是非常复杂的工作，但不要绝望。您可以使用第三方工具自动在 AWS 上设置 Kubernetes 集群。其中一个工具是**kops**。

您可以在[`github.com/kubernetes/kops`](https://github.com/kubernetes/kops)下载 kops。之后，请按照 AWS 的设置说明进行设置，您可以在项目文档中找到[`github.com/kubernetes/kops/blob/master/docs/aws.md`](https://github.com/kubernetes/kops/blob/master/docs/aws.md)。

Kops 本身也是用 Go 编写的，并使用了您在第七章中已经遇到的 AWS SDK。看一下源代码，看看 AWS 客户端库的一些非常复杂的用法的真实例子。

# 无服务器架构

在使用传统的基础设施即服务时，您将获得一些虚拟机以及相应的基础设施（如存储和网络）。通常需要自己操作在这些虚拟机中运行的所有内容。这通常意味着不仅是您编译的应用程序，还包括整个操作系统，包括每个完整的 Linux（或 Windows）系统的内核和系统服务。您还需要负责基础设施的容量规划（这意味着估算应用程序的资源需求并为自动扩展组定义合理的边界）。

所有这些都意味着**操作开销**会让您无法专注于实际工作，也就是构建和部署推动业务的软件。为了减少这种开销，您可以使用平台即服务（PaaS）而不是基础设施即服务（IaaS）。一种常见的 PaaS 托管形式是使用容器技术，开发人员只需提供一个容器镜像，提供商负责运行（和可选地扩展）应用程序，并管理底层基础设施。典型的基于容器的 PaaS 提供包括 AWS 的 EC2 容器服务或任何 Kubernetes 集群，例如 Azure 容器服务或 Google 容器引擎。非基于容器的 PaaS 提供可能包括 AWS Elastic Beanstalk 或 Google App Engine。

最近，又出现了另一种方法，旨在消除 PaaS 提供的操作开销：**无服务器计算**。当然，这个名字是非常误导的，因为在无服务器架构上运行的应用程序显然仍然需要服务器。关键的区别在于这些服务器的存在完全对开发人员隐藏。开发人员只提供要执行的应用程序，提供商负责为该应用程序提供基础设施，并部署和运行它。这种方法与微服务架构很搭配，因为部署使用 web 服务、消息队列或其他方式相互通信的小代码片段变得非常容易。在极端情况下，这经常导致单个函数被部署为服务，从而产生无服务器计算的替代术语：**函数即服务**（**FaaS**）。

许多云服务提供商作为其服务的一部分提供 FaaS 功能，其中最突出的例子是**AWS Lambda**。在撰写本书时，AWS Lambda 并不正式支持 Go 作为编程语言（支持的语言包括 JavaScript、Python、Java 和 C#），而运行 Go 函数只能使用第三方包装器，例如[`github.com/eawsy/aws-lambda-go`](https://github.com/eawsy/aws-lambda-go)。

其他云服务提供商提供类似的服务。Azure 提供**Azure Functions**（支持 JavaScript、C#、F#、PHP、Bash、Batch 和 PowerShell），GCP 提供**Cloud Functions**作为 Beta 产品（仅支持 JavaScript）。如果您正在运行 Kubernetes 集群，可以使用 Fission 框架（[`github.com/fission/fission`](https://github.com/fission/fission)）来运行自己的 FaaS 平台（甚至支持 Go）。然而，Fission 是一个处于早期 alpha 开发阶段的产品，目前还不建议用于生产环境。

您可能已经注意到，流行的 FaaS 提供中对 Go 语言的支持还不够广泛。然而，鉴于 Go 作为一种编程语言和无服务器架构的流行，还不是所有的希望都已经失去。

# 总结

到此，我们的书就要结束了。到目前为止，您应该已经掌握了足够的知识，可以构建复杂的云原生微服务应用程序，这些应用程序具有弹性、分布式和可扩展性。通过本章，您还应该有了下一步如何将您新获得的知识提升到更高水平的想法。我们感谢您给我们提供机会，引导您完成这次学习之旅，并期待成为您未来旅程的一部分。
