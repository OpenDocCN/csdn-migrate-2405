# DevOps 2.5 工具包（二）

> 原文：[`zh.annas-archive.org/md5/E695B8200F27D70136CB7C8920C8BCB0`](https://zh.annas-archive.org/md5/E695B8200F27D70136CB7C8920C8BCB0)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：通过指标和警报发现的问题调试

当你排除了不可能的，无论剩下什么，无论多么不可能，都必须是真相。

- *斯波克*

到目前为止，我们已经探讨了如何收集指标以及如何创建警报，以便在出现问题时通知我们。我们还学会了如何查询指标并搜索我们在尝试找到问题原因时可能需要的信息。我们将在此基础上继续，并尝试调试一个模拟的问题。

仅仅说一个应用程序工作不正常是不够的。我们应该更加精确。我们的目标是不仅能够准确定位哪个应用程序出现故障，还能够确定是其中的哪个部分出了问题。我们应该能够指责特定的功能、方法、请求路径等等。我们在检测应用程序的哪个部分导致问题时越精确，我们就越快地找到问题的原因。因此，通过新版本的发布（热修复）、扩展或其他手段修复问题应该更容易更快。

让我们开始吧。在模拟需要解决的问题之前，我们需要一个集群（除非您已经有一个）。

# 创建一个集群

`vfarcic/k8s-specs` ([`github.com/vfarcic/k8s-specs`](https://github.com/vfarcic/k8s-specs)) 仓库将继续是我们用于示例的 Kubernetes 定义的来源。我们将确保通过拉取最新版本使其保持最新。

本章中的所有命令都可以在`04-instrument.sh` ([`gist.github.com/vfarcic/851b37be06bb7652e55529fcb28d2c16`](https://gist.github.com/vfarcic/851b37be06bb7652e55529fcb28d2c16)) Gist 中找到。就像上一章一样，它不仅包含命令，还包括 Prometheus 的表达式。它们都被注释了（用`#`）。如果您打算从 Gist 中复制和粘贴表达式，请排除注释。每个表达式顶部都有`# Prometheus expression`的注释，以帮助您识别它。

```
 1  cd k8s-specs
 2
 3  git pull
```

鉴于我们已经学会了如何安装一个完全可操作的 Prometheus 和其图表中的其他工具，并且我们将继续使用它们，我将其移至 Gists。接下来的内容是我们在上一章中使用的内容的副本，还增加了环境变量 `PROM_ADDR` 和 `AM_ADDR`，以及安装 **Prometheus Chart** 的步骤。请创建一个符合（或超出）下面 Gists 中指定要求的集群，除非您已经有一个满足这些要求的集群。

+   `gke-instrument.sh`：**GKE** 配置有 3 个 n1-standard-1 工作节点，**nginx Ingress**，**tiller**，**Prometheus** 图表，以及环境变量 **LB_IP**，**PROM_ADDR** 和 **AM_ADDR** ([`gist.github.com/675f4b3ee2c55ee718cf132e71e04c6e`](https://gist.github.com/675f4b3ee2c55ee718cf132e71e04c6e))。

+   `eks-instrument.sh`：**EKS** 配置有 3 个 t2.small 工作节点，**nginx Ingress**，**tiller**，**Metrics Server**，**Prometheus** 图表，以及环境变量 **LB_IP**，**PROM_ADDR** 和 **AM_ADDR** ([`gist.github.com/70a14c8f15c7ffa533ea7feb75341545`](https://gist.github.com/70a14c8f15c7ffa533ea7feb75341545))。

+   `aks-instrument.sh`：**AKS** 配置有 3 个 Standard_B2s 工作节点，**nginx Ingress**，**tiller**，**Prometheus** 图表，以及环境变量 **LB_IP**，**PROM_ADDR** 和 **AM_ADDR** ([`gist.github.com/65a0d5834c9e20ebf1b99225fba0d339`](https://gist.github.com/65a0d5834c9e20ebf1b99225fba0d339))。

+   `docker-instrument.sh`：**Docker for Desktop** 配置有 **2 个 CPU**，**3 GB RAM**，**nginx Ingress**，**tiller**，**Metrics Server**，**Prometheus** 图表，以及环境变量 **LB_IP**，**PROM_ADDR** 和 **AM_ADDR** ([`gist.github.com/1dddcae847e97219ab75f936d93451c2`](https://gist.github.com/1dddcae847e97219ab75f936d93451c2))。

+   `minikube-instrument.sh`：**minikube** 配置有 **2 个 CPU**，**3 GB RAM**，启用了 **ingress, storage-provisioner**，**default-storageclass** 和 **metrics-server** 插件，**tiller**，**Prometheus** 图表，以及环境变量 **LB_IP**，**PROM_ADDR** 和 **AM_ADDR** ([`gist.github.com/779fae2ae374cf91a5929070e47bddc8`](https://gist.github.com/779fae2ae374cf91a5929070e47bddc8))。

现在我们已经准备好面对可能需要调试的第一个模拟问题。

# 面对灾难

让我们探索一个灾难场景。坦率地说，这不会是一个真正的灾难，但它将需要我们找到解决问题的方法。

我们将从安装已经熟悉的`go-demo-5`应用程序开始。

```
 1  GD5_ADDR=go-demo-5.$LB_IP.nip.io
 2
 3  helm install \
 4      https://github.com/vfarcic/go-demo-5/releases/download/
    0.0.1/go-demo-5-0.0.1.tgz \
 5      --name go-demo-5 \
 6      --namespace go-demo-5 \
 7      --set ingress.host=$GD5_ADDR
 8
 9  kubectl -n go-demo-5 \
10      rollout status \
11      deployment go-demo-5
```

我们使用`GD5_ADDR`声明了地址，通过该地址我们将能够访问应用程序。我们在安装`go-demo-5`图表时将其用作`ingress.host`变量。为了安全起见，我们等到应用程序部署完成，从部署的角度来看，唯一剩下的就是通过发送 HTTP 请求来确认它正在运行。

```
 1  curl http://$GD5_ADDR/demo/hello
```

输出是开发人员最喜欢的消息`hello, world!`。

接下来，我们将通过发送二十个持续时间长达十秒的慢请求来模拟问题。这将是我们模拟可能需要修复的问题。

```
 1  for i in {1..20}; do
 2      DELAY=$[ $RANDOM % 10000 ]
 3      curl "http://$GD5_ADDR/demo/hello?delay=$DELAY"
 4  done
```

由于我们已经有了 Prometheus 的警报，我们应该在 Slack 上收到通知，说明应用程序太慢了。然而，许多读者可能会在同一个频道进行这些练习，并且可能不清楚消息是来自我们。相反，我们将打开 Prometheus 的警报屏幕以确认存在问题。在“真实”环境中，您不会检查 Prometheus 警报，而是等待在 Slack 上收到通知，或者您选择的其他通知工具。

```
 1  open "http://$PROM_ADDR/alerts"
```

几分钟后（不要忘记刷新屏幕），`AppTooSlow`警报应该触发，让我们知道我们的一个应用程序运行缓慢，我们应该采取措施解决问题。

忠于每章将展示不同 Kubernetes 版本的输出和截图的承诺，这次轮到 minikube 了。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-25-tk/img/fb08d36b-cba3-4acb-8385-f3836d1a1f1d.png)图 4-1：Prometheus 中一个警报处于触发状态

我们假设我们没有故意生成慢请求，所以我们将尝试找出问题所在。哪个应用程序太慢了？我们可以传递什么有用的信息给团队，以便他们尽快解决问题？

第一个逻辑调试步骤是执行与警报使用的相同表达式。请展开`AppTooSlow`警报，并单击表达式的链接。您将被重定向到已经预填充的图形屏幕。单击“执行”按钮，切换到*图形*选项卡。

从图表中我们可以看到，慢请求数量激增。警报被触发是因为不到 95%的响应在 0.25 秒内完成。根据我的图表（随后的截图），零百分比的响应在 0.25 秒内完成，换句话说，所有响应都比那慢。片刻之后，情况略有改善，只有 6%的请求很快。

总的来说，我们面临着太多请求得到缓慢响应的情况，我们应该解决这个问题。主要问题是如何找出缓慢的原因是什么？

图 4-2：百分比请求快速响应的图表

尝试执行不同的表达式。例如，我们可以输出该`ingress`（应用程序）的请求持续时间的速率。

请键入以下表达式，然后点击执行按钮。

```
 1  sum(rate(
 2      nginx_ingress_controller_request_duration_seconds_sum{
 3          ingress="go-demo-5"
 4      }[5m]
 5  )) /
 6  sum(rate(
 7      nginx_ingress_controller_request_duration_seconds_count{
 8          ingress="go-demo-5"
 9      }[5m]
10  ))
```

该图表显示了请求持续时间的历史记录，但它并没有让我们更接近揭示问题的原因，或者更准确地说，是应用程序的哪一部分慢。我们可以尝试使用其他指标，但它们或多或少同样泛泛，并且可能不会让我们有所收获。我们需要更详细的特定于应用程序的指标。我们需要来自`go-demo-5`应用程序内部的数据。

# 使用仪器提供更详细的指标

我们不应该只是说`go-demo-5`应用程序很慢。这不会为我们提供足够的信息，让我们快速检查代码以找出缓慢的确切原因。我们应该能做得更好，并推断出应用程序的哪一部分表现不佳。我们能否找出产生缓慢响应的特定路径？所有方法都一样慢吗，还是问题只限于一个？我们知道哪个函数产生缓慢吗？在这种情况下，我们应该能够回答许多类似的问题。但是，根据当前的指标，我们无法做到。它们太泛泛，通常只能告诉我们特定的 Kubernetes 资源表现不佳。我们收集的指标太广泛，无法回答特定于应用程序的问题。

到目前为止，我们探讨的指标是出口和仪器化的组合。出口负责获取现有的指标并将其转换为 Prometheus 友好格式。一个例子是 Node Exporter（[`github.com/prometheus/node_exporter`](https://github.com/prometheus/node_exporter)），它获取“标准”Linux 指标并将其转换为 Prometheus 的时间序列格式。另一个例子是 kube-state-metrics（[`github.com/kubernetes/kube-state-metrics`](https://github.com/kubernetes/kube-state-metrics)），它监听 Kube API 服务器并生成资源状态的指标。

仪器化指标已经内置到应用程序中。它们是我们应用程序代码的一个组成部分，通常通过`/metrics`端点公开。

将指标添加到应用程序的最简单方法是通过 Prometheus 客户端库之一。在撰写本文时，Go（[`github.com/prometheus/client_golang`](https://github.com/prometheus/client_golang)）、Java 和 Scala（[`github.com/prometheus/client_java`](https://github.com/prometheus/client_java)）、Python（[`github.com/prometheus/client_python`](https://github.com/prometheus/client_python)）和 Ruby（[`github.com/prometheus/client_ruby`](https://github.com/prometheus/client_ruby)）库是官方提供的。

除此之外，社区还支持 Bash ([`github.com/aecolley/client_bash`](https://github.com/aecolley/client_bash))，C++ ([`github.com/jupp0r/prometheus-cpp`](https://github.com/jupp0r/prometheus-cpp))，Common Lisp ([`github.com/deadtrickster/prometheus.cl`](https://github.com/deadtrickster/prometheus.cl))，Elixir ([`github.com/deadtrickster/prometheus.ex`](https://github.com/deadtrickster/prometheus.ex))，Erlang ([`github.com/deadtrickster/prometheus.erl`](https://github.com/deadtrickster/prometheus.erl))，Haskell ([`github.com/fimad/prometheus-haskell`](https://github.com/fimad/prometheus-haskell))，Lua for Nginx ([`github.com/knyar/nginx-lua-prometheus`](https://github.com/knyar/nginx-lua-prometheus))，Lua for Tarantool ([`github.com/tarantool/prometheus`](https://github.com/tarantool/prometheus))，.NET / C# ([`github.com/andrasm/prometheus-net`](https://github.com/andrasm/prometheus-net))，Node.js ([`github.com/siimon/prom-client`](https://github.com/siimon/prom-client))，Perl ([`metacpan.org/pod/Net::Prometheus`](https://metacpan.org/pod/Net::Prometheus))，PHP ([`github.com/Jimdo/prometheus_client_php`](https://github.com/Jimdo/prometheus_client_php))，和 Rust ([`github.com/pingcap/rust-prometheus`](https://github.com/pingcap/rust-prometheus))。即使您使用不同的语言编写代码，也可以通过以文本为基础的输出格式（[`prometheus.io/docs/instrumenting/exposition_formats/`](https://prometheus.io/docs/instrumenting/exposition_formats/)）轻松提供符合 Prometheus 的指标。

收集指标的开销应该可以忽略不计，而且由于 Prometheus 定期获取它们，输出它们的开销也应该很小。即使您选择不使用 Prometheus，或者切换到其他工具，该格式也正在成为标准，您的下一个指标收集工具很可能也会期望相同的数据。

总之，没有理由不将指标集成到您的应用程序中，正如您很快将看到的那样，它们提供了我们无法从外部获得的宝贵信息。

让我们来看一个`go-demo-5`中已经标记的指标的例子。

```
 1  open "https://github.com/vfarcic/go-demo-5/blob/master/main.go"
```

该应用程序是用 Go 语言编写的。如果这不是您选择的语言，不要担心。我们只是快速看一下一些例子，以了解仪表化背后的逻辑，而不是确切的实现。

第一个有趣的部分如下。

```
 1  ...
 2  var (
 3    histogram = prometheus.NewHistogramVec(prometheus.HistogramOpts{
 4      Subsystem: "http_server",
 5      Name:      "resp_time",
 6      Help:      "Request response time",
 7    }, []string{
 8      "service",
 9      "code",
10      "method",
11      "path",
12    })
13  )
14  ...
```

我们定义了一个包含一些选项的 Prometheus 直方图向量的变量。`Sybsystem`和`Name`形成了基本指标`http_server_resp_time`。由于它是一个直方图，最终的指标将通过添加`_bucket`、`_sum`和`_count`后缀来创建。

请参考*histogram* ([`prometheus.io/docs/concepts/metric_types/#histogram`](https://prometheus.io/docs/concepts/metric_types/#histogram)) 文档，了解有关 Prometheus 指标类型的更多信息。

最后一部分是一个字符串数组(`[]string`)，定义了我们想要添加到指标中的所有标签。在我们的情况下，这些标签是`service`、`code`、`method`和`path`。标签可以是我们需要的任何东西，只要它们提供了我们在查询这些指标时可能需要的足够信息。

兴趣点是`recordMetrics`函数。

```
 1  ...
 2  func recordMetrics(start time.Time, req *http.Request, code int) {
 3    duration := time.Since(start)
 4    histogram.With(
 5      prometheus.Labels{
 6        "service": serviceName,
 7        "code":    fmt.Sprintf("%d", code),
 8        "method":  req.Method,
 9        "path":    req.URL.Path,
10      },
11    ).Observe(duration.Seconds())
12  }
13  ...
```

我创建了一个辅助函数，可以从代码的不同位置调用。它接受`start`时间、`Request`和返回的`code`作为参数。函数本身通过将当前时间与`start`时间相减来计算`duration`。`duration`在`Observe`函数中使用，并提供指标的值。还有标签，将帮助我们在以后微调我们的表达式。

最后，我们将看一个示例，其中调用了`recordMetrics`函数。

```
 1  ...
 2  func HelloServer(w http.ResponseWriter, req *http.Request) {
 3    start := time.Now()
 4    defer func() { recordMetrics(start, req, http.StatusOK) }()
 5    ...
 6  }
 7  ...
```

`HelloServer`函数是返回您已经看到多次的`hello, world!`响应的函数。该函数的细节并不重要。在这种情况下，唯一重要的部分是`defer func() { recordMetrics(start, req, http.StatusOK) }()`这一行。在 Go 中，`defer`允许我们在它所在的函数结束时执行某些操作。在我们的情况下，这个操作是调用`recordMetrics`函数，记录请求的持续时间。换句话说，在执行离开`HelloServer`函数之前，它将通过调用`recordMetrics`函数记录持续时间。

我不会深入探讨包含仪表的代码，因为那将意味着您对 Go 背后的复杂性感兴趣，而我试图让这本书与语言无关。我会让您参考您喜欢的语言的文档和示例。相反，我们将看一下`go-demo-5`中的仪表指标的实际应用。

```
 1  kubectl -n metrics \
 2      run -it test \
 3      --image=appropriate/curl \
 4      --restart=Never \
 5      --rm \
 6      -- go-demo-5.go-demo-5:8080/metrics
```

我们创建了一个基于`appropriate/curl`镜像的 Pod，并通过使用地址`go-demo-5.go-demo-5:8080/metrics`向服务发送了一个请求。第一个`go-demo-5`是服务的名称，第二个是它所在的命名空间。结果，我们得到了该应用程序中所有可用的受监控指标的输出。我们不会逐个讨论所有这些指标，而只会讨论由`http_server_resp_time`直方图创建的指标。

输出的相关部分如下。

```
...
# HELP http_server_resp_time Request response time
# TYPE http_server_resp_time histogram
http_server_resp_time_bucket{code="200",method="GET",path="/demo/hello",service="go-demo",le="0.005"} 931
http_server_resp_time_bucket{code="200",method="GET",path="/demo/hello",service="go-demo",le="0.01"} 931
http_server_resp_time_bucket{code="200",method="GET",path="/demo/hello",service="go-demo",le="0.025"} 931
http_server_resp_time_bucket{code="200",method="GET",path="/demo/hello",service="go-demo",le="0.05"} 931
http_server_resp_time_bucket{code="200",method="GET",path="/demo/hello",service="go-demo",le="0.1"} 934
http_server_resp_time_bucket{code="200",method="GET",path="/demo/hello",service="go-demo",le="0.25"} 935
http_server_resp_time_bucket{code="200",method="GET",path="/demo/hello",service="go-demo",le="0.5"} 935
http_server_resp_time_bucket{code="200",method="GET",path="/demo/hello",service="go-demo",le="1"} 936
http_server_resp_time_bucket{code="200",method="GET",path="/demo/hello",service="go-demo",le="2.5"} 936
http_server_resp_time_bucket{code="200",method="GET",path="/demo/hello",service="go-demo",le="5"} 937
http_server_resp_time_bucket{code="200",method="GET",path="/demo/hello",service="go-demo",le="10"} 942
http_server_resp_time_bucket{code="200",method="GET",path="/demo/hello",service="go-demo",le="+Inf"} 942
http_server_resp_time_sum{code="200",method="GET",path="/demo/hello",service="go-demo"} 38.87928942600006
http_server_resp_time_count{code="200",method="GET",path="/demo/hello",service="go-demo"} 942
...
```

我们可以看到，在应用程序代码中使用的 Go 库从`http_server_resp_time`直方图中创建了相当多的指标。我们得到了每个十二个桶的指标（`http_server_resp_time_bucket`），一个持续时间的总和指标（`http_server_resp_time_sum`），以及一个计数指标（`http_server_resp_time_count`）。如果我们发出具有不同标签的请求，我们将得到更多指标。目前，这十四个指标都来自于响应 HTTP 代码`200`的请求，使用`GET`方法，发送到`/demo/hello`路径，并来自`go-demo`服务（应用程序）。如果我们创建具有不同方法（例如`POST`）或不同路径的请求，指标数量将增加。同样，如果我们在其他应用程序中实现相同的受监控指标（但具有不同的`service`标签），我们将拥有具有相同键（`http_server_resp_time`）的指标，这将提供有关多个应用程序的见解。这引发了一个问题，即我们是否应该统一所有应用程序中的指标名称，还是不统一。

我更喜欢在所有应用程序中具有相同名称的相同类型的受监控指标。例如，所有收集响应时间的指标都可以称为`http_server_resp_time`。这简化了在 Prometheus 中查询数据。与其从每个单独的应用程序中了解受监控指标，不如从一个应用程序中了解所有应用程序的知识。另一方面，我赞成让每个团队完全控制他们的应用程序。这包括决定要实现哪些指标以及如何调用它们。

总的来说，这取决于团队的结构和职责。如果一个团队完全负责他们的应用程序，并且调试特定于他们应用程序的问题，那么标准化已经被仪表化指标的名称是没有必要的。另一方面，如果监控是集中的，并且其他团队可能期望从该领域的专家那里获得帮助，那么创建命名约定是必不可少的。否则，我们可能会轻易地得到成千上万个具有不同名称和类型的指标，尽管它们大多提供相同的信息。

在本章的其余部分，我将假设我们同意在所有适用的应用程序中都有`http_server_resp_time`直方图。

现在，让我们看看如何告诉 Prometheus 它应该从`go-demo-5`应用程序中拉取指标。如果我们能告诉 Prometheus 从所有有仪表化指标的应用程序中拉取数据，那将更好。实际上，现在我想起来了，我们在上一章中还没有讨论 Prometheus 是如何发现 Node Exporter 和 Kube State Metrics 的。所以，让我们简要地通过发现过程。

一个很好的起点是 Prometheus 的目标屏幕。

```
 1  open "http://$PROM_ADDR/targets"
```

最有趣的目标组是`kubernetes-service-endpoints`。如果我们仔细看标签，我们会发现每个标签都有`kubernetes_name`，其中三个目标将其设置为`go-demo-5`。Prometheus 不知何故发现我们有该应用程序的三个副本，并且指标可以通过端口`8080`获得。如果我们进一步观察，我们会注意到`prometheus-node-exporter`也在其中，每个节点在集群中都有一个。

对于`prometheus-kube-state-metrics`也是一样的。在该组中可能还有其他应用程序。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-25-tk/img/a36dd797-57ba-4cf7-bc6c-8da9161fd59c.png)图 4-3：kubernetes-service-endpoints Prometheus 的目标

Prometheus 通过 Kubernetes 服务发现了所有目标。它从每个服务中提取了端口，并假定数据可以通过`/metrics`端点获得。因此，我们在集群中拥有的每个应用程序，只要可以通过 Kubernetes 服务访问，就会自动添加到 Prometheus 的目标`kubernetes-service-endpoints`组中。我们无需摆弄 Prometheus 的配置来将`go-demo-5`添加到其中。它只是被发现了。相当不错，不是吗？

在某些情况下，一些指标将无法访问，并且该目标将标记为红色。例如，在 minikube 中的`kube-dns`无法从 Prometheus 访问。这很常见，只要这不是我们确实需要的指标来源之一，就不必惊慌。

接下来，我们将快速查看一下我们可以使用来自`go-demo-5`的仪表化指标编写的一些表达式。

```
 1  open "http://$PROM_ADDR/graph"
```

请键入接下来的表达式，按“执行”按钮，然后切换到*图表*选项卡。

```
 1  http_server_resp_time_count
```

我们可以看到三条线对应于`go-demo-5`的三个副本。这应该不会让人感到惊讶，因为每个副本都是从应用程序的每个副本的仪表化指标中提取的。由于这些指标是只能增加的计数器，图表的线条不断上升。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-25-tk/img/17add48b-f7c5-4e29-90e6-43dcf3919682.png)图 4-4：http_server_resp_time_count 计数器的图表

这并不是很有用。如果我们对请求计数的速率感兴趣，我们会将先前的表达式包含在`rate()`函数中。我们以后会这样做。现在，我们将编写最简单的表达式，以便得到每个请求的平均响应时间。

请键入接下来的表达式，然后按“执行”按钮。

```
 1  http_server_resp_time_sum{
 2      kubernetes_name="go-demo-5"
 3  } /
 4  http_server_resp_time_count{
 5      kubernetes_name="go-demo-5"
 6  }
```

表达式本身应该很容易理解。我们将所有请求的总和除以计数。由于我们已经发现问题出现在`go-demo-5`应用程序中，我们使用`kubernetes_name`标签来限制结果。尽管这是我们集群中当前唯一运行该指标的应用程序，但习惯于这样做是个好主意，因为在将来我们将扩展到其他应用程序时，可能会有其他应用程序。

我们可以看到，平均请求持续时间在一段时间内增加，只是在稍后又接近初始值。这个峰值与我们之前发送的二十个慢请求相吻合。在我的情况下（以下是屏幕截图），峰值接近平均响应时间的 0.1 秒，然后在稍后降至大约 0.02 秒。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-25-tk/img/e4efb795-db45-4d39-87be-b5982c518722.png)图 4-5：累积平均响应时间的图表

请注意，我们刚刚执行的表达式存在严重缺陷。它显示的是累积平均响应时间，而不是显示`rate`。但是，你已经知道了。那只是对仪表度量的一个预演，而不是它的“真正”用法（很快就会出现）。

您可能会注意到，即使是峰值也非常低。它肯定比我们只通过`curl`发送二十个慢请求所期望的要低。原因在于我们不是唯一一个发出这些请求的人。`readinessProbe`和`livenessProbe`也在发送请求，并且非常快。与上一章不同的是，我们只测量通过 Ingress 进入的请求，这一次我们捕获了进入应用程序的所有请求，包括健康检查。

现在我们已经看到了在我们的`go-demo-5`应用程序内部生成的`http_server_resp_time`度量标准的一些示例，我们可以利用这些知识来尝试调试导致我们走向仪表化的模拟问题。

# 使用内部度量标准来调试潜在问题

我们将重新发送慢响应的请求，以便我们回到开始本章的同一点。

```
 1  for i in {1..20}; do
 2      DELAY=$[ $RANDOM % 10000 ]
 3      curl "http://$GD5_ADDR/demo/hello?delay=$DELAY"
 4  done
 5
 6  open "http://$PROM_ADDR/alerts"
```

我们发送了二十个请求，这些请求将产生随机持续时间的响应（最长十秒）。随后，我们打开了 Prometheus 的警报屏幕。

一段时间后，`AppTooSlow`警报应该会触发（记得刷新你的屏幕），我们有一个（模拟的）需要解决的问题。在我们开始惊慌和匆忙行事之前，我们将尝试找出问题的原因。

请点击`AppTooSlow`警报的表达式。

我们被重定向到具有警报预填表达式的图形屏幕。请随意点击表达式按钮，即使它不会提供任何额外的信息，除了应用程序一开始很快，然后因某种莫名其妙的原因变慢。

您将无法从该表达式中收集更多详细信息。您将不知道所有方法是否都很慢，是否只有特定路径响应缓慢，也不会知道任何其他特定于应用程序的细节。简而言之，`nginx_ingress_controller_request_duration_seconds`度量标准太泛化了。它作为通知我们应用程序响应时间增加的一种方式服务得很好，但它并不提供足够关于问题原因的信息。为此，我们将切换到 Prometheus 直接从`go-demo-5`副本中检索的`http_server_resp_time`度量标准。

请键入以下表达式，然后按“执行”按钮。

```
 1  sum(rate(
 2      http_server_resp_time_bucket{
 3          le="0.1",
 4          kubernetes_name="go-demo-5"
 5      }[5m]
 6  )) /
 7  sum(rate(
 8      http_server_resp_time_count{
 9          kubernetes_name="go-demo-5"
10      }[5m]
11  ))
```

如果你还没有切换到*图表*选项卡，请切换到那里。

该表达式与我们以前使用`nginx_ingress_controller_request_duration_seconds_sum`指标时编写的查询非常相似。我们正在将 0.1 秒桶中的请求速率与所有请求的速率进行比较。

在我的案例中（随后的屏幕截图），我们可以看到快速响应的百分比下降了两次。这与我们之前发送的模拟慢请求相吻合。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-25-tk/img/ab8b8a7e-6ecd-45ec-a77a-3dd0ffd7cfdd.png)图 4-6：使用仪器化指标测量的快速请求百分比的图表

到目前为止，使用仪器化指标`http_server_resp_time_count`与`nginx_ingress_controller_request_duration_seconds_sum`相比，并没有提供任何实质性的好处。如果仅此而已，我们可以得出结论，添加仪器化是一种浪费。然而，我们还没有将标签包含在我们的表达式中。

假设我们想按`method`和`path`对请求进行分组。这可能会让我们更好地了解慢速是全局性的，还是仅限于特定类型的请求。如果是后者，我们将知道问题出在哪里，并希望能够快速找到罪魁祸首。

请键入以下表达式，然后按“执行”按钮。

```
 1  sum(rate(
 2      http_server_resp_time_bucket{
 3          le="0.1",
 4          kubernetes_name="go-demo-5"
 5      }[5m]
 6  ))
 7  by (method, path) /
 8  sum(rate(
 9      http_server_resp_time_count{
10          kubernetes_name="go-demo-5"
11      }[5m]
12  ))
13  by (method, path)
```

该表达式几乎与之前的表达式相同。唯一的区别是添加了`by (method, path)`语句。因此，我们得到了按`method`和`path`分组的快速响应百分比。

输出并不代表“真实”的使用情况。通常，我们会看到许多不同的线条，每条线代表被请求的每种方法和路径。但是，由于我们只对`/demo/hello`使用 HTTP GET 进行了请求，我们的图表有点无聊。你得想象还有许多其他线条。

通过研究图表，我们发现除了一条线（我们仍在想象许多条线）之外，其他所有线都接近于百分之百的快速响应。那条急剧下降的线应该是具有`/demo/hello`路径和`GET`方法的那条线。然而，如果这确实是一个真实的情景，我们的图表可能会有太多线条，我们可能无法轻松地加以区分。我们的表达式可能会受益于添加一个阈值。

请键入以下表达式，然后按“执行”按钮。

```
 1  sum(rate(
 2      http_server_resp_time_bucket{
 3          le="0.1",
 4          kubernetes_name="go-demo-5"
 5      }[5m]
 6  ))
 7  by (method, path) /
 8  sum(rate(
 9      http_server_resp_time_count{
10          kubernetes_name="go-demo-5"
11      }[5m]
12  ))
13  by (method, path) < 0.99
```

唯一的添加是 `<0.99` 的阈值。因此，我们的图表排除了所有结果（所有路径和方法），只留下低于百分之九十九（0.99）的结果。我们去除了所有噪音，只关注超过百分之一的所有请求缓慢的情况（或者少于百分之九十九的请求快速）。结果现在很明确。问题出在处理 `/demo/hello` 路径上的 `GET` 请求的函数中。我们通过图表下方提供的标签知道了这一点。

图 4-7：使用仪器测量的快速请求百分比的图表，限制在百分之九十九以下的结果。

现在我们几乎知道问题的确切位置，剩下的就是修复问题，将更改推送到我们的 Git 存储库，并等待我们的持续部署流程升级软件以使用新版本。

在相对较短的时间内，我们设法找到（调试）了问题，或者更准确地说，将问题缩小到代码的特定部分。

或者，也许我们发现问题不在代码中，而是我们的应用程序需要扩展。无论哪种情况，没有仪器测量的指标，我们只会知道应用程序运行缓慢，这可能意味着应用程序的任何部分都在表现不佳。仪器测量为我们提供了更详细的指标，我们用这些指标更准确地缩小范围，并减少我们通常需要找到问题并相应采取行动的时间。

通常，我们会有许多其他仪器测量指标，我们的“调试”过程会更加复杂。我们会执行其他表达式并查看不同的指标。然而，关键是我们应该将通用指标与直接来自我们应用程序的更详细的指标相结合。前一组通常用于检测是否存在问题，而后一种类型在寻找问题的原因时非常有用。这两种类型的指标在监控、警报和调试我们的集群和应用程序时都有其作用。有了仪器测量指标，我们可以获得更多特定于应用程序的细节。这使我们能够缩小问题的位置和原因。我们对问题的确切原因越有信心，我们就越能够做出反应。

# 现在呢？

我不认为我们需要很多其他的仪表化指标示例。它们与我们通过导出器收集的指标没有任何不同。我会让你开始为你的应用程序进行仪表化。从小处开始，看看哪些效果好，改进和扩展。

又一个章节完成了。销毁你的集群，开始下一个新的，或者保留它。如果你选择后者，请执行接下来的命令来移除`go-demo-5`应用程序。

```
 1  helm delete go-demo-5 --purge
 2
 3  kubectl delete ns go-demo-5
```

在你离开之前，记住接下来的要点。它总结了仪表化。

+   仪表化指标被嵌入到应用程序中。它们是我们应用程序代码的一个组成部分，通常通过`/metrics`端点公开。


# 第五章：使用自定义指标扩展 HorizontalPodAutoscaler

计算机是出色且高效的仆人，但我不愿意在它们的服务下工作。

- *斯波克*

**HorizontalPodAutoscaler**（**HPA**）的采用通常经历三个阶段。

第一阶段是*发现*。第一次我们发现它的功能时，通常会感到非常惊讶。"看这个。它可以自动扩展我们的应用程序。我不再需要担心副本的数量了。"

第二阶段是*使用*。一旦我们开始使用 HPA，我们很快意识到基于内存和 CPU 的应用程序扩展不足够。一些应用程序随着负载的增加而增加其内存和 CPU 使用率，而许多其他应用程序则没有。或者更准确地说，不成比例。对于一些应用程序，HPA 运作良好。对于许多其他应用程序，它根本不起作用，或者不够。迟早，我们需要将 HPA 的阈值扩展到不仅仅是基于内存和 CPU 的阈值。这个阶段的特点是*失望*。"这似乎是个好主意，但我们不能用它来处理我们大多数的应用程序。我们需要退回到基于指标和手动更改副本数量的警报。"

第三阶段是*重新发现*。一旦我们阅读了 HPA v2 文档（在撰写本文时仍处于测试阶段），我们就会发现它允许我们将其扩展到几乎任何类型的指标和表达式。我们可以通过适配器将 HPAs 连接到 Prometheus，或几乎任何其他工具。一旦我们掌握了这一点，我们几乎没有限制条件可以设置为自动扩展我们的应用程序的触发器。唯一的限制是我们将数据转换为 Kubernetes 自定义指标的能力。

我们的下一个目标是扩展 HorizontalPodAutoscaler 定义，以包括基于 Prometheus 中存储的数据的条件。

# 创建一个集群

`vfarcic/k8s-specs`（[`github.com/vfarcic/k8s-specs`](https://github.com/vfarcic/k8s-specs)）存储库将继续作为我们的 Kubernetes 定义的来源。我们将确保通过拉取最新版本使其保持最新。

本章中的所有命令都可以在`05-hpa-custom-metrics.sh`（[`gist.github.com/vfarcic/cc546f81e060e4f5fc5661e4fa003af7`](https://gist.github.com/vfarcic/cc546f81e060e4f5fc5661e4fa003af7)）Gist 中找到。

```
 1  cd k8s-specs
 2
 3  git pull
```

要求与上一章相同。唯一的例外是**EKS**。我们将继续为所有其他 Kubernetes 版本使用与之前相同的 Gists。

对于 EKS 用户的注意事项，尽管我们迄今为止使用的三个 t2.small 节点具有足够的内存和 CPU，但它们可能无法承载我们将创建的所有 Pod。EKS（默认情况下）使用 AWS 网络。t2.small 实例最多可以有三个网络接口，每个接口最多有四个 IPv4 地址。这意味着每个 t2.small 节点上最多可以有十二个 IPv4 地址。鉴于每个 Pod 需要有自己的地址，这意味着每个节点最多可以有十二个 Pod。在本章中，我们可能需要在整个集群中超过三十六个 Pod。我们将添加 Cluster Autoscaler（CA）到集群中，让集群在需要时扩展，而不是创建超过三个节点的集群。我们已经在之前的章节中探讨了 CA，并且设置说明现在已添加到了 Gist `eks-hpa-custom.sh` ([`gist.github.com/vfarcic/868bf70ac2946458f5485edea1f6fc4c)`](https://gist.github.com/vfarcic/868bf70ac2946458f5485edea1f6fc4c))。

请使用以下 Gist 之一创建新的集群。如果您已经有一个要用于练习的集群，请使用 Gist 来验证它是否满足所有要求。

+   `gke-instrument.sh`: **GKE** 配有 3 个 n1-standard-1 工作节点，**nginx Ingress**，**tiller**，**Prometheus** 图表，以及环境变量 **LB_IP**，**PROM_ADDR** 和 **AM_ADDR** ([`gist.github.com/vfarcic/675f4b3ee2c55ee718cf132e71e04c6e`](https://gist.github.com/vfarcic/675f4b3ee2c55ee718cf132e71e04c6e))。

+   `eks-hpa-custom.sh`: **EKS** 配有 3 个 t2.small 工作节点，**nginx Ingress**，**tiller**，**Metrics Server**，**Prometheus** 图表，环境变量 **LB_IP**，**PROM_ADDR** 和 **AM_ADDR**，以及 **Cluster Autoscaler** ([`gist.github.com/vfarcic/868bf70ac2946458f5485edea1f6fc4c`](https://gist.github.com/vfarcic/868bf70ac2946458f5485edea1f6fc4c))。

+   `aks-instrument.sh`: **AKS** 配有 3 个 Standard_B2s 工作节点，**nginx Ingress**，**tiller**，**Prometheus** 图表，以及环境变量 **LB_IP**，**PROM_ADDR** 和 **AM_ADDR** ([`gist.github.com/vfarcic/65a0d5834c9e20ebf1b99225fba0d339`](https://gist.github.com/vfarcic/65a0d5834c9e20ebf1b99225fba0d339))。

+   `docker-instrument.sh`：**Docker for Desktop**，带有**2 个 CPU**，**3GB RAM**，**nginx Ingress**，**tiller**，**Metrics Server**，**Prometheus**图表，和环境变量**LB_IP**，**PROM_ADDR**，和**AM_ADDR**（[`gist.github.com/vfarcic/1dddcae847e97219ab75f936d93451c2`](https://gist.github.com/vfarcic/1dddcae847e97219ab75f936d93451c2)）。

+   `minikube-instrument.sh`：**Minikube**，带有**2 个 CPU**，**3GB RAM**，**ingress**，**storage-provisioner**，**default-storageclass**，和**metrics-server**插件已启用，**tiller**，**Prometheus**图表，和环境变量**LB_IP**，**PROM_ADDR**，和**AM_ADDR**（[`gist.github.com/vfarcic/779fae2ae374cf91a5929070e47bddc8`](https://gist.github.com/vfarcic/779fae2ae374cf91a5929070e47bddc8)）。

现在我们准备扩展我们对 HPA 的使用。但在我们这样做之前，让我们简要地探索（再次）HPA 如何开箱即用。

# 在没有度量适配器的情况下使用 HorizontalPodAutoscaler

如果我们不创建度量适配器，度量聚合器只知道与容器和节点相关的 CPU 和内存使用情况。更复杂的是，这些信息仅限于最近几分钟。由于 HPA 只关心 Pod 和其中的容器，我们只能使用两个指标。当我们创建 HPA 时，如果构成这些 Pod 的容器的内存或 CPU 消耗超过或低于预定义的阈值，它将扩展或缩减我们的 Pods。

Metrics Server 定期从运行在工作节点内的 Kubelet 获取信息（CPU 和内存）。

这些指标被传递给度量聚合器，但在这种情况下，度量聚合器并没有增加任何额外的价值。从那里开始，HPA 定期查询度量聚合器中的数据（通过其 API 端点）。当 HPA 中定义的目标值与实际值存在差异时，HPA 将操纵部署或 StatefulSet 的副本数量。正如我们已经知道的那样，对这些控制器的任何更改都会导致通过创建和操作 ReplicaSets 执行滚动更新，从而创建和删除 Pods，这些 Pods 由运行在调度了 Pod 的节点上的 Kubelet 转换为容器。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-25-tk/img/d9f95b8d-7de9-4e19-86e5-702c61885999.png)图 5-1：开箱即用设置的 HPA（箭头显示数据流向）

从功能上讲，我们刚刚描述的流程运行良好。唯一的问题是指标聚合器中可用的数据。它仅限于内存和 CPU。往往这是不够的。因此，我们不需要改变流程，而是要扩展可用于 HPA 的数据。我们可以通过指标适配器来实现这一点。

# 探索 Prometheus 适配器

鉴于我们希望通过指标 API 扩展可用的指标，并且 Kubernetes 允许我们通过其*自定义指标 API*（[`github.com/kubernetes/metrics/tree/master/pkg/apis/custom_metrics`](https://github.com/kubernetes/metrics/tree/master/pkg/apis/custom_metrics)）来实现这一点，实现我们目标的一个选项可能是创建我们自己的适配器。

根据我们存储指标的应用程序（DB），这可能是一个不错的选择。但是，鉴于重新发明轮子是毫无意义的，我们的第一步应该是寻找解决方案。如果有人已经创建了一个适合我们需求的适配器，那么采用它而不是自己创建一个新的适配器是有意义的。即使我们选择了只提供部分我们寻找的功能的东西，也比从头开始更容易（并向项目做出贡献），而不是从零开始。

鉴于我们的指标存储在 Prometheus 中，我们需要一个指标适配器，它将能够从中获取数据。由于 Prometheus 非常受欢迎并被社区采用，已经有一个项目在等待我们使用。它被称为*用于 Prometheus 的 Kubernetes 自定义指标适配器*。它是使用 Prometheus 作为数据源的 Kubernetes 自定义指标 API 的实现。

鉴于我们已经采用 Helm 进行所有安装，我们将使用它来安装适配器。

```
 1  helm install \
 2      stable/prometheus-adapter \
 3      --name prometheus-adapter \
 4      --version v0.5.0 \
 5      --namespace metrics \
 6      --set image.tag=v0.5.0 \
 7      --set metricsRelistInterval=90s \
 8      --set prometheus.url=http://prometheus-server.metrics.svc \
 9      --set prometheus.port=80
10
11  kubectl -n metrics \
12      rollout status \
13      deployment prometheus-adapter
```

我们从`stable`存储库安装了`prometheus-adapter` Helm Chart。资源被创建在`metrics`命名空间中，`image.tag`设置为`v0.3.0`。

我们将`metricsRelistInterval`从默认值`30s`更改为`90s`。这是适配器用来从 Prometheus 获取指标的间隔。由于我们的 Prometheus 设置每 60 秒从其目标获取指标，我们必须将适配器的间隔设置为高于该值。否则，适配器的频率将高于 Prometheus 的拉取频率，我们将有一些迭代没有新数据。

最后两个参数指定了适配器可以访问 Prometheus API 的 URL 和端口。在我们的情况下，URL 设置为通过 Prometheus 的服务。

请访问*Prometheus Adapter Chart README*（[`github.com/helm/charts/tree/master/stable/prometheus-adapter`](https://github.com/helm/charts/tree/master/stable/prometheus-adapter)）获取有关所有可以设置以自定义安装的值的更多信息。

最后，我们等待`prometheus-adapter`部署完成。

如果一切按预期运行，我们应该能够查询 Kubernetes 的自定义指标 API，并检索通过适配器提供的一些 Prometheus 数据。

```
 1  kubectl get --raw \
 2      "/apis/custom.metrics.k8s.io/v1beta1" \
 3      | jq "."
```

鉴于每个章节都将呈现不同的 Kubernetes 版本的特点，并且 AWS 还没有轮到，所有输出都来自 EKS。根据您使用的平台不同，您的输出可能略有不同。

查询自定义指标的输出的前几个条目如下。

```
{
  "kind": "APIResourceList",
  "apiVersion": "v1",
  "groupVersion": "custom.metrics.k8s.io/v1beta1",
  "resources": [
    {
      "name": "namespaces/memory_max_usage_bytes",
      "singularName": "",
      "namespaced": false,
      "kind": "MetricValueList",
      "verbs": [
        "get"
      ]
    },
    {
      "name": "jobs.batch/kube_deployment_spec_strategy_rollingupdate_max_unavailable",
      "singularName": "",
      "namespaced": true,
      "kind": "MetricValueList",
      "verbs": [
        "get"
      ]
    },
    ...
```

透过适配器可用的自定义指标列表很长，我们可能会被迫认为它包含了 Prometheus 中存储的所有指标。我们将在以后发现这是否属实。现在，我们将专注于可能需要的与`go-demo-5`部署绑定的 HPA 的指标。毕竟，为自动扩展提供指标是适配器的主要功能，如果不是唯一功能的话。

从现在开始，Metrics Aggregator 不仅包含来自度量服务器的数据，还包括来自 Prometheus Adapter 的数据，后者又从 Prometheus 服务器获取度量。我们还需要确认通过适配器获取的数据是否足够，以及 HPA 是否能够使用自定义指标。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-25-tk/img/2caa17d4-543c-4aef-bc51-67282a29270b.png)图 5-2：使用 Prometheus Adapter 的自定义指标（箭头显示数据流向）

在我们深入了解适配器之前，我们将为`go-demo-5`应用程序定义我们的目标。

我们应该能够根据内存和 CPU 使用率以及通过 Ingress 进入或通过仪表化指标观察到的请求数量来扩展 Pods。我们可以添加许多其他标准，但作为学习经验，这些应该足够了。我们已经知道如何配置 HPA 以根据 CPU 和内存进行扩展，所以我们的任务是通过请求计数器来扩展它。这样，我们将能够设置规则，当应用程序接收到太多请求时增加副本的数量，以及在流量减少时减少副本的数量。

由于我们想要扩展与`go-demo-5`相关的 HPA，我们的下一步是安装应用程序。

```
 1  GD5_ADDR=go-demo-5.$LB_IP.nip.io
 2
 3  helm install \
 4    https://github.com/vfarcic/go-demo-5/releases/download/
    0.0.1/go-demo-5-0.0.1.tgz \
 5      --name go-demo-5 \
 6      --namespace go-demo-5 \
 7      --set ingress.host=$GD5_ADDR
 8
 9  kubectl -n go-demo-5 \
10      rollout status \
11      deployment go-demo-5
```

我们定义了应用程序的地址，安装了图表，并等待部署完成。

EKS 用户注意：如果收到了`error: deployment "go-demo-5" exceeded its progress deadline`的消息，集群可能正在自动扩展以适应所有 Pod 和 PersistentVolumes 的区域。这可能比`progress deadline`需要更长的时间。在这种情况下，请等待片刻并重复`rollout`命令。

接下来，我们将通过其 Ingress 资源向应用程序发送一百个请求，以生成一些流量。

```
 1  for i in {1..100}; do
 2      curl "http://$GD5_ADDR/demo/hello"
 3  done
```

现在我们已经生成了一些流量，我们可以尝试找到一个指标，帮助我们计算通过 Ingress 传递了多少请求。由于我们已经知道（从之前的章节中）`nginx_ingress_controller_requests`提供了通过 Ingress 进入的请求数量，我们应该检查它是否现在作为自定义指标可用。

```
 1  kubectl get --raw \
 2      "/apis/custom.metrics.k8s.io/v1beta1" \
 3      | jq '.resources[]
 4      | select(.name
 5      | contains("nginx_ingress_controller_requests"))'
```

我们向`/apis/custom.metrics.k8s.io/v1beta1`发送了一个请求。但是，正如你已经看到的，单独这样做会返回所有的指标，而我们只对其中一个感兴趣。这就是为什么我们将输出导入到`jq`并使用它的过滤器来检索只包含`nginx_ingress_controller_requests`作为`name`的条目。

如果你收到了空的输出，请等待片刻，直到适配器从 Prometheus 中拉取指标（它每九十秒执行一次），然后重新执行命令。

输出如下。

```
{
  "name": "ingresses.extensions/nginx_ingress_controller_requests",
  "singularName": "",
  "namespaced": true,
  "kind": "MetricValueList",
  "verbs": [
    "get"
  ]
}
{
  "name": "jobs.batch/nginx_ingress_controller_requests",
  "singularName": "",
  "namespaced": true,
  "kind": "MetricValueList",
  "verbs": [
    "get"
  ]
}
{
  "name": "namespaces/nginx_ingress_controller_requests",
  "singularName": "",
  "namespaced": false,
  "kind": "MetricValueList",
  "verbs": [
    "get"
  ]
}
```

我们得到了三个结果。每个的名称由资源类型和指标名称组成。我们将丢弃与`jobs.batch`和`namespaces`相关的内容，并集中在与`ingresses.extensions`相关的指标上，因为它提供了我们需要的信息。我们可以看到它是`namespaced`，这意味着指标在其他方面是由其来源的命名空间分隔的。`kind`和`verbs`（几乎）总是相同的，浏览它们并没有太大的价值。

`ingresses.extensions/nginx_ingress_controller_requests`的主要问题是它提供了 Ingress 资源的请求数量。我们无法将其作为 HPA 标准的当前形式使用。相反，我们应该将请求数量除以副本数量。这将给我们每个副本的平均请求数量，这应该是一个更好的 HPA 阈值。我们将探讨如何在后面使用表达式而不是简单的指标。了解通过 Ingress 进入的请求数量是有用的，但可能还不够。

由于`go-demo-5`已经提供了有仪器的指标，看看我们是否可以检索`http_server_resp_time_count`将会很有帮助。提醒一下，这是我们在第四章中使用的相同指标，*通过指标和警报发现的故障调试*。

```
 1  kubectl get --raw \
 2      "/apis/custom.metrics.k8s.io/v1beta1" \
 3      | jq '.resources[]
 4      | select(.name
 5      | contains("http_server_resp_time_count"))'
```

我们使用`jq`来过滤结果，以便只检索`http_server_resp_time_count`。看到空输出不要感到惊讶。这是正常的，因为 Prometheus Adapter 没有配置为处理来自 Prometheus 的所有指标，而只处理符合其内部规则的指标。因此，现在可能是时候看一下包含其配置的`prometheus-adapter` ConfigMap 了。

```
 1  kubectl -n metrics \
 2      describe cm prometheus-adapter
```

输出太大，无法在书中呈现，所以我们只会讨论第一个规则。它如下所示。

```
...
rules:
- seriesQuery: '{__name__=~"^container_.*",container_name!="POD",namespace!="",pod_name!=""}'
  seriesFilters: []
  resources:
    overrides:
      namespace:
        resource: namespace
      pod_name:
        resource: pod
  name:
    matches: ^container_(.*)_seconds_total$
    as: ""
  metricsQuery: sum(rate(<<.Series>>{<<.LabelMatchers>>,container_name!="POD"}[5m]))
    by (<<.GroupBy>>)
...
```

第一个规则仅检索以`container`开头的指标（`__name__=~"^container_.*"`），标签`container_name`不是`POD`，并且`namespace`和`pod_name`不为空。

每个规则都必须指定一些资源覆盖。在这种情况下，`namespace`标签包含`namespace`资源。类似地，`pod`资源是从标签`pod_name`中检索的。此外，我们可以看到`name`部分使用正则表达式来命名新的指标。最后，`metricsQuery`告诉适配器在检索数据时应执行哪个 Prometheus 查询。

如果这个设置看起来令人困惑，您应该知道您并不是唯一一开始看起来感到困惑的人。就像 Prometheus 服务器配置一样，Prometheus Adapter 一开始很难理解。尽管如此，它们非常强大，可以让我们定义服务发现规则，而不是指定单个指标（对于适配器的情况）或目标（对于 Prometheus 服务器的情况）。很快我们将更详细地介绍适配器规则的设置。目前，重要的一点是默认配置告诉适配器获取与几个规则匹配的所有指标。

到目前为止，我们看到`nginx_ingress_controller_requests`指标可以通过适配器获得，但由于我们需要将请求数除以副本数，因此它没有用处。我们还看到`go-demo-5` Pods 中的`http_server_resp_time_count`指标不可用。总而言之，我们没有所有需要的指标，而适配器当前获取的大多数指标都没有用。它通过无意义的查询浪费时间和资源。

我们的下一个任务是重新配置适配器，以便仅从 Prometheus 中检索我们需要的指标。我们将尝试编写自己的表达式，只获取我们需要的数据。如果我们能做到这一点，我们应该能够创建 HPA。

# 使用自定义指标创建 HorizontalPodAutoscaler

正如您已经看到的，Prometheus Adapter 带有一组默认规则，提供了许多我们不需要的指标，而我们需要的并不是所有的指标。它通过做太多事情而浪费 CPU 和内存，但又不够。我们将探讨如何使用我们自己的规则自定义适配器。我们的下一个目标是使适配器仅检索`nginx_ingress_controller_requests`指标，因为这是我们唯一需要的指标。除此之外，它还应该以两种形式提供该指标。首先，它应该按资源分组检索速率。

第二种形式应该与第一种形式相同，但应该除以托管 Ingress 转发资源的 Pod 的部署的副本数。

这将为我们提供每个副本的平均请求数，并将成为基于自定义指标的第一个 HPA 定义的良好候选。

我已经准备了一个包含可能实现我们当前目标的 Chart 值的文件，让我们来看一下。

```
 1  cat mon/prom-adapter-values-ing.yml
```

输出如下。

```
image:
  tag: v0.5.0
metricsRelistInterval: 90s
prometheus:
  url: http://prometheus-server.metrics.svc
  port: 80
rules:
  default: false
  custom:
  - seriesQuery: 'nginx_ingress_controller_requests'
    resources:
      overrides:
        namespace: {resource: "namespace"}
        ingress: {resource: "ingress"}
    name:
      as: "http_req_per_second"
    metricsQuery: 'sum(rate(<<.Series>>{<<.LabelMatchers>>}[5m])) by (<<.GroupBy>>)'
  - seriesQuery: 'nginx_ingress_controller_requests'
    resources:
      overrides:
        namespace: {resource: "namespace"}
        ingress: {resource: "ingress"}
    name:
      as: "http_req_per_second_per_replica"
    metricsQuery: 'sum(rate(<<.Series>>{<<.LabelMatchers>>}[5m])) by (<<.GroupBy>>) / sum(label_join(kube_deployment_status_replicas, "ingress", ",", "deployment")) by (<<.GroupBy>>)'
```

在定义中的前几个条目与我们先前通过`--set`参数使用的数值相同。我们将跳过这些条目，直接进入`rules`部分。

在`rules`部分，我们将`default`条目设置为`false`。这将摆脱我们先前探索的默认规则，并使我们能够从干净的状态开始。此外，还有两个`custom`规则。

第一个规则基于`seriesQuery`，其值为`nginx_ingress_controller_requests`。`resources`部分内的`overrides`条目帮助适配器找出与该指标相关联的 Kubernetes 资源。我们将`namespace`标签的值设置为`namespace`资源。对于`ingress`也有类似的条目。换句话说，我们将 Prometheus 标签与 Kubernetes 资源`namespace`和`ingress`相关联。

很快你会看到，该指标本身将成为完整查询的一部分，并由 HPA 视为单一指标。由于我们正在创建新内容，我们需要一个名称。因此，我们在`name`部分指定了一个名为`http_req_per_second`的单一`as`条目。这将成为我们 HPA 定义中的参考。

你已经知道`nginx_ingress_controller_requests`本身并不是很有用。当我们在 Prometheus 中使用它时，我们必须将其放入`rate`函数中，我们必须`sum`所有内容，并且我们必须按资源对结果进行分组。我们通过`metricsQuery`条目正在做类似的事情。将其视为我们在 Prometheus 中编写的表达式的等价物。唯一的区别是我们使用了像`<<.Series>>`这样的“特殊”语法。这是适配器的模板机制。我们没有硬编码指标的名称、标签和分组语句，而是使用`<<.Series>>`、`<<.LabelMatchers>>`和`<<.GroupBy>>`子句，这些子句将根据我们在 API 调用中放入的内容填充正确的值。

第二个规则几乎与第一个相同。不同之处在于名称（现在是`http_req_per_second_per_replica`）和`metricsQuery`。后者现在将结果除以相关部署的副本数，就像我们在第三章中练习的那样，*收集和查询指标并发送警报*。

接下来，我们将使用新数值更新图表。

```
 1  helm upgrade prometheus-adapter \
 2      stable/prometheus-adapter \
 3      --version v0.5.0 \
 4      --namespace metrics \
 5      --values mon/prom-adapter-values-ing.yml
 6
 7  kubectl -n metrics \
 8      rollout status \
 9      deployment prometheus-adapter
```

现在部署已成功推出，我们可以再次确认 ConfigMap 中存储的配置确实是正确的。

```
 1  kubectl -n metrics \
 2      describe cm prometheus-adapter
```

输出，限于`Data`部分，如下。

```
...
Data
====
config.yaml:
----
rules:
- metricsQuery: sum(rate(<<.Series>>{<<.LabelMatchers>>}[5m])) by (<<.GroupBy>>)
  name:
    as: http_req_per_second
  resources:
    overrides:
      ingress:
        resource: ingress
      namespace:
        resource: namespace
  seriesQuery: nginx_ingress_controller_requests
- metricsQuery: sum(rate(<<.Series>>{<<.LabelMatchers>>}[5m])) by (<<.GroupBy>>) /
    sum(label_join(kube_deployment_status_replicas, "ingress", ",", "deployment"))
    by (<<.GroupBy>>)
  name:
    as: http_req_per_second_per_replica
  resources:
    overrides:
      ingress:
        resource: ingress
      namespace:
        resource: namespace
  seriesQuery: nginx_ingress_controller_requests
...
```

我们可以看到我们之前探索的默认`rules`现在被我们在 Chart 值文件的`rules.custom`部分中定义的两个规则所替换。

配置看起来正确并不一定意味着适配器现在提供数据作为 Kubernetes 自定义指标。我们也要检查一下。

```
 1  kubectl get --raw \
 2      "/apis/custom.metrics.k8s.io/v1beta1" \
 3      | jq "."
```

输出如下。

```
{
  "kind": "APIResourceList",
  "apiVersion": "v1",
  "groupVersion": "custom.metrics.k8s.io/v1beta1",
  "resources": [
    {
      "name": "namespaces/http_req_per_second_per_replica",
      "singularName": "",
      "namespaced": false,
      "kind": "MetricValueList",
      "verbs": [
        "get"
      ]
    },
    {
      "name": "ingresses.extensions/http_req_per_second_per_replica",
      "singularName": "",
      "namespaced": true,
      "kind": "MetricValueList",
      "verbs": [
        "get"
      ]
    },
    {
      "name": "ingresses.extensions/http_req_per_second",
      "singularName": "",
      "namespaced": true,
      "kind": "MetricValueList",
      "verbs": [
        "get"
      ]
    },
    {
      "name": "namespaces/http_req_per_second",
      "singularName": "",
      "namespaced": false,
      "kind": "MetricValueList",
      "verbs": [
        "get"
      ]
    }
  ]
}
```

我们可以看到有四个可用的指标，其中两个是`http_req_per_second`，另外两个是`http_req_per_second_per_replica`。我们定义的两个指标都可以作为`namespaces`和`ingresses`使用。现在，我们不关心`namespaces`，我们将集中在`ingresses`上。

我假设至少过去了五分钟（或更长时间），自从我们发送了一百个请求。如果没有，你是一个快速的读者，你将不得不等一会儿，然后我们再发送一百个请求。我们即将创建我们的第一个基于自定义指标的 HPA，并且我想确保你在激活之前和之后都能看到它的行为。

现在，让我们来看一个 HPA 定义。

```
 1  cat mon/go-demo-5-hpa-ing.yml
```

输出如下。

```
apiVersion: autoscaling/v2beta1
kind: HorizontalPodAutoscaler
metadata:
  name: go-demo-5
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: go-demo-5
  minReplicas: 3
  maxReplicas: 10
  metrics:
  - type: Object
    object:
      metricName: http_req_per_second_per_replica
      target:
        kind: Namespace
        name: go-demo-5
      targetValue: 50m
```

定义的前半部分应该是熟悉的，因为它与我们以前使用的内容没有区别。它将维护`go-demo-5`部署的`3`到`10`个副本。新的内容在`metrics`部分。

过去，我们使用`spec.metrics.type`设置为`Resource`。通过该类型，我们定义了 CPU 和内存目标。然而，这一次，我们的类型是`Object`。它指的是描述单个 Kubernetes 对象的指标，而在我们的情况下，恰好是来自 Prometheus Adapter 的自定义指标。

如果我们浏览*ObjectMetricSource v2beta1 autoscaling* ([`kubernetes.io/docs/reference/generated/kubernetes-api/v1.12/#objectmetricsource-v2beta1-autoscaling`](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.12/#objectmetricsource-v2beta1-autoscaling)) 文档，我们可以看到`Object`类型的字段与我们以前使用的`Resources`类型不同。我们将`metricName`设置为我们在 Prometheus Adapter 中定义的指标（`http_req_per_second_per_replica`）。

请记住，这不是一个指标，而是我们定义的一个表达式，适配器用来从 Prometheus 获取数据并将其转换为自定义指标。在这种情况下，我们得到了进入 Ingress 资源的请求数，然后除以部署的副本数。

最后，`targetValue`设置为`50m`或每秒 0.05 个请求。我故意将其设置为一个非常低的值，以便我们可以轻松达到目标并观察发生了什么。

让我们`apply`定义。

```
 1  kubectl -n go-demo-5 \
 2      apply -f mon/go-demo-5-hpa-ing.yml
```

接下来，我们将描述新创建的 HPA，并看看是否能观察到一些有趣的东西。

```
 1  kubectl -n go-demo-5 \
 2      describe hpa go-demo-5
```

输出，仅限于相关部分，如下所示。

```
...
Metrics:         ( current / target )
  "http_req_per_second_per_replica" on Namespace/go-demo-5: 0 / 50m
Min replicas:    3
Max replicas:    10
Deployment pods: 3 current / 3 desired
...
```

我们可以看到`Metrics`部分只有一个条目。HPA 正在使用基于`Namespace/go-demo-5`的自定义指标`http_req_per_second_per_replica`。目前，当前值为`0`，`target`设置为`50m`（每秒 0.05 个请求）。如果在您的情况下，`current`值为`unknown`，请等待片刻，然后重新运行命令。

进一步向下，我们可以看到`Deployment Pods`的`current`和`desired`数量均设置为`3`。

总的来说，目标没有达到（有`0`个请求），因此 HPA 无需做任何事情。它保持最小数量的副本。

让我们增加一些流量。

```
 1  for i in {1..100}; do
 2      curl "http://$GD5_ADDR/demo/hello"
 3  done
```

我们向`go-demo-5` Ingress 发送了一百个请求。

让我们再次`describe` HPA，并看看是否有一些变化。

```
 1  kubectl -n go-demo-5 \
 2      describe hpa go-demo-5
```

输出，仅限于相关部分，如下所示。

```
...
Metrics:                                                   ( current / target )
  "http_req_per_second_per_replica" on Ingress/go-demo-5:  138m / 50m
Min replicas:                                              3
Max replicas:                                              10
Deployment pods:                                           3 current / 6 desired
...
Events:
  ... Message
  ... -------
  ... New size: 6; reason: Ingress metric http_req_per_second_per_replica above target
```

我们可以看到指标的`current`值增加了。在我的情况下，它是`138m`（每秒 0.138 个请求）。如果您的输出仍然显示`0`，您必须等待直到 Prometheus 拉取指标，直到适配器获取它们，直到 HPA 刷新其状态。换句话说，请等待片刻，然后重新运行上一个命令。

鉴于`current`值高于`target`，在我的情况下，HPA 将`desired`的`Deployment pods`数量更改为`6`（根据指标值的不同，您的数字可能会有所不同）。因此，HPA 通过更改副本的数量来修改 Deployment，并且我们应该看到额外的 Pod 正在运行。这在`Events`部分中更加明显。应该有一条新消息，说明`New size: 6; reason: Ingress metric http_req_per_second_per_replica above target`。

为了安全起见，我们将列出`go-demo-5` Namespace 中的 Pods，并确认新的 Pod 确实正在运行。

```
 1  kubectl -n go-demo-5 get pods
```

输出如下。

```
NAME           READY STATUS  RESTARTS AGE
go-demo-5-db-0 2/2   Running 0        19m
go-demo-5-db-1 2/2   Running 0        19m
go-demo-5-db-2 2/2   Running 0        10m
go-demo-5-...  1/1   Running 2        19m
go-demo-5-...  1/1   Running 0        16s
go-demo-5-...  1/1   Running 2        19m
go-demo-5-...  1/1   Running 0        16s
go-demo-5-...  1/1   Running 2        19m
go-demo-5-...  1/1   Running 0        16s
```

我们现在可以看到有六个`go-demo-5-*` Pods，其中有三个比其余的年轻得多。

接下来，我们将探讨当流量低于 HPA 的“目标”时会发生什么。我们将通过一段时间不做任何事情来实现这一点。由于我们是唯一向应用程序发送请求的人，我们所要做的就是静静地站在那里五分钟，或者更好的是利用这段时间去取一杯咖啡。

我们需要等待至少五分钟的原因在于 HPA 用于扩展和缩小的频率。默认情况下，只要“当前”值高于“目标”，HPA 就会每三分钟扩展一次。缩小需要五分钟。只有在自上次扩展以来“当前”值低于目标至少三分钟时，HPA 才会缩小。

总的来说，我们需要等待五分钟或更长时间，然后才能看到相反方向的扩展效果。

```
 1  kubectl -n go-demo-5 \
 2      describe hpa go-demo-5
```

输出，仅限相关部分，如下所示。

```
...
Metrics:         ( current / target )
  "http_req_per_second_per_replica" on Ingress/go-demo-5:  0 / 50m
Min replicas:    3
Max replicas:    10
Deployment pods: 3 current / 3 desired
...
Events:
... Age   ... Message
... ----  ... -------
... 10m   ... New size: 6; reason: Ingress metric http_req_per_second_per_replica above target
... 7m10s ... New size: 9; reason: Ingress metric http_req_per_second_per_replica above target
... 2m9s  ... New size: 3; reason: All metrics below target
```

输出中最有趣的部分是事件部分。我们将专注于“年龄”和“消息”字段。请记住，只要当前值高于目标，扩展事件就会每三分钟执行一次，而缩小迭代则是每五分钟一次。

在我的情况下，HPA 在三分钟后再次扩展了部署。副本的数量从六个跳到了九个。由于适配器使用的表达式使用了五分钟的速率，一些请求进入了第二次 HPA 迭代。即使在我们停止发送请求后仍然扩展可能看起来不是一个好主意（确实不是），但在“现实世界”的场景中不应该发生，因为流量比我们生成的要多得多，我们不会将`50m`（每秒 0.2 个请求）作为目标。

在最后一次扩展事件后的五分钟内，“当前”值为`0`，HPA 将部署缩小到最小副本数（`3`）。再也没有流量了，我们又回到了起点。

我们确认了 Prometheus 的指标，通过 Prometheus Adapter 获取，并转换为 Kuberentes 的自定义指标，可以在 HPA 中使用。到目前为止，我们使用了通过出口商（`nginx_ingress_controller_requests`）从 Prometheus 获取的指标。鉴于适配器从 Prometheus 获取指标，它不应该关心它们是如何到达那里的。尽管如此，我们将确认仪表化指标也可以使用。这将为我们提供一个巩固到目前为止学到的知识的机会，同时，也许学到一些新的技巧。

```
 1  cat mon/prom-adapter-values-svc.yml
```

输出还是另一组 Prometheus Adapter 图表值。

```
image:
  tag: v0.5.0
metricsRelistInterval: 90s
prometheus:
  url: http://prometheus-server.metrics.svc
  port: 80
rules:
  default: false
  custom:
  - seriesQuery: 'http_server_resp_time_count{kubernetes_namespace!="",kubernetes_name!=""}'
    resources:
      overrides:
        kubernetes_namespace: {resource: "namespace"}
        kubernetes_name: {resource: "service"}
    name:
      matches: "^(.*)server_resp_time_count"
      as: "${1}req_per_second_per_replica"
    metricsQuery: 'sum(rate(<<.Series>>{<<.LabelMatchers>>}[5m])) by (<<.GroupBy>>) / count(<<.Series>>{<<.LabelMatchers>>}) by (<<.GroupBy>>)'
  - seriesQuery: 'nginx_ingress_controller_requests'
    resources:
      overrides:
        namespace: {resource: "namespace"}
        ingress: {resource: "ingress"}
    name:
      as: "http_req_per_second_per_replica"
    metricsQuery: 'sum(rate(<<.Series>>{<<.LabelMatchers>>}[5m])) by (<<.GroupBy>>) / sum(label_join(kube_deployment_status_replicas, "ingress", ",", "deployment")) by (<<.GroupBy>>)'
```

这一次，我们将合并包含不同指标系列的规则。第一条规则基于`go-demo-5`中源自`http_server_resp_time_count`的仪表指标。我们在第四章中使用过它，*通过指标和警报调试问题*，在其定义中并没有什么特别之处。它遵循与我们之前使用的规则相同的逻辑。第二条规则是我们之前使用过的规则的副本。

有趣的是这些规则的是，有两个完全不同的查询产生了不同的结果。然而，在这两种情况下，名称是相同的（`http_req_per_second_per_replica`）。

“等一下”，你可能会说。这两个名称并不相同。一个被称为`${1}req_per_second_per_replica`，而另一个是`http_req_per_second_per_replica`。虽然这是真的，但最终名称，不包括资源类型，确实是相同的。我想向你展示你可以使用正则表达式来形成一个名称。在第一条规则中，名称由`matches`和`as`条目组成。`matches`条目的`(.*)`部分成为第一个变量（还可以有其他变量），稍后用作`as`值（`${1}`）。由于指标是`http_server_resp_time_count`，它将从`^(.*)server_resp_time_count`中提取`http_`，然后在下一行中，用于替换`${1}`。最终结果是`http_req_per_second_per_replica`，这与第二条规则的名称相同。

现在我们已经确定了两条规则都将提供相同名称的自定义指标，我们可能会认为这将导致冲突。如果两者都被称为相同的话，HPA 将如何知道使用哪个指标？适配器是否必须丢弃一个并保留另一个？答案在“资源”部分。

指标的真正标识符是其名称和其关联的资源的组合。第一条规则生成两个自定义指标，一个用于服务，另一个用于命名空间。第二条规则还为命名空间生成自定义指标，但也为 Ingresses 生成自定义指标。

总共有多少个指标？在我们检查结果之前，我会让你考虑一下答案。为了做到这一点，我们将不得不“升级”图表，以使新值生效。

```
 1  helm upgrade -i prometheus-adapter \
 2      stable/prometheus-adapter \
 3      --version v0.5.0 \
 4      --namespace metrics \
 5      --values mon/prom-adapter-values-svc.yml
 6
 7  kubectl -n metrics \
 8      rollout status \
 9      deployment prometheus-adapter
```

我们用新值升级了图表，并等待部署完成。

现在我们可以回到我们未决问题“我们有多少个自定义指标？”让我们看看…

```
 1  kubectl get --raw \
 2      "/apis/custom.metrics.k8s.io/v1beta1" \
 3      | jq "."
```

输出，仅限于相关部分，如下所示。

```
{
  ...
    {
      "name": "services/http_req_per_second_per_replica",
      ...
    },
    {
      "name": "namespaces/http_req_per_second_per_replica",
      ...
    },
    {
      "name": "ingresses.extensions/http_req_per_second_per_replica",
      ...
```

现在我们有三个自定义度量标准，而不是四个。我已经解释过，唯一的标识符是度量标准的名称与其绑定的 Kubernetes 资源。所有度量标准都被称为 `http_req_per_second_per_replica`。但是，由于两个规则都覆盖了两个资源，并且在两者中都设置了 `namespace`，因此必须丢弃一个。我们不知道哪一个被移除了，哪一个留下了。或者，它们可能已经合并了。这并不重要，因为我们不应该用相同名称的度量标准覆盖相同的资源。对于我在适配器规则中包含 `namespace` 的实际原因，除了向您展示可以有多个覆盖以及它们相同时会发生什么之外，没有其他实际原因。

除了那个愚蠢的原因，你可以在脑海中忽略 `namespaces/http_req_per_second_per_replica` 度量标准。

我们使用了两个不同的 Prometheus 表达式来创建两个不同的自定义度量标准，它们具有相同的名称，但与其他资源相关。一个（基于 `nginx_ingress_controller_requests` 表达式）来自 Ingress 资源，而另一个（基于 `http_server_resp_time_count`）来自 Services。尽管后者起源于 `go-demo-5` Pods，但 Prometheus 是通过 Services 发现它的（正如在前一章中讨论的那样）。

我们不仅可以使用 `/apis/custom.metrics.k8s.io` 端点来发现我们拥有哪些自定义度量标准，还可以检查细节，包括数值。例如，我们可以通过以下命令检索 `services/http_req_per_second_per_replica` 度量标准。

```
 1  kubectl get --raw \
 2      "/apis/custom.metrics.k8s.io/v1beta1/namespaces/go-demo5
    /services/*/http_req_per_second_per_replica" \
 3       | jq .
```

输出如下。

```
{
  "kind": "MetricValueList",
  "apiVersion": "custom.metrics.k8s.io/v1beta1",
  "metadata": {
    "selfLink": "/apis/custom.metrics.k8s.io/v1beta1/namespaces/go-demo-5/services/%2A/http_req_per_second_per_replica"
  },
  "items": [
    {
      "describedObject": {
        "kind": "Service",
        "namespace": "go-demo-5",
        "name": "go-demo-5",
        "apiVersion": "/v1"
      },
      "metricName": "http_req_per_second_per_replica",
      "timestamp": "2018-10-27T23:49:58Z",
      "value": "1130m"
    }
  ]
}
```

`describedObject` 部分向我们展示了项目的细节。现在，我们只有一个具有该度量标准的 Service。

我们可以看到该 Service 位于 `go-demo-5` Namespace 中，它的名称是 `go-demo-5`，并且它正在使用 `v1` API 版本。

在更下面，我们可以看到度量标准的当前值。在我的情况下，它是 `1130m`，或者略高于每秒一个请求。由于没有人向 `go-demo-5` Service 发送请求，考虑到每秒执行一次健康检查，这个值是预期的。

接下来，我们将探讨更新后的 HPA 定义，将使用基于服务的度量标准。

```
 1  cat mon/go-demo-5-hpa-svc.yml
```

输出如下。

```
apiVersion: autoscaling/v2beta1
kind: HorizontalPodAutoscaler
metadata:
  name: go-demo-5
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: go-demo-5
  minReplicas: 3
  maxReplicas: 10
  metrics:
  - type: Object
    object:
      metricName: http_req_per_second_per_replica
      target:
        kind: Service
        name: go-demo-5
       targetValue: 1500m
```

与先前的定义相比，唯一的变化在于`target`和`targetValue`字段。请记住，完整的标识符是`metricName`和`target`的组合。因此，这次我们将`kind`更改为`Service`。我们还必须更改`targetValue`，因为我们的应用程序不仅接收来自 Ingress 的外部请求，还接收内部请求。它们可能来自其他可能与`go-demo-5`通信的应用程序，或者像我们的情况一样，来自 Kubernetes 的健康检查。由于它们的频率是一秒，我们将`targetValue`设置为`1500m`，即每秒 1.5 个请求。这样，如果我们不向应用程序发送任何请求，就不会触发扩展。通常，您会设置一个更大的值。但是，目前，我们只是尝试观察在扩展之前和之后它的行为。

接下来，我们将应用对 HPA 的更改，并进行描述。

```
 1  kubectl -n go-demo-5 \
 2      apply -f mon/go-demo-5-hpa-svc.yml
 3
 4  kubectl -n go-demo-5 \
 5      describe hpa go-demo-5
```

后一条命令的输出，仅限于相关部分，如下所示。

```
...
Metrics:                                                  ( current / target )
  "http_req_per_second_per_replica" on Service/go-demo-5: 1100m / 1500m
...
Deployment pods:                                           3 current / 3 desired
...
Events:
  Type    Reason             Age    From                       Message
  ----    ------             ----   ----                       -------
  Normal  SuccessfulRescale  12m    horizontal-pod-autoscaler  New size: 6; reason: Ingress metric http_req_per_second_per_replica above target
  Normal  SuccessfulRescale  9m20s  horizontal-pod-autoscaler  New size: 9; reason: Ingress metric http_req_per_second_per_replica above target
  Normal  SuccessfulRescale  4m20s  horizontal-pod-autoscaler  New size: 3; reason: All metrics below target
```

目前，没有理由让 HPA 扩展部署。当前值低于阈值。在我的情况下，它是`1100m`。

现在我们可以测试基于来自仪器的自定义指标的自动缩放是否按预期工作。通过 Ingress 发送请求可能会很慢，特别是如果我们的集群在云中运行。从我们的笔记本到服务的往返可能太慢了。因此，我们将从集群内部发送请求，通过启动一个 Pod 并从其中执行请求循环。

```
 1  kubectl -n go-demo-5 \
 2      run -it test \
 3      --image=debian \
 4      --restart=Never \
 5      --rm \
 6      -- bash
```

通常，我更喜欢`alpine`镜像，因为它们更小更高效。但是，`for`循环在`alpine`中无法工作（或者我不知道如何编写），所以我们改用`debian`。不过`debian`中没有`curl`，所以我们需要安装它。

```
 1  apt update
 2
 3  apt install -y curl
```

现在我们可以发送请求，这些请求将产生足够的流量，以便 HPA 触发扩展过程。

```
 1  for i in {1..500}; do
 2      curl "http://go-demo-5:8080/demo/hello"
 3  done
 4  
 5  exit
```

我们向`/demo/hello`端点发送了五百个请求，然后退出了容器。由于我们在创建 Pod 时使用了`--rm`参数，它将自动从系统中删除，因此我们不需要执行任何清理操作。

让我们描述一下 HPA 并看看发生了什么。

```
 1  kubectl -n go-demo-5 \
 2      describe hpa go-demo-5
```

输出结果，仅限于相关部分，如下所示。

```
...
Reference:                                                Deployment/go-demo-5
Metrics:                                                  ( current / target )
  "http_req_per_second_per_replica" on Service/go-demo-5: 1794m / 1500m
Min replicas:                                             3
Max replicas:                                             10
Deployment pods:                                          3 current / 4 desired
...
Events:
... Message
... -------
... New size: 6; reason: Ingress metric http_req_per_second_per_replica above target
... New size: 9; reason: Ingress metric http_req_per_second_per_replica above target
... New size: 3; reason: All metrics below target
... New size: 4; reason: Service metric http_req_per_second_per_replica above target
```

HPA 检测到`current`值高于目标值（在我的情况下是`1794m`），并将所需的副本数量从`3`更改为`4`。我们也可以从最后一个事件中观察到这一点。如果在您的情况下，`desired`副本数量仍然是`3`，请等待一段时间进行 HPA 评估的下一次迭代，并重复`describe`命令。

如果我们需要额外确认扩展确实按预期工作，我们可以检索`go-demo-5`命名空间中的 Pods。

```
 1  kubectl -n go-demo-5 get pods
```

输出如下。

```
NAME           READY STATUS  RESTARTS AGE
go-demo-5-db-0 2/2   Running 0        33m
go-demo-5-db-1 2/2   Running 0        32m
go-demo-5-db-2 2/2   Running 0        32m
go-demo-5-...  1/1   Running 2        33m
go-demo-5-...  1/1   Running 0        53s
go-demo-5-...  1/1   Running 2        33m
go-demo-5-...  1/1   Running 2        33m
```

毋庸置疑，当我们停止发送请求后，HPA 很快会缩减`go-demo-5`部署。相反，我们将进入下一个主题。

# 结合 Metric Server 数据和自定义指标

到目前为止，少数 HPA 示例使用单个自定义指标来决定是否扩展部署。您已经从第一章中了解到，基于资源使用情况自动扩展部署和 StatefulSets，我们可以在 HPA 中结合多个指标。然而，该章节中的所有示例都使用了来自 Metrics Server 的数据。我们了解到，在许多情况下，来自 Metrics Server 的内存和 CPU 指标是不够的，因此我们引入了 Prometheus Adapter，它将自定义指标提供给 Metrics Aggregator。我们成功地配置了 HPA 来使用这些自定义指标。然而，通常情况下，我们需要在 HPA 定义中结合这两种类型的指标。虽然内存和 CPU 指标本身是不够的，但它们仍然是必不可少的。我们能否将两者结合起来呢？

让我们再看看另一个 HPA 定义。

```
 1  cat mon/go-demo-5-hpa.yml
```

输出，仅限于相关部分，如下所示。

```
...
  metrics:
  - type: Resource
    resource:
      name: cpu
      targetAverageUtilization: 80
  - type: Resource
    resource:
      name: memory
      targetAverageUtilization: 80
  - type: Object
    object:
      metricName: http_req_per_second_per_replica
      target:
        kind: Service
        name: go-demo-5
      targetValue: 1500m
```

这次，HPA 在`metrics`部分有三个条目。前两个是基于`Resource`类型的“标准”`cpu`和`memory`条目。最后一个条目是我们之前使用过的`Object`类型之一。通过结合这些，我们告诉 HPA 如果满足三个标准中的任何一个，就进行扩展。同样，它也会进行缩减，但为了发生这种情况，所有三个标准都需要低于目标值。

让我们`apply`这个定义。

```
 1  kubectl -n go-demo-5 \
 2      apply -f mon/go-demo-5-hpa.yml
```

接下来，我们将描述 HPA。但在此之前，我们需要等待一段时间，直到更新后的 HPA 经过下一次迭代。

```
 1  kubectl -n go-demo-5 \
 2      describe hpa go-demo-5
```

输出，仅限于相关部分，如下所示。

```
...
Metrics:                                                  ( current / target )
  resource memory on pods  (as a percentage of request):  110% (5768533333m) / 80%
  "http_req_per_second_per_replica" on Service/go-demo-5: 825m / 1500m
  resource cpu on pods  (as a percentage of request):     20% (1m) / 80%
...
Deployment pods:                                          5 current / 5 desired
...
Events:
... Message
... -------
... New size: 6; reason: Ingress metric http_req_per_second_per_replica above target
... New size: 9; reason: Ingress metric http_req_per_second_per_replica above target
... New size: 4; reason: Service metric http_req_per_second_per_replica above target
... New size: 3; reason: All metrics below target
... New size: 5; reason: memory resource utilization (percentage of request) above target
```

我们可以看到基于内存的度量从一开始就超过了阈值。在我的情况下，它是`110%`，而目标是`80%`。因此，HPA 扩展了部署。在我的情况下，它将新大小设置为`5`个副本。

不需要确认新的 Pod 是否正在运行。到现在为止，我们应该相信 HPA 会做正确的事情。相反，我们将简要评论整个流程。

# 完整的 HorizontalPodAutoscaler 事件流

Metrics Server 从运行在工作节点上的 Kubelets 获取内存和 CPU 数据。与此同时，Prometheus Adapter 从 Prometheus Server 获取数据，而你已经知道，Prometheus Server 从不同的来源获取数据。Metrics Server 和 Prometheus Adapter 的数据都合并在 Metrics Aggregator 中。

HPA 定期评估定义为缩放标准的度量。它从 Metrics Aggregator 获取数据，实际上并不在乎它们是来自 Metrics Server、Prometheus Adapter 还是我们可能使用的任何其他工具。

一旦满足缩放标准，HPA 通过改变其副本数量来操作部署和 StatefulSets。

因此，通过创建和更新 ReplicaSets 执行滚动更新，ReplicaSets 又会创建或删除 Pods。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-25-tk/img/3a9e1aa2-f19e-47a8-ba94-b5c03eccf23a.png)图 5-3：HPA 使用 Metrics Server 和 Prometheus Adapter 提供的度量指标的组合（箭头显示数据流）

# 达到涅磐

现在我们知道如何将几乎任何指标添加到 HPA 中，它们比在第一章中看起来要有用得多，*基于资源使用情况自动扩展部署和有状态集*。最初，HPA 并不是非常实用，因为在许多情况下，内存和 CPU 是不足以决定是否扩展我们的 Pods 的。我们必须学会如何收集指标（我们使用 Prometheus Server 进行了这项工作），以及如何为我们的应用程序提供更详细的可见性。自定义指标是这个难题的缺失部分。如果我们用额外的我们需要的指标（例如，Prometheus Adapter）扩展了“标准”指标（CPU 和内存），我们就获得了一个强大的流程，它将使我们应用程序的副本数量与内部和外部需求保持同步。假设我们的应用程序是可扩展的，我们可以保证它们（几乎）总是能够按需执行。至少在涉及到扩展时，不再需要手动干预。具有“标准”和自定义指标的 HPA 将保证 Pod 的数量满足需求，而集群自动扩展器（在适用时）将确保我们有足够的容量来运行这些 Pods。

我们的系统离自给自足又近了一步。它将自适应于变化的条件，而我们（人类）可以把注意力转向比维持系统满足需求状态所需的更有创意和不那么重复的任务。我们离涅槃又近了一步。

# 现在呢？

请注意，我们使用了`autoscaling/v2beta1`版本的 HorizontalPodAutoscaler。在撰写本文时（2018 年 11 月），只有`v1`是稳定且可用于生产环境的。然而，`v1`非常有限（只能使用 CPU 指标），几乎没有什么用。Kubernetes 社区已经在新的（`v2`）HPA 上工作了一段时间，并且根据我的经验，它运行得相当不错。主要问题不是稳定性，而是 API 可能发生的不向后兼容的变化。不久前，`autoscaling/v2beta2`发布了，它使用了不同的 API。我没有在书中包含它，因为（在撰写本文时）大多数 Kubernetes 集群尚不支持它。如果你正在运行 Kubernetes 1.11+，你可能想切换到`v2beta2`。如果这样做，记住你需要对我们探讨的 HPA 定义进行一些更改。逻辑仍然是一样的，它的行为也是一样的。唯一可见的区别在于 API。

请参考*HorizontalPodAutoscaler v2beta2 autoscaling* ([`kubernetes.io/docs/reference/generated/kubernetes-api/v1.12/#horizontalpodautoscaler-v2beta2-autoscaling`](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.12/#horizontalpodautoscaler-v2beta2-autoscaling))，了解从`v2beta1`到`v2beta2`的变化，这些变化在 Kubernetes 1.11+中可用。

就是这样。如果集群专门用于本书，请销毁它；如果不是，或者您计划立即跳转到下一章节，请保留它。如果您要保留它，请通过执行以下命令删除`go-demo-5`资源。

```
 1  helm delete go-demo-5 --purge
 2
 3  kubectl delete ns go-demo-5
```

在您离开之前，您可能希望复习本章的要点。

+   HPA 定期评估定义为扩展标准的指标。

+   HPA 从 Metrics Aggregator 获取数据，它并不真的在乎这些数据是来自 Metrics Server、Prometheus Adapter 还是我们可能使用的任何其他工具。


# 第六章：可视化指标和警报

你们人类经常设法获得你们不想要的东西，这是很有趣的。

- *斯波克*

**仪表板是无用的！它们是浪费时间。如果你想看点东西，就去看 Netflix 吧。比任何其他选择都便宜。**

我在许多公开场合重复了这些话。我认为公司夸大了对仪表板的需求。他们花费了大量精力创建了一堆图表，并让很多人负责盯着它们。好像那样会帮助任何人一样。仪表板的主要优势在于它们色彩丰富，充满线条、方框和标签。这些特性总是很容易卖给像 CTO 和部门负责人这样的决策者。当一个软件供应商与有权签发支票的决策者开会时，他知道没有“漂亮的颜色”就没有销售。软件做什么并不重要，重要的是它的外观。这就是为什么每家软件公司都专注于仪表板。

想想看。仪表板有什么好处？我们会盯着图表看，直到柱状图达到红线，表示达到了临界阈值吗？如果是这样，为什么不创建一个在相同条件下触发的警报，而不是浪费时间盯着屏幕等待发生什么。相反，我们可以做一些更有用的事情（比如看 Netflix）。

我们的“恐慌标准”是否比警报所能表达的更复杂？我认为它更复杂。然而，这种复杂性无法通过预定义的图表来反映。当然，意外事件会发生，我们需要深入挖掘数据。然而，“意外”这个词违背了仪表板所提供的内容。它们都是关于预期结果的。否则，我们如何在不知道期望结果的情况下定义一个图表呢？“它可以是任何东西”无法转化为图表。带有图表的仪表板是我们假设可能出错的方式，并将这些假设放在屏幕上，或者更常见的是放在很多屏幕上。

然而，意外只能通过查询指标来探索，不断深入直到找到问题的原因。这是一项调查工作，无法很好地转化为仪表板。我们使用 Prometheus 查询来进行这项工作。

然而，我在这里把一整章都献给了仪表板。

我承认仪表板并不是（完全）无用的。它们有时是有用的。我真正想传达的是它们的用处被夸大了，我们可能需要以不同于许多人习惯的方式构建和使用仪表板。

但是，我有点跳到了结论。我们稍后会讨论仪表板的细节。现在，我们需要创建一个集群，这将使我们能够进行实验，并将这个对话提升到更实际的水平。

# 创建一个集群

`vfarcic/k8s-specs` ([`github.com/vfarcic/k8s-specs`](https://github.com/vfarcic/k8s-specs)) 仓库将继续作为我们的 Kubernetes 定义的来源。我们将确保通过拉取最新版本使其保持最新。

本章中的所有命令都可以在 `06-grafana.sh` ([`gist.github.com/vfarcic/b94b3b220aab815946d34af1655733cb`](https://gist.github.com/vfarcic/b94b3b220aab815946d34af1655733cb)) Gist 中找到。

```
 1  cd k8s-specs
 2
 3  git pull
```

要求与上一章相同。为了方便起见，Gists 在这里也是可用的。请随意使用它们来创建一个新的集群，或者验证您计划使用的集群是否符合要求。

+   `gke-instrument.sh`：**GKE** 使用 3 个 n1-standard-1 工作节点，**nginx Ingress**，**tiller**，**Prometheus** 图表，和环境变量 **LB_IP**，**PROM_ADDR**，和 **AM_ADDR** ([`gist.github.com/vfarcic/675f4b3ee2c55ee718cf132e71e04c6e`](https://gist.github.com/vfarcic/675f4b3ee2c55ee718cf132e71e04c6e))。

+   `eks-hpa-custom.sh`：**EKS** 使用 3 个 t2.small 工作节点，**nginx Ingress**，**tiller**，**Metrics Server**，**Prometheus** 图表，环境变量 **LB_IP**，**PROM_ADDR**，和 **AM_ADDR**，以及 **Cluster Autoscaler** ([`gist.github.com/vfarcic/868bf70ac2946458f5485edea1f6fc4c`](https://gist.github.com/vfarcic/868bf70ac2946458f5485edea1f6fc4c))。

+   `aks-instrument.sh`：**AKS** 使用 3 个 Standard_B2s 工作节点，**nginx Ingress**，**tiller**，**Prometheus** 图表，和环境变量 **LB_IP**，**PROM_ADDR**，和 **AM_ADDR** ([`gist.github.com/vfarcic/65a0d5834c9e20ebf1b99225fba0d339`](https://gist.github.com/vfarcic/65a0d5834c9e20ebf1b99225fba0d339))。

+   `docker-instrument.sh`：**Docker for Desktop**，带有**2 个 CPU**，**3GB RAM**，**nginx Ingress**，**tiller**，**Metrics Server**，**Prometheus**图表，以及环境变量**LB_IP**，**PROM_ADDR**和**AM_ADDR** ([`gist.github.com/vfarcic/1dddcae847e97219ab75f936d93451c2`](https://gist.github.com/vfarcic/1dddcae847e97219ab75f936d93451c2))。

+   `minikube-instrument.sh`：**minikube**，带有**2 个 CPU**，**3GB RAM**，启用**ingress**，**storage-provisioner**，**default-storageclass**和**metrics-server**插件，**tiller**，**Prometheus**图表，以及环境变量**LB_IP**，**PROM_ADDR**和**AM_ADDR** ([`gist.github.com/vfarcic/779fae2ae374cf91a5929070e47bddc8`](https://gist.github.com/vfarcic/779fae2ae374cf91a5929070e47bddc8))。

# 我们应该使用哪些工具来创建仪表板？

使用 Prometheus 只需几分钟就会发现它并不是设计用来作为仪表板的。当然，你可以在 Prometheus 中创建图表，但它们并不是永久的，也没有提供很多关于数据呈现的功能。Prometheus 的图表设计用于可视化临时查询。这正是我们大部分时间所需要的。当我们收到来自警报的通知表明有问题时，通常会通过执行警报的查询来开始寻找问题的罪魁祸首，然后根据结果深入数据。也就是说，如果警报没有立即显示问题，那么就没有必要接收通知，因为这类明显的问题通常可以自动修复。

但是，正如我已经提到的，Prometheus 并没有仪表板功能，所以我们需要寻找其他工具。

如今，选择仪表板很容易。*Grafana* ([`grafana.com/`](https://grafana.com/))是该领域无可争议的统治者。其他解决方案太老旧，不值得费心，或者它们不支持 Prometheus。这并不是说 Grafana 是市场上最好的工具。但价格合适（免费），并且可以与许多不同的数据源一起使用。例如，我们可以争论*Kibana* ([`www.elastic.co/products/kibana`](https://www.elastic.co/products/kibana))和 Grafana 一样好，甚至更好。但是，它仅限于来自 ElasticSearch 的数据。而 Grafana 除了可以使用来自 ElasticSearch 的数据外，还支持许多其他数据源。有人可能会说*DataDog* ([`www.datadoghq.com/`](https://www.datadoghq.com/))是一个更好的选择。但是，它遇到了与 Kibana 相同的问题。它与特定的指标来源绑定。

没有灵活性，也没有组合来自其他数据源的选项。更重要的是，这两者都不支持 Prometheus。

我将不再与其他工具进行比较。你可以自己尝试。目前，你需要相信我，Grafana 是一个不错的选择，如果不是最好的选择。如果我们在这一点上不同意，那么你继续阅读本章将毫无意义。

既然我已经强制选择了 Grafana，我们将继续安装它。

# 安装和设置 Grafana

接下来你可能知道发生了什么。我们谷歌搜索“Grafana Helm”，希望社区已经创建了一个我们可以使用的图表。我将为您揭示，Helm 的*稳定*频道中有 Grafana。我们所要做的就是检查数值并选择我们将使用的数值。

```
 1  helm inspect values stable/grafana
```

我不会列举我们可以使用的所有数值。我假设到现在为止，你已经是一个 Helm 忍者，可以自己探索它们。相反，我们将使用我已经定义的数值。

```
 1  cat mon/grafana-values-bare.yml
```

输出如下。

```
ingress:
  enabled: true
persistence:
  enabled: true
  accessModes:
  - ReadWriteOnce
  size: 1Gi
resources:
  limits:
    cpu: 20m
    memory: 50Mi
  requests:
    cpu: 5m
    memory: 25Mi
```

这些数值没有什么特别之处。我们启用了 Ingress，设置了`persistence`，并定义了`resources`。正如文件名所示，这是一个非常简单的设置，没有任何多余的东西。

现在剩下的就是安装图表。

```
 1  GRAFANA_ADDR="grafana.$LB_IP.nip.io"
 2    
 3  helm install stable/grafana \
 4      --name grafana \
 5      --namespace metrics \
 6      --version 1.17.5 \
 7      --set ingress.hosts="{$GRAFANA_ADDR}" \
 8      --values mon/grafana-values-bare.yml
 9
10  kubectl -n metrics \
11      rollout status deployment grafana
```

现在我们可以在您喜欢的浏览器中打开 Grafana。

```
 1  open "http://$GRAFANA_ADDR"
```

你将看到登录界面。就像许多其他 Helm 图表一样，安装包括`admin`用户和密码存储为一个秘密。

```
 1  kubectl -n metrics \
 2      get secret grafana \
 3      -o jsonpath="{.data.admin-password}" \
 4      | base64 --decode; echo
```

请返回到 Grafana 登录界面，输入`admin`作为用户名，并将上一个命令的输出粘贴为密码。

Grafana 不收集指标。相反，它使用其他数据源，因此我们的第一个操作是将 Prometheus 设置为数据源。

请点击“添加数据源”图标。

将`Prometheus`作为名称，并选择它作为类型。我们将让 Grafana 通过 Kubernetes 服务`prometheus-server`连接到它。由于两者都在同一个命名空间中，URL 应设置为`http://prometheus-server`。剩下的就是保存并测试。

本章的输出和截图来自 Docker for Desktop。您在这里看到的内容可能与您在屏幕上观察到的内容略有不同。![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-25-tk/img/09055a6f-2b2f-4524-8a89-c197904d9134.png)图 6-1：Grafana 的新数据源屏幕本章的截图比通常多。我相信它们将帮助您复制我们将讨论的步骤。

# 导入和自定义预制仪表板

数据源本身是无用的。我们需要以某种方式将它们可视化。我们可以通过创建自己的仪表板来实现这一点，但这可能不是 Grafana 的最佳（也不是最简单）介绍。相反，我们将导入一个现有的社区维护的仪表板。我们只需要选择一个适合我们需求的仪表板。

```
 1  open "https://grafana.com/dashboards"
```

随意花一点时间探索可用的仪表板。

我认为*Kubernetes 集群监控*（[`grafana.com/dashboards/3119`](https://grafana.com/dashboards/3119)）仪表板是一个很好的起点。让我们导入它。

请点击左侧菜单中的“+”图标，然后点击“导入”链接，您将看到一个屏幕，允许我们导入 Grafana.com 的仪表板之一，或者粘贴定义它的 JSON。

我们将选择前一种选项。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-25-tk/img/1fc859c6-1c3a-4f74-9196-b1b624a8292f.png)图 6-2：Grafana 的导入仪表板选项

请在*Grafana.com 仪表板*字段中输入`3119`，然后点击“加载”按钮。您将看到一些字段。在这种情况下，唯一重要的是*prometheus*下拉列表。我们必须使用它来设置数据源。选择 Prometheus，并点击“导入”按钮。

您看到的是一个带有一些基本 Kubernetes 指标的仪表板。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-25-tk/img/4059d071-a450-49c1-bf7e-a5ca29798723.png)图 6-3：Kubernetes 集群监控仪表板

但是，一些图表可能无法正常工作。这是否意味着我们导入了错误的仪表板？一个简单的答案恰恰相反。在所有可用的仪表板中，这个可能是最有效的。至少，如果我们只计算那些更多或少有用的图表。这样的结果很常见。这些仪表板由社区维护，但其中大多数是为个人使用而制作的。它们被配置为在特定集群中工作并使用特定的指标。您将很难找到许多不经任何更改就能正常工作并且同时显示您真正需要的内容的仪表板。相反，我认为这些仪表板是一个很好的起点。

我只是导入它们以获得一个我可以修改以满足我的特定需求的基础。这就是我们接下来要做的，至少部分地。

目前，我们只关注旨在使其完全运行的更改。我们将使一些当前没有数据的图表运行，并删除对我们无用的图表。

如果我们仔细看一下*总使用量*行，我们会发现*集群文件系统使用情况*是*N/A*。它使用的指标可能有问题。让我们仔细看一下。

在某些集群中（例如，EKS），此仪表板中的硬编码文件系统是正确的。如果是这种情况（如果*集群文件系统使用情况*不是*N/A*），则您无需进行任何更改。但是，我建议您在想象您的集群使用不同文件系统的同时进行练习。这样你就可以学到一些技巧，可以应用到其他仪表板上。

请按下*集群文件系统使用情况*标题旁边的箭头，并单击编辑链接。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-25-tk/img/b8db47c6-c501-49eb-a072-1fea9b62c391.png)图 6-4：Grafana 编辑面板的选项

该图表使用的查询（为了可读性而格式化）如下。

```
 1  sum (
 2      container_fs_usage_bytes{
 3          device=~"^/dev/xvda.$",
 4          id="/",
 5          kubernetes_io_hostname=~"^$Node$"
 6      }
 7  ) / 
 8  sum (
 9      container_fs_limit_bytes{
10          device=~"^/dev/xvda.$",
11          id="/",
12          kubernetes_io_hostname=~"^$Node$"
13      }
14  ) * 100
```

我们不会深入讨论该查询的细节。你现在应该熟悉 Prometheus 表达式。相反，我们将专注于问题的可能原因。我们可能没有名为`/dev/xvda`的文件系统设备（除非您使用 EKS 或在某些情况下使用 GKE）。如果这是问题，我们可以通过简单地将值更改为我们的设备来修复图表。但是，在我们继续之前，我们可能会探索 Grafana 变量。毕竟，如果我们甚至不知道我们的设备是什么，将一个硬编码值更改为另一个值对我们毫无好处。

我们可以转到 Prometheus 并检索所有设备的列表，或者让 Grafana 为我们执行此操作。我们将选择后者。

仔细观察`kubernetes_io_hostname`。它设置为`^$Node$`。这是使用 Grafana 变量的示例。接下来，我们将探讨它们，试图替换硬编码的设备。

请单击位于屏幕右上角的*返回仪表板*按钮。

单击位于屏幕顶部的*设置*图标。您将看到我们可以更改的整个仪表板范围配置。随意在左侧菜单中探索选项。

由于我们有兴趣创建一个新变量，该变量将动态填充查询的`device`标签，我们接下来要做的是单击*设置*部分中的变量链接，然后点击+新按钮。

请将`device`键入为变量名称，将`IO 设备`键入为标签。我们将从 Prometheus（数据源）检索值，因此我们将将类型保留为查询。

接下来，我们需要指定数据源。选择$datasource。这告诉 Grafana 我们要从我们在导入仪表板时选择的任何数据源中查询数据。

到目前为止，一切可能都是不言自明的。接下来的内容不是。我们需要查阅文档，了解如何编写用作变量值的 Grafana 查询。

```
 1  open
    "http://docs.grafana.org/features/datasources/prometheus/#query-variable"
```

让这成为一个练习。通过文档找出如何编写一个查询，以检索`container_fs_usage_bytes`指标中可用的`device`标签的所有不同值。

Grafana 仅支持四种类型的变量查询，因此我想您不会很难找出我们应该添加到查询字段的表达式是`label_values(container_fs_usage_bytes, device)`。

有了查询，剩下的就是单击添加按钮。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-25-tk/img/c8cb3194-277c-4074-8c3e-6d72d9f9476e.png)图 6-5：创建新仪表板变量的 Grafana 屏幕

现在我们应该返回*仪表板*并确认新变量是否可用。

您应该在屏幕左上部看到一个带有标签*IO 设备*的新下拉列表。如果您展开它，您将看到我们集群中使用的所有设备。确保选择正确的设备。这可能是`/dev/sda1`或`/dev/xvda1`。

接下来，我们需要更改图表以使用我们刚刚创建的变量。

请点击*Cluster 文件系统使用情况*图表旁边的箭头，并选择编辑。指标（查询）包含两个硬编码的`^/dev/xvda.$`值。将它们更改为`$device`，然后点击屏幕右上角的*返回仪表板*按钮。

就是这样。现在图表通过显示集群文件系统使用情况（`/dev/sda1`）的百分比来正确工作。

然而，下面的*已使用*和*总计*数字仍然是*N/A*。我相信你知道该怎么做来修复它们。编辑这些图形，并用`$device`替换`^/dev/xvda.$`。

该仪表板仍然有两个问题要解决。更准确地说，我们有两个图表对我们没有用。*系统服务 CPU 使用情况*和*系统服务内存使用情况*图表的目的应该可以从它们的标题中推断出来。然而，大多数 Kubernetes 集群不提供对系统级服务的访问（例如 GKE）。即使提供，我们的 Prometheus 也没有配置来获取数据。如果你不相信我，复制其中一个图表的查询并在 Prometheus 中执行它。就目前而言，这些图表只是在浪费空间，所以我们将删除它们。

请点击*系统服务 CPU 使用情况*行标题旁边的*垃圾桶*图标。点击是以删除该行和面板。对*系统服务内存使用情况*行执行相同的操作。

现在我们已经完成了对仪表板的更改。它已经完全可操作，我们应该通过点击屏幕右上角的*保存仪表板*图标或按**CTRL+S**来保存更改。

我们不会详细介绍 Grafana 的所有选项和我们可以做的操作。我相信你可以自己弄清楚。这是一个非常直观的应用程序。相反，我们将尝试创建自己的仪表板。或者，至少，探索一些东西，让你可以继续自己的工作。

# 创建自定义仪表板

如果我们所有的需求都可以由现有的仪表板满足，那将是很好的。但是，这可能并不是事实。每个组织都是“特殊”的，我们的需求必须反映在我们的仪表板中。有时我们可以使用他人制作的仪表板，有时我们需要对其进行更改。在其他情况下，我们需要创建自己的仪表板。这就是我们接下来要探索的内容。

请点击左侧菜单中的+图标，并选择`创建仪表板`。您将被提供选择几种类型的面板。选择`图形`。

在定义我们的第一个图表之前，我们将更改一些仪表板设置。请点击屏幕右上角的*设置*图标。

在*General*部分，输入仪表板的名称。如果你今天没有灵感，你可以称它为`我的仪表板`。将标签设置为`Prometheus`和`Kubernetes`。在输入每个标签后，你需要按下回车键。最后，将时区更改为本地浏览器时间。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-25-tk/img/61df4ee1-02ff-4141-bce7-d38c27e8c7f7.png)图 6-6：Grafana 的仪表板常规设置屏幕

那是无聊的部分。现在让我们转到更有趣的事情。我们将把我们在 Prometheus 中创建的警报之一转换成图表。我们将使用告诉我们实际 CPU 使用量与保留 CPU 的百分比的那个。为此，我们需要一些变量。更准确地说，我们并不真的需要它们，因为我们可以硬编码这些值。但是，如果以后决定更改它们，那将会引起问题。修改变量比更改查询要容易得多。

具体来说，我们需要变量来告诉我们最小的 CPU 是多少，这样我们就可以忽略那些设置为使用非常低保留的应用程序的阈值。此外，我们将定义作为下限和上限的变量。我们的目标是在与实际使用相比时，如果保留的 CPU 太低或太高，我们会收到通知，就像我们在 Prometheus 警报中所做的那样。

请从左侧菜单中选择变量部分，然后点击“添加变量”按钮。

当我们为导入的仪表板创建新的变量时，你已经看到了 Grafana 变量的屏幕。然而，这次我们将使用略有不同的设置。

将名称设置为`minCpu`，并选择常量作为类型。与之前创建的`device`变量不同，这次我们不需要 Grafana 来查询数值。通过使用这种类型，我们将定义一个常量值。请将值设置为`0.005`（五个 CPU 毫秒）。最后，我们不需要在仪表板中看到该变量，因为该值不太可能经常更改。如果将来需要更改它，我们总是可以回到这个屏幕并更新它。因此，将隐藏值更改为变量。

现在只需点击两次“添加”按钮。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-25-tk/img/e0fc3634-99c7-4fb6-9cf9-5b77aa39567f.png)图 6-7：Grafana 的仪表板新变量屏幕

我们还需要两个变量。可能没有必要重复相同的说明，所以请使用以下信息来创建它们。

```
 1  Name:  cpuReqPercentMin
 2  Type:  Constant
 3  Label: Min % of requested CPU
 4  Hide:  Variable
 5  Value: 50
 6
 7  Name:  cpuReqPercentMax
 8  Type:  Constant
 9  Label: Max % of requested CPU
10  Hide:  Variable
11  Value: 150
```

现在我们可以返回并定义我们的图表。请点击屏幕右上角的*返回仪表板*图标。

你已经知道如何编辑面板。点击*面板标题*旁边的箭头，然后选择编辑。

我们将从*常规*部分开始。请选择它。

接下来，将`%实际 CPU 与保留 CPU`作为标题，以及后面的文本作为描述。

```
 1  The percentage of actual CPU usage compared to reserved. The
    calculation excludes Pods with reserved CPU equal to or smaller than
    $minCpu. Those with less than $minCpu of requested CPU are ignored.
```

请注意描述中`$minCpu`变量的使用。当我们回到仪表板时，它将展开为其值。

接下来，请切换到*指标*选项卡。那里才是真正的操作发生的地方。

我们可以定义多个查询，但对于我们的用例，一个应该就足够了。请在*A*右侧的字段中输入以下查询。

为了方便起见，查询可在`grafana-actual-vs-reserved-cpu` ([`gist.github.com/vfarcic/1b027a1e2b2415e1d156687c1cf14012`](https://gist.github.com/vfarcic/1b027a1e2b2415e1d156687c1cf14012)) Gist 中找到。

```
 1  sum(label_join(
 2      rate(
 3          container_cpu_usage_seconds_total{
 4              namespace!="kube-system",
 5              pod_name!=""
 6          }[5m]
 7      ),
 8      "pod",
 9      ",",
10      "pod_name"
11  )) by (pod) /
12  sum(
13      kube_pod_container_resource_requests_cpu_cores{
14          namespace!="kube-system",
15          namespace!="ingress-nginx"
16      }
17  ) by (pod) and 
18  sum(
19      kube_pod_container_resource_requests_cpu_cores{
20          namespace!="kube-system",
21          namespace!="ingress-nginx"
22      }
23  ) by (pod) > $minCpu
```

该查询几乎与我们在第三章中使用的查询之一几乎相同，*收集和查询指标并发送警报*。唯一的区别是使用了`$minCpu`变量。

输入查询后的几分钟后，我们应该看到图表活跃起来。可能只包括一个 Pod，因为我们的许多应用程序被定义为使用五个 CPU 毫秒（`$minCpu`的值）或更少。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-25-tk/img/3a7042c2-ba76-4ad8-904d-ef3d72c99c47.png)图 6-8：基于图表的 Grafana 面板

接下来，我们将调整图表左侧的单位。请点击*轴*选项卡。

展开*左 Y 单位*，选择无，然后选择百分比（0.0-1.0）。由于我们不使用*右 Y*轴，请取消选中*显示*复选框。

接下来是*图例*部分。请选择它。

勾选*作为表格显示*、*选项在右侧*和*值>当前*复选框。更改将立即应用到图表上，你应该不难推断出每个选项的作用。

只剩下一件事。我们应该定义上限和下限阈值，以清楚地指示结果是否超出预期范围。

请点击*警报*选项卡。

单击“创建警报”按钮，并将“高于”条件更改为“范围之外”。将下两个字段的值设置为`0,5`和`1,5`。这样，当实际 CPU 使用率低于 50％或高于 150％时，与保留值相比，应该会通知我们。

图 6-9：带有警报的 Grafana 图表

我们已经完成了图表，所以请返回到仪表板并享受“漂亮的颜色”。您可能希望拖动图表的右下角以调整其大小。

我们可以看到请求的 CPU 使用率与实际 CPU 使用率之间的差异。我们还有阈值（用红色标记），它将告诉我们使用情况是否超出了设定的边界。

现在出现了一个重要问题。这样的图表有用吗？答案取决于我们打算用它做什么。

如果目标是盯着它，等待其中一个 Pod 开始使用过多或过少的 CPU，我只能说您正在浪费可以用于更有生产力任务的才能。毕竟，我们已经在 Prometheus 中有类似的警报，当满足条件时会向我们发送 Slack 通知。它比我们在图表中拥有的更先进，因为它只会在 CPU 使用率在一定时间内激增时通知我们，从而避免可能在几秒或几分钟后解决的临时问题。我们应该将这些情况视为误报。

该图的另一个用途可能更为被动。我们可以忽略它（关闭 Grafana），只有在上述 Prometheus 警报触发时才回来。这可能更有意义。尽管我们可以在 Prometheus 中运行类似的查询并获得相同的结果，但具有预定义图表可以使我们免于编写这样的查询。您可以将其视为具有相应图形表示的查询注册表。这是更有意义的事情。与盯着仪表板（选择 Netflix）相比，我们可以在需要时回来。虽然在某些情况下这可能是一个合理的策略，但它只在非常简单的情况下起作用。当出现问题时，一个单独的预定义图表解决问题或更准确地说是提供问题原因的明确指示时，图表确实提供了重要价值。然而，往往情况并不那么简单，我们将不得不求助于 Prometheus 来深入挖掘指标。

盯着有图表的仪表板是浪费时间。在收到有关问题的通知后访问仪表板可能更有些意义。但是，除了琐碎的问题，其他问题都需要通过 Prometheus 指标进行更深入的挖掘。

尽管如此，我们刚刚制作的图表可能会证明自己是有用的，所以我们会保留它。在这种情况下，我们可能想要做的是更改 Prometheus 警报的链接（我们目前在 Slack 上收到的警报），以便它直接带我们到图表（而不是仪表板）。我们可以通过单击面板名称旁边的箭头，并选择“查看”选项来获取该链接。

我相信，如果我们将面板类型从图表更改为更少颜色、更少线条、更少坐标轴和没有其他漂亮东西的类型，我们的仪表板可以变得更有用。

# 创建信号量仪表板

如果我声称仪表板为我们带来的价值比我们想象的要低，你可能会问自己这一章开头的同样问题。为什么我们要谈论仪表板？嗯，我已经改变了我的说法，从“仪表板是无用的”变成了“仪表板中有一些价值”。它们可以作为查询的注册表。通过仪表板，我们不需要记住我们需要在 Prometheus 中编写的表达式。在我们深入挖掘指标之前，它们可能是我们寻找问题原因的一个很好的起点。但是，我包括仪表板在解决方案中还有另一个原因。

我喜欢大屏幕。走进一个有大屏幕显示重要内容的房间是非常令人满意的。通常有一个房间，操作员坐在四面墙上都是显示器的环境中。那通常是一个令人印象深刻的景象。然而，许多这样的情况存在问题。一堆显示很多图表的监视器可能并不比漂亮的景象更有意义。最初的几天过后，没有人会盯着图表看。如果这不是真的，你也可以解雇那个人，因为他是在假装工作。

让我再重复一遍。

仪表板并不是为了我们盯着它们而设计的，尤其是当它们在所有人都能看到的大屏幕上时。

因此，如果拥有大屏幕是一个好主意，但图形不是一个好的装饰候选，那么我们应该做什么呢？答案就在于信号量。它们类似于警报，应该清晰地指示系统的状态。如果屏幕上的一切都是绿色的，我们就没有理由做任何事情。其中一个变成红色是一个提示，我们应该做一些事情来纠正问题。因此，我们必须尽量避免误报。如果某事变成红色，而不需要任何行动，我们很可能在将来开始忽视它。当这种情况发生时，我们冒着忽视一个真正问题的风险，认为它只是另一个误报。因此，每次出现警报都应该跟随着一个行动。

这可以是纠正系统的修复措施，也可以是改变导致其中一个信号量变红的条件。无论哪种情况，我们都不应该忽视它。

信号量的主要问题在于它们对 CTO 和其他决策者来说并不那么吸引人。它们既不丰富多彩，也不显示很多框、线和数字。人们经常将有用性与外观上的吸引力混淆。尽管如此，我们并不是在建造应该出售给 CTO 的东西，而是在建造可以帮助我们日常工作的东西。

与图形相比，信号量作为查看系统状态的一种方式要更有用得多，尽管它们看起来不像图形那样丰富多彩和令人愉悦。

让我们创建我们的第一个信号量。

请点击屏幕右上角的*添加面板*图标，并选择 Singlestat。点击*面板标题*旁边的箭头图标，然后选择编辑。

在大多数情况下，创建一个单一的状态（信号量）与创建一个图形并没有太大的不同。显著的区别在于应该产生一个单一值的度量（查询）。我们很快就会到达那里。现在，我们将改变面板的一些一般信息。

请选中“常规”选项卡。

将`Pods with <$cpuReqPercentMin%||>$cpuReqPercentMax% actual compared to reserved CPU`输入为标题，然后输入后面的文本为描述。

```
 1  The number of Pods with less than $cpuReqPercentMin% or more than
    $cpuReqPercentMax% actual compared to reserved CPU
```

这个单一统计将使用与我们之前制作的图表类似的查询。然而，虽然图表显示当前使用量与保留 CPU 相比，但该面板应该显示有多少个 Pod 的实际 CPU 使用量超出了基于保留 CPU 的边界。这反映在我们刚刚输入的标题和描述中。正如您所看到的，这一次我们依赖更多的变量来表达我们的意图。

现在，让我们把注意力转向查询。请单击“指标”选项卡，并将以下表达式输入到* A *旁边的字段中。

为了您的方便，该查询可在`grafana-single-stat-actual-vs-reserved-cpu` ([`gist.github.com/vfarcic/078674efd3b379c211c4da2c9844f5bd`](https://gist.github.com/vfarcic/078674efd3b379c211c4da2c9844f5bd)) Gist 中找到。

```
 1  sum(
 2      (
 3          sum(
 4              label_join(
 5                  rate(container_cpu_usage_seconds_total{
 6                      namespace!="kube-system",
 7                      pod_name!=""}[5m]),
 8                      "pod",
 9                      ",",
10                      "pod_name"
11              )
12          ) by (pod) /
13          sum(
14              kube_pod_container_resource_requests_cpu_cores{
15                  namespace!="kube-system",
16                  namespace!="ingress-nginx"
17              }
18          ) by (pod) and
19          sum(
20              kube_pod_container_resource_requests_cpu_cores{
21                  namespace!="kube-system",
22                  namespace!="ingress-nginx"
23              }
24          ) by (pod) > $minCpu
25      ) < bool ($cpuReqPercentMin / 100)
26  ) +
27  sum(
28      (
29          sum(
30              label_join(
31                  rate(
32                      container_cpu_usage_seconds_total{
33                          namespace!="kube-system",
34                          pod_name!=""
35                      }[5m]
36                  ),
37                  "pod",
38                  ",",
39                  "pod_name"
40              )
41          ) by (pod) /
42          sum(
43              kube_pod_container_resource_requests_cpu_cores{
44                  namespace!="kube-system",
45                  namespace!="ingress-nginx"
46              }
47          ) by (pod) and
48          sum(
49              kube_pod_container_resource_requests_cpu_cores{
50                  namespace!="kube-system",
51                  namespace!="ingress-nginx"
52              }
53          ) by (pod) > $minCpu
54      ) > bool ($cpuReqPercentMax / 100)
55  )
```

该查询类似于我们用作 Prometheus 警报的查询之一。更准确地说，它是两个 Prometheus 警报的组合。前半部分返回具有超过`$minCpu`（5 CPU 毫秒）的保留 CPU 和实际 CPU 使用低于`$cpuReqPercentMin`（50%）的 Pod 数量。后半部分与第一部分几乎相同，只是返回 CPU 使用高于`$cpuReqPercentMax`（150%）的 Pod。

由于我们的目标是返回一个单一的统计数据，即 Pod 的数量，在这种情况下，您可能会感到惊讶，我们使用了`sum`而不是`count`。统计 Pod 的数量确实更有意义，但如果没有结果，将返回`N/A`。为了避免这种情况，我们使用了`bool`的技巧。通过将其放在表达式前面，如果有匹配，则返回`1`，如果没有，则返回`0`。这样，如果没有 Pod 符合条件，我们不会得到空结果，而是得到`0`，这更好地表示有问题的 Pod 的数量。

总的来说，我们正在检索所有实际 CPU 低于保留 CPU 的`$cpuReqPercentMin`（50%）的 Pod 的总和，以及所有实际 CPU 高于保留 CPU 的`$cpuReqPercentMax`（150%）的 Pod 的总和。在这两种情况下，只有超过`$minCpu`（五个 CPU 毫秒）的 Pod 被包括在内。查询本身并不是我们可以编写的最简单的查询，但考虑到我们已经花了很多时间处理 Prometheus 查询，我认为我不应该用一些琐碎的东西“侮辱”您。

接下来，请单击“选项”选项卡。这是我们将定义应触发颜色变化的条件的地方。

我们不想要在指定周期内的平均值，而是有问题的 Pods 的当前数量。我们将通过将 Stat 下拉列表的值更改为 Current 来实现这一点。

我们希望这个面板非常显眼，所以我们将将 Stat 字体大小更改为`200%`。我更喜欢更大的字体，但是 Grafana 不允许我们超过这个值。

接下来，我们想要更改面板的背景颜色，请勾选 Coloring Background 复选框。

我们最多可以使用三种颜色，但我相信我们只需要两种。要么一个或多个 Pod 符合条件，要么没有一个符合条件。

一旦查询返回`1`或更高的数字，我们应该立即收到通知。请将`1`键入为 Coloring Thresholds。如果我们有更多，我们将用逗号分隔它们。

最后，由于我们只有两个条件，绿色和红色，我们需要将第二个颜色从橙色更改为红色。请点击 Coloring Colors 中的*red*图标，并将值替换为单词*red*。第三种颜色没有使用，所以我们将保持不变。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-25-tk/img/23e5659a-1dbc-440a-9d53-13f57bb1eeea.png)图 6-10：Grafana 的单个统计面板

我们已经完成了我们的面板，所以返回*仪表板*。

在继续之前，请点击*保存仪表板*图标，然后点击保存按钮。

到目前为止，我们创建了一个带有图形和单个统计（信号量）的仪表板。前者显示了 CPU 使用率与保留 CPU 随时间的偏差。它有警报（红色区域），告诉我们一个向量是否超出了预定义的边界。单个统计（信号量）显示一个数字，具有绿色或红色的背景，具体取决于该数字是否达到了阈值，而在我们的情况下，阈值设置为`1`。

我们刚刚开始，还需要在此仪表板变得有用之前添加许多其他面板。我会免去您定义其他面板的重复指令。我觉得您已经掌握了 Grafana 的工作原理。至少，您应该具备可以自行扩展的基础知识。

我们将快进。我们将导入我准备好的仪表板并讨论设计选择。

# 更适合大屏幕的仪表板

我们探讨了如何创建一个带有图形和单个统计（信号量）的仪表板。两者都基于类似的查询，显著的区别在于它们显示结果的方式。我们将假设我们开始构建的仪表板的主要目的是在大屏幕上可用，对许多人可见，并不是作为我们在笔记本电脑上持续保持打开的东西。至少，不是持续的。

这样的仪表板的主要目的应该是什么？在我回答这个问题之前，我们将导入我为本章创建的一个仪表板。

请从左侧菜单中单击+按钮，然后选择导入。在*Grafana.com 仪表板*中键入`9132`，然后按加载按钮。选择*Prometheus 数据源*。随时更改任何值以满足您的需求。尽管如此，您可能希望在更熟悉仪表板之后再进行更改。

无论如何，完成后点击导入按钮。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-25-tk/img/a5120c4e-3ecd-4fb2-8080-840bc9cfa513.png)图 6-11：基于信号的 Grafana 仪表板

您可能会看到一个或多个红色的信号。这是正常的，因为我们集群中的一些资源配置不正确。例如，Prometheus 可能请求的内存比它实际需要的要少。这没关系，因为它可以让我们看到仪表板的运行情况。Gists 中使用的定义不应该是生产就绪的，您已经知道您需要调整它们的资源，以及可能还有其他一些东西。

您会注意到我们导入的仪表板只包含信号。至少在第一次看时是这样。尽管它们可能不像图形和其他类型的面板那样吸引人，但它们作为系统健康的指标要更有效得多。我们不需要一直看着那个仪表板。只要它显示在大屏幕上，我们就可以在做其他事情的同时工作。如果其中一个方框变成红色，我们会注意到。这将是一个行动的呼唤。或者更准确地说，如果一个红色的方框持续保持红色，排除了它是一个自行解决的错误警报的可能性，我们将需要采取一些行动。

您可以将此仪表板视为 Prometheus 警报的补充。它并不取代它们，因为我们将在稍后讨论一些微妙但重要的区别。

我不会描述每个面板，因为它们是我们之前创建的 Prometheus 警报的反映。您现在应该对它们很熟悉。如果有疑问，请单击面板左上角的 i 图标。如果描述不够，请进入面板的编辑模式，检查查询和着色选项。

请注意，仪表板可能不是完美的。您可能需要更改一些变量值或着色阈值。例如，*节点* 面板的阈值设置为 `4,5`。从颜色来看，我们可以看到如果节点数跳到四个，它会变成橙色（警告），如果变成五个，就会变成红色（恐慌）。您的值可能会有所不同。理想情况下，我们应该使用变量而不是硬编码的阈值，但目前在 Grafana 中还不可能。变量并非在所有地方都受支持。作为开源项目的支持者，您应该提交 PR。如果您这样做了，请告诉我。

这是否意味着我们所有的仪表板都应该是绿色和红色的框，里面只有一个数字？我确实认为信号灯应该是“默认”显示。当它们是绿色时，就不需要其他任何东西。如果不是这种情况，我们应该增加信号灯的数量，而不是用随机图表来混乱我们的监视器。然而，这就引出了一个问题。当一些框变成红色甚至橙色时，我们该怎么办？

在框下面，您会找到*图表* 行，带有额外的面板。它们默认情况下是不可见的，有其原因。

在正常情况下，看到它们是没有理由的。但是，如果其中一个信号灯发出警报，我们可以展开*图表*，看到有关问题的更多细节。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-25-tk/img/c5d02e39-5bfa-48fb-ab27-4f8cdb1b7741.png)图 6-12：基于表格和图表的 Grafana 仪表板

*图表* 行内的面板是对*警报* 行内的面板（信号灯）的反映。每个图表显示了与相同位置的单个统计数据相关的更详细的数据（但是不同的行）。这样，我们就不需要浪费时间来弄清哪个图表对应于“红色框”。

相反，我们可以直接跳转到相应的图表。如果右侧第二行的信号灯变成红色，就看右侧第二行的图表。如果多个框变成红色，我们可以快速查看相关的图表，并尝试找到关联（如果有的话）。往往情况下，我们将不得不从 Grafana 切换到 Prometheus，并深入挖掘指标。

像你面前的这个仪表板应该让我们快速启动解决问题。顶部的信号灯提供了警报机制，应该导致下面的图表快速指示出问题的可能原因。从那里开始，如果原因很明显，我们可以转到 Prometheus 并开始调试（如果这个词用得对的话）。

带有信号灯的仪表板应该显示在办公室周围的大屏幕上。它们应该提供问题的指示。相应的图表（和其他面板）提供了对问题的第一印象。Prometheus 作为我们用来挖掘指标直到找到罪魁祸首的调试工具。

我们探讨了一些提供类似功能的东西。但是，Prometheus 警报、信号灯、图表警报和 Grafana 通知之间的区别可能并不清楚？为什么我们没有创建任何 Grafana 通知？我们将在接下来探讨这些问题以及其他一些问题。

# Prometheus 警报 vs. Grafana 通知 vs. 信号灯 vs. 图表警报

标题本身可能会让人感到困惑，所以让我们简要描述一下其中提到的每个元素。

Prometheus 警报和 Grafana 通知具有相同的目的，尽管我们没有探讨后者。我会让你自己学习 Grafana 通知的工作原理。谁知道呢？在接下来的讨论之后，你可能甚至不想花时间去了解它们。

Grafana 通知可以以与 Prometheus 的警报转发方式类似的方式转发给不同的接收者。然而，有一些事情使 Grafana 通知变得不那么吸引人。

如果我们可以通过 Prometheus 警报实现与 Grafana 警报相同的结果，那么前者就具有明显的优势。如果从 Prometheus 触发了警报，那意味着导致触发警报的规则也在 Prometheus 中定义。

因此，评估是在数据源处进行的，我们避免了 Grafana 和 Prometheus 之间不必要的延迟。我们离数据源越近越好。在警报/通知的情况下，更近意味着在 Prometheus 内部。

在 Prometheus 中定义警报的另一个优势是它允许我们做更多的事情。例如，在 Grafana 中没有与 Prometheus 的`for`语句相当的东西。我们无法定义一个只有在条件持续一段时间后才触发的通知。我们需要通过对查询进行非平凡的添加来实现相同的功能。另一方面，Alertmanager 提供了更复杂的方法来过滤警报，对其进行分组，并仅转发符合特定条件的警报。在 Prometheus 和 Alertmanager 中定义警报而不是在 Grafana 中定义通知还有许多其他优点。但我们不会详细讨论所有这些优点。我会留给你去发现所有的区别，除非你已经被说服放弃 Grafana 通知，转而使用 Prometheus 警报和 Alertmanager。

有一个重要的原因你不应该完全忽视 Grafana 通知。你使用的数据源可能没有警报/通知机制，或者它可能是你没有拥有的企业许可证的一部分。由于 Grafana 支持许多不同的数据源，其中 Prometheus 只是其中之一，Grafana 通知允许我们使用任何这些数据源，甚至将它们组合在一起。

基于存储在那里的指标，坚持使用 Prometheus 进行警报/通知。对于其他数据源，Grafana 警报可能是更好的选择，甚至是唯一的选择。

现在我们简要探讨了 Prometheus 警报和 Grafana 通知之间的区别，我们将进入信号量。

信号量（基于单个状态面板的 Grafana 仪表板）不能取代 Prometheus 警报。首先，很难，甚至不可能，创建只有在值达到某个阈值一段时间后才变红的信号量（例如，就像 Prometheus 警报中的`for`语句）。这意味着信号量可能会变红，只是在几分钟后又变回绿色。这并不是一个需要采取行动的原因，因为问题在短时间内会自动解决。如果我们每次在 Grafana 中看到红色就跳起来，我们可能会身体非常健康，但我们不会做太多有用的工作。

信号量是可能存在问题的指示，可能不需要任何干预。虽然应该避免这种错误的积极性，但要完全摆脱它们几乎是不可能的。这意味着我们应该盯着屏幕看，看看红色的方框是否在我们采取行动之前至少持续几分钟。信号量的主要目的不是向个人或团队提供通知，告诉他们应该解决问题。Slack、电子邮件和其他目的地的通知会做到这一点。信号量提供了对系统状态的认识。

最后，我们探讨了在图表上定义的警报。这些是图表中的红线和区域。它们并不是表明出现问题的良好指标。它们并不容易被发现，因此不能引起注意，而且绝对不能取代通知。相反，它们在我们发现存在问题后帮助我们。如果通知或信号量警告我们存在可能需要解决的问题，图表警报将帮助我们确定罪魁祸首。哪个 Pod 处于红色区域？哪个入口收到的请求超出了预期？这些只是我们可以通过图表警报回答的一些问题。

# 现在呢？

Grafana 相对简单易用。如果您知道如何为连接到 Grafana 的数据源（例如 Prometheus）编写查询，那么您已经学会了最具挑战性的部分。其余部分大多是勾选框、选择面板类型和在屏幕上排列事物。主要困难在于避免被创建一堆没有太多价值的花哨仪表板所带走。一个常见的错误是为我们能想象到的一切创建图表。这只会降低那些真正重要的价值。少即是多。

就这样。如果集群专门用于本书，请销毁它；如果不是，或者您打算立即跳到下一章，那就保留它。如果要保留它，请通过执行以下命令删除`grafana`图表。如果我们在接下来的章节中需要它，我会确保它包含在 Gists 中。

```
 1  helm delete grafana --purge
```

在离开之前，您可能希望复习本章的要点。

+   查看带有图形的仪表板是浪费时间。在收到有关问题的通知后访问仪表板会更有意义一些。但是，除了琐碎的问题，其他问题都需要通过 Prometheus 指标进行更深入的挖掘。

+   仪表板并不是为了我们盯着它们看而设计的，尤其是当它们显示在大屏幕上，所有人都能看到时。

+   信号灯比图表更有用，作为查看系统状态的一种方式，尽管它们看起来没有图表那么丰富多彩和令人愉悦。

+   带有信号灯的仪表板应该显示在办公室周围的大屏幕上。它们应该提供问题的指示。相应的图表（和其他面板）提供了对问题的第一印象。Prometheus 作为我们用来深入挖掘指标直到找到罪魁祸首的调试工具。

+   对于基于存储在那里的指标的警报/通知，坚持使用 Prometheus。对于其他数据源，Grafana 警报可能是更好甚至是唯一的选择。
