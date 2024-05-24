# GPT3 探索指南（七）

> 原文：[`zh.annas-archive.org/md5/e19ec4b9c1d08c12abd2983dace7ff20`](https://zh.annas-archive.org/md5/e19ec4b9c1d08c12abd2983dace7ff20)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十三章：监控 Docker 指标

概述

本章将为您提供设置系统监控环境以开始收集容器和资源指标所需的技能。通过本章结束时，您将能够为您的指标制定监控策略，并确定在开始项目开发之前需要考虑的事项。您还将在系统上实施基本的 Prometheus 配置。本章将通过探索用户界面、PromQL 查询语言、配置选项以及收集 Docker 和应用程序指标来扩展您对 Prometheus 的了解。它还将通过将 Grafana 作为 Prometheus 安装的一部分来增强您的可视化和仪表板功能。

# 介绍

在本书的上一章中，我们花了一些时间研究了我们的容器如何在其主机系统上使用资源。我们这样做是为了确保我们的应用程序和容器尽可能高效地运行，但是当我们开始将我们的应用程序和容器转移到更大的生产环境时，使用诸如`docker stats`之类的命令行工具将变得繁琐。您会注意到，随着您的容器数量的增加，仅使用`stats`命令来理解指标变得困难。正如您将在接下来的页面中看到的，通过一点规划和配置，为我们的容器环境设置监控将使我们能够轻松跟踪我们的容器和系统的运行情况，并确保我们的生产服务的正常运行时间。

随着我们转向更敏捷的开发流程，应用程序的开发需要纳入对应用程序的监控。在项目开始阶段制定清晰的应用程序监控计划将允许开发人员将监控工具纳入其开发流程。这意味着在创建应用程序之前，就有必要清楚地了解我们计划如何收集和监控我们的应用程序。

除了应用程序和服务之外，监控基础设施、编排和在我们环境中运行的容器也很重要，这样我们就可以全面了解我们环境中发生的一切。

在制定指标监控政策时，您需要考虑以下一些事项：

+   **应用程序和服务**：这包括您的代码可能依赖的第三方应用程序，这些应用程序不驻留在您的硬件上。它还将包括您的应用程序正在运行的编排服务。

+   **硬件**：有时候，退一步并确保您注意到所有您的服务所依赖的硬件，包括数据库、API 网关和服务器，是很有必要的。

+   **要监控和警报的服务**：随着您的应用程序增长，您可能不仅想要监控特定的服务或网页；您可能还想确保用户能够执行所有的交易。这可能会增加您的警报和监控系统的复杂性。

+   **仪表板和报告**：仪表板和报告可以为非技术用户提供大量有用的信息。

+   **适合您需求的应用程序**：如果您在一家较大的公司工作，他们很可能会有一个您可以选择的应用程序列表。但这并不意味着一刀切。您决定用来监控您的环境的应用程序应该适合特定目的，并得到项目中所有相关人员的认可。

这就是**Prometheus**发挥作用的地方。在本章中，我们将使用 Prometheus 作为监控解决方案，因为它被广泛采用，是开源的，并且免费使用。市场上还有许多其他免费和企业应用程序可提供类似的监控功能，包括自托管的应用程序，如 Nagios 和 SCOM，以及较新的订阅式服务，包括 New Relic、Sumo Logic 和 Datadog。Prometheus 是为了监控云上的服务而构建的。它提供了领先市场的功能，领先于其他主要竞争对手。

其他一些应用程序还提供日志收集和聚合，但我们已经将这部分分配给了一个单独的应用程序，并将在下一章专门讨论我们的 Docker 环境的日志管理。Prometheus 只专注于指标收集和监控，由于在日志管理方面有合适的免费和开源替代品，它并没有将日志管理纳入其重点范围。

# 使用 Prometheus 监控环境指标

Prometheus 最初是由 SoundCloud 创建和开发的，因为他们需要一种监控高度动态的容器环境的方法，并且当时对当前的工具感到不满意，因为他们觉得它不符合他们的需求。Prometheus 被开发为 SoundCloud 监控他们的容器以及运行其服务的基础托管硬件和编排的一种方式。

它最初是在 2012 年创建的，自那时起，该项目一直是免费和开源的，并且是云原生计算基金会的一部分。它还被全球各地的公司广泛采用，这些公司需要更多地了解他们的云环境的性能。

Prometheus 通过从系统中收集感兴趣的指标并将其存储在本地磁盘上的时间序列数据库中来工作。它通过从服务或应用程序提供的 HTTP 端点进行抓取来实现这一点。

端点可以被写入应用程序中，以提供与应用程序或服务相关的基本网络界面，提供指标，或者可以由导出器提供，导出器将从服务或应用程序中获取数据，然后以 Prometheus 能理解的形式暴露出来。

注意

本章多次提到了 HTTP 端点，这可能会引起混淆。您将在本章后面看到，HTTP 端点是由服务或应用程序提供的非常基本的 HTTP 网页。正如您很快将看到的那样，这个 HTTP 网页提供了服务向 Prometheus 公开的所有指标的列表，并提供了存储在 Prometheus 时间序列数据库中的指标值。

Prometheus 包括多个组件：

+   **Prometheus**：Prometheus 应用程序执行抓取和收集指标，并将其存储在其时间序列数据库中。

+   **Grafana**：Prometheus 二进制文件还包括一个基本的网络界面，帮助您开始查询数据库。在大多数情况下，Grafana 也会被添加到环境中，以允许更具视觉吸引力的界面。它将允许创建和存储仪表板，以便更轻松地进行指标监控。

+   **导出器**：导出器为 Prometheus 提供了收集来自不同应用程序和服务的数据所需的指标端点。在本章中，我们将启用 Docker 守护程序来导出数据，并安装`cAdvisor`来提供有关系统上运行的特定容器的指标。

+   **AlertManager**：虽然本章未涉及，但通常会与 Prometheus 一起安装`AlertManager`，以在服务停机或环境中触发的其他警报时触发警报。

Prometheus 还提供了基于 Web 的表达式浏览器，允许您使用功能性的 PromQL 查询语言查看和聚合您收集的时间序列指标。这意味着您可以在收集数据时查看数据。表达式浏览器功能有限，但可以与 Grafana 集成，以便您创建仪表板、监控服务和`AlertManager`，从而在需要时触发警报并得到通知。

Prometheus 易于安装和配置（您很快就会看到），并且可以收集有关自身的数据，以便您开始测试您的应用程序。

由于 Prometheus 的采用率和受欢迎程度，许多公司为其应用程序和服务创建了出口器。在本章中，我们将为您提供一些出口器的示例。

现在是时候动手了。在接下来的练习中，您将在自己的系统上下载并运行 Prometheus 二进制文件，以开始监控服务。

注意

请使用`touch`命令创建文件，并使用`vim`命令在 vim 编辑器中处理文件。

## 练习 13.01：安装和运行 Prometheus

在本练习中，您将下载并解压 Prometheus 二进制文件，启动应用程序，并探索 Prometheus 的 Web 界面和一些基本配置。您还将练习监控指标，例如发送到 Prometheus 接口的总 HTTP 请求。

注意

截至撰写本书时，Prometheus 的最新版本是 2.15.1。应用程序的最新版本可以在以下网址找到：https://prometheus.io/download/。

1.  找到最新版本的 Prometheus 进行安装。使用`wget`命令将压缩的存档文件下载到您的系统上。您在命令中使用的 URL 可能与此处的 URL 不同，这取决于您使用的操作系统和 Prometheus 的版本：

```
wget https://github.com/prometheus/prometheus/releases/download/v2.15.1/prometheus-2.15.1.<operating-system>-amd64.tar.gz
```

1.  使用`tar`命令解压您在上一步下载的 Prometheus 存档。以下命令使用`zxvf`选项解压文件，然后提取存档和文件，并显示详细输出：

```
tar zxvf prometheus-2.15.1.<operating-system>-amd64.tar.gz
```

1.  存档提供了一个完全创建的 Prometheus 二进制应用程序，可以立即启动。进入应用程序目录，查看目录中包含的一些重要文件：

```
cd prometheus-2.15.1.<operating-system>-amd64
```

1.  使用`ls`命令列出应用程序目录中的文件，以查看我们应用程序中的重要文件：

```
ls
```

注意输出，它应该类似于以下内容，其中`prometheus.yml`文件是我们的配置文件。`prometheus`文件是应用程序二进制文件，`tsdb`和数据目录是我们存储时间序列数据库数据的位置：

```
LICENSE    console_libraries    data    prometheus.yml    tsdb
NOTICE    consoles    prometheus    promtool
```

在前面的目录列表中，请注意`console_libraries`和`consoles`目录包括用于查看我们即将使用的 Prometheus Web 界面的提供的二进制文件。`promtool`目录包括您可以使用的工具来处理 Prometheus，包括一个配置检查工具，以确保您的`prometheus.yml`文件有效。

1.  如果您的二进制文件没有问题，应用程序已准备就绪，您应该能够验证 Prometheus 的版本。使用`--version`选项从命令行运行应用程序：

```
./prometheus --version
```

输出应该如下所示：

```
prometheus, version 2.15.1 (branch: HEAD, revision: 8744510c6391d3ef46d8294a7e1f46e57407ab13)
  build user:       root@4b1e33c71b9d
  build date:       20191225-01:12:19
  go version:       go1.13.5
```

1.  您不会对配置文件进行任何更改，但在开始之前，请确保它包含 Prometheus 的有效信息。运行`cat`命令查看文件的内容：

```
cat prometheus.yml 
```

输出中的行数已经减少。从以下输出中可以看出，全局的`scrap_interval`参数和`evaluation_interval`参数设置为`15`秒：

```
# my global config
global:
  scrape_interval:     15s # Set the scrape interval to every 
15 seconds. Default is every 1 minute.
  evaluation_interval: 15s # Evaluate rules every 15 seconds. 
The default is every 1 minute.
  # scrape_timeout is set to the global default (10s).
…
```

如果您有时间查看`prometheus.yml`配置文件，您会注意到它分为四个主要部分：

`global`：这控制服务器的全局配置。配置包括`scrape_interval`，用于了解它将多久抓取目标，以及`evaluation_interval`，用于控制它将多久评估规则以创建时间序列数据和生成规则。

`alerting`：默认情况下，配置文件还将通过 AlertManager 设置警报。

`rule_files`：这是 Prometheus 将定位为其度量收集加载的附加规则的位置。`rule_files`指向规则存储的位置。

`scrape_configs`：这些是 Prometheus 将监视的资源。我们希望监视的任何其他目标都将添加到配置文件的此部分中。

1.  启动 Prometheus 只是运行二进制文件并使用`--config.file`命令行选项指定要使用的配置文件的简单问题。运行以下命令启动 Prometheus：

```
./prometheus --config.file=prometheus.yml
```

几秒钟后，您应该会看到消息“服务器已准备好接收 Web 请求。”：

```
…
msg="Server is ready to receive web requests."
```

1.  输入 URL `http://localhost:9090`。Prometheus 提供了一个易于使用的 Web 界面。如果应用程序已正确启动，您现在应该能够在系统上打开 Web 浏览器。应该会呈现给您表达式浏览器，类似于以下屏幕截图。虽然表达式浏览器看起来并不那么令人印象深刻，但它在开箱即用时具有一些很好的功能。它分为三个不同的部分。

**主菜单**：屏幕顶部的主菜单，黑色背景，允许您通过“状态”下拉菜单查看额外的配置细节，通过“警报”选项查看警报历史，并通过`Prometheus`和`Graph`选项返回主表达式浏览器屏幕。

**表达式编辑器**：这是顶部的文本框，我们可以在其中输入我们的 PromQL 查询或从下拉列表中选择指标。然后，单击“执行”按钮开始显示数据。

**图形和控制台显示**：一旦确定要查询的数据，它将以表格格式显示在“控制台”选项卡中，并以时间序列图形格式显示在“图形”选项卡中，您可以使用“添加图形”按钮在网页下方添加更多图形：

![图 13.1：首次加载表达式浏览器](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_13_01.jpg)

图 13.1：首次加载表达式浏览器

1.  单击“状态”下拉菜单。您将看到以下图像，其中包括有用的信息，包括“运行时和构建信息”以显示正在运行的版本的详细信息，“命令行标志”以运行应用程序，“配置”显示当前运行的`config`文件，以及用于警报规则的“规则”。下拉菜单中的最后两个选项显示“目标”，您当前正在从中获取数据的目标，以及“服务发现”，显示正在监控的自动服务：![图 13.2：状态下拉菜单](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_13_02.jpg)

图 13.2：状态下拉菜单

1.  从“状态”菜单中选择“目标”选项，您将能够看到 Prometheus 正在从哪里抓取数据。您也可以通过转到 URL“HTTP：localhost:9090/targets”来获得相同的结果。您应该会看到类似于以下内容的屏幕截图，因为 Prometheus 目前只监视自身：![图 13.3：Prometheus 目标页面](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_13_03.jpg)

图 13.3：Prometheus 目标页面

1.  单击目标端点。您将能够看到目标公开的指标。现在您可以看到 Prometheus 如何利用其拉取架构从目标中抓取数据。单击链接或打开浏览器，输入 URL`http://localhost:9090/metrics`以查看 Prometheus 指标端点。您应该会看到类似于以下内容的内容，显示了 Prometheus 正在公开的所有指标点，然后由自身抓取：

```
# HELP go_gc_duration_seconds A summary of the GC invocation 
durations.
# TYPE go_gc_duration_seconds summary
go_gc_duration_seconds{quantile="0"} 9.268e-06
go_gc_duration_seconds{quantile="0.25"} 1.1883e-05
go_gc_duration_seconds{quantile="0.5"} 1.5802e-05
go_gc_duration_seconds{quantile="0.75"} 2.6047e-05
go_gc_duration_seconds{quantile="1"} 0.000478339
go_gc_duration_seconds_sum 0.002706392
…
```

1.  通过单击返回按钮或输入 URL`http://localhost:9090/graph`返回到表达式浏览器。单击“执行”按钮旁边的下拉列表，以查看所有可用的指标点：![图 13.4：从表达式浏览器中获得的 Prometheus 指标](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_13_04.jpg)

图 13.4：从表达式浏览器中获得的 Prometheus 指标

1.  从下拉列表或查询编辑器中，添加`prometheus_http_requests_total`指标以查看发送到 Prometheus 应用程序的所有 HTTP 请求。您的输出可能与以下内容不同。单击“执行”按钮，然后单击“图形”选项卡以查看我们数据的可视化视图：![图 13.5：从表达式浏览器中显示的 Prometheus HTTP 请求图](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_13_05.jpg)

图 13.5：从表达式浏览器中显示的 Prometheus HTTP 请求图

如果你对我们到目前为止所取得的成就还感到有些困惑，不要担心。在短时间内，我们已经设置了 Prometheus 并开始收集数据。尽管我们只收集了 Prometheus 本身的数据，但我们已经能够演示如何快速轻松地可视化应用程序执行的 HTTP 请求。接下来的部分将向您展示如何通过对 Prometheus 配置进行小的更改，开始从 Docker 和正在运行的容器中捕获数据。

# 使用 Prometheus 监控 Docker 容器

Prometheus 监控是了解应用程序能力的好方法，但它对于帮助我们监控 Docker 和我们系统上运行的容器并没有太多帮助。幸运的是，我们有两种方法可以收集数据，以便更深入地了解我们正在运行的容器。我们可以使用 Docker 守护程序将指标暴露给 Prometheus，并且还可以安装一些额外的应用程序，比如`cAdvisor`，来收集我们系统上运行的容器的更多指标。

通过对 Docker 配置进行一些小的更改，我们能够将指标暴露给 Prometheus，以便它收集运行在我们系统上的 Docker 守护程序的特定数据。这将部分地收集指标，但不会给我们提供实际运行容器的指标。这就是我们需要安装`cAdvisor`的地方，它是由谷歌专门用来收集我们运行容器指标的。

注意

如果我们需要收集更多关于底层硬件、Docker 和我们的容器运行情况的指标，我们还可以使用`node_exporter`来收集更多的指标。我们将不会在本章中涵盖`node_exporter`，但支持文档可以在以下网址找到：

https://github.com/prometheus/node_exporter。

由于 Docker 已经在您的主机系统上运行，设置它以允许 Prometheus 连接其指标只是向`/etc/docker/daemon.json`文件添加一个配置更改。在大多数情况下，该文件很可能是空白的。如果您已经在文件中有详细信息，您只需将以下示例中的*第 2 行*和*第 3 行*添加到您的配置文件中。*第 2 行*启用了这个`experimental`功能，以便暴露给 Prometheus 收集指标，*第 3 行*设置了这些数据点要暴露的 IP 地址和端口：

```
1 {
2        "experimental": true,
3        "metrics-addr": "0.0.0.0:9191"
4 }
```

由于配置更改，您系统上的 Docker 守护程序需要重新启动才能生效。但一旦发生这种情况，您应该可以在`daemon.json`文件中添加的指定 IP 地址和端口处获得可用的指标。在上面的示例中，这将是在`http://0.0.0.0:9191`。

要安装`cAdvisor`，谷歌提供了一个易于使用的 Docker 镜像，可以从谷歌的云注册表中拉取并在您的环境中运行。

要运行`cAdvisor`，您将运行镜像，挂载所有与 Docker 守护程序和运行容器相关的目录。您还需要确保暴露度量标准将可用的端口。默认情况下，`cAdvisor`配置为在端口`8080`上公开度量标准，除非您对`cAdvisor`的基础图像进行更改，否则您将无法更改。

以下`docker run`命令在容器上挂载卷，例如`/var/lib/docker`和`/var/run`，将端口`8080`暴露给主机系统，并最终使用来自 Google 的最新`cadvisor`镜像：

```
docker run \
  --volume=<host_directory>:<container_directory> \
  --publish=8080:8080 \
  --detach=true \
  --name=cadvisor \
  gcr.io/google-containers/cadvisor:latest
```

注意

对`cAdvisor`的基础图像进行更改不是本章将涵盖的内容，但您需要参考`cAdvisor`文档并对`cAdvisor`代码进行特定更改。

`cAdvisor`镜像还将提供一个有用的 Web 界面来查看这些指标。`cAdvisor`不保存任何历史数据，因此您需要使用 Prometheus 收集数据。

一旦 Docker 守护程序和`cAdvisor`有数据可供 Prometheus 收集，我们需要确保我们有一个定期的配置，将数据添加到时间序列数据库中。应用程序目录中的`prometheus.yml`配置文件允许我们执行此操作。您只需在文件的`scrape_configs`部分添加配置。正如您从以下示例中看到的，您需要添加一个`job_name`参数，并提供指标提供位置的详细信息作为`targets`条目：

```
    - job_name: '<scrap_job_name>'
      static_configs:
      - targets: ['<ip_address>:<port>']
```

一旦目标对 Prometheus 可用，您就可以开始搜索数据。现在我们已经提供了如何开始使用 Prometheus 收集 Docker 指标的分解，以下练习将向您展示如何在运行系统上执行此操作。

## 练习 13.02：使用 Prometheus 收集 Docker 指标

在此练习中，您将配置 Prometheus 开始从我们的 Docker 守护程序收集数据。这将使您能够查看 Docker 守护程序本身特别使用了哪些资源。您还将运行`cAdvisor` Docker 镜像，以开始收集运行容器的特定指标：

1.  要开始从 Docker 守护程序收集数据，您首先需要在系统上启用此功能。首先通过文本编辑器打开`/etc/docker/daemon.json`文件，并添加以下详细信息：

```
1 {
2        "experimental": true,
3        "metrics-addr": "0.0.0.0:9191"
4 }
```

您对配置文件所做的更改将会公开 Docker 守护程序的指标，以允许 Prometheus 进行抓取和存储这些值。要启用此更改，请保存 Docker 配置文件并重新启动 Docker 守护程序。

1.  通过打开您的 Web 浏览器并使用您在配置中设置的 URL 和端口号来验证是否已经生效。输入 URL `http://0.0.0.0:9191/metrics`，您应该会看到一系列指标被公开以允许 Prometheus 进行抓取：

```
# HELP builder_builds_failed_total Number of failed image builds
# TYPE builder_builds_failed_total counter
builder_builds_failed_total{reason="build_canceled"} 0
builder_builds_failed_total{reason="build_target_not_reachable
_error"} 0
builder_builds_failed_total{reason="command_not_supported_
error"} 0
builder_builds_failed_total{reason="dockerfile_empty_error"} 0
builder_builds_failed_total{reason="dockerfile_syntax_error"} 0
builder_builds_failed_total{reason="error_processing_commands_
error"} 0
builder_builds_failed_total{reason="missing_onbuild_arguments_
error"} 0
builder_builds_failed_total{reason="unknown_instruction_error"} 0
…
```

1.  现在，您需要让 Prometheus 知道它可以在哪里找到 Docker 正在向其公开的指标。您可以通过应用程序目录中的`prometheus.yml`文件来完成这一点。不过，在这样做之前，您需要停止 Prometheus 服务的运行，以便配置文件的添加生效。打开 Prometheus 正在运行的终端并按下*Ctrl* + *C*。成功执行此操作时，您应该会看到类似以下的输出：

```
level=info ts=2020-04-28T04:49:39.435Z caller=main.go:718 
msg="Notifier manager stopped"
level=info ts=2020-04-28T04:49:39.436Z caller=main.go:730 
msg="See you next time!"
```

1.  使用文本编辑器打开应用程序目录中的`prometheus.yml`配置文件。转到文件的`scrape_configs`部分的末尾，并添加*行 21*至*34*。额外的行将告诉 Prometheus 它现在可以从已在 IP 地址`0.0.0.0`和端口`9191`上公开的 Docker 守护程序获取指标：

prometheus.yml

```
21 scrape_configs:
22   # The job name is added as a label 'job=<job_name>' to any        timeseries scraped from this config.
23   - job_name: 'prometheus'
24
25     # metrics_path defaults to '/metrics'
26     # scheme defaults to 'http'.
27 
28     static_configs:
29     - targets: ['localhost:9090']
30 
31   - job_name: 'docker_daemon'
32     static_configs:
33     - targets: ['0.0.0.0:9191']
34
```

此步骤的完整代码可以在 https://packt.live/33satLe 找到。

1.  保存您对`prometheus.yml`文件所做的更改，并按照以下方式从命令行再次启动 Prometheus 应用程序：

```
./prometheus --config.file=prometheus.yml
```

1.  如果您返回到 Prometheus 的表达式浏览器，您可以再次验证它现在已配置为从 Docker 守护程序收集数据。从`Status`菜单中选择`Targets`，或者使用 URL `http://localhost:9090/targets`，现在应该包括我们在配置文件中指定的`docker_daemon`作业：![图 13.6：带有 docker_daemon 的 Prometheus Targets](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_13_06.jpg)

图 13.6：带有 docker_daemon 的 Prometheus Targets

1.  通过搜索`engine_daemon_engine_cpus_cpus`来验证您是否正在收集数据。这个值应该与您的主机系统上可用的 CPU 或核心数量相同。将其输入到 Prometheus 表达式浏览器中，然后单击`Execute`按钮：![图 13.7：主机系统上可用的 docker_daemon CPU](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_13_07.jpg)

图 13.7：主机系统上可用的 docker_daemon CPU

1.  Docker 守护程序受限于其可以向 Prometheus 公开的数据量。设置`cAdvisor`镜像以收集有关正在运行的容器的详细信息。在命令行上使用以下`docker run`命令将其作为由 Google 提供的容器运行。`docker run`命令使用存储在 Google 容器注册表中的`cadvisor:latest`镜像，类似于 Docker Hub。无需登录到此注册表；镜像将自动拉到您的系统中：

```
docker run \
  --volume=/:/rootfs:ro \
  --volume=/var/run:/var/run:ro \
  --volume=/sys:/sys:ro \
  --volume=/var/lib/docker/:/var/lib/docker:ro \
  --volume=/dev/disk/:/dev/disk:ro \
  --publish=8080:8080 \
  --detach=true \
  --name=cadvisor \
  gcr.io/google-containers/cadvisor:latest
```

1.  `cAdvisor`带有一个 Web 界面，可以为您提供一些基本功能，但由于它不存储历史数据，您将收集数据并将其存储在 Prometheus 上。现在，打开另一个 Web 浏览器会话，并输入 URL `http://0.0.0.0:8080`，您应该会看到一个类似以下的网页：![图 13.8：cAdvisor 欢迎页面](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_13_08.jpg)

图 13.8：cAdvisor 欢迎页面

1.  输入 URL `http://0.0.0.0:8080/metrics`，以查看`cAdvisor`在 Web 界面上显示的所有数据。

注意

当对 Prometheus 配置文件进行更改时，应用程序需要重新启动才能生效。在我们进行的练习中，我们一直通过停止服务来实现相同的结果。

1.  与 Docker 守护程序一样，配置 Prometheus 定期从指标端点抓取数据。停止运行 Prometheus 应用程序，并再次使用文本编辑器打开`prometheus.yml`配置文件。在配置文件底部，添加另一个`cAdvisor`的配置，具体如下：

prometheus.yml

```
35   - job_name: 'cadvisor'
36     scrape_interval: 5s
37     static_configs:
38     - targets: ['0.0.0.0:8080']
```

此步骤的完整代码可在 https://packt.live/33BuFub 找到。

1.  再次保存您的配置更改，并从命令行运行 Prometheus 应用程序，如下所示：

```
./prometheus --config.file=prometheus.yml
```

如果现在查看 Prometheus Web 界面上的`Targets`，您应该会看到类似以下的内容，显示`cAdvisor`也在我们的界面上可用：

![图 13.9：添加了 cAdvisor 的 Prometheus Targets 页面](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_13_09.jpg)

图 13.9：添加了 cAdvisor 的 Prometheus Targets 页面

1.  通过 Prometheus 的`Targets`页面显示`cAdvisor`现在可用并已连接，验证了 Prometheus 现在正在从`cAdvisor`收集指标数据。您还可以从表达式浏览器中测试这一点，以验证它是否按预期工作。通过从顶部菜单中选择`Graphs`或`Prometheus`进入表达式浏览器。页面加载后，将以下 PromQL 查询添加到查询编辑器中，然后单击`Execute`按钮：

```
(time() - process_start_time_seconds{instance="0.0.0.0:8080",job="cadvisor"})
```

注意

我们开始使用一些更高级的 PromQL 查询，可能看起来有点混乱。本章的下一部分致力于让您更好地理解 PromQL 查询语言。

查询正在使用`process_start_time_seconds`指标，特别是针对`cAdvisor`应用程序和`time()`函数来添加总秒数。您应该在表达式浏览器上看到类似以下的结果：

![图 13.10：来自表达式浏览器的 cAdvisor 正常运行时间](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_13_10.jpg)

图 13.10：来自表达式浏览器的 cAdvisor 正常运行时间

通过这个练习，我们现在有一个正在运行的 Prometheus 实例，并且正在从 Docker 守护程序收集数据。我们还设置了`cAdvisor`，以便为我们提供有关正在运行的容器实例的更多信息。本章的下一部分将更深入地讨论 PromQL 查询语言，以帮助您更轻松地查询 Prometheus 提供的指标。

# 了解 Prometheus 查询语言

正如我们在本章的前几部分中所看到的，Prometheus 提供了自己的查询语言，称为 PromQL。它允许您搜索、查看和聚合存储在 Prometheus 数据库中的时间序列数据。本节将帮助您进一步了解查询语言。Prometheus 中有四种核心指标类型，我们将从描述每种类型开始。

## 计数器

计数器随时间计算元素；例如，这可以是您网站的访问次数。当服务或应用程序重新启动时，计数只会增加或重置。它们适用于在某个时间点计算特定事件的次数。每次计数器更改时，收集的数据中的数字也会反映出来。

计数器通常以`_total`后缀结尾。但由于计数器的性质，每次服务重新启动时，计数器将被重置为 0。使用我们查询中的`rate()`或`irate()`函数，我们将能够随时间查看我们的指标速率，并忽略计数器被重置为 0 的任何时间。`rate()`和`irate()`函数都使用方括号`[]`指定时间值，例如`[1m]`。

如果您对我们正在收集的数据中的计数器示例感兴趣，请打开`cAdvisor`的数据收集的指标页面，网址为`http://0.0.0.0:8080/metrics`。提供的第一个指标之一是`container_cpu_system_seconds_total`。如果我们浏览指标页面，我们将看到有关指标值和类型的信息如下：

```
# HELP container_cpu_system_seconds_total Cumulative system cpu time 
consumed in seconds.
# TYPE container_cpu_system_seconds_total counter
container_cpu_system_seconds_total{id="/",image="",name=""} 
195.86 1579481501131
…
```

现在，我们将研究 Prometheus 中可用的第二种指标类型，也就是仪表。

## 仪表

仪表旨在处理随时间可能减少的值，并设计用于公开某物的当前状态的任何指标。就像温度计或燃料表一样，您将能够看到当前状态值。仪表在功能上受到限制，因为可能会在时间点之间存在缺失值，因此它们比计数器不太可靠，因此计数器仍然用于数据的时间序列表示。

如果我们再次转到`cAdvisor`的指标页面，您可以看到一些指标显示为仪表。我们看到的第一个指标之一是`container_cpu_load_average_10s`，它作为一个仪表提供，类似于以下值：

```
# HELP container_cpu_load_average_10s Value of container cpu load 
average over the last 10 seconds.
# TYPE container_cpu_load_average_10s gauge
container_cpu_load_average_10s{id="/",image="",name=""} 0 
1579481501131
…
```

下一部分将带您了解直方图，Prometheus 中可用的第三种指标类型。

## 直方图

直方图比仪表和计数器复杂得多，并提供额外信息，如观察的总和。它们用于提供一组数据的分布。直方图使用抽样，可以用于在 Prometheus 服务器上估计分位数。

直方图比仪表和计数器更不常见，似乎没有为`cAdvisor`设置，但我们可以在 Docker 守护程序指标中看到一些可用的直方图。转到 URL `http://0.0.0.0:9191/metrics`，您将能够看到列出的第一个直方图指标是`engine_daemon_container_actions_seconds`。这是 Docker 守护程序处理每个操作所需的秒数：

```
# HELP engine_daemon_container_actions_seconds The number of seconds 
it takes to process each container action
# TYPE engine_daemon_container_actions_seconds histogram
engine_daemon_container_actions_seconds_bucket{action="changes",
le="0.005"} 1
…
```

接下来的部分将介绍第四种可用的指标类型，换句话说，摘要。

## 摘要

摘要是直方图的扩展，是在客户端计算的。它们具有更高的准确性优势，但对客户端来说也可能很昂贵。我们可以在 Docker 守护程序指标中看到摘要的示例，其中`http_request_duration_microseconds`在这里列出：

```
# HELP http_request_duration_microseconds The HTTP request latencies in microseconds.
# TYPE http_request_duration_microseconds summary
http_request_duration_microseconds{handler="prometheus",quantile=
"0.5"} 3861.5
…
```

现在，既然我们已经解释了 PromQL 中可用的指标类型，我们可以进一步看看这些指标如何作为查询的一部分实现。

# 执行 PromQL 查询

在表达式浏览器上运行查询很容易，但您可能并不总是能获得所需的信息。只需添加指标名称，例如`countainer_cpu_system_seconds_total`，我们就可以得到相当多的响应。不过，响应的数量取决于我们系统上的容器数量以及我们主机系统上正在运行的每个文件系统的返回值。为了限制结果中提供的响应数量，我们可以使用花括号`{}`搜索特定文本。

考虑以下示例。以下命令提供了我们希望查看的`"cadvisor"`容器的完整名称：

```
container_cpu_system_seconds_total{ name="cadvisor"}
```

以下示例使用与 GO 兼容的正则表达式。该命令查找以`ca`开头并在后面有更多字符的任何名称：

```
container_cpu_system_seconds_total{ name=~"ca.+"} 
```

以下代码片段正在搜索任何名称值不为空的容器，使用不等于（`!=`）值：

```
container_cpu_system_seconds_total{ name!=""}
```

如果我们将任何这些指标搜索放在表达式浏览器中并创建图表，您会注意到图表会随着时间线性上升。正如我们之前提到的，这是因为指标`container_cpu_system_seconds_total`是一个计数器，它只会随着时间增加或被设置为零。通过使用函数，我们可以计算更有用的时间序列数据。以下示例使用`rate()`函数来计算匹配时间序列数据的每秒速率。我们使用了`[1m]`，表示 1 分钟。数字越大，图表就会更平滑：

```
rate(container_cpu_system_seconds_total{name="cadvisor"}[1m])
```

`rate`函数只能用于计数器指标。如果我们运行了多个容器，我们可以使用`sum()`函数将所有值相加，并使用`(name)`函数按容器名称提供图表，就像我们在这里做的那样：

```
sum(rate(container_cpu_system_seconds_total[1m])) by (name)
```

注意

如果您想查看 PromQL 中所有可用函数的列表，请转到官方 Prometheus 文档提供的以下链接：

https://prometheus.io/docs/prometheus/latest/querying/functions/。

PromQL 还允许我们从查询中执行算术运算。在以下示例中，我们使用`process_start_time_seconds`指标并搜索 Prometheus 实例。我们可以从`time()`函数中减去这个时间，该函数给出了当前的日期和时间的时代时间：

```
(time() - process_start_time_seconds{instance="localhost:9090",job="prometheus"})
```

注意

时代时间是从 1970 年 1 月 1 日起的秒数，用一个数字表示；例如，1578897429 被转换为 2020 年 1 月 13 日上午 6:37（GMT）。

我们希望这个 PromQL 入门能让您更深入地了解在项目中使用查询语言。以下练习将通过具体的使用案例，进一步加强我们学到的内容，特别是监视我们正在运行的 Docker 容器。

## 练习 13.03：使用 PromQL 查询语言

在以下练习中，我们将在您的系统上引入一个新的 Docker 镜像，以帮助您演示使用 Prometheus 时特定于 Docker 的一些可用指标。这个练习将加强您到目前为止对 PromQL 查询语言的学习，通过一个具体的使用案例来收集和显示基本网站的指标数据。

1.  打开一个新的终端并创建一个名为`web-nginx`的新目录：

```
mkdir web-nginx; cd web-nginx
```

1.  在`web-nginx`目录中创建一个新文件，命名为`index.html`。用文本编辑器打开新文件，并添加以下 HTML 代码：

```
<!DOCTYPE html>
<html lang="en">
<head>
</head>
<body>
    <h1>
        Hello Prometheus
    </h1>
</body>
</html>
```

1.  用以下命令运行一个新的 Docker 容器。到目前为止，您应该已经熟悉了语法，但以下命令将拉取最新的`nginx`镜像，命名为`web-nginx`，并暴露端口`80`，以便您可以查看在上一步中创建的挂载的`index.html`文件：

```
docker run --name web-nginx --rm -v ${PWD}/index.html:/usr/share/nginx/html/index.html -p 80:80 -d nginx
```

1.  打开一个网络浏览器，访问`http://0.0.0.0`。你应该看到的唯一的东西是问候语`Hello Prometheus`：![图 13.11：示例网页](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_13_11.jpg)

图 13.11：示例网页

1.  如果 Prometheus 没有在您的系统上运行，请打开一个新的终端，并从 Prometheus 应用程序目录中，从命令行启动应用程序：

```
./prometheus --config.file=prometheus.yml
```

注意

在本章的这一部分，我们不会展示所有 PromQL 查询的屏幕截图，因为我们不想浪费太多空间。但是这些查询应该对我们设置的正在运行的容器和系统都是有效的。

1.  现在在 Prometheus 中可用的大部分`cAdvisor`指标将以`container`开头。使用`count()`函数与指标`container_memory_usage_bytes`，以查看当前内存使用量的字节数：

```
count(container_memory_usage_bytes)
```

上述查询提供了系统上正在运行的 28 个结果。

1.  为了限制您正在寻找的信息，可以使用花括号进行搜索，或者如下命令中所示，使用不搜索（`!=`）特定的图像名称。目前，您只有两个正在运行的容器，图像名称为`cAdvisor`和`web-nginx`。通过使用`scalar()`函数，您可以计算系统上随时间运行的容器数量。在输入以下查询后，单击`Execute`按钮：

```
scalar(count(container_memory_usage_bytes{image!=""}) > 0)
```

1.  单击`Graphs`选项卡，现在您应该有一个绘制的查询图。该图应该类似于以下图像，其中您启动了第三个图像`web-nginx`容器，以显示 Prometheus 表达式浏览器如何显示此类型的数据。请记住，您只能在图表中看到一条线，因为这是我们系统上两个容器使用的内存，而没有单独的内存使用值：![图 13.12：来自表达式浏览器的 cAdvisor 指标](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_13_12.jpg)

图 13.12：来自表达式浏览器的 cAdvisor 指标

1.  使用`container_start_time_seconds`指标获取容器启动的 Unix 时间戳：

```
container_start_time_seconds{name="web-nginx"}
```

您将看到类似于 1578364679 的东西，这是自纪元时间以来的秒数，即 1970 年 1 月 1 日。

1.  使用`time()`函数获取当前时间，然后从该值中减去`container_start_time_seconds`，以显示容器已运行多少秒：

```
(time() - container_start_time_seconds{name="web-nginx"})
```

1.  监视您的应用程序通过 Prometheus 的`prometheus_http_request_duration_seconds_count`指标的 HTTP 请求。使用`rate()`函数绘制每个 HTTP 请求到 Prometheus 的持续时间的图表：

```
rate(prometheus_http_request_duration_seconds_count[1m])
```

注意

使用`web-nginx`容器查看其 HTTP 请求时间和延迟将是很好的，但是该容器尚未设置为向 Prometheus 提供此信息。我们将在本章中很快解决这个问题。

1.  使用算术运算符将`prometheus_http_request_duration_seconds_sum`除以`prometheus_http_request_duration_seconds_count`，这将提供所做请求的 HTTP 延迟：

```
rate(prometheus_http_request_duration_seconds_sum[1m]) / rate(prometheus_http_request_duration_seconds_count[1m])
```

1.  使用 `container_memory_usage_bytes` 指标运行以下命令，以查看系统上每个运行容器使用的内存。在此查询中，我们使用 `sum by (name)` 命令按容器名称添加值：

```
sum by (name) (container_memory_usage_bytes{name!=""})
```

如果您执行上述查询，您将在表达式浏览器中看到图形，显示 `web-nginx` 和 `cAdvisor` 容器使用的内存：

![图 13.13：我们系统上运行的两个容器的内存](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_13_13.jpg)

图 13.13：我们系统上运行的两个容器的内存

本节帮助您更加熟悉 `PromQL` 查询语言，并组合您的查询以开始从表达式浏览器查看指标。接下来的部分将提供有关如何开始从在 Docker 中创建的应用程序和服务收集指标的详细信息，使用出口商以一种 Prometheus 友好的方式公开数据。

# 使用 Prometheus 出口商

在本章中，我们已配置应用程序指标以提供数据供 Prometheus 抓取和收集，那么为什么我们需要担心出口商呢？正如您所见，Docker 和 `cAdvisor` 已经很好地公开了数据端点，Prometheus 可以从中收集指标。但这些功能有限。正如我们从我们的新 `web-nginx` 网站中看到的，我们的镜像上运行的网页没有相关的数据暴露出来。我们可以使用出口商来帮助从应用程序或服务中收集指标，然后以 Prometheus 能够理解和收集的方式提供数据。

尽管这可能看起来是 Prometheus 工作方式的一个主要缺陷，但由于 Prometheus 的使用增加以及它是开源的事实，供应商和第三方提供商现在提供出口商来帮助您从应用程序获取指标。

这意味着，通过安装特定库或使用预构建的 Docker 镜像来运行您的应用程序，您可以公开您的指标数据供收集。例如，我们在本章前面创建的 `web-nginx` 应用程序正在 NGINX 上运行。要获取我们的 Web 应用程序的指标，我们可以简单地在运行我们的 Web 应用程序的 NGINX 实例上安装 `ngx_stub_status_prometheus` 库。或者更好的是，我们可以找到某人已经构建好的 Docker 镜像来运行我们的 Web 应用程序。

注意

本章的这一部分重点介绍了 NGINX Exporter，但是大量应用程序的导出器可以在其支持文档或 Prometheus 文档中找到。

在下一个练习中，我们将以我们的`nginx`容器为例，并将导出器与我们的`web-nginx`容器一起使用，以公开可供 Prometheus 收集的指标。

## 练习 13.04：使用应用程序的指标导出器

到目前为止，我们已经使用`nginx`容器提供了一个基本的网页，但我们没有特定的指标可用于我们的网页。在这个练习中，您将使用一个不同的 NGINX 镜像，该镜像带有可以暴露给 Prometheus 的指标导出器。

1.  如果`web-nginx`容器仍在运行，请使用以下命令停止容器：

```
docker kill web-nginx
```

1.  在 Docker Hub 中，您有一个名为`mhowlett/ngx-stud-status-prometheus`的镜像，其中已经安装了`ngx_stub_status_prometheus`库。该库将允许您设置一个 HTTP 端点，以从您的`nginx`容器向 Prometheus 提供指标。将此镜像下载到您的工作环境中：

```
docker pull mhowlett/ngx-stub-status-prometheus
```

1.  在上一个练习中，您使用容器上的默认 NGINX 配置来运行您的 Web 应用程序。要将指标暴露给 Prometheus，您需要创建自己的配置来覆盖默认配置，并将您的指标作为可用的 HTTP 端点提供。在您的工作目录中创建一个名为`nginx.conf`的文件，并添加以下配置细节：

```
daemon off;
events {
}
http {
  server {
    listen 80;
    location / {
      index  index.html;
    }
    location /metrics {
      stub_status_prometheus;
    }
  }
}
```

上述配置将确保您的服务器仍然在端口`80`上可用*第 8 行*。*第 11 行*将确保提供您当前的`index.html`页面，*第 14 行*将设置一个子域`/metrics`，以提供`ngx_stub_status_prometheus`库中可用的详细信息。

1.  提供`index.html`文件的挂载点，以启动`web-nginx`容器并使用以下命令挂载您在上一步中创建的`nginx.conf`配置：

```
docker run --name web-nginx --rm -v ${PWD}/index.html:/usr/html/index.html -v ${PWD}/nginx.conf:/etc/nginx/nginx.conf -p 80:80 -d mhowlett/ngx-stub-status-prometheus
```

1.  您的`web-nginx`应用程序应该再次运行，并且您应该能够从 Web 浏览器中看到它。输入 URL `http://0.0.0.0/metrics`以查看指标端点。您的 Web 浏览器窗口中的结果应该类似于以下信息：

```
# HELP nginx_active_connections_current Current number of 
active connections
# TYPE nginx_active_connections_current gauge
nginx_active_connections_current 2
# HELP nginx_connections_current Number of connections currently 
being processed by nginx
# TYPE nginx_connections_current gauge
nginx_connections_current{state="reading"} 0
nginx_connections_current{state="writing"} 1
nginx_connections_current{state="waiting"} 1
…
```

1.  您仍然需要让 Prometheus 知道它需要从新的端点收集数据。因此，停止 Prometheus 的运行。再次进入应用程序目录，并使用您的文本编辑器，在`prometheus.yml`配置文件的末尾添加以下目标：

prometheus.yml

```
40   - job_name: 'web-nginx'
41     scrape_interval: 5s
42     static_configs:
43     - targets: ['0.0.0.0:80']
```

此步骤的完整代码可在 https://packt.live/3hzbQgj 找到。

1.  保存配置更改，并重新启动 Prometheus 的运行：

```
./prometheus --config.file=prometheus.yml
```

1.  确认 Prometheus 是否配置为从您刚刚创建的新指标端点收集数据。打开您的网络浏览器，输入 URL `http://0.0.0.0:9090/targets`：![图 13.14：显示 web-nginx 的目标页面](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_13_14.jpg)

图 13.14：显示 web-nginx 的目标页面

在这个练习中，您学会了向在您的环境中运行的应用程序添加导出器。我们首先扩展了我们之前的`web-nginx`应用程序，以允许它显示多个 HTTP 端点。然后，我们使用了一个包含了`ngx_stub_status_prometheus`库的 Docker 镜像，以便我们能够显示我们的`web-nginx`统计信息。然后，我们配置了 Prometheus 以从提供的端点收集这些详细信息。

在接下来的部分，我们将设置 Grafana，以便我们能够更仔细地查看我们的数据，并为我们正在收集的数据提供用户友好的仪表板。

# 使用 Grafana 扩展 Prometheus

Prometheus web 界面提供了一个功能表达式浏览器，允许我们在有限的安装中搜索和查看我们的时间序列数据库中的数据。它提供了一个图形界面，但不允许我们保存任何搜索或可视化。Prometheus web 界面也有限，因为它不能在仪表板中分组查询。而且，界面提供的可视化并不多。这就是我们可以通过使用 Grafana 等应用程序进一步扩展我们收集的数据的地方。

Grafana 允许我们直接连接到 Prometheus 时间序列数据库，并执行查询并创建视觉上吸引人的仪表板。Grafana 可以作为一个独立的应用程序在服务器上运行。我们可以预先配置 Grafana Docker 镜像，部署到我们的系统上，并配置到我们的 Prometheus 数据库的连接，并设置一个基本的仪表板来监视我们正在运行的容器。

当您第一次登录 Grafana 时，会显示下面的屏幕，Grafana 主页仪表板。您可以通过点击屏幕左上角的 Grafana 图标来返回到这个页面。这是主要的工作区，您可以在这里开始构建仪表板，配置您的环境，并添加用户插件：

![图 13.15：Grafana 主页仪表板](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_13_15.jpg)

图 13.15：Grafana 主页仪表板

屏幕左侧是一个方便的菜单，可以帮助您进一步配置 Grafana。加号符号将允许您向安装中添加新的仪表板和数据源，而仪表板图标（四个方块）将所有仪表板组织到一个区域进行搜索和查看。在仪表板图标下面是探索按钮，它提供一个表达式浏览器，就像 Prometheus 一样，以便运行 PromQL 查询，而警报图标（铃铛）将带您到窗口，您可以在其中配置在不同事件发生后触发警报。配置图标将带您到屏幕，您可以在其中配置 Grafana 的操作方式，而服务器管理员图标允许您管理谁可以访问您的 Grafana Web 界面以及他们可以拥有什么权限。

在下一个练习中安装 Grafana 时，随意探索界面，但我们将努力尽可能自动化这个过程，以避免对您的工作环境进行任何更改。

## 练习 13.05：在您的系统上安装和运行 Grafana

在这个练习中，您将在您的系统上设置 Grafana，并允许应用程序开始使用您在 Prometheus 数据库中存储的数据。您将使用 Grafana 的 Docker 镜像安装 Grafana，提供界面的简要说明，并开始设置基本的仪表板：

1.  如果 Prometheus 没有运行，请重新启动。另外，请确保您的容器、`cAdvisor`和测试 NGINX 服务器（`web-nginx`）正在运行：

```
./prometheus --config.file=prometheus.yml
```

1.  打开您系统的`/etc/hosts`文件，并将一个域名添加到主机 IP`127.0.0.1`。不幸的是，您将无法使用您一直用来访问 Prometheus 的 localhost IP 地址来自动为 Grafana 配置数据源。诸如`127.0.0.1`、`0.0.0.0`或使用 localhost 的 IP 地址将不被识别为 Grafana 的数据源。根据您的系统，您可能已经添加了许多不同的条目到`hosts`文件中。通常您将会在最前面的 IP 地址列表中有`127.0.0.1`的 IP 地址，它将引用`localhost`域并将`prometheus`修改为这一行，就像我们在以下输出中所做的那样：

```
1 127.0.0.1       localhost prometheus
```

1.  保存`hosts`文件。打开您的网络浏览器并输入 URL`http://prometheus:9090`。Prometheus 表达式浏览器现在应该显示出来。您不再需要提供系统 IP 地址。

1.  要自动配置您的 Grafana 镜像，您需要从主机系统挂载一个`provisioning`目录。创建一个 provisioning 目录，并确保该目录包括额外的目录`dashboards`、`datasources`、`plugins`和`notifiers`，就像以下命令中所示：

```
mkdir -p provisioning/dashboards provisioning/datasources provisioning/plugins provisioning/notifiers
```

1.  在`provisioning/datasources`目录中创建一个名为`automatic_data.yml`的文件。用文本编辑器打开文件并输入以下细节，告诉 Grafana 它将使用哪些数据来提供仪表板和可视化效果。以下细节只是命名数据源，提供数据类型以及数据的位置。在这种情况下，这是您的新 Prometheus 域名：

```
apiVersion: 1
datasources:
- name: Prometheus
  type: prometheus
  url: http://prometheus:9090
  access: direct
```

1.  现在，在`provisioning/dashboards`目录中创建一个名为`automatic_dashboard.yml`的文件。用文本编辑器打开文件并添加以下细节。这只是提供了未来仪表板可以在启动时存储的位置：

```
apiVersion: 1
providers:
- name: 'Prometheus'
  orgId: 1
  folder: ''
  type: file
  disableDeletion: false
  editable: true
  options:
    path: /etc/grafana/provisioning/dashboards
```

您已经做了足够的工作来启动我们的 Grafana Docker 镜像。您正在使用提供的受支持的 Grafana 镜像`grafana/grafana`。

注意

我们目前没有任何代码可以添加为仪表板，但在接下来的步骤中，您将创建一个基本的仪表板，稍后将自动配置。如果您愿意，您也可以搜索互联网上 Grafana 用户创建的现有仪表板，并代替它们进行配置。

1.  运行以下命令以拉取并启动 Grafana 镜像。它使用`-v`选项将您的配置目录挂载到 Docker 镜像上的`/etc/grafana/provisioning`目录。它还使用`-e`选项，使用`GF_SECURITY_ADMIN_PASSWORD`环境变量将管理密码设置为`secret`，这意味着您不需要每次登录到新启动的容器时重置管理密码。最后，您还使用`-p`将您的镜像端口`3000`暴露到我们系统的端口`3000`：

```
docker run --rm -d --name grafana -p 3000:3000 -e "GF_SECURITY_ADMIN_PASSWORD=secret" -v ${PWD}/provisioning:/etc/grafana/provisioning grafana/grafana
```

注意

虽然使用 Grafana Docker 镜像很方便，但每次镜像重新启动时，您将丢失所有更改和仪表板。这就是为什么我们将在演示如何同时使用 Grafana 的同时进行安装配置。 

1.  您已经在端口`3000`上启动了镜像，因此现在应该能够打开 Web 浏览器。在您的 Web 浏览器中输入 URL`http://0.0.0.0:3000`。它应该显示 Grafana 的欢迎页面。要登录到应用程序，请使用具有用户名`admin`和我们指定为`GF_SECURITY_ADMIN_PASSWORD`环境变量的密码的默认管理员帐户：![图 13.16：Grafana 登录屏幕](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_13_16.jpg)

图 13.16：Grafana 登录屏幕

1.  登录后，您将看到 Grafana 主页仪表板。单击屏幕左侧的加号符号，然后选择“仪表板”以添加新的仪表板：![图 13.17：Grafana 欢迎屏幕](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_13_17.jpg)

图 13.17：Grafana 欢迎屏幕

注意

您的 Grafana 界面很可能显示为深色默认主题。我们已将我们的更改为浅色主题以便阅读。要在您自己的 Grafana 应用程序上更改此首选项，您可以单击屏幕左下角的用户图标，选择“首选项”，然后搜索“UI 主题”。

1.  单击“添加新面板”按钮。

1.  要使用`Prometheus`数据添加新查询，请从下拉列表中选择`Prometheus`作为数据源：![图 13.18：在 Grafana 中创建我们的第一个仪表板](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_13_18.jpg)

图 13.18：在 Grafana 中创建我们的第一个仪表板

1.  在指标部分，添加 PromQL 查询`sum (rate (container_cpu_usage_seconds_total{image!=""}[1m])) by (name)`。该查询将提供系统上所有正在运行的容器的详细信息。它还将随时间提供每个容器的 CPU 使用情况。根据您拥有的数据量，您可能希望在`查询选项`下拉菜单中将`相对时间`设置为`15m`。

此示例使用`15m`来确保您有足够的数据用于图表，但是此时间范围可以设置为您希望的任何值：

![图 13.19：添加仪表板指标](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_13_19.jpg)

图 13.19：添加仪表板指标

1.  选择`显示选项`按钮以向仪表板面板添加标题。在下图中，面板的标题设置为`CPU Container Usage`：![图 13.20：添加仪表板标题](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_13_20.jpg)

图 13.20：添加仪表板标题

1.  单击屏幕顶部的保存图标。这将为您提供命名仪表板的选项—在这种情况下为`Container Monitoring`。单击`保存`后，您将被带到已完成的仪表板屏幕，类似于这里的屏幕：![图 13.21：仪表板屏幕](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_13_21.jpg)

图 13.21：仪表板屏幕

1.  在仪表板屏幕顶部，在保存图标的左侧，您将有选项以`JSON`格式导出您的仪表板。如果这样做，您可以使用此`JSON`文件添加到您的配置目录中。当您运行时，它将帮助您将仪表板安装到 Grafana 映像中。选择`导出`并将文件保存到`/tmp`目录，文件名将默认为类似于仪表板名称和时间戳数据的内容。在此示例中，它将`JSON`文件保存为`Container Monitoring-1579130313205.json`。还要确保未打开`用于外部共享的导出`选项，如下图所示：![图 13.22：将仪表板导出为 JSON](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_13_22.jpg)

图 13.22：将您的仪表板导出为 JSON

1.  要将仪表板添加到您的配置文件中，您需要首先停止运行 Grafana 映像。使用以下`docker kill`命令执行此操作：

```
docker kill grafana
```

1.  将您在*步骤 15*中保存的仪表板文件添加到`provisioning/dashboards`目录，并将文件命名为`ContainerMonitoring.json`作为复制的一部分，如下命令所示：

```
cp /tmp/ContainerMonitoring-1579130313205.json provisioning/dashboards/ContainerMonitoring.json
```

1.  重新启动 Grafana 映像，并使用默认管理密码登录应用程序：

```
docker run --rm -d --name grafana -p 3000:3000 -e "GF_SECURITY_ADMIN_PASSWORD=secret" -v ${PWD}/provisioning:/etc/grafana/provisioning grafana/grafana
```

注意

通过这种方式预配仪表板和数据源，这意味着您将无法再从 Grafana Web 界面创建仪表板。从现在开始，当您创建仪表板时，您将被要求将仪表板保存为 JSON 文件，就像我们在导出仪表板时所做的那样。

1.  现在登录主页仪表板。您应该会看到`Container Monitoring`仪表板作为最近访问的仪表板可用，但如果您点击屏幕顶部的主页图标，它也会显示在您的 Grafana 安装的`General`文件夹中可用：![图 13.23：可用和预配的容器监控仪表板](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_13_23.jpg)

图 13.23：可用和预配的容器监控仪表板

我们现在已经设置了一个完全功能的仪表板，当我们运行 Grafana Docker 镜像时会自动加载。正如你所看到的，Grafana 提供了一个专业的用户界面，帮助我们监视正在运行的容器的资源使用情况。

这就是我们本节的结束，我们向您展示了如何使用 Prometheus 收集指标，以帮助监视您的容器应用程序的运行情况。接下来的活动将使用您在之前章节中学到的知识，进一步扩展您的安装和监控。

## 活动 13.01：创建一个 Grafana 仪表板来监视系统内存

在以前的练习中，您已经设置了一个快速仪表板，以监视我们的 Docker 容器使用的系统 CPU。正如您在上一章中所看到的，监视正在运行的容器使用的系统内存也很重要。在这个活动中，您被要求创建一个 Grafana 仪表板，用于监视正在运行的容器使用的系统内存，并将其添加到我们的`Container Monitoring`仪表板中，确保在启动我们的 Grafana 镜像时可以预配：

您需要完成此活动的步骤如下：

1.  确保您的环境正在被 Prometheus 监视，并且 Grafana 已安装在您的系统上。确保您使用 Grafana 在 Prometheus 上存储的时间序列数据上进行搜索。

1.  创建一个 PromQL 查询，监视正在运行的 Docker 容器使用的容器内存。

1.  保存您的`Container Monitoring`仪表板上的新仪表板面板。

1.  确保新的改进后的`Container Monitoring`仪表板现在在启动 Grafana 容器时可用和预配。

**预期输出**：

当您启动 Grafana 容器时，您应该在仪表板顶部看到新创建的`内存容器使用情况`面板：

![图 13.24：显示内存使用情况的新仪表板面板](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_13_24.jpg)

图 13.24：显示内存使用情况的新仪表板面板

注意

此活动的解决方案可以通过此链接找到。

下一个活动将确保您能够舒适地使用导出器，并向 Prometheus 添加新的目标，以开始跟踪全景徒步应用程序中的额外指标。

## 活动 13.02：配置全景徒步应用程序以向 Prometheus 暴露指标

您的指标监控环境开始看起来相当不错，但是全景徒步应用程序中有一些应用可能会提供额外的细节和指标供监控，例如在您的数据库上运行的 PostgreSQL 应用程序。选择全景徒步应用程序中的一个应用程序，将其指标暴露给您的 Prometheus 环境：

您需要完成此活动的步骤如下：

1.  确保 Prometheus 正在您的系统上运行并收集指标。

1.  选择作为全景徒步应用程序一部分运行的服务或应用程序，并研究如何暴露指标以供 Prometheus 收集。

1.  将更改实施到您的应用程序或服务中。

1.  测试您的更改，并验证指标是否可供收集。

1.  配置 Prometheus 上的新目标以收集新的全景徒步应用程序指标。

1.  验证您能够在 Prometheus 上查询您的新指标。

成功完成活动后，您应该在 Prometheus 的`Targets`页面上看到`postgres-web`目标显示：

![图 13.25：在 Prometheus 上显示的新 postgres-web 目标页面](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_13_25.jpg)

图 13.25：在 Prometheus 上显示的新 postgres-web 目标页面

注意

此活动的解决方案可以通过此链接找到。

# 总结

在本章中，我们深入研究了度量标准和监控我们的容器应用程序和服务。我们从讨论为什么您需要在度量监控上制定清晰的策略以及为什么您需要在项目开始开发之前做出许多决策开始。然后，我们介绍了 Prometheus，并概述了其历史、工作原理以及为什么它在很短的时间内就变得非常流行。然后是重新开始工作的时候，我们将 Prometheus 安装到我们的系统上，熟悉使用 Web 界面，开始从 Docker 收集度量标准（进行了一些小的更改），并使用`cAdvisor`收集正在运行的容器的度量标准。

Prometheus 使用的查询语言有时可能会有点令人困惑，因此我们花了一些时间来探索 PromQL，然后再看看如何使用导出器来收集更多的度量标准。我们在本章结束时将 Grafana 集成到我们的环境中，显示来自 Prometheus 的时间序列数据，并创建有用的仪表板和可视化数据。

我们的下一章将继续监控主题，收集和监控我们正在运行的容器的日志数据。


# 第十四章：收集容器日志

概述

在上一章中，我们确保为我们运行的 Docker 容器和服务收集了指标数据。本章将在此基础上，致力于收集和监控 Docker 容器和其中运行的应用程序的日志。它将从讨论为什么我们需要为我们的开发项目建立清晰的日志监控策略开始，并讨论我们需要记住的一些事情。然后，我们将介绍我们日志监控策略中的主要角色 - 即 Splunk - 以收集、可视化和监控我们的日志。我们将安装 Splunk，从我们的系统和运行的容器中转发日志数据，并使用 Splunk 查询语言设置与我们收集的日志数据配合工作的监控仪表板。通过本章的学习，您将具备为您的 Docker 容器项目建立集中式日志监控服务的技能。

# 介绍

每当我们的运行应用程序或服务出现问题时，我们通常首先在应用程序日志中寻找线索，以了解问题的原因。因此，了解如何收集日志并监控项目的日志事件变得非常重要。

随着我们实施基于 Docker 的微服务架构，确保我们能够查看应用程序和容器生成的日志变得更加重要。随着容器和服务数量的增加，尝试单独访问每个运行的容器作为故障排除的手段变得越来越不方便。对于可伸缩的应用程序，根据需求进行伸缩，跨多个容器跟踪日志错误可能变得越来越困难。

确保我们有一个合适的日志监控策略将有助于我们排除应用程序故障，并确保我们的服务以最佳效率运行。这也将帮助我们减少在日志中搜索所花费的时间。

在为您的项目构建日志监控策略时，有一些事情您需要考虑：

+   您的应用程序将使用一个框架来处理日志。有时，这可能会对容器造成负担，因此请确保测试您的容器，以确保它们能够在不出现与此日志框架相关的任何问题的情况下运行。

+   容器是瞬时的，因此每次关闭容器时日志都会丢失。您必须将日志转发到日志服务或将日志存储在数据卷中，以确保您可以解决可能出现的任何问题。

+   Docker 包含一个日志驱动程序，用于将日志事件转发到主机上运行的 Syslog 实例。除非您使用 Docker 的企业版，否则如果您使用特定的日志驱动程序，`log`命令将无法使用（尽管对于 JSON 格式的日志可以使用）。

+   日志聚合应用通常会根据其所摄取的数据量向您收费。而且，如果您在环境中部署了一个服务，您还需要考虑存储需求，特别是您计划保留日志的时间有多长。

+   您需要考虑您的开发环境与生产环境的运行方式。例如，在开发环境中没有必要长时间保留日志，但生产环境可能要求您保留一段时间。

+   您可能不仅需要应用程序数据。您可能需要收集应用程序的日志，应用程序运行的容器以及应用程序和容器都在运行的基础主机和操作系统的日志。

我们可以在日志监控策略中使用许多应用程序，包括 Splunk、Sumo Logic、Nagios Logs、Data Dog 和 Elasticsearch。在本章中，我们决定使用 Splunk 作为我们的日志监控应用程序。它是最古老的应用程序之一，拥有庞大的支持和文档社区。在处理数据和创建可视化方面也是最好的。

在接下来的章节中，您将看到如何轻松地启动、运行和配置应用程序，以便开始监控系统日志和我们的容器应用程序。

# 介绍 Splunk

在 Docker 的普及之前很久，Splunk 于 2003 年成立，旨在帮助公司从不断增长的应用和服务提供的大量数据中发现一些模式和信息。Splunk 是一款软件应用，允许您从应用程序和硬件系统中收集日志和数据。然后，它让您分析和可视化您收集的数据，通常在一个中央位置。

Splunk 允许您以不同的格式输入数据，在许多情况下，Splunk 将能够识别数据所在的格式。然后，您可以使用这些数据来帮助排除应用程序故障，创建监控仪表板，并在特定事件发生时创建警报。

注意

在本章中，我们只会触及 Splunk 的一部分功能，但如果您感兴趣，有许多宝贵的资源可以向您展示如何从数据中获得运营智能，甚至使用 Splunk 创建机器学习和预测智能模型。

Splunk 提供了许多不同的产品来满足您的需求，包括 Splunk Cloud，适用于希望选择云日志监控解决方案的用户和公司。

对于我们的日志监控策略，我们将使用 Splunk Enterprise。它易于安装，并带有大量功能。在使用 Splunk 时，您可能已经知道许可成本是按您发送到 Splunk 的日志数据量收费，然后对其进行索引。Splunk Enterprise 允许您在试用期内每天索引高达 500 MB 的数据。60 天后，您可以选择升级许可证，或者继续使用免费许可证，该许可证将继续允许您每天记录 500 MB 的数据。用户可以申请开发者许可证，该许可证允许用户每天记录 10 GB 的数据。

要开始使用 Splunk，我们首先需要了解其基本架构。这将在下一节中讨论。

## Splunk 安装的基本架构

通过讨论 Splunk 的架构，您将了解每个部分的工作原理，并熟悉我们在本章中将使用的一些术语：

+   **索引器**：对于较大的 Splunk 安装，建议您设置专用和复制的索引器作为环境的一部分。索引器的作用是索引您的数据 - 也就是说，组织您发送到 Splunk 的日志数据。它还添加元数据和额外信息，以帮助加快搜索过程。然后索引器将存储您的日志数据，这些数据已准备好供搜索头使用和查询。

+   **搜索头**：这是主要的 Web 界面，您可以在其中执行搜索查询和管理您的 Splunk 安装。搜索头将与索引器连接，以查询已收集和存储在它们上面的数据。在较大的安装中，您甚至可能有多个搜索头，以允许更多的查询和报告进行。

+   **数据转发器**：通常安装在您希望收集日志的系统上。它是一个小型应用程序，配置为在您的系统上收集日志，然后将数据推送到您的 Splunk 索引器。

在接下来的部分中，我们将使用官方的 Splunk Docker 镜像，在活动容器上同时运行搜索头和索引器。我们将继续在 Splunk 环境中使用 Docker，因为它还提供了索引器和数据转发器作为受支持的 Docker 镜像。这使您可以在继续安装之前测试和沙盒化安装。

注意

请注意，我们使用 Splunk Docker 镜像是为了简单起见。如果需要，它将允许我们移除应用程序。如果您更喜欢这个选项，安装应用程序并在您的系统上运行它是简单而直接的。

Splunk 的另一个重要特性是，它包括由 Splunk 和其他第三方提供者提供的大型应用程序生态系统。这些应用程序通常是为了帮助用户监视将日志转发到 Splunk 的服务而创建的，然后在搜索头上安装第三方应用程序。这将为这些日志提供专门的仪表板和监控工具。例如，您可以将日志从思科设备转发，然后安装思科提供的 Splunk 应用程序，以便在开始索引数据后立即开始监视您的思科设备。您可以创建自己的 Splunk 应用程序，但要使其列为官方提供的应用程序，它需要经过 Splunk 的认证。

注意

有关可用的免费和付费 Splunk 应用程序的完整列表，Splunk 已设置他们的 SplunkBase，允许用户从以下网址搜索并下载可用的应用程序：[`splunkbase.splunk.com/apps/`](https://splunkbase.splunk.com/apps/)。

这是对 Splunk 的快速介绍，应该帮助您了解接下来我们将要做的一些工作。然而，让您熟悉 Splunk 的最佳方法是在您的系统上运行容器，这样您就可以开始使用它了。

# 在 Docker 上安装和运行 Splunk

作为本章的一部分，我们将使用官方的 Splunk Docker 镜像在我们的系统上安装它。尽管直接在主机系统上安装 Splunk 并不是一个困难的过程，但将 Splunk 安装为容器镜像将有助于扩展我们对 Docker 的知识，并进一步提升我们的技能。

我们的 Splunk 安装将在同一个容器上同时运行搜索头和索引器，因为我们将监控的数据量很小。然而，如果您要在多个用户访问数据的生产环境中使用 Splunk，您可能需要考虑安装专用的索引器，以及一个或多个专用的搜索头。

注意

在本章中，我们将使用 Splunk Enterprise 版本 8.0.2。本章中将进行的大部分工作不会太高级，因此应该与将来的 Splunk 版本兼容。

在我们开始使用 Splunk 之前，让我们先了解一下 Splunk 应用程序使用的三个主要目录。虽然我们只会执行基本的配置和更改，但以下细节将有助于理解应用程序中的目录是如何组织的，并且会帮助您进行 Docker 容器设置。

在主要的 Splunk 应用程序目录中，通常安装为`/opt/splunk/`，您将看到这里解释的三个主要目录：

+   **etc 目录**：这是我们 Splunk 安装的所有配置信息所在的地方。我们将创建一个目录，并将 etc 目录挂载为我们运行的容器的一部分，以确保我们对配置所做的任何更改都得以保留，当我们关闭应用程序时不会被销毁。这将包括用户访问、软件设置和保存的搜索、仪表板以及 Splunk 应用程序。

+   **bin 目录**：这是存储所有 Splunk 应用程序和二进制文件的地方。在这一点上，您不需要访问此目录或更改此目录中的文件，但这可能是您需要进一步调查的内容。

+   **var 目录**：Splunk 的索引数据和应用程序日志存储在这个目录中。当我们开始使用 Splunk 时，我们不会费心保留我们存储在 var 目录中的数据。但是当我们解决了部署中的所有问题后，我们将挂载 var 目录以保留我们的索引数据，并确保我们可以继续对其进行搜索，即使我们的 Splunk 容器停止运行。

注意

要下载本章中使用的一些应用程序和内容，您需要在[splunk.com](http://splunk.com)上注册一个帐户以获取访问权限。注册时无需购买任何东西或提供信用卡详细信息，这只是 Splunk 用来跟踪谁在使用他们的应用程序的手段。

要运行我们的 Splunk 容器，我们将从 Docker Hub 拉取官方镜像，然后运行类似以下的命令：

```
docker run --rm -d -p <port:port> -e "SPLUNK_START_ARGS=--accept-license" -e "SPLUNK_PASSWORD=<admin-password>" splunk/splunk:latest
```

正如您从前面的命令中所看到的，我们需要暴露所需的相关端口，以便访问安装的不同部分。您还会注意到，我们需要指定两个环境变量作为运行容器的一部分。第一个是`SPLUNK_START_ARGS`，我们将其设置为`--accept-license`，这是您在安装 Splunk 时通常会接受的许可证。其次，我们需要为`SPLUNK_PASSWORD`环境变量提供一个值。这是管理员帐户使用的密码，也是您首次登录 Splunk 时将使用的帐户。

我们已经提供了大量的理论知识，为本章的下一部分做好准备。现在是时候将这些理论付诸实践，让我们的 Splunk 安装运行起来，这样我们就可以开始从主机系统收集日志。在接下来的练习中，我们将在运行的主机系统上安装 Splunk 数据转发器，以便收集日志并转发到我们的 Splunk 索引器。

注意

请使用`touch`命令创建文件，并使用`vim`命令在文件上使用 vim 编辑器进行操作。

## 练习 14.01：运行 Splunk 容器并开始收集数据

在这个练习中，您将使用 Docker Hub 上提供的官方 Splunk Docker 镜像来运行 Splunk。您将进行一些基本的配置更改，以帮助管理用户访问镜像上的应用程序，然后您将在系统上安装一个转发器，以便开始在 Splunk 安装中消耗日志：

1.  创建一个名为`chapter14`的新目录：

```
mkdir chapter14; cd chapter14/
```

1.  使用`docker pull`命令从 Docker Hub 拉取由 Splunk 创建的最新支持的镜像。仓库简单地列为`splunk/splunk`：

```
docker pull splunk/splunk:latest
```

1.  使用`docker run`命令在您的系统上运行 Splunk 镜像。使用`--rm`选项确保容器在被杀死时完全被移除，使用`-d`选项将容器作为守护进程在系统后台运行，使用`-p`选项在主机上暴露端口`8000`，以便您可以在 Web 浏览器上查看应用程序。最后，使用`-e`选项在启动容器时向系统提供环境变量：

```
docker run --rm -d -p 8000:8000 -e "SPLUNK_START_ARGS=--accept-license" -e "SPLUNK_PASSWORD=changeme" --name splunk splunk/splunk:latest
```

在上述命令中，您正在为 Web 界面暴露端口`8000`，使用一个环境变量接受 Splunk 许可，并将管理密码设置为`changeme`。该命令还以`-d`作为守护进程在后台运行。

1.  Splunk 将需要 1 到 2 分钟来启动。使用`docker logs`命令来查看应用程序的进展情况：

```
docker logs splunk
```

当您看到类似以下内容的行显示`Ansible playbook complete`时，您应该准备好登录了：

```
…
Ansible playbook complete, will begin streaming 
```

1.  输入 URL `http://0.0.0.0:8000` 来访问我们的 Splunk 安装的 Web 界面。您应该会看到类似以下的内容。要登录，请使用`admin`作为用户名，并使用在运行镜像时设置的`SPLUNK_PASSWORD`环境变量作为密码。在这种情况下，您将使用`changeme`：![图 14.1：Splunk Web 登录页面](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_14_01.jpg)

图 14.1：Splunk Web 登录页面

登录后，您将看到 Splunk 主屏幕，它应该看起来类似于以下内容。主屏幕分为不同的部分，如下所述：

![图 14.2：Splunk 欢迎屏幕](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_14_02.jpg)

图 14.2：Splunk 欢迎屏幕

主屏幕可以分为以下几个部分：

- **Splunk>**：这是屏幕左上角的图标。如果您简单地点击该图标，它将随时带您回到主屏幕。

- **应用程序菜单**：这在屏幕的左侧，允许您安装和配置 Splunk 应用程序。

- **菜单栏**：它位于屏幕顶部，包含不同的选项，取决于您在帐户中拥有的特权级别。由于您已经以管理员帐户登录，您可以获得完整的选项范围。这使我们能够配置和管理 Splunk 的运行和管理方式。菜单栏中的主要配置选项是“设置”。它提供了一个大的下拉列表，让您控制 Splunk 运行的大部分方面。

- **主工作区**：主工作区填充了页面的其余部分，您可以在这里开始搜索数据，设置仪表板，并开始可视化数据。您可以设置一个主仪表板，这样每次登录或单击“Splunk>`图标时，您也会看到此仪表板。我们将在本章后面设置主仪表板，以向您展示如何操作。

1.  您可以开始对我们的 Splunk 配置进行更改，但如果容器因某种原因停止运行，所有更改都将丢失。相反，创建一个目录，您可以在其中存储所有 Splunk 环境所需的相关配置信息。使用以下命令停止当前正在运行的 Splunk 服务器：

```
docker kill splunk
```

1.  创建一个可以挂载到 Splunk 主机上的目录。为此目的命名为`testSplunk`：

```
mkdir -p ${PWD}/testsplunk
```

1.  再次运行 Splunk 容器，这次使用`-v`选项将您在上一步创建的目录挂载到容器上的`/opt/splunk/etc`目录。暴露额外的端口`9997`，以便稍后将数据转发到我们的 Splunk 安装中。

```
docker run --rm -d -p 8000:8000 -p 9997:9997 -e 'SPLUNK_START_ARGS=--accept-license' -e 'SPLUNK_PASSWORD=changeme' -v ${PWD}/testsplunk:/opt/splunk/etc/ --name splunk splunk/splunk
```

1.  一旦 Splunk 再次启动，以管理员帐户重新登录到 Splunk Web 界面。

1.  向系统添加一个新用户，以确保通过屏幕顶部的“设置”菜单将相关配置详细信息保存在您的挂载目录中。单击“设置”菜单：![图 14.3：Splunk 设置菜单](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_14_03.jpg)

图 14.3：Splunk 设置菜单

1.  打开“设置”菜单，移动到底部部分，然后在“用户和身份验证”部分中单击“用户”。您应该看到已在 Splunk 安装中创建的所有用户的列表。目前只有管理员帐户会列在其中。要创建新用户，请单击屏幕顶部的“新用户”按钮。

1.  您将看到一个网页表单，您可以在其中添加新用户帐户的详细信息。填写新用户的详细信息。一旦您对添加的详细信息感到满意，点击屏幕底部的“保存”按钮：![图 14.4：在 Splunk 上创建新用户](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_14_04.jpg)

图 14.4：在 Splunk 上创建新用户

1.  为了确保您现在将这些数据保存在您的挂载目录中，请返回到您的终端，查看新用户是否存储在您的挂载目录中。只需使用以下命令列出`testsplunk/users`目录中的目录：

```
ls testsplunk/users/
```

您应该看到已为您在上一步中创建的新帐户设置了一个目录；在这种情况下是`vincesesto`：

```
admin        splunk-system-user        users.ini
users.ini.default        vincesesto
```

1.  现在是时候开始向在您的系统上运行的 Splunk 实例发送数据了。在开始从正在运行的 Docker 容器中收集数据之前，在您的运行系统上安装一个转发器，并从那里开始转发日志。要访问特定于您系统的转发器，请转到以下网址并下载特定于您操作系统的转发器：[`www.splunk.com/en_us/download/universal-forwarder.html`](https://www.splunk.com/en_us/download/universal-forwarder.html)。

1.  按照提示接受许可证，以便您可以使用该应用程序。还要接受安装程序中呈现的默认选项：![图 14.5：Splunk 转发器安装程序](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_14_05.jpg)

图 14.5：Splunk 转发器安装程序

1.  转发器通常会自动启动。通过访问终端并使用`cd`命令切换到系统安装目录，验证转发器是否正在运行。对于 Splunk 转发器，二进制和应用程序文件将位于`/opt/splunkforwarder/bin/`目录中：

```
cd /opt/Splunkforwarder/bin/
```

1.  在`bin`目录中，通过运行`./splunk status`命令来检查转发器的状态，如下所示：

```
./splunk status
```

如果它正在运行，您应该看到类似于以下输出：

```
splunkd is running (PID: 2076).
splunk helpers are running (PIDs: 2078).
```

1.  如果转发器在安装时没有启动，请使用以下命令从`bin`目录运行带有`start`选项的转发器：

```
./splunk start
```

提供的输出将显示 Splunk 守护程序和服务的启动。它还将显示正在系统上运行的服务的进程 ID（PID）：

```
splunkd is running (PID: 2076).
splunk helpers are running (PIDs: 2078).
Splunk> Be an IT superhero. Go home early.
...
Starting splunk server daemon (splunkd)...Done
```

1.  您需要让 Splunk 转发器知道它需要发送数据的位置。在本练习的*步骤 8*中，我们确保运行了具有端口`9997`的 Splunk 容器，以便出于这个特定的原因暴露。使用`./splunk`命令告诉转发器将数据发送到我们运行在 IP 地址`0.0.0.0`端口`9997`上的 Splunk 容器，使用我们 Splunk 实例的管理员用户名和密码：

```
./splunk add forward-server 0.0.0.0:9997 -auth admin:changeme
```

该命令应返回类似以下的输出：

```
Added forwarding to: 0.0.0.0:9997.
```

1.  最后，为了完成 Splunk 转发器的设置，指定一些日志文件转发到我们的 Splunk 容器。使用转发器上的`./splunk`命令监视我们系统的`/var/log`目录中的文件，并将它们发送到 Splunk 容器进行索引，以便我们可以开始查看它们：

```
./splunk add monitor /var/log/
```

1.  几分钟后，如果一切正常，您应该有一些日志事件可以在 Splunk 容器上查看。返回到您的网络浏览器，输入以下 URL 以打开 Splunk 搜索页面：`http://0.0.0.0:8000/en-US/app/search/search`。

注意

以下步骤使用非常基本的 Splunk 搜索查询来搜索安装中的所有数据。如果您之前没有使用过 Splunk 查询语言，不用担心；我们将花费一个完整的部分，*使用 Splunk 查询语言*，更深入地解释查询语言。

1.  通过简单地将星号(`*`)作为搜索查询添加，执行基本搜索，如下截图所示。如果一切正常，您应该开始在搜索页面的结果区域看到日志事件：![图 14.6：Splunk 搜索窗口，显示来自我们的转发器的数据](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_14_06.jpg)

图 14.6：Splunk 搜索窗口，显示来自我们的转发器的数据

1.  在本练习的最后部分，您将练习将数据上传到 Splunk 的最简单方法，即直接将文件上传到正在运行的系统中。从[`packt.live/3hFbh4C`](https://packt.live/3hFbh4C)下载名为`weblog.csv`的示例数据文件，并将其放在您的`/tmp`目录中。

1.  返回到您的 Splunk 网络界面，单击`设置`菜单选项。从菜单选项的右侧选择`添加数据`，如下截图所示：![图 14.7：直接导入文件到 Splunk](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_14_07.jpg)

图 14.7：直接导入文件到 Splunk

1.  单击屏幕底部的“从我的计算机上传文件”：![图 14.8：在 Splunk 上上传文件](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_14_08.jpg)

图 14.8：在 Splunk 上上传文件

1.  下一个屏幕将允许您从您的计算机中选择源文件。在此练习中，选择您之前下载的`weblog.csv`文件。当您选择文件后，请点击屏幕顶部的`Next`按钮。

1.  设置`Source Type`以选择或接受 Splunk 查看数据的格式。在这种情况下，它应该已经将您的数据识别为`.csv`文件。点击`Next`按钮。

1.  `Input Settings`页面让您设置主机的名称，但将索引保留为默认值。点击`Review`按钮：![图 14.9：输入设置页面](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_14_09.jpg)

图 14.9：输入设置页面

1.  如果所有条目看起来正确，请点击`Submit`按钮。然后，点击`Start Searching`，您应该看到您的搜索屏幕，以及可供搜索的示例 Web 日志数据。它应该看起来类似于以下内容：![图 14.10：在 Splunk 中搜索导入的文件](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_14_10.jpg)

图 14.10：在 Splunk 中搜索导入的文件

在短时间内，我们已经在系统上设置了 Splunk 搜索头和索引器，并安装了 Splunk 转发器将日志发送到索引器和搜索头。我们还手动向我们的索引中添加了日志数据，以便我们可以查看它。

本章的下一部分将重点介绍如何将 Docker 容器日志传输到我们正在运行的新 Splunk 容器中。

# 将容器日志传输到 Splunk

我们的日志监控环境开始成形，但我们需要将我们的 Docker 容器日志传输到应用程序中，以使其值得工作。我们已经设置了 Splunk 转发器，将日志从我们的系统发送到`/var/log`目录。到目前为止，我们已经学会了我们可以简单地挂载我们容器的日志文件，并使用 Splunk 转发器将日志发送到 Splunk 索引器。这是一种方法，但 Docker 提供了一个更简单的选项来将日志发送到 Splunk。

Docker 提供了一个特定于 Splunk 的日志驱动程序，它将通过我们的网络将容器日志发送到我们 Splunk 安装中的 HTTP 事件收集器。我们需要打开一个新端口来暴露事件收集器，因为 Splunk 使用端口`8088`来收集数据。到目前为止，我们已经在 Splunk 安装中暴露了端口`8000`和`9997`。在我们继续本章的其余部分之前，让我们看看 Splunk 上所有可用的端口以及它们在 Splunk 上的功能：

+   `8000`：您一直在使用这个端口进行 web 应用程序，这是用于在浏览器中访问 Splunk 的专用默认 web 端口。

+   `9997`：这个端口是 Splunk 转发器用来将数据转发到索引器的默认端口。我们在本章的前一节中暴露了这个端口，以确保我们能够从正在运行的系统中收集日志。

+   `8089`：Splunk 自带一个 API，默认作为搜索头的一部分运行。端口`8089`是 API 管理器所在的位置，用于与运行在您的实例上的 API 进行接口。

+   `8088`：端口`8088`需要暴露以允许信息被转发到已在您的系统上设置的事件收集器。在即将进行的练习中，我们将使用这个端口开始将 Docker 容器日志发送到 HTTP 事件收集器。

+   `8080`：如果我们有一个更大的 Splunk 安装，有专用的索引器，端口`8080`用于索引器之间的通信，并允许这些索引器之间的复制。

注意

Splunk 的 web 界面默认在端口`8000`上运行，但如果您在同一端口上托管应用程序，可能会与我们的 Panoramic Trekking App 发生冲突。如果这造成任何问题，请随意将 Splunk 容器上的端口暴露为不同的端口，例如端口`8080`，因为您仍然可以访问 web 界面，并且不会对使用该端口的我们的服务造成任何问题。

一旦在 Splunk 上设置了`HTTP 事件收集器`，将日志转发到 Splunk 只是在我们的`docker run`命令中添加正确的选项。以下示例命令使用`--log-driver=splunk`来向正在运行的容器发出信号，以使用 Splunk 日志驱动程序。

然后需要包括进一步的`--log-opt`选项，以确保日志被正确转发。第一个是`splunk-url`，这是您的系统当前托管的 URL。由于我们没有设置 DNS，我们可以简单地使用托管 Splunk 实例的 IP 地址，以及端口`8088`。第二个是`splunk-token`。这是在创建 HTTP 事件收集器时由 Splunk 分配的令牌：

```
docker run --log-driver=splunk \
--log-opt splunk-url=<splunk-url>:8088 \
--log-opt splunk-token=<event-collector-token> \
<docker-image>
```

您可以将 Splunk 日志驱动程序的详细信息添加到您的 Docker 配置文件中。在这里，您需要将以下详细信息添加到`/etc/docker`配置文件中的`daemon.json`文件中。只有当您将 Splunk 作为单独的应用程序而不是系统上的 Docker 实例时，这才能起作用。由于我们已将 Splunk 实例设置为 Docker 容器，因此此选项将不起作用。这是因为 Docker 守护程序将需要重新启动并连接到配置中列出的`splunk-url`。当然，在没有运行 Docker 守护程序的情况下，`splunk-url`将永远不可用。

```
{
  "log-driver": "splunk",
  "log-opts": {
    "splunk-token": "<splunk-token>",
    "splunk-url": "<splunk-url>::8088"
  }
}
```

在接下来的练习中，我们将扩展我们的 Splunk 安装，打开特定于我们的`HTTP 事件收集器`的端口，我们也将创建它。然后，我们将开始将日志从我们的容器发送到 Splunk，准备开始查看它们。

## 练习 14.02：创建 HTTP 事件收集器并开始收集 Docker 日志

在这个练习中，您将为您的 Splunk 安装创建一个`HTTP 事件收集器`，并使用 Docker`log`驱动程序将日志转发到您的事件收集器。您将使用`chentex`存储库提供的`random-logger` Docker 镜像，并可在 Docker Hub 上使用，以在系统中生成一些日志，并进一步演示 Splunk 的使用：

1.  再次启动 Splunk 镜像，这次将端口`8088`暴露给所有我们的 Docker 容器，以将它们的日志推送到其中：

```
docker run --rm -d -p 8000:8000 -p 9997:9997 -p 8088:8088 \
 -e 'SPLUNK_START_ARGS=--accept-license' \
 -e 'SPLUNK_PASSWORD=changeme' \
 -v ${PWD}/testsplunk:/opt/splunk/etc/ \
 --name splunk splunk/splunk:latest
```

1.  等待 Splunk 再次启动，并使用管理员账户重新登录 web 界面。

1.  转到`设置`菜单，选择`数据输入`以创建新的`HTTP 事件收集器`。从选项列表中选择`HTTP 事件收集器`。

1.  单击`HTTP 事件收集器`页面上的`全局设置`按钮。您将看到一个类似以下内容的页面。在此页面上，单击`启用`按钮，旁边是`所有令牌`，并确保未选择`启用 SSL`，因为在这个练习中您将不使用 SSL。这将使您的操作变得更加简单。当您对屏幕上的细节满意时，单击`保存`按钮保存您的配置：![图 14.11：在您的系统上启用 HTTP 事件收集器](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_14_11.jpg)

图 14.11：在您的系统上启用 HTTP 事件收集器

1.  当您返回到“HTTP 事件收集器”页面时，请点击屏幕右上角的“新令牌”按钮。您将看到一个类似以下的屏幕。在这里，您将设置新的事件收集器，以便可以收集 Docker 容器日志：![图 14.12：在 Splunk 上命名您的 HTTP 事件收集器](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_14_12.jpg)

图 14.12：在 Splunk 上命名您的 HTTP 事件收集器

前面的屏幕是您设置新事件收集器名称的地方。输入名称`Docker Logs`，对于其余的条目，通过将它们留空来接受默认值。点击屏幕顶部的“下一步”按钮。

1.  接受“输入设置”和“审阅”页面的默认值，直到您看到一个类似以下的页面，在这个页面上创建了一个新的“HTTP 事件收集器”，并提供了一个可用的令牌。令牌显示为`5c051cdb-b1c6-482f-973f-2a8de0d92ed8`。您的令牌将不同，因为 Splunk 为用户信任的数据源提供了一个唯一的令牌，以便安全地传输数据。使用此令牌允许您的 Docker 容器开始在 Splunk 安装中记录数据：![图 14.13：在 Splunk 上完成 HTTP 事件收集器](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_14_13.jpg)

图 14.13：在 Splunk 上完成 HTTP 事件收集器

1.  使用`hello-world` Docker 镜像，确保您可以将数据发送到 Splunk。在这种情况下，作为您的`docker run`命令的一部分，添加四个额外的命令行选项。指定`--log-driver`为`splunk`。将日志选项指定为我们系统的`splunk-url`，包括端口`8088`，`splunk-token`（您在上一步中创建的），最后，将`splunk-=insecureipverify`状态指定为`true`。这个最后的选项将限制在设置 Splunk 安装时所需的工作，这样您就不需要组织将与我们的 Splunk 服务器一起使用的 SSL 证书：

```
docker run --log-driver=splunk \
--log-opt splunk-url=http://127.0.0.1:8088 \
--log-opt splunk-token=5c051cdb-b1c6-482f-973f-2a8de0d92ed8 \
--log-opt splunk-insecureskipverify=true \
hello-world
```

命令应返回类似以下的输出：

```
Hello from Docker!
This message shows that your installation appears to be 
working correctly.
…
```

1.  返回到 Splunk Web 界面，点击“开始搜索”按钮。如果您已经从上一个屏幕中移开，请转到 Splunk 搜索页面，网址为`http://0.0.0.0:8000/en-US/app/search/search`。在搜索查询框中，输入`source="http:Docker Logs"`，如下截图所示。如果一切顺利，您还应该看到`hello-world`镜像提供的数据条目：![图 14.14：开始使用 Splunk 收集 docker 日志](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_14_14.jpg)

图 14.14：开始使用 Splunk 收集 docker 日志

1.  上一步已经表明，Splunk 安装现在能够收集 Docker 日志数据，但您需要创建一个新的卷来存储您的索引数据，以便在停止 Splunk 运行时不被销毁。回到您的终端并杀死运行中的`splunk`容器：

```
docker kill splunk
```

1.  在创建原始`testsplunk`目录的同一目录中，创建一个新目录，以便我们可以挂载我们的 Splunk 索引数据。在这种情况下，将其命名为`testsplunkindex`：

```
mkdir testsplunkindex
```

1.  从您的工作目录开始，再次启动 Splunk 镜像。挂载您刚刚创建的新目录，以存储您的索引数据：

```
docker run --rm -d -p 8000:8000 -p 9997:9997 -p 8088:8088 \
 -e 'SPLUNK_START_ARGS=--accept-license' \
 -e 'SPLUNK_PASSWORD=changeme' \
 -v ${PWD}/testsplunk:/opt/splunk/etc/ \
 -v ${PWD}/testsplunkindex:/opt/splunk/var/ \
 --name splunk splunk/splunk:latest
```

1.  使用`random-logger` Docker 镜像在您的系统中生成一些日志。在以下命令中，有一个额外的`tag`日志选项。这意味着每个生成并发送到 Splunk 的日志事件也将包含此标签作为元数据，这可以帮助您在 Splunk 中搜索数据时进行搜索。通过使用`{{.Name}}`和`{{.FullID}}`选项，这些细节将被自动添加，就像容器名称和 ID 号在创建容器时将被添加为您的标签一样：

```
docker run --rm -d --log-driver=splunk \
--log-opt splunk-url=http://127.0.0.1:8088 \
--log-opt splunk-token=5c051cdb-b1c6-482f-973f-2a8de0d92ed8 \
--log-opt splunk-insecureskipverify=true \
--log-opt tag="{{.Name}}/{{.FullID}}" \
--name log-generator chentex/random-logger:latest
```

注意

如果您的 Splunk 实例运行不正确，或者您没有正确配置某些内容，`log-generator`容器将无法连接或运行。您将看到类似以下的错误：

`docker: Error response from daemon: failed to initialize logging driver:`

1.  一旦这个运行起来，回到 web 界面上的 Splunk 搜索页面，在这种情况下，包括你在上一步创建的标签。以下查询将确保只有`log-generator`镜像提供的新数据将显示在我们的 Splunk 输出中：

```
source="http:docker logs" AND "log-generator/"
```

您的 Splunk 搜索应该会产生类似以下的结果。在这里，您可以看到由`log-generator`镜像生成的日志。您可以看到它在随机时间记录，并且每个条目现在都带有容器的名称和实例 ID 作为标签：

![图 14.15：Splunk 搜索结果](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_14_15.jpg)

图 14.15：Splunk 搜索结果

我们的 Splunk 安装进展顺利，因为我们现在已经能够配置应用程序以包括`HTTP 事件收集器`，并开始从`log-generator` Docker 镜像中收集日志。即使我们停止 Splunk 实例，它们仍应可供我们搜索和提取有用信息。

下一节将提供如何使用 Splunk 查询语言的更深入演示。

# 使用 Splunk 查询语言

Splunk 查询语言可能有点难以掌握，但一旦掌握，您会发现它有助于解释、分析和呈现来自 Splunk 环境的数据。熟悉查询语言的最佳方法就是简单地开始使用。

在使用查询语言时需要考虑以下几点：

+   **缩小您的搜索范围**：您想要搜索的数据量越大，您的查询就会花费更长的时间返回结果。如果您知道时间范围或源，比如我们为`docker logs`创建的源，查询将更快地返回结果。

+   **使用简单的搜索词条**：如果您知道日志中会包含什么（例如，`ERROR`或`DEBUG`），这是一个很好的起点，因为它还将帮助限制您接收到的数据量。这也是为什么在前一节中在向 Splunk 实例添加日志时我们使用了标签的另一个原因。

+   **链接搜索词条**：我们可以使用`AND`来组合搜索词条。我们还可以使用`OR`来搜索具有多个搜索词条的日志。

+   **添加通配符以搜索多个词条**：查询语言还可以使用通配符，比如星号。例如，如果您使用了`ERR*`查询，它将搜索不仅是`ERROR`，还有`ERR`和`ERRORS`。

+   提取的字段提供了更多的细节：Splunk 将尽其所能在日志事件中找到和定位字段，特别是如果您的日志采用已知的日志格式，比如 Apache 日志文件格式，或者是识别格式，比如 CSV 或 JSON 日志。如果您为您的应用程序创建日志，如果您将数据呈现为键值对，Splunk 将会出色地提取字段。

+   **添加函数来对数据进行分组和可视化**：向搜索词条添加函数可以帮助您转换和呈现数据。它们通常与管道（`|`）字符一起添加到搜索词条中。下面的练习将使用`stats`、`chart`和`timechart`函数来帮助聚合搜索结果和计算统计数据，比如`average`、`count`和`sum`。例如，如果我们使用了一个搜索词条，比如`ERR*`，然后我们可以将其传输到`stats`命令来计算我们看到错误事件的次数：`ERR* | stats count`

Splunk 在输入查询时还提供了方便的提示。一旦您掌握了基础知识，它将帮助您为数据提供额外的功能。

在接下来的练习中，您将发现，即使 Splunk 找不到您提取的字段，您也可以创建自己的字段，以便分析您的数据。

## 练习 14.03：熟悉 Splunk 查询语言

在这个练习中，您将运行一系列任务，演示查询语言的基本功能，并帮助您更熟悉使用它。这将帮助您检查和可视化您自己的数据：

1.  确保您的 Splunk 容器正在运行，并且`log-generator`容器正在向 Splunk 发送数据。

1.  当您登录 Splunk 时，从主页，点击左侧菜单中的“搜索和报告应用程序”，或者转到 URL`http://0.0.0.0:8000/en-US/app/search/search`来打开搜索页面。

1.  当您到达搜索页面时，您会看到一个文本框，上面写着“在此输入搜索”。从一个简单的术语开始，比如单词`ERROR`，如下截图所示，然后按*Enter*让 Splunk 运行查询：![图 14.16：Splunk 搜索页面](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_14_16.jpg)

图 14.16：Splunk 搜索页面

如果您只输入术语`ERR*`，并在术语的末尾加上一个星号（`*`），这也应该会产生类似于前面截图中显示的结果。

1.  使用`AND`链接搜索项，以确保我们的日志事件包含多个值。输入类似于`sourcetype=htt* AND ERR*`的搜索，以搜索所有`HTTP`事件收集器日志，这些日志还显示其日志中的`ERR`值：![图 14.17：链接搜索项](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_14_17.jpg)

图 14.17：链接搜索项

1.  您输入的搜索很可能默认搜索自安装以来的所有数据。查看所有数据可能会导致非常耗时的搜索。通过输入时间范围来缩小范围。单击查询文本框右侧的下拉菜单，以限制搜索运行的数据。将搜索限制为“最近 24 小时”：![图 14.18：限制时间范围内的搜索](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_14_18.jpg)

图 14.18：限制时间范围内的搜索

1.  查看结果页面左侧的提取字段。您会注意到有两个部分。第一个是“已选择字段”，其中包括特定于您的搜索的数据。第二个是“有趣的字段”。这些数据仍然相关并且是您的数据的一部分，但与您的搜索查询没有特定关联：![图 14.19：提取的字段](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_14_19.jpg)

图 14.19：提取的字段

1.  要创建要列出的字段，请点击“提取您自己的字段”链接。以下步骤将引导您完成创建与`log-generator`容器提供的数据相关的新字段的过程。

1.  您将被带到一个新页面，其中将呈现您最近正在搜索的`httpevent`源类型的示例数据。首先，您需要选择一个示例事件。选择与此处列出的类似的第一行。点击屏幕顶部的“下一步”按钮，以继续下一步：

```
{"line":"2020-02-19T03:58:12+0000 ERROR something happened in this execution.","source":"stdout","tag":"log-generator/3eae26b23d667bb12295aaccbdf919c9370ffa50da9e401d0940365db6605e3"}
```

1.  然后，您将被要求选择要使用的提取字段的方法。如果您正在处理具有明确分隔符的文件，例如`.SSV`文件，请使用“分隔符”方法。但在这种情况下，您将使用“正则表达式”方法。点击“正则表达式”，然后点击“下一步”按钮：![图 14.20：字段提取方法](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_14_20.jpg)

图 14.20：字段提取方法

1.  现在您应该有一行数据，可以开始选择要提取的字段。由`log-generator`容器提供的所有日志数据都是相同的，因此此行将作为 Splunk 接收的所有事件的模板。如下截图所示，点击`ERROR`，当您有机会输入字段名称时，输入`level`，然后选择“添加提取”按钮。选择`ERROR`后的文本行。在此示例中，它是“此执行中发生了某事”。添加一个字段名称`message`。点击“添加提取”按钮。然后，在选择所有相关字段后，点击“下一步”按钮：![图 14.21：Splunk 中的字段提取](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_14_21.jpg)

图 14.21：Splunk 中的字段提取

1.  您现在应该能够看到所有已突出显示的新字段的事件。点击“下一步”按钮：![图 14.22：带有新字段的事件](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_14_22.jpg)

图 14.22：带有新字段的事件

1.  最后，你将看到一个类似以下的屏幕。在`权限`部分，点击`所有应用`按钮，允许此字段提取在整个 Splunk 安装中进行，而不限制在一个应用或所有者中。如果你对提取的名称和其他选项满意，点击屏幕顶部的`完成`按钮：![图 14.23：在 Splunk 中完成字段提取](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_14_23.jpg)

图 14.23：在 Splunk 中完成字段提取

1.  返回到搜索页面，并在搜索查询中添加`sourcetype=httpevent`。加载完成后，浏览提取的字段。现在你应该有你添加的`level`和`message`字段作为`感兴趣的字段`。如果你点击`level`字段，你将得到接收事件数量的详细信息，类似于下面截图中显示的内容：![图 14.24：在搜索结果中显示字段细分](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_14_24.jpg)

图 14.24：在搜索结果中显示字段细分

1.  使用`stats`函数来计算日志中每个错误级别的事件数量。通过使用`sourcetype=httpevent | stats count by level`搜索查询来获取上一步搜索结果的结果，并将`stats`函数的值传递给`count by level`：![图 14.25：使用 stats 函数](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_14_25.jpg)

图 14.25：使用 stats 函数

1.  `stats`函数提供了一些很好的信息，但如果你想看到数据在一段时间内的呈现，可以使用`timechart`函数。运行`sourcetype=httpevent | timechart span=1m count by level`查询，以在一段时间内给出结果。如果你在过去 15 分钟内进行搜索，上述查询应该给出每分钟的数据细分。点击搜索查询文本框下的`可视化`选项卡。你将看到一个代表我们搜索结果的图表：![图 14.26：从搜索结果创建可视化](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_14_26.jpg)

图 14.26：从搜索结果创建可视化

你可以在查询中使用 span 选项来按分钟（1m）、小时（5）、天（1d）等对数据进行分组。

1.  在前面的截图中，提到了图表类型（`柱状图`），你可以更改当前显示的类型。点击`柱状图`文本。它将让你从几种不同类型的图表中选择。在这种情况下，使用折线图：![图 14.27：选择图表类型](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_14_27.jpg)

图 14.27：选择图表类型

注意

在接下来的步骤中，你将为数据可视化创建一个仪表板。仪表板是一种向用户显示数据的方式，用户无需了解 Splunk 或涉及的数据的任何特定信息。对于非技术用户来说，这是完美的，因为你只需提供仪表板的 URL，用户就可以加载仪表板以查看他们需要的信息。仪表板也非常适合你需要定期执行的搜索，以限制你需要做的工作量。

1.  当你对图表满意时，点击屏幕顶部的“另存为”按钮，然后选择“仪表板面板”。你将看到一个类似下面截图中所示的表单。创建一个名为“日志容器仪表板”的新仪表板，将其“共享在应用程序”（当前的搜索应用程序）中，并包括你刚创建的特定面板，命名为“错误级别”：![图 14.28：从搜索结果创建仪表板](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_14_28.jpg)

图 14.28：从搜索结果创建仪表板

1.  点击“保存”按钮创建新仪表板。当你点击保存时，你将有机会查看你的仪表板。但如果你需要在以后查看仪表板，前往你创建仪表板的应用程序（在本例中是“搜索与报告”应用程序），然后点击屏幕顶部的“仪表板”菜单。你将看到可用的仪表板。在这里你可以点击相关的仪表板。你会注意到你有另外两个可用的仪表板，这是作为 Splunk 安装的默认部分提供的：![图 14.29：Splunk 中的仪表板](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_14_29.jpg)

图 14.29：Splunk 中的仪表板

1.  打开你刚创建的“日志容器”仪表板，然后点击屏幕顶部的“编辑”按钮。这样可以让你在不需要返回搜索窗口的情况下向仪表板添加新面板。

1.  当你点击“编辑”按钮时，你将获得额外的选项来更改仪表板的外观和感觉。现在点击“添加面板”按钮。

1.  当你选择“添加面板”时，屏幕右侧将出现一些额外的选择。点击“新建”菜单选项，然后选择“单个数值”。

1.  将面板命名为“总错误”，并将`sourcetype=httpevent AND ERROR | stats count`添加为搜索字符串。您可以添加新仪表板面板的屏幕应该类似于以下内容。它应该提供有关“内容标题”和“搜索字符串”的详细信息：![图 14.30：将面板添加到您的 Splunk 仪表板](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_14_30.jpg)

图 14.30：向您的 Splunk 仪表板添加面板

1.  单击“添加到仪表板”按钮，将新面板添加到仪表板底部作为单个值面板。

1.  在编辑模式下，您可以根据需要移动和调整面板的大小，并添加额外的标题或详细信息。当您对新面板感到满意时，请单击屏幕右上角的“保存”按钮。

希望您的仪表板看起来类似于以下内容：

![图 14.31：向您的仪表板添加新面板](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_14_31.jpg)

图 14.31：向您的仪表板添加新面板

最后，您的仪表板面板具有一些额外的功能，您可以通过单击屏幕右上角的省略号按钮找到这些功能。如果您对您的仪表板不满意，您可以从这里删除它。

1.  单击“设置为主页仪表板面板”选项，该选项在省略号按钮下可用。这将带您回到 Splunk 主屏幕，在那里您的“日志容器仪表板”现在可用，并且在登录到 Splunk 时将是您看到的第一件事：![图 14.32：日志容器仪表板](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_14_32.jpg)

图 14.32：日志容器仪表板

这个练习向您展示了如何执行基本查询，如何使用函数将它们链接在一起，并开始创建可视化效果、仪表板和面板。虽然我们只花了很短的时间来讨论这个主题，但它应该让您更有信心进一步处理 Splunk 查询。

在下一节中，我们将看看 Splunk 应用程序是什么，以及它们如何帮助将您的数据、搜索、报告和仪表板分隔到不同的区域。

# Splunk 应用程序和保存的搜索

Splunk 应用程序是一种让您将数据、搜索、报告和仪表板分隔到不同区域的方式，然后您可以配置谁可以访问什么。Splunk 提供了一个庞大的生态系统，帮助第三方开发人员和公司向公众提供这些应用程序。

我们在本章前面提到过，Splunk 还提供了“SplunkBase”，用于由 Splunk 为用户认证的已批准应用程序，例如用于思科网络设备的应用程序。它不需要是经过批准的应用程序才能在您的系统上使用。Splunk 允许您创建自己的应用程序，如果需要，您可以将它们打包成文件分发给希望使用它们的用户。Splunk 应用程序、仪表板和保存的搜索的整个目的是减少重复的工作量，并在需要时向非技术用户提供信息。

以下练习将为您提供一些关于使用 Splunk 应用程序的实际经验。

## 练习 14.04：熟悉 Splunk 应用程序和保存搜索

在这个练习中，您将从 SplunkBase 安装新的应用程序，并对其进行修改以满足您的需求。这个练习还将向您展示如何保存您的搜索以备将来使用。

1.  确保您的 Splunk 容器正在运行，并且`log-generator`容器正在向 Splunk 发送数据。

1.  当您重新登录 Splunk 时，请单击“应用程序”菜单中“应用程序”旁边的齿轮图标。当您进入“应用程序”页面时，您应该会看到类似以下内容。该页面包含当前安装在系统上的所有 Splunk 应用程序的列表。您会注意到一些应用程序已启用，而一些已禁用。

您还可以选择从 Splunk 应用程序库中浏览更多应用程序，安装来自文件的应用程序，或创建自己的 Splunk 应用程序：

![图 14.33：在 Splunk 中使用应用程序页面](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_14_33.jpg)

图 14.33：在 Splunk 中使用应用程序页面

1.  单击屏幕顶部的“浏览更多应用程序”按钮。

1.  您将进入一个页面，该页面提供了系统中所有可用的 Splunk 应用程序的列表。其中一些是付费的，但大多数是免费使用和安装的。您还可以按名称、类别和支持级别进行搜索。在屏幕顶部的搜索框中输入“离港板 Viz”，然后单击*Enter*：![图 14.34：离港板 Viz 应用程序](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_14_34.jpg)

图 14.34：离港板 Viz 应用程序

注意

本节以`Departures Board Viz`应用为例，因为它易于使用和安装，只需进行最小的更改。每个应用程序都应该为您提供有关其使用的信息类型以及如何开始使用所需数据的一些详细信息。您会注意到有数百种应用程序可供选择，因此您一定会找到适合您需求的东西。

1.  您需要在 Splunk 注册后才能安装和使用可用的应用程序。单击`Departures Board Viz`应用的“安装”按钮，并按照提示进行登录，如果需要的话：![图 14.35：安装 Departures Board Viz 应用](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_14_35.jpg)

图 14.35：安装 Departures Board Viz 应用

1.  如果安装成功，您应该会收到提示，要么打开您刚刚安装的应用程序，要么返回到 Splunk 主页。返回主页以查看您所做的更改。

1.  从主页，您现在应该看到已安装了名为`Departures Board Viz`的新应用程序。这只是一个可视化扩展。单击主屏幕上的`Departures Board Vis`按钮以打开该应用程序：![图 14.36：打开 Departures Board Viz 应用](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_14_36.jpg)

图 14.36：打开 Departures Board Viz 应用

1.  当您打开应用程序时，它将带您到“关于”页面。这只是一个提供应用程序详细信息以及如何与您的数据一起使用的仪表板。单击屏幕顶部的“编辑”按钮以继续：![图 14.37：Departures Board Viz 应用的“关于”页面](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_14_37.jpg)

图 14.37：Departures Board Viz 应用的“关于”页面

1.  单击“编辑搜索”以添加一个新的搜索，显示特定于您的数据。

1.  删除默认搜索字符串，并将`sourcetype=httpevent | stats count by level | sort - count | head 1 | fields level`搜索查询放入文本框中。该查询将浏览您的`log-generator`数据，并提供每个级别的计数。然后，将结果从最高到最低排序（`sort - count`），并提供具有最高值的级别（`head 1 | fields level`）：![图 14.38：添加新的搜索查询](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_14_38.jpg)

图 14.38：添加新的搜索查询

1.  单击“保存”按钮以保存您对可视化所做的更改。您应该看到我们的数据提供的最高错误级别，而不是`Departures Board Viz`默认提供的城市名称。如下截图所示，我们日志中报告的最高错误是`INFO`：![图 14.39：在 Splunk 中编辑应用程序](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_14_39.jpg)

图 14.39：在 Splunk 中编辑应用程序

1.  现在您已经添加了一个 Splunk 应用程序，您将创建一个非常基本的应用程序来进一步修改您的环境。返回到主屏幕，再次点击“应用程序”菜单旁边的齿轮。

1.  在“应用程序”页面上，单击屏幕右侧的“创建应用程序”按钮：![图 14.40：Splunk 应用程序](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_14_40.jpg)

图 14.40：Splunk 应用程序

1.  当您创建自己的应用程序时，您将看到一个类似于此处所示的表单。您将为您的 Splunk 安装创建一个测试应用程序。使用以下截图中提供的信息填写表单，但确保为“名称”和“文件夹名称”添加值。版本也是一个必填字段，需要以`major_version.minor_version.patch_version`的形式。将版本号添加为`1.0.0`。以下示例还选择了`sample_app`选项，而不是`barebones`模板。这意味着该应用程序将填充有示例仪表板和报告，您可以修改这些示例以适应您正在处理的数据。您不会使用任何这些示例仪表板和报告，因此您可以选择任何一个。如果您有预先创建的 Splunk 应用程序可用，则只需要“上传资产”选项，但在我们的实例中，可以将其留空：![图 14.41：创建 Splunk 应用程序](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_14_41.jpg)

图 14.41：创建 Splunk 应用程序

1.  单击“保存”按钮以创建您的新应用程序，然后返回到您的安装的主屏幕。您会注意到现在在主屏幕上列出了一个名为`Test Splunk App`的应用程序。单击您的新应用程序以打开它：![图 14.42：主屏幕上的测试 Splunk 应用程序](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_14_42.jpg)

图 14.42：主屏幕上的测试 Splunk 应用程序

1.  该应用程序在“搜索和报告”应用程序中看起来并无不同，但是如果您点击屏幕顶部的“报告或仪表板”选项卡，您会注意到已经有一些示例报告和仪表板。不过，暂时创建一个您以后可以参考的报告。首先确保您在应用程序的“搜索”选项卡中。

1.  在查询栏中输入`sourcetype=httpevent earliest=-7d | timechart span=1d count by level`。您会注意到我们已将值设置为`earliest=-7d`，这样会自动选择过去 7 天的数据，因此您无需指定搜索的时间范围。然后它将创建您的数据的时间图表，按每天的值进行汇总。

1.  点击屏幕顶部的“另存为”按钮，然后从下拉菜单中选择“报告”。然后您将看到以下表单，以便保存您的报告。只需在点击屏幕底部的“保存”按钮之前命名报告并提供描述：![图 14.43：在您的 Splunk 应用程序中创建保存的报告](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_14_43.jpg)

图 14.43：在您的 Splunk 应用程序中创建保存的报告

1.  当您点击“保存”时，您将有选项查看您的新报告。它应该看起来类似于以下内容：![图 14.44：Splunk 中的每日错误级别报告](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_14_44.jpg)

图 14.44：Splunk 中的每日错误级别报告

如果您以后需要再次参考此报告，可以点击您的新 Splunk 应用程序的“报告”选项卡，它将与应用程序首次创建时提供的示例报告一起列出。以下屏幕截图显示了您的应用程序的“报告”选项卡，其中列出了示例报告，但您还有刚刚创建的“每日错误”报告，它已添加到列表的顶部：

![图 14.45：报告页面](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_14_45.jpg)

图 14.45：报告页面

这就结束了这个练习，我们在其中安装了第三方 Splunk 应用程序并创建了自己的应用程序。这也是本章的结束。不过，在您继续下一章之前，请确保您通过下面提供的活动来重新确认您在本章学到的一切。

## 活动 14.01：为您的 Splunk 安装创建 docker-compose.yml 文件

到目前为止，您一直在使用`docker run`命令简单地在 Docker 容器上运行 Splunk。现在是时候利用您在本书前几节中所学到的知识，创建一个`docker-compose.yml`文件，以便在需要时在您的系统上安装和运行我们的 Splunk 环境。作为这个活动的一部分，添加作为全景徒步应用程序一部分运行的一个容器。还要确保您可以查看所选服务的日志。

执行以下步骤以完成此活动：

1.  决定一旦作为 Docker Compose 文件的一部分运行起来，您希望您的 Splunk 安装看起来如何。这将包括挂载目录和需要作为安装的一部分暴露的端口。

1.  创建您的`docker-compose.yml`文件并运行`Docker Compose`。确保它根据上一步中的要求启动您的 Splunk 安装。

1.  一旦 Splunk 安装运行起来，启动全景徒步应用程序的一个服务，并确保您可以将日志数据发送到您的 Splunk 设置中。

**预期输出：**

这应该会产生一个类似以下的屏幕：

![图 14.46：活动 14.01 的预期输出](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_14_46.jpg)

图 14.46：活动 14.01 的预期输出

注意

此活动的解决方案可以通过此链接找到。

下一个活动将允许您为 Splunk 中记录的新数据创建一个 Splunk 应用程序和仪表板。

## 活动 14.02：创建一个 Splunk 应用程序来监视全景徒步应用程序

在上一个活动中，您确保了作为全景徒步应用程序的一部分设置的一个服务正在使用您的 Splunk 环境记录数据。在这个活动中，您需要在您的安装中创建一个新的 Splunk 应用程序，以专门监视您的服务，并创建一个与向 Splunk 记录数据的服务相关的仪表板。

您需要按照以下步骤完成此活动：

1.  确保您的 Splunk 安装正在运行，并且来自全景徒步应用程序的至少一个服务正在向 Splunk 记录数据。

1.  创建一个新的 Splunk 应用程序，并为监视全景徒步应用程序命名一个相关的名称。确保您可以从 Splunk 主屏幕查看它。

1.  创建一个与您正在监视的服务相关的仪表板，并添加一些可视化效果，以帮助您监视您的服务。

**预期输出：**

成功完成此活动后，应显示类似以下的仪表板：

![图 14.47：活动 14.02 的预期解决方案](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_14_47.jpg)

图 14.47：活动 14.02 的预期解决方案

注意

此活动的解决方案可通过此链接找到。

# 总结

本章教会了您如何使用诸如 Splunk 之类的应用程序来帮助您通过将容器日志聚合到一个中心区域来监视和排除故障您的应用程序。我们从讨论在使用 Docker 时日志管理策略的重要性开始了本章，然后通过讨论其架构以及如何运行该应用程序的一些要点来介绍了 Splunk。

我们直接使用 Splunk 运行 Docker 容器映像，并开始将日志从我们的运行系统转发。然后，我们使用 Splunk 日志驱动程序将我们的容器日志直接发送到我们的 Splunk 容器，挂载重要目录以确保我们的数据即使在停止容器运行后也能保存和可用。最后，我们更仔细地研究了 Splunk 查询语言，通过它我们创建了仪表板和保存搜索，并考虑了 Splunk 应用程序生态系统的优势。

下一章将介绍 Docker 插件，并教您如何利用它们来帮助扩展您的容器和运行在其上的服务。


# 第十五章：通过插件扩展 Docker

概述

在本章中，您将学习如何通过创建和安装插件来扩展 Docker Engine 的功能。您将了解如何在使用 Docker 容器时实现高级和自定义需求。在本章结束时，您将能够识别扩展 Docker 的基础知识。您还将能够安装和配置不同的 Docker 插件。此外，您将使用 Docker 插件 API 来开发自定义插件，并使用各种 Docker 插件来扩展 Docker 中卷、网络和授权的功能。

# 介绍

在之前的章节中，您使用 Docker Compose 和 Docker Swarm 运行了多个 Docker 容器。此外，您监控了容器的指标并收集了日志。Docker 允许您管理容器的完整生命周期，包括网络、卷和进程隔离。如果您想要定制 Docker 的操作以适应您的自定义存储、网络提供程序或身份验证服务器，您需要扩展 Docker 的功能。

例如，如果您有一个自定义的基于云的存储系统，并希望将其挂载到 Docker 容器中，您可以实现一个存储插件。同样，您可以使用授权插件从企业用户管理系统对用户进行身份验证，并允许他们与 Docker 容器一起工作。

在本章中，您将学习如何通过插件扩展 Docker。您将从插件管理和 API 开始，然后学习最先进和最受欢迎的插件类型：授权、网络和卷。接下来的部分将涵盖在 Docker 中安装和操作插件。

# 插件管理

Docker 中的插件是独立于 Docker Engine 运行的外部进程。这意味着 Docker Engine 不依赖于插件，反之亦然。我们只需要告知 Docker Engine 有关插件位置和其功能。Docker 提供以下 CLI 命令来管理插件的生命周期：

+   `docker plugin create`：此命令创建新的插件及其配置。

+   `docker plugin enable/disable`：这些命令启用或禁用插件。

+   `docker plugin install`：此命令安装插件。

+   `docker plugin upgrade`：此命令将现有插件升级到更新版本。

+   `docker plugin rm`：此命令通过从 Docker Engine 中删除其信息来删除插件。

+   `docker plugin ls`：此命令列出已安装的插件。

+   `docker plugin inspect`：此命令显示有关插件的详细信息。

在接下来的部分中，您将学习如何使用插件 API 在 Docker 中实现插件。

# 插件 API

Docker 维护插件 API，以帮助社区编写他们的插件。这意味着只要按照插件 API 的规定实现，任何人都可以开发新的插件。这种方法使 Docker 成为一个开放和可扩展的平台。插件 API 是一种**远程过程调用**（**RPC**）风格的 JSON API，通过 HTTP 工作。Docker 引擎向插件发送 HTTP POST 请求，并使用响应来继续其操作。

Docker 还提供了一个官方的开源 SDK，用于创建新的插件和**辅助包**以扩展 Docker 引擎。辅助包是样板模板，如果您想轻松创建和运行新的插件。目前，由于 Go 是 Docker 引擎本身的主要实现语言，因此只有 Go 中的辅助包。它位于[`github.com/docker/go-plugins-helpers`](https://github.com/docker/go-plugins-helpers)，并为 Docker 支持的每种插件提供辅助程序：

![图 15.1：Go 插件助手](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_15_01.jpg)

图 15.1：Go 插件助手

您可以检查存储库中列出的每个文件夹，以便轻松创建和运行不同类型的插件。在本章中，您将通过几个实际练习来探索支持的插件类型，即授权、网络和卷插件。这些插件使 Docker 引擎能够通过提供额外的功能来实现自定义业务需求，同时还具有默认的 Docker 功能。

# 授权插件

Docker 授权基于两种模式：**启用所有类型的操作**或**禁用所有类型的操作**。换句话说，如果用户可以访问 Docker 守护程序，他们可以运行任何命令并使用 API 或 Docker 客户端命令。如果需要更细粒度的访问控制方法，则需要在 Docker 中使用授权插件。授权插件增强了 Docker 引擎操作的身份验证和权限。它们使得可以更细粒度地控制谁可以在 Docker 引擎上执行特定操作。

授权插件通过请求上下文批准或拒绝 Docker 守护程序转发的请求。因此，插件应实现以下两种方法：

+   `AuthZReq`：在 Docker 守护程序处理请求之前调用此方法。

+   `AuthZRes`：在从 Docker 守护程序返回响应给客户端之前调用此方法。

在接下来的练习中，您将学习如何配置和安装授权插件。您将安装由 Open Policy Agent 创建和维护的**基于策略的授权**插件（[`www.openpolicyagent.org/`](https://www.openpolicyagent.org/)）。**基于策略的访问**是基于根据一些规则（即**策略**）授予用户访问权限的想法。插件的源代码可在 GitHub 上找到（[`github.com/open-policy-agent/opa-docker-authz`](https://github.com/open-policy-agent/opa-docker-authz)），它与类似以下的策略文件一起使用：

```
package docker.authz 
allow {
    input.Method = "GET"
}
```

策略文件存储在 Docker 守护程序可以读取的主机系统中。例如，这里显示的策略文件只允许`GET`作为请求的方法。它实际上通过禁止任何其他方法（如`POST`、`DELETE`或`UPDATE`）使 Docker 守护程序变为只读。在接下来的练习中，您将使用一个策略文件并配置 Docker 守护程序与授权插件通信并限制一些请求。

注意

在以下练习中，插件和命令在 Linux 环境中效果最佳，考虑到 Docker 守护程序的安装和配置。如果您使用的是自定义或工具箱式的 Docker 安装，您可能希望使用虚拟机来完成本章的练习。

注意

请使用`touch`命令创建文件，并使用`vim`命令在 vim 编辑器中处理文件。

## 练习 15.01：具有授权插件的只读 Docker 守护程序

在这个练习中，您需要创建一个只读的 Docker 守护程序。如果您想限制对生产环境的访问和更改，这是一种常见的方法。为了实现这一点，您将安装并配置一个带有策略文件的插件。

要完成练习，请执行以下步骤：

1.  通过运行以下命令在`/etc/docker/policies/authz.rego`位置创建一个文件：

```
mkdir -p /etc/docker/policies
touch /etc/docker/policies/authz.rego
ls /etc/docker/policies
```

这些命令创建一个位于`/etc/docker/policies`的文件：

```
authz.rego
```

1.  用编辑器打开文件并插入以下数据：

```
package docker.authz 
allow {
    input.Method = "GET"
}
```

您可以使用以下命令将内容写入文件中：

```
cat > /etc/docker/policies/authz.rego << EOF
package docker.authz 
allow {
    input.Method = "GET"
}
EOF
cat /etc/docker/policies/authz.rego
```

注意

`cat`命令用于在终端中使文件内容可编辑。除非您在无头模式下运行 Ubuntu，否则可以跳过使用基于 CLI 的命令来编辑文件内容。

策略文件仅允许 Docker 守护程序中的`GET`方法；换句话说，它使 Docker 守护程序变为只读。

1.  通过在终端中运行以下命令安装插件，并在提示权限时输入*y*：

```
docker plugin install --alias opa-docker-authz:readonly \
openpolicyagent/opa-docker-authz-v2:0.5 \
opa-args="-policy-file /opa/policies/authz.rego"
```

该命令安装位于`openpolicyagent/opa-docker-authz-v2:0.5`的插件，并使用别名`opa-docker-authz:readonly`。此外，来自*步骤 1*的策略文件被传递为`opa-args`：

![图 15.2：插件安装](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_15_02.jpg)

图 15.2：插件安装

1.  使用以下命令检查已安装的插件：

```
docker plugin ls
```

该命令列出插件：

![图 15.3：插件列表](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_15_03.jpg)

图 15.3：插件列表

1.  使用以下版本编辑 Docker 守护程序配置位于`/etc/docker/daemon.json`：

```
{
    "authorization-plugins": ["opa-docker-authz:readonly"]
}
```

您可以使用`cat /etc/docker/daemon.json`命令检查文件的内容。

1.  使用以下命令重新加载 Docker 守护程序：

```
sudo kill -HUP $(pidof dockerd)
```

该命令通过使用`pidof`命令获取`dockerd`的进程 ID 来终止`dockerd`的进程。此外，它发送`HUP`信号，这是发送给 Linux 进程以更新其配置的信号。简而言之，您正在使用新的授权插件配置重新加载 Docker 守护程序。运行以下列出命令以检查列出操作是否被允许：

```
docker ps
```

该命令列出正在运行的容器，并显示列出操作是允许的：

```
CONTAINER ID  IMAGE  COMMAND  CREATED  STATUS  PORTS  NAMES
```

1.  运行以下命令以检查是否允许创建新容器：

```
docker run ubuntu
```

该命令创建并运行一个容器；但是，由于该操作不是只读的，因此不被允许：

```
Error response from daemon: authorization denied by plugin 
opa-docker-authz:readonly: request rejected by administrative policy.
See 'docker run –-help'.
```

1.  检查 Docker 守护程序的日志是否有任何与插件相关的行：

```
journalctl -u docker | grep plugin | grep "OPA policy decision"
```

注意

`journalctl`是用于显示来自`systemd`进程的日志的命令行工具。`systemd`进程以二进制格式存储日志。需要`journalctl`来读取日志文本。

以下输出显示*步骤 7*和*步骤 8*中测试的操作通过授权插件，并显示了`"Returning OPA policy decision: true"`和`"Returning OPA policy decision: false"`行。它显示我们的插件已允许第一个操作并拒绝了第二个操作：

![图 15.4：插件日志](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_15_04.jpg)

图 15.4：插件日志

1.  通过从`/etc/docker/daemon.json`中删除`authorization-plugins`部分并重新加载 Docker 守护程序，停止使用插件，类似于*步骤 6*中所做的操作：

```
cat > /etc/docker/daemon.json << EOF
{}
EOF
cat /etc/docker/daemon.json
sudo kill -HUP $(pidof dockerd)
```

1.  通过以下命令禁用和删除插件：

```
docker plugin disable opa-docker-authz:readonly 
docker plugin rm opa-docker-authz:readonly  
```

这些命令通过返回插件的名称来禁用和删除 Docker 中的插件。

在这个练习中，您已经配置并安装了一个授权插件到 Docker 中。在下一节中，您将学习更多关于 Docker 中的网络插件。

# 网络插件

Docker 通过 Docker 网络插件支持各种网络技术。虽然它支持容器对容器和主机对容器的完整功能的网络，但插件使我们能够将网络扩展到更多的技术。网络插件实现了远程驱动程序作为不同网络拓扑的一部分，比如虚拟可扩展局域网（`vxlan`）和 MAC 虚拟局域网（`macvlan`）。您可以使用 Docker 插件命令安装和启用网络插件。此外，您需要使用`--driver`标志指定网络驱动程序的名称。例如，如果您已经安装并启用了`my-new-network-technology`驱动程序，并且希望您的新网络成为其中的一部分，您需要设置一个`driver`标志：

```
docker network create --driver my-new-network-technology mynet
```

这个命令创建了一个名为`mynet`的网络，而`my-new-network-technology`插件管理所有网络操作。

社区和第三方公司开发了网络插件。然而，目前在 Docker Hub 上只有两个经过认证的网络插件 - Weave Net 和 Infoblox IPAM Plugin。

![图 15.5：Docker Hub 中的网络插件](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_15_05.jpg)

图 15.5：Docker Hub 中的网络插件

**Infoblox IPAM Plugin**专注于提供 IP 地址管理服务，比如编写 DNS 记录和配置 DHCP 设置。**Weave Net**专注于为 Docker 容器创建弹性网络，具有加密、服务发现和组播网络。

在`go-plugin-helpers`提供的官方 SDK 中，有用于为 Docker 创建网络扩展的 Go 处理程序。`Driver`接口定义如下：

```
// Driver represent the interface a driver must fulfill.
type Driver interface {
     GetCapabilities() (*CapabilitiesResponse, error)
     CreateNetwork(*CreateNetworkRequest) error
     AllocateNetwork(*AllocateNetworkRequest)        (*AllocateNetworkResponse, error)
     DeleteNetwork(*DeleteNetworkRequest) error
     FreeNetwork(*FreeNetworkRequest) error
     CreateEndpoint(*CreateEndpointRequest)        (*CreateEndpointResponse, error)
     DeleteEndpoint(*DeleteEndpointRequest) error
     EndpointInfo(*InfoRequest) (*InfoResponse, error)
     Join(*JoinRequest) (*JoinResponse, error)
     Leave(*LeaveRequest) error
     DiscoverNew(*DiscoveryNotification) error
     DiscoverDelete(*DiscoveryNotification) error
     ProgramExternalConnectivity(*ProgramExternalConnectivityRequest)        error
     RevokeExternalConnectivity(*RevokeExternalConnectivityRequest)        error
}
```

注意

完整的代码可在[`github.com/docker/go-plugins-helpers/blob/master/network/api.go`](https://github.com/docker/go-plugins-helpers/blob/master/network/api.go)找到。

当您检查接口功能时，网络插件应提供网络、端点和外部连接的操作。例如，网络插件应使用`CreateNetwork`、`AllocateneNetwork`、`DeleteNetwork`和`FreeNetwork`函数实现网络生命周期。

同样，端点生命周期应该由`CreateEndpoint`、`DeleteEndpoint`和`EndpointInfo`函数实现。此外，还有一些扩展集成和管理函数需要实现，包括`GetCapabilities`、`Leave`和`Join`。服务还需要它们特定的请求和响应类型以在托管插件环境中工作。

在接下来的练习中，您将使用 Weave Net 插件创建一个新网络，并让容器使用新网络连接。

## 练习 15.02：Docker 网络插件实战

Docker 网络插件接管特定网络实例的网络操作并实现自定义技术。在这个练习中，您将安装和配置一个网络插件来创建一个 Docker 网络。然后，您将创建一个 Docker 镜像的三个副本应用程序，并使用插件连接这三个实例。您可以使用 Weave Net 插件来实现这个目标。

要完成练习，请执行以下步骤：

1.  通过在终端中运行以下命令初始化 Docker swarm（如果之前未启用）：

```
docker swarm init
```

此命令创建一个 Docker swarm 以部署多个应用程序实例：

![图 15.6：Swarm 初始化](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_15_06.jpg)

图 15.6：Swarm 初始化

1.  通过运行以下命令安装**Weave Net**插件：

```
docker plugin install --grant-all-permissions \
store/weaveworks/net-plugin:2.5.2
```

此命令从商店安装插件并授予所有权限：

![图 15.7：插件安装](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_15_07.jpg)

图 15.7：插件安装

1.  使用以下命令使用驱动程序创建新网络：

```
docker network create  \
--driver=store/weaveworks/net-plugin:2.5.2  \
weave-custom-net
```

使用插件提供的驱动程序创建名为`weave-custom-net`的新网络：

![图 15.8：创建网络](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_15_08.jpg)

图 15.8：创建网络

成功创建网络后，将打印出随机生成的网络名称，如前面的代码所示。

1.  使用以下命令创建一个三个副本的应用程序：

```
docker service create --network=weave-custom-net \
--replicas=3 \
--name=workshop \
-p 80:80 \
onuryilmaz/hello-plain-text
```

该命令创建了`onuryilmaz/hello-plain-text`镜像的三个副本，并使用`the weave-custom-net`网络连接实例。此外，它使用名称`workshop`并发布到端口`80`：

![图 15.9：应用程序创建](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_15_09.jpg)

图 15.9：应用程序创建

1.  通过运行以下命令获取容器的名称：

```
FIRST_CONTAINER=$(docker ps --format "{{.Names}}" |grep "workshop.1")
echo $FIRST_CONTAINER
SECOND_CONTAINER=$(docker ps --format "{{.Names}}" |grep "workshop.2")
echo $SECOND_CONTAINER
THIRD_CONTAINER=$(docker ps --format "{{.Names}}" |grep "workshop.3")
echo $THIRD_CONTAINER
```

这些命令列出了正在运行的 Docker 容器名称，并按`workshop`实例进行过滤。您将需要容器的名称来测试它们之间的连接：

![图 15.10：容器名称](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_15_10.jpg)

图 15.10：容器名称

1.  运行以下命令将第一个容器连接到第二个容器：

```
docker exec -it $FIRST_CONTAINER sh -c "curl $SECOND_CONTAINER" 
```

该命令使用`curl`命令连接第一个和第二个容器：

![图 15.11：容器之间的连接](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_15_11.jpg)

图 15.11：容器之间的连接

上述命令在第一个容器内运行，并且`curl`命令到达第二个容器。输出显示了服务器和请求信息。

1.  类似于*步骤 6*，将第一个容器连接到第三个容器：

```
docker exec -it $FIRST_CONTAINER sh -c "curl $THIRD_CONTAINER" 
```

如预期的那样，在*步骤 6*和*步骤 7*中检索到了不同的服务器名称和地址：

![图 15.12：容器之间的连接](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_15_12.jpg)

图 15.12：容器之间的连接

这表明使用自定义 Weave Net 网络创建的容器正在按预期工作。

1.  您可以使用以下命令删除应用程序和网络：

```
docker service rm workshop
docker network rm weave-custom-net
```

在这个练习中，您已经在 Docker 中安装并使用了一个网络插件。除此之外，您还创建了一个使用自定义网络驱动程序连接的容器化应用程序。在下一节中，您将学习更多关于 Docker 中的卷插件。

# 卷插件

Docker 卷被挂载到容器中，以允许有状态的应用程序在容器中运行。默认情况下，卷是在主机文件系统中创建并由 Docker 管理的。此外，在创建卷时，可以指定卷驱动程序。例如，您可以挂载网络或存储提供程序（如 Google、Azure 或 AWS）的卷。您还可以在 Docker 容器中本地运行数据库，而数据卷在 AWS 存储服务中是持久的。这样，您的数据卷可以在将来与在任何其他位置运行的其他数据库实例一起重用。要使用不同的卷驱动程序，您需要使用卷插件增强 Docker。

Docker 卷插件控制卷的生命周期，包括`Create`、`Mount`、`Unmount`、`Path`和`Remove`等功能。在插件 SDK 中，卷驱动程序接口定义如下：

```
// Driver represent the interface a driver must fulfill.
type Driver interface {
     Create(*CreateRequest) error
     List() (*ListResponse, error)
     Get(*GetRequest) (*GetResponse, error)
     Remove(*RemoveRequest) error
     Path(*PathRequest) (*PathResponse, error)
     Mount(*MountRequest) (*MountResponse, error)
     Unmount(*UnmountRequest) error
     Capabilities() *CapabilitiesResponse
}
```

注意

完整的驱动程序代码可在[`github.com/docker/go-plugins-helpers/blob/master/volume/api.go`](https://github.com/docker/go-plugins-helpers/blob/master/volume/api.go)找到。

驱动程序接口的功能显示，卷驱动程序专注于卷的基本操作，如`Create`、`List`、`Get`和`Remove`操作。插件负责将卷挂载到容器中并从容器中卸载。如果要创建新的卷驱动程序，需要使用相应的请求和响应类型实现此接口。

Docker Hub 和开源社区已经提供了大量的卷插件。例如，目前在 Docker Hub 上已经分类和验证了 18 个卷插件：

![图 15.13：Docker Hub 上的卷插件](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_15_13.jpg)

图 15.13：Docker Hub 上的卷插件

大多数插件专注于从不同来源提供存储，如云提供商和存储技术。根据您的业务需求和技术堆栈，您可以在 Docker 设置中考虑卷插件。

在接下来的练习中，您将使用 SSH 连接在远程系统中创建卷，并在容器中创建卷。对于通过 SSH 连接创建和使用的卷，您将使用[`github.com/vieux/docker-volume-sshfs`](https://github.com/vieux/docker-volume-sshfs)上提供的`open-source docker-volume-sshfs`插件。

## 练习 15.03：卷插件的实际应用

Docker 卷插件通过从不同提供商和技术提供存储来管理卷的生命周期。在这个练习中，您将安装和配置一个卷插件，以通过 SSH 连接创建卷。在成功创建卷之后，您将在容器中使用它们，并确保文件被持久化。您可以使用`docker-volume-sshfs`插件来实现这个目标。

要完成这个练习，请执行以下步骤：

1.  在终端中运行以下命令安装`docker-volume-sshfs`插件：

```
docker plugin install --grant-all-permissions vieux/sshfs
```

此命令通过授予所有权限来安装插件：

![图 15.14：插件安装](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_15_14.jpg)

图 15.14：插件安装

1.  使用以下命令创建一个带有 SSH 连接的 Docker 容器，以便为其他容器提供卷：

```
docker run -d -p 2222:22 \
--name volume_provider \
rastasheep/ubuntu-sshd:14.04
```

此命令创建并运行一个名为`volume_provider`的`sshd`容器。端口`2222`被发布，并将在接下来的步骤中用于连接到此容器。

您应该会得到以下输出：

```
87eecaca6a1ea41e682e300d077548a4f902fdda21acc218a51253a883f725d
```

1.  通过运行以下命令创建一个名为`volume-over-ssh`的新卷：

```
docker volume create -d vieux/sshfs \
--name volume-over-ssh \
-o sshcmd=root@localhost:/tmp \
-o password=root \
-o port=2222
```

此命令使用`vieux/sshfs`驱动程序和`sshcmd`、`password`和`port`参数指定的`ssh`连接创建一个新卷：

```
volume-over-ssh
```

1.  通过运行以下命令在*步骤 3*中创建的卷中创建一个新文件并保存：

```
docker run --rm -v volume-over-ssh:/data busybox \
sh -c "touch /data/test.txt && echo 'Hello from Docker Workshop' >> /data/test.txt"
```

此命令通过挂载`volume-over-ssh`来运行一个容器。然后创建一个文件并写入其中。

1.  通过运行以下命令检查*步骤 4*中创建的文件的内容：

```
docker run --rm -v volume-over-ssh:/data busybox \
cat /data/test.txt
```

此命令通过挂载相同的卷来运行一个容器，并从中读取文件：

```
Hello from Docker Workshop
```

1.  （可选）通过运行以下命令删除卷：

```
docker volume rm volume-over-ssh
```

在这个练习中，您已经在 Docker 中安装并使用了卷插件。此外，您已经创建了一个卷，并从多个容器中用于写入和读取。

在接下来的活动中，您将使用网络和卷插件在 Docker 中安装 WordPress。

## 活动 15.01：使用网络和卷插件安装 WordPress

您的任务是在 Docker 中使用网络和卷插件设计和部署博客及其数据库作为微服务。您将使用 WordPress，因为它是最流行的内容管理系统，被超过三分之一的网站使用。存储团队要求您使用 SSH 来进行 WordPress 内容的卷。此外，网络团队希望您在容器之间使用 Weave Net 进行网络连接。使用这些工具，您将使用 Docker 插件创建网络和卷，并将它们用于 WordPress 及其数据库：

1.  使用 Weave Net 插件创建一个名为`wp-network`的 Docker 网络。

1.  使用`vieux/sshfs`驱动程序创建名为`wp-content`的卷。

1.  创建一个名为`mysql`的容器来运行`mysql:5.7`镜像。确保设置`MYSQL_ROOT_PASSWORD`、`MYSQL_DATABASE`、`MYSQL_USER`和`MYSQL_PASSWORD`环境变量。此外，容器应该使用*步骤 1*中的`wp-network`。

1.  创建一个名为`wordpress`的容器，并使用*步骤 2*中挂载在`/var/www/html/wp-content`的卷。对于 WordPress 的配置，不要忘记根据*步骤 3*设置`WORDPRESS_DB_HOST`、`WORDPRESS_DB_USER`、`WORDPRESS_DB_PASSWORD`和`WORDPRESS_DB_NAME`环境变量。此外，您需要将端口`80`发布到端口`8080`，可以从浏览器访问。

您应该运行`wordpress`和`mysql`容器：

![图 15.15：WordPress 和数据库容器](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_15_15.jpg)

图 15.15：WordPress 和数据库容器

此外，您应该能够在浏览器中访问 WordPress 设置屏幕：

![图 15.16：WordPress 设置屏幕](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_15_16.jpg)

图 15.16：WordPress 设置屏幕

注

此活动的解决方案可以通过此链接找到。

# 摘要

本章重点介绍了使用插件扩展 Docker。通过安装和使用 Docker 插件，可以通过自定义存储、网络或授权方法增强 Docker 操作。您首先考虑了 Docker 中的插件管理和插件 API。通过插件 API，您可以通过编写新插件来扩展 Docker，并使 Docker 为您工作。

本章然后涵盖了授权插件以及 Docker 守护程序如何配置以与插件一起工作。如果您在生产或企业环境中使用 Docker，授权插件是控制谁可以访问您的容器的重要工具。然后您探索了网络插件以及它们如何扩展容器之间的通信。

尽管 Docker 已经涵盖了基本的网络功能，但我们看了一下网络插件如何成为新网络功能的入口。这导致了最后一部分，其中介绍了卷插件，以展示如何在 Docker 中启用自定义存储选项。如果您的业务环境或技术堆栈要求您扩展 Docker 的功能，学习插件以及如何使用它们是至关重要的。

本章的结尾也标志着本书的结束。你从第一章开始学习 Docker 的基础知识，运行了你的第一个容器，看看你已经走了多远。在本书的学习过程中，你使用 Dockerfile 创建了自己的镜像，并学会了如何使用 Docker Hub 等公共仓库发布这些镜像，或者将它们存储在你的系统上运行的仓库中。你学会了使用多阶段的 Dockerfile，并使用 docker-compose 来实现你的服务。你甚至掌握了网络和容器存储的细节，以及在项目中实施 CI/CD 流水线和在 Docker 镜像构建中进行测试。

你练习了使用 Docker Swarm 和 Kubernetes 等应用程序编排你的 Docker 环境，然后更深入地了解了 Docker 安全和容器最佳实践。你的旅程继续进行，监控你的服务指标和容器日志，最后使用 Docker 插件来帮助扩展你的容器服务功能。我们涵盖了大量内容，以提高你对 Docker 的技能和知识。希望这将使你的应用经验达到一个新的水平。请参考交互式版本，了解如何在出现问题时进行故障排除和报告。你还将了解 Docker Enterprise 的当前状态以及在 Docker 的使用和开发方面即将迈出的重要步伐。
