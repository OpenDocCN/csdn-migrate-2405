# Kubernetes 无服务器应用手册（二）

> 原文：[`zh.annas-archive.org/md5/8919C4FA258132C529A8BB4FA8603A2F`](https://zh.annas-archive.org/md5/8919C4FA258132C529A8BB4FA8603A2F)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：使用 Funktion 进行无服务器应用程序

在我们继续在公共云中启动 Kubernetes 集群之前，我们将再看一个本地示例；这次我们将看一下 Funktion。我们将涵盖以下主题：

+   介绍 Funktion

+   安装和配置 Funktion

+   使用 Funktion 运行我们的第一个函数

+   Twitter 流

在我们开始安装和配置 Funktion 之前，我们应该花点时间讨论一下它的功能，因为它与本书中涵盖的其他框架有些不同。

# 介绍 Funktion

Funktion 的标语将其描述为基于事件的 Kubernetes Lambda 编程。从表面上看，Funktion 似乎与 Kubeless 和我们在前几章讨论过的其他无服务器框架非常接近。然而，它有自己的特色，使其与我们正在研究的其他框架有所不同。

我们正在研究的大多数无服务器函数都支持两种基本事件类型：

+   **HTTP**：这是通过标准 HTTP 请求将数据传递给框架的地方；通常数据将被发布为 JSON 对象

+   **订阅**：这是框架监听事件流中的主题的地方，例如，Kubeless 使用 Apache Kafka ([`kafka.apache.org/`](https://kafka.apache.org/))

Funktion 扩展了事件类型的数量 - 实际上，它支持大约 200 种不同类型的事件。这是一个相当大的飞跃！它使用 Apache Camel ([`camel.apache.org/`](https://camel.apache.org/)) 来实现这一点。Apache Camel 是一个开源的 Java 框架，作为开发人员的管道，允许他们摄取和发布数据。

为了让您了解 Apache Camel 和因此 Funktion 支持的一些事件流，以下是一些亮点：

+   AWS-SNS 支持与亚马逊的**简单通知服务**（**SNS**）一起使用

+   Braintree 允许与 Braintree 支付网关服务进行交互

+   etcd 允许您与 etcd 键值存储进行交互

+   Facebook 开放了完整的 Facebook API

+   GitHub 允许您监听来自 GitHub 的事件

+   Kafka - 像 Kubeless 一样，您可以订阅 Kafka 流

+   Twitter 让您能够监听标签、帖子等

还有许多其他服务，如 LinkedIn、Slack、各种 SQL 和 NoSQL 数据库、来自 AWS 的 S3 的文件服务、Dropbox 和 Box 等等。

所有这些选择使其与我们一直在研究和将要研究的其他框架相比，成为一个非常好的选择。

Funktion 部署由几个不同的组件组成。首先是一个**函数**；这就是代码本身，由 Kubernetes ConfigMap 管理。

单独的函数本身并不是很有用，因为它只存在于 ConfigMap 中。因此，我们需要一个**运行时**，一个在调用时执行函数的 Kubernetes 部署。当 Funktion 操作员（稍后会详细介绍）检测到添加了新函数时，将自动创建运行时。

接下来，我们有一个**连接器**；这是一个事件源的表示，就像我们在本节前面讨论的那些一样——它包含有关事件类型、配置（如 API 凭据）以及数据搜索参数的信息。

然后我们有**流程**；这是一系列步骤，可以从调用函数的连接器中消耗事件。

最后，我们有**Funktion**操作员。这是在 Kubernetes 中运行的一个 pod，监视构成我们的 Funktion 部署的所有组件，如函数、运行时、连接器和流程。它负责创建提供 Funktion 功能的 Kubernetes 服务。

Funktion 是开源的，根据 Apache 许可证 2.0 发布；它是由 fabric8 开发的，fabric8 是 Red Hat 的 JBoss 中间件平台的上游项目。fabric8 本身是一个基于 Docker、Kubernetes 和 Jenkins 的面向 Java 的微服务平台。它也与 Red Hat 自己的 OpenShift 平台很好地配合。

现在我们对 Funktion 与其他框架的区别有了一些背景了，我们可以看看如何在我们的单节点 Kubernetes 集群上安装它。

# 安装和配置 Funktion

使用 Funktion 有三个步骤。首先，我们需要安装命令行。这是大部分部署和管理我们的 Funktion 部署的命令将被输入的地方。一旦命令行客户端安装完成，我们可以使用 Minikube 启动我们的单节点 Kubernetes 集群，然后使用 Funktion CLI 引导我们的环境。

# 命令行客户端

与我们正在介绍的许多框架一样，Funktion 是用 Go 语言编写的。这意味着我们的三个平台都有独立的可执行文件。

然而，在撰写本文时，无论是在 macOS 上使用 Homebrew 还是在 Windows 10 专业版上使用 Chocolatey，都没有可用的安装程序，这意味着我们将在所有三个平台上进行手动安装。

可从 GitHub 项目的发布页面上获取可执行文件，网址为[`github.com/funktionio/funktion/releases/`](https://github.com/funktionio/funktion/releases/)。在撰写本文时，当前版本为 1.0.14，因此以下说明将涵盖该版本的安装；如果需要安装更新版本，请在以下命令中替换版本号。

让我们从如何在 macOS 上安装开始。

# macOS 10.13 High Sierra

在 macOS 上安装很简单，因为该项目已发布了未压缩的独立可执行文件。我们只需要下载正确的软件包并使其可执行。要做到这一点，请运行以下命令：

```
$ curl -L https://github.com/funktionio/funktion/releases/download/v1.0.14/funktion-darwin-amd64 > /usr/local/bin/funktion
$ chmod +x /usr/local/bin/funktion
```

现在，命令行工具已安装，我们可以通过运行以下命令来测试它：

```
$ funktion version
```

Funktion 版本将返回如下：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/684fc742-aa4d-49c0-83bd-4ab22703661d.png)

如您所见，虽然安装过程非常简单，但软件包不在 Homebrew 中可用也有一个缺点。如果在 Homebrew 中可用，那么更新到较新版本将更容易，因为 Homebrew 会在您运行时负责检查和安装升级：

```
$ brew update
$ brew upgrade
```

目前，如果需要升级，您将不得不删除当前版本并下载新版本来替换它。

# Windows 10 专业版

在 Windows 上安装 Funktion 命令行客户端的过程与 macOS 类似。首先，以管理员用户身份打开 PowerShell 窗口，方法是从任务栏中的 PowerShell 菜单中选择以管理员身份运行。一旦打开，您应该看到您在文件夹`C:\WINDOWS\system32`中；如果没有，请运行：

```
$ cd C:\WINDOWS\system32
```

一旦您在`C:\WINDOWS\system32`文件夹中，请运行以下命令：

```
$ Invoke-WebRequest -Uri https://github.com/funktionio/funktion/releases/download/v1.0.14/funktion-windows-amd64.exe -UseBasicParsing -OutFile funktion.exe
```

然后，您应该能够通过运行以下命令来检查已安装的 Funktion 命令行客户端的版本：

```
$ funktion version
```

Funktion 版本将返回如下：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/ece541a5-0e24-42fb-83f1-c3578a9c610e.png)

同样，由于我们没有使用软件包管理器来安装 Funktion，因此如果要升级，您将不得不删除旧的可执行文件，然后重复安装过程，并确保更新 URL 中的版本号以反映您所需的版本。

# Ubuntu 17.04

最后，我们有 Ubuntu 17.04。安装过程与我们为 macOS 执行的命令基本相同。但是，要确保我们下载正确的可执行文件，并且在`/usr/local/bin`文件夹的权限在操作系统之间略有不同时，我们还需要使用`sudo`命令：

```
$ sudo sh -c "curl -L https://github.com/funktionio/funktion/releases/download/v1.0.14/funktion-linux-amd64 > /usr/local/bin/funktion"
$ sudo chmod +x /usr/local/bin/funktion
```

下载并使其可执行后，您应该能够运行：

```
$ funktion version
```

你应该看到类似以下的内容：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/05a226e2-1ff8-4f7a-8654-2beb75cd8fcd.png)

现在我们在三个操作系统上都安装了命令行客户端，我们可以继续部署。

# 启动单节点 Kubernetes 集群

你可能已经注意到，我们再次发现自己处于一个位置，现在可以在任何操作系统上使用相同的命令。这意味着本章剩余的命令将能够在我们的三个目标操作系统上运行。

在使用 Minikube 启动我们的单节点 Kubernetes 集群之前，可以通过运行以下命令检查是否有任何更新。macOS 10.13 High Sierra 用户可以运行：

```
$ brew update
$ brew upgrade
```

然后，要检查和更新 Minikube，请运行以下命令，从以下开始：

```
$ brew cask outdated
```

这将向您呈现可以更新的软件包列表。如果 Minikube 在列表中，请运行以下命令：

```
$ brew cask reinstall minikube
```

Windows 10 专业版用户可以运行：

```
$ choco upgrade all
```

Ubuntu 17.04 用户需要检查第三章中的发布页面详细信息，*在本地安装 Kubernetes*，删除旧的二进制文件，并使用更新的版本重复安装过程。

一旦您检查了 Minikube 的更新，可以通过运行以下命令启动您的集群：

```
$ minikube start
```

根据第三章，*在本地安装 Kubernetes*和第四章，*介绍 Kubeless 功能*，这将启动单节点 Kubernetes 集群，并配置您的本地 Kubernetes 客户端与其交互。如果您已经更新了 Minikube，您可能还会注意到下载并安装了一个更新版本的 Kubernetes：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/ae41ec23-755c-4e99-817c-11ec3884c41d.png)

如果你已经升级了 Minikube，可以使用以下命令检查一切是否正常运行：

```
$ minikube status
$ kubectl get all
$ minikube dashboard
```

现在我们的单节点 Kubernetes 集群已经重新启动运行，Funktion 安装的最后阶段是引导部署。

# 引导 Funktion

安装 Funktion 非常简单，事实上，只需要一个命令：

```
$ funktion install platform
```

这将给出以下输出：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/8f6ea10f-3067-4c3d-a405-4c57cd5cc3dd.png)

一两分钟后，您应该能够运行：

```
$ kubectl get pods
$ kubectl get deployments
```

上述命令将检查部署的状态：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/df639ea0-009b-40ca-a096-94488c7ea422.png)

您还应该能够在 Kubernetes 仪表板中看到 Pods 和 Deployments：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/b21219ed-9f41-4034-984f-8a4a82a2c85c.png)

运行以下命令应该返回一个空列表：

```
$ funktion get function
```

这证明了 Funktion 命令行客户端可以连接到您新安装的 Funktion 部署并与其交互。

# 部署一个简单的函数

现在我们的 Funktion 部署已经运行起来了，我们可以看一下部署一个非常简单的 hello world 示例。在支持本书的 GitHub 存储库中的`/Chapter05/hello-world/src`文件夹中，您会找到一个名为`hello.js`的文件。这个文件包含以下代码：

```
module.exports = function(context, callback) {
  var name = context.request.query.name || context.request.body || "World";
  callback(200, "Hello " + name + "!!");
};
```

在`/Chapter05/hello-world/`文件夹中运行以下命令将使用上述代码创建我们的第一个函数：

```
$ funktion create fn -f src/hello.js
```

输出应该如下所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/600fedfc-5558-4f33-a151-a7981b66f6a5.png)

从终端输出中可以看出，这创建了一个名为`hello`的`function`。现在，我们运行以下命令：

```
$ funktion get function
```

这应该返回一些结果。从以下输出中可以看出，我们现在可以看到`NAME`，`PODS`和`URL`列出：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/3ff904eb-5dd0-45c8-8d54-5a3cda0f18b0.png)

我们可以运行以下命令来仅返回函数的`URL`，或在浏览器中打开它：

```
$ funktion url fn hello
$ funktion url fn hello -o
```

您应该看到以下结果：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/f9b79f93-0384-4443-b1d8-796a0f19eace.png)

打开的浏览器窗口显示如下。我相信您会同意这不是最令人兴奋的页面：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/cdee65b3-4613-48ec-a18f-9d315546065c.png)

但它确实证明了我们的函数正在工作并显示内容。您可以通过运行以下命令来显示函数的日志：

```
$ funktion logs function hello
```

这将实时将日志内容流式传输到您的终端窗口。您可以通过刷新浏览器几次来查看，您应该看到您的页面请求与内部健康检查请求一起被记录。

现在我们已经创建了我们的第一个函数，我们可以安装一些连接器。要这样做，请运行以下命令：

```
$ funktion install connector http4 timer twitter
```

现在我们安装了一些连接器，我们可以创建一个流程。我们的第一个流程将使用定时器连接器：

```
$ funktion create flow timer://foo?period=5000 http://hello/
```

这将创建一个名为`foo`的流程，每`5000`毫秒执行一次，目标是我们称为`hello`的函数。要获取有关流程的信息，可以运行以下命令：

```
$ funktion get flow
```

您应该看到以下内容：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/692c3065-80b5-4b34-957c-ada291af1fdf.png)

正如您所看到的，流程称为`timer-foo1`；我们在与其交互时需要使用此名称。例如，您可以通过运行以下命令来检查流程的日志：

```
$ funktion logs flow timer-foo1
```

或者在 Kubernetes 仪表板中，您可以找到名为`timer-foo1`的 pod，并在那里检查日志：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/6ae5d078-e47f-4af9-a05e-9d29cac3ef39.png)

通过运行以下命令检查函数的日志：

```
$ funktion logs function hello
```

您应该看到每五秒有一个来自用户代理为`Apache-HttpClient/4.5.2`的客户端的页面请求。这是计时器流程：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/09ce6583-f8c7-45cf-8f48-c14acaa401e2.png)

要删除流程，只需运行：

```
$ funktion delete flow timer-foo1
```

这将删除运行连接器的 pod，并且您的函数将停止接收自动请求。

返回 Kubernetes 仪表板，单击 Config Maps 应该显示 Funktion 创建的所有内容的列表。正如您所看到的，Funktion 的大部分部分都有一个 ConfigMap：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/9943de0f-e06d-4673-a155-c34fe2a1fc81.png)

单击`hello`的 Config Maps 将显示类似以下页面的内容：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/4ac40215-c69f-42c1-ba2f-8d7853c9f080.png)

正如您所看到的，这包含了我们函数的代码，并且它已自动检测到它是用 Node.js 编写的，还有它是从`src`文件夹部署的。

在查看更高级示例之前，还有一件可能会让您感兴趣的事情，那就是与*Chrome Dev*工具的集成。要做到这一点，请运行以下命令：

```
$ funktion debug fn hello
```

这将在前台打开一个进程，并为您提供一个 URL 放入 Google Chrome 中：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/62def47d-76d9-4c17-bfd8-08798e93ca02.png)

一旦您打开 Google Chrome 并指向您的函数，您可以执行诸如直接在浏览器中编辑代码之类的任务：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/1675f236-2d75-405f-af6c-cfc913783906.png)使用 Chrome Dev 工具进行的任何更改都将直接在 pod 内进行，并且如果重新启动 pod，这些更改将不会持久保存；这应该纯粹用于测试。

要删除我们的`hello`函数，我们只需要运行：

```
$ funktion delete function hello
```

这应该让我们得到一个干净的安装，准备进行更高级的示例。

# Twitter 流

在上一节中我们安装了 Twitter 连接器，让我们看看如何配置它来拉取一些数据。首先，您可以通过运行以下命令查看连接器的所有可配置选项：

```
$ funktion edit connector twitter -l
```

你应该看到类似以下的终端输出：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/8e704887-839f-4a85-b6e4-589f47c085c8.png)

如您所见，您可以配置代理，并提供`accessToken`、`accessTokenSecret`、`consumerKey`和`consumerSecret`。您应该从上一章中获得这些信息。如果没有，那么请使用第四章中的说明重新生成它们，*介绍 Kubeless 功能*。

就像我将用来演示您需要运行的命令的令牌和密钥一样，前面截图中列出的详细信息是默认的虚拟占位符详细信息，不是有效的。

要使用您自己的详细信息更新连接器，请运行以下命令，并确保用您自己的详细信息替换它们：

```
$ funktion edit connector twitter \
 accessToken=1213091858-REJvMEEUeSoGA0WPKp7cv8BBTyTcDeRkHBr6Wpj \
 accessTokenSecret=WopER9tbSJtUtASEz62lI8HTCvhlYBvDHcuCIof5YzyGg \
 consumerKey=aKiWFB6Q7Ck5byHTWu3zHktDF \
 consumerSecret=uFPEszch9UuIlHt6nCxar8x1DSYqhWw8VELqp3pMPB571DwnDg
```

您应该收到连接器已更新的确认。现在，我们可以启动使用 Twitter 适配器的流程。为此，我们应该运行以下命令：

```
$ funktion create flow --name twitsearch "twitter://search?type=polling&keywords=kubernetes&delay=120s"
$ funktion get flows
```

我们将看到以下内容：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/8b8b8510-287d-44c3-bf45-0b177377ac3e.png)

一旦您启动了 pod，您可以通过运行以下命令来检查日志：

```
$ funktion logs flow twitsearch
```

或者通过在仪表板中查看`twitsearch` pod 的日志：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/b28585bf-ed9d-461c-876f-5ba68769c7c6.png)

如您所见，Camel 正在打印包含单词 Kubernetes 的一系列推文。您的应用程序可以订阅此流，并对推文进行处理。最后，运行以下命令将删除流程：

```
$ funktion delete flow twitsearch
```

然后，您可以使用`minikube delete`命令删除您的 Minikube 机器。

# 总结

在本章中，我们简要介绍了 Funktion。我们安装了命令行客户端，然后将其安装在我们的单节点 Kubernetes 集群上。部署后，我们启动了一个测试函数，并与其交互，然后使用其中的一个事件流来搜索包含 Kubernetes 的推文。

Funktion 仍处于早期开发阶段，目前拥有一个小而活跃的社区，他们在项目的 GitHub 页面上做出贡献。因此，在撰写本文时，还没有太多利用 Funktion 支持的 Apache Camel 的许多流程的完整应用实例。如果您计划编写任何摄取数据然后处理数据的应用程序，我建议您密切关注 Funktion。

在下一章中，我们将讨论如何将我们的 Kubernetes 集群从本地单节点扩展到托管在公共云上的多节点集群。


# 第六章：在云中安装 Kubernetes

到目前为止，我们一直在本地机器上运行 Kubernetes。这确实有一些缺点，其中之一是处理能力。我们将开始研究一些更复杂和强大的框架，因此我们需要一些额外的能力。因此，我们将尝试在几个不同的公共云上安装 Kubernetes，每次使用不同的工具：

+   在 DigitalOcean 上启动 Kubernetes

+   在 AWS 上启动 Kubernetes

+   在 Microsoft Azure 上启动 Kubernetes

+   在 Google 云平台上启动 Kubernetes

然后，我们将研究公共云提供商之间的差异，并尝试在其中一个平台上安装 Kubeless。

# 在 DigitalOcean 上启动 Kubernetes

我们将首先研究的公共云平台是 DigitalOcean。DigitalOcean 与我们将在接下来的章节中研究的三大云平台有所不同，因为它的功能较少。例如，在产品页面上，DigitalOcean 列出了八个功能，而 AWS 产品页面列出了十八个主要领域，每个领域又分为六个或更多的功能和服务。

不要因此而认为 DigitalOcean 比我们在本章中将要研究的其他公共云提供商差。

DigitalOcean 的优势在于它是一个非常简单易用的托管平台。通过其直观的 API 和命令行工具，支持服务和出色的管理界面，可以在不到一分钟内轻松启动功能强大但价格竞争力极强的虚拟机。

# 创建 Droplets

Droplets 是 DigitalOcean 对其计算资源的术语。对于我们的 Kubernetes，我们将启动三个 Ubuntu 17.04 Droplets，每个 Droplet 配备 1GB 的 RAM，1 个 CPU 和 30GB 的 SSD 存储。

在撰写本文时，这个由三个 Droplet 组成的集群每月大约需要花费 30 美元才能保持在线。如果您打算在需要时保持在线，那么这三个 Droplets 每小时的费用将是 0.045 美元。

在您创建任何 Droplets 之前，您需要一个帐户；您可以在[`cloud.digitalocean.com/registrations/new`](https://cloud.digitalocean.com/registrations/new)注册 DigitalOcean。注册后，在您进行任何其他操作之前，我建议您立即在您的帐户上启用双因素身份验证。您可以在帐户安全页面上启用此功能[`cloud.digitalocean.com/settings/security/`](https://cloud.digitalocean.com/settings/security/)。

启用双因素身份验证将为您提供额外的安全级别，并帮助保护您的帐户免受任何未经授权的访问以及意外费用的影响。毕竟，您不希望有人登录并使用您的帐户创建 25 个最昂贵的 Droplets，并由您来支付账单。

双因素身份验证通过向您的帐户引入第二级身份验证来工作；通常这是一个由应用程序（如 Google Authenticator）在您的移动设备上生成的四位或六位代码，或者是由您尝试登录的服务发送的短信。这意味着即使您的密码被泄露，攻击者仍然需要访问您的移动设备或号码。

接下来，我们需要生成一个 SSH 密钥并将其上传到 DigitalOcean。如果您已经有一个带有 SSH 密钥的帐户，可以跳过此任务。如果您没有密钥，请按照给定的说明操作。

如果您使用的是 macOS High Sierra 或 Ubuntu 17.04，则可以运行以下命令：

```
$ ssh-keygen -t rsa
```

这将要求您选择一个位置来存储您新生成的私钥和公钥，以及一个密码。密码是可选的，但如果您的 SSH 密钥的私有部分落入错误的手中，它确实会增加另一层安全性：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/b197999c-a3db-4b61-80f7-8a9967e43614.png)

生成密钥后，您需要记下密钥的公共部分。为此，请运行以下命令，并确保更新密钥路径以匹配您自己的路径：

```
$ cat /Users/russ/.ssh/id_rsa.pub
```

您应该看到类似以下的内容：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/6c023c80-d5db-42dd-b09b-82601af14d8e.png)请确保不要分享或发布您的 SSH 密钥的私有部分（文件名不包含`.pub`）。这用于对公钥的公共部分进行身份验证。如果这落入错误的手中，他们将能够访问您的服务器/服务。

对于 Windows 10 专业版用户来说，你很可能正在使用 PuTTY 作为你的 SSH 客户端。如果你没有 PuTTY，你可以通过运行以下命令来安装它：

```
$ choco install putty
```

一旦 PuTTY 安装完成，你可以通过运行以下命令打开 PuTTYgen 程序：

```
$ PUTTYGEN.exe
```

打开后，点击生成并按照提示在空白区域移动你的光标。一秒钟后，你应该会生成一个密钥：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/e9c36baa-2ebd-4faf-8f9b-ce54da273c49.png)

如前面的截图所示，你可以选择添加一个密码，这将用于解锁你的密钥的私有部分；再次强调，这是可选的。

点击保存公钥，也保存私钥，并记下公钥的内容。

现在你有了你的公钥，我们需要让 DigitalOcean 拥有一份副本。为此，转到安全页面，你可以在[`cloud.digitalocean.com/settings/security/`](https://cloud.digitalocean.com/settings/security/)找到它，然后点击添加 SSH 密钥。这将弹出一个对话框，要求你提供你的公钥内容并命名它。填写两个表单字段，然后点击添加 SSH 密钥按钮。

现在你已经为你的账户分配了一个 SSH 密钥，你可以使用它来创建你的 Droplets，并且无需密码即可访问它们。要创建你的 Droplets，点击屏幕右上角的创建按钮，然后从下拉菜单中选择 Droplets。

在 Droplet 创建页面上有几个选项：

+   选择一个镜像：选择 Ubuntu 16.04 镜像

+   选择一个大小：选择每月 10 美元的选项，其中包括 1GB、1CPU 和 30GB SSD

+   添加块存储：保持不变

+   选择数据中心区域：选择离你最近的区域；我选择了伦敦，因为我在英国

+   选择附加选项：选择私人网络连接。

+   添加你的 SSH 密钥：选择你的 SSH 密钥

+   完成并创建：将 Droplets 的数量增加到`3`，现在保持主机名不变

填写完前面的部分后，点击页面底部的创建按钮。这将启动你的三个 Droplets，并向你反馈它们创建过程的进度。一旦它们启动，你应该会看到类似以下页面的内容：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/bef96a2d-ae01-4683-946b-4bf519107cbb.png)

如你所见，我有三个 Droplets，它们的 IP 地址，还有一条很好的激励性信息。现在我们可以开始使用`kubeadm`部署我们的 Kubernetes 集群。

# 使用 kubeadm 部署 Kubernetes

首先，我们需要登录到我们的三个 Droplets 中的一个；我们登录的第一台机器将是我们的 Kubernetes 主节点。

```
$ ssh root@139.59.180.255
```

登录后，以下两个命令检查软件包是否有更新并应用它们：

```
$ apt-get update
$ apt-get upgrade
```

现在我们已经是最新的了，我们可以安装先决条件软件包。要做到这一点，请运行以下命令：

```
$ apt-get install docker.io curl apt-transport-https
```

您可能会注意到，我们使用的是作为核心 Ubuntu 16.04 软件包存储库的一部分分发的 Docker 版本，而不是官方的 Docker 发布版。这是因为`kubeadm`不支持更新版本的 Docker，并且推荐的版本是 1.12。目前，Ubuntu 16.04 支持的 Docker 版本是 1.12.6。

现在我们已经安装了先决条件，我们可以通过运行以下命令来添加 Kubernetes 存储库：

```
$ curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key add -
$ cat <<EOF >/etc/apt/sources.list.d/kubernetes.list
deb http://apt.kubernetes.io/ kubernetes-xenial main
EOF
```

`curl`命令为存储库添加了 GPG 密钥，`cat`命令创建了存储库文件。现在存储库已经就位，我们需要通过运行以下命令更新我们的软件包列表并安装`kubeadm`、`kubelet`和`kubectl`：

```
$ apt-get update
$ apt-get install kubelet kubeadm kubectl
```

安装完成后，您可以通过运行以下命令来检查已安装的`kubeadm`的版本：

```
$ kubeadm version
```

现在我们已经安装了所需的一切，我们可以通过运行以下命令来引导我们的 Kubernetes 主节点：

```
$ kubeadm init
```

这将需要几分钟的时间运行，并且您将得到一些非常冗长的输出，让您知道`kubeadm`已经完成了哪些任务：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/ce95dd39-8086-4fca-97fb-f99503f2083e.png)

完成后，您应该看到以下消息，但是带有您的令牌等：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/936836b4-047f-4bb9-8d89-1bb205a6dbd2.png)

记下底部的`kubeadm join`命令，我们很快会看到它。我们应该运行消息中提到的命令：

```
$ mkdir -p $HOME/.kube
$ sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
$ sudo chown $(id -u):$(id -g) $HOME/.kube/config
```

接下来，我们需要启用 Pod 网络。您可以选择几种选项，所有这些选项都为您的 Kubernetes 集群提供了多主机容器网络：

+   Calico: [`www.projectcalico.org/`](https://www.projectcalico.org/)

+   Canal: [`github.com/projectcalico/canal`](https://github.com/projectcalico/canal)

+   flannel: [`coreos.com/flannel/docs/latest/`](https://coreos.com/flannel/docs/latest/)

+   Kube-router: [`github.com/cloudnativelabs/kube-router/`](https://github.com/cloudnativelabs/kube-router/)

+   Romana: [`github.com/romana/romana/`](https://github.com/romana/romana/)

+   Weave Net: [`www.weave.works/oss/net/`](https://www.weave.works/oss/net/)

对于我们的安装，我们将使用 Weave Net。要安装它，只需运行以下命令：

```
$ export kubever=$(kubectl version | base64 | tr -d '\n')
$ kubectl apply -f "https://cloud.weave.works/k8s/net?k8s-version=$kubever"
```

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/858ea84d-5030-443e-826d-d4bfbc749475.png)

如您所见，这使用了`kubectl`命令来部署 pod 网络。这意味着我们的基本 Kubernetes 集群已经运行起来了，尽管只在单个节点上。

为了准备其他两个集群节点，打开两者的 SSH 会话，并在两者上运行以下命令：

```
$ apt-get update
$ apt-get upgrade
$ apt-get install docker.io curl apt-transport-https
$ curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key add -
$ cat <<EOF >/etc/apt/sources.list.d/kubernetes.list
deb http://apt.kubernetes.io/ kubernetes-xenial main
EOF
$ apt-get update
$ apt-get install kubelet kubeadm kubectl
```

如您所见，这些是我们在主节点上执行的确切一组命令，使我们能够执行`kubeadm`命令的命令。您可能已经猜到，我们将运行我们初始化主节点时收到的`kubeadm join`命令，而不是运行`kubeadm init`。对我来说，该命令如下：

```
$ kubeadm join --token 0c74f5.4d5492bafe1e0bb9 139.59.180.255:6443 --discovery-token-ca-cert-hash sha256:3331ba91e4a3a887c99e59d792b9f031575619b4646f23d8fe2938dc50f89491
```

您需要运行收到的命令，因为令牌将绑定到您的主节点。在两个节点上运行该命令，您应该会看到类似以下终端输出的内容：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/2b0ecfd2-6df2-4b0f-9870-f26c3e4199c1.png)

一旦您在剩余的两个节点上运行了该命令，请返回到您的主节点并运行以下命令：

```
$ kubectl get nodes
```

这应该返回您的 Kubernetes 集群中的节点列表：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/87ad7e15-3fad-4c30-9a97-d80053b3b240.png)

如您所见，我们有一个由三个 Droplets 组成的集群。唯一的缺点是，目前我们必须登录到我们的主节点才能与我们的集群交互。幸运的是，这很容易解决，我们只需要下载集群`admin.conf`文件的副本。

要在 macOS High Sierra 或 Ubuntu 17.04 上执行此操作，请运行以下命令，确保将 IP 地址替换为您的主节点的 IP 地址：

```
$ scp root@139.59.180.255:/etc/kubernetes/admin.conf 
```

如果您使用的是 Windows 10 专业版，您将需要使用诸如 WinSCP 之类的程序。要安装它，请运行以下命令：

```
$ choco install winscp
```

安装后，通过输入`WINSCP.exe`来启动它，然后按照屏幕提示连接到您的主节点并下载`admin.conf`文件，该文件位于`/etc/kubernetes/`中。

一旦您有了`admin.conf`文件的副本，您就可以在本地运行以下命令来查看您的三节点 Kubernetes 集群：

```
$ kubectl --kubeconfig ./admin.conf get nodes
```

一旦我们确认可以使用本地的`kubectl`副本连接，我们应该将配置文件放在适当的位置，这样我们就不必每次使用`--kubeconfig`标志。要做到这一点，请运行以下命令（仅适用于 macOS 和 Ubuntu）：

```
$ mv ~/.kube/config ~/.kube/config.mini
$mv admin.conf ~/.kube/config
```

现在运行以下命令：

```
$ kubectl get nodes
```

这应该显示您的三个 Droplets：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/a370c935-481e-482d-9067-0c81b33b6239.png)

# 删除集群

要删除集群，只需登录到您的 DigitalOcean 控制面板，然后单击每个 Droplet 右侧的更多下拉菜单中的销毁链接。然后按照屏幕上的说明进行操作。确保销毁所有三个 Droplets，因为它们在线时会产生费用。

这是在低规格服务器上手动部署 Kubernetes。在接下来的几节中，我们将看看如何在其他公共云中部署 Kubernetes，首先是 AWS。

# 在 AWS 中启动 Kubernetes

我们可以使用几种工具在 AWS 上启动 Kubernetes 集群；我们将介绍一个叫做`kube-aws`的工具。不幸的是，`kube-aws`不支持基于 Windows 的机器，因此以下说明只适用于 macOS High Sierra 和 Ubuntu 17.04。

`kube-aws`是一个命令行工具，用于生成 AWS CloudFormation 模板，然后用于启动和管理 CoreOS 集群。然后将 Kubernetes 部署到 CoreOS 实例的集群中。

AWS CloudFormation 是亚马逊的本地脚本工具，允许您以编程方式启动 AWS 服务；它几乎涵盖了所有 AWS API。CoreOS 是一个专注于运行容器的操作系统。它的占用空间极小，并且设计为可以在云提供商上直接进行集群和配置。

# 设置

在第一章中，*无服务器景观*，我们看了一下创建 Lambda 函数。为了配置这个，我们安装了 AWS CLI。我假设您仍然配置了这个，并且您配置的 IAM 用户具有管理员权限。您可以通过运行以下命令来测试：

```
$ aws ec2 describe-instances
```

这应该返回类似以下内容：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/4a459583-2e01-466f-b259-998be9d081cb.png)

我们需要将我们的 SSH 密钥导入 AWS。要做到这一点，打开 AWS 控制台（[`console.aws.amazon.com/`](https://console.aws.amazon.com/)）。登录后，从页面顶部的服务菜单中选择 EC2。一旦您进入 EC2 页面，请确保使用页面右上角的区域下拉菜单选择了正确的区域。我将使用欧盟（爱尔兰）,也就是 eu-west-1。

现在我们在正确的区域，点击密钥对选项，在左侧菜单的 NETWORK & SECURITY 部分下可以找到。页面加载后，点击导入密钥对按钮，然后像 DigitalOcean 一样，输入您的密钥对的名称，并在其中输入您的`id_rsa.pub`文件的内容。

接下来，我们需要一个 AWS KMS 存储。要创建这个，运行以下命令，确保根据需要更新您的区域：

```
$ aws kms --region=eu-west-1 create-key --description="kube-aws assets"
```

这将返回几个信息，包括一个 Amazon 资源名称（ARN）。记下这个信息以及`KeyId`：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/fe0b72a4-0a71-4b9b-b749-5b8f6c8f4231.png)

接下来，我们需要一个 Amazon S3 存储桶。使用 AWS CLI 运行以下命令来创建一个，确保更新区域，并且使存储桶名称对您来说是唯一的：

```
$ aws s3api --region=eu-west-1 create-bucket --bucket kube-aws-russ --create-bucket-configuration LocationConstraint=eu-west-1
```

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/597991ee-ed09-4578-9ecf-fa5e501e515b.png)

现在我们已经导入了我们的公共 SSH 密钥，有了 KMS ARN 和一个 S3 存储桶，我们只需要决定集群的 DNS 名称。

我将使用`kube.mckendrick.io`，因为我已经在 Amazon Route 53 DNS 服务上托管了`mckendrick.io`。您应该选择一个可以在其上配置 CNAME 的域或子域，或者一个托管在 Route 53 上的域。

现在我们已经掌握了基础知识，我们需要安装`kube-aws`二进制文件。要做到这一点，如果您正在运行 macOS High Sierra，您只需要运行以下命令：

```
$ brew install kube-aws
```

如果您正在运行 Ubuntu Linux 17.04，您应该运行以下命令：

```
$ cd /tmp
$ wget https://github.com/kubernetes-incubator/kube-aws/releases/download/v0.9.8/kube-aws-linux-amd64.tar.gz
$ tar zxvf kube-aws-linux-amd64.tar.gz
$ sudo mv linux-amd64/kube-aws /usr/local/bin
$ sudo chmod 755 /usr/local/bin/kube-aws
```

安装完成后，运行以下命令确认一切正常：

```
$ kube-aws version
```

在撰写本文时，当前版本为 0.9.8。您可以在发布页面上检查更新版本：[`github.com/kubernetes-incubator/kube-aws/releases/`](https://github.com/kubernetes-incubator/kube-aws/releases/)。

# 使用 kube-aws 启动集群

在我们开始创建集群配置之前，我们需要创建一个工作目录，因为将会创建一些工件。让我们创建一个名为`kube-aws-cluster`的文件夹并切换到它：

```
$ mkdir kube-aws-cluster
$ cd kube-aws-cluster
```

现在我们在我们的工作目录中，我们可以创建我们的集群配置文件。要做到这一点，运行以下命令，确保用之前部分收集的信息替换值：

如果您没有使用 Route 53 托管的域，删除`--hosted-zone-id`标志。

```
kube-aws init \
 --cluster-name=kube-aws-cluster \
 --external-dns-name=kube.mckendrick.io \
 --hosted-zone-id=Z2WSA56Y5ICKTT \
 --region=eu-west-1 \
 --availability-zone=eu-west-1a \
 --key-name=russ \
 --kms-key-arn="arn:aws:kms:eu-west-1:687011238589:key/2d54175d-41e1-4865-ac57-b3c40d0c4c3f"
```

这将创建一个名为`cluster.yaml`的文件，这将是我们配置的基础：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/ab65345d-4e0d-470c-ac19-a7c47f1bf46d.png)

接下来，我们需要创建将被我们的 Kubernetes 集群使用的证书。要做到这一点，请运行以下命令：

```
$ kube-aws render credentials --generate-ca
```

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/a44dd8df-779c-4e89-8153-51d7e1464682.png)

接下来，我们需要生成 AWS CloudFormation 模板。要做到这一点，请运行以下命令：

```
$ kube-aws render stack
```

这将在名为`stack-templates`的文件夹中创建模板：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/40ead830-2614-469f-a53d-119bf97b05fa.png)

在您的工作目录中运行`ls`应该会显示已创建的几个文件和文件夹：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/24c33f41-0a38-4dca-ae0f-8ec08b844605.png)

最后，我们可以运行以下命令来验证并上传文件到我们的 S3 存储桶，记得用您自己的存储桶名称更新命令：

```
$ kube-aws validate --s3-uri s3://kube-aws-russ/kube-aws-cluster
```

现在我们可以启动我们的集群。要做到这一点，只需运行以下命令，确保您更新存储桶名称：

```
$ kube-aws up --s3-uri s3://kube-aws-russ/kube-aws-cluster
```

这将开始使用 AWS CloudFormation 工具启动我们的集群：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/316018ed-2bd7-4db0-87c5-d1b4f760b448.png)

这个过程将需要几分钟；您可以在 AWS 控制台的命令行上查看其进度。要在控制台中查看它，请转到服务菜单并选择 CloudFormation。一旦打开，您应该会看到列出的一些堆栈；选择其中一个，然后单击事件选项卡：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/a43c7b15-c7a5-4922-99c2-9dad09494263.png)

从事件和资源选项卡中可以看出，后台有很多事情正在进行。有：IAM 角色、VPC 和网络、EC2 实例、负载均衡器、DNS 更新、自动缩放组等正在创建。

一旦完成，您应该会看到三个 CloudFormation 堆栈，一个主要的称为`kube-aws-cluster`，另外两个嵌套堆栈，一个称为`kube-aws-cluster-Controlplane`，另一个称为`kube-aws-cluster-Nodepool1`。两个嵌套堆栈都将在其名称后附加一个唯一的 ID。您将在命令行上收到集群已启动的确认：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/98e7b4a3-7a9b-417a-a464-994ae2edf13e.png)

在我们的工作目录中运行以下命令将列出 AWS Kubernetes 集群中的节点：

```
$ kubectl --kubeconfig=kubeconfig get nodes
```

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/0eb190c5-9323-4914-97d9-1574311e8040.png)

# Sock Shop

要测试我们的部署，我们可以启动 Sock Shop。这是由 Weave 编写的演示微服务应用程序。您可以在以下项目页面找到它：[`microservices-demo.github.io/`](https://microservices-demo.github.io/)。

要启动商店，我们需要从工作目录中运行以下命令：

```
$ kubectl --kubeconfig=kubeconfig create namespace sock-shop
$ kubectl --kubeconfig=kubeconfig apply -n sock-shop -f "https://github.com/microservices-demo/microservices-demo/blob/master/deploy/kubernetes/complete-demo.yaml?raw=true"
```

启动需要几分钟的时间；您可以通过运行以下命令来检查进度：

```
$ kubectl --kubeconfig=kubeconfig -n sock-shop get pods
```

等待每个 pod 获得运行状态，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/19341b3e-32db-423a-bdac-fc55e4c1d07f.png)

然后，我们应该能够访问我们的应用程序。要做到这一点，我们需要将其暴露给互联网。由于我们的集群在 AWS 中，我们可以使用以下命令启动一个弹性负载均衡器，并让它指向我们的应用程序：

```
$ kubectl --kubeconfig=kubeconfig -n sock-shop expose deployment front-end --type=LoadBalancer --name=front-end-lb
```

要获取有关我们的负载均衡器的信息，我们可以运行以下命令：

```
$ kubectl --kubeconfig=kubeconfig -n sock-shop get services front-end-lb
```

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/7613f52d-97c2-4551-8899-571b25b58e6d.png)

正如您所见，应用程序正在端口`8079`上暴露，但我们无法完全看到弹性负载均衡器的 URL。要获得这个，我们可以运行以下命令：

```
$ kubectl --kubeconfig=kubeconfig -n sock-shop describe services front-end-lb
```

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/a2ccd721-20a5-43ad-bba0-6165121ce8d2.png)

现在我们知道了弹性负载均衡器的 URL，我们可以将其输入到浏览器中，以及端口。对我来说，完整的 URL 是`http://a47ecf69fc71411e7974802a5d74b8ec-130999546.eu-west-1.elb.amazonaws.com:8079/`（此 URL 已不再有效）。

输入您的 URL 应该显示以下页面：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/13595402-f23d-478e-b25f-39e2acbc7f9c.png)

要删除 Sock Shop 应用程序，只需运行：

```
$ kubectl --kubeconfig=kubeconfig delete namespace sock-shop
```

这将删除我们创建的所有 pod、服务和弹性负载均衡器。

# 删除集群

让我们不要忘记，当集群正在运行时，它会花费我们的钱。要删除集群和 CloudFormation 脚本创建的所有服务，请运行以下命令：

```
$ kube-aws destroy
```

您将收到确认，CloudFormation 堆栈正在被移除，并且这将需要几分钟的时间。我建议您在 AWS 控制台上的 CloudFormation 页面上进行双重检查，以确保在移除堆栈过程中没有出现任何错误，因为任何仍在运行的资源可能会产生费用。

我们还需要删除我们创建的 S3 存储桶和 KMS；要做到这一点，请运行以下命令：

```
$ aws s3 rb s3://kube-aws-russ --force
$ aws kms --region=eu-west-1 disable-key --key-id 2d54175d-41e1-4865-ac57-b3c40d0c4c3f
```

您可以从您在本节早期创建 KMS 时所做的备注中找到`--key-id`。

虽然这次我们不必手动配置我们的集群，或者实际上登录到任何服务器，但启动我们的集群的过程仍然是非常手动的。对于我们的下一个公共云提供商 Microsoft Azure，我们将会看到更本地的部署。

# 在 Microsoft Azure 中启动 Kubernetes

在第一章中，《无服务器景观》，我们看了微软 Azure Functions；然而，我们没有进展到比 Azure web 界面更多的地方来启动我们的 Function。要使用**Azure 容器服务**（**AKS**），我们需要安装 Azure 命令行客户端。

值得一提的是，AKS 目前不支持 Windows 10 PowerShell Azure 工具。但是，如果您使用 Windows，不用担心，因为命令行客户端的 Linux 版本可以通过 Azure web 界面获得。

# 准备 Azure 命令行工具

Azure 命令行工具可以通过 macOS High Sierra 上的 Homebrew 获得，这样安装就像运行以下两个命令一样简单：

```
$ brew update
$ brew install azure-cli
```

Ubuntu 17.04 用户可以运行以下命令：

```
$ echo "deb [arch=amd64] https://packages.microsoft.com/repos/azure-cli/ wheezy main" | sudo tee /etc/apt/sources.list.d/azure-cli.list
$ sudo apt-key adv --keyserver packages.microsoft.com --recv-keys 52E16F86FEE04B979B07E28DB02C46DF417A0893
$ sudo apt-get install apt-transport-https
$ sudo apt-get update && sudo apt-get install azure-cli
```

安装完成后，您需要登录您的账户。要做到这一点，运行以下命令：

```
$ az login
```

当您运行该命令时，您将获得一个 URL，即[`aka.ms/devicelogin`](https://aka.ms/devicelogin)，[还有一个要输入的代码。在浏览器中打开 URL 并输入代码：](https://aka.ms/devicelogin)

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/62006a27-067a-4a96-9e0c-6092f9bc0294.png)

登录后，关闭浏览器窗口并返回到命令行，在几秒钟后，您将收到确认消息，说明您已经以您在浏览器中登录的用户身份登录。您可以通过运行以下命令来再次检查：

```
$ az account show
```

如前所述，Windows 用户可以使用 Azure web 界面访问他们自己的 bash shell。要做到这一点，登录并点击顶部菜单栏中的>_ 图标，选择 bash shell，然后按照屏幕提示操作。在设置结束时，您应该看到类似以下内容：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/dc2439b3-2e32-4cd6-8a0e-c800d832a281.png)

现在我们已经安装并连接到我们的账户的命令行工具，我们可以启动我们的 Kubernetes 集群。

# 启动 AKS 集群

首先，我们需要注册 AKS 服务。要做到这一点，运行以下命令：

```
$ az provider register -n Microsoft.ContainerService
```

注册需要几分钟的时间。您可以通过运行以下命令来检查注册的状态：

```
$ az provider show -n Microsoft.ContainerService
```

一旦看到`registrationState`为`Registered`，您就可以开始了。要启动集群，我们首先需要创建一个资源组，然后创建集群。目前，AKS 在`ukwest`或`westus2`都可用：

```
$ az group create --name KubeResourceGroup --location ukwest
$ az aks create --resource-group KubeResourceGroup --name AzureKubeCluster --agent-count 1 --generate-ssh-keys
```

一旦您的集群启动，您可以运行以下命令配置您的本地`kubectl`副本以对集群进行身份验证：

```
$ az aks get-credentials --resource-group KubeResourceGroup --name AzureKubeCluster
```

最后，您现在可以运行以下命令，开始与您的集群进行交互，就像与任何其他 Kubernetes 集群一样：

```
$ kubectl get nodes
```

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/2f217bab-7462-4f5e-8f09-6db19ed0e273.png)

您会注意到我们只有一个节点；我们可以通过运行以下命令添加另外两个节点：

```
$ az aks scale --resource-group KubeResourceGroup --name AzureKubeCluster --agent-count 3
$ kubectl get nodes
```

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/de2de76c-c091-4475-a503-ea5295fbbf4d.png)

您应该能够在 Azure Web 界面中看到所有已启动的资源：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/c2ea31e2-e863-431b-b43f-5833a66b4bff.png)

现在我们的集群中有三个节点，让我们启动*Sock Shop demo*应用程序。

# 袜店

这些命令与我们之前运行的命令略有不同，因为我们不必为`kubectl`提供配置文件：

```
$ kubectl create namespace sock-shop
$ kubectl apply -n sock-shop -f "https://github.com/microservices-demo/microservices-demo/blob/master/deploy/kubernetes/complete-demo.yaml?raw=true"
```

再次，您可以通过运行以下命令来检查 pod 的状态：

```
$ kubectl -n sock-shop get pods
```

一旦所有的 pod 都在运行，您可以通过运行以下命令暴露应用程序：

```
$ kubectl -n sock-shop expose deployment front-end --type=LoadBalancer --name=front-end-lb
$ kubectl -n sock-shop get services front-end-lb
$ kubectl -n sock-shop describe services front-end-lb
```

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/7b2c4723-430f-431e-9215-7c0b36174e3e.png)

这应该给您一个端口和 IP 地址。从前面的输出中可以看出，这给了我一个 URL `http://51.141.28.140:8079/`，将其放入浏览器中显示了 Sock Shop 应用程序。

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/917aa4e5-b3b1-464b-b915-f3dc80e22132.png)

要删除应用程序，我只需要运行：

```
$ kubectl delete namespace sock-shop
```

# 删除集群

与其他云服务一样，当您的 AKS 节点在线时，将按小时收费。完成集群后，您只需删除资源组；这将删除所有相关的服务：

```
$ az aks delete --resource-group KubeResourceGroup --name AzureKubeCluster
$ az group delete --name KubeResourceGroup
```

删除后，转到 Azure Web 界面，并手动删除任何其他剩余的资源/服务。我们接下来要看的下一个和最后一个公共云是 Google Cloud。

# 在 Google Cloud 平台上启动 Kubernetes

正如您所期望的，Kubernetes 在 Google Cloud 上得到了原生支持。在继续之前，您需要一个帐户，您可以在[`cloud.google.com/`](http://cloud.google.com/)注册。一旦您设置好了您的帐户，类似于本章中我们一直在研究的其他公共云平台，我们需要配置命令行工具。

# 安装命令行工具

所有三个操作系统都有安装程序。如果您使用的是 macOS High Sierra，则可以使用 Homebrew 和 Cask 通过运行以下命令安装 Google Cloud SDK：

```
$ brew cask install google-cloud-sdk
```

Windows 10 专业版用户可以使用 Chocolatey 并运行以下命令：

```
$ choco install gcloudsdk
```

最后，Ubuntu 17.04 用户需要运行以下命令：

```
$ export CLOUD_SDK_REPO="cloud-sdk-$(lsb_release -c -s)"
$ echo "deb http://packages.cloud.google.com/apt $CLOUD_SDK_REPO main" | sudo tee -a /etc/apt/sources.list.d/google-cloud-sdk.list
$ curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo apt-key add -
$ sudo apt-get update && sudo apt-get install google-cloud-sdk
```

安装完成后，您需要通过运行以下命令登录到您的帐户：

```
$ gcloud init
```

这将打开您的浏览器，并要求您登录到您的 Google Cloud 帐户。登录后，您将被要求授予 Google Cloud SDK 访问您的帐户的权限。按照屏幕上的提示授予权限，您应该收到一条消息，确认您已经通过 Google Cloud SDK 进行了身份验证。

回到您的终端，现在应该会提示您创建一个项目。出于测试目的，请回答是（`y`）并输入一个项目名称。这个项目名称必须对您来说是唯一的，所以可能需要尝试几次。如果一开始失败，您可以使用以下命令：

```
$ gcloud projects create russ-kubernetes-cluster
```

如您所见，我的项目名为`russ-kubernetes-cluster`。您应该在命令中引用您自己的项目名称。最后的步骤是将我们的新项目设置为默认项目以及设置区域。我使用了以下命令：

```
$ gcloud config set project russ-kubernetes-cluster
$ gcloud config set compute/zone us-central1-b
```

现在我们已经安装了命令行工具，我们可以继续启动我们的集群。

# 启动 Google 容器集群

您可以使用单个命令启动集群。以下命令将启动一个名为`kube-cluster`的集群：

```
$ gcloud container clusters create kube-cluster
```

当您第一次运行该命令时，可能会遇到一个错误，指出您的项目未启用 Google 容器 API：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/f1515c08-216b-461e-ae0b-d1e0679ccfca.png)

您可以通过按照错误中给出的链接并按照屏幕上的说明启用 API 来纠正此错误。如果您的项目没有与之关联的计费，您可能还会遇到错误：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/42f35b43-439d-4017-ac62-5dab26e669ee.png)

要解决这个问题，请登录到 Google Cloud 网页界面[`console.cloud.google.com/`](https://console.cloud.google.com/)，并从下拉列表中选择您的项目，该下拉列表位于 Google Cloud Platform 旁边。选择您的项目后，点击左侧菜单中的计费链接，并按照屏幕上的提示将您的项目链接到您的计费账户。

一旦您启用了 API 并将您的项目链接到一个计费账户，您应该能够重新运行以下命令：

```
$ gcloud container clusters create kube-cluster
```

这将需要几分钟的时间，但一旦完成，您应该会看到类似以下的内容：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/614a5108-804c-4c22-ba01-e9872ec4b62c.png)

如您所见，`kubectl`的配置已经自动更新，这意味着我们可以运行以下命令来检查我们是否可以与新的集群通信：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/c046a9de-762a-45a4-82e8-90b049fbef67.png)在运行此命令之前，请确保您的本地机器直接连接到互联网，并且您没有通过代理服务器或受到严格防火墙限制的连接，否则您可能无法使用`kubectl proxy`命令遇到困难。

您还应该能够在 Google Cloud 网络界面的容器引擎部分看到您的集群：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/068d1e13-23dc-49b1-8143-3fd4d78e8ca9.png)

现在我们的集群已经运行起来了，让我们再次启动 Sock Shop 应用程序。

# 袜子店

与 Azure 一样，这次也不需要提供配置文件，所以我们只需要运行以下命令：

```
$ kubectl create namespace sock-shop
$ kubectl apply -n sock-shop -f "https://github.com/microservices-demo/microservices-demo/blob/master/deploy/kubernetes/complete-demo.yaml?raw=true"
$ kubectl -n sock-shop get pods
$ kubectl -n sock-shop expose deployment front-end --type=LoadBalancer --name=front-end-lb
$ kubectl -n sock-shop get services front-end-lb
$ kubectl -n sock-shop describe services front-end-lb
```

如您从以下截图中所见，IP 和端口给了我一个`http://104.155.191.39:8079`的 URL：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/1d404220-cacb-44e1-8f3c-79ba92727fa0.png)

此外，在 Google Cloud 网络界面中，单击发现与负载平衡还应该显示我们创建的负载均衡器：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/f6bbf0fd-2dd9-409e-ab55-2ec961b3ff16.png)

单击界面中的链接，或将您的 URL 粘贴到浏览器中，应该会显示您熟悉的商店前台：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/1a0bebbd-c957-4589-8a79-71d9b9d0f0e5.png)

运行以下命令应该删除 Sock Shop 应用程序：

```
$ kubectl delete namespace sock-shop
```

# 运行 Kubeless

在删除 Google Cloud 三节点 Kubernetes 集群之前，让我们快速回顾一下 Kubeless。要部署 Kubeless，请运行以下命令：

```
$ kubectl create ns kubeless
$ kubectl create -f https://github.com/kubeless/kubeless/releases/download/v0.2.3/kubeless-v0.2.3.yaml
```

部署后，您可以通过运行以下命令来检查状态：

```
$ kubectl get pods -n kubeless
$ kubectl get deployment -n kubeless
$ kubectl get statefulset -n kubeless
```

您还可以在 Google Cloud 网络界面的 Google 容器引擎部分检查工作负载和发现与负载平衡。一旦 Kubeless 部署完成，返回到本书附带的存储库中的`/Chapter04/hello-world`文件夹，并运行以下命令部署测试函数：

```
**$ kubeless function deploy hello \**
 **--from-file hello.py \**
 **--handler hello.handler \**
 **--runtime python2.7 \**
 **--trigger-http** 
```

部署后，您可以通过运行以下命令查看该函数：

```
$ kubectl get functions
$ kubeless function ls
```

您可以通过运行以下命令调用该函数：

```
$ kubeless function call hello 
```

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/8cd0fe2d-b02c-482f-8089-1428bf316f17.png)

此外，您可以使用以下命令公开该函数：

```
$ kubectl expose deployment hello --type=LoadBalancer --name=hello-lb
```

一旦负载均衡器创建完成，您可以运行以下命令确认 IP 地址和端口：

```
$ kubectl get services hello-lb
```

一旦您知道 IP 地址和端口，您可以在浏览器中打开该函数，或者使用 curl 或 HTTPie 查看该函数：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/b5eb2e7f-f765-436a-9fa6-620c8d8581eb.png)

现在我们已经使用 Sock Shop 应用程序测试了我们的集群，并部署了一个 Kubeless 函数，我们应该考虑终止我们的集群。

# 删除集群

要删除集群，只需运行以下命令：

```
$ gcloud container clusters delete kube-cluster
```

它会问你是否确定，回答是，一两分钟后，您的集群将被删除。再次，您应该在 Google Cloud 网页界面上仔细检查您的集群是否已被正确删除，以免产生任何意外费用。

# 摘要

在本章中，我们看了四个云提供商。前两个，DigitalOcean 和 AWS，目前不支持原生的 Kubernetes，因此我们使用 `kubeadm` 和 `kube-aws` 来启动和配置我们的集群。对于 Microsoft Azure 和 Google Cloud，我们使用他们的命令行工具来启动他们原生支持的 Kubernetes 服务。我相信您会同意，在撰写本文时，这两项服务比我们看过的前两项要友好得多。

一旦集群运行起来，与 Kubernetes 交互是一个相当一致的体验。当我们发出诸如 `kubectl expose` 的命令时，我们实际上并不需要为集群运行的位置做出任何让步：Kubernetes 知道它在哪里运行，并使用提供商的原生服务来启动负载均衡器，而无需我们干预任何特殊设置或考虑。

您可能会想知道为什么我们没有在 DigitalOcean 上启动 Sock Shop 应用程序。由于机器的规格相当低，应用程序运行非常缓慢，并且 DigitalOcean 是我们看过的四个提供商中唯一一个不支持 Kubernetes 当前不支持提供商的原生负载均衡服务。我相信这将在未来几个月内得到纠正。

此外，您可能会感到惊讶，AWS 上没有原生的 Kubernetes 经验。在撰写本文时是这种情况；然而，有传言称自从 AWS 加入了云原生基金会后，他们正在努力开发原生的 Kubernetes 服务。

在下一章中，我们将介绍 Apache OpenWhisk，这是最初由 IBM 开发的开源无服务器云平台。


# 第七章：Apache OpenWhisk 和 Kubernetes

在本章中，我们将看看 Apache OpenWhisk。虽然不严格是一个仅限于 Kubernetes 的项目，比如 Kubeless 和 Fission（这些将在下一章中介绍），但它可以部署并利用 Kubernetes。

我们将看三个主要主题：

+   Apache OpenWhisk 概述

+   使用 Vagrant 在本地运行 Apache OpenWhisk

+   在 Kubernetes 上运行 Apache OpenWhisk

让我们首先了解更多关于 OpenWhisk。

# Apache OpenWhisk 概述

Apache OpenWhisk 是一个开源的无服务器云计算平台，旨在以与本书其他章节中涵盖的所有工具类似的方式工作。Apache OpenWhisk 最初是 IBM 公共云服务 Bluemix 的 Functions as a Service 部分，现在仍然是。

它在 2016 年 12 月发布了普遍可用版本。随着宣布的新闻稿中有一句来自 Santander 集团平台工程和架构负责人 Luis Enriquez 的引用，他是 IBM Cloud Functions 的一位客户，Luis 说：

“微服务和容器正在改变我们构建应用程序的方式，但由于无服务器，我们可以进一步推动这种转变，OpenWhisk 为我们提供了处理强烈任务和工作负载意外高峰的即时基础设施，并且是我们转向实时和事件驱动架构的关键构建块。”

你可能已经注意到，这听起来很像 AWS 和 Microsoft Azure Functions 的 Lambda——IBM 的服务与竞争对手的区别在于 IBM 已经将 OpenWhisk 提交给了 Apache 孵化器，这是所有外部开发项目成为 Apache 软件基金会努力的一部分的入口。

Apache 软件基金会成立于 1999 年，是一个慈善组织，负责监督和管理超过 350 个开源软件项目的开发和管理，这是为了公共利益。

那么为什么 IBM 要这样做呢？嗯，IBM 不仅是 Apache 软件基金会的金牌赞助商，将其 Functions as a Service 提供开源化对他们来说是有意义的，因为它是唯一一个可以避免供应商锁定的公共云提供商，因为你可以在本地或自己的硬件或虚拟机上运行 Apache OpenWhisk。

这使您可以自由地在任何地方运行和部署 Apache OpenWhisk。但是，如果您想像 Santander 集团一样进行规模化运行，那么您可以选择在 IBM 支持的企业级公共云上运行它。

# 在本地运行 Apache OpenWhisk

我们首先将研究在本地运行 Apache OpenWhisk。我们将通过使用 VirtualBox 和 Vagrant 来实现这一点。

# 安装 Vagrant

在启动本地 Apache OpenWhisk 服务器之前，我们需要安装由 HashiCorp 开发的 Vagrant。我能描述 Vagrant 的最好方式是作为一个开源的虚拟机管理器，您可以使用易于遵循的文本配置文件编写机器配置。

安装 Vagrant 非常简单。在 macOS 10.13 High Sierra 上，我们可以使用 Homebrew 和 Cask：

```
$ brew cask install vagrant
```

如果您正在运行 Windows 10 专业版，您可以使用 Chocolatey 并运行以下命令：

```
$ choco install vagrant
```

最后，如果您正在运行 Ubuntu 17.04，您可以通过运行以下命令直接从 Ubuntu 核心存储库安装 Vagrant：

```
$ sudo apt-get update
$ sudo apt-get install vagrant 
```

请注意，Ubuntu 提供的版本可能会比使用 Homebrew 和 Chocolatey 安装的版本稍微滞后；但是对于我们的目的，这不应该造成任何问题。

您可以通过运行以下命令测试 Vagrant 安装：

```
$ mkdir vagrant-test
$ cd vagrant-test
$ vagrant init ubuntu/xenial64
$ vagrant up
```

这些命令将在`vagrant-test`文件夹中创建一个基本的 Vagrantfile，该文件夹使用来自 Vagrant 网站（[`app.vagrantup.com/ubuntu/boxes/xenial64/`](https://app.vagrantup.com/ubuntu/boxes/xenial64/)）的官方 64 位 Ubuntu 16.04 LTS（Xenial）镜像，下载该镜像，使用 VirtualBox 启动虚拟机，配置网络，并在最终将当前文件夹挂载到虚拟机的`/vagrant`：

！[](assets/706d484d-29b9-4a27-821a-34156e2e7a80.png)

所有这些都是使用以下配置定义的：

```
Vagrant.configure("2") do |config|
 config.vm.box = "ubuntu/xenial64"
end
```

如果您打开 Vagrantfile，您会注意到有很多配置选项，比如 RAM 和 CPU 分配，网络和脚本，这些脚本在虚拟机成功启动后执行。您可以运行以下命令以 SSH 连接到 Vagrant 虚拟机：

```
$ vagrant ssh
```

如果您正在运行 Windows 10 专业版，则需要安装 SSH 客户端。当您执行上述命令时，Vagrant 将为您提供一些选项。

运行以下命令将关闭您的虚拟机并将其删除：

```
$ vagrant destroy
```

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/2ec7c6d5-556c-4acb-a9c1-ff59c3b362c6.png)

我还建议通过运行清除您的工作文件夹：

```
$ cd ../
$ rm -rf vagrant-test
```

现在我们已经安装了 Vagrant，并且快速查看了如何启动和与虚拟机交互，我们现在可以使用它来启动我们自己的本地安装 Apache OpenWhisk。

# 下载和配置 Apache OpenWhisk

正如我们已经提到的，Apache OpenWhisk 附带一个 Vagrantfile，其中包含从头开始部署本地 Apache OpenWhisk 安装的所有命令。要下载 Apache OpenWhisk 存储库并部署虚拟机，请运行以下命令：

```
$ git clone --depth=1 https://github.com/apache/incubator-openwhisk.git openwhisk
$ cd openwhisk/tools/vagrant
$ ./hello
```

这个过程将花费最多 30 分钟，具体取决于您的互联网连接速度；您可以在以下 URL 找到 Vagrantfile 的副本：[`github.com/apache/incubator-openwhisk/blob/master/tools/vagrant/Vagrantfile`](https://github.com/apache/incubator-openwhisk/blob/master/tools/vagrant/Vagrantfile)。

正如您所看到的，它只有将近 200 行，这与上一节中我们测试 Vagrantfile 的三行有很大不同。Vagrantfile 使用 bash 脚本和 Ansible 的组合来启动、安装和配置我们的 Apache OpenWhisk 虚拟机。

Ansible 是来自 Red Hat 的编排/配置工具。它允许您轻松地用人类可读的代码定义部署，无论是与 API 交互以启动基础设施，还是登录到服务器并执行任务来安装和配置软件堆栈。

在过程结束时，它将执行一个基本的 hello world 检查，如下控制台输出所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/4ea18a54-5a0d-417d-8a2b-b5a55316388b.png)

在我们继续之前，请注意以`wsk property set`命令开头的输出。我们将需要这个来配置本地客户端，接下来我们将看到如何安装。

# 安装 Apache OpenWhisk 客户端

每个 Apache OpenWhisk 都有一个用于 macOS、Windows 和 Linux 版本的 Apache OpenWhisk 客户端的下载页面。您可以从以下 URL 访问本地安装：[`192.168.33.13/cli/go/download/`](https://192.168.33.13/cli/go/download/) 或 IBM：[`openwhisk.ng.bluemix.net/cli/go/download/`](https://openwhisk.ng.bluemix.net/cli/go/download/)。

由于您的本地安装使用自签名 SSL 证书，当在浏览器中打开时，您可能会收到警告。您需要接受这些警告才能继续访问该网站。此过程因浏览器而异，因此您需要按照屏幕上的提示进行操作。

要在 macOS 10.13 High Sierra 上安装客户端，我们只需要运行以下命令：

```
$ curl -L --insecure https://192.168.33.13/cli/go/download/mac/amd64/wsk > /usr/local/bin/wsk
$ chmod +x /usr/local/bin/wsk
$ wsk help
```

这将使用`curl`下载二进制文件并忽略自签名证书。

要在 Windows 10 专业版上下载，请运行以下命令。我建议从 IBM 下载，以避免自签名 SSL 证书和 PowerShell 的问题。为此，首先以管理员用户身份打开 PowerShell 窗口。您可以通过从任务栏中的 PowerShell 菜单中选择以管理员身份运行来执行此操作。打开后，您应该看到您在`C:\WINDOWS\system32`文件夹中；如果不是，则运行以下命令：

```
$ cd C:\WINDOWS\system32
$ Invoke-WebRequest -Uri https://openwhisk.ng.bluemix.net/cli/go/download/windows/amd64/wsk.exe -UseBasicParsing -OutFile wsk.exe
```

与 macOS 版本一样，您可以通过运行以下命令来检查客户端是否已安装：

```
$ wsk help
```

最后，在 Ubuntu 17.04 上，您需要运行以下命令：

```
$ sudo sh -c "curl -L --insecure https://192.168.33.13/cli/go/download/linux/amd64/wsk > /usr/local/bin/wsk"
$ sudo chmod +x /usr/local/bin/wsk
```

一旦下载并设置为可执行，您应该能够运行：

```
$ wsk help
```

现在我们已经安装了客户端，我们需要对我们的安装进行身份验证。为此，请运行您在上一节末尾做的笔记中的命令，减去`--namespace guest`部分。对我来说，这个命令是这样的：

```
$ wsk property set --apihost 192.168.33.13 --auth 23bc46b1-71f6-4ed5-8c54-816aa4f8c502:123zO3xZCLrMN6v2BKK1dXYFpXlPkccOFqm12CdAsMgRU4VrNZ9lyGVCGuMDGIwP
```

如果您没有做笔记，那么您可以通过从启动 Vagrant 虚拟机的文件夹运行以下命令来动态传递授权令牌，如下所示：

```
$ wsk property set --apihost 192.168.33.13 --auth `vagrant ssh -- cat openwhisk/ansible/files/auth.guest`
```

如果您不是从启动机器的文件夹运行`vagrant ssh`命令，该命令将失败，因为它将无法找到您的机器配置。现在，您的本地客户端已对本地安装的 Apache OpenWhisk 进行了身份验证，我们可以通过运行以下命令执行与自动安装相同的 hello world 命令：

```
$ wsk -i action invoke /whisk.system/utils/echo -p message hello --result
```

这应该返回以下终端输出的消息`hello`：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/0a257e48-106c-4f26-9d5f-5e4a2dc1d523.png)

现在我们有了本地客户端，我们可以尝试下载和执行另一个示例。

# 你好世界

现在，我们可以部署一个更复杂的解决方案，而不仅仅是使用内置的`echo`实用程序返回消息。与我们之前使用的 hello world 脚本类似，我们将部署一个使用 Node.js 编写的函数，该函数接受输入并将其显示回给我们。

首先，让我们创建一个工作目录：

```
$ mkdir openwhisk-http
$ cd openwhisk-http
```

现在我们有了一个工作目录，创建一个包含以下代码的文件，并将其命名为`hello.js`：

```
function main(args) {
    var msg = "you didn't tell me who you are."
    if (args.name) {
        msg = `hello ${args.name}!`
    }
    return {body:
       `<html><body><h3><center>${msg}</center></h3></body></html>`}
}
```

现在我们有了要部署的函数，首先我们需要创建一个包，然后创建一个暴露给 Web 的操作：

```
$ wsk -i package create /guest/demo
$ wsk -i action create /guest/demo/hello hello.js --web true
```

现在我们已经创建了包和操作，您的终端应该看起来像以下内容：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/a8650b61-bd51-42d4-b5b3-d28e9c717fbd.png)

这意味着您可以使用浏览器在以下 URL 调用您的函数：

[`192.168.33.13/api/v1/web/guest/demo/hello.http?name=Kubernetes%20for%20Serverless%20Applications`](https://192.168.33.13/api/v1/web/guest/demo/hello.http?name=Kubernetes%20for%20Serverless%20Applications)

您应该会看到以下页面：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/ef84888e-ce81-46cd-8bf5-cb91efbfe399.png)

您可以通过在 macOS 或 Ubuntu 上使用 HTTPie 来查看更多信息，方法是运行以下命令：

```
$ http --verify=no https://192.168.33.13/api/v1/web/guest/demo/hello.http?name=Kubernetes%20for%20Serverless%20Applications
```

这将返回标头和输出：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/950b8f7d-cf0d-44fd-8d66-e9151b0d01dc.png)

您可以通过运行以下命令列出软件包和操作，并删除它们：

```
$ wsk -i list
$ wsk -i action delete /guest/demo/hello
$ wsk -i package delete /guest/demo
```

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/186756db-fc2d-4231-a590-d8e4b7de57a5.png)

随意在本地安装 Apache OpenWhisk 上玩耍；您可以在 Awesome OpenWhisk 页面找到更多示例，网址为：[`github.com/apache/incubator-openwhisk-external-resources/`](https://github.com/apache/incubator-openwhisk-external-resources/)。

完成本地安装后，您可以运行以下命令来停止和销毁虚拟机：

```
$ vagrant destroy
```

请记住，您必须在`openwhisk/tools/vagrant/`文件夹中运行此命令，否则 Vagrant 将无法找到您的虚拟机配置。

现在我们已经在本地安装并与 Apache OpenWhisk 进行了交互，让我们看看如何在公共云中的 Kubernetes 上部署它。

# 在 Kubernetes 上运行 Apache OpenWhisk

现在我们知道如何与 Apache OpenWhisk 进行交互以及其基本概念，我们可以考虑在 Kubernetes 集群之上部署一个副本。为此，我将通过运行以下命令在 Google Cloud 中启动一个三节点集群：

```
$ gcloud container clusters create kube-cluster
```

一旦集群运行起来，您可以通过运行以下命令来检查是否可以看到三个节点：

```
$ kubectl get nodes
```

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/75a05a0d-c6bb-492a-a686-963bb127ca3d.png)

现在我们有了我们的 Kubernetes，我们可以继续进行 Apache OpenWhisk 的部署。

# 部署 OpenWhisk

在开始部署之前，所有在 Kubernetes 上部署 Apache OpenWhisk 所需的配置都可以在 GitHub 上找到，因此我们应该通过运行以下命令克隆存储库。

```
$ git clone --depth=1 https://github.com/apache/incubator-openwhisk-deploy-kube.git openwhisk-kube
$ cd openwhisk-kube
```

现在我们有了存储库的副本，我们可以开始部署运行 Apache OpenWhisk 所需的各个组件。首先，我们需要创建一个名为`openwhisk`的命名空间。要做到这一点，请运行以下命令：

```
$ kubectl create namespace openwhisk
```

现在我们可以通过启动 CouchDB 来开始我们的部署。

# CouchDB

要部署 CouchDB，请从`openwhisk-kube`文件夹内运行以下命令：

```
$ kubectl apply -f kubernetes/couchdb/couchdb.yml
```

这将启动一个使用`couchdb.yml`文件中定义的参数运行 CouchDB 的 pod。您可以通过获取 pod 的名称来检查部署是否正常。您可以通过运行以下命令来执行此操作：

```
$ kubectl -n openwhisk get pods
```

一旦您获得了名称，对我来说是`couchdb-1146267775-v0sdm`，然后您可以运行以下命令，确保更新 pod 的名称为您自己的：

```
$ kubectl -n openwhisk logs couchdb-1146267775-v0sdm
```

在日志输出的最后，您应该看到以下消息：

！[](assets/ed49833e-2e94-4ae7-929c-872715c616ee.png)

现在我们的 CouchDB pod 正在运行，我们可以继续下一个，即 Redis。

# Redis

要启动 Redis pod，我们只需要运行以下命令：

```
$ kubectl apply -f kubernetes/redis/redis.yml
```

# API 网关

接下来我们有 API 网关；通过运行以下命令来启动它：

```
$ kubectl apply -f kubernetes/apigateway/apigateway.yml
```

# ZooKeeper

现在我们可以使用以下命令启动 Apache ZooKeeper：

```
$ kubectl apply -f kubernetes/zookeeper/zookeeper.yml
```

# 卡夫卡

现在是时候启动另一个 Apache 项目，Kafka 了：

```
$ kubectl apply -f kubernetes/kafka/kafka.yml
```

此时，我们应该仔细检查我们启动的所有 pod 是否正在运行。要做到这一点，请运行以下命令：

```
$ kubectl -n openwhisk get pods
```

您应该看到`couchdb`，`redis`，`apigateway`，`zookeeper`和`kafka`的 pod，所有这些 pod 都在没有记录重启并且`READY`列中为`1/1`运行：

！[](assets/7fabbba6-2215-4fe1-b633-5967d8fdcc12.png)

# 控制器

接下来是控制器。这与我们部署的其他 pod 略有不同，因为它是以有状态的方式部署的：

```
$ kubectl apply -f kubernetes/controller/controller.yml
```

您应该看到已创建了一个 StatefulSet 而不是一个部署。

# 调用者

再次部署的下一个 pod 将是一个 StatefulSet 而不是一个部署。在部署 pod 之前，我们需要对`kubernetes/invoker/invoker.yml`文件进行轻微更改。这是因为，默认情况下，OpenWhisk 假定您正在运行 Ubuntu 作为基本操作系统，而 Google Cloud 不是。

要做到这一点，请在您选择的文本编辑器中打开`kubernetes/invoker/invoker.yml`并删除以下代码块：

```
      - name: apparmor
        hostPath:
          path: "/usr/lib/x86_64-linux-gnu/libapparmor.so.1"
```

还有另一个关于`apparmor`的参考资料需要删除。这次是在文件底部：

```
        - name: apparmor
          mountPath: "/usr/lib/x86_64-linux-gnu/libapparmor.so.1"
```

一旦删除了引用`apparmor`的两个代码块，您可以通过运行以下命令部署`invoker`：

```
$ kubectl apply -f kubernetes/invoker/invoker.yml
```

部署可能需要几分钟时间。

# NGINX

部署的最后一部分是 NGINX 容器。对于这个容器，我们需要做更多的工作，因为我们需要为我们的集群生成证书。为了生成证书，我们需要使用 OpenSSL。这在 Windows 机器上默认情况下不安装，因此您可以使用以下命令使用 Chocolatey 安装 OpenSSL：

```
$ choco install openssl.light
```

一旦安装了 OpenSSL，您可以通过运行以下命令生成证书：

```
$ mkdir -p certs
$ openssl req -x509 -newkey rsa:2048 -keyout certs/key.pem -out certs/cert.pem -nodes -subj "/CN=localhost" -days 365
```

一旦我们有了证书，我们需要使用`kubernetes/nginx`中的`nginx.conf`文件创建一个`configmap`。为此，请运行以下命令：

```
$ kubectl -n openwhisk create configmap nginx --from-file=kubernetes/nginx/nginx.conf
```

现在我们需要上传生成的证书和密钥作为`secret`：

```
$ kubectl -n openwhisk create secret tls nginx --cert=certs/cert.pem --key=certs/key.pem
```

一旦它们被上传，我们可以通过运行以下命令启动 NGINX pod：

```
$ kubectl apply -f kubernetes/nginx/nginx.yml
```

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/96c0b0fe-1916-4676-b3e6-50bd5caa9f7f.png)

现在我们已经部署了所有的 pod，您应该使用以下命令再次检查它们是否都在运行：

```
$ kubectl -n openwhisk get pods
```

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/b3e76e58-0976-400e-8282-d164eb3adf24.png)

正如您所看到的，一切都在运行。只要数量不增加，您可以忽略任何重启。

# 配置 OpenWhisk

现在我们已经部署了所有的 pod，我们可以开始与我们的部署进行交互。首先，我们需要找出 NGINX pod 的外部 IP 地址。您可以通过运行以下命令找到有关 pod 的信息：

```
$ kubectl -n openwhisk describe service nginx
```

这是输出：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/37646d9e-670d-443a-b63a-2b6fa13e9bb9.png)

正如您所看到的，虽然端口是暴露的，但它们只在节点本身上暴露。由于节点位于私有地址上，我们将无法从本地客户端访问它们。要在外部暴露端口，我们需要创建一个负载均衡服务，运行以下命令来执行此操作：

```
$ kubectl -n openwhisk expose service nginx --type=LoadBalancer --name=front-end
```

这将启动一个负载均衡器并暴露三个端口：`80`、`443`和`8443`。您可以通过运行以下命令找到外部 IP 地址的详细信息：

```
$ kubectl -n openwhisk describe service front-end
```

在输出中，您会找到一行，上面写着 Load Balancer Ingress，后面跟着一个 IP 地址：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/99c8f054-4ab7-4f0e-8799-31cf597501dc.png)

正如您从先前显示的示例输出中看到的，我有一个 IP 地址`35.188.204.73`。这将被用作我与之交互的 API 端点。

现在我们已经获得了安装的 IP 地址，我们可以继续通过运行以下命令来配置认证令牌，确保您使用自己安装的 IP 地址进行更新：

```
$ wsk -i property set --auth 23bc46b1-71f6-4ed5-8c54-816aa4f8c502:123zO3xZCLrMN6v2BKK1dXYFpXlPkccOFqm12CdAsMgRU4VrNZ9lyGVCGuMDGIwP --apihost https://35.188.204.73:443
```

配置完成后，我们可以运行我们的 hello-world 测试。

# 你好，世界

这与前一节中的 hello world 完全相同，所以我不会详细介绍。只需切换到您拥有`hello.js`文件的文件夹，并运行以下命令：

```
$ wsk -i package create /guest/demo
$ wsk -i action create /guest/demo/hello hello.js --web true
```

一旦您运行了创建包和操作的命令，您将能够访问 URL。对我来说，它是以下内容：

`https://35.188.204.73/api/v1/web/guest/demo/hello.http?name=Kubernetes%20for%20Serverless%20Applications`

这显示了我们期望看到的页面：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/de235e08-b560-4d22-b3b5-c7b02f0709ad.png)

再次，我们可以通过运行 HTTPie 来看到更多：

```
$ http --verify=no https://35.188.204.73/api/v1/web/guest/demo/hello.http?name=Kubernetes%20for%20Serverless%20Applications
```

这显示了以下信息：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/ae2ac2d9-2bdc-4a7e-ae6e-4638c1193f3a.png)

正如您所看到的，一旦您使用提供的文件部署了 Apache OpenWhisk，使用它是一个非常一致的体验。

在完成本章之前，我们应该删除我们的 Kubernetes 集群。要做到这一点，请运行以下命令：

```
$ gcloud container clusters delete kube-cluster
```

删除后，请务必检查您的 Google Cloud 控制面板[`console.cloud.google.com/`](https://console.cloud.google.com/)，以确保没有剩余的资源，这可能会产生意外的成本。

# 摘要

在本章中，我们稍微偏离了目标，看了一下 Apache OpenWhisk。我们使用标准虚拟机部署了一个本地副本，然后我们转向部署到在 Google Cloud 上运行的 Kubernetes 集群。

正如您所看到的，一旦部署完成，与 Apache OpenWhisk 的交互是一致的体验，我们能够在两个安装中部署我们简单的 hello-world 应用程序，而无需进行任何修改。

虽然 Kubernetes 对 Apache OpenWhisk 的支持仍处于起步阶段，但我们的偏离表明，不仅是为 Kubernetes 设计的框架，就像我们在前几章中看到的工具一样，它们将在 Kubernetes 之上运行，并提供一致的体验，而无需将您锁定在单一供应商或技术中。

在下一章中，我们将看到可能是最成熟的 Kubernetes 函数作为服务提供：Fission。


# 第八章：使用 Fission 启动应用程序

接下来我们将看一下 Fission。Fission 是一个快速增长的，基于 Kubernetes 的无服务器框架，而且在我们之前章节中看到的技术中，可能是最多才多艺的。在本章中，我们将涵盖：

+   谁构建了 Fission？

+   安装先决条件

+   在本地安装、配置和运行 Fission

+   命令概述

+   在云中安装、配置和运行 Fission

+   部署一些示例 Fission 应用程序

到本章结束时，我们将在两个不同的目标环境中安装 Fission，并且还将启动多个应用程序。

# Fission 概述

Fission 是由 Platform9 开发的开源无服务器应用程序。它旨在在 Kubernetes 之上运行，并利用一些核心的 Kubernetes 功能。Platform9 是一家托管服务提供商，其核心业务是部署、管理和支持专门从事 OpenStack 和 Kubernetes 的开源云。

OpenStack 是一组开源组件，构成了一个完全功能的基础设施即服务产品。它提供计算、网络、块存储、对象存储、编排，甚至容器服务等功能。

该项目的目标是为多个不同的硬件供应商提供支持，从普通的 x86 硬件到专门的存储解决方案，使最终用户能够构建自己的 AWS 和 Microsoft Azure 风格的产品。

随着 AWS Lambda 和 Azure Functions 等服务成熟到现在几乎在大多数企业中都很普遍，Platform9 看到了提供自己的函数即服务的机会。

作为一家专门从事复杂开源解决方案的公司，他们为他们向社区贡献自己的工作是有意义的，因此他们以 Apache 许可证发布了 Fission。

Apache 软件基金会的 Apache 2.0 许可证允许开发人员免费发布他们的软件，允许最终用户以任何目的使用该软件，并在不必担心版税的情况下修改/重新分发它。为了确保许可证不被违反，最终用户必须保留原始的版权声明和免责声明。

这可能看起来像一个奇怪的决定。然而，就像我们在上一章中介绍的 OpenWhisk 一样，Platform9 为他们的客户以及任何想要开始部署**函数即服务**（**FaaS**）的人提供了一个坚实的基础来构建他们的应用程序。他们不仅给了人们在任何地方部署他们的工作负载的自由，还能够为安装和 Fission 平台提供支持服务。

# 安装先决条件

在我们本地或公共云中安装 Fission 之前，我们需要一些支持工具。第一个工具我们已经安装了，那就是 Kubernetes 命令行接口`kubectl`。我们还没有安装运行 Fission 所需的第二个工具：Helm ([`helm.sh/`](http://helm.sh))。

# 安装 Helm

Helm 是 Kubernetes 的一个包管理器，是 Cloud Native Computing Foundation 的一部分，Bitnami、Google、Microsoft 和 Helm 社区都为其开发做出了贡献。

要在 macOS High Sierra 上安装 Helm，我们可以使用 Homebrew；只需运行：

```
$ brew install kubernetes-helm
```

如果您正在运行 Ubuntu Linux，则可以使用安装脚本下载并安装 Helm：

```
$ curl https://raw.githubusercontent.com/kubernetes/helm/master/scripts/get | bash
```

最后，Windows 10 专业版用户可以从 canary 存储库下载 Helm 的实验版本。该版本的直接下载链接为[`kubernetes-helm.storage.googleapis.com/helm-canary-windows-amd64.zip`](https://kubernetes-helm.storage.googleapis.com/helm-canary-windows-amd64.zip)。由于这是一个实验版本，我建议直接运行它，而不要将其放在系统文件夹中。

安装 Helm 的下一步需要您拥有一个运行中的 Kubernetes 集群，因为这是它的启动位置。我将在本章后面包括安装 Helm 的服务器组件 Tiller 的说明。

# 安装 Fission CLI

我们需要安装的最后一个命令行工具是 Fission 本身的工具。您可以通过在 macOS High Sierra 上运行以下命令来安装它：

```
$ curl -Lo fission https://github.com/fission/fission/releases/download/0.3.0/fission-cli-osx && chmod +x fission && sudo mv fission /usr/local/bin/
```

对于 Ubuntu 17.04，您可以运行：

```
$ curl -Lo fission https://github.com/fission/fission/releases/download/0.3.0/fission-cli-linux && chmod +x fission && sudo mv fission /usr/local/bin/
```

最后，Windows 可执行文件可以从[`github.com/fission/fission/releases/download/0.3.0/fission-cli-windows.exe`](https://github.com/fission/fission/releases/download/0.3.0/fission-cli-windows.exe)下载。我建议与 Helm 的可执行文件一起使用，而不是将其安装在`System32`文件夹中。

运行以下命令应该显示当前安装的版本：

```
$ helm version
$ fission --version
```

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/b4a654f6-8c00-4220-b565-f18d42b40e98.png)

如前所述，我们还没有安装 Tiller，因此我们可以安全地忽略关于无法连接到它的错误。

# 在本地运行 Fission

现在我们已经安装了先决条件，我们可以开始创建我们的第一个函数。为此，我们将使用 Minikube。要启动单节点集群，我们只需要运行以下命令：

```
$ minikube start
$ kubectl get nodes
```

这应该启动您的 Minikube 集群，并确认您的本地版本已重新配置以与其通信：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/14b2aeba-7121-49c2-a883-32651ffb3353.png)

一旦我们的集群运行并且可访问，我们需要通过安装 Tiller 来完成 Helm 安装。要做到这一点，我们需要运行以下命令：

```
$ helm init
```

您应该会看到类似以下消息：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/6407f211-02d3-41ab-8863-ba045b51a6e6.png)

# 使用 Helm 启动 Fission

Helm 现在已配置好，我们可以使用它来部署 Fission 的远程组件。可以通过运行以下命令来完成：

```
$ helm install --namespace fission --set serviceType=NodePort https://github.com/fission/fission/releases/download/0.4.0/fission-all-0.4.0.tgz
```

一两分钟后，您应该会收到 Fission 已启动的确认信息。

# 通过输出进行工作

Helm 的输出非常详细。它将为您提供它创建的所有内容的概述，以及开发人员包含的任何附加说明。

输出的这部分包含了部署的基本细节：

```
NAME: lopsided-fox
LAST DEPLOYED: Sat Dec 9 10:52:19 2017
NAMESPACE: fission
STATUS: DEPLOYED
```

接下来，我们会得到有关在 Kubernetes 中部署了什么的信息，从服务账户开始。这些提供运行 pod 的身份服务。这些允许 Fission 的各个组件与 Kubernetes 进行接口交互：

```
==> v1/ServiceAccount
NAME            SECRETS AGE
fission-builder 1       1m
fission-fetcher 1       1m
fission-svc     1       1m
```

然后是绑定。这些为集群提供基于角色的身份验证（RBAC）：

```
==> v1beta1/ClusterRoleBinding
NAME                 AGE
fission-builder-crd  1m
fission-crd          1m
fission-fetcher-crd  1m
```

接下来是服务本身：

```
==> v1/Service
NAME           TYPE        CLUSTER-IP  EXTERNAL-IP PORT(S)        AGE
poolmgr        ClusterIP   10.0.0.134  <none>      80/TCP         1m
buildermgr     ClusterIP   10.0.0.212  <none>      80/TCP         1m
influxdb       ClusterIP   10.0.0.24   <none>      8086/TCP       1m
nats-streaming NodePort    10.0.0.161  <none>      4222:31316/TCP 1m
storagesvc     ClusterIP   10.0.0.157  <none>      80/TCP         1m
controller     NodePort    10.0.0.55   <none>      80:31313/TCP   1m
router         NodePort    10.0.0.106  <none>      80:31314/TCP   1m
```

现在我们有了部署详情。您可能会注意到，如下所示，一些 pod 仍在启动，这就是为什么它们显示为零可用的原因：

```
==> v1beta1/Deployment
NAME.           DESIRED CURRENT UP-TO-DATE AVAILABLE AGE
timer           1       1       1          1         1m
poolmgr         1       1       1          1         1m
influxdb        1       1       1          1         1m
nats-streaming  1       1       1          1         1m
controller      1       1       1          1         1m
mqtrigger       1       1       1          1         1m
router          1       1       1          0         1m
storagesvc      1       1       1          0         1m
kubewatcher     1       1       1          1         1m
buildermgr      1       1       1          0         1m
```

接下来，我们有了部署和服务的 pod：

```
==> v1/Pod(related)
NAME                            READY STATUS            RESTARTS AGE
logger-zp65r                    1/1   Running           0        1m
timer-57f75c486f-9ktbk          1/1   Running           2        1m
poolmgr-69fcff7d7-hbq46         1/1   Running           1        1m
influxdb-c5c6cfd86-wkwrs        1/1   Running           0        1m
nats-streaming-85b9898784-h6j2v 1/1   Running           0        1m
controller-5f964bc987-mmfrx     1/1   Running           0        1m
mqtrigger-c85dd79f7-vj5p7       1/1   Running           0        1m
router-7cfff6794b-gn5pw         0/1   ContainerCreating 0        1m
storagesvc-58d5c8f6-bnqc7       0/1   ContainerCreating 0        1m
kubewatcher-6d784b9987-5wwhv    1/1   Running           0        1m
buildermgr-7ff69c8bb-pvtbx      0/1   ContainerCreating 0        1m
```

然后我们有了命名空间：

```
==> v1/Namespace
NAME.            STATUS AGE 
fission-builder  Active 1m
fission-function Active 1m
```

现在我们有了秘密。这些只是用于正在使用的数据库：

```
==> v1/Secret
NAME     TYPE   DATA AGE 
influxdb Opaque 2    1m
```

我们接近尾声了：持久存储索赔。您可以看到，由于我们在本地启动，它只是使用 VM 上的一个文件夹，而不是创建外部存储：

```
==> v1/PersistentVolumeClaim
NAME.               STATUS VOLUME                                   CAPACITY ACCESS MODES STORAGECLASS AGE
fission-storage-pvc Bound  pvc-082cf8d5-dccf-11e7-bfe6-080027e101f5 8Gi      RWO            standard     1m
```

现在我们有了角色绑定：

```
==> v1beta1/RoleBinding
NAME                   AGE
fission-function-admin 1m
fission-admin          1m
```

最后，我们有了守护进程集：

```
==> v1beta1/DaemonSet
NAME   DESIRED CURRENT READY UP-TO-DATE AVAILABLE NODE SELECTOR AGE
logger 1       1       1     1          1         <none>        1m
```

现在我们已经看到了我们的 Fission 安装的所有 Kubernetes 元素的概述，我们得到了如何与安装进行交互的说明。

# 启动我们的第一个函数

笔记分为三个部分；第一部分提供了如何安装 Fission 命令行客户端的说明。由于我们已经在本章的前一部分中涵盖了这一点，我们可以忽略这一步。

接下来，在第二部分中，我们得到了关于需要设置的环境变量的说明，以便我们的本地 Fission 客户端可以与我们的 Fission 安装进行交互。要设置这些变量，请运行以下命令：

```
$ export FISSION_URL=http://$(minikube ip):31313
$ export FISSION_ROUTER=$(minikube ip):31314 
```

`export`命令仅适用于 macOS High Sierra 和 Ubuntu 17.04。Windows 10 专业版用户将不得不运行以下命令：

```
$ for /f "delims=" %%a in ('minikube ip') do @set minikube_ip=%%a
$ set FISSION_URL=http://%minikube_ip%:31313
$ set FISSION_ROUTER=%minikube_ip%:31314
```

从这些命令中可以看出，我们的 Fission 安装知道它正在运行在 Minikube 安装上，并为我们提供了动态生成 Minikube 安装的 IP 地址的命令。

第三部分包含了一步一步的说明，说明如何运行一个 hello world 函数；让我们现在来运行这些步骤。

首先，我们需要创建一个环境。为此，我们使用以下命令：

```
$ fission env create --name nodejs --image fission/node-env
```

这个命令创建了一个名为`nodejs`的环境，然后指示 Fission 使用来自 Docker Hub 的 Docker 镜像`fission/node-env`——您可以在[`hub.docker.com/r/fission/node-env/`](https://hub.docker.com/r/fission/node-env/)找到这个镜像。

现在我们已经创建了环境，我们需要一个要部署的函数。运行以下命令（仅适用于 macOS 和 Linux）来下载 hello world 示例：

```
$ curl https://raw.githubusercontent.com/fission/fission/master/examples/nodejs/hello.js > /tmp/hello.js
```

这将下载以下代码：

```
module.exports = async function(context) {
    return {
        status: 200,
        body: "Hello, world!\n"
    };
}
```

如您所见，这与我们在早期章节中运行的示例并没有太大不同。现在我们已经下载了一个函数，我们可以使用以下命令部署它：

```
$ fission function create --name hello --env nodejs --code /tmp/hello.js
```

我们快要完成了；最后一步是创建一个到我们函数的路由。要做到这一点，使用以下命令：

```
$ fission route create --method GET --url /hello --function hello
```

现在我们应该能够通过发出 HTTP 请求来调用我们的函数。您可以使用以下命令中的任一个来触发我们的函数：

```
$ curl http://$FISSION_ROUTER/hello
$ http http://$FISSION_ROUTER/hello 
```

对于 Windows 10 专业版，请使用以下命令在 IE 中打开示例：

```
$ explorer http://%FISSION_ROUTER%/hello 
```

HTTPie 将为您提供标头，以及以下输出：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/79722f78-5815-45eb-801c-40cd7b7abb1e.png)

# 一个留言板

现在我们已经有了一个基本的应用程序在运行，让我们来创建一些更复杂的东西。Fission 附带了一个演示应用程序，充当留言板。您可以在伴随本书的 GitHub 存储库中的`/Chapter08/guestbook/`文件夹中找到我们将要部署的文件。

启动应用程序的第一步是启动 Redis 部署；这将用于存储写入留言板的评论。要创建部署，请在`/Chapter08/guestbook/`文件夹中运行以下命令：

```
$ kubectl create -f redis.yaml
```

您可以从以下截图中看到，这创建了一个`namespace`、`deployment`和`service`。

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/c999a786-2b0b-42b6-a941-a1bfaf9f659e.png)

现在我们需要创建一个环境来启动我们的函数。由于应用程序是用 Python 编写的，让我们运行以下命令：

```
$ fission env create --name python --image fission/python-env
```

前面命令的输出显示在以下截图中：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/37069961-48b9-4fef-8ac8-6be14d231f3c.png)

现在我们已经创建了两个函数，一个用于显示评论，一个用于写评论。要添加这些，请运行以下命令：

```
$ fission function create --name guestbook-get --env python --code get.py --url /guestbook --method GET
$ fission function create --name guestbook-add --env python --code add.py --url /guestbook --method POST
```

前面命令的输出可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/79183e9b-e337-4a2e-ab96-8967a67d41b9.png)

您会注意到，用于添加函数的命令与我们在上一节中用于启动 hello world 示例的命令有些不同。在之前的示例中，我们既添加了函数，又创建了路由。您可能还注意到，虽然我们创建了两个函数，但它们都绑定到了相同的路由`/guestbook`。现在不讨论这个问题，让我们启动应用程序并与之交互。

要打开留言板，请运行以下命令：

```
$ open http://$FISSION_ROUTER/guestbook 
```

对于 Windows 10 专业版，请使用：

```
$ explorer http://%FISSION_ROUTER%/guestbook
```

这将在浏览器中打开一个空的留言板页面，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/b699b897-d8f4-4ef6-b4ce-88019c11b36b.png)

现在让我们通过输入一些文本（比如`Testing Fission`）来添加评论，然后单击添加。刷新后，您应该看到您的评论已添加：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/9d18d10b-b9a8-4b97-858f-1d4dc284f2fd.png)

如果收到内部服务器错误，请不要担心，只需刷新页面并重新提交。查看页面的 HTML 源代码，您可能会注意到表单操作配置为将`POST`提交到`/guestbook`：

```
<form action="/guestbook" method="POST">
  <input type="text" name="text">
  <button type="submit">Add</button>
</form>
```

如果您查看我们用于创建两个函数的命令，您会注意到两者都附有一个方法。`guestbook-add`，运行`add.py`，使用了`POST`方法，如下面的代码所示：

```
#
# Handles POST /guestbook -- adds item to guestbook 
#

from flask import request, redirect
import redis

# Connect to redis.
redisConnection = redis.StrictRedis(host='redis.guestbook', port=6379, db=0)

def main():
    # Read the item from POST params, add it to redis, and redirect
    # back to the list
    item = request.form['text']
    redisConnection.rpush('guestbook', item)
    return redirect('/guestbook', code=303)
```

该函数读取表单提交的数据，将评论推送到 Redis 数据库，然后将我们带回`/guestbook`。`303`代码是在`POST`后重定向使用的状态代码。

每当您的浏览器请求页面时，它都会发送一个`GET`请求。在我们的情况下，所有对`/guestbook`的`GET`请求都被路由到`guestbook-get`函数，这是`get.py`代码：

```
#
# Handles GET /guestbook -- returns a list of items in the guestbook
# with a form to add more.
#

from flask import current_app, escape
import redis

# Connect to redis. This is run only when this file is loaded; as
# long as the pod is alive, the connection is reused.
redisConnection = redis.StrictRedis(host='redis.guestbook', port=6379, db=0)

def main():
    messages = redisConnection.lrange('guestbook', 0, -1)

    items = [("<li>%s</li>" % escape(m.decode('utf-8'))) for m in messages]
    ul = "<ul>%s</ul>" % "\n".join(items)
    return """
      <html><body style="font-family:sans-serif;font-size:2rem;padding:40px">
          <h1>Guestbook</h1> 
          <form action="/guestbook" method="POST">
            <input type="text" name="text">
            <button type="submit">Add</button>
          </form>
          <hr/>
          %s
      </body></html>
      """ % ul
```

从上面的代码中可以看出，这会连接到 Redis 数据库，读取每个条目，将结果格式化为无序的 HTML 列表，然后将列表插入到水平线下方（`<hr/>`）。

# Fission 命令

在我们将 Fission 安装移到公共云之前，我们应该更多地了解一下命令客户端。有几个顶级命令可用于管理我们的函数和路由。

# fission function 命令

这基本上是您在使用 Fission 时将花费大部分时间的地方。函数命令是您创建、管理和删除函数的方式。您可以使用`fission function <command>`或`fission fn <command>`。

# create 命令

我们已经使用过这个命令，所以不需要详细介绍。`fission function create` 命令有几个选项；最常见的是：

+   `--name`：这表示我们想要给我们的函数取什么名字。

+   `--env`：这表示我们想要在哪个环境中部署我们的函数。更多关于环境的内容请参见下一节。

+   `--code`：我们希望部署的代码的路径或 URL。

+   `--url`：我们希望我们的函数在哪个 URL 上可用。

+   `--method`：我们在前面 URL 上访问我们的函数的方式；这里的选项有`GET`、`POST`、`PUT`、`DELETE`、`HEAD`—如果您不使用`--method`但使用`--url`，它将始终默认为`GET`。

正如我们在留言板示例中已经看到的，`fission function create` 命令看起来会像下面这样：

```
$ fission function create \
 --name guestbook-get \
 --env python \
 --code get.py \
 --url /guestbook \
 --method GET
```

# 获取选项

这个选项相当简单；运行`fission function get`将显示您选择的函数的源代码。它接受一个输入：`--name`。这是您希望显示源代码的函数的名称。

运行以下命令将显示 hello world 函数的源代码：

```
$ fission function get --name hello 
```

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/136c1f31-a283-4f3b-a893-9e95fedadf5d.png)

# 列出和获取元数据命令

以下两个命令有点类似：

```
$ fission function list
```

这个命令将列出当前安装的函数。列表中包括函数的名称、唯一 ID 以及函数部署的环境：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/de079f74-35db-4cea-a0c8-ce19c6b2f9dd.png)

如果我们已经知道函数的名称，并且想要提醒自己它正在运行的环境，或者需要它的 UID，那么我们可以使用 `fission function getmeta` 命令，并传递函数的名称：

```
$ fission function getmeta --name hello
```

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/30ec7ff7-1556-445e-ad25-d077acc4ffde.png)

# 日志命令

虽然目前没有任何视图，但您可以使用 `fission function logs` 命令查看函数的日志。您可以传递一些不同的选项：

+   `--name`：这是您希望查看日志的函数的名称，这总是必需的

+   `--follow`：保持流打开，日志实时显示

+   `--detail`：添加更多详细输出

使用上述选项，命令将看起来像下面这样：

```
$ fission function logs --detail --follow --name hello
```

然而，正如前面提到的，目前没有太多可看的。

# 更新命令

`fission function update` 命令部署函数的更新版本。它使用与 `fission function create` 命令相同的选项。例如，如果我们想要更新我们的 hello world 函数以使用不同的源，我们将运行以下命令：

```
$ fission function update \
 --name hello \
 --env nodejs \
 --code hello-update.js \
```

# 删除命令

我们要看的最后一个命令是 `fission function delete`。这个命令相当不言自明。它删除函数，只接受一个参数，那就是 `--name`。

在使用 `fission function delete` 时请小心；它不会以任何方式提示您，当您按下 *Enter* 时，您的函数将被删除。

要删除 hello world 函数，例如，我们只需运行以下命令：

```
$ fission function delete --name hello
```

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/fa8b8ea6-3c38-4779-b118-282ede814f46.png)如您所见，并且正如前面提到的，没有 *您确定吗？* 的提示，因此在使用命令时请小心。

# fission environment 命令

下一个顶级命令是 environment。正如我们已经看到的，环境是我们的函数运行的地方，它们还定义了我们的函数在哪种语言中执行。在撰写本文时，Fission 支持 Node.js、Go、Python、PHP、Ruby、Perl 和 .NET C#。

# 创建命令

`fission environment create` 命令是我们已经使用过的一个命令。例如，当我们创建 guestbook 应用程序时，我们需要一个 Python 环境来运行我们的应用程序，所以我们运行了以下命令：

```
$ fission environment create \
 --name python \
 --image fission/python-env
```

图像的完整列表、要使用的 URL 和用于创建图像的 Dockerfile 如下：

| **语言** | **图像名称** | **源 URL** |
| --- | --- | --- |
| Python 2.7 | `fission/python-env` | [`github.com/fission/fission/tree/master/environments/python`](https://github.com/fission/fission/tree/master/environments/python) |
| Python 3.5 | `fission/python3-env` | [`github.com/fission/fission/tree/master/environments/python`](https://github.com/fission/fission/tree/master/environments/python) |
| Node.js | `fission/nodejs-env` | [`github.com/fission/fission/tree/master/environments/nodejs`](https://github.com/fission/fission/tree/master/environments/nodejs) |
| .NET C# | `fission/dotnet-env` | [`github.com/fission/fission/tree/master/environments/dotnet`](https://github.com/fission/fission/tree/master/environments/dotnet) |
| .NET 2.0 C# | `fission/dotnet20-env` | [`github.com/fission/fission/tree/master/environments/dotnet20`](https://github.com/fission/fission/tree/master/environments/dotnet20) |
| Go | `fission/go-runtime` | [`github.com/fission/fission/tree/master/environments/go`](https://github.com/fission/fission/tree/master/environments/go) |
| PHP | `fission/php7-env` | [`github.com/fission/fission/tree/master/environments/php7`](https://github.com/fission/fission/tree/master/environments/php7) |
| Ruby | `fission/ruby-env` | [`github.com/fission/fission/tree/master/environments/ruby`](https://github.com/fission/fission/tree/master/environments/ruby) |
| Perl | `fission/perl-env` | [`github.com/fission/fission/tree/master/environments/perl`](https://github.com/fission/fission/tree/master/environments/perl) |

# 列出和获取命令

与函数命令一样，环境也有`list`和`get`命令，它们的工作方式也相同。

```
$ fission environment list
```

运行上一个命令将列出所有配置的环境。

```
$ fission environment get --name nodejs
```

运行上一个命令将获取命名环境的详细信息。

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/0e86e3f1-0777-4fe1-b51e-2417d7382cf4.png)

# 删除命令

`delete`命令再次按预期工作（请记住它会在没有警告的情况下删除）：

```
$ fission environment delete --name nodejs
```

此外，如果您的环境中有函数，它也将在没有警告的情况下被删除。但是，您的函数将保留，直到您手动删除它们。任何尝试调用没有环境的函数都将导致内部服务器错误。

# 在云中运行 Fission

现在我们知道了在本地运行 Fission 时启动和交互所涉及的内容，让我们看看在云中启动 Kubernetes，然后配置 Fission 在那里运行。

在本节的其余部分，我将仅提供 macOS High Sierra 和 Ubuntu 17.04 主机的说明，因为它们与我们将要运行的命令具有更高的兼容性。

# 启动 Kubernetes 集群

我将使用以下命令在 Google Cloud 中启动我的 Kubernetes：

```
$ gcloud container clusters create kube-cluster
```

前述命令的输出可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/a9396fbc-ab7c-42f1-91b1-0622bee37be9.png)

一旦启动，最多需要大约 5 分钟，您可以使用以下方法检查您的集群是否按预期运行：

```
$ kubectl get nodes
```

前述命令的输出可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/1493cd89-dfb1-41cb-8dce-23131d8674ab.png)

现在我们的三节点集群已经运行起来了，并且我们的本地 Kubernetes 客户端正在与之交互，我们可以再次运行以下命令来部署 Helm 的 Kubernetes 端：

```
$ helm init
```

这将返回以下消息：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/e235d7be-a745-4516-8149-9345b8f5317d.png)

现在我们已经准备好了 Helm，我们可以继续启动 Fission。

# 安装 Fission

与之前一样，我们将使用 Helm 来安装 Fission。在本地安装 Fission 和在 Google Cloud、Microsoft Azure 或 AWS 等公共云上安装 Fission 之间唯一的区别是，我们不会使用`--set serviceType=NodePort`选项，而是直接运行以下命令：

```
$ helm install --namespace fission https://github.com/fission/fission/releases/download/0.4.0/fission-all-0.4.0.tgz
```

您可能会注意到这次运行速度要快得多，并且返回的信息与我们在本地单节点集群上启动 Fission 时非常相似。

您可能会注意到，这次您的安装有一个不同的名称：

```
NAME: orange-shark
LAST DEPLOYED: Sun Dec 10 13:46:02 2017
NAMESPACE: fission
STATUS: DEPLOYED
```

此名称用于在整个过程中引用安装，如您从 Google Cloud Web 控制台的工作负载页面中看到的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/eea42255-91b3-4c26-9e15-bd86210b99e4.png)

在控制台中，点击“发现和负载均衡”将显示分配给您的安装的所有外部 IP 地址。由于我们传递了`NodePort`选项，因此已创建了外部负载均衡器：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/de0020bb-b6fb-4bed-b6f2-6c714b115af1.png)

在控制台中查看的最后一件事是存储页面。如您所见，外部块存储已创建并附加到您的安装中。这与我们在本地启动时不同，因为存储实际上是我们单台机器的存储：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/e81c1074-edd4-49ba-9341-dcee15b2f08d.png)

回到命令行，你会注意到，Helm 再次给了我们关于如何完成本地 Fission 客户端配置的指令。然而，由于我们没有使用 Minikube，这次的指令略有不同。

这次设置`FISSION_URL`和`FISSION_ROUTER`变量的命令使用`kubectl`来查询我们的安装，以找出负载均衡器的外部 IP 地址：

```
 $ export FISSION_URL=http://$(kubectl --namespace fission get svc controller -o=jsonpath='{..ip}')
 $ export FISSION_ROUTER=$(kubectl --namespace fission get svc router -o=jsonpath='{..ip}')
```

你可以通过运行以下命令来检查 URL：

```
$ echo $FISSION_URL
$ echo $FISSION_ROUTER
```

这应该会给你类似以下的输出：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/27b2dd66-4b9b-4a2a-a8ee-20857a4d0816.png)

现在我们已经安装了 Fission，并且我们的本地命令行客户端已配置为与我们的基于云的安装进行交互，我们可以通过运行以下命令快速重新运行 hello world 示例：

```
$ fission env create --name nodejs --image fission/node-env
$ curl https://raw.githubusercontent.com/fission/fission/master/examples/nodejs/hello.js > /tmp/hello.js
$ fission function create --name hello --env nodejs --code /tmp/hello.js --url /hello --method GET
```

这应该会给你类似以下的输出：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/e039c924-6268-4b50-a00d-98c7707193a4.png)

一旦启动，你可以使用以下命令之一来调用该函数：

```
$ curl http://$FISSION_ROUTER/hello
$ http http://$FISSION_ROUTER/hello
```

这应该会给你类似以下的输出：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/9395a699-b5b0-467e-926f-ced6004eb30c.png)

正如你已经看到的，就像我们所看到的所有技术一样，一旦安装，与公共云中的 Fission 交互和使用与在本地运行时并无不同。你真的不需要太在意外部访问等等，因为 Fission 和 Kubernetes 都已经为你解决了这个问题。

# guestbook

在我们继续更高级的示例之前，让我们快速再次启动我们的 guestbook 应用程序。要做到这一点，切换到存储库中的`/Chapter08/guestbook/`文件夹，然后运行以下命令：

```
$ kubectl create -f redis.yaml
$ fission env create --name python --image fission/python-env
$ fission function create --name guestbook-get --env python --code get.py --url /guestbook --method GET
$ fission function create --name guestbook-add --env python --code add.py --url /guestbook --method POST
$ open http://$FISSION_ROUTER/guestbook
```

这应该会给你类似以下的输出：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/87759a92-2586-497c-bf0a-32689b6c97e8.png)

这将启动应用程序，并且还会在浏览器中打开，你可以在其中添加评论：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/0abac7c0-97e9-4abe-beb4-bd6d120aa78b.png)

# 更多示例

在我们结束本章之前，让我们看一些在 Fission 中运行的示例代码，首先是一个天气检查器。

# 天气

在存储库的`/Chapter08/weather/`文件夹中，你会找到`weather.js`。这是一个简单的 Node.js 函数，用于查询 Yahoo 天气 API 以返回给定位置的当前天气：

```
'use strict';

const rp = require('request-promise-native');

module.exports = async function (context) {
    const stringBody = JSON.stringify(context.request.body);
    const body = JSON.parse(stringBody);
    const location = body.location;

    if (!location) {
        return {
            status: 400,
            body: {
                text: 'You must provide a location.'
            }
        };
    }

    try {
        const response = await rp(`https://query.yahooapis.com/v1/public/yql?q=select item.condition from weather.forecast where woeid in (select woeid from geo.places(1) where text="${location}") and u="c"&format=json`);
        const condition = JSON.parse(response).query.results.channel.item.condition;
        const text = condition.text;
        const temperature = condition.temp;
        return {
            status: 200,
            body: {
                text: `It is ${temperature} celsius degrees in ${location} and ${text}`
            },
            headers: {
                'Content-Type': 'application/json'
            }
        };
    } catch (e) {
        console.error(e);
        return {
            status: 500,
            body: e
        };
    }
}
```

正如你从前面的代码中看到的，该函数接受 JSON 编码的数据，其中必须包含一个有效的位置。因此，我们需要使用`POST`路由部署该函数，并且如果没有传递位置数据，它会报错，所以我们还应该部署一个`GET`路由。要做到这一点，只需在`/Chapter08/weather/`文件夹中运行以下命令：

```
$ fission env create --name nodejs --image fission/node-env
$ fission function create --name weather --env nodejs --code weather.js --url /weather --method POST
$ fission route create --method GET --url /weather --function weather
```

如果你已经在终端输出中看到了我们最初为 hello world 示例创建并运行的环境，那么第一个命令可能会导致错误：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/81dd0f50-1acc-4c96-a450-df575172498e.png)

现在我们已经部署了我们的函数，可以通过运行以下两个命令之一来快速测试它：

```
$ http http://$FISSION_ROUTER/weather
$ curl http://$FISSION_ROUTER/weather
```

因为我们没有提供位置，所以你应该会看到以下消息：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/a0fdce7d-d631-4a8c-a887-dcb6246727bc.png)

这正是代码的预期行为。正如你所看到的，它返回了一个`400`错误和我们预期的消息。通过运行以下命令之一提供位置（我使用了`英格兰诺丁汉`）应该会告诉你天气情况：

```
$ http POST http://$FISSION_ROUTER/weather location="Nottingham, England"
$ curl -H "Content-Type: application/json" -X POST -d '{"location":"Nottingham, England"}' http://$FISSION_ROUTER/weather 
```

你可以从下面的终端输出中看到，它已经确认了我所在的地方目前天气并不是很好：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/2a20414b-ca48-4dfc-9068-f4c4c69d2a39.png)

# Slack

在这个例子中，我们将在当前 Kubernetes 安装的默认命名空间中每次创建或删除服务时发布一条消息。这些消息将通过名为 Slack 的 Webhook 发布到一个名为 Slack 的群组消息服务中。

Slack 是一个在线协作工具，允许团队在其中与聊天机器人和其他人进行交互。它提供免费和付费的服务，以及一个详尽的 API 供你的应用程序连接到你的聊天室。

我将假设你已经可以访问 Slack 工作空间，并且有权限向其添加应用程序。如果没有，那么你可以在[`slack.com/`](https://slack.com)配置一个新的工作空间。

一旦你进入了你的工作空间，点击屏幕左上角的工作空间名称，然后从下拉列表中选择“管理应用程序”。这将带你进入 Slack 的**应用程序目录**。在这里，在页面顶部的搜索框中输入`Incoming WebHooks`，选择结果，然后点击“添加配置”按钮。

按照屏幕上的说明创建你选择的频道的 Webhook。我选择在随机频道发布我的更新，我还自定义了图标。在这个页面上，你还会找到一个 Webhook URL。我的（现在已被删除）是 `https://hooks.slack.com/services/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`。

记下这一点，因为我们需要用它来更新代码。正如你在下面的代码中所看到的，你也可以在 `/Chapter08/slack/` 仓库中找到，第三行需要用你的 Webhook 详细信息进行更新：

```
'use strict';

let https = require('https');

const slackWebhookPath = "/put/your/url/here"; // Something like "/services/XXX/YYY/zZz123"

function upcaseFirst(s) {
    return s.charAt(0).toUpperCase() + s.slice(1).toLowerCase();
}

async function sendSlackMessage(msg) {
    let postData = `{"text": "${msg}"}`;
    let options = {
        hostname: "hooks.slack.com",
        path: slackWebhookPath,
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        }
    };

    return new Promise(function(resolve, reject) {
        let req = https.request(options, function(res) {
            console.log(`slack request status = ${res.statusCode}`);
            return resolve();
        });
        req.write(postData);
        req.end();
    });
}

module.exports = async function(context) {
    console.log(context.request.headers);

    let obj = context.request.body;
    let version = obj.metadata.resourceVersion;
    let eventType = context.request.get('X-Kubernetes-Event-Type');
    let objType = context.request.get('X-Kubernetes-Object-Type');

    let msg = `${upcaseFirst(eventType)} ${objType} ${obj.metadata.name}`;
    console.log(msg, version);

    if (eventType == 'DELETED' || eventType == 'ADDED') {
        console.log("sending event to slack")
        await sendSlackMessage(msg);
    }

    return {
        status: 200,
        body: ""
    }
}
```

为了做到这一点，粘贴`https://hooks.slack.com`后面的所有内容，包括斜杠(`/`)。对我来说，这是`/services/T8F3CR4GG/B8FNRR3PC/wmLSDgS0fl5SGOcAgNjwr6pC`。

该行应该类似于以下内容：

```
const slackWebhookPath = "/services/T8F3CR4GG/B8FNRR3PC/wmLSDgS0fl5SGOcAgNjwr6pC"; // Something like "/services/XXX/YYY/zZz123"
```

确保文件名为 `kubeEventsSlack.js`，一旦你的 Webhook 详细信息在代码中，我们可以使用以下命令创建和启动函数：

```
$ fission function create --name kubeslack --env nodejs --code kubeEventsSlack.js
```

函数创建后，我们需要创建一些东西来触发它。以前，我们一直在使用 HTTP 调用来调用函数。不过这一次，我们希望在我们的 Kubernetes 集群中发生某些事情时触发函数。为此，我们需要创建一个观察。

为了做到这一点，运行以下命令：

```
$ fission watch create --function kubeslack --type service --ns default
```

`fission watch` 命令是我们尚未讨论过的内容，所以让我们花点时间了解一下更多关于它的信息。

作为我们 Fission 部署的一部分，有一个名为 `kubewatcher` 的服务。默认情况下，Fission 使用这个服务来通过观察 Kubernetes API 来帮助管理自身，但也向最终用户公开。用于创建之前观察的命令创建了一个观察者，它每次在默认命名空间中对服务进行更改时调用我们的函数(`--function kubeslack`)。我们还可以设置一个观察，以查找对 pods、deployments 等的更改，通过更改类型：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/90b42045-f5c6-46a0-b78f-2d663350d73c.png)

现在我们需要在默认命名空间中启动一个服务。为此，切换到 `/Chapter03/` 文件夹并运行以下命令：

```
$ kubectl apply -f cli-hello-world.yml
```

然后，通过运行以下命令删除服务：

```
$ kubectl delete service cli-hello-world 
```

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/8eef86e2-c090-45d1-8966-a81edfa74be6.png)

如果你检查 Slack，你应该会看到两条消息，确认一个名为 `cli-hello-world` 的服务已被添加和删除：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/c9bcd145-2011-4126-9bbe-079d7e684278.png)

你应该几乎实时地看到这种情况发生，你可能还会看到有关在默认命名空间内启动其他服务的消息。

# 鲸鱼

接下来，也是最后一个例子，我们要看的是一个二进制环境。这个环境与我们一直在看的环境不同，因为它不包含编程语言。相反，我们将部署一个安装和配置名为`cowsay`的 Unix 工具的 bash 脚本。代码如下，并且位于`/Chapter08/whale/`文件夹中：

```
#!/bin/sh

if ! hash cowsay 2> /dev/null; then
    apk update > /dev/null
    apk add curl perl > /dev/null
    curl https://raw.githubusercontent.com/docker/whalesay/master/cowsay > /bin/cowsay 2> /dev/null
    chmod +x /bin/cowsay
    mkdir -p /usr/local/share/cows/
    curl https://raw.githubusercontent.com/docker/whalesay/master/docker.cow > /usr/local/share/cows/default.cow 2> /dev/null
fi

cowsay
```

如你所见，bash 脚本有两个部分。第一部分运行`cowsay`命令，如果出错，它将使用`apk`来安装`curl`和`perl`。安装完成后，它会下载代码副本，并配置默认行为。然后在安装后运行`cowsay`命令。

也许你会想，APK 是什么，`cowsay`又是什么？由于部署到 Fission 环境中的容器运行的是 Alpine Linux，我们需要使用**Alpine 软件包管理器**（**APK**）来安装我们代码运行所需的必要软件包。

Alpine Linux 是一个 Linux 发行版，在过去的两年里开始在更传统的 Ubuntu/CentOS 安装中获得了很多关注，这是因为它的体积。Alpine Linux 的基本安装只需 8MB 的空间。然而，尽管它很小，但它仍然和其他 Linux 发行版一样功能强大。它小巧的体积加上强大的功能，使其成为构建容器的完美操作系统。

`cowsay`是一个 Unix 命令，它会在一个来自牛的对话气泡中重复你给它的任何输入，因此得名`cowsay`。我们将安装 Docker 自己的版本`cowsay`，它使用的是鲸鱼而不是牛。要部署二进制函数，我们首先需要创建环境：

```
$ fission env create --name binary --image fission/binary-env
```

现在我们可以部署函数并创建`POST`和`GET`路由，以便我们可以访问它：

```
$ fission function create --name whalesay --env binary --deploy whalesay.sh --url /whale --method POST
$ fission route create --method GET --url /whale --function whalesay
```

上述命令的输出如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/d956143c-5c1e-4c68-a677-67e5aba546a7.png)

现在我们已经部署了我们的函数，我们可以使用以下之一来访问它：

```
$ http http://$FISSION_ROUTER/whale
$ curl http://$FISSION_ROUTER/whale
```

这将返回一个 ASCII 鲸鱼，如下终端输出所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/28566bb9-7ffc-483d-8579-f670243cb692.png)

你可能会注意到对话框中没有任何内容；那是因为我们需要`POST`一些东西。与之前的示例不同，我们启动的函数将简单地重复我们发布的任何内容。因此，如果我们`POST`一个 JSON 对象，它将返回 JSON 对象。因此，我们将只发布纯文本：

```
$ echo 'Hello from Whalesay !!!' | http POST http://$FISSION_ROUTER/whale
$ curl -X POST -H "Content-Type: text/plain" --data 'Hello from Whalesay !!!' http://$FISSION_ROUTER/whale
```

正如你可以从以下终端输出中看到的那样，这将返回我们发布的消息：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/9e37db66-c2f4-43b5-9be1-6296c995ce70.png)

现在，你可能会认为这似乎是一个相当愚蠢的例子。然而，我们在这里所做的是获取 HTTP 请求的内容，并将其发布到 Linux 二进制文件中，然后使用我们发布的内容执行它。然后，我们通过 HTTP 请求返回运行命令的输出。

此时，您可能希望终止/关闭您已经启动以测试 Fission 的任何 Kubernetes 集群。

# 摘要

在本章中，我们已经研究了 Fission。我们使用 Helm 进行了安装，并在本地和 Google Cloud 上部署了它。我们还启动了几个测试应用程序，一些基本的，一些调用第三方服务来发布和返回信息。在安装和配置示例应用程序的过程中，我希望您开始看到 Fission 的用处以及它和其他无服务器技术如何集成到您自己的应用程序中。

当我开始写这一章时，我希望包括一些关于 Fission 工作流和 Fission UI 的部分。然而，在写作时，这两个附加组件都无法正常工作。现在，不要误会，Fission 是一种强大且易于使用的技术；然而，它非常新，并且仍在开发中，就像 Kubernetes 一样——这意味着在代码基础变得更加稳定之前，新版本中会有破坏性的更新。

例如，我们安装的 Fission 版本 0.4.0 是因为在写作时，最新版本的 Kubernetes 1.8 删除了`ThirdPartyResources`功能，并用`CustomResourceDefinitions`替换，这意味着旧版本的 Fission 将无法在当前版本的 Kubernetes 上运行。

我们将在剩下的章节中研究 Kubernetes 的发布周期以及这可能对您产生的影响。
