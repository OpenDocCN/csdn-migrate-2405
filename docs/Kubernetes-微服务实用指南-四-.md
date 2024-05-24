# Kubernetes 微服务实用指南（四）

> 原文：[`zh.annas-archive.org/md5/C0567D22DC0AB8851752A75F6BAC2512`](https://zh.annas-archive.org/md5/C0567D22DC0AB8851752A75F6BAC2512)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：在 Kubernetes 上运行无服务器任务

在本章中，我们将深入探讨云原生系统中最热门的趋势之一：无服务器计算（也称为**函数即服务**或**FaaS**）。我们将解释无服务器意味着什么（剧透警告：它的意义不止一种），以及它与微服务的比较。我们将使用 Nuclio 无服务器框架实现并部署 Delinkcious 的一个很酷的新功能，即链接检查。最后，我们将简要介绍在 Kubernetes 中进行无服务器计算的其他方法。

本章将涵盖以下主题：

+   云中的无服务器

+   使用 Delinkcious 进行链接检查

+   使用 Nuclio 进行无服务器链接检查

# 技术要求

在本章中，我们将安装一个名为 Nuclio 的无服务器框架。首先，让我们创建一个专用命名空间，如下所示：

```
$ kubectl create namespace nuclio
```

这是一个很好的安全实践，因为 Nuclio 不会干扰您集群的其余部分。接下来，我们将应用一些**基于角色的访问控制**（**RBAC**）权限。如果您查看文件（在将其运行在您的集群之前，您应该始终检查 Kubernetes 清单），您会发现大多数权限都限于 Nuclio 命名空间，并且有一些关于 Nuclio 本身创建的**自定义资源定义**（**CRDs**）的集群范围权限；这是一个很好的卫生习惯：

```
$ kubectl apply -f https://raw.githubusercontent.com/nuclio/nuclio/master/hack/k8s/resources/nuclio-rbac.yaml
```

现在让我们部署 Nuclio 本身；它会创建一些 CRD，并部署控制器和仪表板服务。这非常经济和直接，如下所示：

```
$ kubectl apply -f https://raw.githubusercontent.com/nuclio/nuclio/master/hack/k8s/resources/nuclio.yaml
```

现在，让我们通过检查控制器和仪表板 pod 是否成功运行来验证安装：

```
$ kubectl get pods --namespace nuclio
 NAME                               READY     STATUS    RESTARTS   AGE
 nuclio-controller-556774b65-mtvmm   1/1       Running   0          22m
 nuclio-dashboard-67ff7bb6d4-czvxp   1/1       Running   0          22m
```

仪表板很好，但更适合临时探索。对于更严肃的生产使用，最好使用`nuctl` CLI。下一步是从[`github.com/nuclio/nuclio/releases`](https://github.com/nuclio/nuclio/releases)下载并安装`nuctl`。

然后，将可执行文件复制到您的路径中，创建`symlink nuctl`，如下所示：

```
$ cd /usr/local/bin
$ curl -LO https://github.com/nuclio/nuclio/releases/download/1.1.2/nuctl-1.1.2-darwin-amd64
$ ln -s nuctl-1.1.2-darwin-amd64 nuctl
```

最后，让我们创建一个镜像拉取密钥，以便 Nuclio 可以将函数部署到我们的集群中：

```
$ kubectl create secret docker-registry registry-credentials -n nuclio \
 --docker-username g1g1 \
 --docker-password $DOCKERHUB_PASSWORD \
 --docker-server registry.hub.docker.com \
 --docker-email the.gigi@gmail.com

secret "registry-credentials" created
```

您还可以使用其他注册表和适当的凭据；在 Minikube 中，甚至可以使用本地注册表。但是，为了保持一致，我们将使用 Docker Hub 注册表。

# 代码

代码分为两个 Git 存储库，如下所示：

+   您可以在[`github.com/PacktPublishing/Hands-On-Microservices-with-Kubernetes/tree/master/Chapter09`](https://github.com/PacktPublishing/Hands-On-Microservices-with-Kubernetes/tree/master/Chapter09)找到代码示例。

+   您可以在[`github.com/the-gigi/delinkcious/releases/tag/v0.7`](https://github.com/the-gigi/delinkcious/releases/tag/v0.7)找到更新的 Delinkcious 应用程序。

# 云中的无服务器

人们对云中的无服务器有两种不同的定义，特别是在 Kubernetes 的上下文中。第一种意思是您不必管理集群的节点。这个概念的一些很好的例子包括 AWS Fargate（[`aws.amazon.com/fargate/`](https://aws.amazon.com/fargate/)）和 Azure Container Instances（ACI）（[`azure.microsoft.com/en-us/services/container-instances/`](https://azure.microsoft.com/en-us/services/container-instances/)）。无服务器的第二个意思是，您的代码不是部署为长时间运行的服务，而是打包为可以按需调用或以不同方式触发的函数。这个概念的一些很好的例子包括 AWS Lambda 和 Google Cloud Functions。

让我们了解服务和无服务器函数之间的共同点和区别。

# 微服务和无服务器函数

相同的代码通常可以作为微服务或无服务器函数运行。区别主要在于操作。让我们比较微服务和无服务器函数的操作属性，如下所示：

| **微服务** | **无服务器函数** |
| --- | --- |

|

+   始终运行（可以缩减至至少一个）。

+   可以暴露多个端点（如 HTTP 和 gRPC）。

+   需要自己实现请求处理和路由。

+   可以监听事件。

+   服务实例可以维护内存缓存、长期连接和会话。

+   在 Kubernetes 中，微服务直接由服务对象表示。

|

+   按需运行（理论上；它可以缩减到零）。

+   暴露单个端点（通常为 HTTP）。

+   可以通过事件触发或获得自动端点。

+   通常对资源使用和最大运行时间有严格限制。

+   有时，可能会有冷启动（即从零开始扩展）。

+   在 Kubernetes 中，没有原生的无服务器函数概念（作业和定时作业接近）。

|

这应该为您提供一些相对良好的指导，告诉您何时使用微服务，何时使用无服务器函数。在以下情况下，微服务是正确的选择：

+   您的工作负载需要持续运行，或几乎持续运行。

+   每个请求运行的时间很长，无法被无服务器函数的限制所支持。

+   工作负载在调用之间使用本地状态，无法轻松地移动到外部数据存储。

然而，如果您的工作负载很少运行，持续时间相对较短，那么您可能更喜欢使用无服务器函数。

还有一些其他工程考虑要牢记。例如，服务更为熟悉，通常具有各种支持库。开发人员可能更喜欢服务，并希望将代码部署到系统时有一个单一的范例。特别是在 Kubernetes 中，有大量的无服务器函数选项可供选择，很难选择正确的选项。另一方面，无服务器函数通常支持敏捷和轻量级的部署模型，开发人员可以将一些代码放在一起，它就会在集群上神奇地开始运行，因为无服务器函数解决方案负责处理打包和部署的所有业务。

# 在 Kubernetes 中建模无服务器函数

归根结底，Kubernetes 运行容器，因此您知道您的无服务器函数将被打包为容器。然而，在 Kubernetes 中有两种主要表示无服务器函数的方式。第一种是作为代码；在这里，开发人员基本上以某种形式（作为文件或通过将其推送到 Git 存储库）提供函数。第二种是将其构建为实际容器。开发人员构建一个常规容器，无服务器框架负责安排它并将其作为函数运行。

# 函数作为代码

这种方法的好处是，作为开发人员，您完全可以绕过构建图像、标记它们、将它们推送到注册表并将它们部署到集群的整个业务（即部署、服务、入口和 NetworkPolicy）。这对于临时探索和一次性工作也非常有用。

# 函数作为容器

在这里，作为开发人员，您是在熟悉的领域。您使用常规流程构建一个容器，然后稍后将其部署到集群作为无服务器函数。它仍然比常规服务更轻量级，因为您只需要在容器中实现一个函数，而不是一个完整的 HTTP 或 gRPC 服务器，或者注册以监听某些事件。您可以通过无服务器函数解决方案获得所有这些。

# 构建、配置和部署无服务器函数

您已经实现了您的无服务器函数，现在您想要将其部署到集群中。无论您是构建无服务器函数（如果它是一个容器）还是将其提供为函数，通常也需要以某种方式对其进行配置。配置可能包含诸如扩展限制、函数代码位置以及如何调用和触发它的信息。然后，下一步是将函数部署到集群中。这可能是通过 CLI 或 Web UI 的一次性部署，或者也可能与您的 CI/CD 流水线集成。这主要取决于您的无服务器函数是您主要应用程序的一部分，还是您以临时方式启动它以进行故障排除或手动清理任务。

# 调用无服务器函数

一旦无服务器函数在集群中部署，它将处于休眠状态。将有一个控制器不断运行，准备调用或触发函数。控制器应该占用非常少的资源，只需监听传入的请求或事件以触发函数。在 Kubernetes 中，如果您需要从集群外部调用函数，可能会有一些额外的入口配置。然而，最常见的用例是在内部调用函数并向世界公开一个完整的服务。

现在我们了解了无服务器函数的全部内容，让我们为 Delinkcious 添加一些无服务器函数功能。

# 使用 Delinkcious 进行链接检查

Delinkcious 是一个链接管理系统。链接 - 或者，正式称为**统一资源标识符**（**URIs**）- 实际上只是指向特定资源的指针。链接可能存在两个问题，如下所示：

+   它们可能是损坏的（也就是说，它们指向一个不存在的资源）。

+   它们可能指向一个*不良*资源（如钓鱼或注入病毒的网站、仇恨言论或儿童色情）。

检查链接并维护每个链接的状态是链接管理的重要方面。让我们从设计 Delinkcious 执行链接检查的方式开始。

# 设计链接检查

让我们在 Delinkcious 的背景下考虑链接检查。我们应该将当前状态视为未来的改进。以下是一些假设：

+   链接可能是暂时的或永久的中断。

+   链接检查可能是一个繁重的操作（特别是在分析内容时）。

+   链接的状态可能随时改变（也就是说，如果指向的资源被删除，有效链接可能会突然中断）。

具体来说，Delinkcious 链接会按用户冗余存储。如果两个用户添加相同的链接，它将分别为每个用户存储。这意味着，如果在添加链接时进行链接检查，如果*N*用户添加相同的链接，那么每次都会进行检查。这不是很有效，特别是对于许多用户可能添加并且可以从单个检查中受益的热门链接。

考虑以下情况，这甚至更糟：

+   *N*用户添加链接*L*。

+   对于所有这些*N*用户，链接检查*L*都通过了。

+   另一个用户*N+1*添加相同的链接*L*，现在已经损坏（例如，托管公司删除了页面）。

+   只有最后一个用户*N+1*将拥有链接*L*的正确状态，即无效。

+   所有以前的*N*用户仍然会认为链接是有效的。

由于我们在本章中想要专注于无服务器函数，我们将接受 Delinkcious 为每个用户存储链接的方式中的这些限制。将来可能会有更有效和更健壮的设计，如下所示：

+   独立于用户存储所有链接。

+   添加链接的用户将与该链接关联。

+   链接检查将自动反映所有用户的链接的最新状态。

在设计链接检查时，让我们考虑一些以下选项，用于在添加新链接时检查链接：

+   在添加链接时，只需在链接服务中运行链接检查代码。

+   在添加链接时，调用一个单独的链接检查服务。

+   在添加链接时，调用一个无服务器函数进行链接检查。

+   在添加链接时，保持链接处于待定状态，定期对所有最近添加的链接进行检查。

另外，由于链接随时可能会中断，定期对现有链接运行链接检查可能是有用的。

让我们考虑第一个选项，即在链接管理器内部运行链接检查。虽然这样做简单，但也存在一些问题，比如：

+   如果链接检查时间太长（例如，如果目标不可达或内容分类需要很长时间），那么它将延迟对添加链接的用户的响应，甚至可能超时。

+   即使实际的链接检查是异步进行的，它仍然以不可预测的方式占用了链接服务的资源。

+   没有简单的方法可以安排定期检查或临时检查链接，而不对链接管理器进行重大更改。

+   从概念上讲，链接检查是链接管理的一个单独责任，不应该存在于同一个微服务中。

让我们考虑第二个选项，即实施一个专门的链接检查服务。这个选项解决了大部分第一个选项的问题，但可能有些过度。也就是说，当没有必要经常检查链接时，这并不是最佳选项；例如，如果大多数添加的链接都经过了检查，或者链接检查只是定期进行。此外，为了实施一个单一操作的服务，检查链接似乎有些过度。

这让我们剩下了第三和第四个选项，两者都可以通过无服务器函数解决方案有效实施，如下图所示。

让我们从以下简单的设计开始：

+   当添加新链接时，链接管理器将调用一个无服务器函数。

+   新链接最初将处于待定状态。

+   无服务器函数将仅检查链接是否可达。

+   无服务器函数将通过 NATS 系统发送一个事件，链接管理器将订阅该事件。

+   当链接管理器接收到事件时，将更新链接状态从“待定”到“有效”或“无效”。

以下是描述这一流程的图表：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-msvc-k8s/img/10fb6373-7451-42ce-9277-26ed16dbf867.png)

有了一个坚实的设计，让我们继续实施并将其与 Delinkcious 集成。

# 实施链接检查

在这个阶段，我们将独立于无服务器函数实现链接检查功能。让我们从我们的对象模型开始，并向我们的链接对象添加`Status`字段，可能的值为`pending`、`valid`和`invalid`。我们在这里定义了一个名为`LinkStatus`的`alias`类型，并为这些值定义了常量。但是，请注意，它不像其他语言中的强类型`enum`，它实际上只是一个字符串：

```
const (
     LinkStatusPending = "pending"
     LinkStatusValid   = "valid"
     LinkStatusInvalid = "invalid"
 )

 type LinkStatus = string

 type Link struct {
     Url         string
     Title       string
     Description string
     Status      LinkStatus
     Tags        map[string]bool
     CreatedAt   time.Time
     UpdatedAt   time.Time
 }
```

让我们也定义一个`CheckLinkRequest`对象，以后会派上用场。请注意，每个请求都是针对特定用户的，并包括链接的 URL：

```
type CheckLinkRequest struct {
     Username string
     Url      string
 }
```

现在，让我们定义一个接口，`LinkManager`将实现该接口以在链接检查完成时得到通知。该接口非常简单，只有一个方法，用于通知接收者（在我们的例子中是`LinkManager`）用户、URL 和链接状态：

```
type LinkCheckerEvents interface {
     OnLinkChecked(username string, url string, status LinkStatus)
 }
```

让我们创建一个新的包`pkg/link_checker`，以隔离这个功能。它有一个名为`CheckLink()`的函数，接受一个 URL，并使用内置的 Go HTTP 客户端调用其 HEAD HTTP 方法。

如果结果小于 400，则被视为成功，否则将 HTTP 状态作为错误返回：

```
package link_checker

 import (
     "errors"
     "net/http"
 )

 // CheckLinks tries to get the headers of the target url and returns error if it fails
 func CheckLink(url string) (err error) {
     resp, err := http.Head(url)
     if err != nil {
         return
     }
     if resp.StatusCode >= 400 {
         err = errors.New(resp.Status)
     }
     return
 }
```

HEAD 方法只返回一些头部信息，是检查链接是否可达的有效方法，因为即使对于非常大的资源，头部信息也只是一小部分数据。显然，如果我们想将链接检查扩展到扫描和分析内容，这是不够的，但现在可以用。

根据我们的设计，当链接检查完成时，`LinkManager`应该通过 NATS 接收到一个事件，其中包含检查结果。这与新闻服务监听链接事件（如链接添加和链接更新事件）非常相似。让我们为 NATS 集成实现另一个包`link_checker_events`，它将允许我们发送和订阅链接检查事件。首先，我们需要一个包含用户名、URL 和链接状态的事件对象：

```
package link_checker_events

 import (
     om "github.com/the-gigi/delinkcious/pkg/object_model"
 )

 type Event struct {
     Username string
     Url      string
     Status   om.LinkStatus
 }
```

然后，我们需要能够通过 NATS 发送事件。`eventSender`对象实现了`LinkCheckerEvents`接口。每当它接收到调用时，它会创建`link_checker_events.Event`并将其发布到 NATS：

```
package link_checker_events

 import (
     "github.com/nats-io/go-nats"
     om "github.com/the-gigi/delinkcious/pkg/object_model"
     "log"
 )

 type eventSender struct {
     hostname string
     nats     *nats.EncodedConn
 }

 func (s *eventSender) OnLinkChecked(username string, url string, status om.LinkStatus) {
     err := s.nats.Publish(subject, Event{username, url, status})
     if err != nil {
         log.Fatal(err)
     }
 }

 func NewEventSender(url string) (om.LinkCheckerEvents, error) {
     ec, err := connect(url)
     if err != nil {
         return nil, err
     }
     return &eventSender{hostname: url, nats: ec}, nil
 }
```

事件在`link_checker_events`包中定义，而不是在一般的 Delinkcious 对象模型中定义的原因是，这个事件只是为了通过 NATS 与链接检查监听器进行接口交互而创建的。没有必要在包外部暴露这个事件（除了让 NATS 对其进行序列化）。在`Listen()`方法中，代码连接到 NATS 服务器并在队列中订阅 NATS（这意味着即使多个订阅者订阅了同一个队列，也只有一个监听器会处理每个事件）。

当订阅到队列的监听函数从 NATS 接收到事件时，它将其转发到实现`om.LinkCheckerEvents`的事件接收器（同时忽略链接删除事件）：

```
package link_manager_events

 import (
     om "github.com/the-gigi/delinkcious/pkg/object_model"
 )

 func Listen(url string, sink om.LinkManagerEvents) (err error) {
     conn, err := connect(url)
     if err != nil {
         return
     }

     conn.QueueSubscribe(subject, queue, func(e *Event) {
         switch e.EventType {
         case om.LinkAdded:
             {
                 sink.OnLinkAdded(e.Username, e.Link)
             }
         case om.LinkUpdated:
             {
                 sink.OnLinkUpdated(e.Username, e.Link)
             }
         default:
             // Ignore other event types
         }
     })

     return
 }
```

如果您仔细跟随，您可能已经注意到有一个关键部分缺失，这是我们在设计中描述的，即调用链接检查。一切都已经连接好，准备好检查链接，但实际上没有人在调用链接检查。这就是`LinkManager`发挥作用的地方，用来调用无服务器函数。

# 使用 Nuclio 进行无服务器链接检查

在我们深入研究`LinkManager`并关闭 Delinkcious 中的链接检查循环之前，让我们熟悉一下 Nuclio（[`nuclio.io/`](https://nuclio.io/)），并探索它如何为 Delinkcious 提供非常适用的无服务器函数解决方案。

# Nuclio 的简要介绍

Nuclio 是一个经过精心打磨的开源平台，用于高性能无服务器函数。它由 Iguazio 开发，并支持多个平台，如 Docker、Kubernetes、GKE 和 Iguazio 本身。我们显然关心 Kubernetes，但有趣的是 Nuclio 也可以在其他平台上使用。它具有以下功能：

+   它可以从源代码构建函数，也可以提供您自己的容器。

+   这是一个非常清晰的概念模型。

+   它与 Kubernetes 集成非常好。

+   它使用一个名为`nuctl`的 CLI。

+   如果您想要交互式地使用它，它有一个 Web 仪表板。

+   它有一系列方法来部署、管理和调用您的无服务器函数。

+   它提供 GPU 支持。

+   这是一个 24/7 支持的托管解决方案（需要付费）。

最后，它有一个超酷的标志！您可以在这里查看标志：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-msvc-k8s/img/5a1e8c8f-634e-4833-b4ed-81635a523bba.png)

现在让我们使用 Nuclio 构建和部署我们的链接检查功能到 Delinkcious 中。

# 创建一个链接检查无服务器函数

第一步是创建一个无服务器函数；这里有两个组件：

+   函数代码

+   函数配置

让我们创建一个专门的目录，名为`fun`，用于存储无服务器函数。无服务器函数实际上不属于我们现有的任何类别；也就是说，它们既不是普通的包，也不是服务，也不是命令。我们可以将函数代码和其配置作为一个 YAML 文件放在`link_checker`子目录下。以后，如果我们决定将其他功能建模为无服务器函数，那么我们可以为每个函数创建额外的子目录，如下所示：

```
$ tree fun
 fun
 └── link_checker
 ├── function.yaml
 └── link_checker.go
```

函数本身是在`link_checker.go`中实现的。`link_checker`函数负责在触发时检查链接并向 NATS 发布结果事件。让我们逐步分解，从导入和常量开始。我们的函数将利用 Nuclio GO SDK，该 SDK 提供了一个标准签名，我们稍后会看到。它还导入了我们的 Delinkcious 包：`object_model`，`link_checker`和`link_checker_events`包。

在这里，我们还根据众所周知的 Kubernetes DNS 名称定义 NATS URL。请注意，`natsUrl`常量包括命名空间（默认情况下）。`link_checker`无服务器函数将在 Nuclio 命名空间中运行，但将向运行在默认命名空间中的 NATS 服务器发送事件。

这不是一个问题；命名空间在网络层不是相互隔离的（除非你明确创建了网络策略）：

```
package main

 import (
     "encoding/json"
     "errors"
     "fmt"
     "github.com/nuclio/nuclio-sdk-go"
     "github.com/the-gigi/delinkcious/pkg/link_checker"
     "github.com/the-gigi/delinkcious/pkg/link_checker_events"
     om "github.com/the-gigi/delinkcious/pkg/object_model"
 )

 const natsUrl = "nats-cluster.default.svc.cluster.local:4222"
```

实现 Nuclio 无服务器函数（使用 Go）意味着实现具有特定签名的处理函数。该函数接受 Nuclio 上下文和 Nuclio 事件对象。两者都在 Nuclio GO SDK 中定义。处理函数返回一个空接口（基本上可以返回任何东西）。但是，这里我们使用的是 HTTP 调用函数的标准 Nuclio 响应对象。Nuclio 事件有一个`GetBody()`消息，可以用来获取函数的输入。

在这里，我们使用 Delinkcious 对象模型中的标准 JSON 编码器对`CheckLinkRequest`进行解组。这是调用`link_checker`函数的人和函数本身之间的契约。由于 Nuclio 提供了一个通用签名，我们必须验证在请求体中提供的输入。如果没有提供，那么`json.Unmarshal()`调用将失败，并且函数将返回 400（即，错误的请求）错误：

```
func Handler(context *nuclio.Context, event nuclio.Event) (interface{}, error) { r := nuclio.Response{ StatusCode: 200, ContentType: "application/text", }

body := event.GetBody()
 var e om.CheckLinkRequest
 err := json.Unmarshal(body, &e)
 if err != nil {
     msg := fmt.Sprintf("failed to unmarshal body: %v", body)
     context.Logger.Error(msg)

     r.StatusCode = 400
     r.Body = []byte(fmt.Sprintf(msg))
     return r, errors.New(msg)

 }
```

此外，如果解组成功，但生成的`CheckLinkRequest`具有空用户名或空 URL，则仍然是无效输入，函数也将返回 400 错误：

```
username := e.Username
 url := e.Url
 if username == "" || url == "" {
     msg := fmt.Sprintf("missing USERNAME ('%s') and/or URL ('%s')", username, url)
     context.Logger.Error(msg)

     r.StatusCode = 400
     r.Body = []byte(msg)
     return r, errors.New(msg)
 }
```

在这一点上，函数验证了输入，我们得到了一个用户名和一个 URL，并且准备检查链接本身是否有效。只需调用我们之前实现的`pkg/link_checker`包的`CheckLink()`函数。状态初始化为`LinkStatusValid`，如果检查返回错误，则状态设置为`LinkStatusInvalid`如下：

```
status := om.LinkStatusValid
err = link_checker.CheckLink(url)
if err != nil {
status = om.LinkStatusInvalid
     }
```

但是，不要混淆！`pkg/link_checker`包是实现`CheckLink()`函数的包。相比之下，`fun/link_checker`是一个调用`CheckLink()`的 Nuclio 无服务器函数。

链接已经被检查，我们有了它的状态；现在是时候通过 NATS 发布结果了。同样，我们已经在`pkg/link_checker_events`中完成了所有的艰苦工作。函数使用`natsUrl`常量创建一个新的事件发送器。如果失败，函数将返回错误。如果发送器被正确创建，它将使用用户名、URL 和状态调用其`OnLinkChecked()`方法。最后，它返回 Nuclio 响应（初始化为 200 OK）和无错误，如下所示：

```
    sender, err := link_checker_events.NewEventSender(natsUrl)
     if err != nil {
         context.Logger.Error(err.Error())

         r.StatusCode = 500
         r.Body = []byte(err.Error())
         return r, err
     }

     sender.OnLinkChecked(username, url, status)
     return r, nil
```

然而，代码只是故事的一半。让我们在`fun/link_checker/function.yaml`中审查函数配置。它看起来就像一个标准的 Kubernetes 资源，这不是巧合。

您可以在[`nuclio.io/docs/latest/reference/function-configuration-reference/`](https://nuclio.io/docs/latest/reference/function-configuration-reference/)查看完整规范。

在下面的代码块中，我们指定了 API 版本、种类（`NuclioFunction`），然后是规范。我们填写了描述，运行时字段为 Golang，处理程序定义了实现处理程序函数的包和函数名称。我们还指定了最小和最大副本数，在这种情况下都是`1`。请注意，Nuclio 没有提供缩放到零的方法。每个部署的函数都至少有一个副本等待触发。配置的唯一自定义部分是`build`命令，用于安装`ca-certificates`包。这使用了**Alpine Linux Package Manager**（**APK**）系统。这是必要的，因为链接检查器需要检查 HTTPS 链接，这需要根 CA 证书。

```
apiVersion: "nuclio.io/v1beta1"
 kind: "NuclioFunction"
 spec:
   description: >
     A function that connects to NATS, checks incoming links and publishes LinkValid or LinkInvalid events.
   runtime: "golang"
   handler: main:Handler
   minReplicas: 1
   maxReplicas: 1
   build:
     commands:
     - apk --update --no-cache add ca-certificates
```

好了！我们创建了一个链接检查器无服务器函数和一个配置；现在让我们将其部署到我们的集群中。

# 使用 nuctl 部署链接检查器函数

当 Nuclio 部署函数时，实际上会构建一个 Docker 镜像并将其推送到注册表中。在这里，我们将使用 Docker Hub 注册表；所以，首先让我们登录：

```
$ docker login
Login with your Docker ID to push and pull images from Docker Hub. If you don't have a Docker ID, head over to https://hub.docker.com to create one.
 Username: g1g1
 Password:
 Login Succeeded
```

函数名称必须遵循 DNS 命名规则，因此`link_checker`中的`""`标记是不可接受的。相反，我们将命名函数为`link-checker`并运行`nuctl deploy`命令，如下所示：

```
$ cd fun/link_checker
$ nuctl deploy link-checker -n nuclio -p . --registry g1g1

 nuctl (I) Deploying function {"name": "link-checker"}
 nuctl (I) Building {"name": "link-checker"}
 nuctl (I) Staging files and preparing base images
 nuctl (I) Pulling image {"imageName": "quay.io/nuclio/handler-builder-golang-onbuild:1.1.2-amd64-alpine"}
 nuctl (I) Building processor image {"imageName": "processor-link-checker:latest"}
 nuctl (I) Pushing image {"from": "processor-link-checker:latest", "to": "g1g1/processor-link-checker:latest"}
 nuctl (I) Build complete {"result": {"Image":"processor-link-checker:latest"...}}
 nuctl (I) Function deploy complete {"httpPort": 31475}
```

请注意，目前编写时使用`nuctl`将函数部署到 Docker Hub 注册表的文档是不正确的。我为 Nuclio 团队打开了一个 GitHub 问题（[`github.com/nuclio/nuclio/issues/1181`](https://github.com/nuclio/nuclio/issues/1181)）。希望在您阅读此文时能够修复。

函数已部署到 Nuclio 命名空间，如下所示：

```
$ kubectl get nucliofunctions -n nuclio
 NAME           AGE
 link-checker   42m
```

查看所有配置的最佳方法是再次使用`nuctl`：

```
$ nuctl get function -n nuclio -o yaml
 metadata:
 name: link-checker
 namespace: nuclio
 spec:
 alias: latest
 build:
 path: .
 registry: g1g1
 timestamp: 1554442452
 description: |
A function with a configuration that connects to NATS, listens to LinkAdded events, check the links and send LinkValid or LinkInvalid events.
 handler: main:Handler
 image: g1g1/processor-link-checker:latest
 imageHash: "1554442427312071335"
 maxReplicas: 1
 minReplicas: 1
 platform: {}
 readinessTimeoutSeconds: 30
 replicas: 1
 resources: {}
 runRegistry: g1g1
 runtime: golang
 serviceType: NodePort
 targetCPU: 75
 version: -1
```

正如您所看到的，它大量借鉴了我们的`function.yaml`配置文件。

我们已成功使用`nuctl` CLI 部署了我们的函数，这对开发人员和 CI/CD 系统非常有用。现在让我们看看如何使用 Nuclio Web UI 部署函数。

# 使用 Nuclio 仪表板部署函数

Nuclio 有一个很酷的 Web UI 仪表板。Nuclio 仪表板做得非常好；它作为一个服务安装在我们的集群中。首先，我们需要在访问之前进行一些端口转发：

```
$ kubectl port-forward -n nuclio $(kubectl get pods -n nuclio -l nuclio.io/app=dashboard -o jsonpath='{.items[0].metadata.name}') 8070
```

接下来，我们可以浏览到`localhost:8070`并使用仪表板。仪表板允许您直接从单个屏幕查看、部署和测试（或调用）无服务器函数。这对于临时探索非常有用。

在这里，我稍微修改了`hello`示例函数（用 Python），甚至用文本`Yeah, it works!`进行了测试：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-msvc-k8s/img/9b6b1b79-bec6-467a-96fc-b431bd03c809.png)

一旦函数在集群中部署，我们可以以不同的方式调用它。

# 直接调用链接检查器函数

使用`nuctl`调用函数非常简单。我们需要提供函数名称（`link-checker`），命名空间，集群 IP 地址和输入到函数的主体：

```
nuctl invoke link-checker -n nuclio --external-ips $(mk ip)
```

# 在 LinkManager 中触发链接检查

在开发函数并希望快速进行编辑-部署-调试周期时，使用`nuctl`是不错的。但是，在生产中，您将希望通过使用 HTTP 端点或其中一个触发器来调用函数。对于 Delinkcious，最简单的方法是让`LinkManager`直接命中 HTTP 端点。这发生在将新链接添加到`LinkManager`的`AddLink()`方法时。它只是调用`triggerLinkCheck`并提供用户名和 URL，如下所示：

```
func (m *LinkManager) AddLink(request om.AddLinkRequest) (err error) {
     ...

     // Trigger link check asynchronously (don't wait for result)
     triggerLinkCheck(request.Username, request.Url)
     return
 }
```

重要的是`AddLink()`方法不必等待链接检查完成。如果记得，链接将立即以*pending*状态存储。稍后，当检查完成时，状态将更改为*valid*或*invalid*。为了实现这一点，`triggerLinkCheck()`函数运行一个 goroutine，立即返回控制。

与此同时，goroutine 准备了`om.CheckLinkRequest`，这是`link_checker`无服务器函数的处理程序所期望的。它通过`json.Marshal()`将其序列化为 JSON，并使用 Go 内置的 HTTP 客户端，向 Nuclio 命名空间中链接检查函数的 URL 发送 POST 请求（在另一个命名空间中命中 HTTP 端点没有问题）。在这里，我们只忽略任何错误；如果出现问题，那么链接将保持在*pending*状态，我们可以稍后决定如何处理它。

```
// Nuclio functions listen by default on port 8080 of their service IP
 const link_checker_func_url = "http://link-checker.nuclio.svc.cluster.local:8080"

func triggerLinkCheck(username string, url string) {
     go func() {
         checkLinkRequest := &om.CheckLinkRequest{Username: username, Url: url}
         data, err := json.Marshal(checkLinkRequest)
         if err != nil {
             return
         }

         req, err := http.NewRequest("POST", link_checker_func_url, bytes.NewBuffer(data))
         req.Header.Set("Content-Type", "application/json")
         client := &http.Client{}
         resp, err := client.Do(req)
         if err != nil {
             return
         }
         defer resp.Body.Close()
     }()
 }
```

我们在这里做了很多工作，但我们保持了一切松散耦合并准备进行扩展。很容易添加更复杂的链接检查逻辑，以便触发链接检查作为 NATS 事件，而不是直接命中 HTTP 端点，甚至用完全不同的无服务器函数解决方案替换 Nuclio 无服务器函数。让我们简要地看一下以下部分中的其他选项。

# 其他 Kubernetes 无服务器框架

AWS Lambda 函数使云中的无服务器函数非常受欢迎。Kubernetes 不是一个完全成熟的无服务器函数原语，但它通过作业和 CronJob 资源非常接近。除此之外，社区开发了大量无服务器函数解决方案（Nuclio 就是其中之一）。以下是一些更受欢迎和成熟的选项，我们将在以下小节中看到：

+   Kubernetes 作业和 CronJobs

+   KNative

+   Fission

+   Kubeless

+   OpenFaas

# Kubernetes 作业和 CronJobs

Kubernetes 部署和服务都是关于创建一组长时间运行的 pod，这些 pod 应该无限期地运行。 Kubernetes Job 的目的是运行一个或多个 pod，直到其中一个成功完成。当您创建一个 Job 时，它看起来非常像一个部署，只是重启策略应该是`Never`。

以下是一个从 Python 打印`Yeah, it works in a Job!!!`的 Kubernetes Job：

```
apiVersion: batch/v1
kind: Job
metadata:
  name: yeah-it-works
spec:
  template:
    spec:
      containers:
      - name: yeah-it-works
        image: python:3.6-alpine
        command: ["python",  "-c", "print('Yeah, it works in a Job!!!')"]
      restartPolicy: Never
```

现在我可以运行这个 Job，观察它的完成，并检查日志，如下所示：

```
$ kubectl create -f job.yaml
 job.batch/yeah-it-works created

 $ kubectl get po | grep yeah-it-works
 yeah-it-works-flzl5            0/1     Completed   0          116s

 $ kubectl logs yeah-it-works-flzl5
 Yeah, it works in a Job!!!
```

这几乎是一个无服务器函数。当然，它没有所有的花里胡哨，但核心功能是存在的：启动一个容器，运行它直到完成，并获取结果。

Kubernetes CronJob 类似于 Job，只是它会按计划触发。如果您不想在第三方无服务器函数框架上增加额外的依赖项，那么您可以在 Kubernetes Job 和 CronJob 对象之上构建一个基本解决方案。

# KNative

KNative（[`cloud.google.com/knative/`](https://cloud.google.com/knative/)）是无服务器函数领域的相对新手，但我实际上预测它将成为主流的首选解决方案，其中有几个原因，例如：

+   这是一个强大的解决方案，可以缩放到零（不像 Nuclio）。

+   它可以在集群内构建镜像（使用 Kaniko）。

+   它是特定于 Kubernetes 的。

+   它有 Google 的支持，并且可以通过 Cloud Run 在 GKE 上使用（[`cloud.google.com/blog/products/serverless/announcing-cloud-run-the-newest-member-of-our-serverless-compute-stack`](https://cloud.google.com/blog/products/serverless/announcing-cloud-run-the-newest-member-of-our-serverless-compute-stack)）。

+   它使用 Istio 服务网格作为基础，而 Istio 变得非常重要（更多信息请参见第十三章，*服务网格-使用 Istio*）。

KNative 有三个独立的组件，如下所示：

+   构建

+   服务

+   事件

它被设计为非常可插拔，以便您可以自己选择构建器或事件源。构建组件负责从源代码到镜像的转换。服务组件负责扩展所需的容器数量以处理负载。它可以根据生成的负载进行扩展，或者减少，甚至可以减少到零。事件组件与在无服务器函数中生成和消耗事件有关。

# Fission

Fission（[`fission.io/`](https://fission.io/)）是来自 Platform9 的开源无服务器框架，支持多种语言，如 Python、NodeJS、Go、C#和 PHP。它可以扩展以支持其他语言。它保持一组准备就绪的容器，因此新的函数调用具有非常低的延迟，但在没有负载时无法实现零缩放。Fission 特别之处在于它能够通过 Fission 工作流（[`fission.io/workflows/`](https://fission.io/workflows/)）组合和链接函数。这类似于 AWS 步函数；Fission 的其他有趣特性包括以下内容：

+   它可以与 Istio 集成进行监控。

+   它可以通过 Fluentd 集成将日志整合到 CLI 中（Fluentd 会自动安装为 DaemonSet）。

+   它提供了 Prometheus 集成，用于指标收集和仪表板可见性。

# Kubeless

Kubeless 是 Bitnami 推出的另一个 Kubernetes 原生框架。它使用函数、触发器和运行时的概念模型，这些模型是使用通过 ConfigMaps 配置的 Kubernetes CRD 实现的。Kubeless 使用 Kubernetes 部署来部署函数 pod，并使用**Horizontal Pod Autoscaler**（**HPA**）进行自动缩放。

这意味着 Kubeless 不能实现零缩放，因为目前 HPA 不能实现零缩放。Kubeless 最主要的亮点之一是其出色的用户界面。

# OpenFaas

OpenFaas（[`www.openfaas.com/`](https://www.openfaas.com/)）是最早的 FaaS 项目之一。它可以在 Kubernetes 或 Docker Swarm 上运行。由于它是跨平台的，它以通用的非 Kubernetes 方式执行许多操作。例如，它可以通过使用自己的函数容器管理来实现零缩放。它还支持许多语言，甚至支持纯二进制函数。

它还有 OpenFaaS Cloud 项目，这是一个完整的基于 GitOps 的 CI/CD 流水线，用于管理您的无服务器函数。与其他无服务器函数项目类似，OpenFaas 有自己的 CLI 和 UI 用于管理和部署。

# 总结

在本章中，我们以一种时尚的方式为 Delinkcious 引入了链接检查！我们讨论了无服务器场景，包括它的两个常见含义；即不处理实例、节点或服务器，以及云函数作为服务。然后，我们在 Delinkcious 中实现了一个松散耦合的解决方案，利用我们的 NATS 消息系统来在链接被检查时分发事件。然后，我们详细介绍了 Nuclio，并使用它来闭环，并让`LinkManager`启动无服务器函数进行链接检查，并稍后得到通知以更新链接状态。

最后，我们调查了许多其他解决方案和 Kubernetes 上的无服务器函数框架。在这一点上，您应该对无服务器计算和无服务器函数有一个扎实的了解。您应该能够就您的系统和项目是否可以从无服务器函数中受益以及哪种解决方案最佳做出明智的决定。很明显，这些好处是真实的，而且这不是一个会消失的时尚。我预计 Kubernetes 中的无服务器解决方案将 consolide（可能围绕 KNative）并成为大多数 Kubernetes 部署的基石，即使它们不是核心 Kubernetes 的一部分。

在下一章中，我们将回到基础知识，并探讨我最喜欢的一个主题，即测试。测试可以成就或毁掉大型项目，在微服务和 Kubernetes 的背景下有许多经验教训可以应用。

# 更多阅读

您可以参考以下参考资料以获取更多信息：

+   Nuclio 文档: [`nuclio.io/docs/latest`](https://nuclio.io/docs/latest)

+   Kubernetes（作业-运行完成）: [`kubernetes.io/docs/concepts/workloads/controllers/jobs-run-to-completion/`](https://kubernetes.io/docs/concepts/workloads/controllers/jobs-run-to-completion/)

+   CronJob: [`kubernetes.io/docs/concepts/workloads/controllers/cron-jobs/`](https://kubernetes.io/docs/concepts/workloads/controllers/cron-jobs/)

+   KNative: [`cloud.google.com/knative/`](https://cloud.google.com/knative/)

+   Fission: [`fission.io/`](https://fission.io/)

+   Kubeless: [`kubeless.io/`](https://kubeless.io/)

+   OpenFaas: [`www.openfaas.com`](https://www.openfaas.com)


# 第十章：测试微服务

软件是人类创造的最复杂的东西。大多数程序员在编写 10 行代码时都无法避免出现错误。现在，考虑一下编写由大量相互作用的组件组成的分布式系统所需的工作，这些组件由大型团队使用大量第三方依赖、大量数据驱动逻辑和大量配置进行设计和实现。随着时间的推移，许多最初构建系统的架构师和工程师可能已经离开组织或转移到不同的角色。需求变化，新技术被重新引入，更好的实践被发现。系统必须发展以满足所有这些变化。

底线是，如果没有严格的测试，你几乎没有机会构建一个可行的非平凡系统。适当的测试是确保系统按预期工作并在引入破坏性变化之前立即识别问题的骨架。基于微服务的架构在测试方面引入了一些独特的挑战，因为许多工作流涉及多个微服务，可能难以控制所有相关微服务和数据存储的测试条件。Kubernetes 引入了自己的测试挑战，因为它在幕后做了很多工作，需要更多的工作来创建可预测和可重复的测试。

我们将在 Delinkcious 中演示所有这些类型的测试。特别是，我们将专注于使用 Kubernetes 进行本地测试。然后，我们将讨论隔离这个重要问题，它允许我们在不影响生产环境的情况下运行端到端测试。最后，我们将看到如何处理数据密集型测试。

本章将涵盖以下主题：

+   单元测试

+   集成测试

+   使用 Kubernetes 进行本地测试

+   隔离

+   端到端测试

+   管理测试数据

# 技术要求

代码分布在两个 Git 存储库之间：

+   您可以在这里找到代码示例：[`github.com/PacktPublishing/Hands-On-Microservices-with-Kubernetes/tree/master/Chapter10`](https://github.com/PacktPublishing/Hands-On-Microservices-with-Kubernetes/tree/master/Chapter10)

+   您可以在这里找到更新后的 Delinkcious 应用程序：[`github.com/the-gigi/delinkcious/releases/tag/v0.8`](https://github.com/the-gigi/delinkcious/releases/tag/v0.8)

# 单元测试

单元测试是最容易融入代码库的测试类型，但它带来了很多价值。当我说它是最容易的时候，我认为你可以使用最佳实践，比如适当的抽象、关注点分离、依赖注入等等。试图测试一个意大利面代码库并不容易！

让我们简要谈谈 Go 中的单元测试、Ginkgo 测试框架，然后回顾一些 Delinkcious 中的单元测试。

# 使用 Go 进行单元测试

Go 是一种现代语言，认识到测试的重要性。Go 鼓励对于每个`foo.go`文件，都有一个`foo_test.go`。它还提供了 testing 包，Go 工具有一个`test`命令。让我们看一个简单的例子。这是一个包含`safeDivide()`函数的`foo.go`文件。这个函数用于整数除法，并返回一个结果和一个错误。

如果分母非零，则不返回错误，但如果分母为零，则返回“除以零”错误：

```
package main

 import "errors"

 func safeDivide(a int, b int) (int, error) {
         if b == 0 {
                 return 0, errors.New("division by zero")
         }

         return a / b, nil
 }
```

请注意，当两个操作数都是整数时，Go 除法使用整数除法。这样做是为了确保两个整数相除的结果始终是整数部分（小数部分被舍弃）。例如，6/4 返回 1。

这是一个名为`foo_test.go`的 Go 单元测试文件，测试了非零和零分母，并使用了`testing`包。每个`test`函数接受一个指向`testing.T`对象的指针。当测试失败时，它调用`T`对象的`Errorf()`方法：

```
package main

 import (
         "testing"
 )

func TestExactResult(t *testing.T) {
        result, err := safeDivide(8, 4)
        if err != nil {
                t.Errorf("8 / 4 expected 2,  got error %v", err)
        }

        if result != 2 {
         t.Errorf("8 / 4 expected 2,  got %d", result)
        }
} 

func TestIntDivision(t *testing.T) {
        result, err := safeDivide(14, 5)
        if err != nil {
                t.Errorf("14 / 5 expected 2,  got error %v", err)
        }

        if result != 2 {
                   t.Errorf("14 / 5 expected 2,  got %d", result)
        }
}

func TestDivideByZero(t *testing.T) {
        result, err := safeDivide(77, 0)
        if err == nil {
                t.Errorf("77 / 0 expected 'division by zero' error,  got result %d", result)
        }

       if err.Error() != "division by zero" {
               t.Errorf("77 / 0 expected 'division by zero' error,  got this error instead %v", err)
       }
}
```

现在，要运行测试，我们可以使用`go test -v`命令。这是标准 Go 工具的一部分：

```
$ go test -v
=== RUN   TestExactResult
--- PASS: TestExactResult (0.00s)
=== RUN   TestIntDivision
--- PASS: TestIntDivision (0.00s)
=== RUN   TestDivideByZero
--- PASS: TestDivideByZero (0.00s)
PASS
ok      github.com/the-gigi/hands-on-microservices-with-kubernetes-code/ch10    0.010s
```

很好 - 所有测试都通过了。我们还可以看到测试运行花了多长时间。让我们引入一个有意的错误。现在，`safeDivide`减去了，而不是除以：

```
package main

 import "errors"

 func safeDivide(a int, b int) (int, error) {
         if b == 0 {
                 return 0, errors.New("division by zero")
         }

         return a - b, nil
}
```

我们只期望通过零除测试：

```
$ go test -v
=== RUN   TestExactResult
--- FAIL: TestExactResult (0.00s)
 foo_test.go:14: 8 / 4 expected 2,  got 4
=== RUN   TestIntDivision
--- FAIL: TestIntDivision (0.00s)
 foo_test.go:25: 14 / 5 expected 2,  got 9
=== RUN   TestDivideByZero
--- PASS: TestDivideByZero (0.00s)
FAIL
exit status 1
FAIL    github.com/the-gigi/hands-on-microservices-with-kubernetes-code/ch10    0.009s
```

我们得到了我们预期的结果。

`testing`包还有很多内容。`T`对象有其他方法可以使用。它提供了基准测试和常见设置的设施。然而，总的来说，由于测试包的人体工程学，最好不要在`T`对象上调用方法。在没有额外的工具支持的情况下，使用`testing`包管理复杂和分层的测试集也可能会很困难。这正是 Ginkgo 出现的地方。让我们来了解一下 Ginkgo。Delinkcious 使用 Ginkgo 进行单元测试。

# 使用 Ginkgo 和 Gomega 进行单元测试

Ginkgo（[`github.com/onsi/ginkgo`](https://github.com/onsi/ginkgo)）是一个**行为驱动开发**（**BDD**）测试框架。它仍然在底层使用测试包，但允许您使用更好的语法编写测试。它还与 Gomega（[`github.com/onsi/gomega`](https://github.com/onsi/gomega)）很搭配，后者是一个出色的断言库。使用 Ginkgo 和 Gomega 可以获得以下功能：

+   编写 BDD 风格的测试

+   任意嵌套块（`Describe`，`Context`，`When`）

+   良好的设置/拆卸支持（`BeforeEach`，`AfterEach`，`BeforeSuite`，`AfterSuite`）

+   仅关注一个测试或通过正则表达式匹配

+   通过正则表达式跳过测试

+   并行性

+   与覆盖率和基准测试的集成

让我们看看 Delinkcious 如何在其单元测试中使用 Ginkgo 和 Gomega。

# Delinkcious 单元测试

我们将使用`link_manager`包中的`LinkManager`作为示例。它具有非常复杂的交互：它允许您管理数据存储，访问另一个微服务（社交图服务），触发无服务器函数（链接检查器）并响应链接检查事件。这听起来是一组非常多样化的依赖关系，但正如您将看到的，通过设计可测试性，可以在不太复杂的情况下实现高水平的测试。

# 设计可测试性

适当的测试开始于编写测试之前很长时间。即使您实践**测试驱动设计**（**TDD**）并在实现之前编写测试，您仍然需要在编写测试之前设计要测试的代码的接口（否则测试将调用哪些函数或方法？）。对于 Delinkcious，我们采用了非常有意识的方法，包括抽象、层和关注点分离。我们所有的辛勤工作现在将会得到回报。

让我们看看`LinkManager`，并只考虑它的依赖关系：

```
package link_manager

 import (
     "bytes"
     "encoding/json"
     "errors"
     "github.com/the-gigi/delinkcious/pkg/link_checker_events"
     om "github.com/the-gigi/delinkcious/pkg/object_model"
     "log"
     "net/http"
 )
```

正如您所看到的，`LinkManager`依赖于 Delinkcious 对象模型抽象包，`link_checker_events`和标准的 Go 包。`LinkManager`不依赖于任何其他 Delinkcious 组件的实现或任何第三方依赖。在测试期间，我们可以为所有依赖项提供替代（模拟）实现，并完全控制测试环境和结果。我们将在下一节中看到如何做到这一点。

# 模拟的艺术

理想情况下，对象在创建时应注入所有依赖项。让我们看看`NewLinkManager()`函数：

```
func NewLinkManager(linkStore LinkStore,
     socialGraphManager om.SocialGraphManager,
     natsUrl string,
     eventSink om.LinkManagerEvents,
     maxLinksPerUser int64) (om.LinkManager, error) {
     ...
 }
```

这几乎是理想的情况。我们得到了链接存储、社交图管理器和事件接收器的接口。然而，这里有两个未注入的依赖项：`link_checker_events`和内置的`net/http`包。让我们从模拟链接存储、社交图管理器和链接管理器事件接收器开始，然后考虑更困难的情况。

`LinkStore`是在内部定义的一个接口：

```
package link_manager

 import (
     om "github.com/the-gigi/delinkcious/pkg/object_model"
 )

 type LinkStore interface {
     GetLinks(request om.GetLinksRequest) (om.GetLinksResult, error)
     AddLink(request om.AddLinkRequest) (*om.Link, error)
     UpdateLink(request om.UpdateLinkRequest) (*om.Link, error)
     DeleteLink(username string, url string) error
     SetLinkStatus(username, url string, status om.LinkStatus) error
 }
```

在`pkg/link_manager/mock_social_graph_manager.go`文件中，我们可以找到一个模拟社交图管理器，它实现了`om.SocialGraphManager`并且总是从`newMockSocialGraphManager()`函数中提供的关注者中返回`GetFollowers()`方法。这是重用相同的模拟来进行不同测试的一个很好的方法，这些测试需要`GetFollowers()`不同的预定义响应。其他方法只返回 nil 的原因是它们不被`LinkManager`调用，所以不需要提供实际的响应：

```
package link_manager
type mockSocialGraphManager struct { followers map[string]bool }

func (m *mockSocialGraphManager) Follow(followed string, follower string) error { return nil }

func (m *mockSocialGraphManager) Unfollow(followed string, follower string) error { return nil }

func (m *mockSocialGraphManager) GetFollowing(username string) (map[string]bool, error) { return nil, nil }

func (m *mockSocialGraphManager) GetFollowers(username string) (map[string]bool, error) { return m.followers, nil }

func newMockSocialGraphManager(followers []string) *mockSocialGraphManager { m := &mockSocialGraphManager{ map[string]bool{}, } for _, f := range followers { m.followers[f] = true }

return m

}
```

事件接收器有点不同。我们有兴趣验证当调用各种操作，比如`AddLink()`时，`LinkManager`是否正确通知了事件接收器。为了做到这一点，我们可以创建一个测试事件接收器，它实现了`om.LinkManagerEvents`接口，并跟踪接收到的事件。这是在`pkg/link_manager/test_event_sink.go`文件中的代码。`testEventSink`结构体为每种事件类型保留了一个映射，其中键是用户名，值是链接列表。它根据各种事件更新这些映射：

```
package link_manager

import ( om "github.com/the-gigi/delinkcious/pkg/object_model" )

type testEventsSink struct { addLinkEvents map[string][]om.Link updateLinkEvents map[string][]om.Link deletedLinkEvents map[string][]string }

func (s testEventsSink) OnLinkAdded(username string, link om.Link) { if s.addLinkEvents[username] == nil { s.addLinkEvents[username] = []*om.Link{} } s.addLinkEvents[username] = append(s.addLinkEvents[username], link) }

func (s testEventsSink) OnLinkUpdated(username string, link om.Link) { if s.updateLinkEvents[username] == nil { s.updateLinkEvents[username] = []*om.Link{} } s.updateLinkEvents[username] = append(s.updateLinkEvents[username], link) }

func (s *testEventsSink) OnLinkDeleted(username string, url string) { if s.deletedLinkEvents[username] == nil { s.deletedLinkEvents[username] = []string{} } s.deletedLinkEvents[username] = append(s.deletedLinkEvents[username], url) }

func newLinkManagerEventsSink() testEventsSink { return &testEventsSink{ map[string][]om.Link{}, map[string][]*om.Link{}, map[string][]string{}, } }
```

现在我们已经准备好了模拟，让我们创建 Ginkgo 测试套件。

# 启动测试套件

Ginkgo 是建立在 Go 的测试包之上的，这很方便，因为你可以只用`go test`来运行你的 Ginkgo 测试，尽管 Ginkgo 还提供了一个名为 Ginkgo 的 CLI，提供了更多的选项。要为一个包启动一个测试套件，运行`ginkgo bootstrap`命令。它将生成一个名为`<package>_suite_test.go`的文件。该文件将所有的 Ginkgo 测试连接到标准的 Go 测试，并导入`ginkgo`和`gomega`包。这是`link_manager`包的测试套件文件：

```
package link_manager
import ( "testing"
. "github.com/onsi/ginkgo"
. "github.com/onsi/gomega"
)
func TestLinkManager(t *testing.T) { RegisterFailHandler(Fail) RunSpecs(t, "LinkManager Suite") }
```

有了测试套件文件，我们可以开始编写一些单元测试。

# 实现 LinkManager 单元测试

让我们看看获取和添加链接的测试。那里有很多事情要做。这都在`pkg/link_manager/in_memory_link_manager_test.go`文件中。首先，让我们通过导入`ginkgo`，`gomega`和`delinkcious`对象模型来设置场景：

```
package link_manager
import ( . "github.com/onsi/ginkgo" . "github.com/onsi/gomega" om "github.com/the-gigi/delinkcious/pkg/object_model" )
```

Ginkgo 的`Describe`块描述文件中的所有测试，并定义将被多个测试使用的变量：

```
var _ = Describe("In-memory link manager tests", func() { var err error var linkManager om.LinkManager var socialGraphManager mockSocialGraphManager var eventSink testEventsSink
```

`BeforeEach()`函数在每个测试之前调用。它使用`liat`作为唯一的关注者创建一个新的模拟社交图管理器，一个新的事件接收器，并使用这些依赖项初始化新的`LinkManager`，以及一个内存链接存储，从而利用依赖注入实践：

```
BeforeEach(func() {
     socialGraphManager = newMockSocialGraphManager([]string{"liat"})
     eventSink = newLinkManagerEventsSink()
     linkManager, err = NewLinkManager(NewInMemoryLinkStore(),
         socialGraphManager,
         "",
         eventSink,
         10)
     Ω(err).Should(BeNil())
 })
```

这是实际的测试。注意以 BDD 风格定义测试，读起来像英语，*应该添加并获取链接*。让我们一步一步地分解；首先，测试确保`"gigi"`用户没有现有链接，通过调用`GetLinks()`并断言结果为空，使用 Gomega 的`Ω`运算符：

```
It("should add and get links", func() {
     // No links initially
     r := om.GetLinksRequest{
         Username: "gigi",
     }
     res, err := linkManager.GetLinks(r)
     Ω(err).Should(BeNil())
     Ω(res.Links).Should(HaveLen(0))
```

接下来是关于添加链接并确保没有错误发生的部分：

```
    // Add a link
     r2 := om.AddLinkRequest{
         Username: "gigi",
         Url:      "https://golang.org/",
         Title:    "Golang",
         Tags:     map[string]bool{"programming": true},
     }
     err = linkManager.AddLink(r2)
     Ω(err).Should(BeNil())
```

现在，测试调用`GetLinks()`并期望刚刚添加的链接被返回：

```
    res, err = linkManager.GetLinks(r)
     Ω(err).Should(BeNil())
     Ω(res.Links).Should(HaveLen(1))
     link := res.Links[0]
     Ω(link.Url).Should(Equal(r2.Url))
     Ω(link.Title).Should(Equal(r2.Title))
```

最后，测试确保事件接收器记录了`follower "liat"`的`OnLinkAdded()`调用：

```
    // Verify link manager notified the event sink about a single added event for the follower "liat"
     Ω(eventSink.addLinkEvents).Should(HaveLen(1))
     Ω(eventSink.addLinkEvents["liat"]).Should(HaveLen(1))
     Ω(*eventSink.addLinkEvents["liat"][0]).Should(Equal(link))
     Ω(eventSink.updateLinkEvents).Should(HaveLen(0))
     Ω(eventSink.deletedLinkEvents).Should(HaveLen(0))
 })
```

这是一个非常典型的单元测试，执行以下任务：

+   控制测试环境

+   模拟依赖项（社交图管理器）

+   为外部交互提供记录占位符（测试事件接收器记录链接管理器事件）

+   执行被测试的代码（获取链接和添加链接）

+   验证响应（一开始没有链接；添加后返回一个链接）

+   验证任何外部交互（事件接收器接收到`OnLinkAdded()`事件）

我们这里没有测试错误情况，但很容易添加。您可以添加错误输入并检查返回预期错误的测试代码。

# 你应该测试所有吗？

答案是否定的！测试提供了很多价值，但也有成本。添加测试的边际价值正在减少。测试*所有*是困难的，甚至是不可能的。考虑到测试需要时间来开发，它可能会减慢对系统的更改（您需要更新测试），并且当依赖关系发生变化时，测试可能需要更改。测试还需要时间和资源来运行，这可能会减慢编辑-测试-部署周期。此外，测试也可能存在错误。找到您需要进行多少测试的平衡点是一个判断性的决定。

单元测试非常有价值，但还不够。这对于基于微服务的架构尤其如此，因为有很多小组件可能可以独立工作，但无法一起实现系统的目标。这就是集成测试的用武之地。

# 集成测试

集成测试是包括多个相互交互的组件的测试。集成测试意味着在没有或者很少模拟的情况下测试完整的子系统。Delinkcious 有几个针对特定服务的集成测试。这些测试不是自动化的 Go 测试。它们不使用 Ginkgo 或标准的 Go 测试。它们是在出现错误时会 panic 的可执行程序。这些程序旨在测试跨服务的交互以及服务如何与实际数据存储等第三方组件集成。例如，`link_manager_e2e`测试执行以下步骤：

1.  启动社交图服务和链接服务作为本地进程

1.  在 Docker 容器中启动一个 Postgres 数据库

1.  对链接服务运行测试

1.  验证结果

让我们看看它是如何发挥作用的。导入列表包括 Postgres Golang 驱动程序（`lib/pq`），几个 Delinkcious 包，以及一些标准的 Go 包（`context`，`log`和`os`）。请注意，`pq`被导入为破折号。这意味着`pq`名称不可用。以这种未命名模式导入库的原因是它只需要运行一些初始化代码，不会被外部访问。具体来说，`pq`向标准的 Go `database/sql`库注册了一个 Go 驱动程序：

```
package main
import ( "context" _ "github.com/lib/pq" "github.com/the-gigi/delinkcious/pkg/db_util" "github.com/the-gigi/delinkcious/pkg/link_manager_client" om "github.com/the-gigi/delinkcious/pkg/object_model" . "github.com/the-gigi/delinkcious/pkg/test_util" "log" "os" )
```

让我们来看一些用于设置测试环境的函数，首先是初始化数据库。

# 初始化测试数据库

`initDB()`函数通过传递数据库名称（`link_manager`）调用`RunLocalDB()`函数。这很重要，因为如果你是从头开始的，它也需要创建数据库。然后，为了确保测试总是从头开始运行，它删除`tags`和`links`表，如下所示：

```
func initDB() { db, err := db_util.RunLocalDB("link_manager") Check(err)
tables := []string{"tags", "links"}
 for _, table := range tables {
     err = db_util.DeleteFromTableIfExist(db, table)
     Check(err)
 }
}
```

# 运行服务

测试有两个单独的函数来运行服务。这些函数非常相似。它们设置环境变量并调用`RunService()`函数，我们很快就会深入了解。两个服务都依赖于`PORT`环境变量的值，并且每个服务的值都需要不同。这意味着我们必须按顺序启动服务，而不是并行启动。否则，服务可能最终会监听错误的端口：

```
func runLinkService(ctx context.Context) {
     // Set environment
     err := os.Setenv("PORT", "8080")
     Check(err)

     err = os.Setenv("MAX_LINKS_PER_USER", "10")
     Check(err)

     RunService(ctx, ".", "link_service")
 }

 func runSocialGraphService(ctx context.Context) {
     err := os.Setenv("PORT", "9090")
     Check(err)

     RunService(ctx, "../social_graph_service", "social_graph_service")
 }
```

# 运行实际测试

`main()`函数是整个测试的驱动程序。它打开了链接管理器和社交图管理器之间的相互认证，初始化数据库，并运行服务（只要`RUN_XXX_SERVICE`环境变量为`true`）：

```
func main() {
     // Turn on authentication
     err := os.Setenv("DELINKCIOUS_MUTUAL_AUTH", "true")
     Check(err)

     initDB()

     ctx := context.Background()
     defer KillServer(ctx)

     if os.Getenv("RUN_SOCIAL_GRAPH_SERVICE") == "true" {
         runSocialGraphService(ctx)
     }

     if os.Getenv("RUN_LINK_SERVICE") == "true" {
         runLinkService(ctx)
     }
```

现在它已经准备好实际运行测试了。它使用链接管理器客户端连接到本地主机上的端口`8080`，这是链接服务正在运行的地方。然后，它调用`GetLinks()`方法，打印结果（应该为空），通过调用`AddLink()`添加一个链接，再次调用`GetLinks()`，并打印结果（应该是一个链接）：

```
// Run some tests with the client
     cli, err := link_manager_client.NewClient("localhost:8080")
     Check(err)

     links, err := cli.GetLinks(om.GetLinksRequest{Username: "gigi"})
     Check(err)
     log.Print("gigi's links:", links)

     err = cli.AddLink(om.AddLinkRequest{Username: "gigi",
         Url:   "https://github.com/the-gigi",
         Title: "Gigi on Github",
         Tags:  map[string]bool{"programming": true}})
     Check(err)

     links, err = cli.GetLinks(om.GetLinksRequest{Username: "gigi"})
     Check(err)
     log.Print("gigi's links:", links)
```

这个集成测试不是自动化的。它是为了交互式使用而设计的，开发人员可以运行和调试单个服务。如果发生错误，它会立即退出。每个操作的结果只是简单地打印到屏幕上。

测试的其余部分检查了`UpdateLink()`和`DeleteLink()`操作：

```
    err = cli.UpdateLink(om.UpdateLinkRequest{Username: "gigi",
         Url:         "https://github.com/the-gigi",
         Description: "Most of my open source code is here"},
     )

     Check(err)
     links, err = cli.GetLinks(om.GetLinksRequest{Username: "gigi"})
     Check(err)
     log.Print("gigi's links:", links)

     err = cli.DeleteLink("gigi", "https://github.com/the-gigi")
     Check(err)
     Check(err)
     links, err = cli.GetLinks(om.GetLinksRequest{Username: "gigi"})
     Check(err)
     log.Print("gigi's links:", links)
 }
```

通过链接管理器客户端库进行测试确保了从客户端到服务到依赖服务及其数据存储的整个链条都在工作。

让我们来看一些测试助手函数，当我们试图在本地测试和调试微服务之间的复杂交互时，它们非常有用。

# 实现数据库测试助手

在深入代码之前，让我们考虑一下我们想要实现的目标。我们希望创建一个本地空数据库。我们希望将其作为 Docker 容器启动，但只有在它尚未运行时才这样做。为了做到这一点，我们需要检查 Docker 容器是否已经在运行，如果我们应该重新启动它，或者我们应该运行一个新的容器。然后，我们将尝试连接到目标数据库，并在不存在时创建它。服务将负责根据需要创建模式，因为通用的 DB 实用程序对特定服务的数据库模式一无所知。

`db_util`包中的`db_util.go`文件包含所有辅助函数。首先，让我们回顾一下导入的内容，其中包括标准的 Go `database/sql`包和 squirrel - 一个流畅风格的 Go 库，用于生成 SQL（但不是 ORM）。还导入了 Postgres 驱动程序库`pq`：

```
package db_util

 import (
     "database/sql"
     "fmt"
     sq "github.com/Masterminds/squirrel"
     _ "github.com/lib/pq"
     "log"
     "os"
     "os/exec"
     "strconv"
     "strings"
 )
```

`dbParams`结构包含连接到数据库所需的信息，`defaultDbParams()`函数方便地获取填充有默认值的结构：

```
type dbParams struct {
     Host     string
     Port     int
     User     string
     Password string
     DbName   string
 }

 func defaultDbParams() dbParams {
     return dbParams{
         Host:     "localhost",
         Port:     5432,
         User:     "postgres",
         Password: "postgres",
     }
 }
```

您可以通过传递`dbParams`结构中的信息来调用`connectToDB()`函数。如果一切顺利，您将得到一个数据库句柄（`*sql.DB`），然后可以使用它来以后访问数据库：

```
func connectToDB(host string, port int, username string, password string, dbName string) (db *sql.DB, err error) {
     mask := "host=%s port=%d user=%s password=%s dbname=%s sslmode=disable"
     dcn := fmt.Sprintf(mask, host, port, username, password, dbName)
     db, err = sql.Open("postgres", dcn)
     return
 }
```

完成所有准备工作后，让我们看看`RunLocalDB()`函数是如何工作的。首先，它运行`docker ps -f name=postgres`命令，列出名为`postgres`的正在运行的 Docker 容器（只能有一个）：

```
func RunLocalDB(dbName string) (db *sql.DB, err error) {
     // Launch the DB if not running
     out, err := exec.Command("docker", "ps", "-f", "name=postgres", "--format", "{{.Names}}").CombinedOutput()
     if err != nil {
         return
     }
```

如果输出为空，这意味着没有正在运行的容器，因此它会尝试重新启动容器，以防它已经停止。如果这也失败了，它就会运行一个新的`postgres:alpine`镜像的容器，将标准的`5432`端口暴露给本地主机。注意`-z`标志。它告诉 Docker 以分离（非阻塞）模式运行容器，这允许函数继续。如果由于任何原因无法运行新容器，它会放弃并返回错误：

```
    s := string(out)
     if s == "" {
         out, err = exec.Command("docker", "restart", "postgres").CombinedOutput()
         if err != nil {
             log.Print(string(out))
             _, err = exec.Command("docker", "run", "-d", "--name", "postgres",
                 "-p", "5432:5432",
                 "-e", "POSTGRES_PASSWORD=postgres",
                 "postgres:alpine").CombinedOutput()

         }
         if err != nil {
             return
         }
     }
```

此时，我们正在运行一个在容器中运行的 Postgres DB。我们可以使用`defaultDBParams()`函数并调用`EnsureDB()`函数，接下来我们将对其进行检查：

```
p := defaultDbParams()
 db, err = EnsureDB(p.Host, p.Port, p.User, p.Password, dbName)
 return
}
```

为了确保数据库已准备就绪，我们需要连接到 postgres 实例的 Postgres DB。每个 postgres 实例都有几个内置数据库，包括`postgres`数据库。postgres 实例的 Postgres DB 可用于获取有关实例的信息和元数据。特别是，我们可以查询`pg_database`表以检查目标数据库是否存在。如果不存在，我们可以通过执行`CREATE database <db name>`命令来创建它。最后，我们连接到目标数据库并返回其句柄。通常情况下，如果出现任何问题，我们会返回错误：

```
// Make sure the database exists (creates it if it doesn't)

func EnsureDB(host string, port int, username string, password string, dbName string) (db *sql.DB, err error) { // Connect to the postgres DB postgresDb, err := connectToDB(host, port, username, password, "postgres") if err != nil { return }

// Check if the DB exists in the list of databases
 var count int
 sb := sq.StatementBuilder.PlaceholderFormat(sq.Dollar)
 q := sb.Select("count(*)").From("pg_database").Where(sq.Eq{"datname": dbName})
 err = q.RunWith(postgresDb).QueryRow().Scan(&count)
 if err != nil {
     return
 }

 // If it doesn't exist create it
 if count == 0 {
     _, err = postgresDb.Exec("CREATE database " + dbName)
     if err != nil {
         return
     }
 }

 db, err = connectToDB(host, port, username, password, dbName)
 return
}
```

这是一个深入研究自动设置本地测试数据库的过程。在许多情况下，甚至超出微服务范围，这非常方便。

# 实施服务测试助手

让我们看一些测试服务的辅助函数。`test_util`包非常基础，使用 Go 标准包作为依赖项：

```
package test_util

import ( "context" "os" "os/exec" )
```

它提供了一个错误检查函数和两个运行和停止服务的函数。

# 检查错误

关于 Go 的一个让人讨厌的事情是你必须一直进行显式的错误检查。以下片段非常常见；我们调用一个返回结果和错误的函数，检查错误，如果它不是 nil，我们就做一些事情（通常我们只是返回）：

```
...
 result, err := foo()
 if err != nil {
     return err
 }
...
```

`Check()`函数通过决定它将仅仅恐慌并退出程序（或当前的 Go 例程）使得这一点更加简洁。这在测试场景中是一个可以接受的选择，因为你希望一旦遇到任何故障就退出：

```
func Check(err error) { if err != nil { panic(err) } }
```

前面的片段可以缩短为以下内容：

```
...
 result, err := foo()
 Check(err)
...
```

如果您的代码需要检查许多错误，那么这些小的节省会累积起来。

# 在本地运行服务

最重要的辅助函数之一是`RunService()`。微服务通常依赖于其他微服务。在测试服务时，测试代码通常需要运行依赖的服务。在这里，代码在其`target`目录中构建一个 Go 服务并执行它：

```
// Build and run a service in a target directory
func RunService(ctx context.Context, targetDir string, service string) {
   // Save and restore later current working dir
   wd, err := os.Getwd()
   Check(err)
   defer os.Chdir(wd)

   // Build the server if needed
   os.Chdir(targetDir)
   _, err = os.Stat("./" + service)
   if os.IsNotExist(err) {
      _, err := exec.Command("go", "build", ".").CombinedOutput()
      Check(err)
   }

   cmd := exec.CommandContext(ctx, "./"+service)
   err = cmd.Start()
   Check(err)
}
```

运行服务很重要，但在测试结束时清理并停止所有由测试启动的服务也很重要。

# 停止本地服务

停止服务就像调用上下文的`Done()`方法一样简单。它可以用来向使用上下文的任何代码发出完成信号：

```
func StopService(ctx context.Context) { ctx.Done() }
```

正如您所看到的，运行 Delinkcious，甚至只是在没有 Kubernetes 帮助的情况下本地运行 Delinkcious 的一些部分，都涉及大量的工作。当 Delinkcious 运行时，它非常适用于调试和故障排除，但创建和维护这个设置是乏味且容易出错的。

此外，即使所有集成测试都能正常工作，它们也无法完全复制 Kubernetes 集群，可能会有许多未被捕获的故障模式。让我们看看如何使用 Kubernetes 本身进行本地测试。

# 使用 Kubernetes 进行本地测试

Kubernetes 的一个特点是同一个集群可以在任何地方运行。对于真实世界的系统来说，如果您使用的服务在本地不可用，或者访问本地的速度太慢或者太昂贵，那么情况就不总是那么简单。关键是要在高保真度和便利性之间找到一个好的平衡点。

让我们编写一个烟雾测试，让 Delinkcious 通过获取链接、添加链接和检查它们的状态的主要工作流程。

# 编写烟雾测试

Delinkcious 烟雾测试不是自动化的。它可以是，但需要特殊的设置才能在 CI/CD 环境中运行。对于真实的生产系统，我强烈建议您进行自动化的烟雾测试（以及其他测试）。

代码位于`cmd/smoke_test`目录中，由一个名为`smoke.go`的文件组成。它通过 API 网关公开的 REST API 对 Delinkcious 进行测试。我们可以使用任何语言编写这个测试，因为没有客户端库。我选择使用 Go 是为了保持一致性，并突出如何从 Go 中消费原始的 REST API，直接使用 URL、查询字符串和 JSON 负载序列化。我还使用了 Delinkcious 对象模型链接作为方便的序列化目标。

测试期望本地 Minikube 集群中已安装并运行 Delinkcious。以下是测试的流程：

1.  删除我们的测试链接以重新开始。

1.  获取链接（并打印它们）。

1.  添加一个测试链接。

1.  再次获取链接（新链接应该具有*待定*状态）。

1.  等待几秒钟。

1.  再次获取链接（新链接现在应该具有*有效*状态）。

这个简单的烟雾测试涵盖了 Delinkcious 功能的重要部分，例如以下内容：

+   命中 API 网关的多个端点（获取链接、发布新链接、删除链接）。

+   验证调用者身份（通过访问令牌）。

+   API 网关将转发请求到链接管理器服务。

+   链接管理器服务将触发链接检查器无服务器函数。

+   链接检查器将通过 NATS 通知链接管理器新链接的状态。

以后，我们可以扩展测试以创建社交关系，这将涉及社交图管理器，以及检查新闻服务。这将建立一个全面的端到端测试。对于烟雾测试目的，上述工作流程就足够了。

让我们从导入列表开始，其中包括许多标准的 Go 库，以及 Delinkcious 的`object_model`（用于`Link`结构）包和`test_util`包（用于`Check()`函数）。我们可以很容易地避免这些依赖关系，但它们是熟悉和方便的：

```
package main

import ( "encoding/json" "errors" "fmt" om "github.com/the-gigi/delinkcious/pkg/object_model" . "github.com/the-gigi/delinkcious/pkg/test_util" "io/ioutil" "log" "net/http" net_url "net/url" "os" "os/exec" "time" )
```

接下来的部分定义了一些变量。`delinkciousUrl`稍后将被初始化。`delinkciousToken`应该在环境中可用，`httpClient`是我们将用于调用 Delinkcious REST API 的标准 Go HTTP 客户端：

```
var ( delinkciousUrl string delinkciousToken = os.Getenv("DELINKCIOUS_TOKEN") httpClient = http.Client{} )
```

完成前提工作后，我们可以专注于测试本身。它非常简单，看起来非常像冒烟测试的高级描述。它使用以下命令从 Minikube 获取 Delinkcious URL：

```
$ minikube service api-gateway --url http://192.168.99.161:30866
```

然后，它调用`DeleteLink()`、`GetLinks()`和`AddLink()`函数，如下所示：

```
func main() { tempUrl, err := exec.Command("minikube", "service", "api-gateway", "--url").CombinedOutput() delinkciousUrl = string(tempUrl[:len(tempUrl)-1]) + "/v1.0" Check(err)

// Delete link
 deleteLink("https://github.com/the-gigi")

 // Get links
 getLinks()

 // Add a new link
 addLink("https://github.com/the-gigi", "Gigi on Github")

 // Get links again
 getLinks()

 // Wait a little and get links again
 time.Sleep(time.Second * 3)
 getLinks()

}
```

`GetLinks()`函数构造正确的 URL，创建一个新的 HTTP 请求，将身份验证令牌作为标头添加（根据 API 网关社交登录身份验证的要求），并命中`/links`端点。当响应返回时，它检查状态码，并在出现错误时退出。否则，它将响应的主体反序列化为`om.GetLinksResult`结构，并打印链接：

```
func getLinks() { req, err := http.NewRequest("GET", string(delinkciousUrl)+"/links", nil) Check(err)

req.Header.Add("Access-Token", delinkciousToken)
 r, err := httpClient.Do(req)
 Check(err)

 defer r.Body.Close()

 if r.StatusCode != http.StatusOK {
     Check(errors.New(r.Status))
 }

 var glr om.GetLinksResult
 body, err := ioutil.ReadAll(r.Body)

 err = json.Unmarshal(body, &glr)
 Check(err)

 log.Println("======= Links =======")
 for _, link := range glr.Links {
     log.Println(fmt.Sprintf("title: '%s', url: '%s', status: '%s'", link.Title, link.Url, link.Status))
 }

}
```

`addLink()`函数非常相似，只是它使用 POST 方法，并且只检查响应是否具有 OK 状态。该函数接受一个 URL 和一个标题，并构造一个 URL（包括对查询字符串进行编码）以符合 API 网关规范。如果状态不是 OK，它将使用响应的内容作为错误消息：

```
func addLink(url string, title string) { params := net_url.Values{} params.Add("url", url) params.Add("title", title) qs := params.Encode()

log.Println("===== Add Link ======")
 log.Println(fmt.Sprintf("Adding new link - title: '%s', url: '%s'", title, url))

 url = fmt.Sprintf("%s/links?%s", delinkciousUrl, qs)
 req, err := http.NewRequest("POST", url, nil)
 Check(err)

 req.Header.Add("Access-Token", delinkciousToken)
 r, err := httpClient.Do(req)
 Check(err)
 if r.StatusCode != http.StatusOK {
     defer r.Body.Close()
     bodyBytes, err := ioutil.ReadAll(r.Body)
     Check(err)
     message := r.Status + " " + string(bodyBytes)
     Check(errors.New(message))
 }

}
```

太好了！现在，让我们看看测试是如何运行的。

# 运行测试

在运行测试之前，我们应该导出`DELINKCIOUS_TOKEN`并确保 Minikube 正在运行：

```
$ minikube status host: Running kubelet: Running apiserver: Running kubectl: Correctly Configured: pointing to minikube-vm at 192.168.99.160
```

要运行测试，我们只需输入以下内容：

```
$ go run smoke.go
```

结果将打印到控制台。已经有一个无效的链接，即`http://gg.com`。然后，测试添加了新链接，即`https://github.com/the-gigi`。新链接的状态最初是挂起的，然后在几秒钟后，当链接检查成功时，它变为有效：

```
2019/04/19 10:03:48 ======= Links ======= 2019/04/19 10:03:48 title: 'gg', url: 'http://gg.com', status: 'invalid' 2019/04/19 10:03:48 ===== Add Link ====== 2019/04/19 10:03:48 Adding new link - title: 'Gigi on Github', url: 'https://github.com/the-gigi' 2019/04/19 10:03:49 ======= Links ======= 2019/04/19 10:03:49 title: 'gg', url: 'http://gg.com', status: 'invalid' 2019/04/19 10:03:49 title: 'Gigi on Github', url: 'https://github.com/the-gigi', status: 'pending' 2019/04/19 10:03:52 ======= Links ======= 2019/04/19 10:03:52 title: 'gg', url: 'http://gg.com', status: 'invalid' 2019/04/19 10:03:52 title: 'Gigi on Github', url: 'https://github.com/the-gigi', status: 'valid'
```

# Telepresence

Telepresence ([`www.telepresence.io/`](https://www.telepresence.io/)) 是一个特殊的工具。它允许您在本地运行一个服务，就好像它正在您的 Kubernetes 集群内运行一样。为什么这很有趣？考虑我们刚刚实施的冒烟测试。如果我们检测到失败，我们希望执行以下三件事：

+   找到根本原因。

+   修复它。

+   验证修复是否有效。

由于我们只在 Kubernetes 集群上运行冒烟测试时才发现了故障，这可能是我们的本地单元测试未检测到的故障。找到根本原因的常规方法（除了离线审查代码之外）是添加一堆日志记录语句，添加实验性调试代码，注释掉无关的部分并部署修改后的代码，重新运行冒烟测试，并尝试了解出现了什么问题。

将修改后的代码部署到 Kubernetes 集群通常涉及以下步骤：

1.  修改代码

1.  将修改后的代码推送到 Git 存储库（污染您的 Git 历史记录，因为这些更改仅用于调试）

1.  构建镜像（通常需要运行各种测试）

1.  将新镜像推送到镜像注册表

1.  将新镜像部署到集群

这个过程很繁琐，不鼓励临时探索和快速编辑-调试-修复循环。在第十一章中，我们将探索一些工具，可以跳过推送到 Git 存储库并为您自动构建镜像，但镜像仍然会构建并部署到集群。

使用 Telepresence，您只需在本地对代码进行更改，Telepresence 会确保您的本地服务成为集群的一个完整成员。它看到相同的环境和 Kubernetes 资源，可以通过内部网络与其他服务通信，实际上它是集群的一部分。

Telepresence 通过在集群内安装代理来实现这一点，代理会联系并与您的本地服务进行通信。这非常巧妙。让我们安装 Telepresence 并开始使用它。

# 安装 Telepresence

安装 Telepresence 需要 FUSE 文件系统：

```
brew cask install osxfuse
```

然后，我们可以安装 Telepresence 本身：

```
brew install datawire/blackbird/telepresence
```

# 通过 Telepresence 运行本地链接服务

让我们通过 Telepresence 在本地运行链接管理器服务。首先，为了证明真的是本地服务在运行，我们可以修改服务代码。例如，当获取链接时，我们可以打印一条消息，即`"**** 本地链接服务在这里！调用 GetLinks() ****"`。

让我们将其添加到`svc/link_service/service/transport.go`中的`GetLinks`端点：

```
func makeGetLinksEndpoint(svc om.LinkManager) endpoint.Endpoint { return func(_ context.Context, request interface{}) (interface{}, error) { fmt.Println("**** Local link service here! calling GetLinks() ****") req := request.(om.GetLinksRequest) result, err := svc.GetLinks(req) res := getLinksResponse{} for _, link := range result.Links { res.Links = append(res.Links, newLink(link)) } if err != nil { res.Err = err.Error() return res, err } return res, nil } }
```

现在，我们可以构建本地链接服务（使用 Telepresence 推荐的标志），并将`link-manager`部署与本地服务进行交换：

```
$ cd svc/service/link_service
$ go build -gcflags "all=-N -l" .

$ telepresence --swap-deployment link-manager --run ./link_service
T: How Telepresence uses sudo: https://www.telepresence.io/reference/install#dependencies
T: Invoking sudo. Please enter your sudo password.
Password:
T: Starting proxy with method 'vpn-tcp', which has the following limitations: All processes are affected, only one telepresence can run per machine, and you can't use other VPNs. You may need to add cloud hosts and headless services with --also-proxy.
T: For a full list of method limitations see https://telepresence.io/reference/methods.html
T: Volumes are rooted at $TELEPRESENCE_ROOT. See https://telepresence.io/howto/volumes.html for details.
T: Starting network proxy to cluster by swapping out Deployment link-manager with a proxy
T: Forwarding remote port 8080 to local port 8080.

T: Guessing that Services IP range is 10.96.0.0/12\. Services started after this point will be inaccessible if are outside this range; restart telepresence if you can't access a new Service.
T: Setup complete. Launching your command.
2019/04/20 01:17:06 DB host: 10.100.193.162 DB port: 5432
2019/04/20 01:17:06 Listening on port 8080...
```

请注意，当您为以下任务交换部署时，Telepresence 需要`sudo`权限：

+   修改本地网络（通过`sshuttle`和`pf/iptables`）以用于 Go 程序的`vpn-tcp`方法

+   运行`docker`命令（对于 Linux 上的某些配置）

+   挂载远程文件系统以在 Docker 容器中访问

为了测试我们的新更改，让我们再次运行`smoke`测试：

```
$ go run smoke.go 
2019/04/21 00:18:50 ======= Links ======= 2019/04/21 00:18:50 ===== Add Link ====== 2019/04/21 00:18:50 Adding new link - title: 'Gigi on Github', url: 'https://github.com/the-gigi' 2019/04/21 00:18:50 ======= Links ======= 2019/04/21 00:18:50 title: 'Gigi on Github', url: 'https://github.com/the-gigi', status: 'pending' 2019/04/21 00:18:54 ======= Links ======= 2019/04/21 00:18:54 title: 'Gigi on Github', url: 'https://github.com/the-gigi', status: 'valid'
```

查看我们的本地服务输出，我们可以看到在运行`smoke`测试时确实被调用了：

```
**** Local link service here! calling GetLinks() ****
**** Local link service here! calling GetLinks() ****
```

您可能还记得，smoke 测试会在集群中调用 API 网关，因此我们的本地服务被调用表明它确实在集群中运行。有趣的是，我们本地服务的输出不会被 Kubernetes 日志捕获。如果我们搜索日志，什么也找不到。以下命令不会生成任何输出：

```
$ kubectl logs svc/link-manager | grep "Local link service here" 
```

现在，让我们看看如何将 GoLand 调试器连接到正在运行的本地服务。

# 使用 GoLand 附加到本地链接服务进行实时调试

这是调试的终极目标！我们将使用 GoLand 交互式调试器连接到我们的本地链接服务，同时它作为 Kubernetes 集群的一部分在运行。这再好不过了。让我们开始吧：

1.  首先，按照这里的说明准备好使用 GoLand 附加到本地 Go 进程：[`blog.jetbrains.com/go/2019/02/06/debugging-with-goland-getting-started/#debugging-a-running-application-on-the-local-machine`](https://blog.jetbrains.com/go/2019/02/06/debugging-with-goland-getting-started/#debugging-a-running-application-on-the-local-machine)。

1.  然后，在 GoLand 中点击 Run | Attach to Process 菜单选项，将会出现以下对话框：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-msvc-k8s/img/131918fe-55b0-4ec6-a233-0dd4fd1bfc8a.png)

不幸的是，当 GoLand 成功附加到进程时，Telepresence 错误地认为本地服务已退出，并关闭了到 Kubernetes 集群及其自身控制进程的隧道。

本地链接服务仍在运行，但不再连接到集群。我为 Telepresence 团队打开了一个 GitHub 问题：[`github.com/telepresenceio/telepresence/issues/1003`](https://github.com/telepresenceio/telepresence/issues/1003)。

后来我联系了 Telepresence 开发人员，深入了解了代码，并贡献了最近合并的修复。

请参阅以下 PR（为在 Telepresence 下附加调试器到进程添加支持）：[`github.com/telepresenceio/telepresence/pull/1005`](https://github.com/telepresenceio/telepresence/pull/1005)。

如果您正在使用 VS Code 进行 Go 编程，可以尝试按照这里的信息进行操作：[`github.com/Microsoft/vscode-go/wiki/Debugging-Go-code-using-VS-Code`](https://github.com/Microsoft/vscode-go/wiki/Debugging-Go-code-using-VS-Code)。

到目前为止，我们编写了一个独立的冒烟测试，并使用 Telepresence 来能够在我们的 Kubernetes 集群中本地调试服务。这对于交互式开发来说再好不过了。下一节将处理测试隔离。

# 隔离测试

隔离是测试的一个关键主题。核心思想是，一般来说，您的测试应该与生产环境隔离，甚至与其他共享环境隔离。如果测试不是隔离的，那么测试所做的更改可能会影响这些环境，反之亦然（对这些环境的外部更改可能会破坏假设的测试）。另一种隔离级别是在测试之间。如果您的测试并行运行并对相同的资源进行更改，那么各种竞争条件可能会发生，测试可能会相互干扰并导致错误的负面结果。

如果测试不并行运行，但忽略清理测试 A 可能会导致破坏测试 B 的更改。隔离可以帮助的另一种情况是当多个团队或开发者想要测试不兼容的更改时。如果两个开发者对共享环境进行了不兼容的更改，其中至少一个将遇到失败。隔离有各种级别，它们通常与成本呈反比-更隔离的测试设置成本更高。

让我们考虑以下隔离方法：

+   测试集群

+   测试命名空间

+   跨命名空间/集群

# 测试集群

集群级别的隔离是最高形式的隔离。您可以在完全独立于生产集群的集群中运行测试。这种方法的挑战在于如何保持测试集群/集群与生产集群的同步。在软件方面，通过一个良好的 CI/CD 系统可能并不太困难，但填充和迁移数据通常相当复杂。

测试集群有两种形式：

+   每个开发者都有自己的集群。

+   为执行系统测试而专门设置的集群。

# 每个开发者一个集群

为每个开发人员创建一个集群是最高级别的隔离。开发人员不必担心破坏其他人的代码或受其他人的代码影响。但是，这种方法也有一些显著的缺点，例如：

+   为每个开发人员提供一个成熟的集群通常成本太高。

+   提供的集群通常与生产系统的高保真度不高。

+   通常仍然需要另一个集成环境来协调多个团队/开发人员的更改。

使用 Kubernetes，可能可以将 Minikube 作为每个开发人员的本地集群，并避免许多缺点。

# 系统测试的专用集群

为系统测试创建专用集群是在部署到生产环境之前，整合更改并再次测试的好方法。测试集群可以运行更严格的测试，依赖外部资源，并与第三方服务交互。这样的测试集群是昂贵的资源，您必须仔细管理它们。

# 测试命名空间

测试命名空间是一种轻量级的隔离形式。它们可以与生产系统并行运行，并重用生产环境的一些资源（例如控制平面）。同步数据可能更容易，在 Kubernetes 上，特别是编写自定义控制器来同步和审计测试命名空间与生产命名空间是一个不错的选择。

测试命名空间的缺点是隔离级别降低。默认情况下，不同命名空间中的服务仍然可以相互通信。如果您的系统已经使用多个命名空间，那么您必须非常小心，以保持测试与生产的隔离。

# 编写多租户系统

多租户系统是指完全隔离的实体共享相同的物理或虚拟资源的系统。Kubernetes 命名空间提供了几种机制来支持这一点。您可以定义网络策略，防止命名空间之间的连接（除了与 Kubernetes API 服务器的交互）。您可以定义每个命名空间的资源配额和限制，以防止恶意命名空间占用所有集群资源。如果您的系统已经设置为多租户，您可以将测试命名空间视为另一个租户。

# 跨命名空间/集群

有时，您的系统部署到多个协调的命名空间甚至多个集群中。在这种情况下，您需要更加注意如何设计模拟相同架构的测试，同时要小心测试不要与生产命名空间或集群发生交互。

# 端到端测试

端到端测试对于复杂的分布式系统非常重要。我们为 Delinkcious 编写的冒烟测试就是端到端测试的一个例子，但还有其他几个类别。端到端测试通常针对专用环境运行，比如一个暂存环境，但在某些情况下，它们会直接针对生产环境运行（需要特别注意）。由于端到端测试通常需要很长时间才能运行，并且可能设置起来很慢、费用很高，因此通常不会在每次提交时运行。相反，通常会定期运行（每晚、每个周末或每个月）或临时运行（例如，在重要发布之前）。端到端测试有几个类别。

我们将在以下部分探讨一些最重要的类别，例如以下内容：

+   验收测试

+   回归测试

+   性能测试

# 验收测试

验收测试是一种验证系统行为是否符合预期的测试形式。决定什么是可以接受的是系统利益相关者的责任。它可以简单到一个冒烟测试，也可以复杂到测试代码中所有可能的路径、所有故障模式和所有副作用（例如，写入日志文件的消息）。良好的验收测试套件的主要好处之一是它是描述系统的一种强制性手段，这种描述对于非工程师利益相关者（如产品经理和高层管理人员）是有意义的。理想的情况（我从未在实践中见过）是业务利益相关者能够自己编写和维护验收测试。

这在精神上接近于可视化编程。我个人认为所有的自动化测试都应该由开发人员编写和维护，但你的情况可能有所不同。Delinkcious 目前只公开了一个 REST API，并没有用户界面的 Web 应用程序。大多数系统现在都有成为验收测试边界的 Web 应用程序。在浏览器中运行验收测试是很常见的。有很多好的框架。如果你喜欢使用 Go，Agouti ([`agouti.org/`](https://agouti.org/)) 是一个很好的选择。它与 Ginkgo 和 Gomega 紧密集成，可以通过 PhantomJS、Selenium 或 ChromeDriver 驱动浏览器。

# 回归测试

回归测试是一个很好的选择，当你只想确保新系统不会偏离当前系统的行为时。如果你有全面的验收测试，那么你只需要确保新版本的系统通过所有验收测试，就像之前的版本一样。然而，如果你的验收测试覆盖不足，你可以通过向当前系统和新系统发送相同的输入并验证输出是否相同来获得某种信心。这也可以通过模糊测试来完成，其中你生成随机输入。

# 性能测试

性能测试是一个很大的话题。在这里，目标是衡量系统的性能，而不是其响应的正确性。也就是说，错误可能会显著影响性能。考虑以下错误处理选项：

+   遇到错误时立即返回

+   重试五次，并在尝试之间休眠一秒钟

现在，考虑这两种策略，考虑一个通常需要大约两秒来处理的请求。在一个简单的性能测试中，对于这个请求的大量错误将会增加性能，当使用第一种策略时（因为请求将不会被处理并立即返回），但当使用第二种策略时会降低性能（请求将在失败之前重试五秒）。

微服务架构通常利用异步处理、队列和其他机制，这可能会使系统的实际性能测试变得具有挑战性。此外，涉及大量的网络调用，这可能是不稳定的。

此外，性能不仅仅是响应时间的问题。它可能包括 CPU 和内存利用率、外部 API 调用次数、对网络存储的访问等等。性能也与可用性和成本密切相关。在复杂的云原生分布式系统中，性能测试通常可以指导架构决策。

正如您所看到的，端到端测试是一个相当复杂的问题，必须非常谨慎地考虑，因为端到端测试的价值和成本都不容忽视。管理端到端测试中最困难的资源之一就是测试数据。

让我们来看看一些管理测试数据的方法，它们的优缺点。

# 管理测试数据

使用 Kubernetes 相对容易部署大量软件，包括由许多组件组成的软件，如典型的微服务架构。然而，数据变化要少得多。有不同的方法来生成和维护测试数据。不同的测试数据管理策略适用于不同类型的端到端测试。让我们来看看合成数据、手动测试数据和生产快照。

# 合成数据

合成数据是您以编程方式生成的测试数据。其优缺点如下：

+   **优点**：

+   易于控制和更新，因为它是以编程方式生成的

+   易于创建错误数据以测试错误处理

+   易于创建大量数据

+   **缺点**：

+   您需要编写代码来生成它。

+   可能与实际数据格式不同步。

# 手动测试数据

手动测试数据类似于合成数据，但是您需要手动创建它。其优缺点如下：

+   **优点**：

+   拥有终极控制权，包括验证输出应该是什么

+   可以基于示例数据，并进行轻微调整。

+   快速启动（无需编写和维护代码）

+   无需过滤或去匿名化

+   **缺点**：

+   繁琐且容易出错

+   难以生成大量测试数据

+   难以在多个微服务之间生成相关数据

+   必须在数据格式更改时手动更新

# 生产快照

生产快照实际上是记录真实数据并将其用于填充测试系统。其优缺点如下：

+   **优点**：

+   与真实数据高度一致

+   重新收集确保测试数据始终与生产数据同步

+   **缺点**：

+   需要过滤和去匿名化敏感数据

+   数据可能不支持所有测试场景（例如，错误处理）

+   可能难以收集所有相关数据

# 总结

在本章中，我们涵盖了测试及其各种类型：单元测试，集成测试和各种端到端测试。我们还深入探讨了 Delinkcious 测试的结构。我们探索了链接管理器的单元测试，添加了一个新的冒烟测试，并介绍了 Telepresence，以加速对真实 Kubernetes 集群进行编辑-测试-调试生命周期，同时在本地修改代码。

话虽如此，测试是一个有成本的范围，盲目地添加越来越多的测试并不能使您的系统变得更好或更高质量。在测试数量和质量之间存在许多重要的权衡，例如开发和维护测试所需的时间，运行测试所需的时间和资源，以及测试早期检测到的问题的数量和复杂性。您应该有足够的上下文来为您的系统做出艰难的决策，并选择最适合您的测试策略。

同样重要的是要记住，随着系统的发展，测试也在不断演变，即使是同一组织，测试的水平在风险更高时通常也必须提高。如果您是一个业余开发人员，发布了一个 Beta 产品，有一些用户只是在家里玩玩，您可能在测试上不那么严格（除非它可以节省开发时间）。然而，随着您的公司的发展和吸引更多将您的产品用于关键任务的用户，代码中出现问题的影响可能需要更严格的测试。

在下一章中，我们将探讨 Delinkcious 的各种部署用例和情况。Kubernetes 及其生态系统提供了许多有趣的选项和工具。我们将考虑到生产环境的强大部署以及快速的面向开发人员的场景。

# 进一步阅读

您可以参考以下参考资料，了解本章涵盖的更多信息：

+   **Go 编程语言包测试**：[`golang.org/pkg/testing/`](https://golang.org/pkg/testing/)

+   **Ginkgo**：[`onsi.github.io/ginkgo/`](http://onsi.github.io/ginkgo/)

+   **Gomega**：[`onsi.github.io/gomega/`](http://onsi.github.io/gomega/)

+   **豚鼠**：[`agouti.org/`](https://agouti.org/)

+   **远程呈现**：[`telepresence.io`](https://telepresence.io)
