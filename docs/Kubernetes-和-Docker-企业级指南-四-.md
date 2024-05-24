# Kubernetes 和 Docker 企业级指南（四）

> 原文：[`zh.annas-archive.org/md5/9023162EFAC3D4D142381E2C55E3B624`](https://zh.annas-archive.org/md5/9023162EFAC3D4D142381E2C55E3B624)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：部署安全的 Kubernetes 仪表板

Kubernetes 集群不仅由 API 服务器和 kubelet 组成。集群通常由需要进行安全保护的其他应用程序组成，例如容器注册表、源代码控制系统、流水线服务、GitOps 应用程序和监控系统。您的集群用户通常需要直接与这些应用程序进行交互。

许多集群都专注于对面向用户的应用程序和服务进行身份验证，但集群解决方案并未受到同等重视。用户通常被要求使用 kubectl 的端口转发或代理功能来访问这些系统。从安全和用户体验的角度来看，这种访问方法是一种反模式。用户和管理员将首次接触到这种反模式的是 Kubernetes 仪表板。本章将详细介绍为什么这种访问方法是一种反模式，以及如何正确访问仪表板。我们将指出如何不部署安全的 Web 应用程序，并指出其中的问题和风险。

我们将使用 Kubernetes 仪表板来学习有关 Web 应用程序安全性以及如何在自己的集群中应用这些模式。这些课程不仅适用于仪表板，还适用于其他集群重点应用程序，如 Istio 的 Kiali 仪表板、Grafana、Prometheus 和其他集群管理应用程序。

最后，我们将花一些时间讨论本地仪表板以及如何评估它们的安全性。这是一个流行的趋势，但并非普遍适用。了解这两种方法的安全性非常重要，我们将在本章中探讨它们。

在本章中，我们将涵盖以下主题：

+   仪表板如何知道你是谁？

+   仪表板是否不安全？

+   使用反向代理部署仪表板

+   将仪表板与 OpenUnison 集成

# 技术要求

要完成本章的练习，您需要一个运行 OIDC 集成的 KinD 集群。我们在《第七章》*第七章**《将身份验证集成到您的集群中》*中创建了这个集群。

您可以在以下 GitHub 存储库中访问本章的代码：[`github.com/PacktPublishing/Kubernetes-and-Docker-The-Complete-Guide`](https://github.com/PacktPublishing/Kubernetes-and-Docker-The-Complete-Guide)。

# 仪表板如何知道你是谁？

Kubernetes 仪表板是一个强大的 Web 应用程序，可以快速从浏览器内部访问您的集群。它允许您浏览命名空间并查看节点的状态，甚至提供一个您可以使用来直接访问 Pod 的 shell。使用仪表板和 kubectl 之间存在根本的区别。作为 Web 应用程序，仪表板需要管理您的会话，而 kubectl 不需要。这导致在部署过程中出现一组不同的安全问题，通常没有考虑到，导致严重后果。在本节中，我们将探讨仪表板如何识别用户并与 API 服务器进行交互。

## 仪表板架构

在深入了解仪表板如何对用户进行身份验证之前，了解仪表板的基本工作原理非常重要。从高层次来看，仪表板有三个层次：

+   **用户界面**：这是在浏览器中显示并与之交互的 Angular + HTML 前端。

+   **中间层**：前端与仪表板容器中托管的一组 API 进行交互，将前端的调用转换为 Kubernetes API 调用。

+   **API 服务器**：中间层 API 直接与 Kubernetes API 服务器进行交互。

Kubernetes 仪表板的这种三层架构可以在以下图表中看到：

![图 9.1 – Kubernetes 仪表板架构](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/k8s-dkr/img/Fig_9.1_B15514.jpg)

图 9.1 – Kubernetes 仪表板架构

当用户与仪表板交互时，用户界面会调用中间层，中间层再调用 API 服务器。仪表板不知道如何收集凭证，大多数应用程序用户通常会获得访问权限。没有地方放用户名或密码。它有一个基于 cookie 的非常简单的会话机制系统，但在大多数情况下，仪表板实际上并不知道或关心当前登录的用户是谁。仪表板关心的唯一事情是在与 API 服务器通信时使用什么令牌。

那么，仪表板如何知道你是谁呢？

## 认证方法

仪表板可以确定用户身份的三种方式：

+   **无凭证**：可以告诉仪表板不收集任何令牌或凭证。当这种情况发生时，仪表板将使用容器自己的服务帐户与 API 服务器进行交互，具有通过 RBAC 分配的任何特权。

+   **来自登录/上传 kubectl 配置的令牌**：仪表板可以提示用户提供他们的 kubectl 配置文件或一个用于使用的令牌。一旦提供了令牌（或从上传到仪表板的配置文件中提取出来），就会创建一个加密的 cookie 来存储令牌。这个 cookie 会被中间层解密，里面的令牌会被传递给 API 服务器。

+   **来自反向代理的令牌**：如果用户界面向中间层发出的请求中包含一个包含令牌的授权头，则中间层将在向 API 服务器发出请求时使用该令牌。这是最安全的选项，也是本章将详细介绍的实现方式。

在本章的其余部分，将探讨访问仪表板的前两个选项作为反模式，并解释为什么反向代理模式是从安全和用户体验的角度来看访问集群仪表板实现的最佳选项。

# 了解仪表板安全风险

在设置新集群时，仪表板的安全性问题经常被提出。保护仪表板归结为仪表板的部署方式，而不是仪表板本身是否安全。回到仪表板应用程序的架构，没有安全性的概念被构建进去。中间层只是简单地将令牌传递给 API 服务器。

在谈论任何类型的 IT 安全时，重要的是通过“深度防御”的视角来看待。这是任何系统都应该有多层安全的理念。如果一层失败，就有其他层来填补漏洞，直到失败的层得到解决。单一的失败不会直接给攻击者提供访问权限。

与仪表板安全性相关的最常引用的事件是 2018 年加密货币挖矿者入侵特斯拉的事件。攻击者能够访问特斯拉集群中运行的 Pods，因为仪表板没有得到保护。集群的 Pods 可以访问提供攻击者访问特斯拉云供应商的令牌，攻击者在那里运行他们的加密挖矿系统。

总的来说，仪表板通常是攻击向量，因为它们很容易找到攻击者寻找的内容，并且很容易被不安全地部署。为了说明这一点，在 KubeCon NA 2019 上展示了一个“夺旗”（CTF）活动，其中一个场景是开发人员“意外”暴露了集群的仪表板。

注意

CTF 可作为家庭实验室在[`securekubernetes.com/`](https://securekubernetes.com/)上使用。这是一个非常推荐的资源，供任何学习 Kubernetes 安全的人使用。除了具有教育意义和可怕之外，它也非常有趣！

自特斯拉遭受攻击以来，部署仪表板而不需要凭据变得更加困难。这不再是默认设置，需要更新仪表板和集群。为了演示这样做有多危险，让我们来看看可以造成什么样的损害。

经历这些步骤可能会让人想到“有人真的会经历所有这些步骤来进入仪表板吗？”答案可能是没有人愿意谈论的事情。在上一章中，讨论了授权访问集群和设计多租户的多个选项。其中一个选项是在集群层面进行租户管理，其中每个租户都有自己的集群。不幸的是，许多这些部署包括租户的集群管理员访问权限，这将使他们能够执行这些步骤。集群管理员离谷歌搜索指令只有几步之遥，就能轻松绕过那些开发人员不喜欢在家中使用的烦人 VPN。

## 部署一个不安全的仪表板

虽然这听起来很疯狂，但我们在野外经常看到这种情况。推荐的仪表板安装多次声明不要在隔离的开发实验室之外使用这种类型的配置。不足之处在于，由于它确实使部署仪表板变得如此简单，许多新的管理员使用它，因为它易于设置，并且他们经常在生产集群中使用相同的部署。

现在，让我们展示一下部署时没有考虑安全性的仪表板有多容易受到攻击：

1.  第一步是告诉仪表板允许用户绕过身份验证。编辑**kubernetes-dashboard**命名空间中的**kubernetes-dashboard**部署：

**kubectl edit deployment kubernetes-dashboard -n kubernetes-dashboard**

1.  查找容器的**args**选项，添加**- --enable-skip-login**，然后保存：![图 9.2 - 在仪表板上启用跳过登录](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/k8s-dkr/img/Fig_9.2_B15514.jpg)

图 9.2 - 在仪表板上启用跳过登录

1.  现在我们需要通过创建新的 Ingress 规则将仪表板暴露给网络。使用以下 YAML 创建一个名为**insecure-dashboard.yaml**的新 Ingress 清单。记得用你的 Docker 主机 IP 地址替换**host**部分的 IP 地址：

apiVersion: networking.k8s.io/v1beta1

种类：Ingress

元数据：

名称：dashboard-external-auth

命名空间：kubernetes-dashboard

注释：

kubernetes.io/ingress.class: nginx

nginx.ingress.kubernetes.io/affinity: cookie

nginx.ingress.kubernetes.io/backend-protocol: https

nginx.ingress.kubernetes.io/secure-backends: "true"

nginx.org/ssl-services: kubernetes-dashboard

规格：

规则：

- host: k8s-secret-dashboard.apps.192-168-2-129.nip.io

http：

路径：

- 后端：

serviceName: kubernetes-dashboard

servicePort: 443

路径：/

1.  通过使用**kubectl**部署清单来创建 Ingress 规则。由于我们在清单中添加了命名空间值，因此需要在 kubectl 命令中添加**-n**：

**kubectl create -f insecure-dashboard.yaml**

1.  创建 Ingress 后，打开浏览器，使用 Ingress 规则的**host**部分指定的 Nip.io 名称访问您的 secret 仪表板。

1.  您将看到一个要求令牌或 Kubeconfig 文件的身份验证屏幕，但由于我们在编辑仪表板时启用了跳过登录的选项，您可以通过单击**跳过**来简单地跳过登录：![图 9.3 - 禁用登录的 Kubernetes 仪表板](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/k8s-dkr/img/Fig_9.3_B15514.jpg)

图 9.3 - 禁用登录的 Kubernetes 仪表板

1.  一旦进入仪表板，默认服务账户将无法访问任何内容：![图 9.4 - 默认服务账户的 Kubernetes 仪表板](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/k8s-dkr/img/Fig_9.4_B15514.jpg)

图 9.4 - 默认服务账户的 Kubernetes 仪表板

到目前为止，这可能看起来还不错。您将看到*访问被禁止*的错误，所以目前仪表板不会允许您造成任何损害。不幸的是，许多人到达这一点并采取额外的步骤来更改默认服务账户在集群上的权限。

1.  目前，服务账户未被授权访问集群，因此通过创建新的**ClusterRoleBinding**到 cluster-admin **ClusterRole**来更改。

创建一个名为**dashboard-role.yaml**的新文件，内容如下：

apiVersion: rbac.authorization.k8s.io/v1

种类：ClusterRoleBinding

元数据：

名称：secret-dashboard-cluster-admin

roleRef:

apiGroup: rbac.authorization.k8s.io

种类：ClusterRole

名称：cluster-admin

主题：

- apiGroup: ""

kind: ServiceAccount

命名空间：kubernetes-dashboard

名称：kubernetes-dashboard

1.  通过使用 kubectl 应用它来创建新的**ClusterRoleBinding**：

**kubectl create -f dashboard-role.yaml**

恭喜！秘密仪表板现在可以供任何想要使用它的人使用！

现在，你可能会想*"谁能找到我的仪表板？他们需要知道 URL，而我不会告诉任何人。"* 你感到安全，因为没有其他人知道你的仪表板的 URL 或 IP 地址。这被称为安全性通过混淆，通常被认为是一种糟糕的保护系统的方法。

让我们用一个场景来说明，有人可能在你不知情的情况下利用仪表板。

你是 Reddit 的忠实粉丝，有一天你看到了一个 Reddit 帖子，标题是*这是一个用于保护你的 Kubernetes 仪表板的好工具*。这个帖子看起来很正规，你很兴奋地想测试一下这个新工具。阅读完帖子后，你看到了底部的链接和运行它的命令：你可以从[`raw.githubusercontent.com/PacktPublishing/Kubernetes-and-Docker-The-Complete-Guide/master/chapter9/kubectl-secure-my-dashboard.go`](https://raw.githubusercontent.com/PacktPublishing/Kubernetes-and-Docker-The-Complete-Guide/master/chapter9/kubectl-secure-my-dashboard.go)下载它来试试看！

为了完全体验这个例子，你可以在你的 KinD 集群上运行这个工具，通过在**chapter9**目录下的克隆存储库中执行以下命令。确保将 URL 更改为你的仪表板的 Ingress 主机：

go run kubectl-secure-my-dashboard.go https://k8s-secret-dashboard.apps.192-168-2-129.nip.io

**在 https://k8s-secret-dashboard.apps.192-168-2-129.nip.io 上运行分析**

**你的仪表板已经得到了保护！**

现在，让我们回顾一下刚刚发生的事情。打开浏览器，进入你的秘密仪表板网站，查看发生了什么变化：

![图 9.5 - 显示部署恶意软件的 Kubernetes 仪表板](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/k8s-dkr/img/Fig_9.5_B15514.jpg)

图 9.5 - 显示部署恶意软件的 Kubernetes 仪表板

看来我们的加固插件是一个部署比特币矿工的诡计。太无礼了！

现在你已经看到了一个不安全的仪表板是如何容易被利用的，使用 kubectl 删除部署。

虽然这种攻击可以通过预授权具有批准图像的注册表来减轻（当**OpenPolicyAgent**在*第十一章*中介绍时，*使用 Open Policy Manager 扩展安全性*将涉及到这个话题），但在那时安全性是被动的，试图应对威胁而不是预防它们。使用准入控制器也无法阻止某人从仪表板中提取机密信息。

虽然这是以最简单的方式不安全地访问仪表板的方法，但并不是唯一的方法。kubectl 实用程序包括两个功能，可以使访问仪表板变得容易。端口转发实用程序通常用于在集群内部创建到 pod 的隧道。该实用程序创建到 pod 上特定端口的 TCP 流，使其可以被本地主机访问（或者更多，如果你想的话）。这仍然绕过了仪表板中的身份验证，要求仪表板的服务账户通过 RBAC 具有执行所需任务的访问权限。虽然用户必须具有 RBAC 授权才能将端口转发到 pod，但这样会使仪表板通过两个攻击向量开放：

+   **外部**：运行在用户本地工作站上的任何脚本都可以访问转发的网络隧道。

+   **内部**：集群内部的任何 pod 都可以访问仪表板 pod。

对于内部访问，可以使用网络策略来限制哪些命名空间和 Pod 可以访问仪表板的 API。最好一开始就使用网络策略，但在这种情况下这是一个单点故障。一个配置错误的策略将会使仪表板暴露于攻击之下。

外部来源的威胁可能以您（或您使用的其他工具）决定运行的脚本的形式出现。Web 浏览器无法访问从本地系统外部托管的页面通过端口转发打开的端口，但是您工作站上运行的任何脚本都可以。例如，虽然您可以通过打开浏览器并直接转到该端口来访问转发的主机，但是从远程站点加载的恶意 JavaScript 的网页无法打开到您本地主机的连接。尝试对转发的端口运行之前在本节中运行的加固脚本，将会产生相同的结果，即在您的基础设施上出现一个不需要的 pod。

提供访问的另一种技术是使用 API 服务器的集成代理实用程序。运行**kubectl proxy**会创建一个到 API 服务器的本地网络隧道，然后可以用于代理 HTTP 请求到任何 Pod，包括仪表盘。这与**kubectl port-forward**具有相同的缺点，并且会使您的集群面临来自本地运行的任何脚本的攻击。

这些方法中的共同点是它们在安全性上存在单一故障点。即使采取了限制可以部署的图像的措施，一个不安全的仪表盘仍然可以用于访问秘密对象、删除部署，甚至通过仪表盘中集成的终端远程进入 Pod。

在探讨了如何绕过仪表盘上的所有身份验证及其影响之后，接下来我们将看看如何向仪表盘提供令牌，而无需部署额外的基础设施。

## 使用令牌登录

用户可以将令牌或 kubectl 配置文件上传到仪表盘作为登录，以避免秘密仪表盘的危险。正如前面讨论的，仪表板将获取用户的令牌并将其与对 API 服务器的所有请求一起使用。虽然这似乎解决了为仪表盘提供特权服务帐户的问题，但它也带来了自己的问题。仪表盘不是 kubectl，并不知道如何在令牌过期时刷新令牌。这意味着令牌需要相当长的生命周期才能发挥作用。这将要求创建可以使用的服务帐户，或者使您的 OpenID Connect **id_tokens**更长寿。这两种选择都会抵消通过利用 OpenID Connect 进行身份验证所实施的大部分安全性。

到目前为止，我们只关注了错误的部署仪表盘的方法。虽然了解这一点很重要，但正确的方法是什么？在下一节中，我们将详细介绍使用反向代理部署仪表盘的正确方法。

# 使用反向代理部署仪表盘

代理是 Kubernetes 中常见的模式。在 Kubernetes 集群的每一层都有代理。代理模式也被大多数 Kubernetes 上的服务网格实现所使用，创建将拦截请求的 sidecar。这里描述的反向代理与这些代理的区别在于它们的意图。微服务代理通常不携带会话，而 Web 应用程序需要会话来管理状态。

以下图表显示了带有反向代理的 Kubernetes 仪表板的架构：

![图 9.6 – 带有反向代理的 Kubernetes 仪表板](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/k8s-dkr/img/Fig_9.6_B15514.jpg)

图 9.6 – 带有反向代理的 Kubernetes 仪表板

图 9.6 中显示的反向代理执行三个角色：

+   **身份验证**：反向代理拦截未经身份验证的请求（或过期会话），并触发使用 OpenID Connect 身份提供者进行用户身份验证的过程。

+   **会话管理**：Kubernetes 的仪表板是一个面向用户的应用程序。它应该具有典型的控件，以支持会话超时和撤销。要注意的是，存储所有会话数据的反向代理在 cookie 中。这些方法很难撤销。

+   **身份注入**：一旦代理已经对用户进行了身份验证，它需要能够在每个请求上注入一个 HTTP 授权头，该头是一个 JWT，用于标识已登录的用户，由相同的 OpenID Connect 身份提供者签名，并且具有与 API 服务器相同的发行者和接收者。唯一的例外是使用模拟，正如在*第七章*中讨论的那样，将特定的头部注入到请求中。

反向代理不需要在集群上运行。根据您的设置，这样做可能是有利的，特别是在利用集群进行模拟时。在使用模拟时，反向代理使用服务账户的令牌，因此最好让该令牌永远不要离开集群。

本章的重点是 Kubernetes 项目的仪表板。仪表板功能有多种选择。接下来，我们将探讨这些仪表板如何与 API 服务器交互以及如何评估它们的安全性。

## 本地仪表板

第三方仪表板的一个共同主题是在您的工作站上本地运行，并使用 Kubernetes SDK 与 API 服务器进行交互，就像 kubectl 一样。这些工具的好处在于不需要部署额外的基础设施来保护它们。

Visual Studio Code 的 Kubernetes 插件是一个利用直接 API 服务器连接的本地应用程序的例子。当启动插件 Visual Studio Code 访问您当前的 kubectl 配置，并使用该配置与 API 服务器交互。甚至在 OpenID Connect 令牌过期时，它会刷新该令牌：

![图 9.7 - Visual Studio Code 与 Kubernetes 插件](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/k8s-dkr/img/Fig_9.7_B15514.jpg)

图 9.7 - Visual Studio Code 与 Kubernetes 插件

Visual Studio Code 的 Kubernetes 插件能够刷新其 OpenID Connect 令牌，因为它是使用 client-go SDK 构建的，这与 kubectl 使用的客户端库相同。在评估客户端仪表板时，请确保它与您的身份验证类型配合使用，即使它不是 OpenID Connect。许多 Kubernetes 的 SDK 不支持 OpenID Connect 令牌的刷新。截至本书出版日期，Java 和 Python SDK 最近才开始支持刷新 OpenID Connect 令牌，就像 client-go SDK 一样。在评估本地仪表板时，请确保它能够利用您的短期令牌，并在需要时刷新它们，就像 kubectl 一样。

## 其他集群级应用程序

本章介绍了集群除 Kubernetes 之外还由多个应用程序组成。其他应用程序可能会遵循与仪表板相同的安全模型，而反向代理方法比 kubectl 端口转发更适合暴露这些应用程序，即使应用程序没有内置安全性。以常见的 Prometheus 堆栈为例。Grafana 支持用户身份验证，但 Prometheus 和 Alert Manager 则不支持。如果使用端口转发，您将如何跟踪谁访问了这些系统，或者它们何时被访问？

未提供用户上下文。使用反向代理，每个 URL 的日志和用于访问 URL 的用户可以被转发到中央日志管理系统，并由安全信息和事件管理器（SIEM）进行分析，提供对集群使用的额外可见性层。

与仪表板一样，使用反向代理提供了分层安全方法。它可以从相关应用程序中卸载会话管理，并提供增强的身份验证措施，如多因素身份验证和会话撤销的能力。这些好处将导致一个更安全、更易于使用的集群。

# 将仪表板与 OpenUnison 集成

OpenUnison 使用模拟的方式注入身份标头的主题在*第七章**，将身份验证集成到您的集群*中进行了讨论，但没有讨论 OpenUnison 如何将用户的身份注入到集成了 OpenID Connect 的集群的仪表板中。它起作用，但没有解释。本节将使用 OpenUnison 实现作为一个示例，说明如何为仪表板构建一个反向代理。使用本节的信息来更好地理解 API 安全性，或者为仪表板身份验证构建自己的解决方案。

OpenUnison 部署包括两个集成应用程序：

+   **OpenID Connect 身份提供者和登录门户**：该应用程序托管登录过程和 API 服务器用于获取验证**id_token**所需密钥的发现 URL。它还托管了您可以获取 kubectl 令牌的屏幕。

+   **仪表板**：一个反向代理应用程序，对集成的 OpenID Connect 身份提供程序进行身份验证，并将用户的**id_token**注入到每个请求中。

该图显示了仪表板的用户界面如何与其服务器端组件进行交互，反向代理注入用户的**id_token**：

![图 9.8 - OpenUnison 与仪表板的集成](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/k8s-dkr/img/Fig_9.8_B15514.jpg)

图 9.8 - OpenUnison 与仪表板的集成

仪表板使用与 API 服务器相同的 OpenID Connect 身份提供程序，但不使用其提供的**id_token**。相反，OpenUnison 有一个插件，将独立于身份提供者生成一个新的**id_token**，其中包含用户的身份数据。OpenUnison 可以做到这一点，因为用于为 OpenID Connect 身份提供者生成**id_token**的密钥，被存储在 OpenUnison 中。

生成一个新的、短暂的令牌，与 kubectl 一起使用的 OpenID Connect 会话分开。这样，令牌可以独立于 kubectl 会话进行刷新。这个过程提供了 1 到 2 分钟令牌寿命的好处，同时又具有直接登录过程的便利性。

如果您对安全有所了解，您可能会指出这种方法在安全模型中存在一个明显的单点故障，即用户的凭据！就像本章前面构建的 Secret 仪表板一样，在*了解仪表板安全风险部分*，攻击者通常只需要要求凭据就能获取到它们。这通常是通过电子邮件进行的，称为网络钓鱼攻击，攻击者向受害者发送一个看起来像他们登录页面的链接，但实际上只是收集凭据。这就是为什么多因素认证对基础设施系统如此重要。

在 2019 年的一项研究中，谷歌显示多因素认证可以阻止 99%的自动化和网络钓鱼攻击（https://security.googleblog.com/2019/05/new-research-how-effective-is-basic.html）。将多因素认证添加到身份提供者 OpenUnison 进行认证，或直接集成到 OpenUnison 中，是保护仪表板和集群的最有效方法之一。

# 总结

在本章中，我们详细探讨了 Kubernetes 仪表板的安全性。首先，我们介绍了架构以及仪表板如何将您的身份信息传递给 API 服务器。然后，我们探讨了仪表板如何被 compromise，最后我们详细介绍了如何正确地安全部署仪表板。

有了这些知识，您现在可以为用户提供一个安全的工具。许多用户更喜欢通过 Web 浏览器访问仪表板的简单性。添加多因素认证可以增加额外的安全层和安心感。当您的安全团队质疑仪表板的安全性时，您将有所需的答案来满足他们的担忧。

前三章着重讨论了 Kubernetes API 的安全性。接下来，我们将探讨如何保护每个 Kubernetes 部署的软肋，即节点！

# 问题

1.  仪表板不安全。

A. 真

B. 假

1.  仪表板如何识别用户？

A. 选项要么是无认证，要么是从反向代理注入的令牌

B. 用户名和密码

C. ServiceAccount

D. 多因素认证

1.  仪表板如何跟踪会话状态？

A. 会话存储在 etcd 中。

B. 会话存储在称为**DashboardSession**的自定义资源对象中。

C. 没有会话。

D. 如果上传了令牌，它将被加密并存储在浏览器中作为 cookie。

1.  使用令牌时，仪表板可以多久刷新一次？

A. 每分钟一次

B. 每 30 秒

C. 当令牌过期时

D. 以上都不是

1.  部署仪表板的最佳方式是什么？

A. 使用**kubectl 端口转发**

B. 使用**kubectl 代理**

C. 使用秘密的入口主机

D. 在反向代理后面

1.  仪表板不支持冒充。

A. 正确

B. 错误

1.  OpenUnison 是唯一支持仪表板的反向代理。

A. 正确

B. 错误


# 第十章：创建 PodSecurityPolicies

到目前为止，大部分讨论的安全重点都集中在保护 Kubernetes API 上。身份验证意味着对 API 调用进行身份验证。授权意味着授权访问某些 API。即使在关于仪表板的讨论中，也主要集中在如何通过仪表板安全地对 API 服务器进行身份验证。

这一章将会有所不同，因为我们现在将把重点转移到保护我们的节点上。我们将学习 PodSecurityPolicies（PSPs）如何保护 Kubernetes 集群的节点。我们的重点将放在容器在集群节点上的运行方式，以及如何防止这些容器获得比它们应该拥有的更多访问权限。在本章中，我们将深入了解影响的细节，看看在节点没有受到保护时，如何利用漏洞来获取对集群的访问权限。我们还将探讨即使在不需要节点访问权限的代码中，这些情景如何被利用。

在本章中，我们将涵盖以下主题：

+   什么是 PSP？

+   它们不会消失吗？

+   启用 pod 安全策略

+   PSP 的替代方案

# 技术要求

要跟随本章的示例，请确保您有一个使用*第八章*中的配置运行的 KinD 集群，*RBAC Policies and Auditing*。

您可以在以下 GitHub 存储库中访问本章的代码：[`github.com/PacktPublishing/Kubernetes-and-Docker-The-Complete-Guide/tree/master/chapter10`](https://github.com/PacktPublishing/Kubernetes-and-Docker-The-Complete-Guide/tree/master/chapter10)。

# 什么是 PodSecurityPolicy？

PSP 是一个 Kubernetes 资源，允许您为您的工作负载设置安全控制，允许您对 pod 的操作进行限制。PSP 在 pod 被允许启动之前进行评估，如果 pod 尝试执行 PSP 禁止的操作，它将不被允许启动。

许多人都有使用物理和虚拟服务器的经验，大多数人知道如何保护运行在它们上面的工作负载。当谈到保护每个工作负载时，容器需要被考虑得与众不同。要理解为什么存在 PSPs 和其他 Kubernetes 安全工具，如 Open Policy Agent（OPA），您需要了解容器与虚拟机（VM）之间的区别。

## 理解容器和虚拟机之间的区别

"*容器是轻量级虚拟机*"经常是对于新接触容器和 Kubernetes 的人描述容器的方式。虽然这样做可以形成一个简单的类比，但从安全的角度来看，这是一个危险的比较。运行时的容器是在节点上运行的进程。在 Linux 系统上，这些进程通过一系列限制它们对底层系统的可见性的 Linux 技术进行隔离。

在 Kubernetes 集群中的任何节点上运行**top**命令，所有来自容器的进程都会被列出。例如，即使 Kubernetes 在 KinD 中运行，运行**ps -A -elf | grep java**将显示 OpenUnison 和 operator 容器进程：

![图 10.1 - 从系统控制台的 Pod 进程](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/k8s-dkr/img/Fig_10.1_B15514.jpg)

图 10.1 - 从系统控制台的 Pod 进程

相比之下，虚拟机就像其名称所示，是一个完整的虚拟系统。它模拟自己的硬件，有独立的内核等。虚拟机监视器为虚拟机提供了从硅层到上层的隔离，而与此相比，在节点上的每个容器之间几乎没有隔离。

注意

有一些容器技术可以在自己的虚拟机上运行容器。但容器仍然只是一个进程。

当容器没有运行时，它们只是一个"tarball of tarballs"，其中文件系统的每一层都存储在一个文件中。镜像仍然存储在主机系统上，或者之前容器曾经运行或被拉取的多个主机系统上。

注意

"tarball"是由**tar** Unix 命令创建的文件。它也可以被压缩。

另一方面，虚拟机有自己的虚拟磁盘，存储整个操作系统。虽然有一些非常轻量级的虚拟机技术，但虚拟机和容器之间的大小差异通常是数量级的。

虽然有些人将容器称为轻量级虚拟机，但事实并非如此。它们的隔离方式不同，并且需要更多关注它们在节点上的运行细节。

从这一部分，你可能会认为我们在试图说容器不安全。事实恰恰相反。保护 Kubernetes 集群和其中运行的容器需要注意细节，并且需要理解容器与虚拟机的不同之处。由于很多人都了解虚拟机，因此很容易尝试将其与容器进行比较，但这样做会让你处于不利地位，因为它们是非常不同的技术。

一旦您了解了默认配置的限制和由此带来的潜在危险，您就可以纠正这些“问题”。

## 容器越狱

容器越狱是指您的容器进程获得对底层节点的访问权限。一旦在节点上，攻击者现在可以访问所有其他的 pod 和环境中节点的任何功能。越狱也可能是将本地文件系统挂载到您的容器中。来自[`securekubernetes.com`](https://securekubernetes.com)的一个例子，最初由 VMware 的 Duffie Cooley 指出，使用一个容器来挂载本地文件系统。在 KinD 集群上运行这个命令会打开对节点文件系统的读写权限：

kubectl run r00t --restart=Never -ti --rm --image lol --overrides '{"spec":{"hostPID": true, "containers":[{"name":"1","image":"alpine","command":["nsenter","--mount=/proc/1/ns/mnt","--","/bin/bash"],"stdin": true,"tty":true,"imagePullPolicy":"IfNotPresent","securityContext":{"privileged":true}}]}}'

如果你看不到命令提示符，请尝试按 Enter 键。

上面代码中的**run**命令启动了一个容器，并添加了一个关键选项**hostPID: true**，允许容器共享主机的进程命名空间。您可能会看到一些其他选项，比如**–mount**和一个将**privileged**设置为**true**的安全上下文设置。所有这些选项的组合将允许我们写入主机的文件系统。

现在你在容器中，执行**ls**命令查看文件系统。注意提示符是**root@r00t:/#**，确认你在容器中而不是在主机上：

root@r00t:/# ls

**bin  boot  build  dev  etc  home  kind  lib  lib32  lib64  libx32  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var**

为了证明我们已经将主机的文件系统映射到我们的容器中，创建一个名为**this is from a container**的文件，然后退出容器：

root@r00t:/# touch this_is_from_a_container

root@r00t:/# 退出

最后，让我们查看主机的文件系统，看看容器是否创建了文件。由于我们正在运行 KinD，只有一个工作节点，我们需要使用 Docker **exec**进入工作节点。如果您正在使用本书中的 KinD 集群，工作节点被称为**cluster01-worker**：

docker exec -ti cluster01-worker ls /

**bin  boot  build  dev  etc  home  kind  lib  lib32  lib64  libx32  media  mnt  opt  proc  root  run  sbin  srv  sys  this_is_from_a_container  tmp  usr  var**

在这个例子中，运行了一个容器，挂载了本地文件系统。在 pod 内部，创建了**this_is_from_a_container**文件。退出 pod 并进入节点容器后，文件就在那里。一旦攻击者可以访问节点的文件系统，他们也可以访问 kubelet 的凭据，这可能会打开整个集群。

很容易想象一系列事件会导致比特币矿工（或更糟）在集群上运行。钓鱼攻击获取了开发人员用于他们集群的凭据。尽管这些凭据只能访问一个命名空间，但还是创建了一个容器来获取 kubelet 的凭据，然后启动容器在环境中秘密部署矿工。当然，有多种缓解措施可以用来防止这种攻击，包括以下措施：

+   多因素身份验证可以防止被钓鱼凭据被使用

+   只预授权特定容器

+   PSP 可以阻止容器以**privileged**身份运行，从而阻止这种攻击

+   一个经过适当保护的基本镜像

安全的核心是一个经过适当设计的镜像。对于物理机和虚拟机来说，这是通过保护基本操作系统来实现的。当你安装操作系统时，你不会在安装过程中选择每一个可能的选项。在服务器上运行任何不需要的东西被认为是不良实践。这种做法需要延续到将在集群上运行的镜像，它们应该只包含应用程序所需的必要二进制文件。

考虑到在集群上适当保护镜像的重要性，下一节将从安全的角度探讨容器设计。构建一个安全的容器可以更容易地管理节点的安全。

## 适当设计容器

在探讨如何构建**PodSecurityPolicy**之前，重要的是要解决容器的设计方式。通常，使用**PodSecurityPolicy**来减轻对节点的攻击最困难的部分在于，许多容器都是以 root 用户构建和运行的。一旦应用了受限策略，容器就会停止运行。这在多个层面上都是有问题的。系统管理员在几十年的网络计算中学到，不要以 root 用户身份运行进程，特别是那些通过不受信任的网络匿名访问的 web 服务器等服务。

注意

所有网络都应被视为“不受信任的”。假设所有网络都是敌对的，会导致更安全的实施方法。这也意味着需要安全性的服务需要进行身份验证。这个概念被称为零信任。身份专家多年来一直在使用和倡导这个概念，但是在 DevOps 和云原生领域，谷歌的 BeyondCorp 白皮书（[`cloud.google.com/beyondcorp`](https://cloud.google.com/beyondcorp)）使其更为流行。零信任的概念也应该适用于您的集群内部！

代码中的漏洞可能导致对底层计算资源的访问，然后可能从容器中突破出去。如果通过代码漏洞利用，不需要时以特权容器的 root 身份运行可能会导致突破。

2017 年的 Equifax 泄露事件利用了 Apache Struts web 应用程序框架中的一个漏洞，在服务器上运行代码，然后用于渗透和提取数据。如果这个有漏洞的 web 应用程序在 Kubernetes 上以特权容器运行，这个漏洞可能会导致攻击者获取对集群的访问权限。

构建容器时，至少应遵守以下规定：

+   **以非 root 用户身份运行**：绝大多数应用程序，特别是微服务，不需要 root 权限。不要以 root 用户身份运行。

+   **只写入卷**：如果不向容器写入，就不需要写入访问权限。卷可以由 Kubernetes 控制。如果需要写入临时数据，可以使用**emptyVolume**对象，而不是写入容器的文件系统。

+   **最小化容器中的二进制文件**：这可能有些棘手。有人主张使用“无发行版”的容器，只包含应用程序的二进制文件，静态编译。没有 shell，没有工具。当尝试调试应用程序为何不按预期运行时，这可能会有问题。这是一个微妙的平衡。

+   **扫描已知的常见漏洞暴露（CVE）的容器；经常重建**：容器的一个好处是可以轻松地扫描已知的 CVE。有几种工具和注册表可以为您执行此操作。一旦 CVE 已修补，就进行重建。几个月甚至几年没有重建的容器与未打补丁的服务器一样危险。

重要提示

扫描 CVE 是报告安全问题的标准方法。应用程序和操作系统供应商将使用修补程序更新 CVE，以修复问题。然后，安全扫描工具将使用此信息来处理已修补的已知问题的容器。

在撰写本文时，市场上任何 Kubernetes 发行版中最严格的默认设置属于红帽的 OpenShift。除了合理的默认策略外，OpenShift 会以随机用户 ID 运行 pod，除非 pod 定义指定了 ID。

在 OpenShift 上测试您的容器是个好主意，即使它不是您用于生产的发行版。如果一个容器能在 OpenShift 上运行，它很可能能够适用于集群可以应用的几乎任何安全策略。最简单的方法是使用红帽的 CodeReady Containers（[`developers.redhat.com/products/codeready-containers`](https://developers.redhat.com/products/codeready-containers)）。这个工具可以在您的本地笔记本电脑上运行，并启动一个可以用于测试容器的最小 OpenShift 环境。

注意

虽然 OpenShift 在出厂时具有非常严格的安全控制，但它不使用 PSP。它有自己的策略系统，早于 PSP，称为**安全上下文约束**（**SCCs**）。SCCs 类似于 PSP，但不使用 RBAC 与 pod 关联。

### PSP 详细信息

PSP 与 Linux 进程运行方式紧密相关。策略本身是任何 Linux 进程可能具有的潜在选项列表。

PSP 具有几个特权类别：

+   **特权**：pod 是否需要作为特权 pod 运行？pod 是否需要执行会更改底层操作系统或环境的操作？

+   **主机交互**：pod 是否需要直接与主机交互？例如，它是否需要主机文件系统访问？

+   **卷类型**：这个 pod 可以挂载什么类型的卷？您是否希望将其限制为特定卷，如密钥，而不是磁盘？

+   **用户上下文：**进程允许以哪个用户身份运行？除了确定允许的用户 ID 和组 ID 范围外，还可以设置 SELinux 和 AppArmor 上下文。

一个简单的非特权策略可能如下所示：

api 版本：policy/v1beta1

种类：PodSecurityPolicy

元数据：

名称：pod-security-policy-default

规范：

fsGroup：

规则：'必须以此身份运行'

范围：

# 禁止添加根组。

- 最小值：1

最大值：65535

runAsUser：

规则：'必须以此身份运行'

范围：

# 禁止添加根组。

- 最小值：1

最大值：65535

seLinux：

规则：RunAsAny

辅助组：

规则：'必须以此身份运行'

范围：

# 禁止添加根组。

- 最小值：1

最大值：65535

卷：

- 空目录

- 机密

- 配置映射

- 持久卷索赔

规范中没有提到容器是否可以具有特权，也没有提到可以访问主机的任何资源。这意味着如果 pod 定义尝试直接挂载主机的文件系统或以 root 身份启动，pod 将失败。必须显式启用任何权限，以便 pod 使用它们。

该策略限制了 pod 可以以任何用户身份运行，除了 root 之外，还指定了**MustRunAs**选项，该选项设置为**1**和**65535**之间；不包括用户 0（root）。

最后，该策略允许挂载大多数 pod 可能需要的标准卷类型。很少有 pod 需要能够挂载节点的文件系统。

如果有这样的策略，我们之前用来访问节点文件系统的突破将被阻止。以下是我们之前尝试运行的 pod 的 YAML：

---

规范：

**hostPID：true**

容器：

- 名称：'1'

镜像：alpine

命令：

- nsenter

- "--mount=/proc/1/ns/mnt"

- "--"

- "/bin/bash"

标准输入：true

tty：true

镜像拉取策略：IfNotPresent

**安全上下文：**

**      特权：true**

有两个突出显示的设置。第一个是**hostPID**，它允许 pod 与节点共享进程 ID 空间。Linux 内核用于启用容器的技术之一是 cgroups，它隔离容器中的进程。在 Linux 中，cgroups 将为容器中的进程提供与在节点上简单运行时不同的进程 ID。如所示，可以从节点查看所有容器的进程。从 pod 内部运行**ps -A -elf | grep java**将得到与来自节点的不同 ID。由于我们的策略上没有将**hostPID**选项设置为**true**，**PodSecurityPolicy**执行 webhook 将拒绝此 pod：

![图 10.2-来自主机和容器内的进程 ID](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/k8s-dkr/img/Fig_10.2_B15514.jpg)

图 10.2-来自主机和容器内的进程 ID

下一个突出显示的部分是将安全上下文设置为 true 的特权。这两个设置将允许容器运行，就好像它是作为根用户登录到节点一样。再次强调，默认的 PSP 会阻止这一点，因为特权未启用。PSP 控制器会阻止它。

接下来，查看 NGINX Ingress 控制器从[`raw.githubusercontent.com/kubernetes/ingress-nginx/master/docs/examples/psp/psp.yaml`](https://raw.githubusercontent.com/kubernetes/ingress-nginx/master/docs/examples/psp/psp.yaml)推荐的 PSP：

apiVersion: policy/v1beta1

kind: PodSecurityPolicy

元数据：

。

。

.spec:

**allowedCapabilities:**

**  - NET_BIND_SERVICE**

**  allowPrivilegeEscalation: true**

。

。

。

hostPID: false

**hostPorts:**

**  - min: 80**

**    max: 65535**

在运行在主机上的典型 Web 服务器中，进程将以 root（或至少是特权用户）启动，然后降级为非特权用户，以便它可以打开端口 80 和 443 用于 HTTP 和 HTTPS。这些端口在 Linux 中保留给 root 进程，因此位于 1024 以下。

如果你想知道在 Kubernetes 中是否需要能够在端口 80 或 443 上运行 Web 服务器，实际上并不需要。正如本书前面讨论的那样，绝大多数部署都有一个负载均衡器在它们前面，可以将 80 和 443 端口映射到任何端口。这应该真的是一个例外，而不是规则。NGINX Ingress 控制器是在安全性在 Kubernetes 中并不像今天这样重要的时候发布的。此外，部署模型并不是那么成熟。

为了允许类似于 NGINX Web 服务器直接在主机上运行的行为，NGINX 希望能够从 80 端口开始打开端口，并升级为特权用户，具体使用 NET_BIND_SERVICE 特权，以便 Web 服务器可以在不以 root 身份运行整个进程的情况下打开端口 80 和 443。

正如之前讨论的，绝大多数容器不需要特殊权限。获得这些特殊权限的情况应该很少，并且只应该为特定用例保留。在评估可能在集群上运行的系统时，重要的是要看供应商或项目是否提供了经过测试的 PSP。如果没有，就假设它是无特权的，并使用本章后面讨论的工具来调试特定策略。

### 分配 PSP

设计策略后，需要进行分配。这通常是部署 PSP 最困难的部分。确定 PSP 是否应用于 Pod 的机制是两组权限的并集：

+   **提交 Pod 的用户**：这可能会变得棘手，因为用户很少直接提交 Pod。最佳做法是创建一个**Deployment**或**StatefulSet**。控制器然后创建 Pod（虽然不是直接创建）。"创建"Pod 的用户是正确的控制器服务账户，而不是提交**Deployment**或**StatefulSet**的用户。这意味着通常只有一个或两个服务账户实际上创建 Pod。

+   **Pod 运行的服务账户**：每个 Pod 可以定义一个服务账户来运行。这个服务账户的范围是在 Pod 级别上，而不是在单个容器上。

通过"并集"，Kubernetes 将结合这些权限来确定允许哪些功能。例如，如果提交 Pod 的控制器服务账户没有特权，但 Pod 的服务账户可以以 root 身份运行，那么将选择应用于 Pod 的*最佳*策略，允许 Pod 以 root 身份运行。这个过程可能令人困惑和难以调试，并且经常会产生意想不到的结果。Pod 不能直接请求策略；它必须被分配。将策略限制在一定范围内是很重要的，这样更有可能应用正确的策略。

策略是使用特殊的 RBAC 对象进行评估和应用的。就像创建用于授权对 API 的访问的策略对象一样，需要创建**Role**/**ClusterRole**和**RoleBinding**/**ClusterRoleBinding**。RBAC 对象不适用于特定的 API，而是适用于**PodSecurityPolicy**对象的**apiGroups**、PSPs 的资源和**use**动词。**use**动词没有任何对应的 HTTP 动作。绑定对象通常与授权 API 使用时相同，但主体通常是服务账户，而不是用户。

先前创建的第一个策略是一个很好的通用最低访问策略。要在整个集群中应用它，首先创建一个**ClusterRole**：

api 版本：rbac.authorization.k8s.io/v1

类型：ClusterRole

元数据：

名称：default-psp

规则：

- api 组：

- 策略

资源名称：

- **pod-security-policy-default**

资源：

- podsecuritypolicies

动词：

- use

**resourceNames**部分是特定于所引用的 PSP 的策略的唯一部分。策略中的其他所有内容都是样板文件。**ClusterRoleBinding**将在整个集群中应用这一点：

api 版本：rbac.authorization.k8s.io/v1

类型：ClusterRoleBinding

元数据：

名称：default-psp

roleRef：

api 组：rbac.authorization.k8s.io

类型：ClusterRole

名称：default-psp

主体：

- api 组：rbac.authorization.k8s.io

类型：组

名称：system:authenticated

当创建新的 pod 时，如果没有其他策略适用，则将使用受限策略。

注意

如果您来自 OpenShift 生态系统并且习惯使用 SCCs，则授权过程是不同的。SCCs 包含了直接授权对象的信息，而**PodSecurityPolicy**对象依赖于 RBAC。

# 它们不会消失吗？

2018 年发布 Kubernetes 1.11 时，人们发现 PSPs 可能永远不会成为**通用可用性**（**GA**）。这一发现是基于 PSPs 难以使用以及设计上的系统性问题的反馈。这一发现引发的讨论集中在三个潜在的解决方案上：

+   **修复 PSPs/重新实施新标准**：这两个选项被捆绑在一起，因为人们认为“修复”PSPs 将导致一个打破向后兼容性的标准，从而导致一个新的策略系统。另一个被提出的选项是将 OpenShift 的 SCC 实现移植到上游。

+   **移除 PSPs**：有人认为这应该是特定于实施的，因此由实施者决定。由于 PSP 是使用准入控制器实施的，有人认为这可以留给第三方。

+   **提供“基本”实现**：这是一种混合方法，其中上游 Kubernetes 构建支持 PSP 的子集，并依赖于自定义准入控制器来支持更高级的实现。

目前还没有明确的偏爱方向。已经明确的是，直到有替代方案普遍可用之后，PSPs 才不会被弃用和移除。随着 Kubernetes 1.19 的推出，不允许 API 在 alpha 或 beta 模式下超过三个版本的新政策迫使**PodSecurityPolicy** API 被弃用。该 API 直到 1.22 版本才会被移除，而这至少要等到 2023 年 1 月发布（假设每次发布之间至少有 6 个月的时间）。

有多种方法可以保护免受 PSP 最终被弃用的影响：

+   **完全不使用它们**：这不是一个好方法。这会让集群的节点处于开放状态。

+   **避免临时政策**：自动化政策应用过程将使迁移到 PSP 替代方案更容易。

+   **使用其他技术**：有其他 PSP 实现选项，将在*替代 PSPs*部分进行介绍。

根据您的实施需求对 PSP 做出决定。要了解 PSP 的进展，请关注 GitHub 上的问题：[`github.com/kubernetes/enhancements/issues/5`](https://github.com/kubernetes/enhancements/issues/5)。

# 启用 PSPs

启用 PSPs 非常简单。将**PodSecurityPolicy**添加到 API 服务器的准入控制器列表中，将所有新创建的 Pod 对象发送到**PodSecurityPolicy**准入控制器。该控制器有两个作用：

+   **确定最佳策略**：所请求的功能决定了要使用的最佳策略。一个 Pod 不能明确说明它想要强制执行哪个策略，只能说明它想要什么功能。

+   **确定 Pod 的策略是否被授权**：一旦确定了策略，准入控制器需要确定 Pod 的创建者或 Pod 的**serviceAccount**是否被授权使用该策略。

这两个标准的结合可能导致意想不到的结果。创建 pod 的人不是提交**Deployment**或**StatefulSet**定义的用户。有一个控制器监视**Deployment**更新并创建**ReplicaSet**。有一个控制器监视**ReplicaSet**对象并创建（**Pod**）对象。因此，需要授权的不是创建**Deployment**的用户，而是**ReplicaSet**控制器的**serviceAccount**。通常，博客文章和许多默认配置会将特权策略分配给**kube-system**命名空间中的所有**ServiceAccount**对象。这包括**ReplicaSet**控制器运行的**ServiceAccount**，这意味着它可以创建一个具有特权 PSP 的 pod，而不需要**Deployment**的创建者或 pod 的**serviceAccount**被授权这样做。向您的供应商施压，要求他们提供经过测试的经认证的 PSP 定义非常重要。

在启用准入控制器之前，首先创建初始策略非常重要。从[`raw.githubusercontent.com/PacktPublishing/Kubernetes-and-Docker-The-Complete-Guide/master/chapter10/podsecuritypolicies.yaml`](https://raw.githubusercontent.com/PacktPublishing/Kubernetes-and-Docker-The-Complete-Guide/master/chapter10/podsecuritypolicies.yaml)获取的策略集包括两个策略和相关的 RBAC 绑定。第一个策略是在本章前面描述的非特权策略。第二个策略是一个特权策略，分配给**kube-system**命名空间中的大多数**ServiceAccount**对象。**ReplicaSet**控制器的**ServiceAccount**没有被分配访问特权策略。如果一个**Deployment**需要创建一个特权 pod，pod 的**serviceAccount**将需要通过 RBAC 授权来使用特权策略。第一步是应用这些策略；策略文件位于您克隆的存储库的**chapter10**文件夹中：

1.  进入**chapter10**文件夹，并使用**kubectl**创建 PSP 对象：

kubectl create -f podsecuritypolicies.yaml

**podsecuritypolicy.policy/pod-security-policy-default created**

**clusterrole.rbac.authorization.k8s.io/default-psp created**

**clusterrolebinding.rbac.authorization.k8s.io/default-psp created**

**podsecuritypolicy.policy/privileged created**

**clusterrole.rbac.authorization.k8s.io/privileged-psp created**

创建了 **rolebinding.rbac.authorization.k8s.io/kube-system-psp**

1.  一旦策略被创建，**docker exec** 进入控制平面容器并编辑 **/etc/kubernetes/manifests/kube-apiserver.yaml**。查找 **- --enable-admission-plugins=NodeRestriction** 并将其更改为 **- --enable-admission plugins=PodSecurityPolicy,NodeRestriction**。一旦 API 服务器 pod 重新启动，所有新的和更新的 pod 对象将通过 **PodSecurityPolicy** 准入控制器。

注意

托管的 Kubernetes 提供通常预先配置了 **PodSecurityPolicy** 准入控制器。所有 pod 都被授予特权访问，所以一切都 "正常工作"。启用 PSPs 只是创建策略和 RBAC 规则，但不显式启用它们。

1.  由于策略是通过准入控制器强制执行的，任何启动的 pod 如果没有访问特权策略，将继续运行。例如，NGINX Ingress 控制器仍在运行。检查任何使用 **kubectl describe** 的 pod 的注释将显示没有注释指定使用的策略。为了将策略应用到所有正在运行的 pod，它们必须全部被删除：

kubectl delete pods --all-namespaces --all

删除了 "nginx-ingress-controller-7d6bf88c86-q9f2j" pod

删除了 "calico-kube-controllers-5b644bc49c-8lkvs" pod

删除了 "calico-node-r6vwk" pod

删除了 "calico-node-r9ck9" pod

删除了 "coredns-6955765f44-9vw6t" pod

删除了 "coredns-6955765f44-qrcss" pod

删除了 "etcd-cluster01-control-plane" pod

删除了 "kube-apiserver-cluster01-control-plane" pod

删除了 "kube-controller-manager-cluster01-control-plane" pod

删除了 "kube-proxy-n2xf6" pod

删除了 "kube-proxy-tkxh6" pod

删除了 "kube-scheduler-cluster01-control-plane" pod

删除了 "dashboard-metrics-scraper-c79c65bb7-vd2k8" pod

删除了 "kubernetes-dashboard-6f89967466-p7rv5" pod

删除了 "local-path-provisioner-7745554f7f-lklmf" pod

删除了 "openunison-operator-858d496-zxnmj" pod

删除了 "openunison-orchestra-57489869d4-btkvf" pod

这将需要一些时间来运行，因为集群需要重建自身。从 etcd 到网络，所有都在重建它们的 pod。命令完成后，观察所有的 pod 确保它们恢复。

1.  一旦所有 **Pod** 对象恢复，查看 OpenUnison pod 的注释：

kubectl describe pod -l application=openunison-orchestra -n openunison

名称：openunison-orchestra-57489869d4-jmbk2

命名空间：openunison

优先级：0

节点：cluster01-worker/172.17.0.3

开始时间：Thu, 11 Jun 2020 22:57:24 -0400

标签：application=openunison-orchestra

operated-by=openunison-operator

pod-template-hash=57489869d4

注释：cni.projectcalico.org/podIP: 10.240.189.169/32

cni.projectcalico.org/podIPs: 10.240.189.169/32

kubernetes.io/psp: pod-security-policy-default

突出显示的注释显示 OpenUnison 正在使用默认的受限策略运行。

1.  当 OpenUnison 正在运行时，尝试登录将失败。NGINX Ingress 的 pod 没有运行。正如我们在本章前面讨论的那样，NGINX 需要能够打开端口 443 和 80，但使用默认策略不允许这种情况发生。通过检查 ingress-nginx 命名空间中的事件来确认 NGINX 为什么没有运行：

$ kubectl get events -n ingress-nginx

2m4s 警告 FailedCreate replicaset/nginx-ingress-controller-7d6bf88c86 创建错误：pods "nginx-ingress-controller-7d6bf88c86-" 被禁止：无法根据任何 pod 安全策略进行验证：[spec.containers[0].securityContext.capabilities.add: Invalid value: "NET_BIND_SERVICE": capability may not be added spec.containers[0].hostPort: Invalid value: 80: Host port 80 is not allowed to be used. Allowed ports: [] spec.containers[0].hostPort: Invalid value: 443: Host port 443 is not allowed to be used. Allowed ports: []]

1.  即使 NGINX Ingress 项目提供了策略和 RBAC 绑定，让我们假设没有这些来调试。检查 Deployment 对象，规范中的关键块如下：

端口：

- containerPort: 80

主机端口：80

名称：http

协议：TCP

- containerPort: 443

hostPort: 443

名称：https

协议：TCP

。

。

。

securityContext:

allowPrivilegeEscalation: true

功能：

添加：

- NET_BIND_SERVICE

drop：

- ALL

runAsUser: 101

首先，pod 声明要打开端口 80 和 443。接下来，它的 securityContext 声明要进行特权升级，并且要求 NET_BIND_SERVICE 功能以在不作为 root 的情况下打开这些端口。

1.  类似于调试 RBAC 策略时使用的 audit2rbac 工具，Sysdig 发布了一个工具，将检查命名空间中的 pod 并生成推荐的策略和 RBAC 集。从[`github.com/sysdiglabs/kube-psp-advisor/releases`](https://github.com/sysdiglabs/kube-psp-advisor/releases)下载最新版本：

./kubectl-advise-psp inspect --namespace=ingress-nginx

**apiVersion: policy/v1beta1**

**kind: PodSecurityPolicy**

**metadata:**

** creationTimestamp: null**

** name: pod-security-policy-ingress-nginx-20200611232031**

**spec:**

** defaultAddCapabilities:**

** - NET_BIND_SERVICE**

** fsGroup:**

** rule: RunAsAny**

** hostPorts:**

** - max: 80**

** min: 80**

** - max: 443**

** min: 443**

** requiredDropCapabilities:**

** - ALL**

** runAsUser:**

** ranges:**

** - max: 101**

** min: 101**

** rule: MustRunAs**

** seLinux:**

** rule: RunAsAny**

** supplementalGroups:**

** rule: RunAsAny**

** volumes:**

** - secret**

将此策略与本章前面检查过的 NGINX Ingress 项目提供的策略进行比较；您会发现它在端口和用户上更加严格，但在组上不那么严格。**Deployment**声明了用户但没有声明组，因此**kube-psp-advisor**不知道要对其进行限制。与**audit2rbac**不同，**kube-psp-advisor**不是在扫描日志以查看被拒绝的内容；它是积极地检查 pod 定义以创建策略。如果一个 pod 没有声明需要以 root 身份运行，而只是启动一个以 root 身份运行的容器，那么**kube-psp-advisor**将不会生成适当的策略。

1.  从**kube-psp-advisor**创建名为**psp-ingress.yaml**的策略文件：

**$ ./kubectl-advise-psp inspect --namespace=ingress-nginx > psp-ingress.yaml**

1.  使用**kubectl**部署 PSP：

**$ kubectl create -f ./psp-ingress.yaml -n ingress-nginx**

1.  接下来，为**nginx-ingress-serviceaccount ServiceAccount**（在部署中引用）创建 RBAC 绑定，以便访问此策略：

apiVersion: rbac.authorization.k8s.io/v1

kind: Role

metadata:

name: nginx-ingress-psp

namespace: ingress-nginx

rules:

- apiGroups:

- policy

resourceNames:

- pod-security-policy-ingress-nginx-20200611232826

resources:

- podsecuritypolicies

verbs:

- use

---

apiVersion: rbac.authorization.k8s.io/v1

kind: RoleBinding

metadata:

name: nginx-ingress-psp

namespace: ingress-nginx

roleRef:

apiGroup: rbac.authorization.k8s.io

kind: Role

name: nginx-ingress-psp

subjects:

- kind: ServiceAccount

name: nginx-ingress-serviceaccount

namespace: ingress-nginx

1.  一旦 RBAC 对象创建完成，需要更新部署以强制 Kubernetes 尝试重新创建 pod，因为 API 服务器在一定时间后将停止尝试：

$ kubectl scale deployment.v1.apps/nginx-ingress-controller --replicas=0 -n ingress-nginx

deployment.apps/nginx-ingress-controller scaled

$ kubectl scale deployment.v1.apps/nginx-ingress-controller --replicas=1 -n ingress-nginx

deployment.apps/nginx-ingress-controller scaled

$ kubectl get pods -n ingress-nginx

名称                                      准备就绪    状态      重启次数    年龄

nginx-ingress-controller-7d6bf88c86-h4449   0/1     Running   0          21s

如果您检查 Pod 上的注释，将会有**PodSecurityPolicy**注释，并且 OpenUnison 将再次可访问。

注意

使用 RBAC 来控制 PSP 授权的一个副作用是，命名空间中的管理员可以创建可以运行特权容器的**ServiceAccount**对象。在允许命名空间管理员在其命名空间中创建 RBAC 策略的同时停止这种能力将在下一章中讨论。

恭喜，您已成功在集群上实施了 PSPs！尝试运行我们在本章早些时候运行的突破代码，您会发现它不起作用。**Pod**甚至不会启动！看到 NGINX Ingress 控制器无法启动并对其进行调试，使您能够理解如何在启用策略执行后解决问题。

# PSP 的替代方案

如果不是 PSPs，那又是什么呢？这实际上取决于集群的用例。已经有人尝试在 OPA 中实现完整的**PodSecurityPolicy**执行规范，这将在下一章中更详细地讨论。其他几个项目尝试实现 PSPs，即使不是**PodSecurityPolicy**对象的确切规范。鉴于这个领域的变化如此迅速，本章不会列举所有试图做到这一点的项目。

2020 年 5 月，认证特别兴趣小组（sig-auth）发布了*pod 安全标准*文档，以便不同的安全策略实现能够统一词汇和命名。这些标准已经发布在 Kubernetes 网站上（[`kubernetes.io/docs/concepts/security/pod-security-standards/`](https://kubernetes.io/docs/concepts/security/pod-security-standards/)）。

在自己的准入控制器作为验证 webhook 中实现这个逻辑时要小心。就像任何安全实现一样，需要非常小心，不仅要验证预期的结果，还要确保意外情况得到预期的处理。例如，如果使用**Deployment**来创建**Pod**与直接创建**Pod**有什么不同？当有人试图向定义中注入无效数据时会发生什么？或者有人试图创建一个 side car 或一个**init**容器时会发生什么？在选择方法时，重要的是要确保任何实现都有一个彻底的测试环境。

# 总结

在本章中，我们首先探讨了保护节点的重要性，从安全角度讨论了容器和 VM 之间的区别，以及在节点没有受到保护时容易利用集群的情况。我们还研究了安全的容器设计，最后实施和调试了 PSP 实现。

锁定集群节点提供了一个更少的攻击向量。封装策略使得更容易向开发人员解释如何设计他们的容器，并更容易构建安全的解决方案。

到目前为止，我们所有的安全性都是基于 Kubernetes 的标准技术构建的，几乎在所有 Kubernetes 发行版中都是通用的。在下一章中，我们将通过动态准入控制器和 OPA 来应用超出 Kubernetes 范围的策略。

# 问题

1.  容器是“轻量级 VM”——真还是假？

A. 真

B. 假

1.  容器能否访问其主机的资源？

A. 不，它是隔离的。

B. 如果标记为特权，是的。

C. 只有在策略明确授予的情况下。

D. 有时候。

1.  攻击者如何通过容器获得对集群的访问权限？

A. 容器应用程序中的错误可能导致远程代码执行，这可能被用来打破容器的漏洞，然后用来获取 kubelet 的凭证。

B. 具有创建一个命名空间中容器的能力的受损凭证可以用来创建一个挂载节点文件系统以获取 kubelet 凭证的容器。

C. 以上两者都是。

1.  **PodSecurityPolicy**准入控制器如何确定要应用于 pod 的策略？

A. 通过读取 pod 定义中的注释

B. 通过比较 pod 的请求能力和通过 pod 的创建者和其自己的**ServiceAccount**授权的策略的并集。

C. 通过比较 Pod 请求的功能和为其自己的**ServiceAccount**授权的策略

D. 通过比较 Pod 请求的功能和为 Pod 创建者授权的策略

1.  是什么机制执行了 PSPs？

A. 一个审批控制器，在创建和更新时检查所有的 Pods

B. **PodSecurityPolicy** API

C. OPA

D. Gatekeeper

1.  真或假 - **PodSecurityPolicy** API 将很快被移除。

A. 真

B. 假

1.  真或假 - 容器通常应该以 root 用户身份运行。

A. 真

B. 假


# 第十一章：使用 Open Policy Agent 扩展安全性

到目前为止，我们已经介绍了 Kubernetes 内置的身份验证和授权功能，这有助于保护集群。虽然这将涵盖大多数用例，但并非所有用例都能涵盖。Kubernetes 无法处理的几个安全最佳实践包括预授权容器注册表以及确保资源请求在所有**Pod**对象上。

这些任务留给外部系统，称为动态准入控制器。**Open Policy Agent**（**OPA**）及其 Kubernetes 本地子项目 GateKeeper 是处理这些用例的最流行方式之一。本章将详细介绍 OPA 和 GateKeeper 的部署方式，其架构以及如何开发策略。

在本章中，我们将涵盖以下主题：

+   验证 Webhook 简介

+   OPA 是什么以及它是如何工作的？

+   使用 Rego 编写策略

+   强制内存约束

+   使用 OPA 强制执行 Pod 安全策略

# 技术要求

要完成本章的实践练习，您需要一个运行着来自*第八章*的配置的 Ubuntu 18.04 服务器，运行着一个 KinD 集群，*RBAC Policies and Auditing*。

您可以在以下 GitHub 存储库中访问本章的代码：[`github.com/PacktPublishing/Kubernetes-and-Docker-The-Complete-Guide/tree/master/chapter11.`](https://github.com/PacktPublishing/Kubernetes-and-Docker-The-Complete-Guide/tree/master/chapter11 )

# 动态准入控制器简介

有两种扩展 Kubernetes 的方式：

+   构建自定义资源定义，以便您可以定义自己的对象和 API。

+   实现一个监听来自 API 服务器的请求并以必要信息响应的 Webhook。您可能还记得在*第七章*中，*将身份验证集成到您的集群*，我们解释了使用自定义 Webhook 来验证令牌。

从 Kubernetes 1.9 开始，可以将 Webhook 定义为动态准入控制器，在 1.16 中，动态准入控制器 API 变为**通用可用**（**GA**）。

该协议非常简单。一旦为特定对象类型注册了动态准入控制器，每当创建或编辑该类型的对象时，Webhook 就会被调用进行 HTTP post。然后期望 Webhook 返回代表是否允许的 JSON。

重要说明

截至 1.16 版本，**admission.k8s.io/v1**已经是 GA。所有示例将使用 API 的 GA 版本。

提交给 webhook 的请求由几个部分组成：

+   对象标识符：**资源**和**subResource**属性标识对象、API 和组。如果对象的版本正在升级，则会指定**requestKind**、**requestResource**和**requestSubResource**。此外，还提供了**namespace**和**operation**，以了解对象所在的位置以及它是**CREATE**、**UPDATE**、**DELETE**还是**CONNECT**操作。

+   **提交者标识符**：**userInfo**对象标识提交者的用户和组。提交者和创建原始请求的用户并不总是相同的。例如，如果用户创建了一个**Deployment**，那么**userInfo**对象将不是为创建原始**Deployment**的用户而是为**ReplicaSet**控制器的服务账户，因为**Deployment**创建了一个创建**Pod**的**ReplicaSet**。

+   **对象**：**object**表示正在提交的对象的 JSON，其中**oldObject**表示如果这是一个更新，则被替换的内容。最后，**options**指定了请求的附加选项。

来自 webhook 的响应将简单地具有两个属性，即来自请求的原始**uid**和**allowed**，可以是**true**或**false**。

**userInfo**对象可能会很快产生复杂性。由于 Kubernetes 通常使用多层控制器来创建对象，因此很难跟踪基于与 API 服务器交互的用户创建的使用情况。基于 Kubernetes 中的对象（如命名空间标签或其他对象）进行授权要好得多。

一个常见的用例是允许开发人员拥有一个“沙盒”，他们是其中的管理员，但容量非常有限。与其尝试验证特定用户不会请求太多内存，不如使用限制注释个人命名空间，这样准入控制器就有具体的参考对象，无论用户提交**Pod**还是**Deployment**。这样，策略将检查**命名空间**上的**注释**，而不是个别用户。为了确保只有拥有命名空间的用户能够在其中创建东西，使用 RBAC 来限制访问。

关于通用验证 Webhook 的最后一点是：没有办法指定密钥或密码。这是一个匿名请求。虽然从理论上讲，验证 Webhook 可以用于实现更新，但不建议这样做。

现在我们已经介绍了 Kubernetes 如何实现动态访问控制器，我们将看看 OPA 中最受欢迎的选项之一。

# OPA 是什么，它是如何工作的？

OPA 是一个轻量级的授权引擎，在 Kubernetes 中表现良好。它并不是从 Kubernetes 开始的，但它在那里找到了家园。在 OPA 中没有构建动态准入控制器的要求，但它非常擅长，并且有大量资源和现有策略可用于启动您的策略库。

本节概述了 OPA 及其组件的高级概述，本章的其余部分将深入介绍在 Kubernetes 中实施 OPA 的细节。

## OPA 架构

OPA 由三个组件组成-HTTP 监听器、策略引擎和数据库：

![图 11.1-OPA 架构](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/k8s-dkr/img/Fig_11.1_B15514.jpg)

图 11.1-OPA 架构

OPA 使用的数据库是内存和临时的。它不会保留用于制定策略决策的信息。一方面，这使得 OPA 非常可扩展，因为它本质上是一个授权微服务。另一方面，这意味着每个 OPA 实例必须自行维护，并且必须与权威数据保持同步：

![图 11.2-OPA 在 Kubernetes 中](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/k8s-dkr/img/Fig_11.2_B15514.jpg)

图 11.2-OPA 在 Kubernetes 中

在 Kubernetes 中使用时，OPA 使用一个名为*kube-mgmt*的 side car 来填充其数据库，该 side car 在您想要导入到 OPA 的对象上设置监视。当对象被创建、删除或更改时，*kube-mgmt*会更新其 OPA 实例中的数据。这意味着 OPA 与 API 服务器是“最终一致”的，但它不一定是 API 服务器中对象的实时表示。由于整个 etcd 数据库基本上是一遍又一遍地被复制，因此需要非常小心，以免在 OPA 数据库中复制敏感数据，例如**Secrets**。

## Rego，OPA 策略语言

我们将在下一节详细介绍 Rego 的细节。这里要提到的主要观点是，Rego 是一种策略评估语言，而不是通用编程语言。对于习惯于支持复杂逻辑的开发人员来说，这可能有些困难，比如 Golang、Java 或 JavaScript 等语言，这些语言支持迭代器和循环。Rego 旨在评估策略，并且被简化为这样。例如，如果您想在 Java 中编写代码来检查**Pod**中所有以注册表列表中的一个开头的容器图像，它看起来会像下面这样：

public boolean validRegistries(List<Container> containers,List<String> allowedRegistries) {

for (Container c : containers) {

boolean imagesFromApprovedRegistries = false;

for (String allowedRegistry : allowedRegistries) {

imagesFromApprovedRegistries =  imagesFromApprovedRegistries  || c.getImage().startsWith(allowedRegistry);

}

if (! imagesFromApprovedRegistries) {

return false;

}

}

return true;

}

此代码遍历每个容器和每个允许的注册表，以确保所有图像符合正确的策略。在 Rego 中相同的代码要小得多：

invalidRegistry {

ok_images = [image | startswith(input_images[j],input.parameters.registries[_]) ; image = input_images[j] ]

count(ok_images) != count(input_images)

}

如果容器中的任何图像来自未经授权的注册表，则前面的规则将评估为 true。我们将在本章后面详细介绍此代码的工作原理。理解此代码之所以如此紧凑的关键在于，Rego 中推断了许多循环和测试的样板文件。第一行生成一个符合条件的图像列表，第二行确保符合条件的图像数量与总图像数量相匹配。如果它们不匹配，那么一个或多个图像必须来自无效的注册表。编写紧凑的策略代码的能力使 Rego 非常适合准入控制器。

## GateKeeper

到目前为止，讨论的内容都是关于 OPA 的通用性。在本章的开头提到，OPA 并非起源于 Kubernetes。早期的实现中有一个边车，它将 OPA 数据库与 API 服务器同步，但您必须手动创建**ConfigMap**对象作为策略，并手动为 webhook 生成响应。2018 年，微软推出了 GateKeeper，[`github.com/open-policy-agent/gatekeeper`](https://github.com/open-policy-agent/gatekeeper)，以提供基于 Kubernetes 的体验。

除了从**ConfigMap**对象转移到适当的自定义资源之外，GateKeeper 还添加了一个审计功能，让您可以针对现有对象测试策略。如果对象违反策略，那么将创建一个违规条目来跟踪它。这样，您可以快速了解集群中现有策略违规情况的快照，或者在 GateKeeper 因升级而停机期间是否有遗漏的情况。

GateKeeper 和通用的 OPA 之间的一个主要区别是，在 GateKeeper 中，OPA 的功能不是通过任何人都可以调用的 API 公开的。OPA 是嵌入式的，GateKeeper 直接调用 OPA 来执行策略并保持数据库更新。决策只能基于 Kubernetes 中的数据或在评估时拉取数据。

### 部署 GateKeeper

使用的示例将假定使用 GateKeeper 而不是通用的 OPA 部署。根据 GateKeeper 项目的指示，使用以下命令：

$ kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/master/deploy/gatekeeper.yaml

这将启动 GateKeeper 命名空间的**Pods**，并创建验证 webhook。部署完成后，继续下一节。我们将在本章的其余部分介绍如何使用 GateKeeper 的详细信息。

## 自动化测试框架

OPA 具有内置的自动化测试框架，用于测试您的策略。这是 OPA 最有价值的方面之一。在部署之前能够一致地测试策略可以节省您大量的调试时间。在编写策略时，有一个与策略文件同名的文件，但名称中带有**_test**。例如，要将测试用例与**mypolicies.rego**关联，将测试用例放在同一目录中的**mypolicies_test.rego**中。运行**opa test**将运行您的测试用例。我们将在下一节中展示如何使用这个功能来调试您的代码。

在介绍了 OPA 及其构造基础之后，下一步是学习如何使用 Rego 编写策略。

# 使用 Rego 编写策略

Rego 是一种专门用于编写策略的语言。它与您可能编写过代码的大多数语言不同。典型的授权代码看起来可能是以下内容：

//假定失败

boolean allowed = false;

//在某些条件下允许访问

如果（someCondition）{

allowed = true;

}

//我们被授权了吗？

如果（allowed）{

doSomething();

}

授权代码通常会默认为未经授权，必须发生特定条件才能允许最终操作获得授权。Rego 采用了不同的方法。Rego 通常编写为授权一切，除非发生特定一组条件。

Rego 和更一般的编程语言之间的另一个主要区别是没有明确的“if”/“then”/“else”控制语句。当 Rego 的一行代码要做出决定时，代码被解释为“如果这行是假的，停止执行”。例如，Rego 中的以下代码表示“如果图像以**myregistry.lan/**开头，则停止执行策略并通过此检查，否则生成错误消息”：

不以(image，“myregistry.lan/”)开头

msg := sprintf("image '%v' comes from untrusted registry", [image])

在 Java 中，相同的代码可能如下所示：

如果（！image.startsWith("myregistry.lan/")）{

throw new Exception("image " + image + " comes from untrusted registry");

}

推断控制语句和显式控制语句之间的差异通常是学习 Rego 时最陡峭的部分。尽管这可能产生比其他语言更陡峭的学习曲线，但 Rego 通过以自动化和可管理的方式轻松测试和构建策略来弥补这一点。

OPA 可用于自动化测试策略。在编写集群安全性依赖的代码时，这非常重要。自动化测试将有助于加快您的开发速度，并通过新的工作代码捕获先前工作代码中引入的任何错误，从而提高您的安全性。接下来，让我们来学习编写 OPA 策略、测试它并将其部署到我们的集群的生命周期。

## 开发 OPA 策略

OPA 的一个常见示例是限制 Pod 可以来自哪些注册表。这是集群中常见的安全措施，可以帮助限制哪些 Pod 可以在集群上运行。例如，我们已经多次提到比特币矿工。如果集群不接受除了您自己内部注册表之外的 Pod，那么这就是需要采取的另一步措施，以防止不良行为者滥用您的集群。首先，让我们编写我们的策略，取自 OPA 文档网站（https://www.openpolicyagent.org/docs/latest/kubernetes-introduction/）：

k8sallowedregistries 包

invalidRegistry {

input_images[image]

not startswith(image, "quay.io/")

}

input_images[image] {

image := input.review.object.spec.containers[_].image

}

input_images[image] {

image := input.review.object.spec.template.spec.containers[_].image

}

此代码的第一行声明了我们策略所在的包。在 OPA 中，所有内容都存储在一个包中，包括数据和策略。OPA 中的包类似于文件系统上的目录。当您将策略放入包中时，一切都是相对于该包的。在这种情况下，我们的策略在 k8sallowedregistries 包中。

接下来的部分定义了一个规则。如果我们的 Pod 具有来自 quay.io 的镜像，这个规则最终将是未定义的。如果 Pod 没有来自 quay.io 的镜像，规则将返回 true，表示注册表无效。GateKeeper 将把这解释为失败，并在动态准入审查期间对 API 服务器返回 false。

接下来的两个规则看起来非常相似。input_images 规则中的第一个规则是“针对对象的 spec.container 中的每个容器评估调用规则”，直接匹配直接提交给 API 服务器的 Pod 对象，并提取每个容器的 image 值。第二个 input_images 规则说明：“针对对象的 spec.template.spec.containers 中的每个容器评估调用规则”，以短路 Deployment 对象和 StatefulSets。

最后，我们添加了 GateKeeper 需要通知 API 服务器评估失败的规则：

violation[{"msg": msg, "details": {}}] {

invalidRegistry

msg := "无效的注册表"

}

如果注册表有效，此规则将返回一个空的 msg。将代码分解为制定策略的代码和响应反馈的代码是一个好主意。这样可以更容易进行测试，接下来我们将进行测试。

## 测试 OPA 策略

编写策略后，我们希望设置自动化测试。与测试任何其他代码一样，重要的是您的测试用例涵盖预期和意外的输入。测试积极和消极的结果也很重要。仅证实我们的策略允许正确的注册表是不够的；我们还需要确保它能阻止无效的注册表。以下是我们代码的八个测试用例：

package k8sallowedregistries

test_deployment_registry_allowed {

输入为{"apiVersion"...的 invalidRegistry

}

test_deployment_registry_not_allowed {

输入为{"apiVersion"...的 invalidRegistry

}

test_pod_registry_allowed {

输入为{"apiVersion"...的 invalidRegistry

}

test_pod_registry_not_allowed {

输入为{"apiVersion"...的 invalidRegistry

}

test_cronjob_registry_allowed {

输入为{"apiVersion"...的 invalidRegistry

}

test_cronjob_registry_not_allowed {

输入为{"apiVersion"...的 invalidRegistry

}

test_error_message_not_allowed {

control := {"msg":"无效的注册表","details":{}}

result = 违规，输入为{"apiVersion":"admissi…

result[_] == control

}

test_error_message_allowed {

result = 违规，输入为{"apiVersion":"admissi…

control := {"msg":"无效的注册表","details":{}}

}

总共有八个测试；两个测试确保在出现问题时返回正确的错误消息，六个测试涵盖了三种输入类型的两个用例。我们正在测试简单的**Pod**定义，**Deployment**和**CronJob**。为了验证预期的成功或失败，我们已包含了具有**docker.io**和**quay.io**的**image**属性的定义。代码已经缩写打印，但可以从[`github.com/PacktPublishing/Kubernetes-and-Docker-The-Complete-Guide/tree/master/chapter11/simple-opa-policy/rego/`](https://github.com/PacktPublishing/Kubernetes-and-Docker-The-Complete-Guide/tree/master/chapter11/simple-opa-policy/rego/)下载。

要运行测试，首先按照 OPA 网站上的说明安装 OPA 命令行可执行文件-https://www.openpolicyagent.org/docs/latest/#running-opa。下载后，转到**simple-opa-policy/rego**目录并运行测试：

$ opa test .

data.kubernetes.admission.test_cronjob_registry_not_allowed：失败（248ns）

--------------------------------------------------------------

通过：7/8

失败：1/8

七个测试通过了，但**test_cronjob_registry_not_allowed**失败了。作为**input**提交的**CronJob**不应该被允许，因为它的**image**使用了*docker.io*。它能够通过的原因是因为**CronJob**对象遵循与**Pod**和**Deployment**不同的模式，因此我们的两个**input_image**规则不会加载**CronJob**中的任何容器对象。好消息是，当**CronJob**最终提交**Pod**时，GateKeeper 将不会对其进行验证，从而阻止其运行。坏消息是，直到**Pod**应该运行时，没有人会知道这一点。确保我们除了其他包含容器的对象外，还会捕捉**CronJob**对象，这将使调试变得更加容易，因为**CronJob**将不会被接受。

为了使所有测试通过，向 Github 存储库中的**limitregistries.rego**文件添加一个新的**input_container**规则，该规则将匹配**CronJob**使用的容器：

input_images[image] {

image := input.review.object.spec.jobTemplate.spec.template.spec.containers[_].image

}

现在，运行测试将显示一切都通过了：

$ opa 测试。

通过：8/8

经过测试的策略，下一步是将策略集成到 GateKeeper 中。

## 将策略部署到 GateKeeper

我们创建的策略需要部署到 GateKeeper 中，GateKeeper 提供了策略需要加载的 Kubernetes 自定义资源。第一个自定义资源是**ConstraintTemplate**，其中存储了我们策略的 Rego 代码。此对象允许我们指定与策略执行相关的参数，接下来我们将介绍这一点。为了保持简单，创建一个没有参数的模板：

apiVersion：templates.gatekeeper.sh/v1beta1

种类：ConstraintTemplate

元数据：

名称：k8sallowedregistries

规范：

crd：

规范：

名称：

种类：K8sAllowedRegistries

listKind：K8sAllowedRegistriesList

复数形式：k8sallowedregistries

单数形式：k8sallowedregistries

验证：{}

目标：

- 目标：admission.k8s.gatekeeper.sh

rego：|

包 k8sallowedregistries

。

。

。

此模板的整个源代码可在[`raw.githubusercontent.com/PacktPublishing/Kubernetes-and-Docker-The-Complete-Guide/master/chapter11/simple-opa-policy/yaml/gatekeeper-policy-template.yaml`](https://raw.githubusercontent.com/PacktPublishing/Kubernetes-and-Docker-The-Complete-Guide/master/ch)找到。

一旦创建，下一步是通过创建基于模板的约束来应用策略。约束是基于**ConstraintTemplate**的 Kubernetes 对象的配置的对象。请注意，我们的模板定义了自定义资源定义。这将添加到**constraints.gatekeeper.sh** API 组。如果您查看集群上的 CRD 列表，您将看到**k8sallowedregistries**列出：

![图 11.3 - 由 ConstraintTemplate 创建的 CRD](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/k8s-dkr/img/Fig_11.3_B15514.jpg)

图 11.3 - 由 ConstraintTemplate 创建的 CRD

创建约束意味着创建模板中定义的对象的实例。

为了避免在我们的集群中造成太多混乱，我们将限制此策略到**openunison**命名空间：

apiVersion: constraints.gatekeeper.sh/v1beta1

种类：K8sAllowedRegistries

元数据：

name: restrict-openunison-registries

规格：

匹配：

种类：

- apiGroups: [""]

种类：["Pod"]

- apiGroups: ["apps"]

种类：

- StatefulSet

- Deployment

- apiGroups: ["batch"]

种类：

- CronJob

命名空间：["openunison"]

parameters: {}

该约束限制了我们编写的策略只针对 OpenUnison 命名空间中的**Deployment**、**CronJob**和**Pod**对象。一旦创建，如果我们尝试杀死**openunison-operator** Pod，它将无法成功地由副本集控制器重新创建，因为镜像来自**dockerhub.io**，而不是**quay.io**：

![图 11.4 - 由于 GateKeeper 策略而无法创建的 Pod](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/k8s-dkr/img/Fig_11.4_B15514.jpg)

图 11.4 - 由于 GateKeeper 策略而无法创建 Pod

接下来，查看策略对象。您将看到对象的**status**部分中存在几个违规行为：

![图 11.5 - 违反镜像注册表策略的对象列表](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/k8s-dkr/img/Fig_11.5_B15514.jpg)

图 11.5 - 违反镜像注册表策略的对象列表

部署了您的第一个 GateKeeper 策略后，您可能很快就会注意到它存在一些问题。首先是注册表是硬编码的。这意味着我们需要为每次注册表更改复制我们的代码。它也不适用于命名空间。Tremolo Security 的所有镜像都存储在**docker.io/tremolosecurity**，因此我们可能希望为每个命名空间提供灵活性，并允许多个注册表，而不是限制特定的注册表服务器。接下来，我们将更新我们的策略以提供这种灵活性。

## 构建动态策略

我们当前的注册表策略是有限的。它是静态的，只支持单个注册表。Rego 和 GateKeeper 都提供了构建动态策略的功能，可以在我们的集群中重复使用，并根据各个命名空间的要求进行配置。这使我们可以使用一个代码库进行工作和调试，而不必维护重复的代码。我们将要使用的代码在[`github.com/packtpublishing/Kubernetes-and-Docker-The-Complete-Guide/blob/master/chapter11/parameter-opa-policy/`](https://github.com/packtpublishing/Kubernetes-and-Docker-The-Complete-Guide/blob/master/chapter11/pa)中。

当检查**rego/limitregistries.rego**时，**parameter-opa-policy**和**simple-opa-policy**中代码的主要区别在于**invalidRegistry**规则：

invalidRegistry {

ok_images = [image | startswith(input_images[i],input.parameters.registries[_]) ; image = input_images[i] ]

count(ok_images) != count(input_images)

}

规则的第一行的目标是使用推理确定来自批准注册表的图像。推理提供了一种根据某些逻辑构建集合、数组和对象的方法。在这种情况下，我们只想将以**input.parameters.registries**中任何允许的注册表开头的图像添加到**ok_images**数组中。

要阅读一个推理，从大括号的类型开始。我们的推理以方括号开始，因此结果将是一个数组。对象和集合也可以生成。在开放方括号和管道字符（**|**）之间的单词称为头部，这是如果满足右侧条件将添加到我们的数组中的变量。管道字符（**|**）右侧的所有内容都是一组规则，用于确定**image**应该是什么，以及是否应该有值。如果规则中的任何语句解析为未定义或假，执行将退出该迭代。

我们理解的第一个规则是大部分工作都是在这里完成的。**startswith**函数用于确定我们的每个图像是否以正确的注册表名称开头。我们不再将两个字符串传递给函数，而是传递数组。第一个数组有一个我们尚未声明的变量**i**，另一个使用下划线（**_**）代替索引。**i**被 Rego 解释为“对数组中的每个值执行此操作，递增 1 并允许在整个理解过程中引用它。”下划线在 Rego 中是“对所有值执行此操作”的速记。由于我们指定了两个数组，每个数组的所有组合都将被用作**startswith**函数的输入。这意味着如果有两个容器和三个潜在的预批准注册表，那么**startswith**将被调用六次。当任何组合从**startswith**返回**true**时，将执行下一个规则。这将**image**变量设置为带有索引**i**的**input_image**，这意味着该图像将被添加到**ok_images**。在 Java 中，相同的代码看起来可能是这样的：

ArrayList<String> okImages = new ArrayList<String>();

对于（int i=0;i<inputImages.length;i++）{

对于（int j=0;j<registries.length;j++）{

如果（inputImages[i].startsWith(registries[j]）{

okImages.add(inputImages[i]);

}

}

}

Rego 的一行消除了大部分基本代码的七行。

规则的第二行将**ok_images**数组中的条目数与已知容器图像的数量进行比较。如果它们相等，我们就知道每个容器都包含一个有效的图像。

通过我们更新的 Rego 规则来支持多个注册表，下一步是部署一个新的策略模板（如果您还没有这样做，请删除旧的**k8sallowedregistries** **ConstraintTemplate**和**restrict-openunison-registries** **K8sAllowedRegistries**）。这是我们更新的**ConstraintTemplate**：

apiVersion：templates.gatekeeper.sh/v1beta1

种类：ConstraintTemplate

元数据：

名称：k8sallowedregistries

规范：

crd：

规范：

名称：

种类：K8sAllowedRegistries

listKind：K8sAllowedRegistriesList

复数：k8sallowedregistries

单数：k8sallowedregistries

验证：

**openAPIV3Schema:**

**          properties:**

**            registries:**

**              type: array**

**              items: string**

目标：

- 目标：admission.k8s.gatekeeper.sh

rego：|

package k8sallowedregistries

。

。

。

除了包含我们的新规则，突出显示的部分显示我们向模板添加了一个模式。这将允许模板以特定参数进行重用。这个模式进入了将要创建的**CustomResourceDefenition**，并用于验证我们将创建的**K8sAllowedRegistries**对象的输入，以强制执行我们预先授权的注册表列表。

最后，让我们为**openunison**命名空间创建我们的策略。由于在这个命名空间中运行的唯一容器应该来自 Tremolo Security 的**dockerhub.io**注册表，我们将使用以下策略将所有 Pod 限制为**docker.io/tremolosecurity/**：

apiVersion: constraints.gatekeeper.sh/v1beta1

种类：K8sAllowedRegistries

元数据：

名称：restrict-openunison-registries

规格：

匹配：

种类：

- apiGroups：[""]

种类：["Pod"]

- apiGroups：["apps"]

种类：

- StatefulSet

- Deployment

- apiGroups：["batch"]

种类：

- CronJob

命名空间：["openunison"]

参数：

注册表：["docker.io/tremolosecurity/"]

与我们之前的版本不同，这个策略指定了哪些注册表是有效的，而不是直接将策略数据嵌入到我们的 Rego 中。有了我们的策略，让我们尝试在**openunison**命名空间中运行**busybox**容器以获取一个 shell：

![图 11.6 – 失败的 busybox shell](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/k8s-dkr/img/Fig_11.6_B15514.jpg)

图 11.6 – 失败的 busybox shell

使用这个通用的策略模板，我们可以限制命名空间能够从哪些注册表中拉取。例如，在多租户环境中，您可能希望将所有**Pods**限制为所有者自己的注册表。如果一个命名空间被用于商业产品，您可以规定只有那个供应商的容器可以在其中运行。在转向其他用例之前，重要的是要了解如何调试您的代码并处理 Rego 的怪癖。

## 调试 Rego

调试 Rego 可能是具有挑战性的。与 Java 或 Go 等更通用的编程语言不同，没有办法在调试器中逐步执行代码。以刚刚为检查注册表编写的通用策略为例。所有的工作都是在一行代码中完成的。逐步执行它不会有太大的好处。

为了使 Rego 更容易调试，OPA 项目在命令行上设置了详细输出时提供了所有失败测试的跟踪。这是使用 OPA 内置测试工具的另一个很好的理由。

为了更好地利用这个跟踪，Rego 有一个名为 **trace** 的函数，它接受一个字符串。将这个函数与 **sprintf** 结合使用，可以更容易地跟踪代码未按预期工作的位置。在 **chapter11/paramter-opa-policy-fail/rego** 目录中，有一个将失败的测试。还有一个添加了多个跟踪选项的 **invalidRegistry** 规则：

invalidRegistry {

跟踪(sprintf("input_images : %v",[input_images]))

ok_images = [image |

trace(sprintf("image %v",[input_images[j]]))

startswith(input_images[j],input.parameters.registries[_]) ;

image = input_images[j]

]

trace(sprintf("ok_images %v",[ok_images]))

trace(sprintf("ok_images size %v / input_images size %v",[count(ok_images),count(input_images)]))

count(ok_images) != count(input_images)

}

当测试运行时，OPA 将输出每个比较和代码路径的详细跟踪。无论在哪里遇到 **trace** 函数，跟踪中都会添加一个“注释”。这相当于在代码中添加打印语句进行调试。OPA 跟踪的输出非常冗长，包含的文本太多，无法包含在打印中。在此目录中运行 **opa test.** **-v** 将给你完整的跟踪，可以用来调试你的代码。

## 使用现有的政策

在进入更高级的 OPA 和 GateKeeper 的用例之前，了解 OPA 的构建和使用方式非常重要。如果你检查我们在上一节中工作过的代码，你可能会注意到我们没有检查 **initContainers**。我们只是寻找主要的容器。**initContainers** 是在预期 **Pod** 中列出的容器结束之前运行的特殊容器。它们通常用于准备卷挂载的文件系统和其他应在 **Pod** 的容器运行之前执行的“初始”任务。如果一个坏演员试图启动一个带有拉入比特币矿工（或更糟糕）的 **initContainers** 的 **Pod**，我们的策略将无法阻止它。

在设计和实施政策时非常详细是很重要的。确保在构建政策时不会遗漏任何东西的一种方法是使用已经存在并经过测试的政策。GateKeeper 项目在其 GitHub 存储库 https://github.com/open-policy-agent/gatekeeper/tree/master/library 中维护了几个经过预先测试的政策库以及如何使用它们。在尝试构建自己的政策之前，先看看那里是否已经存在一个。

本节概述了 Rego 及其在策略评估中的工作方式。它没有涵盖所有内容，但应该为您在使用 Rego 文档时提供一个良好的参考点。接下来，我们将学习如何构建依赖于我们请求之外的数据的策略，例如集群中的其他对象。

# 执行内存约束

到目前为止，在本章中，我们构建了自包含的策略。在检查图像是否来自预授权的注册表时，我们所需的唯一数据来自策略和容器。这通常不足以做出策略决策。在本节中，我们将致力于构建一个策略，依赖于集群中的其他对象来做出策略决策。

在深入实施之前，让我们谈谈用例。在提交到 API 服务器的任何 **Pod** 上至少包含内存要求是一个好主意。然而，有一些命名空间，这样做就没有太多意义。例如，**kube-system** 命名空间中的许多容器没有 CPU 和内存资源请求。

有多种方法可以处理这个问题。一种方法是部署一个约束模板，并将其应用到我们想要强制执行内存资源请求的每个命名空间。这可能会导致重复的对象，或者要求我们明确更新策略以将其应用于特定的命名空间。另一种方法是向命名空间添加一个标签，让 OPA 知道它需要所有 **Pod** 对象都具有内存资源请求。由于 Kubernetes 已经有了用于管理内存的 **ResourceQuota** 对象，我们还可以确定一个命名空间是否有 **ResourceQuota**，如果有的话，那么我们就知道应该有内存请求。

对于我们的下一个示例，我们将编写一个策略，该策略表示在具有 **ResourceQuota** 的命名空间中创建的任何 **Pod** 必须具有内存资源请求。策略本身应该非常简单。伪代码将看起来像这样：

if (hasResourceQuota(input.review.object.metdata.namespace) &&  containers.resource.requests.memory == null) {

生成错误;

}

这里的难点是要了解命名空间是否有**ResourceQuota**。Kubernetes 有一个 API，您可以查询，但这意味着要么将秘密嵌入到策略中，以便它可以与 API 服务器通信，要么允许匿名访问。这两个选项都不是一个好主意。另一个查询 API 服务器的问题是很难自动化测试，因为现在您依赖于一个 API 服务器在您运行测试的任何地方都可用。

我们之前讨论过，OPA 可以从 API 服务器复制数据到自己的数据库中。GateKeeper 使用这个功能来创建可以进行测试的对象的“缓存”。一旦这个缓存被填充，我们可以在本地复制它，为我们的策略测试提供测试数据。

## 启用 GateKeeper 缓存

通过在"gatekeeper-system"命名空间中创建一个**Config**对象来启用 GateKeeper 缓存。将此配置添加到您的集群中：

api 版本：config.gatekeeper.sh/v1alpha1

种类：Config

元数据：

名称：config

命名空间："gatekeeper-system"

规范：

同步：

仅同步：

- 组：""

版本："v1"

种类："命名空间"

- 组：""

版本："v1"

种类："ResourceQuota"

这将开始在 GateKeeper 的内部 OPA 数据库中复制**Namespace**和**ResourceQuota**对象。让我们创建一个带有**ResourceQuota**和一个不带**ResourceQuota**的**Namespace**： 

api 版本：v1

种类：命名空间

元数据：

名称：ns-with-no-quota

规范：{}

---

api 版本：v1

种类：命名空间

元数据：

名称：ns-with-quota

规范：{}

---

种类：ResourceQuota

api 版本：v1

元数据：

名称：memory-quota

命名空间：ns-with-quota

规范：

硬：

请求.memory：1G

限制.memory：1G

过一会儿，数据应该在 OPA 数据库中，并且准备好查询。

重要提示

GateKeeper 服务账户在默认安装中对集群中的所有内容都有读取权限。这包括秘密对象。在 GateKeeper 的缓存中复制什么要小心，因为在 Rego 策略内部没有安全控制。如果不小心，您的策略很容易记录秘密对象数据。另外，请确保控制谁可以访问**gatekeeper-system**命名空间。任何获得服务账户令牌的人都可以使用它来读取集群中的任何数据。

## 模拟测试数据

为了自动化测试我们的策略，我们需要创建测试数据。在之前的例子中，我们使用注入到**input**变量中的数据。缓存数据存储在**data**变量中。具体来说，为了访问我们的资源配额，我们需要访问**data.inventory.namespace["ns-with-quota"]["v1"]["ResourceQuota"]["memory-quota"]**。这是您在 GateKeeper 中从 Rego 查询数据的标准方式。就像我们对输入所做的那样，我们可以通过创建一个数据对象来注入这些数据的模拟版本。我们的 JSON 将如下所示：

{

"inventory": {

"namespace":{

"ns-with-no-quota" : {},

"ns-with-quota":{

"v1":{

"ResourceQuota": {

"memory-quota":{

"kind": "ResourceQuota",

"apiVersion": "v1",

"metadata": {

"name": "memory-quota",

"namespace": "ns-with-quota"

},

"spec": {

"hard": {

"requests.memory": "1G",

"limits.memory": "1G"

}}}}}}}}}

当您查看**chapter11/enforce-memory-request/rego/enforcememory_test.rego**时，您会看到测试中有**with input as {…} with data as {…}**，前面的文档作为我们的控制数据。这让我们能够测试我们的策略，使用 GateKeeper 中存在的数据，而无需在集群中部署我们的代码。

## 构建和部署我们的策略

就像以前一样，在编写策略之前，我们已经编写了测试用例。接下来，我们将检查我们的策略：

package k8senforcememoryrequests

违规[{"msg": msg, "details": {}}] {

invalidMemoryRequests

msg := "未指定内存请求"

}

invalidMemoryRequests {

数据。

库存

.namespace

[input.review.object.metadata.namespace]

["v1"]

["ResourceQuota"]

容器：= 输入审查对象规范容器

ok_containers = [ok_container |

containers[j].resources.requests.memory ;

ok_container = containers[j]  ]

count(containers) != count(ok_containers)

}

这段代码应该看起来很熟悉。它遵循了与我们先前策略相似的模式。第一个规则**violation**是 GateKeeper 的标准报告规则。第二个规则是我们测试**Pod**的地方。第一行将在指定**Pod**的命名空间不包含**ResourceQuota**对象时失败并退出。接下来的一行加载**Pod**的所有容器。之后，使用组合来构建具有指定内存请求的容器列表。最后，规则只有在符合条件的容器数量与总容器数量不匹配时才会成功。如果**invalidMemoryRequests**成功，这意味着一个或多个容器没有指定内存请求。这将强制**msg**被设置，并且**violation**通知用户存在问题。

要部署，请将**chapter11/enforce-memory-request/yaml/gatekeeper-policy-template.yaml**和**chapter11/enforce-memory-request/yaml/gatekeeper-policy.yaml**添加到您的集群中。要测试这一点，在我们的**ns-with-quota**和**ns-with-no-quota**命名空间中创建一个没有内存请求的**Pod**。

![图 11.7 - 创建没有内存请求的 Pod](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/k8s-dkr/img/Fig_11.7_B15514.jpg)

图 11.7 - 创建没有内存请求的 Pod

在**ns-with-quota**命名空间中创建**Pod**的第一次尝试失败，因为我们的**require-memory-requests**策略拒绝了它，因为**ns-with-quota**中有一个**ResourceQuota**。第二次尝试成功，因为它在没有**ResourceQuota**的命名空间中运行。

本章大部分时间都花在编写策略上。 OPA 的最终用例将专注于使用 GateKeeper 的预构建策略来替换 Pod 安全策略。

# 使用 OPA 执行 Pod 安全策略

在*第十章*，*创建 Pod 安全策略*中，我们讨论了 Kubernetes 现有的 Pod 安全策略实现永远不会成为"GA"的事实。使用 Kubernetes 实现的替代方案之一是使用 OPA 和 GateKeeper 来强制执行相同的策略，但是在 OPA 而不是在 API 服务器上。这个过程与 Kubernetes 的标准实现方式不同，但使用它可以使您的集群更加独立于供应商，并且不太容易受到 Kubernetes 的 Pod 安全策略未来变化的影响。

GateKeeper 的所有策略都发布在[`github.com/open-policy-agent/gatekeeper/tree/master/library/pod-security-policy`](https://github.com/open-policy-agent/gatekeeper/tree/master/library/pod-security-policy)。它们被构建为一系列**ConstraintTemplate**对象和示例约束。这种对 Pod 安全策略的方法导致了一些特定的差异，以及策略的实施方式。

第一个主要区别是使用 GateKeeper，您必须在 Pod 定义中声明所有内容，以便 GateKeeper 有东西可以进行审计。这在 Pod 安全策略中是不必要的，因为 Kubernetes 将改变 Pod 定义以符合策略。为了说明这一点，看看我们 KinD 集群中**openunison**命名空间中的**openunison-operator**的**Deployment**。没有声明**runAsUser**。现在看一下实际的 Pod 定义，您会看到**runAsUser**设置为**1**。GateKeeper 版本 3 目前还不支持 Pod 变异，因此为了确保**Deployment**或**Pod**具有设置**runAsUser**，需要一个单独的变异 webhook 来相应地设置**runAsUser**属性。

Kubernetes 标准策略实现和使用 GateKeeper 之间的下一个主要区别是 Pod 分配策略的方式。Kubernetes 标准实现使用 RBAC 的组合，利用提交者的帐户信息和**Pod**的**serviceAccount**，以及**Pod**请求的功能来确定使用哪个策略。这可能会导致一些意外的结果。相反，GateKeeper 提供了与 GateKeeper 实施的任何其他约束相同的匹配标准，使用命名空间和标签选择器。

例如，要使用特权约束来运行一个 Pod，您可以使用特定的**labelSelector**创建约束。然后，当提交 Pod 时，该标签需要在**Pod**上，这样 GateKeeper 就知道要应用它。这样可以更容易地明确地将策略应用于**Pod**。它并不涵盖如何强制执行资源的标记。您可能不希望某人能够将自己的**Pod**标记为特权。

最后，GateKeeper 的策略库被分解成多个部分，而不是作为一个对象的一部分。为了应用一个强制执行在特定用户范围内运行的非特权容器的策略，您需要两个单独的策略约束实现和两个单独的约束。

在撰写本文时，您无法在不进行重大额外工作的情况下复制我们在 *第十章* 中构建的内容，即 *创建 Pod 安全策略*。GateKeeper 项目的目标是在未来达到这一点。更完整的解决方案仍然是 Kubernetes 中 Pod 安全策略的标准实现。

# 总结

在本章中，我们探讨了如何使用 GateKeeper 作为动态准入控制器，在 Kubernetes 内置的 RBAC 能力之上提供额外的授权策略。我们看了 GateKeeper 和 OPA 的架构。最后，我们学习了如何在 Rego 中构建、部署和测试策略。

扩展 Kubernetes 的策略会增强集群的安全性配置，并且可以更加确信工作负载在集群上的完整性。使用 GateKeeper 也可以通过持续审计来帮助捕获先前被忽略的策略违规行为。利用这些功能将为您的集群提供更坚实的基础。

本章重点讨论了是否启动 **Pod**。在下一章中，我们将学习一旦激活，如何跟踪 **Pods** 的活动。

# 问题

1.  OPA 和 GateKeeper 是同一件事吗？

A. 是的。

B. 不是。

1.  Rego 代码存储在 GateKeeper 中的方式是什么？

A. 它被存储为被监视的 **ConfigMap** 对象。

B. Rego 必须挂载到 Pod 上。

C. Rego 需要存储为秘密对象。

D. Rego 被保存为 **ConstraintTemplate**。

1.  您如何测试 Rego 策略？

A. 在生产中

B. 使用直接内置到 OPA 中的自动化框架

C. 首先编译为 Web Assembly

1.  在 Rego 中，如何编写 **for** 循环？

A. 你不需要；Rego 将识别迭代步骤。

B. 使用 **for all** 语法。

C. 通过在循环中初始化计数器。

D. Rego 中没有循环。

1.  什么是调试 Rego 策略的最佳方法？

A. 使用 IDE 连接到集群中的 GateKeeper 容器。

B. 在生产中。

C. 向您的代码添加跟踪函数，并使用 **-v** 运行 **opa test** 命令以查看执行跟踪。

D. 包括 **System.out** 语句。

1.  所有约束都需要硬编码。

A. 真的。

B. 错误。

1.  GateKeeper 可以替代 Pod 安全策略。

A. 是的。

B. 错误。
