# Docker AWS 教程（七）

> 原文：[`zh.annas-archive.org/md5/13D3113D4BA58CEA008B572AB087A5F5`](https://zh.annas-archive.org/md5/13D3113D4BA58CEA008B572AB087A5F5)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十六章：AWS 中的 Docker Swarm

Docker Swarm 代表了 Docker 的本机容器管理平台，直接内置到 Docker Engine 中，对于许多第一次使用 Docker 的人来说，Docker Swarm 是他们首次了解和学习的容器管理平台，因为它是 Docker Engine 的集成功能。Docker Swarm 自然是 AWS 支持的 ECS、Fargate、弹性 Beanstalk 和最近的弹性 Kubernetes 服务（EKS）的竞争对手，因此您可能会想知道为什么一本关于 AWS 中的 Docker 的书会有一个专门介绍 Docker Swarm 的章节。许多组织更喜欢使用与云提供商无关的容器管理平台，可以在 AWS、谷歌云和 Azure 等其他云提供商以及本地运行，如果这对您和您的组织是这种情况，那么 Docker Swarm 肯定是值得考虑的选项。

在本章中，您将学习如何使用 Docker for AWS 解决方案将 Docker Swarm 部署到 AWS，该解决方案使得在 AWS 上快速启动和运行 Docker Swarm 集群变得非常容易。您将学习如何管理和访问 Swarm 集群的基础知识，如何创建和部署服务到 Docker Swarm，以及如何利用与 Docker for AWS 解决方案集成的许多 AWS 服务。这将包括将 Docker Swarm 与弹性容器注册表（ECR）集成，通过与 AWS 弹性负载均衡（ELB）集成将应用程序发布到外部世界，使用 AWS 弹性文件系统（EFS）创建共享卷，以及使用 AWS 弹性块存储（EBS）创建持久卷。

最后，您将学习如何解决关键的运营挑战，包括运行一次性部署任务，使用 Docker secrets 进行秘密管理，以及使用滚动更新部署应用程序。通过本章的学习，您将了解如何将 Docker Swarm 集群部署到 AWS，如何将 Docker Swarm 与 AWS 服务集成，以及如何将生产应用程序部署到 Docker Swarm。

本章将涵盖以下主题：

+   Docker Swarm 简介

+   安装 Docker for AWS

+   访问 Docker Swarm

+   将 Docker 服务部署到 Docker Swarm

+   将 Docker 堆栈部署到 Docker Swarm

+   将 Docker Swarm 与 ECR 集成

+   使用 EFS 创建共享 Docker 卷

+   使用 EBS 创建持久 Docker 卷

+   支持一次性部署任务

+   执行滚动更新

# 技术要求

以下是本章的技术要求：

+   对 AWS 账户的管理访问权限

+   本地环境按照第一章的说明进行配置

+   本地 AWS 配置文件，按照第三章的说明进行配置

+   AWS CLI 版本 1.15.71 或更高版本

+   Docker 18.06 CE 或更高版本

+   Docker Compose 1.22 或更高版本

+   GNU Make 3.82 或更高版本

本章假定您已经完成了本书中的所有前一章节

以下 GitHub URL 包含本章中使用的代码示例：[`github.com/docker-in-aws/docker-in-aws/tree/master/ch16`](https://github.com/docker-in-aws/docker-in-aws/tree/master/ch16)。

查看以下视频以查看代码的实际操作：

[`bit.ly/2ogdBpp`](http://bit.ly/2ogdBpp)

# Docker Swarm 介绍

**Docker Swarm**是 Docker Engine 的一个本地集成功能，提供集群管理和容器编排功能，允许您在生产环境中规模化运行 Docker 容器。每个运行版本 1.13 或更高版本的 Docker Engine 都包括在 swarm 模式下运行的能力，提供以下功能：

+   **集群管理**：所有在 swarm 模式下运行的节点都包括本地集群功能，允许您快速建立集群，以便部署您的应用程序。

+   **多主机网络**：Docker 支持覆盖网络，允许您创建虚拟网络，所有连接到网络的容器可以私下通信。这个网络层完全独立于连接 Docker Engines 的物理网络拓扑，这意味着您通常不必担心传统的网络约束，比如 IP 地址和网络分割——Docker 会为您处理所有这些。

+   **服务发现和负载均衡**：Docker Swarm 支持基于 DNS 的简单服务发现模型，允许您的应用程序发现彼此，而无需复杂的服务发现协议或基础设施。Docker Swarm 还支持使用 DNS 轮询自动负载均衡流量到您的应用程序，并可以集成外部负载均衡器，如 AWS Elastic Load Balancer 服务。

+   **服务扩展和滚动更新**：您可以轻松地扩展和缩小您的服务，当需要更新您的服务时，Docker 支持智能的滚动更新功能，并在部署失败时支持回滚。

+   声明式服务模型：Docker Swarm 使用流行的 Docker Compose 规范来声明性地定义应用程序服务、网络、卷等，以易于理解和维护的格式。

+   **期望状态**：Docker Swarm 持续监视应用程序和运行时状态，确保您配置的服务按照期望的状态运行。例如，如果您配置一个具有 2 个实例或副本计数的服务，Docker Swarm 将始终尝试维持这个计数，并在现有节点失败时自动部署新的副本到新节点。

+   **生产级运维功能，如秘密和配置管理**：一些功能，如 Docker 秘密和 Docker 配置，是 Docker Swarm 独有的，并为实际的生产问题提供解决方案，例如安全地将秘密和配置数据分发给您的应用程序。

在 AWS 上运行 Docker Swarm 时，Docker 提供了一个名为 Docker for AWS CE 的社区版产品，您可以在[`store.docker.com/editions/community/docker-ce-aws`](https://store.docker.com/editions/community/docker-ce-aws)找到更多信息。目前，Docker for AWS CE 是通过预定义的 CloudFormation 模板部署的，该模板将 Docker Swarm 与许多 AWS 服务集成在一起，包括 EC2 自动扩展、弹性负载均衡、弹性文件系统和弹性块存储。很快您将会看到，这使得在 AWS 上快速搭建一个新的 Docker Swarm 集群变得非常容易。

# Docker Swarm 与 Kubernetes 的比较

首先，正如本书的大部分内容所证明的那样，我是一个 ECS 专家，如果您的容器工作负载完全在 AWS 上运行，那么我的建议，至少在撰写本书时，几乎总是会选择 ECS。然而，许多组织不想被锁定在 AWS 上，他们希望采用云无关的方法，这就是 Docker Swarm 目前是其中一种领先的解决方案的原因。

目前，Docker Swarm 与 Kubernetes 直接竞争，我们将在下一章讨论。可以说，Kubernetes 似乎已经确立了自己作为首选的云无关容器管理平台，但这并不意味着您一定要忽视 Docker Swarm。

总的来说，我个人认为 Docker Swarm 更容易设置和使用，至少对我来说，一个关键的好处是它使用熟悉的工具，比如 Docker Compose，这意味着你可以非常快速地启动和运行，特别是如果你之前使用过这些工具。对于只想快速启动并确保事情顺利进行的较小组织来说，Docker Swarm 是一个有吸引力的选择。Docker for AWS 解决方案使在 AWS 中建立 Docker Swarm 集群变得非常容易，尽管 AWS 最近通过推出弹性 Kubernetes 服务（EKS）大大简化了在 AWS 上使用 Kubernetes 的过程——关于这一点，我们将在下一章中详细介绍。

最终，我鼓励你以开放的心态尝试两者，并根据你和你的组织目标的最佳容器管理平台做出自己的决定。

# 安装 Docker for AWS

在 AWS 中快速启动 Docker Swarm 的推荐方法是使用 Docker for AWS，你可以在[`docs.docker.com/docker-for-aws/`](https://docs.docker.com/docker-for-aws/)上了解更多。如果你浏览到这个页面，在设置和先决条件部分，你将看到允许你安装 Docker 企业版（EE）和 Docker 社区版（CE）for AWS 的链接。

我们将使用免费的 Docker CE for AWS（稳定版），请注意你可以选择部署到全新的 VPC 或现有的 VPC：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/b3c18990-a854-4275-925f-e86d1f0410e2.png)选择 Docker CE for AWS 选项

鉴于我们已经有一个现有的 VPC，如果你点击部署 Docker CE for AWS（稳定版）用户现有的 VPC 选项，你将被重定向到 AWS CloudFormation 控制台，在那里你将被提示使用 Docker 发布的模板创建一个新的堆栈：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/5df1c0f5-b40b-442c-9b7b-2c67dea80f12.png)

创建 Docker for AWS 堆栈

点击下一步后，你将被提示指定一些参数，这些参数控制了你的 Docker Swarm Docker 安装的配置。我不会描述所有可用的选项，所以假设对于我没有提到的任何参数，你应该保留默认配置。

+   **堆栈名称**：为你的堆栈指定一个合适的名称，例如 docker-swarm。

+   **Swarm Size**: 在这里，您可以指定 Swarm 管理器和工作节点的数量。最少可以指定一个管理器，但我建议还配置一个工作节点，以便您可以测试将应用程序部署到多节点 Swarm 集群。

+   **Swarm Properties**: 在这里，您应该配置 Swarm EC2 实例以使用您现有的管理员 SSH 密钥（EC2 密钥对），并启用创建 EFS 存储属性的先决条件，因为我们将在本章后面使用 EFS 提供共享卷。

+   **Swarm Manager Properties**: 将 Manager 临时存储卷类型更改为 gp2（SSD）。

+   **Swarm Worker Properties**: 将工作节点临时存储卷类型更改为 gp2（SSD）。

+   **VPC/网络**: 选择现有的默认 VPC，然后确保您指定选择 VPC 时显示的 VPC CIDR 范围（例如`172.31.0.0/16`），然后从默认 VPC 中选择适当的子网作为公共子网 1 至 3。

完成上述配置后，点击两次“下一步”按钮，最后在“审阅”屏幕上，选择“我承认 AWS CloudFormation 可能创建 IAM 资源”选项，然后点击“创建”按钮。

此时，您的新 CloudFormation 堆栈将被创建，并且应在 10-15 分钟内完成。请注意，如果您想要增加集群中的管理器和/或工作节点数量，建议的方法是执行 CloudFormation 堆栈更新，修改定义管理器和工作节点计数的适当输入参数。另外，要升级 Docker for AWS Swarm Cluster，您应该应用包含 Docker Swarm 和其他各种资源更新的最新 CloudFormation 模板。

# 由 Docker for AWS CloudFormation 堆栈创建的资源

如果您在 CloudFormation 控制台的新堆栈中查看资源选项卡，您将注意到创建了各种资源，其中最重要的资源列在下面：

+   **CloudWatch 日志组**: 这存储了通过您的 Swarm 集群安排的所有容器日志。只有在堆栈创建期间启用了使用 Cloudwatch 进行容器日志记录参数时（默认情况下，此参数已启用），才会创建此资源。

+   **外部负载均衡器**: 创建了一个经典的弹性负载均衡器，用于发布对您的 Docker 应用程序的公共访问。

+   **弹性容器注册表 IAM 策略**：创建了一个 IAM 策略，并附加到所有 Swarm 管理器和工作节点 EC2 实例角色，允许对 ECR 进行读取/拉取访问。如果您将 Docker 镜像存储在 ECR 中，这是必需的，适用于我们的场景。

+   **其他资源**：还创建了各种资源，例如用于集群管理操作的 DynamoDB 表，以及用于 EC2 自动扩展生命周期挂钩的简单队列服务（SQS）队列，用于 Swarm 管理器升级场景。

如果单击“输出”选项卡，您会注意到一个名为 DefaultDNSTarget 的输出属性，它引用了外部负载均衡器的公共 URL。请注意这个 URL，因为稍后在本章中，示例应用将可以从这里访问：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/0b5dd42f-03a6-4ac0-ae85-7e7b9d625a70.png)Docker for AWS 堆栈输出

# 访问 Swarm 集群

在 CloudFormation 堆栈输出中，还有一个名为 Managers 的属性，它提供了指向每个 Swarm 管理器的 EC2 实例的链接：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/12a015a1-5fcc-4756-abf3-d7312af16cac.png)Swarm Manager 自动扩展组

您可以使用这些信息来获取您的 Swarm 管理器之一的公共 IP 地址或 DNS 名称。一旦您有了这个 IP 地址，您就可以建立到管理器的 SSH 连接。

```
> ssh -i ~/.ssh/admin.pem docker@54.145.175.148
The authenticity of host '54.145.175.148 (54.145.175.148)' can't be established.
ECDSA key fingerprint is SHA256:Br/8IMAuEzPOV29B8zdbT6H+DjK9sSEEPSbXdn+v0YM.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '54.145.175.148' (ECDSA) to the list of known hosts.
Welcome to Docker!
~ $ docker ps --format "{{ .ID }}: {{ .Names }}"
a5a2dfe609e4: l4controller-aws
0d7f5d2ae4a0: meta-aws
d54308064314: guide-aws
58cb47dad3e1: shell-aws
```

请注意，当访问管理器时，您必须指定一个用户名为`docker`，如果运行`docker ps`命令，您会看到默认情况下管理器上运行着四个系统容器：

+   **shell-aws**：这提供了对管理器的 SSH 访问，这意味着您建立到 Swarm 管理器的 SSH 会话实际上是在这个容器内运行的。

+   **meta-aws**：提供通用的元数据服务，包括提供允许新成员加入集群的令牌。

+   **guide-aws**：执行集群状态管理操作，例如将每个管理器添加到 DynamoDB，以及其他诸如清理未使用的镜像和卷以及停止的容器等日常任务。

+   **l4controller-aws**：管理与 Swarm 集群的外部负载均衡器的集成。该组件负责发布新端口，并确保它们可以在弹性负载均衡器上访问。请注意，您不应直接修改集群的 ELB，而应依赖`l4controller-aws`组件来管理 ELB。

要查看和访问集群中的其他节点，您可以使用`docker node ls`命令：

```
> docker node ls
ID                         HOSTNAME                      STATUS   MANAGER STATUS   ENGINE VERSION
qna4v46afttl007jq0ec712dk  ip-172-31-27-91.ec2.internal  Ready                     18.03.0-ce
ym3jdy1ol17pfw7emwfen0b4e* ip-172-31-40-246.ec2.internal Ready    Leader           18.03.0-ce
> ssh docker@ip-172-31-27-91.ec2.internal Permission denied (publickey,keyboard-interactive).
```

请注意，工作节点不允许公共 SSH 访问，因此您只能通过管理器从 SSH 访问工作节点。然而，有一个问题：鉴于管理节点没有本地存储管理员 EC2 密钥对的私钥，您无法建立与工作节点的 SSH 会话。

# 设置本地访问 Docker Swarm

虽然您可以通过 SSH 会话远程运行 Docker 命令到 Swarm 管理器，但是能够使用本地 Docker 客户端与远程 Swarm 管理器守护程序进行交互要容易得多，在那里您可以访问本地 Docker 服务定义和配置。我们还有一个问题，即无法通过 SSH 访问工作节点，我们可以通过使用 SSH 代理转发和 SSH 隧道这两种技术来解决这两个问题。

# 配置 SSH 代理转发

设置 SSH 代理转发，首先使用`ssh-add`命令将您的管理员 SSH 密钥添加到本地 SSH 代理中：

```
> ssh-add -K ~/.ssh/admin.pem
Identity added: /Users/jmenga/.ssh/admin.pem (/Users/jmenga/.ssh/admin.pem)
> ssh-add -L
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCkF7aAzIRayGHiiR81wcz/k9b+ZdmAEkdIBU0pOvAaFYjrDPf4JL4I0rJjdpFBjFZIqKXM9dLWg0skENYSUl9pfLT+CzValQat/XpBw/HfwzbzMy8wqcKehN0pB4V1bpzfOYe7lTLmTYIQ/21wW63QVlZnNyV1VZiVgN5DcLqgiG5CHHAooMIbiExAYvRrgo8XEXoqFRODLwIn4HZ7OAtojWzxElBx+EC4lmDekykgxnfGd30QgATIEF8/+UzM17j91JJohfxU7tA3GhXkScMBXnxBhdOftVvtB8/bGc+DHjJlkYSxL20792eBEv/ZsooMhNFxGLGhidrznmSeC8qL /Users/jmenga/.ssh/admin.pem
```

`-K`标志是特定于 macOS 的，并将您的 SSH 密钥的密码添加到您的 OS X 钥匙串中，这意味着此配置将在重新启动后持续存在。如果您不使用 macOS，可以省略`-K`标志。

现在您可以使用`-A`标志访问您的 Swarm 管理器，该标志配置 SSH 客户端使用您的 SSH 代理身份。使用 SSH 代理还可以启用 SSH 代理转发，这意味着用于与 Swarm 管理器建立 SSH 会话的 SSH 密钥可以自动用于或转发到您可能在 SSH 会话中建立的其他 SSH 连接：

```
> ssh -A docker@54.145.175.148
Welcome to Docker!
~ $ ssh docker@ip-172-31-27-91.ec2.internal
Welcome to Docker!
```

如您所见，使用 SSH 代理转发解决了访问工作节点的问题。

# 配置 SSH 隧道

**SSH 隧道**是一种强大的技术，允许您通过加密的 SSH 会话安全地隧道网络通信到远程主机。 SSH 隧道通过暴露一个本地套接字或端口，该套接字或端口连接到远程主机上的远程套接字或端口。这可以产生您正在与本地服务通信的错觉，当与 Docker 一起工作时特别有用。

以下命令演示了如何使运行在 Swarm 管理器上的 Docker 套接字显示为运行在本地主机上的端口：

```
> ssh -i ~/.ssh/admin.pem -NL localhost:2374:/var/run/docker.sock docker@54.145.175.148 &
[1] 7482
> docker -H localhost:2374 ps --format "{{ .ID }}: {{ .Names }}"
a5a2dfe609e4: l4controller-aws
0d7f5d2ae4a0: meta-aws
d54308064314: guide-aws
58cb47dad3e1: shell-aws
> export DOCKER_HOST=localhost:2374
> docker node ls --format "{{ .ID }}: {{ .Hostname }}" qna4v46afttl007jq0ec712dk: ip-172-31-27-91.ec2.internal
ym3jdy1ol17pfw7emwfen0b4e: ip-172-31-40-246.ec2.internal
```

传递给第一个 SSH 命令的`-N`标志指示客户端不发送远程命令，而`-L`或本地转发标志配置了将本地主机上的 TCP 端口`2374`映射到远程 Swarm 管理器上的`/var/run/docker.sock` Docker Engine 套接字。命令末尾的和符号（`&`）使命令在后台运行，并将进程 ID 作为此命令的输出发布。

有了这个配置，现在您可以运行 Docker 客户端，本地引用`localhost:2374`作为连接到远程 Swarm 管理器的本地端点。请注意，您可以使用`-H`标志指定主机，也可以通过导出环境变量`DOCKER_HOST`来指定主机。这将允许您在引用本地文件的同时执行远程 Docker 操作，从而更轻松地管理和部署到 Swarm 集群。

尽管 Docker 确实包括了一个客户端/服务器模型，可以在 Docker 客户端和远程 Docker Engine 之间进行通信，但要安全地进行这样的通信需要相互传输层安全性（TLS）和公钥基础设施（PKI）技术，这些技术设置和维护起来很复杂。使用 SSH 隧道来暴露远程 Docker 套接字要容易得多，而且被认为与任何形式的远程 SSH 访问一样安全。

# 将应用程序部署到 Docker Swarm

现在您已经使用 Docker for AWS 安装了 Docker Swarm，并建立了与 Swarm 集群的管理连接，我们准备开始部署应用程序。将应用程序部署到 Docker Swarm 需要使用`docker service`和`docker stack`命令，这些命令在本书中尚未涉及，因此在处理 todobackend 应用程序的部署之前，我们将通过部署一些示例应用程序来熟悉这些命令。

# Docker 服务

尽管您在 Swarm 集群中可以技术上部署单个容器，但应避免这样做，并始终使用 Docker *服务*作为部署到 Swarm 集群的标准单位。实际上，我们已经使用 Docker Compose 来使用 Docker 服务，但是与 Docker Swarm 一起使用时，它们被提升到了一个新的水平。

要创建一个 Docker 服务，您可以使用`docker service create`命令，下面的示例演示了如何使用流行的 Nginx Web 服务器搭建一个非常简单的 Web 应用程序：

```
> docker service create --name nginx --publish published=80,target=80 --replicas 2 nginx ez24df69qb2yq1zhyxma38dzo
overall progress: 2 out of 2 tasks
1/2: running [==================================================>]
2/2: running [==================================================>]
verify: Service converged
> docker service ps --format "{{ .ID }} ({{ .Name }}): {{ .Node }} {{ .CurrentState }}" nginx 
```

```
wcq6jfazrums (nginx.1): ip-172-31-27-91.ec2.internal  Running 2 minutes ago
i0vj5jftf6cb (nginx.2): ip-172-31-40-246.ec2.internal Running 2 minutes ago
```

`--name`标志为服务提供了友好的名称，而`--publish`标志允许您发布服务将从中访问的外部端口（在本例中为端口`80`）。`--replicas`标志定义了服务应部署多少个容器，最后您指定了要运行的服务的图像的名称（在本例中为 nginx）。请注意，您可以使用`docker service ps`命令来列出运行服务的各个容器和节点。

如果现在尝试浏览外部负载均衡器的 URL，您应该收到默认的**Welcome to nginx!**网页：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/13d5f811-507a-4314-8724-213ed904269e.png)Nginx 欢迎页面要删除一个服务，您可以简单地使用`docker service rm`命令：

```
> docker service rm nginx
nginx
```

# Docker 堆栈

**Docker 堆栈**被定义为一个复杂的、自包含的环境，由多个服务、网络和/或卷组成，并在 Docker Compose 文件中定义。

一个很好的 Docker 堆栈的例子，将立即为我们的 Swarm 集群增加一些价值，是一个名为**swarmpit**的开源 Swarm 管理工具，您可以在[`swarmpit.io/`](https://swarmpit.io/)上了解更多。要开始使用 swarmpit，请克隆[`github.com/swarmpit/swarmpit`](https://github.com/swarmpit/swarmpit)存储库到本地文件夹，然后打开存储库根目录中的`docker-compose.yml`文件。

```
version: '3.6'

services:
```

```

  app:
    image: swarmpit/swarmpit:latest
    environment:
      - SWARMPIT_DB=http://db:5984
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    ports:
 - target: 8080
 published: 8888
 mode: ingress
    networks:
      - net
    deploy:
      resources:
        limits:
          cpus: '0.50'
          memory: 1024M
        reservations:
          cpus: '0.25'
          memory: 512M
      placement:
        constraints:
          - node.role == manager

  db:
    image: klaemo/couchdb:2.0.0
    volumes:
      - db-data:/opt/couchdb/data
    networks:
      - net
    deploy:
      resources:
        limits:
          cpus: '0.30'
          memory: 512M
        reservations:
          cpus: '0.15'
          memory: 256M
 placement:
 constraints:
 - node.role == manager

  agent:
    ...
    ...

networks:
  net:
    driver: overlay

volumes:
  db-data:
    driver: local
```

我已经突出显示了对文件的修改，即将 Docker Compose 文件规范版本更新为 3.6，修改 app 服务的端口属性，以便在端口 8888 上外部发布管理 UI，并确保数据库仅部署到集群中的 Swarm 管理器。固定数据库的原因是确保在任何情况下，如果数据库容器失败，Docker Swarm 将尝试将数据库容器重新部署到存储本地数据库卷的同一节点。

如果您意外地擦除了 swarmpit 数据库，请注意管理员密码将被重置为默认值 admin，如果您已将 swarmpit 管理界面发布到公共互联网上，这将构成重大安全风险。

有了这些更改，现在可以运行`docker stack deploy`命令来部署 swarmpit 管理应用程序：

```
> docker stack deploy -c docker-compose.yml swarmpit
Creating network swarmpit_net
Creating service swarmpit_agent
Creating service swarmpit_app
Creating service swarmpit_db
> docker stack services swarmpit
ID            NAME            MODE        REPLICAS  IMAGE                     PORTS
8g5smxmqfc6a  swarmpit_app    replicated  1/1       swarmpit/swarmpit:latest  *:8888->8080/tcp
omc7ewvqjecj  swarmpit_db     replicated  1/1
```

```
klaemo/couchdb:2.0.0
u88gzgeg8rym  swarmpit_agent  global      2/2       swarmpit/agent:latest
```

您可以看到`docker stack deploy`命令比`docker service create`命令简单得多，因为 Docker Compose 文件包含了所有的服务配置细节。在端口 8888 上浏览您的外部 URL，并使用默认用户名和密码`admin`/`admin`登录，然后立即通过选择右上角的管理员下拉菜单并选择**更改密码**来更改管理员密码。更改管理员密码后，您可以查看 swarmpit 管理 UI，该界面提供了有关您的 Swarm 集群的大量信息。以下截图展示了**基础设施** | **节点**页面，其中列出了集群中的节点，并显示了每个节点的详细信息：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/77a22746-4832-40ca-b63a-1eefeb5c58d6.png)swarmkit 管理界面

# 将示例应用部署到 Docker Swarm

我们现在进入了本章的业务端，即将我们的示例 todobackend 应用部署到新创建的 Docker swarm 集群。正如你所期望的那样，我们将遇到一些挑战，需要执行以下配置任务：

+   将 Docker Swarm 集成到弹性容器注册表

+   定义堆栈

+   创建用于托管静态内容的共享存储

+   创建 collectstatic 服务

+   创建用于存储 todobackend 数据库的持久性存储

+   使用 Docker Swarm 进行秘密管理

+   运行数据库迁移

# 将 Docker Swarm 集成到弹性容器注册表

todobackend 应用已经发布在现有的弹性容器注册表（ECR）存储库中，理想情况下，我们希望能够集成我们的 Docker swarm 集群，以便我们可以从 ECR 拉取私有镜像。截至撰写本书时，ECR 集成在某种程度上得到支持，即您可以在部署时将注册表凭据传递给 Docker swarm 管理器，这些凭据将在集群中的所有节点之间共享。但是，这些凭据在 12 小时后会过期，目前没有本机机制来自动刷新这些凭据。

为了定期刷新 ECR 凭据，以便您的 Swarm 集群始终可以从 ECR 拉取镜像，您需要执行以下操作：

+   确保您的管理器和工作节点具有从 ECR 拉取的权限。Docker for AWS CloudFormation 模板默认配置了此访问权限，因此您不必担心配置此项。

+   将`docker-swarm-aws-ecr-auth`自动登录系统容器部署为服务，发布在[`github.com/mRoca/docker-swarm-aws-ecr-auth`](https://github.com/mRoca/docker-swarm-aws-ecr-auth)。安装后，此服务会自动刷新集群中所有节点上的 ECR 凭据。

要部署`docker-swarm-aws-ecr-auth`服务，您可以使用以下`docker service create`命令：

```
> docker service create \
    --name aws_ecr_auth \
    --mount type=bind,source=/var/run/docker.sock,destination=/var/run/docker.sock \
    --constraint 'node.role == manager' \
    --restart-condition 'none' \
    --detach=false \
    mroca/swarm-aws-ecr-auth
lmf37a9pbzc3nzhe88s1nzqto
overall progress: 1 out of 1 tasks
1/1: running [==================================================>]
verify: Service converged
```

请注意，一旦此服务启动运行，您必须为使用 ECR 镜像部署的任何服务包括`--with-registry-auth`标志。

以下代码演示了使用`docker service create`命令部署 todobackend 应用程序，以及`--with-registry-auth`标志：

```
> export AWS_PROFILE=docker-in-aws
> $(aws ecr get-login --no-include-email)
WARNING! Using --password via the CLI is insecure. Use --password-stdin.
Login Succeeded
> docker service create --name todobackend --with-registry-auth \
 --publish published=80,target=8000 --env DJANGO_SETTINGS_MODULE=todobackend.settings_release\
 385605022855.dkr.ecr.us-east-1.amazonaws.com/docker-in-aws/todobackend \
 uwsgi --http=0.0.0.0:8000 --module=todobackend.wsgi p71rje93a6pqvipqf2a14v6cc
overall progress: 1 out of 1 tasks
1/1: running [==================================================>]
verify: Service converged
```

您可以通过浏览到外部负载均衡器 URL 来验证 todobackend 服务确实已部署：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/c4dd84d5-c966-4f0d-adcc-8539b3ca7ff6.png)部署 todobackend 服务

请注意，因为我们还没有生成任何静态文件，todobackend 服务缺少静态内容。稍后当我们创建 Docker Compose 文件并为 todobackend 应用程序部署堆栈时，我们将解决这个问题。

# 定义一个堆栈

虽然您可以使用`docker service create`等命令部署服务，但是您可以使用`docker stack deploy`命令非常快速地部署完整的多服务环境，引用捕获各种服务、网络和卷配置的 Docker Compose 文件，构成您的堆栈。将堆栈部署到 Docker Swarm 需要 Docker Compose 文件规范的版本 3，因此我们不能使用`todobackend`存储库根目录下的现有`docker-compose.yml`文件来定义我们的 Docker Swarm 环境，并且我建议保持开发和测试工作流分开，因为 Docker Compose 版本 2 规范专门支持适用于持续交付工作流的功能。

现在，让我们开始为 todobackend 应用程序定义一个堆栈，我们可以通过在`todobackend`存储库的根目录创建一个名为`stack.yml`的文件来部署到 AWS 的 Docker Swarm 集群中：

```
version: '3.6'

networks:
  net:
    driver: overlay

services:
  app:
    image: 385605022855.dkr.ecr.us-east-1.amazonaws.com/docker-in-aws/todobackend
    ports:
      - target: 8000
        published: 80
    networks:
      - net
    environment:
      DJANGO_SETTINGS_MODULE: todobackend.settings_release
    command:
      - uwsgi
      - --http=0.0.0.0:8000
      - --module=todobackend.wsgi
      - --master
      - --die-on-term
      - --processes=4
      - --threads=2
      - --check-static=/public
```

```

    deploy:
      replicas: 2
      update_config:
        parallelism: 1
        delay: 30s

```

我们指定的第一个属性是强制性的`version`属性，我们将其定义为 3.6 版本，这是在撰写本书时支持的最新版本。接下来，我们配置顶级网络属性，该属性指定了堆栈将使用的 Docker 网络。您将创建一个名为`net`的网络，该网络实现了`overlay`驱动程序，该驱动程序在 Swarm 集群中的所有节点之间创建了一个虚拟网络段，堆栈中定义的各种服务可以在其中相互通信。通常，您部署的每个堆栈都应该指定自己的覆盖网络，这样可以在每个堆栈之间提供分割，并且无需担心集群的 IP 寻址或物理网络拓扑。

接下来，您必须定义一个名为`app`的单个服务，该服务代表了主要的 todobackend web 应用程序，并通过`image`属性指定了您在之前章节中发布的 todobackend 应用程序的完全限定名称的 ECR 镜像。请注意，Docker 堆栈不支持`build`属性，必须引用已发布的 Docker 镜像，这是为什么您应该始终为开发、测试和构建工作流程分别拥有单独的 Docker Compose 规范的一个很好的理由。

`ports`属性使用了长格式配置语法（在之前的章节中，您使用了短格式语法），这提供了更多的配置选项，允许您指定容器端口 8000（由`target`属性指定）将在端口 80 上对外发布（由`published`属性指定），而`networks`属性配置`app`服务附加到您之前定义的`net`网络。请注意，`environment`属性没有指定任何数据库配置设置，现在的重点只是让应用程序运行起来，尽管状态可能有些混乱，但我们将在本章后面配置数据库访问。

最后，`deploy`属性允许您控制服务的部署方式，`replica`属性指定部署两个服务实例，`update_config`属性配置滚动更新，以便一次更新一个实例（由`parallelism`属性指定），每个更新实例之间延迟 30 秒。

有了这个配置，您现在可以使用`docker stack deploy`命令部署您的堆栈了：

```
> $(aws ecr get-login --no-include-email)
WARNING! Using --password via the CLI is insecure. Use --password-stdin.
Login Succeeded
> docker stack deploy --with-registry-auth -c stack.yml todobackend Creating network todobackend_net
Creating service todobackend_app
> docker service ps todobackend_app --format "{{ .Name }} -> {{ .Node }} ({{ .CurrentState }})"
todobackend_app.1 -> ip-172-31-27-91.ec2.internal (Running 6 seconds ago)
todobackend_app.2 -> ip-172-31-40-246.ec2.internal (Running 6 seconds ago)
```

请注意，我首先登录到 ECR——这一步并非绝对必需，但如果未登录到 ECR，Docker 客户端将无法确定与最新标签关联的当前图像哈希，并且会出现以下警告：

```
> docker stack deploy --with-registry-auth -c stack.yml todobackend image 385605022855.dkr.ecr.us-east-1.amazonaws.com/docker-in-aws/todobackend:latest could not be accessed on a registry to record
its digest. Each node will access 385605022855.dkr.ecr.us-east-1.amazonaws.com/docker-in-aws/todobackend:latest independently,
possibly leading to different nodes running different
versions of the image.
...
...
```

如果您现在浏览外部负载均衡器 URL，todobackend 应用程序应该加载，但您会注意到应用程序缺少静态内容，如果您尝试访问 `/todos`，将会出现数据库配置错误，这是可以预料的，因为我们尚未配置任何数据库设置或考虑如何在 Docker Swarm 中运行 **collectstatic** 过程。

# 为托管静态内容创建共享存储

Docker for AWS 解决方案包括 Cloudstor 卷插件，这是由 Docker 构建的存储插件，旨在支持流行的云存储机制以实现持久存储。

在 AWS 的情况下，此插件提供了与以下类型的持久存储的开箱即用集成：

+   **弹性块存储**（**EBS**）：提供面向专用（非共享）访问的块级存储。这提供了高性能，能够将卷分离和附加到不同的实例，并支持快照和恢复操作。EBS 存储适用于数据库存储或任何需要高吞吐量和最小延迟来读写本地数据的应用程序。

+   **弹性文件系统**（**EFS**）：使用 **网络文件系统**（**NFS**）版本 4 协议提供共享文件系统访问。NFS 允许在多个主机之间同时共享存储，但这比 EBS 存储要低得多。NFS 存储适用于共享常见文件并且不需要高性能的应用程序。在之前部署 Docker for AWS 解决方案时，您选择了为 EFS 创建先决条件，这为 Cloudstor 卷插件集成了一个用于 Swarm 集群的 EFS 文件系统。

正如您在之前的章节中所了解的，todobackend 应用程序对存储静态内容有特定要求，尽管我通常不建议将 EFS 用于这种用例，但静态内容的要求代表了一个很好的机会，可以演示如何在 Docker Swarm 环境中配置和使用 EFS 作为共享卷。

```
version: '3.6'

networks:
  net:
    driver: overlay

volumes:
 public:
 driver: cloudstor:aws
 driver_opts:
 backing: shared

services:
  app:
    image: 385605022855.dkr.ecr.us-east-1.amazonaws.com/docker-in-aws/todobackend
    ports:
      - target: 8000
        published: 80
    networks:
```

```

      - net
 volumes:
 - public:/public
    ...
    ...
```

首先，您必须创建一个名为`public`的卷，并指定驱动程序为`cloudstor:aws`，这可以确保 Cloudstor 驱动程序加载了 AWS 支持。要创建一个 EFS 卷，您只需配置一个名为`backing`的驱动选项，值为`shared`，然后在`app`服务中挂载到`/public`。

如果您现在使用`docker stack deploy`命令部署您的更改，卷将被创建，并且`app`服务实例将被更新：

```
> docker stack deploy --with-registry-auth -c stack.yml todobackend
Updating service todobackend_app (id: 59gpr2x9n7buikeorpf0llfmc)
> docker volume ls
DRIVER          VOLUME NAME
local           bd3d2804c796064d6e7c4040040fd474d9adbe7aaf68b6e30b1d195b50cdefde
local           sshkey
cloudstor:aws   todobackend_public
>  docker service ps todobackend_app \
 --format "{{ .Name }} -> {{ .DesiredState }} ({{ .CurrentState }})"
todobackend_app.1 -> Running (Running 44 seconds ago)
todobackend_app.1 -> Shutdown (Shutdown 45 seconds ago)
todobackend_app.2 -> Running (Running 9 seconds ago)
todobackend_app.2 -> Shutdown (Shutdown 9 seconds ago)
```

您可以使用`docker volume ls`命令查看当前卷，您会看到一个新的卷，根据约定命名为`<stack name>_<volume name>`（例如，`todobackend_public`），并且驱动程序为`cloudstor:aws`。请注意，`docker service ps`命令输出显示`todobackend.app.1`首先被更新，然后 30 秒后`todobackend.app.2`被更新，这是基于您在`app`服务的`deploy`设置中应用的早期滚动更新配置。

要验证卷是否成功挂载，您可以使用`docker ps`命令查询 Swarm 管理器上运行的任何 app 服务容器，然后使用`docker exec`来验证`/public`挂载是否存在，并且`app`用户可以读写 todobackend 容器运行的。

```
> docker ps -f name=todobackend -q
60b33d8b0bb1
> docker exec -it 60b33d8b0bb1 touch /public/test
> docker exec -it 60b33d8b0bb1 ls -l /public
total 4
-rw-r--r-- 1 app app 0 Jul 19 13:45 test
```

一个重要的要点是，在前面的示例中显示的`docker volume`和其他`docker`命令只在您连接的当前 Swarm 节点的上下文中执行，并且不会显示卷或允许您访问集群中其他节点上运行的容器。要验证卷确实是共享的，并且可以被我们集群中其他 Swarm 节点上运行的 app 服务容器访问，您需要首先 SSH 到 Swarm 管理器，然后 SSH 到集群中的单个工作节点：

```
> ssh -A docker@54.145.175.148
Welcome to Docker!
~ $ docker node ls
ID                          HOSTNAME                        STATUS  MANAGER  STATUS
qna4v46afttl007jq0ec712dk   ip-172-31-27-91.ec2.internal    Ready   Active 
ym3jdy1ol17pfw7emwfen0b4e * ip-172-31-40-246.ec2.internal   Ready   Active   Leader
> ssh docker@ip-172-31-27-91.ec2.internal
Welcome to Docker!
> docker ps -f name=todobackend -q
71df5495080f
~ $ docker exec -it 71df5495080f ls -l /public
total 4
-rw-r--r-- 1 app app 0 Jul 19 13:58 test
~ $ docker exec -it 71df5495080f rm /public/test
```

正如您所看到的，该卷在工作节点上是可用的，可以看到我们在另一个实例上创建的`/public/test`文件，证明该卷确实是共享的，并且可以被所有`app`服务实例访问，而不管底层节点如何。

# 创建一个 collectstatic 服务

现在您已经有了一个共享卷，我们需要考虑如何定义和执行 collectstatic 过程来生成静态内容。迄今为止，在本书中，您已经将 collectstatic 过程作为一个需要在定义的部署序列中的特定时间发生的命令式任务执行，然而 Docker Swarm 提倡最终一致性的概念，因此您应该能够部署您的堆栈，并且有一个可能失败但最终会成功的 collectstatic 过程运行，此时达到了应用程序的期望状态。这种方法与我们之前采取的命令式方法非常不同，但被认为是良好架构的现代云原生应用程序的最佳实践。

为了演示这是如何工作的，我们首先需要拆除 todobackend 堆栈，这样您就可以观察在 Docker 存储引擎创建和挂载 EFS 支持的卷时 collectstatic 过程中将发生的失败：

```
> docker stack rm todobackend
Removing service todobackend_app
Removing network todobackend_net
> docker volume ls
DRIVER         VOLUME NAME
local          sshkey
cloudstor:aws  todobackend_public
> docker volume rm todobackend_public
```

需要注意的一点是，Docker Swarm 在销毁堆栈时不会删除卷，因此您需要手动删除卷以完全清理环境。

现在我们可以向堆栈添加一个 collectstatic 服务：

```
version: '3.6'

networks:
  net:
    driver: overlay

volumes:
  public:
    driver: cloudstor:aws
    driver_opts:
      backing: shared

services:
  app:
    image: 385605022855.dkr.ecr.us-east-1.amazonaws.com/docker-in-aws/todobackend
    ports:
      - target: 8000
        published: 80
    networks:
      - net
    volumes:
      - public:/public
    ...
    ...
  collectstatic:
 image: 385605022855.dkr.ecr.us-east-1.amazonaws.com/docker-in-aws/todobackend volumes:
 - public:/public    networks:
 - net
 environment:
 DJANGO_SETTINGS_MODULE: todobackend.settings_release
 command:
 - python3
 - manage.py
 - collectstatic
 - --no-input
 deploy:
 replicas: 1
 restart_policy:
 condition: on-failure
 delay: 30s
 max_attempts: 6
```

`collectstatic` 服务挂载 `public` 共享卷，并运行适当的 `manage.py` 任务来生成静态内容。在 `deploy` 部分，我们配置了一个副本数量为 1，因为 `collectstatic` 服务只需要在部署时运行一次，然后配置了一个 `restart_policy`，指定 Docker Swarm 在失败时应尝试重新启动服务，每次重新启动尝试之间间隔 30 秒，最多尝试 6 次。这提供了最终一致的行为，因为它允许 collectstatic 在 EFS 卷挂载操作正在进行时最初失败，然后在卷挂载和准备就绪后最终成功。

如果您现在部署堆栈并监视 collectstatic 服务，您可能会注意到一些最初的失败：

```
> docker stack deploy --with-registry-auth -c stack.yml todobackend
Creating network todobackend_default
Creating network todobackend_net
Creating service todobackend_collectstatic
Creating service todobackend_app
> docker service ps todobackend_collectstatic NAME                        NODE                          DESIRED STATE CURRENT STATE
todobackend_collectstatic.1 ip-172-31-40-246.ec2.internal Running       Running 2 seconds ago
\_ todobackend_collectstatic.1 ip-172-31-40-246.ec2.internal Shutdown     Rejected 32 seconds ago
```

`docker service ps`命令不仅显示当前服务状态，还显示服务历史（例如任何先前尝试运行服务），您可以看到 32 秒前第一次尝试运行`collectstatic`失败，之后 Docker Swarm 尝试重新启动服务。这次尝试成功了，尽管`collectstatic`服务最终会完成并退出，但由于重启策略设置为失败，Docker Swarm 不会尝试重新启动服务，因为服务没有错误退出。这支持了在失败时具有重试功能的“一次性”服务的概念，Swarm 尝试再次运行服务的唯一时机是在为服务部署新配置到集群时。

如果您现在浏览外部负载均衡器的 URL，您应该会发现 todobackend 应用程序的静态内容现在被正确呈现，但是数据库配置错误仍然存在。

# 创建用于存储应用程序数据库的持久存储

现在我们可以将注意力转向应用程序数据库，这是 todobackend 应用程序的一个基本支持组件。如果您在 AWS 上运行，我的典型建议是，无论容器编排平台如何，都要像我们在本书中一样使用关系数据库服务（RDS），但是 todobackend 应用程序对应用程序数据库的要求提供了一个机会，可以演示如何使用 Docker for AWS 解决方案支持持久存储。

除了 EFS 支持的卷之外，Cloudstor 卷插件还支持*可重定位*的弹性块存储（EBS）卷。可重定位意味着插件将自动将容器当前分配的 EBS 卷重新分配到另一个节点，以防 Docker Swarm 确定必须将容器从一个节点重新分配到另一个节点。在重新分配 EBS 卷时实际发生的情况取决于情况：

+   新节点位于相同的可用区：插件只是从现有节点的 EC2 实例中分离卷，并在新节点上重新附加卷。

+   新节点位于不同的可用区：在这里，插件对现有卷进行快照，然后从快照在新的可用区创建一个新卷。完成后，之前的卷将被销毁。

重要的是要注意，Docker 仅支持对可移动的 EBS 支持卷的单一访问，也就是说，在任何给定时间，应该只有一个容器读取/写入该卷。如果您需要对卷进行共享访问，那么必须创建一个 EFS 支持的共享卷。

现在，让我们定义一个名为`data`的卷来存储 todobackend 数据库，并创建一个`db`服务，该服务将运行 MySQL 并附加到`data`卷：

```
version: '3.6'

networks:
  net:
    driver: overlay

volumes:
  public:
    driver: cloudstor:aws
    driver_opts:
      backing: shared
 data:
 driver: cloudstor:aws
 driver_opts: 
 backing: relocatable
 size: 10
 ebstype: gp2

services:
  app:
    image: 385605022855.dkr.ecr.us-east-1.amazonaws.com/docker-in-aws/todobackend
    ports:
      - target: 8000
        published: 80
    networks:
      - net
    volumes:
      - public:/public
    ...
    ...
  collectstatic:
    image: 385605022855.dkr.ecr.us-east-1.amazonaws.com/docker-in-aws/todobackend
    volumes:
      - public:/public
    ...
    ...
  db:
 image: mysql:5.7
 environment:
 MYSQL_DATABASE: todobackend
 MYSQL_USER: todo
 MYSQL_PASSWORD: password
 MYSQL_ROOT_PASSWORD: password
 networks:
 - net
 volumes:
 - data:/var/lib/mysql
 command:
 - --ignore-db-dir=lost+found
 deploy:
      replicas: 1
 placement:
 constraints:
 - node.role == manager
```

首先，我们创建一个名为`data`的卷，并将驱动程序配置为`cloudstor:aws`。在驱动程序选项中，我们指定了一个可移动的后端来创建一个 EBS 卷，指定了 10GB 的大小和`gp2`（SSD）存储的 EBS 类型。然后，我们定义了一个名为`db`的新服务，该服务运行官方的 MySQL 5.7 镜像，将`db`服务附加到先前定义的 net 网络，并将数据卷挂载到`/var/lib/mysql`，这是 MySQL 存储其数据库的位置。请注意，由于 Cloudstor 插件将挂载的卷格式化为`ext4`，在格式化过程中会自动创建一个名为`lost+found`的文件夹，这会导致[MySQL 容器中止](https://github.com/docker-library/mysql/issues/69#issuecomment-365927214)，因为它认为存在一个名为`lost+found`的现有数据库。

为了克服这一点，我们传入一个称为`--ignore-db-dir`的单个标志，该标志引用`lost+found`文件夹，该文件夹传递给 MySQL 镜像入口点，并配置 MySQL 守护进程忽略此文件夹。

最后，我们定义了一个放置约束，将强制`db`服务部署到 Swarm 管理器，这将允许我们通过将此放置约束更改为工作程序来测试数据卷的可移动特性。

如果您现在部署堆栈并监视`db`服务，您应该观察到服务需要一些时间才能启动，同时数据卷正在初始化：

```
> docker stack deploy --with-registry-auth -c stack.yml todobackend
docker stack deploy --with-registry-auth -c stack.yml todobackend
Updating service todobackend_app (id: 28vrdqcsekdvoqcmxtum1eaoj)
Updating service todobackend_collectstatic (id: sowciy4i0zuikf93lmhi624iw)
Creating service todobackend_db
> docker service ps todobackend_db --format "{{ .Name }} ({{ .ID }}): {{ .CurrentState }}" todobackend_db.1 (u4upsnirpucs): Preparing 35 seconds ago
> docker service ps todobackend_db --format "{{ .Name }} ({{ .ID }}): {{ .CurrentState }}"
todobackend_db.1 (u4upsnirpucs): Running 2 seconds ago
```

要验证 EBS 卷是否已创建，可以使用 AWS CLI 如下：

```
> aws ec2 describe-volumes --filters Name=tag:CloudstorVolumeName,Values=* \
    --query "Volumes[*].{ID:VolumeId,Zone:AvailabilityZone,Attachment:Attachments,Tag:Tags}"
[
    {
        "ID": "vol-0db01995ba87433b3",
        "Zone": "us-east-1b",
        "Attachment": [
            {
                "AttachTime": "2018-07-20T09:58:16.000Z",
                "Device": "/dev/xvdf",
                "InstanceId": "i-0dc762f73f8ce4abf",
                "State": "attached",
                "VolumeId": "vol-0db01995ba87433b3",
                "DeleteOnTermination": false
            }
        ],
        "Tag": [
            {
                "Key": "CloudstorVolumeName",
                "Value": "todobackend_data"
            },
            {
                "Key": "StackID",
                "Value": "0825319e9d91a2fc0bf06d2139708b1a"
            }
        ]
    }
]
```

请注意，由 Cloudstor 插件创建的 EBS 卷标记为`CloudstorVolumeName`的键和 Docker Swarm 卷名称的值。在上面的示例中，您还可以看到该卷已在 us-east-1b 可用区创建。

# 迁移 EBS 卷

现在，您已成功创建并附加了一个 EBS 支持的数据卷，让我们通过更改其放置约束来测试将`db`服务从管理节点迁移到工作节点：

```
version: '3.6'
...
...
services:
  ...
  ...
  db:
    image: mysql:5.7
    environment:
      MYSQL_DATABASE: todobackend
      MYSQL_USER: todo
      MYSQL_PASSWORD: password
      MYSQL_ROOT_PASSWORD: password
    networks:
      - net
    volumes:
      - data:/var/lib/mysql
    command:
      - --ignore-db-dir=lost+found
    deploy:
      replicas: 1
      placement:
        constraints:
 - node.role == worker
```

如果你现在部署你的更改，你应该能够观察到 EBS 迁移过程：

```
> volumes='aws ec2 describe-volumes --filters Name=tag:CloudstorVolumeName,Values=*
 --query "Volumes[*].{ID:VolumeId,State:Attachments[0].State,Zone:AvailabilityZone}"
 --output text' > snapshots='aws ec2 describe-snapshots --filters Name=status,Values=pending
    --query "Snapshots[].{Id:VolumeId,Progress:Progress}" --output text' > docker stack deploy --with-registry-auth -c stack.yml todobackend
Updating service todobackend_app (id: 28vrdqcsekdvoqcmxtum1eaoj)
Updating service todobackend_collectstatic (id: sowciy4i0zuikf93lmhi624iw)
Updating service todobackend_db (id: 4e3sc0dlot9lxlmt5kwfw3sis)
> eval $volumes vol-0db01995ba87433b3 detaching us-east-1b
> eval $volumes vol-0db01995ba87433b3 None us-east-1b
> eval $snapshots vol-0db01995ba87433b3 76%
> eval $snapshots
vol-0db01995ba87433b3 99%
> eval $volumes vol-0db01995ba87433b3 None us-east-1b
vol-07e328572e6223396 None us-east-1a
> eval $volume
vol-07e328572e6223396 None us-east-1a
> eval $volume
vol-07e328572e6223396 attached us-east-1a
> docker service ps todobackend_db --format "{{ .Name }} ({{ .ID }}): {{ .CurrentState }}"
todobackend_db.1 (a3i84kwz45w9): Running 1 minute ago
todobackend_db.1 (u4upsnirpucs): Shutdown 2 minutes ago
```

我们首先定义一个`volumes`查询，显示当前 Cloudstor 卷的状态，以及一个`snapshots`查询，显示任何正在进行中的 EBS 快照。在部署放置约束更改后，我们运行卷查询多次，并观察当前位于`us-east-1b`的卷，过渡到`分离`状态，然后到`无`状态（分离）。

然后我们运行快照查询，在那里你可以看到一个快照正在为刚刚分离的卷创建，一旦这个快照完成，我们运行卷查询多次来观察旧卷被移除并且在`us-east-1a`创建了一个新卷，然后被附加。在这一点上，`todobackend_data`卷已经从`us-east-1b`的管理者迁移到了`us-east-1a`，你可以通过执行`docker service ps`命令来验证`db`服务现在已经重新启动并运行。

由于 Docker for AWS CloudFormation 模板为管理者和工作者创建了单独的自动扩展组，有可能管理者和工作者正在相同的子网和可用区中运行，这将改变上面示例的行为。

在我们继续下一节之前，实际上我们需要拆除我们的堆栈，因为在我们的堆栈文件中使用明文密码的当前密码管理策略并不理想，而且我们的数据库已经使用这些密码进行了初始化。

```
> docker stack rm todobackend
Removing service todobackend_app
Removing service todobackend_collectstatic
Removing service todobackend_db
Removing network todobackend_net
> docker volume ls
DRIVER          VOLUME NAME
local           sshkey
cloudstor:aws   todobackend_data
cloudstor:aws   todobackend_public
> docker volume rm todobackend_public
todobackend_public
> docker volume rm todobackend_data
todobackend_data
```

请记住，每当你拆除一个堆栈时，你必须手动删除在该堆栈中使用过的任何卷。

# 使用 Docker secrets 进行秘密管理

在前面的例子中，当我们创建`db`服务时，我们实际上并没有配置应用程序与`db`服务集成，因为虽然我们专注于如何创建持久存储，但我没有将`app`服务与`db`服务集成的另一个原因是因为我们目前正在以明文配置`db`服务的密码，这并不理想。

Docker Swarm 包括一个名为 Docker secrets 的功能，为在 Docker Swarm 集群上运行的应用程序提供安全的密钥管理解决方案。密钥存储在内部加密的存储机制中，称为*raft log*，该机制被复制到集群中的所有节点，确保被授予对密钥访问权限的任何服务和相关容器可以安全地访问密钥。

要创建 Docker 密钥，您可以使用`docker secret create`命令：

```
> openssl rand -base64 32 | docker secret create todobackend_mysql_password -
wk5fpokcz8wbwmuw587izl1in
> openssl rand -base64 32 | docker secret create todobackend_mysql_root_password -
584ojwg31c0oidjydxkglv4qz
> openssl rand -base64 50 | docker secret create todobackend_secret_key -
t5rb04xcqyrqiglmfwrfs122y
> docker secret ls
ID                          NAME                              CREATED          UPDATED
wk5fpokcz8wbwmuw587izl1in   todobackend_mysql_password        57 seconds ago   57 seconds ago
584ojwg31c0oidjydxkglv4qz   todobackend_mysql_root_password   50 seconds ago   50 seconds ago
t5rb04xcqyrqiglmfwrfs122y   todobackend_secret_key            33 seconds ago   33 seconds ago
```

在前面的例子中，我们使用`openssl rand`命令以 Base64 格式生成随机密钥，然后将其作为标准输入传递给`docker secret create`命令。我们为 todobackend 用户的 MySQL 密码和 MySQL 根密码创建了 32 个字符的密钥，最后创建了一个 50 个字符的密钥，用于 todobackend 应用程序执行的加密操作所需的 Django `SECRET_KEY`设置。

现在我们已经创建了几个密钥，我们可以配置我们的堆栈来使用这些密钥：

```
version: '3.6'

networks:
  ...

volumes:
  ...

secrets:
 todobackend_mysql_password:
 external: true
 todobackend_mysql_root_password:
 external: true
 todobackend_secret_key:
 external: true

services:
  app:
    ...
    ...
    environment:
      DJANGO_SETTINGS_MODULE: todobackend.settings_release
 MYSQL_HOST: db
 MYSQL_USER: todo
    secrets:
 - source: todobackend_mysql_password
 target: MYSQL_PASSWORD
 - source: todobackend_secret_key
 target: SECRET_KEY
    command:
    ...
    ...
  db:
    image: mysql:5.7
    environment:
      MYSQL_DATABASE: todobackend
      MYSQL_USER: todo
      MYSQL_PASSWORD_FILE: /run/secrets/mysql_password
      MYSQL_ROOT_PASSWORD_FILE: /run/secrets/mysql_root_password
    secrets:
 - source: todobackend_mysql_password
 target: mysql_password
 - source: todobackend_mysql_root_password
 target: mysql_root_password
  ...
  ...
```

我们首先声明顶级`secrets`参数，指定我们之前创建的每个密钥的名称，并将每个密钥配置为`external`，因为我们在堆栈之外创建了这些密钥。如果您不使用外部密钥，必须在文件中定义您的密钥，这并不能解决安全地存储密码在堆栈定义和配置之外的问题，因此将您的密钥作为独立于堆栈的单独实体创建会更安全。

然后，我们重新配置`app`服务以通过`secrets`属性消耗每个密钥。请注意，我们指定了`MYSQL_PASSWORD`和`SECRET_KEY`的目标。每当您将密钥附加到服务时，将在`/run/secrets`创建一个基于内存的 tmpfs 挂载点，每个密钥存储在位置`/run/secrets/<target-name>`，因此对于`app`服务，将挂载以下密钥：

+   `/run/secrets/MYSQL_PASSWORD`

+   `/run/secrets/SECRET_KEY`

我们将在以后学习如何配置我们的应用程序来使用这些密钥，但也请注意，我们配置了`MYSQL_HOST`和`MYSQL_USER`环境变量，以便我们的应用程序知道如何连接到`db`服务以及要进行身份验证的用户。

接下来，我们配置`db`服务以使用 MySQL 密码和根密码密钥，并在这里配置每个密钥的目标，以便以下密钥在`db`服务容器中挂载：

+   `/run/secrets/mysql_password`

+   `/run/secrets/mysql_root_password`

最后，我们从`db`服务中删除了`MYSQL_PASSWORD`和`MYSQL_ROOT_PASSWORD`环境变量，并用它们的基于文件的等效项替换，引用了每个配置的秘密的路径。

在这一点上，如果您部署了新更新的堆栈（如果您之前没有删除堆栈，您需要在此之前执行此操作，以确保您可以使用新凭据重新创建数据库），一旦您的 todobackend 服务成功启动，您可以通过运行`docker ps`命令来确定在 Swarm 管理器上运行的`app`服务实例的容器 ID，之后您可以检查`/run/secrets`目录的内容：

```
> docker stack deploy --with-registry-auth -c stack.yml todobackend
Creating network todobackend_net
Creating service todobackend_db
Creating service todobackend_app
Creating service todobackend_collectstatic
> docker ps -f name=todobackend -q
7804a7496fa2
> docker exec -it 7804a7496fa2 ls -l /run/secrets
total 8
-r--r--r-- 1 root root 45 Jul 20 23:49 MYSQL_PASSWORD
-r--r--r-- 1 root root 70 Jul 20 23:49 SECRET_KEY
> docker exec -it 7804a7496fa2 cat /run/secrets/MYSQL_PASSWORD
qvImrAEBDz9OWJS779uvs/EWuf/YlepTlwPkx4cLSHE=
```

正如您所看到的，您之前创建的秘密现在可以在`/run/secrets`文件夹中使用，如果您现在浏览发布应用程序的外部负载均衡器 URL 上的`/todos`路径，不幸的是，您将收到`访问被拒绝`的错误：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/bade4a1e-0aa5-4a04-870a-04c2dbed709d.png)

数据库认证错误

问题在于，尽管我们已经在`app`服务中挂载了数据库秘密，但我们的 todobackend 应用程序不知道如何使用这些秘密，因此我们需要对 todobackend 应用程序进行一些修改，以便能够使用这些秘密。

# 配置应用程序以使用秘密

在之前的章节中，我们使用了一个入口脚本来支持诸如在容器启动时注入秘密等功能，然而同样有效（实际上更好更安全）的方法是配置您的应用程序以原生方式支持您的秘密管理策略。

对于 Docker 秘密，这非常简单，因为秘密被挂载在容器的本地文件系统中的一个众所周知的位置（`/run/secrets`）。以下演示了修改`todobackend`存储库中的`src/todobackend/settings_release.py`文件以支持 Docker 秘密，正如您应该记得的那样，这些是我们传递给`app`服务的设置，由环境变量配置`DJANGO_SETTINGS_MODULE=todobackend.settings_release`指定。

```
from .settings import *
import os

# Disable debug
DEBUG = True

# Looks up secret in following order:
# 1\. /run/secret/<key>
# 2\. Environment variable named <key>
# 3\. Value of default or None if no default supplied
def secret(key, default=None):
 root = os.environ.get('SECRETS_ROOT','/run/secrets')
 path = os.path.join(root,key)
 if os.path.isfile(path):
 with open(path) as f:
 return f.read().rstrip()
 else:
 return os.environ.get(key,default)

# Set secret key
SECRET_KEY = secret('SECRET_KEY', SECRET_KEY)

# Must be explicitly specified when Debug is disabled
ALLOWED_HOSTS = os.environ.get('ALLOWED_HOSTS', '*').split(',')

# Database settings
DATABASES = {
    'default': {
        'ENGINE': 'mysql.connector.django',
        'NAME': os.environ.get('MYSQL_DATABASE','todobackend'),
        'USER': os.environ.get('MYSQL_USER','todo'),
 'PASSWORD': secret('MYSQL_PASSWORD','password'),
        'HOST': os.environ.get('MYSQL_HOST','localhost'),
        'PORT': os.environ.get('MYSQL_PORT','3306'),
    },
    'OPTIONS': {
      'init_command': "SET sql_mode='STRICT_TRANS_TABLES'"
    }
}

STATIC_ROOT = os.environ.get('STATIC_ROOT', '/public/static')
MEDIA_ROOT = os.environ.get('MEDIA_ROOT', '/public/media')

MIDDLEWARE.insert(0,'aws_xray_sdk.ext.django.middleware.XRayMiddleware')
```

我们首先创建一个名为`secret()`的简单函数，该函数以设置或`key`的名称作为输入，并在无法找到秘密时提供一个可选的默认值。然后，该函数尝试查找路径`/run/secrets`（可以通过设置环境变量`SECRETS_ROOT`来覆盖此路径），并查找与请求的键相同名称的文件。如果找到该文件，则使用`f.read().rstrip()`调用读取文件的内容，`rstrip()`函数会去除`read()`函数返回的换行符。否则，该函数将查找与键相同名称的环境变量，如果所有这些查找都失败，则返回传递给`secret()`函数的`default`值（该值本身具有默认值`None`）。

有了这个函数，我们可以简单地调用秘密函数，如对`SECRET_KEY`和`DATABASES['PASSWORD']`设置进行演示，并以`SECRET_KEY`设置为例，该函数将按以下优先顺序返回：

1.  `/run/secrets/SECRET_KEY`的内容值

1.  环境变量`SECRET_KEY`的值

1.  传递给`secrets()`函数的默认值的值（在本例中，从基本设置文件导入的`SECRET_KEY`设置）

现在我们已经更新了 todobackend 应用程序以支持 Docker secrets，您需要提交您的更改，然后测试、构建和发布您的更改。请注意，您需要在连接到本地 Docker 引擎的单独 shell 中执行此操作（而不是连接到 Docker Swarm 集群）：

```
> git commit -a -m "Add support for Docker secrets"
[master 3db46c4] Add support for Docker secrets
> make login
...
...
> make test
...
...
> make release
...
...
> make publish
...
...
```

一旦您的镜像成功发布，切换回连接到 Swarm 集群的终端会话，并使用`docker stack deploy`命令重新部署您的堆栈：

```
> docker stack deploy --with-registry-auth -c stack.yml todobackend
Updating service todobackend_app (id: xz0tl79iv75qvq3tw6yqzracm)
Updating service todobackend_collectstatic (id: tkal4xxuejmf1jipsg24eq1bm)
Updating service todobackend_db (id: 9vj845j54nsz360q70lk1nrkr)
> docker service ps todobackend_app --format "{{ .Name }}: {{ .CurrentState }}"
todobackend_app.1: Running 20 minutes ago
todobackend_app.2: Running 20 minutes ago
```

如果您运行`docker service ps`命令，如前面的示例所示，您可能会注意到您的 todobackend 服务没有重新部署（在某些情况下，服务可能会重新部署）。原因是我们在堆栈文件中默认使用最新的镜像。为了确保我们能够持续交付和部署我们的应用程序，我们需要引用特定版本或构建标签，这是您应该始终采取的最佳实践方法，因为它将强制在每次服务更新时部署显式版本的镜像。

通过我们的本地工作流程，我们可以利用 todobackend 应用程序存储库中已经存在的`Makefile`，并包含一个`APP_VERSION`环境变量，返回当前的 Git 提交哈希，随后我们可以在我们的堆栈文件中引用它：

```
version: '3.6'

services:
  app:
 image: 385605022855.dkr.ecr.us-east-1.amazonaws.com/docker-in-aws/todobackend:${APP_VERSION}
    ...
    ...
  collectstatic:
 image: 385605022855.dkr.ecr.us-east-1.amazonaws.com/docker-in-aws/todobackend:${APP_VERSION}
    ...
    ...
```

有了这个配置，我们现在需要在`todobackend`存储库的根目录中添加一个`Makefile`的部署配方，当 Docker 客户端解析堆栈文件时，它将自动使`APP_VERSION`环境变量可用：

```
.PHONY: test release clean version login logout publish deploy

export APP_VERSION ?= $(shell git rev-parse --short HEAD)

version:
  @ echo '{"Version": "$(APP_VERSION)"}'

deploy: login
  @ echo "Deploying version ${APP_VERSION}..."
 docker stack deploy --with-registry-auth -c stack.yml todobackend 
login:
  $$(aws ecr get-login --no-include-email)
...
...
```

`deploy`配方引用`login`配方，确保我们始终首先运行等效的`make login`，然后再运行`deploy`配方中的任务。这个配方只是运行`docker stack deploy`命令，这样我们现在可以通过运行`make deploy`来部署对我们堆栈的更新：

```
> make deploy
Deploying version 3db46c4,,,
docker stack deploy --with-registry-auth -c stack.yml todobackend
Updating service todobackend_app (id: xz0tl79iv75qvq3tw6yqzracm)
Updating service todobackend_collectstatic (id: tkal4xxuejmf1jipsg24eq1bm)
Updating service todobackend_db (id: 9vj845j54nsz360q70lk1nrkr)
> docker service ps todobackend_app --format "{{ .Name }}: {{ .CurrentState }}"
todobackend_app.1: Running 5 seconds ago
todobackend_app.1: Shutdown 6 seconds ago
todobackend_app.2: Running 25 minutes ago
> docker service ps todobackend_app --format "{{ .Name }}: {{ .CurrentState }}"
todobackend_app.1: Running 45 seconds ago
todobackend_app.1: Shutdown 46 seconds ago
todobackend_app.2: Running 14 seconds ago
todobackend_app.2: Shutdown 15 seconds ago
```

因为我们的堆栈现在配置了一个特定的图像标记，由`APP_VERSION`变量（在前面的示例中为`3db46c4`）定义，所以一旦检测到更改，`app`服务就会被更新。您可以使用`docker service ps`命令来确认这一点，就像之前演示的那样，并且我们已经配置这个服务以每次更新一个实例，并且每次更新之间有 30 秒的延迟。

如果您现在浏览外部负载均衡器 URL 上的`/todos`路径，认证错误现在应该被替换为`表不存在`错误，这证明我们现在至少能够连接到数据库，但还没有处理数据库迁移作为我们的 Docker Swarm 解决方案的一部分：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/4421dad8-2e82-412a-9d29-3122345044ae.png)

数据库错误

# 运行数据库迁移

现在我们已经建立了一个安全访问堆栈中的 db 服务的机制，我们需要执行的最后一个配置任务是添加一个将运行数据库迁移的服务。这类似于我们之前创建的 collectstatic 服务，它需要是一个“一次性”任务，只有在我们创建堆栈或部署新版本的应用程序时才执行：

```
version: '3.6'

networks:
  ...

volumes:
  ...

secrets:
  ...

services:
  app:
    ...
  migrate:
 image: 385605022855.dkr.ecr.us-east-1.amazonaws.com/docker-in-aws/todobackend:${APP_VERSION}
 networks:
 - net
 environment:
 DJANGO_SETTINGS_MODULE: todobackend.settings_release
 MYSQL_HOST: db
 MYSQL_USER: todo
 secrets:
 - source: todobackend_mysql_password
 target: MYSQL_PASSWORD
```

```
command:
 - python3
 - manage.py
 - migrate
 - --no-input
 deploy:
 replicas: 1
 restart_policy:
 condition: on-failure
 delay: 30s
 max_attempts: 6
  collectstatic:
    ...
  db:
    ...
```

新的`migrate`服务的所有设置应该是不言自明的，因为我们之前已经为其他服务配置过它们。`deploy`配置尤其重要，并且与其他一次性 collectstatic 服务配置相同，Docker Swarm 将尝试确保`migrate`服务的单个副本能够成功启动最多六次，每次尝试之间延迟 30 秒。

如果您现在运行`make deploy`来部署您的更改，`migrate`服务应该能够成功完成：

```
> make deploy
Deploying version 3db46c4...
docker stack deploy --with-registry-auth -c stack.yml todobackend
Updating service todobackend_collectstatic (id: tkal4xxuejmf1jipsg24eq1bm)
Updating service todobackend_db (id: 9vj845j54nsz360q70lk1nrkr)
Updating service todobackend_app (id: xz0tl79iv75qvq3tw6yqzracm)
Creating service todobackend_migrate
> docker service ps todobackend_migrate --format "{{ .Name }}: {{ .CurrentState }}"
todobackend_migrate.1: Complete 18 seconds ago
```

为了验证迁移实际上已经运行，因为我们在创建 Docker Swarm 集群时启用了 CloudWatch 日志，您可以在 CloudWatch 日志控制台中查看`migrate`服务的日志。当使用 Docker for AWS 解决方案模板部署集群时，会创建一个名为`<cloudformation-stack-name>-lg`的日志组，我们的情况下是`docker-swarm-lg`。如果您在 CloudWatch 日志控制台中打开此日志组，您将看到为在 Swarm 集群中运行或已运行的每个容器存在日志流：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/54f50ec8-9ee0-4ceb-878e-ac7caf4c352b.png)

部署 migrate 服务

您可以看到最近的日志流与`migrate`服务相关，如果您打开此日志流，您可以确认数据库迁移已成功运行：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/28559836-2823-487e-95d2-492c1db559e8.png)

migrate 服务日志流

此时，您的应用程序应该已成功运行，并且您应该能够与应用程序交互以创建、更新、查看和删除待办事项。验证这一点的一个好方法是运行您在早期章节中创建的验收测试，这些测试包含在 todobackend 发布图像中，并确保通过`APP_URL`环境变量传递外部负载均衡器 URL，这可以作为自动部署后测试的策略。

```
> docker run -it --rm \ 
 -e APP_URL=http://docker-sw-external-1a5qzeykya672-1599369435.us-east-1.elb.amazonaws.com \ 
 385605022855.dkr.ecr.us-east-1.amazonaws.com/docker-in-aws/todobackend:3db46c4 \
 bats /app/src/acceptance.bats
```

```
Processing secrets []...
1..4
ok 1 todobackend root
```

```
ok 2 todo items returns empty list
ok 3 create todo item
ok 4 delete todo item
```

您现在已成功将 todobackend 应用程序部署到在 AWS 上运行的 Docker Swarm 集群中，我鼓励您进一步测试您的应用程序是否已经准备好投入生产，方法是拆除/重新创建堆栈，并通过进行测试提交和创建新的应用程序版本来运行一些示例部署。

完成后，您应该提交您所做的更改，并不要忘记通过在 CloudFormation 控制台中删除`docker-swarm`堆栈来销毁您的 Docker Swarm 集群。

# 总结

在本章中，您学会了如何使用 Docker Swarm 和 Docker for AWS 解决方案部署 Docker 应用程序。Docker for AWS 提供了一个 CloudFormation 模板，允许您在几分钟内设置一个 Docker Swarm 集群，并提供与 AWS 服务的集成，包括弹性负载均衡器服务、弹性文件系统和弹性块存储。

在创建了一个 Docker Swarm 集群之后，您学会了如何通过配置 SSH 隧道来为本地 Docker 客户端建立与 Swarm 管理器的远程访问，该隧道链接到 Swarm 管理器上的`/var/run/docker.sock`套接字文件，并将其呈现为本地端点，以便您的 Docker 客户端可以与之交互。这使得管理 Swarm 集群的体验类似于管理本地 Docker Engine。

您学会了如何创建和部署 Docker 服务，这些服务通常代表长时间运行的应用程序，但也可以代表一次性任务，比如运行数据库迁移或生成静态内容文件。Docker 堆栈代表复杂的多服务环境，并使用 Docker Compose 版本 3 规范进行定义，并使用`docker stack deploy`命令进行部署。使用 Docker Swarm 的一个优势是可以访问 Docker secrets 功能，该功能允许您将秘密安全地存储在加密的 raft 日志中，该日志会自动复制并在集群中的所有节点之间共享。然后，Docker secrets 可以作为内存 tmpfs 挂载暴露给服务，位于`/run/secrets`。您已经学会了如何轻松地配置您的应用程序以集成 Docker secrets 功能。

最后，您学会了如何解决在生产环境中运行容器时遇到的常见操作挑战，例如如何提供持久的、持久的存储访问，以 EBS 卷的形式，这些卷可以自动与您的容器重新定位，如何使用 EFS 提供对共享卷的访问，以及如何编排部署新的应用程序功能，支持运行一次性任务和滚动升级您的应用程序服务。

在本书的下一章和最后一章中，您将了解到 AWS 弹性 Kubernetes 服务（EKS），该服务于 2018 年中期推出，支持 Kubernetes，这是一种与 Docker Swarm 竞争的领先开源容器管理平台。

# 问题

1.  真/假：Docker Swarm 是 Docker Engine 的本机功能。

1.  您使用哪个 Docker 客户端命令来创建服务？

1.  正确/错误：Docker Swarm 包括三种节点类型——管理器、工作节点和代理。

1.  正确/错误：Docker for AWS 提供与 AWS 应用负载均衡器的集成。

1.  正确/错误：当后备设置为可重定位时，Cloudstor AWS 卷插件会创建一个 EFS 支持的卷。

1.  正确/错误：您创建了一个使用 Cloudstor AWS 卷插件提供位于可用性区域 us-west-1a 的 EBS 支持卷的数据库服务。发生故障，并且在可用性区域 us-west-1b 中创建了一个新的数据库服务容器。在这种情况下，原始的 EBS 卷将重新附加到新的数据库服务容器上。

1.  您需要在 Docker Stack deploy 和 Docker service create 命令中附加哪个标志以与私有 Docker 注册表集成？

1.  您部署了一个从 ECR 下载图像的堆栈。第一次部署成功，但是当您尝试在第二天执行新的部署时，您注意到您的 Docker swarm 节点无法拉取 ECR 图像。您该如何解决这个问题？

1.  您应该使用哪个版本的 Docker Compose 规范来定义 Docker Swarm 堆栈？

1.  正确/错误：在配置单次服务时，您应该将重启策略配置为 always。

# 进一步阅读

您可以查看以下链接，了解本章涵盖的主题的更多信息：

+   Docker 社区版适用于 AWS：[`store.docker.com/editions/community/docker-ce-aws`](https://store.docker.com/editions/community/docker-ce-aws)

+   Docker for AWS 文档：[`docs.docker.com/docker-for-aws`](https://docs.docker.com/docker-for-aws)

+   Docker Compose 文件版本 3 参考：[`docs.docker.com/compose/compose-file/`](https://docs.docker.com/compose/compose-file/)

+   Docker 适用于 AWS 的持久数据卷：[`docs.docker.com/docker-for-aws/persistent-data-volumes/`](https://docs.docker.com/docker-for-aws/persistent-data-volumes/)

+   Docker for AWS 模板存档：[`docs.docker.com/docker-for-aws/archive/`](https://docs.docker.com/docker-for-aws/archive/)

+   使用 Docker secrets 管理敏感数据：[`docs.docker.com/engine/swarm/secrets/`](https://docs.docker.com/engine/swarm/secrets/)

+   Docker 命令行参考：[`docs.docker.com/engine/reference/commandline/cli/`](https://docs.docker.com/engine/reference/commandline/cli/)

+   Docker 入门-第四部分：Swarm：[`docs.docker.com/get-started/part4/`](https://docs.docker.com/get-started/part4/)

+   Docker 入门-第五部分：Stacks：[`docs.docker.com/get-started/part5`](https://docs.docker.com/get-started/part5/)

+   Docker for AWS Swarm ECR 自动登录：[`github.com/mRoca/docker-swarm-aws-ecr-auth`](https://github.com/mRoca/docker-swarm-aws-ecr-auth)

+   SSH 代理转发：[`developer.github.com/v3/guides/using-ssh-agent-forwarding/`](https://developer.github.com/v3/guides/using-ssh-agent-forwarding/)


# 第十七章：弹性 Kubernetes 服务

Kubernetes 是一种流行的开源容器管理平台，最初由谷歌开发，基于谷歌自己内部的 Borg 容器平台。Kubernetes 借鉴了谷歌在大规模运行容器方面的丰富经验，现在得到了所有主要云平台提供商的支持，包括 AWS Elastic Kubernetes Service（EKS）的发布。EKS 提供了一个托管的 Kubernetes 集群，您可以在其中部署容器应用程序，而无需担心日常运营开销和集群管理的复杂性。AWS 已经完成了建立一个强大和可扩展平台的大部分工作，使得使用 Kubernetes 变得比以往更容易。

在本章中，您将被介绍到 Kubernetes 的世界，我们将通过如何配置 Kubernetes 来确保我们能够成功部署和操作本书中使用的示例应用程序，并在 AWS 中建立一个 EKS 集群，您将使用本地开发的配置部署应用程序。这将为您提供实际的、现实世界的见解，作为应用程序所有者，您可以将您的容器工作负载部署到 Kubernetes，并且您可以快速地开始使用 EKS。

我们将首先学习如何在本地使用 Docker for Mac 和 Docker for Windows 对 Kubernetes 进行本地支持。您可以直接启动一个本地单节点集群，减少了通常需要进行的大量手动配置，以便快速启动本地环境。您将学习如何创建运行 Kubernetes 中示例应用程序所需的各种资源，解决关键的运营挑战，如为应用程序数据库提供持久存储、管理密钥和运行一次性任务，如数据库迁移。

一旦您建立了一个工作配置，可以在 Kubernetes 中本地运行示例应用程序，我们将把注意力转向开始使用 EKS，创建 EKS 集群，并建立一个 EC2 自动扩展组，管理运行容器工作负载的工作节点。您将学习如何从本地环境设置对集群的访问，并继续部署 Kubernetes 仪表板，该仪表板提供了丰富的管理用户界面，您可以从中部署和管理应用程序。最后，您将设置与其他 AWS 服务的集成，包括弹性块存储（EBS）和弹性负载均衡（ELB），并将示例应用程序部署到您的 EKS 集群。

本章将涵盖以下主题：

+   Kubernetes 简介

+   Kubernetes 架构

+   开始使用 Kubernetes

+   使用 Docker Desktop 安装 Kubernetes

+   创建核心 Kubernetes 资源，包括 pod、部署和服务

+   创建持久卷

+   创建 Kubernetes secrets

+   运行 Kubernetes 作业

+   创建 EKS 集群

+   建立对 EKS 集群的访问

+   将应用程序部署到 EKS

# 技术要求

以下是本章的技术要求：

+   AWS 账户的管理员访问权限

+   本地 AWS 配置文件，按照第三章的说明进行配置

+   AWS CLI 版本 1.15.71 或更高版本

+   Docker 18.06 或更高版本

+   Docker Compose 1.22 或更高版本

+   GNU Make 3.82 或更高版本

+   本章假设您已经完成了本书中的所有前几章。

以下 GitHub 网址包含本章中使用的代码示例：[`github.com/docker-in-aws/docker-in-aws/tree/master/ch17`](https://github.com/docker-in-aws/docker-in-aws/tree/master/ch17)。

观看以下视频，了解代码的实际操作：

[`bit.ly/2LyGtSY`](http://bit.ly/2LyGtSY)

# Kubernetes 简介

**Kubernetes**是一个开源的容器管理平台，由 Google 在 2014 年开源，并在 2015 年通过 1.0 版本实现了生产就绪。在短短三年的时间里，它已经成为最受欢迎的容器管理平台，并且非常受大型组织的欢迎，这些组织希望将他们的应用程序作为容器工作负载来运行。Kubernetes 是 GitHub 上最受欢迎的开源项目之一（[`github.com/cncf/velocity/blob/master/docs/top30_chart_creation.md`](https://github.com/cncf/velocity/blob/master/docs/top30_chart_creation.md)），根据[Redmonk](https://redmonk.com/fryan/2017/09/10/cloud-native-technologies-in-the-fortune-100/)的说法，截至 2017 年底，Kubernetes 在财富 100 强公司中被使用率达到了 54%。

Kubernetes 的关键特性包括以下内容：

+   **平台无关**：Kubernetes 可以在任何地方运行，从您的本地机器到数据中心，以及在 AWS、Azure 和 Google Cloud 等云提供商中，它们现在都提供集成的托管 Kubernetes 服务。

+   **开源**：Kubernetes 最大的优势在于其社区和开源性质，这使得 Kubernetes 成为了全球领先的开源项目之一。主要组织和供应商正在投入大量时间和资源来为平台做出贡献，确保整个社区都能从这些持续的增强中受益。

+   **血统**：Kubernetes 的根源来自 Google 内部的 Borg 平台，自从 2000 年代初以来一直在大规模运行容器。Google 是容器技术的先驱之一，毫无疑问是容器的最大采用者之一，如果不是最大的采用者。在 2014 年，Google 表示他们每周运行 20 亿个容器，而当时大多数企业刚刚通过一个名为 Docker 的新项目听说了容器技术。这种血统和传统确保了 Google 在多年大规模运行容器中所学到的许多经验教训都被包含在 Kubernetes 平台中。

+   **生产级容器管理功能**：Kubernetes 提供了您在其他竞争平台上期望看到并会遇到的所有容器管理功能。这包括集群管理、多主机网络、可插拔存储、健康检查、服务发现和负载均衡、服务扩展和滚动更新、期望阶段配置、基于角色的访问控制以及秘密管理等。所有这些功能都以模块化的构建块方式实现，使您可以调整系统以满足组织的特定要求，这也是 Kubernetes 现在被认为是企业级容器管理的黄金标准的原因之一。

# Kubernetes 与 Docker Swarm

在上一章中，我提出了关于 Docker Swarm 与 Kubernetes 的个人看法，这一次我将继续，这次更加关注为什么选择 Kubernetes 而不是 Docker Swarm。当您阅读本章时，应该会发现 Kubernetes 具有更为复杂的架构，这意味着学习曲线更高，而我在本章中涵盖的内容只是 Kubernetes 可能实现的一小部分。尽管如此，一旦您理解了这些概念，至少从我的角度来看，您应该会发现最终 Kubernetes 更加强大、更加灵活，可以说 Kubernetes 肯定比 Docker Swarm 更具“企业级”感觉，您可以调整更多的参数来定制 Kubernetes 以满足您的特定需求。

Kubernetes 相对于 Docker Swarm 和其他竞争对手最大的优势可能是其庞大的社区，这意味着几乎可以在更广泛的 Kubernetes 社区和生态系统中找到关于几乎任何配置方案的信息。Kubernetes 运动背后有很多动力，随着 AWS 等领先供应商和提供商采用 Kubernetes 推出自己的产品和解决方案，这一趋势似乎正在不断增长。

# Kubernetes 架构

在架构上，Kubernetes 以集群的形式组织自己，其中主节点形成集群控制平面，工作节点运行实际的容器工作负载：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/64ef6b49-8e21-40b1-a9e2-3473309890f6.png)

Kubernetes 架构

在每个主节点中，存在许多组件：

+   **kube-apiserver**：这个组件公开 Kubernetes API，是您用来与 Kubernetes 控制平面交互的前端组件。

+   **etcd**：这提供了一个跨集群的分布式和高可用的键/值存储，用于存储 Kubernetes 配置和操作数据。

+   **kube-scheduler**：这将 pod 调度到工作节点上，考虑资源需求、约束、数据位置和其他因素。稍后您将了解更多关于 pod 的信息，但现在您可以将它们视为一组相关的容器和卷，需要一起创建、更新和部署。

+   **kube-controller-manager**：这负责管理控制器，包括一些组件，用于检测节点何时宕机，确保 pod 的正确数量的实例或副本正在运行，为在 pod 中运行的应用程序发布服务端点，并管理集群的服务帐户和 API 访问令牌。

+   **cloud-controller-manager**：这提供与底层云提供商交互的控制器，使云提供商能够支持特定于其平台的功能。云控制器的示例包括服务控制器，用于创建、更新和删除云提供商负载均衡器，以及卷控制器，用于创建、附加、分离和删除云提供商支持的各种存储卷技术。

+   **插件**：有许多可用的插件可以扩展集群的功能。这些以 pod 和服务的形式运行，提供集群功能。在大多数安装中通常部署的一个插件是集群 DNS 插件，它为在集群上运行的服务和 pod 提供自动 DNS 命名和解析。

在所有节点上，存在以下组件：

+   **kubelet**：这是在集群中每个节点上运行的代理，确保 pod 中的所有容器健康运行。kubelet 还可以收集容器指标，可以发布到监控系统。

+   **kube-proxy**：这管理每个节点上所需的网络通信、端口映射和路由规则，以支持 Kubernetes 支持的各种服务抽象。

+   **容器运行时**：提供运行容器的容器引擎。最受欢迎的容器运行时是 Docker，但是也支持 rkt（Rocket）或任何 OCI 运行时规范实现。

+   **Pods**：Pod 是部署容器应用程序的核心工作单元。每个 Pod 由一个或多个容器和相关资源组成，并且一个单一的网络接口，这意味着给定 Pod 中的每个容器共享相同的网络堆栈。

请注意，工作节点只直接运行先前列出的组件，而主节点运行到目前为止我们讨论的所有组件，允许主节点也运行容器工作负载，例如单节点集群的情况。

Kubernetes 还提供了一个名为**kubectl**的客户端组件，它提供了通过 Kubernetes API 管理集群的能力。**kubectl**支持 Windows、macOS 和 Linux，并允许您轻松管理和在本地和远程之间切换多个集群。

# 开始使用 Kubernetes

现在您已经简要介绍了 Kubernetes，让我们专注于在本地环境中启动和运行 Kubernetes。

在本书中的早期，当您设置本地开发环境时，如果您使用的是 macOS 或 Windows，您安装了 Docker Desktop 的社区版（CE）版本（Docker for Mac 或 Docker for Windows，在本章中我可能统称为 Docker Desktop），其中包括对 Kubernetes 的本地支持。

如果您使用的是不支持 Kubernetes 的 Docker for Mac/Windows 的变体，或者使用 Linux，您可以按照以下说明安装 minikube：[`github.com/kubernetes/minikube`](https://github.com/kubernetes/minikube)。本节中包含的大多数示例应该可以在 minikube 上运行，尽管诸如负载平衡和动态主机路径配置等功能可能不会直接支持，需要一些额外的配置。

要启用 Kubernetes，请在本地 Docker Desktop 设置中选择**Kubernetes**，并勾选**启用 Kubernetes**选项。一旦您点击**应用**，Kubernetes 将被安装，并需要几分钟来启动和运行：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/9c033101-8ec4-4dba-bfaf-dd99d43ed4e2.png)

使用 Docker for Mac 启用 Kubernetes

Docker Desktop 还会自动为您安装和配置 Kubernetes 命令行实用程序`kubectl`，该实用程序可用于验证您的安装：

```
> kubectl get nodes
NAME                STATUS  ROLES   AGE  VERSION
docker-for-desktop  Ready   master  1m   v1.10.3
```

如果您正在使用 Windows 的 Docker 与 Linux 子系统配合使用，您需要通过运行以下命令将`kubectl`安装到子系统中（有关更多详细信息，请参见[`kubernetes.io/docs/tasks/tools/install-kubectl/#install-kubectl-binary-via-native-package-management`](https://kubernetes.io/docs/tasks/tools/install-kubectl/#install-kubectl-binary-via-native-package-management)）：

```
sudo apt-get update && sudo apt-get install -y apt-transport-https
curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo apt-key add -
sudo touch /etc/apt/sources.list.d/kubernetes.list 
echo "deb http://apt.kubernetes.io/ kubernetes-xenial main" | sudo tee -a /etc/apt/sources.list.d/kubernetes.list
sudo apt-get update
sudo apt-get install -y kubectl
```

安装`kubectl`后，如果您之前将 Linux 子系统的主文件夹更改为 Windows 主文件夹，则现在应该能够与本地 Kubernetes 集群进行交互，无需进一步配置。

如果您的主文件夹与 Windows 主文件夹不同（默认情况下是这种情况），那么您将需要设置一个符号链接，指向 Windows 主文件夹中的`kubectl`配置文件，之后您应该能够使用`kubectl`与本地 Kubernetes 安装进行交互：

```
# Only required if Linux Subsystem home folder is different from Windows home folder
$ mkdir -p ~/.kube
$ ln -s /mnt/c/Users/<username>/.kube/config ~/.kube/config
$ kubectl get nodes
NAME                STATUS  ROLES   AGE  VERSION
docker-for-desktop  Ready   master  1m   v1.10.3
```

Windows 的 Linux 子系统还允许您运行 Windows 命令行程序，因此您也可以运行`kubectl.exe`来调用 Windows kubectl 组件。

# 创建一个 pod

在 Kubernetes 中，您将应用程序部署为*pods*，这些 pods 指的是一个或多个容器和其他与之密切相关的资源，共同代表您的应用程序。**pod**是 Kubernetes 中的核心工作单元，概念上类似于 ECS 任务定义，尽管在底层它们以完全不同的方式工作。

Kubernetes 的常用简写代码是 k8s，其中名称 Kubernetes 中的“ubernete”部分被数字 8 替换，表示“ubernete”中的字符数。

在创建我们的第一个 pod 之前，让我们在 todobackend 存储库中建立一个名为`k8s`的文件夹，该文件夹将保存 todobackend 应用程序的所有 Kubernetes 配置，然后创建一个名为`app`的文件夹，该文件夹将存储与核心 todobackend 应用程序相关的所有资源定义：

```
todobackend> mkdir -p k8s/app todobackend> touch k8s/app/deployment.yaml
```

以下代码演示了 todobackend 应用程序的基本 pod 定义，我们将其保存到`k8s/app/deployment.yaml`文件中：

```
apiVersion: v1
kind: Pod
metadata:
  name: todobackend
  labels:
    app: todobackend
spec:
  containers:
  - name: todobackend
    image: 385605022855.dkr.ecr.us-east-1.amazonaws.com/docker-in-aws/todobackend
    imagePullPolicy: IfNotPresent
    command:
    - uwsgi
    - --http=0.0.0.0:8000
    - --module=todobackend.wsgi
    - --master
    - --die-on-term
    - --processes=4
    - --threads=2
    - --check-static=/public
    env:
    - name: DJANGO_SETTINGS_MODULE
      value: todobackend.settings_release
```

pod 配置文件的格式很容易遵循，通常情况下，您看到的大多数参数都与使用 Docker Compose 定义容器时的同名参数相对应。一个经常引起混淆的重要区别是`command`参数-在 Kubernetes 中，此参数相当于`ENTRYPOINT` Dockerfile 指令和 Docker Compose 服务规范中的`entrypoint`参数，而在 Kubernetes 中，`args`参数相当于 CMD 指令（Dockerfile）和 Docker Compose 中的`command`服务参数。这意味着在前面的配置中，我们的容器中的默认入口脚本被绕过，而是直接运行 uwsgi web 服务器。

`imagePullPolicy`属性值为`IfNotPresent`配置了 Kubernetes 只有在本地 Docker Engine 注册表中没有可用的镜像时才拉取镜像，这意味着在尝试创建 pod 之前，您必须确保已运行现有的 todobackend Docker Compose 工作流以在本地构建和标记 todobackend 镜像。这是必需的，因为当您在 AWS EC2 实例上运行 Kubernetes 时，Kubernetes 只包括对 ECR 的本机支持，并且在您在 AWS 之外运行 Kubernetes 时，不会本地支持 ECR。

有许多第三方插件可用，允许您管理 AWS 凭据并拉取 ECR 镜像。一个常见的例子可以在[`github.com/upmc-enterprises/registry-creds`](https://github.com/upmc-enterprises/registry-creds)找到。

要创建我们的 pod 并验证它是否正在运行，您可以运行`kubectl apply`命令，使用`-f`标志引用您刚刚创建的部署文件，然后运行`kubectl get pods`命令：

```
> kubectl apply -f k8s/app/deployment.yaml
pod "todobackend" created
> kubectl get pods
NAME          READY   STATUS    RESTARTS   AGE
todobackend   1/1     Running   0          7s
> docker ps --format "{{ .Names }}"
k8s_todobackend_todobackend_default_1b436412-9001-11e8-b7af-025000000001_0
> docker ps --format "{{ .ID }}: {{ .Command }} ({{ .Status }})"
fc0c8acdd438: "uwsgi --http=0.0.0.…" (Up 16 seconds)
> docker ps --format "{{ .ID }} Ports: {{ .Ports }}"
fc0c8acdd438 Ports:
```

您可以看到 pod 的状态为`Running`，并且已经部署了一个容器到在您的本地 Docker Desktop 环境中运行的单节点 Kubernetes 集群。一个重要的要注意的是，已部署的 todobackend 容器无法与外部世界通信，因为从 pod 及其关联的容器中没有发布任何网络端口。

Kubernetes 的一个有趣之处是您可以使用 Kubernetes API 与您的 pod 进行交互。为了演示这一点，首先运行`kubectl proxy`命令，它会设置一个本地 HTTP 代理，通过普通的 HTTP 接口公开 API：

```
> kubectl proxy
Starting to serve on 127.0.0.1:8001
```

您现在可以通过 URL `http://localhost:8001/api/v1/namespaces/default/pods/todobackend:8000/proxy/` 访问 pod 上的容器端口 8000：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/30a20671-faac-4e12-af03-adfd67e9629a.png)

运行 kubectl 代理

如您所见，todobackend 应用正在运行，尽管它缺少静态内容，因为我们还没有生成它。还要注意页面底部的 todos 链接（`http://localhost:8001/todos`）是无效的，因为 todobackend 应用程序不知道通过代理访问应用程序的 API 路径。

Kubernetes 的另一个有趣特性是通过运行 `kubectl port-forward` 命令，将 Kubernetes 客户端的端口暴露给应用程序，从而连接到指定的 pod，这样可以实现从 Kubernetes 客户端到应用程序的端口转发：

```
> kubectl proxy
Starting to serve on 127.0.0.1:8001
^C
> kubectl port-forward todobackend 8000:8000
Forwarding from 127.0.0.1:8000 -> 8000
Forwarding from [::1]:8000 -> 8000
Handling connection for 8000
```

如果您现在尝试访问 `http://localhost:8000`，您应该能看到 todobackend 的主页，并且页面底部的 todos 链接现在应该是可访问的：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/6ccde81a-5c0f-4f36-bdb8-79dfb0de4d8f.png)

访问一个端口转发的 pod

您可以看到，再次，我们的应用程序并不处于完全功能状态，因为我们还没有配置任何数据库设置。

# 创建一个部署

尽管我们已经能够发布我们的 todobackend 应用程序，但我们用来做这件事的机制并不适合实际的生产使用，而且只对有限的本地开发场景真正有用。

在现实世界中运行我们的应用程序的一个关键要求是能够扩展或缩减应用程序容器的实例或*副本*数量。为了实现这一点，Kubernetes 支持一类资源，称为*控制器*，它负责协调、编排和管理给定 pod 的多个副本。一种流行的控制器类型是*部署*资源，正如其名称所示，它包括支持创建和更新 pod 的新版本，以及滚动升级和在部署失败时支持回滚等功能。

以下示例演示了如何更新 `todobackend` 仓库中的 `k8s/app/deployment.yaml` 文件来定义一个部署资源：

```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: todobackend
  labels:
    app: todobackend
spec:
  replicas: 2
  selector:
    matchLabels:
      app: todobackend
  template:
    metadata:
      labels:
        app: todobackend
    spec:
      containers:
      - name: todobackend
        image: 385605022855.dkr.ecr.us-east-1.amazonaws.com/docker-in-aws/todobackend
        imagePullPolicy: IfNotPresent
        readinessProbe:
          httpGet:
            port: 8000
        livenessProbe:
          httpGet:
            port: 8000
        command:
        - uwsgi
        - --http=0.0.0.0:8000
        - --module=todobackend.wsgi
        - --master
        - --die-on-term
        - --processes=4
        - --threads=2
        - --check-static=/public
        env:
        - name: DJANGO_SETTINGS_MODULE
          value: todobackend.settings_release
```

我们将之前的 pod 资源更新为现在的 deployment 资源，使用顶级 spec 属性（即 spec.template）的 template 属性内联定义应该部署的 pod。部署和 Kubernetes 的一个关键概念是使用基于集合的标签选择器匹配来确定部署适用于哪些资源或 pod。在前面的示例中，部署资源的 spec 指定了两个副本，并使用 selectors.matchLabels 来将部署与包含标签 app 值为 todobackend 的 pod 匹配。这是一个简单但强大的范例，可以以灵活和松散耦合的方式创建自己的结构和资源之间的关系。请注意，我们还向容器定义添加了 readinessProbe 和 livenessProbe 属性，分别创建了 readiness probe 和 liveness probe。readiness probe 定义了 Kubernetes 应执行的操作，以确定容器是否准备就绪，而 liveness probe 用于确定容器是否仍然健康。在前面的示例中，readiness probe 使用 HTTP GET 请求到端口 8000 来确定部署控制器何时应允许连接转发到容器，而 liveness probe 用于在容器不再响应 liveness probe 时重新启动容器。有关不同类型的探针及其用法的更多信息，请参阅 https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-probes/。

要创建新的部署资源，我们可以首先删除现有的 pod，然后使用 kubectl 应用 todobackend 仓库中的 k8s/app/deployment.yaml 文件：

```
> kubectl delete pods/todobackend
pod "todobackend" deleted
> kubectl apply -f k8s/app/deployment.yaml deployment.apps "todobackend" created> kubectl get deployments NAME                    DESIRED  CURRENT  UP-TO-DATE  AVAILABLE  AGE
todobackend             2        2        2           2          12s> kubectl get pods NAME                                     READY  STATUS   RESTARTS  AGE
todobackend-7869d9965f-lh944             1/1    Running  0         17s
todobackend-7869d9965f-v986s             1/1    Running  0         17s
```

创建部署后，您可以看到配置的副本数量以两个 pod 的形式部署，每个都有一个唯一的名称。只要您配置的 readiness probe 成功，每个 pod 的状态就会立即转换为 ready。

# 创建服务

在这一点上，我们已经为我们的应用程序定义了一个 pod，并使用部署资源部署了多个应用程序副本，现在我们需要确保外部客户端可以连接到我们的应用程序。鉴于我们有多个应用程序副本正在运行，我们需要一个能够提供稳定服务端点、跟踪每个副本位置并在所有副本之间负载平衡传入连接的组件。

*服务*是提供此类功能的 Kubernetes 资源，每个服务都被分配一个虚拟 IP 地址，可以用来访问一组 pod，并且对虚拟 IP 地址的传入连接进行负载平衡到每个 pod 副本，基于通过一个名为 kube-proxy 的标准 Kubernetes 系统资源管理和更新的 iptables 规则：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/869fe4cb-aa5f-4772-935c-4f14ca899e43.png)

Kubernetes 中的服务和端点

在上图中，一个客户端 pod 正试图使用虚拟 IP 地址`10.1.1.1`的端口`80`(`10.1.1.1:80`)与应用程序 pod 进行通信。请注意，服务虚拟 IP 地址在集群中的每个节点上都是公开的，**kube-proxy**组件负责更新 iptables 规则，以循环方式选择适当的端点，将客户端连接路由到。由于虚拟 IP 地址在集群中的每个节点上都是公开的，因此任何节点上的任何客户端都可以与服务通信，并且流量会均匀地分布在整个集群中。

现在您已经对服务的工作原理有了高层次的理解，让我们实际在`k8s/app/deployment.yaml`文件中定义一个新的服务，该文件位于`todobackend`存储库中：

```
apiVersion: v1
kind: Service
metadata:
 name: todobackend
spec:
 selector:
 app: todobackend
 ports:
 - protocol: TCP
 port: 80
    targetPort: 8000
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: todobackend
  labels:
    app: todobackend
...
...
```

请注意，您可以使用`---`分隔符在单个 YAML 文件中定义多个资源，并且我们可以创建一个名为 todobackend 的服务，该服务使用标签匹配将服务绑定到具有`app=todobackend`标签的任何 pod。在`spec.ports`部分，我们将端口 80 配置为服务的传入或监听端口，该端口将连接负载平衡到每个 pod 上的 8000 端口。

我们的服务定义已经就位，现在您可以使用`kubectl apply`命令部署服务：

```
> kubectl apply -f k8s/app/deployment.yaml
service "todobackend" created
deployment.apps "todobackend" unchanged
> kubectl get svc
NAME                 TYPE        CLUSTER-IP      EXTERNAL-IP   PORT(S)   AGE
kubernetes           ClusterIP   10.96.0.1       <none>        443/TCP   8h
todobackend          ClusterIP   10.103.210.17   <none>        80/TCP    10s
> kubectl get endpoints
NAME          ENDPOINTS                       AGE
kubernetes    192.168.65.3:6443               1d
todobackend   10.1.0.27:8000,10.1.0.30:8000   16h
```

您可以使用`kubectl get svc`命令查看当前服务，并注意到每个服务都包括一个唯一的集群 IP 地址，这是集群中其他资源可以用来与与服务关联的 pod 进行通信的虚拟 IP 地址。`kubectl get endpoints`命令显示与每个服务关联的实际端点，您可以看到对`todobackend`服务虚拟 IP 地址`10.103.210.17:80`的连接将负载均衡到`10.1.0.27:8000`和`10.1.0.30:8000`。

每个服务还分配了一个唯一的 DNS 名称，格式为`<service-name>.<namespace>.svc.cluster.local`。Kubernetes 中的默认命名空间称为`default`，因此对于我们的 todobackend 应用程序，它将被分配一个名为`todobackend.default.svc.cluster.local`的名称，您可以使用`kubectl run`命令验证在集群内是否可访问：

```
> kubectl run dig --image=googlecontainer/dnsutils --restart=Never --rm=true --tty --stdin \
 --command -- dig todobackend a +search +noall +answer
; <<>> DiG 9.8.4-rpz2+rl005.12-P1 <<>> todobackend a +search +noall +answer
;; global options: +cmd
todobackend.default.svc.cluster.local. 30 IN A   10.103.210.17
```

在上面的示例中，您可以简单地查询 todobackend，因为 Kubernetes 将 DNS 搜索域发送到`<namespace>.svc.cluster.local`（在我们的用例中为`default.svc.cluster.local`），您可以看到这将解析为 todobackend 服务的集群 IP 地址。

重要的是要注意，集群 IP 地址只能在 Kubernetes 集群内访问 - 如果没有进一步的配置，我们无法从外部访问此服务。

# 暴露服务

为了允许外部客户端和系统与 Kubernetes 服务通信，您必须将服务暴露给外部世界。按照 Kubernetes 的风格，有多种选项可用于实现这一点，这些选项由 Kubernetes 的`ServiceTypes`控制：

+   节点端口：此服务类型将 Kubernetes 每个节点上的外部端口映射到为服务配置的内部集群 IP 和端口。这为您的服务创建了几个外部连接点，随着节点的进出可能会发生变化，这使得创建稳定的外部服务端点变得困难。

+   负载均衡器：表示专用的外部第 4 层（TCP 或 UDP）负载均衡器，专门映射到您的服务。部署的实际负载均衡器取决于您的目标平台 - 例如，对于 AWS，将创建一个经典的弹性负载均衡器。这是一个非常受欢迎的选项，但一个重要的限制是每个服务都会创建一个负载均衡器，这意味着如果您有很多服务，这个选项可能会变得非常昂贵。

+   **Ingress**：这是一个共享的第 7 层（HTTP）负载均衡器资源，其工作方式类似于 AWS 应用程序负载均衡器，其中对单个 HTTP/HTTPS 端点的连接可以根据主机标头或 URL 路径模式路由到多个服务。鉴于您可以跨多个服务共享一个负载均衡器，因此这被认为是基于 HTTP 的服务的最佳选择。

发布您的服务的最流行的方法是使用负载均衡器方法，其工作方式如下图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/95505204-2d0d-4d38-9188-5741bbd5bfc6.png)

Kubernetes 中的负载均衡

外部负载均衡器发布客户端将连接到的外部服务端点，在前面的示例中是`192.0.2.43:80`。负载均衡器服务端点将与具有与服务关联的活动 pod 的集群中的节点相关联，每个节点都通过**kube-proxy**组件设置了节点端口映射。然后，节点端口映射将映射到节点上的每个本地端点，从而实现在整个集群中高效均匀地进行负载平衡。

对于集群内部客户端的通信，通信仍然使用服务集群 IP 地址，就像本章前面描述的那样。

在本章后面，我们将看到如何将 AWS 负载均衡器与 EKS 集成，但是目前您的本地 Docker 桌面环境包括对其自己的负载均衡器资源的支持，该资源会在您的主机上发布一个外部端点供您的服务使用。向服务添加外部负载均衡器非常简单，就像在以下示例中演示的那样，我们修改了`k8s/app/deployments.yaml`文件中的配置，该文件位于 todobackend 存储库中：

```
apiVersion: v1
kind: Service
metadata:
  name: todobackend
spec:
  selector:
    app: todobackend
  ports:
  - protocol: TCP
    port: 80
    targetPort: 8000 type: LoadBalancer
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: todobackend
  labels:
    app: todobackend
...
...
```

为了在您的环境中部署适当的负载均衡器，所需的全部就是将`spec.type`属性设置为`LoadBalancer`，Kubernetes 将自动创建一个外部负载均衡器。您可以通过应用更新后的配置并运行`kubectl get svc`命令来测试这一点：

```
> kubectl apply -f k8s/app/deployment.yaml
service "todobackend" configured
deployment.apps "todobackend" unchanged
> kubectl get svc
NAME                 TYPE           CLUSTER-IP      EXTERNAL-IP   PORT(S)        AGE
kubernetes           ClusterIP      10.96.0.1       <none>        443/TCP        8h
todobackend          LoadBalancer   10.103.210.17   localhost     80:31417/TCP   10s
> curl localhost
{"todos":"http://localhost/todos"}
```

请注意，`kubectl get svc`输出现在显示 todobackend 服务的外部 IP 地址为 localhost（当使用 Docker Desktop 时，localhost 始终是 Docker 客户端可访问的外部接口），并且它在端口 80 上外部发布，您可以通过运行`curl localhost`命令来验证这一点。外部端口映射到单节点集群上的端口 31417，这是**kube-proxy**组件监听的端口，以支持我们之前描述的负载均衡器架构。

# 向您的 pods 添加卷

现在我们已经了解了如何在 Kubernetes 集群内部和外部发布我们的应用程序，我们可以专注于通过添加对 todobackend 应用程序的各种部署活动和依赖项的支持，使 todobackend 应用程序完全功能。

首先，我们将解决为 todobackend 应用程序提供静态内容的问题 - 正如您从之前的章节中了解的那样，我们需要运行**collectstatic**任务，以确保 todobackend 应用程序的静态内容可用，并且应该在部署 todobackend 应用程序时运行。**collectstatic**任务需要将静态内容写入一个卷，然后由主应用程序容器挂载，因此让我们讨论如何向 Kubernetes pods 添加卷。

Kubernetes 具有强大的存储子系统，支持各种卷类型，您可以在[`kubernetes.io/docs/concepts/storage/volumes/#types-of-volumes`](https://kubernetes.io/docs/concepts/storage/volumes/#types-of-volumes)上阅读更多信息。对于**collectstatic**用例，[emptyDir](https://kubernetes.io/docs/concepts/storage/volumes/#emptydir)卷类型是合适的，这是一个遵循每个 pod 生命周期的卷 - 它会随着 pod 的创建和销毁而动态创建和销毁 - 因此它适用于诸如缓存和提供静态内容之类的用例，这些内容在 pod 创建时可以轻松重新生成。

以下示例演示了向`k8s/app/deployment.yaml`文件添加公共`emptyDir`卷：

```
...
...
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: todobackend
  labels:
    app: todobackend
spec:
  replicas: 2
  selector:
    matchLabels:
      app: todobackend
  template:
    metadata:
      labels:
        app: todobackend
    spec:
      securityContext:
 fsGroup: 1000
 volumes:
 - name: public
 emptyDir: {}
      containers:
      - name: todobackend
        image: 385605022855.dkr.ecr.us-east-1.amazonaws.com/docker-in-aws/todobackend
        imagePullPolicy: IfNotPresent
        readinessProbe:
          httpGet:
            port: 8000
        livenessProbe:
          httpGet:
            port: 8000
        volumeMounts:
 - name: public
 mountPath: /public
        command:
        - uwsgi
        - --http=0.0.0.0:8000
        - --module=todobackend.wsgi
        - --master
        - --die-on-term
        - --processes=4
        - --threads=2
        - --check-static=/public
        env:
        - name: DJANGO_SETTINGS_MODULE
          value: todobackend.settings_release
```

我们在 pod 模板的 `spec.Volumes` 属性中定义了一个名为 `public` 的卷，然后在 todobackend 容器定义中使用 `volumeMounts` 属性将 `public` 卷挂载到 `/public`。我们的用例的一个重要配置要求是设置 `spec.securityContext.fsGroup` 属性，该属性定义了将配置为文件系统挂载点的组所有者的组 ID。我们将此值设置为 `1000`；回想一下前几章中提到的，todobackend 映像以 `app` 用户运行，其用户/组 ID 为 1000。此配置确保 todobackend 容器能够读取和写入 `public` 卷的静态内容。

如果您现在部署配置更改，您应该能够使用 `kubectl exec` 命令来检查 todobackend 容器文件系统，并验证我们能够读取和写入 `/public` 挂载点：

```
> kubectl apply -f k8s/app/deployment.yaml
service "todobackend" unchanged
deployment.apps "todobackend" configured
> kubectl exec $(kubectl get pods -l app=todobackend -o=jsonpath='{.items[0].metadata.name}') \
    -it bash
bash-4.4$ touch /public/foo
bash-4.4$ ls -l /public/foo
-rw-r--r-- 1 app app 0 Jul 26 11:28 /public/foo
bash-4.4$ rm /public/foo
```

`kubectl exec` 命令类似于 `docker exec` 命令，允许您在当前运行的 pod 容器中执行命令。此命令必须引用 pod 的名称，我们使用 `kubectl get pods` 命令以及 JSON 路径查询来提取此名称。正如您所看到的，**todobackend** 容器中的 `app` 用户能够读取和写入 `/public` 挂载点。

# 向您的 pod 添加初始化容器

在为静态内容准备了临时卷后，我们现在可以专注于安排 **collectstatic** 任务来为我们的应用程序生成静态内容。Kubernetes 支持 [初始化容器](https://kubernetes.io/docs/concepts/workloads/pods/init-containers/)，这是一种特殊类型的容器，在 pod 中启动主应用程序容器之前执行。Kubernetes 将确保您的初始化容器运行完成并成功完成，然后再启动您的应用程序，如果您指定了多个初始化容器，Kubernetes 将按顺序执行它们，直到所有初始化容器都完成。

以下代码演示了向 `k8s/app/deployment.yaml` 文件添加初始化容器：

```
...
...
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: todobackend
  labels:
    app: todobackend
spec:
  replicas: 2
  selector:
    matchLabels:
      app: todobackend
  template:
    metadata:
      labels:
        app: todobackend
    spec:
      securityContext:
        fsGroup: 1000
      volumes:
      - name: public
        emptyDir: {}
 initContainers:
      - name: collectstatic
 image: 385605022855.dkr.ecr.us-east-1.amazonaws.com/docker-in-aws/todobackend
 imagePullPolicy: IfNotPresent
 volumeMounts:
 - name: public
 mountPath: /public
 command: ["python3","manage.py","collectstatic","--no-input"]
 env:
 - name: DJANGO_SETTINGS_MODULE
 value: todobackend.settings_release
      containers:
      ...
      ...
```

您现在可以部署您的更改，并使用 `kubectl logs` 命令来验证 collectstatic 初始化容器是否成功执行：

```
> kubectl apply -f k8s/app/deployment.yaml
service "todobackend" unchanged
deployment.apps "todobackend" configured
> kubectl logs $(kubectl get pods -l app=todobackend -o=jsonpath='{.items[0].metadata.name}') \
    -c collectstatic
Copying '/usr/lib/python3.6/site-packages/django/contrib/admin/static/admin/fonts/README.txt'
...
...
159 static files copied to '/public/static'.
```

如果您现在在浏览器中浏览 `http://localhost`，您应该能够验证静态内容现在正确呈现：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/6dce9b13-5f6f-4d61-a6a3-6dc3ac1017b6.png)

todobackend 应用程序具有正确的静态内容

# 添加数据库服务

使 todobackend 应用程序完全功能的下一步是添加一个数据库服务，该服务将托管 todobackend 应用程序数据库。我们将在我们的 Kubernetes 集群中运行此服务，但是在 AWS 中的真实生产用例中，我通常建议使用关系数据库服务（RDS）。

定义数据库服务需要两个主要的配置任务：

+   创建持久存储

+   创建数据库服务

# 创建持久存储

我们的数据库服务的一个关键要求是持久存储，在我们的单节点本地 Kubernetes 开发环境中，[hostPath](https://kubernetes.io/docs/concepts/storage/volumes/#hostpath)卷类型代表提供简单持久存储需求的标准选项。

虽然您可以通过在卷定义中直接指定路径来轻松创建 hostPath 卷（请参阅[`kubernetes.io/docs/concepts/storage/volumes/#hostpath`](https://kubernetes.io/docs/concepts/storage/volumes/#hostpath)中的示例 pod 定义），但这种方法的一个问题是它对底层卷类型创建了硬依赖，并且如果您想要删除 pod 和与卷关联的数据，则需要手动清理。

Docker Desktop Kubernetes 支持的一个非常有用的功能是包含一个名为`docker.io/hostpath`的动态卷提供程序，它会自动为您创建 hostPath 类型的卷，该卷可通过运行`kubectl get sc`命令查看的默认*storage class*来使用：

```
> kubectl get sc
NAME                 PROVISIONER          AGE
hostpath (default)   docker.io/hostpath   2d
```

存储类提供了对底层卷类型的抽象，这意味着您的 pod 可以从特定类中请求存储。这包括通用要求，如卷大小，而无需担心底层卷类型。在 Docker Desktop 的情况下，开箱即用包含了一个默认的存储类，它使用 hostPath 卷类型来提供存储请求。

然而，当我们稍后在 AWS 中使用 EKS 设置 Kubernetes 集群时，我们将配置一个使用 AWS Elastic Block Store（EBS）作为底层卷类型的默认存储类。采用这种方法意味着我们不需要更改我们的 pod 定义，因为我们将在每个环境中引用相同的存储类。

如果您正在使用 minikube，名为`k8s.io/minikube-hostpath`的动态 provisioner 提供了类似于 Docker hostpath provisioner 的功能，但是将卷挂载在`/tmp/hostpath-provisioner`下。

要使用存储类而不是直接在 pod 定义中指定卷类型，您需要创建*持久卷索赔*，它提供了存储需求的逻辑定义，如卷大小和访问模式。让我们定义一个持久卷索赔，但在此之前，我们需要在 todobackend 存储库中建立一个名为`k8s/db`的新文件夹，用于存储我们的数据库服务配置：

```
todobackend> mkdir -p k8s/db todobackend> touch k8s/db/storage.yaml
```

在这个文件夹中，我们将创建一个名为`k8s/db/storage.yaml`的文件，在其中我们将定义一个持久卷索赔。

```
kind: PersistentVolumeClaim
apiVersion: v1
metadata:
  name: todobackend-data
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 8Gi         
```

我们在一个专用文件中创建索赔（称为`todobackend-data`），因为这样可以让我们独立管理索赔的生命周期。在前面的示例中未包括的一个属性是`spec.storageClassName`属性 - 如果省略此属性，将使用默认的存储类，但请记住您可以创建和引用自己的存储类。`spec.accessModes`属性指定存储应该如何挂载 - 在本地存储和 AWS 中的 EBS 存储的情况下，我们只希望一次只有一个容器能够读写卷，这由`ReadWriteOnce`访问模式包含。

`spec.resources.requests.storage`属性指定持久卷的大小，在这种情况下，我们配置为 8GB。

如果您正在使用 Windows 版的 Docker，第一次尝试使用 Docker hostPath provisioner 时，将提示您与 Docker 共享 C:\。

如果您现在使用`kubectl`部署持久卷索赔，可以使用`kubectl get pvc`命令查看您新创建的索赔：

```
> kubectl apply -f k8s/db/storage.yaml
persistentvolumeclaim "todobackend-data" created
> kubectl get pvc
NAME               STATUS  VOLUME                                    CAPACITY  ACCESS MODES STORAGECLASS  AGE
todobackend-data   Bound   pvc-afba5984-9223-11e8-bc1c-025000000001  8Gi       RWO              hostpath      5s
```

您可以看到，当您创建持久卷索赔时，会动态创建一个持久卷。在使用 Docker Desktop 时，实际上是在路径`~/.docker/Volumes/<persistent-volume-claim>/<volume>`中创建的。

```
> ls -l ~/.docker/Volumes/todobackend-data
total 0
drwxr-xr-x 2 jmenga staff 64 28 Jul 17:04 pvc-afba5984-9223-11e8-bc1c-025000000001
```

如果您正在使用 Windows 版的 Docker 并且正在使用 Windows 子系统用于 Linux，您可以在 Windows 主机上创建一个符号链接到`.docker`文件夹：

```
> ln -s /mnt/c/Users/<user-name>/.docker ~/.docker
> ls -l ~/.docker/Volumes/todobackend-data
total 0
drwxrwxrwx 1 jmenga jmenga 4096 Jul 29 17:04 pvc-c02a8614-932d-11e8-b8aa-00155d010401
```

请注意，如果您按照第一章中的说明进行了设置，*容器和 Docker 基础知识*，为了设置 Windows Subsystem for Linux，您已经将 `/mnt/c/Users/<user-name>/` 配置为您的主目录，因此您不需要执行上述配置。

# 创建数据库服务

现在我们已经创建了一个持久卷索赔，我们可以定义数据库服务。我们将在 `todobackend` 仓库中的一个新文件 `k8s/db/deployment.yaml` 中定义数据库服务，其中我们创建了一个服务和部署定义：

```
apiVersion: v1
kind: Service
metadata:
  name: todobackend-db
spec:
  selector:
    app: todobackend-db
  clusterIP: None 
  ports:
  - protocol: TCP
    port: 3306
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: todobackend-db
  labels:
    app: todobackend-db
spec:
  selector:
    matchLabels:
      app: todobackend-db
  template:
    metadata:
      labels:
        app: todobackend-db
    spec:
      volumes:
      - name: data
        persistentVolumeClaim:
          claimName: todobackend-data
      containers:
      - name: db
        image: mysql:5.7
        livenessProbe:
          exec:
            command:
            - /bin/sh
            - -c
            - "mysqlshow -h 127.0.0.1 -u $(MYSQL_USER) -p$(cat /tmp/secrets/MYSQL_PASSWORD)"
        volumeMounts:
        - name: data
          mountPath: /var/lib/mysql
        args:
        - --ignore-db-dir=lost+found
        env:
        - name: MYSQL_DATABASE
          value: todobackend
        - name: MYSQL_USER
          value: todo
        - name: MYSQL_ROOT_PASSWORD
          value: super-secret-password
        - name: MYSQL_PASSWORD
          value: super-secret-password
```

我们首先定义一个名为 `todobackend-db` 的服务，它发布默认的 MySQL TCP 端口 `3306`。请注意，我们指定了 `spec.clusterIP` 值为 `None`，这将创建一个无头服务。无头服务对于单实例服务非常有用，并允许使用 pod 的 IP 地址作为服务端点，而不是使用 **kube-proxy** 组件与虚拟 IP 地址进行负载均衡到单个端点。定义无头服务仍将发布服务的 DNS 记录，但将该记录与 pod IP 地址关联，确保 **todobackend** 应用可以通过名称连接到 `todobackend-db` 服务。然后，我们为 `todobackend-db` 服务创建一个部署，并定义一个名为 `data` 的卷，该卷映射到我们之前创建的持久卷索赔，并挂载到 MySQL 容器中的数据库数据目录 (`/var/lib/mysql`)。请注意，我们指定了 `args` 属性（在 Docker/Docker Compose 中相当于 CMD/command 指令），它配置 MySQL 忽略 `lost+found` 目录（如果存在的话）。虽然在使用 Docker Desktop 时这不会成为问题，但在 AWS 中会成为问题，原因与前面的 Docker Swarm 章节中讨论的原因相同。最后，我们创建了一个类型为 `exec` 的活动探针，执行 `mysqlshow` 命令来检查在 MySQL 容器内部可以本地进行与 MySQL 数据库的连接。由于 MySQL 密钥位于文件中，我们将 MySQL 命令包装在一个 shell 进程 (`/bin/sh`) 中，这允许我们使用 `$(cat /tmp/secrets/MYSQL_PASSWORD)` 命令替换。

Kubernetes 允许您在执行时使用语法`$(<environment variable>)`来解析环境变量。例如，前面存活探针中包含的`$(MYSQL_USER)`值将在执行探针时解析为环境变量`MYSQL_USER`。有关更多详细信息，请参阅[`kubernetes.io/docs/tasks/inject-data-application/define-command-argument-container/#use-environment-variables-to-define-arguments`](https://kubernetes.io/docs/tasks/inject-data-application/define-command-argument-container/#use-environment-variables-to-define-arguments)。

如果您现在部署数据库服务和部署资源，可以使用`kubectl get svc`和`kubectl get endpoints`命令来验证无头服务配置：

```
> kubectl apply -f k8s/db/deployment.yaml
service "todobackend-db" created
deployment.apps "todobackend-db" created
> kubectl get svc NAME                 TYPE           CLUSTER-IP      EXTERNAL-IP   PORT(S)        AGE
kubernetes           ClusterIP      10.96.0.1       <none>        443/TCP        8h
todobackend          LoadBalancer   10.103.210.17   localhost     80:31417/TCP   1d
todobackend-db       ClusterIP      None            <none>        3306/TCP       6s
> kubectl get endpoints
NAME             ENDPOINTS                       AGE
kubernetes       192.168.65.3:6443               2d
todobackend      10.1.0.44:8000,10.1.0.46:8000   1d
todobackend-db   10.1.0.55:3306                  14s
```

请注意，`todobackend-db`服务部署时的集群 IP 为 none，这意味着服务的发布端点是`todobackend-db` pod 的 IP 地址。

您还可以通过列出本地主机上`~/.docker/Volumes/todobackend-data`目录中物理卷的内容来验证数据卷是否正确创建：

```
> ls -l ~/.docker/Volumes/todobackend-data/pvc-afba5984-9223-11e8-bc1c-025000000001
total 387152
-rw-r----- 1 jmenga wheel 56 27 Jul 21:49 auto.cnf
-rw------- 1 jmenga wheel 1675 27 Jul 21:49 ca-key.pem
```

```
...
...
drwxr-x--- 3 jmenga wheel 96 27 Jul 21:49 todobackend
```

如果您现在只删除数据库服务和部署，您应该能够验证持久卷未被删除并持续存在，这意味着您随后可以重新创建数据库服务并重新附加到`data`卷而不会丢失数据。

```
> kubectl delete -f k8s/db/deployment.yaml
service "todobackend-db" deleted
deployment.apps "todobackend-db" deleted
> ls -l ~/.docker/Volumes/todobackend-data/pvc-afba5984-9223-11e8-bc1c-025000000001
total 387152
-rw-r----- 1 jmenga wheel 56 27 Jul 21:49 auto.cnf
-rw------- 1 jmenga wheel 1675 27 Jul 21:49 ca-key.pem
...
...
drwxr-x--- 3 jmenga wheel 96 27 Jul 21:49 todobackend
> kubectl apply -f k8s/db/deployment.yaml
service "todobackend-db" created
deployment.apps "todobackend-db" created
```

前面的代码很好地说明了为什么我们将持久卷索赔分离成自己的文件的原因 - 这样做意味着我们可以轻松地管理数据库服务的生命周期，而不会丢失任何数据。如果您确实想要销毁数据库服务及其数据，您可以选择删除持久卷索赔，这样 Docker Desktop **hostPath**提供程序将自动删除持久卷和任何存储的数据。

Kubernetes 还支持一种称为 StatefulSet 的控制器，专门用于有状态的应用程序，如数据库。您可以在[`kubernetes.io/docs/concepts/workloads/controllers/statefulset/`](https://kubernetes.io/docs/concepts/workloads/controllers/statefulset/)上阅读更多关于 StatefulSets 的信息。

# 创建和使用秘密

Kubernetes 支持*secret*对象，允许将诸如密码或令牌之类的敏感数据以加密格式安全存储，然后根据需要私密地暴露给您的容器。Kubernetes 秘密以键/值映射或字典格式存储，这与 Docker 秘密不同，正如您在上一章中看到的，Docker 秘密通常只存储秘密值。

您可以使用文字值手动创建秘密，也可以将秘密值包含在文件中并应用该文件。我建议使用文字值创建您的秘密，以避免将您的秘密存储在配置文件中，这可能会意外地提交并推送到您的源代码存储库中。

```
> kubectl create secret generic todobackend-secret \
 --from-literal=MYSQL_PASSWORD="$(openssl rand -base64 32)" \
 --from-literal=MYSQL_ROOT_PASSWORD="$(openssl rand -base64 32)" \
 --from-literal=SECRET_KEY="$(openssl rand -base64 50)"
secret "todobackend-secret" created
> kubectl describe secrets/todobackend-secret
Name: todobackend-secret
Namespace: default
Labels: <none>
Annotations: <none>

Type: Opaque

Data
====
MYSQL_PASSWORD: 44 bytes
MYSQL_ROOT_PASSWORD: 44 bytes
SECRET_KEY: 69 bytes
```

在上面的示例中，您使用`kubectl create secret generic`命令创建了一个名为`todobackend-secret`的秘密，其中存储了三个秘密值。请注意，每个值都使用与预期环境变量相同的键存储，这将使这些值的配置易于消耗。

现在创建了秘密，您可以配置`todobackend`和`db`部署以使用该秘密。Kubernetes 包括一种特殊的卷类型，称为秘密，允许您在容器中的可配置位置挂载您的秘密，然后您的应用程序可以安全和私密地读取。

# 为数据库服务使用秘密

让我们首先更新`k8s/db/deployment.yaml`文件中定义的数据库部署资源，以使用`todobackend-secret`：

```
apiVersion: v1
kind: Service
metadata:
  name: todobackend-db
spec:
  selector:
    app: todobackend-db
  clusterIP: None 
  ports:
  - protocol: TCP
    port: 3306
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: todobackend-db
  labels:
    app: todobackend-db
spec:
  selector:
    matchLabels:
      app: todobackend-db
  template:
    metadata:
      labels:
        app: todobackend-db
    spec:
      volumes:
      - name: data
        persistentVolumeClaim:
          claimName: todobackend-data
 - name: secrets
 secret:
 secretName: todobackend-secret          items:
 - key: MYSQL_PASSWORD
 path: MYSQL_PASSWORD
 - key: MYSQL_ROOT_PASSWORD
 path: MYSQL_ROOT_PASSWORD
      containers:
      - name: db
        image: mysql:5.7
        livenessProbe:
          exec:
            command:
            - /bin/sh
            - -c
            - "mysqlshow -h 127.0.0.1 -u $(MYSQL_USER) -p$(cat /tmp/secrets/MYSQL_PASSWORD)"
        volumeMounts:
        - name: data
          mountPath: /var/lib/mysql
 - name: secrets
 mountPath: /tmp/secrets
 readOnly: true
        env:
        - name: MYSQL_DATABASE
          value: todobackend
        - name: MYSQL_USER
          value: todo
 - name: MYSQL_ROOT_PASSWORD_FILE
 value: /tmp/secrets/MYSQL_ROOT_PASSWORD
 - name: MYSQL_PASSWORD_FILE
 value: /tmp/secrets/MYSQL_PASSWORD
```

首先创建一个名为`secrets`的卷，类型为`secret`，引用我们之前创建的`todobackend-secret`。默认情况下，所有秘密项目都将可用，但是您可以通过可选的`items`属性控制发布到卷的项目。因为`todobackend-secret`包含特定于 todobackend 应用程序的`SECRET_KEY`秘密，我们配置`items`列表以排除此项目，并仅呈现`MYSQL_PASSWORD`和`MYSQL_ROOT_PASSWORD`键。请注意，指定的`path`是必需的，并且表示为相对路径，基于秘密卷在每个容器中挂载的位置。

然后，您将`secrets`卷作为只读挂载到`/tmp/secrets`中的`db`容器，并更新与密码相关的环境变量，以引用秘密文件，而不是直接使用环境中的值。请注意，每个秘密值将被创建在基于秘密卷挂载到的文件夹中的键命名的文件中。

要部署我们的新配置，您首先需要删除数据库服务及其关联的持久卷，因为这包括了先前的凭据，然后重新部署数据库服务。您可以通过在执行删除和应用操作时引用整个`k8s/db`目录来轻松完成此操作，而不是逐个指定每个文件：

```
> kubectl delete -f k8s/db
service "todobackend-db" deleted
deployment.apps "todobackend-db" deleted
persistentvolumeclaim "todobackend-data" deleted
> kubectl apply -f k8s/db
service "todobackend-db" created
deployment.apps "todobackend-db" created
persistentvolumeclaim "todobackend-data" created
```

一旦您重新创建了`db`服务，您可以使用`kubectl exec`命令来验证`MYSQL_PASSWORD`和`MYSQL_ROOT_PASSWORD`秘密项目是否已写入`/tmp/secrets`：

```
> kubectl exec $(kubectl get pods -l app=todobackend-db -o=jsonpath='{.items[0].metadata.name}')\
 ls /tmp/secrets
MYSQL_PASSWORD
MYSQL_ROOT_PASSWORD
```

# 为应用程序使用秘密

现在，我们需要通过修改`k8s/app/deployment.yaml`文件来更新 todobackend 服务以使用我们的秘密：

```
...
...
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: todobackend
  labels:
    app: todobackend
spec:
  replicas: 2
  selector:
    matchLabels:
      app: todobackend
  template:
    metadata:
      labels:
        app: todobackend
    spec:
      securityContext:
        fsGroup: 1000
      volumes:
      - name: public
        emptyDir: {}
 - name: secrets
 secret:
 secretName: todobackend-secret
          items:
 - key: MYSQL_PASSWORD
            path: MYSQL_PASSWORD
 - key: SECRET_KEY
            path: SECRET_KEY
      initContainers:
      - name: collectstatic
        image: 385605022855.dkr.ecr.us-east-1.amazonaws.com/docker-in-aws/todobackend
        imagePullPolicy: IfNotPresent
        volumeMounts:
        - name: public
          mountPath: /public
        command: ["python3","manage.py","collectstatic","--no-input"]
        env:
        - name: DJANGO_SETTINGS_MODULE
          value: todobackend.settings_release
      containers:
      - name: todobackend
        image: 385605022855.dkr.ecr.us-east-1.amazonaws.com/docker-in-aws/todobackend
        imagePullPolicy: IfNotPresent
        readinessProbe:
          httpGet:
            port: 8000
        livenessProbe:
          httpGet:
            port: 8000
        volumeMounts:
        - name: public
          mountPath: /public
 - name: secrets
 mountPath: /tmp/secrets
 readOnly: true
        command:
        - uwsgi
        - --http=0.0.0.0:8000
        - --module=todobackend.wsgi
        - --master
        - --die-on-term
        - --processes=4
        - --threads=2
        - --check-static=/public
        env:
        - name: DJANGO_SETTINGS_MODULE
          value: todobackend.settings_release
 - name: SECRETS_ROOT
 value: /tmp/secrets
 - name: MYSQL_HOST
 value: todobackend-db
 - name: MYSQL_USER
 value: todo
```

您必须定义`secrets`卷，并确保只有`MYSQL_PASSWORD`和`SECRET_KEY`项目暴露给**todobackend**容器。在**todobackend**应用程序容器中只读挂载卷后，您必须使用`SECRETS_ROOT`环境变量配置到`secrets`挂载的路径。回想一下，在上一章中，我们为**todobackend**应用程序添加了对 Docker 秘密的支持，默认情况下，它期望您的秘密位于`/run/secrets`。但是，因为`/run`是一个特殊的 tmpfs 文件系统，您不能在此位置使用常规文件系统挂载您的秘密，因此我们需要配置`SECRETS_ROOT`环境变量，重新配置应用程序将查找的秘密位置。我们还必须配置`MYSQL_HOST`和`MYSQL_USER`环境变量，以便与`MYSQL_PASSWORD`秘密一起，**todobackend**应用程序具有连接到数据库服务所需的信息。

如果您现在部署更改，您应该能够验证**todobackend**容器中挂载了正确的秘密项目：

```
> kubectl apply -f k8s/app/
service "todobackend" unchanged
deployment.apps "todobackend" configured
> kubectl get pods
NAME                             READY   STATUS    RESTARTS   AGE
todobackend-74d47dd994-cpvl7     1/1     Running   0          35s
todobackend-74d47dd994-s2pp8     1/1     Running   0          35s
todobackend-db-574fb5746c-xcg9t  1/1     Running   0          12m
> kubectl exec todobackend-74d47dd994-cpvl7 ls /tmp/secrets
MYSQL_PASSWORD
SECRET_KEY
```

如果您浏览`http://localhost/todos`，您应该会收到一个错误，指示数据库表不存在，这意味着应用程序现在成功连接和验证到数据库，但缺少应用程序所需的模式和表。

# 运行作业

我们的**todobackend**应用程序几乎完全功能，但是有一个关键的部署任务，我们需要执行，那就是运行数据库迁移，以确保**todobackend**数据库中存在正确的模式和表。正如您在本书中所看到的，数据库迁移应该在每次部署时只执行一次，而不管我们的应用程序运行的实例数量。Kubernetes 通过一种特殊类型的控制器*job*支持这种性质的任务，正如其名称所示，运行一个任务或进程（以 pod 的形式）直到作业成功完成。

为了创建所需的数据库迁移任务作业，我们将创建一个名为`k8s/app/migrations.yaml`的新文件，该文件位于`todobackend`存储库中，这样可以独立于在同一位置定义的`deployment.yaml`文件中的其他应用程序资源来运行作业。

```
apiVersion: batch/v1
kind: Job
metadata:
  name: todobackend-migrate
spec:
  backoffLimit: 4
  template:
    spec:
      restartPolicy: Never
      volumes:
      - name: secrets
        secret:
          secretName: todobackend-secret
          items:
          - key: MYSQL_PASSWORD
            path: MYSQL_PASSWORD
      containers:
      - name: migrate
        image: 385605022855.dkr.ecr.us-east-1.amazonaws.com/docker-in-aws/todobackend
        imagePullPolicy: IfNotPresent
        volumeMounts:
        - name: secrets
          mountPath: /tmp/secrets
          readOnly: true
        command: ["python3","manage.py","migrate","--no-input"]
        env:
        - name: DJANGO_SETTINGS_MODULE
          value: todobackend.settings_release
        - name: SECRETS_ROOT
          value: /tmp/secrets
        - name: MYSQL_HOST
          value: todobackend-db
        - name: MYSQL_USER
          value: todo
```

您必须指定一种`Job`的类型来配置此资源作为作业，大部分情况下，配置与我们之前创建的 pod/deployment 模板非常相似，除了`spec.backoffLimit`属性，它定义了 Kubernetes 在失败时应尝试重新运行作业的次数，以及模板`spec.restartPolicy`属性，它应始终设置为`Never`以用于作业。

如果您现在运行作业，您应该能够验证数据库迁移是否成功运行：

```
> kubectl apply -f k8s/app
service "todobackend" unchanged
deployment.apps "todobackend" unchanged
job.batch "todobackend-migrate" created
> kubectl get jobs
NAME                  DESIRED   SUCCESSFUL   AGE
todobackend-migrate   1         1            6s
> kubectl logs jobs/todobackend-migrate
Operations to perform:
  Apply all migrations: admin, auth, contenttypes, sessions, todo
Running migrations:
  Applying contenttypes.0001_initial... OK
  Applying auth.0001_initial... OK
  Applying admin.0001_initial... OK
  Applying admin.0002_logentry_remove_auto_add... OK
  Applying contenttypes.0002_remove_content_type_name... OK
  Applying auth.0002_alter_permission_name_max_length... OK
  Applying auth.0003_alter_user_email_max_length... OK
  Applying auth.0004_alter_user_username_opts... OK
  Applying auth.0005_alter_user_last_login_null... OK
  Applying auth.0006_require_contenttypes_0002... OK
  Applying auth.0007_alter_validators_add_error_messages... OK
  Applying auth.0008_alter_user_username_max_length... OK
  Applying auth.0009_alter_user_last_name_max_length... OK
  Applying sessions.0001_initial... OK
  Applying todo.0001_initial... OK
```

在这一点上，您已经成功地部署了 todobackend 应用程序，处于完全功能状态，您应该能够连接到 todobackend 应用程序，并创建、更新和删除待办事项。

# 创建 EKS 集群

现在您已经对 Kubernetes 有了扎实的了解，并且已经定义了部署和本地运行 todobackend 应用程序所需的核心资源，是时候将我们的注意力转向弹性 Kubernetes 服务（EKS）了。

EKS 支持的核心资源是 EKS 集群，它代表了一个完全托管、高可用的 Kubernetes 管理器集群，为您处理 Kubernetes 控制平面。在本节中，我们将重点关注在 AWS 中创建 EKS 集群，建立对集群的认证和访问，并部署 Kubernetes 仪表板。

创建 EKS 集群包括以下主要任务：

+   安装客户端组件：为了管理您的 EKS 集群，您需要安装各种客户端组件，包括`kubectl`（您已经安装了）和 AWS IAM 认证器用于 Kubernetes 工具。

+   创建集群资源：这建立了 Kubernetes 的控制平面组件，包括 Kubernetes 主节点。在使用 EKS 时，主节点作为一个完全托管的服务提供。

+   为 EKS 配置 kubectl：这允许您使用本地 kubectl 客户端管理 EKS。

+   创建工作节点：这包括用于运行容器工作负载的 Kubernetes 节点。在使用 EKS 时，您需要负责创建自己的工作节点，通常会以 EC2 自动扩展组的形式部署。就像对于 ECS 服务一样，AWS 提供了一个 EKS 优化的 AMI（[`docs.aws.amazon.com/eks/latest/userguide/eks-optimized-ami.html`](https://docs.aws.amazon.com/eks/latest/userguide/eks-optimized-ami.html)），其中包括所有必要的软件组件，使工作节点能够加入您的 EKS 集群。

+   部署 Kubernetes 仪表板：Kubernetes 仪表板为您提供了一个基于 Web 的管理界面，用于管理和监视您的集群和容器应用程序。

在撰写本文时，EKS 集群不属于 AWS 免费套餐，并且每分钟收费 0.20 美元，因此在继续之前请记住这一点（请参阅[`aws.amazon.com/eks/pricing/`](https://aws.amazon.com/eks/pricing/)获取最新定价信息）。我们将使用 CloudFormation 模板来部署 EKS 集群和 EKS 工作节点，因此您可以根据需要轻松拆除和重新创建 EKS 集群和工作节点，以减少成本。

# 安装客户端组件

要管理您的 EKS 集群，您必须安装`kubectl`，以及 AWS IAM 认证器用于 Kubernetes 组件，它允许`kubectl`使用您的 IAM 凭据对您的 EKS 集群进行身份验证。

您已经安装了`kubectl`，因此要安装用于 Kubernetes 的 AWS IAM 认证器，您需要安装一个名为`aws-iam-authenticator`的二进制文件，该文件由 AWS 发布如下：

```
> curl -fs -o /usr/local/bin/aws-iam-authenticator https://amazon-eks.s3-us-west-2.amazonaws.com/1.10.3/2018-07-26/bin/darwin/amd64/aws-iam-authenticator
> chmod +x /usr/local/bin/aws-iam-authenticator
```

# 创建集群资源

在创建您的 EKS 集群之前，您需要确保您的 AWS 账户满足以下先决条件：

+   **VPC 资源**：EKS 资源必须部署到具有至少三个子网的 VPC 中。AWS 建议您为每个 EKS 集群创建自己的专用 VPC 和子网，但是在本章中，我们将使用在您的 AWS 账户中自动创建的默认 VPC 和子网。请注意，当您创建 VPC 并定义集群将使用的子网时，您必须指定*所有*子网，您期望您的工作节点*和*负载均衡器将被部署在其中。一个推荐的模式是在私有子网中部署您的工作节点，并确保您还包括了公共子网，以便 EKS 根据需要创建面向公众的负载均衡器。

+   **EKS 服务角色**：在创建 EKS 集群时，您必须指定一个 IAM 角色，该角色授予 EKS 服务管理您的集群的访问权限。

+   **控制平面安全组**：您必须提供一个用于 EKS 集群管理器和工作节点之间的控制平面通信的安全组。安全组规则将由 EKS 服务修改，因此您应为此要求创建一个新的空安全组。

AWS 文档包括一个入门（[`docs.aws.amazon.com/eks/latest/userguide/getting-started.html`](https://docs.aws.amazon.com/eks/latest/userguide/getting-started.html)）部分，其中提供了如何使用 AWS 控制台创建 EKS 集群的详细信息。鉴于 EKS 受 CloudFormation 支持，并且我们在本书中一直使用的基础设施即代码方法，我们需要在`todobackend-aws`存储库中创建一个名为`eks`的文件夹，并在一个名为`todobackend-aws/eks/stack.yml`的新 CloudFormation 模板文件中定义我们的 EKS 集群和相关的 EKS 服务角色：

```
AWSTemplateFormatVersion: "2010-09-09"

Description: EKS Cluster

Parameters:
  Subnets:
    Type: List<AWS::EC2::Subnet::Id>
    Description: Target subnets for EKS cluster
  VpcId:
    Type: AWS::EC2::VPC::Id
    Description: Target VPC

Resources:
  EksServiceRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: eks-service-role
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              Service:
                - eks.amazonaws.com
            Action:
              - sts:AssumeRole
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/AmazonEKSClusterPolicy
        - arn:aws:iam::aws:policy/AmazonEKSServicePolicy
  EksClusterSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupName: eks-cluster-control-plane-sg
      GroupDescription: EKS Cluster Control Plane Security Group
      VpcId: !Ref VpcId
      Tags:
        - Key: Name
          Value: eks-cluster-sg
  EksCluster:
    Type: AWS::EKS::Cluster
    Properties:
      Name: eks-cluster
      RoleArn: !Sub ${EksServiceRole.Arn}
      ResourcesVpcConfig:
        SubnetIds: !Ref Subnets
        SecurityGroupIds: 
          - !Ref EksClusterSecurityGroup
```

模板需要两个输入参数 - 目标 VPC ID 和目标子网 ID。`EksServiceRole`资源创建了一个 IAM 角色，授予`eks.awsamazon.com`服务代表您管理 EKS 集群的能力，如`ManagedPolicyArns`属性中引用的托管策略所指定的。然后，您必须为控制平面通信定义一个空安全组，并最后定义 EKS 集群资源，引用`EksServiceRole`资源的`RoleArn`属性，并定义一个针对输入`ApplicationSubnets`的 VPC 配置，并使用`EksClusterSecurityGroup`资源。

现在，您可以使用`aws cloudformation deploy`命令部署此模板，如下所示：

```
> export AWS_PROFILE=docker-in-aws
> aws cloudformation deploy --template-file stack.yml --stack-name eks-cluster \
--parameter-overrides VpcId=vpc-f8233a80 Subnets=subnet-a5d3ecee,subnet-324e246f,subnet-d281a2b6\
--capabilities CAPABILITY_NAMED_IAM
Waiting for changeset to be created..
Waiting for stack create/update to complete
Successfully created/updated stack - eks-cluster
```

集群将大约需要 10 分钟来创建，一旦创建完成，您可以使用 AWS CLI 获取有关集群的更多信息：

```
> aws eks describe-cluster --name eks-cluster --query cluster.status "ACTIVE"
> aws eks describe-cluster --name eks-cluster --query cluster.endpoint
"https://E7B5C85713AD5B11625D7A689F99383F.sk1.us-east-1.eks.amazonaws.com"
> aws eks describe-cluster --name eks-cluster --query cluster.certificateAuthority.data
"LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUN5RENDQWJDZ0F3SUJBZ0lCQURBTkJna3Foa2lHOXcwQkFRc0ZBREFWTVJNd0VRWURWUVFERXdwcmRXSmwKY201bGRHVnpNQjRYRFRFNE1EY3lNakV3TURRME9Gb1hEVEk0TURjeE9URXdNRFEwT0Zvd0ZURVRNQkVHQTFVRQpBeE1LYTNWaVpYSnVaWFJsY3pDQ0FTSXdEUVlKS29aSWh2Y05BUUVCQlFBRGdnRVBBRENDQVFvQ2dnRUJBUEh5CkVsajhLMUQ4M1V3RDFmdlhqYi9TdGZBK0tvWEtZNkVtZEhudnNXeWh1Snd2aGhkZDU2M0tVdGJnYW15Z0pxMVIKQkNCTWptWXVocG8rWm0ySEJrckZGakFFZDVIN1lWUXVOSm15TXdrQVV5MnpFTUU5SjJid3hkVEpqZ3pZdmlwVgpJc05zd3pIL1lSa1NVSElDK0VSaCtURmZJODhsTTBiZlM1R1pueUx0VkZCS3RjNGxBREVxRE1BTkFoaEc5OVZ3Cm5hL2w5THU2aW1jT1VOVGVCRFB0L1hxNGF3TFNUOEgwQlVvWGFwbEt0cFkvOFdqR055RUhzUHZHdXNXU3lkTHMKK3lKNXBlUm8yR3Nxc0VqMGhsbHpuV0RXWnlqQVU5Ni82QXVKRGZVSTBING1WNkpCZWxVU0tTRTZBOU1GSjRjYgpHeVpkYmh0akg1d3Zzdit1akNjQ0F3RUFBYU1qTUNFd0RnWURWUjBQQVFIL0JBUURBZ0trTUE4R0ExVWRFd0VCCi93UUZNQU1CQWY4d0RRWUpLb1pJaHZjTkFRRUxCUUFEZ2dFQkFIRkRIODZnNkNoR2FMejBQb21EK2tyc040SUMKRzhOb0xSc2xkTkJjQmlRczFYK0hKenNxTS9TN0svL1RhUndqVjRZTE1hbnBqWGp4TzRKUWh4Q0ZHR1F2SHptUApST1FhQXRjdWRJUHYySlg5eUlOQW1rT0hDaloyNm1Yazk1b2pjekxQRE1NTlFVR2VmbXUxK282T1ZRUldTKzBMClpta211KzVyQVVFMWtTK00yMDFPeFNGcUNnL0VDd0F4ZXd5YnFMNGw4elpPWCs3VzlyM1duMWh6a3NhSnIrRHkKUVRyQ1p2MWJ0ZENpSnhmbFVxWXN5UEs1UDh4NmhKOGN2RmRFUklFdmtYQm1VbjRkWFBWWU9IdUkwdElnU2h1RAp3K0IxVkVOeUF3ZXpMWWxLaGRQQTV4R1BMN2I0ZmN4UXhCS0VlVHpaUnUxQUhMM1R4THIxcVdWbURUbz0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="
```

集群端点和证书颁发机构数据在本章后面都是必需的，因此请注意这些值。

# 为 EKS 配置 kubectl

使用您创建的 EKS 集群，现在需要将新集群添加到本地的`kubectl`配置中。`kubectl`知道的所有集群默认都在一个名为`~/.kube/config`的文件中定义，目前如果您使用 Docker for Mac 或 Docker for Windows，则该文件将包括一个名为`docker-for-desktop-cluster`的单个集群。

以下代码演示了将您的 EKS 集群和相关配置添加到`~/.kube/config`文件中：

```
apiVersion: v1
clusters:
- cluster:
    insecure-skip-tls-verify: true
    server: https://localhost:6443
  name: docker-for-desktop-cluster
- cluster:
 certificate-authority-data: <Paste your EKS cluster certificate data here>
 server: https://E7B5C85713AD5B11625D7A689F99383F.sk1.us-east-1.eks.amazonaws.com
 name: eks-cluster
contexts:
- context:
    cluster: docker-for-desktop-cluster
    user: docker-for-desktop
  name: docker-for-desktop
- context:
 cluster: eks-cluster
 user: aws
 name: eks
current-context: docker-for-desktop-cluster
kind: Config
preferences: {}
users:
- name: aws
 user:
 exec:
 apiVersion: client.authentication.k8s.io/v1alpha1
 args:
 - token
 - -i
 - eks-cluster
 command: aws-iam-authenticator
 env:
 - name: AWS_PROFILE
 value: docker-in-aws
- name: docker-for-desktop
  user:
    client-certificate-data: ...
    client-key-data: ...
```

在`clusters`属性中首先添加一个名为`eks-cluster`的新集群，指定您在创建 EKS 集群后捕获的证书颁发机构数据和服务器端点。然后添加一个名为`eks`的上下文，这将允许您在本地 Kubernetes 服务器和 EKS 集群之间切换，并最后在用户部分添加一个名为`aws`的新用户，该用户由`eks`上下文用于对 EKS 集群进行身份验证。`aws`用户配置配置 kubectl 执行您之前安装的`aws-iam-authenticator`组件，传递参数`token -i eks-cluster`，并使用您本地的`docker-in-aws`配置文件进行身份验证访问。执行此命令将自动返回一个身份验证令牌给`kubectl`，然后可以用于对 EKS 集群进行身份验证。

在上述配置就位后，您现在应该能够访问一个名为`eks`的新上下文，并验证连接到您的 EKS 集群，如下所示：

```
> kubectl config get-contexts
CURRENT   NAME                 CLUSTER                      AUTHINFO            NAMESPACE
*         docker-for-desktop   docker-for-desktop-cluster   docker-for-desktop
          eks                  eks-cluster                  aws
> kubectl config use-context eks
Switched to context "eks".
> kubectl get all Assume Role MFA token code: ****
NAME                TYPE        CLUSTER-IP   EXTERNAL-IP   PORT(S)   AGE
service/kubernetes  ClusterIP   10.100.0.1   <none>        443/TCP   1h
```

请注意，如果您在前几章中设置了**多因素身份验证**（**MFA**）配置，每次对您的 EKS 集群运行`kubectl`命令时，都会提示您输入 MFA 令牌，这将很快变得烦人。

要暂时禁用 MFA，您可以使用`aws iam remove-user-from-group`命令将用户帐户从用户组中移除：

```
# Removes user from Users group, removing MFA requirement
# To restore MFA run: aws iam add-user-to-group --user-name justin.menga --group-name Users
> aws iam remove-user-from-group --user-name justin.menga --group-name Users
```

然后在`~/.aws/config`文件中为您的本地 AWS 配置文件注释掉`mfa_serial`行：

```
[profile docker-in-aws]
source_profile = docker-in-aws
role_arn = arn:aws:iam::385605022855:role/admin
role_session_name=justin.menga
region = us-east-1
# mfa_serial = arn:aws:iam::385605022855:mfa/justin.menga
```

# 创建工作节点

设置 EKS 的下一步是创建将加入您的 EKS 集群的工作节点。与由 AWS 完全管理的 Kubernetes 主节点不同，您负责创建和管理您的工作节点。AWS 提供了一个 EKS 优化的 AMI，其中包含加入 EKS 集群并作为 EKS 工作节点运行所需的所有软件。您可以浏览[`docs.aws.amazon.com/eks/latest/userguide/eks-optimized-ami.html`](https://docs.aws.amazon.com/eks/latest/userguide/eks-optimized-ami.html)来获取您所在地区的最新 AMI ID：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/75c0a503-604b-4852-bf2b-bc5234c54df1.png)Amazon EKS-Optimized AMI

在编写本书时，EKS-Optimized AMI 需要使用我们在前几章中学到的**cfn-init**框架进行广泛配置。创建工作节点的推荐方法是使用由 AWS 发布的预定义 CloudFormation 模板，该模板已经包含了在[`docs.aws.amazon.com/eks/latest/userguide/launch-workers.html`](https://docs.aws.amazon.com/eks/latest/userguide/launch-workers.html)中指定的所需配置：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/86d253f0-e18a-494d-9ca2-56ee21b93408.png)工作节点 CloudFormation 模板 URL

您现在可以通过在 AWS 控制台中选择**服务** | **CloudFormation**，单击**创建堆栈**按钮，并粘贴您之前在**选择模板**部分获取的工作模板 URL 来为您的工作节点创建新的 CloudFormation 堆栈：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/cafa3d9c-5393-4aa9-9be5-7aaeec57b1ec.png)创建工作节点 CloudFormation 堆栈

点击**下一步**后，您将被提示输入堆栈名称（您可以指定一个类似`eks-cluster-workers`的名称）并提供以下参数：

+   **ClusterName**：指定您的 EKS 集群的名称（在我们的示例中为`eks-cluster`）。

+   **ClusterControlPlaneSecurityGroup**：控制平面安全组的名称。在我们的示例中，我们在创建 EKS 集群时先前创建了一个名为`eks-cluster-control-plane-sg`的安全组。

+   **NodeGroupName**：这定义了将为您的工作节点创建的 EC2 自动扩展组名称的一部分。对于我们的情况，您可以指定一个名为`eks-cluster-workers`或类似的名称。

+   **NodeAutoScalingGroupMinSize**和**NodeAutoScalingGroupMaxSize**：默认情况下，分别设置为 1 和 3。请注意，CloudFormation 模板将自动缩放组的期望大小设置为`NodeAutoScalingGroupMaxSize`参数的值，因此您可能希望降低此值。

+   **NodeInstanceType**：您可以使用预定义的工作节点 CloudFormation 模板指定的最小实例类型是`t2.small`。对于 EKS，节点实例类型不仅在 CPU 和内存资源方面很重要，而且还对网络要求的 Pod 容量有影响。EKS 网络模型（[`docs.aws.amazon.com/eks/latest/userguide/pod-networking.html`](https://docs.aws.amazon.com/eks/latest/userguide/pod-networking.html)）将 EKS 集群中的每个 Pod 公开为可在您的 VPC 内访问的 IP 地址，使用弹性网络接口（ENI）和运行在每个 ENI 上的次要 IP 地址的组合。您可以参考[`docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-eni.html#AvailableIpPerENI`](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-eni.html#AvailableIpPerENI)，其中描述了各种 EC2 实例类型的每个接口的最大 ENI 和次要 IP 地址的数量，并最终确定了每个节点可以运行的最大 Pod 数量。

+   **NodeImageId**：指定您所在地区的 EKS 优化 AMI 的 ID（请参阅上面的截图）。

+   **KeyName**：指定您帐户中现有的 EC2 密钥对（例如，您在本书中之前创建的管理员密钥对）。

+   **VpcId**：指定您的 EKS 集群所在的 VPC ID。

+   **Subnets**：指定您希望放置工作节点的子网。

一旦您配置了所需的各种参数，点击**下一步**按钮两次，最后确认 CloudFormation 可能会在点击**创建**按钮之前创建 IAM 资源，以部署您的工作节点。当您的堆栈成功创建后，打开堆栈的**输出**选项卡，并记录`NodeInstanceRole`输出，这是下一个配置步骤所需的：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/b95ee581-3246-49f3-89ed-40a29347f66e.png)获取 NodeInstanceRole 输出

# 将工作节点加入您的 EKS 集群

CloudFormation 堆栈成功部署后，您的工作节点将尝试加入您的集群，但是在此之前，您需要通过将名为`aws-auth`的 AWS 认证器`ConfigMap`资源应用到您的集群来授予对工作节点的 EC2 实例角色的访问权限。

ConfigMap 只是一个键/值数据结构，用于存储配置数据，可以被集群中的不同资源使用。 `aws-auth` ConfigMap 被 EKS 用于授予 AWS 用户与您的集群进行交互的能力，您可以在[`docs.aws.amazon.com/eks/latest/userguide/add-user-role.html`](https://docs.aws.amazon.com/eks/latest/userguide/add-user-role.html)上了解更多信息。您还可以从[`amazon-eks.s3-us-west-2.amazonaws.com/1.10.3/2018-06-05/aws-auth-cm.yaml`](https://amazon-eks.s3-us-west-2.amazonaws.com/1.10.3/2018-06-05/aws-auth-cm.yaml)下载一个示例`aws-auth` ConfigMap。

创建`aws-auth` ConfigMap， 在`todobackend-aws/eks`文件夹中创建一个名为`aws-auth-cm.yaml`的文件：

```
apiVersion: v1
kind: ConfigMap
metadata:
  name: aws-auth
  namespace: kube-system
data:
  mapRoles: |
    - rolearn: arn:aws:iam::847222289464:role/eks-cluster-workers-NodeInstanceRole-RYP3UYR8QBYA
      username: system:node:{{EC2PrivateDNSName}}
      groups:
        - system:bootstrappers
        - system:nodes
```

在上面的示例中，您需要粘贴在创建工作节点 CloudFormation 堆栈时获得的`NodeInstanceRole`输出的值。创建此文件后，您现在可以使用`kubectl apply`命令将其应用到您的 EKS 集群，然后通过运行`kubectl get nodes --watch`等待您的工作节点加入集群：

```
> kubectl apply -f aws-auth-cm.yaml
configmap "aws-auth" created
> **kubectl get nodes --watch
NAME                                          STATUS     ROLES    AGE   VERSION
ip-172-31-15-111.us-west-2.compute.internal   NotReady   <none>   20s   v1.10.3
ip-172-31-28-179.us-west-2.compute.internal   NotReady   <none>   16s   v1.10.3
ip-172-31-38-41.us-west-2.compute.internal    NotReady   <none>   13s   v1.10.3
ip-172-31-15-111.us-west-2.compute.internal   NotReady   <none>   23s   v1.10.3
ip-172-31-28-179.us-west-2.compute.internal   NotReady   <none>   22s   v1.10.3
ip-172-31-38-41.us-west-2.compute.internal    NotReady   <none>   22s   v1.10.3
ip-172-31-15-111.us-west-2.compute.internal   Ready      <none>   33s   v1.10.3
ip-172-31-28-179.us-west-2.compute.internal   Ready      <none>   32s   v1.10.3
ip-172-31-38-41.us-west-2.compute.internal    Ready      <none>   32s   v1.10.3
```

一旦您的所有工作节点的状态都为`Ready`，您已成功将工作节点加入您的 EKS 集群。

# 部署 Kubernetes 仪表板

设置 EKS 集群的最后一步是将 Kubernetes 仪表板部署到您的集群。Kubernetes 仪表板是一个功能强大且全面的基于 Web 的管理界面，用于管理和监视集群和容器应用程序，并部署为 Kubernetes 集群的 `kube-system` 命名空间中的基于容器的应用程序。仪表板由许多组件组成，我在这里不会详细介绍，但您可以在 [`github.com/kubernetes/dashboard`](https://github.com/kubernetes/dashboard) 上阅读更多关于仪表板的信息。

要部署仪表板，我们将首先创建一个名为 `todobackend-aws/eks/dashboard` 的文件夹，并继续下载和应用组成该仪表板的各种组件到此文件夹：

```
> **curl -fs -O https://raw.githubusercontent.com/kubernetes/dashboard/master/src/deploy/recommended/kubernetes-dashboard.yaml
> **curl -fs -O https://raw.githubusercontent.com/kubernetes/heapster/master/deploy/kube-config/influxdb/heapster.yaml
> **curl -fs -O https://raw.githubusercontent.com/kubernetes/heapster/master/deploy/kube-config/influxdb/influxdb.yaml
> **curl -fs -O https://raw.githubusercontent.com/kubernetes/heapster/master/deploy/kube-config/rbac/heapster-rbac.yaml** > **kubectl apply -f kubernetes-dashboard.yaml
secret "kubernetes-dashboard-certs" created
serviceaccount "kubernetes-dashboard" created
role.rbac.authorization.k8s.io "kubernetes-dashboard-minimal" created
rolebinding.rbac.authorization.k8s.io "kubernetes-dashboard-minimal" created
deployment.apps "kubernetes-dashboard" created
service "kubernetes-dashboard" created
> **kubectl apply -f heapster.yaml** serviceaccount "heapster" createddeployment.extensions "heapster" createdservice "heapster" created
> **kubectl apply -f influxdb.yaml
deployment.extensions "monitoring-influxdb" created
service "monitoring-influxdb" created
> **kubectl apply -f heapster-rbac.yaml** clusterrolebinding.rbac.authorization.k8s.io "heapster" created
```

然后，您需要创建一个名为 `eks-admin.yaml` 的文件，该文件创建一个具有完整集群管理员特权的服务帐户和集群角色绑定：

```
apiVersion: v1
kind: ServiceAccount
metadata:
  name: eks-admin
  namespace: kube-system
---
apiVersion: rbac.authorization.k8s.io/v1beta1
kind: ClusterRoleBinding
metadata:
  name: eks-admin
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
- kind: ServiceAccount
  name: eks-admin
  namespace: kube-system
```

创建此文件后，您需要将其应用于您的 EKS 集群：

```
> **kubectl apply -f eks-admin.yaml
serviceaccount "eks-admin" created
clusterrolebinding.rbac.authorization.k8s.io "eks-admin" created
```

有了 `eks-admin` 服务帐户，您可以通过运行以下命令检索此帐户的身份验证令牌：

```
> **kubectl -n kube-system describe secret $(kubectl -n kube-system get secret | grep eks-admin | awk '{print $1}')
Name: eks-admin-token-24kh4
Namespace: kube-system
Labels: <none>
Annotations: kubernetes.io/service-account.name=eks-admin
              kubernetes.io/service-account.uid=6d8ba3f6-8dba-11e8-b132-02b2aa7ab028

Type: kubernetes.io/service-account-token

Data
====
namespace: 11 bytes
token: **eyJhbGciOiJSUzI1NiIsImtpZCI6IiJ9.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJrdWJlLXN5c3RlbSIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VjcmV0Lm5hbWUiOiJla3MtYWRtaW4tdG9rZW4tMjRraDQiLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC5uYW1lIjoiZWtzLWFkbWluIiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZXJ2aWNlLWFjY291bnQudWlkIjoiNmQ4YmEzZjYtOGRiYS0xMWU4LWIxMzItMDJiMmFhN2FiMDI4Iiwic3ViIjoic3lzdGVtOnNlcnZpY2VhY2NvdW50Omt1YmUtc3lzdGVtOmVrcy1hZG1pbiJ9.h7hchmhGUZKjdnZRk4U1RZVS7P1tvp3TAyo10TnYI_3AOhA75gC6BlQz4yZSC72fq2rqvKzUvBqosqKmJcEKI_d6Wb8UTfFKZPFiC_USlDpnEp2e8Q9jJYHPKPYEIl9dkyd1Po6er5k6hAzY1O1Dx0RFdfTaxUhfb3zfvEN-X56M34B_Gn3FPWHIVYEwHCGcSXVhplVMMXvjfpQ-0b_1La8fb31JcnD48UolkJ1Z_DH3zsVjIR9BfcuPRoooHYQb4blgAJ4XtQYQans07bKD9lmfnQvNpaCdXV_lGOx_I5vEbc8CQKTBdJkCXaWEiwahsfwQrYtfoBlIdO5IvzZ5mg
ca.crt: 1025 bytes
```

在前面的例子中，关键信息是令牌值，连接到仪表板时需要复制和粘贴。要连接到仪表板，您需要启动 kubectl 代理，该代理提供对 Kubernetes API 的 HTTP 访问：

```
> **kubectl proxy** Starting to serve on 127.0.0.1:8001
```

如果您现在浏览到 `http://localhost:8001/api/v1/namespaces/kube-system/services/https:kubernetes-dashboard:/proxy/`，您将被提示登录到仪表板，您需要粘贴之前为 `eks-admin` 服务帐户检索的令牌：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/8315bcd4-56a5-44a0-b7a5-52bee1895ec2.png)

登录 Kubernetes 仪表板

一旦您登录，如果将 Namespace 更改为 **kube-system** 并选择 **Workloads** | **Deployments**，可能会显示一个错误，指示找不到 **monitoring-influxdb** 部署的图像：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/c029f6d5-044b-49cc-99ad-afb86d5b0fbd.png)

Kubernetes 仪表板部署失败

如果是这种情况，您需要更新之前下载的 `todobackend-aws/eks/dashboard/influxdb.yml` 文件，以引用 `k8s.gcr.io/heapster-influxdb-amd64:v1.3.3`（这是一个已知问题(`https://github.com/kubernetes/heapster/issues/2059`）可能在您阅读本章时存在或不存在）：

```
apiVersion: extensions/v1beta1
kind: Deployment
metadata:
 name: monitoring-influxdb
 namespace: kube-system
spec:
 replicas: 1
 template:
 metadata:
 labels:
 task: monitoring
 k8s-app: influxdb
 spec:
 containers:
 - name: influxdb
 image: k8s.gcr.io/heapster-influxdb-amd64:v1.3.3
...
...
```

如果您现在通过运行`kubectl apply -f influxdb.yml`重新应用文件，则仪表板应该显示所有服务都按预期运行。

# 将示例应用程序部署到 EKS

现在我们的 EKS 集群和工作节点已经就位，并且我们已经确认可以向集群部署，是时候将 todobackend 应用程序部署到 EKS 了。在本地定义了在 Kubernetes 中运行应用程序所需的各种资源时，您已经在之前完成了大部分艰苦的工作，现在所需的只是调整一些外部资源，例如负载均衡器和数据库服务的持久卷，以使用 AWS 原生服务。

现在您需要执行以下配置任务：

+   使用 AWS Elastic Block Store（EBS）配置持久卷支持

+   配置支持 AWS Elastic Load Balancers

+   部署示例应用程序

# 使用 AWS EBS 配置持久卷支持

在本章的前面，我们讨论了持久卷索赔和存储类的概念，这使您可以将存储基础设施的细节与应用程序分离。我们了解到，在使用 Docker Desktop 时，提供了一个默认的存储类，它将自动创建类型为 hostPath 的持久卷，这些持久卷可以从本地操作系统的`~/.docker/Volumes`访问，这样在使用 Docker Desktop 与 Kubernetes 时就可以轻松地提供、管理和维护持久卷。

在使用 EKS 时，重要的是要了解，默认情况下，不会为您创建任何存储类。这要求您至少创建一个存储类，如果要支持持久卷索赔，并且在大多数用例中，您通常会定义一个提供标准默认存储介质和卷类型的默认存储类，以支持您的集群。在使用 EKS 时，这些存储类的一个很好的候选者是弹性块存储（EBS），它为在集群中作为工作节点运行的 EC2 实例提供了一种标准的集成机制来支持基于块的卷存储。Kubernetes 支持一种名为`AWSElasticBlockStore`的卷类型，它允许您从工作节点访问和挂载 EBS 卷，并且还包括对名为`aws-ebs`的存储供应商的支持，该供应商提供 EBS 卷的动态提供和管理。

在这个原生支持 AWS EBS 的基础上，非常容易创建一个默认的存储类，它将自动提供 EBS 存储，我们将在名为`todobackend-aws/eks/gp2-storage-class.yaml`的文件中定义它。

```
kind: StorageClass
apiVersion: storage.k8s.io/v1
metadata:
  name: gp2
provisioner: kubernetes.io/aws-ebs
parameters:
  type: gp2
reclaimPolicy: Delete
mountOptions:
  - debug
```

我们将创建一个名为`gp2`的存储类，顾名思义，它将使用`kubernetes.io/aws-ebs`存储供应程序从 AWS 提供`gp2`类型或 SSD 的 EBS 存储。`parameters`部分控制此存储选择，根据存储类型，可能有其他配置选项可用，您可以在[`kubernetes.io/docs/concepts/storage/storage-classes/#aws`](https://kubernetes.io/docs/concepts/storage/storage-classes/#aws)了解更多信息。`reclaimPolicy`的值可以是`Retain`或`Delete`，它控制存储供应程序在从 Kubernetes 中删除与存储类关联的持久卷索赔时是否保留或删除关联的 EBS 卷。对于生产用例，您通常会将其设置为`Retain`，但对于非生产环境，您可能希望将其设置为默认的回收策略`Delete`，以免手动清理不再被集群使用的 EBS 卷。

现在，让我们在我们的 EKS 集群中创建这个存储类，之后我们可以配置新的存储类为集群的默认存储类。

```
> kubectl get sc
No resources found.
> kubectl apply -f eks/gp2-storage-class.yaml
storageclass.storage.k8s.io "gp2" created
> kubectl patch storageclass gp2 \
 -p '{"metadata": {"annotations":{"storageclass.kubernetes.io/is-default-class":"true"}}}' storageclass.storage.k8s.io "gp2" patched
> kubectl describe sc/gp2 Name: gp2
IsDefaultClass: Yes
Annotations: ...
Provisioner: kubernetes.io/aws-ebs
Parameters: type=gp2
AllowVolumeExpansion: <unset>
MountOptions:
  debug
ReclaimPolicy: Delete
VolumeBindingMode: Immediate
Events: <none>
```

创建存储类后，您可以使用`kubectl patch`命令向存储类添加注释，将该类配置为默认类。当您运行`kubectl describe sc/gp2`命令查看存储类的详细信息时，您会看到`IsDefaultClass`属性设置为`Yes`，确认新创建的类是集群的默认存储类。

有了这个，**todobackend**应用程序的 Kubernetes 配置现在有了一个默认的存储类，可以应用于`todobackend-data`持久卷索赔，它将根据存储类参数提供一个`gp2`类型的 EBS 卷。

在本章的前面创建的`eksServiceRole` IAM 角色包括`AmazonEKSClusterPolicy`托管策略，该策略授予您的 EKS 集群管理 EBS 卷的能力。如果您选择为 EKS 服务角色实现自定义 IAM 策略，您必须确保包括用于管理卷的各种 EC2 IAM 权限，例如`ec2:AttachVolume`、`ec2:DetachVolume`、`ec2:CreateVolumes`、`ec2:DeleteVolumes`、`ec2:DescribeVolumes`和`ec2:ModifyVolumes`（这不是详尽的清单）。有关由 AWS 定义的 EKS 服务角色和托管策略授予的 IAM 权限的完整清单，请参阅[`docs.aws.amazon.com/eks/latest/userguide/service_IAM_role.html`](https://docs.aws.amazon.com/eks/latest/userguide/service_IAM_role.html)。

# 配置对 AWS 弹性负载均衡器的支持

在本章的前面，当您为 todobackend 应用程序定义 Kubernetes 配置时，您创建了一个类型为`LoadBalancer`的 todobackend 应用程序的服务。我们讨论了负载均衡器的实现细节是特定于部署到的 Kubernetes 集群的平台的，并且在 Docker Desktop 的情况下，Docker 提供了自己的负载均衡器组件，允许服务暴露给开发机器上的本地网络接口。

在使用 EKS 时，好消息是您不需要做任何事情来支持`LoadBalancer`类型的服务 - 您的 EKS 集群将自动为每个服务端点创建并关联一个 AWS 弹性负载均衡器，`AmazonEKSClusterPolicy`托管策略授予了所需的 IAM 权限。

Kubernetes 确实允许您通过配置*注释*来配置`LoadBalancer`类型的供应商特定功能，这是一种元数据属性，将被给定供应商在其目标平台上理解，并且如果在不同平台上部署，比如您的本地 Docker Desktop 环境，将被忽略。您可以在[`kubernetes.io/docs/concepts/services-networking/service/#publishing-services-service-types`](https://kubernetes.io/docs/concepts/services-networking/service/#publishing-services-service-types)了解更多关于这些注释的信息，以下示例演示了向`todobackend/k8s/app/deployment.yaml`文件中的服务定义添加了几个特定于 AWS 弹性负载均衡器的注释：

```
apiVersion: v1
kind: Service
metadata:
  name: todobackend
  annotations:
 service.beta.kubernetes.io/aws-load-balancer-backend-protocol: "http"
 service.beta.kubernetes.io/aws-load-balancer-connection-draining-enabled: "true"
 service.beta.kubernetes.io/aws-load-balancer-connection-draining-timeout: "60"
spec:
  selector:
    app: todobackend
  ports:
  - protocol: TCP
    port: 80
    targetPort: 8000
  type: LoadBalancer
---
...
...
```

在前面的示例中，我们添加了以下注释：

+   `service.beta.kubernetes.io/aws-load-balancer-backend-protocol`: 这将配置后端协议。值为`http`可确保在传入请求上设置`X-Forward-For`标头，以便您的 Web 应用程序可以跟踪客户端 IP 地址。

+   `service.beta.kubernetes.io/aws-load-balancer-connection-draining-enabled`: 这将启用连接排空。

+   `service.beta.kubernetes.io/aws-load-balancer-connection-draining-timeout`: 这指定了连接排空超时。

一个重要的要点是，注释期望每个值都是字符串值，因此请确保引用布尔值，如`"true"`和`"false"`，以及任何数值，如`"60"`，如前面的代码所示。

# 部署示例应用程序

您现在可以准备将示例应用程序部署到 AWS，首先切换到 todobackend 存储库，并确保您正在使用本章前面创建的`eks`上下文：

```
todobackend> kubectl config use-context eks
Switched to context "eks".
todobackend> kubectl config get-contexts
CURRENT   NAME                 CLUSTER                      AUTHINFO             NAMESPACE
          docker-for-desktop   docker-for-desktop-cluster   docker-for-desktop
*         eks                  eks-cluster                  aws
```

# 创建秘密

请注意，应用程序和数据库服务都依赖于我们在本地 Docker Desktop 上手动创建的秘密，因此您首先需要在 EKS 上下文中创建这些秘密：

```
> kubectl create secret generic todobackend-secret \
 --from-literal=MYSQL_PASSWORD="$(openssl rand -base64 32)" \
 --from-literal=MYSQL_ROOT_PASSWORD="$(openssl rand -base64 32)" \
 --from-literal=SECRET_KEY="$(openssl rand -base64 50)"
secret "todobackend-secret" created
```

# 部署数据库服务

现在可以部署数据库服务，这应该根据您之前创建的默认存储类的配置创建一个新的由 EBS 支持的持久卷：

```
> kubectl apply -f k8s/db
service "todobackend-db" created
deployment.apps "todobackend-db" created
persistentvolumeclaim "todobackend-data" created
> kubectl get pv
NAME                                      CAPACITY STATUS  CLAIM                     STORAGECLASS
pvc-18ac5d3f-925c-11e8-89e1-06186d140068  8Gi      Bound   default/todobackend-data  gp2 
```

您可以看到已创建了持久卷，如果您在 AWS 控制台中浏览**服务** | **EC2**并从左侧 ELASTIC BLOCK STORAGE 菜单中选择**卷**，您应该能够看到持久值的相应 EBS 卷：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/30dc1bb5-7f02-4b95-9203-d31dc5359383.png)

查看 EBS 卷

请注意，Kubernetes 使用多个标签标记 EBS 卷，以便轻松识别与给定 EBS 卷关联的哪个持久卷和持久卷索赔。

在 Kubernetes 仪表板中，您可以通过选择**工作负载** | **部署**来验证`todobackend-db`部署是否正在运行：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/112c5cad-3258-4358-b836-c1fe352f41fc.png)

查看 EBS 卷

# 部署应用程序服务

有了数据库服务，现在可以继续部署应用程序：

```
> kubectl apply -f k8s/app
service "todobackend" created
deployment.apps "todobackend" created
job.batch "todobackend-migrate" created
```

部署应用程序将执行以下任务：

+   创建`todobackend-migrate`作业，运行数据库迁移

+   创建 `todobackend` 部署，其中运行一个 collectstatic initContainer，然后运行主要的 todobackend 应用程序容器

+   创建 `todobackend` 服务，将部署一个带有 AWS ELB 前端的新服务

在 Kubernetes 仪表板中，如果选择 **发现和负载均衡** | **服务** 并选择 **todobackend** 服务，您可以查看服务的每个内部端点，以及外部负载均衡器端点：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/caeb39a5-d2a2-4864-b707-b2822a511d4f.png)

在 Kubernetes 仪表板中查看 todobackend 服务您还可以通过运行 `kubectl describe svc/todobackend` 命令来获取外部端点 URL。

如果您单击外部端点 URL，您应该能够验证 todobackend 应用程序是完全功能的，所有静态内容都正确显示，并且能够在应用程序数据库中添加、删除和更新待办事项项目：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/15a03619-bdd8-4854-875c-955fbad7f459.png)

验证 todobackend 应用程序

# 拆除示例应用程序

拆除示例应用程序非常简单，如下所示：

```
> kubectl delete -f k8s/app
service "todobackend" deleted
deployment.apps "todobackend" deleted
job.batch "todobackend-migrate" deleted
> kubectl delete -f k8s/db
service "todobackend-db" deleted
deployment.apps "todobackend-db" deleted
persistentvolumeclaim "todobackend-data" deleted
```

完成后，您应该能够验证与 todobackend 服务关联的弹性负载均衡器资源已被删除，以及 todobackend 数据库的 EBS 卷已被删除，因为您将默认存储类的回收策略配置为删除。当然，您还应该删除本章前面创建的工作节点堆栈和 EKS 集群堆栈，以避免不必要的费用。

# 摘要

在本章中，您学习了如何使用 Kubernetes 和 AWS 弹性 Kubernetes 服务 (EKS) 部署 Docker 应用程序。Kubernetes 已经成为了领先的容器管理平台之一，拥有强大的开源社区，而且现在 AWS 支持 Kubernetes 客户使用 EKS 服务，Kubernetes 肯定会更受欢迎。

您首先学会了如何在 Docker Desktop 中利用 Kubernetes 的本机支持，这使得在本地快速启动和运行 Kubernetes 变得非常容易。您学会了如何创建各种核心 Kubernetes 资源，包括 pod、部署、服务、秘密和作业，这些为在 Kubernetes 中运行应用程序提供了基本的构建块。您还学会了如何配置对持久存储的支持，利用持久卷索赔来将应用程序的存储需求与底层存储引擎分离。

然后，您了解了 EKS，并学会了如何创建 EKS 集群以及相关的支持资源，包括运行工作节点的 EC2 自动扩展组。您建立了对 EKS 集群的访问，并通过部署 Kubernetes 仪表板来测试集群是否正常工作，该仪表板为您的集群提供了丰富而强大的管理用户界面。

最后，您开始部署 todobackend 应用程序到 EKS，其中包括与 AWS Elastic Load Balancer（ELB）服务集成以进行外部连接，以及使用 Elastic Block Store（EBS）提供持久存储。这里的一个重要考虑因素是，当在 Docker Desktop 环境中部署时，我们不需要修改我们之前创建的 Kubernetes 配置，除了添加一些注释以控制 todobackend 服务负载均衡器的配置（在使用 Docker Desktop 时会忽略这些注释，因此被视为“安全”的特定于供应商的配置元素）。您应该始终努力实现这个目标，因为这确保了您的应用程序在不同的 Kubernetes 环境中具有最大的可移植性，并且可以轻松地独立部署，而不受基础 Kubernetes 平台的影响，无论是本地开发环境、AWS EKS 还是 Google Kubernetes Engine（GKE）。

好吧，所有美好的事情都必须结束了，现在是时候恭喜并感谢您完成了这本书！写这本书是一件非常愉快的事情，我希望您已经学会了如何利用 Docker 和 AWS 的力量来测试、构建、部署和操作自己的容器应用程序。

# 问题

1.  True/false: Kubernetes is a native feature of Docker Desktop CE.

1.  您可以使用 commands 属性在 pod 定义中定义自定义命令字符串，并注意到 entrypoint 脚本容器不再被执行。您如何解决这个问题？

1.  正确/错误：Kubernetes 包括三种节点类型-管理节点、工作节点和代理节点。

1.  正确/错误：Kubernetes 提供与 AWS 应用负载均衡器的集成。

1.  正确/错误：Kubernetes 支持将 EBS 卷重新定位到集群中的其他节点。

1.  您可以使用哪个组件将 Kubernetes API 暴露给 Web 应用程序？

1.  正确/错误：Kubernetes 支持与弹性容器注册表的集成。

1.  什么 Kubernetes 资源提供可用于连接到给定应用程序的多个实例的虚拟 IP 地址？

1.  什么 Kubernetes 资源适合运行数据库迁移？

1.  正确/错误：EKS 管理 Kubernetes 管理节点和工作节点。

1.  在使用 EKS 时，默认存储类提供什么类型的 EBS 存储？

1.  您想在每次部署需要在启动 Pod 中的主应用程序之前运行的任务。您将如何实现这一点？

# 进一步阅读

您可以查看以下链接，了解本章涵盖的主题的更多信息：

+   什么是 Kubernetes？：[`kubernetes.io/docs/concepts/overview/what-is-kubernetes/`](https://kubernetes.io/docs/concepts/overview/what-is-kubernetes/)

+   Kubernetes 教程：[`kubernetes.io/docs/tutorials/`](https://kubernetes.io/docs/tutorials/)

+   Kubernetes Pods：[`kubernetes.io/docs/concepts/workloads/pods/pod-overview/`](https://kubernetes.io/docs/concepts/workloads/pods/pod-overview/)

+   Kubernetes 部署：[`kubernetes.io/docs/concepts/workloads/controllers/deployment/`](https://kubernetes.io/docs/concepts/workloads/controllers/deployment/)

+   Kubernetes 作业：[`kubernetes.io/docs/concepts/workloads/controllers/jobs-run-to-completion/`](https://kubernetes.io/docs/concepts/workloads/controllers/jobs-run-to-completion/)

+   Kubernetes 服务：[`kubernetes.io/docs/concepts/services-networking/service/`](https://kubernetes.io/docs/concepts/services-networking/service/)

+   服务和 Pod 的 DNS：[`kubernetes.io/docs/concepts/services-networking/dns-pod-service/`](https://kubernetes.io/docs/concepts/services-networking/dns-pod-service/)

+   Kubernetes 秘密：[`kubernetes.io/docs/concepts/configuration/secret/`](https://kubernetes.io/docs/concepts/configuration/secret/)

+   Kubernetes 卷：[`kubernetes.io/docs/concepts/storage/volumes/`](https://kubernetes.io/docs/concepts/storage/volumes/)

+   Kubernetes 持久卷：[`kubernetes.io/docs/concepts/storage/persistent-volumes/`](https://kubernetes.io/docs/concepts/storage/persistent-volumes/)

+   Kubernetes 存储类：[`kubernetes.io/docs/concepts/storage/storage-classes/`](https://kubernetes.io/docs/concepts/storage/storage-classes/)

+   动态卷配置：[`kubernetes.io/docs/concepts/storage/dynamic-provisioning/`](https://kubernetes.io/docs/concepts/storage/dynamic-provisioning/)

+   Kubectl 命令参考：[`kubernetes.io/docs/reference/generated/kubectl/kubectl-commands`](https://kubernetes.io/docs/reference/generated/kubectl/kubectl-commands)

+   Amazon EKS 用户指南：[`docs.aws.amazon.com/eks/latest/userguide/what-is-eks.html`](https://docs.aws.amazon.com/eks/latest/userguide/what-is-eks.html)

+   EKS 优化 AMI：[`docs.aws.amazon.com/eks/latest/userguide/eks-optimized-ami.html`](https://docs.aws.amazon.com/eks/latest/userguide/eks-optimized-ami.html)

+   EKS 集群 CloudFormation 资源参考：[`docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-cluster.html`](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-cluster.html)
