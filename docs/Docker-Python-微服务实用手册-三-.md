# Docker Python 微服务实用手册（三）

> 原文：[`zh.annas-archive.org/md5/50389059E7B6623191724DBC60F2DDF3`](https://zh.annas-archive.org/md5/50389059E7B6623191724DBC60F2DDF3)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：使用 GitOps 原则

在了解如何配置 Kubernetes 集群之后，我们将学习如何使用 GitOps 实践来进行配置，而不是应用手动命令和文件。GitOps 意味着使用 Git 存储库来管理集群配置，以存储和跟踪包含配置的 YAML 文件。我们将看到如何将 GitHub 存储库与集群链接，以便使用 Flux 定期更新。

这种方法允许我们以确定性的方式存储配置，以代码描述基础设施的更改。更改可以进行审查，并且集群可以从头开始恢复或复制，正如我们将在第九章 *管理工作流*中看到的那样。

本章将涵盖以下主题：

+   理解 GitOps 的描述

+   设置 Flux 以控制 Kubernetes 集群

+   配置 GitHub

+   通过 GitHub 进行 Kubernetes 集群更改

+   在生产环境中工作

在本章结束时，您将了解如何将 Kubernetes 配置存储在 Git 存储库中，并自动应用合并到主分支的任何更改。

# 技术要求

本章示例的代码可在 GitHub 上找到：[`github.com/PacktPublishing/Hands-On-Docker-for-Microservices-with-Python/tree/master/Chapter08`](https://github.com/PacktPublishing/Hands-On-Docker-for-Microservices-with-Python/tree/master/Chapter08)。

您需要安装`fluxctl`工具。然后，我们将使用此工具手动同步并获取 SSH 密钥，以允许 Flux 与 Git 存储库进行交互。请参阅其文档中的安装方法：[`docs.fluxcd.io/en/stable/tutorials/get-started.html`](https://docs.fluxcd.io/en/stable/tutorials/get-started.html)。

# 理解 GitOps 的描述

运维中的一个传统大问题是确保不同服务器保持适当的配置。当您拥有一大批服务器时，部署服务并保持它们正确配置并不是一项简单的任务。

在本章中，我们将使用*配置*来描述服务以及在生产环境中运行所需的所有配置。这包括服务的特定版本，以及基础设施（操作系统版本，服务器数量等）或依赖服务的软件包和配置（负载均衡器，第三方库等）。

因此，*配置管理*将是进行更改的方式。

随着基础设施的增长，保持所有服务器上的配置跟踪是具有挑战性的。最常见的更改是部署服务的新版本，但还有其他可能性。例如，需要添加到负载均衡器的新服务器，用于修复安全漏洞的 NGINX 的新配置调整，或者用于启用功能的服务的新环境变量。

初始阶段是手动配置，但随着时间的推移，这变得难以做到。

# 管理配置

手动配置意味着团队中的某人跟踪少量服务器，并且在需要进行更改时，单独登录到每台服务器并进行所需的更改。

这种操作方式在多个服务器上需要大量工作，并且容易出错，因为它们可能很容易发散。

因此，一段时间后，可以通过使用 Fabric ([`www.fabfile.org/`](http://www.fabfile.org/))或 Capistrano ([`capistranorb.com/`](https://capistranorb.com/))的一些脚本来改进。基本模型是将配置和新代码推送到服务器，并执行一些自动化任务，在最后重新启动服务。通常，这是直接从团队的计算机上作为手动步骤完成的。

代码和配置通常存在于 Git 上，但手动过程使得可以更改这一点，因为它是分离的。如果以这种方式工作，请确保只部署存储在源代码控制下的文件。

一些服务器维护的元素，如操作系统升级或更新库，可能仍然需要手动完成。

以下图表显示了代码是如何从进行配置更改的团队成员的计算机上推送的：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-dkr-msvc-py/img/eb0cae60-9e53-4481-867b-a36d9c12c30b.png)

在这个阶段，可以通过手动添加新的基础设施，也可以使用诸如 Terraform（[`www.terraform.io/`](https://www.terraform.io/)）这样的工具与云服务进行交互。

一个更复杂的选择是使用 Puppet（[`puppet.com/`](https://puppet.com/)）或 Chef（[`www.chef.io/`](https://www.chef.io/)）等工具。它们采用客户端-服务器架构。它们允许我们使用自己的声明性语言描述服务器的状态，当服务器中的状态发生变化时，所有客户端都会更新以遵循定义。服务器将报告任何问题或偏差，并将集中配置定义。

这个过程总结在下面的图表中：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-dkr-msvc-py/img/0efcc43d-9cf4-4a97-ba2f-bf652c5e7998.png)

在某些情况下，这些工具可以在云服务中分配资源；例如，在 AWS 中添加一个新的 EC2 实例。

配置管理工具还有助于监控并执行一些纠正任务。例如，它可以重新启动应该运行的服务，或者在更改配置时出现问题时重试。

它也更适合于更多服务器的情况。

所有这些策略都需要专门的工具，通常由特定的运维团队处理。这使得开发人员无法配置，需要他们之间的协调才能进行配置更新。

这种工作分工的划分会产生一些摩擦，随着时间的推移，DevOps 运动提出了其他组织这项工作的方式。

# 理解 DevOps

传统的工作划分方式是创建一个控制基础设施和部署的运维团队，以及一个创建服务的开发团队。

这种方法的问题在于开发人员通常不会真正了解他们的代码在生产环境中是如何工作的，同时，运维人员也不会确切地知道部署包含什么。这可能导致“我不知道它是什么”/“我不知道它在哪里”的情况，两个团队之间存在鸿沟。DevOps 最终被创建为填补这一差距的方法。

一个典型的问题是一个服务在生产环境中经常失败，并被运维发现，运维会执行纠正策略（例如，重新启动服务）。

然而，开发团队并不确切知道是什么导致了失败，他们还有其他紧迫的任务，所以他们不会解决问题。

随着时间的推移，这可能会危及系统的稳定性。

DevOps 是一套旨在改善运营方面和开发方面之间协作的技术。它旨在通过使开发人员了解整个运营方面来实现快速部署，并尽可能地使用自动化来简化运营。

它的核心是赋予团队控制自己的基础设施和部署的能力，加快部署速度并了解基础设施以帮助及早识别问题。团队应该在部署和支持基础设施方面是自治的。

为了实现 DevOps 实践，您需要一些工具来以受控的方式控制不同的操作。GitOps 是一个有趣的选择，特别是如果您使用 Kubernetes。

# 定义 GitOps

GitOps 的想法很简单——我们使用 Git 来描述我们的基础设施和配置管理。对定义分支的任何更改都将触发相关的更改。

如果您能够通过代码定义整个系统，Git 会给您带来很多优势：

+   对基础设施或配置管理的任何更改都是有版本的。它们是明确的，如果有问题可以回滚。版本之间的变化可以通过差异来观察，这是正常的 Git 操作。

+   Git 仓库可以作为备份，可以在底层硬件发生灾难性故障时实现从头恢复。

+   这是最常见的源代码控制工具。公司里的每个人可能都知道它的工作原理并且可以使用它。它也很容易与现有的工作流程集成，比如审查。

GitOps 概念是由 Weaveworks 在一篇博客文章中引入并命名的（[`www.weave.works/blog/gitops-operations-by-pull-request`](https://www.weave.works/blog/gitops-operations-by-pull-request)）。从那时起，它在公司中被越来越多地使用。

虽然 GitOps 也可以应用于其他类型的部署（当然也已经应用了），但它与 Kubernetes 有很好的协同作用，这实际上是 Weaveworks 博客文章中的描述。

可以使用 YAML 文件完全配置 Kubernetes 集群，这几乎包含了整个系统的定义。正如我们在上一章中看到的，这可能包括诸如负载均衡器之类的元素的定义。Kubernetes 集群外的元素，比如外部 DNS，这些不包含在 YAML 文件中的元素，很少发生变化。

服务器和基础设施可以使用其他工具自动化，比如 Terraform，或者使用第七章中描述的自动化程序，*配置和保护生产系统*。

出于实际原因，一些基础设施操作完全可以是手动的。例如，升级 EKS 集群的 Kubernetes 版本是一个可以通过 AWS 控制台完成的操作，而且很少发生，所以手动操作也是可以的。

这些操作保持手动也是可以的，因为自动化它们可能不会带来回报。

正如我们在第六章中看到的，Kubernetes 的 YAML 文件包含可以使用`kubectl apply -f <file>`命令应用的元素定义。Kubernetes 非常灵活，因为一个文件可以包含多个元素或一个元素。

将所有的 YAML 文件分组到一个目录结构下，并将它们纳入 Git 控制，这是一种非常明确的应用变更的方式。这是我们将要操作的方式。

这个操作并不复杂，但我们将使用一个现有的工具，由 Weaveworks 创建，叫做**Flux**。

# 设置 Flux 来控制 Kubernetes 集群

Flux（[`github.com/fluxcd/flux`](https://github.com/fluxcd/flux)）是一个工具，确保 Kubernetes 集群的状态与存储在 Git 仓库中的文件匹配。

它被部署在 Kubernetes 集群内部，作为另一个部署。它每 5 分钟运行一次，并与 Git 仓库和 Docker 注册表进行检查。然后，它应用任何变更。这有助于访问 Git 仓库，因为不需要在 CI 系统内部创建任何推送机制。

我们将看到如何在 Kubernetes 内部启动一个从 GitHub 仓库拉取的 Flux 容器。

# 启动系统

为了简单起见，我们将使用本地 Kubernetes。我们将使用第六章中描述的镜像，所以确保运行以下命令：

```py
$ cd Chapter06
$ cd frontend
$ docker-compose build server
...
Successfully tagged thoughts_frontend:latest
$ cd ..
$ cd thoughts_backend/
$ docker-compose build server db
...
Successfully tagged thoughts_frontend:latest
$ cd ..
$ cd users_backend
$ docker-compose build server db
...
Successfully tagged users_server:latest
```

基本的 Kubernetes 配置存储在示例文件夹（[`github.com/PacktPublishing/Hands-On-Docker-for-Microservices-with-Python/tree/master/Chapter08/example`](https://github.com/PacktPublishing/Hands-On-Docker-for-Microservices-with-Python/tree/master/Chapter08/example)）子目录中。

您可以使用以下命令部署整个系统：

```py
$ cd Chapter08/example
$ kubectl apply -f namespace.yaml
namespace/example created
$ kubectl apply -f . --recursive
deployment.apps/frontend created
ingress.extensions/frontend-ingress created
service/frontend-service created
namespace/example unchanged
deployment.apps/thoughts-backend created
ingress.extensions/thoughts-backend-ingress created
service/thoughts-service created
deployment.apps/users-backend created
ingress.extensions/users-backend-ingress created
service/users-service created
```

这创建了整个系统。

应用`namespace.yaml`文件以避免无法部署元素，因为命名空间不存在，但您可以两次运行`kubectl apply -f . --recursive`命令。

如果您检查系统，应该已经部署了，通过运行`kubectl get pods`命令显示：

```py
$ kubectl get pods -n example
NAME                   READY STATUS  RESTARTS AGE
frontend-j75fp         1/1   Running 0        4m
frontend-n85fk         1/1   Running 0        4m
frontend-nqndl         1/1   Running 0        4m
frontend-xnljj         1/1   Running 0        4m
thoughts-backend-f7tq7 2/2   Running 0        4m
users-backend-7wzts    2/2   Running 0        4m
```

请注意，有四个`frontend`的副本。我们将在本章中更改 Pod 的数量，作为如何更改部署的示例。

现在，删除部署以从头开始：

```py
$ kubectl delete namespace example
namespace "example" deleted
```

有关此设置的更多详细信息，请查看第六章中的*在本地部署完整系统*部分，*使用 Kubernetes 进行本地开发*。

# 配置 Flux

我们将准备一个 Flux 系统，它将帮助我们跟踪我们的 Git 配置。我们根据这个存储库中的 Flux 示例准备了一个（[`github.com/fluxcd/flux/tree/master/deploy`](https://github.com/fluxcd/flux/tree/master/deploy)），它在`Chapter08/flux`子目录中可用。

主文件是`flux-deployment.yaml`。其中大部分是注释的样板文件，但请查看要从中提取的存储库的定义：

```py
# Replace the following URL to change the Git repository used by Flux.
- --git-url=git@github.com:PacktPublishing/Hands-On-Docker-for-Microservices-with-Python.git
- --git-branch=master
# Include this if you want to restrict the manifests considered by flux
# to those under the following relative paths in the git repository
- --git-path=Chapter08/example
```

这些行告诉 Flux 要使用的存储库，分支和任何路径。如果路径被注释了，在您的情况下可能是这样，它将使用整个存储库。在下一节中，我们需要更改要使用的存储库为您自己的存储库。

请注意，我们使用`flux`命名空间来部署所有这些元素。您可以重用您的主要命名空间，或者如果对您更有效，可以使用默认命名空间。

要使用 Flux，请创建命名空间，然后应用完整的`flux`目录：

```py
$ kubectl apply -f flux/namespace.yaml
namespace/flux created
$ kubectl apply -f flux/
serviceaccount/flux created
clusterrole.rbac.authorization.k8s.io/flux created
clusterrolebinding.rbac.authorization.k8s.io/flux created
deployment.apps/flux created
secret/flux-git-deploy created
deployment.apps/memcached created
service/memcached created
namespace/flux unchanged
```

使用以下代码，您可以检查一切是否按预期运行：

```py
$ kubectl get pods -n flux
NAME                       READY STATUS  RESTARTS AGE
flux-75fff6bbf7-bfnq6      1/1   Running 0        34s
memcached-84f9f4d566-jv6gp 1/1   Running 0        34s
```

但是，要能够从 Git 存储库部署，我们需要对其进行配置。

# 配置 GitHub

虽然我们可以配置任何 Git 存储库，但通常，我们将使用 GitHub 进行设置。我们需要设置一个有效的密钥来访问 Git 存储库。

这样做的最简单方法是允许 Flux 生成自己的密钥，并将其添加到 GitHub 存储库。但是，为了能够这样做，我们需要创建自己的 GitHub 存储库。

# 分叉 GitHub 存储库

配置存储库的第一步是分叉。让我们查看更多详细信息的以下步骤：

1.  转到 GitHub 代码的页面（[`github.com/PacktPublishing/Hands-On-Docker-for-Microservices-with-Python/`](https://github.com/PacktPublishing/Hands-On-Docker-for-Microservices-with-Python/)），然后单击右上角的 Fork 以生成您自己的副本。

1.  一旦您拥有自己的副本，它将具有类似以下的 URL：

```py
https://github.com/<YOUR GITHUB USER>/Hands-On-Docker-for-Microservices-with-Python/
```

1.  现在，您需要在`Chapter08/flux/flux-deployment.yaml`文件中替换它为`--git-url`参数。

1.  更改后，使用以下命令重新应用 Flux 配置：

```py
$ kubectl apply -f flux/flux-deployment.yaml
deployment.apps/flux changed
```

现在，Flux 正在跟踪您完全控制的自己的存储库，并且您可以对其进行更改。首先，我们需要允许 Flux 访问 GitHub 存储库，可以通过部署密钥实现。

# 添加部署密钥

为了允许 Flux 访问 GitHub，我们需要将其秘钥添加为有效的部署密钥。使用`fluxctl`，很容易获取当前的`ssh`秘钥；只需运行以下命令：

```py
$ fluxctl identity --k8s-fwd-ns flux
ssh-rsa <secret key>
```

有了这些信息，转到您分叉的 GitHub 项目的“设置|部署密钥”部分。使用描述性名称填写标题，使用之前获取的秘钥填写密钥部分，然后选择“添加密钥”：

！[](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-dkr-msvc-py/img/a8ab5d41-bfa3-4964-83e9-88a473e2f7b5.png)

一定要选择“允许写入访问”的复选框。现在，Flux 将能够联系 GitHub。

下一步是在 GitHub 和集群上同步状态。

# 同步 Flux

我们可以与 Flux 同步，因此 GitHub 中的描述将应用于集群，使用以下命令：

```py
$ fluxctl sync --k8s-fwd-ns flux
Synchronizing with git@github.com:<repo>.git
Revision of master to apply is daf1b12
Waiting for daf1b12 to be applied ...
Done.
Macbook Pro:Chapter08 $ kubectl get pods -n example
NAME                   READY STATUS  RESTARTS AGE
frontend-8srpc         1/1   Running 0        24s
frontend-cfrvk         1/1   Running 0        24s
frontend-kk4hj         1/1   Running 0        24s
frontend-vq4vf         1/1   Running 0        24s
thoughts-backend-zz8jw 2/2   Running 0        24s
users-backend-jrvcr    2/2   Running 0        24s
```

同步需要一点时间，可能会出现错误，指出正在克隆存储库：

```py
$ fluxctl sync --k8s-fwd-ns flux
Error: git repository git@github.com:<repo>.git is not ready to sync (status: cloned)
Run 'fluxctl sync --help' for usage
```

等待几分钟，然后重试：

```py
$ fluxctl sync --k8s-fwd-ns flux
Synchronizing with git@github.com:<repo>.git
Revision of master to apply is daf1b12
Waiting for daf1b12 to be applied ...
Done.
$
```

您的 Flux 部署，因此本地 Kubernetes 集群现在与 Git 中的配置同步，并将随任何更改更新。

# 通过 GitHub 进行 Kubernetes 集群更改

通过 Flux，您的本地 Kubernetes 集群将更新以反映 Git 存储库中的更改。几分钟后，Git 中的任何更改都将传播到集群。

让我们通过测试来查看这一点，更新前端部署中的 Pod 数量：

1.  按照以下描述更改您分叉的存储库中的`Chapter08/example/frontend/deployment.yaml`文件：

```py
---
apiVersion: apps/v1
kind: Deployment
metadata:
    name: frontend
    labels:
        app: frontend
    namespace: example
spec:
    replicas: 2
```

这将将副本的数量从`4`更改为`2`。

1.  将更改提交到`master`分支并推送到 GitHub 仓库。

1.  使用以下命令监视集群：

```py
$ kubectl get pods -n example -w
```

几分钟后，您将看到前端 Pod 的数量减少。您可以通过手动同步 Flux 来加快速度。

1.  撤消更改并查看它们将如何被添加。

Flux 不会删除元素以避免问题。这意味着删除部署或服务文件不会从存储库中删除它。要这样做，您需要手动删除它。

您可以通过将副本的数量设置为零来禁用由部署控制的 Pod。

恭喜！您现在拥有一个由 GitHub 存储库控制的集群。

让我们看看如何在生产环境中有效地使用这种方法。

# 在生产中工作

GitOps 主要针对生产环境，这些环境比本章中使用的示例本地集群更大更复杂。在本节中，我们将描述如何利用 Git 的优势来提高部署和更改的清晰度，以及如何确保我们在源代码控制下结构化不同文件以避免混乱。

# 创建结构

对于大型部署来说，结构化 YAML 文件至关重要。从技术上讲，您可以将所有内容合并到一个文件中，但当它增长时，这并不是处理它的最佳方式。Kubernetes 允许极大的灵活性，因此请尝试找到适合您的结构。

一个简单的方法是按命名空间和微服务创建子目录。这是我们在本示例中的结构方式。这种结构将相关元素放在一起，并为任何涉及微服务的人提供了清晰的路径。如果部署仅影响一个微服务（正如我们在第一章中讨论的那样，*进行移动-设计、计划和执行*，在*并行部署和开发速度*部分），这将使更改保持在同一个子目录中。

但不要感到受限于这种结构。如果对您有意义，您可以尝试一些不同的东西；例如，按元素进行划分，即将所有部署放在一个目录下，所有服务放在另一个目录下，依此类推。不要害怕尝试和移动元素，寻找项目的最佳结构。

所有这些文件都在 GitHub 中受源代码控制，这使我们能够利用它们的功能。

# 使用 GitHub 功能

考虑到任何对主分支的合并都会触发集群的变化，这在上线之前应该进行审查。

您可以通过要求需要批准的拉取请求来进行。批准可以来自专门跟踪集群的 Ops 团队，也可以来自微服务的所有者；例如，团队领导或经理。

您可以在 GitHub 中本地强制执行代码所有者。这意味着特定文件或目录的更改需要某个用户或团队批准。查看 GitHub 文档以获取更多信息（[`help.github.com/en/articles/about-code-owners`](https://help.github.com/en/articles/about-code-owners)）。

单个 GitHub 存储库也可以跟踪多个环境，例如，用于运行测试的暂存环境和向客户提供的生产环境。您可以通过分支或子目录来划分它们。

但 GitHub 功能并不是唯一可用的，常规的 Git 标签非常灵活，可以让我们定义要部署的特定容器。

# 使用标签

在本例中，我们使用了图像的`latest`标签。这使用了最近构建的容器，每次构建图像时都可能会发生变化。对于生产环境，我们应该使用与不可变容器相关联的特定标签，正如我们在第三章中讨论的那样，在*使用远程注册表*部分，以及在第四章中的*创建流水线和工作流程*部分中讨论的那样。

这意味着替换以下行：

```py
spec:
  containers:
  - name: frontend-service
    image: thoughts_frontend:latest
```

我们用以下行替换它们：

```py
spec:
  containers:
  - name: frontend-service
    image: <registry>/thoughts_frontend:v1.5
```

这就是能够以受控方式更新图像的优势所在。您将使用流水线（如第四章中所述的*创建流水线和工作流程*）构建和推送带标记的图像到远程注册表，然后您可以控制在集群中部署哪个特定版本。

在某些情况下，可能需要停止同步。Flux 使用工作负载的概念，这些工作负载是可更新的元素，与部署的方式相同。

你可以停止它们的自动更新或控制它们的更新方式。有关更多信息，请参阅文档：[`github.com/fluxcd/flux/blob/master/docs/using/fluxctl.md#workloads`](https://github.com/fluxcd/flux/blob/master/docs/using/fluxctl.md#workloads)。

将此版本置于 Git 控制之下，使开发人员能够轻松地恢复到以前的版本。

为了遵循持续集成原则，尝试进行小的更改并快速应用。Git 将帮助您撤消不良更改，但小的增量更改易于测试，并减少了破坏系统的风险。

大多数操作将是简单的更改，要么更改要部署的图像的版本，要么调整参数，例如副本的数量或环境变量。

# 总结

我们从回顾最常见的不同类型的配置管理策略开始本章，并讨论了它们在项目增长时的应用方式。我们讨论了 DevOps 方法如何使团队承担起部署的责任，并有助于填补开发和运维之间的传统差距。

我们看到了最新的 GitOps 方法在 Kubernetes 集群中运行得非常好，因为配置被紧密描述为一组文件。我们讨论了使用 Git 跟踪配置的优势。

我们介绍了 Flux，这是一个部署在集群内并从 Git 存储库分支中拉取更改的工具。我们提供了一个示例配置，在本地 Kubernetes 集群中部署了它，并配置了 GitHub 以便与其一起工作。这样一来，GitHub 中对 Git 分支的任何推送都会在本地集群中反映出来。

我们在本章结束时介绍了一些在生产环境中工作的策略。我们研究了确保 Kubernetes YAML 文件结构正确，利用 GitHub 功能的方法，并学习了如何发布和回滚带标记的图像。

在下一章中，我们将描述集群的完整开发周期的过程，从引入新功能到在生产环境中部署。我们将描述在实时系统中工作时的一些有用策略，以确保部署的代码运行顺畅且质量高。

# 问题

1.  使用脚本将新代码推送到服务器和使用 Puppet 等配置管理工具有何区别？

1.  DevOps 的核心理念是什么？

1.  使用 GitOps 的优势是什么？

1.  GitOps 只能在 Kubernetes 集群中使用吗？

1.  Flux 部署位于何处？

1.  为了允许 Flux 访问 GitHub，您需要在 GitHub 中配置什么？

1.  在生产环境中工作时，GitHub 提供了哪些功能可以帮助确保对部署的控制？

# 进一步阅读

您可以在以下书籍中了解更多关于 DevOps 实践和理念：*实用 DevOps-第二版* ([`www.packtpub.com/virtualization-and-cloud/practical-devops-second-edition`](https://www.packtpub.com/virtualization-and-cloud/practical-devops-second-edition))，以及*DevOps 悖论* ([`www.packtpub.com/web-development/devops-paradox`](https://www.packtpub.com/web-development/devops-paradox))。


# 第九章：管理工作流程

在本章中，我们将把前几章描述的不同流程汇总到一般工作流程中，以便对单个微服务进行更改。我们将从获取新功能请求的过程转移到本地开发、审查、在演示环境中测试，并批准更改并将其发布到实时集群。

这与我们在第四章中介绍的流水线概念有关，*创建流水线和工作流*。然而，在本章中，我们将讨论任务的过程。流水线和构建结构旨在确保任何提议的更改都符合质量标准。在本章中，我们将重点关注技术的团队合作方面，以及如何在跟踪不同更改的同时实现顺畅的互动。

在本章中，我们将涵盖以下主题：

+   理解功能的生命周期

+   审查和批准新功能

+   设置多个环境

+   扩展工作流程并使其正常运行

本章结束时，我们将清楚地了解设置新功能所涉及的不同步骤，以及如何使用多个环境来测试和确保发布成功。

# 理解功能的生命周期

遵循敏捷原则，任何团队的主要目标是能够快速实现新功能，而不会影响系统的质量或稳定性。变化的第一个元素是**功能请求**。

功能请求是以非技术术语描述系统变更的请求。功能请求通常由非工程师（产品所有者、经理和 CEO）生成，他们希望出于业务原因改进系统，比如打造更好的产品或增加收入。

功能请求可能很简单，比如*更新公司主页的标志*，也可能很大且复杂，比如*添加对新的 5G 网络的支持*。功能请求可能包括错误报告。虽然通常不会，但在本章中会有。

复杂的功能请求可能需要分解为更小的独立功能请求，以便我们可以逐步迭代。

我们的重点是微服务方法和实践，而不是敏捷实践。这些实践涉及如何将功能请求结构化为任务和估算，但并不特定于基础技术。

请查看本章末尾的*进一步阅读*部分，以了解更多关于敏捷实践和方法论的信息。

在单体架构中，所有元素都在同一个代码库下。因此，无论特定功能请求有多复杂，只会影响一个系统。在单体架构中只有一个系统。然而，一旦我们迁移到微服务，情况就不同了。

在微服务架构中，我们需要分析任何新功能请求涉及的微服务。如果我们正确设计了微服务，大多数请求只会影响单个微服务。然而，最终，一些功能请求将太大，无法完全适应单个微服务，需要分成两个或更多步骤，每个步骤都改变不同的微服务。

例如，如果我们有一个新的功能请求，允许我们在一条*想法*的文本中提及用户（类似于 Twitter 上的提及方式），那么这个提及将需要存储在 Thoughts 后端，并在前端显示。这个功能影响了两个微服务：前端和 Thoughts 后端。

在本节中，我们引用了前几章介绍的概念，并从全局角度将它们结合起来。

在下一小节中，我们将看看影响多个微服务的特性。

# 影响多个微服务的特性

对于多个微服务的特性请求，您需要将特性分成几个技术特性，每个特性影响一个单独的微服务。

每个技术特性应涵盖与其影响的微服务相关的方面。如果每个微服务都有明确的目的和目标，那么特性将被完成和概括，以便以后的请求可以使用。

成功的微服务架构的基础是有松散耦合的服务。确保每个微服务的 API 本身是有意义的，这一点很重要，如果我们希望避免模糊服务之间的界限。不这样做可能意味着独立的工作和部署是不被允许的。

还应考虑请求和微服务之间的依赖关系，以便工作可以从后往前安排。这意味着准备添加额外数据或功能的新特性，但默认情况下保留旧行为。在这样做之后，可以部署使用这些额外数据的新特性。这种工作方式确保了任何给定时间的向后兼容性。

我们将在第十一章中更详细地查看影响多个微服务的特性，*处理系统中的变更、依赖和秘密*。我们还将学习如何更详细地协调工作和依赖关系。

回到我们之前的例子，要将用户的提及添加到他们的想法中，我们需要使 Thoughts Backend 能够处理对用户的可选引用。这是一个独立的任务，不会影响现有的功能。它可以被部署和测试。

然后，我们可以在前端进行相应的更改，以允许外部用户通过 HTML 界面与其进行交互。

正如我们在第一章中讨论的，*迁移-设计、计划和执行*，对于任何微服务架构来说，独立部署服务是至关重要的。这使我们能够独立测试服务，并避免任何需要复杂部署的开销，这使得我们难以调试和回滚错误。

如果不同的团队独立地在不同的微服务上工作，那么它们也将需要协调。

在下一节中，我们将学习如何在单个微服务中实施特性。

# 实施特性

一旦我们有了独立技术特性的定义，就可以实施它。

清晰地定义技术特性可能是具有挑战性的。请记住，一个特性可能需要进一步细分为更小的任务。然而，正如我们之前提到的，这里的目标不是构建我们的任务结构。

通过创建一个新的 Git 分支来开始您的任务。代码可以被更改以反映这个分支中的新特性。正如我们在第二章和第三章中所看到的，*使用 Python 创建 REST 服务*和*使用 Docker 构建、运行和测试您的服务*，可以运行单元测试来确保这项工作不会破坏构建。

正如我们在第三章中所描述的，*使用 Docker 构建、运行和测试您的服务*，在*使用不可变容器进行操作*部分，我们可以使用`pytest`参数来运行测试的子集，以加快开发速度，从而在运行测试时获得快速反馈。确保您使用它。

这个功能在整个系统中的工作方式可以通过部署本地集群来检查。这会启动其他可能受到这个分支工作影响的微服务，但它有助于确保当前的工作不会破坏影响其他微服务的现有调用。

根据流水线，推送到 Git 的任何提交都将运行所有测试。 这将及早发现问题，并确保在与主分支合并之前构建正确。

在此过程中，我们可以使用拉取请求来审查主分支和新功能之间的更改。 我们可以检查我们的 GitHub 配置，以确保代码在合并之前处于良好状态。

一旦功能准备就绪并已与主分支合并，应创建一个新标签以允许其部署。 作为配置的一部分，此标签将触发生成注册表中的图像的构建，并使用相同的标签标记图像。 标签和图像是不可变的，因此我们可以确保代码在不同环境之间不会更改。 您可以放心地前进和后退，确保代码与标签中定义的完全相同的代码。

正如我们在第八章中看到的，*使用 GitOps 原则*，可以通过遵循 GitOps 原则部署标签。 部署在 Kubernetes 配置文件中，受 Git 控制，并在需要获得批准的拉取请求中进行审查。 一旦拉取请求已与主分支合并，Flux 将自动部署，正如我们在第八章中描述的那样，在*设置 Flux 控制 Kubernetes 集群*部分。 此时，功能在集群中可用。

让我们回顾一下这个生命周期，从技术请求的描述到部署到集群为止：

这是我们在第四章中介绍的流程的更完整版本。

1.  技术请求已准备好实施到单个微服务中。

1.  创建一个新的功能分支。

1.  在此分支中更改微服务的代码，直到功能准备就绪。

1.  创建了一个拉取请求，用于将功能分支合并到主分支中。 正如我们在第四章中描述的那样，在*理解持续集成实践*部分，运行 CI 流程以确保其质量。

1.  拉取请求已经审查，批准并合并到主分支。

1.  创建了一个新标签。

1.  在 GitOps 存储库中创建一个部署分支，将微服务的版本更改为新标签。

1.  创建用于合并此部署分支的拉取请求。 然后进行审查和合并。

1.  一旦代码已合并，集群将自动发布微服务的新版本。

1.  最后，新功能在集群中可用！

这是生命周期的简化版本； 实际上，可能更复杂。 在本章后面，我们将看到需要将生命周期部署到多个集群的情况。

在接下来的部分中，我们将看一些关于审查和批准拉取请求的建议。

# 审查和批准新功能

根据我们在第四章中描述的流水线模型，候选代码通过一系列阶段，如果出现问题就停止。

正如我们之前提到的，使用 GitHub 拉取请求进行审查适用于我们希望向微服务代码引入新功能，以及希望通过 GitOps 实践将这些更改部署到集群中。

在这两种情况下，我们可以通过自动化测试和流程自动检查。 但是，还有最后一步需要手动干预：知识转移和额外的眼睛。 一旦审阅者认为新功能已准备就绪，他们可以批准它。

工具是一样的，尽管审查过程有些不同。这是因为目标不同。对于功能代码，审查更加开放，直到获得批准并合并到主分支。另一方面，审查和批准发布通常更加直接和快速。

让我们从学习如何审查功能代码开始。

# 审查功能代码

代码审查可以在开发功能并打开合并请求时启动。正如我们已经看到的，在 GitHub 中，代码可以在**拉取请求**阶段进行审查。

代码审查基本上是关于代码和新功能的讨论；也就是说，在将代码引入主分支之前，我们会对代码进行检查。这为我们提供了在开发过程中改进功能的机会，以及在其成为系统组件之前进行改进。

在这里，团队的成员可以阅读尚未合并的代码，并给作者一些反馈。这可能来回进行，直到审阅者认为代码已经准备好合并并批准它。实质上，除了功能的作者之外，其他人需要同意新代码符合所需的标准。

代码库随着时间的推移而增长，它们的组件可以相互帮助。将代码合并到主分支表示您完全接受新代码将作为代码库的一部分由团队维护。

代码可能需要得到一个或多个人的批准，或者特定人员的批准。

在 GitHub 中，你可以启用代码所有者。这些是负责批准存储库或存储库部分的工程师。查看 GitHub 文档以获取更多信息：[`help.github.com/en/articles/about-code-owners`](https://help.github.com/en/articles/about-code-owners)。

代码审查是一个非常常见的过程，而在 GitHub 中使用拉取请求的流行度和便利性已经传播开来。大多数开发人员都熟悉这个过程。

实施良好的反馈文化比看起来更加困难。编写代码是一种深层次的个人体验；没有两个人会写出相同的代码。对开发人员来说，让他人批评自己的代码可能是一种困难的经历，除非有明确的规则。

以下是一些建议：

+   告诉你的审阅者他们应该寻找什么。坚持使用检查表。这有助于在团队内部培养关心共享核心价值观的文化。这也有助于初级开发人员知道要寻找什么。这可能会因团队而异，但以下是一些示例：

+   有新的测试。

+   错误条件要经过测试。

+   文档要得到适当的更新。

+   任何新的端点都要符合标准。

+   架构图已更新。

+   审查代码并不等同于编写代码。总会有差异（例如，这个变量名可以更改），但需要审查的是是否需要实施这样的更改。挑剔将会侵蚀团队成员之间的信任。

+   要审查的代码越大，就越难以完成。最好是以小的增量工作，这与持续集成的原则相符。

+   所有的代码都应该在同等的基础上进行审查。这包括高级开发人员的代码，应鼓励初级开发人员留下诚实的反馈。这有助于代码的所有权和公平性增长。

+   代码审查是一种对话。评论并不一定意味着审阅者的反馈必须在你质疑之前立即实施。它开启了关于改进代码的对话，进行澄清和反驳是完全可以的。有时，处理请求的正确方式，也就是更改代码的一部分，是留下一条评论解释为什么以这种方式进行。

+   审查有助于传播关于代码库的知识。然而，这并不是万能的。代码审查往往会陷入隧道视野，只关注诸如拼写错误和局部代码片段等小问题，而不关注更大的元素。这就是为什么以小的增量实现功能很重要的原因：以帮助周围的人消化变化。

+   留下赞赏的评论很重要。营造一个欣赏写得好的代码的文化。只强调问题会让作者对审查过程感到痛苦。

+   批评应该针对代码，而不是针对编码人员。确保您的审查是文明的。在这一步中，我们要确保代码质量高；作为审查人，您不希望让自己显得更优越。

对于那些不习惯代码审查的人来说，代码审查可能会带来压力。一些公司正在制定原则和想法，以减轻这一过程的痛苦。一个很好的例子可以在[`www.recurse.com/social-rules`](https://www.recurse.com/social-rules)找到。不要害怕制定并分享您自己的原则。

+   重要的是，代码可以随时获得批准，即使团队中的某人正在度假或生病。确保您授予团队多名成员批准，以便批准过程本身不成为瓶颈。

当您开始进行代码审查时，请确保团队领导牢记这些考虑，并强调为什么所有代码都要经过审查。

强调代码审查并不是技术解决方案，而是与人相关的解决方案。因此，它们可能会受到与人相关的问题的影响，比如自负、对立的讨论或无效的辩论。

微服务架构适用于有多人共同开发的大型系统。团队合作至关重要。其中一部分是确保代码不属于单个人，而是整个团队的。代码审查是实现这一目标的好工具，但一定要积极寻找健康的审查。

随着时间的推移，将形成共识，并且会一致地开发大量代码。在一个健康的团队中，花在审查上的时间应该减少。

随着时间的推移，团队将定期进行代码审查，但在开始阶段建立这些基础可能会很复杂。确保您留出时间来介绍它们。正如我们之前提到的，一旦功能准备就绪，我们需要继续批准它。批准新功能的代码并将其合并到主分支是功能审查的最后阶段，但仍然需要发布。发布受代码控制，也需要进行审查。

# 批准发布

使用 GitOps 原则使我们能够启用相同的审查和批准方法，以便我们可以对 Kubernetes 基础架构进行更改。正如我们之前提到的，基础架构是由 Kubernetes 中的 YAML 文件定义的，这使我们能够控制这些更改。

对 Kubernetes 集群进行的任何更改都可以经过拉取请求和审查方法。这使得批准将发布到集群变得简单。

这有助于最小化问题，因为团队的成员参与了更改，并且他们对基础架构的了解更加深入。这与 DevOps 原则很好地契合，允许团队掌控自己的部署和基础架构。

然而，GitOps 中的基础架构更改往往比常规代码审查更容易审查。一般来说，它们是以非常小的增量进行的，大多数更改都是如此直截了当，几乎不会引发辩论的可能性很小。

一般原则是，尽量使基础架构更改尽可能小。基础架构更改存在风险，因为错误可能导致其中的重要部分崩溃。更改越小，风险越小，诊断任何问题也就越容易。

我们之前提到的关于代码审查的所有建议也都有一定作用。其中最重要的一个是包括一些参考基础设施关键部分的指南。

基础设施的某些部分可能受到 GitHub 代码所有者的保护。这使得某些工程师必须批准对基础设施关键部分的更改。查看更多信息，请参阅文档：[`help.github.com/en/articles/about-code-owners`](https://help.github.com/en/articles/about-code-owners)。

由于基础设施被定义为存储在 GitHub 中的代码，这也使得复制基础设施变得容易，从而极大地简化了生成多个环境的过程。

# 设置多个环境

在 Kubernetes 下创建、复制和删除命名空间的便利大大减轻了以前保持多个环境副本以复制基础设施的负担。您可以利用这一点。

根据我们之前提到的 GitOps 原则，我们可以定义新的命名空间来生成新的集群。我们可以使用另一个分支（例如，使用`master`分支用于生产集群，`demo`用于演示集群），或者复制包含集群定义的文件并更改命名空间。

可以为不同的目的使用不同的物理 Kubernetes 集群。最好将生产集群保持独立，不与任何其他环境共享，以减少风险。然而，其他每个环境可以存在于同一个集群中，这不会影响外部客户。

一些功能请求足以证明开发团队将确切知道该做什么，比如在处理错误报告时。然而，其他可能需要更多的测试和沟通，以确保它们在开发过程中满足要求。当我们检查新功能是否确实对预期的外部用户有用时，或者可能是更具探索性的功能时，就可能出现这种情况。在这种情况下，我们需要联系外部方，也就是功能的最终批准者：*利益相关者*。

利益相关者是项目管理中的一个术语，指定了第三方，也就是产品的最终用户或受其影响的用户。在这里，我们使用这个术语来指定对功能感兴趣但不属于团队外部的人，因此他们无法从内部定义功能要求。利益相关者可以是例如经理、客户、公司的 CEO 或内部工具的用户。

任何曾经不得不处理模糊定义的利益相关者请求的开发人员，比如*允许按名称搜索*，都不得不对其进行微调：*不是按名字，而是按姓氏*。

确保您为这类任务定义适当的结束。如果允许其无限制地运行，利益相关者的反馈可能是无穷无尽的。事先定义其中包含和不包含的内容，以及任何截止日期。

为了运行测试并确保正在开发的功能朝着正确的方向发展，您可以创建一个或多个演示环境，在这些环境中，您将部署尚未合并到主分支中的工作。这将帮助我们与利益相关者分享这项工作，以便他们在功能完成之前向我们提供反馈，而无需我们在生产环境中发布它。

正如我们在前几章中看到的，在 Kubernetes 中生成新环境很容易。我们需要创建一个新的命名空间，然后复制集群的生产定义，同时更改命名空间。这将创建一个环境的副本。

更改正在开发的微服务的特定版本将允许我们创建其工作版本。新版本可以像往常一样部署在这个演示环境中。

这是一个简化版本。您可能需要在生产环境和演示环境之间进行更改，例如副本数量和数据库设置。在这种情况下，可以使用*模板环境*作为参考，以便随时可以复制。

其他环境，如暂存，可以以类似的方式创建，旨在创建确保已部署到生产环境的代码将按预期工作的测试。这些测试可以是自动的，但如果我们想要检查用户体验是否合适，也可以是手动的。

暂存环境是一个尽可能忠实于生产环境的副本设置，这意味着我们可以运行测试，以确保在生产环境中部署将正常工作。暂存通常帮助我们验证部署过程是否正确，以及任何最终测试。

暂存环境通常非常昂贵。毕竟，它们是生产环境的副本。使用 Kubernetes，您可以轻松复制生产环境并减少所需的物理基础设施。甚至可以在不使用时启动和停止它以减少成本。

您可以使用多个环境以类似的方式创建部署的级联结构。这意味着需要将标签部署到暂存环境并获得批准，然后才能部署到生产环境。

现在让我们从开发人员的角度来看如何处理这个结构。

# 扩展工作流并使其正常工作

实施这种工作方式的一些挑战包括创建提供充分反馈循环的文化，并在快速审查新代码时仔细检查它。等待审查是一种阻塞状态，会阻止开发人员实施正在审查的功能。

虽然这段等待时间可以用于其他目的，但无法取得进展会迅速降低生产率。开发人员要么会同时保留几个功能，这在上下文切换的角度来看是非常有问题的，要么他们需要等待并无所事事，直到审查完成。

上下文切换可能是生产力的最严重杀手。保持团队的生产力高的关键之一是能够开始并完成任务。如果任务足够小，它将很快完成，因此在项目之间切换更容易。然而，同时处理两个或更多任务是非常不好的做法。

如果这经常发生，请尝试将任务分解为较小的块。

为了能够彻底审查代码并减少阻塞时间，有一些要点需要牢记。

# 审查和批准由整个团队完成

必须随时有足够的审阅者可用。如果只有开发人员有经验，审查可能最终只由团队中最资深的人员完成，例如团队负责人。尽管这个人原则上可能是更好的审阅者，但从长远来看，这种结构将损害团队，因为审阅者将无法做其他事情。如果审阅者因病或度假等原因不可用，开发和发布阶段的进展也将受阻。

相反，使整个团队都能够审查其同行的代码。即使资深贡献者在教导团队其他成员如何审查方面扮演更积极的角色，但一段时间后，大多数审查不应需要他们的帮助。

尽管最初实施这个流程需要积极的指导，但这通常由团队的资深成员来领导。审查代码是一种可培训的能力，其目标是在一段时间后，每个人都能够进行审查并获准批准拉取请求。

部署拉取请求也遵循相同的流程。最终，团队中的每个人，或者至少是相当数量的成员，都应该能够部署一个发布。不过，最初的主要审阅者可能会是不同的人。

最适合审查发布的候选人可能是对 Kubernetes 基础设施配置非常了解，但对微服务代码不是专家。

# 理解并不是每个批准都是一样的

记住，一个功能的不同阶段并不同样关键。代码审查的早期过程是为了确保代码可读，并且保持质量标准。在早期阶段，代码将有相对较多的注释，并且会有更多需要讨论的地方，因为需要调整的元素更多。

审查的一个重要部分是创建*足够易懂*的代码，以便团队的其他成员能够理解。尽管有些人声称代码审查可以让每个人都意识到团队其他成员正在实施的更改，但根据我的经验，审阅者并不那么了解特定功能。

然而，一个良好的审查将确保没有令人费解的东西被引入到代码库中，并且核心元素得到尊重（例如引入测试，保持文档更新，保持代码可读）。正如我们在本章前面建议的那样，尝试创建一个明确的检查事项列表。这将有助于使审查和代码更加一致。

新功能的部署阶段只需要检查微服务版本的更改以及基础设施的其余部分是否完好。这些通常会非常小；大多数情况下会再次检查是否有拼写错误，以及要更改的微服务是否正确。

# 定义发布的明确路径

拥有一个简单明了的流程可以帮助所有参与者清楚地了解一个功能是如何从开发到发布到生产环境的。例如，基于我们讨论过的想法，我们可能会得到一个类似于以下图表所示的部署路径：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-dkr-msvc-py/img/22480f67-8ebb-41fe-8395-f832aa7b5909.png)

对于这些步骤中的每一步，我们需要验证该步骤是否正确。正如我们在第四章中所看到的，*创建流水线和工作流*，自动化测试确保合并到主分支的任何内容都不会破坏现有的构建。这涵盖了前面的图表直到**创建标签**步骤。

同样，可能有一种方法可以在部署后验证部署是否成功。以下是关于此的一些想法：

+   手动测试，以检查部署的微服务是否按预期工作

+   自动化测试，比如第四章中描述的那些，*创建流水线和工作流*

+   检查要部署的图像是否已经使用 Kubernetes 工具或版本 API 正确部署

一旦一个部署阶段成功完成，就可以开始下一个阶段。

在非生产环境中进行部署可以最大程度地减少破坏生产环境的风险，因为这将确保部署过程是正确的。流程需要足够快，以便允许快速部署，从而使它们尽可能小。

从合并到主分支到新版本发布到生产环境，整个过程应该不超过几个小时，但最好是更短。

如果需要更多时间，那么这个流程可能太繁重了。

小而频繁的部署将最大程度地减少破坏生产环境的风险。在一些特殊情况下，常规流程可能会很慢，需要使用紧急程序。

# 紧急发布

让我们假设在生产中有一个关键错误，需要尽快解决。对于这些特殊情况，事先定义一个紧急流程是可以的。

这种紧急流程可能涉及加快审查甚至完全跳过审查。这可能包括跳过中间发布（例如在事先不部署到演示环境）。确保明确定义何时需要使用此流程，并确保仅在紧急情况下使用。

如果您的常规部署流程足够快，那么就不需要紧急流程。这是尝试提高部署时间的一个很好的理由。

回滚是一个很好的例子。要撤销微服务的部署，因为上一个版本引入了关键错误，只需在生产环境中回滚并返回到上一个版本，而不影响其他任何东西，这是一个合理的流程。

请注意，这里我们减少了进行快速更改的风险，并确保已经回滚的版本已经在之前部署过。这是紧急程序可能起作用并减少风险的一个很好的例子。

在发现特殊情况时要运用常识，并与团队事先讨论如何处理。我们将在第十二章 *跨团队协作和沟通* 中讨论回顾。

# 频繁发布和添加功能标志

虽然回滚是可能的，正如我们刚才看到的，但一般共识应该是每次新部署都是向前推进的。新版本的代码包含了上一个版本的代码，再加上一些小的更改。按照 Git 的操作方式，我们在一个分支上工作（主分支），并将其推进。

这意味着要避免几个长期存在的活跃分支。这种模式被称为*基于主干的开发*，是持续集成的推荐工作方式。在基于主干的开发中，功能分支是短暂存在的，并且始终与主分支（或主干）合并，通常在 Git 中称为`master`。

基于主干的开发避免了当我们有长期存在且与主分支分歧的分支时出现的问题，从而使多个组件的集成变得复杂。持续集成的基础是始终具有可以以小的增量发布的代码。这种模式以“主干”作为发布的参考。

在下图中，我们可以看到**功能 A**是如何合并到**主分支**中的，以及**功能 B**仍在进行中。任何发布都将来自**主分支**：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-dkr-msvc-py/img/2dab7dbb-586a-4dea-a959-14ba5beea981.png)

如果**功能 A**引入了一个错误，一个新的 bug 修复分支将从**主分支**分支出来，并将被合并回去。请注意结构是继续向前推进的。

为了使这个系统工作，功能分支需要短暂存在 - 通常只有几天。这样做可以使合并变得容易，并允许进行小的增量更改，这是持续集成的关键。

# 使用功能标志

有时，有一些功能，由设计需要一次性进行大规模/重大更改，比如新的 UI 界面。持续集成倡导者提倡的短小迭代周期，逐渐添加小功能的方式在这些频繁发布的情况下行不通。新界面需要一次性包含所有元素，否则会显得奇怪。

当您希望以小的增量方式继续工作，并同时延迟功能的激活时，可以使用功能标志。

功能标志是启用或禁用特定功能的配置元素。这使您可以通过配置更改改变微服务的行为，起到开关的作用。

在 Kubernetes 中，我们使用`deployment.yaml`文件来描述环境变量，以及 ConfigMaps。我们将在第十一章《处理系统中的变更、依赖关系和机密信息》中讨论 ConfigMaps。

配置与每个单独的环境相关联。这使我们能够在特定环境中展示一个功能，而在另一个环境中不展示，同时代码库保持不变。

例如，可以慢慢开发并在功能标志下保护一个新接口。一些环境，比如演示环境，仍然可以处于活动状态，以便收集内部反馈，但这不会显示在生产环境中。

一旦新接口准备就绪，就可以进行小的更改；例如，我们可以更改配置参数以启用它。这在外部看起来可能是一个很大的变化，但如果我们切换回参数，它可以很容易地恢复。

功能标志在处理外部可访问服务时非常有用。内部服务可以添加更多功能而不会出现任何问题，因为它们只会被系统中的其他微服务调用。

内部微服务通常可以添加新功能。在这里，会尊重向后兼容性。外部可访问的功能有时需要我们出于各种原因（包括接口更改或产品弃用）用另一个功能替换一个功能。

一个相关的方法是将功能推送给一部分用户。这可以是预定义的用户集，例如已经加入测试计划以获得早期功能访问权限的用户，或者是一个随机样本，以便他们可以在全球发布之前及早发现问题。

一些大公司也使用区域访问，其中一些功能首先在特定国家/地区启用。

一旦功能标志被激活，任何已弃用的功能都可以被移除和清理，这样就不会有不会被使用的旧代码了。

# 处理数据库迁移

数据库迁移是对存储在特定环境中的持久数据进行的更改（通常是在一个或多个数据库中）。大多数情况下，这意味着改变数据库模式，但也有其他情况。

生产环境中的数据是运行系统中最重要的资产。对数据库迁移需要特别小心。

在某些情况下，迁移可能会锁定表一段时间，从而使系统无法使用。确保您适当地测试您的迁移，以避免或至少为这些情况做好准备。

尽管数据库迁移在技术上可能是可逆的，但从开发时间的角度来看，这样做是非常昂贵的。例如，添加和删除列可能很简单，但一旦列投入使用，它将包含不应删除的数据。

为了能够在数据迁移事件中无缝工作，您需要将其与将调用它的代码分离，并按照以下步骤进行操作：

1.  设计数据库迁移时，要以不干扰当前代码为目标。例如，向数据库添加表或列是安全的，因为旧代码会忽略它。

1.  执行数据库迁移。这样就可以在现有代码继续运行而不中断的情况下进行所需的更改。

1.  现在，代码可以部署。一旦部署完成，它将开始使用新数据库定义的优势。如果出现问题，代码可以回滚到先前的版本。

这意味着我们需要创建两个部署：

+   一个用于迁移

+   另一个用于使用此迁移的代码

迁移部署可能类似于代码部署。也许有一个运行迁移的微服务，或者可能是一个执行所有工作的脚本。大多数框架都会有一种迁移的方法，以确保迁移不会被应用两次。

例如，对于 SQLAlchemy，有一个名为 Alembic 的工具（[`alembic.sqlalchemy.org/en/latest/`](https://alembic.sqlalchemy.org/en/latest/)），我们可以使用它来生成和运行迁移。

然而，还有一种替代操作：尝试将迁移应用于将使用它们的微服务。在处理生产环境时，这是一个坏主意，因为这将在所有情况下减慢启动时间，而不管是否正在进行迁移。此外，它不会检查代码是否可以安全回滚，并且是否与数据库的先前版本兼容。

与两个独立的部署一起工作显然比自由更改数据库更加受限，但它确保每一步都是稳固的，服务不会中断。这更加故意。例如，要重命名列，我们将按照以下步骤进行：

1.  首先，我们将部署一个创建具有新列名称的新列的迁移，从而复制旧列中的数据。代码从旧列读取和写入。

1.  然后，我们将部署从旧列读取并向两者写入的新代码。在发布过程中，从旧代码到旧列的任何写入都将被正确读取。

1.  之后，我们将创建另一个迁移，将数据从旧迁移复制到新迁移。这样可以确保任何瞬态复制都被正确应用。此时，任何新数据仍然会同时写入两列。

1.  然后，我们将部署代码，从新列读取和写入，忽略旧列。

1.  最后，我们将实施一个迁移来删除旧列。此时，旧列不包含相关数据，可以安全地删除。这不会影响代码。

这是一个故意的长流程示例，但在大多数情况下，不需要这样的长流程。然而，在这些步骤中的任何时候都没有任何不一致。如果某个阶段出现问题，我们可以回滚到上一个阶段 - 直到修复为止，它仍然可以工作。

主要目标是避免数据库与当前部署的代码不兼容的瞬态状态。

# 总结

在本章中，我们讨论了团队的流程，从开始一个新功能到将其部署到生产环境中。

我们首先讨论了在微服务架构中工作时功能请求的关键点。我们介绍了影响多个微服务的请求，并学习了如何构建工作，以便服务不会中断。

我们讨论了构成良好审查和批准流程的要素，以及 GitHub 拉取请求如何帮助我们做到这一点。使用 GitOps 实践来控制基础设施使得部署可以轻松地进行审查。

然后，我们讨论了如何使用 Kubernetes 和 GitOps 帮助我们创建多个环境，以及在处理演示和分段环境时如何利用它们的优势，以测试部署并在进入生产之前在受控环境中展示功能。

之后，我们讨论了如何使团队能够全面了解整个生命周期，从功能请求到部署，并能够快速跟踪整个路径。我们学会了如何澄清这些步骤，以及如何使团队负责审查和批准自己的代码，这使开发人员可以完全拥有开发周期。

我们还讨论了在处理数据库迁移时可能出现的问题，并解释了如何进行这种特殊类型的部署，这不容易回滚。

在下一章中，我们将讨论实时系统以及如何启用诸如指标和日志之类的元素，以便我们可以检测在生产环境中发生的问题和错误，并获得足够的信息尽快主动地进行修复。

# 问题

1.  当接收到一个新的业务功能时，在微服务架构下，我们需要进行怎样的分析？

1.  如果一个功能需要修改两个或更多微服务，我们如何决定首先修改哪一个？

1.  Kubernetes 如何帮助我们建立多个环境？

1.  代码审查是如何工作的？

1.  代码审查的主要瓶颈是什么？

1.  根据 GitOps 原则，部署审查与代码审查有何不同？

1.  为什么一旦一个功能准备合并到主分支时，有一个清晰的部署路径是很重要的？

1.  为什么数据库迁移与常规代码部署不同？

# 进一步阅读

想要了解更多关于敏捷实践并将其引入团队的信息，请查阅以下书籍：

+   《The Agile Developer's Handbook》

+   《Agile Technical Practices Distilled》

如果你的组织在使用 JIRA，阅读《Hands-On Agile Software Development with JIRA》可以帮助你更好地利用这个工具来进行敏捷实践。


# 第四部分：生产就绪系统-使其在实际环境中运行

该书的最后一部分关注一些使实际生活中的系统长期运行的要素，从系统的可观察性，这对于快速检测和解决问题至关重要，到处理影响整个系统的配置，并包括确保不同团队协作和协调开发系统的技术。

本部分的第一章介绍了如何在实时集群中发现操作以检测使用情况和相关问题。本章介绍了可观察性的概念以及支持它的两个主要工具：日志和指标。它涵盖了如何在 Kubernetes 集群中正确地包含它们。

本部分的第二章涉及跨不同微服务共享的配置以及如何处理服务之间的依赖关系。它还展示了如何在现实生活中处理机密信息：包含敏感信息的配置参数，如安全密钥和证书。

本部分的第三章描述了在微服务架构中工作时团队间沟通的常见问题以及如何处理这些问题，包括如何在整个组织中创建共享愿景，团队划分如何影响不同的 API，以及如何跨团队发布新功能。

本部分包括以下章节：

+   [第十章]，*监控日志和指标*

+   [第十一章]，*处理变化、依赖和系统中的机密信息*

+   [第十二章]，*团队间的协作与沟通*


# 第十章：监控日志和指标

在实际运营中，快速检测和调试问题的能力至关重要。在本章中，我们将讨论我们可以用来发现在处理大量请求的生产集群中发生了什么的两个最重要的工具。第一个工具是日志，它帮助我们了解单个请求中发生了什么，而另一个工具是指标，它对系统的聚合性能进行分类。

本章将涵盖以下主题：

+   实时系统的可观测性

+   设置日志

+   通过日志检测问题

+   设置指标

+   积极主动

在本章结束时，您将了解如何添加日志以便检测问题，以及如何添加和绘制指标，并了解它们之间的区别。

# 技术要求

我们将使用示例系统，并对其进行调整，包括集中式日志记录和指标。本章的代码可以在本书的 GitHub 存储库中找到：[`github.com/PacktPublishing/Hands-On-Docker-for-Microservices-with-Python/tree/master/Chapter10`](https://github.com/PacktPublishing/Hands-On-Docker-for-Microservices-with-Python/tree/master/Chapter10)。

要安装集群，您需要构建每个单独的微服务：

```py
$ cd Chapter10/microservices/
$ cd frontend
$ docker-compose build
...
$ cd thoughts_backend
$ docker-compose build
...
$ cd users_backend
$ docker-compose build
...
```

本章中的微服务与之前介绍的相同，但它们增加了额外的日志和指标配置。

现在，我们需要创建示例命名空间，并使用`Chapter10/kubernetes`子目录中的`find`配置启动 Kubernetes 集群：

```py
$ cd Chapter10/kubernetes
$ kubectl create namespace example
$ kubectl apply --recursive -f .
...
```

要能够访问不同的服务，您需要更新您的`/etc/hosts`文件，以便包含以下代码行：

```py
127.0.0.1 thoughts.example.local
127.0.0.1 users.example.local
127.0.0.1 frontend.example.local
127.0.0.1 syslog.example.local
127.0.0.1 prometheus.example.local
127.0.0.1 grafana.example.local
```

有了这些，您将能够访问本章的日志和指标。

# 实时系统的可观测性

可观测性是了解实时系统发生情况的能力。我们可能会遇到低可观测性系统，我们无法了解其中发生了什么，或者高可观测性系统，我们可以通过工具从外部推断事件和内部状态。

可观测性是系统本身的属性。通常，监控是获取有关系统当前或过去状态的信息的行为。这有点命名上的争议，但你要监控系统以收集其中可观测的部分。

在大多数情况下，监控是很容易的。有很多出色的工具可以帮助我们捕获和分析信息，并以各种方式呈现。但是，系统需要暴露相关信息，以便可以收集。

暴露正确数量的信息是困难的。太多信息会产生很多噪音，会掩盖相关信号。信息太少将不足以检测问题。在本章中，我们将探讨不同的策略来解决这个问题，但每个系统都必须自行探索和发现。期望在自己的系统中进行实验和更改！

分布式系统，例如遵循微服务架构的系统，也会出现问题，因为系统的复杂性可能会使其内部状态难以理解。在某些情况下，行为也可能是不可预测的。这种规模的系统本质上永远不会完全健康；总会有一些小问题。您需要制定一个优先级系统，以确定哪些问题需要立即解决，哪些可以在以后解决。

微服务可观测性的主要工具是**日志**和**指标**。它们为社区所熟知，并且有许多工具大大简化了它们的使用，既可以作为可以在本地安装的软件包，也可以作为云服务，有助于数据保留和降低维护成本。

使用云服务进行监控将节省您的维护成本。我们将在*设置日志*和*设置指标*部分稍后讨论这一点。

在可观察性方面的另一种选择是诸如 Data Dog（[`www.datadoghq.com/`](https://www.datadoghq.com/)）和 New Relic（[`newrelic.com/`](https://newrelic.com/)）等服务。它们接收事件——通常是日志——并能够从中推导出指标。

集群状态的最重要细节可以通过`kubectl`进行检查，就像我们在之前的章节中看到的那样。这将包括已部署的版本、重启、拉取镜像等详细信息。

对于生产环境，部署一个基于 Web 的工具来显示这种信息可能是一个好主意。查看 Weave Scope，这是一个开源工具，可以在网页上显示数据，类似于可以使用`kubectl`获得的数据，但以更美观和更图形化的方式。您可以在这里了解更多关于这个工具的信息：[`www.weave.works/oss/scope/`](https://www.weave.works/oss/scope/)。

日志和指标有不同的目标，两者都可能很复杂。我们将在本书中看一些它们的常见用法。

# 理解日志

日志跟踪系统中发生的唯一事件。每个日志都存储一个消息，当代码的特定部分被执行时产生。日志可以是完全通用的（*调用函数 X*）或包含特定细节（*使用参数 A 调用函数 X*）。

日志的最常见格式是将它们生成为纯文本。这非常灵活，通常与与日志相关的工具一起使用文本搜索。

每个日志都包含一些关于谁产生了日志、创建时间等元数据。这通常也被编码为文本，出现在日志的开头。标准格式有助于排序和过滤。

日志还包括严重级别。这允许对消息的重要性进行分类。严重级别可以按重要性顺序为`DEBUG`、`INFO`、`WARNING`或`ERROR`。这种严重性允许我们过滤掉不重要的日志，并确定我们应该采取的行动。日志记录设施可以配置为设置阈值；较不严重的日志将被忽略。

有许多严重级别，如果您愿意，可以定义自定义中间级别。然而，除非在非常特定的情况下，否则这并不是非常有用。在本章后面的*通过日志检测问题*部分，我们将描述如何针对每个级别设置策略；太多级别会增加混乱。

在 Web 服务环境中，大多数日志将作为对 Web 请求的响应的一部分生成。这意味着请求将到达系统，被处理，并返回一个值。沿途将生成多个日志。请记住，在负载下的系统中，多个请求将同时发生，因此多个请求的日志也将同时生成。例如，注意第二个日志来自不同的 IP：

```py
Aug 15 00:15:15.100 10.1.0.90 INFO app: REQUEST GET /endpoint
Aug 15 00:15:15.153 10.1.0.92 INFO api: REQUEST GET /api/endpoint
Aug 15 00:15:15.175 10.1.0.90 INFO app: RESPONSE TIME 4 ms
Aug 15 00:15:15.210 10.1.0.90 INFO app: RESPONSE STATUS 200
```

常见的请求 ID 可以添加到所有与单个请求相关的日志中。我们将在本章后面看到如何做到这一点。

每个单独的日志可能相对较大，并且在聚合时会占用大量磁盘空间。在负载下的系统中，日志可能会迅速膨胀。不同的日志系统允许我们调整其保留时间，这意味着我们只保留它们一段时间。在保留日志以查看过去发生的事情和使用合理的空间之间找到平衡是很重要的。

在启用任何新的日志服务时，请务必检查保留策略，无论是本地还是基于云的。您将无法分析发生在时间窗口之前的情况。仔细检查进度是否符合预期——您不希望在跟踪错误时意外超出配额。

一些工具允许我们使用原始日志生成聚合结果。它们可以计算特定日志出现的次数，并生成每分钟的平均时间或其他统计信息。但这很昂贵，因为每个日志都占用空间。要观察这种聚合行为，最好使用特定的指标系统。

# 理解指标

指标处理聚合信息。它们显示与单个事件无关的信息，而是一组事件的信息。这使我们能够以比使用日志更好的方式检查集群的一般状态。

我们将使用与网络服务相关的典型示例，主要涉及请求指标，但不要感到受限。您可以生成特定于您的服务的指标！

日志记录每个单独事件的信息，而指标将信息减少到事件发生的次数，或将其减少到可以进行平均或以某种方式聚合的值。

这使得指标比日志更轻量，并且可以根据时间绘制它们。指标呈现的信息包括每分钟的请求次数，每分钟请求的平均时间，排队请求的数量，每分钟的错误数量等。

指标的分辨率可能取决于用于聚合它们的工具。请记住，更高的分辨率将需要更多的资源。典型的分辨率是 1 分钟，这足够小以呈现详细信息，除非您的系统非常活跃，每秒接收 10 次或更多请求。

捕获和分析与性能相关的信息，如平均请求时间，使我们能够快速检测可能的瓶颈并迅速采取行动以改善系统的性能。这通常更容易处理，因为单个请求可能无法捕获足够的信息让我们看到整体情况。它还有助于我们预测未来的瓶颈。

根据所使用的工具，有许多不同类型的指标。最常见的支持包括以下内容：

+   **计数器**: 每次发生事件时都会生成一个触发器。这将被计数和聚合。这的一个例子是请求的数量和错误的数量。

+   **量规**: 一个唯一的单一数字。它可以增加或减少，但最后一个值会覆盖之前的值。这的一个例子是队列中的请求数量和可用工作者的数量。

+   **度量**: 与之相关的事件具有数字。这些数字可以被平均、求和或以某种方式聚合。与量规相比，前面的度量仍然是独立的；例如，当我们以毫秒为单位请求时间和以字节为单位请求大小时。度量也可以作为计数器工作，因为它们的数量可能很重要；例如，跟踪请求时间还计算请求的数量。

指标有两种主要工作方式：

+   每次发生事件时，事件都会被*推送*到指标收集器。

+   每个系统都维护自己的指标，然后定期从指标系统中*拉取*它们。

每种方式都有其优缺点。推送事件会产生更高的流量，因为每个事件都需要发送；这可能会导致瓶颈和延迟。拉取事件只会对信息进行抽样，并且会错过样本之间发生的确切情况，但它本质上更具可扩展性。

虽然两种方法都在使用，但趋势是向拉取系统转移。它们减少了推送系统所需的维护工作，并且更容易扩展。

我们将设置使用第二种方法的 Prometheus。第一种方法最常用的指标系统是 Graphite。

指标也可以组合以生成其他指标；例如，我们可以将返回错误的请求次数除以生成错误请求的总请求数。这样的派生指标可以帮助我们以有意义的方式呈现信息。

多个指标可以显示在仪表板上，这样我们就可以了解服务或集群的状态。通过这些图形工具，我们可以一目了然地检测系统的一般状态。我们将设置 Grafana，以显示图形信息：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-dkr-msvc-py/img/1d334374-d1df-4f9f-a7ac-07ccd296c87a.png)

与日志相比，指标占用的空间要少得多，可以捕获更长的时间窗口。甚至可以保留系统的生命周期内的指标。这与日志不同，日志永远无法存储那么长时间。

# 设置日志

我们将把系统生成的所有日志集中到一个单独的 pod 中。在本地开发中，这个 pod 将通过 Web 界面公开所有接收到的日志。

日志将通过`syslog`协议发送，这是传输日志的最标准方式。Python 中有`syslog`的原生支持，几乎任何处理日志并具有 Unix 支持的系统都有。

使用单个容器可以轻松聚合日志。在生产环境中，应该用一个容器来替换这个系统，将接收到的日志传送到 Loggly 或 Splunk 等云服务。

有多个`syslog`服务器可以接收日志并进行聚合；`syslog-ng` ([`www.syslog-ng.com/`](https://www.syslog-ng.com/))和`rsyslog` ([`www.rsyslog.com/`](https://www.rsyslog.com/))是最常见的。最简单的方法是接收日志并将其存储在文件中。让我们启动一个带有`rsyslog`服务器的容器，它将存储接收到的日志。

# 设置 rsyslog 容器

在这一部分，我们将创建自己的`rsyslog`服务器。这是一个非常简单的容器，您可以在 GitHub 上查看有关日志的`docker-compose`和`Dockerfile`的更多信息([`github.com/PacktPublishing/Hands-On-Docker-for-Microservices-with-Python/tree/master/Chapter10/kubernetes/logs`](https://github.com/PacktPublishing/Hands-On-Docker-for-Microservices-with-Python/tree/master/Chapter10/kubernetes/logs))。

我们将使用 UDP 协议设置日志。这是`syslog`的标准协议，但比用于 Web 开发的通常的 TCP 上的 HTTP 要少见。

主要区别在于 UDP 是无连接的，因此日志被发送后不会收到已传递的确认。这使得 UDP 更轻更快，但也更不可靠。如果网络出现问题，一些日志可能会无预警地消失。

这通常是一个合理的权衡，因为日志数量很大，丢失一些日志的影响并不大。`syslog`也可以通过 TCP 工作，从而增加可靠性，但也降低了系统的性能。

Dockerfile 安装了`rsyslog`并复制了其配置文件：

```py
FROM alpine:3.9

RUN apk add --update rsyslog

COPY rsyslog.conf /etc/rsyslog.d/rsyslog.conf
```

配置文件主要是在端口`5140`启动服务器，并将接收到的文件存储在`/var/log/syslog`中：

```py
# Start a UDP listen port at 5140
module(load="imudp")
input(type="imudp" port="5140")
...
# Store the received files in /var/log/syslog, and enable rotation
$outchannel log_rotation,/var/log/syslog, 5000000,/bin/rm /var/log/syslog
```

通过日志轮换，我们设置了`/var/log/syslog`文件的大小限制，以防止其无限增长。

我们可以使用通常的`docker-compose`命令构建容器：

```py
$ docker-compose build
Building rsyslog
...
Successfully built 560bf048c48a
Successfully tagged rsyslog:latest
```

这将创建一个 pod、一个服务和一个 Ingress 的组合，就像我们对其他微服务所做的那样，以收集日志并允许从浏览器进行外部访问。

# 定义 syslog pod

`syslog` pod 将包含`rsyslog`容器和另一个用于显示日志的容器。

为了显示日志，我们将使用 front rail，这是一个将日志文件流式传输到 Web 服务器的应用程序。我们需要在同一个 pod 中的两个容器之间共享文件，最简单的方法是通过卷。

我们使用部署来控制 pod。您可以在[`github.com/PacktPublishing/Hands-On-Docker-for-Microservices-with-Python/blob/master/Chapter10/kubernetes/logs/deployment.yaml`](https://github.com/PacktPublishing/Hands-On-Docker-for-Microservices-with-Python/blob/master/Chapter10/kubernetes/logs/deployment.yaml)中检查部署配置文件。让我们在以下小节中看一下它最有趣的部分。

# log-volume

`log-volume`创建了一个空目录，该目录在两个容器之间共享：

```py
  volumes:
  - emptyDir: {}
    name: log-volume
```

这允许容器在存储信息的同时进行通信。`syslog`容器将向其中写入，而前端容器将从其中读取。

# syslog 容器

`syslog`容器启动了一个`rsyslogd`进程：

```py
spec:
  containers:
  - name: syslog
    command:
      - rsyslogd
      - -n
      - -f
      - /etc/rsyslog.d/rsyslog.conf
    image: rsyslog:latest
    imagePullPolicy: Never
    ports:
      - containerPort: 5140
        protocol: UDP
    volumeMounts:
      - mountPath: /var/log
        name: log-volume
```

`rsyslogd -n -f /etc/rsyslog.d/rsyslog.conf`命令使用我们之前描述的配置文件启动服务器。`-n`参数将进程保持在前台，从而保持容器运行。

指定了 UDP 端口`5140`，这是接收日志的定义端口，并且将`log-volume`挂载到`/var/log`。文件的后面将定义`log-volume`。

# 前端容器

前端容器是从官方容器镜像启动的：

```py
  - name: frontrail
    args:
    - --ui-highlight
    - /var/log/syslog
    - -n
    - "1000"
    image: mthenw/frontail:4.6.0
    imagePullPolicy: Always
    ports:
    - containerPort: 9001
      protocol: TCP
    resources: {}
    volumeMounts:
    - mountPath: /var/log
      name: log-volume
```

我们使用`frontrail /var/log/syslog`命令启动它，指定端口`9001`（这是我们用来访问`frontrail`的端口），并挂载`/var/log`，就像我们用`syslog`容器一样，以共享日志文件。

# 允许外部访问

与其他微服务一样，我们将创建一个服务和一个 Ingress。服务将被其他微服务使用，以便它们可以发送它们的日志。Ingress 将用于访问 Web 界面，以便我们可以在日志到达时查看日志。

YAML 文件位于 GitHub 上（[`github.com/PacktPublishing/Hands-On-Docker-for-Microservices-with-Python/tree/master/Chapter10/kubernetes/logs`](https://github.com/PacktPublishing/Hands-On-Docker-for-Microservices-with-Python/tree/master/Chapter10/kubernetes/logs)），分别是`service.yaml`和`ingress.yaml`文件。

服务非常简单；唯一的特殊之处在于它有两个端口 - 一个 TCP 端口和一个 UDP 端口 - 每个端口连接到不同的容器：

```py
spec:
  ports:
  - name: fronttail
    port: 9001
    protocol: TCP
    targetPort: 9001
  - name: syslog
    port: 5140
    protocol: UDP
    targetPort: 5140
```

Ingress 只暴露了前端端口，这意味着我们可以通过浏览器访问它。请记住，DNS 需要添加到您的`/etc/host`文件中，就像本章开头所描述的那样：

```py
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: syslog-ingress
  namespace: example
spec:
  rules:
  - host: syslog.example.local
    http:
      paths:
      - backend:
          serviceName: syslog
          servicePort: 9001
        path: /
```

在浏览器中输入`http://syslog.example.local`将允许您访问前端界面：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-dkr-msvc-py/img/f6ccd237-8812-48f4-90a1-b5c971772d3a.png)

您可以使用右上角的框来过滤日志。

请记住，大多数时候，日志反映了就绪和存活探针，如前面的屏幕截图所示。您的系统中有更多的健康检查，您将会得到更多的噪音。

您可以通过配置`rsyslog.conf`文件在`syslog`级别上将其过滤掉，但要小心不要遗漏任何相关信息。

现在，我们需要看看其他微服务如何配置并将它们的日志发送到这里。

# 发送日志

我们需要在 uWSGI 中配置微服务，以便我们可以将日志转发到日志服务。我们将使用 Thoughts Backend 作为示例，即使 Frontend 和 Users Backend 也有这个配置，可以在`Chapter10/microservices`目录下找到。

打开`uwsgi.ini`配置文件（[`github.com/PacktPublishing/Hands-On-Docker-for-Microservices-with-Python/blob/master/Chapter10/microservices/thoughts_backend/docker/app/uwsgi.ini`](https://github.com/PacktPublishing/Hands-On-Docker-for-Microservices-with-Python/blob/master/Chapter10/microservices/thoughts_backend/docker/app/uwsgi.ini)）。您将看到以下行：

```py
# Log to the logger container
logger = rsyslog:syslog:5140,thoughts_backend
```

这将以`rsyslog`格式发送日志到端口`5140`的`syslog`服务。我们还添加了*facility*，这是日志来源的地方。这将为来自此服务的所有日志添加字符串，有助于排序和过滤。每个`uwsgi.ini`文件应该有自己的 facility 以帮助过滤。

在支持`syslog`协议的旧系统中，facility 需要符合预定值，例如`KERN`，`LOCAL_7`等。但在大多数现代系统中，这是一个任意的字符串，可以取任何值。

uWSGI 自动记录很有趣，但我们还需要为自定义跟踪设置自己的日志。让我们看看如何做。

# 生成应用程序日志

Flask 自动为应用程序配置了一个记录器。我们需要以以下方式添加日志，如`api_namespace.py`文件中所示（[`github.com/PacktPublishing/Hands-On-Docker-for-Microservices-with-Python/blob/master/Chapter10/microservices/thoughts_backend/ThoughtsBackend/thoughts_backend/api_namespace.py#L102`](https://github.com/PacktPublishing/Hands-On-Docker-for-Microservices-with-Python/blob/master/Chapter10/microservices/thoughts_backend/ThoughtsBackend/thoughts_backend/api_namespace.py#L102)）：

```py
from flask import current_app as app

...
if search_param:
    param = f'%{search_param}%'
    app.logger.info(f'Searching with params {param}')
    query = (query.filter(ThoughtModel.text.ilike(param)))
```

`app.logger`可以调用`.debug`、`.info`、`.warning`或`.error`来生成日志。请注意，可以通过导入`current_app`来检索`app`。

记录器遵循 Python 中的标准`logging`模块。它可以以不同的方式进行配置。查看`app.py`文件（[`github.com/PacktPublishing/Hands-On-Docker-for-Microservices-with-Python/blob/master/Chapter10/microservices/thoughts_backend/ThoughtsBackend/thoughts_backend/app.py`](https://github.com/PacktPublishing/Hands-On-Docker-for-Microservices-with-Python/blob/master/Chapter10/microservices/thoughts_backend/ThoughtsBackend/thoughts_backend/app.py)）以查看我们将在以下子部分中进行的不同配置。

# 字典配置

第一级别的日志记录通过默认的`dictConfig`变量。这个变量由 Flask 自动定义，并允许我们按照 Python 文档中定义的方式配置日志（[`docs.python.org/3.7/library/logging.config.html`](https://docs.python.org/3.7/library/logging.config.html)）。您可以在`app.py`文件中查看日志的定义：

```py
from logging.config import dictConfig

dictConfig({
    'version': 1,
    'formatters': {
        'default': {
            'format': '[%(asctime)s] %(levelname)s in 
                        %(module)s: %(message)s',
        }
    },
    'handlers': {
        'wsgi': {
            'class': 'logging.StreamHandler',
            'stream': 'ext://flask.logging.wsgi_errors_stream',
            'formatter': 'default'
        }
    },
    'root': {
        'level': 'INFO',
        'handlers': ['wsgi']
    }
})
```

`dictConfig`字典有三个主要级别：

+   `formatters`：这检查日志的格式。要定义格式，可以使用 Python 文档中提供的自动值（[`docs.python.org/3/library/logging.html#logrecord-attributes`](https://docs.python.org/3/library/logging.html#logrecord-attributes)）。这收集每个日志的信息。

+   `handlers`：这检查日志的去向。您可以将一个或多个分配给记录器。我们定义了一个名为`wsgi`的处理程序，并对其进行了配置，以便将其发送到 uWSGI。

+   `root`：这是日志的顶层，因此以前未记录的任何内容都将参考此级别。我们在这里配置`INFO`日志级别。

这将设置默认配置，以便我们不会错过任何日志。但是，我们可以创建更复杂的日志处理程序。

# 记录请求 ID

在分析大量日志时的一个问题是对其进行关联。我们需要看到哪些日志彼此相关。一种可能性是通过生成它们的 pod 来过滤日志，该 pod 存储在日志的开头（例如，`10-1-0-27.frontend-service.example.svc.cluster.local`）。这类似于生成日志的主机。然而，这个过程很繁琐，并且在某些情况下，单个容器可以同时处理两个请求。我们需要为每个请求添加一个唯一标识符，该标识符将添加到单个请求的所有日志中。

为此，我们将使用`flask-request-id-header`包（[`pypi.org/project/flask-request-id-header/`](https://pypi.org/project/flask-request-id-header/)）。这将添加一个`X-Request-ID`头（如果不存在），我们可以用它来记录每个单独的请求。

为什么我们设置一个头部而不是将随机生成的值存储在内存中以供请求使用？这是一种常见的模式，允许我们将请求 ID 注入到后端。请求 ID 允许我们在不同微服务的请求生命周期中传递相同的请求标识符。例如，我们可以在前端生成它并将其传递到 Thoughts 后端，以便我们可以跟踪具有相同来源的多个内部请求。

尽管出于简单起见，我们不会在示例中包含这一点，但是随着微服务系统的增长，这对于确定流程和来源变得至关重要。生成一个模块，以便我们可以自动传递内部调用，这是一个很好的投资。

以下图表显示了**前端**和两个服务之间的流程。请注意，**前端**服务在到达时未设置`X-Request-ID`头，并且需要转发到任何调用：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-dkr-msvc-py/img/158370df-bab7-416c-ab69-63d258408159.png)

我们还需要将日志直接发送到`syslog`服务，以便我们可以创建一个为我们执行此操作的处理程序。

当从脚本执行代码时，与在 web 服务器中运行代码相比，我们不使用此处理程序。直接运行脚本时，我们希望日志记录到我们之前定义的默认记录器。在`create_app`中，我们将设置一个参数来区分它们。

Python 日志模块具有许多有趣的功能。查看 Python 文档以获取更多信息（[`docs.python.org/3/library/logging.html`](https://docs.python.org/3/library/logging.html)）。

正确设置日志比看起来更加棘手。不要灰心，继续调整它们直到它们起作用。

我们将在`app.py`文件中设置所有日志配置。让我们分解配置的每个部分：

1.  首先，我们将生成一个格式化程序，以便在生成日志时附加`request_id`，使其在生成日志时可用：

```py
class RequestFormatter(logging.Formatter):
    ''' Inject the HTTP_X_REQUEST_ID to format logs '''

    def format(self, record):
        record.request_id = 'NA'

        if has_request_context():
            record.request_id = request.environ.get("HTTP_X_REQUEST_ID")

        return super().format(record)
```

如您所见，`HTTP_X_REQUEST_ID`头在`request.environ`变量中可用。

1.  稍后，在`create_app`中，我们将设置附加到`application`记录器的处理程序：

```py
# Enable RequestId
application.config['REQUEST_ID_UNIQUE_VALUE_PREFIX'] = ''
RequestID(application)

if not script:
    # For scripts, it should not connect to Syslog
    handler = logging.handlers.SysLogHandler(('syslog', 5140))
    req_format = ('[%(asctime)s] %(levelname)s [%(request_id)s] '
                    %(module)s: %(message)s')
    handler.setFormatter(RequestFormatter(req_format))
    handler.setLevel(logging.INFO)
    application.logger.addHandler(handler)
    # Do not propagate to avoid log duplication
    application.logger.propagate = False
```

只有在脚本外运行时才设置处理程序。`SysLogHandler`包含在 Python 中。之后，我们设置格式，其中包括`request_id`。格式化程序使用我们之前定义的`RequestFormatter`。

在这里，我们将记录器级别的值硬编码为`INFO`，`syslog`主机为`syslog`，这对应于服务。Kubernetes 将正确解析此 DNS。这两个值都可以通过环境变量传递，但出于简单起见，我们没有在这里这样做。

记录器尚未传播，因此避免将其发送到`root`记录器，这将重复记录。

# 记录每个请求

每个请求中都有一些常见元素需要捕获。Flask 允许我们在请求之前和之后执行代码，因此我们可以使用它来记录每个请求的常见元素。让我们学习如何做到这一点。

从`app.py`文件中，我们将定义`logging_before`函数：

```py
from flask import current_app, g

def logging_before():
    msg = 'REQUEST {REQUEST_METHOD} {REQUEST_URI}'.format(**request.environ)
    current_app.logger.info(msg)

    # Store the start time for the request
    g.start_time = time()
```

这将创建一个带有单词`REQUEST`和每个请求的两个基本部分（方法和 URI）的日志，这些部分来自`request.environ`。然后，它们将添加到应用程序记录器的`INFO`日志中。

我们还使用`g`对象来存储请求开始时的时间。

`g`对象允许我们通过请求存储值。我们将使用它来计算请求将花费的时间。

还有相应的`logging_after`函数。它在请求结束时收集时间并计算毫秒数的差异：

```py
def logging_after(response):
    # Get total time in milliseconds
    total_time = time() - g.start_time
    time_in_ms = int(total_time * 1000)
    msg = f'RESPONSE TIME {time_in_ms} ms'
    current_app.logger.info(msg)

    msg = f'RESPONSE STATUS {response.status_code.value}'
    current_app.logger.info(msg)

    # Store metrics
    ...

    return response
```

这将使我们能够检测到需要更长时间的请求，并将其存储在指标中，我们将在下一节中看到。

然后，在`create_app`函数中启用了这些功能：

```py
def create_app(script=False):
    ...
    application = Flask(__name__)
    application.before_request(logging_before)
    application.after_request(logging_after)
```

每次生成请求时都会创建一组日志。

有了生成的日志，我们可以在`frontrail`界面中搜索它们。

# 搜索所有日志

来自不同应用程序的所有不同日志将被集中并可在`http://syslog.example.local`上搜索。

如果您调用`http://frontend.example.local/search?search=speak`来搜索想法，您将在日志中看到相应的 Thoughts Backend，如下图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-dkr-msvc-py/img/1254a0cc-90d6-4340-b901-95536a0a34e0.png)

我们可以按请求 ID 进行过滤，即`63517c17-5a40-4856-9f3b-904b180688f6`，以获取 Thoughts Backend 请求日志。紧接着是`thoughts_backend_uwsgi`和`frontend_uwsgi`请求日志，显示了请求的流程。

在这里，您可以看到我们之前谈到的所有元素：

+   请求之前的`REQUEST`日志

+   包含应用数据的`api_namespace`请求

+   包含结果和时间的`RESPONSE`日志

在 Thoughts Backend 的代码中，我们故意留下了一个错误。如果用户尝试分享新的想法，它将被触发。我们将使用这个来学习如何通过日志调试问题。

# 通过日志检测问题

在您运行的系统中，可能会出现两种类型的错误：预期错误和意外错误。

# 检测预期错误

预期错误是通过在代码中显式创建`ERROR`日志而引发的错误。如果生成了错误日志，这意味着它反映了事先计划的情况；例如，无法连接到数据库，或者某些数据存储在旧的废弃格式中。我们不希望这种情况发生，但我们看到了它发生的可能性，并准备好了代码来处理它。它们通常描述得足够清楚，以至于问题是显而易见的，即使解决方案不明显。

它们相对容易处理，因为它们描述了预见的问题。

# 捕获意外错误

意外错误是可能发生的其他类型的错误。事情以意想不到的方式出错。意外错误通常是由于代码中某些地方引发了 Python 异常而未被捕获。

如果日志已经正确配置，任何未被捕获的异常或错误都会触发一个`ERROR`日志，其中包括堆栈跟踪。这些错误可能不会立即显而易见，需要进一步调查。

为了帮助解释这些错误，我们在`Chapter10`代码的 Thoughts Backend 中引入了一个异常。您可以在 GitHub 上检查代码([`github.com/PacktPublishing/Hands-On-Docker-for-Microservices-with-Python/tree/master/Chapter10/microservices/thoughts_backend/ThoughtsBackend/thoughts_backend`](https://github.com/PacktPublishing/Hands-On-Docker-for-Microservices-with-Python/tree/master/Chapter10/microservices/thoughts_backend/ThoughtsBackend/thoughts_backend))。这模拟了一个意外的异常。

尝试为已登录用户发布新想法时，我们会遇到奇怪的行为，并在日志中看到以下错误。如下图右上角所示，我们正在按`ERROR`进行过滤以查找问题：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-dkr-msvc-py/img/3bad0ee5-9505-4648-8158-cf878d1969ad.png)

如您所见，堆栈跟踪显示在单行中。这可能取决于您如何捕获和显示日志。Flask 将自动生成一个状态码为 500 的 HTTP 响应。如果调用者没有准备好接收 500 响应，这可能会在路径上触发更多错误。

然后，堆栈跟踪将让您知道出了什么问题。在这种情况下，我们可以看到在第 80 行的`api_namespace.py`文件中有一个`raise Exception`命令。这使我们能够定位异常。

由于这是一个特意生成的合成错误示例，实际上很容易找到根本原因。在示例代码中，我们明确引发了一个异常，这会产生一个错误。在实际用例中可能不是这种情况，异常可能在与实际错误不同的地方生成。异常也可能来自同一集群中的不同微服务。

在检测到错误后，目标应该是在微服务中使用单元测试复制错误以生成异常。这将使我们能够在受控环境中复制条件。

如果我们运行 `Chapter10` 中可用的 Thoughts Backend 代码的测试，我们将看到由于此原因而出现错误。请注意，日志将显示在失败的测试中。

```py
$ docker-compose run test
...
___ ERROR at setup of test_get_non_existing_thought ___
-------- Captured log setup ---------
INFO flask.app:app.py:46 REQUEST POST /api/me/thoughts/
INFO flask.app:token_validation.py:66 Header successfully validated
ERROR flask.app:app.py:1761 Exception on /api/me/thoughts/ [POST]
Traceback (most recent call last):
 File "/opt/venv/lib/python3.6/site-packages/flask/app.py", line 1813, in full_dispatch_request
 rv = self.dispatch_request()
 File "/opt/venv/lib/python3.6/site-packages/flask/app.py", line 1799, in dispatch_request
 return self.view_functionsrule.endpoint
 File "/opt/venv/lib/python3.6/site-packages/flask_restplus/api.py", line 325, in wrapper
 resp = resource(*args, **kwargs)
 File "/opt/venv/lib/python3.6/site-packages/flask/views.py", line 88, in view
 return self.dispatch_request(*args, **kwargs)
 File "/opt/venv/lib/python3.6/site-packages/flask_restplus/resource.py", line 44, in dispatch_request
 resp = meth(*args, **kwargs)
 File "/opt/venv/lib/python3.6/site-packages/flask_restplus/marshalling.py", line 136, in wrapper
 resp = f(*args, **kwargs)
 File "/opt/code/thoughts_backend/api_namespace.py", line 80, in post
 raise Exception('Unexpected error!')
Exception: Unexpected error!
INFO flask.app:app.py:57 RESPONSE TIME 3 ms
INFO flask.app:app.py:60 RESPONSE STATUS 500 
```

一旦在单元测试中重现了错误，修复它通常会很简单。添加一个单元测试来捕获触发错误的条件，然后修复它。新的单元测试将检测每次自动构建中是否重新引入了错误。

要修复示例代码，请删除 `raise` 代码行。然后，事情将再次正常工作。

有时，问题无法解决，因为可能是外部问题。也许我们的数据库中的某些行存在问题，或者另一个服务返回的数据格式不正确。在这些情况下，我们无法完全避免错误的根本原因。但是，可以捕获问题，进行一些补救，并从意外错误转变为预期错误。

请注意，并非每个检测到的意外错误都值得花时间处理。有时，未捕获的错误提供了足够的信息，超出了 Web 服务应该处理的范围；例如，可能存在网络问题，Web 服务无法连接到数据库。在开发时，要根据自己的判断来决定是否要花时间处理。

# 记录策略

处理日志时存在问题。对于特定消息，什么是适当的级别？这是 `WARNING` 还是 `ERROR`？这应该是一个 `INFO` 语句吗？

大多数日志级别描述使用定义，例如“程序显示潜在的有害情况”或“程序突出显示请求的进展”。这些定义模糊且在实际环境中并不是很有用。相反，尝试通过将每个日志级别与预期的后续操作联系起来来定义每个日志级别。这有助于明确发现特定级别的日志时应该采取的行动。

以下表格显示了不同级别的一些示例以及应该采取的行动：

| **日志级别** | **采取的行动** | **评论** |
| --- | --- | --- |
| `DEBUG` | 无。 | 不跟踪。 |
| `INFO` | 无。 | `INFO` 日志显示有关请求流程的通用信息，以帮助跟踪问题。 |
| `WARNING` | 跟踪数量。在提高级别时发出警报。 | `WARNING` 日志跟踪已自动修复的错误，例如重试连接（但最终连接成功）或数据库数据中可修复的格式错误。突然增加可能需要调查。 |
| `ERROR` | 跟踪数量。在提高级别时发出警报。审查所有。 | `ERROR` 日志跟踪无法修复的错误。突然增加可能需要立即采取行动以进行补救。 |
| `CRITICAL` | 立即响应。 | `CRITICAL` 日志表示系统发生了灾难性故障。即使一个 `CRITICAL` 日志也表明系统无法正常工作且无法恢复。 |

这只是一个建议，但它为如何做出响应设定了明确的期望。根据团队和期望的服务水平的工作方式，可以将其调整为自己的用例。

在这里，层次结构非常清晰，并且人们接受一定数量的 `ERROR` 日志将被生成。并非所有问题都需要立即修复，但应该记录并进行审查。

在现实生活中，`ERROR`日志通常被归类为“我们注定要失败”或“无所谓”。开发团队应该积极修复或删除“无所谓”的错误，以尽量减少它们。这可能包括降低日志级别，如果它们没有涵盖实际错误的话。您希望尽可能少的`ERROR`日志，但所有这些日志都需要有意义。

然而，务实一点。有时，错误无法立即修复，时间最好用在其他任务上。然而，团队应该保留时间来减少发生的错误数量。不这样做将会损害系统的中期可靠性。

`WARNING`日志表明某些事情可能不像我们预期的那样顺利，但除非数字增长，否则无需惊慌。`INFO`只是在出现问题时为我们提供上下文，但在其他情况下应该被忽略。

避免在请求返回 400 BAD REQUEST 状态代码时产生`ERROR`日志的诱惑。一些开发人员会认为，如果客户发送了格式不正确的请求，那实际上就是一个错误。但是，如果请求已经被正确检测并返回，这并不是你应该关心的事情。这是业务惯例。如果这种行为可能表明其他问题，比如重复尝试发送不正确的密码，您可以设置`WARNING`日志。当系统表现如预期时，生成`ERROR`日志是没有意义的。

作为一个经验法则，如果一个请求没有返回某种 500 错误（500、502、504 等），它不应该生成`ERROR`日志。记住将 400 错误归类为*您（客户）有问题*，而将 500 错误归类为*我有问题*。

然而，这并非绝对。例如，通常为 4XX 错误的认证错误激增可能表明用户由于真正的内部问题而无法创建日志。

有了这些定义，您的开发和运维团队将有一个共同的理解，这将帮助他们采取有意义的行动。

随着系统的成熟，预计需要调整系统并更改日志级别。

# 在开发过程中添加日志

正如我们已经看到的，正确配置`pytest`将使测试中的任何错误显示捕获的日志。

这是一个机会，可以在开发功能时检查是否生成了预期的日志。检查错误条件的任何测试也应该添加相应的日志，并在开发功能期间检查它们是否生成。

您可以检查日志作为测试的一部分，使用诸如`pytest-catchlog`（[`pypi.org/project/pytest-catchlog/`](https://pypi.org/project/pytest-catchlog/)）这样的工具来强制执行正确的日志生成。

通常情况下，在开发过程中，只需稍加注意并检查是否生成了日志就足够了。但是，确保开发人员了解在开发过程中拥有日志的用处。

在开发过程中，`DEBUG`日志可用于显示关于流程的额外信息，这些信息对于生产环境来说可能过多。这可以填补`INFO`日志之间的空白，并帮助我们养成添加日志的习惯。如果在测试期间发现`DEBUG`日志对于在生产环境中跟踪问题有用，可以将其提升为`INFO`。

在受控情况下，可能会在生产环境中启用`DEBUG`日志以跟踪一些困难的问题，但要注意拥有大量日志的影响。

在`INFO`日志中呈现的信息要明智。在显示的信息方面，避免敏感数据，如密码、密钥、信用卡号或个人信息。日志数量也是如此。

注意任何大小限制以及日志生成的速度。随着新功能的添加、更多请求通过系统流动以及新的工作人员的加入，不断增长的系统可能会导致日志爆炸。

此外，还要仔细检查日志是否被正确生成和捕获，并且它们在所有不同级别和环境中是否起作用。所有这些配置可能需要一些时间，但您需要非常确定您能够在生产环境中捕获意外错误，并且所有的管道都设置正确。

让我们来看看可观察性的另一个关键要素：指标。

# 设置指标

要使用 Prometheus 设置指标，我们需要了解该过程的工作原理。其关键组件是，每个受测量的服务都有自己的 Prometheus 客户端，用于跟踪指标。Prometheus 服务器中的数据将可供 Grafana 服务绘制指标。

以下图表显示了一般架构：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-dkr-msvc-py/img/5b14900d-d4cd-4768-a10b-7a918425d553.png)

Prometheus 服务器定期拉取信息。这种操作方法非常轻量级，因为注册指标只是更新服务的本地内存并且能够很好地扩展。另一方面，它在特定时间显示采样数据，并且不会注册每个单独的事件。这在存储和表示数据方面有一定的影响，并且对数据的分辨率施加了限制，特别是对于非常低的速率。

有许多可用的指标导出器，它们将在不同系统中公开标准指标，如数据库、硬件、HTTP 服务器或存储。查看 Prometheus 文档以获取更多信息：[`prometheus.io/docs/instrumenting/exporters/`](https://prometheus.io/docs/instrumenting/exporters/)。

这意味着我们的每个服务都需要安装一个 Prometheus 客户端，并以某种方式公开其收集的指标。我们将使用 Flask 和 Django 的标准客户端。

# 思想后端的指标定义

对于 Flask 应用程序，我们将使用`prometheus-flask-exporter`包（[`github.com/rycus86/prometheus_flask_exporter`](https://github.com/rycus86/prometheus_flask_exporter)），已添加到`requirements.txt`中。

当应用程序创建时，它会在`app.py`文件中激活（[`github.com/PacktPublishing/Hands-On-Docker-for-Microservices-with-Python/blob/master/Chapter10/microservices/thoughts_backend/ThoughtsBackend/thoughts_backend/app.py#L95`](https://github.com/PacktPublishing/Hands-On-Docker-for-Microservices-with-Python/blob/master/Chapter10/microservices/thoughts_backend/ThoughtsBackend/thoughts_backend/app.py#L95)）。

`metrics`对象没有设置应用程序，然后在`created_app`函数中实例化：

```py
from prometheus_flask_exporter import PrometheusMetrics

metrics = PrometheusMetrics(app=None)

def create_app(script=False):
    ...
    # Initialise metrics
    metrics.init_app(application)
```

这将生成`/metrics`服务端点中的一个端点，即`http://thoughts.example.local/metrics`，它以 Prometheus 格式返回数据。Prometheus 格式是纯文本，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-dkr-msvc-py/img/81ba132d-890c-4b57-96db-46bbfca38f44.png)

`prometheus-flask-exporter`捕获的默认指标是基于端点和方法的请求调用（`flask_http_request_total`），以及它们所花费的时间（`flask_http_request_duration_seconds`）。

# 添加自定义指标

当涉及应用程序细节时，我们可能希望添加更具体的指标。我们还在请求结束时添加了一些额外的代码，以便我们可以存储与`prometheus-flask-exporter`允许我们存储的类似信息。

特别是，我们在`logging_after`函数中添加了此代码（[`github.com/PacktPublishing/Hands-On-Docker-for-Microservices-with-Python/blob/master/Chapter10/microservices/thoughts_backend/ThoughtsBackend/thoughts_backend/app.py#L72`](https://github.com/PacktPublishing/Hands-On-Docker-for-Microservices-with-Python/blob/master/Chapter10/microservices/thoughts_backend/ThoughtsBackend/thoughts_backend/app.py#L72)），使用较低级别的`prometheus_client`。

此代码创建了`Counter`和`Histogram`：

```py
from prometheus_client import Histogram, Counter

METRIC_REQUESTS = Counter('requests', 'Requests',
                          ['endpoint', 'method', 'status_code'])
METRIC_REQ_TIME = Histogram('req_time', 'Req time in ms',
                            ['endpoint', 'method', 'status_code']) 

def logging_after(response):
    ...
    # Store metrics
    endpoint = request.endpoint
    method = request.method.lower()
    status_code = response.status_code
    METRIC_REQUESTS.labels(endpoint, method, status_code).inc()
    METRIC_REQ_TIME.labels(endpoint, method, status_code).observe(time_in_ms)
```

在这里，我们创建了两个指标：一个名为`requests`的计数器和一个名为`req_time`的直方图。直方图是 Prometheus 对具有特定值的度量和事件的实现，例如请求时间（在我们的情况下）。

直方图将值存储在桶中，从而使我们能够计算分位数。分位数对于确定诸如时间的 95%值非常有用，例如聚合时间，其中 95%低于它。这比平均值更有用，因为异常值不会影响平均值。

还有一个类似的指标叫做摘要。差异是微妙的，但通常，我们应该使用直方图。查看 Prometheus 文档以获取更多详细信息([`prometheus.io/docs/practices/histograms/`](https://prometheus.io/docs/practices/histograms/))。

指标由它们的名称、测量和它们定义的标签`METRIC_REQUESTS`和`METRIC_REQ_TIME`定义。每个标签都是指标的额外维度，因此您将能够通过它们进行过滤和聚合。在这里，我们定义了端点、HTTP 方法和生成的 HTTP 状态码。

对于每个请求，指标都会更新。我们需要设置标签、计数器调用，即`.inc()`，以及直方图调用，即`.observe(time)`。

您可以在[`github.com/prometheus/client_python`](https://github.com/prometheus/client_python)找到 Prometheus 客户端的文档。

我们可以在指标页面上看到`request`和`req_time`指标。

为用户后端设置指标遵循类似的模式。用户后端是一个类似的 Flask 应用程序，因此我们也安装了`prometheus-flask-exporter`，但没有自定义指标。您可以在`http://users.example.local/metrics`上访问这些指标。

下一阶段是设置一个 Prometheus 服务器，以便我们可以正确地收集和聚合指标。

# 收集指标。

为此，我们需要使用 Kubernetes 部署指标。我们已经在`Chapter10/kubernetes/prometheus.yaml`文件中准备好了一切。

这个 YAML 文件包含一个部署、一个包含配置文件的`ConfigMap`、一个服务和一个 Ingress。服务和 Ingress 都是非常标准的，所以我们在这里不会对它们进行评论。

`ConfigMap`允许我们定义一个文件：

```py
apiVersion: v1
kind: ConfigMap
metadata:
  name: prometheus-config
  namespace: example
data:
  prometheus.yaml: |
    scrape_configs:
    - job_name: 'example'

      static_configs:
        - targets: ['thoughts-service', 'users-service', 
                    'frontend-service']
```

请注意`prometheus.yaml`文件是在`|`符号之后生成的。这是一个最小的 Prometheus 配置，从`thoughts-service`、`users-service`和`frontend-service`服务器中抓取。正如我们从前面的章节中所知，这些名称访问服务，并将连接到提供应用程序的 pod。它们将自动搜索`/metrics`路径。

这里有一个小注意事项。从 Prometheus 的角度来看，服务后面的一切都是相同的服务器。如果有多个正在提供服务的 pod，那么 Prometheus 访问的指标将被负载平衡，指标将不正确。

这可以通过更复杂的 Prometheus 设置来解决，其中我们安装 Prometheus 操作员，但这超出了本书的范围。但是，这对于生产系统非常推荐。实质上，它允许我们注释每个不同的部署，以便动态更改 Prometheus 配置。这意味着一旦设置完成，我们就可以自动访问由 pod 公开的所有指标端点。Prometheus 操作员注释使我们非常容易向指标系统添加新元素。

如果您想了解如何执行此操作，请查看以下文章：[`sysdig.com/blog/kubernetes-monitoring-prometheus-operator-part3`](https://sysdig.com/blog/kubernetes-monitoring-prometheus-operator-part3)。

部署将从`prom/prometheus`中的公共 Prometheus 镜像创建一个容器，如下所示：

```py
spec:
  containers:
  - name: prometheus
    image: prom/prometheus
    volumeMounts:
    - mountPath: /etc/prometheus/prometheus.yml
      subPath: prometheus.yaml
      name: volume-config
    ports:
    - containerPort: 9090
    volumes:
    - name: volume-config
      configMap:
        name: prometheus-config
```

它还将`ConfigMap`挂载为卷，然后作为文件挂载到`/etc/prometheus/prometheus.yml`中。这将使用该配置启动 Prometheus 服务器。容器打开端口`9090`，这是 Prometheus 的默认端口。

在这一点上，请注意我们委托了 Prometheus 容器。这是使用 Kubernetes 的优势之一：我们可以使用标准可用的容器，以最小的配置为我们的集群添加功能。我们甚至不必担心操作系统或 Prometheus 容器的打包。这简化了操作，并允许我们标准化我们使用的工具。

部署的 Prometheus 服务器可以通过`http://prometheus.example.local/`访问，如 Ingress 和 service 中所述。

这显示了一个图形界面，可用于绘制图形，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-dkr-msvc-py/img/98c116d8-05e9-461b-b13b-d8a24a240609.png)

表达式搜索框还将自动完成指标，有助于发现过程。

该界面还显示了来自 Prometheus 的其他有趣元素，例如配置或目标的状态：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-dkr-msvc-py/img/4a164941-5d6b-4364-903e-5123751f6476.png)

此界面中的图形可用，但我们可以通过 Grafana 设置更复杂和有用的仪表板。让我们看看这个设置是如何工作的。

# 绘制图形和仪表板

所需的 Kubernetes 配置`grafana.yaml`可在本书的 GitHub 存储库的`Chapter10/kubernetes/metrics`目录中找到。就像我们使用单个文件配置 Prometheus 一样，我们也使用单个文件配置 Grafana。

出于与之前解释的相同原因，我们不会显示 Ingress 和 service。部署很简单，但我们挂载了两个卷而不是一个，如下面的代码所示：

```py
spec:
  containers:
    - name: grafana
      image: grafana/grafana
      volumeMounts:
        - mountPath: /etc/grafana/provisioning
                     /datasources/prometheus.yaml
          subPath: prometheus.yaml
          name: volume-config
        - mountPath: /etc/grafana/provisioning/dashboards
          name: volume-dashboard
      ports:
        - containerPort: 3000
  volumes:
    - name: volume-config
      configMap:
        name: grafana-config
    - name: volume-dashboard
      configMap:
        name: grafana-dashboard
```

`volume-config`卷共享一个配置 Grafana 的单个文件。`volume-dashboard`卷添加了一个仪表板。后者挂载了一个包含两个文件的目录。这两个挂载点都在 Grafana 期望的配置文件的默认位置。

`volume-config`卷设置了 Grafana 将接收数据以绘制的数据源的位置：

```py
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: grafana-config
  namespace: example
data:
  prometheus.yaml: |
      apiVersion: 1

      datasources:
      - name: Prometheus
        type: prometheus
        url: http://prometheus-service
        access: proxy
        isDefault: true
```

数据来自`http://prometheus-service`，指向我们之前配置的 Prometheus 服务。

`volume-dashboard`定义了两个文件，`dashboard.yaml`和`dashboard.json`：

```py
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: grafana-dashboard
  namespace: example
data:
  dashboard.yaml: |
    apiVersion: 1

    providers:
    - name: 'Example'
      orgId: 1
      folder: ''
      type: file
      editable: true
      options:
        path: /etc/grafana/provisioning/dashboards
  dashboard.json: |-
    <JSON FILE>
```

`dashboard.yaml`是一个简单的文件，指向我们可以找到描述系统可用仪表板的 JSON 文件的目录。我们指向相同的目录以挂载所有内容到单个卷。

`dashboard.json`在此处被编辑以节省空间；查看本书的 GitHub 存储库以获取数据。

`dashboard.json`以 JSON 格式描述了一个仪表板。通过 Grafana 用户界面可以自动生成此文件。添加更多`.json`文件将创建新的仪表板。

# Grafana 用户界面

通过访问`http://grafana.example.local`并使用您的登录/密码详细信息，即`admin/admin`（默认值），您可以访问 Grafana 用户界面：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-dkr-msvc-py/img/e0ed3527-9a22-4a49-8356-5e58795741ac.png)

从那里，您可以检查仪表板，该仪表板可以在左侧中央列中找到：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-dkr-msvc-py/img/15311ba9-bf88-4c0c-8b8b-15a29b88edf3.png)

这捕捉了对 Flask 的调用，无论是数量还是*95^(th)*百分位时间。每个单独的图形都可以进行编辑，以便我们可以看到生成它的配方：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-dkr-msvc-py/img/bfba98e1-1532-46a9-8bbd-126745e3ee24.png)

左侧的图标允许我们更改系统中运行的查询，更改可视化（单位、颜色、条形或线条、绘图的类型等），添加名称等一般信息，并创建警报。

Grafana 用户界面允许我们进行实验，因此非常互动。花些时间尝试不同的选项，并学习如何呈现数据。

查询部分允许我们从 Prometheus 添加和显示指标。请注意默认附近的 Prometheus 徽标，这是数据源。

每个查询都有一个从 Prometheus 中提取数据的指标部分。

# 查询 Prometheus

Prometheus 有自己的查询语言称为 PromQL。这种语言非常强大，但它也有一些特殊之处。

Grafana UI 通过自动完成查询来帮助我们，这使我们可以轻松搜索指标名称。您可以直接在仪表板中进行实验，但是 Grafana 上有一个名为 Explore 的页面，允许您从任何仪表板进行查询，并提供一些不错的提示，包括基本元素。这在左侧边栏中用一个指南针图标表示。

首先要记住的是了解 Prometheus 指标。鉴于其采样方法，大多数指标是单调递增的。这意味着绘制指标将显示一条不断上升的线。

要获得值在一段时间内变化的速率，需要使用`rate`：

```py
rate(flask_http_request_duration_seconds_count[5m])
```

这将生成每秒的请求率，平均使用`5`分钟的移动窗口。速率可以进一步使用`sum`和`by`进行聚合：

```py
sum(rate(flask_http_request_duration_seconds_count[5m])) by (path)
```

要计算时间，可以使用`avg`。您还可以按多个标签进行分组：

```py
avg(rate(flask_http_request_duration_seconds_bucket[5m])) by (method, path)
```

但是，您也可以设置分位数，就像我们在图表中可以做的那样。我们乘以 100 以获得以毫秒为单位的时间，而不是秒，并按`method`和`path`进行分组。现在，`le`是一个特殊的标签，会自动创建并将数据分成多个桶。`histogram_quantile`函数使用这个来计算分位数：

```py
histogram_quantile(0.95, sum(rate(flask_http_request_duration_seconds_bucket[5m])) by (method, path, le)) * 1000

```

可以对指标进行过滤，以便仅显示特定的标签。它们还可以用于不同的功能，例如除法，乘法等。

当我们试图显示几个指标的结果时，例如成功请求占总数的百分比时，Prometheus 查询可能会有点长而复杂。一定要测试结果是否符合您的预期，并留出时间来调整请求。

如果您想了解更多，请务必查看 Prometheus 文档：[`prometheus.io/docs/prometheus/latest/querying/basics/`](https://prometheus.io/docs/prometheus/latest/querying/basics/)。

# 更新仪表板

仪表板可以进行交互式更改和保存，但在我们的 Kubernetes 配置中，我们设置了包含文件的卷为非持久性。因此，重新启动 Grafana 将丢弃任何更改，并重新应用`Chapter10/kubernetes/metrics/grafana.yaml`文件中`volume-dashboard`中定义的配置。

这实际上是一件好事，因为我们将相同的 GitOps 原则应用于将完整配置存储在 Git 存储库中。

但是，正如您所看到的，包含在`grafana.yaml`文件中的仪表板的完整 JSON 描述非常长，因为参数的数量以及手动更改它们的困难。

最好的方法是交互式地更改仪表板，然后使用菜单顶部的共享文件按钮将其导出为 JSON 文件。然后，可以将 JSON 文件添加到配置中：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-dkr-msvc-py/img/e3802571-88e1-4692-85bb-4560de9d23ea.png)

然后可以重新部署 Grafana pod，并且仪表板中的保存更改将包含在内。然后可以通过常规流程在 Git 中更新 Kubernetes 配置。

一定要探索仪表板的所有可能性，包括设置变量的选项，以便您可以使用相同的仪表板监视不同的应用程序或环境以及不同类型的可视化工具。有关更多信息，请参阅完整的 Grafana 文档：[`grafana.com/docs/reference/`](https://grafana.com/docs/reference/)。

有了可用的指标，我们可以利用它们来积极主动地了解系统并预测任何问题。

# 积极主动

指标显示了整个集群状态的聚合视图。它们使我们能够检测趋势问题，但很难找到单个的偶发错误。

不要低估它们。它们对于成功的监控至关重要，因为它们告诉我们系统是否健康。在一些公司，最关键的指标会在墙上的屏幕上显著显示，以便运维团队可以随时看到并迅速做出反应。

在系统中找到指标的适当平衡并不是一项简单的任务，需要时间和反复试验。然而，对于在线服务来说，总有四个重要的指标。它们分别是：

+   **延迟**：系统响应请求所需的毫秒数。

根据不同的时间，可以使用不同的时间单位，比如秒或微秒。根据我的经验，毫秒是足够的，因为在 Web 应用系统中，大多数请求的响应时间应该在 50 毫秒到 1 秒之间。在这里，花费 50 毫秒的系统速度太慢，而花费 1 秒的系统则是非常高效的。

+   **流量**：单位时间内通过系统的请求数，即每秒或每分钟的请求数。

+   **错误**：收到的返回错误的请求的百分比。

+   **饱和度**：集群的容量是否有足够的余地。这包括诸如硬盘空间、内存等元素。例如，有 20%的可用 RAM 内存。

要测量饱和度，请记住安装可用的导出器，它们将自动收集大部分硬件信息（内存、硬盘空间等）。如果您使用云提供商，通常他们也会公开一套相关的指标，例如 AWS 的 CloudWatch。

这些指标可以在 Google SRE Book 中找到，被称为*四个黄金信号*，被认为是成功监控的最重要的高级元素。

# 警报

当指标出现问题时，应该生成自动警报。Prometheus 有一个包含的警报系统，当定义的指标满足定义的条件时会触发警报。

查看有关警报的 Prometheus 文档以获取更多信息：[`prometheus.io/docs/alerting/overview/`](https://prometheus.io/docs/alerting/overview/)。

Prometheus 的 Alertmanager 可以执行某些操作，比如根据规则发送电子邮件进行通知。该系统可以连接到集成的事件解决方案，如 OpsGenie（[`www.opsgenie.com`](https://www.opsgenie.com)），以生成各种警报和通知，如电子邮件、短信、电话等。

日志也可以用来创建警报。有一些工具允许我们在引发`ERROR`时创建一个条目，比如**Sentry**。这使我们能够检测问题并积极地进行补救，即使集群的健康状态没有受到影响。

一些商业工具可以处理日志，比如 Loggly，允许我们从日志中派生指标，根据日志的类型绘制图表，或者从日志中提取值并将其用作数值。虽然不如 Prometheus 这样的系统完整，但它们可以监视一些数值。它们还允许我们在达到阈值时发出通知。

监控领域充满了各种产品，有免费的也有付费的，可以帮助我们处理这些问题。虽然可以创建一个完全内部的监控系统，但能够分析商业云工具是否有帮助是至关重要的。功能的水平以及它们与有用工具的集成，比如外部警报系统，将很难复制和维护。

警报也是一个持续的过程。一些元素将在后续发现，新的警报将不得不被创建。务必投入时间，以确保一切都按预期工作。在系统不健康的时候，日志和指标将被使用，而在那些时刻，时间至关重要。您不希望因为主机参数配置不正确而猜测日志。

# 做好准备

备份如果没有经过测试和工作的恢复过程是没有用的，当检查监控系统是否产生有用信息时要采取主动措施。

特别是，尝试标准化日志，以便对包含什么信息以及其结构有一个良好的期望。不同的系统可能产生不同的日志，但最好让所有微服务以相同的格式记录日志。仔细检查任何参数，例如客户端引用或主机，是否被正确记录。

同样适用于指标。拥有一组所有人都理解的指标和仪表板将在跟踪问题时节省大量时间。

# 摘要

在本章中，我们学习了如何处理日志和指标，以及如何设置日志并使用`syslog`协议将其发送到集中式容器。我们描述了如何向不同的应用程序添加日志，如何包含请求 ID，以及如何从不同的微服务中生成自定义日志。然后，我们学习了如何制定策略，以确保日志在生产中是有用的。

我们还描述了如何在所有微服务中设置标准和自定义的 Prometheus 指标。我们启动了一个 Prometheus 服务器，并对其进行配置，以便从我们的服务收集指标。我们启动了一个 Grafana 服务，以便我们可以绘制指标，并创建了仪表板，以便我们可以显示集群的状态和正在运行的不同服务。

然后，我们向您介绍了 Prometheus 中的警报系统以及如何使用它来通知我们问题。请记住，有商业服务可以帮助您处理日志、指标和警报。分析您的选择，因为它们可以在维护成本方面为您节省大量时间和金钱。

在下一章中，我们将学习如何管理影响多个微服务的更改和依赖关系，以及如何处理配置和秘密。

# 问题

1.  系统的可观察性是什么？

1.  日志中有哪些不同的严重级别可用？

1.  指标用于什么？

1.  为什么需要向日志中添加请求 ID？

1.  Prometheus 有哪些可用的指标类型？

1.  指标中的第 75 百分位是什么，它与平均值有何不同？

1.  四个黄金信号是什么？

# 进一步阅读

您可以通过阅读*监控 Docker*（[`www.packtpub.com/virtualization-and-cloud/monitoring-docker`](https://www.packtpub.com/virtualization-and-cloud/monitoring-docker)）来了解如何使用 Docker 使用不同工具和技术进行监控。要了解有关 Prometheus 和 Grafana 的更多信息，包括如何设置警报，请阅读*使用 Prometheus 进行基础设施监控*（[`www.packtpub.com/virtualization-and-cloud/hands-infrastructure-monitoring-prometheus`](https://www.packtpub.com/virtualization-and-cloud/hands-infrastructure-monitoring-prometheus)）。

监控只是成功运行服务的起点。要了解如何成功改进您的运营，请查看*真实世界 SRE*（[`www.packtpub.com/web-development/real-world-sre`](https://www.packtpub.com/web-development/real-world-sre)）。
