# Kubernetes 微服务实用指南（二）

> 原文：[`zh.annas-archive.org/md5/C0567D22DC0AB8851752A75F6BAC2512`](https://zh.annas-archive.org/md5/C0567D22DC0AB8851752A75F6BAC2512)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：设置 CI/CD 流水线

在基于微服务的系统中，有许多组成部分。Kubernetes 是一个提供了许多构建块的丰富平台。可靠和可预测地管理和部署所有这些组件需要高度的组织和自动化。这就是 CI/CD 流水线的作用。

在本章中，我们将了解 CI/CD 流水线解决的问题，介绍 Kubernetes 的 CI/CD 流水线的不同选项，并最终构建 Delinkcious 的 CI/CD 流水线。

在本章中，我们将讨论以下主题：

+   理解 CI/CD 流水线

+   Kubernetes CI/CD 流水线的选项

+   GitOps

+   自动化的 CI/CD

+   使用 CircleCI 构建您的镜像

+   为 Delinkcious 设置持续交付

# 技术要求

在本章中，您将使用 CircleCI 和 Argo CD。我将向您展示如何稍后在 Kubernetes 集群中安装 Argo CD。要免费设置 CircleCI，请按照它们网站上的*入门*说明[`circleci.com/docs/2.0/getting-started/`](https://circleci.com/docs/2.0/getting-started/)。

# 代码

本章的 Delinkcious 版本可以在[`github.com/the-gigi/delinkcious/releases/tag/v0.2`](https://github.com/the-gigi/delinkcious/releases/tag/v0.2)找到。

我们将在主要的 Delinkcious 代码库上工作，因此没有代码片段或示例。

# 理解 CI/CD 流水线

软件系统的开发生命周期从代码开始，经过测试，生成构件，更多测试，最终部署到生产环境。基本思想是，每当开发人员向其源代码控制系统（例如 GitHub）提交更改时，这些更改都会被**持续集成**（**CI**）系统检测到，并立即运行测试。

这通常会由同行进行审查，并将代码更改（或拉取请求）从特性分支或开发分支合并到主分支。在 Kubernetes 的上下文中，CI 系统还负责构建服务的 Docker 镜像并将其推送到镜像注册表。在这一点上，我们有包含新代码的 Docker 镜像。这就是 CD 系统的作用。

当新镜像可用时，**持续交付**（**CD**）系统将其部署到目标环境。CD 是确保整个系统处于期望状态的过程，通过配置和部署来实现。有时，如果系统不支持动态配置，部署可能会因配置更改而发生。我们将在第五章中详细讨论配置，*使用 Kubernetes 配置微服务*。

因此，CI/CD 流水线是一组工具，可以检测代码更改，并根据组织的流程和政策将其推送到生产环境。通常由 DevOps 工程师负责构建和维护此流水线，并且开发人员大量使用。

每个组织和公司（甚至同一公司内的不同团队）都会有一个特定的流程。在我第一份工作中，我的第一个任务是用许多人都不再理解的递归 makefile 替换基于 Perl 的构建系统（那时候 CI/CD 流水线被称为这样）。该构建系统必须在 Windows 上运行代码生成步骤，使用一些建模软件，在两种不同的 Unix 平台上（包括嵌入式平台）使用两种不同的工具链编译和运行 C++单元测试，并触发 open CVS。我选择了 Python，并不得不从头开始创建一切。

这很有趣，但非常特定于这家公司。通常认为 CI/CD 流水线是由事件驱动的一系列步骤的工作流程。

以下图表展示了一个简单的 CI/CD 流水线：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-msvc-k8s/img/6c83021d-cee3-4999-9aca-fcaee423eabf.png)

此流水线中的各个阶段的功能如下：

1.  开发人员将他们的更改提交到 GitHub（源代码控制）

1.  CI 服务器运行测试，构建 Docker 镜像，并将镜像推送到 DockerHub（镜像注册表）

1.  Argo CD 服务器检测到有新镜像可用，并部署到 Kubernetes 集群

现在我们已经了解了 CI/CD 流水线，让我们来看一下特定的 CI/CD 流水线选择。

# Delinkcious CI/CD 流水线的选项

为您的系统选择 CI/CD 流水线是一个重大决定。当我为 Delinkcious 面临这个决定时，我调查了几种替代方案。这里没有明显的选择。Kubernetes 发展迅速，工具和流程难以跟上。我评估了几种选择，并选择了 CircleCI 进行持续集成和 Argo CD 进行持续交付。我最初考虑了一个整个 CI/CD 流水线的一站式解决方案，但在审查了一些选项后，我决定更喜欢将它们视为两个单独的实体，并为 CI 和 CD 选择了不同的解决方案。让我们简要回顾一些这些选项（还有很多很多）：

+   Jenkins X

+   Spinnaker

+   Travis CI 和 CircleCI

+   Tekton

+   Argo CD

+   自己动手

# Jenkins X

Jenkins X 是我的首选和最喜欢的。我读了一些文章，看了一些演示，让我想要喜欢它。它提供了您想要的所有功能，包括一些高级功能：

+   自动化的 CI/CD

+   通过 GitOps 进行环境推广

+   拉取请求预览环境

+   对您的提交和拉取请求的自动反馈

在幕后，它利用了成熟但复杂的 Jenkins 产品。Jenkins X 的前提是它将掩盖 Jenkins 的复杂性，并提供一个特定于 Kubernetes 的简化工作流程。

当我尝试实际使用 Jenkins X 时，我对一些问题感到失望：

+   它不能直接使用，故障排除很复杂。

+   它非常主观。

+   它不很好地支持单一代码库方法（或根本不支持）。

我试图让它工作一段时间，但在阅读了其他人的经验并看到 Jenkins X 的 slack 社区频道缺乏响应后，我对 Jenkins X 失去了兴趣。我仍然喜欢这个想法，但在我再次尝试之前，它真的必须非常稳定。

# Spinnaker

Spinnaker 是 Netflix 的开源 CI/CD 解决方案。它有很多好处，包括以下：

+   它已被许多公司采用。

+   它与其他产品有很多集成。

+   它支持很多最佳实践。

Spinnaker 的缺点如下：

+   它是一个庞大而复杂的系统。

+   它有一个陡峭的学习曲线。

+   它不是特定于 Kubernetes 的。

最后，我决定放弃 Spinnaker——不是因为 Spinnaker 本身有任何问题，而是因为我对它没有经验。在开发 Delinkcious 本身和写这本书的过程中，我不想从头开始学习这样一个庞大的产品。你可能会发现 Spinnaker 对你来说是正确的 CI/CD 解决方案。

# Travis CI 和 CircleCI

我更喜欢将 CI 解决方案与 CD 解决方案分开。在概念上，CI 流程的作用是生成一个容器镜像并将其推送到注册表。它根本不需要了解 Kubernetes。另一方面，CD 解决方案必须对 Kubernetes 有所了解，并且理想情况下在集群内运行。

对于 CI，我考虑了 Travis CI 和 CircleCI。两者都为开源项目提供免费的 CI 服务。我选择了 CircleCI，因为它更具备功能完备，并且具有更好的用户界面，这很重要。我相信 Travis CI 也会很好用。我在其他一些开源项目中使用 Travis CI。重要的是要注意，流水线的 CI 部分完全与 Kubernetes 无关。最终结果是镜像仓库中的 Docker 镜像。这个 Docker 镜像可以用于其他目的，而不一定要部署在 Kubernetes 集群中。

# Tekton

Tekton 是一个非常有趣的项目。它是 Kubernetes 原生的，具有很好的步骤、任务、运行和流水线的抽象。它相对年轻，但似乎非常有前途。它还被选为 CD 基金会的首批项目之一：[`cd.foundation/projects/`](https://cd.foundation/projects/)。

看它如何发展将会很有趣。

Tekton 的优点如下：

+   现代设计和清晰的概念模型

+   得到 CD 基金会的支持。

+   建立在 prow 之上（Kubernetes 自身的 CI/CD 解决方案）

+   Kubernetes 原生解决方案

Tekton 的缺点如下：

+   它仍然相当新和不稳定。

+   它没有其他解决方案的所有功能和能力。

# Argo CD

与 CI 解决方案相反，CD 解决方案非常特定于 Kubernetes。我选择 Argo CD 有几个原因：

+   对 Kubernetes 有认识

+   建立在通用工作流引擎（Argo）之上

+   出色的用户界面

+   在您的 Kubernetes 集群上运行

+   用 Go 实现（并不是很重要，但我喜欢它）

Argo CD 也有一些缺点：

+   它不是 CD 基金会或 CNCF 的成员（在社区中认可度较低）。

+   Intuit 是其背后的主要公司，不是一个主要的云原生强大力量。

Argo CD 是一个来自 Intuit 的年轻项目，他们收购了 Argo 项目的原始开发人员- Applatix。我真的很喜欢它的架构，当我尝试过它时，一切都像魔术一样运行。

# 自己动手

我曾简要考虑过创建自己的简单 CI/CD 流水线。操作并不复杂。对于本书的目的，我并不需要一个非常可靠的解决方案，而且很容易解释每个步骤发生了什么。然而，考虑到读者，我决定最好使用现有的工具，这些工具可以直接利用，并且还可以节省我开发一个糟糕的 CI/CD 解决方案的时间。

此时，您应该对 Kubernetes 上的 CI/CD 解决方案有了一个很好的了解。我们审查了大多数流行的解决方案，并选择了 CircleCI 和 Argo CD 作为 Delinkcious CI/CD 解决方案的最佳选择。接下来，我们将讨论 GitOps 的热门新趋势。

# GitOps

GitOps 是一个新的时髦词汇，尽管概念并不是很新。这是*基础设施即代码*的另一种变体。基本思想是您的代码、配置和所需的资源都应该在一个源代码控制存储库中进行描述和存储，并进行版本控制。每当您向存储库推送更改时，您的 CI/CD 解决方案将做出响应并采取正确的操作。甚至可以通过在存储库中恢复到先前版本来启动回滚。当然，存储库不一定是 Git，但 GitOps 听起来比源代码控制运营好得多，大多数人都使用 Git，所以我们就在这里了。

CircleCI 和 Argo CD 都完全支持并倡导 GitOps 模型。当您`git push`代码更改时，CircleCI 将触发并开始构建正确的镜像。当您`git push`更改到 Kubernetes 清单时，Argo CD 将触发并将这些更改部署到您的 Kubernetes 集群。

现在我们清楚了 GitOps 是什么，我们可以开始为 Delinkcious 实施流水线的持续集成部分。我们将使用 CircleCI 从源代码构建 Docker 镜像。

# 使用 CircleCI 构建您的镜像

让我们深入研究 Delinkcious CI 流水线。我们将逐步介绍持续集成过程中的每个步骤，其中包括以下内容：

+   审查源代码树

+   配置 CI 流水线

+   理解构建脚本

+   使用多阶段 Dockerfile 对 Go 服务进行 Docker 化

+   探索 CircleCI 用户界面

# 审查源代码树

持续集成是关于构建和测试的东西。第一步是了解 Delinkcious 中需要构建和测试的内容。让我们再看一下 Delinkcious 源代码树：

```
$ tree -L 2
.
├── LICENSE
├── README.md
├── build.sh
├── cmd
│   ├── link_service_e2e
│   ├── social_graph_service_e2e
│   └── user_service_e2e
├── go.mod
├── go.sum
├── pkg
│   ├── db_util
│   ├── link_manager
│   ├── link_manager_client
│   ├── object_model
│   ├── social_graph_client
│   ├── social_graph_manager
│   ├── user_client
│   └── user_manager
└── svc
 ├── api_gateway_service
 ├── link_service
 ├── social_graph_service
 └── user_service
```

`pkg`目录包含服务和命令使用的包。我们应该运行这些包的单元测试。`svc`目录包含我们的微服务。我们应该构建这些服务，将每个服务打包到适当版本的 Docker 镜像中，并将这些镜像推送到 DockerHub（镜像注册表）。`cmd`目录目前包含端到端测试。这些测试旨在在本地运行，不需要由 CI 管道构建（如果您想将端到端测试添加到我们的测试流程中，可以更改这一点）。

# 配置 CI 管道

CircleCI 由一个标准名称和位置的单个 YAML 文件进行配置，即`<根目录>/.circleci/config.yaml`：

```
version: 2
jobs:
  build:
    docker:
    - image: circleci/golang:1.11
    - image: circleci/postgres:9.6-alpine
      environment: # environment variables for primary container
        POSTGRES_USER: postgres
    working_directory: /go/src/github.com/the-gigi/delinkcious
    steps:
    - checkout
    - run:
        name: Get all dependencies
        command: |
          go get -v ./...
          go get -u github.com/onsi/ginkgo/ginkgo
          go get -u github.com/onsi/gomega/...
    - run:
        name: Test everything
        command: ginkgo -r -race -failFast -progress
    - setup_remote_docker:
        docker_layer_caching: true
    - run:
        name: build and push Docker images
        shell: /bin/bash
        command: |
          chmod +x ./build.sh
          ./build.sh
```

让我们分开来理解发生了什么。第一部分指定了构建作业，下面是必要的 Docker 镜像（`golang`和`postgres`）及其环境。然后，我们有工作目录，`build`命令应该在其中执行：

```
version: 2
jobs:
 build:
 docker:
 - image: circleci/golang:1.11
 - image: circleci/postgres:9.6-alpine
      environment: # environment variables for primary container
        POSTGRES_USER: postgres
    working_directory: /go/src/github.com/the-gigi/delinkcious
```

下一部分是构建步骤。第一步只是检出。在 CircleCI UI 中，我将项目与 Delinkcious GitHub 存储库关联起来，以便它知道从哪里检出。如果存储库不是公共的，那么您还需要提供访问令牌。第二步是一个`run`命令，用于获取 Delinkcious 的所有 Go 依赖项：

```
steps:
- checkout
- run:
    name: Get all dependencies
    command: |
      go get -v ./...
      go get -u github.com/onsi/ginkgo/ginkgo
      go get -u github.com/onsi/gomega/...
```

我必须显式地`go get` `ginkgo`框架和`gomega`库，因为它们是使用 Golang 点符号导入的，这使它们对`go get ./...`不可见。

一旦我们有了所有的依赖，我们就可以运行测试。在这种情况下，我正在使用`ginkgo`测试框架：

```
- run:
    name: Test everything
    command: ginkgo -r -race -failFast -progress
```

下一部分是构建和推送 Docker 镜像的地方。由于它需要访问 Docker 守护程序，因此需要通过`setup_remote_docker`步骤进行特殊设置。`docker_layer_caching`选项用于通过重用先前的层使一切更高效和更快。实际的构建和推送由`build.sh`脚本处理，我们将在下一部分进行查看。请注意，我确保通过`chmod +x`是可执行的：

```
- setup_remote_docker:
    docker_layer_caching: true
- run:
    name: build and push Docker images
    shell: /bin/bash
    command: |
      chmod +x ./build.sh
      ./build.sh
```

我在这里只是浅尝辄止。CircleCI 还有更多功能，包括用于可重用配置、工作流、触发器和构件的 orbs。

# 理解 build.sh 脚本

`build.sh`脚本可在[`github.com/the-gigi/delinkcious/blob/master/build.sh`](https://github.com/the-gigi/delinkcious/blob/master/build.sh)找到。

让我们逐步检查它。我们将在这里遵循几个最佳实践。首先，最好在脚本中添加一个 shebang，其中包含将执行您的脚本的二进制文件的路径 - 也就是说，如果您知道它的位置。如果您尝试编写一个可以在许多不同平台上运行的跨平台脚本，您可能需要依赖路径或其他技术。`set -eo pipefail`将在任何出现问题时立即失败（即使在管道的中间）。

这在生产环境中是强烈推荐的：

```
#!/bin/bash

set -eo pipefail
```

接下来的几行只是为目录和 Docker 镜像的标记设置了一些变量。有两个标记：`STABLE_TAB`和`TAG`。`STABLE_TAG`标记具有主要版本和次要版本，并且在每次构建中不会更改。`TAG`包括 CircleCI 提供的`CIRCLE_BUILD_NUM`，并且在每次构建中递增。这意味着`TAG`始终是唯一的。这被认为是标记和版本化镜像的最佳实践：

```
IMAGE_PREFIX='g1g1'
STABLE_TAG='0.2'

TAG="${STABLE_TAG}.${CIRCLE_BUILD_NUM}"
ROOT_DIR="$(pwd)"
SVC_DIR="${ROOT_DIR}/svc"
```

接下来，我们进入`svc`目录，这是所有服务的父目录，并使用在 CircleCI 项目中设置的环境变量登录到 DockerHub。

```
cd $SVC_DIR
docker login -u $DOCKERHUB_USERNAME -p $DOCKERHUB_PASSWORD
```

现在，我们来到了主要事件。脚本遍历`svc`目录的所有子目录，寻找`Dockerfile`。如果找到`Dockerfile`，它会构建一个镜像，使用服务名称和`TAG`以及`STABLE_TAG`的组合对其进行标记，最后将标记的镜像推送到注册表：

```
cd "${SVC_DIR}/$svc"
    if [[ ! -f Dockerfile ]]; then
        continue
    fi
    UNTAGGED_IMAGE=$(echo "${IMAGE_PREFIX}/delinkcious-${svc}" | sed -e 's/_/-/g' -e 's/-service//g')
    STABLE_IMAGE="${UNTAGGED_IMAGE}:${STABLE_TAG}"
    IMAGE="${UNTAGGED_IMAGE}:${TAG}"
    docker build -t "$IMAGE" .
    docker tag "${IMAGE}" "${STABLE_IMAGE}"
    docker push "${IMAGE}"
    docker push "${STABLE_IMAGE}"
done
cd $ROOT_DIR
```

# 使用多阶段 Dockerfile 对 Go 服务进行 Docker 化

在微服务系统中构建的 Docker 镜像非常重要。您将构建许多镜像，并且每个镜像都会构建多次。这些镜像也会在网络上传输，并且它们是攻击者的目标。考虑到这一点，构建具有以下属性的镜像是有意义的：

+   轻量级

+   提供最小的攻击面

这可以通过使用适当的基础镜像来实现。例如，由于其小的占用空间，Alpine 非常受欢迎。然而，没有什么能比得上 scratch 基础镜像。对于基于 Go 的微服务，您可以创建一个只包含服务二进制文件的镜像。让我们继续剥离洋葱，看看其中一个服务的 Dockerfile。剧透警告：它们几乎完全相同，只是在服务名称方面有所不同。

你可以在[`github.com/the-gigi/delinkcious/blob/master/svc/link_service/Dockerfile`](https://github.com/the-gigi/delinkcious/blob/master/svc/link_service/Dockerfile)找到`link_service`的`Dockerfile`。

我们在这里使用了多阶段的`Dockerfile`。我们将使用标准的 Golang 镜像构建镜像。最后一行中的神秘魔法是构建一个真正静态和自包含的 Golang 二进制文件所需的内容，它不需要动态运行时库：

```
FROM golang:1.11 AS builder
ADD ./main.go main.go
ADD ./service service
# Fetch dependencies
RUN go get -d -v

# Build image as a truly static Go binary
RUN CGO_ENABLED=0 GOOS=linux go build -o /link_service -a -tags netgo -ldflags '-s -w' .
```

然后我们将最终的二进制文件复制到一个基于 scratch 的镜像中，并创建尽可能小和最安全的镜像。我们暴露了`7070`端口，这是服务监听的端口：

```
FROM scratch
MAINTAINER Gigi Sayfan <the.gigi@gmail.com>
COPY --from=builder /link_service /app/link_service
EXPOSE 7070
ENTRYPOINT ["/app/link_service"]
```

# 探索 CircleCI UI

CircleCI 有一个非常友好的 UI。在这里，您可以设置各种项目设置，探索您的构建，并深入到特定的构建中。请记住，我们使用了 monorepo 方法，并且在`build.sh`文件中，我们负责构建多个服务。从 CircleCI 的角度来看，Delinkcious 是一个单一的连贯项目。这是 Delinkcious 项目的视图，显示了最近的构建：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-msvc-k8s/img/9a97ae35-684e-46b5-a109-431a25306b59.png)

让我们深入研究一下成功的构建。一切都很好，一切都是绿色的：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-msvc-k8s/img/a41c4da5-4506-4b5d-b58b-ba086564d8e1.png)

您甚至可以展开任何步骤并检查控制台输出。这是测试阶段的输出：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-msvc-k8s/img/5aa9ea2b-c03b-4f08-9d2b-be6cb0ac69af.png)

这很酷，但当事情出错时，你需要弄清楚原因时，它甚至更有用。例如，有一次，我试图将`build.sh`脚本隐藏在`.circleci`目录中，紧挨着`config.yaml`文件，但它没有被添加到 Docker 上下文中，并产生了以下错误：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-msvc-k8s/img/517f725d-a032-41db-9dc5-8c68fbf28b44.png)

# 考虑未来的改进

Dockerfile 几乎是重复的，并且有一些可以参数化的假设。在 Kubernetes 生态系统中，有一些有趣的项目可以帮助解决这些问题。一些解决方案是用于本地开发的，可以自动生成必要的 Dockerfile，而其他一些则更加针对一致和统一的生产设置。我们将在后面的章节中研究其中一些。在本章中，我希望保持简单，避免用太多选项和间接层来压倒你。

另一个改进的机会是仅测试和构建已更改的服务（或其依赖项已更改）。目前，`build.sh` 脚本总是构建所有图像，并使用相同的标签对它们进行标记。

到目前为止，我们已经使用 CircleCI 和 Docker 构建了完整的 CI 管道。下一阶段是设置 Argo CD 作为持续交付管道。

# 为 Delinkcious 设置持续交付

在我们掌握了 CircleCI 中的持续集成之后，我们可以将注意力转向持续交付。首先，我们将看看将 Delinkcious 微服务部署到 Kubernetes 集群需要什么，然后我们将研究 Argo CD 本身，最后，我们将通过 Argo CD 为 Delinkcious 设置完整的持续交付。

# 部署 Delinkcious 微服务

每个 Delinkcious 微服务在其 `k8s` 子目录中定义了一组 Kubernetes 资源的 YAML 清单。这是 link 服务的 `k8s` 目录：

```
]$ tree k8s
k8s
├── db.yaml
└── link_manager.yaml
```

`link_manager.yaml` 文件包含两个资源：Kubernetes 部署和 Kubernetes 服务。Kubernetes 部署如下：

```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: link-manager
  labels:
    svc: link
    app: manager
spec:
  replicas: 1
  selector:
    matchLabels:
      svc: link
      app: manager
  template:
    metadata:
      labels:
        svc: link
        app: manager
    spec:
      containers:
      - name: link-manager
        image: g1g1/delinkcious-link:0.2
        ports:
        - containerPort: 8080
```

Kubernetes 服务如下：

```
apiVersion: v1
kind: Service
metadata:
  name: link-manager
spec:
  ports:
  - port:  8080
  selector:
    svc: link
    app: manager
```

`db.yaml` 文件描述了 link 服务用于持久化其状态的数据库。可以通过将 `k8s` 目录传递给 `kubectl apply` 来一次性部署两者：

```
$ kubectl apply -f k8s
deployment.apps "link-db" created
service "link-db" created
deployment.apps "link-manager" created
service "link-manager" created
```

kubectl create 和 `kubectl apply` 之间的主要区别是，如果资源已经存在，`create` 将返回错误。

使用 `kubectl` 从命令行部署很好，但我们的目标是自动化这个过程。让我们来了解一下。

# 理解 Argo CD

Argo CD 是 Kubernetes 的开源持续交付解决方案。它由 Intuit 创建，并被包括 Google、NVIDIA、Datadog 和 Adobe 在内的许多其他公司采用。它具有一系列令人印象深刻的功能，如下所示：

+   将应用程序自动部署到特定目标环境

+   CLI 和 Web 可视化应用程序以及所需状态和实际状态之间的差异

+   支持高级部署模式的钩子（蓝/绿和金丝雀）

+   支持多个配置管理工具（普通 YAML、ksonnet、kustomize、Helm 等）

+   对所有部署的应用程序进行持续监控

+   手动或自动将应用程序同步到所需状态

+   回滚到 Git 存储库中提交的任何应用程序状态

+   对应用程序的所有组件进行健康评估

+   SSO 集成

+   GitOps webhook integration (GitHub, GitLab, and BitBucket)

+   用于与 CI 流水线集成的服务帐户/访问密钥管理

+   应用事件和 API 调用的审计跟踪

# Argo CD 是建立在 Argo 上的

Argo CD 是一个专门的 CD 流水线，但它是建立在稳固的 Argo 工作流引擎之上的。我非常喜欢这种分层方法，您可以在这个坚实的通用基础上构建具有 CD 特定功能和能力的工作流程。

# Argo CD 利用 GitOps

Argo CD 遵循 GitOps 方法。基本原则是您系统的状态存储在 Git 中。Argo CD 通过检查 Git 差异并使用 Git 基元来回滚和协调实时状态，来管理您的实时状态与期望状态。

# 开始使用 Argo CD

Argo CD 遵循最佳实践，并期望在 Kubernetes 集群上的专用命名空间中安装：

```
$ kubectl create namespace argocd
$ kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml
```

让我们看看创建了什么。 Argo CD 安装了四种类型的对象：pod、service、deployment 和 replica set。以下是 pod：

```
$ kubectl get all -n argocd NAME                                        READY  STATUS RESTARTS  AGE
pod/argocd-application-controller-7c5cf86b76-2cp4z 1/1   Running  1  1m
pod/argocd-repo-server-74f4b4845-hxzw7             1/1   Running  0  1m
pod/argocd-server-9fc58bc5d-cjc95                  1/1   Running  0  1m
pod/dex-server-8fdd8bb69-7dlcj                     1/1   Running  0  1m
```

以下是服务：

```
NAME                                  TYPE        CLUSTER-IP       EXTERNAL-IP  PORT(S) 
service/argocd-application-controller ClusterIP   10.106.22.145    <none>       8083/TCP 
service/argocd-metrics                ClusterIP   10.104.1.83      <none>       8082/TCP 
service/argocd-repo-server            ClusterIP   10.99.83.118     <none>       8081/TCP 
service/argocd-server                 ClusterIP   10.103.35.4      <none>       80/TCP,443/TCP 
service/dex-server                    ClusterIP   10.110.209.247   <none>       5556/TCP,5557/TCP 
```

以下是部署：

```

NAME                                            DESIRED   CURRENT   UP-TO-DATE   AVAILABLE   AGE
deployment.apps/argocd-application-controller   1         1         1            1           1m
deployment.apps/argocd-repo-server              1         1         1            1           1m
deployment.apps/argocd-server                   1         1         1            1           1m
deployment.apps/dex-server                      1         1         1            1           1m

```

最后，以下是副本集：

```
NAME                                                       DESIRED   CURRENT   READY     AGE
replicaset.apps/argocd-application-controller-7c5cf86b76   1         1         1         1m
replicaset.apps/argocd-repo-server-74f4b4845               1         1         1         1m
replicaset.apps/argocd-server-9fc58bc5d                    1         1         1         1m
replicaset.apps/dex-server-8fdd8bb69                       1         1         1         1m
```

然而，Argo CD 还安装了两个**自定义资源定义**（**CRD**）：

```
$ kubectl get crd
NAME                       AGE
applications.argoproj.io   7d
appprojects.argoproj.io    7d
```

CRD 允许各种项目扩展 Kubernetes API 并添加自己的域对象，以及监视它们和其他 Kubernetes 资源的控制器。Argo CD 将应用程序和项目的概念添加到 Kubernetes 的世界中。很快，您将看到它们如何集成，以实现内置 Kubernetes 资源（如部署、服务和 pod）的持续交付目的。让我们开始吧：

1.  安装 Argo CD CLI：

```
$ brew install argoproj/tap/argocd
```

1.  端口转发以访问 Argo CD 服务器：

```
$ kubectl port-forward -n argocd svc/argocd-server 8080:443
```

1.  管理员用户的初始密码是 Argo CD 服务器的名称：

```
$ kubectl get pods -n argocd -l app.kubernetes.io/name=argocd-server -o name | cut -d'/' -f 2
```

1.  登录到服务器：

```
$ argocd login :8080
```

1.  如果它抱怨登录不安全，只需按*y*确认：

```
WARNING: server certificate had error: tls: either ServerName or InsecureSkipVerify must be specified in the tls.Config. Proceed insecurely (y/n)?
```

1.  或者，要跳过警告，请输入以下内容：

```
argocd login --insecure :8080
```

然后，您可以更改密码。

1.  如果您将密码存储在环境变量中（例如`ARGOCD_PASSWORD`），那么您可以使用一行命令登录，而无需进一步提问：

```
argocd login --insecure --username admin --password $ARGOCD_PASSWORD :8080
```

# 配置 Argo CD

记得端口转发到 argocd-server：

```
$ kubectl port-forward -n argocd svc/argocd-server 8080:443
```

然后，您只需浏览到`https://localhost:8080`并提供`admin`用户的密码即可登录：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-msvc-k8s/img/89af4578-32da-4ec6-8162-c853c128dd08.png)

配置 Argo CD 是一种乐趣。它的用户界面非常愉快且易于使用。它支持 Delinkcious monorepo，而且没有假设每个 Git 存储库只包含一个应用程序或项目。

它会要求您选择一个 Git 存储库以监视更改，一个 Kubernetes 集群（默认为安装在其上的集群），然后它将尝试检测存储库中的清单。Argo CD 支持多种清单格式和模板，例如 Helm、ksonnet 和 kustomize。我们将在本书的后面介绍其中一些优秀的工具。为了保持简单，我们已经为每个应用程序配置了包含其原始`k8s` YAML 清单的目录，Argo CD 也支持这些清单。

说到做到，Argo CD 已经准备就绪！

# 使用同步策略

默认情况下，Argo CD 会检测应用程序的清单是否不同步，但不会自动同步。这是一个很好的默认设置。在某些情况下，需要在专用环境中运行更多测试，然后再将更改推送到生产环境。在其他情况下，必须有人参与。然而，在许多其他情况下，可以立即自动部署更改到集群中，而无需人为干预。Argo CD 遵循 GitOps 的事实也使得非常容易将同步回任何先前的版本（包括最后一个）。

对于 Delinkcious，我选择了自动同步，因为它是一个演示项目，部署错误版本的后果是可以忽略不计的。这可以在 UI 中或从 CLI 中完成：

```
argocd app set <APPNAME> --sync-policy automated
```

自动同步策略不能保证应用程序始终处于同步状态。自动同步过程受到一些限制，具体如下：

+   处于错误状态的应用程序将不会尝试自动同步。

+   Argo CD 将仅针对特定提交 SHA 和参数尝试一次自动同步。

+   如果由于任何原因自动同步失败，它将不会再次尝试。

+   您无法使用自动同步回滚应用程序。

在所有这些情况下，您要么必须对清单进行更改以触发另一个自动同步，要么手动同步。要回滚（或者一般地，同步到先前的版本），您必须关闭自动同步。

Argo CD 在部署时提供了另一种修剪资源的策略。当现有资源不再存在于 Git 中时，默认情况下 Argo CD 不会将其删除。这是一种安全机制，用于避免在编辑 Kubernetes 清单时出现错误时破坏关键资源。但是，如果您知道自己在做什么（例如，对于无状态应用程序），您可以打开自动修剪：

```
argocd app set <APPNAME> --auto-prune
```

# 探索 Argo CD

现在我们已经登录并配置了 Argo CD，让我们稍微探索一下。我真的很喜欢 UI，但如果您想以编程方式访问它，也可以通过命令行或 REST API 完成所有操作。

我已经使用三个 Delinkcious 微服务配置了 Argo CD。在 Argo CD 中，每个服务都被视为一个应用程序。让我们来看看应用程序视图：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-msvc-k8s/img/df0184c7-6233-48e9-acdd-69818bdbef64.png)

这里有一些有趣的东西。让我们来谈谈每一个：

+   项目是用于分组应用程序的 Argo CD 概念。

+   命名空间是应用程序应安装的 Kubernetes 命名空间。

+   集群是 Kubernetes 集群，即`https://kubernetes.default.svc`，这是安装了 Argo CD 的集群。

+   状态告诉您当前应用程序是否与其 Git 存储库中的 YAML 清单同步。

+   健康状态告诉您应用程序是否正常。

+   存储库是应用程序的 Git 存储库。

+   路径是存储库中`k8s` YAML 清单所在的相对路径（Argo CD 监视此目录以进行更改）。

以下是您从`argocd` CLI 中获得的内容：

```
$ argocd app list
NAME                  CLUSTER                         NAMESPACE  PROJECT  STATUS     HEALTH   SYNCPOLICY  CONDITIONS
link-manager          https://kubernetes.default.svc  default    default  OutOfSync  Healthy  Auto-Prune  <none>
social-graph-manager  https://kubernetes.default.svc  default    default  Synced     Healthy  Auto-Prune  <none>
user-manager          https://kubernetes.default.svc  default    default  Synced     Healthy  Auto-Prune  <none>
```

正如您可以在 UI 和 CLI 中看到的那样，`link-manager`不同步。我们可以通过从“ACTIONS”下拉菜单中选择“同步”来同步它。

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-msvc-k8s/img/a502437e-8c5b-4674-8729-86ef2c59a169.png)

或者，您也可以从 CLI 中执行此操作：

```
$ argocd app sync link-manager
```

UI 最酷的地方之一是它如何呈现与应用程序相关的所有`k8s`资源。点击`social-graph-manager`应用程序，我们会得到以下视图：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-msvc-k8s/img/82b4007d-977f-4a44-99fb-04fcfe418ba2.png)

我们可以看到应用程序本身、服务、部署和 Pod，包括运行的 Pod 数量。这实际上是一个经过筛选的视图，如果我们愿意，我们可以将与每个部署相关的副本集和每个服务的端点添加到显示中。但是，大多数情况下这些都不是很有趣，因此 Argo CD 默认不显示它们。

我们可以点击一个服务，查看其信息的摘要，包括清单：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-msvc-k8s/img/aa33e5a2-434f-41e1-a431-0f1b81e471e9.png)

对于 Pods，我们甚至可以检查日志，如下面的截图所示，所有这些都可以在 Argo CD 的 UI 中轻松完成：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-msvc-k8s/img/a3d9eeff-e579-4f2f-ac1f-48bcb964819a.png)

Argo CD 已经可以带您走很远。然而，它还有更多的提供，我们将在本书的后面深入探讨这些内容。

# 总结

在本章中，我们讨论了基于微服务的分布式系统的 CI/CD 流水线的重要性。我们审查了一些针对 Kubernetes 的 CI/CD 选项，并确定了使用 CircleCI 进行 CI 部分（代码更改|Docker 镜像）和 Argo CD 进行 CD 部分（`k8s`清单更改|部署的应用程序）的组合。

我们还介绍了使用多阶段构建构建 Docker 镜像的最佳实践，Postgres DB 的`k8s` YAML 清单，以及部署和服务`k8s`资源。然后，我们在集群中安装了 Argo CD，配置它来构建所有我们的微服务，并探索了 UI 和 CLI。在这一点上，您应该对 CI/CD 的概念以及其重要性有清晰的理解，各种解决方案的利弊以及如何为您的系统选择最佳选项。

然而，还有更多内容。在后面的章节中，我们将通过额外的测试、安全检查和高级多环境部署选项来改进我们的 CI/CD 流水线。

在下一章中，我们将把注意力转向配置我们的服务。配置是开发复杂系统的重要部分，需要大型团队开发、测试和部署。我们将探讨各种传统配置选项，如命令行参数、环境变量和配置文件，以及更动态的配置选项和 Kubernetes 的特殊配置功能。

# 进一步阅读

您可以参考以下来源，了解本章涵盖的更多信息：

+   以下是一些扩展您对 Kubernetes 上 CI/CD 选项的了解的好资源。首先，这是我用于 Delinkcious CI/CD 解决方案的两个项目：

+   **CircleCI**: [`circleci.com/docs/`](https://circleci.com/docs/)

+   **Argo**: [`argoproj.github.io/docs/argo-cd/docs/`](https://argoproj.github.io/docs/argo-cd/docs/)

+   然后，还有这本关于 Kubernetes 的 CI/CD 的免费迷你电子书：

+   [`thenewstack.io/ebooks/kubernetes/ci-cd-with-kubernetes/`](https://thenewstack.io/ebooks/kubernetes/ci-cd-with-kubernetes/)

+   最后，这里有一些我在 Delinkcious 中放弃的其他选项，但可能对你来说是一个不错的选择：

+   Jenkins X: [`jenkins-x.io/`](https://jenkins-x.io/)

+   Spinnaker: [`www.spinnaker.io/`](https://www.spinnaker.io/)


# 第五章：使用 Kubernetes 配置微服务

在本章中，我们将进入微服务配置的实际和现实世界领域。配置是构建复杂分布式系统的重要组成部分。一般来说，配置涉及代码应该意识到的系统的任何方面，但并未编码在代码本身中。以下是本章将讨论的主题：

+   配置到底是什么？

+   以老式方式管理配置

+   动态管理配置

+   使用 Kubernetes 配置微服务

在本章结束时，您将对配置的价值有扎实的了解。您还将学会静态和动态配置软件的许多方法，以及 Kubernetes 提供的特殊配置选项（其中之一是其最佳功能）。您还将获得洞察力和知识，以从 Kubernetes 作为开发人员和运营商提供的灵活性和控制中受益。

# 技术要求

在本章中，我们将查看许多 Kubernetes 清单，并扩展 Delinkcious 的功能。不需要安装任何新东西。

# 代码

像往常一样，代码分为两个 Git 存储库：

+   您可以在[`github.com/PacktPublishing/Hands-On-Microservices-with-Kubernetes/tree/master/Chapter05`](https://github.com/PacktPublishing/Hands-On-Microservices-with-Kubernetes/tree/master/Chapter05)找到代码示例

+   您可以在[`github.com/the-gigi/delinkcious/releases/tag/v0.3`](https://github.com/the-gigi/delinkcious/releases/tag/v0.3)找到更新的 Delinkcious 应用程序

# 配置到底是什么？

配置是一个非常重载的术语。让我们为我们的目的清晰地定义它：配置主要是指计算所需的操作数据。配置可能在不同的环境之间有所不同。以下是一些典型的配置项：

+   服务发现

+   支持测试

+   特定于环境的元数据

+   秘密

+   第三方配置

+   功能标志

+   超时

+   速率限制

+   各种默认值

通常，处理输入数据的代码利用配置数据来控制计算的操作方面，而不是算法方面。有一些特殊情况，通过配置，您可以在运行时在不同的算法之间切换，但这已经涉及到灰色地带。让我们为我们的目的保持简单。

在考虑配置时，重要的是要考虑谁应该创建和更新配置数据。可能是代码的开发者，也可能不是。例如，速率限制可能由 DevOps 团队成员确定，但功能标志将由开发人员设置。此外，在不同的环境中，不同的人可能修改相同的值。通常在生产中会有最严格的限制。

# 配置和秘密

秘密是用于访问数据库和其他服务（内部和/或外部）的凭据。从技术上讲，它们是配置数据，但实际上，由于它们的敏感性，它们经常需要在静止时加密并进行更严格的控制。通常会将秘密存储和单独管理，而不是与常规配置分开。

在本章中，我们只考虑非敏感配置。在下一章中，我们将详细讨论秘密。Kubernetes 还在 API 级别将配置与秘密分开。

# 以老式方式管理配置

当我说老式方式时，我的意思是在 Kubernetes 之前的静态配置。但正如您将看到的，老式方式有时是最好的方式，而且通常也得到 Kubernetes 的良好支持。让我们来看看配置程序的各种方式，考虑它们的优缺点，以及何时适用。我们将在这里介绍的配置机制如下：

+   无配置（约定优于配置）

+   命令行参数

+   环境变量

+   配置文件

Delinkcious 主要是用 Go 实现的，但我们将使用不同的编程语言来演示配置选项，只是为了好玩和多样性。

# 约定优于配置

有时，您实际上不需要配置；程序可以只做出一些决定，对其进行文档记录，就这样。例如，输出文件的目录名称可以是可配置的，但程序可以决定它将*输出*，就这样。这种方法的好处是非常可预测的：您不必考虑配置，只需通过阅读程序代码，就可以准确知道它的功能和一切应该在哪里。运营商的工作量很少。缺点是，如果需要更多的灵活性，您就没有办法（例如，可能程序运行的卷上没有足够的空间）。

请注意，约定优于配置并不意味着根本没有配置。这意味着在使用约定时可以减少配置的数量。

这是一个小的 Rust 程序，它将斐波那契序列打印到屏幕上，直到 100。按照约定，它决定不会超过 100。您无法配置它以打印更多或更少的数字而不改变代码：

```
fn main() {
    let mut a: u8 = 0;
    let mut b: u8 = 1;
    println!("{}", a);
    while b <= 100 {
        println!("{}", b);
        b = a + b;
        a = b - a;
    }
}

Output:

0
1
1
2
3
5
8
13
21
34
55
89
```

# 命令行标志

命令行标志或参数是编程的重要组成部分。运行程序时，您提供参数，程序使用这些参数来配置自身。使用它们有利有弊：

+   **优点**：

+   非常灵活

+   熟悉并且在每种编程语言中都可用

+   有关短选项和长选项的最佳实践已经建立

+   与交互式使用文档配合良好

+   **缺点**：

+   参数始终是字符串

+   需要引用包含空格的参数

+   难以处理多行参数

+   命令行参数的数量限制

+   每个参数的大小限制

命令行参数通常用于输入以及配置。输入和配置之间的界限有时可能有点模糊。在大多数情况下，这并不重要，但对于只想通过命令行参数将其输入传递给程序的用户来说，这可能会让他们感到困惑，因为他们会看到一大堆令人困惑的配置选项。

这是一个小的 Ruby 程序，它将斐波那契序列写入到一个作为命令行参数提供的数字。

```
if __FILE__ == $0
  limit = Integer(ARGV[0])
  a = 0
  b = 1
  puts a
  while b < limit
    puts b
    b = a + b
    a = b - a
  end
end
```

# 环境变量

环境变量是另一个受欢迎的选项。当您的程序在可能由另一个程序（或 shell 脚本）设置的环境中运行时，它们非常有用。环境变量通常从父环境继承。它们还用于运行交互式程序，当用户总是希望向程序提供相同的选项（或一组选项）时。与其一遍又一遍地输入带有相同选项的长命令行，不如设置一个环境变量（甚至可能在您的配置文件中）一次，然后无需参数运行程序。一个很好的例子是 AWS CLI，它允许您将许多配置选项指定为环境变量（例如，`AWS_DEFAULT_REGION`或`AWS_PROFILE`）。

这里有一个小的 Python 程序，它会写出斐波那契数列，直到一个作为环境变量提供的数字。请注意，`FIB_LIMIT`环境变量被读取为字符串，程序必须将其转换为整数。

```
import os

limit = int(os.environ['FIB_LIMIT'])
a = 0
b = 1
print(a)
while b < limit:
    print(b)
    b = a + b
    a = b - a
```

# 配置文件

配置文件在有大量配置数据时特别有用，尤其是当这些数据具有分层结构时。在大多数情况下，通过命令行参数或环境变量配置应用程序的选项太过于繁琐。配置文件还有另一个优点，就是可以链接多个配置文件。通常，应用程序会在搜索路径中查找配置文件，例如`/etc/conf`，然后是`home`目录，然后是当前目录。这提供了很大的灵活性，因为您可以拥有通用配置，同时还能够覆盖某些用户或运行时的部分配置。

配置文件非常棒！您应该考虑哪种格式最适合您的用例。有很多选择。配置文件格式会遵循趋势，每隔几年就会有新的亮点。让我们回顾一些旧格式，以及一些新格式。

# INI 格式

INI 文件曾经在 Windows 上非常流行。INI 代表**初始化**。在八十年代，瞎折腾`windows.ini`和`system.ini`以使某些东西工作是非常常见的。格式本身非常简单，包括带有键-值对和注释的部分。这是一个简单的 INI 文件：

```
[section]
a=1
b=2

; here is a comment
[another_section]
c=3
d=4
e=5
```

Windows API 有用于读取和写入 INI 文件的函数，因此许多 Windows 应用程序将它们用作配置文件。

# XML 格式

XML ([`www.w3.org/XML/`](https://www.w3.org/XML/))是 W3C 标准，在九十年代非常流行。它代表**可扩展标记语言**，用于*一切*：数据，文档，API（SOAP），当然还有配置文件。它非常冗长，它的主要特点是自我描述并包含自己的元数据。XML 有模式和许多建立在其之上的标准。有一段时间，人们认为它会取代 HTML（还记得 XHTML 吗？）。那都是过去了。这是一个样本 XML 配置文件：

```
<?xml version="1.0" encoding="UTF-8"?>
    <startminimized value="False">
  <width value="1024">
  <height value = "768">
  <dummy />
  <plugin>
    <name value="Show Warning Message Box">
    <dllfile value="foo.dll">
    <method value = "warning">
  </plugin>
  <plugin>
    <name value="Show Error Message Box">
    <dllfile value="foo.dll">
    <method value = "error">
  </plugin>
  <plugin>
    <name value="Get Random Number">
    <dllfile value="bar.dll">
        <method value = "random">
  </plugin>
</xml>
```

# JSON 格式

JSON（[`json.org/`](https://json.org/)）代表**JavaScript 对象表示法**。随着动态网络应用和 REST API 的增长，它变得越来越受欢迎。与 XML 相比，它的简洁性让人耳目一新，并迅速占领了行业。它的成名之处在于它可以一对一地转换为 JavaScript 对象。这是一个简单的 JSON 文件：

```
{
  "firstName": "John",
  "lastName": "Smith",
  "age": 25,
  "address": {
    "streetAddress": "21 2nd Street",
    "city": "New York",
    "state": "NY",
    "postalCode": "10021"
  },
  "phoneNumber": [
    {
      "type": "home",
      "number": "212 555-1234"
    },
    {
      "type": "fax",
      "number": "646 555-4567"
    }
  ],
  "gender": {
    "type": "male"
  }
}
```

我个人从来不喜欢 JSON 作为配置文件格式；它不支持注释，对数组末尾的额外逗号要求过于严格，将日期和时间序列化为 JSON 总是很麻烦。它也非常冗长，需要用引号、括号，并且需要转义许多字符（尽管它不像 XML 那样糟糕）。

# YAML 格式

你在本书中已经看到了很多 YAML（[`yaml.org/`](https://yaml.org/)），因为 Kubernetes 清单通常是以 YAML 编写的。YAML 是 JSON 的超集，但它还提供了一个更简洁的语法，非常易于阅读，以及更多的功能，比如引用、类型的自动检测和对齐多行值的支持。

这是一个具有比通常在普通 Kubernetes 清单中看到的更多花哨功能的 YAML 文件的示例：

```
# sequencer protocols for Laser eye surgery
---
- step:  &id001                  # defines anchor label &id001
    instrument:      Lasik 3000
    pulseEnergy:     5.4
    pulseDuration:   12
    repetition:      1000
    spotSize:        1mm

- step: &id002
    instrument:      Lasik 3000
    pulseEnergy:     5.0
    pulseDuration:   10
    repetition:      500
    spotSize:        2mm
- step: *id001                   # refers to the first step (with anchor &id001)
- step: *id002                   # refers to the second step
- step:
    <<: *id001
    spotSize: 2mm                # redefines just this key, refers rest from &id001
- step: *id002
```

YAML 不像 JSON 那样受欢迎，但它慢慢地积聚了动力。像 Kubernetes 和 AWS CloudFormation 这样的大型项目使用 YAML（以及 JSON，因为它是超集）作为它们的配置格式。CloudFormation 后来添加了对 YAML 的支持；Kubernetes 从 YAML 开始。

它目前是我最喜欢的配置文件格式；然而，YAML 有它的陷阱和批评，特别是当你使用一些更高级的功能时。

# TOML 格式

进入 TOML（[`github.com/toml-lang/toml`](https://github.com/toml-lang/toml)）—**Tom's Obvious Minimal Language**。TOML 就像是增强版的 INI 文件。它是所有格式中最不为人知的，但自从被 Rust 的包管理器 Cargo 使用以来，它开始获得动力。TOML 在表现形式上介于 JSON 和 YAML 之间。它支持自动检测的数据类型和注释，但它不像 YAML 那样强大。尽管如此，它是最容易被人类阅读和编写的。它支持嵌套，主要是通过点符号而不是缩进。

这是一个 TOML 文件的示例；看看它有多可读：

```
# This is how to comment in TOML.

title = "A TOML Example"

[owner]
name = "Gigi Sayfan"
dob = 1968-09-28T07:32:00-08:00 # First class dates

# Simple section with various data types
[kubernetes]
api_server = "192.168.1.1"
ports = [ 80, 443 ]
connection_max = 5000
enabled = true

# Nested section
[servers]

  # Indentation (tabs and/or spaces) is optional
  [servers.alpha]
  ip = "10.0.0.1"
  dc = "dc-1"

  [servers.beta]
  ip = "10.0.0.2"
  dc = "dc-2"

[clients]
data = [ ["gamma", "delta"], [1, 2] ]

# Line breaks are OK when inside arrays
hosts = [
  "alpha",
  "omega"
]
```

# 专有格式

一些应用程序只是提出了自己的格式。这是一个 Nginx web 服务器的示例配置文件：

```
user       www www;  ## Default: nobody
worker_processes  5;  ## Default: 1
error_log  logs/error.log;
pid        logs/nginx.pid;
worker_rlimit_nofile 8192;

events {
  worker_connections  4096;  ## Default: 1024
}

http {
  include    conf/mime.types;
  include    /etc/nginx/proxy.conf;
  include    /etc/nginx/fastcgi.conf;
  index    index.html index.htm index.php;

  default_type application/octet-stream;
  log_format   main '$remote_addr - $remote_user [$time_local]  $status '
    '"$request" $body_bytes_sent "$http_referer" '
    '"$http_user_agent" "$http_x_forwarded_for"';
  access_log   logs/access.log  main;
  sendfile     on;
  tcp_nopush   on;
  server_names_hash_bucket_size 128; # this seems to be required for some vhosts

  server { # php/fastcgi
    listen       80;
    server_name  domain1.com www.domain1.com;
    access_log   logs/domain1.access.log  main;
    root         html;

    location ~ \.php$ {
      fastcgi_pass   127.0.0.1:1025;
    }
  }
}
```

我不建议为您的应用程序发明另一个构思不周的配置格式。在 JSON、YAML 和 TOML 之间，您应该找到表达性、人类可读性和熟悉度之间的平衡点。此外，所有语言都有库来解析和组合这些熟悉的格式。

不要发明自己的配置格式！

# 混合配置和默认值

到目前为止，我们已经审查了主要的配置机制：

+   约定优于配置

+   命令行参数

+   环境变量

+   配置文件

这些机制并不是互斥的。许多应用程序将支持其中一些，甚至全部。很多时候，会有一个配置解析机制，其中配置文件有一个标准的名称和位置，但您仍然可以通过环境变量指定不同的配置文件，并且甚至可以通过命令行参数为特定运行覆盖甚至那个。你不必走得太远。Kubectl 是一个程序，默认情况下在`$HOME/.kube`中查找其配置文件；您可以通过`KUBECONFIG`环境变量指定不同的文件。您可以通过传递`--config`命令行标志为特定命令指定特殊的配置文件。

说到这一点，kubectl 也使用 YAML 作为其配置格式。这是我的 Minikube 配置文件：

```
$ cat ~/.kube/config
apiVersion: v1
clusters:
- cluster:
 certificate-authority: /Users/gigi.sayfan/.minikube/ca.crt
 server: https://192.168.99.121:8443
 name: minikube
contexts:
- context:
 cluster: minikube
 user: minikube
 name: minikube
current-context: minikube
kind: Config
preferences: {}
users:
- name: minikube
 user:
 client-certificate: /Users/gigi.sayfan/.minikube/client.crt
 client-key: /Users/gigi.sayfan/.minikube/client.key
```

Kubectl 支持在同一配置文件中的多个集群/上下文。您可以通过`kubectl use-context`在它们之间切换；然而，许多经常使用多个集群的人不喜欢将它们全部放在同一个配置文件中，而更喜欢为每个集群单独创建一个文件，然后通过`KUBECONFIG`环境变量或通过命令行传递`--config`来在它们之间切换。

# 十二要素应用程序配置

Heroku 是云平台即服务的先驱之一。2011 年，他们发布了用于构建 Web 应用程序的 12 要素方法论。这是一个相当坚实的方法，并且在当时非常创新。它也恰好是在 Heroku 上轻松部署应用程序的最佳方式。

对于我们的目的，他们网站最有趣的部分是配置部分，可以在[`12factor.net/config`](https://12factor.net/config)找到。

简而言之，他们建议 Web 服务和应用程序始终将配置存储在环境变量中。这是一个安全但有些有限的指导方针。这意味着每当配置更改时，服务都必须重新启动，并且受到环境变量的一般限制。

稍后，我们将看到 Kubernetes 如何支持将配置作为环境变量和配置文件，以及一些特殊的变化。但首先，让我们讨论动态配置。

# 动态管理配置

到目前为止，我们讨论的配置选项都是静态的。你必须重新启动，并且在某些情况下（比如使用嵌入式配置文件），重新部署你的服务来改变它的配置。当配置改变时重新启动服务的好处是你不必担心新配置对内存状态和正在处理的请求的影响，因为你是从头开始的；然而，缺点是你会失去所有正在处理的请求（除非你使用优雅关闭）和任何已经预热的缓存或一次性初始化工作，这可能是相当大的。然而，你可以通过使用滚动更新和蓝绿部署来在一定程度上减轻这种情况。

# 理解动态配置

动态配置意味着服务保持运行，代码和内存状态保持不变，但它可以检测到配置已经改变，并根据新的配置动态调整其行为。从操作员的角度来看，当配置需要改变时，他们只需更新中央配置存储，而不需要强制重新启动/部署代码未改变的服务。

重要的是要理解这不是一个二元选择；一些配置可能是静态的，当它改变时，你必须重新启动服务，但其他一些配置项可能是动态的。

由于动态配置可以改变系统的行为方式，这种改变无法通过源代码控制来捕捉，因此保留更改历史和审计是一个常见的做法。让我们看看什么时候应该使用动态配置，什么时候不应该使用！

# 动态配置何时有用？

动态配置在以下情况下很有用：

+   如果你只有一个服务实例，那么重新启动意味着短暂的中断

+   如果您有要快速切换的功能标志

+   如果您的服务需要初始化或丢弃正在进行中的请求是昂贵的

+   如果您的服务不支持高级部署策略，例如滚动更新，蓝绿色或金丝雀部署

+   重新部署时，新的配置文件可能会从源代码控制中拉取未准备好部署的不相关代码更改

# 何时应避免动态配置？

然而，动态配置并非适用于所有情况。如果您想要完全安全，那么在配置更改时重新启动服务会使事情更容易理解和分析。也就是说，微服务通常足够简单，您可以理解配置更改的所有影响。

在以下情况下，最好避免动态配置：

+   受监管的服务，配置更改必须经过审查和批准流程

+   关键服务，静态配置的低风险胜过动态配置的任何好处

+   动态配置机制不存在，而且好处不足以证明开发这样的机制是合理的

+   现有系统具有大量服务，迁移到动态配置的好处不足以证明成本

+   高级部署策略提供了动态配置的好处，静态配置和重新启动/重新部署

+   跟踪和审计配置更改的复杂性太高

# 远程配置存储

动态配置的一个选项是远程配置存储。所有服务实例可以定期查询配置存储，检查配置是否已更改，并在更改时读取新配置。可能的选项包括以下内容：

+   关系数据库（Postgres，MySQL）

+   键-值存储（Etcd，Redis）

+   共享文件系统（NFS，EFS）

总的来说，如果您的所有/大多数服务已经使用特定类型的存储，通常将动态配置放在那里会更简单。反模式是将配置存储在与服务持久存储相同的存储中。问题在于配置将分布在多个数据存储中，而且一些配置更改是中心化的。跨所有服务管理、跟踪和审计配置更改将会很困难。

# 远程配置服务

更高级的方法是创建一个专门的配置服务。此服务的目的是为所有配置需求提供一站式服务。每个服务将仅访问其配置，并且很容易为每个配置更改实现控制机制。配置服务的缺点是您需要构建它并进行维护。如果不小心的话，它也可能成为**单点故障**（SPOF）。

到目前为止，我们已经非常详细地介绍了系统配置的许多选项。现在，是时候研究一下 Kubernetes 带来了什么了。

# 使用 Kubernetes 配置微服务

使用 Kubernetes 或任何容器编排器，您有各种有趣的配置选项。Kubernetes 为您运行容器。无法为特定运行设置不同的环境选项和命令行参数，因为 Kubernetes 决定何时何地运行容器。您可以将配置文件嵌入到 Docker 镜像中或更改其运行的命令；但是，这意味着为每个配置更改烘烤新镜像并将其部署到集群中。这并不是世界末日，但这是一个繁重的操作。您还可以使用我之前提到的动态配置选项：

+   远程配置存储

+   远程配置服务

但是，当涉及到动态配置时，Kubernetes 有一些非常巧妙的技巧。最创新的动态配置机制是 ConfigMaps。您还可以使用自定义资源更加复杂。让我们深入了解一下。

# 使用 Kubernetes ConfigMaps

ConfigMaps 是由 Kubernetes 每个命名空间管理的 Kubernetes 资源，并且可以被任何 pod 或容器引用。这是`link-manager`服务的 ConfigMap：

```
apiVersion: v1
kind: ConfigMap
metadata:
  name: link-service-config
  namespace: default
data:
  MAX_LINKS_PER_USER: "10"
  PORT: "8080"
```

`link-manager`部署资源通过使用`envFrom`键将其导入到 pod 中：

```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: link-manager
  labels:
    svc: link
    app: manager
spec:
  replicas: 1
  selector:
    matchLabels:
      svc: link
      app: manager
  template:
    metadata:
      labels:
        svc: link
        app: manager
    spec:
      containers:
      - name: link-manager
        image: g1g1/delinkcious-link:0.2
        ports:
        - containerPort: 8080
      envFrom:
      - configMapRef:
          name: link-manager-config
```

这样做的效果是，当`link-manager`服务运行时，ConfigMap 的`data`部分中的键值对将被投影为环境变量：

```
MAX_LINKS_PER_PAGE=10
PORT=9090
```

让我们看看 Argo CD 如何可视化`link-manager`服务具有 ConfigMap。请注意名为`link-service-config`的顶部框：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-msvc-k8s/img/b71de303-e97d-4664-a197-b5c73ba0ac54.png)

您甚至可以通过单击 ConfigMap 框从 Argo CD UI 中深入检查 ConfigMap 本身。非常漂亮。

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-msvc-k8s/img/9bb535b3-a36d-4b39-ac03-0f0f9932b31a.png)

请注意，由于 ConfigMap 作为环境变量被消耗，这是静态配置。如果你想改变其中任何内容，你需要重新启动服务。在 Kubernetes 中，可以通过几种方式来实现：

+   杀死 pod（部署的副本集将创建新的 pod）

+   删除并重新创建部署（这有相同的效果，但不需要显式杀死 pod）

+   应用其他更改并重新部署

让我们看看代码如何使用它。这段代码可以在[svc/link_manager/service/link_manager_service.go](https://github.com/the-gigi/delinkcious/blob/14c91f1c675dea9729d80876a3798897b925712a/svc/link_service/service/link_service.go#L37)找到：

```
port := os.Getenv("PORT")
if port == "" {
   port = "8080"
}

maxLinksPerUserStr := os.Getenv("MAX_LINKS_PER_USER")
if maxLinksPerUserStr == "" {
   maxLinksPerUserStr = "10"
}
```

`os.Getenv()`标准库函数从环境中获取`PORT`和`MAX_LINKS_PER_USER`。这很棒，因为它允许我们在 Kubernetes 集群之外测试服务，并正确配置它。例如，链接服务端到端测试——专为 Kubernetes 之外的本地测试设计——在启动社交图管理器和`link-manager`服务之前设置环境变量：

```
func runLinkService(ctx context.Context) {
   // Set environment
   err := os.Setenv("PORT", "8080")
   check(err)

   err = os.Setenv("MAX_LINKS_PER_USER", "10")
   check(err)

   runService(ctx, ".", "link_service")
}

func runSocialGraphService(ctx context.Context) {
   err := os.Setenv("PORT", "9090")
   check(err)

   runService(ctx, "../social_graph_service", "social_graph_service")
}
```

现在我们已经看过 Delinkcious 如何使用 ConfigMaps，让我们继续进行 ConfigMaps 的工作细节。

# 创建和管理 ConfigMaps

Kubernetes 提供了多种创建 ConfigMaps 的方法：

+   从命令行值

+   从一个或多个文件

+   从整个目录

+   通过直接创建 ConfigMap YAML 清单

最后，所有的 ConfigMaps 都是一组键值对。键和值取决于创建 ConfigMap 的方法。在玩 ConfigMaps 时，我发现使用`--dry-run`标志很有用，这样我就可以在实际创建之前看到将要创建的 ConfigMap。让我们看一些例子。以下是如何从命令行参数创建 ConfigMap：

```
$ kubectl create configmap test --dry-run --from-literal=a=1 --from-literal=b=2 -o yaml
apiVersion: v1
data:
 a: "1"
 b: "2"
kind: ConfigMap
metadata:
 creationTimestamp: null
 name: test
```

这种方法主要用于玩转 ConfigMaps。您必须使用繁琐的`--from-literal`参数逐个指定每个配置项。

从文件创建 ConfigMap 是一种更可行的方法。它与 GitOps 概念很好地配合，您可以保留用于创建 ConfigMaps 的源配置文件的历史记录。我们可以创建一个非常简单的名为`comics.yaml`的 YAML 文件：

```
superhero: Doctor Strange
villain: Thanos
```

接下来，让我们使用以下命令从这个文件创建一个 ConfigMap（好吧，只是一个干燥的`run`）：

```
$ kubectl create configmap file-config --dry-run --from-file comics.yaml -o yaml

apiVersion: v1
data:
 comics.yaml: |+
 superhero: Doctor Strange
 villain: Thanos

kind: ConfigMap
metadata:
 creationTimestamp: null
 name: file-config
```

有趣的是，文件的整个内容都映射到一个键：`comics.yaml`。值是文件的整个内容。在 YAML 中，`|+`表示以下的多行块是一个值。如果我们添加额外的`--from-file`参数，那么每个文件将在 ConfigMap 中有自己的键。同样，如果`--from-file`的参数是一个目录，那么目录中的每个文件都将成为 ConfigMap 中的一个键。

最后，让我们看一个手动构建的 ConfigMap。这并不难做到：只需在`data`部分下添加一堆键值对即可：

```
apiVersion: v1
kind: ConfigMap
metadata:
  name: env-config
  namespace: default
data:
  SUPERHERO: Superman
  VILLAIN: Lex Luthor
```

在这里，我们创建了专门的`SUPERHERO`和`VILLAIN`键。

让我们看看 pod 如何消耗这些 ConfigMap。pod 从`env-config` ConfigMap 中获取其环境。它执行一个命令，监视`SUPERHERO`和`VILLAIN`环境变量的值，并且每两秒钟回显当前值：

```
apiVersion: v1
kind: Pod
metadata:
  name: some-pod
spec:
  containers:
  - name: some-container
    image: busybox
    command: [ "/bin/sh", "-c", "watch 'echo \"superhero: $SUPERHERO villain: $VILLAIN\"'" ]
    envFrom:
    - configMapRef:
        name: env-config
  restartPolicy: Never
```

必须在启动 pod 之前创建 ConfigMap！

```
$ kubectl create -f env-config.yaml
configmap "env-config" created

$ kubectl create -f some-pod.yaml
pod "some-pod" created
```

kubectl 命令非常有用，可以用来检查输出：

```
$ kubectl logs -f some-pod

Every 2s: echo "superhero: $SUPERHERO villain: $VILLAIN"      2019-02-08 20:50:39

superhero: Superman villain: Lex Luthor
```

如预期的那样，值与 ConfigMap 匹配。但是如果我们更改 ConfigMap 会发生什么呢？`kubectl edit configmap`命令允许您在编辑器中更新现有的 ConfigMap：

```
$ kubectl edit configmap env-config

# Please edit the object below. Lines beginning with a '#' will be ignored,
# and an empty file will abort the edit. If an error occurs while saving this file will be
# reopened with the relevant failures.
#
apiVersion: v1
data:
 SUPERHERO: Batman
 VILLAIN: Joker
kind: ConfigMap
metadata:
 creationTimestamp: 2019-02-08T20:49:37Z
 name: env-config
 namespace: default
 resourceVersion: "874765"
 selfLink: /api/v1/namespaces/default/configmaps/env-config
 uid: 0c83dee5-2be3-11e9-9999-0800275914a6

configmap "env-config" edited
```

我们已经将超级英雄和反派更改为 Batman 和 Joker。让我们验证一下更改：

```
$ kubectl get configmap env-config -o yaml

apiVersion: v1
data:
 SUPERHERO: Batman
 VILLAIN: Joker
kind: ConfigMap
metadata:
 creationTimestamp: 2019-02-08T20:49:37Z
 name: env-config
 namespace: default
 resourceVersion: "875323"
 selfLink: /api/v1/namespaces/default/configmaps/env-config
 uid: 0c83dee5-2be3-11e9-9999-0800275914a6
```

新的值已经存在。让我们检查一下 pod 日志。什么都不应该改变，因为 pod 将 ConfigMap 作为环境变量消耗，而在 pod 运行时无法从外部更改：

```
$ kubectl logs -f some-pod

Every 2s: echo "superhero: $SUPERHERO villain: $VILLAIN"    2019-02-08 20:59:22

superhero: Superman villain: Lex Luthor
```

然而，如果我们删除并重新创建 pod，情况就不同了：

```
$ kubectl delete -f some-pod.yaml
pod "some-pod" deleted

$ kubectl create -f some-pod.yaml
pod "some-pod" created

$ kubectl logs -f some-pod

Every 2s: echo "superhero: $SUPERHERO villain: $VILLAIN" 2019-02-08 21:45:47

superhero: Batman villain: Joker
```

我把最好的留到了最后。让我们看看一些动态配置的实际操作。名为`some-other-pod`的 pod 正在将名为`file-config`的 ConfigMap 作为文件进行消耗。首先，它创建了一个名为`config-volume`的卷，该卷从`file-config` ConfigMap 中获取数据。然后，这个卷被挂载到`/etc/config`中。正在运行的命令只是简单地监视`/etc/config/comics`文件：

```
apiVersion: v1
kind: Pod
metadata:
  name: some-other-pod
spec:
  containers:
  - name: some-container
    image: busybox
    command: [ "/bin/sh", "-c", "watch \"cat /etc/config/comics\"" ]
    volumeMounts:
    - name: config-volume
      mountPath: /etc/config
  volumes:
  - name: config-volume
    configMap:
      name: file-config
  restartPolicy: Never
```

这是`file-config` ConfigMap：

```
apiVersion: v1
kind: ConfigMap
metadata:
  name: file-config
  namespace: default
data:
  comics: |+
    superhero: Doctor Strange
    villain: Thanos
```

它有一个名为`comics`（文件名）的键，值是一个多行的 YAML 字符串，其中包含超级英雄和反派条目（`Doctor Strange`和`Thanos`）。说到做到，ConfigMap `data`部分下的 comics 键的内容将被挂载到容器中作为`/etc/config/comics`文件。

让我们验证一下：

```
$ kubectl create -f file-config.yaml
configmap "file-config" created

$ kubectl create -f some-other-pod.yaml
pod "some-other-pod" created

$ kubectl logs -f some-other-pod

Every 2s: cat /etc/config/comics      2019-02-08 22:15:08

superhero: Doctor Strange
villain: Thanos
```

到目前为止，一切看起来都很好。现在是主要的吸引力。让我们将 ConfigMap 的内容更改为超级英雄神奇女侠和反派美杜莎。这次我们将使用`kubectl apply`命令，而不是删除和重新创建 ConfigMap。ConfigMap 被正确更新，但我们也会收到一个警告（可以忽略）：

```
$ kubectl apply -f file-config.yaml
Warning: kubectl apply should be used on resource created by either kubectl create --save-config or kubectl apply
configmap "file-config" configured

$ kubectl get configmap file-config -o yaml
apiVersion: v1
data:
 comics: |+
 superhero: Super Woman
 villain: Medusa

kind: ConfigMap
metadata:
 annotations:
 kubectl.kubernetes.io/last-applied-configuration: |
 {"apiVersion":"v1","data":{"comics":"superhero: Super Woman\nvillain: Medusa\n\n"},"kind":"ConfigMap","metadata":{"annotations":{},"name":"file-config","namespace":"default"}}
 creationTimestamp: 2019-02-08T22:14:01Z
 name: file-config
 namespace: default
 resourceVersion: "881662"
 selfLink: /api/v1/namespaces/default/configmaps/file-config
 uid: d6e892f4-2bee-11e9-9999-0800275914a6
```

请注意前面的注释。有趣的是，它存储了最后一次应用的更改，这在数据中是可用的，而不是以前的值用于历史上下文。

现在，让我们再次检查日志，而不重新启动 pod！

```
$ kubectl logs -f some-other-pod

Every 2s: cat /etc/config/comics     2019-02-08 23:02:58

superhero: Super Woman
villain: Medusa
```

是的，这是一个巨大的成功！现在 pod 打印出了更新的配置信息，无需重新启动。

在本节中，我们演示了如何使用 ConfigMaps 作为文件挂载的动态配置。让我们看看当大规模系统的配置需求由多个团队在长时间内开发时，我们应该做些什么。

# 应用高级配置

对于有大量服务和大量配置的大规模系统，您可能希望有一些消耗多个 ConfigMaps 的服务。这与单个 ConfigMap 可能包含多个文件、目录和文字值的事实是分开的，可以任意组合。例如，每个服务可能有自己特定的配置，但也可能使用一些需要配置的共享库。在这种情况下，您可以为共享库和每个服务单独创建一个 ConfigMap。在这种情况下，服务将同时消耗它们自己的 ConfigMap 和共享库的 ConfigMap。

另一个常见的情况是针对不同环境（开发、暂存和生产）有不同的配置。由于在 Kubernetes 中，每个环境通常都有自己的命名空间，您需要在这里有创意。ConfigMaps 的作用域是它们的命名空间。这意味着即使您在各个环境中的配置是相同的，您仍然需要在每个命名空间中创建一个副本。有各种解决方案可以用来管理这种配置文件和 Kubernetes 清单的泛滥。我不会详细介绍这些内容，只是简单提一下一些更受欢迎的选项，没有特定顺序：

+   Helm: [`helm.sh/`](https://helm.sh/)

+   Kustomize: [`kustomize.io/`](https://kustomize.io/)

+   Jsonnet: [`jsonnet.org/articles/kubernetes.html`](https://jsonnet.org/articles/kubernetes.html)

+   **Ksonnet**：[`github.com/ksonnet/ksonnet`](https://github.com/ksonnet/ksonnet)（不再维护）

您还可以自己构建一些工具来执行此操作。在下一节中，我们将看另一种选择，这种选择非常酷，但更复杂——自定义资源。

# Kubernetes 自定义资源

Kubernetes 是一个非常可扩展的平台。您可以将自己的资源添加到 Kubernetes API 中，并享受 API 机制的所有好处，包括 kubectl 支持来管理它们。是的，就是这么好。您需要做的第一件事是定义自定义资源，也称为 CRD。定义将指定 Kubernetes API 上的端点、版本、范围、种类以及与这种新类型的资源交互时使用的名称。

这里有一个超级英雄 CRD：

```
apiVersion: apiextensions.k8s.io/v1beta1
kind: CustomResourceDefinition
metadata:
  # name must match the spec fields below, and be in the form: <plural>.<group>
  name: superheros.example.org
spec:
  # group name to use for REST API: /apis/<group>/<version>
  group: example.org
  # list of versions supported by this CustomResourceDefinition
  versions:
  - name: v1
    # Each version can be enabled/disabled by Served flag.
    served: true
    # One and only one version must be marked as the storage version.
    storage: true
  # either Namespaced or Cluster
  scope: Cluster
  names:
    # plural name to be used in the URL: /apis/<group>/<version>/<plural>
    plural: superheros
    # singular name to be used as an alias on the CLI and for display
    singular: superhero
    # kind is normally the CamelCased singular type. Your resource manifests use this.
    kind: SuperHero
    # shortNames allow shorter string to match your resource on the CLI
    shortNames:
    - hr
```

自定义资源可以从所有命名空间中访问。当构建 URL 时，范围是相关的，并且在删除命名空间中的所有对象时（命名空间范围 CRD 将与其命名空间一起被删除）。

让我们创建一些超级英雄资源。`antman`超级英雄具有与超级英雄 CRD 中定义的相同的 API 版本和种类。它在`metadata`中有一个名字，而`spec`是完全开放的。你可以在那里定义任何字段。在这种情况下，字段是`superpower`和`size`：

```
apiVersion: "example.org/v1"
kind: SuperHero
metadata:
  name: antman
spec:
  superpower: "can shrink"
  size: "tiny"
```

让我们来看看绿巨人。它非常相似，但在其`spec`中还有一个颜色字段：

```
apiVersion: "example.org/v1"
kind: SuperHero
metadata:
  name: hulk
spec:
  superpower: "super strong"
  size: "big"
  color: "green"
```

让我们从 CRD 本身开始创建整个团队：

```
$ kubectl create -f superheros-crd.yaml
customresourcedefinition.apiextensions.k8s.io "superheros.example.org" created

$ kubectl create -f antman.yaml
superhero.example.org "antman" created

$ kubectl create -f hulk.yaml
superhero.example.org "hulk" created
```

现在让我们用`kubectl`来检查它们。我们可以在这里使用`hr`的简称：

```
$ kubectl get hr
NAME               AGE
antman              5m
hulk                5m
```

我们还可以检查超级英雄的详细信息：

```
$ kubectl get superhero hulk -o yaml
apiVersion: example.org/v1
kind: SuperHero
metadata:
 creationTimestamp: 2019-02-09T09:58:32Z
 generation: 1
 name: hulk
 namespace: default
 resourceVersion: "932374"
 selfLink: /apis/example.org/v1/namespaces/default/superheros/hulk
 uid: 4256d27b-2c51-11e9-9999-0800275914a6
spec:
 color: green
 size: big
 superpower: super strong
```

这很酷，但自定义资源能做什么？很多。如果您考虑一下，您将获得一个带有 CLI 支持和可靠持久存储的免费 CRUD API。只需发明您的对象模型，并创建、获取、列出、更新和删除尽可能多的自定义资源。但它还可以更进一步：您可以拥有自己的控制器，监视您的自定义资源，并在需要时采取行动。这实际上就是 Argo CD 的工作原理，您可以从以下命令中看到：

```
$ kubectl get crd -n argocd
NAME                         AGE
applications.argoproj.io     20d
appprojects.argoproj.io      20d
```

这如何帮助配置？由于自定义资源在整个集群中可用，你可以将它们用于跨命名空间的共享配置。CRDs 可以作为集中的远程配置服务，正如我们在*动态配置*部分中讨论的那样，但你不需要自己实现任何东西。另一个选择是创建一个监视这些 CRDs 的控制器，然后自动将它们复制到适当的 ConfigMaps 中。在 Kubernetes 中，你只受到你的想象力的限制。最重要的是，对于管理配置是一项艰巨任务的大型复杂系统，Kubernetes 为你提供了扩展配置的工具。让我们把注意力转向配置的一个方面，这在其他系统上经常会引起很多困难——服务发现。

# 服务发现

Kubernetes 内置支持服务发现，无需在你的部分进行任何额外的工作。每个服务都有一个 endpoints 资源，Kubernetes 会及时更新该资源，其中包含该服务所有支持的 pod 的地址。以下是单节点 Minikube 集群的 endpoints。请注意，即使只有一个物理节点，每个 pod 都有自己的 IP 地址。这展示了 Kubernetes 的著名的扁平网络模型。只有 Kubernetes API 服务器有一个公共 IP 地址。

```
$ kubectl get endpoints
NAME                   ENDPOINTS             AGE
kubernetes             192.168.99.122:8443   27d
link-db                172.17.0.13:5432      16d
link-manager           172.17.0.10:8080      16d
social-graph-db        172.17.0.8:5432       26d
social-graph-manager   172.17.0.7:9090       19d
user-db                172.17.0.12:5432      18d
user-manager           172.17.0.9:7070       18d
```

通常，你不会直接处理 endpoints 资源。每个服务都会自动通过 DNS 和环境变量向集群中的其他服务公开。

如果你处理发现在 Kubernetes 集群之外运行的外部服务，那么你就得自己解决。一个好的方法可能是将它们添加到 ConfigMap 中，并在这些外部服务需要更改时进行更新。如果你需要管理访问这些外部服务的秘密凭据（这很可能），最好将它们放在 Kubernetes secrets 中，我们将在下一章中介绍。

# 总结

在本章中，我们讨论了与配置相关的一切，但不包括秘密管理。首先，我们考虑了经典配置，然后我们看了动态配置，重点是远程配置存储和远程配置服务。

接下来，我们讨论了 Kubernetes 特定的选项，特别是 ConfigMaps。我们介绍了 ConfigMap 可以被创建和管理的所有方式。我们还看到了一个 pod 可以如何使用 ConfigMap，可以作为环境变量（静态配置），也可以作为挂载卷中的配置文件，当相应的 ConfigMap 被操作员修改时，这些配置文件会自动更新。最后，我们看了更强大的选项，比如自定义资源，并讨论了服务发现这个特殊但非常重要的案例。到这一点，你应该对一般的配置有一个清晰的认识，并了解了在传统方式或 Kubernetes 特定方式下配置微服务的可用选项。

在下一章中，我们将看一下关键的安全主题。部署在 Kubernetes 集群中的基于微服务的系统通常提供基本服务并管理关键数据。在许多情况下，保护数据和系统本身是首要任务。Kubernetes 在遵循最佳实践时提供了多种机制来协助构建安全系统。

# 进一步阅读

以下是一些资源供您使用，以便您可以了解本章讨论的概念和机制的细节：

+   **12 因素应用**：[`12factor.net/`](https://12factor.net/)

+   **Python 中的程序配置**：[`www.drdobbs.com/open-source/program-configuration-in-python/240169310`](http://www.drdobbs.com/open-source/program-configuration-in-python/240169310)

+   **构建动态配置服务**：[`www.compose.com/articles/building-a-dynamic-configuration-service-with-etcd-and-python/`](https://www.compose.com/articles/building-a-dynamic-configuration-service-with-etcd-and-python/)

+   **扩展 Kubernetes（视频）**：[`www.youtube.com/watch?v=qVZnU8rXAEU`](https://www.youtube.com/watch?v=qVZnU8rXAEU)


# 第六章：在 Kubernetes 上保护微服务

在本章中，我们将深入研究如何在 Kubernetes 上保护您的微服务。这是一个广泛的主题，我们将专注于对于在 Kubernetes 集群中构建和部署微服务的开发人员最相关的方面。您必须非常严格地处理安全问题，因为您的对手将积极尝试找到漏洞，渗透您的系统，访问敏感信息，运行僵尸网络，窃取您的数据，破坏您的数据，销毁您的数据，并使您的系统不可用。安全性应该设计到系统中，而不是作为事后的附加物。我们将通过涵盖一般安全原则和最佳实践来解决这个问题，然后深入探讨 Kubernetes 提供的安全机制。

在本章中，我们将涵盖以下主题：

+   应用健全的安全原则

+   用户帐户和服务帐户之间的区分

+   使用 Kubernetes 管理机密

+   使用 RBAC 管理权限

+   通过身份验证、授权和准入控制访问

+   通过使用安全最佳实践来加固 Kubernetes

# 技术要求

在本章中，我们将查看许多 Kubernetes 清单，并使 Delinkcious 更安全。没有必要安装任何新内容。

# 代码

代码分为两个 Git 存储库：

+   您可以在此处找到代码示例：[`github.com/PacktPublishing/Hands-On-Microservices-with-Kubernetes/tree/master/Chapter06`](https://github.com/PacktPublishing/Hands-On-Microservices-with-Kubernetes/tree/master/Chapter06)

+   您可以在此处找到更新的 Delinkcious 应用程序：[`github.com/the-gigi/delinkcious/releases/tag/v0.4`](https://github.com/the-gigi/delinkcious/releases/tag/v0.4)

# 应用健全的安全原则

有许多通用原则。让我们回顾最重要的原则，并了解它们如何帮助防止攻击，使攻击变得更加困难，从而最小化任何攻击造成的损害，并帮助从这些攻击中恢复：

+   **深度防御**：深度防御意味着多层和冗余的安全层。其目的是使攻击者难以破坏您的系统。多因素身份验证是一个很好的例子。您有用户名和密码，但您还必须输入发送到您手机的一次性代码。如果攻击者发现了您的凭据，但无法访问您的手机，他们将无法登录系统并造成破坏。深度防御有多个好处，例如：

+   使您的系统更安全

+   使攻破您的安全成本过高，以至于攻击者甚至不会尝试

+   更好地保护免受非恶意错误

+   **最小权限原则**：最小权限原则类似于间谍世界中著名的“需要知道基础”。您不能泄露您不知道的东西。您无法破坏您无权访问的东西。任何代理都可能被破坏。仅限制到必要的权限将在违规发生时最小化损害，并有助于审计、缓解和分析事件。

+   **最小化攻击面**：这个原则非常明确。您的攻击面越小，保护起来就越容易。请记住以下几点：

+   不要暴露您不需要的 API

+   不要保留您不使用的数据

+   不要提供执行相同任务的不同方式

最安全的代码是根本不写代码。这也是最高效和无 bug 的代码。非常谨慎地考虑要添加的每个新功能的业务价值。在迁移到一些新技术或系统时，请确保不要留下遗留物品。除了防止许多攻击向量外，当发生违规时，较小的攻击面将有助于集中调查并找到根本原因。

+   **最小化爆炸半径**：假设您的系统将被破坏或可能已经被破坏。然而，威胁的级别是不同的。最小化爆炸半径意味着受损组件不能轻易接触其他组件并在系统中传播。这也意味着对这些受损组件可用的资源不超过应该在那里运行的合法工作负载的需求。

+   **不要相信任何人**：以下是您不应该信任的实体的部分列表：

+   您的用户

+   您的合作伙伴

+   供应商

+   您的云服务提供商

+   开源开发人员

+   您的开发人员

+   您的管理员

+   你自己

+   你的安全

当我们说*不要相信*时，我们并不是恶意的。每个人都是可犯错误的，诚实的错误可能会和有针对性的攻击一样有害。*不要相信任何人*原则的伟大之处在于你不必做出判断。最小信任的相同方法将帮助你预防和减轻错误和攻击。

+   **保守一点**：林迪效应表明，对于一些不易腐烂的东西，它们存在的时间越长，你就可以期待它们存在的时间越长。例如，如果一家餐厅存在了 20 年，你可以期待它还会存在很多年，而一个刚刚开业的全新餐厅更有可能在短时间内关闭。这对软件和技术来说非常真实。最新的 JavaScript 框架可能只有短暂的寿命，但像 jQuery 这样的东西会存在很长时间。从安全的角度来看，使用更成熟和经过严峻考验的软件会有其他好处，其安全性经受了严峻考验。从别人的经验中学习往往更好。考虑以下事项：

+   不要升级到最新和最好的（除非明确修复了安全漏洞）。

+   更看重稳定性而不是能力。

+   更看重简单性而不是强大性。

这与*不要相信任何人*原则相辅相成。不要相信新的闪亮东西，也不要相信你当前依赖的新版本。当然，微服务和 Kubernetes 是相对较新的技术，生态系统正在快速发展。在这种情况下，我假设你已经做出了决定，认为这些创新的整体好处和它们当前的状态已经足够成熟，可以进行建设。

+   **保持警惕**：安全不是一劳永逸的事情。你必须积极地继续努力。以下是一些你应该执行的全球性持续活动和流程：

+   定期打补丁。

+   旋转你的秘密。

+   使用短寿命的密钥、令牌和证书。

+   跟进 CVEs。

+   审计一切。

+   测试你系统的安全性。

+   **做好准备**：当不可避免的违规发生时，做好准备并确保你已经或正在做以下事情：

+   建立一个事件管理协议。

+   遵循你的协议。

+   堵住漏洞。

+   恢复系统安全。

+   进行安全事件的事后分析。

+   评估和学习。

+   更新你的流程、工具和安全性以提高你的安全姿态。

+   **不要编写自己的加密算法**：很多人对加密算法感到兴奋和/或失望，当强加密影响性能时。控制你的兴奋和/或失望。让专家来做加密。这比看起来要困难得多，风险也太高了。

既然我们清楚了良好安全性的一般原则，让我们来看看 Kubernetes 在安全方面提供了什么。

# 区分用户账户和服务账户

账户是 Kubernetes 中的一个核心概念。对 Kubernetes API 服务器的每个请求都必须来自一个特定的账户，API 服务器将在进行操作之前对其进行身份验证、授权和准入。有两种类型的账户：

+   用户账户

+   服务账户

让我们来检查两种账户类型，并了解它们之间的区别以及在何时适合使用每种类型。

# 用户账户

用户账户是为人类（集群管理员或开发人员）设计的，他们通常通过 kubectl 或以编程方式从外部操作 Kubernetes。最终用户不应该拥有 Kubernetes 用户账户，只能拥有应用级别的用户账户。这与 Kubernetes 无关。请记住，Kubernetes 会为您管理容器-它不知道容器内部发生了什么，也不知道您的应用实际在做什么。

您的用户凭据存储在`~/.kube/config`文件中。如果您正在使用多个集群，则您的`~/.kube/config`文件中可能有多个集群、用户和上下文。有些人喜欢为每个集群单独创建一个配置文件，并使用`KUBECONFIG`环境变量在它们之间切换。这取决于您。以下是我本地 Minikube 集群的配置文件：

```
apiVersion: v1
clusters:
- cluster:
    certificate-authority: /Users/gigi.sayfan/.minikube/ca.crt
    server: https://192.168.99.123:8443
  name: minikube
contexts:
- context:
    cluster: minikube
    user: minikube
  name: minikube
current-context: minikube
kind: Config
preferences: {}
users:
- name: minikube
  user:
    client-certificate: /Users/gigi.sayfan/.minikube/client.crt
    client-key: /Users/gigi.sayfan/.minikube/client.key
```

正如您在上面的代码块中所看到的，这是一个遵循典型 Kubernetes 资源约定的 YAML 文件，尽管它不是您可以在集群中创建的对象。请注意，一切都是复数形式：集群、上下文、用户。在这种情况下，只有一个集群和一个用户。但是，您可以创建多个上下文，这些上下文是集群和用户的组合，这样您就可以在同一个集群中拥有不同权限的多个用户，甚至在同一个 Minikube 配置文件中拥有多个集群。`current-context`确定了`kubectl`的每个操作的目标（使用哪个用户凭据访问哪个集群）。用户账户具有集群范围，这意味着我们可以访问任何命名空间中的资源。

# 服务账户

服务帐户是另一回事。每个 pod 都有一个与之关联的服务帐户，并且在该 pod 中运行的所有工作负载都使用该服务帐户作为其身份。服务帐户的范围限定为命名空间。当您创建一个 pod（直接或通过部署）时，可以指定一个服务帐户。如果创建 pod 而没有指定服务帐户，则使用命名空间的默认服务帐户。每个服务帐户都有一个与之关联的秘密，用于与 API 服务器通信。

以下代码块显示了默认命名空间中的默认服务帐户：

```
$ kubectl get sa default -o yaml
apiVersion: v1
kind: ServiceAccount
metadata:
 creationTimestamp: 2019-01-11T15:49:27Z
 name: default
 namespace: default
 resourceVersion: "325"
 selfLink: /api/v1/namespaces/default/serviceaccounts/default
 uid: 79e17169-15b8-11e9-8591-0800275914a6
secrets:
- name: default-token-td5tz
```

服务帐户可以有多个秘密。我们很快将讨论秘密。服务帐户允许在 pod 中运行的代码与 API 服务器通信。

您可以从`/var/run/secrets/kubernetes.io/serviceaccount`获取令牌和 CA 证书，然后通过授权标头传递这些凭据来构造`REST HTTP`请求。例如，以下代码块显示了在默认命名空间中列出 pod 的请求：

```
# TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
# CA_CERT=$(cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt)
# URL="https://${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT}"

# curl --cacert "$CERT" -H "Authorization: Bearer $TOKEN" "$URL/api/v1/namespaces/default/pods"
{
  "kind": "Status",
  "apiVersion": "v1",
  "metadata": {

  },
  "status": "Failure",
  "message": "pods is forbidden: User \"system:serviceaccount:default:default\" cannot list resource \"pods\" in API group \"\" in the namespace \"default\"",
  "reason": "Forbidden",
  "details": {
    "kind": "pods"
  },
  "code": 403
}
```

结果是 403 禁止。默认服务帐户不允许列出 pod，实际上它不允许做任何事情。在`授权`部分，我们将看到如何授予服务帐户权限。

如果您不喜欢手动构造 curl 请求，也可以通过客户端库以编程方式执行。我创建了一个基于 Python 的 Docker 镜像，其中包括 Kubernetes 的官方 Python 客户端库（[`github.com/kubernetes-client/python`](https://github.com/kubernetes-client/python)）以及一些其他好东西，如 vim、IPython 和 HTTPie。

这是构建镜像的 Dockerfile：

```
FROM python:3

RUN apt-get update -y
RUN apt-get install -y vim
RUN pip install kubernetes \
                httpie     \
                ipython

CMD bash
```

我将其上传到 DockerHub 作为`g1g1/py-kube:0.2`。现在，我们可以在集群中将其作为一个 pod 运行，并进行良好的故障排除或交互式探索会话：

```
$ kubectl run trouble -it --image=g1g1/py-kube:0.2 bash
```

执行上述命令将使您进入一个命令行提示符，您可以在其中使用 Python、IPython、HTTPie 以及可用的 Kubernetes Python 客户端包做任何您想做的事情。以下是我们如何从 Python 中列出默认命名空间中的 pod：

```
# ipython
Python 3.7.2 (default, Feb  6 2019, 12:04:03)
Type 'copyright', 'credits' or 'license' for more information
IPython 7.2.0 -- An enhanced Interactive Python. Type '?' for help.

In [1]: from kubernetes import client, config
In [2]: config.load_incluster_config()
In [3]: api = client.CoreV1Api()
In [4]: api.list_namespaced_pod(namespace='default')

```

结果将类似 - 一个 Python 异常 - 因为默认帐户被禁止列出 pod。请注意，如果您的 pod 不需要访问 API 服务器（非常常见），您可以通过设置`automountServiceAccountToken: false`来明确表示。

这可以在服务账户级别或 pod 规范中完成。这样，即使在以后有人或某物在您的控制之外添加了对服务账户的权限，由于没有挂载令牌，pod 将无法对 API 服务器进行身份验证，并且不会获得意外访问。Delinkcious 服务目前不需要访问 API 服务器，因此通过遵循最小权限原则，我们可以将其添加到部署中的规范中。

以下是如何为 LinkManager 创建服务账户（无法访问 API 服务器）并将其添加到部署中：

```
apiVersion: v1
kind: ServiceAccount
metadata:
  name: link-manager
  automountServiceAccountToken: false
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: link-manager
  labels:
    svc: link
    app: manager
spec:
  replicas: 1
  selector:
    matchLabels:
      svc: link
      app: manager
  serviceAccountName: link-manager
...
```

在使用 RBAC 授予我们的服务账户超级权限之前，让我们回顾一下 Kubernetes 如何管理秘密。Kubernetes 默认情况下将秘密存储在 etcd 中。可以将 etcd 与第三方解决方案集成，但在本节中，我们将专注于原始的 Kubernetes。秘密应该在静止和传输中进行加密，etcd 自版本 3 以来就支持了这一点。

现在我们了解了 Kubernetes 中账户如何工作，让我们看看如何管理秘密。

# 使用 Kubernetes 管理秘密

在使用 RBAC 授予我们的服务账户超级权限之前，让我们回顾一下 Kubernetes 如何管理秘密。Kubernetes 默认情况下将秘密存储在 etcd ([`coreos.com/etcd/`](https://coreos.com/etcd/))中。Kubernetes 可以管理不同类型的秘密。让我们看看各种秘密类型，然后创建我们自己的秘密并将它们传递给容器。最后，我们将一起构建一个安全的 pod。

# 了解 Kubernetes 秘密的三种类型

有三种不同类型的秘密：

+   服务账户 API 令牌（用于与 API 服务器通信的凭据）

+   注册表秘密（用于从私有注册表中拉取图像的凭据）

+   不透明秘密（Kubernetes 一无所知的您的秘密）

服务账户 API 令牌是每个服务账户内置的（除非您指定了`automountServiceAccountToken: false`）。这是`link-manager`的服务账户 API 令牌的秘密：

```
$ kubectl get secret link-manager-token-zgzff | grep link-manager-token
link-manager-token-zgzff   kubernetes.io/service-account-token  3   20h
```

`pull secrets`图像稍微复杂一些。不同的私有注册表行为不同，并且需要不同的秘密。此外，一些私有注册表要求您经常刷新令牌。让我们以 DockerHub 为例。DockerHub 默认情况下允许您拥有单个私有存储库。我将`py-kube`转换为私有存储库，如下截图所示：

！[](assets/bf7fadd6-8d83-4238-9652-66c89f6bd039.png)

我删除了本地 Docker 镜像。要拉取它，我需要创建一个注册表机密：

```
$ kubectl create secret docker-registry private-dockerhub \
 --docker-server=docker.io \
 --docker-username=g1g1 \
 --docker-password=$DOCKER_PASSWORD \
 --docker-email=$DOCKER_EMAIL
secret "private-dockerhub" created
$ kubectl get secret private-dockerhub
NAME                TYPE                             DATA      AGE
private-dockerhub   kubernetes.io/dockerconfigjson   1         16s
```

最后一种类型的机密是`Opaque`，是最有趣的机密类型。您可以将敏感信息存储在 Kubernetes 不会触及的不透明机密中。它只为您提供了一个强大且安全的机密存储库，并提供了一个用于创建、读取和更新这些机密的 API。您可以通过许多方式创建不透明机密，例如以下方式：

+   从文字值

+   从文件或目录

+   从`env`文件（单独行中的键值对）

+   使用`kind`创建一个 YAML 清单

这与 ConfigMaps 非常相似。现在，让我们创建一些机密。

# 创建您自己的机密

创建机密的最简单和最有用的方法之一是通过包含键值对的简单`env`文件：

```
a=1
b=2
```

我们可以使用`-o yaml`标志（YAML 输出格式）来创建一个机密，以查看创建了什么：

```
$ kubectl create secret generic generic-secrets --from-env-file=generic-secrets.txt -o yaml

apiVersion: v1
data:
 a: MQ==
 b: Mg==
kind: Secret
metadata:
 creationTimestamp: 2019-02-16T21:37:38Z
 name: generic-secrets
 namespace: default
 resourceVersion: "1207295"
 selfLink: /api/v1/namespaces/default/secrets/generic-secrets
 uid: 14e1db5c-3233-11e9-8e69-0800275914a6
type: Opaque
```

类型是`Opaque`，返回的值是 base64 编码的。要获取这些值并解码它们，您可以使用以下命令：

```
$ echo -n $(kubectl get secret generic-secrets -o jsonpath="{.data.a}") | base64 -D
1
```

`jsonpath`输出格式允许您深入到对象的特定部分。如果您喜欢，您也可以使用`jq`（[`stedolan.github.io/jq/`](https://stedolan.github.io/jq/)）。

请注意，机密不会被存储或传输；它们只是以 base-64 进行加密或编码，任何人都可以解码。当您使用您的用户帐户创建机密（或获取机密）时，您会得到解密后机密的 base-64 编码表示。但是，它在磁盘上是加密的，并且在传输过程中也是加密的，因为您是通过 HTTPS 与 Kubernetes API 服务器通信的。

现在我们已经了解了如何创建机密，我们将使它们可用于在容器中运行的工作负载。

# 将机密传递给容器

有许多方法可以将机密传递给容器，例如以下方法：

+   您可以将机密嵌入到容器镜像中。

+   您可以将它们传递到环境变量中。

+   您可以将它们挂载为文件。

最安全的方式是将你的秘密作为文件挂载。当你将你的秘密嵌入到镜像中时，任何有权访问镜像的人都可以检索你的秘密。当你将你的秘密作为环境变量传递时，它们可以通过`docker inspect`、`kubectl describe pod`以及如果你不清理环境的话，子进程也可以查看。此外，通常在报告错误时记录整个环境，这需要所有开发人员的纪律来清理和编辑秘密。挂载的文件不会受到这些弱点的影响，但请注意，任何可以`kubectl exec`进入你的容器的人都可以检查任何挂载的文件，包括秘密，如果你不仔细管理权限的话。

让我们从一个 YAML 清单中创建一个秘密。选择这种方法时，你有责任对值进行 base64 编码：

```
$ echo -n top-secret | base64
dG9wLXNlY3JldA==

$ echo -n bottom-secret | base64
Ym90dG9tLXNlY3JldA==

apiVersion: v1
kind: Secret
type: Opaque
metadata:
  name: generic-secrets2
  namespace: default
data:
  c: dG9wLXNlY3JldA==
  d: Ym90dG9tLXNlY3JldA==
```

让我们创建新的秘密，并通过使用`kubectl get secret`来验证它们是否成功创建：

```
$ kubectl create -f generic-secrets2.yaml
secret "generic-secrets2" created

$ echo -n $(kubectl get secret generic-secrets2 -o jsonpath="{.data.c}") | base64 -d
top-secret

$ echo -n $(kubectl get secret generic-secrets2 -o jsonpath="{.data.d}") | base64 -d
bottom-secret
```

现在我们知道如何创建不透明/通用的秘密并将它们传递给容器，让我们把所有的点连接起来，构建一个安全的 pod。

# 构建一个安全的 pod

该 pod 有一个自定义服务，不需要与 API 服务器通信（因此不需要自动挂载服务账户令牌）；相反，该 pod 提供`imagePullSecret`来拉取我们的私有仓库，并且还挂载了一些通用秘密作为文件。

让我们开始学习如何构建一个安全的 pod：

1.  第一步是自定义服务账户。以下是 YAML 清单：

```
apiVersion: v1
kind: ServiceAccount
metadata:
  name: service-account
automountServiceAccountToken: false
```

让我们创建它：

```
$ kubectl create -f service-account.yaml
serviceaccount "service-account" created
```

1.  现在，我们将把它附加到我们的 pod 上，并设置之前创建的`imagePullSecret`。这里有很多事情要做。我附加了一个自定义服务账户，创建了一个引用`generic-secrets2`秘密的秘密卷，然后挂载到`/etc/generic-secrets2`；最后，我将`imagePullSecrets`设置为`private-dockerhub`秘密：

```
apiVersion: v1
kind: Pod
metadata:
  name: trouble
spec:
  serviceAccountName: service-account
  containers:
  - name: trouble
    image: g1g1/py-kube:0.2
    command: ["/bin/bash", "-c", "while true ; do sleep 10 ; done"]
    volumeMounts:
    - name: generic-secrets2
      mountPath: "/etc/generic-secrets2"
      readOnly: true
  imagePullSecrets:
  - name: private-dockerhub
  volumes:
  - name: generic-secrets2
    secret:
      secretName: generic-secrets2
```

1.  接下来，我们可以创建我们的 pod 并开始玩耍：

```
$ kubectl create -f pod-with-secrets.yaml
pod "trouble" created
```

Kubernetes 能够从私有仓库中拉取镜像。我们不希望有 API 服务器令牌（`/var/run/secrets/kubernetes.io/serviceaccount/`不应该存在），我们的秘密应该作为文件挂载在`/etc/generic-secrets2`中。让我们通过使用`kubectl exec -it`启动一个交互式 shell 来验证这一点，并检查服务账户文件是否存在，但通用秘密`c`和`d`存在：

```
$ kubectl exec -it trouble bash

# ls /var/run/secrets/kubernetes.io/serviceaccount/
ls: cannot access '/var/run/secrets/kubernetes.io/serviceaccount/': No such file or directory

# cat /etc/generic-secrets2/c
top-secret

# cat /etc/generic-secrets2/d
bottom-secret
```

太好了，它起作用了！

在这里，我们着重于管理自定义密钥并构建一个无法访问 Kubernetes API 服务器的安全 Pod，但通常您需要仔细管理不同实体对 Kubernetes API 服务器的访问权限。Kubernetes 具有明确定义的**基于角色的访问控制模型**（也称为**RBAC**）。让我们看看它的运作方式。

# 使用 RBAC 管理权限

RBAC 是用于管理对 Kubernetes 资源的访问的机制。从 Kubernetes 1.8 开始，RBAC 被认为是稳定的。使用`--authorization-mode=RBAC`启动 API 服务器以启用它。当请求发送到 API 服务器时，RBAC 的工作原理如下：

1.  首先，它通过调用者的用户凭据或服务账户凭据对请求进行身份验证（如果失败，则返回 401 未经授权）。

1.  接下来，它检查 RBAC 策略，以验证请求者是否被授权对目标资源执行操作（如果失败，则返回 403 禁止）。

1.  最后，它通过一个准入控制器运行，该控制器可能因各种原因拒绝或修改请求。

RBAC 模型由身份（用户和服务账户）、资源（Kubernetes 对象）、动词（标准操作，如`get`、`list`和`create`）、角色和角色绑定组成。Delinkcious 服务不需要访问 API 服务器，因此它们不需要访问权限。但是，持续交付解决方案 Argo CD 绝对需要访问权限，因为它部署我们的服务和所有相关对象。

让我们来看一下角色中的以下片段，并详细了解它。您可以在这里找到源代码：[`github.com/argoproj/argo-cd/blob/master/manifests/install.yaml#L116`](https://github.com/argoproj/argo-cd/blob/master/manifests/install.yaml#L116)：

```
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  labels:
    app.kubernetes.io/component: server
    app.kubernetes.io/name: argo-cd
  name: argocd-server
rules:
- apiGroups:
  - ""
  resources:
  - secrets
  - configmaps
  verbs:
  - create
  - get
  - list
  ...
- apiGroups:
  - argoproj.io
  resources:
  - applications
  - appprojects
  verbs:
  - create
  - get
  - list
  ...
- apiGroups:
  - ""
  resources:
  - events
  verbs:
  - create
  - list
```

角色有规则。每个规则将允许的动词列表分配给每个 API 组和该 API 组内的资源。例如，对于空的 API 组（表示核心 API 组）和`configmaps`和`secrets`资源，Argo CD 服务器可以应用所有这些动词：

```
- apiGroups:
  - ""
  resources:
  - secrets
  - configmaps
  verbs:
  - create
  - get
  - list
  - watch
  - update
  - patch
  - delete
```

`argoproj.io` API 组和`applications`和`appprojects`资源（都是由 Argo CD 定义的 CRD）有另一个动词列表。最后，对于核心组的`events`资源，它只能使用`create`或`list`动词：

```
- apiGroups:
  - ""
  resources:
  - events
  verbs:
  - create
- list
```

RBAC 角色仅适用于创建它的命名空间。这意味着 Argo CD 可以对`configmaps`和`secrets`做任何事情并不太可怕，如果它是在专用命名空间中创建的。您可能还记得，我在名为`argocd`的命名空间中在集群上安装了 Argo CD。

然而，类似于角色，RBAC 还有一个`ClusterRole`，其中列出的权限在整个集群中都是允许的。Argo CD 也有集群角色。例如，`argocd-application-controller`具有以下集群角色：

```
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  labels:
    app.kubernetes.io/component: application-controller
    app.kubernetes.io/name: argo-cd
  name: argocd-application-controller
rules:
- apiGroups:
  - '*'
  resources:
  - '*'
  verbs:
  - '*'
- nonResourceURLs:
  - '*'
  verbs:
- '*'
```

这几乎可以访问集群中的任何内容。这相当于根本没有 RBAC。我不确定为什么 Argo CD 应用程序控制器需要这样的全局访问权限。我猜想这只是为了更容易地访问任何内容，而不是明确列出所有内容，如果是一个很长的列表。然而，从安全的角度来看，这并不是最佳做法。

角色和集群角色只是一系列权限列表。为了使其正常工作，您需要将角色绑定到一组帐户。这就是角色绑定和集群角色绑定发挥作用的地方。角色绑定仅在其命名空间中起作用。您可以将角色绑定到角色和集群角色（在这种情况下，集群角色仅在目标命名空间中处于活动状态）。这是一个例子：

```
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  labels:
    app.kubernetes.io/component: application-controller
    app.kubernetes.io/name: argo-cd
  name: argocd-application-controller
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: argocd-application-controller
subjects:
- kind: ServiceAccount
name: argocd-application-controller
```

集群角色绑定适用于整个集群，只能绑定集群角色（因为角色受限于其命名空间）。

现在我们了解了如何使用 RBAC 控制对 Kubernetes 资源的访问权限，让我们继续控制对我们自己的微服务的访问权限。

# 通过身份验证、授权和准入来控制访问

Kubernetes 具有一个有趣的访问控制模型，超出了标准的访问控制。对于您的微服务，它提供了身份验证、授权和准入的三重保证。您可能熟悉身份验证（谁在调用？）和授权（调用者被允许做什么？）。准入并不常见。它可以用于更动态的情况，即使调用者经过了正确的身份验证和授权，也可能被拒绝请求。

# 微服务认证

服务账户和 RBAC 是管理 Kubernetes 对象的身份和访问的良好解决方案。然而，在微服务架构中，微服务之间会有大量的通信。这种通信发生在集群内部，可能被认为不太容易受到攻击。但是，深度防御原则指导我们也要加密、认证和管理这种通信。这里有几种方法。最健壮的方法需要你自己的**私钥基础设施**（**PKI**）和**证书颁发机构**（**CA**），可以处理证书的发布、吊销和更新，因为服务实例的出现和消失。这相当复杂（如果你使用云提供商，他们可能会为你提供）。一个相对简单的方法是利用 Kubernetes secrets，并在每两个可以相互通信的服务之间创建共享的密钥。然后，当请求到来时，我们可以检查调用服务是否传递了正确的密钥，从而对其进行认证。

让我们为`link-manager`和`graph-manager`创建一个共享密钥（记住它必须是 base64 编码的）：

```
$ echo -n "social-graph-manager: 123" | base64
c29jaWFsLWdyYXBoLW1hbmFnZXI6IDEyMw==
```

然后，我们将为`link-manager`创建一个密钥，如下所示：

```
apiVersion: v1
kind: Secret
type: Opaque
metadata:
  name: mutual-auth
  namespace: default
data:
  mutual-auth.yaml: c29jaWFsLWdyYXBoLW1hbmFnZXI6IDEyMw==
```

永远不要将密钥提交到源代码控制。我在这里只是为了教育目的而这样做。

要使用`kubectl`和`jsonpath`格式查看密钥的值，您需要转义`mutual-auth.yaml`中的点：

```
$ kubectl get secret link-mutual-auth -o "jsonpath={.data['mutual-auth\.yaml']}" | base64 -D
social-graph-manager: 123
```

我们将重复这个过程为`social-graph-manager`：

```
$ echo -n "link-manager: 123" | base64
bGluay1tYW5hZ2VyOiAxMjM=
```

然后，我们将为`social-graph-manager`创建一个密钥，如下所示：

```
apiVersion: v1
kind: Secret
type: Opaque
metadata:
  name: mutual-auth
  namespace: default
data:
  mutual-auth.yaml: bGluay1tYW5hZ2VyOiAxMjM=
```

此时，`link-manager`和`social-graph-manager`有一个共享的密钥，我们可以将其挂载到各自的 pod 上。这是`link-manager`部署中的 pod 规范，它将密钥从一个卷挂载到`/etc/delinkcious`。密钥将显示为`mutual-auth.yaml`文件：

```
spec:
  containers:
  - name: link-manager
    image: g1g1/delinkcious-link:0.3
    imagePullPolicy: Always
    ports:
    - containerPort: 8080
    envFrom:
    - configMapRef:
        name: link-manager-config
    volumeMounts:
    - name: mutual-auth
      mountPath: /etc/delinkcious
      readOnly: true
  volumes:
  - name: mutual-auth
    secret:
      secretName: link-mutual-auth
```

我们可以将相同的约定应用于所有服务。结果是每个 pod 都将有一个名为`/etc/delinkcious/mutual-auth.yaml`的文件，其中包含它需要通信的所有服务的令牌。基于这个约定，我们创建了一个叫做`auth_util`的小包，它读取文件，填充了一些映射，并暴露了一些用于映射和匹配调用方和令牌的函数。`auth_util`包期望文件本身是一个 YAML 文件，格式为`<caller>: <token>`的键值对。

以下是声明和映射：

```
package auth_util

import (
   _ "github.com/lib/pq"
   "gopkg.in/yaml.v2"
   "io/ioutil"
   "os"
)

const callersFilename = "/etc/delinkcious/mutual-auth.yaml"

var callersByName = map[string]string{}
var callersByToken = map[string][]string{}
```

`init()`函数读取文件（除非`env`变量`DELINKCIOUS_MUTUAL_AUTH`设置为`false`），将其解组为`callersByName`映射，然后遍历它并填充反向`callersByToken`映射，其中令牌是键，调用者是值（可能重复）：

```
func init() {
   if os.Getenv("DELINKCIOUS_MUTUAL_AUTH") == "false" {
      return
   }

   data, err := ioutil.ReadFile(callersFilename)
   if err != nil {
      panic(err)
   }
   err = yaml.Unmarshal(data, callersByName)
   if err != nil {
      panic(err)
   }

   for caller, token := range callersByName {
      callersByToken[token] = append(callersByToken[token], caller)
   }
}
```

最后，`GetToken()`和`HasCaller()`函数提供了被服务和客户端用来相互通信的包的外部接口：

```
func GetToken(caller string) string {
   return callersByName[caller]
}

func HasCaller(caller string, token string) bool {
   for _, c := range callersByToken[token] {
      if c == caller {
         return true
      }
   }

   return false
}
```

让我们看看链接服务如何调用社交图服务的`GetFollowers()`方法。`GetFollowers()`方法从环境中提取认证令牌，并将其与标头中提供的令牌进行比较（这仅为链接服务所知），以验证调用者是否真的是链接服务。与往常一样，核心逻辑不会改变。整个身份验证方案都隔离在传输和客户端层。由于社交图服务使用 HTTP 传输，客户端将令牌存储在名为`Delinkcious-Caller-Service`的标头中。它通过`auth_util`包的`GetToken()`函数获取令牌，而不知道秘密来自何处（在我们的情况下，Kubernetes 秘密被挂载为文件）：

```
// encodeHTTPGenericRequest is a transport/http.EncodeRequestFunc that
// JSON-encodes any request to the request body. Primarily useful in a client.
func encodeHTTPGenericRequest(_ context.Context, r *http.Request, request interface{}) error {
   var buf bytes.Buffer
   if err := json.NewEncoder(&buf).Encode(request); err != nil {
      return err
   }
   r.Body = ioutil.NopCloser(&buf)

   if os.Getenv("DELINKCIOUS_MUTUAL_AUTH") != "false" {
      token := auth_util.GetToken(SERVICE_NAME)
      r.Header["Delinkcious-Caller-Token"] = []string{token}
   }

   return nil
}
```

在服务端，社交图服务传输层确保`Delinkcious-Caller-Token`存在，并且包含有效调用者的令牌：

```
func decodeGetFollowersRequest(_ context.Context, r *http.Request) (interface{}, error) {
   if os.Getenv("DELINKCIOUS_MUTUAL_AUTH") != "false" {
      token := r.Header["Delinkcious-Caller-Token"]
      if len(token) == 0 || token[0] == "" {
         return nil, errors.New("Missing caller token")
      }

      if !auth_util.HasCaller("link-manager", token[0]) {
         return nil, errors.New("Unauthorized caller")
      }
   }
   parts := strings.Split(r.URL.Path, "/")
   username := parts[len(parts)-1]
   if username == "" || username == "followers" {
      return nil, errors.New("user name must not be empty")
   }
   request := getByUsernameRequest{Username: username}
   return request, nil
}
```

这种机制的美妙之处在于，我们将解析文件和从 HTTP 请求中提取标头等繁琐的管道工作都保留在传输层，并保持核心逻辑原始。

在第十三章中，*服务网格-使用 Istio 工作*，我们将看到使用服务网格对微服务进行身份验证的另一种解决方案。现在，让我们继续授权微服务。

# 授权微服务

授权微服务可能非常简单，也可能非常复杂。在最简单的情况下，如果调用微服务经过身份验证，则被授权执行任何操作。然而，有时这是不够的，您需要根据其他请求参数进行非常复杂和细粒度的授权。例如，在我曾经工作过的一家公司，我为具有空间和时间维度的传感器网络开发了授权方案。用户可以查询数据，但他们可能仅限于特定的城市、建筑物、楼层或房间。

如果他们从未经授权的位置请求数据，他们的请求将被拒绝。他们还受到时间范围的限制，不能在指定的时间范围之外查询。

对于 Delinkcious，您可以想象用户可能只能查看自己的链接和他们关注的用户的链接（如果获得批准）。

# 承认微服务

身份验证和授权是非常著名和熟悉的访问控制机制（尽管难以强大地实施）。准入是跟随授权的另一步。即使请求经过身份验证和授权，也可能无法立即满足请求。这可能是由于服务器端的速率限制或其他间歇性问题。Kubernetes 实现了额外的功能，例如作为准入的一部分改变请求。对于您自己的微服务，可能并不需要这样做。

到目前为止，我们已经讨论了帐户、秘密和访问控制。然而，为了更接近一个安全和加固的集群，还有很多工作要做。

# 使用安全最佳实践加固您的 Kubernetes 集群

在本节中，我们将介绍各种最佳实践，并看看 Delinkcious 离正确的方式有多近。

# 保护您的镜像

最重要的之一是确保您部署到集群的镜像是安全的。这里有几个很好的指导方针要遵循。

# 始终拉取镜像

在容器规范中，有一个名为`ImagePullPolicy`的可选键。默认值是`IfNotPresent`。这个默认值有一些问题，如下所示：

+   如果您使用*latest*等标签（您不应该这样做），那么您将无法获取更新的镜像。

+   您可能会与同一节点上的其他租户发生冲突。

+   同一节点上的其他租户可以运行您的镜像。

Kubernetes 有一个名为`AlwaysPullImages`的准入控制器，它将每个 pod 的`ImagePullPolicy`设置为`AlwaysPullImages`。这可以防止所有问题，但会拉取镜像，即使它们已经存在并且您有权使用它们。您可以通过将其添加到传递给`kube-apiserver`的启用准入控制器列表中的`--enable-admission-controllers`标志来启用此准入控制器。

# 扫描漏洞

代码或依赖项中的漏洞会使攻击者能够访问你的系统。国家漏洞数据库（[`nvd.nist.gov/`](https://nvd.nist.gov/)）是了解新漏洞和管理漏洞的流程的好地方，比如**安全内容自动化协议**（**SCAP**）。

开源解决方案，如 Claire（[`github.com/coreos/clair`](https://github.com/coreos/clair)）和 Anchore（[`anchore.com/kubernetes/`](https://anchore.com/kubernetes/)）可用，还有商业解决方案。许多镜像注册表也提供扫描服务。

# 更新你的依赖项

保持依赖项的最新状态，特别是如果它们修复了已知的漏洞。在这里，你需要在警惕和保守之间找到合适的平衡。

# 固定基础镜像的版本

基础镜像的版本固定对于确保可重复构建至关重要。如果未指定基础镜像的版本，将会获取最新版本，这可能并非你想要的。

# 使用最小的基础镜像

最小化攻击面的原则敦促你尽可能使用最小的基础镜像；越小越受限制，越好。除了这些安全好处，你还可以享受更快的拉取和推送（尽管层只有在升级基础镜像时才会使其相关）。Alpine 是一个非常受欢迎的基础镜像。Delinkcious 服务采用了极端的方法，使用`SCRATCH`镜像作为基础镜像。

几乎整个服务只是一个 Go 可执行文件，就是这样。它小巧、快速、安全，但当你需要解决问题时，你会为此付出代价，因为没有工具可以帮助你。

如果我们遵循所有这些准则，我们的镜像将是安全的，但我们仍应用最小权限和零信任的基本原则，并在网络层面最小化影响范围。如果容器、Pod 或节点某种方式被 compromise，它们不应该被允许访问网络的其他部分，除非是工作负载运行所需的。这就是命名空间和网络策略发挥作用的地方。

# 划分和征服你的网络

除了身份验证作为深度防御的一部分，你还可以通过使用命名空间和网络策略来确保服务只有在必要时才能相互通信。

命名空间是一个非常直观但强大的概念。然而，它们本身并不能阻止同一集群中的 pod 相互通信。在 Kubernetes 中，集群中的所有 pod 共享相同的平面网络地址空间。这是 Kubernetes 网络模块的一个很大的简化之一。你的 pod 可以在同一节点上，也可以在不同的节点上 - 这并不重要。

每个 pod 都有自己的 IP 地址（即使多个 pod 在同一物理节点或 VM 上运行，只有一个 IP 地址）。这就是网络策略的作用。网络策略基本上是一组规则，指定了 pod 之间的集群内通信（东西流量），以及集群中服务与外部世界之间的通信（南北流量）。如果没有指定网络策略，所有传入流量（入口）默认情况下都允许访问每个 pod 的所有端口。从安全的角度来看，这是不可接受的。

让我们首先阻止所有的入口流量，然后根据需要逐渐开放：

```
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-all
spec:
  podSelector: {}
  policyTypes:
  - Ingress
```

请注意，网络策略是在 pod 级别工作的。您可以使用有意义的标签正确地对 pod 进行分组，这是您应该这样做的主要原因之一。

在应用此策略之前，最好知道它是否可以从故障排除的 pod 中工作，如下面的代码块所示：

```
# http GET http://$SOCIAL_GRAPH_MANAGER_SERVICE_HOST:9090/following/gigi

HTTP/1.1 200 OK
Content-Length: 37
Content-Type: text/plain; charset=utf-8
Date: Mon, 18 Feb 2019 18:00:52 GMT

{
    "err": "",
    "following": {
        "liat": true
    }
}
```

然而，在应用了`deny-all`策略之后，我们得到了一个超时错误，如下所示：

```
# http GET http://$SOCIAL_GRAPH_MANAGER_SERVICE_HOST:9090/following/gigi

http: error: Request timed out (30s).
```

现在所有的 pod 都被隔离了，让我们允许`social-graph-manager`访问它的数据库。这是一个网络策略，只允许`social-graph-manager`访问端口`5432`上的`social-graph-db`：

```
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-social-graph-db
  namespace: default
spec:
  podSelector:
    matchLabels:
      svc: social-graph
      app: db
  ingress:
  - from:
    - podSelector:
        matchLabels:
          svc: social-graph
          app: manger
    ports:
    - protocol: TCP
      port: 5432
```

以下附加策略允许从`link-manager`对`social-graph-manager`的端口`9090`进行入口，如下面的代码所示：

```
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-link-to-social-graph
  namespace: default
spec:
  podSelector:
    matchLabels:
      svc: social-graph
      app: manager
  ingress:
  - from:
    - podSelector:
        matchLabels:
          svc: link
          app: manger
    ports:
    - protocol: TCP
      port: 9090
```

除了安全性的好处之外，网络策略还作为系统中信息流动的实时文档。您可以准确地知道哪些服务与其他服务通信，以及外部服务。

我们已经控制了我们的网络。现在，是时候把注意力转向我们的镜像注册表了。毕竟，这是我们获取镜像的地方，我们给予了很多权限。

# 保护您的镜像注册表

强烈建议使用私有图像注册表。如果您拥有专有代码，那么您不得以公共访问方式发布您的容器，因为对您的图像进行逆向工程将授予攻击者访问权限。但是，这也有其他原因。您可以更好地控制（和审计）从注册表中拉取和推送图像。

这里有两个选择：

+   使用由 AWS、Google、Microsoft 或 Quay 等第三方管理的私有注册表。

+   使用您自己的私有注册表。

如果您在云平台上部署系统，并且该平台与其自己的图像注册表有良好的集成，或者如果您在云原生计算的精神中不管理自己的注册表，并且更喜欢让 Quay 等第三方为您完成，那么第一个选项是有意义的。

第二个选项（运行自己的容器注册表）可能是最佳选择，如果您需要对所有图像（包括基本图像和依赖项）进行额外控制。

# 根据需要授予对 Kubernetes 资源的访问权限

最小特权原则指导您仅向实际需要访问 Kubernetes 资源的服务授予权限（例如，Argo CD）。RBAC 在这里是一个很好的选择，因为默认情况下所有内容都被锁定，您可以明确添加权限。但是，要注意不要陷入给予通配符访问所有内容的陷阱，只是为了克服 RBAC 配置的困难。例如，让我们看一个具有以下规则的集群角色：

```
rules:
- apiGroups:
  - '*'
  resources:
  - '*'
  verbs:
  - '*'
- nonResourceURLs:
  - '*'
  verbs:
- '*'
```

这比禁用 RBAC 更糟糕，因为它会给您一种虚假的安全感。另一个更动态的选择是通过 Webhook 和外部服务器进行动态身份验证、授权和准入控制。这些给您提供了最大的灵活性。

# 使用配额来最小化爆炸半径

限制和配额是 Kubernetes 的机制，您可以控制分配给集群、Pod 和容器的各种有限资源，如 CPU 和内存。它们非常有用，有多种原因：

+   性能。

+   容量规划。

+   成本管理。

+   它们帮助 Kubernetes 根据资源利用率安排 Pod。

当您的工作负载在预算内运行时，一切都变得更可预测和更容易推理，尽管您必须做出努力来弄清楚实际需要多少资源，并随着时间的推移进行调整。这并不像听起来那么糟糕，因为通过水平 pod 自动缩放，您可以让 Kubernetes 动态调整服务的 pod 数量，即使每个 pod 都有非常严格的配额。

从安全的角度来看，如果攻击者获得对集群上运行的工作负载的访问权限，它将限制它可以使用的物理资源的数量。如今最常见的攻击之一就是用加密货币挖矿来饱和目标。类似的攻击类型是 fork 炸弹，它通过使一个恶意进程无法控制地复制自己来消耗所有可用资源。网络策略通过限制对网络上其他 pod 的访问来限制受损工作负载的爆炸半径。资源配额最小化了受损 pod 的主机节点上利用资源的爆炸半径。

有几种类型的配额，例如以下内容：

+   计算配额（CPU 和内存）

+   存储配额（磁盘和外部存储）

+   对象（Kubernetes 对象）

+   扩展资源（非 Kubernetes 资源，如 GPU）

资源配额非常微妙。您需要理解几个概念，例如单位和范围，以及请求和限制之间的区别。我将解释基础知识，并通过为 Delinkcious 用户服务添加资源配额来演示它们。为容器分配资源配额，因此您可以将其添加到容器规范中，如下所示：

```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: user-manager
  labels:
    svc: user
    app: manager
spec:
  replicas: 1
  selector:
    matchLabels:
      svc: user
      app: manager
  template:
    metadata:
      labels:
        svc: user
        app: manager
    spec:
      containers:
      - name: user-manager
        image: g1g1/delinkcious-user:0.3
        imagePullPolicy: Always
        ports:
        - containerPort: 7070
        resources:
          requests:
            memory: 64Mi
            cpu: 250m
          limits:
            memory: 64Mi
            cpu: 250m
```

资源下有两个部分：

+   **请求**：请求是容器为了启动而请求的资源。如果 Kubernetes 无法满足特定资源的请求，它将不会启动 pod。您的工作负载可以确保在其整个生命周期中分配了这么多 CPU 和内存，并且您可以将其存入银行。

在上面的块中，我指定了`64Mi`内存和`250m` CPU 单位的请求（有关这些单位的解释，请参见下一节）。

+   **限制**：限制是工作负载可能访问的资源的上限。超出其内存限制的容器可能会被杀死，并且整个 pod 可能会从节点中被驱逐。如果被杀死，Kubernetes 将重新启动容器，并在被驱逐时重新调度 pod，就像它对任何类型的故障一样。如果容器超出其 CPU 限制，它将不会被杀死，甚至可能会在一段时间内逃脱，但是由于 CPU 更容易控制，它可能只是得不到它请求的所有 CPU，并且会经常休眠以保持在其限制范围内。

通常，最好的方法是将请求指定为限制，就像我为用户管理器所做的那样。工作负载知道它已经拥有了它将来需要的所有资源，不必担心在同一节点上有其他饥饿的邻居竞争相同资源池的情况下试图接近限制。

虽然资源是针对每个容器指定的，但是当 pod 具有多个容器时，重要的是考虑整个 pod 的总资源请求（所有容器请求的总和）。这是因为 pod 总是作为一个单元进行调度。如果您有一个具有 10 个容器的 pod，每个容器都要求 2 Gib 的内存，那么这意味着您的 pod 需要一个具有 20 Gib 空闲内存的节点。

# 请求和限制的单位

您可以使用以下后缀来请求和限制内存：E、P、T、G、M 和 K。您还可以使用 2 的幂后缀（它们总是稍微大一些），即 Ei、Pi、Ti、Gi、Mi 和 Ki。您还可以只使用整数，包括字节的指数表示法。

以下大致相同：257,988,979, 258e6, 258M 和 246Mi。CPU 单位相对于托管环境如下：

+   1 个 AWS vCPU

+   1 个 GCP Core

+   1 个 Azure vCore

+   1 个 IBM vCPU

+   在具有超线程的裸机英特尔处理器上的 1 个超线程

您可以请求 CPU 的分辨率为 0.001 的分数。更方便的方法是使用 milliCPU 和带有`m`后缀的整数；例如，100 m 是 0.1 CPU。

# 实施安全上下文

有时，Pod 和容器需要提升的特权或访问节点。这对于您的应用工作负载来说将是非常罕见的。但是，在必要时，Kubernetes 具有一个安全上下文的概念，它封装并允许您配置多个 Linux 安全概念和机制。从安全的角度来看，这是至关重要的，因为它打开了一个从容器世界到主机机器的隧道。

以下是一些安全上下文涵盖的一些机制的列表：

+   允许（或禁止）特权升级

+   通过用户 ID 和组 ID 进行访问控制（`runAsUser`，`runAsGroup`）

+   能力与无限制的根访问相对

+   使用 AppArmor 和 seccomp 配置文件

+   SELinux 配置

有许多细节和交互超出了本书的范围。我只分享一个`SecurityContext`的例子：

```
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
spec:
  containers:
  - name: some-container
    image: g1g1/py-kube:0.2
    command: ["/bin/bash", "-c", "while true ; do sleep 10 ; done"]
    securityContext:
      runAsUser: 2000
      allowPrivilegeEscalation: false
      capabilities:
        add: ["NET_ADMIN", "SYS_TIME"]
      seLinuxOptions:
        level: "s0:c123,c456"
```

安全策略执行不同的操作，比如将容器内的用户 ID 设置为`2000`，并且不允许特权升级（获取 root），如下所示：

```
$ kubectl exec -it secure-pod bash

I have no name!@secure-pod:/$ whoami
whoami: cannot find name for user ID 2000

I have no name!@secure-pod:/$ sudo su
bash: sudo: command not found
```

安全上下文是集中化 Pod 或容器的安全方面的一个很好的方式，但在一个大型集群中，您可能安装第三方软件包（如 helm charts），很难确保每个 Pod 和容器都获得正确的安全上下文。这就是 Pod 安全策略出现的地方。

# 使用安全策略加固您的 Pod

Pod 安全策略允许您设置一个适用于所有新创建的 Pod 的全局策略。它作为访问控制的准入阶段的一部分执行。Pod 安全策略可以为没有安全上下文的 Pod 创建安全上下文，或者拒绝创建和更新具有不符合策略的安全上下文的 Pod。以下是一个安全策略，它将阻止 Pod 获取允许访问主机设备的特权状态：

```
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: disallow-privileged-access
spec:
  privileged: false
  allowPrivilegeEscalation: false
  # required fields.
  seLinux:
    rule: RunAsAny
  supplementalGroups:
    rule: RunAsAny
  runAsUser:
    rule: RunAsAny
  fsGroup:
    rule: RunAsAny
  volumes:
  - '*'
```

以下是一些很好的策略要执行（如果您不需要这些能力）：

+   只读根文件系统

+   控制挂载主机卷

+   防止特权访问和升级

最后，让我们确保我们将用于与 Kubernetes 集群一起工作的工具也是安全的。

# 加固您的工具链

Delinkcious 相当完善。它使用的主要工具是 Argo CD。Argo CD 可能会造成很大的损害，它在集群内运行并从 GitHub 拉取。然而，它有很多权限。在我决定将 Argo CD 作为 Delinkcious 的持续交付解决方案之前，我从安全的角度认真审查了它。Argo CD 的开发人员在考虑如何使 Argo CD 安全方面做得很好。他们做出了明智的选择，实施了这些选择，并记录了如何安全地运行 Argo CD。以下是 Argo CD 提供的安全功能：

+   通过 JWT 令牌对管理员用户进行身份验证

+   通过 RBAC 进行授权

+   通过 HTTPS 进行安全通信

+   秘密和凭证管理

+   审计

+   集群 RBAC

让我们简要地看一下它们。

# 通过 JWT 令牌对管理员用户进行身份验证

Argo CD 具有内置的管理员用户。所有其他用户必须使用**单点登录**（**SSO**）。对 Argo CD 服务器的身份验证始终使用**JSON Web Token**（**JWT**）。管理员用户的凭据也会转换为 JWT。

它还支持通过`/api/v1/projects/{project}/roles/{role}/token`端点进行自动化，生成由 Argo CD 本身签发的自动化令牌。这些令牌的范围有限，并且过期得很快。

# 通过 RBAC 进行授权

Argo CD 通过将用户的 JWT 组声明映射到 RBAC 角色来授权请求。这是行业标准认证与 Kubernetes 授权模型 RBAC 的非常好的结合。

# 通过 HTTPS 进行安全通信

Argo CD 的所有通信，以及其自身组件之间的通信，都是通过 HTTPS/TLS 完成的。

# 秘密和凭证管理

Argo CD 需要管理许多敏感信息，例如：

+   Kubernetes 秘密

+   Git 凭证

+   OAuth2 客户端凭证

+   对外部集群的凭证（当未安装在集群中时）

Argo CD 确保将所有这些秘密保留给自己。它永远不会通过在响应中返回它们或记录它们来泄露它们。所有 API 响应和日志都经过清理和编辑。

# 审计

您可以通过查看 git 提交日志来审计大部分活动，这会触发 Argo CD 中的所有内容。但是，Argo CD 还发送各种事件以捕获集群内的活动，以提供额外的可见性。这种组合很强大。

# 集群 RBAC

默认情况下，Argo CD 使用集群范围的管理员角色。这并不是必要的。建议将其写权限限制在需要管理的命名空间中。

# 总结

在本章中，我们认真看待了一个严肃的话题：安全。基于微服务的架构和 Kubernetes 对于支持关键任务目标并经常管理敏感信息的大规模企业分布式系统是最有意义的。除了开发和演进这样复杂系统的挑战之外，我们必须意识到这样的系统对攻击者非常诱人。

我们必须使用严格的流程和最佳实践来保护系统、用户和数据。从这里开始，我们涵盖了安全原则和最佳实践，我们也看到它们如何相互支持，以及 Kubernetes 如何致力于允许它们安全地开发和操作我们的系统。

我们还讨论了作为 Kubernetes 微服务安全基础的支柱：认证/授权/准入的三重 A，集群内外的安全通信，强大的密钥管理（静态和传输加密），以及分层安全策略。

在这一点上，您应该清楚地了解了您可以使用的安全机制，并且有足够的信息来决定如何将它们整合到您的系统中。安全永远不会完成，但利用最佳实践将使您能够在每个时间点上找到安全和系统其他要求之间的正确平衡。

在下一章中，我们将最终向世界开放 Delinkcious！我们将研究公共 API、负载均衡器以及我们需要注意的性能和安全性重要考虑因素。

# 进一步阅读

有许多关于 Kubernetes 安全性的良好资源。我收集了一些非常好的外部资源，这些资源将帮助您在您的旅程中：

+   Kubernetes 安全性：[`kubernetes-security.info/`](https://kubernetes-security.info/)

+   微软 SDL 实践：[`www.microsoft.com/en-us/securityengineering/sdl/practices`](https://www.microsoft.com/en-us/securityengineering/sdl/practices)

以下 Kubernetes 文档页面扩展了本章涵盖的许多主题：

+   网络策略：[`kubernetes.io/docs/concepts/services-networking/network-policies/`](https://kubernetes.io/docs/concepts/services-networking/network-policies/)

+   资源配额：[`kubernetes.io/docs/concepts/policy/resource-quotas/`](https://kubernetes.io/docs/concepts/policy/resource-quotas/)

+   为 Pod 或容器配置安全上下文：[`kubernetes.io/docs/tasks/configure-pod-container/security-context/`](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
