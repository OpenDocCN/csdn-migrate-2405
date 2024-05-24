# Docker AWS 教程（六）

> 原文：[`zh.annas-archive.org/md5/13D3113D4BA58CEA008B572AB087A5F5`](https://zh.annas-archive.org/md5/13D3113D4BA58CEA008B572AB087A5F5)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十三章：持续交付 ECS 应用程序

**持续交付**是创建一个可重复和可靠的软件发布过程的实践，以便您可以频繁且按需地将新功能部署到生产环境，成本和风险更低。采用持续交付有许多好处，如今越来越多的组织正在采用它，以更快地将功能推向市场，提高客户满意度，并降低软件交付成本。

实施持续交付需要在软件交付的端到端生命周期中实现高度自动化。到目前为止，在这门课程中，您已经使用了许多支持自动化和持续交付的技术。例如，Docker 本身带来了高度自动化，并促进了可重复和一致的构建过程，这些都是持续交付的关键组成部分。`todobackend`存储库中的 make 工作流进一步实现了这一点，自动化了 Docker 镜像的完整测试、构建和发布工作流程。在整个课程中，我们还广泛使用了 CloudFormation，它使我们能够以完全自动化的方式创建、更新和销毁完整的 AWS 环境，并且可以轻松地以可靠和一致的方式部署新功能（以新的 Docker 镜像形式）。持续交付将所有这些功能和能力整合在一起，创建了一个端到端的软件变更交付过程，从开发和提交源代码的时间到回归测试和部署到生产的时间。为了实现这种端到端的协调和自动化，我们需要采用专为此目的设计的新工具，AWS 提供了一系列服务来实现这一点，包括 AWS CodePipeline、CodeBuild 和 CloudFormation。

在本章中，您将学习如何实现一个端到端的持续交付流水线（使用 CodePipeline、CodeBuild 和 CloudFormation），该流水线将持续测试、构建和发布 Docker 镜像，然后持续将新构建的 Docker 镜像部署到非生产环境。该流水线还将支持对生产环境进行受控发布，自动创建必须经过审查和批准的变更集，然后才能将新变更部署到生产环境。

本章将涵盖以下主题：

+   介绍 CodePipeline 和 CodeBuild

+   创建自定义 CodeBuild 容器

+   为您的应用程序存储库添加 CodeBuild 支持

+   使用 CodePipeline 创建持续集成流水线

+   使用 CodePipeline 创建持续部署流水线

+   持续将您的应用程序交付到生产环境

# 技术要求

以下列出了完成本章所需的技术要求：

+   AWS 账户的管理员访问权限。

+   本地 AWS 配置文件，根据第三章的说明进行配置。

+   AWS CLI 版本 1.15.71 或更高

+   本章继续自第十二章，因此需要您成功完成第十二章中定义的所有配置任务。

+   本章要求您将`todobackend`和`todobackend-aws`存储库发布到您具有管理访问权限的 GitHub 账户。

以下 GitHub URL 包含本章中使用的代码示例：[`github.com/docker-in-aws/docker-in-aws/tree/master/ch13`](https://github.com/docker-in-aws/docker-in-aws/tree/master/ch13)

查看以下视频以查看代码的实际操作：

[`bit.ly/2BVGMYI`](http://bit.ly/2BVGMYI)

# 介绍 CodePipeline 和 CodeBuild

CodePipeline 和 CodeBuild 是 AWS 开发工具组合中的两项服务，与我们在本书中广泛使用的 CloudFormation 服务一起，为创建完整和全面的持续交付解决方案提供了构建块，为您的应用程序从开发到生产铺平道路。

CodePipeline 允许您创建复杂的流水线，将应用程序的源代码、构建、测试和发布应用程序工件，然后将应用程序部署到非生产和生产环境中。这些流水线的顶层构建模块是阶段，它们必须始终以包含一个或多个流水线的源材料的源阶段开始，例如应用程序的源代码仓库。然后，每个阶段可以由一个或多个操作组成，这些操作会产生一个工件，可以在流水线的后续阶段中使用，或者实现期望的结果，例如部署到一个环境。您可以按顺序或并行定义操作，这使您能够编排几乎任何您想要的场景；例如，我已经使用 CodePipeline 以高度受控的方式编排了完整、复杂的多应用程序环境的部署，这样可以轻松地进行可视化和管理。

每个 CodePipeline 流水线必须定义至少两个阶段，我们将在最初看到一个示例，当我们创建一个包括源阶段（从源代码仓库收集应用程序源代码）和构建阶段（从源阶段收集的应用程序源代码测试、构建和发布应用程序工件）的持续集成流水线。

理解这里的一个重要概念是“工件”的概念。CodePipeline 中的许多操作都会消耗输入工件并产生输出工件，一个操作消耗早期操作的输出的能力是 CodePipeline 工作原理的本质。

例如，以下图表说明了我们将创建的初始持续集成流水线：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/27880320-80ab-4e17-8106-8fc29ba82459.png)持续集成流水线

在上图中，**源阶段**包括一个与您的 todobackend GitHub 存储库相关联的**源操作**。每当对 GitHub 存储库进行提交更改时，此操作将下载最新的源代码，并生成一个输出工件，将您的源代码压缩并使其可用于紧随其后的构建阶段。**构建阶段**有一个**构建操作**，它将您的源操作输出工件作为输入，然后测试、构建和发布 Docker 镜像。上图中的**构建操作**由 AWS CodeBuild 服务执行，该服务是一个完全托管的构建服务，为按需运行构建作业提供基于容器的构建代理。CodePipeline 确保 CodeBuild 构建作业提供了一个包含应用程序源代码的输入工件，这样 CodeBuild 就可以运行本地测试、构建和发布工作流程。

到目前为止，我们已经讨论了 CodePipeline 中源和构建阶段的概念；您在流水线中将使用的另一个常见阶段是部署阶段，在该阶段中，您将应用程序工件部署到目标环境。以下图示了如何扩展上图中显示的流水线，以持续部署您的应用程序：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/a2ac7b82-63b4-4d97-a803-2126e603a611.png)持续部署流水线

在上图中，添加了一个新阶段（称为**Dev 阶段**）；它利用 CodePipeline 与 CloudFormation 的集成将应用程序部署到非生产环境中，我们称之为 dev（开发）。因为我们使用 CloudFormation 进行部署，所以需要提供一个 CloudFormation 堆栈进行部署，这是通过在源阶段添加 todobackend-aws 存储库作为另一个源操作来实现的。**部署操作**还需要另一个输入工件，用于定义要部署的 Docker 镜像的标签，这是通过构建阶段中的 CodeBuild 构建操作的输出工件（称为`ApplicationVersion`）提供的。如果现在这些都不太明白，不要担心；我们将在本章中涵盖所有细节并设置这些流水线，但至少了解阶段、操作以及如何在它们之间传递工件以实现所需的结果是很重要的。

最后，CodePipeline 可以支持部署到多个环境，本章的最后一部分将扩展我们的流水线，以便在生产环境中执行受控发布，如下图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/d3186f6c-4547-4471-9e0e-a4d4fa6b7191.png)持续交付流水线

在前面的图表中，流水线添加了一个新阶段（称为**生产阶段**），只有在您的应用程序成功部署在开发环境中才能执行。与开发阶段的持续部署方法不同，后者立即部署到开发环境中，生产阶段首先创建一个 CloudFormation 变更集，该变更集标识了部署的所有更改，然后触发一个手动批准操作，需要某人审查变更集并批准或拒绝更改。假设更改得到批准，生产阶段将部署更改到生产环境中，这些操作集合将共同提供对生产（或其他受控）环境的受控发布的支持。

现在您已经对 CodePipeline 有了一个高层次的概述，让我们开始创建我们在第一个图表中讨论的持续集成流水线。在构建这个流水线之前，我们需要构建一个自定义的构建容器，以满足 todobackend 存储库中定义的 Docker 工作流的要求，并且我们还需要添加对 CodeBuild 的支持，之后我们可以在 CodePipeline 中创建我们的流水线。

# 创建自定义 CodeBuild 容器

AWS CodeBuild 提供了一个构建服务，使用容器构建代理来执行您的构建。CodeBuild 提供了许多 AWS 策划的镜像，针对特定的应用程序语言和/或平台，比如[Python，Java，PHP 等等](https://docs.aws.amazon.com/codebuild/latest/userguide/build-env-ref-available.html)。CodeBuild 确实提供了一个专为构建 Docker 镜像而设计的镜像；然而，这个镜像有一定的限制，它不包括 AWS CLI、GNU make 和 Docker Compose 等工具，而我们构建 todobackend 应用程序需要这些工具。

虽然您可以在 CodeBuild 中运行预构建步骤来安装额外的工具，但这种方法会减慢构建速度，因为安装额外工具将在每次构建时都会发生。CodeBuild 确实支持使用自定义镜像，这允许您预打包所有应用程序构建所需的工具。

对于我们的用例，CodeBuild 构建环境必须包括以下内容：

+   访问 Docker 守护程序，鉴于构建建立了一个多容器环境来运行集成和验收测试

+   Docker Compose

+   GNU Make

+   AWS CLI

您可能想知道如何满足第一个要求，因为您的 CodeBuild 运行时环境位于一个隔离的容器中，无法直接访问其正在运行的基础架构。Docker 确实支持**Docker 中的 Docker**（**DinD**）的概念，其中 Docker 守护程序在您的 Docker 容器内运行，允许您安装一个可以构建 Docker 镜像并使用工具如 Docker Compose 编排多容器环境的 Docker 客户端。

Docker 中的 Docker 实践有些有争议，并且是使用 Docker 更像虚拟机而不是容器的一个例子。然而，为了运行构建，这种方法是完全可以接受的。

# 定义自定义 CodeBuild 容器

首先，我们需要构建我们的自定义 CodeBuild 镜像，我们将在名为`Dockerfile.codebuild`的 Dockerfile 中定义，该文件位于 todobackend-aws 存储库中。

以下示例显示了 Dockerfile：

```
FROM docker:dind

RUN apk add --no-cache bash make python3 && \
    pip3 install --no-cache-dir docker-compose awscli
```

因为 Docker 发布了一个 Docker 中的 Docker 镜像，我们可以简单地基于这个镜像进行定制；我们免费获得了 Docker 中的 Docker 功能。DinD 镜像基于 Alpine Linux，并已经包含所需的 Docker 守护程序和 Docker 客户端。接下来，我们将添加我们构建所需的特定工具。这包括 bash shell，GNU make 和 Python 3 运行时，这是安装 Docker Compose 和 AWS CLI 所需的。

您现在可以使用`docker build`命令在本地构建此镜像，如下所示：

```
> docker build -t codebuild -f Dockerfile.codebuild .
Sending build context to Docker daemon 405.5kB
Step 1/2 : FROM docker:dind
dind: Pulling from library/docker
ff3a5c916c92: Already exists
1a649ea86bca: Pull complete
ce35f4d5f86a: Pull complete
d0600fe571bc: Pull complete
e16e21051182: Pull complete
a3ea1dbce899: Pull complete
133d8f8629ec: Pull complete
71a0f0a757e5: Pull complete
0e081d1eb121: Pull complete
5a14be8d6d21: Pull complete
Digest: sha256:2ca0d4ee63d8911cd72aa84ff2694d68882778a1c1f34b5a36b3f761290ee751
Status: Downloaded newer image for docker:dind
 ---> 1f44348b3ad5
Step 2/2 : RUN apk add --no-cache bash make python3 && pip3 install --no-cache-dir docker-compose awscli
 ---> Running in d69027d58057
...
...
Successfully built 25079965c64c
Successfully tagged codebuild:latest
```

在上面的示例中，使用名称为`codebuild`创建新构建的 Docker 镜像。现在这样做是可以的，但是我们需要将此 CodeBuild 发布到**弹性容器注册表**（**ECR**），以便 CodeBuild 可以使用。

# 为自定义 CodeBuild 容器创建存储库

现在，您已经构建了一个自定义的 CodeBuild 图像，您需要将图像发布到 CodeBuild 可以从中拉取图像的位置。如果您使用 ECR，通常会将此图像发布到 ECR 中的存储库，这就是我们将采取的方法。

首先，您需要在`todobackend-aws`文件夹的根目录中的`ecr.yml`文件中添加一个新的存储库，该文件夹是您在本章中创建的：

```
AWSTemplateFormatVersion: "2010-09-09"

Description: ECR Resources

Resources:
  CodebuildRepository:
 Type: AWS::ECR::Repository
 Properties:
RepositoryName: docker-in-aws/codebuild
 RepositoryPolicyText:
 Version: '2008-10-17'
 Statement:
 - Sid: CodeBuildAccess
 Effect: Allow
 Principal:
 Service: codebuild.amazonaws.com
 Action:
 - ecr:GetDownloadUrlForLayer
 - ecr:BatchGetImage
 - ecr:BatchCheckLayerAvailability
  TodobackendRepository:
    Type: AWS::ECR::Repository
  ...
  ...
```

在前面的示例中，您创建了一个名为`docker-in-aws/codebuild`的新存储库，这将导致一个名为`<account-id>.dkr.ecr.<region>.amazonaws.com/docker-in-aws/codebuild`的完全限定存储库（例如`385605022855.dkr.ecr.us-east-1.amazonaws.com/docker-in-aws/codebuild`）。请注意，您必须授予 CodeBuild 服务拉取访问权限，因为 CodeBuild 需要拉取图像以运行作为其构建容器。

您现在可以使用`aws cloudformation deploy`命令将更改部署到 ECR 堆栈，您可能还记得来自章节《使用 ECR 发布 Docker 镜像》的命令，部署到名为 ecr-repositories 的堆栈：

```
> export AWS_PROFILE=docker-in-aws
> aws cloudformation deploy --template-file ecr.yml --stack-name ecr-repositories
Enter MFA code for arn:aws:iam::385605022855:mfa/justin.menga:

Waiting for changeset to be created..
Waiting for stack create/update to complete
Successfully created/updated stack - ecr-repositories
```

部署完成后，您需要使用您之前创建的图像的完全限定名称重新标记图像，然后您可以登录到 ECR 并发布图像：

```
> docker tag codebuild 385605022855.dkr.ecr.us-east-1.amazonaws.com/docker-in-aws/codebuild
> eval $(aws ecr get-login --no-include-email)
WARNING! Using --password via the CLI is insecure. Use --password-stdin.
Login Succeeded
> docker push 385605022855.dkr.ecr.us-east-1.amazonaws.com/docker-in-aws/codebuild
The push refers to repository [385605022855.dkr.ecr.us-east-1.amazonaws.com/docker-in-aws/codebuild]
770fb042ae3b: Pushed
0cdc6e0d843b: Pushed
395fced17f47: Pushed
3abf4e550e49: Pushed
0a6dfdbcc220: Pushed
27760475e1ac: Pushed
5270ef39cae0: Pushed
2c88066e123c: Pushed
b09386d6aa0f: Pushed
1ed7a5e2d1b3: Pushed
cd7100a72410: Pushed
latest: digest:
sha256:858becbf8c64b24e778e6997868f587b9056c1d1617e8d7aa495a3170761cf8b size: 2618
```

# 向您的应用程序存储库添加 CodeBuild 支持

每当您创建 CodeBuild 项目时，必须定义 CodeBuild 应如何测试和构建应用程序源代码，然后发布应用程序工件和/或 Docker 镜像。 CodeBuild 在构建规范中定义这些任务，构建规范提供了 CodeBuild 代理在运行构建时应执行的构建说明。

CodeBuild 允许您以多种方式提供构建规范：

+   **自定义**：CodeBuild 查找项目的源存储库中定义的文件。默认情况下，这是一个名为`buildspec.yml`的文件；但是，您还可以配置一个自定义文件，其中包含您的构建规范。

+   **预配置**：当您创建 CodeBuild 项目时，可以在项目设置的一部分中定义构建规范。

+   按需：如果您使用 AWS CLI 或 SDK 启动 CodeBuild 构建作业，您可以覆盖预配置或自定义的构建规范

一般来说，我建议使用自定义方法，因为它允许存储库所有者（通常是您的开发人员）独立配置和维护规范；这是我们将采取的方法。

以下示例演示了在名为`buildspec.yml`的文件中向 todobackend 存储库添加构建规范：

```
version: 0.2

phases:
  pre_build:
    commands:
      - nohup /usr/local/bin/dockerd --host=unix:///var/run/docker.sock --storage-driver=overlay&
      - timeout -t 15 sh -c "until docker info; do echo .; sleep 1; done"
      - export BUILD_ID=$(echo $CODEBUILD_BUILD_ID | sed 's/^[^:]*://g')
      - export APP_VERSION=$CODEBUILD_RESOLVED_SOURCE_VERSION.$BUILD_ID
      - make login
  build:
    commands:
      - make test
      - make release
      - make publish
  post_build:
    commands:
      - make clean
      - make logout
```

构建规范首先指定了必须包含在每个构建规范中的版本，本书编写时最新版本为`0.2`。接下来，您定义了阶段序列，这是必需的，定义了 CodeBuild 将在构建的各个阶段运行的命令。在前面的示例中，您定义了三个阶段：

+   `pre_build`：CodeBuild 在构建之前运行的命令。在这里，您可以运行诸如登录到 ECR 或构建成功运行所需的任何其他命令。

+   `build`：这些命令运行您的构建步骤。

+   `post_build`：CodeBuild 在构建后运行的命令。这些通常涉及清理任务，例如退出 ECR 并删除临时文件。

您可以在[`docs.aws.amazon.com/codebuild/latest/userguide/build-spec-ref.html`](https://docs.aws.amazon.com/codebuild/latest/userguide/build-spec-ref.html)找到有关 CodeBuild 构建规范的更多信息。

在`pre_build`阶段，您执行以下操作：

+   前两个命令用于在自定义 CodeBuild 镜像中启动 Docker 守护程序；`nohup`命令将 Docker 守护程序作为后台任务启动，而`timeout`命令用于确保 Docker 守护程序已成功启动，然后再继续尝试。

+   导出一个`BUILD_ID`环境变量，用于将构建信息添加到将为您的构建生成的应用程序版本中。此`BUILD_ID`值将被添加到构建阶段期间构建的 Docker 镜像附加的应用程序版本标记中，因此，它只能包含与 Docker 标记格式兼容的字符。CodeBuild 作业 ID 通过`CODEBUILD_BUILD_ID`环境变量暴露给您的构建代理，并且格式为`<project-name>:<job-id>`，其中`<job-id>`是 UUID 值。CodeBuild 作业 ID 中的冒号在 Docker 标记中不受支持；因此，您可以使用`sed`表达式剥离作业 ID 的`<project-name>`部分，只留下将包含在 Docker 标记中的作业 ID 值。

+   导出`APP_VERSION`环境变量，在 Makefile 中用于定义构建的 Docker 镜像上标记的应用程序版本。当您在 CodeBuild 与 CodePipeline 一起使用时，重要的是要了解，呈现给 CodeBuild 的源构件实际上是位于 S3 存储桶中的一个压缩版本，CodePipeline 在从源代码库克隆源代码后创建。CodePipeline 不包括任何 Git 元数据；因此，在 todobackend Makefile 中的`APP_VERSION`指令 - `export APP_VERSION ?= $(shell git rev-parse --short HEAD` - 将失败，因为 Git 客户端将没有任何可用的 Git 元数据。幸运的是，在 GNU Make 中的`?=`语法意味着如果环境中已经定义了前述环境变量的值，那么就使用该值。因此，我们可以在 CodeBuild 环境中导出`APP_VERSION`，并且 Make 将只使用配置的值，而不是运行 Git 命令。在前面的示例中，您从一个名为`CODEBUILD_RESOLVED_SOURCE_VERSION`的变量构造了`APP_VERSION`，它是源代码库的完整提交哈希，并由 CodePipeline 设置。您还附加了在前一个命令中计算的`BUILD_ID`变量，这允许您将特定的 Docker 镜像构建跟踪到一个 CodeBuild 构建作业。

+   使用源代码库中包含的`make login`命令登录到 ECR。

一旦`pre_build`阶段完成，构建阶段就很简单了，只需执行我们在本书中迄今为止手动执行的各种构建步骤。最终的`post_build`阶段运行`make clean`任务来拆除 Docker Compose 环境，然后通过运行`make logout`命令删除任何本地 ECR 凭据。

一个重要的要点是`post_build`阶段始终运行，即使构建阶段失败也是如此。这意味着您应该仅将`post_build`任务保留为无论构建是否通过都会运行的操作。例如，您可能会尝试将`make publish`任务作为`post_build`步骤运行；但是，如果您这样做，且前一个构建阶段失败，CodeBuild 仍将尝试运行 make publish 任务，因为它被定义为`post_build`步骤。将 make publish 任务放置在构建阶段的最后一个操作确保如果 make test 或 make release 失败，构建阶段将立即以错误退出，绕过 make publish 操作并继续执行`post_build`步骤中的清理任务。

您可以在[`docs.aws.amazon.com/codebuild/latest/userguide/view-build-details.html#view-build-details-phases`](https://docs.aws.amazon.com/codebuild/latest/userguide/view-build-details.html#view-build-details-phases)找到有关所有 CodeBuild 阶段以及它们在成功/失败时是否执行的更多信息。

您需要执行的最后一步是将更改提交并推送到您的 Git 存储库，以便在配置 CodePipeline 和 CodeBuild 时新创建的`buildspec.yml`文件可用：

```
> git add -A
> git commit -a -m "Add build specification"
[master ab7ac16] Add build specification
 1 file changed, 19 insertions(+)
 create mode 100644 buildspec.yml
> git push
Counting objects: 3, done.
Delta compression using up to 8 threads.
Compressing objects: 100% (3/3), done.
Writing objects: 100% (3/3), 584 bytes | 584.00 KiB/s, done.
Total 3 (delta 1), reused 0 (delta 0)
remote: Resolving deltas: 100% (1/1), completed with 1 local object.
To github.com:docker-in-aws/todobackend.git
   5fdbe62..ab7ac16 master -> master
```

# 使用 CodePipeline 创建持续集成管道

现在，您已经建立了支持 CodeBuild 的先决条件，您可以创建一个持续集成的 CodePipeline 管道，该管道将使用 CodeBuild 来测试、构建和发布您的 Docker 镜像。持续集成侧重于不断将应用程序源代码更改合并到主分支，并通过创建构建并针对其运行自动化测试来验证更改。

根据本章第一个图表，当您为持续集成配置 CodePipeline 管道时，通常涉及两个阶段：

+   **源阶段**：下载源应用程序存储库，并使其可用于后续阶段。对于我们的用例，您将把 CodePipeline 连接到 GitHub 存储库的主分支，对该存储库的后续提交将自动触发新的管道执行。

+   **构建阶段**：运行在源应用程序存储库中定义的构建、测试和发布工作流程。对于我们的用例，我们将使用 CodeBuild 来运行此阶段，它将执行源存储库中定义的构建任务`buildspec.yml`文件，这是在本章前面创建的。

# 使用 AWS 控制台创建 CodePipeline 管道

要开始，请首先从 AWS 控制台中选择**服务**，然后选择**CodePipeline**。如果这是您第一次使用 CodePipeline，您将看到一个介绍页面，您可以单击“开始”按钮开始 CodePipeline 向导。

首先要求您为管道输入名称，然后单击“下一步”，您将被提示设置源提供程序，该提供程序定义将在您的管道中使用的源存储库或文件的提供程序：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/db98d662-8e5f-410b-8afe-1492bf859b6d.png)

在从下拉菜单中选择 GitHub 后，单击“连接到 GitHub”按钮，这将重定向您到 GitHub，在那里您将被提示登录并授予 CodePipeline 对您的 GitHub 帐户的访问权限：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/9b6c00bb-874c-48ea-9185-b8f5d82bc591.png)

点击授权 aws-codesuite 按钮后，您将被重定向回 CodePipeline 向导，您可以选择 todobackend 存储库和主分支：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/44a9298c-0671-4f61-b714-fae334ce3b7c.png)

如果单击“下一步”，您将被要求选择构建提供程序，该提供程序定义将在您的管道中执行构建操作的构建服务的提供程序：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/4ebf9916-9332-4ea5-b7c5-89c361a8123c.png)

在选择 AWS CodeBuild 并选择“创建新的构建项目”选项后，您需要配置构建项目，如下所示：

+   环境镜像：对于环境镜像，请选择“指定 Docker 镜像”选项，然后将环境类型设置为 Linux，自定义镜像类型设置为 Amazon ECR；然后选择您在本章前面发布的`docker-in-aws/codebuild repository/latest`镜像。

+   高级：确保设置特权标志，如下面的屏幕截图所示。每当您在 Docker 中运行 Docker 镜像时，这是必需的：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/132bf4f5-0a72-458b-ab05-419745b1bae5.png)

完成构建项目配置后，请确保在单击“下一步”继续之前，单击“保存构建项目”。

在下一阶段，您将被要求定义一个部署阶段。在这一点上，我们只想执行测试、构建和发布我们的 Docker 应用程序的持续集成任务，因此选择“无部署”选项，然后单击“下一步”继续：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/c5d4b3fa-d8ea-4c84-968d-565b491923cf.png)

最后一步是配置 CodePipeline 可以假定的 IAM 角色，以执行管道中的各种构建和部署任务。单击“创建角色”按钮，这将打开一个新窗口，要求您创建一个新的 IAM 角色，具有适当的权限，供 CodePipeline 使用：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/d924fc71-95b4-41d3-a6e8-29ad258664cf.png)

在审阅政策文件后，单击“允许”，这将在 CodePipeline 向导中选择新角色。最后，单击“下一步”，审查管道配置，然后单击“创建管道”以创建新管道。

在这一点上，您的管道将被创建，并且您将被带到您的管道的管道配置视图。每当您第一次为管道创建管道时，CodePipeline 将自动触发管道的第一次执行，几分钟后，您应该注意到管道的构建阶段失败了：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/a014138c-d861-4c94-9165-871b35dc3908.png)

要了解有关构建失败的更多信息，请单击“详细信息”链接，这将弹出有关失败的更多详细信息，并且还将包括到构建失败的 CodeBuild 作业的链接。如果单击此链接并向下滚动，您会看到失败发生在`pre_build`阶段，并且在构建日志中，问题与 IAM 权限问题有关：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/4640dbba-7a70-49ac-8992-d1d43e7b3d1c.png)

问题在于 CodePipeline 向导期间自动创建的 IAM 角色不包括登录到 ECR 的权限。

为了解决这个问题，打开 IAM 控制台，从左侧菜单中选择角色，找到由向导创建的`code-build-todobackend-service-role`。在权限选项卡中，点击附加策略，找到`AmazonEC2ContainerRegistryPowerUser`托管策略，并点击附加策略按钮。power user 角色授予登录、拉取和推送权限，因为我们将作为构建工作流的一部分发布到 ECR，所以需要这个级别的访问权限。完成配置后，角色的权限选项卡应该与下面的截图一样：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/6e394fa4-1f87-4edd-9edd-6b53978de78a.png)

现在您已经解决了权限问题，请导航回到您的流水线的 CodePipeline 详细信息视图，点击构建阶段的重试按钮，并确认重试失败的构建。这一次，几分钟后，构建应该成功完成，您可以使用`aws ecr list-images`命令来验证已经发布了新的镜像到 ECR：

```
> aws ecr list-images --repository-name docker-in-aws/todobackend \
 --query imageIds[].imageTag --output table
-----------------------------------------------------------------------------------
| ListImages                                                                      |
+---------------------------------------------------------------------------------+
| 5fdbe62                                                                         |
| latest                                                                          |
| ab7ac1649e8ef4d30178c7f68899628086155f1d.10f5ef52-e3ff-455b-8ffb-8b760b7b9c55   |
+---------------------------------------------------------------------------------+
```

请注意，最后发布的镜像的格式为`<long commit hash>`.`<uuid>`，其中`<uuid>`是 CodeBuild 作业 ID，证实 CodeBuild 已成功将新镜像发布到 ECR。

# 使用 CodePipeline 创建持续交付流水线

此时，您已经拥有了一个持续集成流水线，每当在主分支上推送提交到您的源代码库时，它将自动发布新的 Docker 镜像。在某个时候，您将希望将 Docker 镜像部署到一个环境（也许是一个分段环境，在那里您可以运行一些端到端测试来验证您的应用程序是否按预期工作），然后再部署到为最终用户提供服务的生产环境。虽然您可以通过手动更新`ApplicationImageTag`输入来手动部署这些更改到 todobackend 堆栈，但理想情况下，您希望能够自动将这些更改持续部署到至少一个环境中，这样可以立即让开发人员、测试人员和产品经理访问，并允许从参与应用程序开发的关键利益相关者那里获得快速反馈。

这个概念被称为持续部署。换句话说，每当您持续集成和构建经过测试的软件构件时，您就会持续部署这些构件。持续部署在当今非常普遍，特别是如果您部署到非生产环境。远不那么普遍的是一直持续部署到生产环境。要实现这一点，您必须具有高度自动化的部署后测试，并且至少根据我的经验，这对大多数组织来说仍然很难实现。更常见的方法是持续交付，您可以将其视为一旦确定您的发布准备好投入生产，就能自动部署到生产的能力。

持续交付允许常见的情况，即您需要对生产环境进行受控发布，而不是一旦发布可用就持续部署到生产环境。这比一直持续部署到生产环境更可行，因为它允许在选择部署到生产环境之前对非生产环境进行手动测试。

现在您已经了解了持续交付的背景，让我们扩展我们的管道以支持持续交付。

CodePipeline 包括对 ECS 作为部署目标的支持，您可以将持续集成管道发布的新镜像部署到目标 ECS 集群和 ECS 服务。在本章中，我将使用 CloudFormation 来部署应用程序更改；但是，您可以在[`docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs-cd-pipeline.html`](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs-cd-pipeline.html)了解更多关于 ECS 部署机制的信息。

这一阶段的第一步是配置您的代码更改的持续部署到非生产环境，这需要您执行以下配置操作，这些操作将在后续详细讨论：

+   在您的源代码存储库中发布版本信息

+   为您的部署存储库添加 CodePipeline 支持

+   将您的部署存储库添加到 CodePipeline

+   为您的构建操作添加一个输出构件

+   为 CloudFormation 部署创建一个 IAM 角色

+   在管道中添加一个部署阶段

# 在您的源代码存储库中发布版本信息

我们流水线的一个关键要求是能够将新构建的 Docker 镜像部署到我们的 AWS 环境中。目前，CodePipeline 并不真正了解发布的 Docker 镜像标记。我们知道该标记在 CodeBuild 环境中配置，但 CodePipeline 并不了解这一点。

为了使用在 CodeBuild 构建阶段生成的 Docker 镜像标记，您需要生成一个输出构件，首先由 CodeBuild 收集，然后在 CodePipeline 中的未来部署阶段中提供。

为了做到这一点，您必须首先定义 CodeBuild 应该收集的构件，您可以通过在 todobackend 存储库中的`buildspec.yml`构建规范中添加`artifacts`参数来实现这一点：

```
version: 0.2

phases:
  pre_build:
    commands:
      - nohup /usr/local/bin/dockerd --host=unix:///var/run/docker.sock --storage-driver=overlay&
      - timeout -t 15 sh -c "until docker info; do echo .; sleep 1; done"
      - export BUILD_ID=$(echo $CODEBUILD_BUILD_ID | sed 's/^[^:]*://g')
      - export APP_VERSION=$CODEBUILD_RESOLVED_SOURCE_VERSION.$BUILD_ID
      - make login
  build:
    commands:
      - make test
      - make release
      - make publish
      - make version > version.json
  post_build:
    commands:
      - make clean
      - make logout

artifacts:
 files:
 - version.json
```

在上面的示例中，`artifacts`参数配置 CodeBuild 在位置`version.json`查找构件。请注意，您还需要向构建阶段添加一个额外的命令，该命令将`make version`命令的输出写入`version.json`文件，CodeBuild 期望在那里找到构件。

在这一点上，请确保您提交并推送更改到 todobackend 存储库，以便将来的构建可以使用这些更改。

# 向部署存储库添加 CodePipeline 支持

当您使用 CodePipeline 使用 CloudFormation 部署您的环境时，您需要确保您可以提供一个包含输入堆栈参数、堆栈标记和堆栈策略配置的配置文件。该文件必须以 JSON 格式实现，如[`docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/continuous-delivery-codepipeline-cfn-artifacts.html#w2ab2c13c15c15`](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/continuous-delivery-codepipeline-cfn-artifacts.html#w2ab2c13c15c15)中定义的那样，因此我们需要修改`todobackend-aws`存储库中输入参数文件的格式，该文件目前以`<parameter>=<value>`格式位于名为`dev.cfg`的文件中。根据所引用的文档，您所有的输入参数都需要位于一个名为`Parameters`的键下的 JSON 文件中，您可以在`todobackend-aws`存储库的根目录下定义一个名为`dev.json`的新文件。

```
{ 
  "Parameters": {
    "ApplicationDesiredCount": "1",
    "ApplicationImageId": "ami-ec957491",
    "ApplicationImageTag": "latest",
    "ApplicationSubnets": "subnet-a5d3ecee,subnet-324e246f",
    "VpcId": "vpc-f8233a80"
  }
}
```

在前面的例子中，请注意我已将`ApplicationImageTag`的值更新为`latest`。这是因为我们的流水线实际上会动态地从流水线的构建阶段获取`ApplicationImageTag`输入的值，而`latest`值是一个更安全的默认值，以防您希望从命令行手动部署堆栈。

此时，`dev.cfg`文件是多余的，可以从您的存储库中删除；但是，请注意，鉴于`aws cloudformation deploy`命令期望以`<parameter>=<value>`格式提供输入参数，您需要修改手动从命令行运行部署的方式。

您可以解决这个问题的一种方法是使用`jq`实用程序将新的`dev.json`配置文件转换为所需的`<parameter>=<value>`格式：

```
> aws cloudformation deploy --template-file stack.yml --stack-name todobackend \
    --parameter-overrides $(cat dev.json | jq -r '.Parameters|to_entries[]|.key+"="+.value') \
    --capabilities CAPABILITY_NAMED_IAM
```

这个命令现在相当冗长，为了简化运行这个命令，您可以向`todobackend-aws`存储库添加一个简单的 Makefile：

```
.PHONY: deploy

deploy/%:
  aws cloudformation deploy --template-file stack.yml --stack-name todobackend-$* \
    --parameter-overrides $$(cat $*.json | jq -r '.Parameters|to_entries[]|.key+"="+.value') \
    --capabilities CAPABILITY_NAMED_IAM
```

在前面的例子中，任务名称中的`%`字符捕获了一个通配文本值，无论何时执行`make deploy`命令。例如，如果您运行`make deploy`/`dev`，那么`%`字符将捕获`dev`，如果您运行`make deploy`/`prod`，那么捕获的值将是`prod`。然后，您可以使用`$*`变量引用捕获的值，您可以看到我们已经在堆栈名称（`todobackend-$*`，在前面的例子中会扩展为`todobackend-dev`和`todobackend-prod`）和用于 cat`dev.json`或`prod.json`文件的命令中替换了这个变量。请注意，因为在本书中我们一直将堆栈命名为`todobackend`，所以这个命令对我们来说不太适用，但是如果您将堆栈重命名为`todobackend-dev`，这个命令将使手动部署到特定环境变得更加容易。

在继续之前，您需要添加新的`dev.json`文件，提交并推送更改到源 Git 存储库，因为我们将很快将`todobackend-aws`存储库添加为 CodePipeline 流水线中的另一个源。

# 为 CloudFormation 部署创建 IAM 角色

当您使用 CodePipeline 部署 CloudFormation 堆栈时，CodePipeline 要求您指定一个 IAM 角色，该角色将由 CloudFormation 服务来部署您的堆栈。CloudFormation 支持指定 CloudFormation 服务将承担的 IAM 角色，这是一个强大的功能，允许更高级的配置场景，例如从中央构建账户进行跨账户部署。此角色必须指定 CloudFormation 服务作为可信实体，可以承担该角色；因此，通常不能使用为人员访问创建的管理角色，例如您在本书中一直在使用的管理员角色。

要创建所需的角色，请转到 IAM 控制台，从左侧菜单中选择“角色”，然后点击“创建角色”按钮。在“选择服务”部分，选择“CloudFormation”，然后点击“下一步：权限”继续。在“附加权限策略”屏幕上，您可以创建或选择一个适当的策略，其中包含创建堆栈所需的各种权限。为了保持简单，我将只选择“AdministratorAccess”策略。但是，在实际情况下，您应该创建或选择一个仅授予创建 CloudFormation 堆栈所需的特定权限的策略。点击“下一步：审阅”按钮后，指定角色名称为`cloudformation-deploy`，然后点击“创建角色”按钮创建新角色：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/2e5c6f9d-08b7-4abf-9aa4-8ae01e773f32.png)

# 向 CodePipeline 添加部署存储库

现在，您已经准备好了适当的堆栈配置文件和 IAM 部署角色，可以开始修改管道，以支持将应用程序更改持续交付到目标 AWS 环境。您需要执行的第一个修改是将 todobackend-aws 存储库作为另一个源操作添加到管道的源阶段。要执行此操作，请转到管道的详细信息视图，并点击“编辑”按钮。

在编辑屏幕中，您可以点击源阶段右上角的铅笔图标，这将改变视图并允许您添加一个新的源操作，可以在当前操作之前、之后或与当前操作在同一级别：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/99536673-029a-4c09-b052-0f5e5314af0f.png)编辑管道

对于我们的场景，我们可以并行下载部署存储库源；因此，在与其他源存储库相同级别添加一个新操作，这将打开一个添加操作对话框。选择“动作类别”为“源”，配置一个名称为`DeploymentRepository`或类似的操作名称，然后选择 GitHub 作为源提供者，并单击“连接到 GitHub”按钮，在`docker-in-aws/todobackend-aws`存储库上选择主分支：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/2b70a550-a045-4e69-b305-4a204589bfe5.png)添加部署存储库

接下来，滚动到页面底部，并为此源操作的输出工件配置一个名称。CodePipeline 将使部署存储库中的基础架构模板和配置可用于管道中的其他阶段，您可以通过配置的输出工件名称引用它们：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/3dfcd5c8-f127-4f80-a986-f2484d9a2254.png)配置输出工件名称

在前面的截图中，您还将输出工件名称配置为`DeploymentRepository`（与源操作名称相同），这有助于，因为管道详细信息视图仅显示阶段和操作名称，不显示工件名称。

# 在构建阶段添加输出工件

添加部署存储库操作后，编辑管道屏幕应如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/f8faf3c3-1c42-456f-8918-12c795137764.png)编辑管道屏幕

您需要执行的下一个管道配置任务是修改构建阶段中的 CodeBuild 构建操作，该操作是由 CodePipeline 向导为您创建的，当您创建管道时。

您可以通过点击前面截图中 CodeBuild 操作框右上角的铅笔图标来执行此操作，这将打开编辑操作对话框：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/76a52a53-f5b4-48dd-99ff-14fadd367347.png)编辑构建操作

在前面的截图中，请注意 CodePipeline 向导已经配置了输入和输出工件：

+   输入工件：CodePipeline 向导将其命名为`MyApp`，这指的是与您创建管道时引用的源存储库相关联的输出工件（在本例中，这是 GitHub todobackend 存储库）。如果要重命名此工件，必须确保在拥有操作（在本例中是源阶段中的源操作）上重命名输出工件名称，然后更新任何使用该工件作为输入的操作。

+   输出工件：CodePipeline 向导默认将其命名为`MyAppBuild`，然后可以在流水线的后续阶段中引用。输出工件由`buildspec.yml`文件中的 artifacts 属性确定，对于我们的用例，这个工件不是应用程序构建，而是捕获版本元数据（`version.json`）的版本工件，因此我们将这个工件重命名为`ApplicationVersion`。

# 向流水线添加部署阶段

在上述截图中单击“更新”按钮后，您可以通过单击构建阶段下方的“添加阶段”框来添加一个新阶段。对于阶段名称，请输入名称`Dev`，这将代表部署到名为 Dev 的环境，然后单击“添加操作”框以添加新操作：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/294d261f-8ecd-4942-8a13-7c8e5773895a.png)添加部署操作

因为这是一个部署阶段，所以从操作类别下拉菜单中选择“部署”，配置一个操作名称为“部署”，并选择 AWS CloudFormation 作为部署提供程序：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/6aafc914-9182-4329-881f-2c1faf719f56.png)配置 CloudFormation 部署操作

这将公开与 CloudFormation 部署相关的一些配置参数，如前面的截图所示：

+   操作模式：选择“创建或更新堆栈”选项，如果堆栈不存在，则将创建一个新堆栈，或者更新现有堆栈。

+   堆栈名称：引用您在之前章节中已部署的现有 todobackend 堆栈。

+   模板：指的是应该部署的 CloudFormation 模板文件。这是以`InputArtifactName::TemplateFileName`的格式表示的，在我们的情况下是`DeploymentRepository::stack.yml`，因为我们为`DeploymentRepository`源操作配置了一个输出工件名称，并且我们的堆栈位于存储库根目录的`stack.yml`文件中。

+   模板配置：指的是用于提供堆栈参数、标记和堆栈策略的配置文件。这需要引用您之前创建的新`dev.json`文件，在`todobackend-aws`部署存储库中；它与模板参数的格式相同，值为`DeploymentRepository::dev.json`。

一旦您配置了前面截图中显示的属性，请继续向下滚动并展开高级部分，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/7a23b618-6734-4918-96ab-b21350aecc7c.png)配置额外的 CloudFormation 部署操作属性

以下描述了您需要配置的每个额外参数：

+   功能：这授予了 CloudFormation 部署操作的权限，以代表您创建 IAM 资源，并且与您传递给`aws cloudformation deploy`命令的`--capabilities`标志具有相同的含义。

+   角色名称：这指定了 CloudFormation 部署操作使用的 IAM 角色，用于部署您的 CloudFormation 堆栈。引用您之前创建的`cloudformation-deploy`角色。

+   参数覆盖：此参数允许您覆盖通常由模板配置文件（`dev.json`）或 CloudFormation 模板中的默认值提供的输入参数值。对于我们的用例，我们需要覆盖`ApplicationImageTag`参数，因为这需要反映作为构建阶段的一部分创建的图像标记。CodePipeline 支持两种类型的参数覆盖（请参阅[使用参数覆盖函数](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/continuous-delivery-codepipeline-parameter-override-functions.html)），对于我们的用例，我们使用`Fn::GetParam`覆盖，它可以用于从由您的流水线输出的工件中提取属性值的 JSON 文件中。回想一下，在本章的前面，我们向 todobackend 存储库添加了一个`make version`任务，该任务输出了作为 CodeBuild 构建规范的一部分收集的`version.json`文件。我们更新了构建操作以引用此工件为`ApplicationVersion`。在前面的屏幕截图中，提供给`Fn::GetParam`调用的输入列表首先引用了工件（`ApplicationVersion`），然后是工件中 JSON 文件的路径（`version.json`），最后是 JSON 文件中保存参数覆盖值的键（`Version`）。

+   输入工件：这必须指定您在部署配置中引用的任何输入工件。在这里，我们添加了`DeploymentRepository`（用于模板和模板配置参数）和`ApplicationVersion`（用于参数覆盖配置）。

完成后，单击“添加操作”按钮，然后您可以单击“保存管道更改”以完成管道的配置。在这一点上，您可以通过单击“发布更改”按钮来测试您的新部署操作是否正常工作，这将手动触发管道的新执行；几分钟内，您的管道应该成功构建、测试和发布一个新的镜像作为构建阶段的一部分，然后成功通过 dev 阶段将更改部署到您的 todobackend 堆栈：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/9c4d6c8e-0bbc-47b0-85dd-6e7afdb035c0.png)通过 CodePipeline 成功部署 CloudFormation

在上面的屏幕截图中，您可以在部署期间或之后单击“详细信息”链接，这将带您到 CloudFormation 控制台，并向您显示有关正在进行中或已完成的部署的详细信息。如果您展开“参数”选项卡，您应该会看到 ApplicationImageTag 引用的标签格式为`<长提交哈希>`.`<codebuild 作业 ID>`，这证实我们的流水线实际上已部署了在构建阶段构建的 Docker 镜像：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/28a8570e-e4d2-4ab4-ac45-13e6a2063286.png)确认覆盖的输入参数

# 使用 CodePipeline 持续交付到生产环境

现在我们正在持续部署到非生产环境，我们持续交付旅程的最后一步是启用能够以受控方式将应用程序发布到生产环境的能力。CodePipeline 通过利用 CloudFormation 的一个有用特性来支持这一能力，称为变更集。变更集描述了将应用于给定 CloudFormation 堆栈的各种配置更改，这些更改基于可能已应用于堆栈模板文件和/或输入参数的任何更改。对于新的应用程序发布，通常只会更改定义新应用程序构件版本的输入参数。例如，我们的流水线的 dev 阶段覆盖了`ApplicationImageTag`输入参数。在某些情况下，您可能会对 CloudFormation 堆栈和输入参数进行更广泛的更改。例如，您可能需要为容器添加新的环境变量，或者向堆栈添加新的基础设施组件或支持服务。这些更改通常会提交到您的部署存储库中，并且鉴于我们的部署存储库是我们流水线中的一个源，对部署存储库的任何更改都将被捕获为一个变更。

CloudFormation 变更集为您提供了一个机会，可以审查即将应用于目标环境的任何更改，如果变更集被认为是安全的，那么您可以从该变更集发起部署。CodePipeline 支持生成 CloudFormation 变更集作为部署操作，然后可以与单独的手动批准操作结合使用，允许适当的人员审查变更集，随后批准或拒绝变更。如果变更得到批准，那么您可以从变更集触发部署，从而提供一种有效的方式来对生产环境或任何需要某种形式的变更控制的环境进行受控发布。

现在让我们扩展我们的流水线，以支持将应用程序发布受控地部署到新的生产环境，这需要您执行以下配置更改：

+   向部署存储库添加新的环境配置文件

+   向流水线添加创建变更集操作

+   向流水线添加手动批准操作

+   向流水线添加部署变更集操作

+   部署到生产环境

# 向部署存储库添加新的环境配置文件

因为我们正在创建一个新的生产环境，我们需要向部署存储库添加一个环境配置文件，其中将包括特定于您的生产环境的输入参数。如前面的示例所示，演示了在`todobackend-aws`存储库的根目录下添加一个名为`prod.json`的新文件：

```
{ 
  "Parameters": {
    "ApplicationDesiredCount": "1",
    "ApplicationImageId": "ami-ec957491",
    "ApplicationImageTag": "latest",
    "ApplicationSubnets": "subnet-a5d3ecee,subnet-324e246f",
    "VpcId": "vpc-f8233a80"
  }
}
```

您可以看到配置文件的格式与我们之前修改的`dev.json`文件相同。在现实世界的情况下，您当然会期望配置文件中有所不同。例如，我们正在使用相同的应用子网和 VPC ID；您通常会为生产环境拥有一个单独的 VPC，甚至一个单独的账户，但为了保持简单，我们将生产环境部署到与开发环境相同的 VPC 和子网中。

您还需要对我们的 CloudFormation 堆栈文件进行一些微小的更改，因为其中有一些硬编码的名称，如果您尝试在同一 AWS 账户中创建一个新堆栈，将会导致冲突。

```
...
...
Resources:
  ...
  ...
  ApplicationCluster:
    Type: AWS::ECS::Cluster
    Properties:
      # ClusterName: todobackend-cluster
      ClusterName: !Sub: ${AWS::StackName}-cluster
  ...
  ...
  MigrateTaskDefinition:
    Type: AWS::ECS::TaskDefinition
    Properties:
      # Family: todobackend-migrate
      Family: !Sub ${AWS::StackName}-migrate
      ...
      ...
  ApplicationTaskDefinition:
    Type: AWS::ECS::TaskDefinition
    Properties:
      # Family: todobackend
      Family: !Ref AWS::StackName
  ...
  ...
```

在前面的示例中，我已经注释了以前的配置，然后突出显示了所需的新配置。在所有情况下，我们将硬编码的对 todobackend 的引用替换为对堆栈名称的引用。鉴于 CloudFormation 堆栈名称在给定的 AWS 账户和区域内必须是唯一的，这确保了修改后的资源将具有唯一名称，不会与同一账户和区域内的其他堆栈发生冲突。

为了保持简单，生产环境的 CloudFormation 堆栈将使用我们在*管理秘密*章节中创建的相同秘密。在现实世界的情况下，您会为每个环境维护单独的秘密。

在放置新的配置文件和模板更改后，确保在继续下一部分之前已经将更改提交并推送到 GitHub：

```
> git add -A
> git commit -a -m "Add prod environment support"
[master a42af8d] Add prod environment support
 2 files changed, 12 insertions(+), 3 deletions(-)
 create mode 100644 prod.json
> git push
...
...
```

# 向管道添加创建变更集操作

我们现在准备向我们的管道中添加一个新阶段，用于将我们的应用部署到生产环境。我们将在这个阶段创建第一个操作，即创建一个 CloudFormation 变更集。

在管道的详细信息视图中，单击“编辑”按钮，然后在 dev 阶段之后添加一个名为 Production 的新阶段，然后向新阶段添加一个操作：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/709983ae-b16b-4beb-8387-94be2f9b2b00.png)向管道添加一个生产阶段

在“添加操作”对话框中，您需要创建一个类似于为 dev 阶段创建的部署操作的操作，但有一些变化：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/1b96f366-2196-493a-af18-a12ece18dcb5.png)向管道添加创建更改集操作

如果您将 dev 阶段的部署操作配置与前面截图中显示的新创建更改集操作配置进行比较，您会发现配置非常相似，除了以下关键差异：

+   操作模式：您可以将其配置为`create`或`replace`更改集，而不是部署堆栈，只会创建一个新的更改集。

+   堆栈名称：由于此操作涉及我们的生产环境，您需要配置一个新的堆栈名称，我们将其称为`todobackend-prod`。

+   更改集名称：这定义了更改集的名称。我通常将其命名为与堆栈名称相同，因为该操作将在每次执行时创建或替换更改集。

+   模板配置：在这里，您需要引用之前示例中添加到`todobackend-aws`存储库的新`prod.json`文件，因为这个文件包含特定于生产环境的输入参数。该文件通过从`todobackend-aws`存储库创建的`DeploymentRepository`工件提供。

接下来，您需要向下滚动，展开高级部分，使用`Fn::GetParam`语法配置参数覆盖属性，并最终将`ApplicationVersion`和`DeploymentRepository`工件配置为输入工件。这与您之前为`dev`/`deploy`操作执行的配置相同。

# 向管道添加手动批准操作

完成更改集操作的配置后，您需要添加一个在更改集操作之后执行的新操作：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/8e665d07-b1fc-496e-aa77-9f0d637f6c89.png)向管道添加批准操作

在“添加操作”对话框中，选择“批准”作为操作类别，然后配置一个操作名称为 ApproveChangeSet。选择手动批准类型后，注意您可以添加 SNS 主题 ARN 和其他信息到手动批准请求。然后可以用于向批准者发送电子邮件，或触发执行一些自定义操作的 lambda 函数，例如将消息发布到 Slack 等消息工具中。

# 向管道添加部署更改集操作

您需要创建的最后一个操作是，在批准 ApproveChangeSet 操作后，部署先前在 ChangeSet 操作中创建的更改集：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/8e4948db-2942-4902-9e0b-1ef79d3935f1.png)向流水线添加执行更改集操作

在上述截图中，我们选择了“执行更改集”操作模式，然后配置了堆栈名称和更改集名称，这些名称必须与您在 ChangeSet 操作中之前配置的相同值匹配。

# 部署到生产环境

在上述截图中单击“添加操作”后，您的新生产阶段的管道配置应如下所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/04e63fe0-ea86-4462-8481-35d21211f1e4.png)向流水线添加创建更改集操作

在这一点上，您可以通过单击“保存管道更改”按钮保存管道更改，并通过单击“发布更改”按钮测试新的管道阶段，这将强制执行新的管道执行。在管道成功执行构建和开发阶段后，生产阶段将首次被调用，由 ChangeSet 操作创建一个 CloudFormation 更改集，之后将触发批准操作。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/fe4dfcc1-0aef-4ddd-998c-946d30339bd9.png)向流水线添加创建更改集操作

现在管道将等待批准，这是批准者通常会通过单击 ChangeSet 操作的“详细信息”链接来审查先前创建的更改集：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/ba618105-d503-4550-91a1-8173242461a1.png)CloudFormation 更改集

正如您在上述截图中所看到的，更改集指示将创建堆栈中的所有资源，因为生产环境目前不存在。随后的部署应该有非常少的更改，因为堆栈将就位，典型的更改是部署新的 Docker 镜像。

审查更改集并返回到 CodePipeline 详细视图后，您现在可以通过单击“审查”按钮来批准（或拒绝）更改集。这将呈现一个批准或拒绝修订对话框，在这里您可以添加评论并批准或拒绝更改：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/2af34076-a505-4017-b38f-120ab29e1f8b.png)批准或拒绝手动批准操作

如果您点击“批准”，流水线将继续执行下一个操作，即部署与之前 ChangeSet 操作相关联的变更集。对于这次执行，将部署一个名为`todobackend-prod`的新堆栈，一旦完成，您就成功地使用 CodePipeline 部署了一个全新的生产环境！

在这一点上，您应该测试并验证您的新堆栈和应用程序是否按预期工作，按照“使用 ECS 部署应用程序”章节中“部署应用程序负载均衡器”部分的步骤获取应用程序负载均衡器端点的 DNS 名称，您的生产应用程序端点将从中提供服务。我还鼓励您触发流水线，无论是手动触发还是通过对任一存储库进行测试提交，然后审查生成的后续变更集，以进行对现有环境的应用程序部署。请注意，您可以选择何时部署到生产环境。例如，您的开发人员可能多次提交应用程序更改，每次更改都会自动部署到非生产环境，然后再选择部署下一个版本到生产环境。当您选择部署到生产环境时，您的生产阶段将采用最近成功部署到非生产环境的最新版本。

一旦您完成了对生产部署的测试，如果您使用的是免费套餐账户，请记住您现在有多个 EC2 实例和 RDS 实例在运行，因此您应该考虑拆除您的生产环境，以避免产生费用。

# 摘要

在本章中，您创建了一个端到端的持续交付流水线，该流水线自动测试、构建和发布您的应用程序的 Docker 镜像，持续将新的应用程序更改部署到非生产环境，并允许您在生成变更集并在部署到生产环境之前需要手动批准的情况下执行受控发布。

您学会了如何将您的 GitHub 存储库与 CodePipeline 集成，方法是将它们定义为源阶段中的源操作，然后创建一个构建阶段，该阶段使用 CodeBuild 来测试、构建和发布应用程序的 Docker 镜像。您向 todobackend 存储库添加了构建规范，CodeBuild 使用它来执行您的构建，并创建了一个自定义的 CodeBuild 容器，该容器能够在 Docker 中运行 Docker，以允许您构建 Docker 镜像并在 Docker Compose 环境中执行集成和验收测试。

接下来，您在 CodePipeline 中创建了一个部署阶段，该阶段会自动将应用程序更改部署到我们在本书中一直使用的 todobackend 堆栈。这要求您在源阶段为`todobackend-aws`存储库添加一个新的源操作，这使得 CloudFormation 堆栈文件和环境配置文件可用作以后的 CloudFormation 部署操作的工件。您还需要为 todobackend 存储库创建一个输出工件，这种情况下，它只是捕获了在构建阶段构建和发布的 Docker 镜像标记，并使其可用于后续阶段。然后，您将此工件作为参数覆盖引用到您的 dev 阶段部署操作中，使用构建操作版本工件中输出的 Docker 镜像标记覆盖`ApplicationImageTag`参数。

最后，您扩展了管道以支持在生产环境中进行受控发布，这需要创建一个创建变更集操作，该操作创建一个 CloudFormation 变更集，一个手动批准操作，允许某人审查变更集并批准/拒绝它，以及一个部署操作，执行先前生成的变更集。

在下一章中，我们将改变方向，介绍 AWS Fargate 服务，它允许您部署 Docker 应用程序，而无需部署和管理自己的 ECS 集群和 ECS 容器实例。我们将利用这个机会通过使用 Fargate 部署 X-Ray 守护程序来为 AWS X-Ray 服务添加支持，并将通过使用 ECS 服务发现发布守护程序端点。

# 问题

1.  您通常在应用程序存储库的根目录中包含哪个文件以支持 AWS CodeBuild？

1.  真/假：AWS CodeBuild 是一个构建服务，它会启动虚拟机并使用 AWS CodeDeploy 运行构建脚本。

1.  您需要运行哪些 Docker 配置来支持 Docker 镜像和多容器构建环境的构建？

1.  您希望在部署 CloudFormation 模板之前审查所做的更改。您将使用 CloudFormation 的哪个功能来实现这一点？

1.  在使用 CodePipeline CloudFormation 部署操作部署 CloudFormation 堆栈时，必须信任哪个服务以用于指定这些操作的服务角色？

1.  您设置了一个新的 CodeBuild 项目，其中包括一个发布到弹性容器注册表的构建任务。当您尝试发布图像时，第一次构建失败。您确认目标 ECR 存储库存在，并且您可以手动发布图像到存储库。这个问题的可能原因是什么？

1.  您为 CodeBuild 创建了一个自定义构建容器，并将其发布到 ECR，并创建了一个允许您的 AWS 账户从 ECR 拉取访问的存储库策略。在执行构建时，您会收到失败的消息，指示 CodeBuild 无法重试自定义镜像。您将如何解决这个问题？

1.  您创建了一个自定义构建容器，该容器使用 Docker in Docker 来支持 Docker 镜像构建。当构建容器启动并尝试启动 Docker 守护程序时，会出现权限错误。您将如何解决这个问题？

# 进一步阅读

您可以查看以下链接，了解本章涵盖的主题的更多信息：

+   CodePipeline 用户指南：[`docs.aws.amazon.com/codepipeline/latest/userguide/welcome.html`](https://docs.aws.amazon.com/codepipeline/latest/userguide/welcome.html)

+   CodeBuild 用户指南：[`docs.aws.amazon.com/codebuild/latest/userguide/welcome.html`](https://docs.aws.amazon.com/codebuild/latest/userguide/welcome.html)

+   CodeBuild 的构建规范参考：[`docs.aws.amazon.com/codebuild/latest/userguide/build-spec-ref.html`](https://docs.aws.amazon.com/codebuild/latest/userguide/build-spec-ref.html)

+   使用 AWS CodePipeline 与 CodeBuild：[`docs.aws.amazon.com/codebuild/latest/userguide/how-to-create-pipeline.html`](https://docs.aws.amazon.com/codebuild/latest/userguide/how-to-create-pipeline.html)

+   AWS CodePipeline 管道结构参考：[`docs.aws.amazon.com/codepipeline/latest/userguide/reference-pipeline-structure.html`](https://docs.aws.amazon.com/codepipeline/latest/userguide/reference-pipeline-structure.html)

+   使用参数覆盖函数与 AWS CodePipeline 管道：[`docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/continuous-delivery-codepipeline-parameter-override-functions.html`](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/continuous-delivery-codepipeline-parameter-override-functions.html)


# 第十四章：Fargate 和 ECS 服务发现

到目前为止，在本书中，我们已经花了大量时间专注于构建支持您的 ECS 集群的基础架构，详细介绍了如何为 ECS 容器实例构建自定义的 Amazon 机器映像，以及如何创建可以动态添加或删除 ECS 容器实例到 ECS 集群的 EC2 自动扩展组，还有专门用于管理集群的生命周期和容量的章节。

想象一下不必担心 ECS 集群和 ECS 容器实例。想象一下，有人为您管理它们，以至于您甚至真的不知道它们的存在。对于某些用例，对硬件选择、存储配置、安全姿态和其他基础设施相关问题具有强大的控制能力非常重要；到目前为止，您应该对 ECS 如何提供这些功能有相当深入的了解。然而，在许多情况下，不需要那种控制水平，并且能够利用一个管理您的 ECS 集群补丁、安全配置、容量和其他一切的服务将会带来显著的好处，降低您的运营开销，并使您能够专注于实现您的组织正在努力实现的目标。

好消息是，这是完全可能的，这要归功于一个名为**AWS Fargate**的服务，该服务于 2017 年 12 月推出。Fargate 是一个完全托管的服务，您只需定义 ECS 任务定义和 ECS 服务，然后让 Fargate 来处理本书中您已经习惯的 ECS 集群和容器实例管理的其余部分。在本章中，您将学习如何使用 AWS Fargate 部署容器应用程序，使用我们在本书中一直在采用的 CloudFormation 的**基础设施即代码**（**IaC**）方法。为了使本章更加有趣，我们将为名为 X-Ray 的 AWS 服务添加支持，该服务为在 AWS 中运行的应用程序提供分布式跟踪。

当您想要在容器应用程序中使用 X-Ray 时，您需要实现所谓的 X-Ray 守护程序，这是一个从容器应用程序收集跟踪信息并将其发布到 X-Ray 服务的应用程序。我们将扩展 todobackend 应用程序以捕获传入请求的跟踪信息，并通过利用 AWS Fargate 服务向您的 AWS 环境添加 X-Ray 守护程序，该服务将收集跟踪信息并将其转发到 X-Ray 服务。

作为额外的奖励，我们还将实现一个名为 ECS 服务发现的功能，它允许您的容器应用程序自动发布和发现，使用 DNS。这个功能对于 X-Ray 守护程序非常有用，它是一个基于 UDP 的应用程序，不能由各种可用于前端 TCP 和基于 HTTP 的应用程序的负载平衡服务提供服务。ECS 包含对服务发现的内置支持，负责在您的 ECS 任务启动和停止时进行服务注册和注销，使您能够创建其他应用程序可以轻松发现的高可用服务。

本章将涵盖以下主题：

+   何时使用 Fargate

+   为应用程序添加对 AWS X-Ray 的支持

+   创建 X-Ray 守护程序 Docker 镜像

+   配置 ECS 服务发现资源

+   为 Fargate 配置 ECS 任务定义

+   为 Fargate 配置 ECS 服务

+   部署和测试 X-Ray 守护程序

# 技术要求

本章的技术要求如下：

+   对 AWS 帐户的管理员访问权限

+   本地 AWS 配置文件，根据第三章的说明进行配置

+   AWS CLI 版本 1.15.71 或更高版本

+   Docker 18.06 CE 或更高版本

+   Docker Compose 1.22 或更高版本

+   GNU Make 3.82 或更高版本

+   本章继续自第十三章，因此需要您成功完成第十三章中定义的所有配置任务

以下 GitHub URL 包含本章中使用的代码示例：[`github.com/docker-in-aws/docker-in-aws/tree/master/ch14`](https://github.com/docker-in-aws/docker-in-aws/tree/master/ch14)

查看以下视频以查看代码的实际操作：

[`bit.ly/2Lyd9ft`](http://bit.ly/2Lyd9ft)

# 何时使用 Fargate？

正如本章介绍中所讨论的，AWS Fargate 是一项服务，允许您部署基于容器的应用程序，而无需部署任何 ECS 容器实例、自动扩展组，或者与管理 ECS 集群基础设施相关的任何操作要求。这使得 AWS Fargate 成为一个介于使用 AWS Lambda 运行函数作为服务和使用传统 ECS 集群和 ECS 容器实例运行自己基础设施之间的无服务器技术。

尽管 Fargate 是一项很棒的技术，但重要的是要了解，Fargate 目前还很年轻（至少在撰写本书时是这样），它确实存在一些限制，这些限制可能使其不适用于某些用例，如下所述：

+   **无持久存储**：Fargate 目前不支持持久存储，因此如果您的应用程序需要使用持久的 Docker 卷，您应该使用其他服务，例如传统的 ECS 服务。

+   **定价**：定价始终可能会有变化；然而，与 ECS 一起获得的常规 EC2 实例定价相比，Fargate 的初始定价被许多人认为是昂贵的。例如，您可以购买的最小 Fargate 配置为 0.25v CPU 和 512 MB 内存，价格为每月 14.25 美元。相比之下，具有 0.5v CPU 和 512 MB 内存的 t2.nano 的价格要低得多，为 4.75 美元（所有价格均基于“us-east-1”地区）。

+   **部署时间**：就我个人经验而言，在 Fargate 上运行的 ECS 任务通常需要更长的时间来进行配置和部署，这可能会影响您的应用程序部署所需的时间（这也会影响自动扩展操作）。

+   **安全和控制**：使用 Fargate，您无法控制运行容器的底层硬件或实例的任何内容。如果您有严格的安全和/或合规性要求，那么 Fargate 可能无法为您提供满足特定要求的保证或必要的控制。然而，重要的是要注意，AWS 将 Fargate 列为符合 HIPAA 和 PCI Level 1 DSS 标准。

+   网络隔离：在撰写本书时，Fargate 不支持 ECS 代理和 CloudWatch 日志通信使用 HTTP 代理。这要求您将 Fargate 任务放置在具有互联网连接性的公共子网中，或者放置在具有 NAT 网关的私有子网中，类似于您在“隔离网络访问”章节中学到的方法。为了允许访问公共 AWS API 端点，这确实要求您打开出站网络访问，这可能违反您组织的安全要求。

+   服务可用性：在撰写本书时，Fargate 仅在美国东部（弗吉尼亚州）、美国东部（俄亥俄州）、美国西部（俄勒冈州）和欧盟（爱尔兰）地区可用；但是，我希望 Fargate 能够在大多数地区迅速广泛地可用。

如果您可以接受 Fargate 当前的限制，那么 Fargate 将显著减少您的运营开销，并使您的生活更加简单。例如，在自动扩展方面，您可以简单地使用我们在“ECS 自动扩展”章节末尾讨论的应用自动扩展方法来自动扩展您的 ECS 服务，Fargate 将负责确保有足够的集群容量。同样，您无需担心 ECS 集群的打补丁和生命周期管理 - Fargate 会为您处理上述所有事项。

在本章中，我们将部署一个 AWS X-Ray 守护程序服务，以支持 todobackend 应用程序的应用程序跟踪。鉴于这种类型的服务是 Fargate 非常适合的，因为它是一个不需要持久存储、不会影响 todobackend 应用程序的可用性（如果它宕机），也不会处理最终用户数据的后台服务。

# 为应用程序添加对 AWS X-Ray 的支持

在我们可以使用 AWS X-Ray 服务之前，您的应用程序需要支持收集和发布跟踪信息到 X-Ray 服务。X-Ray 软件开发工具包（SDK）包括对各种编程语言和流行的应用程序框架的支持，包括 Python 和 Django，它们都是 todobackend 应用程序的动力源。

您可以在[`aws.amazon.com/documentation/xray/`](https://aws.amazon.com/documentation/xray/)找到适合您选择的语言的适当 SDK 文档，但对于我们的用例，[`docs.aws.amazon.com/xray-sdk-for-python/latest/reference/frameworks.html`](https://docs.aws.amazon.com/xray-sdk-for-python/latest/reference/frameworks.html)提供了有关如何配置 Django 以自动为应用程序的每个传入请求创建跟踪的相关信息。

在 todobackend 存储库中，您首先需要将 X-Ray SDK 包添加到`src/requirements.txt`文件中，这将确保 SDK 与 todobackend 应用程序的其他依赖项一起安装：

```
Django==2.0
django-cors-headers==2.1.0
djangorestframework==3.7.3
mysql-connector-python==8.0.11
pytz==2017.3
uwsgi==2.0.17
aws-xray-sdk
```

接下来，您需要将 Django X-Ray 中间件组件（包含在 SDK 中）添加到位于`src/todobackend/settings_release.py`中的 Django 项目的`MIDDLEWARE`配置元素中：

```
from .settings import *
...
...
STATIC_ROOT = os.environ.get('STATIC_ROOT', '/public/static')
MEDIA_ROOT = os.environ.get('MEDIA_ROOT', '/public/media')

MIDDLEWARE.insert(0,'aws_xray_sdk.ext.django.middleware.XRayMiddleware')
```

这种配置与[Django 的 X 射线文档](https://docs.aws.amazon.com/xray-sdk-for-python/latest/reference/frameworks.html)有所不同，但通常情况下，您只想在 AWS 环境中运行 X-Ray，并且使用标准方法可能会导致本地开发环境中的 X-Ray 配置问题。因为我们有一个单独的发布设置文件，导入基本设置文件，我们可以简单地使用`insert()`函数将 X-Ray 中间件组件插入到基本的`MIDDLEWARE`列表的开头，如所示。这种方法确保我们将在使用发布设置的 AWS 环境中运行 X-Ray，但不会在本地开发环境中使用 X-Ray。

重要的是要在`MIDDLEWARE`列表中首先指定 X-Ray 中间件组件，因为这样可以确保 X-Ray 可以在任何其他中间件组件之前开始跟踪传入请求。

最后，Python X-Ray SDK 包括对许多流行软件包的跟踪支持，包括`mysql-connector-python`软件包，该软件包被 todobackend 应用程序用于连接其 MySQL 数据库。在 Python 中，X-Ray 使用一种称为 patching 的技术来包装受支持软件包的调用，这允许 X-Ray 拦截软件包发出的调用并捕获跟踪信息。对于我们的用例，对`mysql-connector-python`软件包进行 patching 将使我们能够跟踪应用程序发出的数据库调用，这对于解决性能问题非常有用。要对此软件包进行 patching，您需要向应用程序入口点添加几行代码，对于 Django 来说，该入口点位于文件`src/todobackend.wsgi.py`中：

```
"""
WSGI config for todobackend project.

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/2.0/howto/deployment/wsgi/
"""

import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "todobackend.settings")

from aws_xray_sdk.core import xray_recorder
from aws_xray_sdk.core import patch_all

# Required to avoid SegmentNameMissingException errors
xray_recorder.configure(service="todobackend")

patch_all()

application = get_wsgi_application()
```

`xray_recorder`配置将向每个跟踪段添加服务名称，否则您将观察到 SegmentNameMissingException 错误。在这一点上，您已经在应用程序级别上添加了支持以开始跟踪传入请求，并且在提交并将更改推送到 GitHub 之前，您应该能够成功运行“make workflow”（运行`make test`和`make release`）。因为您现在已经建立了一个持续交付管道，这将触发该管道，该管道确保一旦管道构建阶段完成，您的应用程序更改将被发布到 ECR。如果您尚未完成上一章，或者已删除管道，则需要在运行`make test`和`make release`后使用`make login`和`make publish`命令手动发布新镜像。

# 创建 X-Ray 守护程序 Docker 镜像

在我们的应用程序可以发布 X-Ray 跟踪信息之前，您必须部署一个 X-Ray 守护程序，以便您的应用程序可以将此信息发送到它。我们的目标是使用 AWS Fargate 运行 X-Ray 守护程序，但在此之前，我们需要创建一个将运行守护程序的 Docker 镜像。AWS 提供了如何构建 X-Ray 守护程序镜像的示例，我们将按照 AWS 文档中记录的类似方法创建一个名为`Dockerfile.xray`的文件，该文件位于`todobackend-aws`存储库的根目录中：

```
FROM amazonlinux
RUN yum install -y unzip
RUN curl -o daemon.zip https://s3.dualstack.us-east-2.amazonaws.com/aws-xray-assets.us-east-2/xray-daemon/aws-xray-daemon-linux-2.x.zip
RUN unzip daemon.zip && cp xray /usr/bin/xray

ENTRYPOINT ["/usr/bin/xray", "-b", "0.0.0.0:2000"]
EXPOSE 2000/udp
```

您现在可以使用`docker build`命令在本地构建此镜像，如下所示：

```
> docker build -t xray -f Dockerfile.xray .
Sending build context to Docker daemon 474.1kB
Step 1/6 : FROM amazonlinux
 ---> 81bb3e78db3d
Step 2/6 : RUN yum install -y unzip
 ---> Running in 35aca63a625e
Loaded plugins: ovl, priorities
Resolving Dependencies
...
...
Step 6/6 : EXPOSE 2000/udp
 ---> Running in 042542d22644
Removing intermediate container 042542d22644
 ---> 63b422e40099
Successfully built 63b422e40099
Successfully tagged xray:latest
```

现在我们的镜像已构建，我们需要将其发布到 ECR。在此之前，您需要为 X-Ray 镜像创建一个新的存储库，然后将其添加到`todobackend-aws`存储库的根目录中的现有`ecr.yml`文件中：

```
AWSTemplateFormatVersion: "2010-09-09"

Description: ECR Resources

Resources:
  XrayRepository:
 Type: AWS::ECR::Repository
 Properties:
 RepositoryName: docker-in-aws/xray
  CodebuildRepository:
    Type: AWS::ECR::Repository
  ...
  ...
```

在前面的示例中，您使用名称`docker-in-aws/xray`创建了一个新的存储库，这将导致一个完全合格的存储库名称为`<account-id>.dkr.ecr.<region>.amazonaws.com/docker-in-aws/xray`（例如，`385605022855.dkr.ecr.us-east-1.amazonaws.com/docker-in-aws/xray`）。

您现在可以通过运行`aws cloudformation deploy`命令来创建新的存储库：

```
> export AWS_PROFILE=docker-in-aws
> aws cloudformation deploy --template-file ecr.yml --stack-name ecr-repositories
Enter MFA code for arn:aws:iam::385605022855:mfa/justin.menga:

Waiting for changeset to be created..
Waiting for stack create/update to complete
Successfully created/updated stack - ecr-repositories
  ...
  ...
```

部署完成后，您可以登录到 ECR，然后使用新的 ECR 存储库的完全合格名称对之前创建的图像进行标记和发布。

```
> eval $(aws ecr get-login --no-include-email)
Login Succeeded
> docker tag xray 385605022855.dkr.ecr.us-east-1.amazonaws.com/docker-in-aws/xray
> docker push 385605022855.dkr.ecr.us-east-1.amazonaws.com/docker-in-aws/xray
The push refers to repository [385605022855.dkr.ecr.us-east-1.amazonaws.com/docker-in-aws/xray]
c44926e8470e: Pushed
1c9da599a308: Pushed
9d486dac1b0b: Pushed
0c1715974ca1: Pushed
latest: digest: sha256:01d9b6982ce3443009c7f07babb89b134c9d32ea6f1fc380cb89ce5639c33938 size: 1163
```

# 配置 ECS 服务发现资源

ECS 服务发现是一个功能，允许您的客户端应用程序在动态环境中发现 ECS 服务，其中基于容器的端点来来去去。到目前为止，我们已经使用 AWS 应用程序负载均衡器来执行此功能，您可以配置一个稳定的服务端点，您的应用程序可以连接到该端点，然后在 ECS 管理的目标组中进行负载平衡，该目标组包括与 ECS 服务相关联的每个 ECS 任务。尽管这通常是我推荐的最佳实践方法，但对于不支持负载均衡器的应用程序（例如，基于 UDP 的应用程序），或者对于非常庞大的微服务架构，在这种架构中，与给定的 ECS 任务直接通信更有效，ECS 服务发现可能比使用负载均衡器更好。

ECS 服务发现还支持 AWS 负载均衡器，如果负载均衡器与给定的 ECS 服务相关联，ECS 将发布负载均衡器侦听器的 IP 地址。

ECS 服务发现使用 DNS 作为其发现机制，这是有用的，因为在其最基本的形式中，DNS 被任何应用客户端普遍支持。您的 ECS 服务注册的 DNS 命名空间被称为**服务发现命名空间**，它简单地对应于 Route 53 DNS 域或区域，您在命名空间中注册的每个服务被称为**服务发现**。例如，您可以将`services.dockerinaws.org`配置为服务发现命名空间，如果您有一个名为`todobackend`的 ECS 服务，那么您将使用 DNS 名称`todobackend.services.dockerinaws.org`连接到该服务。ECS 将自动管理针对您的服务的 DNS 记录注册的地址（`A`）记录，动态添加与您的 ECS 服务的每个活动和健康的 ECS 任务关联的 IP 地址，并删除任何退出或变得不健康的 ECS 任务。ECS 服务发现支持公共和私有命名空间，对于我们运行 X-Ray 守护程序的示例，私有命名空间是合适的，因为此服务只需要支持来自 todobackend 应用程序的内部应用程序跟踪通信。

ECS 服务发现支持 DNS 服务（SRV）记录的配置，其中包括有关给定服务端点的 IP 地址和 TCP/UDP 端口信息。当使用静态端口映射或**awsvpc**网络模式（例如 Fargate）时，通常使用地址（`A`）记录，当使用动态端口映射时使用 SRV 记录，因为 SRV 记录可以包括为创建的端口映射提供动态端口信息。请注意，应用程序对 SRV 记录的支持有些有限，因此我通常建议在 ECS 服务发现中使用经过验证的`A`记录的方法。

# 配置服务发现命名空间

与大多数 AWS 资源一样，您可以使用 AWS 控制台、AWS CLI、各种 AWS SDK 之一或 CloudFormation 来配置服务发现资源。鉴于本书始终采用基础设施即代码的方法，我们自然会在本章中采用 CloudFormation；因为 X-Ray 守护程序是一个新服务（通常被视为每个应用程序发布跟踪信息的共享服务），我们将在名为`xray.yml`的文件中创建一个新的堆栈，放在`todobackend-aws`存储库的根目录。

以下示例演示了创建初始模板和创建服务发现命名空间资源：

```
AWSTemplateFormatVersion: "2010-09-09"

Description: X-Ray Daemon

Resources:
  ApplicationServiceDiscoveryNamespace:
    Type: AWS::ServiceDiscovery::PrivateDnsNamespace
    Properties:
      Name: services.dockerinaws.org.
      Description: services.dockerinaws.org namespace
      Vpc: vpc-f8233a80
```

在前面的示例中，我们创建了一个私有服务发现命名空间，它只需要命名空间的 DNS 名称、可选描述和关联的私有 Route 53 区域的 VPC ID。为了保持简单，我还硬编码了与我的 AWS 账户相关的 VPC ID 的适当值，通常您会通过堆栈参数注入这个值。

鉴于服务发现命名空间的意图是支持多个服务，您通常会在单独的 CloudFormation 堆栈中创建命名空间，比如创建共享网络资源的专用网络堆栈。然而，为了保持简单，我们将在 X-Ray 堆栈中创建命名空间。

现在，您可以使用`aws cloudformation deploy`命令将初始堆栈部署到 CloudFormation，这应该会创建一个服务发现命名空间和相关的 Route 53 私有区域。

```
> aws cloudformation deploy --template-file xray.yml --stack-name xray-daemon
Waiting for changeset to be created..
Waiting for stack create/update to complete
Successfully created/updated stack - xray-daemon
> aws servicediscovery list-namespaces
{
    "Namespaces": [
        {
            "Id": "ns-lgd774j6s2cmxwq3",
            "Arn": "arn:aws:servicediscovery:us-east-1:385605022855:namespace/ns-lgd774j6s2cmxwq3",
            "Name": "services.dockerinaws.org",
            "Type": "DNS_PRIVATE"
        }
    ]
}
> aws route53 list-hosted-zones --query HostedZones[].Name --output table
-------------------------------
| ListHostedZones             |
+-----------------------------+
| services.dockerinaws.org.   |
+-----------------------------+
```

在前面的示例中，一旦您的堆栈成功部署，您将使用`aws servicediscovery list-namespaces`命令来验证是否创建了一个私有命名空间，而`aws route53 list-hosted-zones`命令将显示已创建一个 Route 53 区域，其区域名称为`services.dockerinaws.org`。

# 配置服务发现服务

现在您已经有了一个服务发现命名空间，下一步是创建一个服务发现服务，它与每个 ECS 服务都有一对一的关系，这意味着您需要创建一个代表稍后在本章中创建的 X-Ray ECS 服务的服务发现服务。

```
AWSTemplateFormatVersion: "2010-09-09"

Description: X-Ray Daemon

Resources:
  ApplicationServiceDiscoveryService:
 Type: AWS::ServiceDiscovery::Service
 Properties:
 Name: xray
 Description: xray service 
 DnsConfig: 
 NamespaceId: !Ref ApplicationServiceDiscoveryNamespace
 DnsRecords:
 - Type: A
 TTL: 60
 HealthCheckCustomConfig:
 FailureThreshold: 1
  ApplicationServiceDiscoveryNamespace:
    Type: AWS::ServiceDiscovery::PrivateDnsNamespace
    Properties:
      Name: services.dockerinaws.org.
      Description: services.dockerinaws.org namespace
      Vpc: vpc-f8233a80
```

在前面的示例中，您添加了一个名为`ApplicationServiceDiscoveryService`的新资源，并配置了以下属性：

+   `Name`：定义服务的名称。此名称将用于在关联的命名空间中注册服务。

+   `DnsConfig`：指定服务关联的命名空间（由`NamespaceId`属性定义），并定义应创建的 DNS 记录类型和生存时间（TTL）。在这里，您指定了一个地址记录（类型为`A`）和一个 60 秒的 TTL，这意味着客户端只会缓存该记录最多 60 秒。通常情况下，您应该将 TTL 设置为较低的值，以确保您的客户端在新的 ECS 任务注册到服务或现有的 ECS 任务从服务中移除时能够获取 DNS 更改。

+   `HealthCheckCustomConfig`：这配置 ECS 来管理确定是否可以注册 ECS 任务的健康检查。您还可以配置 Route 53 健康检查（参见[`docs.aws.amazon.com/AmazonECS/latest/developerguide/service-discovery.html#service-discovery-concepts`](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/service-discovery.html#service-discovery-concepts)）；然而，对于我们的用例来说，鉴于 X-Ray 是基于 UDP 的应用程序，而 Route 53 健康检查仅支持基于 TCP 的服务，您必须使用前面示例中显示的`HealthCheckCustomConfig`配置。`FailureThreshold`指定服务发现在接收到自定义健康检查更新后等待更改给定服务实例的健康状态的`30`秒间隔数。

您现在可以使用`aws cloudformation deploy`命令将更新后的堆栈部署到 CloudFormation，这应该会创建一个服务发现服务。

```
> aws cloudformation deploy --template-file xray.yml --stack-name xray-daemon
Waiting for changeset to be created..
Waiting for stack create/update to complete
Successfully created/updated stack - xray-daemon
> aws servicediscovery list-services
{
    "Services": [
        {
            "Id": "srv-wkdxwh4pzo7ea7w3",
            "Arn": "arn:aws:servicediscovery:us-east-1:385605022855:service/srv-wkdxwh4pzo7ea7w3",
            "Name": "xray",
            "Description": "xray service"
        }
    ]
}
```

这将为`xray.services.dockerinaws.org`创建一个 DNS 记录集，直到我们在本章后面将要创建的 X-Ray ECS 服务的 ECS 服务发现支持配置之前，它将不会有任何地址（`A`）记录与之关联。

# 为 Fargate 配置 ECS 任务定义

您现在可以开始定义您的 ECS 资源，您将配置为使用 AWS Fargate 服务，并利用您在上一节中创建的服务发现资源。

在配置 ECS 任务定义以支持 Fargate 时，有一些关键考虑因素需要您了解：

+   **启动类型**：ECS 任务定义包括一个名为`RequiresCompatibilities`的参数，该参数定义了定义的兼容启动类型。当前的启动类型包括 EC2，指的是在传统 ECS 集群上启动的 ECS 任务，以及 FARGATE，指的是在 Fargate 上启动的 ECS 任务。默认情况下，`RequiresCompatibilities`参数配置为 EC2，这意味着如果要使用 Fargate，必须显式配置此参数。

+   **网络模式**：Fargate 仅支持`awsvpc`网络模式，我们在第十章“隔离网络访问”中讨论过。

+   **执行角色**：Fargate 要求您配置一个**执行角色**，这是分配给管理 ECS 任务生命周期的 ECS 代理和 Fargate 运行时的 IAM 角色。这是一个独立的角色，不同于您在第九章“管理机密”中配置的任务 IAM 角色功能，该功能用于向在 ECS 任务中运行的应用程序授予 IAM 权限。执行角色通常配置为具有类似权限的权限，这些权限您将为与传统 ECS 容器实例关联的 EC2 IAM 实例角色配置，至少授予 ECS 代理和 Fargate 运行时从 ECR 拉取图像和将日志写入 CloudWatch 日志的权限。

+   **CPU 和内存**：Fargate 要求您在任务定义级别定义 CPU 和内存要求，因为这决定了基于您的任务定义运行的 ECS 任务的基础目标实例。请注意，这与您在第八章“使用 ECS 部署应用程序”中为 todobackend 应用程序的 ECS 任务定义配置的每个容器定义 CPU 和内存设置是分开的；您仍然可以配置每个容器定义的 CPU 和内存设置，但需要确保分配给容器定义的总 CPU/内存不超过分配给 ECS 任务定义的总 CPU/内存。Fargate 目前仅支持有限的 CPU/内存分配，您可以在[`docs.aws.amazon.com/AmazonECS/latest/developerguide/AWS_Fargate.html`](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/AWS_Fargate.html)的“任务 CPU 和内存”部分了解更多信息。

+   **日志记录**：截至撰写本文时，Fargate 仅支持`awslogs`日志记录驱动程序，该驱动程序将您的容器日志转发到 CloudWatch 日志。

考虑到上述情况，现在让我们为我们的 X-Ray 守护程序服务定义一个任务定义：

```
...
...
Resources:
  ApplicationTaskDefinition:
 Type: AWS::ECS::TaskDefinition
 Properties:
 Family: !Sub ${AWS::StackName}-task-definition
 NetworkMode: awsvpc
 ExecutionRoleArn: !Sub ${ApplicationTaskExecutionRole.Arn}
 TaskRoleArn: !Sub ${ApplicationTaskRole.Arn}
 Cpu: 256
 Memory: 512
 RequiresCompatibilities:
 - FARGATE
 ContainerDefinitions:
 - Name: xray
 Image: !Sub ${AWS::AccountId}.dkr.ecr.${AWS::Region}.amazonaws.com/docker-in-aws/xray
 Command:
 - -o
 LogConfiguration:
 LogDriver: awslogs
 Options:
 awslogs-group: !Sub /${AWS::StackName}/ecs/xray
 awslogs-region: !Ref AWS::Region
 awslogs-stream-prefix: docker
 PortMappings:
 - ContainerPort: 2000
 Protocol: udp
 Environment:
 - Name: AWS_REGION
 Value: !Ref AWS::Region
  ApplicationLogGroup:
 Type: AWS::Logs::LogGroup
 DeletionPolicy: Delete
 Properties:
 LogGroupName: !Sub /${AWS::StackName}/ecs/xray
 RetentionInDays: 7
  ApplicationServiceDiscoveryService:
    Type: AWS::ServiceDiscovery::Service
  ...
  ...
```

在上面的示例中，请注意`RequiresCompatibilities`参数指定`FARGATE`作为支持的启动类型，并且`NetworkMode`参数配置为所需的`awsvpc`模式。`Cpu`和`Memory`设置分别配置为 256 CPU 单位（0.25 vCPU）和 512 MB，这代表了最小可用的 Fargate CPU/内存配置。对于`ExecutionRoleArn`参数，您引用了一个名为`ApplicationTaskExecutionRole`的 IAM 角色，我们将很快单独配置，与为`TaskRoleArn`参数配置的角色分开。

接下来，您定义一个名为`xray`的单个容器定义，该容器定义引用了您在本章前面创建的 ECR 存储库；请注意，您为`Command`参数指定了`-o`标志。这将在您在上一个示例中配置的 X-Ray 守护程序镜像的`ENTRYPOINT`指令中附加`-o`，从而阻止 X-Ray 守护程序尝试查询 EC2 实例元数据，因为在使用 Fargate 时不支持这一操作。

容器定义的日志配置配置为使用`awslogs`驱动程序，这是 Fargate 所需的，它引用了任务定义下配置的`ApplicationLogGroup` CloudWatch 日志组资源。最后，您指定了 X-Ray 守护程序端口（`UDP 端口 2000`）作为容器端口映射，并配置了一个名为`AWS_REGION`的环境变量，该变量引用您部署堆栈的区域，这对于 X-Ray 守护程序确定守护程序应将跟踪数据发布到的区域性 X-Ray 服务端点是必需的。

# 为 Fargate 配置 IAM 角色

在上一个示例中，您的 ECS 任务定义引用了一个任务执行角色（由`ExecutionRoleArn`参数定义）和一个任务角色（由`TaskRoleArn`参数定义）。

如前所述，任务执行角色定义了将分配给 ECS 代理和 Fargate 运行时的 IAM 权限，通常包括拉取任务定义中定义的容器所需的 ECR 镜像的权限，以及写入容器日志配置中引用的 CloudWatch 日志组的权限：

```
...
...
Resources:
  ApplicationTaskExecutionRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              Service:
                - ecs-tasks.amazonaws.com
            Action:
              - sts:AssumeRole
      Policies:
        - PolicyName: EcsTaskExecutionRole
          PolicyDocument:
            Statement:
              - Sid: EcrPermissions
                Effect: Allow
                Action:
                  - ecr:BatchCheckLayerAvailability
                  - ecr:BatchGetImage
                  - ecr:GetDownloadUrlForLayer
                  - ecr:GetAuthorizationToken
                Resource: "*"
              - Sid: CloudwatchLogsPermissions
                Effect: Allow
                Action:
                  - logs:CreateLogStream
                  - logs:PutLogEvents
                Resource: !Sub ${ApplicationLogGroup.Arn}
  ApplicationTaskDefinition:
    Type: AWS::ECS::TaskDefinition
  ...
  ...
```

任务角色定义了从您的 ECS 任务定义中运行的应用程序可能需要的任何 IAM 权限。对于我们的用例，X-Ray 守护程序需要权限将跟踪发布到 X-Ray 服务，如下例所示：

```
Resources:
 ApplicationTaskRole:
 Type: AWS::IAM::Role
 Properties:
 AssumeRolePolicyDocument:
 Version: "2012-10-17"
 Statement:
 - Effect: Allow
 Principal:
 Service:
 - ecs-tasks.amazonaws.com
 Action:
 - sts:AssumeRole
 Policies:
 - PolicyName: EcsTaskRole
 PolicyDocument:
 Statement:
 - Effect: Allow
 Action:
 - xray:PutTraceSegments
 - xray:PutTelemetryRecords
 Resource: "*"    ApplicationTaskExecutionRole:
    Type: AWS::IAM::Role
  ...
  ...
```

在前面的例子中，您授予`xray:PutTraceSegments`和`xray:PutTelemetryRecords`权限给 X-Ray 守护程序，这允许守护程序将从您的应用程序捕获的应用程序跟踪发布到 X-Ray 服务。请注意，对于`ApplicationTaskExecutionRole`和`ApplicationTaskRole`资源，`AssumeRolePolicyDocument`部分中的受信任实体必须配置为`ecs-tasks.amazonaws.com`服务。

# 为 Fargate 配置 ECS 服务

现在您已经为 Fargate 定义了一个 ECS 任务定义，您可以创建一个 ECS 服务，该服务将引用您的 ECS 任务定义，并为您的服务部署一个或多个实例（ECS 任务）。

正如您可能期望的那样，在配置 ECS 服务以支持 Fargate 时，有一些关键考虑因素需要您注意：

+   **启动类型**：您必须指定 Fargate 作为任何要使用 Fargate 运行的 ECS 服务的启动类型。

+   **平台版本**：AWS 维护不同版本的 Fargate 运行时或平台，这些版本会随着时间的推移而发展，并且可能在某个时候为您的 ECS 服务引入破坏性更改。您可以选择为您的 ECS 服务针对特定的平台版本，或者简单地省略配置此属性，以使用最新可用的平台版本。

+   **网络配置**：因为 Fargate 需要使用**awsvpc**网络模式，您的 ECS 服务必须定义一个网络配置，定义您的 ECS 服务将在其中运行的子网，分配给您的 ECS 服务的安全组，以及您的服务是否分配了公共 IP 地址。在撰写本书时，当使用 Fargate 时，您必须分配公共 IP 地址或使用 NAT 网关，如章节*隔离网络访问*中所讨论的，以确保管理您的 ECS 服务的 ECS 代理能够与 ECS 通信，从 ECR 拉取镜像，并将日志发布到 CloudWatch 日志服务。

尽管您无法与 ECS 代理进行交互，但重要的是要理解所有 ECS 代理通信都使用与在 Fargate 中运行的容器应用程序相同的网络接口。这意味着您必须考虑 ECS 代理和 Fargate 运行时的通信需求，当附加安全组并确定您的 ECS 服务的网络放置时。

以下示例演示了为 Fargate 和 ECS 服务发现配置 ECS 服务：

```
...
...
Resources:
 ApplicationCluster:
 Type: AWS::ECS::Cluster
 Properties:
 ClusterName: !Sub ${AWS::StackName}-cluster
 ApplicationService:
 Type: AWS::ECS::Service
 DependsOn:
 - ApplicationLogGroup
 Properties:
 ServiceName: !Sub ${AWS::StackName}-application-service
 Cluster: !Ref ApplicationCluster
 TaskDefinition: !Ref ApplicationTaskDefinition
 DesiredCount: 2
 LaunchType: FARGATE
 NetworkConfiguration:
 AwsvpcConfiguration:
 AssignPublicIp: ENABLED
 SecurityGroups:
 - !Ref ApplicationSecurityGroup
 Subnets:
 - subnet-a5d3ecee
 - subnet-324e246f
 DeploymentConfiguration:
 MinimumHealthyPercent: 100
 MaximumPercent: 200
 ServiceRegistries:
 - RegistryArn: !Sub ${ApplicationServiceDiscoveryService.Arn}
  ApplicationTaskRole:
    Type: AWS::IAM::Role
  ...
  ...
```

在前面的示例中，首先要注意的是，尽管在使用 Fargate 时您不运行任何 ECS 容器实例或其他基础设施，但在为 Fargate 配置 ECS 服务时仍需要定义一个 ECS 集群，然后在您的 ECS 服务中引用它。

ECS 服务配置类似于在*隔离网络访问*章节中使用 ECS 任务网络运行 todobackend 应用程序时定义的配置，尽管有一些关键的配置属性需要讨论：

+   `LaunchType`：必须指定为`FARGATE`。确保将您的 ECS 服务放置在公共子网中，并在网络配置中将`AssignPublicIp`属性配置为`ENABLED`，或者将您的服务放置在带有 NAT 网关的私有子网中非常重要。在前面的示例中，请注意我已经将`Subnets`属性硬编码为我的 VPC 中的公共子网；您需要将这些值更改为您的环境的适当值，并且通常会通过堆栈参数注入这些值。

+   `ServiceRegistries`：此属性配置您的 ECS 服务以使用我们在本章前面配置的 ECS 服务发现功能，在这里，您引用了您在上一个示例中配置的服务发现服务的 ARN。有了这个配置，ECS 将自动在为链接的服务发现服务创建的 DNS 记录集中注册/注销每个 ECS 服务实例（ECS 任务）的 IP 地址。

在这一点上，还有一个最终需要配置的资源——您需要定义被您的 ECS 服务引用的`ApplicationSecurityGroup`资源：

```
...
...
Resources:
  ApplicationSecurityGroup:
 Type: AWS::EC2::SecurityGroup
 Properties:
 VpcId: vpc-f8233a80
 GroupDescription: !Sub ${AWS::StackName} Application Security Group
 SecurityGroupIngress:
 - IpProtocol: udp
 FromPort: 2000
 ToPort: 2000
 CidrIp: 172.31.0.0/16
 SecurityGroupEgress:
 - IpProtocol: tcp
 FromPort: 80
 ToPort: 80
 CidrIp: 0.0.0.0/0
 - IpProtocol: tcp
 FromPort: 443
 ToPort: 443
 CidrIp: 0.0.0.0/0
 - IpProtocol: udp
 FromPort: 53
 ToPort: 53
 CidrIp: 0.0.0.0/0
 Tags:
 - Key: Name
 Value: !Sub ${AWS::StackName}-ApplicationSecurityGroup
  ApplicationCluster:
    Type: AWS::ECS::Cluster
    Properties:
      ClusterName: !Sub ${AWS::StackName}-cluster
  ApplicationService:
    Type: AWS::ECS::Service
  ...
  ...
```

在上面的示例中，再次注意，我在这里使用了硬编码的值，而我通常会使用堆栈参数，以保持简单和简洁。安全组允许从 VPC 内的任何主机对 UDP 端口 2000 进行入口访问，而出口安全规则允许访问 DNS、HTTP 和 HTTPS，这是为了确保 ECS 代理可以与 ECS、ECR 和 CloudWatch 日志进行通信，以及 X-Ray 守护程序可以与 X-Ray 服务进行通信。

# 部署和测试 X-Ray 守护程序

此时，我们已经完成了配置 CloudFormation 模板的工作，该模板将使用启用了 ECS 服务发现的 Fargate 服务将 X-Ray 守护程序部署到 AWS；您可以使用`aws cloudformation deploy`命令将更改部署到您的堆栈中，包括`--capabilities`参数，因为我们的堆栈现在正在创建 IAM 资源：

```
> aws cloudformation deploy --template-file xray.yml --stack-name xray-daemon \
 --capabilities CAPABILITY_NAMED_IAM
Waiting for changeset to be created..
Waiting for stack create/update to complete
Successfully created/updated stack - xray-daemon
```

一旦部署完成，如果您在 AWS 控制台中打开 ECS 仪表板并选择集群，您应该会看到一个名为 xray-daemon-cluster 的新集群，其中包含一个单一服务和两个正在运行的任务，在 FARGATE 部分：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/c46789ab-3cb2-4a26-b6bc-229781c40131.png)X-Ray 守护程序集群

如果您选择集群并单击**xray-daemon-application-service**，您应该在“详细信息”选项卡中看到 ECS 服务发现配置已经就位：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/b005f475-d3a7-4e40-a393-cf610c7882a4.png)X-Ray 守护程序服务详细信息

在服务发现命名空间中，您现在应该找到附加到`xray.services.dockerinaws.org`记录集的两个地址记录，您可以通过导航到 Route 53 仪表板，从左侧菜单中选择托管区域，并选择`services.dockerinaws.org`区域来查看：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/fdcda94e-f9c6-49e2-87b9-b843c2465b05.png)服务发现 DNS 记录

请注意，这里有两个`A`记录，每个支持我们的 ECS 服务的 ECS 任务一个。如果您停止其中一个 ECS 任务，ECS 将自动从 DNS 中删除该记录，然后在 ECS 将 ECS 服务计数恢复到所需计数并启动替换的 ECS 任务后，添加一个新的`A`记录。这确保了您的服务具有高可用性，并且依赖于您的服务的应用程序可以动态解析适当的服务实例。

# 为 X-Ray 支持配置 todobackend 堆栈

有了我们的 X 射线守护程序服务，我们现在可以为`todobackend-aws`堆栈添加对 X 射线的支持。在本章的开头，您配置了 todobackend 应用程序对 X 射线的支持，如果您提交并推送了更改，您在上一章中创建的持续交付流水线应该已经将更新的 Docker 镜像发布到了 ECR（如果不是这种情况，请在 todobackend 存储库中运行`make publish`命令）。您需要执行的唯一其他配置是更新附加到 todobackend 集群实例的安全规则，以允许 X 射线通信，并确保 Docker 环境配置了适当的环境变量，以启用正确的 X 射线操作。

以下示例演示了在`todobackend-aws`堆栈中的`ApplicationAutoscalingSecurityGroup`资源中添加安全规则，该规则允许与 X 射线守护程序进行通信：

```
...
...
Resources:
  ...
  ...
  ApplicationAutoscalingSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: !Sub ${AWS::StackName} Application Autoscaling Security Group
      VpcId: !Ref VpcId
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 22
          ToPort: 22
          CidrIp: 0.0.0.0/0
      SecurityGroupEgress:
 - IpProtocol: udp
 FromPort: 2000
 ToPort: 2000
 CidrIp: 172.31.0.0/16
        - IpProtocol: udp
          FromPort: 53
          ToPort: 53
          CidrIp: 0.0.0.0/0
        - IpProtocol: tcp
          FromPort: 80
          ToPort: 80
          CidrIp: 0.0.0.0/0
        - IpProtocol: tcp
          FromPort: 443
          ToPort: 443
          CidrIp: 0.0.0.0/0
...
...
```

以下示例演示了为`ApplicationTaskDefinition`资源中的 todobackend 容器定义配置环境设置：

```
...
...
Resources:
  ...
  ...
  ApplicationAutoscalingSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
    ...
    ...
      ContainerDefinitions:
        - Name: todobackend
          Image: !Sub ${AWS::AccountId}.dkr.ecr.${AWS::Region}.amazonaws.com/docker-in-aws/todobackend:${ApplicationImageTag}
          MemoryReservation: 395
          Cpu: 245
          MountPoints:
            - SourceVolume: public
              ContainerPath: /public
          Environment:
            - Name: DJANGO_SETTINGS_MODULE
              Value: todobackend.settings_release
            - Name: MYSQL_HOST
              Value: !Sub ${ApplicationDatabase.Endpoint.Address}
            - Name: MYSQL_USER
              Value: todobackend
            - Name: MYSQL_DATABASE
              Value: todobackend
            - Name: SECRETS
              Value: todobackend/credentials
            - Name: AWS_DEFAULT_REGION
              Value: !Ref AWS::Region
            - Name: AWS_XRAY_DAEMON_ADDRESS
 Value: xray.services.dockerinaws.org:2000
...
...
```

在前面的示例中，您添加了一个名为`AWS_XRAY_DAEMON_ADDRESS`的变量，该变量引用了我们的 X 射线守护程序服务的`xray.services.dockerinaws.org`服务端点，并且必须以`<hostname>:<port>`的格式表示。

您可以通过设置`AWS_XRAY_TRACE_NAME`环境变量来覆盖 X 射线跟踪中使用的服务名称。在我们的场景中，我们在同一帐户中有 todobackend 应用程序的开发和生产实例，并希望确保每个应用程序环境都有自己的跟踪集。

如果您现在提交并推送所有更改到`todobackend-aws`存储库，则上一章的持续交付流水线应该会检测到更改并自动部署您的更新堆栈，或者您可以通过命令行运行`make deploy/dev`命令来部署更改。

# 测试 X 射线服务

在成功部署更改后，浏览到您环境的 todobackend URL，并与应用程序进行一些交互，例如添加一个`todo`项目。

如果您接下来从 AWS 控制台打开 X 射线仪表板（服务|开发人员工具|X 射线）并从左侧菜单中选择服务地图，您应该会看到一个非常简单的地图，其中包括 todobackend 应用程序。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/51bba37a-3dbf-4f06-8d4f-ecc168183a1c.png)X-Ray 服务地图

在上述截图中，我点击了 todobackend 服务，显示了右侧的服务详情窗格，显示了响应时间分布和响应状态响应等信息。另外，请注意，服务地图包括 todobackend RDS 实例，因为我们在本章的前一个示例中配置了应用程序以修补`mysql-connector-python`库。

如果您点击“查看跟踪”按钮，将显示该服务的跟踪；请注意，Django 的 X-Ray 中间件包括 URL 信息，允许根据 URL 对跟踪进行分组：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/d25b61ac-61ec-4621-8b3d-99a298865260.png)X-Ray 跟踪

在上述截图中，请注意 85%的跟踪都命中了一个 IP 地址 URL，这对应于正在进行的应用程序负载均衡器健康检查。如果您点击跟踪列表中的“年龄”列，以从最新到最旧对跟踪进行排序，您应该能够看到您对 todobackend 应用程序所做的请求，对我来说，是一个创建新的`todo`项目的`POST`请求。

您可以通过点击 ID 链接查看以下截图中`POST`跟踪的更多细节：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/9eaf6820-622f-422a-bbc3-6c5e41b1d710.png)X-Ray 跟踪详情

在上述截图中，您可以看到响应总共花费了 218 毫秒，并且进行了两次数据库调用，每次调用都少于 2 毫秒。如果您正在使用 X-Ray SDK 支持的其他库，您还可以看到这些库所做调用的跟踪信息；例如，通过 boto3 库进行的任何 AWS 服务调用，比如将文件复制到 S3 或将消息发布到 Kinesis 流，也会被捕获。显然，这种信息在排除应用程序性能问题时非常有用。

# 摘要

在本章中，您学习了如何使用 AWS Fargate 服务部署 Docker 应用程序。为了使事情更有趣，您还学习了如何利用 ECS 服务发现自动发布应用程序端点的服务可达性信息，这是传统方法的替代方案，传统方法是将应用程序端点发布在负载均衡器后面。最后，为了结束这一定会让您觉得有趣和有趣的章节，您为 todobackend 应用程序添加了对 AWS X-Ray 服务的支持，并部署了一个 X-Ray 守护程序服务，使用 Fargate 来捕获应用程序跟踪。

首先，您学习了如何为 Python Django 应用程序添加对 X-Ray 的支持，这只需要您添加一个拦截传入请求的 X-Ray 中间件组件，并且还需要修补支持包，例如 mysql-connector-python 和 boto3 库，这允许您捕获 MySQL 数据库调用和应用程序可能进行的任何 AWS 服务调用。然后，您为 X-Ray 守护程序创建了一个 Docker 镜像，并将其发布到弹性容器注册表，以便在您的 AWS 环境中部署。

然后，您学习了如何配置 ECS 服务发现所需的支持元素，添加了一个服务发现命名空间，创建了一个公共或私有 DNS 区域，其中维护了服务发现服务端点，然后为 X-Ray 守护程序创建了一个服务发现服务，允许您的 todobackend 应用程序（以及其他应用程序）通过逻辑 DNS 名称发现所有活动和健康的 X-Ray 守护程序实例。

有了这些组件，您继续创建了一个使用 Fargate 的 X-Ray 守护程序服务，创建了一个 ECS 任务定义和一个 ECS 服务。ECS 任务定义对支持 Fargate 有一些特定要求，包括定义一个单独的任务执行角色，该角色授予基础 ECS 代理和 Fargate 运行时的特权，指定 Fargate 作为支持的启动类型，并确保配置了 awsvpc 网络模式。您创建的 ECS 服务要求您配置网络配置以支持 ECS 任务定义的 awsvpc 网络模式。您还通过引用本章早些时候创建的服务发现服务，为 ECS 服务添加了对 ECS 服务发现的支持。

最后，您在 todobackend 堆栈中配置了现有的 ECS 任务定义，以将服务发现服务名称指定为`AWS_XRAY_DAEMON_ADDRESS`变量；在部署更改后，您学会了如何使用 X-Ray 跟踪来分析传入请求到您的应用程序的性能，并能够对 todobackend 应用程序数据库的个别调用进行分析。

在下一章中，您将了解另一个支持 Docker 应用程序的 AWS 服务，称为 Elastic Beanstalk。它提供了一种平台即服务（PaaS）的方法，用于在 AWS 中部署和运行基于容器的应用程序。

# 问题

1.  Fargate 是否需要您创建 ECS 集群？

1.  在配置 Fargate 时，支持哪些网络模式？

1.  真/假：Fargate 将 ECS 代理的控制平面网络通信与 ECS 任务的数据平面网络通信分开。

1.  您使用 Fargate 部署一个新的 ECS 服务，但失败了，出现错误指示无法拉取任务定义中指定的 ECR 镜像。您验证了镜像名称和标签是正确的，并且任务定义的`TaskRoleArn`属性引用的 IAM 角色允许访问 ECR 存储库。这个错误最有可能的原因是什么？

1.  根据这些要求，您正在确定在 AWS 中部署基于容器的应用程序的最佳技术。您的组织部署 Splunk 来收集所有应用程序的日志，并使用 New Relic 来收集性能指标。基于这些要求，Fargate 是否是一种合适的技术？

1.  真/假：ECS 服务发现使用 Consul 发布服务注册信息。

1.  哪种服务发现资源创建了 Route 53 区域？

1.  您配置了一个 ECS 任务定义来使用 Fargate，并指定任务应分配 400 个 CPU 单位和 600 MB 的内存。当您部署使用任务定义的 ECS 服务时，部署失败了。您如何解决这个问题？

1.  默认情况下，AWS X-Ray 通信使用哪种网络协议和端口？

1.  真/假：当您为基于容器的应用程序添加 X-Ray 支持时，它们将发布跟踪到 AWS X-Ray 服务。

# 进一步阅读

您可以查看本章涵盖的主题的更多信息的以下链接：

+   AWS Fargate on Amazon ECS: [`docs.aws.amazon.com/AmazonECS/latest/developerguide/AWS_Fargate.html`](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/AWS_Fargate.html)

+   Amazon ECS 任务执行 IAM 角色: [`docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecs-service.html`](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecs-service.html)

+   ECS 服务发现: [`docs.aws.amazon.com/AmazonECS/latest/developerguide/service-discovery.html`](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/service-discovery.html)

+   AWS X-Ray 开发人员指南: [`docs.aws.amazon.com/xray/latest/devguide/aws-xray.html`](https://docs.aws.amazon.com/xray/latest/devguide/aws-xray.html)

+   AWS X-Ray Python SDK: [`docs.aws.amazon.com/xray/latest/devguide/xray-sdk-python.html`](https://docs.aws.amazon.com/xray/latest/devguide/xray-sdk-python.html)

+   在 Amazon ECS 上运行 X-Ray 守护程序: [`docs.aws.amazon.com/xray/latest/devguide/xray-daemon-ecs.html`](https://docs.aws.amazon.com/xray/latest/devguide/xray-daemon-ecs.html)

+   CloudFormation 服务发现公共命名空间资源参考: [`docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-servicediscovery-publicdnsnamespace.html`](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-servicediscovery-publicdnsnamespace.html)

+   CloudFormation 服务发现私有命名空间资源参考: [`docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-servicediscovery-privatednsnamespace.html`](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-servicediscovery-privatednsnamespace.html)

+   CloudFormation 服务发现服务资源参考: [`docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-servicediscovery-service.html`](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-servicediscovery-service.html)

+   CloudFormation ECS 任务定义资源参考: [`docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecs-taskdefinition.html`](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecs-taskdefinition.html)

+   CloudFormation ECS 服务资源参考: [`docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecs-service.html`](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecs-service.html)


# 第十五章：弹性 Beanstalk

到目前为止，在本书中，我们已经专注于使用弹性容器服务（ECS）及其变体 AWS Fargate 来管理和部署 Docker 应用程序。本书的其余部分将专注于您可以使用的替代技术，以在 AWS 中运行 Docker 应用程序，我们将首先介绍的是弹性 Beanstalk。

弹性 Beanstalk 属于行业通常称为**平台即服务**（**PaaS**）的类别，旨在为您的应用程序提供受管的运行时环境，让您专注于开发、部署和操作应用程序，而不必担心周围的基础设施。为了强调这一范式，弹性 Beanstalk 专注于支持各种流行的编程语言，如 Node.js、PHP、Python、Ruby、Java、.NET 和 Go 应用程序。创建弹性 Beanstalk 应用程序时，您会指定目标编程语言，弹性 Beanstalk 将部署一个支持您的编程语言和相关运行时和应用程序框架的环境。弹性 Beanstalk 还将部署支持基础设施，如负载均衡器和数据库，更重要的是，它将配置您的环境，以便您可以轻松访问日志、监控信息和警报，确保您不仅可以部署应用程序，还可以监视它们，并确保它们处于最佳状态下运行。

除了前面提到的编程语言外，弹性 Beanstalk 还支持 Docker 环境，这意味着它可以支持在 Docker 容器中运行的任何应用程序，无论编程语言或应用程序运行时如何。在本章中，您将学习如何使用弹性 Beanstalk 来管理和部署 Docker 应用程序。您将学习如何使用 AWS 控制台创建弹性 Beanstalk 应用程序并创建一个环境，其中包括应用程序负载均衡器和我们应用程序所需的 RDS 数据库实例。您将遇到一些初始设置问题，并学习如何使用 AWS 控制台和弹性 Beanstalk 命令行工具来诊断和解决这些问题。

为了解决这些问题，您将配置一个名为**ebextensions**的功能，这是 Elastic Beanstalk 的高级配置功能，可用于将许多自定义配置方案应用于您的应用程序。您将利用 ebextensions 来解决 Docker 卷的权限问题，将 Elastic Beanstalk 生成的默认环境变量转换为应用程序期望的格式，并最终确保诸如执行数据库迁移之类的一次性部署任务仅在每个应用程序部署的单个实例上运行。

本章不旨在详尽介绍 Elastic Beanstalk，并且只关注与部署和管理 Docker 应用程序相关的核心场景。有关对其他编程语言的支持和更高级场景的覆盖，请参考[AWS Elastic Beanstalk 开发人员指南](https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/Welcome.html)。

本章将涵盖以下主题：

+   Elastic Beanstalk 简介

+   使用 AWS 控制台创建 Elastic Beanstalk 应用程序

+   使用 Elastic Beanstalk CLI 管理 Elastic Beanstalk 应用程序

+   自定义 Elastic Beanstalk 应用程序

+   部署和测试 Elastic Beanstalk 应用程序

# 技术要求

本章的技术要求如下：

+   AWS 帐户的管理员访问权限

+   本地环境按照第一章的说明进行配置

+   本地 AWS 配置文件，按照第三章的说明进行配置

+   Python 2.7 或 3.x

+   PIP 软件包管理器

+   AWS CLI 版本 1.15.71 或更高版本

+   Docker 18.06 CE 或更高版本

+   Docker Compose 1.22 或更高版本

+   GNU Make 3.82 或更高版本

本章假设您已成功完成本书迄今为止涵盖的所有配置任务

以下 GitHub URL 包含本章中使用的代码示例：[`github.com/docker-in-aws/docker-in-aws/tree/master/ch14`](https://github.com/docker-in-aws/docker-in-aws/tree/master/ch14)。

查看以下视频以查看代码的实际操作：

[`bit.ly/2MDhtj2`](http://bit.ly/2MDhtj2)

# Elastic Beanstalk 简介

正如本章介绍中所讨论的，Elastic Beanstalk 是 AWS 提供的 PaaS 服务，允许您专注于应用程序代码和功能，而不必担心支持应用程序所需的周围基础设施。为此，Elastic Beanstalk 在其方法上有一定的偏见，并且通常以特定的方式工作。Elastic Beanstalk 尽可能地利用其他 AWS 服务，并试图消除与这些服务集成的工作量和复杂性，如果您按照 Elastic Beanstalk 期望您使用这些服务的方式，这将非常有效。如果您在一个中小型组织中运行一个小团队，Elastic Beanstalk 可以为您提供很多价值，提供了大量的开箱即用功能。然而，一旦您的组织发展壮大，并且希望优化和标准化部署、监控和操作应用程序的方式，您可能会发现您已经超出了 Elastic Beanstalk 的个体应用程序重点的范围。

例如，重要的是要了解 Elastic Beanstalk 基于每个 EC2 实例的单个 ECS 任务定义的概念运行，因此，如果您希望在共享基础设施上运行多个容器工作负载，Elastic Beanstalk 不是您的正确选择。相同的情况也适用于日志记录和操作工具 - 一般来说，Elastic Beanstalk 提供了其专注于个体应用程序的工具链，而您的组织可能希望采用跨多个应用程序运行的标准工具集。就个人而言，我更喜欢使用 ECS 提供的更灵活和可扩展的方法，但我必须承认，Elastic Beanstalk 免费提供的一些开箱即用的操作和监控工具对于快速启动应用程序并与其他 AWS 服务完全集成非常有吸引力。

# Elastic Beanstalk 概念

本章主要关注使用 Elastic Beanstalk 运行 Docker 应用程序，因此不要期望对 Elastic Beanstalk 及其支持的所有编程语言进行详尽的覆盖。然而，在我们开始创建 Elastic Beanstalk 应用程序之前，了解基本概念是很重要的，我将在这里简要介绍一下。

在使用 Elastic Beanstalk 时，您创建*应用程序*，可以定义一个或多个*环境*。以 todobackend 应用程序为例，您将把 todobackend 应用程序定义为 Elastic Beanstalk 应用程序，并创建一个名为 Dev 的环境和一个名为 Prod 的环境，以反映我们迄今部署的开发和生产环境。每个环境引用应用程序的特定版本，其中包含应用程序的可部署代码。对于 Docker 应用程序，源代码包括一个名为`Dockerrun.aws.json`的规范，该规范定义了应用程序的容器环境，可以引用外部 Docker 镜像或引用用于构建应用程序的本地 Dockerfile。

另一个重要的概念要了解的是，在幕后，Elastic Beanstalk 在常规 EC2 实例上运行您的应用程序，并遵循一个非常严格的范例，即每个 EC2 实例运行一个应用程序实例。每个 Elastic Beanstalk EC2 实例都运行一个根据目标应用程序特别策划的环境，例如，在多容器 Docker 应用程序的情况下，EC2 实例包括 Docker 引擎和 ECS 代理。Elastic Beanstalk 还允许您通过 SSH 访问和管理这些 EC2 实例（在本章中我们将使用 Linux 服务器），尽管您通常应该将此访问保留用于故障排除目的，并且永远不要尝试直接修改这些实例的配置。

# 创建一个 Elastic Beanstalk 应用程序

现在您已经了解了 Elastic Beanstalk 的基本概念，让我们把注意力转向创建一个新的 Elastic Beanstalk 应用程序。您可以使用各种方法创建和配置 Elastic Beanstalk 应用程序：

+   AWS 控制台

+   AWS CLI 和 SDK

+   AWS CloudFormation

+   Elastic Beanstalk CLI

在本章中，我们将首先在 AWS 控制台中创建一个 Elastic Beanstalk 应用程序，然后使用 Elastic Beanstalk CLI 来管理、更新和完善应用程序。

创建 Docker 应用程序时，重要的是要了解 Elastic Beanstalk 支持两种类型的 Docker 应用程序：

+   单容器应用程序：[`docs.aws.amazon.com/elasticbeanstalk/latest/dg/docker-singlecontainer-deploy.html`](https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/docker-singlecontainer-deploy.html)

+   多容器应用程序：[`docs.aws.amazon.com/elasticbeanstalk/latest/dg/create_deploy_docker_ecs.html`](https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/create_deploy_docker_ecs.html)

对于我们的用例，我们将采用与之前章节中为 ECS 配置 todobackend 应用程序的非常相似的方法，因此我们将需要一个多容器应用程序，因为我们之前在 ECS 任务定义中定义了一个名为**todobackend**的主应用程序容器定义和一个**collectstatic**容器定义（请参阅章节*使用 CloudFormation 定义 ECS 任务定义*中的*部署使用 ECS 的应用程序*）。总的来说，我建议采用多容器方法，无论您的应用程序是否是单容器应用程序，因为原始的单容器应用程序模型违反了 Docker 最佳实践，并且在应用程序要求发生变化或增长时，强制您从单个容器中运行所有内容。

# 创建 Dockerrun.aws.json 文件

无论您创建的是什么类型的 Docker 应用程序，您都必须首先创建一个名为`Dockerrun.aws.json`的文件，该文件定义了组成您的应用程序的各种容器。该文件以 JSON 格式定义，并基于您在之前章节中配置的 ECS 任务定义格式，我们将以此为`Dockerrun.aws.json`文件中的设置基础。

让我们在`todobackend-aws`存储库中创建一个名为`eb`的文件夹，并定义一个名为`Dockerrun.aws.json`的新文件，如下所示：

```
{
  "AWSEBDockerrunVersion": 2,
  "volumes": [
    {
      "name": "public",
      "host": {"sourcePath": "/tmp/public"}
    }
  ],
  "containerDefinitions": [
    {
      "name": "todobackend",
      "image": "385605022855.dkr.ecr.us-east-1.amazonaws.com/docker-in-aws/todobackend",
      "essential": true,
      "memoryReservation": 395,
      "mountPoints": [
        {
          "sourceVolume": "public",
          "containerPath": "/public"
        }
      ],
      "environment": [
        {"name":"DJANGO_SETTINGS_MODULE","value":"todobackend.settings_release"}
      ],
      "command": [
        "uwsgi",
        "--http=0.0.0.0:8000",
        "--module=todobackend.wsgi",
        "--master",
        "--die-on-term",
        "--processes=4",
        "--threads=2",
        "--check-static=/public"
      ],
      "portMappings": [
        {
          "hostPort": 80,
          "containerPort": 8000
        }
      ]
    },
    {
      "name": "collectstatic",
      "image": "385605022855.dkr.ecr.us-east-1.amazonaws.com/docker-in-aws/todobackend",
      "essential": false,
      "memoryReservation": 5,
      "mountPoints": [
        {
          "sourceVolume": "public",
          "containerPath": "/public"
        }
      ],
      "environment": [
        {"name":"DJANGO_SETTINGS_MODULE","value":"todobackend.settings_release"}
      ],
      "command": [
        "python3",
        "manage.py",
        "collectstatic",
        "--no-input"
      ]
    }
  ]
}
```

在定义多容器 Docker 应用程序时，您必须指定并使用规范格式的第 2 版本，该版本通过`AWSEBDockerrunVersion`属性进行配置。如果您回顾一下章节*使用 ECS 部署应用程序*中的*使用 CloudFormation 定义 ECS 任务定义*，您会发现`Dockerrun.aws.json`文件的第 2 版本规范非常相似，尽管格式是 JSON，而不是我们在 CloudFormation 模板中使用的 YAML 格式。我们使用驼峰命名来定义每个参数。

文件包括两个容器定义——一个用于主要的 todobackend 应用程序，另一个用于生成静态内容——我们定义了一个名为`public`的卷，用于存储静态内容。我们还配置了一个静态端口映射，将容器端口 8000 映射到主机的端口 80，因为 Elastic Beanstalk 默认期望您的 Web 应用程序在端口 80 上监听。

请注意，与我们用于 ECS 的方法相比，有一些重要的区别。

+   **镜像**：我们引用相同的 ECR 镜像，但是我们没有指定镜像标签，这意味着最新版本的 Docker 镜像将始终被部署。`Dockerrun.aws.json`文件不支持参数或变量引用，因此如果您想引用一个明确的镜像，您需要一个自动生成此文件的持续交付工作流作为构建过程的一部分。

+   **环境**：请注意，我们没有指定与数据库配置相关的任何环境变量，比如`MYSQL_HOST`或`MYSQL_USER`。我们将在本章后面讨论这样做的原因，但现在要明白的是，当您在 Elastic Beanstalk 中使用 RDS 的集成支持时，自动可用于应用程序的环境变量遵循不同的格式，我们需要转换以满足我们应用程序的期望。

+   **日志**：我已经删除了 CloudWatch 日志配置，以简化本章，但您完全可以在您的容器中包含 CloudWatch 日志配置。请注意，如果您使用了 CloudWatch 日志，您需要修改 Elastic Beanstalk EC2 服务角色，以包括将您的日志写入 CloudWatch 日志的权限。我们将在本章后面看到一个例子。

我还删除了`XRAY_DAEMON_ADDRESS`环境变量，以保持简单，因为您可能不再在您的环境中运行 X-Ray 守护程序。请注意，如果您确实想支持 X-Ray，您需要确保附加到 Elastic Beanstalk 实例的实例安全组包含允许与 X-Ray 守护程序进行网络通信的安全规则。

现在我们已经定义了一个`Dockerrun.aws.json`文件，我们需要创建一个 ZIP 存档，其中包括这个文件。Elastic Beanstalk 要求您的应用程序源代码以 ZIP 或 WAR 存档格式上传，因此有这个要求。您可以通过使用`zip`实用程序从命令行执行此操作：

```
todobackend-aws/eb> zip -9 -r app.zip . -x .DS_Store
adding: Dockerrun.aws.json (deflated 69%)
```

这将在`todobackend-aws/eb`文件夹中创建一个名为`app.zip`的存档，使用`-r`标志指定 zip 应该递归添加所有可能存在的文件夹中的所有文件（这将在本章后面的情况下发生）。在指定`app.zip`的存档名称后，我们通过指定`.`而不是`*`来引用当前工作目录，因为使用`.`语法将包括任何隐藏的目录或文件（同样，这将在本章后面的情况下发生）。

还要注意，在 macOS 环境中，您可以使用`-x`标志来排除`.DS_Store`目录元数据文件，以防止其被包含在存档中。

# 使用 AWS 控制台创建一个弹性 Beanstalk 应用程序

现在我们准备使用 AWS 控制台创建一个弹性 Beanstalk 应用程序。要开始，请选择**服务** | **弹性 Beanstalk**，然后单击**开始**按钮创建一个新应用程序。在**创建 Web 应用程序**屏幕上，指定一个名为 todobackend 的应用程序名称，配置一个**多容器 Docker**的平台，最后使用**上传您的代码**选项为**应用程序代码**设置上传之前创建的`app.zip`文件：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/d841d257-68b2-4f59-8ea4-50c2ff17d47f.png)创建一个弹性 Beanstalk Web 应用程序

接下来，点击**配置更多选项**按钮，这将呈现一个名为**配置 Todobackend-Env**的屏幕，允许您自定义应用程序。请注意，默认情况下，弹性 Beanstalk 将您的第一个应用程序环境命名为`<application-name>-Env`，因此名称为**Todobackend-Env**。

在配置预设部分，选择**高可用性**选项，这将向您的配置添加一个负载均衡器：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/5e471f97-8e8c-4707-9949-f22419a59c26.png)配置弹性 Beanstalk Web 应用程序

如果您查看当前设置，您会注意到**EC2 实例类型**在**实例**部分是**t1.micro**，**负载均衡器类型**在**负载均衡器**部分是**经典**，而**数据库**部分目前未配置。让我们首先通过单击**实例**部分的**修改**链接，更改**实例类型**，然后单击**保存**来修改**EC2 实例类型**为免费层**t2.micro**实例类型：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/6955ffa0-6782-47dd-aed1-eca0baed8119.png)修改 EC2 实例类型

接下来，通过单击**负载均衡器**部分中的**修改**链接，然后单击**保存**，将**负载均衡器类型**更改为**应用程序负载均衡器**。请注意，默认设置期望在**应用程序负载均衡器**和**规则**部分中将您的应用程序暴露在端口`80`上，以及您的容器在 EC2 实例上的端口 80 上，如**进程**部分中定义的那样：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/cb26c7fb-cf9e-4789-bf21-df41b88b4254.png)

修改负载均衡器类型

最后，我们需要通过单击**数据库**部分中的**修改**链接为应用程序定义数据库配置。选择**mysql**作为**引擎**，指定适当的**用户名**和**密码**，最后将**保留**设置为**删除**，因为我们只是为了测试目的而使用这个环境。其他设置的默认值足够，因此在完成配置后，可以单击**保存**按钮：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/2a591e2a-6b48-4839-bcc2-e776bfeb2e48.png)配置数据库设置

在这一点上，您已经完成了应用程序的配置，并且可以单击**配置 Todobackend-env**屏幕底部的**创建应用程序**按钮。弹性 Beanstalk 现在将开始创建您的应用程序，并在控制台中显示此过程的进度。

弹性 Beanstalk 应用程序向导在幕后创建了一个包括您指定的所有资源和配置的 CloudFormation 堆栈。也可以使用 CloudFormation 创建自己的弹性 Beanstalk 环境，而不使用向导。

一段时间后，应用程序的创建将完成，尽管您可以看到应用程序存在问题：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/a97cdb26-7e8f-412b-b2d9-570cd14d3b30.png)初始应用程序状态

# 配置 EC2 实例配置文件

我们已经创建了一个新的弹性 Beanstalk 应用程序，但由于几个错误，当前应用程序的健康状态记录为严重。

如果您在左侧菜单中选择**日志**选项，然后选择**请求日志** | **最后 100 行**，您应该会看到一个**下载**链接，可以让您查看最近的日志活动：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/d8b79e73-f968-41de-8d12-f59c8321ea8b.png)初始应用程序状态

在您的浏览器中应该打开一个新的标签页，显示各种 Elastic Beanstalk 日志。在顶部，您应该看到 ECS 代理日志，最近的错误应该指示 ECS 代理无法从 ECR 将图像拉入您的`Dockerrun.aws.json`规范中：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/a7babaa2-adec-436b-a371-eb476c40aa2e.png)Elastic Beanstalk ECS 代理错误

为了解决这个问题，我们需要配置与附加到我们的 Elastic Beanstalk 实例的 EC2 实例配置文件相关联的 IAM 角色，以包括从 ECR 拉取图像的权限。我们可以通过从左侧菜单中选择**配置**并在**安全**部分中查看**虚拟机实例配置文件**设置来查看 Elastic Beanstalk 正在使用的角色：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/2d1d05a4-22bd-4106-b6d2-d9ec1c92ef5e.png)查看安全配置

您可以看到正在使用名为**aws-elasticbeanstalk-ec2-role**的 IAM 角色，因此，如果您从导航栏中选择**服务** | **IAM**，选择**角色**，然后找到 IAM 角色，您需要按照以下方式将`AmazonEC2ContainerRegistryReadOnly`策略附加到角色：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/4c1d7e88-a2ae-4e62-8813-813fe2d2bc81.png)将 AmazonEC2ContainerRegistryReadOnly 策略附加到 Elastic Beanstack EC2 实例角色

在这一点上，我们应该已经解决了之前导致应用程序启动失败的权限问题。您现在需要配置 Elastic Beanstalk 尝试重新启动应用程序，可以使用以下任一技术来执行：

+   上传新的应用程序源文件-这将触发新的应用程序部署。

+   重新启动应用程序服务器

+   重建环境

鉴于我们的应用程序源（在 Docker 应用程序的情况下是`Dockerrun.aws.json`文件）没有更改，最不破坏性和最快的选项是重新启动应用程序服务器，您可以通过在**所有应用程序** | **todobackend** | **Todobackend-env**配置屏幕的右上角选择**操作** | **重新启动应用程序服务器(s)**来执行。

几分钟后，您会注意到您的应用程序仍然存在问题，如果您重复获取最新日志的过程，并扫描这些日志，您会发现**collectstatic**容器由于权限错误而失败：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/d000d79b-4c00-425c-9d45-95325d27e079.png)collectstatic 权限错误

回想一下，在本书的早些时候，我们如何在我们的 ECS 容器实例上配置了一个具有正确权限的文件夹，以托管**collectstatic**容器写入的公共卷？对于 Elastic Beanstalk，为 Docker 应用程序创建的默认 EC2 实例显然没有以这种方式进行配置。

我们将很快解决这个问题，但现在重要的是要了解还有其他问题。要了解这些问题，您需要尝试访问应用程序，您可以通过单击 All Applications | todobackend | Todobackend-env 配置屏幕顶部的 URL 链接来实现：

获取 Elastic Beanstalk 应用程序 URL

浏览到此链接应立即显示静态内容文件未生成：

缺少静态内容

如果您单击**todos**链接以查看当前的 Todo 项目列表，您将收到一个错误，指示应用程序无法连接到 MySQL 数据库：

数据库连接错误

问题在于我们尚未向`Dockerrun.aws.json`文件添加任何数据库配置，因此我们的应用程序默认使用本地主机来定位数据库。

# 使用 CLI 配置 Elastic Beanstalk 应用程序

我们将很快解决我们应用程序中仍然存在的问题，但为了解决这些问题，我们将继续使用 Elastic Beanstalk CLI 来继续配置我们的应用程序并解决这些问题。

在我们开始使用 Elastic Beanstalk CLI 之前，重要的是要了解，当前版本的该应用程序在与我们在早期章节中引入的多因素身份验证（MFA）要求进行交互时存在一些挑战。如果您继续使用 MFA，您会注意到每次执行 Elastic Beanstalk CLI 命令时都会提示您。

为了解决这个问题，我们可以通过首先将用户从`Users`组中删除来临时删除 MFA 要求：

```
> aws iam remove-user-from-group --user-name justin.menga --group-name Users
```

接下来，在本地的`~/.aws/config`文件中的`docker-in-aws`配置文件中注释掉`mfa_serial`行：

```
[profile docker-in-aws]
source_profile = docker-in-aws
role_arn = arn:aws:iam::385605022855:role/admin
role_session_name=justin.menga
region = us-east-1
# mfa_serial = arn:aws:iam::385605022855:mfa/justin.menga
```

请注意，这并不理想，在实际情况下，您可能无法或不想临时禁用特定用户的 MFA。在考虑 Elastic Beanstalk 时，请记住这一点，因为您通常会依赖 Elastic Beanstalk CLI 执行许多操作。

现在 MFA 已被临时禁用，您可以安装 Elastic Beanstalk CLI，您可以使用 Python 的`pip`软件包管理器来安装它。安装完成后，可以通过`eb`命令访问它：

```
> pip3 install awsebcli --user
Collecting awsebcli
...
...
Installing collected packages: awsebcli
Successfully installed awsebcli-3.14.2
> eb --version
EB CLI 3.14.2 (Python 3.6.5)
```

下一步是在您之前创建的`todobackend/eb`文件夹中初始化 CLI：

```
todobackend/eb> eb init --profile docker-in-aws

Select a default region
1) us-east-1 : US East (N. Virginia)
2) us-west-1 : US West (N. California)
3) us-west-2 : US West (Oregon)
4) eu-west-1 : EU (Ireland)
5) eu-central-1 : EU (Frankfurt)
6) ap-south-1 : Asia Pacific (Mumbai)
7) ap-southeast-1 : Asia Pacific (Singapore)
8) ap-southeast-2 : Asia Pacific (Sydney)
9) ap-northeast-1 : Asia Pacific (Tokyo)
10) ap-northeast-2 : Asia Pacific (Seoul)
11) sa-east-1 : South America (Sao Paulo)
12) cn-north-1 : China (Beijing)
13) cn-northwest-1 : China (Ningxia)
14) us-east-2 : US East (Ohio)
15) ca-central-1 : Canada (Central)
16) eu-west-2 : EU (London)
17) eu-west-3 : EU (Paris)
(default is 3): 1

Select an application to use
1) todobackend
2) [ Create new Application ]
(default is 2): 1
Cannot setup CodeCommit because there is no Source Control setup, continuing with initialization
```

`eb init`命令使用`--profile`标志来指定本地 AWS 配置文件，然后提示您将要交互的区域。然后 CLI 会检查是否存在任何现有的 Elastic Beanstalk 应用程序，并询问您是否要管理现有应用程序或创建新应用程序。一旦您做出选择，CLI 将在名为`.elasticbeanstalk`的文件夹下将项目信息添加到当前文件夹中，并创建或追加到`.gitignore`文件。鉴于我们的`eb`文件夹是**todobackend**存储库的子目录，将`.gitignore`文件的内容追加到**todobackend**存储库的根目录是一个好主意：

```
todobackend-aws/eb> cat .gitignore >> ../.gitignore todobackend-aws/eb> rm .gitignore 
```

您现在可以使用 CLI 查看应用程序的当前状态，列出应用程序环境，并执行许多其他管理任务：

```
> eb status
Environment details for: Todobackend-env
  Application name: todobackend
  Region: us-east-1
  Deployed Version: todobackend-source
  Environment ID: e-amv5i5upx4
  Platform: arn:aws:elasticbeanstalk:us-east-1::platform/multicontainer Docker running on 64bit Amazon Linux/2.11.0
  Tier: WebServer-Standard-1.0
  CNAME: Todobackend-env.p6z6jvd24y.us-east-1.elasticbeanstalk.com
  Updated: 2018-07-14 23:23:28.931000+00:00
  Status: Ready
  Health: Red
> eb list
* Todobackend-env
> eb open
> eb logs 
Retrieving logs...
============= i-0f636f261736facea ==============
-------------------------------------
/var/log/ecs/ecs-init.log
-------------------------------------
2018-07-14T22:41:24Z [INFO] pre-start
2018-07-14T22:41:25Z [INFO] start
2018-07-14T22:41:25Z [INFO] No existing agent container to remove.
2018-07-14T22:41:25Z [INFO] Starting Amazon Elastic Container Service Agent

-------------------------------------
/var/log/eb-ecs-mgr.log
-------------------------------------
2018-07-14T23:20:37Z "cpu": "0",
2018-07-14T23:20:37Z "containers": [
...
...
```

请注意，`eb status`命令会列出应用程序的 URL 在`CNAME`属性中，请记下这个 URL，因为您需要在本章中测试您的应用程序。您还可以使用`eb open`命令访问您的应用程序，这将在您的默认浏览器中打开应用程序的 URL。

# 管理 Elastic Beanstalk EC2 实例

在使用 Elastic Beanstalk 时，能够访问 Elastic Beanstalk EC2 实例是很有用的，特别是如果您需要进行一些故障排除。

CLI 包括建立与 Elastic Beanstalk EC2 实例的 SSH 连接的功能，您可以通过运行`eb ssh --setup`命令来设置它：

```
> eb ssh --setup
WARNING: You are about to setup SSH for environment "Todobackend-env". If you continue, your existing instances will have to be **terminated** and new instances will be created. The environment will be temporarily unavailable.
To confirm, type the environment name: Todobackend-env

Select a keypair.
1) admin
2) [ Create new KeyPair ]
(default is 1): 1
Printing Status:
Printing Status:
INFO: Environment update is starting.
INFO: Updating environment Todobackend-env's configuration settings.
INFO: Created Auto Scaling launch configuration named: awseb-e-amv5i5upx4-stack-AWSEBAutoScalingLaunchConfiguration-8QN6BJJX43H
INFO: Deleted Auto Scaling launch configuration named: awseb-e-amv5i5upx4-stack-AWSEBAutoScalingLaunchConfiguration-JR6N80L37H2G
INFO: Successfully deployed new configuration to environment.
```

请注意，设置 SSH 访问需要您终止现有实例并创建新实例，因为您只能在创建 EC2 实例时将 SSH 密钥对与实例关联。在选择您在本书中早期创建的现有 `admin` 密钥对后，CLI 终止现有实例，创建一个新的自动缩放启动配置以启用 SSH 访问，然后启动新实例。

在创建弹性 Beanstalk 应用程序时，您可以通过在配置向导的安全部分中配置 EC2 密钥对来避免此步骤。

现在，您可以按照以下步骤 SSH 进入您的弹性 Beanstalk EC2 实例：

```
> eb ssh -e "ssh -i ~/.ssh/admin.pem"
INFO: Attempting to open port 22.
INFO: SSH port 22 open.
INFO: Running ssh -i ~/.ssh/admin.pem ec2-user@34.239.245.78
The authenticity of host '34.239.245.78 (34.239.245.78)' can't be established.
ECDSA key fingerprint is SHA256:93m8hag/EtCPb5i7YrYHUXFPloaN0yUHMVFFnbMlcLE.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '34.239.245.78' (ECDSA) to the list of known hosts.
 _____ _ _ _ ____ _ _ _
| ____| | __ _ ___| |_(_) ___| __ ) ___ __ _ _ __ ___| |_ __ _| | | __
| _| | |/ _` / __| __| |/ __| _ \ / _ \/ _` | '_ \/ __| __/ _` | | |/ /
| |___| | (_| \__ \ |_| | (__| |_) | __/ (_| | | | \__ \ || (_| | | <
|_____|_|\__,_|___/\__|_|\___|____/ \___|\__,_|_| |_|___/\__\__,_|_|_|\_\
 Amazon Linux AMI

This EC2 instance is managed by AWS Elastic Beanstalk. Changes made via SSH
WILL BE LOST if the instance is replaced by auto-scaling. For more information
on customizing your Elastic Beanstalk environment, see our documentation here:
http://docs.aws.amazon.com/elasticbeanstalk/latest/dg/customize-containers-ec2.html
```

默认情况下，`eb ssh` 命令将尝试使用名为 `~/.ssh/<ec2-keypair-name>.pem` 的 SSH 私钥，本例中为 `~/.ssh/admin.pem`。如果您的 SSH 私钥位于不同位置，您可以使用 `-e` 标志来覆盖使用的文件，就像上面的示例中演示的那样。

现在，您可以查看一下您的弹性 Beanstalk EC2 实例。鉴于我们正在运行一个 Docker 应用程序，您可能首先倾向于运行 `docker ps` 命令以查看当前正在运行的容器：

```
[ec2-user@ip-172-31-20-192 ~]$ docker ps
Got permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock: Get http://%2Fvar%2Frun%2Fdocker.sock/v1.37/containers/json: dial unix /var/run/docker.sock: connect: permission denied
```

令人惊讶的是，标准的 `ec2-user` 没有访问 Docker 的权限 - 为了解决这个问题，我们需要添加更高级的配置，称为 **ebextensions**。

# 自定义弹性 Beanstalk 应用程序

如前一节所讨论的，我们需要添加一个 ebextension，它只是一个配置文件，可用于自定义您的弹性 Beanstalk 环境以适应我们现有的弹性 Beanstalk 应用程序。这是一个重要的概念需要理解，因为我们最终将使用相同的方法来解决我们应用程序当前存在的所有问题。

要配置 `ebextensions`，首先需要在存储 `Dockerrun.aws.json` 文件的 `eb` 文件夹中创建一个名为 `.ebextensions` 的文件夹（请注意，您需要断开 SSH 会话，转到您的弹性 Beanstalk EC2 实例，并在本地环境中执行此操作）：

```
todobackend/eb> mkdir .ebextensions todobackend/eb> touch .ebextensions/init.config
```

`.ebextensions` 文件夹中具有 `.config` 扩展名的每个文件都将被视为 ebextension，并在应用程序部署期间由弹性 Beanstalk 处理。在上面的示例中，我们创建了一个名为 `init.config` 的文件，现在我们可以配置它以允许 `ec2-user` 访问 Docker 引擎：

```
commands:
  01_add_ec2_user_to_docker_group:
    command: usermod -aG docker ec2-user
    ignoreErrors: true
```

我们在`commands`键中添加了一个名为`01_add_ec2_user_to_docker_group`的命令指令，这是一个顶级属性，定义了在设置和部署最新版本应用程序到实例之前应该运行的命令。该命令运行`usermod`命令，以确保`ec2-user`是`docker`组的成员，这将授予`ec2-user`访问 Docker 引擎的权限。请注意，您可以使用`ignoreErrors`属性来确保忽略任何命令失败。

有了这个配置，我们可以通过在`eb`文件夹中运行`eb deploy`命令来部署我们应用程序的新版本，这将自动创建我们现有的`Dockerrun.aws.json`和新的`.ebextensions/init.config`文件的 ZIP 存档。

```
todobackend-aws/eb> rm app.zip
todobackend-aws/eb> eb deploy
Uploading todobackend/app-180715_195517.zip to S3\. This may take a while.
Upload Complete.
INFO: Environment update is starting.
INFO: Deploying new version to instance(s).
INFO: Stopping ECS task arn:aws:ecs:us-east-1:385605022855:task/dd2a2379-1b2c-4398-9f44-b7c25d338c67.
INFO: ECS task: arn:aws:ecs:us-east-1:385605022855:task/dd2a2379-1b2c-4398-9f44-b7c25d338c67 is STOPPED.
INFO: Starting new ECS task with awseb-Todobackend-env-amv5i5upx4:3.
INFO: ECS task: arn:aws:ecs:us-east-1:385605022855:task/d9fa5a87-1329-401a-ba26-eb18957f5070 is RUNNING.
INFO: New application version was deployed to running EC2 instances.
INFO: Environment update completed successfully.
```

我们首先删除您第一次创建 Elastic Beanstalk 应用程序时创建的初始`app.zip`存档，因为`eb deploy`命令会自动处理这个问题。您可以看到一旦新配置上传，部署过程涉及停止和启动运行我们应用程序的 ECS 任务。

部署完成后，如果您建立一个新的 SSH 会话到 Elastic Beanstalk EC2 实例，您应该能够运行`docker`命令：

```
[ec2-user@ip-172-31-20-192 ~]$ docker ps --format "{{.ID}}: {{.Image}}"
63183a7d3e67: 385605022855.dkr.ecr.us-east-1.amazonaws.com/docker-in-aws/todobackend
45bf3329a686: amazon/amazon-ecs-agent:latest
```

您可以看到实例当前正在运行 todobackend 容器，并且还运行 ECS 代理。这表明 Elastic Beanstalk 中的 Docker 支持在后台使用 ECS 来管理和部署基于容器的应用程序。

# 解决 Docker 卷权限问题

在本章的前面，我们遇到了一个问题，即 collectstatic 容器无法写入公共卷。问题在于 Elastic Beanstalk EC2 实例上运行的 ECS 代理创建了一个*绑定*挂载，这些挂载始终以 root 权限创建。这会阻止我们的 collectstatic 容器以 app 用户的身份写入公共卷，因此我们需要一些方法来解决这个问题。

正如我们已经看到的，`ebextensions`功能可以在 Elastic Beanstalk EC2 实例上运行命令，我们将再次利用这个功能来确保公共卷被配置为允许我们容器中的`app`用户读写`.ebextensions/init.config`文件：

```
commands:
  01_add_ec2_user_to_docker_group:
    command: usermod -aG docker ec2-user
    ignoreErrors: true
 02_docker_volumes:
 command: |
 mkdir -p /tmp/public
 chown -R 1000:1000 /tmp/public
```

我们添加了一个名为`02_docker_volumes`的新命令指令，它将在`01_add_ec2_user_to_docker_group`命令之后执行。请注意，您可以使用 YAML 管道运算符（`|`）来指定多行命令字符串，从而允许您指定要运行的多个命令。我们首先创建`/tmp/public`文件夹，该文件夹是`Dockerrun.aws.json`文件中公共卷主机`sourcePath`属性所指的位置，然后确保用户 ID/组 ID 值为`1000:1000`拥有此文件夹。因为应用程序用户的用户 ID 为 1000，组 ID 为 1000，这将使任何以该用户身份运行的进程能够写入和读取公共卷。

在这一点上，您可以使用`eb deploy`命令将新的应用程序配置上传到 Elastic Beanstalk（请参阅前面的示例）。部署完成后，您可以通过运行`eb open`命令浏览到应用程序的 URL，并且现在应该看到 todobackend 应用程序的静态内容和格式正确。

# 配置数据库设置

我们已解决了访问公共卷的问题，但是应用程序仍然无法工作，因为我们没有传递任何环境变量来配置数据库设置。造成这种情况的原因是，当您在 Elastic Beanstalk 中配置数据库时，所有数据库设置都可以通过以下环境变量获得：

+   `RDS_HOSTNAME`

+   `RDS_USERNAME`

+   `RDS_PASSWORD`

+   `RDS_DB_NAME`

+   `RDS_PORT`

todobackend 应用程序的问题在于它期望以 MYSQL 为前缀的与数据库相关的设置，例如，`MYSQL_HOST`用于配置数据库主机名。虽然我们可以更新我们的应用程序以使用 RDS 前缀的环境变量，但我们可能希望将我们的应用程序部署到其他云提供商，而 RDS 是 AWS 特定的技术。

另一种选择，尽管更复杂的方法是将环境变量映射写入 Elastic Beanstalk 实例上的文件，将其配置为 todobackend 应用程序容器可以访问的卷，然后修改我们的 Docker 镜像以在容器启动时注入这些映射。这要求我们修改位于`todobackend`存储库根目录中的`entrypoint.sh`文件中的 todobackend 应用程序的入口脚本：

```
#!/bin/bash
set -e -o pipefail

# Inject AWS Secrets Manager Secrets
# Read space delimited list of secret names from SECRETS environment variable
echo "Processing secrets [${SECRETS}]..."
read -r -a secrets <<< "$SECRETS"
for secret in "${secrets[@]}"
do
  vars=$(aws secretsmanager get-secret-value --secret-id $secret \
    --query SecretString --output text \
    | jq -r 'to_entries[] | "export \(.key)='\''\(.value)'\''"')
  eval $vars
done

# Inject runtime environment variables
if [ -f /init/environment ]
then
 echo "Processing environment variables from /init/environment..."
 export $(cat /init/environment | xargs)
fi

# Run application
exec "$@"
```

在上面的例子中，我们添加了一个新的测试表达式，用于检查是否存在一个名为`/init/environment`的文件，使用语法`[ -f /init/environment ]`。如果找到了这个文件，我们假设该文件包含一个或多个环境变量设置，格式为`<环境变量>=<值>` - 例如：

```
MYSQL_HOST=abc.xyz.com
MYSQL_USERNAME=todobackend
...
...
```

有了前面的格式，我们接着使用`export $(cat /init/environment | xargs)`命令，该命令会扩展为`export MYSQL_HOST=abc.xyz.com MYSQL_USERNAME=todobackend ... ...`，使用前面的例子，确保在`/init/environment`文件中定义的每个环境变量都被导出到环境中。

如果您现在提交您对`todobackend`存储库的更改，并运行`make login`，`make test`，`make release`和`make publish`命令，最新的`todobackend` Docker 镜像现在将包括更新后的入口脚本。现在，我们需要修改`todobackend-aws/eb`文件夹中的`Dockerrun.aws.json`文件，以定义一个名为`init`的新卷和挂载：

```
{
  "AWSEBDockerrunVersion": 2,
  "volumes": [
    {
      "name": "public",
      "host": {"sourcePath": "/tmp/public"}
    },
 {
 "name": "init",
 "host": {"sourcePath": "/tmp/init"}
 }
  ],
  "containerDefinitions": [
    {
      "name": "todobackend",
      "image": "385605022855.dkr.ecr.us-east-1.amazonaws.com/docker-in-aws/todobackend",
      "essential": true,
      "memoryReservation": 395,
      "mountPoints": [
        {
          "sourceVolume": "public",
          "containerPath": "/public"
        },
{
 "sourceVolume": "init",
 "containerPath": "/init"
 }
      ],
      "environment": [
```

```
{"name":"DJANGO_SETTINGS_MODULE","value":"todobackend.settings_release"}
      ],
   ...
   ...
```

有了这个卷映射到弹性 Beanstalk EC2 实例上的`/tmp/init`和`todobackend`容器中的`/init`，现在我们所需要做的就是将环境变量设置写入到 EC2 实例上的`/tmp/init/environment`，这将显示为`todobackend`容器中的`/init/environment`，并使用我们对入口脚本所做的修改来触发文件的处理。这里的想法是，我们将弹性 Beanstalk RDS 实例设置写入到 todobackend 应用程序所期望的适当环境变量设置中。

在我们能够做到这一点之前，我们需要一个机制来获取 RDS 设置 - 幸运的是，每个弹性 Beanstalk 实例上都有一个名为`/opt/elasticbeanstalk/deploy/configuration/containerconfiguration`的文件，其中包含整个环境和应用程序配置的 JSON 文件格式。

如果您 SSH 到一个实例，您可以使用`jq`实用程序（它已经预先安装在弹性 Beanstalk 实例上）来提取您的弹性 Beanstalk 应用程序的 RDS 实例设置：

```
> sudo jq '.plugins.rds.env' -r \ 
 /opt/elasticbeanstalk/deploy/configuration/containerconfiguration
{
  "RDS_PORT": "3306",
  "RDS_HOSTNAME": "aa2axvguqnh17c.cz8cu8hmqtu1.us-east-1.rds.amazonaws.com",
  "RDS_USERNAME": "todobackend",
  "RDS_DB_NAME": "ebdb",
  "RDS_PASSWORD": "some-super-secret"
}
```

有了这个提取 RDS 设置的机制，我们现在可以修改`.ebextensions/init.config`文件，将这些设置中的每一个写入到`/tmp/init/environment`文件中，该文件将通过`init`卷暴露给`todobackend`容器，位于`/init/environment`：

```
commands:
  01_add_ec2_user_to_docker_group:
    command: usermod -aG docker ec2-user
    ignoreErrors: true
  02_docker_volumes:
    command: |
      mkdir -p /tmp/public
 mkdir -p /tmp/init
      chown -R 1000:1000 /tmp/public
 chown -R 1000:1000 /tmp/init

container_commands:
 01_rds_settings:
 command: |
 config=/opt/elasticbeanstalk/deploy/configuration/containerconfiguration
 environment=/tmp/init/environment
 echo "MYSQL_HOST=$(jq '.plugins.rds.env.RDS_HOSTNAME' -r $config)" >> $environment
 echo "MYSQL_USER=$(jq '.plugins.rds.env.RDS_USERNAME' -r $config)" >> $environment
 echo "MYSQL_PASSWORD=$(jq '.plugins.rds.env.RDS_PASSWORD' -r $config)" >> $environment
 echo "MYSQL_DATABASE=$(jq '.plugins.rds.env.RDS_DB_NAME' -r $config)" >> $environment
 chown -R 1000:1000 $environment
```

我们首先修改`02_docker_volumes`指令，创建 init 卷映射到的`/tmp/init`路径，并确保在 todobackend 应用程序中运行的 app 用户对此文件夹具有读/写访问权限。接下来，我们添加`container_commands`键，该键指定应在应用程序配置应用后但在应用程序启动之前执行的命令。请注意，这与`commands`键不同，后者在应用程序配置应用之前执行命令。

`container_commands`键的命名有些令人困惑，因为它暗示命令将在 Docker 容器内运行。实际上并非如此，`container_commands`键与 Docker 中的容器完全无关。

`01_rds_settings`命令编写了应用程序所需的各种 MYSQL 前缀环境变量设置，通过执行`jq`命令获取每个变量的适当值，就像我们之前演示的那样。因为这个文件是由 root 用户创建的，所以我们最终确保`app`用户对`/tmp/init/environment`文件具有读/写访问权限，该文件将通过 init 卷作为`/init/environment`存在于容器中。

如果您现在使用`eb deploy`命令部署更改，一旦部署完成并导航到 todobackend 应用程序 URL，如果尝试列出 Todos 项目（通过访问`/todos`），请注意现在显示了一个新错误：

访问 todobackend Todos 项目错误

回想一下，当您之前访问相同的 URL 时，todobackend 应用程序尝试使用 localhost 访问 MySQL，但现在我们收到一个错误，指示在`ebdb`数据库中找不到`todo_todoitem`表。这证实了应用程序现在正在与 RDS 实例通信，但由于我们尚未运行数据库迁移，因此不支持应用程序的架构和表。

# 运行数据库迁移

要解决我们应用程序的当前问题，我们需要一个机制，允许我们运行数据库迁移以创建所需的数据库架构和表。这也必须发生在每次应用程序更新时，但这应该只发生一次*每次*应用程序更新。例如，如果您有多个 Elastic Beanstalk 实例，您不希望在每个实例上运行迁移。相反，您希望迁移仅在每次部署时运行一次。

在上一节中介绍的`container_commands`键中包含一个有用的属性叫做`leader_only`，它配置 Elastic Beanstalk 只在领导者实例上运行指定的命令。这是第一个可用于部署的实例。因此，我们可以在`todobackend-aws/eb`文件夹中的`.ebextensions/init.config`文件中添加一个新的指令，每次应用程序部署时只运行一次迁移：

```
commands:
  01_add_ec2_user_to_docker_group:
    command: usermod -aG docker ec2-user
    ignoreErrors: true
  02_docker_volumes:
    command: |
      mkdir -p /tmp/public
      mkdir -p /tmp/init
      chown -R 1000:1000 /tmp/public
      chown -R 1000:1000 /tmp/init

container_commands:
  01_rds_settings:
    command: |
      config=/opt/elasticbeanstalk/deploy/configuration/containerconfiguration
      environment=/tmp/init/environment
      echo "MYSQL_HOST=$(jq '.plugins.rds.env.RDS_HOSTNAME' -r $config)" >> $environment
      echo "MYSQL_USER=$(jq '.plugins.rds.env.RDS_USERNAME' -r $config)" >> $environment
      echo "MYSQL_PASSWORD=$(jq '.plugins.rds.env.RDS_PASSWORD' -r $config)" >> $environment
      echo "MYSQL_DATABASE=$(jq '.plugins.rds.env.RDS_DB_NAME' -r $config)" >> $environment
      chown -R 1000:1000 $environment
  02_migrate:
 command: |
 echo "python3 manage.py migrate --no-input" >> /tmp/init/commands
 chown -R 1000:1000 /tmp/init/commands
 leader_only: true
```

在这里，我们将`python3 manage.py migrate --no-input`命令写入`/tmp/init/commands`文件，该文件将暴露给应用程序容器，位置在`/init/commands`。当然，这要求我们现在修改`todobackend`存储库中的入口脚本，以查找这样一个文件并执行其中包含的命令，如下所示：

```
#!/bin/bash
set -e -o pipefail

# Inject AWS Secrets Manager Secrets
# Read space delimited list of secret names from SECRETS environment variable
echo "Processing secrets [${SECRETS}]..."
read -r -a secrets <<< "$SECRETS"
for secret in "${secrets[@]}"
do
  vars=$(aws secretsmanager get-secret-value --secret-id $secret \
    --query SecretString --output text \
    | jq -r 'to_entries[] | "export \(.key)='\''\(.value)'\''"')
  eval $vars
done

# Inject runtime environment variables
if [ -f /init/environment ]
then
  echo "Processing environment variables from /init/environment..."
  export $(cat /init/environment | xargs)
fi # Inject runtime init commands
if [ -f /init/commands ]
then
  echo "Processing commands from /init/commands..."
  source /init/commands
fi

# Run application
exec "$@"
```

在这里，我们添加了一个新的测试表达式，检查`/init/commands`文件是否存在，如果存在，我们使用`source`命令来执行文件中包含的每个命令。因为这个文件只会在领导者弹性 Beanstalk 实例上写入，入口脚本将在每次部署时只调用这些命令一次。

在这一点上，您需要通过运行`make login`，`make test`，`make release`和`make publish`命令来重新构建 todobackend Docker 镜像，之后您可以通过从`todobackend-aws/eb`目录运行`eb deploy`命令来部署 Elastic Beanstalk 更改。一旦这个成功完成，如果您 SSH 到您的 Elastic Beanstalk 实例并审查当前活动的 todobackend 应用程序容器的日志，您应该会看到数据库迁移是在容器启动时执行的：

```
> docker ps --format "{{.ID}}: {{.Image}}"
45b8cdac0c92: 385605022855.dkr.ecr.us-east-1.amazonaws.com/docker-in-aws/todobackend
45bf3329a686: amazon/amazon-ecs-agent:latest
> docker logs 45b8cdac0c92
Processing secrets []...
Processing environment variables from /init/environment...
Processing commands from /init/commands...
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
[uwsgi-static] added check for /public
* Starting uWSGI 2.0.17 (64bit) on [Sun Jul 15 11:18:06 2018] *
```

如果您现在浏览应用程序 URL，您应该会发现应用程序是完全可用的，并且您已成功将 Docker 应用程序部署到 Elastic Beanstalk。

在结束本章之前，您应该通过将您的用户帐户重新添加到`Users`组来恢复您在本章前面暂时禁用的 MFA 配置：

```
> aws iam add-user-to-group --user-name justin.menga --group-name Users
```

然后在本地的`~/.aws/config`文件中重新启用`docker-in-aws`配置文件中的`mfa_serial`行：

```
[profile docker-in-aws]
source_profile = docker-in-aws
role_arn = arn:aws:iam::385605022855:role/admin
role_session_name=justin.menga
region = us-east-1
mfa_serial = arn:aws:iam::385605022855:mfa/justin.menga 
```

您还可以通过浏览主 Elastic Beanstalk 仪表板并单击**操作|删除**按钮旁边的**todobackend**应用程序来删除 Elastic Beanstalk 环境。这将删除 Elastic Beanstalk 环境创建的 CloudFormation 堆栈，其中包括应用程序负载均衡器、RDS 数据库实例和 EC2 实例。

# 总结

在本章中，您学会了如何使用 Elastic Beanstalk 部署多容器 Docker 应用程序。您了解了为什么以及何时会选择 Elastic Beanstalk 而不是其他替代容器管理服务，如 ECS，总的结论是 Elastic Beanstalk 非常适合规模较小的组织和少量应用程序，但随着组织的增长，需要开始专注于提供共享容器平台以降低成本、复杂性和管理开销时，它变得不那么有用。

您使用 AWS 控制台创建了一个 Elastic Beanstalk 应用程序，这需要您定义一个名为`Dockerrun.aws.json`的单个文件，其中包括运行应用程序所需的容器定义和卷，然后自动部署应用程序负载均衡器和最小配置的 RDS 数据库实例。将应用程序快速运行到完全功能状态是有些具有挑战性的，需要您定义名为`ebextensions`的高级配置文件，这些文件允许您调整 Elastic Beanstalk 以满足应用程序的特定需求。您学会了如何安装和设置 Elastic Beanstalk CLI，使用 SSH 连接到 Elastic Beanstalk 实例，并部署对`Dockerrun.aws.json`文件和`ebextensions`文件的配置更改。这使您能够为以非根用户身份运行的容器应用程序在 Elastic Beanstalk 实例上设置正确权限的卷，并引入了一个特殊的 init 卷，您可以在其中注入环境变量设置和应作为容器启动时执行的命令。

在下一章中，我们将看一下 Docker Swarm 以及如何在 AWS 上部署和运行 Docker Swarm 集群来部署和运行 Docker 应用程序。

# 问题

1.  真/假：Elastic Beanstalk 只支持单容器 Docker 应用程序。

1.  使用 Elastic Beanstalk 创建 Docker 应用程序所需的最低要求是什么？

1.  真/假：`.ebextensions` 文件夹存储允许您自定义 Elastic Beanstalk 实例的 YAML 文件。

1.  您创建了一个部署存储在 ECR 中的 Docker 应用程序的新 Elastic Beanstalk 服务。在初始创建时，应用程序失败，Elastic Beanstalk 日志显示错误，包括“CannotPullECRContainerError”一词。您将如何解决此问题？

1.  真/假：在不进行任何额外配置的情况下，以非根用户身份运行的 Docker 容器在 Elastic Beanstalk 环境中可以读取和写入 Docker 卷。

1.  真/假：您可以将 `leader_only` 属性设置为 true，在 `commands` 键中仅在一个 Elastic Beanstalk 实例上运行命令。

1.  真/假：`eb connect` 命令用于建立对 Elastic Beanstalk 实例的 SSH 访问。

1.  真/假：Elastic Beanstalk 支持将应用程序负载均衡器集成到您的应用程序中。

# 进一步阅读

您可以查看以下链接，了解本章涵盖的主题的更多信息：

+   弹性 Beanstalk 开发人员指南：[`docs.aws.amazon.com/elasticbeanstalk/latest/dg/Welcome.html`](https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/Welcome.html)

+   多容器 Docker 环境：[`docs.aws.amazon.com/elasticbeanstalk/latest/dg/create_deploy_docker_ecs.html`](https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/create_deploy_docker_ecs.html)

+   将 Elastic Beanstalk 与其他 AWS 服务一起使用：[`docs.aws.amazon.com/elasticbeanstalk/latest/dg/AWSHowTo.html`](https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/AWSHowTo.html)

+   使用配置文件进行高级环境配置：[`docs.aws.amazon.com/elasticbeanstalk/latest/dg/ebextensions.html`](https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/ebextensions.html)

+   Elastic Beanstalk 命令行界面：[`docs.aws.amazon.com/elasticbeanstalk/latest/dg/eb-cli3.html`](https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/eb-cli3.html)
