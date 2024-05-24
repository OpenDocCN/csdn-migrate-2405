# Docker Python 微服务实用手册（二）

> 原文：[`zh.annas-archive.org/md5/50389059E7B6623191724DBC60F2DDF3`](https://zh.annas-archive.org/md5/50389059E7B6623191724DBC60F2DDF3)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：创建流水线和工作流程

自动运行的流水线工作流程，通过不同阶段，将及早发现问题，并帮助您的团队以最有效的方式进行协作。

在本章中，我们将遵循持续集成实践，自动运行流水线并在每次更改时确保我们所有的代码都符合高质量标准，并且运行并通过所有测试。我们还将准备一个容器以便投入生产。

我们将看到如何利用 GitHub 和 Travis CI 等工具来创建最小干预的镜像。

在本章中，我们将涵盖以下主题：

+   理解持续集成实践

+   配置 Travis CI

+   配置 GitHub

+   从 Travis CI 推送 Docker 镜像

在本章结束时，您将了解如何在每次代码更改时自动运行测试，以及如何创建一个安全网，使您能够更快，更高效地开发。

# 技术要求

您需要一个 GitHub 帐户，并且需要是您为持续集成设置的项目的所有者。我们将在本章中创建一个 Travis CI 帐户。

您可以在 GitHub 的`Chapter04`子目录中查看本章中提到的完整代码（[`github.com/PacktPublishing/Hands-On-Docker-for-Microservices-with-Python/tree/master/Chapter04`](https://github.com/PacktPublishing/Hands-On-Docker-for-Microservices-with-Python/tree/master/Chapter04)）。以`.travis.yml`结尾的文件位于根目录中（[`github.com/PacktPublishing/Hands-On-Docker-for-Microservices-with-Python/blob/master/.travis.yml`](https://github.com/PacktPublishing/Hands-On-Docker-for-Microservices-with-Python/blob/master/.travis.yml)）。

# 理解持续集成实践

**持续集成**（通常缩写为**CI**）是一系列软件工程实践，确保代码始终处于工作状态。

持续集成这个术语的由来是历史上经常需要频繁集成软件，通常一天多次。这是因为开发人员使用的是本地代码，不一定会自动与其他人的代码结合。如今，使用 Git 等源代码控制版本软件使一些元素自动可用。

持续集成强调始终具有潜在可发布的代码。这使得以非常小的代码增量非常频繁地进行发布成为可能。

更频繁地发布更多的版本实际上会增加每个版本的质量。更多的部署也意味着每个部署都更小，减少了出现大问题的可能性。即使听起来违反直觉，更快的部署与部署质量更高以及更少的生产问题之间存在高度相关性。

这里的目标是能够提高部署速度。但为此，我们需要确保建立一个良好的安全网，自动检查我们正在做的是否安全发布。这就是所有 CI 实践发挥作用的地方。

在设置所有流程和基础设施之后，完全有可能一天多次实施发布（假设代码生成速度足够快）。可能需要一段时间才能达到这一点，但一定要花时间了解流程，并生成所有必要的工具，以确保您在不牺牲稳定性的情况下获得速度。相信我，这是完全可以实现的！

# 生成自动化构建

CI 的核心要素是生成与源代码控制系统集成的自动化构建。软件构建是一个过程（从源代码开始），执行一系列操作并产生输出。如果项目是用编译语言编写的，输出通常将是编译后的程序。

如果我们想要高质量的软件，那么构建的一部分就是检查生成的代码是否符合代码标准。如果代码不符合这些标准，那么构建将返回一个错误。

描述构建错误的一种常见方式是说*构建已损坏*。构建可以以不同的方式中断，某些类型的错误可能会在早期停止它（例如在运行测试之前的编译错误），或者我们可以继续检测更多问题（例如运行所有测试以返回所有可能的错误）。

构建中可能包括的一些步骤示例如下：

+   编译代码。

Python 通常不需要编译，但如果使用 C 扩展（用 C 编写并从 Python 导入的模块：[`docs.python.org/3/extending/`](https://docs.python.org/3/extending/)）或诸如 Cython ([`cython.org/`](https://cython.org/)) 这样的工具可能需要编译。

+   运行单元测试

+   运行静态代码分析工具

+   构建一个或多个容器

+   使用诸如 Safety ([`pyup.io/safety/`](https://pyup.io/safety/))这样的工具检查已知漏洞的依赖项。

+   生成用于分发的二进制或源代码包。例如，RPM ([`rpm.org/`](https://rpm.org/))，Debian 软件包 ([`www.debian.org/doc/manuals/debian-faq/ch-pkg_basics`](https://www.debian.org/doc/manuals/debian-faq/ch-pkg_basics))，等等

+   运行其他类型的测试

+   从代码生成报告、图表或其他资产

任何可以自动运行的东西都可以成为构建的一部分。可以随时生成本地构建，即使代码仍在进行中。这对于调试和解决问题非常重要。但自动构建将针对每个单独的提交运行，并不会在任何中间阶段运行。这使得明确检查预期在生产中运行的代码以及仍在进行中的代码非常重要。

请注意，单个提交可能仍然是正在进行的工作，但无论如何都值得提交。也许这是朝着一个功能迈出的一小步，有多人在同一部分代码上工作，或者工作分布在几天之间，代码在一天结束时被推送。无论如何，每个提交都是一个可重现的步骤，可以构建并检查构建是否成功。

对每个提交运行构建可以非常快速地检测问题。如果提交很小，那么很容易找出破坏性的更改。它还可以轻松地撤销破坏构建的更改并返回到已知的工作代码。

# 了解使用 Docker 进行构建的优势

构建的一个主要传统问题是拥有一个适当的构建环境，其中包含运行完整构建所需的所有依赖项。这可能包括编译器、运行测试的测试框架、任何静态分析工具和软件包管理器。版本不一致也可能导致错误。

正如我们之前所看到的，Docker 是封装软件的绝佳方式。它允许我们创建一个包含我们的代码和所有能够执行所有步骤的工具的镜像。

在上一章中，我们看到了如何在一个构建镜像上运行单元测试的单个命令。镜像本身可以运行自己的单元测试。这样可以抽象测试环境并明确定义它。这里唯一必要的依赖是安装了 Docker。

请记住，单个构建可能会生成多个镜像并使它们协调工作。我们在上一章中看到了如何运行单元测试——通过生成服务镜像和数据库镜像——但还有更多可能的用途。例如，您可以在两个不同的操作系统上运行测试，从每个操作系统创建两个镜像或不同的 Python 解释器版本，并检查测试是否在所有这些版本中都通过。

使用 Docker 镜像可以在所有环境中实现标准化。我们可以在开发环境中本地运行镜像，使用与自动化环境中相同的命令。这样可以简化查找错误和问题，因为它在每次运行构建的地方都创建了相同的环境，包括封装的操作系统。

不要低估这一点。在此之前，一个在运行 Ubuntu 的笔记本电脑上工作的开发人员，想要运行在 CentOS 中部署的代码，需要安装一个虚拟机并按照步骤来创建一个与生产环境类似的环境。但是，本地虚拟机往往会偏离，因为很难保持每个开发人员的本地虚拟机与生产环境中的虚拟机同步；此外，任何自动构建工具也可能有要求，比如不支持在生产中运行的旧版本 CentOS。

更糟糕的是，有时不同的项目安装在同一个虚拟机上，以避免每个项目都有一个虚拟机，这可能会导致兼容性问题。

Docker 大大简化了这个问题，部分原因是它迫使你明确声明依赖关系，并减少了实际运行我们的代码所需的表面。

请注意，我们不一定需要创建一个运行整个构建的单个步骤；它可以是几个 Docker 命令，甚至可以使用不同的镜像。但要求是它们都包含在 Docker 中，这是运行它所需的唯一软件。

使用 Docker 构建的主要产品是 Docker 镜像。我们需要正确地给它们打标签，但只有在构建成功的情况下才需要。

# 利用流水线的概念

CI 工具有助于澄清构建应该如何进行，并围绕流水线的概念进行工作。流水线是一系列阶段。如果其中任何一个不成功，流水线就会停止。

流水线中的每个阶段都可以产生可以在后续阶段使用的元素，或者作为完整构建的最终产品可用。这些最终元素被称为构件。

让我们看一个流水线的例子：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-dkr-msvc-py/img/11e95cdf-0c76-4701-9c4a-69964b4b49dd.png)

第一个阶段从源代码控制系统中拉取最新的提交。然后，我们构建所有的容器并运行测试和静态分析。如果一切顺利，我们就会给生成的`server`容器打标签，并将其推送到注册表中。

这些阶段运行的顺序应该是为了尽快检测问题，以便快速反馈。例如，如果`static-analysis`阶段比`test`阶段快得多，将分析阶段放在第一位将使失败的构建更快完成。要注意哪些部分可以更早执行以减少反馈时间。

CI 工具通常允许在流水线中进行大量配置，包括并行运行不同阶段的可能性。为了能够并行运行阶段，它们需要能够并行化，这意味着它们不应该改变相同的元素。

如果所选的 CI 工具允许并行运行阶段，可以将流水线定义如下：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-dkr-msvc-py/img/c7754936-9bc7-4507-a412-2ad09198cb3c.png)

请注意，我们同时构建数据库和测试图像。下一个阶段构建其余的元素，这些元素已经在缓存中可用，因此速度会非常快。测试和静态分析都可以在两个不同的容器中并行运行。

这可能加快复杂的构建速度。

一定要验证所花费的时间是否减少。有些情况下，所花费的时间会非常相似。例如，静态分析可能非常快，或者你运行它的硬件可能不够强大，无法并行构建，使得并行构建和顺序构建所花费的时间非常相似。因此，一定要验证你的假设。

流水线是特定于 Travis CI 工具的脚本描述的。我们稍后会看一个 Travis CI 的例子。

# 分支、合并和确保清晰的主要构建

何时运行构建？每次推送提交时。但每个结果并不相同。在处理 Git 等源代码控制系统时，我们通常有两种类型的分支：

+   一个主分支

+   功能分支

它们实现了特定的功能或错误修复，当准备好时将合并到主分支中，如下图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-dkr-msvc-py/img/a6510d21-1c6b-4fa8-9d99-fc0e7b0b6a57.png)

在这个例子中，我们看到主分支（**master**）分支到开发**feature** **A**。**Feature** **A**随后被简要介绍。还有一个**feature B**，因为它还没有准备好，所以尚未合并。有了额外的信息，我们可以知道何时安全地将一个功能分支合并到主分支中：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-dkr-msvc-py/img/f477c83f-b377-42f2-b128-2d526c862899.png)

尚未合并的功能分支出现故障并不是很好，但在进行中的工作中，这是可以预料的。与此同时，主分支的破坏是一个应该尽快修复的事件。如果主分支状态良好，那意味着它有可能发布。

GitHub 有一个模型：拉取请求。我们将配置拉取请求自动检查构建是否通过并避免合并。如果我们强制任何功能分支在合并回来之前也与主分支保持最新，那么主分支最终会非常稳定。

对于在 Git 中处理分支以定义发布，最流行的模型是 Git-flow，在这篇有影响力的博文中定义（[`nvie.com/posts/a-successful-git-branching-model/`](https://nvie.com/posts/a-successful-git-branching-model/)）。以下的 CI 实践可以简化一些事情，不涉及诸如发布分支之类的元素。这篇博文是强烈推荐阅读的。

在主分支上有一系列连续成功的构建也对项目的稳定性和质量有很大帮助。如果主分支的破坏非常罕见，那么使用最新的主分支创建新版本的信心就会非常高。

# 配置 Travis CI

Travis CI ([`travis-ci.com/`](https://travis-ci.com/)) 是一个流行的持续集成服务，可免费用于公共 GitHub 项目。与 GitHub 的集成非常简单，它允许您配置它运行的平台，如 macOS、Linux，甚至 iOS。

Travis CI 与 GitHub 紧密集成，因此您只需要登录 GitHub 即可访问它。我们将看看如何将我们的项目连接到它。

为了清晰起见，本章中的代码将只与 Travis 连接起来。

Travis 的工作方式与其他 CI 工具有些不同，它通过启动一个新的虚拟机创建独立的任务。这意味着任何为上一个阶段创建的构件都需要复制到其他地方，以便在下一个阶段开始时下载。

有时这会让事情变得有点不切实际，一个简单的解决方案是为每个单独的任务构建多次。

配置远程系统，如 Travis CI，有时可能会有点令人沮丧，因为它要求您推送一个提交以进行构建，以查看配置是否正确。此外，它使用一个 YAML 文件进行配置，在语法方面可能有点暴躁。您可能需要尝试几次才能得到稳定的东西，但不要担心。一旦设置好，您只能通过特定的拉取请求来更改它，因为配置文件也受源代码控制。

您还可以检查 Travis CI 配置中的请求，看看`.yml`文件是否创建了解析错误。

您可以在这里查看完整的 Travis CI 文档：[`docs.travis-ci.com/`](https://docs.travis-ci.com/)。

要配置 Travis CI，让我们首先从 GitHub 添加一个存储库。

# 将存储库添加到 Travis CI

要将存储库添加到 Travis CI，我们需要采取以下步骤：

1.  第一阶段是转到 Travis CI 网页并使用您的 GitHub 凭据登录。

1.  然后，您需要授权 Travis 访问 GitHub，通过激活它。

1.  然后，选择要构建的存储库。

最简单的起点是在[`github.com/PacktPublishing/Hands-On-Docker-for-Microservices-with-Python`](https://github.com/PacktPublishing/Hands-On-Docker-for-Microservices-with-Python)中 fork 此书中的示例的存储库。随意操作！

但请记住更改用户名、凭据和注册信息以匹配您自己的信息。

您需要对 GitHub 存储库拥有者权限，然后您就可以开始了！

# 创建.travis.yml 文件

Travis CI 中的主要元素是创建`.travis.yml`文件。

请确保将其命名为这样（包括初始点和`.yml`扩展名），并将其包含在 GitHub 存储库的根目录中。如果不这样做，Travis CI 构建将不会启动。请注意，在示例存储库中，该文件位于**根目录**中，而**不是**在`Chapter04`子目录下。

`.travis.yml`描述了构建及其不同的步骤。构建在一个或多个虚拟机中执行。可以通过指定一般操作系统和具体版本来配置这些虚拟机。默认情况下，它们在 Ubuntu Linux 14.04 Trusty 中运行。您可以在此处找到有关可用操作系统的更多信息：[`docs.travis-ci.com/user/reference/overview/`](https://docs.travis-ci.com/user/reference/overview/)。

使用 Docker 允许我们抽象出大部分操作系统的差异，但我们需要确保我们使用的特定`docker`和`docker-compose`版本是正确的。

我们将开始`.travis.yml`，确保存在有效的`docker-compose`版本（1.23.2），使用以下代码：

```py
services:
  - docker

env:
  - DOCKER_COMPOSE_VERSION=1.23.2

before_install:
  - sudo rm /usr/local/bin/docker-compose
  - curl -L https://github.com/docker/compose/releases/download/${DOCKER_COMPOSE_VERSION}/docker-compose-`uname -s`-`uname -m` > docker-compose
  - chmod +x docker-compose
  - sudo mv docker-compose /usr/local/bin
  - docker --version
  - docker-compose version
```

`before_install`块将在所有虚拟机中执行。现在，为了运行测试，我们添加一个`script`块：

```py
script:
- cd ch4
- docker-compose build db
- docker-compose build static-analysis
- docker-compose build test-postgresql
- docker-compose run test-postgresql
- docker-compose run static-analysis
```

我们构建所有要使用的镜像，然后运行测试。请注意，使用 PostgreSQL 数据库运行测试需要构建`db`容器。

关于`db`容器有一个小细节：Travis 虚拟机不允许我们打开端口`5432`。因此我们在`docker-compose`中删除了`ports`。请注意，这仅仅是为了调试目的而使得 PostgreSQL 在外部可用；在内部，容器可以通过其内部网络相互通信。

我们创建了一个名为`db-debug`的服务，它是`db`的副本，但它公开了本地开发的端口。您可以在`docker-compose.yaml`文件中查看它，网址为[`github.com/PacktPublishing/Hands-On-Docker-for-Microservices-with-Python/blob/master/Chapter04/docker-compose.yaml`](https://github.com/PacktPublishing/Hands-On-Docker-for-Microservices-with-Python/blob/master/Chapter04/docker-compose.yaml)。

这将运行所有测试。将代码推送到存储库后，我们可以看到构建在 Travis CI 中开始：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-dkr-msvc-py/img/cbc98740-909b-426f-a13c-87ee5e1bb86a.png)

一旦完成，我们可以通过标记为绿色来确认构建成功。然后可以检查日志以获取更多信息：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-dkr-msvc-py/img/7eb1ed98-42f7-4c6c-bc9c-a9490165daf5.png)

现在您可以在日志的末尾看到测试：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-dkr-msvc-py/img/299c2d36-633a-4dc6-acce-bd4a49d3c8fb.png)

这对于检测问题和构建中断非常有用。现在，让我们看看 Travis 中作业的工作方式。

# 使用 Travis 作业

Travis 将整个构建划分为一系列将依次运行的阶段。在每个阶段，可以有多个作业。同一构建中的所有作业将并行运行。

正如我们之前所见，可以通过用`jobs`部分替换`script`部分来配置测试和静态分析并行运行：

```py
jobs:
  include:
    - stage: tests
      name: "Unit Tests"
      script:
      - cd ch4
      - docker-compose build db
      - docker-compose build test-postgresql
      - docker-compose run test-postgresql
    - stage: tests
      name: "Static Analysis"
      script:
      - cd ch4
      - docker-compose build static-analysis
      - docker-compose run static-analysis
```

这在一个阶段隐式地创建了两个作业。该阶段命名为`tests`，作业分别称为“单元测试”和“静态分析”。

结果显示在 Travis 页面上：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-dkr-msvc-py/img/4644a76d-718c-4224-ae01-55a00fcfed62.png)

请注意，在这两种情况下，由于作业是独立的，它们需要构建所需的映像。由于单元测试作业需要构建`db`映像，这需要几分钟的时间，所以比静态分析慢。

您可以检查每个作业的详细日志。请注意，环境设置和`before_install`操作在所有作业中都会执行。

这个分工不仅可以极大地加快构建速度，还可以澄清问题所在。一眼就可以看出破坏因素是单元测试还是静态分析。这样可以减少混乱。

# 发送通知

默认情况下，Travis CI 会发送电子邮件通知构建的结果，但只有在构建失败或修复了破损的构建时才会发送。这样可以避免不断发送“成功”电子邮件，并且只在需要采取行动时才会发送。默认情况下，电子邮件只发送给提交者（如果不同，则发送给提交作者）。

请注意，“失败”构建和“错误”构建之间存在差异。后者是作业设置中的失败，这意味着`before_install`、`install`或`before_script`部分存在问题，而失败的构建是因为脚本部分返回了非零结果。在更改 Travis 配置时，*错误*构建很常见。

Travis 允许我们配置通知电子邮件并连接更多通知系统，包括 Slack、IRC，甚至 OpsGenie，它可以根据值班计划发送短信。在此处查看更多信息的完整文档：[`docs.travis-ci.com/user/notifications/`](https://docs.travis-ci.com/user/notifications/)。

# 配置 GitHub

为了充分利用我们配置的 CI 系统，我们需要确保在将其合并到主分支之前检查构建。为此，我们可以在 GitHub 中将`master`配置为主分支，并在合并到它之前添加要求：

确保`.travis.yaml`文件包含适当的凭据，如果您 fork 了存储库。您需要使用自己的更新它们。

1.  转到我们的 GitHub 存储库中的设置和分支，然后单击添加规则。

1.  然后，我们启用了要求状态检查通过才能合并选项，并使用来自`travis-ci`的状态检查：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-dkr-msvc-py/img/2516fab5-583a-48a2-be37-387f168305a1.png)

1.  我们还选择了在合并之前要求分支是最新的选项。这确保了没有合并到`master`的分支在之前没有运行过。

看看 GitHub 提供的其他可能性。特别是，强制执行代码审查是明智的，可以在合并之前对代码进行审查并传播知识。

1.  创建新分支和新的拉取请求，旨在失败静态测试，我们可以看到测试是如何添加到 GitHub 的：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-dkr-msvc-py/img/e488d600-6062-4a6b-8d20-7c7e5a45be61.png)

详细链接将带您到 Travis CI 和特定的构建。您还可以查看构建的历史记录：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-dkr-msvc-py/img/1d635138-eae4-4a5d-9387-7c4c490e4a8d.png)

当构建完成时，GitHub 不会让您合并拉取请求：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-dkr-msvc-py/img/fec96e7a-1b64-408a-8df3-aea645993129.png)

有关 Travis CI 中构建页面的详细信息可以在此处找到：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-dkr-msvc-py/img/4f036c07-0a5a-4372-87a7-8c15e38b626f.png)

修复问题并推送代码将触发另一个构建。这一次，它将成功，并且拉取请求将成功合并。您可以看到每个提交都有自己的构建信息，无论是正确还是错误：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-dkr-msvc-py/img/6325f284-fdb6-4df2-b7c4-d0dda7ffe9c5.png)

现在我们可以放心地合并到主分支，确保`master`分支在运行测试时不会中断。

请注意，拉取请求中有两个构建：一个用于分支，另一个用于拉取请求。默认情况下，Travis CI 有这种配置。如果您强制它在合并之前始终创建拉取请求，那么请求将是多余的，尽管在某些情况下，当分支在创建拉取请求之前被推送时，它可能有所帮助。您可以在 Travis 项目配置中启用或禁用它。

可以配置的另一个有趣的特性是，如果推送了更新的提交，可以自动取消构建。这有助于减少系统中的总构建数量。

在 GitHub 的 Commits 视图中也可以检查构建结果。

# 从 Travis CI 推送 Docker 图像

在我们的构建创建了一个 Docker 镜像之后，我们需要能够与团队的其他成员共享或部署它。我们将使用 Docker Hub 中的 Docker 注册表，如前一章所述，来推送镜像。

让我们从设置安全变量开始。

# 设置安全变量

为了能够推送到 Docker 存储库，我们首先需要在 Travis CI 的秘密配置中配置密码，以避免在 GitHub 存储库中提交敏感信息：

值得重申：**不要在 GitHub 存储库中提交机密信息**。这些技术可以用于任何其他所需的机密。

1.  使用`gem`安装`travis`命令行。这假设你的系统上已经安装了`gem`（Ruby 1.93 或更高版本）。如果没有，请查看安装说明（[`github.com/travis-ci/travis.rb#installation`](https://github.com/travis-ci/travis.rb#installation)）：

```py
$ gem install travis
```

1.  登录到 Travis：

```py
travis login --pro
```

1.  使用 Docker Hub 用户名创建一个安全变量：

```py
$ travis encrypt --com DOCKER_USERNAME="<your user name>"
```

1.  你会看到类似以下的输出：

```py
secure: ".... encrypted data ...."
```

1.  然后，您需要将加密数据添加到环境变量中，如下所示：

```py
env:
  global:
    - DOCKER_COMPOSE_VERSION=1.23.2
    - secure: ".... encrypted data ...."
```

1.  现在，请注意新的`global`部分，并重复第 3 步，使用 Docker Hub 密码：

```py
$ travis encrypt --com DOCKER_PASSWORD="<password>"
```

1.  在第一个之后添加另一个安全变量：

```py
env:
  global:
    - DOCKER_COMPOSE_VERSION=1.23.2
    - secure: ".... encrypted data ...."
    - secure: ".... encrypted data ...."
```

此操作创建了两个环境变量，在构建期间可用。不用担心——它们不会显示在日志中：

```py
Setting environment variables from .travis.yml
$ export DOCKER_COMPOSE_VERSION=1.23.2
$ export DOCKER_PASSWORD=[secure]
$ export DOCKER_USERNAME=[secure]
```

现在，我们可以在`before_install`部分添加适当的登录命令，以便 Docker 服务可以连接并推送图像：

```py
before_install:
  ...
  - echo "Login into Docker Hub"
  - echo "$DOCKER_PASSWORD" | docker login -u "$DOCKER_USERNAME" --password-stdin
```

下一阶段是构建和标记结果图像。

# 标记和推送构建

以下代码将添加一个新的阶段，用于构建、标记和最终将结果推送到 Docker 注册表：

```py
jobs:
  include:
    ...
    - stage: push
      script:
      - cd Chapter04
      - docker-compose build server
      - docker tag thoughts_server:latest <registry>/thoughts-backend:$TRAVIS_BRANCH
```

这第一部分构建了服务器的最终镜像，并使用分支的名称进行标记。为了部署它，我们将添加一个`deploy`部分：

```py
- stage: push
  script:
  ...
  - docker tag thoughts_server:latest <registry>/thoughts-backend:$TRAVIS_BRANCH
  deploy:
  - provider: script
    script: docker push <registry>/thoughts-backend:$TRAVIS_BRANCH
    on:
      branch: master 
```

当分支是`master`时，`deploy`部分将执行一个`script`命令。现在，我们的构建还将生成一个最终镜像并推送它。这将确保我们的注册表中有主分支的最新版本。

我们可以添加更多的`deploy`条件来推送标签；例如，如果我们创建了一个新的 Git 标签，我们可以推送带有适当标签的结果图像。

请记住，如前一章所述，标签是标记图像为重要的一种方式。通常，这意味着它已准备好在自动测试之外的某些地方使用，例如在部署中。

我们可以在`deploy`部分添加标签：

```py
      deploy:
      - provider: script
        script: docker push <registry>/thoughts-backend:$TRAVIS_BRANCH
        on:
          branch: master 
      - provider: script
        script: docker push <registry>/thoughts-backend:$TRAVIS_TAG
        on:
          tags: True
```

请注意，这里我们推送的是主分支或有定义标签的情况，因为这两种情况都不会匹配。

您可以在此处查看完整的部署文档：[`docs.travis-ci.com/user/deployment`](https://docs.travis-ci.com/user/deployment)。我们已经介绍了`script`提供程序，这是一种创建自己的命令的方式，但也支持提供程序，如 Heroku、PyPI（用于创建 Python 包的情况）和 AWS S3。

# 对每次提交进行标记和推送

可以将每个构建的图像推送到注册表，由其 Git SHA 标识。当工作正在进行中可以共享用于演示目的、测试等时，这可能很有用。

为此，我们需要在`before_install`部分创建一个包含 Git SHA 的环境变量：

```py
before_install:
  ...
  - export GIT_SHA=`git rev-parse --short HEAD`
  - echo "Building commit $GIT_SHA"
```

然后，`push`部分添加了图像的标记和推送：

```py
- stage: push
  script:
  - cd Chapter04
  - docker-compose build server
  - docker tag thoughts_server:latest <registry>/thoughts-backend:$GIT_SHA
  - docker push <registry>/thoughts-backend:$GIT_SHA
  - docker tag thoughts_server:latest <registry>/thoughts-backend:$TRAVIS_BRANCH
```

由于此操作发生在`deploy`部分之前，因此它将在达到此部分的每次构建中产生。

这种方法将产生大量的标签。根据您的注册表如何管理它们，这可能是昂贵的。请确保这是一个明智的做法。

请记住，这种方法也可以用于其他条件推送。

请注意，注册表需要根据您自己的注册表详细信息进行调整。如果您克隆示例存储库，则后者需要更改。

# 总结

在本章中，我们介绍了持续集成的实践，并探讨了 Docker 如何帮助实现这些实践。我们还研究了如何设计一个管道，确保我们的代码始终符合高标准，并尽快检测到偏差。在 GitHub 中使用 Git 分支和拉取请求与此相一致，因为我们可以确定代码何时准备合并到主分支并部署。

然后，我们介绍了 Travis CI 作为一个与 GitHub 一起使用的优秀工具，以实现持续集成，并讨论了它的特点。我们学习了如何在 Travis CI 中创建一个管道，从创建`.travis.yml`文件，配置作业，使构建推送经过验证的 Docker 镜像到我们的 Docker 注册表，以及如何收到通知。

我们描述了如何加快并行运行部分的速度，以及如何将值设置为秘密。我们还配置了 GitHub，以确保 Travis CI 管道在将新代码合并到我们的主分支之前已成功运行。

在下一章中，我们将学习基本的 Kubernetes 操作和概念。

# 问题

1.  增加部署数量是否会降低它们的质量？

1.  描述管道是什么。

1.  我们如何知道我们的主分支是否可以部署？

1.  Travis CI 的主要配置来源是什么？

1.  Travis CI 何时会默认发送通知电子邮件？

1.  我们如何避免将一个损坏的分支合并到我们的主分支中？

1.  为什么我们应该避免在 Git 存储库中存储秘密？

# 进一步阅读

要了解更多关于持续集成和其他工具的信息，您可以查看《实践持续集成和交付》一书（[`www.packtpub.com/eu/virtualization-and-cloud/hands-continuous-integration-and-delivery`](https://www.packtpub.com/eu/virtualization-and-cloud/hands-continuous-integration-and-delivery)），该书不仅涵盖了 Travis CI，还包括 Jenkins 和 CircleCI 等其他工具。如果您想深入了解 GitHub 及其所有可能性，包括如何有效地协作以及它所支持的不同工作流程，请在《GitHub Essentials》中了解更多信息（[`www.packtpub.com/eu/web-development/github-essentials-second-edition`](https://www.packtpub.com/eu/web-development/github-essentials-second-edition)）。


# 第三部分：使用多个服务-通过 Kubernetes 操作系统

在上一节中，我们介绍了如何开发和容器化单个微服务，本节介绍编排概念，使多个服务协同工作。本节深入解释了作为 Docker 容器编排器的 Kubernetes，以及最大化其使用的实践方法以及如何将其部署到实际运营中。

本节的第一章介绍了 Kubernetes，并解释了这个工具背后的基本概念，这将贯穿本节的使用。Kubernetes 有其自己的特定术语，最初可能有点令人生畏，所以当有不清楚的地方时，不要害怕回到这一章。它还涵盖了如何安装和操作本地集群。

本节的第二章展示了如何在本地 Kubernetes 集群中安装开发的微服务，使用上一章介绍的概念进行具体操作。它配置了一个完整的集群，其中服务正在运行和协作，同时演示了如何在这种环境中进行开发。

本节的第三章涉及实际操作：如何使用商业云服务（本书中使用 AWS 服务）创建云集群，旨在为公开互联网上的外部客户提供服务。它还涵盖了如何在适当的 HTTPS 端点下保护服务，使用私有 Docker 注册表以及自动扩展集群和确保容器平稳运行的实践方法等高级主题。

本节的第四章介绍了 GitOps 的概念，即使用 Git 存储库来控制集群基础设施，将任何基础设施更改保持在源代码控制下，并允许使用 Git 的常见元素，如拉取请求，来控制和验证基础设施更改是否正确。

本节的第五章描述了单个服务内的软件生命周期，以及如何添加新功能的工作原理，从定义功能到在现有 Kubernetes 集群中实时运行。本章展示了测试和验证新功能的实践方法，以便以自信和高效的方式将其引入实时系统。

本节包括以下章节：

+   第五章，*使用 Kubernetes 协调微服务*

+   第六章，*使用 Kubernetes 进行本地开发*

+   第七章，*配置和保护生产系统*

+   第八章，*使用 GitOps 原则*

+   第九章，*管理工作流*


# 第五章：使用 Kubernetes 协调微服务

在本章中，我们将讨论 Kubernetes 背后的基本概念，这是一个允许您管理多个容器并协调它们的工具，从而使已部署在每个容器上的微服务协同工作。

本章将涵盖容器编排器的概念以及特定的 Kubernetes 术语，例如 pod、service、deployment 等之间的区别。我们还将学习如何分析运行中的集群并执行其他常见操作，以便您可以将它们应用于我们的微服务示例。

在本章中，我们将涵盖以下主题：

+   定义 Kubernetes 编排器

+   理解不同的 Kubernetes 元素

+   使用 kubectl 执行基本操作

+   故障排除运行中的集群

在本章结束时，您将了解 Kubernetes 的基本元素，并能够执行基本操作。您还将学习基本的故障排除技能，以便您可以检测可能的问题。

# 技术要求

如果您使用的是 macOS 或 Windows，默认的 Docker 桌面安装可以启动本地 Kubernetes 集群。只需确保在 Kubernetes 的首选项中启用了此功能：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-dkr-msvc-py/img/4437849f-7f85-4020-a25b-34dba652aa6b.png)

对于 Linux，本地安装 Kubernetes 的最简单方法是使用 k3s（[`k3s.io/`](https://k3s.io/)）。

k3s 是对 Kubernetes（即 k8s）的一种致敬，但是它是其简化版本。

k3s 是 Kubernetes 的一个简化安装，您可以使用它来运行包含在单个二进制文件中的集群。如果您希望下载并运行它，请查看安装页面（[`github.com/rancher/k3s/blob/master/README.md`](https://github.com/rancher/k3s/blob/master/README.md)）。

为了能够使用运行在 k3s 集群内的 Docker 版本，我们需要使用以下代码：

```py
$ # Install k3s
$ curl -sfL https://get.k3s.io | sh -
$ # Restart k3s in docker mode
$ sudo systemctl edit --full k3s.service
# Replace `ExecStart=/usr/local/bin/k3s` with `ExecStart=/usr/local/bin/k3s server --docker`
$ sudo systemctl daemon-reload
$ sudo systemctl restart k3s
$ sudo systemctl enable k3s
$ # Allow access outside of root to KUBECTL config
$ sudo chmod 644 /etc/rancher/k3s/k3s.yaml
$ # Add your user to the docker group, to be able to run docker commands
$ # You may need to log out and log in again for the group to take effect
$ sudo usermod -a -G docker $USER
```

确保安装`kubectl`（k3s 默认安装了一个单独的版本）。安装`kubectl`的步骤可以在[`kubernetes.io/docs/tasks/tools/install-kubectl/`](https://kubernetes.io/docs/tasks/tools/install-kubectl/)找到。`kubectl`命令控制 Kubernetes 操作。

检查上述页面上的说明以添加 Bash 完成，这将允许我们按*Tab*键完成一些命令。

如果一切安装正确，您应该能够使用以下命令检查运行中的 pod：

```py
$ kubectl get pods --all-namespaces
NAMESPACE NAME                                         READY STATUS  RESTARTS AGE
docker    compose-89fb656cf-cw7bb                      1/1   Running 0        1m
docker    compose-api-64d7d9c945-p98r2                 1/1   Running 0        1m
kube-system etcd-docker-for-desktop                    1/1   Running 0        260d
kube-system kube-apiserver-docker-for-desktop          1/1   Running 0        2m
kube-system kube-controller-manager-docker-for-desktop 1/1   Running 0        2m
kube-system kube-dns-86f4d74b45-cgpsj                  3/3   Running 1        260d
kube-system kube-proxy-rm82n                           1/1   Running 0        2m
kube-system kube-scheduler-docker-for-desktop          1/1   Running 0        2m
kube-system kubernetes-dashboard-7b9c7bc8c9-hzpkj      1/1   Running 1        260d
```

注意不同的命名空间。它们都是 Kubernetes 自己创建的默认命名空间。

转到以下页面安装 Ingress 控制器：[`github.com/kubernetes/ingress-nginx/blob/master/docs/deploy/index.md`](https://github.com/kubernetes/ingress-nginx/blob/master/docs/deploy/index.md)。在 Docker 桌面上，您需要运行以下两个命令：

```py
$ kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/master/deploy/static/mandatory.yaml
$ kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/master/deploy/static/provider/cloud-generic.yaml
```

这将创建一个带有控制器 pod 的`ingress-nginx`命名空间。Kubernetes 将使用该 pod 来设置 Ingress 配置。

现在，让我们来看看使用 Kubernetes 的优势。

# 定义 Kubernetes 编排器

Kubernetes 是一种流行的容器编排工具。它允许我们以协调的方式管理和部署多个相互交互的容器。由于每个微服务都存在于单独的容器中，正如我们在第一章中提到的那样，*进行迁移-设计、计划和执行*，它们可以协同工作。

要了解更多关于 Kubernetes 的深入介绍，您可以查看由 Scott McCloud 发布的以下漫画：[`cloud.google.com/kubernetes-engine/kubernetes-comic/`](https://cloud.google.com/kubernetes-engine/kubernetes-comic/)。

Kubernetes 旨在用于生产系统。它旨在能够控制大规模部署并抽象出大部分基础设施的细节。Kubernetes 集群中的每个元素都是以编程方式配置的，Kubernetes 本身根据可用的容量来管理集群的部署位置。

Kubernetes 可以完全使用配置文件进行配置。这使得在出现完全瘫痪导致所有物理服务器宕机的情况下，可以复制集群成为可能。甚至可以在不同的硬件上进行这样的操作，而传统的部署可能会非常困难。

这个例子假设数据被存储和检索；例如，在备份设备中。显然，这可能很困难——灾难恢复总是如此。然而，它简化了许多如果你希望复制一个集群所需的步骤。

鉴于 Kubernetes 使用容器并且很容易安装它们，有一个庞大的容器生态系统可以为 Kubernetes 本身添加功能。最好的例子可能是 Kubernetes 仪表板（[`kubernetes.io/docs/tasks/access-application-cluster/web-ui-dashboard/`](https://kubernetes.io/docs/tasks/access-application-cluster/web-ui-dashboard/)），一个显示 Kubernetes 操作概述的用户界面。它不是默认安装的，但可以以与安装服务相同的方式安装。其他用例的例子包括监控和日志记录。这使得 Kubernetes 非常可扩展。

# 将 Kubernetes 与 Docker Swarm 进行比较

Kubernetes 并不是唯一可用的编排器。正如我们在第三章中提到的，还有`docker-compose`。Docker Compose 也可以编排不同的容器并协调它们，但不涉及多台服务器。

Docker 有一个名为 Docker Swarm 的本机扩展，它允许我们使用一组机器来运行`docker-compose`，同时重用相同的 YAML 文件，但增加了一些细节来描述你希望它们如何运行。

您可以在官方文档中了解更多关于 Docker Swarm 的信息（[`docs.docker.com/engine/swarm/`](https://docs.docker.com/engine/swarm/)）。

与 Kubernetes 相比，Docker Swarm 更容易设置，假设您必须管理服务器。随着您扩展 Docker Compose 的功能，您会发现它的学习曲线很低。

另一方面，Kubernetes 更强大和可定制。它有一个更大的社区和更快的创新步伐。它在处理问题方面也更好。最大的问题是设置一个集群，但正如我们将在第七章中看到的，*配置和保护生产系统*，现在有易于商业部署的方式，我们可以用几分钟的时间创建一个集群，这降低了 Kubernetes 的准入门槛。

这使得 Kubernetes（可以说）在处理从旧系统迁移和展望未来时是更好的解决方案。对于小规模部署，或者如果您需要部署和管理自己的服务器，Docker Swarm 可能是一个有趣的选择。

为了帮助您从使用`docker-compose.yaml`文件转移到使用等效的 Kubernetes YAML 文件，您可以使用`kompose`（[`github.com/kubernetes/kompose`](https://github.com/kubernetes/kompose)）。它可能有助于快速启动一个 Kubernetes 集群，并将`docker-compose.yaml`文件中描述的服务转换为它们等效的 Kubernetes 元素，但两个系统之间总是存在差异，可能需要进行调整。

让我们从描述 Kubernetes 的特定元素和命名方式开始。

# 理解不同的 Kubernetes 元素

Kubernetes 有自己的不同元素的命名方式。我们在本书中经常会使用这些命名方式，Kubernetes 文档也在使用它们。了解它们之间的区别很重要，因为其中一些可能是微妙的。

# 节点

Kubernetes 的主要基础设施元素称为**节点**。Kubernetes 集群由一个或多个节点组成，这些节点是支持其他元素抽象化的物理机器（或虚拟机器）。

每个节点需要能够与其他节点通信，并且它们都在一个容器运行时中运行 - 通常是 Docker，但它们也可以使用其他系统，比如`rktlet`（[`github.com/kubernetes-incubator/rktlet`](https://github.com/kubernetes-incubator/rktlet)）。

节点之间创建了一个网络，将所有发送到集群的请求路由到适当的节点，因此发送到集群中任何节点的任何请求都将得到充分的回答。Kubernetes 将处理哪个可部署元素应该部署到哪个节点，甚至在节点出现问题或资源问题时重新部署节点或将它们从一个节点移动到另一个节点。

节点不一定需要完全相同，当部署特定元素到特定节点时需要一定程度的控制，但通常情况下它们是相同的。

虽然节点是支持集群的支柱，但 Kubernetes 通过定义期望的结果并让 Kubernetes 决定何处放置元素，并确保内部网络通道的请求被发送到适当的服务，帮助抽象化特定节点。

# Kubernetes 控制平面

Kubernetes 控制平面是 Kubernetes 用来正确配置作为 Kubernetes 集群中节点的一部分的一组服务器的所有过程的地方。服务器允许节点相互连接，允许我们监视它们的当前状态，并允许我们根据部署、规模等方面进行必要的更改。

负责注册和进行这些更改的节点称为主节点。可以有多个主节点。

所有这些控制通常在幕后顺利运行。它的网络与其他部分分离，这意味着在这个级别出现问题不会影响集群的当前操作，除了我们无法进行更改。

# Kubernetes 对象

Kubernetes 对象是表示部署在集群中的服务状态的抽象。主要涉及运行容器和这些容器的路由，以及持久存储。

让我们从最小到最大来看不同的元素。这个列表并不详尽；查看 Kubernetes 文档以获取更多细节：

+   **容器**：一个单独的 Docker 容器。这些是 Kubernetes 的构建块，但它们永远不会单独存在。

+   **Pod：**在 Kubernetes 中可以部署的基本单元。Pod 是一个或多个容器的集合，通常来自不同的镜像。通常，一个 Pod 只有一个容器，但有时可能有更多的容器是有用的。同一 Pod 中的所有容器共享相同的 IP 地址（Pod IP），这意味着访问`localhost`端口的容器可能实际上在访问另一个容器。这实际上是与它们通信的推荐方式。

这对你来说一开始可能有点奇怪，但通常，多容器 Pod 将有一个主要容器和执行辅助任务的其他内容，比如导出指标。

+   **ConfigMap**：这定义了一组可以注入到 Pod 中的键值对，通常作为环境变量或文件。这允许我们在不同定义的 Pod 之间共享配置，例如，使所有容器记录调试信息。请注意，Pod 可以有自己的配置，但 ConfigMaps 是一种方便的方式来共享相同的值，以便它们可用于不同的 Pod。

+   **卷**：容器内的文件是临时的，如果容器停止执行，这些文件将丢失。卷是一种持久存储形式，可用于在启动之间保持数据信息并在 pod 中的容器之间共享信息。

作为一个一般原则，尽量减少卷的数量。大多数应用程序本来就应该是无状态的，任何可变数据都应该存储在数据库中。如果同一 pod 中的容器需要通信，最好通过 HTTP 请求进行。请记住，任何不可变数据，例如静态文件，都可以存储在容器镜像中。

+   **部署**：这是一个或多个相同 pod 的分组。部署的定义将说明所需的数量，Kubernetes 将根据定义的策略努力实现这一点。单个部署中的 pod 可以部署到不同的节点，并且通常会这样做。如果任何 pod 被删除、完成或出现任何问题，部署将启动另一个，直到达到定义的数量。

+   **作业**：作业创建一个或多个预期完成的 pod。虽然部署会假设任何完成的 pod 都是问题，并且会启动另一个，但作业会重试，直到满足适当数量的成功。完成的 pod 不会被删除，这意味着我们可以检查它们的日志。作业是一次性执行。还有**定时作业**，将在特定时间运行。

+   **服务**。由于 pod 被创建和重新创建，并且具有不同的 IP，为了允许服务访问它们，服务需要定义其他元素可以使用的名称来发现它。换句话说，它将请求路由到适当的 pod。通常，服务和部署将相关联，服务使部署可访问，并在所有定义的 pod 之间进行轮询。服务还可以用于为外部服务创建内部名称。

Kubernetes 中的服务解决了分布式系统中的一个旧问题，即*服务发现*。当集群中的节点需要知道服务的位置时，即使节点发生变化，也会出现这个问题；也就是说，当我们添加或删除节点时，不会改变所有节点的配置设置。

如果创建一个服务，Kubernetes 将自动执行此操作。

+   **入口**: 虽然服务是内部的，但入口是外部的。它将任何外部请求路由到适当的服务，以便它们可以提供服务。您可以通过主机名定义不同的入口，这样可以确保集群通过请求的目标主机路由到不同的服务，或者根据其路径托管单个入口。在内部，入口被实现为实现入口控制器的容器，默认情况下是`nginx`。

根据您的 Kubernetes 安装，您可能需要安装默认控制器。要安装默认控制器，请按照[`github.com/kubernetes/ingress-nginx/blob/master/docs/deploy/index.md`](https://github.com/kubernetes/ingress-nginx/blob/master/docs/deploy/index.md)上的说明操作。

+   **命名空间**：这是虚拟集群的定义。您可以在同一个物理 Kubernetes 集群中定义多个命名空间。在命名空间下定义的每个名称都需要是唯一的，但另一个命名空间可以使用相同的定义。不同命名空间中的对象无法在内部进行通信，但可以在外部进行通信。

使用非常相似的定义生成不同的命名空间可能是有用的，如果您希望为测试、开发或演示概念等目的创建不同的环境。 Kubernetes 的主要优势在于您可以复制整个系统，并利用这一点创建具有细节上的小改变的类似环境，例如环境的新版本。

对象可以在`.yaml`文件中找到，这些文件可以加载到系统中。单个`.yaml`文件可以定义多个对象，例如，定义包含容器的 pod 的部署。

以下图表总结了可用的不同对象：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-dkr-msvc-py/img/487eb397-f409-4b5b-9467-33572ff2452a.png)

作业和卷不存在，但有两个服务可用：一个指向部署，另一个指向外部服务。外部服务针对内部元素，并且不会向外部公开。

# 使用 kubectl 执行基本操作

通过使用`kubectl`，我们可以对所有不同的元素执行操作。我们已经偷偷看了一眼`get`，以了解可用的元素。

有关更多信息和`kubectl`中可用的最常见操作的快速概述，请查看[`kubernetes.io/docs/reference/kubectl/cheatsheet/`](https://kubernetes.io/docs/reference/kubectl/cheatsheet/)上的`kubectl`备忘单。

我们可以使用`kubectl`来`create`一个新元素。例如，要创建和列出命名空间，我们可以使用以下代码：

```py
$ kubectl create namespace example
namespace/example created
$ kubectl get namespaces
NAME        STATUS AGE
default     Active 260d
docker      Active 260d
example     Active 9s
kube-public Active 260d
kube-system Active 260d
```

我们可以创建各种元素，其中一些我们将在本书中介绍。

# 定义元素

命名空间是一个特殊情况，因为它不需要任何配置。要创建新元素，需要创建一个描述该元素的 YAML 文件。例如，我们可以使用 Docker Hub 中的官方 NGINX 镜像创建一个新的 pod：

```py
---
apiVersion: v1
kind: Pod
metadata:
  name: nginx
  namespace: example
spec:
  containers:
    - name: nginx
      image: library/nginx:latest
```

作为最低要求，元素应包含以下内容：

+   元素的 API 版本。

+   元素的类型。

+   元素的名称，以及其命名空间。

+   包括配置详细信息的`spec`部分。对于 pod，我们需要添加必要的容器。

YAML 文件有时可能有点反复无常，特别是涉及缩进和语法时。您可以使用诸如 Kubeval（[`kubeval.instrumenta.dev/`](https://kubeval.instrumenta.dev/)）之类的工具来检查文件是否正确，并且在使用文件之前遵循 Kubernetes 良好实践。

我们将此文件保存为`example_pod.yml`。我们将使用`apply`命令创建它，并使用以下命令监视其运行情况：

```py
$ kubectl apply -f example_pod.yml
pod/nginx created
$ kubectl get pods -n example
NAME  READY STATUS            RESTARTS AGE
nginx 0/1   ContainerCreating 0        2s
$ kubectl get pods -n example
NAME  READY STATUS  RESTARTS AGE
nginx 1/1   Running 0        51s
```

注意使用`-n`参数来确定命名空间。

现在我们可以`exec`进入容器并在其中运行命令。例如，要检查 NGINX 服务器是否正在运行并提供文件，我们可以使用以下代码：

```py
$ kubectl exec -it nginx -n example /bin/bash
root@nginx:/# apt-get update
...
root@nginx:/# apt-get install -y curl
...
root@nginx:/# curl localhost
<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
...
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>
```

pod 可以以两种方式更改。第一种方法是手动运行`edit`，它会打开您预定义的终端编辑器，以便您可以编辑文件：

```py
$ kubectl edit pod nginx -n example
```

您将看到带有所有默认参数的 pod。这种更改 pod 的方式对于小型测试很有用，但一般来说，最好更改原始的 YAML 文件，以便您可以跟踪发生的更改。例如，我们可以更改 NGINX，以便我们使用其以前的版本：

```py
---
apiVersion: v1
kind: Pod
metadata:
  name: nginx
  namespace: example
spec:
  containers:
    - name: nginx
      image: library/nginx:1.16
```

然后，我们可以再次`apply`这些更改，这将重新启动 pod：

```py
$ kubectl apply -f example_pod.yml
pod/nginx configured
$ kubectl get pods -n example
NAME  READY STATUS  RESTARTS AGE
nginx 1/1   Running 1        36s
```

# 获取更多信息

`get`命令接受更多配置。您可以使用`wide`输出选项检索更多信息：

```py
$ kubectl get pods -n example -o wide
NAME  READY STATUS  RESTARTS AGE IP        NODE
nginx 1/1   Running 1        30m 10.1.0.11 docker-for-desktop
```

如果您进行更改并对此更改产生兴趣，可以使用`-w`参数来监视任何更改。例如，以下代码显示了 pod 的重启结果。此重启是由于对容器图像进行更改而产生的：

```py
$ kubectl get pods -n example -w
NAME  READY STATUS  RESTARTS AGE
nginx 1/1   Running 2        32m
nginx 1/1   Running 3        32m
```

如果您需要有关特定元素的更多信息，可以使用`describe`：

```py
$ kubectl describe pod nginx -n example
Name: nginx
Namespace: example
Node: docker-for-desktop/192.168.65.3
Start Time: Sun, 23 Jun 2019 20:56:23 +0100
Labels: <none>
Annotations: ...
Status: Running
IP: 10.1.0.11
...
Events:
 Type Reason Age From Message
 ---- ------ ---- ---- -------
 Normal Scheduled 40m default-scheduler Successfully assigned nginx to docker-for-desktop
 ...
 Normal Created 4m43s (x5 over 40m) kubelet, docker-for-desktop Created container
 Normal Started 4m43s (x5 over 40m) kubelet, docker-for-desktop Started container
```

这返回了大量信息。最有用的信息通常是关于事件的信息，它将返回有关元素的生命周期的信息。

# 删除元素

`delete`命令删除一个元素及其下的所有内容：

```py
$ kubectl delete namespace example
namespace "example" deleted
$ kubectl get pods -n example
No resources found.
```

请注意，有时删除元素将导致其重新创建。这在通过部署创建 pod 时很常见，因为部署将努力使 pod 的数量达到配置的数量。

# 运行集群故障排除

我们可以用`get`和`describe`命令来排查 Kubernetes 中的问题。

根据我的经验，Kubernetes 运行中最常见的问题是，有时某些 Pod 无法启动。排查步骤如下：

1.  容器镜像是否正确？下载镜像出现问题将显示`ErrImagePull`。这可能是由于无法从注册表下载镜像导致的身份验证问题。

1.  `CrashLoopBackOff`状态表示容器的进程已中断。Pod 将尝试一遍又一遍地重新启动。这通常是由于容器的潜在问题引起的。检查配置是否正确。您可以使用以下命令检查容器的`stdout`日志：

```py
$ kubectl logs <pod> -n <namespace> -c <container>
```

确保容器可运行。尝试使用以下命令手动运行它：

```py
$ docker run <image>
```

1.  Pod 通常不会被外部暴露。这通常是由于暴露它们的服务和/或 Ingress 存在问题。您可以通过使用`exec`进入另一个容器，然后尝试访问服务和 Pod 的内部 IP，通常使用`curl`来检测 Pod 在集群内是否响应。

正如我们之前所看到的，`curl`通常不会默认安装在容器中，因为它们通常只安装了一组最小的工具。不用担心，您可以使用操作系统的软件包管理器安装它，优点是，一旦容器被回收（在正常的 Kubernetes 操作中很快就会发生），它就不会占用任何空间！出于同样的原因，每次需要调试问题时可能都需要安装它。

记住我们讨论过的 Ingress、服务、部署和 Pod 的链条，并从内部向外部查找配置错误的位置。

在排查问题时，请记住，可以通过`exec`命令访问 Pod 和容器，这将允许我们检查运行中的进程、文件等。这类似于访问物理服务器的终端。您可以使用以下代码来执行此操作：

```py
$ kubectl exec -it <pod> -n <namespace> /bin/sh
```

要小心，因为 Kubernetes 集群的性质可能需要您检查一个 Pod 中是否有多个容器运行，如果是这样，您可能需要检查特定的容器。

# 总结

在本章中，我们了解了 Kubernetes 的基本概念，以及如何管理和协调包含我们的微服务的多个容器。

首先，我们介绍了 Kubernetes 的概念以及一些高级优势。然后，我们描述了 Kubernetes 术语中定义集群的不同元素。这既包括物理方面，其中节点是主要的定义元素，也包括抽象方面，如 Pod、部署、服务和 Ingress，这些是我们生成工作集群所需的构建块。

我们描述了`kubectl`以及我们可以使用的常见操作来定义元素和通过 YAML 文件检索信息。我们还描述了在处理 Kubernetes 集群时可能出现的一些常见问题。

在下一章中，我们将定义在 YAML 文件中可以使用的不同选项，以便生成集群，并学习如何为我们的微服务示例生成 Kubernetes 集群。

# 问题

1.  什么是容器编排器？

1.  在 Kubernetes 中，什么是节点？

1.  Pod 和容器之间有什么区别？

1.  工作和 Pod 之间有什么区别？

1.  何时应该添加 Ingress？

1.  什么是命名空间？

1.  我们如何在文件中定义一个 Kubernetes 元素？

1.  `kubectl`的`get`和`describe`命令有什么区别？

1.  `CrashLoopBackOff`错误表示什么？

# 进一步阅读

您可以通过阅读《Kubernetes 入门指南-第三版》（[`www.packtpub.com/eu/virtualization-and-cloud/getting-started-kubernetes-third-edition`](https://www.packtpub.com/eu/virtualization-and-cloud/getting-started-kubernetes-third-edition)）和《完整的 Kubernetes 指南》（[`www.packtpub.com/eu/virtualization-and-cloud/complete-kubernetes-guide`](https://www.packtpub.com/eu/virtualization-and-cloud/complete-kubernetes-guide)）来了解更多关于 Kubernetes 的信息。


# 第六章：使用 Kubernetes 进行本地开发

在本章中，您将学习如何定义一个集群，部署所有交互式微服务，以及如何在本地进行开发。我们将在前一章介绍的概念基础上进行构建，并描述如何在 Kubernetes 中以实际方式配置整个系统，部署多个微服务，并使其在您自己的本地计算机上作为一个整体运行。

在这里，我们将介绍另外两个微服务：前端和用户后端。它们在第一章中讨论过，在*战略规划以打破单体*部分。我们将在本章中看到它们需要如何配置才能在 Kubernetes 中工作。这是除了第二章中介绍的 Thoughts 后端，*使用 Python 创建 REST 服务*，第三章，*使用 Docker 构建、运行和测试您的服务*，和第四章，*创建管道和工作流*。我们将讨论如何正确配置它们三个，并添加一些其他选项，以确保它们在部署到生产环境后能够顺利运行。

本章将涵盖以下主题：

+   实施多个服务

+   配置服务

+   在本地部署完整系统

到本章结束时，您将拥有一个在本地工作的 Kubernetes 系统，其中三个微服务已部署并作为一个整体运行。您将了解不同元素的工作原理以及如何配置和调整它们。

# 技术要求

对于本章，您需要像前一章中描述的那样运行本地 Kubernetes 实例。记得安装 Ingress 控制器。

您可以在 GitHub 存储库中检查我们将在其中使用的完整代码（[`github.com/PacktPublishing/Hands-On-Docker-for-Microservices-with-Python/tree/master/Chapter06`](https://github.com/PacktPublishing/Hands-On-Docker-for-Microservices-with-Python/tree/master/Chapter06)）。

# 实施多个服务

在 GitHub 存储库中，您可以找到本章中将使用的三个微服务。它们基于第一章中介绍的单体，并分为三个元素：

+   Thoughts 后端：如前一章所述，它处理了 Thoughts 的存储和搜索。

+   用户后端：存储用户并允许他们登录。根据身份验证方法的描述，它创建一个可用于对其他系统进行身份验证的令牌。

+   前端：这来自单体应用，但是不直接访问数据库，而是向用户和 Thoughts 后端发出请求以复制功能。

请注意，尽管我们描述了集群独立提供静态文件的最终阶段，但静态文件仍由前端提供。这是为了简单起见，以避免多余的服务。

上述服务与 Thoughts 后端在第三章中的方式类似进行了 Docker 化，*使用 Docker 构建、运行和测试您的服务*。让我们看看其他微服务的一些细节。

# 描述用户后端微服务

用户后端的代码可以在[`github.com/PacktPublishing/Hands-On-Docker-for-Microservices-with-Python/tree/master/Chapter06/users_backend`](https://github.com/PacktPublishing/Hands-On-Docker-for-Microservices-with-Python/tree/master/Chapter06/users_backend)找到。其结构与 Thoughts 后端非常相似，是一个与 PostgreSQL 数据库通信的 Flask-RESTPlus 应用程序。

它有两个端点，如其 Swagger 接口中所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-dkr-msvc-py/img/b3fae995-d64e-42dd-90ab-e11643f75592.png)

端点如下：

|  | **端点** | **输入** | **返回** |
| --- | --- | --- | --- |
| `POST` | `/api/login` | `{username: <username>, password: <password>}` | `{Authorized: <token header>}` |
| `POST` | `/admin/users` | `{username: <username>, password: <password>}` | `<new_user>` |

`admin`端点允许您创建新用户，登录 API 返回一个有效的标头，可用于 Thoughts Backend。

用户存储在数据库中，具有以下架构：

| **字段** | **格式** | **注释** |
| --- | --- | --- |
| `id` | `Integer` | 主键 |
| `username` | `String (50)` | 用户名 |
| `password` | `String(50)` | 密码以明文存储，这是一个坏主意，但简化了示例 |
| `creation` | `Datetime` | 用户创建时间 |

使用以下代码描述了 SQLAlchemy 模型定义中的此模式：

```py
class UserModel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50))
    # DO NOT EVER STORE PLAIN PASSWORDS IN DATABASES
    # THIS IS AN EXAMPLE!!!!!
    password = db.Column(db.String(50))
    creation = db.Column(db.DateTime, server_default=func.now())
```

请注意，创建日期会自动存储。还要注意，我们以明文形式存储密码。这是*在生产服务中一个可怕的主意*。您可以查看一篇名为*如何在数据库中存储密码？*的文章（[`www.geeksforgeeks.org/store-password-database/`](https://www.geeksforgeeks.org/store-password-database/)）以获取有关使用盐种加密密码的一般想法。您可以使用`pyscrypt`（[`github.com/ricmoo/pyscrypt`](https://github.com/ricmoo/pyscrypt)）等软件包在 Python 中实现此类结构。

用户*bruce*和*stephen*被添加到`db`示例中，作为示例数据。

# 描述前端微服务

前端代码可以在 GitHub 存储库中找到。它基于 Django 单体应用程序（[`github.com/PacktPublishing/Hands-On-Docker-for-Microservices-with-Python/tree/master/Chapter01/Monolith`](https://github.com/PacktPublishing/Hands-On-Docker-for-Microservices-with-Python/tree/master/Chapter01/Monolith)）介绍于第一章，*进行移动-设计，计划和执行*。

与单体应用程序的主要区别在于不访问数据库。因此，Django ORM 没有用处。它们被替换为对其他后端的 HTTP 请求。为了发出请求，我们使用了 fantastic `requests`库。

例如，`search.py`文件被转换为以下代码，该代码将搜索委托给 Thoughts Backend 微服务。请注意，客户的请求被转换为对`GET /api/thoughts`端点的内部 API 调用。结果以 JSON 格式解码并呈现在模板中：

```py
import requests

def search(request):
    username = get_username_from_session(request)
    search_param = request.GET.get('search')

    url = settings.THOUGHTS_BACKEND + '/api/thoughts/'
    params = {
        'search': search_param,
    }
    result = requests.get(url, params=params)
    results = result.json()

    context = {
        'thoughts': results,
        'username': username,
    }
    return render(request, 'search.html', context)
```

单体等效代码可以在存储库的`Chapter01`子目录中进行比较（[`github.com/PacktPublishing/Hands-On-Docker-for-Microservices-with-Python/blob/master/Chapter01/Monolith/mythoughts/thoughts/search.py`](https://github.com/PacktPublishing/Hands-On-Docker-for-Microservices-with-Python/blob/master/Chapter01/Monolith/mythoughts/thoughts/search.py)）。

请注意，我们通过`requests`库向定义的搜索端点发出`get`请求，结果以`json`格式返回并呈现。

`THOUGTHS_BACKEND`根 URL 来自设置，通常是 Django 的风格。

这个例子很简单，因为没有涉及身份验证。参数从用户界面捕获，然后路由到后端。请求在发送到后端和获取结果后都得到了正确格式化，然后呈现。这是两个微服务共同工作的核心。

一个更有趣的案例是`list_thought`（[`github.com/PacktPublishing/Hands-On-Docker-for-Microservices-with-Python/blob/master/Chapter06/frontend/mythoughts/thoughts/thoughts.py#L18`](https://github.com/PacktPublishing/Hands-On-Docker-for-Microservices-with-Python/blob/master/Chapter06/frontend/mythoughts/thoughts/thoughts.py#L18)）视图。以下代码列出了已登录用户的想法：

```py
def list_thoughts(request):
    username = get_username_from_session(request)
    if not username:
        return redirect('login')

    url = settings.THOUGHTS_BACKEND + '/api/me/thoughts/'
    headers = {
        'Authorization': request.COOKIES.get('session'),
    }
    result = requests.get(url, headers=headers)
    if result.status_code != http.client.OK:
        return redirect('login')

    context = {
        'thoughts': result.json(),
        'username': username,
    }
    return render(request, 'list_thoughts.html', context)
```

在这里，在做任何事情之前，我们需要检查用户是否已登录。这是在 `get_username_from_session` 调用中完成的，它返回 `username` 或 `None`（如果他们未登录）。如果他们未登录，则返回将被重定向到登录屏幕。

由于此端点需要身份验证，因此我们需要将用户的会话添加到请求的 `Authorization` 标头中。用户的会话可以从 `request.COOKIES` 字典中获取。

作为保障，我们需要检查后端返回的状态代码是否正确。对于此调用，任何不是 200（HTTP 调用正确）的结果状态代码都将导致重定向到登录页面。

为了简单和清晰起见，我们的示例服务不处理不同的错误情况。在生产系统中，应该区分错误，其中问题是用户未登录或存在其他类型的用户错误（400 错误），或者后端服务不可用（500 状态码）。

错误处理，如果做得当，是困难的，但值得做好，特别是如果错误帮助用户理解发生了什么。

`get_username_from_session` 函数封装了对 `validate_token_header` 的调用，与上一章介绍的相同：

```py
def get_username_from_session(request):
    cookie_session = request.COOKIES.get('session')
    username = validate_token_header(cookie_session,
                                     settings.TOKENS_PUBLIC_KEY)
    if not username:
        return None

    return username
```

`settings` 文件包含解码令牌所需的公钥。

在本章中，为简单起见，我们直接将密钥复制到 `settings` 文件中。这不适用于生产环境。任何秘密都应通过 Kubernetes 环境配置获取。我们将在接下来的章节中看到如何做到这一点。

环境文件需要指定用户后端和 Thoughts 后端的基本 URL，以便能够连接到它们。

# 连接服务

只有使用 `docker-compose` 才能测试服务是否协同工作。检查 Users 后端和 Thoughts 后端的 `docker-compose.yaml` 文件是否在外部公开了不同的端口。

Thoughts 后端公开端口`8000`，用户后端公开端口`8001`。这允许前端连接到它们（并公开端口`8002`）。此图显示了此系统的工作原理：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-dkr-msvc-py/img/1a463150-339d-4bf2-8a94-374bb6a34ec3.png)

您可以看到三个服务是如何隔离的，因为 `docker-compose` 将为它们创建自己的网络以进行连接。两个后端都有自己的容器，充当数据库。

前端服务需要连接到其他服务。服务的 URL 应该添加到 `environment.env` 文件中，并且应该指示具有计算机 IP 的服务。

内部 IP，如 localhost 或`127.0.0.1`，不起作用，因为它在容器内部被解释。您可以通过运行 `ifconfig` 来获取本地 IP。

例如，如果您的本地 IP 是 `10.0.10.3`，则 `environment.env` 文件应包含以下内容：

```py
THOUGHTS_BACKEND_URL=http://10.0.10.3:8000
USER_BACKEND_URL=http://10.0.10.3:8001
```

如果您在浏览器中访问前端服务，它应该连接到其他服务。

一种可能性是生成一个更大的 `docker-compose` 文件，其中包括所有内容。如果所有微服务都在同一个 Git 存储库中，这可能是有意义的，这种技术被称为**monorepo** ([`gomonorepo.org/`](https://gomonorepo.org/))。可能的问题包括保持内部的 `docker-compose` 与单个系统一起工作，并使通用的 `docker-compose` 保持同步，以便自动化测试应该检测到任何问题。

这种结构有点累赘，因此我们可以将其转换为一个适当的 Kubernetes 集群，以便进行本地开发。

# 配置服务

要在 Kubernetes 中配置应用程序，我们需要为每个应用程序定义以下 Kubernetes 对象：

+   **部署**：部署将控制 pod 的创建，因此它们将始终可用。它还将根据镜像创建它们，并在需要时添加配置。Pod 运行应用程序。

+   **Service**：该服务将使 RESTful 请求在集群内部可用，具有简短的名称。这将路由请求到任何可用的 pod。

+   **Ingress**：这使得服务在集群外部可用，因此我们可以从集群外部访问该应用。

在本节中，我们将详细查看 Thoughts Backend 配置作为示例。稍后，我们将看到不同部分是如何连接的。我们创建了一个 Kubernetes 子目录 ([`github.com/PacktPublishing/Hands-On-Docker-for-Microservices-with-Python/tree/master/Chapter06/thoughts_backend/kubernetes`](https://github.com/PacktPublishing/Hands-On-Docker-for-Microservices-with-Python/tree/master/Chapter06/thoughts_backend/kubernetes)) 来存储每个定义的 `.yaml` 文件。

我们将使用 `example` 命名空间，因此请确保它已创建：

```py
$ kubectl create namespace example
```

让我们从第一个 Kubernetes 对象开始。

# 配置部署

对于 Thoughts Backend 部署，我们将部署一个具有两个容器的 pod，一个带有数据库，另一个带有应用程序。这种配置使得在本地工作变得容易，但请记住，重新创建 pod 将重新启动两个容器。

配置文件完全在这里可用 ([`github.com/PacktPublishing/Hands-On-Docker-for-Microservices-with-Python/blob/master/Chapter06/thoughts_backend/kubernetes/deployment.yaml`](https://github.com/PacktPublishing/Hands-On-Docker-for-Microservices-with-Python/blob/master/Chapter06/thoughts_backend/kubernetes/deployment.yaml))，让我们来看看它的不同部分。第一个元素描述了它是什么以及它的名称，以及它所在的命名空间：

```py
---
apiVersion: apps/v1
kind: Deployment
metadata:
    name: thoughts-backend
    labels:
        app: thoughts-backend
    namespace: example
```

然后，我们生成 `spec`。它包含我们应该保留多少个 pod 以及每个 pod 的模板。`selector` 定义了要监视的标签，它应该与模板中的 `labels` 匹配：

```py
spec:
    replicas: 1
    selector:
        matchLabels:
            app: thoughts-backend
```

`template` 部分在其自己的 `spec` 部分中定义了容器：

```py

    template:
        metadata:
            labels:
                app: thoughts-backend
        spec:
            containers:
                - name: thoughts-backend-service
                  ...
                - name: thoughts-backend-db
                  ...
```

`thoughts-backend-db` 更简单。唯一需要的元素是定义容器的名称和镜像。我们需要将拉取策略定义为 `Never`，以指示镜像在本地 Docker 仓库中可用，并且不需要从远程注册表中拉取它：

```py
- name: thoughts-backend-db
  image: thoughts_backend_db:latest
  imagePullPolicy: Never
```

`thoughts-backend-service` 需要定义服务的暴露端口以及环境变量。变量的值是我们在创建数据库时使用的值，除了 `POSTGRES_HOST`，在这里我们有一个优势，即同一 pod 中的所有容器共享相同的 IP：

```py
 - name: thoughts-backend-service
   image: thoughts_server:latest
   imagePullPolicy: Never
   ports:
   - containerPort: 8000
   env:
   - name: DATABASE_ENGINE
     value: POSTGRESQL
   - name: POSTGRES_DB
     value: thoughts
   - name: POSTGRES_USER
     value: postgres
   - name: POSTGRES_PASSWORD
     value: somepassword
   - name: POSTGRES_PORT
     value: "5432"
   - name: POSTGRES_HOST
     value: "127.0.0.1"
```

要在 Kubernetes 中获取部署，需要应用该文件，如下所示：

```py
$ kubectl apply -f thoughts_backend/kubernetes/deployment.yaml
deployment "thoughts-backend" created
```

部署现在已在集群中创建：

```py
$ kubectl get deployments -n example
NAME             DESIRED CURRENT UP-TO-DATE AVAILABLE AGE
thoughts-backend 1       1       1          1         20s
```

这将自动创建 pods。如果 pod 被删除或崩溃，部署将使用不同的名称重新启动它：

```py
$ kubectl get pods -n example
NAME                              READY STATUS  RESTARTS AGE
thoughts-backend-6dd57f5486-l9tgg 2/2   Running 0        1m
```

部署正在跟踪最新的镜像，但除非删除，否则不会创建新的 pod。要进行更改，请确保手动删除 pod，之后它将被重新创建：

```py
$ kubectl delete pod thoughts-backend-6dd57f5486-l9tgg -n example
pod "thoughts-backend-6dd57f5486-l9tgg" deleted
$ kubectl get pods -n example
NAME                              READY STATUS  RESTARTS AGE
thoughts-backend-6dd57f5486-nf2ds 2/2   Running 0        28s
```

该应用程序在集群内部仍然无法被发现，除非通过其特定的 pod 名称引用它，而这个名称可能会改变，因此我们需要为此创建一个服务。

# 配置服务

我们创建了一个 Kubernetes 服务来为创建的部署公开的应用程序创建一个名称。服务可以在 `service.yaml` 文件中进行检查。让我们来看一下：

```py
---
apiVersion: v1
kind: Service
metadata:
    namespace: example
    labels:
        app: thoughts-service
    name: thoughts-service
spec:
    ports:
        - name: thoughts-backend
          port: 80
          targetPort: 8000
    selector:
        app: thoughts-backend
    type: NodePort
```

初始数据类似于部署。`spec` 部分定义了开放端口，将对 `thoughts-backend` 中的容器中的服务的端口 `80` 的访问路由到端口 `8000`，部署的名称。`selector` 部分将所有请求路由到与之匹配的任何 pod。

类型为 `NodePort`，以允许从集群外部访问。这使我们能够检查它是否正常工作，一旦找到外部暴露的 IP：

```py
$ kubectl apply -f kubernetes/service.yaml
service "thoughts-service" configured
$ kubectl get service -n example
NAME CLUSTER-IP EXTERNAL-IP PORT(S) AGE
thoughts-service 10.100.252.250 <nodes> 80:31600/TCP 1m
```

我们可以通过访问所描述的 pod 的本地主机来访问 Thoughts Backend。在这种情况下，`http://127.0.0.1:31600`：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-dkr-msvc-py/img/4281d880-2b90-4375-b757-16fca37b7c00.png)

服务为我们提供了内部名称，但是如果我们想要控制它如何在外部暴露，我们需要配置 Ingress。

# 配置 Ingress

最后，我们在`ingress.yaml`中描述 Ingress（[`github.com/PacktPublishing/Hands-On-Docker-for-Microservices-with-Python/blob/master/Chapter06/thoughts_backend/kubernetes/ingress.yaml`](https://github.com/PacktPublishing/Hands-On-Docker-for-Microservices-with-Python/blob/master/Chapter06/thoughts_backend/kubernetes/ingress.yaml)）。文件在此处复制。注意我们如何设置元数据以存储在正确的命名空间中：

```py
---
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
    name: thoughts-backend-ingress
    namespace: example
spec:
    rules:
        - host: thoughts.example.local
          http:
            paths:
              - backend:
                  serviceName: thoughts-service
                  servicePort: 80
                path: /
```

此 Ingress 将使服务在端口`80`上暴露给节点。由于多个服务可以在同一节点上暴露，它们通过主机名进行区分，在本例中为`thoughts.example.local`。

我们使用的 Ingress 控制器只允许在`servicePort`中暴露端口`80`（HTTP）和`443`（HTTPS）。

应用服务后，我们可以尝试访问页面，但是，除非我们将调用指向正确的主机，否则我们将收到 404 错误：

```py
$ kubectl apply -f kubernetes/ingress.yaml
ingress "thoughts-backend-ingress" created
$ kubectl get ingress -n example
NAME                     HOSTS                  ADDRESS  PORTS  AGE
thoughts-backend-ingress thoughts.example.local localhost 80 1m
$ curl http://localhost
<html>
<head><title>404 Not Found</title></head>
<body>
<center><h1>404 Not Found</h1></center>
<hr><center>nginx/1.15.8</center>
</body>
</html>
```

我们需要能够将任何请求指向`thoughts.example.local`到我们的本地主机。在 Linux 和 macOS 中，最简单的方法是更改您的`/etc/hosts`文件，包括以下行：

```py
127.0.0.1 thoughts.example.local
```

然后，我们可以使用浏览器检查我们的应用程序，这次是在`http://thoughts.example.local`（端口`80`）：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-dkr-msvc-py/img/ce2705b4-0075-4086-9b08-df80806271e5.png)

定义不同的主机条目允许我们外部访问所有服务，以便能够调整它们并调试问题。我们将以相同的方式定义其余的 Ingresses。

如果在运行`kubectl get ingress -n example`时出现`Connection refused`错误，并且单词`localhost`没有出现，那么您的 Kubernetes 安装没有安装 Ingress 控制器。请仔细检查安装文档[`github.com/kubernetes/ingress-nginx/blob/master/docs/deploy/index.md.`](https://github.com/kubernetes/ingress-nginx/blob/master/docs/deploy/index.md)

所以现在我们在 Kubernetes 中本地部署了一个可工作的应用程序！

# 在本地部署完整系统

我们的每个微服务都可以独立运行，但是要使整个系统工作，我们需要部署这三个（Thoughts 后端、用户后端和前端）并将它们连接在一起。特别是前端需要其他两个微服务正在运行。使用 Kubernetes，我们可以在本地部署它。

要部署完整系统，我们需要先部署用户后端，然后是前端。我们将描述这些系统的每一个，将它们与已部署的 Thoughts 后端相关联，我们之前看到如何部署它。

# 部署用户后端

用户后端文件与 Thoughts 后端非常相似。您可以在 GitHub 存储库中检查它们（[`github.com/PacktPublishing/Hands-On-Docker-for-Microservices-with-Python/tree/master/Chapter06/users_backend/kubernetes`](https://github.com/PacktPublishing/Hands-On-Docker-for-Microservices-with-Python/tree/master/Chapter06/users_backend/kubernetes)）。确保`deployment.yaml`中的环境设置值是正确的：

```py
$ kubectl apply -f users_backend/kubernetes/deployment.yaml
deployment "users-backend" created
$ kubectl apply -f users_backend/kubernetes/service.yaml
service "users-service" created
$ kubectl apply -f users_backend/kubernetes/ingress.yaml
ingress "users-backend-ingress" created
```

记得确保在`/etc/hosts`中包含新的主机名：

```py
127.0.0.1 users.example.local
```

您可以在`http://users.example.local`访问用户后端。

# 添加前端

前端服务和 Ingress 与先前的非常相似。部署略有不同。让我们分三组查看配置：

1.  首先，我们添加关于`namespace`、`name`和`kind`（deployment）的元数据，如下面的代码所示：

```py
---
apiVersion: apps/v1
kind: Deployment
metadata:
    name: frontend
    labels:
        app: frontend
    namespace: example
```

1.  然后，我们使用模板和`replicas`的数量定义`spec`。对于本地系统来说，一个副本就可以了：

```py
spec:
    replicas: 1
    selector:
        matchLabels:
            app: frontend
    template:
        metadata:
            labels:
                app: frontend
```

1.  最后，我们使用容器定义`spec`模板：

```py
        spec:
            containers:
                - name: frontend-service
                  image: thoughts_frontend:latest
                  imagePullPolicy: Never
                  ports:
                     - containerPort: 8000
                  env:
                      - name: THOUGHTS_BACKEND_URL
                        value: http://thoughts-service
                      - name: USER_BACKEND_URL
                        value: http://users-service
```

与先前定义的 Thoughts 后端部署的主要区别在于只有一个容器，而且它上面的环境更简单。

我们将后端 URL 环境定义为服务端点。这些端点在集群内可用，因此它们将被定向到适当的容器。

请记住，`*.example.local`地址仅在您的计算机上可用，因为它们只存在于`/etc/hosts`中。在容器内，它们将不可用。

这适用于本地开发，但另一种选择是拥有一个可以重定向到`127.0.0.1`或类似地址的 DNS 域。

我们应该在`/etc/hosts`文件中添加一个新的域名：

```py
127.0.0.1 frontend.example.local
```

Django 要求您设置`ALLOWED_HOSTS`设置的值，以允许它接受主机名，因为默认情况下它只允许从 localhost 进行连接。有关更多信息，请参阅 Django 文档([`docs.djangoproject.com/en/2.2/ref/settings/#allowed-hosts`](https://docs.djangoproject.com/en/2.2/ref/settings/#allowed-hosts))。为了简化事情，我们可以使用`'*'`来允许任何主机。在 GitHub 上查看代码([`github.com/PacktPublishing/Hands-On-Docker-for-Microservices-with-Python/blob/master/Chapter06/frontend/mythoughts/mythoughts/settings.py#L28`](https://github.com/PacktPublishing/Hands-On-Docker-for-Microservices-with-Python/blob/master/Chapter06/frontend/mythoughts/mythoughts/settings.py#L28))。

在生产中，将主机限制为**完全限定域名**（**FQDN**），主机的完整 DNS 名称是一个良好的做法，但 Kubernetes Ingress 将检查主机头并在不正确时拒绝它。

前端应用程序将像以前一样部署：

```py
$ kubectl apply -f frontend/kubernetes/deployment.yaml
deployment "frontend" created
$ kubectl apply -f frontend/kubernetes/service.yaml
service "frontend-service" created
$ kubectl apply -f frontend/kubernetes/ingress.yaml
ingress "frontend-ingress" created
```

然后我们可以访问整个系统，登录，搜索等。

记住有两个用户，`bruce`和`stephen`。他们的密码与他们的用户名相同。您无需登录即可搜索。

在浏览器中，转到`http://frontend.example.local/`：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-dkr-msvc-py/img/b45ab968-9029-4a8b-9c2a-7571d2057c07.png)

恭喜！您拥有一个工作的 Kubernetes 系统，包括不同的部署的微服务。您可以独立访问每个微服务以进行调试或执行操作，例如创建新用户等。

如果需要部署新版本，请使用`docker-compose`构建适当的容器并删除 pod 以强制重新创建它。

# 总结

在本章中，我们看到了如何在 Kubernetes 本地集群中部署我们的微服务，以允许本地开发和测试。在本地计算机上部署整个系统大大简化了开发新功能或调试系统行为的过程。生产环境将非常相似，因此这也为其奠定了基础。

我们首先描述了两个缺失的微服务。用户后端处理用户的身份验证，前端是第一章中介绍的单体的修改版本，*进行移动-设计，计划和执行*，它连接到两个后端。我们展示了如何以`docker-compose`的方式构建和运行它们。

之后，我们描述了如何设置一组`.yaml`文件来在 Kubernetes 中正确配置应用程序。每个微服务都有自己的部署来定义可用的 pod，一个服务来定义一个稳定的访问点，以及一个 Ingress 来允许外部访问。我们对它们进行了详细描述，然后将它们应用到所有的微服务上。

在下一章中，我们将看到如何从本地部署转移到部署准备好生产的 Kubernetes 集群。

# 问题

1.  我们正在部署的三个微服务是什么？

1.  哪个微服务需要其他两个可用？

1.  为什么我们需要在运行`docker-compose`时使用外部 IP 来连接微服务？

1.  每个应用程序所需的主要 Kubernetes 对象是什么？

1.  有哪些对象是不必要的？

1.  如果我们将任何微服务扩展到多个 pod，您能看到任何问题吗？

1.  为什么我们要使用`/etc/hosts`文件？

# 进一步阅读

您可以在书籍《Kubernetes for Developers》（[`www.packtpub.com/eu/virtualization-and-cloud/kubernetes-developers`](https://www.packtpub.com/eu/virtualization-and-cloud/kubernetes-developers)）和《Kubernetes Cookbook - Second Edition》（[`www.packtpub.com/in/virtualization-and-cloud/kubernetes-cookbook-second-edition`](https://www.packtpub.com/in/virtualization-and-cloud/kubernetes-cookbook-second-edition)）中了解更多关于 Kubernetes 的信息。


# 第七章：配置和保护生产系统

生产（来自生产环境）是描述主要系统的常用名称-为真实客户提供服务的系统。这是公司中可用的主要环境。它也可以被称为**live**。该系统需要在互联网上公开可用，这也使得安全性和可靠性成为重要的优先事项。在本章中，我们将看到如何为生产部署 Kubernetes 集群。

我们将看到如何使用第三方提供商 Amazon Web Services（AWS）来设置一个，以及为什么自己创建是一个坏主意。我们将在这个新部署中部署我们的系统，并将查看如何设置负载均衡器以有序地将流量从旧的单体系统转移到新系统。

我们还将看到如何自动扩展 Kubernetes 集群内的 Pod 和节点，以使资源适应需求。

本章将涵盖以下主题：

+   在野外使用 Kubernetes

+   设置 Docker 注册表

+   创建集群

+   使用 HTTPS 和 TLS 保护外部访问

+   为迁移到微服务做好准备

+   自动扩展集群

+   顺利部署新的 Docker 镜像

我们还将介绍一些良好的实践方法，以确保我们的部署尽可能顺利和可靠地部署。到本章结束时，您将在一个公开可用的 Kubernetes 集群中部署系统。

# 技术要求

我们将在本书中的示例中使用 AWS 作为我们的云供应商。我们需要安装一些实用程序以从命令行进行交互。查看如何在此文档中安装 AWS CLI 实用程序（[`aws.amazon.com/cli/`](https://aws.amazon.com/cli/)）。此实用程序允许从命令行执行 AWS 任务。

为了操作 Kubernetes 集群，我们将使用`eksctl`。查看此文档（[`eksctl.io/introduction/installation/`](https://eksctl.io/introduction/installation/)）以获取安装说明。

您还需要安装`aws-iam-authenticator`。您可以在此处查看安装说明（[`docs.aws.amazon.com/eks/latest/userguide/install-aws-iam-authenticator.html`](https://docs.aws.amazon.com/eks/latest/userguide/install-aws-iam-authenticator.html)）。

本章的代码可以在 GitHub 的此链接找到：[`github.com/PacktPublishing/Hands-On-Docker-for-Microservices-with-Python/tree/master/Chapter07`](https://github.com/PacktPublishing/Hands-On-Docker-for-Microservices-with-Python/tree/master/Chapter07)。

确保您的计算机上安装了`ab`（Apache Bench）。它与 Apache 捆绑在一起，并且在 macOS 和一些 Linux 发行版中默认安装。您可以查看这篇文章：[`www.petefreitag.com/item/689.cfm`](https://www.petefreitag.com/item/689.cfm)。

# 在野外使用 Kubernetes

在部署用于生产的集群时，最好的建议是使用商业服务。所有主要的云提供商（AWS EKS，Google Kubernetes Engine（GKE）和 Azure Kubernetes Service（AKS））都允许您创建托管的 Kubernetes 集群，这意味着唯一需要的参数是选择物理节点的数量和类型，然后通过`kubectl`访问它。

在本书的示例中，我们将使用 AWS，但请查看其他提供商的文档，以确定它们是否更适合您的用例。

Kubernetes 是一个抽象层，因此这种操作方式非常方便。定价类似于支付原始实例以充当节点服务器，并且无需安装和管理 Kubernetes 控制平面，因此实例充当 Kubernetes 节点。

值得再次强调：除非您有非常充分的理由，*不要部署自己的 Kubernetes 集群*；而是使用云提供商的服务。这样做会更容易，并且可以节省大量的维护成本。配置 Kubernetes 节点以实现高性能并实施良好的实践以避免安全问题并不是一件简单的事情。

如果您拥有自己的内部数据中心，则可能无法避免创建自己的 Kubernetes 集群，但在其他任何情况下，直接使用已知云提供商管理的集群更有意义。可能您当前的提供商已经为托管的 Kubernetes 提供了服务！

# 创建 IAM 用户

AWS 使用不同的用户来授予它们多个角色。它们具有不同的权限，使用户能够执行操作。在 AWS 的命名约定中，这个系统称为**身份和访问管理**（**IAM**）。

根据您的设置以及 AWS 在您的组织中的使用方式，创建适当的 IAM 用户可能会相当复杂。查阅文档（[`docs.aws.amazon.com/IAM/latest/UserGuide/id_users_create.html`](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_users_create.html)），并找到负责处理 AWS 的人员，并与他们核实所需的步骤。

让我们看看创建 IAM 用户的步骤：

1.  如果尚未创建具有适当权限的 AWS 用户，则需要创建。确保它能够通过激活程序化访问来访问 API，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-dkr-msvc-py/img/cedad3a8-ea90-4541-9f22-c5605c90b77e.png)

这将显示其访问密钥、秘密密钥和密码。请务必将它们安全地存储起来。

1.  要通过命令行访问，您需要使用 AWS CLI。使用 AWS CLI 和访问信息，配置您的命令行以使用`aws`：

```py
$ aws configure
AWS Access Key ID [None]: <your Access Key>
AWS Secret Access Key [None]: <your Secret Key>
Default region name [us-west-2]: <EKS region>
Default output format [None]:
```

您应该能够通过以下命令获取身份以检查配置是否成功：

```py
$ aws sts get-caller-identity
{
 "UserId": "<Access Key>",
 "Account": "<account ID>",
 "Arn": "arn:aws:iam::XXXXXXXXXXXX:user/jaime"
}
```

现在您可以访问命令行 AWS 操作。

请记住，IAM 用户可以根据需要创建更多密钥，撤销现有密钥等。这通常由负责 AWS 安全的管理员用户处理。您可以在亚马逊文档中阅读更多信息（[`docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html#Using_CreateAccessKey_API`](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html#Using_CreateAccessKey_API)）。密钥轮换是一个不错的主意，以确保旧密钥被废弃。您可以通过`aws`客户端界面执行此操作。

我们将使用 Web 控制台进行一些操作，但其他操作需要使用`aws`。

# 设置 Docker 注册表

我们需要能够访问存储要部署的图像的 Docker 注册表。确保 Docker 注册表可访问的最简单方法是使用相同服务中的 Docker 注册表。

您仍然可以使用 Docker Hub 注册表，但是在同一云提供商中使用注册表通常更容易，因为它集成得更好。这也有助于身份验证方面。

我们需要使用以下步骤配置**弹性容器注册表**（**ECR**）：

1.  登录 AWS 控制台并搜索 Kubernetes 或 ECR：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-dkr-msvc-py/img/29d9a38c-01d7-4df5-b22d-f0df643270b2.png)

1.  创建名为`frontend`的新注册表。它将创建一个完整的 URL，您需要复制：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-dkr-msvc-py/img/17c47ce3-fa05-48a7-aa03-48efcdc28818.png)

1.  我们需要使本地`docker`登录注册表。请注意，`aws ecr get-login`将返回一个`docker`命令，该命令将使您登录，因此请复制并粘贴：

```py
$ aws ecr get-login --no-include-email
<command>
$ docker login -u AWS -p <token>
Login Succeeded
```

1.  现在我们可以使用完整的注册表名称标记要推送的图像，并将其推送：

```py
$ docker tag thoughts_frontend 033870383707.dkr.ecr.us-west-2.amazonaws.com/frontend
$ docker push 033870383707.dkr.ecr.us-west-2.amazonaws.com/frontend
The push refers to repository [033870383707.dkr.ecr.us-west-2.amazonaws.com/frontend]
...
latest: digest: sha256:21d5f25d59c235fe09633ba764a0a40c87bb2d8d47c7c095d254e20f7b437026 size: 2404
```

1.  镜像已推送！您可以通过在浏览器中打开 AWS 控制台来检查：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-dkr-msvc-py/img/bed774ba-ff0f-45bc-aefa-38ed3337de56.png)

1.  我们需要重复这个过程，以推送用户后端和思想后端。

我们使用两个容器的设置来部署用户后端和想法后端，其中包括一个用于服务，另一个用于易失性数据库。这是为了演示目的而做的，但不会是生产系统的配置，因为数据需要是持久的。

在本章的最后，有一个关于如何处理这种情况的问题。一定要检查一下！

所有不同的注册表都将被添加。您可以在浏览器的 AWS 控制台中查看它们：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-dkr-msvc-py/img/cb2a0221-97f4-427d-beab-1bcc17c237e1.png)

我们的流水线需要适应推送到这些存储库。

在部署中的一个良好的做法是进行一个称为**推广**的特定步骤，其中准备用于生产的镜像被复制到一个特定的注册表，降低了错误地在生产中部署坏镜像的机会。

这个过程可能需要多次进行，以在不同的环境中推广镜像。例如，在一个暂存环境中部署一个版本。运行一些测试，如果它们正确，推广版本，将其复制到生产注册表并标记为在生产环境中部署的好版本。

这个过程可以在不同的提供商中使用不同的注册表进行。

我们需要在我们的部署中使用完整 URL 的名称。

# 创建集群

为了使我们的代码在云中可用并且可以公开访问，我们需要设置一个工作的生产集群，这需要两个步骤：

1.  在 AWS 云中创建 EKS 集群（这使您能够运行在此云集群中操作的`kubectl`命令）。

1.  部署您的服务，使用一组`.yaml`文件，就像我们在之前的章节中看到的那样。这些文件需要进行最小的更改以适应云环境。

让我们来检查第一步。

# 创建 Kubernetes 集群

创建集群的最佳方式是使用`eksctl`实用程序。这将为我们自动化大部分工作，并且允许我们以后进行扩展。

请注意，EKS 只在一些地区可用，而不是所有地区。检查 AWS 区域表（[`aws.amazon.com/about-aws/global-infrastructure/regional-product-services/`](https://aws.amazon.com/about-aws/global-infrastructure/regional-product-services/)）以查看可用的区域。我们将使用俄勒冈（`us-west-2`）地区。

要创建 Kubernetes 集群，让我们采取以下步骤：

1.  首先，检查`eksctl`是否正确安装：

```py
$ eksctl get clusters
No clusters found
```

1.  创建一个新的集群。这将需要大约 10 分钟：

```py
$ eksctl create cluster -n Example
[i] using region us-west-2
[i] setting availability zones to [us-west-2d us-west-2b us-west-2c]
...
[✔]  EKS cluster "Example" in "us-west-2" region is ready

```

1.  这将创建集群。检查 AWS web 界面将显示新配置的元素。

需要添加`--arg-access`选项以创建一个能够自动扩展的集群。这将在*自动扩展集群*部分中进行更详细的描述。

1.  `eksctl create`命令还会添加一个包含有关远程 Kubernetes 集群信息的新上下文，并激活它，因此`kubectl`现在将指向这个新集群。

请注意，`kubectl`有上下文的概念，作为它可以连接的不同集群。您可以通过运行`kubectl config get-contexts`和`kubectl config use-context <context-name>`来查看所有可用的上下文，以更改它们。请查看 Kubernetes 文档（[`kubernetes.io/docs/tasks/access-application-cluster/configure-access-multiple-clusters/`](https://kubernetes.io/docs/tasks/access-application-cluster/configure-access-multiple-clusters/)）以了解如何手动创建新的上下文。

1.  这个命令设置了`kubectl`以正确的上下文来运行命令。默认情况下，它生成一个具有两个节点的集群：

```py
$ kubectl get nodes
NAME                    STATUS ROLES AGE VERSION
ip-X.us-west-2.internal Ready <none> 11m v1.13.7-eks-c57ff8
ip-Y.us-west-2.internal Ready <none> 11m v1.13.7-eks-c57ff8
```

1.  我们可以扩展节点的数量。为了减少资源使用和节省金钱。我们需要检索节点组的名称，它控制节点的数量，然后缩减它：

```py
$ eksctl get nodegroups --cluster Example
CLUSTER NODEGROUP CREATED MIN SIZE MAX SIZE DESIRED CAPACITY INSTANCE TYPE IMAGE ID
Example ng-fa5e0fc5 2019-07-16T13:39:07Z 2 2 0 m5.large ami-03a55127c613349a7
$ eksctl scale nodegroup --cluster Example --name ng-fa5e0fc5 -N 1
[i] scaling nodegroup stack "eksctl-Example-nodegroup-ng-fa5e0fc5" in cluster eksctl-Example-cluster
[i] scaling nodegroup, desired capacity from to 1, min size from 2 to 1
```

1.  您可以通过`kubectl`联系集群并正常进行操作：

```py
$ kubectl get svc
NAME TYPE CLUSTER-IP EXTERNAL-IP PORT(S) AGE
kubernetes ClusterIP 10.100.0.1 <none> 443/TCP 7m31s
```

集群已经设置好了，我们可以从命令行上对其进行操作。

创建 EKS 集群可以以许多方式进行调整，但是 AWS 在访问、用户和权限方面可能会变化无常。例如，集群喜欢有一个 CloudFormation 规则来处理集群，并且所有元素应该由相同的 IAM 用户创建。与您组织中负责基础架构定义的任何人核对，以确定正确的配置是什么。不要害怕进行测试，集群可以通过`eksctl`配置或 AWS 控制台快速删除。

此外，`eksctl`会在不同的可用区（AWS 同一地理区域内的隔离位置）中创建集群节点，以尽量减少因 AWS 数据中心出现问题而导致整个集群宕机的风险。

# 配置云 Kubernetes 集群

下一阶段是在 EKS 集群上运行我们的服务，以便在云中可用。我们将使用`.yaml`文件作为基础，但需要进行一些更改。

查看 GitHub `Chapter07`（[`github.com/PacktPublishing/Hands-On-Docker-for-Microservices-with-Python/tree/master/Chapter07`](https://github.com/PacktPublishing/Hands-On-Docker-for-Microservices-with-Python/tree/master/Chapter07)）子目录中的文件。

我们将看到与上一章中的 Kubernetes 配置文件的不同，然后在*部署系统*部分部署它们。

# 配置 AWS 镜像注册表

第一个区别是我们需要将镜像更改为完整的注册表，以便集群使用 ECS 注册表中可用的镜像。

请记住，您需要在 AWS 内部指定注册表，以便 AWS 集群可以正确访问它。

例如，在`frontend/deployment.yaml`文件中，我们需要以这种方式定义它们：

```py
containers:
- name: frontend-service
  image: XXX.dkr.ecr.us-west-2.amazonaws.com/frontend:latest
  imagePullPolicy: Always
```

镜像应该从 AWS 注册表中拉取。拉取策略应更改为强制从集群中拉取。

在创建`example`命名空间后，您可以通过应用文件在远程服务器上部署：

```py
$ kubectl create namespace example
namespace/example created
$ kubectl apply -f frontend/deployment.yaml
deployment.apps/frontend created
```

过一会儿，部署会创建 pod：

```py
$ kubectl get pods -n example
NAME                      READY STATUS  RESTARTS AGE
frontend-58898587d9-4hj8q 1/1   Running 0        13s
```

现在我们需要更改其余的元素。所有部署都需要适应包括正确注册表。

在 GitHub 上检查所有`deployment.yaml`文件的代码。

# 配置使用外部可访问负载均衡器

第二个区别是使前端服务可以在外部访问，以便互联网流量可以访问集群。

这很容易通过将服务从`NodePort`更改为`LoadBalancer`来完成。检查`frontend/service.yaml`文件：

```py
apiVersion: v1
kind: Service
metadata:
    namespace: example
    labels:
        app: frontend-service
    name: frontend-service
spec:
    ports:
        - name: frontend
          port: 80
          targetPort: 8000
    selector:
        app: frontend
    type: LoadBalancer
```

这将创建一个可以外部访问的新**弹性负载均衡器**（**ELB**）。现在，让我们开始部署。

# 部署系统

整个系统可以从`Chapter07`子目录中部署，使用以下代码：

```py
$ kubectl apply --recursive -f .
deployment.apps/frontend unchanged
ingress.extensions/frontend created
service/frontend-service created
deployment.apps/thoughts-backend created
ingress.extensions/thoughts-backend-ingress created
service/thoughts-service created
deployment.apps/users-backend created
ingress.extensions/users-backend-ingress created
service/users-service created
```

这些命令会迭代地通过子目录并应用任何`.yaml`文件。

几分钟后，您应该看到一切都正常运行：

```py
$ kubectl get pods -n example
NAME                              READY STATUS  RESTARTS AGE
frontend-58898587d9-dqc97         1/1   Running 0        3m
thoughts-backend-79f5594448-6vpf4 2/2   Running 0        3m
users-backend-794ff46b8-s424k     2/2   Running 0        3m
```

要获取公共访问点，您需要检查服务：

```py
$ kubectl get svc -n example
NAME             TYPE         CLUSTER-IP EXTERNAL-IP AGE
frontend-service LoadBalancer 10.100.152.177 a28320efca9e011e9969b0ae3722320e-357987887.us-west-2.elb.amazonaws.com 3m
thoughts-service NodePort 10.100.52.188 <none> 3m
users-service    NodePort 10.100.174.60 <none> 3m
```

请注意，前端服务有一个外部 ELB DNS 可用。

如果您在浏览器中输入该 DNS，可以访问服务如下：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-dkr-msvc-py/img/b27d1c74-f06d-4be2-b017-73f59bb4fa8d.png)

恭喜，您拥有自己的云 Kubernetes 服务。服务可访问的 DNS 名称不太好，因此我们将看到如何添加注册的 DNS 名称并在 HTTPS 端点下公开它。

# 使用 HTTPS 和 TLS 保护外部访问

为了向客户提供良好的服务，您的外部端点应通过 HTTPS 提供。这意味着您和客户之间的通信是私密的，不能在网络路由中被窃听。

HTTPS 的工作原理是服务器和客户端加密通信。为了确保服务器是他们所说的那样，需要有一个由授予 DNS 已验证的权威颁发的 SSL 证书。

请记住，HTTPS 的目的不是服务器本身是可信的，而是客户端和服务器之间的通信是私密的。服务器仍然可能是恶意的。这就是验证特定 DNS 不包含拼写错误的重要性。

您可以在这本奇妙的漫画中获取有关 HTTPS 如何运作的更多信息：[`howhttps.works/`](https://howhttps.works/)。

获取外部端点的证书需要两个阶段：

+   您拥有特定的 DNS 名称，通常是通过从域名注册商购买获得的。

+   您通过认可的**证书颁发机构**（**CA**）获得 DNS 名称的唯一证书。 CA 必须验证您控制 DNS 名称。

为了促进 HTTPS 的使用，非营利性组织*Let's Encrypt*（[`letsencrypt.org`](https://letsencrypt.org)）提供有效期为 60 天的免费证书。这将比通过云服务提供商获得证书更费力，但如果资金紧张，这可能是一个选择。

这些天，这个过程非常容易通过云服务提供商来完成，因为它们可以同时充当两者，简化流程。

需要通过 HTTPS 进行通信的重要元素是我们网络的边缘。我们自己的微服务在内部网络中进行通信时不需要使用 HTTPS，HTTP 就足够了。但它需要是一个不受公共干扰的私有网络。

按照我们的例子，AWS 允许我们创建并将证书与 ELB 关联，以 HTTP 提供流量。

让 AWS 提供 HTTPS 流量可以确保我们使用最新和最安全的安全协议，例如**传输层安全性**（**TLS**）v1.3（撰写时的最新版本），但也保持与旧协议的向后兼容性，例如 SSL。

换句话说，默认情况下使用最安全的环境是最佳选择。

设置 HTTPS 的第一步是直接从 AWS 购买 DNS 域名，或将控制权转移到 AWS。这可以通过他们的 Route 53 服务完成。您可以在[`aws.amazon.com/route53/`](https://aws.amazon.com/route53/)上查看文档。

严格来说，不需要将您的 DNS 转移到亚马逊，只要您可以将其指向外部 ELB，但这有助于集成和获取证书。在创建证书时，您需要证明自己拥有 DNS 记录，使用 AWS 可以简化此过程，因为他们会为他们控制的 DNS 记录创建证书。请查看[`docs.aws.amazon.com/acm/latest/userguide/gs-acm-validate-dns.html`](https://docs.aws.amazon.com/acm/latest/userguide/gs-acm-validate-dns.html)上的文档。

要在 ELB 上启用 HTTPS 支持，请查看以下步骤：

1.  转到 AWS 控制台中的监听器：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-dkr-msvc-py/img/fa6eb258-65a0-4953-a49c-4f0ac559524f.png)

1.  单击“编辑”并添加 HTTPS 支持的新规则：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-dkr-msvc-py/img/9bceff02-8ad6-4194-8315-75ea59238415.png)

1.  如您所见，它将需要 SSL 证书。单击“更改”以进行管理：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-dkr-msvc-py/img/c0378dc3-fd4b-4c3a-ab55-11a07af6a74d.png)

1.  从这里，您可以添加现有证书或从亚马逊购买证书。

务必查看亚马逊负载均衡器的文档。有几种类型的 ELB 可供使用，根据您的用例，一些 ELB 具有与其他 ELB 不同的功能。例如，一些新的 ELB 能够在客户端请求 HTTP 数据时重定向到 HTTPS。请查看[`aws.amazon.com/elasticloadbalancing/`](https://aws.amazon.com/elasticloadbalancing/)上的文档。

恭喜，现在您的外部端点支持 HTTPS，确保您与客户的通信是私密的。

# 准备好迁移到微服务

为了在进行迁移时顺利运行，您需要部署一个负载均衡器，它可以让您快速在后端之间切换并保持服务运行。

正如我们在第一章中讨论的那样，*进行移动-设计、计划和执行*，HAProxy 是一个很好的选择，因为它非常灵活，并且有一个很好的 UI，可以让您通过单击网页上的按钮快速进行操作。它还有一个出色的统计页面，可以让您监视服务的状态。

AWS 有一个名为**应用负载均衡器**（**ALB**）的 HAProxy 替代方案。这是 ELB 的功能丰富更新，允许您将不同的 HTTP 路径路由到不同的后端服务。

HAProxy 具有更丰富的功能集和更好的仪表板与之交互。它也可以通过配置文件进行更改，这有助于控制更改，正如我们将在第八章中看到的那样，*使用 GitOps 原则*。

显然，只有在所有服务都在 AWS 上可用时才能使用，但在这种情况下，它可能是一个很好的解决方案，因为它将更简单并且更符合技术堆栈的其余部分。查看文档：[`aws.amazon.com/blogs/aws/new-aws-application-load-balancer/`](https://aws.amazon.com/blogs/aws/new-aws-application-load-balancer/)。

要在服务前部署负载均衡器，我建议不要在 Kubernetes 上部署它，而是以与传统服务相同的方式运行它。这种类型的负载均衡器将是系统的关键部分，消除不确定性对于成功运行是很重要的。它也是一个相对简单的服务。

请记住，负载均衡器需要正确复制，否则它将成为单点故障。亚马逊和其他云提供商允许您设置 ELB 或其他类型的负载均衡器，以便将流量平衡在它们之间。

举例来说，我们创建了一个示例配置和`docker-compose`文件来快速运行它，但配置可以按照团队最舒适的方式进行设置。

# 运行示例

代码可在 GitHub 上找到（[`github.com/PacktPublishing/Hands-On-Docker-for-Microservices-with-Python/tree/master/Chapter07/haproxy`](https://github.com/PacktPublishing/Hands-On-Docker-for-Microservices-with-Python/tree/master/Chapter07/haproxy)）。我们从 Docker Hub 中的 HAProxy Docker 镜像继承（[`hub.docker.com/_/haproxy/`](https://hub.docker.com/_/haproxy/)），添加我们自己的配置文件。

让我们来看看配置文件`haproxy.cfg`中的主要元素：

```py
frontend haproxynode
    bind *:80
    mode http
    default_backend backendnodes

backend backendnodes
    balance roundrobin
    option forwardfor
    server aws a28320efca9e011e9969b0ae3722320e-357987887
               .us-west-2.elb.amazonaws.com:80 check
    server example www.example.com:80 check

listen stats
    bind *:8001
    stats enable
    stats uri /
    stats admin if TRUE
```

我们定义了一个前端，接受任何端口`80`的请求，并将请求发送到后端。后端将请求平衡到两个服务器，`example`和`aws`。基本上，`example`指向`www.example.com`（您的旧服务的占位符），`aws`指向先前创建的负载均衡器。

我们在端口`8001`上启用统计服务器，并允许管理员访问。

`docker-compose`配置启动服务器，并将本地端口转发到容器端口`8000`（负载均衡器）和`8001`（统计）。使用以下命令启动它：

```py
$ docker-compose up --build proxy
...
```

现在我们可以访问`localhost:8000`，它将在`thoughts`服务和 404 错误之间交替。

通过这种方式调用`example.com`时，我们正在转发主机请求。这意味着我们发送一个请求，请求`Host:localhost`到`example.com`，它返回一个 404 错误。请确保检查您的服务，所有后端都接受相同的主机信息。

打开统计页面查看设置：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-dkr-msvc-py/img/50260323-0ec3-4f15-a91e-3e66ece92b0e.png)

检查后端节点中的`aws`和`example`条目。还有很多有趣的信息，比如请求数量、最后连接、数据等等。

您可以在检查`example`后端时执行操作，然后在下拉菜单中将状态设置为 MAINT。应用后，`example`后端将处于维护模式，并从负载均衡器中移除。统计页面如下：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-dkr-msvc-py/img/c4ee4c3e-ae10-4597-b4ff-f3ec513ce6ee.png)

现在在`localhost:8000`中访问负载均衡器只会返回**thoughts**前端。您可以重新启用后端，将其设置为 READY 状态。

有一种称为 DRAIN 的状态，它将停止新会话进入所选服务器，但现有会话将继续。这在某些配置中可能很有趣，但如果后端真正是无状态的，直接转移到 MAINT 状态就足够了。

HAProxy 也可以配置使用检查来确保后端可用。在示例中，我们添加了一个被注释的检查，它发送一个 HTTP 命令来检查返回。

```py
option httpchk HEAD / HTTP/1.1\r\nHost:\ example.com
```

检查将对两个后端相同，因此需要成功返回。默认情况下，它将每隔几秒运行一次。

您可以在[`www.haproxy.org/`](http://www.haproxy.org/)上查看完整的 HAProxy 文档。有很多可以配置的细节。与您的团队跟进，确保像超时、转发标头等区域的配置是正确的。

健康检查的概念也用于 Kubernetes，以确保 Pod 和容器准备好接受请求并保持稳定。我们将在下一节中看到如何确保正确部署新镜像。

# 平稳部署新的 Docker 镜像

在生产环境中部署服务时，确保其能够平稳运行以避免中断服务至关重要。

Kubernetes 和 HAProxy 能够检测服务是否正常运行，并在出现问题时采取行动，但我们需要提供一个充当健康检查的端点，并配置它以定期被 ping，以便及早发现问题。

为简单起见，我们将使用根 URL 作为健康检查，但我们可以设计特定的端点进行测试。一个良好的健康检查应该检查服务是否按预期工作，但是轻便快速。避免过度测试或执行外部验证，这可能会使端点花费很长时间。

返回空响应的 API 端点是一个很好的例子，因为它检查整个管道系统是否正常工作，但回答非常快。

在 Kubernetes 中，有两个测试来确保 Pod 正常工作，即就绪探针和活动探针。

# 活动探针

活动探针检查容器是否正常工作。它是在容器中启动的返回正确的进程。如果返回错误（或更多，取决于配置），Kubernetes 将终止容器并重新启动。

活动探针将在容器内执行，因此需要有效。对于 Web 服务，添加`curl`命令是一个好主意：

```py
spec:
  containers:
  - name: frontend-service
    livenessProbe:
      exec:
        command:
        - curl
        - http://localhost:8000/
        initialDelaySeconds: 5
        periodSeconds: 30
```

虽然有一些选项，比如检查 TCP 端口是否打开或发送 HTTP 请求，但运行命令是最通用的选项。它也可以用于调试目的。请参阅文档以获取更多选项。

要小心对活动探针过于激进。每次检查都会给容器增加一些负载，因此根据负载情况，多个探针可能会导致杀死更多的容器。

如果您的服务经常被活动探针重新启动，要么探针太过激进，要么容器数量负载过高，或者两者兼而有之。

该探针配置为等待五秒，然后每 30 秒运行一次。默认情况下，连续三次失败的检查后，将重新启动容器。

# 就绪探针

就绪探针检查容器是否准备好接受更多请求。这是一个不那么激进的版本。如果测试返回错误或超时，容器不会重新启动，而只会被标记为不可用。

就绪探针通常用于避免过早接受请求，但它会在启动后运行。一个智能的就绪探针可以标记容器何时达到最大容量，无法接受更多请求，但通常配置类似于活跃探针的探针就足够了。

就绪探针在部署配置中定义，方式与活跃探针相同。让我们来看一下：

```py
spec:
  containers:
  - name: frontend-service
    readinessProbe:
      exec:
        command:
        - curl
        - http://localhost:8000/
        initialDelaySeconds: 5
        periodSeconds: 10
```

就绪探针应该比活跃探针更积极，因为结果更安全。这就是为什么`periodSeconds`更短。根据您的特定用例，您可能需要两者或者不需要，但就绪探针是启用滚动更新所必需的，接下来我们将看到。

示例代码中的`frontend/deployment.yaml`部署包括了两个探针。查看 Kubernetes 文档（[`kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/`](https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/)）以获取更多详细信息和选项。

请注意，这两个探针用于不同的目标。就绪探针延迟请求的输入，直到 Pod 准备就绪，而活跃探针有助于处理卡住的容器。

延迟的活跃探针返回将重新启动 Pod，因此负载的增加可能会产生重新启动 Pod 的级联效应。相应地进行调整，并记住两个探针不需要重复相同的命令。

就绪探针和活跃探针都帮助 Kubernetes 控制 Pod 的创建方式，这影响了部署的更新。

# 滚动更新

默认情况下，每次我们更新部署的镜像时，Kubernetes 部署将重新创建容器。

通知 Kubernetes 新版本可用并不足以将新镜像推送到注册表，即使标签相同。您需要更改部署`.yaml`文件中`image`字段中描述的标签。

我们需要控制图像的变化方式。为了不中断服务，我们需要执行滚动更新。这种更新方式会添加新的容器，等待它们就绪，将它们添加到池中，并移除旧的容器。这种部署比移除所有容器并重新启动它们要慢一些，但它允许服务不中断。

如何执行这个过程可以通过调整部署中的`strategy`部分来配置：

```py
spec:
    replicas: 4
    strategy:
      type: RollingUpdate
      rollingUpdate:
        maxUnavailable: 25%
        maxSurge: 1
```

让我们了解这段代码：

+   `strategy`和`type`可以是`RollingUpdate`（默认）或`Recreate`，后者会停止现有的 Pod 并创建新的 Pod。

+   `maxUnavailable`定义了更改期间不可用的最大 Pod 数量。这定义了新容器将被添加和旧容器将被移除的速度。它可以被描述为一个百分比，就像我们的例子，或者是一个固定的数字。

+   `maxSurge`定义了可以在期望 Pod 的限制之上创建的额外 Pod 的数量。这可以是一个特定的数字或者是总数的百分比。

+   当我们将`replicas`设置为`4`时，在两种情况下的结果都是一个 Pod。这意味着在更改期间，最多可以有一个 Pod 不可用，并且我们将逐个创建新的 Pod。

更高的数字将使更新速度更快，但会消耗更多资源（`maxSurge`）或在更新期间更积极地减少可用资源（`maxUnavailable`）。

对于少量的副本，要保守并在您对流程更加熟悉并且有更多资源时增加数量。

最初，手动扩展 Pod 将是最简单和最好的选择。如果流量变化很大，有高峰和低谷，那么自动扩展集群可能是值得的。

# 自动扩展集群

我们之前已经看到了如何为服务更改 Pod 的数量，以及如何添加和移除节点。这可以自动化地描述一些规则，允许集群弹性地改变其资源。

请记住，自动缩放需要调整以适应您的特定用例。如果资源利用率随时间发生很大变化，例如，如果某些小时的活动比其他小时多得多，或者如果有一种病毒元素意味着服务意外地将请求增加了 10 倍，那么这是一种使用技术。

如果您对服务器的使用量很小，并且利用率相对恒定，可能没有必要添加自动缩放。

集群可以在两个不同的方面自动扩展或缩小：

+   在 Kubernetes 配置中，pod 的数量可以自动增加或减少。

+   节点的数量可以在 AWS 中自动增加或减少。

pod 的数量和节点的数量都需要保持一致，以允许自然增长。

如果 pod 的数量增加而没有添加更多的硬件（节点），Kubernetes 集群将没有更多的容量，只是在不同分布中分配了相同的资源。

如果节点数量增加而没有创建更多的 pod，那么在某个时候，额外的节点将没有 pod 可分配，导致资源利用不足。另一方面，任何新添加的节点都会有相关成本，因此我们希望能够正确地使用它。

要能够自动缩放 pod，请确保它是可扩展的。要确保 pod 是可扩展的，请检查它是否是无状态的 Web 服务，并从外部源获取所有信息。

请注意，在我们的代码示例中，前端 pod 是可扩展的，而 Thoughts 和 Users Backend 不可扩展，因为它们包括自己的数据库容器，应用程序连接到该容器。

创建一个新的 pod 会创建一个新的空数据库，这不是预期的行为。这是有意为之的，以简化示例代码。预期的生产部署是，如前所述，连接到外部数据库。

Kubernetes 配置和 EKS 都具有根据规则更改 pod 和节点数量的功能。

# 创建 Kubernetes 水平 Pod 自动缩放器

在 Kubernetes 术语中，用于增加和减少 pod 的服务称为**水平 Pod 自动缩放器**（**HPA**）。

这是因为它需要一种检查测量以进行缩放的方法。要启用这些指标，我们需要部署 Kubernetes 度量服务器。

# 部署 Kubernetes 度量服务器

Kubernetes 度量服务器捕获内部低级别的指标，如 CPU 使用率，内存等。HPA 将捕获这些指标并使用它们来调整资源。

Kubernetes 度量服务器不是向 HPA 提供指标的唯一可用服务器，还可以定义其他度量系统。当前可用适配器的列表可在 Kubernetes 度量项目中找到（[`github.com/kubernetes/metrics/blob/master/IMPLEMENTATIONS.md#custom-metrics-api`](https://github.com/kubernetes/metrics/blob/master/IMPLEMENTATIONS.md#custom-metrics-api)）。

这允许定义自定义指标作为目标。首先从默认指标开始，只有在特定部署存在真正限制时才转移到自定义指标。

要部署 Kubernetes 度量服务器，请从官方项目页面下载最新版本（[`github.com/kubernetes-incubator/metrics-server/releases`](https://github.com/kubernetes-incubator/metrics-server/releases)）。写作时，版本为`0.3.3`。

下载`tar.gz`文件，写作时为`metrics-server-0.3.3.tar.gz`。解压缩并将版本应用到集群：

```py
$ tar -xzf metrics-server-0.3.3.tar.gz
$ cd metrics-server-0.3.3/deploy/1.8+/
$ kubectl apply -f .
clusterrole.rbac.authorization.k8s.io/system:aggregated-metrics-reader created
clusterrolebinding.rbac.authorization.k8s.io/metrics-server:system:auth-delegator created
rolebinding.rbac.authorization.k8s.io/metrics-server-auth-reader created
apiservice.apiregistration.k8s.io/v1beta1.metrics.k8s.io created
serviceaccount/metrics-server created
deployment.extensions/metrics-server created
service/metrics-server created
clusterrole.rbac.authorization.k8s.io/system:metrics-server created
clusterrolebinding.rbac.authorization.k8s.io/system:metrics-server created
```

您将在`kube-system`命名空间中看到新的 pod：

```py
$ kubectl get pods -n kube-system
NAME                            READY STATUS  RESTARTS AGE
...
metrics-server-56ff868bbf-cchzp 1/1   Running 0        42s
```

您可以使用`kubectl top`命令获取有关节点和 pod 的基本信息：

```py
$ kubectl top node
NAME                    CPU(cores) CPU% MEM(bytes) MEMORY%
ip-X.us-west-2.internal 57m        2%   547Mi      7%
ip-Y.us-west-2.internal 44m        2%   534Mi      7%
$ kubectl top pods -n example
$ kubectl top pods -n example
NAME                              CPU(cores) MEMORY(bytes)
frontend-5474c7c4ff-d4v77         2m         51Mi
frontend-5474c7c4ff-dlq6t         1m         50Mi
frontend-5474c7c4ff-km2sj         1m         51Mi
frontend-5474c7c4ff-rlvcc         2m         51Mi
thoughts-backend-79f5594448-cvdvm 1m         54Mi
users-backend-794ff46b8-m2c6w     1m         54Mi
```

为了正确控制使用量的限制，我们需要在部署中配置分配和限制资源。

# 在部署中配置资源

在容器的配置中，我们可以指定所请求的资源以及它们的最大资源。

它们都向 Kubernetes 提供有关容器的预期内存和 CPU 使用情况的信息。在创建新容器时，Kubernetes 将自动将其部署到具有足够资源覆盖的节点上。

在`frontend/deployment.yaml`文件中，我们包括以下`resources`实例：

```py
spec:
    containers:
    - name: frontend-service
      image: 033870383707.dkr.ecr.us-west-2
                 .amazonaws.com/frontend:latest
      imagePullPolicy: Always
      ...
      resources:
          requests:
              memory: "64M"
              cpu: "60m"
          limits:
              memory: "128M"
              cpu: "70m"
```

最初请求的内存为 64 MB，0.06 个 CPU 核心。

内存资源也可以使用 Mi 的平方，相当于兆字节（*1000²*字节），称为 mebibyte（*2²⁰*字节）。在任何情况下，差异都很小。您也可以使用 G 或 T 来表示更大的数量。

CPU 资源是以分数形式衡量的，其中 1 表示节点运行的任何系统中的一个核心（例如，AWS vCPU）。请注意，1000m，表示 1000 毫核心，相当于一个完整的核心。

限制为 128 MB 和 0.07 个 CPU 核心。容器将无法使用超过限制的内存或 CPU。

目标是获得简单的整数以了解限制和所请求的资源。不要期望第一次就完美无缺；应用程序将改变它们的消耗。

以聚合方式测量指标，正如我们将在第十一章中讨论的那样，*处理系统中的变化、依赖关系和机密*，将帮助您看到系统的演变并相应地进行调整。

限制为自动缩放器创建了基准，因为它将以资源的百分比来衡量。

# 创建 HPA

要创建一个新的 HPA，我们可以使用`kubectl autoscale`命令：

```py
$ kubectl autoscale deployment frontend --cpu-percent=10 --min=2 --max=8 -n example
horizontalpodautoscaler.autoscaling/frontend autoscaled
```

这将创建一个新的 HPA，它以`example`命名空间中的`frontend`部署为目标，并设置要在`2`和`8`之间的 Pod 数量。要缩放的参数是 CPU，我们将其设置为可用 CPU 的 10%，并在所有 Pod 中平均。如果超过了，它将创建新的 Pod，如果低于，它将减少它们。

10%的限制用于触发自动缩放器并进行演示。

自动缩放器作为一种特殊类型的 Kubernetes 对象工作，可以查询它：

```py
$ kubectl get hpa -n example
NAME     REFERENCE           TARGETS  MIN MAX REPLICAS AGE
frontend Deployment/frontend 2%/10%   2   8   4        80s
```

请注意，目标显示当前约为 2%，接近限制。这是为了小型可用 CPU 而设计的，将具有相对较高的基线。

几分钟后，副本的数量将减少，直到达到最小值`2`。

缩容可能需要几分钟。这通常是预期的行为，扩容比缩容更积极。

为了创建一些负载，让我们使用应用程序 Apache Bench（`ab`），并与前端中专门创建的端点结合使用大量 CPU：

```py
$ ab -n 100 http://<LOADBALANCER>.elb.amazonaws.com/load
Benchmarking <LOADBALANCER>.elb.amazonaws.com (be patient)....
```

请注意，`ab`是一个方便的测试应用程序，可以同时生成 HTTP 请求。如果愿意，您也可以在浏览器中多次快速点击 URL。

请记住添加负载均衡器 DNS，如在*创建集群*部分中检索到的。

这将在集群中生成额外的 CPU 负载，并使部署扩展：

```py
NAME     REFERENCE           TARGETS MIN MAX REPLICAS AGE
frontend Deployment/frontend 47%/10% 2   8   8        15m
```

请求完成后，几分钟后，Pod 的数量将缓慢缩减，直到再次达到两个 Pod。

但是我们需要一种方式来扩展节点，否则我们将无法增加系统中的资源总数。

# 扩展集群中节点的数量

EKS 集群中作为节点工作的 AWS 实例的数量也可以增加。这为集群增加了额外的资源，并使其能够启动更多的 Pod。

支持这一功能的底层 AWS 服务是自动扩展组。这是一组共享相同镜像并具有定义大小的 EC2 实例，包括最小和最大实例。

在任何 EKS 集群的核心，都有一个控制集群节点的自动扩展组。请注意，`eksctl`将自动扩展组创建并公开为节点组：

```py
$ eksctl get nodegroup --cluster Example
CLUSTER NODEGROUP   MIN  MAX  DESIRED INSTANCE IMAGE ID
Example ng-74a0ead4 2    2    2       m5.large ami-X
```

使用`eksctl`，我们可以手动扩展或缩小集群，就像我们创建集群时描述的那样。

```py
$ eksctl scale nodegroup --cluster Example --name ng-74a0ead4 --nodes 4
[i] scaling nodegroup stack "eksctl-Example-nodegroup-ng-74a0ead4" in cluster eksctl-Example-cluster
[i] scaling nodegroup, desired capacity from to 4, max size from 2 to 4
```

这个节点组也可以在 AWS 控制台中看到，在 EC2 | 自动缩放组下：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-dkr-msvc-py/img/1a35c1f7-06fa-4243-b336-1db202e9b03b.png)

在 Web 界面中，我们可以收集有关自动缩放组的一些有趣信息。活动历史选项卡允许您查看任何扩展或缩小事件，监控选项卡允许您检查指标。

大部分处理都是由`eksctl`自动创建的，比如实例类型和 AMI-ID（实例上的初始软件，包含操作系统）。它们应该主要由`eksctl`控制。

如果需要更改实例类型，`eksctl`要求您创建一个新的节点组，移动所有的 pod，然后删除旧的。您可以在`eksctl`文档中了解更多关于这个过程的信息。

但是从 Web 界面，很容易编辑缩放参数并为自动缩放添加策略。

通过 Web 界面更改参数可能会使`eksctl`中检索的数据混乱，因为它是独立设置的。

可以为 AWS 安装 Kubernetes 自动缩放器，但需要一个`secrets`配置文件，其中包括在自动缩放器 pod 中添加适当的 AMI 的 AWS 权限。

在代码中以 AWS 术语描述自动缩放策略也可能会令人困惑。Web 界面使这变得更容易一些。好处是你可以在配置文件中描述一切，这些文件可以在源代码控制下。

在这里，我们将使用 Web 界面配置，但您可以按照[`eksctl.io/usage/autoscaling/`](https://eksctl.io/usage/autoscaling/)上的说明进行操作。

对于缩放策略，有两个主要的组件可以创建：

+   **定时操作**：这些是在定义的时间发生的扩展和缩小事件。该操作可以通过所需数量和最小和最大数量的组合来改变节点的数量，例如，在周末增加集群。操作可以定期重复，例如每天或每小时。操作还可以有一个结束时间，这将使值恢复到先前定义的值。这可以在系统中预期额外负载时提供几个小时的提升，或者在夜间减少成本。

+   **缩放策略**：这些策略是在特定时间查找需求并在所描述的数字之间扩展或缩小实例的策略。有三种类型的策略：目标跟踪、阶梯缩放和简单缩放。目标跟踪是最简单的，因为它监视目标（通常是 CPU 使用率）并根据需要扩展和缩小以保持接近该数字。另外两种策略需要您使用 AWS CloudWatch 指标系统生成警报，这更强大，但也需要使用 CloudWatch 和更复杂的配置。

节点的数量不仅可以增加，还可以减少，这意味着删除节点。

# 删除节点

删除节点时，正在运行的 pod 需要移动到另一个节点。Kubernetes 会自动处理这个操作，EKS 会以安全的方式执行该操作。

如果节点由于任何原因关闭，例如意外的硬件问题，也会发生这种情况。正如我们之前所看到的，集群是在多个可用区创建的，以最小化风险，但如果 Amazon 的一个可用区出现问题，一些节点可能会出现问题。

Kubernetes 是为这种问题而设计的，因此在意外情况下很擅长将 pod 从一个节点移动到另一个节点。

将一个 pod 从一个节点移动到另一个节点是通过销毁该 pod 并在新节点上重新启动来完成的。由于 pod 受部署控制，它们将保持副本或自动缩放值所描述的适当数量的 pod。

请记住，Pod 本质上是不稳定的，应设计成可以被销毁和重新创建。

扩展还可以导致现有的 Pod 移动到其他节点以更好地利用资源，尽管这种情况较少。增加节点数量通常是在增加 Pod 数量的同时进行的。

控制节点的数量需要考虑要遵循的策略，以实现最佳结果，具体取决于要求。

# 设计一个成功的自动缩放策略

正如我们所看到的，Pod 和节点两种自动缩放需要相互关联。保持节点数量减少可以降低成本，但会限制可用于增加 Pod 数量的资源。

请记住，自动缩放是一个大量数字的游戏。除非您有足够的负载变化来证明其必要性，否则调整它将产生成本节省，这与开发和维护过程的成本不可比。对预期收益和维护成本进行成本分析。

在处理集群大小变化时，优先考虑简单性。在夜间和周末缩减规模可以节省大量资金，而且比生成复杂的 CPU 算法来检测高低要容易得多。

请记住，自动缩放并不是与云服务提供商降低成本的唯一方法，可以与其他策略结合使用。

例如，在 AWS 中，预订 EC2 实例一年或更长时间可以大大减少账单。它们可以用于集群基线，并与更昂贵的按需实例结合使用进行自动缩放，从而额外降低成本：[`aws.amazon.com/ec2/pricing/reserved-instances/`](https://aws.amazon.com/ec2/pricing/reserved-instances/)。

通常情况下，您应该有额外的硬件可用于扩展 Pod，因为这样更快。这在不同的 Pod 以不同的速度扩展的情况下是允许的。根据应用程序的不同，当一个服务的使用量增加时，另一个服务的使用量可能会减少，这将保持利用率在相似的数字。

这可能不是您首先想到的用例，但例如，在夜间安排的任务可能会利用白天被外部请求使用的可用资源。

它们可以在不同的服务中工作，随着负载从一个服务转移到另一个服务而自动平衡。

一旦头部空间减少，就开始扩展节点。始终留出安全余地，以避免陷入节点扩展不够快，由于资源不足而无法启动更多的 Pod 的情况。

Pod 自动缩放器可以尝试创建新的 Pod，如果没有可用资源，它们将不会启动。同样，如果删除了一个节点，任何未删除的 Pod 可能由于资源不足而无法启动。

请记住，我们在部署的`resources`部分向 Kubernetes 描述了新 Pod 的要求。确保那里的数字表明了 Pod 所需的数字。

为了确保 Pod 在不同节点上充分分布，您可以使用 Kubernetes 的亲和性和反亲和性规则。这些规则允许定义某种类型的 Pod 是否应在同一节点上运行。

例如，这对于确保各种 Pod 均匀分布在区域中，或者确保两个服务始终部署在同一节点以减少延迟非常有用。

您可以在这篇博客文章中了解有关亲和性和如何进行配置的更多信息：[`supergiant.io/blog/learn-how-to-assign-pods-to-nodes-in-kubernetes-using-nodeselector-and-affinity-features/`](https://supergiant.io/blog/learn-how-to-assign-pods-to-nodes-in-kubernetes-using-nodeselector-and-affinity-features/)，以及在 Kubernetes 官方配置中（[`kubernetes.io/docs/concepts/configuration/assign-pod-node/`](https://kubernetes.io/docs/concepts/configuration/assign-pod-node/)）。

总的来说，Kubernetes 和`eksctl`默认情况下对大多数应用程序都能很好地工作。仅在高级配置时使用此建议。

# 总结

在本章中，我们看到了如何将 Kubernetes 集群应用到生产环境中，并在云提供商（在本例中是 AWS）中创建 Kubernetes 集群。我们看到了如何设置我们的 Docker 注册表，使用 EKS 创建集群，并调整现有的 YAML 文件，使其适用于该环境。

请记住，尽管我们以 AWS 为例，但我们讨论的所有元素都可以在其他云提供商中使用。查看它们的文档，看看它们是否更适合您。

我们还看到了如何部署 ELB，以便集群对公共接口可用，并如何在其上启用 HTTPS 支持。

我们讨论了部署的不同元素，以使集群更具弹性，并顺利部署新版本，不中断服务——既可以通过使用 HAProxy 快速启用或禁用服务，也可以确保以有序方式更改容器映像。

我们还介绍了自动缩放如何帮助合理利用资源，并允许您覆盖系统中的负载峰值，既可以通过创建更多的 pod，也可以通过在需要时向集群添加更多的 AWS 实例来增加资源，并在不需要时将其删除以避免不必要的成本。

在下一章中，我们将看到如何使用 GitOps 原则控制 Kubernetes 集群的状态，以确保对其进行的任何更改都经过适当审查和捕获。

# 问题

1.  管理自己的 Kubernetes 集群的主要缺点是什么？

1.  您能否列举一些具有托管 Kubernetes 解决方案的商业云提供商的名称？

1.  有没有什么操作需要您执行才能推送到 AWS Docker 注册表？

1.  我们使用什么工具来设置 EKS 集群？

1.  在本章中，我们对先前章节的 YAML 文件进行了哪些主要更改？

1.  在本章中，有哪些 Kubernetes 元素在集群中是不需要的？

1.  为什么我们需要控制与 SSL 证书相关的 DNS？

1.  活跃探针和就绪探针之间有什么区别？

1.  为什么在生产环境中滚动更新很重要？

1.  自动缩放 pod 和节点有什么区别？

1.  在本章中，我们部署了自己的数据库容器。在生产中，这将发生变化，因为需要连接到已经存在的外部数据库。您将如何更改配置以实现这一点？

# 进一步阅读

要了解更多关于如何使用 AWS 的网络能力的信息，您可以查看书籍*AWS Networking Cookbook* ([`www.packtpub.com/eu/virtualization-and-cloud/aws-networking-cookbook`](https://www.packtpub.com/eu/virtualization-and-cloud/aws-networking-cookbook))。要了解如何确保在 AWS 中设置安全系统，请阅读*AWS: Security Best Practices on AWS* ([`www.packtpub.com/eu/virtualization-and-cloud/aws-security-best-practices-aws`](https://www.packtpub.com/eu/virtualization-and-cloud/aws-security-best-practices-aws))。
