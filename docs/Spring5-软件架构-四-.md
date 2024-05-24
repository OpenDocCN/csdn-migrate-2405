# Spring5 软件架构（四）

> 原文：[`zh.annas-archive.org/md5/45D5A800E85F86FC16332EEEF23286B1`](https://zh.annas-archive.org/md5/45D5A800E85F86FC16332EEEF23286B1)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十一章：DevOps 和发布管理

DevOps 是一种重要的技术，可以帮助团队防止他们的工作变得孤立。它还有助于消除整个软件开发周期中的乏味流程和不必要的官僚主义。这种技术在整个软件开发过程中使用，从编写代码到将应用程序部署到生产环境。

本章将演示如何通过采用自动化来实现这些目标，以减少手动任务的数量，并使用自动化管道部署应用程序，负责验证编写的代码，提供基础设施，并将所需的构件部署到生产环境。在本章中，我们将审查以下主题：

+   孤立

+   DevOps 文化动机

+   DevOps 采用

+   采用自动化

+   基础设施即代码

+   使用 Spring Framework 应用 DevOps 实践

+   发布管理管道

+   持续交付

# 孤立

几年前，软件行业使用瀑布模型来管理系统开发生命周期（SDLC）。瀑布模型包括许多阶段，如收集需求、设计解决方案、编写代码、验证代码是否符合用户需求，最后交付产品。为了在每个阶段工作，创建了不同的团队和角色，包括分析师、开发人员、软件架构师、QA 团队、运维人员、项目经理等。每个角色都负责产出并将其交付给下一个团队。

使用瀑布模型创建软件系统所需的步骤如下：

1.  分析师收集软件需求

1.  软件架构师仔细审查需求，并扩展文档，提供有关将使用的工具和技术、必须编写的模块以创建系统、显示组件如何连接以作为整体运行的图表等信息

1.  开发人员按照架构师发布的指令编写应用程序

1.  QAs 必须验证创建的软件是否按预期工作

1.  运维团队部署软件

从这些步骤中可以看出，在每个阶段，不同的团队正在产出明确定义的产出，并将其交付给下一个团队，形成一个链条。这个过程完美地描述了团队使用孤立心态的工作方式。

这个软件生产过程乍一看似乎不错。然而，这种方法有几个缺点。首先，在每个阶段都不可能产生完美的产出，通常会产生不完整的构件。因此，专注于自己流程的团队和部门开始对组织中其他人的工作付出较少关注。如果团队的成员对其他团队内发生的问题感到责任较小，那么在这个领域就会出现冲突的墙壁，因为每个团队都独立工作，彼此之间有几道障碍，导致沟通中断，从而破坏信息的自由流动。

# 如何打破孤立

在前一节中，我们看到团队如何组织以产生产出。很明显，每个团队成员基本上具有与其他团队成员相同的技能。因此，要求分析团队编写某个功能的代码或提供基础设施将应用程序部署到生产环境是不可能的。

打破孤立的第一步是创建多学科团队。这意味着团队应该有不同技能的成员，这些技能将帮助团队解决不同的问题和需求。

理想情况下，每个团队成员都应具备处理任何需求的必要技能。然而，这个目标几乎是不可能实现的。

一旦你有了一个跨学科团队，你很容易会发现在同一个团队中有人以信息孤岛的方式工作。为了解决这个问题，你需要制定一个计划，让每个成员都能够将更多的技能纳入他们的技能组合中。例如，你可以让开发人员与 QA 专家一起使用配对编程技术。这样，开发人员将学习 QA 专家的思维方式，而 QA 将获得开发技能。

跨学科团队在整个软件开发生命周期的各个阶段创建了协作的环境。

# DevOps 文化

对于 DevOps 有很多定义。我们将使用以下定义：

“DevOps 是一种鼓励运营和开发团队共同合作的文化，而不会削弱每个团队具有的特定技能和责任。”

这意味着软件开发团队要对他们所产生的代码负责和拥有权。DevOps 改变了人们在软件开发生命周期中的组织方式和他们遵循的流程。

这种文化消除了信息孤岛，因为它要求所有角色都参与到软件开发生命周期中，并共同合作，如下图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/b318270d-09d7-4d05-a27b-9ed23091466c.png)

打破组织中的信息孤岛

# 动机

为了理解采用 DevOps 的动机，让我们看一个在开发软件的公司和组织中经常遇到的常见现实场景。

假设我们在一家尚未采用 DevOps 或**持续集成**（**CI**）和**持续部署**（**CD**）实践的公司工作。让我们想象一下，这家公司有以下团队负责发布一个功能或新软件：

+   **开发团队：**该团队使用代表新功能或错误修复的分支将代码编写并提交到源代码版本控制系统中。

+   **运维团队：**该团队在不同的环境中安装构件，例如通过测试和生产。

+   **QA 团队：**该团队验证所产生的构件从最终用户和技术角度是否按预期工作，并批准或拒绝所产生的代码。

每当开发人员发布功能和错误修复时，都会重复这个常见的流程。在首次经历这个常见流程时，我们意识到存在一些问题，包括以下问题：

+   **不同的环境：**代码开发的环境通常与暂存和生产环境具有不同的环境和配置。

+   **沟通：**基于 DevOps 实践形成跨学科团队将帮助我们打破组织中的信息孤岛。否则，团队之间缺乏沟通是通过会议、电话会议和/或电子邮件解决的。

+   **不同的行为：**在生产环境中产生的错误数量与在开发环境中产生的错误数量不同。也有一些情况下错误根本无法重现。

正如我们所看到的，这里有几个问题需要解决。让我们看看如何解决上述每一个问题：

+   **不同的环境：**通过基础设施即代码实践，我们可以创建文件，使每个环境都能够使用不可变服务器，这是我们将在关于基础设施即代码的未来部分中讨论的概念。

+   **沟通：**基于 DevOps 实践形成跨学科团队将帮助我们打破组织中的信息孤岛。

+   **不同的行为：**使用基础设施即代码方法，我们将能够创建不可变服务器，保证不同环境（如开发、测试和生产）中的相同行为。

+   **上市时间：**应用**持续交付**（**CD**）使我们能够尽快将新功能部署到生产环境。

这些都是现实场景中常见的问题，这就是为什么一些组织正在采用 DevOps。这从打破信息孤岛开始，对开发团队有很多好处。例如，它允许他们尽快部署，减少错误。它还允许他们快速应对变化，使流程更加高效。因此，我鼓励您的组织打破信息孤岛，变得敏捷，以快速生产高质量的应用程序。

# DevOps 采用

DevOps 的采用符合组织释放应用程序更快的需求，最小化与将软件交付到生产环境相关的错误和风险。作为这一过程的一部分，我们需要增加自动化测试应用程序的流程数量，并强烈建议我们去除手动流程，以避免人为干预，这可能导致错误的产生。

可以自动化的一些流程包括环境配置和部署流程。让我们来看一下 SDLC 的改进：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/0a4f4bff-9659-4f32-9ef2-29dda3582059.jpg)

瀑布方法与敏捷方法和 DevOps

然而，为了更快地交付软件，我们必须解决一些问题。首先，我们需要拥抱自动化文化。自动化文化迫使我们使用许多工具，我们将在下一节介绍，并且我们需要理解，由于微服务的崛起，DevOps 已经成为我们流程的一个重要部分，因为微服务具有更复杂和分布式的系统。然而，不要忘记，DevOps 的主要目标是合作，而不仅仅是自动化。

# 拥抱自动化

拥抱自动化是 DevOps 采用的关键因素之一。有几种工具可以帮助我们进行这一过程。

我们需要找到帮助我们在整个 SDLC 的所有阶段自动化流程的工具。这些阶段如下图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/2fe552c5-3b23-44a3-a440-01ddb919becd.png)

组织中的流水线

在组织内，流水线的设计旨在保持软件交付流程简单。第一步是识别不同的阶段，就像我们在前面的图表中所做的那样，然后我们应该选择合适的工具，让我们能够自动化每个阶段。让我们回顾一下各个阶段和与每个阶段相关的工具/软件：

+   代码（Git、SVN 等）。

+   构建（Maven、Gradle、npm 等）。

+   测试自动化。这也可能包括集成测试（JUnit、Postman、Newman、JFrog、Selenium、Cucumber、Gherkin 等）。

+   部署（Ansible、Vagrant、Docker、Chef、Puppet 等）。

+   监控（我们将在第十二章中深入讨论监控）。

+   持续集成和持续部署（Jenkins、Hudson 等）。

+   代码分析（Sonatype、Jacoco、PMD、FindBugs 等）。

正如我们在第十章中所学到的，*容器化您的应用程序*，我们知道如何基于容器提供环境，并且我们需要理解，我们创建的示例也可以应用于基础设施即代码的概念，我们将在下一节中讨论。

# 基础设施即代码

基础设施即代码是指创建文件以及环境定义和程序的过程，这些将用于配置环境。DevOps 概念开始使用这些脚本或文件存储库与代码一起，以便我们可以确定哪些代码将部署在哪个环境中。使用这些实践，我们可以确保所有服务器和环境是一致的。

一个典型的组织或团队将在多个环境中部署他们的应用程序，主要用于测试目的。当我们有开发、暂存和生产环境时，开发人员面临的最大问题是每个环境都不同，需要不同的属性。

这些属性可能包括以下配置，以及其他配置：

+   服务器名称

+   IP 地址和端口号

+   服务器队列连接

+   数据库连接

+   凭据

软件开发的现代时代突然给我们带来了在构建基础设施时的可测试性、可重复性和透明度。如今的一个关键目标是在本地或云环境中仅使用物理服务器资源重新创建或构建完整的软件环境。

作为其结果，我们应该能够创建数据库实例，用脚本或备份文件中的初始数据填充它们，并重新构建我们的源代码以创建可以随时部署的构件。

有许多工具可以用来应用基础设施即代码的概念：

+   对于配置同步，我们可以使用 Chef、Puppet 或 Ansible

+   对于容器化服务器，我们可以使用 Docker 部署新的应用程序版本

我们将要拥抱的一些关键好处如下：

+   *不可变服务器*，通过在基础设施中重建服务器来应用更改，而不是修改现有服务器

+   *对基础设施进行更改的测试*，这涉及使用文件在我们应用程序和基础设施的不同阶段进行测试来复制环境

以下图表显示了重新创建每个阶段环境的这两个关键好处的主要思想：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/75d805ec-7501-480a-bf5f-5f623c339570.png)

不可变基础设施

自动化的服务器配置过程给我们带来以下好处：

+   可以自动重新创建任何环境或服务器

+   配置文件可以存储凭据或自定义配置，每个环境可能不同

+   在不同阶段环境将始终相同

在接下来的部分，我们将创建一些基础设施即代码的示例。

# Spring 应用程序和 DevOps 实践

Spring 提供了与 DevOps 原则一致的开箱即用功能。让我们看看其中一些。

首先，我们将使用[`start.spring.io`](https://start.spring.io/)上提供的 Spring Initializr 创建一个新的 Spring Boot 应用程序。

# 支持不同环境

在交付应用程序的常见场景是我们在开发环境（几乎总是我们自己的计算机）上编写应用程序，然后将应用程序部署在不同的测试和生产环境中。Spring 配置文件允许我们在每个环境中使用不同的配置。我们可以使用本地配置文件作为应用程序的一部分，然后稍后，我们可以使用环境变量覆盖这些配置值。这通常是因为我们在部署配置的每个环境中使用不同的凭据和配置。

在为我们需要部署应用程序的每个不同环境创建不同的 Spring 配置文件之前，我们将在`/main/resources/static`文件夹后面添加一个`index.html`静态页面，标签如下：

```java
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Welcome devops</title>
</head>

```

在接下来的步骤中，我们将展示 Spring 在 DevOps 方面提供的一些功能。我们还将完成一个练习，为 Docker 容器提供将配置为支持不同环境（如开发、测试和生产环境）的层。

首先，我们将为我们的应用程序创建一个不同的配置文件。例如，我们可以使用三个文件分别命名为`application-dev.properties`、`application-test.properties`和`application-production.properties`在`/infra-as-code/src/main/resources`文件夹中创建不同的配置文件，用于开发、测试和生产：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/2a1858d4-9302-4b3c-a3bc-f8cd6bc3782e.png)

为了了解 Spring 配置文件的工作原理，我们将更改应用程序正在使用的端口。用于配置端口的属性是`server.port`。让我们按照以下方式更改我们拥有的每个不同文件的值：

`application-dev.properties`：

```java
server.port = 8090
```

`application-test.properties`：

```java
server.port = 8091
```

`application-production.properties`：

```java
server.port = 8092
```

# 选择配置文件

在运行支持不同配置文件的应用程序之前，您需要选择要使用的配置文件。可以使用 JVM 参数`spring.profiles.active`标志来选择配置文件，如下所示：

```java
$ java -Dspring.profiles.active=dev -jar target/infra-as-code-0.0.1-SNAPSHOT.jar
```

最后，您可以使用与提供的配置文件相关联的端口在浏览器中检查应用程序。`spring.profiles.active`标志的有效值如下：

+   `dev`

+   `production`

+   `test`

如果您没有为该标志提供任何值，则将使用`application.properties`中的配置。

这是一个探索 Spring 中配置文件的简单示例。请记住，使用配置文件，我们还可以配置数据源、队列、bean 以及您需要的任何内容。您始终可以使用环境变量覆盖任何提供的配置变量。

此外，正如我们在第十章中看到的，*容器化您的应用程序*，我们可以将 Spring Boot 应用程序 docker 化，并借此了解不可变服务器以及如何测试基础架构更改。

在本节中，我们将学习使用 Vagrant ([`www.vagrantup.com/`](https://www.vagrantup.com/))版本 1.7.0 或更高版本重新创建基础架构的类似方法。这可能需要虚拟化软件（例如 VirtualBox：[`www.virtualbox.org/`](https://www.virtualbox.org/)）。

另一个可以执行相同任务的工具是 Ansible ([`ansible.com/`](http://ansible.com/))，本章不涉及该工具。

# Vagrant

Vagrant 是一个旨在重新创建虚拟环境的工具，主要用于开发。其功能基于 VirtualBox，并且可以使用诸如 Chef、Salt 或 Puppet 之类的配置工具。

它还可以与不同的提供者一起使用，例如 Amazon EC2、DigitalOcean、VMware 等。

Vagrant 使用一个名为`Vagrantfile`的配置文件，其中包含所有需要配置所需环境的配置。一旦创建了上述配置文件，就可以使用`vagrant up`命令使用提供的指令安装和配置环境。

Vagrant 必须在继续之前安装在机器上。要做到这一点，请按照工具的文档中提供的步骤进行操作[`www.vagrantup.com/intro/getting-started/install.html`](https://www.vagrantup.com/intro/getting-started/install.html)。

# 使用 Vagrant 工作

现在，我们将在应用程序的根目录中创建一个`Vagrantfile`配置文件来创建一个简单的环境。我们将提供一个 Linux 发行版环境，即 Ubuntu。`Vagrantfile`的内容如下：

```java
# Vagrantfile API/syntax version. Don't touch unless you know what you're doing!
VAGRANTFILE_API_VERSION = "2"

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|

  config.vm.box = "hashicorp/precise32"

  config.vm.network :forwarded_port, guest: 8090, host: 8090
  config.vm.network "public_network", ip: "192.168.1.121"
  #config.vm.synced_folder "target","/opt"

  config.vm.provider "virtualbox" do |vb|
    vb.customize ["modifyvm", :id, "--memory", "2048"]
  end

  # provision
  config.vm.provision "shell", path:"entrypoint.sh"

end
```

请注意`Vagrantfile`的第 6 行：

```java
config.vm.box = "hashicorp/precise32"
```

我们正在从已构建的 VM box `hashicorp/precise32` 创建我们的 Linux 环境。

在继续使用 Vagrant 提供环境之前，我们将创建一个`ssh`文件，该文件将为我们安装 JDK 8。在项目的根目录下，创建一个名为`entrypoint.sh`的文件，内容如下：

```java
#!/usr/bin/env bash
sudo apt-get update

echo "Install Java 8.."
sudo apt-get install -y software-properties-common python-software-properties

echo oracle-java8-installer shared/accepted-oracle-license-v1-1 select true | sudo /usr/bin/debconf-set-selections
sudo add-apt-repository ppa:webupd8team/java -y

sudo apt-get update

sudo apt-get install oracle-java8-installer
echo "Set env variables for Java 8.."
sudo apt-get install -y oracle-java8-set-default

# Start our simple web application with specific JVM_ARGS and SPRING_PROFILE
echo "Run our springboot application."
java -Dspring.profiles.active=dev -jar /vagrant/target/infra-as-code-0.0.1-SNAPSHOT.jar
```

然后，为了创建虚拟机并提供 VM，我们将在控制台上运行以下命令：

```java
vagrant up
```

在第一次尝试时，下载盒子和配置服务器将需要一些时间。在这些过程之间，您将被问及要使用哪个网络接口来配置您的服务器，问题是*网络桥接到哪个接口？*。然后您可以选择对您的机器更方便的选项。

在我们的执行的整个输出结束时，我们将在配置的服务器上看到我们的 Spring 应用程序正在运行，如下图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/d8364ec2-ae89-485e-84c2-8cbb275367e1.png)

现在我们可以在浏览器中检查我们的应用是否在端口`8090`（`http://localhost:8090/`）上运行。您可以通过以下命令访问`ssh`来检查 Vagrant 中运行的 Java 进程：

```java
vagrant ssh
```

这将在我们的配置服务器上打开一个`ssh`会话，让我们可以在控制台中看到已经创建的进程：

```java
vagrant@precise32:~$ ps aux | grep java
```

结果的输出将是我们正在运行的 Java 进程，如下图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/1622befd-b408-4574-bc6f-0e3a0b47e948.png)

要停止虚拟机，可以在控制台中使用`vagrant halt`命令：

```java
vagrant halt
```

要销毁创建的虚拟机，可以输入以下内容：

```java
vagrant destroy
```

我们刚学会使用 Vagrant 将基础设施表示为代码。我们可以使用不同的工具为不同阶段创建所需的环境或服务器；我们可以在上一章中回顾这一点。在下一节中，我们将创建发布管理过程的示例。

# 发布管理

要将您的代码带到生产环境，必须计划好这个过程。

这个规划过程称为**发布管理**。在整个过程中，我们需要关注现有服务的完整性和一致性，确保我们系统的运行。

为了了解发布管理过程中涉及的步骤，我们将看一下以下概念：

+   流水线

+   持续集成

+   持续交付和持续部署

# 流水线

流水线是我们必须经历的一系列步骤来实现目标。我们在第七章中看过这个概念，*管道和过滤器架构*。在这个上下文中，相同的概念用于执行我们发布管理过程中的一系列步骤。流水线将在不同环境中协助我们进行软件交付过程。我们将创建一个由五个阶段组成的简单流水线：

+   自动构建我们的项目

+   运行测试（如单元测试和集成测试）

+   部署到暂存环境

+   运行验收测试

+   部署到生产环境（包括在云端或本地服务器上部署我们的应用程序）

以下图表显示了流水线的外观：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/cd11eede-1f3b-41a6-8d9b-cd6c0aa27780.png)

CI/CD 流水线

每个阶段可能有一个或多个任务或作业，例如创建数据库模式，使用 Vagrant 为盒子进行配置，克隆 Docker 容器等。

上述图表分为两部分：

+   持续集成

+   持续部署

在接下来的几节中，我们将简要介绍这两个概念。

# 持续集成

持续集成（CI）是指开发人员尽可能经常将他们生成的代码合并到主分支中的做法。合并的代码应该没有错误，并且还应该为业务提供价值。

使用 CI，我们可以通过运行一组自动化测试来自动验证提交的代码。当我们使用这种做法时，我们正在处理一个 CI 代码库，避免了过去在安排特定日期和时间发布构建时出现的问题。

采用 CI 方法，最重要的目标是自动化测试，以确保每次将新提交推送到主源代码分支时应用程序都不会出现故障。

# 持续交付和持续部署

CD 是基于 CI 的一个过程。作为 CD 过程的一部分，我们需要其他步骤，这些步骤是将应用程序部署到生产环境所需的，包括配置和提供服务器（基础设施即代码）、验收测试以及为生产环境准备构建。

在生产环境中进行部署时，持续部署过程与持续交付过程不同，不需要*人类*干预。

现在，我们将创建一个基于我们简单流水线的示例。为了专注于 CI 和 CD 的流程，我们将使用上一章节的*Docker Compose*部分中创建的项目，该部分向您展示了如何将应用程序容器化。该项目包括一个完整的环境，已经准备好使用，并且已经包含了自动化测试。

# 自动化流水线

如前所述，我们将需要几个工具来自动化我们示例的流水线。为此，我们将使用以下工具：

+   我们的代码的 GitHub 存储库：我们可以将我们的代码推送到存储库并创建一个自动启动构建和测试的合并

+   使用 Gradle 或 Maven 构建我们的项目

+   使用 Junit、Postman 和 Newman 进行自动化测试

+   使用 Docker 部署到容器中的 Jenkins 作为我们的 CI 和 CD 的自动化服务器

首先，我们将把我们的代码推送到存储库。为此，我们将使用 GitHub。如果还没有，请创建一个帐户。

打开终端并转到我们应用程序的根文件夹。为了方便起见，我们将从我们的机器上推送存储库，因此我们将初始化我们的项目作为存储库。在命令行中执行以下操作：

```java
$ git init
```

命令的输出将如下所示：

```java
Initialized empty Git repository in /Users/alberto/TRABAJO/REPOSITORIES/banking-app/.git/
```

然后，我们将把所有文件添加到一个新的本地存储库中，如下面的代码所示：

```java
$ git add –A
```

现在我们将在本地提交我们的代码，如下面的代码所示：

```java
$ git commit -m initial
```

我们本地提交的输出将打印以下初始行：

```java
[master (root-commit) 5cc5f44] initial  40 files changed, 1221 insertions(+)
```

要推送我们的代码，我们需要在 GitHub 帐户中创建一个存储库。我们可以通过转到存储库部分，点击绿色的创建存储库按钮，并填写存储库的名称和描述来创建一个新的存储库，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/26f922b3-48dd-446f-b3b3-94c9c9c828fd.png)

创建一个 GitHub 存储库

现在我们有了我们存储库的 URL，例如`https://github.com/$YOUR_GITHUB_USER/bank-app`。我们创建的存储库的结果将如下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/b3ab7ef0-b637-4810-9d47-122653be156d.png)

GitHub 存储库

根据 GitHub 给出的说明，我们现在需要使用命令行将我们的代码推送到存储库：

```java
$ git remote add origin https://github.com/lasalazarr/banking-app.git
```

然后，我们将从本地存储库推送我们的更改到我们的 GitHub 存储库，如下面的代码所示：

```java
$ git push -u origin master
```

现在我们可以在我们的 GitHub 帐户存储库上查看我们的代码，并根据建议添加一个`README`文件来解释应用程序的目的。

在下一节中，我们将在继续练习之前先看一下 CI 服务器的概念。

# Jenkins

Jenkins 是一个负责自动化我们流水线的持续集成服务器。在与我们的 Git 存储库集成以自动构建我们的应用程序之前，让我们先回顾一下 CI 服务器背后的关键概念：

+   **流水线**: 流水线由一系列按顺序发生的步骤组成。流水线也是我们可以并行执行任务的地方。

+   **作业**: 这是一个小的工作单元，例如*运行测试*或*拉取我们的代码*。

+   **队列**: 这代表了 CI 服务器在有能力运行时将运行的所有排队作业。

+   **插件**: 这些是我们可以添加到我们的 CI 服务器的功能。例如，我们可以使用一个插件连接到我们的 Git 存储库。

+   **主/从**: 主机可以将工作委派给从机器来扩展我们的 CI。

Jenkins 有不同的分发方法。我们可以在[`jenkins.io/download/`](https://jenkins.io/download/)上查看更多关于这个项目的细节。在我们的示例中，我们将使用一个准备好的 Docker 镜像。

由于我们已经安装了 Docker，我们可以通过运行以下命令在命令行中拉取 Jenkins 镜像：

```java
$ docker pull jenkins/jenkins
```

现在我们可以通过运行以下命令来查看我们的镜像：

```java
$ docker images
```

现在我们将通过在命令行中运行以下命令来从容器中运行我们的 Jenkins 主服务器：

```java
$ docker run -p 8080:8080 -p 50000:50000 -v jenkins_home:/var/jenkins_home jenkins/jenkins:lts
```

注意控制台输出的生成的管理员密码，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/5bc7e400-605d-4b1f-b498-ac8854682b17.png)

生成 Jenkins 密码

我们现在可以看到我们的 Jenkins 服务器正在使用`http://localhost:8080/`运行。

第一步是粘贴我们刚在控制台上看到的管理员密码，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/c0dec531-f445-4ed3-bd75-ab2a4db0e90a.png)

解锁 Jenkins

现在我们将安装建议的插件，这将需要一些时间。然后我们将继续创建一个管理员用户和 URL 的过程。

我们将启用构建触发，因此我们将配置我们的 Jenkins 实例以接收来自 GitHub 的推送通知。为此，请按照以下步骤进行：

1.  转到 Jenkins 主页（`http://localhost:8080`），然后点击左侧菜单中的**New item**图标。

1.  输入项目名称并选择自由风格项目。完成后，点击“OK”按钮，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/6e7d5c71-1915-4f60-80cd-a6b7fc4b9a15.png)

1.  Jenkins 将显示一个页面，应该在该页面上配置作业步骤。首先，输入项目的描述和 GitHub URL 存储库，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/e925304f-0205-4859-b0a5-4255442a3256.png)

4. 输入您的 GitHub 用户帐户的凭据，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/d984098f-7203-45ca-8097-944a3e164645.png)

5. 最后，在页面底部选择 Gradle 作为项目的构建工具：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/71fd61b3-d798-47d6-9762-730393860b23.png)

创建的作业可以配置为在每次向 GitHub 提交代码时触发。该作业将下载代码，运行测试，并使用 Gradle 生成可部署的工件（JAR 文件）。您可以在此作业中添加额外的步骤来在 Docker Hub 中构建、标记和推送 Docker 镜像，然后自动部署到本地或基于云的服务器。

# 总结

在本章中，我们熟悉了 DevOps 文化的含义以及它如何影响组织的流程。我们还学习了如何自动化服务器的仪器化过程，使用基础设施即代码等技术来实现自动化。此外，我们学习了如何构建能够从存储库获取最新实施功能、验证代码、在不同层面运行测试并将应用程序推向生产的流水线。在下一章中，我们将探讨围绕应用程序监控的关注点，看看为什么关心它们如此重要。


# 第十二章：监控

一旦应用程序部署到生产环境中，监控就是其中一个关键方面。在这里，我们需要控制不常见和意外的行为；了解应用程序的工作方式至关重要，这样我们就可以尽快采取行动，以解决任何不希望的行为。

本章提供了一些建议，涉及可用于监视应用程序性能的技术和工具，考虑到技术和业务指标。

在本章中，我们将涵盖以下主题：

+   监控

+   应用程序监控

+   业务监控

+   监控 Spring 应用程序

+   APM 应用程序监控工具

+   响应时间

+   数据库指标

+   JVM 指标

+   Web 事务

# 监控

每个应用程序都是为了解决特定的业务需求和实现特定的业务目标而创建的，因此定期评估应用程序以验证是否实现了这些目标至关重要。作为这一验证过程的一部分，我们希望使用可以为我们提供以下因素的见解的指标来衡量我们应用程序的健康状况和性能：

+   **应用程序监控**：当我们谈论应用程序的健康状况时，了解正在使用的资源量，例如 CPU、内存消耗、线程或 I/O 进程，是很重要的。识别潜在的错误和瓶颈对于知道我们是否需要扩展、调整或重构我们的代码是很重要的。

+   **业务监控**：这些指标有助于了解有关业务本身的关键业务指标。例如，如果我们有一个在线商店，我们想知道我们是否实现了既定的销售目标，或者在银行应用程序中，我们想知道在某个分支机构、渠道等处收到了多少交易和客户。

我们将使用在第五章中创建的银行应用程序，*模型-视图-控制器架构*，作为一个示例，列出一些可以应用于它的监控概念。让我们开始展示如何使用 Spring 框架带来的开箱即用的工具来监视上述应用程序。

# 监控 Spring 应用程序

Spring 框架具有一些内置功能，用于监视和提供指标以了解应用程序的健康状况。我们有多种方法可以做到这一点，因此让我们来审查其中一些：

+   我们可以使用一种老式的方法，即围绕方法创建拦截器来记录我们想要记录的一切。

+   Spring 执行器可以与 Spring Boot 应用程序一起使用。使用此库，我们可以查看应用程序的健康状况；它提供了一种通过 HTTP 请求或 JMX 监视应用程序的简单方法。此外，我们可以使用工具对生成的数据进行索引，并创建有助于理解指标的图表。有很多选项可以创建图表，包括：

+   ELK Stack（ElasticSearch、Logstash 和 Kibana）

+   Spring-boot-admin

+   Prometheus

+   Telegraph

+   Influx 和

+   Graphana 等等

Spring 执行器可以作为现有 Spring Boot 应用程序的一部分集成，将以下依赖项添加为`build.gradle`文件的一部分：

```java
compile('org.springframework.boot:spring-boot-starter-actuator')
```

如果我们使用**Maven**，我们将在`pom.xml`文件中添加以下依赖项：

```java
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-actuator</artifactId>
</dependency>
```

执行器支持许多配置，这些配置必须在`application.properties`文件中提供。我们将向该文件添加一些属性，以提供元数据，例如应用程序的名称、描述和版本。此外，我们将在另一个端口上运行执行器端点，并禁用安全模型：

```java
info.app.name=Banking Application Packt
info.app.description=Spring boot banking application
info.app.version=1.0.0
management.port=8091
management.address=127.0.0.1
management.security.enabled=false
```

然后，在运行应用程序之后，执行器提供的一些端点将可用。让我们来审查其中一些：

+   **健康**：此端点在`http://localhost:8091/health` URL 中提供有关应用程序健康状况的一般信息：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/8d5f15d3-6f32-492a-9935-29bbe1682df3.png)

健康端点结果

+   **信息**：此端点提供有关应用程序元数据的信息，该信息先前在`application.properties`文件中进行了配置。信息可在`http://localhost:8080/info`上找到：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/f3815279-0a6e-48e3-b0d9-70c843c01a74.png)

信息端点结果

+   **指标**：提供有关操作系统、JVM、线程、加载的类和内存的信息。我们可以在`http://localhost:8080/metrics`上查看此信息：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/ec82d481-c29c-47c5-bff4-049bc530f29f.png)

指标端点结果

+   **跟踪**：提供有关最近对我们应用程序发出的请求的信息。我们可以在`http://localhost:8080/trace`上查看此信息：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/21a2ccbe-974f-4563-b825-4691964aee60.png)

跟踪端点结果

如果我们想要查看所有端点，可以在 spring 的官方文档中找到：[`docs.spring.io/spring-boot/docs/current/reference/htmlsingle/#production-ready-endpoints`](https://docs.spring.io/spring-boot/docs/current/reference/htmlsingle/#production-ready-endpoints)。

正如我们在执行器库中看到的那样，我们可以在某个时间获得应用程序的快照，了解应用程序的状态和健康状况，甚至追踪最常用的端点。

有时，提供的信息就足够了。如果您希望拥有图形并检查历史数据，您应该集成我们之前提到的工具。

Spring Actuator 还提供了收集有关应用程序的自定义指标的功能；这对于收集业务指标非常有帮助。例如，如果我们正在使用一个应用程序来创建储蓄账户，我们可以收集指标来了解正在创建多少个账户。然后，在开设更多的分支机构后，我们可以看到创建了多少个账户，并了解它对业务本身的影响。

在收集业务指标时的关键因素是了解对业务而言什么是重要的。为了完成这项任务，与业务人员一起合作非常重要。

业务指标对于了解发布新功能后我们产生的影响非常有帮助。它还有助于理解意外行为或错误。想象一下，您使用不同的电子邮件提供程序推出了新的应用程序版本；您应该比较更改后传递的电子邮件数量与更改电子邮件提供程序之前传递的电子邮件数量。如果您发现这些数字有很大的差异，您需要检查发生了什么，因为差异不应该太大。如果您想了解如何创建自定义指标，我鼓励您访问此链接：[`docs.spring.io/spring-boot/docs/current/reference/html/production-ready-metrics.html`](https://docs.spring.io/spring-boot/docs/current/reference/html/production-ready-metrics.html)。

市场上有许多工具可供我们在不更改代码的情况下监控应用程序，这些工具被称为**应用程序性能管理**工具（**APM**）。我们将在下一节中讨论这些工具的工作原理。

# 应用程序性能管理（APM）工具

云端监控和工具的兴起带来了巨大的发展；有一些工具和公司专门致力于 APM 工具。其中一些基于 JVM 和字节码仪器，如今这些工具甚至可以测量我们应用程序的用户体验。目前最受欢迎的工具有以下几种：

+   New Relic ([`newrelic.com/`](https://newrelic.com/))

+   App Dynamics ([`www.appdynamics.com/`](https://www.appdynamics.com/))

+   Dynatrace ([`www.dynatrace.com/technologies/java-monitoring/spring/`](https://www.dynatrace.com/technologies/java-monitoring/spring/))

+   DataDog ([`www.datadoghq.com/`](https://www.datadoghq.com/))

所有这些工具都使我们能够监视我们的应用程序层、健康状况（CPU、内存、线程、I/O）、数据库和顶级 SQL 查询。它们还允许我们检测瓶颈、业务指标和响应时间。例如，我们将使用 New Relic 监视我们的应用程序。

# New Relic

New Relic 是一个为我们整个环境提供仪表化的工具，而不仅仅是我们的应用程序。因此，我们可以监视我们应用程序的整个环境，包括数据库、应用程序服务器、负载均衡器等因素。

例如，我们将在以下链接创建一个试用账户（[`newrelic.com/signup`](https://newrelic.com/signup)）。注册了 New Relic 账户后，您将被引导到控制面板，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/54cd2652-036d-484f-80a0-6f85e5ec3ece.png)

我们将按以下步骤继续这个过程：

1.  选择监视应用程序并接受 14 天免费试用：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/791b2339-8423-4551-9197-520f2f4ebabf.png)

1.  选择 Java 应用程序选项：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/f823f831-4abe-4cc6-b023-036755c14777.png)

1.  生成许可证密钥，下载并安装代理。在这里，我们将在应用程序的根目录中创建一个名为`newrelic`的文件夹，并复制最近下载的 ZIP 文件的内容：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/da07a472-7cca-4175-b9cb-f718b6bbad83.png)

1.  现在，我们将用我们的密钥许可证和应用程序名称替换`newrelic.yml`，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/2bfb8361-e0c0-4205-8ba1-38b837964ed2.png)

1.  重新启动您的应用程序，包括`javaagent`参数，如下所示：

```java
-javaagent:/full/path/to/newrelic.jar
```

1.  在我们的情况下，使用代理运行应用程序将如下所示：

```java
java -javaagent:newrelic/newrelic.jar -jar build/libs/banking-app-1.0.jar
```

最后，我们可以看到我们的新遗物仪表板，与我们在`newrelic.yaml`文件中定义的名称相同（Banking App Monitoring Packt）。这将包含我们应用程序的所有信息：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/28cc6220-22e5-442e-89f0-187686a21967.png)

您还可以多次导航到应用程序，以查看 APM 提供的更多数据。

然后，我们可以深入了解提供的信息，包括以下内容：

+   响应时间：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/e8d633dd-5851-433e-b8e0-b29a61173975.png)

+   数据库指标：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/6bf3a771-e500-49cb-9d5d-0ebb20db3f77.png)

+   JVM 指标：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/76333a5a-d4ac-4c7b-a36c-dc211cf521bc.png)

+   Web 交易：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/74538b32-fe33-473f-b116-97ded2ed4ae5.png)

您可以从左侧菜单中探索所有选项卡，以查看我们应用程序的更多指标。正如我们所学到的，有了所有这些工具，我们可以确保应用程序的健康，并检查我们是否摆脱了问题和瓶颈。然后，您可以继续探索 APM。

# 摘要

在本章中，我们学习了如何从技术和业务角度收集有用的指标。我们还学习了如何使用 APM 来监视我们的环境，并获取我们需要的信息，以了解最常用交易的健康状况、状态和统计信息，包括我们应用程序的响应时间。所有这些信息将帮助我们在生产中维护我们的应用程序，并迅速应对任何可能的性能问题。

在下一章中，我们将审查安全实践以及如何使用 Spring 编写它们。


# 第十三章：安全

安全是开发团队在开发产品时经常忽视的领域。开发人员在编写代码时应牢记一些关键考虑因素。本章列出的大多数考虑因素都是显而易见的，但也有一些不是，因此我们将讨论所有这些考虑因素。

本章将涵盖以下主题：

+   为什么安全作为应用程序架构的一部分很重要

+   保持软件安全的关键建议：

+   认证和授权

+   加密

+   数据输入验证

+   敏感数据

+   社会工程学

+   渗透测试

+   认证作为服务

我们将首先介绍安全作为应用程序架构的重要性。

# 为什么安全作为应用程序架构的一部分很重要

在过去的几年里，我看到许多组织或公司在已经投入生产后才审查其软件安全问题的案例。这通常发生在他们的系统面临安全问题或业务因停机或数据泄露而损失资金时。

众所周知，安全问题和流程应作为软件开发生命周期（SDLC）的一部分。由于安全是应该考虑的每个应用程序的一个方面，因此必须确保我们的应用程序和代码具有安全约束，使我们能够在所有阶段（设计、开发、测试和部署）对我们的软件感到自信：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/598ebe0b-f094-42dc-be13-a423f0082059.png)

安全作为 SDLC 的一部分

我们的主要目标应该是在将应用程序交付到生产环境之前防止其被 compromise。这样可以避免暴露敏感数据，并确保应用程序在设计时考虑了可能的漏洞。理想情况下，我们应该在系统被客户使用之前解决所有安全问题。作为开发人员，我们大多数时候只收到功能需求。然而，有时我们并没有收到安全需求。在开发我们的代码和应用程序时，我们必须像关注性能、可扩展性和其他非功能性需求一样关注安全性。

编写旨在避免安全威胁的软件时需要牢记的一些关键方面如下：

+   系统很难解密

+   系统安全应该在 SDLC 的每个阶段进行测试。

+   应对应用程序执行渗透测试

+   系统应确保端到端的安全通信

+   应用程序代码中应用反网络钓鱼实践

在下一节中，我们将提供一系列应该遵循的建议，以解决在 SDLC 过程中的安全问题。

# 关键安全建议

有几种类型的攻击可以针对系统或网络，并可用于建立通信。常见的例子包括病毒、恶意软件、网络钓鱼、定向网络钓鱼、拒绝服务（DoS）等。每年都会发现更多复杂的攻击，目标各异。在本节中，我们将重点关注保护 Web 和移动应用程序的代码和环境的关键安全建议。

有几种可以用来确保 Web 和移动应用程序安全的流程和模型。在接下来的章节中，我们将探讨保护软件免受常见安全威胁的主要建议。

# 认证和授权

认证的最简单定义是验证用户身份的过程；授权是验证经过身份验证的用户可以做什么的过程。例如，当我们在计算机上以用户身份登录时，我们被授予访问权限，允许我们对可用资源执行操作（包括文件、应用程序等）。

在我们创建的应用程序中，身份验证是验证对应用程序的访问权限的过程，授权是保护我们的资源的过程，如页面、网络服务、数据库、文件、队列等。在身份验证过程中，我们验证使用应用程序的人的身份。身份验证包括诸如在提供有效凭据之前防止对我们应用程序的访问、多因素身份验证（如安全图像）、**一次性密码（OTP）**、令牌等过程。

关于实现，我们已经在之前的章节中使用了 Spring Security 创建了一些应用程序示例，Spring Security 是一个可扩展的框架，可用于保护 Java 应用程序。Spring Security 也可以用于处理身份验证和授权，使用一种对我们现有代码不具有侵入性的声明式样式。

今天，有几个身份行业标准、开放规范和协议，规定了如何设计身份验证和授权机制，包括以下内容：

+   **基本身份验证**：这是最常见的方法，涉及在每个请求中发送用户名和密码。我们已经在我们的银行应用示例中使用了 Spring Security 实现了这种方法，我们在第十章 *容器化您的应用程序*，第十一章 *DevOps 和发布管理*和第十二章 *监控*中使用了它。

+   **JSON Web Tokens**（**JWT**）：这是一个开放标准，定义了如何建立一个安全的机制，在两个参与者之间安全地交换消息（信息）。这里有几个经过充分测试的库可供使用，我们在第四章 *客户端-服务器架构*中创建了一个示例。该序列可以如下所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/eacccf78-9aa2-4f58-9bcd-2e9bdcb9c842.png)

JWT 身份验证流程

如前所述，前面的序列图可以帮助我们理解令牌验证的过程。对于身份验证，客户端应该将其凭据发送到服务器，服务器将以字符串形式响应一个令牌。这个令牌应该用于后续的请求。当它们被执行时，如果提供的令牌无效或过期，我们将从服务器收到 401 未经授权的状态代码。否则，请求将成功。我们之前提到的身份验证机制遵循基本身份验证模型，这是 Web 应用程序的首选。然而，当您编写 API 时，您将需要其他方法，以处理基于令牌使用的安全性（如 JWT）。如果您不编写 API，您的应用程序可以使用 JSON Web Tokens RFC（[`tools.ietf.org/html/rfc7519`](https://tools.ietf.org/html/rfc7519)）进行安全保护。

今天，这是验证移动应用程序、现代单页应用程序（SPA）和 REST API 的最常见方法。

让我们回顾一些围绕使用令牌的身份验证机制创建的标准：

+   **OAuth**（**开放授权**）：这是一种基于令牌的身份验证和授权的开放标准，可以使用第三方参与者委托身份验证过程。只有在您有三方：您自己、您的用户和需要您的用户数据的第三方应用程序开发人员时，才应使用此标准。

+   **OAuth 2**：这是 OAuth 标准的更发达版本，允许用户在不提供凭据的情况下授予有限访问权限，以将资源从一个应用程序转移到另一个应用程序。每当您使用 Google 或 GitHub 帐户登录网站时，都应该使用此标准。这样做时，您将被问及是否同意分享您的电子邮件地址或帐户。

+   **完整请求签名**：这是由 AWS 身份验证推广的，也在第九章中探讨了*无服务器架构*，当我们演示将**函数作为服务**（**FaaS**）部署到 AWS 时。我们使用这个概念通过在服务器和客户端之间共享一个秘密。客户端使用共享的秘密对完成的请求进行签名，服务器对其进行验证。有关更详细的信息，请访问[`docs.aws.amazon. com/general/latest/gr/sigv4_si gning.html`](http://docs.aws.amazon.%20com/general/latest/gr/sigv4_si%20gning.html)。

# 密码学

密码学是将文本信息转换为不可理解的文本，反之亦然：从加密文本到可理解的文本。在我们的应用程序中，我们使用密码学来创建数据的保密性并保护它免受未经授权的修改。

我们使用加密来加密客户端和服务器之间的通信。这是通过使用**传输层安全（TLS）**协议的公钥加密来完成的。TLS 协议是**安全套接字层（SSL）**协议的后继者。

# 数据输入验证

数据输入验证是指控制每个集成或层中接收的数据的过程。我们需要验证数据输入，以避免在系统中创建任何不一致性。换句话说，我们应该验证应用程序中的数据是一致的，并且不会遇到与 SQL 注入、资源对应用程序或服务器的控制等问题。更高级的技术包括白名单验证和输入类型验证。

# 敏感数据

这种做法涉及保护敏感数据并确定如何以正确的方式进行。数据敏感性涉及使用加密来保护数据的机密性或完整性和冗余。

例如，通常在我们的应用程序用于连接到数据库的密码中使用无意义的文本，因此我们通过保持凭据加密来使这个建议准确。另一个例子可能涉及在银行应用程序上工作并需要呈现信用卡号。在这种情况下，我们会加密该数字，甚至可能掩盖该数字，使其对人类不可读。

# 社会工程

为了帮助您理解什么是社会工程，我们将提供一个简单的定义；即，对一个人的心理操纵，以便该人提供机密信息。

以这个定义为起点，社会工程已经成为应用程序难以控制的安全问题。这是因为失败的关键在于用户是一个人类，有能力被分析和操纵，以便交出秘密信息或凭据，从而可能访问系统。

# OWASP 十大

**开放式 Web 应用程序安全项目（OWASP）**十大列出了 Web 应用程序中最重要的十个安全风险，并由 OWASP 组织每三年发布和更新一次。我们需要遵循 OWASP 清单，以确保我们的 Web 应用程序不会留下安全漏洞。清单可以在[`www.owasp.org/images/7/72/OWASP_Top_10-2017_%28en%29.pdf.pdf`](https://www.owasp.org/images/7/72/OWASP_Top_10-2017_%28en%29.pdf.pdf)[.](https://www.owasp.org/images/7/72/OWASP_Top_10-2017_%28en%29.pdf.pdf)找到。

2017 年发布的最新清单包括以下方面：

+   A1: 注入

+   A2: 身份验证和会话管理出现问题

+   A3: **跨站脚本**（**XSS**）

+   A4: 不安全的直接对象引用

+   A5: 安全配置错误

+   A6: 敏感数据暴露

+   A7: 缺失功能级访问控制

+   A8: **跨站请求伪造**（**CSRF**）

+   A9: 使用已知漏洞的组件

+   A10: 未经验证的重定向和转发

要测试和验证其中几个漏洞，我们可以使用 Burp 套件（[`portswigger.net/burp`](https://portswigger.net/burp)）。这个过程很容易理解，并且将检查应用程序中大多数已知的安全漏洞。作为一个工具，Burp 随 Kali Linux 发行版一起提供，我们将在下一节中解释。

# 渗透测试

**渗透测试（pen test）**是对系统进行模拟攻击以评估其安全性。对于这个测试，我们可以使用像 Kali Linux（[`www.kali.org/`](https://www.kali.org/)）这样的工具，它是一个基于 Debian 的 Linux 发行版，具有用于验证 OWASP 前 10 名等多种工具的渗透测试平台。

Kali 有一个广泛的工具列表，可用于多种用途，如无线攻击、信息收集、利用和验证 Web 应用程序等。如果您想查看详细的工具列表，请访问以下链接：[`tools.kali.org/tools-listing`](https://tools.kali.org/tools-listing)。团队在将应用程序交付到生产环境之前应提供渗透测试。

在下一节中，我们将创建一个基于 Spring Security 的 Java 应用程序。我们将使用 Auth0 作为身份验证和授权服务平台，这是一个基于 OAuth2 标准和 JWT 的第三方授权。

# 身份验证和授权作为服务

我们将使用 Auth0 作为身份验证和授权服务的提供者。我们将创建一个示例来保护我们的应用程序；您不必是安全专家才能做到这一点。以下截图来自 Auth0 入门指南：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/99af84d6-085d-4ccc-9eb6-69a9881c762d.png)Auth0 身份验证和身份验证过程

当我们插入或连接到 Auth0 后，这将成为用于验证其身份并将所需信息发送回应用程序的身份验证和授权服务器，每当用户尝试进行身份验证时。

我们不仅限于 Java；Auth0 为不同的技术和语言提供了多个 SDK 和 API。

使用 Auth0 创建身份验证和授权服务的示例的步骤如下：

1.  在 Auth0 上创建您的免费开发者帐户：[`auth0.com/`](https://auth0.com/)。

1.  登录到 Auth0 门户并创建一个应用程序：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/2943a2d8-8e4e-4d3e-a81a-82303ee5da2f.png)

Auth0 创建应用程序

1.  为应用程序命名，然后选择“常规 Web 应用程序”选项，其中包括 Java 应用程序（您还可以创建原生移动应用程序、单页应用程序和**物联网**（**IoT**））：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/5d88efe8-9be6-4310-955b-34ce4b038238.png)

1.  选择一个使用 Spring Security 的示例应用程序。

1.  点击“下载应用程序”并将项目文件夹更改为`packt-secure-sample`。

要运行示例，我们需要在我们创建的应用程序的设置选项卡中设置**回调 URL**（`http://localhost:3000/callback`）。

要在控制台上运行此示例，请在示例目录中执行以下命令：

```java
# In Linux / macOS./gradlew clean bootRun
# In Windowsgradlew clean bootRun
```

您可以在以下 URL 查看应用程序，`http://localhost:3000/`：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/47495cee-1d34-4ed1-88a5-9b27a7336b89.png)

请注意，应用程序登录页面会重定向到 Auth0。当我们通过第三方应用程序登录，通过我们的 Google 帐户或通过 Auth0 提供的凭据登录后，我们将看到生成的令牌的以下结果：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/463f6bfd-ff5d-4218-8a62-fbc5fecdb729.png)

您现在已经学会了如何使用 Auth0 作为身份验证和授权服务的平台，使用 OAuth2 和 JWT 等标准。

# 总结

在本章中，我们解释了如何应用安全准则和实践，以涵盖您的应用程序可能遇到的最常见安全问题。在这里，我们涵盖了身份验证和授权、加密、数据输入验证、敏感数据、OWASP 十大安全风险、社会工程和渗透测试。这些概念和方法将加强您的应用程序的安全性。

在下一章中，我们将回顾高性能技术和建议，以完成使用 Spring 5 创建应用程序的旅程。


# 第十四章：高性能

当应用程序以意外的方式表现时，不得不处理生产中的问题比任何事情都更令人失望。在本章中，我们将讨论一些简单的技术，可以应用这些技术来摆脱这些令人讨厌的问题，将简单的建议应用到您的日常工作中，以照顾您的应用程序的性能。在本章中，我们将讨论以下主题：

+   为什么性能很重要

+   可扩展性

+   可用性

+   性能

+   使您的软件远离性能问题的关键建议

+   应用程序分析

+   SQL 查询优化

+   负载测试

让我们从介绍性能的重要性开始。

# 为什么性能很重要

在过去的 20 年里，作为顾问，我访问了几家政府机构、银行和金融机构，建立了一个共同因素，即在生产中工作的应用程序缺乏性能，并且我发现了一些常见问题，如果您在 SDLC 的一部分中使用一套良好的实践，这些问题是可以避免的。

关注性能很重要，因为它给公司、项目发起人和客户带来了巨大的麻烦，因为面临这个问题的应用程序会在多个层面上带来不满。

在给出建议之前，我们将审查和了解可扩展性、可用性和性能的非功能性需求。

# 可扩展性

这描述了系统处理高工作负载并根据工作需求增加其容量以解决更多请求的能力。

# 水平扩展性

通过添加具有系统所有功能的额外节点来解决这个问题，重新分配请求，如下图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/07407738-e2aa-4e2b-8a7c-2824e2c98a6f.png)

水平扩展性

# 垂直扩展性

我们通过向节点或服务器添加资源（如 RAM、CPU 或硬盘等）来使用垂直扩展，以处理系统的更多请求。我看到的一个常见做法是向数据库服务器添加更多硬件，以更好地执行正在使用它的多个连接；我们只能通过添加更多资源来扩展服务，如下图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/c711bfde-11e4-4757-9e8d-66adcf3157ca.png)

垂直扩展性

# 高可用性

这指的是系统持续提供服务或资源的能力。这种能力直接与服务级别协议（SLA）相关。

SLA 是根据系统的维护窗口计算的，SLA 定义了系统是否应该扩展或扩展。

# 性能

这是系统对在给定时间间隔内执行任何操作的响应能力。作为软件系统的一部分，我们需要开始定义可衡量的性能目标，如下所示：

+   最小或平均响应时间

+   平均并发用户数量

+   高负载或并发时每秒的请求次数

作为开发人员，我们今天面临的主要挑战是我们的应用程序必须处理的客户和设备数量，甚至更重要的是，我们的应用程序是否将在互联网上运行还是仅在内部网络中运行。下图显示了应用程序通常部署和使用的拓扑结构：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/dd66e4d6-2cec-4366-a347-5bfaa97bf0ff.png)

对系统的高负载请求

在了解性能、可扩展性和可用性的主要概念之后，让我们回顾一些增加应用程序性能的关键建议。

# 避免性能问题的关键建议

通常使用负载测试工具、**应用程序性能监视器**（**APM**）和分析工具来查找和解决软件系统中的性能问题。为了模拟生产中的用户数量，我们需要运行负载测试-为系统的最常用功能创建场景，并同时跟踪和监视应用程序健康状况-测量 CPU、RAM、IO、堆使用、线程和数据库访问等资源。在这个过程的输出中，我们可以给出一些关键建议，以避免软件出现性能问题。

在接下来的部分中，我们将解释我们可能遇到的最常见的瓶颈以及如何避免它们。

# 识别瓶颈

企业应用程序每天变得更加复杂。当业务成功时，支持该业务的应用程序将拥有更多用户，这意味着每天都会收到更大的负载，因此我们需要注意可能出现的性能瓶颈。

理解术语**瓶颈**，我们将给出一个简单的定义。在软件系统中，当应用程序或系统的功能开始受到单个组件的限制时，就会出现瓶颈，就像比较瓶颈减慢整体水流一样。

换句话说，如果我们的应用程序开始表现缓慢或开始超出预期的响应时间，我们就可以看到瓶颈。这可能是由于不同类型的瓶颈引起的，例如以下情况：

+   **CPU**：当此资源繁忙且无法正确响应系统时会发生这种情况。当我们开始看到 CPU 利用率在较长时间内超过 80%时，通常会开始出现这种瓶颈。

+   **内存**：当系统没有足够的 RAM 或快速 RAM 时会发生这种情况。有时应用程序日志显示内存不足异常或内存泄漏问题。

+   **网络**：与必要带宽的缺乏有关

+   应用程序本身、代码问题、太多未受控制的异常、资源使用不当等

使用 APM 来识别瓶颈是一个不错的方法，因为 APM 可以在不减慢应用程序性能的情况下收集运行时信息。

要识别瓶颈，我们可以使用一些实践方法；负载测试和监控工具，或分析工具。接下来的部分将解释分析工具。

# 应用程序性能分析

我们可以查看我们的代码，并开始分析我们怀疑存在性能问题的系统部分，或者我们可以使用分析工具并获取有关整个系统的信息。这些工具收集运行时数据，并监视 CPU、内存、线程、类和 I/O 的资源消耗。

有几种可用于分析 Java 应用程序的工具，包括以下内容：

+   与 JVM 一起提供的工具，如 VisualVM、JStat、JMap 等

+   专门的工具，如 JProfiler、Java Mission Control 和 Yourkit

+   轻量级分析器，如 APM 中提供的那些，就像我们在第十二章中看到的那样，*监控*，使用 New Relic

# Visual VM

这是作为 JDK 的一部分集成的可视化工具，具有分析应用程序的能力。让我们运行我们之前章节中的银行应用程序，并查看我们可以使用它收集哪些信息。

要运行我们之前的银行应用程序，请转到项目文件夹，并通过命令行运行以下命令：`java -jar build/libs/banking-app-1.0.jar`。

现在，我们将使用 VisualVM 收集有关 JVM 的一些指标。我们可以通过以下命令从控制台运行此工具：

```java
$ cd JAVA_HOME/bin
$ jvisualvm
```

我们应该看到类似以下截图的屏幕：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/12186fb2-07fe-45c2-b73c-7ffc34c653db.png)

Java VisualVM

使用“本地”菜单选项，您必须附加要监视的 Java 进程。在这种情况下，我们将选择 banking-app-1.0.jar。然后，我们应该看到应用程序使用的资源的摘要：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/6ec75a25-90ec-4440-a3a1-3602ac6a55c5.png)

VisualVM CPU、RAM、类和线程

还有一个选项卡提供有关线程的信息，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/1893b4e3-a122-471f-ab36-236c5f8e778c.png)

VisualVM 线程

我们可以使用任何我们感觉舒适的工具；一个很好的起点，也是一个易于使用的工具是 Jprofiler，但所有的工具都给我们提供类似的信息。我们需要了解并遵循我们应用程序中发现的任何瓶颈可能引发的问题。

在生产中调试性能问题可能是一项困难的任务，在某些情况下很难找到和修复。我们需要一个让我们信任的工具来理解瓶颈，因此我们需要尝试不同的工具并进行负载测试，以找到适合我们的正确工具。

在您知道有必要优化之前不要进行优化；首先运行应用程序并运行负载测试，看看我们是否可以满足性能的非功能性需求。

# SQL 查询优化

优化企业应用程序的查询和数据访问层对于避免瓶颈和性能问题至关重要。我们可以使用 New Relic 作为 APM，这将帮助我们使用数据库访问图形来检测瓶颈和性能问题。通过这些图形，我们可以找到应用程序使用的 SQL 语句，找到延迟事务或阻塞表，如果我们继续深入信息，还可以找到使用最多的 SQL 语句和管理的连接数，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/414aa751-dcba-464d-8f68-40dc3a952b0a.png)

来自 New Relic 的数据库指标

从应用程序中，我们可以识别最常用的查询，并寻找优化的机会。我们需要索引或重构我们的代码以获得更好的性能。另一方面，如果不使用 APM 或分析工具，我们可以使用许多技术来改进我们的 SQL 和数据访问层，例如以下内容：

+   **审查 SQL 语句**：这通过分析器或 APM 逐个审查和优化执行的 SQL 语句，应用索引，选择正确的列类型，并在必要时使用本地查询优化关系。

+   **JDBC 批处理**：这使用`prepared`语句进行批处理，一些数据库如 Oracle 支持`prepared`语句的批处理。

+   **连接管理**：这审查连接池的使用，并测量和设置正确的池大小。

+   **扩展和扩展**：这在*可扩展性*部分有解释。

+   **缓存**：这使用内存缓冲结构来避免磁盘访问。

+   **避免 ORM**：**对象关系映射**（**ORM**）工具用于将数据库表视为 Java 对象以持久化信息。然而，在某些情况下，最好使用普通的 SQL 语句来避免不必要的连接，从而提高应用程序和数据库的性能。

在下一部分，我们将看看如何模拟虚拟用户以创建应用程序的负载测试。

# 负载测试示例

负载测试用于检查应用程序在一定数量的并发用户使用后的行为；并发用户的数量是指应用程序在生产中将具有的用户数量。您应该始终定义一个性能测试套件，使用以下工具测试整个应用程序：

+   Neoload

+   Apache JMeter

+   Load Runner

+   负载 UI

+   Rational Performance Tester

我们需要定义一个负载测试和配置文件作为我们应用程序的流水线的一部分，并在我们进行性能改进之前和之后运行它。我们将使用 Neoload 创建一个示例，以审查我们应用程序示例中的这些关键建议。

首先，我们需要定义一个场景来运行负载测试；在我们的情况下，我们将使用第十二章中的银行应用程序，*监控*，它已经准备好使用，并定义一个功能常见的场景，如下所示：

1.  用户将使用以下凭据登录：`rene`/`rene`。

1.  然后，用户将点击菜单通知。

1.  最后，用户将点击注销链接。

首先，我们将从以下 URL 下载 Neoload：[`www.neotys.com/download.`](https://www.neotys.com/download)

Neoload 为我们提供了一个试用版本，我们可以模拟最多 50 个虚拟并发用户。

安装 Neoload 后，我们将打开应用程序并创建一个项目：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/e59455fe-eb5c-40d5-b289-2182c806683e.png)

然后，我们将点击开始录制，并选择我们将用于记录应用程序的浏览器：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/fa10d02d-71cf-42dd-ba4a-32b9237dd5c8.png)

然后，在浏览器中，我们将输入我们应用程序的 URL：`http://localhost:8080/login`，并作为用户导航到我们客户的通知集。因此，流程如下：

1.  登录

1.  点击菜单通知

1.  点击注销

选择我们正在记录的主机，即本地主机，并按照下一步的说明进行操作，直到结束。最后，我们将点击停止录制按钮，并且我们应该在左侧菜单中看到我们的操作已记录：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/91ed11b1-338d-45f3-82d7-8e731a976a2b.png)

然后，我们将通过点击悬停在用户图标上方的复选图标来运行记录的场景：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/718b6a6a-f4f9-410b-ab1e-0f80fed17c72.png)

我们应该看到我们的场景在没有错误的情况下运行，模拟一个并发用户，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/cb15e5b7-4176-49e9-8745-62e657e0cd3f.png)

现在，让我们生成负载测试，创建一个人口（模拟用户场景）：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/c427bd33-70c5-4ab1-8234-d85a170faedd.png)

然后，点击运行时图标，以使用 10 个并发用户在 2 分钟内运行负载测试：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/ffe1f2a6-dbb2-4414-8004-2f9ec8ffbc55.png)

然后，点击播放图标：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/05c9f54d-0d3c-4142-895f-2e78e442a949.png)

最后，在测试完成后，我们可以检查结果；在负载测试期间，我们访问了 670 页并发出了 890 个请求，使用 20 个并发用户：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/953bb0e2-b9a5-4bac-b8f6-cb429f645b20.png)

另一方面，在使用 VisualVM 进行负载测试时，我们可以检查应用程序的性能，并查看它在检查线程时的表现，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/16bfcc40-b147-4764-858a-1cf091d3e859.png)

我们将发现，使用虚拟用户模拟时，JVM、内存和线程看起来与在应用程序上导航时有所不同。

在运行负载测试时，监控应用程序的所有资源是值得的，以确定问题可能出现的位置。

最后，我们已经学会了使用性能分析工具或 APM，除了负载测试工具，可以确保我们的应用程序和系统在将代码发布到生产环境之前进行性能改进。

在添加代码以改进应用程序性能后，总是一个好主意运行性能测试，以检查更改的实施情况。

# 总结

在本章中，我们解释了可伸缩性、可用性和性能的含义。我们还学会了如何应用一些技术和工具，以避免在生产中处理性能问题，因此，我们如何改进我们的应用程序以实现更好的响应时间。
