# Docker 故障排除手册（二）

> 原文：[`zh.annas-archive.org/md5/26C3652580332746A9E26A30363AEFD3`](https://zh.annas-archive.org/md5/26C3652580332746A9E26A30363AEFD3)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：设计微服务和 N 层应用程序

让我们扩展上一章中所看到和学到的关于微服务和 N 层应用程序更高级的开发和部署。本章将讨论这些设计方法的基础架构，以及在构建这些类型的应用程序时遇到的典型问题。本章将涵盖以下主题：

+   单片架构模式

+   N 层应用程序架构

+   构建、测试和自动化 N 层应用程序

+   微服务架构模式

+   构建、测试和自动化微服务

+   将多层应用程序解耦为多个图像

+   使不同层的应用程序运行

如今，作为服务构建的现代软件正在引发应用程序设计方式的转变。如今，应用程序不再使用 Web 框架来调用服务和生成网页，而是通过消费和生成 API 来构建。在业务应用程序的开发和部署方面发生了许多变化，其中一些变化是戏剧性的，另一些变化是根据过去的设计方法进行修订或扩展的，这取决于您的观点。存在几种架构设计方法，它们可以通过为企业构建的应用程序与为 Web 构建的应用程序与云构建的应用程序进行区分。

在过去几年的发展趋势中，充斥着诸如**微服务架构**（MSA）之类的术语，这些术语适用于一种特定的应用程序设计和开发方式，即独立部署的服务套件。微服务架构风格的迅猛崛起显然是当今开发部署中不可否认的力量；从单片架构到 N 层应用程序和微服务的转变是相当大的，但这究竟有多少是炒作，有多少可以被磨练？

# 炒作还是自负

在我们开始深入研究故障排除之前，我们应该对现代应用程序以及 N 层和微服务架构风格进行基本的上下文概述。了解这些架构风格的优势和局限将有助于我们规划潜在的故障排除领域，以及我们如何避免它们。容器非常适合这两种架构方法，我们将分别讨论每种方法，以便给予它们适当的重视。

在所有的噪音中，我们有时会忘记，要在这些领域部署系统，仍然需要创建服务，并在工作的分布式应用程序中组合多个服务。在这里，重要的是要理解术语“应用程序”的现代含义。应用程序现在主要是构建为异步消息流或同步请求调用（如果不是两者兼而有之），这些消息流或请求调用用于形成由这些连接联合的组件或服务的集合。参与的服务高度分布在不同的机器和不同的云（私有、公共和混合）之间。

关于建筑风格，我们不会过多比较或进行过于详细的讨论，关于微服务到底是什么，以及它们是否与面向服务的架构（SOA）有任何不同-在其他地方肯定有很多论坛和相关的辩论可供选择。以 Unix 至少根植的设计原则为基础，我们在本书中不会提出任何权威观点，即当前的微服务趋势是概念上独特的或完全巧妙的。相反，我们将提出实施这种架构方法的主要考虑因素以及现代应用程序可以获得的好处。

用例仍然驱动和决定架构方法（或者，在我看来，应该如此），因此在所有主要的架构风格之间进行一定程度的比较分析是有价值的：单体、N 层和微服务。

# 单体架构

单体应用本质上是一个部署单元，包含所有服务和依赖关系，使其易于开发、易于测试、相对容易部署，并且最初易于扩展。然而，这种风格不符合大多数现代企业应用程序（N 层）和大规模 Web 开发的必要需求，当然也不适用于部署到云端的微服务应用程序。变更周期紧密耦合-对应用程序的任何更改，甚至是最小的部分，都需要对整个单体进行全面重建和重新部署。随着单体的成熟，任何尝试扩展都需要扩展整个应用程序而不是单个部分，这特别需要更多的资源，变得非常困难，甚至不可能。在这一点上，单体应用程序变得过于复杂，充斥着越来越难以解读的大量代码，以至于像错误修复或实施新功能这样的业务关键项目变得太耗时，根本无法尝试。随着代码库变得难以理解，可以合理地预期任何更改可能会出现错误。应用程序的不断增长不仅减缓了开发速度，而且完全阻碍了持续开发；要更新单体的任何部分，必须重新部署整个应用程序。

![单体架构](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/Untitled.jpg)

单体架构模式

单体应用程序的其他问题也很多，资源无法更好地满足需求，例如 CPU 或内存需求。由于所有模块都在运行相同的进程，任何错误都有可能导致整个进程停止。最后，更难以采用新的框架或语言，这给采用新技术带来了巨大障碍-您可能会被困在项目开始时所做的技术选择中。不用说，自项目开始以来，您的需求可能已经发生了相当大的变化。使用过时的、低效的技术使得留住和引进新人才变得更加困难。应用程序现在变得非常难以扩展和不可靠，使得敏捷开发和交付应用程序变得不可能。单体应用程序最初的简单和便利很快变成了它自己的致命弱点。

由于这些单片架构基本上是一个执行单元，可以完成所有任务，N 层和微服务架构已经出现，以解决现代化应用程序，主要是云和移动应用程序的专门服务需求。

# N 层应用架构

为了理解 N 层应用程序及其分解为微服务的潜力，我们将其与单片样式进行比较，因为 N 层应用程序的开发和微服务的普及都是为了解决单片架构所带来的过时条件中发现的许多问题。

N 层应用架构，也称为**分布式应用**或**多层**，提供了一个模型，开发人员可以创建灵活和可重用的应用程序。由于应用程序被分为多个层，开发人员可以选择修改或添加特定的层或层，而不需要对整个应用程序进行重新设计，这在单片应用程序下是必要的。多层应用程序是指分布在多个层之间的任何应用程序。它在逻辑上分离了不同的应用程序特定和操作层。层的数量根据业务和应用程序要求而变化，但三层是最常用的架构。多层应用程序用于将企业应用程序划分为两个或多个可以分别开发、测试和部署的组件。

N 层应用程序本质上是 SOA，试图解决过时的单片设计架构的一些问题。正如我们在之前的章节中所看到的，Docker 容器非常适合 N 层应用程序开发。

![N 层应用架构](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/Untitled-1.jpg)

N 层应用架构

一个常见的 N 层应用程序由三层组成：**表示层**（提供基本用户界面和应用程序服务访问）、**领域逻辑层**（提供用于访问和处理数据的机制）和**数据存储层**（保存和管理静态数据）。

### 注意

虽然层和层经常可以互换使用，但一个相当普遍的观点是实际上存在差异。这个观点认为*层*是构成软件解决方案的元素的逻辑结构机制，而*层*是系统基础设施的物理结构机制。除非在我们的书中另有特别说明，否则我们将互换使用层和层。

将各种层在 N 层应用程序中分开的最简单方法是为您的应用程序中要包含的每个层创建单独的项目。例如，表示层可能是一个 Windows 表单应用程序，而数据访问逻辑可能是位于中间层的类库。此外，表示层可能通过服务与中间层的数据访问逻辑进行通信。将应用程序组件分离到单独的层中可以增加应用程序的可维护性和可扩展性。它可以通过使新技术更容易地应用于单个层而无需重新设计整个解决方案来实现这一点。此外，N 层应用程序通常将敏感信息存储在中间层中，以保持与表示层的隔离。

N 层应用程序开发的最常见示例可能是网站；在我们上一章中使用的`cloudconsulted/joomla`镜像中可以看到这样的示例，其中 Joomla、Apache、MySQL 和 PHP 都被*分层*为单个容器。

对我们来说，很容易简单地递归使用我们之前的`cloudconsulted/joomla`镜像，但让我们构建一个经典的三层 Web 应用程序，以暴露自己于一些其他应用潜力，并为我们的开发团队引入另一个单元测试工具。

## 构建一个三层 Web 应用程序

让我们借助以下容器开发和部署一个真实的三层 Web 应用程序：

NGINX > Ruby on Rails > PostgreSQL：

NGINX Docker 容器（Dockerfile）如下：

```
## AngularJS Container build  
FROM nginx:latest 

# Download packages 
RUN apt-get update 
RUN apt-get install -y curl   \ 
                   git    \ 
                   ruby \ 
                   ruby-dev \     
                   build-essential 

# Copy angular files 
COPY . /usr/share/nginx 

# Installation 
RUN curl -sL https://deb.nodesource.com/setup | bash - 
RUN apt-get install -y nodejs \ 
                  rubygems 
RUN apt-get clean 
WORKDIR /usr/share/nginx 
RUN npm install npm -g 
RUN npm install -g bower 
RUN npm install  -g grunt-cli 
RUN gem install sass 
RUN gem install compass 
RUN npm cache clean 
RUN npm install 
RUN bower -allow-root install -g 

# Building 
RUN grunt build 

# Open port and start nginx 
EXPOSE 80 
CMD ["/usr/sbin/nginx", "-g", "daemon off;"]

```

如图所示的 Ruby on Rails Docker 容器（Dockerfile）：

```
## Ruby-on-Rails Container build 
FROM rails:onbuild 

# Create and migrate DB 
RUN bundle exec rake db:create 
RUN bundle exec rake db:migrate 

# Start rails server 
CMD ["bundle", "exec", "rails", "server", "-b", "0.0.0.0"]

```

如图所示的 PostgreSQL Docker 容器：

```
## PostgreSQL Containers build 
# cloudconsulted/postgres is a Postgres setup that accepts remote connections from Docker IP (172.17.0.1/16).  We can therefore make use of this image directory so there is no need to create a new Docker file here.

```

上述 Dockerfile 可用于部署三层 Web 应用程序，并帮助我们开始使用微服务。

# 微服务架构

要开始解释微服务架构风格，将有利于再次与单片进行比较，就像我们在 N 层中所做的那样。您可能还记得，单片应用是作为一个单一单位构建的。还要记住，单片企业应用通常围绕三个主要层构建：客户端用户界面（包括在用户机器上的浏览器中运行的 HTML 页面和 JavaScript）、数据库（包括插入到一个常见且通常是关系型数据库管理系统中的许多表）和服务器端应用程序（处理 HTTP 请求，执行领域逻辑，从数据库中检索和更新数据，并选择和填充要发送到浏览器的 HTML 视图）。这种经典版本的单片企业应用是一个单一的逻辑可执行文件。对系统的任何更改都涉及构建和部署服务器端应用程序的新版本，并且更改底层技术可能是不明智的。

## 通往现代化的道路

微服务代表了现代云和现代应用开发的融合，围绕以下结构：

+   组件化服务

+   围绕业务能力的组织

+   产品，而不是项目

+   智能端点和愚蠢的管道

+   分散式治理和数据管理

+   基础设施自动化

在这里，单片通常侧重于用于集成单片应用的企业服务总线（ESB），现代应用设计是 API 驱动的。这些现代应用在各个方面都采用 API：在前端用于连接富客户端，在后端用于与内部系统集成，并在侧面允许其他应用访问其内部数据和流程。许多开发人员发现，与更复杂的传统企业机制相比，那些已被证明对前端、后端和应用程序之间的场景具有弹性、可扩展性和敏捷性的轻量级 API 服务也可以用于应用程序组装。同样引人注目的是，容器，尤其是在微服务架构方法中，缓解了开发人员被阻止参与架构决策的永恒问题，同时仍然实现了可重复性的好处。使用经过预先批准的容器配置。

### 微服务架构模式

在这里，我们说明了，我们没有一个单一的庞大的单片应用程序，而是将应用程序分割成更小、相互连接的服务（即微服务），每个功能区域实现一个。这使我们能够直接部署以满足专用用例或特定设备或用户的需求，或者微服务方法，简而言之，规定了我们不是拥有所有开发人员都接触的一个巨大的代码库，这通常变得难以管理，而是由小而敏捷的团队管理的许多较小的代码库。这些代码库之间唯一的依赖是它们的 API：

微服务架构模式

微服务架构模式

### 注意

围绕微服务的一个常见讨论是关于这是否只是 SOA。在这一点上存在一些有效性，因为微服务风格确实分享了 SOA 的一些主张。实际上，SOA 意味着许多不同的事情。因此，我们提出并将尝试表明，虽然存在共同的相似之处，但 SOA 与此处所呈现的微服务架构风格仍然存在显着差异。

### 微服务的共同特征

虽然我们不会尝试对微服务架构风格进行正式定义，但有一些共同的特征我们当然可以用来识别它。微服务通常围绕业务能力和优先级进行设计，并包括多个组件服务，可以独立自动化部署，而不会影响应用程序、智能端点和语言和数据的分散控制。

为了提供一些基础，如果不是共同的基础，以下是一个可以被视为符合*微服务*标签的架构的共同特征的概述。应该理解的是，并非所有的微服务架构都会始终展现所有的特征。然而，我们期望大多数微服务架构将展现大部分这些特征，让我们列举一下：

+   独立

+   无状态

+   异步

+   单一职责

+   松散耦合

+   可互换

### 微服务的优势

我们刚刚列出的微服务的共同特征也用于列举它们的优势。而不是要过多地重复，让我们至少审视一下主要的优势点：

+   微服务强制实施一定程度的模块化：这在单片架构中实际上非常难以实现。微服务的优势在于单个服务开发速度更快，更容易理解，更容易维护。

+   微服务使每个服务能够独立开发：这是由专门专注于该服务的团队完成的。微服务的优势在于赋予开发人员选择最适合或更合理的技术的自由，只要该服务遵守 API 合同。这也意味着开发人员不再被困在项目开始时或开始新项目时可能过时的技术中。不仅存在使用当前技术的选项，而且由于服务规模相对较小，现在还可以使用更相关和可靠的技术重写旧服务。

+   微服务使每个服务能够持续部署：开发人员无需协调局部更改的部署。微服务的优势在于持续部署-只要更改成功测试，部署就会立即进行。

+   微服务使每个服务能够独立扩展：您只需部署每个服务实例以满足容量和可用性约束。此外，我们还可以简洁地匹配硬件以满足服务的资源需求（例如，为 CPU 和内存密集型服务优化的计算或内存优化硬件）。微服务的优势在于不仅匹配容量和可用性，而且利用为服务优化的用户特定硬件。

所有这些优势都非常有利，但接下来让我们详细阐述可伸缩性的观点。正如我们在单片架构中所看到的，虽然易于初始化扩展，但在随着时间的推移执行扩展时显然存在不足；瓶颈随处可见，最终，其扩展方法是极不可行的。幸运的是，作为一种架构风格，微服务在扩展方面表现出色。一本典型的书，《可伸缩性的艺术》（[`theartofscalability.com/`](http://theartofscalability.com/)）展示了一个非常有用的三维可伸缩性模型，即*可伸缩性立方体*（[`microservices.io/articles/scalecube.html`](http://theartofscalability.com/)）。

### 可伸缩的微服务

在提供的模型中，沿着 X 轴进行扩展（即，单体应用程序），我们可以看到常见的水平复制方法，通过在负载平衡器后运行应用程序的多个克隆副本来扩展应用程序。这将提高应用程序的容量和可用性。

![可扩展的微服务](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_04_004.jpg)

可扩展的微服务

在 Z 轴上进行扩展（即 N 层/SOA），每个服务器运行代码的相同副本（类似于 X 轴）。这里的区别在于每个服务器仅负责严格的数据子集（即数据分区或通过将数据拆分为相似的内容进行扩展）。因此，系统的某个组件负责将特定请求路由到适当的服务器。

### 注意

**分片**是一种常用的路由标准，其中使用请求的属性将请求路由到特定服务器（例如，行的主键或客户的身份）。

与 X 轴扩展一样，Z 轴扩展旨在提高应用程序的容量和可用性。然而，正如我们在本章中所了解的，单体或 N 层方法（X 和 Y 轴扩展）都无法解决我们不断增加的开发和应用程序复杂性的固有问题。要有效地解决这些问题，我们需要应用 Y 轴扩展（即，微服务）。

扩展的第三个维度（Y 轴）涉及功能分解，或通过将不同的内容拆分来进行扩展。在应用程序层发生的 Y 轴扩展将把单体应用程序分解为不同的服务集，其中每个服务实现一组相关功能（例如，客户管理，订单管理等）。在本章后面，我们将直接探讨服务的分解。

我们通常可以看到的是利用了扩展立方体的三个轴的应用程序。Y 轴扩展将应用程序分解为微服务；在运行时，X 轴扩展在负载平衡器后执行每个服务的多个实例，以增强输出和可用性，一些应用程序可能还会使用 Z 轴扩展来分区服务。

### 微服务的缺点

让我们通过了解一些微服务的缺点来全面尽职调查：

+   **基于微服务的应用部署要复杂得多**：与单片应用相比，微服务应用通常由大量服务组成。事实上，我们在部署它们时会面临更大的复杂性。

+   **管理和编排微服务要复杂得多**：在大量服务中，每个服务都将有多个运行时实例。随着更多需要配置、部署、扩展和监控的移动部件的指数级增加。因此，任何成功的微服务部署都需要开发人员对部署方法进行更细粒度的控制，同时结合高水平的自动化。

+   **测试微服务应用要复杂得多**：为微服务应用编写测试类不仅需要启动该服务，还需要启动其依赖服务。

一旦理解，我们就可以制定策略和设计来减轻这些缺点，并更好地规划故障排除领域。

### 制定微服务的考虑

我们已经审查了从单一交付到多层到容器化微服务的违规行为，并了解到每种应用都有其自己的功能位置。每种架构都有其自己的有效程度；适当的设计策略和这些架构的应用对于您的部署成功是必要的。通过学习了解了单片、N 层和微服务的基本原则，我们更有能力根据每种情况来战略性地实施最合适的架构。

![制定微服务的考虑](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/Untitled-3.jpg)

从单一到微服务

尽管存在缺点和实施挑战，微服务架构模式是复杂、不断发展的应用的更好选择。为了利用微服务进行现代云和 Web 应用程序的设计和部署，我们如何最好地利用微服务的优势，同时减轻潜在的缺点？

无论是开发新应用还是重振旧应用，这些考虑因素都必须考虑到微服务：

+   构建和维护高可用的分布式系统是复杂的

+   更多的移动部件意味着需要跟踪更多的组件

+   松散耦合的服务意味着需要采取步骤来保持数据一致

+   分布式异步进程会产生网络延迟和更多的 API 流量

+   测试和监控单个服务是具有挑战性的

#### 减轻缺点

这可能是整本书中提供的最简单的指导；然而，我们一次又一次地看到明显的事情要么完全被忽视，要么被忽视，要么被忽视。我们在这里提交的观点是，尽管已知的缺点相对较少，但存在着当前和不断发展的机制来解决几乎所有这些问题；人们强烈期望容器市场将发展出大量解决当前问题的解决方案。

再次，让我们从这里开始，作为需要更少故障排除的成功微服务应用程序的基础：

+   **全面负责**：如果不全面负责并知道最终的成功直接取决于你和你的团队，你的项目及其产生的应用程序将受到影响。承诺、奉献和坚持会带来丰厚的成果。

+   **全面理解**：充分理解业务目标以及最适合解决这些目标的技术，更不用说你使用它们的“如何”和“为什么”。始终在学习！

+   **进行详尽协调的规划**：战略性地规划，与其他应用程序利益相关者一起规划，为失败做规划，然后再做更多规划；衡量你的结果并修订计划，不断重新评估计划。始终在衡量，始终在规划！

+   **利用当前技术**：在当今的技术环境中，充分利用最稳定和功能齐全的工具和应用程序至关重要；因此，寻找它们。

+   **随着应用程序的发展**：你必须像你正在使用的容器技术一样灵活和适应；变化必须成为你详尽协调规划的一部分！

太好了！我们知道我们不仅必须承认，而且要积极参与我们应用项目过程的最基本要素。我们也知道并理解微服务架构方法的优缺点，以及这些优点可能远远超过任何负面影响。除了前面提到的五个强大的要素之外，我们如何减轻这些缺点，以利用微服务为我们带来的积极影响呢？

## 管理微服务

此时，你可能会问自己“那么，Docker 在这场对话中的位置在哪里？”我们的第一个半开玩笑的答案是，它完全合适！

Docker 非常适合微服务，因为它将容器隔离到一个进程或服务中。这种有意的单个服务或进程的容器化使得管理和更新这些服务变得非常简单。因此，毫不奇怪，在 Docker 之上的下一个浪潮导致了专门用于管理更复杂场景的框架的出现，包括以下内容：

+   如何在集群中管理单个服务？

+   如何在主机上跨多个实例中管理一个服务？

+   如何在部署和管理层面协调多个服务？

正如在不断成熟的容器市场中所预期的那样，我们看到了更多的辅助工具出现，以配合开源项目，例如 Kubernetes、MaestroNG 和 Mesos 等等，所有这些都是为了解决 Docker 容器化应用程序的管理、编排和自动化需求。例如，Kubernetes 是专门为微服务构建的项目，并且与 Docker 非常配合。Kubernetes 的关键特性直接迎合了微服务架构中至关重要的特征-通过 Docker 轻松部署新服务、独立扩展服务、终端客户端对故障的透明性以及简单的、临时的基于名称的服务端点发现。此外，Docker 自己的原生项目-Machine、Swarm、Compose 和 Orca，虽然在撰写本文时仍处于测试阶段，但看起来非常有前途-很可能很快就会被添加到 Docker 核心内核中。

由于我们稍后将专门讨论 Kubernetes、其他第三方应用程序以及整个章节的 Docker Machine、Swarm 和 Compose，让我们在这里看一个例子，利用我们之前使用过的服务（NGINX、Node.js）以及 Redis 和 Docker Compose。

### 真实世界的例子

NGINX > Node.js > Redis > Docker Compose

```
# Directly create and run the Redis image 
docker run -d -name redis -p 6379:6379 redis 

## Node Container 
# Set the base image to Ubuntu 
FROM ubuntu 

# File Author / Maintainer 
MAINTAINER John Wooten @CONSULTED <jwooten@cloudconsulted.com> 

# Install Node.js and other dependencies 
RUN apt-get update && \ 
        apt-get -y install curl && \ 
        curl -sL https://deb.nodesource.com/setup | sudo bash - && \ 
        apt-get -y install python build-essential nodejs 

# Install nodemon 
RUN npm install -g nodemon 

# Provides cached layer for node_modules 
ADD package.json /tmp/package.json 
RUN cd /tmp && npm install 
RUN mkdir -p /src && cp -a /tmp/node_modules /src/ 

# Define working directory 
WORKDIR /src 
ADD . /src 

# Expose portability 
EXPOSE 8080 

# Run app using nodemon 
CMD ["nodemon", "/src/index.js"] 

## Nginx Containers build 
# Set nginx base image 
FROM nginx 

# File Author / Maintainer 
MAINTAINER John Wooten @CONSULTED <jwooten@cloudconsulted.com> 

# Copy custom configuration file from the current directory 
COPY nginx.conf /etc/nginx/nginx.conf 

## Docker Compose 
nginx: 
build: ./nginx 
links: 
 - node1:node1 
 - node2:node2 
 - node3:node3 
ports: 
- "80:80" 
node1: 
build: ./node 
links: 
 - redis 
ports: 
 - "8080" 
node2: 
build: ./node 
links: 
 - redis 
ports: 
- "8080" 
node3: 
build: ./node 
links: 
 - redis 
ports: 
- "8080" 
redis: 
image: redis 
ports: 
 - "6379"

```

我们将在第十章中更深入地探讨 Docker Compose，*Docker Machine、Compose 和 Swarm*。此外，我们还需要实现一个服务发现机制（在后面的章节中讨论），使服务能够发现其需要与之通信的任何其他服务的位置（主机和端口）。

## 自动化测试和部署

我们希望尽可能多地确信我们的应用程序正在运行；这始于自动化测试，以促进我们的自动化部署。不用说，我们的自动化测试是至关重要的。推动工作软件*上*管道意味着我们自动化部署到每个新环境。

目前，微服务的测试仍然相对复杂；正如我们讨论过的，对于一个服务的测试类将需要启动该服务，以及它所依赖的任何服务。我们至少需要为这些服务配置存根。所有这些都可以做到，但让我们来研究如何减少其复杂性。

### 自动化测试

从战略上讲，我们需要规划我们的设计流程，包括测试，以验证我们的应用程序是否可以部署到生产环境。以下是我们希望通过自动化测试实现的示例工作流程：

![自动化测试](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_04_006.jpg)

上述图表代表了一个 DevOps 管道，从代码编译开始，经过集成测试、性能测试，最终在生产环境中部署应用程序。

#### 设计以应对故障

为了成功，我们必须接受故障是非常真实的可能性。事实上，我们确实应该有目的地将故障插入到我们的应用程序设计流程中，以测试当它们发生时我们如何成功地处理它们。这种在生产中的自动化测试最初需要钢铁般的神经；然而，通过重复和熟悉，我们可以得到自我修复的自动化。故障是必然的；因此，我们必须计划和测试我们的自动化，以减轻这种必然带来的损害。

成功的应用程序设计涉及内置的容错能力；这对于微服务尤为重要，因为使用服务作为组件的结果。由于服务随时可能失败，能够快速检测到故障并且在可能的情况下自动恢复服务是非常重要的。对我们的应用程序进行实时监控在微服务应用程序中至关重要，提供了一个早期警报系统，可以提前发现问题或潜在的错误或问题。这为开发团队提供了更早的响应和调查；由于微服务架构中存在这样的协作和事件协同，我们追踪新出现的行为变得非常重要。

因此，微服务团队应该设计包括一些最低限度的监控和日志设置，用于每个单独的服务：具有上/下状态的仪表板，断路器状态的元数据，当前吞吐量和延迟以及各种操作和业务相关的指标。

在应用程序构建结束时，如果我们的组件不能清晰地组合在一起，我们所做的不过是将复杂性从组件内部转移到它们之间的连接。这使得事情变得更难定义和更难控制。最终，我们应该设计以应对失败的必然性才能取得成功。

#### Dockunit 用于单元测试

为了增强我们的单元测试能力，我们还将安装和使用 Dockunit 来进行单元测试。对于我们的单元测试，有很多选项可供选择。在过去的单元测试中，我发现通过将 Dockunit 部署为我的开发工具包中的一个标准应用程序，我几乎可以满足任何单元测试需求。为了不显得太重复，让我们继续设置使用 Dockunit 进行自动化测试。

Dockunit 的要求是 Node.js、npm 和 Docker。

如果尚未安装，安装 npm（我们将假设已安装 Docker 和 Node.js）：

```
npm install -g dockunit

```

现在我们可以使用 Dockunit 轻松测试我们的 Node.js 应用程序。这可以通过一个`Dockunit.json`文件来完成；以下是一个示例，测试了一个使用`mocha`的 Node.js 0.10.x 和 0.12.0 应用程序：

```
{ 
  "containers": [ 
    { 
      "prettyName": "Node 0.10.x", 
      "image": "google/nodejs:latest", 
      "beforeScripts": [ 
        "npm install -g mocha" 
      ], 
      "testCommand": "mocha" 
    }, 
    { 
      "prettyName": "Node 0.12", 
      "image": "tlovett1/nodejs:0.12", 
      "beforeScripts": [ 
        "npm install -g mocha" 
      ], 
      "testCommand": "mocha" 
    } 
  ] 
} 

```

上面的代码片段显示了一个应用程序如何在 docker 容器内进行单元测试。

### 自动化部署

自动化的一种方法是使用现成的 PaaS（例如 Cloud Foundry 或 Tutum 等）。PaaS 为开发人员提供了一种简单的方式来部署和管理他们的微服务。它使他们免受采购和配置 IT 资源等问题的困扰。与此同时，配置 PaaS 的系统和网络专业人员可以确保符合最佳实践和公司政策。

自动化部署微服务的另一种方法是开发基本上是自己的 PaaS。一个典型的起点是使用集群解决方案，如 Mesos 或 Kubernetes，结合使用 Docker 等技术。本书的后面部分将介绍像 NGINX 这样的软件应用交付方法，它可以轻松处理缓存、访问控制、API 计量和微服务级别的监控，从而帮助解决这个问题。

## 将 N 层应用程序解耦为多个镜像

分解应用程序可以提高部署能力和可伸缩性，并简化对新技术的采用。要实现这种抽象级别，应用程序必须与基础设施完全解耦。应用程序容器，如 Docker，提供了一种将应用程序组件与基础设施解耦的方法。在这个级别上，每个应用服务必须是弹性的（即，它可以独立于其他服务进行扩展和缩减）和具有弹性（即，它具有多个实例并且可以在实例故障时继续运行）。应用程序还应该设计成一个服务的故障不会级联到其他服务。

我们已经说了太多，做得太少。让我们来看看我们真正需要知道的东西——如何构建它！我们可以在这里轻松使用我们的`cloudconsulted/wordpress`镜像来展示我们将其解耦为独立容器的示例：一个用于 WordPress，PHP 和 MySQL。相反，让我们探索其他应用程序，继续展示我们可以使用 Docker 进行应用程序部署的能力和潜力；例如，一个简单的 LEMP 堆栈

### 构建 N 层 Web 应用程序

LEMP 堆栈（NGINX > MySQL > PHP）

为了简化，我们将把这个 LEMP 堆栈分成两个容器：一个用于 MySQL，另一个用于 NGINX 和 PHP，每个都使用 Ubuntu 基础：

```
# LEMP stack decoupled as separate docker container s 
FROM ubuntu:14.04 
MAINTAINER John Wooten @CONSULTED <jwooten@cloudconsulted.com> 

RUN apt-get update 
RUN apt-get -y upgrade 

# seed database password 
COPY mysqlpwdseed /root/mysqlpwdseed 
RUN debconf-set-selections /root/mysqlpwdseed 

RUN apt-get -y install mysql-server 

RUN sed -i -e"s/^bind-address\s*=\s*127.0.0.1/bind-address = 0.0.0.0/" /etc/mysql/my.cnf 

RUN /usr/sbin/mysqld & \ 
    sleep 10s &&\ 
    echo "GRANT ALL ON *.* TO admin@'%' IDENTIFIED BY 'secret' WITH GRANT OPTION; FLUSH PRIVILEGES" | mysql -u root --password=secret &&\ 
    echo "create database test" | mysql -u root --password=secret 

# persistence: http://txt.fliglio.com/2013/11/creating-a-mysql-docker-container/ 

EXPOSE 3306 

CMD ["/usr/bin/mysqld_safe"]

```

第二个容器将安装和存储 NGINX 和 PHP：

```
# LEMP stack decoupled as separate docker container s 
FROM ubuntu:14.04 
MAINTAINER John Wooten @CONSULTED <jwooten@cloudconsulted.com> 

## install nginx 
RUN apt-get update 
RUN apt-get -y upgrade 
RUN apt-get -y install nginx 
RUN echo "daemon off;" >> /etc/nginx/nginx.conf 
RUN mv /etc/nginx/sites-available/default /etc/nginx/sites-available/default.bak 
COPY default /etc/nginx/sites-available/default 

## install PHP 
RUN apt-get -y install php5-fpm php5-mysql 
RUN sed -i s/\;cgi\.fix_pathinfo\s*\=\s*1/cgi.fix_pathinfo\=0/ /etc/php5/fpm/php.ini 

# prepare php test scripts 
RUN echo "<?php phpinfo(); ?>" > /usr/share/nginx/html/info.php 
ADD wall.php /usr/share/nginx/html/wall.php 

# add volumes for debug and file manipulation 
VOLUME ["/var/log/", "/usr/share/nginx/html/"] 

EXPOSE 80 

CMD service php5-fpm start && nginx

```

## 将不同层次的应用程序工作起来

从我们的实际生产示例中，我们已经看到了几种不同的方法，可以使不同的应用程序层一起工作。由于讨论使应用程序层在应用程序内部可互操作的方式都取决于应用程序层的部署，我们可以继续*无限*地讨论如何做到这一点；一个例子引出另一个例子，依此类推。相反，我们将在第六章中更深入地探讨这个领域，*使容器工作*。

# 总结

容器是现代微服务架构的载体；与微服务和 N 层架构风格结合使用容器不仅提供了一些狂野和富有想象力的优势，而且还提供了可行的生产就绪解决方案。在许多方面，使用容器来实现微服务架构与过去 20 年在 Web 开发中观察到的演变非常相似。这种演变的很大一部分是由于需要更好地利用计算资源和维护日益复杂的基于 Web 的应用程序的需求驱动的。对于现代应用程序开发来说，Docker 是一种确凿而有力的武器。

正如我们所看到的，使用 Docker 容器的微服务架构解决了这两个需求。我们探讨了从开发到测试无缝设计的示例环境，消除了手动和容易出错的资源配置和配置的需求。在这样做的过程中，我们简要介绍了微服务应用程序如何进行测试、自动化部署和管理，但在分布式系统中使用容器远不止微服务。越来越多地，容器正在成为所有分布式系统中的“一等公民”，在接下来的章节中，我们将讨论诸如 Docker Compose 和 Kubernetes 这样的工具对于管理基于容器的计算是至关重要的。


# 第五章：在容器化应用程序之间移动

在上一章中，我们介绍了使用 Docker 容器部署微服务应用程序架构。在本章中，我们将探讨 Docker 注册表以及如何在公共和私有模式下使用它。我们还将深入探讨在使用公共和私有 Docker 注册表时出现问题时的故障排除。

我们将讨论以下主题：

+   通过 Docker 注册表重新分发

+   公共 Docker 注册表

+   私有 Docker 注册表

+   确保镜像的完整性-签名镜像

+   **Docker Trusted Registry**（**DTR**）

+   Docker 通用控制平面

# 通过 Docker 注册表重新分发

Docker 注册表是服务器端应用程序，允许用户存储和分发 Docker 镜像。默认情况下，公共 Docker 注册表（Docker Hub）可用于托管多个 Docker 镜像，提供免费使用、零维护和自动构建等附加功能。让我们详细看看公共和私有 Docker 注册表。

## Docker 公共存储库（Docker Hub）

正如前面解释的那样，Docker Hub 允许个人和组织与内部团队和客户共享 Docker 镜像，而无需维护基于云的公共存储库。它提供了集中的资源镜像发现和管理。它还为开发流水线提供了团队协作和工作流自动化。除了镜像存储库管理之外，Docker Hub 的一些附加功能如下：

+   **自动构建**：它帮助在 GitHub 或 Bitbucket 存储库中的代码更改时创建新的镜像

+   **WebHooks**：这是一个新功能，允许在成功将镜像推送到存储库后触发操作

+   **用户管理**：它允许创建工作组来管理组织对镜像存储库的用户访问

可以使用 Docker Hub 登录页面创建帐户以托管 Docker 镜像；每个帐户将与唯一的基于用户的 Docker ID 相关联。可以在不创建 Docker Hub 帐户的情况下执行基本功能，例如从 Docker Hub 进行 Docker 镜像搜索和*拉取*。可以使用以下命令浏览 Docker Hub 中存在的镜像：

```
$ docker search centos

```

它将根据匹配的关键字显示 Docker Hub 中存在的镜像。

也可以使用`docker login`命令创建 Docker ID。以下命令将提示创建一个 Docker ID，该 ID 将成为用户公共存储库的公共命名空间。它将提示输入`用户名`，还将提示输入`密码`和`电子邮件`以完成注册过程：

```
$ sudo docker login 

Username: username 
Password: 
Email: email@blank.com 
WARNING:login credentials saved in /home/username/.dockercfg. 
Account created. Please use the confirmation link we sent to your e-mail to activate it.

```

为了注销，可以使用以下命令：

```
$ docker logout

```

## 私有 Docker 注册表

私有 Docker 注册表可以部署在本地组织内；它是 Apache 许可下的开源软件，并且易于部署。

使用私有 Docker 注册表，您有以下优势：

+   组织可以控制并监视 Docker 图像存储的位置

+   完整的图像分发流程将由组织拥有

+   图像存储和分发对于内部开发工作流程以及与其他 DevOps 组件（如 Jenkins）的集成将非常有用

# 将图像推送到 Docker Hub

我们可以创建一个定制的图像，然后使用标记将其推送到 Docker Hub。让我们创建一个带有小型基于终端的应用程序的简单图像。创建一个包含以下内容的 Dockerfile：

```
FROM debian:wheezy 
RUN apt-get update && apt-get install -y cowsay fortune 

```

转到包含 Dockerfile 的目录并执行以下命令来构建图像：

```
$ docker build -t test/cowsay-dockerfile . 
Sending build context to Docker daemon 2.048 kB 
Sending build context to Docker daemon 
Step 0 : FROM debian:wheezy 
wheezy: Pulling from debian 
048f0abd8cfb: Pull complete 
fbe34672ed6a: Pull complete 
Digest: sha256:50d16f4e4ca7ed24aca211446a2ed1b788ab5e3e3302e7fcc11590039c3ab445 
Status: Downloaded newer image for debian:wheezy 
 ---> fbe34672ed6a 
Step 1 : RUN apt-get update && apt-get install -y cowsay fortune 
 ---> Running in ece42dc9cffe

```

或者，如下图所示，我们可以首先创建一个容器并对其进行测试，然后创建一个带有标记的**Docker 图像**，可以轻松地推送到**Docker Hub**：

![将图像推送到 Docker Hub](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_05_002.jpg)

从 Docker 容器创建 Docker 图像并将其推送到公共 Docker Hub 的步骤

我们可以使用以下命令检查图像是否已创建。如您所见，`test/cowsay-dockerfile`图像已创建：

```
$ docker images
REPOSITORY                  TAG                 IMAGE ID
CREATED             VIRTUAL SIZE
test/cowsay-dockerfile      latest              c1014a025b02        33
seconds ago      126.9 MB
debian                      wheezy              fbe34672ed6a        2
weeks ago         84.92 MB
vkohli/vca-iot-deployment   latest              35c98aa8a51f        8
months ago        501.3 MB
vkohli/vca-cli              latest              d718bbdc304b        9
months ago        536.6 MB

```

为了将图像推送到 Docker Hub 帐户，我们将不得不使用图像 ID 对其进行标记，标记为 Docker 标记/Docker ID，方法如下：

```
$ docker tag c1014a025b02 username/cowsay-dockerfile

```

由于标记的用户名将与 Docker Hub ID 帐户匹配，因此我们可以轻松地推送图像：

```
$ sudo docker push username/cowsay-dockerfile 
The push refers to a repository [username/cowsay-dockerfile] (len: 1) 
d94fdd926b02: Image already exists 
accbaf2f09a4: Image successfully pushed 
aa354fc0b2b2: Image successfully pushed 
3a94f42115fb: Image successfully pushed 
7771ee293830: Image successfully pushed 
fa81ed084842: Image successfully pushed 
e04c66a223c4: Image successfully pushed 
7e2c5c55ef2c: Image successfully pushed

```

![将图像推送到 Docker Hub](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_05_003.jpg)

Docker Hub 的屏幕截图

### 提示

可以预先检查的故障排除问题之一是，自定义 Docker 镜像上标记的用户名应与 Docker Hub 帐户的用户名匹配，以便成功推送镜像。推送到 Docker Hub 的自定义镜像将公开可用。Docker 免费提供一个私有仓库，应该用于推送私有镜像。Docker 客户端版本 1.5 及更早版本将无法将镜像推送到 Docker Hub 帐户，但仍然可以拉取镜像。只支持 1.6 或更高版本。因此，建议始终保持 Docker 版本最新。

如果向 Docker Hub 推送失败并出现**500 内部服务器错误**，则问题与 Docker Hub 基础设施有关，重新推送可能有帮助。如果在推送 Docker 镜像时问题仍然存在，则应参考`/var/log/docker.log`中的 Docker 日志以进行详细调试。

## 安装私有本地 Docker 注册表

可以使用存在于 Docker Hub 上的镜像部署私有 Docker 注册表。映射到访问私有 Docker 注册表的端口将是`5000`：

```
$ docker run -p 5000:5000 registry

```

现在，我们将在前面教程中创建的相同镜像标记为`localhost:5000/cowsay-dockerfile`，以便可以轻松地将匹配的仓库名称和镜像名称推送到私有 Docker 注册表：

```
$ docker tag username/cowsay-dockerfile localhost:5000/cowsay-dockerfile

```

将镜像推送到私有 Docker 注册表：

```
$ docker push localhost:5000/cowsay-dockerfile

```

推送是指一个仓库（`localhost:5000/cowsay-dockerfile`）（长度：1）：

```
Sending image list 
Pushing repository localhost:5000/cowsay-dockerfile (1 tags) 
e118faab2e16: Image successfully pushed 
7e2c5c55ef2c: Image successfully pushed 
e04c66a223c4: Image successfully pushed 
fa81ed084842: Image successfully pushed 
7771ee293830: Image successfully pushed 
3a94f42115fb: Image successfully pushed 
aa354fc0b2b2: Image successfully pushed 
accbaf2f09a4: Image successfully pushed 
d94fdd926b02: Image successfully pushed 
Pushing tag for rev [d94fdd926b02] on {http://localhost:5000/v1/repositories/ cowsay-dockerfile/tags/latest}

```

可以通过访问浏览器中的链接或使用`curl`命令来查看镜像 ID，该命令在推送镜像后会出现。

## 在主机之间移动镜像

将一个镜像从一个注册表移动到另一个注册表需要从互联网上推送和拉取镜像。如果需要将镜像从一个主机移动到另一个主机，那么可以简单地通过`docker save`命令来实现，而不需要上传和下载镜像。Docker 提供了两种不同的方法来将容器镜像保存为 tar 包：

+   `docker export`：这将一个容器的运行或暂停状态保存到一个 tar 文件中

+   `docker save`：这将一个非运行的容器镜像保存到一个文件中

让我们通过以下教程来比较`docker export`和`docker save`命令：

使用 export，从 Docker Hub 拉取一个基本的镜像：

```
$ docker pull Ubuntu 
latest: Pulling from ubuntu 
dd25ab30afb3: Pull complete 
a83540abf000: Pull complete 
630aff59a5d5: Pull complete 
cdc870605343: Pull complete

```

在从上述镜像运行 Docker 容器后，让我们创建一个示例文件：

```
$ docker run -t -i ubuntu /bin/bash 
root@3fa633c2e9e6:/# ls 
bin  boot  dev  etc  home  lib  lib64  media  mnt  opt  proc  root 
run  sbin  srv  sys  tmp  usr  var 
root@3fa633c2e9e6:/# touch sample 
root@3fa633c2e9e6:/# ls 
bin  boot  dev  etc  home  lib  lib64  media  mnt  opt  proc  root 
run  sample  sbin  srv  sys  tmp  usr  var

```

在另一个 shell 中，我们可以看到正在运行的 Docker 容器，然后可以使用以下命令将其导出到 tar 文件中：

```
$  docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED
         STATUS              PORTS               NAMES
3fa633c2e9e6        ubuntu              "/bin/bash"         45 seconds
ago      Up 44 seconds                           prickly_sammet
$ docker export prickly_sammet | gzip > ubuntu.tar.gz

```

然后可以将 tar 文件导出到另一台机器，然后使用以下命令导入：

```
$ gunzip -c ubuntu.tar.gz | docker import - ubuntu-sample 
4411d1d3001702b2304d5ebf87f122ef80b463fd6287f3de4e631c50efa01369

```

在另一台机器上从 Ubuntu-sample 图像运行容器后，我们可以发现示例文件完好无损。

```
$ docker images
REPOSITORY                   TAG                 IMAGE ID  CREATED
IRTUAL SIZE
ubuntu-sample                    latest               4411d1d30017      20 seconds
go    108.8 MB
$ docker run -i -t ubuntu-sample /bin/bash
root@7fa063bcc0f4:/# ls
bin  boot  dev  etc  home  lib  lib64  media  mnt  opt  proc  root run  sample
bin  srv  sys  tmp  usr  var

```

使用 save 命令，以便在运行 Docker 容器的情况下传输图像，我们可以使用`docker save`命令将图像转换为 tar 文件：

```
$ docker save ubuntu | gzip > ubuntu-bundle.tar.gz

```

`ubuntu-bundle.tar.gz`文件现在可以使用`docker load`命令在另一台机器上提取并使用：

```
$ gunzip -c ubuntu-bundle.tar.gz | docker load

```

在另一台机器上从`ubuntu-bundle`图像运行容器，我们会发现示例文件不存在，因为`docker load`命令将存储图像而不会有任何投诉：

```
$ docker run -i -t ubuntu /bin/bash 
root@9cdb362f7561:/# ls 
bin  boot  dev  etc  home  lib  lib64  media  mnt  opt  proc  root 
run  sbin  srv  sys  tmp  usr  var 
root@9cdb362f7561:/#

```

前面的例子都展示了导出和保存命令之间的区别，以及它们在不使用 Docker 注册表的情况下在本地主机之间传输图像的用法。

## 确保图像的完整性-签名图像

从 Docker 版本 1.8 开始，包含的功能是 Docker 容器信任，它将**The Update Framework**（**TUF**）集成到 Docker 中，使用开源工具 Notary 提供对任何内容或数据的信任。它允许验证发布者-Docker 引擎使用发布者密钥来验证，并且用户即将运行的图像确实是发布者创建的；它没有被篡改并且是最新的。因此，这是一个允许验证图像发布者的选择性功能。 Docker 中央命令-*push*，*pull*，*build*，*create*和*run-*将对具有内容签名或显式内容哈希的图像进行操作。图像在推送到存储库之前由内容发布者使用私钥进行签名。当用户第一次与图像交互时，与发布者建立了信任，然后所有后续交互只需要来自同一发布者的有效签名。该模型类似于我们熟悉的 SSH 的第一个模型。 Docker 内容信任使用两个密钥-**离线密钥**和**标记密钥**-当发布者推送图像时，它们在第一次生成。每个存储库都有自己的标记密钥。当用户第一次运行`docker pull`命令时，使用离线密钥建立了对存储库的信任：

+   离线密钥：它是您存储库的信任根源；不同的存储库使用相同的离线密钥。由于具有针对某些攻击类别的优势，应将此密钥保持离线。基本上，在创建新存储库时需要此密钥。

+   **标记密钥**：为发布者拥有的每个新存储库生成。它可以导出并与需要为特定存储库签署内容的人共享。

以下是按照信任密钥结构提供的保护列表：

+   **防止图像伪造**：Docker 内容信任可防止中间人攻击。如果注册表遭到破坏，恶意攻击者无法篡改内容并向用户提供，因为每次运行命令都会失败，显示无法验证内容的消息。

+   **防止重放攻击**：在重放攻击的情况下，攻击者使用先前的有效负载来欺骗系统。Docker 内容信任在发布图像时使用时间戳密钥，从而提供对重放攻击的保护，并确保用户接收到最新的内容。

+   **防止密钥被破坏**：由于标记密钥的在线特性，可能会遭到破坏，并且每次将新内容推送到存储库时都需要它。Docker 内容信任允许发布者透明地旋转受损的密钥，以便用户有效地将其从系统中删除。

Docker 内容信任是通过将 Notary 集成到 Docker 引擎中实现的。任何希望数字签名和验证任意内容集合的人都可以下载并实施 Notary。基本上，这是用于在分布式不安全网络上安全发布和验证内容的实用程序。在以下序列图中，我们可以看到 Notary 服务器用于验证元数据文件及其与 Docker 客户端的集成的流程。受信任的集合将存储在 Notary 服务器中，一旦 Docker 客户端具有命名哈希（标记）的受信任列表，它就可以利用客户端到守护程序的 Docker 远程 API。一旦拉取成功，我们就可以信任注册表拉取中的所有内容和层。

![确保图像的完整性-签名图像](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_05_004.jpg)

Docker 受信任运行的序列图

在内部，Notary 使用 TUF，这是一个用于软件分发和更新的安全通用设计，通常容易受到攻击。TUF 通过提供一个全面的、灵活的安全框架来解决这个普遍的问题，开发人员可以将其与软件更新系统集成。通常，软件更新系统是在客户端系统上运行的应用程序，用于获取和安装软件。

让我们开始安装 Notary；在 Ubuntu 16.04 上，可以直接使用以下命令安装 Notary：

```
$ sudo apt install notary 
Reading package lists... Done 
Building dependency tree        
Reading state information... Done 

The following NEW packages will be installed: 
  Notary 
upgraded, 1 newly installed, 0 to remove and 83 not upgraded. 
Need to get 4,894 kB of archives. 
After this operation, 22.9 MB of additional disk space will be used. 
...

```

否则，该项目可以从 GitHub 下载并手动构建和安装；构建该项目需要安装 Docker Compose：

```
$ git clone https://github.com/docker/notary.git 
Cloning into 'notary'... 
remote: Counting objects: 15827, done. 
remote: Compressing objects: 100% (15/15), done. 

$ docker-compose build 
mysql uses an image, skipping 
Building signer 
Step 1 : FROM golang:1.6.1-alpine 

  $ docker-compose up -d 
$ mkdir -p ~/.notary && cp cmd/notary/config.json cmd/notary/root-ca.crt ~/.notary

```

在上述步骤之后，将`127.0.0.1` Notary 服务器添加到`/etc/hosts`中，或者如果使用 Docker 机器，则将`$(docker-machine ip)`添加到 Notary 服务器。

现在，我们将推送之前创建的`docker-cowsay`镜像。默认情况下，内容信任是禁用的；可以使用`DOCKER_CONTENT_TRUST`环境变量来启用它，这将在本教程中稍后完成。目前，操作内容信任的命令如下所示：

+   push

+   build

+   create

+   pull

+   run

我们将使用仓库名称标记该镜像：

```
$ docker images
REPOSITORY                  TAG                 IMAGE ID
CREATED             VIRTUAL SIZE
test/cowsay-dockerfile      latest              c1014a025b02        33
seconds ago      126.9 MB
debian                      wheezy              fbe34672ed6a        2
weeks ago         84.92 MB
vkohli/vca-iot-deployment   latest              35c98aa8a51f        8
months ago        501.3 MB
vkohli/vca-cli              latest              d718bbdc304b        9
months ago        536.6 MB
$ docker tag test/cowsay-dockerfile username/cowsay-dockerfile
$ docker push username/cowsay-dockerfile:latest
The push refers to a repository [docker.io/username/cowsay-dockerfile]
bbb8723d16e2: Pushing 24.08 MB/42.01 MB

```

现在，让我们检查 notary 是否有这个镜像的数据：

```
$ notary -s https://notary.docker.io -d ~/.docker/trust list docker.io/vkohli/cowsay-dockerfile:latest 
* fatal: no trust data available

```

正如我们在这里所看到的，没有信任数据可以让我们启用`DOCKER_CONTENT_TRUST`标志，然后尝试推送该镜像：

```
$ docker push vkohli/cowsay-dockerfile:latest 
The push refers to a repository [docker.io/vkohli/cowsay-dockerfile] 
bbb8723d16e2: Layer already exists  
5f70bf18a086: Layer already exists  
a25721716984: Layer already exists  
latest: digest: sha256:0fe0af6e0d34217b40aee42bc21766f9841f4dc7a341d2edd5ba0c5d8e45d81c size: 2609 
Signing and pushing trust metadata 
You are about to create a new root signing key passphrase. This passphrase 
will be used to protect the most sensitive key in your signing system. Please 
choose a long, complex passphrase and be careful to keep the password and the 
key file itself secure and backed up. It is highly recommended that you use a 
password manager to generate the passphrase and keep it safe. There will be no 
way to recover this key. You can find the key in your config directory. 
Enter passphrase for new root key with ID f94af29:

```

正如我们在这里所看到的，第一次推送时，它将要求输入密码来签署标记的镜像。

现在，我们将从 Notary 获取先前推送的最新镜像的信任数据：

```
$ notary -s https://notary.docker.io -d ~/.docker/trust list docker.io/vkohli/cowsay-dockerfile:latest
NAME                                 DIGEST                                SIZE
BYTES)    ROLE
----------------------------------------------------------------------------------
-------------------
latest     0fe0af6e0d34217b40aee42bc21766f9841f4dc7a341d2edd5ba0c5d8e45d81c
1374           targets

```

借助上面的例子，我们清楚地了解了 Notary 和 Docker 内容信任的工作原理。

# Docker Trusted Registry (DTR)

DTR 提供企业级的 Docker 镜像存储，可以在本地以及虚拟私有云中提供安全性并满足监管合规要求。DTR 在 Docker Universal Control Plane (UCP)之上运行，UCP 可以在本地或虚拟私有云中安装，借助它我们可以将 Docker 镜像安全地存储在防火墙后面。

![Docker Trusted Registry (DTR)](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_05_005.jpg)

DTR 在 UCP 节点上运行

DTR 的两个最重要的特性如下：

+   **镜像管理**：它允许用户在防火墙后安全存储 Docker 镜像，并且 DTR 可以轻松地作为持续集成和交付过程的一部分，以构建、运行和交付应用程序。![Docker 受信任的注册表（DTR）](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_05_006.jpg)

DTR 的屏幕截图

+   **访问控制和内置安全性**：DTR 提供身份验证机制，以添加用户，并集成了**轻量级目录访问协议**（**LDAP**）和 Active Directory。它还支持**基于角色的身份验证**（**RBAC**），允许您为每个用户分配访问控制策略。![Docker 受信任的注册表（DTR）](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_05_007.jpg)

DTR 中的用户身份验证选项

# Docker 通用控制平面

Docker UCP 是企业级集群管理解决方案，允许您从单个平台管理 Docker 容器。它还允许您管理数千个节点，并可以通过图形用户界面进行管理和监控。

UCP 有两个重要组件：

+   **控制器**：管理集群并保留集群配置

+   **节点**：可以添加多个节点到集群中以运行容器

可以使用 Mac OS X 或 Windows 系统上的**Docker Toolbox**进行沙盒安装 UCP。安装包括一个 UCP 控制器和一个或多个主机，这些主机将作为节点添加到 UCP 集群中，使用 Docker Toolbox。

Docker Toolbox 的先决条件是必须在 Mac OS X 和 Windows 系统上安装，使用官方 Docker 网站提供的安装程序。

![Docker 通用控制平面](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_05_008.jpg)

Docker Toolbox 安装

让我们开始部署 Docker UCP：

1.  安装完成后，启动 Docker Toolbox 终端：![Docker 通用控制平面](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_05_009.jpg)

Docker Quickstart 终端

1.  使用`docker-machine`命令和`virtualbox`创建一个名为`node1`的虚拟机，该虚拟机将充当 UCP 控制器：

```
$ docker-machine create -d virtualbox --virtualbox-memory 
        "2000" --virtualbox-disk-size "5000" node1 
        Running pre-create checks... 
        Creating machine... 
        (node1) Copying /Users/vkohli/.docker/machine/cache/
        boot2docker.iso to /Users/vkohli/.docker/machine/
        machines/node1/boot2docker.iso... 
        (node1) Creating VirtualBox VM... 
        (node1) Creating SSH key... 
        (node1) Starting the VM... 
        (node1) Check network to re-create if needed... 
        (node1) Waiting for an IP... 
        Waiting for machine to be running, this may take a few minutes... 
        Detecting operating system of created instance... 
        Waiting for SSH to be available... 
        Detecting the provisioner... 
        Provisioning with boot2docker... 
        Copying certs to the local machine directory... 
        Copying certs to the remote machine... 
        Setting Docker configuration on the remote daemon... 
        Checking connection to Docker... 
        Docker is up and running! 
        To see how to connect your Docker Client to the 
        Docker Engine running on this virtual machine, run: 
        docker-machine env node1

```

1.  还要创建一个名为`node2`的虚拟机，稍后将其配置为 UCP 节点：

```
        $ docker-machine create -d virtualbox --virtualbox-memory 
        "2000" node2 
        Running pre-create checks... 

        Creating machine... 
        (node2) Copying /Users/vkohli/.docker/machine/cache/boot2docker.iso 
        to /Users/vkohli/.docker/machine/machines/node2/
        boot2docker.iso... 
        (node2) Creating VirtualBox VM... 
        (node2) Creating SSH key... 
        (node2) Starting the VM... 
        (node2) Check network to re-create if needed... 
        (node2) Waiting for an IP... 
        Waiting for machine to be running, this may take a few minutes... 
        Detecting operating system of created instance... 
        Waiting for SSH to be available... 
        Detecting the provisioner... 
        Provisioning with boot2docker... 
        Copying certs to the local machine directory... 
        Copying certs to the remote machine... 
        Setting Docker configuration on the remote daemon... 
        Checking connection to Docker... 
        Docker is up and running! 
        To see how to connect your Docker Client to the 
        Docker Engine running on this virtual machine, 
        run: docker-machine env node2

```

1.  将`node1`配置为 UCP 控制器，负责提供 UCP 应用程序并运行管理 Docker 对象安装的过程。在此之前，设置环境以将`node1`配置为 UCP 控制器：

```
        $ docker-machine env node1
        export DOCKER_TLS_VERIFY="1"
        export DOCKER_HOST="tcp://192.168.99.100:2376"
        export DOCKER_CERT_PATH="/Users/vkohli/.docker/machine/machines/node1"
        export DOCKER_MACHINE_NAME="node1"
        # Run this command to configure your shell:
        # eval $(docker-machine env node1)
        $ eval $(docker-machine env node1)
        $ docker-machine ls
NAME    ACTIVE   DRIVER       STATE    URL            SWARM
        DOCKER  ERRORS
node1   *        virtualbox   Running  tcp://192.168.99.100:2376
        1.11.1  
        node2   -        virtualbox   Running  tcp://192.168.99.101:2376                   v1.11.1  

```

1.  在将`node1`设置为 UCP 控制器时，它将要求输入 UCP 管理员帐户的密码，并且还将要求输入其他别名，可以使用 enter 命令添加或跳过：

```
$ docker run --rm -it -v /var/run/docker.sock:/var/run
        /docker.sock --name ucp docker/ucp install -i --swarm-port 
        3376 --host-address $(docker-machine ip node1) 

        Unable to find image 'docker/ucp:latest' locally 
        latest: Pulling from docker/ucp 
        ... 
        Please choose your initial UCP admin password:  
        Confirm your initial password:  
        INFO[0023] Pulling required images... (this may take a while)  
        WARN[0646] None of the hostnames we'll be using in the UCP 
        certificates [node1 127.0.0.1 172.17.0.1 192.168.99.100] 
        contain a domain component.  Your generated certs may fail 
        TLS validation unless you only use one of these shortnames 
        or IPs to connect.  You can use the --san flag to add more aliases  

        You may enter additional aliases (SANs) now or press enter to 
        proceed with the above list. 
        Additional aliases: INFO[0646] Installing UCP with host address 
        192.168.99.100 - If this is incorrect, please specify an 
        alternative address with the '--host-address' flag  
        INFO[0000] Checking that required ports are available and accessible  

        INFO[0002] Generating UCP Cluster Root CA                
        INFO[0039] Generating UCP Client Root CA                 
        INFO[0043] Deploying UCP Containers                      
        INFO[0052] New configuration established.  Signalling the daemon
        to load it...  
        INFO[0053] Successfully delivered signal to daemon       
        INFO[0053] UCP instance ID:            
        KLIE:IHVL:PIDW:ZMVJ:Z4AC:JWEX:RZL5:U56Y:GRMM:FAOI:PPV7:5TZZ  
        INFO[0053] UCP Server SSL: SHA-256       
        Fingerprint=17:39:13:4A:B0:D9:E8:CC:31:AD:65:5D:
        52:1F:ED:72:F0:81:51:CF:07:74:85:F3:4A:66:F1:C0:A1:CC:7E:C6  
        INFO[0053] Login as "admin"/(your admin password) to UCP at         
        https://192.168.99.100:443

```

1.  UCP 控制台可以使用安装结束时提供的 URL 访问；使用`admin`作为用户名和之前安装时设置的密码登录。![Docker Universal Control Plane](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_05_010.jpg)

Docker UCP 许可证页面

1.  登录后，可以添加或跳过试用许可证。可以通过在 Docker 网站上的 UCP 仪表板上的链接下载试用许可证。UCP 控制台具有多个选项，如列出应用程序、容器和节点：![Docker Universal Control Plane](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_05_011.jpg)

Docker UCP 管理仪表板

1.  首先通过设置环境将 UCP 的`node2`加入控制器：

```
        $ docker-machine env node2 
        export DOCKER_TLS_VERIFY="1" 
        export DOCKER_HOST="tcp://192.168.99.102:2376" 
        export DOCKER_CERT_PATH="/Users/vkohli/.docker/machine/machines/node2" 
        export DOCKER_MACHINE_NAME="node2" 
        # Run this command to configure your shell:  
        # eval $(docker-machine env node2) 
        $ eval $(docker-machine env node2)

```

1.  使用以下命令将节点添加到 UCP 控制器。将要求输入 UCP 控制器 URL、用户名和密码，如图所示：

```
$ docker run --rm -it -v /var/run/docker.sock:/var/run/docker.sock
         --name ucp docker/ucp join -i --host-address 
        $(docker-machine ip node2) 

        Unable to find image 'docker/ucp:latest' locally 
        latest: Pulling from docker/ucp 
        ... 

        Please enter the URL to your UCP server: https://192.168.99.101:443 
        UCP server https://192.168.99.101:443 
        CA Subject: UCP Client Root CA 
        Serial Number: 4c826182c994a42f 
        SHA-256 Fingerprint=F3:15:5C:DF:D9:78:61:5B:DF:5F:39:1C:D6:
        CF:93:E4:3E:78:58:AC:43:B9:CE:53:43:76:50:
        00:F8:D7:22:37 
        Do you want to trust this server and proceed with the join? 
        (y/n): y 
        Please enter your UCP Admin username: admin 
        Please enter your UCP Admin password:  
        INFO[0028] Pulling required images... (this may take a while)  
        WARN[0176] None of the hostnames we'll be using in the UCP 
        certificates [node2 127.0.0.1 172.17.0.1 192.168.99.102] 
        contain a domain component.  Your generated certs may fail 
        TLS validation unless you only use one of these shortnames 
        or IPs to connect.  You can use the --san flag to add more aliases  

        You may enter additional aliases (SANs) now or press enter 
        to proceed with the above list. 
        Additional aliases:  
        INFO[0000] This engine will join UCP and advertise itself
        with host address 192.168.99.102 - If this is incorrect, 
        please specify an alternative address with the '--host-address' flag  
        INFO[0000] Verifying your system is compatible with UCP  
        INFO[0007] Starting local swarm containers               
        INFO[0007] New configuration established.  Signalling the 
        daemon to load it...  
        INFO[0008] Successfully delivered signal to daemon

```

1.  UCP 的安装已完成；现在可以通过从 Docker Hub 拉取官方 DTR 镜像来在`node2`上安装 DTR。为了完成 DTR 的安装，还需要 UCP URL、用户名、密码和证书：

```
        $ curl -k https://192.168.99.101:443/ca > ucp-ca.pem 

        $ docker run -it --rm docker/dtr install --ucp-url https://
        192.168.99.101:443/ --ucp-node node2 --dtr-load-balancer 
        192.168.99.102 --ucp-username admin --ucp-password 123456 
        --ucp-ca "$(cat ucp-ca.pem)" 

        INFO[0000] Beginning Docker Trusted Registry installation  
        INFO[0000] Connecting to network: node2/dtr-br           
        INFO[0000] Waiting for phase2 container to be known to the 
        Docker daemon  
        INFO[0000] Connecting to network: dtr-ol                 
        ... 

        INFO[0011] Installation is complete                      
        INFO[0011] Replica ID is set to: 7a9b6eb67065            
        INFO[0011] You can use flag '--existing-replica-id 7a9b6eb67065' 
        when joining other replicas to your Docker Trusted Registry Cluster

```

1.  安装成功后，DTR 可以在 UCP UI 中列为一个应用程序：![Docker Universal Control Plane](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_05_012.jpg)

Docker UCP 列出所有应用程序

1.  DTR UI 可以使用`http://node2` URL 访问。单击**新存储库**按钮即可创建新存储库：![Docker Universal Control Plane](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_05_013.jpg)

在 DTR 中创建新的私有注册表

1.  可以从之前创建的安全 DTR 中推送和拉取镜像，并且还可以将存储库设置为私有，以便保护公司内部的容器。![Docker Universal Control Plane](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_05_014.jpg)

在 DTR 中创建新的私有注册表

1.  可以使用**设置**选项从菜单中配置 DTR，该选项允许设置 Docker 镜像的域名、TLS 证书和存储后端。![Docker Universal Control Plane](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_05_015.jpg)

DTR 中的设置选项

# 摘要

在本章中，我们深入探讨了 Docker 注册表。我们从使用 Docker Hub 的 Docker 公共存储库的基本概念开始，并讨论了与更大观众共享容器的用例。Docker 还提供了部署私有 Docker 注册表的选项，我们研究了这一点，并可以用于在组织内部推送、拉取和共享 Docker 容器。然后，我们研究了通过使用 Notary 服务器对 Docker 容器进行签名来标记和确保其完整性，该服务器可以与 Docker Engine 集成。DTR 提供了更强大的解决方案，它在本地以及虚拟私有云中提供企业级 Docker 镜像存储，以提供安全性并满足监管合规要求。它在 Docker UCP 之上运行，如前面详细的安装步骤所示。我希望本章能帮助您解决问题并了解 Docker 注册表的最新趋势。在下一章中，我们将探讨如何通过特权容器和资源共享使容器正常工作。


# 第六章：使容器工作

在本章中，我们将探索使用特权模式和超级特权模式容器创建 Docker 容器的各种选项。我们还将探索这些模式的各种故障排除问题。

我们将深入研究各种部署管理工具，如**Chef**、**Puppet**和**Ansible**，它们与 Docker 集成，以便为生产环境部署数千个容器减轻痛苦。

在本章中，我们将涵盖以下主题：

+   特权容器和超级特权容器

+   解决使用不同设置选项创建容器时遇到的问题

+   使 Docker 容器与 Puppet、Ansible 和 Chef 配合工作

+   使用 Puppet 创建 Docker 容器并部署应用程序

+   使用 Ansible 管理 Docker 容器

+   将 Docker 和 Ansible 一起构建

+   用于 Docker 的 Chef

利用前述管理工具自动化 Docker 容器的部署具有以下优势：

+   **灵活性**：它们为您提供了在云实例或您选择的裸机上复制基于 Docker 的应用程序以及 Docker 应用程序所需的环境的灵活性。这有助于管理和测试，以及根据需要提供开发环境。

+   **可审计性**：这些工具还提供了审计功能，因为它们提供了隔离，并帮助跟踪任何潜在的漏洞以及在哪个环境中部署了什么类型的容器。

+   **普遍性**：它们帮助您管理容器周围的整个环境，即管理容器以及非容器环境，如存储、数据库和容器应用程序周围的网络模型。

# 特权容器

默认情况下，容器以非特权模式运行，也就是说，我们不能在 Docker 容器内运行 Docker 守护程序。但是，特权 Docker 容器被赋予对所有设备的访问权限。Docker 特权模式允许访问主机上的所有设备，并在**App Armor**和**SELinux**中设置系统配置，以允许容器与主机上运行的进程具有相同的访问权限：

![特权容器](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_06_001-1.jpg)

突出显示的特权容器

特权容器可以使用以下命令启动：

```
 $
 docker run -it --privileged ubuntu /bin/bash
 root@9ab706a6a95c:/# cd /dev/
 root@9ab706a6a95c:/dev# ls
 agpgart          hdb6                psaux   sg1       tty32  tty7
 atibm            hdb7                ptmx    shm       tty33  tty8
 audio            hdb8                pts     snapshot  tty34  tty9
 beep             hdb9                ram0    sr0       tty35  ttyS0

```

正如我们所看到的，启动特权模式容器后，我们可以列出连接到主机机器的所有设备。

## 故障排除提示

Docker 允许您通过支持添加和删除功能来使用非默认配置文件。最好删除容器进程不需要的功能，这样可以使其更安全。

如果您的主机系统上运行的容器面临安全威胁，通常建议检查是否有任何容器以特权模式运行，这可能会通过运行安全威胁应用程序来影响主机系统的安全。

如下例所示，当我们以非特权模式运行容器时，无法更改内核参数，但当我们使用`--privileged`标志以特权模式运行容器时，它可以轻松更改内核参数，这可能会在主机系统上造成安全漏洞：

```
 $ docker run -it centos /bin/bash
 [root@7e1b1fa4fb89 /]#  sysctl -w net.ipv4.ip_forward=0
 sysctl: setting key "net.ipv4.ip_forward": Read-only file system
 $ docker run --privileged -it centos /bin/bash
 [root@930aaa93b4e4 /]#  sysctl -a | wc -l
 sysctl: reading key "net.ipv6.conf.all.stable_secret"
 sysctl: reading key "net.ipv6.conf.default.stable_secret"
 sysctl: reading key "net.ipv6.conf.eth0.stable_secret"
 sysctl: reading key "net.ipv6.conf.lo.stable_secret"
 638
 [root@930aaa93b4e4 /]# sysctl -w net.ipv4.ip_forward=0
 net.ipv4.ip_forward = 0

```

因此，在审核时，您应确保主机系统上运行的所有容器的特权模式未设置为`true`，除非某些特定应用程序在 Docker 容器中运行时需要：

```
 $ docker ps -q | xargs docker inspect --format '{{ .Id }}: 
    Privileged={{ 
    .HostConfig.Privileged }}'
 930aaa93b4e44c0f647b53b3e934ce162fbd9ef1fd4ec82b826f55357f6fdf3a: 
    Privileged=true

```

# 超级特权容器

这个概念是在 Redhat 的 Project Atomic 博客中介绍的。它提供了使用特殊/特权容器作为代理来控制底层主机的能力。如果我们只发布应用程序代码，我们就有将容器变成黑匣子的风险。将代理打包为具有正确访问权限的 Docker 容器对主机有许多好处。我们可以通过`-v /dev:/dev`绑定设备，这将帮助在容器内部挂载设备而无需超级特权访问。

使用`nsenter`技巧，允许您在另一个命名空间中运行命令，也就是说，如果 Docker 有自己的私有挂载命名空间，通过`nsenter`和正确的模式，我们可以到达主机并在其命名空间中挂载东西。

我们可以以特权模式运行，将整个主机系统挂载到某个路径（`/media/host`）上：

```
 $ docker run -it -v /:/media/host --privileged fedora 
nsenter --mount=/media/host/proc/1/ns/mnt --mount /dev/xvdf /home/mic

```

然后我们可以在容器内部使用`nsenter`；`--mount`告诉`nsenter`查看`/media/host`，然后选择 proc 编号 1 的挂载命名空间。然后，运行常规挂载命令将设备链接到挂载点。如前所述，此功能允许我们挂载主机套接字和设备，例如文件，因此所有这些都可以绑定到容器中供使用：

![超级特权容器](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_06_002-2.jpg)

作为超级特权容器运行的 nsenter 监视主机

基本上，超级特权容器不仅提供安全隔离、资源和进程隔离，还提供了一种容器的运输机制。允许软件以容器镜像的形式进行运输，也允许我们管理主机操作系统和管理其他容器进程，就像之前解释的那样。

让我们考虑一个例子，目前，我们正在加载应用程序所需的内核模块，这些模块是主机操作系统中不包括的 RPM 软件包，并在应用程序启动时运行它们。这个模块可以通过超级特权容器的帮助进行运输，好处是这个自定义内核模块可以与当前内核非常好地配合，而不是将内核模块作为特权容器的一部分进行运输。在这种方法中，不需要将应用程序作为特权容器运行；它们可以分开运行，内核模块可以作为不同镜像的一部分加载，如下所示：

```
 $ sudo docker run --rm --privileged foobar /sbin/modprobe PATHTO/foobar-kmod 
$ sudo docker run -d foobar

```

## 故障排除 - 大规模的 Docker 容器

在生产环境中工作意味着持续部署。当基础设施是分散的和基于云的时，我们经常在相同的系统上管理相同服务的部署。自动化整个配置和管理这个系统的过程将是一个福音。部署管理工具就是为此目的而设计的。它们提供配方、剧本和模板，简化编排和自动化，提供标准和一致的部署。在接下来的章节中，我们将探讨三种常见的配置自动化工具：Chef、Puppet 和 Ansible，以及它们在大规模部署 Docker 容器时提供的便利。

# 木偶

Puppet 是一个自动化引擎，执行自动化的管理任务，如更新配置、添加用户和根据用户规范安装软件包。 Puppet 是一个众所周知的开源配置管理工具，可在各种系统上运行，如 Microsoft Windows、Unix 和 Linux。用户可以使用 Puppet 的声明性语言或特定领域语言（Ruby）描述配置。 Puppet 是模型驱动的，使用时需要有限的编程知识。 Puppet 提供了一个用于管理 Docker 容器的模块。 Puppet 和 Docker 集成可以帮助轻松实现复杂的用例。 Puppet 管理文件、软件包和服务，而 Docker 将二进制文件和配置封装在容器中，以便部署为应用程序。

Puppet 的一个潜在用例是，它可以用于为 Jenkins 构建所需的 Docker 容器进行配置，并且可以根据开发人员的需求进行规模化，即在触发构建时。构建过程完成后，二进制文件可以交付给各自的所有者，并且每次构建后都可以销毁容器。在这种用例中，Puppet 扮演着非常重要的角色，因为代码只需使用 Puppet 模板编写一次，然后可以根据需要触发：

![Puppet](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_06_003-1.jpg)

将 Puppet 和 Jenkins 集成以部署构建 Docker 容器

可以根据`garethr-docker` GitHub 项目安装用于管理 Docker 的 Puppet 模块。该模块只需要包含一个类：

```
    include 'docker'

```

它设置了一个 Docker 托管的存储库，并安装了 Docker 软件包和任何所需的内核扩展。 Docker 守护程序将绑定到`unix socket /var/run/docker.sock`；根据需求，可以更改此配置：

```
    class { 'docker':
      tcp_bind        => ['tcp://127.0.0.1:4245','tcp://10.0.0.1:4244'],
      socket_bind     => 'unix:///var/run/docker.sock',
      ip_forward      => true,
      iptables        => true,
      ip_masq         => true,
      bridge          => br0,
      fixed_cidr      => '10.21.1.0/24',
      default_gateway => '10.21.0.1',
    }

```

如前面的代码所示，Docker 的默认配置可以根据此模块提供的配置进行更改。

## 图像

可以使用此处详细说明的配置语法来拉取 Docker 镜像。

`ubuntu:trusty docker`命令的替代方法如下：

```
 $ docker pull -t="trusty" ubuntu
 docker::image { 'ubuntu':
 image_tag => 'trusty'
    }

```

甚至配置允许链接到 Dockerfile 以构建镜像。也可以通过订阅外部事件（如 Dockerfile 中的更改）来触发镜像的重建。我们订阅`vkohli/Dockerfile`文件夹中的更改，如下所示：

```
    docker::image { 'ubuntu':
      docker_file => '/vkohli/Dockerfile'
      subscribe => File['/vkohli/Dockerfile'],
    }

    file { '/vkohli/Dockerfile':
      ensure => file,
      source => 'puppet:///modules/someModule/Dockerfile',
    }

```

## 容器

创建图像后，可以使用多个可选参数启动容器。我们可以使用基本的`docker run`命令获得类似的功能：

```
    docker::run { 'sampleapplication':
      image           => 'base',
      command         => '/bin/sh -c "while true; do echo hello world; sleep 1; 
                         done"',
      ports           => ['4445', '4555'],
      expose          => ['4665', '4777'],
      links           => ['mysql:db'],
      net             => 'my-user-def',
      volumes         => ['/var/lib/couchdb', '/var/log'],
      volumes_from    => '6446ea52fbc9',
      memory_limit    => '20m', # (format: '<number><unit>', where unit = b, k, m 
                         or g)
      cpuset          => ['0', '4'],
      username        => 'sample',
      hostname        => 'sample.com',
      dns             => ['8.8.8.8', '8.8.4.4'],
      restart_service => true,
      privileged      => false,
      pull_on_start   => false,
      before_stop     => 'echo "The sample application completed"',
      after           => [ 'container_b', 'mysql' ],
      depends         => [ 'container_a', 'postgres' ],
      extra_parameters => [ '--restart=always' ],
    }

```

如下所示，我们还可以传递一些更多的参数，例如以下内容：

+   `pull_on_start`：在启动图像之前，每次都会重新拉取它

+   `before_stop`：在停止容器之前将执行所述命令

+   `extra_parameters`：传递给`docker run`命令所需的附加数组参数，例如`--restart=always`

+   `after`：此选项允许表达需要首先启动的容器

可以设置的其他参数包括`ports`、`expose`、`env_files`和`volumes`。可以传递单个值或值数组。

## 网络

最新的 Docker 版本已经官方支持网络：该模块现在公开了一种类型，Docker 网络，可以用来管理它们：

```
    docker_network { 'sample-net':
      ensure   => present,
      driver   => 'overlay',
      subnet   => '192.168.1.0/24',
      gateway  => '192.168.1.1',
      ip_range => '192.168.1.4/32',
    }

```

正如前面的代码所示，可以创建一个新的覆盖网络`sample-net`，并配置 Docker 守护程序以使用它。

## Docker compose

Compose 是一个用于运行多个 Docker 容器应用程序的工具。使用 compose 文件，我们可以配置应用程序的服务并启动它们。提供了`docker_compose`模块类型，允许 Puppet 轻松运行 compose 应用程序。

还可以添加一个 compose 文件，例如运行四个容器的缩放规则，如下面的代码片段所示。我们还可以提供网络和其他配置所需的附加参数：

```
    docker_compose { '/vkohli/docker-compose.yml':
      ensure  => present,
      scale   => {
        'compose_test' => 4,
      },
      options => '--x-networking'
    }

```

1.  如果 Puppet 程序未安装在您的计算机上，可以按以下方式进行安装：

```
 $ puppet module install garethr-docker
 The program 'puppet' is currently not installed. On Ubuntu 14.04 the 
        puppet program 
        can be installed as shown below;
 $ apt-get install puppet-common
 Reading package lists... Done
 Building dependency tree
 Reading state information... Done
 ...
 The following extra packages will be installed:
 Unpacking puppet-common (3.4.3-1ubuntu1.1) ...
 Selecting previously unselected package ruby-rgen.
 Preparing to unpack .../ruby-rgen_0.6.6-1_all.deb ...
 ...

```

1.  在安装 Puppet 模块之后，可以按照所示安装`garethr-docker`模块：

```
 $ puppet module install garethr-docker
 Notice: Preparing to install into /etc/puppet/modules ...
 Notice: Downloading from https://forge.puppetlabs.com ...
 Notice: Installing -- do not interrupt ...
 /etc/puppet/modules
        |__ **garethr-docker (v5.3.0)
 |__ puppetlabs-apt (v2.2.2)
 |__ puppetlabs-stdlib (v4.12.0)
 |__ stahnma-epel (v1.2.2)

```

1.  我们将创建一个示例 hello world 应用程序，将使用 Puppet 进行部署：

```
 $ nano sample.pp 
        include 'docker' 
        docker::image { 'ubuntu': 
          image_tag => 'precise' 
        } 
        docker::run { 'helloworld': 
          image => 'ubuntu', 
          command => '/bin/sh -c "while true; do echo hello world; sleep 1; 
                     done"',  
        }

```

1.  创建文件后，我们应用（运行）它：

```
 $ puppet apply sample.pp
 Warning: Config file /etc/puppet/hiera.yaml not found, using Hiera 
        defaults 
        Warning: Scope(Apt::Source[docker]): $include_src is deprecated and 
        will be removed in the next major release, please use $include => { 
        'src' => false } instead 
        ... 
        Notice: /Stage[main]/Main/Docker::Run[helloworld]/Service[docker-
        helloworld]/ensure: 
        ensure changed 'stopped' to 'running' 
        Notice: Finished catalog run in 0.80 seconds 
        Post installation it can be listed as running container: 
        $ docker ps 
        CONTAINER ID        IMAGE               COMMAND 
        CREATED             STATUS              PORTS               NAMES   
        bd73536c7f64        ubuntu:trusty       "/bin/sh -c 'while tr"   5 
        seconds ago       Up 5 seconds        helloworld

```

1.  我们可以将其附加到容器并查看输出：

```
 $ docker attach bd7
 hello world
 hello world
 hello world
 hello world

```

如前所示，容器可以部署在多个主机上，并且整个集群可以通过单个 Puppet 配置文件创建。

## 故障排除提示

如果即使 Puppet `apply`命令成功运行后，仍无法列出 Docker 镜像，请检查语法和是否在示例文件中放置了正确的镜像名称。

# Ansible

Ansible 是一个工作流编排工具，通过一个易于使用的平台提供配置管理、供应和应用程序部署的帮助。Ansible 的一些强大功能如下：

+   **供应**：应用程序在不同的环境中开发和部署。可以是裸金属服务器、虚拟机或 Docker 容器，在本地或云上。Ansible 可以通过 Ansible tower 和 playbooks 来简化供应步骤。

+   **配置管理**：保持一个通用的配置文件是 Ansible 的主要用例之一，有助于在所需的环境中进行管理和部署。

+   **应用程序部署**：Ansible 有助于管理应用程序的整个生命周期，从部署到生产。

+   **持续交付**：管理持续交付流水线需要来自各个团队的资源。这不能仅靠简单的平台实现，因此，Ansible playbooks 在部署和管理应用程序的整个生命周期中发挥着重要作用。

+   **安全和合规性**：安全性可以作为部署阶段的一个组成部分，通过将各种安全策略作为自动化流程的一部分，而不是作为事后的思考过程或稍后合并。

+   **编排**：如前所述，Ansible 可以定义管理多个配置的方式，与它们交互，并管理部署脚本的各个部分。

## 使用 Ansible 自动化 Docker

Ansible 还提供了一种自动化 Docker 容器的方式；它使我们能够将 Docker 容器构建和自动化流程进行通道化和操作化，这个过程目前大多数情况下是手动处理的。Ansible 为编排 Docker 容器提供了以下模块：

+   **Docker_service**：现有的 Docker compose 文件可以用于通过 Ansible 的 Docker 服务部分在单个 Docker 守护程序或集群上编排容器。Docker compose 文件与 Ansible playbook 具有相同的语法，因为它们都是**Yaml**文件，语法几乎相同。Ansible 也是用 Python 编写的，Docker 模块使用的是 docker compose 在内部使用的确切 docker-py API 客户端。

这是一个简单的 Docker compose 文件：

```
        wordpress:
        image: wordpress
        links:
           - db:mysql
        ports:
           - 8080:80
        db:
        image: mariadb
        environment:
              MYSQL_ROOT_PASSWORD: sample

```

前面的 Docker compose 文件的 Ansible playbook 看起来很相似：

```
        # tasks file for ansible-dockerized-wordpress
        - name: "Launching DB container"
         docker:
           name: db
           image: mariadb
           env:
             MYSQL_ROOT_PASSWORD: esample
        - name: "Launching wordpress container"
         docker:
           name: wordpress
           image: wordpress
           links:
           - db:mysql
           ports: 
           - 8081:80
```

+   **docker_container**：通过提供启动、停止、创建和销毁 Docker 容器的能力，来管理 Docker 容器的生命周期。

+   **docker_image**：这提供了帮助来管理 Docker 容器的镜像，包括构建、推送、标记和删除 Docker 镜像的命令。

+   **docker_login**：这将与 Docker hub 或任何 Docker 注册表进行身份验证，并提供从注册表推送和拉取 Docker 镜像的功能。

## Ansible Container

Ansible Container 是一个工具，仅使用 Ansible playbooks 来编排和构建 Docker 镜像。可以通过创建 `virtualenv` 并使用 pip 安装的方式来安装 Ansible Container：

```
 $ virtualenv ansible-container
 New python executable in /Users/vkohli/ansible-container/bin/python
 Installing setuptools, pip, wheel...done.
 vkohli-m01:~ vkohli$ source ansible-container/bin/activate
 (ansible-container) vkohli-m01:~ vkohli$ pip install ansible-container
 Collecting ansible-container
 Using cached ansible-container-0.1.0.tar.gz
 Collecting docker-compose==1.7.0 (from ansible-container)
 Downloading docker-compose-1.7.0.tar.gz (141kB)
 100% |=============================| 143kB 1.1MB/s
 Collecting docker-py==1.8.0 (from ansible-container)
 ...
 Downloading docker_py-1.8.0-py2.py3-none-any.whl (41kB)
 Collecting cached-property<2,>=1.2.0 (from docker-compose==1.7.0->ansible-
     container)

```

## 故障排除提示

如果您在安装 Ansible Container 方面遇到问题，可以通过从 GitHub 下载源代码来进行安装：

```
 $ git clone https://github.com/ansible/ansible-container.git
 Cloning into 'ansible-container'...
 remote: Counting objects: 2032, done.
 remote: Total 2032 (delta 0), reused 0 (delta 0), pack-reused 2032
 Receiving objects: 100% (2032/2032), 725.29 KiB | 124.00 KiB/s, done.
 Resolving deltas: 100% (1277/1277), done.
 Checking connectivity... done.
 $ cd ansible-container/
 $ ls
 AUTHORS      container        docs     EXAMPLES.md  LICENSE
 README.md         setup.py  update-authors.py
 codecov.yml  CONTRIBUTORS.md  example  INSTALL.md   MANIFEST.in
 requirements.txt  test
 $ sudo python setup.py install
 running install
 running bdist_egg
 running egg_info
 creating ansible_container.egg-info
 writing requirements to ansible_container.egg-info/requires.txt

```

Ansible Container 有以下命令可供开始使用：

+   **ansible_container init**：此命令创建一个用于开始的 Ansible 文件目录。

```
 $ ansible-container init
 Ansible Container initialized.
 $ cd ansible
 $ ls
 container.yml    main.yml    requirements.tx

```

+   **ansible-container build**：这将从 Ansible 目录中的 playbooks 创建镜像

+   **ansible-container run**：这将启动 `container.yml` 文件中定义的容器

+   **ansible-container push**：这将根据用户选择将项目的镜像推送到私有或公共仓库

+   **ansible-container shipit**：这将导出必要的 playbooks 和角色以部署容器到支持的云提供商

如在 GitHub 上的示例中所示，可以在 `container.yml` 文件中以以下方式定义 Django 服务：

```
    version: "1"
    services:
      django:
        image: centos:7
        expose:
          - "8080"
        working_dir: '/django'

```

# Chef

Chef 有一些重要的组件，如 cookbook 和 recipes。Cookbook 定义了一个场景并包含了一切；其中第一个是 recipes，它是组织中的一个基本配置元素，使用 Ruby 语言编写。它主要是使用模式定义的资源集合。Cookbook 还包含属性值、文件分发和模板。Chef 允许以可版本控制、可测试和可重复的方式管理 Docker 容器。它为基于容器的开发提供了构建高效工作流和管理发布流水线的能力。Chef delivery 允许您自动化并使用可扩展的工作流来测试、开发和发布 Docker 容器。

Docker cookbook 可在 GitHub 上找到（[`github.com/chef-cookbooks/docker`](https://github.com/chef-cookbooks/docker)），并提供自定义资源以在配方中使用。它提供了各种选项，例如以下内容：

+   `docker_service`：这些是用于 `docker_installation` 和 `docker_service` 管理器的复合资源

+   `docker_image`: 这个用于从仓库中拉取 Docker 镜像

+   `docker_container`: 这个处理所有 Docker 容器操作

+   `docker_registry`: 这个处理所有 Docker 注册操作

+   `docker_volume`: 这个管理 Docker 容器所有卷相关的操作

以下是一个样本 Chef Docker 配方，可用作参考以使用 Chef 配方部署容器：

```
    # Pull latest nginx image
    docker_image 'nginx' do
      tag 'latest'
      action :pull
      notifies :redeploy, 'docker_container[sample_nginx]'
    end

    # Run container by exposing the ports
    docker_container 'sample_nginx' do
      repo 'nginx'
      tag 'latest'
      port '80:80'
      host_name 'www'
      domain_name 'computers.biz'
      env 'FOO=bar'
      volumes [ '/some/local/files/:/etc/nginx/conf.d' ]
    end

```

# 总结

在本章中，我们首先深入研究了特权容器，它可以访问所有主机设备以及超级特权容器，展示了容器管理在后台运行服务的能力，这可以用于在 Docker 容器中运行服务以管理底层主机。然后，我们研究了 Puppet，一个重要的编排工具，以及它如何借助 `garethr-docker` GitHub 项目来处理容器管理。我们还研究了 Ansible 和 Chef，它们提供了类似的能力，可以规模化地管理 Docker 容器。在下一章中，我们将探索 Docker 网络堆栈。


# 第七章：管理 Docker 容器的网络堆栈

在本章中，我们将涵盖以下主题：

+   docker0 桥

+   故障排除 Docker 桥接配置

+   配置 DNS

+   排除容器之间和外部网络之间的通信故障

+   ibnetwork 和容器网络模型

+   基于覆盖和底层网络的 Docker 网络工具

+   Docker 网络工具的比较

+   配置**OpenvSwitch**（OVS）以与 Docker 一起工作

# Docker 网络

每个 Docker 容器都有自己的网络堆栈，这是由于 Linux 内核的`net`命名空间，为每个容器实例化了一个新的`net`命名空间，外部容器或其他容器无法看到。

Docker 网络由以下网络组件和服务提供支持：

+   **Linux 桥接器**：内核中内置的 L2/MAC 学习交换机，用于转发

+   **Open vSwitch**：可编程的高级桥接器，支持隧道

+   **网络地址转换器（NAT）**：这些是立即实体，用于转换 IP 地址+端口（SNAT，DNAT）

+   **IPtables**：内核中的策略引擎，用于管理数据包转发、防火墙和 NAT 功能

+   **Apparmor/SElinux**：可以为每个应用程序定义防火墙策略

可以使用各种网络组件来与 Docker 一起工作，提供了访问和使用基于 Docker 的服务的新方法。因此，我们看到了许多遵循不同网络方法的库。一些著名的库包括 Docker Compose、Weave、Kubernetes、Pipework 和 libnetwork。以下图表描述了 Docker 网络的根本思想：

![Docker 网络](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_07_001-2.jpg)

Docker 网络模式

# docker0 桥

**docker0 桥**是默认网络的核心。启动 Docker 服务时，在主机上创建一个 Linux 桥接器。容器上的接口与桥接器通信，桥接器代理到外部世界。同一主机上的多个容器可以通过 Linux 桥接器相互通信。

docker0 可以通过`--net`标志进行配置，通常有四种模式：

+   `--net default`：在此模式下，默认桥用作容器相互连接的桥

+   `--net=none`：使用此标志，创建的容器是真正隔离的，无法连接到网络

+   `--net=container:$container2`：使用此标志，创建的容器与名为`$container2`的容器共享其网络命名空间

+   `--net=host`：在此模式下，创建的容器与主机共享其网络命名空间

## 故障排除 Docker 桥接配置

在本节中，我们将看看容器端口是如何映射到主机端口的，以及我们如何解决连接容器到外部世界的问题。这种映射可以由 Docker 引擎隐式完成，也可以被指定。

如果我们创建两个容器-**容器 1**和**容器 2**-它们都被分配了来自私有 IP 地址空间的 IP 地址，并且也连接到**docker0 桥**，如下图所示：

![故障排除 Docker 桥接配置](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_07_002.jpg)

两个容器通过 Docker0 桥进行通信

前述的两个容器将能够相互 ping 通，也能够访问外部世界。对于外部访问，它们的端口将被映射到主机端口。正如前一节中提到的，容器使用网络命名空间。当第一个容器被创建时，为该容器创建了一个新的网络命名空间。

在容器和 Linux 桥之间创建了一个**虚拟以太网**（**vEthernet**或**vEth**）链接。从容器的`eth0`端口发送的流量通过 vEth 接口到达桥接，然后进行切换：

```
# show linux bridges 
$ sudo brctl show 

```

上述命令的输出将类似于以下内容，其中包括桥接名称和容器上的 vEth 接口：

```
$ bridge name  bridge            id    STP       enabled interfaces 
docker0        8000.56847afe9799 no    veth44cb727    veth98c3700 

```

### 将容器连接到外部世界

主机上的**iptables NAT**表用于伪装所有外部连接，如下所示：

```
$ sudo iptables -t nat -L -n 
... 
Chain POSTROUTING (policy ACCEPT) target prot opt 
source destination MASQUERADE all -- 172.17.0.0/16 
!172.17.0.0/16 
... 

```

### 从外部世界访问容器

端口映射再次使用主机上的 iptables NAT 选项进行，如下图所示，其中容器 1 的端口映射用于与外部世界通信。我们将在本章的后面部分详细讨论。

![从外部世界访问容器](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_07_003.jpg)

容器 1 的端口映射，以与外部世界通信

Docker 服务器默认在 Linux 内核中创建了一个`docker0`桥，可以在其他物理或虚拟网络接口之间传递数据包，使它们表现为单个以太网网络：

```
root@ubuntu:~# ifconfig 
docker0   Link encap:Ethernet  HWaddr 56:84:7a:fe:97:99 
inet addr:172.17.42.1  Bcast:0.0.0.0  Mask:255.255.0.0 
inet6 addr: fe80::5484:7aff:fefe:9799/64 Scope:Link 
inet6 addr: fe80::1/64 Scope:Link 
... 
collisions:0 txqueuelen:0 
RX bytes:516868 (516.8 KB)  TX bytes:46460483 (46.4 MB) 
eth0      Link encap:Ethernet  HWaddr 00:0c:29:0d:f4:2c 
inet addr:192.168.186.129  Bcast:192.168.186.255  
    Mask:255.255.255.0 

```

一旦我们有一个或多个容器正在运行，我们可以通过在主机上运行 `brctl` 命令并查看输出的接口列来确认 Docker 是否已将它们正确连接到 docker0 桥接。首先，使用以下命令安装桥接实用程序：

```
$ apt-get install bridge-utils 

```

这里有一个主机，连接了两个不同的容器：

```
root@ubuntu:~# brctl show 
bridge name     bridge id           STP enabled   interfaces
docker0         8000.56847afe9799   no            veth21b2e16
                                                  veth7092a45 

```

Docker 在创建容器时使用 docker0 桥接设置。每当创建新容器时，它会从桥接可用的范围中分配一个新的 IP 地址：

```
root@ubuntu:~# docker run -t -i --name container1 ubuntu:latest /bin/bash 
root@e54e9312dc04:/# ifconfig 
eth0 Link encap:Ethernet HWaddr 02:42:ac:11:00:07 
inet addr:172.17.0.7 Bcast:0.0.0.0 Mask:255.255.0.0 
inet6 addr: 2001:db8:1::242:ac11:7/64 Scope:Global 
inet6 addr: fe80::42:acff:fe11:7/64 Scope:Link 
UP BROADCAST RUNNING MULTICAST MTU:1500 Metric:1 
... 
root@e54e9312dc04:/# ip route 
default via 172.17.42.1 dev eth0 
172.17.0.0/16 dev eth0 proto kernel scope link src 172.17.0.7 

```

### 注意

默认情况下，Docker 提供了一个名为 vnet docker0 的桥接，其 IP 地址为 `172.17.42.1`。Docker 容器的 IP 地址在 `172.17.0.0/16` 范围内。

要更改 Docker 中的默认设置，请修改 `/etc/default/docker` 文件。

将默认的桥接从 `docker0` 更改为 `br0`：

```
# sudo service docker stop 
# sudo ip link set dev docker0 down 
# sudo brctl delbr docker0 
# sudo iptables -t nat -F POSTROUTING 
# echo 'DOCKER_OPTS="-b=br0"' >> /etc/default/docker 
# sudo brctl addbr br0 
# sudo ip addr add 192.168.10.1/24 dev br0 
# sudo ip link set dev br0 up 
# sudo service docker start 

```

以下命令显示了 Docker 服务的新桥接名称和 IP 地址范围：

```
root@ubuntu:~# ifconfig 
br0       Link encap:Ethernet  HWaddr ae:b2:dc:ed:e6:af 
inet addr:192.168.10.1  Bcast:0.0.0.0  Mask:255.255.255.0 
inet6 addr: fe80::acb2:dcff:feed:e6af/64 Scope:Link 
UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1 
RX packets:0 errors:0 dropped:0 overruns:0 frame:0 
TX packets:7 errors:0 dropped:0 overruns:0 carrier:0 
collisions:0 txqueuelen:0 
RX bytes:0 (0.0 B)  TX bytes:738 (738.0 B) 
eth0      Link encap:Ethernet  HWaddr 00:0c:29:0d:f4:2c 
inet addr:192.168.186.129  Bcast:192.168.186.255  Mask:255.255.255.0 
inet6 addr: fe80::20c:29ff:fe0d:f42c/64 Scope:Link 
... 

```

# 配置 DNS

Docker 为每个容器提供主机名和 DNS 配置，而无需构建自定义镜像。它通过虚拟文件覆盖容器内的 `/etc` 文件，可以在其中写入新信息。

可以通过在容器内运行 `mount` 命令来查看。容器在初始创建时会接收与主机机器相同的 `/resolv.conf`。如果主机的 `/resolv.conf` 文件被修改，只有在容器重新启动时，容器的 `/resolv.conf` 文件才会反映这些修改。

在 Docker 中，可以通过两种方式设置 `dns` 选项：

+   使用 `docker run --dns=<ip-address>`

+   在 Docker 守护程序文件中，添加 `DOCKER_OPTS="--dns ip-address"`

### 提示

您还可以使用 `--dns-search=<DOMAIN>` 指定搜索域。

以下图表显示了在容器中使用 Docker 守护程序文件中的 `DOCKER_OPTS` 设置配置名称服务器：

![配置 DNS](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_07_004.jpg)

使用 DOCKER_OPTS 来设置 Docker 容器的名称服务器设置

主要的 DNS 文件如下：

```
/etc/hostname 
/etc/resolv.conf 
/etc/hosts 

```

以下是添加 DNS 服务器的命令：

```
# docker run --dns=8.8.8.8 --net="bridge" -t -i  ubuntu:latest /bin/bash 

```

以下是添加主机名的命令：

```
#docker run --dns=8.8.8.8 --hostname=docker-vm1  -t -i  ubuntu:latest 
    /bin/bash 

```

# 解决容器与外部网络之间的通信问题

只有在将 `ip_forward` 参数设置为 `1` 时，数据包才能在容器之间传递。通常情况下，您会将 Docker 服务器保留在默认设置 `--ip-forward=true`，并且当服务器启动时，Docker 会为您设置 `ip_forward` 为 `1`。要检查设置，请使用以下命令：

```
# cat /proc/sys/net/ipv4/ip_forward 
0 
# echo 1 > /proc/sys/net/ipv4/ip_forward 
# cat /proc/sys/net/ipv4/ip_forward 
1 

```

通过启用`ip-forward`，用户可以使容器与外部世界之间的通信成为可能；如果您处于多个桥接设置中，还需要进行容器间通信：

![容器和外部网络之间通信的故障排除](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_07_005.jpg)

ip-forward = true 将所有数据包转发到/从容器到外部网络

Docker 不会删除或修改 Docker 过滤链中的任何现有规则。这允许用户创建规则来限制对容器的访问。Docker 使用 docker0 桥来在单个主机中的所有容器之间进行数据包流动。它在 iptables 的`FORWARD`链中添加了一个规则（空白接受策略），以便两个容器之间的数据包流动。`--icc=false`选项将`DROP`所有数据包。

当 Docker 守护程序配置为`--icc=false`和`--iptables=true`，并且使用`--link=`选项调用 Docker 运行时，Docker 服务器将为新容器插入一对 iptables `ACCEPT`规则，以便连接到其他容器公开的端口-这些端口在其 Dockerfile 的`EXPOSE`行中提到：

![容器和外部网络之间通信的故障排除](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_07_006.jpg)

ip-forward = false 将所有数据包转发到/从容器到外部网络

默认情况下，Docker 的转发规则允许所有外部 IP。要仅允许特定 IP 或网络访问容器，请在 Docker 过滤链的顶部插入一个否定规则。

例如，您可以限制外部访问，使只有源 IP`10.10.10.10`可以使用以下命令访问容器：

```
#iptables -I DOCKER -i ext_if ! -s 10.10.10.10 -j DROP 

```

### 注意

**参考:**

[`docs.docker.com/v1.5/articles/networking/`](https://docs.docker.com/v1.5/articles/networking/)

[`docs.docker.com/engine/userguide/networking/`](https://docs.docker.com/v1.5/articles/networking/)

[`containerops.org/`](https://docs.docker.com/engine/userguide/networking/)

## 限制一个容器对另一个容器的 SSH 访问

要限制一个容器对另一个容器的 SSH 访问，请执行以下步骤：

1.  创建两个容器，c1 和 c2：

```
# docker run -i -t --name c1 ubuntu:latest /bin/bash 
root@7bc2b6cb1025:/# ifconfig 
eth0 Link encap:Ethernet HWaddr 02:42:ac:11:00:05 
inet addr:172.17.0.5 Bcast:0.0.0.0 Mask:255.255.0.0 
inet6 addr: 2001:db8:1::242:ac11:5/64 Scope:Global 
inet6 addr: fe80::42:acff:fe11:5/64 Scope:Link 
... 
# docker run -i -t --name c2 ubuntu:latest /bin/bash 
root@e58a9bf7120b:/# ifconfig
        eth0 Link encap:Ethernet HWaddr 02:42:ac:11:00:06
         inet addr:172.17.0.6 Bcast:0.0.0.0 Mask:255.255.0.0
         inet6 addr: 2001:db8:1::242:ac11:6/64 Scope:Global
         inet6 addr: fe80::42:acff:fe11:6/64 Scope:Link 

```

1.  我们可以使用刚刚发现的 IP 地址测试容器之间的连通性。现在让我们使用`ping`工具来看一下。

1.  让我们进入另一个容器 c1，并尝试 ping c2：

```
root@7bc2b6cb1025:/# ping 172.17.0.6
        PING 172.17.0.6 (172.17.0.6) 56(84) bytes of data.
        64 bytes from 172.17.0.6: icmp_seq=1 ttl=64 time=0.139 ms
        64 bytes from 172.17.0.6: icmp_seq=2 ttl=64 time=0.110 ms
        ^C
        --- 172.17.0.6 ping statistics ---
        2 packets transmitted, 2 received, 0% packet loss, time 999ms
        rtt min/avg/max/mdev = 0.110/0.124/0.139/0.018 ms
        root@7bc2b6cb1025:/#
        root@e58a9bf7120b:/# ping 172.17.0.5
        PING 172.17.0.5 (172.17.0.5) 56(84) bytes of data.
        64 bytes from 172.17.0.5: icmp_seq=1 ttl=64 time=0.270 ms
        64 bytes from 172.17.0.5: icmp_seq=2 ttl=64 time=0.107 ms
        ^C
        --- 172.17.0.5 ping statistics ---

        2 packets transmitted, 2 received, 0% packet loss, time 1002ms
        rtt min/avg/max/mdev = 0.107/0.188/0.270/0.082 ms
        root@e58a9bf7120b:/# 

```

1.  在两个容器上安装`openssh-server`：

```
#apt-get install openssh-server 

```

1.  在主机上启用 iptables。最初，您将能够从一个容器 SSH 到另一个容器。

1.  停止 Docker 服务，并在主机机器的`default docker`文件中添加`DOCKER_OPTS="--icc=false --iptables=true"`。此选项将启用 iptables 防火墙并在容器之间关闭所有端口。默认情况下，主机上未启用 iptables：

```
root@ubuntu:~# iptables -L -n
        Chain INPUT (policy ACCEPT)
        target prot opt source destination
        Chain FORWARD (policy ACCEPT)
        target prot opt source destination
        DOCKER all -- 0.0.0.0/0 0.0.0.0/0
        ACCEPT all -- 0.0.0.0/0 0.0.0.0/0 ctstate RELATED,ESTABLISHED
        ACCEPT all -- 0.0.0.0/0 0.0.0.0/0
        DOCKER all -- 0.0.0.0/0 0.0.0.0/0
        ACCEPT all -- 0.0.0.0/0 0.0.0.0/0 ctstate RELATED,ESTABLISHED
        ACCEPT all -- 0.0.0.0/0 0.0.0.0/0
        ACCEPT all -- 0.0.0.0/0 0.0.0.0/0 
ACCEPT all -- 0.0.0.0/0 0.0.0.0/0 
#service docker stop 
#vi /etc/default/docker 

```

1.  Docker Upstart 和 SysVinit 配置文件，自定义 Docker 二进制文件的位置（特别是用于开发测试）：

```
#DOCKER="/usr/local/bin/docker" 

```

1.  使用`DOCKER_OPTS`来修改守护程序的启动选项：

```
#DOCKER_OPTS="--dns 8.8.8.8 --dns 8.8.4.4" 
#DOCKER_OPTS="--icc=false --iptables=true" 

```

1.  重启 Docker 服务：

```
# service docker start 

```

1.  检查 iptables：

```
root@ubuntu:~# iptables -L -n 
Chain INPUT (policy ACCEPT) 
target prot opt source destination 
Chain FORWARD (policy ACCEPT) 
target prot opt source destination 
DOCKER all -- 0.0.0.0/0 0.0.0.0/0 
ACCEPT all -- 0.0.0.0/0 0.0.0.0/0 ctstate RELATED, ESTABLISHED 
ACCEPT all -- 0.0.0.0/0 0.0.0.0/0 
DOCKER all -- 0.0.0.0/0 0.0.0.0/0 
ACCEPT all -- 0.0.0.0/0 0.0.0.0/0 ctstate RELATED, ESTABLISHED 
ACCEPT all -- 0.0.0.0/0 0.0.0.0/0 
ACCEPT all -- 0.0.0.0/0 0.0.0.0/0 
DROP all -- 0.0.0.0/0 0.0.0.0/0 

```

`DROP`规则已添加到主机机器的 iptables 中，这会中断容器之间的连接。现在您将无法在容器之间进行 SSH 连接。

## 链接容器

我们可以使用`--link`参数来通信或连接传统容器。

1.  创建将充当服务器的第一个容器-`sshserver`：

```
root@ubuntu:~# docker run -i -t -p 2222:22 --name sshserver ubuntu bash 
root@9770be5acbab:/# 
Execute the iptables command and you can find a Docker chain rule added. 
#root@ubuntu:~# iptables -L -n 
Chain INPUT (policy ACCEPT) 
target     prot opt source               destination 
Chain FORWARD (policy ACCEPT) 
target     prot opt source               destination 
Chain OUTPUT (policy ACCEPT) 
target     prot opt source               destination 
Chain DOCKER (0 references) 
target     prot opt source               destination 
ACCEPT     tcp  --  0.0.0.0/0            172.17.0.3           tcp dpt:22 

```

1.  创建一个充当 SSH 客户端的第二个容器：

```
root@ubuntu:~# docker run -i -t --name sshclient --link 
        sshserver:sshserver 
        ubuntu bash 
root@979d46c5c6a5:/# 

```

1.  我们可以看到 Docker 链规则中添加了更多规则：

```
root@ubuntu:~# iptables -L -n 
Chain INPUT (policy ACCEPT) 
target     prot opt source               destination 
Chain FORWARD (policy ACCEPT) 
target     prot opt source               destination 
Chain OUTPUT (policy ACCEPT) 
target     prot opt source               destination 
Chain DOCKER (0 references) 
target     prot opt source               destination 
ACCEPT     tcp  --  0.0.0.0/0            172.17.0.3           tcp dpt:22 
ACCEPT     tcp  --  172.17.0.4           172.17.0.3           tcp dpt:22 
ACCEPT     tcp  --  172.17.0.3           172.17.0.4           tcp spt:22 
root@ubuntu:~# 

```

以下图解释了使用`--link`标志的容器之间的通信：

![链接容器](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_07_007.jpg)

Docker--link 在容器之间创建私有通道

1.  您可以使用`docker inspect`检查您的链接容器：

```
root@ubuntu:~# docker inspect -f "{{ .HostConfig.Links }}" sshclient 
[/sshserver:/sshclient/sshserver] 

```

1.  现在您可以成功地通过 SSH 连接到 SSH 服务器：

```
**#ssh root@172.17.0.3 -p 22** 

```

使用`--link`参数，Docker 在容器之间创建了一个安全通道，无需在容器上外部公开任何端口。

# libnetwork 和容器网络模型

libnetwork 是用 Go 实现的，用于连接 Docker 容器。其目标是提供一个**容器网络模型**（**CNM**），帮助程序员提供网络库的抽象。libnetwork 的长期目标是遵循 Docker 和 Linux 的理念，提供独立工作的模块。libnetwork 的目标是提供容器网络的可组合需求。它还旨在通过以下方式将 Docker Engine 和 libcontainer 中的网络逻辑模块化为单一可重用库：

+   用 libnetwork 替换 Docker Engine 的网络模块

+   允许本地和远程驱动程序为容器提供网络

+   提供一个用于管理和测试 libnetwork 的`dnet`工具-但是，这仍然是一个正在进行中的工作

### 注意

**参考:** [`github.com/docker/libnetwork/issues/45`](https://github.com/docker/libnetwork/issues/45)

libnetwork 实现了 CNM。它规范了为容器提供网络的步骤，同时提供了一个抽象，可用于支持多个网络驱动程序。其端点 API 主要用于管理相应的对象，并对其进行簿记，以提供 CNM 所需的抽象级别。

## CNM 对象

CNM 建立在三个主要组件上，如下图所示：

![CNM 对象](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_07_008.jpg)

libnetwork 的网络沙盒模型

### 注意

**参考：**[`www.docker.com`](https://www.docker.com)

### 沙盒

沙盒包含容器的网络堆栈配置，包括路由表的管理、容器的接口和 DNS 设置。沙盒的实现可以是 Linux 网络命名空间、FreeBSD 监狱或类似的概念。

一个沙盒可以包含来自多个网络的许多端点。它还表示容器的网络配置，如 IP 地址、MAC 地址和 DNS 条目。

libnetwork 利用特定于操作系统的参数来填充由沙盒表示的网络配置。它提供了一个框架来在多个操作系统中实现沙盒。

**Netlink**用于管理命名空间中的路由表，目前存在两种沙盒的实现-`namespace_linux.go`和`configure_linux.go`-以唯一标识主机文件系统上的路径。一个沙盒与一个 Docker 容器关联。

以下数据结构显示了沙盒的运行时元素：

```
    type sandbox struct {
          id            string
           containerID   string
          config        containerConfig
          osSbox        osl.Sandbox
          controller    *controller
          refCnt        int
          endpoints     epHeap
          epPriority    map[string]int
          joinLeaveDone chan struct{}
          dbIndex       uint64
          dbExists      bool
          isStub        bool
          inDelete      bool
          sync.Mutex
    }

```

一个新的沙盒是从网络控制器实例化的（稍后将详细解释）：

```
    func (c *controller) NewSandbox(containerID string, options ...SandboxOption) 
     (Sandbox, error) {
        .....
    }

```

### 端点

一个端点将一个沙盒连接到一个网络，并为容器公开的服务提供与部署在同一网络中的其他容器的连接。它可以是 Open vSwitch 的内部端口或类似的 vEth 对。

一个端点只能属于一个网络，也只能属于一个沙盒。它表示一个服务，并提供各种 API 来创建和管理端点。它具有全局范围，但只附加到一个网络。

一个端点由以下结构指定：

```
    type endpoint struct { 
       name          string 
       id            string 
       network       *network 
       iface         *endpointInterface 
       joinInfo      *endpointJoinInfo 
       sandboxID     string 
       exposedPorts  []types.TransportPort 
       anonymous     bool 
       generic      map[string]interface{} 
       joinLeaveDone chan struct{} 
       prefAddress   net.IP 
       prefAddressV6 net.IP 
       ipamOptions   map[string]string 
       dbIndex       uint64 
       dbExists      bool 
       sync.Mutex 
    }
```

一个端点与唯一的 ID 和名称相关联。它附加到一个网络和一个沙盒 ID。它还与 IPv4 和 IPv6 地址空间相关联。每个端点与一个端点接口相关联。

### 网络

能够直接相互通信的一组端点称为**网络**。它在同一主机或多个主机之间提供所需的连接，并在创建或更新网络时通知相应的驱动程序。例如，VLAN 或 Linux 桥在集群中具有全局范围。

网络是从网络控制器中控制的，我们将在下一节中讨论。每个网络都有名称、地址空间、ID 和网络类型：

```
    type network struct { 
       ctrlr        *controller 
       name         string 
       networkType  string 
       id           string 
       ipamType     string 
       addrSpace    string 
       ipamV4Config []*IpamConf 
       ipamV6Config []*IpamConf 
       ipamV4Info   []*IpamInfo 
       ipamV6Info   []*IpamInfo 
       enableIPv6   bool 
       postIPv6     bool 
       epCnt        *endpointCnt 
       generic      options.Generic 
       dbIndex      uint64 
       svcRecords   svcMap 
       dbExists     bool 
       persist      bool 
       stopWatchCh  chan struct{} 
       drvOnce      *sync.Once 
       internal     bool 
       sync.Mutex   
    }
```

### 网络控制器

网络控制器对象提供 API 来创建和管理网络对象。它是通过将特定驱动程序绑定到给定网络来绑定到 libnetwork 的入口点，并支持多个活动驱动程序，包括内置和远程驱动程序。网络控制器允许用户将特定驱动程序绑定到给定网络：

```
    type controller struct { 
       id             string 
       drivers        driverTable 
       ipamDrivers    ipamTable 
       sandboxes      sandboxTable 
       cfg            *config.Config 
       stores         []datastore.DataStore 
       discovery     hostdiscovery.HostDiscovery 
       extKeyListener net.Listener 
       watchCh        chan *endpoint 
       unWatchCh      chan *endpoint 
       svcDb          map[string]svcMap 
       nmap           map[string]*netWatch 
       defOsSbox      osl.Sandbox 
       sboxOnce       sync.Once 
       sync.Mutex 
    }   

```

每个网络控制器都引用以下内容：

+   一个或多个数据结构驱动程序表中的驱动程序

+   一个或多个数据结构中的沙盒

+   数据存储

+   一个 ipamTable![网络控制器](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_07_009.jpg)

网络控制器处理 Docker 容器和 Docker 引擎之间的网络

上图显示了网络控制器如何位于 Docker 引擎、容器和它们连接的网络之间。

### CNM 属性

以下是 CNM 属性：

+   **选项：**这些对终端用户不可见，但是数据的键值对，提供了一种灵活的机制，可以直接从用户传递到驱动程序。只有当键与已知标签匹配时，libnetwork 才会处理选项，结果是选择了一个由通用对象表示的值。

+   **标签：**这些是在 UI 中使用`--labels`选项表示的终端用户可变的选项子集。它们的主要功能是执行特定于驱动程序的操作，并从 UI 传递。

### CNM 生命周期

CNM 的使用者通过 CNM 对象及其 API 与其管理的容器进行网络交互；驱动程序向网络控制器注册。

内置驱动程序在 libnetwork 内注册，而远程驱动程序使用插件机制向 libnetwork 注册。

每个驱动程序处理特定的网络类型，如下所述：

+   使用`libnetwork.New()` API 创建一个网络控制器对象，以管理网络的分配，并可选择使用特定于驱动程序的选项进行配置。使用控制器的`NewNetwork()` API 创建网络对象，作为参数添加了`name`和`NetworkType`。

+   `NetworkType`参数有助于选择驱动程序并将创建的网络绑定到该驱动程序。对网络的所有操作都将由使用前面的 API 创建的驱动程序处理。

+   `Controller.NewNetwork()` API 接受一个可选的选项参数，其中包含驱动程序特定的选项和标签，驱动程序可以用于其目的。

+   调用`Network.CreateEndpoint()`在给定网络中创建一个新的端点。此 API 还接受可选的选项参数，这些参数随驱动程序而异。

+   `CreateEndpoint()`在创建网络中的端点时可以选择保留 IPv4/IPv6 地址。驱动程序使用`driverapi`中定义的`InterfaceInfo`接口分配这些地址。IPv4/IPv6 地址是完成端点作为服务定义所需的，还有端点暴露的端口。服务端点是应用程序容器正在侦听的网络地址和端口号。

+   `Endpoint.Join()`用于将容器附加到端点。如果不存在该容器的沙盒，`Join`操作将创建一个沙盒。驱动程序利用沙盒密钥来标识附加到同一容器的多个端点。

有一个单独的 API 用于创建端点，另一个用于加入端点。

端点表示与容器无关的服务。创建端点时，为容器保留了资源，以便稍后附加到端点。它提供了一致的网络行为。

+   当容器停止时，将调用`Endpoint.Leave()`。驱动程序可以清理在`Join()`调用期间分配的状态。当最后一个引用端点离开网络时，libnetwork 将删除沙盒。

+   只要端点仍然存在，libnetwork 就会持有 IP 地址。当容器（或任何容器）再次加入时，这些地址将被重用。它确保了在停止和重新启动时重用容器的资源。

+   `Endpoint.Delete()`从网络中删除一个端点。这将导致删除端点并清理缓存的`sandbox.Info`。

+   `Network.Delete()` 用于删除网络。如果没有端点连接到网络，则允许删除。

# 基于覆盖和底层网络的 Docker 网络工具

覆盖是建立在底层网络基础设施（底层）之上的虚拟网络。其目的是实现在物理网络中不可用的网络服务。

网络覆盖大大增加了可以在物理网络之上创建的虚拟子网的数量，从而支持多租户和虚拟化功能。

Docker 中的每个容器都分配了一个用于与其他容器通信的 IP 地址。如果容器需要与外部网络通信，您需要在主机系统中设置网络并将容器的端口暴露或映射到主机。在容器内运行此应用程序时，容器将无法广告其外部 IP 和端口，因为它们无法获取此信息。

解决方案是在所有主机上为每个 Docker 容器分配唯一的 IP，并有一些网络产品在主机之间路由流量。

有不同的项目和工具可帮助处理 Docker 网络，如下所示：

+   Flannel

+   Weave

+   Project Calico

## Flannel

**Flannel** 为每个容器分配一个 IP，可用于容器之间的通信。通过数据包封装，它在主机网络上创建一个虚拟覆盖网络。默认情况下，flannel 为主机提供一个`/24`子网，Docker 守护程序将从中为容器分配 IP。

![Flannel](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_07_010.jpg)

使用 Flannel 进行容器之间的通信

Flannel 在每个主机上运行一个代理`flanneld`，负责从预配置的地址空间中分配子网租约。Flannel 使用`etcd` ([`github.com/coreos/etcd`](https://github.com/coreos/etcd))存储网络配置、分配的子网和辅助数据（如主机的 IP）。

为了提供封装，Flannel 使用**Universal TUN/TAP**设备，并使用 UDP 创建覆盖网络以封装 IP 数据包。子网分配是通过`etcd`完成的，它维护覆盖子网到主机的映射。

## Weave

**Weave** 创建一个虚拟网络，连接部署在主机/虚拟机上的 Docker 容器，并实现它们的自动发现。

![Weave](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_07_011.jpg)

Weave 网络

Weave 可以穿越防火墙，在部分连接的网络中运行。流量可以选择加密，允许主机/虚拟机在不受信任的网络中连接。

Weave 增强了 Docker 现有（单个主机）的网络功能，如 docker0 桥，以便这些功能可以继续被容器使用。

## Calico 项目

**Calico 项目**为连接容器、虚拟机或裸机提供可扩展的网络解决方案。Calico 使用可扩展的 IP 网络原则作为第 3 层方法提供连接。Calico 可以在不使用覆盖或封装的情况下部署。Calico 服务应该作为每个节点上的一个容器部署。它为每个容器提供自己的 IP 地址，并处理所有必要的 IP 路由、安全策略规则和在节点集群中分发路由的工作。

Calico 架构包含四个重要组件，以提供更好的网络解决方案：

+   **Felix**，Calico 工作进程，是 Calico 网络的核心，主要路由并提供所需的与主机上工作负载之间的连接。它还为传出端点流量提供与内核的接口。

+   **BIRD**，路由 ic。BIRD，路由分发开源 BGP，交换主机之间的路由信息。BIRD 捡起的内核端点被分发给 BGP 对等体，以提供主机之间的路由。在*calico-node*容器中运行两个 BIRD 进程，一个用于 IPv4（bird），另一个用于 IPv6（bird6）。

+   **confd**，一个用于自动生成 BIRD 配置的模板处理过程，监视`etcd`存储中对 BGP 配置的任何更改，如日志级别和 IPAM 信息。`confd`还根据来自`etcd`的数据动态生成 BIRD 配置文件，并在数据应用更新时自动触发。`confd`在配置文件更改时触发 BIRD 加载新文件。

+   **calicoctl**是用于配置和启动 Calico 服务的命令行。它甚至允许使用数据存储（`etcd`）定义和应用安全策略。该工具还提供了通用管理 Calico 配置的简单界面，无论 Calico 是在虚拟机、容器还是裸机上运行，都支持以下命令在`calicoctl`上。

```
$ calicoctl 
Override the host:port of the ETCD server by setting the 
         environment 
        variable 
ETCD_AUTHORITY [default: 127.0.0.1:2379] 
Usage: calicoctl <command> [<args>...] 
status            Print current status information 
node              Configure the main calico/node container and 
         establish 
                          Calico 
networking 
container         Configure containers and their addresses 
profile           Configure endpoint profiles 
endpoint          Configure the endpoints assigned to existing 
         containers 
pool              Configure ip-pools 
bgp               Configure global bgp 
ipam              Configure IP address management 
checksystem       Check for incompatibilities on the host 
         system 
diags             Save diagnostic information 
version           Display the version of calicoctl 
config            Configure low-level component configuration 
        See 'calicoctl <command> --help' to read about a specific 
         subcommand. 

```

根据 Calico 存储库的官方 GitHub 页面（[`github.com/projectcalico/calico-containers`](https://github.com/projectcalico/calico-containers)），存在以下 Calico 集成：

+   Calico 作为 Docker 网络插件

+   没有 Docker 网络的 Calico

+   Calico 与 Kubernetes

+   Calico 与 Mesos

+   Calico 与 Docker Swarm![Project Calico](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_07_012.jpg)

Calico 架构

# 使用 Docker 引擎 swarm 节点配置覆盖网络

随着 Docker 1.9 的发布，多主机和覆盖网络已成为其主要功能之一。它可以建立私有网络，以连接多个容器。我们将在 swarm 集群中运行的管理器节点上创建覆盖网络，而无需外部键值存储。swarm 网络将使需要该服务的 swarm 节点可用于网络。

当部署使用覆盖网络的服务时，管理器会自动将网络扩展到运行服务任务的节点。多主机网络需要一个用于服务发现的存储，所以现在我们将创建一个 Docker 机器来运行这项服务。

![使用 Docker 引擎 swarm 节点配置覆盖网络](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_07_013.jpg)

跨多个主机的覆盖网络

对于以下部署，我们将使用 Docker 机器应用程序在虚拟化或云平台上创建 Docker 守护程序。对于虚拟化平台，我们将使用 VMware Fusion 作为提供者。

Docker-machine 的安装如下：

```
$ curl -L https://github.com/docker/machine/releases/download/
    v0.7.0/docker-machine-`uname -s`-`uname -m` > /usr/local/bin/
    docker-machine && \ 
> chmod +x /usr/local/bin/docker-machine 
% Total    % Received % Xferd  Average Speed   Time    Time    Time  Current 
                                     Dload  Upload   Total   Spent   Left  Speed 
100   601    0   601    0     0    266      0 --:--:--  0:00:02 --:--:--   266 
100 38.8M  100 38.8M    0     0  1420k      0  0:00:28  0:00:28 --:--:-- 1989k 
$ docker-machine version 
docker-machine version 0.7.0, build a650a40 

```

多主机网络需要一个用于服务发现的存储，因此我们将创建一个 Docker 机器来运行该服务，创建新的 Docker 守护程序：

```
$ docker-machine create \ 
>   -d vmwarefusion \ 
>   swarm-consul 
Running pre-create checks... 
(swarm-consul) Default Boot2Docker ISO is out-of-date, downloading the latest 
    release... 
(swarm-consul) Latest release for github.com/boot2docker/boot2docker is 
    v1.12.1 
(swarm-consul) Downloading 
... 

```

### 提示

要查看如何将 Docker 客户端连接到在此虚拟机上运行的 Docker 引擎，请运行`docker-machine env swarm-consul`。

我们将启动 consul 容器进行服务发现：

```
$(docker-machine config swarm-consul) run \ 
>         -d \ 
>         --restart=always \ 
>         -p "8500:8500" \ 
>         -h "consul" \ 
>         progrium/consul -server -bootstrap 
Unable to find image 'progrium/consul:latest' locally 
latest: Pulling from progrium/consul 
... 
Digest: 
    sha256:8cc8023462905929df9a79ff67ee435a36848ce7a10f18d6d0faba9306b97274 
Status: Downloaded newer image for progrium/consul:latest 
d482c88d6a1ab3792aa4d6a3eb5e304733ff4d622956f40d6c792610ea3ed312 

```

创建两个 Docker 守护程序来运行 Docker 集群，第一个守护程序是 swarm 节点，将自动运行用于协调集群的 Swarm 容器：

```
$ docker-machine create \ 
>   -d vmwarefusion \ 
>   --swarm \ 
>   --swarm-master \ 
>   --swarm-discovery="consul://$(docker-machine ip swarm-
     consul):8500" \ 
>   --engine-opt="cluster-store=consul://$(docker-machine ip swarm-
    consul):8500" \ 
>   --engine-opt="cluster-advertise=eth0:2376" \ 
>   swarm-0 
Running pre-create checks... 
Creating machine... 
(swarm-0) Copying 
     /Users/vkohli/.docker/machine/cache/boot2docker.iso to 
    /Users/vkohli/.docker/machine/machines/swarm-0/boot2docker.iso... 
(swarm-0) Creating SSH key... 
(swarm-0) Creating VM... 
... 

```

Docker 已经启动运行！

### 提示

要查看如何将 Docker 客户端连接到在此虚拟机上运行的 Docker 引擎，请运行`docker-machine env swarm-0`。

第二个守护程序是 Swarm 的`secondary`节点，将自动运行一个 Swarm 容器并将状态报告给`master`节点：

```
$ docker-machine create \ 
>   -d vmwarefusion \ 
>   --swarm \ 
>   --swarm-discovery="consul://$(docker-machine ip swarm-
     consul):8500" \ 
>   --engine-opt="cluster-store=consul://$(docker-machine ip swarm-
    consul):8500" \ 
>   --engine-opt="cluster-advertise=eth0:2376" \ 
>   swarm-1 
Running pre-create checks... 
Creating machine... 
(swarm-1) Copying 
     /Users/vkohli/.docker/machine/cache/boot2docker.iso to 
    /Users/vkohli/.docker/machine/machines/swarm-1/boot2docker.iso... 
(swarm-1) Creating SSH key... 
(swarm-1) Creating VM... 
... 

```

Docker 已经启动运行！

### 提示

要查看如何将 Docker 客户端连接到在此虚拟机上运行的 Docker Engine，请运行`docker-machine env swarm-1`。

Docker 可执行文件将与一个 Docker 守护程序通信。由于我们在一个集群中，我们将通过运行以下命令来确保 Docker 守护程序与集群的通信：

```
$ eval $(docker-machine env --swarm swarm-0) 

```

之后，我们将使用覆盖驱动程序创建一个私有的`prod`网络：

```
$ docker $(docker-machine config swarm-0) network create --driver 
    overlay prod 

```

我们将使用`--net 参数`启动两个虚拟的`ubuntu:12.04`容器：

```
$ docker run -d -it --net prod --name dev-vm-1 ubuntu:12.04 
426f39dbcb87b35c977706c3484bee20ae3296ec83100926160a39190451e57a 

```

在以下代码片段中，我们可以看到这个 Docker 容器有两个网络接口：一个连接到私有覆盖网络，另一个连接到 Docker 桥接口：

```
$ docker attach 426 
root@426f39dbcb87:/# ip address 
23: eth0@if24: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1450 qdisc 
     noqueue state 
    UP 
link/ether 02:42:0a:00:00:02 brd ff:ff:ff:ff:ff:ff 
inet 10.0.0.2/24 scope global eth0 
valid_lft forever preferred_lft forever 
inet6 fe80::42:aff:fe00:2/64 scope link 
valid_lft forever preferred_lft forever 
25: eth1@if26: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc 
     noqueue state 
    UP 
link/ether 02:42:ac:12:00:02 brd ff:ff:ff:ff:ff:ff 
inet 172.18.0.2/16 scope global eth1 
valid_lft forever preferred_lft forever 
inet6 fe80::42:acff:fe12:2/64 scope link 
valid_lft forever preferred_lft forever 

```

另一个容器也将连接到另一个主机上现有的`prod`网络接口：

```
$ docker run -d -it --net prod --name dev-vm-7 ubuntu:12.04 
d073f52a7eaacc0e0cb925b65abffd17a588e6178c87183ae5e35b98b36c0c25 
$ docker attach d073 
root@d073f52a7eaa:/# ip address 
26: eth0@if27: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1450 qdisc 
     noqueue state 
    UP 
link/ether 02:42:0a:00:00:03 brd ff:ff:ff:ff:ff:ff 
inet 10.0.0.3/24 scope global eth0 
valid_lft forever preferred_lft forever 
inet6 fe80::42:aff:fe00:3/64 scope link 
valid_lft forever preferred_lft forever 
28: eth1@if29: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc 
     noqueue state 
    UP 
link/ether 02:42:ac:12:00:02 brd ff:ff:ff:ff:ff:ff 
inet 172.18.0.2/16 scope global eth1 
valid_lft forever preferred_lft forever 
inet6 fe80::42:acff:fe12:2/64 scope link 
valid_lft forever preferred_lft forever 
root@d073f52a7eaa:/# 

```

这是在 Docker Swarm 集群中跨主机配置私有网络的方法。

## 所有多主机 Docker 网络解决方案的比较

|  | **Calico** | **Flannel** | **Weave** | **Docker Overlay N/W** |
| --- | --- | --- | --- | --- |
| **网络模型** | 第 3 层解决方案 | VxLAN 或 UDP | VxLAN 或 UDP | VxLAN |
| **名称服务** | 否 | 否 | 是 | 否 |
| **协议支持** | TCP，UDP，ICMP 和 ICMPv6 | 全部 | 全部 | 全部 |
| **分布式存储** | 是 | 是 | 否 | 是 |
| **加密通道** | 否 | TLS | NaCI 库 | 否 |

# 配置 OpenvSwitch（OVS）以与 Docker 一起工作

**Open vSwitch**（**OVS**）是一个开源的**OpenFlow**能力虚拟交换机，通常与虚拟化程序一起使用，以在主机内部和跨网络的不同主机之间连接虚拟机。覆盖网络需要使用支持的隧道封装来创建虚拟数据路径，例如 VXLAN 或 GRE。

覆盖数据路径是在 Docker 主机中的隧道端点之间进行配置的，这使得给定提供者段中的所有主机看起来直接连接在一起。

当新容器上线时，前缀将在路由协议中更新，通过隧道端点宣布其位置。当其他 Docker 主机接收到更新时，转发将安装到 OVS 中，以确定主机所在的隧道端点。当主机取消配置时，类似的过程发生，隧道端点 Docker 主机将删除取消配置容器的转发条目：

![配置 OpenvSwitch（OVS）以与 Docker 一起工作](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_07_014.jpg)

通过基于 OVS 的 VXLAN 隧道在多个主机上运行的容器之间的通信

### 注意

默认情况下，Docker 使用 Linux docker0 桥；但是，在某些情况下，可能需要使用 OVS 而不是 Linux 桥。单个 Linux 桥只能处理 1,024 个端口；这限制了 Docker 的可扩展性，因为我们只能创建 1,024 个容器，每个容器只有一个网络接口。

## 故障排除 OVS 单主机设置

在单个主机上安装 OVS，创建两个容器，并将它们连接到 OVS 桥：

1.  安装 OVS：

```
$ sudo apt-get install openvswitch-switch 

```

1.  安装`ovs-docker`实用程序：

```
$ cd /usr/bin 
$ wget https://raw.githubusercontent.com/openvswitch/ovs/master 
/utilities/ovs-docker 
$ chmod a+rwx ovs-docker 

```

![故障排除 OVS 单主机设置](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_07_015.jpg)

单主机 OVS

1.  创建一个 OVS 桥。

1.  在这里，我们将添加一个新的 OVS 桥并对其进行配置，以便我们可以将容器连接到不同的网络上：

```
$ ovs-vsctl add-br ovs-br1 
$ ifconfig ovs-br1 173.16.1.1 netmask 255.255.255.0 up 

```

1.  从 OVS 桥添加端口到 Docker 容器。

1.  创建两个`ubuntu` Docker 容器：

```
$ docker run -i-t --name container1 ubuntu /bin/bash 
$ docker run -i-t --name container2 ubuntu /bin/bash 

```

1.  将容器连接到 OVS 桥：

```
# ovs-docker add-port ovs-br1 eth1 container1 --
         ipaddress=173.16.1.2/24 
# ovs-docker add-port ovs-br1 eth1 container2 --
         ipaddress=173.16.1.3/24 

```

1.  使用`ping`命令测试使用 OVS 桥连接的两个容器之间的连接。首先找出它们的 IP 地址：

```
# docker exec container1 ifconfig 
eth0      Link encap:Ethernet  HWaddr 02:42:ac:10:11:02 
inet addr:172.16.17.2  Bcast:0.0.0.0  Mask:255.255.255.0 
inet6 addr: fe80::42:acff:fe10:1102/64 Scope:Link 
... 
# docker exec container2 ifconfig 
eth0      Link encap:Ethernet  HWaddr 02:42:ac:10:11:03 
inet addr:172.16.17.3  Bcast:0.0.0.0  Mask:255.255.255.0 
inet6 addr: fe80::42:acff:fe10:1103/64 Scope:Link 
... 

```

1.  由于我们知道`container1`和`container2`的 IP 地址，我们可以运行以下命令：

```
# docker exec container2 ping 172.16.17.2 
PING 172.16.17.2 (172.16.17.2) 56(84) bytes of data. 
64 bytes from 172.16.17.2: icmp_seq=1 ttl=64 time=0.257 ms 
64 bytes from 172.16.17.2: icmp_seq=2 ttl=64 time=0.048 ms 
64 bytes from 172.16.17.2: icmp_seq=3 ttl=64 time=0.052 ms 
# docker exec container1 ping 172.16.17.2 
PING 172.16.17.2 (172.16.17.2) 56(84) bytes of data. 
64 bytes from 172.16.17.2: icmp_seq=1 ttl=64 time=0.060 ms 
64 bytes from 172.16.17.2: icmp_seq=2 ttl=64 time=0.035 ms 
64 bytes from 172.16.17.2: icmp_seq=3 ttl=64 time=0.031 ms 

```

## 故障排除 OVS 多主机设置

首先，我们将使用 OVS 在多个主机上连接 Docker 容器：

让我们考虑我们的设置，如下图所示，其中包含两个运行 Ubuntu 14.04 的主机-`Host1`和`Host2`：

1.  在两台主机上安装 Docker 和 OVS：

```
# wget -qO- https://get.docker.com/ | sh 
# sudo apt-get install openvswitch-switch 

```

1.  安装`ovs-docker`实用程序：

```
# cd /usr/bin 
# wget https://raw.githubusercontent.com/openvswitch/ovs
        /master/utilities/ovs-docker 
# chmod a+rwx ovs-docker 

```

![故障排除 OVS 多主机设置](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_07_016.jpg)

使用 OVS 进行多主机容器通信

1.  默认情况下，Docker 选择随机网络来运行其容器。它创建一个 docker0 桥，并为其分配一个 IP 地址（`172.17.42.1`）。因此，`Host1`和`Host2`的 docker0 桥 IP 地址相同，这使得两个主机中的容器难以通信。为了克服这一点，让我们为网络分配静态 IP 地址（`192.168.10.0/24`）。

更改默认的 Docker 子网：

1.  在`Host1`上执行以下命令：

```
$ service docker stop 
$ ip link set dev docker0 down 
$ ip addr del 172.17.42.1/16 dev docker0 
$ ip addr add 192.168.10.1/24 dev docker0 
$ ip link set dev docker0 up 
$ ip addr show docker0 
$ service docker start 

```

1.  添加`br0` OVS 桥：

```
$ ovs-vsctl add-br br0 

```

1.  创建到另一个主机的隧道：

```
$ ovs-vsctl add-port br0 gre0 -- set interface gre0 type=gre 
        options:remote_ip=30.30.30.8 

```

1.  将`br0`桥添加到`docker0`桥：

```
$ brctl addif docker0 br0 

```

1.  在 Host2 上执行以下命令：

```
$ service docker stop 
$ iptables -t nat -F POSTROUTING 
$ ip link set dev docker0 down 
$ ip addr del 172.17.42.1/16 dev docker0 
$ ip addr add 192.168.10.2/24 dev docker0 
$ ip link set dev docker0 up 
$ ip addr show docker0 
$ service docker start 

```

1.  添加`br0` OVS 桥：

```
$ ip link set br0 up 
$ ovs-vsctl add-br br0 

```

1.  创建到另一个主机的隧道并将其附加到：

```
# br0 bridge  
        $ ovs-vsctl add-port br0 gre0 -- set interface gre0 type=gre 
        options:remote_ip=30.30.30.7 

```

1.  将`br0`桥添加到`docker0`桥：

```
$ brctl addif docker0 br0 

```

docker0 桥连接到另一个桥-`br0`。这次，它是一个 OVS 桥，这意味着容器之间的所有流量也通过`br0`路由。此外，我们需要连接两个主机上的网络，容器正在其中运行。为此目的使用了 GRE 隧道。这个隧道连接到`br0` OVS 桥，结果也连接到`docker0`。在两个主机上执行上述命令后，您应该能够从两个主机上 ping 通`docker0`桥的地址。

在 Host1 上：

```
$ ping 192.168.10.2 
PING 192.168.10.2 (192.168.10.2) 56(84) bytes of data. 
64 bytes from 192.168.10.2: icmp_seq=1 ttl=64 time=0.088 ms 
64 bytes from 192.168.10.2: icmp_seq=2 ttl=64 time=0.032 ms 
^C 
--- 192.168.10.2 ping statistics --- 
2 packets transmitted, 2 received, 0% packet loss, time 999ms 
rtt min/avg/max/mdev = 0.032/0.060/0.088/0.028 ms 

```

在 Host2 上：

```
$ ping 192.168.10.1 
PING 192.168.10.1 (192.168.10.1) 56(84) bytes of data. 
64 bytes from 192.168.10.1: icmp_seq=1 ttl=64 time=0.088 ms 
64 bytes from 192.168.10.1: icmp_seq=2 ttl=64 time=0.032 ms 
^C 
--- 192.168.10.1 ping statistics --- 
2 packets transmitted, 2 received, 0% packet loss, time 999ms 
rtt min/avg/max/mdev = 0.032/0.060/0.088/0.028 ms 

```

1.  在主机上创建容器。

在 Host1 上，使用以下命令：

```
$ docker run -t -i --name container1 ubuntu:latest /bin/bash 

```

在 Host2 上，使用以下命令：

```
$ docker run -t -i --name container2 ubuntu:latest /bin/bash 

```

现在我们可以从`container1` ping `container2`。这样，我们使用 OVS 在多个主机上连接 Docker 容器。

# 总结

在本章中，我们学习了 Docker 网络是如何通过 docker0 桥进行连接的，以及它的故障排除问题和配置。我们还研究了 Docker 网络和外部网络之间的通信问题的故障排除。在此之后，我们深入研究了 libnetwork 和 CNM 及其生命周期。然后，我们研究了使用不同的网络选项在多个主机上跨容器进行通信，例如 Weave、OVS、Flannel 和 Docker 的最新 overlay 网络，以及它们配置中涉及的故障排除问题。

我们看到 Weave 创建了一个虚拟网络，OVS 使用了 GRE 隧道技术，Flannel 提供了一个独立的子网，Docker overlay 设置了每个主机以连接多个主机上的容器。之后，我们研究了使用 OVS 进行 Docker 网络配置以及单个主机和多个主机设置的故障排除。
