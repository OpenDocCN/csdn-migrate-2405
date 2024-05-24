# Kubernetes DevOps 手册（一）

> 原文：[`zh.annas-archive.org/md5/55C804BD2C19D0AE8370F4D1F28719E7`](https://zh.annas-archive.org/md5/55C804BD2C19D0AE8370F4D1F28719E7)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

本书将带您学习 DevOps、容器和 Kubernetes 的基本概念和有用技能的旅程。

# 本书涵盖的内容

第一章《DevOps 简介》带您了解了从过去到今天我们所说的 DevOps 的演变以及您应该了解的工具。近几年对具有 DevOps 技能的人的需求一直在迅速增长。它加速了软件开发和交付速度，也帮助了业务的敏捷性。

第二章《使用容器进行 DevOps》帮助您学习基本概念和容器编排。随着微服务的趋势，容器已成为每个 DevOps 的便捷和必要工具，因为它具有语言不可知的隔离性。

第三章《使用 Kubernetes 入门》探讨了 Kubernetes 中的关键组件和 API 对象，以及如何在 Kubernetes 集群中部署和管理容器。Kubernetes 通过许多强大的功能（如容器扩展、挂载存储系统和服务发现）简化了容器编排的痛苦。

第四章《存储和资源管理》描述了卷管理，并解释了 Kubernetes 中的 CPU 和内存管理。在集群中进行容器存储管理可能很困难。

第五章《网络和安全》解释了如何允许入站连接访问 Kubernetes 服务，以及 Kubernetes 中默认网络的工作原理。对我们的服务进行外部访问对业务需求是必要的。

第六章《监控和日志记录》向您展示如何使用 Prometheus 监视应用程序、容器和节点级别的资源使用情况。本章还展示了如何从您的应用程序以及 Kubernetes 中收集日志，以及如何使用 Elasticsearch、Fluentd 和 Kibana 堆栈。确保服务正常运行和健康是 DevOps 的主要责任之一。

*第七章，持续交付*，解释了如何使用 GitHub/DockerHub/TravisCI 构建持续交付管道。它还解释了如何管理更新，消除滚动更新时可能的影响，并防止可能的失败。持续交付是加快上市时间的一种方法。

*第八章，集群管理*，描述了如何使用 Kubernetes 命名空间和 ResourceQuota 解决前述问题，以及如何在 Kubernetes 中进行访问控制。建立管理边界和对 Kubernetes 集群进行访问控制对 DevOps 至关重要。

*第九章，AWS 上的 Kubernetes*，解释了 AWS 组件，并展示了如何在 AWS 上部署 Kubernetes。AWS 是最受欢迎的公共云。它为我们的世界带来了基础设施的灵活性和敏捷性。

*第十章，GCP 上的 Kubernetes*，帮助您了解 GCP 和 AWS 之间的区别，以及从 Kubernetes 的角度来看在托管服务中运行容器化应用的好处。GCP 中的 Google 容器引擎是 Kubernetes 的托管环境。

*第十一章，接下来是什么？*，介绍了其他类似的技术，如 Docker Swarm 模式、Amazon ECS 和 Apache Mesos，您将了解哪种方法对您的业务最为合适。Kubernetes 是开放的。本章将教您如何与 Kubernetes 社区联系，学习他人的想法。

# 本书所需内容

本书将指导您通过 macOS 和公共云（AWS 和 GCP）使用 Docker 容器和 Kubernetes 进行软件开发和交付的方法论。您需要安装 minikube、AWSCLI 和 Cloud SDK 来运行本书中的代码示例。

# 本书的受众

本书适用于具有一定软件开发经验的 DevOps 专业人士，他们愿意将软件交付规模化、自动化并缩短上市时间。

# 惯例

在本书中，您将找到许多区分不同信息类型的文本样式。以下是一些样式的示例及其含义的解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 用户名显示如下："将下载的`WebStorm-10*.dmg`磁盘映像文件挂载为系统中的另一个磁盘。"

任何命令行输入或输出都是这样写的：

```
$ sudo yum -y -q install nginx
$ sudo /etc/init.d/nginx start
Starting nginx: 
```

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的单词，例如菜单或对话框中的单词，会在文本中出现，就像这样："本书中的快捷键基于 Mac OS X 10.5+方案。"

警告或重要提示会出现在这样的地方。提示和技巧会出现在这样的地方。


# 第一章：DevOps 简介

软件交付周期变得越来越短，而另一方面，应用程序的大小却变得越来越大。软件开发人员和 IT 运营商面临着找到解决方案的压力。有一个新的角色，称为**DevOps**，专门支持软件构建和交付。

本章涵盖以下主题：

+   软件交付方法论如何改变？

+   什么是微服务，为什么人们采用这种架构？

+   DevOps 如何支持构建和交付应用程序给用户？

# 软件交付挑战

构建计算机应用程序并将其交付给客户已经被讨论并随着时间的推移而发展。它与**软件开发生命周期**（**SDLC**）有关；有几种类型的流程、方法论和历史。在本节中，我们将描述其演变。

# 瀑布和物理交付

回到 20 世纪 90 年代，软件交付采用了**物理**方法，如软盘或 CD-ROM。因此，SDLC 是一个非常长期的时间表，因为很难（重新）交付给客户。

那时，一个主要的软件开发方法论是**瀑布模型**，它具有如下图所示的需求/设计/实施/验证/维护阶段：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00005.jpeg)

在这种情况下，我们不能回到以前的阶段。例如，在开始或完成**实施**阶段后，不可接受返回到**设计**阶段（例如查找技术可扩展性问题）。这是因为它会影响整体进度和成本。项目倾向于继续并完成发布，然后进入下一个发布周期，包括新设计。

它完全符合物理软件交付，因为它需要与物流管理协调，压制并交付软盘/CD-ROM 给用户。瀑布模型和物理交付过去需要一年到几年的时间。

# 敏捷和电子交付

几年后，互联网被广泛接受，然后软件交付方法也从物理转变为**电子**，如在线下载。因此，许多软件公司（也被称为点 com 公司）试图找出如何缩短 SDLC 流程，以交付能够击败竞争对手的软件。

许多开发人员开始采用增量、迭代或敏捷模型等新方法，以更快地交付给客户。即使发现新的错误，现在也更容易通过电子交付更新并交付给客户。自 Windows 98 以来，微软 Windows 更新也被引入。

在这种情况下，软件开发人员只编写一个小的逻辑或模块，而不是一次性编写整个应用程序。然后，交付给质量保证，然后开发人员继续添加新模块，最终再次交付给质量保证。

当所需的模块或功能准备就绪时，将按照以下图表释放：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00006.jpeg)

这种模式使得软件开发生命周期和交付变得更快，也更容易在过程中进行调整，因为周期从几周到几个月，足够小以便进行快速调整。

尽管这种模式目前受到大多数人的青睐，但在当时，应用软件交付意味着软件二进制，如可安装并在客户 PC 上运行的 EXE 程序。另一方面，基础设施（如服务器和网络）非常静态并且事先设置。因此，软件开发生命周期并不倾向于将这些基础设施纳入范围之内。

# 云端软件交付

几年后，智能手机（如 iPhone）和无线技术（如 Wi-Fi 和 4G 网络）得到了广泛的接受，软件应用也从二进制转变为在线服务。Web 浏览器是应用软件的界面，不再需要安装。另一方面，基础设施变得动态起来，因为应用需求不断变化，容量也需要增长。

虚拟化技术和软件定义网络（SDN）使服务器机器变得动态。现在，云服务如亚马逊网络服务（AWS）和谷歌云平台（GCP）可以轻松创建和管理动态基础设施。

现在，基础设施是重要组成部分之一，并且在软件开发交付周期的范围内，因为应用程序安装并在服务器端运行，而不是在客户端 PC 上运行。因此，软件和服务交付周期需要花费几天到几周的时间。

# 持续集成

正如之前讨论的，周围的软件交付环境不断变化；然而，交付周期变得越来越短。为了实现更高质量的快速交付，开发人员和质量保证人员开始采用一些自动化技术。其中一种流行的自动化技术是**持续集成**（**CI**）。CI 包含一些工具的组合，如**版本控制系统**（**VCS**）、**构建服务器**和**测试自动化工具**。

VCS 帮助开发人员将程序源代码维护到中央服务器上。它可以防止覆盖或与其他开发人员的代码冲突，同时保留历史记录。因此，它使得源代码保持一致并交付到下一个周期变得更容易。

与 VCS 一样，有一个集中的构建服务器，它连接 VCS 定期检索源代码，或者当开发人员更新代码到 VCS 时自动触发新的构建。如果构建失败，它会及时通知开发人员。因此，当有人将有问题的代码提交到 VCS 时，它有助于开发人员。

测试自动化工具也与构建服务器集成，构建成功后调用单元测试程序，然后将结果通知给开发人员和质量保证人员。它有助于识别当有人编写有错误的代码并存储到 VCS 时。

CI 的整个流程如下图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00007.jpeg)

CI 不仅有助于开发人员和质量保证人员提高质量，还有助于缩短应用程序或模块包的归档周期。在电子交付给客户的时代，CI 已经远远不够了。然而，因为交付给客户意味着部署到服务器。

# 持续交付

CI 加上部署自动化是为服务器应用程序提供服务给客户的理想流程。然而，还有一些技术挑战需要解决。如何将软件交付到服务器？如何优雅地关闭现有应用程序？如何替换和回滚应用程序？如果系统库也需要更改，如何升级或替换？如果需要，如何修改操作系统中的用户和组设置？等等。

由于基础设施包括服务器和网络，一切都取决于诸如 Dev/QA/staging/production 之类的环境。每个环境都有不同的服务器配置和 IP 地址。

**持续交付**（**CD**）是一种可以实现的实践；它是 CI 工具、配置管理工具和编排工具的组合：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00008.jpeg)

# 配置管理

配置管理工具帮助配置操作系统，包括用户、组和系统库，并管理多个服务器，使其与期望的状态或配置保持一致，如果我们替换服务器。

它不是一种脚本语言，因为脚本语言执行基于脚本逐行执行命令。如果我们执行脚本两次，可能会导致一些错误，例如尝试两次创建相同的用户。另一方面，配置管理关注**状态**，所以如果用户已经创建，配置管理工具就不会做任何事情。但是如果我们意外或有意删除用户，配置管理工具将再次创建用户。

它还支持将应用程序部署或安装到服务器。因为如果您告诉配置管理工具下载您的应用程序，然后设置并运行应用程序，它会尝试这样做。

此外，如果您告诉配置管理工具关闭您的应用程序，然后下载并替换为新的软件包（如果有的话），然后重新启动应用程序，它将保持最新版本。

当然，一些用户只希望在需要时更新应用程序，比如蓝绿部署。配置管理工具也允许您手动触发执行。

蓝绿部署是一种技术，它准备了两套应用程序堆栈，然后只有一个环境（例如：蓝色）提供生产服务。然后当您需要部署新版本的应用程序时，部署到另一侧（例如：绿色），然后进行最终测试。然后如果一切正常，更改负载均衡器或路由器设置，将网络流从蓝色切换到绿色。然后绿色成为生产环境，而蓝色变为休眠状态，等待下一个版本的部署。

# 基础设施即代码

配置管理工具不仅支持操作系统或虚拟机，还支持云基础架构。如果您需要在云上创建和配置网络、存储和虚拟机，就需要进行一些云操作。

但是配置管理工具还可以通过配置文件自动设置云基础架构，如下图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00009.jpeg)

配置管理在维护操作手册（SOP）方面具有一些优势。例如，使用 Git 等版本控制系统维护配置文件，可以追踪环境设置的变化历史。

环境也很容易复制。例如，您需要在云上增加一个额外的环境。如果按照传统方法（即阅读 SOP 文档来操作云），总是存在潜在的人为错误和操作错误。另一方面，我们可以执行配置管理工具，快速自动地在云上创建一个环境。

基础设施即代码可能包含在持续交付过程中，因为基础设施的替换或更新成本比仅仅在服务器上替换应用程序二进制文件要高。

# 编排

编排工具也被归类为配置管理工具之一。然而，当配置和分配云资源时，它更加智能和动态。例如，编排工具管理多个服务器资源和网络，然后当管理员想要增加应用程序实例时，编排工具可以确定一个可用的服务器，然后自动部署和配置应用程序和网络。

尽管编排工具超出了 SDLC 的范围，但在需要扩展应用程序和重构基础设施资源时，它有助于持续交付。

总的来说，SDLC 已经通过多种流程、工具和方法演变，以实现快速交付。最终，软件（服务）交付需要花费几个小时到一天的时间。与此同时，软件架构和设计也在不断演进，以实现大型和丰富的应用程序。

# 微服务的趋势

软件架构和设计也在不断演进，基于目标环境和应用程序规模的大小。

# 模块化编程

当应用程序规模变大时，开发人员尝试将其分成几个模块。每个模块应该是独立和可重用的，并且应该由不同的开发团队维护。然后，当我们开始实施一个应用程序时，应用程序只需初始化并使用这些模块来高效地构建一个更大的应用程序。

以下示例显示了 Nginx（[`www.nginx.com`](https://www.nginx.com)）在 CentOS 7 上使用的库。它表明 Nginx 使用了`OpenSSL`、`POSIX 线程`库、`PCRE`正则表达式库、`zlib`压缩库、`GNU C`库等。因此，Nginx 没有重新实现 SSL 加密、正则表达式等：

```
$ /usr/bin/ldd /usr/sbin/nginx
 linux-vdso.so.1 =>  (0x00007ffd96d79000)
 libdl.so.2 => /lib64/libdl.so.2 (0x00007fd96d61c000)
 libpthread.so.0 => /lib64/libpthread.so.0   
  (0x00007fd96d400000)
 libcrypt.so.1 => /lib64/libcrypt.so.1   
  (0x00007fd96d1c8000)
 libpcre.so.1 => /lib64/libpcre.so.1 (0x00007fd96cf67000)
 libssl.so.10 => /lib64/libssl.so.10 (0x00007fd96ccf9000)
 libcrypto.so.10 => /lib64/libcrypto.so.10   
  (0x00007fd96c90e000)
 libz.so.1 => /lib64/libz.so.1 (0x00007fd96c6f8000)
 libprofiler.so.0 => /lib64/libprofiler.so.0 
  (0x00007fd96c4e4000)
 libc.so.6 => /lib64/libc.so.6 (0x00007fd96c122000)
 ...
```

`ldd`命令包含在 CentOS 的`glibc-common`软件包中。

# 软件包管理

Java 语言和一些轻量级编程语言，如 Python、Ruby 和 JavaScript，都有自己的模块或软件包管理工具。例如，Java 使用 Maven（[`maven.apache.org`](http://maven.apache.org)），Python 使用 pip（[`pip.pypa.io`](https://pip.pypa.io)），Ruby 使用 RubyGems（[`rubygems.org`](https://rubygems.org)），JavaScript 使用 npm（[`www.npmjs.com`](https://www.npmjs.com)）。

软件包管理工具允许您将您的模块或软件包注册到集中式或私有存储库，并允许下载必要的软件包。以下截图显示了 AWS SDK 的 Maven 存储库：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00010.jpeg)

当您向应用程序添加特定的依赖项时，Maven 会下载必要的软件包。以下截图是当您向应用程序添加`aws-java-sdk`依赖项时所得到的结果：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00011.jpeg)

模块化编程有助于提高软件开发速度并减少重复劳动，因此现在是开发软件应用程序的最流行方式。

然而，随着我们不断添加功能和逻辑，应用程序需要越来越多的模块、软件包和框架的组合。这使得应用程序变得更加复杂和庞大，特别是服务器端应用程序。这是因为它通常需要连接到诸如关系型数据库（RDBMS）之类的数据库，以及诸如 LDAP 之类的身份验证服务器，然后通过适当的设计以 HTML 形式将结果返回给用户。

因此，开发人员采用了一些软件设计模式，以便在应用程序中开发一堆模块。

# MVC 设计模式

**模型视图控制器**（**MVC**）是一种流行的应用程序设计模式之一。它定义了三层。**视图**层负责**用户界面**（**UI**）**输入输出**（**I/O**）。**模型**层负责数据查询和持久性，比如加载和存储到数据库。然后，**控制器**层负责业务逻辑，处于**视图**和**模型**之间。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00012.jpeg)

有一些框架可以帮助开发人员更轻松地使用 MVC，比如 Struts ([`struts.apache.org/`](https://struts.apache.org/))，SpringMVC ([`projects.spring.io/spring-framework/`](https://projects.spring.io/spring-framework/))，Ruby on Rails ([`rubyonrails.org/`](http://rubyonrails.org/))和 Django ([`www.djangoproject.com/`](https://www.djangoproject.com/))。MVC 是一种成功的软件设计模式，被用作现代 Web 应用程序和服务的基础之一。

MVC 定义了每一层之间的边界线，允许许多开发人员共同开发同一个应用程序。然而，这也会带来副作用。也就是说，应用程序中的源代码大小不断增加。这是因为数据库代码（**模型**）、展示代码（**视图**）和业务逻辑（**控制器**）都在同一个版本控制系统存储库中。最终会对软件开发周期产生影响，使其变得更慢！这被称为**单片式**，其中包含了构建巨大的 exe/war 程序的大量代码。

# 单片式应用程序

单片式应用程序的定义没有明确的衡量标准，但通常具有超过 50 个模块或包，超过 50 个数据库表，然后需要超过 30 分钟的构建时间。当需要添加或修改一个模块时，会影响大量代码，因此开发人员试图最小化应用程序代码的更改。这种犹豫会导致更糟糕的影响，有时甚至会导致应用程序因为没有人愿意再维护代码而死掉。

因此，开发人员开始将单片式应用程序分割成小的应用程序片段，并通过网络连接起来。

# 远程过程调用

实际上，将应用程序分成小块并通过网络连接已经尝试过了，早在 1990 年代。Sun Microsystems 推出了**Sun RPC**（**远程过程调用**）。它允许您远程使用模块。其中一个流行的 Sun RPC 实现者是**网络文件系统**（**NFS**）。因为它们基于 Sun RPC，NFS 客户端和 NFS 服务器之间的 CPU 操作系统版本是独立的。

编程语言本身也支持 RPC 风格的功能。UNIX 和 C 语言都有`rpcgen`工具。它帮助开发人员生成存根代码，负责网络通信代码，因此开发人员可以使用 C 函数风格，免除了困难的网络层编程。

Java 有**Java 远程方法调用**（**RMI**），它类似于 Sun RPC，但对于 Java，**RMI 编译器**（**rmic**）生成连接远程 Java 进程以调用方法并获取结果的存根代码。下图显示了 Java RMI 的过程流程：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00013.jpeg)

Objective C 也有**分布式对象**，.NET 有**远程调用**，因此大多数现代编程语言都具有开箱即用的远程过程调用功能。

这些远程过程调用设计的好处是将应用程序分成多个进程（程序）。各个程序可以有单独的源代码存储库。尽管在 1990 年代和 2000 年代机器资源（CPU、内存）有限，但它仍然运行良好。

然而，它的设计意图是使用相同的编程语言，并且设计为客户端/服务器模型架构，而不是分布式架构。此外，安全性考虑较少；因此，不建议在公共网络上使用。

在 2000 年代，出现了一个名为**web 服务**的倡议，它使用**SOAP**（HTTP/SSL）作为数据传输，使用 XML 作为数据呈现和服务定义的**Web 服务描述语言**（**WSDL**），然后使用**通用描述、发现和集成**（**UDDI**）作为服务注册表来查找 web 服务应用程序。然而，由于机器资源不丰富，以及 Web 服务编程和可维护性的复杂性，它并未被开发人员广泛接受。

# RESTful 设计

进入 2010 年代，现在机器性能甚至智能手机都有大量的 CPU 资源，加上到处都有几百 Mbps 的网络带宽。因此，开发人员开始利用这些资源，使应用程序代码和系统结构尽可能简单，从而加快软件开发周期。

基于硬件资源，使用 HTTP/SSL 作为 RPC 传输是一个自然的决定，但是根据开发人员对 Web 服务困难的经验，开发人员将其简化如下：

+   通过将 HTTP 和 SSL/TLS 作为标准传输

+   通过使用 HTTP 方法进行**创建/加载/上传/删除**（CLUD）操作，例如`GET`/`POST`/`PUT`/`DELETE`

+   通过使用 URI 作为资源标识符，例如：用户 ID 123 作为`/user/123/`

+   通过使用 JSON 作为标准数据呈现

它被称为**RESTful**设计，并且已被许多开发人员广泛接受，成为分布式应用程序的事实标准。RESTful 应用程序允许任何编程语言，因为它基于 HTTP，因此 RESTful 服务器是 Java，客户端 Python 是非常自然的。

它为开发人员带来了自由和机会，易于进行代码重构，升级库甚至切换到另一种编程语言。它还鼓励开发人员通过多个 RESTful 应用构建分布式模块化设计，这被称为微服务。

如果有多个 RESTful 应用程序，就会关注如何在 VCS 上管理多个源代码以及如何部署多个 RESTful 服务器。然而，持续集成和持续交付自动化使构建和部署多个 RESTful 服务器应用程序变得更加容易。

因此，微服务设计对 Web 应用程序开发人员变得越来越受欢迎。

# 微服务

尽管名称是微服务，但与 20 世纪 90 年代或 2000 年代的应用程序相比，它实际上足够复杂。它使用完整的 HTTP/SSL 服务器并包含整个 MVC 层。微服务设计应关注以下主题：

+   **无状态**：这不会将用户会话存储到系统中，这有助于更容易地扩展。

+   **没有共享数据存储**：微服务应该拥有数据存储，比如数据库。它不应该与其他应用程序共享。这有助于封装后端数据库，使单个微服务内的数据库方案易于重构和更新。

+   **版本控制和兼容性**：微服务可能会更改和更新 API，但应定义一个版本，并且应具有向后兼容性。这有助于解耦其他微服务和应用程序之间的关系。

+   **集成 CI/CD**：微服务应采用 CI 和 CD 流程来消除管理工作。

有一些框架可以帮助构建微服务应用程序，比如 Spring Boot ([`projects.spring.io/spring-boot/)`](https://projects.spring.io/spring-boot/))和 Flask ([`flask.pocoo.org)`](http://flask.pocoo.org))。然而，有许多基于 HTTP 的框架，因此开发人员可以随意尝试和选择任何喜欢的框架甚至编程语言。这就是微服务设计的美妙之处。

下图是单块应用程序设计和微服务设计的比较。它表明微服务（也是 MVC）设计与单块设计相同，包含接口层、业务逻辑层、模型层和数据存储。

但不同的是，应用程序（服务）由多个微服务构成，不同的应用程序可以共享相同的微服务。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00014.jpeg)

开发人员可以使用快速软件交付方法添加必要的微服务并修改现有的微服务，而不会再影响现有应用程序（服务）。

这是对整个软件开发环境和方法论的突破，现在得到了许多开发人员的广泛接受。

尽管持续集成和持续交付自动化流程有助于开发和部署多个微服务，但资源数量和复杂性，如虚拟机、操作系统、库和磁盘容量以及网络，无法与单块应用程序相比。

因此，有一些工具和角色可以支持云上的大型自动化环境。

# 自动化和工具

如前所述，自动化是实现快速软件交付的最佳实践，并解决了管理许多微服务的复杂性。然而，自动化工具并不是普通的 IT/基础架构应用程序，比如**Active Directory**，**BIND**（DNS）和**Sendmail**（MTA）。为了实现自动化，需要一名工程师具备开发人员的技能集，能够编写代码，特别是脚本语言，以及基础设施操作员的技能集，比如虚拟机、网络和存储。

DevOps 是*开发*和*运维*的缩合词，可以具有使自动化流程成为可能的能力，例如持续集成、基础设施即代码和持续交付。DevOps 使用一些 DevOps 工具来实现这些自动化流程。

# 持续集成工具

其中一种流行的版本控制工具是 Git（[`git-scm.com`](https://git-scm.com)）。开发人员始终使用 Git 来签入和签出代码。有一些托管 Git 服务：GitHub（[`github.com)`](https://github.com)）和 Bitbucket（[`bitbucket.org`](https://bitbucket.org)）。它允许您创建和保存您的 Git 存储库，并与其他用户协作。以下截图是 GitHub 上的示例拉取请求：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00015.jpeg)

构建服务器有很多变化。Jenkins（[`jenkins.io`](https://jenkins.io)）是一个成熟的应用程序之一，与 TeamCity（[`www.jetbrains.com/teamcity/)`](https://www.jetbrains.com/teamcity/)）相同。除了构建服务器，您还可以使用托管服务，如 Codeship（[`codeship.com)`](https://codeship.com)）和 Travis CI（[`travis-ci.org)`](https://travis-ci.org)）等**软件即服务（SaaS）**。SaaS 具有与其他 SaaS 工具集成的优势。

构建服务器能够调用外部命令，如单元测试程序；因此，构建服务器是 CI 流水线中的关键工具。

以下截图是使用 Codeship 的示例构建；它从 GitHub 检出代码并调用 Maven 进行构建（`mvn compile`）和单元测试（`mvn test`）：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00016.jpeg)

# 持续交付工具

有各种配置管理工具，如 Puppet（[`puppet.com`](https://puppet.com)）、Chef（[`www.chef.io`](https://www.chef.io)）和 Ansible（[`www.ansible.com`](https://www.ansible.com)），它们是最受欢迎的配置管理工具。

AWS OpsWorks（[`aws.amazon.com/opsworks/`](https://aws.amazon.com/opsworks/)）提供了一个托管的 Chef 平台。以下截图是使用 AWS OpsWorks 安装 Amazon CloudWatch 日志代理的 Chef 配方（配置）。它在启动 EC2 实例时自动安装 CloudWatch 日志代理：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00017.jpeg)

AWS CloudFormation ([`aws.amazon.com/cloudformation/)`](https://aws.amazon.com/cloudformation/)) 帮助实现基础架构即代码。它支持 AWS 操作的自动化，例如执行以下功能：

1.  创建一个 VPC。

1.  在 VPC 上创建一个子网。

1.  在 VPC 上创建一个互联网网关。

1.  创建路由表以将子网与互联网网关关联。

1.  创建一个安全组。

1.  创建一个 VM 实例。

1.  将安全组与 VM 实例关联。

CloudFormation 的配置是通过 JSON 编写的，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00018.jpeg)

它支持参数化，因此可以使用具有相同配置的 JSON 文件轻松创建具有不同参数（例如 VPC 和 CIDR）的附加环境。此外，它支持更新操作。因此，如果需要更改基础架构的某个部分，无需重新创建。CloudFormation 可以识别配置的增量并代表您执行必要的基础架构操作。

AWS CodeDeploy ([`aws.amazon.com/codedeploy/)`](https://aws.amazon.com/codedeploy/)) 也是一个有用的自动化工具。但专注于软件部署。它允许用户定义。以下是一些操作到 YAML 文件上：

1.  在哪里下载和安装。

1.  如何停止应用程序。

1.  如何安装应用程序。

1.  安装后，如何启动和配置应用程序。

以下截图是 AWS CodeDeploy 配置文件`appspec.yml`的示例：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00019.jpeg)

# 监控和日志工具

一旦您开始使用云基础架构管理一些微服务，就会有一些监控工具帮助您管理服务器。

**Amazon** **CloudWatch** 是 AWS 上内置的监控工具。不需要安装代理；它会自动从 AWS 实例中收集一些指标并为 DevOps 可视化。它还支持根据您设置的条件设置警报。以下截图是 EC2 实例的 Amazon CloudWatch 指标：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00020.jpeg)

Amazon CloudWatch 还支持收集应用程序日志。它需要在 EC2 实例上安装代理；然而，当您需要开始管理多个微服务实例时，集中式日志管理是有用的。

ELK 是一种流行的组合堆栈，代表 Elasticsearch（[`www.elastic.co/products/elasticsearch`](https://www.elastic.co/products/elasticsearch)）、Logstash（[`www.elastic.co/products/logstash`](https://www.elastic.co/products/logstash)）和 Kibana（[`www.elastic.co/products/kibana`](https://www.elastic.co/products/kibana)）。Logstash 有助于聚合应用程序日志并转换为 JSON 格式，然后发送到 Elasticsearch。

Elasticsearch 是一个分布式 JSON 数据库。Kibana 可以可视化存储在 Elasticsearch 上的数据。以下示例是一个 Kibana，显示了 Nginx 访问日志：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00021.jpeg)

Grafana（[`grafana.com`](https://grafana.com)）是另一个流行的可视化工具。它曾经与时间序列数据库（如 Graphite（[`graphiteapp.org)`](https://graphiteapp.org)）或 InfluxDB（[`www.influxdata.com)`](https://www.influxdata.com)）连接。时间序列数据库旨在存储数据，这些数据是扁平化和非规范化的数字数据，如 CPU 使用率和网络流量。与关系型数据库不同，时间序列数据库对于节省数据空间和更快地查询数字数据历史具有一些优化。大多数 DevOps 监控工具在后端使用时间序列数据库。

以下示例是一个显示**消息队列服务器**统计信息的 Grafana：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00022.jpeg)

# 沟通工具

一旦您开始像我们之前看到的那样使用多个 DevOps 工具，您需要来回访问多个控制台，以检查 CI 和 CD 流水线是否正常工作。例如，请考虑以下几点：

1.  将源代码合并到 GitHub。

1.  在 Jenkins 上触发新构建。

1.  触发 AWS CodeDeploy 部署应用程序的新版本。

这些事件需要按时间顺序跟踪，如果出现问题，DevOps 需要与开发人员和质量保证讨论处理情况。然而，由于 DevOps 需要逐个捕捉事件然后解释，可能通过电子邮件，因此存在一些过度沟通的需求。这并不高效，同时问题仍在继续。

有一些沟通工具可以帮助集成这些 DevOps 工具，任何人都可以加入以查看事件并相互评论。Slack（[`slack.com`](https://slack.com)）和 HipChat（[`www.hipchat.com`](https://www.hipchat.com)）是最流行的沟通工具。

这些工具支持集成到 SaaS 服务，以便 DevOps 可以在单个聊天室中查看事件。以下截图是与 Jenkins 集成的 Slack 聊天室：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00023.jpeg)

# 公共云

当与云技术一起使用时，CI CD 和自动化工作可以很容易实现。特别是公共云 API 帮助 DevOps 提出许多 CI CD 工具。亚马逊云服务（[`aws.amazon.com)`](https://aws.amazon.com)）和谷歌云平台（[`cloud.google.com)`](https://cloud.google.com)）提供一些 API 给 DevOps 来控制云基础设施。DevOps 可以摆脱容量和资源限制，只需在需要资源时按需付费。

公共云将像软件开发周期和架构设计一样不断增长；它们是最好的朋友，也是实现应用/服务成功的重要关键。

以下截图是亚马逊云服务的网页控制台：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00024.jpeg)

谷歌云平台也有一个网页控制台，如下所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00025.jpeg)

这两种云服务都有一个免费试用期，DevOps 工程师可以使用它来尝试和了解云基础设施的好处。

# 总结

在本章中，我们讨论了软件开发方法论的历史，编程演变和 DevOps 工具。这些方法和工具支持更快的软件交付周期。微服务设计也有助于持续的软件更新。然而，微服务使环境管理变得复杂。

下一章将描述 Docker 容器技术，它有助于以更高效和自动化的方式组合微服务应用程序并进行管理。


# 第二章：使用容器的 DevOps

我们已经熟悉了许多 DevOps 工具，这些工具帮助我们自动化任务并在应用程序交付的不同阶段管理配置，但随着应用程序变得更加微小和多样化，仍然存在挑战。在本章中，我们将向我们的工具箱中添加另一把瑞士军刀，即容器。这样做，我们将寻求获得以下技能：

+   容器概念和基础知识

+   运行 Docker 应用程序

+   使用`Dockerfile`构建 Docker 应用程序

+   使用 Docker Compose 编排多个容器

# 理解容器

容器的关键特性是隔离。在本节中，我们将详细阐述容器是如何实现隔离的，以及为什么在软件开发生命周期中这一点很重要，以帮助建立对这个强大工具的正确理解。

# 资源隔离

当应用程序启动时，它会消耗 CPU 时间，占用内存空间，链接到其依赖库，并可能写入磁盘，传输数据包，并访问其他设备。它使用的一切都是资源，并且被同一主机上的所有程序共享。容器的理念是将资源和程序隔离到单独的盒子中。

您可能听说过诸如 para-virtualization、虚拟机（VMs）、BSD jails 和 Solaris 容器等术语，它们也可以隔离主机的资源。然而，由于它们的设计不同，它们在根本上是不同的，但提供了类似的隔离概念。例如，虚拟机的实现是为了使用 hypervisor 对硬件层进行虚拟化。如果您想在虚拟机上运行应用程序，您必须首先安装完整的操作系统。换句话说，在同一 hypervisor 上的客户操作系统之间的资源是隔离的。相比之下，容器是建立在 Linux 原语之上的，这意味着它只能在具有这些功能的操作系统中运行。BSD jails 和 Solaris 容器在其他操作系统上也以类似的方式工作。容器和虚拟机的隔离关系如下图所示。容器在操作系统层隔离应用程序，而基于 VM 的分离是通过操作系统实现的。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00026.jpeg)

# Linux 容器概念

容器由几个构建模块组成，其中最重要的两个是**命名空间**和**控制组**（**cgroups**）。它们都是 Linux 内核的特性。命名空间提供了对某些类型的系统资源的逻辑分区，例如挂载点（`mnt`）、进程 ID（`PID`）、网络（net）等。为了解释隔离的概念，让我们看一些关于 `pid` 命名空间的简单示例。以下示例均来自 Ubuntu 16.04.2 和 util-linux 2.27.1。

当我们输入 `ps axf` 时，会看到一个长长的正在运行的进程列表：

```
$ ps axf
 PID TTY      STAT   TIME COMMAND
    2 ?        S      0:00 [kthreadd]
    3 ?        S      0:42  \_ [ksoftirqd/0]
    5 ?        S<     0:00  \_ [kworker/0:0H]
    7 ?        S      8:14  \_ [rcu_sched]
    8 ?        S      0:00  \_ [rcu_bh]
```

`ps` 是一个报告系统上当前进程的实用程序。`ps axf` 是列出所有进程的命令。

现在让我们使用 `unshare` 进入一个新的 `pid` 命名空间，它能够逐部分将进程资源与新的命名空间分离，并再次检查进程：

```
$ sudo unshare --fork --pid --mount-proc=/proc /bin/sh
$ ps axf
 PID TTY      STAT   TIME COMMAND
    1 pts/0    S      0:00 /bin/sh
    2 pts/0    R+     0:00 ps axf
```

您会发现新命名空间中 shell 进程的 `pid` 变为 `1`，而所有其他进程都消失了。也就是说，您已经创建了一个 `pid` 容器。让我们切换到命名空间外的另一个会话，并再次列出进程：

```
$ ps axf // from another terminal
 PID TTY   COMMAND
  ...
  25744 pts/0 \_ unshare --fork --pid --mount-proc=/proc    
  /bin/sh
 25745 pts/0    \_ /bin/sh
  3305  ?     /sbin/rpcbind -f -w
  6894  ?     /usr/sbin/ntpd -p /var/run/ntpd.pid -g -u  
  113:116
    ...
```

在新的命名空间中，您仍然可以看到其他进程和您的 shell 进程。

通过 `pid` 命名空间隔离，不同命名空间中的进程无法看到彼此。然而，如果一个进程占用了大量系统资源，比如内存，它可能会导致系统内存耗尽并变得不稳定。换句话说，一个被隔离的进程仍然可能干扰其他进程，甚至导致整个系统崩溃，如果我们不对其施加资源使用限制。

以下图表说明了 `PID` 命名空间以及一个**内存不足**（**OOM**）事件如何影响子命名空间外的其他进程。气泡代表系统中的进程，数字代表它们的 PID。子命名空间中的进程有自己的 PID。最初，系统中仍然有可用的空闲内存。后来，子命名空间中的进程耗尽了系统中的所有内存。内核随后启动了 OOM killer 来释放内存，受害者可能是子命名空间外的进程：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00027.jpeg)

鉴于此，`cgroups` 在这里被用来限制资源使用。与命名空间一样，它可以对不同类型的系统资源设置约束。让我们从我们的 `pid` 命名空间继续，用 `yes > /dev/null` 来压力测试 CPU，并用 `top` 进行监控：

```
$ yes > /dev/null & top
$ PID USER  PR  NI    VIRT   RES   SHR S  %CPU %MEM    
TIME+ COMMAND
 3 root  20   0    6012   656   584 R 100.0  0.0  
  0:15.15 yes
 1 root  20   0    4508   708   632 S   0.0  0.0                   
  0:00.00 sh
 4 root  20   0   40388  3664  3204 R   0.0  0.1  
  0:00.00 top
```

我们的 CPU 负载达到了预期的 100%。现在让我们使用 CPU cgroup 来限制它。Cgroups 组织为`/sys/fs/cgroup/`下的目录（首先切换到主机会话）：

```
$ ls /sys/fs/cgroup
blkio        cpuset   memory            perf_event
cpu          devices  net_cls           pids
cpuacct      freezer  net_cls,net_prio  systemd
cpu,cpuacct  hugetlb  net_prio 
```

每个目录代表它们控制的资源。创建一个 cgroup 并控制进程非常容易：只需在资源类型下创建一个任意名称的目录，并将您想要控制的进程 ID 附加到`tasks`中。这里我们想要限制`yes`进程的 CPU 使用率，所以在`cpu`下创建一个新目录，并找出`yes`进程的 PID：

```
$ ps x | grep yes
11809 pts/2    R     12:37 yes

$ mkdir /sys/fs/cgroup/cpu/box && \
 echo 11809 > /sys/fs/cgroup/cpu/box/tasks
```

我们刚刚将`yes`添加到新创建的 CPU 组`box`中，但策略仍未设置，进程仍在没有限制地运行。通过将所需的数字写入相应的文件来设置限制，并再次检查 CPU 使用情况：

```
$ echo 50000 > /sys/fs/cgroup/cpu/box/cpu.cfs_quota_us
$ PID USER  PR  NI    VIRT   RES   SHR S  %CPU %MEM    
 TIME+ COMMAND
    3 root  20   0    6012   656   584 R  50.2  0.0     
    0:32.05 yes
    1 root  20   0    4508  1700  1608 S   0.0  0.0  
    0:00.00 sh
    4 root  20   0   40388  3664  3204 R   0.0  0.1  
    0:00.00 top
```

CPU 使用率显着降低，这意味着我们的 CPU 限制起作用了。

这两个例子阐明了 Linux 容器如何隔离系统资源。通过在应用程序中增加更多的限制，我们绝对可以构建一个完全隔离的盒子，包括文件系统和网络，而无需在其中封装操作系统。

# 容器化交付

为了部署应用程序，通常会使用配置管理工具。它确实可以很好地处理模块化和基于代码的配置设计，直到应用程序堆栈变得复杂和多样化。维护一个庞大的配置清单基础是复杂的。当我们想要更改一个软件包时，我们将不得不处理系统和应用程序软件包之间纠缠不清和脆弱的依赖关系。经常会出现在升级一个无关的软件包后一些应用程序意外中断的情况。此外，升级配置管理工具本身也是一项具有挑战性的任务。

为了克服这样的困境，引入了使用预先烘焙的虚拟机镜像进行不可变部署。也就是说，每当系统或应用程序包有任何更新时，我们将根据更改构建一个完整的虚拟机镜像，并相应地部署它。这解决了一定程度的软件包问题，因为我们现在能够为无法共享相同环境的应用程序定制运行时。然而，使用虚拟机镜像进行不可变部署是昂贵的。从另一个角度来看，为了隔离应用程序而不是资源不足而配置虚拟机会导致资源利用效率低下，更不用说启动、分发和运行臃肿的虚拟机镜像的开销了。如果我们想通过共享虚拟机来消除这种低效，很快就会意识到我们将遇到进一步的麻烦，即资源管理。

容器在这里是一个完美适应部署需求的拼图块。容器的清单可以在版本控制系统中进行管理，并构建成一个 blob 图像；毫无疑问，该图像也可以被不可变地部署。这使开发人员可以抽象出实际资源，基础设施工程师可以摆脱他们的依赖地狱。此外，由于我们只需要打包应用程序本身及其依赖库，其图像大小将明显小于虚拟机的。因此，分发容器图像比虚拟机更经济。此外，我们已经知道，在容器内运行进程基本上与在其 Linux 主机上运行是相同的，因此几乎不会产生额外开销。总之，容器是轻量级的、自包含的和不可变的。这也清晰地划定了应用程序和基础设施之间的责任边界。

# 开始使用容器。

有许多成熟的容器引擎，如 Docker（[`www.docker.com`](https://www.docker.com)）和 rkt（[`coreos.com/rkt`](https://coreos.com/rkt)），它们已经实现了用于生产的功能，因此您无需从头开始构建一个。此外，由容器行业领导者组成的**Open Container Initiative**（[`www.opencontainers.org`](https://www.opencontainers.org)）已经制定了一些容器规范。这些标准的任何实现，无论基础平台如何，都应具有与 OCI 旨在提供的类似属性，以便在各种操作系统上无缝体验容器。在本书中，我们将使用 Docker（社区版）容器引擎来构建我们的容器化应用程序。

# 为 Ubuntu 安装 Docker

Docker 需要 Yakkety 16.10、Xenial 16.04LTS 和 Trusty 14.04LTS 的 64 位版本。您可以使用`apt-get install docker.io`安装 Docker，但它通常更新速度比 Docker 官方存储库慢。以下是来自 Docker 的安装步骤（[`docs.docker.com/engine/installation/linux/docker-ce/ubuntu/#install-docker-ce`](https://docs.docker.com/engine/installation/linux/docker-ce/ubuntu/#install-docker-ce)）：

1.  确保您拥有允许`apt`存储库的软件包；如果没有，请获取它们：

```
$ sudo apt-get install apt-transport-https ca-certificates curl software-properties-common 
```

1.  添加 Docker 的`gpg`密钥并验证其指纹是否匹配`9DC8 5822 9FC7 DD38 854A E2D8 8D81 803C 0EBF CD88`：

```
$ curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
$ sudo apt-key fingerprint 0EBFCD88 
```

1.  设置`amd64`架构的存储库：

```
$ sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" 
```

1.  更新软件包索引并安装 Docker CE：

```
 $ sudo apt-get update 
 $ sudo apt-get install docker-ce
```

# 在 CentOS 上安装 Docker

需要 CentOS 7 64 位才能运行 Docker。同样，您可以通过`sudo yum install docker`从 CentOS 的存储库获取 Docker 软件包。同样，Docker 官方指南（[`docs.docker.com/engine/installation/linux/docker-ce/centos/#install-using-the-repository`](https://docs.docker.com/engine/installation/linux/docker-ce/centos/#install-using-the-repository)）中的安装步骤如下：

1.  安装实用程序以启用`yum`使用额外的存储库：

```
    $ sudo yum install -y yum-utils  
```

1.  设置 Docker 的存储库：

```
$ sudo yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo 
```

1.  更新存储库并验证指纹是否匹配：

`060A 61C5 1B55 8A7F 742B 77AA C52F EB6B 621E 9F35`：

```
    $ sudo yum makecache fast   
```

1.  安装 Docker CE 并启动它：

```
$ sudo yum install docker-ce
$ sudo systemctl start docker 
```

# 为 macOS 安装 Docker

Docker 使用微型 Linux moby 和 Hypervisor 框架来在 macOS 上构建本机应用程序，这意味着我们不需要第三方虚拟化工具来开发 Mac 上的 Docker。要从 Hypervisor 框架中受益，您必须将您的 macOS 升级到 10.10.3 或更高版本。

下载 Docker 软件包并安装它：

[`download.docker.com/mac/stable/Docker.dmg`](https://download.docker.com/mac/stable/Docker.dmg)

同样，Docker for Windows 不需要第三方工具。请查看此处的安装指南：[`docs.docker.com/docker-for-windows/install`](https://docs.docker.com/docker-for-windows/install)

现在您已经进入了 Docker。尝试创建和运行您的第一个 Docker 容器；如果您在 Linux 上，请使用 `sudo` 运行：

```
$ docker run alpine ls
bin dev etc home lib media mnt proc root run sbin srv sys tmp usr var
```

您会发现您处于 `root` 目录下而不是当前目录。让我们再次检查进程列表：

```
$ docker run alpine ps aux
PID   USER     TIME   COMMAND
1 root       0:00 ps aux
```

它是隔离的，正如预期的那样。您已经准备好使用容器了。

Alpine 是一个 Linux 发行版。由于其体积非常小，许多人使用它作为构建应用程序容器的基础图像。

# 容器生命周期

使用容器并不像我们习惯的工具那样直观。在本节中，我们将从最基本的想法开始介绍 Docker 的用法，直到我们能够从容器中受益为止。

# Docker 基础知识

当执行 `docker run alpine ls` 时，Docker 在幕后所做的是：

1.  在本地找到图像 `alpine`。如果找不到，Docker 将尝试从公共 Docker 注册表中找到并将其拉取到本地图像存储中。

1.  提取图像并相应地创建一个容器。

1.  使用命令执行图像中定义的入口点，这些命令是图像名称后面的参数。在本例中，它是 `ls`。在基于 Linux 的 Docker 中，默认的入口点是 `/bin/sh -c`。

1.  当入口点进程退出时，容器也会退出。

图像是一组不可变的代码、库、配置和运行应用程序所需的一切。容器是图像的一个实例，在运行时实际上会被执行。您可以使用 `docker inspect IMAGE` 和 `docker inspect CONTAINER` 命令来查看区别。

有时，当我们需要进入容器检查镜像或在内部更新某些内容时，我们将使用选项`-i`和`-t`（`--interactive`和`--tty`）。此外，选项`-d`（`--detach`）使您可以以分离模式运行容器。如果您想与分离的容器进行交互，`exec`和`attach`命令可以帮助我们。`exec`命令允许我们在运行的容器中运行进程，而`attach`按照其字面意思工作。以下示例演示了如何使用它们：

```
$ docker run alpine /bin/sh -c "while :;do echo  
  'meow~';sleep 1;done"
meow~
meow~
...
```

您的终端现在应该被“喵喵喵”淹没了。切换到另一个终端并运行`docker ps`命令，以获取容器的状态，找出喵喵叫的容器的名称和 ID。这里的名称和 ID 都是由 Docker 生成的，您可以使用其中任何一个访问容器。为了方便起见，名称可以在`create`或`run`时使用`--name`标志进行分配：

```
$ docker ps
CONTAINER ID    IMAGE    (omitted)     NAMES
d51972e5fc8c    alpine      ...        zen_kalam

$ docker exec -it d51972e5fc8c /bin/sh
/ # ps
PID   USER     TIME   COMMAND
  1 root       0:00 /bin/sh -c while :;do echo  
  'meow~';sleep 1;done
  27 root       0:00 /bin/sh
  34 root       0:00 sleep 1
  35 root       0:00 ps
  / # kill -s 2 1
  $ // container terminated
```

一旦我们进入容器并检查其进程，我们会看到两个 shell：一个是喵喵叫，另一个是我们所在的位置。在容器内部使用`kill -s 2 1`杀死它，我们会看到整个容器停止，因为入口点已经退出。最后，让我们使用`docker ps -a`列出已停止的容器，并使用`docker rm CONTAINER_NAME`或`docker rm CONTAINER_ID`清理它们。自 Docker 1.13 以来，引入了`docker system prune`命令，它可以帮助我们轻松清理已停止的容器和占用的资源。

# 层、镜像、容器和卷

我们知道镜像是不可变的；容器是短暂的，我们知道如何将镜像作为容器运行。然而，在打包镜像时仍然缺少一步。

镜像是一个只读的堆栈，由一个或多个层组成，而层是文件系统中的文件和目录的集合。为了改善磁盘使用情况，层不仅被锁定在一个镜像上，而且在镜像之间共享；这意味着 Docker 只在本地存储基础镜像的一个副本，而不管从它派生了多少镜像。您可以使用`docker history [image]`命令来了解镜像是如何构建的。例如，如果您键入`docker history alpine`，则 Alpine Linux 镜像中只有一个层。

每当创建一个容器时，它会在基础镜像的顶部添加一个可写层。Docker 在该层上采用了**写时复制**（**COW**）策略。也就是说，容器读取存储目标文件的基础镜像的层，并且如果文件被修改，就会将文件复制到自己的可写层。这种方法可以防止从相同镜像创建的容器相互干扰。`docker diff [CONTAINER]` 命令显示容器与其基础镜像在文件系统状态方面的差异。例如，如果基础镜像中的 `/etc/hosts` 被修改，Docker 会将文件复制到可写层，并且在 `docker diff` 的输出中也只会有这一个文件。

以下图示了 Docker 镜像的层次结构：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00028.jpeg)

需要注意的是，可写层中的数据会随着容器的删除而被删除。为了持久化数据，您可以使用 `docker commit [CONTAINER]` 命令将容器层提交为新镜像，或者将数据卷挂载到容器中。

数据卷允许容器的读写绕过 Docker 的文件系统，它可以位于主机的目录或其他存储中，比如 Ceph 或 GlusterFS。因此，对卷的磁盘 I/O 可以根据底层存储的实际速度进行操作。由于数据在容器外是持久的，因此可以被多个容器重复使用和共享。通过在 `docker run` 或 `docker create` 中指定 `-v`（`--volume`）标志来挂载卷。以下示例在容器中挂载了一个卷到 `/chest`，并在其中留下一个文件。然后，我们使用 `docker inspect` 来定位数据卷：

```
$ docker run --name demo -v /chest alpine touch /chest/coins
$ docker inspect demo
...
"Mounts": [
 {
    "Type": "volume",
     "Name":(hash-digits),
     "Source":"/var/lib/docker/volumes/(hash- 
      digits)/_data",
      "Destination": "/chest",
      "Driver": "local",
      "Mode": "",
       ...
$ ls /var/lib/docker/volumes/(hash-digits)/_data
      coins
```

Docker CE 在 macOS 上提供的 moby Linux 的默认 `tty` 路径位于：

`~/Library/Containers/com.docker.docker/Data/com.docker.driver.amd64-linux/tty`.

您可以使用 `screen` 连接到它。

数据卷的一个用例是在容器之间共享数据。为此，我们首先创建一个容器并在其上挂载卷，然后挂载一个或多个容器，并使用 `--volumes-from` 标志引用卷。以下示例创建了一个带有数据卷 `/share-vol` 的容器。容器 A 可以向其中放入一个文件，容器 B 也可以读取它：

```
$ docker create --name box -v /share-vol alpine nop
c53e3e498ab05b19a12d554fad4545310e6de6950240cf7a28f42780f382c649
$ docker run --name A --volumes-from box alpine touch /share-vol/wine
$ docker run --name B --volumes-from box alpine ls /share-vol
wine
```

此外，数据卷可以挂载在给定的主机路径下，当然其中的数据是持久的：

```
$ docker run --name hi -v $(pwd)/host/dir:/data alpine touch /data/hi
$ docker rm hi
$ ls $(pwd)/host/dir
hi
```

# 分发镜像

注册表是一个存储、管理和分发图像的服务。公共服务，如 Docker Hub ([`hub.docker.com`](https://hub.docker.com)) 和 Quay ([`quay.io`](https://quay.io))，汇集了各种流行工具的预构建图像，如 Ubuntu 和 Nginx，以及其他开发人员的自定义图像。我们多次使用的 Alpine Linux 实际上是从 Docker Hub ([`hub.docker.com/_/alpine`](https://hub.docker.com/_/alpine))中拉取的。当然，你也可以将你的工具上传到这样的服务并与所有人分享。

如果你需要一个私有注册表，但出于某种原因不想订阅注册表服务提供商的付费计划，你总是可以使用 registry ([`hub.docker.com/_/registry`](https://hub.docker.com/_/registry))在自己的计算机上设置一个。

在配置容器之前，Docker 将尝试在图像名称中指示的规则中定位指定的图像。图像名称由三个部分`[registry/]name[:tag]`组成，并根据以下规则解析：

+   如果省略了`registry`字段，则在 Docker Hub 上搜索该名称

+   如果`registry`字段是注册表服务器，则在其中搜索该名称

+   名称中可以有多个斜杠

+   如果省略了标记，则默认为`latest`

例如，图像名称`gcr.io/google-containers/guestbook:v3`指示 Docker 从`gcr.io`下载`google-containers/guestbook`的`v3`版本。同样，如果你想将图像推送到注册表，也要以相同的方式标记你的图像并推送它。要列出当前在本地磁盘上拥有的图像，使用`docker images`，并使用`docker rmi [IMAGE]`删除图像。以下示例显示了如何在不同的注册表之间工作：从 Docker Hub 下载`nginx`图像，将其标记为私有注册表路径，并相应地推送它。请注意，尽管默认标记是`latest`，但你必须显式地标记和推送它。

```
$ docker pull nginx
Using default tag: latest
latest: Pulling from library/nginx
ff3d52d8f55f: Pull complete
...
Status: Downloaded newer image for nginx:latest

$ docker tag nginx localhost:5000/comps/prod/nginx:1.14
$ docker push localhost:5000/comps/prod/nginx:1.14
The push refers to a repository [localhost:5000/comps/prod/nginx]
...
8781ec54ba04: Pushed
1.14: digest: sha256:(64-digits-hash) size: 948
$ docker tag nginx localhost:5000/comps/prod/nginx
$ docker push localhost:5000/comps/prod/nginx
The push refers to a repository [localhost:5000/comps/prod/nginx]
...
8781ec54ba04: Layer already exists
latest: digest: sha256:(64-digits-hash) size: 948
```

大多数注册表服务在你要推送图像时都会要求进行身份验证。`docker login`就是为此目的而设计的。有时，当尝试拉取图像时，你可能会收到`image not found error`的错误，即使图像路径是有效的。这很可能是你未经授权访问保存图像的注册表。要解决这个问题，首先要登录：

```
$ docker pull localhost:5000/comps/prod/nginx
Pulling repository localhost:5000/comps/prod/nginx
Error: image comps/prod/nginx:latest not found
$ docker login -u letme -p in localhost:5000
Login Succeeded
$ docker pull localhost:5000/comps/prod/nginx
Pulling repository localhost:5000/comps/prod/nginx
...
latest: digest: sha256:(64-digits-hash) size: 948
```

除了通过注册表服务分发图像外，还有将图像转储为 TAR 存档文件，并将其导入到本地存储库的选项：

+   `docker commit [CONTAINER]`：将容器层的更改提交为新镜像

+   `docker save --output [filename] IMAGE1 IMAGE2 ...`：将一个或多个镜像保存到 TAR 存档中

+   `docker load -i [filename]`：将`tarball`镜像加载到本地存储库

+   `docker export --output [filename] [CONTAINER]`：将容器的文件系统导出为 TAR 存档

+   `docker import --output [filename] IMAGE1 IMAGE2`：导入文件系统`tarball`

`commit`命令与`save`和`export`看起来基本相同。主要区别在于保存的镜像即使最终将被删除，也会保留层之间的文件；另一方面，导出的镜像将所有中间层压缩为一个最终层。另一个区别是保存的镜像保留元数据，例如层历史记录，但这些在导出的镜像中不可用。因此，导出的镜像通常体积较小。

以下图表描述了容器和镜像之间状态的关系。箭头上的标题是 Docker 的相应子命令：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00029.jpeg)

# 连接容器

Docker 提供了三种网络类型来管理容器内部和主机之间的通信，即`bridge`、`host`和`none`。

```
$ docker network ls
NETWORK ID          NAME                DRIVER              SCOPE
1224183f2080        bridge              bridge              local
801dec6d5e30        host                host                local
f938cd2d644d        none                null                local
```

默认情况下，每个容器在创建时都连接到桥接网络。在这种模式下，每个容器都被分配一个虚拟接口和一个私有 IP 地址，通过该接口传输的流量被桥接到主机的`docker0`接口。此外，同一桥接网络中的其他容器可以通过它们的 IP 地址相互连接。让我们运行一个通过端口`5000`发送短消息的容器，并观察其配置。`--expose`标志将给定端口开放给容器外部的世界：

```
$ docker run --name greeter -d --expose 5000 alpine \
/bin/sh -c "echo Welcome stranger! | nc -lp 5000"
2069cbdf37210461bc42c2c40d96e56bd99e075c7fb92326af1ec47e64d6b344 $ docker exec greeter ifconfig
eth0      Link encap:Ethernet  HWaddr 02:42:AC:11:00:02
inet addr:172.17.0.2  Bcast:0.0.0.0  Mask:255.255.0.0
...
```

在这里，容器`greeter`被分配了 IP`172.17.0.2`。现在运行另一个连接到该 IP 地址的容器：

```
$ docker run alpine telnet 172.17.0.2 5000
Welcome stranger!
Connection closed by foreign host
```

`docker network inspect bridge`命令提供配置详细信息，例如子网段和网关信息。

此外，您可以将一些容器分组到一个用户定义的桥接网络中。这也是连接单个主机上多个容器的推荐方式。用户定义的桥接网络与默认的桥接网络略有不同，主要区别在于您可以通过名称而不是 IP 地址访问其他容器。创建网络是通过`docker network create [NW-NAME]`完成的，将容器附加到它是通过创建时的标志`--network [NW-NAME]`完成的。容器的网络名称默认为其名称，但也可以使用`--network-alias`标志给它另一个别名：

```
$ docker network create room
b0cdd64d375b203b24b5142da41701ad9ab168b53ad6559e6705d6f82564baea
$ docker run -d --network room \
--network-alias dad --name sleeper alpine sleep 60
b5290bcca85b830935a1d0252ca1bf05d03438ddd226751eea922c72aba66417
$ docker run --network room alpine ping -c 1 sleeper
PING sleeper (172.18.0.2): 56 data bytes
...
$ docker run --network room alpine ping -c 1 dad
PING dad (172.18.0.2): 56 data bytes
...
```

主机网络按照其名称的字面意思工作；每个连接的容器共享主机的网络，但同时失去了隔离属性。none 网络是一个完全分离的盒子。无论是入口还是出口，流量都在内部隔离，因为容器上没有网络接口。在这里，我们将一个监听端口`5000`的容器连接到主机网络，并在本地与其通信：

```
$ docker run -d --expose 5000 --network host alpine \
/bin/sh -c "echo im a container | nc -lp 5000"
ca73774caba1401b91b4b1ca04d7d5363b6c281a05a32828e293b84795d85b54
$ telnet localhost 5000
im a container
Connection closed by foreign host
```

如果您在 macOS 上使用 Docker CE，主机指的是 hypervisor 框架上的 moby Linux。

主机和三种网络模式之间的交互如下图所示。主机和桥接网络中的容器都连接了适当的网络接口，并与相同网络内的容器以及外部世界进行通信，但 none 网络与主机接口保持分离。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00030.jpeg)

除了共享主机网络外，在创建容器时，标志`-p(--publish) [host]:[container]`还允许您将主机端口映射到容器。这个标志意味着`-expose`，因为您无论如何都需要打开容器的端口。以下命令在端口`80`启动一个简单的 HTTP 服务器。您也可以用浏览器查看它。

```
$ docker run -p 80:5000 alpine /bin/sh -c \
"while :; do echo -e 'HTTP/1.1 200 OK\n\ngood day'|nc -lp 5000; done"

$ curl localhost
good day
```

# 使用 Dockerfile

在组装镜像时，无论是通过 Docker commit 还是 export，以受控的方式优化结果都是一个挑战，更不用说与 CI/CD 管道集成了。另一方面，`Dockerfile` 以代码的形式表示构建任务，这显著减少了我们构建任务的复杂性。在本节中，我们将描述如何将 Docker 命令映射到 `Dockerfile` 中，并进一步对其进行优化。

# 编写您的第一个 Dockerfile

`Dockerfile`由一系列文本指令组成，指导 Docker 守护程序形成一个 Docker 镜像。通常，`Dockerfile`是以指令`FROM`开头的，后面跟着零个或多个指令。例如，我们可以从以下一行指令构建一个镜像：

```
docker commit $(   \
docker start $(  \
docker create alpine /bin/sh -c    \
"echo My custom build > /etc/motd" \
 ))
```

它大致相当于以下`Dockerfile`：

```
./Dockerfile:
---
FROM alpine
RUN echo "My custom build" > /etc/motd
---
```

显然，使用`Dockerfile`构建更加简洁和清晰。

`docker build [OPTIONS] [CONTEXT]`命令是与构建任务相关的唯一命令。上下文可以是本地路径、URL 或`stdin`；表示`Dockerfile`的位置。一旦触发构建，`Dockerfile`以及上下文中的所有内容将首先被发送到 Docker 守护程序，然后守护程序将开始按顺序执行`Dockerfile`中的指令。每次执行指令都会产生一个新的缓存层，随后的指令会在级联中的新缓存层上执行。由于上下文将被发送到不一定是本地路径的地方，将`Dockerfile`、代码、必要的文件和`.dockerignore`文件放在一个空文件夹中是一个良好的做法，以确保生成的镜像仅包含所需的文件。

`.dockerignore`文件是一个列表，指示在构建时可以忽略同一目录下的哪些文件，它通常看起来像下面的文件：

```
./.dockerignore:
---
# ignore .dockerignore, .git
.dockerignore 
.git
# exclude all *.tmp files and vim swp file recursively
/*.tmp
/[._]*.s[a-w][a-z]
...
---
```

通常，`docker build`将尝试在`context`下找到一个名为`Dockerfile`的文件来开始构建；但有时出于某些原因，我们可能希望给它另一个名称。`-f`（`--file`）标志就是为了这个目的。另外，另一个有用的标志`-t`（`--tag`）在构建完镜像后能够给一个或多个仓库标签。假设我们想要在`./deploy`下构建一个名为`builder.dck`的`Dockerfile`，并用当前日期和最新标签标记它，命令将是：

```
$ docker build -f deploy/builder.dck  \
-t my-reg.com/prod/teabreak:$(date +"%g%m%d") \
-t my-reg.com/prod/teabreak:latest .
```

# Dockerfile 语法

`Dockerfile`的构建块是十几个或更多的指令；其中大多数是`docker run/create`标志的对应物。这里我们列出最基本的几个：

+   `FROM <IMAGE>[:TAG|[@DIGEST]`：这是告诉 Docker 守护程序当前`Dockerfile`基于哪个镜像。这也是唯一必须在`Dockerfile`中的指令，这意味着你可以有一个只包含一行的`Dockerfile`。像所有其他与镜像相关的命令一样，如果未指定标签，则默认为最新的。

+   `RUN`：

```
RUN <commands>
RUN ["executable", "params", "more params"]
```

`RUN`指令在当前缓存层运行一行命令，并提交结果。两种形式之间的主要差异在于命令的执行方式。第一种称为**shell 形式**，实际上以`/bin/sh -c <commands>`的形式执行命令；另一种形式称为**exec 形式**，它直接使用`exec`处理命令。

使用 shell 形式类似于编写 shell 脚本，因此通过 shell 运算符和行继续、条件测试或变量替换来连接多个命令是完全有效的。但请记住，命令不是由`bash`而是由`sh`处理。

exec 形式被解析为 JSON 数组，这意味着您必须用双引号包装文本并转义保留字符。此外，由于命令不会由任何 shell 处理，数组中的 shell 变量将不会被评估。另一方面，如果基本图像中不存在 shell，则仍然可以使用 exec 形式来调用可执行文件。

+   `CMD`：

```
CMD ["executable", "params", "more params"]
CMD ["param1","param2"]
CMD command param1 param2 ...:
```

`CMD`设置了构建图像的默认命令；它不会在构建时运行命令。如果在 Docker run 时提供了参数，则这里的`CMD`配置将被覆盖。`CMD`的语法规则几乎与`RUN`相同；第一种形式是 exec 形式，第三种形式是 shell 形式，也就是在前面加上`/bin/sh -c`。`ENTRYPOINT`与`CMD`交互的另一个指令；实际上，三种`CMD`形式在容器启动时都会被`ENTRYPOINT`所覆盖。在`Dockerfile`中可以有多个`CMD`指令，但只有最后一个会生效。

+   `ENTRYPOINT`：

```
ENTRYPOINT ["executable", "param1", "param2"] ENTRYPOINT command param1 param2
```

这两种形式分别是执行形式和 shell 形式，语法规则与`RUN`相同。入口点是图像的默认可执行文件。也就是说，当容器启动时，它会运行由`ENTRYPOINT`配置的可执行文件。当`ENTRYPOINT`与`CMD`和`docker run`参数结合使用时，以不同形式编写会导致非常不同的行为。以下是它们组合的规则：

+   +   如果`ENTRYPOINT`是 shell 形式，则`CMD`和 Docker `run`参数将被忽略。命令将变成：

```
     /bin/sh -c entry_cmd entry_params ...     
```

+   +   如果`ENTRYPOINT`是 exec 形式，并且指定了 Docker `run`参数，则`CMD`命令将被覆盖。运行时命令将是：

```
      entry_cmd entry_params run_arguments
```

+   +   如果`ENTRYPOINT`以执行形式存在，并且只配置了`CMD`，则三种形式的运行时命令将变为以下形式：

```
  entry_cmd entry_parms CMD_exec CMD_parms
  entry_cmd entry_parms CMD_parms
  entry_cmd entry_parms /bin/sh -c CMD_cmd 
  CMD_parms   
```

+   `ENV`：

```
ENV key value
ENV key1=value1 key2=value2 ... 
```

`ENV`指令为随后的指令和构建的镜像设置环境变量。第一种形式将键设置为第一个空格后面的字符串，包括特殊字符。第二种形式允许我们在一行中设置多个变量，用空格分隔。如果值中有空格，可以用双引号括起来或转义空格字符。此外，使用`ENV`定义的键也会影响同一文档中的变量。查看以下示例以观察`ENV`的行为：

```
    FROM alpine
    ENV key wD # aw
    ENV k2=v2 k3=v\ 3 \
        k4="v 4"
    ENV k_${k2}=$k3 k5=\"K\=da\"

    RUN echo key=$key ;\
       echo k2=$k2 k3=$k3 k4=$k4 ;\
       echo k_\${k2}=k_${k2}=$k3 k5=$k5

```

在 Docker 构建期间的输出将是：

```
    ...
    ---> Running in 738709ef01ad
    key=wD # aw
    k2=v2 k3=v 3 k4=v 4
    k_${k2}=k_v2=v 3 k5="K=da"
    ...
```

+   `LABEL key1=value1 key2=value2 ...`：`LABEL`的用法类似于`ENV`，但标签仅存储在镜像的元数据部分，并由其他主机程序使用，而不是容器中的程序。它取代了以下形式的`maintainer`指令：

```
LABEL maintainer=johndoe@example.com
```

如果命令带有`-f(--filter)`标志，则可以使用标签过滤对象。例如，`docker images --filter label=maintainer=johndoe@example.com`会查询出带有前面维护者标签的镜像。

+   `EXPOSE <port> [<port> ...]`：此指令与`docker run/create`中的`--expose`标志相同，会在由生成的镜像创建的容器中暴露端口。

+   `USER <name|uid>[:<group|gid>]`：`USER`指令切换用户以运行随后的指令。但是，如果用户在镜像中不存在，则无法正常工作。否则，在使用`USER`指令之前，您必须运行`adduser`。

+   `WORKDIR <path>`：此指令将工作目录设置为特定路径。如果路径不存在，路径将被自动创建。它的工作原理类似于`Dockerfile`中的`cd`，因为它既可以接受相对路径也可以接受绝对路径，并且可以多次使用。如果绝对路径后面跟着一个相对路径，结果将相对于前一个路径：

```
    WORKDIR /usr
    WORKDIR src
    WORKDIR app
    RUN pwd
    ---> Running in 73aff3ae46ac
    /usr/src/app
    ---> 4a415e366388

```

此外，使用`ENV`设置的环境变量会影响路径。

+   `COPY：`

```
COPY <src-in-context> ... <dest-in-container> COPY ["<src-in-context>",... "<dest-in-container>"]
```

该指令将源复制到构建容器中的文件或目录。源可以是文件或目录，目的地也可以是文件或目录。源必须在上下文路径内，因为只有上下文路径下的文件才会被发送到 Docker 守护程序。此外，`COPY`利用`.dockerignore`来过滤将被复制到构建容器中的文件。第二种形式适用于路径包含空格的情况。

+   `ADD`：

```
ADD <src > ... <dest >
ADD ["<src>",... "<dest >"]
```

`ADD`在功能上与`COPY`非常类似：将文件移动到镜像中。除了复制文件外，`<src>`也可以是 URL 或压缩文件。如果`<src>`是一个 URL，`ADD`将下载并将其复制到镜像中。如果`<src>`被推断为压缩文件，它将被提取到`<dest>`路径中。

+   `VOLUME`：

```
VOLUME mount_point_1 mount_point_2 VOLUME ["mount point 1", "mount point 2"]
```

`VOLUME`指令在给定的挂载点创建数据卷。一旦在构建时声明了数据卷，后续指令对数据卷的任何更改都不会持久保存。此外，在`Dockerfile`或`docker build`中挂载主机目录是不可行的，因为存在可移植性问题：无法保证指定的路径在主机中存在。两种语法形式的效果是相同的；它们只在语法解析上有所不同；第二种形式是 JSON 数组，因此需要转义字符，如`"\"`。

+   `ONBUILD [其他指令]`：`ONBUILD`允许您将一些指令推迟到派生图像的后续构建中。例如，我们可能有以下两个 Dockerfiles：

```
    --- baseimg ---
    FROM alpine
    RUN apk add --no-update git make
    WORKDIR /usr/src/app
    ONBUILD COPY . /usr/src/app/
    ONBUILD RUN git submodule init && \
              git submodule update && \
              make
    --- appimg ---
    FROM baseimg
    EXPOSE 80
    CMD ["/usr/src/app/entry"]
```

然后，指令将按以下顺序在`docker build`中进行评估：

```
    $ docker build -t baseimg -f baseimg .
    ---
    FROM alpine
    RUN apk add --no-update git make
    WORKDIR /usr/src/app
    ---
    $ docker build -t appimg -f appimg .
    ---
    COPY . /usr/src/app/
    RUN git submodule init   && \
        git submodule update && \
        make
    EXPOSE 80
    CMD ["/usr/src/app/entry"] 
```

# 组织 Dockerfile

即使编写`Dockerfile`与编写构建脚本相同，但我们还应考虑一些因素来构建高效、安全和稳定的镜像。此外，`Dockerfile`本身也是一个文档，保持其可读性可以简化管理工作。

假设我们有一个应用程序堆栈，其中包括应用程序代码、数据库和缓存，我们可能会从一个`Dockerfile`开始，例如以下内容：

```
---
FROM ubuntu
ADD . /app
RUN apt-get update 
RUN apt-get upgrade -y
RUN apt-get install -y redis-server python python-pip mysql-server
ADD db/my.cnf /etc/mysql/my.cnf
ADD db/redis.conf /etc/redis/redis.conf
RUN pip install -r /app/requirements.txt
RUN cd /app ; python setup.py
CMD /app/start-all-service.sh
```

第一个建议是创建一个专门用于一件事情的容器。因此，我们将在这个`Dockerfile`的开头删除`mysql`和`redis`的安装和配置。接下来，代码将被移入容器中，使用`ADD`，这意味着我们很可能将整个代码库移入容器。通常有许多与应用程序直接相关的文件，包括 VCS 文件、CI 服务器配置，甚至构建缓存，我们可能不希望将它们打包到镜像中。因此，建议使用`.dockerignore`来过滤掉这些文件。顺便说一句，由于`ADD`指令，我们可以做的不仅仅是将文件添加到构建容器中。通常情况下，使用`COPY`更为合适，除非确实有不这样做的真正需要。现在我们的`Dockerfile`更简单了，如下面的代码所示：

```
FROM ubuntu
COPY . /app
RUN apt-get update 
RUN apt-get upgrade -y
RUN apt-get install -y python python-pip
RUN pip install -r /app/requirements.txt
RUN cd /app ; python setup.py
CMD python app.py
```

在构建镜像时，Docker 引擎将尽可能地重用缓存层，这显著减少了构建时间。在我们的`Dockerfile`中，只要存储库有任何更新，我们就必须经历整个更新和依赖项安装过程。为了从构建缓存中受益，我们将根据一个经验法则重新排序指令：首先运行不太频繁的指令。

另外，正如我们之前所描述的，对容器文件系统的任何更改都会导致新的镜像层。即使我们在随后的层中删除了某些文件，这些文件仍然占用着镜像大小，因为它们仍然保存在中间层。因此，我们的下一步是通过简单地压缩多个`RUN`指令来最小化镜像层。此外，为了保持`Dockerfile`的可读性，我们倾向于使用行继续字符“`\`”格式化压缩的`RUN`。

除了与 Docker 的构建机制一起工作之外，我们还希望编写一个可维护的`Dockerfile`，使其更清晰、可预测和稳定。以下是一些建议：

+   使用`WORKDIR`而不是内联`cd`，并为`WORKDIR`使用绝对路径。

+   明确公开所需的端口

+   为基础镜像指定标签

+   使用执行形式启动应用程序

前三个建议非常直接，旨在消除歧义。最后一个建议是关于应用程序如何终止。当来自 Docker 守护程序的停止请求发送到正在运行的容器时，主进程（PID 1）将接收到一个停止信号（`SIGTERM`）。如果进程在一定时间后仍未停止，Docker 守护程序将发送另一个信号（`SIGKILL`）来终止容器。在这里，exec 形式和 shell 形式有所不同。在 shell 形式中，PID 1 进程是"`/bin/sh -c`"，而不是应用程序。此外，不同的 shell 处理信号的方式也不同。有些将停止信号转发给子进程，而有些则不会。Alpine Linux 的 shell 不会转发它们。因此，为了正确停止和清理我们的应用程序，建议使用`exec`形式。结合这些原则，我们有以下`Dockerfile`：

```
FROM ubuntu:16.04
RUN apt-get update && apt-get upgrade -y  \
&& apt-get install -y python python-pip
ENTRYPOINT ["python"]
CMD ["entry.py"]
EXPOSE 5000
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . /app 
```

还有其他一些实践可以使`Dockerfile`更好，包括从专用和更小的基础镜像开始，例如基于 Alpine 的镜像，而不是通用目的的发行版，使用除`root`之外的用户以提高安全性，并在`RUN`中删除不必要的文件。

# 多容器编排

随着我们将越来越多的应用程序打包到隔离的容器中，我们很快就会意识到我们需要一种工具，能够帮助我们同时处理多个容器。在这一部分，我们将从仅仅启动单个容器上升一步，开始编排一组容器。

# 堆叠容器

现代系统通常构建为由多个组件组成的堆栈，这些组件分布在网络上，如应用服务器、缓存、数据库、消息队列等。同时，一个组件本身也是一个包含许多子组件的自包含系统。此外，微服务的趋势为系统之间纠缠不清的关系引入了额外的复杂性。由于这个事实，即使容器技术在部署任务方面给了我们一定程度的缓解，启动一个系统仍然很困难。

假设我们有一个名为 kiosk 的简单应用程序，它连接到 Redis 来管理我们当前拥有的门票数量。一旦门票售出，它会通过 Redis 频道发布一个事件。记录器订阅了 Redis 频道，并在接收到任何事件时将时间戳日志写入 MySQL 数据库。

对于**kiosk**和**recorder**，你可以在这里找到代码以及 Dockerfiles：[`github.com/DevOps-with-Kubernetes/examples/tree/master/chapter2`](https://github.com/DevOps-with-Kubernetes/examples/tree/master/chapter2)。架构如下：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00031.jpeg)

我们知道如何分别启动这些容器，并将它们连接在一起。基于我们之前讨论的内容，我们首先会创建一个桥接网络，并在其中运行容器：

```

$ docker network create kiosk
$ docker run -d -p 5000:5000 \
    -e REDIS_HOST=lcredis --network=kiosk kiosk-example 
$ docker run -d --network-alias lcredis --network=kiosk redis
$ docker run -d -e REDIS_HOST=lcredis -e MYSQL_HOST=lmysql \
-e MYSQL_ROOT_PASSWORD=$MYPS -e MYSQL_USER=root \
--network=kiosk recorder-example
$ docker run -d --network-alias lmysql -e MYSQL_ROOT_PASSWORD=$MYPS \ 
 --network=kiosk mysql:5.7 
```

到目前为止一切都运行良好。然而，如果下次我们想再次启动相同的堆栈，我们的应用很可能会在数据库之前启动，并且如果有任何传入连接请求对数据库进行任何更改，它们可能会失败。换句话说，我们必须在启动脚本中考虑启动顺序。此外，脚本还存在一些问题，比如如何处理随机组件崩溃，如何管理变量，如何扩展某些组件等等。

# Docker Compose 概述

Docker Compose 是一个非常方便地运行多个容器的工具，它是 Docker CE 发行版中的内置工具。它的作用就是读取`docker-compose.yml`（或`.yaml`）来运行定义的容器。`docker-compose`文件是基于 YAML 的模板，通常是这样的：

```
version: '3'
services:
 hello-world:
 image: hello-world
```

启动它非常简单：将模板保存为`docker-compose.yml`，然后使用`docker-compose up`命令启动它。

```
$ docker-compose up
Creating network "cwd_default" with the default driver
Creating cwd_hello-world_1
Attaching to cwd_hello-world_1
hello-world_1  |
hello-world_1  | Hello from Docker!
hello-world_1  | This message shows that your installation appears to be working correctly.
...
cwd_hello-world_1 exited with code 0

```

让我们看看`docker-compose`在`up`命令后面做了什么。

Docker Compose 基本上是 Docker 的多个容器功能的混合体。例如，`docker build`的对应命令是`docker-compose build`；前者构建一个 Docker 镜像，后者构建`docker-compose.yml`中列出的 Docker 镜像。但需要指出的是：`docker-compose run`命令并不是`docker run`的对应命令；它是从`docker-compose.yml`中的配置中运行特定容器。实际上，与`docker run`最接近的命令是`docker-compose up`。

`docker-compose.yml`文件包括卷、网络和服务的配置。此外，应该有一个版本定义来指示使用的`docker-compose`格式的版本。通过对模板结构的理解，前面的`hello-world`示例所做的事情就很清楚了；它创建了一个名为`hello-world`的服务，它是由`hello-world:latest`镜像创建的。

由于没有定义网络，`docker-compose`将使用默认驱动程序创建一个新网络，并将服务连接到与示例输出中的 1 到 3 行相同的网络。

此外，容器的网络名称将是服务的名称。您可能会注意到控制台中显示的名称与`docker-compose.yml`中的原始名称略有不同。这是因为 Docker Compose 尝试避免容器之间的名称冲突。因此，Docker Compose 使用生成的名称运行容器，并使用服务名称创建网络别名。在此示例中，`hello-world`和`cwd_hello-world_1`都可以在同一网络中解析到其他容器。

# 组合容器

由于 Docker Compose 在许多方面与 Docker 相同，因此更有效的方法是了解如何使用示例编写`docker-compose.yml`，而不是从`docker-compose`语法开始。现在让我们回到之前的`kiosk-example`，并从`version`定义和四个`services`开始：

```
version: '3'
services:
 kiosk-example:
 recorder-example:
 lcredis:
 lmysql:
```

`kiosk-example`的`docker run`参数非常简单，包括发布端口和环境变量。在 Docker Compose 方面，我们相应地填写源镜像、发布端口和环境变量。因为 Docker Compose 能够处理`docker build`，如果本地找不到这些镜像，它将构建镜像。我们很可能希望利用它来进一步减少镜像管理的工作量。

```
kiosk-example:
 image: kiosk-example
 build: ./kiosk
 ports:
  - "5000:5000"
  environment:
    REDIS_HOST: lcredis
```

以相同的方式转换`recorder-example`和`redis`的 Docker 运行，我们得到了以下模板：

```
version: '3'
services:
  kiosk-example:
    image: kiosk-example
    build: ./kiosk
    ports:
    - "5000:5000"
    environment:
      REDIS_HOST: lcredis
  recorder-example:
    image: recorder-example
    build: ./recorder
    environment:
      REDIS_HOST: lcredis
      MYSQL_HOST: lmysql
      MYSQL_USER: root
      MYSQL_ROOT_PASSWORD: mysqlpass
  lcredis:
    image: redis
    ports:
    - "6379"
```

对于 MySQL 部分，它需要一个数据卷来保存数据以及配置。因此，除了`lmysql`部分之外，我们在`services`级别添加`volumes`，并添加一个空映射`mysql-vol`来声明一个数据卷：

```
 lmysql:
 image: mysql:5.7
   environment:
     MYSQL_ROOT_PASSWORD: mysqlpass
   volumes:
   - mysql-vol:/var/lib/mysql
   ports:
   - "3306"
  ---
volumes:
  mysql-vol:
```

结合所有前述的配置，我们得到了最终的模板，如下所示：

```
docker-compose.yml
---
version: '3'
services:
 kiosk-example:
    image: kiosk-example
    build: ./kiosk
    ports:
    - "5000:5000"
    environment:
      REDIS_HOST: lcredis
 recorder-example:
    image: recorder-example
    build: ./recorder
    environment:
      REDIS_HOST: lcredis
      MYSQL_HOST: lmysql
      MYSQL_USER: root
      MYSQL_ROOT_PASSWORD: mysqlpass
 lcredis:
 image: redis
    ports:
    - "6379"
 lmysql:
    image: mysql:5.7
    environment:
      MYSQL_ROOT_PASSWORD: mysqlpass
    volumes:
    - mysql-vol:/var/lib/mysql
    ports:
    - "3306"
volumes:
 mysql-vol: 
```

该文件放在项目的根文件夹中。相应的文件树如下所示：

```
├── docker-compose.yml
├── kiosk
│   ├── Dockerfile
│   ├── app.py
│   └── requirements.txt
└── recorder
 ├── Dockerfile
 ├── process.py
 └── requirements.txt  
```

最后，运行`docker-compose up`来检查一切是否正常。我们可以通过发送`GET /tickets`请求来检查我们的售票亭是否正常运行。

编写 Docker Compose 的模板就是这样简单。现在我们可以轻松地在堆栈中运行应用程序。

# 总结

从 Linux 容器的最原始元素到 Docker 工具栈，我们经历了容器化应用的每个方面，包括打包和运行 Docker 容器，为基于代码的不可变部署编写`Dockerfile`，以及使用 Docker Compose 操作多个容器。然而，本章获得的能力只允许我们在同一主机上运行和连接容器，这限制了构建更大应用的可能性。因此，在下一章中，我们将遇到 Kubernetes，释放容器的力量，超越规模的限制。


# 第三章：开始使用 Kubernetes

我们已经了解了容器可以为我们带来的好处，但是如果我们需要根据业务需求扩展我们的服务怎么办？有没有一种方法可以在多台机器上构建服务，而不必处理繁琐的网络和存储设置？此外，是否有其他简单的方法来管理和推出我们的微服务，以适应不同的服务周期？这就是 Kubernetes 的作用。在本章中，我们将学习：

+   Kubernetes 概念

+   Kubernetes 组件

+   Kubernetes 资源及其配置文件

+   如何通过 Kubernetes 启动 kiosk 应用程序

# 理解 Kubernetes

Kubernetes 是一个用于管理跨多台主机的应用容器的平台。它为面向容器的应用程序提供了许多管理功能，例如自动扩展、滚动部署、计算资源和卷管理。与容器的本质相同，它被设计为可以在任何地方运行，因此我们可以在裸机上、在我们的数据中心、在公共云上，甚至是混合云上运行它。

Kubernetes 考虑了应用容器的大部分操作需求。重点是：

+   容器部署

+   持久存储

+   容器健康监控

+   计算资源管理

+   自动扩展

+   通过集群联邦实现高可用性

Kubernetes 非常适合微服务。使用 Kubernetes，我们可以创建`Deployment`来部署、滚动或回滚选定的容器（第七章，*持续交付*）。容器被视为临时的。我们可以将卷挂载到容器中，以在单个主机世界中保留数据。在集群世界中，容器可能被调度在任何主机上运行。我们如何使卷挂载作为永久存储无缝工作？Kubernetes 引入了**Volumes**和**Persistent Volumes**来解决这个问题（第四章，*使用存储和资源*）。容器的生命周期可能很短。当它们超出资源限制时，它们可能随时被杀死或停止，我们如何确保我们的服务始终为一定数量的容器提供服务？Kubernetes 中的**ReplicationController**或**ReplicaSet**将确保一定数量的容器组处于运行状态。Kubernetes 甚至支持**liveness probe**来帮助您定义应用程序的健康状况。为了更好地管理资源，我们还可以为 Kubernetes 节点定义最大容量和每组容器（即**pod**）的资源限制。Kubernetes 调度程序将选择满足资源标准的节点来运行容器。我们将在第四章，*使用存储和资源*中学习这一点。Kubernetes 提供了一个可选的水平 pod 自动缩放功能。使用此功能，我们可以按资源或自定义指标水平扩展 pod。对于那些高级读者，Kubernetes 设计了高可用性（**HA**）。我们可以创建多个主节点来防止单点故障。

# Kubernetes 组件

Kubernetes 包括两个主要组件：

+   **主节点**：主节点是 Kubernetes 的核心，它控制和调度集群中的所有活动

+   **节点**：节点是运行我们的容器的工作节点

# Master 组件

Master 包括 API 服务器、控制器管理器、调度程序和 etcd。所有组件都可以在不同的主机上进行集群运行。然而，从学习的角度来看，我们将使所有组件在同一节点上运行。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00032.jpeg)Master 组件

# API 服务器（kube-apiserver）

API 服务器提供 HTTP/HTTPS 服务器，为 Kubernetes 主节点中的所有组件提供 RESTful API。例如，我们可以获取资源状态，如 pod，POST 来创建新资源，还可以观察资源。API 服务器读取和更新 etcd，这是 Kubernetes 的后端数据存储。

# 控制器管理器（kube-controller-manager）

控制器管理器在集群中控制许多不同的事物。复制控制器管理器确保所有复制控制器在所需的容器数量上运行。节点控制器管理器在节点宕机时做出响应，然后会驱逐 pod。端点控制器用于关联服务和 pod 之间的关系。服务账户和令牌控制器用于控制默认账户和 API 访问令牌。

# etcd

etcd 是一个开源的分布式键值存储（[`coreos.com/etcd`](https://coreos.com/etcd)）。Kubernetes 将所有 RESTful API 对象存储在这里。etcd 负责存储和复制数据。

# 调度器（kube-scheduler）

调度器根据节点的资源容量或节点上资源利用的平衡来决定适合 pod 运行的节点。它还考虑将相同集合中的 pod 分散到不同的节点。

# 节点组件

节点组件需要在每个节点上进行配置和运行，向主节点报告 pod 的运行时状态。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00033.jpeg)节点组件

# Kubelet

Kubelet 是节点中的一个重要进程，定期向 kube-apiserver 报告节点活动，如 pod 健康、节点健康和活动探测。正如前面的图表所示，它通过容器运行时（如 Docker 或 rkt）运行容器。

# 代理（kube-proxy）

代理处理 pod 负载均衡器（也称为**服务**）和 pod 之间的路由，它还提供了从外部到服务的路由。有两种代理模式，用户空间和 iptables。用户空间模式通过在内核空间和用户空间之间切换来创建大量开销。另一方面，iptables 模式是最新的默认代理模式。它改变 Linux 中的 iptables **NAT**以实现在所有容器之间路由 TCP 和 UDP 数据包。

# Docker

正如第二章中所述，*使用容器进行 DevOps*，Docker 是一个容器实现。Kubernetes 使用 Docker 作为默认的容器引擎。

# Kubernetes 主节点与节点之间的交互

在下图中，客户端使用**kubectl**向 API 服务器发送请求；API 服务器响应请求，从 etcd 中推送和拉取对象信息。调度器确定应该分配给哪个节点执行任务（例如，运行 pod）。**控制器管理器**监视运行的任务，并在发生任何不良状态时做出响应。另一方面，**API 服务器**通过 kubelet 从 pod 中获取日志，并且还是其他主节点组件之间的中心。

与主节点和节点之间的交互

# 开始使用 Kubernetes

在本节中，我们将学习如何在开始时设置一个小型单节点集群。然后我们将学习如何通过其命令行工具--kubectl 与 Kubernetes 进行交互。我们将学习所有重要的 Kubernetes API 对象及其在 YAML 格式中的表达，这是 kubectl 的输入，然后 kubectl 将相应地向 API 服务器发送请求。

# 准备环境

开始的最简单方法是运行 minikube ([`github.com/kubernetes/minikube`](https://github.com/kubernetes/minikube))，这是一个在本地单节点上运行 Kubernetes 的工具。它支持在 Windows、Linux 和 macOS 上运行。在下面的示例中，我们将在 macOS 上运行。Minikube 将启动一个安装了 Kubernetes 的虚拟机。然后我们将能够通过 kubectl 与其交互。

请注意，minikube 不适用于生产环境或任何重负载环境。由于其单节点特性，存在一些限制。我们将在第九章 *在 AWS 上运行 Kubernetes*和第十章 *在 GCP 上运行 Kubernetes*中学习如何运行一个真正的集群。

在安装 minikube 之前，我们必须先安装 Homebrew ([`brew.sh/`](https://brew.sh/))和 VirtualBox ([`www.virtualbox.org/`](https://www.virtualbox.org/))。Homebrew 是 macOS 中一个有用的软件包管理器。我们可以通过`/usr/bin/ruby -e "$(curl -fsSL [`raw.githubusercontent.com/Homebrew/install/master/install)`](https://raw.githubusercontent.com/Homebrew/install/master/install))"`命令轻松安装 Homebrew，并从 Oracle 网站下载 VirtualBox 并点击安装。

然后是启动的时间！我们可以通过`brew cask install minikube`来安装 minikube：

```
// install minikube
# brew cask install minikube
==> Tapping caskroom/cask
==> Linking Binary 'minikube-darwin-amd64' to '/usr/local/bin/minikube'.
...
minikube was successfully installed!
```

安装完 minikube 后，我们现在可以启动集群了：

```
// start the cluster
# minikube start
Starting local Kubernetes v1.6.4 cluster...
Starting VM...
Moving files into cluster...
Setting up certs...
Starting cluster components...
Connecting to cluster...
Setting up kubeconfig...
Kubectl is now configured to use the cluster.
```

这将在本地启动一个 Kubernetes 集群。在撰写时，最新版本是`v.1.6.4` minikube。继续在 VirtualBox 中启动名为 minikube 的 VM。然后将设置`kubeconfig`，这是一个用于定义集群上下文和认证设置的配置文件。

通过`kubeconfig`，我们能够通过`kubectl`命令切换到不同的集群。我们可以使用`kubectl config view`命令来查看`kubeconfig`中的当前设置：

```
apiVersion: v1

# cluster and certificate information
clusters:
- cluster:
 certificate-authority-data: REDACTED
 server: https://35.186.182.157
 name: gke_devops_cluster
- cluster:
 certificate-authority: /Users/chloelee/.minikube/ca.crt
 server: https://192.168.99.100:8443
 name: minikube

# context is the combination of cluster, user and namespace
contexts:
- context:
 cluster: gke_devops_cluster
 user: gke_devops_cluster
 name: gke_devops_cluster
- context:
 cluster: minikube
 user: minikube
 name: minikube
current-context: minikube
kind: Config
preferences: {}

# user information
users:
- name: gke_devops_cluster
user:
 auth-provider:
 config:
 access-token: xxxx
 cmd-args: config config-helper --format=json
 cmd-path: /Users/chloelee/Downloads/google-cloud-sdk/bin/gcloud
 expiry: 2017-06-08T03:51:11Z
 expiry-key: '{.credential.token_expiry}'
 token-key: '{.credential.access_token}'
 name: gcp

# namespace info
- name: minikube
user:
 client-certificate: /Users/chloelee/.minikube/apiserver.crt
 client-key: /Users/chloelee/.minikube/apiserver.key
```

在这里，我们知道我们当前正在使用与集群和用户名称相同的 minikube 上下文。上下文是认证信息和集群连接信息的组合。如果您有多个上下文，可以使用`kubectl config use-context $context`来强制切换上下文。

最后，我们需要在 minikube 中启用`kube-dns`插件。`kube-dns`是 Kuberentes 中的 DNS 服务：

```
// enable kube-dns addon
# minikube addons enable kube-dns
kube-dns was successfully enabled
```

# kubectl

`kubectl`是控制 Kubernetes 集群管理器的命令。最常见的用法是检查集群的版本：

```
// check Kubernetes version
# kubectl version
Client Version: version.Info{Major:"1", Minor:"6", GitVersion:"v1.6.2", GitCommit:"477efc3cbe6a7effca06bd1452fa356e2201e1ee", GitTreeState:"clean", BuildDate:"2017-04-19T20:33:11Z", GoVersion:"go1.7.5", Compiler:"gc", Platform:"darwin/amd64"}
Server Version: version.Info{Major:"1", Minor:"6", GitVersion:"v1.6.4", GitCommit:"d6f433224538d4f9ca2f7ae19b252e6fcb66a3ae", GitTreeState:"clean", BuildDate:"2017-05-30T22:03:41Z", GoVersion:"go1.7.3", Compiler:"gc", Platform:"linux/amd64"} 
```

我们随后知道我们的服务器版本是最新的，在撰写时是最新的版本 1.6.4。 `kubectl`的一般语法是：

```
kubectl [command] [type] [name] [flags] 
```

`command`表示您要执行的操作。如果您只在终端中键入`kubectl help`，它将显示支持的命令。`type`表示资源类型。我们将在下一节中学习主要的资源类型。`name`是我们命名资源的方式。沿途始终保持清晰和信息丰富的命名是一个好习惯。对于`flags`，如果您键入`kubectl options`，它将显示您可以传递的所有标志。

`kubectl`非常方便，我们总是可以添加`--help`来获取特定命令的更详细信息。例如：

```
// show detailed info for logs command 
kubectl logs --help 
Print the logs for a container in a pod or specified resource. If the pod has only one container, the container name is 
optional. 

Aliases: 
logs, log 

Examples: 
  # Return snapshot logs from pod nginx with only one container 
  kubectl logs nginx 

  # Return snapshot logs for the pods defined by label   
  app=nginx 
  kubectl logs -lapp=nginx 

  # Return snapshot of previous terminated ruby container logs   
  from pod web-1 
  kubectl logs -p -c ruby web-1 
... 
```

然后我们得到了`kubectl logs`命令中的完整支持选项。

# Kubernetes 资源

Kubernetes 对象是集群中的条目，存储在 etcd 中。它们代表了集群的期望状态。当我们创建一个对象时，我们通过 kubectl 或 RESTful API 向 API 服务器发送请求。API 服务器将状态存储到 etcd 中，并与其他主要组件交互，以确保对象存在。Kubernetes 使用命名空间在虚拟上隔离对象，根据不同的团队、用途、项目或环境。每个对象都有自己的名称和唯一 ID。Kubernetes 还支持标签和注释，让我们对对象进行标记。标签尤其可以用于将对象分组在一起。

# Kubernetes 对象

对象规范描述了 Kubernetes 对象的期望状态。大多数情况下，我们编写对象规范，并通过 kubectl 将规范发送到 API 服务器。Kubernetes 将尝试实现该期望状态并更新对象状态。

对象规范可以用 YAML（[`www.yaml.org/`](http://www.yaml.org/)）或 JSON（[`www.json.org/`](http://www.json.org/)）编写。在 Kubernetes 世界中，YAML 更常见。在本书的其余部分中，我们将使用 YAML 格式来编写对象规范。以下代码块显示了一个 YAML 格式的规范片段：

```
apiVersion: Kubernetes API version 
kind: object type 
metadata:  
  spec metadata, i.e. namespace, name, labels and annotations 
spec: 
  the spec of Kubernetes object 
```

# 命名空间

Kubernetes 命名空间被视为多个虚拟集群的隔离。不同命名空间中的对象对彼此是不可见的。当不同团队或项目共享同一个集群时，这是非常有用的。大多数资源都在一个命名空间下（也称为命名空间资源）；然而，一些通用资源，如节点或命名空间本身，不属于任何命名空间。Kubernetes 默认有三个命名空间：

+   default

+   kube-system

+   kube-public

如果没有明确地为命名空间资源分配命名空间，它将位于当前上下文下的命名空间中。如果我们从未添加新的命名空间，将使用默认命名空间。

kube-system 命名空间被 Kubernetes 系统创建的对象使用，例如插件，这些插件是实现集群功能的 pod 或服务，例如仪表板。kube-public 命名空间是在 Kubernetes 1.6 中新引入的，它被一个 beta 控制器管理器（BootstrapSigner [`kubernetes.io/docs/admin/bootstrap-tokens`](https://kubernetes.io/docs/admin/bootstrap-tokens)）使用，将签名的集群位置信息放入`kube-public`命名空间，以便认证/未认证用户可以看到这些信息。

在接下来的章节中，所有的命名空间资源都将位于默认命名空间中。命名空间对于资源管理和角色也非常重要。我们将在第八章《集群管理》中介绍更多内容。

# 名称

Kubernetes 中的每个对象都拥有自己的名称。一个资源中的对象名称在同一命名空间内是唯一标识的。Kubernetes 使用对象名称作为资源 URL 到 API 服务器的一部分，因此它必须是小写字母、数字字符、破折号和点的组合，长度不超过 254 个字符。除了对象名称，Kubernetes 还为每个对象分配一个唯一的 ID（UID），以区分类似实体的历史发生。

# 标签和选择器

标签是一组键/值对，用于附加到对象。标签旨在为对象指定有意义的标识信息。常见用法是微服务名称、层级、环境和软件版本。用户可以定义有意义的标签，以便稍后与选择器一起使用。对象规范中的标签语法是：

```
labels: 
  $key1: $value1 
  $key2: $value2 
```

除了标签，标签选择器用于过滤对象集。用逗号分隔，多个要求将由`AND`逻辑运算符连接。有两种过滤方式：

+   基于相等性的要求

+   基于集合的要求

基于相等性的要求支持`=`，`==`和`!=`运算符。例如，如果选择器是`chapter=2,version!=0.1`，结果将是**对象 C**。如果要求是`version=0.1`，结果将是**对象 A**和**对象 B**。如果我们在支持的对象规范中写入要求，将如下所示：

```
selector: 
  $key1: $value1 
```

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00035.jpeg)选择器示例

基于集合的要求支持`in`，`notin`和`exists`（仅针对键）。例如，如果要求是`chapter in (3, 4),version`，那么对象 A 将被返回。如果要求是`version notin (0.2), !author_info`，结果将是**对象 A**和**对象 B**。以下是一个示例，如果我们写入支持基于集合的要求的对象规范：

```
selector: 
  matchLabels:  
    $key1: $value1 
  matchExpressions: 
{key: $key2, operator: In, values: [$value1, $value2]} 
```

`matchLabels`和`matchExpressions`的要求被合并在一起。这意味着过滤后的对象需要在两个要求上都为真。

我们将在本章中学习使用 ReplicationController、Service、ReplicaSet 和 Deployment。

# 注释

注释是一组用户指定的键/值对，用于指定非标识性元数据。使用注释可以像普通标记一样，例如，用户可以向注释中添加时间戳、提交哈希或构建编号。一些 kubectl 命令支持 `--record` 选项，以记录对注释对象进行更改的命令。注释的另一个用例是存储配置，例如 Kubernetes 部署（[`kubernetes.io/docs/concepts/workloads/controllers/deployment`](https://kubernetes.io/docs/concepts/workloads/controllers/deployment)）或关键附加组件 pods（[`coreos.com/kubernetes/docs/latest/deploy-addons.html`](https://coreos.com/kubernetes/docs/latest/deploy-addons.html)）。注释语法如下所示，位于元数据部分：

```
annotations: 
  $key1: $value1 
  $key2: $value2 
```

命名空间、名称、标签和注释位于对象规范的元数据部分。选择器位于支持选择器的资源的规范部分，例如 ReplicationController、service、ReplicaSet 和 Deployment。

# Pods

Pod 是 Kubernetes 中最小的可部署单元。它可以包含一个或多个容器。大多数情况下，我们只需要一个 pod 中的一个容器。在一些特殊情况下，同一个 pod 中包含多个容器，例如 Sidecar 容器（[`blog.kubernetes.io/2015/06/the-distributed-system-toolkit-patterns.html`](http://blog.kubernetes.io/2015/06/the-distributed-system-toolkit-patterns.html)）。同一 pod 中的容器在共享上下文中运行，在同一节点上共享网络命名空间和共享卷。Pod 也被设计为有生命周期的。当 pod 因某些原因死亡时，例如由于缺乏资源而被 Kubernetes 控制器杀死时，它不会自行恢复。相反，Kubernetes 使用控制器为我们创建和管理 pod 的期望状态。

我们可以使用 `kubectl explain <resource>` 命令来获取资源的详细描述。它将显示资源支持的字段：

```
// get detailed info for `pods` 
# kubectl explain pods 
DESCRIPTION: 
Pod is a collection of containers that can run on a host. This resource is created by clients and scheduled onto hosts. 

FIELDS: 
   metadata  <Object> 
     Standard object's metadata. More info: 
     http://releases.k8s.io/HEAD/docs/devel/api- 
     conventions.md#metadata 

   spec  <Object> 
     Specification of the desired behavior of the pod. 
     More info: 
     http://releases.k8s.io/HEAD/docs/devel/api-
     conventions.md#spec-and-status 

   status  <Object> 
     Most recently observed status of the pod. This data 
     may not be up to date. 
     Populated by the system. Read-only. More info: 
     http://releases.k8s.io/HEAD/docs/devel/api-
     conventions.md#spec-and-status 

   apiVersion  <string> 
     APIVersion defines the versioned schema of this 
     representation of an 
     object. Servers should convert recognized schemas to 
     the latest internal 
     value, and may reject unrecognized values. More info: 
     http://releases.k8s.io/HEAD/docs/devel/api-
     conventions.md#resources 

   kind  <string> 
     Kind is a string value representing the REST resource  
     this object represents. Servers may infer this from 
     the endpoint the client submits 
     requests to. Cannot be updated. In CamelCase. More 
         info: 
     http://releases.k8s.io/HEAD/docs/devel/api-
     conventions.md#types-kinds 
```

在以下示例中，我们将展示如何在一个 pod 中创建两个容器，并演示它们如何相互访问。请注意，这既不是一个有意义的经典的 Sidecar 模式示例。这些模式只在非常特定的场景中使用。以下只是一个示例，演示了如何在 pod 中访问其他容器：

```
// an example for creating co-located and co-scheduled container by pod
# cat 3-2-1_pod.yaml
apiVersion: v1
kind: Pod
metadata:
 name: example
spec:
 containers:
 - name: web
 image: nginx
 - name: centos
 image: centos
 command: ["/bin/sh", "-c", "while : ;do curl http://localhost:80/; sleep 10; done"]
```

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00036.jpeg)Pod 中的容器可以通过 localhost 进行访问

此规范将创建两个容器，`web` 和 `centos`。Web 是一个 nginx 容器 ([`hub.docker.com/_/nginx/`](https://hub.docker.com/_/nginx/))。默认情况下，通过暴露容器端口 `80`，因为 centos 与 nginx 共享相同的上下文，当在 [`localhost:80/`](http://localhost:80/) 中进行 curl 时，应该能够访问 nginx。

接下来，使用 `kubectl create` 命令启动 pod，`-f` 选项让 kubectl 知道使用文件中的数据：

```
// create the resource by `kubectl create` - Create a resource by filename or stdin
# kubectl create -f 3-2-1_pod.yaml
pod "example" created  
```

在创建资源时，在 `kubectl` 命令的末尾添加 `--record=true`。Kubernetes 将在创建或更新此资源时添加最新的命令。因此，我们不会忘记哪些资源是由哪个规范创建的。

我们可以使用 `kubectl get <resource>` 命令获取对象的当前状态。在这种情况下，我们使用 `kubectl get pods` 命令。

```
// get the current running pods 
# kubectl get pods
NAME      READY     STATUS              RESTARTS   AGE
example   0/2       ContainerCreating   0          1s
```

在 `kubectl` 命令的末尾添加 `--namespace=$namespace_name` 可以访问不同命名空间中的对象。以下是一个示例，用于检查 `kube-system` 命名空间中的 pod，该命名空间由系统类型的 pod 使用：

`# kubectl get pods --namespace=kube-system`

`NAME READY STATUS RESTARTS AGE`

`kube-addon-manager-minikube 1/1 Running 2 3d`

`kube-dns-196007617-jkk4k 3/3 Running 3 3d`

`kubernetes-dashboard-3szrf 1/1 Running 1 3d`

大多数对象都有它们的简称，在我们使用 `kubectl get <object>` 列出它们的状态时非常方便。例如，pod 可以称为 po，服务可以称为 svc，部署可以称为 deploy。输入 `kubectl get` 了解更多信息。

我们示例 pod 的状态是 `ContainerCreating`。在这个阶段，Kubernetes 已经接受了请求，尝试调度 pod 并拉取镜像。当前没有容器正在运行。等待片刻后，我们可以再次获取状态：

```
// get the current running pods
# kubectl get pods
NAME      READY     STATUS    RESTARTS   AGE
example   2/2       Running   0          3s  
```

我们可以看到当前有两个容器正在运行。正常运行时间为三秒。使用 `kubectl logs <pod_name> -c <container_name>` 可以获取容器的 `stdout`，类似于 `docker logs <container_name>`：

```
// get stdout for centos
# kubectl logs example -c centos
<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
...
```

pod 中的 centos 通过 localhost 与 nginx 共享相同的网络！Kubernetes 会在 pod 中创建一个网络容器。网络容器的功能之一是在 pod 内部的容器之间转发流量。我们将在 第五章 中了解更多，*网络和安全*。

如果我们在 pod 规范中指定了标签，我们可以使用`kubectl get pods -l <requirement>`命令来获取满足要求的 pod。例如，`kubectl get pods -l 'tier in (frontend, backend)'`。另外，如果我们使用`kubectl pods -owide`，它将列出哪个 pod 运行在哪个节点上。

我们可以使用`kubectl describe <resource> <resource_name>`来获取资源的详细信息：

```
// get detailed information for a pod
# kubectl describe pods example
Name:    example
Namespace:  default
Node:    minikube/192.168.99.100
Start Time:  Fri, 09 Jun 2017 07:08:59 -0400
Labels:    <none>
Annotations:  <none>
Status:    Running
IP:    172.17.0.4
Controllers:  <none>
Containers:  
```

此时，我们知道这个 pod 正在哪个节点上运行，在 minikube 中我们只有一个节点，所以不会有任何区别。在真实的集群环境中，知道哪个节点对故障排除很有用。我们没有为它关联任何标签、注释和控制器：

```
web:
 Container ID:    
 docker://a90e56187149155dcda23644c536c20f5e039df0c174444e 0a8c8  7e8666b102b
   Image:    nginx
   Image ID:    docker://sha256:958a7ae9e56979be256796dabd5845c704f784cd422734184999cf91f24c2547
   Port:
   State:    Running
      Started:    Fri, 09 Jun 2017 07:09:00 -0400
   Ready:    True
   Restart Count:  0
   Environment:  <none>
   Mounts:
      /var/run/secrets/kubernetes.io/serviceaccount from 
      default-token-jd1dq (ro)
     centos:
     Container ID:  docker://778965ad71dd5f075f93c90f91fd176a8add4bd35230ae0fa6c73cd1c2158f0b
     Image:    centos
     Image ID:    docker://sha256:3bee3060bfc81c061ce7069df35ce090593bda584d4ef464bc0f38086c11371d
     Port:
     Command:
       /bin/sh
       -c
       while : ;do curl http://localhost:80/; sleep 10; 
       done
      State:    Running
       Started:    Fri, 09 Jun 2017 07:09:01 -0400
      Ready:    True
      Restart Count:  0
      Environment:  <none>
      Mounts:
          /var/run/secrets/kubernetes.io/serviceaccount from default-token-jd1dq (ro)
```

在容器部分，我们将看到这个 pod 中包含了两个容器。它们的状态、镜像和重启计数：

```
Conditions:
 Type    Status
 Initialized   True
 Ready   True
 PodScheduled   True
```

一个 pod 有一个`PodStatus`，其中包括一个表示为`PodConditions`的数组映射。`PodConditions`的可能键是`PodScheduled`、`Ready`、`Initialized`和`Unschedulable`。值可以是 true、false 或 unknown。如果 pod 没有按预期创建，`PodStatus`将为我们提供哪个部分失败的简要视图：

```
Volumes:
 default-token-jd1dq:
 Type:  Secret (a volume populated by a Secret)
 SecretName:  default-token-jd1dq
 Optional:  false
```

Pod 关联了一个 service account，为运行在 pod 中的进程提供身份。它由 API Server 中的 service account 和 token controller 控制。

它将在包含用于 API 访问令牌的 pod 中，为每个容器挂载一个只读卷到`/var/run/secrets/kubernetes.io/serviceaccount`下。Kubernetes 创建了一个默认的 service account。我们可以使用`kubectl get serviceaccounts`命令来列出它们：

```
QoS Class:  BestEffort
Node-Selectors:  <none>
Tolerations:  <none>
```

我们还没有为这个 pod 分配任何选择器。QoS 表示资源服务质量。Toleration 用于限制可以使用节点的 pod 数量。我们将在第八章中学到更多，*集群管理*：

```
Events:
 FirstSeen  LastSeen  Count  From      SubObjectPath    Type     
  Reason    Message
  ---------  --------  -----  ----      -------------    ------ 
  --  ------    -------
  19m    19m    1  default-scheduler        Normal    Scheduled  
  Successfully assigned example to minikube
  19m    19m    1  kubelet, minikube  spec.containers{web}  
  Normal    Pulling    pulling image "nginx"
  19m    19m    1  kubelet, minikube  spec.containers{web}  
  Normal    Pulled    Successfully pulled image "nginx"
  19m    19m    1  kubelet, minikube  spec.containers{web}  
  Normal    Created    Created container with id 
  a90e56187149155dcda23644c536c20f5e039df0c174444e0a8c87e8666b102b
  19m    19m    1  kubelet, minikube  spec.containers{web}   
  Normal    Started    Started container with id  
 a90e56187149155dcda23644c536c20f5e039df0c174444e0a8c87e86 
 66b102b
  19m    19m    1  kubelet, minikube  spec.containers{centos}  
  Normal    Pulling    pulling image "centos"
  19m    19m    1  kubelet, minikube  spec.containers{centos}  
  Normal    Pulled    Successfully pulled image "centos"
  19m    19m    1  kubelet, minikube  spec.containers{centos}  
  Normal    Created    Created container with id 
 778965ad71dd5f075f93c90f91fd176a8add4bd35230ae0fa6c73cd1c 
 2158f0b
  19m    19m    1  kubelet, minikube  spec.containers{centos}  
  Normal    Started    Started container with id 
 778965ad71dd5f075f93c90f91fd176a8add4bd35230ae0fa6c73cd1c 
 2158f0b 
```

通过查看事件，我们可以了解 Kubernetes 在运行节点时的步骤。首先，调度器将任务分配给一个节点，这里它被命名为 minikube。然后 minikube 上的 kubelet 开始拉取第一个镜像并相应地创建一个容器。然后 kubelet 拉取第二个容器并运行。

# ReplicaSet (RS) 和 ReplicationController (RC)

一个 pod 不会自我修复。当一个 pod 遇到故障时，它不会自行恢复。因此，**ReplicaSet**（**RS**）和**ReplicationController**（**RC**）就发挥作用了。ReplicaSet 和 ReplicationController 都将确保集群中始终有指定数量的副本 pod 在运行。如果一个 pod 因任何原因崩溃，ReplicaSet 和 ReplicationController 将请求启动一个新的 Pod。

在最新的 Kubernetes 版本中，ReplicationController 逐渐被 ReplicaSet 取代。它们共享相同的概念，只是使用不同的 pod 选择器要求。ReplicationController 使用基于相等性的选择器要求，而 ReplicaSet 使用基于集合的选择器要求。ReplicaSet 通常不是由用户创建的，而是由 Kubernetes 部署对象创建，而 ReplicationController 是由用户自己创建的。在本节中，我们将通过示例逐步解释 RC 的概念，这样更容易理解。然后我们将在最后介绍 ReplicaSet。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00037.jpeg)带有期望数量 2 的 ReplicationController

假设我们想创建一个`ReplicationController`对象，期望数量为两个。这意味着我们将始终有两个 pod 在服务中。在编写 ReplicationController 的规范之前，我们必须先决定 pod 模板。Pod 模板类似于 pod 的规范。在 ReplicationController 中，元数据部分中的标签是必需的。ReplicationController 使用 pod 选择器来选择它管理的哪些 pod。标签允许 ReplicationController 区分是否所有与选择器匹配的 pod 都处于正常状态。

在这个例子中，我们将创建两个带有标签`project`，`service`和`version`的 pod，如前图所示：

```
// an example for rc spec
# cat 3-2-2_rc.yaml
apiVersion: v1
kind: ReplicationController
metadata:
 name: nginx
spec:
 replicas: 2
 selector:
 project: chapter3
 service: web
 version: "0.1"
 template:
 metadata:
 name: nginx
 labels:
 project: chapter3
 service: web
 version: "0.1"
 spec:
 containers:
 - name: nginx
 image: nginx
 ports:
 - containerPort: 80
// create RC by above input file
# kubectl create -f 3-2-2_rc.yaml
replicationcontroller "nginx" created  
```

然后我们可以使用`kubectl`来获取当前的 RC 状态：

```
// get current RCs
# kubectl get rc
NAME      DESIRED   CURRENT   READY     AGE
nginx     2         2         2         5s  
```

它显示我们有两个期望的 pod，我们目前有两个 pod 并且两个 pod 已经准备就绪。现在我们有多少个 pod？

```
// get current running pod
# kubectl get pods
NAME          READY     STATUS    RESTARTS   AGE
nginx-r3bg6   1/1       Running   0          11s
nginx-sj2f0   1/1       Running   0          11s  
```

它显示我们有两个正在运行的 pod。如前所述，ReplicationController 管理所有与选择器匹配的 pod。如果我们手动创建一个具有相同标签的 pod，理论上它应该与我们刚刚创建的 RC 的 pod 选择器匹配。让我们试一试：

```
// manually create a pod with same labels
# cat 3-2-2_rc_self_created_pod.yaml
apiVersion: v1
kind: Pod
metadata:
 name: our-nginx
 labels:
 project: chapter3
 service: web
 version: "0.1"
spec:
 containers:
 - name: nginx
 image: nginx
 ports:
 - containerPort: 80
// create a pod with same labels manually
# kubectl create -f 3-2-2_rc_self_created_pod.yaml 
pod "our-nginx" created  
```

让我们看看它是否正在运行：

```
// get pod status
# kubectl get pods
NAME          READY     STATUS        RESTARTS   AGE
nginx-r3bg6   1/1       Running       0          4m
nginx-sj2f0   1/1       Running       0          4m
our-nginx     0/1       Terminating   0          4s  
```

它已经被调度，ReplicationController 捕捉到了它。pod 的数量变成了三个，超过了我们的期望数量。最终该 pod 被杀死：

```
// get pod status
# kubectl get pods
NAME          READY     STATUS    RESTARTS   AGE
nginx-r3bg6   1/1       Running   0          5m
nginx-sj2f0   1/1       Running   0          5m  
```

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00038.jpeg)ReplicationController 确保 pod 处于期望的状态。

如果我们想要按需扩展，我们可以简单地使用 `kubectl edit <resource> <resource_name>` 来更新规范。在这里，我们将将副本数从 `2` 更改为 `5`：

```
// change replica count from 2 to 5, default system editor will pop out. Change `replicas` number
# kubectl edit rc nginx
replicationcontroller "nginx" edited  
```

让我们来检查 RC 信息：

```
// get rc information
# kubectl get rc
NAME      DESIRED   CURRENT   READY     AGE
nginx     5         5         5         5m      
```

我们现在有五个 pods。让我们来看看 RC 是如何工作的：

```
// describe RC resource `nginx`
# kubectl describe rc nginx
Name:    nginx
Namespace:  default
Selector:  project=chapter3,service=web,version=0.1
Labels:    project=chapter3
 service=web
 version=0.1
Annotations:  <none>
Replicas:  5 current / 5 desired
Pods Status:  5 Running / 0 Waiting / 0 Succeeded / 0 Failed
Pod Template:
 Labels:  project=chapter3
 service=web
 version=0.1
 Containers:
 nginx:
 Image:    nginx
 Port:    80/TCP
 Environment:  <none>
 Mounts:    <none>
 Volumes:    <none>
Events:
 FirstSeen  LastSeen  Count  From      SubObjectPath  Type      
  Reason      Message
---------  --------  -----  ----      -------------  --------  ------      -------
34s    34s    1  replication-controller      Normal    SuccessfulCreate  Created pod: nginx-r3bg6 
34s    34s    1  replication-controller      Normal    SuccessfulCreate  Created pod: nginx-sj2f0 
20s    20s    1  replication-controller      Normal    SuccessfulDelete  Deleted pod: our-nginx
15s    15s    1  replication-controller      Normal    SuccessfulCreate  Created pod: nginx-nlx3v
15s    15s    1  replication-controller      Normal    SuccessfulCreate  Created pod: nginx-rqt58
15s    15s    1  replication-controller      Normal    SuccessfulCreate  Created pod: nginx-qb3mr  
```

通过描述命令，我们可以了解 RC 的规范，也可以了解事件。在我们创建 `nginx` RC 时，它按规范启动了两个容器。然后我们通过另一个规范手动创建了另一个 pod，名为 `our-nginx`。RC 检测到该 pod 与其 pod 选择器匹配。然后数量超过了我们期望的数量，所以它将其驱逐。然后我们将副本扩展到了五个。RC 检测到它没有满足我们的期望状态，于是启动了三个 pods 来填补空缺。

如果我们想要删除一个 RC，只需使用 `kubectl` 命令 `kubectl delete <resource> <resource_name>`。由于我们手头上有一个配置文件，我们也可以使用 `kubectl delete -f <configuration_file>` 来删除文件中列出的资源：

```
// delete a rc
# kubectl delete rc nginx
replicationcontroller "nginx" deleted
// get pod status
# kubectl get pods
NAME          READY     STATUS        RESTARTS   AGE
nginx-r3bg6   0/1       Terminating   0          29m  
```

相同的概念也适用于 ReplicaSet。以下是 `3-2-2.rc.yaml` 的 RS 版本。两个主要的区别是：

+   在撰写时，`apiVersion` 是 `extensions/v1beta1`

+   选择器要求更改为基于集合的要求，使用 `matchLabels` 和 `matchExpressions` 语法。

按照前面示例的相同步骤，RC 和 RS 之间应该完全相同。这只是一个例子；然而，我们不应该自己创建 RS，而应该始终由 Kubernetes `deployment` 对象管理。我们将在下一节中学到更多：

```
// RS version of 3-2-2_rc.yaml 
# cat 3-2-2_rs.yaml
apiVersion: extensions/v1beta1
kind: ReplicaSet
metadata:
 name: nginx
spec:
 replicas: 2
 selector:
 matchLabels:
 project: chapter3
 matchExpressions:
 - {key: version, operator: In, values: ["0.1", "0.2"]}
   template:
     metadata:
       name: nginx
        labels:
         project: chapter3
         service: web
         version: "0.1"
     spec:
       containers:
        - name: nginx
          image: nginx
          ports:
         - containerPort: 80
```

# 部署

在 Kubernetes 1.2 版本之后，部署是管理和部署我们的软件的最佳原语。它支持优雅地部署、滚动更新和回滚 pods 和 ReplicaSets。我们通过声明性地定义我们对软件的期望更新，然后部署将逐渐为我们完成。

在部署之前，ReplicationController 和 kubectl rolling-update 是实现软件滚动更新的主要方式，这更加命令式和较慢。现在部署成为了管理我们应用的主要高级对象。

让我们来看看它是如何工作的。在这一部分，我们将体验到部署是如何创建的，如何执行滚动更新和回滚。第七章，*持续交付*有更多关于如何将部署集成到我们的持续交付流水线中的实际示例信息。

首先，我们可以使用`kubectl run`命令为我们创建一个`deployment`：

```
// using kubectl run to launch the Pods
# kubectl run nginx --image=nginx:1.12.0 --replicas=2 --port=80
deployment "nginx" created

// check the deployment status
# kubectl get deployments
NAME      DESIRED   CURRENT   UP-TO-DATE   AVAILABLE   AGE
nginx     2         2         2            2           4h  
```

在 Kubernetes 1.2 之前，`kubectl run`命令将创建 pod。

部署时部署了两个 pod：

```
// check if pods match our desired count
# kubectl get pods
NAME                     READY     STATUS        RESTARTS   AGE
nginx-2371676037-2brn5   1/1       Running       0          4h
nginx-2371676037-gjfhp   1/1       Running       0          4h  
```

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00039.jpeg)部署、ReplicaSets 和 pod 之间的关系

如果我们删除一个 pod，替换的 pod 将立即被调度和启动。这是因为部署在幕后创建了一个 ReplicaSet，它将确保副本的数量与我们的期望数量匹配。一般来说，部署管理 ReplicaSets，ReplicaSets 管理 pod。请注意，我们不应该手动操作部署管理的 ReplicaSets，就像如果它们由 ReplicaSets 管理，直接更改 pod 也是没有意义的：

```
// list replica sets
# kubectl get rs
NAME               DESIRED   CURRENT   READY     AGE
nginx-2371676037   2         2         2         4h      
```

我们还可以通过`kubectl`命令为部署公开端口：

```
// expose port 80 to service port 80
# kubectl expose deployment nginx --port=80 --target-port=80
service "nginx" exposed

// list services
# kubectl get services
NAME         CLUSTER-IP   EXTERNAL-IP   PORT(S)   AGE
kubernetes   10.0.0.1     <none>        443/TCP   3d
nginx        10.0.0.94    <none>        80/TCP    5s  
```

部署也可以通过 spec 创建。之前由 kubectl 启动的部署和服务可以转换为以下 spec：

```
// create deployments by spec
# cat 3-2-3_deployments.yaml
apiVersion: apps/v1beta1
kind: Deployment
metadata:
 name: nginx
spec:
 replicas: 2
 template:
 metadata:
 labels:
 run: nginx
 spec:
 containers:
 - name: nginx
 image: nginx:1.12.0
 ports:
 - containerPort: 80
---
kind: Service
apiVersion: v1
metadata:
 name: nginx
 labels:
 run: nginx
spec:
 selector:
 run: nginx
 ports:
 - protocol: TCP
 port: 80
 targetPort: 80
 name: http

// create deployments and service
# kubectl create -f 3-2-3_deployments.yaml
deployment "nginx" created
service "nginx" created  
```

为执行滚动更新，我们将不得不添加滚动更新策略。有三个参数用于控制该过程：

| **参数** | **描述** | **默认值** |
| --- | --- | --- |
| `minReadySeconds` | 热身时间。新创建的 pod 被认为可用的时间。默认情况下，Kubernetes 假定应用程序一旦成功启动就可用。 | 0 |
| `maxSurge` | 在执行滚动更新过程时可以增加的 pod 数量。 | 25% |
| `maxUnavailable` | 在执行滚动更新过程时可以不可用的 pod 数量。 | 25% |

`minReadySeconds`是一个重要的设置。如果我们的应用程序在 pod 启动时不能立即使用，那么没有适当的等待，pod 将滚动得太快。尽管所有新的 pod 都已经启动，但应用程序可能仍在热身；有可能会发生服务中断。在下面的示例中，我们将把配置添加到`Deployment.spec`部分：

```
// add to Deployments.spec, save as 3-2-3_deployments_rollingupdate.yaml
minReadySeconds: 3 
strategy:
 type: RollingUpdate
 rollingUpdate:
 maxSurge: 1
 maxUnavailable: 1  
```

这表示我们允许一个 pod 每次不可用，并且在滚动 pod 时可以启动一个额外的 pod。在进行下一个操作之前的热身时间将为三秒。我们可以使用`kubectl edit deployments nginx`（直接编辑）或`kubectl replace -f 3-2-3_deployments_rollingupdate.yaml`来更新策略。

假设我们想要模拟新软件的升级，从 nginx 1.12.0 到 1.13.1。我们仍然可以使用前面的两个命令来更改镜像版本，或者使用`kubectl set image deployment nginx nginx=nginx:1.13.1`来触发更新。如果我们使用`kubectl describe`来检查发生了什么，我们将看到部署已经通过删除/创建 pod 来触发了 ReplicaSets 的滚动更新：

```
// check detailed rs information
# kubectl describe rs nginx-2371676037 
Name:    nginx-2371676037 
Namespace:  default
Selector:  pod-template-hash=2371676037   ,run=nginx
Labels:    pod-template-hash=2371676037 
 run=nginx
Annotations:  deployment.kubernetes.io/desired-replicas=2
 deployment.kubernetes.io/max-replicas=3
 deployment.kubernetes.io/revision=4
 deployment.kubernetes.io/revision-history=2
Replicas:  2 current / 2 desired
Pods Status:  2 Running / 0 Waiting / 0 Succeeded / 0 Failed
Pod Template:
 Labels:  pod-template-hash=2371676037 
 run=nginx
Containers:
nginx:
Image:    nginx:1.13.1
Port:    80/TCP
...
Events:
FirstSeen  LastSeen  Count  From      SubObjectPath  Type    Reason      Message
---------  --------  -----  ----      -------------  --------  ------      -------
3m    3m    1  replicaset-controller      Normal    SuccessfulCreate  Created pod: nginx-2371676037-f2ndj
3m    3m    1  replicaset-controller      Normal    SuccessfulCreate  Created pod: nginx-2371676037-9lc8j
3m    3m    1  replicaset-controller      Normal    SuccessfulDelete  Deleted pod: nginx-2371676037-f2ndj
3m    3m    1  replicaset-controller      Normal    SuccessfulDelete  Deleted pod: nginx-2371676037-9lc8j
```

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00040.jpeg)部署的示例

上图显示了部署的示例。在某个时间点，我们有两个（期望数量）和一个（`maxSurge`）pod。在启动每个新的 pod 后，Kubernetes 将等待三个（`minReadySeconds`）秒，然后执行下一个操作。

如果我们使用命令`kubectl set image deployment nginx nginx=nginx:1.12.0 to previous version 1.12.0`，部署将为我们执行回滚。

# 服务

Kubernetes 中的服务是将流量路由到一组逻辑 pod 的抽象层。有了服务，我们就不需要追踪每个 pod 的 IP 地址。服务通常使用标签选择器来选择它需要路由到的 pod（在某些情况下，服务是有意地创建而不带选择器）。服务抽象是强大的。它实现了解耦，并使微服务之间的通信成为可能。目前，Kubernetes 服务支持 TCP 和 UDP。

服务不关心我们如何创建 pod。就像 ReplicationController 一样，它只关心 pod 是否匹配其标签选择器，因此 pod 可以属于不同的 ReplicationControllers。以下是一个示例：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00041.jpeg)服务通过标签选择器映射 pod

在图中，所有的 pod 都匹配服务选择器，因此服务将负责将流量分发到所有的 pod，而无需显式分配。

**服务类型**

服务有四种类型：ClusterIP、NodePort、LoadBalancer 和 ExternalName。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00042.jpeg)LoadBalancer 包括 NodePort 和 ClusterIP 的功能

**ClusterIP**

ClusterIP 是默认的服务类型。它在集群内部 IP 上公开服务。集群中的 pod 可以通过 IP 地址、环境变量或 DNS 访问服务。在下面的示例中，我们将学习如何使用本地服务环境变量和 DNS 来访问集群中服务后面的 pod。

在启动服务之前，我们想要创建图中显示的两组 RC：

```
// create RC 1 with nginx 1.12.0 version
# cat 3-2-3_rc1.yaml
apiVersion: v1
kind: ReplicationController
metadata:
 name: nginx-1.12
spec:
 replicas: 2
 selector:
 project: chapter3
 service: web
 version: "0.1"
template:
 metadata:
 name: nginx
 labels:
 project: chapter3
 service: web
 version: "0.1"
 spec:
 containers:
 - name: nginx
 image: nginx:1.12.0
 ports:
 - containerPort: 80
// create RC 2 with nginx 1.13.1 version
# cat 3-2-3_rc2.yaml
apiVersion: v1
kind: ReplicationController
metadata:
 name: nginx-1.13
spec:
 replicas: 2
 selector:
 project: chapter3
 service: web
 version: "0.2"
 template:
 metadata:
 name: nginx
 labels:
 project: chapter3
 service: web
 version: "0.2"
spec:
 containers:
- name: nginx
 image: nginx:1.13.1
 ports:
 - containerPort: 80  
```

然后我们可以制定我们的 pod 选择器，以定位项目和服务标签：

```
// simple nginx service 
# cat 3-2-3_service.yaml
kind: Service
apiVersion: v1
metadata:
 name: nginx-service
spec:
 selector:
 project: chapter3
 service: web
 ports:
 - protocol: TCP
 port: 80
 targetPort: 80
 name: http

// create the RCs 
# kubectl create -f 3-2-3_rc1.yaml
replicationcontroller "nginx-1.12" created 
# kubectl create -f 3-2-3_rc2.yaml
replicationcontroller "nginx-1.13" created

// create the service
# kubectl create -f 3-2-3_service.yaml
service "nginx-service" created  
```

由于`service`对象可能创建一个 DNS 标签，因此服务名称必须遵循字符 a-z、0-9 或-（连字符）的组合。标签开头或结尾的连字符是不允许的。

然后我们可以使用`kubectl describe service <service_name>`来检查服务信息：

```
// check nginx-service information
# kubectl describe service nginx-service
Name:      nginx-service
Namespace:    default
Labels:      <none>
Annotations:    <none>
Selector:    project=chapter3,service=web
Type:      ClusterIP
IP:      10.0.0.188
Port:      http  80/TCP
Endpoints:    172.17.0.5:80,172.17.0.6:80,172.17.0.7:80 + 1 more...
Session Affinity:  None
Events:      <none>
```

一个服务可以公开多个端口。只需在服务规范中扩展`.spec.ports`列表。

我们可以看到这是一个 ClusterIP 类型的服务，分配的内部 IP 是 10.0.0.188。端点显示我们在服务后面有四个 IP。可以通过`kubectl describe pods <pod_name>`命令找到 pod IP。Kubernetes 为匹配的 pod 创建了一个`endpoints`对象以及一个`service`对象来路由流量。 

当使用选择器创建服务时，Kubernetes 将创建相应的端点条目并进行更新，这将告诉目标服务路由到哪里：

```
// list current endpoints. Nginx-service endpoints are created and pointing to the ip of our 4 nginx pods.
# kubectl get endpoints
NAME            ENDPOINTS                                               AGE
kubernetes      10.0.2.15:8443                                          2d
nginx-service   172.17.0.5:80,172.17.0.6:80,172.17.0.7:80 + 1 more...   10s  
```

ClusterIP 可以在集群内定义，尽管大多数情况下我们不会显式使用 IP 地址来访问集群。使用`.spec.clusterIP`可以完成工作。

默认情况下，Kubernetes 将为每个服务公开七个环境变量。在大多数情况下，前两个将用于使用`kube-dns`插件来为我们进行服务发现：

+   `${SVCNAME}_SERVICE_HOST`

+   `${SVCNAME}_SERVICE_PORT`

+   `${SVCNAME}_PORT`

+   `${SVCNAME}_PORT_${PORT}_${PROTOCAL}`

+   `${SVCNAME}_PORT_${PORT}_${PROTOCAL}_PROTO`

+   `${SVCNAME}_PORT_${PORT}_${PROTOCAL}_PORT`

+   `${SVCNAME}_PORT_${PORT}_${PROTOCAL}_ADDR`

在下面的示例中，我们将在另一个 pod 中使用`${SVCNAME}_SERVICE_HOST`来检查是否可以访问我们的 nginx pods：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00043.jpeg)通过环境变量和 DNS 名称访问 ClusterIP 的示意图

然后我们将创建一个名为`clusterip-chk`的 pod，通过`nginx-service`访问 nginx 容器：

```
// access nginx service via ${NGINX_SERVICE_SERVICE_HOST}
# cat 3-2-3_clusterip_chk.yaml
apiVersion: v1
kind: Pod
metadata:
 name: clusterip-chk
spec:
 containers:
 - name: centos
 image: centos
 command: ["/bin/sh", "-c", "while : ;do curl    
http://${NGINX_SERVICE_SERVICE_HOST}:80/; sleep 10; done"]  
```

我们可以通过`kubectl logs`命令来检查`cluserip-chk` pod 的`stdout`：

```
// check stdout, see if we can access nginx pod successfully
# kubectl logs -f clusterip-chk
% Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                     Dload  Upload   Total   Spent    Left  Speed
100   612  100   612    0     0   156k      0 --:--:-- --:--:-- --:--:--  199k
 ...
<title>Welcome to nginx!</title>
    ...  
```

这种抽象级别解耦了 pod 之间的通信。Pod 是有寿命的。有了 RC 和 service，我们可以构建健壮的服务，而不必担心一个 pod 可能影响所有微服务。

启用`kube-dns`插件后，同一集群和相同命名空间中的 pod 可以通过服务的 DNS 记录访问服务。Kube-dns 通过监视 Kubernetes API 来为新创建的服务创建 DNS 记录。集群 IP 的 DNS 格式是`$servicename.$namespace`，端口是`_$portname_$protocal.$servicename.$namespace`。`clusterip_chk` pod 的规范将与环境变量相似。只需在我们之前的例子中将 URL 更改为[`http://nginx-service.default:_http_tcp.nginx-service.default/`](http://nginx-service.default:_http_tcp.nginx-service.default/)，它们应该完全相同地工作！

**NodePort**

如果服务设置为 NodePort，Kubernetes 将在每个节点上分配一个特定范围内的端口。任何发送到该端口的节点的流量将被路由到服务端口。端口号可以由用户指定。如果未指定，Kubernetes 将在 30000 到 32767 范围内随机选择一个端口而不发生冲突。另一方面，如果指定了，用户应该自行负责管理冲突。NodePort 包括 ClusterIP 的功能。Kubernetes 为服务分配一个内部 IP。在下面的例子中，我们将看到如何创建一个 NodePort 服务并利用它：

```
// write a nodeport type service
# cat 3-2-3_nodeport.yaml
kind: Service
apiVersion: v1
metadata:
 name: nginx-nodeport
spec:
 type: NodePort
 selector:
 project: chapter3
 service: web
 ports:
 - protocol: TCP
 port: 80
 targetPort: 80

// create a nodeport service
# kubectl create -f 3-2-3_nodeport.yaml
service "nginx-nodeport" created  
```

然后你应该能够通过`http://${NODE_IP}:80`访问服务。Node 可以是任何节点。`kube-proxy`会监视服务和端点的任何更新，并相应地更新 iptables 规则（如果使用默认的 iptables 代理模式）。

如果你正在使用 minikube，你可以通过`minikube service [-n NAMESPACE] [--url] NAME`命令访问服务。在这个例子中，是`minikube service nginx-nodeport`。

**LoadBalancer**

这种类型只能在云提供商支持的情况下使用，比如谷歌云平台（第十章，*GCP 上的 Kubernetes*）和亚马逊网络服务（第九章，*AWS 上的 Kubernetes*）。通过创建 LoadBalancer 服务，Kubernetes 将由云提供商为服务提供负载均衡器。

**ExternalName（kube-dns 版本>=1.7）**

有时我们会在云中利用不同的服务。Kubernetes 足够灵活，可以是混合的。ExternalName 是创建外部端点的**CNAME**的桥梁之一，将其引入集群中。

**没有选择器的服务**

服务使用选择器来匹配 pod 以指导流量。然而，有时您需要实现代理来成为 Kubernetes 集群和另一个命名空间、另一个集群或外部资源之间的桥梁。在下面的示例中，我们将演示如何在您的集群中为[`www.google.com`](http://www.google.com)实现代理。这只是一个示例，代理的源可能是云中数据库或其他资源的终点：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00044.jpeg)无选择器的服务如何工作的示例

配置文件与之前的类似，只是没有选择器部分：

```
// create a service without selectors
# cat 3-2-3_service_wo_selector_srv.yaml
kind: Service
apiVersion: v1
metadata:
 name: google-proxy
spec:
 ports:
 - protocol: TCP
 port: 80
 targetPort: 80

// create service without selectors
# kubectl create -f 3-2-3_service_wo_selector_srv.yaml
service "google-proxy" created  
```

由于没有选择器，将不会创建任何 Kubernetes 终点。Kubernetes 不知道将流量路由到何处，因为没有选择器可以匹配 pod。我们必须自己创建。

在`Endpoints`对象中，源地址不能是 DNS 名称，因此我们将使用`nslookup`从域中查找当前的 Google IP，并将其添加到`Endpoints.subsets.addresses.ip`中：

```
// get an IP from google.com
# nslookup www.google.com
Server:    192.168.1.1
Address:  192.168.1.1#53

Non-authoritative answer:
Name:  google.com
Address: 172.217.0.238

// create endpoints for the ip from google.com
# cat 3-2-3_service_wo_selector_endpoints.yaml
kind: Endpoints
apiVersion: v1
metadata:
 name: google-proxy
subsets:
 - addresses:
 - ip: 172.217.0.238
 ports:
 - port: 80

// create Endpoints
# kubectl create -f 3-2-3_service_wo_selector_endpoints.yaml
endpoints "google-proxy" created  
```

让我们在集群中创建另一个 pod 来访问我们的 Google 代理：

```
// pod for accessing google proxy
# cat 3-2-3_proxy-chk.yaml
apiVersion: v1
kind: Pod
metadata:
 name: proxy-chk
spec:
 containers:
 - name: centos
 image: centos
 command: ["/bin/sh", "-c", "while : ;do curl -L http://${GOOGLE_PROXY_SERVICE_HOST}:80/; sleep 10; done"]

// create the pod
# kubectl create -f 3-2-3_proxy-chk.yaml
pod "proxy-chk" created  
```

让我们检查一下 pod 的`stdout`：

```
// get logs from proxy-chk
# kubectl logs proxy-chk
% Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                     Dload  Upload   Total   Spent    Left  Speed
100   219  100   219    0     0   2596      0 --:--:-- --:--:-- --:--:--  2607
100   258  100   258    0     0   1931      0 --:--:-- --:--:-- --:--:--  1931
<!doctype html><html itemscope="" itemtype="http://schema.org/WebPage" lang="en-CA">
 ...  
```

万岁！我们现在可以确认代理起作用了。对服务的流量将被路由到我们指定的终点。如果不起作用，请确保您为外部资源的网络添加了适当的入站规则。

终点不支持 DNS 作为源。或者，我们可以使用 ExternalName，它也没有选择器。它需要 kube-dns 版本>= 1.7。

在某些用例中，用户对服务既不需要负载平衡也不需要代理功能。在这种情况下，我们可以将`CluterIP = "None"`设置为所谓的无头服务。有关更多信息，请参阅[`kubernetes.io/docs/concepts/services-networking/service/#headless-services`](https://kubernetes.io/docs/concepts/services-networking/service/#headless-services)。

# 卷

容器是短暂的，它的磁盘也是如此。我们要么使用`docker commit [CONTAINER]`命令，要么将数据卷挂载到容器中（第二章，*使用容器进行 DevOps*）。在 Kubernetes 的世界中，卷管理变得至关重要，因为 pod 可能在任何节点上运行。此外，确保同一 pod 中的容器可以共享相同的文件变得非常困难。这是 Kubernetes 中的一个重要主题。第四章，*存储和资源处理*介绍了卷管理。

# 秘密

秘密，正如其名称，是以键值格式存储敏感信息以提供给 pod 的对象，这可能是密码、访问密钥或令牌。秘密不会落地到磁盘上；相反，它存储在每个节点的`tmpfs`文件系统中。模式上的 Kubelet 将创建一个`tmpfs`文件系统来存储秘密。由于存储管理的考虑，秘密并不设计用于存储大量数据。一个秘密的当前大小限制为 1MB。

我们可以通过启动 kubectl 创建秘密命令或通过 spec 来基于文件、目录或指定的文字值创建秘密。有三种类型的秘密格式：通用（或不透明，如果编码）、docker 注册表和 TLS。

通用/不透明是我们将在应用程序中使用的文本。Docker 注册表用于存储私有 docker 注册表的凭据。TLS 秘密用于存储集群管理的 CA 证书包。

docker-registry 类型的秘密也被称为**imagePullSecrets**，它用于在拉取镜像时通过 kubelet 传递私有 docker 注册表的密码。这非常方便，这样我们就不需要为每个提供的节点执行`docker login`。命令是`kubectl create secret docker-registry` `<registry_name>` `--docker-server``=<docker_server> --docker-username=<docker_username>` `-``-docker-password=<docker_password> --docker-email=<docker_email>`

我们将从一个通用类型的示例开始，以展示它是如何工作的：

```
// create a secret by command line
# kubectl create secret generic mypassword --from-file=./mypassword.txt
secret "mypassword" created  
```

基于目录和文字值创建秘密的选项与文件的选项非常相似。如果在`--from-file`后指定目录，那么目录中的文件将被迭代，文件名将成为秘密密钥（如果是合法的秘密名称），其他非常规文件将被忽略，如子目录、符号链接、设备、管道。另一方面，`--from-literal=<key>=<value>`是一个选项，如果你想直接从命令中指定纯文本，例如，`--from-literal=username=root`。

在这里，我们从文件`mypassword.txt`创建一个名为`mypassword`的秘密。默认情况下，秘密的键是文件名，这相当于`--from-file=mypassword=./mypassword.txt`选项。我们也可以追加多个`--from-file`。使用`kubectl get secret` `<secret_name>` `-o yaml`命令可以查看秘密的详细信息：

```
// get the detailed info of the secret
# kubectl get secret mypassword -o yaml
apiVersion: v1
data:
 mypassword: bXlwYXNzd29yZA==
kind: Secret
metadata:
 creationTimestamp: 2017-06-13T08:09:35Z
 name: mypassword
 namespace: default
 resourceVersion: "256749"
 selfLink: /api/v1/namespaces/default/secrets/mypassword
 uid: a33576b0-500f-11e7-9c45-080027cafd37
type: Opaque  
```

我们可以看到秘密的类型变为`Opaque`，因为文本已被 kubectl 加密。它是 base64 编码的。我们可以使用一个简单的 bash 命令来解码它：

```
# echo "bXlwYXNzd29yZA==" | base64 --decode
mypassword  
```

Pod 检索秘密有两种方式。第一种是通过文件，第二种是通过环境变量。第一种方法是通过卷实现的。语法是在容器规范中添加`containers.volumeMounts`，并在卷部分添加秘密配置。

**通过文件检索秘密**

让我们先看看如何从 Pod 内的文件中读取秘密：

```
// example for how a Pod retrieve secret 
# cat 3-2-3_pod_vol_secret.yaml 
apiVersion: v1 
kind: Pod 
metadata: 
  name: secret-access 
spec: 
  containers: 
  - name: centos 
    image: centos 
    command: ["/bin/sh", "-c", "cat /secret/password-example; done"] 
    volumeMounts: 
      - name: secret-vol 
        mountPath: /secret 
        readOnly: true 
  volumes: 
    - name: secret-vol 
      secret: 
        secretName: mypassword 
        # items are optional 
        items: 
        - key: mypassword  
          path: password-example 

// create the pod 
# kubectl create -f 3-2-3_pod_vol_secret.yaml 
pod "secret-access" created 
```

秘密文件将被挂载在`/<mount_point>/<secret_name>`中，而不指定`items``key`和`path`，或者在 Pod 中的`/<mount_point>/<path>`中。在这种情况下，它位于`/secret/password-example`下。如果我们描述 Pod，我们可以发现这个 Pod 中有两个挂载点。第一个是只读卷，存储我们的秘密，第二个存储与 API 服务器通信的凭据，这是由 Kubernetes 创建和管理的。我们将在第五章中学到更多内容，*网络和安全*。

```
# kubectl describe pod secret-access
...
Mounts:
 /secret from secret-vol (ro)
 /var/run/secrets/kubernetes.io/serviceaccount from default-token-jd1dq (ro)
...  
```

我们可以使用`kubectl delete secret` `<secret_name>`命令删除秘密。

描述完 Pod 后，我们可以找到`FailedMount`事件，因为卷不再存在：

```
# kubectl describe pod secret-access
...
FailedMount  MountVolume.SetUp failed for volume "kubernetes.io/secret/28889b1d-5015-11e7-9c45-080027cafd37-secret-vol" (spec.Name: "secret-vol") pod "28889b1d-5015-11e7-9c45-080027cafd37" (UID: "28889b1d-5015-11e7-9c45-080027cafd37") with: secrets "mypassword" not found
...  
```

同样的想法，如果 Pod 在创建秘密之前生成，那么 Pod 也会遇到失败。

现在我们将学习如何通过命令行创建秘密。接下来我们将简要介绍其规范格式：

```
// secret example # cat 3-2-3_secret.yaml 
apiVersion: v1 
kind: Secret 
metadata:  
  name: mypassword 
type: Opaque 
data:  
  mypassword: bXlwYXNzd29yZA==
```

由于规范是纯文本，我们需要通过自己的`echo -n <password>` `| base64`来对秘密进行编码。请注意，这里的类型变为`Opaque`。按照这样做，它应该与我们通过命令行创建的那个相同。

**通过环境变量检索秘密**

或者，我们可以使用环境变量来检索秘密，这样更灵活，适用于短期凭据，比如密码。这样，应用程序可以使用环境变量来检索数据库密码，而无需处理文件和卷：

秘密应该始终在需要它的 Pod 之前创建。否则，Pod 将无法成功启动。

```
// example to use environment variable to retrieve the secret
# cat 3-2-3_pod_ev_secret.yaml
apiVersion: v1
kind: Pod
metadata:
 name: secret-access-ev
spec:
 containers:
 - name: centos
 image: centos
 command: ["/bin/sh", "-c", "while : ;do echo $MY_PASSWORD; sleep 10; done"]
 env:
 - name: MY_PASSWORD
 valueFrom:
 secretKeyRef:
 name: mypassword
 key: mypassword

// create the pod 
# kubectl create -f 3-2-3_pod_ev_secret.yaml
pod "secret-access-ev" created 
```

声明位于`spec.containers[].env[]`下。在这种情况下，我们需要秘密名称和密钥名称。两者都是`mypassword`。示例应该与通过文件检索的示例相同。

# ConfigMap

ConfigMap 是一种能够将配置留在 Docker 镜像之外的方法。它将配置数据作为键值对注入到 pod 中。它的属性与 secret 类似，更具体地说，secret 用于存储敏感数据，如密码，而 ConfigMap 用于存储不敏感的配置数据。

与 secret 相同，ConfigMap 可以基于文件、目录或指定的文字值。与 secret 相似的语法/命令，ConfigMap 使用`kubectl create configmap`而不是：

```
// create configmap
# kubectl create configmap example --from-file=config/app.properties --from-file=config/database.properties
configmap "example" created  
```

由于两个`config`文件位于同一个名为`config`的文件夹中，我们可以传递一个`config`文件夹，而不是逐个指定文件。在这种情况下，创建等效命令是`kubectl create configmap example --from-file=config`。

如果我们描述 ConfigMap，它将显示当前信息：

```
// check out detailed information for configmap
# kubectl describe configmap example
Name:    example
Namespace:  default
Labels:    <none>
Annotations:  <none>

Data
====
app.properties:
----
name=DevOps-with-Kubernetes
port=4420

database.properties:
----
endpoint=k8s.us-east-1.rds.amazonaws.com
port=1521  
```

我们可以使用`kubectl edit configmap` `<configmap_name>`来更新创建后的配置。

我们还可以使用`literal`作为输入。前面示例的等效命令将是`kubectl create configmap example --from-literal=app.properties.name=name=DevOps-with-Kubernetes`，当我们在应用程序中有许多配置时，这并不总是很实用。

让我们看看如何在 pod 内利用它。在 pod 内使用 ConfigMap 也有两种方式：通过卷或环境变量。

# 通过卷使用 ConfigMap

与 secret 部分中的先前示例类似，我们使用`configmap`语法挂载卷，并在容器模板中添加`volumeMounts`。在`centos`中，该命令将循环执行`cat ${MOUNTPOINT}/$CONFIG_FILENAME`。

```
cat 3-2-3_pod_vol_configmap.yaml
apiVersion: v1
kind: Pod
metadata:
 name: configmap-vol
spec:
 containers:
 - name: configmap
 image: centos
 command: ["/bin/sh", "-c", "while : ;do cat /src/app/config/database.properties; sleep 10; done"]
 volumeMounts:
 - name: config-volume
 mountPath: /src/app/config
 volumes:
 - name: config-volume
 configMap:
 name: example

// create configmap
# kubectl create -f 3-2-3_pod_vol_configmap.yaml
pod "configmap-vol" created

// check out the logs
# kubectl logs -f configmap-vol
endpoint=k8s.us-east-1.rds.amazonaws.com
port=1521  
```

然后我们可以使用这种方法将我们的非敏感配置注入到 pod 中。

# 通过环境变量使用 ConfigMap

要在 pod 内使用 ConfigMap，您必须在`env`部分中使用`configMapKeyRef`作为值来源。它将将整个 ConfigMap 对填充到环境变量中：

```
# cat 3-2-3_pod_ev_configmap.yaml
apiVersion: v1
kind: Pod
metadata:
 name: config-ev
spec:
 containers:
 - name: centos
 image: centos
 command: ["/bin/sh", "-c", "while : ;do echo $DATABASE_ENDPOINT; sleep 10;    
   done"]
 env:
 - name: MY_PASSWORD
 valueFrom:
 secretKeyRef:
 name: mypassword
 key: mypassword

// create configmap
# kubectl create -f 3-2-3_pod_ev_configmap.yaml
pod "configmap-ev" created

// check out the logs
# kubectl logs configmap-ev
endpoint=k8s.us-east-1.rds.amazonaws.com port=1521  
```

Kubernetes 系统本身也利用 ConfigMap 来进行一些认证。例如，kube-dns 使用它来放置客户端 CA 文件。您可以通过在描述 ConfigMaps 时添加`--namespace=kube-system`来检查系统 ConfigMap。

# 多容器编排

在这一部分，我们将重新审视我们的售票服务：一个作为前端的售票机网络服务，提供接口来获取/放置票务。有一个作为缓存的 Redis，用来管理我们有多少张票。Redis 还充当发布者/订阅者通道。一旦一张票被售出，售票机将向其发布一个事件。订阅者被称为记录器，它将写入一个时间戳并将其记录到 MySQL 数据库中。请参考第二章中的最后一节，*使用容器进行 DevOps*，了解详细的 Dockerfile 和 Docker compose 实现。我们将使用`Deployment`、`Service`、`Secret`、`Volume`和`ConfigMap`对象在 Kubernetes 中实现这个例子。源代码可以在[`github.com/DevOps-with-Kubernetes/examples/tree/master/chapter3/3-3_kiosk`](https://github.com/DevOps-with-Kubernetes/examples/tree/master/chapter3/3-3_kiosk)找到。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-k8s/img/00045.jpeg)Kubernetes 世界中售票机的一个例子

我们将需要四种类型的 pod。使用 Deployment 来管理/部署 pod 是最好的选择。它将通过部署策略功能减少我们在未来进行部署时的痛苦。由于售票机、Redis 和 MySQL 将被其他组件访问，我们将为它们的 pod 关联服务。MySQL 充当数据存储，为了简单起见，我们将为其挂载一个本地卷。请注意，Kubernetes 提供了一堆选择。请查看第四章中的详细信息和示例，*使用存储和资源*。像 MySQL 的 root 和用户密码这样的敏感信息，我们希望它们存储在秘钥中。其他不敏感的配置，比如数据库名称或数据库用户名，我们将留给 ConfigMap。

我们将首先启动 MySQL，因为记录器依赖于它。在创建 MySQL 之前，我们必须先创建相应的`secret`和`ConfigMap`。要创建`secret`，我们需要生成 base64 加密的数据：

```
// generate base64 secret for MYSQL_PASSWORD and MYSQL_ROOT_PASSWORD
# echo -n "pass" | base64
cGFzcw==
# echo -n "mysqlpass" | base64
bXlzcWxwYXNz
```

然后我们可以创建秘钥：

```
# cat secret.yaml
apiVersion: v1
kind: Secret
metadata:
 name: mysql-user
type: Opaque
data:
 password: cGFzcw==

---
# MYSQL_ROOT_PASSWORD
apiVersion: v1
kind: Secret
metadata:
 name: mysql-root
type: Opaque
data:
 password: bXlzcWxwYXNz

// create mysql secret
# kubectl create -f secret.yaml --record
secret "mysql-user" created
secret "mysql-root" created
```

然后我们来到我们的 ConfigMap。在这里，我们将数据库用户和数据库名称作为示例放入：

```
# cat config.yaml
kind: ConfigMap
apiVersion: v1
metadata:
 name: mysql-config
data:
 user: user
 database: db

// create ConfigMap
# kubectl create -f config.yaml --record
configmap "mysql-config" created  
```

然后是启动 MySQL 及其服务的时候：

```
// MySQL Deployment
# cat mysql.yaml
apiVersion: apps/v1beta1
kind: Deployment
metadata:
 name: lmysql
spec:
 replicas: 1
 template:
 metadata:
 labels:
 tier: database
 version: "5.7"
 spec:
 containers:
 - name: lmysql
 image: mysql:5.7
 volumeMounts:
 - mountPath: /var/lib/mysql
 name: mysql-vol
 ports:
 - containerPort: 3306
 env:
 - name: MYSQL_ROOT_PASSWORD
 valueFrom:
 secretKeyRef:
 name: mysql-root
 key: password
 - name: MYSQL_DATABASE
 valueFrom:
 configMapKeyRef:
 name: mysql-config
 key: database
 - name: MYSQL_USER
 valueFrom:
 configMapKeyRef:
 name: mysql-config
 key: user
 - name: MYSQL_PASSWORD
 valueFrom:
 secretKeyRef:
 name: mysql-user
 key: password
 volumes:
 - name: mysql-vol
 hostPath:
 path: /mysql/data
---
kind: Service
apiVersion: v1
metadata:
 name: lmysql-service
spec:
 selector:
 tier: database
 ports:
 - protocol: TCP
 port: 3306
 targetPort: 3306
 name: tcp3306  
```

我们可以通过添加三个破折号作为分隔，将多个规范放入一个文件中。在这里，我们将`hostPath /mysql/data`挂载到具有路径`/var/lib/mysql`的 pod 中。在环境部分，我们通过`secretKeyRef`和`configMapKeyRef`利用秘钥和 ConfigMap 的语法。

创建 MySQL 后，Redis 将是下一个很好的候选，因为它是其他的依赖，但它不需要先决条件：

```
// create Redis deployment
# cat redis.yaml
apiVersion: apps/v1beta1
kind: Deployment
metadata:
 name: lcredis
spec:
 replicas: 1
 template:
 metadata:
 labels:
 tier: cache
 version: "3.0"
 spec:
 containers:
 - name: lcredis
 image: redis:3.0
 ports:
 - containerPort: 6379
minReadySeconds: 1
strategy:
 type: RollingUpdate
 rollingUpdate:
 maxSurge: 1
 maxUnavailable: 1
---
kind: Service
apiVersion: v1
metadata:
 name: lcredis-service
spec:
 selector:
 tier: cache
 ports:
 - protocol: TCP
 port: 6379
 targetPort: 6379
 name: tcp6379

// create redis deployements and service
# kubectl create -f redis.yaml
deployment "lcredis" created
service "lcredis-service" created  
```

然后现在是启动 kiosk 的好时机：

```
# cat kiosk-example.yaml
apiVersion: apps/v1beta1
kind: Deployment
metadata:
 name: kiosk-example
spec:
 replicas: 5
 template:
 metadata:
 labels:
 tier: frontend
 version: "3"
 annotations:
 maintainer: cywu
 spec:
 containers:
 - name: kiosk-example
 image: devopswithkubernetes/kiosk-example
 ports:
 - containerPort: 5000
 env:
 - name: REDIS_HOST
 value: lcredis-service.default
 minReadySeconds: 5
 strategy:
 type: RollingUpdate
 rollingUpdate:
 maxSurge: 1
 maxUnavailable: 1
---
kind: Service
apiVersion: v1
metadata:
 name: kiosk-service
spec:
 type: NodePort
 selector:
 tier: frontend
 ports:
 - protocol: TCP
 port: 80
 targetPort: 5000
 name: tcp5000

// launch the spec
# kubectl create -f kiosk-example.yaml
deployment "kiosk-example" created
service "kiosk-service" created    
```

在这里，我们将`lcredis-service.default`暴露给 kiosk pod 的环境变量，这是 kube-dns 为`Service`对象（在本章中称为 service）创建的 DNS 名称。因此，kiosk 可以通过环境变量访问 Redis 主机。

最后，我们将创建录音机。录音机不向其他人公开任何接口，因此不需要`Service`对象：

```
# cat recorder-example.yaml
apiVersion: apps/v1beta1
kind: Deployment
metadata:
 name: recorder-example
spec:
 replicas: 3
 template:
 metadata:
 labels:
 tier: backend
 version: "3"
 annotations:
 maintainer: cywu
 spec:
 containers:
 - name: recorder-example
 image: devopswithkubernetes/recorder-example
 env:
 - name: REDIS_HOST
 value: lcredis-service.default
 - name: MYSQL_HOST
 value: lmysql-service.default
 - name: MYSQL_USER
 value: root
 - name: MYSQL_ROOT_PASSWORD
 valueFrom:
 secretKeyRef:
 name: mysql-root
 key: password
minReadySeconds: 3
strategy:
 type: RollingUpdate
 rollingUpdate:
 maxSurge: 1
 maxUnavailable: 1
// create recorder deployment
# kubectl create -f recorder-example.yaml
deployment "recorder-example" created  
```

录音机需要访问 Redis 和 MySQL。它使用通过秘密注入的根凭据。Redis 和 MySQL 的两个端点通过服务 DNS 名称`<service_name>.<namespace>`访问。

然后我们可以检查`deployment`对象：

```
// check deployment details
# kubectl get deployments
NAME               DESIRED   CURRENT   UP-TO-DATE   AVAILABLE   AGE
kiosk-example      5         5         5            5           1h
lcredis            1         1         1            1           1h
lmysql             1         1         1            1           1h
recorder-example   3         3         3            3           1h  
```

不出所料，我们有四个`deployment`对象，每个对象都有不同的期望 pod 数量。

由于我们将 kiosk 公开为 NodePort，我们应该能够访问其服务端点，并查看它是否正常工作。假设我们有一个节点，IP 是`192.168.99.100`，Kubernetes 分配的 NodePort 是 30520。

如果您正在使用 minikube，`minikube service [-n NAMESPACE] [--url] NAME`可以帮助您通过默认浏览器访问服务 NodePort：

`//打开 kiosk 控制台`

`# minikube service kiosk-service`

在默认浏览器中打开 kubernetes 服务默认/kiosk-service...

然后我们可以知道 IP 和端口。

然后我们可以通过`POST`和`GET /tickets`创建和获取票据：

```
// post ticket
# curl -XPOST -F 'value=100' http://192.168.99.100:30520/tickets
SUCCESS

// get ticket
# curl -XGET http://192.168.99.100:30520/tickets
100  
```

# 总结

在本章中，我们学习了 Kubernetes 的基本概念。我们了解到 Kubernetes 主节点有 kube-apiserver 来处理请求，控制器管理器是 Kubernetes 的控制中心，例如，它确保我们期望的容器数量得到满足，控制关联 pod 和服务的端点，并控制 API 访问令牌。我们还有 Kubernetes 节点，它们是承载容器的工作节点，接收来自主节点的信息，并根据配置路由流量。

然后，我们使用 minikube 演示了基本的 Kubernetes 对象，包括 pod、ReplicaSets、ReplicationControllers、deployments、services、secrets 和 ConfigMap。最后，我们演示了如何将我们学到的所有概念结合到 kiosk 应用程序部署中。

正如我们之前提到的，容器内的数据在容器消失时也会消失。因此，在容器世界中，卷是非常重要的，用来持久保存数据。在下一章中，我们将学习卷是如何工作的，以及它的选项，如何使用持久卷等等。
