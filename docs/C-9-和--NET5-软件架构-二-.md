# C#9 和 .NET5 软件架构（二）

> 原文：[`zh.annas-archive.org/md5/83D8F5A1D11ACA866E980121BEEF9AAA`](https://zh.annas-archive.org/md5/83D8F5A1D11ACA866E980121BEEF9AAA)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：将微服务架构应用于企业应用程序

本章专门描述基于称为微服务的小模块的高度可扩展架构。微服务架构允许进行细粒度的扩展操作，每个模块都可以根据需要进行扩展，而不会影响系统的其他部分。此外，它们还允许更好的持续集成/持续部署（CI/CD），因为每个系统子部分都可以独立演进和部署，而不受其他部分的影响。

在本章中，我们将涵盖以下主题：

+   什么是微服务？

+   什么时候使用微服务有帮助？

+   .NET 如何处理微服务？

+   管理微服务所需的工具有哪些？

通过本章的学习，您将学会如何在.NET 中实现单个微服务。第六章“Azure Service Fabric”和第七章“Azure Kubernetes Service”还介绍了如何部署、调试和管理基于微服务的整个应用程序。

# 技术要求

在本章中，您将需要以下内容：

+   安装了所有数据库工具的 Visual Studio 2019 免费社区版或更高版本。

+   一个免费的 Azure 账户。第一章“理解软件架构的重要性”中的“创建 Azure 账户”部分解释了如何创建账户。

+   如果您想在 Visual Studio 中调试 Docker 容器化的微服务，需要 Windows 版 Docker Desktop（[`www.docker.com/products/docker-desktop`](https://www.docker.com/products/docker-desktop)）。

# 什么是微服务？

微服务架构允许将解决方案的每个模块独立于其他模块进行扩展，以实现最大吞吐量和最小成本。事实上，对整个系统进行扩展而不是当前瓶颈部分必然会导致资源的明显浪费，因此对子系统扩展的细粒度控制对系统的整体成本有着重要影响。

然而，微服务不仅仅是可扩展的组件-它们是可以独立开发、维护和部署的软件构建块。将开发和维护分割成可以独立开发、维护和部署的模块，可以改善整个系统的 CI/CD 周期（CI/CD 概念在第三章的“使用 Azure DevOps 组织工作”部分和“使用 Azure DevOps 记录需求”部分中有更详细的解释）。

由于微服务的“独立性”，CI/CD 的改进是可能的，因为它实现了以下功能：

+   在不同类型的硬件上进行微服务的扩展和分布。

+   由于每个微服务都是独立部署的，因此不存在二进制兼容性或数据库结构兼容性约束。因此，不需要对组成系统的不同微服务的版本进行对齐。这意味着每个微服务可以根据需要进行演进，而不受其他微服务的限制。

+   将开发任务分配给完全独立的小团队，从而简化工作组织并减少处理大型团队时不可避免的协调低效问题。

+   使用更合适的技术和更合适的环境来实现每个微服务，因为每个微服务都是一个独立的部署单元。这意味着选择最适合您需求的工具和最大程度减少开发工作和/或最大程度提高性能的环境。

+   由于每个微服务可以使用不同的技术、编程语言、工具和操作系统来实现，企业可以通过将环境与开发人员的能力匹配来利用所有可用的人力资源。例如，如果使用 Java 实现微服务并具有相同的所需行为，那么未充分利用的 Java 开发人员也可以参与.NET 项目。

+   遗留子系统可以嵌入独立的微服务中，从而使它们能够与新的子系统合作。这样，公司可以减少新系统版本的上市时间。此外，这样，遗留系统可以逐渐向更现代的系统演进，对成本和组织的影响可接受。

下一小节解释了微服务的概念是如何构思的。然后，我们将继续通过探索基本的微服务设计原则并分析为什么微服务通常被设计为 Docker 容器来继续介绍本章节。

## 微服务和模块概念的演变

为了更好地理解微服务的优势以及它们的设计技术，我们必须牢记软件模块化和软件模块的双重性质：

+   代码模块化是指使我们能够修改一块代码而不影响应用程序其余部分的代码组织。通常，它是通过面向对象设计来实现的，其中模块可以用类来标识。

+   **部署模块化**取决于部署单元是什么以及它们具有哪些属性。最简单的部署单元是可执行文件和库。因此，例如，动态链接库（DLL）肯定比静态库更模块化，因为它们在部署之前不需要与主要可执行文件链接。

虽然代码模块化的基本概念已经达到了稳定状态，但部署模块化的概念仍在不断发展，微服务目前是这一演变路径上的最新技术。

作为对导致微服务发展的主要里程碑的简要回顾，我们可以说，首先，将单体可执行文件拆分为静态库。随后，动态链接库（DLL）取代了静态库。

当.NET（以及其他类似的框架，如 Java）改进了可执行文件和库的模块化时，发生了巨大的变化。实际上，使用.NET，它们可以部署在不同的硬件和不同的操作系统上，因为它们部署在第一次执行库时编译的中间语言中。此外，它们克服了以前 DLL 的一些版本问题，因为任何可执行文件都会带有一个与安装在操作系统中的相同 DLL 版本不同的版本的 DLL。

然而，.NET 不能接受两个引用的 DLL - 假设为*A*和*B* - 使用共同依赖项的两个不同版本 - 假设为*C*。例如，假设有一个新版本的*A*，具有许多我们想要使用的新功能，反过来依赖于*B*不支持的*C*的新版本。在这种情况下，由于*C*与*B*的不兼容性，我们应该放弃*A*的新版本。这个困难导致了两个重要的变化：

+   开发世界从 DLL 和/或单个文件转向了包管理系统，如 NuGet 和 npm，这些系统可以通过语义化版本控制自动检查版本兼容性。

+   **面向服务的架构**（SOA）。部署单元开始被实现为 SOAP，然后是 REST Web 服务。这解决了版本兼容性问题，因为每个 Web 服务在不同的进程中运行，并且可以使用最合适的每个库的版本，而不会导致与其他 Web 服务不兼容的风险。此外，每个 Web 服务公开的接口是平台无关的，也就是说，Web 服务可以与使用任何框架的应用程序连接并在任何操作系统上运行，因为 Web 服务协议基于普遍接受的标准。SOA 和协议将在*第十四章*《使用.NET Core 应用面向服务的架构》中详细讨论。

微服务是 SOA 的演变，并增加了更多功能和约束，以改善服务的可伸缩性和模块化，以改善整体的 CI/CD 周期。有时人们说*微服务是 SOA 做得好*。

## 微服务设计原则

总之，微服务架构是最大程度地实现独立性和细粒度扩展的 SOA。现在我们已经澄清了微服务独立性和细粒度扩展的所有优势，以及独立性的本质，我们可以看看微服务设计原则。

让我们从独立性约束产生的原则开始。我们将在单独的小节中讨论它们。

### 设计选择的独立性

每个微服务的设计不能依赖于在其他微服务实现中所做的设计选择。这个原则使得每个微服务的 CI/CD 周期完全独立，并让我们在如何实现每个微服务上有更多的技术选择。这样，我们可以选择最好的可用技术来实现每个微服务。

这个原则的另一个结果是，不同的微服务不能连接到相同的共享存储（数据库或文件系统），因为共享相同的存储也意味着共享决定存储子系统结构的所有设计选择（数据库表设计，数据库引擎等）。因此，要么一个微服务有自己的数据存储，要么根本没有存储，并与负责处理存储的其他微服务进行通信。

在这里，拥有专用的数据存储并不意味着物理数据库分布在微服务本身的进程边界内，而是微服务具有对由外部数据库引擎处理的数据库或一组数据库表的独占访问权限。事实上，出于性能原因，数据库引擎必须在专用硬件上运行，并具有针对其存储功能进行优化的操作系统和硬件功能。

通常，*设计选择的独立性*以更轻的形式解释，通过区分逻辑和物理微服务。更具体地说，逻辑微服务是由使用相同数据存储但独立负载平衡的多个物理微服务实现的。也就是说，逻辑微服务被设计为一个逻辑单元，然后分割成更多的物理微服务以实现更好的负载平衡。

### 独立于部署环境

微服务在不同的硬件节点上进行扩展，并且不同的微服务可以托管在同一节点上。因此，微服务越少依赖操作系统提供的服务和其他安装的软件，它就可以部署在更多的硬件节点上。还可以进行更多的节点优化。

这就是为什么微服务通常是容器化并使用 Docker 的原因。容器将在本章的*容器和 Docker*小节中更详细地讨论，但基本上，容器化是一种技术，允许每个微服务携带其依赖项，以便它可以在任何地方运行。

### 松散耦合

每个微服务必须与所有其他微服务松散耦合。这个原则具有双重性质。一方面，这意味着，根据面向对象编程原则，每个微服务公开的接口不能太具体，而应尽可能通用。然而，这也意味着微服务之间的通信必须最小化，以减少通信成本，因为微服务不共享相同的地址空间，运行在不同的硬件节点上。

### 不要有链接的请求/响应

当请求到达微服务时，它不能引起对其他微服务的递归链式请求/响应，因为类似的链式请求/响应会导致无法接受的响应时间。如果所有微服务的私有数据模型在每次更改时都与推送通知同步，就可以避免链式请求/响应。换句话说，一旦由微服务处理的数据发生变化，这些变化就会发送到可能需要这些数据来处理其请求的所有微服务。这样，每个微服务都在其私有数据存储中拥有处理所有传入请求所需的所有数据，无需向其他微服务请求缺少的数据。

总之，每个微服务必须包含其所需的所有数据，以提供传入请求并确保快速响应。为了使其数据模型保持最新并准备好处理传入请求，微服务必须在数据发生变化时立即通知其它微服务。这些数据变化应通过异步消息进行通信，因为同步嵌套消息会导致不可接受的性能问题，因为它们会阻塞所有涉及调用树的线程，直到返回结果。

值得指出的是，“设计选择的独立性”原则实际上是领域驱动设计中的有界上下文原则，我们将在《第十二章：理解软件解决方案中的不同领域》中详细讨论。在本章中，我们将看到，通常情况下，完整的领域驱动设计方法对于每个微服务的“更新”子系统非常有用。

总的来说，按照有界上下文原则开发的所有系统通常都更适合使用微服务架构来实现。实际上，一旦将系统分解为几个完全独立且松耦合的部分，由于不同的流量和不同的资源需求，这些不同的部分很可能需要独立扩展。

除了上述约束，我们还必须添加一些构建可重用 SOA 的最佳实践。关于这些最佳实践的更多细节将在《第十四章：使用.NET Core 应用面向服务的架构》中给出，但是现在，大多数 SOA 最佳实践都是由用于实现 Web 服务的工具和框架自动强制执行的。

细粒度的扩展要求微服务足够小，以便隔离明确定义的功能，但这也需要一个复杂的基础架构来自动实例化微服务，将实例分配到各种硬件计算资源上，通常称为“节点”，并根据需要进行扩展。这些结构将在本章的“需要哪些工具来管理微服务？”部分中介绍，并在《第六章：Azure Service Fabric》和《第七章：Azure Kubernetes Service》中详细讨论。

此外，通过异步通信进行通信的细粒度扩展的分布式微服务要求每个微服务具有弹性。实际上，由于硬件故障或在负载平衡操作期间目标实例被终止或移动到另一个节点的简单原因，针对特定微服务实例的通信可能会失败。

临时故障可以通过指数级重试来克服。这意味着在每次失败后，我们会延迟指数级地重试相同的操作，直到达到最大尝试次数。例如，首先，我们会在 10 毫秒后重试，如果这次重试操作失败，那么在 20 毫秒后进行新的尝试，然后是 40 毫秒，依此类推。

另一方面，长期故障通常会导致重试操作的激增，可能会使所有系统资源饱和，类似于拒绝服务攻击。因此，通常会将指数级重试与“断路器策略”一起使用：在一定数量的失败之后，假定存在长期故障，并且通过返回立即失败而不尝试通信操作来阻止对资源的访问一段时间。

同样重要的是，某些子系统的拥塞，无论是由于故障还是请求高峰，都不会传播到其他系统部分，以防止整体系统拥塞。**隔离舱壁**通过以下方式避免拥塞传播：

+   只允许一定数量的类似的同时出站请求；比如说，10。这类似于对线程创建设置上限。

+   超过先前限制的请求将被排队。

+   如果达到最大队列长度，任何进一步的请求都会导致抛出异常以中止它们。

重试策略可能导致同一消息被接收和处理多次，因为发送方未收到消息已被接收的确认，或者因为操作超时，而接收方实际上已接收了消息。这个问题的唯一可能解决方案是设计所有消息都是幂等的，也就是说，设计消息的处理多次与处理一次具有相同的效果。

例如，将数据库表字段更新为一个值是幂等操作，因为重复一次或两次会产生完全相同的效果。然而，递增十进制字段不是幂等操作。微服务设计者应该努力设计整个应用程序，尽可能多地使用幂等消息。剩下的非幂等消息必须以以下方式或其他类似技术转换为幂等消息：

+   附上时间和一些唯一标识符，以唯一标识每条消息。

+   将所有已接收的消息存储在一个字典中，该字典已由附加到前一点提到的消息的唯一标识符进行索引。

+   拒绝旧消息。

+   当接收到可能是重复的消息时，请验证它是否包含在字典中。如果是，则已经被处理，因此拒绝它。

+   由于旧消息被拒绝，它们可以定期从字典中删除，以避免指数级增长。

我们将在*第六章*的示例中使用这种技术，*Azure Service Fabric*。

值得指出的是，一些消息代理（如 Azure Service Bus）提供了实施先前描述的技术的设施。Azure Service Bus 在“.NET 通信设施”子部分中进行了讨论。

在下一小节中，我们将讨论基于 Docker 的微服务容器化。

## 容器和 Docker

我们已经讨论了具有不依赖于运行环境的微服务的优势：更好的硬件使用、能够将旧软件与新模块混合使用、能够混合使用多个开发堆栈以使用最佳堆栈来实现每个模块等。通过在私有虚拟机上部署每个微服务及其所有依赖项，可以轻松实现与托管环境的独立性。

然而，启动具有其操作系统私有副本的虚拟机需要很长时间，而微服务必须快速启动和停止，以减少负载平衡和故障恢复成本。事实上，新的微服务可能会启动以替换故障的微服务，或者因为它们从一个硬件节点移动到另一个硬件节点以执行负载平衡。此外，为每个微服务实例添加整个操作系统副本将是一个过度的开销。

幸运的是，微服务可以依赖一种更轻量级的技术：容器。容器是一种轻量级虚拟机。它们不会虚拟化整个机器-它们只是虚拟化位于操作系统内核之上的操作系统文件系统级别。它们使用托管机器的操作系统（内核、DLL 和驱动程序），并依赖于操作系统的本机功能来隔离进程和资源，以确保运行的图像的隔离环境。

因此，容器与特定的操作系统绑定，但它们不会遭受在每个容器实例中复制和启动整个操作系统的开销。

在每台主机机器上，容器由运行时处理，该运行时负责从*图像*创建容器，并为每个容器创建一个隔离的环境。最著名的容器运行时是 Docker，它是容器化的*事实上的*标准。

图像是指定放入每个容器的内容以及要在容器外部公开的容器资源（如通信端口）的文件。图像不需要显式指定其完整内容，但可以分层。这样，通过在现有图像之上添加新的软件和配置信息来构建图像。

例如，如果您想将.NET 应用程序部署为 Docker 镜像，只需将软件和文件添加到 Docker 镜像中，然后引用已经存在的.NET Docker 镜像即可。

为了方便图像引用，图像被分组到可能是公共或私有的注册表中。它们类似于 NuGet 或 npm 注册表。Docker 提供了一个公共注册表（[`hub.docker.com/_/registry`](https://hub.docker.com/_/registry)），您可以在其中找到大多数您可能需要在自己的图像中引用的公共图像。然而，每个公司都可以定义私有注册表。例如，Azure 提供了 Microsoft 容器注册表，您可以在其中定义您的私有容器注册表服务：[`azure.microsoft.com/en-us/services/container-registry/`](https://azure.microsoft.com/en-us/services/container-registry/)。在那里，您还可以找到大多数与.NET 相关的图像，您可能需要在您的代码中引用它们。

在实例化每个容器之前，Docker 运行时必须解决所有递归引用。这个繁琐的工作不是每次创建新容器时都执行的，因为 Docker 运行时有一个缓存，它存储与每个输入图像对应的完全组装的图像。

由于每个应用程序通常由几个模块组成，这些模块在不同的容器中运行，Docker 还允许使用称为`.yml`文件的组合文件，指定以下信息：

+   部署哪些图像。

+   如何将每个图像公开的内部资源映射到主机机器的物理资源。例如，如何将 Docker 图像公开的通信端口映射到物理机器的端口。

我们将在本章的* .NET 如何处理微服务？*部分中分析 Docker 图像和`.yml`文件。

Docker 运行时处理单个机器上的图像和容器，但通常，容器化的微服务是部署和负载均衡在由多台机器组成的集群上的。集群由称为**编排器**的软件组成。编排器将在本章的*需要哪些工具来管理微服务？*部分中介绍，并在*第六章*，*Azure 服务织物*和*第七章*，*Azure Kubernetes 服务*中详细描述。

现在我们已经了解了微服务是什么，它们可以解决什么问题以及它们的基本设计原则，我们准备分析何时以及如何在我们的系统架构中使用它们。下一节将分析我们应该何时使用它们。

# 微服务何时有帮助？

回答这个问题需要我们理解微服务在现代软件架构中的作用。我们将在以下两个小节中进行讨论：

+   分层架构和微服务

+   什么时候考虑微服务架构是值得的？

让我们详细了解分层架构和微服务。

## 分层架构和微服务

企业系统通常以逻辑独立的层组织。第一层是与用户交互的层，称为表示层，而最后一层负责存储/检索数据，称为数据层。请求起源于表示层，并通过所有层传递，直到达到数据层，然后返回，反向穿过所有层，直到达到表示层，表示层负责向用户/客户端呈现结果。层不能“跳过”。

每个层从前一层获取数据，处理数据，并将其传递给下一层。然后，它从下一层接收结果并将其发送回前一层。此外，抛出的异常不能跨越层 - 每个层必须负责拦截所有异常并解决它们，或将它们转换为以其前一层语言表达的其他异常。层架构确保每个层的功能与所有其他层的功能完全独立。

例如，我们可以更改数据库引擎而不影响数据层以上的所有层。同样，我们可以完全更改用户界面，即表示层，而不影响系统的其余部分。

此外，每个层实现了不同类型的系统规范。数据层负责系统“必须记住”的内容，表示层负责系统用户交互协议，而中间的所有层实现了领域规则，指定数据如何处理（例如，如何计算员工工资）。通常，数据层和表示层之间只有一个领域规则层，称为业务或应用层。

每个层都“说”不同的语言：数据层“说”所选择的存储引擎的语言，业务层“说”领域专家的语言，表示层“说”用户的语言。因此，当数据和异常从一层传递到另一层时，它们必须被转换为目标层的语言。

关于如何构建分层架构的详细示例将在《第十二章》《理解软件解决方案中的不同领域》的《用例 - 理解用例的领域》部分中给出，该部分专门讨论领域驱动设计。

话虽如此，微服务如何适应分层架构？它们是否适用于所有层的功能还是只适用于某些层？单个微服务是否可以跨越多个层？

最后一个问题最容易回答：是的！实际上，我们已经说过微服务应该在其逻辑边界内存储所需的数据。因此，有些微服务跨越业务和数据层。其他一些微服务负责封装共享数据并保持在数据层中。因此，我们可能有业务层微服务、数据层微服务以及跨越两个层的微服务。那么，表示层呢？

### 表示层

如果在服务器端实现，表示层也可以适应微服务架构。单页应用程序和移动应用程序在客户端机器上运行表示层，因此它们要么直接连接到业务微服务层，要么更常见地连接到公共接口并负责将请求路由到正确的微服务的 API 网关。

在微服务架构中，如果表示层是一个网站，可以使用一组微服务来实现。然而，如果它需要重型的 Web 服务器和/或重型的框架，将它们容器化可能不方便。这个决定还必须考虑到容器化 Web 服务器和系统其余部分之间可能需要硬件防火墙的性能损失。

ASP.NET 是一个轻量级的框架，运行在轻量级的 Kestrel Web 服务器上，因此可以高效地容器化，并用于内部网络应用的微服务。然而，公共高流量的网站需要专用的硬件/软件组件，阻止它们与其他微服务一起部署。实际上，虽然 Kestrel 对于内部网络网站是一个可接受的解决方案，但公共网站需要更完整的 Web 服务器，如 IIS、Apache 或 NGINX。在这种情况下，安全性和负载均衡要求更加紧迫，需要专用的硬件/软件节点和组件。因此，基于微服务的架构通常提供专门的组件来处理与外部世界的接口。例如，在第七章《Azure Kubernetes 服务》中，我们将看到在 Kubernetes 集群中，这个角色由所谓的“入口”扮演。

单体网站可以轻松地分解为负载均衡的较小子网站，而无需使用微服务特定的技术，但是微服务架构可以将所有微服务的优势带入单个 HTML 页面的构建中。更具体地说，不同的微服务可以负责每个 HTML 页面的不同区域。不幸的是，在撰写本文时，使用现有的.NET 技术很难实现类似的场景。

可以在这里找到一个使用基于 ASP.NET 的微服务实现每个 HTML 页面构建的网站的概念验证：[`github.com/Particular/Workshop/tree/master/demos/asp-net-core`](https://github.com/Particular/Workshop/tree/master/demos/asp-net-core)。这种方法的主要限制是微服务仅合作生成生成 HTML 页面所需的数据，而不是生成实际的 HTML 页面。相反，这由一个单体网关处理。实际上，在撰写本文时，诸如 ASP.NET MVC 之类的框架并不提供任何用于分发 HTML 生成的功能。我们将在第十五章《展示 ASP.NET Core MVC》中回到这个例子。

现在我们已经澄清了系统的哪些部分可以从采用微服务中受益，我们准备好陈述在决定如何采用微服务时的规则了。

## 什么时候值得考虑微服务架构？

微服务可以改进业务层和数据层的实现，但是它们的采用也有一些成本：

+   为节点分配实例并对其进行扩展会产生云费用或内部基础设施和许可证的成本。

+   将一个独特的进程分解为更小的通信进程会增加通信成本和硬件需求，特别是如果微服务被容器化。

+   为微服务设计和测试软件需要更多的时间，并增加了工程成本，无论是时间还是复杂性。特别是，使微服务具有弹性并确保它们充分处理所有可能的故障，以及使用集成测试验证这些功能，可能会将开发时间增加一个数量级以上。

那么，什么时候微服务的成本值得使用？有哪些功能必须实现为微服务？

对于第二个问题的粗略答案是：是的，当应用程序在流量和/或软件复杂性方面足够大时。实际上，随着应用程序的复杂性增加和流量增加，我们建议支付与其扩展相关的成本，因为这样可以进行更多的扩展优化，并在开发团队方面更好地处理。我们为此支付的成本很快就会超过采用微服务的成本。

因此，如果细粒度的扩展对我们的应用程序有意义，并且我们能够估计细粒度扩展和开发带来的节省，我们可以轻松计算出一个整体应用程序吞吐量限制，从而使采用微服务变得方便。

微服务的成本也可以通过增加我们产品/服务的市场价值来证明。由于微服务架构允许我们使用针对其使用进行优化的技术来实现每个微服务，因此增加到我们的软件中的质量可能会证明所有或部分微服务的成本。

然而，扩展和技术优化并不是唯一需要考虑的参数。有时候，我们被迫采用微服务架构，无法进行详细的成本分析。

如果负责整个系统的 CI/CD 的团队规模增长过大，这个大团队的组织和协调会导致困难和低效。在这种情况下，最好将整个 CI/CD 周期分解为可以由较小团队负责的独立部分的架构。

此外，由于这些开发成本只能通过大量请求来证明，我们可能有高流量由不同团队开发的独立模块正在处理。因此，扩展优化和减少开发团队之间的交互的需求使得采用微服务架构非常方便。

从这个可以得出结论，如果系统和开发团队增长过快，就需要将开发团队分成较小的团队，每个团队负责一个高效的有界上下文子系统。在类似的情况下，微服务架构很可能是唯一可行的选择。

另一种迫使采用微服务架构的情况是将新的子部分与基于不同技术的遗留子系统集成，因为容器化的微服务是实现遗留系统与新的子部分之间高效交互的唯一方式，以逐步用新的子部分替换遗留子部分。同样，如果我们的团队由具有不同开发堆栈经验的开发人员组成，基于容器化的微服务架构可能成为必需。

在下一节中，我们将分析可用的构建块和工具，以便我们可以实现基于.NET 的微服务。

# .NET 如何处理微服务？

.NET 被设计为一个多平台框架，足够轻量级和快速，以实现高效的微服务。特别是，ASP.NET 是实现文本 REST 和二进制 gRPC API 与微服务通信的理想工具，因为它可以在轻量级 Web 服务器（如 Kestrel）上高效运行，并且本身也是轻量级和模块化的。

整个.NET 框架在设计时就考虑了微服务作为战略部署平台，并提供了用于构建高效轻量级 HTTP 和 gRPC 通信的工具和包，以确保服务的弹性和处理长时间运行的任务。下面的小节描述了一些可以用来实现基于.NET 的微服务架构的不同工具或解决方案。

## .NET 通信设施

微服务需要两种类型的通信渠道。

+   第一种是用于接收外部请求的通信渠道，可以直接接收或通过 API 网关接收。由于可用的 Web 服务标准和工具，HTTP 是外部通信的常用协议。.NET 的主要 HTTP/gRPC 通信工具是 ASP.NET，因为它是一个轻量级的 HTTP/gRPC 框架，非常适合在小型微服务中实现 Web API。我们将在*第十四章*的*使用.NET Core 应用服务导向架构*中详细介绍 ASP.NET 应用程序，该章节专门介绍 HTTP 和 gRPC 服务。.NET 还提供了一种高效且模块化的 HTTP 客户端解决方案，能够池化和重用重型连接对象。此外，`HttpClient`类将在*第十四章*的*使用.NET Core 应用服务导向架构*中详细介绍。

+   第二种是一种不同类型的通信渠道，用于向其他微服务推送更新。实际上，我们已经提到过，由于对其他微服务的阻塞调用形成了复杂的阻塞调用树，因此无法通过正在进行的请求触发微服务之间的通信，这将增加请求的延迟时间，达到不可接受的水平。因此，在使用更新之前不应立即请求更新，并且应在状态发生变化时推送更新。理想情况下，这种通信应该是异步的，以实现可接受的性能。实际上，同步调用会在等待结果时阻塞发送者，从而增加每个微服务的空闲时间。然而，如果通信足够快（低通信延迟和高带宽），那么只将请求放入处理队列然后返回成功通信的确认而不是最终结果的同步通信是可以接受的。发布者/订阅者通信将是首选，因为在这种情况下，发送者和接收者不需要彼此了解，从而增加了微服务的独立性。实际上，对某种类型的通信感兴趣的所有接收者只需要注册以接收特定的*事件*，而发送者只需要发布这些事件。所有的连接工作由一个负责排队事件并将其分发给所有订阅者的服务执行。发布者/订阅者模式将在*第十一章*的*设计模式和.NET 5 实现*中详细描述，以及其他有用的模式。

虽然.NET 没有直接提供可帮助实现异步通信或实现发布者/订阅者通信的客户端/服务器工具，但 Azure 提供了一个类似的服务，即*Azure Service Bus*。Azure Service Bus 通过 Azure Service Bus *队列*处理队列异步通信和通过 Azure Service Bus *主题*处理发布者/订阅者通信。

一旦在 Azure 门户上配置了 Azure Service Bus，您就可以通过`Microsoft.Azure.ServiceBus` NuGet 包中的客户端连接到它，以便发送消息/事件和接收消息/事件。

Azure Service Bus 有两种类型的通信：基于队列和基于主题。在基于队列的通信中，发送者放入队列的每个消息都会被第一个从队列中拉取的接收者从队列中删除。另一方面，基于主题的通信是发布者/订阅者模式的一种实现。每个主题都有多个订阅，可以从每个主题订阅中拉取发送到主题的每个消息的不同副本。

设计流程如下：

1.  定义 Azure Service Bus 的私有命名空间。

1.  获取由 Azure 门户创建的根连接字符串和/或定义具有较少权限的新连接字符串。

1.  定义队列和/或主题，发送者将以二进制格式发送其消息。

1.  为每个主题定义所需订阅的名称。

1.  在基于队列的通信中，发送者将消息发送到一个队列，接收者从同一个队列中拉取消息。每个消息被传递给一个接收者。也就是说，一旦接收者获得对队列的访问权，它就会读取并删除一个或多个消息。

1.  在基于主题的通信中，每个发送者将消息发送到一个主题，而每个接收者从与该主题关联的私有订阅中拉取消息。

Azure Service Bus 还有其他商业替代品，如 NServiceBus、MassTransit、Brighter 和 ActiveMQ。还有一个免费的开源选项：RabbitMQ。RabbitMQ 可以在本地、虚拟机或 Docker 容器中安装。然后，您可以通过`RabbitMQ.Client` NuGet 包中的客户端与其连接。

RabbitMQ 的功能与 Azure Service Bus 提供的功能类似，但您必须处理所有实现细节、执行操作的确认等，而 Azure Service Bus 会处理所有低级操作并为您提供一个更简单的接口。Azure Service Bus 和 RabbitMQ 将在第十一章“设计模式和.NET 5 实现”中与基于发布者/订阅者的通信一起进行描述。

如果微服务发布到 Azure Service Fabric 中，将在下一章（第六章“Azure Service Fabric”）中描述，我们可以使用内置的可靠二进制通信。

通信是弹性的，因为通信原语自动使用重试策略。这种通信是同步的，但这不是一个大的限制，因为 Azure Service Fabric 中的微服务具有内置队列；因此，一旦接收者接收到消息，他们可以将其放入队列中并立即返回，而不会阻塞发送者。

然后，队列中的消息由一个单独的线程处理。这种内置通信的主要限制是它不基于发布者/订阅者模式；发送者和接收者必须相互了解。当这种情况不可接受时，应该使用 Azure Service Bus。我们将在第六章“Azure Service Fabric”中学习如何使用 Service Fabric 的内置通信。

## 弹性任务执行

弹性通信和一般情况下的弹性任务执行可以通过一个名为 Polly 的.NET 库轻松实现，该项目是.NET 基金会的成员之一。Polly 可以通过 Polly NuGet 包获得。

在 Polly 中，您定义策略，然后在这些策略的上下文中执行任务，如下所示：

```cs
var myPolicy = Policy
  .Handle<HttpRequestException>()
  .Or<OperationCanceledException>()
  .Retry(3);
....
....
myPolicy.Execute(()=>{
    //your code here
}); 
```

每个策略的第一部分指定了必须处理的异常。然后，您指定在捕获其中一个异常时要执行的操作。在上述代码中，如果由`HttpRequestException`异常或`OperationCanceledException`异常报告了失败，则`Execute`方法将重试最多三次。

以下是指数重试策略的实现：

```cs
var erPolicy= Policy
    ...
    //Exceptions to handle here
    .WaitAndRetry(6, 
        retryAttempt => TimeSpan.FromSeconds(Math.Pow(2,
            retryAttempt))); 
```

`WaitAndRetry`的第一个参数指定在失败的情况下最多执行六次重试。作为第二个参数传递的 lambda 函数指定下一次尝试之前等待的时间。在这个具体的例子中，这个时间随着尝试次数的增加呈指数增长（第一次重试 2 秒，第二次重试 4 秒，依此类推）。

以下是一个简单的断路器策略：

```cs
var cbPolicy=Policy
    .Handle<SomeExceptionType>()
    .CircuitBreaker(6, TimeSpan.FromMinutes(1)); 
```

在六次失败之后，由于返回了异常，任务将在 1 分钟内无法执行。

以下是 Bulkhead 隔离策略的实现（有关更多信息，请参见“微服务设计原则”部分）：

```cs
Policy
  .Bulkhead(10, 15) 
```

`Execute`方法允许最多 10 个并行执行。进一步的任务被插入到执行队列中。这个队列有一个 15 个任务的限制。如果超过队列限制，将抛出异常。

为了使 Bulkhead 隔离策略正常工作，以及为了使每个策略正常工作，必须通过相同的策略实例触发任务执行；否则，Polly 无法计算特定任务的活动执行次数。

策略可以与`Wrap`方法结合使用：

```cs
var combinedPolicy = Policy
  .Wrap(erPolicy, cbPolicy); 
```

Polly 提供了更多选项，例如用于返回特定类型的任务的通用方法、超时策略、任务结果缓存、定义自定义策略等等。还可以将 Polly 配置为任何 ASP.NET 和.NET 应用程序的依赖注入部分的`HttPClient`定义的一部分。这样，定义弹性客户端就非常简单。

官方 Polly 文档的链接在*进一步阅读*部分中。

## 使用通用主机

每个微服务可能需要运行多个独立的线程，每个线程对接收到的请求执行不同的操作。这些线程需要多个资源，例如数据库连接、通信通道、执行复杂操作的专用模块等等。此外，当微服务由于负载平衡或错误而停止时，必须适当地初始化所有处理线程，并在停止时优雅地停止。

所有这些需求促使.NET 团队构思和实现*托管服务*和*主机*。主机为运行多个任务（称为**托管服务**）提供了适当的环境，并为它们提供资源、公共设置和优雅的启动/停止。

Web 主机的概念主要是为了实现 ASP.NET Core Web 框架，但是从.NET Core 2.1 开始，主机概念扩展到了所有.NET 应用程序。

在撰写本书时，在任何 ASP.NET Core 或 Blazor 项目中，都会自动为您创建一个`Host`，因此您只需要在其他项目类型中手动添加它。

与`Host`概念相关的所有功能都包含在`Microsoft.Extensions.Hosting` NuGet 包中。

首先，您需要使用流畅的接口配置主机，从一个`HostBuilder`实例开始。此配置的最后一步是调用`Build`方法，该方法使用我们提供的所有配置信息组装实际的主机：

```cs
var myHost=new HostBuilder()
    //Several chained calls
    //defining Host configuration
    .Build(); 
```

主机配置包括定义公共资源、定义文件的默认文件夹、从多个来源加载配置参数（JSON 文件、环境变量和传递给应用程序的任何参数）以及声明所有托管服务。

值得指出的是，ASP.NET Core 和 Blazor 项目使用执行`Host`的预配置方法，其中包括前面列出的几个任务。

然后，可以启动主机，这将导致所有托管服务启动：

```cs
host.Start(); 
```

程序在前面的指令上保持阻塞，直到主机关闭。主机可以通过其中一个托管服务或通过调用`awaithost.StopAsync(timeout)`来关闭。这里，`timeout`是一个时间段，定义了等待托管服务正常停止的最长时间。在此时间之后，如果托管服务尚未终止，所有托管服务都将被中止。

通常，微服务关闭的事实是通过在协调器启动微服务时传递的`cancellationToken`来表示的。当微服务托管在 Azure Service Fabric 中时，就会发生这种情况。

因此，在大多数情况下，我们可以使用`RunAsync`或`Run`方法，而不是使用`host.Start()`，可能会传递一个从协调器或操作系统中获取的`cancellationToken`：

```cs
await host.RunAsync(cancellationToken) 
```

这种关闭方式在`cancellationToken`进入取消状态时立即触发。默认情况下，主机在关闭时有 5 秒的超时时间，即一旦请求关闭，它会等待 5 秒钟然后退出。这个时间可以在`ConfigureServices`方法中进行更改，该方法用于声明*托管服务*和其他资源：

```cs
var myHost = new HostBuilder()
    .ConfigureServices((hostContext, services) =>
    {
        services.Configure<HostOptions>(option =>
        {
            option.ShutdownTimeout = System.TimeSpan.FromSeconds(10);
        });
        ....
        ....
        //further configuration
    })
    .Build(); 
```

然而，增加主机超时时间不会增加编排器超时时间，因此如果主机等待时间过长，编排器将终止整个微服务。

如果在`Run`或`RunAsync`中没有显式传递取消令牌，则会自动生成一个取消令牌，并在操作系统通知应用程序即将终止时自动发出信号。这个取消令牌将传递给所有托管服务，以便它们有机会优雅地停止。

托管服务是`IHostedService`接口的实现，其唯一的方法是`StartAsync(cancellationToken)`和`StopAsync(cancellationToken)`。

这两个方法都传递了一个`cancellationToken`。`StartAsync`方法中的`cancellationToken`表示请求了关闭。`StartAsync`方法在执行启动主机所需的所有操作时定期检查这个`cancellationToken`，如果它被触发，主机启动过程将被中止。另一方面，`StopAsync`方法中的`cancellationToken`表示关闭超时已过期。

托管服务可以在用于定义主机选项的同一个`ConfigureServices`方法中声明，如下所示：

```cs
services.AddHostedService<MyHostedService>(); 
```

然而，一些项目模板（如 ASP.NET Core 项目模板）在不同的类中定义了一个`ConfigureServices`方法。如果这个方法接收与`HostBuilder.ConfigureServices`方法中可用的`services`参数相同的参数，那么这将正常工作。

`ConfigureServices`内的大多数声明需要添加以下命名空间：

```cs
using Microsoft.Extensions.DependencyInjection; 
```

通常情况下，不直接实现`IHostedService`接口，而是可以从`BackgroundService`抽象类继承，该抽象类公开了更容易实现的`ExecuteAsync(CancellationToken)`方法，我们可以在其中放置整个服务的逻辑。通过将`cancellationToken`作为参数传递，可以更容易地处理关闭。我们将在*第六章*的示例中查看`IHostedService`的实现，*Azure Service Fabric*。

为了允许托管服务关闭主机，我们需要将`IApplicationLifetime`接口声明为其构造函数参数：

```cs
public class MyHostedService: BackgroundService 
{
    private readonly IHostApplicationLifetime applicationLifetime;
    public MyHostedService(IHostApplicationLifetime applicationLifetime)
    {
        this.applicationLifetime=applicationLifetime;
    }
    protected Task ExecuteAsync(CancellationToken token) 
    {
        ...
        applicationLifetime.StopApplication();
        ...
    }
} 
```

当创建托管服务时，它会自动传递一个`IHostApplicationLifetime`的实现，其中的`StopApplication`方法将触发主机关闭。这个实现是自动处理的，但我们也可以声明自定义资源，其实例将自动传递给所有声明它们为参数的主机服务构造函数。因此，假设我们定义了如下构造函数：

```cs
Public MyClass(MyResource x, IResourceInterface1 y)
{
    ...
} 
```

有几种方法可以定义上述构造函数所需的资源：

```cs
services.AddTransient<MyResource>();
services.AddTransient<IResourceInterface1, MyResource1>();
services.AddSingleton<MyResource>();
services.AddSingleton<IResourceInterface1, MyResource1>(); 
```

当我们使用`AddTransient`时，会创建一个不同的实例，并将其传递给所有需要该类型实例的构造函数。另一方面，使用`AddSingleton`时，会创建一个唯一的实例，并将其传递给所有需要声明类型的构造函数。带有两个泛型类型的重载允许您传递一个接口和实现该接口的类型。这样，构造函数需要接口，并与该接口的具体实现解耦。

如果资源的构造函数包含参数，则这些参数将以递归方式使用在`ConfigureServices`中声明的类型进行自动实例化。这种与资源的交互模式称为**依赖注入**（**DI**），将在*第十一章*的*设计模式和.NET 5 实现*中详细讨论。

`HostBuilder`还有一个方法，我们可以用来定义默认文件夹，也就是用来解析所有.NET 方法中提到的所有相对路径的文件夹：

```cs
.UseContentRoot("c:\\<deault path>") 
```

它还有一些方法，我们可以用来添加日志记录目标：

```cs
.ConfigureLogging((hostContext, configLogging) =>
    {
        configLogging.AddConsole();
        configLogging.AddDebug();
    }) 
```

前面的示例显示了一个基于控制台的日志记录源，但我们也可以使用适当的提供程序记录到 Azure 目标。*进一步阅读*部分包含了一些可以与部署在 Azure Service Fabric 中的微服务一起使用的 Azure 日志记录提供程序的链接。一旦您配置了日志记录，您可以通过在它们的构造函数中添加`ILoggerFactory`或`ILogger<T>`参数来启用托管服务并记录自定义消息。

最后，`HostBuilder`有一些方法，我们可以用来从各种来源读取配置参数：

```cs
.ConfigureHostConfiguration(configHost =>
    {
        configHost.AddJsonFile("settings.json", optional: true);
        configHost.AddEnvironmentVariables(prefix: "PREFIX_");
        configHost.AddCommandLine(args);
    }) 
```

应用程序内部如何使用参数将在*第十五章* *介绍 ASP.NET Core MVC*中更详细地解释，该章节专门讨论 ASP.NET。

## Visual Studio 对 Docker 的支持

Visual Studio 支持创建、调试和部署 Docker 图像。Docker 部署要求我们在开发机器上安装*Windows Docker 桌面*，以便我们可以运行 Docker 图像。下载链接可以在本章开头的*技术要求*部分找到。在开始任何开发活动之前，我们必须确保它已安装并运行（当 Docker 运行时运行时，您应该在窗口通知栏中看到一个 Docker 图标）。

Docker 支持将以一个简单的 ASP.NET MVC 项目来描述。让我们创建一个。要做到这一点，请按照以下步骤：

1.  将项目命名为`MvcDockerTest`。

1.  为简单起见，如果尚未禁用身份验证，请禁用身份验证。

1.  在创建项目时，您可以选择添加 Docker 支持，但请不要勾选 Docker 支持复选框。您可以测试如何在创建项目后添加 Docker 支持。

一旦您的 ASP.NET MVC 应用程序脚手架和运行，右键单击**解决方案资源管理器**中的项目图标，然后选择**添加**，然后选择**容器编排器支持** | **Docker Compose**。

您将会看到一个对话框，询问您选择容器应该使用的操作系统；选择与安装*Windows Docker 桌面*时选择的相同的操作系统。这将不仅启用 Docker 图像的创建，还将创建一个 Docker Compose 项目，帮助您配置 Docker Compose 文件，以便它们同时运行和部署多个 Docker 图像。实际上，如果您向解决方案添加另一个 MVC 项目并为其启用容器编排器支持，新的 Docker 图像将被添加到相同的 Docker Compose 文件中。

启用 Docker Compose 而不仅仅是`Docker`的优势在于，您可以手动`配置`图像在开发机器上的运行方式，以及通过编辑添加到解决方案中的 Docker Compose 文件来映射 Docker 图像端口到外部端口。

如果您的 Docker 运行时已经正确安装并运行，您应该能够从 Visual Studio 运行 Docker 图像。

### 分析 Docker 文件

让我们分析一下由 Visual Studio 创建的 Docker 文件。这是一系列的图像创建步骤。每个步骤都是通过`From`指令来丰富现有的图像，这是一个对已经存在的图像的引用。以下是第一步：

```cs
FROM mcr.microsoft.com/dotnet/aspnet:x.x AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443 
```

第一步使用了由 Microsoft 在 Docker 公共存储库中发布的`mcr.microsoft.com/dotnet/aspnet:x.x` ASP.NET（Core）运行时（其中`x.x`是您项目中选择的 ASP.NET（Core）版本）。

`WORKDIR`命令在将要创建的图像中创建了随后的目录。如果目录尚不存在，则在图像中创建它。两个`EXPOSE`命令声明了图像端口将被暴露到图像外部并映射到实际托管机器的端口。映射的端口在部署阶段通过 Docker 命令的命令行参数或 Docker Compose 文件中决定。在我们的例子中，有两个端口：一个用于 HTTP（80），另一个用于 HTTPS（443）。

这个中间图像由 Docker 缓存，它不需要重新计算，因为它不依赖于我们编写的代码，而只依赖于所选的 ASP.NET（Core）运行时版本。

第二步生成一个不同的图像，不用于部署，而是用于创建将被部署的特定应用程序文件：

```cs
FROM mcr.microsoft.com/dotnet/core/sdk:x  AS build
WORKDIR /src
COPY ["MvcDockerTest/MvcDockerTest.csproj", "MvcDockerTest/"]
RUN dotnet restore MvcDockerTest/MvcDockerTest.csproj
COPY . .
WORKDIR /src/MvcDockerTest
RUN dotnet build MvcDockerTest.csproj -c Release -o /app/build
FROM build AS publish
RUN dotnet publish MvcDockerTest.csproj -c Release -o /app/publish 
```

此步骤从包含我们不需要添加到部署的 ASP.NET SDK 图像开始；这些是用于处理项目代码的。在“构建”图像中创建了新的`src`目录，并使其成为当前图像目录。然后，将项目文件复制到`/src/MvcDockerTest`中。

`RUN`命令在图像上执行操作系统命令。在这种情况下，它调用`dotnet`运行时，要求其恢复先前复制的项目文件引用的 NuGet 包。

然后，`COPY..`命令将整个项目文件树复制到`src`图像目录中。最后，将项目目录设置为当前目录，并要求`dotnet`运行时以发布模式构建项目并将所有输出文件复制到新的`/app/build`目录中。最后，在名为`publish`的新图像中执行`dotnet publish`任务，将发布的二进制文件输出到`/app/publish`中。

最后一步从我们在第一步中创建的图像开始，其中包含 ASP.NET（Core）运行时，并添加在上一步中发布的所有文件：

```cs
FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "MvcDockerTest.dll"] 
```

`ENTRYPOINT`命令指定执行图像所需的操作系统命令。它接受一个字符串数组。在我们的例子中，它接受`dotnet`命令及其第一个命令行参数，即我们需要执行的 DLL。

### 发布项目

如果我们右键单击项目并单击“发布”，将显示几个选项：

+   将图像发布到现有或新的 Web 应用程序（由 Visual Studio 自动创建）

+   发布到多个 Docker 注册表之一，包括私有 Azure 容器注册表，如果尚不存在，可以从 Visual Studio 内部创建

Docker Compose 支持允许您运行和发布多容器应用程序，并添加其他图像，例如可在任何地方使用的容器化数据库。

以下 Docker Compose 文件将两个 ASP.NET 应用程序添加到同一个 Docker 图像中：

```cs
version: '3.4'
services:
  mvcdockertest:
    image: ${DOCKER_REGISTRY-}mvcdockertest
    build:
      context: .
      dockerfile: MvcDockerTest/Dockerfile
  mvcdockertest1:
    image: ${DOCKER_REGISTRY-}mvcdockertest1
    build:
      context: .
      dockerfile: MvcDockerTest1/Dockerfile 
```

上述代码引用了现有的 Docker 文件。任何与环境相关的信息都放在`docker-compose.override.yml`文件中，当从 Visual Studio 启动应用程序时，该文件与`docker-compose.yml`文件合并：

```cs
version: '3.4'
services:
  mvcdockertest:
    environment:
      - ASPNETCORE_ENVIRONMENT=Development
      - ASPNETCORE_URLS=https://+:443;http://+:8 
    ports:
      - "3150:80"
      - "44355:443"
    volumes:
      - ${APPDATA}/Asp.NET/Https:/root/.aspnet/https:ro
  mvcdockertest1:
    environment:
      - ASPNETCORE_ENVIRONMENT=Development
      - ASPNETCORE_URLS=https://+:443;http://+:80
      - ASPNETCORE_HTTPS_PORT=44317
    ports:
      - "3172:80"
      - "44317:443"
    volumes:
      - ${APPDATA}/Asp.NET/Https:/root/.aspnet/https:ro 
```

对于每个图像，该文件定义了一些环境变量，当应用程序启动时，这些变量将在图像中定义，还定义了端口映射和一些主机文件。

主机中的文件直接映射到图像中。每个声明包含主机中的路径，路径在图像中的映射方式以及所需的访问权限。在我们的例子中，使用`volumes`来映射 Visual Studio 使用的自签名 HTTPS 证书。

现在，假设我们想要添加一个容器化的 SQL Server 实例。我们需要像下面这样的指令，分别在`docker-compose.yml`和`docker-compose.override.yml`之间进行拆分：

```cs
sql.data:
  image: mssql-server-linux:latest
  environment:
  - SA_PASSWORD=Pass@word
  - ACCEPT_EULA=Y
  ports:
  - "5433:1433" 
```

在这里，前面的代码指定了 SQL Server 容器的属性，以及 SQL Server 的配置和安装参数。更具体地说，前面的代码包含以下信息：

+   `sql.data`是给容器命名的名称。

+   `image`指定从哪里获取图像。在我们的例子中，图像包含在公共 Docker 注册表中。

+   `environment`指定 SQL Server 所需的环境变量，即管理员密码和接受 SQL Server 许可证。

+   如往常一样，`ports`指定了端口映射。

+   `docker-compose.override.yml`用于在 Visual Studio 中运行图像。

如果您需要为生产环境或测试环境指定参数，可以添加更多的`docker-compose-xxx.override.yml`文件，例如`docker-compose-staging.override.yml`和`docker-compose-production.override.yml`，然后在目标环境中手动启动它们，类似以下代码：

```cs
docker-compose -f docker-compose.yml -f docker-compose-staging.override.yml 
```

然后，您可以使用以下代码销毁所有容器：

```cs
docker-compose -f docker-compose.yml -f docker-compose.test.staging.yml down 
```

虽然`docker-compose`在处理节点集群时的能力有限，但主要用于测试和开发环境。对于生产环境，需要更复杂的工具，我们将在本章后面的*需要哪些工具来管理微服务？*部分中看到。

## Azure 和 Visual Studio 对微服务编排的支持

Visual Studio 具有基于 Service Fabric 平台的微服务应用程序的特定项目模板，您可以在其中定义各种微服务，配置它们，并将它们部署到 Azure Service Fabric，这是一个微服务编排器。Azure Service Fabric 将在*第六章*，*Azure Service Fabric*中详细介绍。

Visual Studio 还具有特定的项目模板，用于定义要部署在 Azure Kubernetes 中的微服务，并且具有用于调试单个微服务的扩展，同时与部署在 Azure Kubernetes 中的其他微服务进行通信。

还提供了用于在开发机器上测试和调试多个通信微服务的工具，无需安装任何 Kubernetes 软件，并且可以使用最少的配置信息自动部署到 Azure Kubernetes 上。

所有用于 Azure Kubernetes 的 Visual Studio 工具将在*第七章*，*Azure Kubernetes Service*中进行描述。

# 需要哪些工具来管理微服务？

在 CI/CD 周期中有效地处理微服务需要一个私有的 Docker 镜像注册表和一个先进的微服务编排器，该编排器能够执行以下操作：

+   在可用的硬件节点上分配和负载均衡微服务

+   监视服务的健康状态，并在发生硬件/软件故障时替换故障服务

+   记录和展示分析数据

+   允许设计师动态更改要分配给集群的硬件节点、服务实例数量等要求

下面的小节描述了我们可以使用的 Azure 设施来存储 Docker 镜像。Azure 中可用的微服务编排器在各自的章节中进行了描述，即*第六章*，*Azure Service Fabric*和*第七章*，*Azure Kubernetes Service*。

## 在 Azure 中定义您的私有 Docker 注册表

在 Azure 中定义您的私有 Docker 注册表很容易。只需在 Azure 搜索栏中键入`Container registries`，然后选择**Container registries**。在出现的页面上，点击**Add**按钮。

将出现以下表单：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_05_01.png)

图 5.1：创建 Azure 私有 Docker 注册表

您选择的名称用于组成整体注册表 URI：<name>.azurecr.io。与往常一样，您可以指定订阅、资源组和位置。**SKU**下拉菜单可让您选择不同级别的服务，这些服务在性能、可用内存和一些其他辅助功能方面有所不同。

无论何时在 Docker 命令或 Visual Studio 发布表单中提到图像名称，都必须在注册表 URI 前加上前缀：<name>.azurecr.io/<my imagename>。

如果使用 Visual Studio 创建了图像，则可以按照发布项目后出现的说明进行发布。否则，您必须使用`docker`命令将它们推送到您的注册表中。

使用与 Azure 注册表交互的 Docker 命令的最简单方法是在计算机上安装 Azure CLI。从[`aka.ms/installazurecliwindows`](https://aka.ms/installazurecliwindows)下载安装程序并执行它。安装了 Azure CLI 后，您可以从 Windows 命令提示符或 PowerShell 使用`az`命令。为了连接到您的 Azure 帐户，您必须执行以下登录命令：

```cs
az login 
```

此命令应启动您的默认浏览器，并引导您完成手动登录过程。

登录到 Azure 帐户后，您可以通过输入以下命令登录到私有注册表：

```cs
az acr login --name {registryname} 
```

现在，假设您在另一个注册表中有一个 Docker 镜像。作为第一步，让我们在本地计算机上拉取镜像：

```cs
docker pull other.registry.io/samples/myimage 
```

如果有几个版本的前面的图像，则将拉取最新版本，因为没有指定版本。可以按如下方式指定图像的版本：

```cs
docker pull other.registry.io/samples/myimage:version1.0 
```

使用以下命令，您应该在本地图像列表中看到`myimage`：

```cs
docker images 
```

然后，使用您想要在 Azure 注册表中分配的路径为图像打上标签：

```cs
docker tag myimage myregistry.azurecr.io/testpath/myimage 
```

名称和目标标签都可以有版本（`:<version name>`）。

最后，使用以下命令将其推送到您的注册表中：

```cs
docker push myregistry.azurecr.io/testpath/myimage 
```

在这种情况下，您可以指定一个版本；否则，将推送最新版本。

通过执行以下命令，您可以使用以下命令从本地计算机中删除图像：

```cs
docker rmi myregistry.azurecr.io/testpath/myimage 
```

# 摘要

在本章中，我们描述了什么是微服务以及它们是如何从模块的概念演变而来的。然后，我们讨论了微服务的优势以及何时值得使用它们，以及它们的设计的一般标准。我们还解释了 Docker 容器是什么，并分析了容器与微服务架构之间的紧密联系。

然后，我们通过描述在.NET 中可用的所有工具来进行更实际的实现，以便我们可以实现基于微服务的架构。我们还描述了微服务所需的基础设施以及 Azure 集群如何提供 Azure Kubernetes 服务和 Azure Service Fabric。

下一章详细讨论了 Azure Service Fabric 编排器。

# 问题

1.  模块概念的双重性质是什么？

1.  缩放优化是微服务的唯一优势吗？如果不是，请列出一些其他优势。

1.  Polly 是什么？

1.  Visual Studio 提供了哪些对 Docker 的支持？

1.  什么是编排器，Azure 上有哪些编排器可用？

1.  为什么基于发布者/订阅者的通信在微服务中如此重要？

1.  什么是 RabbitMQ？

1.  为什么幂等消息如此重要？

# 进一步阅读

以下是 Azure Service Bus 和 RabbitMQ 两种事件总线技术的官方文档链接：

+   **Azure Service Bus**：[`docs.microsoft.com/en-us/azure/service-bus-messaging/`](https://docs.microsoft.com/en-us/azure/service-bus-messaging/)

+   **RabbitMQ**：[`www.rabbitmq.com/getstarted.html`](https://www.rabbitmq.com/getstarted.html)

+   Polly 是一种可靠通信/任务工具，其文档可以在这里找到：[`github.com/App-vNext/Polly`](https://github.com/App-vNext/Polly)。

+   有关 Docker 的更多信息可以在 Docker 的官方网站上找到：[`docs.docker.com/`](https://docs.docker.com/)。

+   Kubernetes 和`.yaml`文件的官方文档可以在这里找到：[`kubernetes.io/docs/home/`](https://kubernetes.io/docs/home/)。

+   Azure Kubernetes 的官方文档可以在这里找到：[`docs.microsoft.com/en-US/azure/aks/`](https://docs.microsoft.com/en-US/azure/aks/)。

+   Azure Service Fabric 的官方文档可以在此处找到：[`docs.microsoft.com/zh-cn/azure/service-fabric/`](https://docs.microsoft.com/zh-cn/azure/service-fabric/)。

+   Azure Service Fabric 可靠服务的官方文档可以在此处找到：[`docs.microsoft.com/zh-cn/azure/service-fabric/service-fabric-reliable-services-introduction`](https://docs.microsoft.com/zh-cn/azure/service-fabric/service-fabric-reliable-services-introduction)。


# 第六章：Azure Service Fabric

本章专门描述了 Azure Service Fabric，它是微软的一种主观的微服务编排器。它在 Azure 上可用，但 Service Fabric 软件也可以下载，这意味着用户可以使用它来定义自己的本地微服务集群。

虽然 Service Fabric 并不像 Kubernetes 那样广泛使用，但它具有更好的学习曲线，使您能够尝试微服务的基本概念，并在很短的时间内构建复杂的解决方案。此外，它提供了一个集成的部署环境，包括您实现完整应用所需的一切。更具体地说，它还提供了集成的通信协议和一种简单可靠的存储状态信息的方式。

在本章中，我们将涵盖以下主题：

+   Visual Studio 对 Azure Service Fabric 应用程序的支持

+   如何定义和配置 Azure Service Fabric 集群

+   如何通过“日志微服务”使用案例来实践编写可靠的服务及其通信

通过本章的学习，您将学会如何基于 Azure Service Fabric 实现一个完整的解决方案。

# 技术要求

在本章中，您将需要以下内容：

+   Visual Studio 2019 免费社区版或更高版本，已安装所有数据库工具和 Azure 开发工作负载。

+   一个免费的 Azure 账户。*第一章*的*理解软件架构的重要性*中的*创建 Azure 账户*部分解释了如何创建账户。

+   在 Visual Studio 中调试微服务时，需要一个用于 Azure Service Fabric 的本地仿真器。它是免费的，可以从[`docs.microsoft.com/en-us/azure/service-fabric/service-fabric-get-started#install-the-sdk-and-tools`](https://docs.microsoft.com/en-us/azure/service-fabric/service-fabric-get-started#install-the-sdk-and)下载。

为了避免安装问题，请确保您的 Windows 版本是最新的。此外，仿真器使用 PowerShell 高特权级命令，默认情况下被 PowerShell 阻止。要启用它们，您需要在 Visual Studio 包管理器控制台或任何 PowerShell 控制台中执行以下命令。为了使以下命令成功，必须以*管理员*身份启动 Visual Studio 或外部 PowerShell 控制台：

```cs
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Force -Scope CurrentUser 
```

## Visual Studio 对 Azure Service Fabric 的支持

Visual Studio 具有针对微服务应用程序的特定项目模板，基于 Service Fabric 平台，您可以在其中定义各种微服务，配置它们，并将它们部署到 Azure Service Fabric，这是一个微服务编排器。Azure Service Fabric 将在下一节中详细介绍。

在本节中，我们将描述在 Service Fabric 应用程序中可以定义的各种类型的微服务。本章最后一节将提供一个完整的代码示例。如果您想在开发机器上调试微服务，您需要安装本章技术要求中列出的 Service Fabric 仿真器。

可以通过在“Visual Studio 项目类型下拉筛选器”中选择**云**来找到 Service Fabric 应用程序：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_06_01.png)

图 6.1：选择 Service Fabric 应用程序

选择项目并选择项目和解决方案名称后，您可以选择多种服务：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_06_02.png)

图 6.2：服务选择

所有基于.NET Core 的项目都使用了针对 Azure Service Fabric 特定的微服务模型。Guest Executable 在现有的 Windows 应用程序周围添加了一个包装器，将其转换为可以在 Azure Service Fabric 中运行的微服务。Container 应用程序允许在 Service Fabric 应用程序中添加任何 Docker 镜像。所有其他选择都提供了一个模板，允许您使用 Service Fabric 特定的模式编写微服务。

如果您选择**无状态服务**并填写所有请求信息，Visual Studio 将创建两个项目：一个包含整个应用程序的配置信息的应用程序项目，以及一个包含您选择的特定服务的服务代码和特定服务配置的项目。如果您想向应用程序添加更多微服务，请右键单击应用程序项目，然后选择**添加** | **新的 Service Fabric 服务**。

如果您右键单击解决方案并选择**添加** | **新项目**，将创建一个新的 Service Fabric 应用程序，而不是将新服务添加到已经存在的应用程序中。

如果您选择**Guest Executable**，您需要提供以下内容：

+   服务名称。

+   一个包含主可执行文件的文件夹，以及为了正常工作而需要的所有文件。如果您想要在项目中创建此文件夹的副本，或者只是链接到现有文件夹，您需要这个。

+   是否要添加一个链接到此文件夹，或者将所选文件夹复制到 Service Fabric 项目中。

+   主可执行文件。

+   要传递给可执行文件的命令行参数。

+   要在 Azure 上使用作为工作文件夹的文件夹。您可以使用包含主可执行文件（`CodeBase`）的文件夹，Azure Service Fabric 将在其中打包整个微服务的文件夹（`CodePackage`），或者命名为`Work`的新子文件夹。

如果您选择**容器**，您需要提供以下内容：

+   服务名称。

+   您私有 Azure 容器注册表中的 Docker 镜像的完整名称。

+   将用于连接到 Azure 容器注册表的用户名。密码将在与用户名自动创建的应用程序配置文件的相同`RepositoryCredentials` XML 元素中手动指定。

+   您可以访问服务的端口（主机端口）以及主机端口必须映射到的容器内部的端口（容器端口）。容器端口必须是在 Dockerfile 中公开并用于定义 Docker 镜像的相同端口。

之后，您可能需要添加进一步的手动配置，以确保您的 Docker 应用程序正常工作。*进一步阅读*部分包含指向官方文档的链接，您可以在其中找到更多详细信息。

有五种.NET Core 本机 Service Fabric 服务类型。Actor 服务模式是由 Carl Hewitt 几年前构思的一种主观模式。我们不会在这里讨论它，但*进一步阅读*部分包含一些提供更多信息的链接。

其余四种模式是指使用（或不使用）ASP.NET（Core）作为主要交互协议，以及服务是否具有内部状态。事实上，Service Fabric 允许微服务使用分布式队列和字典，这些队列和字典对于声明它们的微服务的所有实例都是全局可访问的，与它们运行的硬件节点无关（在需要时它们被序列化和分发到所有可用的实例）。

有状态和无状态模板在配置方面主要有所不同。所有本机服务都是指定了两个方法的类。有状态服务指定：

```cs
protected override IEnumerable<ServiceReplicaListener> CreateServiceReplicaListeners()
protected override async Task RunAsync(CancellationToken cancellationToken) 
```

而无状态服务则需要指定：

```cs
protected override IEnumerable< ServiceInstanceListener > CreateServiceInstanceListeners()
protected override async Task RunAsync(CancellationToken cancellationToken) 
```

`CreateServiceReplicaListeners`和`CreateServiceInstanceListeners`方法指定了微服务用于接收消息和处理这些消息的代码的监听器列表。监听器可以使用任何协议，但它们需要指定相对套接字的实现。

`RunAsync`包含用于异步运行由接收到的消息触发的任务的后台线程的代码。在这里，您可以构建一个运行多个托管服务的主机。

ASP.NET Core 模板遵循相同的模式；但是，它们使用基于 ASP.NET Core 的唯一侦听器和没有`RunAsync`实现，因为可以从 ASP.NET Core 内部启动后台任务，其侦听器定义了一个完整的`WebHost`。但是，您可以将更多侦听器添加到由 Visual Studio 创建的`CreateServiceReplicaListeners`实现返回的侦听器数组中，还可以添加自定义的`RunAsync`覆盖。

值得指出的是，由于`RunAsync`是可选的，并且由于 ASP.NET Core 模板没有实现它，因此`CreateServiceReplicaListeners`和`CreateServiceInstanceListeners`也是可选的，例如，基于计时器的后台工作程序不需要实现它们中的任何一个。

有关 Service Fabric 的本机服务模式的更多详细信息将在下一节中提供，而本章的*用例-日志记录微服务*部分将提供一个完整的代码示例，专门针对本书的用例。

# 定义和配置 Azure Service Fabric 集群

Azure Service Fabric 是主要的微软编排器，可以托管 Docker 容器、本地.NET 应用程序和一种名为**可靠服务**的分布式计算模型。我们已经在*Visual Studio 支持 Azure Service Fabric*部分中解释了如何创建包含这三种类型服务的应用程序。在本节中，我们将解释如何在 Azure 门户中创建 Azure Service Fabric 集群，并提供一些关于可靠服务的详细信息。有关*可靠服务*的更多实际细节将在*用例-日志记录微服务*部分中提供。

您可以通过在 Azure 搜索栏中输入`Service Fabric`并选择**Service Fabric Cluster**来进入 Azure 的 Service Fabric 部分。

显示了所有 Service Fabric 集群的摘要页面，对于您的情况，应该是空的。当您点击**添加**按钮创建第一个集群时，将显示一个多步骤向导。以下小节描述了可用的步骤。

## 第 1 步-基本信息

以下截图显示了 Azure Service Fabric 的创建过程：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_06_03.png)

图 6.3：Azure Service Fabric 创建

在这里，您可以选择操作系统、资源组、订阅、位置以及要用于连接远程桌面到所有集群节点的用户名和密码。

您需要选择一个集群名称，该名称将用于组成集群 URI，格式为`<集群名称>.<位置>.cloudapp.azure.com`，其中`位置`是您选择的数据中心位置的名称。由于 Service Fabric 主要是为 Windows 设计的，所以选择 Windows 是一个更好的选择。对于 Linux 机器来说，更好的选择是 Kubernetes，这将在下一章中介绍。

然后，您需要选择节点类型，即您想要为主节点使用的虚拟机类型，以及初始规模集，即要使用的虚拟机的最大数量。请选择一个廉价的节点类型，最多不超过三个节点，否则您可能很快就会耗尽所有的免费 Azure 信用额。

有关节点配置的更多详细信息将在下一小节中给出。

最后，您可以选择一个证书来保护节点之间的通信。让我们点击**选择证书**链接，在打开的窗口中选择自动创建新密钥保管库和新证书。有关安全性的更多信息将在*第 3 步-安全配置*部分中提供。

## 第 2 步-集群配置

在第二步中，您可以对集群节点类型和数量进行微调：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_06_04.png)

图 6.4：集群配置

更具体地说，在上一步中，我们选择了集群的主节点。在这里，我们可以选择是否添加各种类型的辅助节点及其规模容量。一旦您创建了不同的节点类型，您可以配置服务仅在其需求所需的能力足够的特定节点类型上运行。

让我们点击**添加**按钮来添加一个新的节点类型：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_06_05.png)

图 6.5：添加一个新的节点类型

不同节点类型的节点可以独立进行扩展，**主节点**类型是 Azure Service Fabric 运行时服务的托管位置。对于每个节点类型，您可以指定机器类型（**耐久性层**）、机器规格（CPU 和 RAM）和初始节点数。

您还可以指定所有从集群外部可见的端口（**自定义端点**）。

托管在集群的不同节点上的服务可以通过任何端口进行通信，因为它们是同一本地网络的一部分。因此，**自定义端点**必须声明需要接受来自集群外部的流量的端口。在**自定义端点**中公开的端口是集群的公共接口，可以通过集群 URI（即`<cluster name>.<location>.cloudapp.azure.com`）访问。它们的流量会自动重定向到由集群负载均衡器打开相同端口的所有微服务。

要理解**启用反向代理**选项，我们必须解释在服务的物理地址在其生命周期中发生变化时，如何将通信发送到多个实例。在集群内部，服务通过`fabric://<application name>/<service name>`这样的 URI 进行标识。也就是说，这个名称允许我们访问`<service name>`的多个负载均衡实例之一。然而，这些 URI 不能直接用于通信协议。相反，它们用于从 Service Fabric 命名服务获取所需资源的物理 URI，以及其所有可用的端口和协议。

稍后，我们将学习如何使用*可靠服务*执行此操作。然而，对于没有专门为 Azure Service Fabric 运行而设计的 Docker 化服务来说，这个模型是不合适的，因为它们不知道 Service Fabric 特定的命名服务和 API。

因此，Service Fabric 提供了另外两个选项，我们可以使用它们来标准化 URL，而不是直接与其命名服务交互：

+   **DNS**：每个服务可以指定其`hostname`（也称为**DNS 名称**）。DNS 服务负责将其转换为实际的服务 URL。例如，如果一个服务指定了一个`order.processing`的 DNS 名称，并且它在端口`80`上有一个 HTTP 端点和一个`/purchase`路径，我们可以使用`http://order.processing:80/purchase`来访问此端点。默认情况下，DNS 服务是活动的，但您可以通过在辅助节点屏幕上点击**配置高级设置**来显示高级设置选择，或者转到**高级**选项卡来禁用它。

+   **反向代理**：Service Fabric 的反向代理拦截所有被定向到集群地址的调用，并使用名称服务将它们发送到正确的应用程序和该应用程序中的服务。由反向代理服务解析的地址具有以下结构：`<cluster name>.<location>.cloudapp.azure.com: <port>//<app name>/<service name>/<endpoint path>?PartitionKey=<value>& PartitionKind=value`。在这里，分区键用于优化有状态的可靠服务，并将在本小节末尾进行解释。这意味着无状态服务缺少前一个地址的查询字符串部分。因此，由反向代理解析的典型地址可能类似于`myCluster.eastus.cloudapp.azure.com: 80//myapp/myservice/<endpoint path>?PartitionKey=A & PartitionKind=Named`。如果从同一集群上托管的服务调用前面的端点，我们可以指定`localhost`而不是完整的集群名称（即从同一集群，而不是从同一节点）：`localhost: 80//myapp/myservice/<endpoint path>?PartitionKey=A & PartitionKind=Named`。默认情况下，反向代理未启用。

由于我们将使用 Service Fabric 可靠服务与 Service Fabric 内置通信设施，并且由于这些内置通信设施不需要反向代理或 DNS，请避免更改这些设置。

此外，如果您只是为了在本章末尾的简单示例中进行实验而创建 Service Fabric 集群，请仅使用主节点，并避免通过创建辅助节点来浪费您的免费 Azure 信用。

## 第 3 步-安全配置

完成第二步后，我们来到一个安全页面：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_06_06.png)

图 6.6：安全页面

在第一步中，我们已经定义了主要的证书。在这里，您可以选择一个次要的证书，在主要证书接近到期时使用。您还可以添加一个证书，用于在反向代理上启用 HTTPS 通信。由于在我们的示例中，我们不使用 Docker 化服务（因此不需要反向代理），所以我们不需要这个选项。

在这一点上，我们可以点击“审查和创建”按钮来创建集群。提交您的批准将创建集群。请注意：一个集群可能会在短时间内消耗您的免费 Azure 信用，所以在测试时请保持您的集群开启。之后，您应该删除它。

我们需要将主要证书下载到开发机器上，因为我们需要它来部署我们的应用程序。一旦证书下载完成，只需双击它即可将其安装在我们的机器上。在部署应用程序之前，您需要将以下信息插入到 Visual Studio Service Fabric 应用程序的**Cloud Publish Profile**中（有关更多详细信息，请参见本章的*用例-日志记录微服务*部分）：

```cs
<ClusterConnectionParameters 
    ConnectionEndpoint="<cluster name>.<location 
    code>.cloudapp.azure.com:19000"
    X509Credential="true"
    ServerCertThumbprint="<server certificate thumbprint>"
    FindType="FindByThumbprint"
    FindValue="<client certificate thumbprint>"
    StoreLocation="CurrentUser"
    StoreName="My" /> 
```

由于客户端（Visual Studio）和服务器使用相同的证书进行身份验证，因此服务器和客户端的指纹是相同的。证书指纹可以从 Azure 密钥保管库中复制。值得一提的是，您还可以通过在*第 3 步*中选择相应的选项来将特定于客户端的证书添加到主服务器证书中。

正如我们在*Visual Studio 对 Azure Service Fabric 的支持*小节中提到的，Azure Service Fabric 支持两种类型的*可靠服务*：无状态和有状态。无状态服务要么不存储永久数据，要么将其存储在外部支持中，例如 Redis 缓存或数据库（有关 Azure 提供的主要存储选项，请参见*第九章*，*如何选择云中的数据存储*）。

另一方面，有状态服务使用 Service Fabric 特定的分布式字典和队列。每个分布式数据结构可以从服务的所有*相同*副本中访问，但只允许一个副本，称为主副本，在其上进行写操作，以避免对这些分布式资源的同步访问，这可能会导致瓶颈。

所有其他副本，即辅助副本，只能从这些分布式数据结构中读取。

您可以通过查看您的代码从 Azure Service Fabric 运行时接收到的上下文对象来检查副本是否为主副本，但通常情况下，您不需要这样做。实际上，当您声明服务端点时，您需要声明那些只读的端点。只读端点应该接收请求，以便它可以从共享数据结构中读取数据。因此，由于只有只读端点被激活用于辅助副本，如果您正确实现了它们，写/更新操作应该自动在有状态辅助副本上被阻止，无需进行进一步的检查。

在有状态服务中，辅助副本可以在读操作上实现并行处理，因此为了在写/更新操作上实现并行处理，有状态服务被分配了不同的数据分区。具体来说，对于每个有状态服务，Service Fabric 会为每个分区创建一个主实例。然后，每个分区可能有多个辅助副本。

分布式数据结构在每个分区的主实例和其辅助副本之间共享。可以根据对要存储的数据进行哈希算法生成的分区键将有状态服务中可以存储的全部数据范围划分为所选的分区数。

通常，分区键是属于给定间隔的整数，该间隔在所有可用分区之间进行划分。例如，可以通过调用一个众所周知的哈希算法对一个或多个字符串字段进行哈希运算来生成分区键，以获得然后处理为唯一整数的整数（例如，对整数位进行异或运算）。然后，可以通过取整数除法的余数来限制该整数在选择的分区键的整数间隔中（例如，除以 1,000 的余数将是 0-999 间隔中的整数）。确保所有服务使用完全相同的哈希算法非常重要，因此更好的解决方案是为所有服务提供一个公共的哈希库。

假设我们想要四个分区，这些分区将在 0-999 的整数键中进行选择。在这里，Service Fabric 将自动创建我们有状态服务的四个主实例，并将它们分配给以下四个分区键子区间：0-249，250-499，500-749 和 750-999。

在代码中，您需要计算发送到有状态服务的数据的分区键。然后，Service Fabric 的运行时将为您选择正确的主实例。下面的部分将提供更多关于此的实际细节以及如何在实践中使用可靠服务。

# 用例 - 日志微服务

在本节中，我们将看一个基于微服务的系统，该系统记录与我们的 WWTravelClub 用例中的各个目的地相关的购买数据。特别是，我们将设计微服务来计算每个位置的每日收入。在这里，我们假设这些微服务从同一 Azure Service Fabric 应用程序中托管的其他子系统接收数据。具体来说，每个购买日志消息由位置名称、总体套餐费用以及购买日期和时间组成。

首先，让我们确保我们在本章*技术要求*部分提到的 Service Fabric 模拟器已经安装并在您的开发机器上运行。现在，我们需要将其切换，以便它运行**5 个节点**：右键单击您在 Windows 通知区域中拥有的小 Service Fabric 集群图标，在打开的上下文菜单中，选择**切换集群模式** -> **5 个节点**。

现在，我们可以按照*Visual Studio 对 Azure Service Fabric 的支持*部分中列出的步骤来创建一个名为`PurchaseLogging`的 Service Fabric 项目。选择一个.NET Core 有状态可靠服务，并将其命名为`LogStore`。

由 Visual Studio 创建的解决方案由一个代表整体应用程序的`PurchaseLogging`项目和一个包含在`PurchaseLogging`应用程序中的第一个微服务的实现的`LogStore`项目组成。

在`PackageRoot`文件夹下，`LogStore`服务和每个可靠服务都包含`ServiceManifest.xml`配置文件和一个`Settings.xml`文件夹（在`Config`子文件夹下）。`Settings.xml`文件夹包含一些将从服务代码中读取的设置。初始文件包含了 Service Fabric 运行时所需的预定义设置。让我们添加一个新的`Settings`部分，如下面的代码所示：

```cs
<?xml version="1.0" encoding="utf-8" ?>
<Settings xmlns:xsd="http://www.w3.org/2001/XMLSchema" 
          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
          xmlns="http://schemas.microsoft.com/2011/01/fabric">
<!-- This is used by the StateManager's replicator. -->
<Section Name="ReplicatorConfig">
<Parameter Name="ReplicatorEndpoint" Value="ReplicatorEndpoint" />
</Section>
<!-- This is used for securing StateManager's replication traffic. -->
<Section Name="ReplicatorSecurityConfig" />
<!-- Below the new Section to add -->
<Section Name="Timing">
<Parameter Name="MessageMaxDelaySeconds" Value="" />
</Section>
</Settings> 
```

我们将使用`MessageMaxDelaySeconds`的值来配置系统组件，并确保消息的幂等性。设置值为空，因为大多数设置在服务部署时会被`PurchaseLogging`项目中包含的整体应用程序设置所覆盖。

`ServiceManifest.xml`文件包含了一些由 Visual Studio 自动处理的配置标签，以及一些端点的列表。由于这些端点被 Service Fabric 运行时使用，因此有两个端点是预配置的。在这里，我们必须添加我们的微服务将监听的所有端点的配置细节。每个端点定义的格式如下：

```cs
<Endpoint Name="<endpoint name>" PathSuffix="<the path of the endpoint URI>" Protocol="<a protcol like Tcp, http, https, etc.>" Port="the exposed port" Type="<Internal or Input>"/> 
```

如果`Type`是`Internal`，则端口将仅在集群的本地网络中打开；否则，端口也将从集群外部可用。在前一种情况下，我们还必须在 Azure Service Fabric 集群的配置中声明该端口，否则集群负载均衡器/防火墙将无法将消息转发到该端口。

公共端口可以直接从集群 URI(`<cluster name>.<location code>.cloudapp.azure.com`)到达，因为每个集群的负载均衡器将把接收到的输入流量转发到它们。

在这个例子中，我们不会定义端点，因为我们将使用预定义的基于远程通信，但我们将在本节的后面向您展示如何使用它们。

`PurchaseLogging`项目在*services*解决方案资源管理器节点下包含对`LogStore`项目的引用，并包含各种包含各种 XML 配置文件的文件夹。具体来说，我们有以下文件夹：

+   `ApplicationPackageRoot`包含名为`ApplicationManifest.xml`的整体应用程序清单。该文件包含一些初始参数定义，然后进行进一步的配置。参数的格式如下：

```cs
<Parameter Name="<parameter name>" DefaultValue="<parameter definition>" /> 
```

+   一旦定义，参数可以替换文件的其余部分中的任何值。参数值通过将参数名称括在方括号中来引用，如下面的代码所示：

```cs
<UniformInt64Partition PartitionCount="[LogStore_PartitionCount]" LowKey="0" HighKey="1000" /> 
```

一些参数定义了每个服务的副本和分区的数量，并且由 Visual Studio 自动创建。让我们用以下代码片段中的值替换 Visual Studio 建议的这些初始值：

```cs
<Parameter Name="LogStore_MinReplicaSetSize" DefaultValue="1" />
<Parameter Name="LogStore_PartitionCount" DefaultValue="2" />
<Parameter Name="LogStore_TargetReplicaSetSize" DefaultValue="1" /> 
```

我们将使用两个分区来展示分区是如何工作的，但您可以增加此值以提高写入/更新并行性。`LogStore`服务的每个分区不需要多个副本，因为副本可以提高读取操作的性能，而此服务并非设计为提供读取服务。在类似情况下，您可以选择两到三个副本，使系统具有冗余性并更加健壮。但是，由于这只是一个示例，我们不关心故障，所以我们只留下一个。

前述参数用于定义整个应用程序中`LogStore`服务的角色。此定义是由 Visual Studio 在同一文件中自动生成的，位于 Visual Studio 创建的初始定义下方，只是分区间隔更改为 0-1,000：

```cs
<Service Name="LogStore" ServicePackageActivationMode="ExclusiveProcess">
<StatefulService ServiceTypeName="LogStoreType" 
    TargetReplicaSetSize=
    "[LogStore_TargetReplicaSetSize]" 
    MinReplicaSetSize="[LogStore_MinReplicaSetSize]">
<UniformInt64Partition PartitionCount="
        [LogStore_PartitionCount]" 
        LowKey="0" HighKey="1000" />
</StatefulService>
</Service> 
```

+   `ApplicationParameters`包含在各种部署环境（即实际的 Azure Service Fabric 集群和具有一个或五个节点的本地仿真器）中为`ApplicationManifest.xml`中定义的参数提供可能的覆盖。

+   `PublishProfiles`包含发布应用程序所需的设置，这些设置与`ApplicationParameters`文件夹处理的相同环境相关。您只需要使用实际的 Azure Service Fabric URI 名称和在 Azure 集群配置过程中下载的身份验证证书来自定义云发布配置文件：

```cs
<ClusterConnectionParameters 
    ConnectionEndpoint="<cluster name>.<location 
    code>.cloudapp.azure.com:19000"
    X509Credential="true"
    ServerCertThumbprint="<server certificate thumbprint>"
    FindType="FindByThumbprint"
    FindValue="<client certificate thumbprint>"
    StoreLocation="CurrentUser"
    StoreName="My" /> 
```

需要遵循的其余步骤已经组织成几个子部分。让我们首先看看如何确保消息的幂等性。

## 确保消息的幂等性

由于故障或负载平衡引起的小超时，消息可能会丢失。在这里，我们将使用预定义的基于远程通信的通信，以在发生故障时执行自动消息重试。但是，这可能导致相同的消息被接收两次。由于我们正在对采购订单的收入进行汇总，因此必须防止多次对同一采购进行汇总。

为此，我们将实现一个包含必要工具的库，以确保消息副本被丢弃。

让我们向解决方案添加一个名为**IdempotencyTools**的新的.NET Standard 2.0 库项目。现在，我们可以删除 Visual Studio 生成的初始类。该库需要引用与`LogStore`引用的`Microsoft.ServiceFabric.Services` NuGet 包相同版本，因此让我们验证版本号并将相同的 NuGet 包引用添加到`IdempotencyTools`项目中。

确保消息幂等性的主要工具是`IdempotentMessage`类：

```cs
using System;
using System.Runtime.Serialization;
namespace IdempotencyTools
{
    [DataContract]
    public class IdempotentMessage<T>
    {
        [DataMember]
        public T Value { get; protected set; }
        [DataMember]
        public DateTimeOffset Time { get; protected set; }
        [DataMember]
        public Guid Id { get; protected set; }
        public IdempotentMessage(T originalMessage)
        {
            Value = originalMessage;
            Time = DateTimeOffset.Now;
            Id = Guid.NewGuid();
        }
    }
} 
```

我们添加了`DataContract`和`DataMember`属性，因为它们是我们将用于所有内部消息的远程通信序列化器所需的。基本上，前述类是一个包装器，它向传递给其构造函数的消息类实例添加了`Guid`和时间标记。

`IdempotencyFilter`类使用分布式字典来跟踪它已经收到的消息。为了避免这个字典的无限增长，较旧的条目会定期删除。在字典中找不到的太旧的消息会自动丢弃。

时间间隔条目保存在字典中，并在`IdempotencyFilter`静态工厂方法中传递，该方法创建新的过滤器实例，以及字典名称和`IReliableStateManager`实例，这些都是创建分布式字典所需的：

```cs
public class IdempotencyFilter
{
    protected IReliableDictionary<Guid, DateTimeOffset> dictionary;
    protected int maxDelaySeconds;
    protected DateTimeOffset lastClear;
    protected IReliableStateManager sm;
    protected IdempotencyFilter() { }
    public static async Task<IdempotencyFilter> NewIdempotencyFilter(
        string name, 
        int maxDelaySeconds, 
        IReliableStateManager sm)
    {
        return new IdempotencyFilter()
            {
                dictionary = await
                sm.GetOrAddAsync<IReliableDictionary<Guid,
                DateTimeOffset>>(name),
                maxDelaySeconds = maxDelaySeconds,
                lastClear = DateTimeOffset.UtcNow,
                sm = sm,
            };
}
...
... 
```

字典包含每条消息的时间标记，由消息`Guid`索引，并通过调用`IReliableStateManager`实例的`GetOrAddAsync`方法以字典类型和名称创建。`lastClear`包含删除所有旧消息的时间。

当新消息到达时，`NewMessage`方法会检查是否必须丢弃该消息。如果必须丢弃消息，则返回`null`；否则，将新消息添加到字典中，并返回不带`IdempotentMessage`包装的消息：

```cs
public async Task<T> NewMessage<T>(IdempotentMessage<T> message)
{
    DateTimeOffset now = DateTimeOffset.Now;
    if ((now - lastClear).TotalSeconds > 1.5 * maxDelaySeconds)
    {
        await Clear();
    }
    if ((now - message.Time).TotalSeconds > maxDelaySeconds)
        return default(T);
    using (var tx = this.sm.CreateTransaction())
    {
        ...
        ...
    }
 } 
```

首先，该方法验证是否是清除字典的时间以及消息是否太旧。然后，它启动事务以访问字典。所有分布式字典操作都必须包含在事务中，如下面的代码所示：

```cs
using (ITransaction tx = this.sm.CreateTransaction())
{
    if (await dictionary.TryAddAsync(tx, message.Id, message.Time))
    {
         await tx.CommitAsync();
         return message.Value;
    }
    else
    {
         return default;
    }
} 
```

如果在字典中找到消息`Guid`，则事务将被中止，因为不需要更新字典，并且该方法返回`default(T)`，实际上是`null`，因为不必处理消息。否则，将消息条目添加到字典中，并返回未包装的消息。

`Clear`方法的代码可以在与本书关联的 GitHub 存储库中找到。

## 交互库

有一些类型必须在所有微服务之间共享。如果内部通信是使用远程调用或 WCF 实现的，每个微服务必须公开一个接口，其中包含其他微服务调用的所有方法。这些接口必须在所有微服务之间共享。此外，对于所有通信接口，实现消息的类也必须在所有微服务之间共享（或在它们的一些子集之间共享）。因此，所有这些结构都在外部库中声明，并由微服务引用。

现在，让我们向我们的解决方案添加一个名为`Interactions`的新的.NET Standard 2.0 库项目。由于此库必须使用`IdempotentMessage`泛型类，因此我们必须将其添加为对`IdempotencyTools`项目的引用。我们还必须添加对包含在`Microsoft.ServiceFabric.Services.Remoting` NuGet 包中的远程通信库的引用，因为用于公开微服务远程方法的所有接口必须继承自此包中定义的`IService`接口。

`IService`是一个空接口，声明了继承接口的通信角色。`Microsoft.ServiceFabric.Services.Remoting` NuGet 包的版本必须与其他项目中声明的`Microsoft.ServiceFabric.Services`包的版本匹配。

以下代码显示了需要由`LogStore`类实现的接口声明：

```cs
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using IdempotencyTools;
using Microsoft.ServiceFabric.Services.Remoting;
namespace Interactions
{
    public interface ILogStore: IService
    {
        Task<bool> LogPurchase(IdempotentMessage<PurchaseInfo>
        idempotentMessage);
    }
} 
```

以下是`PurchaseInfo`消息类的代码，该类在`ILogStore`接口中被引用：

```cs
using System;
using System.Collections.Generic;
using System.Runtime.Serialization;
using System.Text;
namespace Interactions
{
    [DataContract]
    public class PurchaseInfo
    {
        [DataMember]
        public string Location { get; set; }
        [DataMember]
        public decimal Cost { get; set; }
        [DataMember]
        public DateTimeOffset Time { get; set; }
    }
} 
```

现在，我们准备实现我们的主要`LogStore`微服务。

## 实现通信接收端

要实现`LogStore`微服务，我们必须添加对`Interaction`库的引用，该库将自动创建对远程库和`IdempotencyTools`项目的引用。

然后，`LogStore`类必须实现`ILogStore`接口：

```cs
internal sealed class LogStore : StatefulService, ILogStore
...
...
private IReliableQueue<IdempotentMessage<PurchaseInfo>> LogQueue;
public async Task<bool>
    LogPurchase(IdempotentMessage<PurchaseInfo> idempotentMessage)
{
    if (LogQueue == null) return false;
    using (ITransaction tx = this.StateManager.CreateTransaction())
    {
        await LogQueue.EnqueueAsync(tx, idempotentMessage);
        await tx.CommitAsync();
        return true;
    }
} 
```

一旦服务从远程运行时接收到`LogPurchase`调用，它将消息放入`LogQueue`中，以避免调用者保持阻塞，等待消息处理完成。通过这种方式，我们既实现了同步消息传递协议的可靠性（调用者知道消息已被接收），又实现了异步消息处理的性能优势，这是异步通信的典型特点。

作为所有分布式集合的最佳实践，`LoqQueue`在`RunAsync`方法中创建，因此如果第一个调用在 Azure Service Fabric 运行时调用`RunAsync`之前到达，则`LogQueue`可能为空。在这种情况下，该方法返回`false`以表示服务尚未准备好，发送方将稍等一会然后重新发送消息。否则，将创建事务以将新消息加入队列。

然而，如果我们不提供一个返回服务想要激活的所有监听器的`CreateServiceReplicaListeners()`的实现，我们的服务将不会接收任何通信。在远程通信的情况下，有一个预定义的方法来执行整个工作，所以我们只需要调用它：

```cs
protected override IEnumerable<ServiceReplicaListener>
    CreateServiceReplicaListeners()
{
    return this.CreateServiceRemotingReplicaListeners<LogStore>();
} 
```

在这里，`CreateServiceRemotingReplicaListeners`是在远程通信库中定义的扩展方法。它为主副本和辅助副本（用于只读操作）创建监听器。在创建客户端时，我们可以指定它的通信是针对主副本还是辅助副本。

如果您想使用不同的监听器，您必须创建`ServiceReplicaListener`实例的`IEnumerable`。对于每个监听器，您必须使用三个参数调用`ServiceReplicaListener`构造函数：

+   一个接收可靠服务上下文对象作为输入并返回`ICommunicationListener`接口实现的函数。

+   监听器的名称。当服务有多个监听器时，这第二个参数就变得必须。

+   一个布尔值，如果监听器必须在辅助副本上激活，则为 true。

例如，如果我们想要添加自定义和 HTTP 监听器，代码就会变成以下的样子：

```cs
return new ServiceReplicaListener[]
{
    new ServiceReplicaListener(context =>
    new MyCustomHttpListener(context, "<endpoint name>"),
    "CustomWriteUpdateListener", true),
    new ServiceReplicaListener(serviceContext =>
    new KestrelCommunicationListener(serviceContext, "<endpoint name>",
    (url, listener) =>
        {
           ...
        })
        "HttpReadOnlyListener",
    true)
}; 
```

`MyCustomHttpListener`是`ICommunicationListener`的自定义实现，而`KestrelCommunicationListener`是基于 Kestrel 和 ASP.NET Core 的预定义 HTTP 监听器。以下是定义`KestrelCommunicationListener`监听器的完整代码：

```cs
new ServiceReplicaListener(serviceContext =>
new KestrelCommunicationListener(serviceContext, "<endpoint name>", (url, listener) =>
{
    return new WebHostBuilder()
    .UseKestrel()
    .ConfigureServices(
        services => services
        .AddSingleton<StatefulServiceContext>(serviceContext)
        .AddSingleton<IReliableStateManager>(this.StateManager))
    .UseContentRoot(Directory.GetCurrentDirectory())
    .UseStartup<Startup>()
    .UseServiceFabricIntegration(listener, 
    ServiceFabricIntegrationOptions.UseUniqueServiceUrl)
    .UseUrls(url)
    .Build();
})
"HttpReadOnlyListener",
true) 
```

`ICommunicationListener`的实现也必须有一个`Close`方法，它必须关闭已打开的通信通道，以及一个`Abort`方法，它必须**立即**关闭通信通道（不优雅地，也就是说，不通知连接的客户端等）。

现在我们已经打开了通信，我们可以实现服务逻辑。

## 实现服务逻辑

服务逻辑由在`RunAsync`被 Service Fabric 运行时启动的独立线程执行。当您只需要实现一个任务时，创建`IHost`并将所有任务设计为`IHostedService`实现是一个好的做法。事实上，`IHostedService`实现是独立的软件块，更容易进行单元测试。`IHost`和`IHostedService`在*使用通用主机*的*第五章*的*将微服务架构应用于企业应用程序*的子章节中有详细讨论。

在本节中，我们将实现计算每个位置的日收入的逻辑，这个逻辑位于名为`ComputeStatistics`的`IHostedservice`中，它使用一个分布式字典，其键是位置名称，值是一个名为`RunningTotal`的类的实例。这个类存储当前的运行总数和正在计算的日期：

```cs
namespace LogStore
{
    public class RunningTotal
    {
        public DateTime Day { get; set; }
        public decimal Count { get; set; }
        public RunningTotal 
                Update(DateTimeOffset time, decimal value)
        {
            ...
        }
    }
} 
```

这个类有一个`Update`方法，当接收到新的购买消息时更新实例。首先，传入消息的时间被标准化为世界标准时间。然后，这个时间的日期部分被提取出来，并与运行总数的当前`Day`进行比较，如下面的代码所示：

```cs
public RunningTotal Update(DateTimeOffset time, decimal value)
        {
            var normalizedTime = time.ToUniversalTime();
            var newDay = normalizedTime.Date;           
           ... 
           ...
        } 
```

如果是新的一天，我们假设前一天的运行总数计算已经完成，所以`Update`方法将它返回到一个新的`RunningTotal`实例中，并重置`Day`和`Count`，以便它可以计算新一天的运行总数。否则，新值将被添加到运行的`Count`中，并且该方法返回`null`，表示当天的总数还没有准备好。这个实现可以在下面的代码中看到：

```cs
public RunningTotal Update(DateTimeOffset time, decimal value)
{
    ...
    ...
    var result = newDay > Day && Day != DateTime.MinValue ? 
    new RunningTotal
    {
        Day=Day,
        Count=Count
    } 
    : null;
    if(newDay > Day) Day = newDay;
    if (result != null) Count = value;
    else Count += value;
    return result;
} 
```

`ComputeStatistics`的`IHostedService`实现需要一些参数才能正常工作，如下所示：

+   包含所有传入消息的队列

+   `IReliableStateManager`服务，这样它就可以创建分布式字典来存储数据

+   `ConfigurationPackage`服务，以便它可以读取在`Settings.xml`服务文件中定义的设置，以及可能在应用程序清单中被覆盖的设置

在通过依赖注入由`IHost`创建`ComputeStatistics`实例时，必须将前面的参数传递给`ComputeStatistics`构造函数。我们将在下一小节中回到`IHost`的定义。现在，让我们专注于`ComputeStatistics`构造函数及其字段：

```cs
namespace LogStore
{
    public class ComputeStatistics : BackgroundService
    {
        IReliableQueue<IdempotentMessage<PurchaseInfo>> queue;
        IReliableStateManager stateManager;
        ConfigurationPackage configurationPackage;
        public ComputeStatistics(
            IReliableQueue<IdempotentMessage<PurchaseInfo>> queue,
            IReliableStateManager stateManager,
            ConfigurationPackage configurationPackage)
        {
            this.queue = queue;
            this.stateManager = stateManager;
            this.configurationPackage = configurationPackage;
        } 
```

所有构造函数参数都存储在私有字段中，以便在调用`ExecuteAsync`时可以使用它们：

```cs
protected async override Task ExecuteAsync(CancellationToken stoppingToken)
{
    bool queueEmpty = false;
    var delayString=configurationPackage.Settings.Sections["Timing"]
        .Parameters["MessageMaxDelaySeconds"].Value;
    var delay = int.Parse(delayString);
    var filter = await IdempotencyFilter.NewIdempotencyFilterAsync(
        "logMessages", delay, stateManager);
    var store = await
        stateManager.GetOrAddAsync<IReliableDictionary<string, RunningTotal>>("partialCount");
....
... 
```

在进入循环之前，`ComputeStatistics`服务准备一些结构和参数。它声明队列不为空，意味着可以开始出队消息。然后，它从服务设置中提取`MessageMaxDelaySeconds`并将其转换为整数。这个参数的值在`Settings.xml`文件中为空。现在，是时候覆盖它并在`ApplicationManifest.xml`中定义其实际值了：

```cs
<ServiceManifestImport>
<ServiceManifestRef ServiceManifestName="LogStorePkg" ServiceManifestVersion="1.0.0" />
<!--code to add start -->
<ConfigOverrides>
<ConfigOverride Name="Config">
<Settings>
<Section Name="Timing">
<Parameter Name="MessageMaxDelaySeconds" Value="[MessageMaxDelaySeconds]" />
</Section>
</Settings>
</ConfigOverride>
</ConfigOverrides>
<!--code to add end-->
</ServiceManifestImport> 
```

`ServiceManifestImport`将服务清单导入应用程序并覆盖一些配置。每当更改其内容和/或服务定义并重新部署到 Azure 时，必须更改其版本号，因为版本号更改告诉 Service Fabric 运行时在群集中要更改什么。版本号还出现在其他配置设置中。每当它们所引用的实体发生更改时，必须更改它们。

`MessageMaxDelaySeconds`与已接收消息的字典的名称以及`IReliableStateManager`服务的实例一起传递给幂等性过滤器的实例。最后，创建用于存储累计总数的主分布式字典。

之后，服务进入循环，并在`stoppingToken`被标记时结束，即当 Service Fabric 运行时发出信号表示服务将被停止时：

```cs
while (!stoppingToken.IsCancellationRequested)
    {
        while (!queueEmpty && !stoppingToken.IsCancellationRequested)
        {
            RunningTotal total = null;
            using (ITransaction tx = stateManager.CreateTransaction())
            {
                ...
                ... 
                ...
            }
        }
        await Task.Delay(100, stoppingToken);
        queueEmpty = false;
    }
} 
```

内部循环运行直到队列变为空，然后退出并等待 100 毫秒，然后验证是否有新的消息被入队。

以下是封装在事务中的内部循环的代码：

```cs
RunningTotal finalDayTotal = null;
using (ITransaction tx = stateManager.CreateTransaction())
{
    var result = await queue.TryDequeueAsync(tx);
    if (!result.HasValue) queueEmpty = true;
    else
    {
        var item = await filter.NewMessage<PurchaseInfo>(result.Value);
        if(item != null)
        {
            var counter = await store.TryGetValueAsync(tx, 
            item.Location);
            //counter update
            ...
        }
        ...
        ...
    }
} 
```

在这里，服务尝试出队一条消息。如果队列为空，则将`queueEmpty`设置为`true`以退出循环；否则，它通过幂等性过滤器传递消息。如果消息在此步骤中幸存下来，它将使用它来更新消息中引用的位置的累计总数。然而，分布式字典的正确操作要求每次更新条目时将旧计数器替换为新计数器。因此，将旧计数器复制到新的`RunningTotal`对象中。如果调用`Update`方法，可以使用新数据更新此新对象：

```cs
 //counter update    
    var newCounter = counter.HasValue ? 
    new RunningTotal
    {
        Count=counter.Value.Count,
        Day= counter.Value.Day
    }
    : new RunningTotal();
    finalDayTotal = newCounter.Update(item.Time, item.Cost);
    if (counter.HasValue)
        await store.TryUpdateAsync(tx, item.Location, 
        newCounter, counter.Value);
    else
        await store.TryAddAsync(tx, item.Location, newCounter); 
```

然后，事务被提交，如下所示：

```cs
if(item != null)
{
  ...
  ...
}
await tx.CommitAsync();
if(finalDayTotal != null)
{
    await SendTotal(finalDayTotal, item.Location);
} 
```

当`Update`方法返回完整的计算结果时，即`total != null`时，将调用以下方法：

```cs
protected async Task SendTotal(RunningTotal total, string location)
{
   //Empty, actual application would send data to a service 
   //that exposes daily statistics through a public Http endpoint
} 
```

`SendTotal`方法将总数发送到一个通过 HTTP 端点公开所有统计信息的服务。在阅读了专门介绍 Web API 的*第十四章*《使用.NET Core 应用服务导向架构》之后，您可能希望使用连接到数据库的无状态 ASP.NET Core 微服务实现类似的服务。无状态 ASP.NET Core 服务模板会自动为您创建一个基于 ASP.NET Core 的 HTTP 端点。

然而，由于该服务必须从`SendTotal`方法接收数据，它还需要基于远程的端点。因此，我们必须创建它们，就像我们为`LogStore`微服务所做的那样，并将基于远程的端点数组与包含 HTTP 端点的预先存在的数组连接起来。

## 定义微服务的主机

现在我们已经准备好定义微服务的`RunAsync`方法了：

```cs
protected override async Task RunAsync(CancellationToken cancellationToken)
{
    LogQueue = await 
        this.StateManager
        .GetOrAddAsync<IReliableQueue
<IdempotentMessage<PurchaseInfo>>>("logQueue");
    var configurationPackage = Context
        .CodePackageActivationContext
        .GetConfigurationPackageObject("Config");
    ...
    ... 
```

在这里，创建了服务队列，并将服务设置保存在`configurationPackage`中。

之后，我们可以创建`IHost`服务，就像我们在*第五章*的*将微服务架构应用于企业应用程序*的*使用通用主机*子部分中所解释的那样：

```cs
var host = new HostBuilder()
    .ConfigureServices((hostContext, services) =>
    {
        services.AddSingleton(this.StateManager);
        services.AddSingleton(this.LogQueue);
        services.AddSingleton(configurationPackage);
        services.AddHostedService<ComputeStatistics>();
    })
    .Build();
await host.RunAsync(cancellationToken); 
```

`ConfigureServices`定义了所有`IHostedService`实现所需的所有单例实例，因此它们被注入到引用其类型的所有实现的构造函数中。然后，`AddHostedService`声明了微服务的唯一`IHostedService`。一旦构建了`IHost`，我们就运行它，直到`RunAsync`取消令牌被标记。当取消令牌被标记时，关闭请求被传递给所有`IHostedService`实现。

## 与服务通信

由于我们尚未实现整个购买逻辑，我们将实现一个无状态的微服务，向`LogStore`服务发送随机数据。右键单击**Solution Explorer**中的`PurchaseLogging`项目，然后选择**Add** | **Service Fabric Service**。然后，选择.NET Core 无状态模板，并将新的微服务项目命名为`FakeSource`。

现在，让我们添加对`Interaction`项目的引用。在转到服务代码之前，我们需要在`ApplicationManifest.xml`中更新新创建的服务的副本计数，以及所有其他环境特定参数覆盖（云端，一个本地集群节点，五个本地集群节点）：

```cs
<Parameter Name="FakeSource_InstanceCount" DefaultValue="2" /> 
```

这个虚假服务不需要侦听器，它的`RunAsync`方法很简单：

```cs
string[] locations = new string[] { "Florence", "London", "New York", "Paris" };
protected override async Task RunAsync(CancellationToken cancellationToken)
{
    Random random = new Random();
    while (true)
    {
        cancellationToken.ThrowIfCancellationRequested();
        PurchaseInfo message = new PurchaseInfo
        {
            Time = DateTimeOffset.UtcNow,
            Location= locations[random.Next(0, locations.Length)],
            Cost= 200m*random.Next(1, 4)
        };
        //Send message to counting microservices 
        ...
        ...
        await Task.Delay(TimeSpan.FromSeconds(1), cancellationToken);
    }
} 
```

在每个循环中，创建一个随机消息并发送到计数微服务。然后，线程休眠一秒钟并开始新的循环。发送创建的消息的代码如下：

```cs
//Send message to counting microservices 
var partition = new ServicePartitionKey(Math.Abs(message.Location.GetHashCode()) % 1000);
var client = ServiceProxy.Create<ILogStore>(
    new Uri("fabric:/PurchaseLogging/LogStore"), partition);
try
{
    while (!await client.LogPurchase(new  
    IdempotentMessage<PurchaseInfo>(message)))
    {
        await Task.Delay(TimeSpan.FromMilliseconds(100),
        cancellationToken);
    }
}
catch
{
} 
```

在这里，从位置字符串计算出 0-9,999 区间内的一个密钥。我们使用`GetHashCode`，因为我们确信所有涉及的服务都使用相同的.NET Core 版本，因此我们确信它们使用相同的`GetHashCode`实现，以完全相同的方式计算哈希。然而，一般来说，最好提供一个具有标准哈希码实现的库。

这个整数被传递给`ServicePartitionKey`构造函数。然后，创建一个服务代理，并传递要调用的服务的 URI 和分区键。代理使用这些数据向命名服务请求给定分区值的主要实例的物理 URI。

`ServiceProxy.Create`还接受第三个可选参数，该参数指定代理发送的消息是否也可以路由到辅助副本。默认情况下，消息只路由到主要实例。如果消息目标返回`false`，表示它尚未准备好（请记住，当`LogStore`消息队列尚未创建时，`LogPurchase`返回`false`），则在 100 毫秒后尝试相同的传输。

向远程目标发送消息非常容易。然而，其他通信侦听器要求发送者手动与命名服务交互，以获取物理服务 URI。可以使用以下代码完成：

```cs
ServicePartitionResolver resolver = ServicePartitionResolver.GetDefault();
ResolvedServicePartition partition =     
await resolver.ResolveAsync(new Uri("fabric:/MyApp/MyService"), 
    new ServicePartitionKey(.....), cancellationToken);
//look for a primary service only endpoint
var finalURI= partition.Endpoints.First(p =>
    p.Role == ServiceEndpointRole.StatefulPrimary).Address; 
```

此外，在通用通信协议的情况下，我们必须使用 Polly 这样的库手动处理故障和重试（有关更多信息，请参见*第五章*的*将微服务架构应用于企业应用程序*的*具有弹性的任务执行*子部分）。

## 测试应用程序

为了测试应用程序，您需要以管理员权限启动 Visual Studio。因此，关闭 Visual Studio，然后右键单击 Visual Studio 图标，并选择以管理员身份启动的选项。一旦您再次进入 Visual Studio，加载`PurchaseLogging`解决方案，并在`ComputeStatistics.cs`文件中设置断点：

```cs
total = newCounter.Update(item.Time, item.Cost);
if (counter.HasValue)...//put breakpoint on this line 
```

每次断点被触发时，查看`newCounter`的内容，以验证所有位置的运行总数如何变化。在调试模式下启动应用程序之前，请确保本地集群正在运行五个节点。如果您从一个节点更改为五个节点，则本地集群菜单会变灰，直到操作完成，请等待菜单恢复正常。

一旦启动应用程序并构建应用程序，控制台将出现，并且您将开始在 Visual Studio 中接收操作完成的通知。应用程序需要一些时间在所有节点上加载；之后，您的断点应该开始被触发。

# 摘要

在本章中，我们描述了如何在 Visual Studio 中定义 Service Fabric 解决方案，以及如何在 Azure 中设置和配置 Service Fabric 集群。

我们描述了 Service Fabric 的构建模块、可靠服务、各种类型的可靠服务以及它们在 Service Fabric 应用程序中的角色。

最后，我们通过实现 Service Fabric 应用程序将这些概念付诸实践。在这里，我们提供了关于每个可靠服务架构的更多实际细节，以及如何组织和编写它们的通信。

下一章描述了另一个著名的微服务编排器 Kubernetes 及其在 Azure Cloud 中的实现。

# 问题

1.  什么是可靠服务？

1.  您能列出可靠服务的不同类型及其在 Service Fabric 应用程序中的角色吗？

1.  什么是`ConfigureServices`？

1.  在定义 Azure Service Fabric 集群时必须声明哪些端口类型？

1.  为什么需要可靠有状态服务的分区？

1.  我们如何声明远程通信必须由辅助副本处理？其他类型的通信呢？

# 进一步阅读

+   Azure Service Fabric 的官方文档可以在这里找到：[`docs.microsoft.com/en-US/azure/service-fabric/`](https://docs.microsoft.com/en-US/azure/service-fabric/)。

+   Azure Service Fabric 可靠服务的官方文档可以在这里找到：[`docs.microsoft.com/en-us/azure/service-fabric/service-fabric-reliable-services-introduction`](https://docs.microsoft.com/en-us/azure/service-fabric/service-fabric-reliable-services-introduction)。

+   有关 Actor 模型的更多信息可以在这里找到：[`www.researchgate.NET/publication/234816174_Actors_A_conceptual_foundation_for_concurrent_object-oriented_programming`](https://www.researchgate.NET/publication/234816174_Actors_A_conceptual_foundation_for_concurrent_obj)。

+   可以在这里找到可以在 Azure Service Fabric 中实现的 Actor 模型的官方文档：[`docs.microsoft.com/en-US/azure/service-fabric/service-fabric-reliable-actors-introduction`](https://docs.microsoft.com/en-US/azure/service-fabric/service-fabric-reliable-actors-introduction)。

微软还实现了一个独立于 Service Fabric 的高级 Actor 模型，称为 Orleans 框架。有关 Orleans 的更多信息可以在以下链接找到：

+   **Orleans - 虚拟演员**：[`www.microsoft.com/en-us/research/project/orleans-virtual-actors/?from=https%3A%2F%2Fresearch.microsoft.com%2Fen-us%2Fprojects%2Forleans%2F`](https://www.microsoft.com/en-us/research/project/orleans-virtual-actors/?from=https%3A%2F%2Fresearch).

+   **Orleans** **文档**：[`dotnet.github.io/orleans/docs/index.html`](https://dotnet.github.io/orleans/docs/index.html)


# 第七章：Azure Kubernetes Service

本章致力于描述 Kubernetes 微服务编排器，特别是在 Azure 中的实现，名为 Azure Kubernetes Service。该章节解释了基本的 Kubernetes 概念，然后重点介绍了如何与 Kubernetes 集群进行交互，以及如何部署 Azure Kubernetes 应用程序。所有概念都通过简单的示例进行了实践。我们建议在阅读本章之前先阅读*第五章*的*将微服务架构应用于企业应用程序*和*第六章*的*Azure Service Fabric*，因为它依赖于这些先前章节中解释的概念。

更具体地说，在本章中，您将学习以下主题：

+   Kubernetes 基础

+   与 Azure Kubernetes 集群交互

+   高级 Kubernetes 概念

通过本章结束时，您将学会如何实现和部署基于 Azure Kubernetes 的完整解决方案。

# 技术要求

+   Visual Studio 2019 免费的 Community Edition 或更高版本，安装了所有数据库工具，或者任何其他`.yaml`文件编辑器，如 Visual Studio Code。

+   免费的 Azure 账户。*第一章*的*创建 Azure 账户*部分解释了如何创建一个。

本章的代码可在[`github.com/PacktPublishing/Software-Architecture-with-C-9-and-.NET-5`](https://github.com/PacktPublishing/Software-Architecture-with-C-9-and-.NET-5)找到。

# Kubernetes 基础

Kubernetes 是一个先进的开源编排器，您可以在私人机器集群上本地安装。在撰写本文时，它是最广泛使用的编排器，因此微软也将其作为 Azure Service Fabric 的更好替代品，因为它目前是*事实上*的标准，并且可以依赖于广泛的工具和应用程序生态系统。本节介绍了基本的 Kubernetes 概念和实体。

Kubernetes 集群是运行 Kubernetes 编排器的虚拟机集群。与 Azure Service Fabric 一样，组成集群的虚拟机被称为节点。我们可以在 Kubernetes 上部署的最小软件单元不是单个应用程序，而是一组容器化的应用程序，称为 pod。虽然 Kubernetes 支持各种类型的容器，但最常用的容器类型是 Docker，我们在*第五章*的*将微服务架构应用于企业应用程序*中进行了分析，因此我们将把讨论限制在 Docker 上。

`pod`很重要，因为属于同一 pod 的应用程序确保在同一节点上运行。这意味着它们可以通过本地主机端口轻松通信。然而，不同 pod 之间的通信更复杂，因为 pod 的 IP 地址是临时资源，因为 pod 没有固定的节点在其上运行，而是由编排器从一个节点移动到另一个节点。此外，为了提高性能，pod 可能会被复制，因此，通常情况下，将消息发送到特定 pod 是没有意义的，而只需发送到同一 pod 的任何相同副本之一即可。

在 Azure Service Fabric 中，基础设施会自动为相同副本组分配虚拟网络地址，而在 Kubernetes 中，我们需要定义显式资源，称为服务，这些服务由 Kubernetes 基础设施分配虚拟地址，并将其通信转发到相同 pod 的集合。简而言之，服务是 Kubernetes 分配常量虚拟地址给 pod 副本集的方式。

所有 Kubernetes 实体都可以分配名称值对，称为标签，用于通过模式匹配机制引用它们。更具体地说，选择器通过列出它们必须具有的标签来选择 Kubernetes 实体。

因此，例如，所有从同一服务接收流量的 pod 都是通过在服务定义中指定的标签来选择的。

服务将其流量路由到所有连接的 Pod 的方式取决于 Pod 的组织方式。无状态的 Pod 被组织在所谓的`ReplicaSets`中，它们类似于 Azure Service Fabric 服务的无状态副本。与 Azure Service Fabric 无状态服务一样，`ReplicaSets`分配给整个组的唯一虚拟地址，并且流量在组中的所有 Pod 之间均匀分配。

有状态的 Kubernetes Pod 副本被组织成所谓的`StatefulSets`。与 Azure Service Fabric 有状态服务类似，`StatefulSets`使用分片将流量分配给它们的所有 Pod。因此，Kubernetes 服务为它们连接的`StatefulSet`的每个 Pod 分配一个不同的名称。这些名称看起来像这样：`basename-0.<base URL>`，`basename-1.<base URL>`，...，`basename-n.<base URL>`。这样，消息分片可以轻松地完成如下：

1.  每次需要将消息发送到由*N*个副本组成的`StatefulSet`时，计算 0 到*N*-1 之间的哈希值，例如`x`。

1.  将后缀`x`添加到基本名称以获取集群地址，例如`basename-x.<base URL>`。

1.  将消息发送到`basename-x.<base URL>`集群地址。

Kubernetes 没有预定义的存储设施，也不能使用节点磁盘存储，因为 Pod 会在可用节点之间移动，因此必须使用分片的云数据库或其他类型的云存储来提供长期存储。虽然`StatefulSet`的每个 Pod 可以使用常规的连接字符串技术访问分片的云数据库，但 Kubernetes 提供了一种技术来抽象外部 Kubernetes 集群环境提供的类似磁盘的云存储。我们将在*高级 Kubernetes 概念*部分中描述这些内容。

在这个简短的介绍中提到的所有 Kubernetes 实体都可以在`.yaml`文件中定义，一旦部署到 Kubernetes 集群中，就会创建文件中定义的所有实体。接下来的子节描述了`.yaml`文件，而随后的其他子节详细描述了到目前为止提到的所有基本 Kubernetes 对象，并解释了如何在`.yaml`文件中定义它们。在整个章节中将描述更多的 Kubernetes 对象。

## .yaml 文件

`.yaml`文件与 JSON 文件一样，是一种以人类可读的方式描述嵌套对象和集合的方法，但它们使用不同的语法。你有对象和列表，但对象属性不用`{}`括起来，列表也不用`[]`括起来。相反，嵌套对象通过简单地缩进其内容来声明。可以自由选择缩进的空格数，但一旦选择了，就必须一致使用。

列表项可以通过在前面加上连字符（`-`）来与对象属性区分开。

以下是涉及嵌套对象和集合的示例：

```cs
Name: Jhon
Surname: Smith
Spouse: 
  Name: Mary
  Surname: Smith
Addresses:
- Type: home
  Country: England
  Town: London
  Street: My home street
- Type: office
  Country: England
  Town: London
  Street: My home street 
```

前面的`Person`对象有一个嵌套的`Spouse`对象和一个嵌套的地址集合。

`.yaml`文件可以包含多个部分，每个部分定义一个不同的实体，它们由包含`---`字符串的行分隔。注释以`#`符号开头，在每行注释前必须重复该符号。

每个部分都以声明 Kubernetes API 组和版本开始。实际上，并不是所有对象都属于同一个 API 组。对于属于`core` API 组的对象，我们可以只指定 API 版本，如下面的示例所示：

```cs
apiVersion: v1 
```

虽然属于不同 API 组的对象也必须指定 API 名称，如下面的示例所示：

```cs
apiVersion: apps/v1 
```

在下一个子节中，我们将详细分析构建在其上的`ReplicaSets`和`Deployments`。

## ReplicaSets 和 Deployments

Kubernetes 应用程序的最重要的构建块是`ReplicaSet`，即一个被复制*n*次的 Pod。然而，通常情况下，您会采用一个更复杂的对象，该对象建立在`ReplicaSet`之上 - `Deployment`。`Deployments`不仅创建`ReplicaSet`，还监视它们以确保副本的数量保持恒定，独立于硬件故障和可能涉及`ReplicaSets`的其他事件。换句话说，它们是一种声明性的定义`ReplicaSets`和 Pod 的方式。

每个`Deployment`都有一个名称（`metadata->name`），一个指定所需副本数量的属性（`spec->replicas`），一个键值对（`spec->selector->matchLabels`）用于选择要监视的 Pod，以及一个模板（`spec->template`），用于指定如何构建 Pod 副本：

```cs
apiVersion: apps/v1
kind: Deployment
metadata: 
  name: my-deployment-name
  namespace: my-namespace #this is optional
spec: 
   replicas: 3
   selector: 
     matchLabels: 
       my-pod-label-name: my-pod-label-value
         ...
   template:
      ... 
```

`namespace`是可选的，如果未提供，则假定为名为`default`的命名空间。命名空间是保持 Kubernetes 集群中对象分开的一种方式。例如，一个集群可以托管两个完全独立的应用程序的对象，每个应用程序都放在一个单独的`namespace`中。

缩进在模板内部是要复制的 Pod 的定义。复杂的对象（如`Deployments`）还可以包含其他类型的模板，例如外部环境所需的类似磁盘的内存的模板。我们将在“高级 Kubernetes 概念”部分进一步讨论这个问题。

反过来，Pod 模板包含一个`metadata`部分，其中包含用于选择 Pod 的标签，以及一个`spec`部分，其中包含所有容器的列表：

```cs
metadata: 
  labels: 
    my-pod-label-name: my-pod-label-value
      ...
spec: 
  containers:
   ...
  - name: my-container-name
    image: <Docker imagename>
    resources: 
      requests: 
        cpu: 100m 
        memory: 128Mi 
      limits: 
        cpu: 250m 
        memory: 256Mi 
    ports: 
    - containerPort: 6379
    env: 
    - name: env-name
      value: env-value
       ... 
```

每个容器都有一个名称，并且必须指定用于创建容器的 Docker 镜像的名称。如果 Docker 镜像不包含在公共 Docker 注册表中，则名称必须是包含存储库位置的 URI。

然后，容器必须指定它们需要创建在`resources->requests`对象中的内存和 CPU 资源。只有在当前可用这些资源的情况下才会创建 Pod 副本。相反，`resources->limits`对象指定容器副本实际可以使用的最大资源。如果在容器执行过程中超过了这些限制，将采取措施限制它们。具体来说，如果超过了 CPU 限制，容器将被限制（其执行将停止以恢复其 CPU 消耗），而如果超过了内存限制，容器将被重新启动。`containerPort`必须是容器暴露的端口。在这里，我们还可以指定其他信息，例如使用的协议。

CPU 时间以毫核表示，其中 1,000 毫核表示 100％的 CPU 时间，而内存以 Mebibytes（*1Mi = 1024*1024 字节*）或其他单位表示。`env`列出了要传递给容器的所有环境变量及其值。

容器和 Pod 模板都可以包含进一步的字段，例如定义虚拟文件的属性和定义返回容器就绪状态和健康状态的命令的属性。我们将在“高级 Kubernetes 概念”部分中分析这些内容。

下面的子部分描述了用于存储状态信息的 Pod 集。

## 有状态集

`StatefulSets`与`ReplicaSet`非常相似，但是`ReplicaSet`的 Pod 是不可区分的处理器，通过负载均衡策略并行地为相同的工作贡献，而`StatefulSet`中的 Pod 具有唯一的标识，并且只能通过分片方式共享相同的工作负载。这是因为`StatefulSets`被设计用于存储信息，而信息无法并行存储，只能通过分片的方式在多个存储之间分割。

出于同样的原因，每个 Pod 实例始终与其所需的任何虚拟磁盘空间绑定在一起（参见“高级 Kubernetes 概念”部分），因此每个 Pod 实例负责向特定存储写入。

此外，`StatefulSets`的 pod 实例附带有序号。它们按照这些序号顺序启动，并按相反的顺序停止。如果`StatefulSet`包含*N*个副本，这些序号从零到*N*-1。此外，通过将模板中指定的 pod 名称与实例序号链接起来，可以获得每个实例的唯一名称，方式如下 - `<pod 名称>-<实例序号>`。因此，实例名称将类似于`mypodname-0`，`mypodname-1`等。正如我们将在*服务*子部分中看到的那样，实例名称用于为所有实例构建唯一的集群网络 URI，以便其他 pod 可以与`StatefulSets`的特定实例通信。

以下是典型的`StatefulSet`定义：

```cs
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: my-stateful-set-name
spec:
  selector:
    matchLabels:
      my-pod-label-name: my-pod-label-value
...
  serviceName: "my-service-name"
  replicas: 3 
  template:
    ... 
```

模板部分与`Deployments`相同。与`Deployments`的主要概念上的区别是`serviceName`字段。它指定必须与`StatefulSets`连接以为所有 pod 实例提供唯一网络地址的服务的名称。我们将在*服务*子部分中详细讨论这个主题。此外，通常，`StatefulSets`使用某种形式的存储。我们将在*高级 Kubernetes 概念*部分详细讨论这个问题。

值得指出的是，`StatefulSets`的默认有序创建和停止策略可以通过为`spec->podManagementPolicy`属性指定显式的`Parallel`值来更改（默认值为`OrderedReady`）。

下面的子部分描述了如何为`ReplicaSets`和`StatefulSets`提供稳定的网络地址。

## 服务

由于 pod 实例可以在节点之间移动，因此它们没有与之关联的稳定 IP 地址。服务负责为整个`ReplicaSet`分配一个唯一且稳定的虚拟地址，并将流量负载均衡到所有与之连接的实例。服务不是在集群中创建的软件对象，只是为实施其功能所需的各种设置和活动的抽象。

服务在协议栈的第 4 级工作，因此它们理解诸如 TCP 之类的协议，但它们无法执行例如 HTTP 特定的操作/转换，例如确保安全的 HTTPS 连接。因此，如果您需要在 Kubernetes 集群上安装 HTTPS 证书，您需要一个能够在协议栈的第 7 级进行交互的更复杂的对象。`Ingress`对象就是为此而设计的。我们将在下一个子部分中讨论这个问题。

服务还负责为`StatefulSet`的每个实例分配一个唯一的虚拟地址。实际上，有各种类型的服务；一些是为`ReplicaSet`设计的，另一些是为`StatefulSet`设计的。

`ClusterIP`服务类型被分配一个唯一的集群内部 IP 地址。它通过标签模式匹配指定与之连接的`ReplicaSets`或`Deployments`。它使用由 Kubernetes 基础设施维护的表来将接收到的流量在所有与之连接的 pod 实例之间进行负载均衡。

因此，其他 pod 可以通过与分配了稳定网络名称`<service 名称>.<service 命名空间>.svc.cluster.local`的服务进行交互，与连接到该服务的 pod 进行通信。由于它们只分配了本地 IP 地址，因此无法从 Kubernetes 集群外部访问`ClusterIP`服务。以下是典型`ClusterIP`服务的定义：

```cs
apiVersion: v1
kind: Service
metadata:
  name: my-service
  namespace: my-namespace
spec:
  selector:
    my-selector-label: my-selector-value
    ...
  ports:
    - name: http
      protocol: TCP
      port: 80
      targetPort: 9376
    - name: https
      protocol: TCP
      port: 443
      targetPort: 9377 
```

每个服务可以在多个端口上工作，并且可以将任何端口（`port`）路由到容器公开的端口（`targetPort`）。但是，很常见的情况是`port = targetPort`。端口可以有名称，但这些名称是可选的。此外，协议的规范是可选的，如果不指定，则允许所有支持的第 4 级协议。`spec->selector`属性指定选择服务要将其接收到的通信路由到的所有名称/值对。

由于无法从 Kubernetes 集群外部访问`ClusterIP`服务，我们需要其他类型的服务来将 Kubernetes 应用程序暴露在公共 IP 地址上。

`NodePort`类型的服务是将 pod 暴露给外部世界的最简单方式。为了实现`NodePort`服务，在 Kubernetes 集群的所有节点上都打开相同的端口`x`，并且每个节点将其接收到的流量路由到一个新创建的`ClusterIP`服务。

反过来，`ClusterIP`服务将其流量路由到服务选择的所有 pod：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_07_01.png)

图 7.1：NodePort 服务

因此，只需通过任何集群节点的公共 IP 与端口`x`通信，就可以访问与`NodePort`服务连接的 pod。当然，整个过程对开发人员来说是完全自动和隐藏的，他们唯一需要关注的是获取端口号`x`以确定外部流量的转发位置。

`NodePort`服务的定义与`ClusterIP`服务的定义相同，唯一的区别是它们将`spec->type`属性的值设置为`NodePort`。

```cs
...
spec:
  type: NodePort
  selector:
  ... 
```

默认情况下，每个`Service`指定的`targetPort`都会自动选择 30000-327673 范围内的节点端口`x`。对于`NodePortServices`来说，与每个`targetPort`关联的端口属性是无意义的，因为所有流量都通过所选的节点端口`x`传递，并且按照惯例，设置为与`targetPort`相同的值。开发人员还可以通过`nodePort`属性直接设置节点端口`x`：

```cs
...
ports:
    - name: http
      protocol: TCP
      port: 80
      targetPort: 80
      nodePort: 30007
    - name: https
      protocol: TCP
      port: 443
      targetPort: 443
      nodePort: 30020
... 
```

当 Kubernetes 集群托管在云中时，将一些 pod 暴露给外部世界的更方便的方式是通过`LoadBalancer`服务，此时 Kubernetes 集群通过所选云提供商的第四层负载均衡器暴露给外部世界。

`LoadBalancer`服务的定义与`ClusterIp`服务相同，唯一的区别是`spec->type`属性必须设置为`LoadBalancer`：

```cs
...
spec:
  type: LoadBalancer
  selector:
  ... 
```

如果没有添加进一步的规范，动态公共 IP 将被随机分配。然而，如果需要特定的公共 IP 地址给云提供商，可以通过在`spec->loadBalancerIP`属性中指定它来用作集群负载均衡器的公共 IP 地址：

```cs
...
spec:
  type: LoadBalancer
  loadBalancerIP: <your public ip>
  selector:
  ... 
```

在 Azure Kubernetes 中，您还必须在注释中指定分配 IP 地址的资源组：

```cs
apiVersion: v1
kind: Service
metadata:
  annotations:
    service.beta.kubernetes.io/azure-load-balancer-resource-group: <IP resource group name>
  name: my-service name
... 
```

在 Azure Kubernetes 中，您可以保留动态 IP 地址，但可以获得类型为`<my-service-label>.<location>.cloudapp.azure.com`的公共静态域名，其中`<location>`是您为资源选择的地理标签。`<my-service-label>`是一个您验证过使前面的域名唯一的标签。所选标签必须在您的服务的注释中声明，如下所示：

```cs
apiVersion: v1
kind: Service
metadata:
  annotations:
service.beta.kubernetes.io/azure-dns-label-name: <my-service-label>
  name: my-service-name
... 
```

`StatefulSets`不需要任何负载均衡，因为每个 pod 实例都有自己的标识，只需要为每个 pod 实例提供一个唯一的 URL 地址。这个唯一的 URL 由所谓的无头服务提供。无头服务的定义与`ClusterIP`服务相同，唯一的区别是它们的`spec->clusterIP`属性设置为`none`：

```cs
...
spec:
clusterIP: none
  selector:
... 
```

所有由无头服务处理的`StatefulSets`必须将服务名称放置在其`spec->serviceName`属性中，如*StatefulSets*子部分中所述。

无头服务为其处理的所有`StatefulSets` pod 实例提供的唯一名称是`<unique pod name>.<service name>.<namespace>.svc.cluster.local`。

服务只能理解低级协议，如 TCP/IP，但大多数 Web 应用程序位于更复杂的 HTTP 协议上。这就是为什么 Kubernetes 提供了基于服务的更高级实体`Ingresses`。下一小节描述了这些内容，并解释了如何通过级别 7 协议负载均衡器将一组`pods`公开，该负载均衡器可以为您提供典型的 HTTP 服务，而不是通过`LoadBalancer`服务。

## Ingresses

`Ingresses`主要用于使用 HTTP(S)。它们提供以下服务：

+   HTTPS 终止。它们接受 HTTPS 连接并将其路由到云中的任何服务的 HTTP 格式。

+   基于名称的虚拟主机。它们将多个域名与同一个 IP 地址关联，并将每个域或`<domain>/<path prefix>`路由到不同的集群服务。

+   负载均衡。

`Ingresses`依赖于 Web 服务器来提供上述服务。实际上，只有在安装了`Ingress Controller`之后才能使用`Ingresses`。`Ingress Controllers`是必须安装在集群中的自定义 Kubernetes 对象。它们处理 Kubernetes 与 Web 服务器之间的接口，可以是外部 Web 服务器或作为`Ingress Controller`安装的 Web 服务器的一部分。

我们将在*高级 Kubernetes 概念*部分中描述基于 NGINX Web 服务器的`Ingress Controller`的安装，作为使用 Helm 的示例。 *进一步阅读*部分包含有关如何安装与外部 Azure 应用程序网关进行接口的`Ingress Controller`的信息。

HTTPS 终止和基于名称的虚拟主机可以在`Ingress`定义中进行配置，与所选择的`Ingress Controller`无关，而负载均衡的实现方式取决于所选择的特定`Ingress Controller`及其配置。一些`Ingress Controller`配置数据可以通过`Ingress`定义的`metadata->annotations`字段传递。

基于名称的虚拟主机在 Ingress 定义的`spec>rules`部分中定义：

```cs
...
spec:
...
  rules:
  - host: *.mydomain.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: my-service-name
            port:
              number: 80
  - host: my-subdomain.anotherdomain.com
... 
```

每个规则都指定了一个可选的主机名，可以包含`*`通配符。如果没有提供主机名，则规则匹配所有主机名。对于每个规则，我们可以指定多个路径，每个路径重定向到不同的服务/端口对，其中服务通过其名称引用。与每个`path`的匹配方式取决于`pathType`的值；如果该值为`Prefix`，则指定的`path`必须是任何匹配路径的前缀。否则，如果该值为`Exact`，则匹配必须完全相同。匹配区分大小写。

通过将特定主机名与在 Kubernetes 密钥中编码的证书关联，可以指定特定主机名上的 HTTPS 终止：

```cs
...
spec:
...
  tls:
  - hosts:
      - www.mydomain.com
      secretName: my-certificate1
      - my-subdomain.anotherdomain.com
      secretName: my-certificate2
... 
```

可以免费获取 HTTPS 证书，网址为[`letsencrypt.org/`](https://letsencrypt.org/)。该过程在网站上有详细说明，但基本上，与所有证书颁发机构一样，您提供一个密钥，他们根据该密钥返回证书。还可以安装一个**证书管理器**，它负责自动安装和更新证书。在 Kubernetes 密钥/证书对如何编码为 Kubernetes 密钥的字符串中，详细说明在*高级 Kubernetes 概念*部分中。

整个`Ingress`定义如下所示：

```cs
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: my-example-ingress
  namespace: my-namespace
spec:
  tls:
  ...
  rules:
... 
```

在这里，`namespace`是可选的，如果未指定，则假定为`default`。

在下一节中，我们将通过定义 Azure Kubernetes 集群并部署一个简单应用程序来实践这里解释的一些概念。

# 与 Azure Kubernetes 集群交互

要创建一个**Azure Kubernetes 服务**（**AKS**）集群，请在 Azure 搜索框中键入`AKS`，选择**Kubernetes 服务**，然后单击**添加**按钮。将显示以下表单：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_07_02.png)

图 7.2：创建 Kubernetes 集群

值得一提的是，您可以通过将鼠标悬停在任何带有圆圈的“i”上来获取帮助，如上述屏幕截图所示。

与往常一样，您需要指定订阅、资源组和区域。然后，您可以选择一个唯一的名称（Kubernetes 集群名称），以及您想要使用的 Kubernetes 版本。对于计算能力，您需要为每个节点选择一个机器模板（节点大小）和节点数量。初始屏幕显示默认的三个节点。由于三个节点对于 Azure 免费信用来说太多了，我们将其减少为两个。此外，默认虚拟机也应该被更便宜的虚拟机替换，因此单击“更改大小”并选择“DS1 v2”。

“可用区”设置允许您将节点分布在多个地理区域以实现更好的容错性。默认值为三个区域。由于我们只有两个节点，请将其更改为两个区域。

在进行了上述更改后，您应该会看到以下设置：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_07_03.png)

图 7.3：选择的设置

现在，您可以通过单击“查看+创建”按钮来创建您的集群。应该会出现一个审查页面，请确认并创建集群。

如果您单击“下一步”而不是“查看+创建”，您还可以定义其他节点类型，然后可以提供安全信息，即“服务主体”，并指定是否希望启用基于角色的访问控制。在 Azure 中，服务主体是与您可能用于定义资源访问策略的服务相关联的帐户。您还可以更改默认网络设置和其他设置。

部署可能需要一些时间（10-20 分钟）。之后，您将拥有您的第一个 Kubernetes 集群！在本章结束时，当不再需要该集群时，请不要忘记删除它，以避免浪费您的 Azure 免费信用。

在下一小节中，您将学习如何通过 Kubernetes 的官方客户端 Kubectl 与集群进行交互。

## 使用 Kubectl

创建完集群后，您可以使用 Azure Cloud Shell 与其进行交互。单击 Azure 门户页面右上角的控制台图标。以下屏幕截图显示了 Azure Shell 图标：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_07_04.png)

图 7.4：Azure Shell 图标

在提示时，选择“Bash Shell”。然后，您将被提示创建一个存储帐户，确认并创建它。

我们将使用此 Shell 与我们的集群进行交互。在 Shell 的顶部有一个文件图标，我们将使用它来上传我们的`.yaml`文件：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_07_05.png)

图 7.5：如何在 Azure Cloud Shell 中上传文件

还可以下载一个名为 Azure CLI 的客户端，并在本地机器上安装它（参见[`docs.microsoft.com/en-US/cli/azure/install-azure-cli`](https://docs.microsoft.com/en-US/cli/azure/install-azure-cli)），但在这种情况下，您还需要安装与 Kubernetes 集群交互所需的所有工具（Kubectl 和 Helm），这些工具已预先安装在 Azure Cloud Shell 中。

创建 Kubernetes 集群后，您可以通过`kubectl`命令行工具与其进行交互。`kubectl`已集成在 Azure Shell 中，因此您只需激活集群凭据即可使用它。您可以使用以下 Cloud Shell 命令来完成此操作：

```cs
az aks get-credentials --resource-group <resource group> --name <cluster name> 
```

上述命令将凭据存储在`/.kube/config`配置文件中，该凭据是自动创建的，以便您与集群进行交互。从现在开始，您可以无需进一步身份验证即可发出`kubectl`命令。

如果您发出`kubectl get nodes`命令，您将获得所有 Kubernetes 节点的列表。通常，`kubectl get <对象类型>`列出给定类型的所有对象。您可以将其与`nodes`、`pods`、`statefulset`等一起使用。`kubectl get all`显示在您的集群中创建的所有对象的列表。如果您还添加了特定对象的名称，您将只获取该特定对象的信息，如下所示：

```cs
kubectl get <object type><object name> 
```

如果添加`--watch`选项，对象列表将持续更新，因此您可以看到所有选定对象的状态随时间变化。您可以通过按下 Ctrl + c 来退出此观察状态。

以下命令显示了有关特定对象的详细报告：

```cs
kubectl describe <object name> 
```

可以使用以下命令创建在`.yaml`文件中描述的所有对象，例如`myClusterConfiguration.yaml`：

```cs
kubectl create -f myClusterConfiguration.yaml 
```

然后，如果您修改了`.yaml`文件，可以使用`apply`命令在集群上反映所有修改，如下所示：

```cs
kubectl apply -f myClusterConfiguration.yaml 
```

`apply`执行与`create`相同的工作，但如果资源已经存在，`apply`会覆盖它，而`create`则会显示错误消息。

您可以通过将相同的文件传递给`delete`命令来销毁使用`.yaml`文件创建的所有对象，如下所示：

```cs
kubectl delete -f myClusterConfiguration.yaml 
```

`delete`命令还可以传递对象类型和要销毁的该类型对象的名称列表，如下例所示：

```cs
kubectl delete deployment deployment1 deployment2... 
```

上述`kubectl`命令应足以满足大部分实际需求。有关更多详细信息，请参阅*Further reading*部分中的官方文档链接。

在下一小节中，我们将使用`kubectl create`安装一个简单的演示应用程序。

## 部署演示 Guestbook 应用程序

Guestbook 应用程序是官方 Kubernetes 文档示例中使用的演示应用程序。我们将使用它作为 Kubernetes 应用程序的示例，因为它的 Docker 镜像已经在公共 Docker 存储库中可用，所以我们不需要编写软件。

Guestbook 应用程序存储了访问酒店或餐厅的客户的意见。它由一个使用`Deployment`实现的 UI 层和一个使用基于 Redis 的内存存储实现的数据库层组成。而 Redis 存储则是由一个用于写入/更新的唯一主存储和几个只读副本组成，这些副本始终基于 Redis，并实现了读取并行性。写入/更新并行性可以通过多个分片的 Redis 主节点来实现，但由于应用程序的特性，写入操作不应占主导地位，因此在实际情况下，单个主数据库应该足够满足单个餐厅/酒店的需求。整个应用程序由三个`.yaml`文件组成，您可以在与本书相关的 GitHub 存储库中找到。

以下是包含在`redis-master.yaml`文件中的基于 Redis 的主存储的代码：

```cs
apiVersion: apps/v1 
kind: Deployment
metadata:
  name: redis-master
  labels:
    app: redis
spec:
  selector:
    matchLabels:
      app: redis
      role: master
      tier: backend
  replicas: 1
  template:
    metadata:
      labels:
        app: redis
        role: master
        tier: backend
    spec:
      containers:
      - name: master
        image: k8s.gcr.io/redis:e2e
        resources:
          requests:
            cpu: 100m
            memory: 100Mi
        ports:
        - containerPort: 6379
---
apiVersion: v1
kind: Service
metadata:
  name: redis-master
  labels:
    app: redis
    role: master
    tier: backend
spec:
  ports:
  - port: 6379
    targetPort: 6379
  selector:
    app: redis
    role: master
    tier: backend 
```

该文件由两个对象定义组成，由一个只包含`---`的行分隔，即`.yaml`文件的对象定义分隔符。第一个对象是一个具有单个副本的`Deployment`，第二个对象是一个`ClusterIPService`，它在内部`redis-master.default.svc.cluster.local`网络地址上的`6379`端口上公开`Deployment`。`Deployment pod template`定义了三个`app`、`role`和`tier`标签及其值，这些值在 Service 的`selector`定义中用于将 Service 与在`Deployment`中定义的唯一 pod 连接起来。

让我们将`redis-master.yaml`文件上传到 Cloud Shell，然后使用以下命令在集群中部署它：

```cs
kubectl create -f redis-master.yaml 
```

操作完成后，您可以使用`kubectl get all`命令检查集群的内容。

从`redis-slave.yaml`文件中定义了从存储，它与主存储完全类似，唯一的区别是这次有两个副本和不同的 Docker 镜像。

让我们也上传此文件，并使用以下命令部署它：

```cs
kubectl create -f redis-slave.yaml 
```

UI 层的代码包含在`frontend.yaml`文件中。`Deployment`有三个副本和不同的服务类型。让我们使用以下命令上传并部署此文件：

```cs
kubectl create -f frontend.yaml 
```

值得分析的是`frontend.yaml`文件中的服务代码：

```cs
apiVersion: v1
kind: Service
metadata:
  name: frontend
  labels:
    app: guestbook
    tier: frontend
spec:
  type: LoadBalancer
  ports:
  - port: 80
  selector:
    app: guestbook
    tier: frontend 
```

这种类型的服务属于`LoadBalancer`类型，因为它必须在公共 IP 地址上公开应用程序。为了获取分配给服务和应用程序的公共 IP 地址，请使用以下命令：

```cs
kubectl get service 
```

前面的命令应该显示所有已安装服务的信息。您应该在列表的`EXTERNAL-IP`列下找到公共 IP。如果您只看到`<none>`的值，请重复该命令，直到公共 IP 地址分配给负载均衡器。

一旦获得 IP 地址，使用浏览器导航到该地址。应用程序的主页现在应该显示出来了！

在完成对应用程序的实验后，使用以下命令从集群中删除应用程序，以避免浪费您的 Azure 免费信用额度（公共 IP 地址需要付费）：

```cs
kubectl delete deployment frontend redis-master redis-slave 
kubectl delete service frontend redis-master redis-slave 
```

在下一节中，我们将分析其他重要的 Kubernetes 功能。

# 高级 Kubernetes 概念

在本节中，我们将讨论其他重要的 Kubernetes 功能，包括如何为`StatefulSets`分配永久存储，如何存储密码、连接字符串或证书等秘密信息，容器如何通知 Kubernetes 其健康状态，以及如何使用 Helm 处理复杂的 Kubernetes 包。所有主题都按照专门的子部分进行组织。我们将从永久存储的问题开始。

## 需要永久存储

由于 Pod 会在节点之间移动，它们不能依赖于当前运行它们的节点提供的永久存储。这给我们留下了两个选择：

1.  **使用外部数据库**：借助数据库，`ReplicaSets`也可以存储信息。然而，如果我们需要更好的写入/更新操作性能，我们应该使用基于非 SQL 引擎（如 Cosmos DB 或 MongoDB）的分布式分片数据库（参见*第九章*，*如何在云中选择数据存储*）。在这种情况下，为了充分利用表分片，我们需要使用`StatefulSets`，其中每个`pod`实例负责不同的表分片。

1.  **使用云存储**：由于不与物理集群节点绑定，云存储可以永久关联到`StatefulSets`的特定 Pod 实例。

由于访问外部数据库不需要任何特定于 Kubernetes 的技术，而是可以使用通常的连接字符串来完成，我们将集中讨论云存储。

Kubernetes 提供了一个名为**PersistentVolumeClaim**（PVC）的存储抽象，它独立于底层存储提供商。更具体地说，PVC 是分配请求，可以与预定义资源匹配或动态分配。当 Kubernetes 集群在云中时，通常使用由云提供商安装的动态提供商进行动态分配。

Azure 等云提供商提供具有不同性能和不同成本的不同存储类。此外，PVC 还可以指定`accessMode`，可以是：

+   `ReadWriteOnce` - 卷可以被单个 Pod 挂载为读写。

+   `ReadOnlyMany` - 卷可以被多个 Pod 挂载为只读。

+   `ReadWriteMany` - 卷可以被多个 Pod 挂载为读写。

卷声明可以添加到`StatefulSets`的特定`spec->volumeClaimTemplates`对象中：

```cs
volumeClaimTemplates:
-  metadata:
   name: my-claim-template-name
spec:
  resources:
    request:
      storage: 5Gi
  volumeMode: Filesystem
  accessModes:
    - ReadWriteOnce
  storageClassName: my-optional-storage-class 
```

`storage`属性包含存储需求。将`volumeMode`设置为`Filesystem`是一种标准设置，表示存储将作为文件路径可用。另一个可能的值是`Block`，它将内存分配为`未格式化`。`storageClassName`必须设置为云提供商提供的现有存储类。如果省略，则将假定默认存储类。

可以使用以下命令列出所有可用的存储类：

```cs
kubectl get storageclass 
```

一旦`volumeClaimTemplates`定义了如何创建永久存储，那么每个容器必须指定将永久存储附加到的文件路径，位于`spec->containers->volumeMounts`属性中。

```cs
...
volumeMounts
- name: my-claim-template-name
  mountPath: /my/requested/storage
  readOnly: false
... 
```

在这里，`name`必须与 PVC 的名称相对应。

以下子节显示了如何使用 Kubernetes secrets。

## Kubernetes secrets

秘密是一组键值对，它们被加密以保护它们。可以通过将每个值放入文件中，然后调用以下`kubectl`命令来创建它们：

```cs
kubectl create secret generic my-secret-name \
  --from-file=./secret1.bin \
  --from-file=./secret2.bin 
```

在这种情况下，文件名成为键，文件内容成为值。

当值为字符串时，可以直接在`kubectl`命令中指定，如下所示：

```cs
kubectl create secret generic dev-db-secret \
  --from-literal=username=devuser \
  --from-literal=password=sdsd_weew1' 
```

在这种情况下，键和值按顺序列出，由`=`字符分隔。

定义后，可以在 pod（`Deployment`或`StatefulSettemplate`）的`spec->volume`属性中引用 secrets，如下所示：

```cs
...
volumes:
  - name: my-volume-with-secrets
    secret:
      secretName: my-secret-name
... 
```

之后，每个容器可以在`spec->containers->volumeMounts`属性中指定要将它们挂载到的路径：

```cs
...
volumeMounts:
    - name: my-volume-with-secrets
      mountPath: "/my/secrets"
      readOnly: true
... 
```

在上面的示例中，每个键被视为具有与键相同名称的文件。文件的内容是秘密值，经过 base64 编码。因此，读取每个文件的代码必须解码其内容（在.NET 中，`Convert.FromBase64`可以完成这项工作）。

当 secrets 包含字符串时，它们也可以作为环境变量传递给`spec->containers->env object`：

```cs
env:
    - name: SECRET_USERNAME
      valueFrom:
        secretKeyRef:
          name: dev-db-secret
          key: username
    - name: SECRET_PASSWORD
      valueFrom:
        secretKeyRef:
          name: dev-db-secret
          key: password 
```

在这里，`name`属性必须与 secret 的`name`匹配。当容器托管 ASP.NET Core 应用程序时，将 secrets 作为环境变量传递非常方便，因为在这种情况下，环境变量立即在配置对象中可用（请参阅*第十五章*的*加载配置数据并与选项框架一起使用*部分，*介绍 ASP.NET Core MVC*）。

Secrets 还可以使用以下`kubectl`命令对 HTTPS 证书的密钥/证书对进行编码：

```cs
kubectl create secret tls test-tls --key="tls.key" --cert="tls.crt" 
```

以这种方式定义的 secrets 可用于在`Ingresses`中启用 HTTPS 终止。只需将 secret 名称放置在`spec->tls->hosts->secretName`属性中即可。

## 活跃性和就绪性检查

Kubernetes 会自动监视所有容器，以确保它们仍然存活，并且将资源消耗保持在`spec->containers->resources->limits`对象中声明的限制范围内。当某些条件被违反时，容器要么被限制，要么被重新启动，要么整个 pod 实例在不同的节点上重新启动。Kubernetes 如何知道容器处于健康状态？虽然它可以使用操作系统来检查节点的健康状态，但它没有适用于所有容器的通用检查。

因此，容器本身必须通知 Kubernetes 它们的健康状态，否则 Kubernetes 必须放弃验证它们。容器可以通过两种方式通知 Kubernetes 它们的健康状态，一种是声明返回健康状态的控制台命令，另一种是声明提供相同信息的端点。

这两个声明都在`spec->containers->livenessProb`对象中提供。控制台命令检查声明如下所示：

```cs
...
  livenessProbe:
    exec:
      command:
      - cat
      - /tmp/healthy
    initialDelaySeconds: 10
    periodSeconds: 5
 ... 
```

如果`command`返回`0`，则容器被视为健康。在上面的示例中，我们假设在容器中运行的软件将其健康状态记录在`/tmp/healthy`文件中，因此`cat/tmp/healthy`命令返回它。`PeriodSeconds`是检查之间的时间，而`initialDelaySeconds`是执行第一次检查之前的初始延迟。始终需要初始延迟，以便给容器启动的时间。

端点检查非常类似：

```cs
...
  livenessProbe:
    exec:
      httpGet:
        path: /healthz
        port: 8080
        httpHeaders:
          - name: Custom-Health-Header
          value: container-is-ok
    initialDelaySeconds: 10
    periodSeconds: 5
 ... 
```

如果 HTTP 响应包含声明的标头和声明的值，则测试成功。您还可以使用纯 TCP 检查，如下所示：

```cs
...
  livenessProbe:
    exec:
      tcpSocket:
        port: 8080
    initialDelaySeconds: 10
    periodSeconds: 5
 ... 
```

在这种情况下，如果 Kubernetes 能够在声明的端口上打开与容器的 TCP 套接字，则检查成功。

类似地，一旦安装了容器，就会使用就绪性检查来监视容器的就绪性。就绪性检查的定义方式与活跃性检查完全相同，唯一的区别是将`livenessProbe`替换为`readinessProbe`。

以下小节解释了如何自动缩放`Deployments`。

## 自动缩放

与手动修改`Deployment`中的副本数以适应负载的减少或增加不同，我们可以让 Kubernetes 自行决定副本的数量，试图保持声明的资源消耗恒定。因此，例如，如果我们声明目标为 10%的 CPU 消耗，当每个副本的平均资源消耗超过此限制时，将创建一个新副本，而如果平均 CPU 低于此限制，则销毁一个副本。用于监视副本的典型资源是 CPU 消耗，但我们也可以使用内存消耗。

通过定义`HorizontalPodAutoscaler`对象来实现自动缩放。以下是`HorizontalPodAutoscaler`定义的示例：

```cs
apiVersion: autoscaling/v2beta1
kind: HorizontalPodAutoscaler
metadata:
  name: my-autoscaler
spec:
  scaleTargetRef:
    apiVersion: extensions/v1beta1
    kind: Deployment
    name: my-deployment-name
  minReplicas: 1
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      targetAverageUtilization: 25 
```

`spec-> scaleTargetRef->name`指定要自动缩放的`Deployment`的名称，而`targetAverageUtilization`指定目标资源（在我们的情况下是 CPU）的使用百分比（在我们的情况下是 25%）。

以下小节简要介绍了 Helm 软件包管理器和 Helm 图表，并解释了如何在 Kubernetes 集群上安装 Helm 图表。给出了安装`Ingress Controller`的示例。

## Helm - 安装 Ingress Controller

Helm 图表是组织安装包含多个`.yaml`文件的复杂 Kubernetes 应用程序的一种方式。Helm 图表是一组`.yaml`文件，组织成文件夹和子文件夹。以下是从官方文档中获取的 Helm 图表的典型文件夹结构：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_07_06.png)

图 7.6：Helm 图表的文件夹结构

特定于应用程序的`.yaml`文件放置在顶级`templates`目录中，而`charts`目录可能包含其他用作辅助库的 Helm 图表。顶级`Chart.yaml`文件包含有关软件包（名称和描述）的一般信息，以及应用程序版本和 Helm 图表版本。以下是典型示例：

```cs
apiVersion: v2
name: myhelmdemo
description: My Helm chart
type: application
version: 1.3.0
appVersion: 1.2.0 
```

在这里，`type`可以是`application`或`library`。只能部署`application`图表，而`library`图表是用于开发其他图表的实用程序。`library`图表放置在其他 Helm 图表的`charts`文件夹中。

为了配置每个特定应用程序的安装，Helm 图表`.yaml`文件包含在安装 Helm 图表时指定的变量。此外，Helm 图表还提供了一个简单的模板语言，允许仅在满足取决于输入变量的条件时包含一些声明。顶级`values.yaml`文件声明了输入变量的默认值，这意味着开发人员只需要指定几个需要与默认值不同的变量。我们不会描述 Helm 图表模板语言，但您可以在*进一步阅读*部分中找到官方 Helm 文档。

Helm 图表通常以与 Docker 镜像类似的方式组织在公共或私有存储库中。有一个 Helm 客户端，您可以使用它从远程存储库下载软件包，并在 Kubernetes 集群中安装图表。Helm 客户端立即在 Azure Cloud Shell 中可用，因此您可以开始在 Azure Kubernetes 集群中使用 Helm，而无需安装它。

在使用其软件包之前，必须添加远程存储库，如下例所示：

```cs
helm repo add <my-repo-local-name> https://kubernetes-charts.storage.googleapis.com/ 
```

上述命令使远程存储库的软件包可用，并为其指定本地名称。之后，可以使用以下命令安装远程存储库的任何软件包：

```cs
helm install <instance name><my-repo-local-name>/<package name> -n <namespace> 
```

在这里，`<namespace>`是要安装应用程序的命名空间。通常情况下，如果未提供，则假定为`default`命名空间。`<instance name>`是您为安装的应用程序指定的名称。您需要此名称才能使用以下命令获取有关已安装应用程序的信息：

```cs
helm status <instance name> 
```

您还可以使用以下命令获取使用 Helm 安装的所有应用程序的信息：

```cs
helm ls 
```

还需要应用程序名称来通过以下命令从集群中删除应用程序：

```cs
helm delete <instance name> 
```

当我们安装应用程序时，我们还可以提供一个包含要覆盖的所有变量值的`.yaml`文件。我们还可以指定 Helm 图表的特定版本，否则将假定为最新版本。以下是一个同时覆盖版本和值的示例：

```cs
helm install <instance name><my-repo-local-name>/<package name> -f  values.yaml –version <version> 
```

最后，值覆盖也可以通过`--set`选项提供，如下所示：

```cs
...--set <variable1>=<value1>,<variable2>=<value2>... 
```

我们还可以使用`upgrade`命令升级现有的安装，如下所示：

```cs
helm upgrade <instance name><my-repo-local-name>/<package name>... 
```

`upgrade`命令可以使用`-f`选项或`--set`选项指定新的值覆盖，并且可以使用`--version`指定新版本。

让我们使用 Helm 为 guestbook 演示应用程序提供一个`Ingress`。更具体地说，我们将使用 Helm 安装一个基于 Nginx 的`Ingress-Controller`。要遵循的详细过程如下：

1.  添加远程存储库：

```cs
helm repo add gcharts https://kubernetes-charts.storage.googleapis.com/ 
```

1.  安装`Ingress-Controller`：

```cs
helm install ingress gcharts/nginx-ingress 
```

1.  安装完成后，如果键入`kubectl get service`，您应该在已安装的服务中看到已安装的`Ingress-Controller`的条目。该条目应包含一个公共 IP。请记下此 IP，因为它将是应用程序的公共 IP。

1.  打开`frontend.yaml`文件并删除`type: LoadBalancer`行。保存并上传到 Azure Cloud Shell。我们将前端应用程序的服务类型从`LoadBalancer`更改为`ClusterIP`（默认）。此服务将连接到您将要定义的新 Ingress。

1.  使用`kubectl`部署`redis-master.yaml`，`redis-slave.yaml`和`frontend.yaml`，如*部署演示 Guestbook 应用程序*子部分所述。创建一个`frontend-ingress.yaml`文件，并将以下代码放入其中：

```cs
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: simple-frontend-ingress
spec:
  rules:
  - http:
      paths:
      - path:/
        backend:
          serviceName: frontend
          servicePort: 80 
```

1.  将`frontend-ingress.yaml`上传到 Cloud Shell，并使用以下命令部署它：

```cs
kubectl apply -f frontend-ingress.yaml 
```

1.  打开浏览器并导航到您在*步骤 3*中注释的公共 IP。在那里，您应该看到应用程序正在运行。

由于分配给`Ingress-Controller`的公共 IP 在 Azure 的*公共 IP 地址*部分中可用（使用 Azure 搜索框找到它），您可以在那里检索它，并为其分配一个类型为`<chosen name>.<your Azure region>.cloudeapp.com`的主机名。

鼓励您为应用程序公共 IP 分配一个主机名，然后使用此主机名从[`letsencrypt.org/`](https://letsencrypt.org/)获取免费的 HTTPS 证书。获得证书后，可以使用以下命令从中生成一个密钥：

```cs
kubectl create secret tls guestbook-tls --key="tls.key" --cert="tls.crt" 
```

然后，您可以通过将前面的密钥添加到`frontend-ingress.yamlIngress`中，将以下`spec->tls`部分添加到其中：

```cs
...
spec:
...
  tls:
  - hosts:
      - <chosen name>.<your Azure region>.cloudeapp.com
secretName: guestbook-tls 
```

进行更正后，将文件上传到 Azure Cloud Shell，并使用以下内容更新先前的`Ingress`定义：

```cs
kubectl apply frontend-ingress.yaml 
```

此时，您应该能够通过 HTTPS 访问 Guestbook 应用程序。

当您完成实验时，请不要忘记从集群中删除所有内容，以避免浪费您的免费 Azure 信用额度。您可以通过以下命令来完成：

```cs
kubectl delete frontend-ingress.yaml
kubectl delete frontend.yaml
kubectl delete redis-slave.yaml
kubectl delete redis-master.yaml
helm delete ingress 
```

# 摘要

在本章中，我们介绍了 Kubernetes 的基本概念和对象，然后解释了如何创建 Azure Kubernetes 集群。我们还展示了如何部署应用程序，以及如何使用简单的演示应用程序监视和检查集群的状态。

本章还介绍了更高级的 Kubernetes 功能，这些功能在实际应用程序中起着基本作用，包括如何为在 Kubernetes 上运行的容器提供持久存储，如何通知 Kubernetes 容器的健康状态，以及如何提供高级 HTTP 服务，如 HTTPS 和基于名称的虚拟主机。

最后，我们回顾了如何使用 Helm 安装复杂的应用程序，并对 Helm 和 Helm 命令进行了简短的描述。

在下一章中，您将学习如何使用 Entity Framework 将.NET 应用程序与数据库连接。

# 问题

1.  为什么需要服务（Services）？

1.  为什么需要`Ingress`？

1.  为什么需要 Helm？

1.  是否可以在同一个`.yaml`文件中定义多个 Kubernetes 对象？如果可以，如何操作？

1.  Kubernetes 如何检测容器故障？

1.  为什么需要持久卷索赔（Persistent Volume Claims）？

1.  `ReplicaSet`和`StatefulSet`之间有什么区别？

# 进一步阅读

+   一个很好的书籍，可以扩展在本章中获得的知识，是以下这本：[`www.packtpub.com/product/hands-on-kubernetes-on-azure-second-edition/9781800209671`](https://www.packtpub.com/product/hands-on-kubernetes-on-azure-second-edition/9781800209671)。

+   Kubernetes 和`.yaml`文件的官方文档可以在这里找到：[`kubernetes.io/docs/home/`](https://kubernetes.io/docs/home/)。

+   有关 Helm 和 Helm charts 的更多信息可以在官方文档中找到。这些文档写得非常好，包含一些很好的教程：[`helm.sh/`](https://helm.sh/)。

+   Azure Kubernetes 的官方文档可以在这里找到：[`docs.microsoft.com/en-US/azure/aks/`](https://docs.microsoft.com/en-US/azure/aks/)。

+   基于 Azure 应用程序网关的`Ingress Controller`的官方文档可以在这里找到：[`github.com/Azure/application-gateway-kubernetes-ingress`](https://github.com/Azure/application-gateway-kubernetes-ingress)。

+   `Ingress`证书的发布和更新可以按照这里的说明进行自动化：[`docs.microsoft.com/en-us/azure/application-gateway/ingress-controller-letsencrypt-certificate-application-gateway`](https://docs.microsoft.com/en-us/azure/application-gateway/ingress-controller-letsencrypt-certificat)。虽然该过程指定了基于 Azure 应用程序网关的入口控制器，但适用于任何`Ingress Controller`。
