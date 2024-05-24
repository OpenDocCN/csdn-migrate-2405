# Spring 微服务（三）

> 原文：[`zh.annas-archive.org/md5/52026E2A45414F981753F74B874EEB00`](https://zh.annas-archive.org/md5/52026E2A45414F981753F74B874EEB00)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：自动缩放微服务

Spring Cloud 提供了必要的支持，以便在规模上部署微服务。为了充分发挥类似云的环境的全部功能，微服务实例还应能够根据流量模式自动扩展和收缩。

本章将详细介绍如何通过有效使用从 Spring Boot 微服务收集的执行器数据来控制部署拓扑，从而使微服务能够弹性增长和收缩，并实现一个简单的生命周期管理器。

在本章结束时，您将学习以下主题：

+   自动缩放的基本概念和不同的自动缩放方法

+   在微服务的上下文中，生命周期管理器的重要性和能力

+   检查自定义生命周期管理器以实现自动缩放

+   从 Spring Boot 执行器中以编程方式收集统计信息，并将其用于控制和塑造传入流量

# 审查微服务能力模型

本章将涵盖微服务能力模型中讨论的**应用生命周期管理**能力，该能力在第三章中讨论，*应用微服务概念*，如下图所示：

![审查微服务能力模型](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-msvc/img/B05447_6_1.jpg)

在本章中，我们将看到生命周期管理器的基本版本，这将在后续章节中得到增强。

# 使用 Spring Cloud 扩展微服务

在第五章中，*使用 Spring Cloud 扩展微服务*，您学习了如何使用 Spring Cloud 组件扩展 Spring Boot 微服务。我们实现的 Spring Cloud 的两个关键概念是自注册和自发现。这两个能力使得微服务部署自动化。通过自注册，微服务可以在实例准备好接受流量时，通过向中央服务注册表注册服务元数据来自动宣传服务的可用性。一旦微服务注册，消费者就可以通过发现注册表服务实例来从下一刻开始消费新注册的服务。注册表是这种自动化的核心。

这与传统 JEE 应用服务器采用的传统集群方法有很大不同。在 JEE 应用服务器的情况下，服务器实例的 IP 地址在负载均衡器中更多地是静态配置的。因此，在互联网规模的部署中，集群方法并不是自动缩放的最佳解决方案。此外，集群还带来其他挑战，例如它们必须在所有集群节点上具有完全相同的二进制版本。还有可能一个集群节点的故障会因节点之间的紧密依赖关系而影响其他节点。

注册表方法将服务实例解耦。它还消除了在负载均衡器中手动维护服务地址或配置虚拟 IP 的需要：

![使用 Spring Cloud 扩展微服务](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-msvc/img/B05447_6_2.jpg)

如图所示，在我们的自动化微服务部署拓扑中有三个关键组件：

+   **Eureka**是微服务注册和发现的中央注册组件。消费者和提供者都使用 REST API 来访问注册表。注册表还保存服务元数据，如服务标识、主机、端口、健康状态等。

+   **Eureka**客户端与**Ribbon**客户端一起提供客户端动态负载平衡。消费者使用 Eureka 客户端查找 Eureka 服务器，以识别目标服务的可用实例。Ribbon 客户端使用此服务器列表在可用的微服务实例之间进行负载平衡。类似地，如果服务实例停止服务，这些实例将从 Eureka 注册表中移除。负载均衡器会自动对这些动态拓扑变化做出反应。

+   第三个组件是使用 Spring Boot 开发的**微服务**实例，并启用了执行器端点。

然而，这种方法存在一个缺陷。当需要额外的微服务实例时，需要手动启动一个新实例。在理想情况下，启动和停止微服务实例也需要自动化。

例如，当需要添加另一个搜索微服务实例来处理流量增加或负载突发情况时，管理员必须手动启动一个新实例。同样，当搜索实例一段时间处于空闲状态时，需要手动将其从服务中移除，以实现最佳的基础设施使用。这在服务在按使用量付费的云环境中尤为重要。

# 理解自动扩展的概念

自动扩展是一种根据资源使用情况自动扩展实例的方法，以通过复制要扩展的服务来满足 SLA。

系统会自动检测流量增加，启动额外的实例，并使它们可用于处理流量。同样，当流量减少时，系统会自动检测并通过将活动实例从服务中收回来减少实例数量：

![理解自动扩展的概念](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-msvc/img/B05447_6_3.jpg)

如前图所示，通常使用一组预留机器来进行自动扩展。

由于许多云订阅都是基于按使用量付费的模式，因此在针对云部署时，这是一种必要的能力。这种方法通常被称为**弹性**。它也被称为**动态资源配置和取消配置**。自动扩展是一种针对具有不同流量模式的微服务的有效方法。例如，会计服务在月末和年末流量会很高。永久预留实例来处理这些季节性负载是没有意义的。

在自动扩展方法中，通常有一个资源池，其中有一些备用实例。根据需求，实例将从资源池移动到活动状态，以满足多余的需求。这些实例没有预先标记为任何特定的微服务，也没有预先打包任何微服务二进制文件。在高级部署中，Spring Boot 二进制文件可以根据需要从 Nexus 或 Artifactory 等存储库中下载。

## 自动扩展的好处

实施自动扩展机制有许多好处。在传统部署中，管理员针对每个应用程序预留一组服务器。通过自动扩展，不再需要这种预分配。这种预分配的服务器可能导致服务器利用不足。在这种情况下，即使相邻服务需要额外的资源，空闲服务器也无法利用。

对于数百个微服务实例，为每个微服务预分配固定数量的服务器并不划算。更好的方法是为一组微服务预留一定数量的服务器实例，而不是预先分配或标记它们与微服务相关。根据需求，一组服务可以共享一组可用资源。通过这种方式，微服务可以通过最佳地利用资源在可用的服务器实例之间动态移动：

![自动扩展的好处](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-msvc/img/B05447_6_4.jpg)

如前图所示，**M1**微服务有三个实例，**M2**有一个实例，**M3**有一个实例正在运行。还有另一台服务器保持未分配。根据需求，未分配的服务器可以用于任何微服务：**M1**、**M2**或**M3**。如果**M1**有更多的服务请求，那么未分配的实例将用于**M1**。当服务使用量下降时，服务器实例将被释放并移回池中。稍后，如果**M2**的需求增加，同一服务器实例可以使用**M2**激活。

自动扩展的一些关键好处包括：

+   **它具有高可用性和容错性**：由于存在多个服务实例，即使一个失败，另一个实例也可以接管并继续为客户提供服务。这种故障转移对消费者来说是透明的。如果此服务没有其他实例可用，自动扩展服务将识别此情况并启动另一台带有服务实例的服务器。由于启动或关闭实例的整个过程是自动的，因此服务的整体可用性将高于没有自动扩展的系统。没有自动扩展的系统需要手动干预以添加或删除服务实例，在大规模部署中将很难管理。

例如，假设有两个**预订**服务实例正在运行。如果流量增加，通常情况下，现有实例可能会过载。在大多数情况下，整套服务将被堵塞，导致服务不可用。在自动扩展的情况下，可以快速启动新的**预订**服务实例。这将平衡负载并确保服务可用性。

+   **它增加了可伸缩性**：自动扩展的关键好处之一是水平可伸缩性。自动扩展允许我们根据流量模式自动选择性地扩展或缩减服务。

+   **它具有最佳的使用和节省成本**：在按使用量付费的订阅模型中，计费是基于实际资源利用率的。采用自动扩展方法，实例将根据需求启动和关闭。因此，资源得到了最佳利用，从而节省成本。

+   **它优先考虑某些服务或服务组**：通过自动扩展，可以优先考虑某些关键交易而不是低价值交易。这将通过从低价值服务中移除实例并重新分配给高价值服务来实现。这也将消除低优先级交易在高价值交易因资源不足而受阻时大量利用资源的情况。![自动扩展的好处](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-msvc/img/B05447_6_5.jpg)

例如，**预订**和**报告**服务以两个实例运行，如前图所示。假设**预订**服务是一个收入生成服务，因此价值高于**报告**服务。如果对**预订**服务的需求更大，那么可以设置策略将一个**报告**服务从服务中移除，并释放此服务器供**预订**服务使用。

## 不同的自动扩展模型

自动扩展可以应用于应用程序级别或基础设施级别。简而言之，应用程序扩展是通过仅复制应用程序二进制文件进行扩展，而基础设施扩展是复制整个虚拟机，包括应用程序二进制文件。

### 应用程序的自动扩展

在这种情况下，扩展是通过复制微服务而不是底层基础设施（如虚拟机）来完成的。假设有一组可用于扩展微服务的 VM 或物理基础设施。这些 VM 具有基本镜像，以及诸如 JRE 之类的任何依赖项。还假设微服务在性质上是同质的。这样可以灵活地重用相同的虚拟或物理机器来运行不同的服务：

![自动扩展应用程序](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-msvc/img/B05447_6_6.jpg)

如前图所示，在**场景 A**中，**VM3**用于**Service 1**，而在**场景 B**中，相同的**VM3**用于**Service 2**。在这种情况下，我们只交换了应用程序库，而没有交换底层基础设施。

这种方法可以更快地实例化，因为我们只处理应用程序二进制文件，而不是底层的虚拟机。切换更容易更快，因为二进制文件体积较小，也不需要操作系统启动。然而，这种方法的缺点是，如果某些微服务需要操作系统级调整或使用多语言技术，那么动态交换微服务将不会有效。

### 云中的自动扩展

与前一种方法相比，在这种情况下，基础设施也是自动配置的。在大多数情况下，这将根据需求创建新的 VM 或销毁 VM：

![自动扩展基础设施](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-msvc/img/B05447_6_7.jpg)

如前图所示，保留实例是作为具有预定义服务实例的 VM 映像创建的。当对**Service 1**有需求时，**VM3**被移动到活动状态。当对**Service 2**有需求时，**VM4**被移动到活动状态。

如果应用程序依赖于基础设施级别的参数和库，例如操作系统，这种方法是有效的。此外，这种方法对于多语言微服务更好。缺点是 VM 镜像的重量级和启动新 VM 所需的时间。在这种情况下，与传统的重量级虚拟机相比，轻量级容器（如 Docker）更受青睐。

## 云中的自动扩展

弹性或自动扩展是大多数云提供商的基本功能之一。云提供商使用基础设施扩展模式，如前一节所讨论的。这些通常基于一组池化的机器。

例如，在 AWS 中，这是基于引入具有预定义 AMI 的新 EC2 实例。AWS 支持使用自动扩展组来进行自动扩展。每个组都设置了最小和最大数量的实例。AWS 确保在这些范围内根据需求进行实例扩展。在可预测的流量模式下，可以根据时间表配置预配。AWS 还提供了应用程序自定义自动扩展策略的能力。

Microsoft Azure 还支持根据 CPU、消息队列长度等资源利用率进行自动扩展。IBM Bluemix 支持根据 CPU 使用率进行自动扩展。

其他 PaaS 平台，如 CloudBees 和 OpenShift，也支持 Java 应用程序的自动扩展。Pivotal Cloud Foundry 通过 Pivotal Autoscale 支持自动扩展。扩展策略通常基于资源利用率，如 CPU 和内存阈值。

有一些组件在云顶部运行，并提供细粒度的控制来处理自动扩展。Netflix Fenzo、Eucalyptus、Boxfuse 和 Mesosphere 是这一类组件中的一些。

# 自动扩展方法

自动扩展是通过考虑不同的参数和阈值来处理的。在本节中，我们将讨论通常应用于决定何时扩展或缩小的不同方法和策略。

## 根据资源约束进行扩展

这种方法是基于通过监控机制收集的实时服务指标。通常，资源扩展方法是基于机器的 CPU、内存或磁盘做出决策。也可以通过查看服务实例本身收集的统计数据来实现，比如堆内存使用情况。

典型的策略可能是当机器的 CPU 利用率超过 60%时，启动另一个实例。同样，如果堆大小超过一定阈值，我们可以添加一个新实例。资源利用率低于设定阈值时，也可以缩减计算能力。这是通过逐渐关闭服务器来实现的：

![受资源约束的扩展](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-msvc/img/B05447_6_8.jpg)

在典型的生产场景中，不会在第一次阈值违规时创建额外的服务。最合适的方法是定义一个滑动窗口或等待期。

以下是一些例子：

+   **响应滑动窗口**的一个例子是，如果特定交易的 60%响应时间在 60 秒的采样窗口中一直超过设定的阈值，就增加服务实例

+   在**CPU 滑动窗口**中，如果 CPU 利用率在 5 分钟的滑动窗口中一直超过 70%，那么会创建一个新实例

+   **异常滑动窗口**的一个例子是，如果在 60 秒的滑动窗口中有 80%的交易或连续 10 次执行导致特定系统异常，比如由于线程池耗尽而导致连接超时，那么会创建一个新的服务实例

在许多情况下，我们会将实际预期的阈值设定为较低的阈值。例如，不是将 CPU 利用率阈值设定为 80%，而是设定为 60%，这样系统有足够的时间来启动一个实例，而不会停止响应。同样，在缩减规模时，我们会使用比实际阈值更低的阈值。例如，我们将使用 40%的 CPU 利用率来缩减规模，而不是 60%。这样可以让我们有一个冷却期，以便在关闭实例时不会出现资源竞争。

基于资源的扩展也适用于服务级参数，如服务的吞吐量、延迟、应用程序线程池、连接池等。这些也可以是在应用程序级别，比如基于内部基准测试的服务实例中处理的**销售订单**数量。

## 特定时间段的扩展

基于时间的扩展是一种根据一天、一个月或一年的某些时段来扩展服务的方法，以处理季节性或业务高峰。例如，一些服务可能在办公时间内经历更多的交易，而在非办公时间内交易数量明显较少。在这种情况下，白天，服务会自动扩展以满足需求，并在非办公时间自动缩减：

![特定时间段的扩展](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-msvc/img/B05447_6_9.jpg)

全球许多机场对夜间着陆施加限制。因此，与白天相比，夜间在机场办理登机手续的乘客数量较少。因此，在夜间减少实例数量是成本有效的。

## 基于消息队列长度的扩展

当微服务基于异步消息传递时，这种方法特别有用。在这种方法中，当队列中的消息超过一定限制时，会自动添加新的消费者：

![基于消息队列长度的扩展](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-msvc/img/B05447_6_10.jpg)

这种方法是基于竞争消费者模式。在这种情况下，一组实例用于消费消息。根据消息阈值，会添加新实例来消费额外的消息。

## 基于业务参数的扩展

在这种情况下，增加实例是基于某些业务参数的，例如，在处理**销售结束**交易之前立即启动一个新实例。一旦监控服务接收到预先配置的业务事件（例如**销售结束前 1 小时**），将会预先启动一个新实例，以预期大量交易。这将根据业务规则提供基于细粒度控制的扩展：

![基于业务参数的扩展](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-msvc/img/B05447_6_11.jpg)

## 预测自动扩展

预测扩展是一种新的自动扩展范式，不同于传统的基于实时指标的自动扩展。预测引擎将采用多个输入，例如历史信息，当前趋势等，来预测可能的流量模式。根据这些预测进行自动扩展。预测自动扩展有助于避免硬编码规则和时间窗口。相反，系统可以自动预测这些时间窗口。在更复杂的部署中，预测分析可能使用认知计算机制来预测自动扩展。

在突发流量激增的情况下，传统的自动扩展可能无法帮助。在自动扩展组件能够对情况做出反应之前，激增已经发生并损害了系统。预测系统可以理解这些情况并在它们实际发生之前进行预测。一个例子是在计划的停机后立即处理一大堆请求。

Netflix Scryer 是这样一个系统的例子，它可以提前预测资源需求。

# 自动扩展 BrownField PSS 微服务

在本节中，我们将研究如何增强第五章中开发的微服务，*使用 Spring Cloud 扩展微服务*，以实现自动扩展。我们需要一个组件来监视某些性能指标并触发自动扩展。我们将称这个组件为**生命周期管理器**。

服务生命周期管理器或应用程序生命周期管理器负责检测扩展需求并相应地调整实例数量。它负责动态启动和关闭实例。

在本节中，我们将研究一个原始的自动扩展系统，以了解基本概念，这将在后面的章节中得到增强。

## 自动扩展系统所需的功能

典型的自动扩展系统具有以下图表中显示的功能：

![自动扩展系统所需的功能](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-msvc/img/B05447_6_12.jpg)

在微服务的自动扩展生态系统中涉及的组件如下所述：

+   **微服务**：这些是一组正在运行的微服务实例，它们不断发送健康和指标信息。或者，这些服务公开执行器端点以进行指标收集。在前面的图表中，这些被表示为**微服务 1**到**微服务 4**。

+   **服务注册表**：服务注册表跟踪所有服务、它们的健康状态、它们的元数据和它们的端点 URI。

+   **负载均衡器**：这是一个客户端负载均衡器，它查找服务注册表以获取有关可用服务实例的最新信息。

+   **生命周期管理器**：生命周期管理器负责自动扩展，具有以下子组件：

+   **指标收集器**：指标收集单元负责从所有服务实例收集指标。生命周期管理器将汇总这些指标。它还可以保持一个滑动时间窗口。这些指标可以是基础设施级别的指标，例如 CPU 使用率，也可以是应用程序级别的指标，例如每分钟的交易数。

+   **扩展策略**：扩展策略只是指示何时扩展和缩小微服务的一组规则，例如，在 5 分钟的滑动时间窗口内，CPU 使用率超过 60%的 90%。

+   **决策引擎**：决策引擎负责根据汇总的指标和扩展策略做出扩展或缩减的决策。

+   **部署规则**：部署引擎使用部署规则来决定部署服务时要考虑哪些参数。例如，服务部署约束可能要求实例必须分布在多个可用区域，或者服务需要至少 4GB 的内存。

+   **部署引擎**：基于决策引擎的决策，部署引擎可以启动或停止微服务实例，或通过改变服务的健康状态来更新注册表。例如，它将健康状态设置为“暂时停用”以暂时移除服务。

## 使用 Spring Boot 实现自定义生命周期管理器

本节介绍的生命周期管理器是一个最小实现，用于理解自动扩展的能力。在后面的章节中，我们将使用容器和集群管理解决方案来增强这个实现。Ansible、Marathon 和 Kubernetes 是一些有用的工具，用于构建这种能力。

在本节中，我们将使用 Spring Boot 为第五章中开发的服务实现一个应用级自动扩展组件，*使用 Spring Cloud 扩展微服务*。

## 理解部署拓扑

以下图表显示了 BrownField PSS 微服务的示例部署拓扑：

![理解部署拓扑](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-msvc/img/B05447_6_13.jpg)

如图所示，有四台物理机器。从四台物理机器创建了八个虚拟机。每台物理机器能够承载两个虚拟机，每个虚拟机能够运行两个 Spring Boot 实例，假设所有服务具有相同的资源需求。

四台虚拟机**VM1**到**VM4**是活动的，用于处理流量。**VM5**到**VM8**被保留用于处理可扩展性。**VM5**和**VM6**可以用于任何微服务，并且也可以根据扩展需求在微服务之间切换。冗余服务使用来自不同物理机器创建的虚拟机，以提高容错性。

我们的目标是在流量增加时使用四个虚拟机**VM5**到**VM8**扩展任何服务，并在负载不足时缩减。我们解决方案的架构如下。

## 理解执行流程

请查看以下流程图：

![理解执行流程](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-msvc/img/B05447_6_14.jpg)

如前图所示，以下活动对我们很重要：

+   Spring Boot 服务代表了诸如搜索、预订、票价和办理登机等微服务。这些服务在启动时会自动将端点详细信息注册到 Eureka 注册表。这些服务启用了执行器，因此生命周期管理器可以从执行器端点收集指标。

+   生命周期管理器服务实际上就是另一个 Spring Boot 应用程序。生命周期管理器具有一个指标收集器，它运行一个后台作业，定期轮询 Eureka 服务器，并获取所有服务实例的详细信息。然后，指标收集器调用 Eureka 注册表中注册的每个微服务的执行器端点，以获取健康和指标信息。在真实的生产场景中，采用订阅方法进行数据收集更好。

+   通过收集的指标信息，生命周期管理器执行一系列策略，并根据这些策略决定是否扩展或缩减实例。这些决策要么是在特定虚拟机上启动特定类型的新服务实例，要么是关闭特定实例。

+   在关闭的情况下，它使用执行器端点连接到服务器，并调用关闭服务来优雅地关闭一个实例。

+   在启动新实例的情况下，生命周期管理器的部署引擎使用扩展规则并决定在哪里启动新实例以及启动实例时要使用的参数。然后，它使用 SSH 连接到相应的 VM。一旦连接，它通过传递所需的约束作为参数来执行预安装的脚本（或将此脚本作为执行的一部分）。此脚本从中央 Nexus 存储库中获取应用程序库，其中保存了生产二进制文件，并将其初始化为 Spring Boot 应用程序。端口号由生命周期管理器参数化。目标机器上需要启用 SSH。

在本例中，我们将使用**TPM**（**每分钟事务数**）或**RPM**（**每分钟请求数**）作为决策的采样指标。如果搜索服务的 TPM 超过 10，那么它将启动一个新的搜索服务实例。同样，如果 TPM 低于 2，其中一个实例将被关闭并释放回池中。

在启动新实例时，将应用以下策略：

+   任何时候的服务实例数应该至少为 1，最多为 4。这也意味着至少一个服务实例将始终处于运行状态。

+   定义了一个扩展组，以便在不同物理机器上创建一个新实例的 VM 上。这将确保服务在不同的物理机器上运行。

这些策略可以进一步增强。生命周期管理器理想情况下提供通过 REST API 或 Groovy 脚本自定义这些规则的选项。

## 生命周期管理器代码演示

我们将看一下如何实现一个简单的生命周期管理器。本节将演示代码，以了解生命周期管理器的不同组件。

### 提示

完整的源代码在代码文件中的`第六章`项目中可用。`chapter5.configserver`，`chapter5.eurekaserver`，`chapter5.search`和`chapter5.search-apigateway`分别复制并重命名为`chapter6.*`。

执行以下步骤来实现自定义生命周期管理器：

1.  创建一个新的 Spring Boot 应用程序，并将其命名为`chapter6.lifecyclemanager`。项目结构如下图所示：![生命周期管理器代码演示](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-msvc/img/B05447_6_15.jpg)

此示例的流程图如下图所示：

![生命周期管理器代码演示](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-msvc/img/B05447_6_16.jpg)

此图的组件在此处详细解释。

1.  创建一个`MetricsCollector`类，其中包含以下方法。在 Spring Boot 应用程序启动时，将使用`CommandLineRunner`调用此方法，如下所示：

```java
public void start(){
  while(true){ 
    eurekaClient.getServices().forEach(service -> {        System.out.println("discovered service "+ service);
      Map metrics = restTemplate.getForObject("http://"+service+"/metrics",Map.class);
      decisionEngine.execute(service, metrics);
    });  
  }    
}
```

前面的方法查找在 Eureka 服务器中注册的服务并获取所有实例。在现实世界中，实例应该发布指标到一个共同的地方，指标聚合将在那里发生，而不是轮询。

1.  以下的`DecisionEngine`代码接受指标并应用特定的扩展策略来确定服务是否需要扩展：

```java
  public boolean execute(String serviceId, Map metrics){
  if(scalingPolicies.getPolicy(serviceId).execute(serviceId, metrics)){    
      return deploymentEngine.scaleUp(deploymentRules.getDeploymentRules(serviceId), serviceId);  
    }
    return false;
  }
```

1.  根据服务 ID，将挑选并应用与服务相关的策略。在这种情况下，`TpmScalingPolicy`中实现了最小 TPM 扩展策略，如下所示：

```java
public class TpmScalingPolicy implements ScalingPolicy {
  public boolean execute(String serviceId, Map metrics){
    if(metrics.containsKey("gauge.servo.tpm")){
      Double tpm = (Double) metrics.get("gauge.servo.tpm");
      System.out.println("gauge.servo.tpm " + tpm);
      return (tpm > 10);
    }
    return false;
  }
}
```

1.  如果策略返回`true`，`DecisionEngine`将调用`DeploymentEngine`来启动另一个实例。`DeploymentEngine`使用`DeploymentRules`来决定如何执行扩展。规则可以强制执行最小和最大实例数，在哪个区域或机器上启动新实例，新实例所需的资源等。`DummyDeploymentRule`只需确保最大实例数不超过 2。

1.  在这种情况下，`DeploymentEngine`使用 JCraft 的**JSch**（**Java Secure Channel**）库来 SSH 到目标服务器并启动服务。这需要以下额外的 Maven 依赖项：

```java
<dependency>
    <groupId>com.jcraft</groupId>
    <artifactId>jsch</artifactId>
    <version>0.1.53</version>
</dependency>
```

1.  当前的 SSH 实现足够简单，因为我们将在未来的章节中更改它。在这个例子中，`DeploymentEngine`通过 SSH 库向目标机器发送以下命令：

```java
 String command ="java -jar -Dserver.port=8091 ./work/codebox/chapter6/chapter6.search/target/search-1.0.jar";

```

与 Nexus 的集成是通过目标机器使用带有 Nexus CLI 的 Linux 脚本或使用`curl`来完成的。在这个例子中，我们不会探索 Nexus。

1.  下一步是更改搜索微服务以公开一个新的 TPM 量规。我们必须更改之前开发的所有微服务以提交这个额外的指标。

本章我们只会检查搜索，但为了完成它，所有服务都必须更新。为了获得 `gauge.servo.tpm` 指标，我们必须在所有微服务中添加 `TPMCounter`。

以下代码计算了一个滑动窗口内的交易次数：

```java
class TPMCounter {
  LongAdder count;
  Calendar expiry = null; 
  TPMCounter(){
    reset();
  }  
  void reset (){
    count = new LongAdder();
    expiry = Calendar.getInstance();
    expiry.add(Calendar.MINUTE, 1);
  }
  boolean isExpired(){
    return Calendar.getInstance().after(expiry);
  }
  void increment(){
     if(isExpired()){
       reset();
     }
     count.increment();
  }
}
```

1.  以下代码需要添加到`SearchController`中以设置`tpm`值：

```java
class SearchRestController {
  TPMCounter tpm = new TPMCounter();
  @Autowired
  GaugeService gaugeService;
   //other code 
```

1.  以下代码来自`SearchRestController`的 get REST 端点（搜索方法），它将`tpm`值作为量规提交给执行器端点：

```java
tpm.increment();
gaugeService.submit("tpm", tpm.count.intValue()); 
```

## 运行生命周期管理器

执行以下步骤来运行前一节中开发的生命周期管理器：

1.  编辑`DeploymentEngine.java`并更新密码以反映机器的密码，如下所示。这是 SSH 连接所需的：

```java
session.setPassword("rajeshrv");
```

1.  通过从根文件夹（`第六章`）运行 Maven 来构建所有项目，使用以下命令：

```java
mvn -Dmaven.test.skip=true clean install

```

1.  然后，按以下方式运行 RabbitMQ：

```java
./rabbitmq-server

```

1.  确保配置服务器指向正确的配置存储库。我们需要为生命周期管理器添加一个属性文件。

1.  从各自的项目文件夹运行以下命令：

```java
java -jar target/config-server-0.0.1-SNAPSHOT.jar
java -jar target/eureka-server-0.0.1-SNAPSHOT.jar
java -jar target/lifecycle-manager-0.0.1-SNAPSHOT.jar
java -jar target/search-1.0.jar
java -jar target/search-apigateway-1.0.jar
java -jar target/website-1.0.jar

```

1.  一旦所有服务都启动了，打开浏览器窗口并加载 `http://localhost:8001`。

1.  连续执行 11 次航班搜索，在一分钟内依次执行。这将触发决策引擎实例化搜索微服务的另一个实例。

1.  打开 Eureka 控制台（`http://localhost:8761`）并观察第二个**SEARCH-SERVICE**。一旦服务器启动，实例将如下所示出现：![运行生命周期管理器](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-msvc/img/B05447_6_17.jpg)

# 摘要

在本章中，您了解了在部署大规模微服务时自动缩放的重要性。

我们还探讨了自动缩放的概念以及自动缩放的不同模型和方法，例如基于时间、基于资源、基于队列长度和预测性的方法。然后我们审查了生命周期管理器在微服务环境中的作用并审查了它的能力。最后，我们通过审查一个简单的自定义生命周期管理器的示例实现来结束本章，该示例是在 BrownField PSS 微服务环境中。

自动缩放是处理大规模微服务时所需的重要支持能力。我们将在第九章中讨论生命周期管理器的更成熟的实现，*使用 Mesos 和 Marathon 管理 Docker 化的微服务*。

下一章将探讨对于成功的微服务部署至关重要的日志记录和监控能力。


# 第七章：微服务的日志记录和监控

由于互联网规模微服务部署的分布式特性，最大的挑战之一是对单个微服务进行日志记录和监控。通过相关不同微服务发出的日志来跟踪端到端事务是困难的。与单片应用程序一样，没有单一的监控窗格来监视微服务。

本章将介绍微服务部署中日志记录和监控的必要性和重要性。本章还将进一步探讨解决日志记录和监控的挑战和解决方案，涉及多种潜在的架构和技术。

通过本章结束时，您将了解以下内容：

+   日志管理的不同选项、工具和技术

+   在跟踪微服务中使用 Spring Cloud Sleuth

+   微服务端到端监控的不同工具

+   使用 Spring Cloud Hystrix 和 Turbine 进行电路监控

+   使用数据湖来实现业务数据分析

# 审查微服务能力模型

在本章中，我们将从第三章中讨论的微服务能力模型中探讨以下微服务能力：

+   **中央日志管理**

+   **监控和仪表板**

+   **依赖管理**（监控和仪表板的一部分）

+   **数据湖**

![审查微服务能力模型](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-msvc/img/B05447_07_01.jpg)

# 了解日志管理的挑战

日志只是来自运行进程的事件流。对于传统的 JEE 应用程序，有许多框架和库可用于日志记录。Java Logging（JUL）是 Java 本身提供的一个选项。Log4j、Logback 和 SLF4J 是其他一些流行的日志记录框架。这些框架支持 UDP 和 TCP 协议进行日志记录。应用程序将日志条目发送到控制台或文件系统。通常采用文件回收技术来避免日志填满所有磁盘空间。

日志处理的最佳实践之一是在生产环境中关闭大部分日志条目，因为磁盘 IO 的成本很高。磁盘 IO 不仅会减慢应用程序的速度，还会严重影响可伸缩性。将日志写入磁盘还需要高磁盘容量。磁盘空间不足的情况可能导致应用程序崩溃。日志框架提供了在运行时控制日志以限制打印内容的选项。这些框架大多提供对日志控制的细粒度控制。它们还提供在运行时更改这些配置的选项。

另一方面，如果适当分析，日志可能包含重要信息并具有很高的价值。因此，限制日志条目基本上限制了我们理解应用程序行为的能力。

从传统部署到云部署后，应用程序不再锁定到特定的预定义机器。虚拟机和容器不是与应用程序硬连接的。用于部署的机器可能会不时更改。此外，诸如 Docker 之类的容器是短暂的。这基本上意味着不能依赖磁盘的持久状态。一旦容器停止并重新启动，写入磁盘的日志就会丢失。因此，我们不能依赖本地机器的磁盘来写入日志文件。

正如我们在第一章中讨论的那样，*解密微服务*，十二要素应用程序的原则之一是避免应用程序自身路由或存储日志文件。在微服务的情况下，它们将在隔离的物理或虚拟机上运行，导致日志文件分散。在这种情况下，几乎不可能跟踪跨多个微服务的端到端事务：

![了解日志管理的挑战](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-msvc/img/B05447_07_02.jpg)

如图所示，每个微服务都会向本地文件系统发出日志。在这种情况下，微服务 M1 调用 M3。这些服务将它们的日志写入自己的本地文件系统。这使得难以关联和理解端到端的事务流。此外，如图所示，有两个 M1 的实例和两个 M2 的实例在两台不同的机器上运行。在这种情况下，很难实现对服务级别的日志聚合。

# 集中式日志解决方案

为了解决前面提到的挑战，传统的日志解决方案需要认真重新思考。新的日志解决方案除了解决前面提到的挑战外，还应该支持以下总结的能力：

+   能够收集所有日志消息并对其进行分析

+   能够关联和跟踪端到端的交易

+   能够保留日志信息以进行趋势分析和预测的更长时间段

+   消除对本地磁盘系统的依赖能力

+   能够聚合来自多个来源的日志信息，如网络设备、操作系统、微服务等

解决这些问题的方法是集中存储和分析所有日志消息，而不管日志的来源是什么。新日志解决方案采用的基本原则是将日志存储和处理与服务执行环境分离。与在微服务执行环境中存储和处理大量日志消息相比，大数据解决方案更适合存储和处理大量日志消息。

在集中式日志解决方案中，日志消息将从执行环境发货到中央大数据存储。日志分析和处理将使用大数据解决方案进行处理：

![集中式日志解决方案](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-msvc/img/B05447_07_03.jpg)

如前面的逻辑图所示，集中式日志解决方案中有许多组件，如下所示：

+   日志流：这些是源系统输出的日志消息流。源系统可以是微服务、其他应用程序，甚至是网络设备。在典型的基于 Java 的系统中，这相当于流式处理 Log4j 日志消息。

+   日志发货人：日志发货人负责收集来自不同来源或端点的日志消息。然后，日志发货人将这些消息发送到另一组端点，例如写入数据库，推送到仪表板，或将其发送到流处理端点进行进一步的实时处理。

+   日志存储：日志存储是存储所有日志消息以进行实时分析、趋势分析等的地方。通常，日志存储是一个能够处理大数据量的 NoSQL 数据库，例如 HDFS。

+   日志流处理器：日志流处理器能够分析实时日志事件以进行快速决策。流处理器会采取行动，如向仪表板发送信息、发送警报等。在自愈系统的情况下，流处理器甚至可以采取行动来纠正问题。

+   日志仪表板：仪表板是用于显示日志分析结果的单一窗格，如图表和图形。这些仪表板是为运营和管理人员准备的。

这种集中式方法的好处是没有本地 I/O 或阻塞磁盘写入。它也不使用本地机器的磁盘空间。这种架构在根本上类似于大数据处理的 Lambda 架构。

### 注意

要了解更多关于 Lambda 架构的信息，请访问[`lambda-architecture.net`](http://lambda-architecture.net)。

每条日志消息中都需要有上下文、消息和关联 ID。上下文通常包括时间戳、IP 地址、用户信息、进程详细信息（如服务、类和函数）、日志类型、分类等。消息将是简单的自由文本信息。关联 ID 用于建立服务调用之间的链接，以便跨微服务的调用可以被追踪。

# 日志解决方案的选择

有多种选择可用于实现集中式日志记录解决方案。这些解决方案使用不同的方法、架构和技术。重要的是要了解所需的功能，并选择满足需求的正确解决方案。

## 云服务

有许多云日志服务可用，例如 SaaS 解决方案。

Loggly 是最受欢迎的基于云的日志服务之一。Spring Boot 微服务可以使用 Loggly 的 Log4j 和 Logback appender 直接将日志消息流式传输到 Loggly 服务中。

如果应用程序或服务部署在 AWS 上，AWS CloudTrail 可以与 Loggly 集成进行日志分析。

Papertrial、Logsene、Sumo Logic、Google Cloud Logging 和 Logentries 是其他基于云的日志解决方案的例子。

云日志服务通过提供简单易集成的服务，消除了管理复杂基础设施和大型存储解决方案的开销。然而，在选择云日志服务时，延迟是需要考虑的关键因素之一。

## 现成的解决方案

有许多专门设计的工具，可以在本地数据中心或云中安装，提供端到端的日志管理功能。

Graylog 是流行的开源日志管理解决方案之一。Graylog 使用 Elasticsearch 进行日志存储，使用 MongoDB 作为元数据存储。Graylog 还使用 GELF 库进行 Log4j 日志流式传输。

Splunk 是一种流行的商业工具，用于日志管理和分析。与其他解决方案使用日志流式传输相比，Splunk 使用日志文件传输方法来收集日志。

## 最佳集成

最后一种方法是选择最佳的组件并构建自定义的日志解决方案。

### 日志收集器

有一些日志收集器可以与其他工具结合使用，构建端到端的日志管理解决方案。不同的日志收集工具之间的功能有所不同。

Logstash 是一个强大的数据管道工具，可用于收集和传输日志文件。Logstash 充当代理，提供一种接受来自不同来源的流数据并将其同步到不同目的地的机制。Log4j 和 Logback appender 也可以用于将日志消息直接从 Spring Boot 微服务发送到 Logstash。Logstash 的另一端连接到 Elasticsearch、HDFS 或任何其他数据库。

Fluentd 是另一个与 Logstash 非常相似的工具，Logspout 也是如此，但后者更适合基于 Docker 容器的环境。

### 日志流处理器

流处理技术可选择用于即时处理日志流。例如，如果 404 错误持续作为对特定服务调用的响应发生，这意味着服务出现了问题。这种情况必须尽快处理。在这种情况下，流处理器非常有用，因为它们能够对传统的反应式分析无法处理的某些事件流做出反应。

用于流处理的典型架构是将 Flume 和 Kafka 与 Storm 或 Spark Streaming 结合在一起。Log4j 具有 Flume appender，用于收集日志消息。这些消息被推送到分布式 Kafka 消息队列中。流处理器从 Kafka 收集数据，并在发送到 Elasticsearch 和其他日志存储之前即时处理它们。

Spring Cloud Stream、Spring Cloud Stream 模块和 Spring Cloud Data Flow 也可用于构建日志流处理。

### 日志存储

实时日志消息通常存储在 Elasticsearch 中。Elasticsearch 允许客户端基于文本索引进行查询。除了 Elasticsearch，HDFS 也常用于存储归档的日志消息。MongoDB 或 Cassandra 用于存储月度聚合交易计数等摘要数据。离线日志处理可以使用 Hadoop 的 MapReduce 程序来完成。

### 仪表板

中央日志解决方案所需的最后一部分是仪表板。用于日志分析的最常用的仪表板是基于 Elasticsearch 数据存储的 Kibana。Graphite 和 Grafana 也用于显示日志分析报告。

## 自定义日志实现

之前提到的工具可以用来构建自定义端到端的日志解决方案。自定义日志管理最常用的架构是 Logstash、Elasticsearch 和 Kibana 的组合，也称为 ELK 堆栈。

### 注意

本章的完整源代码可在代码文件的“第七章”项目下找到。将`chapter5.configserver`、`chapter5.eurekaserver`、`chapter5.search`、`chapter5.search-apigateway`和`chapter5.website`复制到一个新的 STS 工作空间中，并将它们重命名为`chapter7.*`。

以下图显示了日志监控流程：

![自定义日志实现](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-msvc/img/B05447_07_04.jpg)

在本节中，将研究使用 ELK 堆栈的自定义日志解决方案的简单实现。

按照以下步骤实现用于日志记录的 ELK 堆栈：

1.  从[`www.elastic.co`](https://www.elastic.co)下载并安装 Elasticsearch、Kibana 和 Logstash。

1.  更新 Search 微服务（chapter7.search）。审查并确保 Search 微服务中有一些日志语句。日志语句并不特别，只是使用`slf4j`进行简单的日志记录。

```java
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
  //other code goes here
  private static final Logger logger = LoggerFactory.getLogger(SearchRestController.class);
//other code goes here

logger.info("Looking to load flights...");
for (Flight flight : flightRepository.findByOriginAndDestinationAndFlightDate("NYC", "SFO", "22-JAN-16")) {
      logger.info(flight.toString());
}
```

1.  在 Search 服务的`pom.xml`文件中添加`logstash`依赖项，以将`logback`集成到 Logstash 中，如下所示：

```java
<dependency>
  <groupId>net.logstash.logback</groupId>
  <artifactId>logstash-logback-encoder</artifactId>
  <version>4.6</version>
</dependency>
```

1.  此外，通过以下行将`logback`版本降级以与 Spring 1.3.5.RELEASE 兼容：

```java
<logback.version>1.1.6</logback.version>
```

1.  覆盖默认的 Logback 配置。可以通过在`src/main/resources`下添加一个新的`logback.xml`文件来完成，如下所示：

```java
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <include resource="org/springframework/boot/logging/logback/defaults.xml"/>
  <include resource="org/springframework/boot/logging/logback/console-appender.xml" />
    <appender name="stash" class="net.logstash.logback.appender.LogstashTcpSocketAppender">
        <destination>localhost:4560</destination>
        <!-- encoder is required -->
        <encoder class="net.logstash.logback.encoder.LogstashEncoder" />
    </appender>
  <root level="INFO">
    <appender-ref ref="CONSOLE" />
    <appender-ref ref="stash" />
  </root>
</configuration>
```

前面的配置通过添加一个新的 TCP 套接字`appender`来覆盖默认的 Logback 配置，该套接字将所有日志消息流式传输到在端口`4560`上监听的 Logstash 服务。重要的是要添加一个编码器，如前面的配置中所述。

1.  创建如下代码所示的配置，并将其存储在`logstash.conf`文件中。该文件的位置不重要，因为在启动 Logstash 时将作为参数传递。此配置将从在`4560`端口上监听的套接字接收输入，并将输出发送到在`9200`端口上运行的 Elasticsearch。 `stdout`是可选的，并设置为 debug：

```java
input {
  tcp {
     port => 4560
     host => localhost
  }
}
output {
elasticsearch { hosts => ["localhost:9200"] }
  stdout { codec => rubydebug }
}
```

1.  从各自的安装文件夹运行 Logstash、Elasticsearch 和 Kibana，如下所示：

```java
./bin/logstash -f logstash.conf
./bin/elasticsearch
./bin/kibana

```

1.  运行 Search 微服务。这将调用单元测试用例，并导致打印前面提到的日志语句。

1.  转到浏览器，访问 Kibana，网址为`http://localhost:5601`。

1.  转到“Settings” | “Configure an index pattern”，如下所示：![自定义日志实现](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-msvc/img/B05447_07_05.jpg)

1.  转到“Discover”菜单查看日志。如果一切顺利，我们将看到 Kibana 截图如下。请注意，日志消息显示在 Kibana 屏幕上。

Kibana 提供了开箱即用的功能，可以使用日志消息构建摘要图表和图形：

![自定义日志实现](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-msvc/img/B05447_07_06.jpg)

## 使用 Spring Cloud Sleuth 进行分布式跟踪

前一节通过集中日志数据解决了微服务的分布式和碎片化日志问题。通过集中的日志解决方案，我们可以将所有日志存储在一个中央位置。然而，要跟踪端到端的事务仍然几乎是不可能的。为了进行端到端跟踪，跨越微服务的事务需要有一个相关 ID。

Twitter 的 Zipkin、Cloudera 的 HTrace 和 Google 的 Dapper 系统是分布式跟踪系统的例子。Spring Cloud 使用 Spring Cloud Sleuth 库在这些系统之上提供了一个包装组件。

分布式跟踪使用**跨度**和**跟踪**的概念。跨度是一个工作单元；例如，调用一个服务由一个 64 位的跨度 ID 标识。一组跨度形成一个类似树状结构的跟踪。使用跟踪 ID，可以跟踪端到端的调用：

![使用 Spring Cloud Sleuth 进行分布式跟踪](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-msvc/img/B05447_07_07.jpg)

如图所示，**微服务 1**调用**微服务 2**，**微服务 2**调用**微服务 3**。在这种情况下，如图所示，相同的跟踪 ID 在所有微服务之间传递，可以用来跟踪端到端的事务。

为了演示这一点，我们将使用搜索 API 网关和搜索微服务。必须在搜索 API 网关（`chapter7.search-apigateway`）中添加一个新的端点，该端点在内部调用搜索服务以返回数据。如果没有跟踪 ID，几乎不可能追踪或链接来自网站到搜索 API 网关到搜索微服务的调用。在这种情况下，只涉及两到三个服务，而在复杂的环境中，可能有许多相互依赖的服务。

按照以下步骤使用 Sleuth 创建示例：

1.  更新搜索和搜索 API 网关。在此之前，需要将 Sleuth 依赖项添加到各自的 POM 文件中，可以通过以下代码完成：

```java
<dependency>
  <groupId>org.springframework.cloud</groupId>
  <artifactId>spring-cloud-starter-sleuth</artifactId>
</dependency>
```

1.  在构建新服务的情况下，选择**Sleuth**和**Web**，如下所示：![使用 Spring Cloud Sleuth 进行分布式跟踪](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-msvc/img/B05447_07_08.jpg)

1.  在搜索服务以及 Logback 配置中添加 Logstash 依赖，如前面的示例所示。

1.  接下来是在 Logback 配置中添加两个属性：

```java
<property name="spring.application.name" value="search-service"/>
<property name="CONSOLE_LOG_PATTERN" value="%d{yyyy-MM-dd HH:mm:ss.SSS} [${spring.application.name}] [trace=%X{X-Trace-Id:-},span=%X{X-Span-Id:-}] [%15.15t] %-40.40logger{39}: %m%n"/>
```

第一个属性是应用程序的名称。在这里给出的名称是服务 ID：在搜索和搜索 API 网关中分别是`search-service`和`search-apigateway`。第二个属性是一个可选的模式，用于打印带有跟踪 ID 和跨度 ID 的控制台日志消息。前面的改变需要应用到两个服务中。

1.  在 Spring Boot 应用程序类中添加以下代码片段，以指示 Sleuth 何时开始一个新的跨度 ID。在这种情况下，使用`AlwaysSampler`表示每次调用服务时都必须创建跨度 ID。这个改变需要应用在两个服务中：

```java
  @Bean
    public AlwaysSampler defaultSampler() {
      return new AlwaysSampler();
    }
```

1.  在搜索 API 网关中添加一个新的端点，该端点将调用搜索服务，如下所示。这是为了演示跟踪 ID 在多个微服务之间的传播。网关中的这个新方法通过调用搜索服务返回机场的操作中心，如下所示：

```java
  @RequestMapping("/hubongw")
  String getHub(HttpServletRequest req){
    logger.info("Search Request in API gateway for getting Hub, forwarding to search-service ");
    String hub = restTemplate.getForObject("http://search-service/search/hub", String.class);
    logger.info("Response for hub received,  Hub "+ hub);
    return hub; 
  }
```

1.  在搜索服务中添加另一个端点，如下所示：

```java
  @RequestMapping("/hub")
  String getHub(){
    logger.info("Searching for Hub, received from search-apigateway ");
    return "SFO"; 
  }
```

1.  添加后，运行两个服务。使用浏览器（`http://localhost:8095/hubongw`）在网关的新中心（`/hubongw`）端点上进行访问。

如前所述，搜索 API 网关服务运行在`8095`上，搜索服务运行在`8090`上。

1.  查看控制台日志以查看打印的跟踪 ID 和跨度 ID。第一个打印来自搜索 API 网关，第二个来自搜索服务。请注意，在这两种情况下，跟踪 ID 都是相同的，如下所示：

```java
2016-04-02 17:24:37.624 [search-apigateway] [trace=8a7e278f-7b2b-43e3-a45c-69d3ca66d663,span=8a7e278f-7b2b-43e3-a45c-69d3ca66d663] [io-8095-exec-10] c.b.p.s.a.SearchAPIGatewayController    : Response for hub received,  Hub DXB

2016-04-02 17:24:37.612 [search-service] [trace=8a7e278f-7b2b-43e3-a45c-69d3ca66d663,span=fd309bba-5b4d-447f-a5e1-7faaab90cfb1] [nio-8090-exec-1] c.b.p.search.component.SearchComponent  : Searching for Hub, received from search-apigateway
```

1.  打开 Kibana 控制台并使用控制台中打印的跟踪 ID 搜索跟踪 ID。在这种情况下，它是 `8a7e278f-7b2b-43e3-a45c-69d3ca66d663`。如下面的截图所示，使用跟踪 ID，可以跟踪跨多个服务的服务调用:![使用 Spring Cloud Sleuth 进行分布式跟踪](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-msvc/img/B05447_07_09.jpg)

# 监控微服务

微服务是真正的分布式系统，具有流动的部署拓扑。如果没有复杂的监控系统，运维团队可能会在管理大规模微服务时遇到麻烦。传统的单片应用部署仅限于已知服务、实例、机器等。这比可能在不同机器上运行的大量微服务实例更容易管理。更复杂的是，这些服务会动态改变其拓扑。集中式日志记录能力只解决了问题的一部分。运维团队了解运行时部署拓扑和系统行为至关重要。这需要比集中式日志记录更多的东西。

一般应用程序监控更多是一组指标、聚合和它们对某些基线值的验证。如果有服务级别的违规，监控工具会生成警报并将其发送给管理员。对于数百甚至数千个相互连接的微服务，传统的监控实际上并没有真正提供真正的价值。在大规模微服务中实现一刀切的监控或使用单一视图监控所有东西并不容易实现。

微服务监控的主要目标之一是从用户体验的角度了解系统的行为。这将确保端到端的行为是一致的，并符合用户的预期。

## 监控挑战

与分散的日志记录问题类似，监控微服务的关键挑战在于微服务生态系统中有许多移动部分。

典型问题总结如下:

+   统计数据和指标分散在许多服务、实例和机器中。

+   可能会使用异构技术来实现微服务，这使得事情变得更加复杂。单一的监控工具可能无法提供所有所需的监控选项。

+   微服务部署拓扑是动态的，无法预先配置服务器、实例和监控参数。

许多传统监控工具适用于监控单片应用程序，但在监控大规模、分布式、相互关联的微服务系统方面表现不佳。许多传统监控系统是基于代理的，需要在目标机器或应用程序实例上预先安装代理。这带来了两个挑战:

+   如果代理需要与服务或操作系统进行深度集成，那么在动态环境中将很难管理。

+   如果这些工具在监控或为应用程序进行仪器化时增加了开销，可能会导致性能问题

许多传统工具需要基线指标。这些系统使用预设规则，例如如果 CPU 利用率超过 60% 并保持在这个水平 2 分钟，那么应该向管理员发送警报。在大规模的互联网部署中，预先配置这些值非常困难。

新一代的监控应用程序通过自学习应用程序的行为并设置自动阈值值。这使管理员免于进行这种乏味的任务。自动基线有时比人类预测更准确:

![监控挑战](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-msvc/img/B05447_07_10.jpg)

如图所示，微服务监控的关键领域包括:

+   **指标来源和数据收集器**：在源头进行指标收集，可以通过服务器将指标信息推送到中央收集器，也可以通过嵌入轻量级代理来收集信息。数据收集器从不同来源收集监控指标，如网络、物理机器、容器、软件组件、应用程序等。挑战在于使用自动发现机制而不是静态配置来收集这些数据。

这可以通过在源机器上运行代理、从源头流式传输数据或定期轮询来完成。

+   **指标的聚合和关联**：需要聚合能力来聚合从不同来源收集的指标，如用户交易、服务、基础设施、网络等。聚合可能具有挑战性，因为它需要一定程度上理解应用程序的行为，如服务依赖关系、服务分组等。在许多情况下，这些是根据来源提供的元数据自动制定的。

通常，这是由一个中间人接受指标来完成的。

+   **处理指标和可操作见解**：一旦数据被聚合，下一步就是进行测量。通常使用设定的阈值进行测量。在新一代监控系统中，这些阈值是自动发现的。监控工具然后分析数据并提供可操作的见解。

这些工具可能使用大数据和流分析解决方案。

+   **警报、操作和仪表板**：一旦发现问题，就必须通知相关人员或系统。与传统系统不同，微服务监控系统应能够实时采取行动。积极的监控对于实现自愈至关重要。仪表板用于显示 SLA、KPI 等。

仪表板和警报工具能够满足这些要求。

微服务监控通常有三种方法。实际上，需要结合这些方法才能有效监控：

+   **应用性能监控**（**APM**）：这更多地是一种传统的系统指标收集、处理、警报和仪表板呈现的方法。这些更多来自系统的角度。应用拓扑发现和可视化是许多 APM 工具实施的新功能。不同 APM 提供商之间的能力有所不同。

+   **合成监控**：这是一种技术，用于使用在生产环境或类似生产环境中的多个测试场景进行端到端交易来监控系统的行为。收集数据以验证系统的行为和潜在热点。合成监控还有助于了解系统的依赖关系。

+   **实时用户监控**（**RUM**）或**用户体验监控**：这通常是一个基于浏览器的软件，记录真实用户的统计数据，如响应时间、可用性和服务水平。对于微服务，由于发布周期更频繁、拓扑结构更动态，用户体验监控更为重要。

## 监控工具

有许多工具可用于监控微服务。许多工具之间也存在重叠。监控工具的选择实际上取决于需要监控的生态系统。在大多数情况下，需要多个工具来监控整个微服务生态系统。

本节的目标是让我们熟悉一些常见的微服务友好的监控工具：

+   AppDynamics、Dynatrace 和 New Relic 是 Gartner Magic Quadrant 2015 年 APM 领域的顶级商业供应商。这些工具对微服务友好，可以在单个控制台中有效支持微服务监控。Ruxit、Datadog 和 Dataloop 是其他专为基本上友好的分布式系统而构建的商业产品。多个监控工具可以使用插件向 Datadog 提供数据。

+   云供应商都有自己的监控工具，但在许多情况下，这些监控工具本身可能不足以进行大规模微服务监控。例如，AWS 使用 CloudWatch，Google Cloud Platform 使用 Cloud Monitoring 来收集来自各种来源的信息。

+   一些数据收集库，如 Zabbix、statd、collectd、jmxtrans 等，以较低的级别收集运行时统计数据、指标、量规和计数。通常，这些信息被馈送到数据收集器和处理器，如 Riemann、Datadog 和 Librato，或者仪表板，如 Graphite。

+   Spring Boot Actuator 是收集微服务指标、量规和计数的好工具，正如我们在《使用 Spring Boot 构建微服务》的第二章中讨论的那样。Netflix Servo 是一种类似于 Actuator 的度量收集器，QBit 和 Dropwizard 度量也属于同一类度量收集器。所有这些度量收集器都需要聚合器和仪表板来促进全尺寸监控。

+   通过日志进行监控是一种流行但不太有效的微服务监控方法。在这种方法中，正如在前一节中讨论的那样，日志消息从各种来源（如微服务、容器、网络等）传送到一个中央位置。然后，我们可以使用日志文件来跟踪交易、识别热点等。Loggly、ELK、Splunk 和 Trace 是这一领域的候选者。

+   Sensu 是开源社区中用于微服务监控的流行选择。Weave Scope 是另一个工具，主要针对容器化部署。Spigo 是一个专为微服务监控系统，与 Netflix 堆栈紧密结合。

+   Pingdom、New Relic Synthetics、Runscope、Catchpoint 等提供了在实时系统上进行合成交易监控和用户体验监控的选项。

+   Circonus 更多地被归类为 DevOps 监控工具，但也可以进行微服务监控。Nagios 是一种流行的开源监控工具，但更多地属于传统的监控系统。

+   Prometheus 提供了一个时间序列数据库和可视化 GUI，可用于构建自定义监控工具。

## 监控微服务的依赖关系

当有大量具有依赖关系的微服务时，重要的是要有一个监控工具，可以显示微服务之间的依赖关系。静态配置和管理这些依赖关系并不是一种可扩展的方法。有许多有用的工具可以监控微服务的依赖关系，如下所示：

+   像 AppDynamics、Dynatrace 和 New Relic 这样的监控工具可以绘制微服务之间的依赖关系。端到端事务监控也可以跟踪事务依赖关系。其他监控工具，如 Spigo，也对微服务依赖管理很有用。

+   CMDB 工具，如 Device42 或专门的工具，如 Accordance，对于管理微服务的依赖关系非常有用。Veritas Risk Advisor（VRA）也对基础设施发现非常有用。

+   使用图形数据库（如 Neo4j）进行自定义实现也是有用的。在这种情况下，微服务必须预先配置其直接和间接的依赖关系。在服务启动时，它会发布并与 Neo4j 数据库交叉检查其依赖关系。

## Spring Cloud Hystrix 用于容错微服务

本节将探讨 Spring Cloud Hystrix 作为一种容错和延迟容忍微服务实现的库。Hystrix 基于*失败快速*和*快速恢复*原则。如果服务出现问题，Hystrix 有助于隔离它。它通过回退到另一个预先配置的回退服务来快速恢复。Hystrix 是 Netflix 的另一个经过实战检验的库。Hystrix 基于断路器模式。

### 注意

在[`msdn.microsoft.com/en-us/library/dn589784.aspx`](https://msdn.microsoft.com/en-us/library/dn589784.aspx)上阅读有关断路器模式的更多信息。

在本节中，我们将使用 Spring Cloud Hystrix 构建一个断路器。执行以下步骤来更改 Search API Gateway 服务，以将其与 Hystrix 集成：

1.  更新 Search API Gateway 服务。为服务添加 Hystrix 依赖项。如果从头开始开发，请选择以下库：![Spring Cloud Hystrix for fault-tolerant microservices](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-msvc/img/B05447_07_11.jpg)

1.  在 Spring Boot 应用程序类中，添加`@EnableCircuitBreaker`。这个命令将告诉 Spring Cloud Hystrix 为这个应用程序启用断路器。它还公开了用于指标收集的`/hystrix.stream`端点。

1.  为 Search API Gateway 服务添加一个组件类，其中包含一个方法；在这种情况下，这是用`@HystrixCommand`注释的`getHub`。这告诉 Spring 这个方法容易失败。Spring Cloud 库包装这些方法以处理容错和延迟容忍，通过启用断路器。Hystrix 命令通常跟随一个回退方法。在失败的情况下，Hystrix 会自动启用提到的回退方法，并将流量转移到回退方法。如下面的代码所示，在这种情况下，`getHub`将回退到`getDefaultHub`：

```java
@Component  
class SearchAPIGatewayComponent { 
  @LoadBalanced
  @Autowired 
  RestTemplate restTemplate;

  @HystrixCommand(fallbackMethod = "getDefaultHub")
  public String getHub(){
    String hub = restTemplate.getForObject("http://search-service/search/hub", String.class);
    return hub;
  }
  public String getDefaultHub(){
    return "Possibily SFO";
  }
}
```

1.  `SearchAPIGatewayController`的`getHub`方法调用`SearchAPIGatewayComponent`的`getHub`方法，如下所示：

```java
@RequestMapping("/hubongw") 
String getHub(){
  logger.info("Search Request in API gateway for getting Hub, forwarding to search-service ");
  return component.getHub(); 
}
```

1.  这个练习的最后一部分是构建一个 Hystrix 仪表板。为此，构建另一个 Spring Boot 应用程序。在构建此应用程序时，包括 Hystrix、Hystrix 仪表板和执行器。

1.  在 Spring Boot 应用程序类中，添加`@EnableHystrixDashboard`注释。

1.  启动 Search 服务、Search API Gateway 和 Hystrix 仪表板应用程序。将浏览器指向 Hystrix 仪表板应用程序的 URL。在本例中，Hystrix 仪表板在端口`9999`上启动。因此，打开 URL`http://localhost:9999/hystrix`。

1.  将显示类似于以下屏幕截图的屏幕。在 Hystrix 仪表板中，输入要监视的服务的 URL。

在这种情况下，Search API Gateway 正在端口`8095`上运行。因此，`hystrix.stream`的 URL 将是`http://localhost:8095/hytrix.stream`，如下所示：

![Spring Cloud Hystrix for fault-tolerant microservices](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-msvc/img/B05447_07_12.jpg)

1.  Hystrix 仪表板将显示如下：![Spring Cloud Hystrix for fault-tolerant microservices](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-msvc/img/B05447_07_13.jpg)

### 提示

请注意，至少必须执行一个事务才能看到显示。这可以通过访问`http://localhost:8095/hubongw`来实现。

1.  通过关闭 Search 服务创建一个故障场景。请注意，当访问 URL`http://localhost:8095/hubongw`时，将调用回退方法。

1.  如果连续失败，则断路器状态将更改为打开。这可以通过多次访问上述 URL 来实现。在打开状态下，原始服务将不再被检查。Hystrix 仪表板将显示断路器的状态为**打开**，如下面的屏幕截图所示。一旦断路器打开，系统将定期检查原始服务的状态以进行恢复。当原始服务恢复时，断路器将恢复到原始服务，并且状态将设置为**关闭**：![Spring Cloud Hystrix for fault-tolerant microservices](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-msvc/img/B05447_07_14.jpg)

### 注意

要了解每个参数的含义，请访问 Hystrix wiki [`github.com/Netflix/Hystrix/wiki/Dashboard`](https://github.com/Netflix/Hystrix/wiki/Dashboard)。

## 使用 Turbine 聚合 Hystrix 流

在上一个示例中，我们的微服务的`/hystrix.stream`端点在 Hystrix 仪表板中给出。Hystrix 仪表板一次只能监视一个微服务。如果有许多微服务，则 Hystrix 仪表板指向的服务必须每次切换要监视的微服务时更改。一次只查看一个实例是很繁琐的，特别是当有多个微服务实例或多个微服务时。

我们必须有一种机制来聚合来自多个`/hystrix.stream`实例的数据，并将其合并成单个仪表板视图。Turbine 正是这样做的。Turbine 是另一个服务器，它从多个实例收集 Hystrix 流，并将它们合并成一个`/turbine.stream`实例。现在，Hystrix 仪表板可以指向`/turbine.stream`以获取合并信息：

![使用 Turbine 聚合 Hystrix 流](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-msvc/img/B05447_07_15.jpg)

### 提示

Turbine 目前仅适用于不同的主机名。每个实例必须在单独的主机上运行。如果您在同一主机上本地测试多个服务，则更新主机文件（`/etc/hosts`）以模拟多个主机。完成后，必须配置`bootstrap.properties`如下：

```java
eureka.instance.hostname: localdomain2
```

此示例展示了如何使用 Turbine 监视多个实例和服务之间的断路器。在此示例中，我们将使用搜索服务和搜索 API 网关。Turbine 内部使用 Eureka 来解析配置用于监视的服务 ID。

执行以下步骤来构建和执行此示例：

1.  Turbine 服务器可以作为另一个 Spring Boot 应用程序创建，使用 Spring Boot Starter 选择 Turbine 以包括 Turbine 库。

1.  创建应用程序后，在主 Spring Boot 应用程序类中添加`@EnableTurbine`。在此示例中，Turbine 和 Hystrix 仪表板都配置为在同一个 Spring Boot 应用程序上运行。通过向新创建的 Turbine 应用程序添加以下注释，可以实现这一点：

```java
@EnableTurbine
@EnableHystrixDashboard
@SpringBootApplication
public class TurbineServerApplication {
```

1.  将以下配置添加到`.yaml`或属性文件中，以指向我们感兴趣监视的实例：

```java
spring:
   application:
     name : turbineserver
turbine:
   clusterNameExpression: new String('default')
   appConfig : search-service,search-apigateway
server:
  port: 9090
eureka:
  client:
    serviceUrl:
       defaultZone: http://localhost:8761/eureka/
```

1.  上述配置指示 Turbine 服务器查找 Eureka 服务器以解析`search-service`和`search-apigateway`服务。`search-service`和`search-apigateways`服务 ID 用于向 Eureka 注册服务。Turbine 使用这些名称通过与 Eureka 服务器检查来解析实际的服务主机和端口。然后，它将使用此信息从每个实例中读取`/hystrix.stream`。Turbine 然后读取所有单独的 Hystrix 流，将它们聚合，并在 Turbine 服务器的`/turbine.stream` URL 下公开它们。

1.  集群名称表达式指向默认集群，因为在此示例中没有进行显式集群配置。如果手动配置了集群，则必须使用以下配置：

```java
turbine:
  aggregator:
    clusterConfig: [comma separated clusternames]
```

1.  将搜索服务的`SearchComponent`更改为添加另一个断路器，如下所示：

```java
  @HystrixCommand(fallbackMethod = "searchFallback")
  public List<Flight> search(SearchQuery query){
```

1.  此外，在搜索服务的主应用程序类中添加`@EnableCircuitBreaker`。

1.  将以下配置添加到搜索服务的`bootstrap.properties`中。这是因为所有服务都在同一主机上运行：

```java
Eureka.instance.hostname: localdomain1
```

1.  同样，在搜索 API 网关服务的`bootstrap.properties`中添加以下内容。这是为了确保两个服务使用不同的主机名：

```java
eureka.instance.hostname: localdomain2
```

1.  在此示例中，我们将运行两个`search-apigateway`实例：一个在`localdomain1:8095`上，另一个在`localdomain2:8096`上。我们还将在`localdomain1:8090`上运行一个`search-service`实例。

1.  使用命令行覆盖运行微服务以管理不同的主机地址，如下所示：

```java
java -jar -Dserver.port=8096 -Deureka.instance.hostname=localdomain2 -Dserver.address=localdomain2 target/chapter7.search-apigateway-1.0.jar
java -jar -Dserver.port=8095 -Deureka.instance.hostname=localdomain1 -Dserver.address=localdomain1 target/chapter7.search-apigateway-1.0.jar
java -jar -Dserver.port=8090 -Deureka.instance.hostname=localdomain1 -Dserver.address=localdomain1 target/chapter7.search-1.0.jar

```

1.  通过将浏览器指向`http://localhost:9090/hystrix`来打开 Hystrix 仪表板。

1.  与其给出`/hystrix.stream`，这次我们将指向`/turbine.stream`。在这个例子中，Turbine 流正在`9090`上运行。因此，在 Hystrix 仪表板中要给出的 URL 是`http://localhost:9090/turbine.stream`。

1.  通过打开浏览器窗口并访问以下两个 URL 来触发一些事务：`http://localhost:8095/hubongw`和`http://localhost:8096/hubongw`。

完成后，仪表板页面将显示**getHub**服务。

1.  运行`chapter7.website`。使用网站`http://localhost:8001`执行搜索事务。

在执行前面的搜索之后，仪表板页面将显示**search-service**。如下截图所示：

![使用 Turbine 聚合 Hystrix 流](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-msvc/img/B05447_07_16.jpg)

正如我们在仪表板中所看到的，**search-service**来自 Search 微服务，而**getHub**来自 Search API 网关。由于我们有两个 Search API 网关的实例，**getHub**来自两个主机，由**Hosts 2**表示。

# 使用数据湖进行数据分析

与分段日志和监控的情景类似，分段数据是微服务架构中的另一个挑战。分段数据在数据分析中带来了挑战。这些数据可能用于简单的业务事件监控、数据审计，甚至从数据中推导出业务智能。

数据湖或数据中心是处理这种情况的理想解决方案。事件源架构模式通常用于将状态和状态变化作为事件与外部数据存储共享。当状态发生变化时，微服务将状态变化作为事件发布。感兴趣的各方可以订阅这些事件，并根据自己的需求进行处理。中央事件存储也可以订阅这些事件，并将它们存储在大数据存储中进行进一步分析。

常用的数据处理架构如下图所示：

![使用数据湖进行数据分析](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-msvc/img/B05447_07_17.jpg)

从微服务生成的状态变化事件——在我们的案例中是**Search**、**Booking**和**Check-In**事件——被推送到分布式高性能消息系统，如 Kafka。数据摄取服务，如 Flume，可以订阅这些事件并将其更新到 HDFS 集群中。在某些情况下，这些消息将通过 Spark Streaming 实时处理。为了处理事件的异构来源，Flume 也可以在事件源和 Kafka 之间使用。

Spring Cloud Streams、Spring Cloud Streams 模块和 Spring Data Flow 也是用于高速数据摄取的替代方案。

# 总结

在本章中，您了解了处理互联网规模微服务时日志记录和监控所面临的挑战。

我们探讨了集中式日志记录的各种解决方案。您还了解了如何使用 Elasticsearch、Logstash 和 Kibana（ELK）实现自定义集中式日志记录。为了理解分布式跟踪，我们使用 Spring Cloud Sleuth 升级了 BrownField 微服务。

在本章的后半部分，我们深入探讨了微服务监控解决方案所需的能力以及监控的不同方法。随后，我们检查了一些可用于微服务监控的工具。

通过 Spring Cloud Hystrix 和 Turbine 进一步增强了 BrownField 微服务，以监控服务间通信的延迟和故障。示例还演示了如何使用断路器模式在发生故障时回退到另一个服务。

最后，我们还提到了数据湖的重要性以及如何在微服务环境中集成数据湖架构。

微服务管理是我们在处理大规模微服务部署时需要解决的另一个重要挑战。下一章将探讨容器如何帮助简化微服务管理。


# 第八章：使用 Docker 容器化微服务

在微服务的上下文中，容器化部署是锦上添花。它通过自包含底层基础设施来帮助微服务更加自治，从而使微服务与云中立。

本章将介绍虚拟机镜像的概念和相关性，以及微服务的容器化部署。然后，本章将进一步使读者熟悉使用 Spring Boot 和 Spring Cloud 开发的 BrownField PSS 微服务构建 Docker 镜像。最后，本章还将介绍如何在类生产环境中管理、维护和部署 Docker 镜像。

通过本章结束时，您将了解以下内容：

+   容器化概念及其在微服务上下文中的相关性

+   构建和部署微服务作为 Docker 镜像和容器

+   以 AWS 作为基于云的 Docker 部署的示例

# 审查微服务能力模型

在本章中，我们将探讨第三章中讨论的微服务能力模型中的以下微服务能力：

+   容器和虚拟机

+   私有/公共云

+   微服务仓库

该模型如下图所示：

![审查微服务能力模型](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-msvc/img/B05447_08_01.jpg)

# 了解 BrownField PSS 微服务中的空白

在第五章*使用 Spring Cloud 扩展微服务*中，BrownField PSS 微服务使用 Spring Boot 和 Spring Cloud 开发。这些微服务部署为版本化的 fat JAR 文件，特别是在本地开发机器上的裸金属上。

在第六章*微服务自动扩展*中，通过自定义生命周期管理器添加了自动扩展能力。在第七章*日志和监控微服务*中，通过集中日志和监控解决方案解决了围绕日志和监控的挑战。

我们的 BrownField PSS 实施仍然存在一些空白。到目前为止，该实施尚未使用任何云基础设施。专用机器，如传统的单片应用部署，不是部署微服务的最佳解决方案。自动化，如自动配置、按需扩展、自助服务和基于使用量的付款，是管理大规模微服务部署所需的基本能力。一般来说，云基础设施提供所有这些基本能力。因此，具有前述能力的私有或公共云更适合部署互联网规模的微服务。

此外，在裸金属上运行一个微服务实例并不划算。因此，在大多数情况下，企业最终会在单个裸金属服务器上部署多个微服务。在单个裸金属上运行多个微服务可能会导致“吵闹的邻居”问题。在同一台机器上运行的微服务实例之间没有隔离。因此，部署在单台机器上的服务可能会占用其他服务的空间，从而影响其性能。

另一种方法是在虚拟机上运行微服务。然而，虚拟机的性能较重。因此，在物理机上运行许多较小的虚拟机并不高效。这通常会导致资源浪费。在共享虚拟机以部署多个服务的情况下，我们将面临与前述共享裸金属相同的问题。

在基于 Java 的微服务的情况下，共享 VM 或裸机来部署多个微服务也会导致在微服务之间共享 JRE。这是因为在我们的 BrownField PSS 抽象中创建的 fat JAR 仅包含应用程序代码及其依赖项，而不包括 JRE。在安装在机器上的 JRE 上进行任何更新都会对部署在该机器上的所有微服务产生影响。同样，如果特定微服务需要 OS 级参数、库或调整，则在共享环境中很难对其进行管理。

一个微服务原则坚持认为它应该是自包含的，并通过完全封装其端到端运行时环境来实现自主性。为了符合这一原则，所有组件，如操作系统、JRE 和微服务二进制文件，都必须是自包含和隔离的。实现这一点的唯一选择是遵循每个 VM 部署一个微服务的方法。然而，这将导致虚拟机的利用率不足，并且在许多情况下，由于这种情况而产生的额外成本可能会抵消微服务的好处。

# 什么是容器？

容器并不是革命性的、开创性的概念。它们已经实践了相当长的时间。然而，由于广泛采用云计算，世界正在见证容器的重新进入。传统虚拟机在云计算领域的缺陷也加速了容器的使用。像**Docker**这样的容器提供商大大简化了容器技术，这也使得容器技术在当今世界得到了广泛的应用。最近 DevOps 和微服务的流行也促成了容器技术的重生。

那么，什么是容器？容器在操作系统之上提供了私有空间。这种技术也被称为操作系统虚拟化。在这种方法中，操作系统的内核提供了隔离的虚拟空间。这些虚拟空间中的每一个被称为一个容器或**虚拟引擎**（**VE**）。容器允许进程在主机操作系统之上的隔离环境中运行。多个容器在同一主机上运行的表示如下：

![什么是容器？](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-msvc/img/B05447_08_02.jpg)

容器是构建、运输和运行组件化软件的简单机制。通常，容器打包了运行应用程序所必需的所有二进制文件和库。容器保留自己的文件系统、IP 地址、网络接口、内部进程、命名空间、操作系统库、应用程序二进制文件、依赖项和其他应用程序配置。

组织使用数十亿个容器。此外，许多大型组织都在大力投资容器技术。Docker 遥遥领先于竞争对手，得到了许多大型操作系统供应商和云提供商的支持。**Lmctfy**、**SystemdNspawn**、**Rocket**、**Drawbridge**、**LXD**、**Kurma**和**Calico**是其他一些容器化解决方案。开放容器规范也正在开发中。

# VM 和容器之间的区别

几年前，**Hyper-V**、**VMWare**和**Zen**等 VM 是数据中心虚拟化的热门选择。企业通过实施虚拟化而节省了成本，而不是传统的裸机使用。它还帮助许多企业以更加优化的方式利用其现有基础设施。由于 VM 支持自动化，许多企业发现他们在虚拟机上的管理工作更少。虚拟机还帮助组织获得应用程序运行的隔离环境。

乍一看，虚拟化和容器化表现出完全相同的特征。然而，总的来说，容器和虚拟机并不相同。因此，在虚拟机和容器之间进行苹果对苹果的比较是不公平的。虚拟机和容器是两种不同的技术，解决虚拟化的不同问题。这种差异可以从以下图表中看出：

![虚拟机和容器之间的区别](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-msvc/img/B05447_08_03.jpg)

与容器相比，虚拟机的操作级别要低得多。虚拟机提供硬件虚拟化，如 CPU、主板、内存等。虚拟机是一个独立的单元，内嵌操作系统，通常称为**客户操作系统**。虚拟机复制整个操作系统，并在虚拟机内部运行，不依赖于主机操作系统环境。由于虚拟机嵌入了完整的操作系统环境，因此它们在性质上比较笨重。这既是优势也是劣势。优势在于虚拟机为在虚拟机上运行的进程提供了完全隔离。劣势在于它限制了在裸机上启动虚拟机的数量，因为虚拟机的资源需求。

虚拟机的大小直接影响其启动和停止时间。由于启动虚拟机会启动操作系统，因此虚拟机的启动时间通常较长。虚拟机更适合基础设施团队，因为管理虚拟机需要较低水平的基础设施能力。

在容器世界中，容器不会模拟整个硬件或操作系统。与虚拟机不同，容器共享主机内核和操作系统的某些部分。在容器的情况下，没有客户操作系统的概念。容器在主机操作系统的顶部直接提供了一个隔离的执行环境。这既是它的优势也是劣势。优势在于它更轻，更快。由于同一台机器上的容器共享主机操作系统，容器的整体资源利用率相当小。因此，与笨重的虚拟机相比，可以在同一台机器上运行许多较小的容器。由于同一主机上的容器共享主机操作系统，也存在一些限制。例如，在容器内部无法设置 iptables 防火墙规则。容器内的进程与在同一主机上运行的不同容器的进程完全独立。

与虚拟机不同，容器镜像在社区门户网站上是公开可用的。这使得开发人员的生活变得更加轻松，因为他们不必从头开始构建镜像；相反，他们现在可以从认证来源获取基础镜像，并在下载的基础镜像上添加额外的软件组件层。

容器的轻量化特性也为自动化构建、发布、下载、复制等提供了大量机会。通过几个命令下载、构建、运行容器或使用 REST API 使容器更加适合开发人员。构建一个新的容器不会超过几秒钟。容器现在也是持续交付流水线的一部分。

总之，容器相对于虚拟机有许多优势，但虚拟机也有其独特的优势。许多组织同时使用容器和虚拟机，例如在虚拟机上运行容器。

# 容器的优势

我们已经考虑了容器相对于虚拟机的许多优势。本节将解释容器的整体优势，超越虚拟机的优势：

+   自包含：容器将必要的应用程序二进制文件和它们的依赖项打包在一起，以确保在开发、测试或生产等不同环境之间没有差异。这促进了十二要素应用程序和不可变容器的概念。Spring Boot 微服务捆绑了所有必需的应用程序依赖项。容器通过嵌入 JRE 和其他操作系统级别的库、配置等，进一步扩展了这一边界。

+   轻量级：总的来说，容器体积小，占用空间少。最小的容器 Alpine 大小不到 5MB。使用 Alpine 容器和 Java 8 打包的最简单的 Spring Boot 微服务只有大约 170MB 的大小。虽然大小仍然偏大，但比通常几 GB 的 VM 镜像要小得多。容器的较小占用空间不仅有助于快速启动新容器，还使构建、部署和存储更加容易。

+   可扩展：由于容器镜像体积小，在启动时没有操作系统引导，容器通常更快地启动和关闭。这使得容器成为云友好的弹性应用程序的热门选择。

+   可移植：容器在不同机器和云提供商之间提供可移植性。一旦容器构建完成所有依赖项，它们可以在多台机器或多个云提供商之间移植，而不依赖于底层机器。容器可以从桌面移植到不同的云环境。

+   较低的许可成本：许多软件许可条款是基于物理核心的。由于容器共享操作系统，并且在物理资源级别上没有虚拟化，因此在许可成本方面具有优势。

+   DevOps：容器的轻量级占用空间使得容易自动化构建，并从远程存储库发布和下载容器。这使得在敏捷和 DevOps 环境中易于使用，通过与自动交付流水线集成。容器还支持“构建一次”的概念，通过在构建时创建不可变容器，并在多个环境之间移动它们。由于容器并不深入基础设施，多学科的 DevOps 团队可以将容器作为日常生活的一部分进行管理。

+   版本控制：容器默认支持版本。这有助于构建有版本的工件，就像有版本的存档文件一样。

+   可重用：容器镜像是可重用的工件。如果一个镜像是通过组装一些库来实现某个目的，它可以在类似的情况下被重复使用。

+   不可变的容器：在这个概念中，容器在使用后被创建和销毁。它们永远不会被更新或打补丁。不可变的容器在许多环境中被使用，以避免部署单元的补丁复杂性。打补丁会导致无法追踪和无法一致地重新创建环境。

# 微服务和容器

微服务和容器之间没有直接关系。微服务可以在没有容器的情况下运行，容器可以运行单片应用程序。然而，微服务和容器之间存在一个甜蜜点。

容器适用于单片应用程序，但单片应用程序的复杂性和大小可能会削弱容器的一些优势。例如，使用单片应用程序可能不容易快速启动新容器。除此之外，单片应用程序通常具有本地环境依赖，如本地磁盘、与其他系统的独立依赖等。这些应用程序很难通过容器技术进行管理。这就是微服务与容器相辅相成的地方。

以下图表显示了在同一主机上运行的三个多语言微服务，并共享相同的操作系统，但抽象了运行时环境：

![微服务和容器](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-msvc/img/B05447_08_04.jpg)

当管理许多多语言微服务时，容器的真正优势可以看出来，例如，一个微服务用 Java 编写，另一个微服务用 Erlang 或其他语言编写。容器帮助开发人员以平台和技术无关的方式打包任何语言或技术编写的微服务，并统一分布到多个环境中。容器消除了处理多语言微服务的不同部署管理工具的需求。容器不仅抽象了执行环境，还抽象了如何访问服务。无论使用何种技术，容器化的微服务都会暴露 REST API。一旦容器启动运行，它就会绑定到某些端口并暴露其 API。由于容器是自包含的，并在服务之间提供完全的堆栈隔离，在单个 VM 或裸金属上，可以以统一的方式运行多个异构微服务并处理它们。

# Docker 简介

前面的部分讨论了容器及其优势。容器已经在业界使用多年，但 Docker 的流行使容器有了新的前景。因此，许多容器定义和观点都源自 Docker 架构。Docker 如此受欢迎，以至于容器化甚至被称为**dockerization**。

Docker 是一个基于 Linux 内核构建、运输和运行轻量级容器的平台。Docker 默认支持 Linux 平台。它还支持 Mac 和 Windows，使用**Boot2Docker**，它运行在 Virtual Box 之上。

亚马逊**EC2 容器服务**（**ECS**）在 AWS EC2 实例上对 Docker 有开箱即用的支持。Docker 可以安装在裸金属上，也可以安装在传统的虚拟机上，如 VMWare 或 Hyper-V。

## Docker 的关键组件

Docker 安装有两个关键组件：**Docker 守护程序**和**Docker 客户端**。Docker 守护程序和 Docker 客户端都作为单个二进制文件分发。

以下图表显示了 Docker 安装的关键组件：

![Docker 的关键组件](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-msvc/img/B05447_08_05.jpg)

### Docker 守护程序

Docker 守护程序是运行在主机上的服务器端组件，负责构建、运行和分发 Docker 容器。Docker 守护程序暴露 API 供 Docker 客户端与守护程序交互。这些 API 主要是基于 REST 的端点。可以想象 Docker 守护程序是运行在主机上的控制器服务。开发人员可以以编程方式使用这些 API 来构建自定义客户端。

### Docker 客户端

Docker 客户端是一个远程命令行程序，通过套接字或 REST API 与 Docker 守护程序进行交互。CLI 可以在与守护程序相同的主机上运行，也可以在完全不同的主机上运行，并远程连接到守护程序。Docker 用户使用 CLI 构建、运输和运行 Docker 容器。

## Docker 概念

Docker 架构围绕着一些概念构建：镜像、容器、注册表和 Dockerfile。

### Docker 镜像

Docker 的一个关键概念是镜像。Docker 镜像是操作系统库、应用程序及其库的只读副本。一旦创建了镜像，它就保证在任何 Docker 平台上运行而不需要修改。

在 Spring Boot 微服务中，Docker 镜像打包了操作系统，如 Ubuntu、Alpine、JRE 和 Spring Boot fat 应用程序 JAR 文件。它还包括运行应用程序和暴露服务的指令：

![Docker 镜像](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-msvc/img/B05447_08_06.jpg)

如图所示，Docker 镜像基于分层架构，其中基本镜像是 Linux 的各种版本之一。如前图所示，每个层都添加到具有前一个镜像作为父层的基本镜像层中。Docker 使用联合文件系统的概念将所有这些层组合成单个镜像，形成单个文件系统。

在典型情况下，开发人员不会从头开始构建 Docker 镜像。操作系统的镜像，或其他常见的库，如 Java 8 镜像，都可以从可信任的来源公开获取。开发人员可以在这些基本镜像的基础上开始构建。在 Spring 微服务中，基本镜像可以是 JRE 8，而不是从 Ubuntu 等 Linux 发行版镜像开始。

每次重新构建应用程序时，只有更改的层会被重新构建，其余层保持不变。所有中间层都被缓存，因此，如果没有更改，Docker 会使用先前缓存的层并在其上构建。在同一台机器上运行具有相同类型基本镜像的多个容器将重用基本镜像，从而减小部署的大小。例如，在主机上，如果有多个使用 Ubuntu 作为基本镜像运行的容器，它们都会重用相同的基本镜像。这也适用于发布或下载镜像时：

Docker 镜像

如图所示，图像中的第一层是称为`bootfs`的引导文件系统，类似于 Linux 内核和引导加载程序。引导文件系统充当所有图像的虚拟文件系统。

在引导文件系统之上，放置了操作系统文件系统，称为`rootfs`。根文件系统向容器添加了典型的操作系统目录结构。与 Linux 系统不同，在 Docker 的情况下，`rootfs`处于只读模式。

根据需求，其他所需的镜像被放置在`rootfs`之上。在我们的情况下，这些是 JRE 和 Spring Boot 微服务的 JAR 文件。当容器被初始化时，会在所有其他文件系统之上放置一个可写文件系统以供进程运行。进程对底层文件系统所做的任何更改都不会反映在实际容器中。相反，这些更改会被写入可写文件系统。这个可写文件系统是易失性的。因此，一旦容器停止，数据就会丢失。因此，Docker 容器是短暂的。

Docker 内部打包的基本操作系统通常是 OS 文件系统的最小副本。实际上，运行在其上的进程可能并不使用整个 OS 服务。在 Spring Boot 微服务中，很多情况下，容器只是启动一个 CMD 和 JVM，然后调用 Spring Boot 的 fat JAR。

### Docker 容器

Docker 容器是 Docker 镜像的运行实例。容器在运行时使用主机操作系统的内核。因此，它们与在同一主机上运行的其他容器共享主机内核。Docker 运行时确保容器进程使用内核功能（如**cgroups**和操作系统的内核**namespace**）分配其自己的隔离进程空间。除了资源隔离，容器还有自己的文件系统和网络配置。

实例化的容器可以具有特定的资源分配，如内存和 CPU。从相同镜像初始化的容器可以具有不同的资源分配。Docker 容器默认获得独立的**子网**和**网关**。网络有三种模式。

### Docker 注册表

Docker 注册表是 Docker 镜像发布和下载的中心位置。URL [`hub.docker.com`](https://hub.docker.com)是 Docker 提供的中央注册表。Docker 注册表有公共镜像，可以下载并用作基本注册表。Docker 还有私有镜像，专门针对在 Docker 注册表中创建的帐户。Docker 注册表的截图如下所示：

![Docker 注册表](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-msvc/img/B05447_08_08.jpg)

Docker 还提供**Docker Trusted Registry**，可用于在本地部署注册表。

### Dockerfile

Dockerfile 是一个包含构建 Docker 镜像的指令的构建或脚本文件。Dockerfile 中可以记录多个步骤，从获取基本镜像开始。Dockerfile 是一个通常命名为 Dockerfile 的文本文件。`docker build`命令查找 Dockerfile 以获取构建指令。可以将 Dockerfile 比作 Maven 构建中使用的`pom.xml`文件。

# 在 Docker 中部署微服务

本节将通过展示如何为我们的 BrownField PSS 微服务构建容器来实现我们的学习。

### 注意

本章的完整源代码可在代码文件的`第八章`项目中找到。将`chapter7.configserver`，`chapter7.eurekaserver`，`chapter7.search`，`chapter7.search-apigateway`和`chapter7.website`复制到新的 STS 工作区，并将它们重命名为`chapter8.*`。

执行以下步骤来构建 BrownField PSS 微服务的 Docker 容器：

1.  从官方 Docker 网站[`www.docker.com`](https://www.docker.com)安装 Docker。

按照所选操作系统的下载和安装说明，使用**开始**链接。安装后，使用以下命令验证安装：

```java
$docker –version
Docker version 1.10.1, build 9e83765

```

1.  在本节中，我们将看看如何将**Search**(`chapter8.search`)微服务，**Search API Gateway**(`chapter8.search-apigateway`)微服务和**Website**(`chapter8.website`) Spring Boot 应用程序 docker 化。

1.  在进行任何更改之前，我们需要编辑`bootstrap.properties`，将配置服务器 URL 从 localhost 更改为 IP 地址，因为在 Docker 容器内无法解析 localhost。在现实世界中，这将指向 DNS 或负载均衡器，如下所示：

```java
spring.cloud.config.uri=http://192.168.0.105:8888
```

### 注意

用您的机器的 IP 地址替换 IP 地址。

1.  同样，在 Git 存储库上编辑`search-service.properties`，将 localhost 更改为 IP 地址。这适用于 Eureka URL 以及 RabbitMQ URL。更新后提交回 Git。您可以通过以下代码执行此操作：

```java
spring.application.name=search-service
spring.rabbitmq.host=192.168.0.105
spring.rabbitmq.port=5672
spring.rabbitmq.username=guest
spring.rabbitmq.password=guest
orginairports.shutdown:JFK
eureka.client.serviceUrl.defaultZone: http://192.168.0.105:8761/eureka/
spring.cloud.stream.bindings.inventoryQ=inventoryQ
```

1.  通过取消注释以下行来更改 RabbitMQ 配置文件`rabbitmq.config`，以提供对 guest 的访问。默认情况下，guest 只能从本地主机访问：

```java
    {loopback_users, []}
```

`rabbitmq.config`的位置对于不同的操作系统是不同的。

1.  在 Search 微服务的根目录下创建一个 Dockerfile，如下所示：

```java
FROM frolvlad/alpine-oraclejdk8
VOLUME /tmp
ADD  target/search-1.0.jar search.jar
EXPOSE 8090
ENTRYPOINT ["java","-jar","/search.jar"]
```

以下是对 Dockerfile 内容的快速检查：

+   `FROM frolvlad/alpine-oraclejdk8`：这告诉 Docker 构建使用特定的`alpine-oraclejdk8`版本作为此构建的基本镜像。`frolvlad`表示定位`alpine-oraclejdk8`镜像的存储库。在这种情况下，它是使用 Alpine Linux 和 Oracle JDK 8 构建的镜像。这将帮助我们将应用程序层叠在基本镜像之上，而无需自己设置 Java 库。在这种情况下，由于此镜像在我们的本地镜像存储中不可用，Docker 构建将继续从远程 Docker Hub 注册表下载此镜像。

+   `VOLUME /tmp`：这允许容器访问主机机器中指定的目录。在我们的情况下，这指向 Spring Boot 应用程序为 Tomcat 创建工作目录的`tmp`目录。`tmp`目录对于容器来说是一个逻辑目录，间接指向主机的一个本地目录。

+   `ADD target/search-1.0.jar search.jar`: 这将应用程序二进制文件添加到容器中，并指定目标文件名。在这种情况下，Docker 构建将`target/search-1.0.jar`复制到容器中作为`search.jar`。

+   `EXPOSE 8090`: 这是告诉容器如何进行端口映射。这将`8090`与内部 Spring Boot 服务的外部端口绑定。

+   `ENTRYPOINT ["java","-jar", "/search.jar"]`: 这告诉容器在启动时要运行哪个默认应用程序。在这种情况下，我们指向 Java 进程和 Spring Boot fat JAR 文件来启动服务。

1.  下一步是从存储 Dockerfile 的文件夹运行`docker build`。这将下载基础镜像，并依次运行 Dockerfile 中的条目，如下所示：

```java
docker build –t search:1.0 .

```

这个命令的输出将如下所示：

![在 Docker 中部署微服务](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-msvc/img/B05447_08_09.jpg)

1.  对 Search API Gateway 和 Website 重复相同的步骤。

1.  创建完镜像后，可以通过输入以下命令来验证。这个命令将列出镜像及其详细信息，包括镜像文件的大小：

```java
docker images

```

输出将如下所示：

![在 Docker 中部署微服务](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-msvc/img/B05447_08_11.jpg)

1.  接下来要做的是运行 Docker 容器。可以使用`docker run`命令来完成这个操作。这个命令将加载并运行容器。在启动时，容器调用 Spring Boot 可执行 JAR 来启动微服务。

在启动容器之前，请确保 Config 和 Eureka 服务器正在运行：

```java
docker run --net host -p 8090:8090 -t search:1.0
docker run --net host -p 8095:8095 -t search-apigateway:1.0
docker run --net host -p 8001:8001 -t website:1.0

```

前面的命令启动了 Search 和 Search API Gateway 微服务以及网站。

在这个例子中，我们使用主机网络`(--net host`)而不是桥接网络，以避免 Eureka 注册到 Docker 容器名称。这可以通过覆盖`EurekaInstanceConfigBean`来纠正。从网络角度来看，主机选项比桥接选项更少隔离。主机与桥接的优势和劣势取决于项目。

1.  一旦所有服务都完全启动，可以使用`docker ps`命令进行验证，如下面的屏幕截图所示：![在 Docker 中部署微服务](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-msvc/img/B05447_08_10.jpg)

1.  下一步是将浏览器指向`http://192.168.99.100:8001`。这将打开 BrownField PSS 网站。

注意 IP 地址。这是 Docker 机器的 IP 地址，如果你在 Mac 或 Windows 上使用 Boot2Docker 运行。在 Mac 或 Windows 上，如果不知道 IP 地址，则输入以下命令来找出默认机器的 Docker 机器 IP 地址：

```java
docker-machine ip default

```

如果 Docker 在 Linux 上运行，那么这就是主机 IP 地址。

对**Booking**、**Fares**、**Check-in**和它们各自的网关微服务应用相同的更改。

# 在 Docker 上运行 RabbitMQ

由于我们的示例也使用了 RabbitMQ，让我们探讨如何将 RabbitMQ 设置为 Docker 容器。以下命令从 Docker Hub 拉取 RabbitMQ 镜像并启动 RabbitMQ：

```java
docker run –net host rabbitmq3

```

确保`*-service.properties`中的 URL 已更改为 Docker 主机的 IP 地址。在 Mac 或 Windows 的情况下，应用之前的规则来找出 IP 地址。

# 使用 Docker 注册表

Docker Hub 提供了一个集中存储所有 Docker 镜像的位置。这些镜像可以存储为公共或私有。在许多情况下，由于安全相关的问题，组织会在本地部署自己的私有注册表。

执行以下步骤来设置和运行本地注册表：

1.  以下命令将启动一个注册表，将注册表绑定到端口`5000`上：

```java
docker run -d -p 5000:5000 --restart=always --name registry registry:2

```

1.  将`search:1.0`标记到注册表，如下所示：

```java
docker tag search:1.0 localhost:5000/search:1.0

```

1.  然后，通过以下命令将镜像推送到注册表：

```java
docker push localhost:5000/search:1.0

```

1.  从注册表中拉取镜像，如下所示：

```java
docker pull localhost:5000/search:1.0

```

## 设置 Docker Hub

在上一章中，我们使用了本地 Docker 注册表。本节将展示如何设置和使用 Docker Hub 来发布 Docker 容器。这是一个方便的机制，可以全球访问 Docker 镜像。在本章的后面部分，Docker 镜像将从本地机器发布到 Docker Hub，并从 EC2 实例下载。

为此，创建一个公共 Docker Hub 账户和一个存储库。对于 Mac，按照以下 URL 的步骤进行：[`docs.docker.com/mac/step_five/`](https://docs.docker.com/mac/step_five/)。

在本例中，使用`brownfield`用户名创建了 Docker Hub 账户。

在这种情况下，注册表充当微服务存储库，其中所有 docker 化的微服务将被存储和访问。这是微服务能力模型中解释的能力之一。

## 将微服务发布到 Docker Hub

要将 docker 化的服务推送到 Docker Hub，请按照以下步骤进行。第一条命令标记 Docker 镜像，第二条命令将 Docker 镜像推送到 Docker Hub 存储库：

```java
docker tag search:1.0brownfield/search:1.0
docker push brownfield/search:1.0

```

要验证容器镜像是否已发布，请转到 Docker Hub 存储库`https://hub.docker.com/u/brownfield`。

对所有其他 BrownField 微服务也重复此步骤。在此步骤结束时，所有服务将被发布到 Docker Hub。

# 云上的微服务

微服务能力模型中提到的能力之一是使用云基础设施进行微服务。在本章的前面部分，我们还探讨了使用云进行微服务部署的必要性。到目前为止，我们还没有将任何东西部署到云上。由于我们总共有八个微服务——`Config-server`、`Eureka-server`、Turbine、RabbitMQ、Elasticsearch、Kibana 和 Logstash——在我们的整体 BrownField PSS 微服务生态系统中，很难在本地机器上运行所有这些微服务。

在本书的其余部分，我们将使用 AWS 作为云平台来部署 BrownField PSS 微服务。

## 在 AWS EC2 上安装 Docker

在本节中，我们将在 EC2 实例上安装 Docker。

本例假设读者熟悉 AWS，并且在 AWS 上已经创建了一个账户。

执行以下步骤在 EC2 上设置 Docker：

1.  启动一个新的 EC2 实例。在这种情况下，如果我们必须同时运行所有实例，可能需要一个大实例。本例使用**t2.large**。

在本例中，使用以下 Ubuntu AMI 镜像：`ubuntu-trusty-14.04-amd64-server-20160114.5 (ami-fce3c696)`。

1.  连接到 EC2 实例并运行以下命令：

```java
sudo apt-get update 
sudo apt-get install docker.io

```

1.  上述命令将在 EC2 实例上安装 Docker。使用以下命令验证安装：

```java
docker version

```

# 在 EC2 上运行 BrownField 服务

在本节中，我们将在创建的 EC2 实例上设置 BrownField 微服务。在这种情况下，构建设置在本地桌面机器上，并且二进制文件将部署到 AWS。

执行以下步骤在 EC2 实例上设置服务：

1.  通过以下命令安装 Git：

```java
sudo apt-get install git

```

1.  在任意文件夹上创建一个 Git 存储库。

1.  更改配置服务器的`bootstrap.properties`，指向为本例创建的适当 Git 存储库。

1.  更改所有微服务的`bootstrap.properties`，指向使用 EC2 实例的私有 IP 地址的配置服务器。

1.  将本地 Git 存储库中的所有`*.properties`复制到 EC2 Git 存储库并执行提交。

1.  更改`*.properties`文件中的 Eureka 服务器 URL 和 RabbitMQ URL，以匹配 EC2 私有 IP 地址。完成后将更改提交到 Git。

1.  在本地机器上重新编译所有项目，并为`search`、`search-apigateway`和`website`微服务创建 Docker 镜像。将它们全部推送到 Docker Hub 注册表。

1.  从本地机器复制配置服务器和 Eureka 服务器的二进制文件到 EC2 实例。

1.  在 EC2 实例上设置 Java 8。

1.  然后，按顺序执行以下命令：

```java
java –jar config-server.jar 
java –jar eureka-server.jar 
docker run –net host rabbitmq:3
docker run --net host -p 8090:8090 rajeshrv/search:1.0
docker run --net host -p 8095:8095 rajeshrv/search-apigateway:1.0
docker run --net host -p 8001:8001 rajeshrv/website:1.0

```

1.  通过打开网站的 URL 并执行搜索来检查所有服务是否正常工作。请注意，在这种情况下我们将使用公共 IP 地址：`http://54.165.128.23:8001`。

# 更新生命周期管理器

在第六章中，*自动缩放微服务*，我们考虑了一个生命周期管理器来自动启动和停止实例。我们使用 SSH 并执行 Unix 脚本来在目标机器上启动 Spring Boot 微服务。使用 Docker，我们不再需要 SSH 连接，因为 Docker 守护程序提供了基于 REST 的 API 来启动和停止实例。这极大地简化了生命周期管理器的部署引擎组件的复杂性。

在本节中，我们不会重写生命周期管理器。总的来说，我们将在下一章中替换生命周期管理器。

# 容器化的未来 - 单内核和强化安全

容器化仍在不断发展，但采用容器化技术的组织数量近年来有所增加。虽然许多组织正在积极采用 Docker 和其他容器技术，但这些技术的缺点仍在于容器的大小和安全问题。

目前，Docker 镜像通常很大。在一个弹性自动化的环境中，容器经常被创建和销毁，大小仍然是一个问题。更大的大小表示更多的代码，更多的代码意味着更容易受到安全漏洞的影响。

未来绝对在小型容器中。Docker 正在研究单内核，轻量级内核可以在低功率的物联网设备上运行 Docker。单内核不是完整的操作系统，但它们提供了支持部署应用程序所需的基本库。

容器的安全问题被广泛讨论和辩论。关键的安全问题围绕用户命名空间隔离或用户 ID 隔离。如果容器在根目录上，则可以默认获取主机的根权限。使用来自不受信任来源的容器镜像是另一个安全问题。Docker 正在尽快弥合这些差距，但有许多组织使用虚拟机和 Docker 的组合来规避一些安全顾虑。

# 总结

在本章中，您了解了在处理互联网规模的微服务时需要具有云环境的必要性。

我们探讨了容器的概念，并将其与传统虚拟机进行了比较。您还学习了 Docker 的基础知识，我们解释了 Docker 镜像、容器和注册表的概念。在微服务的背景下解释了容器的重要性和好处。

然后，本章转向了一个实际示例，通过将 BrownField 微服务 docker 化。我们演示了如何在 Docker 上部署之前开发的 Spring Boot 微服务。通过探索本地注册表以及 Docker Hub 来推送和拉取 docker 化的微服务，您学习了注册表的概念。

作为最后一步，我们探讨了如何在 AWS 云环境中部署一个 dockerized 的 BrownField 微服务。


# 第九章：使用 Mesos 和 Marathon 管理 docker 化的微服务

在互联网规模的微服务部署中，要管理成千上万个 docker 化的微服务并不容易。必须有一个基础设施抽象层和一个强大的集群控制平台，才能成功地管理互联网规模的微服务部署。

本章将解释在云环境中部署大规模微服务时，需要使用 Mesos 和 Marathon 作为基础设施抽象层和集群控制系统，以实现优化的资源使用。本章还将提供在云环境中设置 Mesos 和 Marathon 的逐步方法。最后，本章将演示如何在 Mesos 和 Marathon 环境中管理 docker 化的微服务。

在本章结束时，您将学到：

+   需要有一个抽象层和集群控制软件

+   从微服务的角度看 Mesos 和 Marathon

+   使用 Mesos 和 Marathon 管理 docker 化的 BrownField 航空公司 PSS 微服务

# 审查微服务能力模型

在本章中，我们将探讨微服务能力模型中的**集群控制和供应**微服务能力，该模型在第三章中讨论了*应用微服务概念*：

![审查微服务能力模型](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-msvc/img/B05447_09_01.jpg)

# 缺失的部分

在第八章中，我们讨论了如何将 BrownField 航空公司的 PSS 微服务 docker 化。Docker 帮助打包了 JVM 运行时和应用程序的 OS 参数，这样在将 docker 化的微服务从一个环境移动到另一个环境时就不需要特别考虑。Docker 提供的 REST API 简化了生命周期管理器与目标机器在启动和停止构件时的交互。

在大规模部署中，有数百甚至数千个 Docker 容器，我们需要确保 Docker 容器以自己的资源约束运行，例如内存、CPU 等。除此之外，可能还会为 Docker 部署设置规则，例如不应在同一台机器上运行容器的复制副本。此外，需要建立一种机制，以最佳地利用服务器基础设施，避免产生额外成本。

有些组织处理数十亿个容器。手动管理它们几乎是不可能的。在大规模 Docker 部署的情况下，需要回答一些关键问题：

+   如何管理成千上万的容器？

+   如何监视它们？

+   在部署构件时，我们如何应用规则和约束？

+   如何确保我们正确利用容器以获得资源效率？

+   如何确保至少在任何时候运行一定数量的最小实例？

+   如何确保依赖服务正在运行？

+   如何进行滚动升级和优雅迁移？

+   如何回滚故障部署？

所有这些问题都指向了需要解决两个关键能力的需求，这两个能力如下：

+   提供统一抽象的集群抽象层，覆盖许多物理或虚拟机器。

+   一个集群控制和初始化系统，以智能地管理集群抽象之上的部署

生命周期管理器理想地处理这些情况。可以向生命周期管理器添加足够的智能来解决这些问题。但是，在尝试修改生命周期管理器之前，重要的是更深入地了解集群管理解决方案的作用。

# 为什么集群管理很重要

由于微服务将应用程序分解为不同的微应用程序，许多开发人员请求更多的服务器节点进行部署。为了正确管理微服务，开发人员倾向于每个 VM 部署一个微服务，这进一步降低了资源利用率。在许多情况下，这导致 CPU 和内存的过度分配。

在许多部署中，微服务的高可用性要求迫使工程师为冗余添加越来越多的服务实例。实际上，尽管它提供了所需的高可用性，但这将导致服务器实例的资源利用不足。

一般来说，与单片应用程序部署相比，微服务部署需要更多的基础设施。由于基础设施成本的增加，许多组织未能看到微服务的价值：

![为什么集群管理很重要](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-msvc/img/B05447_09_02.jpg)

为了解决之前提到的问题，我们需要一个具备以下功能的工具：

+   自动化一系列活动，如高效地将容器分配给基础设施，并使开发人员和管理员对此保持透明

+   为开发人员提供一个抽象层，使他们可以在不知道要使用哪台机器来托管他们的应用程序的情况下，部署他们的应用程序到数据中心

+   针对部署工件设置规则或约束

+   为开发人员和管理员提供更高级别的灵活性，同时减少管理开销，或许还能减少人为干预

+   通过最大限度地利用可用资源来以成本效益的方式构建、部署和管理应用程序

容器在这个背景下解决了一个重要问题。我们选择的任何具备这些功能的工具都可以以统一的方式处理容器，而不考虑底层的微服务技术。

# 集群管理的作用是什么？

典型的集群管理工具帮助虚拟化一组机器，并将它们作为单个集群进行管理。集群管理工具还帮助在机器之间移动工作负载或容器，同时对消费者保持透明。技术布道者和实践者使用不同的术语，如集群编排、集群管理、数据中心虚拟化、容器调度器、容器生命周期管理、容器编排、数据中心操作系统等。

许多这些工具目前既支持基于 Docker 的容器，也支持非容器化的二进制部署，比如独立的 Spring Boot 应用程序。这些集群管理工具的基本功能是将实际的服务器实例与应用程序开发人员和管理员抽象出来。

集群管理工具帮助自助服务和基础设施的预配，而不是要求基础设施团队分配所需的具有预定义规格的机器。在这种自动化的集群管理方法中，机器不再提前预配和预分配给应用程序。一些集群管理工具还帮助在许多异构机器或数据中心之间虚拟化数据中心，并创建一个弹性的、类似私有云的基础设施。集群管理工具没有标准的参考模型。因此，供应商之间的功能差异很大。

集群管理软件的一些关键功能总结如下：

+   **集群管理**：它将一组虚拟机和物理机作为单个大型机器进行管理。这些机器在资源能力方面可能是异构的，但它们基本上都是运行 Linux 操作系统的机器。这些虚拟集群可以在云上、本地或两者的组合上形成。

+   **部署**：它处理大量机器的应用程序和容器的自动部署。它支持应用程序容器的多个版本，还支持跨大量集群机器的滚动升级。这些工具还能够处理故障推广的回滚。

+   **可扩展性**：它处理应用程序实例的自动和手动扩展，以优化利用率为主要目标。

+   **健康**：它管理集群、节点和应用程序的健康状况。它会从集群中删除故障机器和应用实例。

+   **基础设施抽象化**：它将开发人员与应用程序部署的实际机器抽象出来。开发人员不需要担心机器、其容量等等。完全由集群管理软件决定如何调度和运行应用程序。这些工具还将机器细节、其容量、利用率和位置从开发人员那里抽象出来。对于应用程序所有者来说，这些等同于一个具有几乎无限容量的单个大型机器。

+   **资源优化**：这些工具的固有行为是以高效的方式在一组可用的机器上分配容器工作负载，从而降低所有权成本。可以有效地使用简单到极其复杂的算法来提高利用率。

+   **资源分配**：它根据资源可用性和应用程序开发人员设置的约束来分配服务器。资源分配基于这些约束、亲和规则、端口需求、应用程序依赖性、健康状况等。

+   **服务可用性**：确保服务在集群中的某个地方正常运行。在发生机器故障时，集群控制工具会自动通过在集群中的其他机器上重新启动这些服务来处理故障。

+   **灵活性**：这些工具能够快速地将工作负载分配给可用资源，或者在资源需求发生变化时将工作负载移动到其他机器上。还可以根据业务的关键性、业务优先级等设置约束，重新调整资源。

+   **隔离**：其中一些工具可以直接提供资源隔离。因此，即使应用程序未经容器化，仍然可以实现资源隔离。

用于资源分配的算法种类繁多，从简单算法到复杂算法，再到机器学习和人工智能。常用的算法包括随机算法、装箱算法和分散算法。根据资源可用性设置的约束将覆盖默认算法：

![集群管理的作用是什么？](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-msvc/img/B05447_09_03.jpg)

上图显示了这些算法如何填充可用的机器部署。在这种情况下，演示了两台机器：

+   **分散**：此算法在可用的机器上均匀分配工作负载。这在图**A**中显示。

+   **装箱**：此算法尝试逐个填充数据机器，并确保最大限度地利用机器。在使用按需付费的云服务时，装箱算法尤其有效。这在图**B**中显示。

+   **随机**：此算法随机选择机器，并在随机选择的机器上部署容器。这在图**C**中显示。

有可能使用认知计算算法，如机器学习和协同过滤来提高效率。诸如**超额分配**之类的技术允许通过为高优先级任务分配未充分利用的资源来更好地利用资源，例如为收入产生服务分配最佳努力任务，如分析、视频、图像处理等。

# 与微服务的关系

如果微服务基础架构没有得到适当的配置，很容易导致过度的基础架构，从而增加拥有成本。正如前面所讨论的，具有集群管理工具的类似云的环境对于处理大规模微服务时实现成本效益至关重要。

使用 Spring Cloud 项目进行加速的 Spring Boot 微服务是利用集群管理工具的理想候选工作负载。由于基于 Spring Cloud 的微服务不知道位置，这些服务可以在集群中的任何位置部署。每当服务启动时，它们会自动注册到服务注册表并宣布其可用性。另一方面，消费者始终在注册表中查找可用的服务实例。这样，应用程序支持完全流动的结构，而不预设部署拓扑。通过 Docker，我们能够抽象运行时，使服务能够在任何基于 Linux 的环境中运行。

# 与虚拟化的关系

集群管理解决方案在许多方面与服务器虚拟化解决方案不同。集群管理解决方案作为应用程序组件运行在 VM 或物理机上。

# 集群管理解决方案

市场上有许多集群管理软件工具可用。对它们进行苹果对苹果的比较是不公平的。尽管没有一对一的组件，但它们之间在功能上有许多重叠的领域。在许多情况下，组织使用一个或多个这些工具的组合来满足他们的需求。

以下图表显示了微服务环境下集群管理工具的位置：

![集群管理解决方案](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-msvc/img/B05447_09_04.jpg)

在本节中，我们将探讨市场上可用的一些流行的集群管理解决方案。

## Docker Swarm

Docker Swarm 是 Docker 的本地集群管理解决方案。Swarm 与 Docker 有本地和更深层次的集成，并公开与 Docker 远程 API 兼容的 API。Docker Swarm 在逻辑上将一组 Docker 主机分组，并将它们作为单个大型 Docker 虚拟主机进行管理。与应用程序管理员和开发人员决定将容器部署在哪个主机不同，这个决策将被委托给 Docker Swarm。Docker Swarm 将根据装箱和扩展算法决定使用哪个主机。

由于 Docker Swarm 基于 Docker 的远程 API，对于已经使用 Docker 的人来说，其学习曲线比任何其他容器编排工具都要窄。然而，Docker Swarm 是市场上相对较新的产品，它只支持 Docker 容器。

Docker Swarm 使用**管理器**和**节点**的概念。管理器是管理人员与 Docker 容器进行交互和调度的单一点。节点是部署和运行 Docker 容器的地方。

## Kubernetes

Kubernetes（k8s）来自谷歌的工程，使用 Go 语言编写，并在谷歌进行了大规模部署的实战测试。与 Swarm 类似，Kubernetes 帮助管理跨节点集群的容器化应用程序。Kubernetes 帮助自动化容器部署、调度和容器的可伸缩性。Kubernetes 支持许多有用的功能，例如自动渐进式部署、版本化部署以及容器的弹性，如果容器由于某种原因失败。

Kubernetes 架构具有**主节点**，**节点**和**Pods**的概念。主节点和节点一起形成一个 Kubernetes 集群。主节点负责在多个节点之间分配和管理工作负载。节点只是一个虚拟机或物理机。节点进一步细分为 Pods。一个节点可以托管多个 Pods。一个或多个容器被分组并在一个 Pod 内执行。Pods 还有助于管理和部署共同服务以提高效率。Kubernetes 还支持标签的概念，作为键值对来查询和找到容器。标签是用户定义的参数，用于标记执行共同类型工作负载的某些类型的节点，例如前端 Web 服务器。部署在集群上的服务获得一个单一的 IP/DNS 来访问该服务。

Kubernetes 对 Docker 有开箱即用的支持；然而，与 Docker Swarm 相比，Kubernetes 的学习曲线更陡峭。RedHat 作为其 OpenShift 平台的一部分，为 Kubernetes 提供商业支持。

## Apache Mesos

Mesos 是由加州大学伯克利分校最初开发的开源框架，被 Twitter 大规模使用。Twitter 主要使用 Mesos 来管理庞大的 Hadoop 生态系统。

Mesos 与之前的解决方案略有不同。Mesos 更像是一个资源管理器，依赖其他框架来管理工作负载的执行。Mesos 位于操作系统和应用程序之间，提供了一个逻辑机器集群。

Mesos 是一个分布式系统内核，它将许多计算机逻辑分组和虚拟化为一个大型机器。Mesos 能够将多种异构资源分组到一个统一的资源集群上，应用程序可以在其上部署。因此，Mesos 也被称为在数据中心构建私有云的工具。

Mesos 具有**主节点**和**从节点**的概念。与之前的解决方案类似，主节点负责管理集群，而从节点运行工作负载。Mesos 内部使用 ZooKeeper 进行集群协调和存储。Mesos 支持框架的概念。这些框架负责调度和运行非容器化应用程序和容器。Marathon，Chronos 和 Aurora 是用于调度和执行应用程序的流行框架。Netflix Fenzo 是另一个开源的 Mesos 框架。有趣的是，Kubernetes 也可以用作 Mesos 框架。

Marathon 支持 Docker 容器以及非容器化应用程序。Spring Boot 可以直接在 Marathon 中配置。Marathon 提供了许多开箱即用的功能，例如支持应用程序依赖关系，将应用程序分组以扩展和升级服务，启动和关闭健康和不健康的实例，推出推广，回滚失败的推广等。

Mesosphere 为 Mesos 和 Marathon 提供商业支持，作为其 DCOS 平台的一部分。

## Nomad

HashiCorp 的 Nomad 是另一个集群管理软件。Nomad 是一个集群管理系统，它抽象了较低级别的机器细节和它们的位置。Nomad 的架构与之前探讨的其他解决方案相比更简单。Nomad 也更轻量级。与其他集群管理解决方案类似，Nomad 负责资源分配和应用程序的执行。Nomad 还接受用户特定的约束，并根据此分配资源。

Nomad 具有**服务器**的概念，所有作业都由其管理。一个服务器充当**领导者**，其他充当**跟随者**。Nomad 具有**任务**的概念，这是最小的工作单位。任务被分组成**任务组**。一个任务组有在相同位置执行的任务。一个或多个任务组或任务被管理为**作业**。

Nomad 支持许多工作负载，包括 Docker，开箱即用。Nomad 还支持跨数据中心的部署，并且具有区域和数据中心感知能力。

## 舰队

Fleet 是 CoreOS 的集群管理系统。它在较低级别上运行，并在 systemd 之上工作。Fleet 可以管理应用程序依赖关系，并确保所有所需的服务在集群中的某个地方运行。如果服务失败，它会在另一个主机上重新启动服务。在分配资源时可以提供亲和性和约束规则。

Fleet 具有**引擎**和**代理**的概念。在集群中任何时候只有一个引擎，但有多个代理。任务提交给引擎，代理在集群机器上运行这些任务。

Fleet 也支持 Docker。

# 使用 Mesos 和 Marathon 进行集群管理

正如我们在前一节中讨论的，有许多集群管理解决方案或容器编排工具可供选择。不同的组织根据其环境选择不同的解决方案来解决问题。许多组织选择 Kubernetes 或带有 Marathon 等框架的 Mesos。在大多数情况下，Docker 被用作默认的容器化方法来打包和部署工作负载。

在本章的其余部分，我们将展示 Mesos 如何与 Marathon 一起提供所需的集群管理能力。许多组织使用 Mesos，包括 Twitter、Airbnb、Apple、eBay、Netflix、PayPal、Uber、Yelp 等。

## 深入了解 Mesos

Mesos 可以被视为数据中心内核。DCOS 是 Mesos 的商业版本，由 Mesosphere 支持。为了在一个节点上运行多个任务，Mesos 使用资源隔离概念。Mesos 依赖于 Linux 内核的**cgroups**来实现类似容器方法的资源隔离。它还支持使用 Docker 进行容器化隔离。Mesos 支持批处理工作负载以及 OLTP 类型的工作负载：

![深入了解 Mesos](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-msvc/img/B05447_09_05.jpg)

Mesos 是一个在 Apache 许可下的开源顶级 Apache 项目。Mesos 将 CPU、内存和存储等较低级别的计算资源从较低级别的物理或虚拟机中抽象出来。

在我们研究为什么需要 Mesos 和 Marathon 之前，让我们先了解 Mesos 架构。

### Mesos 架构

以下图表显示了 Mesos 的最简单的架构表示。Mesos 的关键组件包括一个 Mesos 主节点，一组从属节点，一个 ZooKeeper 服务和一个 Mesos 框架。Mesos 框架进一步分为两个组件：调度程序和执行程序：

![Mesos 架构](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-msvc/img/B05447_09_06.jpg)

前面图表中的方框解释如下：

+   **主节点**：Mesos 主节点负责管理所有 Mesos 从属节点。Mesos 主节点从所有从属节点获取资源可用性信息，并负责根据特定资源策略和约束适当地填充资源。Mesos 主节点从所有从属机器中抢占可用资源，并将它们汇集为一个单一的大型机器。主节点根据这个资源池向运行在从属机器上的框架提供资源。

为了实现高可用性，Mesos 主节点由 Mesos 主节点的备用组件支持。即使主节点不可用，现有任务仍然可以执行。但是，在没有主节点的情况下无法调度新任务。主节点备用节点是等待活动主节点故障并在故障发生时接管主节点角色的节点。它使用 ZooKeeper 进行主节点领导者选举。领导者选举必须满足最低法定人数要求。

+   **从属节点**：Mesos 从属节点负责托管任务执行框架。任务在从属节点上执行。Mesos 从属节点可以以键值对的形式启动，例如*数据中心=X*。这在部署工作负载时用于约束评估。从属机器与 Mesos 主节点共享资源可用性。

+   ZooKeeper：ZooKeeper 是 Mesos 中使用的集中协调服务器，用于协调 Mesos 集群中的活动。在 Mesos 主节点故障的情况下，Mesos 使用 ZooKeeper 进行领导者选举。

+   框架：Mesos 框架负责理解应用程序的约束，接受主节点的资源提供，并最终在主节点提供的从属资源上运行任务。Mesos 框架由两个组件组成：框架调度程序和框架执行程序：

+   调度程序负责注册到 Mesos 并处理资源提供

+   执行程序在 Mesos 从属节点上运行实际程序

框架还负责执行某些策略和约束。例如，一个约束可以是，假设最少有 500MB 的 RAM 可用于执行。

框架是可插拔组件，可以用另一个框架替换。框架工作流程如下图所示：

![Mesos 架构](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-msvc/img/B05447_09_07.jpg)

在前面的工作流程图中表示的步骤如下所述：

1.  框架向 Mesos 主节点注册并等待资源提供。调度程序可能有许多任务在其队列中等待执行，具有不同的资源约束（例如，在此示例中为任务 A 到 D）。在这种情况下，任务是安排的工作单元，例如 Spring Boot 微服务。

1.  Mesos 从属将可用资源提供给 Mesos 主节点。例如，从属会广告其机器上可用的 CPU 和内存。

1.  然后，Mesos 主节点根据设置的分配策略创建资源提供，并将其提供给框架的调度组件。分配策略确定资源将提供给哪个框架以及将提供多少资源。可以通过插入额外的分配策略来自定义默认策略。

1.  基于约束、能力和策略的调度框架组件可能接受或拒绝资源提供。例如，如果资源不足，框架会拒绝资源提供，根据设置的约束和策略。

1.  如果调度程序组件接受资源提供，它将提交一个或多个任务的详细信息给 Mesos 主节点，每个任务都有资源约束。例如，在这个例子中，它准备好提交任务 A 到 D。

1.  Mesos 主节点将任务列表发送给资源可用的从属。安装在从属机器上的框架执行程序组件会接收并运行这些任务。

Mesos 支持许多框架，例如：

+   用于长时间运行的进程（例如 Web 应用程序）的 Marathon 和 Aurora

+   用于大数据处理的 Hadoop、Spark 和 Storm

+   用于批处理调度的 Chronos 和 Jenkins

+   用于数据管理的 Cassandra 和 Elasticsearch

在本章中，我们将使用 Marathon 来运行 docker 化的微服务。

### Marathon

Marathon 是 Mesos 框架实现之一，可以运行容器和非容器执行。Marathon 特别设计用于长时间运行的应用程序，例如 Web 服务器。Marathon 确保使用 Marathon 启动的服务即使 Mesos 上托管的从属失败也能继续可用。这将通过启动另一个实例来完成。

Marathon 是用 Scala 编写的，具有高度可扩展性。Marathon 提供 UI 以及 REST API 与 Marathon 交互，例如启动、停止、扩展和监视应用程序。

与 Mesos 类似，Marathon 的高可用性是通过运行指向 ZooKeeper 实例的多个 Marathon 实例来实现的。其中一个 Marathon 实例充当领导者，其他实例处于待机模式。如果领先的主节点失败，将进行领导者选举，并确定下一个活动主节点。

Marathon 的一些基本特性包括：

+   设置资源约束

+   应用程序的扩展、缩减和实例管理

+   应用程序版本管理

+   启动和关闭应用程序

Marathon 的一些高级功能包括：

+   滚动升级、滚动重启和回滚

+   蓝绿部署

# 为 BrownField 微服务实现 Mesos 和 Marathon

在本节中，将部署在 AWS 云中并使用 Mesos 和 Marathon 进行管理的 docker 化的 Brownfield 微服务，该微服务在第八章中开发。

为了演示目的，解释中只涵盖了三个服务（**搜索**、**搜索 API 网关**和**网站**）：

![为 BrownField 微服务实现 Mesos 和 Marathon](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-msvc/img/B05447_09_08.jpg)

目标状态实现的逻辑架构如上图所示。该实现使用多个 Mesos 从属实例来执行 docker 化的微服务，其中包括一个 Mesos 主节点。使用 Marathon 调度程序组件来调度 docker 化的微服务。docker 化的微服务托管在 Docker Hub 注册表上。docker 化的微服务使用 Spring Boot 和 Spring Cloud 实现。

以下图表显示了物理部署架构：

![为 BrownField 微服务实现 Mesos 和 Marathon](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-msvc/img/B05447_09_09.jpg)

如上图所示，在本示例中，我们将使用四个 EC2 实例：

+   **EC2-M1**：这个托管了 Mesos 主节点、ZooKeeper、Marathon 调度程序和一个 Mesos 从属实例

+   **EC2-M2**：这个托管了一个 Mesos 从属实例

+   **EC2-M3**：这个托管了另一个 Mesos 从属实例

+   **EC2-M4**：这个托管了 Eureka、配置服务器和 RabbitMQ

对于真正的生产设置，需要多个 Mesos 主节点以及多个 Marathon 实例来实现容错。

## 设置 AWS

启动四个将用于此部署的**t2.micro** EC2 实例。所有四个实例必须在同一个安全组中，以便实例可以使用它们的本地 IP 地址相互看到。

以下表格显示了机器详细信息和 IP 地址，仅供参考和链接后续指令：

![设置 AWS](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-msvc/img/B05447_09_10.jpg)

| 实例 ID | 私有 DNS/IP | 公有 DNS/IP |
| --- | --- | --- |
| `i-06100786` | `ip-172-31-54-69.ec2.internal``172.31.54.69` | `ec2-54-85-107-37.compute-1.amazonaws.com``54.85.107.37` |
| `i-2404e5a7` | `ip-172-31-62-44.ec2.internal``172.31.62.44` | `ec2-52-205-251-150.compute-1.amazonaws.com``52.205.251.150` |
| `i-a7df2b3a` | `ip-172-31-49-55.ec2.internal``172.31.49.55` | `ec2-54-172-213-51.compute-1.amazonaws.com``54.172.213.51` |
| `i-b0eb1f2d` | `ip-172-31-53-109.ec2.internal``172.31.53.109` | `ec2-54-86-31-240.compute-1.amazonaws.com``54.86.31.240` |

根据您的 AWS EC2 配置替换 IP 和 DNS 地址。

## 安装 ZooKeeper、Mesos 和 Marathon

在部署中将使用以下软件版本。本节中的部署遵循前一节中解释的物理部署架构：

+   Mesos 版本 0.27.1

+   Docker 版本 1.6.2，构建 7c8fca2

+   Marathon 版本 0.15.3

### 注意

有关设置 ZooKeeper、Mesos 和 Marathon 的详细说明，请参阅[`open.mesosphere.com/getting-started/install/`](https://open.mesosphere.com/getting-started/install/)。

执行以下步骤进行最小化安装 ZooKeeper、Mesos 和 Marathon 以部署 BrownField 微服务：

1.  作为先决条件，所有机器上必须安装 JRE 8。执行以下命令：

```java
sudo apt-get -y install oracle-java8-installer

```

1.  通过以下命令在所有标记为 Mesos 从属实例的机器上安装 Docker：

```java
sudo apt-get install docker

```

1.  打开终端窗口并执行以下命令。这些命令设置了用于安装的存储库：

```java
sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv E56151BF
DISTRO=$(lsb_release -is | tr '[:upper:]' '[:lower:]')
CODENAME=$(lsb_release -cs)
# Add the repository
echo "deb http://repos.mesosphere.com/${DISTRO} ${CODENAME} main" | \
 sudo tee /etc/apt/sources.list.d/mesosphere.list
sudo apt-get -y update

```

1.  执行以下命令安装 Mesos 和 Marathon。这也将安装 Zookeeper 作为依赖项：

```java
sudo apt-get -y install mesos marathon

```

在为 Mesos slave 执行保留的三个 EC2 实例上重复上述步骤。作为下一步，必须在为 Mesos 主节点标识的机器上配置 ZooKeeper 和 Mesos。

### 配置 ZooKeeper

连接到为 Mesos 主节点和 Marathon 调度器保留的机器。在这种情况下，`172.31.54.69`将用于设置 ZooKeeper、Mesos 主节点和 Marathon。

ZooKeeper 需要进行两个配置更改，如下：

1.  第一步是将`/etc/zookeeper/conf/myid`设置为介于`1`和`255`之间的唯一整数，如下所示：

```java
Open vi /etc/zookeeper/conf/myid and set 1\. 

```

1.  下一步是编辑`/etc/zookeeper/conf/zoo.cfg`。更新文件以反映以下更改：

```java
# specify all zookeeper servers
# The first port is used by followers to connect to the leader
# The second one is used for leader election
server.1= 172.31.54.69:2888:3888
#server.2=zookeeper2:2888:3888
#server.3=zookeeper3:2888:3888
```

用相关的私有 IP 地址替换 IP 地址。在这种情况下，我们将只使用一个 ZooKeeper 服务器，但在生产场景中，需要多个服务器以实现高可用性。

### 配置 Mesos

对 Mesos 配置进行更改，以指向 ZooKeeper，设置仲裁，并通过以下步骤启用 Docker 支持：

1.  编辑`/etc/mesos/zk`以设置以下值。这是为了将 Mesos 指向 ZooKeeper 实例进行仲裁和领导者选举：

```java
zk:// 172.31.54.69:2181/mesos 
```

1.  编辑`/etc/mesos-master/quorum`文件，并将值设置为`1`。在生产场景中，可能需要最少三个仲裁：

```java
vi /etc/mesos-master/quorum

```

1.  默认的 Mesos 安装不支持 Mesos slave 上的 Docker。为了启用 Docker，更新以下`mesos-slave`配置：

```java
echo 'docker,mesos' > /etc/mesos-slave/containerizers

```

### 作为服务运行 Mesos、Marathon 和 ZooKeeper

所有必需的配置更改都已实施。启动 Mesos、Marathon 和 Zookeeper 的最简单方法是将它们作为服务运行，如下所示：

+   以下命令启动服务。服务需要按以下顺序启动：

```java
sudo service zookeeper start
sudo service mesos-master start
sudo service mesos-slave start
sudo service marathon start

```

+   在任何时候，可以使用以下命令来停止这些服务：

```java
sudo service zookeeper stop
sudo service mesos-master stop
sudo service mesos-slave stop
sudo service marathon stop

```

+   一旦服务启动并运行，使用终端窗口验证服务是否正在运行：![作为服务运行的 Mesos、Marathon 和 ZooKeeper](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-msvc/img/B05447_09_11.jpg)

#### 在命令行中运行 Mesos slave

在这个例子中，我们将使用命令行版本来调用 Mesos slave，以展示额外的输入参数，而不是使用 Mesos slave 服务。停止 Mesos slave，并使用此处提到的命令行来重新启动 slave：

```java
$sudo service mesos-slave stop

$sudo /usr/sbin/mesos-slave  --master=172.31.54.69:5050 --log_dir=/var/log/mesos --work_dir=/var/lib/mesos --containerizers=mesos,docker --resources="ports(*):[8000-9000, 31000-32000]"

```

所使用的命令行参数解释如下：

+   `--master=172.31.54.69:5050`：此参数用于告诉 Mesos slave 连接到正确的 Mesos 主节点。在这种情况下，只有一个主节点在`172.31.54.69:5050`运行。所有的 slave 都连接到同一个 Mesos 主节点。

+   `--containerizers=mesos,docker`：此参数用于启用对 Docker 容器执行以及在 Mesos slave 实例上的非容器化执行的支持。

+   `--resources="ports(*):[8000-9000, 31000-32000]`：此参数表示 slave 在绑定资源时可以提供两个端口范围。`31000`到`32000`是默认范围。由于我们使用以`8000`开头的端口号，因此很重要告诉 Mesos slave 也允许从`8000`开始暴露端口。

执行以下步骤来验证 Mesos 和 Marathon 的安装：

1.  在所有为 slave 指定的三个实例上执行前面步骤中提到的命令来启动 Mesos slave。由于它们都连接到同一个主节点，因此可以在所有三个实例上使用相同的命令。

1.  如果 Mesos slave 成功启动，控制台中将出现类似以下的消息：

```java
I0411 18:11:39.684809 16665 slave.cpp:1030] Forwarding total oversubscribed resources

```

上述消息表明 Mesos slave 开始定期向 Mesos 主节点发送资源可用性的当前状态。

1.  打开`http://54.85.107.37:8080`来检查 Marathon UI。用 EC2 实例的公共 IP 地址替换 IP 地址：![在命令行中运行 Mesos slave](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-msvc/img/B05447_09_12.jpg)

由于目前尚未部署任何应用程序，因此 UI 的**应用程序**部分为空。

1.  打开运行在端口`5050`上的 Mesos UI，访问`http://54.85.107.37:5050`：![在命令行中运行 Mesos 从属](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-msvc/img/B05447_09_13.jpg)

控制台的**从属**部分显示有三个已激活的 Mesos 从属可用于执行。它还表明没有活动任务。

### 准备 BrownField PSS 服务

在上一节中，我们成功地设置了 Mesos 和 Marathon。在本节中，我们将看看如何部署之前使用 Mesos 和 Marathon 开发的 BrownField PSS 应用程序。

### 注意

本章的完整源代码可在代码文件的`第九章`项目中找到。将`chapter8.configserver`、`chapter8.eurekaserver`、`chapter8.search`、`chapter8.search-apigateway`和`chapter8.website`复制到一个新的 STS 工作区，并将它们重命名为`chapter9.*`。

1.  在部署任何应用程序之前，我们必须在其中一个服务器上设置配置服务器、Eureka 服务器和 RabbitMQ。按照第八章中描述的*在 EC2 上运行 BrownField 服务*部分中描述的步骤，使用 Docker 容器化微服务。或者，我们可以在前一章中用于此目的的相同实例上使用。

1.  将所有`bootstrap.properties`文件更改为反映配置服务器的 IP 地址。

1.  在部署我们的服务之前，微服务需要进行一些特定的更改。当在 BRIDGE 模式下运行 docker 化的微服务时，我们需要告诉 Eureka 客户端要使用的主机名。默认情况下，Eureka 使用**实例 ID**进行注册。然而，这并不有用，因为 Eureka 客户端将无法使用实例 ID 查找这些服务。在上一章中，使用了 HOST 模式而不是 BRIDGE 模式。

主机名设置可以使用`eureka.instance.hostname`属性来完成。然而，在特定情况下在 AWS 上运行时，另一种方法是在微服务中定义一个 bean 来获取 AWS 特定的信息，如下所示：

```java
@Configuration
class EurekaConfig { 
@Bean
    public EurekaInstanceConfigBean eurekaInstanceConfigBean() {
    EurekaInstanceConfigBean config = new EurekaInstanceConfigBean(new InetUtils(new InetUtilsProperties()));
AmazonInfo info = AmazonInfo.Builder.newBuilder().autoBuild("eureka");
        config.setDataCenterInfo(info);
        info.getMetadata().put(AmazonInfo.MetaDataKey.publicHostname.getName(), info.get(AmazonInfo.MetaDataKey.publicIpv4));
        config.setHostname(info.get(AmazonInfo.MetaDataKey.localHostname));       
config.setNonSecurePortEnabled(true);
config.setNonSecurePort(PORT); 
config.getMetadataMap().put("instanceId",  info.get(AmazonInfo.MetaDataKey.localHostname));
return config;
}
```

上述代码使用亚马逊主机信息使用 Netflix API 提供了自定义的 Eureka 服务器配置。该代码使用私有 DNS 覆盖了主机名和实例 ID。端口从配置服务器中读取。该代码还假定每个服务一个主机，以便端口号在多次部署中保持不变。这也可以通过在运行时动态读取端口绑定信息来覆盖。

上述代码必须应用于所有微服务。

1.  使用 Maven 重新构建所有微服务。构建并推送 Docker 镜像到 Docker Hub。三个服务的步骤如下所示。对所有其他服务重复相同的步骤。在执行这些命令之前，工作目录需要切换到相应的目录：

```java
docker build -t search-service:1.0 .
docker tag search-service:1.0 rajeshrv/search-service:1.0
docker push rajeshrv/search-service:1.0

docker build -t search-apigateway:1.0 .
docker tag search-apigateway:1.0 rajeshrv/search-apigateway:1.0
docker push rajeshrv/search-apigateway:1.0

docker build -t website:1.0 .
docker tag website:1.0 rajeshrv/website:1.0
docker push rajeshrv/website:1.0

```

### 部署 BrownField PSS 服务

Docker 镜像现在已发布到 Docker Hub 注册表。执行以下步骤来部署和运行 BrownField PSS 服务：

1.  在专用实例上启动配置服务器、Eureka 服务器和 RabbitMQ。

1.  确保 Mesos 服务器和 Marathon 正在配置 Mesos 主服务器的机器上运行。

1.  按照之前描述的在所有机器上运行 Mesos 从属的命令行来运行 Mesos 从属。

1.  此时，Mesos Marathon 集群已经启动并准备好接受部署。可以通过为每个服务创建一个 JSON 文件来进行部署，如下所示：

```java
{
  "id": "search-service-1.0",
  "cpus": 0.5,
  "mem": 256.0,
  "instances": 1,
  "container": {
   "docker": {
    "type": "DOCKER",
      "image": "rajeshrv/search-service:1.0",
       "network": "BRIDGE",
       "portMappings": [
        {  "containerPort": 0, "hostPort": 8090 }
      ]
    }
  }
}
```

上述 JSON 代码将存储在`search.json`文件中。同样，也为其他服务创建一个 JSON 文件。

JSON 结构解释如下：

+   `id`：这是应用程序的唯一 ID。这可以是一个逻辑名称。

+   `cpus`和`mem`：这为应用程序设置了资源约束。如果资源提供不满足这个资源约束，Marathon 将拒绝来自 Mesos 主服务器的资源提供。

+   `instances`：这决定了要启动多少个此应用程序的实例。在前面的配置中，默认情况下，一旦部署，它就会启动一个实例。Marathon 在任何时候都会保持所述实例的数量。

+   `container`：此参数告诉 Marathon 执行器使用 Docker 容器进行执行。

+   `image`：这告诉 Marathon 调度器要使用哪个 Docker 镜像进行部署。在这种情况下，它将从 Docker Hub 仓库`rajeshrv`下载`search-service:1.0`镜像。

+   `network`：此值用于 Docker 运行时建议在启动新的 Docker 容器时使用的网络模式。这可以是 BRIDGE 或 HOST。在这种情况下，将使用 BRIDGE 模式。

+   `portMappings`：端口映射提供了如何映射内部和外部端口的信息。在前面的配置中，主机端口设置为`8090`，这告诉 Marathon 执行器在启动服务时使用`8090`。由于容器端口设置为`0`，相同的主机端口将分配给容器。如果主机端口值为`0`，Marathon 会选择随机端口。

1.  还可以使用 JSON 描述符进行额外的健康检查，如下所示：

```java
"healthChecks": [
    {
      "protocol": "HTTP",
      "portIndex": 0,
      "path": "/admin/health",
      "gracePeriodSeconds": 100,
      "intervalSeconds": 30,
      "maxConsecutiveFailures": 5
    }
  ]
```

1.  创建并保存此 JSON 代码后，使用 Marathon 的 REST API 将其部署到 Marathon：

```java
curl -X POST http://54.85.107.37:8080/v2/apps -d @search.json -H "Content-type: application/json"

```

对所有其他服务也重复此步骤。

上述步骤将自动将 Docker 容器部署到 Mesos 集群，并启动服务的一个实例。

### 审查部署

具体步骤如下：

1.  打开 Marathon UI。如下图所示，UI 显示所有三个应用程序都已部署，并处于**运行**状态。它还指示**1 个 1**实例处于**运行**状态：![审查部署](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-msvc/img/B05447_09_14.jpg)

1.  访问 Mesos UI。如下图所示，有三个**活动任务**，全部处于**运行**状态。它还显示了这些服务运行的主机：![审查部署](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-msvc/img/B05447_09_15.jpg)

1.  在 Marathon UI 中，点击正在运行的应用程序。以下屏幕截图显示了**search-apigateway-1.0**应用程序。在**实例**选项卡中，显示了服务绑定的 IP 地址和端口：![审查部署](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-msvc/img/B05447_09_16.jpg)

**扩展应用程序**按钮允许管理员指定需要多少个服务实例。这可用于扩展和缩减实例。

1.  打开 Eureka 服务器控制台，查看服务的绑定情况。如屏幕截图所示，当服务注册时，**AMI**和**可用区**会反映出来。访问`http://52.205.251.150:8761`：![审查部署](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-msvc/img/B05447_09_17.jpg)

1.  在浏览器中打开`http://54.172.213.51:8001`，验证**Website**应用程序。

# 生命周期管理器的位置

生命周期管理器在第六章中介绍，具有根据需求自动扩展或缩减实例的能力。它还具有根据策略和约束条件在一组机器上决定部署何处和如何部署应用程序的能力。生命周期管理器的能力如下图所示：

![生命周期管理器的位置](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-msvc/img/B05447_09_18.jpg)

Marathon 具有根据策略和约束条件管理集群和集群部署的能力。可以使用 Marathon UI 更改实例的数量。

我们的生命周期管理器和 Marathon 之间存在冗余的能力。有了 Marathon，就不再需要 SSH 工作或机器级脚本。此外，部署策略和约束条件可以委托给 Marathon。Marathon 提供的 REST API 可以用于启动扩展功能。

**Marathon 自动缩放**是 Mesosphere 的一个自动缩放的概念验证项目。Marathon 自动缩放提供基本的自动缩放功能，如 CPU、内存和请求速率。

## 重写生命周期管理器与 Mesos 和 Marathon

我们仍然需要一个定制的生命周期管理器来收集来自 Spring Boot 执行器端点的指标。如果缩放规则超出了 CPU、内存和缩放速率，定制的生命周期管理器也很方便。

以下图表显示了使用 Marathon 框架更新的生命周期管理器：

![重写生命周期管理器与 Mesos 和 Marathon](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-msvc/img/B05447_09_19.jpg)

在这种情况下，生命周期管理器收集来自不同 Spring Boot 应用程序的执行器指标，将它们与其他指标结合起来，并检查特定的阈值。根据缩放策略，决策引擎通知缩放引擎是缩小还是扩大。在这种情况下，缩放引擎只是一个 Marathon REST 客户端。这种方法比我们早期使用 SSH 和 Unix 脚本的原始生命周期管理器实现更清洁、更整洁。

# 技术元模型

我们已经涵盖了使用 BrownField PSS 微服务的许多内容。以下图表通过将所有使用的技术汇总到技术元模型中来总结了这一点。

![技术元模型](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-msvc/img/B05447_09_20.jpg)

# 总结

在本章中，您了解了集群管理和初始化系统在大规模高效管理 docker 化微服务的重要性。

在深入研究 Mesos 和 Marathon 之前，我们探讨了不同的集群控制或集群编排工具。我们还在 AWS 云环境中实施了 Mesos 和 Marathon，以演示如何管理为 BrownField PSS 开发的 docker 化微服务。

在本章末尾，我们还探讨了生命周期管理器在 Mesos 和 Marathon 中的位置。最后，我们基于 BrownField PSS 微服务实现，总结了本章的技术元模型。

到目前为止，我们已经讨论了成功实施微服务所需的所有核心和支持技术能力。成功的微服务实施还需要超越技术的流程和实践。下一章，也是本书的最后一章，将涵盖微服务的流程和实践视角。
