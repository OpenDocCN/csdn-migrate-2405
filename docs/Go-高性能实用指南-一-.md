# Go 高性能实用指南（一）

> 原文：[`zh.annas-archive.org/md5/CBDFC5686A090A4C898F957320E40302`](https://zh.annas-archive.org/md5/CBDFC5686A090A4C898F957320E40302)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

《Go 高性能实战》是一个完整的资源，具有经过验证的方法和技术，可帮助您诊断和解决 Go 应用程序中的性能问题。本书从性能概念入手，您将了解 Go 性能背后的思想。接下来，您将学习如何有效地实现 Go 数据结构和算法，并探索数据操作和组织，以便编写可扩展软件的程序。通道和 goroutines 用于并行和并发，以编写分布式系统的高性能代码也是本书的核心部分。接着，您将学习如何有效地管理内存。您将探索**CUDA**驱动**API**，使用容器构建 Go 代码，并利用 Go 构建缓存加快编译速度。您还将清楚地了解如何对 Go 代码进行性能分析和跟踪，以检测系统中的瓶颈。最后，您将评估集群和作业队列以进行性能优化，并监视应用程序以检测性能回归。

# 本书适合对象

这本 Go 书对于具有中级到高级 Go 编程理解的开发人员和专业人士来说是必不可少的，他们有兴趣提高代码执行速度。

# 本书涵盖内容

第一章《Go 性能简介》将讨论计算机科学中性能为何重要。您还将了解为什么 Go 语言中性能很重要。

第二章《数据结构和算法》涉及数据结构和算法，它们是构建软件的基本单元，尤其是复杂性能软件。理解它们将帮助您思考如何最有效地组织和操作数据，以编写有效的、高性能的软件。此外，迭代器和生成器对于 Go 是必不可少的。本章将包括不同数据结构和算法的解释，以及它们的大 O 符号是如何受影响的。

第三章《理解并发》将讨论利用通道和 goroutines 进行并行和并发，这在 Go 中是惯用的，也是在系统中编写高性能代码的最佳方式。能够理解何时何地使用这些设计模式对于编写高性能的 Go 是至关重要的。

第四章《Go 中的 STL 算法等价物》讨论了许多来自其他高性能语言（尤其是 C++）的程序员如何理解标准模板库的概念，该库提供了常见的编程数据结构和函数，以便快速迭代和编写大规模的高性能代码。

第五章《Go 中的矩阵和向量计算》涉及一般的矩阵和向量计算。矩阵在图形处理和人工智能中很重要，特别是图像识别。向量可以在动态数组中保存大量对象。它们使用连续存储，并可以被操作以适应增长。

第六章《编写可读的 Go 代码》着重于编写可读的 Go 代码的重要性。理解本章讨论的模式和习惯用法将帮助您编写更易读、更易操作的 Go 代码。此外，能够编写习惯用法的 Go 将有助于提高代码质量，并帮助项目保持速度。

第七章《Go 中的模板编程》专注于 Go 中的模板编程。元编程允许最终用户编写生成、操作和运行 Go 程序的 Go 程序。Go 具有清晰的静态依赖关系，这有助于元编程。它在元编程方面存在其他语言所没有的缺点，比如 Python 中的`__getattr__`，但如果被认为明智，我们仍然可以生成 Go 代码并编译生成的代码。

第八章《Go 中的内存管理》讨论了内存管理对系统性能至关重要。能够充分利用计算机的内存占用量使您能够将高性能程序保留在内存中，这样您就不必经常承受切换到磁盘的巨大性能损失。有效地管理内存是编写高性能 Go 代码的核心原则。

第九章《Go 中的 GPU 并行化》专注于 GPU 加速编程，在当今高性能计算堆栈中变得越来越重要。我们可以使用 CUDA 驱动程序 API 进行 GPU 加速。这在诸如深度学习算法等主题中通常被使用。

第十章《Go 中的编译时评估》讨论了在编写 Go 程序时最小化依赖关系以及每个文件声明自己的依赖关系。常规语法和模块支持也有助于提高编译时间，以及接口满足。这些都有助于加快 Go 编译速度，同时利用容器构建 Go 代码并利用 Go 构建缓存。

第十一章《构建和部署 Go 代码》着重介绍了如何部署新的 Go 代码。更进一步地，本章解释了我们如何将其推送到一个或多个地方，以便针对不同环境进行测试。这样做将使我们能够推动系统的吞吐量极限。

第十二章《Go 代码性能分析》专注于对 Go 代码进行性能分析，这是确定 Go 函数中瓶颈所在的最佳方法之一。进行这种性能分析将帮助您推断在函数内部可以进行哪些改进，以及在整个系统中个别部分在函数调用中所占用的时间。

第十三章《跟踪 Go 代码》介绍了一种检查 Go 程序中函数和服务之间互操作性的绝妙方法，也称为跟踪。跟踪允许您通过系统传递上下文并评估您所卡住的位置。无论是第三方 API 调用、缓慢的消息队列还是 O(n²)函数，跟踪都将帮助您找到瓶颈所在。

第十四章《集群和作业队列》着重介绍了集群和作业队列在 Go 中的重要性，作为使分布式系统同步工作并传递一致消息的良好方式。分布式计算很困难，因此在集群和作业队列中寻找潜在的性能优化变得非常重要。

第十五章《跨版本比较代码质量》讨论了在编写、调试、分析和监控长期监控应用程序性能的 Go 代码之后，您应该做些什么。如果您无法继续提供基础架构中其他系统所依赖的性能水平，那么向您的代码添加新功能是毫无意义的。

# 为了充分利用本书

本书适用于 Go 专业人士和开发人员，他们希望加快代码执行速度，因此需要具有中级到高级的 Go 编程理解才能充分利用本书。Go 语言的系统要求相对较低。现代计算机和现代操作系统应该支持 Go 运行时及其依赖项。Go 在许多低功耗设备上使用，这些设备具有有限的 CPU、内存和 I/O 要求。

您可以在以下网址查看语言的要求：[`github.com/golang/go/wiki/MinimumRequirements`](https://github.com/golang/go/wiki/MinimumRequirements)。

在本书中，我使用 Fedora Core Linux（在撰写本书时为第 29 版）作为操作系统。有关如何安装 Fedora Workstation Linux 发行版的说明，请访问以下网址：[`getfedora.org/en/workstation/download/`](https://getfedora.org/en/workstation/download/)。

Docker 在本书的许多示例中使用。您可以在以下网址查看 Docker 的要求：[`docs.docker.com/install/`](https://docs.docker.com/install/)。

在第九章中，《Go 中的 GPU 并行化》，我们讨论了 GPU 编程。要执行本章的任务，您需要以下两种东西之一：

+   启用 NVIDIA 的 GPU。我在测试中使用了一款 NVIDIA GeForce GTX 670，计算能力为 3.0。

+   启用 GPU 的云实例。第九章讨论了几种不同的提供商和方法。Compute Engine 上的 GPU 适用于此。有关 Compute Engine 上 GPU 的最新信息，请访问以下网址：[`cloud.google.com/compute/docs/gpus`](https://cloud.google.com/compute/docs/gpus)。

阅读本书后，希望您能够编写更高效的 Go 代码。您将有望能够量化和验证自己的努力。

# 下载示例代码文件

您可以从您在[www.packt.com](http://www.packt.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，可以访问[www.packtpub.com/support](https://www.packtpub.com/support)注册，直接将文件发送到您的邮箱。

按照以下步骤下载代码文件：

1.  登录或注册[www.packt.com](http://www.packt.com)。

1.  选择“支持”选项卡。

1.  单击“代码下载”。

1.  在搜索框中输入书名，然后按照屏幕上的说明操作。

下载文件后，请确保您使用最新版本的解压缩或提取文件夹：

+   WinRAR/7-Zip 适用于 Windows

+   Zipeg/iZip/UnRarX 适用于 Mac

+   7-Zip/PeaZip 适用于 Linux

本书的代码包也托管在 GitHub 上，网址为[`github.com/bobstrecansky/HighPerformanceWithGo/`](https://github.com/bobstrecansky/HighPerformanceWithGo/)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还提供了来自我们丰富书籍和视频目录的其他代码包，可在**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**上找到。快去看看吧！

# 实际代码

本书的实际代码视频可在[`bit.ly/2QcfEJI`](http://bit.ly/2QcfEJI)上观看。

# 下载彩色图片

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图片。您可以在此处下载：[`static.packt-cdn.com/downloads/9781789805789_ColorImages.pdf`](https://static.packt-cdn.com/downloads/9781789805789_ColorImages.pdf)。

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码字词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。例如："以下代码块将显示`Next()`咒语"

代码块设置如下：

```go
// Note the trailing () for this anonymous function invocation
func() {
  fmt.Println("Hello Go")
}()
```

当我们希望引起你对代码块的特定部分的注意时，相关的行或项目会以粗体显示：

```go
// Note the trailing () for this anonymous function invocation
func() {
  fmt.Println("Hello Go")
}()
```

任何命令行输入或输出都是这样写的：

```go
$ go test -bench=. -benchtime 2s -count 2 -benchmem -cpu 4
```

**粗体**：表示一个新术语，一个重要的词，或者你在屏幕上看到的词。例如，菜单或对话框中的单词会以这种方式出现在文本中。这是一个例子：“**reverse algorithm**接受一个数据集，并颠倒集合的值”

警告或重要提示会以这种方式出现。

技巧和窍门会以这种方式出现。


# 第一部分：学习 Go 语言中的性能

在这一部分，您将学习为什么计算机科学中的性能很重要。您还将了解为什么 Go 语言中的性能很重要。接下来，您将学习有关数据结构和算法、并发、STL 算法等价物以及在 Go 中的矩阵和向量计算。

本节的章节包括以下内容：

+   第一章，“Go 语言性能简介”

+   第二章，“数据结构和算法”

+   第三章，“理解并发”

+   第四章，“Go 中的 STL 算法等价物”

+   第五章，“在 Go 语言中的矩阵和向量计算”


# 第一章：Go 性能简介

本书是针对中级到高级 Go 开发人员编写的。这些开发人员将希望从其 Go 应用程序中挤出更多性能。为此，本书将帮助推动《Site Reliability Engineering Workbook》中定义的四个黄金信号（[`landing.google.com/sre/sre-book/chapters/monitoring-distributed-systems/`](https://landing.google.com/sre/sre-book/chapters/monitoring-distributed-systems/)）。如果我们能减少延迟和错误，同时增加流量并减少饱和，我们的程序将继续更加高效。遵循四个黄金信号的理念对于任何以性能为目标开发 Go 应用程序的人都是有益的。

在本章中，您将介绍计算机科学性能的一些核心概念。您将了解 Go 计算机编程语言的一些历史，其创建者是如何决定将性能置于语言的前沿，并且为什么编写高性能的 Go 很重要。Go 是一种以性能为重点设计的编程语言，本书将带您了解如何利用 Go 的设计和工具来提高性能。这将帮助您编写更高效的代码。

在本章中，我们将涵盖以下主题：

+   了解计算机科学中的性能

+   Go 的简要历史

+   Go 性能背后的理念

这些主题旨在指导您开始了解在 Go 语言中编写高性能代码所需的方向。

# 技术要求

对于本书，您应该对 Go 语言有一定的了解。在探索这些主题之前，了解以下一些关键概念是很重要的：

+   Go 参考规范：[`golang.org/ref/spec`](https://golang.org/ref/spec)

+   如何编写 Go 代码：[`golang.org/doc/code.html`](https://golang.org/doc/code.html)

+   Effective Go: [`golang.org/doc/effective_go.html`](https://golang.org/doc/effective_go.html)

在本书中，将提供许多代码示例和基准结果。所有这些都可以通过 GitHub 存储库访问[`github.com/bobstrecansky/HighPerformanceWithGo/`](https://github.com/bobstrecansky/HighPerformanceWithGo/)。

如果您有问题或想要请求更改存储库，请随时在存储库内创建问题[`github.com/bobstrecansky/HighPerformanceWithGo/issues/new`](https://github.com/bobstrecansky/HighPerformanceWithGo/issues/new)。

# 了解计算机科学中的性能

计算机科学中的性能是计算机系统可以完成的工作量的衡量标准。高性能的代码对许多不同的开发人员群体至关重要。无论您是大型软件公司的一部分，需要快速向客户交付大量数据，还是嵌入式计算设备程序员，可用的计算资源有限，或者是业余爱好者，希望从用于宠物项目的树莓派中挤出更多请求，性能都应该是您开发思维的前沿。性能很重要，特别是当您的规模不断增长时。

重要的是要记住，我们有时会受到物理限制。 CPU、内存、磁盘 I/O 和网络连接性都有性能上限，这取决于您从云提供商购买或租用的硬件。还有其他系统可能会与我们的 Go 程序同时运行，也会消耗资源，例如操作系统软件包、日志记录工具、监控工具和其他二进制文件——要记住，我们的程序很频繁地不是物理机器上唯一的租户。

优化的代码通常在许多方面有所帮助，包括以下内容：

+   响应时间减少：响应请求所需的总时间。

+   降低延迟：系统内因果关系之间的时间延迟。

+   增加吞吐量：数据处理速率。

+   更高的可扩展性：可以在一个封闭系统内处理更多的工作。

在计算机系统中有许多方法可以处理更多的请求。增加更多的个体计算机（通常称为横向扩展）或升级到更强大的计算机（通常称为纵向扩展）是处理计算机系统需求的常见做法。在不需要额外硬件的情况下，提高代码性能是服务更多请求的最快方法之一。性能工程既可以帮助横向扩展，也可以帮助纵向扩展。代码性能越高，单台机器就能处理更多的请求。这种模式可能导致运行工作负载的物理主机减少或更便宜。这对许多企业和爱好者来说是一个巨大的价值主张，因为它有助于降低运营成本，改善最终用户体验。

# Big O 符号简要说明

Big O 符号([`en.wikipedia.org/wiki/Big_O_notation`](https://en.wikipedia.org/wiki/Big_O_notation))通常用于描述基于输入大小的函数的极限行为。在计算机科学中，Big O 符号用于解释算法相对于彼此的效率——我们将在第二章中更详细地讨论这一点，*数据结构和算法*。Big O 符号在优化性能方面很重要，因为它被用作比较运算符，解释算法的扩展性如何。了解 Big O 符号将帮助您编写更高性能的代码，因为它将在代码编写时帮助您做出性能决策。了解不同算法在何时具有相对优势和劣势的点，将帮助您确定实现的正确选择。我们无法改进我们无法衡量的东西——Big O 符号帮助我们对手头的问题陈述给出一个具体的衡量。

# 衡量长期性能的方法

在进行性能改进时，我们需要不断监视我们的变化以查看影响。有许多方法可以用来监视计算机系统的长期性能。其中一些方法的例子如下：

+   Brendan Gregg 的 USE 方法：利用率、饱和度和错误([www.brendangregg.com/usemethod.html](http://www.brendangregg.com/usemethod.html))

+   Tom Wilkie 的 RED 指标：请求、错误和持续时间([`www.weave.works/blog/the-red-method-key-metrics-for-microservices-architecture/`](https://www.weave.works/blog/the-red-method-key-metrics-for-microservices-architecture/))

+   Google SRE 的四个黄金信号：延迟、流量、错误和饱和度([`landing.google.com/sre/sre-book/chapters/monitoring-distributed-systems/`](https://landing.google.com/sre/sre-book/chapters/monitoring-distributed-systems/))

我们将在第十五章中进一步讨论这些概念，*跨版本比较代码质量*。这些范式帮助我们做出关于代码性能优化的明智决策，避免过早优化。过早优化对许多计算机程序员来说是非常关键的一个方面。我们经常不得不确定什么是*足够快*。当许多其他代码路径有机会从性能角度进行改进时，我们可能会浪费时间尝试优化一小部分代码。Go 的简单性允许进行额外的优化，而不会增加认知负担或增加代码复杂性。我们将在第二章中讨论的算法，将帮助我们避免过早优化。

# 优化策略概述

在这本书中，我们还将尝试理解我们到底在优化什么。优化 CPU 或内存利用率的技术可能看起来与优化 I/O 或网络延迟的技术大不相同。了解问题空间以及硬件和上游 API 中的限制将帮助您确定如何针对手头的问题陈述进行优化。优化通常也会显示出递减的回报。经常情况下，基于外部因素，特定代码热点的开发投资回报不值得，或者添加优化会降低可读性并增加整个系统的风险。如果您能够早期确定优化是否值得进行，您将能够更加狭窄地聚焦，并可能继续开发更高性能的系统。

了解计算机系统中的基线操作可能是有帮助的。*Peter Norvig*，谷歌研究总监，设计了一张表（随后的图片），帮助开发人员了解典型计算机上各种常见的时间操作（[`norvig.com/21-days.html#answers`](https://norvig.com/21-days.html#answers)）。

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/0761aefe-aed8-4d74-ad2b-32047bce2da4.png)

清楚地了解计算机的不同部分如何相互协作有助于我们推断出我们的性能优化应该放在哪里。从表中得出，从磁盘顺序读取 1 MB 的数据所需的时间要比通过 1 Gbps 网络链路发送 2 KB 的数据要长得多。当您能够对常见的计算机交互进行*草稿计算*比较运算符时，可以帮助您推断出下一个应该优化的代码部分。当您退后一步并全面审视系统的快照时，确定程序中的瓶颈变得更容易。

将性能问题分解为可以同时改进的小而可管理的子问题是一种有助于优化的转变。试图一次解决所有性能问题通常会让开发人员感到受挫和沮丧，并且经常导致许多性能努力失败。专注于当前系统中的瓶颈通常会产生结果。解决一个瓶颈通常会很快地发现另一个。例如，解决了 CPU 利用率问题后，您可能会发现系统的磁盘无法快速写入计算出的值。以结构化方式解决瓶颈是创建高性能和可靠软件的最佳方法之一。

# 优化级别

从下图的金字塔底部开始，我们可以逐步向上发展。这张图表显示了进行性能优化的建议优先级。这个金字塔的前两个级别——设计级别和算法和数据结构级别——通常会提供更多的现实世界性能优化目标。以下图表显示了一种通常有效的优化策略。改变程序的设计以及算法和数据结构往往是提高代码质量和速度的最有效的地方：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/cda5e953-f4d8-49cc-97fc-2c030dfc3a3f.png)

设计层面的决策通常对性能有最明显的影响。在设计层面确定目标可以帮助确定最佳的优化方法。例如，如果我们正在为一个具有缓慢磁盘 I/O 的系统进行优化，我们应该优先降低对磁盘的调用次数。相反，如果我们正在为一个具有有限计算资源的系统进行优化，我们需要计算程序响应所需的最基本值。在新项目开始时创建详细的设计文档将有助于理解性能提升的重要性以及如何在项目中优先考虑时间。从在计算系统内传输有效载荷的角度思考往往会导致注意到优化可能发生的地方。我们将在《理解并发》的第三章中更多地讨论设计模式。

算法和数据结构的决策通常会对计算机程序产生可衡量的性能影响。在编写高性能代码时，我们应该专注于尝试利用常数 O(1)、对数 O(log n)、线性 O(n)和对数线性 O(n log n)函数。在规模上避免二次复杂度 O(n²)对于编写可扩展的程序也很重要。我们将在《数据结构和算法》的第二章中更多地讨论 O 符号及其与 Go 语言的关系。

# Go 的简要历史

Robert Griesemer、Rob Pike 和 Ken Thompson 于 2007 年创建了 Go 编程语言。最初，它被设计为一种以系统编程为重点的通用语言。语言的创造者们在设计 Go 语言时考虑了一些核心原则：

+   静态类型

+   运行效率

+   可读性

+   可用性

+   易学习

+   高性能网络和多处理

Go 于 2009 年公开宣布，v1.0.3 于 2012 年 3 月 3 日发布。在撰写本书时，Go 版本 1.14 已发布，Go 版本 2 也即将推出。正如前面提到的，Go 最初的核心架构考虑之一是具有高性能的网络和多处理。本书将涵盖 Griesemer、Pike 和 Thompson 实施和宣传的许多设计考虑。设计者们创建 Go 是因为他们对 C++语言中做出的一些选择和方向感到不满。长时间运行的大型分布式编译集群是创作者们的主要痛点。在此期间，作者们开始了解下一个 C++编程语言版本的发布，被称为 C++x11。这个 C++版本计划中有很多新功能，Go 团队决定他们想要在他们的工作中采用“少即是多”的计算语言习惯。

语言的作者们在第一次会议上讨论了从 C 编程语言开始，构建功能并删除他们认为对语言不重要的多余功能。最终，团队从零开始，只借用了一些最基本的 C 和其他编程语言的部分。在他们的工作开始形成后，他们意识到他们正在剥夺其他语言的一些核心特性，尤其是没有头文件、循环依赖和类。作者们相信，即使剥夺了许多这些片段，Go 仍然可以比其前身更具表现力。

# Go 标准库

Go 标准库遵循相同的模式。它旨在同时考虑简单性和功能性。将切片，映射和复合文字添加到标准库有助于语言早期变得有见地。Go 的标准库位于`$GOROOT`中，并且可以直接导入。将这些默认数据结构内置到语言中使开发人员能够有效地使用这些数据结构。标准库包与语言分发捆绑在一起，并在安装 Go 后立即可用。经常提到标准库是如何编写符合惯用法的 Go 的可靠参考。标准库符合惯用法的原因是这些核心库部分清晰，简洁，并且具有相当多的上下文。它们还很好地添加了一些小但重要的实现细节，例如能够为连接设置超时，并明确地能够从底层函数中收集数据。这些语言细节有助于语言的繁荣。

一些显着的 Go 运行时特性包括以下内容：

+   垃圾收集以进行安全内存管理（并发的，三色的，标记-清除收集器）

+   并发性以支持同时执行多个任务（关于这一点，可以在第三章中了解更多，*理解并发性*）

+   堆栈管理以进行内存优化（原始实现中使用了分段堆栈；当前的 Go 堆栈管理采用了堆栈复制）

# Go 工具集

Go 的二进制发布还包括用于创建优化代码的庞大工具集。在 Go 二进制文件中，`go`命令具有许多功能，可帮助构建，部署和验证代码。让我们讨论一些与性能相关的核心功能。

Godoc 是 Go 的文档工具，将文档的要点放在程序开发的前沿。清晰的实现，深入的文档和模块化都是构建可扩展，高性能系统的核心要素。Godoc 通过自动生成文档来帮助实现这些目标。Godoc 从在`$GOROOT`和`$GOPATH`中找到的包中提取和生成文档。生成文档后，Godoc 运行一个 Web 服务器，并将生成的文档显示为 Web 页面。可以在 Go 网站上查看标准库的文档。例如，标准库`pprof`包的文档可以在[`golang.org/pkg/net/http/pprof/`](https://golang.org/pkg/net/http/pprof/)找到。

将`gofmt`（Go 的代码格式化工具）添加到语言中为 Go 带来了不同类型的性能。`gofmt`的诞生使得 Go 在代码格式化方面非常有见地。强制执行精确的格式化规则使得可以以对开发人员有意义的方式编写 Go，同时让工具按照一致的模式格式化代码，从而使得在 Go 项目中保持一致的模式成为可能。许多开发人员在保存他们正在编写的文件时，让他们的 IDE 或文本编辑器执行`gofmt`命令。一致的代码格式化减少了认知负荷，并允许开发人员专注于代码的其他方面，而不是确定是否使用制表符或空格来缩进他们的代码。减少认知负荷有助于开发人员的动力和项目速度。

Go 的构建系统也有助于性能。`go build`命令是一个强大的工具，用于编译包及其依赖项。Go 的构建系统还有助于依赖管理。构建系统的输出结果是一个编译的、静态链接的二进制文件，其中包含了在您为其编译的平台上运行所需的所有必要元素。`go module`（Go 1.11 中引入的初步支持功能，Go 1.13 中最终确定）是 Go 的依赖管理系统。语言的显式依赖管理有助于以版本化包的组合作为一个统一单元提供一致的体验，从而实现更可重现的构建。可重现的构建有助于开发人员通过源代码的可验证路径创建二进制文件。在项目中创建一个 vendored 目录的可选步骤也有助于本地存储和满足项目的依赖关系。

编译后的二进制文件也是 Go 生态系统中的重要组成部分。Go 还允许您为其他目标环境构建二进制文件，这在需要为另一台计算机架构交叉编译二进制文件时非常有用。能够构建可以在任何平台上运行的二进制文件，有助于您快速迭代和测试代码，以便在它们变得更难以修复之前，在其他架构上找到瓶颈。语言的另一个关键特性是，您可以在一个带有 OS 和架构标志的机器上编译二进制文件，然后在另一个系统上执行该二进制文件。当构建系统具有大量系统资源而构建目标具有有限的计算资源时，这一点至关重要。为两种架构构建二进制文件就像设置构建标志一样简单：

在 x86_64 架构的 macOS X 上构建二进制文件时，使用以下执行模式：

```go
GOOS=darwin GOARCH=amd64 go build -o myapp.osx
```

在 ARM 架构的 Linux 上构建二进制文件时，使用以下执行模式：

```go
GOOS=linux GOARCH=arm go build -o myapp.linuxarm
```

您可以使用以下命令找到所有有效的`GOOS`和`GOARCH`组合的列表：

```go
go tool dist list -json
```

这有助于您查看 Go 语言可以为其编译二进制文件的所有 CPU 架构和操作系统。

# 基准测试概述

基准测试的概念也将是本书的核心要点。Go 的测试功能内置了性能。在开发和发布过程中触发测试基准是可能的，这使得继续交付高性能代码成为可能。随着引入新的副作用、添加功能和代码复杂性的增加，验证代码库中性能回归的方法变得很重要。许多开发人员将基准测试结果添加到其持续集成实践中，以确保其代码在向存储库添加的所有新拉取请求中继续保持高性能。您还可以使用[golang.org/x/perf/cmd/benchstat](http://golang.org/x/perf/cmd/benchstat)包中提供的`benchstat`实用程序来比较基准测试的统计信息。以下示例存储库演示了对标准库的排序函数进行基准测试的示例，网址为[`github.com/bobstrecansky/HighPerformanceWithGo/tree/master/1-introduction`](https://github.com/bobstrecansky/HighPerformanceWithGo/tree/master/1-introduction)。

在标准库中密切结合测试和基准测试鼓励将性能测试作为代码发布过程的一部分。重要的是要记住，基准测试并不总是表明真实世界的性能场景，因此要对从中获得的结果持保留态度。记录、监控、分析和跟踪运行中的系统（将在第十二章《Go 代码性能分析》、第十三章《Go 代码跟踪》和第十五章《跨版本比较代码质量》中讨论）可以帮助验证您在进行基准测试后对代码所做的假设。

# Go 性能背后的思想

Go 的许多性能立场都来自并发和并行。Goroutines 和 channels 经常用于并行执行许多请求。Go 提供的工具有助于实现接近 C 语言的性能，同时语义清晰易读。这是 Go 常被开发人员在大规模解决方案中使用的许多原因之一。

# Goroutines - 从一开始就有性能

Go 语言的诞生是在多核处理器开始在商用硬件中变得越来越普遍的时候。Go 语言的作者意识到他们的新语言需要并发性。Go 通过 goroutines 和 channels（我们将在第三章《理解并发性》中讨论）使并发编程变得简单。Goroutines 是轻量级的计算线程，与操作系统线程不同，通常被描述为该语言的最佳特性之一。Goroutines 并行执行它们的代码，并在工作完成时完成。与依赖于操作系统线程的 Java 等语言相比，Goroutines 的启动时间比线程的启动时间更快，这允许程序中发生更多的并发工作。Go 还对于与 goroutines 相关的阻塞操作非常智能。这有助于 Go 在内存利用、垃圾回收和延迟方面更加高效。Go 的运行时使用`GOMAXPROCS`变量将 goroutines 复用到真实的操作系统线程上。我们将在第二章《数据结构和算法》中学习更多关于 goroutines 的知识。

# Channels - 一种类型的导管

Channels 提供了在 goroutines 之间发送和接收数据的模型，同时跳过底层平台提供的同步原语。通过深思熟虑的 goroutines 和 channels，我们可以实现高性能。Channels 可以是有缓冲的，也可以是无缓冲的，因此开发人员可以通过开放的通道传递动态数量的数据，直到接收者接收到值时，发送者解除通道的阻塞。如果通道是有缓冲的，发送者将会阻塞直到缓冲区填满。一旦缓冲区填满，发送者将解除通道的阻塞。最后，`close()`函数可以被调用来指示通道将不再接收任何值。我们将在第三章《理解并发性》中学习更多关于 channels 的知识。

# C-可比性能

另一个最初的目标是接近 C 语言对于类似程序的性能。Go 语言还内置了广泛的性能分析和跟踪工具，我们将在第十二章“Go 代码性能分析”和第十三章“Go 代码跟踪”中了解到。Go 语言让开发人员能够查看 goroutine 使用情况、通道、内存和 CPU 利用率，以及与个别调用相关的函数调用的细分。这是非常有价值的，因为 Go 语言使得通过数据和可视化轻松解决性能问题。

# 大规模分布式系统

由于其操作简单性和标准库中内置的网络原语，Go 经常用于大规模分布式系统。在开发过程中能够快速迭代是构建强大、可扩展系统的重要部分。在分布式系统中，高网络延迟经常是一个问题，Go 团队一直致力于解决这个平台上的问题。从标准库网络实现到使 gRPC 成为在分布式平台上在客户端和服务器之间传递缓冲消息的一等公民，Go 语言开发人员已经将分布式系统问题置于他们语言问题空间的前沿，并为这些复杂问题提出了一些优雅的解决方案。

# 摘要

在本章中，我们学习了计算机科学中性能的核心概念。我们还了解了 Go 编程语言的一些历史，以及它的起源与性能工作直接相关。最后，我们了解到由于语言的实用性、灵活性和可扩展性，Go 语言在许多不同的情况下被使用。本章介绍了将在本书中不断建立的概念，让您重新思考编写 Go 代码的方式。

在第二章“数据结构和算法”中，我们将深入研究数据结构和算法。我们将学习不同的算法、它们的大 O 表示法，以及这些算法在 Go 语言中的构建方式。我们还将了解这些理论算法如何与现实世界的问题相关，并编写高性能的 Go 代码，以快速高效地处理大量请求。了解更多关于这些算法的知识将帮助您在本章早期提出的优化三角形的第二层中变得更加高效。


# 第二章：数据结构和算法

数据结构和算法是构建软件的基本单元，尤其是复杂的性能软件。了解它们有助于我们思考如何有影响地组织和操作数据，以编写有效的、高性能的软件。本章将包括不同数据结构和算法的解释，以及它们的大 O 符号受到的影响。

正如我们在第一章中提到的，“Go 性能简介”，设计层面的决策往往对性能有着最明显的影响。最廉价的计算是您不必进行的计算——如果您在软件架构时早期努力优化设计，就可以避免很多性能惩罚。

在本章中，我们将讨论以下主题：

+   利用大 O 符号进行基准测试

+   搜索和排序算法

+   树

+   队列

创建不包含多余信息的简单数据结构将帮助您编写实用的、高性能的代码。算法也将有助于改善您拥有的数据结构的性能。

# 理解基准测试

度量和测量是优化的根本。谚语“不能衡量的东西无法改进”在性能方面是正确的。为了能够对性能优化做出明智的决策，我们必须不断地测量我们试图优化的函数的性能。

正如我们在第一章中提到的，“Go 性能简介”，Go 的创建者在语言设计中将性能作为首要考虑。Go 测试包（[`golang.org/pkg/testing/`](https://golang.org/pkg/testing/)）用于系统化地测试 Go 代码。测试包是 Go 语言的基本组成部分。该包还包括一个有用的内置基准测试功能。通过`go test -bench`调用的这个功能运行您为函数定义的基准测试。测试结果也可以保存并在以后查看。拥有函数的基准测试以前的结果可以让您跟踪您在函数和它们结果中所做的长期变化。基准测试与性能分析和跟踪相结合，可以获取系统状态的准确报告。我们将在第十二章“Go 代码性能分析”和第十三章“Go 代码跟踪”中学习更多关于性能分析和跟踪的知识。在进行基准测试时，重要的是要注意禁用 CPU 频率调整（参见[`blog.golang.org/profiling-go-programs`](https://blog.golang.org/profiling-go-programs)）。这将确保在基准测试运行中更加一致。可以在[`github.com/bobstrecansky/HighPerformanceWithGo/blob/master/frequency_scaling_governor_diable.bash`](https://github.com/bobstrecansky/HighPerformanceWithGo/blob/master/frequency_scaling_governor_diable.bash)找到一个包含的禁用频率调整的 bash 脚本。

# 基准测试执行

在 Go 中，基准测试使用在函数调用中以大写 B 开头的单词`Benchmark`来表示它们是基准测试，并且应该使用基准测试功能。要执行您在测试包中为代码定义的基准测试，可以在`go test`执行中使用`-bench=.`标志。这个测试标志确保运行所有您定义的基准测试。以下是一个基准测试的示例代码块：

```go
package hello_test 
import ( 
    "fmt" 
    "testing" 
) 
func BenchmarkHello(b *testing.B) { // Benchmark definition 
    for i := 0; i < b.N; i++ { 
        fmt.Sprintf("Hello High Performance Go")
    } 
}
```

在这个（诚然简单的）基准测试中，我们对我们的 `fmt.Sprintf` 语句进行了 b.N 次迭代。基准测试包执行并运行我们的 `Sprintf` 语句。在我们的测试运行中，基准测试会调整 `b.N`，直到可以可靠地计时该函数。默认情况下，go 基准测试会运行 1 秒，以获得具有统计学意义的结果集。

在调用基准测试实用程序时有许多可用的标志。以下表格列出了一些有用的基准测试标志：

| **标志** | **用例** |
| --- | --- |
| `-benchtime t` | 运行足够的测试迭代以达到定义的 t 时长。增加此值将运行更多的 `b.N` 迭代。 |
| `-count n` | 每个测试运行 n 次。 |
| `-benchmem` | 为你的测试打开内存分析。 |
| `-cpu x,y,z` | 指定应执行基准测试的 `GOMAXPROCS` 值列表。 |

以下是基准测试执行的示例。在我们的示例执行中，我们两次对现有的 Hello 基准测试进行了分析。我们还使用了四个 `GOMAXPROCS`，查看了我们测试的内存分析，并将这些请求执行了 2 秒，而不是默认的 1 秒测试调用。我们可以像这样调用我们的 `go test -bench` 功能：

```go
$ go test -bench=. -benchtime 2s -count 2 -benchmem -cpu 4
```

基准测试将一直运行，直到函数返回、失败或跳过。一旦测试完成，基准测试的结果将作为标准错误返回。在测试完成并整理结果后，我们可以对基准测试的结果进行智能比较。我们的下一个结果显示了一个示例测试执行以及前面的 `BenchmarkHello` 函数的结果输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/96668579-0851-402f-af1e-051278ef6c8d.png)

在我们的输出结果中，我们可以看到返回了一些不同的数据：

+   `GOOS` 和 `GOARCH`（在第一章的*Go 工具集*部分讨论过）

+   运行的基准测试的名称，然后是以下内容：

+   -8：用于执行测试的 `GOMAXPROCS` 的数量。

+   10000000：我们的循环运行了这么多次以收集必要的数据。

+   112 ns/op：我们测试中每次循环的速度。

+   PASS：表示我们的基准测试运行的结束状态。

+   测试的最后一行，编译测试运行的结束状态（ok），我们运行测试的路径以及测试运行的总时间。

# 真实世界的基准测试

在本书中运行基准测试时，请记住基准测试并非性能结果的全部和终极标准。基准测试既有积极的一面，也有缺点：

基准测试的积极面如下：

+   在问题变得难以控制之前就能发现潜在问题

+   帮助开发人员更深入地了解他们的代码

+   可以识别设计和数据结构以及算法阶段的潜在瓶颈

基准测试的缺点如下：

+   需要按照给定的节奏进行，才能产生有意义的结果

+   数据整理可能会很困难

+   并非总是能为手头的问题产生有意义的结果

基准测试适用于比较。在同一系统上将两个事物进行基准测试可以得到相对一致的结果。如果你有能力运行更长时间的基准测试，可能会更准确地反映函数的性能。

Go `benchstat` ([`godoc.org/golang.org/x/perf/cmd/benchstat`](https://godoc.org/golang.org/x/perf/cmd/benchstat)) 包是一个有用的实用程序，它帮助你比较两个基准测试。比较非常重要，以便推断你对函数所做的更改对系统是否产生了积极或消极的影响。你可以使用 `go get` 实用程序安装 `benchstat`：

```go
go get golang.org/x/perf/cmd/benchstat
```

考虑以下比较测试。我们将测试单个 JSON 结构的编组，其中包含三个元素，与两个包含五个元素的 JSON 数组的编组进行比较。您可以在[`github.com/bobstrecansky/HighPerformanceWithGo/tree/master/2-data-structures-and-algorithms/Benchstat-comparison`](https://github.com/bobstrecansky/HighPerformanceWithGo/tree/master/2-data-structures-and-algorithms/Benchstat-comparison)找到这些的源代码。

为了得到一个示例比较运算符，我们执行我们的基准测试，如下面的代码片段所示：

```go
[bob@testhost single]$ go test -bench=. -count 5 -cpu 1,2,4 > ~/single.txt
[bob@testhost multi]$ go test -bench=. -count 5 -cpu 1,2,4 > ~/multi.txt
[bob@testhost ~]$ benchstat -html -sort -delta single.txt multi.txt > out.html
```

这将生成一个 HTML 表格，用于验证执行时间的最大增量。如下图所示，即使对我们的数据结构和我们处理的元素数量增加了一点复杂性，也会对函数的执行时间产生相当大的变化：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/7c08f7d1-7c30-4e40-b081-c9c6165f057d.png)

快速识别终端用户的性能痛点可以帮助您确定编写高性能软件的路径。

在下一节中，我们将看到大 O 符号是什么。

# 介绍大 O 符号

大 O 符号是一种近似算法速度的好方法，它会随着传递给算法的数据大小而改变。大 O 符号通常被描述为函数的增长行为，特别是它的上限。大 O 符号被分解为不同的类。最常见的类别是 O(1)、O(log n)、O(n)、O(n log n)、O(n²)和 O(2^n)。让我们快速看一下每个算法的定义和在 Go 中的实际示例。

这些常见类别的图表如下。生成此图的源代码可以在[`github.com/bobstrecansky/HighPerformanceWithGo/blob/master/2-data-structures-and-algorithms/plot/plot.go`](https://github.com/bobstrecansky/HighPerformanceWithGo/blob/master/2-data-structures-and-algorithms/plot/plot.go)找到：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/034638be-b29a-488f-8aa3-c3493058aa2a.png)

这个大 O 符号图表给我们一个常用的计算机软件中不同算法的可视化表示。

# 实际的大 O 符号示例

如果我们拿一个包含 32 个输入值的样本数据集，我们可以快速计算每个算法完成所需的时间。您会注意到下表中的完成单位时间开始迅速增长。实际的大 O 符号值如下：

| **算法** | **完成的单位时间** |
| --- | --- |
| O(1) | 1 |
| O(log n) | 5 |
| O(n) | 32 |
| O(n log n) | 160 |
| O(n²) | 1,024 |
| O(2^n) | 4,294,967,296 |

随着完成单位时间的增加，我们的代码变得不那么高效。我们应该努力使用尽可能简单的算法来解决手头的数据集。

# 数据结构操作和时间复杂度

以下图表包含一些常见的数据结构操作及其时间复杂度。正如我们之前提到的，数据结构是计算机科学性能的核心部分。在编写高性能代码时，了解不同数据结构之间的差异是很重要的。有这个表格可以帮助开发人员在考虑操作对性能的影响时选择正确的数据结构操作：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/7fcfc5a9-a9fb-4bf2-8891-b508ce6d290c.png)

常见的数据结构操作（来自 bigocheatsheet.com）- 感谢 Eric Rowell

这个表格向我们展示了特定数据结构的时间和空间复杂度。这是一个有价值的性能参考工具。

# O(1) - 常数时间

在常数时间内编写的算法具有不依赖于算法输入大小的上限。常数时间是一个常数值的上限，因此不会比数据集的上限时间长。这种类型的算法通常可以添加到实践中的函数中——它不会给函数增加太多的处理时间。请注意这里发生的常数。单个数组查找对函数的处理时间增加了可忽略的时间量。在数组中查找成千上万个单独的值可能会增加一些开销。性能始终是相对的，重要的是要注意您为函数增加的额外负载，即使它们只执行微不足道的处理。

常数时间的例子如下：

+   访问地图或数组中的单个元素

+   确定一个数字的模

+   堆栈推送或堆栈弹出

+   推断一个整数是偶数还是奇数

在 Go 中，一个常数时间算法的例子是访问数组中的单个元素。

在 Go 中，这将被写成如下形式：

```go
package main
import "fmt"
func main() {
   words := [3]string{"foo", "bar", "baz"}
   fmt.Println(words[1]) // This references the string in position 1 in the array, "bar"
}
```

这个函数的大 O 符号是 O(1)，因为我们只需要查看`words[1]`的单个定义值，就可以找到我们要找的值，也就是`bar`。在这个例子中，随着数组大小的增长，引用数组中的对象的时间将保持恒定。该算法的标准化时间应该都是相同的，如下表所示：

| **数据集中的项目数** | **结果计算时间** |
| --- | --- |
| 10 | 1 秒 |
| 100 | 1 秒 |
| 1,000 | 1 秒 |

O(1)符号的一些示例代码如下：

```go
package oone

func ThreeWords() string {
  threewords := [3]string{"foo", "bar", "baz"}
  return threewords[1]
}

func TenWords() string {
  tenwords := [10]string{"foo", "bar", "baz", "qux", "grault", "waldo", "plugh", "xyzzy", "thud", "spam"}
  return tenwords[6]
}
```

无论数组中有多少项，查找一个元素的时间都是相同的。在下面的示例输出中，我们分别有三个元素和十个元素的数组。它们都花费了相同的时间来执行，并在规定的时间范围内完成了相同数量的测试迭代。这可以在下面的截图中看到：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/11a995b2-cec2-497c-971e-264288fee4ae.png)

这个基准测试的表现与我们的预期一样。`BenchmarkThree`和`BenchmarkTen`基准测试都花费了 0.26 ns/op，这应该在数组查找中保持一致。

# O(log n) - 对数时间

对数增长通常表示为调和级数的部分和。可以表示如下：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/5a4ae3d3-8114-4368-9af5-cf2254c4bfd8.png)

在对数时间内编写的算法具有随着输入大小减少而趋于零的操作数量。当必须访问数组中的所有元素时，不能在算法中使用 O(log n)算法。当 O(log n)单独使用时，通常被认为是一种高效的算法。关于对数时间性能的一个重要概念是，搜索算法通常与排序算法一起使用，这增加了找到解决方案的复杂性。根据数据集的大小和复杂性，通常在执行搜索算法之前对数据进行排序是有意义的。请注意此测试的输入和输出范围——额外的测试被添加以显示数据集的结果计算时间的对数增长。

一些对数时间算法的例子如下：

+   二分查找

+   字典搜索

下表显示了对数时间的标准化时间：

| **数据集中的项目数** | **结果计算时间** |
| --- | --- |
| 10 | 1 秒 |
| 100 | 2 秒 |
| 1,000 | 3 秒 |

Go 的标准库有一个名为`sort.Search()`的函数。以下代码片段中已包含了它以供参考：

```go
func Search(n int, f func(int) bool) int {
  // Define f(-1) == false and f(n) == true.
  // Invariant: f(i-1) == false, f(j) == true.
  i, j := 0, n
  for i < j {
    h := int(uint(i+j) >> 1) // avoid overflow when computing h
    // i ≤ h < j
    if !f(h) {
      i = h + 1 // preserves f(i-1) == false
    } else {
      j = h // preserves f(j) == true
    }
  }
  // i == j, f(i-1) == false, and f(j) (= f(i)) == true => answer is i.
  return i
}
```

这个代码示例可以在标准库中找到[`golang.org/src/sort/search.go`](https://golang.org/src/sort/search.go)。O(log n)函数的代码和基准可以在[`github.com/bobstrecansky/HighPerformanceWithGo/tree/master/2-data-structures-and-algorithms/BigO-notation-o-logn`](https://github.com/bobstrecansky/HighPerformanceWithGo/tree/master/2-data-structures-and-algorithms/BigO-notation-o-logn)找到。

以下截图显示了对数时间基准：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/cf9bd878-23e5-42f0-b56c-efa3ba48457e.png)

这个测试显示了基于我们设置的输入的对数增长的时间。具有对数时间响应的算法在编写高性能代码方面非常有帮助。

# O(n) – 线性时间

以线性时间编写的算法与其数据集的大小成线性比例。线性时间是当整个数据集需要按顺序读取时的最佳时间复杂度。算法在线性时间内花费的时间量与数据集中包含的项目数量呈 1:1 的关系。

一些线性时间的例子如下：

+   简单循环

+   线性搜索

线性时间的标准化时间可以在以下表中找到：

| **数据集中的项目数量** | **结果计算时间** |
| --- | --- |
| 10 | 10 秒 |
| 100 | 100 秒 |
| 1,000 | 1,000 秒 |

请注意，结果计算时间呈线性增长，并与我们的数据集中找到的项目数量相关（参见以下截图）。O(n)函数的代码和基准可以在[`github.com/bobstrecansky/HighPerformanceWithGo/tree/master/2-data-structures-and-algorithms/BigO-notation-o-n`](https://github.com/bobstrecansky/HighPerformanceWithGo/tree/master/2-data-structures-and-algorithms/BigO-notation-o-n)找到：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/0353b6e7-8ef9-4446-b4f5-100d01bdd6d5.png)

一个重要的要点是，大 O 符号并不一定是响应时间增长的完美指标；它只表示一个上限。在审查这个基准时，要注意计算时间随数据集中项目数量的线性增长。O(n)算法通常不是计算机科学中性能的主要瓶颈。计算机科学家经常在迭代器上执行循环，这是一个常用的模式，用于完成计算工作。确保你始终注意你的数据集的大小！

# O(n log n) – 准线性时间

在 Go 中，通常使用准线性（或对数线性）时间编写的算法来对数组中的值进行排序。

一些准线性时间的例子如下：

+   Quicksort 的平均情况时间复杂度

+   Mergesort 的平均情况时间复杂度

+   Heapsort 的平均情况时间复杂度

+   Timsort 的平均情况时间复杂度

准线性时间的标准化时间可以在以下表中找到：

| **数据集中的项目数量** | **结果计算时间** |
| --- | --- |
| 10 | 10 秒 |
| 100 | 200 秒 |
| 1,000 | 3,000 秒 |

你会在这里看到一个熟悉的模式。这个算法遵循了与 O(log n)算法类似的模式。这里唯一改变的是 n 的乘数，所以我们可以看到类似的结果与一个缩放因子（参见以下截图）。O(n log n)函数的代码和基准可以在[`github.com/bobstrecansky/HighPerformanceWithGo/tree/master/2-data-structures-and-algorithms/BigO-notation-o-nlogn`](https://github.com/bobstrecansky/HighPerformanceWithGo/tree/master/2-data-structures-and-algorithms/BigO-notation-o-nlogn)找到：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/dba95ab6-8b0c-41c9-8531-dc894233bcb7.png)

排序算法仍然相当快，并不是性能不佳代码的关键。通常，语言中使用的排序算法使用基于大小的多种排序算法的混合。Go 的`quickSort`算法，在`sort.Sort()`中使用，如果切片包含少于 12 个元素，则使用`ShellSort`和`insertionSort`。`quickSort`的标准库算法如下：

```go
func quickSort(data Interface, a, b, maxDepth int) {
  for b-a > 12 { // Use ShellSort for slices <= 12 elements
    if maxDepth == 0 {
      heapSort(data, a, b)
      return
    }
    maxDepth--
    mlo, mhi := doPivot(data, a, b)
    // Avoiding recursion on the larger subproblem guarantees
    // a stack depth of at most lg(b-a).
    if mlo-a < b-mhi {
      quickSort(data, a, mlo, maxDepth)
      a = mhi // i.e., quickSort(data, mhi, b)
    } else {
      quickSort(data, mhi, b, maxDepth)
      b = mlo // i.e., quickSort(data, a, mlo)
    }
  }
  if b-a > 1 {
    // Do ShellSort pass with gap 6
    // It could be written in this simplified form cause b-a <= 12
    for i := a + 6; i < b; i++ {
      if data.Less(i, i-6) {
        data.Swap(i, i-6)
      }
    }
    insertionSort(data, a, b)
  }
}
```

前面的代码可以在标准库中找到[`golang.org/src/sort/sort.go#L183`](https://golang.org/src/sort/sort.go#L183)。这个`quickSort`算法性能良好，并且在 Go 生态系统中经常使用。

# O(n2) – 二次时间

用二次时间编写的算法的执行时间与输入大小的平方成正比。嵌套循环是常见的二次时间算法，这带来了排序算法。

二次时间的一些例子如下：

+   冒泡排序

+   插入排序

+   选择排序

二次时间的标准化时间可以在下表中找到：

| **数据集中的项目数量** | **计算时间** |
| --- | --- |
| 10 | 100 秒 |
| 100 | 10,000 秒 |
| 1,000 | 1,000,000 秒 |

您会注意到从这个表中，随着输入增加了 10 倍，计算时间呈二次增长。

如果可能的话，应该避免二次时间算法。如果需要嵌套循环或二次计算，请确保验证您的输入并尝试限制输入大小。

可以在[`github.com/bobstrecansky/HighPerformanceWithGo/tree/master/2-data-structures-and-algorithms/BigO-notation-o-n2`](https://github.com/bobstrecansky/HighPerformanceWithGo/tree/master/2-data-structures-and-algorithms/BigO-notation-o-n2)找到 O(n²)函数的代码和基准测试。以下是运行此基准测试的输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/f412695c-2fa3-46c7-9204-eaf40c91c468.png)

二次时间算法的计时非常迅速增加。我们可以通过自己的基准测试看到这一点。

# O(2n) – 指数时间

当数据添加到输入集时，指数算法呈指数增长。通常在没有输入数据集的倾向时使用，必须尝试输入集的每种可能的组合。

指数时间的一些例子如下：

+   斐波那契数列的递归实现不佳

+   汉诺塔

+   旅行推销员问题

指数时间的标准化时间可以在下表中找到：

| **数据集中的项目数量** | **计算时间** |
| --- | --- |
| 10 | 1,024 秒 |
| 100 | 1.267 * 10³⁰秒 |
| 1,000 | 1.07 * 10³⁰¹秒 |

随着数据集中项目数量的增加，计算时间呈指数增长。

指数时间算法应该只在非常狭窄的数据集范围内的紧急情况下使用。通常，澄清您的潜在问题或数据集进一步可以帮助您避免使用指数时间算法。

可以在[`github.com/bobstrecansky/HighPerformanceWithGo/tree/master/2-data-structures-and-algorithms/BigO-notation-o-n2`](https://github.com/bobstrecansky/HighPerformanceWithGo/tree/master/2-data-structures-and-algorithms/BigO-notation-o-n2)找到 O(n²)算法的代码。可以在以下截图中看到此基准测试的一些示例输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/5fc4a22c-73c8-485f-91af-d06ed8509d48.png)

指数时间算法问题通常可以分解为更小、更易消化的部分。这也可以进行优化。

在下一节中，我们将看看排序算法。

# 了解排序算法

排序算法用于获取数据集中的各个元素并按特定顺序排列它们。通常，排序算法会获取数据集并将其按字典顺序或数字顺序排列。能够高效地进行排序对于编写高性能代码很重要，因为许多搜索算法需要排序的数据集。常见的数据结构操作可以在以下图表中看到：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/e82896f2-626c-45f7-9ce7-54b0be484b54.png)

常见数据结构操作（来自 bigocheatsheet.com）- 感谢 Eric Rowell

正如你所看到的，数组排序算法的大 O 符号表示可以有很大的不同。在为无序列表选择正确的排序算法时，这对于提供优化的解决方案非常重要。

# 插入排序

插入排序是一种排序算法，它一次构建一个数组项，直到结果为排序数组。它并不是非常高效，但它有一个简单的实现，并且对于非常小的数据集来说很快。数组是原地排序的，这也有助于减少函数调用的内存占用。

这个标准库中的`insertionSort`算法可以在下面的代码片段中找到。我们可以使用下面的代码片段来推断插入排序是一个 O(n²)算法的平均情况。这是因为我们要遍历一个二维数组并操作数据：

```go
func insertionSort(data Interface, a, b int) {
  for i := a + 1; i < b; i++ {
    for j := i; j > a && data.Less(j, j-1); j-- {
      data.Swap(j, j-1)
    }
  }
}
```

这段代码可以在标准库中找到[`golang.org/src/sort/sort.go#L183`](https://golang.org/src/sort/sort.go#L24)。简单的插入排序通常对小数据集很有价值，因为它非常容易阅读和理解。当编写高性能代码时，简单性往往比其他一切都更重要。

# 堆排序

Go 语言在标准库中内置了`heapSort`，如下面的代码片段所示。这段代码片段帮助我们理解`heapSort`是一个 O(n log n)的排序算法。这比我们之前的插入排序示例要好，因此对于更大的数据集，使用我们的堆排序算法时，我们将拥有更高性能的代码：

```go
func heapSort(data Interface, a, b int) {
  first := a
  lo := 0
  hi := b - a
  // Build heap with greatest element at top.
  for i := (hi - 1) / 2; i >= 0; i-- {
    siftDown(data, i, hi, first)
  }
  // Pop elements, largest first, into end of data.
  for i := hi - 1; i >= 0; i-- {
    data.Swap(first, first+i)
    siftDown(data, lo, i, first)
  }
}
```

这段代码可以在标准库中找到[`golang.org/src/sort/sort.go#L53`](https://golang.org/src/sort/sort.go#L53)。当我们的数据集变得更大时，开始使用高效的排序算法如`heapSort`是很重要的。

# 归并排序

归并排序是一种平均时间复杂度为 O(n log n)的排序算法。如果算法的目标是产生稳定的排序，通常会使用`MergeSort`。稳定的排序确保输入数组中具有相同键的两个对象在结果数组中以相同的顺序出现。如果我们想要确保键-值对在数组中有序，稳定性就很重要。Go 标准库中可以找到稳定排序的实现。下面的代码片段中可以看到：

```go
func stable(data Interface, n int) {
  blockSize := 20 // must be > 0
  a, b := 0, blockSize
  for b <= n {
    insertionSort(data, a, b)
    a = b
    b += blockSize
  }

  insertionSort(data, a, n)
  for blockSize < n {
    a, b = 0, 2*blockSize
    for b <= n {
      symMerge(data, a, a+blockSize, b)
      a = b
      b += 2 * blockSize
    }

    if m := a + blockSize; m < n {
      symMerge(data, a, m, n)
    }
    blockSize *= 2
  }
}
```

这段代码可以在标准库中找到[`golang.org/src/sort/sort.go#L356`](https://golang.org/src/sort/sort.go#L356)。当需要保持顺序时，稳定的排序算法非常重要。

# 快速排序

Go 标准库中有一个快速排序算法，正如我们在*O(n log n) – quasilinear time*部分中看到的。快速排序最初在 Unix 中作为标准库中的默认排序例程实现。从那时起，它被构建并用作 C 编程语言中的 qsort。由于它的熟悉度和悠久的历史，它通常被用作今天许多计算机科学问题中的排序算法。使用我们的算法表，我们可以推断`quickSort`算法的标准实现具有 O(n log n)的平均时间复杂度。它还具有使用最坏情况下 O(log n)的空间复杂度的额外好处，使其非常适合原地移动。

现在我们已经完成了排序算法，我们将转向搜索算法。

# 理解搜索算法

搜索算法通常用于从数据集中检索元素或检查该元素是否存在。搜索算法通常分为两个独立的类别：线性搜索和区间搜索。

# 线性搜索

在线性搜索算法中，当顺序遍历切片或数组时，会检查切片或数组中的每个元素。这个算法并不是最高效的算法，因为它的复杂度为 O(n)，因为它可以遍历列表中的每个元素。

线性搜索算法可以简单地写成对切片的迭代，如下面的代码片段所示：

```go
func LinearSearch(data []int, searchVal int) bool { 
for _, key := range data {
       if key == searchVal {
           return true
       }
   }
   return false
}
```

这个函数告诉我们，随着数据集的增大，它会很快变得昂贵。对于包含 10 个元素的数据集，这个算法不会花费太长时间，因为它最多只会迭代 10 个值。如果我们的数据集包含 100 万个元素，这个函数将需要更长的时间才能返回一个值。

# 二分搜索

一个更常用的模式（也是您最有可能想要用于高性能搜索算法的模式）称为二分搜索。二分搜索算法的实现可以在 Go 标准库中找到[`golang.org/src/sort/search.go`](https://golang.org/src/sort/search.go)，并且在本章前面的排序搜索函数中显示过。与我们之前编写的线性搜索函数的 O(n)复杂度相比，二分搜索树具有 O(log n)的搜索复杂度。二分搜索往往经常被使用，特别是当需要搜索的数据集达到任何合理大小时。二分搜索也很聪明地早早实现 - 如果您的数据集增长而您不知情，至少所使用的算法不会增加复杂性。在下面的代码中，我们使用了`SearchInts`便利包装器来进行 Go 搜索函数。这允许我们使用二分搜索迭代整数数组：

```go
package main

import (
    "fmt"
    "sort"
)

func main() {
    intArray := []int{0, 2, 3, 5, 11, 16, 34}
    searchNumber := 34
    sorted := sort.SearchInts(intArray, searchNumber)
    if sorted < len(intArray) {
        fmt.Printf("Found element %d at array position %d\n", searchNumber, sorted)
    } else {
        fmt.Printf("Element %d not found in array %v\n", searchNumber, intArray)
    }
}
```

这个函数的输出如下：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/66928f1b-7aa7-44b9-a8a6-79fd381a9650.png)

这告诉我们，二分搜索库能够在我们搜索的数组（`intArray`）中找到我们正在搜索的数字（`34`）。它在数组中的第 6 个位置找到了整数 34（这是正确的；数组是从 0 开始索引的）。

接下来的部分涉及另一个数据结构：树。

# 探索树

树是一种非线性数据结构，用于存储信息。它通常用于存储维护关系的数据，特别是如果这些关系形成层次结构。树也很容易搜索（*理解排序算法*部分的数组排序算法图表向我们展示了许多树的操作具有 O(log n)的时间复杂度）。对于许多问题，树是最佳解决方案，因为它们引用分层数据。树是由不形成循环的节点组合而成。

每棵树都由称为节点的元素组成。我们从根节点开始（下面的二叉树图中标有根的黄色框）。在每个节点中有一个左引用指针和一个右引用指针（在我们的例子中是数字 2 和 7），以及一个数据元素（在本例中是数字 1）。随着树的增长，节点的深度（从根到给定节点的边的数量）增加。在这个图中，节点 4、5、6 和 7 的深度都是 3。节点的高度是从节点到树中最深的叶子的边的数量（如下面二叉树图中的高度 4 框所示）。整个树的高度等于根节点的高度。

# 二叉树

二叉树是计算机科学中重要的数据结构。它们经常用于搜索、优先队列和数据库。它们是高效的，因为它们易于以并发方式遍历。Go 语言具有出色的并发原语（我们将在第三章中讨论，*理解并发*），可以让我们以简单的方式做到这一点。能够使用 goroutines 和通道来遍历二叉树可以帮助加快我们遍历分层数据的速度。平衡的二叉树可以在下图中看到：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/b4cfd02e-78ce-43a6-a49c-7b5b7a863f90.png)

以下是一些特殊的二叉树：

+   **满二叉树**：除了叶子节点外，每个节点都有 2 个子节点。

+   **完全二叉树**：一棵完全填充的树，除了底层之外。底层必须从左到右填充。

+   **完美二叉树**：一个完全二叉树，其中所有节点都有两个子节点，树的所有叶子都在同一层。

# 双向链表

双向链表也是 Go 标准库的一部分。这是一个相对较大的包，因此为了方便起见，可以在以下代码片段中找到此包的函数签名：

```go
func (e *Element) Next() *Element {
func (e *Element) Prev() *Element {
func (l *List) Init() *List {
func New() *List { return new(List).Init() }
func (l *List) Len() int { return l.len }
func (l *List) Front() *Element {
func (l *List) Back() *Element {
func (l *List) lazyInit() {
func (l *List) insert(e, at *Element) *Element {
func (l *List) insertValue(v interface{}, at *Element) *Element {
func (l *List) remove(e *Element) *Element {
func (l *List) move(e, at *Element) *Element {
func (l *List) Remove(e *Element) interface{} {
func (l *List) PushFront(v interface{}) *Element {
func (l *List) PushBack(v interface{}) *Element {
func (l *List) InsertBefore(v interface{}, mark *Element) *Element {
func (l *List) InsertAfter(v interface{}, mark *Element) *Element {
func (l *List) MoveToFront(e *Element) {
func (l *List) MoveToBack(e *Element) {
func (l *List) MoveBefore(e, mark *Element) {
func (l *List) MoveAfter(e, mark *Element) {
func (l *List) PushBackList(other *List) {
func (l *List) PushFrontList(other *List) {
```

这些函数签名（以及它们对应的方法）可以在 Go 标准库中找到，网址为[`golang.org/src/container/list/list.go`](https://golang.org/src/container/list/list.go)。

最后，我们将看一下队列。

# 探索队列

队列是计算机科学中经常用来实现**先进先出**（**FIFO**）数据缓冲区的模式。进入队列的第一件事也是离开的第一件事。这是以有序的方式进行的，以处理排序数据。将事物添加到队列中称为将数据入队列，从队列末尾移除称为出队列。队列通常用作存储数据并在另一个时间进行处理的固定装置。

队列的好处在于它们没有固定的容量。新元素可以随时添加到队列中，这使得队列成为异步实现的理想解决方案，例如键盘缓冲区或打印机队列。队列用于必须按接收顺序完成任务的情况，但在实时发生时，可能基于外部因素而不可能完成。

# 常见的排队函数

非常频繁地，其他小的排队操作被添加，以使队列更有用：

+   `isfull()`通常用于检查队列是否已满。

+   `isempty()`通常用于检查队列是否为空。

+   `peek()`检索准备出队的元素，但不出队。

这些函数很有用，因为正常的入队操作如下：

1.  检查队列是否已满，如果队列已满则返回错误

1.  递增后指针；返回下一个空位

1.  将数据元素添加到后指针指向的位置

完成这些步骤后，我们可以将下一个项目入队到我们的队列中。

出队也和以下操作一样简单：

1.  检查队列是否为空，如果队列为空则返回错误

1.  访问队列前端的数据

1.  将前指针递增到下一个可用元素

完成这些步骤后，我们已经从队列中出队了这个项目。

# 常见的排队模式

拥有优化的排队机制对于编写高性能的 Go 代码非常有帮助。能够将非关键任务推送到队列中，可以让您更快地完成关键任务。另一个要考虑的问题是，您使用的排队机制不一定非得是 Go 队列。您可以将数据推送到外部机制，如 Kafka ([`kafka.apache.org/`](https://kafka.apache.org/))或 RabbitMQ ([`www.rabbitmq.com/`](https://www.rabbitmq.com/))在分布式系统中。管理自己的消息队列可能会变得非常昂贵，因此在今天，拥有单独的消息排队系统是司空见惯的。当我们研究集群和作业排队时，我们将在第十四章 *集群和作业队列*中更详细地介绍这一点。

# 总结

在本章中，我们学习了如何对 Go 程序进行基准测试。我们了解了如何根据 Big O 符号的考虑来设计对问题集具有影响力的数据结构和算法。我们还学习了搜索和排序算法、树和队列，以使我们的数据结构和算法对手头的问题具有最大的影响力。

在第三章中，*理解并发*，我们将学习一些最重要的 Go 构造，并了解它们如何影响性能。闭包、通道和 goroutines 可以帮助我们在并行性和并发性方面做出一些强大的设计决策。


# 第三章：理解并发

迭代器和生成器对于 Go 至关重要。在 Go 中使用通道和 goroutine 进行并行和并发是 Go 中的惯用法，也是编写高性能、可读性强的代码的最佳方式之一。我们首先将讨论一些基本的 Go 构造，以便能够理解如何在 Go 的上下文中使用迭代器和生成器，然后深入探讨语言中可用的迭代器和生成器的构造。

在本章中，我们将涵盖以下主题：

+   闭包

+   Goroutines

+   通道

+   信号量

+   WaitGroups

+   迭代器

+   生成器

能够理解 Go 语言的基本构造以及何时何地使用适当的迭代器和生成器对于编写高性能的 Go 语言至关重要。

# 理解闭包

Go 语言最重要的部分之一是它是一种支持头等函数的语言。头等函数是具有作为变量传递给其他函数的能力的函数。它们也可以从其他函数返回。这一点很重要，因为我们可以将它们用作闭包。

闭包很有帮助，因为它们是保持代码 DRY 的好方法，同时有助于隔离数据。到目前为止，保持数据集小是本书的核心原则，这在本章（以及任何后续章节）中都没有改变。能够隔离希望操作的数据可以帮助您继续编写高性能的代码。

闭包保持局部作用域，并访问外部函数的作用域和参数，以及全局变量。闭包是引用其主体外部的变量的函数。这些函数有能力为引用的变量分配值并访问这些值，因此我们可以在函数之间传递闭包。

# 匿名函数

理解 Go 中的闭包的第一步是理解匿名函数。使用变量创建匿名函数。它们也是没有名称或标识符的函数，因此称为*匿名函数*。

将`Hello Go`打印到屏幕的普通函数调用将是以下代码块中显示的内容：

```go
func HelloGo(){
  fmt.Println("Hello Go")
}
```

接下来，我们可以调用`HelloGo()`，函数将打印`Hello Go`字符串。

如果我们想将`HelloGo()`函数实例化为匿名函数，我们将在以下代码块中引用它：

```go
// Note the trailing () for this anonymous function invocation
func() { 
    fmt.Println("Hello Go")
}()
```

我们之前的匿名函数和`HelloGo()`函数在词法上是相似的。

我们还可以将函数存储为变量以供以后使用，如下面的代码块所示：

```go
    fmt.Println("Hello Go from an Anonymous Function Assigned to a Variable")
}
```

这三个东西——`HelloGo()`函数、我们之前定义的匿名函数和分配给`hello`变量的函数——在词法上是相似的。

在我们分配了这个`hello`变量之后，我们可以通过简单调用`hello()`来调用这个函数，我们之前定义的匿名函数将被调用，并且`Hello Go`将以与之前调用的匿名函数相同的方式打印到屏幕上。

我们可以在以下代码块中看到这些每个是如何工作的：

```go
package main

import "fmt"

func helloGo() {
    fmt.Println("Hello Go from a Function")

} 

func main() {   
    helloGo() 
    func() { fmt.Println("Hello Go from an Anonymous Function") }()
    var hello func() = func() { fmt.Println("Hello Go from an Anonymous Function Variable") }
    hello()
} 
```

此程序的输出显示了三个相似的打印语句，略有不同的打印以显示它们如何在以下截图中返回：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/695a6215-85af-475b-bfc3-4e9110d09d89.png)

匿名函数是 Go 语言的一个强大方面。随着我们继续本章，我们将看到如何在它们的基础上构建一些非常有用的东西。

# 关于闭包的匿名函数

此时，您可能想知道为什么具有匿名函数以及它们与闭包有关是明智的。一旦我们有了匿名函数，我们就可以利用闭包来引用在其自身定义之外声明的变量。我们可以在接下来的代码块中看到这一点：

```go
package main 
import "fmt" 
func incrementCounter() func() int {
 var initializedNumber = 0
 return func() int {
 initializedNumber++
 return initializedNumber
 } 
} 

func main() {
 n1 := incrementCounter() 
 fmt.Println("n1 increment counter #1: ", n1()) // First invocation of n1
 fmt.Println("n1 increment counter #2: ", n1()) // Notice the second invocation; n1 is called twice, so n1 == 2
 n2 := incrementCounter() // New instance of initializedNumber
 fmt.Println("n2 increment counter #1: ", n2()) // n2 is only called once, so n2 == 1
 fmt.Println("n1 increment counter #3: ", n1()) // state of n1 is not changed with the n2 calls
}
```

当我们执行此代码时，我们将收到以下结果输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/14480e66-3518-4501-8e4d-0c64fd8e8580.png)

在这个代码示例中，我们可以看到闭包如何帮助数据隔离。`n1`变量使用`incrementCounter()`函数进行初始化。这个匿名函数将`initializedNumber`设置为`0`，并返回一个增加的`initializedNumber`变量的计数。

当我们创建`n2`变量时，同样的过程再次发生。调用一个新的`incrementCounter`匿名函数，并返回一个新的`initializedNumber`变量。在我们的主函数中，我们可以注意到`n1`和`n2`有单独的维护状态。我们可以看到，即使在第三次调用`n1()`函数之后。能够在函数调用之间保持这些数据，同时还将数据与另一个调用隔离开来，这是匿名函数的一个强大部分。

# 用于嵌套和延迟工作的闭包

闭包也经常用于嵌套和延迟工作。在下面的例子中，我们可以看到一个函数闭包，它允许我们嵌套工作：

```go
package main
import (
 "fmt"
 "sort"
) 

func main() {
 input := []string{"foo", "bar", "baz"}
 var result []string
 // closure callback
 func() {
 result = append(input, "abc") // Append to the array
 result = append(result, "def") // Append to the array again
 sort.Sort(sort.StringSlice(result)) // Sort the larger array
 }() 
 fmt.Print(result)
}
```

在这个例子中，我们可以看到我们两次向字符串切片添加内容并对结果进行排序。我们稍后将看到如何将匿名函数嵌套在 goroutine 中以帮助提高性能。

# 使用闭包的 HTTP 处理程序

闭包在 Go 的 HTTP 调用中也经常用作中间件。您可以将普通的 HTTP 函数调用包装在闭包中，以便在需要时为调用添加额外的信息，并为不同的函数重用中间件。

在我们的示例中，我们将设置一个具有四个独立路由的 HTTP 服务器：

+   `/`：这提供以下内容：

+   一个带有 HTTP 418 状态码的 HTTP 响应（来自`newStatusCode`中间件）。

+   一个`Foo:Bar`头部（来自`addHeader`中间件）。

+   一个`Hello PerfGo!`的响应（来自`writeResponse`中间件）。

+   `/onlyHeader`：提供只添加`Foo:Bar`头部的 HTTP 响应。

+   `/onlyStatus`：只提供状态码更改的 HTTP 响应。

+   `/admin`：检查用户`admin`头部是否存在。如果存在，它会打印管理员门户信息以及所有相关的普通值。如果不存在，它会返回未经授权的响应。

这些示例已经被使用，因为它们易于理解。在 Go 中使用闭包处理 HTTP 处理程序也很方便，因为它们可以做到以下几点：

+   将数据库信息与数据库调用隔离开来

+   执行授权请求

+   用隔离的数据（例如时间信息）包装其他函数

+   与其他第三方服务透明地通信，并具有可接受的超时时间

位于[[`golang.org/doc/articles/wiki/`](https://golang.org/doc/articles/wiki/)]的 Go *编写 Web 应用程序*文档提供了一堆其他设置模板的主要示例，能够实时编辑页面，验证用户输入等。让我们来看看我们的示例代码，展示了在以下代码块中 HTTP 处理程序中的闭包。首先，我们初始化我们的包并创建一个`adminCheck`函数，它帮助我们确定用户是否被授权使用系统：

```go
package main

import (
 "fmt"
 "net/http"
) 

// Checks for a "user:admin" header, proper credentials for the admin path
func adminCheck(h http.Handler) http.HandlerFunc {
 return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
 if r.Header.Get("user") != "admin" {
 http.Error(w, "Not Authorized", 401)
 return
 }
 fmt.Fprintln(w, "Admin Portal")
 h.ServeHTTP(w, r)
 }) 
} 
```

接下来，我们设置了一些其他示例，比如提供一个 HTTP 418（`I'm a teapot`状态码）并添加一个`foo:bar`的 HTTP 头部，并设置特定的 HTTP 响应：

```go
// Sets a HTTP 418 (I'm a Teapot) status code for the response
func newStatusCode(h http.Handler) http.HandlerFunc {
 return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
 w.WriteHeader(http.StatusTeapot)
 h.ServeHTTP(w, r)
 })
}

// Adds a header, Foo:Bar
func addHeader(h http.Handler) http.HandlerFunc {
 return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
 w.Header().Add("Foo", "Bar")
 h.ServeHTTP(w, r)
 })
}

// Writes a HTTP Response
func writeResponse(w http.ResponseWriter, r *http.Request) {
 fmt.Fprintln(w, "Hello PerfGo!")
} 
```

最后，我们用一个 HTTP 处理程序将所有内容包装在一起：

```go
// Wrap the middleware together
func main() {
 handler := http.HandlerFunc(writeResponse)
 http.Handle("/", addHeader(newStatusCode(handler)))
 http.Handle("/onlyHeader", addHeader(handler)) 
 http.Handle("/onlyStatus", newStatusCode(handler))
 http.Handle("/admin", adminCheck(handler))
 http.ListenAndServe(":1234", nil)
}
```

我们的路由器测试示例如下。这是修改头部和 HTTP 状态码的输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/ec5a3321-759f-4aaf-933e-166db601b2de.png)

这是仅修改头部的输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/7398f36f-3215-4d2b-ac6c-e0f32eb1263a.png)

这是仅修改状态的输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/f47bb2df-dcbc-4450-8e3c-896d5a51f873.png)

这是未经授权的管理员输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/dab62428-96a3-4228-a69f-713bb72aabb5.png)

这是授权的管理员输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/36ab738b-e5f3-4a2e-a8d3-f205fac95b2b.png)

能够使用匿名函数添加中间件可以帮助快速迭代，同时保持代码复杂性低。在下一节中，我们将探讨 goroutines。

# 探索 goroutines

Go 是一种以并发为设计目标的语言。并发是执行独立进程的能力。Goroutines 是 Go 中的一种构造，可以帮助处理并发。它们通常被称为“轻量级线程”，原因是充分的。在其他语言中，线程由操作系统处理。这反过来使用了更大尺寸的调用堆栈，并且通常使用给定内存堆栈大小的并发较少。Goroutines 是在 Go 运行时内并发运行的函数或方法，不连接到底层操作系统。Go 语言内的调度器管理 goroutines 的生命周期。系统的调度器也有很多开销，因此限制正在使用的线程数量可以帮助提高性能。

# Go 调度器

Go 运行时调度器通过几个不同的部分来管理 goroutine 的生命周期。Go 调度器在其第二次迭代中进行了更改，这是根据 Dmitry Vyukov 撰写的设计文档而得出的，该文档于 Go 1.1 中发布。在这份设计文档中，Vyukov 讨论了最初的 Go 调度器以及如何实现工作共享和工作窃取调度器，这是由 MIT 的 Robert D. Blumofe 博士和 Charles E. Leiserson 博士在一篇名为《通过工作窃取进行多线程计算的调度》的论文中最初提出的。这篇论文背后的基本概念是确保动态的、多线程的计算，以确保处理器被有效利用同时保持内存需求。

Goroutines 在初始时只有 2KB 的堆栈大小。这是为什么 goroutines 被用于大量并发编程的原因之一——因为在一个程序中拥有数万甚至数十万个 goroutines 要容易得多。其他语言中的线程可能占用数兆字节的空间，使它们不太灵活。如果需要更多内存，Go 的函数可以在可用内存空间的其他位置分配更多内存，以帮助 goroutine 的空间增长。默认情况下，运行时会给新的堆栈分配两倍的内存。

Goroutines 只有在系统调用时才会阻塞运行的线程。当这种情况发生时，运行时会从调度器结构中取出另一个线程。这些线程用于等待执行的其他 goroutines。

工作共享是一个过程，其中调度器将新线程迁移到其他处理器以进行工作分配。工作窃取执行类似的操作，但是未被充分利用的处理器从其他处理器窃取线程。在 Go 中遵循工作窃取模式有助于使 Go 调度器更加高效，并且反过来为在内核调度器上运行的 goroutines 提供更高的吞吐量。最后，Go 的调度器实现了自旋线程。自旋线程将利用额外的 CPU 周期而不是抢占线程。线程以三种不同的方式自旋：

+   当一个线程没有附加到处理器时。

+   当使一个 goroutine 准备好时，会将一个 OS 线程解除阻塞到一个空闲的处理器上。

+   当一个线程正在运行但没有 goroutines 附加到它时。这个空闲线程将继续搜索可运行的 goroutines 来执行。

# Go 调度器 goroutine 内部

Go 调度器有三个关键结构来处理 goroutines 的工作负载：M 结构、P 结构和 G 结构。这三个结构共同工作，以高效的方式处理 goroutines。让我们更深入地看看每一个。如果你想查看这些的源代码，可以在[`github.com/golang/go/blob/master/src/runtime/runtime2.go/`](https://github.com/golang/go/blob/master/src/runtime/runtime2.go/)找到。

# M 结构

M 结构标记为**M**代表**机器**。M 结构是 OS 线程的表示。它包含一个指针，指向可运行的 goroutine 全局队列（由 P 结构定义）。M 从 P 结构中检索其工作。M 包含准备执行的空闲和等待的 goroutine。一些值得注意的 M 结构参数如下：

+   包含调度堆栈的 goroutine（go）

+   **线程本地存储**（**tls**）

+   用于执行 Go 代码的 P 结构（p）

# P 结构

这个结构标记为**P**代表**处理器**。P 结构表示一个逻辑处理器。这是由`GOMAXPROCS`设置的（在 Go 版本 1.5 之后应该等于可用核心数）。P 维护所有 goroutine 的队列（由 G 结构定义）。当您使用 Go 执行器调用新的 goroutine 时，这个新的 goroutine 会被插入到 P 的队列中。如果 P 没有关联的 M 结构，它将分配一个新的 M。一些值得注意的 P 结构参数如下：

+   P 结构 ID（id）

+   如果适用，与关联的 M 结构的后向链接（m）

+   可用延迟结构的池（deferpool）

+   可运行 goroutine 的队列（runq）

+   可用 G 的结构（gFree）

# G 结构

这个结构标记为**G**代表**goroutine**。G 结构表示单个 goroutine 的堆栈参数。它包括一些对于 goroutine 很重要的不同参数的信息。对于每个新的 goroutine 以及运行时的 goroutine，都会创建 G 结构。一些值得注意的 G 结构参数如下：

+   堆栈指针的当前值（`stack.lo`和`stack.hi`）

+   Go 和 C 堆栈增长序言的当前值（`stackguard0`和`stackguard1`）

+   M 结构的当前值（m）

# 正在执行的 goroutine

现在我们对 goroutine 的基本原理有了基本的了解，我们可以看到它们的实际应用。在下面的代码块中，我们将看到如何使用`go`调用来调用 goroutine：

```go
package main

import (
 "fmt"
 "time"
) 

func printSleep(s string) {
 for index, stringVal := range s {
 fmt.Printf("%#U at index %d\n", stringVal, index)
 time.Sleep(1 * time.Millisecond) // printSleep sleep timer
 } 
} 

func main() {
 const t time.Duration = 9 
 go printSleep("HELLO GOPHERS")
 time.Sleep(t * time.Millisecond) // Main sleep timer
 fmt.Println("sleep complete")
} 
```

在执行此函数期间，我们只得到了`printSleep()`函数的部分返回（打印`HELLO GOPHERS`），然后主睡眠计时器完成。为什么会发生这种情况？如果`main()` goroutine 完成，它会关闭，程序终止，并且剩余的 goroutine 将不会运行。我们能够得到前九个字符的返回，是因为这些 goroutine 在主函数执行完成之前就已经完成了。如果我们将`const t`的持续时间更改为`14`，我们将收到整个`HELLO GOPHERS`字符串。原因是在`main`函数完成之前，`go printSleep()`周围产生的所有 goroutine 都没有执行。只有在正确使用时，goroutine 才是强大的。

另一个帮助管理并发 goroutine 的 Go 内置功能是 Go 通道，这是我们将在下一节中讨论的主题。

# 引入通道

通道是允许发送和接收值的机制。通道通常与 goroutine 一起使用，以便在 goroutine 之间并发地传递对象。Go 中有两种主要类型的通道：无缓冲通道和缓冲通道。

# 通道内部

通道是使用`make()` Golang 内置函数调用的，其中创建了一个`hchan`结构。`hchan`结构包含队列中的数据计数，队列的大小，用于缓冲区的数组指针，发送和接收索引和等待者，以及互斥锁。以下代码块说明了这一点：

```go
type hchan struct {
    qcount   uint           // total data in the queue
    dataqsiz uint           // size of the circular queue
    buf      unsafe.Pointer // points to an array of dataqsiz elements
    elemsize uint16
    closed   uint32
    elemtype *_type // element type
    sendx    uint   // send index
    recvx    uint   // receive index
    recvq    waitq  // list of recv waiters
    sendq    waitq  // list of send waiters
    // lock protects all fields in hchan, as well as several
    // fields in sudogs blocked on this channel.
    //  
    // Do not change another G's status while holding this lock
    // (in particular, do not ready a G), as this can deadlock
    // with stack shrinking.
    lock mutex
}
```

这个代码块引用自[`golang.org/src/runtime/chan.go#L32`](https://golang.org/src/runtime/chan.go#L32)。

# 缓冲通道

缓冲通道是具有有限大小的通道。它们通常比无限大小的通道更高效。它们对于从你启动的一组显式数量的 goroutine 中检索值非常有用。因为它们是**FIFO**（先进先出）的排队机制，它们可以有效地用作固定大小的排队机制，我们可以按照它们进入的顺序处理请求。通道在使用之前通过调用`make()`函数创建。一旦创建了缓冲通道，它就已经准备好可以使用了。如果通道中仍有空间，缓冲通道不会在接收写入时阻塞。重要的是要记住数据在通道内的箭头方向流动。在我们的示例中（以下代码块），我们执行以下操作：

+   将`foo`和`bar`写入我们的`buffered_channel`

+   检查通道的长度-长度为`2`，因为我们添加了两个字符串

+   从通道中弹出`foo`和`bar`

+   检查通道的长度-长度为`0`，因为我们移除了两个字符串

+   向我们的通道中添加`baz`

+   从通道中弹出`baz`到一个变量`out`

+   打印结果的`out`变量，它是`baz`（我们添加到通道中的最后一个元素）

+   关闭我们的缓冲通道，表示不再有数据通过这个通道传递

让我们看一下以下代码块：

```go
package main
import "fmt"
 func main() {
 buffered_channel := make(chan string, 2)
 buffered_channel <- "foo"
 buffered_channel <- "bar"

 // Length of channel is 2 because both elements added to channel
 fmt.Println("Channel Length After Add: ", len(buffered_channel))

 // Pop foo and bar off the stack
 fmt.Println(<-buffered_channel)
 fmt.Println(<-buffered_channel)

 // Length of channel is 0 because both elements removed from channel
 fmt.Println("Channel Length After Pop: ", len(buffered_channel)) 

 // Push baz to the stack
 buffered_channel <- "baz"

 // Store baz as a variable, out
 out := <-buffered_channel
 fmt.Println(out)
 close(buffered_channel)
}
```

这段代码可以在[`github.com/bobstrecansky/HighPerformanceWithGo/blob/master/3-iterators-and-generators/channels/buffered_channel.go`](https://github.com/bobstrecansky/HighPerformanceWithGo/blob/master/3-iterators-and-generators/channels/buffered_channel.go)找到。

正如我们在代码块示例中看到的，我们能够将数据推送到栈中并从栈中弹出数据。还需要注意的是`len()`内置函数返回通道缓冲区中未读（或排队）的元素数量。除了`len()`内置函数，我们还可以使用`cap()`内置函数来推断缓冲区的总容量。这两个内置函数结合使用通常可以用来了解通道的当前状态，特别是如果它的行为不符合预期。关闭通道也是一个好习惯。当你关闭一个通道时，你告诉 Go 调度程序不会再有值被发送到该通道。还需要注意的是，如果你尝试向一个关闭的通道或者队列中没有空间的通道写入数据，你的程序会引发 panic。

以下程序会引发 panic：

```go
package main
 func main() {
 ch := make(chan string, 1) 
 close(ch)
 ch <- "foo"
}
```

我们将会看到以下的错误消息截图：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/ac43436f-bb84-4120-aa93-6a018f3680f9.png)

这是因为我们试图向一个已经关闭的通道(`ch`)传递数据(`foo`字符串)。

以下程序也会引发 panic：

```go
package main 
 func main() {
 ch := make(chan string, 1)
ch <- "foo"
ch <- "bar"
}
```

我们会看到以下错误消息：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/388c2dbf-21f0-44a4-bddf-9380ae00be8c.png)

程序会因为 goroutine 会被阻塞而引发 panic。这个错误会被运行时检测到，程序退出。

# 遍历通道

你可能想知道你的缓冲通道中所有的值。我们可以通过在我们想要检查的通道上调用`range`内置函数来实现这一点。我们在以下代码块的示例中向通道添加了三个元素，关闭了通道，然后使用`fmt`写入了通道中的所有元素：

```go
package main

import "fmt"

func main() {

    bufferedChannel := make(chan int, 3)
    bufferedChannel <- 1
    bufferedChannel <- 3
    bufferedChannel <- 5
    close(bufferedChannel)                                                                                                                  
    for i := range bufferedChannel {
        fmt.Println(i)
    }   
} 

```

结果输出显示了我们缓冲通道中的所有值：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/7b342089-1d86-44b5-8cdb-7291667a2a50.png)

提醒一下-确保关闭通道。如果我们删除前面的`close(bufferedChannel)`函数，我们将会遇到死锁。

# 无缓冲通道

在 Go 中，无缓冲通道是默认的通道配置。无缓冲通道是灵活的，因为它们不需要有一个有限的通道大小定义。当通道的接收者比通道的发送者慢时，它们通常是最佳选择。它们在读取和写入时都会阻塞，因为它们是同步的。发送者将阻塞通道，直到接收者接收到值。它们通常与 goroutines 一起使用，以确保项目按预期的顺序进行处理。

在我们接下来的示例代码块中，我们执行以下操作：

+   创建一个布尔通道来维护状态

+   创建一个未排序的切片

+   使用 `sortInts()` 函数对我们的切片进行排序

+   响应我们的通道，以便我们可以继续函数的下一部分

+   搜索我们的切片以查找给定的整数

+   响应我们的通道，以便我们的通道上的事务完成

+   返回通道值，以便我们的 Go 函数完成

首先，我们导入我们的包并创建一个函数，用于在通道中对整数进行排序：

```go
package main
import (
    "fmt"
    "sort"
)
func sortInts(intArray[] int, done chan bool) {
    sort.Ints(intArray)
    fmt.Printf("Sorted Array: %v\n", intArray)
    done < -true
}
```

接下来，我们创建一个 `searchInts` 函数，用于在通道中搜索整数：

```go
func searchInts(intArray []int, searchNumber int, done chan bool) {
    sorted := sort.SearchInts(intArray, searchNumber)
    if sorted < len(intArray) {
        fmt.Printf("Found element %d at array position %d\n", searchNumber, sorted)
    } else {
        fmt.Printf("Element %d not found in array %v\n", searchNumber, intArray)
    }       
    done <- true
}        
```

最后，我们在我们的 `main` 函数中将它们全部绑定在一起：

```go
func main() {
    ch := make(chan bool)
    go func() {
        s := []int{2, 11, 3, 34, 5, 0, 16} // unsorted
        fmt.Println("Unsorted Array: ", s)
        searchNumber := 16
        sortInts(s, ch)
        searchInts(s, searchNumber, ch)
    }()
    <-ch
}             
```

我们可以在以下截图中看到该程序的输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/dc8e3fa2-936a-4a43-b2d7-06a7d2dcc4a7.png)

这是使用通道并行执行操作的好方法。

# 选择

选择是一种允许您以有意义的方式结合 goroutines 和通道的构造。我们可以复用 Go 函数，以便能够执行 goroutine 运行时发生的情况。在我们的示例中，我们创建了三个单独的通道：一个 `string` 通道，一个 `bool` 通道和一个 `rune` 通道。接下来，我们在以下代码块中运行一些匿名函数，以便向这些通道中填充数据，并使用内置的 select 返回通道中的值。

1.  首先，我们初始化我们的包并设置三个单独的通道：

```go
package main

import (
    "fmt"
    "time"
) 

func main() {

    // Make 3 channels
    ch1 := make(chan string)
    ch2 := make(chan bool)
    ch3 := make(chan rune)
```

1.  接下来，通过匿名函数向每个通道传递适当的变量：

```go
    // string anonymous function to ch1
    go func() {
        ch1 <- "channels are fun"
    }() 

    // bool anonymous function to ch2
    go func() {
        ch2 <- true
    }() 

    // rune anonymous function to ch3 with 1 second sleep
    go func() {
        time.Sleep(1 * time.Second)
        ch3 <- 'r' 
    }() 
```

1.  最后，我们通过我们的 `select` 语句将它们传递：

```go

    // select builtin to return values from channels                                                                                        
    for i := 0; i < 3; i++ {
        select {
        case msg1 := <-ch1:
            fmt.Println("Channel 1 message: ", msg1)
        case msg2 := <-ch2:
            fmt.Println("Channel 2 message: ", msg2)
        case msg3 := <-ch3:
            fmt.Println("Channel 3 message: ", msg3)
        }   
    }   
}       
```

该程序的结果输出可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/1a2b978b-932d-440d-acc9-76e6d3cef53d.png)

您会注意到这里 `rune` 匿名函数最后返回。这是由于在该匿名函数中插入了休眠。如果多个值准备就绪，`select` 语句将随机返回传递到通道中的值，并在 goroutine 结果准备就绪时按顺序返回。

在下一节中，我们将学习什么是信号量。

# 引入信号量

信号量是另一种控制 goroutines 执行并行任务的方法。信号量很方便，因为它们使我们能够使用工作池模式，但我们不需要在工作完成并且工作线程处于空闲状态时关闭工作线程。在 Go 语言中使用加权信号量的概念相对较新；信号量的 sync 包实现是在 2017 年初实现的，因此它是最新的并行任务构造之一。

如果我们以以下代码块中的简单循环为例，向请求添加 100 毫秒的延迟，并向数组添加一个项目，我们很快就会看到随着这些任务按顺序操作，所需的时间增加：

```go
package main

import (
    "fmt"
    "time"
)       

func main() {
    var out = make([]string, 5)                                                                                                             
    for i := 0; i < 5; i++ {
        time.Sleep(100 * time.Millisecond)
        out[i] = "This loop is slow\n"
    }   
    fmt.Println(out)
}       
```

我们可以使用相同的构造创建一个加权信号量实现。我们可以在以下代码块中看到：

1.  首先，我们初始化程序并设置信号量变量：

```go
package main

import (
 "context"
 "fmt"
 "runtime"
 "time"

 "golang.org/x/sync/semaphore"
)

func main() {
    ctx := context.Background()
    var (
        sem    = semaphore.NewWeighted(int64(runtime.GOMAXPROCS(0)))
        result = make([]string, 5)
    )   
```

1.  然后，我们运行我们的信号量代码：

```go

    for i := range result {
        if err := sem.Acquire(ctx, 1); err != nil {
            break
        }
        go func(i int) {
            defer sem.Release(1)
            time.Sleep(100 * time.Millisecond)
            result[i] = "Semaphores are Cool \n"
        }(i)
    }   
    if err := sem.Acquire(ctx, int64(runtime.GOMAXPROCS(0))); err != nil {
        fmt.Println("Error acquiring semaphore")
    }   
    fmt.Println(result)
}    
```

这两个函数之间的执行时间差异非常明显，可以在以下输出中看到：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/b4ce5faa-d65a-4c48-ba59-d0c393bd7725.png)

信号量实现的运行速度比两倍还要快，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/beebc1ba-0328-44b1-8992-00ddff52a5c9.png)

信号量实现的速度超过两倍。 这是只有五个 100 毫秒的阻塞睡眠。 随着规模的不断增长，能够并行处理事务变得越来越重要。

在下一节中，我们将讨论 WaitGroups。

# 理解 WaitGroups

WaitGroups 通常用于验证多个 goroutine 是否已完成。 我们这样做是为了确保我们已完成了所有我们期望完成的并发工作。

在以下代码块的示例中，我们使用`WaitGroup`对四个网站进行请求。 这个`WaitGroup`将等到所有的请求都完成后才会完成`main`函数，并且只有在所有的`WaitGroup`值都返回后才会完成：

1.  首先，我们初始化我们的包并设置我们的检索函数：

```go
package main

import (
    "fmt"
    "net/http"
    "sync"
    "time"
) 

func retrieve(url string, wg *sync.WaitGroup) {
    // WaitGroup Counter-- when goroutine is finished
    defer wg.Done() 
    start := time.Now()
    res, err := http.Get(url)
    end := time.Since(start)
    if err != nil {
        panic(err)
    } 
    // print the status code from the response
    fmt.Println(url, res.StatusCode, end) 

} 
```

1.  在我们的`main`函数中，我们接下来使用我们的检索函数在一个 goroutine 中使用 WaitGroups：

```go
func main() {
    var wg sync.WaitGroup
    var urls = []string{"https://godoc.org", "https://www.packtpub.com", "https://kubernetes.io/"}
    for i := range urls {
        // WaitGroup Counter++ when new goroutine is called
        wg.Add(1) 
        go retrieve(urls[i], &wg)
    }
    // Wait for the collection of goroutines to finish 
    wg.Wait()
} 
```

从以下输出中可以看出，我们收到了所有网页请求的测量数据，它们的响应代码和它们各自的时间：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/c1cffc7b-dea6-45b7-a6b8-033b614b03e3.png)

我们经常希望所有的 goroutine 都能完成。 WaitGroups 可以帮助我们做到这一点。

在下一节中，我们将讨论迭代的过程。

# 迭代器和迭代的过程

迭代是查看一组数据的方法，通常是列表，以便从该列表中检索信息。 Go 有许多不同的迭代器模式，都有利有弊：

| **迭代器** | **优点** | **缺点** |
| --- | --- | --- |
| `for`循环 | 最简单的实现 | 没有默认并发。 |
| 具有回调的迭代器函数 | 简单的实现 | Go 的非常规样式； 难以阅读。 |
| 通道 | 简单的实现 | 在计算上比其他一些迭代器更昂贵（成本差异较小）。 唯一自然并发的迭代器。 |
| 有状态的迭代器 | 难以实现 | 良好的调用者接口。 适用于复杂的迭代器（通常在标准库中使用）。 |

重要的是要相互对比所有这些以验证关于每个迭代器需要多长时间的假设。 在以下测试中，我们对它们的和进行了`0`到`n`的求和，并对它们进行了基准测试。

以下代码块具有简单的`for`循环迭代器：

```go
package iterators

var sumLoops int
func simpleLoop(n int) int {
    for i: = 0; i < n; i++ {
        sumLoops += i
    }
    return sumLoops
}
```

以下代码块具有回调迭代器：

```go
package iterators

var sumCallback int

func CallbackLoop(top int) {
    err: = callbackLoopIterator(top, func(n int) error {
        sumCallback += n
        return nil
    })
    if err != nil {
        panic(err)
    }
}

func callbackLoopIterator(top int, callback func(n int) error) error {
    for i: = 0; i < top; i++{
        err: = callback(i)
        if err != nil {
            return err
        }
    }
    return nil
}
```

以下代码块将展示`Next()`的使用。 让我们再一次一步一步地看一下：

1.  首先，我们初始化我们的包变量和结构。 接下来，我们创建一个`CounterIterator`：

```go
package iterators

var sumNext int

type CounterStruct struct {
    err error
    max int
    cur int
}

func NewCounterIterator(top int) * CounterStruct {
    var err error
    return &CounterStruct {
        err: err,
        max: top,
        cur: 0,
    }
}
```

1.  接下来是`Next()`函数，`Value()`函数和`NextLoop()`函数：

```go
func(i * CounterStruct) Next() bool {
    if i.err != nil {
        return false
    }
    i.cur++
        return i.cur <= i.max
}
func(i * CounterStruct) Value() int {
    if i.err != nil || i.cur > i.max {
        panic("Value is not valid after iterator finished")
    }
    return i.cur
}
func NextLoop(top int) {
    nextIterator: = NewCounterIterator(top)
    for nextIterator.Next() {
        fmt.Print(nextIterator.Value())
    }
}
```

1.  下一个代码块具有缓冲通道实现：

```go
package iterators

var sumBufferedChan int

func BufferedChanLoop(n int) int {

    ch: = make(chan int, n)

        go func() {
        defer close(ch)
        for i: = 0;
        i < n;
        i++{
            ch < -i
        }
    }()

    for j: = range ch {
        sumBufferedChan += j
    }
    return sumBufferedChan
}
```

1.  下一个代码块具有无缓冲通道实现：

```go
package iterators

var sumUnbufferedChan int

func UnbufferedChanLoop(n int) int {
    ch: = make(chan int)

        go func() {
        defer close(ch)
        for i: = 0;
        i < n;
        i++{
            ch < -i
        }
    }()

    for j: = range ch {
        sumUnbufferedChan += j
    }
    return sumUnbufferedChan
}
```

1.  将所有这些编译在一起后，我们可以进行测试基准。 这些基准测试可以在以下代码块中找到。 让我们再一次一步一步地看一下。

1.  首先，我们初始化我们的包并设置一个简单的回调循环基准：

```go
package iterators

import "testing"

func benchmarkLoop(i int, b *testing.B) {
    for n := 0; n < b.N; n++ {
        simpleLoop(i)
    } 
}

func benchmarkCallback(i int, b *testing.B) {
    b.ResetTimer()
    for n := 0; n < b.N; n++ {
        CallbackLoop(i)
    } 
}
```

1.  接下来是一个`Next`和缓冲通道基准：

```go
func benchmarkNext(i int, b *testing.B) {
    b.ResetTimer()
    for n := 0; n < b.N; n++ {
        NextLoop(i)
    } 
}

func benchmarkBufferedChan(i int, b *testing.B) {
    b.ResetTimer()
    for n := 0; n < b.N; n++ {
        BufferedChanLoop(i)
    } 
}
```

1.  最后，我们设置了无缓冲通道基准，并为每个基准创建了循环函数：

```go
func benchmarkUnbufferedChan(i int, b *testing.B) {
    b.ResetTimer()
    for n := 0; n < b.N; n++ {
        UnbufferedChanLoop(i)
    }   
}

func BenchmarkLoop10000000(b *testing.B)           { benchmarkLoop(1000000, b) }
func BenchmarkCallback10000000(b *testing.B)       { benchmarkCallback(1000000, b) }
func BenchmarkNext10000000(b *testing.B)           { benchmarkNext(1000000, b) }
func BenchmarkBufferedChan10000000(b *testing.B)   { benchmarkBufferedChan(1000000, b) }
func BenchmarkUnbufferedChan10000000(b *testing.B) { benchmarkUnbufferedChan(1000000, b) }   
```

基准测试的结果可以在以下截图中找到：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/853c9c7a-85e3-436c-b9cf-ac131f448b3c.png)

这些迭代器测试的上下文非常重要。 因为在这些测试中我们只是做简单的加法，所以迭代的简单构造是关键。 如果我们在每次调用中添加延迟，那么并发通道迭代器的性能将更好。 并发在合适的上下文中是一件强大的事情。

在下一节中，我们将讨论生成器。

# 生成器简介

生成器是在循环结构中返回下一个顺序值的例程。生成器通常用于实现迭代器并引入并行性。在 Go 中，Goroutines 被用来实现生成器。为了在 Go 中实现并行性，我们可以使用生成器与消费者并行运行以产生值。它们通常在循环结构中被使用。生成器本身也可以并行化。这通常是在生成输出的成本很高且输出可以以任何顺序生成时才会这样做。

# 总结

在本章中，我们学习了 Go 中用于迭代器和生成器的许多基本构造。理解匿名函数和闭包帮助我们建立了关于这些函数如何工作的基础知识。然后我们学习了 goroutines 和 channels 的工作原理，以及如何有效地实现它们。我们还学习了关于信号量和 WaitGroups，以及它们在语言中的作用。理解这些技能将帮助我们以更有效的方式解析计算机程序中的信息，从而实现更多的并发数据操作。在第四章中，*在 Go 中的 STL 算法等效实现*，我们将学习如何在 Go 中实现**标准模板库**（**STL**）的实际应用。
