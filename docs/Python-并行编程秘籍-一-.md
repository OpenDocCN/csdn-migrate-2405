# Python 并行编程秘籍（一）

> 原文：[`zh.annas-archive.org/md5/e472b7edae31215ac8e4e5f1e5748012`](https://zh.annas-archive.org/md5/e472b7edae31215ac8e4e5f1e5748012)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

计算行业的特点是寻求越来越高效的性能，从网络、电信、航空电子等领域的高端应用到台式计算机、笔记本电脑和视频游戏中的低功耗嵌入式系统。这种发展路径已经导致了多核系统的出现，其中双核、四核和八核处理器只是即将到来的计算核心数量不断增加的开始。

然而，这种扩展不仅在半导体行业中，也在可以通过并行计算执行的应用程序的开发中带来了挑战。

事实上，**并行计算**代表着同时利用多个计算资源来解决处理问题，以便可以在多个 CPU 上执行，将问题分解为可以同时处理的离散部分，每个部分进一步分解为可以在不同 CPU 上串行执行的一系列指令。

计算资源可以包括具有多个处理器的单台计算机，通过网络连接的任意数量的计算机，或者两种方法的组合。并行计算一直被认为是计算的极端顶点或未来，直到几年前，它是由复杂系统的数值模拟和涉及各个领域的情况所驱动：天气和气候预测、化学和核反应、人类基因组图谱、地震和地质活动、机械设备的行为（从假肢到航天飞机）、电子电路和制造过程。

然而，如今，越来越多的商业应用程序要求开发速度更快的计算机，以支持以复杂方式处理大量数据。这些应用包括数据挖掘和并行数据库、石油勘探、网络搜索引擎和服务、计算机辅助医学诊断、跨国公司管理、高级图形和虚拟现实（尤其是视频游戏行业）、多媒体和视频网络技术以及协作工作环境。

最后但同样重要的是，并行计算代表了最大化时间这一无限但同时越来越宝贵和稀缺的资源的尝试。这就是为什么并行计算正在从为少数人保留的非常昂贵的超级计算机的世界转向基于多处理器、**图形处理单元**（**GPU**）或几台相互连接的计算机的更经济和解决方案，这些解决方案可以克服串行计算的约束和单个 CPU 的限制。

为了介绍并行编程的概念，我们采用了最流行的编程语言之一——Python。Python 之所以如此受欢迎，部分原因在于其灵活性，因为它是网页和桌面开发人员、系统管理员和代码开发人员以及最近的数据科学家和机器学习工程师经常使用的语言。

从技术角度来看，在 Python 中，没有单独的编译阶段（例如在 C 中发生的情况），从源代码生成可执行文件。Python 是一种便携式语言的事实使其成为一种便携式语言。一旦源代码编写完成，它可以在当前使用的大多数平台上进行解释和执行，无论是来自苹果（macOS X）还是 PC（Microsoft Windows 和 GNU/Linux）。

Python 的另一个优点是*易学性*。任何人都可以在几天内学会使用它并编写他们的第一个应用程序。在这种情况下，语言的开放结构起着基础性作用，没有冗余的声明，因此非常类似于口语。最后，Python 是自由软件：不仅 Python 解释器和在我们的应用程序中使用 Python 是免费的，而且 Python 也可以自由修改和根据完全开源许可证的规则进行重新分发。

《Python 并行编程食谱，第二版》包含各种示例，为读者提供解决实际问题的机会。它审查了并行架构的软件设计原则，强调程序清晰度的重要性，并避免使用复杂术语，而是使用清晰直接的示例。

每个主题都作为完整的、可工作的 Python 程序的一部分呈现，总是跟随所讨论程序的输出。各章节的模块化组织提供了一个经过验证的路径，从最简单的论点到最高级的论点，但也适合那些只想学习一些特定问题的人。

# 本书适合对象

《Python 并行编程食谱，第二版》旨在面向希望利用并行编程技术编写强大高效代码的软件开发人员。阅读本书将使您能够掌握并行计算的基础知识和高级方面。

Python 编程语言易于使用，使非专家能够轻松处理和理解本书中概述的主题。

# 本书涵盖的内容

第一章，*开始并行计算和 Python*，概述了并行编程架构和编程模型。该章介绍了 Python 编程语言，讨论了语言的特性、易学易用性、可扩展性以及丰富的可用软件库和应用程序，这些都使 Python 成为任何应用程序的有价值工具，特别是当然是并行计算。

第二章，*基于线程的并行性*，讨论使用`threading`Python 模块的线程并行性。读者将通过完整的编程示例学习如何同步和操作线程，以实现多线程应用程序。

第三章，*基于进程的并行性*，引导读者通过基于进程的方法来并行化程序。一整套示例将向读者展示如何使用`multiprocessing` Python 模块。

第四章，*消息传递*，专注于消息传递交换通信系统。特别是，将介绍`mpi4py`库，并提供大量应用示例。

第五章，*异步编程*，解释了并发编程的异步模型。在某些方面，它比线程模型更简单，因为有一个单一的指令流，任务明确放弃控制，而不是任意挂起。该章向读者展示如何使用`asyncyio`模块以异步方式组织每个任务作为一系列必须以异步方式执行的较小步骤。

第六章，*分布式 Python*，介绍了分布式计算，即聚合多个计算单元以透明一致的方式协同运行单个计算任务的过程。特别是，该章提供的示例应用描述了使用`socket`和 Celery 模块管理分布式任务。

第七章，*云计算*，概述了与 Python 编程语言相关的主要云计算技术。**PythonAnywhere**平台非常适用于在云上部署 Python 应用程序，并将在本章中进行讨论。本章还包含演示使用**容器**和**无服务器**技术的示例应用程序。

第八章，*异构计算*，探讨了为数值计算提供突破性性能的现代 GPU，但代价是增加了编程复杂性。事实上，GPU 的编程模型要求编码人员手动管理 CPU 和 GPU 之间的数据传输。本章将通过编程示例和用例教读者如何利用**PyCUDA**、**Numba**和**PyOpenCL**等强大的 Python 模块来利用 GPU 卡提供的计算能力。

第九章，*Python 调试和测试*，是介绍软件工程中两个重要主题：调试和测试的最后一章。特别地，将描述以下 Python 框架：用于调试的`winpdb-reborn`，以及用于软件测试的`unittest`和`nose`。

# 为了充分利用本书

本书是*独立的*：在开始阅读之前，唯一的基本要求是对编程的热情和对书中涵盖的主题的好奇心。

# 下载示例代码文件

您可以从您的帐户在[www.packt.com](http://www.packt.com)下载本书的示例代码文件。如果您在其他地方购买了本书，您可以访问[www.packtpub.com/support](https://www.packtpub.com/support)注册，直接将文件发送到您的邮箱。

您可以按照以下步骤下载代码文件：

1.  登录或注册[www.packtpub.com](http://www.packtpub.com/support)。

1.  选择“支持”选项卡。

1.  点击“代码下载”。

1.  在搜索框中输入书名，然后按照屏幕上的说明操作。

下载文件后，请确保使用最新版本的解压缩或提取文件夹：

+   Windows 的 WinRAR/7-Zip

+   Mac 的 Zipeg/iZip/UnRarX

+   Linux 的 7-Zip/PeaZip

该书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Python-Parallel-Programming-Cookbook-Second-Edition`](https://github.com/PacktPublishing/Python-Parallel-Programming-Cookbook-Second-Edition)。我们还有其他代码包，来自我们丰富的书籍和视频目录，可在**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**找到。快去看看吧！

# 下载彩色图像

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图像。您可以在这里下载：[`static.packt-cdn.com/downloads/9781789533736_ColorImages.pdf`](https://static.packt-cdn.com/downloads/9781789533736_ColorImages.pdf)。

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：指示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。以下是一个例子："可以使用`terminate`方法立即终止进程。"

代码块设置如下：

```py
import socket
port=60000
s =socket.socket()
host=socket.gethostname()
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```py
 p = multiprocessing.Process(target=foo)
 print ('Process before execution:', p, p.is_alive())
 p.start()
```

任何命令行输入或输出都以以下方式编写：

```py
> python server.py
```

**粗体**：表示新术语、重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会以这种方式出现在文本中。以下是一个例子："转到系统属性|环境变量|用户或系统变量|新建。"

警告或重要说明会出现在这样的地方。提示和技巧会出现在这样的地方。

# 章节

在本书中，您会经常看到几个标题（*准备工作*、*如何做…*、*它是如何工作的…*、*还有更多…*和*另请参阅*）。

为了清晰地说明如何完成食谱，请使用以下各节：

# 准备工作

这一部分告诉您在食谱中可以期待什么，并描述如何设置任何软件或食谱所需的任何初步设置。

# 如何做…

这一部分包含了遵循食谱所需的步骤。

# 它是如何工作的…

这一部分通常包括对前一部分发生的事情的详细解释。

# 还有更多…

这一部分包括有关食谱的额外信息，以使您对食谱更加了解。

# 另请参阅

这一部分为食谱提供了其他有用信息的链接。


# 第一章：开始并行计算和 Python

*并行*和*分布式计算*模型基于同时使用不同处理单元进行程序执行。尽管并行和分布式计算之间的区别非常微弱，但可能的定义之一将并行计算模型与共享内存计算模型相关联，将分布式计算模型与消息传递模型相关联。

从这一点开始，我们将使用术语*并行计算*来指代并行和分布式计算模型。

接下来的部分将概述并行编程体系结构和编程模型。这些概念对于初学者来说是有用的，他们第一次接触并行编程技术。此外，它也可以成为有经验的程序员的基本参考。还介绍了并行系统的双重特征。第一种特征基于系统架构，而第二种特征基于并行编程范式。

本章以对 Python 编程语言的简要介绍结束。语言的特点、易用性和学习性，以及软件库和应用程序的可扩展性和丰富性，使 Python 成为任何应用的有价值工具，也适用于并行计算。介绍了线程和进程的概念，以及它们在语言中的使用。

在本章中，我们将涵盖以下内容：

+   为什么我们需要并行计算？

+   弗林的分类

+   内存组织

+   并行编程模型

+   性能评估

+   介绍 Python

+   Python 和并行编程

+   介绍进程和线程

# 为什么我们需要并行计算？

现代计算机提供的计算能力增长导致我们在相对较短的时间内面临着日益复杂的计算问题。直到 21 世纪初，复杂性是通过增加晶体管数量以及单处理器系统的时钟频率来处理的，达到了 3.5-4 GHz 的峰值。然而，晶体管数量的增加导致了处理器本身耗散功率的指数增长。实质上，因此存在着一个物理限制，阻止了单处理器系统性能的进一步提高。

因此，近年来，微处理器制造商已经将注意力集中在*多核*系统上。这些系统基于多个物理处理器的核心，它们共享相同的内存，从而绕过了之前描述的功耗问题。近年来，*四核*和*八核*系统也已成为普通台式机和笔记本配置的标准。

另一方面，硬件上的如此重大变化也导致了软件结构的演变，这些软件一直被设计为在单个处理器上顺序执行。为了利用通过增加处理器数量提供的更多计算资源，现有软件必须以适合 CPU 并行结构的形式进行重新设计，以便通过同时执行同一程序的多个部分的单元来获得更高的效率。

# 弗林的分类

弗林的分类是一种用于分类计算机体系结构的系统。它基于两个主要概念：

+   指令流：具有*n*个 CPU 的系统具有*n*个程序计数器，因此有*n*个指令流。这对应于一个程序计数器。

+   **数据流**：计算数据列表上的函数的程序具有数据流。计算相同函数在几个不同数据列表上的程序具有更多的数据流。这由一组操作数组成。

由于指令和数据流是独立的，存在四类并行机器：**单指令单数据**（**SISD**）、**单指令多数据**（**SIMD**）、**多指令单数据**（**MISD**）和**多指令多数据**（**MIMD**）：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-pll-prog-cb/img/315c390f-4c31-4a69-811e-5696dff064d1.png)

弗林分类法

# 单指令单数据（SISD）

SISD 计算系统类似于冯·诺伊曼机，即单处理器机器。如*弗林分类法*图所示，它执行单个指令，作用于单个数据流。在 SISD 中，机器指令是按顺序处理的。

在一个时钟周期内，CPU 执行以下操作：

+   **取指**：CPU 从内存区域获取数据和指令，称为*寄存器*。

+   **解码**：CPU 解码指令。

+   **执行**：指令在数据上执行。操作的结果存储在另一个寄存器中。

执行阶段完成后，CPU 开始另一个 CPU 周期：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-pll-prog-cb/img/8d131bb3-cd52-4f51-969c-8c836a394f89.png)

取指、解码和执行周期

在这种类型的计算机上运行的算法是顺序的，因为它们不包含任何并行性。SISD 计算机的一个例子是具有单个 CPU 的硬件系统。

这些架构的主要元素（即冯·诺伊曼架构）如下：

+   **中央存储器单元**：用于存储指令和程序数据。

+   **CPU**：用于从存储器单元获取指令和/或数据，解码指令并按顺序执行。

+   **I/O 系统**：这指的是程序的输入和输出数据。

传统的单处理器计算机被归类为 SISD 系统：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-pll-prog-cb/img/1a6b6929-c4c4-41bb-96ae-2ec6b2aea55d.png)

SISD 架构图

以下图表具体显示了 CPU 在取指、解码和执行阶段中使用的区域：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-pll-prog-cb/img/9ceec645-0aa1-4c90-97a7-cba9f8eb5031.png)

CPU 在取指-解码-执行阶段的组件

# 多指令单数据（MISD）

在这种模型中，*n*个处理器，每个都有自己的控制单元，共享一个单一的存储单元。在每个时钟周期中，从存储器接收的数据由所有处理器同时处理，每个处理器根据从其控制单元接收的指令进行处理。

在这种情况下，通过对同一数据执行多个操作来获得并行性（指令级并行性）。这些架构可以有效解决的问题类型相当特殊，例如数据加密。因此，MISD 计算机在商业领域没有找到位置。MISD 计算机更多地是一种智力锻炼，而不是一种实际的配置。

# 单指令多数据（SIMD）

SIMD 计算机由*n*个相同的处理器组成，每个处理器都有自己的本地存储器，可以在其中存储数据。所有处理器都在单一指令流的控制下工作。此外，还有*n*个数据流，每个处理器对应一个数据流。处理器同时在每个步骤上执行并执行相同的指令，但对不同的数据元素进行操作。这是数据级并行性的一个例子。

SIMD 架构比 MISD 架构更加灵活。并行算法可以解决涵盖广泛应用领域的许多问题。另一个有趣的特点是，这些计算机的算法相对容易设计、分析和实现。限制在于只有能够分解为多个子问题（这些子问题都是相同的，然后通过相同的指令集同时解决）的问题才能用 SIMD 计算机解决。

根据这一范式开发的超级计算机，我们必须提到*Connection Machine*（Thinking Machine,1985）和*MPP*（NASA, 1983）。

正如我们将在第六章中看到的，*分布式 Python*，以及第七章中看到的，*云计算*，现代图形卡（GPU）的出现，内置了许多 SIMD 嵌入单元，导致了这种计算范式的更广泛使用。

# 多指令多数据（MIMD）

根据弗林的分类，这类并行计算机是最一般和最强大的类。这包括*n*个处理器，*n*个指令流和*n*个数据流。每个处理器都有自己的控制单元和本地内存，这使得 MIMD 架构比 SIMD 架构更具计算能力。

每个处理器都在其自己的控制单元发出的指令流的控制下运行。因此，处理器可以潜在地运行不同的程序和不同的数据，这使它们能够解决不同的子问题，并且可以成为单个更大问题的一部分。在 MIMD 中，架构是通过线程和/或进程的并行级别实现的。这也意味着处理器通常是异步操作的。

如今，这种架构应用于许多个人电脑、超级计算机和计算机网络。然而，您需要考虑的一个反面是：异步算法难以设计、分析和实现：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-pll-prog-cb/img/f3fa5a98-1a89-4d76-a8af-c25a376c1ac8.png)

SIMD 架构（A）和 MIMD 架构（B）

通过考虑 SIMD 机器可以分为两个子组：

+   数值超级计算机

+   矢量机器

另一方面，MIMD 可以分为具有共享内存和具有分布式内存的机器。

事实上，下一节着重讨论 MIMD 机器内存组织的最后一个方面。

# 内存组织

我们需要考虑的另一个方面是评估并行架构的内存组织，或者说，数据访问的方式。无论处理单元有多快，如果内存不能以足够的速度维护和提供指令和数据，那么性能就不会有所改善。

我们需要克服的主要问题是使内存的响应时间与处理器的速度兼容，这是内存周期时间，即两次连续操作之间经过的时间。处理器的周期时间通常比内存的周期时间短得多。

当处理器启动对内存的传输时，处理器的资源将在整个内存周期内保持占用；此外，在此期间，由于正在进行传输，没有其他设备（例如 I/O 控制器、处理器，甚至发出请求的处理器）能够使用内存：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-pll-prog-cb/img/d56ae362-cff1-4d47-97aa-78419437b2b7.png)

MIMD 架构中的内存组织

解决内存访问问题导致了 MIMD 架构的二分法。第一种系统称为*共享内存*系统，具有高虚拟内存，并且所有处理器都可以平等访问该内存中的数据和指令。另一种系统是***分布式内存***模型，其中每个处理器都有本地内存，其他处理器无法访问。

分布式内存共享的区别在于内存访问的管理，由处理单元执行；这一区别对程序员来说非常重要，因为它决定了并行程序的不同部分如何进行通信。

特别是，分布式内存机器必须在每个本地内存中制作共享数据的副本。这些副本是通过将包含要共享的数据的消息从一个处理器发送到另一个处理器来创建的。这种内存组织的一个缺点是，有时这些消息可能非常大并且需要相对长的时间来传输，而在共享内存系统中，没有消息交换，主要问题在于同步对共享资源的访问。

# 共享内存

共享内存多处理器系统的架构如下图所示。这里的物理连接非常简单。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-pll-prog-cb/img/0f53e868-04c0-4493-9b33-f9be28089ca2.png)

共享内存架构图

在这里，总线结构允许任意数量的设备（CPU +缓存在前面的图中）共享相同的通道（主内存，如前面的图所示）。总线协议最初是设计用于允许单个处理器和一个或多个磁盘或磁带控制器通过共享内存进行通信。

每个处理器都与缓存内存相关联，因为假定处理器需要在本地内存中具有数据或指令的概率非常高。

当一个处理器修改同时被其他处理器使用的存储在内存系统中的数据时，问题就会发生。新值将从已更改的处理器缓存传递到共享内存。然而，它还必须传递到所有其他处理器，以便它们不使用过时的值。这个问题被称为“缓存一致性”问题，是内存一致性问题的特例，需要硬件实现来处理并发问题和同步，类似于线程编程。

共享内存系统的主要特点如下：

+   所有处理器的内存都是相同的。例如，与相同数据结构相关联的所有处理器将使用相同的逻辑内存地址，从而访问相同的内存位置。

+   通过读取各个处理器的任务并允许共享内存来实现同步。实际上，处理器一次只能访问一个内存。

+   共享内存位置在另一个任务访问时不得被另一个任务更改。

+   任务之间共享数据很快。通信所需的时间是它们中的一个读取单个位置所需的时间（取决于内存访问速度）。

在共享内存系统中，内存访问如下：

+   统一内存访问（UMA）：该系统的基本特征是对内存的访问时间对于每个处理器和任何内存区域都是恒定的。因此，这些系统也被称为对称多处理器（SMP）。它们相对简单实现，但扩展性不强。编码人员负责通过在管理资源的程序中插入适当的控制、信号量、锁等来管理同步。

+   非统一内存访问（NUMA）：这些架构将内存分为分配给每个处理器的高速访问区域，以及用于数据交换的通用区域，访问速度较慢。这些系统也被称为分布式共享内存（DSM）系统。它们具有很强的可扩展性，但开发起来比较复杂。

+   无远程内存访问（NoRMA）：内存在处理器之间物理分布（本地内存）。所有本地内存都是私有的，只能访问本地处理器。处理器之间的通信是通过用于交换消息的通信协议进行的，这被称为消息传递协议。

+   **仅缓存内存架构**（**COMA**）：这些系统只配备了缓存内存。在分析 NUMA 架构时，注意到这种架构在缓存中保留了数据的本地副本，并且这些数据在主内存中存储为重复。这种架构去除了重复，并且只保留了缓存内存；内存在处理器之间物理分布（本地内存）。所有本地内存都是私有的，只能访问本地处理器。处理器之间的通信也是通过消息传递协议进行的。

# 分布式内存

在分布式内存系统中，每个处理器都与内存相关联，处理器只能访问自己的内存。一些作者将这种类型的系统称为多处理机，反映了系统的元素本身是处理器和内存的小而完整的系统，如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-pll-prog-cb/img/edbcb72a-7807-4dba-97da-a1e69af3c29d.png)

分布式内存架构模式

这种组织方式有几个优点：

+   在通信总线或交换机的级别没有冲突。每个处理器可以使用自己本地内存的全部带宽，而不受其他处理器的干扰。

+   没有共享总线意味着处理器数量没有固有限制。系统的大小仅受连接处理器的网络的限制。

+   缓存一致性没有问题。每个处理器负责自己的数据，不必担心升级任何副本。

主要的缺点是处理器之间的通信更难实现。如果一个处理器需要另一个处理器的内存中的数据，那么这两个处理器不一定需要通过消息传递协议交换消息。这引入了两种减速的来源：从一个处理器向另一个处理器构建和发送消息需要时间，而且任何处理器都必须停止以管理从其他处理器接收到的消息。设计为在分布式内存机器上运行的程序必须组织为一组通过消息进行通信的独立任务：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-pll-prog-cb/img/6174b7b7-c606-48e1-a585-3412e6d542c7.png)

基本消息传递

分布式内存系统的主要特点如下：

+   内存在处理器之间物理分布；每个本地内存只能被其处理器直接访问。

+   通过在处理器之间移动数据（即使只是消息本身）来实现同步（通信）。

+   本地内存中数据的细分会影响机器的性能——必须准确地进行细分，以最小化 CPU 之间的通信。除此之外，协调这些分解和组合操作的处理器必须有效地与操作数据结构各个部分的处理器进行通信。

+   使用消息传递协议，以便 CPU 可以通过交换数据包进行通信。消息是信息的离散单元，从这个意义上说，它们具有明确定义的身份，因此总是可以将它们与其他消息区分开来。

# 大规模并行处理（MPP）

MPP 机器由数百个处理器组成（在某些机器中可以达到数十万个处理器），它们通过通信网络连接。世界上最快的计算机基于这些架构；这些架构系统的一些例子是 Earth Simulator、Blue Gene、ASCI White、ASCI Red、ASCI Purple 和 Red Storm。

# 工作站集群

这些处理系统是基于通过通信网络连接的经典计算机。计算集群属于这一分类。

在集群架构中，我们将节点定义为参与集群的单个计算单元。对于用户来说，集群是完全透明的 - 所有的硬件和软件复杂性都被掩盖，数据和应用程序都可以像来自单个节点一样访问。

在这里，我们确定了三种类型的集群：

+   **故障转移集群**：在这种情况下，节点的活动会持续监控，当一个节点停止工作时，另一台机器会接管这些活动。其目的是通过架构的冗余性来确保连续的服务。

+   **负载平衡集群**：在这个系统中，作业请求被发送到活动较少的节点。这确保了处理作业所需的时间较短。

+   **高性能计算集群**：在这种情况下，每个节点都配置为提供极高的性能。该过程也被分成多个作业，并行化并分布到不同的机器上。

# 异构架构

在超级计算的同质世界中引入 GPU 加速器已经改变了超级计算机的使用和编程方式。尽管 GPU 提供了高性能，但它们不能被视为自主的处理单元，因为它们总是需要与 CPU 的组合一起使用。因此，编程范式非常简单：CPU 控制并以串行方式计算，将计算量非常大且具有高度并行性的任务分配给图形加速器。

CPU 和 GPU 之间的通信不仅可以通过高速总线进行，还可以通过共享单个内存区域进行，无论是物理内存还是虚拟内存。事实上，在两个设备都没有自己的内存区域的情况下，可以使用各种编程模型提供的软件库，如*CUDA*和*OpenCL*，来引用一个共同的内存区域。

这些架构被称为*异构架构*，应用程序可以在单个地址空间中创建数据结构，并将作业发送到适合解决任务的设备硬件。多个处理任务可以安全地在相同的区域内运行，以避免数据一致性问题，这要归功于原子操作。

因此，尽管 CPU 和 GPU 似乎不能有效地共同工作，但通过使用这种新架构，我们可以优化它们与并行应用程序的交互和性能：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-pll-prog-cb/img/46dac58e-d70e-4177-bc35-1018279093a9.png)

异构架构模式

在接下来的部分中，我们将介绍主要的并行编程模型。

# 并行编程模型

并行编程模型存在作为硬件和内存架构的抽象。事实上，这些模型并不具体，也不指代任何特定类型的机器或内存架构。它们可以（至少在理论上）在任何类型的机器上实现。与以前的细分相比，这些编程模型是在更高的层次上制定的，并代表了软件执行并行计算的方式。每个模型都有自己的方式与其他处理器共享信息，以便访问内存和分配工作。

绝对来说，没有一个模型比其他模型更好。因此，应用的最佳解决方案将在很大程度上取决于程序员需要解决和解决的问题。最广泛使用的并行编程模型如下：

+   共享内存模型

+   多线程模型

+   分布式内存/消息传递模型

+   数据并行模型

在这个配方中，我们将为您概述这些模型。

# 共享内存模型

在这个模型中，任务共享一个内存区域，我们可以异步读写。有一些机制允许编码人员控制对共享内存的访问；例如，锁或信号量。这个模型的优点是编码人员不必澄清任务之间的通信。在性能方面的一个重要缺点是，更难理解和管理数据局部性。这指的是保持数据局部于处理器上，以保留内存访问、缓存刷新和总线流量，当多个处理器使用相同数据时发生。

# 多线程模型

在这个模型中，一个进程可以有多个执行流。例如，首先创建一个顺序部分，然后创建一系列可以并行执行的任务。通常，这种类型的模型用于共享内存架构。因此，对我们来说，管理线程之间的同步将非常重要，因为它们在共享内存上运行，并且程序员必须防止多个线程同时更新相同的位置。

当前一代的 CPU 在软件和硬件上都是多线程的。**POSIX**（代表**可移植操作系统接口**）线程是软件上多线程实现的经典例子。英特尔的超线程技术通过在一个线程停滞或等待 I/O 时在两个线程之间切换来在硬件上实现多线程。即使数据对齐是非线性的，也可以从这个模型中实现并行性。

# 消息传递模型

消息传递模型通常应用于每个处理器都有自己的内存（分布式内存系统）的情况。更多的任务可以驻留在同一台物理机器上或任意数量的机器上。编码人员负责确定通过消息进行的并行性和数据交换，并且需要在代码中请求和调用函数库。

一些例子自 20 世纪 80 年代以来就存在，但直到 20 世纪 90 年代中期才创建了一个标准化的模型，导致了一种事实上的标准，称为**消息传递接口**（**MPI**）。

MPI 模型显然是设计用于分布式内存的，但作为并行编程模型，多平台模型也可以在共享内存机器上使用：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-pll-prog-cb/img/bd5deb5a-ea45-42d8-ba4e-b7852b6e0fcd.png)

消息传递范式模型

# 数据并行模型

在这个模型中，我们有更多的任务操作相同的数据结构，但每个任务操作不同部分的数据。在共享内存架构中，所有任务都可以通过共享内存访问数据，而在分布式内存架构中，数据结构被划分并驻留在每个任务的本地内存中。

为了实现这个模型，编码人员必须开发一个指定数据分布和对齐的程序；例如，当前一代的 GPU 只有在数据（**任务** **1**，**任务** **2**，**任务** **3**）对齐时才能高效运行，如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-pll-prog-cb/img/93cf041f-f65b-46e5-b36d-59d4ed537910.png)

数据并行范式模型

# 设计并行程序

利用并行性设计算法是基于一系列操作，必须执行这些操作才能使程序正确执行工作而不产生部分或错误的结果。必须执行的宏操作包括：

+   任务分解

+   任务分配

+   聚集

+   映射

# 任务分解

在这个第一阶段，软件程序被分割成任务或一组指令，然后可以在不同的处理器上执行以实现并行性。为了执行这种细分，使用了两种方法：

+   **域分解**：在这里，问题的数据被分解。应用程序对处理不同数据部分的所有处理器都是通用的。当我们有大量必须处理的数据时，使用这种方法。

+   **功能分解**：在这种情况下，问题被分解成任务，每个任务将对所有可用数据执行特定操作。

# 任务分配

在这一步中，指定了任务将在各个进程之间分配的机制。这个阶段非常重要，因为它确定了各个处理器之间的工作负载分配。在这里负载平衡至关重要；事实上，所有处理器必须连续工作，避免长时间处于空闲状态。

为了执行这一点，编码人员考虑了系统的可能异质性，试图将更多的任务分配给性能更好的处理器。最后，为了更有效地进行并行化，有必要尽量限制处理器之间的通信，因为它们通常是减速和资源消耗的来源。

# 聚合

聚合是将较小的任务与较大的任务组合以提高性能的过程。如果设计过程的前两个阶段将问题分割成远远超过可用处理器数量的任务，并且计算机没有专门设计来处理大量小任务（一些架构，如 GPU，可以很好地处理这一点，并且确实受益于运行数百万甚至数十亿的任务），那么设计可能会变得非常低效。

通常，这是因为任务必须被传输到处理器或线程，以便它们计算所述任务。大多数通信的成本与传输的数据量不成比例，但也会为每个通信操作产生固定成本（例如延迟，在建立 TCP 连接时固有的）。如果任务太小，那么这个固定成本很容易使设计变得低效。

# 映射

在并行算法设计过程的映射阶段，我们指定每个任务应在哪里执行。目标是最小化总执行时间。在这里，你经常需要做出权衡，因为两种主要策略经常相互冲突：

+   频繁通信的任务应放置在同一处理器上以增加局部性。

+   可以同时执行的任务应放置在不同的处理器中以增强并发性。

这被称为*映射问题*，已知为**NP 完全**。因此，在一般情况下，该问题没有多项式时间的解决方案。对于相同大小的任务和具有易于识别的通信模式的任务，映射是直接的（我们也可以在这里执行聚合，将映射到相同处理器的任务组合在一起）。然而，如果任务具有难以预测的通信模式或任务的工作量因任务而异，那么设计有效的映射和聚合方案就很困难。

对于这些类型的问题，可以使用负载平衡算法来识别运行时的聚合和映射策略。最困难的问题是在程序执行过程中通信量或任务数量发生变化的问题。对于这类问题，可以使用动态负载平衡算法，它们在执行过程中定期运行。

# 动态映射

存在许多负载平衡算法，适用于各种问题：

+   **全局算法**：这些需要对正在执行的计算进行全局了解，这通常会增加很多开销。

+   **局部算法**：这些仅依赖于与所讨论的任务相关的本地信息，与全局算法相比减少了开销，但通常在寻找最佳聚合和映射方面效果较差。

然而，减少的开销可能会减少执行时间，即使映射本身更糟。如果任务除了在执行开始和结束时很少通信，那么通常会使用任务调度算法，该算法简单地将任务映射到处理器，使它们变为空闲。在任务调度算法中，维护一个任务池。任务被放入此池中，并由工作者从中取出。

在这个模型中有三种常见的方法：

+   **管理者/工作者：**这是基本的动态映射方案，所有工作者都连接到一个集中的管理者。管理者反复向工作者发送任务并收集结果。这种策略可能是相对较少处理器的最佳选择。通过提前获取任务，可以改进基本策略，使通信和计算重叠。

+   **分层管理者/工作者：**这是管理者/工作者的变体，具有半分布式布局。工作者被分成组，每个组都有自己的管理者。这些组管理者与中央管理者通信（可能也相互通信），而工作者从组管理者请求任务。这样可以将负载分散到几个管理者中，并且如果所有工作者都从同一个管理者请求任务，则可以处理更多的处理器。

+   **去中心化：**在这种方案中，一切都是去中心化的。每个处理器维护自己的任务池，并与其他处理器通信以请求任务。处理器如何选择其他处理器来请求任务是不同的，并且是根据问题的基础确定的。

# 评估并行程序的性能

并行编程的发展产生了性能指标的需求，以便决定其使用是否方便。事实上，并行计算的重点是在相对较短的时间内解决大问题。为此目标做出贡献的因素包括所使用的硬件类型、问题的并行度以及采用的并行编程模型。为了方便起见，引入了基本概念的分析，比较了从原始序列获得的并行算法。

通过分析和量化使用的线程数量和/或进程数量来实现性能。为了分析这一点，让我们引入一些性能指标：

+   **加速**

+   **效率**

+   **扩展**

并行计算的限制由**阿姆达尔**定律引入。为了评估顺序算法并行化的效率程度，我们有**古斯塔夫森**定律。

# 加速

**加速**是显示以并行方式解决问题的好处的度量。它定义为在单个处理元素上解决问题所需的时间（*Ts*）与在*p*个相同处理元素上解决相同问题所需的时间（*Tp*）的比率。

我们将加速定义如下：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-pll-prog-cb/img/d06f79cc-0130-4c88-9669-be45342198b8.png)

我们有线性加速，如果 *S=p*，那么这意味着执行速度随处理器数量的增加而增加。当然，这是一个理想情况。虽然当*Ts*是最佳顺序算法的执行时间时，加速是绝对的，但当*Ts*是单处理器上并行算法的执行时间时，加速是相对的。

让我们总结一下这些条件：

+   *S = p* 是线性或理想加速。

+   *S < p* 是真实加速。

+   *S > p* 是超线性加速。

# 效率

在理想世界中，具有*p*个处理元素的并行系统可以给我们一个等于*p*的加速。然而，这很少实现。通常会在空闲或通信中浪费一些时间。效率是度量处理元素将多少执行时间用于执行有用工作的指标，以执行时间的一部分表示。

我们用 *E* 表示，并可以定义如下：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-pll-prog-cb/img/a51cb8a0-063e-4177-a8e3-caa123753d53.png)

具有线性加速的算法的值为*E = 1*。在其他情况下，它们的值小于*1*。这三种情况分别标识为：

+   当*E = 1*时，这是一个线性案例。

+   当*E < 1*时，这是一个真实案例。

+   当*E << 1*时，这是一个效率低下的可并行化问题。

# 扩展

扩展被定义为在并行机器上高效的能力。它确定了计算能力（执行速度）与处理器数量成比例。通过增加问题的规模和同时增加处理器的数量，性能不会有损失。

可扩展的系统，根据不同因素的增量，可以保持相同的效率或改善效率。

# Amdahl 定律

Amdahl 定律是一条广泛使用的定律，用于设计处理器和并行算法。它规定了可以实现的最大加速比受程序的串行部分限制：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-pll-prog-cb/img/d0ef21cb-ef7a-401d-990a-5a3b45325d05.png)

*1 - P*表示程序的串行部分（不并行化）。

这意味着，例如，如果一个程序中有 90%的代码可以并行执行，但 10%必须保持串行，则最大可实现的加速比为 9，即使有无限数量的处理器也是如此。

# Gustafson 定律

Gustafson 定律陈述如下：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-pll-prog-cb/img/5b33302b-8561-4073-a6df-09072923e8f5.png)

在这里，正如我们在方程中指出的那样：

+   *P*是*处理器数量*。

+   *S*是*加速*因子。

+   *α*是任何并行过程的*不可并行化部分*。

Gustafson 定律与 Amdahl 定律形成对比，后者假设程序的整体工作量不随处理器数量的变化而改变。

事实上，Gustafson 定律建议程序员首先设置解决问题的并行*时间*，然后基于（即时间）*调整*问题的大小。因此，*并行系统*越*快*，在相同时间内可以解决的*问题*就*越大*。

Gustafson 定律的影响是将计算机研究的目标引向以某种方式选择或重新制定问题，以便在相同的时间内仍然可以解决更大的问题。此外，该定律重新定义了*效率*的概念，即需要*至少减少程序的顺序部分*，尽管*工作量增加*。

# 介绍 Python

Python 是一种强大、动态和解释性的编程语言，广泛应用于各种应用程序。它的一些特点如下：

+   清晰易读的语法。

+   非常广泛的标准库，通过额外的软件模块，我们可以添加数据类型、函数和对象。

+   易学易用的快速开发和调试。使用 Python，在 Python 中开发代码可以比在 C/C++代码中快 10 倍。代码也可以作为原型工作，然后转换为 C/C++。

+   基于异常的错误处理。

+   强大的内省功能。

+   丰富的文档和软件社区。

Python 可以被视为一种粘合语言。使用 Python，可以开发更好的应用程序，因为不同类型的编码人员可以共同在一个项目上工作。例如，在构建科学应用程序时，C/C++程序员可以实现高效的数值算法，而在同一项目上的科学家可以编写测试和使用这些算法的 Python 程序。科学家不必学习低级编程语言，C/C++程序员也不需要理解所涉及的科学。

您可以从[`www.python.org/doc/essays/omg-darpa-mcc-position`](https://www.python.org/doc/essays/omg-darpa-mcc-position)了解更多信息。

让我们看一些非常基本的代码示例，以了解 Python 的特点。

以下部分对大多数人来说可能是复习内容。我们将在第二章 *基于线程的并行性*和第三章 *基于进程的并行性*中实际使用这些技术。

# 帮助函数

Python 解释器已经提供了有效的帮助系统。如果要了解如何使用对象，只需键入`help(object)`。

例如，让我们看看如何在整数`0`上使用`help`函数：

```py
>>> help(0)
Help on int object:

class int(object)
 | int(x=0) -> integer
 | int(x, base=10) -> integer
 | 
 | Convert a number or string to an integer, or return 0 if no 
 | arguments are given. If x is a number, return x.__int__(). For 
 | floating point numbers, this truncates towards zero.
 | 
 | If x is not a number or if base is given, then x must be a string,
 | bytes, or bytearray instance representing an integer literal in the
 | given base. The literal can be preceded by '+' or '-' and be
 | surrounded by whitespace. The base defaults to 10\. Valid bases are 0 
 | and 2-36.
 | Base 0 means to interpret the base from the string as an integer 
 | literal.
>>> int('0b100', base=0)
```

`int`对象的描述后面是适用于它的方法列表。前五个方法如下：

```py
 | Methods defined here:
 | 
 | __abs__(self, /)
 | abs(self)
 | 
 | __add__(self, value, /)
 | Return self+value.
 | 
 | __and__(self, value, /)
 | Return self&value.
 | 
 | __bool__(self, /)
 | self != 0
 | 
 | __ceil__(...)
 | Ceiling of an Integral returns itself.
```

`dir(object)`也很有用，它列出了对象可用的方法：

```py
>>> dir(float)
['__abs__', '__add__', '__and__', '__bool__', '__ceil__', '__class__', '__delattr__', '__dir__', '__divmod__', '__doc__', '__eq__', '__float__', '__floor__', '__floordiv__', '__format__', '__ge__', '__getattribute__', '__getnewargs__', '__gt__', '__hash__', '__index__', '__init__', '__int__', '__invert__', '__le__', '__lshift__', '__lt__', '__mod__', '__mul__', '__ne__', '__neg__', '__new__', '__or__', '__pos__', '__pow__', '__radd__', '__rand__', '__rdivmod__', '__reduce__', '__reduce_ex__', '__repr__', '__rfloordiv__', '__rlshift__', '__rmod__', '__rmul__', '__ror__', '__round__', '__rpow__', '__rrshift__', '__rshift__', '__rsub__', '__rtruediv__', '__rxor__', '__setattr__', '__sizeof__', '__str__', '__sub__', '__subclasshook__', '__truediv__', '__trunc__', '__xor__', 'bit_length', 'conjugate', 'denominator', 'from_bytes', 'imag', 'numerator', 'real', 'to_bytes']
```

最后，对象的相关文档由`.__doc__`函数提供，如下例所示：

```py
>>> abs.__doc__
'Return the absolute value of the argument.'
```

# 语法

Python 不采用语句终止符，并且代码块通过缩进指定。期望缩进级别的语句必须以冒号（`:`）结尾。这导致以下结果：

+   Python 代码更清晰、更易读。

+   程序结构始终与缩进的结构相一致。

+   缩进风格在任何列表中都是统一的。

错误的缩进可能导致错误。

以下示例显示如何使用`if`结构：

```py
print("first print")
if condition:
 print(“second print”)
print(“third print”)
```

在这个例子中，我们可以看到以下内容：

+   以下语句：`print("first print")`，`if condition:`，`print("third print")`具有相同的缩进级别，并且始终被执行。

+   在`if`语句之后，有一个缩进级别更高的代码块，其中包括`print ("second print")`语句。

+   如果`if`的条件为真，则执行`print ("second print")`语句。

+   如果`if`的条件为假，则不执行`print ("second print")`语句。

因此，非常重要的是要注意缩进，因为它始终在程序解析过程中进行评估。

# 注释

注释以井号（`#`）开头，位于单独一行上：

```py
# single line comment
```

多行字符串用于多行注释：

```py
""" first line of a multi-line comment
second line of a multi-line comment."""
```

# 赋值

赋值使用等号（`=`）进行。对于相等性测试，使用相同数量的（`==`）。您可以使用`+=`和`-=`运算符增加和减少值，后跟一个附录。这适用于许多类型的数据，包括字符串。您可以在同一行上分配和使用多个变量。

一些示例如下：

```py
>>> variable = 3
>>> variable += 2
>>> variable
5
>>> variable -= 1
>>> variable
4

>>> _string_ = "Hello"
>>> _string_ += " Parallel Programming CookBook Second Edition!"
>>> print (_string_) 
Hello Parallel Programming CookBook Second Edition!
```

# 数据类型

Python 中最重要的结构是*列表*、*元组*和*字典*。自 Python 2.5 版本以来，集合已经集成到 Python 中（之前的版本可在`sets`库中找到）：

+   **列表**：这些类似于一维数组，但您可以创建包含其他列表的列表。

+   **字典**：这些是包含键对和值（哈希表）的数组。

+   **元组**：这些是不可变的单维对象。

数组可以是任何类型，因此可以将诸如整数和字符串之类的变量混合到列表、字典和元组中。

任何类型的数组中第一个对象的索引始终为零。允许负索引，并且从数组末尾计数；`-1`表示数组的最后一个元素：

```py
#let's play with lists
list_1 = [1, ["item_1", "item_1"], ("a", "tuple")]
list_2 = ["item_1", -10000, 5.01]

>>> list_1
[1, ['item_1', 'item_1'], ('a', 'tuple')]

>>> list_2
['item_1', -10000, 5.01]

>>> list_1[2]
('a', 'tuple')

>>>list_1[1][0]
['item_1', 'item_1']

>>> list_2[0]
item_1

>>> list_2[-1]
5.01

#build a dictionary 
dictionary = {"Key 1": "item A", "Key 2": "item B", 3: 1000}
>>> dictionary 
{'Key 1': 'item A', 'Key 2': 'item B', 3: 1000} 

>>> dictionary["Key 1"] 
item A

>>> dictionary["Key 2"]
-1

>>> dictionary[3]
1000
```

您可以使用冒号（`:`）获取数组范围：

```py
list_3 = ["Hello", "Ruvika", "how" , "are" , "you?"] 
>>> list_3[0:6] 
['Hello', 'Ruvika', 'how', 'are', 'you?'] 

>>> list_3[0:1]
['Hello']

>>> list_3[2:6]
['how', 'are', 'you?']
```

# 字符串

Python 字符串使用单引号（`'`）或双引号（`"`）标示，并且允许在字符串中使用另一种标示：

```py
>>> example = "she loves ' giancarlo"
>>> example
"she loves ' giancarlo"
```

在多行上，它们用三个（或三个单）引号括起来（`'''`多行字符串`'''`）：

```py
>>> _string_='''I am a 
multi-line 
string'''
>>> _string_
'I am a \nmulti-line\nstring'
```

Python 还支持 Unicode；只需使用`u "This is a unicode string"`语法：

```py
>>> ustring = u"I am unicode string"
>>> ustring
'I am unicode string'
```

要在字符串中输入值，请键入`%`运算符和一个元组。然后，每个`%`运算符将从左到右替换为元组元素*：*

```py
>>> print ("My name is %s !" % ('Mr. Wolf'))
My name is Mr. Wolf!
```

# 流程控制

流程控制指令是`if`、`for`和`while`。

在下一个示例中，我们检查数字是正数、负数还是零，并显示结果：

```py
num = 1

if num > 0:
 print("Positive number")
elif num == 0:
 print("Zero")
else:
 print("Negative number")
```

以下代码块使用`for`循环找到存储在列表中的所有数字的总和：

```py
numbers = [6, 6, 3, 8, -3, 2, 5, 44, 12]
sum = 0
for val in numbers:
 sum = sum+val
print("The sum is", sum)
```

我们将执行`while`循环来迭代代码，直到条件结果为真。我们将使用这个循环来代替`for`循环，因为我们不知道会导致代码的迭代次数。在这个例子中，我们使用`while`来添加自然数，直到*sum = 1+2+3+...+n*：

```py
n = 10
# initialize sum and counter
sum = 0
i = 1
while i <= n:
 sum = sum + i
 i = i+1 # update counter

# print the sum
print("The sum is", sum)
```

前三个示例的输出如下：

```py
Positive number
The sum is 83
The sum is 55
>>>
```

# 函数

Python 函数使用`def`关键字声明：

```py
def my_function():
 print("this is a function")
```

要运行一个函数，使用函数名，后跟括号，如下所示：

```py
>>> my_function()
this is a function
```

参数必须在函数名后面的括号内指定：

```py
def my_function(x):
 print(x * 1234)

>>> my_function(7)
8638
```

多个参数必须用逗号分隔：

```py
def my_function(x,y):
 print(x*5+ 2*y)

>>> my_function(7,9)
53
```

使用等号来定义默认参数。如果没有参数调用函数，则将使用默认值：

```py
def my_function(x,y=10):
 print(x*5+ 2*y)

>>> my_function(1)
25

>>> my_function(1,100)
205
```

函数的参数可以是任何类型的数据（如字符串、数字、列表和字典）。在这里，以下列表`lcities`被用作`my_function`的参数：

```py
def my_function(cities):
 for x in cities:
 print(x)

>>> lcities=["Napoli","Mumbai","Amsterdam"]
>>> my_function(lcities)
Napoli
Mumbai
Amsterdam
```

使用`return`语句从函数中返回一个值：

```py
def my_function(x,y):
 return x*y >>> my_function(6,29)  174 
```

Python 支持一种有趣的语法，允许您在需要定义小型单行函数的地方定义它们。这些 lambda 函数源自 Lisp 编程语言。

lambda 函数的一个示例，`functionvar`，如下所示：

```py
# lambda definition equivalent to def f(x): return x + 1

functionvar = lambda x: x * 5
>>> print(functionvar(10))
50
```

# 类

Python 支持类的多重继承。按照惯例（而不是语言规则），私有变量和方法以两个下划线（`__`）开头声明。我们可以给类的实例分配任意属性（属性），如下例所示：

```py
class FirstClass:
 common_value = 10
 def __init__ (self):
 self.my_value = 100
 def my_func (self, arg1, arg2):
 return self.my_value*arg1*arg2

# Build a first instance
>>> first_instance = FirstClass()
>>> first_instance.my_func(1, 2)
200

# Build a second instance of FirstClass
>>> second_instance = FirstClass()

#check the common values for both the instances
>>> first_instance.common_value
10

>>> second_instance.common_value
10

#Change common_value for the first_instance
>>> first_instance.common_value = 1500
>>> first_instance.common_value
1500

#As you can note the common_value for second_instance is not changed
>>> second_instance.common_value
10

# SecondClass inherits from FirstClass. 
# multiple inheritance is declared as follows:
# class SecondClass (FirstClass1, FirstClass2, FirstClassN)

class SecondClass (FirstClass):
 # The "self" argument is passed automatically
 # and refers to the class's instance
 def __init__ (self, arg1):
 self.my_value = 764
 print (arg1)

>>> first_instance = SecondClass ("hello PACKT!!!!")
hello PACKT!!!!

>>> first_instance.my_func (1, 2)
1528
```

# 异常

Python 中的异常使用`try-except`块（`exception_name`）进行管理：

```py
def one_function():
 try:
 # Division by zero causes one exception
 10/0
 except ZeroDivisionError:
 print("Oops, error.")
 else:
 # There was no exception, we can continue.
 pass
 finally:
 # This code is executed when the block
 # try..except is already executed and all exceptions
 # have been managed, even if a new one occurs
 # exception directly in the block.
 print("We finished.")

>>> one_function()
Oops, error.
We finished
```

# 导入库

外部库使用`import [library name]`导入。或者，您可以使用`from [library name] import [function name]`语法导入特定函数。这是一个例子：

```py
import random
randomint = random.randint(1, 101)

>>> print(randomint)
65

from random import randint
randomint = random.randint(1, 102)

>>> print(randomint)
46
```

# 管理文件

为了让我们能够与文件系统交互，Python 提供了内置的`open`函数。可以调用此函数来打开文件并返回一个文件对象。后者允许我们对文件执行各种操作，如读取和写入。当我们完成与文件的交互时，最后必须记得使用`file.close`方法关闭它：

```py
>>> f = open ('test.txt', 'w') # open the file for writing
>>> f.write ('first line of file \ n') # write a line in file
>>> f.write ('second line of file \ n') # write another line in file
>>> f.close () # we close the file
>>> f = open ('test.txt') # reopen the file for reading
>>> content = f.read () # read all the contents of the file
>>> print (content)
first line of the file
second line of the file
>>> f.close () # close the file
```

# 列表推导

列表推导是创建和操作列表的强大工具。它们由一个表达式后跟一个`for`子句，然后后跟零个或多个`if`子句。列表推导的语法非常简单：

```py
[expression for item in list]
```

然后，执行以下操作：

```py
#list comprehensions using strings
>>> list_comprehension_1 = [ x for x in 'python parallel programming cookbook!' ]
>>> print( list_comprehension_1)

['p', 'y', 't', 'h', 'o', 'n', ' ', 'p', 'a', 'r', 'a', 'l', 'l', 'e', 'l', ' ', 'p', 'r', 'o', 'g', 'r', 'a', 'm', 'm', 'i', 'n', 'g', ' ', 'c', 'o', 'o', 'k', 'b', 'o', 'o', 'k', '!']

#list comprehensions using numbers
>>> l1 = [1,2,3,4,5,6,7,8,9,10]
>>> list_comprehension_2 = [ x*10 for x in l1 ]
>>> print( list_comprehension_2)

[10, 20, 30, 40, 50, 60, 70, 80, 90, 100]
```

# 运行 Python 脚本

要执行 Python 脚本，只需调用 Python 解释器，然后是脚本名称，即`my_pythonscript.py`。或者，如果我们在不同的工作目录中，则使用其完整地址：

```py
> python my_pythonscript.py 
```

从现在开始，对于每次调用 Python 脚本，我们将使用前面的表示法；即`python`，后跟`script_name.py`，假设启动 Python 解释器的目录是脚本所在的目录。

# 使用 pip 安装 Python 包

`pip`是一个工具，允许我们搜索、下载和安装 Python 包，这些包可以在 Python 包索引中找到，该索引是一个包含数以万计用 Python 编写的包的存储库。这也允许我们管理已经下载的包，允许我们更新或删除它们。

# 安装 pip

`pip`已经包含在 Python 版本≥3.4 和≥2.7.9 中。要检查是否已经安装了这个工具，我们可以运行以下命令：

```py
C:\>pip
```

如果`pip`已经安装，则此命令将显示已安装的版本。

# 更新 pip

还建议检查您使用的`pip`版本是否始终保持最新。要更新它，我们可以使用以下命令：

```py
 C:\>pip install -U pip
```

# 使用 pip

`pip`支持一系列命令，允许我们*搜索、下载、安装、更新*和*删除*软件包，等等。

要安装`PACKAGE`，只需运行以下命令：

```py
C:\>pip install PACKAGE 
```

# 介绍 Python 并行编程

Python 提供了许多库和框架，可以促进高性能计算。但是由于**全局解释器锁**（**GIL**），使用 Python 进行并行编程可能会非常隐匿。

事实上，最广泛和广泛使用的 Python 解释器**CPython**是用 C 编程语言开发的。 CPython 解释器需要 GIL 来进行线程安全操作。使用 GIL 意味着当您尝试访问线程中包含的任何 Python 对象时，您将遇到全局锁。一次只有一个线程可以获取 Python 对象或 C API 的锁。

幸运的是，情况并不那么严重，因为在 GIL 的领域之外，我们可以自由地使用并行性。这包括我们将在接下来的章节中讨论的所有主题，包括多进程、分布式计算和 GPU 计算。

因此，Python 实际上并不是多线程的。但是什么是线程？什么是进程？在接下来的章节中，我们将介绍这两个基本概念以及 Python 编程语言如何处理它们。

# 进程和线程

*线程*可以与轻量级进程进行比较，因为它们提供了类似进程的优势，但是不需要进程的典型通信技术。线程允许将程序的主控制流分成多个并发运行的控制流。相比之下，进程有它们自己的*地址空间*和自己的资源。这意味着在不同进程上运行的代码部分之间的通信只能通过适当的管理机制进行，包括管道、代码 FIFO、邮箱、共享内存区域和消息传递。另一方面，线程允许创建程序的并发部分，其中每个部分都可以访问相同的地址空间、变量和常量。

以下表格总结了线程和进程之间的主要区别：

| **线程** | **进程** |
| --- | --- |
| 共享内存。 | 不共享内存。 |
| 启动/更改 计算成本较低。 | 启动/更改 计算成本较高。 |
| 需要更少的资源（轻量级进程）。 | 需要更多的计算资源。 |
| 需要同步机制来正确处理数据。 | 不需要内存同步。 |

在这个简短的介绍之后，我们终于可以展示进程和线程是如何运行的。

特别是，我们想比较以下函数`do_something`的串行、多线程和多进程执行时间，该函数执行一些基本计算，包括随机选择整数的列表（一个`do_something.py`文件）：

```py
import random

def do_something(count, out_list):
 for i in range(count):
 out_list.append(random.random())
```

接下来是串行（`serial_test.py`）实现。让我们从相关的导入开始：

```py
from do_something import *
import time 
```

请注意导入时间模块，该模块将用于评估执行时间，在本例中，以及`do_something`函数的串行实现。要构建的列表的`size`等于`10000000`，而`do_something`函数将执行`10`次：

```py
if __name__ == "__main__":
 start_time = time.time()
 size = 10000000 
 n_exec = 10
 for i in range(0, exec):
 out_list = list()
 do_something(size, out_list)

 print ("List processing complete.")
 end_time = time.time()
 print("serial time=", end_time - start_time) 
```

接下来，我们有多线程实现（`multithreading_test.py`）。

导入相关库：

```py
from do_something import *
import time
import threading
```

请注意导入`threading`模块，以便使用 Python 的多线程功能。

在这里，有`do_something`函数的多线程执行。我们不会对以下代码中的指令进行深入评论，因为它们将在第二章中更详细地讨论，*基于线程的并行性*。

然而，在这种情况下，也应该注意到，列表的长度显然与串行情况下的长度相同，`size = 10000000`，而定义的线程数为 10，`threads = 10`，这也是必须执行`do_something`函数的次数：

```py
if __name__ == "__main__":
 start_time = time.time()
 size = 10000000
 threads = 10 
 jobs = []
 for i in range(0, threads):
```

还要注意通过`threading.Thread`方法构建单个线程：

```py
out_list = list()
thread = threading.Thread(target=list_append(size,out_list))
jobs.append(thread)
```

我们开始执行线程然后立即停止它们的循环顺序如下：

```py
 for j in jobs:
 j.start()
 for j in jobs:
 j.join()

 print ("List processing complete.")
 end_time = time.time()
 print("multithreading time=", end_time - start_time)
```

最后，有多进程实现（`multiprocessing_test.py`）。

我们首先导入必要的模块，特别是`multiprocessing`库，其特性将在第三章中深入解释，*基于进程的并行*：

```py
from do_something import *
import time
import multiprocessing
```

与先前情况一样，要构建的列表长度，大小和`do_something`函数的执行次数保持不变（`procs = 10`）：

```py
if __name__ == "__main__":
 start_time = time.time()
 size = 10000000 
 procs = 10 
 jobs = []
 for i in range(0, procs):
 out_list = list()
```

在这里，通过`multiprocessing.Process`方法调用单个进程的实现受到如下影响：

```py
 process = multiprocessing.Process\
 (target=do_something,args=(size,out_list))
 jobs.append(process)
```

接下来，我们开始执行进程然后立即停止它们的循环顺序如下执行：

```py
 for j in jobs:
 j.start()

 for j in jobs:
 j.join()

 print ("List processing complete.")
 end_time = time.time()
 print("multiprocesses time=", end_time - start_time)
```

然后，我们打开命令行并运行先前描述的三个函数。

转到已复制函数的文件夹，然后输入以下内容：

```py
> python serial_test.py
```

结果是在具有以下特征的机器上获得的 - CPU Intel i7 / 8 GB RAM，如下所示：

```py
List processing complete.
serial time= 25.428767204284668
```

在`multithreading`实现的情况下，我们有以下情况：

```py
> python multithreading_test.py
```

输出如下：

```py
List processing complete.
multithreading time= 26.168917179107666
```

最后，有**多进程**实现：

```py
> python multiprocessing_test.py
```

其结果如下：

```py
List processing complete.
multiprocesses time= 18.929869890213013
```

可以看到，串行实现的结果（即使用`serial_test.py`）与使用多线程实现的结果类似（使用`multithreading_test.py`），在这种情况下，线程基本上是一个接一个地启动，优先考虑一个而不是另一个，直到结束，而使用 Python 多进程能力在执行时间方面有益（使用`multiprocessing_test.py`）。


# 第二章：基于线程的并行性

目前，在软件应用程序中管理并发的最广泛使用的编程范式是基于多线程的。通常，一个应用程序由一个被分成多个独立线程的单一进程组成，这些线程代表不同类型的活动，以并行方式运行并相互竞争。

如今，使用多线程的现代应用程序已经被大规模采用。事实上，所有当前的处理器都是多核的，这样它们可以执行并行操作并利用计算机的计算资源。

因此，*多线程编程*绝对是实现并发应用程序的一种好方法。然而，多线程编程经常隐藏一些非常规的困难，必须适当地管理以避免出现死锁或同步问题等错误。

我们将首先定义基于线程和多线程编程的概念，然后介绍`multithreading`库。我们将学习关于线程定义、管理和通信的主要指令。

通过`multithreading`库，我们将看到如何通过不同的技术解决问题，例如*锁*、*RLock*、*信号量*、*条件*、*事件*、*屏障*和*队列*。

在本章中，我们将涵盖以下内容：

+   什么是线程？

+   如何定义线程

+   如何确定当前线程

+   如何在子类中使用线程

+   使用锁进行线程同步

+   使用 RLock 进行线程同步

+   使用信号量进行线程同步

+   使用条件进行线程同步

+   使用事件进行线程同步

+   使用屏障进行线程同步

+   使用队列进行线程通信

我们还将探讨 Python 提供的主要线程编程选项。为此，我们将专注于使用`threading`模块。

# 什么是线程？

*线程*是一个独立的执行流，可以与系统中的其他线程并行和并发执行。

多个线程可以共享数据和资源，利用所谓的共享信息空间。线程和进程的具体实现取决于您计划运行应用程序的操作系统，但是一般来说，可以说线程包含在进程内，并且同一进程中的不同线程条件共享一些资源。相比之下，不同进程不与其他进程共享自己的资源。

线程由三个元素组成：程序计数器、寄存器和堆栈。与同一进程的其他线程共享的资源主要包括*数据*和*操作系统资源*。此外，线程有自己的执行状态，即*线程状态*，并且可以与其他线程*同步*。

线程状态可以是就绪、运行或阻塞：

+   当线程被创建时，它进入**就绪**状态。

+   线程由操作系统（或运行时支持系统）安排执行，当轮到它执行时，它通过进入**运行**状态开始执行。

+   线程可以等待条件发生，从**运行**状态转换到**阻塞**状态。一旦锁定条件终止，**阻塞**线程返回到**就绪**状态：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-pll-prog-cb/img/1c9d8391-719e-4277-a1ae-dd4155345659.png)

线程生命周期

多线程编程的主要优势在于性能，因为进程之间的上下文切换比属于同一进程的线程之间的上下文切换要重得多。

在接下来的食谱中，直到本章结束，我们将通过编程示例来研究 Python 的`threading`模块，介绍其主要功能。

# Python 线程模块

Python 使用 Python 标准库提供的`threading`模块来管理线程。该模块提供了一些非常有趣的功能，使基于线程的方法变得更加容易；事实上，`threading`模块提供了几种非常简单实现的同步机制。

`threading`模块的主要组件如下：

+   `thread`对象

+   `lock`对象

+   `RLock`对象

+   `semaphore`对象

+   `condition`对象

+   `event`对象

在接下来的示例中，我们将使用`threading`库提供的功能来检查不同应用示例。对于接下来的示例，我们将参考 Python 3.5.0 发行版([`www.python.org/downloads/release/python-350/`](https://www.python.org/downloads/release/python-350/))。

# 定义线程

使用线程的最简单方法是使用目标函数实例化它，然后调用`start`方法让它开始工作。

# 准备工作

Python `threading`模块提供了一个`Thread`类，用于在不同的线程中运行进程和函数：

```py
class threading.Thread(group=None, 
                       target=None, 
                       name=None, 
                       args=(), 
                       kwargs={}) 
```

以下是`Thread`类的参数：

+   `group`：这是`group`值，应为`None`；这是为将来的实现保留的。

+   `target`：这是启动线程活动时要执行的函数。

+   `name`：这是线程的名称；默认情况下，它被分配一个形式为`Thread-N`的唯一名称。

+   `args`：这是要传递给目标的参数元组。

+   `kwargs`：这是要用于`target`函数的关键字参数字典。

在下一节中，让我们了解如何定义线程。

# 如何做...

我们将通过传递一个数字来定义一个线程，该数字表示线程编号，最后将打印出结果：

1.  通过以下 Python 命令导入`threading`模块：

```py
import threading
```

1.  在`main`程序中，使用`target`函数`my_func`实例化了一个`Thread`对象。然后，传递给函数的参数将包含在输出消息中：

```py
t = threading.Thread(target=function , args=(i,))
```

1.  线程在调用`start`方法之前不会开始运行，而`join`方法使调用线程等待，直到线程完成执行，如下所示：

```py
import threading

def my_func(thread_number):
 return print('my_func called by thread N°\
 {}'.format(thread_number))

def main():
 threads = []
 for i in range(10):
 t = threading.Thread(target=my_func, args=(i,))
 threads.append(t)
 t.start()
 t.join()

if __name__ == "__main__":
 main()
```

# 它是如何工作的...

在`main`程序中，我们初始化线程列表，将每个创建的线程实例添加到其中。创建的线程总数为 10，而第 i 个线程的**i**索引作为参数传递给第 i 个线程：

```py
my_func called by thread N°0
my_func called by thread N°1
my_func called by thread N°2
my_func called by thread N°3
my_func called by thread N°4
my_func called by thread N°5
my_func called by thread N°6
my_func called by thread N°7
my_func called by thread N°8
my_func called by thread N°9
```

# 还有更多...

所有当前处理器都是多核的，因此可以执行多个并行操作，并充分利用计算机的计算资源。尽管如此，多线程编程隐藏了许多非平凡的困难，必须适当地管理，以避免死锁或同步问题等错误。

# 确定当前线程

使用参数来标识或命名线程是繁琐且不必要的。每个`Thread`实例都有一个默认值的*name*，可以在创建线程时更改。

在线程名对于处理不同操作的多个服务线程的服务器进程中是有用的。

# 准备工作

这个`threading`模块提供了`currentThread().getName()`方法，返回当前线程的名称。

下一节将学习如何使用此函数来确定正在运行的线程。

# 如何做...

让我们看看以下步骤：

1.  要确定正在运行的线程，我们创建了三个`target`函数，并导入`time`模块以引入暂停执行两秒：

```py
import threading
import time

def function_A():
 print (threading.currentThread().getName()+str('-->\
 starting \n'))
 time.sleep(2)
 print (threading.currentThread().getName()+str( '-->\
 exiting \n'))

def function_B():
 print (threading.currentThread().getName()+str('-->\
 starting \n'))
 time.sleep(2)
 print (threading.currentThread().getName()+str( '-->\
 exiting \n'))

def function_C():
 print (threading.currentThread().getName()+str('-->\
 starting \n'))
 time.sleep(2)
 print (threading.currentThread().getName()+str( '-->\
 exiting \n'))

```

1.  三个线程使用`target`函数实例化。然后，我们传递要打印的名称，如果未定义，则将使用默认名称。然后，为每个线程调用`start()`和`join()`方法：

```py
if __name__ == "__main__":

 t1 = threading.Thread(name='function_A', target=function_A)
 t2 = threading.Thread(name='function_B', target=function_B)
 t3 = threading.Thread(name='function_C',target=function_C) 

 t1.start()
 t2.start()
 t3.start()

 t1.join()
 t2.join()
 t3.join()
```

# 它是如何工作的...

我们将设置三个线程，每个线程都分配了一个`target`函数。当执行并终止`target`函数时，将适当地打印出函数名。

对于这个例子，输出应该如下（即使显示的顺序可能不同）：

```py
function_A--> starting 
function_B--> starting 
function_C--> starting 

function_A--> exiting 
function_B--> exiting 
function_C--> exiting
```

# 定义一个线程子类

创建线程可能需要定义一个从`Thread`类继承的子类。后者，如*定义一个线程*部分所述，包含在`threading`模块中，必须导入。

# 准备工作

我们将在下一节中定义的类代表我们的线程，遵循一个明确的结构：我们首先必须定义**`__init__`**方法，但最重要的是，我们必须重写`run`方法。

# 如何做...

涉及的步骤如下：

1.  我们定义了`MyThreadClass`类，可以用它来创建所有想要的线程。这种类型的每个线程将以`run`方法中定义的操作为特征，在这个简单的例子中，`run`方法限制于在执行开始和结束时打印一个字符串：

```py
import time
import os
from random import randint
from threading import Thread

class MyThreadClass (Thread):
```

1.  此外，在`__init__`方法中，我们指定了两个初始化参数，分别是`name`和`duration`，它们将在`run`方法中使用：

```py
def __init__(self, name, duration):
 Thread.__init__(self)
 self.name = name
 self.duration = duration 

 def run(self):
 print ("---> " + self.name +\
 " running, belonging to process ID "\
 + str(os.getpid()) + "\n")
 time.sleep(self.duration)
 print ("---> " + self.name + " over\n")
```

1.  然后在创建线程时设置这些参数。特别是，`duration`参数是使用`randint`函数计算的，该函数输出 1 到 10 之间的随机整数。从`MyThreadClass`的定义开始，让我们看看如何实例化更多的线程，如下所示：

```py
def main():

 start_time = time.time()

 # Thread Creation
 thread1 = MyThreadClass("Thread#1 ", randint(1,10))
 thread2 = MyThreadClass("Thread#2 ", randint(1,10))
 thread3 = MyThreadClass("Thread#3 ", randint(1,10))
 thread4 = MyThreadClass("Thread#4 ", randint(1,10))
 thread5 = MyThreadClass("Thread#5 ", randint(1,10))
 thread6 = MyThreadClass("Thread#6 ", randint(1,10))
 thread7 = MyThreadClass("Thread#7 ", randint(1,10))
 thread8 = MyThreadClass("Thread#8 ", randint(1,10)) 
 thread9 = MyThreadClass("Thread#9 ", randint(1,10))

 # Thread Running
 thread1.start()
 thread2.start()
 thread3.start()
 thread4.start()
 thread5.start()
 thread6.start()
 thread7.start()
 thread8.start()
 thread9.start()

 # Thread joining
 thread1.join()
 thread2.join()
 thread3.join()
 thread4.join()
 thread5.join()
 thread6.join()
 thread7.join()
 thread8.join()
 thread9.join()

 # End 
 print("End")

 #Execution Time
 print("--- %s seconds ---" % (time.time() - start_time))

if __name__ == "__main__":
 main()
```

# 工作原理...

在这个例子中，我们创建了九个线程，每个线程都有自己的`name`和`duration`属性，根据`__init__`方法的定义。

然后使用`start`方法运行它们，该方法仅限于执行先前定义的`run`方法的内容。请注意，每个线程的进程 ID 相同，这意味着我们处于多线程进程中。

另外，注意`start`方法*不是阻塞的*：当它被执行时，控制立即转移到下一行，而线程在后台启动。实际上，正如你所看到的，线程的创建*不是*按照代码指定的顺序进行的。同样，线程终止受`duration`参数的约束，使用`randint`函数进行评估，并通过参数传递给每个线程创建实例。要等待线程完成，必须执行`join`操作。

输出如下：

```py
---> Thread#1 running, belonging to process ID 13084
---> Thread#5 running, belonging to process ID 13084
---> Thread#2 running, belonging to process ID 13084
---> Thread#6 running, belonging to process ID 13084
---> Thread#7 running, belonging to process ID 13084
---> Thread#3 running, belonging to process ID 13084
---> Thread#4 running, belonging to process ID 13084
---> Thread#8 running, belonging to process ID 13084
---> Thread#9 running, belonging to process ID 13084

---> Thread#6 over
---> Thread#9 over
---> Thread#5 over
---> Thread#2 over
---> Thread#7 over
---> Thread#4 over
---> Thread#3 over
---> Thread#8 over
---> Thread#1 over

End

--- 9.117518663406372 seconds ---
```

# 还有更多...

与 OOP 最常关联的特性是*继承*，它是定义新类作为已经存在的类的修改版本的能力。继承的主要优势是可以向类添加新方法，而无需更改原始定义。

原始类通常被称为父类和派生类，子类。继承是一个强大的特性，一些程序可以更轻松、更简洁地编写，提供了在不修改原始类的情况下定制类行为的可能性。继承结构可以反映问题的结构，有时可以使程序更容易理解。

然而（提醒用户注意！），继承可能会使程序更难阅读。这是因为在调用方法时，不清楚该方法在代码中的哪里定义，必须在多个模块中进行跟踪，而不是在一个单一明确定义的地方。

许多继承可以做的事情通常即使没有继承也可以优雅地处理，因此只有在问题的结构需要时才适合使用继承。如果在错误的时间使用，继承可能造成的危害可能会超过使用它的好处。

# 使用锁进行线程同步

`threading`模块还包括了一个简单的锁机制，允许我们在线程之间实现同步。

# 准备工作

*锁*只不过是一个通常可以被多个线程访问的对象，线程在执行受保护的程序部分之前必须拥有该对象。这些锁是通过在`threading`模块中定义的`Lock()`方法来创建的。

一旦锁被创建，我们可以使用两种方法来同步执行两个（或更多）线程：`acquire()` 方法用于获取锁控制，`release()` 方法用于释放锁。

`acquire()`方法接受一个可选参数，如果未指定或设置为`True`，则强制线程暂停执行，直到锁被释放并可以获取。另一方面，如果使用参数等于`False`执行`acquire()`方法，则立即返回一个布尔结果，如果锁已被获取，则为`True`，否则为`False`。

在下面的示例中，我们通过修改上一个示例*定义线程子类*中引入的代码来展示锁机制。

# 如何做到这一点...

涉及的步骤如下：

1.  如下面的代码块所示，`MyThreadClass`类已经被修改，在**`run`**方法中引入了`acquire()`和`release()`方法，而`Lock()`的定义在类本身的定义之外：

```py
import threading
import time
import os
from threading import Thread
from random import randint

# Lock Definition
threadLock = threading.Lock()

class MyThreadClass (Thread):
 def __init__(self, name, duration):
 Thread.__init__(self)
 self.name = name
 self.duration = duration
 def run(self):
 #Acquire the Lock
 threadLock.acquire() 
 print ("---> " + self.name + \
 " running, belonging to process ID "\
 + str(os.getpid()) + "\n")
 time.sleep(self.duration)
 print ("---> " + self.name + " over\n")
 #Release the Lock
 threadLock.release()
```

1.  `main()`函数与之前的代码示例相比没有改变：

```py
def main():
 start_time = time.time()
 # Thread Creation
 thread1 = MyThreadClass("Thread#1 ", randint(1,10))
 thread2 = MyThreadClass("Thread#2 ", randint(1,10))
 thread3 = MyThreadClass("Thread#3 ", randint(1,10))
 thread4 = MyThreadClass("Thread#4 ", randint(1,10))
 thread5 = MyThreadClass("Thread#5 ", randint(1,10))
 thread6 = MyThreadClass("Thread#6 ", randint(1,10))
 thread7 = MyThreadClass("Thread#7 ", randint(1,10))
 thread8 = MyThreadClass("Thread#8 ", randint(1,10))
 thread9 = MyThreadClass("Thread#9 ", randint(1,10))

 # Thread Running
 thread1.start()
 thread2.start()
 thread3.start()
 thread4.start()
 thread5.start()
 thread6.start()
 thread7.start()
 thread8.start()
 thread9.start()

 # Thread joining
 thread1.join()
 thread2.join()
 thread3.join()
 thread4.join()
 thread5.join()
 thread6.join()
 thread7.join()
 thread8.join()
 thread9.join()

 # End 
 print("End")
 #Execution Time
 print("--- %s seconds ---" % (time.time() - start_time))

if __name__ == "__main__":
 main()
```

# 工作原理...

我们通过使用锁修改了上一节的代码，以便线程按顺序执行。

第一个线程获取锁并执行其任务，而其他八个线程保持*等待*状态。在第一个线程执行结束时，也就是执行`release()`方法时，第二个线程将获取锁，而第三到第八个线程仍将等待直到执行结束（也就是再次运行`release()`方法后）。

*锁获取*和*锁释放*的执行重复进行，直到第九个线程，最终结果是由于锁机制，这个执行是按顺序进行的，如下面的输出所示：

```py
---> Thread#1 running, belonging to process ID 10632
---> Thread#1 over
---> Thread#2 running, belonging to process ID 10632
---> Thread#2 over
---> Thread#3 running, belonging to process ID 10632
---> Thread#3 over
---> Thread#4 running, belonging to process ID 10632
---> Thread#4 over
---> Thread#5 running, belonging to process ID 10632
---> Thread#5 over
---> Thread#6 running, belonging to process ID 10632
---> Thread#6 over
---> Thread#7 running, belonging to process ID 10632
---> Thread#7 over
---> Thread#8 running, belonging to process ID 10632
---> Thread#8 over
---> Thread#9 running, belonging to process ID 10632
---> Thread#9 over

End

--- 47.3672661781311 seconds ---
```

# 还有更多...

`acquire()`和`release()`方法的插入点决定了整个代码的执行。因此，非常重要的是，您花时间分析您想要使用的线程以及如何同步它们。

例如，我们可以像这样在`MyThreadClass`类中改变`release()`方法的插入点：

```py
import threading
import time
import os
from threading import Thread
from random import randint

# Lock Definition
threadLock = threading.Lock()

class MyThreadClass (Thread):
 def __init__(self, name, duration):
 Thread.__init__(self)
 self.name = name
 self.duration = duration
 def run(self):
 #Acquire the Lock
 threadLock.acquire() 
 print ("---> " + self.name + \
 " running, belonging to process ID "\ 
 + str(os.getpid()) + "\n")
 #Release the Lock in this new point
 threadLock.release()
 time.sleep(self.duration)
 print ("---> " + self.name + " over\n")
```

在这种情况下，输出会发生相当大的变化：

```py
---> Thread#1 running, belonging to process ID 11228
---> Thread#2 running, belonging to process ID 11228
---> Thread#3 running, belonging to process ID 11228
---> Thread#4 running, belonging to process ID 11228
---> Thread#5 running, belonging to process ID 11228
---> Thread#6 running, belonging to process ID 11228
---> Thread#7 running, belonging to process ID 11228
---> Thread#8 running, belonging to process ID 11228
---> Thread#9 running, belonging to process ID 11228

---> Thread#2 over
---> Thread#4 over
---> Thread#6 over
---> Thread#5 over
---> Thread#1 over
---> Thread#3 over
---> Thread#9 over
---> Thread#7 over
---> Thread#8 over

End
--- 6.11468243598938 seconds ---
```

正如你所看到的，只有线程的创建是按顺序进行的。一旦线程创建完成，新线程获取锁，而前一个线程在后台继续计算。

# 使用 RLock 进行线程同步

可重入锁，或者简称为 RLock，是一种同步原语，同一个线程可以多次获取它。

它使用专有线程的概念。这意味着在*锁定状态*下，一些线程拥有锁，而在*解锁状态*下，锁没有被任何线程拥有。

下一个示例演示了如何通过`RLock()`机制管理线程。

# 准备工作

通过`threading.RLock()`类实现了 RLock。它提供了与`threading.Lock()`类相同语法的`acquire()`和`release()`方法。

一个`RLock`块可以被同一个线程多次获取。其他线程在拥有它的线程对每次之前的`acquire()`调用进行`release()`调用之前将无法获取`RLock`块。确实，`RLock`块必须被释放，但只能由获取它的线程释放。

# 如何做到这一点...

涉及的步骤如下：

1.  我们引入了`Box`类，它提供了`add()`和`remove()`方法，这些方法访问`execute()`方法，以执行添加或删除项目的操作。对`execute()`方法的访问由`RLock()`进行调节：

```py
import threading
import time
import random

class Box:
 def __init__(self):
 self.lock = threading.RLock()
 self.total_items = 0

 def execute(self, value):
 with self.lock:
 self.total_items += value

 def add(self):
 with self.lock:
 self.execute(1)

 def remove(self):
 with self.lock:
 self.execute(-1)
```

1.  两个线程调用以下函数。它们有`box`类和要添加或移除的项目的总数作为参数：

```py
def adder(box, items):
 print("N° {} items to ADD \n".format(items))
 while items:
 box.add()
 time.sleep(1)
 items -= 1
 print("ADDED one item -->{} item to ADD \n".format(items))

def remover(box, items):
 print("N° {} items to REMOVE\n".format(items))
 while items:
 box.remove()
 time.sleep(1)
 items -= 1
 print("REMOVED one item -->{} item to REMOVE\
 \n".format(items))
```

1.  在这里，设置要添加或从箱子中移除的项目的总数。正如你所看到的，这两个数字将是不同的。当`adder`和`remover`方法都完成它们的任务时，执行结束：

```py
def main():
 items = 10
 box = Box()

 t1 = threading.Thread(target=adder, \
 args=(box, random.randint(10,20)))
 t2 = threading.Thread(target=remover, \
 args=(box, random.randint(1,10)))

 t1.start()
 t2.start()

 t1.join()
 t2.join()

if __name__ == "__main__":
 main()
```

# 它是如何工作的...

在`main`程序中，`t1`和`t2`两个线程已经与`adder()`和`remover()`函数关联。如果项目的数量大于零，这些函数是活动的。

对`RLock()`的调用是在**`Box`**类的`__init__`方法中进行的：

```py
class Box:
 def __init__(self):
 self.lock = threading.RLock()
 self.total_items = 0
```

`adder()`和`remover()`函数分别与`Box`类的项目进行交互，并调用`Box`类的`add()`和`remove()`方法。

在每个方法调用中，使用在`_init_`方法中设置的`lock`参数来捕获和释放资源。

这里是输出：

```py
N° 16 items to ADD 
N° 1 items to REMOVE 

ADDED one item -->15 item to ADD 
REMOVED one item -->0 item to REMOVE 

ADDED one item -->14 item to ADD 
ADDED one item -->13 item to ADD 
ADDED one item -->12 item to ADD 
ADDED one item -->11 item to ADD 
ADDED one item -->10 item to ADD 
ADDED one item -->9 item to ADD 
ADDED one item -->8 item to ADD 
ADDED one item -->7 item to ADD 
ADDED one item -->6 item to ADD 
ADDED one item -->5 item to ADD 
ADDED one item -->4 item to ADD 
ADDED one item -->3 item to ADD 
ADDED one item -->2 item to ADD 
ADDED one item -->1 item to ADD 
ADDED one item -->0 item to ADD 
>>>
```

# 还有更多...

*lock*和*RLock*之间的区别如下：

+   *lock*只能在释放之前被获取一次。但是，`RLock`可以从同一个线程多次获取；为了释放，必须释放相同次数。

+   另一个区别是，已获取的锁可以被任何线程释放，而已获取的`RLock`只能被获取它的线程释放。

# 使用信号量进行线程同步

**信号量**是由操作系统管理的抽象数据类型，用于同步多个线程对共享资源和数据的访问。它由一个内部变量组成，用于标识与其关联的资源的并发访问量。

# 准备好了

信号量的操作基于两个函数：`acquire()`和`release()`，如下所述：

+   每当一个线程想要访问与信号量相关的给定资源时，它必须调用`acquire()`操作，这会*减少信号量的内部变量*，如果这个变量的值看起来是非负的，就允许访问资源。如果值为负，则线程将被挂起，另一个线程释放资源的操作将被搁置。

+   在使用共享资源后，线程通过`release()`指令释放资源。这样，信号量的内部变量增加，允许*等待*线程（如果有的话）有机会访问新释放的资源。

信号量是计算机科学历史上最古老的同步原语之一，由早期荷兰计算机科学家 Edsger W. Dijkstra 发明。

以下示例显示了如何通过信号量同步线程。

# 如何做...

以下代码描述了一个问题，我们有两个线程`producer()`和`consumer()`，它们共享一个公共资源，即项目。`producer()`的任务是生成项目，而`consumer()`线程的任务是使用已经生成的项目。

如果项目尚未由`consumer()`线程生成，则它必须等待。一旦项目生成，`producer()`线程通知消费者应该使用资源：

1.  通过将信号量初始化为`0`，我们获得了一个所谓的信号量事件，其唯一目的是同步两个或多个线程的计算。在这里，一个线程必须同时使用数据或共享资源：

```py
semaphore = threading.Semaphore(0)
```

1.  这个操作与锁的锁定机制中描述的非常相似。`producer()`线程创建项目，之后通过调用`release()`方法释放资源：

```py
semaphore.release()
```

1.  同样，`consumer()`线程通过`acquire()`方法获取数据。如果信号量的计数器等于`0`，那么它会阻塞条件的`acquire()`方法，直到被其他线程通知。如果信号量的计数器大于`0`，那么它会递减该值。当生产者创建一个项目时，它释放信号量，然后消费者获取并消耗共享资源：

```py
semaphore.acquire()
```

1.  通过信号量进行的同步过程如下代码块所示：

```py
import logging
import threading
import time
import random

LOG_FORMAT = '%(asctime)s %(threadName)-17s %(levelname)-8s %\
 (message)s'
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)

semaphore = threading.Semaphore(0)
item = 0

def consumer():
 logging.info('Consumer is waiting')
 semaphore.acquire()
 logging.info('Consumer notify: item number {}'.format(item))

def producer():
 global item
 time.sleep(3)
 item = random.randint(0, 1000)
 logging.info('Producer notify: item number {}'.format(item))
 semaphore.release()

#Main program
def main():
 for i in range(10):
 t1 = threading.Thread(target=consumer)
 t2 = threading.Thread(target=producer)

 t1.start()
 t2.start()

 t1.join()
 t2.join()

if __name__ == "__main__":
 main()
```

# 工作原理...

获取的数据然后被打印到标准输出：

```py
print ("Consumer notify : consumed item number %s " %item)
```

这是我们在 10 次运行后得到的结果：

```py
2019-01-27 19:21:19,354 Thread-1 INFO Consumer is waiting
2019-01-27 19:21:22,360 Thread-2 INFO Producer notify: item number 388
2019-01-27 19:21:22,385 Thread-1 INFO Consumer notify: item number 388
2019-01-27 19:21:22,395 Thread-3 INFO Consumer is waiting
2019-01-27 19:21:25,398 Thread-4 INFO Producer notify: item number 939
2019-01-27 19:21:25,450 Thread-3 INFO Consumer notify: item number 939
2019-01-27 19:21:25,453 Thread-5 INFO Consumer is waiting
2019-01-27 19:21:28,459 Thread-6 INFO Producer notify: item number 388
2019-01-27 19:21:28,468 Thread-5 INFO Consumer notify: item number 388
2019-01-27 19:21:28,476 Thread-7 INFO Consumer is waiting
2019-01-27 19:21:31,478 Thread-8 INFO Producer notify: item number 700
2019-01-27 19:21:31,529 Thread-7 INFO Consumer notify: item number 700
2019-01-27 19:21:31,538 Thread-9 INFO Consumer is waiting
2019-01-27 19:21:34,539 Thread-10 INFO Producer notify: item number 685
2019-01-27 19:21:34,593 Thread-9 INFO Consumer notify: item number 685
2019-01-27 19:21:34,603 Thread-11 INFO Consumer is waiting
2019-01-27 19:21:37,604 Thread-12 INFO Producer notify: item number 503
2019-01-27 19:21:37,658 Thread-11 INFO Consumer notify: item number 503
2019-01-27 19:21:37,668 Thread-13 INFO Consumer is waiting
2019-01-27 19:21:40,670 Thread-14 INFO Producer notify: item number 690
2019-01-27 19:21:40,719 Thread-13 INFO Consumer notify: item number 690
2019-01-27 19:21:40,729 Thread-15 INFO Consumer is waiting
2019-01-27 19:21:43,731 Thread-16 INFO Producer notify: item number 873
2019-01-27 19:21:43,788 Thread-15 INFO Consumer notify: item number 873
2019-01-27 19:21:43,802 Thread-17 INFO Consumer is waiting
2019-01-27 19:21:46,807 Thread-18 INFO Producer notify: item number 691
2019-01-27 19:21:46,861 Thread-17 INFO Consumer notify: item number 691
2019-01-27 19:21:46,874 Thread-19 INFO Consumer is waiting
2019-01-27 19:21:49,876 Thread-20 INFO Producer notify: item number 138
2019-01-27 19:21:49,924 Thread-19 INFO Consumer notify: item number 138
>>>
```

# 还有更多...

信号量的一个特殊用途是*互斥体*。互斥体只是一个内部变量初始化为`1`的信号量，它允许在对数据和资源的访问中实现互斥排他。

信号量仍然广泛用于多线程编程的编程语言；然而，它们有两个主要问题，我们已经讨论如下：

+   它们并不能阻止一个线程对同一个信号量执行更多的等待操作。很容易忘记对执行的等待数量做出所有必要的信号。

+   你可能会遇到死锁的情况。例如，当`t1`线程在`s1`信号量上执行等待时，`t2`线程在`t1`线程上执行等待，然后在`s2`和`t2`上执行等待，最后在`s1`上执行等待时，就会创建死锁情况。

# 使用条件进行线程同步

*condition*标识应用程序中状态的变化。它是一种同步机制，其中一个线程等待特定条件，另一个线程通知该*条件已发生*。

一旦条件发生，线程就会*获取*锁，以便对共享资源进行*独占访问*。

# 准备工作

一个很好的说明这种机制的方法是再次看一个生产者/消费者问题。生产者类在缓冲区不满时向缓冲区写入数据，而消费者类在缓冲区满时从缓冲区中取出数据（从后者中消除）。生产者类将通知消费者缓冲区不为空，而消费者将向生产者报告缓冲区不满。

# 如何做...

涉及的步骤如下：

1.  消费者类获取通过**`items[]`**列表建模的共享资源：

```py
condition.acquire()
```

1.  如果列表的长度等于`0`，则消费者被置于等待状态：

```py
if len(items) == 0:
 condition.wait()
```

1.  然后它从 items 列表中进行一次**`pop`**操作：

```py
items.pop()
```

1.  因此，消费者的状态被通知给生产者，共享资源被释放：

```py
condition.notify()
```

1.  生产者类获取共享资源，然后验证列表是否完全满（在我们的示例中，我们放置了最大数量的项目`10`，可以包含在 items 列表中）。如果列表已满，则生产者被置于等待状态，直到列表被消耗：

```py
condition.acquire()
if len(items) == 10:
 condition.wait()
```

1.  如果列表不满，则添加一个单个项目。状态被通知并且资源被释放：

```py
condition.notify()
condition.release()
```

1.  为了向你展示条件机制，我们将再次使用*消费者/生产者*模型：

```py
import logging
import threading
import time

LOG_FORMAT = '%(asctime)s %(threadName)-17s %(levelname)-8s %\
 (message)s'
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)

items = []
condition = threading.Condition()

class Consumer(threading.Thread):
 def __init__(self, *args, **kwargs):
 super().__init__(*args, **kwargs)

 def consume(self):

 with condition:

 if len(items) == 0:
 logging.info('no items to consume')
 condition.wait()

 items.pop()
 logging.info('consumed 1 item')

 condition.notify()

 def run(self):
 for i in range(20):
 time.sleep(2)
 self.consume()

class Producer(threading.Thread):
 def __init__(self, *args, **kwargs):
 super().__init__(*args, **kwargs)

 def produce(self):

 with condition:

 if len(items) == 10:
 logging.info('items produced {}.\
 Stopped'.format(len(items)))
 condition.wait()

 items.append(1)
 logging.info('total items {}'.format(len(items)))

 condition.notify()

 def run(self):
 for i in range(20):
 time.sleep(0.5)
 self.produce()
```

# 工作原理...

`producer`不断生成项目并将其存储在缓冲区中。与此同时，`consumer`不时使用生成的数据，从缓冲区中删除它。

一旦`consumer`从缓冲区中取出一个对象，它就会唤醒`producer`，后者将开始再次填充缓冲区。

同样，如果缓冲区为空，`consumer`将被挂起。一旦`producer`将数据下载到缓冲区中，`consumer`就会被唤醒。

正如你所看到的，即使在这种情况下，使用`condition`指令也允许线程正确同步。

单次运行后我们得到的结果如下：

```py
2019-08-05 14:33:44,285 Producer INFO total items 1
2019-08-05 14:33:44,786 Producer INFO total items 2
2019-08-05 14:33:45,286 Producer INFO total items 3
2019-08-05 14:33:45,786 Consumer INFO consumed 1 item
2019-08-05 14:33:45,787 Producer INFO total items 3
2019-08-05 14:33:46,287 Producer INFO total items 4
2019-08-05 14:33:46,788 Producer INFO total items 5
2019-08-05 14:33:47,289 Producer INFO total items 6
2019-08-05 14:33:47,787 Consumer INFO consumed 1 item
2019-08-05 14:33:47,790 Producer INFO total items 6
2019-08-05 14:33:48,291 Producer INFO total items 7
2019-08-05 14:33:48,792 Producer INFO total items 8
2019-08-05 14:33:49,293 Producer INFO total items 9
2019-08-05 14:33:49,788 Consumer INFO consumed 1 item
2019-08-05 14:33:49,794 Producer INFO total items 9
2019-08-05 14:33:50,294 Producer INFO total items 10
2019-08-05 14:33:50,795 Producer INFO items produced 10\. Stopped
2019-08-05 14:33:51,789 Consumer INFO consumed 1 item
2019-08-05 14:33:51,790 Producer INFO total items 10
2019-08-05 14:33:52,290 Producer INFO items produced 10\. Stopped
2019-08-05 14:33:53,790 Consumer INFO consumed 1 item
2019-08-05 14:33:53,790 Producer INFO total items 10
2019-08-05 14:33:54,291 Producer INFO items produced 10\. Stopped
2019-08-05 14:33:55,790 Consumer INFO consumed 1 item
2019-08-05 14:33:55,791 Producer INFO total items 10
2019-08-05 14:33:56,291 Producer INFO items produced 10\. Stopped
2019-08-05 14:33:57,791 Consumer INFO consumed 1 item
2019-08-05 14:33:57,791 Producer INFO total items 10
2019-08-05 14:33:58,292 Producer INFO items produced 10\. Stopped
2019-08-05 14:33:59,791 Consumer INFO consumed 1 item
2019-08-05 14:33:59,791 Producer INFO total items 10
2019-08-05 14:34:00,292 Producer INFO items produced 10\. Stopped
2019-08-05 14:34:01,791 Consumer INFO consumed 1 item
2019-08-05 14:34:01,791 Producer INFO total items 10
2019-08-05 14:34:02,291 Producer INFO items produced 10\. Stopped
2019-08-05 14:34:03,791 Consumer INFO consumed 1 item
2019-08-05 14:34:03,792 Producer INFO total items 10
2019-08-05 14:34:05,792 Consumer INFO consumed 1 item
2019-08-05 14:34:07,793 Consumer INFO consumed 1 item
2019-08-05 14:34:09,794 Consumer INFO consumed 1 item
2019-08-05 14:34:11,795 Consumer INFO consumed 1 item
2019-08-05 14:34:13,795 Consumer INFO consumed 1 item
2019-08-05 14:34:15,833 Consumer INFO consumed 1 item
2019-08-05 14:34:17,833 Consumer INFO consumed 1 item
2019-08-05 14:34:19,833 Consumer INFO consumed 1 item
2019-08-05 14:34:21,834 Consumer INFO consumed 1 item
2019-08-05 14:34:23,835 Consumer INFO consumed 1 item
```

# 还有更多...

有趣的是，查看 Python 内部的条件同步机制。如果没有现有的锁被传递给类的构造函数，内部的`class _Condition`会创建一个`RLock()`对象。此外，当调用`acquire()`和`released()`时，锁将被管理：

```py
class _Condition(_Verbose):
 def __init__(self, lock=None, verbose=None):
 _Verbose.__init__(self, verbose)
 if lock is None:
 lock = RLock()
 self.__lock = lock
```

# 使用事件进行线程同步

事件是用于线程间通信的对象。一个线程等待信号，而另一个线程输出它。基本上，`event`对象管理一个内部标志，可以通过`clear()`设置为`false`，通过`set()`设置为`true`，并通过`is_set()`进行测试。

通过`wait()`方法，线程可以持有一个信号，该方法会发送调用`set()`方法。

# 准备工作

要理解通过`event`对象进行线程同步，让我们来看看生产者/消费者问题。

# 如何做...

再次，为了解释如何通过事件同步线程，我们将参考*生产者/消费者*问题。该问题描述了两个进程，一个生产者和一个消费者，它们共享一个固定大小的公共缓冲区。生产者的任务是生成项目并将它们存放在连续的缓冲区中。与此同时，消费者将使用生成的项目，不时地从缓冲区中取出它们。

问题在于确保如果缓冲区已满，生产者不会处理新数据，消费者不会在缓冲区为空时寻找数据。

现在，让我们看看如何使用`event`语句实现消费者/生产者问题的线程同步：

1.  在这里，相关的库被导入如下：

```py
import logging
import threading
import time
import random
```

1.  然后，我们定义日志输出格式。清晰地可视化发生的事情是很有用的：

```py
LOG_FORMAT = '%(asctime)s %(threadName)-17s %(levelname)-8s %\
 (message)s'
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
```

1.  设置`items`列表。该参数将被`Consumer`和`Producer`类使用：

```py
items = []
```

1.  `event`参数定义如下。该参数将用于同步线程之间的通信：

```py
event = threading.Event()
```

1.  `Consumer`类使用项目列表和`Event()`函数进行初始化。在`run`方法中，消费者等待新项目进行消费。当项目到达时，它从`item`列表中弹出：

```py
class Consumer(threading.Thread):
 def __init__(self, *args, **kwargs):
 super().__init__(*args, **kwargs)

 def run(self):
 while True:
 time.sleep(2)
 event.wait()
 item = items.pop()
 logging.info('Consumer notify: {} popped by {}'\
 .format(item, self.name))
```

1.  `Producer`类使用项目列表和`Event()`函数进行初始化。与使用`condition`对象的示例不同，项目列表不是全局的，而是作为参数传递的：

```py
class Producer(threading.Thread):
 def __init__(self, *args, **kwargs):
 super().__init__(*args, **kwargs)
```

1.  在`run`方法中，对于每个创建的项目，`Producer`类将其附加到项目列表，然后通知事件：

```py
 def run(self):
 for i in range(5):
 time.sleep(2)
 item = random.randint(0, 100)
 items.append(item)
 logging.info('Producer notify: item {} appended by\ 
 {}'\.format(item, self.name))
```

1.  这需要两个步骤，第一步如下：

```py
 event.set()
 event.clear()
```

1.  `t1`线程向列表添加一个值，然后设置事件以通知消费者。消费者调用`wait()`停止阻塞，并从列表中检索整数：

```py
if __name__ == "__main__":
 t1 = Producer()
 t2 = Consumer()

 t1.start()
 t2.start()

 t1.join()
 t2.join()
```

# 工作原理...

通过以下模式可以轻松地总结`Producer`和`Consumer`类之间的所有操作：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-pll-prog-cb/img/915fcac0-899f-465a-9fd2-ce18a24bb0f0.png)

使用事件对象进行线程同步

特别是，`Producer`和`Consumer`类具有以下行为：

+   `Producer`获取锁，向队列添加项目，并通知`Consumer`这个事件（设置事件）。然后它会休眠，直到收到新的项目添加。

+   `Consumer`获取一个块，然后开始循环监听元素。当事件到达时，消费者放弃块，从而允许其他生产者/消费者进入并获取块。如果`Consumer`重新激活，则通过安全地处理队列中的新项目重新获取锁：

```py
2019-02-02 18:23:35,125 Thread-1 INFO Producer notify: item 68 appended by Thread-1
2019-02-02 18:23:35,133 Thread-2 INFO Consumer notify: 68 popped by Thread-2
2019-02-02 18:23:37,138 Thread-1 INFO Producer notify: item 45 appended by Thread-1
2019-02-02 18:23:37,143 Thread-2 INFO Consumer notify: 45 popped by Thread-2
2019-02-02 18:23:39,148 Thread-1 INFO Producer notify: item 78 appended by Thread-1
2019-02-02 18:23:39,153 Thread-2 INFO Consumer notify: 78 popped by Thread-2
2019-02-02 18:23:41,158 Thread-1 INFO Producer notify: item 22 appended by Thread-1
2019-02-02 18:23:43,173 Thread-1 INFO Producer notify: item 48 appended by Thread-1
2019-02-02 18:23:43,178 Thread-2 INFO Consumer notify: 48 popped by Thread-2
```

# 使用屏障进行线程同步

有时，一个应用程序可以被划分为阶段，根据规则，如果首先，所有进程的线程都完成了自己的任务，那么没有一个进程可以继续。一个**屏障**实现了这个概念：完成了自己阶段的线程调用一个原始的屏障并停止。当所有涉及的线程都完成了他们的执行阶段并调用了原始的屏障时，系统解锁它们所有，允许线程进入后续阶段。

# 准备就绪

Python 的线程模块通过**`Barrier`**类实现屏障。在下一节中，让我们学习如何在一个非常简单的例子中使用这种同步机制。

# 如何做...

在这个例子中，我们模拟了一个有三个参与者`Huey`、`Dewey`和`Louie`的比赛，其中一个屏障被类比为终点线。

此外，当所有三个参与者都穿过终点线时，比赛可以自行结束。

屏障是通过`Barrier`类实现的，必须在参数中指定要完成的线程数才能进入下一个阶段：

```py
from random import randrange
from threading import Barrier, Thread
from time import ctime, sleep

num_runners = 3
finish_line = Barrier(num_runners)
runners = ['Huey', 'Dewey', 'Louie']

def runner():
 name = runners.pop()
 sleep(randrange(2, 5))
 print('%s reached the barrier at: %s \n' % (name, ctime()))
 finish_line.wait()

def main():
 threads = []
 print('START RACE!!!!')
 for i in range(num_runners):
 threads.append(Thread(target=runner))
 threads[-1].start()
 for thread in threads:
 thread.join()
 print('Race over!')

if __name__ == "__main__":
 main()
```

# 工作原理...

首先，我们将参与者的数量设置为`num_runners = 3`，以便通过`Barrier`指令在下一行设置最终目标。参与者被设置在参与者列表中；每个参与者都将在`runner`函数中使用`randrange`指令确定到达时间。

当一个跑步者到达终点线时，调用`wait`方法，这将阻塞所有已经做出该调用的跑步者（线程）。这个的输出如下：

```py
START RACE!!!!
Dewey reached the barrier at: Sat Feb 2 21:44:48 2019 

Huey reached the barrier at: Sat Feb 2 21:44:49 2019 

Louie reached the barrier at: Sat Feb 2 21:44:50 2019 

Race over!
```

在这种情况下，`Dewey`赢得了比赛。

# 使用队列进行线程通信

当线程需要共享数据或资源时，多线程可能会变得复杂。幸运的是，线程模块提供了许多同步原语，包括信号量、条件变量、事件和锁。

然而，使用`queue`模块被认为是最佳实践。事实上，队列要容易处理得多，并且使得线程编程变得更加安全，因为它有效地将对资源的所有访问集中到一个单独的线程，并允许更清晰和更可读的设计模式。

# 准备就绪

我们将简单地考虑这些队列方法：

+   `put()`: 将一个项目放入队列

+   `get()`: 从队列中移除并返回一个项目

+   `task_done()`: 每次处理完一个项目时都需要调用

+   `join()`: 阻塞直到所有项目都被处理

# 如何做...

在这个例子中，我们将看到如何使用`threading`模块和`queue`模块。此外，我们在这里有两个实体试图共享一个共同的资源，即一个队列。代码如下：

```py
from threading import Thread
from queue import Queue
import time
import random

class Producer(Thread):
 def __init__(self, queue):
 Thread.__init__(self)
 self.queue = queue
 def run(self):
 for i in range(5):
 item = random.randint(0, 256)
 self.queue.put(item)
 print('Producer notify : item N°%d appended to queue by\ 
 %s\n'\
 % (item, self.name))
 time.sleep(1)

class Consumer(Thread):
 def __init__(self, queue):
 Thread.__init__(self)
 self.queue = queue

 def run(self):
 while True:
 item = self.queue.get()
 print('Consumer notify : %d popped from queue by %s'\
 % (item, self.name))
 self.queue.task_done()

if __name__ == '__main__':
 queue = Queue()
 t1 = Producer(queue)
 t2 = Consumer(queue)
 t3 = Consumer(queue)
 t4 = Consumer(queue)

 t1.start()
 t2.start()
 t3.start()
 t4.start()

 t1.join()
 t2.join()
 t3.join()
 t4.join()
```

# 工作原理...

首先，使用`producer`类，我们不需要传递整数列表，因为我们使用队列来存储生成的整数。

`producer`类中的线程生成整数并将它们放入队列中的`for`循环。`producer`类使用`Queue.put(item[, block[, timeout]])`在队列中插入数据。它具有在将数据插入队列之前获取锁的逻辑。

有两种可能性：

+   如果可选参数`block`为`true`且`timeout`为`None`（这是我们在示例中使用的默认情况），则我们需要阻塞直到有一个空闲槽可用。如果超时是一个正数，则最多阻塞超时秒，并在该时间内没有可用的空闲槽时引发 full 异常。

+   如果`block`为`false`，则如果立即有空闲槽，则将项目放入队列，否则引发 full 异常（在这种情况下忽略超时）。在这里，`put`检查队列是否已满，然后在内部调用`wait`，之后生产者开始等待。

接下来是`consumer`类。线程从队列中获取整数，并使用`task_done`指示完成对其的操作。`consumer`类使用`Queue.get([block[, timeout]])`并在从队列中移除数据之前获取锁定。如果队列为空，消费者将处于等待状态。最后，在`main`函数中，我们创建四个线程，一个用于`producer`类，三个用于`consumer`类。

输出应该是这样的：

```py
Producer notify : item N°186 appended to queue by Thread-1
Consumer notify : 186 popped from queue by Thread-2

Producer notify : item N°16 appended to queue by Thread-1
Consumer notify : 16 popped from queue by Thread-3

Producer notify : item N°72 appended to queue by Thread-1
Consumer notify : 72 popped from queue by Thread-4

Producer notify : item N°178 appended to queue by Thread-1
Consumer notify : 178 popped from queue by Thread-2

Producer notify : item N°214 appended to queue by Thread-1
Consumer notify : 214 popped from queue by Thread-3
```

# 还有更多...

`producer`类和`consumer`类之间的所有操作都可以很容易地用以下模式来总结：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-pll-prog-cb/img/cb11a94d-258a-485f-a1b4-8954a860b41a.png)使用队列模块进行线程同步

+   `Producer`线程获取锁定，然后将数据插入**QUEUE**数据结构中。

+   `Consumer`线程从**QUEUE**中获取整数。这些线程在从**QUEUE**中移除数据之前获取锁定。

如果**QUEUE**为空，那么`consumer`线程将进入**等待**状态。

通过这个示例，本章关于基于线程的并行性就结束了。
