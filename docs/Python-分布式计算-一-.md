# Python 分布式计算（一）



# 零、序言 （Distributed Computing with Python）

* * *

序言
[第 1 章 并行和分布式计算介绍](https://www.jianshu.com/p/a8ec42f6cb4e)
[第 2 章 异步编程](https://www.jianshu.com/p/02893376bfe8)
[第 3 章 Python 的并行计算](https://www.jianshu.com/p/66f47049cc5a)
[第 4 章 Celery 分布式应用](https://www.jianshu.com/p/ee14ed9e4989)
[第 5 章 云平台部署 Python](https://www.jianshu.com/p/84dde3009782)
[第 6 章 超级计算机群使用 Python](https://www.jianshu.com/p/59471509d3d9)
[第 7 章 测试和调试分布式应用](https://www.jianshu.com/p/c92721ff5f3c)
[第 8 章 继续学习](https://www.jianshu.com/p/de89c55f8e8a)

* * *

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-dist-comp/img/31879890ae1ea802c9db239987f99b0e.jpg)Python 分布式计算

* * *

## 作者简介

Francesco Pierfederici 是一名喜爱 Python 的软件工程师。过去 20 年间，他的工作领域涉及天文学、生物学和气象预报。

他搭建过上万 CPU 核心的大型分布式系统，并在世界上最快的超级计算机上运行过。他还写过用处不大，但极为有趣的应用。他总是喜欢创造新事物。

“我要感谢我的妻子 Alicia，感谢她在成书过程中的耐心。我还要感谢 Packt 出版社的 Parshva Sheth 和 Aaron Lazar，以及技术审稿人 James King，他们让这本书变得更好。” —— Francesco Pierfederici

* * *

## 审稿人简介

James King 是一名有丰富分布式系统开发经验的工程师。他是许多开源项目的贡献者，包括 OpenStack 和 Mozilla Firefox。他喜欢数学、与孩子们骑马、游戏和艺术。

* * *

## 序言

并行和分布式计算是一个具有吸引力的课题，几年之前，只有大公司和国家实验室的开发者才能接触到。这十年间，情况发生了改变：现在所有人都可以使用各种语言搭建中小型的分布式应用，这些语言中自然包括我们的最爱：Python。

这本书是为搭建分布式系统的 Python 开发者而写的实践指导。它首先介绍了关于并行和分布式计算的基础理论。然后，用 Python 的标准库做了几个并行计算示例。接着，不再使用一台计算机，而是使用第三方库，包括 Celery 和 Pyro，扩展到更多节点。

剩下的章节探讨了分布式应用的部署方案，包括云平台和超级计算机群（High Performance Computing，HPC），分析了各自的优势和难点。

最后，分析了一些难点，监控、登录、概述和调试。

总之，这是一本关注实践的书，它将教会你使用一些流行的框架和方法，使用 Python 搭建并行分布系统。

## 本书的内容

第 1 章，并行和分布式计算介绍，介绍基础理论。
第 2 章，异步编程，介绍两种分布式应用的编程风格：同步和异步。
第 3 章，Python 的并行计算，介绍使用 Python 的标准库，实现同一时间完成多项任务。
第 4 章，Celery 分布式应用，介绍如何使用 Celery 搭建最简单的分布式应用，以及 Celery 的竞争对手 Python-RQ 和 Pyro。
第 5 章，云平台使用 Python，展示如何使用 AWS 将 Python 应用部署到云平台。
第 6 章，超级计算机群使用 Python，介绍将 Python 应用部署到超级计算机群，多应用于大学和国家实验室。
第 7 章，测试和调试分布式应用，讲解了 Python 分布式应用在测试、概述和调试中的难点。
第 8 章，继续学习，回顾前面所学，向感兴趣的读者介绍继续学习的路径。

* * *

序言
[第 1 章 并行和分布式计算介绍](https://www.jianshu.com/p/a8ec42f6cb4e)
[第 2 章 异步编程](https://www.jianshu.com/p/02893376bfe8)
[第 3 章 Python 的并行计算](https://www.jianshu.com/p/66f47049cc5a)
[第 4 章 Celery 分布式应用](https://www.jianshu.com/p/ee14ed9e4989)
[第 5 章 云平台部署 Python](https://www.jianshu.com/p/84dde3009782)
[第 6 章 超级计算机群使用 Python](https://www.jianshu.com/p/59471509d3d9)
[第 7 章 测试和调试分布式应用](https://www.jianshu.com/p/c92721ff5f3c)
[第 8 章 继续学习](https://www.jianshu.com/p/de89c55f8e8a)

* * *

# 一、并行和分布式计算介绍 （Distributed Computing with Python）



本书示例代码适用于 Python 3.5 及以上。

* * *

当代第一台数字计算机诞生于上世纪 30 年代末 40 年代初（Konrad Zuse 1936 年的 Z1 存在争议），也许比本书大多数读者都要早，比作者本人也要早。过去的七十年见证了计算机飞速地发展，计算机变得越来越快、越来越便宜，这在整个工业领域中是独一无二的。如今的手机，iPhone 或是安卓，比 20 年前最快的电脑还要快。而且，计算机变得越来越小：过去的超级计算机能装下整间屋子，现在放在口袋里就行了。

这其中包括两个重要的发明。其一是主板上安装多块处理器（每个处理器含有多个核心），这使得计算机能真正地实现并发。我们知道，一个处理器同一时间只能处理同一事务；后面章节我们会看到，当处理器快到一定程度，就可以给出同一时间进行多项任务的假象。若要真正实现同一时间多任务，就需要多个处理器。

另一项发明是高速计算机网络。它首次让无穷多的电脑实现了相互通讯。联网的电脑可能处于同一地点（称为局域网 LAN）或分布在不同地点（称为广域网 WAN）。

如今，我们都已熟悉多处理器/多核心计算机，事实上，我们的手机、平板电脑、笔记本电脑都是多核心的。显卡，或图形处理器（GPU），往往是大规模并行机制，含有数百乃至上千个处理单元。我们周围的计算机网络无处不在，包括：Internet、WiFi、4G 网络。

本章剩余部分会探讨一些定义。我们会介绍并行和分布式计算的概念。给出一些常见的示例。探讨每个架构的优缺点，和编程的范式。

在开始介绍概念之前，先澄清一些东西。在剩余部分中，除非特别指明，我们会交叉使用处理器和 CPU 核心。这在概念上显然是不对的：一个处理器会有一个或多个核，每台计算机会有一个或多个处理器。取决于算法和性能要求，在多处理器或单处理器多核的计算机上运行可能会有速度上的不同，假定算法是并行的。然而，我们会忽略这些差异，将注意力集中于概念本身。

## 并行计算

并行计算的概念很多。本书提供一个简洁的概念：

> 并行计算是同时使用多个处理器处理事务。

典型的，这个概念要求这些处理器位于同一块主板，以区别于分布式计算。

分工的历史和人类文明一样久远，也适用于数字世界，当代计算机安装的计算单元越来越多。

并行计算是有用且必要的原因很多。最简单的原因是性能；如果我们要把一个冗长的计算分成小块、打包给不同的处理器，就可以在相同时间内完成更多工作。

或者，并行计算在处理一项任务时，还可以向用户呈现反馈界面。记住一个处理器同一时间只能处理一项任务。有 GUIs 的应用需要将任务交付给另一个处理器的独立线程，以让另一个处理器能更新 GUI，并对输入进行反馈。

下图展示了这个常见的架构，主线程使用事件循环（Event Loop）处理用户和系统输入。需要长时间处理的任务和会阻塞 GUI 的任务会被移交给后台或 worker 线程：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-dist-comp/img/ddfeb4582e95bd9ce40782ad89fba617.jpg)

一个该并行架构的实际案例可以是一个图片应用。当我们将数码相机或手机连接到电脑上时，图片应用会进行一系列动作，同时它的用户界面要保持交互。例如，应用要将图片从设备拷贝到硬盘上、建立缩略图、提取元数据（拍摄日期及时间）、生成索引、最后更新图片库。与此同时，我们仍然可以浏览以前传输的图片，打开图片、进行编辑等等。

当然，整个过程在单处理器上可能是顺序依次进行的，这个处理器也要处理 GUI。这就会造成用户界面反应迟缓，整个应用会变慢。并行运行可以使这个过程流畅，提高用户体验。

敏锐的读者此时可能指出，以前的只有单处理器单核的旧电脑也可以（通过多任务）同时处理多个事件。即使如今，也可以让运行的任务数超过计算机的处理器数目。其实，这是因为一个正在运行的任务被从 CPU 移出（这可能是自发或被操作系统强制的，例如，响应 IO 事件），好让另一个任务可以在 CPU 上运行。类似的中断会时而发生，在应用运行中，各种任务会相继获得会被移出 CPU。切换通常很快，这样，用户就会有计算机并行运行任务的感觉。实际上，只有一个任务在特定的时间运行。

通常在并行应用中运行的工具是线程。系统（比如 Python）通常对线程有严格的限制（见第 3 章），开发者要转而使用子进程 subprocess（通常的方法是分叉）。子进程取代（或配合）线程，与主进程同时运行。

第一种方法是多线程编程（multithreaded programming）。第二种方法是多进程（multiprocessing）。多进程可以看做是多线程的变通。

许多情况下，多进程要优于多线程。有趣的是，尽管二者都在单机运行，多线程是共享内存架构的例子，而多进程是分布式内存架构的例子（参考本书后续内容）。

## 分布式计算

本书采用如下对分布式计算的定义：

> 分布式计算是指同一时间使用多台计算机处理一个任务。

一般的，与并行计算类似，这个定义也有限制。这个限制通常是要求，对于使用者，这些计算机可以看做一台机器，进而掩盖应用的分布性。本书中，我们更喜欢这个广义的定义。

显然，只有当计算机之间互相连接时，才可以使用分布式计算。事实上，许多时候，这只是对我们在之前部分的并行计算的概念总结。

搭建分布式系统的理由有很多。通常的原因是，要做的任务量太大，一台计算机难以完成，或是不能在一定时间内完成。一个实际的例子就是皮克斯或梦工厂的 3D 动画电影渲染。

考虑到整部电影要渲染的总帧数（电影两个小时，每秒有 30 帧），电影工作室需要将海量的工作分配到多台计算机（他们称其为计算机农场）。

另外，应用本身需要分布式的环境。例如，即时聊天和视频会议应用。对于这些应用，性能不是最重要的。最关键的是，应用本身要是分布式的。下图中，我们看到一个非常常见的网络应用架构（另一个分布式应用例子），多个用户与网站相连。同时，应用本身要与 LAN 中不同主机的系统（例如数据库服务器）通讯：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-dist-comp/img/fe9bb5f807c67a793f4b2efc675bda9d.jpg)

另一个分布式系统的例子，可能有点反直觉，就是 CPU-GPU。如今，显卡本身就是很复杂的计算机。它们高并行运行，处理海量计算密集型任务，不仅是为了在显示器上显示图像。有大量的工具和库（例如 NVIDIA 的 CUDA，OpenCL 和 OpenAcc）可以让开发者对 GPU 进行开发，来做广义计算任务。（译者注：比如在比特币中，使用显卡编程来挖矿。）

然而，CPU 和 GPU 组成的系统实际上就是一个分布式系统，网络被 PCI 总线取代了。任何要使用 CPU 和 GPU 的应用都要处理数据在两个子系统之间的移动，就像传统的在网络中运行的应用。

将现存的代码移植到计算机网络（或 GPU）不是一件轻松的工作。要移植的话，我发现先在一台计算机上使用多进程完成，是一个很有用的中间步骤。我们会在第 3 章看到，Python 有强大的功能完成这项任务（参考`concurrent.futures`模块）。

一旦完成多进程并行运行，就可以考虑将这些进程分拆给独立的应用，这就不是重点了。

特别要注意的是数据，在哪里存储、如何访问。简单情况下，共享式的文件系统（例如，UNIX 的 NFS）就足够了；其余情况，就需要数据库或是消息队列。我们会在第 4 章中看几个这样的实例。要记住，真正的瓶颈往往是数据而不是 CPU。

## 共享式内存 vs 分布式内存

在概念上，并行计算和分布计算很像，毕竟，二者都是要将总计算量分解成小块，再在处理器上运行。有些读者可能会想，一种情况下，使用的处理器全部位于一台计算机之内，另一种情况下，处理器位于不同的计算机。那么，这种技术是不是有点多余？

答案是，可能。正如我们看到的，一些应用本身是分布式的。其它应用则需要更多的性能。对于这些应用，答案就可能是“有点多余”——应用本身不关心算力来自何处。然而，考虑到所有情况，硬件资源的物理存放地点还是有一定意义的。

也许，并行和分布式计算的最明显的差异就是底层的内存架构和访问方式不同。对于并行计算，原则上，所有并发任务可以访问同一块内存空间。这里，我们必须要说原则上，因为我们已经看到并行不一定非要用到线程（线程是可以访问同一块内存空间）。

下图中，我们看到一个典型的共享式内存架构，四个处理器可以访问同一内存地址。如果应用使用线程，如果需要的话，线程就可以访问同一内存空间：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-dist-comp/img/5aaa54f668305f38ef5539a181cbb05b.jpg)

然而，对于分布式应用，不同的并发任务不能正常访问同一内存。原因是，一些任务是在这一台计算机运行，一些任务是在另一台计算机运行，它们是物理分隔的。

因为计算机之间可以靠网络通讯，可以想象写一个软件层（中间件），以一个统一的内存逻辑空间呈现应用。这些中间件就是分布式共享内存架构。此书不涉及这样的系统。

下图中，我们还有有四个 CPU，它们处于共享内存架构中。每个 CPU 都有各自的私有内存，看不到其它 CPU 的内存空间。四台计算机（包围 CPU 和内存的方框）通过网络通讯，通过网络进行数据传输：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-dist-comp/img/428bdd2ad7fe7a03c34a8fc899a53ee0.jpg)

现实中，计算机是我们之前讲过的两种极端情况的结合体。计算机网络通讯就像一个纯粹的分布式内存架构。然而，每台计算机有多个处理器，运行着共享式内存架构。下图描述了这样的混合式架构：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-dist-comp/img/f9708403c9e5d2bbc200cf7c71744541.jpg)

这些架构有各自的优缺点。对于共享式内存系统，在单一文件的并发线程中分享数据速度极快，远远快过网络传输。另外，使用单一内存地址可以简化编程。

同时，还要注意不要让各个线程发生重叠，或是彼此改变参数。

分布式内存系统扩展性强、组建成本低：需要更高性能，扩展即可。另一优点是，处理器可以访问各自的内存，不必担心发生竞争条件（竞争条件指多个线程或者进程在读写一个共享数据时，结果依赖于它们执行的相对时间的情形）。它的缺点是，开发者需要手动写数据传输的策略，需要考虑数据存储的位置。另外，不是所有算法都能容易移植到这种架构。

## 阿姆达尔定律

本章最后一个重要概念是阿姆达尔定律。简言之，阿姆达尔定律是说，我们可以尽情并行化或分布化计算，添加算力资源获得更高性能。然而，最终代码的速度不能比运行在单处理器的单序列（即非并行）的组件要快。

更正式的，阿姆达尔定律有如下公式。考虑一个部分并行的算法，称`P`为并行分量，`S`为序列分量（即非并行分量），`P+S=100%`。`T(n)`为运行时间，处理器数量为`n`。有如下关系：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-dist-comp/img/86454eba352e51964934f55e3b4e8a1d.jpg)

这个公式转化成白话就是：在`n`个处理器上运行这个算法的时间大于等于，单处理器上运行序列分量的时间`S*T(1)`加上，并行分量在单处理器上运行的时间`P*T(1)`除以`n`。

当提高处理器的数量`n`，等式右边的第二项变得越来越小，与第一项对比，逐渐变得可以忽略不计。此时，这个公式近似于：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-dist-comp/img/f7dafcb057bf2643ae5143c22233f939.jpg)

这个公式转化成白话就是：在无限个处理器上运行这个算法的时间近似等于序列分量在单处理器上的运行时间`S*T(1)`。

现在，思考一下阿姆达尔定律的意义。此处的假定过于简单，通常，我们不能使算法完全并行化。

也就是说，大多情况下，我们不能让`S=0`。原因有很多：我们可能必须要拷贝数据和/或代码到不同的处理器可以访问的位置。我们可能必须要分隔数据，将数据块在网络中传输。可能要收集所有并发任务的结果，并进行进一步处理，等等。

无论原因是什么，如果不能使算法完全并行化，最终的运行时间取决于序列分量的表现。并行化的程度越高，加速表现越不明显。

题外话，完全并行通常称作密集并行（Embarrassingly parallel），或者用政治正确的话来说，愉悦并行（pleasantly parallel），它拥有最佳的扩展性能（速度与处理器的数量呈线性关系）。当然，对此不必感到尴尬！不幸的是，密集并行很少见。

让我们给阿姆达尔定律添加一些数字。假定，算法在单处理器耗时 100 秒。再假设，并行分量为 99%，这个数值已经很高了。添加处理器的数量以提高速度。来看以下计算：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-dist-comp/img/5adb7646fe369dc5138059ba43d682c4.jpg)

我们看到，随着`n`的提高，加速的效果不让人满意。使用 10 个处理器，是 9.2 倍速。使用 100 个处理器，则是 50 倍速。使用 1000 个处理器，仅仅是 91 倍速。

下图描述了倍速与处理器数量的关系。无论使用多少处理器，也无法大于 100 倍速，即运行时间小于 1 秒，即小于序列分量运行的时间。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-dist-comp/img/f10521e91fbe611e79a515c763ce64a5.jpg)

阿姆达尔定律告诉我们两点：我们最快可以将倍速提高到多少；收益减少时，何时应该减少硬件资源的投入。

另一有趣的地方是阿姆达尔定律适用于分布式系统和混合并行-分布式系统。这时，`n`等于所有计算机的处理器总数目。

随着能接触的系统的性能变得越来越高，如果能使用剩余性能，还可以缩短分布式算法运行的时间。

随着应用的的执行时间变短，我们就倾向于处理更复杂的问题。对于这样的算法进化，即问题规模的扩大（计算要求的扩大）达到可接受的性能时，称作古斯塔夫森定律。

## 混合范式

我们现在能买到的电脑大多是多处理器多核的，我们将要写的分布式应用就是要这样的电脑上运行。这使得我们可以既开发分布式计算，也可以开发并行式计算。这种混合分布-并行范式是如今开发网络分布应用的事实标准。现实通常是混合的。

## 总结

这一章讲了基础概念。我们学习了并行和分布式计算，以及两个架构的例子，探讨了优缺点。分析了它们是如何访问内存，并指出现实通常是混合的。最后讲了阿姆达尔定律，它对扩展性能的意义，硬件投入的经济考量。下一章会将概念转化为实践，并写 Python 代码！



# 二、异步编程 （Distributed Computing with Python）



从本章开始，终于开始写代码了！本书中所有的代码都适用于 Python 3.5 及以上版本。当模块、语句或语法结构不适用于以前的版本时（比如 Python 2.7），会在本章中指出。进行一些修改，本书代码也可以运行在 Python 2.x 版本上。

先回顾下上一章的知识。我们已经学到，改变算法的结构可以让其运行在本地计算机，或运行在集群上。即使是在一台计算机上运行，我们也可以使用多线程或多进程，让子程序运行在多个 CPU 上。

现在暂时不考虑多 CPU，先看一下单线程/进程。与传统的同步编程相比，异步编程或非阻塞编程，可以使性能获得极大提高。

任何包含多任务的程序，它的每个每个任务都在执行一个操作。我们可以把这些任务当做功能或方法，也可以把几个任务合并看做一个功能。例如，将总任务细分、在屏幕打印内容、或从网络抓取信息，等等。

看一下传统程序中的这些任务是如何使用一个 CPU 的。考虑一个原生的实例，它有四个任务：A、B、C、D。这些任务具体是做什么在这里不重要。我们可以假设这四个任务是关于计算和 I/O 操作的。安排这四个任务的最直观的方式是序列化。下图展示了这四个任务对 CPU 的使用：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-dist-comp/img/b4f82a8d10d21a7f3121ef2546af6042.jpg)

我们看到，当每个任务都执行 I/O 操作时，CPU 处于空闲状态，等待任务进行计算。这使得 CPU 大部分时间处于闲置状态。

重点是，从不同组件，例如硬盘、内存和网络，向 CPU 传递数据的速度相差极大（几个数量级）。

这就会造成任何进行大量 I/O 操作（访问硬盘、网络通讯等等）的代码都极有可能造成 CPU 大部分时间闲置，如上图所示。

理想的状态应该是安排一下任务，当一个任务等待 I/O 时，它处于悬停状态，就让另一个任务接管 CPU。这就是异步（也称为事件驱动）编程。

下图生动地展示了用异步编程的方式安排四个任务：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-dist-comp/img/d0f0737f027a7f1e5f82064d4d4ac94f.jpg)

任务仍然是序列的，但是不再各自占用 CPU 直到任务结束，任务不需要计算时，它们会自发地放弃 CPU。尽管 CPU 仍有闲置，程序的总运行时间明显缩短了。

使用多线程在不同的线程并行运行，也可以达到同样的效果。但是，有一个显著的不同：使用多线程时，是由操作系统决定哪个线程处于运行或悬停。然而，在异步编程中，每个任务可以自己决定是否放弃 CPU。

另外，单单使用异步编程，我们不能做出真正的并发：同一时间仅仅有一个任务在运行，消除了竞争条件。当然，我们可以混合使用多线程/多进程和异步编程。

另一点要注意的是，异步编程更善于处理 I/O 密集型任务，而不是 CPU 密集型任务（暂停任务不会使性能提高）。

## 协程

在 Python 中，让一个功能中途暂停的关键是使用协程。为了理解协程，先要理解生成器 generator，要理解生成器，先要理解迭代器 iterator。

大部分 Python 开发者都熟悉对类进行迭代（例如，字符串、列表、元组、文件对象等等）：

```py
>>> for i in range(3):
...     print(i)
...
1
2
>>> for line in open('exchange_rates_v1.py'):
...     print(line, end='')
... 
#!/usr/bin/env python3
import itertools
import time
import urllib.request
… 
```

我们可以将各种对象（不仅仅是列表和字符串）进行迭代的原因是**迭代协议**。迭代协议定义了迭代的标准格式：一个执行`__iter__`和`__next__`（或 Python 2.x 中的 `__iter__`和`next`）的对象就是一个迭代器，可以进行迭代操作，如下所示：

```py
class MyIterator(object):
    def __init__(self, xs):
        self.xs = xs

    def __iter__(self):
        return self

    def __next__(self):
        if self.xs:
            return self.xs.pop(0)
        else:
            raise StopIteration

for i in MyIterator([0, 1, 2]):
    print(i) 
```

结果如下所示：

```py
1
2
3 
```

我们能对`MyIterator`中的实例进行循环的原因是，它用`__iter__`和`__next__`方法，运行了迭代协议：前者返回了迭代的对象，后者逐个返回了序列中的元素。

为了进一步理解协议是如何工作的，我们手动分解这个循环，如下所示：

```py
itrtr = MyIterator([3, 4, 5, 6])

print(next(itrtr))
print(next(itrtr))
print(next(itrtr))
print(next(itrtr))

print(next(itrtr)) 
```

运行结果如下：

```py
3
4
5
6
Traceback (most recent call last):
  File "iteration.py", line 32, in <module>
    print(next(itrtr))
  File "iteration.py", line 19, in __next__
  raise StopIteration
StopIteration 
```

我们实例化了`MyIterator`，然后为了获取它的值，我们多次调用了`next()`。当序列到头时，`next()`会抛出异常`StopIteration`。Python 中的`for`循环使用了同样的机制，它调用迭代器的`next()`，通过获取异常`StopIteration`得知何时停止。

生成器就是一个 callable，它生成一个结果序列，而不是返回结果。这是通过产生（通过`yield`关键字）值而不是返回值，见下面的例子（generators.py）：

```py
def mygenerator(n):
    while n:
        n -= 1
        yield n

if __name__ == '__main__':
    for i in mygenerator(3):
        print(i) 
```

结果如下：

```py
2
1
0 
```

这是一个使用`yield`使`mygenerator`成为生成器的简单例子，它的功能并不简单。调用`generator`函数并不开始生成序列，只是产生一个`generator`对象，见如下 shell 语句：

```py
>>> from generators import mygenerator
>>> mygenerator(5)
<generator object mygenerator at 0x101267b48> 
```

为了激活`generator`对象，需要调用`next()`，见如下代码：

```py
>>> g = mygenerator(2)
>>> next(g)
1
>>> next(g)
0
>>> next(g)
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
StopIteration 
```

每个`next()`从生成的序列产生一个值，直到序列为空，也就是获得异常`StopIteration`时。迭代器的行为也是类似的。本质上，生成器是简化的迭代器，免去了定义类中`__iter__`和`__next__`的方法。

另外，生成器是一次性操作，不能重复生成的序列。若要重复序列，必须再次调用`generator`函数。

用来在`generator`函数中产生序列值的`yield`表达式，还可以在等号右边使用，以消除值。这样就可以得到协程。协程就是一类函数，它可以通过`yield`，在指定位置暂停或继续任务。

需要注意，尽管协程是强化的生成器，在概念意义上并不等于生成器。原因是，协程与迭代无关。另一不同点，生成器产生值，而协程消除值。

让我们做一些协程，看看如何使用。协程有三种主要的结构，如下所示：

*   `yield()`： 用来暂停协程的执行
*   `send()`： 用来向协程传递数据（以让协程继续执行）
*   `close()`：用来关闭协程

下面代码展示了协程的使用（coroutines.py）：

```py
def complain_about(substring):
    print('Please talk to me!')
    try:
        while True:
            text = (yield)
            if substring in text:
                print('Oh no: I found a %s again!'
                      % (substring))
    except GeneratorExit:
        print('Ok, ok: I am quitting.') 
```

我们先定义个一个协程，它就是一个函数，名字是`complain_about`，它有一个参数：一个字符串。打印一句话之后，进入一个无限循环，由`try except`控制退出，即只有通过异常才能退出。利用异常`GeneratorExit`，当获得这个异常时就会退出。

循环的主体十分简单，使用`yield`来获取数据，存储在变量`text`中。然后，我们检测`substring`是否在`text`中。如果在的话，弹出一条新语句。

下面代码展示了在 shell 中如何使用这个协程：

```py
>>> from coroutines import complain_about
>>> c = complain_about('Ruby')
>>> next(c)
Please talk to me!
>>> c.send('Test data')
>>> c.send('Some more random text')
>>> c.send('Test data with Ruby somewhere in it')
Oh no: I found a Ruby again!
>>> c.send('Stop complaining about Ruby or else!')
Oh no: I found a Ruby again!
>>> c.close()
Ok, ok: I am quitting. 
```

执行`complain_about('Ruby')`产生了协程。为了使用新建的协程，我们用`next()`调用它，与在生成器中所做的相同。只有调用`next()`之后，才在屏幕上看到**Please talk to me!**。

这时，协程到达了`text = (yield)`，意味着它暂停了执行。控制点返回了 shell，我们就可以向协程发送数据了。我们使用`send()`方法发送数据，如下所示：

```py
>>> c.send('Test data')
>>> c.send('Some more random text')
>>> c.send('Test data with Ruby somewhere in it')
Oh no: I found a Ruby again! 
```

每次调用`send()`方法都使代码到达下一个 yield。在我们的例子中，到达`while`循环的下一次迭代，返回`text = (yield)`。这里，控制点返回 shell。

我们可以调用`close()`方法停止协程，它可以在协程内部抛出异常`GeneratorExit`。此时，协程唯一能做的就是清理数据并退出。下面的代码展示了如何结束协程：

```py
>>> c.close()
Ok, ok: I am quitting. 
```

如果将`try except`部分注释掉，就不会获得`GeneratorExit`异常。但是协程还是会停止，如下所示：

```py
>>> def complain_about2(substring):
...     print('Please talk to me!')
...     while True:
...         text = (yield)
...         if substring in text:
...             print('Oh no: I found a %s again!'
...                   % (substring))
... 
>>> c = complain_about2('Ruby')
>>> next(c)
Please talk to me!
>>> c.close()
>>> c.send('This will crash')
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
StopIteration
>>> next(c)
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
StopIteration 
```

我们看到，一旦关闭协程，对象仍会保持，但是用途为零：不能向它发送数据，也不能调用`next()`使用它。

当使用协程时，许多人觉得必须要用`next()`很繁琐，转而使用装饰器，避免多余的调用，如下所示：

```py
>>> def coroutine(fn):
...     def wrapper(*args, **kwargs):
...         c = fn(*args, **kwargs)
...         next(c)
...         return c
...     return wrapper
... 
>>> @coroutine
... def complain_about2(substring):
...     print('Please talk to me!')
...     while True:
...         text = (yield)
...         if substring in text:
...             print('Oh no: I found a %s again!'
...                   % (substring))
... 
>>> c = complain_about2('JavaScript')
Please talk to me!
>>> c.send('Test data with JavaScript somewhere in it')
Oh no: I found a JavaScript again!
>>> c.close() 
```

协程的层级结构可以很复杂，可以让一个协程向其它多个协程发送数据，或从多个源接收数据。这在网络集群编程和系统编程中很有用（为了提高性能），可以用纯 Python 高效代替大多数 Unix 工具。

## 一个异步实例

为了简单又有趣，让我们写一个工具，可以对指定的文件，统计某个词的出现次数。使用之前的协程做基础，再添加一些功能。

在 Linux 和 Mac OS X 上，可以使用`grep`命令获得同样的结果。我们先下载一个大的文本文件，用作输入的数据。我们选择的是 Project Gutenberg 上列夫托尔斯泰所写的《战争与和平》，它的地址是[http://www.gutenberg.org/cache/epub/2600/pg2600.txt](https://link.jianshu.com?t=http://www.gutenberg.org/cache/epub/2600/pg2600.txt)。

下面代码展示了如何下载（译者注：win 上使用 Git Bash）：

```py
$ curl -sO http://www.gutenberg.org/cache/epub/2600/pg2600.txt
$ wc pg2600.txt
   65007  566320 3291648 pg2600.txt 
```

接下来，我们统计 love 一词出现的次数，忽略大小写，如下所示（译者注：会有编码问题）：

```py
$ time (grep -io love pg2600.txt | wc -l)
677
(grep -io love pg2600.txt) 0.11s user 0.00s system 98% cpu 0.116 total 
```

现在使用 Python 的协程来做（grep.py）：

```py
def coroutine(fn):
    def wrapper(*args, **kwargs):
        c = fn(*args, **kwargs)
        next(c)
        return c
    return wrapper

def cat(f, case_insensitive, child):
    if case_insensitive:
        line_processor = lambda l: l.lower()
    else:
        line_processor = lambda l: l

    for line in f:
        child.send(line_processor(line))

@coroutine
def grep(substring, case_insensitive, child):
    if case_insensitive:
        substring = substring.lower()
    while True:
        text = (yield)
        child.send(text.count(substring))

@coroutine
def count(substring):
    n = 0
    try:
        while True:
            n += (yield)
    except GeneratorExit:
        print(substring, n)

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('-i', action='store_true',
                        dest='case_insensitive')
    parser.add_argument('pattern', type=str)
    parser.add_argument('infile', type=argparse.FileType('r'))

    args = parser.parse_args()

    cat(args.infile, args.case_insensitive,
        grep(args.pattern, args.case_insensitive,
             count(args.pattern))) 
```

分析代码之前，我们先运行一下，和`grep`进行比较：

```py
$ time python3.5 grep.py -i love pg2600.txt
love 677
python3.5 grep.py -i love pg2600.txt  0.09s user 0.01s system 97% cpu 0.097 total 
```

可以看到，使用协程的纯 Python 版本与使用`grep`和`wc`命令的 Unix 相比，十分具有竞争力。当然，Unix 的`grep`命令远比 Python 版本强大。不能简单宣称 Python 比 C 语言快！但是，Python 的结果也是让人满意的。

来分析下代码。首先，再次执行`coroutine`的装饰器。之后，将总任务分解成三块：

*   逐行读取文件（通过`cat`函数）
*   统计每行中`substring`的出现次数（`grep`协程）
*   求和并打印数据（`count`协程）

在脚本文件的主体部分，我们解析命令行选项，将`cat`结果传给`grep`，将`grep`结果传给`count`，就像操作普通的 Unix 工具。

实现这个链条极其简单。我们将接收数据的协程当做参数（前面例子的`child`），传递给产生数据的函数或协程。然后，在数据源中，调用协程的`send`方法。

第一个函数`cat`，作为整个函数的数据源，它逐行读取文件，将每行发送给`grep`
（`child.send(line)`）。如果匹配是大小写不敏感的，不需要进行转换；如果大小写敏感，则都转化为小写。

`grep`命令是我们的第一个协程。这里，进入一个无限循环，持续获取数据（`text = (yield)`），统计`substring`在`text`中的出现次数，，将次数发送给写一个协程（即`count`）：`child.send(text.count(substring)))`。

`count`协程用总次数`n`，从`grep`获取数据，对总次数进行求和，`n += (yield)`。它捕获发送给各个协程关闭时的`GeneratorExit`异常（在我们的例子中，到达文件最后就会出现异常），以判断何时打印这个`substring`和`n`。

当把协程组织为更复杂的结构时，会更有趣。比如，我们可以统计多个单词出现的次数。

下面的代码展示了一种这样做的方法，通过一个额外的协程负责广播，将输入数据发送给任意数目的子协程（`mgrep.py`）：

```py
def coroutine(fn):
    def wrapper(*args, **kwargs):
        c = fn(*args, **kwargs)
        next(c)
        return c
    return wrapper

def cat(f, case_insensitive, child):
    if case_insensitive:
        line_processor = lambda l: l.lower()
    else:
        line_processor = lambda l: l

    for line in f:
        child.send(line_processor(line))

@coroutine
def grep(substring, case_insensitive, child):
    if case_insensitive:
        substring = substring.lower()
    while True:
        text = (yield)
        child.send(text.count(substring))

@coroutine
def count(substring):
    n = 0
    try:
        while True:
            n += (yield)
    except GeneratorExit:
        print(substring, n)

@coroutine
def fanout(children):
    while True:
        data = (yield)
        for child in children:
            child.send(data)

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('-i', action='store_true', dest='case_insensitive')
    parser.add_argument('patterns', type=str, nargs='+',)
    parser.add_argument('infile', type=argparse.FileType('r'))

    args = parser.parse_args()

    cat(args.infile, args.case_insensitive,
        fanout([grep(p, args.case_insensitive,
                     count(p)) for p in args.patterns])) 
```

代码看上去和之前的例子差不多。让我们分析一下差别。我们定义了一个广播器：`fanout`。`fanout()`协程使用一列协程作为输入，自身位于一个无限循环中。当收到数据后（`data = (yield)`），便将数据分发给注册的协程（`for child in children: child.send(data)`）。

不用修改`cat`、`grep`、`count`的代码，我们就可以利用原有的代码来搜索任意个数的字符串了！

它的性能依旧很好，如下所示：

```py
$ time python3.5 mgrep.py -i love hate hope pg2600.txt
hate 103
love 677
hope 158
python3.5 mgrep.py -i love hate hope pg2600.txt  0.16s user 0.01s system 98% cpu 0.166 total 
```

## 总结

Python 从 1.5.2 版本之后引入了`asyncore`和`asynchat`模块，开始支持异步编程。2.5 版本引入了`yield`，可以向协程传递数据，简化了代码、加强了性能。Python 3.4 引入了一个新的库进行异步 I/O，称作`asyncio`。

Python 3.5 通过`async def`和`await`，引入了真正的协程类型。感兴趣的读者可以继续研究 Python 的新扩展。一句警告：异步编程是一个强大的工具，可以极大地提高 I/O 密集型代码的性能。但是异步编程也是存在问题的，而且还相当复杂。

任何异步代码都要精心选择非阻塞的库，以防使用阻塞代码。并且要运行一个协程规划期（因为 OS 不能像规划线程一样规划协程），包括写一个事件循环和其它事务。读异步代码会有一定困难，即使我们的最简单的例子也很难一眼看懂。所以，一定要小心！



# 三、Python 的并行计算 （Distributed Computing with Python）



我们在前两章提到了线程、进程，还有并发编程。我们在很高的层次，用抽象的名词，讲了如何组织代码，已让其部分并发运行，在多个 CPU 上或在多台机器上。

本章中，我们会更细致的学习 Python 是如何使用多个 CPU 进行并发编程的。具体目标是加速 CPU 密集型任务，提高 I/O 密集型任务的反馈性。

好消息是，使用 Python 的标准库就可以进行并发编程。这不是说不用第三方的库或工具。只是本章中的代码仅仅利用到了 Python 的标准库。

本章介绍如下内容：

*   多线程
*   多进程
*   多进程队列

## 多线程

Python 从 1.4 版本开始就支持多线程了。它在`threading`模块中还提供了一个高级界面给系统本地（Linux 和 Mac OS X 中的**POSIX**）线程，本章的例子会使用`threading`。

要注意在单 CPU 系统中，使用多线程并不是真正的并发，在给定时间只有一个线程在运行。只有在多 CPU 计算机上，线程才是并发的。本章假设使用的计算机是多处理器的。

让我们写一个简单的例子，使用多线程从网络下载数据。使用你的编辑器，新建一个 Python 文件，`currency.py`，代码如下：

```py
from threading import Thread
from queue import Queue
import urllib.request

URL = 'http://finance.yahoo.com/d/quotes.csv?s={}=X&f=p'
def get_rate(pair, outq, url_tmplt=URL):
    with urllib.request.urlopen(url_tmplt.format(pair)) as res:
        body = res.read()
    outq.put((pair, float(body.strip())))

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('pairs', type=str, nargs='+')
    args = parser.parse_args()

    outputq = Queue()
    for pair in args.pairs:
        t = Thread(target=get_rate,
                   kwargs={'pair': pair,
                           'outq': outputq})
        t.daemon = True
        t.start()

    for _ in args.pairs:
        pair, rate = outputq.get()
        print(pair, rate)
        outputq.task_done()
    outputq.join() 
```

这段代码十分简单。我们先从标准库引入需要的模块（`threading`、`queue`、`urllib.request`）。然后定义一个简单的函数`get_rate`，用以得到货币对（即 EURUSD 代表欧元兑美元，CHFAUS 代表瑞士法郎兑澳元），和一个线程安全型队列（即，一个 Python 的`queue`模块`Queue`实例），用以链接 Yahoo!Finance，并下载最新的汇率。

调用 Yahoo!Finance API 会返回包括数字的白文本（或者一个包含信息的 CSV 文件）。这意味着，我们不必解析 HTML，直接可以在文本中找到需要的汇率。

此段代码使用了`argparse`模块，解析命令行参数。然后构造了一个队列（`outputq`），来保存各个线程下载的汇率的数据。一旦有了输出队列，我们就可以为每个汇率对新建一个工作线程。每个线程运行`get_rate`函数，使用汇率对和输出队列作为参数。

因为这些线程只是`fire`和`forget`线程，可以将它们做成守护进程，也就是说，Python 主程序退出时不会等待它们退出（进程术语`join`）。

正确理解最后的守护进程和队列是十分重要的。使用线程的最大难点是，我们无法判断某个线程何时进行读取或写入与其它线程共享的数据。

这就会造成所谓的**竞争条件**。一方面，系统的正确执行取决于某些动作按顺序执行；另一方面，不能保证这些动作按照这些动作按照设计的顺序执行。

竞争条件的一个简单例子是引用计数算法。引用计数中，垃圾回收解释器如**CPython**（Python 的标准解释器），每个对象都有一个计数器，用于跟踪引用的次数。

每一次引用一个对象时，对应的计数器增加 1。每一次删除一个引用时，计数器减 1。当计数器为 0 时，对象就被删除了。尝试使用被删除的对象，会发生语法错误。

这意味着，我们必须强制给计数器的增加和减少添加一个顺序。设想两个线程获取一个对象的引用一段时间，然后删除。如果两个线程在同一时间访问同一个引用计数器，它们就会复写值，如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-dist-comp/img/601bc2e6fa6d96465b323529a5ac5eb7.jpg)

解决此类同步问题的方法之一是使用锁。线程安全队列是一个简易的使用锁数据结构的例子，使用它可以组织数据的访问。

因为每个线程都向同一个输出队列写入，我们最好监督队列，好知道何时有了结果，进而退出。在前面的代码中，我们的实现方法是从每个汇率对的队列取出一个结果（`args.pairs`循环），等待队列来加入（`outputq。join()`），即取得多有数据之后（更准确的，当每个`get()`方法之后都调用`task_done()`）。这样，就可以保证程序不提前退出。

尽管这个代码只是示例，没有进行查错、重试、处理缺省值或无效数值，它仍然是一个有用的、以队列为基础的架构。但是，要记住，使用锁的队列控制数据访问、避免竞争条件，取决于应用，可能花费很高。

下图展示了这个例子的架构，有三个工作线程，用以获取三个汇率值的数据，并将名字和数值存储到输出队列：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-dist-comp/img/e53cbb56e7bc9a8dface881f1b4125a0.jpg)

当然，我们可以不用线程，依次调用`get_rate()`函数取得每个汇率值。打开 Python shell，我们可以如下实现：

```py
>>> from currency import get_rate
>>> import queue
>>> from time import time
>>> q = queue.Queue()
>>> pairs = ('EURUSD', 'GBPUSD', 'CHFEUR')
>>> t0 = time(); [get_rate(p, q) for p in pairs]; dt = time() - t0
[None, None, None]
>>> dt
1.1785249710083008
>>> [q.get() for p in pairs]
[('EURUSD', 1.1042), ('GBPUSD', 1.5309), ('CHFEUR', 0.9176)] 
```

每次使用一个请求，取得三个汇率，耗时 1.2 秒。

让我们运行下使用线程的例子：

```py
$ time python3.5 currency.py EURUSD GBPUSD CHFEUR
EURUSD 1.1042
GBPUSD 1.5309
CHFEUR 0.9176
python3.5 currency.py EURUSD GBPUSD CHFEUR  0.08s user 0.02s system 26% cpu 0.380 total 
```

后者总耗时 0.4 秒，为什么它的速度是前者的三倍呢？原因是，使用线程，可以并行运行三个请求。当然，还有一个主线程和队列（根据阿姆达尔定律，它们都属于序列分量），但是通过并发，还是使性能得到了极大提高。另外，我们可以像上一章一样，在单 CPU 上使用协程和非阻塞 socket。

让我们看另一个例子，虽然使用了线程，性能却没有提高。用下面的代码新建一个文件（`fib.py`）：

```py
from threading import Thread

def fib(n):
    if n <= 2:
        return 1
    elif n == 0:
        return 0
    elif n < 0:
        raise Exception('fib(n) is undefined for n < 0')
    return fib(n - 1) + fib(n - 2)

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('-n', type=int, default=1)
    parser.add_argument('number', type=int, nargs='?', default=34)
    args = parser.parse_args()

    assert args.n >= 1, 'The number of threads has to be > 1'
    for i in range(args.n):
        t = Thread(target=fib, args=(args.number,))
        t.start() 
```

这段代码很好理解。先引入线程模块，然后让每个线程计算斐波那契额数`args.number`。我们并不关心斐波那契额数（不进行存储），只是想进行一些 CPU 密集型计算，计算菲波那切数列是一个很好的例子。

用不同并发程度，运行这个例子，如下所示：

```py
$ time python3.5 ./fib.py -n 1 34
python3.5 ./fib.py -n 1 34  2.00s user 0.01s system 99% cpu 2.013 total
$ time python3.5 ./fib.py -n 2 34
python3.5 ./fib.py -n 2 34  4.38s user 0.04s system 100% cpu 4.414 total
$ time python3.5 ./fib.py -n 3 34
python3.5 ./fib.py -n 3 34  6.28s user 0.08s system 100% cpu 6.354 total
$ time python3.5 ./fib.py -n 4 34
python3.5 ./fib.py -n 4 34  8.47s user 0.11s yousystem 100% cpu 8.541 total 
```

有趣的是，当用两个线程计算前 34 个斐波那契数时，耗时是单线程的两倍。增加线程的数目，会线性的增加耗时。很明显，并行运行的线程发生了错误。

Python 底层有个东西影响着我们的 CPU 制约型进程，它就是全局锁（Global Interpreter Lock）。正如它的名字，全局锁控制引用计数始终合理。尽管 Python 的线程是 OS 原生的，全局锁却使特定时间只有一个是运行的。

有人会说 Python 是单线程的，这并不正确。但也不全部错误。刚刚我们看到的，和之前的协程很像。在协程的例子中，在给定时间只有一段代码才能运行，当一个协程或进程等待 I/O 时，让另一个运行 CPU，也可以达到并发的效果。当一个任务需要占用 CPU 大量时间时，就像菲波那切数列这个 CPU 制约型任务，就不会有多大提高。

与协程很像，在 Python 中使用线程是可取的。并行 I/O 可以极大提高性能，无论是对多线程还是协程。GUI 应用也可以从使用线程受益，一个线程可以处理更新 GUI，另一个在后台运行，而不必使前台死机。只需要注意全局锁，做好应对。另外，并不是所有 Python 解释器都有全局锁，**Jython**就没有。

## 多进程

传统上，Python 开发者为了避免全局锁对 CPU 制约型线程的影响，使用的是多进程而不是多线程。多进程有一些缺点，它必须启动 Python 的多个实例，启动时间长，耗费内存多。

同时，使用多进程并行运行任务，有一些极好的优点。

多进程有它们各自的内存空间，使用的是无共享架构，数据访问十分清晰。也更容易移植到分布式系统中。

Python 的标准库中有两个模块，可以用来实现并行进程，两个模块都很优秀。其中之一是`multiprocessing`，另一个是`concurrent.futures`。`concurrent.futures`模块构建在`multiprocessing`和`threading`模块之上，提供更优的功能。

我们在下一个例子中使用的是`concurrent.futures`。Python 2.x 用户可以用外部包的方式安装，即`futures`。

我们还是使用之前的菲波那切数列例子，这次使用多进程。同时，会快速介绍`concurrent.futures`模块。

使用下面代码新建一个文件（`mpfib.py`）：

```py
import concurrent.futures as cf

def fib(n):
    if n <= 2:
        return 1
    elif n == 0:
        return 0
    elif n < 0:
        raise Exception('fib(n) is undefined for n < 0')
    return fib(n - 1) + fib(n - 2)

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('-n', type=int, default=1)
    parser.add_argument('number', type=int, nargs='?', default=34)
    args = parser.parse_args()

    assert args.n >= 1, 'The number of threads has to be > 1'
    with cf.ProcessPoolExecutor(max_workers=args.n) as pool:
        results = pool.map(fib, [args.number] * args.n) 
```

这段代码很紧凑，也很易读。看一下它与多线程的不同，我们得到命令行参数之后，创建了一个`ProcessPoolExecutor`实例，调用它的`map()`方法进行并行计算。

根据直觉，我们建立了一个工作进程池`args.n`，使用这个进程池对每个输入（`args.number`重复`args.n`次）执行`fib`函数，以并行方式运行（取决于 CPU 的数目）。

（在一个四处理器的计算机上）运行这段代码，结果如下：

```py
$ time python3.5 ./mpfib.py -n 1 34
python3.5 ./mpfib.py -n 1 34  1.89s user 0.02s system 99% cpu 1.910 total
$ time python3.5 ./mpfib.py -n 2 34
python3.5 ./mpfib.py -n 2 34  3.76s user 0.02s system 196% cpu 1.928 total
$ time python3.5 ./mpfib.py -n 3 34
python3.5 ./mpfib.py -n 3 34  5.70s user 0.03s system 291% cpu 1.964 total
$ time python3.5 ./mpfib.py -n 4 34
python3.5 ./mpfib.py -n 4 34  7.71s user 0.03s system 386% cpu 2.006 total 
```

我们看到，在四处理器的计算机上运行时，可以实现真正的并行，运行一次到四次，时间差不多。

进程数比处理器数目多时，性能会急剧下降，如下所示：

```py
$ time python3.5 ./mpfib.py -n 8 34
python3.5 ./mpfib.py -n 8 34  30.23s user 0.06s system 755% cpu 4.011 total
$ time python3.5 ./mpfib.py -n 16 34
python3.5 ./mpfib.py -n 16 34  63.78s user 0.13s system 758% cpu 8.424 total 
```

再看一下代码的最后两行，这里的内容不少。首先，使用`concurrent.futures`模块导出的`ProcessPoolExecutor`类。它是被导出的两个类之一，另一个是`ThreadPoolExecutor`，用它来建立线程池，而不是进程池。

`ProcessPoolExecutor`和`ThreadPoolExecutor`有相同的 API（实际上，二者都是同一个类的子类），它们有三个主要方法，如下：

*   `submit(f, *args, **kwargs)`：用来规划异步调用`f(*args, **kwargs)`，并返回一个`Future`实例作为结果占位符。
*   `map(f, *arglist, timeout=None, chunksize=1)`：它等价于内建的`(f, *arglist)`方法，它返回的是一个列表的`Future`对象，而不是`map`那样的结果。

第三种方法`shutdown(wait=True)`用来当所有`Executor`对象运行完毕时，释放资源。之前，则一直在等待（`if wait=True`）。运行这个方法之后再使用`Executor`对象，会抛出`RuntimeError`异常。

`Executor`对象还可以用来当做上下文管理（context manager），正如例子中，使用`cf.ProcessPoolExecutor(max_workers=args.n)`构建`pool`。上下文管理退出时，会默认阻塞调用`Executor shutdown`方法。这意味着，一旦上下文管理退出，我们访问`results`列表只会得到一些整数而不是`Future`实例。

`Future`实例是`concurrent.futures`包导出的另一个主要的类，它是异步调用的结果占位符。我们可以用它检测是否调用仍在运行，是否抛出异常，等等。我们调用一个`Future`实例的`result()`方法，来访问它的值。

不用上下文管理，再来运行一下这个例子。这样，就可以观察运行的`Future`类。结果如下：

```py
>>> from mpfib import fib
>>> from concurrent.futures import ProcessPoolExecutor
>>> pool = ProcessPoolExecutor(max_workers=1)
>>> fut = pool.submit(fib, 38)
>>> fut
<Future at 0x101b74128 state=running>
>>> fut.running()
True
>>> fut.done()
False
>>> fut.result(timeout=0)
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "/Library/Frameworks/Python.framework/Versions/3.5/lib/python3.5/concurrent/futures/_base.py", line 407, in result
    raise TimeoutError()
concurrent.futures._base.TimeoutError
>>> fut.result(timeout=None)
39088169
>>> fut
<Future at 0x101b74128 state=finished returned int>
>>> fut.done()
True
>>> fut.running()
False
>>> fut.cancelled()
False
>>> fut.exception() 
```

这里，我们看到如何使用`concurrent.futures`包创建工作池（使用`ProcessPoolExecutor`类），并给它分配工作（`pool.submit(fib, 38)`）。正如所料，`submit`返回了一个`Future`对象（代码中的`fut`），它是还没产生结果时的占位符。

我们检测`fut`以确认它的状态，运行（`fut.running()`），完毕（`fut.done()`），取消（`fut.cancelled()`）。如果没有产生结果（`fut.result(timeout=0)`），就检测，会抛出异常`TimeoutError`。意味着，我们必须要么等待`Future`对象可用，或不设置超时的情况下，询问它的值。这就是我们做的，`fut.result(timeout=None)`，它会一直等待`Future`对象。因为代码没有错误，`fut.exception()`返回的是`None`。

我们可以只修改一行多进程的例子代码，就将它编程多线程的，将`ProcessPoolExecutor`换成`ThreadPoolExecutor`。快速写一个例子，将之前的例子（`mpfib.py`），更换下行：

```py
with cf. ProcessPoolExecutor (max_workers=args.n) as pool: 
```

为：

```py
with cf.ThreadPoolExecutor(max_workers=args.n) as pool: 
```

新文件（`mtfib.py`）的性能和之前的`fib.py`的性能差不多，如下所示：

```py
$ time python3.5 ./mtfib.py -n 1 34 
python3.5 ./mtfib.py -n 1 34  2.04s user 0.01s system 99% cpu 2.059 total
$ time python3.5 ./mtfib.py -n 2 34
python3.5 ./mtfib.py -n 2 34  4.43s user 0.04s system 100% cpu 4.467 total
$ time python3.5 ./mtfib.py -n 3 34
python3.5 ./mtfib.py -n 3 34  6.69s user 0.06s system 100% cpu 6.720 total
$ time python3.5 ./mtfib.py -n 4 34
python3.5 ./mtfib.py -n 4 34  8.98s user 0.10s system 100% cpu 9.022 total 
```

## 多进程队列

多进程要解决的问题是，如何在工作进程之间交换数据。`multiprocessing`模块提供的方法是队列和管道。接下来，我们来看多进程队列。

`multiprocessing.Queue` 类是按照`queue.Queue`类建模的，不同之处是多进程队列中的 items 要求是可选取的。为了展示如何使用队列，新建一个文件（`queues.py`），它的代码如下：

```py
import multiprocessing as mp

def fib(n):
    if n <= 2:
        return 1
    elif n == 0:
        return 0
    elif n < 0:
        raise Exception('fib(n) is undefined for n < 0')
    return fib(n - 1) + fib(n - 2)

def worker(inq, outq):
    while True:
        data = inq.get()
        if data is None:
            return
        fn, arg = data
        outq.put(fn(arg))

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('-n', type=int, default=1)
    parser.add_argument('number', type=int, nargs='?', default=34)
    args = parser.parse_args()

    assert args.n >= 1, 'The number of threads has to be > 1'

    tasks = mp.Queue()
    results = mp.Queue()
    for i in range(args.n):
        tasks.put((fib, args.number))

    for i in range(args.n):
        mp.Process(target=worker, args=(tasks, results)).start()

    for i in range(args.n):
        print(results.get())

    for i in range(args.n):
        tasks.put(None) 
```

到这里，你应该对代码很熟悉了。我们还是用递归方法计算计算菲波那切数列。我们使用两个队列的架构，一个队列运行任务（调用函数和参数），另一个队列保存结果（整数）。

在任务队列中使用一个哨兵值（`None`），给工作进程发消息，好让其退出。工作进程是一个简单的`multiprocessing.Process`实例，它的目标是`worker`函数。

这个队列的例子的性能和无队列例子（`mpfib.py`）的性能相同，如下所示：

```py
$ time python3.5 ./queues.py -n 1 34
5702887
python3.5 ./queues.py -n 1 34  1.87s user 0.02s system 99% cpu 1.890 total
$ time python3.5 ./queues.py -n 4 34
5702887 (repeated 4 times)
python3.5 ./queues.py -n 4 34  7.66s user 0.03s system 383% cpu 2.005 total
$ time python3.5 ./queues.py -n 8 34
5702887 (repeated 8 times)
python3.5 ./queues.py -n 8 34  30.46s user 0.06s system 762% cpu 4.003 total 
```

对于我们的例子，添加几个队列不会产生明显的性能下降。

## 一些思考

开发并行应用的主要难点就是控制数据访问，避免竞争条件或篡改共享数据。有时，发生异常很容易发现错误。其他时候，就不容易发现，程序持续运行，但结果都是错的。

检测程序和内部函数是很重要的。对于并行应用，检测更为重要，因为想要建立一个逻辑图十分困难。

并行开发的另一难点是，要明确何时停止。阿姆达尔定律指出，并行开发是收益递减的。并行化可能耗时巨大。一定要知道，哪段代码是需要并行化的，理论加速上限又是多少。

只有这样，我们才能知道何时该停止继续投入。其它时候，使用现存的并行库（如 Numpy），可以提供更好的收益。

另外，避免收益递减的方法是增加任务量，因为计算机的性能是不断提高的。

当然，随着任务量增大，创建、协调、清洗的贡献就变小了。这是古斯塔夫森定律的核心。

## 总结

我们学习了一些可以让 Python 加速运行或是在多个 CPU 上运行的方法。其一是使用多线程，另一个是多进程。这两个都是 Python 的标准库支持的。

我们学习了三个模块：开发多线程应用的`threading`，开发并行多进程的`multiprocessing`，还有更高级的异步模块`concurrent.futures`。

随着技术的发展，Python 中开发并行应用不仅只有这三个模块。其它的包封装了并行策略，可以解放开发者。可能，最有名的就是 NumPy，Python 处理 array 和 matrix 标准包。依赖 BLAS 库，NumPy 可以用多线程加速运行复杂运算（比如矩阵的点乘）。

`multiprocessing`模块可以让 Python 运行在计算机集群上。特别的，它有几个`Manager`类（即`BaseManager`和`SyncManager`）。它使用 socket 服务器管理数据和队列，并在网络中共享。感兴趣的读者可以继续阅读多进程模块的文档[https://docs.python.org/3/library/multiprocessing.html#managers](https://link.jianshu.com?t=https://docs.python.org/3/library/multiprocessing.html#managers)。

另一个值得关注的是 Cython，一个类似 Python 的原因，它可以建立`C`模块，现在非常流行。Cython 对**OpenMP**（一个基于指令的 C、C++、Fortran 的 API）支持很好，可以让开发者方便地使用多线程。



# 四、Celery 分布式应用 （Distributed Computing with Python）



本章是前面某些知识点的延续。特别的，本章以实例详细的探讨了异步编程和分布式计算。本章关注**Celery**，一个复杂的用于构建分布应用的 Python 框架。最后，对比了 Celery 的对手：`Pyro`和`Python-RQ`。

此时，你应该已经明白了并行、分布和异步编程的基本含义。如果没有的话，最好再学习下前面几章。

## 搭建多机环境

学习 Celery 和其它 Python 包之前，先来搭建测试环境。我们开发的是分布应用，因此需要多机环境。

可以使用至少两台联网机器的读者可以跳过这部分。其余读者，请继续阅读。对于后者，仍然有免费或便宜的解决方案。

其一是在主机上使用虚拟机 VM（例如 VirtualBox，[https://www.virtualbox.org](https://link.jianshu.com?t=https://www.virtualbox.org/)）。创建几个 VM，安装 Linux，让它们在后台运行。因为它们不需要图像化桌面，所以可以很轻量，使用少量 RAM 和 CPU 即可。

另一方法是买几个便宜的小型计算机主板，比如树莓派（[https://www.raspberrypi.org](https://link.jianshu.com?t=https://www.raspberrypi.org/)），在它上面安装 Linux，连上局域网。

第三种方案是用云服务器，比如 Amazon EC2，使用它的虚拟机。如果使用这种方法，要确认这些包的端口在防火墙是打开的。

无论是用哪种方法，紧跟着的问题就是没有在集群上安装完整的 DNS。最便捷的方法是在所有机器上编辑`/etc/hosts`文件。查看 IP 地址，为每台机器起一个名字，并将它们添加到`/etc/hosts`。

我在 Mac 主机上使用了两个虚拟机，这是我的 hosts 文件：

```py
$ cat /etc/hosts
##
# Host Database
#
# localhost is used to configure the loopback interface
# when the system is booting.  Do not change this entry.
##
127.0.0.1 localhost
255.255.255.255 broadcasthost
::1             localhost 
fe80::1%lo0 localhost

# Development VMs
192.168.123.150 ubuntu1 ubuntu1.local
192.168.123.151 ubuntu2 ubuntu2.local 
```

相似的，这是我的两个虚拟机（运行 Ubuntu 15.04）上的 host 文件：

```py
$ cat /etc/hosts
127.0.0.1 localhost
192.168.123.151 ubuntu2
192.168.123.150 ubuntu1

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters 
```

你要确保 hosts 文件上的 IP 地址和名字是要使用的机器。本书，会命名这些机器命名为 HOST1、HOST2、HOST3 等等。

搭建好多机环境之后，就可以开始写分布应用了。

## 安装 Celery

目前为止，我们用的都是 Python 的标准库，Celery（[http://www.celeryproject.org](https://link.jianshu.com?t=http://www.celeryproject.org/)）是用到的第一个第三方库。Celery 是一个分布任务队列，就是一个以队列为基础的系统，和之前的某些例子很像。它还是分布式的，意味着工作进程和保存结果的和请求的队列，在不同机器上。

首先安装 Celery 和它的依赖。在每台机器上建立一个虚拟环境（起名为`book`），代码如下（环境是 Unix）：

```py
$ pip install virtualenvwrapper 
```

如果这个命令被拒绝，可以加上`sudo`，用超级用户权限来安装`virtualenvwrapper`，代码如下：

```py
$ sudo pip install virtualenvwrapper 
```

`sudo`命令会向你询问 Unix 用户密码。或者，可以用下面代码安装`virtualenvwrapper`：

```py
$ pip install --user virtualenvwrapper 
```

不管使用哪种方法，完成安装`virtualenvwrapper`之后，都需要配置它，定义三个环境变量（用于 bash 类的 shell，假定`virtualenvwrapper`安装在`/usr/local/bin`）：

```py
$ export WORKON_HOME=$HOME/venvs
$ export PROJECT_HOME=$HOME/workspace
$ source /usr/local/bin/virtualenvwrapper.sh 
```

你需要修改前置路径，来决定虚拟环境所在的位置（`$WORKON_HOME`）和代码的根目录（`$PROJECT_HOME`）。`virtualenvwrapper.sh`的路径也可能需要变动。这三行代码最好添加到相关的 shell 启动文件（例如，`~/.bashrc`或`~/.profile`）。

做好了前面的设置，我们就可以创建要使用的虚拟环境了，如下所示：

```py
$ mkvirtualenv book --python=`which python3.5` 
```

这个命令会在`$WORKON_HOME`之下建立新的虚拟环境，名字是`book`，使用的是 Python 3.5。以后，可以用下面命令启动这个虚拟环境：

```py
$ workon book 
```

使用虚拟环境的好处是，可以在里面安装所有需要的包，而不污染系统的 Python。以后不再需要这个虚拟环境时，可以方便的删除（参考`rmvirtualenv`命令）。

现在就可以安装 Celery 了。和以前一样，（在每台机器上）使用`pip`：

```py
$ pip install celery 
```

该命令可以在激活的虚拟环境中下载、解压、安装所有的依赖。

快完成了，现在只需安装配置一个中间代理，Celery 用它主持任务队列，并向工作进程（只有一台机器，HOST1）发送消息。从文档中可以看到，Celery 支持多种中间代理，包括**SQLAlchemy**（[http://www.sqlalchemy.org](https://link.jianshu.com?t=http://www.sqlalchemy.org/)），用以本地开发和测试。这里推荐使用的中间代理是**RabbitMQ**（[https://www.rabbitmq.com](https://link.jianshu.com?t=https://www.rabbitmq.com/)）。

[https://www.rabbitmq.com](https://link.jianshu.com?t=https://www.rabbitmq.com/)上有安装指导、文档和下载。在 Mac 主机上，安装的最简方法是使用**homebrew**（[http://brew.sh](https://link.jianshu.com?t=http://brew.sh/)），如下所示：

```py
$ brew install rabbitmq 
```

对于 Windows 用户，最好使用官方的安装包。对于 Linux，官方也提供了安装包。

安装好**RabbitMQ**之后，就可以立即使用了。这里还有一个简单的配置步骤，因为在例子中，访问队列不会创建用户和密码。只要编辑 RabbitMQ 的配置文件（通常位于`/usr/local/etc/rabbitmq/rabbitmq.config`），添加下面的条目，允许网络中的默认`guest`账户：

```py
[
  {rabbit, [{loopback_users, []}]}
]. 
```

手动启动 RabbitMQ，如下所示（服务器脚本可能不在`$PATH`环境，通常存储在`/usr/local/sbin`）：

```py
$ sudo rabbitmq-server 
```

`sudo`会向你询问用户密码。对于我们的例子，我们不会进一步配置中间代理，使用默认访客账户就行。

> 注意：感兴趣的读者可以在[http://www.rabbitmq.com/admin-guide.html](https://link.jianshu.com?t=http://www.rabbitmq.com/admin-guide.html)阅读 RabbitMQ 的管理指导。

到这里，我们就安装好了所有需要的东西，可以开始使用 Celery 了。有另外一个依赖，也值得考虑安装，尽管不是严格需要的，尤其是我们只想使用 Celery。它是结果后台，即 Celery 的工作进程用其存储计算的结果。它就是 Redis（[http://redis.io](https://link.jianshu.com?t=http://redis.io/)）。安装 Redis 是非必须的，但极力推荐安装，和 RabbitMQ 类似，Redis 运行在另一台机器上，称作 HOST2。

Redis 的安装十分简单，安装代码适用于 Linux，Mac OS X 和 Windows。我们在 Mac 上用 homebrew 安装，如下：

```py
$ brew install redis 
```

在其它操作系统上，例如 Linux，可以方便的用二进制码安装（例如对于 Ubuntu，`sudo apt-get install redis-server`）。

启动 Redis 的命令如下：

```py
$ sudo redis-server 
```

本章剩下的部分会假定结果后台存在，如果没有安装，会到时指出配置和代码的不同。同时，任何在生产环境中使用 Celery 的人，都应该考虑使用结果后台。

## 测试安装

快速尝试一个例子，以验证 Celery 是正确安装的。我们需要四个终端窗口，三个不同的机器（命名为 HOST1、HOST2、HOST3 和 HOST4）。在 HOST1 的窗口启动 RabbitMQ（确保`rabbitmq-server`路径正确）：

```py
HOST1 $ sudo /usr/local/sbin/rabbitmq-server 
```

在 HOST2 的窗口，启动 Redis（没安装的话，跳到下一段）：

```py
HOST2 $ sudo /usr/local/bin/redis-server 
```

最后，在 HOST3 的窗口，创建如下 Python 文件（记得使用`workon book`激活虚拟环境），命名为`test.py`：

```py
import celery

app = celery.Celery('test',
                        broker='amqp://HOST1',
                        backend='redis://HOST2')

@app.task
def echo(message):
    return message 
```

这段代码很简单。先引入了`Celery`包，然后定义了一个 Celery 应用（`app`），名字是`test`。这个应用使用 HOST1 的中间代理 RabbitMQ 和 HOST2 的 Redis 数据库的默认账户和消息队列。

要是想用 RabbitMQ 作为结果后台而不用 Redis，需要修改前面的代码，将`backend`进行如下修改：

```py
import celery

app = celery.Celery('test',
                        broker='amqp://HOST1',
                        backend=amqp://HOST1')

@app.task
def echo(message):
    return message 
```

有了应用实例，就可以用它装饰远程的 worker（使用装饰器`@app.task`）。在这个例子中，我们装饰一个简单的函数，它可以返回传递给它的消息（`echo`）。

之后，在终端 HOST3，建立 worker 池，如下所示：

```py
HOST3 $ celery -A test worker --loglevel=info 
```

记得要在`test.py`的目录（或将`PYTHONPATH`环境变量指向`test.py`的目录），好让 Celery 可以引入代码。

`celery`命令会默认启动 CPU 数目相同的 worker 进程。worker 会使用`test`模块中的应用`app`（我们可以使用实例的名字`celery -A test.app worker`），并使用`INFO`等级在控制台显示日志。在我的电脑上（有`HyperThreading`的四核电脑），Celery 默认启用了八个 worker 进程。

在 HOST4 终端，复制`test.py`代码，启动`book`虚拟环境，在`test.py`目录打开 Python shell，如下所示：

```py
HOST4 $ python3.5
Python 3.5.0 (v3.5.0:374f501f4567, Sep 12 2015, 11:00:19)
[GCC 4.2.1 (Apple Inc. build 5666) (dot 3)] on darwin
Type "help", "copyright", "credits" or "license" for more information. 
```

从复制的`test`模块引入`echo`函数，如下：

```py
>>> from test import echo 
```

我们现在可以像普通 Python 函数一样调用`echo`，`echo`可以直接在本地（即 HOST4）运行，如下所示：

```py
>>> res = echo('Python rocks!')
>>> print(res)
Python rocks! 
```

为了让 HOST3 的 worker 进程运行`echo()`函数，我们不能像之前那样直接调用。我们需要调用它的`delay`方法（装饰器`@app.task`注入的），见下面的命令：

```py
>>> res = echo.delay('Python rocks!'); print(type(res)); print(res)
<class 'celery.result.AsyncResult'>
1423ec2b-b6c7-4c16-8769-e62e09c1fced
>>> res.ready()
True
>>> res.result
'Python rocks!' 
```

我们看到，调用`echo.delay('Python rocks!')`不会返回字符串。相反，它在任务队列（运行在 HOST1 的 RabbitMQ 服务器）中安排了一个请求以执行`echo`函数，并返回`Future`，准确的说是`AsyncResult`（Celery 的 Future）。正如`concurrent.futures`模块，这个对象是一个异步调用结果的占位符。在我们的例子中，异步调用的是我们安插在任务队列的`echo`函数，调用它的是其它位置的 Celery 的 worker 进程（我们的例子中是 HOST3）。

我们可以查询`AsyncResult`对象来确定它们是否预备好。如果是的话，我们可以访问它们的结果，在我们的例子中是字符串'Python rocks!'。

切换到启用 worker 进程的窗口，我们可以看到 worker 池接收到了`echo`任务请求，如下所示：

```py
[2015-11-10 08:30:12,869: INFO/MainProcess] Received task: test.echo[1423ec2b-b6c7-4c16-8769-e62e09c1fced]
[2015-11-10 08:30:12,886: INFO/MainProcess] Task test.echo[1423ec2b-b6c7-4c16-8769-e62e09c1fced] succeeded in 0.01469148206524551s: 'Python rocks!' 
```

我们现在可以退出 Python shell 和 worker 进程（在发起`celery worker`命令的终端窗口按`CTRL+C`）：Celery 安装成功。

## Celery 介绍

什么是分布式任务队列，Celery 是怎么运行分布式任务队列的呢？分布式任务队列这种架构已经存在一定时间了。这是一种 master-worker 架构，有一个中间件层，中间件层使用多个任务请求队列（即任务队列），和一个用于存储结果的队列（即结果后台）。

主进程（也叫作`client`或`producer`）将任务请求安插到某个任务队列，从结果后台获取数据。worker 进程订阅任务队列以明确任务是什么，并把结果放到结果后台。

这是一个简单灵活的架构。主进程不需要知道有多少个可用的 worker，也不需要知道 worker 运行在哪台机器。它只需要知道队列在哪，以及如何发送任务请求。

worker 进程也是如此。它们不需要知道任务请求来自何处，也不需要知道结果用来做什么。它们只需知道从哪里取得任务，存储在哪里。

这样的优点是 worker 的数量、种类、形态可以随意变化，而不对总系统的功能产生影响（但会影响性能和延迟）。分布式任务队列可以方便地进行扩展（添加新 worker），规划优先级（给队列定义不同的优先级，给不同的队列安排不同数量的 worker）。

另一个优点是，这个去耦合化的系统在原则上，worker 和 producer 可以用不同语言来写。例如，Python 代码生成的工作由 C 语言写的 worker 进程来做，这样性能是最高的。

Celery 使用了第三方、健壮的、实地验证的系统来做它的队列和结果后台。推荐的中间代理是 RabbitMQ，我们之前用过。RabbitMQ 是一个非常复杂的消息代理，有许多特性，本书不会对它做深入探索。结果后台也是如此，它可以是一个简单的 RabbitMQ 队列，或者更优的，使用专门的服务比如 Redis。

下图展示了典型的使用 RabbitMQ 和 Redis 的 Celery 应用架构：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-dist-comp/img/3a8cdc68a0ec86521bbf2a6893207e33.jpg)

每个方框中的进程（即 RabbitMQ、Redis、worker 和`master.py`）都可以运行在不同的机器上。小型的安装方案是将 RabbitMQ 和 Redis 放在同一个主机上，worker 几点可能只有一个或两个。大型方案会使用更多的机器，或者专门的服务器。

## 更复杂的 Celery 应用

我们用 Celery 做两个简单有趣的应用。第一个仿照第 3 章中汇率例子，第二个是一个分布式排序算法。

我们还是使用四台机器（HOST1、HOST2、HOST3、HOST4）。和以前一样，HOST1 运行 RabbitMQ，HOST2 运行 Redis，HOST3 运行 Celery 的 worker，HOST 运行主代码。

先从简单的例子开始。创建一个 Python 文件（`celery/currency.py`），代码如下（如果你没有使用 Redis，记得修改`backend`成`'amqp://HOST1'`）：

```py
import celery
import urllib.request

app = celery.Celery('currency',
                    broker='amqp://HOST1',
                    backend='redis://HOST2')

URL = 'http://finance.yahoo.com/d/quotes.csv?s={}=X&f=p'

@app.task
def get_rate(pair, url_tmplt=URL):
    with urllib.request.urlopen(url_tmplt.format(pair)) as res:
        body = res.read()
    return (pair, float(body.strip()))

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('pairs', type=str, nargs='+')
    args = parser.parse_args()

    results = [get_rate.delay(pair) for pair in args.pairs]
    for result in results:
        pair, rate = result.get()
        print(pair, rate) 
```

这段代码和第 3 章的多线程版本差不多。主要的区别是，因为使用的是 Celery，我们不需要创建队列，Celery 负责建立队列。另外，除了为每个汇率对建一个线程，我们只需让 worker 负责从队列获取任务请求，执行相应的函数请求，完毕之后返回结果。

探讨调用的行为是有益的，比如成功的调用、由于缺少 worker 而不工作的调用、失败且抛出异常的调用。我们从成功的调用开始。

和`echo`的例子一样，在各自的终端启动 RabbitMQ 和 Redis（通过`redis-server`和`rabbitmq-server`命令）。

然后，在 worker 主机（HOST3）上，复制`currency.py`文件，切换到它的目录，创建 worker 池（记住，Celery 启动的 worker 数目尽可能和 CPU 核数一样多）：

```py
HOST3 $ celery -A currency worker --loglevel=info 
```

最后，复制相同的文件到 HOST4，并运行如下：

```py
HOST4 $ python3.5 currency.py EURUSD CHFUSD GBPUSD GBPEUR CADUSD CADEUR
EURUSD 1.0644
CHFUSD 0.986
GBPUSD 1.5216
GBPEUR 1.4296
CADUSD 0.751
CADEUR 0.7056 
```

一切工作正常，我么得到了五个汇率。如果查看启动 worker 池的主机（HOST3），我们会看到类似下图的日志：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-dist-comp/img/f9bae4de200bc467877102a3888206d8.jpg)

这是日志等级`loglevel=info`时，Celery worker 的日志。每个任务都被分配了一个独立 ID（例如 GBP 兑 USD 的任务 ID 是 f8658917-868c-4eb5-b744-6aff997c6dd2），基本的时间信息也被打印了出来。

如果没有可用的 worker 呢？最简单的方法是停止 worker（在终端窗口按`CTRL+C`），返回 HOST4 的`currency.py`，如下所示：

```py
OST4 $ python3.5 currency.py EURUSD CHFUSD GBPUSD GBPEUR CADUSD CADEUR 
```

什么都没发生，`currency.py`一直处于等待 worker 的状态。这样的状态可能也可能不是我们想要的：其一，让文件等待而不发生崩溃，是很方便的；其二，我们可能想在一定时间后，停止等待。可以在`result.get()`用`timeout`参数。

例如，修改代码，使用`result.get(timeout=1)`，会有如下结果（还是在没有 worker 的情况下）：

```py
HOST4 $ python3.5 currency.py EURUSD CHFUSD GBPUSD GBPEUR CADUSD CADEUR
 Traceback (most recent call last):
  File "currency.py", line 29, in <module>
    pair, rate = result.get(timeout=1)
  File "/venvs/book/lib/python3.5/site-packages/celery/result.py", line 169, in get
    no_ack=no_ack,
  File " /venvs/book/lib/python3.5/site-packages/celery/backends/base.py", line 226, in wait_for
    raise TimeoutError('The operation timed out.')
celery.exceptions.TimeoutError: The operation timed out. 
```

当然，我们应该总是使用超时，以捕获对应的异常，作为错误处理的策略。

要记住，默认下，任务队列是持续的，它的日志不会停止（Celery 允许用户定制）。这意味着，如果我们现在启动了一些 worker，它们就会开始从队列获取悬挂的任务，并返回结果。我们可以用如下命令清空队列：

```py
HOST4 $ celery purge
WARNING: This will remove all tasks from queue: celery.
         There is no undo for this operation!

(to skip this prompt use the -f option)

Are you sure you want to delete all tasks (yes/NO)? yes
Purged 12 messages from 1 known task queue. 
```

接下来看任务产生异常的情况。修改 HOST3 的`currency.py`文件，让`get_rate`抛出一个异常，如下所示：

```py
@app.task
def get_rate(pair, url_tmplt=URL):
    raise Exception('Booo!') 
```

现在，重启 HOST3 的 worker 池（即`HOST3 $ celery -A currency worker --loglevel=info`），然后在 HOST4 启动主程序：

```py
HOST4 $ python3.5 currency.py EURUSD CHFUSD GBPUSD GBPEUR CADUSD CADEUR
Traceback (most recent call last):
  File "currency.py", line 31, in <module>
    pair, rate = result.get(timeout=1)
  File "/Users/fpierfed/Documents/venvs/book/lib/python3.5/site-packages/celery/result.py", line 175, in get
    raise meta['result']
Exception: Booo! 
```

所有的 worker 都抛出了异常，异常传递到了调用的代码，在首次调用`result.get()`返回。

任务抛出任何异常，我们都要小心。远程运行的代码失败的原因可能有很多，不一定和代码本身有关，因此需要谨慎应对。

Celery 可以用如下的方法提供帮助：我们可以用`timeout`获取结果；重新提交失败的任务（参考`task`装饰器的`retry`参数）。还可以取消任务请求（参考任务的`apply_async`方法的`expires`参数，它比之前我们用过的`delay`功能强大）。

有时，任务图会很复杂。一项任务的结果还要传递给另一个任务。Celery 支持复杂的调用方式，但是会有性能损耗。

用第二个例子来探讨：一个分布式的归并排序算法。这是包含两个文件的长代码：一个是算法本身（`mergesory.py`），一个是主代码（`main.py`）。

归并排序是一个简单的基于递归二分输入列表的算法，将两个部分排序，再将结果合并。建立一个新的 Python 文件（`celery/mergesort.py`），代码如下：

```py
import celery

app = celery.Celery('mergesort',
                        broker='amqp://HOST1',
                        backend='redis://HOST2')

@app.task
def sort(xs):
    lenxs = len(xs)
    if(lenxs <= 1):
        return(xs)

    half_lenxs = lenxs // 2
    left = xs[:half_lenxs]
    right = xs[half_lenxs:]
    return(merge(sort(left), sort(right)))

def merge(left, right):
    nleft = len(left)
    nright = len(right)

    merged = []
    i = 0
    j = 0
    while i < nleft and j < nright:
        if(left[i] < right[j]):
            merged.append(left[i])
            i += 1
        else:
            merged.append(right[j])
            j += 1
    return merged + left[i:] + right[j:] 
```

这段代码很直白。Celery 应用命名为`app`，它使用 RabbitMQ 作为任务队列，使用 Redis 作为结果后台。然后，定义了`sort`算法，它使用了附属的`merge`函数以合并两个排好序的子列表，成为一个排好序的单列表。

对于主代码，另建一个文件（`celery/main.py`），它的代码如下：

```py
#!/usr/bin/env python3.5
import random
import time
from celery import group
from mergesort import sort, merge

# Create a list of 1,000,000 elements in random order.
sequence = list(range(1000000))
random.shuffle(sequence)

t0 = time.time()

# Split the sequence in a number of chunks and process those 
# independently.
n = 4
l = len(sequence) // n
subseqs = [sequence[i * l:(i + 1) * l] for i in range(n - 1)]
subseqs.append(sequence[(n - 1) * l:])

# Ask the Celery workers to sort each sub-sequence.
# Use a group to run the individual independent tasks as a unit of work.
partials = group(sort.s(seq) for seq in subseqs)().get()

# Merge all the individual sorted sub-lists into our final result.
result = partials[0]
for partial in partials[1:]:
    result = merge(result, partial)

dt = time.time() - t0
print('Distributed mergesort took %.02fs' % (dt))

# Do the same thing locally and compare the times.
t0 = time.time()
truth = sort(sequence)
dt = time.time() - t0
print('Local mergesort took %.02fs' % (dt))

# Final sanity checks.
assert result == truth
assert result == sorted(sequence) 
```

我们先生成一个足够长的无序（`random.shuffle`）整数序列（`sequence = list(range(1000000))`）。然后，分成长度相近的子列表（`n=4`）。

有了子列表，就可以对它们进行并行处理（假设至少有四个可用的 worker）。问题是，我们要知道什么时候这些列表排序好了，好进行合并。

Celery 提供了多种方法让任务协同执行，`group`是其中之一。它可以在一个虚拟的任务里，将并发的任务捆绑执行。`group`的返回值是`GroupResult`（与类`AsyncResult`的层级相同）。如果没有结果后台，`GroupResult get()`方法是必须要有的。当组中所有的任务完成并返回值，`group`方法会获得一个任务签名（用参数调用任务`s()`方法，比如代码中的`sort.s(seq)`）的列表。任务签名是 Celery 把任务当做参数，传递给其它任务（但不执行）的机制。

剩下的代码是在本地合并排好序的列表，每次合并两个。进行完分布式排序，我们再用相同的算法重新排序原始列表。最后，对比归并排序结果与内建的`sorted`调用。

要运行这个例子，需要启动 RabbitMQ 和 Redis。然后，在 HOST3 启动一些 worker，如下所示：

```py
HOST3 $ celery -A mergesort worker --loglevel=info 
```

记得拷贝`mergesort.py`文件，并切换到其目录运行（或者，定义`PYTHONPATH`指向它所在的位置）。

之后，在 HOST4 上运行：

```py
HOST4 $ python3.5 main.py
Distributed mergesort took 10.84s
Local mergesort took 26.18s 
```

查看 Celery 日志，我们看到 worker 池接收并执行了 n 个任务，结果发回给了 caller。

性能和预想的不一样。使用多进程（使用`multiprocessing`或`concurrent.futures`）来运行，与前面相比，可以有 n 倍的性能提升（7 秒，使用四个 worker）。

这是因为 Celery 同步耗时长，最好在只有不得不用的时候再使用。Celery 持续询问组中的部分结果是否准备好，好进行后续的工作。这会非常消耗资源。

## 生产环境中使用 Celery

下面是在生产环境中使用 Celery 的 tips。

第一个建议是在 Celery 应用中使用配置模块，而不要在 worker 代码中进行配置。假设，配置文件是`config.py`，可以如下将其传递给 Celery 应用：

```py
import celery
app = celery.Celery('mergesort')
app.config_from_object('config') 
```

然后，与其他可能相关的配置指令一起，在`config.py`中添加：

```py
BROKER_URL = 'amqp://HOST1'
CELERY_RESULT_BACKEND = 'redis://HOST2' 
```

关于性能的建议是，使用至少两个队列，好让任务按照执行时间划分优先级。使用多个队列，将任务划分给合适的队列，是分配 worker 的简便方法。Celery 提供了详尽的方法将任务划分给队列。分成两步：首先，配置 Celery 应用，启动 worker，如下所示：

```py
# In config.py
CELERY_ROUTES = {project.task1': {'queue': 'queue1'},
                    'project.task2': {'queue': 'queue2'}} 
```

为了在队列中启动 worker，在不同的机器中使用下面的代码：

```py
HOST3 $ celery –A project worker –Q queue1
HOST5 $ celery –A project worker –Q queue2 
```

使用 Celery 命令行工具的`-c`标志，可以控制 worker 池的大小，例如，启动一个有八个 worker 的池：

```py
HOST3 $ celery –A project worker –c 8 
```

说道 worker，要注意，Celery 默认使用多进程模块启动 worker 池。这意味着，每个 worker 都是一个完整的 Python 进程。如果某些 worker 只处理 I/O 密集型任务，可以将它们转换成协程或多线程，像前面的例子。这样做的话，可以使用`-P`标志，如下所示：

```py
$ celery –A project worker –P threads 
```

使用线程和协程可以节省资源，但不利于 CPU 制约型任务，如前面的菲波那切数列的例子。

谈到性能，应该尽量避免同步原语（如前面的`group()`），除非非用不可。当同步无法回避时，好的方法是使用结果后台（如 Redis）。另外，如果可能的话，要避免传递复杂的对象给远程任务，因为这些对象需要序列化和去序列化，通常很耗时。

额外的，如果不需要某个任务的结果，应该确保 Celery 不去获取这些结果。这是通过装饰器`@task(ignore_result=True)`来做的。如果所有的任务结果都忽略了，就不必定义结果后台。这可以让性能大幅提高。

除此之外，还要指出，如何启动 worker、在哪里运行 worker、如何确保它们持续运行是很重要的。默认的方法是使用工具，例如**supervisord** ([http://supervisord.org](https://link.jianshu.com?t=http://supervisord.org/)) ，来管理 worker 进程。

Celery 带有一个 supervisord 的配置案例（在安装文件的`extra/supervisord`目录）。一个监督的优秀方案是**flower**([https://github.com/mher/flower](https://link.jianshu.com?t=https://github.com/mher/flower))，一个 worker 的网络控制和监督工具。

最后，RabbitMQ 和 Redis 结合起来，是一个很好的中间代理和结果后台解决方案，适用于大多数项目。

## Celery 的替代方案：Python-RQ

Celery 的轻量简易替代方案之一是 Python-RQ ([http://python-rq.org](https://link.jianshu.com?t=http://python-rq.org/))。它单单基于 Redis 作为任务队列和结果后台。没有复杂任务或任务路由，使用它很好。

因为 Celery 和 Python-RQ 在概念上很像，让我们立即重写一个之前的例子。新建一个文件（`rq/currency.py`），代码如下：

```py
import urllib.request

URL = 'http://finance.yahoo.com/d/quotes.csv?s={}=X&f=p'

def get_rate(pair, url_tmplt=URL):
    # raise Exception('Booo!')

    with urllib.request.urlopen(url_tmplt.format(pair)) as res:
        body = res.read()
    return (pair, float(body.strip())) 
```

这就是之前的汇率例子的代码。区别是，与 Celery 不同，这段代码不需要依赖 Python-RQ 或 Redis。将这段代码拷贝到 worker 节点（HOST3）。

主程序也同样简单。新建一个 Python 文件（rq/main.py），代码如下：

```py
#!/usr/bin/env python3
import argparse
import redis
import rq
from currency import get_rate

parser = argparse.ArgumentParser()
parser.add_argument('pairs', type=str, nargs='+')
args = parser.parse_args()

conn = redis.Redis(host='HOST2')
queue = rq.Queue(connection=conn)

jobs = [queue.enqueue(get_rate, pair) for pair in args.pairs]

for job in jobs:
    while job.result is None:
        pass
    print(*job.result) 
```

我们在这里看到 Python-RQ 是怎么工作的。我们需要连接 Redis 服务器（HOST2），然后将新建的连接对象传递给`Queue`类构造器。结果`Queue`对象用来向其提交任务请求。这是通过传递函数对象和其它参数给`queue.enqueue`。

函数排队调用的结果是`job`实例，它是个异步调用占位符，之前见过多次。

因为 Python-RQ 没有 Celery 的阻塞`AsyncResult.get()`方法，我们要手动建一个事件循环，持续向`job`实例查询，以确认是否它们的`result`不是`None`这种方法不推荐在生产环境中使用，因为持续的查询会浪费资源，查询不足会浪费时间，但对于这个简易例子没有问题。

为了运行代码，首先要安装 Python-RQ，用 pip 进行安装：

```py
$ pip install rq 
```

在所有机器上都要安装。然后，在 HOST2 运行 Redis：

```py
$ sudo redis-server 
```

在 HOST3 上，启动一些 worker。Python-RQ 不自动启动 worker 池。启动多个 worker 的简易的方法是使用一个文件（`start_workers.py`）：

```py
#!/usr/bin/env python3
import argparse
import subprocess

def terminate(proc, timeout=.5):
    """
    Perform a two-step termination of process `proc`: send a SIGTERM
    and, after `timeout` seconds, send a SIGKILL. This should give 
    `proc` enough time to do any necessary cleanup.
    """
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
    return

parser = argparse.ArgumentParser()
parser.add_argument('N', type=int)
args = parser.parse_args()

workers = []
for _ in range(args.N):
    workers.append(subprocess.Popen(['rqworker',
                                            '-u', 'redis://yippy']))
try:
    running = [w for w in workers if w.poll() is None]
    while running:
        proc = running.pop(0)
        try:
            proc.wait(timeout=1.)
        except subprocess.TimeoutExpired:
            running.append(proc)
except KeyboardInterrupt:
    for w in workers:
        terminate(w) 
```

这个文件会启动用户指定书目的 Python-RQ worker 进程（通过使用`rqworker`脚本，Python-RQ 源码的一部分），通过`Ctrl+C`杀死进程。更健壮的方法是使用类似之前提过的 supervisord 工具。

在 HOST3 上运行：

```py
HOST3 $ ./start_workers.py 6 
```

现在可以运行代码。在 HOST4，运行`main.py`：

```py
HOST4 $ python3.5 main.py EURUSD CHFUSD GBPUSD GBPEUR CADUSD CADEUR
EURUSD 1.0635
CHFUSD 0.9819
GBPUSD 1.5123
GBPEUR 1.422
CADUSD 0.7484
CADEUR 0.7037 
```

效果与 Celery 相同。

## Celery 的替代方案：Pyro

Pyro ([http://pythonhosted.org/Pyro4/](https://link.jianshu.com?t=http://pythonhosted.org/Pyro4/))的意思是 Python Remote Objects，是 1998 年创建的一个包。因此，它十分稳定，且功能完备。

Pyro 使用的任务分布方法与 Celery 和 Python-RQ 十分不同，它是在网络中将 Python 对象作为服务器。然后创建它们的代理对象，让调用代码可以将其看做本地对象。这个架构在 90 年代末的系统很流行，比如 COBRA 和 Java RMI。

Pyro 掩盖了代码中的对象是本地还是远程的，是让人诟病的一点。原因是，远程代码运行错误的原因很多，当远程代码隐藏在代理对象后面执行，就不容易发现错误。

另一个诟病的地方是，Pyro 在点对点网络（不是所有主机名都可以解析）中，或者 UDP 广播无效的网络中，很难正确运行。

尽管如此，大多数开发者认为 Pyro 非常简易，在生产环境中足够健壮。

Pyro 安装很简单，它是纯 Python 写的，依赖只有几个，使用 pip：

```py
$ pip install pyro4 
```

这个命令会安装 Pyro 4.x 和 Serpent，后者是 Pyro 用来编码和解码 Python 对象的序列器。

用 Pyro 重写之前的汇率例子，要比用 Python-RQ 复杂，它需要另一个软件：Pyro nameserver。但是，不需要中间代理和结果后台，因为 Pyro 对象之间可以直接进行通讯。

Pyro 运行原理如下。每个远程访问的对象都封装在处于连接监听的 socket 服务器框架中。每当调用远程对象中的方法，被调用的方法，连同它的参数，就被序列化并发送到适当的对象/服务器上。此时，远程对象执行被请求的任务，经由相同的连接，将结果发回到（同样是序列化的）调用它的代码。

因为每个远程对象自身就可以调用远程对象，这个架构可以是相当去中心化的。另外，一旦建立通讯，对象之间就是 p2p 的，这与分布式任务队列的轻度耦合架构十分不同。另一点，每个远程对象既可以做 master，也可以做 worker。

接下来重写汇率的例子，来看看具体是怎么运行的。建立一个 Python 文件（`pyro/worker.py`），代码如下：

```py
import urllib.request
import Pyro4

URL = 'http://finance.yahoo.com/d/quotes.csv?s={}=X&f=p'

@Pyro4.expose(instance_mode="percall")
class Worker(object):
    def get_rate(self, pair, url_tmplt=URL):
        with urllib.request.urlopen(url_tmplt.format(pair)) as res:
            body = res.read()
        return (pair, float(body.strip()))

# Create a Pyro daemon which will run our code.
daemon = Pyro4.Daemon()
uri = daemon.register(Worker)
Pyro4.locateNS().register('MyWorker', uri)

# Sit in an infinite loop accepting connections
print('Accepting connections')
try:
    daemon.requestLoop()
except KeyboardInterrupt:
    daemon.shutdown()
print('All done') 
```

worker 的代码和之前的很像，不同点是将`get_rate`函数变成了`Worker`类的一个方法。变动的原因是，Pyro 允许导出类的实例，但不能导出函数。

剩下的代码是 Pyro 特有的。我们需要一个`Daemon`实例（它本质上是后台的网络服务器），它会获得类，并在网络上发布，好让其它的代码可以调用方法。分成两步来做：首先，创建一个类`Pyro4.Daemon`的实例，然后添加类，通过将其传递给`register`方法。

每个 Pyro 的`Daemon`实例可以隐藏任意数目的类。内部，需要的话，`Daemon`对象会创建隐藏类的实例（也就是说，如果没有代码需要这个类，相应的`Daemon`对象就不会将其实例化）。

每一次网络连接，`Daemon`对象默认会实例化一次注册的类，如果要进行并发任务，这样就不可以。可以通过装饰注册的类修改，`@Pyro4.expose(instance_mode=...)`。

`instance_mode`支持的值有三个：`single`、`session`和`percall`。使用`single`意味`Daemon`只为类创建一个实例，使用它应付所有的客户请求。也可以通过注册一个类的实例（而不是类本身）。

使用`session`可以采用默认模式：每个 client 连接都会得到一个新的实例，client 始终都会使用它。使用`instance_mode="percall"`，会为每个远程方法调用建立一个新实例。

无论创建实例的模式是什么，用`Daemon`对象注册一个类（或实例）都会返回一个唯一的识别符（即 URI），其它代码可以用识别符连接对象。我们可以手动传递 URI，但更方便的方法是在 Pyro nameserver 中存储它，这样通过两步来做。先找到 nameserver，然后给 URI 注册一个名字。在前面的代码中，是通过下面来做的：

```py
Pyro4.locateNS().register('MyWorker', uri) 
```

nameserver 的运行类似 Python 的字典，注册两个名字相同的 URI，第二个 URI 就会覆盖第一个。另外，我们看到，client 代码使用存储在 nameserver 中的名字控制了许多远程对象。这意味着，命名需要特别的留意，尤其是当许多 worker 进程提供的功能相同时。

最后，在前面的代码中，我们用`daemon.requestLoop()`进入了一个`Daemon`事件循环。`Daemon`对象会在无限循环中服务 client 的请求。

对于 client，创建一个 Python 文件（`pyro/main.py`），它的代码如下：

```py
#!/usr/bin/env python3
import argparse
import time
import Pyro4

parser = argparse.ArgumentParser()
parser.add_argument('pairs', type=str, nargs='+')
args = parser.parse_args()

# Retrieve the rates sequentially.
t0 = time.time()
worker = Pyro4.Proxy("PYRONAME:MyWorker")

for pair in args.pairs:
    print(worker.get_rate(pair))
print('Sync calls: %.02f seconds' % (time.time() - t0))

# Retrieve the rates concurrently.
t0 = time.time()
worker = Pyro4.Proxy("PYRONAME:MyWorker")
async_worker = Pyro4.async(worker)

results = [async_worker.get_rate(pair) for pair in args.pairs]
for result in results:
    print(result.value)
print('Async calls: %.02f seconds' % (time.time() - t0)) 
```

可以看到，client 把相同的工作做了两次。这么做的原因是展示 Pyro 两种调用方式：同步和异步。

来看代码，我们使用`argparse`包从命令行获得汇率对。然后，对于同步的方式，通过名字`worker = Pyro4.Proxy("PYRONAME:MyWorker")`获得了一些远程`worker`对象。前缀`PYRONAME:`告诉 Pyro 在 nameserver 中该寻找哪个名字。这样可以避免手动定位 nameserver。

一旦有了`worker`对象，可以把它当做本地的`worke`r 类的实例，向其调用方法。这就是我们在第一个循环中做的：

```py
for pair in args.pairs:
    print(worker.get_rate(pair)) 
```

对每个`worker.get_rate(pair)`声明，Proxy 对象会用它的远程`Daemon`对象连接，发送请求，以运行`get_rate(pair)`。我们例子中的`Daemon`对象，每次会创建一个`Worker`类的的实例，并调用它的`get_rate(pair)`方法。结果序列化之后发送给 client，然后打印出来。每个调用都是同步的，任务完成后会封锁。

在第二个循环中，做了同样的事，但是使用的是异步调用。我们需要向远程的类创建一个 Proxy 对象，然后，将它封装在一个异步 handler 中。这就是下面代码的功能：

```py
worker = Pyro4.Proxy("PYRONAME:MyWorker")
async_worker = Pyro4.async(worker) 
```

我们现在可以在后台用`async_worker`获取汇率。每次调用`async_worker.get_rate(pair)`是非阻塞的，会返回一个`Pyro4.futures.FutureResult`的实例，它和`concurrent.futures`模块中`Future`对象很像。访问它的`value`需要等待，直到相应的异步调用完成。

为了运行这个例子，需要三台机器的三个窗口：一个是 nameserver（HOST1），一个是`Worker`类和它的 Daemon（HOST2），第三个（HOST3）是 client（即`main.py`）。

在第一个终端，启动 nameserver，如下：

```py
HOST1 $ pyro4-ns --host 0.0.0.0
Broadcast server running on 0.0.0.0:9091
NS running on 0.0.0.0:9090 (0.0.0.0)
Warning: HMAC key not set. Anyone can connect to this server!
URI = PYRO:Pyro.NameServer@0.0.0.0:9090 
```

简单来说，nameserver 绑定为 0.0.0.0，任何人都可以连接它。我们没有设置认证，因此在倒数第二行弹出了一个警告。

nameserver 运行起来了，在第二个终端启动 worker：

```py
HOST2 $ python3.5 worker.py
Accepting connections 
```

让`Daemon`对象接收连接，现在去第三个终端窗口运行 client 代码，如下：

```py
HOST3 $ python3.5 main.py EURUSD CHFUSD GBPUSD GBPEUR CADUSD CADEUR
('EURUSD', 1.093)
('CHFUSD', 1.0058)
('GBPUSD', 1.5141)
('GBPEUR', 1.3852)
('CADUSD', 0.7493)
('CADEUR', 0.6856)
Sync calls: 1.55 seconds
('EURUSD', 1.093)
('CHFUSD', 1.0058)
('GBPUSD', 1.5141)
('GBPEUR', 1.3852)
('CADUSD', 0.7493)
('CADEUR', 0.6856)
Async calls: 0.29 seconds 
```

结果和预想一致，IO 限制型代码可以方便的进行扩展，异步代码的速度六倍于同步代码。

这里，还有几个提醒。第一是，Pyro 的`Daemon`实例要能解析主机的名字。如果不能解析，那么它只能接受 127.0.0.1 的连接，这意味着，不能被远程连接（只能本地连接）。解决方案是将其与运行的主机进行 IP 绑定，确保它不是环回地址。可以用下面的 Python 代码选择一个可用的 IP：

```py
from socket import gethostname, gethostbyname_ex

ips = [ip for ip in gethostbyname_ex(gethostname())[-1] 
        if ip != '127.0.0.1']
ip = ips.pop() 
```

另一个要考虑的是：作为 Pyro 使用“直接连接被命名对象”方法的结果，很难像 Celery 和 Python-RQ 那样直接启动一批 worker。在 Pyro 中，必须用不同的名字命名 worker，然后用名字进行连接（通过代理）。这就是为什么，Pyro 的 client 用一个 mini 的规划器来向可用的 worker 分配工作。

另一个要注意的是，nameserver 不会跟踪 worker 的断开，因此，用名字寻找一个 URI 对象不代表对应的远程`Daemon`对象是真实运行的。最好总是这样对待 Pyro 调用：远程服务器的调用可能成功，也可能不成功。

记住这些点，就可以用 Pyro 搭建复杂的网络和分布式应用。

## 总结

这一章很长。我们学习了 Celery，他是一个强大的包，用以构建 Python 分布式应用。然后学习了 Python-RQ，一个轻量且简易的替代方案。两个包都是使用分布任务队列架构，它是用多个机器来运行相同系统的分布式任务。

然后介绍了另一个替代方案，Pyro。Pyro 的机理不同，它使用的是代理方式和远程过程调用（RPC）。

两种方案都有各自的优点，你可以选择自己喜欢的。

下一章会学习将分布式应用部署到云平台，会很有趣。

