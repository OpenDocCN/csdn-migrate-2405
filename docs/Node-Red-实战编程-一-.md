# Node-Red 实战编程（一）

> 原文：[`zh.annas-archive.org/md5/C5AA5862C03AC3F75583D0632C740313`](https://zh.annas-archive.org/md5/C5AA5862C03AC3F75583D0632C740313)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

Node-RED 是由 Node.js 制作的基于流的编程工具。这个工具主要用于连接物联网设备和软件应用程序。然而，它不仅可以涵盖物联网，还可以涵盖标准的 Web 应用程序。

Node-RED 正在扩展为一个无代码/低代码编程工具。本书涵盖了如何使用它的基础知识，包括从 1.2 版本发布的新功能，以及高级教程。

# 这本书适合谁

这本书最适合那些第一次学习无代码/低代码编程工具的软件编程人员。Node-RED 是一个基于流的编程工具，这个工具可以轻松构建任何软件应用程序的 Web 应用程序，如物联网数据处理，标准 Web 应用程序，Web API 等。因此，这本书将帮助 Web 应用程序开发人员和物联网工程师。

# 本书涵盖的内容

第一章《介绍 Node-RED 和基于流的编程》教会我们什么是 Node-RED。内容还涉及基于流的编程，解释了为什么开发了 Node-RED 以及它的用途。了解这个新工具 Node-RED 有助于改善我们的编程经验。

第二章《设置开发环境》涵盖了通过安装 Node-RED 设置开发环境。Node-RED 可以安装在 Node.js 可以运行的任何操作系统上，如 Windows，macOS，Rasberry Pi OS 等。我们可以通过命令行或使用安装程序在每个环境中安装 Node-RED。本章涵盖了特定操作系统的重要注意事项。

第三章《通过创建基本流了解 Node-RED 特性》教会我们关于 Node-RED 的基本用法。在 Node-RED 中，各种功能与称为节点的部分一起使用。在 Node-RED 中，我们使用称为流的概念创建应用程序，就像工作流一样。我们将通过组合基本节点创建一个示例流。

第四章《学习主要节点》教会我们如何利用更多的节点。我们不仅将了解 Node-RED 默认提供的节点，还将学习如何获取社区发布的各种节点以及如何使用它们。

第五章《在本地实现 Node-RED》教会我们在本地环境，即我们的桌面环境中利用 Node-RED 的最佳实践。由于 Node-RED 是基于 Node.js 的工具，它擅长构建服务器端应用程序。然而，服务器不仅仅存在于网络之外。通过在边缘设备（如树莓派）的本地环境中使用 Node-RED 的虚拟运行时，我们可以更方便地使用它。

第六章《在云中实现 Node-RED》教会我们在云平台上利用 Node-RED 的最佳实践。由于 Node-RED 是基于 Node.js 的工具，它擅长构建服务器端应用程序。通过在任何云平台上使用 Node-RED，我们可以更方便地使用它，因此我们将在 IBM Cloud 上使用 Node-RED 制作流程作为云平台的一个用例。

第七章《从 Node-RED 调用 Web API》教会我们如何利用 Node-RED 中的 Web API。为了最大限度地提高 Web 应用程序的吸引力，与各种 Web API 链接是必不可少的。在 Node-RED 中，调用 Web API 与常规 Node.js 应用程序中调用 Web API 之间的区别，可以帮助我们充分利用 Node-RED。

[*第八章*]（B16353_08_ePub_AM.xhtml#_idTextAnchor102），*使用 Git 的项目功能*，教我们如何在 Node-RED 中使用源代码版本控制工具。在 Node-RED 中，项目功能在 1.x 版本及更高版本中可用。项目功能可以与基于 Git 的每个源代码版本控制工具进行链接。通过将流程版本化到存储库中，我们的开发将加速。

[*第九章*]（B16353_09_ePub_AM.xhtml#_idTextAnchor110），*使用 Node-RED 创建 ToDo 应用程序*，教我们如何使用 Node-RED 开发标准的 Web 应用程序。这里的 Web 应用程序是一个简单的 ToDo 应用程序。整个应用程序的架构非常简单，将帮助我们了解如何使用 Node-RED 开发 Web 应用程序，包括用户界面。

[*第十章*]（B16353_10_ePub_AM.xhtml#_idTextAnchor121），*处理树莓派上的传感器数据*，教我们使用 Node-RED 进行 IoT 数据处理的应用程序开发方法。Node-RED 最初是为处理 IoT 数据而开发的。因此，Node-RED 今天仍在使用的许多用例都是 IoT 数据处理。Node-RED 将从传感器获取的数据传递给我们想要进行的每个过程，并将其发布。

[*第十一章*]（B16353_11_ePub_AM.xhtml#_idTextAnchor134），*通过在 IBM Cloud 中创建服务器端应用程序来可视化数据*，教我们关于在云平台上使用 Node-RED 进行 IoT 数据处理的应用程序开发方法。我们通常使用来自任何云平台的边缘设备的数据进行分析、可视化等。Node-RED 处理从 MQTT 代理订阅的数据，并为任何目的可视化它。

[*第十二章*]（B16353_12_ePub_AM.xhtml#_idTextAnchor142），*使用 Slack 和 IBM Watson 开发聊天机器人应用程序*，教我们如何创建聊天机器人应用程序。乍一看，Node-RED 和聊天机器人似乎没有关联，但许多聊天机器人应用程序在幕后使用 Node-RED。原因是 Node-RED 可以像工作流程一样对数据进行逐个数据的服务器端处理。在这里，我们创建一个在全球范围内使用的 Slack 上运行的聊天机器人。

[*第十三章*]（B16353_13_ePub_AM.xhtml#_idTextAnchor150），*在 Node-RED 库中创建和发布自己的节点*，教我们如何自己开发节点。对于许多用例，我们可以从 Node-RED 库中找到我们需要的处理节点。这是因为许多节点由许多开发人员的贡献在互联网上公开。通过开发自己的节点并将其发布到 Node-RED 库，让我们帮助大量其他 Node-RED 用户。

# 为了充分利用本书

您将需要 Node-RED 版本 1.2 或更高版本，Node.js 版本 12 或更高版本，npm 版本 6 或更高版本，并最好安装在计算机上的最新次要版本。但这是在本地环境中运行 Node-RED 的情况。在 IBM Cloud 上运行的情况下，这取决于云平台的环境，这是本书中的教程之一。所有代码示例都经过了 macOS、Windows 和 Raspberry Pi OS 的测试，但一些章节基于 macOS 具有命令行说明。

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/B16353_Preface_Table_1.jpg)

**如果您使用的是本书的数字版本，我们建议您自己输入代码或通过 GitHub 存储库访问代码（链接在下一节中提供）。这样做将帮助您避免与复制和粘贴代码相关的任何潜在错误。**

# 下载示例代码文件

您可以从 GitHub 上下载本书的示例代码文件[`github.com/PacktPublishing/-Practical-Node-RED-Programming`](https://github.com/PacktPublishing/-Practical-Node-RED-Programming)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还有来自丰富书籍和视频目录的其他代码包可供下载[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)。快去看看吧！

# 下载彩色图像

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图像。您可以在这里下载：[`static.packt-cdn.com/downloads/9781800201590_ColorImages.pdf`](https://static.packt-cdn.com/downloads/9781800201590_ColorImages.pdf)。

# 使用的约定

本书中使用了许多文本约定。

`文本中的代码`：表示文本中的代码词，数据库表名，文件夹名，文件名，文件扩展名，路径名，虚拟 URL，用户输入和 Twitter 用户名。这是一个例子：“让我们使用`<h1>`标签将页面标题附加到正文。”

代码块设置如下：

```js
// generate random number
var min = 1 ;
var max = 10 ;
var a = Math.floor( Math.random() * (max + 1 - min) ) + min ;
// set random number to message
msg.payload = a;
// return message
return msg;
```

任何命令行输入或输出都以以下方式编写：

```js
$ node --version
v12.18.1
$ npm –version
6.14.5
```

**粗体**：表示一个新术语，一个重要的词，或者屏幕上看到的词。例如，菜单或对话框中的单词会以这种方式出现在文本中。这是一个例子：“在选择名称和付款计划后，点击**选择区域**按钮。”

提示或重要说明

会出现在这样。


# 第一部分：Node-RED 基础

在本节中，读者将了解什么是基于流程的编程（FBP）工具，包括 Node-RED，以及如何使用它进行物联网/网络编程，并将学习如何在基本水平上使用 Node-RED 流程编辑器。

在本节中，我们将涵盖以下章节：

+   第一章，介绍 Node-RED 和基于流程的编程

+   第二章，设置开发环境

+   第三章，通过创建基本流程了解 Node-RED 特性

+   第四章，学习主要节点


# 第一章：介绍 Node-RED 和基于流的编程

本章将帮助您从读者成长为 Node-RED 用户。首先，您将了解**基于流的编程（FBP）**工具的历史，而不仅仅是 Node-RED。然后，您将对 Node-RED 的整体有一个广泛的了解，作为构建 Web 应用程序和**物联网**（**IoT**）数据处理的有用工具，然后学习有关 Node-RED 的 IoT 和 Node.js 是什么。

提供技术内容将有助于加速软件应用程序的开发，但如果您看一下 Node-RED 工具本身的历史，将有助于您更好地理解为什么您需要像 Node-RED 这样的 FBP 工具。这就是本章将要做的事情。

更具体地，我们将涵盖以下主题：

+   什么是 FBP？

+   什么是 Node-RED？

+   Node-RED 的好处

+   Node-RED 和物联网

让我们开始吧！

# 什么是 FBP？

那么，首先什么是 FBP 呢？这是您在工作中使用的工作流程，您可以很容易地想象到。让我们回顾一下这些工作流程。

## 工作流程

在正常的工作流程中，方框和线表示进程流程。它可能只是一个业务设计。方框代表进程。方框处理由谁、何时、何地、什么以及多少来定义。有时，它就像明确地写出处理流程，例如使用游泳道或在方框内放置写定义。无论如何，看看方框应该能够看出将要做什么。

另一方面，让我们试着将这个业务流程总结为一个文件。你不觉得会很复杂吗？即使他们使用一些段落来组合，读者会在阅读时会感到困惑。他们将在什么时候做？这可能会令人困惑：

![图 1.1 – 工作流程示例](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/pic_1-1.jpg)

图 1.1 – 工作流程示例

现在，让我们回到软件编程。FBP 是一种用数据流定义应用程序的软件编程概念。处理的每个部分都是一个黑盒子。它们在预定义的连接的黑盒子之间传递数据。FBP 被认为是面向组件的，因为这些黑盒子进程可以重复连接，形成多个应用程序，而无需在内部进行修改。让我们更详细地探讨 FBP。

## 基于流的编程（FBP）

我认为 FBP 是工作流和数据流的良好结合。FBP 使用**数据工厂**的隐喻来定义应用程序。它将应用程序视为一组异步进程的网络，这些进程从某一点开始，并进行单个顺序处理，一次执行一个操作，直到结束，而不是通过使用结构化数据块流进行通信。这被称为**信息包**（**IP**）。这种观点侧重于数据及其转换过程，以产生所需的输出。网络通常在进程外部定义为一组由称为**调度器**的软件解释的连接列表。

进程通过固定容量连接进行通信。连接通过端口连接到进程。端口具有网络定义和进程代码所约定的特定名称。在这一点上，可以通过使用多个进程执行相同的代码。特定的 IP 通常只由单个进程拥有或在两个进程之间传输。端口可以是普通类型或数组类型。

FBP 应用程序通常比传统程序运行得更快，因为 FBP 进程可以继续运行，只要有空间放入数据并输出到处理。它不需要任何特殊的编程，并且可以充分利用机器上的所有处理器。

FBP 具有高级功能风格，因此系统的行为可以很容易地定义；例如，在分布式多方协议中，如分布式数据流模型中，可以准确分析确定变量或语句是否正确行为的标准：

![图 1.2 – 简单的 FBP 设计示例](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/pic_1-2.jpg)

图 1.2 - 简单的 FBP 设计示例

现在您已经对 FBP 有了扎实的了解，让我们学习如何以这种方式实现 Node-RED。

# 什么是 Node-RED？

Node-RED 是我们迄今为止描述的 FBP 工具之一。由 IBM 的新兴技术服务团队开发，Node-RED 现在属于 OpenJS 基金会。

## 概述

FBP 是由 J. Paul Morrison 在 20 世纪 70 年代发明的。正如我们之前提到的，FBP 将应用程序的行为描述为一个黑盒网络，在 Node-RED 中被描述为“节点”。每个节点中定义了处理；数据被传递给它，使用该数据进行处理，然后将该数据传递给下一个节点。网络起到了允许数据在节点之间流动的作用。

这种编程方法非常易于使用，可以用来直观地制作模型，并且易于多层用户访问。如果将问题分解为每个步骤，任何人都可以理解流程在做什么。这就是为什么您不需要在节点内部编写代码：

![图 1.3 - Node-RED 流程编辑器作为 FBP 工具](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/pic_1-3.jpg)

图 1.3 - Node-RED 流程编辑器作为 FBP 工具

## 流编辑器和运行时

Node-RED 不仅是一个编程工具，还是一个封装了 Node-RED 构建的应用程序的 Node.js 运行时的执行平台。

我们需要使用**流编辑器**为物联网、Web 服务等制作 Node-RED 应用程序。流编辑器也是一个 Node.js Web 应用程序。我们将在*第三章**，通过创建基本流程了解 Node-RED 特性*中清楚地告诉您如何使用流编辑器。

流编辑器是 Node-RED 的核心功能，实际上是一个使用 Node.js 制作的 Web 应用程序。它与 Node.js 运行时一起工作。这个流编辑器在浏览器中运行。您必须从调色板中选择要使用的节点，并将其拖到工作区。连线是将节点连接在一起的过程，从而创建一个应用程序。用户（开发人员）只需点击一次即可将应用程序部署到目标运行时。

包含各种节点的调色板可以轻松扩展，因为您可以安装开发人员创建的新节点，这意味着您可以将创建的流程轻松共享为 JSON 文件。在我们探讨 Node-RED 的好处之前，让我们先看一下其创建背后的简要历史。

## Node-RED 的历史和起源

在 2013 年初，来自 IBM 英国新兴技术服务团队的 Nick-O'Leary 和 Dave Conway-Jones 创建了 Node-RED。

最初，它只是一个**概念验证**（**PoC**），用于帮助可视化和理解**消息队列遥测传输**（**MQTT**）主题之间的映射，但很快，它成为了一个非常受欢迎的工具，可以轻松扩展到各种用途。

Node-RED 于 2013 年 9 月成为开源项目，现在仍然作为开源项目进行开发。它于 2016 年 10 月成为 JS 基金会的创始项目之一，后来与 Node.js 基金会合并，于 2019 年 3 月创建了 OpenJS 基金会。

OpenJS 基金会支持 JavaScript 和 Web 技术的增长，作为一个中立的组织来领导和共同资助任何项目和活动，这对整个生态系统都有益处。OpenJS 基金会目前托管了 30 多个开源 JavaScript 项目，包括 Appium、Dojo、jQuery、Node.js 和 webpack。

Node-RED 已根据 Apache 2 许可证提供，这使得它在个人和商业领域都可以广泛使用：

![图 1.4 - Dave Conway-Jones 和 Nick O'Leary](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/pic_1-4.jpg)

图 1.4 - Dave Conway-Jones 和 Nick O'Leary

为什么叫 Node-RED？

官方文档（[`nodered.org/about/`](https://nodered.org/about/)）指出，这个名字是一个简单的双关语，听起来像“Code Red”。这是一个死胡同，Node-RED 是对它在最初几天构思时的称呼的重大改进。 “Node”部分既反映了流/节点编程模型，也反映了底层的 Node.js 运行时。

Nick 和 Dave 从未就“RED”部分代表什么达成结论。“快速事件开发人员”是一个建议，但从未被迫正式确定任何事情。因此，“Node-RED”这个名字诞生了。

# Node-RED 的好处

让我们在这里思考一下。为什么要使用汽车？我认为答案非常简单明了。首先，我们可以得出答案，即它们被用作广义上的交通工具。还有其他交通选择，比如步行、骑自行车、乘火车和公交车。然后，我们有从这些其他选择中选择汽车的原因，如下所示：

+   你不会感到疲惫。

+   你可以快速到达目的地。

+   你可以按自己的步调前进。

+   你可以保持个人空间。

当然，也有一些缺点，但我认为这些是使用汽车的主要原因。虽然其他交通工具也可以达到同样的目的，但重要的是要考虑每种交通工具的优缺点，并根据你认为最适合你的原因使用汽车作为交通工具。

我们在软件中也可以看到同样的情况。例如，为什么要使用 Word、Excel 和 PowerPoint？你可能会使用 Word，因为这是写文件的最有效方式。然而，你也可以使用其他文字处理软件或手写。同样地，你可以使用其他方式制作电子表格，而不是 Excel。除了 PowerPoint，如果你想制作有效的演示材料，也有其他方式。然而，你可能会选择最适合你情况的工具。

让我们回顾一下 Node-RED 的用途。它是一个适用于为 Web 应用程序和物联网制作数据控制应用程序的 FBP 工具。它的开发环境和执行环境是基于浏览器的应用程序，使用了 Node.js，使其开发尽可能简单。

那么，使用提供这些功能的 Node-RED 的原因是什么呢？你想避免繁重的编码吗？你没有编码技能吗？当然，这些也是使用该程序的原因。

让我们回顾一下汽车的例子。在广义上，我们的困境（交通工具）在这里被开发（创建）Node.js 应用程序来描述软件工具所取代。诸如汽车、自行车、火车、公交车、船、飞机等交通选择都是选项，而在软件开发中，我们也有许多选择，比如使用 Node.js scratch，或使用 Node.js 的各种框架和使用 Node-RED。至于选择 Node-RED 的原因，让我们看一下一些重要的要点。

## 简化

使用 Node-RED 进行编程时，你会注意到它的简单性。正如无代码/低代码的名称所示，编码被消除，编程是通过最少的操作直观完成的。

## 效率

Node-RED 所代表的 FBP 几乎可以完全通过图形界面操作完成。Node-RED 流编辑器负责构建应用程序执行环境、库同步、集成开发环境（IDE）和编辑器准备，这样你就可以专注于开发。

## 通用

正如面向对象开发所代表的，将源代码作为一个通用组件是开发中最重要的想法之一。在基于常规编码的开发中，每个通用组件存在于函数和类中，但在 Node-RED 中，它们存在为易于理解的节点（只是一个框）。如果你没有一个作为通用组件想要使用的节点，任何人都可以立即创建一个并将其发布到世界上。

## 高质量

高质量是基于流程和可视化编程的真正价值。每个作为组件提供的节点都是一个经过单元测试的完整模块。因此，应用程序作者可以专注于在连接级别检查操作，而不必担心节点的内容。这是一个消除单个级别的人为错误并确保高质量的重要因素。

## 开源

Node-RED 是一款开源软件。因此，它可以根据 Apache2 许可灵活使用。一些人正在基于 Node-RED 开发自己的服务，而另一些人则正在更改自己的用户界面，并将其部署为内置。正如我们之前提到的，我们还建立了一个平台，可以发布我们自己开发的节点，以便任何人都可以使用它。

## Node-RED 库

该库索引了所有发布到公共 npm 存储库（[`www.npmjs.com/`](https://www.npmjs.com/)）的 Node-RED 模块，假设它们遵循适当的打包指南。

这是我们看到最多社区贡献的领域，有超过 2,000 个可用的节点 - 这意味着每个人都能找到适合自己的东西：

![图 1.5 - Node-RED 库](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/pic_1-5.jpg)

图 1.5 - Node-RED 库

## 各种平台

Node-RED 可以在各种平台上使用。这是因为 Node-RED 本身是一个 Node.js 应用程序，正如我们之前提到的。如果你有一个 Node.js 的运行环境，你就可以运行它。它主要用于边缘设备、云服务和嵌入式格式。

通过理解 Node-RED 和物联网之间的关系以及物联网的架构，可以对此有所了解，这将在下一节中解释。

# Node-RED 和物联网

再次强调，Node-RED 是一个**虚拟环境**，以革命性的方式在浏览器上结合硬件设备、API 和在线服务。它提供以下功能：

+   基于浏览器的用户界面。

+   与 Node.js 一起工作，且轻量级。

+   封装功能，可以作为节点使用（意味着功能被锁在一个抽象的胶囊中）。

+   您可以创建和添加自己的节点。

+   轻松访问 IBM 云服务。

换句话说，可以说这个工具适合构建与物联网相关的服务，比如设备上的数据控制，以及连接边缘设备和云服务。最初，Node-RED 的开发概念是为了物联网，所以这是有道理的。

现在，让我们来看一下物联网的基本结构，以便那些对物联网只有模糊概念的人能够理解。可以说，物联网基本上由六个层组成，如下图所示：

![图 1.6 - 物联网六层](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/pic_1-6.jpg)

图 1.6 - 物联网六层

让我们更详细地看看这些。

**设备**

设备是所谓的边缘设备。物联网具有各种传感器，并处理从它们获取的数据。由于仅在边缘设备上拥有数据是没有意义的，我们需要通过网关将数据发送到网络。

**网络**

这是发送从设备获取的数据到互联网服务器所需的网络。通常指的是互联网。除了互联网，还可以通过蓝牙或串行进行 P2P 连接。

**平台**

接收和使用数据的一方是平台。我们可能还有一个用于激活和验证事物、管理通信和持久化接收到的数据的数据库。

**分析**

这是一个分析接收到的数据的层。广义上来说，它可以被分类为一个应用程序。这部分准备数据，使其能够以有意义的形式进行处理。

**应用程序**

应用程序根据数据分析结果提供特定的服务。它可以是 Web 或移动应用程序，也可以是硬件特定的嵌入式应用程序。可以说这是物联网解决方案的最终用户使用的层。

现在我们对物联网有了一定的了解，我们将探讨为什么应该使用 Node-RED。

## Node-RED 和物联网

在到目前为止解释物联网的过程中，我们已经明确说明了为什么 Node-RED 适合物联网。例如，你可以理解为什么为物联网开发的 FBP 工具在与 Node-RED 一起使用时能够生存下来。特别是，应该考虑以下三点：

+   由于它可以在边缘设备上运行（预装在特定版本的树莓派 OS 上），因此非常适合在设备层进行数据处理。

+   由于它可以在云上运行（作为 IBM Cloud 中的默认服务），因此很容易与存储和分析中间件进行链接。

+   由于可以涵盖 MQTT 和 HTTP 协议，因此在边缘设备和服务器处理云之间交换数据非常容易。

这样一来，Node-RED，它主要涵盖了物联网所需的元素，现在被用于各种应用，如 Web 服务和图表显示，以及物联网的编程。此外，截至 2020 年 6 月，如果你查看 Node-RED 的 Google 趋势，你会发现用户数量在逐渐增加。因此，Node-RED 是一个非常有吸引力的 FBP 工具：

![图 1.7 - "Node-RED"的 Google 趋势](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/pic_1-7.jpg)

图 1.7 - "Node-RED"的 Google 趋势

可以使用 Node-RED 的典型边缘设备是树莓派。当然，也可以在其他平台上使用 Node-RED，但它与树莓派配合得很好，树莓派还预装了操作系统的版本。

树莓派 OS 支持 Node-RED

Node-RED 也已经打包到了树莓派 OS 的存储库中，并出现在他们的推荐软件列表中。这使得可以使用`apt-get install Node-RED`进行安装，并包括了树莓派 OS 打包版本的 Node.js，但不包括 npm。更多信息可以在[`nodered.org/docs/getting-started/raspberrypi`](https://nodered.org/docs/getting-started/raspberrypi)找到。

IBM Cloud 是一个可以使用 Node-RED 的典型云平台。当然，你也可以在其他云上使用 Node-RED，但 IBM Cloud 提供了一个任何人都可以轻松开始使用的服务。

重要说明

Node-RED 在 IBM Cloud 平台上作为其目录中的 Starter Kits 应用程序之一可用。在 IBM Cloud 上作为 Web 应用程序使用流程编辑器非常容易（[`nodered.org/docs/getting-started/ibmcloud`](https://nodered.org/docs/getting-started/ibmcloud)）。

# 摘要

在本章中，你了解了什么是 FBP 和 Node-RED。因此，你现在明白了为什么 Node-RED 目前被很多人作为 FBP 工具所喜爱和使用。在这一点上，你可能想要使用 Node-RED 构建一个应用程序。在下一章中，我们将在我们的环境中安装 Node-RED，并更深入地了解它。


# 第二章：设置开发环境

在本章中，您将安装使用 Node-RED 所需的工具。这不仅包括 Node-RED 本身，还包括其运行时 Node.js，以及如何更新 Node-RED 和 Node.js。

Node-RED 于 2019 年 9 月发布了 1.0 里程碑版本。这反映了该项目的成熟度，因为它已经被广泛用于生产环境。它继续开发并通过对底层 Node.js 运行时进行更改来保持最新状态。您可以在[`nodered.org/docs/getting-started/`](https://nodered.org/docs/getting-started/)上检查 Node-RED 安装的最新状态。

Node-RED 官方网站上有许多安装指南，例如本地安装、树莓派、Docker 和主要云平台。

在本章中，您将学习如何在本地计算机上安装 Node-RED，无论是在 Windows、Mac 还是在树莓派上运行。我们将涵盖以下主题：

+   为 Windows 安装`npm`和 Node.js

+   为 Mac 安装`npm`和 Node.js

+   为树莓派安装`npm`和 Node.js

+   为 Windows 安装 Node-RED

+   为 Mac 安装 Node-RED

+   为树莓派安装 Node-RED

本章结束时，我们将安装所有必要的工具，并准备好继续使用 Node-RED 构建一些基本流程。

作为参考，作者的测试操作环境是 Windows 10 2004 18363.476、macOS Mojave 10.14.6 (18G5033)和 Raspberry Pi OS 9.4 stretch。

# 技术要求

本章需要安装以下内容：

+   Node.js (v12.18.1)*

+   npm (v6.14.5)*

*写作时的 LTS 版本。

# 为 Windows 安装 npm 和 Node.js

如果您想在 Windows 上使用 Node-RED，必须通过以下网站安装 npm 和 Node.js：

https://nodejs.org/en/#home-downloadhead。

您可以直接在那里获取 Node.js 的 Windows 安装程序。之后，按照以下步骤操作：

1.  访问原始 Node.js 网站并下载安装程序。

您可以选择**推荐**或**最新功能**版本，但在本书中，应使用**推荐**版本：

![图 2.1–选择推荐版本安装程序](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_2.1_B16353.jpg)

图 2.1–选择推荐版本安装程序

1.  单击下载的`msi`文件以开始安装 Node.js。它包括当前版本的 npm。Node-RED 在 Node.js 运行时上运行，因此需要它。

1.  只需根据安装向导的对话框按钮进行单击，尽管在安装过程中需要注意一些要点。

1.  接下来，您需要接受最终用户许可协议：![图 2.2–最终用户许可协议窗口](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_2.2_B16353.jpg)

图 2.2–最终用户许可协议窗口

您还可以更改安装目标文件夹。在本书中，将使用默认文件夹（`C:/Program Files/nodejs/`）：

![图 2.3–安装目标文件夹](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_2.3_B16353.jpg)

图 2.3–安装目标文件夹

1.  在下一个屏幕上不需要自定义设置。您可以只选择默认功能并单击**下一步**：![图 2.4–不需要自定义设置](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_2.4_B16353.jpg)

图 2.4–不需要自定义设置

1.  在接下来的屏幕上，您可以单击**下一步**而无需勾选任何内容。但是，可以在此处选择可以选择的工具进行安装。这包括安装和设置这些环境的路径（Visual C++、windows-build-tools 和 Python）：![图 2.5–本机模块工具窗口](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_2.5_B16353.jpg)

图 2.5–本机模块工具窗口

1.  当 Node.js 安装完成后，使用以下命令检查工具的版本：

```js
$ node --version
v12.18.1
$ npm –version
6.14.5
```

当 Node.js 和 npm 安装完成后，您可以检查它们的版本号。有了这些，您就可以安装 Node-RED 了。

重要提示

根据项目的不同，使用旧的 Node.js 版本进行操作是稳定的，但如果您使用不同版本的 Node.js，它可能不起作用。然而，每次切换项目都卸载当前的 Node.js 版本并安装所需的 Node.js 版本需要时间。因此，如果您使用 Windows，我建议使用 Node.js 版本管理工具，如 nodist ([`github.com/nullivex/nodist`](https://github.com/nullivex/nodist))。还有其他类型的 Node.js 版本控制工具，请尝试找到一个对您来说容易使用的。

# 为 Mac 安装 npm 和 Node.js

如果您想在 macOS 上使用 Node-RED，您必须通过以下网站安装`npm`和 Node.js：

https://nodejs.org/en/#home-downloadhead

您可以直接在那里获取 Mac 安装程序。

访问原始的 Node.js 网站并下载安装程序。您可以选择推荐版本或最新功能版本，但是对于本书，您应该使用推荐版本：

![图 2.6-选择推荐版本的安装程序](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_2.6_B16353.jpg)

图 2.6-选择推荐版本的安装程序

点击您下载的`.pkg`文件开始安装 Node.js。它包括当前版本的`npm`。Node-RED 在 Node.js 运行时上运行，所以它是必需的。尽管在安装过程中有一些需要注意的地方，但只需按照安装向导进行简单点击即可。

您需要接受最终用户许可协议：

![图 2.7-最终用户许可协议窗口](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_2.7_B16353.jpg)

图 2.7-最终用户许可协议窗口

您可以更改安装位置。在本书中，将使用默认位置（Macintosh HD）：

![图 2.8-安装位置](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_2.8_B16353.jpg)

图 2.8-安装位置

当 Node.js 安装完成后，您可以使用以下命令检查工具的版本。一旦安装了 Node.js 和`npm`，您可以检查它们的版本号。您已经准备好安装 Node-RED 了：

```js
$ node --version
v12.18.1
$ npm –version
6.14.5
```

注意

根据项目的不同，使用旧的 Node.js 版本进行操作是稳定的，如果您使用不同版本的 Node.js，它可能不起作用。然而，每次切换项目都卸载当前的 Node.js 版本并安装所需的 Node.js 版本需要时间。因此，如果您使用 macOS，我建议使用 Node.js 版本管理工具，如 Nodebrew ([`github.com/hokaccha/nodebrew`](https://github.com/hokaccha/nodebrew))。还有其他类型的 Node.js 版本控制工具，请尝试找到一个对您来说容易使用的。

现在我们已经介绍了 Windows 和 Mac 的安装过程，让我们学习如何为树莓派安装`npm`和 Node.js。

# 为树莓派安装 npm 和 Node.js

如果您想在树莓派上使用 Node-RED，恭喜您-您已经准备好安装 Node-RED 了。这是因为 Node.js 和 npm 已经默认安装了。您可以使用现有的安装脚本来安装 Node-RED，包括 Node.js 和 npm。这个脚本将在本章的后面部分描述，在*为树莓派安装 Node-RED*部分，所以您现在可以跳过这个操作。

但是，您应该检查树莓派上的 Node.js 和 npm 版本。请键入以下命令：

```js
$ node --version
v12.18.1
$ npm –version
6.14.5
```

如果不是 LTS 版本或稳定版本，您可以通过 CLI 进行更新。请键入并运行以下命令来执行此操作。在这个命令中，最后一行使用了`lts`，但如果您想安装稳定版本，也可以将`lts`替换为`stable`：

```js
$ sudo apt-get update
$ sudo apt-get install -y nodejs npm
$ sudo npm install npm n -g
$ sudo n lts
```

现在我们已经成功检查了树莓派上 Node.js 和 npm 的版本，并进行了更新（如果适用），我们将继续安装 Windows 上的 Node-RED。

重要提示

Node-RED 项目提供的脚本负责安装 Node.js 和`npm`。通常不建议使用由树莓派 OS 提供的版本，因为它们的打包方式很奇怪。

# 为 Windows 安装 Node-RED

在本节中，我们将解释如何在 Windows 环境中设置 Node-RED。此过程适用于 Windows 10，但也适用于 Windows 7 和 Windows Server 2008 R2 及更高版本。目前不支持 Windows 7 或更早版本的 Windows Server 2008 R2，也不建议使用。

对于 Windows，将 Node-RED 安装为全局模块会将`node-red`命令添加到系统路径中。在命令提示符中运行以下命令：

```js
$ npm install -g --unsafe-perm node-red
```

安装完成 Node-RED 后，您可以立即使用 Node-RED。请运行以下命令。运行此命令后，您将识别用于访问 Node-RED 流编辑器的 URL。通常会分配 localhost（127.0.0.1）和默认端口 1880：

```js
$ node-red
Welcome to Node-RED
===================
…
[info] Starting flows
[info] Started flows
[info] Server now running at http://127.0.0.1:1880/
```

让我们在浏览器上访问 Node-RED。为此，请在命令提示符中收到的 URL 中输入。我强烈建议使用 Chrome 或 Firefox 来运行 Node-RED：

![图 2.9 - Node-RED 流编辑器](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_2.9_B16353.jpg)

图 2.9 - Node-RED 流编辑器

现在，您已经准备好在 Node-RED 中编程。从*第三章*，*通过创建基本流了解 Node-RED 特性*，开始，我们将学习如何实际构建使用 Node-RED 的应用程序。

现在，让我们继续在 macOS 中安装 Node-RED。

# 在 Mac 上安装 Node-RED

在本节中，我们将解释如何在 macOS 环境中设置 Node-RED。此过程适用于 macOS Mojave。它可能适用于所有版本的 Mac OS X，但我强烈建议您使用当前版本的 macOS。

对于 macOS，将 Node-RED 安装为全局模块会将`node-red`命令添加到系统路径中。在终端中运行以下命令。根据您的本地设置，您可能需要在命令前加上`sudo`：

```js
$ sudo npm install -g --unsafe-perm node-red
```

您还可以使用其他工具安装 Node-RED。这主要适用于 Mac/Linux 或支持以下工具的操作系统：

1.  Docker ([`www.docker.com/`](https://www.docker.com/))，如果您有运行 Docker 的环境。

当前的 Node-RED 1.x 存储库在 Docker Hub 上已更名为"`nodered/node-red`"。

0.20.x 版本之前的版本可从[`hub.docker.com/r/nodered/node-red-docker`](https://hub.docker.com/r/nodered/node-red-docker)获取。

```js
$ docker run -it -p 1880:1880 --name mynodered nodered/node-red
```

1.  Snap（[`snapcraft.io/docs/installing-snapd`](https://snapcraft.io/docs/installing-snapd)），如果您的操作系统支持。

如果您将其安装为 Snap 软件包，可以在安全容器中运行它，该容器无法访问您必须使用的外部功能，例如以下功能：

+   访问主系统存储（只允许读/写本地主目录）。

+   Gcc：需要为要安装的节点编译二进制组件。

+   Git：如果您想利用项目功能，则需要。

+   直接访问 GPIO 硬件。

+   访问外部命令，例如在 Exec 节点中执行的流。

容器的安全性较低，但您也可以在**经典**模式下运行它们，这样您就可以获得更多访问权限。

运行以下命令以使用 Snap 安装 Node-RED：

```js
$ sudo snap install node-red
```

安装完成 Node-RED 后，您可以立即使用 Node-RED。请运行以下命令。运行此命令后，您可以找到用于访问 Node-RED 流编辑器的 URL。通常会分配 localhost（`127.0.0.1`）和默认端口`1880`：

```js
$ node-red
Welcome to Node-RED
===================
…
[info] Server now running at http://127.0.0.1:1880/
[info] Starting flows
[info] Started flows
```

让我们在浏览器上访问 Node-RED。在命令提示符中输入您收到的 URL。我强烈建议使用 Chrome 或 Firefox 来运行 Node-RED：

![图 2.10 - Node-RED 流编辑器](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_2.10_B16353.jpg)

图 2.10 - Node-RED 流编辑器

现在，您已经准备好在 Node-RED 中编程。在*第三章*，*通过创建基本流了解 Node-RED 特性*，我们将学习如何实际使用 Node-RED 构建应用程序。

我们的最终安装将是在树莓派上的 Node-RED。

# 为树莓派安装 Node-RED

在本节中，我们将解释如何在树莓环境中设置 Node-RED。此过程适用于树莓派 OS Buster（Debian 10.x），但也适用于树莓派 OS Jessie（Debian 8.x）及以上版本。

你可以轻松检查你的树莓派 OS 版本。只需在终端上运行以下命令：

```js
$ lsb_release -a
```

如果您还想检查您的 Debian 版本，请运行以下命令：

```js
$ cat /etc/debian_version
```

您现在已经准备好安装 Node-RED。以下脚本安装 Node-RED，包括 Node.js 和`npm`。此脚本也可用于升级您已安装的应用程序。

注意

此说明可能会更改，因此建议根据需要参考官方文档。

此脚本适用于基于 Debian 的操作系统，包括 Ubuntu 和 Diet-Pi：

```js
$ bash <(curl -sL https://raw.githubusercontent.com/node-red/linux-installers/master/deb/update-nodejs-and-nodered)
```

您可能需要运行`sudo apt install build-essential git`以确保 npm 可以构建需要安装的二进制组件。

Node-RED 已经打包为树莓派 OS 存储库的一部分，并包含在*推荐软件*列表中。可以使用`apt-get install Node-RED`命令进行安装，它还包含了 Node.js 的树莓派 OS 打包版本，但不包括 npm。

虽然使用这些软件包可能一开始看起来很方便，但强烈建议使用安装脚本。

安装完成后，您可以启动 Node-RED 并访问 Node-RED 流编辑器。我们有两种启动方式，如下：

1.  通过 CLI 运行：如果您想在本地运行 Node-RED，可以在终端中使用`node-red`命令启动 Node-RED。然后，您可以通过按*Ctrl* + *C*或关闭终端窗口来停止它：

```js
$ node-red
```

1.  通过编程菜单运行：安装完 Node-RED 后，您可以从树莓派菜单启动它。单击**菜单 | 编程 | Node-RED**打开终端并启动 Node-RED。启动 Node-RED 后，您可以像在 CLI 中一样从浏览器访问 Node-RED 流编辑器：

![图 2.11 - 通过树莓派菜单访问 Node-RED](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_2.11_B16353.jpg)

图 2.11 - 通过树莓派菜单访问 Node-RED

从菜单启动 Node-RED 后，您应该在终端上检查 Node-RED 运行进程，并找到 Node-RED 流编辑器的 URL。通常情况下，它与可以直接通过 CLI 启动的 URL 相同：

![图 2.12 - 检查访问 Node-RED 流编辑器的 URL](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_2.12_B16353.jpg)

图 2.12 - 检查访问 Node-RED 流编辑器的 URL

让我们在浏览器上访问 Node-RED。您可以在命令提示符中收到的 URL 中输入。如果您的树莓派默认的 Web 浏览器是 Chromium，那么使用 Node-RED 应该没有问题。但是，如果您希望使用其他浏览器，我强烈建议安装 Chromium 来运行 Node-RED：

![图 2.13 - Node-RED 流编辑器](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_2.13_B16353.jpg)

图 2.13 - Node-RED 流编辑器

就是这样！我们现在已经涵盖了开始使用 Node-RED 所需的每个工具的所有安装选项。

# 总结

在本章中，您已经准备好了环境，以便可以使用 Node-RED 流编辑器。在这一点上，我相信您已经可以访问 Node-RED 流编辑器，所以您会想要学习如何使用它。在下一章中，我们将在其中制作一个示例流，并了解 Node-RED 流编辑器的主要功能。


# 第三章：通过创建基本流程了解 Node-RED 特性

在本章中，我们将使用 Node-RED Flow Editor 实际创建一个流程。通过创建一个简单的流程，您将了解如何使用该工具及其特性。为了更好地理解，我们将创建一些示例流程。

从现在开始，您将使用 Node-RED 创建名为流程的应用程序。在本章中，您将学习如何使用 Node-RED 以及如何将应用程序创建为流程。为此，我们将涵盖以下主题：

+   Node-RED Flow Editor 机制

+   使用 Flow Editor

+   为数据处理应用程序制作流程

+   为 Web 应用程序制作流程

+   导入和导出流程定义

在本章结束时，您将掌握如何使用 Node-RED Flow Editor，并知道如何使用它构建一个简单的应用程序。

# 技术要求

要完成本章，您需要以下内容：

+   Node-RED（v1.1.0 或更高版本）。

+   本章的代码可以在[`github.com/PacktPublishing/-Practical-Node-RED-Programming`](https://github.com/PacktPublishing/-Practical-Node-RED-Programming)的`Chapter03`文件夹中找到。

# Node-RED Flow Editor 机制

正如您在之前的章节中学到的，Node-RED 有两个逻辑部分：一个称为 Flow Editor 的开发环境，用于执行在那里创建的应用程序的执行环境。它们分别称为运行时和编辑器。让我们更详细地看看它们：

+   **运行时**：包括 Node.js 应用程序运行时。它负责运行部署的流程。

+   **编辑器**：这是一个 Web 应用程序，用户可以在其中编辑他们的流程。

主要的可安装包包括两个组件，一个用于提供 Flow Editor 的 Web 服务器，另一个用于管理运行时的 REST Admin API。在内部，这些组件可以分别安装并嵌入到现有的 Node.js 应用程序中，如下图所示：

![图 3.1 - Node-RED 概述](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_3.1_B16353.jpg)

图 3.1 - Node-RED 概述

现在您了解了 Node-RED 的机制，让我们立即学习如何使用 Flow Editor。

## 使用 Flow Editor

让我们来看看 Flow Editor 的主要功能。

Flow Editor 的主要特点如下：

+   **节点**：Node-RED 应用程序的主要构建块，它们代表定义明确的功能块。

+   **Flow**：一系列通过连线连接在一起的节点，代表消息在应用程序中经过的一系列步骤。

+   **左侧面板是调色板**：编辑器中可用的节点集合，您可以使用它们来构建您的应用程序。

+   **部署按钮**：编辑应用程序后，按此按钮部署您的应用程序。

+   **侧边栏**：用于显示各种功能的面板，如处理参数设置、规格和调试器显示。

+   **侧边栏标签**：每个节点的设置，标准输出，变更管理等。

+   **主菜单**：流程删除，定义导入/导出，项目管理等。

这些功能在 Flow Editor 的屏幕上排列如下：

![图 3.2 - Node-RED Flow Editor](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_3.2_B16353.jpg)

图 3.2 - Node-RED Flow Editor

在开始使用 Node-RED 之前，您需要了解 Flow 菜单中包含的内容。其内容可能会有所不同，取决于您使用的 Node-RED 版本，但它具有一些通用的设置项，如**流程项目管理**、**排列视图**、**导入/导出流程**、**安装库中发布的节点**等。有关如何使用 Node-RED 的更多信息，可以根据需要参考官方文档。

重要提示

Node-RED 用户指南：[`nodered.org/docs/user-guide/`](https://nodered.org/docs/user-guide/)。

以下图表显示了 Node-RED 中 Flow Editor 菜单选项的所有内容：

![图 3.3 - Node-RED Flow Editor 菜单](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_3.3_B16353.jpg)

图 3.3 – Node-RED 流编辑器菜单

有了这个，你就可以使用 Node-RED 来构建一个应用程序了。所以，让我们开始吧！

首先，你需要在你的环境中运行 Node-RED。如果你还没有这样做，请参考*第二章**，设置开发环境*，了解如何在你的环境中设置它，比如 Windows、Mac 或树莓派。

Node-RED 运行后，让我们继续下一节，我们将制作我们的第一个流程。

# 制作数据处理应用程序的流程

在本节中，你将创建一个工作应用程序（在 Node-RED 中称为流程）。无论是**物联网**（**IoT**）还是作为 Web 应用程序的服务器处理，Node-RED 执行的基本操作都是顺序传输数据。

在这里，我们将创建一个流程，其中 JSON 数据是以伪方式生成的，最终通过 Node-RED 上的一些节点将数据输出到标准输出。

调色板的左侧有许多节点。请注意这里的**常用**类别。你应该能够很容易地找到**注入**节点，如下面的截图所示：

![图 3.4 – 注入节点](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_3.4_B16353.jpg)

图 3.4 – 注入节点

这个节点可以将消息注入到下一个节点。让我们开始吧：

1.  将其拖放到 Flow 1（默认流程标签）的调色板上。

你会看到节点上标有**时间戳**这个词。这是因为它的默认消息载荷是一个时间戳值。我们可以改变数据类型，所以让我们把它改成 JSON 类型。

1.  当节点的**属性**面板打开时，双击节点并更改其设置：![图 3.5 – 编辑注入节点属性面板](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_3.5_B16353.jpg)

图 3.5 – 编辑注入节点属性面板

1.  点击第一个参数的下拉菜单，选择**{}JSON**。你可以通过点击右侧的**[…]**按钮编辑 JSON 数据。

1.  点击**[…]**按钮，JSON 编辑器将打开。你可以用基于文本的编辑器或可视化编辑器制作 JSON 数据。

1.  这次，让我们用一个名为`{"name" : "太极"}`的项目来制作 JSON 数据。你应该用你的名字替换我的名字：![图 3.6 – JSON 编辑器](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_3.6_B16353.jpg)

图 3.6 – JSON 编辑器

太棒了 - 你成功地制作了一些示例 JSON 数据！

1.  点击**完成**按钮并关闭此面板。

1.  同样，在调色板上放置一个**调试**节点。

1.  放置后，将**注入**和**调试**节点连接到它。

一旦你执行了这个流程，从**注入**节点传递的 JSON 数据将被**调试**节点输出到调试控制台（标准输出）。你不需要在**调试**节点上配置任何东西：

![图 3.7 – 放置调试节点并连接它](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_3.7_B16353.jpg)

图 3.7 – 放置调试节点并连接它

1.  最后，你需要部署你创建的流程。在 Node-RED 流编辑器中，我们可以通过点击右上角的**部署**按钮将所有的流程部署到 Node-RED 运行时。

1.  在运行流程之前，你应该从节点菜单的侧边栏中选择**调试**选项卡，以启用调试控制台，如下面的截图所示：![图 3.8 – 启用调试控制台](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_3.8_B16353.jpg)

图 3.8 – 启用调试控制台

1.  让我们运行这个流程。点击**注入**节点的开关，看看在调试控制台上执行流程的结果：

![图 3.9 – 执行流程并检查结果](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_3.9_B16353.jpg)

图 3.9 – 执行流程并检查结果

这是一个非常简单和容易的数据处理流程示例。在本书的后半部分，我们还将通过实际连接物联网设备并传递从 Web API 获取的数据来实验数据处理。在本节中，你只需要了解如何在 Node-RED 中处理数据就足够了。接下来，我们将实验制作一个用于 Web 应用程序的流程。

为 Web 应用程序制作流程

在这一部分，您将为 Web 应用程序创建一个新的流程。我们将以与创建先前的数据处理流程相同的方式创建此流程。

您可以在相同流程（Flow 1）的工作区中创建它，但为了清晰和简单起见，让我们按照以下步骤为流程创建一个新的工作区：

1.  从**Flow**菜单中选择**Flows | Add**。 Flow 2 将添加到 Flow 1 的右侧。这些流名称，如“Flow 1”和“Flow 2”，是创建时提供的默认名称。如果需要，可以重命名流程，使其具有更具体的名称：![图 3.10 - 添加新流程](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_3.10_B16353.jpg)

图 3.10 - 添加新流程

1.  从调色板的**network**类别中选择**http 输入**节点，然后将其拖放到 Flow 2 的调色板上（您刚刚添加的新流程选项卡）：![图 3.11 - 一个 http 输入节点](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_3.11_B16353.jpg)

图 3.11 - 一个 http 输入节点

1.  双击节点以打开其**Edit**对话框。

1.  输入您将要创建的 Web 应用程序的 URL（路径）。

此路径将作为您将要创建的 Web 应用程序的 URL 的一部分，位于 Node-RED URL 下。在这种情况下，如果您的 Node-RED URL 是`http://localhost:1880/`，您的 Web 应用程序 URL 将是`http://localhost:1880/web`。可以在以下截图中看到示例：

![图 3.12 - 设置 URL 的路径](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_3.12_B16353.jpg)

图 3.12 - 设置 URL 的路径

1.  要通过 HTTP 发送请求，需要一个 HTTP 响应。因此，在 Node-RED 的工作区上放置一个**http 响应**节点。

您可以在调色板的**network**类别中找到此节点，位于**http 输入**节点旁边。在这里，**http 响应**节点只是返回响应，因此您无需打开配置面板。您可以将其保留不变。如果要在响应消息中包含状态代码，可以从**settings**面板中进行设置，如下截图所示：

![图 3.13 - 一个 http 响应节点](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_3.13_B16353.jpg)

图 3.13 - 一个 http 响应节点

1.  在调色板上放置**http 响应**节点后，从**http 输入**节点添加一根导线到**http 响应**节点。

这完成了 Web 应用程序的流程，因为我们已经允许了 HTTP 请求和响应。您将在每个节点的右上角看到一个浅蓝色的点，表示它们尚未部署 - 因此，请确保单击**Deploy**按钮：

![图 3.14 - 连接的节点](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_3.14_B16353.jpg)

图 3.14 - 连接的节点

1.  一旦成功部署，打开浏览器中的新标签页。

1.  然后，访问显示在`http://localhost:1880/web`中的 Web 应用程序的 URL。

您会发现屏幕上只显示**{}**。这不是错误。这是发送 HTTP 请求并返回响应的结果。现在，由于我们尚未设置要传递给响应的内容，因此将空 JSON 作为消息数据传递。如下所示：

![图 3.15 - Web 应用程序结果](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_3.15_B16353.jpg)

图 3.15 - Web 应用程序结果

这并不好，所以让我们创建一些内容。让我们做一些非常简单的事情，并实现一些简单的 HTML 代码。那么我应该在哪里编写这个？答案很简单。Node-RED 有一个模板节点，允许您将 HTML 代码指定为输出。让我们使用这个：

1.  将一个**模板**节点拖放到**http 输入**节点和**http 响应**节点之间的导线上，以便**模板**节点将连接到它：![图 3.16 - 在我们现有的两个节点之间的导线上放置一个“模板”节点](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_3.16_B16353.jpg)

图 3.16 - 在我们现有的两个节点之间的导线上放置“模板”节点

1.  接下来，双击`<h1>`标签。使用`<h2>`标签排列类似菜单的内容。代码将如下所示：

```js
<html>
  <head>
    <title>Node-RED Web sample</title>
  </head>
  <body>
    <h1>Hello Node-RED!!</h1>
    <h2>Menu 1</h2>
    <p>It is Node-RED sample webpage.</p>
    <hr>
    <h2>Menu 2</h2>
    <p>It is Node-RED sample webpage.</p>
  </body>
</html>
```

注意

您还可以从本书的 GitHub 存储库中获取此代码[`github.com/PacktPublishing/-Practical-Node-RED-Programming/tree/master/Chapter03`](https://github.com/PacktPublishing/-Practical-Node-RED-Programming/tree/master/Chapter03)。

1.  完成**模板**节点的编辑后，单击**完成**按钮关闭它。

以下屏幕截图显示了您编辑模板节点时的外观：

![图 3.17-模板区域中的代码](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_3.17_B16353.jpg)

图 3.17-模板区域中的代码

有了这个，我们已经完成了准备要显示在我们页面上的 HTML。请确保再次单击`http://localhost:1880/web`。现在您应该看到以下输出：

![图 3.18-Web 应用程序结果](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_3.18_B16353.jpg)

图 3.18-Web 应用程序的结果

此时，您应该了解如何在 Node-RED 上制作 Web 应用程序。我想到目前为止一切都很顺利。现在我们已经积累了一些动力，让我们继续学习。在下一节中，我们将导入和导出我们创建的流程定义。

# 导入和导出流程定义

在这一部分，您将导入和导出您创建的流程定义。通常，在开发时，需要备份源代码和版本控制。您还可以导入他人创建的源代码，或者导出自己的源代码并传递给他人。Node-RED 有类似的概念。在 Node-RED 中，导入和导出流本身是一种正常的做法，而不是导入或导出源代码（例如，前面描述的模板节点）。

因此，首先让我们导出到目前为止创建的流程。这很容易做到：

1.  只需在 Node-RED Flow Editor 的**Main**菜单下的**Edit**对话框中选择**导出**。

当显示**导出**菜单时，您只能选择当前流或所有流。您还可以选择原始 JSON（无缩进）或格式化 JSON（带缩进）。

1.  在这里，选择当前流并选择**格式化**。

1.  现在，您可以选择如何保存导出的 JSON 数据-在计算机的下载位置中保存`flows.json`。

1.  在文本编辑器中打开此文件，以便检查 JSON 文件的内容。

有了这个，我们已经学会了如何导出。

接下来，我们需要将此定义（`flows.json`）导入到我们的 Node-RED Flow Editor 中。请按照以下步骤操作：

1.  只需在 Node-RED Flow Editor 的**Flow**菜单中选择**导入**。

显示**导入**菜单时，您可以选择**粘贴流 json**或**选择基于文件的导入**。您还可以从流选项卡中选择**当前流**或**新流**。如果选择**新流**，将自动添加一个新的流选项卡。

1.  在这里，请选择您导出到本地计算机的`flows.json`。

1.  文件加载完成后，单击**导入**按钮：![图 3.20-导入操作](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_3.20_B16353.jpg)

图 3.20-导入操作

1.  现在，您有了新的选项卡，名称为 Flow 2，与旧的 Flow 2 选项卡上相同的流。它已完全导入，但尚未部署，因此请单击**部署**按钮，如下所示：![图 3.21-添加新流](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_3.21_B16353.jpg)

图 3.21-添加新流

有了这个，我们已经成功地准备好了我们导入的流程将显示在我们的网页上。请确保单击**部署**按钮。

1.  通过转到`http://localhost:1880/web`再次访问网页。

在这里，您将看到此网页与您导出的网页具有相同的设计。干得好！

![图 3.22-Web 应用程序的结果](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_3.22_B16353.jpg)

图 3.22-Web 应用程序的结果

现在，让我们结束这一章。

# 摘要

在本章中，您学习了如何使用 Node-RED Flow Editor 制作基本流程并导入/导出流程。现在您已经知道如何使用 Node-RED Flow Editor，您会想要了解更多其功能。当然，Node-RED 不仅具有诸如**Inject**、**http**和**template**等基本节点，还有更吸引人的节点，如**switch**、**change**、**mqtt**和**dashboard**。在下一章中，我们将尝试使用几个主要节点，以便我们可以编写 JavaScript，捕获错误，执行数据切换，延迟功能，使用 CSV 解析器等。


# 第四章：学习主要节点

在本章中，您将了解 Node-RED 中使用的主要节点。Node-RED 是一个开源项目，默认情况下提供了一些主要节点，但可以根据需要导入和使用来自公共库的节点。

Node-RED 有很多节点。因此，本书不足以解释所有这些节点。因此，在本章中，让我们挑选主要节点和最常用的基本节点，并学习如何使用它们，探索本章中的这些主题：

+   什么是节点？

+   如何使用节点

+   从库中获取各种节点

在本章结束时，您将掌握如何在 Node-RED 流编辑器中使用主要节点。

# 技术要求

要在本章中取得进展，您需要以下技术要求：

+   Node-RED（v1.1.0 或更高版本）。

+   本章中使用的代码可以在[`github.com/PacktPublishing/-Practical-Node-RED-Programming`](https://github.com/PacktPublishing/-Practical-Node-RED-Programming)的`Chapter04`文件夹中找到。

# 什么是节点？

首先让我们了解 Node-RED 中的节点到底是什么。

Node-RED 是一个使用**图形用户界面**（**GUI**）工具编程 Node.js 应用程序的工具。Node-RED 还作为在 Node-RED 上编程的软件（Node-RED Flow）的执行环境。

通常，在使用 Node.js 进行编程时，源代码是用代码编辑器或**集成开发环境**（**IDE**）编写的。通过构建编写的源代码（编译，与依赖文件关联等），生成可执行文件。

在 Node-RED 上进行可视化编程基本上遵循相同的过程。不同之处在于，编码部分是将节点放置在 Node-RED 上，而不是编辑器。

在 Node-RED 中，使用 Node.js 编程时提供的基本处理由称为节点的实现部分提供。在正常的面向对象编程中，这些部分通常以常见部分的形式提供为库文件。

由于 Node-RED 是基于 GUI 的可视化编程工具，这些常见部分不仅仅是库文件。这些常见部分形状像盒子，在 Node-RED 中称为节点。此外，除了一些节点外，通常在编程时，节点可以将可以作为节点属性的变量（参数，参数等）设置为节点属性。

换句话说，由于已经编程了部分（节点），因此只需将它们放置在 GUI 中即可完成编程。以下图比较了纯 Node.js 编程与在 Node-RED 中创建流的情况：

![图 4.1 – Node-RED 与 Node.js 编程](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_4.1_B16353.jpg)

图 4.1 – Node-RED 与 Node.js 编程

现在您了解了 Node-RED 和节点的概念，让我们更仔细地看看节点。

当您启动 Node-RED 时，基本处理节点默认提供在 Node-RED 流编辑器中。这称为**预安装节点**。

以下是预安装节点的典型类别：

+   **常见**：这包括将特定数据注入流的节点，判断处理状态的节点以及用于调试输出日志的节点。

+   **功能**：这包括可以直接在 JavaScript 和 HTML 中编写的节点，可以转换参数变量的节点以及根据这些参数的内容进行条件分支的节点。

+   **网络**：这包括处理通信所需的协议处理的节点，如 MQTT，HTTP 和 WebSockets。

当然，这里给出的示例只是一小部分。实际上有许多更多的类别和节点。

重要提示

预安装的节点也取决于 Node-RED 版本。建议查看官方文档以获取有关您的 Node-RED 版本的信息：[`nodered.org/docs/`](https://nodered.org/docs/)。

节点在 Node-RED 流程编辑器中排列像零件一样，并且可以通过简单连接电线来使用。如前所述，除了一些节点外，您不必自己编写代码。

基本上，流程编辑器看起来像一个框，里面有一个设置窗口。在设置窗口中，您可以为每个节点设置所需的参数和配置：

![图 4.2 - 节点](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_4.2_B16353.jpg)

图 4.2 - 节点

这就是您需要了解的有关节点的所有概念。在下一节中，您将学习如何实际使用节点。

# 如何使用节点

在本节中，我们将学习如何使用节点。

在 Node-RED 中进行可视化编程与其他可视化编程工具有些不同，因为它使用基于流的编程。但请放心，这一点并不难。如果您实际创建了一些简单的流程，您应该能够掌握如何在 Node-RED 中使用节点。

因此，现在让我们使用一些典型的预安装节点创建一个示例流程。树莓派、Windows 和 macOS 系统的环境是相同的。请使用您喜欢的环境。

## 常见类别

让我们介绍一下我们将用来制作流程的节点。您可以从常见类别中将所有节点放置在调色板上。

使用常见类别中的节点创建一个示例流程。使用以下四个节点：

+   **inject**节点

+   **complete**节点

+   **catch**节点

+   **debug**节点

请按照以下图示放置和连接节点：

![图 4.3 - 具有常见类别节点的流程](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_4.3_B16353.jpg)

图 4.3 - 具有常见类别节点的流程

这里**inject**节点中的数据是简单的 JSON 数据。双击放置的**inject**节点以打开设置面板并设置 JSON 数据。请参考以下内容：

```js
{"name":"Taiji"}
```

您可以更改**inject**节点中的 JSON 数据以发送您想要发送的数据。此外，您应该设置**complete**节点的属性。打开设置面板并设置一个节点来观察状态。

将每个节点的参数设置如下：

+   使用以下 JSON 创建`msg.payload`：

```js
{"name": "Taiji"}
```

您可以在这里设置任何值：

![图 4.4 - 用于插入数据的注入节点](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_4.4_B16353.jpg)

图 4.4 - 用于插入数据的注入节点

+   **complete**节点：

检查**属性**选项卡的第一个选项以观察**inject**节点的状态：

![图 4.5 - 用于观察状态的完整节点](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_4.5_B16353.jpg)

图 4.5 - 用于观察状态的完整节点

其他节点的属性无需更改。

设置更改后，您需要部署并单击**inject**节点的按钮。之后，您可以在**debug**选项卡的右侧面板中看到 JSON 数据。

您可以从本书的 GitHub 存储库中获取流程定义[`github.com/PacktPublishing/-Practical-Node-RED-Programming/blob/master/Chapter04/common-flows.json`](https://github.com/PacktPublishing/-Practical-Node-RED-Programming/blob/master/Chapter04/common-flows.json)。

## 函数类别

在本节中，我们将学习如何使用函数类别中的一些主要节点，并将使用这些节点制作一个流程。

使用函数类别中的节点创建一个示例流程。在这里，我们将使用以下六个节点：

+   **inject**节点

+   **function**节点

+   **switch**节点

+   **change**节点

+   **template**节点

+   **debug**节点

请按照以下图示放置和连接节点：

![图 4.6 - 具有函数类别节点的流程](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_4.6_B16353.jpg)

图 4.6 - 具有函数类别节点的流程

请按照以下步骤制作流程：

1.  将**inject**节点和**debug**节点放置在调色板上。这两个节点可以使用其默认参数。这里不需要更改设置。

1.  在调色板上放置一个**function**节点。

1.  打开**function**节点的设置面板，并输入以下代码：

```js
// generate random number
var min = 1 ;
var max = 10 ;
var a = Math.floor( Math.random() * (max + 1 - min) ) +   min ;
// set random number to message
msg.payload = a;
// return message
return msg;
```

1.  编码后，点击**Done**保存设置：![图 4.7 - 函数节点设置](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_4.7_B16353.jpg)

图 4.7–功能节点设置

1.  放置`6`

1.  `5`

应该如下所示：

![图 4.8–开关节点设置](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_4.8_B16353.jpg)

图 4.8–开关节点设置

如果输入参数为`5`或更少，则输出路由为`1`，如果输入参数为`6`或更多，则输出路由为`2`。这意味着下一个节点取决于输入参数的数量。

1.  在调色板上放置两个**template**节点。

之前的功能是**switch**节点，因此数据根据输出结果而分割。

1.  打开**switch**节点的每个`1`的设置面板：

```js
The number is small: {{payload}} !
```

一旦我们添加了前面的代码，**template**节点将看起来像以下屏幕截图：

![图 4.9–第一个模板节点设置](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_4.9_B16353.jpg)

图 4.9–第一个模板节点设置

1.  输入第二个`2`的**switch**节点的以下代码：

```js
The number is big: {{payload}} !
```

它将看起来像以下屏幕截图：

![图 4.10–第二个模板节点设置](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_4.10_B16353.jpg)

图 4.10–第二个模板节点设置

1.  将**change**节点放置在调色板上，打开**change**节点的设置面板，并查看**规则**下方的设置框。

1.  从**to**旁边的下拉菜单中选择**string**，并在旁边的文本框中输入所需的字符串。这里写着**已更改为字符串数据！**。请参考以下屏幕截图：![图 4.11–更改节点设置](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_4.11_B16353.jpg)

图 4.11–更改节点设置

1.  更改设置后，您需要部署并单击**inject**节点的按钮。

一旦您这样做，您可以在右侧面板的调试选项卡中看到数据，如下所示：

![图 4.12–在调试选项卡中显示结果](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_4.12_B16353.jpg)

图 4.12–在调试选项卡中显示结果

第一个调试消息是默认的**inject**节点值作为时间戳。第二个是**change**节点后放置的**debug**节点的调试消息。最后一个取决于随机数，并由**template**节点格式化。

您可以从书的 GitHub 存储库中获取流程定义：[`github.com/PacktPublishing/-Practical-Node-RED-Programming/blob/master/Chapter04/function-flows.json`](https://github.com/PacktPublishing/-Practical-Node-RED-Programming/blob/master/Chapter04/function-flows.json)。

接下来，让我们了解一些默认未提供的节点。

# 从库中获取几个节点

您可以获得由 Node-RED 贡献者开发的几个更有吸引力的节点，并将它们安装在您的 Node-RED 流编辑器中。您可以找到新节点，分享您的流程，并查看其他人如何使用 Node-RED。在本节中，我们将学习如何从 Node-RED 库中获取几个其他节点。让我们首先访问 Node-RED 库站点：[`flows.nodered.org/`](https://flows.nodered.org/)。在以下屏幕截图中，您可以看到 Node-RED 库的外观：

![图 4.13–Node-RED 库](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_4.13_B16353.jpg)

图 4.13–Node-RED 库

在您自己的 Node-RED 环境的流编辑器中使用此库非常容易。让我们看看如何从库中安装节点：

1.  从侧边栏菜单中选择**管理调色板**。您将看到**用户设置**面板打开，并选择了**调色板**选项卡。

1.  在搜索字段中键入`watson`，或者您想要使用的任何其他节点的名称。如果找到想要的节点，请单击**安装**按钮：![图 4.14–打开用户设置面板并找到要使用的节点](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_4.14_B16353.jpg)

图 4.14–打开用户设置面板并找到要使用的节点

1.  单击**安装**按钮后，将出现一个弹出窗口，您需要再次单击**安装**。

一旦您这样做并且安装完成，您将收到一个弹出消息，上面写着**节点已添加到调色板**。

就是这样！你可以在调色板中看到你安装的所有节点，如下图所示：

![图 4.15 - 你安装的节点被添加到你的调色板中](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_4.15_B16353.jpg)

图 4.15 - 你安装的节点被添加到你的调色板中

提示

你可以在 Node-RED 库网站上搜索有用的节点。可以通过关键词搜索，并按照最近添加、下载次数和评分进行排序。我建议首先按下载次数排序，因为被许多开发者下载的节点很可能非常有用：[`flows.nodered.org/search?type=node&sort=downloads`](https://flows.nodered.org/search?type=node&sort=downloads)。

现在你已经成为了一个优秀的 Node-RED 用户，并且掌握了如何使用 Node-RED 流编辑器制作一些流程（应用程序）。

# 总结

在本章中，你学会了如何在 Node-RED 流编辑器中使用每个主要节点。你已经成功地制作了你的 Node-RED 流程！你在这里创建的流程步骤是你将来需要创建各种流程的大部分步骤。

本章学到的重要一点是，每个节点都有自己独特的特性。通过像拼图一样组合它们，我们可以创建一个类似于通过常规编程创建的应用程序的流程。

在下一章中，让我们为物联网边缘设备创建一个更实用的示例流程（应用程序）。


# 第二部分：掌握 Node-RED

在这一部分，读者将使用 Node-RED 流编辑器实际创建一个应用程序。他们将首先学习如何为每个主要环境（即树莓派、桌面和云等独立环境）创建一个示例流，而不是试图从头开始构建高级应用程序。

在这一部分，我们将涵盖以下章节：

+   *第五章*, [*本地实现 Node-RED*](https://epic.packtpub.com/index.php?module=oss_Chapters&action=DetailView&record=357f4893-3535-50c5-da63-5ed08ca52158)

+   *第六章*, [*在云中实现 Node-RED*](https://epic.packtpub.com/index.php?module=oss_Chapters&action=DetailView&record=2a24eba8-3fc5-b13f-a829-5ed08c56141d)

+   *第七章*, [*从 Node-RED 调用 Web API*](https://epic.packtpub.com/index.php?module=oss_Chapters&action=DetailView&record=976a0979-ff68-102c-812a-5ed08c769020)

+   *第八章*, [*使用 Git 的项目功能*](https://epic.packtpub.com/index.php?module=oss_Chapters&action=DetailView&record=3c3cbb04-0b5d-e147-bfa9-5ed08c8eeab3)


# 第五章：本地实现 Node-RED

在本章中，让我们使用独立版本的 Node-RED。Node-RED 包括开发环境、执行环境和应用程序本身。您可以通过在本地环境中运行的独立版本来理解其机制。

具体来说，启动独立版本的 Node-RED 最常见的原因是在物联网边缘设备上使用它。物联网边缘设备通常具有传感器，这些传感器通常应用于“物联网”的“物”部分。在本章中，我们将查看边缘设备内的传感数据并创建一个示例流程。

让我们从以下四个主题开始：

+   在本地机器上运行 Node-RED

+   使用独立版本的 Node-RED

+   在边缘设备上使用物联网

+   创建一个示例流程

在本章结束时，您将学会如何构建处理物联网设备传感器数据的流程。

# 技术要求

要完成本章，您需要以下内容：

+   Node-RED（v1.1.0 或更高版本）：[`nodered.org/`](https://nodered.org/)

+   树莓派：[`www.raspberrypi.org/`](https://www.raspberrypi.org/)

本章中使用的代码可以在[`github.com/PacktPublishing/-Practical-Node-RED-Programming`](https://github.com/PacktPublishing/-Practical-Node-RED-Programming)的`Chapter05`文件夹中找到。

# 在本地机器上运行 Node-RED

现在我们可以为物联网边缘设备上的传感数据创建流程，在这种情况下，本地机器使用的是树莓派。关于这一点将在*使用独立版本的 Node-RED*部分中描述，但总的来说，本教程是为物联网边缘设备而设计的。

我已经解释了如何在树莓派上启动 Node-RED，所以您现在应该知道如何运行它，但如果您需要复习，请参考*第二章*中的*为树莓派安装 Node-RED*部分，*设置开发环境*。

现在，按照以下步骤在您的树莓派上启动 Node-RED：

1.  让我们从树莓派菜单中执行 Node-RED 开始：![图 5.1 – 从树莓派菜单中运行 Node-RED](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_5.01_B16353.jpg)

图 5.1 – 从树莓派菜单中运行 Node-RED

1.  您可以在终端上检查 Node-RED 的状态。如果显示**Started flows**，则 Node-RED 已准备就绪：![图 5.2 – 树莓派终端](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_5.2_B16353.jpg)

图 5.2 – 树莓派终端

1.  您可以通过`localhost:1880` URL 访问 Node-RED 流程编辑器：

![图 5.3 – Node-RED 流程编辑器](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_5.3_B16353.jpg)

图 5.3 – Node-RED 流程编辑器

在使用流程编辑器之前，让我们学习一些概念。

# 使用独立版本的 Node-RED

现在我们将学习独立版本的 Node-RED 是什么，以及它与其他版本有何不同。通常我们使用 Node-RED 流程编辑器作为独立编辑器；然而，我们也可以在任何具有 Docker、Kubernetes 或 Cloud Foundry 等容器技术的云上使用 Node-RED 流程编辑器。我们将明确演示使用独立版本的用例，以学习如何使用它。

让我们思考一下 Node-RED 被使用的情况。

Node-RED 是用 Node.js 创建应用程序的工具。它也是执行环境。如果你能用 Node.js 编写应用程序，那就没问题。

那么，为什么要使用 Node-RED 构建应用程序呢？

一个答案是将每个数据处理单元视为黑匣子。这使得每个过程的作用非常清晰，易于构建和维护。

另一个答案是避免人为错误。由于每个过程都被模块化为一个节点，因此在使用该过程时，您只需要了解输入/输出规范。这意味着您可以避免人为错误，如编码错误和缺少测试规范。这也可以是无代码/低代码以及 Node-RED 的优势。

接下来，想象一个使用 Node-RED 的具体情况，具有刚刚描述的特征。

考虑一个控制数据并将其连接到下一个流程的业务逻辑。这在物联网解决方案中很常见。

物联网解决方案的标准架构是由边缘设备和云平台构建的。它将边缘设备获取的传感器数据发送到云端，然后在云端处理数据，如可视化、分析和持久化。

在本章中，我想专注于边缘设备部分。

边缘设备通常希望在将获取的传感器数据发送到云端之前对其进行一定程度的准备。这样做的原因是，如果您发送所有获取的数据，存在网络过载的风险。

因此，独立的 Node-RED 练习使用了树莓派，这是一个著名的物联网基础设施。

在本章中，我们将使用树莓派和 Grove Base 模块的**Grove Base HAT**。这是物联网边缘设备平台的标准之一，因此我们需要将 Grove Base 驱动程序安装到树莓派上。

重要提示

本章提供了一个使用 Grove Base HAT 的示例，这是相对便宜且可以购买的（链接在下一节中提到），但是任何可以连接到树莓派并在 Node-RED 上处理数据的传感器设备都可以处理数据。

当使用除 Grove Base HAT 传感器设备以外的模块时，请使用相应的节点并阅读本章。（如果没有相应的节点，则需要进行实现。）

您可以检查 Node-RED 库以查看是否存在与每个设备对应的节点：

[`flows.nodered.org/`](https://flows.nodered.org/)

让我们通过以下步骤准备在树莓派上使用 Grove Base HAT：

1.  让我们从在树莓派上执行以下命令开始：

```js
 $ curl -sL https://github.com/Seeed-Studio/grove.py/raw/master/install.sh | sudo bash -s -
```

1.  如果一切顺利，您将看到以下通知：![图 5.4 – 成功安装 grove.py](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_5.4_B16353.jpg)

图 5.4 – 成功安装 grove.py

1.  接下来的步骤是启用 ARM I2C。我们可以通过执行以下命令来实现：

```js
 $ sudo raspi-config
```

1.  执行完命令后，您将看到以下配置窗口。请选择**接口选项**：![图 5.5 – 软件配置工具](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_5.5_B16353.jpg)

图 5.5 – 软件配置工具

1.  选择**I2C**：![图 5.6 – 启用 I2C](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_5.6_B16353.jpg)

图 5.6 – 启用 I2C

1.  选择后，同一窗口将显示**是否要启用 ARM I2C 接口？**消息。请选择**是**以接受它。

您现在已成功启用了 I2C。重新启动树莓派并重新启动 Node-RED 流编辑器。通过这样做，您的树莓派已经可以使用 I2C 接口，下一步，我们需要通过 I2C 接口连接传感器设备和树莓派。

# 在边缘设备上使用物联网

现在让我们考虑物联网中边缘设备的案例研究。

物联网最近在几个行业中得到了采用，例如天气预报和农业领域；但是，基本构成是相同的。边缘设备获取的各种数据被发送到服务器端平台，如云端，并且数据在服务器端进行处理和可视化，这是充满资源的。有各种各样的可视化方式，但在最简单的情况下，将必要的数据值输出到日志作为标准输出。

在本章中，我想考虑物联网用例中的边缘设备部分。这是关于在传感器模块使用获取的传感器数据在去往服务器端进行格式化和缩小之前进行处理。

有哪些不同类型的传感器？

以下传感器通常在物联网的实验级别上使用：

+   温度

+   湿度

+   陀螺仪（加速度，角速度）

+   光

+   声音

+   压敏

+   磁性

在这里，我们将考虑使用光传感器和温度/湿度传感器将获取的值输出到日志的用例。

为了获取传感器数据，您需要一个设备。在这个示例流程（应用程序）中，使用的是树莓派，但它没有传感功能，因为它只是一个基础。使用老式的板，您必须焊接传感器设备/模块，但树莓派的方便之处在于有许多传感器模块套件可以一键连接。

如前所介绍的，我们将使用 Seeed 提供的 Grove 系列，该系列具有树莓派的传感器模块和连接板：[`wiki.seeedstudio.com/Grove_Base_Hat_for_Raspberry_Pi/`](https://wiki.seeedstudio.com/Grove_Base_Hat_for_Raspberry_Pi/)

让我们准备树莓派的 Grove Base HAT 模块。

重要提示

如果您没有树莓派的 Grove Base HAT 并且想要运行本教程，请通过官方网站购买（[`www.seeedstudio.com/Grove-Base-Hat-for-Raspberry-Pi.html`](https://www.seeedstudio.com/Grove-Base-Hat-for-Raspberry-Pi.html)）。

这就是用于树莓派的 Grove Base HAT 的样子：

![图 5.7 – 用于树莓派的 Grove Base HAT](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_5.07_B16353.jpg)

图 5.7 – 用于树莓派的 Grove Base HAT

我们需要将 Grove Base HAT 和传感器模块连接到树莓派。要做到这一点，请按照以下步骤进行：

1.  将 Grove Base HAT 放在树莓派上并拧紧：![图 5.8 – 将 Base HAT 设置在您的树莓派上](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_5.08_B16353.jpg)

图 5.8 – 将 Base HAT 设置在您的树莓派上

这就是 Grove - 光传感器 v1.2 - LS06-S 光电晶体管的样子：

![图 5.9 – Grove - 光传感器 v1.2](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_5.09_B16353.jpg)

图 5.9 – Grove - 光传感器 v1.2

您可以从[`www.seeedstudio.com/Grove-Light-Sensor-v1-2-LS06-S-phototransistor.html`](https://www.seeedstudio.com/Grove-Light-Sensor-v1-2-LS06-S-phototransistor.html)获取它。

1.  将 Grove 光传感器连接到 Base HAT 的模拟端口：![图 5.10 – 将光传感器连接到您的 Base HAT](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_5.10_B16353.jpg)

图 5.10 – 将光传感器连接到您的 Base HAT

重要提示

请注意！这家供应商**Seeed**有一个类似的温湿度传感器**SHT35**，但它不受 Grove Base HAT 节点支持。您需要使用**SHT31**。

这就是 Grove - 温湿度传感器（SHT31）的样子：

![图 5.11 – Grove – 温湿度传感器（SHT31）](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_5.11_B16353.jpg)

图 5.11 – Grove – 温湿度传感器（SHT31）

您可以从[`www.seeedstudio.com/Grove-Temperature-Humidity-Sensor-SHT31.html`](https://www.seeedstudio.com/Grove-Temperature-Humidity-Sensor-SHT31.html)获取它。

1.  将 Grove 温湿度传感器连接到 Base HAT 的 I2C 端口：

![图 5.12 – 将温湿度传感器连接到您的 Base HAT](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_5.12_B16353.jpg)

图 5.12 – 将温湿度传感器连接到您的 Base HAT

就是这样。现在您的设备已经设置好，我们准备进行下一步！在这一部分，我们已经了解了物联网边缘设备的流行简单用例，接下来，我们将为这些用例制作一个流程。

# 制作一个示例流程

在本节中，我们将在 Node-RED 流编辑器中创建这两个传感器数据输出流。

您将使用准备好的传感器模块收集数据，并创建一个示例流程，在 Node-RED 上将其可视化。通过使用两种不同的传感器模块，我们可以学习 Node-RED 中的数据处理基础知识。

## 用例 1 – 光传感器

第一个是光传感器。让我们创建一个流程（应用程序），检测光线并将固定点观察到的值输出到日志：

![图 5.13 – 用例 1 – 获取光传感器数据](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_5.13_B16353.jpg)

图 5.13 – 用例 1 – 获取光传感器数据

将光传感器模块连接到树莓派，并使用树莓派上的 Node-RED 流编辑器将获取的数据输出为标准输出。

## 用例 2 – 温湿度传感器

第二个是温度/湿度传感器。让我们创建一个应用程序（流），用于检测温度和湿度，并将通过固定点观察检测到的值输出到日志：

![图 5.14 – 用例 2 – 获取温度/湿度数据](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_5.14_B16353.jpg)

图 5.14 – 用例 2 – 获取温度/湿度数据

将温度/湿度传感器模块连接到树莓派，并使用树莓派上的 Node-RED 流程编辑器将获取的数据输出为标准输出。

如果您想在设备上对这两个用例进行现场测试，需要连接一个传感器，以获取传感器数据。

在创建流程之前，您可能需要准备这个。

这次，我们将使用 Grove Base HAT，它很容易与树莓派一起使用，由于上一步已经完成了设置，我们已经准备好在树莓派上访问数据。但是，我们还没有准备好 Node-RED。默认情况下，使用 Node-RED 访问这些数据是困难的。一种方法是使用 Function 节点并从头开始编写脚本，这非常困难但并非不可能。

为了处理 Raspberry Pi 在 Node-RED 上识别的传感器数据，需要一个专门用于 Grove Base HAT 的“节点”。

好消息是，您可以立即开始使用该节点。这是因为田中正吾（Seigo Tanaka）是 Node-RED 用户组日本董事会成员（[`nodered.jp/`](https://nodered.jp/)）和 Node-RED 贡献者，已经创建并发布了一个用于 Grove Base HAT 的节点。这是用于树莓派的 Grove Base HAT 节点：

```js
node-red-contrib-grove-base-hat
```

您可以在这里了解更多信息：[`www.npmjs.com/package/node-red-contrib-grove-base-hat`](https://www.npmjs.com/package/node-red-contrib-grove-base-hat)。

如果您需要复习如何安装发布在节点库中的节点，请阅读*第四章*中的*从库中获取多个节点*部分。

我之所以提到这一点，是因为下一步是将 Grove Base HAT 节点从库中安装到您的环境中。

让我们在 Node-RED 流程编辑器中启用 Grove Base HAT 节点：

1.  单击右上角的菜单，选择**管理调色板**以打开设置面板：![图 5.15 – 选择管理调色板](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_5.15_B16353.jpg)

图 5.15 – 选择管理调色板

1.  打开设置面板后，在搜索窗口中输入您想要使用的节点名称。我们想要使用**node-red-contrib-grove-base-hat**，所以请键入以下内容：

```js
grove base
```

1.  之后，您可以在搜索窗口中看到**node-red-contrib-grove-base-hat**节点。单击**安装**按钮：![图 5.16 – 安装 node-red-contrib-grove-base-hat 节点](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_5.16_B16353.jpg)

图 5.16 – 安装 node-red-contrib-grove-base-hat 节点

1.  单击**安装**按钮后，您将看到一条消息，要求您阅读文档以了解有关此节点的更多信息。如有必要，请阅读文档，然后单击消息框上的**安装**按钮：

![图 5.17 – 读取节点文档的消息窗口](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_5.17_B16353.jpg)

图 5.17 – 读取节点文档的消息窗口

现在您已经准备好使用 Grove Base HAT 节点了。检查流程编辑器中的调色板。在调色板底部，您可以看到已添加了 Grove Base HAT 节点：

![图 5.18 – 仪表板上的 Grove Base HAT 节点](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_5.18_B16353.jpg)

图 5.18 – 仪表板上的 Grove Base HAT 节点

Grove Base HAT 可以连接许多传感器模块。这次只使用了光线和温度/湿度传感器，但通过查看节点类型，还可以看到其他东西。

在这里创建的两个用例所遵循的程序也可以应用于使用其他传感器时。如果感兴趣，请尝试其他传感器。在下一节中，我们将为用例 1 创建一个流程。

## 为用例 1 制作流程 – 光传感器

在用例 1 中，Node-RED 可以用来处理从光传感器获取的光照强度作为 JSON 数据。该数据可以被处理为 JSON 数据，然后发送到服务器端，各种处理可以在边缘设备上轻松进行。

从光传感器获取的数值被 Node-RED 接收，并且输出为调试日志（标准输出）。我们可以通过以下步骤设置这一点：

1.  从流编辑器左侧的调色板中选择**grove light sensor v1_2**节点，然后将其拖放到工作区中放置：![图 5.19 – grove light sensor v1_2](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_5.19_B16353.jpg)

图 5.19 – grove light sensor v1_2

该节点允许传感器设备的值，通过 Raspberry Pi 通过 Grove Base HAT 持续获取，被处理为 Node-RED 上的 JSON 格式消息对象。

1.  在放置**grove-light-sensor-v1_2**节点后，放置**inject**节点和**debug**节点，并将它们连接，使得您放置的**grove-light-sensor-v1_2**节点被夹在它们之间：![图 5.20 – 放置节点并为光传感器连接它们](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_5.20_B16353.jpg)

图 5.20 – 放置节点并为光传感器连接它们

1.  接下来，检查**grove-light-sensor-v1_2**节点的设置。双击节点打开设置面板。

1.  在设置面板中有一个名为**Port**的选择项。**A0**是默认选择项。

这个**Port**设置是为了指定 Grove Base HAT 上的哪个连接器从连接的模块获取数据。

1.  早些时候，我们将 Grove 光传感器连接到了 Grove Base HAT。如果按照本教程中的步骤进行连接，它应该连接到 A2 端口，因此选择**A2**作为节点设置值。如果连接到另一个端口，请选择您要连接的端口：![图 5.21 – 如果您将传感器连接到 Base HAT 的 A2，则选择 A2 作为端口](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_5.21_B16353.jpg)

图 5.21 – 如果您将传感器连接到 Base HAT 的 A2，则选择 A2 作为端口

1.  在设置面板上检查和设置**Port**后，点击右上角的**Done**按钮关闭设置面板。

就是这样！不要忘记点击**deploy**按钮。

您应该记住如何从 inject 节点执行流程，因为您在上一章中学习了这个。点击 inject 节点上的开关来运行流程。当点击开关时的时间数据被输出为日志，所以请尝试点击几次。

重要提示

不要忘记显示调试窗口，以显示获取数据的值将输出到调试窗口。即使调试输出被激活，Node-RED 也不会自动显示调试窗口。

**debug**窗口中的输出结果如下：

![图 5.22 – 光传感器流的结果](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_5.22_B16353.jpg)

图 5.22 – 光传感器流的结果

您可以看到结果输出到**debug**窗口。

恭喜！通过这个，我们成功地创建了一个处理第一个光传感器值的基本流程（应用程序）与 Node-RED。

您也可以在这里下载流程定义文件：[`github.com/PacktPublishing/-Practical-Node-RED-Programming/blob/master/Chapter05/light-sensor-flows.json`](https://github.com/PacktPublishing/-Practical-Node-RED-Programming/blob/master/Chapter05/light-sensor-flows.json)。

## 为用例 2 制作流程 – 温湿度传感器

在用例 2 中，Node-RED 可以用来处理从温湿度传感器获取的温度和湿度作为 JSON 数据。这些数据可以被处理为 JSON 数据，然后发送到服务器端，各种处理可以在边缘设备上轻松进行。

从温湿度传感器获取的数值被 Node-RED 接收，并且输出为调试日志（标准输出）：

1.  从流程编辑器左侧的调色板中选择 **grove temperature humidity sensor sht3x** 节点，然后将其拖放到工作区中放置：![图 5.23 - grove temperature humidity sensor sht3x](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_5.23_B16353.jpg)

图 5.23 - grove temperature humidity sensor sht3x

这个节点允许将在树莓派上通过 Grove Base HAT 持续获取的传感器设备的值作为 JSON 格式的消息对象在 Node-RED 上处理。

1.  放置 **grove-temperature-humidity-sensor-sht3x** 节点后，分别放置 **inject** 和 **debug** 节点，并将它们连接起来，使得您放置的 **grove-temperature-humidity-sensor-sht3x** 节点被夹在它们之间：![图 5.24 - 放置节点并为温湿度传感器连接线路](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_5.24_B16353.jpg)

图 5.24 - 放置节点并为温湿度传感器连接线路

1.  接下来，检查 **grove-temperature-humidity-sensor-sht3x** 节点的设置，并双击节点打开设置面板。

实际上，这个节点没有要设置的值（严格来说，可以设置名称，但这个设置的有无不影响操作）：

![图 5.25 - 已设置为 I2C 端口](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_5.25_B16353.jpg)

图 5.25 - 已设置为 I2C 端口

您可以在设置面板上看到端口被指定为 **I2C**（不可更改）。如果您按照本文档中的步骤将 Grove 温湿度传感器连接到 Grove Base HAT，模块应正确连接到 **I2C** 端口。如果它连接到除 I2C 之外的端口，请重新正确连接。

1.  在设置面板上检查 **端口**，然后点击右上角的 **完成** 按钮关闭设置面板。

就是这样！不要忘记点击 **部署** 按钮。

1.  点击注入节点上的开关以运行流程。当点击开关时的时间数据将作为日志输出，所以请尝试点击几次。

重要提示

如前所述，请不要忘记显示调试窗口，以显示获取数据的值将作为输出显示在调试窗口中。即使启用了调试输出，Node-RED 也不会自动显示调试窗口。

**调试** 窗口中的输出如下所示：

![图 5.26 - 温湿度传感器流程的结果](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_5.26_B16353.jpg)

图 5.26 - 温湿度传感器流程的结果

您可以看到结果被输出到 **调试** 窗口。

恭喜！通过这个，我们已经成功创建了一个基本的流程（应用程序），用 Node-RED 处理第二个样本，即温湿度传感器的数值。

您也可以在这里下载这个流程定义文件：[`github.com/PacktPublishing/-Practical-Node-RED-Programming/blob/master/Chapter05/light-sensor-flows.json`](https://github.com/PacktPublishing/-Practical-Node-RED-Programming/blob/master/Chapter05/light-sensor-flows.json)。

干得好！现在您已经学会了如何在 Node-RED 上处理以 JSON 格式获得的光照传感器和温湿度传感器的数据。

# 总结

在本章中，您学会了如何通过将 Node-RED 与真实的 IoT 用例进行比较来创建一个样本流程（应用程序）。我们通过使用传感器模块和树莓派与 Node-RED 交换数据，对 IoT 有了一定的了解。

在这里创建的流程步骤将帮助您将来在边缘设备中使用其他传感器模块创建不同的流程。

在下一章中，我们将像这次一样使用 IoT 用例，但我们将在云端（服务器端）创建一个实际的样本流程（应用程序）。


# 第六章：在云中实现 Node-RED

在本章中，我们将学习如何利用 Node-RED，在云平台上（主要是作为服务的平台）独立使用。**作为服务的平台**（**PaaS**）提供了一个作为应用执行环境的实例，应用开发人员只需专注于执行自己创建的应用，而不用耗费精力构建环境。Node-RED 实际上是一个 Node.js 应用，因此您可以在任何具有 Node.js 运行时环境的地方运行它。

有各种主要的大型云，如 Azure、AWS 和 GCP，但 Node-RED 在 IBM Cloud 中默认准备了一个入门应用（在 IBM Cloud 上可以启动的 Web 应用称为入门应用），所以我们将在本章中使用它。

在本章中，我们将涵盖以下主题:

+   在云上运行 Node-RED

+   在云中使用 Node-RED 的具体情况是什么？

+   服务器端的物联网案例研究

+   创建一个示例流程

在本章结束时，您将掌握如何在云上构建处理传感器数据的流程。

# 技术要求

本章中使用的代码可以在[`github.com/PacktPublishing/-Practical-Node-RED-Programming`](https://github.com/PacktPublishing/-Practical-Node-RED-Programming)的`Chapter06`文件夹中找到。

# 在云上运行 Node-RED

这次我们将使用 IBM Cloud。原因是 IBM Cloud 上有 Node-RED Starter Kit。这是一种软件样板，包括 Node-RED 在云上所需的服务，如数据库、CI/CD 工具等。

如果您还没有使用过 IBM Cloud，不用担心 - IBM 提供免费的 IBM Cloud 账户（Lite 账户），无需注册信用卡。您可以在[`ibm.biz/packt-nodered`](http://ibm.biz/packt-nodered)注册 IBM Cloud Lite 账户。

在 IBM Cloud 上使用 Node-RED 之前，您需要完成 IBM Cloud Lite 账户的注册流程。

重要提示

在本书中，我们强烈建议您在使用 IBM Cloud 时选择 Lite 账户。您可以随意从 Lite 账户升级到标准账户（PAYG/按使用付费），这意味着您可以通过注册信用卡自动升级到 PAYG。

请注意，使用 Lite 账户可以免费使用的服务，在 PAYG 中可能会收费。

现在，让我们按照以下步骤在 IBM Cloud 上启动 Node-RED：

重要提示

这里提供的说明/截图在撰写时是正确的。IBM Cloud 的用户界面变化如此之快，可能与当前的用户界面不同。

1.  使用您之前创建的账户登录 IBM Cloud ([`cloud.ibm.com`](https://cloud.ibm.com))：![图 6.1 - 通过您的 Lite 账户登录](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_6.1_B16353.jpg)

图 6.1 - 通过您的 Lite 账户登录

1.  登录 IBM Cloud 后，您将在屏幕上看到您自己的仪表板。如果这是您第一次使用 IBM Cloud，在仪表板上将不会显示任何资源:![图 6.2 - IBM Cloud 仪表板](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_6.2_B16353.jpg)

图 6.2 - IBM Cloud 仪表板

接下来，我们将在这个云平台上创建 Node-RED。

1.  我们将在云上创建 Node-RED 作为一个服务。从左上角的菜单中点击**应用开发**，然后点击**获取一个入门套件**按钮。这样可以创建一个新的应用服务:![图 6.3 - 获取入门套件按钮](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_6.3_B16353.jpg)

图 6.3 - 获取入门套件按钮

1.  如果您在搜索框中输入`Node-RED`，就可以找到 Node-RED。找到后，点击**Node-RED**面板:![图 6.4 - Node-RED 入门套件](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_6.4_B16353.jpg)

图 6.4 - Node-RED 入门套件

1.  点击**Node-RED**面板后，我们需要设置一些项目。

您可以通过提供自己的值自由更改每个项目，但在本章中，这里设置的值将用于解释目的。

请参阅*图 6.5*以进行配置的设置和值。请注意，一旦设置，这些项目将无法在以后更改。

1.  设置所有项目后，点击**创建**按钮：![图 6.5 - 将 Node-RED 创建为 Node.js 应用程序](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_6.5_B16353.jpg)

图 6.5 - 将 Node-RED 创建为 Node.js 应用程序

您现在已经创建了 Node-RED 应用程序的框架。之后，您将被自动重定向到**应用程序详细信息**屏幕，在那里您将能够看到链接服务的**Cloudant**实例也已经被配置。

然而，只有应用程序源代码和合作服务的实例被创建，它们尚未部署到 IBM Cloud 上的 Node.js 执行环境中。实际部署将在启用 CI/CD 工具链时完成。

1.  一切准备就绪后，点击屏幕中央的**部署您的应用**按钮以启用它：![图 6.6 - 部署您的 Node-RED 应用程序](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_6.6_B16353.jpg)

图 6.6 - 部署您的 Node-RED 应用程序

1.  点击**部署您的应用**按钮后，转到应用程序设置窗口。

1.  您将被要求创建 IBM Cloud API 密钥。不用担心，因为它将自动生成。点击**新建**按钮打开一个新的弹出窗口，然后在弹出窗口上点击**确定**按钮。一旦您这样做，IBM Cloud API 密钥将被生成：

IBM Cloud API 密钥

IBM Cloud API 密钥用于控制您的 IBM Cloud 帐户和各种服务（例如，在本教程中是 Cloud Foundry）。您可以使用它来为 IBM Cloud 上的服务发行外部访问令牌，例如。您可以在这里了解有关 IBM Cloud API 密钥的更多信息：[`cloud.ibm.com/docs/account?topic=account-manapikey`](https://cloud.ibm.com/docs/account?topic=account-manapikey)。

![图 6.7 - 生成 IBM Cloud API 密钥](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_6.7_B16353.jpg)

图 6.7 - 生成 IBM Cloud API 密钥

1.  在窗口中选择资源规范。

这一次，我们使用的是 IBM Cloud 的 Lite 帐户，因此我们在 IBM Cloud 上只有 256 MB 的内存可用于所有服务。因此，如果我们为 Cloud Foundry Node.js 服务使用 256 MB，我们将无法为其他服务使用更多内存。但是 Node-RED 需要 256 MB 才能在 IBM Cloud 上运行，因此请在这里使用 256 MB。默认情况下已经为实例分配了 256 MB，因此点击**下一步**按钮，不更改任何参数：

![图 6.8 - Node.js 运行时实例详细信息](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_6.8_B16353.jpg)

图 6.8 - Node.js 运行时实例详细信息

完成此操作后，将显示**DevOps 工具链**设置屏幕。

1.  点击**创建**按钮，填入默认值。

您可以将 DevOps 工具链名称更改为任何您喜欢的名称。这是用于标识您在 IBM Cloud 中创建的工具链的名称：

![图 6.9 - 配置 DevOps 工具链窗口](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_6.9_B16353.jpg)

图 6.9 - 配置 DevOps 工具链窗口

现在，您可以使用环境（Node.js 运行时和 DevOps 工具链）来运行您在上一步中创建的 Node-RED 应用程序。您创建的 Node-RED 应用程序会通过工具链自动部署在 Node.js 运行时上。

1.  确认**交付管道**（DevOps 工具链中执行每个工具的管道）区域中显示的**状态**为**成功**，然后点击其上方的工具链名称（在本例中为**Node-REDforPackt**）：![图 6.10 - 检查 Node-RED 的状态并转到 Pipeline 工具](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_6.10_B16353.jpg)

图 6.10 - 检查 Node-RED 的状态并转到 Pipeline 工具

在**交付管道**中，检查**构建**和**部署**面板的状态是否都是绿色并显示**阶段通过**。

1.  在**DEPLOY**面板下的**LAST EXECUTION RESULT**下点击**查看控制台**：![图 6.11 - 检查每个阶段的状态并转到应用程序控制台](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_6.11_B16353.jpg)

图 6.11 - 检查每个阶段的状态并转到应用程序控制台

1.  在 Node-RED 应用程序的控制台屏幕上，确认状态为**运行**，然后单击**查看应用 URL**：![图 6.12 - 检查 Node-RED 是否正在运行并打开 Flow Editor](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_6.12_B16353.jpg)

图 6.12 - 检查 Node-RED 是否正在运行并打开 Flow Editor

干得好！您在 IBM Cloud 上打开了 Node-RED 流编辑器。接下来，我们将开始使用您刚刚打开的 Node-RED 流编辑器。

如果在执行这些步骤时出现任何错误，最好删除 Cloud Foundry App、Cloudant 和 DevOps 工具链，并按照之前提到的相同步骤重新创建它们。

1.  设置**用户名**和**密码**以访问您在 IBM Cloud 上的流编辑器。

点击**访问应用 URL**后，您将被重定向到初始设置对话框，以便您可以在 IBM Cloud 上使用 Node-RED 流编辑器。

您可以通过单击每个**下一步**按钮来继续此对话框，但请注意，您应该选择**安全地设置编辑器，以便只有经过授权的用户才能访问它**，并使用**用户名**和**密码**登录以便登录到您自己的流编辑器。这是因为此流编辑器作为公共 Web 应用程序在 IBM Cloud 上。这意味着任何人都可以访问您的流编辑器，如果知道 URL 的话。因此，我强烈建议您选择此选项并设置您自己的**用户名**和**密码**值：

![图 6.13 - 设置用户名和密码以访问流编辑器](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_6.13_B16353.jpg)

图 6.13 - 设置用户名和密码以访问流编辑器

我们快要完成了！

1.  单击**转到您的 Node-RED 流编辑器**按钮，然后使用在上一步中设置的**用户名**和**密码**详细信息登录：![图 6.14 - 登录到您的 Node-RED 流编辑器](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_6.14_B16353.jpg)

图 6.14 - 登录到您的 Node-RED 流编辑器

接下来，我们将检查 IBM Cloud 上的 Node-RED 流编辑器，并查看它是否可用。

1.  单击**注入**节点并检查结果：

图 6.15 - 默认示例流

](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_6.15_B16353.jpg)

图 6.15 - 默认示例流

当您单击**注入**节点时，您将在**调试**选项卡上看到结果值：

![图 6.16 - 检查结果](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_6.16_B16353.jpg)

图 6.16 - 检查结果

现在，您可以在 IBM Cloud 上的 Node-RED 中创建一个流。Node-RED 流编辑器始终作为 IBM Cloud 上的 Node.js 应用程序运行。这意味着在 IBM Cloud 上启用了 Node.js 运行时服务（实例）。换句话说，与在树莓派上运行的 Node-RED 不同，此版本的 Node-RED 通过互联网访问流编辑器。

在接下来的部分，我将简要解释一下在这样的云上使用 Node-RED 的情况。

# 在云中使用 Node-RED 的具体情况是什么？

让我们重新审视 Node-RED 在云中的使用情况。

正如我们在上一章中提到的，Node-RED 既是一个工具，也是一个用 Node.js 编写的 Node.js 应用程序的执行环境。作为使用 Node-RED 构建应用程序的原因，我解释了通过黑箱化数据处理的各个单元，每个过程的作用变得非常清晰，易于构建和维护。

这不仅是在边缘设备上的原因，也是在服务器端（云端），用于持久化、分析和可视化由边缘设备收集的数据。

Node-RED 最大的特点是以消息的形式将 Node.js 的处理以顺序或并行的方式连接到输入/输出数据块的处理。可以说这非常适合物联网数据处理。

再次，正如我们在上一章中讨论的那样，物联网解决方案的标准架构是建立在边缘设备和云平台上的。它将边缘设备获取的传感器数据发送到云端，使其持久化，并为所需的处理链进行处理。

本章将重点关注云的这一部分。

边缘设备和云实际上还没有连接。假设数据已传递到云端，让我们将数据持久化存储在数据库中并进行可视化。

我们将使用在 IBM Cloud 上的 Node-RED 中所有开发人员都喜欢的仪表板节点。

在您在 IBM Cloud 上使用 Node-RED 之前，请安装一个新节点；即**node-red-dashboard**。

Node-RED 提供了**调色板管理器**，它易于安装，用于直接安装额外的节点。当您使用大量节点时，这非常有帮助。但是，由于 IBM Cloud Lite 帐户的 Node-RED 应用内存有限，可能会出现问题。

因此，在这里，我们需要获取`package.json`文件并在 IBM Cloud 上重新部署 Node-RED 应用程序。

您可以在[`flows.nodered.org/node/node-red-dashboard`](https://flows.nodered.org/node/node-red-dashboard)了解有关此节点的信息。

按照以下步骤对`package.json`文件进行更改：

1.  在 IBM Cloud 的 Node-RED **应用详情**页面上，点击**源代码**。这将把您重定向到一个 Git 仓库，您可以在那里编辑 Node-RED 应用的源代码：![图 6.17 – 访问您的应用源代码](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_6.17_B16353.jpg)

图 6.17 – 访问您的应用源代码

1.  点击文件列表上的`package.json`。这个文件定义了您的应用程序的模块依赖关系：![图 6.18 – 选择 package.json](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_6.18_B16353.jpg)

图 6.18 – 选择 package.json

1.  点击`dependencies`部分：

```js
"node-red-dashboard": "2.x",
```

1.  添加任何提交消息并点击**提交更改**按钮：

![图 6.19 – 编辑 package.json 并添加 node-red-dashboard](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_6.19_B16353.jpg)

图 6.19 – 编辑 package.json 并添加 node-red-dashboard

之后，持续交付管道将自动开始构建和部署 Node-RED 应用程序。您可以随时在交付管道上检查状态，就像您在创建 Node-RED Starter 应用程序时所做的那样：

![图 6.20 – 重新构建并自动部署您的应用程序](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_6.20_B16353.jpg)

图 6.20 – 重新构建并自动部署您的应用程序

当您在 lite 帐户上收到**部署阶段**失败的内存限制错误时，请在 IBM Cloud 仪表板上停止您的 Node-RED 服务，然后运行**部署阶段**。您可以通过访问 IBM Cloud 仪表板并在**资源摘要**下点击**Cloud Foundry 应用**来停止 Node-RED 服务：

![图 6.21 选择 Cloud Foundry 应用](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_6.21_B16353.jpg)

图 6.21 选择 Cloud Foundry 应用

之后，在**Cloud Foundry 应用**下的 Node-RED 记录上点击**停止**选项。

![图 6.22 点击停止选项](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_6.22_B16353.jpg)

图 6.22 点击停止选项

就是这样。您可以通过关闭**调色板管理**屏幕并在流编辑器的左侧向下滚动来确认已添加仪表板节点，如下面的截图所示：

![图 6.23 – 检查仪表板节点是否已安装](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_6.23_B16353.jpg)

图 6.23 – 检查仪表板节点是否已安装

还有一件事：我们需要使用数据库，但 IBM Cloud 的 Node-RED 默认使用 Cloudant 数据库。我们将在下一节的案例研究中使用 Cloudant。

现在，您可以在 IBM Cloud 上使用 Node-RED 进行物联网服务器端的情况。

# 物联网案例研究重点在服务器端

现在，让我们考虑物联网的服务器端用例研究。

它并不取决于每个边缘设备的情况。它主要用于处理数据并将其存储在数据库中以进行可视化。

在本章中，我们将考虑物联网的用例；也就是说，假设使用传感器模块接收的传感器数据在服务器端接收，并进行后续处理。

与上一章不同的是，在这个服务器端处理教程中，数据的内容并不重要。主要目的是保存接收到的数据并根据需要进行可视化，因此我想定义以下两个用例。

## 用例 1 - 存储数据

第一个用例是存储数据。让我们创建一个应用程序（流程），将您从设备接收到的数据存储起来。在本节中，我们不使用来自设备的真实数据；我们只使用由 inject 节点生成的数据：

![图 6.24 - 用例 1 概述](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_6.24_B16353.jpg)

图 6.24 - 用例 1 概述

现在，让我们看看第二个用例。

## 用例 2 - 温度/湿度传感器

第二个用例是将数据显示为图表。让我们创建一个应用程序（流程），将您从设备接收到的数据发布到仪表板上。我们不会使用任何设备的真实数据，只使用由 inject 节点生成的数据：

![图 6.25 - 用例 2 概述](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_6.25_B16353.jpg)

图 6.25 - 用例 2 概述

正如我们之前提到的，我们将使用 Cloudant 作为用例 1 的数据库，使用仪表板作为用例 2 的图表显示。这些已经准备好了。

# 创建一个示例流程

现在，让我们在 Node-RED 流编辑器上创建这两个服务器端用例流程。

请再次检查**Cloudant**节点和**仪表板**节点是否已安装在您的流编辑器上。如果没有，请按照本章*在云上使用 Node-RED 的具体情况*中提到的步骤安装这些节点。

现在，您需要在**Cloudant**上为本教程准备一个特定的数据库。请按照以下步骤进行：

1.  访问您的 IBM Cloud 仪表板，并从**资源摘要**区域点击**查看全部**：![图 6.26 - IBM Cloud 仪表板视图](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_6.26_B16353_.jpg)

图 6.26 - IBM Cloud 仪表板视图

1.  您会发现使用 Node-RED 创建的**Cloudant**服务。请点击服务的名称：![图 6.27 - 从资源列表中选择 Cloudant 服务](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_6.27_B16353_.jpg)

图 6.27 - 从资源列表中选择 Cloudant 服务

1.  点击**IBM Cloud**左上角的**启动仪表板**按钮：![图 6.28 - 启动 Cloudant 仪表板](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_6.28_B16353.jpg)

图 6.28 - 启动 Cloudant 仪表板

1.  启动 Cloudant 仪表板后，请点击`packt_db`。之后，点击**创建**按钮：

![图 6.29 - 在 Cloudant 上创建一个新数据库](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_6.29_B16353.jpg)

图 6.29 - 在 Cloudant 上创建一个新数据库

现在您已经为本教程创建了数据库，可以随时使用它！

## 为用例 1 创建一个流程 - 存储数据

在 IoT 中，服务器端处理从边缘设备接收到的数据开始。然而，正如我们之前提到的，我们将专注于将数据存储在数据库中，因此我们将使用由**inject**节点生成的虚拟数据。作为消息接收的数据块将在 Node-RED 上持久存储在 Cloudant 数据库中。

我们可以按照以下步骤制作流程：

1.  从左侧的调色板中将一个**inject**节点和一个**cloudant out**节点拖放到工作区中：![图 6.30 - 放置 Inject 节点和 cloudant out 节点](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_6.30_B16353.jpg)

图 6.30 - 放置 Inject 节点和 cloudant out 节点

**inject**节点生成虚拟数据，而**cloudant out**节点将输入值原样存储在 Cloudant 数据库中。

1.  之后，我们还将创建一个从 Cloudant 检索数据的流程，但首先，让我们只创建保存数据的流程。连接这些节点：![图 6.31 - 连接这两个节点](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_6.31_B16353.jpg)

图 6.31 - 连接这两个节点

1.  接下来，修改**inject**节点的设置。双击节点打开**设置**面板。

1.  选择**JSON**作为第一个参数；也就是**msg.payload**，然后点击右侧的**[…]**按钮打开 JSON 编辑器：![图 6.32 - 在 inject 节点的第一个参数上的 JSON](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_6.32_B16353.jpg)

```js
{"temp":"29.18", "humi":"55.72"}
```

您可以使用选项卡在文本编辑器和可视化编辑器之间切换。请参考以下图片：

![图 6.33 - 有两种类型的 JSON 编辑器可用](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_6.33_B16353.jpg)

图 6.33 - 有两种类型的 JSON 编辑器可用

无需编辑**msg.topic**。

1.  设置**JSON**数据后，点击右上角的**完成**按钮关闭**设置**面板。

1.  然后，编辑`packt_db`的设置作为数据库名称。这个名称是您在 Cloudant 仪表板上命名的数据库。

第一个参数**Service**会自动设置；它是 IBM Cloud 上的您的 Cloudant 服务。第三个参数**Operation**不需要从其默认值更改。

1.  设置数据库名称后，点击右上角的**完成**按钮关闭**设置**面板：![图 6.34 - 在 cloudant 输出节点上设置数据库名称](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_6.34_B16353.jpg)

图 6.34 - 在 cloudant 输出节点上设置数据库名称

1.  就是这样！不要忘记点击**部署**按钮。

1.  点击**inject**节点上的按钮来运行流程。当按钮被点击时，数据将被存储在 Cloudant 数据库中。

此时，我们无法通过 Node-RED 流程编辑器检查 Cloudant 上的数据；我们只能在 Cloudant 仪表板上检查它：

![图 6.35 - Cloudant 仪表板上的结果](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_6.35_B16353.jpg)

图 6.35 - Cloudant 仪表板上的结果

现在，让我们按照以下步骤创建一个从 Cloudant 获取数据的流程：

1.  从左侧的调色板中将一个**inject**节点、一个**cloudant in**节点和一个**debug**节点拖放到工作区中，以创建一个新的流程。

**inject**节点只是作为触发器执行这个流程，所以不需要更改其中的参数。**cloudant in**节点从您的 Cloudant 数据库获取数据。**debug**节点在调试选项卡上输出日志。

1.  连接这些节点：![图 6.36 - 放置新的三个节点并将它们连接以获取数据](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_6.36_B16353.jpg)

图 6.36 - 放置新的三个节点并将它们连接以获取数据

1.  接下来，通过双击节点来修改**cloudant in**节点的设置，以打开其**设置**面板。

1.  就像`packt_db`作为数据库的名称，并选择**所有文档**作为第三个参数，也就是**搜索方式**。

第一个参数**Service**会自动设置；它是 IBM Cloud 上的您的 Cloudant 服务。

1.  设置数据库名称和搜索目标后，点击右上角的**完成**按钮关闭**设置**面板：![图 6.37 - 在 cloudant in 节点上设置数据库名称并搜索目标](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_6.37_B16353.jpg)

图 6.37 - 在 cloudant in 节点上设置数据库名称并搜索目标的结果

1.  就是这样！不要忘记点击**部署**按钮。

1.  点击**inject**节点上的按钮来运行流程。这样做时，您将从 Cloudant 数据库中获取数据。

您会看到结果被输出到**debug**窗口：

![图 6.38 - 从 Cloudant 获取数据的结果](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_6.38_B16353.jpg)

图 6.38 - 从 Cloudant 获取数据的结果

恭喜！通过这样，我们成功地创建了一个基本的流程（应用程序），它可以将传感器数据存储在 Node-RED 中的数据库中。

您也可以在这里下载流程定义文件：[`github.com/PacktPublishing/-Practical-Node-RED-Programming/blob/master/Chapter06/cloudant-flows.json`](https://github.com/PacktPublishing/-Practical-Node-RED-Programming/blob/master/Chapter06/cloudant-flows.json)

重要提示

此流程在 cloudant in/out 流中没有 Cloudant 服务名称的值。请检查一旦导入了此流程定义，您的服务名称是否已自动设置在其中。

现在您已经了解了如何在 Node-RED 上处理数据。我们将在下一节中可视化这些数据。

## 创建用例 2 的流程-可视化数据

第一个用例是将传感器数据存储在数据库中，而第二个用例是在 Node-RED 上可视化传感器数据。在 IoT 中，获取传感器数据后，我们必须以某种形式对其进行可视化。重点是检索和可视化用例 1 中存储的数据。我们将通过以下步骤来实现这一点：

1.  从左侧的调色板中将**inject**节点、**function**节点和**chart**节点放置在流程编辑器的工作区中，然后将这些节点连接起来：![图 6.39 - 放置节点并连接它们以显示数据](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_6.39_B16353.jpg)

图 6.39 - 放置节点并连接它们以显示数据

**Inject**节点只是作为触发器执行此流程，因此无需更改其中的参数。**function**节点生成要显示在 Node-RED 上的图表上的数字数据。最后，**chart**节点使数据能够出现在图表上。

1.  在**function**节点中编写代码以生成可以传递给图表节点的数字数据。

1.  双击节点以打开设置面板。然后，将以下代码添加到您放置的**function**节点中：

```js
// Set min and max for random number
var min = -10 ;
var max = 10 ;
// Generate random number and return it
msg.payload = Math.floor( Math.random() * (max + 1 - min) ) + min ;
return msg;
```

就是这样：

![图 6.40 - 用于生成随机数的代码](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_6.40_B16353.jpg)

图 6.40 - 用于生成随机数的代码

1.  编写此脚本后，单击右上角的**Done**按钮关闭**Settings**面板。

1.  然后，在此处编辑`Packt Chart`的设置。

1.  输入名称后，单击`Packt Chart`。现在，单击右上角的**Done**按钮：![图 6.41 - 在图表节点上设置参数](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_6.41_B16353.jpg)

图 6.41 - 在图表节点上设置参数

1.  就是这样！不要忘记单击**Deploy**按钮。

1.  单击**inject**节点上的左按钮以运行流程。当单击按钮时，**function**节点生成的数据将被发送到**chart**节点。

您可以在仪表板窗口上查看结果。

1.  单击流程编辑器右上角的**Dashboard**按钮，然后单击**Open window**按钮。这两个按钮都是图标，因此请参考以下屏幕截图，以查看您必须单击哪些按钮：![图 6.42 - 单击仪表板图标按钮并打开窗口图标按钮](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_6.42_B16353.jpg)

图 6.42 - 单击仪表板图标按钮并打开窗口图标按钮

1.  新窗口中的折线图将为空。请多次单击**inject**节点的开关。之后，您将看到折线图中填充了值：

![图 6.43 - 具有值的折线图](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_6.43_B16353.jpg)

图 6.43 - 具有值的折线图

恭喜！通过这样做，我们已成功创建了一个基本的流程（应用程序），用 Node-RED 显示传感器数据的图表。

您还可以在此处下载此流程定义文件：[`github.com/PacktPublishing/-Practical-Node-RED-Programming/blob/master/Chapter06/dashboard-flows.json`](https://github.com/PacktPublishing/-Practical-Node-RED-Programming/blob/master/Chapter06/dashboard-flows.json)。

# 摘要

在本章中，您学会了如何通过遵循真实的 IoT 用例创建服务器端示例流程（应用程序）。这些都是简单的教程，但我相信对您有益，这样您就能够为 IoT 服务器端应用程序制作流程。

我们在这里创建的流程步骤将帮助您为将来创建其他服务器端应用程序的不同流程。

在下一章中，我们将使用与本章相同的 IoT 用例，但我们将创建一个实际的示例流程（应用程序），该流程将调用 Web API。
