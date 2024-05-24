# WebAssembly 游戏开发实用指南（一）

> 原文：[`annas-archive.org/md5/2bc11e3fb2b816b3a221f95dafc6aa63`](https://annas-archive.org/md5/2bc11e3fb2b816b3a221f95dafc6aa63)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

WebAssembly 是一项将在未来几年改变网络的技术。WebAssembly 承诺了一个世界，网络应用程序以接近本机速度运行。这是一个你可以用任何喜欢的语言为网络编写应用程序，并将其编译为本机平台以及网络的世界。对于 WebAssembly 来说，现在还处于早期阶段，但这项技术已经像火箭一样起飞。如果你对网络的未来和现在一样感兴趣，那就继续阅读吧！

我写这本书是为了反映我喜欢学习新技能的方式。我将带领你通过使用 WebAssembly 及其所有相关技术开发游戏。我是一名长期从事游戏和网络开发的人，我一直喜欢通过编写游戏来学习新的编程语言。在这本书中，我们将使用与 WebAssembly 紧密相关的网络和游戏开发工具涵盖许多主题。我们将学习如何使用各种编程语言和工具编写针对 WebAssembly 的游戏，包括 Emscripten、C/C++、WebGL、OpenGL、JavaScript、HTML5 和 CSS。作为一家专门从事网络游戏开发的独立游戏开发工作室的老板，我发现了解网络和游戏技术是至关重要的，我在这本书中充满了这些技术。你将学习一系列技能，重点是如何使用 WebAssembly 快速启动应用程序。如果你想学习如何使用 WebAssembly 开发游戏，或者想创建运行速度极快的基于网络的应用程序，这本书适合你。

# 这本书是为谁写的

这本书不是编程入门。它适用于至少掌握一种编程语言的人。了解一些网络技术，如 HTML，会有所帮助，但并非绝对必要。这本书包含了如何在 Windows 或 Ubuntu Linux 上安装所需工具的说明，如果两者中选择一个，我建议使用 Ubuntu，因为它的安装过程要简单得多。

# 这本书涵盖了什么

第一章，*WebAssembly 和 Emscripten 简介*，介绍了 WebAssembly，为什么网络需要它，以及为什么它比 JavaScript 快得多。我们将介绍 Emscripten，为什么我们需要它进行 WebAssembly 开发，以及如何安装它。我们还将讨论与 WebAssembly 相关的技术，如 asm.js、LLVM 和 WebAssembly Text。

第二章，*HTML5 和 WebAssembly*，讨论了 WebAssembly 模块如何使用 JavaScript“粘合代码”与 HTML 集成。我们将学习如何创建自己的 Emscripten HTML 外壳文件，以及如何在我们将用 C 编写的 WebAssembly 模块中进行调用和调用。最后，我们将学习如何编译和运行与我们的 WebAssembly 模块交互的 HTML 页面，以及如何使用 Emscripten 构建一个简单的 HTML5 Canvas 应用程序。

第三章，*WebGL 简介*，介绍了 WebGL 及支持它的新画布上下文。我们将学习着色器是什么，以及 WebGL 如何使用它们将几何图形渲染到画布上。我们将学习如何使用 WebGL 和 JavaScript 将精灵绘制到画布上。最后，我们将编写一个应用程序，集成了 WebAssembly、JavaScript 和 WebGL，显示一个精灵并在画布上移动。

第四章，*在 WebAssembly 中使用 SDL 进行精灵动画*，教你关于 SDL 库以及我们如何使用它来简化从 WebAssembly 到 WebGL 的调用。我们将学习如何使用 SDL 在 HTML5 画布上渲染、动画化和移动精灵。

第五章，“键盘输入”，介绍了如何从 JavaScript 中接收键盘输入并调用 WebAssembly 模块。我们还将学习如何在 WebAssembly 模块内使用 SDL 接受键盘输入，并使用输入来移动 HTML5 画布上的精灵。

第六章，“游戏对象和游戏循环”，探讨了一些基本的游戏设计。我们将学习游戏循环，以及 WebAssembly 中的游戏循环与其他游戏的不同之处。我们还将学习游戏对象以及如何在游戏内部创建对象池。我们将通过编写游戏的开头来结束本章，其中有两艘太空船在画布上移动并互相射击。

第七章，“碰撞检测”，将碰撞检测引入我们的游戏中。我们将探讨 2D 碰撞检测的类型，实现基本的碰撞检测系统，并学习一些使其工作的三角学知识。我们将修改我们的游戏，使得当抛射物相撞时太空船被摧毁。

第八章，“基本粒子系统”，介绍了粒子系统，并讨论了它们如何可以在视觉上改善我们的游戏。我们将讨论虚拟文件系统，并学习如何通过网页向其中添加文件。我们将简要介绍 SVG 和矢量图形，以及如何将它们用于数据可视化。我们还将进一步讨论三角学以及我们将如何在粒子系统中使用它。我们将构建一个新的 HTML5 WebAssembly 应用程序，帮助我们配置和测试稍后将添加到我们的游戏中的粒子系统。

第九章，“改进的粒子系统”，着手改进我们的粒子系统配置工具，添加了粒子缩放、旋转、动画和颜色过渡。我们将修改工具以允许粒子系统循环，并添加爆发效果。然后，我们将更新我们的游戏以支持粒子系统，并为我们的引擎排气和爆炸添加粒子系统效果。

第十章，“AI 和转向行为”，介绍了 AI 和游戏 AI 的概念，并讨论了它们之间的区别。我们将讨论有限状态机、自主代理和转向行为的 AI 概念，并在敌方 AI 中实现这些行为，使其能够避开障碍物并与玩家作战。

第十一章，“设计 2D 摄像头”，引入了 2D 摄像头设计的概念。我们将首先向我们的游戏添加一个渲染管理器，并创建一个锁定在玩家太空船上的摄像头，跟随它在扩展的游戏区域周围移动。然后，我们将添加投影焦点和摄像头吸引器的高级 2D 摄像头功能。

第十二章，“音效”，涵盖了在我们的游戏中使用 SDL 音频。我们将讨论从在线获取音效的位置，以及如何将这些声音包含在我们的 WebAssembly 模块中。然后，我们将向我们的游戏添加音效。

第十三章，“游戏物理”，介绍了计算机游戏中的物理概念。我们将在我们的游戏对象之间添加弹性碰撞。我们将在游戏的物理中添加牛顿第三定律，即当太空船发射抛射物时的后坐力。我们将在吸引太空船的星球上添加一个重力场。

第十四章，“UI 和鼠标输入”，讨论在我们的 WebAssembly 模块中添加要管理和呈现的用户界面。我们将收集要求并将其转化为我们游戏中的新屏幕。我们将添加一个新的按钮对象，并学习如何使用 SDL 从我们的 WebAssembly 模块内管理鼠标输入。

第十五章，“着色器和 2D 照明”，深入探讨了如何创建一个混合 OpenGL 和 SDL 的新应用程序。我们将创建一个新的着色器，加载并渲染多个纹理到一个四边形上。我们将学习法线贴图，以及如何使用法线贴图来在 2D 中近似冯氏光照模型，使用 OpenGL 在我们的 WebAssembly 模块中。

第十六章，“调试和优化”，介绍了调试和优化 WebAssembly 模块的基本方法。我们将从 WebAssembly 的调试宏和堆栈跟踪开始。我们将介绍源映射的概念，以及 Web 浏览器如何使用它们来调试 WebAssembly 模块。我们将学习使用优化标志来优化 WebAssembly 代码。我们将讨论使用分析器来优化我们的 WebAssembly 代码。

# 充分利用本书

您必须了解计算机编程的基础知识。

了解 HTML 和 CSS 等网络技术的基础知识将有所帮助。

# 下载示例代码文件

您可以从这里下载本书的代码包：[`github.com/PacktPublishing/Hands-On-Game-Development-with-WebAssembly`](https://github.com/PacktPublishing/Hands-On-Game-Development-with-WebAssembly)。

我们还有来自我们丰富书籍和视频目录的其他代码包，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)上找到。去看看吧！

# 下载彩色图像

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图像。您可以在这里下载：[`www.packtpub.com/sites/default/files/downloads/9781838644659_ColorImages.pdf`](https://www.packtpub.com/sites/default/files/downloads/9781838644659_ColorImages.pdf)。

# 使用的约定

您可以从[www.packt.com](http://www.packt.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，您可以访问[www.packt.com/support](http://www.packt.com/support)并注册，以便直接通过电子邮件接收文件。

您可以按照以下步骤下载代码文件：

1.  登录或注册[www.packt.com](http://www.packt.com)。

1.  选择“支持”选项卡。

1.  单击“代码下载和勘误”。

1.  在搜索框中输入书名，然后按照屏幕上的说明操作。

下载文件后，请确保使用最新版本的解压缩或提取文件夹：

+   WinRAR/7-Zip for Windows

+   Zipeg/iZip/UnRarX for Mac

+   7-Zip/PeaZip for Linux

该书的代码包也托管在 GitHub 上，网址为[**https://github.com/PacktPublishing/Hands-On-Game-Development-with-WebAssembly**](https://github.com/PacktPublishing/Hands-On-Game-Development-with-WebAssembly)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还有来自我们丰富书籍和视频目录的其他代码包，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)上找到。去看看吧！

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码字，数据库表名，文件夹名，文件名，文件扩展名，路径名，虚拟 URL，用户输入和 Twitter 句柄。例如：“我们将复制`basic_particle_shell.html`文件到一个新的外壳文件，我们将其称为`advanced_particle_shell.html`。”

代码块设置如下：

```cpp
<label class="ccontainer"><span class="label">loop:</span>
<input type="checkbox" id="loop" checked="checked">
<span class="checkmark"></span>
</label>
<br/>
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```cpp
<label class="ccontainer"><span class="label">loop:</span>
<input type="checkbox" id="loop" checked="checked">
<span class="checkmark"></span>
</label>
<br/>
```

任何命令行输入或输出都以以下方式编写：

```cpp
emrun --list_browsers
```

**粗体**：表示新术语，重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会以这种形式出现在文本中。例如：“从管理面板中选择系统信息。”

警告或重要提示会以这种形式出现。

提示和技巧会出现在这样的形式中。

# 第一章：介绍 WebAssembly 和 Emscripten

欢迎来到令人兴奋的 WebAssembly 新世界！对于 WebAssembly 来说，现在还处于早期阶段，但这项技术目前正如火箭般腾飞，通过阅读本书，您有机会站在起步阶段。如果您对网络游戏开发感兴趣，或者您想尽可能多地了解这项新技术，以便在其成熟时为自己找到位置，那么您来对地方了。尽管 WebAssembly 还处于萌芽阶段，但所有主要的浏览器供应商都已经采用了它。现在是早期阶段，使用案例有限，但幸运的是，游戏开发是其中之一。因此，如果您想成为下一代网络应用程序开发派对的早期参与者，那就继续阅读吧，冒险家！

在本章中，我将向您介绍 WebAssembly、Emscripten 以及围绕 WebAssembly 的一些基础技术。我将教您 Emscripten 工具链的基础知识，以及如何使用 Emscripten 将 C++代码编译成 WebAssembly。我们将讨论 LLVM 是什么，以及它如何融入 Emscripten 工具链。我们将讨论 WebAssembly 的**最小可行产品**（**MVP**），以及在其当前 MVP 形式下 WebAssembly 的最佳使用案例，以及即将到来的内容。我将介绍**WebAssembly 文本**（**.wat**），以及我们如何使用它来理解 WebAssembly 字节码的设计，以及它与其他机器字节码的区别。我们还将简要讨论**asm.js**，以及它在 WebAssembly 设计中的历史意义。最后，我将向您展示如何在 Windows 和 Linux 上安装和运行 Emscripten。

在本章中，我们将涵盖以下主题：

+   什么是 WebAssembly？

+   我们为什么需要 WebAssembly？

+   为什么 WebAssembly 比 JavaScript 更快？

+   WebAssembly 会取代 JavaScript 吗？

+   什么是 asm.js？

+   对 LLVM 的简要介绍

+   对 WebAssembly 文本的简要介绍

+   什么是 Emscripten，我们如何使用它？

# 什么是 WebAssembly？

WebAssembly 不是像 JavaScript 那样的高级编程语言，而是一种编译的二进制格式，所有主要浏览器目前都能够执行。WebAssembly 是一种机器字节码，不是设计用于直接在任何真实机器硬件上运行，而是在每个浏览器内置的 JavaScript 引擎中运行。在某些方面，它类似于旧的**Java 虚拟机**（**JVM**）；例如，它是一个平台无关的编译字节码。JavaScript 字节码的一个主要问题是需要下载和安装浏览器中的插件才能运行字节码。**WebAssembly**不仅旨在在浏览器中直接运行而无需插件，而且还旨在生成在 Web 浏览器内高效执行的紧凑二进制格式。规范的 MVP 版本利用了浏览器制造商设计他们的 JavaScript **即时**（**JIT**）编译器的现有工作。WebAssembly 目前是一项年轻的技术，许多改进计划中。然而，使用当前版本的 WebAssembly 的开发人员已经看到了相对于 JavaScript 的性能提升 10-800%。

MVP 是可以赋予产品的最小功能集，以使其吸引早期采用者。由于当前版本是 MVP，功能集很小。有关更多信息，请参阅这篇关于 WebAssembly“后 MVP 未来”的优秀文章：[`hacks.mozilla.org/2018/10/webassemblys-post-mvp-future/`](https://hacks.mozilla.org/2018/10/webassemblys-post-mvp-future/)。

# 我们为什么需要 WebAssembly？

JavaScript 已经存在很长时间了。它已经从一个允许在网页上添加花里胡哨的小脚本语言发展成一个庞大的 JIT 编译语言生态系统，可以用来编写完整的应用程序。如今，JavaScript 正在做许多在 1995 年由网景创建时可能从未想象过的事情。JavaScript 是一种解释语言，这意味着它必须在运行时进行解析、编译和优化。JavaScript 也是一种动态类型语言，这给优化器带来了麻烦。

Chrome V8 团队成员 Franziska Hinkelmann 在*Web Rebels 2017*会议上发表了一次精彩的演讲，她讨论了过去 20 年来对 JavaScript 所做的所有性能改进，以及他们在 JavaScript V8 引擎中尽可能挤出每一点性能时遇到的困难：[`youtu.be/ihANrJ1Po0w`](https://youtu.be/ihANrJ1Po0w)。

WebAssembly 解决了 JavaScript 及其在浏览器中的悠久历史所带来的许多问题。因为 JavaScript 引擎已经是字节码格式，所以不需要运行解析器，这消除了应用程序执行中的一个重要瓶颈。这种设计还允许 JavaScript 引擎始终知道它正在处理的数据类型。字节码使优化变得更加容易。这种格式允许浏览器中的多个线程同时处理编译和优化代码的不同部分。

有关 Chrome V8 引擎解析代码时发生的详细解释，请参考*JSConf EU 2017*的这个视频，其中 Chrome V8 工具的 Marja Hölttä（负责人）详细介绍了您可能想要了解有关解析 JavaScript 的更多细节：[`www.youtube.com/watch?v=Fg7niTmNNLg&t=123s`](https://www.youtube.com/watch?v=Fg7niTmNNLg&t=123s)。

WebAssembly 不是一种高级编程语言，而是一个带有虚拟机操作码的二进制文件。目前，它被认为处于 MVP 开发阶段。这项技术仍处于初期阶段，但即使现在，它也为许多用例提供了显著的性能和文件大小优势，例如游戏开发。由于 WebAssembly 目前的限制，我们只有两种选择用于其开发的语言 - C/C++或 Rust。WebAssembly 的长期计划是支持多种编程语言进行开发。如果我想以最低的抽象级别编写，我可以在**Web Assembly Text**（**WAT**）中编写所有内容，但 WAT 是作为一种支持调试和测试的语言开发的，并不打算供开发人员用于编写应用程序。

# 为什么 WebAssembly 比 JavaScript 快？

正如我所提到的，WebAssembly 比 JavaScript 快 10-800％，这取决于应用程序。要理解原因，我需要谈一下当运行 JavaScript 代码时 JavaScript 引擎做了什么，以及当运行 WebAssembly 时它必须做什么。我将专门谈谈 V8（Chrome JavaScript 引擎），尽管据我所知，相同的一般过程也存在于 SpiderMonkey（Firefox）和 Chakra（IE 和 Edge）JavaScript 引擎中。

JavaScript 引擎的第一件事是将您的源代码解析成**抽象语法树**（**AST**）。源代码根据应用程序内的逻辑被分成分支和叶子。此时，解释器开始处理您当前执行的语言。多年来，JavaScript 一直是一种解释语言，因此，如果您在 JavaScript 中运行相同的代码 100 次，JavaScript 引擎必须将该代码转换为机器代码 100 次。可以想象，这是极其低效的。

Chrome 浏览器在 2008 年引入了第一个 JavaScript JIT 编译器。JIT 编译器与**提前编译**（**AOT**）编译器相对，它在运行代码时编译代码。一种分析器坐在那里观察 JavaScript 执行，寻找重复执行的代码。每当它看到代码执行几次时，就将该代码标记为 JIT 编译的“热”代码。然后编译器编译 JavaScript“存根”代码的字节码表示。这个字节码通常是**中间表示**（**IR**），与特定于机器的汇编语言相去一步。解码存根将比下次通过解释器运行相同代码的速度快得多。

以下是运行 JavaScript 代码所需的步骤：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-gm-dev-wasm/img/9dd90a0a-c663-46b1-9fa2-977cf4d76ee7.png)

图 1.1：现代 JavaScript 引擎所需的步骤

在所有这些情况下，还有一个**优化编译器**正在观察分析器以寻找“热”代码分支。优化编译器然后将这些代码分支优化为 JIT 创建的字节码的高度优化的机器代码。此时，JavaScript 引擎已经创建了一些运行速度非常快的代码，但有一个问题（或者可能有几个）。

JavaScript 引擎必须对数据类型做出一些假设，以获得优化的机器代码。问题是，JavaScript 是一种动态类型语言。动态类型使程序员更容易学习如何编写 JavaScript 代码，但对于代码优化器来说却是一个糟糕的选择。我经常看到的例子是，当 JavaScript 看到表达式`c = a + b`时会发生什么（尽管我们几乎可以将此示例用于任何表达式）。

执行此操作的任何机器代码几乎都需要三个步骤：

1.  将`a`值加载到一个寄存器中。

1.  将`b`值添加到一个寄存器中。

1.  然后将寄存器存储到`c`中。

以下伪代码摘自*ECMAScript® 2018 语言规范*的第 12.8.3 节，描述了 JavaScript 中使用加法运算符（+）时必须运行的代码：

```cpp
1\. Let lref be the result of evaluating AdditiveExpression.
2\. Let lval be ? GetValue(lref).
3\. Let rref be the result of evaluating MultiplicativeExpression.
4\. Let rval be ? GetValue(rref).
5\. Let lprim be ? ToPrimitive(lval).
6\. Let rprim be ? ToPrimitive(rval).
7\. If Type(lprim) is String or Type(rprim) is String, then
   a. Let lstr be ? ToString(lprim).
   b. Let rstr be ? ToString(rprim).
   c. Return the string-concatenation of lstr and rstr.
8\. Let lnum be ? ToNumber(lprim).
9\. Let rnum be ? ToNumber(rprim).
10.Return the result of applying the addition operation to lnum and      
   rnum.
```

您可以在网上找到*ECMAScript® 2018 语言规范*，网址为[`www.ecma-international.org/ecma-262/9.0/index.html`](https://www.ecma-international.org/ecma-262/9.0/index.html)。

这个伪代码并不是我们必须评估的全部内容。其中几个步骤是调用高级函数，而不是运行机器代码命令。例如，`GetValue`本身就有 11 个步骤，反过来又调用其他步骤。所有这些可能最终导致数百个机器操作码。这里发生的绝大部分是类型检查。在 JavaScript 中，当您执行`a + b`时，每个变量都可能是以下类型之一：

+   整数

+   浮点数

+   字符串

+   对象

+   这些的任何组合

更糟糕的是，JavaScript 中的对象也是高度动态的。例如，也许您已经定义了一个名为`Point`的函数，并使用`new`运算符创建了两个具有该函数的对象：

```cpp
function Point( x, y ) {
    this.x = x;
    this.y = y;
}

var p1 = new Point(1, 100);
var p2 = new Point( 10, 20 );
```

现在我们有两个共享相同类的点。假设我们添加了这行：

```cpp
p2.z = 50;
```

这意味着这两个点将不再共享相同的类。实际上，`p2`已经成为一个全新的类，这对该对象在内存中的存在位置和可用的优化产生了影响。JavaScript 被设计为一种高度灵活的语言，但这一事实产生了许多特殊情况，而特殊情况使优化变得困难。

JavaScript 动态特性带来的另一个优化问题是，没有一种优化是最终的。所有围绕类型的优化都必须不断使用资源进行检查，以查看它们的类型假设是否仍然有效。此外，优化器必须保留非优化代码，以防这些假设被证明是错误的。优化器可能会确定最初做出的假设结果是不正确的。这会导致“退出”，优化器将丢弃其优化代码并取消优化，导致性能不一致。

最后，JavaScript 是一种具有**垃圾收集**（**GC**）的语言，这使得 JavaScript 代码的作者在编写代码时可以承担更少的内存管理负担。尽管这对开发人员来说很方便，但它只是将内存管理的工作推迟到运行时的机器上。多年来，JavaScript 中的 GC 变得更加高效，但在运行 JavaScript 时，JavaScript 引擎仍然必须执行这项工作，而在运行 WebAssembly 时则不需要。

执行 WebAssembly 模块消除了运行 JavaScript 代码所需的许多步骤。WebAssembly 消除了解析，因为 AOT 编译器完成了该功能。解释器是不必要的。我们的 JIT 编译器正在进行近乎一对一的字节码到机器码的转换，这是非常快的。JavaScript 需要大部分优化是因为 WebAssembly 中不存在的动态类型。在 WebAssembly 编译之前，AOT 编译器可以进行与硬件无关的优化。JIT 优化器只需要执行 WebAssembly AOT 编译器无法执行的特定于硬件的优化。

以下是 JavaScript 引擎执行 WebAssembly 二进制文件的步骤：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-gm-dev-wasm/img/1d7fb906-b411-416d-a1a2-b32a2812d1ac.png)

图 1.2：执行 WebAssembly 所需的步骤

我想要提到的最后一件事不是当前 MVP 的特性，而是 WebAssembly 可能带来的未来。使现代 JavaScript 运行速度快的所有代码都占用内存。保留非优化代码的旧副本占用内存。解析器、解释器和垃圾收集器都占用内存。在我的桌面上，Chrome 经常占用大约 1GB 的内存。通过在我的网站[`www.classicsolitaire.com`](https://www.classicsolitaire.com)上运行一些测试，我可以看到启用 JavaScript 引擎时，Chrome 浏览器占用约 654MB 的内存。

这是一个任务管理器的截图：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-gm-dev-wasm/img/8d052928-1b7a-4284-a3c1-f65bae8e02e6.png)

图 1.3：启用 JavaScript 的 Chrome 任务管理器进程截图

关闭 JavaScript 后，Chrome 浏览器占用约 295MB。

这是一个任务管理器的截图：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-gm-dev-wasm/img/2a92e10a-f57d-4275-92d0-09154ab9b9ea.png)

图 1.4：没有 JavaScript 的 Chrome 任务管理器进程截图

因为这是我的网站之一，我知道该网站上只有几百千字节的 JavaScript 代码。对我来说，令人震惊的是，运行这么少量的 JavaScript 代码会使我的浏览器占用大约 350MB 的内存。目前，WebAssembly 在现有的 JavaScript 引擎上运行，并且仍然需要相当多的 JavaScript 粘合代码来使一切正常运行，但从长远来看，WebAssembly 不仅将允许我们加快 Web 上的执行速度，还将使我们能够以更小的内存占用来实现。

# WebAssembly 会取代 JavaScript 吗？

简短的回答是不会很快。目前，WebAssembly 仍处于 MVP 阶段。在这个阶段，使用案例的数量仅限于 WebAssembly 与 JavaScript 和文档对象模型（DOM）之间的有限来回。WebAssembly 目前无法直接与 DOM 交互，Emscripten 使用 JavaScript“粘合代码”来实现该交互。这种交互可能很快会发生变化，可能在您阅读本文时就已经发生了，但在未来几年，WebAssembly 将需要额外的功能来增加可能的使用案例数量。

WebAssembly 并不是一个“功能完备”的平台。目前，它无法与任何需要 GC 的语言一起使用。这种情况将会改变，最终，几乎所有强类型语言都将以 WebAssembly 为目标。此外，WebAssembly 很快将与 JavaScript 紧密集成，允许诸如 React、Vue 和 Angular 等框架开始用 WebAssembly 替换大量的 JavaScript 代码，而不影响应用程序编程接口（API）。React 团队目前正在努力改进 React 的性能。

从长远来看，JavaScript 可能会编译成 WebAssembly。出于技术原因，这还有很长的路要走。JavaScript 不仅需要 GC（目前不支持），而且由于其动态特性，JavaScript 还需要运行时分析器来进行优化。因此，JavaScript 将产生非常糟糕的优化代码，或者需要进行重大修改以支持严格类型。更有可能的是，像 TypeScript 这样的语言将添加功能，使其能够编译成 WebAssembly。

在 GitHub 上开发的*AssemblyScript*项目正在开发一个 TypeScript 到 WebAssembly 的编译器。该项目创建 JavaScript 并使用 Binaryen 将该 JavaScript 编译成 WebAssembly。AssemblyScript 如何处理垃圾回收的问题尚不清楚。有关更多信息，请参阅[`github.com/AssemblyScript/assemblyscript`](https://github.com/AssemblyScript/assemblyscript)。

JavaScript 目前在网络上无处不在；有大量的库和框架是用 JavaScript 开发的。即使有一大批开发人员渴望用 C++或 Rust 重写整个网络，WebAssembly 也还没有准备好取代这些 JavaScript 库和框架。浏览器制造商已经付出了巨大的努力来使 JavaScript 运行（相对）快速，因此 JavaScript 可能仍然会成为网络的标准脚本语言。网络将始终需要一种脚本语言，无数开发人员已经努力使 JavaScript 成为这种脚本语言，因此 JavaScript 很可能永远不会消失。

然而，网络需要一种编译格式，WebAssembly 很可能会满足这种需求。目前，编译代码可能在网络上只是一个小众市场，但在其他地方却是标准。随着 WebAssembly 接近功能完备的状态，它将提供比 JavaScript 更多的选择和更好的性能，企业、框架和库将逐渐向其迁移。

# 什么是 asm.js？

早期实现在 Web 浏览器中使用 JavaScript 实现类似本机速度的尝试是 asm.js。尽管达到了这个目标，并且 asm.js 被所有主要浏览器供应商采用，但它从未被开发人员广泛采用。asm.js 的美妙之处在于它仍然可以在大多数浏览器中运行，即使在那些不对其进行优化的浏览器中也是如此。asm.js 的理念是，可以在 JavaScript 中使用类型化数组来模拟 C++内存堆。浏览器模拟 C++中的指针和内存分配，以及类型。设计良好的 JavaScript 引擎可以避免动态类型检查。使用 asm.js，浏览器制造商可以避开 JavaScript 动态特性带来的许多优化问题，只需假装这个版本的 JavaScript 不是动态类型的即可。Emscripten 作为 C++到 JavaScript 编译器，迅速采用了 asm.js 作为其编译的 JavaScript 子集，因为它在大多数浏览器中的性能得到了改善。由 asm.js 带来的性能改进引领了 WebAssembly 的发展。用于使 asm.js 性能良好的相同引擎修改可以用来引导 WebAssembly MVP。只需要添加一个字节码到字节码编译器，就可以将 WebAssembly 字节码直接转换为浏览器使用的 IR 字节码。

在撰写本文时，Emscripten 不能直接从 LLVM 编译到 WebAssembly。相反，它将编译为 asm.js，并使用一个名为 Binaryen 的工具将 Emscripten 的 asm.js 输出转换为 WebAssembly。

# LLVM 简介

Emscripten 是我们将用来将 C++编译成 WebAssembly 的工具。在讨论 Emscripten 之前，我需要解释一下一个名为 LLVM 的技术以及它与 Emscripten 的关系。

首先，花点时间想想航空公司（跟着我）。航空公司希望将乘客从一个机场运送到另一个机场。但是要为每个机场到地球上的每个其他机场提供直达航班是具有挑战性的。这意味着航空公司必须提供大量的直达航班，比如从俄亥俄州的阿克伦到印度的孟买。让我们回到 20 世纪 90 年代，那是编译器世界的状态。如果你想要从 C++编译到 ARM，你需要一个能够将 C++编译到 ARM 的编译器。如果你需要从 Pascal 编译到 x86，你需要一个能够将 Pascal 编译到 x86 的编译器。这就像在任何两个城市之间只有直达航班一样：每种语言和硬件的组合都需要一个编译器。结果要么是你必须限制你为其编写编译器的语言数量，限制你可以支持的平台数量，或者更可能的是两者都有。

2003 年，伊利诺伊大学的一名学生克里斯·拉特纳想到了一个问题：“如果我们为编程语言创建一个轮毂和辐条模型会怎样？”他的想法导致了 LLVM 的诞生，LLVM 最初代表“低级虚拟机”。其理念是，不是为了任何可能的分发编译源代码，而是为了 LLVM。然后在中间语言和最终输出语言之间进行编译。理论上，这意味着如果你在下图的右侧开发了一个新的目标平台，你立即就能得到左侧所有语言：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-gm-dev-wasm/img/e5aaec1e-100f-4f61-9bb7-d072053b93dc.png)

图 1.5：LLVM 作为编程语言和硬件之间的轮毂。

要了解更多关于 LLVM 的信息，请访问 LLVM 项目主页[`llvm.org`](https://llvm.org)或阅读《LLVM Cookbook》，作者 Mayur Padney 和 Suyog Sarda，Packt Publishing：[`www.packtpub.com/application-development/llvm-cookbook`](https://www.packtpub.com/application-development/llvm-cookbook)。

# WebAssembly 文本简介

WebAssembly 二进制不是一种语言，而是类似于为 ARM 或 x86 构建的构建目标。然而，字节码的结构与其他特定硬件的构建目标不同。WebAssembly 字节码的设计者考虑了网络。目标是创建一种紧凑且可流式传输的字节码。另一个目标是用户应该能够对 WebAssembly 二进制执行“查看/源代码”以查看发生了什么。WebAssembly 文本是 WebAssembly 二进制的伴随代码，允许用户以人类可读的形式查看字节码指令，类似于汇编语言可以让您以机器可读的形式查看操作码。

对于习惯于为 ARM、x86 或 6502（如果您是老派的话）等硬件编写汇编的人来说，WebAssembly 文本可能一开始看起来很陌生。您可以使用 S 表达式编写 WebAssembly 文本，它具有括号密集的树结构。一些操作对于汇编语言来说也非常高级，例如 if/else 和 loop 操作码。如果您记得 WebAssembly 不是设计为直接在计算机硬件上运行，而是快速下载和转换为机器码，那么这就更有意义了。

处理 WebAssembly 文本时，刚开始会感到有些陌生的另一件事是缺少寄存器。WebAssembly 被设计为一种虚拟*堆栈机*，这是一种与您可能熟悉的 x86 和 ARM 等*寄存器机*不同的替代机器。堆栈机的优势在于生成的字节码比寄存器机小得多，这是选择堆栈机用于 WebAssembly 的一个很好的理由。堆栈机不是使用一系列寄存器来存储和操作数字，而是在堆栈上推送或弹出值（有时两者都有）。例如，在 WebAssembly 中调用`i32.add`会从堆栈中取出两个 32 位整数，将它们相加，然后将结果推送回堆栈。计算机硬件可以充分利用可用的寄存器来执行此操作。

# Emscripten

现在我们知道了 LLVM 是什么，我们可以讨论 Emscripten。Emscripten 最初是开发为将 LLVM IR 编译成 JavaScript，但最近已更新为将 LLVM 编译成 WebAssembly。其想法是，一旦您使 LLVM 编译器工作，您就可以获得编译为 LLVM IR 的所有语言的好处。实际上，WebAssembly 规范仍处于早期阶段，不支持诸如 GC 之类的常见语言特性。因此，目前仅支持非 GC 语言，如 C/C++和 Rust。WebAssembly 仍处于其发展的早期 MVP 阶段，但很快将添加 GC 和其他常见语言特性。发生这种情况时，应该会有大量编程语言可以编译为 WebAssembly。

Emscripten 于 2012 年发布时，旨在成为 LLVM 到 JavaScript 的编译器。2013 年，添加了对 asm.js 的支持，这是 JavaScript 语言的更快、更易优化的子集。2015 年，Emscripten 开始添加对 LLVM 到 WebAssembly 的编译支持。Emscripten 还为 C++和 JavaScript 提供了**软件开发工具包**（**SDK**），提供了比 WebAssembly MVP 本身提供的更好的 JavaScript 和 WebAssembly 交互工具。Emscripten 还集成了一个名为 Clang 的 C/C++到 LLVM 编译器，因此您可以将 C++编译成 WebAssembly。此外，Emscripten 将生成您启动项目所需的 HTML 和 JavaScript 粘合代码。

Emscripten 是一个非常动态的项目，工具链经常发生变化。要了解 Emscripten 的最新变化，请访问项目主页[`emscripten.org`](https://emscripten.org)。

# 在 Windows 上安装 Emscripten

我将保持本节简短，因为这些说明可能会发生变化。您可以在 Emscripten 网站上找到官方 Emscripten 下载和安装说明来补充这些说明：[`emscripten.org/docs/getting_started/downloads.html`](https://emscripten.org/docs/getting_started/downloads.html)。

我们需要从 GitHub 上的 emsdk 源文件下载并构建 Emscripten。首先，我们将介绍在 Windows 上的操作。

Python 2.7.12 或更高版本是必需的。如果您尚未安装高于 2.7.12 的 Python 版本，您需要从[python.org](http://python.org)获取 Windows 安装程序并首先安装：[`www.python.org/downloads/windows/`](https://www.python.org/downloads/windows/)。

如果您已安装 Python，但仍然收到 Python 未找到的错误提示，可能需要将 Python 添加到 Windows 的 PATH 变量中。有关更多信息，请参考本教程：[`www.pythoncentral.io/add-python-to-path-python-is-not-recognized-as-an-internal-or-external-command/`](https://www.pythoncentral.io/add-python-to-path-python-is-not-recognized-as-an-internal-or-external-command/)。

如果您已经安装了 Git，则克隆存储库相对简单：

1.  运行以下命令来克隆存储库：

```cpp
git clone https://github.com/emscripten-core/emsdk.git
```

1.  无论您在何处运行此命令，它都将创建一个`emsdk`目录。使用以下命令进入该目录：

```cpp
cd emsdk
```

您可能尚未安装 Git，在这种情况下，以下步骤将帮助您迅速掌握：

1.  在 Web 浏览器中转到以下 URL：[`github.com/emscripten-core/emsdk`](https://github.com/juj/emsdk)。

1.  您将在右侧看到一个绿色按钮，上面写着克隆或下载。下载 ZIP 文件：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-gm-dev-wasm/img/bb90bfed-56b4-4e14-a43d-455d5d850245.png)

1.  将下载的文件解压缩到`c:\emsdk`目录。

1.  通过在开始菜单中输入`cmd`并按*Enter*来打开 Windows 命令提示符。

1.  然后，通过输入以下内容将目录更改为`c:\emsdk\emsdk-master`目录：

```cpp
 cd \emsdk\emsdk-master
```

此时，无论您是否已安装 Git 都无关紧要。让我们继续向前：

1.  从源代码安装`emsdk`，运行以下命令：

```cpp
emsdk install latest
```

1.  然后激活最新的`emsdk`：

```cpp
emsdk activate latest
```

1.  最后，设置我们的路径和环境变量：

```cpp
emsdk_env.bat
```

这最后一步需要在您的安装目录中的每次打开新的命令行窗口时重新运行。不幸的是，它不会永久设置 Windows 环境变量。希望这在未来会有所改变。

# 在 Ubuntu 上安装 Emscripten

如果您在 Ubuntu 上安装，您应该能够使用`apt-get`软件包管理器和 git 进行完整安装。让我们继续向前：

1.  Python 是必需的，因此如果您尚未安装 Python，请务必运行以下命令：

```cpp
sudo apt-get install python
```

1.  如果您尚未安装 Git，请运行以下命令：

```cpp
sudo apt-get install git
```

1.  现在您需要克隆`emsdk`的 Git 存储库：

```cpp
git clone https://github.com/emscripten-core/emsdk.git
```

1.  更改您的目录以进入`emsdk`目录：

```cpp
cd emsdk
```

1.  从这里，您需要安装最新版本的 SDK 工具，激活它，并设置您的环境变量：

```cpp
./emsdk install latest
./emsdk activate latest
source ./emsdk_env.sh
```

1.  为了确保一切安装正确，运行以下命令：

```cpp
emcc --version
```

# 使用 Emscripten

我们通过命令行运行 Emscripten；因此，您可以使用任何文本编辑器来编写 C/C++代码。我个人偏爱 Visual Studio Code，您可以在此处下载：[`code.visualstudio.com/download`](https://code.visualstudio.com/download)。

Visual Studio Code 的一个美妙之处在于它具有内置的命令行终端，这样您就可以在不切换窗口的情况下编译代码。它还有一个出色的 C/C++扩展，您可以安装它。只需从扩展菜单中搜索 C/C++并安装 Microsoft C/C++ Intellisense 扩展。

无论您选择哪种文本编辑器或集成开发环境，您都需要一个简单的 C 代码片段来测试 emcc 编译器。

1.  创建一个新的文本文件并将其命名为`hello.c`。

1.  在`hello.c`中输入以下代码：

```cpp
#include <emscripten.h>
#include <stdlib.h>
#include <stdio.h>

int main() {
    printf("hello wasm\n");
}
```

1.  现在我可以将`hello.c`文件编译成 WebAssembly，并生成一个`hello.html`文件：

```cpp
emcc hello.c --emrun -o hello.html
```

1.  如果您想要从`emrun`运行 HTML 页面，则需要`--emrun`标志。此标志会在 C 代码中添加代码，以捕获`stdout`、`stderr`和退出，没有它`emrun`将无法工作：

```cpp
emrun --browser firefox hello.html
```

使用`--browser`标志运行`emrun`将选择您想要运行脚本的浏览器。`emrun`的行为在不同的浏览器之间似乎是不同的。Chrome 将在 C 程序退出时关闭窗口。这可能很烦人，因为我们只是想显示一个简单的打印消息。如果您有 Firefox，我建议使用`--browser`标志运行`emrun`。

我不想暗示 Chrome 不能运行 WebAssembly。当 WebAssembly 模块退出时，Chrome 的行为确实有所不同。因为我试图尽可能简化我们的 WebAssembly 模块，所以当主函数完成时，它就会退出。这就是在 Chrome 中出现问题的原因。当我们学习游戏循环时，这些问题将会消失。

要查看可用的浏览器，请运行以下命令：

```cpp
emrun --list_browsers
```

`emrun`应该在浏览器中打开一个 Emscripten 模板的 HTML 文件。

确保您的浏览器能够运行 WebAssembly。以下主要浏览器的版本应该能够运行 WebAssembly：

+   Edge 16

+   Firefox 52

+   Chrome 57

+   Safari 11

+   Opera 44

如果您熟悉设置自己的 Web 服务器，您可能希望考虑使用它而不是 emrun。在本书的前几章中使用 emrun 后，我又开始使用我的 Node.js Web 服务器。我发现随时运行基于 Node 的 Web 服务器更容易，而不是每次想要测试代码时都重新启动 emrun Web 服务器。如果您知道如何设置替代 Web 服务器（如 Node、Apache 和 IIS），您可以使用您喜欢的任何 Web 服务器。尽管 IIS 需要一些额外的配置来处理 WebAssembly MIME 类型。

# 其他安装资源

为 Emscripten 创建安装指南可能会有些问题。WebAssembly 技术经常发生变化，而 Emscripten 的安装过程在您阅读本文时可能已经不同。如果您遇到任何问题，我建议查阅 Emscripten 网站上的下载和安装说明：[`emscripten.org/docs/getting_started/downloads.html`](https://emscripten.org/docs/getting_started/downloads.html)。

您可能还想查阅 GitHub 上的 Emscripten 页面：[`github.com/emscripten-core/emsdk`](https://github.com/emscripten-core/emsdk)。

Google Groups 有一个 Emscripten 讨论论坛，如果您在安装过程中遇到问题，可以在那里提问：[`groups.google.com/forum/?nomobile=true#!forum/emscripten-discuss`](https://groups.google.com/forum/?nomobile=true#!forum/emscripten-discuss)。

您也可以在 Twitter 上联系我（`@battagline`），我会尽力帮助您：[`twitter.com/battagline`](https://twitter.com/battagline)。

# 摘要

在本章中，我们了解了 WebAssembly 是什么，以及为什么它将成为 Web 应用程序开发的未来。我们了解了为什么我们需要 WebAssembly，尽管我们已经有了像 JavaScript 这样强大的语言。我们了解了为什么 WebAssembly 比 JavaScript 快得多，以及它如何有可能增加其性能优势。我们还讨论了 WebAssembly 取代 JavaScript 成为 Web 应用程序开发的事实标准的可能性。

我们已经讨论了使用 Emscripten 和 LLVM 创建 WebAssembly 模块的实际方面。我们已经讨论了 WebAssembly 文本及其结构。我们还讨论了使用 Emscripten 编译我们的第一个 WebAssembly 模块，以及使用它创建运行该模块的 HTML 和 JavaScript 粘合代码。

在下一章中，我们将更详细地讨论如何使用 Emscripten 来创建我们的 WebAssembly 模块，以及用于驱动它的 HTML/CSS 和 JavaScript。


# 第二章：HTML5 和 WebAssembly

在本章中，我们将向您展示我们编写的用于目标 WebAssembly 的 C 代码如何与 HTML5、JavaScript 和 CSS 结合在一起，创建一个网页。我们将教您如何创建一个新的 HTML 外壳文件，供 Emscripten 在创建我们的 WebAssembly 应用程序时使用。我们将讨论`Module`对象以及 Emscripten 如何将其用作 JavaScript 和 WebAssembly 模块之间的接口。我们将向您展示如何在我们的 HTML 页面上从 JavaScript 中调用用 C 编写的 WebAssembly 函数。我们还将向您展示如何从我们的 C 代码中调用 JavaScript 函数。我们将讨论如何使用 CSS 来改善我们网页的外观。我们将向您介绍 HTML5 Canvas 元素，并展示如何可以从 JavaScript 中向画布显示图像。我们将简要讨论如何从我们的 WebAssembly 模块移动这些图像。本章将让您了解所有内容是如何协同工作的，并为我们为 WebAssembly 应用程序开发的其他功能奠定基础。

从本章开始，一直到本书的其余部分，您将需要从 GitHub 项目中获取图像和字体文件来编译示例。对于本章，您将需要从项目目录中获取`/Chapter02/spaceship.png`图像文件。请从以下网址下载项目：[`github.com/PacktPublishing/Hands-On-Game-Development-with-WebAssembly`](https://github.com/PacktPublishing/Hands-On-Game-Development-with-WebAssembly)。

我强烈建议您在阅读本章的每个部分时进行实际操作。您可以使用您喜欢的代码编辑器和命令行进行跟随。尽管我们已经提供了直接下载代码的链接，但无法强调您通过实际跟随本章建议的编辑来学到多少。您将犯错误并从中学到很多。如果您决定跟随操作，另一个建议是：除非当前部分的编辑/步骤成功，否则不要继续进行下一部分。如果需要帮助，请在 Twitter 上联系我（`@battagline`）。

在本章中，我们将涵盖以下主题：

+   Emscripten 最小外壳文件

+   创建新的 HTML 外壳和 C 文件

+   定义我们的 CSS

+   HTML5 和游戏开发

+   向 Emscripten 模板添加画布

# Emscripten 最小外壳文件

我们使用 Emscripten 创建的第一个构建使用了默认的 HTML 外壳文件。如果您有一个网站，这可能不是您希望网页看起来的方式。您可能更喜欢使用 CSS 和 HTML5 来设计您的外观和感觉，以满足您的设计或业务需求。例如，我用于我的网站的模板通常在游戏画布的左右两侧包括广告。这就是这些网站的流量变现方式。您可能选择在您的网站上方添加一个标志。还有一个文本区域，Emscripten 从`printf`或其他标准 IO 调用中记录输出。您可以选择完全删除这个`textarea`元素，或者您可以保留它，但将其隐藏，因为它对以后的调试很有用。

要基于不是默认 Emscripten 外壳的新外壳文件构建 HTML 文件，我们必须使用`--shell-file`参数，将新的 HTML 模板文件传递给它，而不是 Emscripten 的默认文件。新的`emcc`命令将如下所示：

```cpp
emcc hello.c --shell-file new_shell.html --emrun -o hello2.html
```

暂时不要执行这个命令。我们目前在项目目录中没有`new_shell.html`文件，因此在该文件存在之前运行该命令将导致错误消息。我们需要创建`new_shell.html`文件，并将其用作 HTML 外壳，而不是 Emscripten 的默认 HTML 外壳。这个外壳文件必须遵循特定的格式。为了构建它，我们必须从 Emscripten 的最小 HTML 外壳文件开始，您可以在 GitHub 上找到它：

[`github.com/emscripten-core/emscripten/blob/master/src/shell_minimal.html`](https://github.com/emscripten-core/emscripten/blob/master/src/shell_minimal.html)

我们将编写自己的 HTML 外壳，使用 `shell_minimal.html` 文件作为起点。最小外壳中的大部分内容都不是必需的，因此我们将对其进行一些重大编辑。我们将删除大部分代码以适应我们的目的。当您在文本编辑器中打开 `shell_minimal.html` 时，您会看到它以标准的 HTML 头部和 `style` 标签开头：

```cpp
<style>
 .emscripten { padding-right: 0; margin-left: auto; margin-right: auto;    
               display: block; }
 textarea.emscripten { font-family: monospace; width: 80%; }
 div.emscripten { text-align: center; }
 div.emscripten_border { border: 1px solid black; }
 /* the canvas *must not* have any border or padding, or mouse coords 
    will be wrong */
 canvas.emscripten { border: 0px none; background-color: black; }
 .spinner {
            height: 50px;
            width: 50px;
            margin: 0px auto;
            -webkit-animation: rotation .8s linear infinite;
            -moz-animation: rotation .8s linear infinite;
            -o-animation: rotation .8s linear infinite;
            animation: rotation 0.8s linear infinite;
            border-left: 10px solid rgb(0,150,240);
            border-right: 10px solid rgb(0,150,240);
            border-bottom: 10px solid rgb(0,150,240);
            border-top: 10px solid rgb(100,0,200);
            border-radius: 100%;
            background-color: rgb(200,100,250);
          }
 @-webkit-keyframes rotation {
         from {-webkit-transform: rotate(0deg);}
         to {-webkit-transform: rotate(360deg);}
  }
 @-moz-keyframes rotation {
         from {-moz-transform: rotate(0deg);}
         to {-moz-transform: rotate(360deg);}
 }
 @-o-keyframes rotation {
         from {-o-transform: rotate(0deg);}
         to {-o-transform: rotate(360deg);}
 }
 @keyframes rotation {
         from {transform: rotate(0deg);}
         to {transform: rotate(360deg);}
 }
 </style>
```

这段代码是基于撰写时可用的 `shell_minimal.html` 版本。不预期对此文件进行任何更改。然而，WebAssembly 发展迅速。不幸的是，我们无法完全肯定在您阅读此文时，该文件是否会保持不变。如前所述，如果遇到问题，请随时在 Twitter 上联系我（`@battagline`）。

我们删除此样式标签，以便您可以按自己的喜好设置代码样式。如果您喜欢他们的旋转加载图像并希望保留它，这是必需的，但最好将所有这些都删除，并用链接标签从外部加载 CSS 文件替换它，如下所示：

```cpp
<link href="shell.css" rel="stylesheet" type="text/css">
```

向下滚动一点，您会看到它们使用的加载指示器。我们最终将用我们自己的加载指示器替换它，但现在我们正在本地测试所有这些，我们的文件都很小，所以我们也会删除这些代码：

```cpp
<figure style="overflow:visible;" id="spinner">
    <div class="spinner"></div>
    <center style="margin-top:0.5em"><strong>emscripten</strong></center>
</figure>
<div class="emscripten" id="status">Downloading...</div>
    <div class="emscripten">
        <progress value="0" max="100" id="progress" hidden=1></progress>
    </div>
```

之后是一个 HTML5 `canvas` 元素和与之相关的一些其他标签。我们最终需要重新添加一个 `canvas` 元素，但现在我们不会使用 `canvas`，因此代码的这部分也是不必要的：

```cpp
<div class="emscripten">
    <input type="checkbox" id="resize">Resize canvas
    <input type="checkbox" id="pointerLock" checked>Lock/hide mouse 
     pointer&nbsp;&nbsp;&nbsp;
    <input type="button" value="Fullscreen" onclick=
    "Module.requestFullscreen(document.getElementById
    ('pointerLock').checked,
            document.getElementById('resize').checked)">
 </div>
```

在 `canvas` 之后，有一个 `textarea` 元素。这也是不必要的，但最好将其用作从我的 C 代码执行的任何 `printf` 命令的打印位置。外壳用两个 `<hr/>` 标签将其包围，用于格式化，因此我们也可以删除这些标签：

```cpp
 <hr/>
 <textarea class="emscripten" id="output" rows="8"></textarea>
 <hr/>
```

接下来是我们的 JavaScript。它以三个变量开头，这些变量代表我们之前删除的 HTML 元素，因此我们也需要删除所有这些 JavaScript 变量：

```cpp
var statusElement = document.getElementById('status');
var progressElement = document.getElementById('progress');
var spinnerElement = document.getElementById('spinner');
```

JavaScript 中的 `Module` 对象是 Emscripten 生成的 JavaScript *粘合* 代码用来与我们的 WebAssembly 模块交互的接口。这是 shell HTML 文件中最重要的部分，了解它正在做什么是至关重要的。`Module` 对象以两个数组 `preRun` 和 `postRun` 开始。这些是在模块加载之前和之后运行的函数数组，分别。

```cpp
var Module = {
 preRun: [],
 postRun: [],
```

出于演示目的，我们可以像这样向这些数组添加函数：

```cpp
preRun: [function() {console.log("pre run 1")},
            function() {console.log("pre run 2")}],
postRun: [function() {console.log("post run 1")},
            function() {console.log("post run 2")}],
```

这将从我们在 Chapter1 中创建的 hello WASM 应用程序产生以下输出，*WebAssembly 和 Emscripten 简介*：

```cpp
pre run 2
pre run 1
status: Running...
Hello wasm
post run 2
post run 1
```

请注意，`preRun` 和 `postRun` 函数按照它们在数组中的顺序相反的顺序运行。我们可以使用 `postRun` 数组来调用一个函数，该函数将初始化我们的 WebAssembly 封装器，但是，出于演示目的，我们将在我们的 C `main()` 函数中调用 JavaScript 函数。

`Module` 对象内的下两个函数是 `print` 和 `printErr` 函数。`print` 函数用于将 `printf` 调用的输出打印到控制台和我们命名为 `output` 的 `textarea` 中。您可以将此 `output` 更改为打印到任何 HTML 标记，但是，如果您的输出是原始 HTML，则必须运行几个已注释掉的文本替换调用。`print` 函数如下所示：

```cpp
print: (function() {
    var element = document.getElementById('output');
    if (element) element.value = ''; // clear browser cache
    return function(text) {
        if (arguments.length > 1) text = 
        Array.prototype.slice.call(arguments).join(' ');
        // These replacements are necessary if you render to raw HTML
        //text = text.replace(/&/g, "&amp;");
        //text = text.replace(/</g, "&lt;");
        //text = text.replace(/>/g, "&gt;");
        //text = text.replace('\n', '<br>', 'g');
        console.log(text);
        if (element) {
            element.value += text + "\n";
            element.scrollTop = element.scrollHeight; // focus on 
            bottom
        }
    };
})(),
```

`printErr` 函数在粘合代码中运行，当我们的 WebAssembly 模块或粘合代码本身发生错误或警告时。`printErr` 的输出只在控制台中，尽管原则上，如果你想添加代码来写入 HTML 元素，你也可以这样做。这是 `printErr` 代码：

```cpp
printErr: function(text) {
     if (arguments.length > 1) text = 
     Array.prototype.slice.call(arguments).join(' ');
     if (0) { // XXX disabled for safety typeof dump == 'function') {
       dump(text + '\n'); // fast, straight to the real console
     } else {
         console.error(text);
     }
 },
```

在`print`函数之后，还有一个`canvas`函数。此函数设置为警告用户丢失了 WebGL 上下文。目前我们不需要该代码，因为我们已经删除了 HTML Canvas。当我们重新添加`canvas`元素时，我们将需要恢复此函数。更新它以处理丢失上下文事件，而不仅仅是警告用户也是有意义的。

```cpp
canvas: (function() {
     var canvas = document.getElementById('canvas');
     // As a default initial behavior, pop up an alert when webgl 
        context is lost. To make your
     // application robust, you may want to override this behavior 
        before shipping!
     // See http://www.khronos.org/registry/webgl/specs/latest/1.0/#5.15.2
     canvas.addEventListener("webglcontextlost", function(e) { 
        alert('WebGL context lost. You will need to reload the page.'); 
        e.preventDefault(); }, false);
     return canvas;
 })(),
```

在您的网页可能丢失其 WebGL 上下文的几种不同情况下。上下文是您进入 GPU 的门户，您的应用程序对 GPU 的访问由浏览器和操作系统共同管理。让我们来到*隐喻之地*，在那里我们想象 GPU 是一辆公共汽车，Web 浏览器是公共汽车司机，使用其上下文的应用程序是一群吵闹的中学生。如果公共汽车司机（浏览器）觉得孩子们（应用程序）太吵闹，他可以停下公共汽车（GPU），让所有孩子下车（使应用程序失去上下文），然后让他们一个接一个地上车，如果他们答应表现好的话。

之后，最小外壳文件中有一些代码用于跟踪模块的状态和依赖关系。在这段代码中，我们可以删除对`spinnerElement`、`progressElement`和`statusElement`的引用。稍后，如果我们选择，可以用元素替换这些内容，以跟踪加载模块的状态，但目前不需要。以下是最小外壳中的状态和运行依赖监控代码：

```cpp
setStatus: function(text) {
    if (!Module.setStatus.last) Module.setStatus.last = { time: 
        Date.now(), text: '' };
    if (text === Module.setStatus.last.text) return;
    var m = text.match(/([^(]+)\((\d+(\.\d+)?)\/(\d+)\)/);
    var now = Date.now();

    // if this is a progress update, skip it if too soon
    if (m && now - Module.setStatus.last.time < 30) return; 
    Module.setStatus.last.time = now;
    Module.setStatus.last.text = text;
    if (m) {
        text = m[1];
    }
    console.log("status: " + text);
},
totalDependencies: 0,
monitorRunDependencies: function(left) {
  this.totalDependencies = Math.max(this.totalDependencies, left);
    Module.setStatus(left ? 'Preparing... (' + (this.totalDependencies-
                     left) + '/' + this.totalDependencies + ')' : 'All 
                     downloads complete.');
}
};
 Module.setStatus('Downloading...');
```

JavaScript 代码的最后一部分在最小外壳文件中确定了在浏览器错误发生时 JavaScript 将会做什么：

```cpp
window.onerror = function() {
    Module.setStatus('Exception thrown, see JavaScript console');
    Module.setStatus = function(text) {
        if (text) Module.printErr('[post-exception status] ' + text);
    };
```

在我们的 JavaScript 之后，还有一行非常重要的代码：

```cpp
{{{ SCRIPT }}}
```

此标记告诉 Emscripten 将 JavaScript 粘合代码的链接放在这里。以下是编译到最终 HTML 文件中的示例：

```cpp
<script async type="text/javascript" src="img/shell-min.js"></script>
```

`shell-min.js`是由 Emscripten 构建的 JavaScript 粘合代码。在下一节中，我们将学习如何创建自己的 HTML 外壳文件。

# 创建新的 HTML 外壳和 C 文件

在这一部分中，我们将创建一个新的`shell.c`文件，其中公开了从 JavaScript 调用的几个函数。我们还将使用`EM_ASM`调用`InitWrappers`函数，该函数将在我们即将创建的新 HTML 外壳文件中定义。此函数将在 JavaScript 中创建包装器，可以调用 WebAssembly 模块中定义的函数。在创建新的 HTML 外壳文件之前，我们需要创建将由 HTML 外壳内的 JavaScript 包装器调用的 C 代码：

1.  按照以下方式创建新的`shell.c`文件：

```cpp
#include <emscripten.h>
#include <stdlib.h>
#include <stdio.h>

int main() {
    printf("Hello World\n");
    EM_ASM( InitWrappers() );
    printf("Initialization Complete\n");
}

void test() {
    printf("button test\n");
}

void int_test( int num ) {
    printf("int test=%d\n", num);
}

void float_test( float num ) {
    printf("float test=%f\n", num);
}

void string_test( char* str ) {
    printf("string test=%s\n", str);
}
```

当 WebAssembly 模块加载时，`main`函数将运行。此时，`Module`对象可以使用`cwrap`创建该函数的 JavaScript 版本，我们可以将其绑定到 HTML 元素的`onclick`事件上。在`main`函数内部，`EM_ASM( InitWrappers() );`代码调用了在 HTML 外壳文件中的 JavaScript 中定义的`InitWrappers()`函数。DOM 使用事件来调用接下来的四个函数。

我们初始化包装器的另一种方式是从`Module`对象的`postRun: []`数组中调用`InitWrappers()`函数。

我们将在 DOM 中将对`test()`函数的调用与按钮点击绑定。`int_test`函数将作为一个值从 DOM 中的输入字段传递，并通过使用`printf`语句将一个消息打印到控制台和`textarea`元素中，其中包括该整数。`float_test`函数将作为一个浮点数传递一个数字，并打印到控制台和`textarea`元素中。`string_test`函数将打印从 JavaScript 传入的字符串。

现在，我们将在 HTML 外壳文件中添加以下代码，并将其命名为`new_shell.html`。该代码基于 Emscripten 团队创建的*Emscripten 最小外壳文件*，并在前一节中进行了解释。我们将整个 HTML 页面分为四个部分呈现。

首先是 HTML 文件的开头和`head`元素：

```cpp
<!doctype html>
<html lang="en-us">
<head>
    <meta charset="utf-8">
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
    <title>New Emscripten Shell</title>
    <link href="shell.css" rel="stylesheet" type="text/css">
</head>
```

接下来是`body`标签的开始。在此之后，我们有几个 HTML `input`元素以及`textarea`元素：

```cpp
<body>
    <div class="input_box">&nbsp;</div>
    <div class="input_box">
        <button id="click_me" class="em_button">Click Me!</button>
    </div>
    <div class="input_box">
        <input type="number" id="int_num" max="9999" min="0" step="1" 
         value="1" class="em_input">
        <button id="int_button" class="em_button">Int Click!</button>
    </div>
    <div class="input_box">
        <input type="number" id="float_num" max="99" min="0" 
          step="0.01" value="0.0" class="em_input">
        <button id="float_button" class="em_button">Float Click!</button>
    </div>
    <div class="input_box">&nbsp;</div>
    <textarea class="em_textarea" id="output" rows="8"></textarea>
    <div id="string_box">
        <button id="string_button" class="em_button">String Click!</button>
        <input id="string_input">
    </div>
```

在我们的 HTML 之后，我们有`script`标签的开始，以及我们添加到默认 shell 文件中的一些 JavaScript 代码：

```cpp

 <script type='text/javascript'>
    function InitWrappers() {
        var test = Module.cwrap('test', 'undefined');
        var int_test = Module.cwrap('int_test', 'undefined', ['int']);
        var float_test = Module.cwrap('float_test', 'undefined', 
                                       ['float']);
        var string_test = Module.cwrap('string_test', 'undefined', 
                                       ['string']);
        document.getElementById("int_button").onclick = function() {

        if( int_test != null ) {
            int_test(document.getElementById('int_num').value);
        }
    }

    document.getElementById("string_button").onclick = function() {
        if( string_test != null ) {
            string_test(document.getElementById('string_input').value);
        }
    }

    document.getElementById("float_button").onclick = function() {
        if( float_test != null ) {
            float_test(document.getElementById('float_num').value);
        }
    }

    document.getElementById("click_me").onclick = function() {
        if( test != null ) {
            test();
        }
    }
 }

function runbefore() {
    console.log("before module load");
}

function runafter() {
    console.log("after module load");
}
```

接下来是我们从默认 shell 文件中引入的`Module`对象。在`Module`对象之后，我们有`script`标签的结束，`{{{ SCRIPT }}}`标签，在编译时由 Emscripten 替换，以及我们文件中的结束标签：

```cpp
var Module = {
    preRun: [runbefore],
    postRun: [runafter],
    print: (function() {
        var element = document.getElementById('output');
        if (element) element.value = ''; // clear browser cache
            return function(text) {
                if (arguments.length > 1) text = 
                   Array.prototype.slice.call(arguments).join(' ');
                /*
                // The printf statement in C is currently writing to a 
                   textarea. If we want to write
                // to an HTML tag, we would need to run these lines of 
                   codes to make our text HTML safe
                text = text.replace(/&/g, "&amp;");
                text = text.replace(/</g, "&lt;");
                text = text.replace(/>/g, "&gt;");
                text = text.replace('\n', '<br>', 'g');
                */
                console.log(text);
                if (element) {
                    element.value += text + "\n";
                    element.scrollTop = element.scrollHeight; 
                     // focus on bottom
                } 
            };
        })(),
        printErr: function(text) {
            if (arguments.length > 1) text = 
                Array.prototype.slice.call(arguments).join(' ');
            if (0) { // XXX disabled for safety typeof dump == 
                       'function') {
                dump(text + '\n'); // fast, straight to the real                     console
            } else {
                console.error(text);
            }
        },
        setStatus: function(text) {
            if (!Module.setStatus.last) Module.setStatus.last = { time: 
                Date.now(), text: '' };
            if (text === Module.setStatus.last.text) return;
            var m = text.match(/([^(]+)\((\d+(\.\d+)?)\/(\d+)\)/);
            var now = Date.now();

            // if this is a progress update, skip it if too soon
            if (m && now - Module.setStatus.last.time < 30) return;
            Module.setStatus.last.time = now;
            Module.setStatus.last.text = text;

            if (m) {
                text = m[1];
            }
            console.log("status: " + text);
        },
        totalDependencies: 0,
        monitorRunDependencies: function(left) {
            this.totalDependencies = Math.max(this.totalDependencies,                                               
                                              left);
            Module.setStatus(left ? 'Preparing... (' + 
            (this.totalDependencies-left) + '/' +             
            this.totalDependencies + ')' : 'All downloads complete.');
        }
    };
    Module.setStatus('Downloading...');
    window.onerror = function() {
    Module.setStatus('Exception thrown, see JavaScript console');
    Module.setStatus = function(text) {
        if (text) Module.printErr('[post-exception status] ' + text);
    };
};
</script>
{{{ SCRIPT }}}
</body>
</html>
```

这前面的四个部分组成了一个名为`new_shell.html`的单个 shell 文件。您可以通过将最后四个部分输入到一个名为`new_shell.html`的文件中来创建此代码，或者您可以从我们的 GitHub 页面下载该文件[`github.com/PacktPublishing/Hands-On-Game-Development-with-WebAssembly/blob/master/Chapter02/new_shell.html`](https://github.com/PacktPublishing/Hands-On-Game-Development-with-WebAssembly/blob/master/Chapter02/new_shell.html)。

现在我们已经大块地看完了整个`new_shell.html`文件，我们可以花一点时间来分解其中的重要部分，并以更细粒度的方式进行讨论。您会注意到我们删除了所有的 CSS 样式代码，并创建了一个新的`shell.css`文件，并在其中包含了以下行：

```cpp
<link href="shell.css" rel="stylesheet" type="text/css">
```

接下来，我们重新设计了这个文件中的 HTML 代码，以创建与 WebAssembly 模块交互的元素。首先，我们将添加一个按钮，该按钮将调用 WebAssembly 模块内的`test()`函数：

```cpp
<div class="input_box">
    <button id="click_me" class="em_button">Click Me!</button>
</div>
```

我们将在我们创建的`shell.css`文件中对按钮及其包含的`div`元素进行样式设置。我们需要定义将在稍后编写的 JavaScript 代码中由此`button`元素的`onclick`事件调用的函数。我们将在 HTML 中定义的两个输入/按钮对中做类似的事情，如下面的代码块所示：

```cpp
<div class="input_box">
    <input type="number" id="int_num" max="9999" min="0" step="1" 
     value="1" class="em_input">
    <button id="int_button" class="em_button">Int Click!</button>
</div>
<div class="input_box">
    <input type="number" id="float_num" max="99" min="0" step="0.01" 
     value="0.0" class="em_input">
    <button id="float_button" class="em_button">Float Click!</button>
</div>
```

就像我们对第一个`button`元素所做的那样，我们将把接下来的两个按钮与将调用 WebAssembly 模块的函数联系起来。这些函数调用还将把`input`元素中定义的值传递到 WebAssembly 函数中。我们将`textarea`元素留作 WebAssembly 模块内的`printf`调用的输出。我们在 CSS 文件中对其进行了不同的样式设置，但我们将保持功能不变：

```cpp
<textarea class="em_textarea" id="output" rows="8"></textarea>
<div id="string_box">
    <button id="string_button" class="em_button">String Click!</button>
    <input id="string_input">
</div>
```

在`textarea`元素下面，我们添加了另一个`button`和一个`string` `input`元素。这个按钮将调用 WebAssembly 模块内的`string_test`函数，并将`string_input`元素中的值作为 C `char*`参数传递给它。

既然我们已经在 HTML 中定义了所有需要的元素，我们将逐步添加一些 JavaScript 代码，以将 JavaScript 和 WebAssembly 模块联系在一起。我们需要做的第一件事是定义`InitWrappers`函数。`InitWrappers`将从 C 代码的`main`函数内部调用：

```cpp
function InitWrappers() {
    var test = Module.cwrap('test', 'undefined');
    var int_test = Module.cwrap('int_test', 'undefined', ['int']);
    var float_test = Module.cwrap('float_test', 'undefined', 
                                   ['float']);
    var string_test = Module.cwrap('string_test', 'undefined',
                                     ['string']);
    document.getElementById("int_button").onclick = function() {
        if( int_test != null ) {
            int_test(document.getElementById('int_num').value);
        }
    }

    document.getElementById("string_button").onclick = function() {
        if( string_test != null ) {
            string_test(document.getElementById('string_input').value);
        }
    }

    document.getElementById("float_button").onclick = function() {
        if( float_test != null ) {
            float_test(document.getElementById('float_num').value);
        }
    }

    document.getElementById("click_me").onclick = function() {
        if( test != null ) {
            test();
        }
    }
}
```

此函数使用`Module.cwrap`来创建围绕 WebAssembly 模块内导出函数的 JavaScript 函数包装器。我们传递给`cwrap`的第一个参数是我们要包装的 C 函数的名称。所有这些 JavaScript 函数都将返回`undefined`。JavaScript 没有像 C 那样的`void`类型，因此当我们在 JavaScript 中声明`return`类型时，我们需要使用`undefined`类型。如果函数要返回`int`或`float`，我们需要在这里放置`'number'`值。传递给`cwrap`的最后一个参数是一个字符串数组，表示传递给 WebAssembly 模块的参数的 C 类型。

在我们定义了函数的 JavaScript 包装器之后，我们需要从按钮中调用它们。其中一个调用是对 WebAssembly 的`int_test`函数。以下是我们为`int_button`设置`onclick`事件的方式：

```cpp
document.getElementById("int_button").onclick = function() {
    if( int_test != null ) {
        int_test(document.getElementById('int_num').value);
    }
}
```

我们要做的第一件事是检查`int_test`是否已定义。如果是这样，我们调用我们之前解释的`int_test`包装器，将`int_num`输入的值传递给它。然后我们对所有其他按钮做类似的事情。

接下来我们要做的是创建一个`runbefore`和`runafter`函数，将它们放在`Module`对象的`preRun`和`postRun`数组中：

```cpp
function runbefore() {
    console.log("before module load");
}
function runafter() {
    console.log("after module load");
}
var Module = {
    preRun: [runbefore],
    postRun: [runafter],
```

这将导致在模块加载之前在控制台上打印“before module load”，并且在模块加载后打印“after module load”。这些函数不是必需的；它们旨在展示您如何在加载 WebAssembly 模块之前和之后运行代码。如果您不想从 WebAssembly 模块的`main`函数中调用`InitWrappers`函数，您可以将该函数放在`postRun`数组中。

JavaScript 代码的其余部分与 Emscripten 创建的`shell_minimal.html`文件中的内容类似。我们已删除了对于本演示多余的代码，例如与 HTML5`canvas`相关的代码，以及与`spinnerElement`、`progressElement`和`statusElement`相关的代码。这并不是说在 JavaScript 中留下这些代码有什么问题，但对于我们的演示来说并不是真正必要的，因此我们已将其删除以减少所需的最小代码。

# 定义 CSS

现在我们有了一些基本的 HTML，我们需要创建一个新的`shell.css`文件。没有任何 CSS 样式，我们的页面看起来非常糟糕。

没有样式的页面将类似于以下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-gm-dev-wasm/img/f8b0d833-eab2-4125-9705-d44e21ddf664.png)

图 2.1：没有 CSS 样式的 Hello WebAssembly 应用程序

幸运的是，一点点 CSS 可以让我们的网页看起来很不错。以下是我们正在创建的新`shell.css`文件的样子：

```cpp
body {
    margin-top: 20px;
}

.input_box {
    width: 20%;
    display: inline-block;
}
.em_button {
    width: 45%;
    height: 40px;
    background-color: orangered;
    color: white;
    border: 2px solid white;
    font-size: 20px;
    border-radius: 8px;
    transition-duration: 0.5s;
}

.em_button:hover {
    background-color: orange;
    color: white;
    border: 2px solid white;
}

.em_input {
    width: 45%;
    height: 20px;
    font-size: 20px;
    background-color: darkslategray;
    color: white;
    padding: 6px;
}

#output {
    background-color: darkslategray;
    color: white;
    font-size: 16px;
    padding: 10px;
    padding-right: 0;
    margin-left: auto;
    margin-right: auto;
    display: block;
    width: 60%;
}

#string_box {
    padding-top: 10px;
    margin-left: auto;
    margin-right: auto;
    display: block;
    width: 60%;
}

#string_input {
    font-size: 20px;
    background-color: darkslategray;
    color: white;
    padding: 6px;
    margin-left: 5px;
    width: 45%;
    float: right;
}
```

让我快速浏览一下我们需要做的样式化页面的步骤。这本书不是一本关于 CSS 的书，但简要地介绍一下这个主题也无妨。

1.  我们要做的第一件事是在页面主体上放置 20 像素的小边距，以在浏览器工具栏和页面内容之间留出一点空间：

```cpp
body {
    margin-top: 20px;
}
```

1.  我们已创建了五个输入框，每个输入框占浏览器宽度的`20%`。左右两侧的框中都没有内容，因此内容占据了浏览器宽度的 60%。它们以内联块的形式显示，这样它们就可以在屏幕上水平排列。以下是使其发生的 CSS：

```cpp
.input_box {
    width: 20%;
    display: inline-block;
}
```

1.  然后我们有一些类来使用名为`em_button`的类来样式化我们的按钮：

```cpp
.em_button {
    width: 45%;
    height: 40px;
    background-color: orangered;
    color: white;
    border: 0px;
    font-size: 20px;
    border-radius: 8px;
    transition-duration: 0.2s;
}

.em_button:hover {
    background-color: orange;
}
```

我们已将按钮宽度设置为占包含元素的`45%`。我们将按钮高度设置为 40 像素。我们已将按钮的颜色设置为`orangered`，文本颜色设置为`白色`。我们通过将边框宽度设置为 0 像素来移除边框。我们已将字体大小设置为 20 像素，并给它设置了 8 像素的边框半径，这样按钮就呈现出圆角外观。最后一行设置了用户悬停在按钮上时过渡到新颜色所需的时间。

在定义`em_button`类之后，我们定义了`em_button:hover`类，当用户悬停在按钮上时，它会改变按钮的颜色。

某些版本的 Safari 需要在`em_button`类定义内部包含一行`-webkit-transition-duration: 0.2s;`，才能实现悬停状态的过渡。没有这一行，在某些版本的 Safari 中，按钮会立即从`orangered`变为`orange`，而不是在 200 毫秒内过渡。

我们定义的下一个类是用于`input`元素的：

```cpp
.em_input {
    width: 45%;
    height: 20px;
    font-size: 20px;
    background-color: darkslategray;
    color: white;
    padding: 6px;
}
```

我们在开头设置了它的`高度`、`宽度`和`字体大小`。我们将背景颜色设置为`darkslategray`，文本为`白色`。我们添加了`6`像素的填充，以便在`input`元素的字体和边缘之间有一小段空间。

在 CSS 元素名称前面的`#`样式化 ID 而不是类。ID 定义了特定的元素，而类（在 CSS 中以`.`开头）可以分配给 HTML 中的多个元素。CSS 的下一部分样式化了具有 ID 输出的`textarea`：

```cpp
#output {
    background-color: darkslategray;
    color: white;
    font-size: 16px;
    padding: 10px;
    margin-left: auto;
    margin-right: auto;
    display: block;
    width: 60%;
}
```

前两行设置了背景和文本颜色。我们将字体大小设置为`16`像素，并添加了`10`像素的填充。接下来的两行使用左右边距将`textarea`居中：

```cpp
margin-left: auto;
margin-right: auto;
```

设置`display: block;`将此元素放在一行上。将宽度设置为`60%`使元素占据包含元素的`60%`，在这种情况下是浏览器的`body`标记。

最后，我们对`string_box`和`string_input`元素进行了样式设置：

```cpp
#string_box {
    padding-top: 10px;
    margin-left: auto;
    margin-right: auto;
    display: block;
    width: 60%;
}

#string_input {
    font-size: 20px;
    background-color: darkslategray;
    color: white;
    padding: 6px;
    margin-left: 5px;
    width: 45%;
    float: right;
}
```

`string_box`是包含字符串按钮和字符串输入元素的框。我们在框的顶部填充了一些空间，以在其上方的`textarea`和`string_box`之间添加一些空间。`margin-left: auto`和`margin-right: auto`将框居中。然后，我们使用`display:block`和`width: 60%`使其占据浏览器的`60%`。

对于`string_input`元素，我们设置了字体大小和颜色，并在其周围填充了 6 像素。我们设置了左边距为 5 像素，以在元素和其按钮之间留出一些空间。我们将其设置为占包含元素宽度的`45%`，而`float: right`样式将元素推到包含元素的右侧。

要构建我们的应用程序，我们需要运行`emcc`：

```cpp
 emcc shell.c -o shell-test.html --shell-file new_shell.html -s NO_EXIT_RUNTIME=1 -s EXPORTED_FUNCTIONS="['_test', '_string_test', '_int_test', '_float_test', '_main']" -s EXTRA_EXPORTED_RUNTIME_METHODS="['cwrap', 'ccall']"
```

`EXPORTED_FUNCTIONS`用于定义从 JavaScript 调用的所有函数。它们在前面加上`_`字符。`EXTRA_EXPORTED_RUNTIME_METHODS`用于使`cwrap`和`ccall`方法在我们的 shell 文件内部的 JavaScript 中可用。我们目前没有使用`ccall`，这是`cwrap`的替代方法，我们将来可能选择使用它。

重要的是要记住，您必须使用 Web 服务器或`emrun`来运行 WebAssembly 应用程序。如果您想使用`emrun`运行 WebAssembly 应用程序，您必须使用`--emrun`标志进行编译。Web 浏览器需要 Web 服务器来流式传输 WebAssembly 模块。如果您尝试直接从硬盘驱动器在浏览器中打开使用 WebAssembly 的 HTML 页面，那么 WebAssembly 模块将无法加载。

现在我们已经添加了一些 CSS 样式，我们的应用程序看起来好多了：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-gm-dev-wasm/img/e8381064-6edf-40d8-8e9d-2f1e4f4b678c.png)

图 2.2：带有 CSS 样式的 Hello WebAssembly 应用程序

在下一节中，我们将讨论 HTML5 网络游戏开发。

# HTML5 和游戏开发

大多数 HTML 渲染是通过 HTML **文档对象模型**（**DOM**）完成的。DOM 是一种称为*保留模式*的图形库。保留模式图形保留了一个称为**场景图**的树。这个场景图跟踪我们模型中的所有图形元素以及如何渲染它们。保留模式图形的好处是它们对开发人员来说很容易管理。图形库完成了所有繁重的工作，并为我们跟踪了对象以及它们的渲染位置。缺点是保留模式系统占用了更多的内存，并且为开发人员提供了更少的控制权。当我们编写 HTML5 游戏时，我们可以使用`<IMG>` HTML 元素在 DOM 中渲染图像，并使用 JavaScript 或 CSS 动画移动这些元素，直接在 DOM 中操作这些图像的位置。

然而，在大多数情况下，这会使游戏变得非常缓慢。每次我们在 DOM 中移动一个对象时，都会强制浏览器重新计算 DOM 中所有其他对象的位置。因此，通常情况下，通过在 DOM 中操作对象来制作网络游戏通常是行不通的。

# 即时模式与保留模式

即时模式经常被认为是保留模式的相反，但实际上，当我们为即时模式系统编写代码时，我们可能会在保留模式库的 API 之上构建一些功能。 即时模式迫使开发人员完成保留模式库所做的所有或大部分繁重工作。 我们作为开发人员被迫管理我们的场景图，并了解我们需要渲染的图形对象以及这些对象必须何时以何种方式渲染。 简而言之，这是更多的工作，但如果做得好，游戏将比使用 DOM 渲染更快地渲染。

你可能会问自己：*我该如何使用这个 Immediate Mode*？进入 HTML5 画布！ 2004 年，苹果公司开发了画布元素作为苹果专有浏览器技术的即时模式显示标签。 画布将我们网页的一部分分隔出来，允许我们使用即时模式渲染到该区域。 这将使我们能够在不需要浏览器重新计算 DOM 中所有元素的位置的情况下，渲染到 DOM 的一部分（画布）。 这允许浏览器进一步优化画布的渲染，使用计算机的**图形处理单元**（**GPU**）。

# 向 Emscripten 模板添加画布

在本章的较早部分，我们讨论了从 shell 模板调用 Emscripten WebAssembly 应用程序。 现在您知道如何使 JavaScript 和 WebAssembly 之间的交互工作，我们可以将`canvas`元素添加回模板，并开始使用 WebAssembly 模块操纵该`canvas`。 我们将创建一个新的`.c`文件，该文件将调用一个 JavaScript 函数，传递一个`x`和`y`坐标。 JavaScript 函数将操纵太空船图像，将其移动到`canvas`周围。 我们还将创建一个名为`canvas_shell.html`的全新 shell 文件。

与我们为之前版本的 shell 所做的一样，我们将首先将此文件分成四个部分，以便从高层次讨论它。 然后我们将逐一讨论该文件的基本部分。

1.  HTML 文件的开头以开头的`HTML`标签和`head`元素开始：

```cpp
<!doctype html>
<html lang="en-us">
<head>
    <meta charset="utf-8">
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
    <title>Canvas Shell</title>
    <link href="canvas.css" rel="stylesheet" type="text/css">
</head>
```

1.  在那之后，我们有了开头的`body`标签，并且删除了在此文件的早期版本中存在的许多 HTML 元素：

```cpp
<body>
    <canvas id="canvas" width="800" height="600" oncontextmenu="event.preventDefault()"></canvas>
    <textarea class="em_textarea" id="output" rows="8"></textarea>
    <img src="img/spaceship.png" id="spaceship">
```

1.  接下来是开头的`script`标签，一些全局 JavaScript 变量和一些我们添加的新函数：

```cpp
    <script type='text/javascript'>
        var img = null;
        var canvas = null;
        var ctx = null;
        function ShipPosition( ship_x, ship_y ) {
            if( img == null ) {
                return;
            }
            ctx.fillStyle = "black";
            ctx.fillRect(0, 0, 800, 600);
            ctx.save();
            ctx.translate(ship_x, ship_y);
            ctx.drawImage(img, 0, 0, img.width, img.height);
            ctx.restore();
        }
        function ModuleLoaded() {
            img = document.getElementById('spaceship');
            canvas = document.getElementById('canvas');
            ctx = canvas.getContext("2d");
        }
```

1.  在新的 JavaScript 函数之后，我们有`Module`对象的新定义：

```cpp
        var Module = {
            preRun: [],
            postRun: [ModuleLoaded],
            print: (function() {
                var element = document.getElementById('output');
                if (element) element.value = ''; // clear browser cache
                return function(text) {
                    if (arguments.length > 1) text = 
                    Array.prototype.slice.call(arguments).join(' ');
                        // uncomment block below if you want to write 
                           to an html element
                        /*
                        text = text.replace(/&/g, "&amp;");
                        text = text.replace(/</g, "&lt;");
                        text = text.replace(/>/g, "&gt;");
                        text = text.replace('\n', '<br>', 'g');
                        */
                        console.log(text);
                        if (element) {
                            element.value += text + "\n";
                            element.scrollTop = element.scrollHeight; 
      // focus on bottom
                        }
                    };
                })(),
                printErr: function(text) {
                    if (arguments.length > 1) text = 
                       Array.prototype.slice.call(arguments).join(' ');
                    console.error(text);
                },
                canvas: (function() {
                    var canvas = document.getElementById('canvas');
                    canvas.addEventListener("webglcontextlost", 
                    function(e) { 
                        alert('WebGL context lost. You will need to 
                                reload the page.');
                        e.preventDefault(); }, 
                        false);
                    return canvas;
                })(),
                setStatus: function(text) {
                    if (!Module.setStatus.last) Module.setStatus.last = 
                    { time: Date.now(), text: '' };
                    if (text === Module.setStatus.last.text) return;
                    var m = text.match(/([^(]+)\((\d+
                    (\.\d+)?)\/(\d+)\)/);
                    var now = Date.now();

                    // if this is a progress update, skip it if too        
                       soon
                    if (m && now - Module.setStatus.last.time < 30) 
            return; 
                    Module.setStatus.last.time = now;
                    Module.setStatus.last.text = text;
                    if (m) {
                        text = m[1];
                    }
                    console.log("status: " + text);
                },
                totalDependencies: 0,
                monitorRunDependencies: function(left) {
                    this.totalDependencies = 
                    Math.max(this.totalDependencies, left);
                    Module.setStatus(left ? 'Preparing... (' + 
                    (this.totalDependencies-left) + 
                        '/' + this.totalDependencies + ')' : 'All 
                        downloads complete.');
                }
            };
            Module.setStatus('Downloading...');
            window.onerror = function() {
                Module.setStatus('Exception thrown, see JavaScript 
                                    console');
                Module.setStatus = function(text) {
                    if (text) Module.printErr('[post-exception status] 
                    ' + text);
                };
            };
```

最后几行关闭了我们的标签，并包括了`{{{ SCRIPT }}}` Emscripten 标签：

```cpp
    </script>
{{{ SCRIPT }}}
</body>
</html>
```

这些前面的四个代码块定义了我们的新`canvas_shell.html`文件。 如果您想下载该文件，可以在 GitHub 上找到它，地址为：[`github.com/PacktPublishing/Hands-On-Game-Development-with-WebAssembly/blob/master/Chapter02/canvas.html`](https://github.com/PacktPublishing/Hands-On-Game-Development-with-WebAssembly/blob/master/Chapter02/canvas.html)。

现在我们已经从高层次查看了代码，我们可以更详细地查看源代码。 在 HTML 的`head`部分，我们正在更改我们链接的`title`和`CSS`文件的`name`。 这是 HTML`head`中的更改：

```cpp
<title>Canvas Shell</title>
<link href="canvas.css" rel="stylesheet" type="text/css">
```

我们不需要之前`<body>`标签中的大多数元素。 我们需要一个`canvas`，这是我们从 Emscripten 提供的`shell_minimal.html`文件中删除的，但现在我们需要将其添加回去。 我们保留了最初在最小 shell 中的`textarea`，并添加了一个新的`img`标签，其中包含从[embed.com](https://www.embed.com)网站上的 TypeScript 画布教程中获取的太空船图像，网址为[`www.embed.com/typescript-games/draw-image.html`](https://www.embed.com/typescript-games/draw-image.html)。 这是`body`元素中的新 HTML 标签：

```cpp
<canvas id="canvas" width="800" height="600" oncontextmenu="event.preventDefault()"></canvas>
<textarea class="em_textarea" id="output" rows="8"></textarea>
<img src="img/spaceship.png" id="spaceship">
```

最后，我们需要更改 JavaScript 代码。我们要做的第一件事是在开头添加三个变量，用于保存对`canvas`元素、画布上下文和新的飞船`img`元素的引用：

```cpp
var img = null;
var canvas = null;
var ctx = null;
```

接下来我们要添加到 JavaScript 中的是一个函数，用于将飞船图像渲染到给定的*x*和*y*坐标的画布上：

```cpp
function ShipPosition( ship_x, ship_y ) {
    if( img == null ) {
        return;
    } 
    ctx.fillStyle = "black";
    ctx.fillRect(0, 0, 800, 600); 
    ctx.save();
    ctx.translate(ship_x, ship_y);
    ctx.drawImage(img, 0, 0, img.width, img.height);
    ctx.restore();
}
```

该函数首先检查`img`变量是否为`null`以外的值。这将让我们知道模块是否已加载，因为`img`变量最初设置为 null。接下来我们要做的是使用`ctx.fillStyle = `black``清除画布的黑色，将上下文填充样式设置为颜色`black`，然后调用`ctx.fillRect`绘制填充整个画布的黑色矩形。接下来的四行保存了画布上下文，将上下文位置转换为飞船的`x`和`y`坐标值，然后将飞船图像绘制到画布上。这四行中的最后一行执行上下文恢复，将我们的平移设置回到(0,0)的起始位置。

在定义了这个函数之后，WebAssembly 模块可以调用它。当模块加载时，我们需要设置一些初始化代码来初始化这三个变量。以下是该代码：

```cpp
function ModuleLoaded() {
    img = document.getElementById('spaceship');
    canvas = document.getElementById('canvas');
    ctx = canvas.getContext("2d");
} 
var Module = {
    preRun: [],
    postRun: [ModuleLoaded],
```

`ModuleLoaded`函数使用`getElementById`将`img`和`canvas`分别设置为飞船和画布的 HTML 元素。然后我们将调用`canvas.getContext(”2d”)`来获取 2D 画布上下文，并将`ctx`变量设置为该上下文。所有这些都在`Module`对象完成加载时调用，因为我们将`ModuleLoaded`函数添加到`postRun`数组中。

我们还在最小的 shell 文件中添加了`canvas`函数，该函数在之前的教程中已经删除了。该代码监视画布上下文，并在上下文丢失时向用户发出警报。最终，我们希望这段代码能够解决问题，但目前知道发生了什么是很好的。以下是该代码：

```cpp
canvas: (function() {
    var canvas = document.getElementById('canvas');
    // As a default initial behavior, pop up an alert when webgl 
       context is lost. To make your
    // application robust, you may want to override this behavior 
       before shipping!
    // See http://www.khronos.org/registry/webgl/specs/latest/1.0/#5.15.2
    canvas.addEventListener("webglcontextlost", function(e) { 
        alert('WebGL context lost. You will need to reload the page.'); 
        e.preventDefault(); }, false);
    return canvas;
})(),
```

为了配合这个新的 HTML shell 文件，我们创建了一个新的`canvas.c`文件，用于编译成 WebAssembly 模块。请注意，从长远来看，我们将在 JavaScript 中做的事情要少得多，而在 WebAssembly C/C++代码中要多得多。以下是新的`canvas.c`文件：

```cpp
#include <emscripten.h>
#include <stdlib.h>
#include <stdio.h>

int ship_x = 0;
int ship_y = 0;

void MoveShip() {
    ship_x += 2;
    ship_y++;

    if( ship_x >= 800 ) {
        ship_x = -128;
    }

    if( ship_y >= 600 ) {
        ship_y = -128;
    }
    EM_ASM( ShipPosition($0, $1), ship_x, ship_y );
}

int main() {
    printf("Begin main\n");
    emscripten_set_main_loop(MoveShip, 0, 0);
    return 1;
}
```

首先，我们创建一个`ship_x`和`ship_y`变量来跟踪飞船的*x*和*y*坐标。之后，我们创建一个`MoveShip`函数。每次调用该函数时，该函数将飞船的*x*位置增加`2`，飞船的*y*位置增加`1`。它还检查飞船的 x 坐标是否离开了画布的右侧，如果是，则将其移回左侧，如果飞船已经移出画布底部，则执行类似的操作。该函数的最后一步是调用我们的 JavaScript`ShipPosition`函数，传递飞船的*x*和*y*坐标。这最后一步将在 HTML5 画布元素上以新坐标绘制我们的飞船。

在我们的`main`函数的新版本中，有以下一行：

```cpp
emscripten_set_main_loop(MoveShip, 0, 0);
```

这行将作为第一个参数传递的函数转换为游戏循环。我们将在后面的章节中详细介绍`emscripten_set_main_loop`的工作原理，但目前只需知道这会导致每次渲染新帧时调用`MoveShip`函数。

最后，我们将创建一个新的`canvas.css`文件，其中包含`body`和`#output` CSS 的代码，并添加一个新的`#canvas` CSS 类。以下是`canvas.css`文件的内容：

```cpp
body {
    margin-top: 20px;
}

#output {
    background-color: darkslategray;
    color: white;
    font-size: 16px;
    padding: 10px;
    margin-left: auto;
    margin-right: auto;
    display: block;
    width: 60%;
}

#canvas {
    width: 800px;
    height: 600px;
    margin-left: auto;
    margin-right: auto;
    display: block;
}
```

一切完成后，我们将使用`emcc`编译新的`canvas.html`文件，以及`canvas.wasm`和`canvas.js`的粘合代码。以下是对`emcc`的调用示例：

```cpp
emcc canvas.c -o canvas.html --shell-file canvas_shell.html
```

在`emcc`之后，我们传入`.c`文件的名称`canvas.c`，这将用于编译我们的 WASM 模块。`-o`标志告诉我们的编译器下一个参数将是输出。使用扩展名为`.html`的输出文件告诉`emcc`编译 WASM、JavaScript 和 HTML 文件。接下来传入的标志是`--shell-file`，告诉`emcc`后面的参数是 HTML 外壳文件的名称，这将用于创建我们最终输出的 HTML 文件。

重要的是要记住，您必须使用 Web 服务器或`emrun`来运行 WebAssembly 应用程序。如果您想使用`emrun`运行 WebAssembly 应用程序，您必须使用`--emrun`标志进行编译。Web 浏览器需要一个 Web 服务器来流式传输 WebAssembly 模块。如果您尝试直接从硬盘驱动器在浏览器中打开使用 WebAssembly 的 HTML 页面，那么 WebAssembly 模块将无法加载。

以下是`canvas.html`的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-gm-dev-wasm/img/d8f3036f-4633-49d4-85ac-8e6324bebfa5.png)

图 2.3：我们的第一个 WebAssembly HTML5 画布应用程序

# 摘要

在本章中，我们讨论了 Emscripten 最小外壳 HTML 文件，它的各个组件以及它们的工作原理。我们还写了关于文件的哪些部分可以不用，如果我们不使用我们的外壳来生成画布代码。您了解了`Module`对象，以及它是使用 JavaScript 粘合代码将我们的 HTML 中的 JavaScript 和我们的 WebAssembly 联系在一起的接口。然后，我们创建了一个包含我们导出的函数的新的 WebAssembly 模块，以允许 JavaScript 使用`Module.cwrap`来创建我们可以从 DOM 中调用的 JavaScript 函数，从而执行我们的 WebAssembly 函数。

我们创建了一个全新的 HTML 外壳文件，使用了 Emscripten 最小外壳的一些`Module`代码，但几乎完全重写了原始外壳的 HTML 和 CSS。然后，我们能够将新的 C 代码和 HTML 外壳文件编译成一个能够从 JavaScript 调用 WebAssembly 函数，并且能够从 WebAssembly 调用 JavaScript 函数的工作 WebAssembly 应用程序。

我们讨论了使用 HTML5 画布元素的好处，以及即时模式和保留模式图形之间的区别。我们还解释了为什么对于游戏和其他图形密集型任务来说，使用即时模式而不是保留模式是有意义的。

然后，我们创建了一个外壳文件来利用 HTML5 画布元素。我们添加了 JavaScript 代码来将图像绘制到画布上，并编写了使用 WebAssembly 在每帧修改画布上图像位置的 C 代码，从而在 HTML5 画布上创建出移动的太空飞船的外观。

在下一章中，我们将向您介绍 WebGL，它是什么，以及它如何改进 Web 上的图形渲染。


# 第三章：WebGL 简介

在苹果创建 Canvas 元素之后，Mozilla 基金会于 2006 年开始研究 Canvas 3D 原型，并在 2007 年实现了这个早期版本，最终成为 WebGL。2009 年，一个名为 Kronos Group 的财团成立了一个 WebGL 工作组。到 2011 年，该组织已经制定了基于 OpenGL ES 2.0 API 的 WebGL 1.0 版本。

正如我之前所说，WebGL 被视为与 HTML5 Canvas 元素一起使用的 3D 渲染 API。它的实现消除了传统 2D 画布 API 的一些渲染瓶颈，并几乎直接访问计算机的 GPU。因此，使用 WebGL 将 2D 图像渲染到 HTML5 画布通常比使用原始 2D 画布实现更快。然而，由于增加了三维渲染的复杂性，使用 WebGL 要复杂得多。因此，有几个库是建立在 WebGL 之上的。这允许用户使用 WebGL，但使用简化的 2D API。如果我们在传统的 JavaScript 中编写游戏，我们可能会使用像 Pixi.js 或 Cocos2d-x 这样的库来简化我们的代码，以便在 WebGL 上进行 2D 渲染。现在，WebAssembly 使用**Simple DirectMedia Layer**（**SDL**）的实现，这是大多数开发人员用来编写游戏的库。这个 WebAssembly 版本的 SDL 是建立在 WebGL 之上的，并提供高端性能，但使用起来更容易。

使用 SDL 并不妨碍您直接从编译为 WebAssembly 的 C++代码中直接使用 WebGL。有时，我们可能对直接与 WebGL 进行交互感兴趣，因为我们感兴趣的功能在 SDL 内部并不直接可用。这些用例的一个例子是创建允许特殊 2D 光照效果的自定义着色器。

在本章中，您需要从 GitHub 项目中获取图像文件来运行示例。该应用程序需要项目目录中的`/Chapter03/spaceship.png`图像文件。请从以下网址下载项目：[`github.com/PacktPublishing/Hands-On-Game-Development-with-WebAssembly`](https://github.com/PacktPublishing/Hands-On-Game-Development-with-WebAssembly)。

在本章中，我们将涵盖以下主题：

+   WebGL 和画布上下文

+   WebGL 着色器简介

+   WebGL 和 JavaScript

# WebGL 和画布上下文

WebGL 是用于绘制 HTML5 元素的渲染上下文，是 2D 渲染上下文的替代品。通常，当有人提到画布时，他们指的是 2D 渲染上下文，通过调用`getContext`并传入字符串`2d`来访问。这两个上下文都是用于绘制到 HTML5 画布元素的方法。上下文是一种用于即时模式渲染的 API 类型。可以请求两种不同的 WebGL 上下文，两者都提供对不同版本的 WebGL API 的访问。这些上下文是*webgl*和*webgl2*。在接下来的示例中，我将使用*webgl*上下文，并将使用 WebGL 1.0 API。还有一个很少使用的上下文，用于将位图渲染到画布上，我们可以通过传入`bitmaprenderer`作为字符串值来访问。

我想指出，术语画布有时用于指代 2D 画布上下文，有时用于指代即时模式渲染的 HTML5 画布元素。当我在本书中提到画布而没有提到 2D 上下文时，我指的是 HTML5 画布元素。

在下一节中，我将向您介绍着色器和 GLSL 着色器语言。

# WebGL 着色器简介

当 OpenGL 或 WebGL 与 GPU 交互时，它们传递数据告诉 GPU 需要渲染的几何图形和纹理。此时，GPU 需要知道如何将这些纹理和与之相关的几何图形渲染成一个在计算机显示器上显示的单个 2D 图像。**OpenGL 着色器语言**（**GLSL**）是一种用于指导 GPU 如何渲染 2D 图像的语言，它与 OpenGL 和 WebGL 一起使用。

从技术上讲，WebGL 使用 GLSL ES 着色器语言（有时称为 ELSL），它是 GLSL 语言的一个子集。GLSL ES 是与 OpenGL ES 一起使用的着色器语言，OpenGL ES 是 OpenGL 的一个移动友好子集（ES 代表嵌入式系统）。因为 WebGL 基于 OpenGL ES，它继承了 GLSL ES 着色器语言。请注意，每当我在 WebGL 或 WebAssembly 的上下文中提到 GLSL 时，我指的是 GLSL ES。

WebGL 渲染管道要求我们编写两种类型的着色器来将图像渲染到屏幕上。这些是顶点着色器，它以每个顶点为基础渲染几何图形，以及片段着色器，它渲染像素候选，称为片段。GLSL 看起来很像 C 语言，所以如果你在 C 或 C++中工作，代码会看起来有些熟悉。

这个 GLSL 着色器的介绍不会详细讨论。在后面的章节中，我将更详细地讨论 WebGL 着色器。现在，我只想介绍这个概念，并向你展示一个非常简单的 2D WebGL 着色器。在关于 2D 光照的章节中，我将更详细地讨论这个问题。这是一个用于渲染 2D WebGL 渲染引擎中四边形的简单顶点着色器的示例：

```cpp
precision mediump float;

attribute vec4 a_position;
attribute vec2 a_texcoord;

uniform vec4 u_translate;

varying vec2 v_texcoord;

void main() {
   gl_Position = u_translate + a_position;
    v_texcoord = a_texcoord;
}
```

这个非常简单的着色器接收顶点的位置，并根据通过 WebGL 传递到着色器中的位置统一值移动它。这个着色器将在我们的几何图形中的每个顶点上运行。在 2D 游戏中，所有几何图形都将被渲染为四边形。以这种方式使用 WebGL 可以更好地利用计算机的 GPU。让我简要地讨论一下这个顶点着色器代码中发生了什么。

如果你是游戏开发的新手，顶点着色器和像素着色器的概念可能会感到有些陌生。它们并不像一开始看起来那么神秘。如果你想更好地理解着色器是什么，你可能想快速阅读一下维基百科的*着色器*文章（[`en.wikipedia.org/wiki/Shader`](https://en.wikipedia.org/wiki/Shader)）。如果你仍然感到迷茫，可以随时在 Twitter 上问我问题（`@battagline`）。

这个着色器的第一行设置了浮点精度：

```cpp
precision mediump float;
```

计算机上的所有浮点运算都是对实数分数的近似。我们可以用 0.333 来低精度地近似 1/3，用 0.33333333 来高精度地近似。代码中的精度行表示 GPU 上浮点值的精度。我们可以使用三种可能的精度：`highp`、`mediump`或`lowp`。浮点精度越高，GPU 执行代码的速度就越慢，但所有计算值的精度就越高。一般来说，我将这个值保持在`mediump`，这对我来说效果很好。如果你有一个需要性能而不是精度的应用程序，你可以将其更改为`lowp`。如果你需要高精度，请确保你了解目标 GPU 的能力。并非所有 GPU 都支持`highp`。

属性变量是与顶点数组一起传递到管道中的值。在我们的代码中，这些值包括与顶点相关的纹理坐标，以及与顶点相关的 2D 平移矩阵：

```cpp
attribute vec4 a_position;
attribute vec2 a_texcoord;
```

uniform 变量类型是一种在所有顶点和片段中保持恒定的变量类型。在这个顶点着色器中，我们传入一个 uniform 向量`u_translate`。通常情况下，除非是为了相机，您不会希望将所有顶点平移相同的量，但因为我们只是编写一个用于绘制单个精灵的 WebGL 程序，所以使用`uniform`变量来进行`translate`将是可以的：

```cpp
uniform vec4 u_translate;
```

`varying`变量（有时被称为插值器）是从顶点着色器传递到片段着色器的值，片段着色器中的每个片段都会得到该值的插值版本。在这段代码中，唯一的`varying`变量是顶点的纹理坐标：

```cpp
varying vec2 v_texcoord;
```

在数学中，插值值是计算出的中间值。例如，如果我们在 0.2 和 1.2 之间进行插值，我们将得到一个值为 0.7。也就是说，0.2 的起始值，加上(1.2-0.2)/2 的平均值=0.5。所以，0.2+0.5=0.7。使用`varying`关键字从顶点着色器传递到片段着色器的值将根据片段相对于顶点的位置进行插值。

最后，在顶点着色器中执行的代码位于`main`函数内。该代码获取顶点的位置，并将其乘以平移矩阵以获得顶点的世界坐标，以便将其放入`gl_Position`中。然后，它将直接将传递到顶点着色器的纹理坐标设置为插值变量，以便将其传递到片段着色器中：

```cpp
void main() {
    gl_Position = u_translate + a_position;
    v_texcoord = a_texcoord;
}
```

顶点着色器运行后，顶点着色器生成的所有片段都会通过片段着色器运行，片段着色器会为每个片段插值所有的`varying`变量。

这是一个片段着色器的简单示例：

```cpp
precision mediump float;

varying vec2 v_texcoord;

uniform sampler2D u_texture;

void main() {
    gl_FragColor = texture2D(u_texture, v_texcoord);
}
```

就像在我们的顶点着色器中一样，我们首先将浮点精度设置为`mediump`。片段有一个`uniform sample2D`纹理，定义了用于在我们的游戏中生成 2D 精灵的纹理映射：

```cpp
uniform sampler2D u_texture;
```

`uniform`有点像是传递到管道中并应用于着色器中使用它的每个顶点或每个片段的全局变量。`main`函数中执行的代码也很简单。它获取从`v_texcoord`变量中插值的纹理坐标，并从我们采样的纹理中检索颜色值，然后使用该值设置`gl_FragColor`片段的颜色：

```cpp
void main() {
    gl_FragColor = texture2D(u_texture, v_texcoord);
}
```

直接在 JavaScript 中使用 WebGL 将一个简单的 2D 图像绘制到屏幕上需要更多的代码。在下一节中，我们将编写我能想到的最简单版本的 2D 精灵渲染 WebGL 应用程序，这恰好是我们在上一章中编写的 2D 画布应用程序的新版本。我认为值得看到两种方法在 HTML 画布上渲染 2D 图像之间的区别。了解更多关于 WebGL 的知识也将有助于我们理解当我们最终在 WebAssembly 中使用 SDL API 时发生了什么。在创建 WebGL JavaScript 应用程序时，我会尽量保持演示和代码的简单。

正如我之前提到的，本章的目的是让您亲身体验 WebGL。在本书的大部分内容中，我们不会直接处理 WebGL，而是使用更简单的 SDL API。如果您对编写自己的着色器不感兴趣，您可以将本章视为可选但有益的信息。

在下一节中，我们将学习如何使用 WebGL 绘制到画布上。

# WebGL 和 JavaScript

正如我们在上一章中学到的，使用 2D 画布非常简单。要绘制图像，你只需要将上下文转换为要绘制图像的像素坐标，并调用`drawImage`上下文函数，传入图像、宽度和高度。如果你愿意，你甚至可以更简单地忘记转换，直接将 x 和 y 坐标传递到`drawImage`函数中。在 2D 画布中，你在使用图像，但在 WebGL 中，即使在编写 2D 游戏时，你总是在使用 3D 几何。在 WebGL 中，你需要将纹理渲染到几何体上。你需要使用顶点缓冲区和纹理坐标。我们之前编写的顶点着色器接收 3D 坐标数据和纹理坐标，并将这些值传递到片段着色器，后者将在几何体之间进行插值，并使用纹理采样函数来检索正确的纹理数据，以将像素渲染到画布上。

# WebGL 坐标系统与 2D 画布

使用 WebGL，画布元素的中心是原点(0,0)。**正 Y**向上，而**正 X**向右。对于从未使用过 2D 图形的人来说，这更直观一些，因为它类似于我们在小学学到的坐标几何中的象限。在 2D 画布中，你总是在使用像素，并且画布上不会出现负数。

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-gm-dev-wasm/img/4eec22e0-cd90-4ea2-9e50-e58c4ba7f9b3.png)

当你调用`drawImage`时，X 和 Y 坐标是图像的左上角绘制的位置。WebGL 有点不同。一切都使用几何，需要顶点着色器和像素着色器。我们将图像转换为纹理，然后将其拉伸到几何上，以便显示。这是 WebGL 坐标系统的样子：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-gm-dev-wasm/img/9e188d87-56e7-4899-baff-52a2cd299f30.png)

如果你想在画布上的特定像素位置放置图像，你需要知道画布的宽度和高度。你的画布的**中心点**是**(0,0)**，**左上角**是**(-1, 1)**，**右下角**是**(1, -1)**。因此，如果你想在 x=150，y=160 处放置图像，你需要使用以下方程来找到 WebGL 的 x 坐标：

```cpp
 webgl_x = (pixel_x - canvas_width / 2) / (canvas_width / 2)
```

因此，对于`pixel_x`位置为 150，我们需要从 150 减去 400 得到-250。然后，我们需要将-250 除以 400，我们会得到-0.625。我们需要做类似的事情来获取 WebGL 的 y 坐标，但是轴的符号是相反的，所以我们需要做以下操作来获取`pixel_x`值，而不是我们之前做的：

```cpp
((canvas_height / 2) - pixel_y) / (canvas_height / 2)
```

通过插入值，我们得到((600 / 2) - 160) / (600 / 2) 或 (300 - 160) / 300 = 0.47。

我跳过了很多关于 WebGL 的信息，以简化这个解释。WebGL 不是一个 2D 空间，即使在这个例子中我把它当作一个 2D 空间。因为它是一个 3D 空间，单位中画布的大小是基于一个称为裁剪空间的视图区域。如果你想了解更多，Mozilla 有一篇关于裁剪空间的优秀文章：[`developer.mozilla.org/en-US/docs/Web/API/WebGL_API/WebGL_model_view_projection`](https://developer.mozilla.org/en-US/docs/Web/API/WebGL_API/WebGL_model_view_projection)。

# 顶点和 UV 数据

在我们看一大段可怕的 WebGL JavaScript 代码之前，我想简要讨论数据缓冲区以及我们将如何将几何和纹理坐标数据传递到着色器中。我们将在一个大缓冲区中传递 32 位浮点数据，该缓冲区将包含顶点的 X 和 Y 坐标的组合以及该顶点的 UV 纹理坐标。UV 映射是 GPU 将 2D 纹理坐标映射到 3D 几何的方法：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-gm-dev-wasm/img/8f2d81e2-1594-408e-85bc-6a01b00b9973.png)

WebGL 和 OpenGL 通过为每个顶点分配 U 和 V 坐标来实现这一点。分配给顶点的 UV 坐标（0,0）意味着该顶点的颜色将基于纹理左上角的颜色。UV 坐标（1,1）意味着它将根据纹理右下角的颜色进行着色。当我们在 3D 对象的点之间进行插值时，我们还在纹理内部的不同 UV 坐标之间进行插值。这些 UV 坐标可以在我们的片段着色器中使用`texture2D`内置函数进行采样，通过传入纹理和当前 UV 坐标。

让我们来看看我们在这个 WebGL 应用程序中使用的顶点和纹理数据数组：

```cpp
var vertex_texture_data = new Float32Array([
 //  X,     Y,     U,   V
     0.16,  0.213, 1.0, 1.0,
    -0.16,  0.213, 0.0, 1.0,
     0.16, -0.213, 1.0, 0.0,
    -0.16, -0.213, 0.0, 0.0,
    -0.16,  0.213, 0.0, 1.0,
     0.16, -0.213, 1.0, 0.0
 ]);
```

这些数据已经按行和列输入。尽管这是一组线性数据，但格式允许您看到我们将为每个顶点传递四个浮点值。数据上方有一条注释，显示每列代表什么。前两个数据值是几何图形的 X 和 Y 坐标。接下来的两个值是将纹理映射到几何图形的 X 和 Y 坐标的 U 和 V 坐标。这里有六行，尽管我们正在渲染一个矩形。我们需要六个点而不是四个的原因是，WebGL 通常使用三角形组成的几何图形。因此，我们需要重复两个顶点。

也许你会想，*为什么是三角形？*嗯，曾经有一段时间，计算机图形使用的几何图形并不是分解成三角形的。但是当你有一个四边形，而不是所有的点都共面（在同一个平面上）时就会出现问题。这与我去使用四条腿凳子的酒吧时遇到的问题是一样的。我很确定四条腿凳子的存在是某种秘密组织的阴谋，目的是让我失去平衡，但我岔开了话题。因为三个点定义一个平面，所以三角形根据定义总是共面的，就像一个三条腿的凳子永远不会摇摆一样。

# 2D 画布到 WebGL

让我们从`Chapter02`目录中复制出画布代码到`Chapter03`目录中。接下来，我们将把`canvas_shell.html`文件重命名为`webgl_shell.html`。我们将把`canvas.css`重命名为`webgl.css`。最后，我们将把`canvas.c`文件重命名为`webgl.c`。我们还需要确保复制`spaceship.png`文件。我们不会对`webgl.css`文件进行任何更改。我们将对`webgl_shell.html`文件进行最重要的更改。有很多代码需要添加，以完成从 2D 画布到 WebGL 的切换；几乎所有的代码都是额外的 JavaScript 代码。我们需要对`webgl.c`进行一些微小的调整，以使`MoveShip`函数中飞船的位置反映出带有原点在画布中心的 WebGL 坐标系统。

在我们开始之前，我想提一下，这个 WebGL 代码并不是为了投入生产。我们将要创建的游戏不会像我在这里演示的方式使用 WebGL。那不是最有效或可扩展的代码。我们所编写的代码将无法在没有重大更改的情况下一次渲染多个精灵。我之所以向你演示使用 WebGL 渲染 2D 图像的过程，是为了让你了解在使用类似 SDL 这样的库时发生了什么。如果你不在乎幕后的工作原理，那么跳过也没人会责怪你。就我个人而言，我总是更愿意多了解一点。

# 对 head 标签进行微小调整

在我们的`head`标签内，我们需要改变`title`，因为我们将`canvas.css`重命名为`webgl.css`，所以我们需要将我们的`link`标签指向新的样式表名称。以下是在 HTML 开头必须更改的唯一两个标签：

```cpp
<title>WebGL Shell</title>
<link href="webgl.css" rel="stylesheet" type="text/css">
```

稍后在 HTML 中，我们将删除`img`标签，其中`src`设置为`"spaceship.png"`。这并不是必须的。在画布版本中，我们使用此标签将图像呈现到画布上。在这个 WebGL 版本中，我们将动态加载图像，因此没有必要保留它，但如果您忘记删除它，将不会以任何方式损害应用程序。

# 主要 JavaScript 更改

`webgl_shell.html`文件中 JavaScript 部分内的`Module`代码将保持不变，因此您无需担心在以下行之后修改任何内容：

```cpp
var Module = {
```

但是，`script`标签中代码的前半部分将需要进行一些重大修改。您可能希望重新开始并删除整个模块。

# WebGL 全局变量

我们要做的第一件事是创建许多 JavaScript 全局变量。如果此代码不仅仅是用于演示，使用这么多全局变量通常是不受欢迎的，被认为是不良实践。但就我们现在所做的事情而言，它有助于简化事情：

```cpp
<script type='text/javascript'>
 var gl = null; // WebGLRenderingContext
 var program = null; // WebGLProgram
 var texture = null; // WebGLTexture
 var img = null; // HTMLImageElement
 var canvas = null;
 var image_width = 0;
 var image_height = 0;
 var vertex_texture_buffer = null; // WebGLBuffer
 var a_texcoord_location = null; // GLint
 var a_position_location = null; // GLint
 var u_translate_location = null; // WebGLUniformLocation
 var u_texture_location = null; // WebGLUniformLocation
```

第一个变量`gl`是渲染上下文的新版本。通常，如果您使用 2D 渲染上下文，您称之为`ctx`，如果您使用 WebGL 渲染上下文，您将其命名为`gl`。第二行定义了`program`变量。当我们编译顶点和片段着色器时，我们会得到一个编译后的版本，以`WebGLProgram`对象的形式存储在`program`变量中。`texture`变量将保存我们将从`spaceship.png`图像文件加载的`WebGLTexture`。这是我们在上一章中用于 2D 画布教程的图像。`img`变量将用于加载将用于加载纹理的`spaceship.png`图像文件。`canvas`变量将再次是对我们的 HTML 画布元素的引用，`image_width`和`image_height`将在加载后保存`spaceship.png`图像的高度和宽度。

`vertex_texture_buffer`属性是一个缓冲区，将用于将顶点几何和纹理数据传输到 GPU，以便我们在上一节中编写的着色器可以使用它。`a_texcoord_location`和`a_position_location`变量将用于保存对顶点着色器中`a_texcoord`和`a_position`属性变量的引用，最后，`u_translate_location`和`u_texture_location`用于引用着色器中的`u_translate`和`u_texture`统一变量。

# 返回顶点和纹理数据

如果我告诉你我们还有一些变量要讨论，你会不会不高兴？好吧，下一个变量是我们之前讨论过的变量，但我会再次提到它，因为它很重要。`vertex_texture_data`数组是一个存储用于渲染的所有顶点几何和 UV 纹理坐标数据的数组：

```cpp
var vertex_texture_data = new Float32Array([
     // x,  y,     u,   v
     0.16,  0.213, 1.0, 1.0,
    -0.16,  0.213, 0.0, 1.0,
     0.16, -0.213, 1.0, 0.0,
    -0.16, -0.213, 0.0, 0.0,
    -0.16,  0.213, 0.0, 1.0,
     0.16, -0.213, 1.0, 0.0
 ]);
```

我之前没有提到的一件事是，为什么`x`和`y`值在 x 轴上的范围是`-0.16`到`0.16`，在 y 轴上的范围是`-0.213`到`0.213`。因为我们正在渲染一张单独的图像，我们不需要动态地缩放几何图形以适应图像。我们正在使用的太空船图像是 128 x 128 像素。我们使用的画布大小是 800 x 600 像素。正如我们之前讨论的，无论我们为画布使用什么大小，WebGL 都会将两个轴都适应到-1 到+1 的范围内。这使得坐标（0, 0）成为画布元素的中心。这也意味着画布的宽度始终为 2，高度始终为 2，无论画布元素有多少像素宽或高。因此，如果我们想要计算出我们的几何图形有多宽，以使其与图像的宽度匹配，我们需要进行一些计算。首先，我们需要弄清楚 WebGL 剪辑空间宽度的一个单位对应于一个像素的宽度。WebGL 剪辑空间的宽度为 2.0，实际画布的宽度为 800 像素，因此在 WebGL 空间中一个像素的宽度为 2.0 / 800 = 0.0025。我们需要知道我们的图像在 WebGL 剪辑空间中有多宽，因此我们将 128 像素乘以 0.0025，得到 WebGL 剪辑空间宽度为 0.32。因为我们希望我们的几何图形的 x 值在中心为 0，我们的 x 几何范围从-0.16 到+0.16。

现在我们已经完成了宽度，让我们来解决高度。画布的高度为 600 像素，但在 WebGL 剪辑空间中，画布的高度始终为 2.0（-1.0 Y 到+1.0 Y）。因此，一个像素中有多少个 WebGL 单位？2.0 / 600 = 0.00333333…重复。显然，这是一个浮点精度无法匹配实际值的情况。我们将截掉一些尾随的 3，并希望精度足够。回到计算图像在 WebGL 剪辑空间中的高度，它高 128 像素，所以我们需要将 128 乘以 0.0033333…重复。结果是 0.4266666…重复，我们将截断为 0.426。因此，我们的 y 几何必须从`-0.213`到`+0.213`。

我正在尽力忽略 WebGL 剪辑空间的复杂性。这是一个 3D 体积，而不是像 2D 画布上下文那样简单的 2D 绘图区域。有关此主题的更多信息，请参阅 Mozilla 开发人员文档的剪辑空间部分：[`developer.mozilla.org/en-US/docs/Web/API/WebGL_API/WebGL_model_view_projection#Clip_space`](https://developer.mozilla.org/en-US/docs/Web/API/WebGL_API/WebGL_model_view_projection#Clip_space)。

正如我之前所说的，当我们开发游戏时，SDL 会为我们处理很多事情，但是在将来，您可能希望在 WebAssembly 中使用 OpenGL。OpenGL ES 2.0 和 OpenGL ES 3.0 库已经移植到 WebAssembly，并且这些库或多或少地与 WebGL 具有直接的类比。WebGL 1.0 是 OpenGL ES 2.0 的修改版本，它是设计用于在移动硬件上运行的 OpenGL 的一个版本。WebGL 2.0 是 OpenGL ES 3.0 的修改版本。通过对 SDL 的调用理解 WebGL 正在做什么，可以使我们成为更好的游戏开发人员，即使 SDL 为我们做了很多繁重的工作。

# 缓冲区常量

我选择使用一个单独的`Float32Array`来保存此应用程序的所有顶点数据。这包括 X 和 Y 坐标数据，以及 U 和 V 纹理坐标数据。因此，当我们将这些数据加载到 GPU 的缓冲区中时，我们需要告诉 WebGL 如何将这些数据分开成不同的属性。我们将使用以下常量来告诉 WebGL`Float32Array`中的数据是如何分解的：

```cpp
const FLOAT32_BYTE_SIZE = 4; // size of a 32-bit float
const STRIDE = FLOAT32_BYTE_SIZE * 4; // there are 4 elements for every vertex. x, y, u, v
const XY_OFFSET = FLOAT32_BYTE_SIZE * 0;
const UV_OFFSET = FLOAT32_BYTE_SIZE * 2;
```

`FLOAT32_BYTE_SIZE`常量是`Float32Array`中每个变量的大小。`STRIDE`常量将用于告诉 WebGL 单个顶点数据使用了多少字节。我们在前面的代码中定义的四列代表*x*、*y*、*u*和*v*。由于这些变量中的每一个使用了四个字节的数据，我们将变量的数量乘以每个变量使用的字节数来得到*stride*，或者单个顶点使用的字节数。`XY_OFFSET`常量是每个 stride 内的起始位置，我们将在那里找到*x*和*y*坐标数据。为了保持一致，我将浮点字节大小乘以位置，但由于它是`0`，我们可以直接使用`const XY_OFFSET = 0`。现在，`UV_OFFSET`是从每个 stride 开始的偏移量，我们将在那里找到 UV 纹理坐标数据。由于它们在位置 2 和 3，偏移量是每个变量使用的字节数乘以`2`。

# 定义着色器

我在前一节中详细介绍了着色器所做的一切。你可能想再次浏览一下那一节作为复习。代码的下一部分定义了多行 JavaScript 字符串中的顶点着色器代码和片段着色器代码。以下是顶点着色器代码：

```cpp
var vertex_shader_code = `
    precision mediump float;
    attribute vec4 a_position;
    attribute vec2 a_texcoord;
    varying vec2 v_texcoord;
    uniform vec4 u_translate;

    void main() {
        gl_Position = u_translate + a_position;
        v_texcoord = a_texcoord;
    }
`;
```

片段着色器代码如下：

```cpp
var fragment_shader_code = `
    precision mediump float;
    varying vec2 v_texcoord;
    uniform sampler2D u_texture;

    void main() {
        gl_FragColor = texture2D(u_texture, v_texcoord);
    }
`;
```

让我们来看看顶点着色器代码中的属性：

```cpp
attribute vec4 a_position;
attribute vec2 a_texcoord;
```

这两个属性将从`Float32Array`中的数据中传递。在 WebGL 中的一个很棒的技巧是，如果你没有使用所有四个位置变量（*x*，*y*，*z*，*w*），你可以传递你正在使用的两个（*x*，*y*），GPU 将知道如何在其他两个位置使用适当的值。这些着色器将需要传递两个属性：

```cpp
attribute vec4 a_position;
attribute vec2 a_texcoord;
```

我们将再次使用缓冲区和`Float32Array`来完成这个任务。我们还需要传递两个`uniform`变量。`u_translate`变量将被顶点着色器用于平移精灵的位置，`u_texture`是片段着色器将使用的纹理缓冲区。这些着色器几乎是尽可能简单的。许多教程都是从没有纹理开始，只是硬编码片段着色器的颜色输出，就像这样：

```cpp
gl_FragColor = vec4(1.0, 0.0, 0.0, 1.0);
```

做出这个改变将导致片段着色器始终输出红色，所以请不要做这个改变。我能想到的唯一让这个教程更简单的事情是不加载纹理并渲染纯色，以及不允许几何体被移动。

# `ModuleLoaded`函数

在旧的 2D 画布代码中，我们在`ModuleLoaded`函数之前定义了`ShipPosition` JavaScript 函数，但是我们已经将这两个函数互换了。我觉得在渲染部分之前解释 WebGL 初始化会更好。以下是`ModuleLoaded`函数的新版本：

```cpp
function ModuleLoaded() {
    canvas = document.getElementById('canvas');
    gl = canvas.getContext("webgl", { alpha: false }) ||
                            canvas.getContext("experimental-webgl", { 
                            alpha: false });

    if (!gl) {
        console.log("No WebGL support!");
        return;
    }

    gl.blendFunc( gl.SRC_ALPHA, gl.ONE_MINUS_SRC_ALPHA );
    gl.enable( gl.BLEND );

    var vertex_shader = gl.createShader(gl.VERTEX_SHADER);
    gl.shaderSource( vertex_shader, vertex_shader_code );
    gl.compileShader( vertex_shader );

    if( !gl.getShaderParameter(vertex_shader, gl.COMPILE_STATUS) ) {
        console.log('Failed to compile vertex shader' + 
                     gl.getShaderInfoLog(vertex_shader));
        gl.deleteShader(vertex_shader);
        return;
    }

    var fragment_shader = gl.createShader(gl.FRAGMENT_SHADER);
    gl.shaderSource( fragment_shader, fragment_shader_code );
    gl.compileShader( fragment_shader );

    if( !gl.getShaderParameter(fragment_shader, gl.COMPILE_STATUS) ) {
        console.log('Failed to compile fragment shader' + 
                     gl.getShaderInfoLog(fragment_shader));
        gl.deleteShader(fragment_shader);
        return;
    }

    program = gl.createProgram();

    gl.attachShader(program, vertex_shader);
    gl.attachShader(program, fragment_shader);
    gl.linkProgram(program);

    if( !gl.getProgramParameter(program, gl.LINK_STATUS) ) {
        console.log('Failed to link program');
        gl.deleteProgram(program);
        return;
    }

    gl.useProgram(program);

    u_texture_location = gl.getUniformLocation(program, "u_texture");
    u_translate_location = gl.getUniformLocation(program, 
    "u_translate");

    a_position_location = gl.getAttribLocation(program, "a_position");
    a_texcoord_location = gl.getAttribLocation(program, "a_texcoord");

    vertex_texture_buffer = gl.createBuffer();

    gl.bindBuffer(gl.ARRAY_BUFFER, vertex_texture_buffer);
    gl.bufferData(gl.ARRAY_BUFFER, vertex_texture_data, 
    gl.STATIC_DRAW);

    gl.enableVertexAttribArray(a_position_location);
    gl.vertexAttribPointer(a_position_location, 2, gl.FLOAT, false, 
    STRIDE, XY_OFFSET);

    gl.enableVertexAttribArray(a_texcoord_location);
    gl.vertexAttribPointer(a_texcoord_location, 2, gl.FLOAT, false, 
    STRIDE, UV_OFFSET);

    texture = gl.createTexture();

    gl.bindTexture(gl.TEXTURE_2D, texture);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.REPEAT);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.REPEAT);

    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.NEAREST);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.NEAREST);

    img = new Image();
    img.addEventListener('load', function() {
        image_width = img.width;
        image_height = img.height;

        gl.bindTexture(gl.TEXTURE_2D, texture);
        gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, gl.RGBA,
        gl.UNSIGNED_BYTE, img );
    });
    img.src = "spaceship.png";

    gl.viewport(0, 0, gl.canvas.width, gl.canvas.height);
}
```

前几行获取了`canvas`元素，并使用它来获取 WebGL 上下文。如果 JavaScript 未能获取 WebGL 上下文，我们会警告用户，让他们知道他们的浏览器不支持 WebGL：

```cpp
canvas = document.getElementById('canvas');

gl = canvas.getContext("webgl", { alpha: false }) ||
                        canvas.getContext("experimental-webgl", { 
                        alpha: false });
if (!gl) {
    console.log("No WebGL support!");
    return;
}
```

接下来的两行打开了 alpha 混合：

```cpp
gl.blendFunc( gl.SRC_ALPHA, gl.ONE_MINUS_SRC_ALPHA );
gl.enable( gl.BLEND );
```

编译、加载和链接顶点和片段着色器是一项具有挑战性的工作。我不确定为什么 WebGL 库中没有一个函数可以一步完成所有这些工作。几乎每个为 2D 编写 webgl 的人都要做到这一点，他们要么将其放入一个单独的`.js`文件中，要么将其复制粘贴到每个项目的代码中。目前，你需要知道关于下面的代码批处理的是，它正在将我们之前编写的顶点和片段着色器编译成程序变量。从那时起，我们将使用程序变量与着色器进行交互。以下是代码：

```cpp
var vertex_shader = gl.createShader(gl.VERTEX_SHADER);
gl.shaderSource( vertex_shader, vertex_shader_code );
gl.compileShader( vertex_shader );

if( !gl.getShaderParameter(vertex_shader, gl.COMPILE_STATUS) ) {
    console.log('Failed to compile vertex shader' + 
    gl.getShaderInfoLog(vertex_shader));
    gl.deleteShader(vertex_shader);
    return;
}

var fragment_shader = gl.createShader(gl.FRAGMENT_SHADER);
gl.shaderSource( fragment_shader, fragment_shader_code );
gl.compileShader( fragment_shader );

if( !gl.getShaderParameter(fragment_shader, gl.COMPILE_STATUS) ) {
    console.log('Failed to compile fragment shader' + 
    gl.getShaderInfoLog(fragment_shader));
    gl.deleteShader(fragment_shader);
    return;
}

program = gl.createProgram();
gl.attachShader(program, vertex_shader);
gl.attachShader(program, fragment_shader);
gl.linkProgram(program);

if( !gl.getProgramParameter(program, gl.LINK_STATUS) ) {
    console.log('Failed to link program');
    gl.deleteProgram(program);
    return;
}
gl.useProgram(program);
```

现在我们在`program`变量中有了`WebGLProgram`对象，我们可以使用该对象与我们的着色器进行交互。

1.  我们要做的第一件事是获取我们着色器程序中的`uniform`变量的引用：

```cpp
u_texture_location = gl.getUniformLocation(program, "u_texture");
u_translate_location = gl.getUniformLocation(program, "u_translate");
```

1.  之后，我们将使用`program`对象来获取我们顶点着色器使用的属性变量的引用：

```cpp
a_position_location = gl.getAttribLocation(program, "a_position");
a_texcoord_location = gl.getAttribLocation(program, "a_texcoord");
```

1.  现在，是时候开始使用缓冲区了。您还记得我们创建了包含所有顶点数据的`Float32Array`吗？现在是使用缓冲区将该数据发送到 GPU 的时候了：

```cpp
vertex_texture_buffer = gl.createBuffer();

gl.bindBuffer(gl.ARRAY_BUFFER, vertex_texture_buffer);
gl.bufferData(gl.ARRAY_BUFFER, vertex_texture_data, 
              gl.STATIC_DRAW);

gl.enableVertexAttribArray(a_position_location);
gl.vertexAttribPointer(a_position_location, 2, gl.FLOAT, false, 
                        STRIDE, XY_OFFSET);

gl.enableVertexAttribArray(a_texcoord_location);
gl.vertexAttribPointer(a_texcoord_location, 2, gl.FLOAT, false, 
                        STRIDE, UV_OFFSET);
```

第一行创建了一个名为`vertex_texture_buffer`的新缓冲区。以`gl.bindBuffer`开头的行将`vertex_texture_buffer`绑定到`ARRAY_BUFFER`，然后`bufferData`将`vertex_texture_data`中的数据添加到`ARRAY_BUFFER`中。之后，我们需要使用之前在`a_position_location`和`a_texcoord_location`变量中创建的对`a_position`和`a_texcoord`的引用告诉 WebGL 在这个数组缓冲区中找到`a_position`和`a_texcoord`属性的数据。它首先调用`enableVertexAttribArray`来使用我们创建的位置变量启用该属性。接下来，`vertexAttribPointer`使用`STRIDE`和`XY_OFFSET`或`UV_OFFSET`告诉 WebGL 属性数据在缓冲区数据中的位置。

1.  之后，我们将创建并绑定纹理缓冲区：

```cpp
texture = gl.createTexture();
gl.bindTexture(gl.TEXTURE_2D, texture);
```

1.  现在我们有了一个绑定的纹理缓冲区，我们可以在缩放时配置该缓冲区为镜像包裹和最近邻插值：

```cpp
gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.REPEAT);
gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.REPEAT);

gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.NEAREST);
gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.NEAREST);
```

我们使用`gl.NEAREST`而不是`gl.LINEAR`，因为我希望游戏具有老式的像素化外观。在您的游戏中，您可能更喜欢不同的算法。

1.  配置纹理缓冲区后，我们将下载`spaceship.png`图像并将该图像数据加载到纹理缓冲区中：

```cpp
img = new Image();

img.addEventListener('load', function() {
    image_width = img.width;
    image_height = img.height;

    gl.bindTexture(gl.TEXTURE_2D, texture);
    gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, gl.RGBA,
                    gl.UNSIGNED_BYTE, img );
});

img.src = "spaceship.png";
```

1.  我们要做的最后一件事是将视口设置为从（0,0）到画布的宽度和高度。视口告诉 WebGL 画布元素中的空间如何与我们的 WebGL 裁剪空间相关联：

```cpp
gl.viewport(0, 0, gl.canvas.width, gl.canvas.height);
```

# ShipPosition 函数

如果这是生产质量的代码，我将在渲染函数中执行目前在初始化例程中执行的大部分工作。在画布上独立移动精灵将需要更新我们的数组缓冲区。我可能不会以我所做的方式定义几何形状，也就是手动计算大小。我目前没有对数组缓冲区或纹理缓冲区进行任何更改；我试图保持这段代码尽可能少，以便使用 WebGL 将精灵渲染到画布上。这是我拥有的内容：

```cpp
function ShipPosition( ship_x, ship_y ) {
    if( image_width == 0 ) {
        return;
    }

    gl.uniform4fv(u_translate_location, [ship_x, ship_y, 0.0, 0.0]);
    gl.drawArrays(gl.TRIANGLES, 0, 6);
}

```

1.  前几行检查图像下载是否已完成。如果没有，我们将退出该函数：

```cpp
if( image_width == 0 ) {
    return;
}
```

1.  接下来，我们告诉 WebGL 使用我们飞船坐标加载`u_translate`统一变量：

```cpp
gl.uniform4fv(u_translate_location, [ship_x, ship_y, 0.0, 0.0]);
```

1.  最后，我们指示 WebGL 使用数组缓冲区中的六个顶点绘制三角形：

```cpp
gl.drawArrays(gl.TRIANGLES, 0, 6);
```

# MoveShip 函数

我们需要回到 WebAssembly C 模块。`webgl.c`文件是`canvas.c`的复制版本，我们需要做的唯一更改是在`MoveShip`函数内部。这是`MoveShip`的新版本：

```cpp
void MoveShip() {
    ship_x += 0.002;
    ship_y += 0.001;

    if( ship_x >= 1.16 ) {
        ship_x = -1.16;
    }

    if( ship_y >= 1.21 ) {
        ship_y = -1.21;
    }

    EM_ASM( ShipPosition($0, $1), ship_x, ship_y );
}
```

更改都是从像素空间转换为 WebGL 裁剪空间。在 2D 画布版本中，我们每帧将两个像素添加到飞船的`x`坐标和一个像素添加到飞船的`y`坐标。但是在 WebGL 中，将`x`坐标移动两个像素将使其移动整个屏幕的宽度。因此，我们必须将这些值修改为与 WebGL 坐标系统兼容的小单位：

```cpp
ship_x += 0.002;
ship_y += 0.001;
```

将`0.002`添加到`x`坐标会使飞船每帧移动画布宽度的 1/500。将`y`坐标移动`0.001`会使飞船在 y 轴上每帧移动屏幕高度的 1/1,000。你可能会注意到，在这个应用程序的 2D 画布版本中，飞船向右下方移动。这是因为在 2D 画布坐标系统中增加`y`坐标会使图像向下移动。在 WebGL 坐标系统中，飞船向上移动。我们唯一需要做的另一件事就是改变飞船包裹其`x`和`y`坐标的坐标，以适应 WebGL 剪辑空间：

```cpp
if( ship_x >= 1.16 ) {
    ship_x = -1.16;
}

if( ship_y >= 1.21 ) {
    ship_y = -1.21;
}
```

现在我们有了所有的源代码，继续运行`emcc`来编译我们的新`webgl.html`文件。

```cpp
emcc webgl.c -o webgl.html --shell-file webgl_shell.html
```

一旦你编译了`webgl.html`，将其加载到 Web 浏览器中。它应该看起来像这样：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-gm-dev-wasm/img/bb758221-c27c-49c3-9aef-70052e0c0fff.png)

图 3.1：我们的 WebGL 应用程序的屏幕截图

重要的是要记住，应用程序必须从 Web 服务器上运行，或者使用`emrun`。如果你不从 Web 服务器上运行应用程序，或者使用`emrun`，当 JavaScript 粘合代码尝试下载 WASM 和数据文件时，你将会收到各种错误。你还应该知道，IIS 需要额外的配置才能为`.wasm`和`.data`文件扩展名设置正确的 MIME 类型。

现在我们在 WebGL 中完成了所有这些工作，下一章中，我将谈论如果一开始就使用 SDL，所有这些工作将会更容易。

# 总结

在这一章中，我们讨论了 WebGL 以及它如何提高网络游戏的性能。我向你介绍了 GLSL 着色器的概念，并讨论了顶点着色器和片段着色器，这两种着色器之间的区别，以及它们如何用于将几何图形和图像渲染到 HTML5 画布上。

我们还使用 WebGL 重新创建了我们在 2D 画布上创建的移动飞船。我们讨论了如何使用顶点几何来将 2D 图像渲染到 3D 画布上。我们还讨论了基于像素的 2D 画布坐标系统和 3D WebGL 坐标系统之间的区别。

WebGL 是一个广泛的主题，因此单独一章只能给出一个非常粗略的介绍。WebGL 是一个 3D 渲染空间，在这一章中，我刻意忽略了这一点，将其视为 2D 空间。你可以在我们所做的基础上进行扩展，但为了提高应用程序的性能，我们将来使用 WebAssembly SDL API 与 WebGL 进行所有交互。如果你想了解更多关于 WebGL 的知识，Packt 有大量专门致力于 WebGL 的图书可供查阅[`search.packtpub.com/?query=webgl`](https://search.packtpub.com/?query=webgl)。

在下一章中，我将教你 SDL 的基础知识，它是什么，以及它如何与 WebAssembly 一起工作。我们还将学习如何使用 SDL 将精灵渲染到 HTML5 画布上，对其进行动画处理，并在画布上移动它。
