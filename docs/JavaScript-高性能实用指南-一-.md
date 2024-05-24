# JavaScript 高性能实用指南（一）

> 原文：[`zh.annas-archive.org/md5/C818A725F2703F2B569E2EC2BCD4F774`](https://zh.annas-archive.org/md5/C818A725F2703F2B569E2EC2BCD4F774)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

今天的网络环境发生了巨大变化-不仅在创建 Web 应用程序方面，而且在创建服务器端应用程序方面也是如此。以 jQuery 和 Bootstrap 等 CSS 框架为主导的前端生态系统已经被具有响应性的完整应用程序所取代，这些应用程序可能被误认为是在桌面上运行的应用程序。

我们编写这些应用程序的语言也发生了戏剧性的变化。曾经是一团混乱的`var`和作用域问题已经变成了一种快速且易于编程的语言。JavaScript 不仅改变了我们编写前端的方式，还改变了后端编程的体验。

我们现在能够用我们前端使用的语言来编写服务器端应用程序。JavaScript 也现代化了，甚至可能通过 Node.js 推广了事件驱动系统。我们现在可以用 JavaScript 编写前端和后端的代码，甚至可能在两者之间共享我们生成的 JavaScript 文件。

然而，尽管应用程序的格局已经发生了变化，许多人已经转向了现代框架，比如 React 和 Vue.js 用于前端，Express 和 Sails 用于后端，但许多这些开发人员并不了解内部运作。虽然这展示了进入生态系统是多么简单，但也展示了我们如何不理解如何优化我们的代码库是多么容易。

本书专注于教授高性能 JavaScript。这不仅意味着快速执行速度，还意味着更低的内存占用。这意味着任何前端系统都能更快地到达用户手中，我们也能更快地启动我们的应用程序。除此之外，我们还有许多新技术推动了网络的发展，比如 Web Workers。

# 本书对象

本书适合那些对现代网络的最新功能感兴趣的人。除此之外，它也适合那些对减少内存成本并提高速度感兴趣的人。对计算机工作原理甚至 JavaScript 编译器工作原理感兴趣的人也会对本书内容感兴趣。最后，对于那些对 WebAssembly 感兴趣但不知道从何开始的人来说，这是学习基本知识的好起点。

# 本书内容

第一章，“网络高性能工具”，将介绍我们的应用程序可以运行的各种浏览器。我们还将介绍各种工具，帮助我们调试、分析，甚至运行临时代码来测试我们的 JavaScript 功能。

第二章，“不可变性与可变性-安全与速度之间的平衡”，将探讨可变/不可变状态的概念。我们将介绍何时何地使用每种状态。除此之外，我们还将介绍如何在拥有可变数据结构的同时创建不可变性的幻觉。

第三章，“原生之地-看看现代网络”，将介绍 JavaScript 的发展历程以及截至 ECMAScript 2020 的所有新功能。除此之外，我们还将探讨各种高级功能，比如柯里化和以函数式方式编写。

第四章，“实际例子-看看 Svelte 和原生”，将介绍一个相当新的框架叫做 Svelte。它将介绍这个编译成原生 JavaScript 的框架，并探讨它如何通过直观的框架实现闪电般快速的结果。

第五章，“切换上下文-无 DOM，不同的原生”，将介绍低级别的 Node.js 工作。这意味着我们将看看各种可用的模块。我们还将看看如何在没有额外库的情况下实现惊人的结果。

第六章，*消息传递-了解不同类型*，将介绍不同进程之间交流的不同方式。我们将涵盖未命名管道，命名管道，套接字，以及通过 TCP/UDP 进行传输。我们还将简要介绍 HTTP/2 和 HTTP/3。

第七章，*流-理解流和非阻塞 I/O*，将介绍流 API 以及如何利用它。我们将介绍每种类型的流以及每种流的用例。除此之外，我们还将实现一些实用的流，经过一些修改后，可以在其他项目中使用。

第八章，*数据格式-查看除 JSON 之外的不同数据类型*，将研究模式和无模式数据类型。我们将研究实施数据格式，然后看看流行的数据格式是如何运作的。

第九章，*实际示例-构建静态服务器*，将使用前面四章的概念构建一个静态站点生成器。虽然它可能没有 GatsbyJS 那么强大，但它将具有我们从静态站点生成器中期望的大多数功能。

第十章，*Workers-了解专用和共享工作者*，将回到前端，看看两种 Web Worker 类型。我们将利用这些来处理来自主线程的数据。除此之外，我们还将看看如何在工作者和主进程之间交流。

第十一章，*Service Workers-缓存和加速*，将介绍服务工作者和服务工作者的生命周期。除此之外，我们还将看看如何在渐进式 Web 应用程序中利用服务工作者的实际示例。

第十二章，*构建和部署完整的 Web 应用程序*，将使用 CircleCI 工具进行**持续集成**/**持续部署**（**CI**/**CD**）。我们将看到如何使用它来部署我们在第九章构建的 Web 应用程序，*实际示例-构建静态服务器*，到服务器上。我们甚至将在部署之前检查应用程序的一些安全性。

第十三章，*WebAssembly-简要了解 Web 上的本机代码*，将介绍这项相对较新的技术。我们将看到如何编写低级 WebAssembly 以及它在 Web 上的运行方式。然后，我们将把注意力转向为浏览器编写 C++。最后，我们将看看一个移植的应用程序以及背后的 WebAssembly。

# 为了充分利用本书

总的来说，运行大多数代码的要求是最低的。需要一台能够运行 Chrome、Node.js 和 C 编译器的计算机。我们将在本书的最后使用的 C 编译器将是 CMake。这些系统应该在所有现代操作系统上都能运行。

对于 Chrome 来说，拥有最新版本将是有帮助的，因为我们将利用一些提案阶段或 ECMAScript 2020 中的功能。我们正在使用最新的 LTS 版本的 Node.js（v12.16.1），并且避免使用 Node.js 13，因为它不会被提升为 LTS。除此之外，Windows 的命令行工具并不是很好，因此建议下载 Cmder，从[`cmder.net/`](https://cmder.net/)，以在 Windows 上拥有类似 Bash 的 shell。

最后，需要一个现代的集成开发环境或编辑器。我们将在整本书中使用 Visual Studio Code，但也可以使用许多其他替代方案，比如 Visual Studio、IntelliJ、Sublime Text 3 等。

| **书中涉及的软件/硬件** | **操作系统要求** |
| --- | --- |
| Svelte.js v3 | Windows 10/OSX/Linux |
| ECMAScript 2020 | Windows 10/OSX/Linux |
| Node.js v12.16.1 LTS | Windows 10/OSX/Linux |
| WebAssembly | Windows 10/OSX/Linux |

# 下载示例代码文件

您可以从[www.packt.com](http://www.packt.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，可以访问[www.packtpub.com/support](https://www.packtpub.com/support)注册，文件将直接发送到您的邮箱。

您可以按照以下步骤下载代码文件：

1.  在[www.packt.com](http://www.packt.com)登录或注册。

1.  选择支持选项卡。

1.  点击代码下载。

1.  在搜索框中输入书名，然后按照屏幕上的说明操作。

下载文件后，请确保使用最新版本的软件解压或提取文件夹：

+   Windows 系统使用 WinRAR/7-Zip

+   Mac 系统使用 Zipeg/iZip/UnRarX

+   Linux 系统使用 7-Zip/PeaZip

本书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Hands-On-High-Performance-Web-Development-with-JavaScript`](https://github.com/PacktPublishing/Hands-On-High-Performance-Web-Development-with-JavaScript)。如果代码有更新，将在现有的 GitHub 存储库中更新。

我们还有其他代码包，来自我们丰富的图书和视频目录，可在**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)** 上找到。去看看吧！

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 用户名。例如："这与`console.time`和`timeEnd`非常相似，但它应该展示生成器可用的内容。"

代码块设置如下：

```js
for(let i = 0; i < 100000; i++) {
    const j = Library.outerFun(true);
}
```

任何命令行输入或输出都是这样写的：

```js
> npm install what-the-pack
```

**粗体**：表示新术语、重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会以这种方式出现在文本中。例如："如果我们在 Windows 中按下*F12*打开 DevTools，我们可能会看到**Shader Editor**选项卡已经打开。"

警告或重要提示会显示为这样。提示和技巧会显示为这样。


# 第一章：网络高性能工具

JavaScript 已经成为网络的主要语言。它不需要额外的运行时，也不需要编译过程来运行 JavaScript 应用程序。任何用户都可以打开一个网络浏览器并开始在控制台中输入来学习这种语言。除此之外，语言和**文档对象模型**（**DOM**）也有许多进步。所有这些都为开发人员提供了一个丰富的环境来创造。

除此之外，我们可以将网络视为*一次构建，随处部署*的环境。在一个操作系统上运行的代码也将在另一个操作系统上运行。如果我们想要针对所有浏览器，可能需要进行一些调整，但它可以被视为*一次开发，随处部署*的平台。然而，所有这些都导致了应用程序变得臃肿，使用了昂贵的框架和不必要的 polyfill。大多数工作职位都需要这些框架，但有时我们不需要它们来创建丰富的应用程序。

本章重点介绍我们将用来帮助构建和分析高性能网络应用程序的工具。我们将研究不同的现代浏览器及其独特的贡献。然后我们将深入研究 Chrome 开发者工具。总的来说，我们将学到以下内容：

+   每个浏览器中嵌入的不同开发工具

+   深入了解以下 Chrome 工具：

+   性能选项卡

+   内存选项卡

+   渲染器选项卡

+   jsPerf 和代码基准测试

# 技术要求

本章的先决条件如下：

+   一个网络浏览器，最好是 Chrome。

+   编辑器；最好使用 VS Code。

+   JavaScript 的知识和一些 DOM API。

+   相关代码可以在[`github.com/PacktPublishing/Hands-On-High-Performance-Web-Development-with-JavaScript/tree/master/Chapter01`](https://github.com/PacktPublishing/Hands-On-High-Performance-Web-Development-with-JavaScript/tree/master/Chapter01)找到。

# 不同环境的开发工具

有四种被认为是现代浏览器的浏览器。它们是 Edge、Chrome、Firefox 和 Safari。这些浏览器遵守最新的标准，并且正在积极开发。我们将看看它们各自的发展情况以及一些独特的功能。

Internet Explorer 接近于终止其生命周期。浏览器只会进行关键的安全修复。新应用程序应该尽量淘汰这个浏览器，但如果仍有客户群在使用它，我们可能需要为其开发。在本书中，我们不会专注于为其提供 polyfill。

# Edge

微软的 Edge 浏览器是他们对现代网络的看法。借助 EdgeHTML 渲染器和 Chakra JavaScript 引擎，在许多基准测试中表现良好。虽然 Chakra 引擎与 Chrome 或 Firefox 有不同的优化，但从纯 JavaScript 的角度来看，这是一个有趣的浏览器。

在撰写本书时，微软正在将 Edge 的渲染引擎更改为 Chromium 系统。这对 Web 开发人员有许多影响。首先，这意味着更多的浏览器将运行 Chromium 系统。这意味着在跨浏览器开发方面要担心的事情会减少。虽然需要支持当前形式的 Edge，但它可能会在未来一年内消失。

在功能方面，Edge 相对于其他浏览器来说比较轻。如果我们需要对其进行任何类型的性能测试，最好的选择是使用 jsPerf 或其他工具来分析代码，而不是使用内置工具。此外，Chakra 引擎利用不同的优化技术，因此在 Chrome 或 Safari 上有效的代码可能对 Edge 来说不够优化。在 Windows 上打开开发者工具，我们可以按下*F12*。这将弹出通常的控制台对话框，如下所示：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-hiperf/img/03e0519d-a88e-4fd9-8d77-7084d4d20dac.png)

我们不会介绍 Edge 的任何有趣功能，因为他们的开发工具中的大多数，如果不是全部，功能与其他浏览器中的功能相同。

基于 Chromium 的最新 Edge 浏览器将支持 OS X 用户，这意味着与 Windows 或 Linux 相比，OS X 用户进行跨浏览器开发将变得更加容易。

# Safari

苹果的 Safari 浏览器基于 WebKit 渲染引擎和 JavaScriptCore 引擎。WebKit 引擎是 Chrome 的 Blink 引擎的基础，JavaScriptCore 引擎在 OS X 操作系统的一些地方使用。关于 Safari 的一个有趣的点是，如果我们运行 Windows 或 Linux，我们将无法直接访问它。

要访问 Safari，我们需要利用在线服务。BrowserStack 或 LambdaTest 以及其他一些服务都可以为我们完成这项工作。有了这些服务中的任何一个，我们现在可以访问我们可能没有的浏览器。感谢 LambdaTest，我们将利用他们的免费服务简要查看 Safari。

再次，我们会注意到 Safari 浏览器开发工具并不是太多。所有这些工具在其他浏览器中也都可用，并且通常在这些其他浏览器中更加强大。熟悉每个界面可以帮助在特定浏览器中进行调试，但不需要花费太多时间查看那些没有任何特定功能的浏览器。

# Firefox

Mozilla 的 Firefox 使用了 SpiderMonkey JavaScript 引擎和增强的 Gecko 引擎。当他们将他们的项目 Servo 代码的部分添加到 Gecko 引擎中时，Gecko 引擎得到了一些很好的改进，从而提供了一个不错的多线程渲染器。Mozilla 一直处于最新 Web 技术的前沿。他们是最早实现 WebGL 的之一，他们也是最早实现 WebAssembly 和**WebAssembly System Interface**（**WASI**）标准的之一。

接下来是关于着色器和着色器语言**OpenGL Shading Language**（**GLSL**）的一些技术讨论。建议您继续阅读以了解更多信息，但对于那些迷失方向的人来说，访问文档以了解更多关于这项技术的信息可能会有所帮助，网址为[`developer.mozilla.org/en-US/docs/Games/Techniques/3D_on_the_web/GLSL_Shaders`](https://developer.mozilla.org/en-US/docs/Games/Techniques/3D_on_the_web/GLSL_Shaders)。

如果我们在 Windows 中打开 DevTools，按*F12*，我们可能会看到**Shader Editor**选项卡。如果没有，可以转到右侧的三个点菜单，打开设置。在左侧，应该有一个带有默认开发者工具标题的复选框列表。继续选择**Shader Editor**选项。现在，如果我们进入此选项卡，应该会看到以下内容：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-hiperf/img/0912e619-dc8b-4878-8f6c-b4f2902ad4c4.png)

该选项卡正在请求画布上下文。基本上，该工具正在寻找一些项目：

+   一个画布元素

+   一个启用了 3D 的上下文

+   顶点和片段着色器

我们仓库中的一个名为`shader_editor.html`的文件包含了设置画布和着色器的必要代码，这样我们就可以利用着色器编辑器。这些着色器是在 Web 上以编程方式使用 GPU 的方法。它们利用了一个名为 OpenGL ES 3.0 的 OpenGL 规范的版本。这使我们能够使用该规范中的几乎所有内容，特别是顶点和片段着色器。

要使用这些着色器进行编程，我们使用一种称为**GL Shading Language**（**GLSL**）的语言。这是一种类似于 C 的语言，具有许多特定于它的功能，例如 swizzling。Swizzling 是利用矢量组件（最多四个）并以我们选择的任何形状或形式组合它们的能力。这看起来像下面这样的例子：

```js
vec2 item = vec2(1.0, 1.0);
vec4 other_item = item.xyxx;
```

这创建了一个四元素向量，并将*x*、*y*、*z*和*w*分量分别设置为两元素向量中的`x`、`y`、`x`和`x`项。命名可能需要一段时间才能习惯，但它确实使某些事情变得更容易。如上所示的一个例子，我们需要从两元素向量中创建一个四元素向量。在基本的 JavaScript 中，我们需要执行以下操作：

```js
const item = [1.0, 1.0];
const other_item = [item[0], item[1], item[0], item[0]];
```

我们可以利用 swizzling 的简写语法，而不是编写前面的内容。GLSL 系统中还有其他功能，我们将在后面的章节中进行介绍，但这应该让我们对这些语言有所了解。

现在，如果我们打开`shader_editor.html`文件并重新加载页面，我们应该会看到一个白色的页面。如果我们查看着色器编辑器，我们可以看到右侧我们正在将一个名为`gl_FragColor`的变量设置为一个四元素向量，其中所有元素都设置为`1.0`。如果我们将它设置为`vec4(0.0, 0.0, 0.0, 1.0)`会发生什么？我们现在应该在左上角看到一个黑色的框。这展示了向量的四个分量是颜色的红色、绿色、蓝色和 alpha 分量，范围从`0.0`到`1.0`，就像 CSS 的`rgba`系统一样。

除了单一的纯色之外，还有其他颜色组合吗？每个着色器都带有一些预先定义的全局变量。其中之一，在片段着色器中，称为`gl_FragCoord`。这是窗口空间中左下角的坐标，范围从`0.0`到`1.0`（这里应该有一个主题，说明在 GLSL 中哪些值被认为是好的）。如果我们将四元素向量的*x*元素设置为`gl_FragCoord`的*x*元素，将*y*元素设置为`gl_FragCoord`的*y*元素，我们应该会得到一个简单的白色框，但左侧和底部各有一个单像素的边框。

除了 swizzling 和全局变量，我们还可以在这些着色器中使用其他数学函数。让我们将这些*x*和*y*元素包装在`sin`函数中。如果我们这样做，我们应该在屏幕上得到一个漂亮的格子图案。这应该给出片段着色器实际在做什么的提示。它试图根据各种输入在 3D 空间中绘制该位置，其中一个输入是来自顶点着色器的位置。

然后它试图绘制构成我们用顶点着色器声明的网格内部的每个像素。此外，这些片段是同时计算的（或者尽可能多地由显卡来计算），因此这是一个高度并行化的操作。

这应该给我们一个很好的窥视 GLSL 编程世界的机会，以及 GLSL 语言除了 3D 工作之外可以为我们提供的可能性。现在，我们可以更多地尝试这些概念，并转向最后一个浏览器 Chrome。

# Chrome

谷歌的 Chrome 浏览器使用 Blink 引擎，并使用著名的 V8 JavaScript 运行时。这是 Node.js 内部使用的相同运行时，因此熟悉开发工具将在很多方面帮助我们。

Chrome 一直处于网络技术的前沿，就像 Firefox 一样。他们是第一个实现各种想法的人，比如 QUIC 协议，HTTP/3 标准就是基于它。他们创建了原生插件接口（NaCL），帮助创建了 WebAssembly 的标准。他们甚至是使 Web 应用程序开始变得更像本地应用程序的先驱，通过提供蓝牙、游戏手柄和通知等 API。

我们将特别关注 Chrome 附带的 Lighthouse 功能。Lighthouse 功能可以从 Chrome 浏览器的**审计**选项卡中访问。一旦我们在这里，我们可以使用各种设置来设置我们的审计：

+   首先，我们可以根据页面是在移动设备上运行还是在桌面上运行来审计我们的页面。然后我们可以审计我们网站的各种功能。

+   如果我们正在开发渐进式 Web 应用程序，我们可能会决定不需要 SEO。另一方面，如果我们正在开发营销网站，我们可能会决定不需要渐进式 Web 应用程序检查。我们可以模拟受限连接。

+   最后，我们可以从干净的存储开始。如果我们的应用程序利用了内置浏览器缓存系统，比如会话存储或本地存储，这将特别有帮助。

举例来说，让我们看看外部网站，并查看它在审核应用程序中的表现如何。我们将查看的网站是亚马逊，位于[`www.amazon.com`](https://www.amazon.com)。这个网站应该是我们要遵循的一个很好的例子。我们将把它作为桌面应用程序来查看，不进行任何限制。如果我们运行审核，我们应该得到类似以下的结果：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-hiperf/img/e41e6600-bb25-4f3d-a38c-8cf5ab197fe0.png)

正如我们所看到的，主页在性能和最佳实践方面表现良好，但 Chrome 警告我们有关可访问性和 SEO 性能。在可访问性方面，似乎图片没有`alt`属性，这意味着屏幕阅读器将无法正常工作。此外，似乎开发人员的`tabindexes`高于 0，可能导致选项卡顺序不遵循正常页面流程。

如果我们想要设置自己的系统进行测试，我们需要在本地托管我们的页面。有许多出色的静态站点托管解决方案（我们将在本书后面构建一个），但如果我们需要托管内容，最简单的方法之一是下载 Node.js 并安装`static-server`模块。我们将在后面深入介绍如何启动和运行 Node.js，并如何创建我们自己的服务器，但目前这是最好的选择。

我们已经看过了主要的现代 Web 浏览器，我们应该瞄准它们。它们每个都有自己的能力和限制，这意味着我们应该在所有这些浏览器上测试我们的应用程序。然而，本书的重点将是 Chrome 浏览器及其附带的开发工具。由于 Node.js 是使用 V8 引擎构建的，并且许多其他新浏览器都是基于 Chromium 引擎构建的，比如 Brave，因此利用这一点是有意义的。我们将详细介绍 Chrome 开发工具给我们的三个特定功能。

# Chrome - 深入了解性能选项卡

除了 Firefox 内部的一些工具外，Chrome 已经成为用户和开发人员首选的广泛使用的浏览器。对于开发人员来说，这在很大程度上要归功于其出色的开发工具。接下来的部分将着眼于设计 Web 应用程序时对任何开发人员都重要的三个关键工具。我们将从性能工具开始。

这个工具允许我们在应用程序运行时运行性能测试。如果我们想要查看我们的应用程序在执行某些操作时的行为，这将非常有用。例如，我们可以分析我们的应用程序的启动状态，并查看可能的瓶颈位置。或者，当用户交互发生时，比如在表单上提交时，我们可以看到我们经过的调用层次结构来发布信息并将其返回给用户。除此之外，它甚至可以帮助我们分析在使用 Web Worker 时代码的性能以及我们的应用程序上下文之间的数据传输方式。

以下是撰写时最新版本 Chrome 的**性能**选项卡的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-hiperf/img/55c88e55-444a-4c81-99fe-a4fd32b2b6ad.png)

有几个部分是我们感兴趣的。首先，我们开发工具标签下面的工具栏是我们的主要工具栏。左边的两个按钮可能是最重要的，记录和重新加载记录工具。这些将允许我们对我们的应用程序进行分析，并查看在我们的代码的关键时刻发生了什么。在这些之后是选择工具，用于获取之前可能运行过的配置文件。

接下来是两个选项，我通常都会随时打开：

+   首先，当应用程序发生关键事件时，屏幕截图功能会为我们抓取屏幕截图，比如内存增长或添加新文档。

+   下一个选项是内存分析器。它将告诉我们当前消耗了多少内存。

最后，还有删除操作。正如许多人所推测的那样，这将删除您当前正在使用的配置文件。

让我们在一个简单的测试应用程序上进行测试运行。从存储库中获取`chrome_performance.html`文件。这个文件展示了一个标准的待办事项应用程序，但它是用一个非常基本的模板系统和没有库来编写的。在本书中，不使用库将成为标准。

如果我们运行这个应用程序并从重新加载运行性能测试，我们应该得到以下结果：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-hiperf/img/7ca12819-18a5-4053-8a1e-9e9a4cdf5813.png)

页面加载几乎是瞬间完成的，但我们仍然可以在这里得到一些有用的信息。从上到下，我们得到以下信息：

+   一系列图片的时间轴，以及 FPS、CPU 使用率、网络使用率和堆使用率的图表。

+   不同统计数据的折线图，比如 JavaScript 堆使用、文档数量、文档节点数量、监听器数量以及我们正在使用的 GPU 内存。

+   最后，我们得到一个分栏部分，其中包含有关时间和时间分配的所有信息。

确保让分析器自行运行。在页面上的所有操作完成后，它应该会自动关闭。这应该确保您尽可能接近正确的应用程序运行信息。分析器可能需要运行几次才能得到准确的图片。内部垃圾收集器正在努力保留一些对象，以便稍后重用它们，因此获得准确的图片意味着看到低点是最有可能的应用程序基线，随后是**垃圾收集**（**GC**）。一个很好的指标是看到主要的 GC 和/或 DOM GC。这意味着我们又重新开始了。

在这个基本示例中，我们可以看到大部分时间都花在了 HTML 上。如果我们打开它，我们会看到评估我们的脚本占用了大部分时间。由于大部分时间都花在了评估脚本和将我们的模板化待办事项应用程序插入 DOM 中，让我们看看如果没有这种行为，统计数据会是什么样子。

注释掉除了我们的基本标签之外的所有内容，比如`html`、`head`和`body`标签。这次运行有一些有趣的元素。首先，文档的数量应该保持不变或减少。这将在后面提到。其次，节点的数量急剧减少，可能降到了大约 12 个。我们的 JavaScript 堆略微减少，监听器的数量显著减少。

让我们再加入一个`div`标签。文档、堆空间和监听器的数量保持不变，但节点的数量再次增加。让我们再添加另一个`div`元素，看看它对节点数量的影响。它应该增加四个。最后一次，让我们再添加另一个`div`元素。同样，我们应该注意到增加了四个 DOM 节点。这给了我们一些线索，了解 DOM 的运行方式以及如何确保我们的分析是正确的。

首先，节点的数量并不直接等于屏幕上的 DOM 元素数量。DOM 节点由几个基本节点组成。例如，如果我们添加一个`input`元素，我们可能会注意到节点的数量增加了超过四个。其次，可用的文档数量几乎总是高于单个文档。

虽然一些行为可以归因于性能分析器中的错误，但它也展示了幕后发生的事情，这些事情对开发人员是不可见的。当我们触及内存选项卡并查看调用层次时，我们会看到内部系统正在创建和销毁开发人员无法完全控制的节点，以及开发人员看不到但是浏览器优化的文档。

让我们再次添加我们的代码块，回到原始文档。如果需要的话，继续回滚 Git 分支（如果这是从存储库中拉取的），然后再次运行性能分析器。我们特别想查看调用树选项卡和解析 HTML 下拉菜单。应该有一个类似以下的层次结构：`解析 HTML > 评估脚本 > (匿名) > runTemplate > runTemplate`。

让我们改变代码，将我们的内部`for`循环转换为一个数组`map`函数，就像这样：

```js
const tempFun = runTemplate.bind(null, loopTemp);
loopEls = data.items.map(tempFun);
```

注释掉`loopEls`数组初始化和`for`循环。再次运行性能分析器，让我们看看这个调用堆栈是什么样子。我们会注意到，即使我们将其绑定到一个名为`tempFun`的新函数，它仍然会将`runTemplate`函数本身作为自己进行性能分析。这是我们在查看调用层次时必须牢记的另一个要点。我们可能会绑定、调用或应用函数，但开发工具仍会尝试维护函数的原始定义。

最后，让我们向我们的数据列表添加很多项目，看看这对我们的分析有什么影响。将以下代码放在数据部分下面：

```js
for(let i = 0; i < 10000; i++) {
    data.items.push({text : `Another item ${i}`});
}
```

现在我们应该得到一个与之前不同的画面：

+   首先，我们的时间几乎平均分配在 GPU 的布局和脚本的评估之间，现在看起来我们大部分时间都在运行布局引擎。这是有道理的，因为我们在脚本的末尾添加每个项目时，我们强制 DOM 来计算布局。

+   其次，评估脚本部分现在应该包含比之前简单的调用层次更多的部分。

+   我们还将开始看到函数的不同部分在性能分析器中注册。这表明，如果某些东西低于某个阈值（这实际上取决于机器甚至 Chrome 的版本），它将不会显示函数被认为足够重要以进行性能分析。

垃圾回收是环境清理我们不再使用的未使用项目的过程。由于 JavaScript 是一个内存管理环境，这意味着开发人员不像在 C++和 Rust 等语言中那样自己分配/释放内存，我们有一个程序来为我们做这些。特别是 V8 有两个 GC，一个叫做**Scavenger**的次要 GC，一个叫做**Mark-Compact**的主要 GC。

清道夫会检查新分配的对象，看看是否有任何准备清理的对象。大多数时候，我们的代码将被编写为在短时间内使用大量临时变量。这意味着它们在初始化变量的几个语句之后将不再需要。看下面的代码片段：

```js
const markedEls = [];
for(let i = 0; i < 10000; i++) {
    const obj = els[i];
    if( obj.marked ) {
        markedEls.push(Object.assign({}, obj));
    }
}
```

在这个假设的例子中，我们想获取对象并在它们标记为某个过程时对它们进行克隆。我们收集我们想要的对象，其余的现在没有用了。清道夫会注意到几件事情。首先，它似乎我们不再使用旧列表，所以它会自动收集这些内存。其次，它会注意到我们有一堆未使用的对象指针（除了 JavaScript 中的原始类型，其他都是按引用传递的），它可以清理这些。

这是一个快速的过程，它要么交织在我们的运行时中，称为停止-继续垃圾回收，要么会在与我们的代码并行运行，这意味着它将在另一个执行线程中的确切时间运行。

标记-压缩垃圾收集运行时间更长，但收集的内存更多。它将遍历当前仍在堆中的物品列表，并查看这些物品是否有零引用。如果没有更多的引用，它将从堆中删除这些对象。然后它将尝试压缩堆中的所有空隙，这样我们就不会有高度碎片化的内存。这对于诸如数组之类的东西特别有用。

数组在内存中是连续的，所以如果 V8 引擎能找到足够大的空间来放置数组，它就会放在那里。否则，它可能需要扩展堆并为我们的运行时分配更多内存。这就是标记-压缩 GC 试图防止发生的事情。

虽然不需要完全了解垃圾收集器的工作方式才能编写高性能的 JavaScript，但对它有一个良好的理解将有助于编写不仅易于阅读而且在你使用的环境中表现良好的代码。

如果你想了解更多关于 V8 垃圾收集器的信息，我建议你去这个网站[`v8.dev/blog`](https://v8.dev/blog)。看到 V8 引擎是如何工作的，以及新的优化如何导致某些编码风格比过去更高效，比如数组的 map 函数，总是很有趣。

我们没有详细介绍性能选项卡，但这应该给出了如何在测试代码时利用它的一个很好的概述。它还应该展示了 Chrome 的一些内部工作和垃圾收集器。

在下一节关于内存的讨论中将会有更多内容，但强烈建议对当前的代码库运行一些测试，并注意在运行这些应用程序时性能如何。

# Chrome-深入了解内存选项卡

当我们从性能部分转移到内存部分时，我们将重新审视性能工具中的许多概念。V8 引擎为开发既在 CPU 使用效率方面又在内存使用效率方面高效的应用程序提供了大量支持。测试内存使用情况以及内存分配位置的一个很好的方法是内存分析工具。

在撰写本文时的最新版本的 Chrome 中，内存分析器显示如下：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-hiperf/img/7e5b2bb5-9bfe-447f-aa66-0109c9e6bcc9.png)

我们主要将关注被选中的第一个选项，即堆快照工具。时间轴上的分配仪表盘是可视化和回放堆是如何被分配的以及哪些对象导致分配发生的一个很好的方法。最后，分配抽样工具会定期进行快照，而不是提供连续的查看，使其更轻便，并能够在进行繁重操作时执行内存测试。

堆快照工具将允许我们看到堆上内存的分配位置。从我们之前的例子中，让我们运行堆快照工具（如果你还没有注释掉分配了 10,000 个 DOM 节点的`for`循环，现在注释掉它）。快照运行后，你应该会得到一个左侧有树形视图的表格。让我们去寻找在控制台中能够访问到的*global*物品之一。

我们目前按它们是什么或者它们属于谁来分组物品。如果我们打开（闭包）列表，我们可以找到`runTemplate()`函数被保存在那里。如果我们进入（字符串）列表，我们可以找到用来创建我们列表的字符串。一个可能提出的问题是为什么一些这些物品仍然被保存在堆上，即使我们不再需要它们。嗯，这涉及到垃圾收集器的工作方式以及谁当前正在引用这些物品。

查看当前存储在内存中的列表项。如果您点击每个列表项，它会显示它们被`loopEls`引用。如果我们回到我们的代码，可以注意到我们使用的唯一一行代码`loopEls`在以下位置：

```js
const tempFun = runTemplate.bind(null, loopTemp);
loopEls = data.items.map(tempFun);
```

将其移除并将基本的`for`循环放回。运行堆快照并返回(strings)部分。这些字符串不再存在！让我们再次更改代码，使用`map`函数，但这次不使用 bind 函数创建新函数。代码应该如下所示：

```js
const loopEls = data.items.map((item) => {
    return runTemplate(loopTemp, item);
});
```

再次更改代码后运行堆快照，我们会注意到这些字符串不再存在。敏锐的读者会注意到第一次运行中代码存在错误；`loopEls`变量没有添加任何变量类型前缀。这导致`loopEls`变量进入全局范围，这意味着垃圾收集器无法收集它，因为垃圾收集器认为该变量仍在使用中。

现在，如果我们把注意力转向列表中的第一项，我们应该观察到整个模板字符串仍然被保留。如果我们点击该元素，我们会注意到它被`template`变量所持有。然而，我们可以说，由于该变量是一个常量，它应该自动被收集。再次说明，V8 编译器不知道这一点，已经将它放在全局范围内。

我们可以通过两种方式解决这个问题。首先，我们可以使用老式技术，并将其包装在**立即调用的函数表达式**（**IIFE**）中，如下所示：

```js
(function() { })();
```

或者，如果我们愿意并且正在为支持它的浏览器编写我们的应用程序，我们可以将脚本类型更改为`module`类型。这两种解决方案都确保我们的代码现在不再是全局范围的。让我们将整个代码库放在 IIFE 中，因为这在所有浏览器中都受支持。如果我们运行堆转储，我们会看到那个字符串不再存在。

最后，应该触及的最后一个领域是堆空间的工作集和实际分配的数量。在 HTML 文件的顶部添加以下行：

```js
<script type="text/javascript" src="./fake_library.js"></script>
```

这是一个简单的文件，它将自身添加到窗口以充当库。然后，我们将测试两种情况。首先，运行以下代码：

```js
for(let i = 0; i < 100000; i++) {
    const j = Library.outerFun(true);
    const k = Library.outerFun(true);
    const l = Library.outerFun(true);
    const m = Library.outerFun(true);
    const n = Library.outerFun(true);
}
```

现在，转到性能部分，查看显示的两个数字。如果需要，可以点击垃圾桶。这会导致主要的垃圾收集器运行。应该注意左边的数字是当前使用的，右边的数字是已分配的。这意味着 V8 引擎为堆分配了大约 6-6.5 MB 的空间。

现在，以类似的方式运行代码，但让我们将每个运行分解成它们自己的循环，如下所示：

```js
for(let i = 0; i < 100000; i++) {
    const j = Library.outerFun(true);
}
```

再次检查性能选项卡。内存应该在 7 MB 左右。点击垃圾桶，它应该降到 5.8 MB 左右，或者接近基线堆应该在的位置。这给我们展示了什么？由于它必须为第一个`for`循环中的每个变量分配项目，它必须增加其堆空间。即使它只运行了一次，次要垃圾收集器应该已经收集了它，但由于垃圾收集器内置的启发式，它将保留该堆空间。由于我们决定这样做，垃圾收集器将保留更多的堆内存，因为我们很可能会在短期内重复这种行为。

现在，对于第二组代码，我们决定使用一堆`for`循环，每次只分配一个变量。虽然这可能会慢一些，V8 看到我们只分配了小块空间，因此可以减少主堆的大小，因为我们很可能会在不久的将来保持相同的行为。V8 系统内置了许多启发式规则，并且它会尝试根据我们过去的行为来猜测我们将要做什么。堆分配器可以帮助我们了解 V8 编译器将要做什么，以及我们的编码模式在内存使用方面最像什么。

继续玩内存标签，并添加代码。看看流行的库（尝试保持它们小，以便跟踪内存分配），注意它们决定如何编写代码以及它如何导致堆分配器在内存中保留对象，甚至保持更大的堆大小。

通常情况下，编写小函数有很多好处，但编写做一件事情非常出色的小函数对于垃圾收集器也非常有益。它将根据编码人员编写这些小函数的事实来制定启发式规则，并减少总体堆空间。这反过来会导致应用程序的内存占用也减少。请记住，我们的内存使用情况不是工作集大小（左侧数字），而是总堆空间（右侧数字）。

# Chrome-深入了解渲染标签

我们将在开发者工具中查看的最后一个部分将是渲染部分。这通常不是一个默认可用的标签。在工具栏中，您会注意到关闭按钮旁边有一个三点按钮。点击它，转到更多工具，然后点击渲染选项。

现在应该有一个标签项，靠近控制台标签，看起来像下面这样：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-hiperf/img/070e6696-33c3-4f22-95e2-bdc511c9e190.png)

这个标签可以展示一些我们在开发应用程序时感兴趣的项目：

+   首先，在开发一个将有大量数据或大量事件的应用程序时，建议打开 FPS 计量器。这不仅可以让我们知道我们的 GPU 是否被利用，还可以告诉我们是否由于不断重绘而丢失帧数。

+   其次，如果我们正在开发一个有大量滚动的应用程序（考虑无限滚动的应用程序），那么我们将希望打开滚动性能问题部分。这可以通知我们，如果我们的应用程序中有一个或多个项目可能会导致滚动体验不流畅。

+   最后，绘制闪烁选项非常适合在我们的应用程序中有大量动态内容时使用。当发生绘制事件时，它会闪烁，并突出显示必须重新绘制的部分。

我们将通过一个应用程序，这个应用程序将会对大多数这些设置造成问题，并看看我们如何提高性能以改善用户体验。打开以下文件：`chrome_rendering.html`。

我们应该看到左上角有一个方框在变换颜色。如果我们打开**绘制闪烁**选项，现在每当方框颜色改变时，我们应该看到一个绿色方框出现。

这是有道理的。每次重新着色时，这意味着渲染器必须重新绘制该位置。现在取消以下行的注释：

```js
let appendCount = 0;
const append = function() {
    if( appendCount >= 100 ) {
        return clearInterval(append);
    }
    const temp = document.createElement('p');
    temp.textContent = `We are element ${appendCount}`;
    appendEl.appendChild(temp);
    appendCount += 1;
};
setInterval(append, 1000);
```

我们应该看到大约每隔 1 秒添加一个元素。有几件事情很有趣。首先，我们仍然看到每秒或更长时间自行着色的框被重新绘制。但是，除此之外，我们会注意到滚动条也在重新绘制自己。这意味着滚动条是渲染表面的一部分（有些人可能知道这一点，因为你可以用 CSS 来定位滚动条）。但同样有趣的是，当每个元素被添加时，它不必重新绘制整个父元素；它只在添加子元素的地方进行绘制。

那么，一个很好的问题是：如果我们在文档中添加一个元素会发生什么？注释掉正在改变 DOM 的代码行，并取消注释以下代码行以查看其效果：

```js
setTimeout(() => {
    const prependElement = document.createElement('p');
    prependElement.textContent = 'we are being prepended to the entire  
     DOM';
    document.body.prepend(prependElement);
}, 5000);
```

我们可以看到，在文档的生命周期中大约五秒钟后，我们添加的元素和那个红色框都被重新绘制了。这是有道理的。Chrome 必须重新绘制任何发生变化的东西。就我们的窗口外观而言，这意味着它必须改变框的位置，并添加我们在顶部添加的文本，导致两个项目都被重新绘制。

现在，我们可以看到一个有趣的事情，那就是如果我们用 CSS 将元素绝对定位会发生什么。这意味着，就我们所看到的而言，只有矩形的顶部部分和我们的文本元素需要重新绘制。但是，如果我们通过将位置设置为绝对来做到这一点，我们仍然会看到 Chrome 不得不重新绘制两个元素。

即使我们将`document.body.prepend`改为`document.body.append`，它仍然会同时绘制两个对象。Chrome 必须这样做，因为框是一个 DOM 对象。它无法只重绘对象的部分；它必须重绘整个对象。

一个要记住的好事是，当改变文档中的某些内容时，它会导致重新布局或重绘吗？添加一个列表项是否也会导致其他元素移动、改变颜色等？如果是，我们可能需要重新考虑我们的内容层次结构，以确保我们在文档中引起最少的重绘。

关于绘画的最后一点。我们应该看看画布元素是如何工作的。画布元素允许我们通过 2D 渲染上下文或 WebGL 上下文创建 2D 和 3D 图像。我们将专门关注 2D 渲染上下文，但应该注意这些规则也适用于 WebGL 上下文。

继续注释掉我们迄今为止添加的所有代码，并取消注释以下代码行：

```js
const context = canvasEl.getContext('2d');
context.fillStyle = 'green';
context.fillRect(10, 10, 10, 10);
context.fillStyle = 'red';
context.fillRect(20, 20, 10, 10);
setTimeout(() => {
    context.fillStyle = 'green';
    context.fillRect(30, 30, 10, 10);
}, 2000);
```

大约两秒后，我们应该看到一个绿色框被添加到我们小的对角线方块组中。这种绘画方式有趣的地方在于它只显示了对那个小绿色方块的重新绘制。让我们注释掉那段代码，并添加以下代码：

```js
const fillStyles = ['green', 'red'];
const numOfRunsX = 15;
const numOfRunsY = 10;
const totalRuns = numOfRunsX * numOfRunsY;
let currX = 0;
let currY = 0;
let count = 0;
const paint = function() {
    context.fillStyle = fillStyles[count % 2];
    context.fillRect(currX, currY, 10, 10);
    if(!currX ) {
        currY += 10;
    }
    if( count === totalRuns ) {
        clearInterval(paint);
    }
}
setInterval(paint, 1000);
```

大约每隔 1 秒，我们会看到它真正只在我们指定的位置进行重新绘制。这对于需要不断改变页面上的信息的应用程序可能会产生重大影响。如果我们发现需要不断更新某些内容，实际上在画布中完成可能比在 DOM 中更好。虽然画布 API 可能不适合成为一个丰富的环境，但有一些库可以帮助解决这个问题。

并不是每个应用都需要画布的重绘能力，大多数应用都不需要。然而，我们在本书中讨论的每一种技术都不会解决应用程序中发现的 100%的问题。其中一个问题是重绘问题，这可以通过基于画布的解决方案来解决。画布特别适用于绘图和基于网格的应用程序。

现在，我们将看一下滚动选项。当我们有一个很长的项目列表时，这可以帮助我们。这可能是在树视图中，在无限滚动应用程序中，甚至在基于网格的应用程序中。在某些时候，由于尝试一次渲染数千个元素，我们将遇到严重的减速问题。

首先，让我们使用以下代码将 1,000,000 个段落元素渲染到我们的应用程序中：

```js
for(let i = 0; i < 1000000; i++) {
    const temp = document.createElement('p');
    temp.textContent = `We are element ${i}`;
    appendEl.appendChild(temp);
}
```

虽然这可能看起来不像一个真实的场景，但它展示了如果我们必须立即将所有内容添加到 DOM 中，无限加载的应用程序将会变得不可行。那么我们该如何处理这种情况呢？我们将使用一种称为延迟渲染的东西。基本上，我们将把所有对象保存在内存中（在这种情况下；对于其他用例，我们将不断地为更多数据进行 REST 请求），并且我们将按照它们应该出现在屏幕上的顺序添加它们。我们需要一些代码来实现这一点。

以下示例绝不是实现延迟渲染的一种可靠方式。与本书中的大多数代码一样，它采用了一个简单的视图来展示一个观点。它可以很容易地进行扩展，以创建一个延迟渲染的真实系统，但这不是应该被复制和粘贴的东西。

开始延迟渲染的一个好方法是知道我们将拥有多少元素，或者至少想要在我们的列表中展示多少元素。为此，我们将使用 460 像素的高度。除此之外，我们将设置我们的列表元素具有 5 像素的填充，并且高度为 12 像素，底部有 1 像素的边框。这意味着每个元素的总高度为 23 像素。这也意味着一次可以看到 20 个元素（460 / 23）。

接下来，我们通过将我们拥有的项目数量乘以每个项目的高度来设置列表的高度。这可以在以下代码中看到：

```js
list.style.height = `${itemHeight * items.length}px`;
```

现在，我们需要保存我们当前所在的索引（屏幕上当前的 20 个项目），并在发生滚动事件时进行测量。如果我们注意到我们在阈值以上，我们就会移动到一个新的索引，并重置我们的列表以保存那组 20 个元素。最后，我们将无序列表的顶部填充设置为列表的总高度减去我们已经滚动的部分。

所有这些都可以在以下代码中看到：

```js
const checkForNewIndex = function(loc) {
    let tIndex = Math.floor(Math.abs(loc) / ( itemHeight * numItemsOnScreen 
     ));
    if( tIndex !== currIndex ) {
        currIndex = tIndex;
        const fragment = document.createDocumentFragment();
        fragment.append(...items.slice(currIndex * numItemsOnScreen, 
         (currIndex + 2) * numItemsOnScreen));
        list.style.paddingTop = `${currIndex * containerHeight}px`;
        list.style.height = `${(itemHeight * items.length) - (currIndex * 
         containerHeight)}px`;
        list.innerHTML = '';
        list.appendChild(fragment);
    }
}
```

现在我们拥有了所有这些，我们把这个函数放在什么地方呢？嗯，既然我们在滚动，逻辑上来说，把它放在列表的滚动处理程序中是有意义的。让我们用以下代码来做到这一点：

```js
list.onwheel = function(ev) {
    checkForNewIndex(list.getBoundingClientRect().y);
}
```

现在，让我们打开**滚动性能问题**选项。如果我们重新加载页面，我们会注意到它正在突出显示我们的列表，并声明`mousewheel`事件可能成为潜在的瓶颈。这是有道理的。Chrome 注意到我们在每次滚动事件上附加了一个非平凡的代码片段，因此它向我们显示我们可能会有问题。

现在，如果我们在常规桌面上，很可能不会有任何问题，但是如果我们添加以下代码，我们可以很容易地看到 Chrome 试图告诉我们的内容：

```js
const start = Date.now();
while( Date.now() < start + 1000 ) {; }
```

有了这段代码，我们可以看到滚动时出现了卡顿。既然我们现在能看到卡顿，并且它可能成为滚动的潜在瓶颈，下一个最佳选择是什么？将其放入`setInterval`中，使用`requestAnimationFrame`，甚至使用`requestIdleCallback`，最后一个是最不理想的解决方案。

渲染选项卡可以帮助解决应用程序中可能出现的许多问题，并且应该成为开发人员经常使用的工具，以找出是什么导致了应用程序的卡顿或性能问题。

这三个选项卡可以帮助诊断大多数问题，并且在开发应用程序时应该经常使用。

# jsPerf 和基准测试

我们已经来到了关于网络高性能的最后一节，以及我们如何轻松评估我们的应用程序是否以最佳效率运行。然而，有时我们会想要真正进行基准测试，即使这可能不会给出最好的结果。jsPerf 就是这样的工具之一。

创建 jsPerf 测试时必须非常小心。首先，我们可能会遇到浏览器进行的优化，这可能会使结果偏向于某种实现而不是另一种。接下来，我们必须确保在多个浏览器中运行这些测试。如前一节所述，每个浏览器都运行不同的 JavaScript 引擎，这意味着创建者们对它们进行了不同的实现。最后，我们需要确保在我们的测试中没有任何多余的代码，否则结果可能会被扭曲。

让我们看一些脚本，并根据在 jsPerf 中运行它们的结果来看看它们的效果。所以，让我们开始：

1.  转到[`jsperf.com`](https://jsperf.com)。如果我们想创建自己的测试，我们将需要使用 GitHub 账户登录，所以现在就去做吧。

1.  接下来，让我们创建我们的第一个性能测试。系统是不言自明的，但我们将讨论一些方面：

+   首先，如果我们需要添加一些 HTML 代码，以便进行 DOM 操作，我们会将其放在*准备代码 HTML*部分。

+   接下来，我们将输入我们所有测试中需要的任何变量。

+   最后，我们可以整合我们的测试用例。让我们运行一个测试。

1.  我们将首先查看的测试是利用循环与利用`filter`函数。对于这个测试，我们不需要任何 HTML，所以我们可以将这一部分留空。

1.  接下来，我们将输入所有测试用例都需要的以下代码：

```js
const arr = new Array(10000);
for(let i = 0; i < arr.length; i++) {
    arr[i] = i % 2 ? i : -1;
}
```

1.  然后，我们将添加两个不同的测试用例，`for`循环和`filter`函数。它们应该如下所示：

对于循环的情况：

```js
const nArr = [];
for(let i = 0; i < arr.length; i++) {
    if( Math.abs(arr[i]) === arr[i]) {
        nArr.push(arr[i]);
    }
}
```

对于 filter 的情况：

```js
const nArr = arr.filter(item => Math.abs(item) === item);
```

1.  现在，我们可以保存测试用例并运行性能测试器。点击运行按钮，观察测试运行器多次检查每段代码。我们应该看到如下内容：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-hiperf/img/d23c88f7-5965-4ad3-b737-2f64b53dbe34.png)

嗯，正如预期的那样，`for`循环的性能优于`filter`函数。右侧的这三个数字的分解如下：

+   每秒操作次数，或者系统在一秒内可以运行多少基本指令。

+   每个特定测试用例的每次测试运行的差异。对于`for`循环，加减 2%。

+   最后，它会告诉我们它是否是最快的，或者比最快的慢了多少。对于 filter，它慢了 86%。

哇，这明显慢了很多！在这种情况下，我们可能会想出一种让 filter 运行更加高效的方法。一种方法是我们可以提前创建函数，而不是创建一个匿名函数。在我们的结果底部附近，我们将看到一个链接，可以让我们添加更多的测试。让我们回到测试用例中，为我们的新测试添加一个测试。

在底部附近应该有一个**添加代码片段**按钮。让我们点击这个按钮并填写细节。我们将称这个新的代码片段为`filterFunctionDefined`，它应该看起来像下面这样：

```js
const reducer = function(item) {
    return Math.abs(item) === item;
}
const nArr = arr.filter(reducer);
```

我们可以保存这个测试用例并重新运行结果。结果似乎几乎与常规的`filter`函数完全相同。其中一些原因是我们的浏览器为我们优化了我们的代码。我们可以在所有浏览器中测试这些结果，以便更好地了解我们的代码在每个浏览器中的运行情况。但是，即使我们在其他地方运行这个测试，我们也会看到结果是一样的；`filter`函数比普通的`for`循环慢。

这对于几乎每个基于数组的函数都是正确的。辅助函数很棒，但它们也比常规循环慢。我们将在下一章中详细介绍，但请提前意识到，浏览器提供给我们的大多数便利都会比直接以更简单的方式编写函数要慢。

让我们设置另一个测试，只是为了确保我们理解 jsPerf。

首先，创建一个新的测试。让我们对对象执行一个测试，并查看使用`for-in`循环与使用`Object.keys()`方法的差异。同样，我们不需要使用 DOM，因此在 HTML 部分不需要填写任何内容。

对于我们的测试设置，让我们创建一个空对象，然后使用以下代码填充它，其中包含一堆无用的数据：

```js
const obj = {};
for(let i = 0; i < 10000; i++) {
    obj[`item${i}`] = i;
}
```

接下来，让我们创建两个测试用例，第一个是调用`for in`，应该如下所示：

```js
const results = [];
for(let key in obj) {
    results.push([key, obj[key]]);
}
```

第二个测试用例是`Object.keys()`版本，如下所示：

```js
const results = [];
const keys = Object.keys(obj);
for(let i = 0; i < keys.length; i++) {
    results.push([keys[i], obj[keys[i]]);
}
```

现在，如果我们运行我们的测试，我们会注意到`keys`版本能够每秒执行大约 600 次操作，而`fo..in`版本能够每秒执行大约 550 次。这两者相差不大，因此浏览器的差异实际上可能会起作用。当我们开始出现轻微差异时，最好选择后来实现的或最有可能进行优化的选项。

大多数情况下，如果某些东西只是被实现，并且浏览器供应商同意添加某些东西，那么它可能处于早期开发阶段。如果性能结果在允许的公差范围内（通常在 5-10%的差异左右），那么最好选择更新的选项。它更有可能在未来进行优化。

所有这些测试都很棒，如果我们找到了真正想与人们分享的东西，这是一个很好的解决方案。但是，如果我们想自己运行这些测试而不必担心外部网站怎么办呢？嗯，我们可以利用 jsPerf 正在使用的基础库。它被称为 Benchmark.js，当我们需要为调试代码设置自己的系统时，它是一个很好的工具。我们可以在[`benchmarkjs.com/`](https://benchmarkjs.com/)找到它。

让我们获取源代码，并将其设置为 HTML 文件中的外部脚本。我们还需要将*Lodash*添加为依赖项。接下来，让我们编写与之前相同的测试，但是我们将在内部脚本中编写它们，并在屏幕上显示结果。我们还将只显示我们脚本的标题以及这些结果。

我们显然可以使这个更加花哨，但重点将是让库为我们正确地进行基准测试。

我们将有一些设置代码，其中将有一个对象数组。这些对象只有两个属性，测试的名称和我们想要运行的函数。在我们的`for`循环与`filter`测试的情况下，它看起来会像这样：

```js
const forTest = Object.assign({}, testBaseObj);
forTest.title = 'for loop';
forTest.fun = function() {
    const arr = [];
    for(let i = 0; i < startup.length; i++) {
        if( Math.abs(startup[i]) === startup[i] ) {
            arr.push(startup[i]);
        }
    }
}
const filterTest = Object.assign({}, testBaseObj);
filterTest.title = 'filter';
filterTest.fun = function() {
    const arr = startup.filter((item) => Math.abs(item) === item);
}
const tests = [forTest, filterTest];
```

从这里开始，我们设置了一个基准套件，并循环执行我们的测试，将它们添加到套件中。然后我们添加了两个监听器，一个用于完成循环，以便我们可以在列表中显示它，另一个用于完成，以便我们可以突出显示运行最快的条目。它应该如下所示：

```js
const suite = new Benchmark.Suite;
for(let i = 0; i < tests.length; i++) {
    suite.add(tests[i].title, tests[i].fun);
}
suite.on('cycle', function(event) {
    const el = document.createElement('li');
    el.textContent = event.target;
    el.id = event.target.name;
    appendEl.appendChild(el);
})
.on('complete', function() {
    const fastest = this.filter('fastest').map('name');
    document.getElementById(fastest[0]).style.backgroundColor = 'green';
})
.run({ 'async' : true });
```

如果我们设置了所有这些，或者运行了`benchmark.html`，我们将看到输出。我们可以从基准库中获得许多其他有趣的统计数据。其中之一是每个测试的标准偏差。在 Edge 中运行的`for`循环测试的情况下，大约为 0.004。另一个有趣的注释是我们可以查看每次运行所花费的时间。同样，以`for`循环为例，Edge 浏览器正在慢慢优化我们的代码，并且很可能将其放入缓存，因为时间不断减少。

# 总结

本章介绍了许多用于分析和调试代码的概念。它考虑了各种现代浏览器，甚至考虑了它们可能具有或不具有的特殊功能。我们特别关注了 Chrome 浏览器，因为许多开发人员将其用作主要的开发浏览器。除此之外，V8 引擎用于 Node.js，这意味着我们所有的 Node.js 代码将使用 V8 调试器。最后，我们看了一下如何利用 jsPerf 来找出某段代码的最佳实现方式。我们甚至研究了在我们自己的系统中运行它的可能性以及如何实现这一点。

展望未来，本书的剩余部分将不再具体讨论这些主题，但在本书的其余部分开发代码时应该使用这些工具。除此之外，我们将几乎在 Chrome 浏览器中运行所有的代码，除了当我们编写 GLSL 时，因为 Firefox 拥有最好的组件来实际测试这些代码。在下一章中，我们将探讨不可变性以及在开发中何时应该利用它。


# 第二章：不可变性与可变性-安全与速度之间的平衡

近年来，开发实践已经转向更加功能化的编程风格。这意味着更少关注可变编程（在修改某些东西时改变变量而不是创建新变量）。当我们将变量从一种东西改变为另一种东西时，就会发生可变性。这可能是更新数字，改变消息内容，甚至将项目从字符串更改为数字。可变状态会导致编程陷阱的许多领域，例如不确定状态，在多线程环境中死锁，甚至在我们不希望的情况下更改数据类型（也称为副作用）。现在，我们有许多库和语言可以帮助我们遏制这种行为。

所有这些都导致了对使用不可变数据结构和基于输入创建新对象的函数的推动。虽然这会减少可变状态的错误，但它也带来了一系列其他问题，主要是更高的内存使用和更低的速度。大多数 JavaScript 运行时都没有优化，允许这种编程风格。当我们关注内存和速度时，我们需要尽可能多地获得优势，这就是可变编程给我们带来的优势。

在本章中，我们将重点关注以下主题：

+   当前网络上的不可变性趋势

+   编写安全的可变代码

+   网络上的类似功能的编程

# 技术要求

本章的先决条件如下：

+   一个网络浏览器，最好是 Chrome

+   编辑器；首选 VS Code

+   了解 Redux 或 Vuex 等当前状态库

+   相关代码可以在[`github.com/PacktPublishing/Hands-On-High-Performance-Web-Development-with-JavaScript/tree/master/Chapter02`](https://github.com/PacktPublishing/Hands-On-High-Performance-Web-Development-with-JavaScript/tree/master/Chapter02)找到。

# 当前对不可变性的迷恋

当前网络趋势显示了对利用不可变性的迷恋。诸如 React 之类的库可以在没有其不可变状态的情况下使用，但它们通常与 Redux 或 Facebook 的 Flow 库一起使用。这些库中的任何一个都将展示不可变性如何可以导致更安全的代码和更少的错误。

对于那些不了解的人，不可变性意味着一旦设置了数据，就无法更改变量。这意味着一旦我们给变量分配了某些内容，我们就不能再更改该变量。这有助于防止不必要的更改发生，并且还可以导致一个称为**纯函数**的概念。我们不会深入讨论纯函数是什么，但要知道这是许多函数式程序员一直在引入 JavaScript 的概念。

但是，这是否意味着我们需要它，它是否会导致更快的系统？在 JavaScript 的情况下，这可能取决于情况。一个管理良好的项目，有文档和测试，可以很容易地展示出我们可能不需要这些库。除此之外，我们可能需要实际改变对象的状态。我们可能在一个位置写入对象，但有许多其他部分从该对象中读取。

有许多开发模式可以给我们带来与不可变性相似的好处，而不需要创建大量临时对象或者甚至进入完全纯粹的功能化编程风格。我们可以利用诸如**资源获取即初始化**（**RAII**）的系统。我们可能会发现自己想要使用一些不可变性，在这种情况下，我们可以利用内置的浏览器工具，如`Object.freeze()`或`Object.seal()`。

然而，我们在走得太快了。让我们来看看其中提到的一些库，看看它们如何处理不可变状态，以及在编码时可能会导致问题。

# 深入 Redux

**Redux**是一个很好的状态管理系统。当我们开发诸如 Google Docs 或者一个报告系统这样的复杂系统时，它可以管理我们应用程序的状态。然而，它可能会导致一些过于复杂的系统，这些系统可能并不需要它所代表的状态管理。

Redux 的理念是没有一个对象应该能够改变应用程序的状态。所有的状态都需要托管在一个单一的位置，并且应该有处理状态变化的函数。这意味着写入的单一位置，以及多个位置能够读取数据。这与我们以后想要利用的一些概念类似。

然而，它会进一步进行许多文章都希望我们传回全新的对象。这是有原因的。许多对象，特别是那些具有多层的对象，不容易复制。简单的复制操作，比如使用`Object.assign({}, obj)`或者利用数组的扩展运算符，只会复制它们内部持有的引用。在我们编写基于 Redux 的应用程序之前，让我们看一个例子。

如果我们从我们的存储库中打开`not_deep_copy.html`，我们将看到控制台打印相同的内容。如果我们看一下代码，我们将看到一个非常常见的复制对象和数组的情况：

```js
const newObj = Object.assign({}, obj);
const newArr = [...arr];
```

如果我们只将其复制一层深，我们将看到它实际上执行了一次复制。以下代码将展示这一点：

```js
const obj2 = {item : 'thing', another : 'what'};
const arr2 = ['yes', 'no', 'nope'];

const newObj2 = Object.assign({}, obj2);
const newArr2 = [...arr2]
```

我们将更详细地讨论这个案例，以及如何真正执行深层复制，但我们可以开始看到 Redux 可能隐藏了仍然存在于我们系统中的问题。让我们构建一个简单的 Todo 应用程序，至少展示 Redux 及其能力。所以，让我们开始：

1.  首先，我们需要拉取 Redux。我们可以通过**Node Package Manager**（**npm**）来做到这一点，并在我们的系统中安装它。只需简单地`npm install redux`。

1.  我们现在将进入新创建的文件夹，获取`redux.min.js`文件并将其放入我们的工作目录中。

1.  现在我们将创建一个名为`todo_redux.html`的文件。这将包含我们的所有主要逻辑。

1.  在顶部，我们将将 Redux 库作为依赖项添加进来。

1.  然后，我们将添加我们要在存储库上执行的操作。

1.  接下来，我们将设置我们想要在应用程序中使用的 reducers。

1.  然后，我们将设置存储并准备好进行数据更改。

1.  然后我们将订阅这些数据变化并更新 UI。

我们正在处理的示例是 Redux 示例中 Todo 应用程序的略微修改版本。其中一个好处是我们将利用原始 DOM，而不是使用其他库，比如 React，所以我们可以看到 Redux 如何适用于任何应用程序，如果需要的话。

1.  所以，我们的操作将是添加一个`todo`元素，切换一个`todo`元素以完成或未完成，并设置我们想要看到的`todo`元素。这段代码如下所示：

```js
const addTodo = function(test) {
    return { type : ACTIONS.ADD_TODO, text };
}
const toggleTodo = function(index) {
    return { type : ACTIONS.TOGGLE_TODO, index };
}
const setVisibilityFilter = function(filter) {
    return { type : ACTIONS.SET_VISIBILITY_FILTER, filter };
}
```

1.  接下来，reducers 将被分开，一个用于我们的可见性过滤器，另一个用于实际的`todo`元素。

可见性 reducer 非常简单。它检查操作的类型，如果是`SET_VISIBILITY_FILTER`类型，我们将处理它，否则，我们只是传递状态对象。对于我们的`todo` reducer，如果我们看到一个`ADD_TODO`操作，我们将返回一个新的项目列表，其中我们的项目位于底部。如果我们切换其中一个项目，我们将返回一个将该项目设置为与其原来设置相反的新列表。否则，我们只是传递状态对象。所有这些看起来像下面这样：

```js
const visibilityFilter = function(state = 'SHOW_ALL', action) {
    switch(action.type) {
        case 'SET_VISIBILITY_FILTER': {
            return action.filter;
        }
        default: {
            return state;
        }
    }
}

const todo = function(state = [], action) {
    switch(action.type) {
        case 'ADD_TODO': {
            return [
                ...state,
                {
                    text : action.text,
                    completed : false
                }
        }
        case 'TOGGLE_TODO': {
            return state.map((todo, index) => {
                if( index === action.index ) {
                    return Object.assign({}, todo, {
                        completed : !todo.completed
                    });
                }
                return todo;
            }
        }
        default: {
            return state;
        }
    }
}
```

1.  完成后，我们将两个 reducer 放入一个单一的 reducer 中，并设置`state`对象。

我们逻辑的核心在于 UI 实现。请注意，我们设置了这个工作基于数据。这意味着数据可以传递到我们的函数中，UI 会相应地更新。我们也可以反过来，但是让 UI 由数据驱动是一个很好的范例。我们首先有一个先前的状态存储。我们可以进一步利用它，只更新实际更新的内容，但我们只在第一次检查时使用它。我们获取当前状态并检查两者之间的差异。如果我们看到长度已经改变，我们知道应该添加一个`todo`项目。如果我们看到可见性过滤器已更改，我们将相应地更新 UI。最后，如果这两者都不是真的，我们将检查哪个项目被选中或取消选中。代码如下所示：

```js
store.subscribe(() => 
    const state = store.getState();
    // first type of actions ADD_TODO
    if( prevState.todo.length !== state.todo.length ) {
     container.appendChild(createTodo(state.todo[state.todo.length
     - 1].text));
    // second type of action SET_VISIBILITY_FILTER
    } else if( prevState.visibilityFilter !== 
      state.visibilityFilter ) {
        setVisibility(container.children, state);
    // final type of action TOGGLE_TODO
    } else {
        const todos = container.children;
        for(let i = 0; i < todos.length; i++) {
            if( state.todo[i].completed ) {
                todos[i].classList.add('completed');
            } else {
                todos[i].classList.remove('completed');
            }
        }
    }
    prevState = state;
});
```

如果我们运行这个，我们应该得到一个简单的 UI，我们可以以以下方式进行交互：

+   添加`todo`项目。

+   将现有的`todo`项目标记为已完成。

我们还可以通过点击底部的三个按钮之一来查看不同的视图，如下面的截图所示。如果我们只想看到我们所有已完成的任务，我们可以点击“更新”按钮。

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-hiperf/img/a46cdc61-ccb1-453c-a5e8-ed9318b16997.png)

现在，我们可以保存状态以进行离线存储，或者我们可以将状态发送回服务器进行常规更新。这就是使 Redux 非常好的地方。但是，在使用 Redux 时也有一些注意事项，与我们之前所述的相关：

1.  首先，我们需要在我们的 Todo 应用程序中添加一些内容，以便能够处理我们状态中的嵌套对象。这个 Todo 应用程序中遗漏的一部分信息是设置一个截止日期。因此，让我们添加一些字段供我们填写以设置完成日期。我们将添加三个新的数字输入，如下所示：

```js
<input id="year" type="number" placeholder="Year" />
<input id="month" type="number" placeholder="Month" />
<input id="day" type="number" placeholder="Day" />
```

1.  然后，我们将添加另一种`Overdue`的过滤器类型：

```js
<button id="SHOW_OVERDUE">Overdue</button>
```

1.  确保将其添加到`visibilityFilters`对象中。现在，我们需要更新我们的`addTodo`操作。我们还将传递一个`Date`对象。这也意味着我们需要更新我们的`ADD_TODO`情况，以将`action.date`添加到我们的新`todo`对象中。然后，我们将更新我们的 Add 按钮的`onclick`处理程序，并调整为以下内容：

```js
const year = document.getElementById('year');
const month = document.getElementById('month');
const day = document.getElementById('day');
store.dispatch(addTodo(input.value), {year : year.value, month : month.value, day : day.value}));
year.value = "";
month.value = "";
day.value = "";
```

1.  我们可以将日期保存为`Date`对象（这样更有意义），但为了展示可能出现的问题，我们将只保存一个带有`year`、`month`和`day`字段的新对象。然后，我们将通过添加另一个`span`元素并用这些字段的值填充它来在 Todo 应用程序上展示这个日期。最后，我们需要更新我们的`setVisibility`方法，以便显示我们过期的项目。它应该如下所示：

```js
case visibilityFilters.SHOW_OVERDUE: {
    const currTodo = state.todo[i];
    const tempTime = currTodo.date;
    const tempDate = new Date(`${tempTime.year}/${tempTime.month}/${tempTime.day}`);
    if( tempDate < currDay && !currTodo.completed ) {
        todos[i].classList.remove('hide');
    } else {
        todos[i].classList.add('hide');
    }
}
```

有了所有这些，我们现在应该有一个可工作的 Todo 应用程序，同时展示我们的过期项目。现在，这就是在处理 Redux 等状态管理系统时可能变得混乱的地方。当我们想要对已创建的项目进行修改，而它不是一个简单的扁平对象时会发生什么？好吧，我们可以只获取该项目并在状态系统中对其进行更新。让我们添加这段代码：

1.  首先，我们将创建一个新的按钮和输入，用于更改最后一个条目的年份。我们将为“更新”按钮添加一个点击处理程序：

```js
document.getElementById('UPDATE_LAST_YEAR').onclick = function(e) {
    store.dispatch({ type : ACTIONS.UPDATE_LAST_YEAR, year :  
     document.getElementById('updateYear').value });
}
```

1.  然后，我们将为`todo`系统添加这个新的操作处理程序：

```js
case 'UPDATE_LAST_YEAR': {
    const prevState = state;
    const tempObj = Object.assign({}, state[state.length - 
     1].date);
    tempObj.year = action.year;
    state[state.length - 1].date = tempObj;
    return state;
}
```

现在，如果我们运行我们的系统，我们会注意到一些情况。我们的代码在订阅中的检查对象条件中没有通过：

```js
if( prevState === state ) {
    return;
}
```

我们直接更新了状态，因此 Redux 从未创建新对象，因为它没有检测到更改（我们直接更新了一个对象的值，而我们没有一个 reducer）。现在，我们可以创建另一个专门用于日期的 reducer，但我们也可以重新创建数组并将其传递：

```js
case 'UPDATE_LAST_YEAR': {
    const prevState = state;
    const tempObj = Object.assign({}, state[state.length - 1].date);
    tempObj.year = action.year;
    state[state.length - 1].date = tempObj;
    return [...state];
}
```

现在，我们的系统检测到有变化，我们能够通过我们的方法来更新代码。

更好的实现方式是将我们的`todo` reducer 拆分为两个单独的 reducer。但是，由于我们正在进行示例，所以尽可能简单。

通过所有这些，我们可以看到我们需要遵守 Redux 为我们制定的规则。虽然这个工具在大规模应用中可能会带来巨大的好处，但对于较小的状态系统甚至组件化系统，我们可能会发现直接使用真正的可变状态更好。只要我们控制对可变状态的访问，我们就能充分利用可变状态的优势。

这并不是要贬低 Redux。它是一个很棒的库，即使在更重的负载下也能表现良好。但是，有时我们想直接使用数据集并直接进行变异。Redux 可以做到这一点，并为我们提供其事件系统，但是我们可以在不使用 Redux 提供的所有其他部分的情况下自己构建这个。记住，我们希望尽可能地精简代码库，并使其尽可能高效。当我们处理成千上万的数据项时，额外的方法和额外的调用会累积起来。

通过这个对 Redux 和状态管理系统的介绍，我们还应该看一下一个使不可变系统成为必需的库：Immutable.js。

# Immutable.js

再次利用不可变性，我们可以以更易于理解的方式编写代码。然而，这通常意味着我们无法满足真正高性能应用所需的规模。

首先，Immutable.js 在 JavaScript 中提供了一种很好的函数式数据结构和方法，这通常会导致更清晰的代码和更清晰的架构。但是，我们在这些优势方面得到的东西会导致速度的降低和/或内存的增加。

记住，当我们使用 JavaScript 时，我们处于一个单线程环境。这意味着我们实际上没有死锁、竞争条件或读/写访问问题。

在使用诸如`SharedArrayBuffers`之类的东西在工作线程或不同的标签之间可能会遇到这些问题，但这是以后章节的讨论。现在，我们正在一个单线程环境中工作，多核系统的问题并不会真正出现。

让我们举一个现实生活中可能出现的用例的例子。我们想将一个列表的列表转换为对象列表（想象一下 CSV）。在普通的 JavaScript 中构建这种数据结构的代码可能如下所示：

```js
const fArr = new Array(fillArr.length - 1);
const rowSize = fillArr[0].length;
const keys = new Array(rowSize);
for(let i = 0; i < rowSize; i++) {
    keys[i] = fillArr[0][i];
}
for(let i = 1; i < fillArr.length; i++) {
    const obj = {};
    for(let j = 0; j < rowSize; j++) {
        obj[keys[j]] = fillArr[i][j];
    }
    fArr[i - 1] = obj;
}
```

我们构建一个新的数组，大小为输入列表的大小减一（第一行是键）。然后，我们存储行大小，而不是每次在内部循环中计算。然后，我们创建另一个数组来保存键，并从输入数组的第一个索引中获取它们。接下来，我们循环遍历输入中的其余条目并创建对象。然后，我们循环遍历每个内部数组，并将键设置为值和位置`j`，并将值设置为输入的`i`和`j`值。

通过嵌套数组和循环读取数据可能会令人困惑，但可以获得快速的读取时间。在一个双核处理器和 8GB RAM 的计算机上，这段代码花了 83 毫秒。

现在，让我们在 Immutable.js 中构建类似的东西。它应该看起来像下面这样：

```js
const l = Immutable.List(fillArr);
const _k = Immutable.List(fillArr[0]);
const tFinal = l.map((val, index) => {
    if(!index ) return;
    return Immutable.Map(_k.zip(val));
});
const final = tfinal.shift();
```

如果我们理解函数式概念，这将更容易解释。首先，我们想要根据我们的输入创建一个列表。然后我们创建另一个临时列表用于存储键称为`_k`*.*。对于我们的临时最终列表，我们利用`map`函数。如果我们在`0`索引处，我们就从函数中`return`（因为这是键）。否则，我们返回一个通过将键列表与当前值进行 zip 的新映射。最后，我们移除最终列表的前部，因为它将是未定义的。

这段代码在可读性方面很棒，但它的性能特征如何？在当前的机器上，它运行大约需要 1 秒。这在速度方面有很大的差异。让我们看看它们在内存使用方面的比较。

已解决的内存（运行代码后内存返回的状态）似乎是相同的，回到了大约 1.2 MB。然而，不可变版本的峰值内存约为 110 MB，而 Vanilla JavaScript 版本只达到了 48 MB，所以内存使用量略低于一半。让我们看另一个例子并看看发生的结果。

我们将创建一个值数组，除了我们希望其中一个值是不正确的。因此，我们将使用以下代码将第 50,000 个索引设置为`wrong`：

```js
const tempArr = new Array(100000);
for(let i = 0; i < tempArr.length; i++) {
    if( i === 50000 ) { tempArr[i] = 'wrong'; }
    else { tempArr[i] = i; }
}
```

然后，我们将使用简单的`for`循环遍历一个新数组，如下所示：

```js
const mutArr = Array.apply([], tempArr);
const errs = [];
for(let i = 0; i < mutArr.length; i++) {
    if( mutArr[i] !== i ) {
        errs.push(`Error at loc ${i}. Value : ${mutArr[i]}`);
        mutArr[i] = i;
    }
}
```

我们还将测试内置的`map`函数：

```js
const mut2Arr = Array.apply([], tempArr);
const errs2 = [];
const fArr = mut2Arr.map((val, index) => {
    if( val !== index ) {
        errs2.push(`Error at loc: ${index}. Value : ${val}`);
        return index;
    }
    return val;
});
```

最后，这是不可变版本：

```js
const immArr = Immutable.List(tempArr);
const ierrs = [];
const corrArr = immArr.map((item, index) => {
    if( item !== index ) {
        ierrs.push(`Error at loc ${index}. Value : ${item}`);
        return index;
    }
    return item;
});
```

如果我们运行这些实例，我们会发现最快的将在基本的`for`循环和内置的`map`函数之间切换。不可变版本仍然比其他版本慢 8 倍。当我们增加不正确值的数量时会发生什么？让我们添加一个随机数生成器来构建我们的临时数组，以便产生随机数量的错误，并看看它们的表现。代码应该如下所示：

```js
for(let i = 0; i < tempArr.length; i++) {
    if( Math.random() < 0.4 ) {
        tempArr[i] = 'wrong';
    } else {
        tempArr[i] = i;
    }
}
```

运行相同的测试，我们发现不可变版本大约会慢十倍。现在，这并不是说不可变版本在某些情况下不会运行得更快，因为我们只涉及了它的 map 和 list 功能，但这确实提出了一个观点，即在将其应用于 JavaScript 库时，不可变性在内存和速度方面是有代价的。

我们将在下一节中看到为什么可变性可能会导致一些问题，但也会看到我们如何通过利用类似 Redux 处理数据的想法来处理它。

不同的库总是有其适用的时间和场合，并不是说 Immutable.js 或类似的库是不好的。如果我们发现我们的数据集很小或其他考虑因素起作用，Immutable.js 可能适合我们。但是，当我们在高性能应用程序上工作时，这通常意味着两件事。一是我们将一次性获得大量数据，二是我们将获得大量导致数据积累的事件。我们需要尽可能使用最有效的方法，而这些通常内置在我们正在使用的运行时中。

# 编写安全的可变代码

在我们继续编写安全的可变代码之前，我们需要讨论引用和值。值可以被认为是任何原始类型。在 JavaScript 中，原始类型是指不被视为对象的任何内容。简单来说，数字、字符串、布尔值、null 和 undefined 都是值。这意味着如果你创建一个新变量并将其分配给原始变量，它实际上会给它一个新值。那么这对我们的代码意味着什么呢？嗯，我们之前在 Redux 中看到，它无法看到我们更新了状态系统中的属性，因此我们的先前状态和当前状态显示它们是相同的。这是由于浅相等测试。这个基本测试测试传入的两个变量是否指向同一个对象。一个简单的例子是在以下代码中看到的：

```js
let x = {};
let y = x;
console.log( x === y );
y = Object.assign({}, x);
console.log( x === y );
```

我们会发现第一个版本说这两个项目是相等的。但是，当我们创建对象的副本时，它会声明它们不相等。`y`现在有一个全新的对象，这意味着它指向内存中的一个新位置。虽然对*按值传递*和*按引用传递*的更深入理解可能有好处，但这应该足以继续使用可变代码。

在编写安全的可变代码时，我们希望给人一种错觉，即我们正在编写不可变的代码。换句话说，接口应该看起来像我们在使用不可变的系统，但实际上我们在内部使用的是可变的系统。因此，接口与实现之间存在分离。

我们可以通过以可变的方式编写代码来使实现变得非常快速，但提供一个看起来不可变的接口。一个例子如下：

```js
Array.prototype._map = function(fun) {
    if( typeof fun !== 'function' ) {
        return null;
    }
    const arr = new Array(this.length);
    for(let i = 0; i < this.length; i++) {
        arr[i] = fun(this[i]);
    }
    return arr;
}
```

我们在数组原型上编写了一个`_map`函数，以便每个数组都可以使用它，并且我们编写了一个简单的`map`函数。如果我们现在测试运行这段代码，我们会发现一些浏览器使用这种方式更快，而其他浏览器使用内置选项更快。如前所述，内置选项最终会变得更快，但往往一个简单的循环会更快。现在让我们看另一个可变实现的例子，但具有不可变的接口：

```js
Array.prototype._reduce = function(fun, initial=null) {
    if( typeof fun !== 'function' ) {
        return null;
    }
    let val = initial ? initial : this[0];
    const startIndex = initial ? 0 : 1;
    for(let i = startIndex; i < this.length; i++) {
        val = fun(val, this[i], i, this);
    }
    return val;
}
```

我们编写了一个`reduce`函数，在每个浏览器中都有更好的性能。现在，它没有相同数量的类型检查，这可能会导致更好的性能，但它展示了我们如何编写可以提供更好性能但给用户提供相同类型接口的函数。

到目前为止，我们讨论的是，如果我们为别人编写一个库来使他们的生活更轻松。如果我们正在编写一些我们自己或内部团队将要使用的东西，这是大多数应用程序开发人员的情况，会发生什么呢？

在这种情况下，我们有两个选择。首先，我们可能会发现我们正在处理一个传统系统，并且我们将不得不尝试以与已有代码类似的风格进行编程，或者我们正在开发一些全新的东西，我们可以从头开始。

编写传统代码是一项艰巨的工作，大多数人通常会做错。虽然我们应该致力于改进代码库，但我们也在努力匹配风格。对于开发人员来说，尤其困难的是，他们需要浏览代码并看到使用了 10 种不同代码选择，因为在项目的整个生命周期中有 10 个不同的开发人员参与其中。如果我们正在处理其他人编写的东西，通常最好匹配代码风格，而不是提出完全不同的东西。

有了一个新系统，我们可以按照自己的意愿编写代码，并且在适当的文档支持下，我们可以编写出非常快速的代码，同时也容易让其他人理解。在这种情况下，我们可以编写可变的代码，函数中可能会产生副作用，但我们可以记录这些情况。

副作用是指当一个函数不仅返回一个新变量或者变量的引用时发生的情况。当我们更新另一个变量，而我们对其没有当前范围时，这构成了一个副作用。一个例子如下：

```js
var glob = 'a single point system';
const implement = function(x) {
    glob = glob.concat(' more');
    return x += 2;
}
```

我们有一个名为`glob`的全局变量，我们在函数内部对其进行更改。从技术上讲，这个函数对`glob`有范围，但我们应该尝试将实现的范围定义为仅限于传入的内容以及实现内部定义的临时变量。由于我们正在改变`glob`，我们在代码库中引入了一个副作用。

现在，在某些情况下，副作用是必需的。我们可能需要更新一个单一点，或者我们可能需要将某些东西存储在一个单一位置，但我们应该尝试实现一个接口来为我们完成这些操作，而不是直接影响全局项目（这听起来很像 Redux）。通过编写一个或两个函数来影响超出范围的项目，我们现在可以诊断问题可能出现的地方，因为我们有这些单一的入口点。

那么这会是什么样子呢？我们可以创建一个状态对象，就像一个普通的对象一样。然后，我们可以在全局范围内编写一个名为`updateState`的函数，如下所示：

```js
const updateState = function(update) {
    const x = Object.keys(update);
    for(let i = 0; i < x.length; i++) {
        state[x[i]] = update[x[i]];
    }
}
```

现在，虽然这可能是好的，但我们仍然容易受到通过实际全局属性更新我们的状态对象的影响。幸运的是，通过将我们的状态对象和函数设为`const`，我们可以确保错误的代码无法触及这些实际的名称。让我们更新我们的代码，以确保我们的状态受到直接更新的保护。我们可以通过两种方式来实现这一点。第一种方法是使用模块编码，然后我们的状态对象将被限定在该模块中。我们将在本书中进一步讨论模块和导入语法。在这种情况下，我们将使用第二种方法，即**立即调用函数表达式**（**IIFE**）的方式进行编码。以下展示了这种实现方式：

```js
const state = {};
(function(scope) {
    const _state = {};
    scope.update = function(obj) {
        const x = Object.keys(obj);
        for(let i = 0; i < x.length; i++) {
            _state[x[i]] = obj[x[i]];
        }
    }
    scope.set = function(key, val) {
        _state[key] = val;
    }
    scope.get = function(key) {
        return _state[key];
    }
    scope.getAll = function() {
        return Object.assign({}, _state);
    }
})(state);
Object.freeze(state);
```

首先，我们创建一个常量状态。然后我们使用 IIFE 并传入状态对象，在其上设置一堆函数。它在一个内部`scoped _state`变量上工作。我们还拥有所有我们期望的内部状态系统的基本函数。我们还冻结了外部状态对象，因此它不再能被操纵。可能会出现的一个问题是，为什么我们要返回一个新对象而不是一个引用。如果我们试图确保没有人能够触及内部状态，那么我们不能传递一个引用出去；我们必须传递一个新对象。

我们仍然有一个问题。如果我们想要更新多层深度，会发生什么？我们将再次遇到引用问题。这意味着我们需要更新我们的更新函数以执行深度更新。我们可以用多种方式来做到这一点，但一种方法是将值作为字符串传递，然后在小数点上分割。

这并不是处理这个问题的最佳方式，因为我们在技术上可以让对象的属性以小数点命名，但这将允许我们快速编写一些东西。在编写高性能代码库时，平衡编写功能性代码和被认为是完整解决方案的东西之间的平衡是两回事，必须在写作时加以平衡。

因此，我们现在将有一个如下所示的方法：

```js
const getNestedProperty = function(key) {
    const tempArr = key.split('.');
    let temp = _state;
    while( tempArr.length > 1 ) {
        temp = temp[tempArr.shift()];
        if( temp === undefined ) {
            throw new Error('Unable to find key!');
        }
    }
    return {obj : temp, finalKey : tempArr[0] };
}
scope.set = function(key, val) {
    const {obj, finalKey} = getNestedProperty(key);
    obj[finalKey] = val;
}
scope.get = function(key) {
    const {obj, finalKey} = getNestedProperty(key);
    return obj[finalKey];
}
```

我们正在通过小数点来分解键。我们还获取了对内部状态对象的引用。当列表中仍有项目时，我们会在对象中向下移动一级。如果我们发现它是未定义的，那么我们将抛出一个错误。否则，一旦我们在我们想要的位置的上一级，我们将返回一个具有该引用和最终键的对象。然后我们将在 getter 和 setter 中使用这个对象来替换这些值。

现在，我们仍然有一个问题。如果我们想要使引用类型成为内部状态系统的属性值，会怎么样呢？嗯，我们将遇到之前看到的相同问题。我们将在单个状态对象之外有引用。这意味着我们将不得不克隆每一步，以确保外部引用不指向内部副本中的任何内容。我们可以通过添加一堆检查并确保当我们到达引用类型时，以一种高效的方式进行克隆来创建这个系统。代码如下所示：

```js
const _state = {},
checkPrimitives = function(item) {
    return item === null || typeof item === 'boolean' || typeof item === 
     'string' || typeof item === 'number' || typeof item === 'undefined';
},
cloneFunction = function(fun, scope=null) {
    return fun.bind(scope);
},
cloneObject = function(obj) {
    const newObj = {};
    const keys = Object.keys(obj);
    for(let i = 0; i < keys.length; i++) {
        const key = keys[i];
        const item = obj[key];
        newObj[key] = runUpdate(item);
    }
    return newObj;
},
cloneArray = function(arr) {
    const newArr = new Array(arr.length);
    for(let i = 0; i < arr.length; i++) {
        newArr[i] = runUpdate(arr[i]);
    }
    return newArr;
},
runUpdate = function(item) {
    return checkPrimitives(item) ?
        item : 
        typeof item === 'function' ?
            cloneFunction(item) :
        Array.isArray(item) ?
            cloneArray(item) :
            cloneObject(item);
};

scope.update = function(obj) {
    const x = Object.keys(obj);
    for(let i = 0; i < x.length; i++) {
        _state[x[i]] = runUpdate(obj[x[i]]);
    }
}
```

我们所做的是编写一个简单的克隆系统。我们的`update`函数将遍历键并运行更新。然后我们将检查各种条件，比如我们是否是原始类型。如果是，我们只需复制值，否则，我们需要弄清楚我们是什么复杂类型。我们首先搜索是否是一个函数；如果是，我们只需绑定值。如果是一个数组，我们将遍历所有的值，并确保它们都不是复杂类型。最后，如果是一个对象，我们将遍历所有的键，并尝试运行相同的检查来更新这些键。

然而，我们刚刚做了我们一直在避免的事情；我们已经创建了一个不可变的状态系统。我们可以为这个集中的状态系统添加更多的功能，比如事件，或者我们可以实现一个已经存在很长时间的编码标准，称为**Resource Allocation Is Initialization**（**RAII**）。

有一个名为**proxies**的内置 Web API 非常好。这些基本上是系统，我们能够在对象发生某些事情时执行某些操作。在撰写本文时，这些仍然相当慢，除非是在我们不担心时间敏感的对象上，否则不应该真正使用它们。我们不打算对它们进行详细讨论，但对于那些想要了解它们的读者来说，它们是可用的。

# 资源分配即初始化（RAII）

RAII 的概念来自 C++，在那里我们没有内存管理器。我们封装逻辑，可能希望共享需要在使用后释放的资源。这确保我们没有内存泄漏，并且正在使用该项的对象是以安全的方式进行的。这个概念的另一个名称是**scope-bound resource management**（**SBRM**），也在另一种最近的语言 Rust 中使用。

我们可以在 JavaScript 代码中应用与 C++和 Rust 相同类型的 RAII 思想。我们可以处理这个问题的几种方法，我们将对它们进行讨论。第一种方法是，当我们将一个对象传递给一个函数时，我们可以从调用函数中将该对象`null`掉。

现在，我们将不得不在大多数情况下使用`let`而不是`const`，但这是一种有用的范式，可以确保我们只保留我们需要的对象。

这个概念可以在以下代码中看到：

```js
const getData = function() {
    return document.getElementById('container').value;
};
const encodeData = function(data) {
    let te = new TextEncoder();
    return te.encode(data);
};
const hashData = function(algorithm) {
    let str = getData();
    let finData = encodeData(str);
    str = null;
    return crypto.subtle.digest(algorithm, finData);
};
{
    let but = document.getElementById('submit');
    but.onclick = function(ev) {
        let algos = ['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512'];
        let out = document.getElementById('output');
        for(let i = 0; i < algos.length; i++) {
            const newEl = document.createElement('li');
            hashData(algos[i]).then((res) => {
                let te = new TextDecoder();
                newEl.textContent = te.decode(res);
                out.append(newEl);
            });
        }
        out = null;
    }
    but = null;
}
```

如果我们运行以下代码，我们会注意到我们正在尝试追加到一个`null`。这就是这种设计可能会让我们陷入麻烦的地方。我们有一个异步方法，我们正在尝试使用一个我们已经使无效的值，尽管我们仍然需要它。处理这种情况的最佳方法是什么？一种方法是在使用完毕后将其`null`掉。因此，我们可以将代码更改为以下内容：

```js
for(let i = 0; i < algos.length; i++) {
    let temp = out;
    const newEl = document.createElement('li');
    hashData(algos[i]).then((res) => {
        let te = new TextDecoder();
        newEl.textContent = te.decode(res);
        temp.append(newEl);
        temp = null
    });
}
```

我们仍然有一个问题。在`Promise`的下一部分（`then`方法）运行之前，我们仍然可以修改值。一个最后的好主意是将此输入输出包装在一个新函数中。这将给我们所寻找的安全性，同时也确保我们遵循 RAII 背后的原则。以下代码是由此产生的：

```js
const showHashData = function(parent, algorithm) {
    const newEl = document.createElement('li');
    hashData(algorithm).then((res) => {
        let te = new TextDecoder();
        newEl.textContent = te.decode(res);
        parent.append(newEl);
    });
}
```

我们还可以摆脱一些之前的 null，因为函数将处理这些临时变量。虽然这个例子相当琐碎，但它展示了在 JavaScript 中处理 RAII 的一种方式。

除此范式之外，我们还可以向传递的项目添加属性，以表明它是只读版本。这将确保我们不会修改该项目，但如果我们仍然想从中读取，我们也不需要在调用函数上将元素`null`掉。这使我们能够确保我们的对象可以被利用和维护，而不必担心它们会被修改。

我们将删除以前的代码示例，并更新它以利用这个只读属性。我们首先定义一个函数，将其添加到任何传入的对象中，如下所示：

```js
const addReadableProperty = function(item) {
    Object.defineProperty(item, 'readonly', {
        value : true,
        writable :false
    });
    return item;
}
```

接下来，在我们的`onclick`方法中，我们将输出传递给此方法。现在，它已经附加了`readonly`属性。最后，在我们的`showHashData`函数中，当我们尝试访问它时，我们已经在`readonly`属性上设置了保护。如果我们注意到对象具有它，我们将不会尝试追加到它，就像这样：

```js
if(!parent.readonly ) {
    parent.append(newEl);
}
```

我们还将此属性设置为不可写，因此如果一个恶意的行为者决定操纵我们对象的`readonly`属性，他们仍然会注意到我们不再向 DOM 追加内容。`defineProperty`方法非常适用于编写无法轻易操纵的 API 和库。另一种处理方法是冻结对象。使用`freeze`方法，我们可以确保对象的浅拷贝是只读的。请记住，这仅适用于浅实例，而不适用于持有引用类型的任何其他属性。

最后，我们可以利用计数器来查看是否可以设置数据。我们基本上正在创建一个读取端锁。这意味着在读取数据时，我们不希望设置数据。这意味着我们必须采取许多预防措施，以确保我们在读取所需内容后正确释放数据。这可能看起来像下面这样：

```js
const ReaderWriter = function() {
    let data = {};
    let readers = 0;
    let readyForSet = new CustomEvent('readydata');
    this.getData = function() {
        readers += 1;
        return data;
    }
    this.releaseData = function() {
        if( readers ) {
            readers -= 1;
            if(!readers ) {
                document.dispatchEvent(readyForSet);
            }
        }
        return readers;
    }
    this.setData = function(d) {
        return new Promise((resolve, reject) => {
            if(!readers ) {
                data = d;
                resolve(true);
            } else {
                document.addEventListener('readydata', function(e) {
                    data = d;
                    resolve(true);
                }, { once : true });
            }
        });
    }
}
```

我们所做的是设置一个构造函数。我们将数据、读者数量和自定义事件作为私有变量保存。然后创建三种方法。首先，`getData`将获取数据，并为使用它的人添加一个计数器。接下来是`release`方法。这将递减计数器，如果计数器为 0，我们将触发一个事件，告诉`setData`事件可以最终写入可变状态。最后是`setData`函数。返回值将是一个 promise。如果没有人持有数据，我们将立即设置并解析它。否则，我们将为我们的自定义事件设置一个事件监听器。一旦触发，我们将设置数据并解析 promise。

现在，这种锁定可变数据的最终方法不应该在大多数情况下使用。可能只有少数情况下你会想要使用它，比如热缓存，我们需要确保在读者从中读取时不要覆盖某些东西（这在 Node.js 方面尤其可能发生）。

所有这些方法都有助于创建一个安全的可变状态。通过这些方法，我们能够直接改变对象并共享内存空间。大多数情况下，良好的文档和对数据的谨慎控制将使我们不需要采取我们在这里所做的极端措施，但是当我们发现某些问题出现并且我们正在改变不应该改变的东西时，拥有这些 RAII 方法是很好的。

大多数情况下，不可变和高度函数式的代码最终会更易读，如果某些东西不需要高度优化，建议以易读性为重。但是，在高度优化的情况下，例如编码和解码或装饰表中的列，我们需要尽可能地提高性能。这将在本书的后面部分看到，我们将利用各种编程技术的混合。

尽管可变编程可能很快，但有时我们希望以函数方式实现事物。接下来的部分将探讨以这种函数方式实现程序的方法。

# 函数式编程风格

即使我们谈论了关于函数概念在原始速度方面不是最佳的，但在 JavaScript 中利用它们仍然可能非常有帮助。有许多语言不是纯函数式的，所有这些语言都给了我们利用许多范式的最佳思想的能力。例如 F#和 Scala 等语言。在这种编程风格方面有一些很棒的想法，我们可以利用 JavaScript 中的内置概念。

# 惰性评估

在 JavaScript 中，我们可以进行所谓的惰性评估。惰性评估意味着程序不运行不需要的部分。一个思考这个问题的方式是，当有人得到一个问题的答案列表，并被告知把正确的答案放在问题的答案列表中。如果他们发现答案是他们查看的第二个项目，他们就不会继续查看他们得到的其他答案；他们会在第二个项目处停下来。我们在 JavaScript 中使用惰性评估的方式是使用生成器。

生成器是一种函数，它会暂停执行，直到在它们上调用`next`方法。一个简单的例子如下所示：

```js
const simpleGenerator = function*() {
    let it = 0;
    for(;;) {
        yield it;
        it++;
    }
}

const sg = simpleGenerator();
for(let i = 0; i < 10; i++) {
    console.log(sg.next().value);
}
sg.return();
console.log(sg.next().value);
```

首先，我们注意到`function`旁边有一个星号。这表明这是一个生成器函数。接下来，我们设置一个简单的变量来保存我们的值，然后我们有一个无限循环。有些人可能会认为这将持续运行，但惰性评估表明我们只会运行到`yield`。这个`yield`意味着我们将在这里暂停执行，并且我们可以获取我们发送回来的值。

所以，我们启动函数。我们没有什么要传递给它，所以我们只是简单地启动它。接下来，我们在生成器上调用`next`并获取值。这给了我们一个单独的迭代，并返回`yield`语句上的任何内容。最后，我们调用`return`来表示我们已经完成了这个生成器。如果我们愿意，我们可以在这里获取最终值。

现在，我们会注意到当我们调用`next`并尝试获取值时，它返回了 undefined。我们可以看一下生成器，并注意到它有一个叫做`done`的属性。这可以让我们看到有限生成器是否已经完成。那么当我们想要做一些事情时，这怎么会有帮助呢？一个相当琐碎的例子是一个计时函数。我们将在想要计时的东西之前启动计时器，然后我们将再次调用它来计算某个东西运行所花费的时间（与`console.time`和`timeEnd`非常相似，但它应该展示了生成器的可用性）。

这个生成器可能看起来像下面这样：

```js
const timing = function*(time) {
    yeild Date.now() - time;
}
const time = timing(Date.now());
let sum = 0;
for(let i = 0; i < 1000000; i++) {
    sum = sum + i;
}
console.log(time.next().value);
```

我们现在正在计时一个简单的求和函数。所有这个函数做的就是用当前时间初始化计时生成器。一旦调用下一个函数，它就会运行到`yield`语句并返回`yield`中保存的值。这将给我们一个新的时间与我们传入的时间进行比较。现在我们有了一个用于计时的简单函数。这对于我们可能无法访问控制台并且需要在其他地方记录这些信息的环境特别有用。

就像前面的代码块所示，我们也可以使用许多不同类型的惰性加载。其中利用这个接口的最好类型之一是流。流在 Node.js 中已经有一段时间了，但是浏览器的流接口有一个基本的标准化，某些部分仍在讨论中。这种类型的惰性加载或惰性读取的一个简单例子可以在下面的代码中看到：

```js
const nums = function*(fn=null) {
    let i = 0;
    for(;;) {
        yield i;
        if( fn ) {
            i += fn(i);
        } else {
            i += 1;
        }
    }
}
const data = {};
const gen = nums();
for(let i of gen) {
    console.log(i);
    if( i > 100 ) {
        break;
    }
    data.push(i);
}

const fakestream = function*(data) {
    const chunkSize = 10;
    const dataLength = data.length;
    let i = 0;
    while( i < dataLength) {
        const outData = [];
        for(let j = 0; j < chunkSize; j++) {
            outData.push(data[i]);
            i+=1;
        }
        yield outData;
    }
}

for(let i of fakestream(data)) {
    console.log(i);
}
```

这个例子展示了惰性评估的概念，以及我们将在后面章节中看到的流的一些概念。首先，我们创建一个生成器，它可以接受一个函数，并可以利用它来创建我们的逻辑函数中的数字。在我们的例子中，我们只会使用默认情况，并且让它一次生成一个数字。接下来，我们将通过`for/of`循环运行这个生成器，以生成 101 个数字。

接下来，我们创建一个`fakestream`生成器，它将为我们分块数据。这类似于流，允许我们一次处理一块数据。我们可以对这些数据进行转换（称为`TransformStream`），或者只是让它通过（称为`PassThrough`的一种特殊类型的`TransformStream`）。我们在`10`处创建一个假的块大小。然后我们再次对之前的数据运行另一个`for/of`循环，并简单地记录它。但是，如果我们愿意，我们也可以对这些数据做些什么。

这不是流使用的确切接口，但它展示了我们如何在生成器中实现惰性求值，并且这也内置在某些概念中，比如流。生成器和惰性求值技术还有许多其他潜在的用途，这里不会涉及，但对于寻求更功能式风格的列表和映射理解的开发人员来说，它们是可用的。

# 尾递归优化

这是许多功能性语言具有的另一个概念，但大多数 JavaScript 引擎没有（WebKit 是个例外）。尾递归优化允许以一定方式构建的递归函数运行得就像一个简单的循环一样。在纯函数语言中，没有循环这样的东西，所以处理集合的唯一方法是通过递归进行。我们可以看到，如果我们将一个函数构建为尾递归函数，它将破坏我们的堆栈。以下代码说明了这一点：

```js
const _d = new Array(100000);
for(let i = 0; i < _d.length; i++) {
    _d[i] = i;
}
const recurseSummer = function(data, sum=0) {
    if(!data.length ) {
        return sum;
    }
    return recurseSummer(data.slice(1), sum + data[0]);
}
console.log(recurseSummer(_d));
```

我们创建了一个包含 100,000 个项目的数组，并为它们分配了它们索引处的值。然后我们尝试使用递归函数来对数组中的所有数据进行求和。由于函数的最后一次调用是函数本身，一些编译器能够在这里进行优化。如果它们注意到最后一次调用是对同一个函数的调用，它们知道当前的堆栈可以被销毁（函数没有剩余工作要做）。然而，非优化的编译器（大多数 JavaScript 引擎）不会进行这种优化，因此我们不断向我们的调用系统添加堆栈。这导致调用堆栈大小超出限制，并使我们无法利用这个纯粹的功能概念。

然而，JavaScript 还是有希望的。一个叫做 trampolining 的概念可以通过修改函数和我们调用它的方式来实现尾递归。以下是修改后的代码，以利用 trampolining 并得到我们想要的结果：

```js
const trampoline = (fun) => {
    return (...arguments) => {
        let result = fun(...arguments);
        while( typeof result === 'function' ) {
            result = result();
        }
        return result;
    }
}

const _d = new Array(100000);
for(let i = 0; i < _d.length; i++) {
    _d[i] = i;
}
const recurseSummer = function(data, sum=0) {
    if(!data.length ) {
        return sum;
    }
    return () => recurseSummer(data.slice(1), sum + data[0]);
}
const final = trampoline(recurseSummer);
console.log(final(_d));
```

我们所做的是将我们的递归函数包装在一个我们通过简单循环运行的函数中。`trampoline`函数的工作方式如下：

+   它接受一个函数，并返回一个新构造的函数，该函数将运行我们的递归函数，但通过循环进行检查返回类型。

+   在这个内部函数中，它通过执行函数的第一次运行来启动循环。

+   当我们仍然将一个函数作为我们的返回类型时，它将继续循环。

+   一旦我们最终得到了一个函数，我们将返回结果。

现在我们能够利用尾递归来做一些在纯粹的功能世界中会做的事情。之前看到的一个例子（可以看作是一个简单的 reduce 函数）是一个例子。

```js
const recurseFilter = function(data, con, filtered=[]) {
    if(!data.length ) {
        return filtered;
    }
    return () => recurseFilter(data.slice(1), con, con(data[0]) ? 
     filtered.length ? new Array(...filtered), data[0]) : [data[0]] : filtered);

const finalFilter = trampoline(recurseFilter);
console.log(finalFilter(_d, item => item % 2 === 0));
```

通过这个函数，我们模拟了纯函数语言中基于过滤的操作可能是什么样子。同样，如果没有长度，我们就到达了数组的末尾，并返回我们过滤后的数组。否则，我们返回一个新函数，该函数用一个新列表、我们要进行过滤的函数以及过滤后的列表递归调用自身。这里有一些奇怪的语法。如果我们有一个空列表，我们必须返回一个带有新项的单个数组，否则，它将给我们一个包含我们传入的项目数量的空数组。

我们可以看到，这两个函数都通过了尾递归的检查，并且也是纯函数语言中可以编写的函数。但是，我们也会看到，这些函数运行起来比简单的`for`循环甚至这些类型函数的内置数组方法要慢得多。归根结底，如果我们想要使用尾递归来编写纯粹的函数式编程，我们可以，但在 JavaScript 中这样做是不明智的。

# 柯里化

我们将要看的最后一个概念是柯里化。柯里化是一个接受多个参数的函数实际上是一系列接受单个参数并返回另一个函数或最终值的函数。让我们看一个简单的例子来看看这个概念是如何运作的：

```js
const add = function(a) {
    return function(b) {
        return a + b;
    }
}
```

我们正在接受一个接受多个参数的函数，比如`add`函数。然后我们返回一个接受单个参数的函数，这里是`b`。这个函数然后将数字`a`和`b`相加。这使我们能够像通常一样使用函数（除了我们运行返回给我们的函数并传入第二个参数），或者我们得到运行它的返回值，并使用该函数来添加接下来的任何值。这些概念中的每一个都可以在以下代码中看到：

```js
console.log(add(2)(5), 'this will be 7');
const add5 = add(5);
console.log(add5(5), 'this will be 10');
```

柯里化有一些用途，它们也展示了一个可以经常使用的概念。首先，它展示了部分应用的概念。这样做是为我们设置一些参数并返回一个函数。然后我们可以将这个函数传递到语句链中，并最终用它来填充剩下的函数。

只需记住，所有柯里化函数都是部分应用函数，但并非所有部分应用函数都是柯里化函数。

部分应用的示例可以在以下代码中看到：

```js
const fullFun = function(a, b, c) {
    console.log('a', a);
    console.log('b', b);
    console.log('c', c);
}
const tempFun = fullFun.bind(null, 2);
setTimeout(() => {
    const temp2Fun = tempFun.bind(null, 3);
    setTimeout(() => {
        const temp3Fun = temp2Fun.bind(null, 5);
        setTimeout() => {
            console.log('temp3Fun');
            temp3Fun();
        }, 1000);
    }, 1000);
    console.log('temp2Fun');
    temp2Fun(5);
}, 1000);
console.log('tempFun');
tempFun(3, 5);
```

首先，我们创建一个接受三个参数的函数。然后我们创建一个新的临时函数，将`2`绑定到该函数的第一个参数。`Bind`是一个有趣的函数。它将我们想要的作用域作为第一个参数（`this`指向的内容），然后接受任意长度的参数来填充我们正在处理的函数的参数。在我们的例子中，我们只将第一个变量绑定到数字`2`。然后我们创建一个第二个临时函数，其中我们将第一个临时函数的第一个变量绑定到`3`。最后，我们创建一个第三个临时函数，其中我们将第二个函数的第一个参数绑定到数字`5`。

我们可以在每次运行时看到，我们能够运行这些函数中的每一个，并且它们根据我们使用的函数版本不同而接受不同数量的参数。`bind`是一个非常强大的工具，它允许我们传递函数，这些函数可能会在最终使用函数之前从其他函数中获取参数填充。

柯里化是我们将使用部分应用，但我们将用多个嵌套函数组成多参数函数的概念。那么柯里化给我们带来了什么，而其他概念无法做到呢？如果我们处于纯函数世界，实际上我们可以得到很多。例如，数组上的`map`函数。它希望一个单个项目的函数定义（我们将忽略通常不使用的其他参数），并希望函数返回一个单个项目。当我们有一个像下面这样的函数，并且它可以在`map`函数中使用，但它有多个参数时会发生什么？以下代码展示了我们可以用柯里化和这种用例做些什么：

```js
const calculateArtbitraryValueWithPrecision = function(prec=0, val) {
    return function(val) {
        return parseFloat((val / 1000).toFixed(prec));
    }
}
const arr = new Array(50000);
for(let i = 0; i < arr.length; i++) {
    arr[i] = i + 1000;
}
console.log(arr.map(calculatorArbitraryValueWithPrecision(2)));
```

我们正在接受一个通用函数（甚至是任意的），并通过使其更具体（在本例中是保留两位小数）在`map`函数中使用它。这使我们能够编写非常通用的函数，可以处理任意数据并从中制作特定的函数。

我们将在我们的代码中使用部分应用，并且可能会使用柯里化。然而，总的来说，我们不会像在纯函数式语言中那样使用柯里化，因为这可能会导致减速和更高的内存消耗。最重要的是要理解部分应用和外部作用域变量如何在内部作用域位置中使用的概念。

这三个概念对于纯函数式编程的理念非常关键，但我们将不会利用其中大部分。在高性能代码中，我们需要尽可能地提高速度和内存利用率，而其中大部分构造占用的资源超出了我们的承受范围。某些概念可以在高性能代码中大量使用。以下内容将在后续章节中使用：部分应用、流式/惰性求值，可能还有一些递归。熟悉函数式代码将有助于在使用利用这些概念的库时更加得心应手，但正如我们长时间讨论过的那样，它们并不像我们的迭代方法那样高性能。

# 总结

在本章中，我们已经了解了可变性和不可变性的概念。我们已经看到不可变性可能会导致减速和更高的内存消耗，并且在编写高性能代码时可能会成为一个问题。我们已经看了可变性以及如何确保我们编写的代码利用了它，但也使其安全。除此之外，我们还进行了可变和不可变代码的性能比较，并看到了不可变类型的速度和内存消耗增加的情况。最后，我们看了 JavaScript 中的函数式编程以及我们如何利用这些概念。函数式编程可以帮助解决许多问题，比如无锁并发，但我们也知道 JavaScript 运行时是单线程的，因此这并没有给我们带来优势。总的来说，我们可以从不同的编程范式中借鉴许多概念，拥有这些概念可以使我们成为更好的程序员，并帮助我们编写干净、安全和高性能的代码。

在下一章中，我们将看一下 JavaScript 作为一种语言是如何发展的。我们还将看一下浏览器是如何改变以满足开发人员的需求的，新的 API 涵盖了从访问 DOM 到长期存储的所有内容。


# 第三章：Vanilla Land - 看现代 Web

自 ECMAScript 2015 标准发布以来，JavaScript 语言的格局发生了很大变化。现在有许多新功能使 JavaScript 成为各种开发的一流语言。使用该语言变得更容易，我们现在甚至可以看到一些语法糖。

从 ECMAScript 2015 标准及以后，我们已经获得了类、模块、更多声明变量的方式、作用域的变化等。所有这些特性等等将在本章的其余部分进行解释。如果您对该语言还不熟悉，或者只是想了解一下可能不熟悉的特性，这是一章值得阅读的好章节。我们还将看一下一些旧的 Web 部分，如 DOM 查询，以及我们如何利用它们来替换我们可能当前正在使用的多余库，如 jQuery。

在本章中，将涵盖以下主题：

+   深入现代 JavaScript

+   理解类和模块

+   与 DOM 一起工作

+   理解 Fetch API

# 技术要求

本章的先决条件如下：

+   诸如 VS Code 之类的编辑器

+   一个使用 Node.js 的系统

+   一个浏览器，最好是 Chrome

+   对 JavaScript 及其作用域的一般理解

+   相关代码可以在[`github.com/PacktPublishing/Hands-On-High-Performance-Web-Development-with-JavaScript/tree/master/Chapter03`](https://github.com/PacktPublishing/Hands-On-High-Performance-Web-Development-with-JavaScript/tree/master/Chapter03)找到。

# 深入现代 JavaScript

如介绍中所述，语言在许多方面都有所改进。我们现在有了适当的作用域，更好地处理`async`操作，更多的集合类型，甚至元编程特性，如反射和代理。所有这些特性都导致了更复杂的语言，但也导致了更有效的问题解决。我们将看一下新标准中出现的一些最佳项，以及它们在我们的代码中可以用来做什么。

另一个需要注意的是，未来显示的任何 JavaScript 代码都可以通过以下方式运行：

1.  通过按下键盘上的*F12*将其添加到开发者控制台

1.  利用开发者控制台中可以在“Sources”选项卡中看到的片段，在左侧面板中应该有一个名为“Snippets”的选项

1.  编写一个基本的`index.html`，其中添加了一个脚本元素

# Let/const 和块作用域

在 ECMAScript 2015 之前，我们只能使用`var`关键字来定义变量。`var`关键字的生命周期从函数声明到函数结束。这可能会导致很多问题。以下代码展示了我们可能在`var`关键字中遇到的问题之一：

```js
var fun = function() {
    for(var i = 0; i < 10; i++) {
        state['this'] += 'what';
    }
    console.log('i', i);
}
fun();
```

控制台会打印出什么？在大多数语言中，我们可能会猜想这是一个错误，或者会打印`null`。然而，JavaScript 的`var`关键字是函数作用域的，所以变量`i`将是`10`。这导致了许多错误的出现，因为意外地忘记声明变量，甚至可怕的`switch`语句错误（这些错误仍然会发生在`let`和`const`中）。`switch`语句错误的一个例子如下：

```js
var x = 'a';
switch(x) {
    case 'a':
        y = 'z';
        break;
    case 'b':
        y = 'y';
        break;
    default:
        y = 'b';
}
console.log(y);
```

从前面的`switch`语句中，我们期望`y`是`null`，但因为`var`关键字不是块作用域的，它将是字母`z`。我们总是必须掌握变量并确保我们没有使用在我们范围之外声明的东西并改变它，或者我们确保我们重新声明变量以阻止泄漏发生。

使用`let`和`const`，我们得到了块作用域。这意味着花括号告诉我们变量应该存在多久。这里有一个例子：

```js
let x = 10;
let fun2 = function() {
    {
        let x = 20;
        console.log('inner scope', x);
    }
    console.log('outer scope', x);
    x += 10;
}
fun2();
console.log('this should be 20', x);
```

当我们查看变量`x`的打印输出时，我们可以看到我们首先在函数外部将其声明为`10`。在函数内部，我们使用大括号创建了一个新的作用域，并将`x`重新声明为`20`。在块内部，代码将打印出`inner scope 20`。但是，在`fun2`内部的块之外，我们打印出`x`，它是`10`。`let`关键字遵循此块作用域。如果我们将变量声明为`var`，则第二次打印时它将保持为`20`。最后，我们将`10`添加到外部的`x`，我们应该看到`x`是`20`。

除了获得块作用域之外，`const`关键字还赋予了我们一些不可变性。如果我们正在使用的类型是值类型，我们将无法改变该值。如果我们有一个引用类型，引用内部的值可以被改变，但是我们不能改变引用本身。这带来了一些很好的功能。

一个很好的编码风格是尽可能多地使用`const`，只有在需要在基本级别上改变某些东西时才使用`let`，比如循环。由于对象、数组或函数的值可以被改变，我们可以将它们设置为`const`。唯一的缺点是它们不能被置空，但它仍然在可能的性能增益之上增加了相当多的安全性，编译器可以利用知道一个值是不可变的。

# 箭头函数

语言的另一个显著变化是添加了箭头函数。有了这个，我们现在可以在不使用语言上的各种技巧的情况下改变`this`。可以看到以下示例：

```js
const create = function() {
    this.x = 10;
    console.log('this', this);
    const innerFun = function() {
        console.log('inner this', this);
    }
    const innerArrowFun = () => {
        console.log('inner arrow this', this);
    }
    innerFun();
    innerArrowFun();
}
const item = new create();
```

我们正在为一个新对象创建一个构造函数。我们有两个内部函数，一个是基本函数调用，另一个是箭头函数。当我们打印这个时，我们注意到基本函数打印出了窗口的作用域。当我们打印内部箭头函数的作用域时，我们得到了父级的作用域。

我们可以通过几种方式来解决基本内部函数的问题。首先，我们可以在父级中声明一个变量，并在内部函数中使用它。此外，当我们运行函数时，我们可以使用 call 或`apply`来实际运行函数。

然而，这两种方法都不是一个好主意，特别是当我们现在有箭头函数时。要记住的一个关键点是箭头函数获取父级的作用域，所以无论`this`指向父级的什么，我们现在都将在箭头函数内部执行相同的操作。现在，我们可以通过在箭头函数上使用`apply`来始终更改它，但最好只使用`apply`等来进行部分应用，而不是通过更改其`this`关键字来调用函数。

# 集合类型

数组和对象一直是 JavaScript 开发人员使用的两种主要类型。但是，现在我们有了另外两种集合类型，可以帮助我们做一些我们过去使用这些其他类型的事情。这些是 set 和 map。set 是一个无序的唯一项集合。这意味着如果我们试图将已经存在的东西放入 set 中，我们会注意到我们只有一个单一项。我们可以很容易地用数组模拟一个 set，如下所示：

```js
const set = function(...items) {
   this._arr = [...items];
   this.add = function(item) {
       if( this._arr.includes(item) ) return false;
       this._arr.push(item);
       return true;
   }
   this.has = function(item) {
       return this._arr.includes(item);
   }
   this.values = function() {
       return this._arr;
   }
   this.clear = function() {
       this._arr = [];
   }
}
```

由于我们现在有了 set 系统，我们可以直接使用该 API。我们还可以访问`for of`循环，因为 set 是一个可迭代项（如果我们获取附加到 set 的迭代器，我们也可以使用下一个语法）。与数组相比，当我们处理大型数据集时，set 在读取访问速度上也具有优势。以下示例说明了这一点：

```js
const data = new Array(10000000);
for(let i = 0; i < data.length; i++) {
    data[i] = i;
}
const setData = new Set();
for(let i = 0; i < data.length; i++) {
    setData.add(i);
}
data.includes(5000000);
setData.has(5000000);
```

尽管创建 set 需要一些时间，但是当查找项目或甚至获取它们时，set 的性能几乎比数组快 100 倍。这主要是由于数组查找项目的方式。由于数组是纯线性的，它必须遍历每个元素进行检查，而 set 是一个简单的常量时间检查。

集合可以根据引擎的不同方式实现。V8 引擎中的集合是利用哈希字典进行查找构建的。我们不会详细介绍这些内部情况，但基本上，查找时间被认为是常数，或者对于计算机科学家来说是*O(1)*，而数组查找时间是线性的，或者*O(n)*。

除了集合，我们还有地图。我们可以将它们视为普通对象，但它们有一些很好的属性：

+   首先，我们可以使用任何值作为键，甚至是对象。这对于添加我们不想直接绑定到对象的其他数据非常有用（私有值浮现在脑海中）。

+   除此之外，地图也是可迭代的，因此我们可以像集合一样利用`for of`循环。

+   最后，地图可以在大型数据集和键和值类型相同的情况下为我们带来性能优势。

以下示例突出了地图通常比普通对象更好的许多领域，以及曾经使用对象的领域：

```js
const map = new Map();
for(let i = 0; i < 10000; i++) {
    map.set(`${i}item`, i);
}
map.forEach((val, key) => console.log(val));
map.size();
map.has('0item');
map.clear();
```

除了这两个项目，我们还有它们的弱版本。弱版本有一个主要限制：值必须是对象。一旦我们了解了`WeakSet`和`WeakMap`的作用，这就说得通了。它们*弱地*存储对项目的引用。这意味着当它们存储的项目存在时，我们可以执行这些接口给我们的方法。一旦垃圾收集器决定收集它们，引用将从弱版本中删除。我们可能会想，为什么要使用这些？

对于`WeakMap`，有一些用例：

+   首先，如果我们没有私有变量，我们可以利用`WeakMap`在对象上存储值，而实际上不将属性附加到它们上。现在，当对象最终被垃圾收集时，这个私有引用也会被回收。

+   我们还可以利用弱映射将属性或数据附加到 DOM，而实际上不必向 DOM 添加属性。我们可以获得数据属性的所有好处，而不会使 DOM 混乱。

+   最后，如果我们想要将引用数据存储到一边，但在数据消失时使其消失，这是另一个用例。

总的来说，当我们想要将某种数据与对象绑定而不需要紧密耦合时，我们会使用`WeakMap`。我们将能够看到这一点，如下所示：

```js
const items = new WeakMap();
const container = document.getElementById('content');
for(let i = 0; i < 50000; i++) {
    const el = document.createElement('li');
    el.textContent = `we are element ${i}`;
    el.onclick = function(ev) {
        console.log(items.get(el));
    }
    items.set(el, i);
    container.appendChild(el);
}
const removeHalf = function() {
    const amount = Math.floor(container.children.length / 2);
    for(let i = 0; i < amount; i++) {
        container.removeChild(container.firstChild); 
    }
}
```

首先，我们创建一个`WeakMap`来存储我们想要针对创建的 DOM 元素的数据。接下来，我们获取我们的无序列表，并在每次迭代中添加一个列表元素。然后，我们通过`WeakMap`将我们所在的数字与 DOM 元素联系起来。这样，`onclick`处理程序就可以获取该项并取回我们存储在其中的数据。

有了这个，我们可以点击任何元素并取回数据。这很酷，因为我们过去直接在 DOM 中向 HTML 元素添加数据属性。现在我们可以使用`WeakMap`。但是，我们还有一个更多的好处，这已经被讨论过。如果我们在命令行中运行`removeHalf`函数并进行垃圾收集，我们可以看一下`WeakMap`中有多少项。如果我们这样做，并检查`WeakMap`中有多少元素，我们会注意到它存储的元素数量可以从 25,000 到我们开始的完整 50,000 个元素。这是由于上面所述的原因；一旦引用被垃圾收集，`WeakMap`将不再存储它。它具有弱引用。

垃圾收集器要收集的数量将取决于我们正在运行的系统。在某些系统上，垃圾收集器可能决定不从列表中收集任何内容。这完全取决于 Chrome 或 Node.js 中的 V8 垃圾收集是如何设置的。

如果我们用普通的`WeakMap`替换它，我们很容易看到这一点。让我们继续进行这个小改变。通过这个改变，观察同样的步骤。我们会注意到地图仍然有 50,000 个项目。这就是我们所说的，当我们说某物有强引用或弱引用时的意思。弱引用将允许垃圾收集器清理项目，而强引用则不会。*WeakMaps*非常适合这种数据与另一个数据源的链接。如果我们希望在主对象被清理时清理项目装饰或链接，`WeakMap`是一个不错的选择。

`WeakSet`有一个更有限的用例。一个很好的用例是检查对象属性或图中的无限循环。如果我们将所有访问过的节点存储在`WeakSet`中，我们就能够检查我们是否有这些项目，但我们也不必在检查完成后清除集合。这意味着一旦数据被收集，存储在`WeakSet`中的所有引用也将被收集。总的来说，当我们需要标记一个对象或引用时，应该使用`WeakSet`。这意味着如果我们需要查看我们是否拥有它或它是否被访问过，`WeakSet`很可能是这项工作的合适选择。

我们可以利用上一章的深拷贝示例。通过它，我们还遇到了一个我们没有考虑到的用例。如果一个项目指向对象中的另一个项目，并且同一个项目决定再次指向原始项目，会发生什么？这可以在以下代码中看到：

```js
const a = {item1 : b};
const b = {item1 : a};
```

如果每个项目都指向彼此，我们将遇到循环引用的问题。解决这个问题的方法是使用`WeakSet`。我们可以保存所有访问过的节点，如果我们遇到一个已经访问过的节点，我们就从函数中返回。这可以在代码的修改版本中看到：

```js
const state = {};
(function(scope) {
    const _state = {},
          _held = new WeakSet(),
          checkPrimitives = function(item) {
              return item === null || typeof item === 'string' || typeof 
               item === 'number' || typeof item === 'boolean' ||
               typeof item === 'undefined';
          },
          cloneFunction = function(fun, scope=null) {
              return fun.bind(scope);
          },
          cloneObject = function(obj) {
              const newObj = {},
              const keys = Object.keys(obj);
              for(let i = 0; i < keys.length; i++) {
                  const key = keys[i];
                  const item = obj[key];
                  newObj[key] = runUpdate(item);
              }
              return newObj;
          },
          cloneArray = function(arr) {
              const newArr = new Array(arr.length);
              for(let i = 0; i < arr.length; i++) {
                  newArr[i] = runUpdate(arr[i]);
              }
              return newArr;
          },
          runUpdate = function(item) {
              if( checkPrimitives(item) ) {
                  return item;
              }
              if( typeof item === 'function' ) {
                  return cloneFunction(item);
              }
              if(!_held.has(item) ) {
                  _held.add(item);
                  if( item instanceof Array ) {
                      return cloneArray(item);
                  } else {
                      return cloneObject(item);
                  }
              }
          };
    scope.update = function(obj) {
        const x = Object.keys(obj);
        for(let i = 0; i < x.length; i++) {
            _state[x[i]] = runUpdate(obj[x[i]]);
        }
        _held = new WeakSet();
    }
})(state);
Object.freeze(state);
```

正如我们所看到的，我们已经添加了一个新的`_held`变量，它将保存我们所有的引用。然后，`runUpdate`函数已经被修改，以确保当一个项目不是原始类型或函数时，我们检查我们的`held`列表中是否已经有它。如果有，我们就跳过这个项目，否则我们将继续进行。最后，我们用一个新的`WeakSet`替换了`_held`变量，因为在*WeakSets*上`clear`方法不再可用。

这并不会保留循环引用，这可能是一个问题，但它解决了因对象相互引用而导致系统陷入无限循环的问题。除了这种用例，也许还有一些更高级的想法，`WeakSet`并没有太多其他的需求。主要的是，如果我们需要跟踪某物的存在。如果我们需要这样做，`WeakSet`就是我们的完美用例。

大多数开发人员不会发现需要*WeakSets*或*WeakMaps*。这些可能会被库作者使用。然而，之前提到的约定在某些情况下可能会出现，因此了解这些项目的原因和存在的意义是很好的。如果我们没有使用某物的理由，那么我们很可能不应该使用它，这在这两个项目中绝对是这样，因为它们有非常具体的用例，而*WeakMaps*的主要用例之一是在 ECMAScript 标准中提供给我们的（私有变量）。

# 反射和代理

我们要讨论的 ECMAScript 标准的最后一个重要部分是两个元编程对象。元编程是指生成代码的技术。这可能是用于编译器或解析器等工具。它也可以用于自我改变的代码。甚至可以用于运行时评估另一种语言（解释）并对其进行操作。虽然这可能是反射和代理给我们的主要功能，但它也使我们能够监听对象上的事件。

在上一章中，我们谈到了监听事件，并创建了一个`CustomEvent`来监听对象上的事件。好吧，我们可以改变那段代码，并利用代理来实现该行为。以下是处理对象上基本事件的一些基本代码：

```js
const item = new Proxy({}, {
    get: function(obj, prop) {
        console.log('getting the following property', prop);
        return Reflect.has(obj, prop) ? obj[prop] : null;
    },
    set: function(obj, prop, value) {
        console.log('trying to set the following prop with the following 
         value', prop, value);
        if( typeof value === 'string' ) {
            obj[prop] = value;
        } else {
            throw new Error('Value type is not a string!');
        }
    }
});
item.one = 'what';
item.two = 'is';
console.log(item.one);
console.log(item.three);
item.three = 12;
```

我们所做的是为这个对象的`get`和`set`方法添加了一些基本的日志记录。我们通过使`set`方法只接受字符串值，扩展了这个对象的功能。有了这个，我们创建了一个可以被监听的对象，并且我们可以对这些事件做出响应。

代理目前比向系统添加`CustomEvent`要慢。正如前面所述，尽管代理在 ECMAScript 2015 标准中，但它们的采用速度很慢，因此浏览器需要更多时间来优化它们。另外，应该注意的是，我们不希望直接在这里运行日志记录。相反，我们选择让系统排队消息，并利用称为`requestIdleCallback`的东西，在浏览器注意到我们应用程序的空闲时间时运行我们的日志记录代码。这仍然是一项实验性技术，但应该很快添加到所有浏览器中。

代理的另一个有趣特性是可撤销方法。这是一个代理，我们最终可以说是被撤销的，当我们尝试在此方法调用后使用它时，会抛出`TypeError`。这对于任何试图使用对象实现 RAII 模式的人来说非常有用。我们可以撤销代理，而不再能够利用它，而不是试图将引用`null`掉。

这种 RAII 模式与空引用略有不同。一旦我们撤销了代理，所有引用将不再能够使用它。这可能会成为一个问题，但它也会给我们带来失败快速的额外好处，这在代码开发中总是一个很好的特性。这意味着当我们在开发中时，它会抛出`TypeError`，而不仅仅是传递一个空值。在这种情况下，只有 try-catch 块才能让这段代码继续运行，而不仅仅是简单的空检查。失败快速是保护我们自己在开发中并更早捕获错误的好方法。

这里展示了一个示例，修改了前面代码的版本：

```js
const isPrimitive = function(item) {
    return typeof item === 'string' || typeof item === 'number' || typeof 
     item === 'boolean';
}
const item2 = Proxy.revocable({}, {
    get: function(obj, prop) {
        return Reflect.has(obj, prop) ? obj[prop] : null
    },
    set: function(obj, prop, value) {
        if( isPrimitive(value) ) {
            obj[prop] = value;
        } else {
            throw new Error('Value type is not a primitive!');
        }
    }
});
const item2Proxy = item2.proxy;
item2Proxy.one = 'this';
item2Proxy.two = 12;
item2Proxy.three = true;
item2.revoke();
(function(obj) {
    console.log(obj.one);
})(item2Proxy);
```

现在，我们不仅在设置时抛出*TypeErrors*，一旦我们撤销代理，我们也会抛出`TypeError`。当我们决定编写能够保护自己的代码时，这对我们非常有用。当我们使用对象时，我们也不再需要在代码中编写一堆守卫子句。如果我们使用代理和可撤销代替，我们可以保护我们的设置。

我们没有深入讨论代理系统的术语。从技术上讲，我们在代理处理程序中添加的方法称为陷阱，类似于操作系统陷阱，但我们实际上可以将它们简单地视为简单的事件。有时，术语可能会给事情增加一些混乱，通常是不需要的。

除了代理，反射 API 是一堆静态方法，它们反映了代理处理程序。我们可以在某些熟悉的系统的位置使用它们，比如`Function.prototype.apply`方法。我们可以使用`Reflect.apply`方法，这在编写我们的代码时可能会更清晰一些。如下所示：

```js
Math.max.apply(null, [1, 2, 3]);
Reflect.apply(Math.max, null, [1, 2, 3]);
item3 = {};
if( Reflect.set(item3, 'yep', 12) {
    console.log('value was set correctly!');
} else {
    console.log('value was not set!');
}
Reflect.defineProperty(item3, 'readonly', {value : 42});
if( Reflect.set(item3, 'readonly', 'nope') ) {
    console.log('we set the value');
} else {
    console.log('value should not be set!');
}
```

正如我们所看到的，我们第一次在对象上设置了一个值，并且成功了。但是，第二个属性首先被定义，并且被设置为不可写（当我们使用`defineProperty`时的默认值），因此我们无法在其上设置一个值。

通过这两个 API，我们可以为访问对象编写一些不错的功能，甚至使变异尽可能安全。我们可以很容易地利用这两个 API 来使用 RAII 模式，甚至可以进行一些很酷的元编程。

# 其他值得注意的变化

随着 ECMAScript 标准的进步，出现了许多变化，我们可以专门讨论所有这些变化，但我们将在这里列出一些在本书中编写的代码中以及其他地方可能看到的变化。

# 展开运算符

展开运算符允许我们拆开数组，可迭代集合（如集合或映射），甚至是最新标准中的对象。这为我们提供了更美观的语法，用于执行一些常见操作，例如以下操作：

```js
// working with a variable amount of arguments
const oldVarArgs = function() {
    console.log('old variable amount of arguments', arguments);
}
const varArgs = function(...args) {
    console.log('variable amount of arguments', args);
}
// transform HTML list into a basic array so we have access to array
// operations
const domArr = [...document.getElementsByTagName('li')];
// clone array
const oldArr = [1, 2, 3, 4, 5];
const clonedArr = [...oldArr];
// clone object
const oldObj = {item1 : 'that', item2 : 'this'};
const cloneObj = {...oldObj};
```

以前的 `for` 循环和其他迭代版本现在变成了简单的一行代码。此外，第一个项目很好，因为它向代码的读者显示我们正在将函数用作变量参数函数。我们可以通过代码看到这一点，而不需要文档来说明这一点。

处理参数时，如果我们在函数中要对其进行任何改变，先创建一个副本，然后再进行改变。如果我们决定直接改变参数，会发生某些非优化。

# 解构

解构是将数组或对象的项目以更简单的方式传递给我们分配给的变量的过程。可以在以下代码中看到：

```js
//object
const desObj = {item1 : 'what', item2 : 'is', item3 : 'this'};
const {item1, item2} = desObj;
console.log(item1, item2);

//array
const arr = [1, 2, 3, 4, 5];
const [a, ,b, ...c] = arr;
console.log(a, b, c);
```

这两个示例展示了一些很酷的特性。首先，我们可以从对象中挑选我们想要的项目。我们还可以在左侧重新分配值为其他值。除此之外，我们甚至可以进行嵌套对象和解构。

对于数组，我们可以选择所有项目、部分项目，甚至通过将数组的其余部分放入变量来使用 `rest` 语法。在前面的示例中，`a` 将保存 `1`，`b` 将保存 `3`，`c` 将是一个包含 `4` 和 `5` 的数组。我们通过使该空间为空来跳过了 2。在其他语言中，我们会使用 `_` 来展示这一点，但在这里我们可以直接跳过它。同样，所有这些只是语法糖，使得能够编写更紧凑和更清晰的代码。

# 幂运算符

这里没有什么可说的，除了我们不再需要使用 `Math.pow()` 函数；我们现在有了幂运算符或 `**`，从而使代码更清晰，数学方程更美观。

# 参数默认值

这些允许我们在调用函数时为某个位置放入默认值。可以如下所示：

```js
const defParams = function(arg1, arg2=null, arg3=10) {
    if(!arg2 ) {
        console.log('nothing was passed in or we passed in a falsy value');
    }
    const pow = arg3;
    if( typeof arg1 === 'number' ) {
        return arg1 ** pow;
    } else {
        throw new TypeError('argument 1 was not a number!');
    }
}
```

需要注意的一点是，一旦我们开始在参数链中使用默认值，就不能停止使用默认值。在前面的示例中，如果我们给参数 2 设置了默认值，那么我们必须给参数 3 设置默认值，即使我们只是将 undefined 或 `null` 传递给它。同样，这有助于代码的清晰度，并确保我们不再需要在查看数组的参数时创建默认情况。

很多代码仍然利用函数的参数部分。甚至还有函数的其他属性可以获取，比如调用者。如果我们处于严格模式，很多这种行为都会被破坏。严格模式是一种不允许访问 JavaScript 引擎中某些行为的方式。关于这一点的良好描述可以在[`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Strict_mode`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Strict_mode)找到。除此之外，由于新标准提供了许多有用的替代方案，我们不应再使用函数的参数部分。

# 字符串模板

字符串模板允许我们传入将求值为字符串或具有 `toString` 函数的对象的任意代码。这再次使我们能够编写更清晰的代码，而不必创建大量连接的字符串。它还允许我们编写多行字符串，而无需创建转义序列。可以如下所示：

```js
const literal = `This is a string literal. It can hold multiple lines and
variables by denoting them with curly braces and prepended with the dollar 
sign like so \$\{\}.
here is a value from before ${a}. We can also pass an arbitrary expression 
that evaluates ${a === 1 ? b : c}.
`
console.log(literal);
```

只需记住，即使我们可以做某事，做某事可能不是最好的主意。具体来说，我们可能能够传递将求值为某个值的任意表达式，但我们应该尽量保持它们简洁清晰，以使代码更易读。

# 类型化数组

我们将在未来的章节中对此进行详细讨论，但类型化数组是表示系统中任意字节的一种方式。这使我们能够使用更低级的功能，例如编码器和解码器，甚至直接处理`fetch`调用的字节流，而无需将 blob 转换为数字或字符串。

这些通常以`ArrayBuffer`开始，然后我们在其上创建一个视图。这可能看起来像下面这样：

```js
const arrBuf = new ArrayBuffer(16);
const uint8 = new Uint8Array(arrBuf);
uint8[0] = 255;
```

正如我们所看到的，我们首先创建一个数组缓冲区。可以将其视为低级实例。它只保存原始字节。然后我们必须在其上创建一个视图。大部分时间，我们将使用`Uint8Array`，因为我们需要处理任意字节，但我们可以一直使用视图到`BigInt`。这些通常用于低级系统，例如 3D 画布代码、WebAssembly 或来自服务器的原始流。

# BigInt

`BigInt`是一个任意长的整数。JavaScript 中的数字以 64 位浮点数双精度存储。这意味着即使我们只有一个普通整数，我们仍然只能获得 53 位的精度。我们只能在变量中存储数字，最大到 9000 万亿。比这更大的数字通常会导致系统进入未定义的行为。为了弥补这一点，我们现在可以在 JavaScript 中利用`BigInt`特性。这看起来像下面这样：

```js
const bigInt = 100n;
console.log('adding two big ints', 100n + 250n);
console.log('add a big int and a regular number', 100n + BigInt(250));
```

我们会注意到*BigInts*后面会附加一个`n`。如果我们想要在常规操作中使用它们，我们还需要将常规数字强制转换为*BigInts*。现在我们有了大整数，我们可以处理非常大的数字，这在 3D、金融和科学应用中非常有用。

不要试图将*BigInts*强制转换回常规数字。这里存在一些未定义的行为，如果我们尝试这样做，可能会失去精度。最好的方法是，如果我们需要使用*BigInts*，就保持在*BigInts*中。

# 国际化

最后，我们来到国际化。以前，我们需要国际化诸如日期、数字格式甚至货币等内容。我们会使用特殊的查找或转换器来为我们执行这些操作。通过 ECMAScript 的更新版本，我们已经获得了使用内置`Intl`对象获取这些新格式的支持。一些用例可以如下所示：

```js
const amount = 1478.99;
console.log(new Intl.NumberFormat('en-UK', {style : 'currency', currency : 'EUR'}).format(amount));
console.log(new Intl.NumberFormat('de-DE', {style : 'currency', currency : 'EUR'}).format(amount));
const date = new Date(0);
console.log(new Intl.DateTimeFormat('en-UK').format(date));
console.log(new Intl.DateTimeFormat('de-DE').format(date));
```

有了这个，我们现在可以根据某人的所在地或他们在我们应用程序开始时选择的语言来国际化我们的系统。

这只会将数字转换为该国家代码的样式；它不会尝试转换实际值，因为货币等选项在一天之内会发生变化。如果我们需要执行这样的转换，我们将需要使用 API。除此之外，如果我们想要翻译某些内容，我们仍然需要有单独的查找，以确定我们需要在文本中放置什么，因为不同语言之间没有直接的翻译。

有了 ECMAScript 标准中添加的这些令人惊叹的功能，现在让我们转向一种封装函数和数据的方式。为此，我们将使用类和模块。

# 理解类和模块

随着新的 ECMAScript 标准，我们得到了新的类语法，用于实现**面向对象编程**（**OOP**），后来，我们还得到了模块，一种导入和导出用户定义的函数和对象集合的方式。这两种系统使我们能够消除系统中内置的某些黑客技巧，并且也能够移除一些几乎是必不可少的库，用于模块化我们的代码库。

首先，我们需要了解 JavaScript 是什么类型的语言。JavaScript 是一种多范式语言。这意味着我们可以利用许多不同编程风格的思想，并将它们合并到我们的代码库中。我们在之前的章节中提到的一种编程风格是函数式编程。

在纯函数式编程中，我们有纯函数，或者执行操作并且没有副作用（在函数应该执行的外部执行其他操作）的函数。当我们以这种方式编写时，我们可以创建通用函数，并将它们组合在一起，以创建可以处理复杂思想的一系列简单思想。我们还将函数视为语言中的一等公民。这意味着函数可以分配给变量并传递给其他函数。我们还可以组合这些函数，正如我们在之前的章节中所看到的。这是解决问题的一种方式。

另一种流行的编程风格是面向对象编程。这种风格表明程序可以用类和对象的层次结构来描述，并且可以构建和一起使用这些类和对象来创建这个复杂的思想。这个想法可以在大多数流行的语言中看到。我们构建具有一些通用功能或某些特定版本需要合并的定义的基类。我们从这个基类继承并添加我们自己的特定功能，然后我们创建这些对象。一旦我们把所有这些对象放在一起，我们就可以处理我们需要的复杂思想。

使用 JavaScript，我们可以得到这两种思想，但是 JavaScript 中的面向对象设计有点不同。我们拥有所谓的原型继承。这意味着在 JavaScript 中并没有所谓的抽象概念*类*。在 JavaScript 中，我们只有对象。我们继承一个对象的原型，该原型具有方法和数据，所有具有相同原型的对象共享，但它们都是实例化的实例。

当我们在 JavaScript 中谈论类语法时，我们指的是构造函数和我们添加到它们的原型的方法/数据的语法糖。另一种思考这种类型的继承的方式是注意到在 JavaScript 中没有抽象概念，只有具体对象。如果这看起来有点神秘或令人困惑，下面的代码应该澄清这些陈述的含义：

```js
const Item = funciton() {
    this.a = 1;
    this.b = 'this';
    this.c = function() {
        console.log('this is going to be a new function each time');
    }
}
Item.prototype.d = function() {
    console.log('this is on the prototype so it will only be here 
     once');
}
const item1 = new Item();
const item2 = new Item();

item1.c === item2.c; //false
item1.d === item2.d; //true

const item3 = new (Object.getPrototypeOf(item1)).constructor();
item3.d === item2.d ;//true
Object.getPrototypeOf(item1).constructor === Item; //true
```

通过这个例子，我们展示了一些东西。首先，这是创建构造函数的旧方法。构造函数是设置作用域和在实例化时直接可用于对象的所有函数的函数。在这种情况下，我们已经将`a`、`b`和`c`作为`Item`构造函数的实例变量。其次，我们已经向项目的原型添加了一些内容。当我们在构造函数的原型上声明某些内容时，我们使所有该构造函数的实例都可以使用它。

从这里，我们声明了两个基于`Item`构造函数的项目。这意味着它们将分别获得`a`、`b`和`c`变量的单独实例，但它们将共享函数`d`。我们可以在接下来的两个语句中看到这一点。这展示了如果我们直接添加一些内容到构造函数的`this`作用域中，它将创建该项目的全新实例，但如果我们将一些内容放在原型上，所有项目都将共享它。

最后，我们可以看到`item3`是一个新的`Item`，但我们通过迂回的方式到达了构造函数。一些浏览器支持项目上的`__proto__`属性，但这个函数应该在所有浏览器中都可用。我们获取原型并注意到有一个构造函数。这正是我们在顶部声明的完全相同的函数，因此我们能够利用它来创建一个新的项目。我们可以看到它也在与其他项目相同的原型上，并且原型上的构造函数与我们声明的`item`变量完全相同。

所有这些都应该展示的是 JavaScript 纯粹由对象构成。没有其他语言中真正的类等抽象类型。如果我们利用新的语法，最好理解我们所做的只是利用语法糖来做我们以前可以用原型做的事情。也就是说，下一个例子将展示完全相同的行为，但一个是老式的基于原型的，另一个是利用新的类语法：

```js
class newItem {
    constructor() {
        this.c = function() {
            console.log('this is going to be a new function each time!);
        }
    }
    a = '1';
    b = 'this';
    d() {
        console.log('this is on the prototype so it will only be here 
         once');
    }
}
const newItem1 = new newItem();
const newItem2 = new newItem();

newItem1.c === newItem2.c //false
newItem1.d === newItem2.d //true

newItem === Object.getPrototypeOf(newItem1).constructor; //true
```

通过这个例子，我们可以看到在创建与原型版本之前相同的对象时，我们获得了一些更清晰的语法。构造函数与我们声明`Item`为函数时是一样的。我们可以传入任何参数并在这里进行设置。类中的一个有趣之处是我们能够在类内部创建实例变量，就像我们在原型示例中在`this`上声明它们一样。我们还可以看到`d`的声明放在了原型上。我们将在下面探索类语法的更多方面，但花些时间并玩弄这两段代码。当我们试图编写高性能代码时，理解 JavaScript 是基于原型的将会极大地帮助。

类中的公共变量是相当新的（Chrome 72）。如果我们无法访问更新的浏览器，我们将不得不使用 Babel 将我们的代码转译回浏览器能理解的版本。我们还将看看另一个只在 Chrome 中且是实验性的功能，但它应该在一年内传递到所有浏览器。

# 其他值得注意的功能

JavaScript 类为我们提供了许多很好的功能，使我们编写的代码清晰简洁，同时性能几乎与直接编写原型相同。一个很好的功能是包括静态成员变量和静态成员函数。

虽然没有太大的区别，但它确实允许我们编写无法被成员函数访问的函数（它们仍然可以被访问，但要困难得多），并且它可以为将实用函数分组到特定类中提供一个很好的工具。这里展示了静态函数和变量的一个例子：

```js
class newItem {
    static e() {
        console.log(this);
    }
    static f = 10;
}

newItem1.e() //TypeError
newItem.e() //give us the class
newItem.f //10
```

两个静态定义被添加到`newItem`类中，然后我们展示了可用的内容。通过函数`e`和静态变量`f`，我们可以看到它们不包括在我们从`newItem`创建的对象中，但当我们直接访问`newItem`时，我们可以访问它们。除此之外，我们可以看到静态函数内部的`this`指向类。静态成员和变量非常适合创建实用函数，甚至用于在 JavaScript 中创建单例模式。

如果我们想要以旧式风格创建相同的体验，它看起来会像下面这样：

```js
Item.e = function() {
    console.log(this);
}
Item.f = 10;
```

正如我们所看到的，我们必须在`Item`的第一个定义之后放置这些定义。这意味着我们必须相对小心地尝试将我们的类定义的所有代码分组在旧式风格中，而类语法允许我们将其全部放在一个组中。

除了静态变量和函数之外，我们还有一种为类中的变量编写 getter 和 setter 的简写方式。可以如下所示：

```js
get g() {
    return this._g;
}
set g(val) {
    if( typeof val !== 'string' ) {
        return;
    }
    this._g = val;
}
```

有了这个 getter 和 setter，当有人或某物尝试访问这个变量时，我们能够在这些函数内部做各种事情。就像我们设置了一个代理来监听变化一样，我们也可以在 getter 和 setter 中做类似的事情。我们还可以在这里设置日志记录。当我们想要访问某些东西时，这种语法非常好，只需使用属性名，而不是像`getG`和`setG`这样写。

最后，还有 Chrome 76 中出现的新私有变量。虽然这仍处于候选推荐阶段，但仍然会被讨论，因为它很可能会发挥作用。很多时候，我们希望尽可能多地公开信息。然而，有时我们希望利用内部变量来保存状态，或者一般情况下不被访问。在这方面，JavaScript 社区提出了`_`解决方案。任何带有`_`的东西都被视为私有变量。但是，用户仍然可以访问这些变量并对其进行操作。更糟糕的是，恶意用户可能会发现这些私有变量中的漏洞，并能够操纵系统。在旧系统中创建私有变量的一种技术是以下形式：

```js
const Public = (function() {
    let priv = 0;
    const Private = function() {}
    Private.prototype.add1 = function() {
        priv += 1;
    }
    Private.prototype.getVal = function() {
        return priv;
    }
    return Private;
})();
```

有了这个，除了实现者之外，没有人可以访问`priv`变量。这为我们提供了一个面向公众的系统，而不会访问私有变量。然而，这个系统仍然有一个问题：如果我们创建另一个`Public`对象，我们仍然会影响相同的`priv`变量。还有其他方法可以确保我们在创建新对象时获得新变量，但这些都是我们试图制定的系统的变通方法。相反，我们现在可以利用以下语法：

```js
class Public {
    #h = 10;
    get h() {
        return this.#h;
    }
}
```

井号的作用是表示这是一个私有变量。如果我们尝试从任何一个实例中访问它，它将返回未定义。这与 getter 和 setter 接口非常配合，因为我们将能够控制对变量的访问，甚至在需要时修改它们。

最后，再来看一下类的`extend`和`super`关键字。通过`extend`，我们可以对类进行扩展。让我们以`newItem`类为例，扩展其功能。这可能看起来像这样：

```js
class extendedNewItem extends newItem {
    constructor() {
        super();
        console.log(this.c());
    }
    get super_h() {
        return super.h;
    }
    static e() {
        super.e();
        console.log('this came from our extended class');
    }
}
const extended = new extendedNewItem();
```

在这个例子中发生了一些有趣的行为。首先，如果我们在扩展对象上运行`Object.getPrototypeOf`，我们会看到原型是我们所期望的`extendedNewItem`。现在，如果我们获取它的原型，我们会看到它是`newItem`。我们创建了一个原型链，就像许多内置对象一样。

其次，我们可以使用`super`从类内部访问父类的方法。这本质上是对我们父类的原型的引用。如果我们想要继续遍历所有的原型，我们不能链式调用它们。我们必须利用诸如`Object.getPrototypeOf`之类的东西。我们还可以通过检查我们的扩展对象来看到，我们得到了我们父类系统中保存的所有成员变量。

这使我们能够组合我们的类并创建基类或抽象类，这些类给我们一些定义好的行为，然后我们可以创建扩展类，给我们想要的特定行为。我们将在后面看到更多使用类和我们在这里讨论过的许多概念的代码，但请记住，类只是原型系统的语法糖，对此的良好理解将有助于理解 JavaScript 作为一种语言的工作原理。

关于 JavaScript 生态系统中的类接口有很多好东西，而且似乎还有一些其他很棒的想法可能会在未来出现，比如装饰器。随时关注**Mozilla 开发者网络**（**MDN**）页面，了解新的内容和可能在未来出现的内容总是一个好主意。现在我们将看一下模块以及它们在我们编写清晰快速代码的系统中是如何工作的。

一个很好的经验法则是不要扩展任何类超过一到两个级别。如果我们再继续下去，我们可能会开始创建一个维护的噩梦，除了潜在的对象变得过于沉重，包含了它们不需要的信息。提前考虑将始终是我们创建系统时的最佳选择，尽量减少我们类的影响是减少内存使用的一种方式。

# 模块

在 ECMAScript 2015 之前，我们没有加载代码的概念，除了使用脚本标签。我们提出了许多模块概念和库，比如**RequireJS**或**AMD**，但没有一个是内置到语言中的。随着模块的出现，我们现在有了一种创建高度模块化代码的方式，可以轻松地打包并导入到我们代码的其他部分。我们还在我们以前必须使用 IIFE 来获得这种行为的系统中获得了作用域锁。

首先，在我们开始使用模块之前，我们需要一个静态服务器来托管我们所有的内容。即使我们让 Chrome 允许访问本地文件系统，模块系统也会因为无法将它们作为文本/JavaScript 提供而感到不安。为了解决这个问题，我们可以安装 node 包`node-static`。我们将把这个包添加到一个静态目录中。我们可以运行以下命令：`npm install node-static`。一旦这个包下载完成到`static`目录中，我们可以从我们的存储库中的`Chapter03`文件夹中获取`app.js`文件并运行`node app.js`。这将启动静态服务器，并从`static`目录中的`files`目录中提供服务。然后我们可以把任何想要提供的文件放在那里，并且能够从我们的代码中获取到它们。

现在，我们可以编写一个基本的模块，如下所示，并将其保存为`lib.js`：

```js
export default function() {
    console.log('this is going to be our simple lib');
}
```

然后，我们可以从 HTML 文件中导入这个模块，如下所示：

```js
<script type="module'>
    import lib from './lib.js';
</script>
```

即使是这个基本的例子，我们也可以了解模块在浏览器中是如何工作的。首先，脚本的类型需要是一个模块。这告诉浏览器我们要加载模块，并且我们要把这段代码作为模块来处理。这给了我们几个好处。首先，当我们使用模块时，我们会自动进入严格模式。其次，我们在模块中自动获得了作用域。这意味着我们刚刚导入的`lib`不会作为全局变量可用。如果我们将内容加载为文本/JavaScript 并将变量放在全局路径上，那么我们将自动拥有它们；这就是为什么我们通常必须使用 IIFE。最后，我们得到了一个很好的语法来加载我们的 JavaScript 文件。我们仍然可以使用旧的方式加载一堆脚本，但我们也可以只导入基于模块的脚本。

接下来，我们可以看到模块本身使用了`export`和`default`关键字。`export`表示我们希望这个项在这个作用域或文件之外可用。现在我们可以在当前文件之外访问到这个项。`default`表示如果我们加载模块而没有定义我们想要的内容，我们将自动获得这个项。这可以在以下示例中看到：

```js
const exports = {
    this : 'that',
    that : 'this'
}

export { exports as Item };
```

首先，我们定义了一个名为`exports`的对象。这是我们要添加为导出项的对象。其次，我们将此项添加到一个`export`声明中，并且还重命名了它。这是模块的一个好处。在导出或导入的一侧，我们都可以重命名我们想要导出的项。现在，在我们的 HTML 文件中，我们会有如下声明：

```js
import { Item } from './lib.js';
```

如果我们在声明周围没有括号，我们将尝试引入默认导出。由于我们有花括号，它将在`lib.js`中查找名为`Item`的项目。如果找到，它将引入与之关联的代码。

现在，就像我们从导出列表中重命名导出一样，我们可以重命名导入。让我们继续将其更改为以下内容：

```js
import { Item as _item } from './lib.js';
```

现在我们可以像往常一样利用该项，但是作为变量`_item`而不是`Item`。这对于名称冲突非常有用。我们只能想出那么多变量名，所以，我们可以在加载它们时改变它们，而不是在单独的库中更改变量。

良好的样式约定是在顶部声明所有导入。然而，有一些用例可能需要动态加载模块，因为某种类型的用户交互或其他事件。如果发生这种情况，我们可以利用动态导入来实现这一点。这些看起来如下：

```js
document.querySelector('#loader').addEventListener('click', (ev) => {
    if(!('./lib2.js' in imported)) {
        import('./lib2.js')
        .then((module) => {
            imported['./lib2.js'] = module;
            module.default();
        });
    } else {
        imported['./lib2.js'].default();
    }
});
```

我们添加了一个按钮，当点击时，我们尝试将模块加载到我们的系统中。这不是在我们的系统中缓存模块的最佳方式，大多数浏览器也会为我们做一些缓存，但这种方式相当简单，展示了动态导入系统。导入函数基于承诺，因此我们尝试抓取它，如果成功，我们将其添加到导入的对象中。然后调用默认方法。我们可以访问模块为我们导出的任何项目，但这是最容易访问的项目之一。

看到 JavaScript 的发展是令人惊讶的。所有这些新功能给了我们以前必须依赖第三方的能力。关于 DOM 的变化也是如此。我们现在将看看这些变化。

# 使用 DOM

文档对象模型（DOM）并不总是最容易使用的技术。我们有古老的过时 API，大多数时候，它们在不同浏览器之间无法对齐。但是，在过去的几年里，我们已经得到了一些很好的 API 来做以下事情：轻松获取元素，构建内存层次结构以进行快速附加，并使用 DOM 阴影进行模板。所有这些都导致了一个丰富的环境，可以对底层节点进行更改，并创建许多丰富的前端，而无需使用 jQuery 等库。在接下来的几节中，我们将看到如何使用这些新 API 有所帮助。

# 查询选择器

在拥有这个 API 之前（或者我们试图尽可能跨浏览器），我们依赖于诸如`getElementById`或`getElementsByClassName`之类的系统。每个都提供了一种我们可以获取 DOM 元素的方式，如下例所示：

```js
<p>This is a paragraph element</p>
<ul id="main">
    <li class="hidden">1</li>
    <li class="hidden">2</li>
    <li>3</li>
    <li class="hidden">4</li>
    <li>5</li>
</ul>
<script type="module">
    const main = document.getElementById('main');
    const hidden = document.getElementsByClassName('hidden');
</script>
```

这个旧 API 和新的`querySelector`和`querySelectorAll`之间的一个区别是，旧 API 将 DOM 节点集合实现为`HTMLCollection`，而新 API 将它们实现为`NodeList`。虽然这可能看起来不是一个重大的区别，但`NodeList`API 确实给了我们一个已经内置到系统中的`forEach`。否则，我们将不得不将这两个集合都更改为常规的 DOM 节点数组。在新 API 中实现的前面的示例如下：

```js
const main = document.querySelector('#main');
const hidden = document.querySelectorAll('.hidden');
```

当我们想要开始向我们的选择过程添加其他功能时，这变得更加美好。

假设我们现在有一些输入，并且我们想获取所有文本类型的输入。在旧 API 中会是什么样子？如果需要，我们可以给它们都附加一个类，但这会污染我们对类的使用，可能不是处理这些信息的最佳方式。

我们可以通过利用旧 API 方法之一来获取这些数据，然后检查这些元素是否将输入属性设置为`text`。这可能看起来像下面这样：

```js
const allTextInput = Array.from(document.getElementsByTagName('input'))
    .filter(item => item.getAttribute('type') === "text");
```

但是现在我们有了一定程度的冗长，这是不需要的。相反，我们可以通过使用 CSS 选择器来获取它们，使用选择器 API 如下：

```js
const alsoTextInput = doucment.querySelectorAll('input[type="text"]');
```

这意味着我们应该能够利用 CSS 语法访问任何 DOM 节点，就像 jQuery 一样。我们甚至可以从另一个元素开始，这样我们就不必解析整个 DOM，就像这样：

```js
const hidden = document.querySelector('#main').querySelectorAll('.hidden');
```

选择器 API 的另一个好处是，如果我们不使用正确的 CSS 选择器，它将抛出错误。这为我们提供了系统为我们运行检查的额外好处。虽然新的选择器 API 已经存在，但由于需要包括 Internet Explorer 在支持的 Web 浏览器中，它并没有被广泛使用。强烈建议开始使用新的选择器 API，因为它不那么冗长，我们能够做的事情比旧系统多得多。

jQuery 是一个库，它为我们提供了比基本系统更好的 API。jQuery 支持的大多数更改现在已经过时，许多我们已经谈论过的新的 web API 正在接管。对于大多数新应用程序，它们将不再需要使用 jQuery。

# 文档片段

我们在之前的章节中已经看到了这些，但是触及它们是很好的。文档片段是可重用的容器，我们可以在其中创建 DOM 层次结构，并一次性附加所有这些节点。这导致更快的绘制时间和更少的重绘。

以下示例展示了两种使用直接 DOM 添加和片段添加的方式附加一系列列表元素：

```js
const num = 10000;
const container = document.querySelector('#add');
for(let i = 0; i < num; i++) {
    const temp = document.createElement('li');
    temp.textContent = `item ${i}`;
    container.appendChild(temp);
}
while(container.firstChild) {
    container.removeChild(container.firstChild);
}
const fragment = document.createDocumentFragment();
for(let i = 0; i < num; i++) {
    const temp = document.createElement('li');
    temp.textContent = `item ${i}`;
    fragment.appendChild(temp);
}
container.appendChild(fragment);
```

虽然这两者之间的时间很短，但发生的重绘次数并非如此。在我们的第一个示例中，每次直接向文档添加元素时，文档都会重绘，而我们的第二个示例只会重绘一次 DOM。这就是文档片段的好处；它使向 DOM 添加变得简单，同时只使用最少的重绘。

# Shadow DOM

阴影 DOM 通常与模板和 Web 组件配对使用，但也可以单独使用。阴影 DOM 允许我们封装我们应用程序的特定部分的标记和样式。如果我们想要页面的某个部分具有特定的样式，但不希望其传播到页面的其他部分，这是很好的。

我们可以通过利用其 API 轻松地使用阴影 DOM，如下所示：

```js
const shadow = document.querySelector('#shadowHolder').attachShadow({mode : 'open'});
const style = document.createElement('style');
style.textContent = `<left out to shorten code snippet>`;
const frag = document.createDocumentFragment();
const header = document.createElement('h1');
const par = document.createElement('p');
header.textContent = 'this is a header';
par.textContent = 'Here is some text inside of a paragraph element. It is going to get the styles we outlined above';

frag.appendChild(header);
frag.appendChild(par);
shadow.appendChild(style);
shadow.appendChild(frag);
```

首先，我们将阴影 DOM 附加到一个元素上，这里是我们的`shadowHolder`元素。有一个模式选项，它允许我们说是否可以在阴影上下文之外通过 JavaScript 访问内容，但已经发现我们可以轻松地规避这一点，因此建议保持它开放。接下来，我们创建一些元素，其中一个是一些样式属性。然后，我们将这些附加到一个文档片段，最后附加到阴影根。

搞定所有这些之后，我们可以看到并注意到我们的阴影 DOM 受到了放在其中的样式属性的影响，而不是放在我们主文档顶部的样式属性。如果我们在文档顶部放置一个我们的阴影样式没有的样式会发生什么？它仍然不会受到影响。有了这个，我们现在能够创建可以单独样式化的组件，而无需使用类。这将我们带到 DOM 的最后一个主题之一。

# Web 组件

Web 组件 API 允许我们创建具有定义行为的自定义元素，仅利用浏览器 API。这与诸如 Bootstrap 甚至 Vue 之类的框架不同，因为我们能够利用浏览器中存在的所有技术。

Chrome 和 Firefox 都支持所有这些 API。Safari 支持其中大部分，如果这是我们想要支持的浏览器，我们只能利用其中的一些 API。Edge 不支持 Web 组件 API，但随着它转向 Chromium 基础，我们将看到另一个能够利用这项技术的浏览器。

让我们创建一个基本的`tooltip`元素。首先，我们需要在我们的类中扩展基本的`HTMLElement`。然后，我们需要附加一些属性，以允许我们放置元素并给我们需要使用的文本。最后，我们需要注册这个组件到我们的系统中，以确保它识别我们的自定义元素。以下代码创建了这个自定义元素（修改自[`developer.mozilla.org/en-US/docs/Web/Web_Components/Using_custom_elements`](https://developer.mozilla.org/en-US/docs/Web/Web_Components/Using_custom_elements)）：

```js
class Tooltip extends HTMLElement {
    constructor() {
        super();
        this.text = this.getAttribute('text');
        this.type = this.getAttribute('type');
        this.typeMap = new Map(Object.entries({
            'success' : "&#x2714",
            'error' : "&#x2716",
            'info' : "&#x2755",
            'default' : "&#x2709"
        }));

        this.shadow = this.attachShadow({mode : 'open'});
        const container = document.createElement('span');
        container.classList.add('wrapper');
        container.classList.add('hidden');
        const type = document.createElement('span');
        type.id = 'icon';
        const el = document.createElement('span');
        el.id = 'main';
        const style = document.createElement('style');
        el.textContent = this.text;
        type.innerHTML = this.getType(this.type);

        style.innerText = `<left out>`
        this.shadow.append(style);
        this.shadow.append(container);
        container.append(type);
        contianer.append(el);
    }
    update() {
        const x = this.getAttribute('x');
        const y = this.getAttribute('y');
        const type = this.getAttribute('type');
        const text = this.getAttribute('text');
        const show = this.getAttribute('show');
        const wrapper = this.shadow.querySelector('.wrapper');
        if( show === "true" ) {
            wrapper.classList.remove('hidden');
        } else {
            wrapper.classList.add('hidden');
        }
        this.shadow.querySelector('#icon').innerHTML = this.getType(type);
        this.shadow.querySelector('#main').innerText = text;
        wrapper.style.left = `${x}px`;
        wrapper.style.top = `${y}px`;
    }
    getType(type) {
        return type ?
            this.typeMap.has(type) ?
                this.typeMap.get(type) :
                this.typeMap.get('default') :
            this.typeMap.get('default');
    }
    connectCallback() {
        this.update(this);
    }
    attributeChangedCallback(name, oldValue, newValue) {
        this.update(this);
    }
    static get observedAttributes() {
        return ['x', 'y', 'type', 'text', 'show'];
    }
}

customElements.define('our-tooltip', Tooltip);
```

首先，我们有一个属性列表，我们将使用它们来样式化和定位我们的`tooltip`。它们分别称为`x`、`y`、`type`、`text`和`show`。接下来，我们创建了一个基于表情符号的文本映射，这样我们就可以利用图标而不需要引入一个完整的库。然后我们在一个阴影容器内设置了可重用的对象。我们还将阴影根放在对象上，这样我们就可以轻松访问它。`update`方法将在我们的元素第一次创建时触发，并在属性的任何后续更改时触发。我们可以在最后三个函数中看到这一点。`connectedCallback`将在我们被附加到 DOM 时触发。`attributeChangedCallback`将提醒我们发生了任何属性更改。这与代理 API 非常相似。最后一部分让我们的对象知道我们特别关心哪些属性，这种情况下是`x`、`y`、`type`、`text`和`show`。最后，我们使用`customElements.define`方法注册我们的自定义组件，给它一个名称和我们想要在创建这些对象时运行的类。

现在，如果我们创建我们的`tooltip`，我们可以利用这些不同的属性来制作一个可重用的`tooltip`系统，甚至是警报。以下代码演示了这一点：

```js
<our-tooltip show="true" x="100" y="100" icon="success" text="here is our tooltip"></our-tooltip>
```

我们应该看到一个浮动框，上面有一个复选标记和文本“这是我们的提示”。通过利用 Web 组件 API 中的模板系统，我们可以使这个`tooltip`更容易阅读。

# 模板

现在，我们有一个不错的可重用的`tooltip`元素，但是我们的样式标签中也有相当多的代码，它完全由模板化的字符串组成。最好的办法是，如果我们可以把这个语义标记放在别的地方，并把执行逻辑放在我们的 Web 组件中，就像现在一样。这就是模板发挥作用的地方。`<template>`元素不会显示在页面上，但我们仍然可以通过给它一个 ID 来很容易地获取它。因此，重构我们当前的代码的一种方式是这样的：

```js
<template id="tooltip">
    <style>
        /* left out */
    </style>
    <span class="wrapper hidden" x="0" y="0" type="default" show="false">
        <span id="icon">&#2709</span>
        <span id="main">This is some default text</span>
    </span>
</template>
```

我们的 JavaScript 类构造函数现在应该是这样的：

```js
constructor() {
    super();
    this.type = this.getAttribute('type');
    this.typeMap = // same as before
    const template = document.querySelector('#tooltip').content;
    this.shadow = this.attachShadow({mode : 'open'});
    this.shadow.appendChild(template.cloneNode(true));
}
```

这样更容易阅读，更容易理解。现在我们获取我们的模板并获取它的内容。我们创建一个`shadow`对象并附加我们的模板。我们需要确保克隆我们的模板节点，否则我们将在我们决定创建的所有元素之间共享相同的引用！你会注意到的一件事是，我们现在无法通过属性来控制文本。虽然看到这种行为很有趣，但我们真的希望把这些信息留给我们的`tooltip`的创建者。我们可以通过`<slot>`元素来实现这一点。

插槽给了我们一个区域，我们可以在那个位置放置 HTML。我们可以利用这一点，让`tooltip`的用户放入他们想要的标记。我们可以给他们一个看起来像下面这样的模板：

```js
<span class="wrapper hidden" x="0" y="0" type="default" show="false">
    <span id="icon">&#2709</span>
    <span id="main"><slot name="main_text">This is default text</slot></span>
</span>
```

我们的实现可能如下所示：

```js
<our-tooltip show="true" x="100" y="100" type="success">
    <span slot="main_text">That was a successful operation!</span>
</our-tooltip>
```

正如我们所看到的，阴影 DOM 的使用，以及浏览器中的 Web 组件和模板系统，使我们能够创建丰富的元素，而无需外部库，如 Bootstrap 或 Foundation。

我们可能仍然需要这些库来提供一些基本的样式，但我们不应该像过去那样需要它们。最理想的情况是，我们可以编写所有自己的组件和样式，而不需要利用外部库。但是，由于这些系统相对较新，如果我们无法控制用户的使用，我们可能会陷入填充的困境。

# 理解 Fetch API

在 Fetch API 之前，我们必须利用`XMLHttpRequest`系统。要创建一个服务器数据请求，我们必须编写类似以下的内容：

```js
const oldReq = new XMLHttpRequest();
oldReq.addEventListener('load', function(ev) {
    document.querySelector('#content').innerHTML = 
     JSON.stringify(ev.target.response);
});
oldReq.open('GET', 'http://localhost:8081/sample');
oldReq.setRequestHeader('Accept', 'application/json');
oldReq.responseType = 'json';
oldReq.send();
```

首先，您会注意到对象类型被称为`XMLHttpRequest`。原因是由于谁发明了它以及背后的原因。微软最初开发了这种技术，用于 Outlook Web Access 产品。最初，他们来回传输 XML 文档，因此他们为其构建的对象命名。一旦其他浏览器供应商，主要是 Mozilla，采用了它，他们决定保留名称，即使其目的已经从仅发送 XML 文档转变为从服务器发送到客户端的任何类型的响应。

其次，我们向对象添加了一个事件监听器。由于这是一个普通对象而不是基于 promise 的，我们以`addEventListener`方法的老式方式添加监听器。这意味着一旦它被使用，我们也会清理事件监听器。接下来，我们打开请求，传入我们想要发送的方法和发送的位置。然后我们可以设置一堆请求头（在这里特别指定我们想要的应用程序/JSON 数据，并将`responseType`设置为`json`，以便浏览器正确转换）。最后，我们发送请求。

一旦我们获得响应，我们的事件将触发，我们可以从事件的目标中检索响应。一旦我们开始发布数据，情况可能会变得更加繁琐。这就是 jQuery 的`$.ajax`和类似方法的原因。它使得与`XMLHttpRequest`对象一起工作变得更加容易。那么从 Fetch API 的角度来看，这种响应是什么样子的呢？这个完全相同的请求可以如下所示：

```js
fetch('http://localhost:8081/sample')
.then((res) => res.json())
.then((res) => {
    document.querySelector('#content').innerHTML = JSON.stringify(res);
});
```

我们可以看到这样阅读和理解起来要容易得多。首先，我们设置我们要访问的 URL。如果我们在`fetch`调用中不传递操作，它将自动假定我们正在创建一个`GET`请求。接下来，我们获取响应，并确保以`json`格式获取它。响应将始终作为*promise*返回（稍后会详细介绍），因此我们希望将其转换为我们想要的格式，即`json`。从这里，我们得到了最终的对象，我们可以将其设置为我们内容的`innerHTML`。从这两个基本对象的示例中，我们可以看到 Fetch API 几乎具有与`XMLHttpRequest`相同的功能，但它的格式更容易理解，我们可以轻松地使用 API。

# Promises

正如我们在之前的`fetch`示例中看到的，我们利用了一个叫做 promise 的东西。简单地说，promise 就是一个我们将来会需要的值，而返回给我们的是一个合同，声明了“我会在以后把它交给你”。Promise 是基于回调的概念。如果我们看一个可能包装在`XMLHttpRequest`周围的回调的例子，我们可以看到它是如何作为一个 promise 运行的：

```js
const makeRequest = function(loc, success, failure) {
    const oldReq = new XMLHttpRequest();
    oldReq.addEventListener('load', function(ev) {
        if( ev.target.status === 200 ) {
            success(ev.target.response);
        } else {
            failure(ev.target.response);
        }
    }, { once : true });
    oldReq.open('GET', loc);
    oldReq.setRequestHeader('Accept', 'application/json');
    oldReq.responseType = 'json';
    oldReq.send();
}
```

通过这样，我们几乎可以得到与 promise 相同的功能，但是利用回调或我们想要在发生某事时运行的函数。回调系统的问题是被称为回调地狱。这是高度异步代码总是有回调的想法，这意味着如果我们想要利用它，我们将会有一个美妙的回调树视图。这看起来像下面这样：

```js
const fakeFetchRequest(url, (res) => {
    res.json((final) => {
        document.querySelector('#content').innerHTML = 
         JSON.stringify(final);
    });
});
```

这个虚构的`fetch`版本是如果`fetch`的 API 不是基于 promise 的。首先，我们会传入我们的 URL。我们还需要为响应返回时提供一个回调。然后，我们需要将该响应传递给`json`方法，该方法还需要一个回调来将响应数据转换为`json`。最后，我们会得到结果并将其放入我们的 DOM。

正如我们所看到的，回调可能会导致很多问题。相反，我们有了 promise。promise 在创建时需要一个参数，即一个具有两个参数（resolve 和 reject）的函数。有了这些，我们可以通过`resolve`函数向调用者返回成功，或者通过`reject`函数报错。这将允许我们通过`then`调用和`catch`调用将这些 promise 链接在一起，就像我们在`fetch`示例中看到的那样。

然而，这也可能导致另一个问题。我们可能会得到一长串 promise，看起来比回调好一些，但并不明显。然后我们有了`async`/`await`系统。我们可以使用`await`来利用响应，而不是不断地用`then`链接 promise。然后我们可以将我们的`fetch`调用转换成以下形式：

```js
(async function() {
    const res = await fetch('http://localhost:8081/sample');
    const final = await res.json();
    document.querySelector('#content').innerHTML = JSON.stringify(final);
})();
```

函数前的`async`描述符告诉我们这是一个`async`函数。如果没有这个描述符，我们就无法使用`await`。接下来，我们可以直接使用`await`函数，而不是将`then`函数链接在一起。结果就是原本会被包装在我们的`resolve`函数中的内容。现在，我们有了一个非常易读的东西。

我们需要小心`async`/`await`系统。它确实会等待，所以如果我们将其放在主线程上，或者没有将其包装在其他东西中，它可能会阻塞主线程，导致我们无法继续执行。此外，如果我们有一堆任务需要同时运行，我们可以利用`Promise.all()`，而不是一个接一个地等待它们（使我们的代码变成顺序执行）。这允许我们将一堆 promise 放在一起，并允许它们异步运行。一旦它们都返回，我们就可以继续执行。

`async`/`await`系统的一个好处是它实际上可能比使用通用 promise 更快。许多浏览器已经围绕这些特定的关键字添加了优化，因此我们应该尽可能地利用它们。

之前已经提到过，但浏览器供应商不断改进他们对 ECMAScript 标准的实现。这意味着新技术一开始会比较慢，但一旦被广泛使用或得到所有供应商的认可，它们就会开始优化，并通常比其对应的技术更快。在可能的情况下，利用浏览器供应商提供给我们的新技术！

# 回到 fetch

现在我们已经看到了`fetch`请求的样子，我们应该看一下如何获取底层的可读流。`fetch`系统已经添加了很多功能，其中两个是管道和流。这可以在许多最近的 Web API 中看到，可以观察到浏览器供应商已经注意到了 Node.js 如何利用流。

如前一章所述，流是一种一次处理数据块的方式。它还确保我们不必一次性获取整个有效负载，而是可以逐步构建有效负载。这意味着如果我们需要转换数据，我们可以在数据块到达时即时进行转换。这也意味着我们可以处理不常见的数据类型，比如 JSON 和纯文本。

我们将编写一个基本示例，演示`TransformStream`如何对输入进行简单的 ROT13 编码（ROT13 是一种非常基本的编码器，它将我们得到的第 13 个字母替换原来的字母）。稍后我们将更详细地介绍流（这些将是 Node.js 版本，但概念相对类似）。示例大致如下：

```js
class Rot13Transform {
    constructor() {
    }
    async transform(chunk, controller) {
        const _chunk = await chunk;
        const _newChunk = _chunk.map((item) => ((item - 65 + 13) % 26) + 
         65);
        controller.enqueue(_newChunk);
        return;
    }
}

fetch('http://localhost:8081/rot')
.then(response => response.body)
.then(res => res.pipeThrough(new TransformStream(new Rot13Transform())))
.then(res => new Response(res))
.then(response => response.text())
.then(final => document.querySelector('#content').innerHTML = final)
.catch(err => console.error(err));
```

让我们将这个例子分解成实际的`TransformStream`，然后是利用它的代码。首先，我们创建一个类，用于容纳我们的旋转代码。然后，我们需要一个叫做`transform`的方法，它接受两个参数，块和控制器。块是我们将要获取的数据。

请记住，这不会一次性获取所有数据，因此如果我们需要构建对象或类似的东西，我们需要为前面的数据创建一个可能的临时存储位置，如果当前块没有给我们想要的所有内容。在我们的情况下，我们只是在底层字节上运行一个旋转方案，因此我们不需要有一个临时持有者。

接下来，控制器是流控制和声明数据是否准备从中读取（一个可读或转换流）或写入（一个可写流）的基础系统。接下来，我们等待一些数据并将其放入一个临时变量中。然后，我们对每个字节运行一个简单的映射表达式，将它们向右旋转 13 次，然后对 26 取模。

ASCII 约定将所有大写字符从 65 开始。这就是这里涉及一些数学的原因，因为我们试图首先得到 0 到 26 之间的数字，进行操作，然后将其移回正常的 ASCII 范围内。

一旦我们旋转了输入，我们就会将其排队在控制器上。这意味着数据已准备好从另一个流中读取。接下来，我们可以看一系列发生的承诺。首先，我们获取我们的数据。然后，我们通过获取其主体从`fetch`请求中获取底层的`ReadableStream`。然后，我们利用一个叫做`pipeThrough`的方法。管道机制会自动为我们处理流量控制，因此在处理流时会让我们的生活变得更加轻松。

流控制对于使流工作至关重要。它基本上告诉其他流，如果我们被堵住了，就不要再发送数据，或者我们可以继续接收数据。如果没有这种机制，我们将不断地不得不控制我们的流，当我们只想专注于我们想要合并的逻辑时，这可能会是一个真正的痛苦。

我们将数据传输到一个新的`TransformStream`中，该流采用我们的旋转逻辑。现在，这将把响应中的所有数据传输到我们的转换代码中，并确保它经过转换后输出。然后，我们将我们的`ReadableStream`包装在一个新的`Response`中，这样我们就可以像处理`fetch`请求的任何其他`Response`对象一样处理它。然后，我们像处理普通文本一样获取数据并将其放入我们的 DOM 中。

正如我们所看到的，这个例子展示了我们可以通过流系统做很多很酷的事情。虽然 DOM API 仍在变化中，但这些概念与 Node.js 中的流接口类似。它还展示了我们如何可能为更复杂的二进制类型编写解码器，这些类型可能通过网络传输，比如 smile 格式。

# 停止 fetch 请求

在进行请求时，我们可能想要执行的一个操作是停止它们。这可能是出于多种原因，比如：

+   首先，如果我们在后台进行请求，并且让用户更新`POST`请求的参数，我们可能希望停止当前请求，并让他们发出新的请求。

+   其次，一个请求可能花费太长时间，我们希望确保停止请求，而不是挂起应用程序或使其进入未知状态。

+   最后，我们可能有一个设置好的缓存机制，一旦我们完成缓存大量数据，我们希望使用它。如果发生这种情况，我们希望停止任何待处理的请求，并将其切换到该来源。

任何这些原因都是停止请求的好理由，现在我们有一个可以做到这一点的 API。`AbortController`系统允许我们停止这些请求。发生的情况是`AbortController`有一个`signal`属性。我们将这个`signal`附加到`fetch`请求上，当我们调用`abort`方法时，它告诉`fetch`请求我们不希望它继续进行请求。这非常简单和直观。以下是一个例子：

```js
(async function() {
    const controller = new AbortController();
    const signal = controller.signal;
    document.querySelector('#stop').addEventListener('click', (ev) => {
        controller.abort();
    });
    try {
        const res = await fetch('http://localhost:8081/longload', 
         {signal});
        const final = await res.text();
        document.querySelector('#content').innerHTML = final;
    } catch(e) {
        console.error('failed to download', e);
    }
})();
```

正如我们所看到的，我们已经建立了一个`AbortController`系统并获取了它的`signal`属性。然后我们设置了一个按钮，当点击时，将运行`abort`方法。接下来，我们看到了典型的`fetch`请求，但在选项中，我们传递了`signal`。现在，当我们点击按钮时，我们会看到请求因 DOM 错误而停止。我们还看到了一些关于`async`/`await`的错误处理。`async`/`await`可以利用基本的`try-catch`语句来捕获错误，这只是`async`/`await`API 使代码比回调和基于 promise 的版本更可读的另一种方式。

这是另一个实验性的 API，将来很可能会有变化。但是，我们在`XMLHttpRequest`中也有了相同类型的想法，因此 Fetch API 也会得到它是有道理的。请注意，MDN 网站是获取有关浏览器支持和任何我们已经讨论过并将在未来章节讨论的实验性 API 的最新信息的最佳地方。

`fetch`和 promise 系统是从服务器获取数据并展示处理异步流量的新方式。虽然我们过去必须利用回调和一些看起来很糟糕的对象，但现在我们有了一个非常容易使用的简洁的 API。尽管 API 的部分正在变化，但请注意，这些系统很可能会以某种方式存在。

# 总结

在本章中，我们看到了过去 5 年来浏览器环境发生了多少变化。通过新的 API 增强了我们编写代码的方式，通过 DOM API 使我们能够编写具有内置控件的丰富 UI，我们现在能够尽可能地使用原生应用。这包括获取外部数据的使用，以及新的异步 API，如 promises 和`async`/`await`系统。

在下一章中，我们将看到一个专注于输出原生 JavaScript 并为我们提供无运行时应用环境的库。当我们讨论节点和工作线程时，我们还将把大部分现代 API 整合到本书的其余部分中。玩弄这些系统，并熟悉它们，因为我们才刚刚开始。
