# Webassembly 学习手册（一）

> 原文：[`annas-archive.org/md5/d5832e9a9d99a1607969f42f55873dd5`](https://annas-archive.org/md5/d5832e9a9d99a1607969f42f55873dd5)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

本书介绍了 WebAssembly，这是一项新颖而令人兴奋的技术，能够在浏览器中执行除 JavaScript 以外的其他语言。本书描述了如何从头开始构建一个 C/JavaScript 应用程序，使用 WebAssembly，并将现有的 C++代码库移植到浏览器中运行的过程，借助 Emscripten 的帮助。

WebAssembly 代表了 Web 平台的重要转变。作为诸如 C、C++和 Rust 等语言的编译目标，它提供了构建新型应用程序的能力。WebAssembly 得到了所有主要浏览器供应商的支持，并代表了一项协作努力。

在本书中，我们将描述构成 WebAssembly 的元素及其起源。我们将介绍安装所需工具、设置开发环境以及与 WebAssembly 交互的过程。我们将通过简单示例并逐渐深入的用例来工作。通过本书结束时，您将能够在 C、C++或 JavaScript 项目中充分利用 WebAssembly。

# 本书适合对象

如果您是希望为 Web 构建应用程序的 C/C++程序员，或者是希望改进其 JavaScript 应用程序性能的 Web 开发人员，那么本书适合您。本书面向熟悉 JavaScript 的开发人员，他们不介意学习一些 C 和 C++（反之亦然）。本书通过提供两个示例应用程序，同时考虑到了 C/C++程序员和 JavaScript 程序员的需求。

# 本书涵盖内容

第一章，*什么是 WebAssembly？*，描述了 WebAssembly 的起源，并提供了对该技术的高级概述。它涵盖了 WebAssembly 的用途，支持哪些编程语言以及当前的限制。

第二章，*WebAssembly 的元素- Wat、Wasm 和 JavaScript API*，概述了构成 WebAssembly 的元素。它详细解释了文本和二进制格式，以及相应的 JavaScript 和 Web API。

第三章，*设置开发环境*，介绍了用于开发 WebAssembly 的工具。它提供了每个平台的安装说明，并提供了改进开发体验的建议。

第四章，*安装所需的依赖项*，提供了每个平台安装工具链要求的说明。通过本章结束时，您将能够将 C 和 C++编译为 WebAssembly 模块。

第五章，*创建和加载 WebAssembly 模块*，解释了如何使用 Emscripten 生成 WebAssembly 模块，以及传递给编译器的标志如何影响生成的输出。它描述了在浏览器中加载 WebAssembly 模块的技术。

第六章，*与 JavaScript 交互和调试*，详细介绍了 Emscripten 的 Module 对象和浏览器的全局 WebAssembly 对象之间的区别。本章描述了 Emscripten 提供的功能，以及生成源映射的说明。

第七章，*从头开始创建应用程序*，介绍了创建一个与 WebAssembly 模块交互的 JavaScript 会计应用程序的过程。我们将编写 C 代码来计算会计交易的值，并在 JavaScript 和编译后的 WebAssembly 模块之间传递数据。

第八章，*使用 Emscripten 移植游戏*，采用逐步方法将现有的 C++游戏移植到 WebAssembly 上，使用 Emscripten。在审查现有的 C++代码库之后，对适当的文件进行更改，以使游戏能够在浏览器中运行。

第九章，*与 Node.js 集成*，演示了如何在服务器端和客户端使用 Node.js 和 npm 与 WebAssembly。本章涵盖了在 Express 应用程序中使用 WebAssembly，将 WebAssembly 与 webpack 集成以及使用 Jest 测试 WebAssembly 模块。

第十章，*高级工具和即将推出的功能*，涵盖了正在标准化过程中的高级工具，用例和新的 WebAssembly 功能。本章描述了 WABT，Binaryen 和在线可用的工具。在本章中，您将学习如何使用 LLVM 编译 WebAssembly 模块，以及如何将 WebAssembly 模块与 Web Workers 一起使用。本章最后描述了标准化过程，并审查了一些正在添加到规范中的令人兴奋的功能。

# 充分利用本书

您应该具有一些编程经验，并了解变量和函数等概念。如果您从未见过 JavaScript 或 C/C++代码，您可能需要在阅读本书的示例之前进行一些初步研究。我选择使用 JavaScript ES6/7 功能，如解构和箭头函数，因此如果您在过去 3-4 年内没有使用 JavaScript，语法可能会有些不同。

# 下载示例代码文件

您可以从[www.packtpub.com](http://www.packtpub.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，您可以访问[www.packtpub.com/support](http://www.packtpub.com/support)并注册，以便将文件直接发送到您的邮箱。

您可以按照以下步骤下载代码文件：

1.  在[www.packtpub.com](http://www.packtpub.com/support)上登录或注册。

1.  选择“支持”选项卡。

1.  单击“代码下载和勘误”。

1.  在搜索框中输入书名，然后按照屏幕上的说明操作。

下载文件后，请确保使用以下最新版本解压或提取文件夹：

+   Windows 上的 WinRAR/7-Zip

+   Mac 上的 Zipeg/iZip/UnRarX

+   Linux 上的 7-Zip/PeaZip

本书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Learn-WebAssembly`](https://github.com/PacktPublishing/Learn-WebAssembly)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还有其他代码包来自我们丰富的书籍和视频目录，可在**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**上找到。去看看吧！

# 下载彩色图片

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图片。您可以在此处下载：[`www.packtpub.com/sites/default/files/downloads/9781788997379_ColorImages.pdf`](https://www.packtpub.com/sites/default/files/downloads/9781788997379_ColorImages.pdf)。

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词，数据库表名，文件夹名，文件名，文件扩展名，路径名，虚拟 URL，用户输入和 Twitter 句柄。例如："`instantiate()` 是编译和实例化 WebAssembly 代码的主要 API。"

代码块设置如下：

```cpp
int addTwo(int num) {
 return num + 2;
}
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```cpp
int calculate(int firstVal, int secondVal) {
return firstVal - secondVal;
}
```

任何命令行输入或输出都将按照以下格式编写：

```cpp
npm install -g webassembly
```

**粗体**：表示新术语，重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会在文本中出现。例如：“您可以通过按下“开始”菜单按钮，右键单击“命令提示符”应用程序并选择“以管理员身份运行”来执行此操作。”

警告或重要说明会出现在这样的地方。

提示和技巧会出现在这样的地方。

# 第一章：什么是 WebAssembly？

**WebAssembly**（**Wasm**）代表了 Web 平台的一个重要里程碑。使开发人员能够在 Web 上运行编译后的代码，而无需插件或浏览器锁定，带来了许多新的机会。关于 WebAssembly 是什么以及对其持续能力的一些怀疑，存在一些混淆。

在本章中，我们将讨论 WebAssembly 的产生过程，WebAssembly 在官方定义方面的含义以及它所涵盖的技术。将涵盖潜在的用例、支持的语言和局限性，以及如何找到额外的信息。

我们本章的目标是了解以下内容：

+   为 WebAssembly 铺平道路的技术

+   WebAssembly 是什么以及它的一些潜在用例

+   可以与 WebAssembly 一起使用的编程语言

+   WebAssembly 的当前局限性

+   WebAssembly 与 Emscripten 和 asm.js 的关系

# 通往 WebAssembly 的道路

可以说，Web 开发有一个有趣的历史。已经进行了几次（失败的）尝试来扩展平台以支持不同的语言。诸如插件之类的笨拙解决方案未能经受住时间的考验，而将用户限制在单个浏览器上则是一种灾难的预兆。

WebAssembly 作为一个优雅的解决方案，解决了自从浏览器能够执行代码以来一直存在的问题：*如果你想为 Web 开发，你必须使用 JavaScript*。幸运的是，使用 JavaScript 并没有像在 2000 年代初那样带有负面含义，但它作为一种编程语言仍然有一定的局限性。在本节中，我们将讨论导致 WebAssembly 出现的技术，以更好地理解为什么需要这种新技术。

# JavaScript 的演变

JavaScript 是由 Brendan Eich 在 1995 年的短短 10 天内创建的。最初被程序员视为一种*玩具*语言，主要用于在网页上制作按钮闪烁或横幅出现。过去的十年里，JavaScript 已经从一个玩具演变成了一个具有深远能力和庞大追随者的平台。

2008 年，浏览器市场的激烈竞争导致了**即时**（**JIT**）编译器的添加，这提高了 JavaScript 的执行速度 10 倍。Node.js 于 2009 年首次亮相，代表了 Web 开发的范式转变。Ryan Dahl 结合了谷歌的 V8 JavaScript 引擎、事件循环和低级 I/O API，构建了一个平台，允许在服务器和客户端使用 JavaScript。Node.js 导致了`npm`，这是一个允许在 Node.js 生态系统内使用的库的包管理器。截至撰写本文时，有超过 60 万个可用的包，每天都有数百个包被添加：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-wasm/img/d473abb9-dda2-4db0-acfb-0a63607c8190.png)

自 2012 年以来 npm 包数量的增长，来自 Modulecounts

不仅是 Node.js 生态系统在增长；JavaScript 本身也在积极发展。ECMA **技术委员会 39**（**TC39**）规定了 JavaScript 的标准，并监督新语言特性的添加，每年发布一次 JavaScript 的更新，采用社区驱动的提案流程。凭借其丰富的库和工具、对语言的不断改进以及拥有最庞大的程序员社区之一，JavaScript 已经成为一个不可忽视的力量。

但是这种语言确实有一些缺点：

+   直到最近，JavaScript 只包括 64 位浮点数。这可能会导致非常大或非常小的数字出现问题。`BigInt`是一种新的数值原语，可以缓解一些这些问题，正在被添加到 ECMAScript 规范中，但可能需要一些时间才能在浏览器中得到完全支持。

+   JavaScript 是弱类型的，这增加了它的灵活性，但可能会导致混淆和错误。它基本上给了你足够的绳子来绞死自己。

+   尽管浏览器供应商尽最大努力，但 JavaScript 并不像编译语言那样高效。

+   如果开发人员想要创建 Web 应用程序，他们需要学习 JavaScript——不管他们喜不喜欢。

为了避免编写超过几行 JavaScript，一些开发人员构建了**转译器**，将其他语言转换为 JavaScript。转译器（或源到源编译器）是一种将一种编程语言的源代码转换为另一种编程语言等效源代码的编译器。TypeScript 是前端 JavaScript 开发的流行工具，将 TypeScript 转译为针对浏览器或 Node.js 的有效 JavaScript。选择任何编程语言，都有很大可能有人为其创建了 JavaScript 转译器。例如，如果你喜欢编写 Python，你有大约 15 种不同的工具可以用来生成 JavaScript。但最终，它仍然是 JavaScript，因此你仍然受到该语言的特殊性的影响。

随着 Web 逐渐成为构建和分发应用程序的有效平台，越来越复杂和资源密集型的应用程序被创建。为了满足这些应用程序的需求，浏览器供应商开始研发新技术，将其集成到软件中，而不会干扰 Web 开发的正常进程。谷歌和 Mozilla 分别是 Chrome 和 Firefox 的创建者，他们采取了两种不同的路径来实现这一目标，最终形成了 WebAssembly。

# 谷歌和 Native Client

谷歌开发了**Native Client**（**NaCl**），旨在安全地在 Web 浏览器中运行本机代码。可执行代码将在**沙盒**中运行，并提供本机代码执行的性能优势。

在软件开发的背景下，沙盒是一个环境，防止可执行代码与系统的其他部分进行交互。它旨在防止恶意代码的传播，并对软件的操作进行限制。

NaCl 与特定架构相关，而**Portable Native Client**（**PNaCl**）是 NaCl 的独立于架构的版本，可在任何平台上运行。该技术由两个元素组成：

+   可以将 C/C++代码转换为 NaCl 模块的工具链

+   运行时组件是嵌入在浏览器中的组件，允许执行 NaCl 模块：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-wasm/img/ee7ab5c5-f671-4caa-8073-2c3ef941c399.png)

本机客户端工具链及其输出

NaCl 的特定架构可执行文件（`nexe`）仅限于从谷歌 Chrome Web 商店安装的应用程序和扩展，但 PNaCl 可执行文件（`pexe`）可以在 Web 上自由分发并嵌入 Web 应用程序中。Pepper 使得可移植性成为可能，Pepper 是用于创建 NaCl 模块的开源 API，以及其相应的插件 API（PPAPI）。Pepper 实现了 NaCl 模块与托管浏览器之间的通信，并以安全和可移植的方式访问系统级功能。通过包含清单文件和已编译模块（`pexe`）以及相应的 HTML、CSS 和 JavaScript，应用程序可以轻松分发：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-wasm/img/0a230248-b946-4f66-b811-ff2530fc48d1.png)

Pepper 在本机客户端应用程序中的作用

NaCl 提供了克服 Web 性能限制的有希望的机会，但也有一些缺点。尽管 Chrome 内置支持 PNaCl 可执行文件和 Pepper，其他主要浏览器却没有。技术的反对者对应用程序的黑盒性质以及潜在的安全风险和复杂性表示了异议。

Mozilla 致力于改进 JavaScript 的性能，使用`asm.js`。由于 API 规范的不完整和文档有限，他们不会为 Firefox 添加对 Pepper 的支持。最终，NaCl 于 2017 年 5 月被弃用，改为支持 WebAssembly。

# Mozilla 和 asm.js

Mozilla 于 2013 年推出了`asm.js`，并为开发人员提供了一种将其 C 和 C++源代码转换为 JavaScript 的方法。`asm.js`的官方规范将其定义为 JavaScript 的严格子集，可用作编译器的低级高效目标语言。它仍然是有效的 JavaScript，但语言特性仅限于适合**提前**（**AOT**）优化的特性。AOT 是浏览器的 JavaScript 引擎用来通过将其编译为本机机器代码来更有效地执行代码的技术。`asm.js`通过具有 100%类型一致性和手动内存管理来实现这些性能增益。

使用 Emscripten 等工具，C/C++代码可以被转译成`asm.js`，并且可以使用与普通 JavaScript 相同的方式进行分发。访问`asm.js`模块中的函数需要**链接**，这涉及调用其函数以获取具有模块导出的对象。

`asm.js`非常灵活，但是与模块的某些交互可能会导致性能损失。例如，如果`asm.js`模块被赋予访问自定义 JavaScript 函数的权限，而该函数未通过动态或静态验证，代码就无法利用 AOT 并会退回到解释器：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-wasm/img/3b40bcf8-0a50-4ed5-806e-3f3a5f64679a.png)

`asm.js`的 AOT 编译工作流程

`asm.js`不仅仅是一个过渡阶段。它构成了 WebAssembly 的**最小可行产品**（**MVP**）的基础。官方 WebAssembly 网站在标题为*WebAssembly 高级目标*的部分明确提到了`asm.js`。

那么为什么要创建 WebAssembly 而不使用`asm.js`呢？除了潜在的性能损失外，`asm.js`模块是一个必须在编译之前通过网络传输的文本文件。WebAssembly 模块是以二进制格式，这使得由于其较小的大小而更加高效地传输。

WebAssembly 模块使用基于 promise 的实例化方法，利用现代 JavaScript 并消除了任何*这个加载了吗*的代码。

# WebAssembly 的诞生

**万维网联盟**（**W3C**）是一个致力于制定 Web 标准的国际社区，于 2015 年 4 月成立了 WebAssembly 工作组，以标准化 WebAssembly 并监督规范和提案过程。自那时起，*核心规范*和相应的*JavaScript API*和*Web API*已经发布。浏览器中对 WebAssembly 支持的初始实现是基于`asm.js`的功能集。WebAssembly 的二进制格式和相应的`.wasm`文件结合了`asm.js`输出的特征和 PNaCl 的分布式可执行概念。

那么 WebAssembly 将如何成功，而 NaCl 失败了呢？根据 Axel Rauschmayer 博士的说法，详细原因在[`2ality.com/2015/06/web-assembly.html#what-is-different-this-time`](http://2ality.com/2015/06/web-assembly.html#what-is-different-this-time)中有三个原因。

“首先，这是一个协作努力，没有任何一家公司单独进行。目前，涉及的项目有：Firefox，Chromium，Edge 和 WebKit。

其次，与 Web 平台和 JavaScript 的互操作性非常出色。从 JavaScript 中使用 WebAssembly 代码将像导入模块一样简单。

第三，这不是要取代 JavaScript 引擎，而是要为它们增加一个新功能。这大大减少了实现 WebAssembly 的工作量，并有助于获得 Web 开发社区的支持。”

- Dr. Axel Rauschmayer

# WebAssembly 到底是什么，我在哪里可以使用它？

WebAssembly 在官方网站上有一个简明扼要的定义，但这只是一个部分。WebAssembly 还有其他几个组件。了解每个组件的作用将让您更好地理解整个技术。在本节中，我们将详细解释 WebAssembly 的定义，并描述潜在的用例。

# 官方定义

官方的 WebAssembly 网站（[`webassembly.org`](https://webassembly.org)）提供了这个定义：

Wasm 是一种基于堆栈的虚拟机的二进制指令格式。Wasm 被设计为高级语言（如 C/C++/Rust）的可移植编译目标，从而可以在 Web 上部署客户端和服务器应用程序。

让我们把这个定义分解成几个部分，以便更清楚地解释。

# 二进制指令格式

WebAssembly 实际上包括几个元素——二进制格式和文本格式，这些都在*核心规范*中有文档记录，对应的 API（JavaScript 和 Web），以及一个编译目标。二进制和文本格式都映射到一个公共结构，以**抽象语法**的形式存在。为了更好地理解抽象语法，可以在**抽象语法树**（**AST**）的上下文中解释。AST 是编程语言源代码结构的树形表示。诸如 ESLint 之类的工具使用 JavaScript 的 AST 来查找 linting 错误。以下示例包含 JavaScript 的函数和相应的 AST（来自[`astexplorer.net`](https://astexplorer.net)）。

一个简单的 JavaScript 函数如下：

```cpp
function doStuff(thingToDo) {
  console.log(thingToDo);
}
```

相应的 AST 如下：

```cpp
{
  "type": "Program",
  "start": 0,
  "end": 57,
  "body": [
    {
      "type": "FunctionDeclaration",
      "start": 9,
      "end": 16,
      "id": {
        "type": "Identifier",
        "start": 17,
        "end": 26,
        "name": "doStuff"
      },
      "generator": false,
      "expression": false,
      "params": [
        {
          "type": "Identifier",
          "start": 28,
          "end": 57,
          "name": "thingToDo"
        }
      ],
      "body": {
        "type": "BlockStatement",
        "start": 32,
        "end": 55,
        "body": [
          {
            "type": "ExpressionStatement",
            "start": 32,
            "end": 55,
            "expression": {
              "type": "CallExpression",
              "start": 32,
              "end": 54,
              "callee": {
                "type": "MemberExpression",
                "start": 32,
                "end": 43,
                "object": {
                  "type": "Identifier",
                  "start": 32,
                  "end": 39,
                  "name": "console"
                },
                "property": {
                  "type": "Identifier",
                  "start": 40,
                  "end": 43,
                  "name": "log"
                },
                "computed": false
              },
              "arguments": [
                {
                  "type": "Identifier",
                  "start": 44,
                  "end": 53,
                  "name": "thingToDo"
                }
              ]
            }
          }
        ]
      }
    }
  ],
  "sourceType": "module"
}
```

AST 可能会很冗长，但它在描述程序的组件方面做得很好。在 AST 中表示源代码使得验证和编译变得简单高效。WebAssembly 文本格式的代码被序列化为 AST，然后编译为二进制格式（作为`.wasm`文件），然后被网页获取、加载和利用。模块加载时，浏览器的 JavaScript 引擎利用**解码堆栈**将`.wasm`文件解码为 AST，执行类型检查，并解释执行函数。WebAssembly 最初是用于 AST 的二进制指令格式。由于验证返回`void`的 Wasm 表达式的性能影响，二进制指令格式已更新为针对**堆栈机**。

堆栈机由两个元素组成：堆栈和指令。堆栈是一个具有两个操作的数据结构：*push*和*pop*。项目被推送到堆栈上，然后按照**后进先出**（**LIFO**）的顺序从堆栈中弹出。堆栈还包括一个**指针**，指向堆栈顶部的项目。指令表示对堆栈中项目执行的操作。例如，一个`ADD`指令可能从堆栈中弹出顶部的两个项目（值为`100`和`10`），并将总和推回到堆栈上（值为`110`）：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-wasm/img/1e2d75b9-2021-4486-8049-726f6134410d.png)

一个简单的堆栈机

WebAssembly 的堆栈机操作方式相同。程序计数器（指针）维护代码中的执行位置，虚拟控制堆栈跟踪`blocks`和`if`结构的进入（推入）和退出（弹出）。指令执行时不涉及 AST。因此，定义中的**二进制指令格式**部分指的是一种二进制表示的指令，这些指令可以被浏览器中的解码堆栈读取。

# 可移植的编译目标

WebAssembly 从一开始就考虑了可移植性。在这个上下文中，可移植性意味着 WebAssembly 的二进制格式可以在各种操作系统和指令集架构上高效地执行，无论是在 Web 上还是离线。WebAssembly 的规范定义了执行环境中的可移植性。WebAssembly 被设计为在符合某些特征的环境中高效运行，其中大部分与内存有关。WebAssembly 的可移植性也可以归因于核心技术周围缺乏特定的 API。相反，它定义了一个 `import` 机制，其中可用的导入集由宿主环境定义。

简而言之，这意味着 WebAssembly 不与特定环境绑定，比如 Web 或桌面。WebAssembly 工作组已经定义了一个 *Web API*，但这与 *核心规范* 是分开的。*Web API* 适用于 WebAssembly，而不是反过来。

定义中的**编译**方面表明，WebAssembly 从高级语言编写的源代码编译成其二进制格式将会很简单。MVP 关注两种语言，C 和 C++，但由于 Rust 与 C++ 相似，也可以使用。编译将通过使用 Clang/LLVM 后端来实现，尽管在本书中我们将使用 Emscripten 生成我们的 Wasm 模块。计划最终支持其他语言和编译器（比如 GCC），但 MVP 专注于 LLVM。

# 核心规范

官方定义为我们提供了对整体技术的高层洞察，但为了完整起见，值得深入挖掘一下。WebAssembly 的 *核心规范* 是官方文档，如果你想深入了解 WebAssembly，可以参考这个文档。如果你对运行时结构的特征感兴趣，可以查看第 4 节：*执行*。我们在这里不会涉及这一点，但了解 *核心规范* 的位置将有助于建立对 WebAssembly 的完整定义。

# 语言概念

*核心规范* 表明 WebAssembly 编码了一种低级的、类似汇编的编程语言。规范定义了这种语言的结构、执行和验证，以及二进制和文本格式的细节。语言本身围绕以下概念构建：

+   **值**，或者说 WebAssembly 提供的值类型

+   在堆栈机器内执行的**指令**

+   在错误条件下产生的**陷阱**并中止执行

+   **函数**，代码组织成的函数，每个函数都以一系列值作为参数，并返回一系列值作为结果

+   **表**，这是特定元素类型（比如函数引用）的值数组，可以被执行程序选择

+   **线性内存**，这是一个原始字节的数组，可以用来存储和加载值

+   **模块**，WebAssembly 二进制（`.wasm` 文件）包含函数、表和线性内存

+   **嵌入器**，WebAssembly 可以在宿主环境（比如 Web 浏览器）中执行的机制

函数、表、内存和模块与 *JavaScript API* 直接相关，对此有所了解是很重要的。这些概念描述了语言本身的基本结构以及如何编写或编码 WebAssembly。就使用而言，理解 WebAssembly 对应的语义阶段提供了对该技术的完整定义：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-wasm/img/52382cbb-fa93-4206-adde-c38848bf1429.png)

语言概念及其关系

# 语义阶段

*核心规范* 描述了编码模块（`.wasm` 文件）在宿主环境（比如 Web 浏览器）中被利用时经历的不同阶段。规范的这一方面代表了输出是如何处理和执行的：

+   **解码**：将二进制格式转换为模块

+   **验证**：解码模块经过验证检查（例如类型检查），以确保模块形式良好且安全

+   **执行，第 1 部分：实例化**：通过初始化**全局变量**、**内存**和**表**来实例化模块实例，然后调用模块的`start()`函数

+   **执行，第 2 部分：调用**：从模块实例调用导出的函数：

以下图表提供了语义阶段的可视化表示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-wasm/img/51755ca6-f4c7-43b3-93d3-81575523ae30.png)

模块使用的语义阶段

# JavaScript 和 Web API

WebAssembly 工作组还发布了与 JavaScript 和 Web 交互的 API 规范，使它们有资格被纳入 WebAssembly 技术领域。*JavaScript API*的范围仅限于 JavaScript 语言本身，而不是特定于环境（例如 Web 浏览器或 Node.js）。它定义了用于与 WebAssembly 交互和管理编译和实例化过程的类、方法和对象。*Web API*是*JavaScript API*的扩展，定义了特定于 Web 浏览器的功能。*Web API*规范目前仅定义了两种方法，`compileStreaming`和`instantiateStreaming`，这些是简化在浏览器中使用 Wasm 模块的便利方法。这些将在第二章中更详细地介绍，*WebAssembly 的要素 - Wat、Wasm 和 JavaScript API*。

# 那么它会取代 JavaScript 吗？

WebAssembly 的最终目标不是取代 JavaScript，而是补充它。JavaScript 丰富的生态系统和灵活性仍然使其成为 Web 的理想语言。WebAssembly 的 JavaScript API 使得两种技术之间的互操作性相对简单。那么你是否能够只使用 WebAssembly 构建 Web 应用程序？WebAssembly 的一个明确目标是可移植性，复制 JavaScript 的所有功能可能会阻碍该目标。然而，官方网站包括一个目标，即执行并与现有 Web 平台很好地集成，所以只有时间能告诉我们。在一种编译为 WebAssembly 的语言中编写整个代码库可能并不实际，但将一些应用程序逻辑移动到 Wasm 模块可能在性能和加载时间方面有益。

# 我可以在哪里使用它？

WebAssembly 的官方网站列出了大量潜在的用例。我不打算在这里覆盖它们所有，但有几个代表了对 Web 平台功能的重大增强：

+   图像/视频编辑

+   游戏

+   音乐应用程序（流媒体、缓存）

+   图像识别

+   实时视频增强

+   虚拟现实和增强现实

尽管一些用例在技术上可以使用 JavaScript、HTML 和 CSS 实现，但使用 WebAssembly 可以带来显著的性能提升。提供一个二进制文件（而不是单个 JavaScript 文件）可以大大减少捆绑包大小，并且在页面加载时实例化 Wasm 模块可以加快代码执行速度。

WebAssembly 不仅仅局限于浏览器。在浏览器之外，您可以使用它来构建移动设备上的混合本机应用程序，或者执行不受信任代码的服务器端计算。在手机应用程序中使用 Wasm 模块可能在功耗和性能方面非常有益。

WebAssembly 在使用上也提供了灵活性。你可以在 WebAssembly 中编写整个代码库，尽管在当前形式或 Web 应用程序的上下文中可能不太实际。鉴于 WebAssembly 的强大 JavaScript API，你可以在 JavaScript/HTML 中编写 UI，并使用 Wasm 模块来实现不直接访问 DOM 的功能。一旦支持了其他语言，对象就可以在 Wasm 模块和 JavaScript 代码之间轻松传递，这将大大简化集成并增加开发者的采用率。

# 支持哪些语言？

WebAssembly 的 MVP 的高级目标是提供与`asm.js`大致相同的功能。这两种技术非常相关。C、C++和 Rust 是非常受欢迎的支持手动内存分配的语言，这使它们成为最初实现的理想候选。在本节中，我们将简要概述每种编程语言。

# C 和 C++

C 和 C++是已经存在 30 多年的低级编程语言。C 是过程化的，不本质上支持类和继承等面向对象编程概念，但它快速、可移植且被广泛使用。

C++是为了填补 C 的不足而构建的，它添加了诸如运算符重载和改进的类型检查等功能。这两种语言一直稳居前 10 最受欢迎的编程语言之列，这使它们非常适合 MVP：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-wasm/img/049542c7-ebe1-4b35-b4a1-de0ec95a532c.png)

TIOBE 长期历史上前 10 种编程语言的排名

C 和 C++的支持也内置在 Emscripten 中，因此除了简化编译过程，它还允许你充分利用 WebAssembly 的功能。还可以使用 LLVM 将 C/C++代码编译成`.wasm`文件。LLVM 是一组模块化和可重用的编译器和工具链技术。简而言之，它是一个简化从源代码到机器代码的编译过程配置的框架。如果你想制作自己的编程语言并且想要构建编译器，LLVM 有工具来简化这个过程。我将在第十章中介绍如何使用 LLVM 将 C/C++编译成`.wasm`文件，*高级工具和即将推出的功能*。

以下片段演示了如何使用 C++将“Hello World！”打印到控制台：

```cpp
#include <iostream>

int main() {
    std::cout << "Hello, World!\n";
    return 0;
}
```

# Rust

C 和 C++原本是 WebAssembly 的主要使用语言，但 Rust 也是一个完全合适的替代品。Rust 是一种系统编程语言，语法与 C++类似。它设计时考虑了内存安全性，但仍保留了 C 和 C++的性能优势。Rust 当前的夜间构建版本的编译器可以从 Rust 源代码生成`.wasm`文件，因此如果你更喜欢 Rust 并且熟悉 C++，你应该能够在本书的大多数示例中使用 Rust。

以下片段演示了如何使用 Rust 将“Hello World！”打印到控制台：

```cpp
fn main() {
    println!("Hello World!");
}
```

# 其他语言

还存在各种工具，可以使其他流行的编程语言与 WebAssembly 一起使用，尽管它们大多是实验性的：

+   通过 Blazor 的 C#

+   通过 WebIDL 的 Haxe

+   通过 TeaVM 或 Bytecoder 的 Java

+   通过 TeaVM 的 Kotlin

+   通过 AssemblyScript 的 TypeScript

技术上也可以将一种语言转译为 C，然后将其编译为 Wasm 模块，但编译的成功取决于转译器的输出。很可能你需要对代码进行重大更改才能使其正常工作。

# 有哪些限制？

诚然，WebAssembly 并非没有局限性。新功能正在积极开发，技术不断发展，但 MVP 功能仅代表了 WebAssembly 功能的一部分。在本节中，我们将介绍其中一些限制以及它们对开发过程的影响。

# 没有垃圾回收

WebAssembly 支持平面线性内存，这本身并不是一个限制，但需要一些了解如何显式分配内存以执行代码。C 和 C++是 MVP 的逻辑选择，因为内存管理内置于语言中。一开始没有包括一些更流行的高级语言，比如 Java，原因是**垃圾回收**（**GC**）。

GC 是一种自动内存管理形式，程序不再使用的对象占用的内存会被自动回收。GC 类似于汽车上的自动变速器。经过熟练工程师的大力优化，它可以尽可能高效地运行，但限制了驾驶员的控制量。手动分配内存就像驾驶手动变速器的汽车。它可以更好地控制速度和扭矩，但错误使用或缺乏经验可能会导致汽车严重损坏。C 和 C++的出色性能和速度部分归功于手动分配内存。

GC 语言允许您编程而无需担心内存可用性或分配。JavaScript 就是一个 GC 语言的例子。浏览器引擎采用一种称为标记-清除算法来收集不可达对象并释放相应的内存。WebAssembly 目前正在努力支持 GC 语言，但很难准确说出何时会完成。

# 没有直接的 DOM 访问

WebAssembly 无法访问 DOM，因此任何 DOM 操作都需要间接通过 JavaScript 或使用诸如 Emscripten 之类的工具来完成。有计划添加引用 DOM 和其他 Web API 对象的能力，但目前仍处于提案阶段。DOM 操作可能会与 GC 语言紧密相关，因为它将允许在 WebAssembly 和 JavaScript 代码之间无缝传递对象。

# 旧版浏览器不支持

旧版浏览器没有全局的`WebAssembly`对象可用来实例化和加载 Wasm 模块。如果找不到该对象，有一些实验性的 polyfills 会使用`asm.js`，但 WebAssembly 工作组目前没有创建的计划。由于`asm.js`和 WebAssembly 密切相关，如果`WebAssembly`对象不可用，简单地提供一个`asm.js`文件仍然可以提供性能增益，同时适应向后兼容性。您可以在[`caniuse.com/#feat=wasm`](https://caniuse.com/#feat=wasm)上查看当前支持 WebAssembly 的浏览器。

# 它与 Emscripten 有什么关系？

Emscripten 是可以从 C 和 C++源代码生成`asm.js`的源到源编译器。我们将使用它作为一个构建工具来生成 Wasm 模块。在本节中，我们将快速回顾 Emscripten 与 WebAssembly 的关系。

# Emscripten 的作用

Emscripten 是一个 LLVM 到 JavaScript 的编译器，这意味着它接受诸如 Clang（用于 C 和 C++）的编译器的 LLVM 位码输出，并将其转换为 JavaScript。它不是一个特定的技术，而是一组技术的组合，它们一起构建、编译和运行`asm.js`。为了生成 Wasm 模块，我们将使用**Emscripten SDK**（**EMSDK**）管理器：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-wasm/img/4d92b3fc-da38-44bc-97b4-e1be3b1fc6a3.png)

使用 EMSDK 生成 Wasm 模块

# EMSDK 和 Binaryen

在第四章中，*安装所需的依赖项*，我们将安装 EMSDK 并使用它来管理编译 C 和 C++ 到 Wasm 模块所需的依赖项。Emscripten 使用 Binaryen 的 `asm2wasm` 工具将 Emscripten 输出的 `asm.js` 编译成 `.wasm` 文件。Binaryen 是一个编译器和工具链基础库，包括将各种格式编译成 WebAssembly 模块以及反之的工具。了解 Binaryen 的内部工作对于使用 WebAssembly 并不是必需的，但重要的是要意识到底层技术以及它们如何协同工作。通过将某些标志传递给 Emscripten 的编译命令 (`emcc`)，我们可以将结果的 `asm.js` 代码传递给 Binaryen 以输出我们的 `.wasm` 文件。

# 总结

在本章中，我们讨论了与 WebAssembly 的历史相关的技术，以及导致其创建的技术。提供了对 WebAssembly 定义的详细概述，以便更好地理解涉及的底层技术。

*核心规范*、*JavaScript API* 和 *Web API* 被提出为 WebAssembly 的重要元素，并展示了技术将如何发展。我们还审查了潜在的用例、当前支持的语言以及使非支持语言可用的工具。

WebAssembly 的局限性是缺乏 GC、无法直接与 DOM 通信以及不支持旧版浏览器。这些都是为了传达技术的新颖性并揭示其中一些缺点而进行讨论的。最后，我们讨论了 Emscripten 在开发过程中的作用以及它在 WebAssembly 开发工作流程中的位置。

在第二章中，*WebAssembly 元素 - Wat、Wasm 和 JavaScript API*，我们将更深入地探讨构成 WebAssembly 的元素：**WebAssembly 文本格式**（**Wat**）、二进制格式（Wasm）、JavaScript 和 Web API。

# 问题

1.  哪两种技术影响了 WebAssembly 的创建？

1.  什么是堆栈机器，它与 WebAssembly 有什么关系？

1.  WebAssembly 如何补充 JavaScript？

1.  哪三种编程语言可以编译成 Wasm 模块？

1.  LLVM 在 WebAssembly 方面扮演什么角色？

1.  WebAssembly 有哪三个潜在的用例？

1.  DOM 访问和 GC 有什么关系？

1.  Emscripten 使用什么工具来生成 Wasm 模块？

# 进一步阅读

+   官方 WebAssembly 网站：[`webassembly.org`](https://webassembly.org)

+   原生客户端技术概述：[`developer.chrome.com/native-client/overview`](https://developer.chrome.com/native-client/overview)

+   LLVM 编译器基础设施项目：[`llvm.org`](https://llvm.org)

+   关于 Emscripten：[`kripken.github.io/emscripten-site/docs/introducing_emscripten/about_emscripten.html`](http://kripken.github.io/emscripten-site/docs/introducing_emscripten/about_emscripten.html)

+   asm.js 规范：[`asmjs.org/spec/latest`](http://asmjs.org/spec/latest)


# 第二章：WebAssembly 的元素-Wat、Wasm 和 JavaScript API

第一章《什么是 WebAssembly？》描述了 WebAssembly 的历史，并提供了技术的高层概述以及潜在的用例和限制。WebAssembly 被描述为由多个元素组成，不仅仅是官方定义中指定的二进制指令格式。

在本章中，我们将深入研究与 WebAssembly 工作组创建的官方规范相对应的元素。我们将更详细地检查 Wat 和二进制格式，以更好地理解它们与模块的关系。我们将审查*JavaScript API*和*Web API*，以确保您能够有效地在浏览器中使用 WebAssembly。

本章的目标是理解以下内容：

+   文本和二进制格式之间的关系

+   Wat 是什么以及它在开发过程中的作用

+   二进制格式和模块（Wasm）文件

+   JavaScript 和 Web API 的组件以及它们与 Wasm 模块的关系

+   如何利用 WasmFiddle 评估 WebAssembly 的阶段（C/C++ > Wat > Wasm）

# 共同结构和抽象语法

在第一章中，《什么是 WebAssembly？》，我们讨论了 WebAssembly 的二进制和文本格式如何映射到抽象语法的共同结构。在深入了解这些格式之前，值得一提的是它们在*核心规范*中的关系。以下图表是目录的可视化表示（为了清晰起见，排除了一些部分）：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-wasm/img/24a8a8a0-7afd-4ffe-892c-bb162b09b784.png)*核心规范*目录

正如您所看到的，**文本格式**和**二进制格式**部分包含与**结构**部分相关的**值**、**类型**、**指令**和**模块**的子部分。因此，我们在下一节中涵盖的许多内容与二进制格式有直接的对应关系。考虑到这一点，让我们深入了解文本格式。

# Wat

*文本格式*部分提供了对常见语言概念（如值、类型和指令）的技术描述。如果您打算为 WebAssembly 构建工具，这些都是重要的概念，但如果您只打算在应用程序中使用它，则不是必需的。话虽如此，文本格式是 WebAssembly 的重要部分，因此有一些概念您应该了解。在本节中，我们将深入了解文本格式的一些细节，并从*核心规范*中突出重点。

# 定义和 S 表达式

要理解 Wat，让我们从直接从 WebAssembly *核心规范*中提取的描述的第一句开始：

"WebAssembly 模块的文本格式是它们的抽象语法渲染成 S 表达式。"

那么什么是**符号表达式**（**S 表达式**）？S 表达式是嵌套列表（树形结构）数据的表示。基本上，它们提供了一种在文本形式中表示基于列表的数据的简单而优雅的方式。要理解文本表示的嵌套列表如何映射到树形结构，让我们从 HTML 页面中推断树形结构。以下示例包含一个简单的 HTML 页面和相应的树形结构图。

一个简单的 HTML 页面：

```cpp
<html>
<head>
  <link rel="icon" href="favicon.ico">
  <title>Page Title</title>
</head>
<body>
  <div>
    <h1>Header</h1>
    <p>This is a paragraph.</p>
  </div>
  <div>Some content</div>
  <nav>
    <ul>
      <li>Item 1</li>
      <li>Item 2</li>
      <li>Item 3</li>
    </ul>
  </nav>
</body>
</html>
```

相应的树形结构是：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-wasm/img/fbdfac80-c6f7-45cb-beb9-5ebdc2ed8ffe.png)

HTML 页面的树形结构图

即使你以前从未见过树形结构，也很容易看出 HTML 如何在结构和层次结构方面映射到树形结构。映射 HTML 元素相对简单，因为它是一种具有明确定义标签且没有实际逻辑的标记语言。

Wat 表示可以具有多个具有不同参数的函数的模块。为了演示源代码、Wat 和相应的树结构之间的关系，让我们从一个简单的 C 函数开始，该函数将 2 添加到作为参数传入的数字中：

这是一个将`2`添加到传入的`num`参数并返回结果的 C 函数：

```cpp
int addTwo(int num) {
    return num + 2;
}
```

将`addTwo`函数转换为有效的 Wat 会产生以下结果：

```cpp
(module
  (table 0 anyfunc)
  (memory $0 1)
  (export "memory" (memory $0))
  (export "addTwo" (func $addTwo))
  (func $addTwo (; 0 ;) (param $0 i32) (result i32)
    (i32.add
      (get_local $0)
      (i32.const 2)
    )
  )
)
```

在第一章中，*什么是 WebAssembly？*，我们谈到了与*核心规范*相关的语言概念（*函数*、*线性内存*、*表*等）。在该规范中，*结构*部分在抽象语法的上下文中定义了每个这些概念。规范的*文本格式*部分也与这些概念对应，您可以在前面的片段中通过它们的关键字来定义它们（`func`、`memory`、`table`）。

树结构：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-wasm/img/28fa4fdc-1b9e-4672-b752-8bb1a272e9e0.png)

Wat 的树结构图

整个树太大，无法放在一页上，因此此图表仅限于 Wat 源文本的前五行。每个填充的点代表一个列表节点（或一组括号的内容）。正如您所看到的，用 s 表达式编写的代码可以以树结构清晰简洁地表达，这就是为什么 s 表达式被选择为 WebAssembly 的文本格式的原因。

# 值、类型和指令

尽管详细覆盖*核心规范*的*文本格式*部分超出了本文的范围，但值得演示一些语言概念如何映射到相应的 Wat。以下图表演示了这些映射在一个样本 Wat 片段中。这是从 C 代码编译而来的，表示一个以单词作为参数并返回字符数的平方根的函数：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-wasm/img/7c3b4124-7f45-49c6-a933-de3bf3861864.png)

具有语言概念细节的 Wat 示例

如果您打算编写或编辑 Wat，请注意它支持块和行注释。指令被分成块，并包括设置和获取与有效类型相关联的变量的内存。您可以使用`if`语句控制逻辑流，并且使用`loop`关键字支持循环。

# 在开发过程中的作用

文本格式允许以文本形式表示二进制 Wasm 模块。这对于开发和调试的便利性有一些深远的影响。拥有 WebAssembly 模块的文本表示允许开发人员在浏览器中查看加载模块的源代码，从而消除了抑制 NaCl 采用的黑匣子问题。它还允许围绕故障排除模块构建工具。官方网站描述了驱动文本格式设计的用例：

• 在 WebAssembly 模块上查看源代码，从而自然地适应 Web（其中可以查看每个源代码）。

• 在没有源映射的情况下，在浏览器开发工具中呈现（这在最小可行产品（MVP）的情况下是必然的）。

• 直接编写 WebAssembly 代码的原因包括教学、实验、调试、优化和测试规范本身。

列表中的最后一项反映了文本格式并不打算在正常开发过程中手动编写，而是从诸如 Emscripten 之类的工具生成。在生成模块时，您可能不会看到或操作任何`.wat`文件，但在调试上下文中可能会查看它们。

文本格式不仅在调试方面有价值，而且具有这种中间格式可以减少对单个编译工具的依赖。目前存在多种不同的工具来消耗和发出这种 s 表达式语法，其中一些工具被 Emscripten 用于将您的代码编译成`.wasm`文件。

# 二进制格式和模块文件（Wasm）

*二进制格式*部分的*核心规范*提供了与*文本格式*部分相同级别的语言概念细节。在本节中，我们将简要介绍二进制格式的一些高级细节，并讨论构成 Wasm 模块的各个部分。

# 定义和模块概述

二进制格式被定义为抽象语法的密集线性编码。不要过于技术化，这基本上意味着它是一种高效的二进制形式，可以快速解码，文件大小小，内存使用减少。二进制格式的文件表示是`.wasm`文件，这将是 Emscripten 的编译输出，我们将用于示例。

*值*、*类型*和*指令*子部分在二进制格式的*核心规范*中与*文本格式*部分直接相关。每个概念都在编码的上下文中进行了介绍。例如，根据规范，整数类型使用 LEB128 可变长度整数编码进行编码，可以是无符号或有符号变体。如果您希望为 WebAssembly 开发工具，这些都是重要的细节，但如果您只打算在网站上使用它，则不是必需的。

*结构*、*二进制格式*和*文本格式*（wat）部分的*核心规范*都有一个*模块*子部分。我们在上一节中没有涵盖模块的方面，因为在二进制的上下文中描述它们更为谨慎。官方的 WebAssembly 网站为模块提供了以下描述：

"WebAssembly 中的可分发、可加载和可执行的代码单元称为**模块**。在运行时，可以使用一组导入值对模块进行**实例化**，以产生一个**实例**，它是一个不可变的元组，引用了运行模块可访问的所有状态。"

我们将在本章后面讨论如何使用 JavaScript 和 Web API 与模块进行交互，因此让我们建立一些上下文，以了解模块元素如何映射到 API 方法。

# 模块部分

一个模块由几个部分组成，其中一些您将通过 JavaScript API 进行交互：

+   导入（`import`）是可以在模块内访问的元素，可以是以下之一：

+   函数，可以在模块内使用`call`运算符调用

+   全局变量，可以通过`global`运算符在模块内访问

+   线性内存，可以通过`memory`运算符在模块内访问

+   表，可以通过`call_indirect`在模块内访问

+   导出（`export`）是可以由消费 API（即由 JavaScript 函数调用）访问的元素

+   模块启动函数（`start`）在模块实例初始化后调用

+   全局（`global`）包含全局变量的内部定义

+   线性内存（`memory`）包含具有初始内存大小和可选最大大小的线性内存的内部定义

+   数据（`data`）包含数据段数组，指定给定内存的固定范围的初始内容

+   表（`table`）是一个线性内存，其元素是特定表元素类型的不透明值：

+   在 MVP 中，其主要目的是在 C/C++中实现间接函数调用

+   元素（`elements`）是一个允许模块使用任何其他模块中的任何导入或内部定义表的元素进行初始化的部分

+   函数和代码：

+   函数部分声明了模块中定义的每个内部函数的签名

+   代码部分包含由函数部分声明的每个函数的函数体

一些关键字（`import`，`export`等）可能看起来很熟悉；它们出现在前一节的 Wat 文件的内容中。WebAssembly 的组件遵循一个直接对应 API 的逻辑映射（例如，您将`memory`和`table`实例传递给 JavaScript 的`WebAssembly.instantiate()`函数）。您与二进制格式的模块的主要交互将通过这些 API 进行。

# JavaScript 和 Web API

除了*WebAssembly 核心规范*之外，还有两个用于与 WebAssembly 模块交互的 API 规范：*WebAssembly JavaScript 接口*（JavaScript API）和*WebAssembly Web API*。在前面的章节中，我们涵盖了*核心规范*的相关方面，以便熟悉基础技术。如果您从未阅读过*核心规范*（或者跳过了本章的前几节），这并不会阻碍您在应用程序中使用 WebAssembly。但对于 API 来说情况并非如此，因为它们描述了实例化和与编译后的 Wasm 模块交互所需的方法和接口。在本节中，我们将回顾 Web 和 JavaScript API，并描述如何使用 JavaScript 加载和与 Wasm 模块进行通信。

# WebAssembly 存储和对象缓存

在深入讨论交互之前，让我们讨论 JavaScript 和 WebAssembly 在执行上下文中的关系。*核心规范*在*执行*部分包含了以下描述：

"在实例化模块或调用结果模块实例上的导出函数时，将执行 WebAssembly 代码。

执行行为是根据模拟程序状态的抽象机器来定义的。它包括一个堆栈，记录操作数值和控制结构，以及包含全局状态的抽象存储。"

在幕后，JavaScript 使用称为**代理**的东西来管理执行。定义中提到的*存储*包含在代理中。以下图表代表了一个 JavaScript 代理：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-wasm/img/d01b7a99-69fe-4b97-b7f2-b4fed202aff1.png)

JavaScript 代理元素

存储表示抽象机器的状态。WebAssembly 操作接受存储并返回更新后的存储。每个代理都与将 JavaScript 对象映射到 WebAssembly 地址的缓存相关联。那么这为什么重要呢？它代表了 WebAssembly 模块与 JavaScript 之间交互的基本方法。JavaScript 对象对应于*JavaScript API*中的 WebAssembly 命名空间。考虑到这一点，让我们深入了解接口。

# 加载模块和 WebAssembly 命名空间方法

*JavaScript API*涵盖了浏览器中全局`WebAssembly`对象上可用的各种对象。在讨论这些对象之前，我们将从`WebAssembly`对象上可用的方法开始，简要概述它们的预期目的：

+   `instantiate()`是用于编译和实例化 WebAssembly 代码的主要 API

+   `instantiateStreaming()`执行与`instantiate()`相同的功能，但它使用流式处理来编译和实例化模块，从而消除了一个中间步骤

+   `compile()`只编译 WebAssembly 模块，但不实例化它

+   `compileStreaming()`也只编译 WebAssembly 模块，但它使用类似于`instantiateStreaming()`的流式处理

+   `validate()`检查 WebAssembly 二进制代码以确保字节有效，并在有效时返回 true，无效时返回 false

`instantiateStreaming()`和`compileStreaming()`方法目前仅存在于*Web API*中。事实上，这两种方法构成了整个规范。`WebAssembly`对象上可用的方法主要用于编译和实例化模块。考虑到这一点，让我们讨论如何获取和实例化一个 Wasm 模块。

当您执行一个 fetch 调用来获取一个模块时，它会返回一个 Promise，该 Promise 解析为该模块的原始字节，这些字节需要加载到一个`ArrayBuffer`中并进行实例化。从现在开始，我们将把这个过程称为加载模块。

以下图表展示了这个过程：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-wasm/img/368f1c3b-c24a-4265-967f-6347f5fa8b34.png)

获取和加载 WebAssembly 模块

使用 Promises 实际上非常简单。以下代码演示了如何加载一个模块。`importObj`参数传递任何数据或函数给 Wasm 模块。您现在可以忽略它，因为我们将在第五章中更详细地讨论它，*创建和加载 WebAssembly 模块*：

```cpp
fetch('example.wasm')
  .then(response => response.arrayBuffer())
  .then(buffer => WebAssembly.instantiate(buffer, importObj))
  .then(({ module, instance }) => {
    // Do something with module or instance
  });
```

上面的示例规定了使用`instantiate()`方法加载模块的方法。`instantiateStreaming()`方法有些不同，并通过一步完成获取、编译和实例化模块来简化这个过程。以下代码使用这种方法实现了相同的目标（加载模块）：

```cpp
WebAssembly.instantiateStreaming(fetch('example.wasm'), importObj)
  .then(({ module, instance }) => {
    // Do something with module or instance
  });
```

实例化方法返回一个 Promise，该 Promise 解析为一个包含编译的`WebAssembly.Module`（`module`）和`WebAssembly.Instance`（`instance`）的对象，这两者将在本节后面进行详细介绍。在大多数情况下，您将使用其中一种方法在您的站点上加载 Wasm 模块。实例包含了所有可以从 JavaScript 代码调用的导出的 WebAssembly 函数。

`compile()`和`compileStreaming()`方法返回一个 Promise，该 Promise 只解析为一个编译的`WebAssembly.Module`。如果您想要在以后编译一个模块并实例化它，这将非常有用。**Mozilla 开发者网络**（**MDN**），由 Mozilla 管理的 Web 文档站点，提供了一个示例，其中编译的模块被传递给了一个 Web Worker。

就`validate()`方法而言，它的唯一目的是测试作为参数传入的类型数组或`ArrayBuffer`是否有效。这将在响应的原始字节加载到`ArrayBuffer`后调用。这个方法没有包含在代码示例中，因为尝试实例化或编译无效的 Wasm 模块将抛出`TypeError`或`WebAssembly`对象上存在的`Error`对象之一。我们将在本节后面介绍这些`Error`对象。

# WebAssembly 对象

除了在*加载模块和 WebAssembly 命名空间方法*部分介绍的方法之外，全局`WebAssembly`对象还有子对象，用于与和排查 WebAssembly 交互。这些对象直接对应我们在 WebAssembly 二进制和文本格式部分讨论的概念。以下列表包含了这些对象以及它们的定义，这些定义来自 MDN：

+   `WebAssembly.Module`对象包含了已经被浏览器编译的无状态 WebAssembly 代码，可以有效地与 worker 共享，缓存在`IndexedDB`中，并且可以被多次实例化

+   `WebAssembly.Instance`对象是`WebAssembly.Module`的一个有状态的可执行实例，其中包含了所有导出的 WebAssembly 函数，允许从 JavaScript 调用 WebAssembly 代码

+   `WebAssembly.Memory`，在使用构造函数调用时，创建一个新的`Memory`对象，它是一个可调整大小的`ArrayBuffer`，保存着被 WebAssembly `Instance`访问的内存的原始字节

+   `WebAssembly.Table`，在使用构造函数调用时，创建一个给定大小和元素类型的新`Table`对象，表示一个 WebAssembly `Table`（存储函数引用）

+   `WebAssembly.CompileError`在使用构造函数调用时，创建一个错误，指示在 WebAssembly 解码或验证过程中发生了问题

+   `WebAssembly.LinkError`在使用构造函数调用时，创建一个错误，指示在模块实例化过程中发生了问题

+   `WebAssembly.RuntimeError`在调用构造函数时创建一个错误，指示 WebAssembly 指定了一个陷阱（例如，发生了堆栈溢出）。

让我们分别深入研究每一个，从`WebAssembly.Module`对象开始。

# WebAssembly.Module

`WebAssembly.Module`对象是`ArrayBuffer`和实例化模块之间的中间步骤。`compile()`和`instantiate()`方法（以及它们的流式处理对应方法）返回一个解析为模块的 Promise（小写的 module 表示已编译的`Module`）。一个模块也可以通过直接将类型化数组或`ArrayBuffer`传递给构造函数来同步创建，但对于大型模块，这是不鼓励的。

`Module`对象还有三个静态方法：`exports()`、`imports()`和`customSections()`。所有三个方法都以模块作为参数，但`customSections()`以表示部分名称的字符串作为其第二个参数。自定义部分在*Core Specification*的*Binary Format*部分中描述，并且旨在用于调试信息或第三方扩展。在大多数情况下，你不需要定义这些。`exports()`函数在你使用一个你没有创建的 Wasm 模块时很有用，尽管你只能看到每个导出的名称和种类（例如，`function`）。

对于简单的用例，你不会直接处理`Module`对象或已编译的模块。大部分交互将在`Instance`中进行。

# WebAssembly.Instance

`WebAssembly.Instance`对象是实例化的 WebAssembly 模块，这意味着你可以从中调用导出的 WebAssembly 函数。调用`instantiate()`或`instantiateStreaming()`会返回一个解析为包含实例的对象的 Promise。你可以通过引用实例的`export`属性上函数的名称来调用 WebAssembly 函数。例如，如果一个模块包含一个名为`sayHello()`的导出函数，你可以使用`instance.exports.sayHello()`来调用该函数。

# WebAssembly.Memory

`WebAssembly.Memory`对象保存了 WebAssembly `Instance`访问的内存。这个内存可以从 JavaScript 和 WebAssembly 中访问和改变。要创建一个新的`Memory`实例，你需要通过`WebAssembly.Memory()`构造函数传递一个带有`initial`和（可选的）`maximum`值的对象。这些值以 WebAssembly 页面为单位，其中一个页面是 64KB。通过调用带有表示要增长的 WebAssembly 页面数量的单个参数的`grow()`函数来增加内存实例的大小。你也可以通过其`buffer`属性访问内存实例中包含的当前缓冲区。

MDN 描述了获取`WebAssembly.Memory`对象的两种方法。第一种方法是从 JavaScript 中构造它（`var memory = new WebAssembly.Memory(...)`），而第二种方法是由 WebAssembly 模块导出它。重要的一点是内存可以在 JavaScript 和 WebAssembly 之间轻松传递。

# WebAssembly.Table

`WebAssembly.Table`对象是一个类似数组的结构，用于存储函数引用。与`WebAssembly.Memory`一样，`Table`可以从 JavaScript 和 WebAssembly 中访问和改变。在撰写时，表只能存储函数引用，但随着技术的发展，很可能还可以存储其他实体。

要创建一个新的`Table`实例，你需要传递一个带有`element`、`initial`和（可选的）`maximum`值的对象。`element`成员是一个表示表中存储的值类型的字符串；目前唯一有效的值是`"anyfunc"`（用于函数）。`initial`和`maximum`值表示 WebAssembly `Table`中的元素数量。

您可以使用`length`属性访问`Table`实例中的元素数量。该实例还包括用于操作和查询表中元素的方法。`get()`方法允许您访问给定索引处的元素，该索引作为参数传递。`set()`方法允许您将第一个参数指定的索引处的元素设置为第二个参数指定的值（根据前面的说明，仅支持函数）。最后，`grow()`允许您增加`Table`实例（元素数量）的大小，增加的数量作为参数传递。

# WebAssembly 错误（CompileError、LinkError、RuntimeError）

JavaScript API 提供了用于创建特定于 WebAssembly 的`Error`对象实例的构造函数，但我们不会花太多时间来介绍这些对象。本节开头的对象定义列表描述了每个错误的性质，如果满足指定条件，则可能引发这些错误。这三个错误都可以使用消息、文件名和行号参数（均为可选）进行构造，并且具有与标准 JavaScript `Error`对象相同的属性和方法。

# 使用 WasmFiddle 连接各个部分

我们在本章中回顾了 WebAssembly 的各个元素以及相应的 JavaScript 和 Web API，但是理解这些元素如何组合在一起仍然可能会令人困惑。随着我们在本书中的示例中的进展，您将能够看到 C/C++、WebAssembly 和 JavaScript 是如何相互交互的，这些概念将变得更加清晰。

话虽如此，演示这种交互可能有助于澄清一些困惑。在本节中，我们将使用一个名为 WasmFiddle 的在线工具来演示这些元素之间的关系，以便您可以看到 WebAssembly 的实际运行情况，并对开发工作流程有一个高层次的概述。

# 什么是 WasmFiddle？

WasmFiddle 位于[`wasdk.github.io/WasmFiddle/`](https://wasdk.github.io/WasmFiddle/)，是一个在线代码编辑工具，允许您编写一些 C 或 C++代码并将其转换为 Wat，编译为 Wasm，或者直接使用 JavaScript 进行交互。C/C++和 JavaScript 编辑器都很简单，不打算用作您的主要开发环境，但它在 Wasm 编译器中提供了有价值的服务。在第三章 *设置开发环境*中，您将发现从零开始生成 Wasm 文件需要一些工作——能够将您的 C 代码粘贴到浏览器中并点击几个按钮会使事情变得更加方便。以下图表快速概述了界面：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-wasm/img/a30bacbd-3e98-45bf-a2af-c4c7b35c24ea.png)

WasmFiddle 用户界面的组件

如您所见，界面相对简单。让我们尝试一些代码！

# C 代码转换为 Wat

以下屏幕截图中左上角的窗格包含一个简单的 C 函数，该函数将 2 添加到指定为参数的数字。左下角的窗格包含相应的 Wat：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-wasm/img/14cdb18b-d295-4891-a9a6-a4ab72246a22.png)

C 函数和相应的 Wat

如果这看起来很熟悉，那是因为相同的代码在本章开头对 Wat 的 s 表达式进行了解释时使用过。深入挖掘一下，您可以看到 C 代码如何对应于 Wat 输出。`addTwo()`函数作为字符串从模块中导出，位于第`5`行。第`5`行还包含`(func $addTwo)`，它引用了第`6`行上的`$addTwo`函数。第`6`行指定可以传入一个`i32`类型（整数）的单个参数，并且返回的结果也是`i32`。在左上角（或 C/C++编辑器上方）按下“Build”按钮将把 C 代码编译成 Wasm 文件。一旦构建完成，Wasm 将可以供下载或与 JavaScript 进行交互。

# Wasm 到 JavaScript

以下屏幕截图中的右上方窗格包含一些 JavaScript 代码，用于编译在上一步生成的 Wasm。`wasmCode`是在构建完成时生成的，因此应该自动可用。WasmFiddle 不使用`instantiate()`方法，而是创建一个编译后的`WebAssembly.Module`实例，并将其传递给新的`WebAssembly.Instance`的构造函数。`wasmImports`对象目前为空，但如果需要，我们可以传入`WebAssembly.Memory`和`WebAssembly.Table`实例：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-wasm/img/82dade82-c419-4ccb-85d2-89f58e525bcb.png)

JavaScript 代码调用从编译后的 Wasm 模块中的 C 函数

JavaScript 的最后一行将`addTwo()`的结果打印到右下窗格中，当传入数字`2`时。`log()`方法是一个自定义函数，确保输出打印到右下窗格（数字`4`）。请注意 JavaScript 代码如何与`wasmInstance`交互。`addTwo()`函数是从实例的`exports`对象中调用的。尽管这是一个人为的例子，但它演示了 C 或 C++代码在被 JavaScript 用作 Wasm 模块之前经历的步骤。

# 总结

在本章中，我们讨论了 WebAssembly 的元素及其关系。 *核心规范*的结构被用来描述文本和二进制格式到一个共同的抽象语法的映射。我们强调了文本格式（Wat）在调试和开发环境中的有用性，以及为什么 s 表达式非常适合抽象语法的文本表示。我们还回顾了有关二进制格式和构成模块的各种元素的细节。在 JavaScript 和 Web API 中定义了方法和对象，并描述了它们在 WebAssembly 交互中的作用。最后，使用 WasmFiddle 工具演示了源代码、Wat 和 JavaScript 之间的关系的简单示例。

在第三章中，*设置开发环境*，我们将安装开发工具，以便有效地使用 WebAssembly 进行工作。

# 问题

1.  s 表达式擅长表示什么类型的数据？

1.  二进制和文本格式之间共享的四个语言概念是什么？

1.  文本格式的一个用例是什么？

1.  可以存储在 WebAssembly `Table`中的唯一元素类型是什么？

1.  JavaScript 引擎使用什么来管理执行？

1.  哪种方法需要更少的代码来实例化一个模块，`instantiate()`还是`instantiateStreaming()`？

1.  `WebAssembly` JavaScript 对象上有哪些错误对象，以及是什么事件导致了每一个错误对象？

# 进一步阅读

+   MDN 上的 WebAssembly：[`developer.mozilla.org/en-US/docs/WebAssembly`](https://developer.mozilla.org/en-US/docs/WebAssembly)

+   WasmFiddle：[`wasdk.github.io/WasmFiddle`](https://wasdk.github.io/WasmFiddle)

+   维基百科上的 s 表达式：[`en.wikipedia.org/wiki/S-expression`](https://en.wikipedia.org/wiki/S-expression)

+   树的示例：[`interactivepython.org/runestone/static/pythonds/Trees/ExamplesofTrees.html`](http://interactivepython.org/runestone/static/pythonds/Trees/ExamplesofTrees.html)


# 第三章：设置开发环境

现在您熟悉了 WebAssembly 的元素，是时候设置一个合适的开发环境了。使用 WebAssembly 进行开发等同于使用 C 或 C++进行开发。区别在于构建过程和输出。在本章中，我们将介绍开发工具，并讨论如何在您的系统上安装和配置它们。

本章的目标是了解以下内容：

+   如何安装所需的开发工具（Git、Node.js 和 Visual Studio Code）

+   如何配置 Visual Studio Code 以便使用 C/C++和 WebAssembly 扩展

+   如何设置本地 HTTP 服务器来提供 HTML、JavaScript 和`.wasm`文件

+   检查浏览器是否支持 WebAssembly

+   有哪些有用的工具可以简化和改进开发过程

# 安装开发工具

您需要安装一些应用程序和工具来开始开发 WebAssembly。我们将使用文本编辑器 Visual Studio Code 来编写我们的 C/C++、JavaScript、HTML 和 Wat。我们还将使用 Node.js 来提供文件和 Git 来管理我们的代码。我们将使用软件包管理器来安装这些工具，这使得安装过程比手动下载和安装要简单得多。在本节中，我们将涵盖操作系统，以及每个平台的软件包管理器。我们还将简要介绍每个应用程序在开发过程中的作用。

# 操作系统和硬件

为了确保安装和配置过程顺利进行，重要的是要了解我在本书中使用的操作系统。如果遇到问题，可能是由于您使用的平台与我使用的平台不兼容。在大多数情况下，您不应该遇到问题。为了排除操作系统版本可能导致的问题，我提供了我在下面列表中使用的操作系统的详细信息：

# macOS

+   High Sierra，版本 10.13.x

+   2.2 GHz 英特尔 i7 处理器

+   16 GB 的 RAM

# Ubuntu

+   在 VMware Fusion 中运行的 Ubuntu 16.04 LTS

+   2.2 GHz 英特尔 i7 处理器

+   4 GB 的 RAM

# Windows

+   Windows 10 Pro 在 VMware Fusion 中运行

+   2.2 GHz 英特尔 i7 处理器

+   8 GB 的 RAM

# 软件包管理器

软件包管理器是简化软件安装过程的工具。它们允许我们在命令行中升级、配置、卸载和搜索可用软件，而无需访问网站下载和运行安装程序。它们还简化了具有多个依赖项或需要在使用前手动配置的软件的安装过程。在本节中，我将介绍每个平台的软件包管理器。

# macOS 的 Homebrew

Homebrew 是 macOS 的一个优秀的软件包管理器，它允许我们直接安装大多数我们将使用的工具。Homebrew 就像在终端中粘贴以下命令并运行它一样简单：

```cpp
/usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
```

您将在终端中看到一些消息，指导您完成安装过程。完成后，您需要安装一个名为**Homebrew-Cask**的 Homebrew 扩展，它允许您安装 macOS 应用程序，而无需下载安装程序，挂载它，并将应用程序拖入`Applications`文件夹。您可以通过运行以下命令来安装：

```cpp
brew tap caskroom/cask
```

就是这样！现在你可以通过运行以下任一命令来安装应用程序：

```cpp
# For command line tools: brew install <Tool Name> 
# For desktop applications:
brew cask install <Application Name>
```

# Ubuntu 的 Apt

Apt 是 Ubuntu 提供的软件包管理器；无需安装。它允许您直接安装命令行工具和应用程序。如果 Apt 的存储库中没有某个应用程序，您可以使用以下命令添加存储库：

```cpp
add-apt-repository 
```

# Windows 的 Chocolatey

Chocolatey 是 Windows 的软件包管理器。它类似于 Apt，可以让您安装命令行工具和应用程序。要安装 Chocolatey，您需要以管理员身份运行命令提示符（`cmd.exe`）。您可以通过按下开始菜单按钮，输入 cmd，右键单击命令提示符应用程序并选择以管理员身份运行来实现这一点：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-wasm/img/257d1dc9-7c8b-4e3e-91ff-2697e0749527.png)

以管理员身份运行命令提示符

然后运行以下命令：

```cpp
@"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))" &amp;&amp; SET "PATH=%PATH%;%ALLUSERSPROFILE%\chocolatey\bin"
```

获取命令文本的最简单方法是通过 Chocolatey 的安装页面[`chocolatey.org/install`](https://chocolatey.org/install)。在*使用 cmd.exe 安装*部分下有一个按钮可以将文本复制到剪贴板上。您也可以按照安装页面上的步骤使用 PowerShell 来安装应用程序。

# Git

Git 是一个**版本控制系统**（**VCS**），它允许您跟踪文件的更改并在多个开发人员共同贡献到同一代码库的工作之间进行管理。Git 是 GitHub 和 GitLab 的 VCS 引擎，并且也可在 Bitbucket 上使用（它们还提供 Mercurial，这是另一个 VCS）。Git 将允许我们从 GitHub 克隆存储库，并且是下一章中将要介绍的 EMS DK 的先决条件。在本节中，我们将介绍 Git 的安装过程。

# 在 macOS 上安装 Git

如果您使用的是 macOS，Git 可能已经可用。macOS 自带了 Apple Git，可能会比最新版本落后几个版本。对于本书的目的，您已经安装的版本应该足够了。如果您希望升级，可以通过在终端中运行以下命令来安装最新版本的 Git：

```cpp
# Install Git to the Homebrew installation folder (/usr/local/bin/git):
brew install git

# Ensure the default Git is pointing to the Homebrew installation:
sudo mv /usr/bin/git /usr/bin/git-apple
```

如果运行此命令，您应该会看到`/usr/local/bin/git`：

```cpp
which git
```

您可以通过运行以下命令来检查安装是否成功：

```cpp
git --version
```

# 在 Ubuntu 上安装 Git

您可以使用`apt`来安装 Git；只需在终端中运行以下命令：

```cpp
sudo apt install git
```

您可以通过运行以下命令来检查安装是否成功：

```cpp
git --version
```

# 在 Windows 上安装 Git

您可以使用 Chocolatey 来安装 Git。打开命令提示符或 PowerShell 并运行以下命令：

```cpp
choco install git
```

您可以通过运行以下命令来检查安装是否成功：

```cpp
git --version
```

您可以通过在安装命令的末尾添加`-y`来绕过确认消息（例如，`choco install git -y`）。您还可以选择始终跳过确认，方法是输入

**`choco feature enable -n allowGlobalConfirmation`** 命令。

# Node.js

Node.js 的官方网站将其描述为一个异步事件驱动的 JavaScript 运行时。Node 旨在构建可扩展的网络应用程序。我们将在本书中使用它来提供我们的文件并在浏览器中处理它们。Node.js 捆绑了`npm`，这是 JavaScript 的软件包管理器，它将允许我们全局安装软件包并通过命令行访问它们。在本节中，我们将介绍使用**Node 版本管理器**（**nvm**）在每个平台上的安装过程。

# nvm

我们将使用 Node.js 的**长期稳定**（**LTS**）版本（版本 8）来确保我们使用平台的最稳定版本。我们将使用`nvm`来管理 Node.js 版本。这将防止冲突，如果您已经在计算机上安装了更高（或更低）版本的 Node.js。`nvm`允许您安装多个 Node.js 版本，并可以快速切换到单个终端窗口的上下文中进行隔离。

# 在 macOS 上安装 nvm

在终端中运行以下命令：

```cpp
brew install nvm
```

按照 Homebrew 指定的后续安装步骤确保您可以开始使用它（您可能需要重新启动终端会话）。如果在执行步骤之前清除了终端内容，您可以运行此命令再次查看安装步骤：

```cpp
brew info nvm
```

您可以通过运行以下命令来检查安装是否成功：

```cpp
nvm --version
```

# 在 Ubuntu 上安装 nvm

Ubuntu 捆绑了`wget`，它可以使用 HTTP/S 和 FTP/S 协议检索文件。`nvm`的 GitHub 页面（[`github.com/creationix/nvm`](https://github.com/creationix/nvm)）包含使用`wget`安装它的以下命令：

```cpp
wget -qO- https://raw.githubusercontent.com/creationix/nvm/v0.33.11/install.sh | bash
```

安装完成后，重新启动终端以完成安装。您可以通过运行以下命令来检查安装是否成功：

```cpp
nvm --version
```

# 在 Windows 上安装 nvm

`nvm`目前不支持 Windows，因此您实际上正在安装一个名为`nvm`-windows 的不同应用程序。`nvm`-windows 的 GitHub 页面位于[`github.com/coreybutler/nvm-windows`](https://github.com/coreybutler/nvm-windows)。一些命令略有不同，但我们运行的安装命令将是相同的。要安装`nvm`-windows，请打开命令提示符或 PowerShell 并运行此命令：

```cpp
choco install nvm
```

您可以通过运行以下命令来检查安装是否成功：

```cpp
nvm --version
```

# 使用 nvm 安装 Node.js

安装`nvm`后，您需要安装本书中将使用的 Node.js 版本：版本 8.11.1。要安装它，请运行以下命令：

```cpp
nvm install 8.11.1
```

如果您之前没有安装 Node.js 或`nvm`，它将自动将其设置为默认的 Node.js 安装，因此此命令的输出应为`v8.11.1`：

```cpp
node --version
```

如果您已安装现有的 Node.js 版本，您可以将 v8.11.1 作为默认版本，或者确保在使用本书示例时运行此命令以使用 v8.11.1：

```cpp
nvm use 8.11.1
```

您可以在代码所在的文件夹中创建一个名为`.nvmrc`的文件，并将其填充为`v8.11.1`。您可以在此目录中运行`nvm use`，它将设置版本为`8.11.1`，而无需指定它。

# GNU make 和 rimraf

在`learn-webassembly`存储库中，代码示例使用 GNU Make 和 VS Code 的任务功能（我们将在第五章中介绍）来执行整本书中定义的构建任务。GNU Make 是一个非常好的跨平台工具，用于自动化构建过程。您可以在[`www.gnu.org/software/make`](https://www.gnu.org/software/make)上阅读更多关于 GNU Make 的信息。让我们回顾每个平台的安装步骤。

# macOS 和 Ubuntu 上的 GNU Make

如果您使用的是 macOS 或 Linux，则 GNU `make`应该已经安装。要验证这一点，请在终端中运行以下命令：

```cpp
make -v
```

如果您看到版本信息，您已经准备好了。跳到*安装 rimraf*部分。否则，请按照您的平台的 GNU Make 安装说明进行操作。

# 在 macOS 上安装 GNU Make

要在 macOS 上安装 GNU Make，请从终端运行以下命令：

```cpp
brew install make
```

您可以通过运行以下命令来检查安装是否成功：

```cpp
make -v
```

如果您看到版本信息，请跳到*安装 rimraf*部分。

# 在 Ubuntu 上安装 GNU Make

要在 Ubuntu 上安装 GNU Make，请从终端运行以下命令：

```cpp
sudo apt-get install make
```

您可以通过运行以下命令来检查安装是否成功：

```cpp
make -v
```

如果您看到版本信息，请跳到*安装 rimraf*部分。

# 在 Windows 上安装 GNU make

您可以使用 Chocolatey 在 Windows 上安装 GNU `make`。打开命令提示符或 PowerShell 并运行以下命令：

```cpp
choco install make
```

您可能需要重新启动 CLI 以使用`make`命令。重新启动后，运行以下命令以验证安装：

```cpp
make -v
```

如果您看到版本信息，请继续下一节。如果遇到问题，您可能需要下载并安装[`gnuwin32.sourceforge.net/packages/make.htm`](http://gnuwin32.sourceforge.net/packages/make.htm)上的设置包。

# 安装 rimraf

在 Makefiles 或 VS Code 任务中定义的一些构建步骤会删除文件或目录。根据您的平台和 shell，删除文件或文件夹所需的命令会有所不同。为了解决这个问题，我们将使用`rimraf npm`包（[`www.npmjs.com/package/rimraf`](https://www.npmjs.com/package/rimraf)）。全局安装该包会提供一个`rimraf`命令，该命令可以执行适合操作系统和 shell 的正确删除操作。

要安装`rimraf`，请确保已安装 Node.js，并从 CLI 运行以下命令：

```cpp
npm install -g rimraf
```

为了确保安装成功，请运行以下命令：

```cpp
rimraf --help
```

您应该看到使用说明和一系列命令行标志。让我们继续进行 VS Code 安装。

# VS Code

VS Code 是一个跨平台的文本编辑器，支持多种语言，并拥有丰富的扩展生态系统。集成调试和 Git 支持内置，并且不断添加新功能。我们可以在本书的整个 WebAssembly 开发过程中使用它。在本节中，我们将介绍每个平台的安装步骤：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-wasm/img/d936d227-0ea4-44a0-8ffa-f43768420eb0.png)

来自 Visual Studio Code 网站的屏幕截图

# 在 macOS 上安装 Visual Studio Code

使用 Homebrew-Cask 安装 VS Code。在终端中运行以下命令进行安装：

```cpp
brew cask install visual-studio-code
```

安装完成后，您应该能够从“应用程序”文件夹或 Launchpad 启动它。

# 在 Ubuntu 上安装 Visual Studio Code

在 Ubuntu 上安装 VS Code 的过程有一些额外的步骤，但仍然相对简单。首先，从 VS Code 的下载页面（[`code.visualstudio.com/Download`](https://code.visualstudio.com/Download)）下载`.deb`文件。下载完成后，运行以下命令完成安装：

```cpp
# Change directories to the Downloads folder
cd ~/Downloads

# Replace <file> with the name of the downloaded file
sudo dpkg -i <file>.deb

# Complete installation
sudo apt-get install -f
```

如果出现缺少依赖项错误，您可以在`sudo dpkg`之前运行以下命令来解决它：

```cpp
sudo apt-get install libgconf-2-4
sudo apt --fix-broken install
```

您现在应该能够从启动器中打开 VS Code 了。

# 在 Windows 上安装 VS Code

您可以使用 Chocolatey 安装 VS Code。从命令提示符或 PowerShell 运行以下命令：

```cpp
choco install visualstudiocode
```

安装后，您可以从“开始”菜单中访问它。

您可以通过在 CLI 中运行`code .`来打开当前工作目录的 VS Code。

# 配置 VS Code

VS Code 是一个功能强大的文本编辑器，具有许多出色的功能。除了高度可配置和可定制之外，它还拥有一个非常丰富的扩展生态系统。我们需要安装其中一些扩展，这样我们就不需要为不同的编程语言使用不同的编辑器。在本节中，我们将介绍如何配置 VS Code 以及安装哪些扩展来简化 WebAssembly 开发过程。

# 管理设置和自定义

自定义和配置 VS Code 非常简单和直观。您可以通过在 macOS 上选择 Code | Preferences | Settings 或在 Windows 上选择 File | Preferences | Settings 来管理自定义设置，如编辑器字体和选项卡大小。用户和工作区设置分别在 JSON 文件中管理，并且在您无法记住设置的确切名称时提供自动完成。您还可以通过在首选项菜单中选择适当的选项来更改主题或键盘快捷键。设置文件也是您可以为安装的任何扩展设置自定义设置的地方。安装扩展时会默认添加一些设置，因此更改它们就像更新和保存此文件一样简单。

# 扩展概述

在配置过程中，我们需要安装一些扩展。在 VS Code 中，有多种方式可以查找和安装扩展。我喜欢点击扩展按钮（编辑器左侧活动栏顶部的第四个按钮），在搜索框中输入我要找的内容，然后点击绿色的安装按钮来安装我想要的扩展。你也可以访问 VS Code Marketplace（[`marketplace.visualstudio.com/vscode`](https://marketplace.visualstudio.com/vscode)），搜索并选择你想要安装的扩展，然后在扩展页面上点击绿色的安装按钮。你也可以通过命令行来管理扩展。更多信息，请访问[`code.visualstudio.com/docs/editor/extension-gallery`](https://code.visualstudio.com/docs/editor/extension-gallery)：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-wasm/img/a4681032-4748-44a9-a937-d92678e2636f.png)

在 VS Code 中安装扩展

# C/C++和 WebAssembly 的配置

VS Code 默认不支持 C 和 C++，但有一个很好的扩展可以让你使用这些语言。它也不支持 WebAssembly 文本格式的语法高亮，但有一个扩展可以添加这个功能。在本节中，我们将介绍*为 VS Code 安装和配置 C/C++*和*WebAssembly Toolkit for VSCode*扩展。

# 为 VS Code 安装 C/C++

VS Code 的 C/C++扩展包括了一些用于编写和调试 C 和 C++代码的功能，比如自动补全、符号搜索、类/方法导航、逐行代码步进等等。要安装这个扩展，可以在扩展中搜索 C/C++并安装由微软创建的名为 C/C++的扩展，或者访问扩展的官方页面[`marketplace.visualstudio.com/items?itemName=ms-vscode.cpptools`](https://marketplace.visualstudio.com/items?itemName=ms-vscode.cpptools)并点击绿色的安装按钮。

安装完成后，你可以通过在 VS Code 的扩展列表中选择扩展并选择*Contributions*标签来查看扩展的配置细节。这个标签包含了各种设置、命令和调试器的详细信息：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-wasm/img/db5aeb52-94d7-4d7b-9af0-e3637e5cb4ce.png)

C/C++扩展的*Contributions*标签

# 为 VS Code 配置 C/C++

微软有一个官方页面专门介绍这个扩展，你可以在[`code.visualstudio.com/docs/languages/cpp`](https://code.visualstudio.com/docs/languages/cpp)上查看。这个页面描述了如何通过使用 JSON 文件进行配置等内容。让我们首先创建一个新的配置文件来管理我们的 C/C++环境。你可以通过按下*F1*键，输入 C/C，然后选择 C/Cpp: Edit Configurations…来生成一个新的配置文件：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-wasm/img/653b245b-f3a0-4fb5-bacd-9624555a6bde.png)

C/C++扩展选项的命令面板

这将在当前项目的`.vscode`文件夹中生成一个新的`c_cpp_properties.json`文件。该文件包含了关于你的 C/C++编译器的配置选项，基于你的平台、要使用的 C 和 C++标准，以及头文件的包含路径。生成后，你可以关闭这个文件。当我们配置 EMSDK 时，我们会再次访问它。

# VSCode 的 WebAssembly 工具包

目前有几种不同的 WebAssembly 扩展可用于 VS Code。我正在使用 VSCode 的 WebAssembly 工具包扩展，因为它允许你右键单击一个`.wasm`文件并选择 Show WebAssembly，这样就可以显示文件的 Wat 表示。你可以通过扩展面板（搜索 WebAssembly）或从 VS Code Marketplace 的官方扩展页面（[`marketplace.visualstudio.com/items?itemName=dtsvet.vscode-wasm`](https://marketplace.visualstudio.com/items?itemName=dtsvet.vscode-wasm)）安装这个扩展：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-wasm/img/e5df8895-859b-40c0-a647-5c7d51fd567e.png)

使用 VS Code 扩展的 WebAssembly Toolkit 查看`.wasm`文件的 Wat

安装完成后，您就可以开始了！现在您已经安装了所有必需的扩展，让我们评估一些可简化常见任务的可选扩展。

# 其他有用的扩展

VS Code 有一些很棒的扩展，可以提高效率并自定义界面。在本节中，我将介绍一些我安装的扩展，这些扩展可以简化常见任务以及用户界面/图标主题。您不需要为本书中的示例安装这些扩展，但您可能会发现其中一些有用。

# 自动重命名标签

在处理 HTML 时，此扩展非常有用。如果更改标记类型，它会自动更改关闭标记的名称。例如，如果您有一个`<div>`元素，并且想将其更改为`<span>`，将打开元素的文本更改为`span`将更新关闭元素的文本（`</div>`更改为`</span>`）：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-wasm/img/94ea0207-f80b-43fd-8907-fca386c945c7.png)

自动重命名标签重命名 HTML 标签

# 括号对颜色器

此扩展为您的代码着色括号，大括号和括号，以便您可以快速识别开放和关闭括号。WebAssembly 的文本格式广泛使用括号，因此能够确定哪些元素包含在哪个列表中，使调试和评估变得更加简单：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-wasm/img/6a7bd70b-1c52-43b9-ba23-3db2d688ca43.png)

在 Wat 文件中匹配括号的括号对颜色器

# Material Icon 主题和 Atom One Light 主题

在 VS Code Marketplace 上有超过 1,000 个图标和界面主题可用。我在本节中包括 Material Icon 主题和 Atom One Light 主题，因为它们在本书的截图中被使用。Material Icon 主题非常受欢迎，已经有超过 200 万次下载，而 Atom One Light 主题已经有超过 70,000 次下载：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-wasm/img/c32d88eb-7850-49c3-9ff4-84e0eb89969d.png)

Material Icons 主题中的图标

# 为 Web 设置

与 Wasm 模块交互和调试将在浏览器中进行，这意味着我们需要一种方法来提供包含我们示例文件的文件夹。正如我们在第二章中讨论的那样，*WebAssembly 的元素-Wat，Wasm 和 JavaScript API*，WebAssembly 被集成到浏览器的 JavaScript 引擎中，但您需要确保您使用支持它的浏览器。在本节中，我们将提供克隆书籍示例存储库的说明。我们还将回顾如何快速设置本地 Web 服务器以进行测试和评估浏览器选项，以确保您能够在本地开发。

# 克隆书籍示例存储库

您可能希望现在克隆 GitHub 存储库，其中包含本书中的所有示例。您绝对需要为第七章 *从头开始创建应用程序*克隆代码，因为应用程序的代码库太大，无法放入单个章节中。选择硬盘上的一个文件夹，并运行以下命令来克隆存储库：

```cpp
git clone https://github.com/mikerourke/learn-webassembly
```

克隆过程完成后，您会发现示例按章节组织。如果一个章节中有几个示例，它们将按章节文件夹内的子文件夹进行拆分。

如果您使用 Windows，请不要将存储库克隆到`\Windows`文件夹或任何其他权限受限的文件夹中。否则，在尝试编译示例时，您将遇到问题。

# 安装本地服务器

我们将使用一个`npm`包`serve`来提供文件。要安装，只需运行此命令：

```cpp
npm install -g serve
```

安装完成后，您可以在任何文件夹中提供文件。为了确保它正常工作，让我们尝试提供一个本地文件夹。本节的代码位于`learn-webassembly`存储库的`/chapter-03-dev-env`文件夹中。按照以下说明验证您的服务器安装：

1.  首先，让我们创建一个包含我们将在本书的其余部分中使用的代码示例的文件夹（示例使用名称`book-examples`）。

1.  启动 VS Code，并从菜单栏中选择文件 | 打开...（对于 macOS/Linux），以及文件 | 打开文件夹...（对于 Windows）。

1.  接下来，选择文件夹`book-examples`，然后按打开（或选择文件夹）按钮。

1.  一旦 VS Code 完成加载，右键单击 VS Code 文件资源管理器中的位置，并从菜单中选择新文件夹，命名文件夹为`chapter-03-dev-env`。

1.  选择`chapter-03-dev-env`文件夹，然后按新建文件按钮（或*Cmd*/*Ctrl* + *N*）创建一个新文件。将文件命名为`index.html`，并填充以下内容：

```cpp
<!doctype html>
<html lang="en-us">
  <title>Test Server</title>
</head>
<body>
  <h1>Test</h1>
  <div>
    This is some text on the main page. Click <a href="stuff.html">here</a>
    to check out the stuff page.
  </div>
</body>
</html>
```

1.  在`chapter-03-dev-env`文件夹中创建另一个名为`stuff.html`的文件，并填充以下内容：

```cpp
<!doctype html>
<html lang="en-us">
<head>
  <title>Test Server</title>
</head>
<body>
  <h1>Stuff</h1>
  <div>
    This is some text on the stuff page. Click <a href="index.html">here</a>
    to go back to the index page.
  </div>
</body>
</html>
```

1.  我们将使用 VS Code 的集成终端来提供文件。您可以通过选择 View | Integrated Terminal 来访问此功能，或者使用键盘快捷键*Ctrl* + *`*（*`*是*Esc*键下的反引号键）。加载后，运行此命令来提供工作文件夹：

```cpp
serve -l 8080 chapter-03-dev-env
```

您应该看到以下内容：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-wasm/img/00cc7407-20b7-42e2-8831-9dcedd076726.png)

在终端中运行 serve 命令的结果

`-l 8080`标志告诉`serve`在端口`8080`上提供文件。第一个链接（`http://127.0.0.1:8080`）只能在您的计算机上访问。下面的任何链接都可以用来从本地网络上的另一台计算机访问页面。如果您在浏览器中导航到第一个链接（`http://127.0.0.1:8080/index.html`），您应该会看到这个：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-wasm/img/2c6d3092-1cb0-4e6e-8aa7-436774502b04.png)

在 Google Chrome 中提供的测试页面

单击此处链接应该将您带到 Stuff 页面（地址栏将显示`127.0.0.1:8080/stuff.html`）。如果一切正常，现在是验证您的浏览器的时候了。

# 验证您的浏览器

为了确保您能够在浏览器中测试示例，您需要确保全局存在`WebAssembly`对象。为了防止与浏览器兼容性相关的任何问题，我建议您安装 Google Chrome 或 Mozilla Firefox 进行开发。如果您之前安装了这两个浏览器中的任何一个，那么您的浏览器很有可能已经是有效的。为了做到全面，我们仍将介绍验证过程。在本节中，我将回顾您可以采取的步骤，以确保您的浏览器支持 WebAssembly。

# 验证 Google Chrome

验证 Chrome 的过程非常简单。选择看起来像三个垂直点的按钮（在地址栏旁边），然后选择**更多工具** | **开发者工具**，或者使用键盘快捷键*Cmd*/*Ctrl* + *Shift* + *I*：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-wasm/img/a8ed36a6-4d8f-4db0-9a43-316d02af59ee.png)

在 Google Chrome 中访问开发者工具

一旦开发者工具窗口出现，选择控制台选项卡，输入`WebAssembly`，然后按*Enter*。如果您看到这个，您的浏览器是有效的：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-wasm/img/8a26528d-e9a8-4b91-920d-52a4472250e0.png)

在 Google Chrome 的开发者工具控制台中验证 WebAssembly 的结果

# 验证 Mozilla Firefox

验证 Firefox 的过程与验证 Google Chrome 几乎相同。选择**工具** | **Web 开发者** | **切换工具**，或者使用键盘快捷键*Cmd*/*Ctrl* + *Shift* + *I*：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-wasm/img/ec99f38f-7129-4e8c-a154-e616dc89e593.png)

在 Mozilla Firefox 中访问开发者工具

选择控制台选项卡，点击命令输入框，输入`WebAssembly`，然后按*Enter*。如果您的 Firefox 版本有效，您将看到这个：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-wasm/img/a9aa4970-18d1-42f9-94fa-a572856d2b08.png)

在 Mozilla Firefox 中验证 WebAssembly 的结果

# 验证其他浏览器

其他浏览器的验证过程基本相同；在不同浏览器之间唯一不同的验证方面是如何访问开发者工具。如果`WebAssembly`对象可以通过您正在使用的浏览器的控制台访问，您可以使用该浏览器进行 WebAssembly 开发。

# 其他工具

除了我们在前几节中介绍的应用程序和工具之外，还有一些功能丰富且免费的工具可以极大地改善您的开发过程。我没有时间介绍它们所有，但我想强调一下我经常使用的工具。在本节中，我将简要介绍每个平台上可用的一些流行的工具和应用程序。

# macOS 的 iTerm2

默认的 macOS 安装包括 Terminal 应用程序，Terminal，这对本书的使用已经足够了。如果您想要一个更全面的终端，iTerm2 是一个很好的选择。它提供诸如分割窗口、广泛的定制、多个配置文件和可以显示笔记、运行作业、命令历史等的工具栏功能。您可以从官方网站([`www.iterm2.com/`](https://www.iterm2.com/))下载图像文件并手动安装，或者使用 Homebrew-Cask 安装 iTerm，使用以下命令：

```cpp
brew cask install iterm2
```

这是 iTerm2 打开并显示多个编辑器窗口的样子：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-wasm/img/25f36b2a-329f-46ea-b070-2f580add757f.png)

具有多个窗格和工具栏的 iTerm 实例

# Ubuntu 的 Terminator

Terminator 是 Ubuntu 的 iTerm 和`cmder`，是一个终端仿真器，允许在单个窗口内使用多个选项卡和窗格。Terminator 还提供诸如拖放、查找功能和大量插件和主题等功能。您可以通过`apt`安装 Terminator。为了确保您使用的是最新版本，请在终端中运行以下命令：

```cpp
sudo add-apt-repository ppa:gnome-terminator
sudo apt-get update
sudo apt-get install terminator 
```

参考截图：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-wasm/img/e8a7a5ed-adea-42a2-9d92-b9c55bc1a87b.png)

从 http://technicalworldforyou.blogspot.com 获取的终结者截图

B09984_03_17

# Windows 的 cmder

`cmder`是 Windows 的控制台仿真器，为标准命令提示符或 PowerShell 添加了许多功能和特性。它提供诸如多个选项卡和可定制性之类的功能。它允许您在同一程序中打开不同外壳的实例。您可以从官方网站([cmder.net](https://cmder.net))下载并安装它，或者使用以下命令使用 Chocolatey 安装它：

```cpp
choco install cmder
```

这就是它的样子：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-wasm/img/2ec1d160-3abc-4e51-9614-da686a21035e.png)

官方网站的 cmder 截图

# Zsh 和 Oh-My-Zsh

Zsh 是一个改进了 Bash 的交互式 shell。Oh-My-Zsh 是 Zsh 的配置管理器，具有各种有用的插件。您可以在他们的网站上看到整个列表([`github.com/robbyrussell/oh-my-zsh`](https://github.com/robbyrussell/oh-my-zsh))。例如，如果您想在 CLI 中拥有强大的自动完成和语法高亮功能，可以使用诸如 zsh-autosuggestion 和 zsh-syntax-highlighting 等插件。您可以在 macOS、Linux 和 Windows 上安装和配置 Zsh 和 Oh-My-Zsh。Oh-My-Zsh 页面上有安装说明以及主题和插件列表。

# 摘要

在本章中，我们介绍了我们将用于开始使用 WebAssembly 进行工作的开发工具的安装和配置过程。我们讨论了如何使用操作系统的软件包管理器（例如 macOS 的 Homebrew）快速轻松地安装 Git、Node.js 和 VS Code。还介绍了配置 VS Code 的步骤以及您可以添加的必需和可选扩展以增强开发体验。我们讨论了如何安装本地 Web 服务器进行测试以及如何验证浏览器以确保支持 WebAssembly。最后，我们简要回顾了一些您可以安装到平台上以帮助开发的其他工具。

在第四章中，*安装所需的依赖项*，我们将安装所需的依赖项并测试工具链。

# 问题

1.  你应该使用哪个操作系统的软件包管理器？

1.  BitBucket 支持 Git 吗？

1.  为什么我们使用 Node.js 的第 8 个版本而不是最新版本？

1.  你如何在 Visual Studio Code 中更改颜色主题？

1.  你如何访问 Visual Studio Code 中的命令面板？

1.  你如何检查浏览器是否支持 WebAssembly？

1.  *其他工具*部分中的工具在所有三个操作系统上都受支持吗？

# 进一步阅读

+   Homebrew：[`brew.sh`](https://brew.sh)

+   `apt`文档：[`help.ubuntu.com/lts/serverguide/apt.html.en`](https://help.ubuntu.com/lts/serverguide/apt.html.en)

+   Chocolatey：[`chocolatey.org`](https://chocolatey.org)

+   Git：[`git-scm.com`](https://git-scm.com)

+   Node.js：[`nodejs.org/en`](https://nodejs.org/en)

+   GNU Make：[`www.gnu.org/software/make`](https://www.gnu.org/software/make)

+   VS Code：[`code.visualstudio.com`](https://code.visualstudio.com)


# 第四章：安装所需的依赖项

现在您已经设置好了开发环境，并准备开始编写 C、C++和 JavaScript，是时候添加最后一块拼图了。为了从我们的 C/C++代码生成`.wasm`文件，我们需要安装和配置**Emscripten SDK**（**EMSDK**）。

在本章中，我们将讨论开发工作流程，并谈论 EMSDK 如何融入开发过程。我们将提供详细的说明，说明如何在每个平台上安装和配置 EMSDK，以及任何先决条件。安装和配置过程完成后，您将通过编写和编译一些 C 代码来测试它。

本章的目标是理解以下内容：

+   与 WebAssembly 一起工作时的整体开发工作流程

+   EMSDK 与 Emscripten 和 WebAssembly 的关系以及为什么需要它

+   如何安装 EMSDK 的先决条件

+   如何安装和配置 EMSDK

+   如何测试 EMSDK 以确保它正常工作

# 开发工作流程

WebAssembly 的开发工作流程与大多数其他需要编译和构建过程的语言类似。在进入工具设置之前，我们将介绍开发周期。在本节中，我们将为本章其余部分将安装和配置的工具建立一些上下文。

# 工作流程中的步骤

对于本书，我们将编写 C 和 C++代码，并将其编译为 Wasm 模块，但这个工作流程适用于任何编译为`.wasm`文件的编程语言。以下图表概述了这个过程：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-wasm/img/b43e1500-5c09-4f8d-a81c-665fad256758.png)

开发工作流程中的步骤

本书中将使用这个过程来进行示例，因此您将了解项目结构如何与工作流程对应。我们将使用一些可用的工具来加快和简化这个过程，但步骤仍将保持不变。

# 将工具集成到工作流程中

有许多编辑器和工具可用于简化开发过程。幸运的是，C/C++和 JavaScript 已经存在了相当长的时间，因此您可以利用最适合您的选项。WebAssembly 的工具列表要短得多，因为这项技术存在的时间较短，但它们确实存在。

我们将使用的主要工具是 VS Code，它提供了一些优秀和有用的功能，可以简化构建和开发过程。除了用它来编写我们的代码外，我们还将利用 VS Code 内置的任务功能从 C/C++构建`.wasm`文件。通过在项目根文件夹中创建一个`.vscode/tasks.json`文件，我们可以指定与构建步骤相关的所有参数，并使用键盘快捷键快速运行它。除了执行构建之外，我们还可以启动和停止运行的 Node.js 进程（即工作流程图中的本地服务器）。我们将在下一章中介绍如何添加和配置这些功能。

# Emscripten 和 EMSDK

我们将使用 Emscripten 将我们的 C/C++代码编译为`.wasm`文件。到目前为止，Emscripten 只是在一般情况下简要提到过。由于我们将在构建过程中使用这个工具和相应的 Emscripten SDK（EMSDK），因此了解每种技术的作用以及它在开发工作流程中的作用是很重要的。在本节中，我们将描述 Emscripten 的目的，并讨论它与 EMSDK 的关系。

# Emscripten 概述

那么 Emscripten 是什么？维基百科提供了以下定义：

“Emscripten 是一个源到源编译器，作为 LLVM 编译器的后端运行，并生成称为 asm.js 的 JavaScript 子集。它也可以生成 WebAssembly。”

我们在第一章中讨论了源到源编译器（或转换器），并以 TypeScript 为例。转换器将一种编程语言的源代码转换为另一种编程语言的等效源代码。为了详细说明 Emscripten 作为 LLVM 编译器的后端运行，我们需要提供有关 LLVM 的一些额外细节。

LLVM 的官方网站（[`llvm.org`](https://llvm.org)）将 LLVM 定义为*一组模块化和可重用的编译器和工具链技术*。LLVM 由几个子项目组成，但我们将重点放在 Emscripten 使用的两个项目上：Clang 和 LLVM 核心库。为了了解这些部件如何组合在一起，让我们回顾一下三阶段编译器的设计：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-wasm/img/fd686aef-f7e8-4aa4-a782-25c68ec02e2a.png)

通用三阶段编译器的设计

该过程相对简单：三个独立的阶段或*端*处理编译过程。这种设计允许不同的前端和后端用于各种编程语言和目标架构，并通过使用中间表示将机器代码与源代码完全解耦。现在让我们将每个编译阶段与我们将用于生成 WebAssembly 的工具链的组件相关联：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-wasm/img/3a332b22-6a36-4623-b326-dde857731fd7.png)

使用 LLVM、Clang 和 Emscripten 的三阶段编译

Clang 用于将 C/C++编译为 LLVM 的**中间表示**（**IR**），Emscripten 将其编译为 Wasm 模块（二进制格式）。这两个图表还展示了 Wasm 和机器代码之间的关系。您可以将 WebAssembly 视为浏览器中的 CPU，Wasm 是其运行的机器代码。

# EMSDK 适用于哪里？

Emscripten 是指用于将 C 和 C++编译为`asm.js`或 WebAssembly 的工具链。EMSDK 用于管理工具链中的工具和相应的配置。这消除了复杂的环境设置需求，并防止了工具版本不兼容的问题。通过安装 EMSDK，我们拥有了使用 Emscripten 编译器所需的所有工具（除了先决条件）。以下图表是 Emscripten 工具链的可视化表示（EMSDK 显示为深灰色）：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-wasm/img/c88f7e5e-eefe-454f-a218-816b9caebac5.png)

Emscripten 工具链（从 emscripten.org 稍作修改）

现在您对 Emscripten 和 EMSDK 有了更好的了解，让我们继续安装先决条件的过程。

# 安装先决条件

在安装和配置 EMSDK 之前，我们需要安装一些先决条件。您在第三章中安装了两个先决条件：Node.js 和 Git。每个平台都有略有不同的安装过程和工具要求。在本节中，我们将介绍每个平台的先决条件工具的安装过程。

# 常见的先决条件

您可能已经安装了所有的先决条件。以下是无论平台如何都需要的三个先决条件：

+   Git

+   Node.js

+   Python 2.7

注意 Python 版本；这很重要，因为安装错误的版本可能会导致安装过程失败。如果您在第二章中跟随并安装了 Node.js 和 Git，那么剩下的就是安装 Python 2.7 和为您的平台指定的任何其他先决条件。每个平台的 Python 安装过程将在以下子节中指定。

Python 是一种用于通用编程的高级编程语言。如果您想了解更多，请访问官方网站[`www.python.org/`](https://www.python.org/)。

# 在 macOS 上安装先决条件

在安装 EMSDK 之前，您需要安装另外三个工具：

+   Xcode

+   Xcode 命令行工具

+   CMake

您可以从 macOS 应用商店安装 Xcode。如果您已经安装了 Xcode，可以通过转到 Xcode | 首选项 | 位置并检查命令行工具选项是否有值来检查是否已安装命令行工具。如果您安装了 Homebrew 软件包管理器，则应该已经安装了命令行工具：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-wasm/img/1fec0953-9278-4312-b286-c5ed34ec45e3.png)

检查 Xcode 命令行工具的当前版本

如果没有看到，请打开终端并运行此命令：

```cpp
xcode-select --install
```

完成后，可以通过运行此命令来安装 CMake：

```cpp
brew install cmake
```

在安装 Python 之前，请运行此命令：

```cpp
python --version
```

如果您看到`Python 2.7.xx`（其中`xx`是补丁版本，可以是任何数字），则可以准备安装 EMSDK。如果出现错误，表示找不到 Python 命令，或者看到`Python 3.x.xx`，我建议您安装`pyenv`，一个 Python 版本管理器。要安装`pyenv`，请运行此命令：

```cpp
brew install pyenv
```

您需要执行一些额外的配置步骤才能完成安装。请按照[`github.com/pyenv/pyenv#homebrew-on-mac-os-x`](https://github.com/pyenv/pyenv#homebrew-on-mac-os-x)上的 Homebrew 安装说明进行操作。安装和配置`pyenv`后，运行此命令安装 Python 2.7：

```cpp
pyenv install 2.7.15
```

安装完成后，运行此命令：

```cpp
pyenv global 2.7.15
```

为确保您使用的是正确版本的 Python，请运行此命令：

```cpp
python --version
```

您应该看到 Python `2.7.xx`，其中`xx`是补丁版本（我看到的是`2.7.10`，这将可以正常工作）。

# 在 Ubuntu 上安装先决条件

Ubuntu 应该已经安装了 Python 2.7。您可以通过运行此命令确认：

```cpp
python --version
```

如果您看到 Python `2.7.xx`（其中`xx`是补丁版本，可以是任何数字），则可以准备安装 EMSDK。如果出现错误，表示找不到 python 命令，或者看到`Python 3.x.xx`，我建议您安装`pyenv`，一个 Python 版本管理器。在安装`pyenv`之前，请检查是否已安装`curl`。您可以通过运行以下命令来执行此操作：

```cpp
curl --version
```

如果您看到版本号和其他信息，则已安装`curl`。如果没有，您可以通过运行以下命令来安装`curl`：

```cpp
sudo apt-get install curl
```

`curl`安装完成后，运行此命令安装`pyenv`：

```cpp
curl -L https://github.com/pyenv/pyenv-installer/raw/master/bin/pyenv-installer | bash
```

安装和配置 pyenv 后，运行此命令安装 Python 2.7：

```cpp
pyenv install 2.7.15
```

如果遇到构建问题，请转到[`github.com/pyenv/pyenv/wiki/common-build-problems`](https://github.com/pyenv/pyenv/wiki/common-build-problems)上的*常见构建问题*页面。安装完成后，运行此命令：

```cpp
pyenv global 2.7.15
```

为确保您使用的是正确版本的 Python，请运行此命令：

```cpp
python --version
```

您应该看到`Python 2.7.xx`，其中`xx`是补丁版本（我看到的是`2.7.10`，这将可以正常工作）。

# 在 Windows 上安装先决条件

Windows 的唯一额外先决条件是 Python 2.7。在尝试安装之前，运行此命令：

```cpp
python --version
```

如果您看到`Python 2.7.xx`（其中`xx`是补丁版本，可以是任何数字），则可以准备安装 EMSDK。如果出现错误，表示找不到 Python 命令，或者看到`Python 3.x.xx`并且系统上没有安装 Python 2.7，请运行此命令安装 Python 2.7：

```cpp
choco install python2 -y
```

如果在安装 Python 2.7 之前看到`Python 3.x.xx`，您应该能够通过更新路径来更改当前的 Python 版本。在尝试安装 EMSDK 之前，运行此命令将 Python 设置为 2.7：

```cpp
SET PATH=C:\Python27\python.exe
```

# 安装和配置 EMSDK

如果您已安装了所有先决条件，就可以准备安装 EMSDK 了。获取 EMSDK 并使其运行的过程相对简单。在本节中，我们将介绍 EMSDK 的安装过程，并演示如何更新您的 VS Code C/C++配置以适应 Emscripten。

# 跨所有平台的安装过程

首先，选择一个文件夹来安装 EMSDK。我创建了一个文件夹在 `~/Tooling`（或者在 Windows 上是 `C:\Users\Mike\Tooling`）。在终端中，`cd` 到你刚创建的文件夹，并运行这个命令：

```cpp
git clone https://github.com/juj/emsdk.git
```

一旦克隆过程完成，请按照下面对应你的平台的部分中的说明完成安装。

# 在 macOS 和 Ubuntu 上安装

一旦克隆过程完成，运行以下代码片段中的每个命令。如果看到一条建议你运行 `git pull` 而不是 `./emsdk update` 的消息，请在运行 `./emsdk install latest` 命令之前使用 `git pull` 命令：

```cpp
# Change directory into the EMSDK installation folder
cd emsdk

# Fetch the latest registry of available tools
./emsdk update

# Download and install the latest SDK tools
./emsdk install latest

# Make the latest SDK active for the current user (writes ~/.emscripten file)
./emsdk activate latest

# Activate PATH and other environment variables in the current Terminal
source ./emsdk_env.sh
```

`source ./emsdk_env.sh` 命令将在当前终端中激活环境变量，这意味着每次创建新的终端实例时，你都需要重新运行它。为了避免这一步，你可以将以下行添加到你的 Bash 或 Zsh 配置文件中（即 `~/.bash_profile` 或 `~/.zshrc`）：

```cpp
source ~/Tooling/emsdk/emsdk_env.sh > /dev/null
```

如果你将 EMSDK 安装在不同的位置，请确保更新路径以反映这一点。将这行添加到你的配置文件中将自动运行该环境更新命令，这样你就可以立即开始使用 EMSDK。为了确保你可以使用 Emscripten 编译器，请运行这个命令：

```cpp
emcc --version
```

如果你看到一个带有版本信息的消息，设置就成功了。如果你看到一个错误消息，说明找不到该命令，请仔细检查你的配置。你可能在你的 Bash 或 Zsh 配置文件中指定了无效的 `emsdk_env.sh` 路径。

# 在 Windows 上安装和配置

在完成安装之前，我建议你以后使用 **PowerShell**。本书中的示例将在 `cmder` 中使用 PowerShell。一旦克隆过程完成，运行以下代码片段中给出的每个命令。如果看到一条建议你运行 `git pull` 而不是 `./emsdk update` 的消息，请在运行 `./emsdk install latest` 命令之前使用 `git pull` 命令：

```cpp
# Change directory into the EMSDK installation folder
cd emsdk

# Fetch the latest registry of available tools
.\emsdk update

# Download and install the latest SDK tools
.\emsdk install latest

# Make the latest SDK active for the current user (writes ~/.emscripten file)
.\emsdk activate --global latest
```

`.\emsdk activate` 命令中的 `--global` 标志允许你在每个会话中运行 `emcc` 而无需运行脚本来设置环境变量。为了确保你可以使用 Emscripten 编译器，请重新启动你的 CLI 并运行这个命令：

```cpp
emcc --version
```

如果你看到一个带有版本信息的消息，设置就成功了。

# 在 VS Code 中配置

如果你还没有这样做，创建一个包含我们将要使用的代码示例的文件夹（示例使用名称 `book-examples`）。在 VS Code 中打开这个文件夹，按 *F1* 键，选择 C/Cpp: Edit Configurations… 来创建一个 `.vscode/c_cpp_properties.json` 文件在你项目的根目录。它应该会自动打开文件。将以下行添加到 `browse.path` 数组中：`"${env:EMSCRIPTEN}/system/include"`。这将防止在包含 `emscripten.h` 头文件时抛出错误。如果它没有自动生成，你可能需要手动创建 `browse` 对象并添加一个 `path` 条目。以下代码片段代表了 Ubuntu 上更新后的配置文件：

```cpp
{
  "name": "Linux",
  "includePath": [
    "/usr/include",
    "/usr/local/include",
    "${workspaceFolder}",
    "${env:EMSCRIPTEN}/system/include"
  ],
  "defines": [],
  "intelliSenseMode": "clang-x64",
  "browse": {
    "path": [
      "/usr/include",
      "/usr/local/include",
      "${workspaceFolder}"
      ],
    "limitSymbolsToIncludedHeaders": true,
    "databaseFilename": ""
  }
}
```

# 测试编译器

安装和配置 EMSDK 后，你需要测试它以确保你能够从 C/C++ 代码生成 Wasm 模块。测试的最简单方法是使用 `emcc` 命令编译一些代码，并尝试在浏览器中运行它。在这一部分，我们将通过编写和编译一些简单的 C 代码并评估与 `.wasm` 输出相关联的 Wat 来验证 EMSDK 的安装。

# C 代码

我们将使用一些非常简单的 C 代码来测试我们的编译器安装。我们不需要导入任何头文件或外部库。我们不会在这个测试中使用 C++，因为我们需要对 C++执行额外的步骤，以防止名称混淆，我们将在第六章中更详细地描述。本节的代码位于`learn-webassembly`存储库的`/chapter-04-installing-deps`文件夹中。按照这里列出的说明来测试 EMSDK。

在你的`/book-examples`文件夹中创建一个名为`/chapter-04-installing-deps`的子文件夹。接下来，在这个文件夹中创建一个名为`main.c`的新文件，并填充以下内容：

```cpp
int addTwoNumbers(int leftValue, int rightValue) {
    return leftValue + rightValue;
}
```

# 编译 C 代码

为了使用 Emscripten 编译 C/C++文件，我们将使用`emcc`命令。我们需要向编译器传递一些参数，以确保我们获得一个在浏览器中可以利用的有效输出。为了从 C/C++文件生成 Wasm 文件，命令遵循这种格式：

```cpp
emcc <file.c> -Os -s WASM=1 -s SIDE_MODULE=1 -s BINARYEN_ASYNC_COMPILATION=0 -o <file.wasm>
```

以下是`emcc`命令的每个参数的详细说明：

| **参数** | **描述** |
| --- | --- |
| `<file.c>` | 将被编译为 Wasm 模块的 C 或 C++输入文件的路径；当我们运行命令时，我们将用实际文件路径替换它。 |
| `-Os` | 编译器优化级别。这个优化标志允许模块实例化，而不需要 Emscripten 的粘合代码。 |
| `-s WASM=1` | 告诉编译器将代码编译为 WebAssembly。 |
| `-s SIDE_MODULE=1` | 确保只输出一个`WebAssembly`模块（没有粘合代码）。 |
| `-s BINARYEN_ASYNC_COMPILATION=0` | 来自官方文档：是否异步编译 wasm，这更有效，不会阻塞主线程。目前，这对于除了最小的模块之外的所有模块在 V8 中运行是必需的。 |
| `-o <file.wasm>` | 输出文件`.wasm`文件的路径。当我们运行命令时，我们将用所需的输出路径替换它。 |

为了测试 Emscripten 是否正常工作，请在 VS Code 中打开集成终端并运行以下命令：

```cpp
# Ensure you're in the /chapter-04-installing-deps folder:
cd chapter-04-installing-deps

# Compile the main.c file to main.wasm:
emcc main.c -Os -s WASM=1 -s SIDE_MODULE=1 -s BINARYEN_ASYNC_COMPILATION=0 -o main.wasm
```

第一次编译文件可能需要一分钟，但后续构建将会快得多。如果编译成功，你应该在`/chapter-04-installing-deps`文件夹中看到一个`main.wasm`文件。如果遇到错误，Emscripten 的错误消息应该足够详细，以帮助你纠正问题。

如果一切顺利完成，你可以通过在 VS Code 的文件资源管理器中右键单击`main.wasm`并从上下文菜单中选择显示 WebAssembly 来查看与`main.wasm`文件相关的 Wat。输出应该如下所示：

```cpp
(module
  (type $t0 (func (param i32)))
  (type $t1 (func (param i32 i32) (result i32)))
  (type $t2 (func))
  (type $t3 (func (result f64)))
  (import "env" "table" (table $env.table 2 anyfunc))
  (import "env" "memoryBase" (global $env.memoryBase i32))
  (import "env" "tableBase" (global $env.tableBase i32))
  (import "env" "abort" (func $env.abort (type $t0)))
  (func $_addTwoNumbers (type $t1) (param $p0 i32) (param $p1 i32) (result i32)
    get_local $p1
    get_local $p0
    i32.add)
  (func $runPostSets (type $t2)
    nop)
  (func $__post_instantiate (type $t2)
     get_global $env.memoryBase
    set_global $g2
    get_global $g2
    i32.const 5242880
    i32.add
    set_global $g3)
  (func $f4 (type $t3) (result f64)
    i32.const 0
    call $env.abort
    f64.const 0x0p+0 (;=0;))
  (global $g2 (mut i32) (i32.const 0))
  (global $g3 (mut i32) (i32.const 0))
  (global $fp$_addTwoNumbers i32 (i32.const 1))
  (export "__post_instantiate" (func $__post_instantiate))
  (export "_addTwoNumbers" (func $_addTwoNumbers))
  (export "runPostSets" (func $runPostSets))
  (export "fp$_addTwoNumbers" (global 4))
  (elem (get_global $env.tableBase) $f4 $_addTwoNumbers))
```

如果编译器成功运行，你就可以继续下一步，编写 JavaScript 代码与模块进行交互，这将在下一章中介绍。

# 摘要

在本章中，我们介绍了在使用 WebAssembly 时的整体开发工作流程。为了生成我们的`.wasm`文件，我们正在使用 Emscripten，这需要安装 EMSDK。在审查任何安装细节之前，我们讨论了底层技术，并描述了它们如何相互关联以及与 WebAssembly 的关系。我们介绍了在本地计算机上使 EMDSK 工作所需的每个步骤。每个平台上 EMSDK 的安装过程都有所介绍，以及 EMSDK 的安装和配置说明。安装 EMSDK 之后，我们测试了编译器（不是）。那是我们在上一节中运行的`emcc`命令。使用`emcc`命令对一个简单的 C 代码文件，以确保 Emscripten 工作正常。在下一章中，我们将详细介绍创建和加载你的第一个模块的过程！

# 问题

1.  开发工作流程中的五个步骤是什么？

1.  Emscripten 在编译过程中代表哪个阶段或结束？

1.  IR 代表什么（LLVM 的输出）？

1.  EMSDK 在 Emscripten 的编译过程中扮演什么角色？

1.  在所有三个平台（macOS、Windows 和 Linux）上需要哪些 EMSDK 先决条件？

1.  为什么需要在使用 Emscripten 编译器之前运行`emsdk_env`脚本？

1.  为什么需要将`"${env:EMSCRIPTEN}/system/include"`路径添加到 C/Cpp 配置文件中？

1.  用于将 C/C++编译为 Wasm 模块的命令是什么？

1.  `-Os`编译器标志代表什么？

# 进一步阅读

+   Emscripten: [`emscripten.org`](http://emscripten.org)

+   LLVM 编译器基础设施项目：[`llvm.org`](https://llvm.org)

+   使用 Visual Studio Code 进行 C++编程：[`code.visualstudio.com/docs/languages/cpp`](https://code.visualstudio.com/docs/languages/cpp)
