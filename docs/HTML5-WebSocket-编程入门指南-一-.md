# HTML5 WebSocket 编程入门指南（一）

> 原文：[`zh.annas-archive.org/md5/9F0B5C2FFC2804553003B921048B2098`](https://zh.annas-archive.org/md5/9F0B5C2FFC2804553003B921048B2098)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

WebSocket 协议是 HTML5 世界中握手的艺术。它定义了服务器和客户端之间的双向通信，从而使 Web 应用程序更加流畅、更快速、更高效。本书将指导您完成创建现代 Web 应用程序的整个过程，充分利用 WebSocket 的功能。您将逐步学习如何配置客户端和服务器、传输文本和多媒体、添加安全层，并为旧版浏览器提供回退。此外，您将了解这些技术如何在本机移动和平板客户端中运行，释放 HTML5 WebSocket 协议的全部功能。

# 本书涵盖内容

第一章, *WebSocket-握手!*, 简要而紧凑地介绍了 WebSocket 协议，指定了 Web 中双向通信的需求，并展示了一些鼓舞人心的现实世界示例。

第二章, *WebSocket API*, 突出了 WebSocket API 的基本概念，并演示了一个 WebSocket Web 客户端应用程序。

第三章, *服务器配置*, 实现了服务器端功能，这对于有效实现真正的双向通信至关重要。

第四章, *数据传输-发送、接收和解码*, 展示了 WebSocket 如何处理文本、图像和多媒体等不同数据类型。

第五章, *安全*, 检查了运行 WebSocket 应用程序时的一些常见安全风险，并提供了确保系统稳定性的方法。

第六章, *错误处理和回退*, 回答了当出现问题时该怎么办，以及在处理旧版浏览器时如何模拟 WebSocket 行为。

第七章, *移动端（以及平板电脑）*, 将 WebSocket 功能扩展到移动世界，并展示了 WebSocket 应用程序如何在 iPhone 或 iPad 上本地运行。

附录, 提供了一些进一步的资源，包括有趣和有争议的文章。

# 本书所需内容

要充分利用本书，您需要一个现代的 Web 浏览器和一个文本编辑器。为了让生活更轻松，以下是一些软件要求，可以帮助您构建和调试 WebSocket 应用程序：

+   最新版本的 Google Chrome、Internet Explorer、Mozilla Firefox 或 Opera，包括它们的开发者工具

+   诸如 Aptana 或 WebMatrix 之类的文本编辑器

考虑到服务器端的例子，如果您选择使用我们的 C#代码，您需要：

+   .NET Framework 3.5 或更高版本

+   Visual Studio 2010 或更高版本

最后，考虑到移动和平板电脑的例子，如果您选择在 iOS 上部署，您需要：

+   Mac OS X 10.7 或更高版本

+   XCode 4.5 或更高版本

+   苹果开发者许可证

随意选择您喜欢的服务器端、移动和平板电脑技术。无论使用哪种工具和 SDK，主要的方法和技术都是相同的。

# 本书适合对象

本书适用于对开发现代 Web 应用程序感兴趣的专业软件开发人员、研究人员和学生。需要掌握 HTML、JavaScript 和至少一种服务器端技术的基本知识。如果您想充分利用移动和平板电脑章节，对任何移动平台的良好了解将是一个加分项。本书旨在指导您了解 WebSocket 编程的原则和基础知识，以便您可以将这些知识应用到您擅长的每个平台上。

# 约定

在本书中，您会发现一些文本样式，用于区分不同类型的信息。以下是一些样式的示例，以及它们的含义解释。

文本中的代码单词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 用户名显示如下："您可能已经注意到，我们在这个演示中使用`echo.websocket.org`服务器"。

一段代码设置如下：

```js
h1 {
  color: blue;
  text-align: center;
  font-family: "Helvetica Neue", Arial, Sans-Serif;
  font-size: 1em;
}
```

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的单词，比如菜单或对话框中的单词，会在文本中显示为："在**解决方案资源管理器**选项卡上，右键单击**引用**图标，然后选择**添加新引用**"。

### 注意

警告或重要提示会出现在这样的框中。

### 提示

提示和技巧会显示如下。


# 第一章：WebSocket – a Handshake!

在现实生活中，握手是温柔地握住两个人的手，然后进行简短的上下移动。如果你以这种方式问候过某人，那么你已经理解了 HTML5 WebSocket 协议的基本概念。

WebSocket 定义了 Web 服务器和 Web 客户端之间的持久双向通信，这意味着双方可以同时交换消息数据。WebSocket 引入了真正的并发性，它们针对高性能进行了优化，并且可以实现更加响应迅速和丰富的 Web 应用程序。

以下图表显示了服务器与多个客户端的握手：

![WebSocket – a Handshake!](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/gtst-h5-ws-prog/img/6962_01_01.jpg)

值得一提的是，WebSocket 协议已经由**互联网工程任务组**（**IETF**）标准化，用于 Web 浏览器的 WebSocket API 目前正在由**万维网联盟**（**W3C**）标准化——是的，这是一个正在进行中的工作。不，你不需要担心巨大的变化，因为当前的规范已经发布为“建议标准”。

# WebSocket 之前的生活

在深入研究 WebSocket 的世界之前，让我们看看用于服务器和客户端之间双向通信的现有技术。

## 轮询

Web 工程师最初使用一种称为轮询的技术来处理这个问题。轮询是一种同步方法（即没有并发），它执行周期性请求，无论是否存在要传输的数据。客户端在指定的时间间隔后进行连续的请求。每次，服务器都会用可用的数据或适当的警告消息进行响应。

虽然轮询“只是起作用”，但很容易理解这种方法对于大多数情况来说是过度的，并且对于现代 Web 应用程序来说非常消耗资源。

## 长轮询

长轮询是一种类似的技术，正如其名称所示，客户端打开连接，服务器保持连接活动，直到获取一些数据或超时发生。然后客户端可以重新开始并执行顺序请求。长轮询是对轮询的性能改进，但是不断的请求可能会减慢过程。

## 流式传输

流式传输似乎是实时数据传输的最佳选择。在使用流式传输时，客户端发出请求，服务器保持连接无限期地打开，准备好时获取新数据。虽然这是一个很大的改进，但流式传输仍然包括 HTTP 头，这会增加文件大小并导致不必要的延迟。

## 回发和 AJAX

Web 是围绕 HTTP 请求-响应模型构建的。HTTP 是一种无状态协议，这意味着两个部分之间的通信由独立的请求和响应对组成。简单地说，客户端向服务器请求一些信息，服务器用适当的 HTML 文档进行响应，然后页面刷新（实际上称为回发）。在此期间没有发生任何事情，直到执行新的操作（例如单击按钮或从下拉菜单中进行选择）。任何页面加载都会导致令人讨厌的（从用户体验角度来看）闪烁效果。

直到 2005 年，通过**异步 JavaScript 和 XML**（**AJAX**）绕过了回发闪烁。AJAX 基于 JavaScript 的`XmlHttpRequest`对象，允许异步执行 JavaScript 代码，而不干扰用户界面的其余部分。AJAX 发送和接收的只是网页的一部分，而不是重新加载整个页面。

想象一下，你正在使用 Facebook，并且想在你的时间线上发表评论。你在适当的文本字段中输入状态更新，按 Enter 键，然后...哇！你的评论会自动发布，而不需要重新加载整个页面。除非 Facebook 使用了 AJAX，否则浏览器需要刷新整个页面才能显示你的新状态。

AJAX，加上流行的 JavaScript 库如 jQuery，极大地改善了最终用户体验，并被广泛认为是每个网站必备的属性。只有在 AJAX 之后，JavaScript 才成为了一个值得尊敬的编程语言，而不再被视为必要的邪恶。

但这还不够。长轮询是一种有用的技术，它让你的浏览器看起来保持了一个持久的连接，而事实上客户端在不断地发出调用！这可能会极大地消耗资源，特别是在移动设备上，速度和数据大小真的很重要。

前面描述的所有方法都提供了实时的双向通信，但与 WebSockets 相比有三个明显的缺点：

+   它们发送 HTTP 头，使总文件大小变大

+   通信类型是半双工的，意味着每个方（客户端/服务器）必须等待另一个方完成

+   Web 服务器消耗更多资源

后台世界看起来像一部对讲机-你需要等待对方讲完话（半双工）。在 WebSocket 世界中，参与者可以同时说话（全双工）！

Web 最初是用于显示文本文档的，但想想它如今的用途。我们显示多媒体内容，添加位置功能，完成复杂任务，因此传输的数据不同于文本。AJAX 和浏览器插件如 Flash 都很棒，但需要一种更本地的做事方式。我们如今使用 Web 的方式需要一个全新的应用程序开发框架。

# 然后来了 HTML5

HTML5 如今引起了巨大的关注，因为它为之前讨论的问题提供了重要的解决方案。如果您已经熟悉 HTML5，请随意跳过本节并继续。

HTML5 是一个强大的框架，用于开发和设计 Web 应用程序。

HTML5 不仅仅是一种新的标记或一些新的样式选择器，也不是一种新的编程语言。HTML5 代表着一系列技术、编程语言和工具，每种都有各自的作用，所有这些一起完成了一个特定的任务-即为任何类型的设备构建丰富的 Web 应用程序。

HTML5 的主要支柱包括标记、CSS3 和 JavaScript API。

以下图表显示了 HTML5 组件：

![然后来了 HTML5](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/gtst-h5-ws-prog/img/6962_01_02.jpg)

以下是 HTML5 家族的主要成员。由于本书未涵盖 HTML5 的全部内容，建议您访问[html5rocks.com](http://html5rocks.com)并开始使用实际示例和演示。

| 标记 | 结构元素表单元素属性 |
| --- | --- |
| 图形 | 样式表 CanvasSVGWebGL |
| 多媒体 | 音视频 |
| 存储 | 缓存本地存储 Web SQL |
| 连接 | Web 消息 WebSocketWebWorkers |
| 位置 | 地理位置 |

尽管存储和连接被认为是最先进的主题，但如果您不是经验丰富的 Web 开发人员，您不需要担心。在本书中，我们将解释如何完成常见任务，并创建一些逐步示例，您可以稍后下载并进行实验。此外，通过 HTML5 API 管理 WebSockets 非常简单，因此深呼吸，毫无恐惧地投入其中。

# WebSocket 协议

WebSocket 协议从根本上重新定义了全双工通信。实际上，WebSockets 和 WebWorkers 在将桌面丰富功能带到 Web 浏览器方面迈出了一大步。在后台世界中，并发和多线程并不存在。它们以一种相当受限的方式被模拟。

## URL

HTTP 协议需要自己的模式（http 和 https）。WebSocket 协议也是如此。以下是一个典型的 WebSocket URL 示例：

`ws://example.com:8000/chat.php`

首先要注意的是`ws`前缀。这很正常，因为我们需要一个新的 URL 模式来支持新协议。`wss`也得到支持，它是 WebSocket 的安全连接（SSL）等价物。URL 的其余部分类似于旧的 HTTP URL，并在下图中有所说明。

下图显示了 WebSocket URL 的标记：

![URL](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/gtst-h5-ws-prog/img/6962_01_03.jpg)

## 浏览器支持

目前，WebSocket 协议的最新规范是 RFC 6455，幸运的是，每个现代 web 浏览器的最新版本都支持它。具体来说，RFC 6455 在以下浏览器中得到支持：

+   Internet Explorer 10+

+   Mozilla Firefox 11+

+   Google Chrome 16+

+   Safari 6+

+   Opera 12+

值得一提的是，Safari（iOS 版）、Firefox（Android 版）、Chrome（Android 版、iOS 版）和 Opera Mobile 的移动版本都支持 WebSocket，将 WebSocket 的功能带到了智能手机和平板电脑上！

但是，等等。许多人仍在全球范围内使用的旧版浏览器呢？好吧，不用担心，因为在本书中，我们将研究一些备用技术，使我们的网站能够被尽可能多的用户访问。

## 谁在使用 WebSocket

尽管 WebSocket 是一种全新的技术，但相当多的有前途的公司利用其各种能力，以提供更丰富的用户体验。最著名的范例是 Kaazing（[`demo.kaazing.com/livefeed/`](http://demo.kaazing.com/livefeed/)），这是一家初创公司，为其实时通信平台筹集了 1700 万美元的投资。

其他业务包括以下内容：

| 名称 | 网站 | 描述 |
| --- | --- | --- |
| Gamooga | [`www.gamooga.com/`](http://www.gamooga.com/) | 应用程序和游戏的实时后端 |
| GitLive | [`gitlive.com/`](http://gitlive.com/) | GitHub 项目的通知 |
| Superfeedr | [`superfeedr.com/`](http://superfeedr.com/) | 实时数据推送 |
| Pusher | [`pusher.com/`](http://pusher.com/) | 用于 web 和移动应用程序的可扩展实时功能 API |
| Smarkets | [`smarkets.com/`](https://smarkets.com/) | 实时投注 |
| IRC Cloud | [`www.irccloud.com/`](https://www.irccloud.com/) | 聊天 |

包含大量 WebSocket 演示的两个重要资源如下：

+   [`www.websocket.org/demos.html`](http://www.websocket.org/demos.html)

+   [`www.html5rocks.com/en/features/connectivity`](http://www.html5rocks.com/en/features/connectivity)

# 移动？

WebSocket，顾名思义，与网络有关。正如你所知，网络不仅仅是一些浏览器的技术，而是一个广泛的通信平台，适用于大量设备，包括台式电脑、智能手机和平板电脑。

显然，任何利用 WebSocket 的 HTML5 应用程序都可以在（几乎）任何支持 HTML5 的移动 web 浏览器上运行。想象一下，你想要使用原生移动应用程序的增强功能来实现相同的功能。WebSocket 在主流移动操作系统中得到支持吗？简短的答案是：是的。目前，移动行业的所有主要参与者（苹果、谷歌、微软）都提供了 WebSocket API，供你在自己的原生应用程序中使用。iOS、Android 和 Windows 智能手机和平板电脑都以类似的方式集成了 WebSocket，就像 HTML5 一样。

# 未来就在眼前

新的神经科学研究证实了关于握手的古老格言的力量：人们对那些伸出手来打招呼的人留下更好的印象（[`www.sciencedaily.com/releases/2012/10/121019141300.htm`](http://www.sciencedaily.com/releases/2012/10/121019141300.htm)）。正如人类的握手可以带来更好的交易一样，WebSocket 的握手可以带来更好的用户体验。我们将用户体验视为性能（用户等待时间更短）和简单性（开发者构建直接快速）的结合。

所以，这取决于你：你想构建现代的、真正实时的 Web 应用程序吗？你想为用户提供最大的体验吗？你想为现有的 Web 应用程序提供出色的性能提升吗？如果对任何一个问题的答案是肯定的，那么现在是时候意识到 WebSocket API 已经足够成熟，可以立即提供其好处了。

# 我们要做什么？

在整本书中，我们将实施一个真实的项目：一个简单的、多用户的、基于 WebSocket 的聊天应用程序。实时聊天是所有现代社交网络中非常常见的功能。我们将逐步学习如何配置 Web 服务器，实现 HTML5 客户端，并在它们之间传递消息。

除了纯文本消息，我们还将看到 WebSocket 如何处理各种类型的数据，如二进制文件、图像和视频。是的，我们也会演示实时媒体流！

此外，我们将增强我们应用程序的安全性，检查一些已知的安全风险，并找出如何避免常见的陷阱。此外，我们将瞥一眼一些针对那些不能（或不想）更新他们的浏览器的可怜家伙的备用技术。

最后但并非最不重要的是，我们将涉及移动端。您可以使用台式机浏览器、手机或平板电脑进行聊天。如果您可以在多个目标上使用相同的技术和原则，那不是很好吗？通过阅读本书，您将了解如何轻松将您的 Web 应用程序转换为原生移动和平板应用程序。

# 总结

在本章中，我们介绍了 WebSocket 协议，提到了实时通信的现有技术，并确定了 WebSocket 满足的特定需求。此外，我们还检查了它与 HTML5 的关系，并说明了用户如何从这些增强中受益。现在是时候更详细地介绍 WebSocket 客户端 API 了。


# 第二章：WebSocket API

如果您熟悉 HTML 和 JavaScript，您已经了解足够的知识来立即开始开发 HTML5 WebSockets。WebSocket 通信和数据传输是双向的，因此我们需要两方来建立它：服务器和客户端。本章重点介绍 HTML5 Web 客户端，并介绍 WebSocket 客户端 API。

# HTML5 基础知识

任何 HTML5 Web 客户端都是结构、样式和编程逻辑的组合。正如我们已经提到的，HTML5 框架为每种用途提供了离散的技术集。尽管我们假设您已经对这些概念有一定了解，让我们快速浏览一下它们。

## 标记

标记定义了您的 Web 应用程序的结构。它是一组 XML 标记，让您指定 HTML 文档中可视元素的层次结构。流行的新 HTML5 标记包括`header`、`article`、`footer`、`aside`和`nav`标记。这些元素具有特定的含义，并有助于区分 Web 文档的不同部分。

以下是 HTML5 标记代码的一个简单示例，用于生成我们聊天应用程序的基本元素：一个文本字段、两个按钮和一个标签。文本字段用于输入我们的消息，第一个按钮将发送消息，第二个按钮将终止聊天，标签将显示来自服务器的交互：

```js
<!DOCTYPE html>
<head>
  <title>HTML5 WebSockets</title>
</head>
<body>
  <h1> HTML5 WebSocket chat. </h1>
  <input type="text" id="text-view" />
  <input type="button" id="send-button" value="Send!" />
  <input type="button" id="stop-button" value="Stop" />
  <br/>
  <label id="status-label">Status</label>
</body>
```

前面代码的第一行（`DOCTYPE`）表示我们正在使用最新版本的 HTML，即 HTML5。

有关 HTML5 标记的更多信息，请访问[`html5doctor.com/`](http://html5doctor.com/)。在[`html5doctor.com/element-index/`](http://html5doctor.com/element-index/)上有一个支持的 HTML5 标记的完整参考。

## 样式

为了显示颜色、背景、字体、对齐等，您需要熟悉**层叠样式表**（**CSS**）。CSS 相当直观，因此，如果要更改标题样式（例如颜色、对齐和字体），您可以编写类似以下代码：

```js
h1 {
  color: blue;
  text-align: center;
  font-family: "Helvetica Neue", Arial, Sans-Serif;
  font-size: 1em;
}
```

[`www.css3.info/`](http://www.css3.info/) 是 CSS3 和进一步阅读的绝佳资源。

## 逻辑

标记定义了结构，CSS 规则应用了样式。那么事件处理和用户操作呢？JavaScript 就派上用场了！JavaScript 是一种脚本编程语言，可以根据伴随的操作控制和改变 Web 应用程序的行为。使用 JavaScript，您可以处理按钮点击、页面加载，应用额外样式，添加特殊效果，甚至从 Web 服务获取数据。使用 JavaScript，您可以创建对象，分配属性和方法，并在发生某些事件时引发和捕获它们。

以下是一个简单的 JavaScript 示例：

```js
var buttonSend = document.getElementById("send-button");

buttonSend.onclick = function() {
  console.log("Button clicked!");
}
```

第一行搜索文档树，找到名为`action-button`的元素，并将其存储在名为`buttonSend`的对象中。然后，将一个函数分配给按钮的 onclick 事件。每次单击按钮时，函数的主体都会被执行。

全新的 HTML5 功能主要基于 JavaScript，因此在实现任何 Web 应用程序之前，对这种语言的基本了解是必不可少的。最重要的是，WebSocket API 也是纯 JavaScript！

# 聊天应用程序

全双工通信中最受欢迎的类型是聊天。我们将从这里开始开发一个简单的聊天应用程序。首先要做的是配置客户端，它由三个基本文件组成：

+   包含网页标记结构的 HTML（`.html`）文件

+   包含所有样式信息的 CSS（`.css`）文件

+   包含应用程序逻辑的 JavaScript（`.js`）文件

目前，这就是您需要为功能齐全的 HTML5 聊天客户端。不需要浏览器插件或其他外部库。

# API 概述

**API**，代表**应用程序编程接口**，是一组对象、方法和例程，让您与底层功能层进行交互。考虑到 WebSocket 协议，其 API 包括 WebSocket 主要对象、事件、方法和属性。

将这些特性转化为操作，WebSocket API 允许您连接到本地或远程服务器，监听消息，发送数据，并关闭连接。

以下是 WebSocket API 的典型用法。

以下插图显示了典型的 WebSocket 工作流程：

![API 概述](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/gtst-h5-ws-prog/img/6962_02_01.jpg)

## 浏览器支持

WebSocket 协议是 HTML5 的一个新功能，因此并非每个浏览器都支持它。如果您曾经尝试在不支持的浏览器上运行特定于 WebSocket 的代码，将不会发生任何事情。考虑一下您的用户：他们在无响应的网站上冲浪并不好。此外，您也不想错过任何潜在的客户！

因此，在运行任何 WebSocket 代码之前，应检查浏览器兼容性。如果浏览器无法运行代码，应提供错误消息或备用方案，如 AJAX 或基于 Flash 的功能。在第六章 *错误处理和备用方案*中将会更多地介绍备用方案。我也喜欢提供温和提示用户更新其浏览器的消息。

JavaScript 提供了一种简单的方法来查找浏览器是否可以执行特定于 WebSocket 的代码：

```js
if (window.WebSocket) {
  console.log("WebSockets supported.");

  // Continue with the rest of the WebSockets-specific functionality…
}
else {
  console.log("WebSockets not supported.");
  alert("Consider updating your browser for a richer experience.");
}
```

`window.WebSocket`语句指示浏览器是否实现了 WebSocket 协议。以下语句是等效的：

```js
window.WebSocket

"WebSocket" in window

window["WebSocket"]
```

它们中的每一个都会导致相同的验证检查。您还可以使用浏览器的开发人员工具检查任何功能支持。

想知道哪些浏览器支持 WebSocket 协议吗？可以在[`caniuse.com/#feat=websockets`](http://caniuse.com/#feat=websockets)上找到最新的资源。

截至目前，WebSocket 已完全受到 Internet Explorer 10+、Firefox 20+、Chrome 26+、Safari 6+、Opera 12.1+、Safari for iOS 6+和 Blackberry Browser 7+的支持。

## WebSocket 对象

现在是时候初始化与服务器的连接了。我们所需要做的就是创建一个 WebSocket JavaScript 对象，并提供远程或本地服务器的 URL：

```js
var socket = new WebSocket("ws://echo.websocket.org");
```

当构造此对象时，它会立即打开到指定服务器的连接。第三章 *配置服务器*，将详细向我们展示如何开发服务器端程序。现在，只需记住需要一个有效的 WebSocket URL。

示例 URL `ws://echo.websocket.org`是一个我们可以用于测试和实验的公共地址。[Websocket.org](http://Websocket.org)服务器一直在运行，当它接收到消息时，会将其发送回客户端！这就是我们确保客户端应用程序正常工作所需的一切。

## 事件

创建`WebSocket`对象后，我们需要处理其暴露的事件。WebSocket API 中有四个主要事件：打开、消息、关闭和错误。您可以通过实现`onopen`、`onmessage`、`onclose`和`onerror`函数来处理它们，也可以使用`addEventListener`方法。对于我们需要做的事情，这两种方式几乎是等效的，但第一种方式更清晰。

显然，我们将为事件提供的函数不会按顺序执行。它们将在特定操作发生时异步执行。

因此，让我们仔细看看它们。

### 打开

`onopen`事件在连接成功建立后立即触发。这意味着客户端和服务器之间的初始握手已经导致了成功的第一次交易，应用程序现在已准备好传输数据：

```js
socket.onopen = function(event) {
  console.log("Connection established.");

  // Initialize any resources here and display some user-friendly messages.
  var label = document.getElementById("status-label");
  label.innerHTML = "Connection established!";
}
```

在等待连接打开时，为用户提供适当的反馈是一个好的做法。WebSockets 绝对很快，但是互联网连接可能很慢！

### onmessage

`onmessage`事件是客户端与服务器的通信。每当服务器发送一些数据时，`onmessage`事件就会触发。消息可能包含纯文本、图像或二进制数据。如何解释和可视化这些数据由您决定：

```js
socket.onmessage = function (event) {
  console.log("Data received!");
}
```

检查数据类型非常简单。以下是如何显示字符串响应的方法：

```js
socket.onmessage = function (event) {
  if (typeof event.data === "string") {
    // If the server has sent text data, then display it.
    var label = document.getElementById("status-label");
    label.innerHTML = event.data;
  }
}
```

我们将在第四章中了解更多关于支持的数据类型，*数据传输-发送、接收和解码*

### onclose

`onclose`事件标志着对话的结束。每当触发此事件时，除非重新打开连接，否则服务器和客户端之间无法传输消息。连接可能由多种原因终止。它可能被服务器关闭，也可能被客户端使用`close()`方法关闭，或者由于 TCP 错误而关闭。

您可以通过检查事件的`code`、`reason`和`wasClean`参数轻松检测连接关闭的原因。

`code`参数为您提供一个唯一的数字，指示中断的来源。

`reason`参数以字符串格式提供中断的描述。

最后，`wasClean`参数指示连接是由于服务器决定还是由于意外的网络行为而关闭。以下代码片段说明了参数的正确使用方式：

```js
socket.onclose = function(event) {
  console.log("Connection closed.");

  var code = event.code;
  var reason = event.reason;
  var wasClean = event.wasClean;

  var label = document.getElementById("status-label");

  if (wasClean) {
    label.innerHTML = "Connection closed normally.";
  }
  else {
    label.innerHTML = "Connection closed with message " + reason + "(Code: " + code + ")";
  }
}
```

您可以在本书附录中找到代码值的详细列表。

### onerror

当发生错误（通常是意外行为或失败）时，将触发`onerror`事件。请注意，`onerror`事件总是跟随连接终止，即关闭事件。

当发生意外错误时，一个好的做法是通知用户，并可能尝试重新连接：

```js
socket.onclose = function(event) {
  console.log("Error occurred.");

  // Inform the user about the error.
  var label = document.getElementById("status-label");
  label.innerHTML = "Error: " + event;
}
```

## 操作

事件发生时会触发。当我们希望发生某事时，我们会明确调用操作（或方法）！WebSocket 协议支持两个主要操作：`send()`和`close()`。

### send()

在连接打开时，您可以与服务器交换消息。`send()`方法允许您向 Web 服务器传输各种数据。以下是我们如何向聊天室中的每个人发送聊天消息（实际上是 HTML 文本字段的内容）：

```js
// Find the text view and the button.
var textView = document.getElementById("text-view");
var buttonSend = document.getElementById("send-button");

// Handle the button click event.
buttonSend.onclick = function() {
  // Send the data!!!
  socket.send(textView.value);
}
```

就是这么简单！

但是...前面的代码并不完全正确。请记住，只有在连接打开时才能发送消息。这意味着我们需要将`send()`方法放在`onopen`事件处理程序中，或者检查`readyState`属性。该属性返回 WebSocket 连接的状态。因此，前面的代码片段应相应地进行修改：

```js
button.onclick = function() {
  // Send the data if the connection is open.
  if (socket.readyState === WebSocket.OPEN) {
    socket.send(textView.value);
  }
}
```

发送所需数据后，您可以等待服务器的交互或关闭连接。在我们的演示示例中，除非单击停止按钮，否则我们会保持连接开放。

### close()

`close()`方法作为告别握手。它终止连接，除非连接再次打开，否则无法交换数据。

与前面的示例类似，当用户单击第二个按钮时，我们调用`close()`方法：

```js
var textView = document.getElementById("text-view");
var buttonStop = document.getElementById("stop-button");

buttonStop.onclick = function() {
  // Close the connection, if open.
  if (socket.readyState === WebSocket.OPEN) {
    socket.close();
  }
}
```

我们还可以传递我们之前提到的`code`和`reason`参数：

```js
socket.close(1000, "Deliberate disconnection");
```

## 属性

`WebSocket`对象公开了一些属性值，让我们了解其特定特性。我们已经遇到了`readyState`属性。以下是其余的：

| 属性 | 描述 |
| --- | --- |
| `url` | 返回 WebSocket 的 URL |
| `protocol` | 返回服务器使用的协议 |
| `readyState` | 报告连接的状态，并可以采用以下自解释的值：`WebSocket.OPEN``WebSocket.CLOSED``WebSocket.CONNECTING``WebSocket.CLOSING` |
| `bufferedAmount` | 返回调用`send()`方法时排队的总字节数 |
| `binaryType` | 返回`onmessage`事件触发时接收到的二进制数据格式 |

## 完整的示例

这里是我们使用的完整 HTML 和 JavaScript 文件。为了保持重点简单，我们省略了样式表文件。但是，您可以在[`pterneas.com/books/websockets/source-code`](http://pterneas.com/books/websockets/source-code)下载完整的源代码。

### index.html

我们网页应用程序页面的完整标记代码如下：

```js
<!DOCTYPE html>
<html>
<head>
  <title>HTML5 WebSockets</title>
  <link rel="stylesheet" href="style.css" />
  <script src="img/chat.js"></script>
</head>
<body>
  <h1> HTML5 WebSocket chat. </h1>
  <input type="text" id="text-view" />
  <input type="button" id="send-button" value="Send!"  />
  <input type="button" id="stop-button" value="Stop" />
  </br>
  <label id="status-label">Status</label>
</body>
</html>
```

### chat.js

所有用于聊天功能的 JavaScript 代码如下：

```js
window.onload = function() {
  var textView = document.getElementById("text-view");
  var buttonSend = document.getElementById("send-button");
  var buttonStop = document.getElementById("stop-button");
  var label = document.getElementById("status-label");

  var socket = new WebSocket("ws://echo.websocket.org");

  socket.onopen = function(event) {
    label.innerHTML = "Connection open";
  }

  socket.onmessage = function(event) {
    if (typeof event.data === "string") {
      label.innerHTML = label.innerHTML + "<br />" + event.data;
    }
  }

  socket.onclose = function(event) {
    var code = event.code;
    var reason = event.reason;
    var wasClean = event.wasClean;

    if (wasClean) {
      label.innerHTML = "Connection closed normally.";
    }
    else {
      label.innerHTML = "Connection closed with message: " + reason + " (Code: " + code + ")";
    }
  }

  socket.onerror = function(event) {
    label.innerHTML = "Error: " + event;
  }

  buttonSend.onclick = function() {
    if (socket.readyState == WebSocket.OPEN) {
      socket.send(textView.value);
    }
  }

  buttonStop.onclick = function() {
    if (socket.readyState == WebSocket.OPEN) {
      socket.close();
    }
  }
}
```

## 服务器怎么样？

您可能已经注意到，我们在这个演示中使用了`echo.websocket.org`服务器。这个公共服务简单地返回您发送的数据。在下一章中，我们将构建自己的 WebSocket 服务器并开发一个真正的聊天应用程序。

# 摘要

在本章中，我们构建了我们的第一个 WebSocket 客户端应用程序！我们介绍了`WebSocket`对象并解释了它的各种方法、事件和属性。我们还在几行 HTML 和 JavaScript 代码中开发了一个基本的聊天客户端。正如您在当前示例中所注意到的，只有一个虚拟服务器回显消息。继续阅读，了解如何配置您自己的 WebSocket 服务器以实现更多的魔法。

### 提示

**下载示例代码**

您可以从您在[`www.packtpub.com`](http://www.packtpub.com)购买的所有 Packt 图书中下载示例代码文件。如果您在其他地方购买了本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，以便文件直接通过电子邮件发送给您。


# 第三章：配置服务器

WebSocket 代表双向全双工通信。因此，我们需要两方参与这种对话。在上一章中，我们实现了 WebSocket 客户端应用程序。现在是时候建立通道的另一端了，也就是 WebSocket 服务器。

# 为什么我需要一个 WebSocket 服务器？

我们假设你对服务器有一定的了解。服务器只是一个具有特定硬件和软件要求的远程计算机，以实现高可用性和正常运行、增强的安全性和管理多个并发连接。

WebSocket 服务器只是一个能够处理 WebSocket 事件和操作的简单程序。它通常公开类似于 WebSocket 客户端 API 的方法，并且大多数编程语言都提供了实现。以下图表说明了 WebSocket 服务器和 WebSocket 客户端之间的通信过程，强调了触发的事件和操作。

以下图表显示了 WebSocket 服务器和客户端事件触发：

![为什么我需要一个 WebSocket 服务器？](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/gtst-h5-ws-prog/img/6962_03_01.jpg)

不要混淆——Web 服务器可以在 Apache 或 IIS 之上运行，也可以是一个完全不同的应用程序。

考虑到硬件，你可以使用超级计算机或你的开发者机器作为服务器。这完全取决于每个项目的要求和预算。

# 设置服务器

从头开始实现一个 WebSocket 服务器并不是一个困难的过程，尽管它需要特定的知识，而且远非本书的目的。因此，我们将使用当前已经存在的 WebSocket 实现之一。由于有着庞大的开发者社区，我们可以轻松地选择我们喜欢的编程语言或框架的 WebSocket 服务器。此外，大多数实现都是开源的，所以如果需要，你甚至可以调整它们以满足自己的需求！

## 选择适合你的技术

我们列出了一些流行的 WebSocket 服务器实现。在选择之前，以下是一些你应该问自己的问题：

+   你最熟悉哪种技术？

+   你的项目有什么具体的要求？

+   你已经有一个想要增强的解决方案了吗？

+   服务器的文档是否详尽且易懂？

+   服务器是否有一个活跃的支持社区？

现在让我们来看看最流行的 WebSocket 服务器库，适用于最广泛使用的编程语言。

### C/C++

| Tufao | [`github.com/vinipsmaker/tufao`](https://github.com/vinipsmaker/tufao) |
| --- | --- |
| Wslay | [`wslay.sourceforge.net/`](http://wslay.sourceforge.net/) |
| Libwebsockets | [`libwebsockets.org/trac`](http://libwebsockets.org/trac) |
| Mongoose | [`code.google.com/p/mongoose/`](https://code.google.com/p/mongoose/) |

### Java

| Apache Tomcat | [`tomcat.apache.org/`](http://tomcat.apache.org/) |
| --- | --- |
| JBoss | [`www.jboss.org/`](http://www.jboss.org/) |
| GlassFish | [`glassfish.java.net/`](http://glassfish.java.net/) |
| Atmosphere | [`github.com/Atmosphere/atmosphere`](https://github.com/Atmosphere/atmosphere) |
| Play Framework | [`www.playframework.com/`](http://www.playframework.com/) |
| Jetty | [`www.eclipse.org/jetty/`](http://www.eclipse.org/jetty/) |
| jWebSocket | [`jwebsocket.org/`](http://jwebsocket.org/) |
| Migratory data | [`migratorydata.com/`](http://migratorydata.com/) |
| Bristleback | [`bristleback.pl/`](http://bristleback.pl/) |

### .NET

| Internet Information Services 8 | [`www.iis.net/`](http://www.iis.net/) |
| --- | --- |
| Fleck | [`github.com/statianzo/Fleck`](https://github.com/statianzo/Fleck) |
| SuperWebSocket | [`superwebsocket.codeplex.com/`](http://superwebsocket.codeplex.com/) |

### PHP

| Php-websocket | [`github.com/nicokaiser/php-websocket`](https://github.com/nicokaiser/php-websocket) |
| --- | --- |
| Rachet | [`socketo.me/`](http://socketo.me/) |
| Hoar | [`github.com/hoaproject/Websocket`](https://github.com/hoaproject/Websocket) |

### Python

| Tornado | [`www.tornadoweb.org/en/stable/`](http://www.tornadoweb.org/en/stable/) |
| --- | --- |
| Pywebsocket | [`code.google.com/p/pywebsocket/`](https://code.google.com/p/pywebsocket/) |
| Autobahn | [`autobahn.ws/`](http://autobahn.ws/) |
| txWS | [`github.com/MostAwesomeDude/txWS`](https://github.com/MostAwesomeDude/txWS) |
| WebSocket for Python | [`github.com/Lawouach/WebSocket-for-Python`](https://github.com/Lawouach/WebSocket-for-Python) |

### Ruby

| EM-WebSocket | [`github.com/igrigorik/em-websocket`](https://github.com/igrigorik/em-websocket) |
| --- | --- |
| Socky 服务器 | [`github.com/socky/socky-server-ruby`](https://github.com/socky/socky-server-ruby) |

### JavaScript

这不是开玩笑。你可以使用 JavaScript 创建一个 Web 服务器，这要感谢`Node.js`。`Node.js` ([`nodejs.org`](http://nodejs.org))是一个事件驱动的框架，让你构建实时 Web 应用程序。它也是由谷歌的 JavaScript 引擎 V8 解释的。虽然该框架不直接支持 WebSockets，但有一些相当不错的扩展支持 WebSockets。

| Socket IO | [`socket.io/`](http://socket.io/) |
| --- | --- |
| WebSocket-Node | [`github.com/Worlize/WebSocket-Node`](https://github.com/Worlize/WebSocket-Node) |
| Node WebSocket 服务器 | [`github.com/miksago/node-websocket-server`](https://github.com/miksago/node-websocket-server) |

`Node.js`不断吸引更多的粉丝，所以值得一试。

## 搭建开发环境

你将创建服务器的环境取决于你计划使用的技术、框架和编程语言。有着惊人多样性的**集成开发环境**（**IDEs**）和实用工具可以让你的生活更轻松！

以下是我们提议的一些 IDE，以及它们支持的 Web 编程语言：

| IDE | 操作系统 | 支持的语言 |
| --- | --- | --- |
| Aptana | Windows，Mac，Linux | HTML5JavaScriptPHP |
| NetBeans | Windows，Mac，Linux | HTML5C/C++Java |
| Eclipse（带有 Web 开发插件） | Windows，Mac，Linux | HTML5JavaScriptC/C++Java |
| Visual Studio | Windows | HTML5JavaScript.NET |
| WebMatrix | Windows | HTML5JavaScriptPHP.NET |

在整本书中，我们决定使用 C#.NET 和 Fleck，但这对你来说没有任何影响。随意选择你喜欢的语言或你现有项目所需的语言。

出于教学目的，C#具有以下优势：

+   它在 Windows 上使用.NET 框架，在 Mac 和 Linux 上使用 Mono

+   它有一个活跃的开发者社区，更容易找到支持

+   它很容易学习

+   你可以快速设置一个最小配置的 WebSocket 服务器

Fleck 库之所以被选择，是因为有三个原因：

+   它支持 Windows 和基于 Unix 的操作系统

+   它非常易于使用和配置

+   它得到了很好的维护和文档支持

这是如何快速使用 C#设置 Fleck WebSocket 服务器的方法：

1.  下载 Visual Studio Express（它可以免费获取，网址为[`www.microsoft.com/visualstudio/eng/products/visual-studio-express-for-windows-desktop`](http://www.microsoft.com/visualstudio/eng/products/visual-studio-express-for-windows-desktop)）。

1.  下载 Fleck ([`github.com/statianzo/Fleck`](https://github.com/statianzo/Fleck))。

1.  启动 Visual Studio，点击**文件** | **新建** | **项目**。

1.  在 Visual C#下选择**Windows**。

1.  选择**控制台应用程序**（是的，基于控制台的服务器是设置 WebSocket 服务器的最简单方式）。

1.  给你的项目取任何你喜欢的名字，然后点击**确定**。

1.  在**解决方案资源管理器**选项卡上，右键单击**引用**图标，然后选择**添加新引用**。

1.  点击**浏览**，找到`Fleck.dll`文件。

1.  点击**确定**，你就完成了！

# 连接到 Web 服务器

WebSocket 服务器的工作方式与 WebSocket 客户端类似。它响应事件，并在必要时执行操作。无论您使用的编程语言是什么，每个 WebSocket 服务器都会执行一些特定的操作。它被初始化为 WebSocket 地址，处理`OnOpen`、`OnClose`和`OnMessage`事件，并向客户端发送消息。

## 创建 WebSocket 服务器实例

每个 WebSocket 服务器都需要一个有效的主机和端口。以下是我们在 Fleck 中创建 WebSocketServer 实例的方法：

```js
var server = new WebSocketServer("ws://localhost:8181");
```

您可以输入任何有效的 URL，并指定一个未被使用的端口。

保留连接的客户端记录非常有用，因为您可能需要为它们提供不同的数据或向每个客户端发送不同的消息。

Fleck 使用`IWebSocketConnection`接口表示传入的连接（客户端）。我们可以创建一个空列表，并在有人连接或断开连接时更新它：

```js
var clients = new List<IWebSocketConnection>();
```

之后，我们可以调用`Start`方法，并等待客户端连接。一旦启动，服务器就能够接受传入的连接。

在 Fleck 中，`Start`方法需要一个参数，指示引发事件的套接字：

```js
server.Start(socket) =>
{
});
```

一些语法解释：`Start`声明后面的内容称为 C# Action，如果您使用不同的语言，可以完全忽略它。我们将在`Start`块内处理所有事件。

## 打开

`OnOpen`事件确定了一个新的客户端请求访问并执行初始握手。我们应该将客户端添加到列表中，并可能存储与之相关的任何信息，比如 IP 地址。Fleck 为我们提供了这样的信息，以及连接的唯一标识符。

```js
server.Start(socket) =>
{
  socket.OnOpen = () =>
  {
    // Add the incoming connection to our list.
    clients.Add(socket);
  }

  // Handle the other events here…
}); 
```

## 关闭

`OnClose`事件在客户端断开连接时触发。我们可以从列表中删除该客户端，并通知其他客户端有人断开连接：

```js
socket.OnClose = () =>
{
  // Remove the disconnected client from the list.
  clients.Remove(socket);
};
```

## 消息

`OnMessage`事件在客户端向服务器发送数据时触发。在此事件处理程序内，我们可以将传入的消息传输给所有客户端，或者可能只选择其中一些。这个过程很简单。请注意，此处理程序接受名为`message`的字符串作为参数：

```js
socket.OnMessage = () =>
{
  // Display the message on the console.
  Console.WriteLine(message);
};
```

## 发送

`Send()`方法简单地将所需的消息传输给指定的客户端。使用`Send()`，我们可以在客户端之间传递文本或二进制数据。让我们遍历注册的客户端并将消息传递给他们。我们需要修改`OnMessage`事件如下：

```js
socket.OnMessage = () =>
{
foreach (var client in clients)
{
  // Send the message to everyone!
  // Also, send the client connection's unique identifier in order to recognize who is who.
  client.Send(client.ConnectionInfo.Id + " says: " + message);
}
};
```

显然，您不需要公开每个人的 IP 地址或 ID！这对您的用户来说完全没有意义，除非他们是黑客。当然，在真正的聊天对话中，用户选择昵称而不是字符串文字。我们将在下一章中为他们提供昵称选项。

Fleck 接受字符串和字节数组。字符串包含纯文本、XML 或 JSON 消息。字节数组在处理图像或二进制文件时非常有用。

# 其他方法

根据您使用的 WebSocket 服务器实现，可能会有额外的事件或方法。例如，Fleck 支持`OnBinary`事件，这是`OnMessage`事件的二进制支持等价物。

请记住，Web 服务器将连接存储在列表中，我们需要遍历所有连接以发送消息。

# 完整的源代码

以下是完整的服务器端源代码，还有一些额外的添加以提供更好的用户体验。截图显示了 Chrome 和 Internet Explorer 10 窗口并排聊天！

以下截图显示了使用 Chrome 进行聊天的用户：

![完整的源代码](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/gtst-h5-ws-prog/img/6962_03_02.jpg)

以下截图显示了使用 Internet Explorer 10 同时进行聊天的第二个用户：

![完整的源代码](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/gtst-h5-ws-prog/img/6962_03_03.jpg)

```js
namespace WebSockets.Server
{
  class Program
  {
    static void Main(string[] args)
    {
      // Store the subscribed clients.
      var clients = new List<IWebSocketConnection>();

      // Initialize the WebSocket server connection.
      var server = new WebSocketServer("ws://localhost:8181");

      server.Start(socket) =>
      {
        socket.OnOpen = () =>
        {
          // Add the incoming connection to our list.
          clients.Add(socket);

          // Inform the others that someone has just joined the conversation.
          foreach (var client in clients)
          {
            // Check the connection unique ID and display a different welcome message!
            if (client.ConnectionInfo.Id != socket.ConnectionInfo.Id)
            {
              client.Send("<i>" + socket.ConnectionInfo.Id + " joined the conversation.</i>");
            }
            else
            {
              client.Send("<i>You have just joined the conversation.</i>");
            }
          }
        };

        socket.OnClose = () =>
        {
          // Remove the disconnected client from the list.
          clients.Remove(socket);

          // Inform the others that someone left the conversation.
          foreach (var client in clients)
          {
            if (client.ConnectionInfo.Id != socket.ConnectionInfo.Id)
            {
              client.Send("<i>" + socket.ConnectionInfo.Id + " left the chat room.</i>");
              }
            }
          };

          socket.OnMessage = message =>
          {
            // Send the message to everyone!
            // Also, send the client connection's unique identifier in order to recognize who is who.
            foreach (var client in clients)
            {
              client.Send(socket.ConnectionInfo.Id + " says: <strong>" + message + "</strong>");
            }
          };
        });

        // Wait for a key press to close...
        Console.ReadLine();
      }
  }
}
```

# 总结

到目前为止，您应该能够创建一个完整的 WebSocket 应用程序！《第二章》*WebSocket API*，介绍了如何使用 JavaScript 配置客户端，而本章则向您展示了如何使用您最熟悉的环境和编程语言配置 WebSocket 服务器。此外，我们还研究了 WebSocket 服务器事件和操作。在接下来的章节中，我们将学习如何有效处理不同的数据格式并保护我们基于 WebSocket 的应用程序。


# 第四章：数据传输-发送、接收和解码

现代网页开发都是关于内容的。无论您正在构建什么样的应用程序，用户都会停止使用它，除非他们得到他们想要的。在早期的网络时代，某人可以在自己的网站上发布的内容非常有限。如今，内容远不止是静态文本和图像；您可以交换消息，观看视频，下载程序等等。作为网页开发人员，您应该能够以快速高效的方式传递所需的内容。WebSocket 协议支持各种可传输数据，尽可能地加快整个过程的速度。

在本章的演示中，您将通过 WebSockets 处理图像和视频数据。让我们开始吧！

# WebSockets 可以传输哪些类型的数据？

WebSocket 协议支持文本和二进制数据。在 JavaScript 中，文本称为字符串，而二进制数据由 ArrayBuffer 和 Blob 类表示（第一个仍处于实验阶段）。使用纯文本和二进制格式，您可以传输和解码几乎任何类型的 HTML5 媒体。

请记住，WebSockets 一次只支持一种二进制格式，并且您必须明确声明如下：

```js
socket.binaryType = "arraybuffer";
```

另一种方法是：

```js
socket.binaryType = "blob"
```

在本书中，我们将演示使用每种数据类型的具体示例。

## 字符串

在之前的章节中，您已经简单了解了传输纯文本数据的情况，其中您交换了简单的聊天消息。除此之外，字符串在处理人类可读的数据格式（如**XML**和**JSON**）时非常有帮助。

请记住，每当`onmessage`事件被触发时，客户端需要检查数据类型并相应地采取行动。JavaScript 可以轻松确定数据类型是否为`string`类型，使用严格相等运算符（即`===`）。

```js
socket.onmessage = function(event) {
  if (typeof event.data === "string") {
    console.log("Received string data.");
  }
}
```

如果您对核心 JavaScript 有一般的经验，您可能会注意到您可以使用以下表达式代替：

```js
if (event.data instanceof String)
```

尽管此代码非常有效，但在您的情况下不起作用。原因是`instanceof`表达式要求左侧的对象是使用 JavaScript 字符串构造函数创建的。在您的情况下，数据是从服务器生成的，因此您只能确定它们的基础类型，而不是它们的 JavaScript 类。

### JSON

**JSON**（**JavaScript 对象表示法**）是一种在计算机之间传输人类可读数据的轻量级格式。它以键值对的形式结构化，通常描述属性和值。由于其高效性，JSON 是服务器和客户端之间传输数据的主要格式。如今，包括 Facebook、Twitter 和 Github 在内的最流行的 RESTful API 完全支持 JSON。此外，JSON 是 JavaScript 的子集，因此您可以立即解析它，而无需使用外部解析器！

假设 Web 服务器以某种方式发送了以下 JSON 字符串：

```js
{
"name" : "Vangos Pterneas",
"message" : "Hello world!"
}
```

显然，前面的表示包含两个键值对。猜猜看？在您的聊天演示中，它代表来自另一个用户的聊天数据。您将在几分钟内使用这些信息。

以下代码显示了如何处理 JSON 对象并提取其属性：

socket.onmessage = function(event) {

```js
  if (typeof event.data === "string") {
    // Create a JSON object.
    var jsonObject = JSON.parse(event.data);

    // Extract the values for each key.
    var userName = jsonObject.name;
    var userMessage = jsonObject.message;
  }
}
```

前面的代码很简单。使用`eval`函数，您可以从输入字符串创建一个 JSON 对象。`eval`实际上是调用 JavaScript 编译器并执行封闭的字符串参数。生成对象的属性是 JSON 键的名称，每个属性都包含其相应的值。

### XML

与 JSON 类似，您可以使用 JavaScript 解析 XML 编码的字符串。我们不会深入研究 XML 解析，因为这超出了本书的范围。解析 XML 并不困难，尽管它需要不同的技术来处理不同的浏览器（**DOMParser**与**ActiveXObject**）。最好的方法是使用第三方库，比如**jQuery**。

### 注意

在 XML 和 JSON 的情况下，服务器应该向您发送一个字符串值，而不是实际的 XML/JSON 文件（当然是二进制类型的）！

## ArrayBuffer

ArrayBuffer 包含结构化的二进制数据。关键词在于**结构化**，这意味着封闭的位按顺序给出，因此您可以检索其中的部分。为了针对特定格式操作 ArrayBuffer，您需要创建相应的`ArrayBufferView`对象。

ArrayBuffers 非常适用于存储图像文件。假设您的聊天室客人可以通过在聊天窗口上拖放图像文件来交换图像。以下代码解释了 JavaScript 如何处理 HTML5 浏览器中的拖放事件：

```js
document.ondrop = function(event) {
  var file = event.dataTransfer.files[0];
  var reader = new FileReader();

  reader.readAsArrayBuffer(file);

  reader.onload = function() {
    socket.send(reader.result);
  }

  return false;
}
```

在前面的代码片段中，您首先为拖放事件创建了一个事件处理程序。事件处理程序接受一个参数，让您访问已放置的文件。您只放置了一个单一的图像，因此您需要零索引文件。之后，您创建一个文件读取器，将文件的数据读取为 ArrayBuffer。当读取器完成处理文件时，您处理`onload`事件，其中您使用 WebSocket 将图像发送到 Web 服务器。

在[`www.html5rocks.com/en/tutorials/file/dndfiles/`](http://www.html5rocks.com/en/tutorials/file/dndfiles/)了解更多有关 FileReader 的信息。

以下是提高发送方法的拖放效果的屏幕截图：

![ArrayBuffer](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/gtst-h5-ws-prog/img/6962OS_04_01.jpg)

将图像拖放到浏览器并发送到服务器

接收 ArrayBuffers 数据相当简单。请注意，您使用`instanceof`进行检查，而不是使用严格相等运算符。

```js
socket.onmessage = function(event) {
  if (event.data instanceof ArrayBuffer) {
    var buffer = event.data;
  }
}
```

## Blob

**Blob**（二进制大对象）以其最原始的形式包含完全原始的数据。理论上，Blob 可能是任何东西，甚至是非 JavaScript 对象。因此，解释 Blob 数据可能会非常棘手。作为一个经验法则，最好确切地知道服务器应该发送什么，否则您将需要做相当不具体的假设。

然而，Blob 数据的一个很大的优势是它们的文件大小。二进制格式是机器级格式，因此几乎没有使用会增加其大小的抽象层。

当您通过网络传输多媒体时，您需要尽可能快的速度，以实现最佳的用户体验。WebSocket Blob 不会为您的互联网连接增加额外的负担，并且它们依赖客户端进行正确的解释。

以下代码显示了如何显示作为一组原始位发送的传入图像：

```js
socket.onmessage = function(event) {
  if (event.data instanceof Blob) {
    // 1\. Get the raw data.
var blob = event.data;

    // 2\. Create a new URL for the blob object.
    window.URL = window.URL || window.webkitURL;
    var source = window.URL.createObjectURL(blob);

    // 3\. Create an image tag programmatically.
    var image = document.createElement("img");
    image.src = source;
    image.alt = "Image generated from blob";

    // 4\. Insert the new image at the end of the document.
    document.body.appendChild(image);
  }
}
```

前面的代码片段通过正确解释传入的原始数据生成了图像。您已经使用了一些全新的 HTML5 JavaScript 方法来轻松处理 Blob。让我们更具体一些。

首先，您验证服务器消息是否是 Blob 的实例，类似于您检查缓冲数组的方式。然后，您将原始数据存储到一个名为`blob`的本地变量中。

为了以图像格式显示 Blob，您需要正确解码它。新的 JavaScript API 使基本图像操作变得非常简单。您不是读取字节，而是创建一个指定数据源的普通 URL。只要 HTML 文档存在，这个 URL 就是活动的。这意味着在关闭浏览器窗口后无法检索它。

`window.URL`属性目前在所有主要浏览器中都受支持，尽管**Google Chrome**将其命名为`window.webkitURL`。`createObjectURL`方法为指定的临时文件生成 URL。您不需要提供任何进一步的细节或编写任何进一步的代码！JavaScript 将您收到的 Blob 表示为正常的浏览器 URL！

最后，使用您已经了解的 DOM 操作方法，您创建一个图像元素，为其提供新的 URL，并将其插入到 HTML 文档的末尾。

### 注意

`createObjectURL`方法在 Chrome 23+、Firefox 8+、Internet Explorer 10+、Opera 16+和 Safari 6+以及它们的移动对应版本中都受支持（除了 IE 和 Opera）。

试一下，你会看到类似以下截图的东西：

![Blob](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/gtst-h5-ws-prog/img/6962OS_04_02.jpg)

显示为 HTML 图像的传入 blob 数据

### 视频流

许多网页设计师和开发人员认为网络的未来是视频。直到现在，视频是通过第三方插件和技术（如 Flash 或 Silverlight）传递的。尽管这些技术在桌面浏览器上运行得很好，但它们需要额外的软件，并且对移动和平板设备的电池寿命造成了灾难。在苹果决定停止 iPhone 和 iPad 对 Flash 的支持之后，HTML5 成为了通过网络传递视频和丰富图形的唯一可用途径。

就 WebSockets 而言，使用快速高效的方式在不同客户端之间流式传输视频是有意义的。实时视频流目前被认为是 Flash 仍然存在的最后原因之一。让我们看看如何可以通过 WebSocket 方式从服务器向客户端流式传输实时视频数据。

视频只不过是一系列连续的图像。每个图像被称为**帧**。当每秒显示多个帧（通常超过 20 帧）时，人眼无法区分这些图像，会认为是连续的流。这就是你要用来从服务器向客户端流式传输视频文件的技术。

服务器每秒发送 20 帧或更多帧（图像），因此客户端不断等待新消息。还记得你为显示图像编写的代码吗？在实时视频流上下文中，你不需要将数据存储为 URL，直到网页关闭。相反，当你不再使用它们时，最好将帧 URL 丢弃。此外，无需使用 JavaScript 创建`<img>`元素，因为你可以将它放在我们的标记中：

```js
<img id="video" src="img/" alt="Video streaming" />
```

...并在你的 JavaScript 代码中创建一个引用：

```js
var video = document.getElementById("video");
```

因此，这是修改后的 onmessage 客户端事件，每秒将被触发 20 次或更多次：

```js
socket.onmessage = function(event) {
  if (event.data instanceof Blob) {
    // 1\. Get the raw data.
var blob = event.data;

    // 2\. Create a new URL for the blob object.
    window.URL = window.URL || window.webkitURL;
    var source = window.URL.createObjectURL(blob);

    // 3\. Update the image source.
    video.src = source;
    // 4\. Release the allocated memory.
    window.URL.revokeObjectURL(source);
  }
}
```

这段代码与您用来在 HTML 文档中放置图像的代码类似。有两件事需要注意：

+   你已经为`<img>`元素创建了一个引用，以便不断修改它的`src`属性。

+   在每次`src`赋值之后，通过调用`revokeObjectURL`函数释放图像。这个函数清理分配给指定 URL 的内存，并让浏览器知道它不需要再保留 URL 的引用了。

以下截图显示了使用连续帧进行视频流传输：

![视频流](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/gtst-h5-ws-prog/img/6962OS_04_03.jpg)

### 注意

虽然它表达了观点，但这可能不是流式传输视频的最佳方式。为了更专业的方法，看看 WebRTC（[`www.webrtc.org`](http://www.webrtc.org)），这是一个由谷歌、Mozilla 和 Opera 实现的出色的多媒体开发 API。

# 把所有东西放在一起

你可能想知道处理请求、接收图像并更新视频帧的服务器端代码在哪里。我们故意留出了服务器端部分，以便专注于客户端 JavaScript 代码。对于我们的聊天演示 Web 应用程序，我们现在将向您展示客户端和服务器端代码。再次注意，您可以使用您选择的编程语言和框架来实现 WebSocket 服务器。

让我们仔细看看你将要实现的新部分。

## 使用 JSON 发送昵称和消息

首先，在 HTML 文档中添加一个文本字段，以便用户输入他/她喜欢的昵称。你将通过以 JSON 格式对它们进行编码，将昵称和文本消息发送出去。

在消息输入框之前添加一个新的文本输入：

```js
<label id="status-label">Status...</label>
<input type="text" id="name-view" placeholder="Your name" />
<input type="text" id="text-view" placeholder="Type yourmessage..." />
```

然后，在 JavaScript 代码中创建一个引用：

```js
var nameView = document.getElementById("name-view");
```

最后，像几页前一样，将昵称和消息发送到服务器！

```js
buttonSend.onclick = function (event) {
  if (socket.readyState == WebSocket.OPEN) {
    var json = "{ 'name' : '" + nameView.value + "', 'message' :
      '" + textView.value + "' }";
    socket.send(json);
    textView.value = "";
  }
}
```

服务器现在需要将这条消息传输给客户端。与上一章相比，没有任何改变：

```js
socket.OnMessage = message =>
  {
    // Send the text message to everyone!
    foreach (var client in clients)
      {
        client.Send(message);
      }
  };
```

客户端解码 JSON 字符串并相应地显示消息。您已为在聊天区域显示文本添加了更漂亮的呈现样式。

```js
socket.onmessage = function (event) {
  if (typeof event.data === "string") {
    // Display message.
    var jsonObject = eval('(' + event.data + ')');
    var userName = jsonObject.name;
    var userMessage = jsonObject.message;

    chatArea.innerHTML = chatArea.innerHTML + 
      "<p><strong>" + userName + "</strong>: " + userMessage +
        "</p>";
  }
}
```

## 将图像发送到服务器

还记得我们之前讨论过的`ondrop`事件吗？出于一致性原因，这里使用 Blob 而不是 ArrayBuffers 实现了相同的功能：

```js
document.ondrop = function(event) {
  var file = event.dataTransfer.files[0];

  socket.send(file);

  return false;
}
```

处理 HTML5 拖放时，记住始终要阻止默认的拖放行为！除非您明确定义要覆盖默认功能，否则您实现的任何内容都不会显示正确。幸运的是，阻止预定义的操作发生非常简单：

```js
document.ondragover = function (event) {
  event.preventDefault();
}
```

服务器需要将 blob 图像分发给所有客户端。`Fleck`库引入了`OnBinary`事件，当接收到二进制数据时会触发。

```js
socket.OnBinary = data =>
  {
    // Send the binary data to everyone!
    foreach (var client in clients)
      {
        client.Send(data);
      }
};
```

该方法与`OnMessage`方法类似。唯一的区别是它以字节数组（数据）而不是字符串作为参数。字节数组是最本地和高效的图像表示。

当其余客户端接收到图像时，将创建一个新的`<img>`元素。您已经看到了方法，所以相应地更新`onmessage`函数：

```js
socket.onmessage = function(event) {
if (typeof event.data === "string") {
  // Decode JSON, then display nickname and message.
  // …
}
  else if (event.data instanceof Blob) {
  // Get the raw data and create an image element.
var blob = event.data;

    window.URL = window.URL || window.webkitURL;
    var source = window.URL.createObjectURL(blob);

var image = document.createElement("img");
    image.src = source;
    image.alt = "Image generated from blob";

    document.body.appendChild(image);
  }
}
```

# 总结

在本章中，您详细了解了 WebSocket 协议支持的各种数据格式。您使用字符串和二进制数据（文本、图像和视频）实现了各种示例，找出了如何正确地对客户端数据进行编码和解码，最后扩展了聊天演示以操纵图像和视频。下一章将讨论网络上的安全考虑，这将使您的应用程序更加健壮。


# 第五章：安全

安全对于交换数据的 Web 应用程序来说是一个至关重要的问题。每个在网络中生存和发展的站点或应用程序都可能受到人类或机器入侵者的攻击。这是一个令人沮丧但却真实存在的现实，我们都必须接受。

当然，这并不意味着您的 Web 应用是完全不安全的。幸运的是，原生 HTML5 安全机制可以在不进行任何配置的情况下保护您免受最常见的安全攻击。此外，WebSocket 协议旨在成为一个安全服务，因此基本的保护是有保障的。

在本章中，我们将介绍 WebSocket 应用可能存在的一些已知安全风险，并为您提供工具和知识，以防止、对抗和克服这些风险，以保护您的用户。

# WebSocket 标头

通常您不会与一个不认识的人或不愿透露身份的人握手。在 WebSocket 世界中，您需要确保请求的来源。**来源**是客户端发送的一个标头，对于跨域通信至关重要，因为它允许 Web 服务器拒绝特定的连接。来源是 WebSocket 中引入和记录的第一个也是最重要的安全方面。

还需要一些额外的标头才能允许客户端升级到 WebSocket 协议。这些标头以`Sec-`前缀开头，并保证每个 WebSocket 请求都将通过 WebSocket 构造函数初始化，而不是任何可能要访问交换信息的 HTTP API。

以下是客户端发送的 WebSocket 标头的示例：

```js
GET /chat HTTP/1.1
Host: server.example.com
Upgrade: websocket
Connection: Upgrade
Origin: http://example.com
Pragma: no-cache
Cache-Control: no-cache
Sec-WebSocket-Key: AAf/gvkPw6szicrMH3Rwbg==
Sec-WebSocket-Version: 13
Sec-WebSocket-Extensions: x-webkit-deflate-frame
```

`Sec-WebSocket-Version`参数可以帮助您识别所使用的浏览器。如果您需要针对特定浏览器进行特定调整，请注意。服务器的相应握手应如下所示：

```js
HTTP/1.1 101 Switching Protocols
  Upgrade: websocket
  Connection: Upgrade
  Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
```

如果您对更多理论细节感兴趣，请随时阅读 RFC 6455 的完整规范[`tools.ietf.org/html/rfc6455`](http://tools.ietf.org/html/rfc6455)。

# 常见攻击

目前，您需要知道的是，该协议旨在尽可能安全。不过要小心！WebSocket 是一个全新的协议，而并非所有的 Web 浏览器都正确实现了它。例如，其中一些仍允许 HTTP 和 WS 的混合使用，尽管规范暗示相反。一切都可能发生变化，而在等待浏览器成熟的同时，您可以轻松地自行采用一些保护技术。

因此，老式的问题并没有得到解决。还记得那些窃听 HTTP 并拦截网络流量的坏人吗？嗯，WS 也可以被同样的方式窃听。

以下是您需要注意的一些常见安全攻击，以及因此您可以保护您的应用程序和用户的一些方法。

## 拒绝服务

**拒绝服务**（**DoS**）攻击试图使机器或网络资源对请求它的用户不可用。想象一下，有人以无限次数的请求以极短的时间间隔向 Web 服务器发出请求。显然，服务器无法处理每个连接，要么停止响应，要么响应过慢。这是 DoS 攻击的最简单形式。

无需多言，这对最终用户来说可能是多么令人沮丧，他们甚至无法加载一个网页。

DoS 攻击甚至可以应用于点对点通信，迫使 P2P 网络的客户端同时连接到受害的 Web 服务器。

以下图描述了 DoS 攻击：

![拒绝服务](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/gtst-h5-ws-prog/img/6962OS_05_01.jpg)

DoS 攻击

## 中间人攻击

假设您正在通过即时通讯客户端与女友聊天。她的前男友想要查看您交换的消息，因此他与您两个独立建立连接，并窃听您的消息。他还向您和您的女友发送消息，作为您通信的隐形中间人。这就是所谓的中间人攻击。中间人攻击更容易发生在未加密的连接上，因为入侵者可以直接读取数据包。当连接加密时，信息必须由攻击者解密，这可能会非常困难。

从技术角度来看，攻击者拦截公钥消息交换并发送消息，同时用自己的密钥替换请求的密钥。

显然，使攻击者的工作变得困难的一个坚实策略是使用带有 WebSockets 的 SSH。在交换关键数据时，最好使用 WSS 安全连接，而不是未加密的 WS。

以下图表描述了间谍如何干扰和获取数据：

![中间人攻击](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/gtst-h5-ws-prog/img/6962OS_05_02.jpg)

中间人攻击

## XSS

**跨站脚本**（**XSS**）是一种漏洞，使攻击者能够将客户端脚本注入到网页或应用程序中。攻击者可以使用您的应用程序中心发送 HTML 或 JavaScript 代码，并让该代码在客户端机器上执行。

当填写网页表单时，您可能会遇到最简单形式的 XSS 攻击。想象一下，有人使用我们开发的聊天应用程序发送了以下数据：

```js
<img src="http://www.therichest.org/wp-content/uploads/young-bill-
  gates.jpg" />
```

试一下！在消息文本字段中输入上述行，点击**发送**，并等待结果。

以下图像显示了对我们的 WebSocket 聊天应用程序的 XSS 攻击：

![XSS](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/gtst-h5-ws-prog/img/6962OS_05_03.jpg)

尽管在聊天应用程序中图像传输并不坏，但用户通过注入 HTML 代码发送了图像。以类似的方式，某人可能会执行 JavaScript 代码并损害对话。

我们能做些什么？考虑到关于 XSS 攻击的旧规则仍然有效并且是最佳实践。您可以检查您的代码中的 HTML 实体或 JavaScript 语法，并用适当的表示形式替换它们，或者简单地拒绝它们。

[`www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet`](https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet) 包含了更多信息，如果您想了解 XSS 攻击的各个方面以及如何避免它们。

# WebSocket 本地防御机制

默认情况下，WebSocket 协议设计为安全的。在现实世界中，您可能会遇到由于浏览器实现不佳而可能发生的各种问题。不过不用担心。随着时间的推移，浏览器供应商会立即修复任何问题，如果您仍然感到害怕，您总是可以使用一些老式的回退技术（在下一章中描述）。

## SSH/TLS

正如您可能已经猜到的那样，当您在 SSH（或 TLS）上使用安全的 WebSocket 连接时，会增加一层额外的安全性。还记得当您需要在 HTTP 和 HTTPS 之间做出决定吗？只有在绝对必要时才选择 HTTPS 进行交易（例如，银行账户信息，私人数据等）。否则，HTTP 是更轻量级和更快速的选择。HTTPS 需要更多的 CPU 资源，比 HTTP 慢得多。

在 WebSocket 世界中，您不需要担心安全连接的性能。尽管顶部仍然有额外的 TLS 层，但协议本身包含了针对这种用途的优化，此外，WSS 通过代理更加流畅。

## 客户端到服务器的掩码

WebSocket 服务器和 WebSocket 客户端之间传输的每条消息都包含一个名为**掩码密钥**的特定密钥，这允许任何符合 WebSocket 标准的中间人解除掩码并检查消息。如果中间人不符合 WebSocket 标准，则消息不会受到影响。掩码由实现 WebSocket 协议的浏览器处理。

# 安全工具箱

最后，我们介绍了一些有用的工具，帮助您调查 WebSocket 客户端和服务器之间信息流动，分析交换的数据，并识别可能的风险。

## Fiddler

**Fiddler**是一个很棒的工具，用于监视网络活动并检查任何传入或传出数据的流量。

以下截图显示了 fiddler 的操作，显示了 WebSocket 的标头：

![Fiddler](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/gtst-h5-ws-prog/img/6962OS_05_04.jpg)

Fiddler 可以从[`www.fiddler2.com/fiddler2/`](http://www.fiddler2.com/fiddler2/)下载

## Wireshark

**Wireshark**是一个网络数据包分析器，捕获数据包并尽可能准确地显示其数据。

以下截图显示了 wireshark 的操作：

![Wireshark](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/gtst-h5-ws-prog/img/6962OS_05_05.jpg)

Wireshark 可以从[`www.wireshark.org/`](http://www.wireshark.org/)下载

## 浏览器开发者工具

Chrome，Firefox 和 Opera 在开发者支持方面是很棒的浏览器。它们内置的工具帮助我们确定几乎任何客户端交互和资源的方面。

以下截图显示了 Chrome 开发者工具的操作：

![浏览器开发者工具](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/gtst-h5-ws-prog/img/6962OS_05_06.jpg)

## ZAP

**ZAP**是一个渗透测试工具，通过对 Web 应用程序和站点进行攻击，发现它们的漏洞！与所有先前的工具一样，ZAP 带有方便的 GUI 可视化。

以下截图显示了 ZAP 的操作：

![ZAP](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/gtst-h5-ws-prog/img/6962OS_05_07.jpg)

ZAP 可以从[`code.google.com/p/zaproxy/`](https://code.google.com/p/zaproxy/)下载

# 总结

在本章中，您调查了您的 Web 应用程序必须意识到的各种安全威胁，看到了内置的 WebSocket 安全机制，并介绍了一些流行的工具，帮助我们更好地管理网络传输。接下来，我们将描述一些针对缺乏完整或部分 WebSocket 支持的浏览器的备用技术。


# 第六章：错误处理和备用方案

到目前为止，您一定熟悉了 WebSocket 的功能，并且对全双工通信的强大有了一定的了解。然而，WebSocket 的好处是建立在 HTML5 之上的，并且在很大程度上依赖于浏览器的全面支持。当您想要实现的功能不受受众使用的手段支持时会发生什么？您会让您的客户离开吗？这听起来不是一个好主意。幸运的是，通过一点额外的努力，您可以实现、模仿并大部分模拟 WebSocket 的行为。

WebSocket 是未来友好的方式，但为了支持尽可能广泛的受众，您需要一些备用技术。

# 错误处理

在处理错误时，您必须考虑内部和外部参数。内部参数包括由于代码中的错误或意外的用户行为而产生的错误。外部错误与应用程序无关，而是与您无法控制的参数相关。最重要的是网络连接。任何交互式的双向网络应用程序都需要一个活动的互联网连接。

## 检查网络可用性

想象一下，您的用户正在享受您的 Web 应用程序，突然在他们的任务中间，网络连接变得无响应。在现代原生桌面和移动应用程序中，检查网络可用性是一项常见的任务。最常见的方法是简单地向一个应该处于活动状态的网站（例如[`www.google.com`](http://www.google.com)）发出 HTTP 请求。如果请求成功，桌面或移动设备就知道有活动的连接。

同样，HTML 有`XMLHttpRequest`用于确定网络可用性。不过，HTML5 使得这更加容易，并引入了一种检查浏览器是否能接受 Web 响应的方法。这是通过 navigator 对象实现的：

```js
if (navigator.onLine) { 
  alert("You are Online");
}
else {

  alert("You are Offline");
}
```

离线模式意味着设备未连接或用户从浏览器工具栏中选择了离线模式。

以下是在 WebSocket 关闭事件发生时通知用户网络不可用并尝试重新连接的方法：

```js
socket.onclose = function (event) {
  // Connection closed.
  // Firstly, check the reason.
  if (event.code != 1000) {
    // Error code 1000 means that the connection was closed normally.
    // Try to reconnect.
    if (!navigator.onLine) {
      alert("You are offline. Please connect to the Internet and try   again.");
    }
  }
}
```

前面的代码非常简单。它检查错误代码以确定 WebSocket 连接是否已成功关闭。错误代码 1000 将确定这一点。如果关闭事件是由于错误而引发的，代码将不是 1000。在这种情况下，代码会检查连接性并适当地通知用户。

您可能会注意到这是一个 HTML5 功能。稍后，我们将讨论 polyfills，以下是两个用于检查网络连接性的 polyfills：

+   [`github.com/remy/polyfills/blob/master/offline-events.js`](https://github.com/remy/polyfills/blob/master/offline-events.js)

+   [`nouincolor.com/heyoffline.js/`](http://nouincolor.com/heyoffline.js/)

第一个方法是使用`XMLHttpRequest`，类似于智能手机 API 所做的事情。

# 备用解决方案

在现实生活中，人们更喜欢进行身体接触，因为这样更直接和高效，但这不应该是认识某人的唯一方式。有很多情况下你无法握手，所以你需要找到其他的沟通方式。

HTML5 的悲哀现实是，并非每个浏览器都能完全支持它。特别是考虑到新的 JavaScript API，不同浏览器之间仍然存在主要或次要的差异。然而，即使浏览器供应商决定为其当前版本提供完全相同的功能，仍然会有人无法或不想更新。根据 StatCounter 和 W3Counter 的数据，截至 2013 年 3 月，桌面浏览的大部分份额属于 Google Chrome，其次是 Microsoft Internet Explorer 和 Mozilla Firefox。

Internet Explorer 8 仍占 7％，Internet Explorer 7 占 5％，Safari 5.1 占 3％。总共 15％的份额转化为您可能不想错过的客户数量。

这里是备用解决方案，可以处理这种情况，并为旧版浏览器的用户提供一个优雅的缩减体验。如今有两种流行的备用方案，**插件**（如 Flash 或 Silverlight）和**JavaScript hacks**，正式称为**polyfills**。

## JavaScript polyfills

我们首先来研究 polyfills，因为它们更接近原生网络。JavaScript polyfills 是模拟未来功能的解决方案和库，通过为旧版浏览器提供支持来实现。目前，几乎所有 HTML5 特定功能（如 canvas、storage、geolocation、WebSockets、CSS3 等）都有 polyfill 解决方案。

应该并行使用 polyfill 解决方案和基于标准的、符合 HTML5 的 API。

如果您需要同时实现 HTML5 和 polyfill 解决方案，为什么不只实现第二个并节省时间和金钱呢？好吧，以下是您应该同时使用两者的四个原因：

1.  更好的用户体验：使用 HTML5 时，您为访问者提供了最佳和最顺畅的体验。一切都由浏览器处理，您只需专注于应用程序的需求。使用 polyfill 来解决特定问题时，最终产品无法达到相同的质量。当然，提供一些东西总比什么都不提供要好，但是 polyfill 只是为那些运行较差的浏览器打补丁。

1.  性能：原生 HTML5 解决方案和 polyfill 插件之间最显著的优势是性能。当您请求 JavaScript 文件时，您需要额外的资源，这会增加加载时间。此外，JavaScript 插件的运行速度远远慢于原生浏览器实现的方法。关于 WebSockets，该协议旨在提供双向全双工通信。这是您可以实现这种类型的最快方式。而 polyfill 所能做的就是简单地模拟全双工通信，使用传统的 AJAX 轮询。我们已经看到 AJAX 轮询比 WebSockets 慢得多。

1.  面向未来：现在使用 HTML5 可以让您的网站或应用程序在任何未来的浏览器更新中自动增强。例如，三年前使用 canvas 的人在 Internet Explorer 更新到第 9 版时自动受益。

1.  符合标准：尽管内容而不是网络标准应该是我们的首要任务，但了解我们当前的实现是否符合正式的技术规范也是好的。此外，网络标准提出了所谓的“最佳实践”。尽管 polyfills 通常由有效的 JavaScript 代码组成，但大多数时候它们需要通过插入必要的非标准代码来解决特定浏览器的错误和不一致性。

### 流行的 polyfills

**Modernizr**，一个用于检测 HTML5 和 CSS3 功能的知名库，提供了一系列 HTML5 polyfills 的列表，可以在支持旧版浏览器时让您的生活更加轻松。无论您使用哪种 HTML5 功能，都可以在[`github.com/Modernizr/Modernizr/wiki/HTML5-Cross-Browser-Polyfills`](https://github.com/Modernizr/Modernizr/wiki/HTML5-Cross-Browser-Polyfills)找到相应的 polyfill。

关于 WebSockets，以下是一些模拟 WebSocket 行为的库：

| 名称 | 超链接 |
| --- | --- |
| SockJS | [`github.com/sockjs/sockjs-client`](https://github.com/sockjs/sockjs-client) |
| socket.io | [`socket.io/`](http://socket.io/) |
| Kaazing WebSocket Gateway | [`kaazing.com/products/kaazing-websocket-gateway.html`](http://kaazing.com/products/kaazing-websocket-gateway.html) |
| web-socket-js | [`github.com/gimite/web-socket-js/`](http://github.com/gimite/web-socket-js/) |
| Atmosphere | [`jfarcand.wordpress.com/2010/06/15/using-atmospheres-jquery-plug-in-to-build-applicationsupporting-both-websocket-and-comet/`](http://jfarcand.wordpress.com/2010/06/15/using-atmospheres-jquery-plug-in-to-build-applicationsupporting-both-websocket-and-comet/) |
| Graceful WebSocket | [`github.com/ffdead/jquery-graceful-websocket`](https://github.com/ffdead/jquery-graceful-websocket) |
| Portal | [`github.com/flowersinthesand/portal`](https://github.com/flowersinthesand/portal) |
| DataChannel | [`github.com/piranna/DataChannel-polyfill`](https://github.com/piranna/DataChannel-polyfill) |

除了 Kaazing，以上所有库都是开源的，可以免费使用。其中一些库使用 AJAX 方法，而其他一些依赖 Flash 来模拟 WebSocket 的行为。

以下是使用 Graceful WebSocket 库的示例。我们选择了 Graceful WebSocket，因为它简单，轻量级，不使用 Flash，并且暴露了类似于 WebSocket API 的功能。

首先，下载该库以及 jQuery，并将它们包含在您的项目中：

```js
<script src="img/ jquery-1.9.1.min.js"></script>
<script src="img/jquery.gracefulWebSocket.js"></script>
```

像平常一样构建您的文档，并只需一次将对 WebSocket 原生类的任何引用替换为`gracefulWebSocket`即可。

替换这个：

```js
var socket = new WebSocket("ws://localhost:8181");
```

使用这个：

```js
var socket = $.gracefulWebSocket("ws://localhost:8181");
```

就是这么简单！其余的 WebSocket 事件和方法保持不变：

```js
socket.onopen = function (event) {
  // Handle the open event as previously.   
};

socket.onclose = function (event) {
  // Handle the close event as previously.   
};

socket.onmessage = function (event) {
  // Handle the message event as previously.   
};

socket.onerror = function (event) {
  // Handle the error event as previously.   
};
```

发送数据同样简单，可以按以下方式进行：

```js
socket.send("Hello server! I'm a WebSocket polyfill.");
```

在正常模式下，上述代码的前几行简单地包装了 WebSocket 对象并执行原生方法。在回退模式下，该库将协议从 WS 更改为 HTTP，通过进行 HTTP GET 请求来监听消息，并使用 HTTP POST 请求发送消息。

### 注意

特定的 polyfill 解决方案只需要对我们的代码进行轻微修改。其他解决方案可能需要您进行大量修改，或者只能与特定的服务器后端一起使用。在将其用于生产之前，您需要密切关注每个插件的要求、使用方法和文档。

## 浏览器插件

在 HTML5 之前的富互联网应用程序中，浏览器插件是一个非常有用的解决方案。举几个例子，开发人员过去通常利用 Flash（主要是）、Silverlight 或 Java 的功能，在其网站上提供桌面丰富的功能。几年前，基本的 UX 效果、过渡和动画无法使用纯 HTML、CSS 或 JavaScript 来实现。

为了填补这一空白，浏览器插件为开发人员提供了一个可以安装在客户端浏览器中的框架，并允许更丰富的内容。

浏览器插件有一些缺点，使它们日益被淘汰。它们占用资源多，用户需要等待更长时间才能完全加载页面，而且它们大多基于专有技术。因此，越来越多的公司（包括苹果和微软）正在摒弃浏览器插件，转而支持 HTML5。

然而，如果您的用户使用旧版浏览器，他们很可能在旧的台式电脑上安装了一个或多个这样的浏览器插件。一些出色的 WebSocket 实现使用 Flash 来实现双向通信，之前提到的一些 polyfill 也是如此。

**websocket-as**，可在[`github.com/y8/websocket-as`](https://github.com/y8/websocket-as)找到，是一个流行的实用程序，用 ActionScript 编写，实现了类似 HTML5 方法的 WebSocket API。Microsoft 的 Silverlight 和 WCF 技术也有类似的例子([`www.codeproject.com/Articles/220350/Super-WebSockets-WCF-Silverlight-5`](http://www.codeproject.com/Articles/220350/Super-WebSockets-WCF-Silverlight-5))。

如果您熟悉 Flash 或 Silverlight，那么您可以基于您喜欢的浏览器插件实现一个回退解决方案。否则，您可以坚持使用 JavaScript 实现。

# 摘要

并非所有浏览器都原生支持 WebSocket 协议。因此，您需要为那些无法感知 HTML5 好处的用户提供一些备用解决方案。幸运的是，开源社区为我们提供了各种技术，使用纯 HTTP 或 Flash 内部模拟 WebSockets 的功能。实现 HTML5 和备用方案对于您的 Web 应用程序至关重要，并且与您想要触及的受众范围密切相关。在本章中，我们研究了一些流行的备用技术，并了解了如何处理 WebSocket 应用程序中的常见连接错误。这就是您需要了解的关于 WebSocket 和 HTML 部分的内容。在最后一章中，我们将从本地移动体验的角度来研究 WebSocket 协议。


# 第七章：进入移动（还有平板）

WebSockets，顾名思义，是使用网络的东西。网络通常与浏览器页面交织在一起，因为这是显示在线数据的主要手段。然而，非浏览器程序也使用在线数据传输。iPhone（最初）和 iPad（后来）的发布引入了一个全新的网络互联世界，而不一定需要使用网络浏览器。相反，新的智能手机和平板设备利用原生应用程序的力量提供了独特的用户体验。

# 为什么移动设备很重要

目前，全球有十亿部活跃的智能手机。也就是说，有数百万潜在的应用程序客户。这些人使用他们的手机来完成日常任务、上网、交流或购物。

智能手机已经成为应用程序的代名词，如今，几乎任何用途都有相应的应用程序。大多数应用程序连接到互联网以检索数据，进行交易，收集新闻等。

如果您能够利用现有的 WebSocket 知识并开发在智能手机或平板设备上本地运行的 WebSocket 客户端，那将是多么美妙啊！

## 原生移动应用与移动网站

嗯，这是一个常见的冲突，通常情况下，答案取决于您的需求和目标受众。如果您熟悉现代设计趋势，设计一个响应式和移动友好的网站现在是必须的。然而，您应该确保内容，也就是真正重要的东西，通过智能手机和经典桌面浏览器同样可以访问。

毫无疑问，WebSocket 网络应用程序将在任何符合 HTML5 标准的浏览器上运行，包括 iOS 的 Safari 和移动设备的 Chrome。因此，在现代智能手机上不需要担心兼容性问题。

然而，如果您的应用程序利用设备特定信息，如离线存储、GPS、通知或加速计，以及 WebSockets，您需要使用除 HTML 和 JavaScript 之外的更本地的实现语言。W3C 正在定义一些规范，让客户端可以访问摄像头、GPS 和加速计等硬件。然而，目前只有少数现代网络浏览器支持这些规范。在撰写本文时，本地方法是前进的道路，尽管客户端的未来似乎更加有趣！iOS 使用 Objective-C，Android 使用 Java，Windows Phone 使用 C#。如果您认为您的移动使用情景不需要利用智能手机的任何功能，可以选择基于浏览器的应用程序。如果需要原生功能，则需要原生解决方案。这正是我们将在本章中构建的内容！

## 先决条件

为了开发智能手机应用程序，您需要安装首选目标的开发工具和 SDK。我们将演示的示例背后的哲学在三大主要移动操作系统中基本相同，即 iOS、Android 和 Windows。

如果您尚未安装移动 SDK，请在以下位置选择一个（它们都是免费的）：

| 平台 | 目标 | SDK 网址 |
| --- | --- | --- |
| iOS | iPhone, iPad | [`developer.apple.com/devcenter/ios/`](https://developer.apple.com/devcenter/ios/) |
| Android | Android 手机和平板 | [`developer.android.com/sdk/`](http://developer.android.com/sdk/) |
| Windows | Windows Phone, Windows 8 | [`developer.windowsphone.com/ develop`](http://developer.windowsphone.com/ develop)&[`msdn.microsoft.com/ windows/apps`](http://msdn.microsoft.com/ windows/apps) |

我们假设您至少熟悉上述 SDK 和技术之一。如果不熟悉，您可以转到相应的开发者门户网站，并按照在线资源和教程进行操作，这将为您提供一个很好的起点。

在本章中，我们决定为 iOS 提供代码示例，但请随意使用您最熟悉的平台。

## 安装 SDK

下载所需的 SDK 后，您将按照自动化向导的步骤在系统中安装它。请注意，iOS SDK 只能在 Mac 操作系统上运行，Windows SDK 在 Windows 操作系统上运行，Android SDK 在 Mac、Windows 或 Linux 上运行。除了 SDK，还有一些自动安装的好东西：

+   智能手机/平板电脑模拟器

+   一个集成开发环境，您可以在其中编写和调试代码

尽管您应该始终在真实设备（手机和平板电脑）上测试代码，但模拟器是一个非常可靠的持续调试解决方案。

考虑到 iOS，这里有 iPhone 和 iPad 模拟器，运行 iOS 6。

下图显示了一个 iPhone 模拟器：

![安装 SDK](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/gtst-h5-ws-prog/img/6962OS_07_01.jpg)

下图显示了一个 iPad 模拟器：

![安装 SDK](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/gtst-h5-ws-prog/img/6962OS_07_02.jpg)

## 在移动浏览器中测试我们现有的代码

还记得我们在第二章中编写的 HTML 和 JavaScript 代码吗，*WebSocket API*？安装了 SDK 和模拟器后，我们可以使用模拟器中包含的移动浏览器访问网络。我们还可以访问本地的 HTML、CSS 和 JavaScript 文件，而无需将它们上传到 Web 服务器。这是一个在 iPad 上运行良好的聊天客户端。

以下图片显示了 Safari 上的 iOS WebSocket web 应用（代码没有修改）：

![在移动浏览器中测试我们现有的代码](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/gtst-h5-ws-prog/img/6962OS_07_03.jpg)

# 使用原生方式

那么，如果您的应用程序支持特定设备或离线功能，并且仍希望在网络可用时使用 WebSockets 呢？

您可以使用原生方式。

幸运的是，所有主要的移动平台都支持 WebSockets，因此您无需对服务器代码进行任何更改！毕竟，HTML5 就像 iPhone 或 iPad 一样是一个前端客户端。使用与 JavaScript 示例相同的技术，您将使用 Objective-C 构建相同的应用程序。这个过程与任何其他移动平台类似，所以如果您对 Objective-C 概念不熟悉，也不用担心。

## 创建项目

首先，打开**XCode**，这是苹果提供的用于构建 iOS 应用的开发环境。Eclipse 和 Visual Studio 是 Android 和 Windows 的等价物。

按照给定的步骤创建项目

1.  启动 XCode，然后点击**创建新的 XCode 项目**。以下截图显示了 XCode 的启动画面：![创建项目](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/gtst-h5-ws-prog/img/6962OS_07_04.jpg)

1.  创建一个单视图应用程序。提供一个名称，以及公司和组织标识符（如果需要）。例如，将应用程序命名为`WebSocketsMobile`。然后，选择一个本地文件夹放置它，如下图所示：![创建项目](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/gtst-h5-ws-prog/img/6962OS_07_05.jpg)

## 创建 WebSocket iPhone 应用

如果您需要为生产部署应用程序，还需要为目标平台指定一些图标。我们现在将跳过这些内容，但请随意添加应用程序可能需要的任何资源。XCode 会自动为我们创建一些文件。故事板文件（一个用于 iPhone，一个用于 iPad）将让我们创建应用程序的用户界面，`ViewController`文件将处理所有编程逻辑。

以下截图显示了我们 iPhone 应用的初始 UI：

![创建 WebSocket iPhone 应用](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/gtst-h5-ws-prog/img/6962OS_07_06.jpg)

1.  在用户界面构建器中添加一些控件。为了学习目的，我们将尽量保持简单，只添加一个用于编写消息的`UITextField`，一个用于发送消息的按钮，以及一个用于显示聊天消息的`UILabel`。记得将标签的行数设置为 0（即无限）。不要忘记使用助理编辑器将输出连接到**视图控制器**，（[`www.techotopia.com/index.php/Establishing_Outlets_and_Actions_using_the_Xcode_Assistant_Editor).`](http://www.techotopia.com/index.php/Establishing_Outlets_and_Actions_using_the_Xcode_Assistant_Editor).)下面的截图显示了 iPhone 应用程序的用户界面：![创建 WebSocket iPhone 应用程序](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/gtst-h5-ws-prog/img/6962OS_07_07.jpg)

1.  下载`UnittWebSocketClient`库并将其包含在项目中。该库处理大部分 WebSocket 功能。您可以选择另一个库或者实现自己的库。按照[`code.google.com/p/unitt/wiki/UnittWebSocketClient`](https://code.google.com/p/unitt/wiki/UnittWebSocketClient)中指定的方向进行操作。

1.  在项目中包含库的头文件，并将您的视图控制器指定为`WebSocketDelegate`。然后订阅相应的事件，这些事件与 JavaScript 的事件相同：

```js
// ViewController.h

#import <UIKit/UIKit.h>
#import "WebSocket.h"
@interface ViewController : UIViewController <WebSocketDelegate>
@end

// ViewController.m

#import "ViewController.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad
{
  [super viewDidLoad];
}

- (void)didReceiveMemoryWarning
{
  [super didReceiveMemoryWarning];
}

- (void)didOpen
{
  // JavaScript event: onopen
}

- (void)didClose:(NSUInteger)aStatusCode message:(NSString *)aMessage error:(NSError *)aError
{
  // JavaScript event: onclose
}

- (void)didReceiveError:(NSError *)aError
{
  // JavaScript event: onerror
}

- (void)didReceiveTextMessage:(NSString *)aMessage
{
  // JavaScript event: onmessage
}

- (void)didReceiveBinaryMessage:(NSData *)aMessage
{
  // JavaScript event: onmessage
}

@end
```

1.  现在是时候填充方法了，就像我们在 JavaScript 示例中所做的那样。以下是设置应用程序并运行所需做的事情：

```js
// ViewController.h

@interface ViewController : UIViewController <WebSocketDelegate>
{
  // Create a new WebSocket object.
  WebSocket *socket;
}

// ViewController.m

- (void)viewDidLoad
{
  [super viewDidLoad];

  // Specify the WebSocket configuration. The only necessary parameter is the URL.
  WebSocketConnectConfig *config = [WebSocketConnectConfig
    configWithURLString:@"ws://echo.websocket.org"
    origin:nil protocols:nil tlsSettings:nil headers:nil
      verifySecurityKey:YES extensions:nil];

  // Initialize the WebSocket object.
  socket = [WebSocket webSocketWithConfig:config
    delegate:self];

  // Open the WebSocket connection and start listening for
    events.
  [socket open];
}

- (void)didReceiveTextMessage:(NSString *)aMessage
{
  // JavaScript event: onmessage

  labelChat.text = [NSString stringWithFormat:@"%@\r%@",
    labelChat.text, aMessage];
}

- (IBAction)sendTapped:(id)sender
{
  [socket sendText:textMessage.text];
}
```

下图显示了本机 iOS WebSocket 客户端正在运行！

![创建 WebSocket iPhone 应用程序](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/gtst-h5-ws-prog/img/6962OS_07_08.jpg)

# iPad 怎么样呢？

虽然您创建的应用程序在 iPad 设备上运行得很好，但最好为平板提供不同的界面。只需转到`MainStoryboard_iPad.storyboard`文件，重新排列 UI 元素，并提供特定于平板的功能。然后，选择项目目标，在摘要选项卡中展开`iPad 部署信息`选项，并确保选择了`MainStoryboard_iPad`。如果您的应用程序不太复杂，可以选择 iPhone storyboard，或者指定应用程序目标仅为 iPhone。这样，当有人在 iPad 设备上运行您的应用程序时，他/她将在 iPad 设备上看到一个居中显示的较小屏幕。

# 摘要

在本章中，我们发现了 WebSockets 如何可以作为在连接的移动和平板客户端之间传输消息的通用枢纽。我们实现了一个原生的 iOS 应用程序，它与一个 WebSocket 服务器进行通信，就像 HTML5 JavaScript 客户端一样。


# 附录 A. 附录

在一本书中不可能涵盖所有内容。有些事情是故意或者无意中被遗漏的。因此，这里有一些额外的主题，让您可以更深入地了解 WebSocket 世界。

# 资源

WebSocket API 正在不断扩展。为了跟上即将到来的变化，这里有一些在线资源，您可以收藏以供进一步阅读。

## 在线资源

以下网站提供有关 WebSocket 协议、应用程序和实际示例的最新内容。看看它们，保持关注，并收藏您最喜欢的网站。

| WebSocket.org | [`www.websocket.org/`](http://www.websocket.org/) |
| --- | --- |
| Web 平台文档 | [`docs.webplatform.org/wiki/apis/websocket/WebSocket`](http://docs.webplatform.org/wiki/apis/websocket/WebSocket) |
| HTML5 rocks | [`www.html5rocks.com/en/features/connectivity`](http://www.html5rocks.com/en/features/connectivity) |
| HTML5 演示 | [`html5demos.com/`](http://html5demos.com/) |
| Mozilla Developer Network | [`developer.mozilla.org/en-US/docs/WebSockets`](https://developer.mozilla.org/en-US/docs/WebSockets) |
| WebSockets API (W3C) | [`www.w3.org/TR/2009/WD-websockets-20091222/`](http://www.w3.org/TR/2009/WD-websockets-20091222/) |

## 文章

需要更多思考？这些文章提供了知名博客作者的个人观点。您甚至会阅读到有争议的主题，但您肯定会发现在网络行业中没有黑白之分。

| WebSockets 与 REST…战斗！ | [`nbevans.wordpress.com/2011/12/16/websockets-versus-rest-fight/`](http://nbevans.wordpress.com/2011/12/16/websockets-versus-rest-fight/) |
| --- | --- |
| HTML5 WebSocket 速查表 | [`refcardz.dzone.com/refcardz/html5-websocket`](http://refcardz.dzone.com/refcardz/html5-websocket) |
| 您会让您的祖母使用 WebSockets 吗？ | [`community.qualys.com/blogs/securitylabs/2012/08/15/would-you-let-your-grandma-use-websockets`](https://community.qualys.com/blogs/securitylabs/2012/08/15/would-you-let-your-grandma-use-websockets) |
| 您的用户不在乎您是否使用 WebSockets | [`www.hanselman.com/blog/YourUsersDontCareIfYouUseWebSockets.aspx`](http://www.hanselman.com/blog/YourUsersDontCareIfYouUseWebSockets.aspx) |
| WebSockets 和未完成标准的风险 | [`news.cnet.com/8301-30685_3-20025272-264.html`](http://news.cnet.com/8301-30685_3-20025272-264.html) |

# 源代码

我们在本书中演示的源代码可以在[`pterneas.com/books/websockets/source-code`](http://pterneas.com/books/websockets/source-code)上找到。请注意，给定的链接将始终保持最新，遵循当前的趋势和标准。

您可以随意下载和修改所有包含的文件。

## 系统要求

Web 标准是一种跨平台机制。这意味着客户端源代码将在任何符合 HTML5 标准的浏览器上运行。您只需要一个文本编辑器，如记事本或 GEdit 来修改文件。

服务器端代码已在 Windows 中进行了测试，尽管您可以在支持 Mono 框架的任何操作系统上运行它([`www.mono-project.com/`](http://www.mono-project.com/))。最后，关于 iOS 源代码，您需要一台 Mac 电脑，以及 XCode 开发环境。

请记住，您可以使用您选择的操作系统、服务器端库和集成开发环境来构建自己的项目。主要逻辑和功能保持不变。

## 保持联系

发现错误或有任何更改建议？我们很乐意听取您的反馈，并尽快解决任何问题。只需将您的消息发送至`<vangos@pterneas.com>`。
