# WebSocket 基础知识（一）

> 原文：[`zh.annas-archive.org/md5/B169597DE295933B6F244191B5501868`](https://zh.annas-archive.org/md5/B169597DE295933B6F244191B5501868)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

HTML 是 Web 开发中最重要的部分，但在某些方面存在不足，但现在开发人员因其增强和功能而重新转向 HTML5，为他们提供了全新的开发体验。不同浏览器上的 WebSocket 支持使得使用许多功能开发 Web 应用程序变得更加容易。

客户端和服务器之间的数据通信是任何 Web 应用程序中最重要的部分之一。几乎所有浏览器都支持 WebSockets，这使得它更加强大和可用。开发人员总是希望在坚实的基础上构建他们的应用程序，以便为用户提供可靠的应用程序。现在 WebSocket 使这成为可能。随着 HTML5 的增强，它在社区中得到了广泛的接受和赞赏。

本书将让您了解如何使用 HTML5 的 WebSockets 创建出色的应用程序，特别是需要从客户端和服务器端推送数据的应用程序。通过本书中我们将创建的一些基本示例应用程序，您将了解如何设置客户端以及如何轻松创建基于 Node.js 的 WebSocket 服务器。

本书适用于希望学习创建基于 WebSocket 的应用程序的开发人员。它为您提供了实现使用 WebSockets 进行通信的不同方面的真实场景。它易于学习，易于理解。

# 本书涵盖的内容

第一章 *介绍 Web 应用程序的世界*，是对 Web 应用程序的介绍，涵盖了 Web 的基础知识。本章介绍了 HTML5 及其新特性和 WebSockets。

第二章 *开始使用 WebSockets*，深入介绍了 WebSockets，包括 WebSockets 的好处以及如何创建示例应用程序。在这里，您将学习如何使用 Node.js 平台创建自己的基本 WebSocket 服务器。

第三章 *配置服务器和实时数据传输*，展示了如何使用 WebSockets 在连接到服务器的不同用户之间发送数据。本章还涵盖了使用 JavaScript 库创建应用程序，以共享演示文稿并在不同用户之间协作更改幻灯片。

第四章 *在实际场景中使用 WebSockets*，演示了另一个应用程序，以更多地解释 WebSockets 如何在现实场景中使用。本章还讨论了 JavaScript 框架及其用途。

第五章 *移动和平板电脑的 WebSockets*，介绍了 WebSockets 在移动设备上的行为，移动 WebSockets 的不同库，在 Android 手机上运行服务器以及使用 Express.js 包从服务器内部提供内容。

第六章 *使用现代工具增强 HTML5 Web 应用程序开发*，解释了可以用于增强 Web 应用程序开发的不同工具和技术。本章介绍了使用不同工具加快开发速度，如编辑器、包管理器、版本控制、样板、应用程序框架、响应式 Web 设计等。

# 本书所需内容

您需要一台安装了现代浏览器的计算机，主要是支持 WebSockets 和 HTML5 的浏览器。您还需要一个文本编辑器，如 Sublime Text。此外，如果您没有安装 Node.js，则需要安装 Node.js。

要检查您的浏览器是否支持 WebSockets 和 HTML5，请访问[`www.caniuse.com`](http://www.caniuse.com)。

# 本书适合对象

本书适用于具有 HTML 和 JavaScript 基础知识的 Web 开发人员。它专注于实现不同的应用程序，并为开发人员提供实践经验。这是一本快速的书，它为您提供了开发基于 WebSocket 的应用程序所需的工具和技术。

# 约定

在本书中，您会发现一些区分不同信息类型的文本样式。以下是一些示例以及它们的含义解释。

文本中的代码单词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 用户名显示如下：“在这里，`Host`是我们正在访问的服务器的名称。”

代码块设置如下：

```js
<html>

<head>
<meta charset="utf-8" >
<title>WebSocket Test</title>
<script language="javascript" type="text/javascript">
var wsUri = "ws://echo.websocket.org/";
var output;
```

**新术语**和**重要单词**以粗体显示。屏幕上看到的单词，例如菜单或对话框中的单词，会以这种方式出现在文本中：“在左侧窗口中查看**控制台**日志。”

### 注意

警告或重要说明会出现在这样的框中。

### 提示

提示和技巧会以这种方式出现。


# 第一章：介绍网络应用程序的世界

HTML5 和 WebSockets 使网络应用程序开发达到了新的水平。网络开发技术的革命性改进为开发人员提供了现代工具和技术。使用 WebSockets，他们可以创建不仅可以从客户端发送数据，还可以从服务器端发送数据的网络应用程序。使用实时数据传输的网络应用程序可以以更低的带宽使用率创建。通过补充 HTML5 增强功能，WebSockets 可以使未来的应用程序更加强大。在深入了解 WebSockets 之前，让我们先了解网络的基础知识。

# 什么是网络？

网络的基础是在八十年代末奠定的。网络是通过互联的超文本文档工作的，我们可以使用互联网访问它们。浏览器在阅读和转换这些超文本文档成为可读和更有意义的格式方面发挥着至关重要的作用，我们称之为网页。HTML5 是浏览器读取和呈现给我们的超文本文档。浏览器不仅读取和呈现，还为我们创建了**文档对象模型**（**DOM**），以便我们可以轻松地阅读和操作结构。DOM 的动态操作可以通过 JavaScript 语言实现，这是 HTML 的标准脚本语言。服务器在网络的运作中起着至关重要的作用。我们主要认为网络分为两部分：客户端和服务器。客户端被认为是浏览器，而服务器是给客户端提供数据的一方。

让我们看看网络是如何工作的：

1.  浏览器从服务器请求 URL。

1.  服务器检查并返回 HTML 文件。

1.  浏览器引擎绘制页面。

简而言之，这就是网络的工作原理。浏览器和服务器是网络中最重要的实体。浏览器有引擎来读取 HTML 文件，并以 HTML 文件描述的方式呈现网络应用程序。不同的浏览器，如 Blink、Trident、Gecko、WebKit 等，有不同的引擎来呈现页面的 HTML。现在服务器是存储所有数据并在用户请求时提供数据的一方。

# 网络应用程序

在网络的早期，页面是静态的。它们只用于显示最少的交互和功能性内容。但随着网络标准的进步，计算机的发展，高效的浏览器，增强的工具和库，创建网络应用程序现在变得非常容易，许多功能可以很快地添加进去。

这里有一个简单的网络应用程序定义 - 任何在浏览器上运行的应用程序都是网络应用程序。我们在日常生活中使用许多网络应用程序来检查邮件，阅读新闻，观看视频等。网络应用程序在您的浏览器中运行，不需要太多的计算机资源。

网络正在以非常快的速度增长。许多公司正在网络上构建他们的应用程序。第一个和最重要的好处是它独立于操作系统。您可以在 Windows、Mac 或 Linux 上运行它，它的工作方式是相同的，因为工作主要由浏览器完成，并且它们适用于大多数操作系统。

以下是一些网络应用程序的示例：

+   Gmail

+   Dropbox

+   Flickr

+   Facebook

# WebSockets 的作用是什么？

我们已经看到了一些 Web 应用程序的例子，现在问题是 WebSockets 在这些应用程序或任何 Web 应用程序中的位置在哪里？让我们首先了解一些应用程序行为；让我们以 Gmail 为例，它基本上是一个邮件客户端。邮件客户端的工作是获取邮件并显示它们。这听起来很简单，但当有人给你发送一封邮件，你希望立即显示该邮件时，问题就出现了。为了实现这样的功能，有不同的方式，如轮询和长轮询，这些方式都不高效。因此，WebSockets 通过提供服务器推送功能来解决这个问题。WebSockets 提供了从客户端和服务器端推送的功能，这使它脱颖而出。

WebSockets 具有一些良好的特性和优点，超过了其他通信方法。WebSockets 的一些特性和优点包括：

+   全双工通信

+   低带宽消耗

+   安全性

+   低延迟

+   在传输控制协议（TCP）上运行（尽管它需要 HTTP 进行初始握手）

+   几乎所有的网络浏览器和服务器都支持，包括移动浏览器

我们可以将 WebSockets 视为增强 Web 应用体验的功能。借助 HTML5 增强的功能，我们可以创建动态和实时的应用程序。

# WebSockets 相对于其他方法

有不同的方式来实现客户端和服务器之间的数据通信。Flash，Comet，PusherApp 等都提供了 WebSockets 所需的功能。那么问题来了，为什么我们要选择 WebSockets 呢？有很多原因可以选择 WebSockets 而不是其他方法，其中一些原因如下：

+   与其他数据通信方式相比，WebSockets 表现出低延迟，从近 150 毫秒减少到 50 毫秒。

+   WebSockets 是一种轻量级连接，使用带宽较低。

+   在学习和实施不同技术方面，需要更少的开发人员工作量。

+   在使用不同技术时编译更容易。

+   使用 WebSockets 可以轻松进行代码维护。

+   WebSockets 提供了全双工连接支持，而没有太多的开销。

# 现代浏览器

现代浏览器配备了先进的功能，以支持 Web 应用程序。

Web 应用程序具有许多不同的功能，为了支持这些功能，我们需要的不仅仅是普通的浏览器，而是现代浏览器。为了支持 HTML5 提供的高级功能，现代浏览器必须实现 HTML5 标准，因为它具有最新的功能和功能。有一些浏览器的版本不支持 HTML5，主要是因为它们没有实现 HTML5 标准，要么是因为它们是早期开发的，要么是因为它们选择不支持。

现代浏览器的一些优势如下：

+   良好的性能

+   良好的安全性

+   问题更少

+   页面加载更快

+   实验性的应用程序编程接口或 API

+   支持最新的功能

+   访问本机资源

# HTML

HTML 是一种标记语言，用于浏览器呈现网页。这是由万维网联盟（W3）制定的标准。这个标准有一些定义的元素，不同的浏览器实现了这些元素。

# HTML5-现代 Web 标准

在八年的 HTML5 标准制定工作之后，W3 于 2014 年 10 月 28 日最终确定了这一标准。这个标准将对未来的网络产生革命性的影响。对 HTML 标准的增强是革命性的。让我们来看看 HTML5 的主要特性，使其成为 Web 的一个伟大标准：

## 媒体-音频/视频

HTML5 标准引入的一个重要功能是媒体播放。现在我们可以直接使用浏览器播放音频/视频。以前，我们需要使用一些插件来播放音频和视频，这为我们的网络应用程序增加了另一层。例如，YouTube 使用 Flash 播放器播放视频，但现在我们可以直接播放视频。这个功能对完全使用 HTML 构建的应用程序来说是一个更大的优势。

除了播放音频和视频之外，我们还可以捕获设备的音频和视频资源。可以使用`getUserMedia()` API 来访问摄像头和麦克风，但由于它是一个实验性功能，因此并不是所有浏览器都支持它；但这是一个非常需要的功能。这个 API 不仅可以访问台式电脑，还可以访问移动设备和平板电脑上的摄像头和麦克风。这是另一个将消除对媒体访问和捕获的不同插件的依赖的功能。

## Canvas

Canvas 允许您在运行时以每个像素的方式进行操作。因此，您可以绘制形状，渲染图形，着色，操作它们，甚至以每个像素操作位图图像，以及许多其他功能。Canvas 功能使我们在绘制和制作网络应用程序方面具有优势，就像 Microsoft Paint（以前的 Microsoft Paintbrush）或 Adobe Photoshop 一样。

Canvas 元素具有一组不同的方法，可以使用线条、圆圈、框、文本、图形等来创建绘图。JavaScript 用于在画布容器中绘制。

## 表单元素

表单元素中有许多增强功能，可以帮助我们为用户创建出色的体验，并且从开发人员的角度来看易于管理。验证以前是一个大问题；我们不得不为此编写自己的代码，但现在它是元素的一部分。有一些增强功能是为移动设备而设计的，例如字段类型键盘，例如专门用于数字字段的键盘。一些新元素包括：

+   **Input**：以下是输入类型：

+   `type="email"`：具有内置电子邮件验证器的字段

+   `type="url"`：具有内置 URL 验证器的字段

+   `type="number"`：具有内置数字输入限制和验证器的字段

+   `type="range"`：具有最大和最小功能的范围滑块

+   **Datalist**：它指定了列表控件的预定义选项列表。

+   **Keygen**：该元素使用公钥/私钥方法提供安全数据提交。从安全性的角度来看，这是一个很好的增强功能。

+   **Output**：这个元素有助于在填写表单时显示输出值。

## 语义

语义是具有含义的元素。每个开发人员都希望用易于理解和实现的语言编码。语义是使代码更易于阅读和理解的因素，因为它定义了该元素或标记的含义。语义元素的一些示例包括`<audio>`、`<video>`、`<form>`和`<table>`。非语义元素的示例包括`<div>`和`<span>`。从这些示例中我们可以看出，非语义元素并没有告诉我们有关内容，而语义元素清楚地告诉我们有关内容。

HTML5 中的一些新语义如下：

+   `<section>`

+   `<nav>`

+   `<article>`

+   `<aside>`

+   `<hgroup>`

+   `<header>`

+   `<footer>`

这些新元素的添加将有助于使代码更易读和有意义。现在让我向您介绍自定义元素。是的，现在我们可以使用 JavaScript 制作自己的自定义元素，可以从头开始创建它们，也可以通过向 DOM 元素的默认集合添加新行为来扩展它们。这样，我们可以创建不同的可重用网络组件集，并在整个网络应用程序中使用它们。这个功能为代码增加了意义，并且对于大型应用程序来说，制作可重用的网络组件是一个巨大的优势。

## 首先移动

HTML5 和 CSS3 标准是为移动设备而制定的。有许多增强功能可以优化移动/平板设备的代码。手机已经发展到一个程度，已经成为我们日常生活的一部分。我们已经开始更多地在移动/平板设备上浏览互联网。HTML5 已经赋予 Web 很多力量，以满足现代 Web 的需求。HTML5 和 CSS3 具有一些出色的功能，可以为所有设备提供相同的内容：台式机、移动设备和平板电脑。一些重要的功能包括以下内容：

+   **视口**：这有助于根据设备调整网页的视图。我们可以设置不同的缩放级别等。

+   **媒体查询**：根据屏幕大小的 CSS；这不是一个很棒的功能吗？现在通过使用媒体查询，CSS 样式可以在运行时更改。响应式网页设计是现代 Web 的一个非常重要的特性。我们需要根据屏幕大小显示内容，并且它应该适应并显示适当的内容，消除页面上对于较小设备来说不那么重要的内容。

+   **触摸事件**：这些对于移动/平板设备非常重要。**滑动**是现在 HTML5 DOM 的重要事件之一。

## 离线存储

世界正在不断涌现出不同的技术，我们广泛使用在线和网络服务，以创建一个有效的工作空间和一个满足我们专业和个人需求的网络世界。有些情况下，您需要网站在离线状态下也能访问，即在设备上没有活动的互联网连接。这可以通过使用离线存储功能来实现。一旦您打开了一个网页，就可以将数据放入缓存，这样下次您打开它，或者由于某种原因您的连接丢失，您仍然可以打开并使用它。

当数据需要本地存储时，离线系统非常重要，特别是当系统处于离线模式时需要重新加载或恢复页面时。

因此，每当我们打开一个 URL 时，它基本上会访问服务器，然后服务器返回请求的文件。然后，浏览器呈现服务器提供的文件。现在，如果我们处于离线状态，浏览器将接管控制，而不是访问服务器获取文件，它会从先前打开时缓存的本地副本中加载文件。还有一个 API 可以告诉我们是在线还是离线。在移动/平板设备的情况下，这非常有帮助，因为连接可能随时丢失。

## 地理定位

有许多应用程序使用地理定位，如 Twitter、Facebook、Foursquare、Google Maps 等。将此功能作为 HTML5 的一部分引入，使开发人员更容易获取其设备的位置。

移动和平板设备具有**全球定位系统**（**GPS**），并且可以使用此 API 访问设备的硬件。让我们以一个应用程序为例，您想要找到附近的酒店。使用 GPS，可以检测到您的位置，并提供附近酒店的相应列表。这个功能减少了开发人员在实现与地理定位相关的功能方面的工作。是的，这是一个需要用户许可才能工作的功能。用户会收到提示，允许 Web 应用程序访问他们的位置详情。

## 拖放

拖放是一个一直存在的功能，但只能使用一些插件来实现。好消息是现在它是 HTML5 标准的一部分。通过利用这个功能，可以定义许多新的控件，因为我们还有自定义语义功能，可以用来定义我们自己的自定义控件。

网络应用程序使用许多不同的控件或小部件以更加用户友好的方式显示数据。对于大规模应用程序，列表和网格是显示数据最重要的控件，拖放起着非常重要的作用。显示日历或项目时间表的控件需要拖放功能，以使其更易用。一些基本的交互包括：

+   在列表中重新排列项目

+   从一个列表中移动项目到另一个列表

+   重新排列布局

+   在画布上拖动项目

+   从计算机拖动文件到浏览器

有许多很好的拖放功能的例子。不同的公司已经实现并制作了自己的组件库，其中实现了拖放功能。一些例子包括 Sencha、jQueryUI、KineticJS、Kendo UI 等。

## Web workers

Web workers 只是在后台运行的 JavaScript。JavaScript 主要用于在运行时操作网页的 HTML，并且只使用一个主线程。Web workers 使得在后台运行一段 JavaScript 代码而不影响当前进程成为可能。通常，每当我们在 JavaScript 中运行一个进程时，它以队列方式运行，这意味着一次只执行一个进程。它会在一段时间内阻塞整个 UI，你也无法点击按钮。这对应用程序的性能产生了巨大影响。这也是为什么更大的网络应用程序在选择 HTML 时犹豫不决的原因之一，但是 Web workers 肯定会改变这一点。

## JavaScript

HTML 页面是静态的；为了使它们动态和交互，使用 JavaScript。JavaScript 被称为 Web 的语言。它基于**ECMAScript**，每个浏览器都运行 JavaScript。从点击按钮、导航到页面、调用服务等所有交互都是由 JavaScript 完成的。

有许多使用 JavaScript 构建的框架，以使脚本编写更加容易：其中一个主要使用的框架是 jQuery。它为用户提供了以可读和有意义的方式使用 DOM 事件、功能和 API 的灵活性。

## 现代服务器

JavaScript 正在快速改进。大多数开发人员现在都在使用 JavaScript 进行客户端处理。**Node.js**服务器的引入改变了开发人员的工作范围。以前，开发人员使用不同的服务器，为此他们不得不学习许多不同的语言。Node.js 消除了这一差距，并为开发人员提供了一个基于 JavaScript 的构建服务器的平台。

建立在 Node.js 平台上的 JavaScript 服务器非常简单易用，也提高了生产力。开发人员可以在很短的时间内创建一个服务器并运行它。在 Node.js 中创建服务器非常容易，并且具有许多功能，例如使用不同的可用包进行实时数据传输。有许多为 Node.js 构建的框架，例如**Express.js**，它有助于加快开发过程。

Node.js 是免费平台，并提供许多可以自由分发的不同包。**Node** **Package Manager** (**NPM**)管理应用程序的依赖关系。它也是一个版本管理器。

## WebSockets

随着网络应用程序的增长，对支持全双工通信的实时数据的需求也在增加。实时通信一直很难实现，人们过去使用 Flash 来实现这一点。之所以使用类似 Flash 的插件，是因为这一功能在 HTML 标准中缺失。所以每当我们想在 HTML 中实现这样的机制时，我们使用轮询机制，这在性能方面是非常昂贵的过程。

HTML5 已经准备好了所有需要的功能，以满足良好的网络应用程序的需求。WebSockets 是 HTML5 标准的一部分，WebSocket API 完全可供利用。

WebSockets 为客户端和服务器之间提供了全双工通信，基本上允许数据在需要时轻松传输，而不像轮询机制那样在间隔上不断向服务器发送请求以检查变化。WebSockets 可以从服务器或客户端发送数据，基本上打开了一个连接桥，允许双方进行数据传输。WebSockets 已经消除了使用第三方插件的需求，使 HTML 开发人员能够直接使用 WebSockets API 进行实现。

# 总结

在本章中，我们已经了解了现代 Web 的重要元素，以及 HTML5 标准带给我们的增强功能。我们已经介绍了 WebSockets，在下一章中，我们将看到 WebSockets 在客户端和服务器端的实现。


# 第二章：使用 WebSockets 入门

客户端服务器通信是任何 Web 应用程序中最重要的部分之一。 服务器和客户端之间的数据通信必须平稳快速，以便用户可以获得出色的体验。 如果我们研究传统的服务器通信方法，我们会发现这些方法是有限的，而且并不是真正的最佳解决方案。 这些方法已经被人们使用了很长一段时间，并且使 HTML 成为数据通信的第二选择。

# 为什么要使用 WebSockets？

为什么我们需要 WebSockets 的答案在于这个问题——其他通信方法存在什么问题？ 用于服务器通信的一些方法是请求/响应，轮询和长轮询，已经解释如下：

+   请求/响应：这是一种常用的机制，其中客户端请求服务器并获得响应。 这个过程是由一些交互驱动的，比如网页上按钮的点击来刷新整个页面。 当 AJAX 出现时，它使网页动态化，并帮助加载网页的某些部分而不加载整个页面。

+   轮询：有些情况下，我们需要在没有用户交互的情况下反映数据，比如足球比赛的比分。 在轮询中，数据在一段时间后被获取，并且它不断地向服务器发送请求，无论数据是否已更改。 这会导致不必要的对服务器的调用，每次都打开连接然后关闭连接。

+   长轮询：基本上是在特定时间段内保持打开的连接。 这是实现实时通信的一种方式，但仅当您知道时间间隔时才有效。

这些方法的问题导致了解决方案，即 WebSockets。 它解决了在使用旧方法时遇到的所有问题。

# WebSockets 的重要性

WebSockets 出现来拯救我们摆脱旧的服务器通信方法。 WebSockets 通过提供全双工的双向通信桥解决了服务器通信的最大问题之一。 它为服务器和客户端提供了在任何时间点发送数据的能力，这是任何旧方法都无法提供的。 这不仅提高了性能，还减少了数据的延迟。 它创建了一个轻量级的连接，我们可以长时间保持连接而不牺牲性能。 它还允许我们在任何时间点完全控制打开和关闭连接。

WebSockets 是 HTML5 标准的一部分，因此我们不需要担心添加额外的插件来使其工作。 WebSockets API 完全由 JavaScript 支持和实现。 几乎所有现代浏览器现在都支持 WebSockets； 可以使用网站[`caniuse.com/#feat=websockets`](http://caniuse.com/#feat=websockets)进行检查，该网站给出以下截图：

![WebSockets 的重要性](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ws-ess/img/B03854_02_01.jpg)

WebSockets 需要在客户端和服务器端都实现。 在客户端，API 是 HTML5 的一部分。 但是在服务器端，我们需要使用实现 WebSockets 的库。 现在有许多——或者我们可以说几乎所有——支持 WebSockets API 库的服务器。 Node.js 是一个现代的基于 JavaScript 的平台，也支持使用不同包实现基于 WebSockets 的服务器，这使得开发人员可以轻松编写服务器和客户端代码，而无需学习另一种语言。

# 何时使用？

WebSockets 作为客户端和服务器之间非常强大的通信方式，对于需要大量服务器交互的应用程序非常有用。 由于 WebSockets 使我们能够实现实时通信的好处，因此需要实时数据传输的应用程序，如聊天应用程序，可以利用 WebSockets。 它不仅用于实时通信，还用于只需要服务器向客户端推送数据的情况。

当我们知道其使用目的时，可以决定使用 WebSockets。当我们只需创建一个具有静态页面和几乎没有交互的网站时，不应使用 WebSockets。我们应该在客户端和服务器之间的数据传递方面使用 WebSockets。

有许多应用程序，如股票应用程序，其中数据保持实时更新。协作应用程序需要实时数据共享，例如国际象棋游戏或乒乓球游戏。WebSockets 主要用于实时游戏 Web 应用程序。

# 它是如何工作的？

WebSockets 使用 TCP 层进行通信。连接是通过 HTTP 建立的，基本上是客户端和服务器之间的握手机制。握手后，连接升级为 TCP。让我们通过这个流程图看看它是如何工作的：

![它是如何工作的？](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ws-ess/img/B03854_02_02.jpg)

以下步骤将带您完成前面图表中显示的流程：

1.  第一步是从客户端发起的 HTTP 调用；HTTP 调用的标头如下所示：

```js
GET /chat HTTP/1.1
Host: server.example.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw==
Sec-WebSocket-Protocol: chat, superchat
Sec-WebSocket-Version: 13
Origin: http://example.com

```

+   在这里，`Host`是我们正在访问的服务器的名称。

+   “升级”显示这是一个升级调用，这种情况下是 WebSockets。连接定义了这是一个升级调用。

+   `Sec-Websocket-Key`是一个随机生成的密钥，用于验证响应。这是握手的认证密钥。

+   `Origin`也是另一个重要的参数，显示调用的来源；在服务器端，它用于检查请求者的真实性。

1.  一旦服务器检查了真实性，就会发送回复，看起来像这样：

```js
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: HSmrc0sMlYUkAGmm5OPpG2HaGWk=
Sec-WebSocket-Protocol: chat

```

+   在这里，`Sec-WebSocket-Accept`有一个密钥，解码并与发送的密钥进行检查，以确认响应是否来自正确的发起者。

1.  因此，一旦连接打开，客户端和服务器就可以彼此发送数据。

1.  数据以小数据包的形式使用 TCP 协议发送。这些调用不是 HTTP，因此在浏览器的开发者工具的网络选项卡下不会直接显示。

# WebSocket API

WebSockets 标准由 W3 定义。WebSockets 的 API 接口如下所示：

```js
enum BinaryType { "blob", "arraybuffer" };

[Constructor(DOMString url, optional (DOMString or DOMString[]) protocols), Exposed=Window,Worker]

interface WebSocket : EventTarget {

  readonly attribute DOMString url;

  // ready state

  const unsigned short CONNECTING = 0;
  const unsigned short OPEN = 1;
  const unsigned short CLOSING = 2;
  const unsigned short CLOSED = 3;
  readonly attribute unsigned short readyState;
  readonly attribute unsigned long bufferedAmount;

  // networking

           attribute EventHandler onopen;
           attribute EventHandler onerror;
           attribute EventHandler onclose;
  readonly attribute DOMString extensions;
  readonly attribute DOMString protocol;

  void close([Clamp] optional unsigned short code, optional DOMString reason);

  // messaging
           attribute EventHandler onmessage;
           attribute BinaryType binaryType;
  void send(DOMString data);
  void send(Blob data);
  void send(ArrayBuffer data);
  void send(ArrayBufferView data);

};
```

我们可以从接口中看到 WebSockets API 提供的准备状态、网络事件和消息类型。

### 提示

**下载示例代码**

您可以从[`www.packtpub.com`](http://www.packtpub.com)的帐户中下载您购买的所有 Packt Publishing 图书的示例代码文件。如果您在其他地方购买了这本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，直接将文件发送到您的电子邮件。

## 准备状态

以下是准备状态：

+   **CONNECTING**：连接尚未建立。

+   **OPEN**：WebSockets 连接已建立，可以进行通信。

+   **CLOSING**：连接正在进行关闭握手或已调用`close()`方法。

+   **CLOSED**：连接已关闭或无法打开。

## 事件

以下是触发的事件：

+   **onopen**：当连接打开时触发。

+   **onclose**：当连接关闭时触发。

+   **onerror**：遇到错误时触发。

+   **onmessage**：当从服务器接收到消息时触发。

# 回声测试

让我们从**回声测试**应用程序开始。转到 URL [`www.websocket.org/echo.html`](https://www.websocket.org/echo.html)。在这里，您可以看到一个现成的**回声**服务器，我们可以访问，然后接收消息。它只是为您提供一个服务器；当您向该服务器发送消息时，它将返回相同的消息。继续玩您的回声应用程序。之后，我们将看到如何编写我们自己的客户端代码来访问这个回声服务器。

![回声测试](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ws-ess/img/B03854_02_03.jpg)

# WebSockets 客户端应用

让我们从 JavaScript 中编写客户端代码开始。我们现在将暂时使用相同的 Echo 服务器。让我们开始编写我们的客户端代码。以下是客户端代码的样子：

```js
<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8" >
    <title>WebSocket Test</title>
    <script language="javascript" type="text/javascript">
      var wsUri = "ws://echo.websocket.org/";
      var output;

      function init(){
          output = document.getElementById("output");
          testWebSocket();
      }
      function testWebSocket(){

          websocket = new WebSocket(wsUri);

          websocket.onopen = onOpen;

          websocket.onclose = onClose;

          websocket.onmessage = onMessage;

          websocket.onerror = onError;

      }

      function onOpen(evt){
          writeToScreen("CONNECTED");
          doSend("WebSocket rocks");
      }

      function onClose(evt){
          writeToScreen("DISCONNECTED");
      }

      function onMessage(evt){
          writeToScreen('<span style="color: blue;">RESPONSE: ' + evt.data + '</span>');
          websocket.close();
      }

      function onError(evt){
          writeToScreen('<span style="color: red;">ERROR:</span> ' + evt.data);
      }

      function doSend(message){
          writeToScreen("SENT: " + message);
          websocket.send(message);
      }

      function writeToScreen(message){
          var pre = document.createElement("p");
          pre.style.wordWrap = "break-word";
          pre.innerHTML = message;
          output.appendChild(pre);
      }

      window.addEventListener("load", init, false);

    </script>
  </head>
  <body>
    <h2>WebSocket Test</h2>
    <div id="output"></div>
  </body>
</html>
```

如果我们运行这段代码，将得到以下输出：

![WebSockets 客户端应用程序](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ws-ess/img/B03854_02_04.jpg)

这是一个非常简单的代码；有一点 JavaScript 经验的开发人员也可以理解。让我们来看看代码并理解发生了什么。这里的顺序如下：

1.  我们与服务器建立连接。

1.  如果成功，我们就向服务器发送消息。

1.  一旦我们从服务器接收到消息，我们就会显示它。

1.  然后，我们关闭连接。

让我们谈谈使用 WebSockets 创建任何应用程序时需要注意的重要阶段。

## 实例化

我们可以像创建任何其他类的实例一样创建 WebSockets 对象的实例。以下是我们可以这样做的方法：

```js
var wsUri = "ws://echo.websocket.org/";
websocket = new WebSocket(wsUri);
```

### 注意

我们只需要传递一个重要的参数，那就是服务器的 URI。您会注意到我们使用了**ws://** URL 模式，这基本上定义了通信应该使用哪种协议。还有另一个 URL 模式，即**wss://**，用于在我们想要使用安全通信时使用，就像我们有 HTTPS 用于安全连接一样。

## 添加事件

我们可以向 WebSockets 对象添加事件处理程序，在任何事件发生时触发。有四个主要事件需要添加处理程序，它们是：

+   当我们创建 WebSockets 对象的实例时，将触发打开事件，告诉我们连接现在已经打开。以下是我们添加事件的方式：

```js
websocket.onopen = onOpen;
```

+   当连接关闭时，将调用`onClose`方法：

```js
websocket.onclose = onClose;
```

+   当我们从服务器接收到消息时，将触发`onmessage`事件，我们可以处理它并使用事件的数据属性获取数据：

```js
websocket.onmessage = onMessage;
```

+   有时我们在连接过程中会遇到一些错误，因为服务器宕机或发生了一些配置问题，或者由于其他原因。由于这些不同的可能原因，我们可能会收到一个错误，该错误将在`onerror`事件处理程序中捕获并提供给客户端：

```js
websocket.onerror = onError;
```

## 发送消息

我们不仅可以发送字符串，还可以发送对象、blob 和数组缓冲区到服务器，反之亦然。发送方法如下：

```js
websocket.send(message);
```

这是一个重要的方法，因为我们用它向服务器发送数据。

## 接收消息

接收数据也很简单，因为我们已经为事件添加了处理程序。在这里，我们将在事件对象的数据属性下获取数据。在这种情况下，我们添加了一些样式并将其添加到 HTML 页面中，以便我们可以看到一个视觉上吸引人的消息，这可以从输出中看到：

```js
function onMessage(evt){
    writeToScreen('<span style="color: blue;">RESPONSE: ' + evt.data + '</span>');
}
```

## 关闭连接

连接也需要关闭；最佳实践是在使用完连接后关闭连接。同样，我们希望在接收到消息后关闭与服务器的连接。我们必须确保在退出应用程序之前关闭连接。我们只需调用 WebSocket 对象的`close()`方法即可关闭打开的连接。关闭连接的方法如下：

```js
    websocket.close();
```

# WebSocket 服务器

我们已经看到了客户端的工作方式以及如何向服务器发送数据并从服务器接收数据。现在我们将看看如何让我们自己的服务器代码处理消息。

使用现代 Web 技术，我们将探索使用 Node.js 创建 WebSocket 服务器的实现。Node.js 是一个非常友好、轻量级且易于使用的平台。让我们看看如何创建我们自己的 WebSockets 服务器。

## Node.js 服务器

Node.js 服务器为我们提供了很大的灵活性来创建我们自己的服务器。有许多通过 NPM 可用的库包。我们将使用 Einar Otto Stangvik 创建的库，它基本上处理一般机制，比如升级 HTTP 协议等。这是一个非常健壮、干净和轻量级的库。

现在，要设置服务器，您必须在您的计算机上安装 Node.js。如果您还没有安装，那就去查看 Node.js 的网站（[`nodejs.org/`](https://nodejs.org/)），阅读文档，并安装它。参考以下步骤安装 WebSocket 服务器：

1.  在 Node.js 中使用 NPM 创建一个新项目。您只需要运行`npm init`命令。按照随后的说明操作。

1.  这将创建一个`package.json`文件，其中包含项目和相关包的所有信息。这对于版本和包的控制非常有用。这是`npm init`命令执行后 Node.js 命令提示符的样子：![Node.js 服务器](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ws-ess/img/B03854_02_05.jpg)

1.  完成后，我们需要使用`npm install ws`命令设置 WebSockets 包。这个命令将安装 WebSocket 连接所需的库，看起来会像这样：![Node.js 服务器](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ws-ess/img/B03854_02_06.jpg)

### 注意

可能会出现与 Python 相关的错误。请忽略它。这个库有一些其他功能需要安装 Python，但我们正在使用的功能与 Python 无关，所以我们可以忽略它。这个错误不会影响我们的开发过程，我们的代码将正常工作。

现在我们准备编码。首先，我们将创建我们的服务器 JavaScript 文件，命名为`server.js`，这将是我们的主服务器文件。请注意，它应该在我们之前运行`npm init`命令的同一个文件夹中创建。服务器代码将如下所示：

```js
var WebSocketServer = require('ws').Server
wss = new WebSocketServer({ port: 8080 });
wss.on('connection', function connection(ws) {
ws.on('message', function incoming(message) {
console.log('received: %s', message);
ws.send(message);
});
ws.send('Connected');
});
```

这是一个非常简单的服务器。让我们逐步了解代码：

1.  在这里，我们只是创建了一个 WebSocketServer 实例，并定义了它应该监听的端口。有时端口`8080`不可用，所以您可能会收到错误。不用担心；您可以通过以下方式简单地更改它：

```js
var WebSocketServer = require('ws').Server
wss = new WebSocketServer({ port: 8080 });
```

1.  一旦我们有了实例，我们就需要添加连接监听器，如果连接建立，它就会被触发：

```js
wss.on('connection', function connection(ws)
```

1.  一旦连接建立，我们需要为特定的 WebSockets 连接实例添加监听器。这个实例可以用于许多目的，比如发送消息：

```js
ws.on('message', function incoming(message)
```

1.  然后是消息发送部分。因为我们正在创建一个 Echo 服务器，所以我们只需要将收到的消息发送回去。所以我们使用相同的消息，并通过 WebSockets 实例发送它：

```js
ws.send(message);
```

1.  一旦我们编写了代码，就该是测试的时候了。我们需要启动我们的 Node.js 服务器，可以使用以下命令来完成：

```js
> node server.js

```

1.  一旦服务器启动，我们只需要从客户端代码中更改一行——我们在本章前面开发的服务器 URI。之前，我们访问的是[www.websocket.org](http://www.websocket.org)网站，但现在我们需要访问我们自己的服务器。我们只需将 URI 从`ws://demo.websocket.org`更改为`ws://localhost:8080`，然后就可以运行我们的客户端应用程序文件，就像我们在上一个客户端应用程序中做的那样，并查看结果：

```js
var wsUri = "ws://localhost:8080";
```

![Node.js 服务器](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ws-ess/img/B03854_02_07.jpg)

结果将与之前的相同。

恭喜！您刚刚创建了您的第一个 WebSockets Echo 应用程序。

# 总结

在本章中，我们学习了如何编写客户端和服务器端代码。我们了解了如何将 Node.js 用作 WebSockets 服务器，以及如何利用它快速创建一个小型服务器。

在下一章中，我们将制作一个简单的应用程序，看看 WebSockets 如何被使用。


# 第三章：配置服务器和传输实时数据

数据是任何应用程序的核心。客户端和服务器之间的数据传输是其中非常重要的一部分。在上一章中，我们已经看到了如何使用 WebSockets 传输数据。现在，我们将看到如何利用它，并制作一个可以使用实时数据传输的应用程序。实时数据传输主要用于协作应用程序或任何需要在数据发生变化时立即反映的应用程序。

在本章中，我们将涵盖以下主题：

+   实时数据传输

+   实时应用程序

+   协作演示应用程序

+   添加协作

+   自己动手

+   技巧和窍门

# 全双工实时数据传输

众所周知，一旦发生变化，发送和接收数据就是实时数据传输。它可以是发生在数据中的一些变化。数据变化的原因可能是用户本身或某些定时事件。在正常情况下，用户的更改应该相应地反映给其他用户；例如，人们互相发送消息的聊天应用程序。聊天应用程序是实时数据传输的一个很小的例子；让我们谈谈一些大的例子，比如游戏。游戏是需要实时数据传输的主要应用程序。但随着行业的发展，我们日常使用的应用程序也在采用实时全双工数据通信。如果我们看任何股票市场应用程序，我们可以看到实时数据变化发生，这基本上是服务器推送的一个很好的例子。在这种情况下，服务器正在推送数据，这是 WebSockets 的一个很好的特性。

# 实时应用程序的基础

我们已经了解了什么是实时数据传输；现在让我们看看我们需要做什么来制作一个实时数据传输应用程序。在开始任何应用程序之前，有一些基础步骤我们需要考虑。一些主要步骤包括：

+   选择我们需要使协作或实时数据传输应用程序的功能

+   选择服务器端技术使其成为可能

+   选择与服务器轻松集成的客户端技术

这三个步骤是需要牢记的主要要点。正如我们所知，HTML5 支持 WebSockets，并且是数据通信的最佳方式之一。现在对于服务器端，我们已经看到了 Node.js 服务器可以如何轻松地无缝集成。现在最重要的部分是我们需要使实时的功能。这取决于我们正在构建的应用程序的类型。接下来，牢记这些要点，我们将开始构建我们的应用程序，以便更好地理解它。

# 协作演示应用程序

在考虑基础元素的基础上，让我们构建一个演示应用程序，如果你更改演示，那么其他用户也会相应地更改，反之亦然。基本上，我们将构建一个基于 Web 的协作演示共享应用程序。为了使这个应用程序适用于现代浏览器，我们需要一个 JavaScript 库，它给我们提供了演示应用程序所需的所有功能，比如创建不同的页面、导航等。然后我们将添加使不同用户之间可以协作的功能。

## 演示库

有不同的 JavaScript 库可供选择。给我们足够功能来创建我们的应用程序的库是**reveal.js**。这是一个制作精良的 API，完全基于 HTML5。还有一个制作精良的在线演示应用程序，也是基于我们将要使用的相同 JavaScript 库。该网站是[www.slides.com](http://www.slides.com)。继续访问这个网站；它会让你感受到我们的演示将会是什么样子。我们将使用这个 API，并使其协作，以便其他用户也可以更改幻灯片，并且反映可以被所有人看到。

## 设置图书馆

首先，我们需要下载并设置库文件。我们将要使用的库可以在[`github.com/hakimel/reveal.js`](https://github.com/hakimel/reveal.js)找到。以下是设置库的步骤：

1.  下载副本并打开`index.html`文件。![设置库](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ws-ess/img/B03854_03_01.jpg)

1.  一旦你打开文件，你就可以看到默认的演示文稿。![设置库](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ws-ess/img/B03854_03_02.jpg)

1.  reveal.js 库是一个完整的演示解决方案，带有自己的导航和演示机制。

1.  在这里，你可以使用键盘控制来导航到不同的页面。使用右箭头键转到下一张幻灯片，使用左箭头键转到上一张幻灯片。同样，使用上下箭头键可以进行不同级别的演示。它支持各种文本，你可以在其中放置真实的代码或任何 HTML 内容，这是实时的。你可以浏览幻灯片以了解更多关于库功能的信息。

## 添加协作

要向演示库添加协作功能，让我们首先看看我们需要遵循哪些步骤使这个应用程序工作。将客户端和服务器端的重要步骤写下来是一个好的做法，以确保我们覆盖了每一个步骤。

对于这个应用程序，让我们列出客户端需要做的事情的清单：

+   连接到 WebSocket 服务器

+   从 WebSocket 接收消息

+   将从服务器接收的幻灯片编号应用到当前演示

+   当用户更改幻灯片时向服务器发送幻灯片详细信息

既然我们已经列出了客户端的要点，让我们也列出服务器端的要点：

+   初始化 WebSocket 服务器

+   从客户端接收幻灯片数据

+   存储当前幻灯片数据

+   为后来加入的新用户传递当前幻灯片数据

+   将幻灯片数据更改广播给所有用户

+   检查幻灯片数据更改以减少重复调用

由于我们已经下载了库，我们需要添加我们的自定义客户端和服务器端代码使其工作。

## 代码实现

库已经为我们准备好了大部分代码，所以我们不需要为客户端添加太多代码。我们需要完全编写服务器端代码。让我们来看看代码。

### 客户端代码

在客户端，主文件是`index.html`，所以我们将把我们的代码添加到该文件中。在文件的 JavaScript 代码末尾，添加以下代码：

```js
function isJson(str)
{
    try 
    {
        JSON.parse(str);
    }
    catch (e)
    {
        return false;
    }
    return true;
}

var ws;

var isChangedByMe = true;
function init()
{
  ws = new WebSocket('ws://localhost:9001');
  //Connection open event handler
    ws.onopen = function(evt) 
    {
      ws.send('connection open');
    }
  //Event Handler to receive messages from server
  ws.onmessage = function(message)
  {
      console.log('received: '+ message);
      if(isJson(message.data))
      {
        var obj = JSON.parse(message.data);
        console.log("changing slide to "+ obj.indexh);
        isChangedByMe = false;
        Reveal.slide( obj.indexh, obj.indexv);
      }
  }
  //Adding event handler when slide is changed by use
  Reveal.addEventListener( 'slidechanged', function( event )
  {
      if(isChangedByMe)
      {
        ws.send(JSON.stringify({ 'indexh' :event.indexh , 'indexv' : event.indexv}));
        console.log("sending slide data : " + event.indexh);
      }
      isChangedByMe = true;
  });
}
//Event handler for application load event
window.addEventListener("load", init, false);
```

#### 代码解释

让我们看看我们在这段代码中写了什么。

我们已经向窗口添加了 load 事件监听器，这样一旦我们知道浏览器窗口已经正确加载，我们就可以开始初始化我们的 WebSocket 连接：

```js
window.addEventListener("load", init, false);
```

一旦调用`init`方法，我们就写下了实际与 WebSocket 服务器通信的代码。在这里，在这段代码中，我们实例化了 WebSocket 对象，并编写了一个事件处理程序，当连接打开时将被调用。一旦连接建立，这个方法被调用，我们就知道连接已经创建。现在我们发送一些随机数据，这可以被视为对服务器的确认：

```js
  ws = new WebSocket('ws://localhost:9001');
  ws.onopen = function(evt) 
   {
      ws.send('connection open');
   }
```

现在，我们添加消息事件处理程序，当服务器发送消息时调用它——在我们的情况下，我们必须处理服务器将要发送给我们的数据：

```js
  ws.onmessage = function(message)
```

所以你可以看到我们调用了`isJson`方法并将消息数据发送给它。这个方法被调用来检查我们收到的数据是否是我们想要的格式；否则它可能会抛出一个错误：

```js
     if(isJson(message.data))
```

在检查我们是否有正确类型的数据之后，我们现在将数据解析成**JavaScript 对象表示法**（**JSON**）格式。我们必须解析 JSON 方法的原因是因为我们正在以 JSON 格式发送数据，它被转换为字符串：

```js
     var obj = JSON.parse(message.data)
```

一旦数据被转换，我们就在 obj 变量中得到了一个 JSON 对象。现在来看一个重要的方法，这个方法基本上是一个 reveal.js 库方法，用于设置演示的当前幻灯片：

```js
      Reveal.slide( obj.indexh, obj.indexv);
```

这样我们就接收到数据并在演示文稿中设置它。现在来看代码的第二部分——将数据发送到服务器。

reveal.js 库给了我们一个事件，我们可以监听并获取关于当前幻灯片的信息：

```js
  Reveal.addEventListener( 'slidechanged', function( event )
```

一旦我们将监听器添加到`slidechanged`事件中，我们就可以使用在事件属性下传递的数据。

以下是我们如何从 JSON 对象创建字符串并将其传递给服务器：

```js
  ws.send(JSON.stringify({ 'indexh' :event.indexh , 'indexv' : event.indexv}));
```

在 WebSockets 客户端中，我们使用`send`方法将数据发送到服务器。一旦发送，服务器接收到并执行我们定义的操作。现在让我们来看看服务器是如何设置和行为的。

### 服务器代码

在上一章中，我们已经看到了如何创建一个 Node.js 服务器。以类似的方式，我们将使用 NPM 创建另一个应用程序（请参考第二章，*使用 WebSockets 入门*来获取设置和运行服务器的说明）。以下是我们需要在`server.js`文件中编写的服务器代码：

```js
var WebSocketServer = require('ws').Server
   wss = new WebSocketServer({ port: 9001 });

//Broadcast method to send message to all the users
wss.broadcast = function broadcast(data,sentBy)
{
  for(var i in this.clients)
  {
    if(this.clients[i] != sentBy)
    {
      this.clients[i].send(data);
    }
  }
};

//Data holder for current side number
var currentSlideData = { 'indexh' :0 , 'indexv' : 0};
//JSON string parser
function isJson(str)
{
    try
    {
        JSON.parse(str);
    } 
    catch (e)
    {
        return false;
    }
    return true;
}

//WebSocket connection open handler
wss.on('connection', function connection(ws)
{
//WebSocket message receive handler
    ws.on('message', function incoming(message)
    {
    if(isJson(message))
    {
      var obj = JSON.parse(message);

        if(currentSlideData.indexv != obj.indexv || currentSlideData.indexh != obj.indexh )

        {
          currentSlideData.indexv = obj.indexv;
          currentSlideData.indexh = obj.indexh;
//Broadcasting the message to all the users
          wss.broadcast(message,this);
          console.log('broadcasting data');
        }
    }

      console.log('received: %s', message);

  });

  console.log('sending initial Data');
//When user is connected sending the current slide information for the users who joined later
  ws.send(JSON.stringify(currentSlideData));

});
```

这段代码非常标准和直接。让我们分解并理解我们在这里放了什么以及为什么。

#### 代码解释

在这里，你可以看到的一个主要方法是`broadcast`。我们编写这个方法来将幻灯片更改数据广播给所有使用 WebSockets 连接的用户。我们只是简单地循环遍历所有客户端，并使用`send()`方法发送数据：

```js
wss.broadcast = function broadcast(data,sentBy)
{
  for(var i in this.clients) 
  {
    if(this.clients[i] != sentBy)
    {
      this.clients[i].send(data);  
    }
  }
};
```

在此之后，我们定义一个变量，我们将暂时保存幻灯片数据。这个变量很重要，因为每当我们获取幻灯片数据时，我们将存储它，并在需要时传递它。有一种情况是用户在后期加入会议；使用存储在这个变量中的数据，我们可以为他们提供存储的当前幻灯片编号：

```js
var currentSlideData = {'indexh' :0 , 'indexv' : 0};
```

现在看一下以下代码片段。在这里，我们正在处理连接事件，以便我们可以将当前幻灯片编号数据传递给用户。这个事件给了我们新用户的指示。在发送数据时，你会注意到我们使用了`JSON.stringify`方法。这个方法用于从 JSON 中创建字符串，因为我们的对象是以 JSON 格式的：

```js
wss.on('connection', function connection(ws) 
{
  console.log('sending initial Data');

  ws.send(JSON.stringify(currentSlideData));

});
```

在这段代码中，我们可以看到有一个参数被传递：该特定用户的 WebSocket 对象的实例。为了接收消息，我们需要添加一个`message`事件处理程序，你可以在以下代码中看到。参数是从客户端传递的实际消息：

```js
  ws.on('message', function incoming(message)
```

收到消息后，我们检查传递的对象是否是 JSON。为此，我们定义了 JSON 方法，它基本上检查 JSON 字符串并返回 true/false。检查后，我们解析 JSON 字符串并检查值是否与幻灯片索引数据的最后一个值相似。如果不是，我们将其存储并将消息广播给所有客户端。检查是必要的，以避免重复调用。以下是代码：

```js
if(isJson(message))
  {
    var obj = JSON.parse(message);
      if(currentSlideData.indexv != obj.indexv || currentSlideData.indexh != obj.indexh )
      {
        currentSlideData.indexv = obj.indexv;
        currentSlideData.indexh = obj.indexh;
        wss.broadcast(message,this);
        console.log('broadcasting data');
      }
  }
```

就是这样——只是一个简单的服务器代码，非常强大，适用于我们的小型应用程序。

一旦我们运行应用程序，它将如下所示：

![代码解释](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ws-ess/img/B03854_03_03.jpg)

我们可以看到两者都有相同的第一张幻灯片，即索引为零的幻灯片：

![代码解释](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ws-ess/img/B03854_03_04.jpg)

一旦我们导航到其他幻灯片，其他用户的幻灯片也会改变。看一下左侧窗口中的**控制台**日志。我们可以看到**发送幻灯片数据**以及幻灯片编号被显示出来，这表明在幻灯片改变时，数据正在被发送。在右侧窗口中，我们可以看到**将幻灯片更改为**被记录在控制台中，这表明数据是从服务器接收到的，相应地我们看到用户的幻灯片也在改变。

![代码解释](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ws-ess/img/B03854_03_05.jpg)

同样，如果我们从右侧窗口更改幻灯片，它将在左侧窗口上反映出来，这在日志中是清晰可见的。所有用户都会发生同样的情况。以下是在命令提示符中看到的日志的截图：

![代码解释](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ws-ess/img/B03854_03_06.jpg)

在服务器端，我们可以看到接收到的数据和数据广播日志显示数据正在传递给所有用户。在服务器端放置日志总是有助于检查调试应用程序的步骤。

# 自己动手

这个应用程序是一个非常简单和易于构建的应用程序。你已经学会了如何创建一个带有一些有限功能的简单应用程序。可以对这个应用程序进行许多添加，并且可以使其更加强大。让我们给你一些可以开发的功能的提示。

## 输入用户名

每当用户访问 URL 时，应用程序都会要求用户名。输入的用户名将显示在屏幕左上角。我认为这种情况相当容易构建。我会把它的实现留给你。直到我们想要显示用户列表，这是相当容易的。

## 用户列表

制作一个按钮，它将显示当前在线用户的列表。这种情况需要在客户端和服务器端都进行代码更改。让我列出一些你需要实现这个功能的关键点：

1.  用户一输入名称，立即在服务器端保存。这可以通过以特定格式发送用户名称并在服务器端处理相同来实现，以将其存储在数组或对象中。

1.  在服务器端维护所有用户的列表以供参考。

1.  从服务器获取用户列表，只要我们加入服务器即可。这可以通过发送一个特定的消息，比如`getUsers`，并在`message`事件处理程序中添加另一个条目来返回用户列表来实现。

1.  在 UI 界面上制作一个按钮，并滑动显示用户列表。

## 基于用户的授权来更改演示文稿

当用户进入会议时，询问他们是否要以演讲者或与会者的身份加入。如果用户选择以演讲者身份加入，则允许用户更改幻灯片。如果用户选择以与会者身份加入，则限制用户更改幻灯片。

询问用户输入名称很容易；稍微复杂的部分是限制用户更改幻灯片。如果我们深入研究 reveal.js 库的配置，这是很容易的。在配置中，我们可以看到一些参数是 true 和 false。我们只需要根据用户类型（演讲者/与会者）进行修改。

## 使用户成为演讲者

我们有演讲者和与会者。现在让我们为演讲者提供权限，以允许与会者。因此，从用户列表中，如果演讲者点击用户名，那么该用户将成为演讲者。

通过在运行时更改 reveal.js 的配置，可以以简单的方式实现这一点。我们只需要在用户角色更改时调用相同的功能，就像我们之前根据角色更改的配置一样。

# 提示和技巧

让我们谈谈在制作应用程序时可以使用的一些提示和技巧。

+   使用 JSON：

JSON 格式在 JavaScript 中是一种易于阅读的格式。以 JSON 格式传输数据总是很好的。

+   基于对象的 WebSocket 结构：

通常，在任何需要传输不同数据集的应用程序中，最好确定消息的正确结构。以聊天应用程序为例：如果我们确定了一个结构，更好地处理消息。以下是一个示例结构：

```js
  {
    type: "message"
    data : {
      from: "varun"
      to : "user1"
      data : "hello"
           }
  }
```

+   使用 ArrayBuffer：

还有另一种使用 ArrayBuffer 发送数据的方法；你也可以发送一个二进制大对象（BLOB）。以下是一个示例：

```js
var array = new Float32Array(5);
  for(var i = 0; i < array.length; ++i) {
    array[i] = i / 2;
  }
  ws.send(array, { binary: true, mask: true });
```

这些结构可以帮助更好地理解，并可用于不同类型的消息。在这里，类型可以是消息、图像、音频、文件或其他任何东西。而属性数据是通用的，可以包含所有这些不同类型的数据。

# 摘要

在本章中，我们已经看到了如何利用基于 HTML5 的 JavaScript 库。我们将 WebSockets 与 reveal.js 库结合起来，用于协作应用程序。这是一个简单的例子，您已经看到我们用更少的编码实现了一个良好的工作应用程序。您已经学会了如何配置服务器，发送和接收数据，并从服务器向所有客户端广播数据。

在接下来的章节中，我们将看到另一个库的使用，以及一些框架，利用现代技术开发完整的应用程序。


# 第四章：在真实场景中使用 WebSockets

我们在上一章中看到了如何创建一个实时演示共享应用程序。我们了解了实时数据传输的工作原理以及如何设置服务器。现在我们将进入下一步，看看我们需要添加哪些元素来加强我们的应用程序的结构。在这一章中，我们将看到创建应用程序的不同步骤。

# 真实场景

这里的问题是什么是真实场景？我们已经看到了一个真实世界的场景应用程序，但是这里我们指的是什么？一个结构良好的应用程序如果没有框架支持是不完整的。在上一个应用程序中，我们使用了 JavaScript 服务器和 JavaScript 库，进行了集成并构建了我们的应用程序。但是你认为应用程序的结构足够好以支持可扩展性或可重用性吗？答案是否定的，因为我们没有使用任何框架来为我们的应用程序提供更好的结构。在这一章中，让我们谈谈实际场景，我们在应用程序中实现不同的结构或框架。

# JavaScript 框架

随着 HTML5 的发展，JavaScript 框架开始进入视野。情况是我们有很多选择。一些常用的框架包括 AngularJS、Ember.js、Knockout.js、Backbone.js 等等。我们将在下一个示例中使用 AngularJS。AngularJS 是由谷歌开发的，是一个功能强大的框架，具有许多必要的功能。

## AngularJS

AngularJS 是由谷歌开发的开源框架。它基于一个非常著名的设计模式：**Model-View-ViewModel**（**MVVM**）。除此之外，它还提供了与 HTML5 无缝配合的功能，如指令、绑定和控制器。它主要处理单页应用程序的问题，提供了实现动态视图和路由机制的功能，以简化页面之间的导航，而无需加载完整的网页。这个特性使得这个框架对开发者非常有益。它不仅解决了开发中的问题，还使得测试变得非常容易。

关于 AngularJS 框架在网上有很多详细信息。

# 学以致用

学以致用是学习的最佳方式之一。有时候你会学习一些东西，然后实施它。但是因为你已经阅读了场景，你可以很容易地实施它。最好的方法之一是开始行动，当你面临问题时，尝试找到解决方案。这将提高你的解决问题的能力，并帮助你探索更多。在类似的情况下，让我们从一个应用程序开始，看看我们在哪里遇到问题，以及我们在哪里可以看到需要一个框架。

# 协作绘图应用程序

让我们构建一个绘图应用程序，用户可以在画布上绘图，其他用户也可以同时进行相同的操作。基本上，我们正在创建一个协作绘图应用程序。在构建应用程序之前，让我们收集要求并进行一些分析，这是构建应用程序必需的。

## 要求

在这里，我们的主要要求是需要制作一个提供协作绘图的应用程序。所以我们需要一个客户端应用程序，它连接到服务器，并实时地将数据从一个用户传递到另一个用户。除此之外，我们需要使用 HTML 来绘制一个机制。我们可以使用一个很好的现成库，它为我们提供了绘图所需的功能，而不是花费大量时间编写绘图功能的代码。

因此，如果我们列出构建应用程序所需的项目，它将如下所示：

+   客户端应用程序

+   服务器

+   绘图库

+   实时数据传输的实现

现在我们知道要创建什么。下一步是为应用程序划分任务。

### 绘图库

我们选择使用库而不是编写整个东西。有一些库可用，但其中最好的是**Fabric**.**js**库。你可以从[`fabricjs.com/`](http://fabricjs.com/)下载该库。你甚至可以构建一个自定义的库文件，选择其中的功能以使其更轻量级。这个库提供了许多功能，你可以在上述网站上看到所有这些功能。让我们看一下 Fabric.js 库的演示代码：

```js
<!DOCTYPE html>
<html>
<head>
</head>
<body>
    <canvas id="canvas" width="300" height="300">
....</canvas>

    <script src="img/fabric.js">
....</script>

    <script>
        var canvas = new fabric.Canvas('canvas');
        var rect = new fabric.Rect({
            top : 100,
            left : 100,
            width : 60,
            height : 70,
            fill : 'red'
        });
        canvas.add(rect);
    </script>
</body>
</html>
```

我们可以看到这段代码中这个库是多么简单。你只需要添加画布标签并开始向其中添加对象，它就会在应用程序中显示。这个库非常容易实现，这将帮助我们很多，因为我们已经在这里处理了很多不同的事情。尝试一下这段代码，看看输出结果，并尝试使用这个库来熟悉它。

## 客户端应用程序

第一步是制作一个客户端应用程序。以下是客户端的代码：

```js
<!DOCTYPE html>

<html>

<head>

</head>

<body>

<button id="addCircle">Add Circle</button>

<button id="addRectangle">Add Rectangle</button>

<button id="addTriangle">Add Triangle</button>

<button id="pencil" toggle>Pencil</button>

<button id="selection" toggle>Selection</button>

    <canvas id="canvas" width="1024" height="768"></canvas>

    <script src="img/fabric.js"></script>

    <script>

//creating canvas instance
        var canvas = new fabric.Canvas('canvas');

//setting some properties for canvas

        canvas.freeDrawingBrush.color = 'green';

        canvas.freeDrawingBrush.lineWidth = 10;
        canvas.selectable = false;

        canvas.on('path:created',function(e){

            console.log(JSON.stringify(e));

        })

//main initialize method
        function init()

        {

            pencil.addEventListener('click', pencilHandler);

            addCircle.addEventListener('click', addCircleHandler);

            addRectangle.addEventListener('click', addRectangleHandler);

            addTriangle.addEventListener('click', addTriangleHandler);

            selection.addEventListener('click', function(){

                canvas.isDrawingMode = false;

            })

        }

//changing the drawing mode to free drawing
        function pencilHandler()

        {

            canvas.isDrawingMode = true;

        }

//adding circle to the canvas
        function addCircleHandler()

        {

            var circle = new fabric.Circle({

              radius: 20,

              fill: 'green',

              left: 100,

              top: 100

            });

        canvas.add(circle);

        }

//adding rectangle to the canvas
        function addRectangleHandler()

        {

            var rect = new fabric.Rect({

                top : 100,

                left : 100,

                width : 60,

                height : 70,

                fill : 'red'

            });

            canvas.add(rect);

        }

//adding triangle to the canvas
        function addTriangleHandler()

        {

            var triangle = new fabric.Triangle({

                width: 20,

                height: 30,

                fill: 'blue',

                left: 50,

                top: 50

            });

            canvas.add(triangle);

        }

//adding window load event
        window.addEventListener("load", init, false);

    </script>

</body>

</html>
```

在这段代码中，我们创建了一个画布，并制作了一些按钮来添加不同的形状到画布上。添加的一个重要功能是自由绘制。复制并粘贴代码到`index.html`文件中并尝试运行它。如果你阅读了 Fabric.js 库，你将了解它是如何工作的。不要忘记下载库文件并在代码中包含库。

## 与服务器集成

由于我们已经为基本客户端功能编写了代码，现在我们需要使用 WebSocket 将应用程序与服务器集成。为此，我们首先需要找出需要发送到服务器的数据。为了协作，我们必须发送关于我们需要在其他用户画布上创建的形状的数据。让我们列出我们需要在客户端和服务器端执行的一系列操作。

客户端：

+   捕获添加形状按钮的事件

+   将对象发送到服务器

+   创建与服务器的 WebSocket 连接

+   捕获服务器数据

+   处理并将从服务器接收的对象添加到画布上

服务器：

+   创建一个 WebSocket 服务器

+   接收数据

+   将数据传递给所有连接的客户端

根据前面列出的项目清单，我们已经对服务器端和客户端代码进行了一些更改。

### 客户端代码

现在，我们将根据列出的服务器通信项目在我们的客户端代码中实现代码，这将有代码与服务器通信。以下是根据客户端项目更改的客户端代码：

```js
<!DOCTYPE html>
<html>
  <head>
  </head>
  <body>
    <button id="addCircle">Add Circle</button>
    <button id="addRectangle">Add Rectangle</button>
    <button id="addTriangle">Add Triangle</button>
    <button id="pencil" toggle>Pencil</button>
    <button id="selection" toggle>Selection</button>
    <canvas id="canvas" width="1024" height="768"></canvas>
    <script src="img/fabric.js"></script>
    <script>
      //creating canvas instance
              var canvas = new fabric.Canvas('canvas');

      //setting some properties for canvas
              canvas.freeDrawingBrush.color = 'green';

              canvas.freeDrawingBrush.lineWidth = 10;

              canvas.selectable = false;

              canvas.on('path:created',function(e){

                  console.log(JSON.stringify(e));

              }) 

      //main initialize method
              function init()

              {

                  initServer();

                  pencil.addEventListener('click', pencilHandler);

                  addCircle.addEventListener('click', addCircleHandler);

                  addRectangle.addEventListener('click', 
      addRectangleHandler);

                  addTriangle.addEventListener('click', 
      addTriangleHandler);

                  selection.addEventListener('click', function(){

                      canvas.isDrawingMode = false;

                  })

              }

      //changing the drawing mode to free drawing
              function pencilHandler()

              {

                  canvas.isDrawingMode = true;

              }
      //add circle to the canvas
              function addCircleHandler()

              {

                  var obj = {

                    radius: 20, 

                    fill: 'green',

                    left: 100, 

                    top: 100

                  };

                  // var circle = new fabric.Circle(obj);

                  // canvas.add(circle);
      //sending the circle object to the server
                  sendObject('Circle',obj);

              }

      //add rectangle to the canvas
              function addRectangleHandler()

              {

                  var obj = {

                      top : 100,

                      left : 100,

                      width : 60,

                      height : 70,

                      fill : 'red'

                  };

                  var rect = new fabric.Rect(obj);

                  // canvas.add(rect);
      //sending the rectangle object to the server
                  sendObject('Rectangle',obj);

              }

      //add triangle to the canvas       
       function addTriangleHandler()

              {

                  var obj = {

                      width: 20,

                      height: 30,

                      fill: 'blue',

                      left: 50,

                      top: 50

                  };

                  var triangle = new fabric.Triangle(obj);

                  // canvas.add(triangle);
      //sending the object to server 
                  sendObject('Rectangle',obj);

              }

      //generic method to add object to the canvas
              function addObject(type,obj)

              {

                  var shape;

                  if(type == 'Triangle')

                  {

                      shape = new fabric.Triangle(obj);

                  }

                  else if(type == 'Rectangle')

                  {

                      shape = new fabric.Rect(obj);

                  }

                   else if(type == 'Circle')

                  {

                      shape = new fabric.Circle(obj);

                  }

                  canvas.add(shape);

              }

      //check for JSON string
              function isJson(str)

              {

                  try

                  {

                      JSON.parse(str);

                  }

                  catch (e)

                  {
                      return false;

                  }

                  return true;

              }

              var ws;

      //method to send object to the server
              function sendObject(type,obj)

              {

                  ws.send(JSON.stringify({'type': type,'data' : obj}));

              }

              function connectionOpen()

              {

                   ws.send('connection open');

              }
      //method handler when message is received from server
              function onMessageFromServer(message)

              {

                  console.log('received: '+ message);

                  if(isJson(message.data))

                  {

                      var obj = JSON.parse(message.data)

                      console.log("got data from server");

                      addObject(obj.type,obj.data)

                  }
              }

      //initialize server method
              function initServer()

              {

                  ws = new WebSocket('ws://localhost:9001');

                  ws.onopen = connectionOpen;

                  ws.onmessage = onMessageFromServer;

              }

              window.addEventListener("load", init, false);

    </script>
  </body>
</html>
```

#### 代码解释

我们已经在上一章中看到了如何从 WebSocket 服务器发送和接收数据。这里我们编写了一个发送数据的方法`sendObject`，它将对象的类型和属性发送到服务器：

```js
 function sendObject(type,obj)

        {
            ws.send(JSON.stringify({'type': type,'data' : obj}));
        }
```

这里的一个主要方法是`addObject`。一旦我们从服务器获取数据，我们就会得到两个属性：一个是类型，另一个是具有属性值的对象。这些是我们发送到服务器的值，然后检查对象的类型并使用相应的方法将其添加到画布中：

```js
function addObject(type,obj)

        {

            var shape;

            if(type == 'Triangle')

            {

                shape = new fabric.Triangle(obj);

            }

            else if(type == 'Rectangle')

            {

                shape = new fabric.Rect(obj);

            }

             else if(type == 'Circle')

            {

                shape = new fabric.Circle(obj);

            } 

            canvas.add(shape);

        }
```

其余的代码非常简单和直接。

### 服务器代码

现在让我们看看在服务器端需要做什么。以下代码将展示我们需要在服务器端编写什么：

```js
var WebSocketServer = require('ws').Server
    wss = new WebSocketServer({

        port: 9001

    });

//method to broadcast message to all the users
wss.broadcast = function broadcast(data, sentBy)

{

    for (var i in this.clients)

    {

        this.clients[i].send(data);

    }

};

function isJson(str)

{

    try

    {

        JSON.parse(str);

    } 

    catch (e)

    {

        return false;

    }

    return true;

}

//client connection open method
wss.on('connection', function connection(ws)

{
//client message receive method
    ws.on('message', function incoming(message)

    {
        if (isJson(message))

        {
//broadcasting message to all users
            wss.broadcast(message, this);

            console.log('broadcasting data');

        }

        console.log('received: %s', message);

    });

    console.log('sending initial Data');

});
```

#### 代码解释

在服务器端，我们并没有做太多编码。它几乎与上一章的服务器代码相同。我们接收数据并将其广播给所有连接的用户。

# 自己动手

这个应用程序是一个非常简单和易于构建的应用程序。我们已经看到了如何创建一个具有一些有限功能的简单应用程序。可以添加许多功能来使这个应用程序更加强大。让我们给你一些关于你可以开发的功能的提示和信息。

## 用户注册

用户打开 URL 时，将打开一个登录/注册对话框。用户的姓名等详细信息将显示在屏幕左上角。

### 提示

这种情况将需要一个数据库连接。有一些数据库可以很容易地连接到我们的 Node.js 服务器，比如**MongoDB**。我会把它的实现方法留给你。要了解如何连接 Node.js 和 MongoDB，请访问[`mongodb.github.io/node-mongodb-native/`](http://mongodb.github.io/node-mongodb-native/)。

## 用户列表

创建一个按钮，点击后会显示当前在线用户的列表。这种情况需要在客户端和服务器端都进行代码更改。让我列出一些你需要实现这个功能的关键点：

+   一旦你开发了用户注册功能，我们已经在数据库中保存了用户列表。我们可以维护一个所有在线用户的列表，或者我们可以只在服务器上保留列表。将数据持久化在服务器上的问题是，一旦服务器重新启动，数据将被擦除。

+   从服务器获取用户列表，一旦我们加入服务器就立即发送。这可以通过发送特定的消息来实现，比如`getOnlineUsers`，并在消息事件处理程序中添加另一个条目，返回用户列表。

+   在屏幕上显示用户列表，这样你就可以看到一个合适的在线用户列表。这需要在客户端进行更改。

## 与特定用户分享

由于我们已经实现了用户列表，现在我们可以实现基于用户的绘图共享。在这种情况下，我们只能与一些特定的用户分享我们的绘图。

### 提示

这可以通过向我们发送到服务器的对象添加另一个参数来实现：目标用户 ID。这个用户 ID 对于用户是唯一的，用于识别用户。这将帮助我们仅向特定用户发送数据。

## 保存绘图

一旦我们完成了绘图，我们可以保存它，并使其在将来可用。

### 提示

我们必须将我们的应用程序连接到一个可以保存我们在先前场景中已经实现的值的数据库。现在我们需要在数据库中添加另一个表，只用于存储绘图。Fabric.js 给我们提供了我们绘制的所有绘图元素的对象，我们可以制作一个 JSON 字符串并将其存储在数据库中以供将来使用。

# 应用程序结构

重构应用程序是一个非常重要的部分。如果我们看一下我们写的代码，我们会发现它没有一个良好的结构。结构必须是这样的，以便将来如果我们想要添加一些功能，那么应该很容易做到。代码应该以一种易于维护的方式编写。为了实现这一点，我们需要使用某种结构，这就是所谓的框架。框架旨在为应用程序提供一种结构感。

# 重构应用程序

现在我们知道了框架，让我们使用 AngularJS 框架重构我们的应用程序。让我们看看我们可以在这里重构什么；我们将把一切分成模型、视图、控制器和服务层。让我们看看这些术语是什么，它们在我们的应用程序中的作用。

## 模型

在我们的应用程序中，我们还没有看到存储数据的需求，但如果我们想扩展我们的应用程序并添加更多功能，那么就需要一个**模型**。正如我们在一些场景中所看到的，我们有用户和绘图列表，我们需要模型在客户端存储数据，以便很容易地访问。AngularJS 提供了很好的功能来存储数据，绑定有助于在 UI 中非常容易地显示列表数据。

## 视图

一个应用程序通常被分成不同的视图，但在我们的应用程序中，我们只有一个视图。正如我们在场景中所看到的，我们需要一个用户登录界面。在这种情况下，我们需要设置一个不同的视图，这时视图就出现了。AngularJS 为我们提供了一种非常简单的方式来维护我们的视图。AngularJS 的路由机制也帮助我们在不同的视图之间导航，提供浏览器历史以及维护单页面应用程序。

## 控制器

由于应用程序被分成不同的视图，我们还需要不同的控制器，这些控制器基本上控制 UI 行为，并帮助与服务进行通信。AngularJS 控制器非常强大，并实现了**依赖注入**（**DI**），这有助于将服务、模型等注入到控制器中，以在视图中进行操作。

## 服务

当我们有一个连接到服务器的应用程序时，服务非常重要。将服务器通信集中在一个地方是一个很好的方法，因为它在应用程序中创建了不同的层，可以在不影响应用程序的其他层的情况下进行操作。

当我们阅读并了解使用 AngularJS 框架构建应用程序的不同模式时，我强烈建议您开始使用 AngularJS 实现相同的应用程序。这是一个非常优秀的框架，可以满足开发者的所有需求，是一个功能齐全的框架。

# 总结

在本章中，我们已经看到了如何利用基于 HTML5 的 JavaScript 库。我们将 WebSockets 与 Fabric.js 库结合在一起，用于协作应用程序。我们还看到了如何将应用程序分成部分并进行创建。我们了解了开发流程，并学习了应用程序的结构。

在下一章中，我们将看到 WebSocket 的行为及其在移动设备和平板电脑上的实现。


# 第五章：移动和平板电脑的 WebSockets

WebSockets 在 Web 上运行良好并且性能良好。我们已经看到了在 Web 上实现 WebSockets 是多么简单和强大。随着手机的增长，应用程序从桌面转移到移动设备的需求变得非常重要。在本章中，我们将重点关注 WebSocket 的行为以及在移动设备和平板电脑上的实现。

# 移动设备和 WebSocket

整个世界都在转向移动设备；那么我们为什么不呢？手机已经变得非常强大，它们可以做电脑能做的事情。同样，浏览器也变得非常强大，它们也开始采用 HTML5。不仅仅是浏览器，甚至应用程序的支持也增加了。有很多应用程序提供了很多功能。在这里，WebSockets 扮演了一个重要的角色：每当需要实时数据传输时，WebSockets 都可以帮助我们。让我们看一些 WebSockets 可以帮助的情况：

+   聊天应用程序

+   视频会议

+   游戏

+   具有实时数据更新的仪表板

+   股票应用

+   体育比分应用程序

+   实时数据更新

现在所有这些应用程序都可以在 Web 上制作，并且与浏览器兼容，这要归功于支持 HTML5 的现代浏览器。

要在移动设备上实现 WebSockets，有一些可用的库可以使用。需要提供一种一致的方式来在不同的后端技术中实现 WebSockets。有一些库提供了这些功能：

+   推动者

+   Socket.IO

## 推动者

Pusher 是一个著名的库，可帮助您制作实时应用程序。您可以在[`www.pusher.com`](http://www.pusher.com)找到它。这是一组构建的库，可与不同服务器上构建的不同应用程序集成，例如 Ruby on Rails、Python、PHP 和 Node。它不仅在服务器端提供支持，还为基于 JavaScript 的应用程序以及 iOS 和 Android 设备提供支持。

Pusher 是一个基于事件的 API，并实现了发布者/订阅者机制。在这里，订阅者是服务器，发布者是客户端。订阅者订阅事件，发布者触发订阅者监听的事件。为了实现这个功能，发布者和订阅者在内部实现了 WebSockets，这基本上提供了实时体验。

Pusher API 的另一个重大优势是它具有备用机制，当 WebSockets 不可用时，例如在一些较旧的浏览器版本中，然后它在内部使用 Flash 等其他技术来发送数据。这使得该库具有优势，因此我们不需要为不同的浏览器和设备编写不同的实现。

## Socket.IO

Socket.IO 是另一个完全基于 JavaScript 的库。它不仅支持客户端，还完全支持 Node.js 服务器。该库提供高性能的实时数据传输，并在内部使用 WebSockets。您可以使用此 API 制作各种实时协作应用程序。

# 在移动设备上运行服务器

到目前为止，我们一直在本地服务器和应用程序上工作，但是要在移动设备上运行应用程序，我们需要将客户端应用程序代码转移到服务器，以便以服务器 URL 为应用程序提供服务。为此，我们将举一个简单的例子：基本上，我们将要更改一个我们已经创建的应用程序。在第二章中，*开始使用 WebSockets*，我们为 Echo 测试开发了一个应用程序，它基本上返回我们发送到服务器的任何内容。现在让我们看看它在手机上的运行方式。

首先，我们将更改服务器代码，以满足客户端代码。以下是我们将在服务器端进行的更改：

```js
var express = require('express');

var app = express()

var http = require('http').Server(app);

app.use(express.static(__dirname + '/public'));

app.get('/', function(req, res)
{

  res.sendfile('public/index.html');

});

http.listen(3000, function()
{

  console.log('listening on *:3000');

});

var WebSocketServer = require('ws').Server
  , wss = new WebSocketServer({ port: 9001 });

wss.on('connection', function connection(ws)
{

  ws.on('message', function incoming(message)
  {

    console.log('received: %s', message);

    ws.send(message);

  });

  ws.send('Connected');

});
```

一旦这些设置完成，您就可以开始了。只需在您的移动设备上打开 Chrome 浏览器，打开服务器 URL `http://localhost:3000`，看到魔法。您将看到与我们在桌面上看到的相同的输出。

打开 Chrome 浏览器，转到`chrome://inspect`。

```js
npm install express

```

这个软件包需要安装在与我们的`server.js`文件相同的目录中。这很重要，因为我们的服务器将运行并使用这个软件包，如果找不到它，服务器可能无法按我们想要的方式工作并抛出错误。

在这里，我们监听`3000`端口，所以每当我们打开`http://localhost:3000`时，它将打开指定的文件。我们已经在`public`文件夹下定义了文件，`index.html`。因此，我们将打开的第一个文件是`index.html`文件，我们将看到它的内容。就像我们在之前的章节中所做的那样，我们也在客户端代码中做了同样的编码，几乎没有任何变化。只是文件的位置已经改变了，没有别的。

### 如您所见，应用程序的输出没有任何变化。它与我们在桌面上看到的完全相同。

一旦更改完成，您可以启动服务器并在浏览器中检查它是否工作。由于您监听`3000`端口，只需在浏览器中运行`http://localhost:3000`，确保应用程序正常运行。

要安装 Express.js 服务器，我们只需要运行以下命令：

## 确保所有客户端代码及其相关库都放在`public`文件夹中，因为我们是从公共文件夹中提取它，如果没有正确放置，可能会出现错误。

更改完成后，我们需要在手机上运行本地服务器。这似乎很困难，但实际上并不是。谷歌 Chrome 为我们提供了一个很棒的功能，通过它我们可以在移动浏览器上使用本地服务器。以下是我们需要实施的在移动设备上运行本地服务器的步骤：

1.  注意

1.  浏览器支持

1.  使用 USB 将您的设备连接到计算机。

1.  在您的移动/平板设备上启用 USB 调试。

1.  现在我们需要考虑的主要设置是**端口转发**。我们使用两个不同的端口：`3000`用于客户端，`9001`用于 WebSocket 服务器。只需确保将它们都添加到**端口转发设置**中。

### 提示

在这里，我们没有针对移动设备做任何特定的事情；我们只是创建了另一个服务器，为我们提供主要的客户端文件。我们在这里使用了`Express.js`服务器，它有助于通过服务器提供内容。您可以在互联网上阅读更多关于`Express.js`服务器及其工作原理的信息。在这里，我们的主要重点只是创建一个将监听特定端口的服务器。因此，当有人访问该特定 URL 时，我们将在浏览器上运行客户端应用程序。

1.  这将检查连接的设备。

由于 HTML5 的原因，我们能够以非常简单的方式实现这种输出行为，因为 HTML5 在几乎所有浏览器中都表现一致，并且大多数浏览器都在采用它。这使我们能够使用 HTML5 WebSockets 制作应用程序，并使其几乎在任何地方运行。在构建应用程序时，我们需要确保具有响应式设计，因为移动设备具有不同的分辨率和不同的屏幕尺寸。这是在创建应用程序时需要注意的一个主要问题。但多亏了 HTML5，我们有了媒体查询，可以轻松处理这种情况。

### 手机输出

![移动设备上的本地服务器](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ws-ess/img/B03854_05_01.jpg)

![手机输出](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ws-ess/img/B03854_05_02.jpg)

# 如果您在设置移动设备时仍然遇到问题，请访问[`developer.chrome.com/devtools/docs/remote-debugging`](https://developer.chrome.com/devtools/docs/remote-debugging)。您将获得有关如何设置移动设备的所有详细信息。

HTML5 已经被几乎所有浏览器采用，甚至在移动和平板设备上也是如此。这使得我们在几乎所有现代浏览器中使用 WebSocket 应用程序时具有优势。要检查哪些移动浏览器受支持，请访问[`caniuse.com/#feat=websockets`](http://caniuse.com/#feat=websockets)，这将为我们提供支持 WebSockets 的所有浏览器的列表。

# 自己动手

现在是时候自己动手了：为移动设备创建应用程序与为桌面设备创建应用程序一样容易。现在让我们将一些应用程序转换为移动设备。

## 情景 1

由于我们已经开发了一个演示共享和绘图应用程序，现在我们也将它们提供给移动设备。

### 提示

这是一个非常简单的任务：正如我们所知，我们只需更改服务器以提供客户端应用程序，然后就可以了。我们不必改变其他任何东西的原因是，我们用于应用程序的库编写得非常好，它们也可以适应移动视图。试试看。

当您在移动设备上打开演示共享应用程序时，它将是这个样子：

![情景 1](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ws-ess/img/B03854_05_03.jpg)

## 情景 2

服务器将保持不变，但您可以通过使用类似**Bootstrap**的库来调整客户端应用程序界面，使其根据设备屏幕大小进行响应。对于实时数据传输，您可以使用非常易于使用和实现的 Socket.IO API。

### 提示

**为桌面和移动创建一个聊天应用程序**

为此，您需要创建一个服务器，它只接收消息并将其广播给所有人。客户端将非常简单，以便它只向服务器发送消息。这很简单直接，但关键是您需要为桌面和移动设备制作它。

请参考以下图片。

![情景 2](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ws-ess/img/B03854_05_04.jpg)

## 情景 3

制作一个问题游戏，您可以通过使用用户界面输入问题和选项来提问。其他人将收到问题并回答。一旦回答，您将立即收到答案。

### 提示

就像聊天应用程序一样，您可以使用相同的 Socket.IO API 来发送数据。其余的都很容易——只要用户回答问题，您就可以使用 API 发送它。

# 总结

在本章中，我们已经看到了在 HTML5 中编码是多么容易，利用其特性提供设备无关的应用程序。几乎所有现代浏览器都支持 WebSockets，这使得我们在开发一致的应用程序方面变得更加容易——我们不必为不同的设备编写不同的代码。我们还看到了 Node.js 如何为不同的设备提供灵活性和良好的支持。在本章中，我们探讨了不同的移动应用程序和一些 API，这些 API 有助于我们实现 WebSockets，以及如何设置本地服务器来运行应用程序。

在下一章中，我们将看到如何使用现代工具增强 HTML5 Web 应用程序开发。
