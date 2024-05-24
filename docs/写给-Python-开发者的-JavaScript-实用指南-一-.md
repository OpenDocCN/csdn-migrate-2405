# 写给 Python 开发者的 JavaScript 实用指南（一）

> 原文：[`zh.annas-archive.org/md5/3cb5d18379244d57e9ec1c0b43934446`](https://zh.annas-archive.org/md5/3cb5d18379244d57e9ec1c0b43934446)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

在学习 Python 时，您通过学习 Python 的基础知识、其优雅和编程原则，迈出了软件工程职业生涯的第一步。在您职业生涯的下一个阶段，让我们学习如何将您的编程知识转移到 JavaScript 上，以处理前端任务，包括 UX/UI 工作、表单验证、前端动画等。您可能熟悉使用 Flask 渲染前端，但 JavaScript 将使您能够实时创建用户界面并对用户输入做出反应。

我们将深入探讨两种语言之间的差异，不仅在语法层面上，还在语义层面上：*为什么*和*何时*我们使用 JavaScript 而不是 Python，它们的关注点分离是什么，如何使用 Node.js 在前端和后端连接我们现有的 HTML 和 CSS，以创建引人入胜的用户体验，以及如何利用 Web 应用程序的所有层创建全栈应用程序。

# 本书的受众

在软件工程中，一刀切并不适用。Python 是一种适用、可扩展的语言，专为后端 Web 工作设计，但也可以引发对前端的好奇。本书是为具有 1-3 年 Python 经验的程序员编写的，他们希望扩展对前端编程世界的了解，该世界由 JavaScript 实现，并了解如何在前端和后端都使用 JavaScript（通过 Node.js）可以实现高效的编码和工作流程。

对数据类型、函数和作用域的扎实理解对于掌握本书中阐述的概念至关重要。熟悉 HTML、CSS、文档对象模型（DOM）以及 Flask 和/或 Django 将会很有帮助。

# 本书涵盖的内容

第一章，“JavaScript 进入主流编程”，我们将了解 JavaScript 的重要性。

第二章，“我们可以在服务器端使用 JavaScript 吗？当然可以！”，深入探讨了服务器端 JavaScript。JavaScript 的使用不仅限于浏览器端，还可以用于丰富、复杂的基于服务器的应用程序。

第三章，“细枝末节的语法”，是您将学习如何编写 JavaScript 以及它的语法与 Python 的不同之处的细节。

第四章，“数据及其朋友 JSON”，涵盖了数据。每个计算机程序都必须处理某种数据。您将学习如何在 JavaScript 中与数据交互。

第五章，“Hello World！及更多：您的第一个应用程序”，让您编写您的第一个 JavaScript 程序！

第六章，“文档对象模型（DOM）”，教会您如何使用网页的基础知识，以便将 JavaScript 与用户交互连接起来。

第七章，“事件、事件驱动设计和 API”，将带您超越基本交互，向您展示如何将动态数据纳入您的程序中。

第八章，“使用框架和库”，介绍了一些现代 JavaScript 程序的支架，以扩展您对行业标准应用的了解。

第九章，“解读错误消息和性能泄漏”，涵盖了错误。错误是难免的！我们应该了解一些如何处理它们并调试我们的程序的知识。

第十章，“JavaScript，前端的统治者”，更详细地介绍了 JavaScript 如何将前端整合在一起。

第十一章，“什么是 Node.js？”，深入探讨了 Node.js。由于已经研究了 JavaScript 在前端的使用，本章将探讨它在“JavaScript 无处不在”范式中使用 Node.js 的角色。

第十二章，*Node.js 与 Python 对比*，问，为什么开发人员选择 Node.js 而不是 Python？它们可以一起工作吗？我们如何安装我们需要创建和运行程序的软件包？

第十三章，*使用 Express*，介绍了 Express.js（或只是 Express），这是一个 Web 应用程序框架，被认为是 Node.js 的事实标准 Web 服务器。

第十四章，*使用 Django 的 React*，探索 Django。您可能已经将 Django 作为 Python 框架，让我们看看它与前端和后端的 JavaScript 框架有何不同。

第十五章，*将 Node.js 与前端结合*，将前端和后端连接在一起。我们将为（几乎）全栈功能构建两个小型应用程序。

第十六章，*进入 Webpack*，涉及部署工具，这对于高效的 JavaScript 至关重要。

第十七章，*安全和密钥*，深入探讨安全性。JavaScript 需要了解安全资源，那么我们该如何处理呢？

第十八章，*Node.js 和 MongoDB*，转向 MongoDB。MongoDB 是如何与 JavaScript 一起使用数据库的一个很好的例子。我们将使用它作为我们的示例 NoSQL 数据库，因为它与 JSON 数据很好地配合。

第十九章，*将所有内容放在一起*，让您使用完整的现代 JavaScript 堆栈创建最终项目。

# 要充分利用本书

由于我们将首先使用 JavaScript，因此您需要在计算机上安装代码编辑器，如 Visual Studio Code，Sublime Text 或其他通用编程环境。由于编码环境的限制，平板电脑等移动设备可能不是合适的环境，但较低配置的计算机可以使用。我们将使用命令行工具，因此熟悉 macOS 终端将会很有用；Windows 操作系统用户应下载并安装 Git Bash 或类似的终端程序，因为标准的 Windows 命令提示符将不够。

需要使用现代浏览器来使用我们的程序。推荐使用 Chrome。我们将在整个 JavaScript 工作中使用 ECMAScript 2015（也称为 ES6）。

我们将安装系统的各种其他组件，如 Node.js 和 Node Package Manager，Angular 和 React。每个必需组件的安装说明将在章节中提供。可能需要管理员权限才能完成所有安装步骤。

**如果您使用的是本书的数字版本，我们建议您自己输入代码或通过 GitHub 存储库（链接在下一节中提供）访问代码。这样做将有助于避免与复制和粘贴代码相关的任何潜在错误。**

我们的一些项目还需要访问网站，因此需要一个活跃的互联网连接。也建议具有一点幽默感。

## 下载示例代码文件

您可以从[www.packt.com](http://www.packt.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，可以访问[www.packtpub.com/support](https://www.packtpub.com/support)注册，将文件直接发送到您的邮箱。

您可以按照以下步骤下载代码文件：

1.  在[www.packt.com](http://www.packt.com)上登录或注册。

1.  选择“支持”选项卡。

1.  点击“代码下载”。

1.  在搜索框中输入书名，然后按照屏幕上的说明操作。

下载文件后，请确保使用以下最新版本解压或提取文件夹：

+   Windows 使用 WinRAR/7-Zip

+   Mac 使用 Zipeg/iZip/UnRarX

+   Linux 使用 7-Zip/PeaZip

该书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers`](https://github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还有其他代码包，来自我们丰富的图书和视频目录，可在**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**上找到。去看看吧！

## 下载彩色图片

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图片。您可以在这里下载：[`static.packt-cdn.com/downloads/9781838648121_ColorImages.pdf`](https://static.packt-cdn.com/downloads/9781838648121_ColorImages.pdf)。

## 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。这里有一个例子：“将下载的`WebStorm-10*.dmg`磁盘映像文件挂载为系统中的另一个磁盘。”

代码块设置如下：

```js
html, body, #map {
 height: 100%; 
 margin: 0;
 padding: 0
}
```

当我们希望引起您对代码块的特别关注时，相关的行或项目会以粗体显示：

```js
[default]
exten => s,1,Dial(Zap/1|30)
exten => s,2,Voicemail(u100)
exten => s,102,Voicemail(b100)
exten => i,1,Voicemail(s0)
```

任何命令行输入或输出都是这样写的：

```js
$ mkdir css
$ cd css
```

**粗体**：表示一个新术语、一个重要词或屏幕上看到的词。例如，菜单或对话框中的单词会在文本中出现。这里有一个例子：“从管理面板中选择系统信息。”

警告或重要说明会出现在这样的地方。提示和技巧会出现在这样的地方。


# 第一部分 - JavaScript 是什么？它又不是什么？

啊，JavaScript，这个神秘的东西。让我们来解开它是什么，又不是什么，因为前端几乎离不开它，而后端也喜爱它。

在这一部分，我们将涵盖以下章节：

+   第一章，*JavaScript 进入主流编程*

+   第二章，*我们可以在服务器端使用 JavaScript 吗？当然可以！*

+   第三章，*细枝末节的语法*

+   第四章，*数据和你的朋友，JSON*


# 第一章：JavaScript 进入主流编程

JavaScript 可以在客户端和服务器端运行，这意味着使用 JavaScript 与 Python 的用例会有所不同。从不起眼的开始，JavaScript 以其怪癖、优势和局限性，现在成为我们所知的交互式网络的主要支柱之一，从丰富的前端交互到 Web 服务器。它是如何成为 Web 上最重要的普遍技术之一的？为了理解 JavaScript 在前端和后端都能添加功能的强大能力，我们首先需要了解前端是什么，以及它不是什么。了解 JavaScript 的起源有助于澄清 JavaScript 的“为什么”，所以让我们来看一下。

本章将涵盖以下主题：

+   国家超级计算应用中心（NCSA）和互动的需求

+   早期网络浏览器和 10 天的原型

+   进入 Ecma 国际

+   HTML、CSS 和 JavaScript——前端的最好伙伴

+   JavaScript 如何适应前端生态系统

# 技术要求

您可以在 GitHub 上找到本章中的代码文件[`github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers`](https://github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers)。

# NCSA 和互动的需求

与 21 世纪现在拥有的丰富媒介相比，早期互联网是一个相当无聊的地方。没有图形浏览器，只有相当基本的（和神秘的）命令，早期采用者只能在一段时间内完成某些学术任务。从 ARPANET（高级研究计划局网络）开始，它旨在通过成为第一个分组交换网络之一来促进基本通信和文件传输。此外，它是第一个实现传输控制协议/互联网协议（TCP/IP）套件的网络，我们现在认为它是理所当然的，因为它在所有现代网络应用程序的幕后运行。

为什么这很重要？早期互联网是为基本和简单的目的而设计的，但自那时以来它已经发展壮大。作为 Python 开发人员，您已经了解现代网络的强大之处，因此不需要对网络的完整历史有所了解。让我们跳到我们现在所知的前端的起源。

1990 年，蒂姆·伯纳斯-李（Tim Berners-Lee）进入：发明了万维网。通过自己构建第一个网络浏览器，并与欧洲核子研究组织（CERN）创建第一个网站，闸门打开了，世界从此改变。从学术上的摆弄开始，现在已经成为全球必需品，全球数百万人依赖于互联网。不用说，在 21 世纪的今天，我们使用网络和多种形式的数字通信来进行日常生活。

伯纳斯-李创建的项目之一是 HTML——超文本标记语言。作为网站的支柱，这种基本标记语言在计算机社区中引发了重大的增长和发展。只用了几年的时间（确切地说是 1993 年），第一个我们现在称之为浏览器的迭代版本 Mosaic 发布了。它是由伊利诺伊大学厄巴纳-香槟分校的 NCSA 开发的，并且是网络发展的重要组成部分。

# 早期网络浏览器和 10 天的原型

那么，为什么是 JavaScript？显然，网络需要的不仅仅是静态数据，所以在 1995 年，Netscape Communications 的 Brendan Eich 出现了。最初的想法并不是创建一个全新的语言，而是将 Scheme 整合到 Netscape 中。这个想法被 Sun Microsystems 与 Java 的合作所取代。决定了 Eich 正在创建的这种语言会有些类似于 Java，而不是 Scheme。这个想法的起源来自 Netscape Communications 的创始人 Marc Andreessen。他觉得需要一种语言来将 HTML 与“粘合语言”结合起来，帮助处理图像、插件和——是的——交互性。

Eich 在 10 天内创建了 JavaScript 的原型（最初称为 Mocha，然后是 LiveScript）。很难相信一个 10 天的原型已经成为网络的如此重要的一部分，但这就是历史记录的事实。一旦 Netscape 开发出了一个可供生产使用的版本，JavaScript 就在 1995 年与 Netscape Navigator 一起发布了。JavaScript 发布后不久，微软创建了自己的 JavaScript 版本，称为（毫不起眼地）JScript。JScript 于 1996 年与微软的 Internet Explorer 3.0 一起发布。

现在，有两种技术在同一个领域竞争。JScript 是从 Netscape 的 JavaScript 中进行了逆向工程，但由于这两种语言的特点，浏览器之间的战争开始了，导致网站经常出现“最佳在 Netscape Navigator 中查看”或“最佳在 Internet Explorer 中查看”的标签，这是由于在一个网站上支持这两种技术涉及的技术复杂性。早期版本之间的差异只增加了。一些网站在一个浏览器中可以完美运行，在另一个浏览器中却会出现严重故障，更不用说其他竞争对手对 Netscape 和微软浏览器造成的复杂性了！早期开发人员还发现这两种技术之间的差异只加剧了武器竞赛。如果你经历过性能下降（或者更糟糕的是，你在早期像我一样使用 JavaScript），你肯定感受到了竞争版本的痛苦。每家公司以及其他第三方都在竞相创建下一个最好的 JavaScript 版本。JavaScript 的核心必须在客户端进行解释，而浏览器之间的差异导致了混乱。必须采取一些措施，而 Netscape 有一个解决方案，尽管它并不完美。

我们将在下一节中了解这个解决方案。

# 进入 Ecma International

**欧洲计算机制造商协会**（**ECMA**）在 1994 年更名为 Ecma International，以反映其精炼的目的。作为一个标准组织，它的目的是促进各种技术的现代化和一致性。部分是为了应对微软的工作，Netscape 在 1996 年与 Ecma International 接触，以标准化这种语言。

JavaScript 在 ECMA-262 规范中有文档记录。你可能已经看到过**ECMAScript**或“基于 ECMAScript 的语言”这个术语。除了 JavaScript 之外，还有更多的 ECMAScript 语言！ActionScript 是另一种基于 ECMAScript 的语言，遵循与 JavaScript 类似的约定。随着 Flash 作为一种网络技术的衰落，我们不再在实践中看到 ActionScript，除了一些离散的用途，但事实仍然存在：Ecma International 创建了标准，并用于创建不同的技术，这有助于缓解浏览器之战——至少是一段时间。

关于 JavaScript，Ecma International 最有趣的部分也许是已经编码的各种版本。迄今为止，已经有九个版本，都有不同的差异。我们将在本书中使用 ECMAScript 2015（也称为 ES6），因为它是今天网页开发工作最稳定的基线。2016-2018 版本的功能可以被一些浏览器使用，并将被介绍。

# HTML、CSS 和 JavaScript——前端的最好伙伴

每个现代网站或 Web 应用程序的核心至少包括三种技术：HTML、**层叠样式表**（**CSS**）和 JavaScript。它们是前端的“最好的朋友”，并在以下截图中进行了说明：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/9a5e3a54-0f0e-42a2-ab09-3ab748173cfe.png)

图 1.1 - 最好的朋友：HTML、CSS 和 JavaScript

这三种技术的交汇处就是我们现代网站的所在。让我们在接下来的章节中来看看这些。

## HTML，被忽视的英雄

当我们思考网络时，网站的基本结构——骨架，可以说是 HTML。然而，由于其（有意的）简单性，它经常被忽视为一种简单的技术。想象一下网站就像是一个身体：HTML 是骨架；CSS 是皮肤；我们的朋友 JavaScript 是肌肉。

HTML 的历史与网络本身的历史密不可分，因为它随着网络本身的发展不断演进，具有先进的规范、特性和语法。但 HTML 是什么？它不是一个完整的编程语言：它不能进行逻辑操作或数据操作。然而，作为一种标记语言，它对我们使用网络非常重要。我们不会花太多时间讨论 HTML，但一些基础知识会让我们走上正确的轨道。

HTML 规范由**万维网联盟**（**W3C**）控制，其当前版本是 HTML5。HTML 的语法由称为标签的元素组成，这些标签具有特定的定义，并用尖括号括起来。在 JavaScript 中使用时，这些标签描述了 JavaScript 可以读取和操作的数据节点。

HTML 对我们在 JavaScript 中的重要性是什么？JavaScript 可以使用浏览器内部的**应用程序编程接口**（**API**）即**文档对象模型**（**DOM**）来操作 HTML。DOM 是页面上所有 HTML 的程序表示，并且它规定了 JavaScript 如何操作呈现页面上的元素。与 Python 不同，JavaScript 可以在前端对用户输入做出反应，而无需与服务器进行通信；它的执行逻辑可以在前端进行。想象一下当您在网站上的表单中输入信息时。有时，有必填字段，如果您尝试提交表单，JavaScript 可以阻止向服务器提交，并给出视觉提示——例如必填框上的红色轮廓和警告消息——并告知用户信息缺失。这是 JavaScript 使用 DOM 进行交互的一个例子。我们将在后面更深入地探讨这一点，在第七章中，*事件、事件驱动设计和 API*。

这是一个简单的 HTML5 样板的例子：

```js
<!doctype html>

<html lang="en">
<head>
  <meta charset="utf-8">

  <title>My Page</title>

</head>

<body>
  <h1>Welcome to my page!</h1>
  <p>Here’s where you can learn all about me</p>
</body>
</html>
```

它本身相当易读：在标题为`title`的标签中包含了一个包含页面简单标题的字符串。在`meta`标签中，除了标签的名称外，我们还有一个元素：`charset` *属性*。HTML5 还引入了*语义*标签，它们不仅为页面提供了视觉结构，还描述了标签的目的。例如，`nav`和`footer`用于表示页面上的导航和页脚部分。如果您想在我们进行的过程中尝试 HTML、CSS 和 JavaScript，您可以使用诸如 Codepen.io 或 JSFiddle.net 之类的工具。由于我们目前只使用客户端工作，您不需要在计算机上安装编译器或其他软件。您也可以使用您喜欢的文本编辑器在本地工作，然后在浏览器中加载您的 HTML。

对于我们在 JavaScript 中的需求来说，还有一组重要的属性是`class`和`id`。这些属性为 JavaScript 访问 HTML 提供了一个高效的通道。让我们在下面的代码块中看一个更加详细的 HTML 示例：

```js
<!doctype html>

<html lang="en">
<head>
  <meta charset="utf-8">

  <title>My Page</title>

</head>

<body>
  <h1 id="header">Welcome to my page!</h1>
  <label for="name">Please enter your name:</label>
  <form>
    <input type="text" placeholder="Name here" name="name" id="name" />
    <p class="error hidden" id="error">Please enter your name.</p>
    <button type="submit" id="submit">Submit</button>
  </form>
</body>
</html>
```

这将给我们一个非常简单的页面输出，如下所示：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/c97ed1d0-da66-4260-a57a-6e4beeef7fb3.png)

图 1.2 - 一个简单的 HTML 页面

非常基础，对吧？为什么“请输入您的姓名”会重复显示？如果你注意到页面上的第二个`p`标签，它的一个类是`hidden`。然而，我们仍然可以看到它。我们需要 CSS 来帮助我们。

## CSS

如果 HTML 是我们页面的骨架，那么 CSS 就是它的“皮肤”，赋予它外观和感觉。在前端使用 JavaScript 时，必然会考虑到 CSS。在我们网站表单的示例中，红色轮廓和警告消息通常是通过切换 CSS 类触发的。以下是 CSS 的简短示例：

```js
.error {
  color: red;
  font-weight: bold;
}
```

在这个示例中，我们有一个 CSS 声明（`error`类，由其名称前面的句号表示为类），以及花括号内的两个 CSS 规则，用于字体颜色和字体粗细。现在完全掌握 CSS 结构和规则并不重要，但作为前端的 JavaScript 开发人员，你可能会与 CSS 互动。例如，切换我们的`error`类以使表单中的文本变红并加粗是 JavaScript 触发向用户发送消息的一种方式，告诉他们表单提交存在问题。

让我们将前面的 CSS 添加到我们之前的 HTML 工作中。我们可以看到这导致了以下变化：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/c0f69e97-3388-4d9e-9eda-cf0b0e5049ef.png)

图 1.3 - 添加一些 CSS

现在，我们可以看到红色和粗体的规则已经反映出来，但我们仍然可以看到段落。我们接下来的两个 CSS 规则是以下的：

```js
.hidden {
  display: none;
}

.show {
  display: block;
}
```

这更接近我们期望看到的内容。但为什么要创建一个段落然后用 CSS 隐藏它呢？

## JavaScript

现在，让我们来介绍 JavaScript。如果 JavaScript 是身体的肌肉，那么它就负责操纵骨骼（HTML）和皮肤（CSS）。我们的肌肉不能太多地改变我们的外貌，但它们肯定可以让我们处于不同的位置，扩展和收缩我们的弹性皮肤，并操纵我们的骨骼位置。通过 JavaScript，可以重新排列页面上的内容，更改颜色，创建动画等等。我们将深入探讨 JavaScript 如何与 HTML 和 CSS 交互，因为毕竟，JavaScript 就是我们现在阅读这本书的原因！

JavaScript 与 Python 相比最显著的一点是，为了对页面进行更改，Python 程序必须响应来自客户端的输入，然后浏览器会重新呈现 HTML。JavaScript 通过在浏览器中执行来避免这一点。

例如，在我们之前显示的页面中，如果用户尝试在不输入名称的情况下提交表单，JavaScript 可以移除`hidden`类并添加`show`类，此时错误消息就会显示。这是一个非常简单的例子，但它强调了 JavaScript 可以在浏览器中执行更改而无需回调服务器的想法。让我们把这些组合起来。

以下是 HTML 的示例：

```js
<!doctype html>

<html lang="en">
<head>
  <meta charset="utf-8">

  <title>My Page</title>

</head>

<body>
  <h1 id="header">Welcome to my page!</h1>
  <form>
    <label for="name">Please enter your name:</label>
    <input type="text" placeholder="Name here" name="name" id="name" />
    <p class="error hidden" id="error">Please enter your name.</p>
    <button type="submit" id="submit">Submit</button>
 </form>
</body>
</html>
```

以下是 CSS 的示例：

```js
.error {
  color: red;
  font-weight: bold;
}

.hidden {
  display: none;
}

.show {
  display: block;
}
```

现在，让我们写一些 JavaScript。目前可能还不太明白，但如果你在 JSFiddle 等编辑器中跟着做，尝试将以下 JavaScript 放入 JS 窗格中并点击运行：

```js
document.getElementById('submit').onclick = e => {
  e.preventDefault()
  if (document.getElementById('name').value === '') {
    document.getElementById('error').classList.toggle('hidden')
    document.getElementById('error').classList.toggle('show')
  }
}
```

现在，如果你运行这个并在不输入任何数据的情况下点击提交，我们的错误消息将显示。到目前为止非常简单，但恭喜你！你刚刚写了一些 JavaScript！那么，我们如何用 Python 来做到这一点呢？我们需要将表单提交到后端，评估提供的输入，并重新呈现带有错误消息的页面。

相反，欢迎来到与前端一起工作。

# JavaScript 如何适应前端生态系统

正如您所想象的那样，JavaScript 不仅仅是隐藏和显示元素。一个强大的应用程序不仅仅是一堆脚本标签——JavaScript 适应整个生命周期和生态系统，创造丰富的用户体验。我们将在第八章中使用 React 来深入探讨**单页应用程序**（**SPAs**），所以现在，让我们先打下基础。

如果您对 SPA 这个术语不熟悉，不用担心——您可能已经使用了至少几个，而没有意识到它们是什么。也许您使用谷歌的 Gmail 服务。如果是这样，稍微浏览一下，注意到页面似乎并没有进行硬刷新来从服务器获取信息。相反，它与服务器异步通信，并动态呈现内容。在等待从服务器加载内容的过程中，通常会出现一个小的旋转图标。从服务器异步加载内容并发送数据的基本范式称为**Ajax**。

Ajax，即**异步 JavaScript 和 XML**，只是一组用于客户端的技术和技巧，通过允许在后台获取和发送数据来简化用户体验。我们稍后将讨论使用 Ajax 从前端调用 API，但现在，让我们尝试一个小例子。

## 我们的第一个 Ajax 应用程序

首先，我们将使用 Flask 创建一个非常简单的 Python 脚本。如果您对 Flask 还不熟悉，不用担心——我们不会在这里详细介绍它。

这是一个`app.py`脚本的例子：

```js
from flask import Flask
import os

app = Flask(__name__, static_folder=os.getcwd())

@app.route('/')
def root():
    return app.send_static_file('index.html')

@app.route('/data')
def query():
    return 'Todo...'
```

这是我们的 HTML 和 JavaScript（`index.html`）：

```js
<!doctype html>

<html lang="en">
<head>
  <meta charset="utf-8">

  <title>My Page</title>

</head>

<body>
 <h1 id="header">Welcome to my page!</h1>
 <form>
   <label for="name">Please enter your name:</label>
   <input type="text" placeholder="Name here" name="name" id="name" />
   <button type="submit" id="submit">Submit</button>
 </form>
 <script>
   document.getElementById('submit').onclick = event => {
     event.preventDefault()
     fetch('/data')
       .then(res => res.text())
       .then(response => alert(response))
       .catch(err => console.error(err))
   }
 </script>
</body>
</html>
```

在我们分解这个之前，让我们尝试运行它，通过执行以下代码：

```js
$ pip install flask
$ export FLASK_APP=my_application
$ export FLASK_DEBUG=1
$ flask run
```

我们应该看到以下屏幕：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/54a5cfd5-4bbd-43ed-87e8-c1c722705bc1.png)

图 1.4 - 一个基本的 Flask 页面

让我们点击提交，然后应该出现以下屏幕：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/1c78b4ca-5adb-4d5a-9662-a22897b1b457.png)

图 1.5 - 将 Python 连接到 JavaScript！

我们成功地在 JavaScript 中显示了来自 Python 的文本 Todo…！让我们快速看一下我们是如何做到的。

我们的基本路由（`/`路由）将提供我们的静态`index.html`文件。太好了，现在我们可以看到我们的 HTML。但是第二个路由`/data`呢？它只是返回文本。到目前为止，它与任何基本的 Flask 应用程序并没有太大的不同。

现在，让我们看看我们的 JavaScript。首先要注意的一件事是：在我们的 HTML 文件中，我们可以用`<script>`标签包裹我们的 JavaScript。虽然将 JavaScript 存储在一个带有自己的脚本标签的单独文件中（我们会讨论到这一点），但在 HTML 中直接包含代码对于小型、快速和非生产调试目的非常方便。有时您会直接在 HTML 文件中插入代码，但这并不经常发生。现在，我们将打破最佳实践，玩一下以下片段：

```js
document.getElementById('submit').onclick = event => {
```

嗯。这是什么神秘的一行？这是一个 ES6 箭头函数的开头。我们稍后会更深入地讨论函数，但现在，让我们看看我们可以从这行中得到什么，如下所示：

+   `document.getElementById('submit')`：通过查看我们的 HTML，我们可以看到有一个带有 ID 属性`'submit'`的元素：按钮。所以，首先，我们要找到我们的按钮。

+   `.onclick`：这是一个动作动词。如果您猜到这个函数是设计为在用户点击按钮时执行操作，那么您是正确的。

至于函数的其余内容，我们可以猜到我们正在处理一个事件——涉及获取数据然后对其进行某些操作。那么，这个操作是什么？

`alert(response)`就是我们对它的处理！`alert`只是你在浏览器中看到的那些烦人的弹出消息之一，而且，我们用来显示 Flask 的数据！虽然不太*实用*，但希望你能看到我们的方向：前端并不是独立存在的——我们可以在客户端和服务器端之间来回通信，只需在任一端写几行代码。

在讨论 API 时，我们将更详细地查看`fetch`函数，但现在，让我们花一分钟来看看我们到目前为止所做的练习，如下所示：

1.  我们使用 Python 和 Flask 创建了一个小型的 Web 应用程序来提供一个简单的 HTML 页面。

1.  这个应用程序还有一个端点，用来提供一个非常简单的消息作为输出：待办事项……。

1.  使用 JavaScript，当用户点击提交按钮时我们采取了行动。

1.  点击提交按钮后，JavaScript 与 Python 应用程序通信以请求数据。

1.  返回的数据显示在警报窗口中向用户展示。

就是这样！我们成功发出了第一个 Ajax 调用。

### 实际中的 JavaScript

既然我们已经看到了 JavaScript 如何与 Python 一起使用的实际例子，让我们讨论一下它在前端领域的用途。剧透警告：我们将在下一章开始在服务器端使用 JavaScript。在我们的 Ajax 示例中遇到了一些神秘的命令，因此可能很容易忽视对 JavaScript 的使用和需求，但我们看到它是一种真正具有实际应用的语言。

JavaScript 之美的一部分在于它几乎被所有浏览器普遍采用。随着时间的推移，JavaScript 的语法和功能已经慢慢发展，但对于不同功能的支持，曾经在各个浏览器之间差异巨大，现在正在标准化。然而，仍然存在一些差异，但网上有一些有用的工具，可以及时更新浏览器可能支持或不支持的各种功能。其中一个网站是[caniuse.com](https://caniuse.com)，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/b85d0547-d160-41ad-9ce7-d9faeb1f7fb5.png)

图 1.6：caniuse.com 的屏幕截图，显示了元素滚动方法的选择。

这个网站将 JavaScript 的各种方法和属性按照各种流行的浏览器分解成矩阵，以显示每个浏览器支持（或不支持）的情况。然而，总的来说，除非你使用的是尖端功能，否则你不需要太担心你的代码是否能在特定的浏览器上运行。

现在，我们已经展示了 JavaScript 与 Python 交互的示例，作为我们的后端使用 Flask，但我们可以使用几乎任何后端系统，只要它准备好接受入站的 HTTP 流量。Python、PHP、Ruby、Java——所有的可能性都在那里，只要后端期望与前端一起工作。

关于 jQuery 等库的一点说明：我们在本书中不会使用 jQuery。虽然它对于某些方法的快捷方式和简化很有用，但它的一个主要吸引点（至少对于像我这样的许多开发人员来说）是它在浏览器之间的底层标准化。还记得我们发出的 Ajax `fetch`调用吗？过去，Ajax 调用必须以两种不同的方式编写，每种方式对应一个主要类型的 JavaScript 解释器。然而，浏览器的标准化已经缓解了大部分跨浏览器的噩梦。jQuery 仍然提供许多有用的工具，特别是对于**用户界面**（**UI**）来说，比如可以使我们无需从头开始编写组件的插件。是否使用 jQuery 或类似的库取决于你或将由项目的需求决定。像 React 这样的库，我们将会讨论，旨在满足与 jQuery 等库非常不同的需求。

# 总结

JavaScript 在现代网络中占据着重要的地位。从 NCSA 的简单起步，它现在已经成为现代网络应用的一个组成部分，无论是用于 UI、Ajax 还是其他需求。它有官方规范，并不断发展，使得与 JavaScript 一起工作变得更加令人兴奋。与 HTML 和 CSS 协同工作，它可以做的远不止简单的交互，而且可以轻松地与（几乎）任何后端系统通信。它的目的是给我们带来不仅仅是静态页面，我们希望页面能够工作。如果你跟着编码，我们做了一个简单的 Ajax 应用，虽然现在这些命令对你来说可能毫无意义，但希望你能看到 JavaScript 是相当易读的。我们将在以后深入研究 JavaScript 的语法和结构。

我们还没有讨论过 JavaScript 后端的用途，但不用担心，下面就会讨论。

# 问题

试着回答以下问题来测试你的知识：

1.  哪个国际组织维护 JavaScript 的官方规范？

1.  W3C

1.  Ecma 国际

1.  网景

1.  Sun

1.  哪些后端可以与 JavaScript 通信？

1.  PHP

1.  Python

1.  Java

1.  以上所有

1.  谁是 JavaScript 的原始作者？

1.  Tim Berners-Lee

1.  Brendan Eich

1.  Linus Torvalds

1.  比尔·盖茨

1.  DOM 是什么？

1.  JavaScript 在内存中对 HTML 的表示

1.  一个允许 JavaScript 修改页面的 API

1.  以上两者

1.  以上都不是

1.  Ajax 的主要用途是什么？

1.  与 DOM 通信

1.  操作 DOM

1.  监听用户输入

1.  与后端通信

# 进一步阅读

以下是一些资源供您参考：

+   Thoriq Firdaus，Ben Frain 和 Benjamin LaGrone。*HTML5 和 CSS3：构建响应式网站。*伯明翰：Packt Publishing，2016 年。

+   浏览器战争：[`en.wikipedia.org/wiki/Browser_wars`](https://en.wikipedia.org/wiki/Browser_wars)

+   W3C：[`www.w3.org/`](https://www.w3.org/)


# 第二章：我们可以在服务器端使用 JavaScript 吗？当然可以！

我们通常不会认为 JavaScript 存在于服务器端，因为它的大部分历史只存在于浏览器端。然而，归根结底，JavaScript *是*一种语言——而语言可以对其应用程序（在一定程度上）是不可知的。虽然从一开始就可以使用一些不同的工具在服务器端使用 JavaScript，但是**Node.js**的引入使得在服务器端使用 JavaScript 成为主流。在这里，Python 和 JavaScript 之间的相似之处比在前端更多，但在实践中两种技术的使用仍然存在显著差异。让我们来看一下 Node.js 以及我们如何利用它在服务器端的力量——以及为什么我们想要这样做！

本章将涵盖以下主题：

+   为什么要在服务器端使用 JavaScript？

+   Node.js 生态系统

+   线程和异步性

# 技术要求

您可以在 GitHub 上找到本章中的代码文件：[`github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers`](https://github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers)。

# 为什么要在服务器端使用 JavaScript？

有许多服务器端语言：Java、PHP、Ruby、Go，还有我们的朋友 Python，只是举几个例子。那么，为什么我们要使用 JavaScript 作为服务器端语言呢？一个答案是为了减少上下文切换。理论上，同一个开发人员可以用最少的心理变化来编写 Web 应用程序的前端和后端。迄今为止，关于切换编程语言的成本的研究还很少，往往是高度个人化的，但一些研究表明，从一项任务切换到另一项任务，然后再切换回来，会降低生产力，增加完成任务所需时间。换句话说，从 JavaScript 切换到 Python 需要一些心理上的运动。当然，通过实践，这种心理负担变得不重要（想象一个可以实时听取一种语言并将其翻译成另一种语言的翻译员）。然而，随着技术变化的速度，达到那种流利程度更加困难。可以说，任务之间的一致性越大，切换任务所涉及的心理负担就越小。

让我们来看一下我们讨论过的编码语言在语法和风格方面的相似之处，还有一些历史。

## 语法相似之处

开发人员喜欢使用 Node.js 的原因之一是它在语法上几乎与前端 JavaScript 相同。

让我们来看一下我们已经写过的一些代码。

这里有一个 JavaScript 代码的例子：

```js
document.getElementById('submit').onclick = event => {
  event.preventDefault()
  fetch('/data')
    .then(res => res.text())
    .then(response => alert(response))
    .catch(err => console.error(err))
}
```

现在，让我们来看一下一些完全不同的 Node.js 代码，但是具有类似的语法，点符号、花括号等。这是一个例子：

```js
const http = require('http')

http.createServer((request, response) => {
  response.writeHead(200, {'Content-Type': 'text/plain'})
  response.end('Hello World!')
}).listen(8080)
```

乍一看，这两个代码片段可能看起来并不相似，所以让我们仔细看看。在我们的 JavaScript 示例中，看看`event.preventDefault()`，然后在我们的 Node.js 示例中，看看`response.end('Hello World!')`。它们都使用**点语法**来指定父对象的**方法**（或函数）。这两行完全做着不同的事情，但我们可以根据 JavaScript 的规则来阅读它们。点语法在 JavaScript 中是一个非常重要的概念，因为它本质上是一种面向对象的语言。就像在使用面向对象的 Python 处理对象时一样，我们可以访问 JavaScript 对象的类方法和属性。就像在 Python 中一样，JavaScript 中也有类、实例、方法和属性。

那么，这个 Node.js 示例到底在做什么呢？再次，我们可以看到 JavaScript 是一种相当易读的语言！即使不太了解 Node.js 的内部，我们也可以看到我们正在创建一个服务器，发送一些东西，并监听输入。如果我们再次与 Flask 示例进行比较，如下所示，我们正在做什么：

```js
from flask import Flask, Response

app = Flask(__name__)

@app.route('/')
def main():
    content = {'Hello World!'}
    return Response(content, status=200, mimetype='text/plain')

$ flask run --port=8080
```

这两个片段的工作原理并没有本质上的不同；它们是用两种不同的语言实现相同目标的两种不同方式。

让我们看一个在客户端 JavaScript 和 Node.js 中执行相同工作的函数。我们还没有详细讨论语法，所以暂时不要让语法成为绊脚石。

这是一个 JavaScript 示例：

```js
for (let i = 0; i < 100; i++) {
  console.log(i)
}
```

这是一个 Node.js 示例：

```js
for (let i = 0; i < 100; i++) {
  console.log(i)
}
```

仔细看看这两个。这不是一个把戏：事实上，它们是相同的。将 JavaScript 版本与以下代码片段中的基本 Python 循环进行比较：

```js
for x in range(100):
    print(x)
```

我们稍后将深入探讨 JavaScript 的语法，以及为什么它看起来比其 Pythonic 对应物更长，但现在，让我们承认 Python 代码与 JavaScript 有多么*不同*。

## 更多历史

Node.js，由 Ryan Dahl 创建，最初于 2009 年发布，是 JavaScript 的开源运行时，可以在浏览器之外运行。它可能看起来很新，但在其时间内已经获得了很大的立足点，包括主要的公司。然而，大多数人不知道的一个事实是，Node.js *不是* 服务器端 JavaScript 的第一个实现。这个区别再次属于 Netscape，几年前。然而，许多人认为这种语言发展不够，因此它在这方面的使用被限制到了不存在的程度。

Dahl 试图将服务器端和客户端更紧密地联系在一起。从历史上看，应用程序的两侧之间存在着相当大的关注点分离。JavaScript 可以与前端一起工作，但查询服务器是一个持续的过程。据说 Dahl 在创建 Node.js 时受到启发，因为他对文件上传进度条必须依赖与服务器的持续通信感到沮丧。Node.js 通过提供基于*事件循环的架构*来促进这种通信，呈现了一种更顺畅的执行方式。自从创建 Node.js 以来，Dahl 已经开始创建 Deno，这是一个类似于 Node.js 的 JavaScript 和 TypeScript 运行时。然而，对于我们的目的，我们将使用 Node.js。

我们稍后将深入探讨 Node.js 使用的回调范式，我们还将看到前端 JavaScript 也使用它。

让我们通过更仔细地观察它的谚语生命周期来看看 Node.js 是如何工作的。

# Node.js 生态系统

大多数语言不是范式：只编写自包含的代码。称为**包**的独立代码模块在软件工程和开发中被广泛使用。换个角度思考，即使是一个全新的 Web 服务器也没有软件来直接提供网站服务。您必须安装软件包，如 Apache 或 nginx，甚至才能到达网站的“Hello World！”步骤。Node.js 也不例外。它有许多工具可以使获取这些软件包的过程更简单。让我们从头开始看一个使用 Node.js 的基本“Hello World！”服务器示例。我们稍后将更详细地讨论这些概念，所以现在让我们只是进行基本设置。

## Node.js

当然，我们首先需要访问语言本身。你可以通过几种方法在你的机器上获取 Node.js，包括包管理器，但最简单的方法就是从官方网站下载：[`nodejs.org`](https://nodejs.org/)。安装时，确保包括**Node Package Manager**（**npm**）。根据你的环境，在安装完成后可能需要重新启动你的机器。

安装了 Node.js 之后，确保你可以访问它。打开你的终端并执行以下命令：

```js
$ node -v
```

你应该会看到返回的版本号。如果是这样，你就准备好继续了！

## npm

Node.js 的一个优势是其丰富的开源社区。当然，这并不是 Node.js 独有的，但这是一个吸引人的事实。就像 Python 有`pip`一样，Node.js 有`npm`。有数十万个软件包和数十亿次的下载，`npm`是世界上最大的软件包注册表。当然，随着软件包的增多，就会有一系列的相互依赖关系和保持它们更新的需求，因此 npm 提供了一个相当稳定的版本管理方法，以确保你使用的软件包在一起正常运行。

就像我们测试了 Node 版本一样，我们也会测试`npm`，就像这样：

```js
$ npm -v
```

如果由于某种原因你*没有*安装`npm`，那么现在是时候研究如何安装它了，因为最初安装 Node 时并没有带有`npm`。有几种安装它的方法，比如使用 Homebrew，但最好重新查看一下你是如何安装 Node 的。

## Express.js

Express 是一个快速、流行的 Web 应用程序框架。我们将把它作为我们 Node.js 工作的基础。我们稍后会详细讨论如何使用它，所以现在让我们快速搭建一个脚手架。我们将全局安装 Express 和一个脚手架工具，如下所示：

1.  使用命令行安装 Express 生成器，通过运行以下命令：`npm install -g express express-generator`。

1.  使用生成器创建一个新目录并搭建应用程序，通过运行以下命令：`express --view=hbs sample && cd sample`。

1.  你的`sample`目录现在应该包含一个类似这样的骨架：

```js
├── app.js
├── bin
│ └── www
├── package.json
├── public
│ ├── images
│ ├── javascripts
│ └── stylesheets
│ └── style.css
├── routes
│ ├── index.js
│ └── users.js
└── views
    ├── error.hbs
    ├── index.hbs
    └── layout.hbs
```

1.  现在，我们将通过运行以下命令来安装应用程序的依赖项：`npm install`。

1.  它将下载必要的软件包，然后我们将准备启动服务器，通过运行以下命令：`npm start`。

1.  访问`http://localhost:3000/`，你应该会看到以下截图中显示的有史以来最激动人心的页面：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/1a90e2e5-80ce-4d0e-a6f0-d2d3283aeb77.png)

图 2.1 - Express 欢迎页面

恭喜！这是你的第一个 Node.js 应用程序！让我们来看看它的内部：

打开`routes`目录中的`index.js`文件，你应该会看到类似于这样的内容：

```js
var express = require('express');
var router = express.Router();

/* GET home page. */
router.get('/', function(req, res, next) {
  res.render('index', { title: 'Express' });
});

module.exports = router;
```

值得注意的是，此时你可能会注意到一些 Node.js 示例和现代 JavaScript 之间的语法差异。如果你注意到了，这些行以分号结尾，而我们之前的示例没有。我们将在后面讨论不同版本的 JavaScript，但现在，如果这让你感到惊讶，就记住这个注释。

让我们来看一下`router.get`语句，在下面的代码块中有所说明：

```js
router.get('/', function(req, res, next) {
 res.render('index', { title: 'Express' });
});
```

`get`指的是程序响应的 HTTP 动词。同样，如果我们处理 POST 数据，行的开头将是`router.post`。因此，本质上，这是在说：“嘿，服务器，当你收到对主页的请求时，用`title`变量等于`Express`来渲染 index 模板。”别担心，我们将在第十三章*使用 Express*中详细介绍这个问题，但现在，让我们玩一下：

1.  在`res.render`行之前添加一行`console.log('hello')`。

1.  将`Express`改为`My Site`。

在对 Node.js 代码进行更改时，您需要重新启动本地服务器。您可以返回到您的终端，使用*Ctrl* + *C*退出 Express，然后使用`npm start`重新启动它。当然，也有处理这个问题的进程管理器，但是现在，我们使用的是一个非常基本的实现。

再次导航到`https://localhost:3000/`。您应该会看到以下内容：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/e221d0fc-250c-460d-97ca-19cf03614e83.png)

图 2.2 - 更改后的 Express 页面

现在，让我们回到您的终端。当您访问本地主机时，您还触发了一个`console.log()`语句-一个调试打印语句。您应该会看到`hello`与 Express 提供的请求和响应一起显示在屏幕上，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/843c1443-a9c0-4f00-869c-e0f93e587ff0.png)

图 2.3 - console.log

使用控制台对我们来说将是非常宝贵的，无论是在客户端还是服务器端。这只是它可以做的一小部分！继续使用 *Ctrl* + *C* 退出。

# 线程和异步性

与传统的 Web 架构一样，了解在后端使用 Node.js 的*原因*是很重要的。

我们已经看了 Node.js 的运行方式，现在，让我们看看 Node 的客户端-服务器架构与传统范式有何不同。

## 传统的客户端-服务器架构

为了了解 Node.js 与传统架构的不同之处，让我们看一下以下请求图表：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/c0ac1cec-e2b8-4c71-9eff-f303c0130ff3.png)

图 2.4 - 传统的客户端-服务器图表

在传统的设置中，每个对服务器的请求（或连接）都会在服务器的内存中产生一个新的线程，占用系统的**随机存取内存**（**RAM**），直到达到可能的线程数量。之后，一些请求必须等待，直到有更多的内存可用。如果你不熟悉**线程**的概念，它们基本上是在计算机上运行的一小段命令。这种*多线程*范式意味着对服务器接收的每个新请求，都会在内存中创建一个新的唯一位置来处理该请求。

现在，请记住，一个*请求*不是一个完整的网页-一个页面可以有数十个请求，用于其他补充资产，如图像。在下面的截图中，看一下谷歌主页仅有 16 个请求：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/f21cef55-9e15-49ab-837c-f80ccc457f37.png)

图 2.5 - google.com 请求

为什么这很重要？简而言之：可伸缩性。每秒的请求越多，使用的内存就越多。我们都见过网站在负载下崩溃时会发生什么-一个令人讨厌的错误页面。这是我们都想要避免的事情。

## Node.js 架构

与这种范式相反，Node.js 是*单线程*的，允许进行数千次非阻塞的输入输出调用，而无需额外的开销，如下图所示：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/39249e9f-ca08-4ab9-a08f-4efeff2017bf.png)

图 2.6 - Node.js 客户端-服务器图表

然而，有一件事情需要早早注意到：这种范式并不是管理服务器上的流量和负载的万能解决方案。目前确实没有一个完全解决大量流量问题的银弹。然而，这种结构确实有助于使服务器更加高效。

Node.js 与 JavaScript 配合得如此完美的原因之一是它已经在处理**事件**的概念。正如我们将看到的，事件是 JavaScript 前端的一个强大基石，因此可以推断，通过将这个过程延续到后端，我们将看到与其他架构有些不同的方法。

# 总结

尽管在服务器上运行 JavaScript 的概念并不新鲜，但随着 Node.js 的流行、稳定性和功能的大大扩展，它的受欢迎程度也大大提高。早期，服务器端 JavaScript 被抛弃，但在 2009 年随着 Node.js 的创建再次光芒万丈。

Node.js 通过在客户端和服务器端使用相同的基本语法，减少了开发人员的上下文切换心智负担。同一个开发人员可以相当无缝地处理整个堆栈，因为客户端工作和如何在服务器上操作 Node.js 之间存在相当大的相似之处。除了方法上的差异，还有一种不同的基本范式来处理对服务器的请求，与其他更传统的实现相比。

JavaScript：不仅仅是客户端！

在下一章中，我们将深入探讨 JavaScript 的语法、语义和最佳实践。

# 问题

尝试回答以下问题来测试你的知识：

1.  真或假：Node.js 是单线程的。

1.  真或假：Node.js 的架构使其不受分布式拒绝服务（DDoS）攻击的影响。

1.  谁最初创建了 Node.js？

1.  Brendan Eich

1.  Linux Torvalds

1.  Ada Lovelace

1.  Ryan Dahl

1.  真或假：服务器端的 JavaScript 本质上是不安全的，因为代码暴露在前端。

1.  真或假：Node.js 本质上优于 Python。

# 进一步阅读

请参考以下链接以获取更多关于这个主题的信息：

+   为什么我要使用 Node.js？逐案教程：[`www.toptal.com/nodejs/why-the-hell-would-i-use-node-js`](https://www.toptal.com/nodejs/why-the-hell-would-i-use-node-js)

+   事件驱动架构：[`en.wikipedia.org/wiki/Event-driven_architecture`](https://en.wikipedia.org/wiki/Event-driven_architecture)


# 第三章：细枝末节的语法

当比较两种编程语言时，必然会有结构和语法上的差异。好消息是，Python 和 JavaScript 都是非常易读的语言，所以从 Python 切换到 JavaScript 和 Node.js 的上下文转换不应该太费力。

风格是一个很好的问题：制表符还是空格？分号还是不用？在任何编程语言中写作时出现的许多风格问题都已经在 Python 的 PEP-8 风格指南中得到了回答。虽然 JavaScript 没有官方的风格指南，但不用担心——外面并不是西部荒野。

在我们能够编写 JavaScript 之前，我们必须知道它是什么，才能够阅读和理解它。所有编程语言都有所不同，利用你的 Python 知识来学习一门新语言将需要一些思维的重新构建。例如，当我们想要声明变量时，JavaScript 是什么样子的？它是如何构建的，以便计算机能够理解？在我们进展时，我们需要注意什么？

本章是解锁 JavaScript 能做什么以及如何做的关键。

本章将涵盖以下主题：

+   风格的历史

+   语法规则

+   标点和可读性

+   房间里的大象-空白

+   现有标准-使用 linting 来拯救！

# 技术要求

要跟着本章的示例编码，你有几种选择：

+   直接在浏览器的 JavaScript 控制台中编码

+   在 Node 命令行中编码

+   使用网络编辑器，如[jsfiddle.net](https://jsfiddle.net)或[codepen.io](https://codepen.io)

使用网络编辑器可能更可取，因为你可以轻松保存你的进度。无论如何，你应该熟悉如何在浏览器中打开 JavaScript 控制台，因为我们将用它来调试输出。这通常在浏览器的“查看”菜单中；如果不是很明显，一些浏览器可能需要在“偏好设置”中打开开发者模式，所以请查阅你的浏览器文档以找到它。

你可以在 GitHub 上找到本章的代码文件，网址为[`github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-3/Linting`](https://github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-3/Linting)。

# 风格的历史

每种编程语言都有自己的风格，旨在简化每行代码的可读性和理解性。有些语言比其他语言更严格；JavaScript 在其原始形式中是较为宽松的语言之一。Brian W. Kernighan 和 P. J. Plauger 在 1974 年首次出版的《编程风格的要素》中有许多格言，这些格言不仅帮助塑造了编码标准，也塑造了编程语言本身。

你可能熟悉*Python*的 PEP-20 格言：

+   美好胜过丑陋。

+   明确比隐式更好。

+   简单比复杂更好。

+   复杂比复杂更好。

+   平面比嵌套更好。

+   稀疏比密集好。

+   可读性很重要。

+   特殊情况并不足以打破规则。

+   尽管实用性胜过纯洁性。

+   错误不应该悄悄地传递。

+   除非明确被消除。

+   面对模棱两可，拒绝猜测的诱惑。

+   应该有一种——最好只有一种——明显的方法来做到这一点。

+   尽管这种方式一开始可能不明显，除非你是荷兰人。

+   现在总比永远好。

+   尽管从来比*现在*好。

+   如果实现难以解释，那是个坏主意。

+   如果实现容易解释，那可能是个好主意。

+   命名空间是一个很棒的想法——我们应该做更多这样的事情！

开玩笑的特质抛开不谈，这些格言中的许多都是在 Python 开发之前写下的原则和经验的启发。Python 于 1991 年首次发布，从一开始就强调代码的可读性，并制定了一些严格的指导方针，从 PEP-8 到 PEP-20。

让我们举个例子，比如两个格言：

| **编程风格的要素，1974** | **Python 之禅，1999** |
| --- | --- |
| 写得清晰——不要太聪明。 | 明确比含蓄更好。 |

这里表达了类似的观点。我认为大多数软件工程师都会同意这样一种说法，即清晰、明确和可读是你在开发程序时应该追求的良好品质。

然而，有一个观点需要牢记，随着你在 JavaScript 学习中不断进步：由于 JavaScript 的语法*设计*比其他一些语言更宽松，你可能会发现不同的公司对 JavaScript 代码有自己的内部风格。这并不是 JavaScript 独有的现象——许多语言在公司中也有风格指南，以确保员工之间的代码一致性。这也有助于语言的整体生态系统具有一致的可读性。然而，这会导致不同代码库在风格上存在差异。

与任何语言一样，我们需要了解语法，以知道我们将如何编写 JavaScript。与 Python 一样，机器在执行工作之前期望得到格式正确的代码，这是你的工作。接下来是语法。

# 语法规则

就像任何其他编程语言一样，JavaScript 有语法规则必须遵循，以便计算机理解我们的代码想要告诉它的内容。这些规则相当简单明了，从大写和标点符号到使用特定结构和避免混淆含义的常用词，都可以提高代码的可读性。JavaScript 语法规则包括以下内容：

+   大写

+   保留关键字

+   变量语法

+   数据类型

+   逻辑结构

+   函数

+   标点符号

## 大小写很重要

与大多数编程语言一样，大小写有所不同。`myNode`和`mynode`变量将被解释为完全不同的变量。也就是说，计算机会完全区分`myNode`和`mynode`，因为它们的大小写不同。

## 保留关键字

JavaScript 中有许多保留的关键字不能用作变量名。以下是其中大部分的列表：

| `abstract` `arguments`

`await`

`boolean`

`break`

`byte`

`case`

`catch`

`char`

`class`

`const`

`continue`

`debugger`

`default`

`delete`

`do` | `double` `else`

`enum`

`eval`

`export`

`extends`

`false`

`final`

`finally`

`float`

`for`

`function`

`goto`

`if`

`implements`

`import` | `in` `instanceof`

`int`

`interface`

`let`

`long`

`native`

`new`

`null`

`package`

`private`

`protected`

`public`

`return`

`short`

`static` | `super` `switch`

`synchronized`

`this`

`throw`

`throws`

`transient`

`true`

`try`

`typeof`

`var`

`void`

`volatile`

`while`

`with`

`yield` |

这些关键字始终以小写形式存在，如果尝试将其中一个关键字用作变量名，程序将显示错误。

## 声明变量

在 JavaScript 中，最好在使用变量之前声明变量。这个声明可以在赋值时进行，也可以定义一个没有值的变量。

与其他一些语言不同，JavaScript 是*弱类型*的，因此不需要声明正在创建的变量的类型。按照惯例，JavaScript 中的变量以小写字母开头，采用驼峰命名法，而不是蛇形命名法。因此，`myAge`比`my_age`或`MyAge`更可取。变量不能以数字开头。

在 JavaScript 中有三个关键字用于声明变量：`const`、`let`和`var`。

### const

**const**，即**constant**，是一个在程序运行过程中不会改变值的变量。它们对于强制执行不希望更改的值很有用。在 ECMAScript 的第六版 ES2015（通常称为 ES6）之前，任何变量的值都可以被改变，因此常见的错误，比如使用赋值运算符（`=`）而不是比较运算符（`==`或`===`）：

```js
const firstName = "Jean-Luc"
const lastName = "Picard"
```

当然，皮卡德船长*可能*会改变他的名字，但这似乎不太可能。

有时，我们想将变量声明为硬常量，比如π或 API 密钥。这些用例通常是对命名标准的唯一例外，通常全部大写，有时有下划线：

```js
const PI = 3.14159
const API_KEY = 'cnview8773jass'
```

到目前为止，我们已经有了两种数据类型的示例：**字符串**和**数字**。JavaScript 没有*float*与*int*与*long*的概念；它们都是数字。如果你注意到了，我们也可以用单引号或双引号声明字符串。一些库和框架更喜欢其中一种，但对于标准的 JavaScript 来说，使用任何一种都可以。然而，最好保持一致。

### let

使用`let`声明变量时，我们明确声明我们期望或允许变量的值在程序运行过程中发生变化：

```js
let ship = "Stargazer"
ship = "Enterprise" // ship now equals "Enterprise"
```

皮卡德船长随时可以被转移到另一艘船上，所以我们希望我们的程序允许值的变化。

### var

JavaScript 中定义变量的最古老的方法是使用`var`关键字。使用`var`声明不会对变量的值施加任何限制；它可以被更改。

`var`的使用仍然受支持，但被认为是遗留的，并在 ES6 中被弃用。然而，由于存在数十年的现有程序和示例，至少熟悉`var`是很重要的。

## 数据类型

尽管 JavaScript 是弱类型的，但了解可用的数据类型对我们很重要，因为我们需要了解它们以解决比较和重新赋值等问题。

以下是基本 Python 变量到基本 JavaScript 的粗略映射：

| **Python** | **JavaScript** |
| --- | --- |
| Number | Number |
| String | String |
| List | Array |
| Dictionary | Object |
| Set | Set |

这涵盖了你可能会使用的基本类型。让我们来看看其他更微妙的 JavaScript 数据类型。有些在 Python 中有对应的，有些没有：

| **Python** | **JavaScript 半等效** | **差异原因** |
| --- | --- | --- |
| `bool` | `boolean` | 虽然在实践中数据类型是相同的，但 Python 的`bool`数据类型继承自`int`。虽然在 JavaScript 中可以使用`1`和`0`表示`True`和`False`，但它们不会被识别为`boolean`类型。 |
| `None` | `null` | 从技术上讲，`None`本身就是一个对象，而`null`是一个假值。 |
|  | `undefined` | 在 JavaScript 中，一个没有用值声明的变量仍然有一个伪值：`undefined`的单例值。 |
|  | `object` | Python 和 JavaScript 都是面向对象的语言，但它们对对象的使用有些不同。JavaScript 中对象的基本用法是键值存储。对象不是原始类型，可以存储多种类型的数据。 |
|  | `symbol` | 符号是 ES6 中的一种新数据类型。虽然使用方法有微妙之处，但值得一提。它们用于为对象创建唯一标识符。 |

现在，我们需要更多地了解一些类型，包括如何比较它们和处理它们。

### typeof 和 equality

尽管变量类型是可变的，但了解变量在某一时刻是什么数据类型通常是有用的。`typeof`运算符帮助我们做到这一点：

```js
typeof(1) // returns "number"
typeof("hello") // returns "string"
```

请注意返回值是字符串。

在比较变量时，有两种相等运算符：宽松相等和严格相等。让我们看一些例子：

```js
let myAge = 38
const age = "38"
myAge == age
```

如果我们运行这个比较，将得到 `true` 的结果。然而，我们可以看到 `myAge` 是一个数字，而 `age` 是一个字符串。结果为 `true` 的原因是，当使用宽松相等运算符（双等号）时，JavaScript 使用*类型强制转换*来试图提供帮助。当比较不同类型的变量时，值会被宽松比较，因此虽然 `38` 和 `"38"` 是不同类型，但由于它们的值，比较的结果是真值。

正如你可以想象的那样，这可能会产生一些意想不到的行为。要求 JavaScript 在比较中包含类型，使用*严格相等*运算符：三个等号。

通过前面的例子，我们可以尝试 `myAge === age`，将得到 `false` 的结果，因为它们是不同的数据类型。通常认为最佳实践是使用严格相等来避免类型强制转换，除非您有特定需要使用宽松相等。

### 数组和对象

数组和对象不是原始类型，可以包含混合类型。以下是一些示例：

```js
const officers = ['Riker','Data','Worf']

const captain = {
  "name": "Jean-Luc Picard",
  "age": 62,
  "serialNumber": "SP 937-215",
  "command": "NCC 1701-D",
  "seniorStaff": officers
}
```

`officers` 是一个**数组**，我们可以通过方括号看到。关于数组的一个有趣的事实是，即使我们通常将它们声明为常量，数组中的值可以被更改。`.push()` 和 `.pop()` 是两个用于操作数组的有用方法：

```js
officers.push('Troi') // officers now equals ['Riker','Data','Worf', 'Troi']
```

请注意，数组中的值没有以任何方式排序；我们可以通过使用方括号表示法来获取 `Riker`。然而，如果我们尝试完全重新分配数组，当重新分配已声明的常量时，我们仍然会得到一个错误。数组可以容纳任何组合的数据类型。

我们将使用的一个非常方便的数组属性是 `.length`。由于它是一个属性，它不使用括号：

```js
officers.length // now equals 4
```

请注意，即使数组是从零开始索引的，`length` 属性却不是。数组中有四个元素，索引从 0 到 3。

我们将在本章中更详细地讨论方法和属性。

**对象**是 JavaScript 非常强大的基础组件。实际上，从技术上讲，JavaScript 中的几乎所有东西都是对象！我们可以通过点符号访问数组方法，因为数组从技术上讲是一种对象。但是，我们无法通过点符号访问数组的*值*。

如果我们看 `captain`，我们可以看到三种不同的数据类型：字符串、数字和数组。对象也可以有嵌套对象。作为键值存储的一部分，键应该是一个字符串。要访问一个值，我们使用点符号：

```js
captain.command // equals "NCC 1701-D"
```

我们可以使用点符号访问对象的部分，这类似于 Python 中的**dict**，但不完全相同！随着我们使用对象，细微差别将变得更加清晰，因为它们是 JavaScript 独特之处的基础。

## 条件语句

让我们看看在 Python 和 JavaScript 中以两种方式编写的 `if`/`else` 语句：

| **Python** | **JavaScript** |
| --- | --- |

|

```js
if a < b:
  min = a
else:
  min = b
```

|

```js
let min

if (a < b) {
  min = a
} else {
  min = b
}
```

|

|

```js
min = a if a < b else b
```

|

```js
let min = (a < b) ? a : b
```

|

在两列中，代码正在执行相同的操作：简单测试以查看 `a` 是否小于 `b`，然后将较小的值分配给 `min` 变量。第一行是完整的 `if`/`else` 语句，第二行使用三元结构。这些示例中有一些语法规则需要注意：

+   `min` 必须在使用之前声明，作为最佳实践。在严格模式下，这实际上会抛出错误。

+   我们的 `if` 子句被括号包围。

+   我们的 `if`/`else` 语句被大括号包围。

+   三元运算符中的关键字和操作符与 Python 中的显着不同（并且有点更加神秘）。

如果我们想要使用我们现在了解的 `typeof`，我们可以使用严格相等来更好地理解我们的变量：

```js
let myVar = 2

if (typeof(myVar) === "number") {
  myVar++; // myVar now equals 3
}
```

## 循环

JavaScript 中有四种主要类型的循环：`for`、`while`、`do`/`while` 和 `for..in`。（还有一些其他的循环结构方式，但这些是主要的。）它们的使用情况应该不会有太多意外。

### for 循环

使用迭代器执行指定次数的代码：

| **Python** | **JavaScript** |
| --- | --- |

|

```js
names = ["Alice","Bob","Carol"]
for x in names:
    print(x)
```

|

```js
const names = ["Alice","Bob","Carol"]

for (let i = 0; i < names.length; i++) {
  console.log(names[i])
}
```

|

现在，你可能会想，“如果 JavaScript 有`for..in`循环，为什么我们不使用它呢？”事实证明，Python 的`for/in`和 JavaScript 的`for..in`是*假朋友*：它们的名字看起来很像，但在使用上却非常不同。我们将很快讨论 JavaScript 的`for..in`循环。另外，注意我们需要在`for`循环中有三个子句：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/a869732b-aee6-483a-80d5-041b081918d6.png)

图 3.1 - `for`循环的声明、条件和执行阶段

**声明**将定义一个迭代器或使用现有的可变变量。注意它应该是一个可变的数字！

我们的**条件**是我们要测试的内容。我们希望我们的循环在`i`小于`names.length`时运行。由于`name.length`是`3`，我们将运行我们的循环三次，或者直到`i`等于`4`，这不再满足我们的条件。

在我们的循环的每次迭代结束时，我们都会**执行**一些东西；通常是简单地递增我们的声明。现在注意一下我们的每个子句之间的分号…不像 JavaScript 的其他部分，这些*不*是可选的。在执行部分之后没有分号。

### while 循环

JavaScript 的`while`循环在使用上与 Python 的等效部分相同，只是语法上有一点不同：

| **Python** | **JavaScript** |
| --- | --- |

|

```js
i = 0
while i < 10:
    i += 1
```

|

```js
let i = 0
while (i < 10) {
   i++
}
```

|

### do/while 循环

正如名称所示，`do`/`while`循环在给定条件等于`true`时执行`do`代码。看一下 JavaScript：

```js
let i = 0

do {
  i++
} while (i < 10)
```

### for..in 循环

现在，我承诺要解释为什么 Python 的`for..in`与 JavaScript 的用法不同。不同之处在于 JavaScript 的`for..in`用于遍历对象中的键，而 Python 的`for..in`用作离散实体的循环。

让我们看一个例子：

```js
const officers = ['Riker','Data','Worf']

const captain = {
  "name": "Jean-Luc Picard",
  "age": 62,
  "serialNumber": "SP 937-215",
  "command": "NCC 1701-D",
  "seniorStaff": officers
}

let myString = ''

for (let x in captain) {
  myString += captain[x] + ' '
}
```

你认为`myString`现在等于多少？由于*JavaScript*中`for..in`的目的是遍历对象中的每个*键*，它是`Jean-Luc Picard 62 SP 937-215 NCC 1701-D Riker,Data,Worf`。

### for..of 循环

还有一个`for`循环：`for..of`，它与`for..in`不同。`for..of`循环遍历任何可迭代的值，比如数组、字符串、集合等。如果我们想遍历`officers`并记录每个名字，我们可以这样做：

```js
for (const officer of officers) {
  console.log(officer)
}
```

接下来，我们将讨论函数！

## 函数

啊，函数。我们喜欢它们，因为它们是模块化、**不重复自己**（**DRY**）程序的关键。JavaScript 和 Python 中的用例是一样的：代码块打算被调用多次，通常是带有不同参数。参数是函数将接受的变量，以便在可变数据集上执行其代码。参数是我们在调用函数时传递的东西。本质上它们是一样的，但根据它们在何时何地使用，有不同的词：它们是抽象，还是实际数据？让我们来看一个并排比较：

| **Python** | **JavaScript** |
| --- | --- |

|

```js
def add_one(x):
  x += 1
  return x

print(add_one(5))
// output is 6
```

|

```js
function addOne(val) {
  return ++val
}

console.log(addOne(5))
// output is 6
```

|

如果你还没有在浏览器中打开 JavaScript 控制台，现在应该打开来看看我们的输出`6`。

你可以看到结构相当相似，我们的参数被传递在括号中。如前所述，我们在 JavaScript 中更喜欢驼峰命名，并用大括号封装。使用参数`5`调用函数是一样的。为了简洁起见，我们可以在`return`执行之前使用`++`运算符在左边递增`val`。这样的快捷方式在 JavaScript 中很常见，但记住要明智地使用它们：“写得清晰—不要太聪明。”

然而，JavaScript 实际上有两种不同的声明函数的方式，还有 ES6 中引入的新语法。

### 函数声明

在前面的代码中，`addOne()`是*函数声明*的一个例子。它使用函数关键字来声明我们的功能。它的结构和看起来一样简单：

```js
function functionName(optionalParameters, separatedByCommas) {
  // do work
  // optionally return a value
}
```

### 函数表达式

这是`addOne()`的一个函数表达式的例子：

```js
const addOne = function(val) {
  return ++val
}
```

函数表达式应该在表达式中使用`const`，尽管使用`var`或`let`在语法上并不是错误的。

声明和表达式之间有什么区别？核心区别在于函数*声明*可以在程序中的任何地方使用，因为它被*hoisted*到顶部。由于 JavaScript 是自上而下解释的；这是对该范例的一个重大例外。因此，相反，使用*表达式*必须在表达式编写后发生。

### 箭头函数

ES6 引入了箭头语法来编写函数表达式：

```js
const addOne = (val) => { return ++val }
```

为了进一步复杂化问题，我们可以省略`val`周围的括号，因为只有一个参数：

```js
const addOne = val => { return ++val }
```

箭头函数和表达式之间的主要区别集中在*词法作用域*上。我们在*hoisting*中提到了作用域，并且我们将在下一章中更详细地讨论它。

## 注释

与任何语言一样，注释都很重要。在 JavaScript 中有两种声明注释的方法：

```js
const addOne = (val) => { return ++val } // I am an inline, single line comment

// I am a single comment

/*
 I am a multiline comment
*/
```

因此，我们可以用`//`开始注释，并写到行尾。我们可以用`//`进行全行注释，还可以用`/*`进行多行注释，以`*/`结束。此外，您可能会在 JSDoc 风格的注释中遇到注释，用于内联文档：

```js
/**
 * Returns the argument incremented by one
 * @example
 * // returns 6
 * addOne(5);
 * @returns {Number} Returns the value of the argument incremented by one.
 */    
```

有关 JSDoc 的更多信息包含在*进一步阅读*部分中。

## 方法和属性

到目前为止，我们已经看到`.push()`和`.pop()`作为数组实例的方法。在 JavaScript 中，**方法**只是一个固有于其数据类型的函数，它对变量的数据和属性进行操作。我之前提到过，几乎 JavaScript 中的一切都是对象，这并不夸张。从功能和语法到结构和用法，*对象*的原始数据类型与任何其他变量之间有许多相似之处。

我们对 JavaScript 语法的理解的下一部分是每个人都喜欢的：标点符号。虽然这可能看起来微不足道，但对于代码的解释，*无论是人还是计算机*，它都非常重要。

# 标点符号和可读性

与每种语言一样，JavaScript 对标点符号和空格如何影响可读性有一些约定。让我们看看一些想法：

+   **Python**：

```js
def add_one(x):
  x += 1
  return x
```

+   **Java**：

```js
int add_one(int val) {
  val += 1;
  return val;
}
```

+   **C++**：

```js
int add_one (int val)
{
  val += 1;
  return val;
}
```

+   **JavaScript**：

```js
function addOne(val) {
  return ++val
}
```

在 JavaScript 中，前面示例的约定如下：

+   函数名称和括号之间没有空格。

+   在左花括号之前有一个空格，它在同一行上。

+   右花括号单独一行，与`function`的开头语句对齐。

在这里，关于 JavaScript 和我们将在本书中使用的示例与您可能在现场和在线示例中遇到的示例之间还有一个现代观点：**分号**。

在现代 JavaScript 中，除了少数例外，语句末尾的分号是*可选的*。过去，始终用分号终止语句行是最佳实践，您会在现有代码中看到很多分号。这是一个从公司到公司、项目到项目和库到库的风格问题。有一些标准，我们将很快在 linting 中讨论，但在本书的目的上，我们将*不*使用分号来终止语句，除非在语法上需要（例如我们在循环中看到的）。

重要的是要注意，嵌套行应该缩进两个空格。两个空格和四个空格是一个风格问题，但在这本书中，我们将使用**两个空格**。帮助保持一致性的一种方法是配置您的代码编辑器将制表符转换为两个空格（或四个，根据需要）。这样，您只需按一下*Tab*，而不用担心按了空格键多少次。我不会详细阐述正确缩进的重要性，但请记住：您的代码遵循的风格和最佳实践越多，对于维护您的代码的人员以及您未来的自己来说，它就会更易读！

# 大象在房间里——空白

好的，好的，我们知道 Python 是基于空格的：制表符很重要！然而，在大多数情况下，JavaScript 真的*不在乎*空格。正如我们之前看到的，缩进和空格是*风格*而不是*语法*的问题。

所以问题是：当我第一次学习 Python 时，依赖空格的语言的想法令人憎恶。我想：“一个依赖于不正确的 IDE 设置就会崩溃的语言怎么能生存？”。撇开我的观点不谈，好消息是 Python 中的缩进与 JavaScript 中的缩进加大括号是平行的。

这里有一个例子：

| **Python** | **JavaScript** |
| --- | --- |

|

```js
def hello_world(x):
 if x > 3:
   x += 1
 else:
   x += 2
 return x
```

|

```js
function helloWorld(val) {
  if (val > 3) {
    return ++val
  } else {
    return val+2
  }
}
```

|

如果您注意到，我们 Python 函数中的`if`语句的缩进方式与此 JavaScript 示例的缩进方式相同，尽管没有大括号。所以耶！您对 Python 缩进规则的遵守实际上在 JavaScript 中*非常*有用！虽然不需要像 Python 那样包含空格，但它确实可以提高可读性。

归根结底，JavaScript 喜欢缩进就像 Python 一样，因为这样可以使代码更易读，尽管对于程序运行来说并不是必需的。

# 现有标准- linting 来拯救！

我们已经看过了 JavaScript 的约定和规范，但大多数规则都有一个“这可能会有所不同”的例外或“这在技术上并不是必需的”。那么，在一个可塑的、以意见为驱动的环境中，我们如何理解我们的代码呢？一个答案：*linting*。

简而言之，**linting**指的是通过预定义的规则运行代码的过程，以确保它不仅在语法上正确，而且还遵循适当的风格规则。这不仅限于 JavaScript 的实践；您可能也对 Python 代码进行了 linting。在现代 JavaScript 中，linting 已经被视为确保代码一致的最佳实践。社区中的两个主要风格指南是 AirBnB ([`github.com/airbnb/javascript`](https://github.com/airbnb/javascript))和 Google ([`google.github.io/styleguide/jsguide.html`](https://google.github.io/styleguide/jsguide.html))。您的代码编辑器可能支持使用 linter，但我们现在不会进入实际使用它们的细节，因为每个编辑器的设置都有所不同。以下是在 Atom 中的快速查看：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/7dd21500-86c8-4ab5-84c7-58bf85c03d90.png)

图 3.2 - Atom 中的 Linting 错误

对于我们的目的，要知道标准是存在的，尽管它们可能会因风格指南而有所不同。您可以从[`github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-3/Linting`](https://github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-3/Linting)克隆一个演示 linting 的存储库。

有几种流行的 linting 工具可用，例如 ESLint 和 Prettier。您选择的工具可以根据您选择的风格指南进行自定义。

好了，这一章内容太多了！让我们结束吧。

# 总结

JavaScript 拥有丰富的语法和语法，经过多年的使用和完善。使用 ES6，我们有各种数据类型、声明函数的方法和代码规范。虽然编写 JavaScript 似乎是非常随意和快速的，但有最佳实践，而且语言的基本原理与其他语言一样强大。请记住，大小写是有影响的；不要将保留字用作变量名；使用`const`或`let`声明变量；尽管 JavaScript 是弱类型的，但数据类型很重要；条件、循环和函数都有助于构建代码的逻辑结构。

精通 JavaScript 的语法和语法对于理解如何使用这种强大的语言至关重要，所以花时间熟悉细节和复杂性。在向前迈进时，我们将假设您对 JavaScript 的风格流利，因为我们将涉及更困难的材料。

在下一章中，我们将亲自动手处理数据，并了解 JavaScript 如何处理和建模数据。

# 问题

尝试回答以下问题来测试你的知识：

1.  以下哪个不是有效的 JavaScript 变量声明？

1.  `var myVar = 'hello';`

1.  `const myVar = "hello"`

1.  `String myVar = "hello";`

1.  `let myVar = "hello"`

1.  以下哪个开始了函数声明？

1.  `function`

1.  `const`

1.  `func`

1.  `def`

1.  以下哪个不是基本循环类型？

1.  `for..in`

1.  `for`

1.  `while`

1.  `map`

1.  真或假 - JavaScript *需要*使用分号进行行分隔。

1.  真

1.  假

1.  真或假 - 空格在 JavaScript 中*从不*计数。

1.  真

1.  假

# 进一步阅读

+   B. W. Kernighan 和 P. J. Plauger，*编程风格的要素第二版*，McGraw Hill，纽约，1978 年。 ISBN 0-07-034207-5

+   PEP-8 - *Python 代码风格指南*：[`www.python.org/dev/peps/pep-0008/`](https://www.python.org/dev/peps/pep-0008/)

+   PEP-20 - *Python 之禅*：[`www.python.org/dev/peps/pep-0020/`](https://www.python.org/dev/peps/pep-0020/)

+   JSDoc：[`usejsdoc.org/`](http://usejsdoc.org/)


# 第四章：数据和你的朋友，JSON

现在是时候学习 JavaScript 如何内部处理数据的具体细节了。这些结构大多数（几乎）与 Python 相同，但在语法和用法上有所不同。我们在第三章中提到过，*Nitty-Gritty Grammar*，但现在是时候深入了解如何处理数据、使用方法和属性了。了解如何处理数据是使用 JavaScript 的基础，特别是在进行高级工作，比如处理 API 和 Ajax 时。

本章将涵盖以下主题：

+   数据类型 - JavaScript 和 Python 都是动态类型的！

+   探索数据类型

+   数组和集合

+   对象和 JSON

+   HTTP 动词

+   前端的 API 调用 - Ajax

# 技术要求

从 GitHub 上克隆或下载本书的存储库[`github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers`](https://github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers)，并查看`Chapter-4`的材料。

# 数据类型 - JavaScript 和 Python 都是动态类型的！

在第三章中，*Nitty-Gritty Grammar*，我们讨论了使用`typeof()`来确定变量的数据类型，并使用`let`和`const`来定义它们。关于 JavaScript 有一个有趣的事实，它与 Python 共享：它们都是动态类型的。与 Java 等静态类型语言相反，JavaScript 的变量类型可以在程序运行过程中改变。这就是为什么`typeof()`会有用的一个原因。

让我们看一个快速的例子，对比 JavaScript 和 Java：

| **Java** | **JavaScript** |
| --- | --- |

|

```js
int age;
age =  38;
age = "thirty-eight";
```

|

```js
let age
age = 38
age = "thirty-eight"
```

|

如果我们尝试运行 Java 代码，我们会得到一个错误，指出类型不兼容。在 Java 中，*变量*有一个类型。然而，当我们运行 JavaScript 代码时，一切都很顺利。在 JavaScript 中，*值*有一个类型。

还要知道 JavaScript 是*弱类型*的，这意味着在大多数情况下允许数据类型之间的隐式转换。如果我们回想一下第三章中的宽松和严格相等运算符，*Nitty-Gritty Grammar*，弱类型是为什么当前的最佳实践规定在尽可能使用严格相等检查。

如果我们看一下一些语言在强/弱和动态/静态方面的比较，我们可以将这些语言绘制在这样一个轴上：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/bb1f8ae0-83e2-4a6b-8bb6-1a37426c00a2.png)

图 4.1 - 类型的轴

JavaScript 风格通常倡导使用描述性名称而不是简写名称。这是可以接受的原因之一是，通常情况下，JavaScript 代码在进入生产之前会被*缩小*。这并不完全像编译，但它确实压缩空白并重命名变量以被压缩。当我们讨论 webpack 时，我们将在第十六章，*进入 webpack*中讨论一些这些构建过程。

好的，所以 JavaScript 是动态和弱类型的。这在实践中意味着什么？简短的答案是：要小心！在比较运算符中很容易混淆类型，甚至更糟糕的是，意外地将变量转换为不同的类型。在编写程序时，这给了我们更多的灵活性，但它也可能是一个诅咒。一些开发人员喜欢使用匈牙利命名法（[`frontstuff.io/write-more-understandable-code-with-hungarian-notation`](https://frontstuff.io/write-more-understandable-code-with-hungarian-notation)）来帮助区分变量类型，但这在 JavaScript 中并不常见。帮助自己和同事保持正确类型的最好方法可能是在变量名中明确表示类型。

# 探索数据类型

让我们深入研究原始数据类型，因为它们对我们在 JavaScript 中的工作至关重要。我们不仅需要知道我们正在使用的*是什么*，而且*为什么*也很重要。我们的**原始数据类型**是语言其余部分的构建块：布尔值、数字和字符串。JavaScript 的其余部分都是建立在这些原始数据类型之上的。我们将从布尔值开始。

## 布尔值

**布尔值**可能是最简单和最通用的数据类型，因为它与二进制逻辑的 1 和 0 紧密相关。在 JavaScript 中，布尔值简单地写为`true`或`false`。不建议使用`1`或`0`作为布尔值，因为它们将被解释为数字，从而导致严格的相等失败。布尔值是一种特定的数据类型，与 Python 不同，在语言的核心部分，布尔值继承自数字。

还记得第三章中的*Nitty-Gritty Grammar*吗，我们在那里学到几乎所有 JavaScript 中的东西都是对象吗？布尔值也是如此。正如您在下面的屏幕截图中所看到的，如果您在浏览器中打开 JavaScript 控制台，很可能会自动完成，以便查看对于布尔值可用的方法：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/77521c80-1b46-4b99-a80e-590a5e05874c.png)

图 4.2 - Chrome 中的布尔自动完成

现在，我怀疑这些方法中没有一个对您特别有用，但这是一个方便的方法，可以检查对于给定变量可用的方法。

布尔值只能带我们走这么远 - 是时候看看**数字**了。

## 数字

JavaScript 没有整数、浮点数或双精度等不同类型的数字概念 - 一切都只是一个数字。所有基本算术方法都是内置的，`Math`对象提供了您期望在编程语言中找到的其余功能。这是一个例子：

```js
let myNumber = 2.14 myNumber = Math.floor(myNumber) // myNumber now equals 2
```

您还可以使用科学计数法，如下所示：

```js
myNumber = 123e5  // myNumber is 12300000
```

JavaScript 中的数字不仅仅是任意的数字，而是固有的浮点数。从技术上讲，它们存储为遵循国际 IEEE 754 标准的双精度浮点数。然而，这确实导致了一些…有趣的…怪癖。如果您得到奇怪的结果，例如下面来自 JavaScript 控制台的屏幕截图中的结果，请记住这一点：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/e62bdb66-7599-428a-bda8-57b9f3e55912.png)

图 4.3 - 浮点精度错误

一个经验法则是考虑您希望进行计算的精度。您可以使用数字的`toPrecision()`方法指定您的精度，然后使用`parseFloat()`函数，如下所示：

```js
let x = 0.2 + 0.1 // x = 0.30000000000000004
x = parseFloat(x.toPrecision(1)) // x = 0.3
```

`toPrecision()`返回一个字符串，这乍一看可能有些反直觉，但这有一个很好的理由。假设您需要您的数字有两位小数（例如，显示美元和美分）。如果您在数字上使用`toPrecision()`并返回一个数字，如果您对整数进行更多计算，它将仅呈现整数，除非您也操纵小数位。这其中是有一些方法的。

接下来是：**字符串**。我们需要向我们的程序添加一些内容！

## 字符串

啊，可敬的字符串数据类型。它具有一些您期望的基本功能，例如`length`属性和`slice()`和`split()`方法，但总是让我困惑的两个是`substr()`和`substring()`：

```js
"hello world".substr(3,5) // returns "lo wo" "hello world".substring(3,5) //  returns "lo"
```

这两种方法之间的区别在于第一个指定了`(start, length)`，而第二个指定了`(start, end index)`。记住区别的一个方便方法是`.substring()`在名称中有一个"i"，与索引相关 - 在字符串中停止的位置。

ES6 中的一个新添加使我们的生活更轻松，那就是模板文字。看看这个日志：

```js
const name = "Bob"
let age = 50
console.log("My name is " + name + " and I am " + age + " years old.")
```

它可以工作，但有点笨重。让我们使用模板文字：

```js
console.log(`My name is ${name} and I am ${age} years old.`)
```

在这个例子中有两个重要的事情需要注意：

+   字符串以反引号开始和结束，而不是引号。

+   要插入的变量被包含在`${ }`中。

模板文字很方便，但不是必需的。当您遇到问题时，在网上研究代码时，您肯定会看到以前的字符串连接方式的示例。但是，请记住，这对您来说也是一种选择。

让我们尝试一个练习！

## 练习-基本计算器

有了我们对布尔值、数字和字符串的了解，让我们构建一个基本的计算器。首先克隆存储库[`github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-4/calculator/starter-code`](https://github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-4/calculator/starter-code)。

您可以大部分时间安全地忽略 HTML 和 CSS，但是阅读 HTML 将有所帮助。让我们来看看 JavaScript：

```js
window.onload = (() => {
  const buttons = document.getElementsByTagName('button')
  const output = document.getElementsByTagName('input')[0]
  let operation = null
  let expression = firstNumber = secondNumber = 0

  output.value = expression

  const clickHandler = ((event) => {
    let value = event.target.value

    /** Write your calculator logic here.
        Use conditionals and math to modify the output variable.

        Example of how to use the operators object:
          operators'=' // returns 3

        Expected things to use:
          if/else
          switch() - https://developer.mozilla.org/en-
           US/docs/Web/JavaScript/Reference/Statements/switch
          parseFloat()
          String concatenation
          Assignment
    */

  })

  for (let i = 0; i < buttons.length; i++) {
    buttons[i].onclick = clickHandler
  }

  const operators = {
    '+': function(a, b) { return a + b },
    '-': function(a, b) { return a - b },
    '*': function(a, b) { return a * b },
    '/': function(a, b) { return a / b }
  };
})
```

这对于初学 JavaScript 的人来说并不是一个容易的练习，所以不要害怕查看解决方案代码并进行逆向工程：[`github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-4/calculator/solution-code`](https://github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-4/calculator/solution-code)。

接下来，让我们探索**数组**和 ES6 的一个新添加：**集合**。

# 数组和集合

任何编程语言都有一些关于数组或*项目集合*的概念，它们都共享一些共同的特征或用途。JavaScript 有一些这样的概念：**数组**和**集合**。这两种结构都包含项目，并且在许多方面它们的使用方式也相似，因为它们可以被枚举、迭代和显示以进行逻辑构建。

让我们首先看看数组。

## 数组

数组可以包含不同的数据类型。这是一个完全可行的数组：

```js
const myArray = ['hello',1,'goodbye',null,true,1,'hello',{ 0 : 1 }]
```

它包含字符串、数字、布尔值、`null`和一个对象。这没问题！虽然在实践中，您可能不会混合数据类型，但没有什么可以阻止您这样做。

使用`typeof()`对数组有一个怪癖：因为它们不是真正的原始值，`typeof(myArray)`将返回`object`。在编写 JavaScript 时，您应该记住这一点。

正如我们在第三章中看到的，*Nitty-Gritty Grammar*，`.push()`和`.pop()`是最有用的数组方法之一，分别用于向数组添加和删除项目。还有很多其他可用的方法。让我们来看看其中的一些。

要创建一个数组，我们可以像以前的代码一样做，也可以简单地写成`const myArray = []`。现在，虽然我们可以修改数组中的值，但我们可以将其声明为`const`，因为在大多数情况下，我们不希望让程序完全重新定义它。我们仍然可以操作数组中的值；我们只是不想破坏和重新创建它。让我们继续使用前面示例中的数组项：

```js
myArray.push('goodbye') // myArray is now ['hello',1,'goodbye',null,true,1,'hello',{ 0 : 1 }, 'goodbye']
myArray[3] // equals null
```

请记住，数组是从零开始索引的，所以我们的计数从`0`开始。

要从数组末尾删除一个元素，我们使用`.pop()`，如下所示：

```js
let myValue = myArray.pop() // myValue = 'goodbye'
```

要从数组开头删除一个对象，使用`.shift()`，如下所示：

```js
myValue = myArray.shift() // myValue now equals 'hello'
```

请注意，到目前为止介绍的所有这些方法都会直接改变原始数组。`.pop()`和`.shift()`返回被删除的值，而不是数组本身。这种区别很重要，因为并非所有的数组方法都是这样的。让我们来看看`slice`和`splice`：

```js
myValue =  myArray.slice(0,1) // myValue equals 1, and myArray is unchanged
myValue = myArray.splice(0,1,'oh no') // myValue = 1, and myArray equals ['oh no', 'goodbye', null, true, 1, 'hello',{ 0 : 1 }]
```

您可以在**MDN Web Docs**网站上查找这两种方法的参数。为了介绍这些方法，只需知道变量上的方法的行为可以从变异变为稳定。

集合与数组密切相关，但有一些细微的差别。让我们来看看。

## 集合

集合是 ES6 中引入的一种复合数据类型。集合是一个删除了重复项并禁止添加重复项的数组。尝试以下代码：

```js
const myArray = ['oh no', 'goodbye', null, true, 1, 'hello',{ 0 : 1 }]
myArray.push('goodbye')
console.log(myArray)

const mySet = new Set(myArray)
console.log(mySet)

mySet.add('goodbye')
console.log(mySet)
```

`myArray`的长度为 8，而`mySet`的长度为 7——即使在尝试添加`'goodbye'`之后也是如此。JavaScript 的集合`.add()`方法首先会测试确保正在添加的是唯一值。请注意`new`关键字和数据类型的大写；这不是创建集合的唯一方式，但很重要。在 ES5 及之前，声明新变量的常见做法是这样的，但现在除了少数情况外，这种做法被认为是遗留的。

在面试中，有一个常见的初级 JavaScript 问题，要求你对数组进行去重。您可以使用**set**一次性完成这个操作，而不是遍历数组并检查每个值。

虽然有许多可能的解决方案可以在不使用集合的情况下对数组进行去重，但让我们看一个使用`.sort()`方法的相当基本的例子。正如您可以从名称中期望的那样，这个方法将按升序对数组进行排序。如果您知道数组将包含相同数据类型的字符串或数字，则最好使用这种方法。

考虑以下数组：

```js
const myArray = ['oh no', 'goodbye', 'hello', 'hello', 'goodbye']
```

我们知道去重、排序后的数组应该如下所示：

```js
['goodbye', 'hello', 'oh no']
```

我们可以这样测试：

```js
const mySet = new Set(myArray.sort())
```

现在，让我们尝试不使用集合。这是一种使用去重函数的方法：

```js
const myArray = ['oh no', 'goodbye', 'hello', 'hello', 'goodbye']

function unique(a) {
 return a.sort().filter(function(item, pos, ary) {
   return !pos || item != ary[pos - 1]
 })
}

console.log(unique(myArray))
```

继续看一下：[`github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/blob/master/chapter-4/deduplicate/index.html`](https://github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/blob/master/chapter-4/deduplicate/index.html)。

输出是什么？我们应该得到一个长度为 3 的数组，如下所示：

```js
["goodbye", "hello", "oh no"]
```

原始方法稍微复杂一些，对吧？集合是一种更加用户友好的数组去重方式。对象是 JavaScript 中的另一种集合类型。正如承诺的那样，这里有一个更深入的介绍。

# 对象和 JSON

对象！对象是 JavaScript 的核心。如前所述，在《第三章》*Nitty-Gritty Grammar*中，几乎 JavaScript 中的所有东西，从本质上讲，都是对象。对象可能一开始会让人望而生畏，但在理论上它们很容易理解：

这是一个对象的骨架：

```js
const myObject = { key: value }
```

对象是一组*键/值对*。它们有很多用途，特别是用来包含和组织数据。让我们来看一下《第三章》中关于 Captain Picard 的例子，*Nitty-Gritty Grammar*：

```js
const captain = {
  "name": "Jean-Luc Picard",
  "age": 62,
  "serialNumber": "SP 937-215",
  "command": "NCC 1701-D",
  "seniorStaff": ['Riker','Data','Worf', 'Troi']
}
```

正如我们所见，我们可以使用点表示法来访问对象的属性，就像这样：

```js
captain.command // equals "NCC 1701-D"
```

我们还可以将其他数据类型用作值，就像`captain.seniorStaff`一样。

与其他所有东西一样，对象也有自己的方法。其中最方便的之一是`.hasOwnProperty()`：

```js
console.log(captain.hasOwnProperty('command')) // logs true
```

现在，让我们再次尝试数组去重，但这次让我们利用对象来创建一个哈希映射：

```js
const myArray = ['oh no', 'goodbye', 'hello', 'hello', 'goodbye']

function unique_fast(a) {
  const seen = {};
  const out = [];
  let len = a.length;
  let j = 0;
  for (let i = 0; i < len; i++) {
    const item = a[i];
    if (seen[item] !== 1) {
      seen[item] = 1;
      out[j++] = item;
    }
  }
  return out;
}

console.log(unique_fast(myArray))
```

让我们来看一下：[`github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/blob/master/chapter-4/deduplicate/hashmap.html`](https://github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/blob/master/chapter-4/deduplicate/hashmap.html)。现在，这种方法几乎比我们之前探讨的去重方法快了近一倍，虽然这并不是立即显而易见的。为什么呢？简而言之，对象的值可以立即在 O(1)时间内访问，而不是在 O(n)时间内遍历整个数组。如果您对大 O 符号不熟悉，这是一种计算代码复杂性的模糊方式，这里有一个很好的入门：[`www.topcoder.com/blog/big-o-notation-primer/`](https://www.topcoder.com/blog/big-o-notation-primer/)。

让我们将两种方法与一个长度为 24,975 的数组进行对比。

第一个实现，[`github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/blob/master/chapter-4/deduplicate/large.html`](https://github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/blob/master/chapter-4/deduplicate/large.html)，将在 5 到 8 毫秒之间（结果可能有所不同）。

然而，通过使用带有对象的哈希映射，我们可以将运行时间减少至少几毫秒：[`github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/blob/master/chapter-4/deduplicate/large_hashmap.html`](https://github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/blob/master/chapter-4/deduplicate/large_hashmap.html)。

现在，几毫秒可能看起来微不足道（并且不可能用肉眼区分），但想想一个需要反复运行的操作，针对相似长度的数据集。节省的时间会累积起来。

你可以查看[`stackoverflow.com/a/9229821/2581282`](https://stackoverflow.com/a/9229821/2581282)了解更多关于这个问题的想法和解释。

接下来，我们将研究一些使 JavaScript...嗯，*JavaScript*！它的继承和类的概念与其他语言有很大不同。让我们深入了解一下。

## 原型继承

JavaScript 中的继承确实是它的主要优势之一。JavaScript 使用**原型**继承，而不是经典的基于类的继承。（专业提示：它的发音是*pro-to-TYPE-al*而不是*pro-to-TYPICAL*。）这是因为它使用对象的原型作为模板。你还记得之前我们在控制台中使用字符串和数字的方法，并发现即使在简单的数据类型上，我们也有许多可用的方法吗？嗯，我们可以做得更多。

在 JavaScript 的原型继承概念中，原型链是基本的，它告诉我们在方法方面我们可以访问什么。让我们看一下图表：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/81656623-0365-4bb7-81ad-178cea0103d9.png)

图 4.4 - 原型链

那么，这意味着什么？考虑`Alice`：我们可以看到这个变量是一个字符串，因为它是从`String`原型继承而来的。因此，翻译成代码，我们可以这样说：

```js
const Alice = new String()
Alice.name = "Alice"
console.log(Alice.name)
```

我们在控制台中会得到什么？只是`Alice`。我们给了我们的`Alice`字符串对象`name`的*属性*。现在，让我们来看看原型中这个神秘的`sayHello()`方法。如果我们执行以下操作，你认为会发生什么？

```js
Alice.sayHello()
```

如果你猜到我们在`sayHello()`函数上会得到一个未定义的错误，那么你是正确的。我们还没有定义它。

这是我们通过修改`String`原型来实现的：

```js
String.prototype.sayHello = function() {
 console.log(`My name is ${this.name}.`)
}
const Alice = new String()
Alice.name = "Alice"
Alice.sayHello()
```

现在，在我们的控制台中，我们将得到`My name is Alice`。好的，发生了什么？

通过直接修改`String`原型并添加一个`sayHello()`方法，我们可以在任何字符串上使用这个方法并访问它的属性。就像我们之前使用点表示法一样，我们可以使用`this`关键字来引用我们正在工作的对象的属性。因此，在我们的原型中，`this.name`有效并等于`Alice.name`。

现在，你可能会想*这似乎有点危险*。我们正在修改一个基本数据类型，如果我们尝试在*没有*`name`属性的字符串上调用`.sayHello()`，我们将得到一个很大的错误。你是对的！有一种更好的方法可以做到这一点，而且仍然利用了原型继承的概念。看一下这个：

```js
function Person(name) {
  this.name = name

  this.sayHello = function() {
    console.log(`My name is ${this.name}.`)
  }
}

const Alice = new Person('Alice')
const Bob = new Person('Bob')

Alice.sayHello()
Bob.sayHello()
```

正如我们所期望的，我们得到了`My name is Alice.`和`My name is Bob.`。我们不需要两次定义`sayHello()`；相反，`Alice`和`Bob`从`Person`那里*继承*了这个方法。效率！

现在我们要谈谈杰森。杰森是谁？不，不，我们要检查的是基于对象的数据结构称为**JSON**。

## JSON

**JSON**（发音为*jay-sohn*或*jason*）代表**JavaScript 对象表示法**。如果你以前在现场看到过它，你可能知道它经常被用作方便的 API 传输格式。我们稍后会更详细地讨论 API，但现在让我们了解一下 JSON 是什么，以及它为什么有用。

让我们看看它是什么样子的。我们将使用**星球大战 API**（**SWAPI**）([`swapi.dev`](https://swapi.dev))作为一个方便的只读 API。看一下这个例子的结果：[`swapi.dev/api/people/1/?format=json`](https://swapi.dev/api/people/1/?format=json)：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/120bc245-bca3-4ee3-9307-b2bdc4966f25.png)

图 4.5 - SWAPI 人物实例

JSON 的一个很棒的地方是它相当易读，因为它没有像 XML 那样有很多节点和格式。然而，在它的原始格式中，就像前面的截图一样，它仍然是一团糟。浏览器有很好的工具可以将 JSON 解析成易读的树形结构。花点时间找一个安装到你的浏览器上，然后访问之前的 API 调用。现在，你的响应应该格式化如下截图所示：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/660ec1ae-7931-4696-b340-89ecda9ba8e0.png)

图 4.6 - SWAPI 格式化

现在更容易阅读了。向卢克·天行者问好！

这个 API 的作者之一的设计决定是，每个结果中只包含资源的唯一数据。例如，对于`homeworld`，它不会明确写出“塔图因”，而是提供了一个**URI**（**U****niform Resource Identifier**）用于一个*planet*资源。我们可以看到`homeworld`及其数据是键值对，就像其他对象一样，`films`是一个字符串数组，整个数据集是一个用大括号括起来的对象。这就是 JSON 的全部内容：格式正确的 JavaScript 对象。

现在是时候深入了解一些关于互联网如何工作的信息，以便更好地使用 JavaScript、API 和整个网络。

# HTTP 动词

让我们快速看一下允许我们与 API 来回通信的 HTTP 动词：

| **HTTP 动词** | **CRUD 等效** |
| --- | --- |
| POST | 创建 |
| GET | 读取 |
| PUT | 更新/替换 |
| PATCH | 更新/修改 |
| DELETE | 删除 |

虽然 API 中使用的实际动词取决于 API 的设计，但这些是许多 API 今天使用的标准 REST 术语。**REST**代表**REpresentational** **State** **Transfer**，是关于如何格式化 API 的标准描述。现在，REST 或 RESTful API 并不总是要使用 JSON 进行通信 - REST 对格式是不可知的。让我们看看实际中的 API 调用。

# 前端的 API 调用 - Ajax

**Ajax**（也拼写为 AJAX）代表**异步 JavaScript 和 XML**。然而，现在，你更可能使用 JSON 而不是 XML，所以这个名字有点误导。现在看代码：看一下[`github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/blob/master/chapter-4/ajax/swapi.html`](https://github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/blob/master/chapter-4/ajax/swapi.html)。在本地打开这个链接，在你的开发者工具中，你应该看到一个 JSON 对象，如下所示：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/3bf95b87-4173-419f-9bd5-b7d93eb3ff40.png)

图 4.7 - SWAPI Ajax 结果

恭喜！你已经完成了你的第一个 Ajax 调用！让我们来分解一下下面的代码：

```js
fetch('https://swapi.co/api/people/1/')
  .then((response) => {
    return response.json()
  })
  .then((json) => {
    console.log(json)
  })
```

`fetch`是 ES6 中一个相当新的 API，它基本上取代了使用`XMLHttpRequest`进行 Ajax 调用的旧方法，这种语法相当简洁。也许不太明显的是`.then()`函数的作用，甚至它们是什么。

`.then()`是 Promise 的一个例子。我们现在不会详细讨论 Promise，但基本前提是建立在 JavaScript 的异步部分。基本上，Promise 说：“执行这段代码，我保证以后会提供更多的数据给你。不要在这里阻塞代码执行。”

在浏览器中本地打开[`github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/blob/master/chapter-4/ajax/swapi-2.html`](https://github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/blob/master/chapter-4/ajax/swapi-2.html)。你应该会看到“加载数据…”一闪而过，然后显示 JSON。您可以使用浏览器的开发者工具来限制您的互联网连接，以查看它的运行情况。

以下是 JavaScript 代码：

```js
fetch('https://swapi.co/api/people/1/')
  .then((response) => {
    return response.json()
  })
  .then((json) => {
    document.querySelector('#main').innerHTML = JSON.stringify(json)
  })
document.querySelector('#headline').innerHTML = "Luke Skywalker"
```

不要太担心`document.querySelector`行——我们将在第六章中详细介绍这些内容，*文档对象模型（DOM）*。现在，只需了解它们用于在 HTML 文档中放置信息。让我们使用开发者工具将连接节流到慢 3G 或类似的速度。当我们刷新时，我们应该看到“等待标题…”的闪烁，然后是“卢克·天行者”，接着是“加载数据…”，*然后*，几秒钟后，JSON 作为文本。

那么，这是如何工作的呢？将代码行从“等待标题…”更改为“卢克·天行者”是在 Ajax 调用之后。那么为什么标题在数据部分之前就改变了呢？答案是*Promise*。

使用`fetch`，我们确定我们本质上使用的是异步数据，因此`.then()`语句告诉我们在承诺语句解析*之后*我们可以做什么。它使程序可以继续进行程序的其他部分。事实上，我们可以进行多次 fetch 调用，这些调用可能在不同的时间返回，但仍然不会阻止用户使用程序。异步性是使用现代 JavaScript 时的一个基本概念，所以请花时间理解它。

接下来，让我们通过实际*使用*API 来获得一些经验！现在是真正动手并与不仅是本地代码而且外部代码互动的时候了。

## SWAPI 实验室

让我们通过这个 API 进行一些实践。我们现在要做的事情可能有些不够优雅，但它将向我们展示如何利用异步行为来获得优势。

您应该期望看到类似于这样的东西：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/d0bfb7d6-c598-4c5d-a379-56e4e22f3dd7.png)

图 4.8 – SWAPI Promises result

请记住，由于我们使用了 Promise 并且必须迭代`films`数组，电影的顺序可能会有所不同。如果愿意，您可以选择按电影编号排序它们。

这个实验室将需要嵌套的 Promise 和一些我们尚未涵盖的语法，所以如果你想做这个实验，请给自己足够的时间来实验：

+   起始代码：[`github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-4/ajax-lab/starter-code`](https://github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-4/ajax-lab/starter-code)

+   解决方案代码：[`github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-4/ajax-lab/solution-code`](https://github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-4/ajax-lab/solution-code)

与任何实验室一样，请记住解决方案代码可能与您的代码不匹配，但它是作为思考过程的资源。

# 总结

数据是每个程序的核心，你的 JavaScript 程序也不例外：

+   JavaScript 是弱类型的，这意味着变量类型可以根据需要变化。

+   布尔值是简单的真/假语句。

+   数字之间没有区分整数、浮点数或其他类型的数字。

+   数组和集合可以包含大量数据，并且使我们组织数据更容易。

+   对象是高效存储数据的键值对。

+   API 调用实际上并不可怕！

我们仔细研究了数据类型、API 和 JSON。我们发现 JavaScript 中的数据非常灵活，甚至可以操作对象本身的原型。通过查看 JSON 和 API，我们成功地使用`fetch()`执行了我们的第一个 API 调用。

在下一章中，我们将进一步深入编写 JavaScript，制作一个更有趣的应用程序，并了解如何构建一个应用程序的细节！

# 问题

对于以下问题，请选择正确的选项：

1.  JavaScript 本质上是：

1.  同步的

1.  异步的

1.  两者都是

1.  `fetch()` 调用返回：

1.  `然后`

1.  下一个

1.  `最后`

1.  承诺

1.  通过原型继承，我们可以（全选）：

1.  向基本数据类型添加方法。

1.  从基本数据类型中减去方法。

1.  重命名我们的数据类型。

1.  将我们的数据转换为另一种格式。

```js
let x = !!1
console.log(x)
```

1.  从上面的代码中，预期输出是什么？

1.  1

1.  `false`

1.  `0`

1.  `true`

```js
const Officer = function(name, rank, posting) {
  this.name = name
  this.rank = rank
  this.posting = posting
  this.sayHello = () => {
    console.log(this.name)
  }
}

const Riker = new Officer("Will Riker", "Commander", "U.S.S. Enterprise")
```

1.  在上面的代码中，输出 `Will Riker` 的最佳方法是什么？

1.  `Riker.sayHello()`

1.  `console.log(Riker.name)`

1.  `console.log(Riker.this.name)`

1.  `Officer.Riker.name()`

# 进一步阅读

有关静态与动态类型语言的更多信息，您可以参考 [`android.jlelse.eu/magic-lies-here-statically-typed-vs-dynamically-typed-languages-d151c7f95e2b`](https://android.jlelse.eu/magic-lies-here-statically-typed-vs-dynamically-typed-languages-d151c7f95e2b)。

要了解更多关于匈牙利命名法的信息，请参考 [`frontstuff.io/write-more-understandable-code-with-hungarian-notation`](https://frontstuff.io/write-more-understandable-code-with-hungarian-notation)。
