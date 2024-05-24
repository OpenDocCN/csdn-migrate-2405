# jQueryMobile Web 开发基础知识（一）

> 原文：[`zh.annas-archive.org/md5/9E8057489CB5E1187C018B204539E747`](https://zh.annas-archive.org/md5/9E8057489CB5E1187C018B204539E747)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 序言

# 什么是 jQuery Mobile？

在将近两年之前的 2010 年 8 月 11 日，John Resig（jQuery 的创建者）宣布了 jQuery Mobile 项目。虽然重点是 UI 框架，但这也是对 jQuery 本身作为移动网站工具的认可，以及将对核心框架本身进行工作，使其在设备上运行更顺畅。随着版本的发布，jQuery Mobile 项目逐渐演变成一个强大的框架，每次更新都融合了更多的平台、更多的功能和更好的性能。

但是当我们说 *UI 框架* 时，我们是指什么？这对开发人员和设计师意味着什么？jQuery Mobile 提供了一种将常规 HTML（和 CSS）转换为移动友好站点的方法。正如您将很快在第一章中看到的，您可以取一个常规的 HTML 页面，加入 jQuery Mobile 所需的部分（基本上是五行 HTML），然后发现您的页面立即转变为移动友好版本。

与其他框架不同，jQuery Mobile 专注于 HTML。事实上，作为与 jQuery 绑定的框架，您可以在不写一行 JavaScript 的情况下完成大量工作。这是一种强大、实用的创建移动网站的方式，任何现有 HTML 开发人员都可以在几小时内掌握并调整。将此与其他框架进行比较，比如 Sencha Touch。Sencha Touch 也是一个强大的框架，但其方法与众不同，使用 JavaScript 来帮助定义和布局页面。jQuery Mobile 对于熟悉 HTML 而不是 JavaScript 的人更加友好。jQuery Mobile 是*触摸友好*的，这对于任何曾经使用过智能手机并苦于在网站上点击准确位置的人都是有意义的。对于任何无意中点击重置按钮而不是提交按钮的人也是有意义的。jQuery Mobile 将增强您的内容以帮助解决这些问题。常规按钮变成了大、厚实且易于点击的按钮。链接可以转变为基于列表的导航系统。内容可以分割成具有平滑动画效果的虚拟页面。您会惊讶地发现，jQuery Mobile 几乎不需要编写代码就能工作得很好。

jQuery Mobile 有一些非常大的赞助商。它们包括诺基亚、黑莓、Adobe 和其他大公司。这些公司投入了资金、硬件和开发资源，以帮助确保该项目的成功： 

![什么是 jQuery Mobile?](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_Preface_01.jpg)

## 成本是多少？

啊，百万美元问题。幸运的是，这个问题很容易回答：什么也不需要。像 jQuery 本身一样，jQuery Mobile 完全免费供任何目的使用。不仅如此，它完全开源。不喜欢某些功能的工作方式？您可以更改它。希望有些框架不支持的功能？您可以添加它。公平地说，深入挖掘代码库可能是大多数人不太愿意做的事情。然而，您需要知道的是，如果有需要，您可以这样做，而其他人也可以这样做，这导致了一个社区可以共同开发的产品。

## 您需要了解什么？

最后，除了不花一分钱获取并使用 jQuery Mobile 外，最好的事情可能是您可能已经具备了使用该框架所需的所有技能。正如您将在接下来的章节中看到的，jQuery Mobile 是基于 HTML 的框架。如果您了解 HTML，即使只是简单的 HTML，您也可以使用 jQuery Mobile 框架。了解 CSS 和 JavaScript 是一种优势，但并非完全必需的。（虽然 jQuery Mobile 在幕后使用了大量 CSS 和 JavaScript，但您实际上不必自己编写任何内容！）

## 那么原生应用程序呢？

jQuery Mobile 并不创建原生应用程序。您将在本书后面看到，如何将 jQuery Mobile 与 *包装器* 技术（如 PhoneGap）结合起来创建原生应用程序，但总的来说，jQuery Mobile 是用于构建网站的。关于开发网站还是移动应用程序的问题并非本书可以回答的。您需要查看您的业务需求并确定哪种方式会满足它们。因为我们不是在构建移动应用程序本身，所以您不必担心在 Google 或 Apple 上设置任何帐户，也不必为市场支付任何费用。任何带有浏览器的移动设备用户都可以查看您的移动优化网站。

再次强调 - 如果您想使用 jQuery Mobile 开发真正的移动应用程序，这绝对是一个选项。

## 求救！

虽然我们希望这本书涵盖您所有 jQuery Mobile 需要的每一个可能的主题，但很可能会有一些我们无法涵盖的内容。如果您需要帮助，有几个地方您可以尝试。

其次，jQuery Mobile 文档 ([`jquerymobile.com/demos/1.0/`](http://jquerymobile.com/demos/1.0/))，涵盖了语法、功能和一般开发，与本书类似。虽然内容可能有些重复，但如果您在这里发现有些内容令人困惑，请尝试官方文档。有时，第二个解释确实可以帮助理解。

首先，jQuery Mobile 论坛 ([`forum.jquery.com/jquery-mobile`](http://forum.jquery.com/jquery-mobile))，是一个开放式讨论列表，讨论 jQuery Mobile 主题。这是提问的完美场所。此外，这也是了解其他人遇到的问题的好地方。您甚至可能能够帮助他们。学习新主题的最佳方式之一就是帮助他人。

## 例子

想要看看 jQuery Mobile 的实际效果吗？有一个网站可以满足您。JQM Gallery ([`www.jqmgallery.com/`](http://www.jqmgallery.com/))，是用户提交的使用 jQuery Mobile 构建的网站集合。毫不奇怪，这个网站也使用了 jQuery Mobile，这使它成为另一种抽样 jQuery Mobile 的方式：

![示例](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_Preface_03.jpg)

# 本书涵盖内容

第一章，*准备您的第一个 jQuery Mobile 项目*，指导您完成第一个 jQuery Mobile 项目。它详细说明了必须添加到项目目录和源代码中的内容。

第二章，*处理 jQuery Mobile 页面*，延续了上一章的工作，并介绍了 jQuery Mobile 页面的概念。

第三章，*用页眉、页脚和工具栏增强页面*，解释了如何使用精美格式化的页眉和页脚增强您的页面。

第四章，*列表处理*，描述了如何创建 jQuery Mobile 列表视图。这些是移动优化的列表，特别适用于导航。

第五章，*实践 —— 构建一个简单的酒店移动网站*，引导您创建您的第一个“真实”（尽管简单）的 jQuery Mobile 应用程序。

第六章，*处理表单和 jQuery Mobile*，解释了使用 jQuery Mobile 优化的表单的过程。布局和特殊表单功能都有详细介绍。

第七章，*创建模态对话框、网格和可折叠块*，指导您使用 jQuery Mobile 特有的用户界面项目来创建基于网格的布局、对话框和可折叠内容区域。

第八章，*jQuery Mobile 配置、工具和 JavaScript 方法*，描述了您的代码可能需要的各种基于 JavaScript 的实用工具。

第九章，*处理事件*，详细说明了由各种 jQuery Mobile 相关功能引发的事件，例如页面加载和卸载。

第十章，*进一步操作 Notekeeper 移动应用程序*，指导您完成创建另一个网站的过程，一个增强了 HTML5 的笔记应用程序。

第十一章，*增强 jQuery Mobile*，演示了如何通过选择和创建独特主题来更改您的 jQuery Mobile 站点的默认外观。

第十二章, *创建原生应用*，将之前学习的内容进行扩展，说明如何使用开源项目 PhoneGap 创建真正的原生应用。

第十三章, *成为专家 ­ 构建一个 RSS 阅读器应用*，通过创建一个可以让您在移动设备上添加和阅读 RSS 订阅的应用，对之前的章节进行了拓展。

# 您为本书所需的内容

无需什么！技术上您需要一台计算机，还有一个浏览器，但是 jQuery Mobile 是用 HTML、CSS 和 JavaScript 构建的。与框架一同工作时不需要集成开发环境（IDE）或特殊工具。如果您的系统上有任何编辑器（所有操作系统都包括某种免费编辑器），您都可以使用 jQuery Mobile 进行开发。

有一些可以帮助您更加高效的好的集成开发环境。例如，Adobe Dreamweaver CS 5.5 可以原生支持 jQuery Mobile，包括代码辅助和设备预览：

![您为本书所需的内容](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_Preface_02.jpg) 

总的来说，您可以免费使用 jQuery Mobile 进行开发。您可以免费下载、开发和发布 jQuery Mobile 站点。

# 本书适合人群

本书适用于任何希望拥抱移动开发并将技能扩展到桌面之外的人。

# 惯例

在本书中，您会发现一些文本样式，用于区分不同类型的信息。以下是这些样式的一些示例，以及它们的含义解释。

文本中的代码词显示如下："注意到添加到 `div` 标签的新`data-title`标签。"

代码块设置如下：

```js
<html>
<head>
<meta name="viewport" content="width=device-width, initial- scale=1">
<title>Multi Page Example</title>

```

**新术语**和**重要单词**以粗体显示。屏幕上看到的单词，比如菜单或对话框中出现的单词，如下文所示："想象一下我们的**Megacorp**页面。它有三个页面，但**产品**页面是单独的 HTML 文件。"

### 注意 

警告或重要说明会以这样的方式显示。

### 提示

提示和技巧以这种方式出现。


# 第一章：准备你的第一个 jQuery Mobile 项目

你知道 jQuery Mobile 是什么，它的历史以及它的特点和目标。现在我们实际上要构建我们的第一个 jQuery Mobile 网站（好吧，网页），看看它的使用是多么简单。

在本章中我们将：

+   创建一个简单的 HTML 页面

+   将 jQuery Mobile 添加到页面中

+   利用自定义数据属性（data-*）

+   更新 HTML 以利用 jQuery Mobile 认可的数据属性

# 重要的初步要点

你可以在你从 Github 下载的 ZIP 文件的 c1 文件夹中找到本章的所有源代码。如果你想手工输入所有内容，我们建议你使用类似的文件名。

# 构建一个 HTML 页面

让我们从一个不是移动优化的简单网页开始。明确地说，我们并不是说它不能在移动设备上使用。完全不是。但是在移动设备上可能*使用起来*可能不太方便。它可能很难阅读（文本太小）。它可能太宽。它可能使用在触摸屏上工作不好的表单。我们根本不知道会有什么样的问题，直到我们开始测试。（我们都在移动设备上测试过我们的网站，看看它们的工作情况，对吧？）

让我们看一看 `列表 1-1：`

```js
Listing 1-1: test1.html
<html>
<head>
<title>First Mobile Example</title>
</head>
<body>
<h1>Welcome</h1>
<p>
Welcome to our first mobile web site. It's going to be the best site you've ever seen. Once we get some content. And a business plan. But the hard part is done!
</p>
<p>
<i>Copyright Megacorp &copy; 2012</i>
</p>
</body>
</html>

```

正如我们所说的，没有什么太复杂的，对吧？让我们在浏览器中快速看一下这个：

![构建一个 HTML 页面](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_01_01.jpg)

### 注意

您还可以从您在 [`www.packtpub.com`](http://www.packtpub.com) 购买的所有 Packt 图书的帐户中下载示例代码文件。如果您在其他地方购买了这本书，您可以访问 [`www.packtpub.com/support`](http://www.packtpub.com/support) 并注册，将文件直接发送到您的邮箱。

没那么糟糕，对吧？但是让我们在移动模拟器中看看同样的页面：

![构建一个 HTML 页面](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_01_02.jpg)

哇，这太小了。你可能在移动设备上以前见过这样的网页。当然，你通常可以使用捏和缩放或双击操作来增大文本的大小。但是最好立即以移动友好的视图呈现页面。这就是 jQuery Mobile 的作用所在。

# 获取 jQuery Mobile

在前言中，我们谈到了 jQuery Mobile 只是一组文件。这并不是为了减少创建这些文件所需的工作量，或者它们有多么强大，而是为了强调使用 jQuery Mobile 意味着您不需要安装任何特殊工具或服务器。您可以下载这些文件并简单地将它们包含在您的页面中。如果这样做对您来说太麻烦，您甚至有一个更简单的解决方案。jQuery Mobile 的文件托管在内容交付网络（CDN）上。这是他们托管的资源，并保证（尽可能保证）在线并可用。已经有多个网站在使用这些 CDN 托管的文件。这意味着当用户访问您的站点时，他们已经在他们的缓存中具有了这些资源。对于本书，我们将使用 CDN 托管的文件，但是对于这个第一个示例，我们将下载并提取这些文件。我建议无论如何都这样做，因为有时候当您在飞机上时想要迅速创建一个移动站点时。

要获取这些文件，请访问 [`jquerymobile.com/download`](http://jquerymobile.com/download)。这里有几个选项，但您需要选择 ZIP 文件选项。继续下载该 ZIP 文件并解压缩它。（您之前从 Github 下载的 ZIP 文件已经包含了一份拷贝。）下面的截图演示了从 ZIP 文件中提取文件后应该看到的内容：

![获取 jQuery Mobile](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_01_03.jpg)

### 注意

重要说明：在撰写本书时，jQuery Mobile 正在准备发布 1.1 版本。已发布的版本是 1.0.1。但是，由于 1.1 版本即将发布，因此正在使用该版本。显然，在您阅读本书时，可能会发布更高版本。您在前面截图中看到的文件名是特定于版本的，因此请记住它们在您那里可能会有所不同。

注意 ZIP 文件包含了用于 jQuery Mobile 的 CSS 和 JavaScript 文件，以及它们的压缩版本。通常情况下，在生产应用程序中您会想要使用压缩版本，在开发过程中使用常规版本。图像文件夹包含了 6 张图像，在生成移动优化页面时由 CSS 使用。因此，明确地说，整个框架，以及本书余下部分将要讨论的所有功能，都将由 8 个文件的框架组成。当然，您还需要包含 jQuery 库。您可以在 [www.jquery.com](http://www.jquery.com) 分别下载。

# 实现 jQuery Mobile

好的，我们已经获取了这些文件，如何使用它们呢？要将 jQuery Mobile 支持添加到网站中，至少需要以下三个步骤：

1.  首先在页面中添加 HTML 5 doctype：`<!DOCTYPE html>`。这用于帮助通知浏览器将要处理的内容类型。

1.  添加视口元标记：`<meta name="viewport" content="width=device-width, initial-scale="1">`。这有助于在移动设备上查看页面时设置更好的默认值。

1.  最后 - 必须将 CSS、JavaScript 库和 jQuery 本身包含到文件中。

让我们看看修改后的上一个 HTML 文件，添加了以上所有内容：

```js
Listing 1-2: test2.html
<!DOCTYPE html>
<html>
<head>
<title>First Mobile Example</title>
<meta name="viewport" content="width=device-width, initial- scale=1">
<link rel="stylesheet" href ="jquery.mobile-1.1.0-rc.1.css" />
<script type="text/javascript" src ="http://code.jquery.com/jquery-1.7.1.min.js"></script>
<script type="text/javascript" src="img/jquery.mobile-1.1.0- rc.1.min.js"></script>
</head>
<body>
<h1>Welcome</h1>
<p>
Welcome to our first mobile web site. It's going to be the best site you've ever seen. Once we get some content. And a business plan. But the hard part is done!
</p>
<p>
<i>Copyright Megacorp &copy; 2012</i>
</p>
</body>
</html>

```

大部分情况下，这个版本和`listing 1`完全一样，只是增加了 doctype、CSS 链接和我们的两个 JavaScript 库。请注意，我们指向了托管版本的 jQuery 库。混合本地 JavaScript 文件和远程文件是完全可以的。如果你想确保可以离线工作，你也可以简单地下载 jQuery 库。

因此，在`body`标签之间的代码没有变化，但是在浏览器中现在会有一个完全不同的视图。下面的截图显示了安卓手机浏览器现在如何呈现该页面：

![实现 jQuery Mobile](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_01_04.jpg)

立即看到了一些差异。最大的区别是文本的相对大小。注意它有多大，更容易阅读。正如我们所说，用户可以放大上一个版本，但许多移动用户并不知道这种技巧。这个页面立即加载，更适用于移动设备。

# 使用数据属性操作

正如我们在前面的例子中看到的，只需添加 jQuery Mobile 就可以大大更新我们页面以支持移动设备。但是，要真正为移动设备准备我们的页面，还涉及到更多工作。在本书的过程中，我们将使用各种数据属性来标记我们的页面，使其符合 jQuery Mobile 的要求。但是数据属性是什么？

HTML5 引入了数据属性的概念，作为向 DOM（文档对象模型）添加临时值的一种方式。例如，这是一个完全有效的 HTML：

```js
<div id="mainDiv" data-ray="moo">Some content</div>

```

在上一个 HTML 中，`data-ray`属性是完全虚构的。但是，因为我们的属性以`data-`开头，所以它也是完全合法的。那么当你在浏览器中查看时会发生什么？什么也不会发生！这些数据属性的目的是与其他代码集成，比如 JavaScript，它基本上可以对它们做任何想做的事情。因此，例如，你可以编写 JavaScript 来查找 DOM 中具有`data-ray`属性的每个项目，并将背景颜色更改为值中指定的任何值。

这就是 jQuery Mobile 的作用，大量使用数据属性，既用于标记（创建微件）也用于行为（控制链接点击时发生的事情）。让我们看看在 jQuery Mobile 中数据属性的主要用法之一 - 定义页面、标题、内容和页脚：

```js
Listing 1-3: test3.html
<!DOCTYPE html>
<html>
<head>
<title>First Mobile Example</title>
<meta name="viewport" content="width=device-width, initial- scale=1">
<link rel="stylesheet" href ="jquery.mobile-1.1.0-rc.1.css" />
<script type="text/javascript" src ="http://code.jquery .com/jquery-1.7.1.min.js"></script>
<script type="text/javascript" src="img/jquery. mobile-1.1.0-rc.1.min.js"></script>
</head>
<body>
<div data-role="page">
<div data-role="header">Welcome</div>
<div data-role="content">
<p>
Welcome to our first mobile web site. It's going to be the best site you've ever seen. Once we get some content. And a business plan. But the hard part is done!
</p>
</div>
<div data-role="footer">
<i>Copyright Megacorp &copy; 2012</i>
</div>
</div>
</body>
</html>

```

将以前的代码片段与`listing 1-2`进行比较，您会发现主要的区别在于增加了`div`块。一个`div`块定义了页面。请注意，它包裹了`body`标签中的所有内容。在`body`标签内，有三个单独的`div`块。一个具有"header"角色，另一个具有"content"角色，最后一个标记为"footer"角色。所有块都使用`data-role`，这应该能给你一个线索，我们为每个块定义了一个角色。正如我们在上面所述，这些数据属性对浏览器本身并没有意义。但让我们看一下当 jQuery Mobile 遇到这些标签时会发生什么：

![使用数据属性](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_01_05.jpg)

请立即注意到，现在页眉和页脚都有黑色背景。这使它们从其他内容中更加突出。说到内容，页面文本现在与两侧之间有一些空白。一旦应用了识别的`data-roles`的`div`标签，所有这些都是自动完成的。这是一个主题，我们在本书中会一再看到。你将要做的绝大部分工作将涉及使用数据属性。

# 概要

在本章中，我们谈到了网页在移动浏览器中可能并不总是呈现良好。我们谈论了简单使用 jQuery Mobile 如何可以极大改善网站的移动体验。具体来说，我们讨论了如何下载 jQuery Mobile 并将其添加到现有的 HTML 页面，HTML 中的数据属性的含义，以及 jQuery Mobile 如何利用数据属性来增强您的页面。在下一章中，我们将在此基础上进行构建，并开始处理链接和多个内容页面。


# 第二章：使用 jQuery Mobile 页面

在上一章中，您看到了向简单 HTML 页面添加 jQuery Mobile 有多么容易。虽然每个网站仅由一个页面组成会很好，但实际网站由多个通过链接连接的页面组成。jQuery Mobile 使得使用多个页面变得简单，并提供了许多不同的方式来创建和链接这些页面。

在本章中，我们将：

+   将多个页面添加到一个 jQuery Mobile 文件中

+   讨论 jQuery Mobile 如何修改链接（以及如何禁用它）

+   演示如何链接和添加额外文件到 jQuery Mobile 站点

+   讨论 jQuery Mobile 如何自动处理 URL 以便于简单的书签标记

# 重要的初步要点

如上一章所述，本章所有代码都可通过在 Github 下载的 ZIP 文件获取。

# 将多个页面添加到一个文件中

在上一章中，我们处理了一个具有简单文本页面的文件。对于我们的第一个修改，我们将向文件中添加另一页并创建一个链接到它。如果你还记得，jQuery Mobile 寻找一个特定的`<div>`包装器来帮助它知道你的页面在哪里：`<div data-role="page">`。jQuery Mobile 如此简单易用的原因在于我们可以通过简单地添加另一个具有相同格式的 div 来添加另一页。以下代码段 `Listing 2-1` 显示了此功能的一个简单示例：

```js
Listing 2-1: test1.html
<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial- scale=1">
<title>Multi Page Example</title>
<link rel ="stylesheet" href="http://code.jquery.com/mobile/ latest/jquery.mobile.min.css" />
<script src ="http://code.jquery.com/jquery- 1.7.1.min.js"></script>
<script src ="http://code.jquery.com/mobile/latest/ jquery.mobile.min.js"></script>
</head>
<body>
<div data-role="page" id="homePage">
<div data-role="header">Welcome</div>
<div data-role="content">
<p>
Welcome to our first mobile web site. It's going to be the best site you've ever seen. Once we get some content. And a business plan. But the hard part is done!
</p>
<p>
You can also <a href= "#aboutPage">learn more</a> about Megacorp.
</p>
</div>
<div data-role="footer">
<i>Copyright Megacorp &copy; 2012</i>
</div>
</div>
<div data-role="page" id="aboutPage">
<div data-role="header">About Megacorp</div>
<div data-role="content">
<p>
This text talks about Megacorp and how interesting it is. Most likely though you want to
<a href= "#homePage">return</a> to the home page.
</p>
</div>
<div data-role="footer">
<i>Copyright Megacorp &copy; 2012</i>
</div>
</div>
</body>
</html>

```

好的，像往常一样，我们从一些必需的内容开始：HTML5 文档类型，meta 标签，一个 CSS 包含以及两个 JavaScript 文件。这在上一章已经涵盖了，我们不会再提及它。请注意，此模板切换到了 CSS 和 JavaScript 库的 CDN 版本：

```js
<link rel="stylesheet" href="http://code.jquery.com/ mobile/latest/jquery.mobile.min.css" />
<script src="img/jquery-1.7.1.min.js"></script>
<script src="img/ jquery.mobile.min.js"></script>

```

这些版本由 jQuery 团队托管，并具有始终是最新版本的好处。大多数情况下，您的访问者在到达您的移动站点之前已经加载了这些库，因此它们存在于他们的缓存中。虽然这是我们在进一步的示例中要采取的路线，但请记住，您始终可以使用您下载的版本。

现在请注意我们有两个`<div>`块。第一个与上一个示例没有太多变化。我们添加了一个唯一的 ID（`homepage`），以及一个第二段落。请注意第二段落中的链接。它使用了标准的内部链接（`#aboutPage`）告诉浏览器我们只想简单地将浏览器滚动到页面的那部分。指定的目标 `aboutPage` 在另一个 `div` 块中定义在下面。

在传统的网页中，这将显示为页面上的两个主要文本块。点击其中任何一个链接将简单地使浏览器上下滚动。然而，jQuery Mobile 将在这里做一些显著不同的事情。下图显示了页面在移动浏览器中的渲染方式：

![将多个页面添加到一个文件中](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_02_01.jpg)

注意到了吗？即使我们的 HTML 包含了两个文本块（两个`<div>`块），但它只渲染了一个。jQuery Mobile 总是显示它找到的第一个页面，并且仅显示该页面。最棒的部分来了。如果你点击链接，第二个页面将自动加载。使用你设备上的返回按钮，或者简单点击链接，将带你回到第一个页面。你还会注意到平滑的过渡效果。这是你稍后可以配置的内容。但所有这些交互，页面的显示和隐藏，过渡，都是由 jQuery Mobile 自动完成的。现在是谈论链接以及点击它们时 jQuery Mobile 所做的事情的好时机。

# jQuery Mobile、链接和你

当 jQuery Mobile 遇到一个简单的链接 `(<a href= "something.html"> Foo</a>)` 时，它会自动捕获对该链接的任何点击，并将其更改为基于 Ajax 的加载。这意味着如果它检测到目标是页面上的某个东西，也就是说，我们上面使用的 hashmark 样式 (`href="#foo"`) 链接，它将处理将用户过渡到新页面。如果它检测到一个指向同一服务器上另一个文件的页面，则会使用 Ajax 加载页面并替换当前可见的页面。

如果你链接到外部网站，那么 jQuery Mobile 将保持链接不变，正常的链接行为将发生。可能会有时候你想要完全禁用 jQuery Mobile 对你的链接的任何操作。在这种情况下，你可以利用一个数据属性，让框架知道它根本不应该做任何事情。一个例子：

```js
<a href= "foo.html" data-ajax="false">Normal, non-special link</a>

```

正如我们在第一章中看到的*准备您的第一个 jQuery 移动项目*，jQuery Mobile 大量使用数据属性。它还非常擅长让你禁用你不喜欢的行为。当我们在本书中继续阅读时，你会看到一个又一个的例子，展示 jQuery Mobile 如何增强你的网站以适配移动设备。在所有这些情况下，框架都意识到可能有时你想要禁用它。

# 使用多个文件

在理想的世界中，我们可以用一个文件构建整个网站，永远不需要进行修订，并且每个项目都在周五下午 2 点之前完成。但在现实世界中，我们必须处理大量的文件，进行大量的修订，不幸的是，还有大量的工作。在前面的代码清单中，你看到了我们如何在一个文件中包含两个页面。jQuery Mobile 处理起来也很容易。但你可以想象，在一段时间后，这将变得难以控制。虽然我们可以包含十个、二十个、甚至三十个页面，但这将使文件变得难以处理，并且对用户的初始下载速度也会更慢。

要处理多个页面和文件，我们只需在第一个文件的同一域中制作简单的链接到其他文件。我们甚至可以将第一种技术（一个文件中的两个页面）与链接到其他文件相结合。在`listing 2-2`中，我们修改了第一个示例以添加到一个新页面的链接。请注意我们保留了现有的`关于`页面。

```js
Listing 2-2:test2.html
<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial- scale=1">
<title>Multi Page Example (2)</title>
<link rel="stylesheet" href="http://code.jquery.com/mobile/ latest/jquery.mobile.min.css" />
<script src="img/jquery- 1.7.1.min.js"></script>
<script src="img/jquery.mobile.min.js"></script>
</head>
<body>
<div data-role="page" id="homePage">
<div data-role="header">Welcome</div>
<div data-role="content">
<p>
Welcome to our first mobile web site. It's going to be the best site you've ever seen. Once we get some content. And a business plan. But the hard part is done!
</p>
<p>
Find out about our wonderful
<a href= "products.html">products</a>.
</p>
<p>
You can also <a href= "#aboutPage">learn more</a> about Megacorp.
</p>
</div>
<div data-role="footer">
<i>Copyright Megacorp &copy; 2012</i>
</div>
</div>
<div data-role="page" id="aboutPage">
<div data-role="header">About Megacorp</div>
<div data-role="content">
<p>
This text talks about Megacorp and how interesting it is. Most likely though you want to
<a href= "#homePage">return</a> to the home page.
</p>
</div>
<div data-role="footer">
<i>Copyright Megacorp &copy; 2012</i>
</div>
</div>
</body>
</html>

```

现在，让我们看一看`listing 2-3`，我们的产品页面:

```js
Listing 2-3: products.html
<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial- scale=1">
<title>Products</title>
<link rel="stylesheet" href="http://code.jquery.com/mobile/ latest/jquery.mobile.min.css" />
<script src="img/jquery- 1.7.1.min.js"></script>
<script src="img/jquery.mobile.min.js"></script>
</head>
<body>
<div data-role="page" id="productsPage">
<div data-role="header">Products</div>
<div data-role="content">
<p>
Our products include:
</p>
<ul>
<li>Alpha Series</li>
<li>Beta Series</li>
<li>Gamma Series</li>
</ul>
</div>
</div>
</body>
</html>

```

我们的产品页面相当简单，但请注意我们在顶部包含了 jQuery 和 jQuery Mobile 资源。为什么？我之前提到 jQuery Mobile 将使用 Ajax 加载其他页面。如果在 Chrome 或支持 Firebug 的 Firefox 中打开`test2.html`，您可以自行查看。点击产品链接将触发 XHR（类似 Ajax）请求，如下图所示:

![处理多个文件](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_02_02.jpg)

这很棒。但是当有人收藏该应用程序时会发生什么？现在让我们看看 jQuery Mobile 如何处理 URL 和导航。

### 提示

**什么是 Firebug?**

Firebug 是 Firefox 的一个扩展程序 ([www.getfirebug.com](http://www.getfirebug.com))，为您的浏览器提供一套开发者相关工具。Chrome 内置了类似的工具。这些工具提供了许多功能，其中之一是监视与 XHR（或 Ajax）相关的请求。

# jQuery Mobile 和 URL

如果您在浏览器中打开了`test2.html`并进行了操作，您可能已经注意到在导航时 URL 的一些有趣之处。以下是初始 URL。(地址和文件夹当然会在您的计算机上有所不同):`http://localhost/mobile/c2/test2.html`。

点击产品后，URL 将更改为`http://localhost/mobile/c2/products.html`。如果我点击返回，然后点击**了解更多**，我会得到`http://localhost/mobile/c2/test2.html#aboutPage`。

在两个子页面中（产品页面和关于页面），URL 是由框架本身更改的。框架在支持的浏览器中使用`history.pushState`和`history.replaceState`。对于较旧的浏览器或不支持 JavaScript 操作 URL 的浏览器，将改用基于哈希的导航。 在 Internet Explorer 中查看产品链接时，如下所示:

`http://localhost/mobile/c2/test2.html#/mobile/c2/products.html`。

有趣的是，在这种书签样式中，始终首先加载`test2.html`。实际上，您可以构建您的`products.html`只包括 div，并确保如果首先请求了产品，它仍然会正确渲染。问题出在更新、更高级的浏览器上。如果您没有包括正确的 jQuery 和 jQuery Mobile 包含文件，当他们直接访问`products.html`时，您将得到一个没有样式的页面。最好始终包括适当的页头文件（CSS、JavaScript 等）。任何良好的编辑器都将提供创建模板的简单方法。

# 额外的自定义操作

在 jQuery Mobile 中处理多个页面非常简单。您可以将前两章中讨论的内容应用到现在，构建一个相当简单但符合移动设备的网站。以下是您可能想要考虑的一些更有趣的技巧。

## 页面标题

在前面的示例中，当您单击**Products**页面时，您可能已经注意到浏览器的标题正确更新为`Products`。这是因为 jQuery Mobile 注意到并解析了`products.html`文件中的标题标签。但是，如果您单击**About**链接，您不会得到相同的行为。显然，由于**About**页面位于同一 HTML 文件中，它也具有相同的标题标签。jQuery Mobile 提供了一种简单的方法来解决这个问题，再次涉及到数据标签。以下代码片段显示了一种为嵌入页面添加标题的简单方法：

```js
<div data-role="page" id="aboutPage" data-title="About Megacorp">
<div data-role="header">About Megacorp</div>
<div data-role="content">
<p>
This text talks about Megacorp and how interesting it is. Most likely though you want to
<a href= "#homePage">return</a> to the home page.
</p>
</div>
<div data-role="footer">
<i>Copyright Megacorp &copy; 2012</i>
</div>
</div>

```

注意新添加到`div`标签中的`data-title`标签。当加载**About**页面时，jQuery Mobile 会注意到这一点，并更新浏览器标题。同样，这仅在在一个 HTML 文件中包含多个页面时才需要。您可以在`test3.html`中找到这个版本：

![页面标题](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_02_03.jpg)

## 预取内容

将所有内容包含在一个 HTML 文件中的好处是所有页面都可以立即使用。但是负面影响（更新困难，初始下载速度慢）远远超过了这一点。大多数 jQuery Mobile 应用程序将包含多个文件，通常每个文件只包含一个或两个页面。但是，您可以确保某些页面加载更快以帮助改善用户体验。想象一下我们的**Megacorp**页面。它有三个页面，但是**Products**页面是一个单独的 HTML 文件。由于这是站点上唯一的真实内容，最有可能所有用户都会点击该链接。我们可以告诉 jQuery Mobile 在主页面加载时立即预取内容。这样，当用户单击该链接时，页面将加载得更快。再次，这归结为一个简单的数据属性。

```js
<p>
Find out about our wonderful <a href= "products.html" data- prefetch>products</a>.
</p>

```

在前面的链接中，我们所做的只是在链接中添加了`data-prefetch`。当 jQuery Mobile 在链接中发现这一点时，它将自动立即获取内容。现在，当用户单击**Products**链接时，他们将更快地看到内容。这个修改已保存在`test4.html`中。

显然，这种技术应谨慎使用。给定一个具有四个主要链接的页面，您可能只想考虑预取两个最受欢迎的页面，而不是全部四个。

## 更改页面过渡方式

之前，我们提到您可以配置 jQuery Mobile 在页面之间使用的过渡效果。在本书后面，我们将讨论如何在全局范围内执行此操作，但是如果您想要在特定链接中切换到不同的过渡效果，只需在链接中包含`data-transition`属性即可：

```js
<p>
Find out about our wonderful <a href= "products.html" data- transition="pop">products</a>.
</p>

```

许多转场还支持反向操作。通常情况下，jQuery Mobile 会判断您是否需要这样做，但如果您想强制指定一个方向，请使用 data-direction 属性：

```js
<p>
Find out about our wonderful <a href= "products.html" data- transition="pop" data-direction="reverse">products</a>.
</p>

```

# 总结

本章进一步阐述了 jQuery Mobile 页面的概念以及如何处理多个页面。具体来说，我们看到一个物理文件可以包含许多不同的页面。jQuery Mobile 将处理除第一个页面外的所有隐藏页面。我们还看到了如何链接到其他页面以及 jQuery Mobile 如何使用 Ajax 动态加载内容到浏览器中。接下来，我们讨论了 jQuery Mobile 如何处理更新浏览器的 URL 以便启用书签功能。最后，我们讨论了两种工具，这些工具将有助于改善您的页面。第一种方法是为嵌入页面提供标题。第二种技术演示了如何预取内容以进一步改善访问您网站的用户的体验。

在下一章中，我们将看看标题、页脚和导航栏。这些将极大地增强我们的页面，并使其更易于导航。


# 第三章：通过标题、页脚和工具栏增强页面

工具栏提供了一种简单的方法来为移动网站添加导航元素。它们可以为用户始终可以在导航应用程序中浏览时参考的一致性或站点范围导航控件提供特别有用的功能。

在本章中，我们将：

+   讨论如何同时创建标题和页脚

+   讨论如何将这些标题和页脚转换为有用的工具栏

+   演示如何创建固定定位的工具栏，无论页面的内容多大，它们都会始终显示出来

+   展示导航栏的示例

# 重要的预备知识点

如前一章所述，本章的所有代码都可以通过在 Github 下载的 ZIP 文件中获得。本章中的大多数代码示例都很简短，因此在测试时应使用完整的代码。

# 添加标题

您之前已经使用过标题，所以代码会很熟悉。在本章中，我们将更深入地研究它们，并演示如何向您的站点标题添加其他功能，例如按钮。

如果您记得，标题可以通过简单地使用具有适当角色的 div 来定义：

```js
<div data-role="header">My Header</div>

```

前一个标签将为文本添加漂亮的黑色背景，使其更加突出，如下面的截图所示：

![添加标题](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_03_01.jpg)

但是，我们可以做得更好。通过在我们的文本周围包含一个`h1`标签，jQuery Mobile 将使标题变得更大，并自动居中文本，如以下标签后面的截图所示：

```js
<div data-role="header"><h1>My Header</h1></div>

```

![添加标题](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_03_02.jpg)

立即您就能看到差别。我们可以通过添加按钮进一步增加标题的功能。按钮可以用于导航（例如返回主屏幕），或提供到相关页面的链接。因为标题的中心用于文本，所以只有两个*空格*可用于左侧和右侧的按钮。您只需在标题中创建链接即可添加按钮。第一个链接将位于文本左侧，第二个链接将位于右侧。以下代码片段是一个示例：

```js
<div data-role="header">
<a href= "index.html">Home</a>
<h1>My Header</h1>
<a href= "contact.html">Contact</a>
</div>

```

在移动浏览器中查看时，您将看到以下截图：

![添加标题](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_03_03.jpg)

注意，更简单的链接会自动转换为大按钮，使它们更易于使用，并对标题更具“控制”性。您可能会想，如果您只想要一个按钮，并且希望它在右侧，该怎么办？删除第一个按钮并保留第二个不起作用，如下面的代码片段所示：

```js
<div data-role="header">
<h1>My Header</h1>
<a href= "contact.html">Contact</a>
</div>

```

前面的代码片段在标题中创建了一个按钮，但位于左侧。为了将按钮定位到右侧，只需添加类`ui-btn-right`。以下代码片段是一个示例：

```js
<div data-role="header">
<h1>My Header</h1>
<a href= "contact.html" class="ui-btn-right">Contact</a>
</div>

```

您还可以指定`ui-btn-left`将链接放在左侧，但如前面的代码片段所示，那是正常的行为：

![添加标题](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_03_04.jpg)

# 图标预览

虽然不是特定的页眉工具栏功能，但 jQuery Mobile 中所有按钮都可以使用的一个有趣功能是指定一个图标。jQuery Mobile 随附了一组简单易识别的图标，并可立即使用。这些图标将在第六章中进一步讨论，*创建移动优化表单*，但是作为一个快速预览，以下代码片段显示了一个带有两个自定义图标的页眉：

```js
<div data-role="header">
<a href= "index.html" data-icon="home">Home</a>
<h1>My Header</h1>
<a href= "contact.html" data-icon="info">Contact</a>
</div>

```

注意新属性 `data-icon`。在浏览器中查看时，你会看到以下截图所示内容：

![图标预览](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_03_05.jpg)

# 处理返回按钮

根据用户的硬件，他们可能有或者没有物理返回按钮。对于有返回按钮的设备，比如安卓手机，在 jQuery Mobile 应用中点击返回按钮会很好用。用户点击按钮后，之前所在的页面会立即加载。但是在其他设备上，比如 iPhone，没有这样的按钮可以点击。虽然你可以提供链接自己导航到其他页面，但 jQuery Mobile 提供了一些很好的内置支持，可以直接向后导航。

有两种方式可以添加自动返回按钮。 `清单 3-1` 显示了一个简单的、两个页面的 jQuery Mobile 网站。在第二个页面中，我们添加了一个新的数据属性 `data-add-back-btn="true"`。这将在第二个页面的页眉中自动创建一个返回按钮。接下来，我们还在页面内容中添加了一个简单的链接。虽然链接的实际 URL 是空白的，请注意 `data-rel="back"` 属性。jQuery Mobile 会检测到此链接，并自动将用户发送到上一页。以下代码片段是一个示例：

```js
Listing 3-1: back_button_test.html
<!DOCTYPE html>
<html>
<head>
<title>Back Examples</title>
<meta name="viewport" content="width=device-width, initial- scale=1">
<link rel="stylesheet" href="http://code.jquery.com/mobile/ latest/jquery.mobile.min.css" />
<script src="img/jquery- 1.7.1.min.js"></script>
<script src="img/jquery.mobile.min.js"></script>
</head>
<body>
<div data-role="page">
<div data-role="header"><h1>My Header</h1></div>
<div data-role="content">
<p>
<a href= "#subpage">Go to the sub page...</a>
</p>
</div>
</div>
<div data-role="page" id="subpage" data-add-back-btn="true">
<div data-role="header"><h1>Sub Page</h1></div>
<div data-role="content">
<p>
<a href= "" data-rel="back">Go back...</a>
</p>
</div>
</div>
</body>
</html>

```

下面的截图展示了该功能的运行方式：

![处理返回按钮](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_03_06.jpg)

如果你好奇，按钮的文本可以通过在页面 div 中简单使用另一个数据属性来自定义：`data-add-back-btn="true" data-back-btn-text="返回"`。你也可以通过 JavaScript 全局地启用返回按钮支持并更改文本。这将在第九章中讨论，*jQuery Mobile 中的 JavaScript 配置和实用工具*。

# 处理页脚

页脚在大部分情况下会与页眉类似。我们之前演示过使用 data-role 创建页脚：

```js
<div data-role="footer">My Footer</div>

```

但是，就像我们的标题一样，如果我们在 div 标签内添加适当的 HTML，我们可以获得更好的格式：

```js
<div data-role="header"><h4>My Footer</h4></div>

```

添加了 `h4` 标签后，我们的页脚现在居中并且稍微填充，以使它们更加突出，如以下截图所示：

![处理页脚](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_03_07.jpg)

与页眉一样，您可以在页脚中包含按钮。与页眉不同，页脚中的按钮不会自动定位到文本的左右两侧。事实上，如果您决定使用文本和按钮，您需要确保从页脚文本中删除`h4`标签，否则您的页脚会变得相当大。以下是一个简单的示例，其中包含两个按钮：

```js
<div data-role="footer">
<a href= "credits.html">Credits</a>
<a href= "contact.html">Contact</a>
</div>

```

以下屏幕截图展示了这个变化：

![操作页脚](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_03_08.jpg)

这是有效的 - 但请注意按钮周围的空间不多。您可以通过将一个称为`ui-bar`的类添加到页脚`div`标签中来改进，如下面的代码片段所示：

```js
<div data-role="footer" class="ui-bar">
<a href= "credits.html">Credits</a>
<a href= "contact.html">Contact</a>
</div>

```

![操作页脚](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_03_09.jpg)

# 创建固定和全屏页眉和页脚

在前面关于页眉和页脚的讨论中，您看到了一些如何添加按钮的示例。这些按钮可以用于在您的站点中导航。但是如果某个页面特别长怎么办？例如，博客条目在移动设备上查看时可能会非常长。当用户滚动时，页眉或页脚可能会离开屏幕。jQuery Mobile 提供了一种创建固定位置页眉和页脚的方法。启用此功能后，页眉和页脚将始终可见。当用户滚动时，它们可能会消失，但只要他们抬起手指并停止滚动，页眉和页脚就会重新出现。可以通过向用于页眉或页脚的 div 标签添加`data-position="fixed"`来启用此功能。`清单 3-2`展示了一个示例。为了确保页面实际上滚动，许多文本段落被重复。这已从书中的代码中删除，但存在于实际文件中。

```js
Listing 3-2: longpage.html
<!DOCTYPE html>
<html>
<head>
<title>Fixed Positioning Example</title>
<meta name="viewport" content="width=device-width, initial- scale=1">
<link rel="stylesheet" href="http://code.jquery.com/mobile/ latest/jquery.mobile.min.css" />
<script src="img/jquery- 1.7.1.min.js"></script>
<script src="img/jquery.mobile.min.js"></script>
</head>
<body>
<div data-role="page">
<div data-role="header" data-position="fixed"><h1>My Header</h1></div>
<div data-role="content">
<p>
Lorem ipsum dolor sit amet, consectetur adipiscing elit. Suspendisse id posuere lacus. Nulla ac sem ut eros dignissim interdum a et erat. Class aptent taciti sociosqu ad litora torquent per conubia nostra, per inceptos himenaeos. In ac tellus est. Nunc consequat metus lobortis enim mattis nec convallis tellus pulvinar. Nullam diam ligula, dictum sed congue nec, dapibus id ipsum. Ut facilisis pretium dui, nec varius dui iaculis ultricies. Maecenas sollicitudin urna felis, non faucibus
leo. Cum sociis natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus. In id volutpat lectus.Quisque mauris ipsum, vehicula id ornare aliquet, auctor volutpat dui. Sed euismod sem in arcu dapibus condimentum dictum nibh consequat.
</p>
</div>
<div data-role="footer" data-position="fixed"><h4>My Footer</h4></div>
</div>
</body>
</html>

```

我们不会为这个示例提供截图，因为它不会很好地传达功能，但如果您在移动设备上尝试此操作，请注意，当您向上或向下滚动时，只要您抬起手指，页眉和页脚就会同时弹出。这使用户无论页面有多大都可以访问它们。

## 全屏定位

要考虑的另一种选择是所谓的全屏定位。这是一个常用于图片的比喻，但也可以用于使用固定定位页眉和页脚的情况。在这种情况下，页眉和页脚会随着点击的出现和消失而出现和消失。因此，对于照片，这允许您查看照片的原样，但也可以通过简单的点击重新获取页眉和页脚。也许，与其称之为全屏定位，不如考虑将其视为*可检索的*页眉和页脚。一般来说，当您希望查看页面内容时最好使用，再次，这是一个很好的例子。

要启用此功能，只需将`data-fullscreen="true"`添加到用于定义页面的 div 标签中即可。`清单 3-3`展示了此功能，如下面的代码片段所示：

```js
Listing 3-3: fullscreen.html
<!DOCTYPE html>
<html>
<head>
<title>Full Screen Example</title>
<meta name="viewport" content="width=device-width, initial- scale=1">
<link rel="stylesheet" href="http://code.jquery.com/mobile/ latest/jquery.mobile.min.css" />
<script src="img/jquery- 1.7.1.min.js"></script>
<script src="img/jquery.mobile.min.js"></script>
</head>
<body>
<div data-role="page" data-fullscreen="true">
<div data-role="header" data-position="fixed"><h1>My Header</h1></div>
<div data-role="content">
<p>
<img src="img/green.png" title="Green Block">
</p>
<p>
</div>
<div data-role="footer" data-position="fixed"><h4>My Footer</h4></div>
</div>
</body>
</html>

```

和前一个示例一样，前面的代码片段在静态截图中展示效果不太好。在手机浏览器中打开它，看一看吧。记住，你可以点击多次来切换效果的开启和关闭。

# 使用导航栏

你现在已经看到了一些示例，其中包括带有页眉和页脚的按钮，但是 jQuery Mobile 还有一个更简洁的版本，称为 NavBars（或导航栏）。这些是全屏宽的条形用来放置按钮。jQuery Mobile 还支持将一个按钮标记为活动按钮。在用于导航时，这是一种标记页面为活动状态的简单方法。

NavBar 简单地说就是包含在使用`data-role="navbar"`的 div 标签中的无序列表。放在页脚中时，它看起来类似于以下代码片段：

```js
<div data-role="footer">
<div data-role="navbar">
<ul>
<li><a href= "persistent_footer_index.html" class="ui-btn- active">Home</a></li>
<li><a href= "persistent_footer_credits.html" >Credits</a></li>
<li><a href= "persistent_footer_contact.html" >Contact</a></li>
</ul>
</div>
</div>

```

注意第一个链接使用了`class="ui-btn-active"`。这会将第一个按钮标记为活动状态。jQuery Mobile 不会自动为你完成这个操作，所以在构建每个页面并使用`navbar`时，你需要*适当地*移动类。以下截图显示了它的外观：

![Working with navigation bars](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_03_10.jpg)

你最多可以添加 5 个按钮，jQuery Mobile 会适当调整按钮大小以使其适应。如果超过五个，则按钮将简单地分成多行。很可能这不是你想要的。用太多的按钮来混淆用户，最终只会激怒他们。

你还可以在页眉中包括一个`navbar`。如果放置在文本或其他按钮之后，jQuery Mobile 将自动将其放置到下一行：

```js
<div data-role="header">
<h1>Home</h1>
<div data-role="navbar">
<ul>
<li><a href= "persistent_footer_index.html" class="ui-btn- active">Home</a></li>
<li><a href= "persistent_footer_credits.html" >Credits</a></li>
<li><a href= "persistent_footer_contact.html" >Contact</a></li>
</ul>
</div>
</div>

```

![Working with navigation bars](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_03_11.jpg)

你可以在名为`header_and_footer_with_navbar.html`的文件中看到这两者的应用示例。

## 跨多个页面持久化导航栏页脚

现在让我们将前面的两个主题合并成一个令人难以置信的小功能 - 多页面持久化页脚。这需要做一些额外工作，但你可以创建一个页脚 NavBar，在切换页面时不会消失。为了做到这一点，你需要遵循一些简单的规则：

+   你的页脚 div 必须出现在所有页面上

+   你的页脚 div 必须在所有页面上使用相同的`data-id`值

+   在 NavBar 中的*活动*页面上，必须使用两个 CSS 类：`ui-state-persist` 和 `ui-btn-active`。

+   你还必须使用持久化页脚功能

这听起来有点复杂，但实际上在模板中只需要增加一小部分 HTML 代码。在`listing 3-4`中，一个虚构公司的索引页面使用了页脚 NavBar。注意当前选定页面使用了`ui-state-persist`和`ui-btn-active`。

```js
Listing 3-4: persistent_footer_index.html
<!DOCTYPE html>
<html>
<head>
<title>Persistent Footer Example</title>
<meta name="viewport" content="width=device-width, initial- scale=1"> <link rel="stylesheet" href="http://code.jquery.com/mobile/ latest/jquery.mobile.min.css" />
<script src="img/jquery- 1.7.1.min.js"></script>
<script src="img/jquery.mobile.min.js"></script>
</head>
<body>
<div data-role="page">
<div data-role="header"><h1>Home</h1></div>
<div data-role="content">
<p>
This is the Home Page
</p>
</div>
<div data-role="footer" data-position="fixed" data- id="footernav">
<div data-role="navbar">
<ul>
<li><a href= "persistent_footer_index.html" class="ui-btn- active ui-state-persist">Home</a></li>
<li><a href= "persistent_footer_credits.html"> Credits</a></li>
<li><a href= "persistent_footer_contact.html"> Contact</a></li>
</ul>
</div>
</div>
</div>
</body>
</html>

```

下面的截图显示了页面的完整外观：

![Persisting navigation bar footers across multiple pages](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_03_12.jpg)

我们不需要太担心另外两个页面。你可以在下载的 ZIP 文件中找到它们。以下代码片段是第二个页面的页脚部分。请注意，这里唯一的变化是`ui-btn-active`类的移动：

```js
<div data-role="footer" data-position="fixed" data-id="footernav">
<div data-role="navbar">
<ul>
<li><a href= "persistent_footer_index.html">Home</a></li>
<li><a href= "persistent_footer_credits.html" class="ui-btn- active ui-state-persist">Credits</a></li>
<li><a href= "persistent_footer_contact.html">Contact</a></li>
</ul>
</div>
</div>

```

点击从一个页面到另一个页面时，每个页面都显示平滑的过渡，但页脚栏保持不变。就像一个有框架的站点（不要抖动 - 框架并不总是被鄙视），当用户在整个站点中导航时，页脚将保持不变。

# 摘要

在本章中，我们讨论了如何向您的 jQuery Mobile 页面添加标题、页脚和导航栏（NavBars）。我们展示了正确的 div 标记如何在您的页面上创建格式良好的标题和页脚，以及如何使这些标题和页脚在长页面中持续存在。此外，我们演示了*全屏模式*用于标题和页脚。这些是点击时出现和消失的标题和页脚 - 完美用于您想在移动设备上以全屏视图显示的图像和其他项目。最后，我们看到了如何结合持久页脚和 NavBars 以创建页脚，当页面更改时不会消失。

在下一章中，我们将深入探讨列表。列表是人们为其移动站点添加导航和菜单的主要方式之一。jQuery Mobile 提供了大量选项来创建和样式化列表。


# 第四章：与列表一起工作

列表是为移动网站的用户提供菜单的绝佳方式。jQuery Mobile 提供了丰富的列表选项，从简单的列表到带有自定义缩略图和多个用户操作的列表。

在这一章中，我们将：

+   谈论如何创建列表

+   如何创建链接和子菜单样式的列表

+   如何创建不同样式的列表

# 创建列表

正如您（希望！）所学到的，jQuery Mobile 在 UI 方面采取了一种*增强*的方法。您采用普通的、简单的 HTML，添加一些标记（有时候！），jQuery Mobile 将完成增强 UI 的繁重工作。同样的过程也适用于列表。我们之前都使用过 HTML 中的简单列表，下面的代码片段就是一个示例：

```js
<ul>
<li>Raymond Camden</li>
<li>Scott Stroz</li>
<li>Todd Sharp</li>
<li>Dave Ferguson</li>
</ul>

```

我们都知道它们是如何显示的（在前一个代码片段中是一个项目符号列表）。让我们将该列表放在一个简单的 jQuery Mobile 优化页面中。`Listing 4-1`将一个典型页面放入我们的列表中：

```js
Listing 4-1: test1.html
<!DOCTYPE html>
<html>
<head>
<title>Unordered List Example</title>
<meta name="viewport" content="width=device-width, initial- scale=1">
<link rel="stylesheet" href="http://code.jquery.com/mobile/ latest/jquery.mobile.min.css" />
<script src="img/jquery- 1.7.1.min.js"></script>
<script src="img/jquery.mobile.min.js"></script>
</head>
<body>
<div data-role="page">
<div data-role="header">
<h1>My Header</h1>
</div>
<div data-role="content">
<ul>
<li>Raymond Camden</li>
<li>Scott Stroz</li>
<li>Todd Sharp</li>
<li>Dave Ferguson</li>
</ul>
</div>
<div data-role="footer">
<h1>My Footer</h1>
</div>
</div>
</body>
</html>

```

给定这个 HTML，jQuery Mobile 立即为我们提供了一些好东西，如下截图所示：

![创建列表](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_04_01.jpg)

我们可以通过简单的更改来增强该列表。从`listing 4-1`中取出普通的`<ul>`标签，并添加一个`data-role="listview"`属性，如下代码所示：

```js
<ul data-role="listview">

```

在您从 Github 下载的代码中，您可以在`test2.html`中找到这个修改。虽然变化很大，如下截图所示：

![创建列表](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_04_02.jpg)

您可以看到项目不再在前面有圆点符号，但它们更大，更容易阅读。当我们开始向列表中添加链接时，事情变得更加有趣。在下面的代码片段中，我为每个列表项添加了一个链接：

```js
<ul data-role="listview">
<li><a href= "ray.html">Raymond Camden</a></li>
<li><a href= "scott.html">Scott Stroz</a></li>
<li><a href= "todd.html">Todd Sharp</a></li>
<li><a href= "dave.html">Dave Ferguson</a></li>
</ul>

```

再次，您可以在之前下载的 ZIP 文件中找到这个代码片段的完整文件。这个文件可以在`test3.html`中找到。下面的截图展示了该代码的渲染效果：

![创建列表](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_04_03.jpg)

注意新的箭头图片。当 jQuery Mobile 检测到列表中有链接时，它会自动添加。现在，您已经将一个相对简单的 HTML 无序列表转换为一个简单的菜单系统。这本身就相当令人印象深刻，但是正如我们将在本章的其余部分中看到的那样，jQuery Mobile 提供了丰富的渲染选项，让您定制列表。

您可能想知道您可以创建多复杂的菜单系统。因为 HTML 本身支持嵌套列表，jQuery Mobile 也会将它们渲染出来。`Listing 4-2`演示了一个嵌套列表的示例：

```js
Listing 4-2: Nested List
<!DOCTYPE html>
<html>
<head>
<title>List Example</title>
<meta name="viewport" content="width=device-width, initial- scale=1">
<link rel="stylesheet" href="http://code.jquery.com/mobile/ latest/jquery.mobile.min.css" />
<script src="img/jquery- 1.7.1.min.js"></script>
<script src="img/jquery.mobile.min.js"></script>
</head>
<body>
<div data-role="page">
<div data-role="header">
<h1>My Header</h1>
</div>
<div data-role="content">
<ul data-role="listview">
<li>Games
<ul>
<li>Pong</li>
<li>Breakout</li>
<li>Tron</li>
</ul>
</li>
<li>Weapons
<ul>
<li>Nukes</li>
<li>Swords</li>
<li>Ninja Stars</li>
</ul>
</li>
<li>Planets
<ul>
<li>Earth</li>
<li>Jupiter</li>
<li>Uranus</li>
</ul>
</li>
</ul>
</div>
<div data-role="footer">
<h1>My Footer</h1>
</div>
</div>
</body>
</html>

```

在前面示例中使用的嵌套列表的 HTML 并没有特别之处。它是标准的。但是 jQuery Mobile 将采取内部列表并实际隐藏内容。即使在*上*级 LI 项中没有链接，它们也会变成链接：

![创建列表](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_04_04.jpg)

单击菜单项中的一个会加载内部菜单。如果在您自己的移动设备上（或在浏览器中）运行此操作，请注意 URL 也会发生变化，它们会创建一个可书签的应用程序视图：

![创建列表](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_04_05.jpg)

# 使用列表功能

jQuery Mobile 提供多种不同样式的列表，以及可以应用于它们的不同功能。本章的下一部分将介绍其中的一些可用选项。这些选项没有特定的顺序，并且被呈现为您可用的选项的画廊。您可能不会（也不应该！）尝试在一个应用程序中使用所有这些选项，但是牢记 jQuery Mobile 提供的各种列表样式是件好事。

## 创建插入式列表

最简单、最精致的列表变化之一是将它们转换为**插入式列表**。这些列表不会占满设备的整个宽度。我们可以对之前用`data-role="content"`修改过的初始列表添加另一个属性，即`data-inset="true"`，在以下代码块（位于`test5.html`中）中实现：

```js
<ul data-role="listview" data-inset="true">
<li>Raymond Camden</li>
<li>Scott Stroz</li>
<li>Todd Sharp</li>
<li>Dave Ferguson</li>
</ul>

```

结果现在与之前的示例非常不同：

![创建插入式列表](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_04_06.jpg)

## 创建列表分隔符

您可能希望向列表中添加的另一个有趣的 UI 元素是分隔符。这是将长列表分隔成稍微容易扫描的内容的好方法。添加列表分隔符就像添加一个使用了`data-role="list-divider"`的`li`标签一样简单。下面的代码片段展示了此元素的一个简单示例：

```js
<ul data-role="listview" data-inset="true">
<li data-role="list-divider">Active</li>
<li>Raymond Camden</li>
<li>Scott Stroz</li>
<li>Todd Sharp</li>
<li data-role="list-divider">Archived</li>
<li>Dave Ferguson</li>
</ul>

```

在上一个代码块中，请注意两个使用了`list-divider`角色的新`li`标签。在本示例中，我将它们用于将人员列表分成两组。您可以在`test6.html`中找到完整的模板。以下截图显示了此内容的呈现方式：

![创建列表分隔符](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_04_07.jpg)

## 创建带有计数气泡的列表

jQuery Mobile 列表中的另一个有趣的 UI 技巧是*计数气泡*。这是一种 UI 增强，它在每个列表项的末尾添加一个简单的数字。这些数字被包裹在类似于*气泡*的外观中，通常用于电子邮件样式的界面。在下面的代码片段中，计数气泡用于表示在技术会议上消耗的 cookie 数量：

```js
<ul data-role="listview" data-inset="true">
<li data-role="list-divider">Cookies Eaten</li>
<li>Raymond Camden <span class="ui-li-count">9</span></li>
<li>Scott Stroz <span class="ui-li-count">4</span></li>
<li>Todd Sharp <span class="ui-li-count">13</span></li>
<li>Dave Ferguson <span class="ui-li-count">8</span></li>
</ul>

```

在上一个代码片段中，我们使用了一个带有类名`ui-list-count`的`span`标签来包裹表示每个人吃的 cookie 数量的数字。一个简单的 HTML 更改，但考虑一下它如何被很好地呈现，如下面的截图所示：

![创建带有计数气泡的列表](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_04_08.jpg)

您可以在`test7.html`中找到此功能的完整示例。

## 使用缩略图和图标

列表的另一个常见需求是包含图像。jQuery Mobile 支持缩略图（较小的图像）和图标（更小的图像），它们在列表控件内显示得很好。让我们首先看一下如何在列表中包含缩略图。假设您已经有了大小适中的图像（我们的示例都是宽高都为 160 像素），您可以简单地在每个`li`元素中包含它们，如以下代码片段所示：

```js
<ul data-role="listview" data-inset="true">
<li><a href="ray.html"><img src="img/ray.png"> Raymond Camden</a></li>
<li><a href="scott.html"><img src="img/scott.png"> Scott Stroz</a></li>
<li><a href="todd.html"><img src="img/todd.png"> Todd Sharp</a></li>
<li><a href="dave.html"><img src="img/dave.png"> Dave Ferguson</a></li>
</ul>

```

对图像没有做任何特殊处理，也没有添加任何数据属性或类。jQuery Mobile 将自动左对齐图像，并将项目文本对齐到每个`li`块的顶部：

![使用缩略图和图标](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_04_09.jpg)

你可以在`test8.html`中找到前面的演示。那么图标呢？要在代码中包含图标，请将类`ui-li-icon`添加到您的图像中（请注意，类的开头是`ui`，而不是`ul。`）以下代码片段是具有相同列表的示例：

```js
<ul data-role="listview" data-inset="true">
<li><a href="ray.html"><img src="img/ray_small.png" class="ui-li-icon"> Raymond Camden</a></li>
<li><a href="scott.html"><img src="img/scott_small.png" class="ui-li- icon"> Scott Stroz</a></li>
<li><a href="todd.html"><img src="img/todd_small.png" class="ui-li- icon"> Todd Sharp</a></li>
<li><a href="dave.html"><img src="img/dave_small.png" class="ui-li- icon"> Dave Ferguson</a></li>
</ul>

```

使用此类时，jQuery Mobile 会缩小图像，但根据我的经验，当图像在之前被调整大小时，格式会更好。这样做还可以提高网页的速度，因为较小的图像应该会导致更快的下载时间。上面的图像都是宽高各 16 像素。结果是...

![使用缩略图和图标](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_04_10.jpg)

你可以在`test9.html`中找到前面的例子。

## 创建分割按钮列表

jQuery Mobile 列表的另一个有趣功能是 Split Button 列表。这只是一个具有多个操作的列表。当用户单击列表项时，会激活一个主要操作，并且通过列表项末尾的按钮可用于辅助操作。对于此示例，让我们首先从截图开始，然后再展示如何实现它：

![创建分割按钮列表](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_04_11.jpg)

如您所见，每个列表项在行末都有一个辅助图标。这是一个分割项目列表的示例，简单地通过向列表项添加第二个链接来定义。例如：

```js
<ul data-role="listview" data-inset="true">
<li><a href= ray.html"><img src="img/ray_small.png" class="ui-li-icon"> Raymond Camden</a><a href="foo.html">Delete</a></li>
<li><a href= scott.html"><img src="img/scott_small.png" class="ui-li- icon"> Scott Stroz</a><a href="foo.html">Delete</a></li>
<li><a href= todd.html"><img src="img/todd_small.png" class="ui-li- icon"> Todd Sharp</a><a href="foo.html">Delete</a></li>
<li><a href= dave.html"><img src="img/dave_small.png" class="ui-li- icon"> Dave Ferguson</a><a href="foo.html">Delete</a></li>
</ul>

```

请注意，第二个链接的文本**删除**实际上被图标替换了。您可以通过将数据属性`split-icon`添加到您的`ul`标记中来指定图标，如下代码行所示：

```js
<ul data-role="listview" data-inset="true" data-split-icon="delete">

```

此示例的完整代码可以在`test10.html`中找到。

## 使用搜索过滤器

对于我们最后一个列表功能，我们将查看搜索过滤器。到目前为止，我们处理的列表都相当短。但是，较长的列表可能会使用户难以找到他们要找的内容。jQuery Mobile 提供了一种非常简单的方法来向列表添加搜索过滤器。通过将`data-filter="true"`添加到任何列表中，jQuery Mobile 将自动在顶部添加一个搜索字段，当您输入时会进行过滤：

```js
<ul data-role="listview" data-inset="true" data-filter="true">
<li><a href="ray.html">Raymond Camden</a></li>
<li><a href="scott.html">Scott Stroz</a></li>
<li><a href="todd.html">Todd Sharp</a></li>
<li><a href="dave.html">Dave Ferguson</a></li>
(lots of items....)
</ul>

```

结果看起来类似于以下截图：

![使用搜索过滤器](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_04_12.jpg)

如果您在上一个字段中开始输入，列表会在您输入时自动过滤出结果：

![使用搜索过滤器](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_04_13.jpg)

默认情况下，搜索是不区分大小写的，并且匹配列表项的任何位置。您可以在`ul`标签中使用`data-placeholder-text="Something"`来为搜索表单指定占位文本。您还可以使用`data-filter-theme`指定表单的特定主题。最后，您可以使用 JavaScript 根据情况添加自定义的列表过滤逻辑。

# 总结

本章讨论了如何在 jQuery Mobile 中使用列表视图。我们看到如何将常规 HTML 列表转换为移动优化列表，并演示了框架提供的众多列表功能类型。

在下一章中，我们将利用已学到的知识构建一个真实（尽管有点简单）的酒店移动优化网站。


# 第五章：实践中的一些 —— 构建一个简单的酒店移动网站

在过去的四章中，我们已经看了 jQuery Mobile 的一些特性，但我们已经有足够的知识来构建一个简单、相当基本的移动优化网站了。

在本章中，我们将：

+   讨论我们酒店移动网站将包含什么

+   使用 jQuery Mobile 创建酒店移动网站

+   讨论使网站更具互动性的方法

# 欢迎来到 Hotel Camden

世界闻名的 Hotel Camden 现在已经有了一段时间的网络存在。（好吧，为了明确起见，我们是在编造这个！）他们是网络世界的早期创新者，从 1996 年开始建立一个简单的网站，并逐年改进他们的在线存在。现在，Hotel Camden 的在线访客可以看到房间的虚拟游览，使用令人惊叹的 3D Adobe Flash 插件查看场地，并实际上可以在线预订。不过，最近，Hotel Camden 的业主们决定他们想进入移动空间。目前，他们想要简单地开始，创建一个包含以下功能的移动优化网站：

+   **联系信息：**这将包括电话号码和电子邮件地址。理想情况下，用户将能够点击这些联系方式并与真人联系。

+   **酒店位置地图：**这应该包括地址，可能还有地图。

+   **可用的房间类型：**这可以是一个从最简单到最华丽的房间的简单列表。

+   最后 - 提供一种让用户进入真正网站的方式。我们接受我们的移动版本在某种程度上会有所限制（对于这个版本），所以至少我们应该提供一种让用户返回站点桌面版本的方式。

# 主页

让我们从 Camden Hotel 的初始主页开始。这将提供一个简单的选项列表，以及顶部的一些营销文本。这些文本实际上对任何人都没有帮助，但是营销人员不会让我们在没有它的情况下发布网站：

```js
Listing 5-1: index.html
<!DOCTYPE html>
<html>
<head>
<title>The Camden Hotel</title>
<meta name="viewport" content="width=device-width, initial- scale=1">
<link rel="stylesheet" href="http://code.jquery.com/mobile/ latest/jquery.mobile.min.css" />
<script src="img/jquery- 1.7.1.min.js"></script>
<script src="img/jquery.mobile.min.js"></script>
</head>
<body>
<div data-role="page">
<div data-role="header">
<h1>Camden Hotel</h1>
</div>
<div data-role="content">
<p>
Welcome to the Camden Hotel. We are a luxury hotel specializing in catering to the rich and overly privileged. You will find our accommodations both flattering to your ego, as well as damaging to your wallet. Enjoy our complimentary wi-fi access, as well as caviar baths while sleeping in beds with gold thread.
</p>
<ul data-role="listview" data-inset="true">
<li><a href= "find.html">Find Us</a></li>
<li><a href= "rooms.html">Our Rooms</a></li>
<li><a href= "contact.html">Contact Us</a></li>
<li><a href= "">Non-Mobile Site</a></li>
</ul>
</div>
<div data-role="footer">
<h4>&copy; Camden Hotel 2012</h4>
</div>
</div>
</body>
</html>

```

在高层次上，`listing 5-1` 中的代码只是我们之前讨论过的 jQuery 页面模型的另一个实例。您可以看到包括的 CSS 和 JavaScript，以及设置页面、页眉、页脚和内容的 div 包装器。在我们的内容 div 中，您还可以看到正在使用的列表。我们留空了非移动站点选项（“非移动站点”）的 URL，因为我们没有一个真正的网站用于 Camden Hotel。

列表项的顺序也经过深思熟虑。每个项目按照员工认为的最常见请求的顺序列出，第一个是简单地找到酒店，而最后一个选项（忽略离开网站）是能够联系酒店。

总的来说 - 这个示例的想法是为我们认为酒店客户最需要的最重要的方面提供快速访问。以下截图显示了网站的外观：

![主页](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_05_01.jpg)

它并不是非常吸引人，但渲染效果很好，而且使用起来相当容易。稍后你会学习如何为 jQuery Mobile 设计主题，使您的网站不像其他所有示例一样。

# 寻找酒店

我们移动网站的下一页专注于帮助用户找到酒店。这将包括地址以及地图。`Listing 5-2` 显示了这是如何完成的：

```js
Listing 5-2: find.html
<!DOCTYPE html>
<html>
<head>
<title>The Camden Hotel - Find Us</title>
<meta name="viewport" content="width=device-width, initial- scale=1">
<link rel="stylesheet" href="http://code.jquery.com/mobile/ latest/jquery.mobile.min.css" />
<script src="img/jquery- 1.7.1.min.js"></script>
<script src="img/ jquery.mobile.min.js"></script>
</head>
<body>
<div data-role="page">
<div data-role="header">
<h1>Find Us</h1>
</div>
<div data-role="content">
<p>
The Camden Hotel is located in beautiful downtown Lafayette, LA. Home of the Ragin Cajuns, good food, good music, and all around good times, the Camden Hotel is smack dab in the middle of one of the most interesting cities in America!
</p>
<p>
400 Kaliste Saloom<br/>
Lafayette, LA<br/>
70508
</p>
<p>
<img src="img/ staticmap?center=400+Kaliste+Saloom,+Lafayette, LA&zoom=12&size=150x150&scale=2&maptype=roadmap& markers=label:H%7C400+Kaliste+Saloom,+Lafayette, LA&sensor=false">
</p>
</div>
<div data-role="footer">
<h4>&copy; Camden Hotel 2012</h4>
</div>
</div>
</body>
</html>

```

模板的开头再次包含了我们的样板，并且与以前一样，顶部有一些营销用语。但是在这之下，就是地址和地图。我们使用了谷歌的一个很酷的功能，静态地图。您可以在其主页上了解更多关于谷歌静态地图的信息：[`code.google.com/apis/maps/documentation/staticmaps/`](http://code.google.com/apis/maps/documentation/staticmaps/)。基本上，这是通过 URL 参数创建静态地图的一种方式。这些地图没有缩放或平移，但如果您只想向用户展示您的业务所在的位置，这是一种非常强大且简单的方法。虽然您可以使用此 API 的大量选项，但我们的示例只是将其居中到一个地址，并在那里添加一个标记。标签 **H** 用于标记，但也可以使用自定义图标。以下截图显示了这是什么样子的：

![寻找酒店](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_05_02.jpg)

您可以稍微调整一下地图 URL，更改缩放比例，更改颜色等，以满足您的喜好。

# 列出酒店房间

现在让我们看看 `rooms.html`。这是我们将列出酒店可用房型的地方：

```js
Listing 5-3: rooms.html
<!DOCTYPE html>
<html>
<head>
<title>The Camden Hotel - Our Rooms</title>
<meta name="viewport" content="width=device-width, initial- scale=1">
<link rel="stylesheet" href="http://code.jquery.com/mobile/ latest/jquery.mobile.min.css" />
<script src="img/jquery- 1.7.1.min.js"></script>
<script src="img/jquery.mobile.min.js"></script>
</head>
<body>
<div data-role="page">
<div data-role="header">
<h1>Our Rooms</h1>
</div>
<div data-role="content">
<p>
Select a room below to see a picture.
</p>
<ul data-role="listview" data-inset="true">
<li><a href= "room_poor.html">Simple Elegance</a></li>
<li><a href= "room_medium.html">Gold Standard</a></li>
<li><a href= "room_high.html">Emperor Suite</a></li>
</ul>
</div>
<div data-role="footer">
<h4>&copy; Camden Hotel 2012</h4>
</div>
</div>
</body>
</html>

```

房间页面只是他们房间的一个列表。酒店有三个级别的房间，每个都链接到列表中，用户可以获取详情。您可以在从 Github 下载的 ZIP 中找到所有三个文件，但让我们详细看看其中一个：

```js
Listing 5-4: room_high.html
<!DOCTYPE html>
<html>
<head>
<title>The Camden Hotel - Emperor Suite</title>
<meta name="viewport" content="width=device-width, initial- scale=1">
<link rel="stylesheet" href="http://code.jquery.com/mobile/ latest/jquery.mobile.min.css" />
<script src="img/jquery- 1.7.1.min.js"></script>
<script src="img/jquery.mobile.min.js"></script>
</head>
<body>
<div data-role="page" data-fullscreen="true">
<div data-role="header" data-position="fixed">
<h1>Emperor Suite</h1>
</div>
<div data-role="content">
<img src="img/room2.jpg" />
</div>
<div data-role="footer" data-position="fixed">
<h4>&copy; Camden Hotel 2012</h4>
</div>
</div>
</body>
</html>

```

房间详细信息页面只是一个图片。不是很有用，但它可以传达重点。但请注意，我们使用了在 第三章 中学到的一个技巧，*通过工具栏增强页面* - 全屏模式。这允许用户快速点击并隐藏标题，以便他们可以看到房间的全部风采：

![列出酒店房间](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_05_03.jpg)

# 联系酒店

现在让我们来看看联系页面。这将为用户提供到达酒店的信息：

```js
Listing 5-5: contact.html
<!DOCTYPE html>
<html>
<head>
<title>The Camden Hotel - Contact</title>
<meta name="viewport" content="width=device-width, initial- scale=1">
<link rel="stylesheet" href="http://code.jquery.com/mobile/ latest/jquery.mobile.min.css" />
<script src="img/jquery- 1.7.1.min.js"></script>
<script src="img/jquery.mobile.min.js"></script>
</head>
<body>
<div data-role="page">
<div data-role="header">
<h1>Contact Us</h1>
</div>
<div data-role="content">
<p>
<b>Phone:</b> <a href= "tel:555-555-5555"> 555-555-5555</a><br/>
<b>Email:</b> <a href= "mailto:people@camdenhotel.fake"> people@camdenhotel.fake</a>
</p>
</div>
<div data-role="footer">
<h4>&copy; Camden Hotel 2012</h4>
</div>
</div>
</body>
</html>

```

与以前一样，我们将页面包装在正确的脚本块和 `div` 标签中。特别注意我们的两个链接。手机和电子邮件链接都使用可能对您不熟悉的 URL。第一个 `tel:555-555-555` 实际上是请求移动设备拨打电话号码的一种方式。点击它会弹出拨号器，如下图所示：

![联系酒店](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_05_04.jpg)

这使得用户可以快速拨打酒店电话。同样，mailto 链接可以让用户快速给酒店发送电子邮件。还有其他的 URL 方案，包括用于发送短信的方案。正如你可能猜到的那样，这个方案使用形式“sms”，所以要开始向电话号码发送短信，你可以使用以下 URL：`sms://5551112222`。

# 摘要

在本章中，我们总结了到目前为止所学的知识，并为一家虚拟酒店建立了一个非常简单但有效的网站。这个网站分享了关于酒店的基本信息，方便需要在移动设备上了解酒店情况的人，利用了 Google 的静态地图 API 来创建一个显示酒店位置的简单地图，并演示了使用`tel`和`mailto`URL 方案进行自动拨打电话和发送电子邮件的方法。

在下一章中，我们将看看表单以及如何使用 jQuery Mobile 自动改进它们。


# 第六章：使用表单和 jQuery Mobile

在本章中，我们将研究表单。表单是大多数网站的关键部分，因为它们为用户提供了与网站交互的主要方式。jQuery Mobile 在使表单既可用又为移动设备设计上有很大帮助。

在本章中，我们将：

+   讨论 jQuery Mobile 处理表单的方式

+   使用示例表单并描述结果的处理方式

+   讨论如何构建特定类型的表单并利用 jQuery Mobile 的惯例

# 在您开始之前

在本章中，我们将讨论表单以及 jQuery Mobile 如何增强它们。作为我们讨论的一部分，我们将把我们的表单提交到服务器上。为了让服务器实际对响应做些什么，我们将使用 Adobe 的一个称为 ColdFusion 的应用服务器。ColdFusion 在生产中不免费，但是在开发中是 100%免费的，并且是构建 Web 应用程序的一个很好的服务器。您不需要下载 ColdFusion。如果不这样做，您在本章中使用的表单不应该提交。本章确实讨论了如何提交表单，但是对表单的响应并不是真正关键的。如果您了解另一种语言，比如 PHP，您应该能够简单地模仿 ColdFusion 使用的代码来回显表单数据。

ColdFusion（当前版本为 9）可在[`www.adobe.com/go/coldfusion`](http://www.adobe.com/go/coldfusion)下载。Windows、OS X 和 Linux 版本都存在。如上所述，您可以在开发服务器上免费运行 ColdFusion，没有超时限制。

# jQuery Mobile 对表单的处理

在我们进入代码之前，有两件非常重要的事情您应该知道 jQuery Mobile 将如何处理您的 HTML 表单：

+   所有表单都将通过 Ajax 提交其数据。这意味着数据直接发送到您表单的操作，并且结果将被带回给用户并放置在容纳表单的页面中。这样可以防止完整页面重新加载。

+   所有表单字段都会自动增强，每个都有自己的方式。随着我们在本章中的进行，您将看到这方面的示例，但基本上 jQuery Mobile 修改您的表单字段以在移动设备上更好地工作。一个很好的例子是按钮。jQuery Mobile 自动扩大和增高按钮，使其更易于在手机的小型形式因素中点击。如果出于某种原因您不喜欢这样做，jQuery Mobile 提供了一种方法来禁用此功能，可以在全局或每次使用的基础上。

考虑到这一点，让我们看看我们第一个示例`列表 6-1：`

```js
Listing 6-1: test1.html
<!DOCTYPE html>
<html>
<head>
<title>Form Example 1</title>
<meta name="viewport" content="width=device-width, initial- scale=1">
<link rel="stylesheet" href="http://code.jquery.com/mobile/ latest/jquery.mobile.min.css" />
<script src="img/jquery- 1.7.1.min.js"></script>
<script src="img/jquery.mobile.min.js"></script>
</head>
<body>
<div data-role="page">
<div data-role="header">
<h1>Form Demo</h1>
</div>
<div data-role="content">
<form action="echo.cfm" method="post">
<div data-role="fieldcontain">
<label for="name">Name:</label>
<input type="text" name="name" id="name" value="" />
</div>
<div data-role="fieldcontain">
<label for="email">Email:</label>
<input type="text" name="email" id="email" value="" />
</div>
<div data-role="fieldcontain">
<input type="submit" name="submit" value="Send" />
</div>
</form>
</div>
</div>
</body>
</html>

```

与往常一样，模板从适当的包含开始，并使用特殊标记的`div`标签包裹页面的主要内容。我们将专注于主要内容区域的表单字段。建议每个表单字段都用以下标记包装：

```js
<div data-role="fieldcontain">
</div>

```

这将帮助 jQuery Mobile 对齐标签和表单字段。一会儿你就会明白原因。我们的表单有两个文本字段，一个用于姓名，一个用于电子邮件。最后一项只是提交按钮。所以除了使用`fieldcontain`包装器并确保我们的表单字段有标签之外，这里没有发生任何特别的事情。不过马上你就会看到表单发生了一些相当令人印象深刻的变化：

![jQuery Mobile 对表单的处理](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_06_01.jpg)

请注意标签是如何显示在表单字段上方的。这在移动设备上为字段提供了更多的空间。同时请注意提交按钮很大且易于点击。如果我们旋转设备，jQuery Mobile 会更新显示以利用额外的空间：

![jQuery Mobile 对表单的处理](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_06_02.jpg)

请注意，字段现在直接对齐到其标签的右侧。那么当表单提交时会发生什么？正如本章开头所提到的，我们将使用 ColdFusion 来处理对表单请求的响应。我们的`echo.cfm`模板将简单地循环遍历所有表单字段并将它们显示给用户：

```js
Listing 6-2: echo.cfm
<div data-role="page">
<div data-role="header">
<h1>Form Result</h1>
</div>
<div data-role="content">
<cfloop item="field" collection="#form#">
<cfoutput>
<p>
The form field #field# has the value #form[field]#.
</p>
</cfoutput>
</cfloop>
</div>
</div>

```

如果您不想安装 ColdFusion，您可以简单地编辑`listing 6-1`中的表单操作值，将其指向一个 PHP 文件，或者任何其他服务器端处理器。您也可以将其简单地更改为文件本身`test1.html`。当您提交时，什么都不会发生，但您也不会收到错误。这是设备在提交后显示的内容：

![jQuery Mobile 对表单的处理](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_06_03.jpg)

jQuery Mobile 更新表单字段的另一个很好的例子是`textarea。textarea`，默认情况下，在移动设备上使用起来可能会非常困难，特别是当文本量超出`textarea`的大小并添加滚动条时。在以下代码清单中，我们只是修改了先前的表单，包括第三个项目，一个使用了`textarea`的个人简介字段。完整文件可在本书的代码 ZIP 文件中找到。以下代码片段是添加到前两个字段之后的`div`块：

```js
<div data-role="fieldcontain">
<label for="bio">Bio:</label>
<textarea name="bio" id="bio" />
</div>

```

当在设备上查看时，`textarea`会展开以吸收更多的宽度，就像常规文本字段一样，并且会变得更高：

![jQuery Mobile 对表单的处理](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_06_04.jpg)

但一旦您开始输入并输入多行文本时，`textarea`会自动扩展：

![jQuery Mobile 对表单的处理](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_06_05.jpg)

这样比使用滚动条更容易阅读。现在让我们看看另一个常见的表单选项——单选按钮和复选框。

## 操作单选按钮和复选框

单选按钮和复选框也被更新为在移动设备上很好地工作，但需要稍微多一点的代码。在之前的例子中，我们用一个`div`标签包装了表单字段，该标签使用了`data-role="fieldcontain"`。当操作单选按钮和复选框时，需要一个额外的标签：

```js
<fieldset data-role="controlgroup">

```

此`fieldset`标签将用于将您的单选按钮或复选框分组在一起。`清单 6-3`演示了一组单选按钮和一组复选框：

```js
Listing 6-3: test3.html
<!DOCTYPE html>
<html>
<head>
<title>Form Example 3</title>
<meta name="viewport" content="width=device-width, initial- scale=1">
<link rel="stylesheet" href="http://code.jquery.com/mobile/ latest/jquery.mobile.min.css" />
<script src="img/jquery- 1.7.1.min.js"></script>
<script src="img/jquery.mobile.min.js"></script>
</head>
<body>
<div data-role="page">
<div data-role="header">
<h1>Form Demo</h1>
</div>
<div data-role="content">
<form action="echo.cfm" method="post">
<div data-role="fieldcontain">
<fieldset data-role="controlgroup">
<legend>Favorite Movie:</legend>
<input type="radio" name="favoritemovie" id="favoritemovie1" value="Star Wars">
<label for="favoritemovie1">Star Wars</label>
<input type="radio" name="favoritemovie" id="favoritemovie2" value="Vanilla Sky">
<label for="favoritemovie2">Vanilla Sky</label>
<input type="radio" name="favoritemovie" id="favoritemovie3" value="Inception">
<label for="favoritemovie3">Inception</label>
</fieldset>
</div>
<div data-role="fieldcontain">
<fieldset data-role="controlgroup">
<legend>Favorite Colors:</legend>
<input type="checkbox" name="favoritecolor" id="favoritecolor1" value="Green">
<label for="favoritecolor1">Green</label>
<input type="checkbox" name="favoritecolor" id="favoritecolor2" value="Red">
<label for="favoritecolor2">Red</label>
<input type="checkbox" name="favoritecolor" id="favoritecolor3" value="Yellow">
<label for="favoritecolor3">Yellow</label>
</fieldset>
</div>
<input type="submit" name="submit" value="Send" />
</div>
</form>
</div>
</div>
</body>
</html>

```

我们的表单有两个主要问题——您最喜欢的电影是什么以及您最喜欢的颜色是什么？每个块都包裹在我们之前提到的`div`标签中。在其中是使用`data-role="controlgroup"`的`fieldset`。最后，您然后有您的单选按钮和复选框组。重要的是要在适当的标签标签内包含标签，就像之前的每个示例中一样。一旦渲染，jQuery Mobile 将这些组合成一个漂亮的、单一的控件：

![使用单选按钮和复选框](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_06_06.jpg)

注意每个项目的宽可点击区域。这样在移动设备上更容易选择项目。这两个控件的另一个有趣功能是将它们转换为水平按钮栏的能力。在`test4.html`中，两个`fieldset`标签被修改以包含一个新的数据属性：

```js
<fieldset data-role="controlgroup" data-type="horizontal">

```

![使用单选按钮和复选框](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_06_07.jpg)

正如您所见，效果在第一组中的较长文本中效果不佳，因此请务必进行测试。

## 使用选择菜单

另一个 jQuery Mobile 表单增强的示例是使用选择菜单。与我们之前的示例一样，我们利用一个`fieldcontain div`和`label`标签，但在那之外，`select`标签像往常一样使用。以下代码片段来自`test5.html`：

```js
<div data-role="fieldcontain">
<label for="favmovie">Favorite Movie:</label>
<select name="favmovie" id="favmovie">
<option value="Star Wars">Star Wars</option>
<option value="Revenge of the Sith">Revenge of the Sith</option>
<option value="Tron">Tron</option>
<option value="Tron Legacy">Tron Legacy</option>
</select>
</div>

```

在移动设备上，选择的初始显示被修改为更容易点击：

![使用选择菜单](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_06_08.jpg)

但是，一旦点击，设备的原生菜单将接管。在您使用的平台上，这将看起来不同。以下截图显示了 Android 如何渲染菜单：

![使用选择菜单](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_06_09.jpg)

另一个与选择字段一起使用的选项是分组。jQuery Mobile 允许您垂直或水平将多个选择字段组合在一起。在这两种情况下，唯一需要的就是将您的选择字段包装在一个`fieldset`中，并使用`data-role`为`controlgroup`，就像我们之前为单选按钮和复选框所做的那样。以下代码片段是垂直对齐的选择字段组的示例：

```js
<div data-role="fieldcontain">
<fieldset data-role="controlgroup">
<legend>Trip Setup:</legend>
<label for="location">Location</label>
<select name="location" id="location">
<option value="Home">Home</option>
<option value="Work">Work</option>
<option value="Moon">Moon</option>
<option value="Airport">Airport</option>
</select>
<label for="time">Time</label>
<select name="time" id="time">
<option value="Morning">Morning</option>
<option value="Afternoon">Afternoon</option>
<option value="Evening">Evening</option>
</select>
<label for="time">Meal</label>
<select name="meal" id="meal">
<option value="Meat">Meat</option>
<option value="Vegan">Vegan</option>
<option value="Kosher">Kosher</option>
</select>
</fieldset>
</div>

```

此模板的其余部分可以在`test6.html`中找到。以下截图显示了它的外观：

![使用选择菜单](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_06_10.jpg)

请注意 jQuery Mobile 如何将它们分组在一起，并将边角圆润地呈现出来。水平版本可以通过在 fieldset 标签中添加一个`data-type="horizontal"`属性来实现。另外，重要的是要删除使用“fieldcontain”的`div`。这是一个示例（完整文件可以在`test7.html`中找到）：

```js
<div data-role="page">
<div data-role="header">
<h1>Form Demo</h1>
</div>
<div data-role="content">
<form action="echo.cfm" method="post">
<fieldset data-role="controlgroup" data-type="horizontal">
<legend>Trip Setup:</legend>
<label for="location">Location</label>
<select name="location" id="location">
<option value="Home">Home</option>
<option value="Work">Work</option>
<option value="Moon">Moon</option>
<option value="Airport">Airport</option>
</select>
<label for="time">Time</label>
<select name="time" id="time">
<option value="Morning">Morning</option>
<option value="Afternoon">Afternoon</option>
<option value="Evening">Evening</option>
</select>
<label for="meal">Meal</label>
<select name="meal" id="meal">
<option value="Meat">Meat</option>
<option value="Vegan">Vegan</option>
<option value="Kosher">Kosher</option>
</select>
</fieldset>
<div data-role="fieldcontain">
<input type="submit" name="submit" value="Send" />
</div>
</form>
</div>
</div>

```

以下截图显示了结果：

![使用选择菜单](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_06_11.jpg)

## 搜索、切换和滑块字段

除了接受常规表单字段并使其更好地工作外，jQuery Mobile 还有助于使一些较新的 HTML5 表单字段在多个浏览器上正确工作。尽管在桌面上对于每个主要浏览器的支持尚未确定，但 jQuery Mobile 为搜索、切换和滑块字段提供了内置支持。让我们看看每个字段。

### 搜索字段

这三个新字段中最简单的是搜索字段，它在您开始输入后在字段末尾添加了一个快速删除图标。某些设备还会在前面放置一个沙漏图标，以帮助传达该字段用于某种类型的搜索的概念。要使用此字段，只需将类型从文本切换到搜索即可。就像下面的来自`test8.html`的例子一样：

```js
<div data-role="fieldcontain">
<label for="name">Name:</label>
<input type="search" name="name" id="name" value="" />
</div>

```

以下截图是结果。请注意，我已经输入了一些内容，字段会自动在末尾添加一个**删除**图标：

![搜索字段](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_06_12.jpg)

### 翻转切换字段

翻转切换字段是在一个值和两个值之间切换的控件。创建切换字段涉及使用具有特定 data-role 值的选择控件。现在，这里可能会有点混乱。要使选择字段变为切换字段，您可以使用`data-role="slider"`。稍后我们将看到另一个滑块控件，但它使用了不同的技术。只需记住，即使您在 HTML 中看到`"slider"`，我们实际上正在创建的是一个切换控件。让我们看一个简单的例子。（您可以在`test9.html`中找到此完整源代码）：

```js
<div data-role="fieldcontain">
<label for="gender">Gender:</label>
<select name="gender" id="gender" data-role="slider">
<option value="0">Male</option>
<option value="1">Female</option>
</select>
</div>

```

一旦由 jQuery Mobile 渲染，以下截图显示了结果，首先是默认的**男性**选项，然后是**女性**：

![翻转切换字段](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_06_13.jpg)![翻转切换字段](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_06_14.jpg)

### 滑块字段

对于我们特殊字段中的最后一个，我们来看看滑块。与搜索字段一样，这是基于一项 HTML5 规范，在某些浏览器中有效，在其他浏览器中无效。jQuery Mobile 只需使其在所有地方都起作用。为了启用此字段，我们将普通文本字段切换类型为`"range"`，为我们的滑块提供范围，我们还提供了`min`和`max`值。您还可以通过添加属性`data-highlight="true"`为滑块添加额外的颜色。以下代码片段是一个示例。（您可以在`test10.html`中找到完整文件）：

```js
<div data-role="fieldcontain">
<label for="coolness">Coolness:</label>
<input type="range" name="coolness" id="coolness" min="0" max="100" value="22" data-highlight="true">
</div>

```

结果是一个滑块控件和一个输入字段。两者都允许您在最小值和最大值之间修改值：

![滑块字段](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_06_15.jpg)

请注意，范围的 HTML5 规范支持步长属性。虽然这在一些浏览器中有效，但 jQuery Mobile 尚未直接支持。换句话说，jQuery Mobile 不会尝试在没有内置支持的浏览器上添加此支持。只要您意识到它可能不始终按预期工作，就可以添加该属性。

## 使用原生表单控件

现在你已经看到 jQuery Mobile 为增强和加强你的表单字段以在移动设备上更好地工作所做的努力，但如果你不喜欢 jQuery Mobile 的工作呢？如果你喜欢它对按钮的更新但厌恶它对下拉框的更改呢？幸运的是，jQuery Mobile 提供了一种简单的方法来禁用自动增强。在每个你希望保持不变的字段中，只需在标记中添加 `data-role="none"`。所以根据以下 HTML，第一个项目将被更新，而第二个项目不会：

```js
<input type="submit" value="Awesome">
<input type="submit" value="Not So Awesome" data-role="none">

```

![使用原生表单控件](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_06_16.jpg)

另一个选项是在初始化 jQuery Mobile 时禁用它。该选项将在第九章中讨论，*jQuery Mobile 中的 JavaScript 配置和实用程序*。

# 使用“迷你”字段

在前面的示例中，我们看到了 jQuery Mobile 如何自动增强表单字段，使它们在较小的、基于触摸的设备上更易于使用。一般来说，jQuery Mobile 将你的字段变得更大更漂亮。虽然这在大多数情况下是可取的，但你可能希望让你的表单字段减肥一点。这对于将表单字段放置在页眉或页脚中尤其如此。jQuery Mobile 支持任何表单字段上的属性，可以创建字段的更小版本：`data-mini="true"`。以下代码片段是一个完整的示例：

```js
<div data-role="fieldcontain">
<label for="name">Name:</label>
<input type="search" name="name" id="name" value="" />
</div>
<div data-role="fieldcontain">
<label for="name">Name (Slim):</label>
<input type="search" name="name" id="name" value="" data- mini="true" />
</div>

```

结果有点微妙，但你可以在以下截图的第二个字段中看到高度差异：

![使用“迷你”字段](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_06_17.jpg)

这个例子可以在名为 `test12.html` 的文件中找到。

# 摘要

在本章中，我们讨论了表单以及它们在 jQuery Mobile 应用程序中的呈现方式。我们讨论了 jQuery Mobile 如何自动将所有表单提交转换为基于 Ajax 的调用，并更新表单字段以在移动设备上更好地工作。不仅所有的表单字段都会自动更新，而且你还可以使用新的控件，如切换、滑块和搜索输入。

在下一章中，我们将看一下模态对话框、小部件和布局网格。这些为你的移动优化站点提供了额外的 UI 选项。


# 第七章：创建模态对话框、网格和可折叠块

在这一章中，我们将看到对话框、网格和可折叠块。在之前的章节中，我们已经处理过页面、按钮和表单控件。虽然 jQuery Mobile 为它们提供了很好的支持，但在框架中还有更多的 UI 控件可供使用。

在本章中，我们将：

+   讨论如何链接到和创建对话框以及如何处理离开它们

+   演示网格及如何将其添加到你的页面

+   展示可折叠块如何让你在很小的空间内装入大量信息

# 创建对话框

对话框：至少在 jQuery Mobile 框架下：是覆盖现有页面的小窗口。通常为用户提供短消息或问题。它们通常还包括一个按钮，允许用户关闭对话框并返回网站。在 jQuery Mobile 中创建对话框只需要简单地为链接添加一个属性：`data-rel="dialog"`。下面的示例演示了一个样例：

```js
Listing 7-1: test1.html
<!DOCTYPE html>
<html>
<head>
<title>Dialog Test</title>
<meta name="viewport" content="width=device-width, initial- scale=1">
<link rel="stylesheet" href="http://code.jquery.com/mobile/ latest/jquery.mobile.min.css" />
<script src="img/jquery- 1.7.1.min.js"></script>
<script src="img/ jquery.mobile.min.js"></script>
</head>
<body>
<div data-role="page" id="first">
<div data-role="header">
<h1>Dialog Test</h1>
</div>
<div data-role="content">
<p>
<a href="#page2">Another Page (normal)</a>
</p>
<p>
<a href="#page3" data-rel="dialog">A Dialog (dialog)</a>
</p>
</div>
</div>
<div data-role="page" id="page2">
<div data-role="header">
<h1>The Second</h1>
</div>
<div data-role="content">
<p>
This is the Second
</p>
</div>
</div>
<div data-role="page" id="page3">
<div data-role="header">
<h1>The Third</h1>
</div>
<div data-role="content">
<p>
This is the Third
</p>
</div>
</div>
</body>
</html>

```

这是一个简单的多页面 jQuery Mobile 站点。请注意我们如何链接到第二和第三页。第一个链接很典型。然而，第二个链接包括了前面提到的`data-rel`属性。请注意第二和第三页都是以通常方式定义的。所以我们在此处的唯一改变是在链接上。当点击第二个链接时，页面将完全不同地呈现：

![创建对话框](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_07_01.jpg)

记住，该页面并未有不同的定义。你在上一屏幕截图中看到的变化是由链接本身的更改驱动的。就是这样！点击小的**X**按钮将隐藏对话框并将用户带回原始页面。

该页面内的任意链接也将处理关闭对话框。如果你希望添加一个类似取消的按钮或链接，可以在链接中使用`data-rel="back"`。链接的目标应为启动对话框的页面。`列表 7-2`展示了之前模板的修改版本。在这个版本中，我们只是在对话框中添加了两个按钮。第一个按钮将打开第二页，而第二个将作为一个**取消**操作。

```js
Listing 7-2: test2.html
<!DOCTYPE html>
<html>
<head>
<title>Dialog Test (2)</title>
<meta name="viewport" content="width=device-width, initial- scale=1">
<link rel="stylesheet" href="http://code.jquery.com/mobile/ latest/jquery.mobile.min.css" />
<script src="img/jquery- 1.7.1.min.js"></script>
<script src="img/jquery.mobile.min.js"></script>
</head>
<body>
<div data-role="page" id="first">
<div data-role="header">
<h1>Dialog Test</h1>
</div>
<div data-role="content">
<p>
<a href="#page2">Another Page (normal)</a>
</p>
<p>
<a href="#page3" data-rel="dialog">A Dialog (dialog)</a>
</p>
</div>
</div>
<div data-role="page" id="page2">
<div data-role="header">
<h1>The Second</h1>
</div>
<div data-role="content">
<p>
This is the Second
</p>
</div>
</div>
<div data-role="page" id="page3">
<div data-role="header">
<h1>The Third</h1>
</div>
<div data-role="content">
<p>
This is the Third
</p>
<a href="#page2" data-role="button">Page 2</a>
<a href="#first" data-role="button" data- rel="back">Cancel</a>
</div>
</div>
</body>
</html>

```

这个模板中的主要变化是对话框中按钮的添加，包含在`page3 div`中。请注意第一个链接被设置为按钮，但在外面却是一个简单的链接。第二个按钮包含了添加的`data-rel="back"`属性。这将简单地关闭对话框。下面的截图展示了添加按钮后对话框的样子：

![创建对话框](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_07_02.jpg)

# 使用网格布局内容

网格是 jQuery Mobile 中少数不使用特定数据属性的特性之一。相反，你只需为内容指定 CSS 类即可使用网格布局。

网格有四种类型：两列、三列、四列和五列。（你可能不会想在手机设备上使用五列。最好是留给平板。）

你可以通过使用 `ui-grid-X` 类开始一个网格，其中 `X` 可以是 `a, b, c`, 或 `d`。`ui-grid-a` 表示两列网格，`ui-grid-b` 是三列网格。你大概能猜到 `c` 和 `d` 代表什么。

所以要开始一个两列网格，你需要用以下代码包裹你的内容：

```js
<div class="ui-grid-a">
Content
</div>

```

在 `div` 标签内，你可以为内容的每个 "单元格" 使用一个 `div`。网格调用的类以 `ui-block-X` 开头，`X` 从 `a` 到 `d`。`ui-block-a` 会被用于第一个单元格，`ui-block-b` 用于下一个，以此类推。这与 HTML 表格非常相似。

综合起来，下面的代码片段展示了一个简单的两列网格，其中有两个单元格的内容：

```js
<div class="ui-grid-a">
<div class="ui-block-a">Left</div>
<div class="ui-block-b">Right</div>
</div>

```

单元格内的文本会自动换行。`7-3` 展示了一个简单的网格，其中一个单元格中有大量文本：

```js
Listing 7-3: test3.html
<!DOCTYPE html>
<html>
<head>
<title>Grid Test</title>
<meta name="viewport" content="width=device-width, initial- scale=1">
<link rel="stylesheet" href="http://code.jquery.com/mobile/ latest/jquery.mobile.min.css" />
<script src="img/jquery- 1.7.1.min.js"></script>
<script src="img/jquery.mobile.min.js"></script>
</head>
<body>
<div data-role="page" id="first">
<div data-role="header">
<h1>Grid Test</h1>
</div>
<div data-role="content">
<div class="ui-grid-a">
<div class="ui-block-a">
<p>
This is my left hand content. There won't be a lot of it.
</p>
</div>
<div class="ui-block-b">
<p>
This is my right hand content. I'm going to fill it with some dummy text.
</p>
<p>
Bacon ipsum dolor sit amet andouille capicola spare ribs, short loin venison sausage prosciutto turducken turkey flank frankfurter pork belly short ribs. Venison frankfurter filet mignon, jowl meatball hamburger pastrami pork chop drumstick. Fatback pancetta boudin, ribeye shoulder capicola cow leberkäse bresaola spare ribs prosciutto venison ball tip jowl andouille. Beef ribs t-bone swine, tail capicola turkey pork belly leberkäse frankfurter jowl. Shankle ball tip sirloin frankfurter bacon beef ribs. Tenderloin beef ribs pork chop, pancetta turkey bacon short ribs ham flank chuck pork belly. Tongue strip steak short ribs tail swine.
</p>
</div>
</div>
</div>
</div>
</body>
</html>

```

在移动浏览器中，你可以清楚地看到两列：

![使用网格布局内容](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_07_03.jpg)

然后就是简单地切换到其他类来处理其他类型的网格。例如，设置一个四列网格类似于以下代码片段：

```js
<div class="ui-grid-c">
<div class="ui-block-a">1st cell</div>
<div class="ui-block-b">2nd cell</div>
<div class="ui-block-c">3rd cell</div>
</div>

```

同样，记住你的目标受众。任何超过两列的都可能在手机上显得太窄。

要在网格中创建多行，只需重复块。下面的代码片段展示了一个有两行单元格的网格的简单示例：

```js
<div class="ui-grid-a">
<div class="ui-block-a">Left Top</div>
<div class="ui-block-b">Right Top</div>
<div class="ui-block-a">Left Bottom</div>
<div class="ui-block-b">Right Bottom</div>
</div>

```

请注意，这里没有行的概念。 jQuery Mobile 可以处理当块重新以标记为 `ui-block-a` 开始时，它应该创建一个新的行。下面的代码片段，`7-4` 是一个简单的例子：

```js
Listing 7-4:test4.html
<!DOCTYPE html>
<html>
<head>
<title>Grid Test (2)</title>
<meta name="viewport" content="width=device-width, initial- scale=1">
<link rel="stylesheet" href="http://code.jquery.com/mobile/ latest/jquery.mobile.min.css" />
<script src="img/jquery- 1.7.1.min.js"></script>
<script src="img/ jquery.mobile.min.js"></script>
</head>
<body>
<div data-role="page" id="first">
<div data-role="header">
<h1>Grid Test</h1>
</div>
<div data-role="content">
<div class="ui-grid-a">
<div class="ui-block-a">
<p>
<img src="img/ray.png">
</p>
</div>
<div class="ui-block-b">
<p>
This is Raymond Camden. Here is some text about him. It may wrap or it may not but jQuery Mobile will make it look good. Unlike Ray!
</p>
</div>
<div class="ui-block-a">
<p>
This is Scott Stroz. Scott Stroz is a guy who plays golf and is really good at FPS video games.
</p>
</div>
<div class="ui-block-b">
<p>
<img src="img/scott.png">
</p>
</div>
</div>
</div>
</div>
</body>
</html>

```

下面的截图显示了结果：

![使用网格布局内容](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_07_04.jpg)

# 使用可折叠内容

在本章中，我们要看的最后一个小部件支持可折叠内容。这只是可以折叠和展开的内容。创建一个可折叠内容小部件就像简单地用 `div` 包裹它，加上 `data-role="collapsible"`，并包含内容的标题。考虑以下简单的例子：

```js
<div data-role="collapsible">
<h1>My News</h1>
<p>This is the latest news about me...
</div>

```

渲染时，jQuery Mobile 会将标题转换为可展开和折叠内容的可点击横幅。让我们看一个真实的例子。想象一下，你想要分享公司主要地址的位置。你还想要包括分公司。由于大多数人不会关心其他办公室，我们可以使用一个简单的可折叠内容小部件来默认隐藏内容。下面的代码片段，`7-5` 展示了一个例子：

```js
Listing 7-5: test5.html
<!DOCTYPE html>
<html>
<head>
<title>Collapsible Content</title>
<meta name="viewport" content="width=device-width, initial- scale=1">
<link rel="stylesheet" href="http://code.jquery.com/mobile/ latest/jquery.mobile.min.css" />
<script src="img/jquery- 1.7.1.min.js"></script>
<script src="img/ jquery.mobile.min.js"></script>
</head>
<body>
<div data-role="page" id="first">
<div data-role="header">
<h1>Our Offices</h1>
</div>
<div data-role="content">
<p>
<strong>Main Office:</strong><br/>
400 Elm Street<br/>
New York, NY<br/>
90210
</p>
<div data-role="collapsible">
<h3>Satellite Offices</h3>
<p>
<strong>Asia:</strong>
Another Address Here
</p>
<p>
<strong>Europe:</strong>
Another Address Here
</p>
<p>
<strong>Mars:</strong>
Another Address Here
</p>
</div>
</div>
</div>
</body>
</html>

```

你可以看到其他办公室都被使用新的可折叠内容角色的 `div` 标签包裹着。查看时，请注意它们是隐藏的：

![使用可折叠内容](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_07_05.jpg)

点击标题旁边的 **+** 将其打开，再次点击将其重新关闭：

![处理可折叠内容](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_07_06.jpg)

默认情况下，jQuery Mobile 会折叠和隐藏内容。当然，您也可以告诉 jQuery Mobile 初始化块时打开而不是关闭。要这样做，只需在初始的`div`标签中添加`data-collapsed="false"`。例如：

```js
<div data-role="collapsible" data-collapsed="false">
<h1>My News</h1>
<p>This is the latest news about me...
</div>

```

这个区域仍然具有折叠和打开的能力，但默认情况下会打开。

可折叠内容块的另一个选项是对折叠区域的内容进行主题化。通过提供`data-content-theme`属性，您可以指定一个背景颜色，使区域更具连贯性。主题化在第十一章中有介绍，*主题化 jQuery Mobile*，但我们可以看一个快速示例。在以下截图中，第一个区域没有使用该功能，而第二个区域使用了：

![处理可折叠内容](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_07_08.jpg)

注意到图标也向右移动了。这展示了另一个选项，`data-iconpos`。在`code`文件夹中的`test5-2.html`中找到的以下代码片段演示了这些选项：

```js
<div data-role="collapsible">
<h3>First</h3>
<p>
Hello World...
</p>
</div>
<div data-role="collapsible" data-content-theme="c" data- iconpos="right">
<h3>First</h3>
<p>
Hello World again...
</p>
</div>

```

最后，您可以将多个可折叠区域合并成一个称为手风琴的单元。只需将多个可折叠块放入一个新的`div`标签中即可完成此操作。这个`div`标签使用`data-role="collapsible-set"`将内部块作为一个单位。`清单 7-6`演示了一个示例。它采用了早期的办公地址示例，并为每个唯一的地址使用了一个可折叠集：

```js
Listing 7-6: test6.html
<!DOCTYPE html>
<html>
<head>
<title>Collapsible Content</title>
<meta name="viewport" content="width=device-width, initial- scale=1">
<link rel="stylesheet" href="http://code.jquery.com/mobile/ latest/jquery.mobile.min.css" />
<script src="img/jquery- 1.7.1.min.js"></script>
<script src="img/jquery.mobile.min.js"></script>
</head>
<body>
<div data-role="page" id="first">
<div data-role="header">
<h1>Our Offices</h1>
</div>
<div data-role="content">
<div data-role="collapsible-set">
<div data-role="collapsible">
<h3>Main Office</h3>
<p>
400 Elm Street<br/>
New York, NY<br/>
90210
</p>
</div>
<div data-role="collapsible">
<h3>Asia</h3>
<p>
Another Address Here
</p>
</div>
<div data-role="collapsible">
<h3>Europe</h3>
<p>
Another Address Here
</p>
</div>
<div data-role="collapsible">
<h3>Mars</h3>
<p>
Another Address Here
</p>
</div>
</div>
</div>
</div>
</body>
</html>

```

在`清单 7-6`中，我们只需使用一个可折叠集的`div`标签包装四个可折叠块。完成后，jQuery Mobile 将它们分组在一起，并在打开另一个时自动关闭一个：

![处理可折叠内容](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_07_07.jpg)

# 概要

在本章中，我们更多地了解了 jQuery Mobile 如何增强基本的 HTML，以为我们的移动页面提供额外的布局控件。通过对话框，我们学会了向用户提供基本、快速、模态消息的方法。通过网格，我们学到了一种新的方法来轻松地将内容布局在列中。最后，通过可折叠的内容块，我们学到了一种很酷的方式来分享额外的内容，而不占用太多的屏幕空间。

在下一章中，我们将演示一个完整的、真实的示例，创建一个基本的笔记跟踪器。它利用了额外的 HTML5 功能，以及你在过去几章中学到的一些 UI 技巧。
