# jQueryMobile 秘籍（一）

> 原文：[`zh.annas-archive.org/md5/55209463BC487F6190B6A043F64AEE64`](https://zh.annas-archive.org/md5/55209463BC487F6190B6A043F64AEE64)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

jQuery Mobile 是一款获奖的基于 HTML5/CSS3 的开源、跨平台 UI 框架。它提供了一个非常酷和高度可定制的 UI。它建立在流行的 jQuery 库上，并使用声明式编码，使其易于使用和学习。考虑到它支持的众多浏览器和平台，它是市场领导者。

*jQuery Mobile Cookbook* 提供了超过八十个简单易懂的配方。您可以快速学习并立即开始编写代码。高级主题，如使用脚本来操纵、自定义和扩展框架，也会涉及到。这些技巧解决了您日常遇到的常见问题。本书对于初学者和经验丰富的 jQuery Mobile 开发人员都非常有用。

您首先会使用各种控件开发简单的应用程序，然后学习如何自定义它们。稍后，您将探索使用高级功能，如配置、事件和方法。

开发单页和多页应用程序。使用缓存来提升性能。使用自定义过渡效果、图标精灵、样式和主题。学习高级特性，如配置、事件和方法。利用 jQuery Mobile 探索 HTML5 的新特性和语义。

*jQuery Mobile Cookbook* 是一本易于阅读的书，内容丰富，附有实用的技巧和截图。

# 本书内容概述

第一章，*入门*，开始简要介绍 jQuery Mobile 框架是什么以及它对您有什么作用。您将在此处编写您的第一个 jQuery Mobile 跨平台应用程序。您还将了解如何使用在线的 `JSBin` 工具来开发和测试您的应用程序。

第二章，*页面和对话框*，在这里您将学习如何比较和使用单页和多页模板应用程序。您将学习各种性能优化技术，如预取和使用 DOM 缓存来提高页面加载速度。您将使用 JavaScript 和 CSS 创建新的自定义过渡效果，并学习如何为登录页面使用页面重定向。您还将创建一个自定义样式的对话框，并使用 HTML5 History API 来创建自己的自定义弹出窗口。

第三章，*工具栏*，在这里您将学习如何使用固定和全屏工具栏以及如何在页面之间保持导航链接的持久性。您将了解如何创建和添加自定义圆形按钮、图像以及标题栏的自定义返回按钮，以及页脚的网格布局。

第四章，*按钮和内容格式化*，在这里你将使用 JavaScript 动态创建按钮并分配动作。然后，你将学习如何使用自定义图标、添加自定义图标精灵，最后替换 jQuery Mobile 框架提供的现有图标精灵。你将学会如何创建嵌套手风琴（可折叠集），如何创建自定义布局网格，最后看到如何格式化和显示应用程序中的 XML 和 JSON 内容。

第五章，*表单*，向你展示了如何原生样式化表单、禁用文本控件，并将单选按钮分组成多行网格。你将学会自定义复选框组、自动初始化选择菜单，并创建动态翻转开关和滑块控件。你还将学会验证并将表单提交到服务器使用 `POST`，以及如何使用 `GET` 获取数据。最后，你将学会创建一个可访问的表单。

第六章，*列表视图*，在这里你将学习如何使用各种列表类型并自定义它们。你将使用嵌入列表、自定义编号列表，然后创建只读列表。你将了解如何格式化列表内容，使用拆分按钮和图像图标列表。你还将为列表创建自定义搜索过滤器，最后看到如何使用 JavaScript 修改列表。

第七章，*配置*，向你展示了如何调整、配置和自定义 jQuery 移动框架提供的各种选项和设置。包括配置活动类、启用 Ajax、自动初始化页面、配置默认转换、自定义错误和页面加载消息、以及使用自定义命名空间，以及一些更高级的配置选项。

第八章，*事件*，向你展示了如何使用框架中提供的各种事件。你将学会如何使用方向、滚动、触摸、虚拟鼠标和布局事件，以及页面初始化、页面加载、页面更改和页面移除事件。你还将了解如何使用页面转换和动画事件。

第九章，*方法和实用工具*，在这里你将学习如何使用框架中提供的方法和实用工具。本章介绍了框架提供的方法，并列出了每个方法的工作示例。你将学会如何加载页面，更改页面，以及如何进行静默滚动。

第十章，*主题框架*，在这里你将学习如何为嵌套列表设置主题，样式化按钮角，使用自定义背景和字体。你将探索如何覆盖全局活动状态并覆盖现有的颜色方案。最后，你将使用 `ThemeRoller` 网页工具创建并使用自己的颜色方案。

第十一章，*HTML5 和 jQuery Mobile*，在这里您将学习如何在您的 jQuery 移动应用中使用各种 HTML5 特性。您将探索一些新的 HTML5 语义，使用应用缓存将您的应用程序离线，使用 Web Workers 看看如何进行异步操作，并且您将使用 Web 存储使用本地和会话存储来存储数据。然后，您将学习如何在 Canvas 中绘制二维图形，使用 SVG 图像并对其应用高斯模糊滤镜，使用地理位置 API 跟踪您的设备位置，并最终学习如何在应用中使用音频和视频。

# 本书所需的条件

要使用 jQuery Mobile，您只需您喜爱的文本编辑器编写 HTML 代码。然后，您可以在您喜爱的浏览器中运行此代码，并在广泛的平台和设备上启动您的应用程序。支持的平台和设备的全面详细列表可在 [`jquerymobile.com/gbs`](http://jquerymobile.com/gbs) 上找到。

要安装和运行食谱书中的食谱，您将需要从 [`www.nodejs.org`](http://www.nodejs.org) 下载并安装`node.js` Web 服务器。nodejs 网站上的在线文档中有安装到您特定平台（Windows/Linux/Mac）所需的简单步骤。随附此食谱书的源代码包只需要解压缩，它包含所有所需的 nodejs 模块。您现在可以直接在浏览器中启动食谱。有关如何执行此操作的详细说明，请参阅源代码包中的`Readme.txt`文件。

# 本书适合谁

如果您是一位具有 jQuery/JavaScript 技能的初学者，本书为您提供了大量示例来帮助您入门。

如果您是一位经验丰富的开发者，本书将让您更深入地探索 jQuery Mobile。

# 约定

在本书中，您将找到一些区分不同信息类型的文本样式。以下是这些样式的一些示例，以及它们的含义解释。

文本中的代码词如下所示：“现在，打开您喜爱的浏览器中的`main.html`文件，您将看到类似以下截图的输出：”。

代码块设置如下：

```js
<body>
  <!-- Main Page -->
  <div id="main" data-role="page">
    <div data-role="header">
      <h1>Welcome - JS BIN</h1>
    </div>
    <div id="content" data-role="content">
      <p>The jQuery Mobile Cookbook</p>
    </div>
    <div data-role="footer">
      <h4>Enjoy reading the book ...</h4>
    </div>
 </div>
</body>
</html>
```

当我们希望引起您对代码块的特定部分的注意时，相关的行或项目会以粗体显示：

```js
<!DOCTYPE html>
<html>
<head>
<link href="http://code.jquery.com/mobile/latest
  /jquery.mobile.css" rel="stylesheet" type="text/css" />
<script src="http://code.jquery.com
 /jquery-1.7.1.min.js"></script>
<script src="http://code.jquery.com/mobile/latest
  /jquery.mobile.js"></script>
<meta name="viewport" content="width=device-width, 
 initial-scale=1">
<title>Welcome using JS Bin</title>
</head>
```

**新术语** 和 **重要词汇** 以粗体显示。您在屏幕上看到的词语，例如菜单或对话框中的词语，会在文本中显示为：“您还可以通过单击**使用 JS 运行**按钮来手动运行脚本。”

### 注意

警告或重要说明会显示在如此的框中。

### 提示

技巧和窍门如此显示。


# 第一章：入门

在本章中，我们将涵盖以下内容：

+   编写您的第一个 jQuery Mobile 应用程序

+   使用 JS Bin 创建一个简单的应用程序

# 介绍

**jQuery Mobile 框架**是一个开源的跨平台 UI 框架。它使用 HTML5、CSS3 和非常流行的 jQuery JavaScript 库构建，并遵循开放网络标准。它提供了专为移动设备设计的触摸友好型 UI 小部件。它具有强大的主题框架，可为您的应用程序设置样式。它支持 AJAX 以执行各种任务，如页面导航和过渡效果。

由于 jQuery Mobile 遵循开放网络标准，您可以确保您的应用程序能够在广泛的浏览器和平台上获得最大的支持和兼容性。您只需编写一次应用程序，它就能在 iPhone、iPad、Android 手机和平板电脑、Blackberry、Bada、Windows、Symbian、Meego 甚至即将推出的基于 HTML5 的平台（如 Boot2Gecko 和 Tizen）上无缝运行。同样的代码将在 Chrome、Firefox、Opera、IE、Safari 和桌面上的其他浏览器上运行。此外，它甚至可以在您的智能电视或任何具有与开放网络标准兼容的浏览器的其他设备上运行。市场覆盖潜力是巨大的。

目前认证的支持浏览器、平台和支持等级的列表可在 jQuery Mobile 网站上查看 [`www.jquerymobile.com/gbs`](http://www.jquerymobile.com/gbs)。请注意，某些功能，如 CSS 3D 动画和 AJAX，可能不受某些较老和传统平台的支持。在这种情况下，该框架采用 **渐进增强**。这意味着最初支持基本功能。以后，当更有能力的未来浏览器或平台可用时，您的应用程序将自动利用其功能并提供升级功能。在大多数情况下，您不需要编写代码或以任何方式干预。与移动原生应用程序相比，这是一个很大的优势。

在编写本机应用程序时，您将不得不使用不同的语言编写代码，这取决于平台。然后，您将不得不为每个平台编译代码，并构建可以在设备上运行的二进制包。升级应用程序以支持下一个版本意味着您必须回过头来重新执行整个检查/修复代码、重新构建和重新打包的过程。随着您为更多平台添加支持，这种额外的工作量会不断增加。在某个点之后，整个过程就变得难以管理。您最好只支持应用程序的前一两个平台。

当然，使用原生应用程序也有优势。你的应用程序的性能可能是一个非常关键的因素。在某些应用程序中，你必须使用原生应用程序，特别是当你期望实时响应时。此外，使用原生应用程序，你可以访问核心操作系统和设备功能，例如摄像头、加速计、联系人和日历。今天使用 HTML5 实现这些并不容易。

**HTML5**是移动应用程序的一个相对新的参与者。但是差距正在逐渐缩小。已经有库可用，使用简单的 JavaScript API 暴露原生功能，该 API 直接可用于你的 HTML5 应用程序。PhoneGap 就是这样一个流行的库。Firefox 的 Boot2Gecko 和 Intel/Samsung 的 Tizen 完全基于 HTML5，你应该能够直接从浏览器中访问核心设备功能。未来看起来非常有前途。

jQuery Mobile 框架拥有大量的插件和工具，可以帮助您构建应用程序。它拥有一个非常活跃和充满活力的开发者社区，并且不断添加新功能。它受到诸如 Filament Group、Mozilla、Nokia、Palm、Adobe、Rhomobile 等公司的大力支持。在它的第一年（2011 年），该框架已经获得了 Packt 开源奖和.NET 创新奖等奖项。

基于 Web 的移动应用程序已经发展了。在早期，它们使用纯原生代码进行 UI 开发，然后出现了 Flash 和其他基于插件的 UI（例如 Silverlight）。但是，即使是 Adobe 和微软（使用其 Windows 8 平台）也在全力推进 HTML5 开发。因此，情况非常适合像 jQuery Mobile 这样的基于开源 Web 标准的跨平台框架迅猛增长。

jQuery Mobile 框架要求你对大多数基本任务和构建 UI 使用声明性语法（HTML 标记）。你必须仅在声明性语法无法帮助的情况下以及当然要添加你的应用程序逻辑时，才退回到只使用 JavaScript 编写脚本。这与今天市场上的许多其他 UI 框架不同。其他框架要求你编写更多的 JavaScript，并且学习曲线更陡峭。

如果你熟悉 HTML、CSS 和 jQuery/JavaScript，那么学习 jQuery Mobile 将会变得非常容易。有许多流行的 IDE 和 UI 构建工具可供您使用，以便通过可视化拖放 UI 控件并在 jQuery Mobile 中进行开发。但是，要开始，你只需要你喜欢的文本编辑器来编写代码。你还需要一个浏览器（在你的桌面或移动设备上运行）来测试应用程序。现在，你已经准备好编写你的第一个 jQuery Mobile 跨平台应用程序了。

# 编写你的第一个 jQuery Mobile 应用程序

简单的 jQuery Mobile 应用程序由一个页面组成，这是构建应用程序的基本构建块。页面遵循具有三个主要部分的基本结构，即**页眉**、**页面内容** 和**页脚**。您可以使用多个页面构建功能丰富的应用程序，每个页面具有自己的功能、逻辑和导航流程。此示例展示了如何创建一个页面并编写您的第一个 jQuery Mobile 应用程序。

## 准备就绪

从 `code/01/welcome` 文件夹复制此示例的完整代码。您可以使用以下 URL 启动此代码：`http://localhost:8080/01/welcome/main.html`。

## 如何做...

执行以下步骤：

1.  使用您喜欢的文本编辑器创建以下 `main.html` 文件：

    ```js
    <!DOCTYPE html>
    <html>
      <head>
        <title>Welcome</title>
        <meta name='viewport' content='width=device-width, 
          initial-scale=1'>
    ```

1.  包含 jQuery 和 jQuery Mobile JavaScript 文件：

    ```js
     <link rel='stylesheet' href='http://code.jquery.com
     /mobile/1.1.1/jquery.mobile-1.1.1.min.css' />
     <script src='http://code.jquery.com/jquery-
     1.7.1.min.js'></script>
     <script src='http://code.jquery.com/mobile
     /1.1.1/jquery.mobile-1.1.1.min.js'></script>
      </head>
      <body>
    ```

1.  创建 jQuery Mobile 页面：

    ```js
        <!-- Main Page -->
     <div id='main' data-role='page'>
          <div data-role='header'>
            <h1>Welcome!</h1>
          </div>
     <div id='content' data-role='content'>
            <p>The jQuery Mobile Cookbook</p>
          </div>
     <div data-role='footer'>
            <h4>Enjoy reading the book ...</h4>
          </div>
        </div>
      </body>
    </html>
    ```

## 它是如何工作的...

创建 `main.html` 作为一个以 `<!DOCTYPE html>` 声明开始的 HTML5 文档。在文件的 `<head>` 标签中，添加一个 `<meta>` 标签，并通过使用 `content='width=device-width'` 属性指定视口应占用整个设备宽度。通过使用指向 jQuery Mobile 内容交付网络 (CDN) 站点上 CSS 文件位置的 `<link>` 标签，包含 jQuery Mobile 样式表。

接下来，包含 JavaScript 库；先是 jQuery，然后是 jQuery Mobile JavaScript 文件。使用 `<script>` 标签，将 `src` 指向 CDN 位置，如代码所示。现在您已经准备好创建页面了。

页面、其页眉、页脚和内容都是 `<div>` 容器，通过使用 `data-role` 属性进行样式设置。在 `<body>` 标签中添加一个带有 `data-role='page'` 的 `<div>` 标签。在页面内作为子元素分别添加三个带有 `data-role='header'`、`'content'` 和最后 `'footer'` 的 `<div>` 标签。这将分别创建页面的页眉、内容和页脚。您可以在这些 `<div>` 标签内添加任何文本、表单、列表或其他 HTML 控件。框架将以触摸友好的移动启用样式增强和渲染控件。

现在，使用您喜欢的浏览器打开 `main.html` 文件，您将看到类似以下截图的输出：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_01_01.jpg)

在不同的浏览器、移动设备和平板电脑中打开并比较此文件的输出。您将看到在所有符合规范和认证的浏览器/设备上，页面都会打开并且看起来几乎一样。

恭喜！您刚刚创建了您的第一个跨平台 jQuery Mobile Web 应用程序。

## 还有更多...

在编写此示例时，jQuery Mobile v1.1.1 是稳定版本，并在本书中的所有示例中使用。建议使用的支持的 jQuery 库是 jQuery v1.7.1。

您可以直接从 jQuery Mobile CDN 使用库，就像本示例中所示的那样。您还可以从 [`www.jquerymobile.com/download`](http://www.jquerymobile.com/download) 下载库文件（以单个压缩文件的形式提供），并将文件托管到您的网络中。当本地托管时，您只需更新代码中的链接，以指向文件在您的网络上的正确位置（或您硬盘上的路径），如下面的代码片段所示：

```js
<link rel="stylesheet" href='[local path]/jquery.mobile-
  1.1.1.min.css' />
<script src='[local path]/jquery-1.7.1.min.js'></script>
<script src='[local path]/mobile/1.1.1/jquery.mobile-
  1.1.1.min.js'></script>
```

### 页面主题

默认情况下，框架提供了五种基本的颜色方案或组合，称为**颜色样本**。它们被命名为 `a`、`b`、`c`、`d` 和 `e`。默认情况下，创建页面时使用样本 `d`。这使得页面具有白色和黑色的明亮组合，如前面的屏幕截图所示。您可以通过使用 `data-theme` 属性来更改页面和页眉/页脚的颜色样本，如以下代码片段所示：

```js
<div data-role='page' data-theme='a'>
  <div data-role='header' data-theme='b'>
….
  <div data-role='footer' data-theme='b'>
```

输出现在将类似于以下屏幕截图：

![页面主题](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_01_02.jpg)

## 另请参阅

+   *使用 JS Bin 创建一个简单应用程序*示例

+   第二章中的*编写单页模板应用程序*和*编写多页模板应用程序*示例，*页面和对话框*

# 使用 JS Bin 创建一个简单应用程序

**JS Bin** 是由 *Remy Sharp* 开发的开源网络应用程序，位于 [`www.jsbin.com`](http://www.jsbin.com)。JS Bin 允许您在线直接输入您的 HTML、CSS 和 JavaScript 代码，并允许您包含所需的 jQuery 和 jQuery Mobile 库。您可以添加和直接运行您的 JavaScript 代码，并在浏览器上预览输出。您还可以共享您的代码，并与他人合作进行审查或故障排除。一切按照预期工作后，您最终可以下载您的代码。这是一个非常受许多 jQuery Mobile 开发人员欢迎的工具。本示例向您展示了如何使用 JS Bin 创建一个简单的 jQuery Mobile 应用程序。

## 准备就绪

本示例中的代码是使用 [JS Bin 网页应用](http://www.jsbin.com) 创建的。代码位于 `code/01/jsbin` 源文件夹中。您可以使用 `http://localhost:8080/01/jsbin/main.html` URL 启动代码。

## 如何实现...

1.  打开 [JS Bin 网页应用工具](http://www.jsbin.com)，你会看到一个基本的 HTML 模板。

1.  在左上角面板上选择 **添加库** 链接，并包含最新的 jQuery Mobile 库文件。接下来，编辑 `<head>` 部分，如以下代码片段所示：

    ```js
    <html>
      <head>
        <link href="http://code.jquery.com/mobile/latest
          /jquery.mobile.css" rel="stylesheet" type="text/css" />
     <script src="http://code.jquery.com
     /jquery-1.7.1.min.js"></script>
        <script src="http://code.jquery.com
          /mobile/latest/jquery.mobile.js"></script>
     <meta name="viewport" content="width=device-width, 
     initial-scale=1">
     <title>Welcome using JS Bin</title>
      </head>
    ```

1.  向 `<body>` 部分添加代码以创建一个简单的 jQuery Mobile 页面：

    ```js
      <body>
        <!-- Main Page -->
        <div id="main" data-role="page">
          <div data-role="header">
            <h1>Welcome - JS BIN</h1>
          </div>
          <div id="content" data-role="content">
            <p>The jQuery Mobile Cookbook</p>
          </div>
          <div data-role="footer">
            <h4>Enjoy reading the book ...</h4>
          </div>
        </div>
      </body>
    </html>
    ```

1.  预览或输出现在显示在屏幕右侧的 **输出** 面板中。

1.  您现在可以下载源文件（或将其复制粘贴到本地文件中），以获得一个简单的可工作的 jQuery Mobile 应用程序。

## 工作原理...

在浏览器中启动 JS Bin Web 应用程序。您将在浏览器中看到以下屏幕，左侧有一个基本的 HTML 模板（您可以编辑），顶部有一个菜单栏，右侧有一个**输出**窗格，可立即预览代码的输出：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_01_03.jpg)

您可以单击各种菜单选项，查看**CSS**或**JavaScript**窗格如何可见或隐藏。选择**自动运行 JS**选项将允许您自动运行您的 JS 代码；您可以将其保留。您也可以通过单击**Run with JS**按钮手动运行脚本。

单击**添加库**菜单选项，并选择**jQuery Mobile Latest**选项，如下截图所示：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_01_04.jpg)

这将在 HTML 的`<head>`部分包含指向 jQuery Mobile 和 jQuery 库的链接和引用。

### 注意

当您使用 JS Bin 添加 jQuery Mobile 库到您的代码时，请确保编辑并设置要与您的应用程序一起使用的 jQuery Mobile 和 jQuery 库的正确版本。在编写此示例时，JS Bin 使用的是 jQuery v1.6.4，而 jQuery v1.7.1 推荐与 jQuery Mobile v1.1.1 一起使用。

接下来，编辑`<meta>`标签以设置正确的视口`宽度`和`缩放`，如代码所示。然后，使用`data-role="page"`的`div`标签向`<body>`标签添加一个页面。创建标题(`data-role="header"`)、页面内容(`data-role="content"`)和页脚(`data-role="footer"`)，如所示。当您添加这些部分时，您会注意到屏幕右侧的**输出**窗格会更新，并显示代码的输出预览。

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_01_05.jpg)

您还可以添加 CSS 样式和 JavaScript，并检查其工作原理。最后，您的代码已准备就绪，您可以将其复制粘贴到本地编辑器中。您还可以点击左上角的**JS Bin**菜单选项下载文件。现在，启动本地文件在浏览器中，您会发现输出与 JS Bin 的**输出**窗格中显示的内容相匹配。

## 还有更多...

这个示例向您展示了使用 JS Bin 创建基本 jQuery Mobile 应用程序所需的简单步骤。JS Bin 提供了许多方便使用的功能，例如创建和使用准备好的模板、使用 GitHub 保存和分叉您的代码以及克隆您的代码。此工具最适合您想要在线存储文件并在源文件上进行协作时使用。有关使用 JS Bin 的更多信息和教程，请参阅[`jsbin.tumblr.com/`](http://jsbin.tumblr.com/)。

### 注意

您可以免费注册并使用您的用户帐户登录 JS Bin 以使用保存、下载或克隆功能。没有用户登录时只提供基本功能。

## 另请参阅

+   *编写您的第一个 jQuery Mobile 应用程序*示例


# 第二章：页面和对话框

在本章中，我们将讨论：

+   编写单页模板应用程序

+   编写多页模板应用程序

+   预取页面以实现更快的导航

+   使用 DOM 缓存以提高性能

+   自定义样式对话框

+   使用 CSS 创建跳转页面过渡效果

+   使用 JS 创建幻灯片和淡入淡出的页面过渡效果

+   使用`data-url`处理登录页面导航

+   使用 History API 创建自定义错误弹出框

# 介绍

一个**页面**是写在`<div data-role="page">`容器内的基本 jQuery Mobile 对象，它显示在屏幕上。它可以包含页眉、页面内容和页脚。您可以在页面内嵌入各种 HTML5 控件和微件。jQuery Mobile 框架会自动增强和显示所有这些控件，使它们适合轻触（手指触摸）。您的应用程序可以有一系列单独的 HTML 文件，每个文件代表一个单独的页面，或者可以有一个包含多个页面`div`容器的单个 HTML 文件。您可以提供链接以在一个页面内打开其他页面，用户点击链接时，新页面将使用 Ajax 和 CSS3 动画打开。当前页面然后不再显示。

一个**对话框**是具有`data-role="dialog"`属性的页面。您还可以通过为页面链接添加`data-rel="dialog"`属性来将页面加载为对话框。对话框的样式与页面不同，并且出现在页面上方的屏幕中间。对话框的标题栏还提供了一个关闭按钮。

# 编写单页模板应用程序

在**单页模板**应用程序中，应用程序的每个页面都有自己的 HTML 文件。页面包装在`<div data-role="page">`内。启动应用程序时，jQuery Mobile 框架将第一页（或主要页面）加载到 DOM 中，并在整个应用程序周期中保留其引用。当用户导航到另一个页面时，主页面仅被隐藏，并且现在标记为活动页面的其他所有页面都会从 DOM 中被删除。页面之间的导航使用锚链接指定。锚链接使用`data-role="button"`属性装饰为按钮。单击任何链接时，将使用一些精彩的 CSS3 过渡进行导航，并通过 Ajax 拉入新页面。

此示例向您展示如何创建一个单页模板应用程序，并在应用程序的页面之间导航。

## 准备工作

从`code/02/single-page`源文件夹中复制此示例的完整代码。您可以使用`http://localhost:8080/02/single-page/main.html`网址启动此代码。

## 如何做...

执行以下步骤：

1.  创建`main.html`，并向其中添加一个包含页眉、页脚和页面内容的页面容器。添加打开`page2.html`的链接：

    ```js
    <div id="main" data-role="page">
      <div data-role="header">
        <h1>Header of main.html</h1>
      </div>
      <div data-role="content">
     <a href="page2.html" data-role="button">
     Go to Page 2</a>
       </div>
     <div data-role="footer">
       <h4>Footer of main.html</h4>
     </div>
    </div>
    ```

1.  由于这是一个单页模板应用程序，将每个页面添加到自己的 HTML 文件中。接下来，创建`page2.html`并将应用程序的第二个页面添加到其中。添加一个链接以返回到`main.html`。

    ```js
    <div id="page2" data-role="page">
      <div data-role="header">
        <h1>Header of page2.html</h1>
      </div>
      <div data-role="content">
     <a href="#" data-role="button" data-rel="back" 
     data-theme="b">Go Back</a>
      </div>
      <div data-role="footer">
        <h4>Footer of page2.html</h4>
      </div>
    </div>
    ```

## 它是如何工作的...

创建`main.html`，并使用指定了`data-role="page"`属性的`<div>`页面容器向其中添加页面。按照代码所示的方式，添加页眉、页脚和页面内容。现在，在页面内容中，添加一个锚链接以打开第二页`page2.html`。你可以使用`data-role="button"`属性来将此链接样式化为按钮。

接下来，创建`page2.html`并使用指定了`data-role="page"`属性的`<div>`页面容器向其中添加页面。按照代码清单中所示的方式，添加页眉、页脚和页面内容。在页面内容中，添加一个锚链接以返回到`main.html`。同时，设置`data-role="button"`属性来将此链接样式化为按钮。

现在，当你启动应用程序时，`main.html`页面首先加载到 DOM 中。此页面在整个应用程序的生命周期内保持在 DOM 中。如下图所示：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_02_01.jpg)

当你点击按钮打开`page2.html`时，主页面被隐藏，`page2.html`被显示并激活，如下图所示：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_02_02.jpg)

现在，点击链接返回到`main.html`。浏览器再次打开`main.html`页面并隐藏`page2.html`。

在`page2.html`中，锚按钮具有`data-rel="back"`属性。这表示应该加载浏览器历史记录中的上一个页面。`href`链接将被忽略，因此可以将其设置为`#`。

### 提示

**为单页模板应用程序设置标题**

使用`<title>`标签为单页应用的每个页面设置页面标题。这样可以确保在浏览应用程序的各个页面时显示相关的标题。

## 还有更多...

推荐大多数应用程序使用单页模板，原因如下：

+   页面更轻量、更干净、更模块化，因此更易于维护。

+   DOM 大小相对较小。

+   页面在多个平台和环境下工作良好。它们即使在不支持 JavaScript 的情况下也可以工作。这样可以使你的应用程序能够覆盖更多设备。

另一方面：

+   每次访问页面时都会生成一个新的请求，这会消耗更多的带宽。

+   再次打开先前加载的页面将生成一个全新的请求。

+   第一次加载更快，但随后每个页面都必须被获取。

总之，单页模板应用程序更适合于较大的应用程序以及希望覆盖尽可能多平台的情况。

### 关闭 Ajax 导航

在此示例中，在`#page2`中，`href`值设置为`#`。如果您将`href`值设置为页面的绝对或相对 URL，即`href="main.html"`，那么 Ajax 导航仍将工作。要防止通过 Ajax 加载页面，请将`data-ajax="false"`属性添加到链接中。当关闭 Ajax 时，框架将不使用自定义 CSS3 过渡。

```js
<a href="page2.html" data-role="button" data-ajax="false">text</a>
```

### 提示

**使用 URL 而不是`data-rel="back"`**

在单页应用程序中导航时，最好始终在锚链接的`href`中使用 URL。这样，Ajax 导航将在支持 Ajax 的情况下工作。在不支持 Ajax 的 C 级浏览器中，应用程序仍将继续工作，因为它使用`href`进行导航。在这样的浏览器中，如果您的应用程序仅依赖于`data-rel="back"`属性，而不使用`href`，那么页面导航将中断。

### 使用`data-rel`和`data-direction`

当您同时向锚链接添加`href`和`data-rel="back"`属性时，框架将忽略`href`属性。页面将仅考虑`data-rel`属性并导航“返回”; 也就是说，它将导航到浏览器历史堆栈中作为前一个条目的页面。如果指定了`data-direction="reverse"`属性，则框架将反转最近使用的页面转换的方向。`data-direction`属性不依赖于`data-rel`属性，并且可以在任何转换中独立使用。

```js
<a href="page2.html" data-role="button" 
    data-direction="reverse">text</a>
```

### 页面容器是可选的

在单页模板应用程序中，指定`<div data-role="page">`页面容器是可选的。页面内容将由 jQuery Mobile 框架自动包装为页面容器。

### 注意

始终使用`div`页面容器来包装您的页面。这样做更易读，更易维护代码。它还允许您向页面添加特定于页面的数据属性，例如`data-theme`。

## 另请参阅

+   *编写多页模板应用*、*为了更快的导航而预取页面*和*使用 DOM 缓存来提高性能*的技巧

+   *编写您的第一个 jQuery Mobile 应用程序*在第一章，*介绍*

# 编写多页模板应用

在多页面模板应用程序中，HTML 文件将包含多个页面。每个页面都包装在 `<div data-role="page">` 中。页面 ID 用于标识页面以便在它们上面进行链接或调用任何操作。页面 ID 在你的应用程序中必须是唯一的。当你启动应用程序时，jQuery Mobile 框架会将所有可用页面加载到 DOM 中，并显示在 HTML 中找到的第一个页面。页面之间的导航通过使用锚链接指定，并且你可以通过使用 `data-role="button"` 属性将这些链接装饰为按钮。单击任何链接时，导航通过一些很酷的 CSS3 过渡发生，并且通过 Ajax 拉入新页面。本配方向你展示如何创建一个多页面模板应用程序，并在其中多个页面之间导航。

## 准备工作

从`code/02/multi-page`源文件夹中复制此配方的完整代码。你可以使用 URL `http://localhost:8080/02/multi-page/main.html` 启动此代码。

## 如何做...

执行以下步骤：

1.  创建 `main.html`，并向其添加 `#main` 页面。按照以下代码片段中所示的方式定义页眉、页面内容和页脚。在页面内容中添加一个链接来打开 `#page2` 页面：

    ```js
    <div id="main" data-role="page">
      <div data-role="header">
        <h1>Header of #main</h1>
      </div>
      <div data-role="content">
     <a href="#page2" data-role="button">Go to Page 2</a>
      </div>
      <div data-role="footer">
        <h4>Footer of #main Page</h4>
      </div>
    </div>
    ```

1.  接下来，在 `main.html` 中，如下所示地在其自己的页面 `div` 容器中添加第二个 `#page2` 页面。向此页面添加页眉、页面内容和页脚。最后，在页面内容中添加一个链接以返回 `#main` 页面：

    ```js
    <div id="page2" data-role="page" data-title="Multi-Page Template">
      <div data-role="header">
        <h1>Header of #page2</h1>
      </div>
      <div data-role="content">
     <a href="#" data-role="button" data-rel="back" data-theme="b">Go Back</a>
      </div>
      <div data-role="footer">
        <h4>Footer of #page2</h4>
      </div>
    </div>
    ```

    ### 提示

    **下载示例代码**

    你可以从你在[`www.PacktPub.com`](http://www.PacktPub.com)账户购买的所有 Packt 书籍中下载示例代码文件。如果你在其他地方购买了这本书，你可以访问[`www.PacktPub.com/support`](http://www.PacktPub.com/support)并注册，直接将文件通过电子邮件发送给你。

## 工作原理...

创建`main.html`，并向其添加两个页面，`#main` 和 `#page2`。首先，使用指定了 `data-role="page"` 属性的 `<div>` 页面容器添加 `#main` 页面。按照代码中所示的方式添加页眉、页脚和页面内容。现在，添加一个锚链接到页面内容，以打开第二个页面 `#page2`。你可以通过使用 `data-role="button"` 属性将此链接样式化为按钮。

接下来，使用指定了 `data-role="page"` 属性的 `<div>` 页面容器添加 `#page2` 页面。按照代码列表中所示的方式向其添加页眉、页脚和页面内容。在这里，页面内容中添加了回到 `#main` 页面的锚链接。设置 `data-role="button"` 属性将其样式化为按钮。还将 `data-rel="back"` 属性添加到其中。这指示 jQuery Mobile 框架，此链接应打开浏览器历史记录中可用的上一页。

现在，当你启动应用时，所有页面都加载到 DOM 中，并在整个应用的生命周期内保留在 DOM 中。框架将打开它找到的第一个页面。所以，`#main`显示有一个按钮可以打开`#page2`，如下所示：

![工作原理...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_02_03.jpg)

当你点击按钮打开第二个页面时，`#main`页面会从视图中隐藏，而`#page2`页面会显示并激活，如下所示：

![工作原理...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_02_04.jpg)

最后，点击链接返回`#main`页面。由于使用了`data-rel="back"`，浏览器会再次打开`#main`页面并隐藏`#page2`。

### 提示

**为多页面模板应用设置标题**

使用`<title>`标签为多页面模板应用的第一个或主要页面设置页面标题。使用`data-title`属性为所有其他页面设置标题。这将确保每个页面显示正确的标题。

## 还有...

在使用多页面模板构建应用之前，建议考虑以下因素：

+   多页面模板应用由于 DOM 尺寸较大而更加沉重。

+   由于所有页面都预加载到 DOM 中，因此 DOM 尺寸较大且更沉重。

+   应用需要 JavaScript 支持。这会限制你的目标平台选择，并且你可能需要忽略许多流行的旧平台。但随着老旧电话/平台逐渐淘汰，这个排除列表正在变得越来越短。

此外：

+   只有第一次页面加载较慢，但后续的页面导航都很快。

+   所有页面都预加载到 DOM 中，因此后续页面导航不需要新请求（到服务器）。这意味着更少的带宽。

总之，多页面模板应用更适合相对较小的应用和你知道目标平台能力（包括 JavaScript 支持）的情况。

### 注意

jQuery Mobile 支持的浏览器和平台的更新列表可在[`www.jquerymobile.com/gbs`](http://www.jquerymobile.com/gbs)找到。它还详细说明了这些平台上提供的支持等级。

### 使用过渡效果

`data-transition`属性可用于指定 jQuery Mobile 默认可用的各种过渡效果。下面的代码使用了翻转过渡效果来打开`#page2`：

```js
<a href="#page2" data-transition="flip" data-role="button">text</a>
```

### 关闭 Ajax 导航

如果在加载多模板应用中的页面时传递了`data-ajax="false"`属性，则这并不完全停止了 Ajax 导航。无论`data-transition`属性中指定的过渡效果如何，都将使用默认的淡入淡出过渡效果来加载页面。

```js
<a href="#page2" data-ajax="false" data-role="button">text</a>
```

### 页面容器是必须的

对于多页面模板应用内的所有页面，指定`<div data-role="page">`页面容器是必需的。无论是单页面模板还是多页面模板，都使用页面容器来制作你的应用和所有页面。

## 另请参见

+   *编写单页模板应用程序*、*为了更快地导航而预取页面*和*使用 DOM 缓存来提高性能*的配方

+   *编写您的第一个 jQuery Mobile 应用程序*在第一章中的*介绍*中的配方

# 为了更快地导航而预取页面

使用单页模板制作移动应用程序使您的移动应用程序更快、更轻便。但是在导航期间必须获取每个页面。每次加载页面时，您都可以看到`ui-loader`旋转图标。这个问题在多页模板应用程序中不会发生，因为所有页面都已经预加载到 DOM 中。通过使用**预取**功能，可以使单页模板应用程序模仿多页模板应用程序。

预取的页面在后台加载，并在用户尝试打开它时立即可用。可以通过两种方式预取页面。第一种是只需将`data-prefetch`属性添加到锚链接。第二种方式是使用 JavaScript 调用`loadPage()`方法。本配方向您展示如何通过在您的 jQuery Mobile 应用程序中预取页面来提高页面加载速度。

## 准备工作

从`code/02/prefetch`源文件夹中复制此配方的完整代码。您可以使用 URL `http://localhost:8080/02/prefetch/main.html`来启动此代码。

## 如何操作...

应该遵循的步骤是：

1.  创建`main.html`并向其添加两个链接。第一个链接指向`prefetch.html`，第二个链接指向`prefetch-JS.html`。在加载`main.html`文件后，其中的链接页面可以使用第一个链接上的`data-prefetch`属性在后台预取，如以下代码片段所示：

    ```js
    <div id="main" data-role="page">
      <div data-role="header">
        <h1>Header of Main Page</h1>
      </div>
      <div data-role="content">
     <a href="prefetch.html" data-role="button" 
     data-prefetch>Prefetch Page</a> 
        <a href="prefetch-JS.html" data-role="button">
            Prefetch Page using JS</a>
      </div>
      <div data-role="footer">
        <h4>Footer of Main Page</h4>
      </div>
    </div>
    ```

1.  接下来，将以下代码片段中给出的 JavaScript 添加到`main.html`的`<head>`部分。在这里，使用`loadPage()`方法将`prefetch-JS.html`文件后台加载到 DOM 中：

    ```js
      $("#main").live("pageshow", function(event, data) {
     $.mobile.loadPage( "prefetch-JS.html", 
     { showLoadMsg: false } );
      });
    </script>
    ```

1.  现在，按照以下代码片段所示创建`prefetch.html`文件。这是一个常规页面，通过`data-prefetch`属性在`main.html`页面（在步骤 1 中）中预取。还要添加一个链接以返回到`main.html`：

    ```js
    <div id="prefetch" data-role="page">
      <div data-role="header">
        <h1>Header of Prefetched Page</h1>
      </div>
      <div data-role="content">
        <a href="#" data-role="button" data-rel="back" 
            data-theme="b">Go Back</a>
      </div>
      <div data-role="footer">
        <h4>Footer of Prefetched Page</h4>
      </div>
    </div>
    ```

1.  你会看到在第 2 步中，使用 JavaScript 预取了`prefetchJS.html`。现在，按照以下代码片段所示创建`prefetchJS.html`，并添加一个链接以返回到`main.html`：

    ```js
    <div id="jsprefetch" data-role="page">
      <div data-role="header">
        <h1>Header of JS Prefetched Page</h1>
      </div>
      <div data-role="content">
        <a href="#" data-role="button" data-rel="back" 
            data-theme="b">Go Back</a>
      </div>
      <div data-role="footer">
        <h4>Footer of JS Prefetched Page</h4>
      </div>
    </div>
    ```

## 工作原理...

创建`main.html`，并向其添加两个链接。将第一个链接指向`prefetch.html`，并将`data-prefetch`属性设置为此链接。此页面现在在`main.html`加载时会自动在后台获取，并在打开`main.html`时立即可用。

将第二个链接指向`prefetch-JS.html`文件。要使用 JavaScript 预取此页面，请为`#main`的`pageshow`事件添加事件处理程序。在此回调函数中，调用`loadPage()`方法以获取`prefetch-JS.html`文件。还设置`showLoadMsg`选项为`false`，以防止显示旋转的`页面 ui-loader`消息。接下来，按照代码中所示创建两个 HTML 文件。在这两个页面中都添加返回到`main.html`的链接。

现在，当您启动应用程序时，两个 HTML 文件都会被预取。您可以使用浏览器的代码检查器观察此预取行为，如下面的截图所示：

![工作原理...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_02_05.jpg)

此截图显示了在加载`main.html`页面后的 Google Chrome 浏览器中的代码检查器。我们可以看到`#prefetch`和`#jsprefetch`页面已经被预取并在 DOM 中可用。现在，导航到这些预取页面几乎是即时的，旋转的`ui-loader`图标动画不会显示出来。这使得您的应用程序速度更快，并为用户提供了更好的用户体验。如果没有使用预取，只有在导航到它时才会加载页面。

使用`data-prefetch`属性是预取页面的更简单方法，因为您不必再写任何代码。但是，使用`loadPage()`用 JavaScript 预取页面允许您向`loadPage()`方法提供更多选项，并更好地控制页面加载的行为。您还可以使用此方法构建有条件的预取。

## 还有更多...

避免在太多页面上使用预取，因为所有页面都必须被获取并存储在 DOM 中。这意味着更多的内存利用率，而内存在移动设备上是一种稀缺资源。这会减慢您的应用程序。预取的页面越多，意味着利用的带宽越多。因此，请谨慎使用。

### 当预取未完成时

如果页面尚未完全预取，并且您尝试导航到该页面，则`ui-loader`旋转器将出现，并且只有在页面完全获取后才会显示该页面。这可能发生在较慢的连接上。

### 预取的页面不会永久缓存

当页面被预取时，它会在 DOM 中可用。如果您导航到此页面，然后再次导航，该页面将自动从 DOM 中删除。因此，如果它是一个频繁访问的页面，您必须将其添加到 DOM 缓存中。

## 请参阅

+   *使用 DOM 缓存来提高性能* 配方

+   在第九章*方法和实用程序*中的*使用 loadPage()加载页面* 配方

# 使用 DOM 缓存来提高性能

在单页模板应用程序中的页面导航期间，每个新页面都会被提取并存储在 DOM 中。该页面留在 DOM 中，并在您从该页面导航离开时被删除。只有应用程序的主页面或第一个页面始终留在 DOM 中。如前面的示例所示，预取常用页面可能在一定程度上有助于提高性能。但是当您访问一个预取的页面并从中导航离开时，该页面将从缓存中移除。因此，频繁访问页面的多次提取问题并未完全解决。

使用 DOM 缓存，特定页面会在 DOM 中标记为缓存。这些页面一旦加载，就会在应用程序的整个生命周期内保留在 DOM 中。你可以以两种方式使用 DOM 缓存。第一种是通过向要缓存的页面的页面容器添加`data-dom-cache`属性。第二种方式是使用 JavaScript。本教程向你展示如何通过使用 DOM 缓存来提高应用程序的性能。

## 准备工作

从`code/02/dom-cache`源文件夹复制此教程的完整代码。您可以使用 URL `http://localhost:8080/02/dom-cache/main.html`启动此代码。

## 如何实现...

需要遵循的步骤包括：

1.  创建`main.html`文件，并添加链接以导航到两个页面，`cached.html`和`cached-JS.html`。而这两个页面又指定它们在 DOM 中应该被缓存：

    ```js
    <div id="main" data-role="page">
      <div data-role="header">
        <h1>Header of Main Page</h1>
      </div>
      <div data-role="content">
        <a href="cached.html" data-role="button">
          Cached Page
        </a>
        <a href="cached-JS.html" data-role="button">
          JS Cached Page
        </a>
      </div>
      <div data-role="footer">
        <h4>Footer of Main Page</h4>
      </div>
    </div>
    ```

1.  创建`cached.html`页面，并将其页面容器的`data-dom-cache`属性设置为 true。还添加一个按钮以返回到`main.html`页面：

    ```js
    <div id="cached" data-role="page" data-dom-cache="true">
      <div data-role="header">
        <h1>Header of Cached Page</h1>
      </div>
      <div data-role="content">
        <a href="#" data-role="button" data-rel="back">
          Go Back
        </a>
      </div>
      <div data-role="footer">
        <h4>Footer of Cached Page</h4>
      </div
    </div>
    ```

1.  最后，创建`cached-JS.html`文件，并通过添加到页面的`div`容器的 JavaScript 来将其缓存，如下面的代码段所示。添加一个按钮以导航回到`main.html`：

    ```js
    <div id="jscached" data-role="page">
      <script>
     $("#jscached").page({ domCache: true });
      </script>

      <div data-role="header">
        <h1>Header of JS Cached Page</h1>
      </div>
      <div data-role="content">
        <a href="#" data-role="button" data-rel="back">
          Go Back
        </a>
      </div>
      <div data-role="footer">
        <h4>Footer of JS Cached Page</h4>
      </div
    </div>
    ```

## 工作原理...

创建`main.html`并添加两个链接，以打开`cached.html`和`cached-JS.html`文件。接下来，创建`cached.html`文件，并添加一个返回`main.html`的链接。在这里，将`data-dom-cache="true"`属性设置为页面容器。这表示页面在加载后必须在 DOM 中缓存。

现在创建`cached-JS.html`文件，并添加返回到`main.html`的链接。在这里，将给定的脚本添加到页面的`div`容器中。在脚本中，将页面的`domCache`选项设置为`true`。现在，当加载此页面时，它将被缓存在 DOM 中。

启动应用程序并在页面之间导航。在页面导航期间，每个新页面都会被提取并存储在 DOM 中。您可以使用浏览器的代码检查器观察 DOM 缓存的行为。以下图片显示了 Chrome 代码检查器快照，显示了两个页面都被访问并在 DOM 中被缓存后的情况。当前活动的页面显示为`#main`；这通过将`ui-page-active`类添加到页面的`div`容器来指示。其他两个页面也被缓存，并且在 DOM 中也是可用的。

![工作原理...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_02_06.jpg)

### 提示

**将脚本添加到页面的 div 而不是<head>元素**

当使用 Ajax 导航时，`<head>`部分仅在第一个页面或应用程序的主页面上处理。忽略了其余页面的`<head>`元素，仅处理它们页面的`div`容器。因此，为了确保您的脚本在这些页面中执行，您必须在页面的`div`容器内包含`<script>`标签。

## 还有更多...

如果你想缓存应用程序中曾经访问过的所有页面，那么在每个页面中添加缓存选项将变得很麻烦。有一种方法可以使用 JavaScript 在全局范围内执行此操作。将以下脚本添加到主页的`<head>`部分。现在，每次访问的页面都会自动在 DOM 中缓存起来。

```js
<script>
 $.mobile.page.prototype.options.domCache = true;
</script>
```

### DOM 缓存可能会减慢应用程序的运行速度

在 DOM 中缓存大量页面可能会使您的应用程序变得非常笨重，并减慢其运行速度。在这种情况下，您将不得不编写额外的代码来管理 DOM 中缓存的页面，并执行任何所需的清理操作。因此，只在选定的频繁访问页面上使用 DOM 缓存。

## 另请参阅

+   *预取页面以加快导航速度* 示例

# 自定义对话框样式

你可以通过在页面容器上使用`data-role="dialog"`属性来将页面样式化为对话框。您还可以在用于打开页面的锚链接中指定`data-rel="dialog"`属性。页面现在会被样式化为对话框，并以弹出过渡方式打开。当您向对话框添加标题时，默认情况下，关闭图标会在标题的左侧创建。在某些应用程序/平台中，您可能希望将此关闭按钮定位在标题的右侧。没有现成的选项可用来更改此图标的位置。本示例向您展示了如何构建一个具有自定义样式标题的对话框，以将关闭按钮定位在标题的右侧。

## 准备工作

从`code/02/custom-dialog`源文件夹中复制此示例的完整代码。你可以使用网址`http://localhost:8080/02/custom-dialog/main.html`来运行此代码。

## 如何操作...

需要执行的步骤是：

1.  使用`#main`页面创建`main.html`。在这里添加一个链接，以使用`data-rel="dialog"`属性将`#customdialog`页面作为对话框打开：

    ```js
    <div id="main" data-role="page">
      <div data-role="header">
        <h1>Header of Main Page</h1>
      </div>
      <div data-role="content">
     <a href="#customdialog" data-role="button" 
     data-rel="dialog">Open Custom Dialog</a>
      </div>
      <div data-role="footer">
        <h4>Footer of Main Page</h4>
      </div>
    </div>
    ```

1.  在`main.html`中创建`#customdialog`页面，并将自定义标题添加到对话框中，将关闭按钮定位在标题的右侧。在此代码中阻止了默认标题的增强功能：

    ```js
    <div id="customdialog" data-role="page">  
     <div class="ui-corner-top ui-overlay-shadow ui-header ui-bar-a" 
     role="banner">
     <a href="#main" data-icon="delete" data-iconpos="notext" 
     class="ui-btn-right ui-btn ui-btn-icon-notext ui-btn-corner-
     all ui-shadow ui-btn-up-a" title="Close" data-theme="a" data-
     transition="pop" data-direction="reverse">
          <span class="ui-btn-inner ui-btn-corner-all">
            <span class="ui-btn-text">Close</span>
     <span class="ui-icon ui-icon-delete ui-icon-shadow"></span>
          </span>
        </a>
        <h1 class="ui-title" tabindex="0" role="heading" 
            aria-level="1">Custom Dialog</h1>
      </div>
    ```

1.  最后，添加页面内容并添加一个链接，以返回到`#main`页面：

    ```js
      <div data-role="content">
        <a href="#" data-role="button" data-rel="back" 
            data-theme="b">Go Back</a>
      </div>
      <div data-role="footer">
        <h4>Footer of Dialog</h4>
      </div>
    </div>
    ```

## 工作原理...

创建包含两个页面`#main`和`#customdialog`的`main.html`。在`#main`页面中添加一个链接，以设置`data-rel="dialog"`属性打开`#customdialog`页面作为对话框。接下来，创建`#customdialog`页面，并添加一个按钮返回`#main`页面。现在，在`#customdialog`的标题中，不要使用`data-role="header"`属性。这将防止对话框标题使用默认样式进行增强。关闭图标现在不会放置在标题的左侧。现在，可以添加自定义标题并对其进行自定义样式设置，就像之前的代码清单中所示。启动应用程序并打开对话框，您将看到对话框弹出。此对话框现在具有自定义样式的标题，并且关闭图标位于标题的右侧，如以下屏幕截图所示：

![工作原理...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_02_07.jpg)

要了解如何得到自定义样式，首先创建一个打开常规对话框的页面。使用浏览器的代码检查器，并观察 jQuery Mobile 框架对对话框标题所做的代码增强。将生成的代码“原样”复制到自定义对话框代码中。然后，必须进行以下各节中提到的更改。

第一个更改是修复关闭图标的位置。您会看到使用添加到标题代码中的锚链接执行关闭操作。在这里，将`ui-btn-left`类替换为`ui-btn-right`类。这将使图标在标题中右侧位置。`jquery.mobile.css`文件中已经包含了这些类定义。

通过此更改，现在关闭图标同时出现在标题的左侧和右侧位置。这是因为标题仍然具有`data-role="header"`属性。这使得框架增强整个标题并自动在左侧添加关闭图标。但是，由于您已经手动添加了所有这些生成的类，现在可以安全地从代码中删除`data-role="header"`属性。保留您添加的所有其他代码和类。现在，当您启动代码时，您只会看到标题右侧位置上的单个关闭图标。

## 还有更多...

此技术非常重要。它可用于自定义 jQuery Mobile 应用程序的外观和感觉。该框架提供了许多基本选项、元素和属性，可以添加到您的应用程序中。然后，框架通过在内部添加更多的标记代码和样式来增强这些内容，使其在您的浏览器中看起来很好。增强的代码在浏览器的**查看源代码**选项中是不可见的。但是，通过代码检查器或调试工具，您可以查看增强的代码，将其复制到您的 HTML 文件中，进行调整，获得您想要的结果。以下屏幕截图显示了使用此方法创建的自定义对话框标题的代码检查器视图：

![还有更多...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_02_08.jpg)

### 自定义 CSS

对话框页面可以通过在自定义 CSS 文件中引入自己的样式来进一步增强。检查`jquery.mobile.css`文件中所有包含`ui-dialog`的类。将要调整的样式复制到您的自定义 CSS 中，并设置适当的新值。下面的代码行显示了一个示例更改，其中将对话框的顶部边距设置为 `-12px`，而不是默认值 `-15px`：

```js
.ui-dialog { margin-top: -12px; };
```

## 另请参阅

+   在第三章中的*向标题添加自定义圆形按钮*配方中，*工具栏*

# 使用 CSS 创建弹跳页面过渡

当您在应用程序的各个页面之间导航时，jQuery Mobile 框架使用 CSS3 动画来显示一些很酷的过渡效果。 **淡入淡出** 过渡默认用于页面，**弹出** 过渡用于对话框。您可以使用特定过渡导航到页面，并且在导航出页面时，您可以反转过渡的方向。截至 v1.1.1 版，jQuery Mobile 自带一套默认的 10 个过渡效果。jQuery Mobile 在线文档中有一个漂亮的在线演示，显示了所有可用的过渡效果。但这还不是全部；您可以使用 CSS 创建自己的自定义过渡效果，并在应用程序中使用它们。此配方向您展示如何使用 CSS 并在页面过渡期间创建弹跳页面效果。

## 准备工作

从`code/02/custom-css-transition`源文件夹中复制此配方的完整代码。您可以使用 URL`http://localhost:8080/02/custom-css-transition/main.html`启动此代码。

## 如何做…

应遵循的步骤是：

1.  创建`customtransition.css`文件，并按以下代码片段所示定义`bounceup`自定义转换。在 CSS 中对页面的 `Y` 位置属性进行动画处理：

    ```js
    .bounceup.in, .bounceup.in.reverse {
      -webkit-transform: translateY(0) ;
     -webkit-animation-name: bounceupin;
      -webkit-animation-duration: 1s;
      -webkit-animation-timing: cubic-bezier(0.1, 0.2, 0.8, 0.9);	    
    }
    @-webkit-keyframes bounceupin {
      0% { -webkit-transform: translateY(100%); }
      90% { -webkit-transform: translateY(-10%); }
      100% {-webkit-transform: translateY(0); }
    }
    ```

1.  定义下一个反向动画：

    ```js
    .bounceup.out, .bounceup.out.reverse {
      -webkit-transform: translateY(100%);
     -webkit-animation-name: bounceupout;
      -webkit-animation-duration: 1s;
      -webkit-animation-timing: cubic-bezier(0.1, 0.2, 0.8, 0.9);
    }
    @-webkit-keyframes bounceupout {
      0% { -webkit-transform: translateY(0); }
      90% { -webkit-transform: translateY(110%); }
      100% {-webkit-transform: translateY(100%); }
    }
    ```

1.  创建`main.html`并在其`<head>`部分中包含对`customtransition.css`样式表的引用，如下所示：

    ```js
    <meta name="viewport" content="width=device-width, 
      initial-scale=1">
    <link rel="stylesheet" href="http://code.jquery.com
      /mobile/1.1.1/jquery.mobile-1.1.1.min.css" /> 
    <link rel="stylesheet" href="customtransition.css" />
    <script src="img/jquery-1.7.1.min.js">
    </script>
    <script src="http://code.jquery.com/mobile
      /1.1.1/jquery.mobile-1.1.1.min.js"></script>
    ```

1.  创建一个带有打开`#page2`链接的`#main`页面。将之前定义的`bounceup`自定义转换设置为`data-transition`属性：

    ```js
    <div id="main" data-role="page">
      <div data-role="header">
        <h1>Header of Main Page</h1>
      </div>
      <div data-role="content">
     <a href="#page2" data-role="button" 
     data-transition="bounceup">Go to Page 2</a>
      </div>
      <div data-role="footer">
        <h4>Footer of Main Page</h4>
      </div>
    </div>
    ```

1.  最后，创建一个带有链接返回`#main`页面的`#page2`页面：

    ```js
    <div id="page2" data-role="page" data-title="Custom 
      Transition using CSS">
      <div data-role="header">
        <h1>Header of Page 2</h1>
      </div>
      <div data-role="content">
        <a href="#" data-role="button" data-rel="back" 
            data-theme="b">Go Back</a>
      </div>
      <div data-role="footer">
        <h4>Footer of Page 2</h4>
      </div>
    </div>
    ```

## 它是如何工作的…

创建`customtransition.css`文件并定义自定义`bounceup`转换。首先，定义`.bounceup.in`和`.bounceup.in.reverse`类，两者具有相同的值。这将使进入新页面和离开新页面（反向）的转换看起来类似。在类中，使用`translateY`属性设置屏幕上新页面的 `Y` 坐标或垂直位置。在给定的持续时间内，使用立方贝塞尔动画曲线对该属性进行动画处理 1 秒。接下来，定义动画`Y`坐标的关键帧（这是使用`bounceupin`动画名称指定的）。关键帧定义了动画中各个时刻的 `Y` 值。

您可以使用一个简单的技巧来获得此动画中使用的弹跳效果。将`Y`的值设置为超出屏幕的 90％持续时间，然后将其设置为 100％持续时间或动画完成时的屏幕边缘。这使得它在新页面动画到屏幕时具有整洁的弹跳效果，短暂地延伸出屏幕，然后回到正确的位置。类似地，当页面导航到屏幕外时，为当前页面定义`.bounceup.out`和`.bounceup.out.reverse`动画，如代码所示。

现在，创建`main.html`，并在`jquery.mobile.css`文件包含之后，在其`<head>`部分包含 CSS 文件。创建`#main`页面，并使用`data-transition="bounceup"`属性添加一个链接以打开`#page2`页面，并使用自定义转换。最后，创建`#page2`页面，并添加一个链接以返回`#main`页面。现在，当你启动应用程序并单击按钮时，页面导航将发生，使用一个漂亮的自定义弹跳动画。

在页面转换期间，有一个**from**页面和一个**to**页面。jQuery Mobile 在 from 页面（当前页面）上应用`out`类样式，并在**to**页面（新页面）上应用`in`类样式。如果要支持反向转换，则在`in`和`out`类后缀中添加单词`reverse`，如 CSS 文件中所示。使用这些样式，jQuery Mobile 将在页面上应用正确的转换效果。您可以进一步调整此配方中的代码，并通过 CSS 动画进行更多页面动画的探索。您可以尽情发挥创意！

## 还有更多...

此配方中列出的 CSS 样式仅支持 web kit 浏览器（Chrome 和 Safari）。您可以进一步探索并尝试在其他浏览器上运行，如 IE、Firefox 或 Opera。您将需要为 CSS 属性添加供应商特定前缀。此外，浏览器应能够支持使用的 CSS 属性。流行浏览器所需的供应商前缀如下所示：

+   **Chrome 和 Safari**：`–webkit`

+   **Opera**：`–o`

+   **Firefox**: `–moz`

+   **IE**：`–ms`

### 向`customtransition.css`文件添加供应商前缀

要为其他浏览器增加支持，您将需要扩展此配方中提供的`customtransition.css`文件。您可以通过添加属性的供应商前缀来执行此操作，如下所示：

```js
.bounceup.in, .bounceup.in.reverse {
  -webkit-transform: translateY(0);
  -moz-transform: translateY(0);
  -ms-transform: translate(0)
  -o-transform: translate(0)
  transform: translate(0)

  -webkit-animation-name: bounceupin;
  -moz-animation-name: bounceupin;
  -ms-animation-name: bounceupin;
  -o-animation-name: bounceupin;
  animation-name: bounceupin;
}
```

对于代码中列出的具有`–webkit`前缀的所有指定 CSS 属性，都必须执行此操作。

### 提示

各种浏览器中的**CSS3 动画支持**

支持 CSS3 动画所需的最低浏览器版本是桌面上的 Chrome、Firefox 5.0、IE 10、Safari 4.0 和 Android 浏览器 4、Firefox 移动版 5.0 以及移动端的 Safari 移动版（iOS 2）。

### 当 CSS3 属性成为标准时

在上述 CSS 中，每个属性的最后一行是它变成标准后的属性名。在这一点上，浏览器将不再支持特定属性的供应商前缀。但是您不必修改 CSS 中的任何一行代码，因为标准属性已经在您的文件中可用。浏览器将跳过它不理解的所有属性，并拾取标准属性。所以一切都会正常工作。

### 渐进增强

你会注意到，此处的过渡动画在某些浏览器上不会正常工作。但是页面导航的基本功能在任何地方都能正常工作。截至撰写本文时，对 CSS3 动画的最佳支持是由 Webkit 浏览器提供的。但是 CSS3 的美妙之处在于，随着浏览器的不断改进和用户设备的升级，用户将自动获得更好的应用体验。您不必修改任何代码或发布任何升级版本。这就是所谓的**渐进增强**。使用 jQuery Mobile 意味着您的代码已经使用了渐进增强。如果您的应用是原生编写的，这将不会那么容易。

## 另请参阅

+   *使用 JS 创建幻灯片和淡入淡出页面过渡*配方

+   在第七章 *配置*中的 *配置默认过渡效果* 配方

# 使用 JS 创建幻灯片和淡入淡出页面过渡

在上一个配方中，您学会了如何使用 CSS 为您的 jQuery Mobile 应用添加自定义过渡。您也可以使用 JavaScript 创建自定义过渡。本配方向您展示如何使用 JavaScript 在应用程序中的页面过渡期间创建“slidefade”（滑动和淡入淡出）效果。

## 准备工作

从`code/02/custom-js-transition`源文件夹复制此处配方的完整代码。您可以使用 URL `http://localhost:8080/02/custom-js-transition/main.html` 启动此代码。

## 如何做...

执行以下步骤：

1.  创建`customtransition.js` JavaScript 文件，并通过添加一个`mycustomTransition()`方法来定义您的自定义过渡，如下面的代码片段所示。在此处，定义`from`和`to`页面在过渡期间应如何动画显示：

    ```js
    function mycustomTransition( name, reverse, $to, $from ) {
        var deferred = new $.Deferred();
        // Define your custom animation here
        $to.width("0");
        $to.height("0");
        $to.show();
        $from.animate(
            { width: "0", height: "0", opacity: "0" },
            { duration: 750 },
            { easing: 'easein' }
        );
        $to.animate(
            { width: "100%", height: "100%", opacity: "1" },
            { duration: 750 },
            { easing: 'easein' }
        );
    ```

1.  接下来，使用直接从`jquery.mobile.js`文件复制的标准模板来完成过渡函数定义：

    ```js
    // Standard template from jQuery Mobile JS file
    reverseClass = reverse ? " reverse" : "";
    viewportClass 
      = "ui-mobile-viewport-transitioning viewport-" + name;
    $to.add( $from ).removeClass( "out in reverse " + name );
    if ( $from && $from[ 0 ] !== $to[ 0 ] ) {
      $from.removeClass( $.mobile.activePageClass );
    }
    $to.parent().removeClass( viewportClass );
    deferred.resolve( name, reverse, $to, $from );
    $to.parent().addClass( viewportClass );
    if ( $from ) {
      $from.addClass( name + " out" + reverseClass );
    }
    $to.addClass( $.mobile.activePageClass + " " + name 
      + " in" + reverseClass );

    return deferred.promise();
    }
    ```

1.  最后，使用 jQuery Mobile 框架注册名为`slidefade`的自定义过渡：

    ```js
    // Register the custom transition
    $.mobile.transitionHandlers["slidefade"] = mycustomTransition;

    ```

1.  接下来，创建`main.html`文件，并在`<head>`部分包含`customtransition.js`文件：

    ```js
    <meta name="viewport" content="width=device-width, 
      initial-scale=1">
    <link rel="stylesheet" href="http://code.jquery.com
      /mobile/1.1.1/jquery.mobile-1.1.1.min.css" />
    <script src="img/jquery-1.7.1.min.js">
    </script>
    <script src="http://code.jquery.com/mobile/1.1.1
      /jquery.mobile-1.1.1.min.js"></script>
    <script src="img/customtransition.js"></script>

    ```

1.  定义`#main`页面，并包含一个链接以打开`#page2`。使用带有`data-transition`属性的自定义`slidefade`过渡：

    ```js
    <div id="main" data-role="page">
      <div data-role="header">
        <h1>Header of Main Page</h1>
      </div>
      <div data-role="content">
     <a href="#page2" data-role="button" 
     data-transition="slidefade" data-theme="b">Go to Page 2</a>
      </div>
      <div data-role="footer">
        <h4>Footer of Main Page</h4>
      </div>
    </div>
    ```

1.  最后，使用一个链接定义`#page2`页面，以返回`#main`页面：

    ```js
    <div id="page2" data-role="page" data-title="Custom Transition using JS">
      <div data-role="header">
        <h1>Header of Page 2</h1>
      </div>
      <div data-role="content">
        <a href="#" data-role="button" data-rel="back" 
            data-theme="b">Go Back</a>
      </div>
      <div data-role="footer">
        <h4>Footer of Page 2</h4>
      </div>
    </div>
    ```

## 工作原理...

创建`customtransition.js`文件并定义`mycustomTransition`函数。在这里，首先创建一个 jQuery`$.Deferred`对象。然后，编写自定义转换代码。将目标页面的初始宽度和高度设置为零。通过调用`show()`函数使其可见。接下来，定义`to`和`from`页面（from 页面是当前页面）的动画。

### 注意

jQuery 的`$.Deferred`对象可用于注册和调用多个同步或异步回调，然后返回它们的结果。您可以在[`api.jquery.com/category/deferred-object/`](http://api.jquery.com/category/deferred-object/)了解更多关于此功能及其提供的方法。

调用`animate()`函数并设置选项，如动画的宽度、高度、不透明度、持续时间以及动画曲线，如代码清单所示。设置数值，使得起始页面在指定持续时间内以宽度和不透明度为零进行动画。这将慢慢隐藏页面并将其向左滑动。同样，动画目标页面，使得在给定的持续时间内，宽度、高度和不透明度从零达到 100%。目标页面从左边淡入，占据整个屏幕。现在，这两个动画同时发生，给过渡带来了良好的最终结果。

转换完成后，代码必须确保正确页面设置为活动页面。您可以直接从`jquery.mobile.js`文件中的标准模板中复制此代码片段和框架所需的其他默认操作。现在，一旦转换完成，调用`deferred.resolve()`函数。还要从转换处理程序返回延迟对象的承诺。

最后，您应该使用`slidefade`名称将自定义转换处理程序注册到框架中。这将确保当您在`data-transition`属性中指定`slidefade`转换名称时，将从`$.mobile.transitionHandlers`目录中选择并使用正确的转换。

创建`main.html`并在`<head>`部分包含`customtransition.js`文件。定义`#main`页面，其中包含使用`data-transition="slidefade"`属性打开`#page2`的链接，如代码所示。还要定义`#page2`，其中包含返回`#main`页面的链接。您不必在`#page2`中设置转换，因为 JavaScript 已经处理了反向动画。启动您的应用程序，并在页面之间导航时，您将看到新页面滑入，同时当前页面淡出，为您提供自定义滑动和淡出过渡效果。再考虑一下，也许"滑动和收缩"会是这个转换的更好名称。

## 还有更多...

如果您在应用程序中定义了自定义过渡并在大多数页面导航中使用它，那么可以直接将此自定义过渡设置为所有页面使用的默认过渡。这样，就不需要在每个链接中指定 `data-transition` 属性。这在 `customtransition.js` 文件中指定。在注册自定义过渡处理程序之后（文件末尾），添加如下行：

```js
$.mobile.defaultTransitionHandler = myCustomTransition;
```

在上面的代码片段中，`myCustomTransition` 是新定义的过渡处理程序。现在，所有页面都将使用 `slidefade` 过渡。但这不会影响默认使用弹出过渡的 `Dialog` 过渡。

### JavaScript 过渡与 CSS3 过渡的比较

尽管可能会遇到供应商前缀和不兼容的浏览器，但在 CSS3 过渡中使用 CSS3 过渡而不是 JS 过渡。使用 CSS3 过渡，所需的代码较少，开发和维护起来更容易。而且，您不必从头开始编写动画的整个逻辑。随着 jQuery Mobile 的未来版本，页面过渡框架或逻辑可能会发生变化，这将破坏您的自定义 JS 过渡。

而在 CSS3 中，美妙之处在于您的应用程序在 CSS3 支持不足时会逐步增强并退回到基本功能。随着浏览器的改进和升级，供应商前缀将确保您的代码无需修改即可更好地工作。当供应商前缀消失时，标准属性将得到选择，然后所有内容将继续正常工作。因此，只有当您想要做更复杂的事情并且 CSS3 过渡不能完全支持您的需求时，才使用 JS 过渡。

## 另请参阅

+   *使用 CSS 创建弹跳页面过渡* 配方

+   第七章 *配置你的默认过渡* 配方

# 使用 data-url 处理登录页面导航

当您在应用程序中编写登录页面时，一旦用户输入有效凭据，您将希望在成功时将用户重定向到不同的页面或不同的文件夹。本配方向您展示了如何使用`data-url`属性在登录页面导航情景中将用户重定向到不同页面。

## 准备工作

从`code/02/data-url`源文件夹中复制此配方的全部代码。您可以使用 URL `http://localhost:8080/02/data-url/login/main.html`来启动此代码。

## 如何实现...

应该遵循以下步骤：

1.  创建名为 `login` 和 `records` 的两个文件夹。`login` 文件夹将包含 `main.html` 文件，`records` 文件夹将包含 `index.html` 和 `data.html` 文件。

1.  在`login`文件夹中，将`main.html`创建为多页文档。在这里，首先添加如下代码片段中显示的`#main`页面。还要添加一个链接以打开`#login`页面。

    ```js
    <div data-role="page" id="main">
      <div data-role="header">
        <h1>Header of Main Page</h1>
      </div>
      <div data-role="content">
        <p>Page: login/main.html #main</p>
        <p><a href="#login" data-role="button">
          Login to Records folder</a></p>
      </div>
    </div>
    ```

1.  接下来，在`main.html`中创建`#login`页面，并添加一个打开`index.html`文件的链接。指定`data-url`属性指向`records`文件夹（用于页面重定向），如下面的代码片段所示：

    ```js
    <div data-role="page" id="login" 
     data-url="http://localhost:8080/02/data-url/records/"
        data-title="data-url main# Login Page">
      <div data-role="header">
        <h1>Header of Login Page</h1>
      </div>
      <div data-role="content">
        <p>Page: login/main.html #login</p>
        <p><a href="index.html" data-role="button">
          Go to Index Page</a></p>
      </div>
    </div>
    ```

1.  现在，在`records`文件夹中创建`index.html`文件，如下面的代码片段所示。在这里添加一个链接以打开`data.html`文件。还为页面设置`data-url`，如以下代码所示：

    ```js
    <div data-role="page" 
     data-url="http://localhost:8080/02/data-url/records/"
      <div data-role="header">
        <h1>Header of Index Page</h1>
      </div>
      <div data-role="content">
        <p>Page: records/index.html</p>
        <p><a href="data.html" data-role="button">
            Go to Data Page</a></p>
      </div>
    </div>
    ```

1.  最后，在`records`文件夹中创建`data.html`文件。在这里添加一个链接到`index.html`文件。此处未设置`data-url`属性，但导航仍将正常工作，因为之前的页面重定向成功完成：

    ```js
    <div data-role="page">
      <div data-role="header">
        <h1>Header of Data Page</h1>
      </div>
      <div data-role="content">
        <p>Page: records/data.html</p>
        <p><a href="index.html" data-role="button" 
            data-theme="b">Go to Index Page</a></p>
      </div>
    </div>
    ```

## 工作原理...

在上述代码列出的每个页面中，还在页面标题下方显示当前页面的页面 URL。请注意此文本，并将其与浏览器地址栏中显示的地址进行比较，以便在此示例中导航到各个页面时进行观察。

首先，创建`login`和`records`文件夹。在`login`文件夹中，创建`main.html`文件，这是一个多页文档。将`#main`和`#login`页面添加到其中。在`#main`页面中，添加一个**登录到记录文件夹**按钮以打开`#login`页面。接下来，创建`#login`页面，并将其`data-url`属性指定为`http://localhost:8080/02/data-url/records`。在此页面添加一个**打开索引页**按钮，以打开位于`records`文件夹中的`index.html`文件。现在，当您启动应用程序并单击`login`按钮时，将显示`#login`页面。但浏览器地址栏将显示 URL 为`http://localhost:8080/02/data-url/records/`，如下图所示。而**转到索引页**按钮上方的文本仍然显示当前页面位置为`login/main.html #login`。

![工作原理...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_02_09.jpg)

这个重定向发生了，因为在`#login`页面的`div`容器中使用了`data-url`属性。jQuery Mobile 框架会更新地址栏，显示此属性的值，而不是用于获取页面的实际 URL。

这是一个非常方便的功能，允许您在应用程序中执行重定向。这个示例没有显示服务器验证的用户名或密码。但在实际生活中，用户会在`#main`页面输入用户名/密码凭据，然后在服务器成功响应后，您可以将用户重定向到受限文件夹和网页。不要将任何未经身份验证的用户重定向，并且他们将无法访问`records`文件夹中的任何页面。

接下来，按照代码中给出的内容添加`index.html`和`records.html`文件。添加这些页面的链接以实现它们之间的导航。现在，在`#login`页面中，当您点击**打开索引页**按钮时，代码中`href`属性只指定了`index.html`。但是此时重定向已经发生，`records`文件夹中的`index.html`文件被打开。`index.html`现在是这里的着陆页面，使您能够访问其他页面，比如位于`records`文件夹中的`data.html`等。使用`data-url`的另一种方法是，您还可以在成功登录时使用`changePage()`方法将用户重定向到`index.html`页面。

在`index.html`中，将`data-url="http://localhost:8080/02/data-url/records"`属性设置为支持当用户点击浏览器的后退或前进按钮时的正确导航，如果不这样做，当您在`index.html`中单击后退按钮时，导航将中断。`data-url`可帮助您在历史堆栈中设置正确的值。

您可以通过浏览器的后退和前进按钮来玩转，看看在应用程序中导航时，地址栏是如何更新的，与标题下方显示的文本相比如何更新。

### 提示

**使用正确的值来设置 data-url**

您可以为`data-url`属性指定任何值，在地址栏中都将显示相同值。但您应该注意确保它是有效的引用，并且浏览器应该能够呈现页面。指定不正确或不存在的 URL 将在刷新浏览器或单击后/前按钮时中断导航。

## 还有更多...

jQuery Mobile 为您的应用程序中的所有页面设置并维护`data-url`属性。应用程序的第一页不需要`data-url`，因为它始终在 DOM 中，并且可以通过其 ID 或 URL 引用。对于所有其他页面，如果未指定`data-url`属性，则默认情况下会添加带有页面 ID 的值。对于相同域中的外部页面，将页面的相对路径用作`data-url`的值。对于来自不同域的页面，将使用绝对路径。

### 使用`data-url`作为 href 链接

如果一个页面的`div`标签同时包含页面 ID 和`data-url`，则在`href`属性值中可以使用`data-url`或页面 ID，以导航到该页面。

### 使用子散列 URL

一些插件动态将页面分成单独的页面。这些页面必须通过深链接到达。这些页面的`data-url`属性应以以下方式指定：

```js
data-url="page.html&ui-page=subpage"
```

## 另请参阅

+   在第六章的*提交使用 POST 的表单*中，*表单*

# 使用 History API 创建自定义错误弹窗

jQuery Mobile 框架不会跟踪对话框的历史记录。因此，当您单击浏览器的返回按钮时，对话框不会重新出现。对于一些功能，例如显示错误弹出或警报，使用对话框存在一个很明显的小问题。当对话框从一个页面打开时，地址栏将显示带有`#&ui-state=dialog`文本后缀的页面 URL。这可能不是所有人都希望看到的。这个示例向您展示了如何使用**历史 API**并自定义常规对话框以出现，例如弹出而不对 URL 进行任何更改，利用历史 API。

## 准备就绪

从`code/02/history`源文件夹中复制此示例的完整代码。您可以使用 URL`http://localhost:8080/02/history/main.html`启动此代码。

## 如何做...

需要遵循的步骤是：

1.  创建`main.html`，并添加一个链接以打开`errordialog.html`文件作为对话框。还添加一个`input`按钮，如下面的代码片段所示：

    ```js
    <div id="main" data-role="page">
      <div data-role="header">
        <h1>Header of Main</h1>
      </div>
      <div data-role="content">
        <a href="errordialog.html" data-theme="b" 
          data-role="button" data-rel="dialog">
          Dialog
        </a>
     <input type="submit" value="Popup" id="linkButton"
     data-theme="b"/>
      </div>
      <div data-role="footer">
        <h4>Footer of Main</h4>
      </div>
    </div>
    ```

1.  将以下脚本添加到`main.html`的`<head>`部分，以在`input`按钮的`click`事件上打开`errorpopup.html`作为对话框：

    ```js
      $("#main").live("pageinit", function(event) {
          $("#linkButton").bind( "click", function(event, ui) {
     $.mobile.changePage( "errorpopup.html", {
     changeHash: false,
     role: "dialog"
     });
        });
      });
    ```

1.  创建`errordialog.html`文件以显示自定义错误消息。还添加一个按钮返回到`main.html`，如下面的代码片段所示：

    ```js
    <div id="errordialog" data-role="page">
      <div data-role="header">
        <h1>Error !</h1>
      </div>
      <div data-role="content">
        <p>Please correct and resubmit<p>
        <a href="main.html" data-role="button" 
            data-theme="b">Close</a>
      </div>
    </div>
    ```

1.  创建`errorpopup.html`，并在页面容器内添加以下脚本。这是一个常规对话框，但它具有自定义样式的标题。单击锚链接时，从历史堆栈中删除它的条目：

    ```js
    <div id="errorpopup" data-role="page">
      <script>
        $("#errorpopup").live("pageinit", function(event) {
          $("a").click(function(event) {
     history.back();
          });
        });
      </script>
    ```

1.  然后，为页面添加自定义标题，并添加返回到`main.html`的链接：

    ```js
     <div class="ui-corner-top ui-overlay-shadow ui-header ui-bar-a" 
     role="banner">
        <h1 class="ui-title" tabindex="0" role="heading" 
          aria-level="1">
          Error !
        </h1>
      </div>
      <div data-role="content">
        <p>Please correct and resubmit<p>
        <a href="main.html" data-role="button" data-
          theme="b">
          Close
        </a>
      </div>
    </div>
    ```

## 它是如何工作的...

创建`main.html`，其中`#main`页面有一个链接可以打开`errordialog.html`页面。添加一个输入提交按钮（`id="linkButton"`），如下所示。接下来，按照以下代码创建`errordialog.html`页面，其中有一个按钮可以返回到`main.html`。当你启动应用程序并点击第一个按钮（**对话框**）时，`errordialog.html`页面会作为常规对话框打开，并具有弹出过渡效果。你会看到地址栏发生变化，并在 URL 末尾显示`#&ui-state=dialog`文本，如下面的屏幕截图所示。关闭并打开这个对话框几次，然后如果你按住返回按钮，浏览器的历史记录将被显示，并且你会看到**错误对话框**在历史堆栈列表中的条目：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_02_10.jpg)

现在，在`main.html`中，添加给定的脚本到`pageinit`事件处理程序中，当应用程序启动时调用。在这里，处理`#linkButton`输入按钮的`click`事件，并在回调中使用以下部分描述的选项调用`changePage()`方法，以打开`errorpopup.html`页面。将`role`选项设置为`dialog`以打开页面作为对话框。此外，将`changeHash`选项设置为`false`，以指示打开页面时不更改地址栏中的 URL 哈希。

接下来，创建 `errorpopup.html` 并将给定的脚本添加到页面容器中。在这个脚本中，绑定 `pageinit` 事件，该事件在页面初始化时触发。在这里，为锚点按钮的 `click` 事件添加一个事件处理程序。在这个回调中，调用 `history.back()` 方法来删除历史记录堆栈中的历史记录条目。您应该将此脚本添加到页面容器中，以便每次页面在 DOM 中加载和初始化时都会被调用。

接下来，向错误弹出页容器添加一个自定义标题。这个自定义标题与本章前面 *自定义样式对话框* 部分使用的相同。这个对话框标题被定制，使其看起来更像一个弹出窗口，并避免了默认情况下在对话框标题中出现的关闭按钮。最后，在页面内容中，添加一个按钮返回到 `main.html`。

现在，重新启动应用程序，单击第二个按钮（**Popup**）。创建的自定义对话框将显示为弹出窗口，如下图所示：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_02_11.jpg)

此弹出窗口的行为与默认对话框不同。**关闭** 图标不存在。您会注意到浏览器的地址栏未更改。您还会看到单击并按住浏览器的后退按钮时，**Error Popup** 页面标题不会显示在历史记录列表中。关闭弹出窗口并返回到 `main.html`。您可以单击并按住浏览器的后退或前进按钮，以查看弹出窗口从未显示在历史记录列表中，而对话框则列在其中，如下图所示：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_02_12.jpg)

## 还有更多...

历史 API 使用起来非常简单，并提供了额外的方法，您可以使用这些方法来处理和操作浏览器中的历史记录堆栈。您可以使用 `pushState()` 方法向历史记录中添加一个新条目。使用 `replaceState()` 方法，您可以替换历史记录中的条目和现有条目的 URL。这是一个非常方便的方法，可以让您根据应用程序的需要来操作历史记录。如本示例代码所示，`history.back()` 将您带回历史记录中的上一步，而 `history.forward()` 则让您向前迈进一步。要转到历史记录堆栈中的特定条目，还可以使用 `history.go()` 方法，将一个数字值传递给它，表示您要跳过多少条目。因此，`history.go(-3)` 将使您回退三个条目，而正值将使您向前跳三个条目。

### 对话框上的 popstate 事件

每当单击后退或前进按钮时，都会触发 `popstate` 事件。该事件由框架使用 `onpopstate` 处理程序处理，并根据需要导航到下一个或上一个页面。如果 `popstate` 导致目标页面是对话框，则框架会处理该事件，不会导航回对话框。因此，当您单击浏览器的后退或前进按钮时，对话框不会再次显示。

### 弹出窗口小部件

在编写本配方时，使用的是 jQuery Mobile v1.1.1。因此，在此配方中创建的错误弹出对话框不是真正的弹出式窗口，因为它仍然显示在单独的页面上，并且不悬停在原始页面上。**弹出**小部件将在 jQuery Mobile v1.2.0 中提供。然后，您可以使用`data-rel="popup"`属性添加一个简单的、真正的弹出窗口，如下面的代码片段所示：

```js
<a href="#myPopup" data-rel="popup">Open Popup</a>
<div data-role="popup" id="myPopup">
  <p>A simple true popup!<p>
</div>
```

您可以选择使用`data-history="false"`属性将弹出窗口设置为不在历史记录中跟踪。您可以在[`jquerymobile.com/demos/1.2.0/docs/pages/popup/index.html`](http://jquerymobile.com/demos/1.2.0/docs/pages/popup/index.html)了解更多关于使用弹出窗口的信息。

## 另请参阅

+   *自定义对话框样式*配方

+   第八章的*使用页面初始化事件*配方，*事件*

+   使用`changePage()`方法更改页面的*使用 changePage() 方法更改页面*配方 第九章，*方法与实用工具*


# 第三章 工具栏

在本章中，我们将涵盖：

+   使用全屏固定工具栏

+   使用持久导航栏工具栏

+   使用多个按钮自定义页眉

+   向页眉添加自定义圆形按钮

+   向页眉添加图像

+   添加自定义返回按钮

+   向页脚添加布局网格

# 介绍

jQuery Mobile 框架提供了两个工具栏，**页眉** 和 **页脚**。 页眉是页面中的第一个容器，页脚是最后一个。 页眉用于指定应用程序或页面的标题，并可以包含用于导航的标准 **导航栏**。 页脚用于各种目的。 它可以包含标准按钮和表单控件，并可以根据您的需要进行自定义。 它还可以包含用于页面导航的导航栏。 页脚通常也用于显示版权和许可信息。

# 使用全屏固定工具栏

**固定工具栏** 在页面滚动时保持在屏幕上的相同位置。 当您的应用程序页面内容占据整个视口时，固定工具栏将重叠在页面内容上。 你不能在这里切换固定工具栏的可见性。 要切换工具栏的可见性，您可以在 **全屏模式** 中使用固定工具栏。 此示例向您展示了如何创建一个使用全屏工具栏的简单 **照片查看器** 应用程序。

## 准备就绪

从 `code/03/fullscreen-toolbars` 源文件夹中复制此示例的完整代码。 可以使用 URL `http://localhost:8080/03/fullscreen-toolbars/main.html` 启动此代码。

## 如何操作...

1.  在 `main.html` 中创建 `#main` 页面和一个 `<img>` 标签，以显示缩小的 **尼亚加拉瀑布** 图像，如下代码所示：

    ```js
    <div id="main" data-role="page">
      <div data-role="header">
        <h1>Photo Gallery</h1>
      </div>
      <div data-role="content">
        <img src="img/niagara.png" width="150" height="100" />
        <br>The Niagara Falls, NY, US, 24/12/2011
        <br><a href="#photo" data-role="button" data-inline="true">View full screen</a>
      </div>
      <div data-role="footer" data-position="fixed">
        Footer of Photo Gallery
      </div>
    </div>
    ```

1.  创建 `#photo` 页面以全屏模式显示图像：

    ```js
    <div id="photo" data-role="page" data-fullscreen="true" data-add-back-btn="true">
     <div data-role="header" data-position="fixed" >
        <h1>The Niagara Falls, NY, US</h1>
      </div>
      <div data-role="content">
        <img src="img/niagara.png" width="100%" height="100%" />
      </div>
     <div data-role="footer" data-position="fixed">
        Date taken: 24/12/2011
      </div>
    </div>
    ```

## 它是如何工作的...

在 `main.html` 中，创建 `#main` 页面以使用 `<img>` 标签显示 **尼亚加拉瀑布** 的缩略图，使用较小的 `width` 和 `height`。 添加一个链接以打开 `#photo` 页面。 当您首次启动应用程序时，将显示以下屏幕，并带有较小尺寸的快照图像：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_03_01.jpg)

接下来创建 `#photo` 页面，使用 `data-fixed="true"` 属性添加固定工具栏。 使用 `data-fullscreen="true"` 属性设置页面容器占据整个屏幕。 使用 `<img>` 标签添加图像，宽度为 `100%`，高度为 `height`。

现在，当您单击 `#main` 中的 **查看全屏** 按钮时，将打开 `#photo` 页面，显示全屏图像的 **尼亚加拉瀑布**。 也可以看到固定工具栏。 现在，当您点击屏幕时，工具栏的可见性将切换。 全屏显示如下截图所示：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_03_02.jpg)

## 还有更多...

默认情况下，全屏工具栏将覆盖页面内容。您将无法访问工具栏下方显示的任何内容。您需要点击屏幕，切换工具栏的可见性，然后访问页面内容。这可能会成为您的应用程序用户的可用性问题。因此，请明智地使用此功能。

### 注

全屏工具栏在需要显示全屏内容的页面中非常理想，例如照片、预览、幻灯片或视频。

### CSS 属性 `position:fixed`

浏览器必须支持 `position:fixed` CSS 属性，才能正确动态定位固定工具栏。大多数现代浏览器都支持此属性。对于较旧的浏览器，可能不支持此功能，框架将会优雅地降级并回退到使用常规静态工具栏。在这些旧平台上，您可以使用**Polyfills**来支持固定工具栏，并在 [`jquerymobile.com//test/docs/toolbars/bars-fixed.html`](http://jquerymobile.com//test/docs/toolbars/bars-fixed.html) 中提供有关此的详细说明。

### 切换固定工具栏的可见性

正如本文中已经提到的，您可以点击屏幕来切换固定工具栏的可见性。通过使用 **fixedtoolbar 插件** 的 `tapToggle` 属性（默认为 `true`），可以控制此点击行为的变化。要启用或禁用点击，请使用以下代码片段，该代码片段使用 jQuery 选择器来找到工具栏：

```js
// to disable tap to toggle toolbars use
$("[data-position='fixed']").fixedtoolbar({ tapToggle: false });

// to enable tap to toggle toolbars use
$("[data-position='fixed']").fixedtoolbar({ tapToggle: true });
```

### 使用 JavaScript 切换固定工具栏的可见性

你也可以使用 JavaScript 调用 `fixedtoolbar` 插件上的 `show` 或 `hide` 方法来切换固定工具栏的可见性，如下面的代码所示。代码片段使用 jQuery 选择器来找到工具栏。

```js
$("[data-position='fixed']").fixedtoolbar('show');
// or
$("[data-position='fixed']").fixedtoolbar('hide');
```

## 参见

+   *在工具栏中使用持久性导航栏* 食谱

# 在工具栏中使用持久性导航栏

**Navbar widget** 可用于在您的应用程序中提供导航链接。**Persistent Navbar** 保持在您的应用程序中的同一位置固定，就像一个固定的选项卡栏一样，在您页面之间导航时不会移动。本文向您展示如何在工具栏中使用持久性导航栏来创建一个简单的**电视菜单 UI**。

## 准备工作

从 `code/03/persistent-navbar` 源文件夹中复制此处食谱的全部代码。可以使用 URL `http://localhost:8080/03/persistent-navbar/main.html` 来启动此代码。

## 如何操作...

1.  在 `main.html` 中创建一个简单的**电视菜单 UI**，其中包含三个页面，分别是 "`#movies`"、"`#songs`" 和 "`#serials`"。在下面的代码中，添加带有导航栏的 `#movies` 页面，其页眉和页脚如下所示：

    ```js
    <div id="movies" data-role="page" >
     <div data-role="header" data-id="persistheader" data-position="fixed">
        <h1>Movies</h1>
        <div data-role="navbar">
          <ul>
            <li><a href="#" data-role="button" 
     class="ui-btn-active ui-state-persist">
                Movies</a></li>
            <li><a href="#songs" data-role="button">Songs</a></li>
            <li><a href="#serials" data-role="button">Serials</a></li>
          </ul>
        </div>
      </div>
      <div data-role="content">
        <h3>This is the Movies Page</h3>
      </div>
     <div data-role="footer" data-id="persistfooter" data-position="fixed" >
        <div data-role="navbar">
          <ul>
            <li><a href="#" data-role="button">New</a></li>
            <li><a href="#" data-role="button">Popular</a></li>
            <li><a href="#" data-role="button">Classics</a></li>
          </ul>
        </div>
      </div>
    </div>
    ```

1.  接下来，按照以下代码添加 `#songs` 页面，内容相似：

    ```js
    <div id="songs" data-role="page" >
     <div data-role="header" data-id="persistheader" data-position="fixed">
        <h1>Songs</h1>
        <div data-role="navbar">
          <ul>
            <li><a href="#movies" data-role="button">Movies</a></li>
            <li><a href="#" data-role="button"
     class="ui-btn-active ui-state-persist">
                Songs</a></li>
            <li><a href="#serials" data-role="button">Serials</a></li>
          </ul>
        </div>
      </div>
      <div data-role="content">
        <h3>This is the Songs Page</h3>
      </div>
     <div data-role="header" data-id="persistheader" data-position="fixed">
        <div data-role="navbar">
          <ul>
            <li><a href="#" data-role="button">New</a></li>
            <li><a href="#" data-role="button">Popular</a></li>
            <li><a href="#" data-role="button">Classics</a></li>
          </ul>
        </div>
      </div>
    </div>
    ```

1.  最后，按照以下代码添加 `#serials` 页面：

    ```js
    <div id="serials" data-role="page" >
     <div data-role="header" data-id="persistheader" data-position="fixed">
        <h1>Serials</h1>
        <div data-role="navbar">
          <ul>
            <li><a href="#movies" data-role="button">Movies</a></li>
            <li><a href="#songs" data-role="button">Songs</a></li>
            <li><a href="# " data-role="button"
     class="ui-btn-active ui-state-persist">
                Serials</a></li>
          </ul>
        </div>
      </div>
      <div data-role="content">
        <h3>This is the Serials Page</h3>
      </div>
     <div data-role="header" data-id="persistheader" data-position="fixed">
        <div data-role="navbar">
          <ul>
            <li><a href="#" data-role="button">New</a></li>
            <li><a href="#" data-role="button">Popular</a></li>
            <li><a href="#" data-role="button">Classics</a></li>
          </ul>
        </div>
      </div>
    </div>
    ```

## 它的工作原理...

创建`main.html`并向其添加三个页面：`#movies`、`#songs`和`#serials`。在`#main`页面中，通过指定`data-position="fixed"`来添加一个固定页眉。为了在所有页面中保持此页眉不变，请设置属性`data-id="persistheader"`。现在添加一个具有三个链接的`navbar`，如前面的代码所示。第一个链接指向相同的页面，因此对于`href`标签，使用`#`。还要添加属性`class="ui-btn-active ui-state-persist`，表示当您进入此页面时，此按钮应处于活动状态。接下来，在页面底部添加一个带有三个链接的页脚，分别为**New**、**Popular**和**Classics**，如前面的代码所示。添加属性`data-id="persistfooter"`和`data-position="fixed"`，以指示这是一个固定的页脚，并且要在所有页面中保持不变。您应该为所有三个页面的页眉使用相同的`data-id`值。同样，页脚的三个页面应使用相同的`data-id`。使用相同的值将创建一个粘性的`navbar`，在页面转换时保持不动。

接下来，添加`#songs`页面，其内容与**Movies**页面相似。与之前提到的相同，将标题和页脚的`data-id`值设置为相同。现在，在页眉`navbar`中将第二个按钮设置为活动状态，将属性`class="ui-btn-active ui-state-persist"`设置为它。最后，添加带有固定持久页眉和页脚的`"#serials"`页面，就像之前的页面一样。在这里，将页眉`navbar`中的第三个按钮设置为活动状态。当您启动应用程序时，您可以使用页眉导航栏导航到这三个页面。这三个页面都有相同的页眉和页脚。

您可以在三个页面的页脚中随机选择不同的按钮。当您在页面之间来回导航时，您会看到页脚按钮的状态被保持和记住了。屏幕显示如下截图所示：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_03_03.jpg)

### 注意

在菜单驱动的应用程序中，持续的导航栏非常方便，通常用于页面之间的导航。

## 还有更多...

您可以通过添加`data-icon`属性为`navbar`按钮设置图标。可以使用`data-iconpos`属性将图标位置设置为`top`、`bottom`、`right`或`left`，如下面的代码所示：

```js
<a href="#" data-role="button" data-icon="home" data-iconpos="right">Home</a>
```

### 具有固定持久工具栏的 3D 页面过渡

如果您将具有 3D 页面过渡的持久固定工具栏与页面一起使用，则可能会遇到定位问题。性能也可能较慢。因此，最好将这些页面转换为使用 2D 动画，例如`slide`、`slidup`、`slidedown`、`fade`或`none`。

## 另请参见

+   *使用全屏固定工具栏*配方

# 自定义具有多个按钮的页眉

当您将按钮添加到页面标题时，它们会排列到标题的左侧，并且默认情况下只能将一个按钮定位到右侧。本配方向您展示如何将四个按钮添加到标题中，并且其中两个按钮位于右侧。

## 准备工作

从`code/03/multiple-header-buttons`源文件夹复制此配方的完整代码。可以使用 URL`http://localhost:8080/03/multiple-header-buttons/main.html`启动此代码。

## 如何做...

1.  创建一个名为`jqm.css`的新样式表，并根据以下代码中的给定内容定义两个新的自定义样式：

    ```js
    .ui-btn-nexttoleft {
      position: absolute; 
      left: 80px; 
      top: .4em; 
    }
    .ui-btn-nexttoright {
      position: absolute; 
      right: 80px; 
      top: .4em; 
    }
    ```

1.  在`main.html`的`<head>`标签中包含前一个样式表，如下所示：

    ```js
    <link rel="stylesheet" href="http://code.jquery.com/mobile/1.1.1/jquery.mobile-1.1.1.min.css" /> 
    <link rel="stylesheet" href="jqm.css" />
    <script src="img/jquery-1.7.1.min.js"></script>
    <script src="img/jquery.mobile-1.1.1.min.js"></script>
    ```

1.  现在，使用 jQuery Mobile 框架提供的默认样式向页面标题添加四个按钮，同时也使用您的自定义样式，如下代码所示：

    ```js
    <div id="main" data-role="page">
      <div data-role="header">
        <a href="#" data-role="button" data-theme="c" 
     class="ui-btn-left">
            Button1</a>
        <a href="#" data-role="button" data-theme="c" 
     class="ui-btn-nexttoleft">
            Button2</a>
        <h1>Custom Header</h1>
        <a href="#" data-role="button" data-theme="c" 
     class="ui-btn-nexttoright">
            Button3</a>
        <a href="#" data-role="button" data-theme="c" 
     class="ui-btn-right">
            Button4</a>
      </div>
      <div data-role="content">
       This page has a custom styled Header with multiple buttons
      </div>
    </div>
    ```

## 工作原理...

创建`jqm.css`样式表，并定义两个新类`.ui-btn-nexttoleft`和`.ui-btn-nexttoright`，以指定按钮将使用的绝对位置。创建`main.html`并在包含`jquery.mobile.css`文件的链接之后包含对前一个样式表的链接，如前述代码所示。

接下来，在页眉中添加一个带有`<h1>`文本的页眉，并在其两侧添加两个锚按钮。将属性`class="ui-btn-left"`添加到第一个按钮，使其出现在左上角。将属性`class="ui-btn-nexttoleft"`添加到第二个按钮。类似地，将属性`class="ui-btn-nexttoright"`添加到第三个按钮，最后将`class="ui-btn-right"`添加到第四个按钮，它将出现在右上角。第二和第三个按钮使用您定义的自定义类。现在，当您启动页面时，按钮将按照以下屏幕截图中所示的方式在页眉中定位：

![工作原理...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_03_04.jpg)

### 注意

在样式表中使用绝对值时要小心；如果文本大小或布局发生变化，可能需要修改绝对位置。

## 更多信息...

使用属性`data-role="header"`添加到页眉`div`容器会使 jQuery Mobile 框架以标准方式增强页眉。您可以跳过此属性，并通过在`div`容器中使用类`"ui-bar"`自定义页眉。您还可以在页眉中包含除按钮之外的小部件。

```js
<div class="ui-bar">

```

## 另请参阅

+   第二章中的*自定义样式对话框*配方，*页面和对话框*

+   *在页眉中添加自定义圆形按钮*配方

+   *在页眉中添加图像*配方

# 在页眉中添加自定义圆形按钮

jQuery Mobile 框架允许您向页面的页眉中添加自定义控件。本配方向您展示如何向应用程序的页眉中添加自定义圆形按钮。

## 准备工作

从 `code/03/round-button-header` 源文件夹中复制此配方的完整代码。此代码可使用 URL `http://localhost:8080/03/round-button-header/main.html` 启动。

## 如何做...

1.  创建名为 `jqm.css` 的新样式表，并在其中定义一个自定义的 `roundbtn` 类：

    ```js
    .roundbtn  {
      width: 40px;
      height: 40px;
      margin-top: 20px;
      -webkit-border-radius: 20px; 
      -moz-border-radius: 20px; 
      -ms-border-radius: 20px;
      -o-border-radius: 20px;
      border-radius: 20px;
    }
    ```

1.  创建 `main.html`，在 `<head>` 标签中包含先前的样式表：

    ```js
    <link rel="stylesheet" href="http://code.jquery.com/mobile/1.1.1/jquery.mobile-1.1.1.min.css" /> 
    <link rel="stylesheet" href="jqm.css" />
    <script src="img/jquery-1.7.1.min.js"></script>
    <script src="img/jquery.mobile-1.1.1.min.js"></script>
    ```

1.  使用新定义的 `roundbtn` 样式，在 `#main` 页面的页眉中添加一个 `About` 按钮，如下面的代码所示：

    ```js
    <div id="main" data-role="page" >
     <div data-role="header" style="height: 50px" >
        <h1 style="margin: 15px">Custom Round Button</h1>
        <a href="#about" data-rel="dialog" data-role="button"
     class="roundbtn ui-btn ui-shadow ui-btn-up-c ui-btn-left">
          <br>About</a>
      </div>
      <div data-role="content">
        This page has a Round button in the Header
      </div>
    </div>
    ```

1.  将 `#about` 对话框添加如下代码中：

    ```js
    <div id="about" data-role="page" >
      <div data-role="header" >
        <h1>About</h1>
      </div>
      <div data-role="content">
        Round Button Demo
      </div>
    </div>
    ```

## 它是如何工作的...

创建 `jqm.css` 样式表，并在其中定义一个名为 `roundbtn` 的新类，其中包含 `width`、`height` 和 `border-radius` 属性，如前面的代码所示。要创建一个圆形按钮，将 `border-radius` 属性的值设置为 `width` 属性值的一半。最后，添加供应商特定的属性以确保边框半径在各种浏览器上正常工作。

创建 `main.html`，在包含链接到 `jquery.mobile.css` 文件之后，包含上述样式表的链接，如前面的代码所示。接下来创建 `#main` 页面，并在其中添加带有 `<h1>` 文本的页眉。使用样式属性将页眉的 `height` 设置为 `50px`，以确保圆形按钮的 `height`（如 CSS 中指定的）适合页眉。接下来，在页眉中添加一个锚链接，其属性为 `data-role="button"` 和 `data-rel="dialog"`，以将 `"#about"` 页面作为对话框打开。使用 `class` 属性为此按钮添加 `roundbtn` 样式。还要添加框架在将锚链接增强为按钮时添加的其他类。您可以通过使用浏览器的开发者工具检查锚元素来获取这些类的列表。您必须手动添加这些类，以确保圆形按钮获得正确的样式，因为它已被定制。

最后，根据前面的代码定义 `#about` 页面。当您启动应用程序时，页眉中现在会显示一个圆形按钮，如下面的屏幕截图所示。单击圆形按钮将打开 `#about` 对话框。

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_03_05.jpg)

## 还有更多...

您的浏览器应支持 CSS 中的 `border-radius` 或相应的供应商特定前缀 `border-radius` 属性。如果不支持，则会看到一个矩形按钮而不是一个圆形按钮。

## 另请参见

+   第二章 中的 *使用 CSS 创建弹跳页面过渡* 配方，*页面和对话框*，关于供应商前缀的注意事项

+   第二章 中的 *自定义样式对话框* 配方，*页面和对话框*

+   *使用多个按钮自定义页眉* 配方

+   *在页眉中添加图像* 配方

# 在页眉中添加图像

jQuery Mobile 页面的页眉通常包含要用作页面页眉的文本。您还可以向页眉添加其他内容和标记。本配方向您展示如何向应用程序的页眉添加图像。

## 准备工作

从`code/03/header-image`源文件夹中复制此配方的全部代码。可以使用 URL`http://localhost:8080/03/header-image/main.html`来启动这段代码。

## 如何做…

在这个配方中，图像`ABC.png`被用作一个虚构公司 ABC Inc.的标志图像。

![如何操作……](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_03_06.jpg)

1.  创建`main.html`并将上述图像添加到其页眉。图片链接到对话框，代码如下所示：

    ```js
    <div id="main" data-role="page" data-theme="a">
      <div data-role="header" data-theme="a">
        <h1>ABC Company</h1>
     <a href="#about" data-rel="dialog" data-theme="a" class="ui-btn ui-shadow ui-btn-up-a">
     <img src="img/ABC.png" width="24" height="24" alt="About ABC" /></a>
      </div>
      <div data-role="content">
        This page has an Image in the Header
      </div>
    </div>
    ```

1.  如下代码所示，添加`#about`对话框：

    ```js
    <div id="about" data-role="page" >
      <div data-role="header" >
        <h1>About ABC</h1>
      </div>
      <div data-role="content">
        <img src="img/ABC.png" width="24" height="24" alt="ABC" style="margin-right:5px" />ABC Company Inc.
      </div>
    </div>
    ```

## 工作原理…

在`main.html`中，创建一个`#main`页面，并在其中添加一个带有`<h1>`文本的页眉。现在，使用属性`data-rel="dialog"`在页眉中添加一个锚点链接，以打开`#about`页面作为对话框。使用属性`class="ui-btn ui-shadow ui-btn-up-a"`指定锚点链接的自定义样式。请不要添加`data-role="button"`，因为框架会将此链接增强为按钮。接下来，如前面的代码中所示，添加指向`ABC.png`图像的`<img>`元素。通过使用`width`和`height`属性将该图像缩放到适当的大小。最后，如下代码中所示，定义`#about`页面。启动应用程序后，`#main`页面的页眉会显示左上角的`ABC.png`图像，如下截图所示。单击该图像将打开`#about`对话框页面。

![工作原理……](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_03_07.jpg)

## 还有更多…

您还可以为图像使用本机样式，避免在锚点元素上设置任何自定义样式以仅显示图像。使用属性`data-role="none"`即可实现，代码如下所示：

```js
<a href="#about" data-role="none" data-rel="dialog" data-theme="a">
  <img src="img/ABC.png" widht="24" height="24"
      alt="About ABC" />
</a>
```

## 另请参阅

+   *使用多个按钮自定义页眉*的配方

+   *在页眉中添加自定义的圆形按钮*配方

# 添加一个定制的返回按钮

在应用程序中打开新页面时，jQuery Mobile 框架提供了一个选项，可以在页面的页眉中添加一个**返回**按钮，以帮助您导航回上一页。默认情况下，**返回**按钮是不可见的。本配方向您展示如何使用 JavaScript 动态添加和自定义应用程序中的**返回**按钮。

## 准备工作

从`code/03/custom-back-button`源文件夹中复制此配方的全部代码。可以使用 URL`http://localhost:8080/03/custom-back-button/main.html`来启动这段代码。

## 如何做…

1.  创建`main.html`并在其中添加两个锚点链接。第一个链接打开一个带有页眉中**返回**按钮的页面，而第二个链接则打开一个没有**返回**按钮的页面。

1.  同时在页面中添加一个提交按钮，如下代码所示：

    ```js
    <div id="main" data-role="page">
      <div data-role="header">
        <h1>Header of Main Page</h1>
      </div>
      <div data-role="content">
        <a href="page1.html" data-role="button">Page with Header Back Button</a>
        <a href="page2.html" data-role="button">Page without Header Back Button</a>
        <input type="submit" id="addbackbtns" value="Click to Add and Customize the Back Button" data-inline="true" data-role="button">
      </div>
    </div>
    ```

1.  将以下脚本添加到页面的`<head>`部分，并将其绑定到提交按钮的`click`事件：

    ```js
    $("#main").live("pageinit", function(event) {
      $("#addbackbtns").bind("click", function(event, ui) {
        $.mobile.page.prototype.options.addBackBtn = true;
        $.mobile.page.prototype.options.backBtnText = "Prev";
        $.mobile.page.prototype.options.backBtnTheme = "e";
      });});
    ```

1.  在页面页眉中创建带有**返回**按钮的`page1.html`，如下所示的代码：

    ```js
    <div id="page1" data-role="page" data-add-back-btn="true">
      <div data-role="header">
        <h1>Header with Back Button</h1>
      </div>
      <div data-role="content">
        This page has a Header with the Default Back Button
      </div>
    </div>
    ```

1.  创建`page2.html`，默认情况下没有**返回**按钮：

    ```js
    <div id="page2" data-role="page">
      <div data-role="header">
        <h1>Header without Back Button</h1>
      </div>
      <div data-role="content">
        This page has a Header without any buttons
        <a href="main.html" data-rel="back" data-direction="reverse" data-role="button">Back</a>
      </div>
    </div>
    ```

## 工作原理...

创建`main.html`并向其添加两个锚链接，分别打开`page1.html`和`page2.html`。创建`page1.html`并在页面`div`容器中添加属性`data-add-back-btn="true"`，如前面的代码所示。现在，当你点击`main.html`中的第一个按钮时，它会打开`page1.html`，你可以看到页面页眉中显示了**返回**按钮。点击它返回到`main.html`。

创建`page2.html`，并且不要添加`data-add-back-btn`属性。现在，当你点击`main.html`中的第二个按钮时，它会打开`page2.html`，而页眉中没有**返回**按钮。你可以在页面内容中添加一个锚链接来返回`main.html`。

现在，在`main.html`中，添加一个提交按钮，带有`id="addbackbtns"`和文本**点击添加和自定义返回按钮**。在页面初始化后启动的`pageinit`事件处理程序中，将提交按钮的`click`事件绑定到回调函数。在这里，像前面的代码中所示，将`$.mobile.page.prototype`对象的`addBackBtn`选项设置为`true`。这将自动在应用程序的所有页面上启用**返回**按钮。此外，您还可以通过设置`backBtnText`和`backBtnTheme`选项进一步自定义**返回**按钮的文本和主题，如前面的代码所示。

现在你可以从`main.html`访问这两个页面，并看到返回按钮现在可用且样式相同。两者都是黄色的，文本设置为**Prev**，如下图所示：

![工作原理...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_03_08.jpg)

## 还有更多...

如食谱中所述，你可以设置以下属性并在应用程序的所有页面上全局启用**返回**按钮：

```js
$.mobile.page.prototype.options.addBackBtn = true;
```

当所有页面默认启用**返回**按钮时，你可以通过将属性`data-add-back-btn="false"`添加到其页面`div`容器中来关闭特定页面的按钮：

```js
<div id="page3" data-role="page" data-add-back-btn="false">
```

## 另请参阅

+   *使用多个按钮自定义页眉*的方法

+   *在页眉中添加自定义的圆形按钮*的方法

# 在页脚中添加布局网格

**布局网格**允许您在相邻的列中放置控件。这个食谱向您展示了如何使用布局网格在页脚添加多个表单控件。

## 准备工作

从`code/03/footer-layoutgrid`源文件夹复制此食谱的完整代码。可以使用 URL`http://localhost:8080/03/footer-layoutgrid/main.html`启动此代码。

## 如何操作...

1.  创建`main.html`并在其页面中添加一个页脚。向页面页脚添加布局网格，并像下面的代码中所示添加表单控件：

    ```js
    <div data-role="footer" data-position="fixed" class="ui-bar">
     <fieldset class="ui-grid-a">
        <div class="ui-block-a" data-role="fieldcontain">
          <label for="syncslider">Sync (mins):</label>
          <input type="range" name="syncslider" id="syncslider" value="5" min="1" max="60"/>
        </div>
        <div class="ui-block-b">
          <div data-role="fieldcontain">
            <fieldset data-role="controlgroup" data-type="horizontal">
              <legend>Share :</legend>
              <input type="radio" name="sharefile" id="shareFileNone" value="sharefile-1" checked="checked" data-theme="c"/>
              <label for="shareFileNone">None</label>
              <input type="radio" name="sharefile" id="shareFileFriends" value="sharefile-2" data-theme="c"/>
              <label for="shareFileFriends">Friends</label>
              <input type="radio" name="sharefile" id="shareFilePublic" value="sharefile-3" data-theme="c"/>
              <label for="shareFilePublic">Public</label>
            </fieldset>
          </div>
        </div>
      </fieldset>
    </div>
    ```

## 工作原理...

创建`main.html`并向其添加一个页脚。通过指定属性`class="ui-bar"`来样式化页脚。这将创建一个水平栏，您可以在其中添加自定义控件。现在通过创建一个具有属性`class="ui-grid-a"`的`fieldset`元素向页脚添加一个两列布局网格。

在布局网格的第一列添加一个带有属性`data-role="fieldcontain"`的`div`容器。必须添加属性`class="ui-block-a"`，以指示该`div`容器放置在网格的第一列中。现在通过添加一个带有`type="range"`属性的`input`元素将滑块小部件添加到此列。

类似地，添加一个带有属性`data-role="fieldcontain"`和`class="ui-block-b"`的`div`容器，以指示该`div`容器应放置在布局网格的第二列中。通过添加属性`data-role="controlgroup"`将三个单选按钮添加到单个组中，还添加属性`data-type="horizontal"`将单选按钮放置在水平行中（默认情况下，它们是垂直排列在彼此下方）。

现在页脚的外观如下图所示：

![工作原理...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-cb/img/7225_03_09.jpg)

## 还有更多...

可以通过为网格添加相应的类来指定布局网格中的最多五列，如下面的代码所示：

+   两列网格 - 使用`ui-grid-a`类

+   三列网格 - 使用`ui-grid-b`类

+   四列网格 - 使用`ui-grid-c`类

+   五列网格 - 使用`ui-grid-d`类

    ### 注意

    鉴于移动设备的屏幕空间有限，要有选择地使用四列或五列的布局网格。界面可能会显得拥挤，可能没有足够的空间来填充表单控件。

### 布局网格中控件的大小

向布局网格列添加表单控件或小部件将导致该控件占据整个列的宽度。如果不想要这种行为，您将需要修改控件的样式。

### 注意

按钮和选择表单控件支持`data-inline="true"`属性。您可以将此属性设置为控件，它们将保持其实际的紧凑大小，并且不会调整大小以占据整个列的宽度。

### 在布局网格中换到下一行

如果您的布局网格有多行，您必须将各种控件添加到它们自己的`div`容器中，从第一列开始为`class="ui-block-a"`，移动到第五列为`class="ui-block-e"`。在任何时候添加第六个`ui-block`或在中间使用`class="ui-block-a"`的`div`容器将导致列换行，新添加的`div`容器现在移至下一行。

### 注意

从`ui-block-a`类开始一行，按正确的顺序向`ui-block-e`移动。

不要在同一行中重复相同的 ui 块。

## 另请参阅

+   *在工具栏中使用持久性导航栏*方法

+   在第四章的*创建自定义布局网格*配方，*按钮和内容格式化*
