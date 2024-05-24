# HTML5 iPhone Web 应用开发（一）

> 原文：[`zh.annas-archive.org/md5/C42FBB1BF1A841DF79FD9C30381620A5`](https://zh.annas-archive.org/md5/C42FBB1BF1A841DF79FD9C30381620A5)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

自 90 年代以来，Web 应用程序已经走过了很长的路，当时静态 HTML 页面被传送到客户端。在那些日子里，Web 页面采用严格的客户端-服务器模型，其中大部分处理都在服务器上进行，客户端只是以很少或没有交互方式呈现信息。这样的信息只能通过速度非常慢的桌面计算机访问。

那些日子已经过去，我们现在以前所未有的方式相连。从可以在地铁上打电话的手机，到在空中 3 万英尺处呈现您最喜欢的报纸最新文章的平板电脑；我们现在处于一个数字时代，信息通过创新技术可以轻松获取。然而，我们仍然在努力创建技术和物理世界之间无缝互动。

尽管我们有设备对我们的触摸敏感，可以检测我们的位置，并具有监测我们生命信号的能力，但仍然取决于我们创建将改变世界的应用程序。创建这些应用程序需要大型团队、复杂的业务角色和昂贵的开支。

在短暂的时间内，开发这些应用程序对许多企业家来说是一个挑战，他们希望推动变革。一个分散的移动市场，直到今天仍在持续，导致了有限的开发资源。我们看到这些技术的进步增加了，但很少有人了解或甚至对学习所有这些语言感兴趣，感到有必要创建跨平台应用程序。

然而，只是时间问题，一个单一的平台将到来并永远改变世界。HTML5 及其在各种设备上的实现，帮助推动了传递创新和改变世界所需的力量。在我们的应用程序中利用这项技术，可以推动硬件的极限，同时创建许多用户都可以享受的东西，无论他们喜欢使用什么设备。

多年来，我意识到设备不可知的应用程序将成为常态。我们已经看到竞争对手采用这些标准，对他们的成功几乎没有影响；事实上，可以说它产生了相反的效果。因此，这本书的写作目的是为了向您提供基于开放标准的应用程序创建技术，以及成功创建设备不可知软件的方法。

# 本书涵盖的内容

第一章 *应用程序架构*，帮助您了解如何为 iPhone Web 应用程序开发创建标准架构。我们将根据本书的需要定制标准的 HTML5 移动样板。

第二章 *集成 HTML5 视频*，帮助您了解在 Web 应用程序中实现 HTML5 视频播放器的基础知识。我们将审查规范并实现一个公开的 API 来利用它。

第三章 *HTML5 音频*，解释了 HTML5 音频 API 的实现。我们将创建一个利用第二章相同原则的可重用组件的音频播放器。

第四章 *触摸和手势*，帮助您了解触摸和手势事件，包括相似之处和不同之处。我们将讨论一些示例，更重要的是，规范如何正确整合我们应用程序的用户体验。

第五章 *理解 HTML5 表单*，解释了 HTML5 表单的新功能，最终理解它在我们的 iOS Web 应用程序中的用途。我们将审查新的输入、它们的交互以及 iOS 操作系统所期望的行为。

第六章，“位置感知应用程序”，将以地理定位作为关键点，从规范到在 Safari iOS 浏览器中的完整实现。我们将创建一个利用此功能的示例，并演示我们如何在自己的应用程序中利用它。

第七章，“单页应用程序”，充满了有关如何在应用程序中创建无缝体验的信息。我们将讨论 MVC 设计模式的原则，并创建一个充分利用其潜力的示例。

第八章，“离线应用程序”，将涵盖诸如缓存、历史和本地存储等关键主题。我们将介绍基本知识，并透露细节，以便我们创建真正的离线应用程序。

第九章，“清洁和优化代码原则”，将使我们暂时绕过开发过程，以完善我们的技艺。我们将讨论最佳实践、行业支持的技术以及改进我们的代码以使应用程序整体受益的方法。

第十章，“创建原生 iPhone Web 应用程序”，回顾了我们如何创建之前学到的原生应用程序。应用相同的技术，我们将基于开放标准创建原生应用程序。

# 您需要为本书做好准备。

本书旨在为 iOS 提供 Web 应用程序开发解决方案。考虑到这一点，您将需要一部 iPhone 和/或 iPad，最好是一台安装有 Mac OS X 10.8 及以上版本的苹果电脑。您肯定需要一个文本编辑器或您选择的集成开发环境，包括安装了 iOS 模拟器的 Xcode 4 及以上版本。最后，您将在最现代的 Web 浏览器中测试您的应用程序，包括 Safari。

# 本书适合对象

本书适用于初学者到中级开发人员，他们专门从事 iOS 的 Web 应用程序开发。本书从入门级材料开始，每章都会深入讨论每个主题。所涵盖的主题将让您对如何处理开发过程以及实现这些目标所需的步骤有一个良好的理解。

# 约定

在本书中，您将找到一些文本样式，用于区分不同类型的信息。以下是这些样式的一些示例，以及它们的含义解释。

文本中的代码单词显示如下：“尽管我们之前已经编写了这段代码，让我们简要回顾一下`MediaElement`类的结构。”

代码块设置如下：

```html
<div class="audio-container">
    <audio controls preload>
        <source src="img/nintendo.mp3" type='audio/mpeg; codecs="mp3"'/>
        <p>Audio is not supported in your browser.</p>
    </audio>
    <select>
        <option value="sample1.mp3" selected>Sample1</option>
        <option value="sample2.mp3">Sample2</option>
        <option value="sample3.mp3">Sample3</option>
    </select>
</div>
```

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的单词，例如菜单或对话框中的单词，会以这样的方式出现在文本中：“然后通过单击**以 zip 格式下载**按钮来下载 zip 文件。”

### 注意

警告或重要说明会出现在这样的框中。

### 提示

提示和技巧会以这样的方式出现。


# 第一章：应用程序架构

在本章中，我们将为我们的 iPhone 应用程序创建一个标准架构。我们将以 HTML5 移动锅炉板为基础，并根据本书中的几个项目的需求进行定制。从在 HTML5 中标记我们的内容到创建 JavaScript 框架，我们将创建静态页面，帮助我们专注于 iPhone Web 应用程序开发的基础。

在本章中，我们将涵盖：

+   实施 HTML5 移动锅炉板

+   创建初步架构

+   自定义我们的框架

+   创建语义标记

+   结构化我们的样式表

+   响应式设计原则

+   建立我们的 JavaScript 架构

+   路由到移动站点

+   主屏幕图标

+   介绍我们的构建脚本

+   部署我们的项目

# 实施 HTML5 移动锅炉板

当您开始开发时，始终要从一个可以塑造成项目需求的基本框架开始。在许多情况下，我们在工作的地方或者为我们自己的个人项目开发这些框架。然而，开源社区为我们提供了一个可以在项目中使用的优秀框架——HTML5 移动锅炉板。这个框架基于著名的 HTML5 锅炉板，并针对移动进行了优化，包括精简的 HTML 模板；使用`Zepto`，以及针对移动进行了优化的工具和辅助功能。

## 下载并安装 HTML5 移动锅炉板

我们需要采取的第一步是下载 HTML5 移动锅炉板，位于这里：

[`html5boilerplate.com/mobile/`](http://html5boilerplate.com/mobile/)

一旦下载了锅炉板，您应该从解压的存档文件中看到以下结构：

![下载和安装 HTML5 移动锅炉板](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-iph-webapp-dev/img/1024_01_01.jpg)

初步目录结构

下一步是将这些文件放在您选择的目录中。例如，我已经将我的文件放在 Mac 上的以下目录中：

`/Users/alvincrespo/Sites/html5iphonewebapp`

接下来，我们将使用一个构建系统，帮助我们创建多个环境，简化部署过程，并在我们想要为测试和/或生产优化我们的网站时使事情变得更容易。

根据 HTML5 移动锅炉板的文档，有两种不同类型的构建系统，如 Node Build 脚本和 Ant Build 脚本。在本书中，我们将使用 Ant Build 脚本。我建议使用 Ant Build 脚本，因为它已经存在一段时间，并且具有我在项目中使用的适当功能，包括 CSS Split，它将帮助拆分锅炉板附带的主 CSS 文件。

## 集成构建脚本

要下载 Ant Build 脚本，请转到以下链接：

[`github.com/h5bp/ant-build-script`](https://github.com/h5bp/ant-build-script)

然后，通过单击**Download as zip**按钮下载 zip 文件。下载 Ant Build 脚本后，将文件夹及其内容复制到您的项目中。

一旦您的 Ant Build 脚本目录完全转移到您的项目中，将包含构建脚本的目录重命名为`build`。此时，您的项目应该已经完全设置好，以便在本书的其余应用程序中使用。我们将在本章后面介绍如何使用构建脚本。

# 创建我们的应用程序框架

对于每个项目，创建一个适应项目需求的框架是很重要的。重要的是要考虑项目的每个方面。从所需的文档到团队的优势和劣势，建立一个坚实的基础对我们构建和相应调整是很重要的。

## 修改锅炉板

现在，我们将修改我们的锅炉板，以满足我们将要构建的项目的需求。为简单起见，我们将从文件夹中删除以下项目：

+   `CHANGELOG.md`

+   `crossdomain.xml`

+   `README.md`

+   `/doc (目录)`

现在，目录已经整理好了，是时候看一下一些样板代码，并根据本书项目的需求进行定制了。

## 定制我们的标记

首先，用你喜欢的文本编辑器打开应用程序。一旦我们用我们选择的编辑器打开了应用程序，让我们看看`index.html`。

索引文件需要进行清理，以便专注于 iPhone Web 应用程序的开发，并且需要删除 Google Analytics 等未使用的项目。所以让我们删除一些对我们来说不必要的代码。

查找以下代码：

```html
<!DOCTYPE html>
<!--[if IEMobile 7 ]>    <html class="no-js iem7"> <![endif]-->
<!--[if (gt IEMobile 7)|!(IEMobile)]><!--> <html class="no-js"> <!--<![endif]-->
```

### 提示

**下载示例代码**

你可以从你在[`www.packtpub.com`](http://www.packtpub.com)的帐户中下载你购买的所有 Packt 图书的示例代码文件。如果你在其他地方购买了这本书，你可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，直接将文件发送到你的邮箱。

并将其修改为：

```html
<!DOCTYPE html>
<html class="no-js">
```

我们在这里所做的是移除 IE Mobile 的检测。虽然这对其他项目可能有帮助，但对于我们来说，它并不能真正帮助我们创建一个完全兼容 iPhone 的应用程序。然而，我们还需要删除一个`IEMobile`特定的 meta 标记：

```html
<meta http-equiv="cleartype" content="on">
```

之前的 meta 标记打开了`cleartype`（一种帮助字体呈现的实用程序）对 IE 移动的支持。这对我们来说并不是必要的，也不是我们应用程序的要求。

现在我们已经从页面中删除了一些不必要的标记，我们可以开始启用一些将增强我们应用程序的功能。查找以下 meta 标记并启用它们，删除周围的注释：

```html
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black">
```

这些指令告诉我们的应用程序可以在全屏模式下运行，并将状态栏设置为黑色。

我们还可以从文档的`<head>`中删除以下代码：

```html
<!-- This script prevents links from opening in Mobile Safari. https://gist.github.com/1042026 -->
<!--
        <script>(function(a,b,c){if(c in b&&b[c]){var d,e=a.location,f=/^(a|html)$/i;a.addEventListener("click",function(a){d=a.target;while(!f.test(d.nodeName))d=d.parentNode;"href"in d&&(d.href.indexOf("http")||~d.href.indexOf(e.host))&&(a.preventDefault(),e.href=d.href)},!1)}})(document,window.navigator,"standalone")</script>
-->
```

一旦我们删除了之前的脚本，你的标记现在应该看起来像下面这样：

```html
<!DOCTYPE html>
<head>
    <meta charset="utf-8">
    <title></title>
    <meta name="description" content="">
    <meta name="HandheldFriendly" content="True">
    <meta name="MobileOptimized" content="320">
    <meta name="viewport" content="width=device-width">
    <link rel="apple-touch-icon-precomposed" sizes="144x144" href="img/touch/apple-touch-icon-144x144-precomposed.png">
    <link rel="apple-touch-icon-precomposed" sizes="114x114" href="img/touch/apple-touch-icon-114x114-precomposed.png">
    <link rel="apple-touch-icon-precomposed" sizes="72x72" href="img/touch/apple-touch-icon-72x72-precomposed.png">
    <link rel="apple-touch-icon-precomposed" href="img/touch/apple-touch-icon-57x57-precomposed.png">
    <link rel="shortcut icon" href="img/touch/apple-touch-icon.png">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-status-bar-style" content="black">
    <link rel="stylesheet" href="css/normalize.css">
    <link rel="stylesheet" href="css/main.css">
    <script src="img/modernizr-2.6.1.min.js"></script>
</head>
```

现在，我们可以专注于清理我们的正文。幸运的是，我们只需要删除一件事情——Google Analytics，因为我们不会专注于 iPhone Web 应用的跟踪。

为此，找到以下代码并删除它：

```html
<!-- Google Analytics: change UA-XXXXX-X to be your site's ID. -->
<script>
    var _gaq=[["_setAccount","UA-XXXXX-X"],["_trackPageview"]];
    (function(d,t){var g=d.createElement(t),s=d.getElementsByTagName(t)[0];g.async=1;
    g.src=("https:"==location.protocol?"//ssl":"//www")+".google-analytics.com/ga.js";
    s.parentNode.insertBefore(g,s)}(document,"script"));
</script>
```

页面上应该只有以下脚本：

```html
<script src="img/zepto.min.js"></script>
<script src="img/helper.js"></script>
```

一旦我们完成了上述步骤，我们的标记应该变得简洁明了，如下所示：

```html
<!DOCTYPE html>
<html class="no-js">
<head>
    <meta charset="utf-8">
    <title></title>
    <meta name="description" content="">
    <meta name="HandheldFriendly" content="True">
    <meta name="MobileOptimized" content="320">
    <meta name="viewport" content="width=device-width">

    <link rel="apple-touch-icon-precomposed" sizes="144x144" href="img/touch/apple-touch-icon-144x144-precomposed.png">
    <link rel="apple-touch-icon-precomposed" sizes="114x114" href="img/touch/apple-touch-icon-114x114-precomposed.png">
    <link rel="apple-touch-icon-precomposed" sizes="72x72" href="img/touch/apple-touch-icon-72x72-precomposed.png">
    <link rel="apple-touch-icon-precomposed" href="img/touch/apple-touch-icon-57x57-precomposed.png">
    <link rel="shortcut icon" href="img/touch/apple-touch-icon.png">

    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-status-bar-style" content="black">

    <link rel="stylesheet" href="css/normalize.css">
    <link rel="stylesheet" href="css/main.css">
    <script src="img/modernizr-2.6.1.min.js"></script>
</head>
    <body>

        <!-- Add your site or application content here -->

        <script src="img/zepto.min.js"></script>
        <script src="img/helper.js"></script>
    </body>
</html>
```

从这里开始，我们应该检查每个项目的样式表和脚本，并在开始项目之前尽可能优化它。然而，我们将使用的这个样板已经由社区优化，并得到了许多开发人员的支持，并且对于我们在这里使用的情况，样式和脚本都已经准备就绪。如果你感兴趣，我鼓励你查看`normalize.css`文件，其中包含了重置页面的优秀指令。还有必要审查已经使用这个样板增强了以支持移动设备的`main.css`文件。

现在，我们将继续建立我们的框架。

# 定制我们的框架

对于开发人员来说，为他们正在进行的每个项目建立一个框架都是至关重要的，无论项目大小如何。当然，你的框架也应该根据项目的要求进行调整。在本节中，我们将建立一个简单的框架，以便在本书的使用过程中使用。

我们已经根据我们的需求整理了样板，现在我们将继续扩展样板，包括对我们将构建的应用程序至关重要的文件。

第一个应用程序将基于 HTML5 视频规范（[`dev.w3.org/html5/spec-author-view/video.html`](http://dev.w3.org/html5/spec-author-view/video.html)）。在该应用程序中，我们将为我们的视频播放器创建一个特定的功能，包括播放、暂停和全屏功能。所以让我们创建一个专门针对这个应用程序的目录；我们将这个目录称为`video`。

在这个目录中，我们将创建一个`index.html`文件，并从`index.html`文件的主页复制内容。

现在我们已经创建了我们的视频部分，让我们在我们的`css`目录中创建一个`video.css`文件。

然后，在我们的`/js`文件夹中创建一个`App`目录。在`/js/App`目录中，让我们创建一个`App.js`文件。稍后，我们将详细解释这个文件是什么，但现在它将是我们的主要应用程序命名空间，基本上封装了我们应用程序的全局功能。

最后，在`/js/App`目录中创建一个`App.Video.js`文件，其中将包含我们视频应用程序的功能。

现在，您将为我们的每个应用程序重复之前的步骤；包括视频、音频、触摸、表单、位置、单页和离线。最终，您的目录结构应该包括以下新目录和文件：

```html
/audio
    index.html
/css
    audio.css
    forms.css
    location.css
    main.css
    normalize.css
    singlepage.css
    touch.css
    video.css
/forms
    index.html
/js
    /App/App.Audio.js
    /App/App.Forms.js
    /App/App.js
    /App/App.Location.js
    /App/App.SinglePage.js
    /App/App.Touch.js
    /App/App.Video.js
/location
    index.html
/offline
    index.html
/singlepage
    index.html
/touch
    index.html
/video
    .index.html
```

此时，我们应该修复对依赖项的引用，比如我们的 JavaScript 和样式表。所以让我们打开`/video/index.html`。

让我们修改以下行：

```html
<link rel="stylesheet" href="css/normalize.css">
<link rel="stylesheet" href="css/main.css">
<script src="img/modernizr-2.6.1.min.js"></script>
```

将先前的标记更改为以下内容：

```html
<link rel="stylesheet" href="../css/normalize.css">
<link rel="stylesheet" href="../css/main.css">
<script src="img/modernizr-2.6.1.min.js"></script>
```

### 提示

请注意，我们在每个依赖项中添加了`../`。这本质上是告诉页面向上一级并检索适当的文件。我们还需要对 apple-touch-icon-precomposed 链接、快捷图标和页面底部的脚本进行同样的操作。

我们的框架现在几乎完成了，只是它们还没有连接起来。现在我们已经把一切都组织好了，让我们开始把一切连接起来。它看起来可能不太好看，但至少它将能够工作并朝着一个完全功能的应用程序迈进。

让我们从主`index.html`文件`/ourapp/index.html`开始。一旦我们打开了主`index.html`文件，让我们在`<body>`元素内创建一个基本的站点结构。我们将给它一个类名为`"site-wrapper"`，并将其放在注释`Add your site or application content here`的下方：

```html
<body>
    <!-- Add your site or application content here -->
    <div class="site-wrapper">

    </div>
    <script src="img/zepto.min.js"></script>
    <script src="img/helper.js"></script>
</body>
```

在包含我们站点的包装器中，让我们使用新的 HTML5`<nav>`元素来语义化地描述将存在于所有应用程序中的主导航栏：

```html
<div class="site-wrapper">
<nav>      
</nav>
</div>
```

还没有什么特别的，但现在我们将继续使用无序列表元素，并创建一个没有样式的导航栏：

```html
<nav>
    <ul>
        <li>
            <a href="./index.html">Application Architecture</a>
        </li>
        <li>
            <a href="./video/index.html">HTML5 Video</a>
        </li>
        <li>
            <a href="./audio/index.html">HTML5 Audio</a>
        </li>
        <li>
            <a href="./touch/index.html">Touch and Gesture Events</a>
        </li>
        <li>
            <a href="./forms/index.html">HTML5 Forms</a>
        </li>
        <li>
            <a href="./location/index.html">Location Aware Applications</a>
        </li>
        <li>
            <a href="./singlepage/index.html">Single Page Applications</a>
        </li>
    </ul>
</nav>
```

如果我们复制在`/video/index.html`中创建的代码并测试页面，您会发现它不会正确工作。对于所有子目录，如视频和音频，我们需要将相对路径从`./`更改为`../`，以便我们可以向上一级文件夹。考虑到这一点，`nav`元素在其他应用程序中将如下所示：

```html
<nav>
    <ul>
        <li>
            <a href="../index.html">Application Architecture</a>
        </li>
        <li>
            <a href="../video/index.html">HTML5 Video</a>
        </li>
        <li>
            <a href="../audio/index.html">HTML5 Audio</a>
        </li>
        <li>
            <a href="../touch/index.html">Touch and Gesture Events</a>
        </li>
        <li>
            <a href="../forms/index.html">HTML5 Forms</a>
        </li>
        <li>
            <a href="../location/index.html">Location Aware Applications</a>
        </li>
        <li>
            <a href="../singlepage/index.html">Single Page Applications</a>
        </li>
    </ul>
</nav>
```

现在，我们可以将`/video/index.html`中的导航复制到其余的应用程序文件或我们之前创建的`index.html`文件中。完成后，我们将拥有一个连接良好的单一站点。

信不信由你，我们这里有一个非常简单的网站。我们的页面已经设置了基本的标记和通用样式。此时，我们需要一个将我们的页面连接在一起的导航。然而，我们几乎没有涉及一些重要的方面，包括应用程序的语义标记，我们将在下一节中讨论。

# 创建语义标记

语义标记之所以重要，原因有几个，包括搜索引擎优化、创建可维护的架构、使代码易于理解以及满足无障碍要求。然而，您应该熟悉使用与您的内容相关的标记来构建页面的结构。HTML5 规范中有一些新元素，有助于简化这个过程，包括`<header>`、`<nav>`、`<footer>`、`<section>`、`<article>`和`<aside>`元素。这些元素中的每一个都有助于描述页面的各个方面，并轻松识别应用程序的组件。在本节中，让我们从我们的视频应用程序开始构建我们的应用程序。

## 创建页眉

首先，让我们给我们的主索引页面一个标题和一个描述我们所在页面的页眉。让我们在应用程序的`/index.html`中打开主`index.html`文件。

找到`<title>`标签，并在其中输入`iPhone Web Application Development – Home`。请注意，我们在这里使用连字符。这很重要，因为它使用户更容易扫描页面内容，并有助于特定关键字的排名。

您现在应该在文档的`<head>`标签中有以下`<title>`：

`<title>iPhone Web Application Development - Home</title>`

现在，我们希望页面的内容也反映标题，并提醒用户他们在我们网站上的进度。我们想要做的是创建一个描述他们所在部分的页眉。为了实现这一点，让我们在之前创建的导航之前放置以下代码。然后您的代码应如下所示：

```html
<hgroup>
    <h1>iPhone Web Application Development</h1>
    <h2>Home</h2>
</hgroup>
<nav>...</nav>
```

`<hgroup>`元素用于对一个部分的多个标题进行分组。标题的等级基于`<h1>`到`<h6>`，其中`<h1>`的等级最高，`<h6>`的等级最低。因此，突出显示的文本将使我们的`<h1>`内容高于我们的`<h2>`。

还要注意，我们尚未使用`<section>`元素。但是，这个页面确实通过 W3C 标记验证服务（[`validator.w3.org/`](http://validator.w3.org/)）进行验证。

我们可以通过将我们的`<hgroup>`和`<nav>`元素包装在`<header>`元素中来进一步描述页面，以提供页面的介绍性帮助。完成此操作后，您的代码应如下所示：

```html
<header>
    <hgroup>... </hgroup>
    <nav>... </nav>
</header>
```

通过先前的代码，我们最终为我们的页面提供了一些结构。我们用一个主页眉描述我们的页面，用一个子页眉描述页面。我们还为页面提供了导航菜单，允许用户在应用程序之间导航。

## 创建页脚

现在让我们添加一个包含本书名称和版权日期的`<footer>`：

```html
<footer>
    <p>iPhone Web Application Development &copy; 2013</p>
</footer>
```

先前的代码基本上将与最近的分区祖先相关联。因此，页脚将与其前面的内容相关联，我们稍后会填充。此时，您的内容应该如下所示：

```html
<div class="site-wrapper">
    <header>
        <hgroup>...</hgroup>
        <nav>...</nav>
    </header>
    <footer>...</footer>
</div>
```

## 清理部分

您可能想知道为什么我们不立即为包含`<header>`和`<footer>`元素的`<div>`元素使用`<section>`元素。在这种情况下，这并不一定有用，因为我们并没有创建一个元素内容会在大纲中列出的页面。这是 W3C 的建议，每个开发人员在决定使用`<div>`还是`<section>`元素时都应该意识到。最终，这取决于内容本身和团队希望创建的大纲。

现在我们已经为我们的页面创建了基本结构，我们可以继续为我们的其他应用程序做同样的事情。如果您希望查看最终版本，本书提供的代码将为您完成这些工作。

有了这个想法，我们将继续进行应用程序开发，确保在合适的时候使用语义代码。

# 构建我们的样式表

样式在我们构建的任何应用程序中都非常重要，特别是因为它是用户体验的第一个方面。在这一部分，我们将开始适当地构建我们的样式。

## 全局样式

首先，让我们打开位于`CSS`目录中的`main.css`文件。打开此文件后，您将看到默认的样式。在这一点上，让我们跳过这些内容，以创建我们自己的样式。随着我们继续开发我们的应用程序，我们将审查这些样式。

在`main.css`中找到以下行：

```html
/* ==========================================================================
   Author's custom styles
========================================================================== */
```

在这条注释之后，我们希望包括我们之前编写的语义代码的全局样式。

首先定义全局站点样式，比如背景颜色：

```html
html{
    background: #231F20;
    border-top: 10px solid #FDFF3A;
    border-bottom: 5px solid #FDFF3A;
    width: 100%;
}
```

在之前的样式中，我们做了一些样式选择，比如设置背景颜色和一些边框。这里重要的部分是 HTML 元素的宽度被定义为 100％。这基本上允许我们的所有内容扩展到手机宽度的 100％。

## 定义我们的全局字体

然后我们需要在页面上定义整体字体。目前这只是基本的，可以根据我们的应用程序继续扩展设计，但现在先看看以下样式：

```html
h1, h2, p, a {
    font-family: Arial, Helvetica, sans-serif;
    text-decoration: none;
}

h1, h2 {
    color: #A12E33;
    font-weight: bold;
    margin: 0;
    padding: 0;
}

h1 {
    font-size: 18px;
}

h2 {
    font-size: 14px;
    font-weight: normal;
}

p {
    color: #F15E00;
    font-size: 12px;
}

a,
a:visited {
    color: #F19C28;
}
```

在之前的代码中，你可以看到我们是从更高的层次向下工作的，这是对层叠样式表的基本理解。我们首先通过使用特定的字体系列并且没有装饰来定义我们的标题、锚点和段落。

当我们继续定义之前的样式时，我们开始更具体地定义每一个，标题没有填充或边距，有特定的颜色。然后，当我们继续往下看，我们可以看到每种类型的标题都有特定的字体大小，我们也对段落和锚点做同样的处理。

## 我们的页面布局

一旦我们定义了一些字体和站点样式，我们就为包含我们内容的`<div>`元素包含一些基本布局信息：

```html
.site-wrapper {
    padding: 5px 10px 10px;
}
```

由于我们的元素自动缩放到屏幕宽度的 100％，我们告诉内容在顶部有`5px`的填充，在左右各有`10px`的填充，在底部有`10px`的填充。或者，我们可以写以下样式：

```html
    padding-top: 5px;
    padding-left: 10px;
    padding-right: 10px;
    padding-bottom: 10px;
```

前者被称为快捷属性设置，被认为是最佳实践。

## 使用`:before`和`:after`添加内容

由于我们还希望确保我们的第二个标题以某种形式有所区别，我们可以使用 CSS3 伪类选择器和属性来定义之前和之后的内容，如下所示：

```html
hgroup h2:before,
hgroup h2:after {
    content: " :: ";
}
```

### 注意

请记住，Safari 3.2 及以上版本支持`:before`和`:after`伪选择器。

之前的选择器针对`<hgroup>`元素内的`<h2>`元素，并在其之前和之后添加我们在属性中定义的内容，就像`:before`和`:after`伪类选择器一样。

## 为我们的导航添加样式

接下来，让我们为我们的导航添加一些样式，使其看起来更加易用。

```html
nav ul {
    padding: 0;
}

nav li {
    list-style: none;
}

nav a {
    display: block;
    font-size: 12px;
    padding: 5px 0;
}
```

在这里，我们去掉了`<ul>`元素的填充，然后移除了每个列表元素的默认样式选项。最后，我们通过将字体大小设置为`12px`并在每个锚点的顶部和底部添加填充来确保每个锚点正确显示，以便在 iPhone 上轻松选择。

最后，我们将为我们的页脚添加一些样式。

```html
footer p {
    text-align: center;
}
```

非常简单，我们将段落在页脚中居中对齐。由于我们在字体部分定义了段落的默认样式，所以样式被应用了。

当之前的样式被正确应用时，你的结果应该类似于以下显示：

![为我们的导航添加样式](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-iph-webapp-dev/img/1024_01_02.jpg)

# 响应式设计原则

响应式设计是我们移动应用程序的关键。考虑到许多移动体验现在超过了桌面上的体验，我们必须创建适应不断发展的技术环境的应用程序。幸运的是，HTML5 移动样板自带了我们可以修改的初步样式。

## 媒体查询的拯救

首先，让我们在`css`目录中打开`main.css`文件。

接下来，向文件底部滚动，你应该看到以下样式：

```html
/* ==========================================================================
   EXAMPLE Media Queries for Responsive Design.
   Theses examples override the primary ('mobile first') styles.
   Modify as content requires.
========================================================================== */

@media only screen and (min-width: 800px) {
}

@media only screen and (-webkit-min-device-pixel-ratio: 1.5),
       only screen and (min-resolution: 144dpi) {}
```

尽管这些样式让我们起步，但对于 iPhone 开发，我们需要更多的定制。第一个媒体查询是专门针对平板设备的，第二个媒体查询帮助我们针对分辨率更高的设备，比如 iPhone 4。

我们想要做的是让这个更简单一些。因为我们只针对 iPhone，这就是我们可以用来替换之前代码的内容：

```html
/* iPhone 4 and 5 Styles*/
@media only screen and (-webkit-min-device-pixel-ratio: 2) { }
```

先前的代码将针对 iPhone 4 和 5。我们通过检查设备上的`-webkit-min-device-pixel-ratio`属性来特别针对这两个设备，如果为真，意味着我们可以提供高清图形。

我们想要检查的另一个方面是我们在`index.html`页面中设置的视口设置。幸运的是，我们之前已经清理过这个，它应该有以下内容：

```html
<meta name="viewport" content="width=device-width">
```

先前的代码片段基本上会根据设备的宽度调整我们的内容。

在这一点上，我们应该为以后在我们的应用程序中实现响应式样式做好准备。现在我们的样式已经为我们的应用程序设置好，并且足够通用以扩展，让我们开始添加脚本背后的框架。

## 响应式图像

图像是任何应用程序的极其重要的部分。它有助于展示产品的特点，并且举例说明您希望用户理解的信息。然而，今天各种各样的设备需要内容正确响应。除此之外，我们需要能够提供适合体验的内容，这意味着我们需要为高分辨率设备量身定制，以便最高质量的内容传达给受众。

有多种技术可以提供适当的内容。但是，您选择的技术取决于项目的要求。在这部分，我们将回顾根据内容和/或容器调整图像大小的传统响应式网页设计原则。

### 流体图像

在这种技术中，开发人员将所有图像的最大宽度设置为 100%。然后我们定义图像的容器相应调整。

#### 流体宽度图像

要实现全宽度图像，我们可以这样做：

```html
<body>
<img src="img/batman.jpeg" alt="Its Batman!">
</body>
```

标记很简单，基本上我们将图像包装到一个扩展所需全宽度的元素中。在这种情况下，body 的宽度将扩展到 100%。

接下来，我们将定义图像的样式如下：

```html
img {
    max-width: 100%;
}
```

通过这简单的 CSS 声明，我们告诉我们的图像将其最大宽度设置为包含内容的 100%。这将根据设备宽度的变化自动调整图像大小，这对于使网站对用户设备响应是至关重要的。

#### 全宽图像

在这种情况下，我们希望图像保持其全宽，但我们也需要相应地裁剪它。

为了实现这一点，我们可以简单地创建一个带有`class`的`div`，在这种情况下我们添加一个`overflow`类：

```html
<div class="overflow"></div>
```

然后我们可以创建保持图像全宽并根据内容调整大小的样式：

```html
overflow {
    background: transparent url('img/somgimg.jpg') no-repeat 50% 0;
    height: 500px;
    width: 100%;
}
```

这有点复杂，但基本上我们使用`background`属性附加图像。关键在于确保使用 50%将其居中。高度属性只是为了显示图像，宽度告诉容器与其内容相关的 100%。

这是我们在实现传统响应式设计时使用的两种技术。当我们创建视频和图像库时，我们将在以后实现这些技术。

# 建立我们的 JavaScript 架构

在为应用程序建立 JavaScript 架构时，有很多要考虑的事情，包括近期或短期内可能的变化、安全性、易用性和实施、文档等等。一旦我们能回答我们所提出的各种问题，我们就可以决定采用哪种模式（模块、外观和/或中介等）。我们还需要知道哪种库或框架最适合我们，比如`jQuery`、`Zepto.js`、`Backbone.js`或`Angular.js`。

幸运的是，为了在 iPhone 上提供有效的应用程序，我们将保持简单明了。我们将利用`Zepto.js`作为我们支持的库以保持轻量级。然后我们将通过创建遵循模块化模式的自定义 JavaScript 框架来构建 Zepto。

## 构建我们的应用功能

首先，让我们在我们喜欢的文本编辑器中打开我们的应用程序目录。

接下来，打开我们之前在 JavaScript 目录中创建的`App.js`文件。`App.js`文件应该是完全空的，不应该被包含在任何地方。这是我们将开始编写框架的地方。

### 给我们的应用程序命名空间

如果你是 JavaScript 的新手，你很可能大部分时间都是在全局作用域中编写代码——也许大部分 JavaScript 都是放在 script 标签中。虽然这可能实现了你的一些目标，但在开发大规模应用程序时，我们希望避免这样的做法。我们希望给我们的应用程序命名空间是为了可维护性、效率和可移植性。

让我们首先检查`App`命名空间；如果存在，我们将使用其中的内容，如果不存在，那么我们将创建一个空对象。以下代码展示了我们如何实现这一点：

```html
var App = window.App || {};
```

### 立即调用的函数表达式

太棒了！我们正在检查`App`命名空间，现在让我们定义它。在检查后，让我们包含以下代码：

```html
App = (function(){}());
```

先前的代码正在做几件事情，让我们一步一步来。首先，我们将`App`命名空间设置为所谓的**立即调用的函数表达式**（**IIFE**）。我们实质上是创建了一个由括号包裹并在闭括号后立即调用的函数。

当我们使用之前的技术或 IIFE 时，我们创建了一个新的执行上下文或作用域。这有助于创建自包含的代码，希望不会影响站点上的其他代码。它保护我们，并帮助我们有效地遵循模块化模式。

让我们通过传入 window、document 和 Zepto 对象来扩展先前的功能，如下所示：

```html
App = (function(window, document, $){
}(window, document, Zepto));
```

我知道这可能有点令人困惑，但让我们花点时间来思考一下我们在这里做什么。首先，我们在名为`window`、`document`和`$`的函数中设置了一些参数。然后，在调用此方法时，我们传入了`window`、`document`和`Zepto`。记住，我们之前讨论过这会创建一个新的作用域或执行上下文？嗯，这对我们很有用，因为现在我们可以传入任何可能是全局的对象的引用。

这对我们有什么用呢？嗯，想象一下，如果你想一遍又一遍地使用实际的`Zepto`对象，那将会有点累人。虽然输入`Zepto`并不难，但你可以将其命名空间为美元符号，保持简单。

### 使用严格模式

好的，我们已经设置好了我们的模块。现在让我们继续扩展它，包括`use strict`指令：

```html
App = (function(window, document, $){
    'use strict';
}(window, document, Zepto));
```

这个指令通过改变 JavaScript 的运行方式来帮助我们调试我们的应用程序，允许某些错误被抛出而不是悄悄失败。

### 默认选项

默认选项是给你的代码库提供一些可扩展性的好方法。例如，如果我们想要自定义或缓存与应用程序相关的元素，那么以下是我们将使用的默认值：

```html
var _defaults = {
'element': document.body,
    'name': 'App',
    'videoOptions': {},
    'audioOptions': {},
    'touchOptions': {},
    'formOptions': {},
    'locationOptions': {},
    'singlePageOptions': {}
};
```

让我们简要地看一下这些默认值。首先，我们将创建一个`defaults`变量，其中包含了我们应用程序的所有默认值。在其中，我们已经定义了一个默认位置，用于引用我们应用程序的`'element'`默认设置为`document.body`——这样就可以获取我们在**DOM**（**文档对象模型**）中的 body 元素。然后，我们为我们的应用程序创建一个自定义名称叫做`'App'`。之后，我们创建了视频、音频、触摸、表单、位置和单页面应用程序的空对象——以后会逐渐扩展这些空对象。当我们继续阅读本书时，这些空对象将被扩展。

### 定义构造函数

现在我们需要在`use strict`指令之后定义我们的构造函数。这个构造函数将接受一个名为`options`的参数。然后我们将用参数`options`扩展默认值，并存储这些设置，以便以后可以检索。最后，我们将把`'element'`选项作为`Zepto`对象进行缓存。

```html
function App(options) {
    this.options = $.extend({}, _defaults, options);
    this.$element = $(this.options.element);
}
```

这是先前代码的完成情况。首先，我们使用关键字`this`，它是对将要成为 App 实例的引用。因此，`this`是对象本身的上下文。希望这不会太令人困惑，并且随着我们的进行会变得清晰。在这种情况下，我们使用`this`来定义一个对象`options`，它将包含`_defaults`和我们传递给构造函数的任何自定义选项的合并内容。

注意，当我们将空对象或`{}`作为第一个参数传递给`$.extend()`时，我们告诉`Zepto`将`_defaults`和`options`合并到一个新对象中，因此不会覆盖`_defaults`对象。当我们需要在将来对默认选项进行某种检查时，这是有用的。

一旦我们定义了选项，我们就使用`this.$element`缓存元素，其中`$`在`element`前面只是为了我的参考，这样我就可以立即识别 Zepto 对象与普通 JavaScript 对象。

### 原型

好的，我们已经创建了我们的`App`命名空间，构建了一个 IIFE 来包含我们的代码，并定义了我们的构造函数。现在，让我们开始创建一些可以被访问的公共方法，使其更加模块化。但在我们这样做之前，让我们尝试理解 JavaScript 的`prototype`。

将`prototype`视为可以随时访问、修改和更新的活动对象。它也可以被视为指针，因为 JavaScript 将继续沿着链路向下查找对象，直到找到对象或返回`undefined`。原型只是一种将功能扩展到任何非普通对象的方法。

为了使事情变得更加混乱，我提到非普通对象具有原型。这些非普通对象将是数组、字符串、数字等。普通对象是我们简单地声明一个空对象，如下所示：

```html
var x = {};
```

`x`变量没有原型，它只是一个键/值存储，类似于我们的`_defaults`对象。

如果您还没有理解原型，不要担心，这一切都是关于动手实践和获取一些经验。所以，让我们继续前进，让我们的应用程序开始工作。

此时，您的`App.js`文件应该如下所示：

```html
var App = window.App || {};
App = (function(window, document, $){
    'use strict';
    var _defaults = {
        'element': document.body,
        'name': 'App',
        // Configurable Options for each other class
        'videoOptions': {},
        'audioOptions': {},
        'touchOptions': {},
        'formOptions': {},
        'locationOptions': {},
        'singlePageOptions': {}
    };
    function App(options) {
        this.options = $.extend({}, _defaults, options);
        this.$element = $(this.options.element);
    }
}(window, document, Zepto));
```

### 定义公共方法

现在我们需要通过在原型中输入来创建一些公共方法。我们将创建一个`getDefaults`方法，它返回我们的默认选项；`toString`将覆盖原生的`toString`方法，以便我们可以返回一个自定义名称。然后我们将创建初始化方法来创建我们的其他应用程序，我们将分别命名这些方法为`initVideo`、`initAudio`、`initLocalization`、`initTouch`、`initForms`和`initSinglePage`。

```html
App.prototype.getDefaults = function() {
    return _defaults;
};

App.prototype.toString = function() {
    return '[ ' + (this.options.name || 'App') + ' ]';
};

App.prototype.initVideo = function() {
    App.Video.init(this.options.videoOptions);
    return this;
};

App.prototype.initAudio = function() {
    App.Audio.init(this.options.audioOptions);
    return this;
};

App.prototype.initLocalization = function() {
    App.Location.init(this.options.locationOptions);
    return this;
};

App.prototype.initTouch = function() {
    App.Touch.init(this.options.touchOptions);
    return this;
};

App.prototype.initForms = function() {
    App.Forms.init(this.options.formOptions);
    return this;
};

App.prototype.initSinglePage = function() {
    App.SinglePage.init(this.options.singlePageOptions);
    return this;
};
```

此时，我们有几种方法可以在创建`App`实例时公开访问。首先，让我们回顾我们之前实现的代码，特别是这一行代码，它被复制，但根据`init`方法进行了定制：

```html
App.Touch.init(this.options.touchOptions);
```

对于我们创建的每个`init`方法，我们都调用适当的应用程序，例如`App.Touch`、`App.Forms`、`App.Video`等。然后我们传递在构造函数中定义的选项，例如`this.options.touchOptions`、`this.options.formOptions`、`this.options.videoOptions`等。

请注意，我们尚未为 Video、Forms、Touch 等创建这些类，但我们将很快创建这些类。

### 返回我们的构造函数/函数

在`App.js`中我们需要做的最后一件事是返回构造函数。因此，在之前定义的所有公共方法之后，包括以下代码：

```html
return App;
```

这段代码虽然简单，但非常重要。让我们看一个简化版本的`App.js`，以更好地理解正在发生的事情：

```html
App = (function(){
    function App() {}
    return App;
}());
```

如前所述，我们正在创建一个`App`命名空间，该命名空间设置为立即调用的函数表达式。当我们这样做时，在这个函数内部创建了一个新的作用域。

这就是为什么我们可以有一个名为`App`的函数或构造函数，而没有冲突或错误。但是如果您回忆起来，我们的函数`App`也是一个对象，就像 JavaScript 中的所有东西一样都是对象。这就是为什么当我们返回我们的函数`App`时，`App`命名空间被设置为构造函数。这样一来，您就可以创建多个`App`的实例，同时将代码集中在一个新的不可触及的范围内。

# 集成自定义模块模板

现在，为了将我们的架构其余部分放在一起，我们需要打开 JavaScript 目录中的每个其他`App`文件（`/js/App`）。

当我们打开这些文件时，我们需要粘贴以下模板，这是基于我们为`App.js`编写的脚本：

```html
var App = window.App || {};

App.Module = (function(window, document, $){
    'use strict';

    var _defaults = {
        'name': 'Module'
    };

    function Module(options) {
        this.options = $.extend({}, _defaults, options);

        this.$element = $(this.options.element);
    }

    Module.prototype.getDefaults = function() {
        return _defaults;
    };

    Module.prototype.toString = function() {
        return '[ ' + (this.options.name || 'Module') + ' ]';
    };

    Module.prototype.init = function() {

        return this;
    };

    return Module;

}(window, document, Zepto));
```

当我们每个模板都放入后，我们必须将`Module`更改为适当的类型，即视频、音频、位置等。

一旦您完成了粘贴部分并更改了名称，基本的 JavaScript 架构就设置好了。

## 包含我们的脚本

最后需要处理的一项事项是将这个基本架构包含到每个`index.html`文件中。为了做到这一点，您需要在页面底部粘贴以下代码，就在`helper.js`包含之后：

```html
<script src="img/App.js"></script>
<script src="img/App.Audio.js"></script>
<script src="img/App.Forms.js"></script>
<script src="img/App.Location.js"></script>
<script src="img/App.SinglePage.js"></script>
<script src="img/App.Touch.js"></script>
<script src="img/App.Video.js"></script>
<script src="img/main.js"></script>
```

我们基本上包含了框架的每个脚本。这里重要的是始终首先包含`App.js`。原因在于`App.js`创建了`App`对象并直接修改它。如果您在所有其他脚本之后包含它，那么`App.js`将覆盖其他脚本，因为它直接影响了`App`对象。

## 初始化我们的框架

我们需要处理的最后一项事项是`main.js`，其中包括我们应用程序的初始化。我们通过将我们的代码包装在 IIFE 中，然后将实例暴露给`window`对象来实现这一点。我们使用以下代码来实现这一点：

```html
(function(window, document) {
    'use strict';

    var app = new App({
        'element': document.querySelector('.site-wrapper')
    });

    window.app = app;

}(window, document));
```

我们之前看到的是将 IIFE 分配给对象。这里我们看不到，因为这不是必要的。我们只是想确保我们的代码不会影响其余的代码，大多数情况下不会发生，因为这个项目的简单性。然而，作为最佳实践，我尽量在大多数情况下将我的代码自包含起来。

前面代码的不同之处在于我们在这里看到了我们框架的初始化：

```html
var app = new App({
    'element': document.querySelector('.site-wrapper')
});
```

我们通过使用`new`关键字创建`App`的新实例，然后将一个对象传递给它，该对象将合并到我们之前编写的默认选项中。

### 注意

`querySelector`是一个附加到文档对象的 JavaScript 方法。该方法接受一个我们通常在 CSS 中使用的选择器，解析 DOM，并找到适当的元素。在这种情况下，我们告诉我们的应用程序将自己包含到具有`site-wrapper`类的元素中。

当我们最终初始化我们的应用程序时，我们将`app`附加到`window`对象上：

```html
window.app = app;
```

这基本上使它可以在我们的应用程序中的任何地方访问，通过将其附加到`window`对象上。

我们现在已经完成了应用程序的框架。虽然我们没有在页面上操纵任何内容，也没有附加与用户输入相关的任何事件，但我们现在有了一个遵循最佳实践、高效、有效且易于访问的编码的坚实基础。

# 路由到移动站点

除非我们正在制作一个完全响应式的站点，其中站点的样式会根据设备的尺寸而变化，否则我们很可能需要对站点进行某种重定向，以便转到我们站点的移动友好版本。

幸运的是，这可以很容易地通过几种方式实现。虽然我不会详细介绍我们可以实现这一点的方式，但以下是一些在决定如何前进时可能有所帮助的技术。

### 提示

由于本书面向前端，将路由到移动站点的过程将简要涵盖 PHP 和 htaccess。我们总是可以在前端执行此过程，但出于 SEO 和页面排名的目的，应该避免这样做。

## 通过 PHP 进行重定向

在 PHP 中，我们可以进行以下类型的重定向：

```html
<?php
    $iphone = strpos($_SERVER['HTTP_USER_AGENT'], "iPhone");
    if ($iphone) {
        header('Location: http://mobile.site.com/');
    }
?>
```

在这个例子中，我们正在创建一个变量`$iPhone`，并给它一个布尔值，true 或 false。如果在用户代理中找到`iPhone`，这可能是或可能不是最好的技术，然后我们告诉页面使用 PHP 中的`header()`方法进行重定向。

再次说明，还有其他方法可以实现这一点，但这将让你立即开始并运行起来。

## 通过 htaccess 进行重定向

我们还可以检测 iPhone，并通过在服务器上使用`htaccess`文件放置这些指令来进行重定向：

```html
RewriteEngine on
RewriteCond %{HTTP_USER_AGENT} iPhone
RewriteRule .* http://mobile.example.com/ [R]
```

在这个例子中，我们正在启用重写引擎，创建一个重写条件，检查用户代理中是否有`iPhone`文本，然后如果条件满足就创建一个重写规则。

实质上，如果我们想要重定向到我们网站的移动版本，我们需要能够检测设备的类型，而不是它的尺寸，然后适当地进行重定向。

# 主屏幕图标

如果您正在创建一个应用程序，应该模仿成为本机应用程序的感觉，或者只是增加 Web 应用程序的体验，那么拥有代表您的应用程序的书签图标是一个好主意。

目前，我们支持在我们的`index.html`文件中使用以下标记：

```html
<link rel="apple-touch-icon-precomposed" sizes="144x144" href="img/touch/apple-touch-icon-144x144-precomposed.png">
<link rel="apple-touch-icon-precomposed" sizes="114x114" href="img/touch/apple-touch-icon-114x114-precomposed.png">
<link rel="apple-touch-icon-precomposed" sizes="72x72" href="img/touch/apple-touch-icon-72x72-precomposed.png">
<link rel="apple-touch-icon-precomposed" href="img/touch/apple-touch-icon-57x57-precomposed.png">
<link rel="shortcut icon" href="img/touch/apple-touch-icon.png">
```

这些指令告诉 Safari 我们有适合相应设备的主屏幕图标。从上到下，我们支持视网膜显示屏、第一代 iPad 和非视网膜 iPhone、iPad Touch，甚至 Android 2.1+。

简单地说，我们有一个应用程序，用户可以将其添加到主屏幕的书签中，从而可以立即从主屏幕访问 Web 应用程序。

# 介绍我们的构建脚本

早些时候，我们安装了我们的构建脚本以及 HTML5 移动样板。现在，我们将通过为我们的目的定制它来进一步探索构建脚本。我们需要确保我们的样式、脚本、图像和标记都经过优化以进行部署。我们还需要设置多个环境来彻底测试我们的应用程序。

## 配置我们的构建脚本

让我们从为我们的需求配置构建脚本开始，这样我们将拥有一个为我们工作并立即启动的自定义构建脚本。

### 缩小和连接脚本

首先，让我们确保我们的脚本被连接和缩小。因此，让我们打开所有我们的`index.html`文件，并在页面底部用以下注释包装所有我们的脚本：

```html
<!-- scripts concatenated and minified via ant build script-->
<script src="img/script.js"></script>
<!-- end scripts-->
```

先前的注释被`ant`任务或构建脚本用来查找所有正在使用的 JavaScript 文件，将它们连接并进行缩小。该过程还将在新优化的 JavaScript 文件上使用时间戳，以打破服务器上的缓存。

### 缩小和连接样式

默认情况下，Ant 构建脚本会缩小和连接我们的样式。但是，如果我们想保留标识应用程序特定部分的注释，比如视频或音频部分，那么我们需要做一些事情来保留这些注释。

注释可以用来标识一个部分，并且可以写成以下形式：

```html
/*!
  Video Styling
*/
```

为每个样式表写上先前的注释。

然后，我们需要将每个样式表添加到项目属性中，以便可以通过 YUI 压缩器对每个样式表进行缩小。为此，我们需要打开位于`/build/config`目录中的`project.properties`文件。

然后找到以下行：

```html
file.stylesheets  =
```

一旦我们找到了那一行，让我们按照以下方式添加所有我们的`css`文件：

```html
file.stylesheets  = audio.css,forms.css,location.css,singlepage.css,touch.css,video.css
```

请注意，每个文件后面没有空格。这对于构建脚本的处理是必要的。

这是我们目前需要做的所有优化样式。

## 创建多个环境

通常，一个项目将在开发、测试和生产环境上运行。测试环境应该在配置方面最接近生产环境，这样我们就可以有效地重现可能出现的任何问题。

为了正确构建我们的环境，让我们通过构建我们的项目的过程。首先，让我们打开`终端`，这是一个允许你通过命令行界面与任何 Unix 风格计算机的操作系统进行交互的程序。

### 导航我们的目录

一旦终端启动并运行，我们必须导航到我们的项目。以下是一些可以帮助你导航的命令：

```html
cd /somesite
```

上一个命令意味着我们正在从当前目录切换到`Somesite`目录，相对于你现在的位置。

```html
cd ../somesite
```

这个命令告诉我们要更改目录，但是使用`../`向上一级，然后进入`somesite`目录。

举个更容易理解的例子，我的项目存在于`/Sites/html5iphonewebapp`。所以我可以使用以下命令进入我的项目：

```html
cd /Users/somuser/Sites/html5iphonewebapp
```

这个命令将我的目录更改为我正在开发这个应用程序的项目。

### 构建我们的项目

一旦我们进入了项目目录，我们就可以开始构建我们的项目。默认情况下，Ant Build 脚本会创建一个生产环境，优化整个过程的所有部分。

```html
ant build
```

这个命令告诉我们要构建我们的项目，并且如解释的那样，在一个名为`publish`的目录中创建我们的生产版本。当你运行该命令时，你会注意到你的终端会更新，让你知道构建过程中的哪个步骤。

一旦构建完成，你的目录结构应该类似于以下截图：

![构建我们的项目](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-iph-webapp-dev/img/1024_01_03.jpg)

`publish`目录代表生产环境。你还会看到一个中间目录已经被创建；这是你的测试环境。

然而，假设你想要完全控制构建，并且想要手动创建你的环境，那么可以在终端中执行以下操作：

```html
ant build -Denv=dev
```

这个命令，`ant build –Denv=`, 让我们定义我们想要构建的环境，并相应地执行。

我们现在有一个准备好进行构建的项目。在这个过程中有很多步骤，所以我鼓励你练习这个过程，以便为你和/或你的团队开发一个适合你们的良好架构和部署过程。

# 总结

在本章中，我们看到了如何为我们的项目使用 HTML5 移动样板，从下载默认包到根据我们的需求进行定制。我们还采取了一些简单的步骤来为我们的 JavaScript、CSS 和 HTML 建立一个坚实的架构。作为一个额外的奖励，我们还介绍了包括构建过程并为我们的项目进行定制。然后我们快速回顾了 JavaScript 应用程序的最佳实践，并给出了一些关于如何将用户引导到一个单独的移动站点的建议。我们现在已经准备好深入开发移动 Web 应用程序了。


# 第二章：集成 HTML5 视频

媒体分发对于任何 Web 应用程序都是必不可少的；提供改变用户感知的丰富体验。很多时候，我们被要求在网站上放一张静态图片，而其他时候，我们被要求包含视频画廊，允许用户通过某种独特的导航轻松切换视频。以前，我们可以使用 Flash 和其他基于插件的技术来实现这一点，但随着 HTML5 视频的广泛支持，我们现在有能力在不需要下载插件的情况下提供视频。

需要记住的一件事是，HTML5 视频和音频共享相同的规范。这是因为它们都被认为是媒体元素。这意味着视频和音频共享一些属性和方法，使得在我们的应用程序中实现它们更容易。

无论如何，让我们开始学习如何配置我们的服务器以正确地传送我们的视频。

在本章中，我们将涵盖：

+   配置我们的服务器以进行视频分发

+   实施 HTML5 视频

+   监听 HTML5 视频事件

+   创建一个完整的 JavaScript 视频库

+   自定义 HTML5 视频控件

# 配置服务器

在实施视频之前，我们需要确保服务器知道我们将提供哪些媒体类型。现在这样做有助于避免以后出现网络错误时不知道原因的头痛。所以让我们开始吧。

## 视频格式

首先，我们需要知道我们将提供哪些文件类型。在我们的示例中，我们将使用 MP4，但允许支持的文件类型总是一个好主意。确保你的视频有 WebM、OGV 和 MP4 格式。但首先，在我们继续之前，让我们先了解一下这些格式。

### 提示

我们不会深入解释广泛支持的不同类型，但请记住，Theora、WebM 和 H.264/MPEG-4 是最广泛支持的格式。Theora 和 WebM 都是免费的，WebM 的开发得到了 Google 的支持。由于担心专利问题，Theora 在浏览器中的实现一直滞后，而 WebM 由于其免版税和开放的视频压缩功能，得到了 Mozilla Firefox、Google 和 Opera 的广泛支持。

当涉及到 H.264 时，情况变得有点棘手。尽管它是一个高质量、速度快、视频压缩的标准格式，但专利使其受到限制。因此，它在流行浏览器中的支持一直滞后。最终，每个浏览器都开始支持这种格式，但不是没有争议。

## 视频格式指令

接下来，根据服务器类型，我们需要包含特定的指令来允许我们的文件类型。在这个例子中，我们使用的是 Apache 服务器，因此以下语法：

```html
AddType video/ogg .ogv
AddType video/mp4 .mp4
AddType video/webm .webm
```

前面的代码将被添加到服务器上的`.htaccess`文件或`httpd.conf`文件中。无论哪种方式，`AddType`指令都会告诉服务器它应该和可以提供哪些类型。因此，当我们逐行进行时，我们可以看到我们正在添加`video/ogg`类型和扩展名`.ogv`，我们也为 MP4 和 WebM 这样做。

采取这些初始步骤有助于我们在使用 HTML5 在网站上实现视频时避免任何网络问题。如果你想知道我们如何使用这些类型，不用担心，下一节我们将详细介绍。

# 一个简单的 HTML5 视频

我们一直渴望在我们的 Web 应用程序中做一些酷炫的东西，所以让我们开始吧。让我们从在我们的网站上以最简单的方式包含一个视频开始，而不涉及任何复杂的交互！

## 单一视频格式

首先，让我们打开位于`Chapter 2`项目的`video`子目录中的`index.html`文件。如果你跳过了第一章，不要担心，`Chapter 2`的源文件会跟随并帮助你继续前进。

一旦我们有了我们的`index.html`文件，我们希望在内容区域中包含`video`元素，在`<header>`元素之后。这很简单，我们可以这样做：

```html
<video src="img/testvid.mp4" controls preload></video>
```

前面的代码类似于图像元素。我们定义了一个`src`属性，指示浏览器在哪里找到视频，然后我们定义了`controls`和`preload`属性，这些属性指示浏览器显示默认的本机控件并预加载视频。简单吧？

## 支持多种格式

这就是我们在网站上放置视频所需要的一切，但当然，事情并不总是那么简单。正如我们之前讨论的，浏览器可以支持我们指定的格式中的一个或一个都不支持。当然，现在我们有很好的浏览器支持，但我们要确保我们的应用程序是稳固的，所以我们需要确保我们传递适当的文件。为了做到这一点，我们可以修改上面的代码如下：

```html
<video poster="testvid.jpg" controls preload>
    <source src="img/testvid.webm" type='video/webm'/>
    <source src="img/testvid.ogv" type='video/ogg'/>
    <source src="img/textvid.mp4" type='video/mp4'/>
    <p>Fallback Content</p>
</video>
```

在这里，我们介绍了一个新属性，`poster`。`poster`属性是我们在视频开始时显示的图像，或者在视频无法加载时显示的图像。当我们将源元素移动到`video`元素内部时，事情变得有点复杂。但是，如果我们检查一切，我们基本上是在定义多个源视频及其类型。然后浏览器将选择适当的视频进行显示。可能会让你困惑的是包含`Fallback Content`文本的段落元素。如果一切都失败了，或者浏览器不支持 HTML5 视频，这就是它的作用。

如果这有点令人困惑，不要太担心，因为 iPhone 的移动 Safari 支持 MP4，而且这对你的应用程序来说已经足够了。所以如果我们想保持简单，我们可以在我们的 iPhone 应用程序中使用以下代码，这也正是我们在本书中所做的：

```html
<video src="img/testvid.mp4" controls preload>
    <p>Video is not supported in your browser.</p>
</video>
```

现在我们的应用程序中有一个简单的视频播放，我们可能想要捕捉视频的事件。

# 监听 HTML5 视频事件

很可能你会想要完全控制你的应用程序，或者至少监视可能发生的事情。出于各种原因，你通常会发现自己附加事件或监听事件。从跟踪到增强体验，事件是我们如何在页面上驱动交互的方式。使用 HTML5 视频，我们可以使用本机浏览器从头到尾监视视频的状态。你有机会监听视频何时加载完成以及用户何时暂停视频。

让我们回顾一下我们可以使用的事件。你会发现，我们用于视频的事件也可以转移到音频上。这是因为，正如我们之前学到的那样，视频和音频元素都被归类为 HTML5 规范中的媒体元素。这是我们可以使用的事件表：

| 事件名称 | 条件 |
| --- | --- |
| `loadedmetadata` | 已确定媒体资源的持续时间和尺寸。 |
| `loadeddata` | 现在可以首次渲染媒体数据。 |
| `canplay` | 媒体数据的播放可以恢复。 |
| `seeking` | 媒体资源的寻找属性已设置为 true。 |
| `seeked` | 媒体资源的寻找属性已设置为 false。 |
| `play` | 元素未暂停。当`play()`方法已返回或`autoplay`属性已导致元素开始播放时触发。 |
| `ended` | 已到达媒体资源的结尾并且播放已停止。 |
| `pause` | `pause()`方法已返回，元素已暂停。 |
| `timeupdate` | 媒体资源的播放位置以某种方式发生了变化。 |
| `volumechange` | 当音量或静音属性发生变化时触发。 |

规范定义了更多的事件，但这些是我们将从先前简单实现中监听的事件。所以让我们开始吧。

## 视频标记回顾

首先，打开`video`目录中的`index.html`文件。在这个文件中，您必须确保您的内容看起来像下面这样：

```html
<div class="site-wrapper">
    <header>
        ....
    </header>
    <div class="gallery">
                    <video src="img/testvid.mp4" controls preload></video>
    </div>
    <footer>
        ...
    </footer>
</div>
```

不要注意省略号，这只是为了使代码在文本中更短。您要确保的是，您有来自上一节的简单的`<video>`元素实现。

## 附加视频事件

现在开始有趣的部分。让我们开始扩展我们的 JavaScript 以包括监听器。让我们打开位于`App`文件夹下`/js`目录中的`App.Video.js`文件。如果您没有从我们的架构章节一直跟着做，不用担心，对您来说重要的是要理解我们为应用程序创建了一个结构，`App.Video.js`文件将包含视频应用程序的所有功能。

找到`App.Video`类的构造函数。这应该在您的文本编辑器的第 16 行，并且当前应该看起来像下面这样：

```html
function Video(options) {
    // Customizes the options by merging them with whatever is passed in
    this.options = $.extend({}, _defaults, options);

    //Cache the main element
    this.$element = $(this.options.element);
}
```

再次回顾一下，我们将一个称为`options`的对象传递给我们的构造函数。从这里，我们创建一个名为`options`的属性，用于`Video`的实例，这个属性将使用 Zepto 的 extend 方法设置为选项和默认值的扩展或合并版本。然后，我们缓存通过合并选项发送的元素。这可能有点令人困惑，但在 JavaScript 应用程序中，这是一个非常公认的模式。

由于我们已经验证了我们的构造函数存在并且运行良好，现在我们想要添加先前的监听器。我们可以使用本地的`addEventListener`方法轻松地做到这一点，如下所示：

```html
this.options.element.addEventListener('canplay', function(e){ 
    console.log('video :: canplay'); 
});

this.options.element.addEventListener('seeking', function(e){ 
    console.log('video :: seeking'); 
});

this.options.element.addEventListener('seeked', function(e){ 
    console.log('video :: seeked'); 
});

this.options.element.addEventListener('ended', function(e){ 
    console.log('video :: ended'); 
});

this.options.element.addEventListener('play', function(e){ 
    console.log('video :: play'); 
});

this.options.element.addEventListener('pause', function(e){ 
    console.log('video :: pause'); 
});

this.options.element.addEventListener('loadeddata', function(e){ 
    console.log('video :: loadeddata'); 
});

this.options.element.addEventListener('loadedmetadata', function(e){ 
    console.log('video :: loadedmetadata'); 
});

this.options.element.addEventListener('timeupdate', function(e){ 
    console.log('video :: timeupdate'); 
});
```

这里有几件事情需要注意。首先，我们使用`this.options.element`而不是缓存版本的`this.$element`。我们这样做是因为我们实际上想要元素而不是`Zepto`对象。其次，我们调用`addEventListener`并传递两个参数。第一个参数是一个字符串，定义了我们要监听的事件。第二个参数是一个回调函数，每当我们在参数一中指定的事件触发时都会被调用。

### 提示

请注意，我们正在使用`console.log()`方法。它类似于`alert()`，但没有那么烦人。它有助于更好地调试，并输出到一个控制台，让我们跟踪所有的日志输出。在继续之前，使用这种方法是调试我们的应用程序和测试功能的好方法。

您的构造函数现在应该如下所示：

```html
function Video(options) {
    // Customizes the options by merging them with whatever is passed in
    this.options = $.extend({}, _defaults, options);

    // Cache the main element
    this.element = options.element;
    this.$element = $(this.options.element);

    this.options.element.addEventListener('canplay', function(e){ 
        console.log('video :: canplay'); 
    });

    this.options.element.addEventListener('seeking', function(e){ 
        console.log('video :: seeking'); 
    });

    this.options.element.addEventListener('seeked', function(e){ 
        console.log('video :: seeked'); 
    });

    this.options.element.addEventListener('ended', function(e){ 
        console.log('video :: ended'); 
    });

    this.options.element.addEventListener('play', function(e){ 
        console.log('video :: play'); 
    });

    this.options.element.addEventListener('pause', function(e){ 
        console.log('video :: pause'); 
    });

    this.options.element.addEventListener('loadeddata', function(e){ 
        console.log('video :: loadeddata'); 
    });

    this.options.element.addEventListener('loadedmetadata', function(e){ 
        console.log('video :: loadedmetadata'); 
    });

    this.options.element.addEventListener('timeupdate', function(e){ 
        console.log('video :: timeupdate'); 
    });
}
```

## 初始化我们的视频

现在我们已经定义了一个初步的视频类，我们需要初始化它。所以让我们继续打开`main.js`，我们的初始化代码应该在那里。它应该看起来像这样：

```html
(function(window, document) {
    'use strict';

    // Create an instance of our framework
    var app = new App({
        // Custom Option, allowing us to centralize our framework
        // around the site-wrapper class
        'element': document.querySelector('.site-wrapper')
    });
    // Expose our framework globally
    window.app = app;
}(window, document));
```

我们在上一章中创建了这个，但让我们简要地回顾一下。在这里，我们创建了一个闭包，传递了`window`和`document`对象。在内部，我们设置解释器严格地读取我们的代码。然后我们创建了`App`类的一个实例，然后将其暴露给`window`对象。

现在我们需要添加`Video`类的初始化。为此，让我们在声明`App`的新实例之后放入以下代码片段，如下所示：

```html
new App.Video({
    'element': document.getElementsByTagName('video')[0]
});
```

这个片段创建了`App.Video`类或`Video`类的一个新实例，并传入一个包含元素的简单对象。我们通过使用附加到`document`对象的`getElementsByTagName`方法来检索元素。我们告诉方法查找所有的视频元素。有趣的部分是`[0]`，它告诉查找结果只获取返回的数组中的第一个元素。

如果我们加载页面并测试视频，我们应该在控制台中看到我们之前定义的日志输出，类似于以下的截图：

![初始化我们的视频](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-iph-webapp-dev/img/1024_02_01.jpg)

视频日志输出

我们已经开始了`Video`类的初步工作，从事件到初始化。然而，如果我们要使它可重用于我们的应用程序，并且如果我们想要扩展其功能，我们需要稍微整理一下。因此，让我们花一些时间创建一个完全功能的 JavaScript 视频库，它将在我们的 iPhone 网络应用程序中工作。

# 创建一个 JavaScript 视频库

目前，我们有一个非常简单的`Video`类，它缓存一个元素，然后附加了多个由 HTML5 媒体元素规范定义的事件。我们已经定义了视频播放器的基本要素，现在需要进一步抽象，以便更好地重用和管理。遵循一些约定并创建一个灵活的框架将帮助我们更快更有效地移动。

首先，让我们考虑一些可能需要从这个类中得到的东西：

+   一个附加适当事件的事件方法

+   可以定义的回调方法，例如`onPlay`，`onPause`和`onEnded`

+   可以从实例外部调用的公共方法

+   类似于 jQuery 的可链接方法，您可以依次调用一个方法，例如`fadeIn().fadeOut().show().hide()`

拥有一个抽象类行为的项目列表是建立一个坚实框架或库的正确方向。现在让我们开始创建回调。

## 集中我们的事件

首先，让我们解决如何为我们的`Video`类附加事件。以前，我们将这些事件添加到构造函数中，虽然这是一种不错的技术，但可以通过指定一个处理事件附加到`Video`对象实例的函数来改进。

那么，让我们在`Video`类中创建一个名为`attachEvents`的私有方法，该方法只能在`App.Video`闭包或 IIFE 中访问。当我们创建我们的`attachEvents`方法时，我们应该将所有的事件处理程序放在其中。然后我们希望在初始化`this.$element`之后调用`attachEvents`方法。完成后，您的代码应该如下所示：

```html
function Video(options) {
    this.options = $.extend({}, _defaults, options);

    // Cache the main element
    this.element = options.element;
    this.$element = $(this.options.element);

    attachEvents();
}

function attachEvents() {
    // All your event handlers go here
}
```

### 提示

在之前的代码中，`attachEvents()`函数将包含我们之前创建的事件处理程序。为了简洁起见，我现在省略了它们。

现在，如果我们运行这段代码，很可能会遇到一些错误。这实际上是正常的，被称为作用域问题。为了解决这个问题，首先我们需要了解幕后发生了什么。

### JavaScript 中的作用域

如果您是 JavaScript 的新手，作用域很可能会在早晚困扰您。如果您在 JavaScript 中处于中级或高级水平，您可能仍然会遇到作用域问题。这是完全正常的，我们都会遇到这种情况。无论如何，让我们拿出当前的`Video`类并分析一下，以便在上下文中理解作用域。

JavaScript 具有函数级作用域，这意味着每次创建新函数时，都会创建一个新的作用域。作用域可能会相当令人困惑，但通过实践会变得更容易。现在把作用域看作是对当前位置的引用，它知道自己和它的环境，但不知道在它内部新创建的作用域。如果听起来令人困惑，当你开始时可能会有些困惑。但让我们通过一些代码来更好地理解一下。

所以，让我们从全局范围开始：

```html
// Global Scope
var x = 10;
(function($){ 
    // New Scope
    console.log(x);
}(Zepto));
```

在这个例子中，`App.Video`的简化版本中，我们可以看到全局作用域在闭包周围。当我们创建一个闭包时，会创建一个新的作用域。这里很酷的一点是，闭包外的任何东西都可以被访问到。因此，当我们在闭包内部执行`console.log`时，我们应该得到`10`。

每当你创建一个新的函数作用域时，你可以传递参数，本质上是给你发送的值命名空间。在这种情况下，我们传入`Zepto`，并告诉新的函数作用域在该作用域内将美元符号定义为`Zepto`的实例。希望这能更清楚地解释作用域，如果不清楚，不要担心；理解这个概念需要时间和耐心。

因此，我们事件处理程序的问题在于`attachEvents`内的新函数作用域没有对`this.options`的引用。由于新的作用域，关键字`this`相对于窗口对象，而不是`Video`对象。它没有引用的原因是因为我们的构造函数是一个完全不同的作用域，它们之间没有交流。为了解决这个问题，我们可以使用`.call()`方法，它将改变`this`关键字的引用，以反映`Video`函数作用域。可以通过修改`attachEvents`的调用来实现：

```html
attachEvents.call(this);
```

如果你现在运行你的代码，你不应该得到任何错误。如果有的话，看看代码的最终版本，进行比较并找出问题所在。

## 暴露功能

在本章的后面，我们将探索自定义用户界面，帮助我们覆盖视频播放器的默认功能。然而，为了做到这一点，我们需要确保一些功能是公开的。在 JavaScript 中，为了使方法在闭包之外公开，我们需要将方法附加到`class`的原型上——在这种情况下是`Video`。

我们已经看到我们的所有类中都暴露了两个方法；这些包括`getDefaults`和重写函数`toString`。让我们通过添加`play`、`pause`、`stop`、`mute`、`unmute`和`fullscreen`方法来扩展原型。

```html
Video.prototype.play = function() {
    return this;
}

Video.prototype.pause = function() {
    return this;
}

Video.prototype.stop = function() {
    return this.pause();
}

Video.prototype.mute = function() {
    return this;
};

Video.prototype.unmute = function() {
    return this;
};

Video.prototype.fullscreen = function() {
    return this;
}
```

我相信你已经注意到这些方法中缺少了代码，没关系。我们想要理解的是，我们可以扩展`Video`原型，并且可以通过在`return this`行中返回实例来为我们的方法添加链式调用。

让我们开始为我们的方法添加功能，从`play`开始：

```html
Video.prototype.play = function() {
    this.element.play();

    return this;
}
```

在这里，我们通过调用`play`方法获取了我们在`Video`构造函数中缓存的元素。你可能想知道这个`play`方法是从哪里来的？嗯，HTML5 规范为媒体元素（包括视频和音频）定义了一个`play`方法。因此，我们可以使用`this.element.play()`来调用这个方法。我们可以用同样的方法来调用`pause`方法：

```html
Video.prototype.pause = function() {
    this.element.pause();
    return this;
}
```

再次，我们有一个由 HTML5 规范定义的暂停媒体元素的方法。当我们定义一个`stop`方法时，事情变得有点混乱：

```html
Video.prototype.stop = function() {
    return this.pause();
}
```

和以前一样；我们实际上没有做任何改变。让我解释一下，规范没有定义`stop`方法，所以我们需要创建一个方法来提供这个功能。但这并不太困难，因为我们已经定义了一个执行类似操作的`pause`方法。所以我们需要做的就是调用`this.pause()`，因为这是`Video`的一个实例，我们已经定义了一个`pause`方法。这里的巧妙之处在于我们不需要返回`this`，因为暂停方法已经返回了`this`，所以我们只需要返回调用`pause`方法的结果。我知道这有点令人困惑，但随着时间的推移，如果这是你第一次这样做，它会变得清晰起来。

现在，我们来看看我们的`mute`和`unmute`方法：

```html
Video.prototype.mute = function() {
    this.element.muted = true;
    return this;
};
Video.prototype.unmute = function() {
    this.element.muted = false;
    return this;
};
```

这些方法的唯一区别在于我们在视频元素上设置了一个属性为`false`。在这种情况下，我们将静音属性设置为`true`或`false`，取决于你调用的方法。

这里的事情变得有点复杂：

```html
Video.prototype.fullscreen = function() {
    if (typeof this.element.requestFullscreen === 'undefined') {
        this.element.webkitRequestFullScreen();
    } else {
        this.element.requestFullscreen();
    }
    return this;
}
```

这有点复杂，可能有点令人沮丧。相信我，行业内的许多人都感到痛苦。我们需要理解的是，我们正在处理的浏览器 Safari 是运行在一个名为 WebKit 的开源网络浏览器引擎上。

WebKit 非常受欢迎并得到广泛支持。问题在于，虽然它在实现最新和最好的功能方面做得很好，但其中许多是实验性的，因此它们具有前缀。我们在 CSS（层叠样式表）中经常看到这一点，使用`-webkit`。但在 JavaScript 中，我们也面临相同的问题，`webkit[standardMethodName]`。

虽然这可能很棒，但我们需要确保我们对剥离该前缀的新版本具有向后兼容性。这就是为什么在上一个方法中，我们对标准方法名称进行检查，如果不存在，我们使用`-webkit`前缀。否则，我们使用标准版本。

## 集成回调

回调在任何库或框架中都非常有用，您可能已经在使用 jQuery 或其他一些流行框架时看到过类似的东西。实质上，回调是在方法完成后调用的方法。例如，在`Zepto`方法中，`fadeout`接受两个参数，第一个是速度，第二个参数是在淡出完成时调用的函数。可以如下所示：

```html
$('.some-class').fadeout('fast', function(){
    // Do something when fading is complete
});
```

在上一个代码中的第二个参数不仅是一个回调函数，还是一个匿名函数。匿名函数只是一个没有名称的函数。在这种情况下，它在每次`fadeOut()`效果完成时执行。我们可以将上一个代码重写如下：

```html
$('.some-class').fadeOut('fast', someFadeOutFunc);
function someFadeOutFunc(){
    // Do something when fading is complete
}
```

由于我们创建了一个名为`someFadeOutFunc`的方法，当`fadeOut`完成时，我们只需调用该函数，而不是创建一个新函数。从架构的角度来看，这更有效和可管理。

创建回调的第一步是定义我们在代码中可能需要回调的位置。在这种情况下，我们可能希望为视频播放器中采取的每个操作创建一个回调，因此我们将创建以下回调：

+   `onCanPlay`

+   `onSeeking`

+   `onSeeked`

+   `onEnded`

+   `onPlay`

+   `onPause`

+   `onLoadedData`

+   `onLoadedMetaData`

+   `onTimeUpdate`

+   `onFullScreen`

好的，现在我们知道我们的代码中需要哪些回调，让我们在`attachEvents`方法之前的构造函数中实现它们：

```html
this.callbacks = {
    'onCanPlay': function(){ },
    'onSeeking': function(){},
    'onSeeked': function(){},
    'onEnded': function(){},
    'onPlay': function(){},
    'onPause': function(){},
    'onLoadedData': function(){},
    'onLoadedMetaData': function(){},
    'onTimeUpdate': function(){},
    'onFullScreen': function(){}
};
```

我们在这里所做的是将一个名为`callbacks`的属性附加到`Video`的实例上。该属性包含一个对象，该对象为我们想要实现的每个回调设置了键/值对，值是一个空的匿名函数。

### 扩展回调

尽管我们可以在类中使用回调，但问题在于它们不具有可扩展性，这意味着使用您的`Video`类的开发人员将无法扩展您的回调。为了使它们具有可扩展性，我们需要将它们放在我们的`_defaults`对象中：

```html
var _defaults = {
    'element': 'video',
    'name': 'Video',
    'callbacks': {
        'onCanPlay': function(){ },
        'onSeeking': function(){},
        'onSeeked': function(){},
        'onEnded': function(){},
        'onPlay': function(){},
        'onPause': function(){},
        'onLoadedData': function(){},
        'onLoadedMetaData': function(){},
        'onTimeUpdate': function(){},
        'onFullScreen': function(){}
    }
};
```

缺点是现在我们需要使用`this.options.callbacks`来访问我们想要的回调。通过在我们的构造函数中执行以下操作，可以轻松解决这个问题：

```html
this.callbacks = this.options.callbacks;
```

这仍然允许我们访问回调，但只能从扩展对象中访问。

### 使用回调

现在我们有了回调，并且已经使它们具有可扩展性，我们可以进入并将它们集成到我们的事件处理程序中。但首先，我们需要将我们的事件处理程序作为私有方法放在这个`Video`类中，并按以下方式调用我们的自定义回调：

```html
function onCanPlay(e, ele) {
    this.callbacks.onCanPlay();
}

function onSeeking(e, ele) {

    this.callbacks.onSeeking();
}

function onSeeked(e, ele) {

    this.callbacks.onSeeked();
}

function onEnded(e, ele) {

    this.callbacks.onEnded();
}

function onPlay(e, ele) {

    this.callbacks.onPlay();
}

function onPause(e, ele) {

    this.callbacks.onPause();
}

function onLoadedData(e, ele) {
    this.callbacks.onLoadedData();
}

function onLoadedMetaData(e, ele) {
    this.callbacks.onLoadedMetaData();
}

function onTimeUpdate(e, ele) {
    this.callbacks.onTimeUpdate();
}
```

在这一点上，我们已经完全将我们的回调集成到我们的库中。现在，我们只需要通过修改`attachEvents`处理程序来调用它们，如下所示：

```html
function attachEvents() {
        var that = this;
        this.element.addEventListener('canplay', function(e){ onCanPlay.call(that, e, this);  });
        this.element.addEventListener('seeking', function(e){ onSeeking.call(that, e, this); });
        this.element.addEventListener('seeked', function(e){ onSeeked.call(that, e, this);  });
        this.element.addEventListener('ended', function(e){ onEnded.call(that, e, this);  });
        this.element.addEventListener('play', function(e){ onPlay.call(that, e, this);  });
        this.element.addEventListener('pause', function(e){ onPause.call(that, e, this);  });
        this.element.addEventListener('loadeddata', function(e){ onLoadedData.call(that, e, this);  });
        this.element.addEventListener('loadedmetadata', function(e){ onLoadedMetaData.call(that, e, this);  });
        this.element.addEventListener('timeupdate', function(e){ onTimeUpdate.call(that, e, this);  });
    }
```

这里实施了一些概念。首先，我们用之前定义的实际私有方法替换了`console.logs`。其次，我们使用`call`方法通过传入`that`来更改`private`方法的范围，然后将`event`和`element`作为参数发送进去。

## 将所有内容联系起来

我们拥有一切所需的东西，如事件处理程序、公开功能、回调，甚至可链接的方法。这都很好，但现在我们需要让它起作用。这就是魔法发挥作用的地方。

要验证，您的`Video`类应该如下所示：

```html
var App = window.App || {};

App.Video = (function(window, document, $){
    'use strict';

    var _defaults = { ... };

    // Constructor
    function Video(options) {
        this.options = $.extend({}, _defaults, options);

        this.element = options.element;
        this.$element = $(this.options.element);

        this.callbacks = this.options.callbacks;

        attachEvents.call(this);
    }

    // Private Methods
    function attachEvents() { ... }

    // Event Handlers
    function onCanPlay(e, ele) { ... }
    function onSeeking(e, ele) { ... }
    function onSeeked(e, ele) { ... }
    function onEnded(e, ele) { ... }
    function onPlay(e, ele) { ... }
    function onPause(e, ele) { ... }
    function onLoadedData(e, ele) { ... }
    function onLoadedMetaData(e, ele) { ... }
    function onTimeUpdate(e, ele) { ... }

    // Public Methods
    Video.prototype.getDefaults = function() { ... };
    Video.prototype.toString = function() { ... };
    Video.prototype.play = function() { ... }
    Video.prototype.pause = function() { ... }
    Video.prototype.stop = function() { ... }
    Video.prototype.mute = function() { ... };
    Video.prototype.unmute = function() { ... };
    Video.prototype.fullscreen = function() { ... }

    return Video;

}(window, document, Zepto));
```

### 注意

请注意，上一段代码中的省略号表示应该有功能。由于页面数量的限制，我们只能展示到目前为止代码的简要摘要。如果您需要查看已完成的工作，请查看前面的部分或查看本书附带的源代码。

如果您的文件看起来像这样，那就太完美了！如果它看起来不太像这样，不要担心，这就是为什么我们在这本书中附上了源代码。在这一点上，我们已经准备好在我们的页面上初始化这个库了。

让我们打开`main.js`文件；该文件应该位于`js`目录下。我们需要进行以下添加：

```html
new App.Video({
    'element': document.getElementsByTagName('video')[0],
    'callbacks': {
        'onCanPlay': function(){ console.log('onCanPlay'); },
        'onSeeking': function(){ console.log('onSeeking'); },
        'onSeeked': function(){ console.log('onSeeked'); },
        'onEnded': function(){ console.log('onEnded'); },
        'onPlay': function(){ console.log('onPlay'); },
        'onPause': function(){ console.log('onPause'); },
        'onLoadedData': function(){ console.log('onLoadedData'); },
        'onLoadedMetaData': function(){ console.log('onLoadedMetaData'); },
        'onTimeUpdate': function(){ console.log('onTimeUpdate'); },
        'onFullScreen': function(){ console.log('onFullScreen'); }
    }
});
```

让我们快速浏览一下。首先，我们创建一个新的`App.Video`实例，传入一个参数——一个简单的对象。其次，我们传入的对象包含两个对象：我们想要在页面上的`video`元素，以及一个覆盖默认值的回调对象。第一个参数使用内置方法`getElementsByTagName`来获取`video`元素的所有实例，然后我们使用`[0]`获取找到的第一个实例。这是因为该方法返回一个数组。第二个参数`callbacks`包含我们想要在`App.Video`实例上调用的函数回调。在这些方法中，我们只想要记录被调用的方法。

从这里开始，当实例被初始化时，我们定义的`Video`库将合并我们传入的简单对象，并从那里开始。几乎就像魔术一样，除了我们已经创建了它。

最后要注意的一点是，确保我们只在视频页面上初始化视频。如果我们在应用程序的非视频页面上，这段代码将产生一个错误。这是因为没有视频元素，我们也没有添加错误检测。这是一个很好的功能，但本书不涵盖这部分。因此，让我们在`main.js`中做以下操作：

```html
if(document.querySelector('video') !== 'null') {
    new App.Video({
        'element': document.getElementsByTagName('video')[0],
        'callbacks': {
            ...
        }
    });
}
```

在前面的代码中，我们将我们的初始化代码包装在一个`if`语句中，检查我们是否在视频页面上。我们进行检查的方式是使用文档对象上的内置方法`querySelector`。这个方法接受一个 CSS 类型的选择器，在这种情况下，我们发送`video`选择器，告诉它获取所有`video`元素的实例。如果返回的结果不是 null，那么我们就初始化。

现在我们不需要对标记做任何事情，这段代码将运行，我们应该没问题。如果由于某种原因您遇到任何错误，请查看本书附带的源代码。接下来，让我们考虑覆盖视频播放器的默认控件，以便更好地控制功能。

# 自定义 HTML5 视频控件

我们可能希望对视频控件有更多的输入，从样式到视频功能，比如添加停止按钮。为了做到这一点，我们需要稍微修改我们的标记。我们应该对视频做以下操作：

```html
<div class="video-container">
    <video src="img/testvid.mp4" controls preload>
        <p>Video is not supported in your browser.</p>
    </video>
</div>
```

我们在这里所做的只是在`video`元素周围添加了一个包含`div`的类，并给它添加了一个`video-container`的类。现在我们想要为`video`元素添加一些响应式样式，所以让我们打开`video.css`并添加以下样式：

```html
video {
    display: block;
    width: 100%;
    max-width: 640px;
    margin: 0 auto;
}

.video-container {
    width: 100%;
}
```

第一个选择器将应用于页面上的所有`video`元素，并告诉每个元素相对于其容器具有 100%的宽度，但最大宽度为`640px`。边距属性有助于使其在页面或容器中居中。下一个选择器`video-container`只指定宽度为 100%。这种样式将相应地调整播放器的大小；您可以通过调整浏览器大小来查看。

在这个例子中，我们将使用锚元素来使用基本控件。请记住，您可以使用任何类型的样式或标记来设计您的控件，只要记住我们已经在我们的`Video`类中公开了视频播放，所以为了简洁起见，我们将演示如何使用锚元素来实现这一点。

在我们的`video-container`中，我们想要附加以下标记：

```html
<div class="video-controls">
    <div class="vc-state">
        <a class="vc-play vc-state-play" href="#play">Play</a>
        <a class="vc-pause vc-state-pause" href="#pause">Pause</a>
    </div>
    <div class="vc-track">
        <div class="vc-progress vc-track-progress"></div>
        <div class="vc-handle vc-track-handle"></div>
    </div>
    <div class="vc-volume">
        <a class="vc-unmute vc-volume-unmute" href="#volume">Volume On</a>
        <a class="vc-mute vc-volume-mute" href="#volume">Volume Off</a>
    </div>
    <a class="vc-fullscreen" href="#fullscreen">Fullscreen</a>
</div>
```

前面的标记是我们将用于控件的标记。它们非常直观，但让我们回顾一下这里做出的一些决定。首先，我们有一个带有`video-controls`类的周围`div`，以帮助定义我们所有控件的存在位置。其次，每种类型的控件都以`vc`为前缀，代表视频控件。第三，在这个例子中，我们有四种类型的控件，即状态、轨道、音量和全屏控件。最后一点是，其中一些控件具有显示/隐藏功能，例如，播放和暂停只有在其他控件取消时才会显示。

对于样式，我们可以将以下样式添加到`video.css`文件中：

```html
.video-controls {
    margin: 12px auto;
    width: 100%;
    text-align: center;
}

.video-controls .vc-state,
.video-controls .vc-track,
.video-controls .vc-volume,
.video-controls .vc-fullscreen {
    display: inline-block;
    margin-right: 10px;
}

.video-controls .vc-fullscreen {
    margin-right: 0;
}

.video-controls .vc-state-pause,
.video-controls .vc-volume-unmute {
    display: none;
}
```

在这一部分的样式中，我们将所有视频控件样式自包含到`video-controls`类中。这有助于以模块化的方式维护样式。再次遵循响应式设计原则，我们告诉控件宽度为 100%。然后，每种类型的控件都设置为显示为内联块，类似于`float`。最后，我们告诉所有默认控件，它们不应该在初始时显示，所以设置为`display: none`。现在，我们需要为我们的控件添加交互性。

首先，让我们创建一个遵循整个框架的`App.VideoControls`类：

```html
var App = window.App || {};

App.VideoControls = (function(window, document, $){
    'use strict';

    var _defaults = { };

    function VideoControls(ele, options) {
        this.options = $.extend({}, _defaults, options);
        this.ele = ele;
        this.$ele = $(ele);

        this.init();
    }
    return VideoControls;

}(window, document, Zepto));
```

正如你所看到的，这里并没有太大的区别。唯一的区别是现在有一个被调用的`init`方法。这是为了将初始化功能分离到其他地方，以便构造函数不完全被代码填满。现在我们需要添加以下默认值：

```html
var _defaults = {
    // Supported Features
    'features': ['play', 'pause', 'fullscreen', 'mute', 'unmute', 'playpause'],
    // State of the controls
    'state': 'paused',
    // State of the sound
    'sound': 'unmuted',
    // Customizable Classes or Classes associated with Elements
    'classes': {
        'state': {
            'holder': 'vc-state',
            'play': 'vc-state-play',
            'pause': 'vc-state-pause'
        },
        'track': {
            'holder': 'vc-track',
            'progress': 'vc-track-progress',
            'handle': 'vc-track-handle'
        },
        'volume': {
            'holder': 'vc-volume',
            'mute': 'vc-volume-mute',
            'unmute': 'vc-volume-unmute'
        }
    },
    // Customizable Events or Dispatched Events
    'events': {
        'onPlay': 'videocontrols:play',
        'onPause': 'videocontrols:pause',
        'onFullScreen': 'videocontrols:fullscreen',
        'onMute': 'videocontrols:mute',
        'onUnmute': 'videocontrols:onUnmute'
    }
};
```

作为对这些默认值的回顾，第一个默认值是一个特性数组，允许开发人员进入这段代码来自定义我们需要初始化的内容。第二个默认值保持控件的状态，即播放、暂停等。第三个是专门用于声音的状态。类默认值允许我们使用自定义类，因此使用这个`videocontrols`类的开发人员不受我们在标记中定义的类的限制。最后一个是事件默认值，定义了我们想要分发的自定义事件。通过将其包含在我们的默认值中，开发人员现在也可以自定义这些事件。

### 注意

正如你所注意到的，构建一个可以在任何类型的网络应用程序中重复使用和正确实现的视频播放器需要很多工作。尽管一开始非常困难，但付出努力最终会有所帮助。现在我们可以以更模块化的方式添加和删除功能。

由于创建模仿原生控件的自定义控件需要大量的代码，我们决定将其余的功能，包括显示/隐藏和触发自定义事件，留在源代码中供您审查。不过不用担心，所有内容都有注释，如果您有问题，我鼓励您给我发电子邮件或向您的同事寻求帮助。

现在，我们想要实现控件和视频播放器之间的通信。但首先，我们需要清理一下`main.js`文件。因此，让我们从`main.js`中删除以下代码：

```html
if(document.querySelector('video') !== 'null') {
    new App.Video({
        'element': document.getElementsByTagName('video')[0],
        'callbacks': {
            ...
        }
    });
}
```

我们不希望这段代码出现在`main.js`中，因为它将在本书中构建的所有应用程序之间共享，所以我们需要将其抽离出来。因此，我们在`js/App`目录中创建了另一个名为`App.VideoController.js`的 JavaScript 文件。这个文件也包含在本书的源代码中。

请打开本书附带的`App.VideoController.js`文件，并找到`initControls`方法；它应该看起来像下面这样：

```html
VideoController.prototype.initControls = function() {
    // Remove Default control
    // Comment this out if you want native controls
    $(videoEle).removeAttr('controls');

    controlsEle = document.querySelector('.video-controls');

    controls = new App.VideoControls(controlsEle);

    $(controlsEle).
         on('videocontrols:play', function(){
            video.play();
        }).
        on('videocontrols:pause', function(){
            video.pause();
        }).
        on('videocontrols:fullscreen', function(){
            video.fullscreen();
        }).
        on('videocontrols:mute', function(){
            video.mute();
        }).
        on('videocontrols:onUnmute', function(){
            video.unmute();
        });

    return this;
}
```

让我们简要回顾一下这个方法中正在发生的事情，以便更好地理解它。首先，我们告诉我们的`video`元素隐藏它的控件。这是通过移除`controls`属性来实现的。然后我们将我们的`controls` div 缓存在`controlsEle`中。接下来，我们初始化我们的`App.VideoControls`类，并将其传递给缓存的`controls` div。最后，我们为缓存的视频控件添加监听器，并监听我们在`App.VideoControls`默认值中定义的自定义事件。这些监听器然后通过告诉实例`video`运行适当的函数来调用我们在`App.Video`中公开的方法。

我们需要处理的最后一个问题是初始化整个程序。由于我们在`main.js`中删除了初始化，我们需要在其他地方开始它。最好的地方应该是在特定的`index.html`上，即`video/index.html`。因此，让我们打开这个文件，并在页面底部包含以下脚本，就在`main.js`包含之后。

```html
<script>
    new App.VideoController(true);
</script>
```

这是最后需要处理的事项。当我们运行我们的页面时，我们应该有一个完全功能的视频播放器，它可以使用我们定制的控件。

# 总结

给自己一个大大的鼓励，因为你已经取得了相当大的成就！你不仅拥有了一个带有定制控件的视频播放器，而且还建立了一个符合 HTML5 规范并在 iPhone 上运行的稳固视频库。我们已经研究了 HTML5 规范的视频集成，创建了一个使用原生控件的简单视频播放器，构建了一个完全功能和模块化的视频库，用一个控件类扩展了视频库，定制了我们的体验，并最终创建了一个控制器类，将视频和定制控件连接起来。在这个过程中，我们花了一些时间来理解 JavaScript 中的作用域、原型和回调的有用性。如果在本章教授的概念中的任何时候你遇到了一些困难，请通过本书查看源代码，并且一如既往地，实践是完美的。下一章应该会更容易，因为我们将把我们在这里学到的概念应用到音频上。
