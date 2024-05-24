# HTML5 Web 应用开发示例（一）

> 原文：[`zh.annas-archive.org/md5/F338796025D212EF3B95DC40480B4CAD`](https://zh.annas-archive.org/md5/F338796025D212EF3B95DC40480B4CAD)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

现在是开始使用 HTML5 的时候了。HTML5 为编写在 Web 浏览器中运行的功能齐全的应用程序提供了完整的应用程序开发框架。尽管 HTML5 规范尚未完全完成，但几乎每个现代浏览器都已广泛支持最受欢迎的功能，从台式机到平板电脑再到智能手机上运行。这意味着你可以编写一次应用程序，然后在几乎任何设备上运行。

如果你想开始编写 HTML5 Web 应用程序，但不知道从哪里开始，那么这本书适合你。我们将从构建 Web 应用程序的基础知识开始，然后通过构建真正的工作应用程序来学习 HTML5、CSS3 和 JavaScript。这不是一本参考书。我们将尽量减少理论知识，最大限度地进行实际编码。

就在几年前，在浏览器中编写功能齐全的应用程序需要其他技术，比如作为浏览器插件运行的 Flash 或 Java 小程序。和大多数人一样，我只用 JavaScript 编写简单的客户端验证脚本。我甚至都没想过可以用 JavaScript 编写真正的应用程序。一切开始改变是因为发生了几件事情。

首先，我发现了 jQuery。这是一个库，通过抽象浏览器的特殊性，使得编写 JavaScript 变得更加容易，并且非常容易操作网页的元素。此外，它还可以帮助我们执行一些很酷的操作，比如动画元素。然后大约三年前，我在寻找一种在网页上直接绘制图形原语的方法时了解到了 HTML5。从那时起，我看到 HTML5 发展成为一个完整的框架，能够用来编写无需插件的真正应用程序。

这本书是过去三年几乎每天写 JavaScript 的结晶，学到了什么有效，什么无效。可以说是技术上的大脑倾泻。目标是写一本我在刚开始时希望能读到的书。

HTML5 Web 应用程序开发的未来看起来很光明。在 Web 浏览器开发领域，所有大公司都全力支持 HTML5 和 JavaScript。HTML5 是 Web 应用程序开发的未来！

# 本书涵盖的内容

第一章，“手边的任务”，将通过构建一个模板来教你 JavaScript 应用程序的基本组件，该模板可用于开始编写新的应用程序。然后我们将创建一个任务列表应用程序，学习如何操作 DOM 以及如何使用 HTML5 Web 存储来保存应用程序的状态。

第二章，“时尚起来”，将展示如何使用新的 CSS3 功能为你的 Web 应用程序添加专业外观的样式，包括圆角、阴影和渐变。我们还将学习如何使用 CSS 精灵使图像加载更加高效。

第三章，“细节决定成败”，将通过向任务列表应用程序添加详细信息部分来教你关于新的 HTML5 表单输入类型。我们还将学习自定义数据属性，并学习如何使用它们将视图中的数据绑定到模型。

第四章，“一块空白画布”，将展示如何使用新的 Canvas 元素和 API 直接在网页上绘制，创建一个绘图应用程序。我们还将学习如何处理来自触摸屏设备的触摸事件。

第五章，“不再是空白画布”，将继续教授有关画布的知识，向你展示如何使用新的文件 API 从画布中导出图像，并将图像加载到画布中。然后我们将深入到像素级别，学习如何直接操作画布图像数据。

第六章，*Piano Man*，将教你如何使用音频元素和 API 在网页中播放声音。我们将创建一个虚拟钢琴，在点击键时播放声音。

第七章，*Piano Hero*，将把前一章的虚拟钢琴变成一个游戏，玩家必须在正确的时间弹奏正确的音符以获得积分。在这个过程中，我们将学习如何使用 JavaScript 定时器和动画元素。

第八章，*A Change in the Weather*，将向你展示如何从服务器获取数据并使用 Ajax 与 Web 服务通信。我们将构建一个天气小部件，使用地理位置 API 获取用户的位置，并显示来自 Web 服务的本地天气报告。

第九章，*Web Workers Unite*，将教你如何使用 HTML5 web workers 在单独的线程中执行长时间运行的进程，以使你的应用程序更具响应性。我们将创建一个应用程序，使用 web worker 在画布上绘制 Mandelbrot 分形。

第十章，*Releasing an App into the Wild*，将教你如何在发布应用程序到世界之前使用 JavaScript 压缩器来合并和压缩应用程序的 JavaScript 文件。我们还将学习如何使用 HTML5 应用程序缓存创建可以离线使用的应用程序。

# 本书所需的内容

HTML5 的好处在于使用它是没有成本的。你不需要任何特殊的工具或许可证来开发 Web 应用程序。然而，使用一个好的代码编辑器会对你有所帮助，特别是在刚开始的时候。没有什么比自动建议更能帮助你记住 JavaScript 函数、元素名称和样式选项。而语法高亮对于使代码更易于阅读是至关重要的。

也就是说，如果你还没有一个源代码编辑器，我可以建议几个。Notepad++是一个免费的编辑器，具有 JavaScript、HTML 和 CSS 语法高亮显示和一些基本的自动建议，没有太多的开销。我用它来写这本书中的所有代码。在高端，Microsoft Visual Studio 提供非常好的自动建议功能，但比基本文本编辑器的开销更大。另一个很好的选择是 NetBeans，一个用 Java 编写的开源 IDE，具有良好的 Web 开发支持。

你还需要一个支持 HTML5 的 Web 浏览器和开发者工具。大多数浏览器的最新版本都支持本书中使用的 HTML5 功能。你使用的浏览器应该取决于你最喜欢的开发者工具。我使用 Chrome，因为它内置了很棒的开发者工具。安装了 Firebug 插件的 Firefox 也非常好。在这本书中，我使用 Chrome 作为首选的浏览器。Internet Explorer 9 并不完全支持我们将要学习的所有 HTML5 功能，而且开发者工具也不如其他浏览器好，所以我建议不要用它进行开发。

你可能还需要一个像 IIS 或 Apache 这样的 Web 服务器。在开发时，大多数情况下你可以直接从文件系统中打开你的 Web 应用程序。然而，一些 HTML5 功能只能通过 Web 服务器工作。我已经在本书中指出了这种情况。

# 这本书适合谁

这本书是为那些在其他语言有经验并想要开始编写 HTML5 Web 应用程序的程序员而写的。您应该对 HTML、CSS 和 JavaScript 有一些基本的了解。例如，您应该知道如何编写简单的 HTML 文档。您还应该了解如何使用 CSS 选择器的基础知识，因为它们对于使用 jQuery 很重要。您不需要知道如何使用 jQuery，因为本书将简要介绍基础知识，但这可能会有所帮助。只要您能理解并编写简单的 JavaScript 代码，那就足以让您开始了。我们将从基础知识开始，通过大量示例逐步深入。

# 约定

在本书中，您会经常看到几个标题。

为了清晰地说明如何完成一个过程或任务，我们使用：

# 行动时间 - 标题

1.  行动 1

1.  行动 2

1.  行动 3

说明通常需要一些额外的解释，以便理解，因此它们后面跟着：

## *刚刚发生了什么？*

这个标题解释了您刚刚完成的任务或说明的工作原理。

您还会在书中找到其他一些学习辅助工具，包括：

## 小测验 - 标题

这些是旨在帮助您测试自己理解的简短的多项选择题。

## 试试看 - 标题

这些实际挑战为您提供了尝试所学内容的想法。

您还会发现一些文本样式，用于区分不同类型的信息。以下是一些这些样式的示例，以及它们的含义解释。

文本中的代码单词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下："接下来，我们将向`Canvas2D`对象添加一个`drawText()`方法。"

代码块设置如下：

```html
this.drawText = function(text, point, fill)
{
    if (fill)
    {
        context.fillText(text, point.x, point.y);
    }
    else
    {
        context.strokeText(text, point.x, point.y);
    }
};
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目会以粗体显示：

```html
switch (action.tool)
{
    // code not shown...
    case "text":
 canvas2d.drawText(action.text, action.points[0],
 action.fill);
 break;
}
```

**新** **术语**和**重要** **单词**以粗体显示。您在屏幕上看到的单词，比如菜单或对话框中的单词，会以这样的方式出现在文本中："当单击**保存**按钮时，它将获取数据 URL，然后打开它。"

### 注意

警告或重要说明会以这样的方式出现在一个框中。

### 提示

技巧和窍门会以这种方式出现。


# 第一章：手头的任务

> “我渴望完成一项伟大而崇高的任务，但我的首要任务是完成小任务，就像它们是伟大而崇高的一样。”
> 
> - 海伦·凯勒

*在本章中，我们将学习创建 HTML5 应用程序的基础知识。我们将创建一个应用程序模板，用作快速构建新应用程序的起点，并且付出最小的努力。然后，我们将使用该模板创建一个简单的任务列表应用程序。在此过程中，我们将发现如何与用户交互并操作应用程序的用户界面。我们还将了解我们的第一个新 HTML5 功能，Web 存储 API。*

在本章中，我们将学习：

+   HTML5 应用程序的三个基本组件，HTML，CSS 和 JavaScript

+   对于那些不熟悉 JavaScript 库的 jQuery 基础知识

+   如何初始化应用程序并处理用户交互

+   如何操作 DOM 以添加、删除、更改和移动元素

+   如何创建可重用的 HTML 模板

+   如何使用 HTML5 Web 存储 API 存储和检索应用程序的状态

# HTML5 应用程序的组件

在开始构建我们的第一个应用程序之前，我们需要了解一些 HTML5 应用程序基础知识。HTML5 应用程序类似于使用任何其他编程语言编写的应用程序。在我们开始进行有趣的部分之前，需要放置一定数量的基础设施和管道。

当涉及到搭建项目时，Web 应用程序非常好。您可以每次开始新应用程序时都从头开始。但是随着您编写越来越多的应用程序，您会注意到每次开始时都在做相同的基本事情，因此创建应用程序模板以快速启动而不必每次重新发明轮子是有意义的。

为了了解 HTML5 应用程序是如何构建的，我们将从头开始构建自己的应用程序模板，我们可以在创建新应用程序时使用。我们将使用此模板作为本书中构建的所有应用程序的基础。

每个 Web 应用程序都以三个组件开始：HTML，CSS 和 JavaScript。您可以将它们全部放在一个文件中，对于非常简单的应用程序可能是可以接受的，但是我们在这里学习如何构建真正的应用程序。因此，我们将首先创建三个文件，每个组件一个文件，并将它们放在名为`template`的文件夹中。它们将被命名为`app.html`，`app.css`和`app.js`。

以下图表是对 HTML5 应用程序及其组件的解释。我们的应用程序是建立在 HTML，CSS 和 JavaScript 之上的。这些又建立在 CSS3 和 HTML5 框架之上，其中包括新的标记元素和 JavaScript API。

![HTML5 应用程序的组件](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-webapp-dev-ex/img/5947OT_01_05.jpg)

让我们看看我们应用程序的文件夹结构。我们将把我们创建的所有文件放在应用程序文件夹的根目录下。我们还将添加一个名为`lib`的文件夹，其中包含应用程序可能需要的任何第三方 JavaScript 库。由于我们将始终使用 jQuery 库，因此我们将在其中放置一个副本。如果有任何其他资产，例如图像或音频文件，我们将分别将它们放在`images`和`audio`文件夹中：

![HTML5 应用程序的组件](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-webapp-dev-ex/img/5947OT_01_02.jpg)

### 注意

我们可以从在线内容交付网络（CDN）引用 jQuery 库，但这要求您始终具有互联网连接。相信我，您永远不知道何时会在某个地方结束而无法连接并发现无法完成任何工作。

# 行动时间-创建 HTML 文件

我们将构建的第一个组件是我们的基本 HTML 文件`app.html`。我们将尽可能保持我们的 HTML 干净。它应该只包含标记。不应该混入任何样式或脚本块。保持标记、样式和行为分开将使您的应用程序更容易调试和维护。例如，如果某些东西的外观有问题，我们将知道问题在 CSS 文件中而不是 JavaScript 文件中。另一个好处是，您可以通过更改 CSS 完全重新设计应用程序的用户界面，而不必触及其功能。

这是我们基本 HTML 文件的标记。它只包括我们的 CSS 和 JavaScript 以及 jQuery 库，并定义了大多数应用程序将使用的简单 body 结构。这是我们将要编写的应用程序的一个很好的起点。

```html
<!DOCTYPE html>
<html>
  <head>
    <title>App</title>
    <link href="app.css" rel="StyleSheet" />
    <script src="img/jquery-1.8.1.min.js"></script>
    <script src="img/app.js"></script>
  </head>
  <body>
    <div id="app">
      <header>App</header>
      <div id="main"></div>
      <footer></footer>
    </div>
  </body>
</html>
```

### 提示

**下载示例代码**

您可以从您在[`www.packtpub.com`](http://www.packtpub.com)的帐户中下载您购买的所有 Packt 图书的示例代码文件。如果您在其他地方购买了本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，以便直接通过电子邮件接收文件。

HTML5 标记和以前版本的 HTML 之间的一个主要区别是文档类型声明已经大大简化。正如你可能记得的那样，HTML5 之前的文档类型声明非常冗长，普通人根本记不住。它们看起来像这样：

```html
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
```

现在让我们来看看新的改进的 HTML5 文档类型声明。它简单、优雅，最重要的是易于记忆：

```html
<!DOCTYPE html>
```

您可能注意到的另一个区别是`<header>`和`<footer>`元素。这些是 HTML5 中的新语义元素，本质上与`<div>`元素相同。HTML5 实际上有一整套新的语义元素，旨在为 HTML 标记提供比仅仅将所有内容包装在`<div>`标记中更多的含义。

由于我们在这里构建的是应用程序，而不是编写内容页面，我们不会过多关注这些语义元素。大多数时候，我们将使用普通的`<div>`元素。但为了让您熟悉它们，这里是一些最有用的新语义元素的概述：

+   `<article>`：定义文档中的一篇文章

+   `<aside>`：定义页面内容以外的内容

+   `<footer>`：定义文档中某个部分的页脚

+   `<header>`：定义文档中某个部分的标题

+   `<nav>`：包含页面导航链接

+   `<section>`：定义文档中的一个部分

在 HTML5 中，以前版本的 HTML 中存在的一些元素和属性现在已经不再存在。这些主要是与布局和字体有关的元素，包括`<big>`、`<center>`、`<font>`、`<strike>`和`<u>`。过时的元素，如`<frame>`和`<applet>`也已经淘汰。

现在让我们来看看我们标记中`<body>`元素的内容。首先是一个`<div id=`"`app`"`>`元素。这将包装应用程序的整个标记。其他标记，如站点导航或与应用程序无关的任何其他内容，可以放在此元素之外。

在`app`元素内部，我们还有三个元素。在这里，我们使用了一些新的语义元素。首先，我们在应用程序中有一个`<header>`元素，它将包含应用程序的名称，比如标题栏（不要与文档`<head>`部分中的`<title>`元素混淆）。`<div id=`"`main`"`>`元素是应用程序主要部分的标记所在的地方。我们在它下面添加一个`<footer>`元素，它将被用作状态栏来显示应用程序的状态。

# 行动时间-创建 CSS 文件

接下来我们将创建名为`app.css`的基本 CSS 文件。这将包含所有应用程序将使用的基本样式，如默认字体和颜色。CSS 文件的第一部分包含一些文档范围的元素样式，设置了基本的外观和感觉。

```html
body
{
    font: 1em Verdana, Geneva, sans-serif;
    padding: 0;
    margin: 5px;
    color: Black;
    background-color: WhiteSmoke;
}
div
{
    padding: 0;
    margin: 0;
}
button
{
    cursor: pointer;
}
.hidden
{
    display: none;
}
```

首先，我们设置要应用于 body 的样式，这将传递到其他元素。我喜欢将字体大小设置为`1em`，而不是固定的像素大小，这样它就会使用浏览器的默认字体大小。然后，您可以使用 em 或百分比基于此进行其他测量，以便为您提供更具反应性的布局，并使以后更改应用程序外观更容易。当您始终需要某些东西保持相同大小时，常数像素大小很好，或者用于边框和边距等小值。

### 注意

通常，在大多数浏览器中，默认情况下 1em 等于 16px。

接下来，我们确保所有`div`元素的填充和边距都被移除，所以我们将它们归零。当用户悬停在按钮上时，将光标更改为指针也是很好的，所以我们也会在这里设置。最后，有一个`.hidden`类选择器，可以添加到任何元素中，以将其隐藏不显示。

我们将用一些样式来完成 CSS 的`app`和`main`元素。在这一点上，我们所设置的只是边距、填充和颜色：

```html
#app
{
    margin: 4px;
    background-color: #bbc;
}
#app>header
{
    padding: 0 0.5em;
    font-size: 1.5em;
    color: WhiteSmoke;
    background-color: #006;
}
#app>footer
{
    padding: 0.25em;
    color: WhiteSmoke;
    background-color: #006;
}
#main
{
    margin: 1em;
}
```

# 行动时间-创建 JavaScript 文件

让我们继续进行 JavaScript 文件`app.js`。在这里，我们将为我们的应用程序模板勾画出一个基本的轮廓。如果您不知道美元符号是用来做什么的，它们是 jQuery 库的别名。我们将在一会儿讨论一些 jQuery 基础知识。

```html
"use strict";

function MyApp()
{
    var version = "v1.0";

    function setStatus(message)
    {
        $("#app>footer").text(message);
    }

    this.start = function()
    {
        $("#app>header").append(version);
        setStatus("ready");
    };
}
```

从顶部开始，我们将在我们的 JavaScript 文件中包含`"use strict"`。这通知 JavaScript 运行时在运行我们的代码时使用更新和更严格的标准。例如，在旧版本的 JavaScript 中，完全可以在不使用`var`关键字先声明变量名的情况下使用它。这会导致它成为附加到`window`对象的全局变量。当定义`"use strict"`时，如果尝试这样做，将会收到错误。它可以帮助您找到可能导致程序中出现错误的糟糕编码错误。

### 注意

如果您使用一些不适用于严格模式的较旧的 JavaScript 库，可以在函数声明中添加`"use strict"`，以使仅该代码块使用严格模式。

```html
function strict()
{
    "use strict";
    // Everything inside here will use strict
// mode
}
```

接下来我们定义主应用程序对象`myApp`。在 JavaScript 中，有许多定义对象的方法，包括使用对象字面量和构造函数。对象字面量是定义对象的最简单方法，但这些对象通常在 JavaScript 加载后立即创建，通常在 DOM 准备就绪之前。以下是我们的对象作为对象字面量的样子：

```html
var myApp = {
    version: "v1.0",
    setStatus: function(message)
    {
        $("#app>footer").text(message);
    },
    start: function()
    {
        $("#app>header").append(this.version);
        this.setStatus("ready");
    };
};
```

由于我们的应用程序正在操作文档对象模型（DOM），我们不希望在 DOM 准备就绪之前创建对象。这就是为什么我们将使用函数构造函数形式来创建对象。

**DOM**，或**文档对象模型**，是 HTML 标记的内部表示。它是一个对象的分层树，表示 HTML 元素。

使用对象字面量的另一个问题是，其中定义的所有内容都是对象的成员，因此必须使用`this`关键字访问。请注意，在前面的对象字面量形式中，我们必须使用`this`来访问`version`和`setStatus()`。然而，当使用构造函数创建对象时，我们可以在构造函数中定义函数和变量，而不使它们成为对象的成员。由于它们不是成员，您不必使用`this`关键字来访问它们。

那么使用`this`有什么问题呢？在您使用 JavaScript 编程一段时间后，您会意识到`this`关键字可能会引起很多混乱，因为它在不同的时间可能会有不同的含义。在其他语言中，比如 C#和 Java，`this`总是指向您所在的对象。在 JavaScript 中，`this`是指向调用函数的对象的指针，对于事件处理程序来说，通常是`window`对象。因此，我们尽量避免使用它，越少用越好。

使用构造函数的另一个优点是能够定义私有和公共方法。请注意，`setStatus()`方法是使用普通函数声明定义的。这将使它成为一个私有方法，只能从封闭它的对象内部访问，并且不需要使用`this`来调用它。另一方面，`start()`方法是使用`this`分配给对象的。这将使`start()`成为一个公共方法，只能从对象的实例中访问。我们将在整个 JavaScript 中使用这种范式来实现对象的私有和公共成员。

我们需要的最后一件事是一个文档准备好的事件处理程序。文档准备好的事件在页面加载完成并且 DOM 层次结构已完全构建后触发。使用 jQuery 添加此事件处理程序有两种方法。第一种更冗长的方式是您所期望的：

```html
$(document).ready(handler);
```

然而，由于它可能是您需要实现的最基本和重要的事件，jQuery 提供了一种简写形式，就是这么简单：

```html
$(handler);
```

这是我们的文档准备好的事件处理程序：

```html
$(function() {
    window.app = new MyApp();
    window.app.start();
});
```

这是一个重要的代码片段。它定义了我们应用程序的起点。它相当于其他语言（如 C、C++、C#和 Java）中的`main()`函数。

在这里，我们创建了我们的主应用程序对象的一个实例，然后将其分配给一个名为`app`的全局变量，通过将其附加到`window`对象。我们将它设置为`global`，这样它就可以在整个应用程序中访问。最后但同样重要的是，我们调用我们的应用程序对象的`start()`方法来启动应用程序。

## 发生了什么？

我们刚刚创建了一个模板，可以用来开始编写新的应用程序，启动时间最短。它由 HTML、CSS 和 JavaScript 文件组成。在这一点上，我们的模板已经完成，我们已经拥有了开始编写新的 HTML5 应用程序所需的基础知识。

## 美元符号标识符

您可能已经注意到我们的 JavaScript 代码中到处都是美元符号。美元符号只不过是 jQuery 对象的别名。您可以用 jQuery 替换所有美元符号，效果是一样的，只是要多输入一些。如果您已经了解 jQuery，您可能想要跳过。否则，我将简要概述一下 jQuery。

jQuery 是一个流行的 JavaScript 库，它在最基本的层面上提供了访问和操作 DOM 的功能。它还提供了许多其他有用的功能，如事件处理、动画和 AJAX 支持。此外，它隐藏了许多不同浏览器之间的差异，因此您可以专注于编程，而不是如何使您的代码在每个浏览器中都能正常工作。它使编写 JavaScript 应用程序变得可忍受，甚至可以说是有趣的。我不会想在没有它的情况下编写 HTML5 应用程序。它对 JavaScript 来说就像 System 库对 Java 和 C#一样。

在大多数情况下，jQuery 使用与 CSS 相同的查询语法来选择元素。典型的模式是选择一个或多个元素，然后对它们执行某些操作，或者从中检索数据。因此，例如，这是一个 jQuery 选择，用于获取 DOM 中的所有`div`元素：

```html
$("div")
```

以下查询将给出具有 ID 为`main`的元素：

```html
$("#main")
```

与 CSS 一样，井号选择具有特定 ID 的元素，点选择具有特定类的元素。您还可以使用复合搜索条件。下一个查询将返回所有具有 ID 为`main`的元素的后代，并具有`selected`类的元素：

```html
$(#main .selected")
```

在选择了一个或多个元素之后，您可以对它们执行一些操作。jQuery 选择返回一个类似数组的 jQuery 对象，但也有很多内置函数可以做各种事情，我们将在本书中逐步学习。例如，以下代码行将隐藏从前一个选择返回的所有元素（将它们的 CSS `display`属性设置为`none`）：

```html
$(#main .selected").hide()
```

简单而强大。那么美元符号到底是怎么回事呢？有些人认为这是 jQuery 可以使用美元符号作为别名的一种魔法。但显然，美元符号是 JavaScript 中一个有效的字符，可以作为变量或函数名称的开头。

# 创建我们的第一个应用程序

在本章和接下来的几章中，我们将构建一个使用 HTML5 和 CSS3 的任务列表应用程序。在开始之前，我们应该明确我们应用程序的规格，这样我们就知道我们想要构建什么。

+   我们的任务列表应用程序应该允许用户快速输入一个或多个任务名称，并在列表中显示它们。

+   用户应该能够通过编辑、删除或上下移动任务来轻松操作任务。

+   应用程序应该记住输入的任务，所以当用户回到应用程序时，他们可以继续之前的工作。

+   UI 应该是响应式的，这样它可以在许多不同的设备上使用，具有不同的屏幕尺寸。

+   我们将从简单的开始，并随着进展逐步构建。在整个过程中，我们将构建一些 JavaScript 库，可以在后续项目中使用，这样我们就可以快速上手。

# 行动时间-创建任务列表

现在我们已经掌握了基础知识，让我们开始任务列表应用程序。我们将称我们的应用程序为`Task at Hand`，或者`Task@Hand`以时髦一点。首先复制我们的模板文件夹，并将其重命名为`taskAtHand`。还要将`.html`、`.css`和`.js`文件重命名为`taskAtHand`。现在我们准备开始我们的第一个 HTML5 应用程序。您可以在`第一章/示例 1.1`中找到本节的代码。

我们需要做的第一件事是进入 HTML 文件，并在`<head>`元素中更改标题和 CSS 和 JS 文件的名称为`taskAtHand`：

```html
<head>
  <title>Task@Hand</title>
  <link href="taskAtHand.css" rel="StyleSheet" />
  <script src="img/jquery-1.8.1.min.js"></script>
  <script src="img/strong>"></script>
</head>
```

接下来我们转到 body。首先我们在`<header>`元素中更改应用程序的名称。然后进入`<div id=`"`app`"`>`元素，并添加一个文本输入字段，用户可以在其中输入任务的名称。最后，我们添加一个空列表来保存我们的任务列表。因为我们正在构建一个列表，所以我们将使用无序列表`<ul>`元素。

```html
<body>
  <div id="app">
    <header>Task@Hand</header>
    <div id="main">
      <div id="add-task">
        <label for="new-task-name">Add a task</label>
        <input type="text" id="new-task-name" title="Enter a task name" placeholder="Enter a task name"/>
      </div>
      <ul id="task-list">
      </ul>
    </div>
    <footer>
    </footer>
  </div>
</body>
```

这是我们现在需要的所有标记。这里有一件事要指出，这是 HTML5 中的新内容。输入元素有一个新的属性叫做`placeholder`，它会在用户开始输入之前在字段中显示一些文本。这给用户一个提示，告诉他们应该在字段中输入什么。这对允许用户输入文本的输入元素是有效的。

让我们进入 JavaScript 文件并开始编码。我们要做的第一件事是将应用程序对象重命名为`TaskAtHandApp`：

```html
function TaskAtHandApp()
{
    // code not shown…
}
$(function() {
    window.app = new TaskAtHandApp();
    window.app.start();
});
```

### 注意

在 JavaScript 中的一个标准是，只有需要一个新语句（即对象构造函数）的东西才应该以大写字母开头。这有助于区分需要使用`new`关键字创建的内容。其他所有内容，包括变量和函数名称，都应该以小写字母开头。

当用户输入完任务名称并按下*Enter*键时，我们希望创建一个新的列表项元素并将其添加到列表中。我们首先需要在文本字段中添加一个事件处理程序，以便在按下键时得到通知。我们将在应用程序对象的`start()`方法中添加这个。

```html
this.start = function()
{
    $("#new-task-name").keypress(function(e) {
        if (e.which == 13) // Enter key
        {
            addTask();
            return false;
        }
    })
    .focus();

    $("#app header").append(version);
    setStatus("ready");
};
```

首先，我们通过对其 ID 进行 jQuery 选择来获取文本字段，即`new-task-name`。然后，我们向该元素添加一个`keypress()`事件处理程序，传入一个函数，以便在每次触发事件时执行。jQuery 向事件处理程序函数传递一个参数，即`keypress`事件对象。事件对象包含一个名为`which`的字段，其中包含按下的键的字符代码。我们感兴趣的是*Enter*键，它的代码是`13`。

当用户按下*Enter*键时，我们调用`addTask()`方法（下面定义），然后它返回`false`。我们在这里返回`false`的原因是告诉系统我们处理了按键事件，并且不希望它执行默认操作。一些浏览器在按下*Enter*键时会执行其他操作。

接下来，我们在`keypress()`处理程序的末尾添加另一个函数调用，将焦点设置回文本字段。此时，您可能会问自己，这是如何工作的，调用一个函数的函数？这称为函数链接，可能是 jQuery 最有用的功能之一。jQuery 的大多数方法都返回对象本身的指针，因此我们可以在一行代码中执行多个操作。

现在我们将编写`addTask()`方法。此方法将获取任务的名称，并将新的列表项添加到我们 HTML 中的`<ul>`元素中：

```html
function addTask()
{
    var taskName = $("#new-task-name").val();
    if (taskName)
    {
        addTaskElement(taskName);
        // Reset the text field
        $("#new-task-name").val("").focus();
    }
}
function addTaskElement(taskName)
{
    var $task = $("<li></li>");
    $task.text(taskName);
    $("#task-list").append($task);
}
```

首先，我们使用 jQuery 的`val()`方法获取`new-task-name`文本字段的值，该方法用于获取输入字段的值。只是为了确保用户实际输入了内容，我们测试`taskName`变量是否为"真值"，在这种情况下意味着它不是空字符串。

接下来我们调用`addTaskElement()`方法。在那里，我们创建一个新的`<li>`元素。您可以通过传入元素定义而不是选择到 jQuery 来创建一个新元素。在这种情况下，我们使用`"<li></li>"`来创建一个新的空列表项元素，然后将其分配给`$task`变量。然后，我们立即使用`text()`方法填充该元素的任务名称。

### 注意

将 jQuery 对象分配给变量时，最好的做法是以`$`开头的变量名，这样您就知道它引用了一个 jQuery 对象。

现在我们有了新元素，我们需要将其添加到文档的正确位置，即`<ul id=`"`task-list`"`>`元素内。这是通过选择`task-list`元素并调用`append()`方法来完成的。这将我们的新`<li>`元素添加到任务列表的末尾。

我们在`addTask()`方法中做的最后一件事是清除文本输入字段的值，并将焦点重新设置在它上面，以便用户可以立即输入另一个任务。我们在这里使用函数链接来在一条语句中完成两个操作。请注意，我们在设置和获取文本字段的值时都使用了 jQuery 的`val()`方法。如果传入一个值，它会设置控件的值；否则，它会返回控件的值。您会发现很多 jQuery 方法都是这样工作的。例如，`text()`方法将在元素内设置文本，或者如果没有传入值，则返回文本。

## *刚刚发生了什么？*

我们创建了一个任务列表应用程序，用户可以在其中输入任务名称并构建任务列表。让我们在浏览器中打开应用程序，看看我们目前有什么：

![刚刚发生了什么？](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-webapp-dev-ex/img/5947OT_01_04.jpg)

# 行动时间-从列表中删除任务

现在我们可以向列表中添加任务了，让我们添加删除任务的功能。为此，我们需要为列表中的每个任务添加一个删除按钮。我们将在`addTaskElement()`方法中添加创建按钮的代码。您可以在`第一章/example1.2`中找到此部分的代码。

```html
function addTaskElement(taskName)
{
    var $task = $("<li></li>");
    var $delete = $("<button class='delete'>X</button>");
    $task.append($delete)
         .append("<span class='task-name'>" + taskName +
                 "</span>"); 
    $delete.click(function() { $task.remove(); });
}
```

这个方法的第一件事是创建一个带有`delete`类的新`<button>`元素。然后，它创建了列表项元素，就像我们之前做的那样，只是首先附加了删除按钮，然后附加了任务名称。请注意，我们现在将任务名称包装在一个`<span class=`'`task-name`'`>`元素中，以帮助我们跟踪它。最后，我们为删除按钮添加了一个点击事件处理程序。要从列表元素中删除任务，我们只需调用`remove()`方法将其从 DOM 中删除。哇，它就消失了！

# 行动时间-在列表中移动任务

顺便说一句，让我们为列表中的任务添加上移和下移按钮。为此，我们将向`addTaskElement()`方法添加一些代码。首先，我们需要创建`move-up`和`move-down`按钮，然后将它们与`delete`按钮一起添加到列表元素中。

```html
function addTaskElement(taskName)
{
    var $task = $("<li></li>");
    var $delete = $("<button class='delete'>X</button>");
    var $moveUp = $("<button class='move-up'>^</button>");
    var $moveDown = $("<button class='move-up'>v</button>");
    $task.append($delete)
        .append($moveUp)
        .append($moveDown)
        .append("<span class='task-name'>" + taskName +
                "</span>");
    $("#task-list").append($task);

    $delete.click(function() { $task.remove(); });
    $moveUp.click(function() {
        $task.insertBefore($task.prev());
    });
    $moveDown.click(function() {
        $task.insertAfter($task.next());
    });
}
```

当单击**向上移动**或**向下移动**按钮时，它使用`prev()`和`next()`方法找到前一个或下一个任务元素。然后它使用 jQuery 的`insertBefore()`和`insertAfter()`方法将任务元素向上或向下移动到任务列表中。

## *刚刚发生了什么？*

我们为每个任务元素添加了按钮，以便可以删除它们或将它们上下移动到列表的顺序中。我们学会了如何使用 jQuery 的`remove()`、`insertBefore()`和`insertAfter()`方法来修改 DOM。

# HTML 模板

正如您所看到的，我们的`addTaskElement()`方法有点混乱。我们在 JavaScript 中以编程方式创建了一堆元素，并手动将它们添加到 DOM 中。如果我们只需在 HTML 文件中定义任务元素的结构，并使用它来创建新任务，那不是更容易吗？好吧，我们可以，而且我们将这样做。在本节中，我们将创建一个 HTML 模板，以便轻松创建新任务。

### 注意

有很多 JavaScript 库可以用来实现 HTML 模板，它们具有很多强大的功能，但对于我们的应用程序，我们只需要一些简单的东西，所以我们将自己实现。

# 行动时间-实施模板

首先，我们需要一个放置模板标记的地方。因此，我们将在 HTML 文件中的`app`元素之外添加一个`<div id="templates">`，并给它一个`hidden`类。正如您可能还记得的，从我们的 CSS 中，`hidden`类为元素设置`display`为`none`。这将隐藏模板标记，使用户永远看不到它。现在让我们定义模板：

```html
<div id="app">
  …
</div>
<div id="templates" class="hidden">
 <ul id="task-template">
 <li class="task">
 <div class="tools">
 <button class="delete" title="Delete">X</button>
 <button class="move-up" title="Up">^</button>
 <button class="move-down" title="Down">v</button>
 </div>
 <span class="task-name"></span>
 </li>
 </ul>
</div>
```

我不知道你怎么想，但对我来说，这比在代码中构建任务元素要容易得多。这样做也更容易阅读、添加和维护。你可能已经注意到，还添加了一些其他元素和属性，如果要以编程方式添加，那将是非常痛苦的。在按钮周围放置了一个`<div class="tools">`，将它们组合在一起，并为每个按钮添加了一个`title`属性，它将显示为浏览器中的工具提示。

请注意，我们在任务元素中没有使用任何 ID 属性。相反，我们使用类属性来标识不同的元素。这样做的原因是，ID 唯一地标识一个元素，因此它应该只被使用一次。如果我们创建一个具有一堆 ID 的模板并开始复制它，我们将会有重复的 ID。如果您多次使用 ID，那么 ID 对于唯一标识元素就毫无价值了。

在继续之前，我们需要为按钮及其容器在 CSS 中添加一些样式。我们希望按钮保持与任务名称在同一行，但它们的容器`<div>`是一个块级元素。让我们将它更改为`inline-block`，这样它就不会断行：

```html
#task-list .task .tools
{
    display: inline-block;
}
```

我们还希望从按钮中移除边框，使它们都是相同的大小，并移除填充和边距，使其更加紧凑：

```html
#task-list .task .tools button
{
    margin: 0;
    padding: 0;
    width: 1.25em;
    height: 1.25em;
    border: none;
}
```

所以，现在我们有了一个任务模板，我们该怎么办呢？这里再次用到了 jQuery。我们所要做的就是获取模板元素，并使用`clone()`方法来复制它。然后将复制的内容插入到 DOM 中的任何位置。下面是我们新的`addTaskElement()`方法的样子：

```html
function addTaskElement(taskName)
{
    var $task = $("#task-template .task").clone();
 $("span.task-name", $task).text(taskName);

    $("#task-list").append($task);

    $("button.delete", $task).click(function() {
        $task.remove();
    });
    $("button.move-up", $task).click(function() { 
        $task.insertBefore($task.prev());
    });
    $("button.move-down", $task).click(function() {
        $task.insertAfter($task.next());
    });
}
```

我们用一行代码替换了所有创建元素的代码行，它获取了任务模板元素，并使用`clone()`方法对其进行复制。第二行将任务名称填入了我们设置好的`<span class="task-name">`元素中。如果你仔细看，你会发现我们现在在选择时向 jQuery 传递了第二个参数。这告诉 jQuery 只搜索`task`元素的后代元素。否则它会在整个文档中找到每个任务名称元素并更改它们。在选择按钮时，我们也是用相同的方法来识别它们，使用它们的类名来连接点击事件处理程序。

## *刚刚发生了什么？*

我们实现了一个 HTML 模板，允许我们删除所有动态生成任务元素的代码，并用 jQuery 的`clone()`方法来替换它。这使得我们更容易在 HTML 中更新和维护元素结构，而不是在 JavaScript 中。

# 行动时间-编辑列表中的任务

到目前为止，我们有一个任务列表，可以向其中添加任务，从中删除任务，并更改任务的顺序。让我们添加一些功能，允许用户更改任务的名称。当用户点击任务名称时，我们将把它更改为文本输入字段。为此，我们需要在任务元素模板中的任务名称后面添加一个文本输入字段：

```html
<li class="task">
    <div class="tools">
        <button class="delete" title="Delete">X</button>
        <button class="move-up" title="Up">^</button>
        <button class="move-down" title="Down">v</button>
    </div>
    <span class="task-name"></span>
    <input type="text" class="task-name hidden"/>
</li>
```

我们给它一个`task-name`的类来标识它，并且还添加了隐藏类，所以默认情况下它是不可见的。我们只想在用户点击任务名称时显示它。所以让我们进入 JavaScript 文件，并在`addTaskElement()`方法的末尾添加一个`<span>`元素的事件处理程序：

```html
$("span.task-name", $task).click(function() {
    onEditTaskName($(this));
});
```

让我们来分解一下。首先，我们获取了任务元素的子元素，类名为`task-name`的 span。然后，我们添加了一个点击事件处理程序，调用`onEditTaskName()`方法。`onEditTaskName()`方法以`<span>`元素的引用作为参数。当你在 jQuery 事件处理程序函数中时，`this`指的是事件的源元素。因此，`$`(`this`)创建了一个包装`<span>`元素的 jQuery 对象，这样我们就可以在其上调用 jQuery 方法：

```html
function onEditTaskName($span)
{
    $span.hide()
        .siblings("input.task-name")
        .val($span.text())
        .show()
        .focus();
}
```

尽管`onEditTaskName()`方法在技术上只包含一行代码，但其中发生了很多事情。它使用函数链接在一个紧凑的语句中完成了很多工作。首先，它隐藏了`<span>`元素。然后，它通过查找`<span>`元素的兄弟元素，即类名为`task-name`的`<input>`元素，获取了文本输入字段。然后，它使用 jQuery 的`text()`方法从`<span>`元素中获取任务名称并设置文本字段的值。最后，它使文本字段可见，并将焦点设置在它上面。

当用户点击任务名称时，它似乎会在他们眼前变成一个可编辑的文本字段。现在我们只需要一种方法，在用户完成编辑名称后将其改回来。为此，我们将以下内容添加到`addTaskElement()`方法的末尾：

```html
$("input.task-name", $task).change(function() {
    onChangeTaskName($(this));
});
```

这与任务名称点击事件处理程序的工作方式相同。我们将调用一个名为`onChangeTaskName()`的方法，并传递一个包装文本字段输入元素的 jQuery 对象：

```html
function onChangeTaskName($input)
{
    $input.hide();
    var $span = $input.siblings("span.task-name");
    if ($input.val())
    {
        $span.text($input.val());
    }
    $span.show();
}
```

首先，我们隐藏文本输入字段，然后获取任务名称`<span>`元素并将其存储在一个变量中。在更新名称之前，我们检查用户是否确实输入了内容。如果是，我们就更新任务名称。最后，我们调用`show()`来使任务名称再次可见。用户会看到文本字段再次变成静态文本。

最后还有一件事要做。如果用户在不更改任何内容的情况下点击字段，我们将不会收到更改事件，并且文本字段将不会被隐藏。但是，当发生这种情况时，我们可以获得`blur`事件。因此，让我们向文本字段添加一个`blur`事件处理程序，以隐藏它并显示静态任务名称`<span>`元素：

```html
$("input.task-name", $task).change(function() {
    onChangeTaskName($(this));
})
.blur(function() {
 $(this).hide().siblings("span.task-name").show();
});

```

## *发生了什么？*

我们在任务模板中添加了一个文本字段，当用户点击任务名称时，它会显示出来，以便他们可以编辑任务名称。当任务名称文本字段更改时，它会更新任务名称标签。

发生了什么？

# 保存应用程序的状态

现在我们有一个非常实用的任务列表应用程序。我们可以添加、删除和移动任务。甚至可以编辑现有任务的名称。只有一个问题。由于我们动态向 DOM 添加了所有这些任务元素，所以下次用户返回应用程序时，它们将不会存在。我们需要一种方法来保存任务列表，这样用户下次返回应用程序时，任务仍将存在。否则，这有什么意义呢？

HTML5 刚好有这样的东西-Web Storage。Web Storage 是 HTML5 中的一个新 API，允许您在客户端上存储信息。过去，客户端上唯一可用的存储方式是 cookie。但是 cookie 并不是在客户端存储数据的好方法。它们仅限于几千字节的数据，并且还包含在 HTTP 请求中，增加了它们的大小。

另一方面，Web Storage 允许我们保存更多的数据（在大多数浏览器中最多可达 5MB），并且不会增加 HTTP 请求的内容。它由两个具有相同接口的全局对象组成，`localStorage`和`sessionStorage`。两者之间唯一的区别是存储在`sessionStorage`中的数据在关闭浏览器时会消失，而存储在`localStorage`中的数据不会。由于我们希望在会话之间保存应用程序数据，因此我们只会使用`localStorage`。

数据以键/值对的形式存储。您可以使用`setItem()`方法设置值，并使用`getItem()`检索值，如下所示：

```html
localStorage.setItem("myKey", "myValue");
var value = localStorage.getItem("myKey") // returns "myValue"
```

如果尝试使用在`localStorage`中不存在的键获取值，它将返回`null`。如果尝试向`localStorage`添加值并且内存不足，将会收到`QUOTA_EXCEEDED_ERR`异常。

`localStorage`有一些限制：

+   用户不一定可以访问存储在其中的任何内容（尽管可以通过浏览器的开发人员工具访问）。

+   它由域中的所有应用程序共享，因此存储限制在所有应用程序之间共享。这也意味着在所有应用程序中，所有键都必须是唯一的。如果两个应用程序使用相同的键，它们最终会覆盖彼此的数据。

+   键和值都必须是字符串。如果要存储的内容不是字符串，必须先将其转换为字符串。当您从存储中取出该值时，必须将其从字符串转换回您期望的类型。

幸运的是，JavaScript 有一个叫做 JSON 的实用对象，它提供了将值转换为字符串和从字符串转换回值的函数。**JSON**代表**JavaScript 对象表示法**，是以可读格式表示值的标准。它是 JavaScript 中对象文字表示法的子集，因此如果您知道如何定义对象文字，您就知道 JSON。JSON 对象有两种方法; `JSON.stringify()`将值转换为字符串，`JSON.parse()`将字符串转换回值。

# 行动时间-创建一个 localStorage 包装器

为了帮助解决`localStorage`的一些限制，我们将创建一个名为`AppStorage`的对象，它提供了对`localStorage`对象的包装。`AppStorage`对象将帮助我们避免键冲突，并提供一种简单的方法来存储非字符串值。让我们在一个名为`appStorage.js`的新文件中定义这个对象，这样我们可以在所有应用程序中重用它。您可以在`第一章/示例 1.3`中找到这一部分的代码。

```html
function AppStorage(appName)
{
    var prefix = (appName ? appName + "." : "");
```

构造函数以应用程序名称作为参数。下一行设置了一个名为`prefix`的私有变量，它将用于为所有键添加应用程序名称前缀，以避免冲突。如果未提供`appName`参数，则不会使用前缀，这对于在所有应用程序之间共享数据可能很有用。如果我们将`"myApp"`传递给构造函数，我们应用程序的所有键将以`"myApp"`开头（例如，`myApp.settings`或`myApp.data`）。

这一行创建了一个公共变量，用于确定浏览器是否支持`localStorage`。它只是检查全局`localStorage`对象是否存在：

```html
this.localStorageSupported = (('localStorage' in window) && window['localStorage']);
```

让我们首先实现`setValue()`方法，用于在本地存储中设置值：

```html
this.setValue = function(key, val)
{
    if (this.localStorageSupported)
        localStorage.setItem(prefix + key, JSON.stringify(val));
    return this;
};
```

`setValue()`方法接受一个键和一个要放入本地存储的值。它在键前面添加应用程序前缀，以避免命名冲突。由于您只能将字符串放入本地存储，我们使用`JSON.stringify()`方法将值转换为字符串，然后调用`localStorage.setItem()`进行存储。

现在让我们实现`getValue()`方法来从`localStorage`中获取值：

```html
this.getValue = function(key)
{
    if (this.localStorageSupported)
        return JSON.parse(localStorage.getItem(prefix + key));
    else return null;
};
```

`getValue()`方法接受一个键，将前缀添加到它，并返回与之在`localStorage`中关联的字符串值。它使用`JSON.parse()`将从`localStorage`中检索到的字符串解析为值。如果键不存在或不支持本地存储，这些方法将返回`null`。

我们需要的下一步是删除项目的方法。让我们实现`removeValue()`方法来做到这一点。它只是调用`localStorage.removeItem()`，传入带前缀的键：

```html
this.removeValue = function(key)
{
    if (this.localStorageSupported)
        localStorage.removeItem(prefix + key);
    return this;
};
```

在这个过程中，让我们添加一个方法来删除应用程序的所有键。`localStorage`确实有一个`clear()`方法，但这会完全清空您域中的`localStorage`，而不仅仅是我们应用程序的值。因此，我们需要获取我们应用程序的所有键，然后逐个删除它们：

```html
this.removeAll = function()
{
    var keys = this.getKeys();
    for (var i in keys)
    {
        this.remove(keys[i]);
    }
    return this;
};
```

`removeAll()`方法引用了一个`getKeys()`方法。这个方法将返回应用程序的所有键名数组。我们将制作`getKeys()`方法，这样用户也可以传入一个过滤函数，以便根据自己的标准进一步过滤结果：

```html
this.getKeys = function(filter)
{
    var keys = [];
    if (this.localStorageSupported)
    {
        for (var key in localStorage)
        {
            if (isAppKey(key))
            {
                // Remove the prefix from the key
                if (prefix) key = key.slice(prefix.length);
                // Check the filter
                if (!filter || filter(key))
                {
                    keys.push(key);
                }
            }
        }
    }
    return keys;
};
function isAppKey(key)
{
    if (prefix)
    {
        return key.indexOf(prefix) === 0;
    }
    return true;
};
```

这个方法通过循环遍历`localStorage`中的所有键来工作，你可以通过实现使用`in`关键字的循环来获取对象或数组中的所有键，它调用私有方法`isAppKey()`来确定键是否属于我们的应用程序。如果是，它会从键中移除应用程序前缀。最后，如果没有定义过滤器或过滤器函数返回`true`，则将键添加到要返回的键数组中。

私有的`isAppKey()`方法以键名作为参数，并在键属于我们的应用程序时返回`true`。如果未定义应用程序名称前缀，则没有要检查的内容。否则，我们检查键是否以应用程序前缀开头。

我们需要编写最后一个公共方法。`contains()`方法将确定与键关联的值是否存在。它只是尝试获取与键关联的值并检查是否存在：

```html
this.contains = function(key)
{
    return this.get(key) !== null;
};
```

## *刚发生了什么？*

我们创建了一个名为`AppStorage`的包装对象，它包装了 HTML5`localStorage`对象。它封装了与`localStorage`交互和保存 JavaScript 对象的所有行为。现在我们可以将任何类型的数据保存到`localStorage`中，然后检索它。

# 行动时间-存储任务列表

让我们回到任务列表应用程序。首先在我们的 HTML 文件中添加对`appStorage.js`的引用：

```html
<script src="img/appStorage.js"></script>
```

接下来，我们将在`TaskAtHandApp`对象中添加一个私有的`appStorage`变量，并将应用程序的名称传递给构造函数：

```html
function TaskAtHandApp()
{
    var version = "v1.3",
        appStorage = new AppStorage("taskAtHand");
    //…
}
```

现在让我们添加一个私有方法，可以在每次更改时调用以保存任务：

```html
function saveTaskList()
{
    var tasks = [];
    $("#task-list .task span.task-name").each(function() {
        tasks.push($(this).text())
    });
    appStorage.setValue("taskList", tasks);
}
```

`saveTaskList()`方法查找列表中每个任务的任务名称`<span>`元素。然后调用 jQuery 的`each()`方法，用于迭代由选择找到的元素。`each()`方法接受一个函数作为参数，并为每个元素调用该函数。我们的函数只是将任务名称推送到任务数组的末尾。然后我们调用`appStorage.setValue()`，告诉它使用键`"taskList"`存储任务数组。

现在我们需要在列表更改时每次调用`saveTaskList()`。这将在`addTask()`和`onChangeTaskName()`方法中进行。此外，在`addTaskElement()`中，我们需要在`delete`、`move-up`和`move-down`的按钮点击事件处理程序中调用它。为了使事情更容易阅读，让我们通过将内联处理程序代码移出到私有方法中进行一些重构：

```html
function addTaskElement(taskName)
{
    // code not shown…
    $("button.delete", $task).click(function() {
        removeTask($task);
    });
    $("button.move-up", $task).click(function() {
        moveTask($task, true);
    });
    $("button.move-down", $task).click(function() {
        moveTask($task, false);
    });
    //…
}
function removeTask($task)
{
    $task.remove();
    saveTaskList();
}
function moveTask($task, moveUp)
{
    if (moveUp)
    {
        $task.insertBefore($task.prev());
    }
    else
    {
        $task.insertAfter($task.next());
    }
    saveTaskList();
}
```

现在让我们在 Chrome 中看一下这个。继续添加一些任务，然后按*F12*打开开发者工具。如果您点击窗口顶部的**资源**图标，您将在左窗格中看到资源列表。展开**本地存储**项目，然后单击其下的项目。您应该在右窗格中看到存储在本地存储中的域中的所有数据：

![行动时间-存储任务列表](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-webapp-dev-ex/img/5947OT_01_01.jpg)

在**Key**列中，您应该找到`taskAtHand.taskList`，并在**Value**列中看到代表我们任务列表的 JSON，正如您可能记得的那样，它存储为数组。

现在继续玩一下。尝试添加、删除、编辑和移动任务。您应该在每次更改后看到本地存储中的值更新。我们现在有一个持久的任务列表。

当使用`file://`协议时，一些浏览器不允许访问`localStorage`（也就是说，您直接从文件系统打开文件到浏览器）。如果您的`localStorage`不起作用，请尝试在另一个网络浏览器中使用，或者通过诸如 IIS 或 Apache 之类的网络服务器访问您的应用程序。

# 行动时间-加载任务列表

我们已经保存了任务列表。但如果我们无法加载它，那对我们来说没有太大用处。所以让我们添加一个名为`loadTaskList()`的新私有方法：

```html
function loadTaskList()
{
    var tasks = appStorage.getObject("taskList");
    if (tasks)
    {
        for (var i in tasks)
        {
            addTaskElement(tasks[i]);
        }
    }
}
```

此方法调用`appStorage.getValue()`，传入我们任务列表的键。然后检查确保我们得到了一些东西。如果是这样，它会遍历数组中的所有任务，为每个任务调用`addTaskElement()`方法。

唯一剩下的事情是在`start()`方法中添加一个调用`loadTaskList()`，这样在应用程序启动时加载列表：

```html
this.start = function()
{
    // Code not shown…
    loadTaskList();
    setStatus("ready");
};
```

## *刚才发生了什么？*

在我们的任务列表应用程序中，我们使用`AppStorage`对象将任务列表存储到`localStorage`中，每当有变化时，然后在用户返回时检索它并构建任务列表。

## 尝试一下

编写一个本地存储浏览器应用程序，用于查看域中每个应用程序的数据。在顶层，列出所有应用程序。当您深入到应用程序时，它会显示所有本地存储项。当您单击一个项目时，它会显示该项目的内容。

## 快速测验

Q1\. HTML5 应用程序的三个基本组件是什么？

1.  jQuery、模板和本地存储

1.  文档、对象和模型

1.  标签、元素和属性

1.  HTML、CSS 和 JavaScript

Q2\. 本地存储可以存储哪些类型的数据？

1.  任何类型

1.  对象

1.  数字

1.  字符串

# 总结

就是这样。我们现在已经完成了我们的第一个 HTML5 应用程序。一个任务列表，我们可以添加、删除和编辑任务。任务是持久的，所以当用户返回应用程序时，他们可以从他们离开的地方继续。在本章中，我们涵盖了以下概念：

+   我们学会了构建 HTML5 应用程序及其三个组件，HTML、CSS 和 JS 的基础知识。

+   我们创建了一个应用程序模板，以帮助我们快速启动新应用程序。

+   我们学会了如何使用 jQuery 来访问和操作 DOM。

+   我们学会了如何初始化一个 Web 应用程序并处理用户交互。

+   我们学会了如何创建 HTML 模板，以便我们可以在标记中定义可重用的元素结构。

+   我们学会了如何使用 Web Storage 来保存和检索应用程序的状态，并创建了一个`AppStorage`对象来帮助我们访问`localStorage`。

现在我们已经学会了创建 HTML5 应用程序的基础知识，并且我们的任务列表应用程序正在运行，我们准备开始一些样式设计。在下一章中，我们将学习一些新的 CSS3 功能，这些功能将使我们的应用程序看起来和任何桌面应用程序一样好，甚至更好。


# 第二章：让我们时尚起来

> “在风格问题上，随波逐流；在原则问题上，坚如磐石。”- 托马斯·杰斐逊

*在本章中，我们将戴上我们的平面设计师帽子，进行一些样式设计。现在我们在第一章中创建的任务列表应用程序可以工作，但看起来像是 2005 年的东西。我们将使用 CSS3 使其现代化，并使用最新的 CSS3 功能使其看起来干净、现代。我们将添加圆角、阴影、渐变和过渡效果。我们还将使用 CSS 精灵为任务列表按钮添加一些图像。*

在本章中，我们将学习：

+   在 CSS3 中指定颜色的新方法和设置透明度

+   如何向元素添加圆角

+   如何向元素和文本添加阴影

+   如何在元素背景中绘制渐变

+   新的 CSS3 背景属性

+   如何在应用程序中使用 CSS 精灵

+   如何使用过渡和变换为用户界面添加效果

+   如何动态加载样式表以创建可定制的用户界面

# CSS3 概述

CSS3 不是 HTML5 规范的一部分，但它是编写 HTML5 应用程序的一个重要部分。CSS3 与 HTML5 并行开发，并提供许多新的样式，使网页的外观和功能比以往更好。曾经是 Photoshop 的领域，如渐变和阴影，现在可以通过样式轻松添加。使用这些新的图形功能将使您的应用程序看起来现代，并为您的应用程序增添特色。

CSS 的一些最令人兴奋的新增功能之一是能够向元素添加渐变和阴影。圆角是每个人都希望在网页中拥有的功能，曾经是许多 HTML hack 的领域，现在可以轻松添加。从未有过如此简单地使网页和应用程序看起来好，而无需下载额外的图像和代码来支持它们。

您可以在`chapter2/css3-examples/css3-examples.html`中看到所有以下 CSS3 样式的示例。

## CSS3 颜色

在开始新效果之前，让我们讨论一下颜色。CSS3 有新的定义颜色的方式，允许您设置透明度并以 HSL 格式定义颜色。当然，您仍然可以使用旧的十六进制值标准、任何 CSS 颜色名称和`rgb()`指定符。

已添加了一个新的`rgba()`指定符，允许设置颜色的 alpha 或不透明度。与`rgb()`一样，前三个参数设置红色、绿色和蓝色的数量，取值范围为`0`到`255`。第四个参数 alpha 是一个浮点值，范围从`0`到`1`，其中`0`是完全透明，`1`是完全不透明。以下声明了一个红色背景颜色，透明度为 50%：

```html
background-color: rgba(255, 0, 0, 0.5);
```

尽管大多数浏览器支持`rgba()`，但最好通过在其前面以`rgb()`格式定义颜色来为不支持它的浏览器指定一个回退，如下所示：

```html
background-color: rgb(255, 0, 0);
background-color: rgba(255, 0, 0, 0.5);
```

这是一个重叠三个元素的示例，所有元素的 alpha 值均为`0.5`，颜色分别为红色、绿色和蓝色（是的，您可以绘制圆形元素，我们将在下一节中看到）。

![CSS3 颜色](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-webapp-dev-ex/img/5947_02_06.jpg)

除了 RGB 颜色，CSS3 还支持**HSL**颜色，它代表**色调**、**饱和度**和**亮度**。HSL 基于一个颜色轮，边缘是全彩色，中心渐变为灰色。现在将该轮延伸为一个圆柱体，底部是黑色，顶部是白色，中间是全彩色。这就是 HSL 颜色的理论。

它是使用`hsl(h, s, l)`指定的。色调是从`0`到`360`的值，对应于颜色轮上的角度。`0`是红色，`120`是绿色，`240`是蓝色，`360`又回到红色。饱和度是颜色的百分比，其中`0%`是完全灰色，`100%`是全彩色。亮度是亮度的百分比，其中`0%`是黑色，`50%`是全彩色，`100%`是白色。您可以像`rgb()`一样指定它，也可以不带 alpha 值，如下所示：

```html
hsl(240, 100%, 50%);
hsla(240, 100%, 50%, 0.5);
```

大多数人不会考虑 HSL 中的颜色，但它确实存在，以防您想要使用它。如果您想尝试一下，可以在[`hslpicker.com`](http://hslpicker.com)找到一个不错的 HSL 选择器。

# 圆角

我们将要看的第一个 CSS3 效果是圆角，因为在 CSS3 之前这是一个非常受欢迎的功能。过去，如果您想要圆角，只有一些非最佳的解决方案可用。您可以加载四个图像，每个角一个，然后添加一些额外的标记来使它们对齐（并尝试使其在所有浏览器中工作）。或者使用多个`div`标签来“绘制”圆角边框的某种黑客方式。或者其他半打方法之一。最终，它们都不是很好的解决方案。那么为什么我们要如此努力地在 CSS3 之前使圆角边框起作用呢？因为人们被它们吸引，它们似乎让您的设计看起来更自然。

使用 CSS3 的新`border-radius`属性非常容易地向元素添加圆角。如果您希望每个角具有相同的边框半径，只需给出一个值，如下所示：

```html
border-radius: 0.5em;
```

如果要将边框的每个角设置为不同的半径，也可以这样做。值按照 CSS 属性的标准顺序，顺时针从左上角开始：左上，右上，右下和左下。

```html
border-radius: 1px 4px 8px 12px;
```

您可以设置一个、两个、三个或四个值。一和四是不言自明的。

+   如果设置了两个值，则第一个值适用于左上和右下，第二个值适用于右上和左下。因此，它是相对的角。

+   如果设置了三个值，则第二个值适用于右上和左下。第一个适用于左上，第三个适用于右下。

您还可以单独定义每个角的半径，如下所示：

```html
border-top-left-radius: 1px;
border-top-right-radius: 4px;
border-bottom-right-radius: 8px;
border-bottom-left-radius: 12px;
```

### 注意

想要创建圆形或椭圆形？将`border-radius`值设置为`50%`。

![Rounded corners](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-webapp-dev-ex/img/5947_02_01.jpg)

# 阴影

在 CSS3 中，向元素和文本添加阴影非常简单。使用阴影使某些元素真正脱颖而出，并为您的 UI 赋予更自然的外观。有许多选项可用于添加阴影，例如大小、位置和颜色。阴影不一定总是在元素和文本后面；它们也可以为它们提供框架、突出显示和添加效果。

## 盒子阴影

除了圆角，您还可以使用新的 CSS3 `box-shadow`属性为元素添加阴影。`box-shadow`属性接受一些参数，告诉它如何绘制阴影：

```html
box-shadow: h-offset v-offset blur-radius spread-radius color;
```

以下是参数的解释：

+   `h-offset`：阴影的水平偏移。负值将阴影放在元素的左侧。

+   `v-offset`：阴影的垂直偏移。负值将阴影放在元素上方。

+   `blur-radius`：确定模糊量；数字越高，模糊越多（可选）。

+   `spread-radius`：阴影的大小。如果为零，则与模糊大小相同（可选）。

+   `color`：阴影的颜色（可选）。

+   `inset`：添加`inset`以将阴影从外部更改为内部（可选）。

### 注意

您可以使用`box-shadow`属性为元素添加除阴影之外的一些有趣效果。通过将`offset`值设置为零并调整模糊和扩展（请参见前两个示例），您可以为元素设置内部或外部发光。

![Box shadows](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-webapp-dev-ex/img/5947_02_02.jpg)

## 文本阴影

除了盒子阴影，CSS3 还支持使用`text-shadow`属性添加文本阴影。它的工作方式几乎与`box-shadow`相同，并且使用几乎相同的参数：

```html
text-shadow: h-offset v-offset blur-radius color;
```

与`box-shadow`一样，您可以产生一些有趣的效果，例如发光文本：

![Text shadows](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-webapp-dev-ex/img/5947_02_05.jpg)

# 行动时间-样式行动

让我们在任务列表应用程序中充分利用`border-radius`和`box-shadow`效果。首先，我们将在页面上居中显示任务列表。然后我们将在每个任务周围放一个有圆角和阴影的框。让我们打开`taskAtHand.css`并进行一些更改。您可以在`chapter2/example2.1`中找到此部分的代码。

首先，我们将更改包含`task-name`文本字段和任务列表的`<div id="main">`元素的样式。让我们给这个部分设置一个最小宽度为`9em`，最大宽度为`25em`。我们不希望任务列表变得太宽或太小，以便更容易阅读。这将为我们提供一个反应式布局的开端。我们还将将上下边距设置为`1em`，将左右边距设置为`auto`以使其在页面上居中。

### 注意

一个反应式布局是根据其环境调整其布局以适应其显示的设备的布局。通过使用反应式布局，您可以确保您的应用程序在任何设备上都能正常工作和显示良好，从手机到桌面设备。

```html
#main
{
    max-width: 25em;
    min-width: 9em;
    margin: 1em auto;
}
```

我们还想通过将其`width`属性设置为`98%`来将`task-name`文本输入字段的样式更改为占据主区域的整个宽度。这将为文本框的边框留出一些余地；`100%`会让它爆炸：

```html
#task-name
{
    font-size: 1em;
    display: block;
    width: 98%;
}
```

现在让我们来处理`task-list`项目。我们将给它们设置背景颜色，圆角和阴影。我们将使阴影变黑并且给它一些透明度，这样背景颜色就会透过来。我们还将把`position`属性设置为`relative`，这样我们就可以在其中定位任务按钮（见下一个屏幕截图）：

```html
#task-list .task
{
    position: relative;
    list-style: none;
    padding: 0.25em;
    margin: 0.25em;
    background-color: beige;
    border-radius: 4px;
    box-shadow: 2px 2px 3px rgba(0, 0, 0, 0.6);
}
```

让我们还在任务按钮周围添加一个边框来对它们进行分组，并使用绝对定位将它们移到`task`元素的右上方。我们也可以在这里将其浮动到右侧，但是绝对定位可以给我们更多的控制：

```html
#task-list .task .tools
{
    position: absolute;
    top: 0.25em;
    right: 0.25em;
    border: 1px solid black;
    border-radius: 2px;
}
```

### 注意

在使用绝对定位时，元素相对于最近的已定位的父元素进行定位。在这种情况下，那将是`task`元素。这就是为什么我们将其`position`属性设置为`relative`的原因。

## *刚刚发生了什么？*

如果你在浏览器中查看应用程序，你会注意到我们的任务列表看起来更加自然。阴影确实让任务项目从页面中凸显出来，并赋予它们深度。这使它们成为应用程序的亮点。通过将任务按钮移到右侧并且远离，我们真的让任务名称脱颖而出：

![刚刚发生了什么？](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-webapp-dev-ex/img/5947_02_03.jpg)

调整浏览器窗口大小，看看列表的反应。这是相同的布局调整为更小的样子，就像你在手机或其他移动设备上看到的一样：

![刚刚发生了什么？](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-webapp-dev-ex/img/5947_02_04.jpg)

# 背景

有许多新的样式用于设置元素的背景样式。现在您可以轻松地绘制渐变而不使用图像。您可以改变背景图像的大小和原点，甚至在背景中使用多个图像。

渐变为元素绘制了从一种颜色到一种或多种其他颜色的背景。它们为您的页面增添了深度，并增添了更加自然的外观。您可以在 CSS3 中指定两种不同类型的渐变：**线性**和**径向**。线性渐变是线性的。它们从一种颜色直线流向另一种颜色。径向渐变从中心点向外扩散。

## 线性渐变

线性渐变是使用`background`属性上的`linear-gradient`指定符来定义的。对于最简单的形式，你可以使用我们在颜色部分讨论过的任何`color`指定符来指定起始和结束颜色，它会从元素的顶部到底部绘制渐变。以下是从红色到蓝色的渐变：

```html
background: linear-gradient(#FF0000, #0000FF);
```

尽管渐变目前受到几乎所有浏览器的支持，但您仍然必须使用特定于浏览器的前缀才能使其工作。这意味着至少要指定四次才能覆盖大多数浏览器。请记住，始终将非专有版本指定为最后一个，如下面的 CSS 片段所示，这样它将在可用时覆盖特定于浏览器的版本：

```html
background: -webkit-linear-gradient(#FF0000, #0000FF);
background: -moz-linear-gradient(#FF0000, #0000FF);
background: -ms-linear-gradient(#FF0000, #0000FF);
background: linear-gradient(#FF0000, #0000FF);
```

如果要使渐变从顶部开始，可以指定第一个参数，该参数可以是要从其开始的侧面的名称或旋转的量。侧面有`top`、`bottom`、`left`和`right`。您可以指定从`-360deg`到`360deg`的度数，或从`-6.28rad`到`6.28rad`的弧度。`0`与`left`相同。正数逆时针旋转，负数顺时针旋转。以下是从`left`到`right`绘制渐变的示例：

```html
background: linear-gradient(left, #FF0000, #0000FF);
```

以下是以`45`度角绘制的渐变，即从左下角开始：

```html
background: linear-gradient(45deg, #FF0000, #0000FF);
```

如果愿意，您还可以添加多于两个的颜色停止。以下是从红色到蓝色到绿色的`45`度角渐变：

```html
background: linear-gradient(45deg, #FF0000, #0000FF, #00FF00);
```

以下是这些代码片段的显示方式：

![线性渐变](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-webapp-dev-ex/img/5947_02_07.jpg)

## 径向渐变

径向渐变在其使用的参数上几乎与线性渐变相同。默认情况下，从元素的中心到边缘绘制渐变：

```html
background: radial-gradient(#FF0000, #0000FF);
```

您还可以指定位置，例如使用预定义位置或从顶部左侧角的偏移点作为渐变的中心：

```html
background: radial-gradient(top, #FF0000, #0000FF);
```

以下是以距离左上角`20`像素和`20`像素处为中心绘制的渐变：

```html
background: radial-gradient(20px 20px, #FF0000, #0000FF);
```

您还可以为径向渐变添加多于两个的颜色停止。以下是从红色到蓝色到绿色的渐变，中心位于距左侧`20`像素和下方`20`像素的位置：

```html
background: radial-gradient(20px 20px, #FF0000, #0000FF, #00FF00);
```

以下是这些代码片段的显示方式：

![径向渐变](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-webapp-dev-ex/img/5947_02_08.jpg)

您可以指定许多其他设置来实现一些有趣的渐变效果，但这超出了本书的范围。如果发现自己创建自己的渐变太难，可以在[`www.colorzilla.com/gradient-editor/`](http://www.colorzilla.com/gradient-editor/)找到一个出色的渐变生成器。

## 背景图片

您可以将背景图像的大小设置为固定像素量或元素区域的百分比。图像将被缩放以适应指定的区域。`background-size`属性接受两个值：水平大小和垂直大小。如果要使背景图像填充元素的整个背景，可以使用以下方法：

```html
background-size: 100% 100%;
```

您可以通过用逗号分隔它们来指定多个背景图像。列表中的第一张图像将绘制在顶部，最后一张将绘制在底部。以下是绘制两个背景图像的示例：

```html
background: url(bg-front.png),
            url(bg-back.png);
```

![背景图片](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-webapp-dev-ex/img/5947_02_17.jpg)

还有一个新的`background-origin`属性，用于确定背景图像的绘制位置。可能的值如下：

+   `content-box`：仅在元素的内容区域中绘制背景图像

+   `padding-box`：将背景图像绘制到元素的填充区域

+   `border-box`：将背景图像一直绘制到元素的边框

以下是一个示例：

```html
background-origin: content-box;
```

以下是输出：

![背景图片](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-webapp-dev-ex/img/5947_02_13.jpg)

## CSS 精灵

我们接下来要讨论的概念是 CSS 精灵。这种技术对于 CSS3 来说并不新鲜，但在编写 HTML5 应用程序时，了解如何使用它是很重要的。CSS 精灵允许您将应用程序中的所有图像放入单个图像文件中，然后使用 CSS 将单个图像切片到元素中。这种技术节省了下载多个图像所需的时间和网络资源。如果您的应用程序有很多小图像，这种技术尤其有用。

要实现 CSS 精灵，将所有图像放入单个图像文件中，称为**精灵表**。然后按照以下步骤将精灵表中的图像放入页面上的元素中：

1.  使元素与要显示的图像大小相同。

1.  将元素的背景图像设置为精灵表图像。

1.  调整精灵表的背景位置，使要查看的图像位于元素的左上角。

让我们看一个例子。以下精灵表有 16 张图片，每张图片宽 10 像素，高 10 像素。首先，我们将元素的`width`和`height`属性设置为`10`像素。接下来，我们将背景图像设置为`sprite-sheet.png`精灵表。如果我们现在停下来，我们只会在我们的元素中看到第一张图片。

但是我们想要在我们的元素中显示第七张图片。因此，我们需要将精灵表的背景位置向左移动 20 像素，向上移动 10 像素。您必须使用负偏移来将正确的图像放置在位置上，因为您正在移动背景图像，而不是元素：

```html
#seven
{
    Width: 10px;
    height: 10px;
    background-image: url(sprite-sheet.png);
    background-position: -20px -10px;
}
```

这是结果：

![CSS 精灵](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-webapp-dev-ex/img/5947_02_12.jpg)

### 注意

将其视为在网页上切割一个洞，然后在洞后面滑动精灵表，直到正确的图像显示在洞中。

# 行动时间 - 添加渐变和按钮图像

让我们利用我们对渐变和背景图像的了解，使我们的应用程序看起来更有趣。首先，我们将在我们的任务列表应用程序的背景中添加一个渐变。我们将在`<div id="app">`元素上添加一个线性渐变。它将从顶部开始，渐变为底部的深蓝色。请注意，我们保留旧的背景颜色作为不支持渐变的浏览器的回退：

```html
#app
{
    margin: 4px;
    background-color: #bbc;
    background: -webkit-linear-gradient(top, #bbc, #558);
    background: -moz-linear-gradient(top, #bbc, #558);
    background: -ms-linear-gradient(top, #bbc, #558);
    background: linear-gradient(top, #bbc, #558);
}
```

这就是它的样子：

![行动时间 - 添加渐变和按钮图像](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-webapp-dev-ex/img/5947_02_09.jpg)

现在让我们使用 CSS 精灵将图像添加到任务列表应用程序中的按钮。我们需要删除、向上移动和向下移动的图像。我们的按钮将是 16x16 像素，因此我们的图像也需要是相同的大小。由于我们有三张图片，我们将创建一个 48 像素宽、16 像素高的精灵表。我们将把名为`icons.png`的精灵表图像文件放入`images`文件夹中。

![行动时间 - 添加渐变和按钮图像](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-webapp-dev-ex/img/5947_02_11.jpg)

现在让我们打开`taskAtHand.css`并添加样式，将图像从精灵表中提取到按钮中。首先，我们将更改适用于所有任务按钮的样式，将大小设置为 16x16 像素，并将背景图像设置为我们的精灵表。这样，我们只需要指定一次精灵表图像，它就会应用到我们所有的按钮上：

```html
#task-list .task .tools button
{
    margin: 0;
    padding: 0;
    border: none;
    color: transparent;
 width: 16px;
 height: 16px;
 background: url(images/icons.png);
}
```

现在我们所有的按钮都将使用`icons.png`作为它们的背景。我们现在所要做的就是设置每个按钮的背景位置，使它们与正确的图像对齐：

```html
#task-list .task .tools button.delete
{
    background-position: 0 0;
}
#task-list .task .tools button.move-up
{
    background-position: -16px 0;
}
#task-list .task .tools button.move-down
{
    background-position: -32px 0;
}
```

## *刚刚发生了什么？*

现在在浏览器中查看应用程序。我们添加了渐变，所以它不再那么沉闷和单调。现在它看起来现代而时尚。我们使用 CSS 精灵向按钮添加图像，从一个精灵表图像中提取图像。有了真正的按钮图标，这样看起来不是更好吗？

![刚刚发生了什么？](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-webapp-dev-ex/img/5947_02_14.jpg)

# 过渡

现在我们有一个相当不错的 UI，但是我们可以通过一些过渡效果使其变得更好。CSS3 过渡在元素样式改变时为元素添加动画效果。例如，如果我们改变元素的大小，它将逐渐从较小的大小变为较大的大小，从而为用户提供视觉反馈。当事物逐渐改变时，它比突然出现在页面上的东西更容易引起我们的注意。

CSS3 的`transition`属性允许我们在元素上指定过渡。它的格式如下：

```html
transition: property duration timing-function delay
```

以下是参数的解释：

+   `property`：要添加过渡的 CSS 属性。例如，`width`或`color`。使用`all`将过渡应用于所有属性。

+   `duration`：过渡所需的时间长度。例如，`0.5s`需要半秒钟来完成过渡。

+   `timing-function`：确定过渡在持续时间内的进展方式：

+   `linear`：从开始到结束的速度相同

+   `ease`：开始缓慢，然后加速，然后结束缓慢

+   `ease-in`：开始缓慢然后加速

+   `ease-out`：开始快然后减慢

+   `ease-in-out`：先缓慢，然后加速

+   `cubic-bezier()`: 如果你不喜欢预定义的函数，你可以构建自己的

+   `delay`: 开始过渡之前等待的时间。

`cubic-bezier`函数接受四个参数，这些参数是从`0`到`1`的数字。以下产生与`ease`函数相同的效果：

```html
transition: all 1s cubic-bezier(0.25, 0.1, 0.25, 1);
```

构建自己的`cubic-bezier`函数并不是大多数人可以凭空做到的。如果你想探索创建自己的时间函数，请访问[`cubic-bezier.com/`](http://cubic-bezier.com/)。

与渐变一样，过渡得到了广泛的支持，但在声明时仍应使用特定于浏览器的前缀：

```html
-webkit-transition: all 1s ease;
-moz-transition: all 1s ease;
-o-transition: all  1s ease;
transition: all 1s ease;
```

应用过渡的最简单方法是与 CSS 的`hover`选择器结合使用。当用户将鼠标移动到元素上时，以下内容将使元素的背景颜色从白色渐变到蓝色，用时 0.25 秒：

```html
#some-element
{
    background-color: White;
    transition: all 0.25s ease;
}
#some-element:hover
{
    background-color: Blue;
}
```

# 变换

CSS3 变换提供了更复杂的效果。有 2D 和 3D 变换可用。我们将在这里讨论一些 2D 变换。变换可以与过渡一起使用，提供一些有趣的效果。这是`transform`属性的基本形式：

```html
transform: function();
```

有一些不同的 2D`transform`函数。我们首先看的是`translate()`。它将一个元素从当前位置移动到一个新位置。它以 x 和 y 位置作为参数。你可以使用负值向上和向左移动。以下将使一个元素向右移动`10`像素，向上移动`25`像素：

```html
transform: translate(10px, -25px);
```

`rotate()`函数按给定的角度旋转元素。旋转量可以用度或弧度来指定。使用负值逆时针旋转，正值顺时针旋转：

```html
transform: rotate(45deg);
```

`scale()`函数通过某个因子调整元素的大小。它接受一个或两个参数。如果只提供一个参数，它将按该量进行缩放。如果指定了两个参数，它将分别缩放水平和垂直轴。以下示例将元素的宽度加倍，高度减半：

```html
transform: scale(2, 0.5);
```

我们将看一下`skew()`函数。这个函数扭曲或拉伸一个元素。它接受两个参数，即旋转 x 和 y 轴的量。角度的指定方式与`rotate()`函数相同：

```html
transform: skew(45deg, 10deg);
```

变换还需要特定于浏览器的前缀：

```html
-webkit-transform: rotate(45deg);
-moz-transform: rotate(45deg);
-o-transform: rotate(45deg);
-ms-transform: rotate(45deg);
transform: rotate(45deg);
```

以下是变换在浏览器中的样子：

![Transforms](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-webapp-dev-ex/img/5947_02_10.jpg)

# 行动时间-效果在行动

让我们给任务列表添加一些效果。首先，我们将添加选择列表中任务的能力。当点击一个任务时，它将增大并获得一个有颜色的边框，这样就很容易看出它被选中了。我们还将为任务添加悬停效果，这样当用户将鼠标移动到一个任务上时，任务的操作按钮就会显示出来。当鼠标移出任务时，按钮将淡出。你可以在`chapter2/example2.2`中找到这一部分的代码。

我们需要做的第一件事是回到`taskAtHand.js`，并在`addTaskElement()`方法中创建`task`元素后添加一个`click`事件处理程序：

```html
$task.click(function() { onSelectTask($task); });
```

当点击一个任务时，它调用`onSelectTask()`方法。在这个方法中，我们将通过给它一个`selected`类名来标记一个`task`元素为选定。我们还将从先前选定的任务元素中删除`selected`类：

```html
function onSelectTask($task)
{
    if ($task)
    {
        // Unselect other tasks
        $task.siblings(".selected").removeClass("selected");
        // Select this task
        $task.addClass("selected");
    }
}
```

现在让我们在`taskAtHand.css`中为选定的任务添加样式。我们将增加填充以使元素更大，添加边框以突出显示它，并改变背景颜色：

```html
#task-list .task.selected
{
    padding: 0.6em 0.5em;
    border: 2px solid orange;
    border-radius: 6px;
    background-color: white;
}
```

这很好，但我们可以通过添加过渡来使它更好。我们将在`.task`类中添加`transition`属性。它将在 0.25 秒内平稳地改变所有属性。当用户选择一个任务时，这将为用户提供一些良好的视觉反馈：

```html
#task-list .task
{
    /* Not shown... */
    -webkit-transition: all 0.25s ease;
    -moz-transition: all 0.25s ease;
    -o-transition: all 0.25s ease;
    transition: all 0.25s ease;
}
```

在此期间，让我们再添加一个过渡效果。我们将隐藏任务操作按钮，直到用户将鼠标移动到任务上或选择任务。为此，我们只需要添加一些额外的 CSS。首先，我们将通过将其`opacity`属性设置为`0`来隐藏任务按钮的容器元素，使其变为透明。然后，我们添加与之前相同的`transition`属性：

```html
#task-list .task .tools
{
    position: absolute;
    top: 0.25em;
    right: 0.25em;
    border: 1px solid black;
    border-radius: 2px;
 opacity: 0;

 -webkit-transition: all 0.25s ease;
 -moz-transition: all 0.25s ease;
 -o-transition: all 0.25s ease;
 transition: all 0.25s ease;
}
```

现在我们为`task`元素添加一个`hover`选择器，将`opacity`属性设置为`1`，使其不透明。这个选择器和过渡一起，将使任务按钮在用户悬停在任务上时出现淡入效果。我们还添加了一个选择器，使任务按钮在选择任务时显示出来（以下片段中的第二行）：

```html
#task-list .task:hover .tools,
#task-list .task.selected .tools
{
    opacity: 1;
}
```

在 CSS3 之前，您可以使用 jQuery 的`fadeIn()`和`fadeOut()`方法以及一些鼠标事件来使用 JavaScript 做同样的事情，但这需要更多的代码。

## *刚刚发生了什么？*

我们在任务列表中添加了一些 CSS3 过渡效果，使任务项目按钮淡入淡出，并在单击时使选定的任务项目变大。我们已经看到，只需几行 CSS 代码，我们就可以为我们的应用程序添加一些不错的效果。现在我们的任务列表看起来是这样的，**Task 2**被选中：

![刚刚发生了什么？](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-webapp-dev-ex/img/5947_02_15.jpg)

# 动态样式表

让我们为我们的应用程序添加一个新功能，允许用户选择颜色方案或主题，以便他们可以自定义应用程序的外观和感觉。我们可以通过动态加载 CSS 文件来改变网页的外观，以覆盖默认样式表中的现有样式。为了实现这一点，我们将在应用程序中添加一个主题的下拉列表供用户选择。当他们改变主题时，它将改变样式表，从而改变页面的颜色。

# 行动时间-添加主题选择器

首先，我们需要一个放置主题选择器的地方。因此，让我们在`taskAtHand.html`中的任务列表应用程序的标记中添加一个工具栏。我们将它插入在`<header>`和`<div id="main">`元素之间。工具栏将包含一个`<label>`和一个`<select>`下拉列表。列表将包含四种不同的颜色主题：`blue`、`green`、`magenta`和`red`。您可以在`chapter2/example2.3`中找到此部分的代码：

```html
<div id="app">
  <header>Task@Hand</header>
 <div id="toolbar">
 <label for="theme">Theme</label>
 <select id="theme" title="Select theme">
 <option value="blue">Blue</option>
 <option value="green">Green</option>

 <option value="magenta">Magenta</option>
 <option value="red">Red</option>
 </select>
 </div>
  <div id="main">
```

现在让我们设计工具栏。我们将使字体比页面的其他部分稍微小一些，并将背景颜色设置为黑色，并带有一些透明度，以便它后面的颜色透过来：

```html
#toolbar
{
    padding: 0.25em;
    font-size: 0.8em;
    color: WhiteSmoke;
    background-color: rgba(0, 0, 0, 0.4);
}
```

接下来，我们必须实现不同的主题。因此，让我们创建一些新的 CSS 文件，每个主题一个文件。我们将把它们放在一个名为`themes`的文件夹中，以便将它们分组在一起。CSS 文件将与`<option>`值具有相同的名称：`blue.css`、`green.css`、`magenta.css`和`red.css`。让我们来看一下`green.css`：

```html
#app
{
    background-color: #bcb;
    background: -webkit-linear-gradient(top, #bcb, #585);
    background: -moz-linear-gradient(top, #bcb, #585);
    background: -ms-linear-gradient(top, #bcb, #585);
    background: linear-gradient(top, #bcb, #585);
}
#app>header,
#app>footer
{
    background-color: #060;
}
```

从顶部开始，我们覆盖`app`元素的背景渐变，使它们成为绿色，而不是蓝色。我们还将`header`和`footer`元素改为绿色。其他 CSS 文件将与此文件完全相同，只是它们的颜色会有所不同。

现在让我们在 HTML 文件的`<header>`元素中添加一个样式表`<link>`元素，用于主题 CSS 文件。由于蓝色主题是默认的，我们将设置它加载`blue.css`：

```html
<link href="taskAtHand.css" rel="StyleSheet" />
<link id="theme-style" href="themes/blue.css" rel="StyleSheet" />

```

请注意，我们在基本样式表之后包含主题样式表。这将允许我们覆盖默认样式。还要注意，我们给`<link>`元素一个`ID`属性，这样我们以后就可以在 JavaScript 中访问它。

我们需要添加的其余代码在`taskAtHand.js`中。首先，我们将在`TaskAtHand.start()`方法中为主题选择器添加一个`change`事件处理程序：

```html
$("#theme").change(onChangeTheme);
```

当用户选择新主题时，它将调用`onChangeTheme()`私有方法：

```html
function onChangeTheme()
{
    var theme = $("#theme>option").filter(":selected").val();
    setTheme(theme);
    appStorage.setValue("theme", theme);
}
```

这个方法通过获取其`<option>`元素并使用 jQuery 的`:selected`选择器在`filter()`方法内找到选定的选项，从列表中获取所选选项。然后调用`setTheme()`方法，接下来我们将实现。最后，我们将所选主题保存到`localStorage`，这样下次用户返回应用程序时就可以设置它。

`setTheme()`方法接受主题名称作为参数。它获取`<link id="theme-style">`元素，并将其`href`属性更改为新样式表的 URL：

```html
function setTheme(theme)
{
    $("#theme-style").attr("href", "themes/" + theme + ".css");
}
```

当这发生时，页面将加载新的样式表，并将其样式应用于现有样式。就像这样，页面的颜色发生了变化。

等等，我们还没有完成。还记得我们是如何将主题保存到`localStorage`的吗？现在当用户返回我们的应用程序时，我们需要将其取出。我们将创建一个`loadTheme()`方法来做到这一点：

```html
function loadTheme()
{
    var theme = appStorage.getValue("theme");
    if (theme)
    {
        setTheme(theme);
        $("#theme>option[value=" + theme + "]")
            .attr("selected","selected");
    }
}
```

这个方法从`localStorage`获取主题名称。如果找到了一个，它就调用`setTheme()`来设置它。然后通过在列表中找到具有其值为主题名称的`<option>`，并在其上设置`selected`属性，来选择该主题。最后一件事是从`start()`方法中添加对`loadTheme()`的调用，然后我们就完成了。

### 注意

我们的主题样式更改非常简单，但是您可以完全改变应用程序的外观和感觉使用这种技术。

## *刚刚发生了什么？*

我们添加了一个主题选择器，可以更改主题样式表，这会导致页面使用不同的颜色来绘制背景。我们将所选主题保存到本地存储中，因此当用户返回应用程序时，设置将被记住。

# 填充窗口

在我们离开 CSS 章节之前，还有一件事情我们需要重新设计。让我们使应用程序填满整个窗口的空间。现在随着列表的增长，背景渐变也在增长，页脚也在下移。如果渐变覆盖整个窗口，页脚始终位于底部会更好。

# 行动时间-扩展应用程序

我们可以使用绝对定位来填充浏览器窗口。让我们为`<div id="app">`元素的样式添加以下内容：

```html
#app
{
 position: absolute;
 top: 0;
 bottom: 0;
 left: 0;
 right: 0;
 overflow: auto;
    /* Code not shown… */
}
```

首先，它将元素的定位设置为绝对定位，这样我们就可以将元素的位置设置为我们想要的位置。然后我们将所有的`position`属性设置为`0`。这样就可以拉伸元素，使其填满整个窗口空间。最后，我们将`overflow`属性设置为`auto`。这将使滚动条出现，并且如果任务列表超出窗口的高度，渐变会延伸到窗口底部以下。

我们还需要重新定位页脚，使其固定在窗口底部。我们可以通过将`position`设置为`absolute`和`bottom`设置为`0`来实现。请注意，我们没有将`right`设置为`0`，因此页脚不会占据整个宽度。否则，它可能会干扰任务列表：

```html
#app>footer
{
    position: absolute;
    bottom: 0;
    /* Code not shown… */
}
```

## *刚刚发生了什么？*

我们扩展了主应用程序元素，使其占据整个浏览器窗口的空间，并将页脚移动到底部。让我们看看我们的应用程序现在在浏览器中的样子：

![刚刚发生了什么？](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-webapp-dev-ex/img/5947_02_16.jpg)

## 试试看

想出并实现更多的主题。使用我们学到的一些 CSS3 特性，如径向渐变、背景图片，甚至一些盒子阴影来制作一些看起来有趣的主题。

## 快速测验

Q1\. 渐变可以有多少个颜色停？

1.  一个

1.  二

1.  三

1.  任意数量

Q2\. 过渡是什么作用？

1.  将 CSS 属性从一个值过渡到另一个值

1.  将元素从一种类型过渡到另一种类型

1.  从一个类过渡到另一个类

1.  从一个视图过渡到另一个视图

# 总结

在本章中，我们学习了一些新的 CSS3 功能，可以用来使您的应用程序更加突出，并为用户提供大量的视觉反馈。我们通过向任务元素添加圆角和阴影，并向任务工具按钮添加图像来更新了我们的任务列表应用程序。我们为背景添加了渐变和主题选择器，允许用户更改颜色方案。我们还添加了一些过渡效果，使变化看起来更加自然。

在本章中，我们涵盖了以下概念。

+   如何在 CSS3 中定义带有透明度的颜色

+   如何给元素添加圆角

+   如何向元素和文本添加阴影

+   如何创建线性和径向渐变

+   如何使用 CSS3 过渡和变换来创建视觉效果

+   如何使用 CSS 精灵来减少应用程序的网络印记

+   如何动态加载样式表

+   如何使您的应用程序填满整个窗口

在我们继续之前，让我给你一个警告。仅仅因为 CSS3 拥有所有这些出色的效果，并不意味着你必须在应用程序中全部使用它们。每个文本并不都需要阴影，你不需要让你的背景具有彩虹般的渐变，也不需要让每个元素旋转 30 度。谨慎地使用这些效果将使您的应用程序看起来更专业；过度使用将使它们看起来滑稽。

在下一章中，我们将通过为每个任务添加一个详细部分，使用一些新的 HTML5 输入类型，将我们的任务列表应用程序提升到一个新的水平。我们还将学习如何使用自定义数据属性将数据模型绑定到输入元素。


# 第三章：细节决定成败

> “希望了解世界的人必须从具体细节中了解它。”

*—赫拉克利特*

*本章主要介绍新的 HTML5 输入类型以及如何使用 JavaScript 与其进行交互。在第一章中，*手头的任务*，我们创建了一个任务列表应用程序，在第二章中，*时尚起来*，我们使用了新的 CSS3 样式对其进行了美化。在本章中，我们将继续改进它，通过添加新的 HTML5 输入类型的任务详细信息部分。然后，我们将使用自定义数据属性自动将视图中的值绑定到应用程序中的数据模型。我们还将添加一些 jQuery 动画，使 UI 过渡更加流畅。*

我们将在本章中学习以下主题：

+   新的 HTML5 输入类型及其提供的好处

+   自定义数据属性及其用途

+   如何使用自定义数据属性将数据模型绑定到输入元素

+   使用 jQuery 动画方法隐藏和显示元素

+   使用定时器将保存到 localStorage 的内容排队

# HTML5 输入类型

HTML5 带来了一系列新的输入类型。这些新类型旨在提供格式化、验证，有时还提供选择器。对于触摸设备，其中一些类型为键盘提供了不同的按键。并非所有新的输入类型都得到了所有浏览器的支持。幸运的是，如果浏览器不支持某种类型，它将只是将其显示为普通文本字段。不幸的是，如果不支持的类型只显示为文本字段，您不能依赖浏览器提供正确格式化的数据。因此，如果您要使用它们，请确保您有备用方案。

以下是一些更有用的新输入类型，以及 Chrome 支持的其中一些类型的图像。

### 注意

请参见`第三章/输入类型/input-types.html`中的示例。

## 颜色

`color`输入类型用于选择颜色。单击时通常会显示颜色选择器。值是十六进制颜色指示符（例如，#FF0000）。目前这个控件的支持范围有限，因此请谨慎使用。

```html
<input type="color" value="#FF0000"/>
```

![颜色](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-webapp-dev-ex/img/5947OT_03_04.jpg)

## 日期

`date`输入类型用于选择日期。单击时通常会显示日期选择器。值是 yyyy-mm-dd 格式的日期字符串（例如，2013-01-23）。您还可以以相同的日期格式指定`min`和`max`属性，以限制日期范围：

```html
<input type="date" value="2013-01-23" min="2013-01-01"/>
```

![日期](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-webapp-dev-ex/img/5947OT_03_05.jpg)

## 电子邮件

`email`输入类型用于输入电子邮件地址。它的外观和行为类似于标准文本字段。在触摸设备上，键盘通常会更改以提供电子邮件符号，如*@*符号和*.com*：

```html
<input type="email" value="foo@bar.com"/>
```

## 数字

`number`输入类型用于输入数字。通常会显示带有上下按钮（微调控件）的形式，单击时会按`step`的量更改值。在触摸设备上，键盘可能会更改为数字键盘。您可以使用一些属性来限制字段：

+   `min`：指定允许的最小值

+   `max`：指定允许的最大值

+   `step`：指定单击上下微调按钮时值更改的量

```html
<input type="number" value="23" min="0" max="100" step="1"/>
```

![数字](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-webapp-dev-ex/img/5947OT_03_06.jpg)

## 范围

`range`输入类型用于从一系列值中选择一个值。这几乎与`number`输入类型相同，只是通常显示为滑块控件。它具有与`number`输入类型相同的属性。

```html
<input type="range" value="20" min="0" max="100" step="10"/>
```

![范围](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-webapp-dev-ex/img/5947OT_03_07.jpg)

## 时间

`time`输入类型用于选择时间。单击时，它可能会显示时间选择器，或者您可以使用微调器设置时间。值是 24 小时格式的时间字符串，格式为 hh:mm:ss（例如，13:35:15）。

```html
<input type="time" value="13:35:15"/>
```

![时间](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-webapp-dev-ex/img/5947OT_03_08.jpg)

## URL

`url`输入类型用于输入 URL。与`email`类型一样，触摸设备通常会显示为优化输入 URL 的键盘。

```html
<input type="url" value="http://www.worldtreesoftware.com"/>
```

## 数据列表

除了这些新的输入类型，HTML5 中还添加了一个新的`<datalist>`表单元素。它用于为文本字段添加一个下拉提示列表。当用户开始在文本字段中输入时，与正在输入的字母匹配的所有列表选项将显示在字段下的下拉菜单中。用户可以选择其中一个选项来自动填写字段。

你可以通过在`<datalist>`元素上设置一个 ID，并在`<input>`元素的`list`属性中引用它，将`<datalist>`元素与文本字段关联起来。

```html
<input type="text" list="color-list"/>
<datalist id="color-list">
    <option value="Red"/>
    <option value="Orange"/>
    <option value="Yellow"/>
    <option value="Green"/>
    <option value="Blue"/>
    <option value="Purple"/>
</datalist>
```

![数据列表](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-webapp-dev-ex/img/5947OT_03_09.jpg)

### 注意

由于新输入类型的实现在这个时候还不够完善，所以在使用它们时要小心。如果不支持使用`number`字段不会引起太多问题；用户仍然可以在文本字段中输入数字。但是如果像`color`字段这样的东西不被支持，它会显示为一个文本字段。在这种情况下，你的用户愿意输入十六进制代码的颜色吗？

## 自动聚焦

HTML5 输入元素还有一个有用的补充。新增了一个`autofocus`属性，用于在页面首次加载时设置焦点在特定的`<input>`元素上。以前我们在应用程序中通过调用 jQuery 的`focus()`方法来为`<input id="new-task-name">`元素设置焦点。在 HTML5 中，我们可以通过添加`autofocus`属性来实现相同的功能。

```html
<input type="text" autofocus id="new-task-name".../>
```

# 任务详细信息

让我们在我们的任务列表应用程序中充分利用一些新的输入类型。目前我们只有一个任务名称输入字段。我们对此无能为力。所以让我们为每个任务添加一些字段，让用户可以定义更多关于它们的细节。你可以在`Chapter 3\example3.1`中找到这一部分的源代码。

# 行动时间 - 添加任务详细信息

我们将为每个任务添加以下新字段：

+   **开始日期**：任务应该开始的日期。输入类型为`date`。

+   **截止日期**：任务应该完成的日期。输入类型为`date`。

+   **状态**：下拉列表`<select>`，选项为**无**，**未开始**，**已开始**和**已完成**。

+   **优先级**：下拉列表`<select>`，选项为**无**，**低**，**正常**和**高**。

+   **% 完成**：输入类型为`number`，有效范围为**0**到**100**。

让我们在`taskAtHand.html`中的任务模板标记中定义这些字段。每个任务的详细信息将显示在任务名称下的一个部分中。我们的模板现在看起来像以下的代码片段：

```html
<li class="task">
    <span class="task-name"></span>
    <input type="text" class="task-name hidden"/>
    <div class="tools">
        <button class="delete" title="Delete">X</button>
        <button class="move-up" title="Up">^</button>
        <button class="move-down" title="Down">v</button>
    </div>
    <div class="details">
 <label>Start date:</label>
 <input type="date"/><br/>
 <label>Due date:</label>
 <input type="date"/><br/>
 <label>Status:</label>
 <select>
 <option value="0">None</option>
 <option value="1">Not Started</option>
 <option value="2">Started</option>
 <option value="3">Completed</option>
 </select><br/>
 <label>Priority:</label>
 <select>
 <option value="0">None</option>
 <option value="1">Low</option>
 <option value="2">Normal</option>
 <option value="3">High</option>
 </select><br/>
 <label>%&nbsp;Complete:</label>
 <input type="number min="0" max="100" step="10" value="0"/>
 </div>
</li>
```

首先，我们添加了一个新的`<div class="details">`元素来包含新的详细字段。这样我们可以将详细信息与任务名称分开以便以不同的样式进行设置。然后我们向其中添加了标签和字段。请注意，对于**% 完成**，我们设置了`number`字段的`min`和`max`属性，以限制数字在 0 到 100 之间。

接下来我们需要为详细信息部分设置样式。我们将给它一个灰色的背景和圆角。我们将所有标签设置为相同的宽度，并将它们右对齐，以便所有输入字段对齐。然后我们将**状态**和**优先级**的`<select>`元素设置为固定宽度，以便它们也对齐。

```html
#task-list .task .details
{
    display: block;
    background-color: gray;
    color: white;
    border-radius: 4px;
    margin-top: 0.5em;
    padding: 0.25em;
    overflow: auto;
}
#task-list .task .details label
{
    width: 8em;
    text-align: right;
    display: inline-block;
    vertical-align: top;
    font-size: 0.8em;
}
#task-list .task .details select
{
    width: 8em;
}
```

## *刚刚发生了什么？*

我们使用一些新的 HTML5 输入类型为我们的任务添加了一个任务详细信息部分。以下截图显示了现在的任务项目是什么样子的，有一个详细信息部分：

![刚刚发生了什么？](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-webapp-dev-ex/img/5947OT_03_01.jpg)

# 行动时间 - 隐藏任务详细信息

看起来不错，但它也占用了很多空间。如果列表中的每个任务都这么长，它很快就会滚动到页面之外，我们将无法很好地看到任务列表的概述。由于任务详细信息是可选字段，我们可以通过不显示详细信息来使我们的列表更加紧凑，直到用户想要查看它们为止。我们将通过隐藏详细信息部分并在任务名称旁边添加一个切换按钮来实现这一点，以便在单击时显示或隐藏详细信息。

首先让我们在我们的任务模板中的任务名称旁边添加一个切换详细信息按钮，并给它一个名为`toggle-details`的类。

```html
<li class="task">
    <button class="toggle-details">+</button>
    <span class="task-name"></span>
    <!—- Not shown… -->
</li>
```

现在让我们在 JavaScript 代码中实现切换按钮。首先，在`addTaskElement()`方法中为切换按钮添加一个单击事件处理程序，该处理程序调用`toggleDetails()`方法：

```html
$("button.toggle-details", $task).click(function() {
    toggleDetails($task);
});
```

然后我们实现`toggleDetails()`方法：

```html
function toggleDetails($task)
{
    $(".details", $task).slideToggle();
    $("button.toggle-details", $task).toggleClass("expanded");
}
```

`toggleDetails()`方法使用了一些我们尚未见过的新的 jQuery 方法。它使用`slideToggle()`来切换任务详情的可见性，并使用`toggleClass()`来切换按钮上的`expanded`类。`toggleClass()`方法会在元素没有该类时向元素添加一个类，并在元素有该类时将其删除。

`slideToggle()`方法是一个动画函数，用于切换元素的可见性。它通过向下滑动的方式使元素可见，将其下面的元素推下。要隐藏元素，它会将其向上滑动，缩小直到隐藏。还有一个用于淡入淡出元素的方法，称为`fadeToggle()`。但是，当元素在变得可见时，滑动提供了更平滑的过渡，因为它会将其他元素推开。

### 注意

一般来说，当元素在变得可见时，滑动效果看起来更好，因为它会将下面的元素推下。它还适用于类似菜单的行为。当您使一个元素变得可见并显示在其他元素的顶部时，淡入通常看起来最好。

现在让我们为按钮添加一些样式。当然，我们想要一些漂亮的图标，就像我们的其他任务按钮一样，所以让我们将它们添加到我们的精灵表文件`icons.png`中。我们需要一个图像来显示任务属性折叠时的情况，另一个图像用于显示它们展开时的情况。让我们为这两个图标创建第二行图像。

![进行操作-隐藏任务详情](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-webapp-dev-ex/img/5947OT_03_02.jpg)

我们在样式表中需要做的第一件事是将详情的`display`设置为`none`，以便它们默认情况下是隐藏的：

```html
#task-list .task .details
{
 display: none;
    /* Not shown… */
}
```

然后我们为`toggle-details`按钮添加样式。由于我们使用与任务工具按钮相同的精灵表，因此我们将通过将其添加到 CSS 选择器中，使用相同的样式来为我们的新按钮添加样式。然后，我们将添加选择器以使用背景位置偏移将图像放入按钮中：

```html
#task-list .task .tools button,
#task-list .task button.toggle-details
{
    /* Not shown… */
    background: url(images/icons.png);
}
#task-list .task button.toggle-details
{
    background-position: 0 -16px;
}
#task-list .task button.toggle-details.expanded
{
    background-position: -16px -16px;
}
```

我们的`toggle-details`图像的垂直偏移量为`-16px`，因为它们位于精灵表的第二行。请注意，第二个图像与`expanded`类匹配。当详情可见时，我们将`expanded`类添加到按钮上。

## 刚刚发生了什么？

我们为每个任务添加了一个切换按钮，当单击时隐藏或显示任务详情。在浏览器中打开它，看看我们现在有什么。您可以打开和关闭任务详情，并且它们会平稳地展开和关闭。相当酷。

![刚刚发生了什么？](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-webapp-dev-ex/img/5947OT_03_03.jpg)

# 自定义数据属性

HTML5 的另一个新功能是自定义数据属性。自定义数据属性允许您将自定义数据存储为 DOM 中任何元素的属性。您只需使用`data-`作为属性名称的前缀。名称应全部为小写字母。您可以为属性分配任何字符串值。

例如，假设我们有一个产品列表，我们想要存储有关产品的信息，例如产品 ID 和类别。我们只需向相关元素添加`data-product-id`和`data-category`属性：

```html
<ul id="product-list">
  <li data-product-id="d1e0ddde" data-category="widgets">
    Basic Widget
  </li>
  <li data-product-id="e6b2c03f" data-category="widgets">
    Super Widget
  </li>
</ul>
```

现在我们有了自定义属性，我们可以使用 JavaScript 从元素中提取自定义数据，并在我们的应用程序中使用它。jQuery 碰巧有一个专门为此目的设计的`data()`方法。您只需给出自定义属性的名称，减去`data-`，它就会返回与其关联的值。

继续上一个示例，假设我们希望允许用户单击列表中的产品，然后对其进行一些处理。以下的`setSelectedProduct()`方法使用`data()`方法从被单击的元素中提取产品 ID 和类别：

```html
$("#product-list li").click(function() {
    var $product = $(this);
    var productId = $product.data("product-id");
    var category = $product.data("category");
    // Do something...
});
```

# 使用自定义属性进行数据绑定

自定义数据属性的一个很好的用途是实现数据绑定。数据绑定允许我们将 DOM 中的用户控件映射到数据模型中的字段，以便在用户更改它们时自动更新。使用这种技术，我们可以消除许多无聊的重复代码，这些代码只是处理事件并将视图中的字段映射到模型中的字段。

### 注意

有一些出色的数据绑定库可用于 JavaScript，包括`Backbone.js`和`Knockout`。我们将在这里实现自己简单的数据绑定，以学习如何使用自定义属性。如果你发现自己正在构建一个大量数据的应用程序，你可能会考虑使用其中一个库。

# 行动时间-构建数据模型

在我们开始实现数据绑定之前，我们需要一个数据模型进行绑定。如果你还记得，我们只是将任务名称保存到`localStorage`。我们的数据模型只是一个字符串数组。现在每个任务都有多个详细字段，我们需要一些更实质的东西来保存所有这些数据。你可以在`Chapter 3\example3.2`中找到本节的源代码。

让我们从为我们的数据模型定义一个任务对象开始。我们将创建一个新文件`taskList.js`来放置它。

```html
function Task(name)
{
    this.name = name;
    this.id = Task.nextTaskId++;
    this.created = new Date();
    this.priority = Task.priorities.normal;
    this.status = Task.statuses.notStarted;
    this.pctComplete = 0;
    this.startDate = null;
    this.dueDate = null;
}
// Define some "static variables" on the Task object
Task.nextTaskId = 1;
Task.priorities = {
    none: 0,
    low: 1,
    normal: 2,
    high: 3
};
Task.statuses = {
    none: 0,
    notStarted: 1,
    started: 2,
    completed: 3
};
```

从头开始，我们的构造函数接受一个参数-任务名称。它用于设置对象中的名称字段。每个任务都有一个唯一的任务 ID，每次创建任务时都会递增。其余成员设置为默认值。

我们将`Task.nextTaskId`字段附加到`Task`对象构造函数，以跟踪下一个唯一任务 ID 应该是什么。这样做可以让我们定义我们在具有类的语言中定义静态或类变量的内容，比如 Java 或 C#（在这些语言中，它们使用静态变量定义）。`nextTaskId`字段在更改时将保存到`localStorage`，以便我们知道用户返回应用程序时我们离开的位置。

注意`priority`和`status`使用枚举。我们将这些实现为静态对象（因为 JavaScript 没有枚举），附加到`Task`构造函数。

我们需要的下一件事是一个列表，用于存储`Task`对象。为了更容易管理这段代码，我们将创建一个`TaskList`对象，它基本上是一个数组的包装器。它提供了添加、删除和获取任务的方法：

```html
function TaskList(tasks)
{
    tasks = tasks || [];
```

构造函数接受一个可选参数，即`Task`对象的数组。构造函数的第一行检查是否传入了一个数组。如果没有，则使用空方括号(`[]`)创建一个新的空数组。

### 注意

在 JavaScript 中，逻辑或运算符（`||`）可以充当空值合并运算符。如果操作数是“真值”，它将返回左操作数；否则返回右操作数。在这种情况下，真值意味着传入了`tasks`参数并且不是`null`或`undefined`。这是定义默认值的非常有用的范例。

现在我们添加一个公共的`getTasks()`方法，它简单地返回数组。我们以后需要访问它来保存任务：

```html
    this.getTasks = function()
    {
        return tasks;
    };
```

接下来我们添加一个公共的`addTask()`方法，它接受一个`Task`对象并将其追加到数组的末尾：

```html
    this.addTask = function(task)
    {
        tasks.push(task);
        return this;
    };
```

公共的`removeTask()`方法以任务 ID 作为参数，并从列表中删除相关的任务：

```html
    this.removeTask = function(taskId)
    {
        var i = getTaskIndex(taskId);
        if (i >= 0)
        {
            var task = tasks[i];
            tasks.splice(i, 1);
            return task;
        }
        return null;
    };
```

它通过调用`getTaskIndex()`获取任务的索引，然后使用`array.splice()`方法从`tasks`数组中删除它。`getTaskIndex()`方法是一个私有方法，它以任务 ID 作为参数，并通过数组搜索找到具有该 ID 的任务。如果找到任务，则返回它。否则返回`-1`：

```html
    function getTaskIndex(taskId)
    {
        for (var i in tasks)
        {
            if (tasks[i].id == taskId)
            {
                return parseInt(i);
            }
        }
        // Not found
        return -1;
    }
```

接下来是公共的`getTask()`方法。它以任务 ID 作为参数，并使用`getTaskIndex()`方法来查找它。它返回相关的`Task`对象，如果不存在则返回`null`。

```html
    this.getTask = function(taskId)
    {
        var index = getTaskIndex(taskId);
        return (index >= 0 ? tasks[index] : null);
    };
```

我们要添加的最后一个公共方法称为`each()`。它将`callback`函数的引用作为参数。它循环遍历任务数组，并对数组中的每个任务执行`callback`函数。此方法可用于遍历列表中的所有任务：

```html
    this.each = function(callback)
    {
        for (var i in tasks)
        {
            callback(tasks[i]);
        }
    };
}
```

# 行动时间-实现绑定

让我们回到 HTML 文件中的任务模板，并添加一些自定义数据属性。我们将为所有任务详细信息的`<input>`和`<select>`元素添加自定义属性。数据属性的名称将是`data-field`，属性值将是元素在`Task`对象中匹配的字段的名称。我们稍后将在 JavaScript 中使用这些属性来将 DOM 元素和数据模型连接在一起：

```html
<div class="details">
    <label>Start date:</label>
    <input type="date" data-field="startDate"/><br/>
    <label>Due date:</label>
    <input type="date" data-field="dueDate"/><br/>
    <label>Status:</label>
    <select data-field="status">
        <!— options removed... -->
    </select><br/>
    <label>Priority:</label>
    <select data-field="priority">
        <!— options removed... -->
    </select><br/>
    <label>%&nbsp;Complete:</label>
    <input type="number" data-field="pctComplete"
        min="0" max="100" step="10" value="0"/>
</div>
```

现在我们有了一个数据模型，我们需要进入`taskAtHand.js`中的`TaskAtHandApp`对象，并更新它以使用该模型。首先，我们将添加一个`taskList`变量，并将其初始化为`TaskList`对象的实例：

```html
function TaskAtHandApp()
{
    var version = "v3.2",
        appStorage = new AppStorage("taskAtHand"),
 taskList = new TaskList();

```

然后，我们将进入`addTask()`方法，并添加代码来创建一个新的`Task`对象，并将其添加到任务列表中。这也是在将`nextTaskId`值递增后将其保存到`localStorage`中的地方：

```html
function addTask()
{
    var taskName = $("#new-task-name").val();
    if (taskName)
    {
 var task = new Task(taskName);
 taskList.addTask(task);
 appStorage.setValue("nextTaskId", Task.nextTaskId);
        addTaskElement(task);
        saveTaskList();
        // Reset the field
        $("#new-task-name").val("").focus();
    }
}
```

请注意，我们还更改了`addTaskElement()`方法的参数，以传入`Task`对象。因此，让我们更新`addTaskElement()`方法，以将`Task`对象作为参数而不是任务名称：

```html
function addTaskElement(task)
{
    var $task = $("#task-template .task").clone();
 $task.data("task-id", task.id);
    $("span.task-name", $task).text(task.name);
```

在 DOM 中创建新任务元素后，我们使用名为`task-id`的自定义数据属性在其上设置任务 ID。这是通过 jQuery 的`data()`方法完成的，该方法将数据属性名称和值作为参数。接下来，我们将任务名称设置到`task.name`字段的`<span>`属性中。

现在我们将实现数据绑定的第一部分。下面的代码块使用了我们之前添加到标记中的数据属性，将`Task`对象的值设置到详细部分中关联的`<input>`和`<select>`元素中：

```html
    // Populate all of the details fields
    $(".details input, .details select", $task).each(function() {
        var $input = $(this);
        var fieldName = $input.data("field");
        $input.val(task[fieldName]);
    });
```

它的工作原理如下：

1.  首先，它查找任务元素内的所有`<input>`和`<select>`元素。

1.  然后调用 jQuery 的`each()`方法，用于遍历所选元素集，传入一个`callback`函数。

1.  在`callback`函数中，`this`指向当前元素。因此，我们首先将元素包装在 jQuery 对象中。

1.  然后，我们使用`data()`方法获取`data-field`自定义属性的值，这是与元素关联的`Task`对象中字段的名称。

1.  最后，我们将用户控件的值设置为`Task`对象中字段的值。我们使用方括号从`Task`对象中获取值。请记住，在 JavaScript 中，`object["field"]`与`object.field`是相同的。

### 注意

您可以将使用方括号访问对象字段视为类似于在 C#或 Java 中使用反射在运行时动态访问对象中的值。

现在，我们需要添加代码来实现双向绑定。每当用户更改表单控件的值时，我们希望自动将其保存回数据模型。因此，让我们为每个详细表单控件添加一个 change 事件处理程序：

```html
$(".details input, .details select", $task).change(function() {
    onChangeTaskDetails(task.id, $(this));
});
```

这调用`onChangeTaskDetails()`方法，传入任务 ID 和更改的表单控件元素，该元素包装在 jQuery 对象中。让我们实现该方法：

```html
function onChangeTaskDetails(taskId, $input)
{
    var task = taskList.getTask(taskId)
    if (task)
    {
        var fieldName = $input.data("field");
        task[fieldName] = $input.val();
        saveTaskList();
    }
}
```

让我们分解一下，看看它是如何工作的：

1.  首先，它从具有指定 ID 的任务列表中获取`Task`对象。

1.  确保我们得到了一个对象（你永远不知道，所以总是检查），我们从元素的`data-field`属性中获取`Task`对象字段名称。

1.  然后，我们将`Task`对象上的字段值设置为表单控件元素的值，再次使用方括号动态访问它。

1.  最后，我们调用`saveTaskList()`来提交对`localStorage`的更改。

提醒一下，我们需要重写`saveTaskList()`方法来保存我们的新`TaskList`对象。这很容易。我们只需调用任务列表的`getTasks()`方法来获取`Task`对象的数组。然后我们将数组保存到`localStorage`：

```html
function saveTaskList()
{
    appStorage.setValue("taskList", taskList.getTasks());
}
```

### 注意

如果您有来自先前示例的旧任务列表数据，则需要在使用新数据模型之前将其删除。在 Chrome 开发者工具中，您可以单击该项目，然后按*删除*键将其删除。

## *刚刚发生了什么？*

首先，我们创建了一个数据模型来保存所有任务数据。然后，我们使用自定义数据属性向我们的应用程序添加了数据绑定，以在页面更改字段时自动更新数据模型。然后我们将任务列表保存到本地存储。

# 行动时间-加载任务列表

现在我们已将新数据模型保存到`localStorage`，我们需要更新`loadTaskList()`方法来加载数据：

```html
function loadTaskList()
{
    var tasks = appStorage.getValue("taskList");
    taskList = new TaskList(tasks);
    rebuildTaskList();
}
```

首先，我们从`localStorage`获取任务数组，并将其作为参数传递给`TaskList`对象的构造函数。然后，我们调用一个新方法`rebuildTaskList()`来在 DOM 中创建任务元素：

```html
function rebuildTaskList()
{
    // Remove any old task elements
    $("#task-list").empty();
    // Create DOM elements for each task
    taskList.each(function(task)
    {
        addTaskElement(task);
    });
}
```

首先，我们使用 jQuery 的`empty()`方法从任务列表元素中删除任何旧元素。然后，我们使用我们在`TaskList`对象中实现的`each()`方法来迭代任务，并为每个任务调用`addTaskElement()`来构建任务元素。

# 排队更改

现在，我们已将用户控件绑定到数据模型，并在每次进行更改时自动保存。不过，这样做有一个问题。像`number`或`time`类型的输入控件，这些控件与微调按钮相关联，每次单击微调按钮时都会触发`change`事件。如果用户按住微调按钮，它将以惊人的速度触发`change`事件。这将反过来在非常短的时间内重复将任务列表保存到`localStorage`。这似乎不是一件非常有效的事情，特别是如果您有大量数据。

# 行动时间-延迟保存

### 注意

请参阅`第三章\示例 3.3`中的代码。

我们可以通过延迟保存到`localStorage`一段时间来缓解这个问题，以等待所有用户交互完成。使用 JavaScript 的`setTimeout()`函数很容易实现这一点。我们将在`saveTaskList()`方法中进行此更改，但首先我们需要在`TaskAtHandApp`对象中设置一个全局变量，以跟踪`setTimeout()`返回的超时 ID：

```html
function TaskAtHandApp()
{
    var version = "v3.3",
        appStorage = new AppStorage("taskAtHand"),
        taskList = new TaskList(),
        timeoutId = 0;
```

当更改待保存时，我们希望在页面底部的状态元素中显示消息，以便用户知道他们的更改将被保存。当实际保存发生时，我们将更新消息并使其淡出，以便用户知道保存已完成。为此，我们需要重写`setStatus()`方法：

```html
function setStatus(msg, noFade)
{
    $("#app>footer").text(msg).show();
    if (!noFade)
    {
        $("#app>footer").fadeOut(1000);
    }
}
```

我们添加了一个可选的`noFade`参数。当设置为`true`时，消息将不会淡出。否则，我们使用 jQuery 的`fadeOut()`方法在 1000 毫秒或一秒内逐渐淡出消息。现在让我们更新`saveTaskList()`方法：

```html
function saveTaskList()
{
    if (timeoutId) clearTimeout(timeoutId);
    setStatus("saving changes...", true);
    timeoutId = setTimeout(function()
    {
        appStorage.setValue("taskList", taskList.getTasks());
        timeoutId = 0;
        setStatus("changes saved.");
    },
    2000);
}
```

我们首先检查`timeoutId`变量是否有值，以查看是否已经有保存待处理。如果有，我们将使用 JavaScript 的`clearTimeout()`函数取消超时。这样做的效果是，如果用户在保存待处理时进行其他更改，所有更改将被排队并一次性保存。

接下来，我们使用`setTimeout()`设置一个新的超时。`setTimeout()`函数接受要执行的函数和等待执行该函数的毫秒数。它返回一个超时 ID，我们将其存储在`timeoutId`变量中，以防以后需要取消超时。

在 2000 毫秒或两秒的不活动后，任务列表将被保存。然后我们重置`timeoutId`变量，因为我们的超时已经结束。最后，我们调用`setStatus()`告诉用户更改已保存。

## *刚刚发生了什么？*

我们使用 JavaScript 的`setTimeout()`函数来有效地排队更改，这样当值快速变化时，我们不会不断保存任务列表。

## 尝试一下

就这样；我们的任务列表应用程序已经完成，至少在这本书中是这样。现在去添加你自己的功能，使它变得更好。例如，添加更多的任务字段，比如一个文本区域来输入备注。也许在工具栏中添加一个选项来隐藏已完成的任务。尝试添加一个排序选项，按名称、状态或日期对列表进行排序。

## 弹出测验

Q1\. 如果浏览器不支持新的 HTML5 输入类型会发生什么？

1.  输入字段未显示。

1.  该字段显示为文本字段。

1.  该字段设置为只读。

1.  浏览器显示错误消息。

Q2\. 自定义数据属性可以用在什么样的元素上？

1.  只有表单输入元素。

1.  只有块级元素。

1.  只有内联元素。

1.  任何元素。

# 总结

在本章中，我们看了一些更有用的 HTML5 输入类型。我们使用这些输入类型为每个任务创建了一个可折叠的任务详情部分。然后我们使用自定义数据属性来实现简单的数据绑定，将视图中的输入字段映射到数据模型。

在本章中，我们涵盖了以下概念：

+   如何以及何时使用新的 HTML5 输入类型

+   如何使用自定义数据属性在 DOM 中存储私有数据

+   如何使用自定义数据属性实现数据绑定，将数据模型绑定到表单控件

+   如何使用 jQuery 动画方法隐藏和显示元素

+   如何使用定时器延迟保存到`localStorage`，使应用程序更加响应

在下一章中，我们将朝着一个全新的方向前进。我们将看看 HTML5 画布元素和 API，并编写一个使用它的全新应用程序。
