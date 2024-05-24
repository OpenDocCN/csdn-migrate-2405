# JavaScript 测试入门指南（一）

> 原文：[`zh.annas-archive.org/md5/BA61B4541373C00E412BDA63B9F692F1`](https://zh.annas-archive.org/md5/BA61B4541373C00E412BDA63B9F692F1)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 序言

在今天 Web 2.0 的世界中，JavaScript 是网络开发的重要部分。尽管市场上有很多 JavaScript 框架，但学会在没有框架帮助的情况下编写、测试和调试 JavaScript，会使你成为一个更好的 JavaScript 开发者。然而，测试和调试可能既耗时又繁琐，令人痛苦。这本书将通过提供各种测试策略、建议和工具指南，让你的测试变得顺畅和简单，从而减轻你的烦恼。

本书采用易于跟随的、逐步的教学风格，以便最大化你的学习。你将首先学习到你作为 JavaScript 开发者最常遇到的不同的错误类型。你还将通过我们易于跟随的示例，学习到 JavaScript 的最重要特性。

随着学习，你将通过验证学会如何编写更好的 JavaScript 代码；仅仅学习如何编写验证过的代码就会极大地提高你作为 JavaScript 开发者的能力，最重要的是，帮助你编写运行得更好、更快、且错误更少的 JavaScript 代码。

随着我们的 JavaScript 程序变得更大，我们需要更好的方法来测试我们的 JavaScript 代码。你将学习到各种测试概念以及如何在你的测试计划中使用它们。之后，你将学习如何为你的代码实施测试计划。为了适应更复杂的 JavaScript 代码，你将了解更多关于 JavaScript 的内置特性，以便识别和捕捉不同类型的 JavaScript 错误；这些信息有助于找到问题的根源，从而采取行动。

最后，你将学习如何利用内置浏览器工具和其他外部工具来自动化你的测试过程。

# 本书内容涵盖

第一章，*什么是 JavaScript 测试？*，涵盖了 JavaScript 在网络开发中的作用以及 HTML 和 CSS 等基本构建模块。它还涵盖了您最常见到的错误类型。

第二章，*JavaScript 中的即兴测试和调试*，介绍了我们为何要为我们的 JavaScript 程序进行即兴测试，并通过编写一个简单的程序，介绍 JavaScript 最常用的特性。这个程序将作为一个例子，用于执行即兴测试。

第三章，*语法验证*，介绍了如何编写验证过的 JavaScript。完成这一章后，您将提高作为 JavaScript 开发者的技能，同时理解更多关于验证在测试 JavaScript 代码中的作用。

第四章，*规划测试*，介绍了制定测试计划的重要性，以及我们在执行测试时可以使用的策略和概念。本章还涵盖了各种测试策略和概念，我们将通过一个简单的测试计划来看看制定测试计划意味着什么。

第五章，*将测试计划付诸行动*，紧接着第四章，我们应用我们已经制定的简单测试计划。最重要的是，我们将通过揭示错误、记录并应用我们在第四章中学到的理论来修复错误。

第六章，*测试更复杂的代码*，介绍了测试我们代码的高级方法。测试代码的一种方式是使用 JavaScript 提供的内置错误对象。本章还介绍了如何使用控制台日志，如何编写自己的消息，以及如何捕获错误。

第七章，*调试工具*，讨论了我们的代码变得太大而复杂，无法使用手动方法进行测试的情况。我们现在可以利用市场上流行浏览器提供的调试工具，包括 Internet Explorer 8、FireFox 3.6、Chrome 5.0、Safari 4.0 和 Opera 10.

第八章，*测试工具*，介绍了你可以使用免费、跨浏览器和跨平台的测试工具来自动化你的测试。它还涵盖了如何测试你的界面，自动化测试，以及进行断言和基准测试。

# 本书所需准备

像 Notepad++这样的基本文本编辑器。

浏览器，如 Internet Explorer 8、Google Chrome 4.0、Safari 4.0 和更新版本、FireFox 3.6。

JavaScript 版本 1.7 或更高版本。

其他涉及到的软件还包括 Sahi、JSLitmus 和 QUnit。

# 本书面向人群

本书适合初学者 JavaScript 程序员，或者可能只有少量使用 JavaScript 经验的初学者程序员，以及希望学习 HTML 和 CSS 的人。

# 约定

在本书中，你会发现几个频繁出现的标题。

为了清楚地说明如何完成一个程序或任务，我们使用：

# 动手时间—标题

1.  行动 1

1.  行动 2

1.  行动 3

说明往往需要一些额外的解释，以便它们有意义，所以它们后面跟着：

## 刚才发生了什么？

这个标题解释了你刚刚完成的工作或指令的工作原理。

你还会发现书中有一些其他的学习辅助工具，包括：

## 互动测验—标题

这些是旨在帮助你测试自己理解程度的简短多项选择题。

## 试一试英雄—标题

这些部分设定了实际挑战，并给你提供了一些实验你学到的内容的点子。

你还会发现有一些文本样式，用于区分不同类型的信息。以下是一些这些样式的示例及其含义解释。

文本中的代码词汇如下所示展示："我们可以通过使用`include`指令包含其他上下文。"

一段代码如下所示：

```js
<input type="submit" value="Submit"
onclick="amountOfMoneySaved(moneyForm.money.value)" />
</form>
</body>
</html>

```

当我们要引您注意代码块中的某个特定部分时，相关的行或项目会被加粗：

```js
function changeElementUsingName(a){
var n = document.getElementsByName(a); 
for(var i = 0; i< n.length; i++){
n[i].setAttribute("style","color:#ffffff");
}
}

```

**新术语**和**重要词汇**以粗体显示。例如，您在屏幕上、菜单或对话框中看到的词汇，在文本中会这样显示："点击**下一页**按钮将您带到下一页"。

### 注意

警告或重要说明会以这样的盒子形式出现。

### 注意

技巧和窍门会这样展示。

# 读者反馈

我们总是欢迎读者的反馈。告诉我们您对这本书的看法——您喜欢或可能不喜欢的地方。读者的反馈对我们来说非常重要，以便我们开发出您真正能从中获得最大收益的标题。

要给我们发送一般性反馈，只需发送一封电子邮件到`<feedback@packtpub.com>`，并在您消息的主题中提到书名。

如果您需要一本书，并希望我们出版，请通过[www.packtpub.com](http://www.packtpub.com)上的**建议一个标题**表单给我们发个消息，或者发送电子邮件到`<suggest@packtpub.com>`。

如果您在某个主题上有专业知识，并且您有兴趣撰写或为书籍做出贡献，请查看我们作者指南中的[www.packtpub.com/authors](http://www.packtpub.com/authors)。

# 客户支持

现在您已经成为 Packt 书籍的骄傲拥有者，我们有很多事情可以帮助您充分利用您的购买。

### 注意

**下载本书的示例代码**

您可以从您在[`www.PacktPub.com`](http://www.PacktPub.com)账户上下载您购买的所有 Packt 书籍的示例代码文件。如果您在其他地方购买了这本书，您可以访问[`www.PacktPub.com/support`](http://www.PacktPub.com/support)并注册，以便将文件直接通过电子邮件发送给您。

## 错误

虽然我们已经尽一切努力确保我们内容的准确性，但是错误仍然会发生。如果您在我们的某本书中发现了一个错误——可能是文本或代码中的错误——如果您能向我们报告，我们将非常感激。这样做，您可以节省其他读者不必要的挫折，并帮助我们改进本书的后续版本。如果您发现任何错误，请通过访问[`www.packtpub.com/support`](http://www.packtpub.com/support)，选择您的书，点击**让我们知道**链接，并输入您错误的详情。一旦您的错误得到验证，您的提交将被接受，错误将被上传到我们的网站，或添加到该标题的错误部分现有的错误列表中。您可以通过从[`www.packtpub.com/support`](http://www.packtpub.com/support)选择您的标题来查看现有的错误。

## 盗版

互联网上侵犯版权材料的问题持续存在，遍布所有媒体。在 Packt，我们对保护我们的版权和许可非常重视。如果您在互联网上以任何形式发现我们作品的非法副本，请立即提供给我们位置地址或网站名称，这样我们可以采取补救措施。

请通过`<copyright@packtpub.com>`联系我们，并提供疑似侵权材料的链接。

我们感谢您在保护我们的作者，以及我们为您提供有价值内容的能力方面所提供的帮助。

## 问题

如果您在阅读本书的任何方面遇到问题，可以通过`<questions@packtpub.com>`联系我们，我们会尽力解决。


# 第一章：什么是 JavaScript 测试？

> 首先，请允许我欢迎你拿起这本书。如果你拿起这本书，我会假设你对 JavaScript 测试感兴趣。你很可能会经历 JavaScript，希望通过学习如何测试你的 JavaScript 程序来提高你的技能。
> 
> JavaScript 通常与网络浏览器关联，是创建网页上交互元素的关键工具之一。然而，与 PHP、Python 等服务器端语言不同，JavaScript 通常默默失败（尽管像 IE 这样的浏览器有时会提供警告信息）；没有错误信息告诉你发生了错误。这使得调试变得困难。
> 
> 通常，我们将学习关于 JavaScript 测试的基本构建块。这包括**HTML（超文本标记语言）**、**CSS（层叠样式表）**和 JavaScript 的基础知识。之后，你将学习各种技术使 HTML、CSS 和 JavaScript 协同工作；这些技术是你在其他章节中要学习的内容的基础。

更具体地说，我们将在本章中学习以下内容：

+   HTML、CSS 和 JavaScript 的基础

+   HTML、CSS 和 JavaScript 的语法

+   如何使用 CSS 和 JavaScript 选择 HTML 元素？

+   网页为什么需要在没有 JavaScript 的情况下工作？

+   测试是什么，为什么你需要测试？

+   什么是错误？

+   JavaScript 错误的类型

本章中示例很简单——它们旨在让你看到主要语法和正在使用的内置方法或函数。在本章中，代码将最少；你会被要求输入代码。之后，我们将简要回顾代码示例，看看发生了什么。

带着这个想法，我们将立即开始。

# JavaScript 在网页中占有什么位置？

每个网页都由以下属性组成——内容、外观和行为。这些属性分别由超文本标记语言（HTML）、层叠样式表（CSS）和 JavaScript 控制。

## HTML 内容

HTML 代表超文本标记语言。它是网页的主导标记语言。通常，它控制网页的内容。HTML 通过`<head>`、`<body>`、`<form>`和`<p>`等语义标记来定义网页（或 HTML 文档），以控制标题、文档主体、表单、段落等。你可以把 HTML 看作是一种描述网页应该看起来怎样的方式。

HTML 使用标记标签，这些标签通常成对出现。HTML 的语法如下：

`<name-of-html-tag>` 你的内容可以在这里括起来 `</name-of-html-tag>`

请注意，**HTML**标签由尖括号括起来；**HTML**标签对以`<name-of-html-tag>`开头，以`</name-of-html-tag>`结尾。这个第二个**HTML**标签被称为闭合标签，它们在**HTML**标签前有一个斜杠。

以下是一些常见的 HTML 元素：

+   `<head> </head>`

+   `<body> </body>`

+   `<title> </title>`

+   `<p> </p>`

+   `<h1> </h1>`

+   `<a> </a>`

要查看完整的 HTML 元素列表，请访问[`www.w3schools.com/tags/default.asp`](http://www.w3schools.com/tags/default.asp)。

# 行动时间—构建一个 HTML 文档

我们将通过使用上面看到的 HTML 标签和语法来创建一个 HTML 文档。（你在这里看到的示例可以在`Chapter 1`的源代码文件夹中找到，文档名为`chapter1-common-html.html`）

1.  首先，打开你最喜欢的文本编辑器或工具，比如微软记事本，然后创建一个新文档。

1.  将以下代码输入到你的新文档中并保存。

    ```js
    <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
    <html >
    <head>
    <title>This is a sample title</title>
    </head>
    <body>
    <h1>This is header 1</h1>
    <h2>This is header 2</h2>
    <h3>This is header 3</h3>
    <p>This is a paragraph. It can be styled by CSS</p>
    <hr>
    <div style="position:absolute; background-color:black; color:#ffffff;top:10px;right:10px;border:solid 3px yellow; height:200px; width:200px;">Your content here</div>
    <div>
    <div>I am enclosed within a <i>div</i> tag. And it can be styled on a document level.
    <ol>
    <li>This is an ordered list and it is centered</li>
    <li>apple</li>
    <li>orange</li>
    <li>banana</li>
    </ol>
    <ul>
    <li>This is an unordered list. And it can be styled by CSS.</li>
    <li>apple</li>
    <li>orange</li>
    <li>banana</li>
    </ul>
    </div>
    <div>I am enclosed within a <i>div</i> tag. And it can be styled by CSS.
    <ol>
    <li>This is an ordered list and it is centered</li>
    <li>apple</li>
    <li>orange</li>
    <li>banana</li>
    </ol>
    <ul>
    <li>This is an unordered list. And it can be styled by CSS</li>
    <li>apple</li>
    <li>orange</li>
    <li>banana</li>
    </ul>
    <a href="#">This is a link. And it can be styled by CSS </a>
    </div>
    </div>
    </body>
    </html>

    ```

1.  最后，打开浏览器中的文档，你会看到类似以下屏幕截图的示例：

![行动时间—构建一个 HTML 文档](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-test-bgd/img/0004_01_1.jpg)

+   请注意右上角的黑色盒子。这是 CSS 工作的一个简单例子。这将在后面解释。

## 刚才发生了什么？

你刚刚使用更常见的**HTML**元素和**HTML**语法创建了一个 HTML 文档。

每个**HTML**标签都有特定的用途，正如你在浏览器中看到的结果一样。例如，你肯定注意到了`<h1>This is header 1</h1>`产生了最大的文本，`<h2>This is header 2</h2>`产生了第二大文本，依此类推。

`<ol> </ol>`代表有序列表，而`<ul> </ul>`代表无序列表（带有子弹点的列表）。

你应该注意到了`<div> </div>`的使用。这用于在 HTML 文档中定义一个部分。然而，`<div> </div>`的效果和力量只能在本章的下一部分看到。

但是等等，似乎我还没有对 HTML 做一个完整的介绍。没错。我没有介绍 HTML 元素的各个属性。所以让我们快速概述一下。

### 使用其属性样式化 HTML 元素

通常，HTML 元素的 core 属性包括`class, id, style`和`title`属性。你可以以以下方式使用这些属性：

```js
<div id="menu" class="shaded" style="..." title="Nice menu"> Your
content here </div>

```

注意，这四个属性可以同时使用。另外，属性的顺序无关紧要。

但我们还没有进行任何样式设计。样式只发生在`style`属性中。为了看到一个例子，请在之前的代码中`<body>`和`</body>`标签之间输入以下代码。

```js
<div style= "position:absolute; background-color:black;color:#ffffff;
top:10px;right:10px;border:solid 3px yellow; height:200px;
width:200px;">Your content here
</div>

```

你应该能看到一个 200px 乘 200px 的黑色盒子，带有黄色边框，位于浏览器窗口的右上角（如之前的屏幕截图所示）。以下是只显示黑色盒子的屏幕截图：

![使用其属性样式化 HTML 元素](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-test-bgd/img/0004_01_2.jpg)

通常，你指定的内联样式会操作`style`属性的样式属性，以使其看起来是你想要的样子。

只有`style`属性允许你设置 HTML 元素的样式。但这种方法只用于为元素指定内联样式。

如果你想知道`<title>`标签的作用，它实际上是一个指定元素额外信息的属性。这通常用在`<head>`标签内。如果你打开任何包含`<title>`标签的 HTML 文档，你会在浏览器的标签页或浏览器窗口的标题中找到这个标签的内容。

那么`id`属性和`class`属性是什么呢？我们将在下一节简要介绍这些内容。

### 为 HTML 元素指定 id 和 class 名称

通常，`id`属性和`class`属性允许 HTML 元素通过 CSS（我们将在本章后面介绍的层叠样式表）来设置样式。你可以把`id`属性和`class`属性看作是一个“名字”，或者是一种识别对应 HTML 元素的方法，这样如果这个“名字”被 CSS 引用，元素就会按照特定的 CSS 样式进行设置。此外，`id`属性和`class`属性经常被 JavaScript 引用以操纵一些 DOM（文档对象模型）属性等。

在本书的这一点上，你必须理解一个重要的概念：每个 HTML 元素的`id`属性在 HTML 文件中必须是唯一的，而`class`属性则不是。

## 层叠样式表

CSS 代表层叠样式表。CSS 用于控制网页的布局、外观和格式。CSS 是你指定 HTML 元素风格化外观的方法。通过 CSS，你可以定义字体、颜色、大小，甚至是 HTML 元素的布局。

如果你注意到了，我们还没有向我们的 HTML 文档添加任何形式的 CSS 样式；在前面的截图中，你所看到的是我们浏览器的默认 CSS（除了右上角的黑色盒子），大多数浏览器如果没有定义特定的 CSS，都会有相同的默认 CSS。

CSS 可以是内部的或外部的；内部 CSS 通过`<style>`标签嵌入 HTML 文档中，而外部 CSS 则通过`<link>`标签链接，例如：

```js
<link rel="stylesheet" type="text/css" href="style.css">.

```

通常，使用内部 CSS 被认为是一种不好的实践，应该避免。与内部 CSS 相比，外部 CSS 更受欢迎，因为它可以节省我们的时间和精力，我们只需更改`.css`文件即可更改网站的设计，而不需要对每个 HTML 文档进行单独的更改。它还有助于提高性能，因为浏览器只需下载一个 CSS 并将其缓存在内存中。

本节最重要的点是 CSS 选择器的使用和 CSS 的语法。

CSS 选择器的工作方式如下：选择 ID 时，ID 的名称前面有一个井号字符。对于类选择器，它前面有一个点号。在你稍后看到的代码中，你会看到同时使用了 ID 和类选择器（在源代码中也进行了注释）。以下是选择器的一个快速预览：

```js
/* this is a id selector */
#nameOfID {
/* properties here*/
}
/* this is a class selector */
.nameOfClass {
/* properties here*/
}

```

CSS 的语法如下：选择器 { 声明 } . 声明由分号分隔的一组名称或值属性对组成，其中冒号将名称与值分隔开。

记得我们在上一节提到了`id`属性 和 `class`属性吗？现在你将看到 CSS 是如何使用`id`属性和`class`属性的。

# 动手时间—使用 CSS 样式化你的 HTML 文档

现在我们将继续样式化我们在上一节创建的 HTML 文档，使用 CSS。为了简单起见，我们将使用内部 CSS。在本节中，你将看到 CSS 语法在实际工作中的应用，以及它是如何通过利用相应 HTML 元素的`id`属性和`class`属性来样式化每个 HTML 元素的。注意这个例子中同时使用了`id`和`class`选择器。

### 注意

这个例子完成版本可以在`Chapter 1`的源代码文件夹中找到，文件名为：`chapter1-css-appearance.html`

1.  接着上一个例子，打开你的文本编辑器，在`</title>`标签后插入以下代码：

    ```js
    <style type="text/css">
    body{
    background-color:#cccccc;
    }
    /* Here we create a CSS selector for IDs by a name preceded by a hash character */
    #container{
    width:750px; /* this makes the width of the div element with the id 'container' to have a width of 750px */
    height:430px;
    border:1px solid black;solid 1px black;
    }
    /* #[nameOfElement] */
    #boxed1{
    background-color:#ff6600;
    border:2px solid black;
    height:360px;
    width:300px;
    padding:20px;
    float:left;
    margin:10px;
    }
    #boxed2{
    HTML documentstyling, CSS usedbackground-color:#ff6600;
    border:2px solid black;
    height:360px;
    width:300px;
    padding:20px;
    float:left;
    margin:10px;
    }
    #ordered1{
    font-size:20px;
    color:#ce0000;
    text-align:center;
    }
    #unordered1{
    font-size:12px;
    color:#000f00;
    }
    #ordered2{
    font-size:20px;
    color:#ce0000;
    text-align:center;
    }
    #unordered2{
    font-size:12px;
    color:#000f00;
    }
    #unordered2.nice{
    font-size:16px;
    }
    .intro{
    color:black;
    font-weight:bold;
    }
    a:link {color:#FF0000;} /* unvisited link */
    a:visited {color:#00FF00;} /* visited link */
    a:hover {color:#FF00FF;} /* mouse over link */
    a:active {color:#0000FF;} /* selected link */
    </style>

    ```

1.  在添加上面的 CSS 代码后，你需要为你 的 HTML 元素添加`class`和`id`属性。你需要添加的内容如下：

    ```js
    <! - Some code omitted above -- >
    <body>
    <! - Some code omitted -- >
    <p class="intro">This is a paragraph. I am styled by a class called "intro"</p>
    <hr>
    <div id="container">
    <div id="boxed1">I am enclosed within a <i>div</i> tag. And I can be styled on a document level.
    <ol id="ordered1">
    <li>This is an ordered list and it is centered</li>
    <li>apple</li>
    <li>orange</li>
    <li>banana</li>
    </ol>
    <ul id="unordered1">
    <li>This is an unordered list.</li>
    <li>apple</li>
    <li>orange</li>
    <li>banana</li>
    </ul>
    <a class="link" href="#">I am a link that is styled by a class</a>
    </div>
    <div id="boxed2">I am enclosed within a <i>div</i> tag. And I am styled on a local level.
    <ol id="ordered2">
    <li>This is an ordered list and it is centered</li>
    <li>apple</li>
    <li>orange</li>
    <li>banana</li>
    </ol>
    <ul class="nice" id="unordered2">
    <li>This is an unordered list and I have a class defined</li>
    <li>apple</li>
    <li>orange</li>
    <li>banana</li>
    </ul>
    <a class="link" href="#">I am a link that is styled by a class</a>
    </div>
    </div>
    </body>
    </html>

    ```

    需要添加的`class`和`id`属性在上面的代码片段中突出显示。如果你不确定自己是否做得正确，打开`chapter1-css-appearance.html`看看。

1.  现在保存文件，并在浏览器中打开它。你应该看到你的 HTML 文档现在看起来与使用 CSS 样式化之前不同。你的输出应该与下面示例中的截图类似：

![动手时间—使用 CSS 样式化你的 HTML 文档](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-test-bgd/img/0004_01_3.jpg)

## 刚才发生了什么？

你刚刚在你上一节创建的 HTML 文档中应用了 CSS。注意你同时使用了`id`选择器和`class`选择器语法。在每个选择器内部，你也应该看到一些样式属性。

这个例子中的 HTML 元素与上一个例子相似，不同之处在于现在的 HTML 元素具有`id`和`class`名称。

在下面的子部分中，我将继续解释引用各种 HTML 元素的技术，以及我们如何通过使用它们的样式属性来设置元素样式。

### 通过它的 id 或 class 名称引用 HTML 元素并对其进行样式设置

我们引用了各种 HTML 元素的`id`或`class`名称。考虑上面例子中的以下代码片段：

```js
<! some code omitted above-->
<p class="intro">This is a paragraph. I am styled by a class called "intro"</p>
<! some code omitted -->
<div id="boxed">This is enclosed within a <i>div</i> tag. And it is styled on a local level.
<ol id="ordered1">
<li>This is an ordered list and it is centered</li>
<li>apple</li>
<li>orange</li>
<li>banana</li>
</ol>
<ul class="nice" id="unordered1">
<li>This is an unordered list and has a class defined</li>
<li>apple</li>
<li>orange</li>
<li>banana</li>
</ul>
<a class="link" href="#">This is a link that is styled by a class</a>
</div>

```

高亮的代码指的是使用`id`和`class`名称属性的 HTML 元素。注意有些 HTML 元素同时具有`id`和`class`名称属性，而有些则没有。

现在考虑这个 CSS 代码段，它出现在示例中：

```js
#boxed1{
background-color:#ff6600;
border:2px solid black;
height:360px;
width:300px;
padding:20px;
float:left;
margin:10px;
}

```

`#boxed1`选择器指的是 HTML 文档中的`<div>`元素，其 id 为`#boxed1`。注意，具有 id 为`#boxed1`的`<div>`元素是根据声明中的名称和值属性对进行样式的。如果你更改值属性并刷新你的浏览器，你将注意到`#boxed1`元素也发生了变化。

现在，考虑以下 CSS 代码段：

```js
.intro{
color:black;
font-weight:bold;
}

```

以及：

```js
a:link {color:#FF0000;} /* unvisited link */
a:visited {color:#00FF00;} /* visited link */
a:hover {color:#FF00FF;} /* mouse over link */
a:active {color:#0000FF;} /* selected link */

```

前两个代码段是我们所说的`class`选择器，它们的语法与`id`选择器略有不同。例如，`.intro`类选择器选择类名称为“intro”的`<p>`元素，而`a:link`、`a:visited`、`a:hover`和`a:active`选择器指的是锚点的四种状态。

到目前为止，我们已经介绍了 CSS 选择器如何选择 HTML 文档中的 HTML 元素。但我们还没有涉及到 HTML 元素同时具有`id`和`class`属性的情况，现在我们来解释一下。

### 类选择器和 id 选择器之间的区别

尽管`id`选择器和`class`选择器看起来一样，但它们之间有一些细微的差别。例如，`id`选择器用于指定一个 HTML 元素，而`class`选择器用于指定几个 HTML 元素。

例如，你可以尝试将锚元素`<a class="link" href="#">`更改为`<a class="`**intro**`" href="#">`，你会注意到链接现在变成了粗体。

### 注意

如果一个 HTML 元素有一个由`id`和`class`选择器控制的样式属性，那么`class`选择器中的样式属性将优先于`id`选择器中的样式属性。

### 类选择器和 id 选择器的其他用途

在下面的章节中，你将了解到 HTML 元素的`id`和`class`名称在网页上提供交互性方面起着重要作用。这是通过使用 JavaScript 实现的，JavaScript 通过其`id`或`class`名称来引用 HTML 元素，之后对引用的 HTML 元素执行各种操作，如 DOM 操作。

### CSS 属性的完整列表

这里给出的例子不完整。要获取 CSS 的完整参考，你可以访问[`www.w3schools.com/css/css_reference.asp`](http://www.w3schools.com/css/css_reference.asp)。

## JavaScript 为网页提供行为

在本节中，我们将介绍 JavaScript 的一些关键方面。总的来说，如果 HTML 为 HTML 文档提供内容，而 CSS 为 HTML 文档设置样式，那么 JavaScript 通过为网页提供行为来赋予 HTML 文档生命。

行为可以包括动态改变 HTML 文档的背景颜色，或者改变文本的字体大小等等。JavaScript 甚至可以用来创建如动画幻灯片、淡入淡出效果等效果。

通常，行为是基于事件的，通过实时操作 DOM 来实现（至少从用户的角度来看）。

如果你对 JavaScript 还不太熟悉，JavaScript 是一种具有面向对象能力的解释型编程语言。它是一种松散类型的语言，这意味着你在声明变量或函数时不需要定义数据类型。

在我看来，理解 JavaScript 语言特性最好的方式是通过一个例子。现在，是时候动手了。

# 动手时间—给你的 HTML 文档添加行为

我们将把 JavaScript 应用到一个带有 CSS 样式的 HTML 文档上。与之前的例子相比，HTML 元素和 CSS 一般来说没有太大变化，除了你会在 HTML 文档中看到 HTML 按钮。

这个例子中应用到 HTML 文档上的 JavaScript 被称为内联 JavaScript，因为它存在于 HTML 文档中。

我们在这里要展示的是如何声明变量、函数，如何操作 HTML 元素的 DOM，以及如何通过它们的`id`或`class`来引用 HTML 元素。你还将学习到数组的一些常用内置方法，以及如何引用这些元素，从而使你的任务变得更简单。

这个例子并不复杂，但你将学习到一些最重要的、用于引用 HTML 元素并操作 DOM 的常用技术。

### 注意

（这个例子完整的代码可以在源代码文件夹`Chapter 1`中找到，文件名为：`chapter1-javascript-behavior.html`）：

1.  继上一个例子之后，在`</style>`标签后输入以下 JavaScript 代码：

```js
<script type="text/javascript">
function changeProperties(d){
var e = document.getElementById(d);
e.style.position = "absolute";
e.style.fontFamily = "sans-serif";
e.style.backgroundColor = "#000000";
e.style.border = "solid 2px black";
e.style.left = "200px";
e.style.color = "#ffffff";
}
function arrangeList(f) {
// This is the element whose children we are going to sort
if (typeof f == "string"){ // check to see if the element is "string"
f = document.getElementById(f);
}
// Transfer the element (but not text node) children of e to a real array
var listElements = [];
for(var x = f.firstChild; x != null; x = x.nextSibling)
if (x.nodeType == 1){
listElements.push(x);
}
listElements.sort(function(n, m) { // .sort is a built in method of arrays
var s = n.firstChild.data;
var t = m.firstChild.data;
if (s < t){
return -1;
}
else if (s > t){
return 1;
}
else{
return 0;
}
});
for(var i = 0; i < listElements.length; i++){
f.appendChild(listElements[i]);
}
}
function insertContent(a){
var elementToBeInserted = document.getElementById(a);
elementToBeInserted.innerHTML = "<h1>This is a dynamic content</h1><br><p>great to be here</p>";
}
function changeElementUsingName(a){
var n = document.getElementsByName(a);
for(var i = 0; i< n.length; i++){
n[i].setAttribute("style","color:#ffffff");
}
}
function hideElement(a){
var header = document.getElementById(a);
header.style.visibility = "hidden";
}
function hideElementUsingTagName(a){
var n = document.getElementsByTagName(a);
for(var i = 0; i< n.length; i++){
n[i].setAttribute("style","visibility:hidden");
}
}
</script>

```

+   现在保存你的文档并在浏览器中加载它，你会看到一个与下一张截图类似的示例：

![动手时间—给你的 HTML 文档添加行为](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-test-bgd/img/0004_01_4.jpg)

## 刚才发生了什么？

你已经创建了一个带有 CSS 样式的 HTML 文档，并向其应用了 JavaScript。与之前的例子相比，HTML 元素和 CSS 一般来说没有太大变化，但你将会看到`<button>`元素。

通过点击 HTML 按钮，你可以看到 JavaScript 的强大作用。你会发现如果你点击了**改变属性**按钮，你将看到右侧的 HTML 盒子向左移动了 200 像素，其背景颜色也发生了变化。你还可以点击其他按钮来测试它们对 HTML 文档的影响。

当你点击每个 HTML 按钮时，你正在调用一个 JavaScript 函数，通过 DOM 操纵文档中的相关 HTML 元素。你应该看到诸如隐藏内容、创建动态内容、重新排列项目列表等效果。

在以下部分中，我首先简要介绍了 JavaScript 语法，然后将事件附加到 HTML 元素上，最后使用 JavaScript 的内置方法来查找 HTML 元素并操作它们。

### JavaScript 语法

我们将从学习 JavaScript 的基本语法开始。考虑一下打开的`<script>`标签：

```js
<script type="text/javascript">
// code omitted
</script>

```

上述`<script>`标签的作用是确定 JavaScript 的开始和结束位置。在`type`属性内，我们写`text/javascript`以表示这是一个 JavaScript 代码。

现在，让我们考虑一下以下的代码片段：

```js
function arrangeList(f) {
if (typeof f == "string"){ // check to see if the element is "string"
f = document.getElementById(f);
}
var listElements = [];//declaring a variable
for(var x = f.firstChild; x != null; x = x.nextSibling)
if (x.nodeType == 1){
listElements.push(x);
}
listElements.sort(function(n, m) { // .sort is a built in method of arrays
var s = n.firstChild.data;
var t = m.firstChild.data;
if (s < t){
return -1;
}
else if (s > t){
return 1;
}
else{
return 0;
}
});
for(var i = 0; i < listElements.length; i++){
f.appendChild(listElements[i]);
}
}

```

上面的代码片段显示了一个名为`arrangeList`的函数。我们通过使用保留关键字`function`后跟函数名称来定义一个函数。参数在`( )`内传递，在这个代码片段中，`f`是传递给函数的参数。函数从`a`开始{并在`a}`结束。

简而言之，函数语法可以定义如下：

```js
function functionname(parameter1, parameter2, ... parameterX){
Body of the function
}

```

第二个高亮行通过使用`if`语句展示了 JavaScript 中的决策制定。这个语法与 C 编程语言中的`if`语句相似。JavaScript 的`if`语句的语法如下：

```js
if (condition){
code to be executed if condition is true.
}

```

`if`语句的一个变体是**if-else**。

```js
if (condition){
code to be executed if condition is true.
}
else{
code to be executed if condition is not true.
}

```

我们使用关键字`var`后跟一个变量名。在上面的例子中，`var listElements = []`；意味着定义了一个名为`listElements`的变量，并给它一个表示空列表的`[]`值。通常，由于 JavaScript 是松散类型的，变量可以被赋予任意值。

继续上面的内容，你应该看到`for`循环在起作用。它的语法也与 C 语言的`for`循环相似。

如果你是 JavaScript 的新手，`document.getElementById()`和`listElements.push(x)`之类的语句可能会让你感到困惑。这两行代码中发生的事情是我们使用了 JavaScript 的一些内置方法来引用具有相应 ID 的 HTML 元素。现在，`document.getElementById()`对你来说将更重要；这将在你学习如何在 HTML 文档中查找元素的部分进行介绍。

### javascript 事件

首先，让我们来看一下你 JavaScript 中找到的以下代码片段：

```js
<button onclick="changeProperties('boxed1')">change properties</button>
<button onclick="insertContent('empty')">Create dynamic content</button>
<button onclick="arrangeList('ordered1')">Rearrange list</button>
<button onclick="arrangeList('unordered1')">Rearrange unordered list</button>
<button onclick="hideElement('header1')">hide header 1</button>
<button onclick="changeElementUsingName('lost')">Change hyperlink colors</button>
<button onclick="hideElementUsingTagName('h2')">Hide header 2 (using tag name)
</button>

```

上面的代码片段显示了通过`onclick`附加到 HTML 按钮上的事件。当按钮被点击时，相应的 JavaScript 函数将被调用。

例如，`<button onclick="changeProperties('boxed1')">change properties</button>`意味着当这个按钮被点击时，`changeProperties()`函数将被调用，参数`boxed1`是一个具有`ID boxed1`的`div`元素。

### 在文档中查找元素

记住，我们已经看到了 JavaScript 的一些内置方法。JavaScript 可以通过使用一些内置方法或属性在 HTML 文档中查找元素。在找到 HTML 元素后，你可以操作它的属性。JavaScript 具有`Document`对象（DOM 树的根）的三个属性，可以让你找到所需的 HTML 元素。这里提到的技术是 JavaScript 测试的骨架。理解这一部分对理解本书的其余部分至关重要。所以，确保你理解了这一章节的内容。

首先，`document.getElementById()`。这个属性允许你通过特定的 ID 选择一个 HTML 元素。`document.getElementById()`只能返回一个元素，因为每个`id`属性的值都是（应该是）唯一的。以下是来自示例的代码片段：

```js
function changeProperties(d){
var e = document.getElementById(d); 
e.style.position = "absolute";
e.style.fontFamily = "sans-serif";
e.style.backgroundColor = "#000000";
e.style.border = "2px solid black";
e.style.left = "200px";
e.style.color = "#ffffff";
}

```

考虑上面代码片段中突出显示的行，`var e = document.getElementById(d)`。这里发生的是 HTML 元素'd'被引用，而'd'碰巧是`changeProperties()`函数的参数。如果你查看这个示例的源代码，你会看到一个 HTML 按钮，其内容为：`<button onclick="changeProperties('boxed1')">改变属性</button>`。注意'boxed1'正在被引用，这意味着参数'f'取值为'boxed1'的 HTML 元素 id。因此，`var e = document.getElementById(d)`意味着通过`document.getElementById()`方法将 ID 为'boxed1'的 HTML `div` 分配给变量`e`。

其次，注意`document.getElementsByName()`语句。这个方法和`document.getElementById()`类似，但它查看的是`name`属性而不是`id`属性。它返回一个元素的数组而不是一个单一的元素。考虑以下代码片段：

```js
function changeElementUsingName(a){
var n = document.getElementsByName(a); 
for(var i = 0; i< n.length; i++){
n[i].setAttribute("style","color:#ffffff");
}
}

```

这里发生的是通过名称'`a`'（碰巧是函数的参数）引用了 HTML 元素，并且因为返回的是元素数组，我们使用一个`for`循环遍历元素，并使用`.setAttribute`方法将文本颜色改为白色。`name`属性仅适用于`<form>`和`<a>`标签。

最后，看看`document.getElementsByTagName()`。这个方法通过 HTML 标签名称来查找 HTML 元素。例如，以下代码：

```js
function hideElementUsingTagName(a){
var n = document.getElementsByTagName(a); 
for(var i = 0; i< n.length; i++){
n[i].setAttribute("style","visibility:hidden");
}
}

```

通过标签名称查找 HTML 元素，并使其隐藏。在我们这个例子中，使用`h2`作为参数，因此当你点击相关按钮时，所有包含在`<h2>`标签中的文本都会消失。

现在，如果你将参数改为`div`，那么你会注意到所有的方框都会消失。

### 把所有内容放在一起

现在我将简要描述 JavaScript 如何与 HTML 元素交互。在本小节中，你会了解到：当 HTML 按钮被点击（一个事件）后，它调用一个 JavaScript 函数。然后，JavaScript 函数接收一个参数并执行该函数。考虑下面的代码片段。

以下是为带有事件的 HTML 按钮编写的代码：

```js
<button onclick="insertContent('empty')">Create dynamic content</button>code

```

接下来，以下是为 HTML `div` 元素编写的代码：

```js
<div id="empty"></div>

```

最后，以下是要调用的 JavaScript 函数的代码：

```js
function insertContent(a){
var elementToBeInserted = document.getElementById(a);
elementToBeInserted.innerHTML = "<h1>This is a dynamic content</h1><br><p>great to be here</p>";
}

```

现在，让我解释我们要在这里做什么；点击 HTML 按钮后，调用 JavaScript 函数`insertContent()`。参数'`empty`'被传递给`insertContent()`。'`empty`'指的是 ID 为'`empty`'的`div`元素。

在调用`insertContent()`后，参数'empty'被传递给变量`var elementToBeInserted`，通过使用`document.getElementById()`。然后，利用 HTML 元素节点的内置方法`innerHTML()`（因为 HTML 元素节点传递给了`elementToBeInserted`变量），我们动态地插入文本"`<h1>This `is a dynamic content</h1><br><p>great to be here</p>`"。

然后请在你的网页浏览器中打开文件，并点击 HTML 按钮。你会注意到新的一段文本被动态地插入到 HTML 文档中。

### 注意

HTML 元素节点的内置方法`innerHTML()`允许我们操纵（或者在这个例子中，动态插入）HTML 内容到使用`innerHTML()`方法的 HTML 节点中。例如，在我们的例子中，我们将`"<h1>This is a dynamic content</h1><br><p>great to be here</p>"`插入到`<div id="empty"></div>`中。技术上讲，插入后，最终结果将是：`<div id="empty"><h1>This is a dynamic content</h1><br><p>great to be here</p></div>`。

# JavaScript 与服务器端语言的区别

总的来说，JavaScript 与服务器端语言的主要区别在于它们的用途和执行位置。在现代应用中，JavaScript 在客户端（用户的网页浏览器）运行，而服务器端语言在服务器上运行，因此经常用来读取、创建、删除和更新 MySQL 等数据库。

这意味着 JavaScript 在网页浏览器上进行处理，而服务器端语言在网页服务器上执行。

服务器端语言包括 ASP.NET、PHP、Python、Perl 等。

在现代网络开发技术背景下，你可能已经听说过 Web 2.0 应用程序。一个重要的技术是 JavaScript 经常被广泛使用，以提供交互性并执行异步数据检索（有时是数据操作），这也被称作 AJAX（它是异步 JavaScript 和 XML 的缩写）。

JavaScript 不能用来与数据库交互，而像 PHP、Python 和 JSP 这样的服务器端语言可以。

JavaScript 也被称为前端，而服务器端则是后端技术。

### 注意

JavaScript 也可以用在服务器端，尽管它最常与客户端技术相关联。尽管 JavaScript 通常不与与数据库交互关联，但未来这种情况可能会改变。考虑像 Google Chrome 这样的新浏览器，它为 JavaScript 提供了与浏览器内建数据库交互的数据库 API。

# 为什么页面需要在没有 JavaScript 的情况下工作

虽然关于我们应该让网页在没有或具有 JavaScript 的情况下工作的争论有很多，但我个人认为，这取决于网站或应用程序的使用方式。不过无论如何，我将从一些页面需要在没有 JavaScript 的情况下工作的常见原因开始。

首先，并非所有用户都在网页浏览器中启用了 JavaScript。这意味着如果您的应用程序（或功能）需要 JavaScript，那么没有启用 JavaScript 的用户将无法使用您的应用程序。

其次，如果您打算支持移动设备上的用户，那么您需要确保您的网站或应用程序在没有 JavaScript 的情况下也能工作。主要原因是移动设备对 JavaScript 的支持往往不够满意；如果您使用 JavaScript，您的网站或应用程序可能不如预期工作（或者更糟，根本无法工作）。

另一个角度来看，这基于您对用户群体的理解。例如，大概唯一可以忽略那些禁用 JavaScript 的用户的情况是，当您可以保证或事先知道您的用户群体已启用 JavaScript 时。这种情况可能出现在您为内部使用开发应用程序时，您事先知道您的所有用户都已启用 JavaScript。

如果您在想如何创建在没有 JavaScript 的情况下也能工作的页面，您可以了解一下优雅降级（graceful degradation）的概念。想象一下，您有一个应用程序，该应用程序的核心功能是基于 AJAX 的。这意味着为了使用您的应用程序，您的用户需要启用 JavaScript。在这种情况下，您可能需要考虑让您的页面在没有 JavaScript 的情况下也能工作，以确保所有用户都能使用您的应用程序。

# 测试是什么？

一般来说，程序员在编写程序时会有一些目标。除了创建一个为解决特定问题或满足特定需求而编写的程序之外，其他常见目标还包括确保程序至少是正确的、高效的，并且可以容易地扩展。

在上文提到的目标中，正确性至少在这本书中是最重要的目标。我们所说的正确，是指对于任何给定的输入，我们需要确保输入是我们想要的或需要的，相应的输出也是正确的。这一点的隐含意义是指程序逻辑是正确的：它按照我们的意图工作，没有语法错误，引用的变量、对象和参数是正确的并且是我们需要的。

例如，一个用 JavaScript 编写的退休计划计算器。我们可能会期望用户输入诸如他们当前的年龄、退休年龄和每月储蓄等值。想象一下，如果用户输入错误的数据，比如字符串或字符。JavaScript 退休计划计算器将无法工作，因为输入数据是错误的。更糟糕的是，如果用户输入了正确的数据，而我们计算为退休设置 aside 的金额的算法是错误的，这将导致输出是错误的。

上述错误可以通过测试来避免，这是本书的主题。在本章剩余的部分，我们将讨论你作为 JavaScript 程序员可能遇到的一些错误类型。但在我们进入那个话题之前，我将简要讨论为什么我们需要测试。

# 为什么你需要测试？

首先且最重要的是，人类容易犯错误。作为一名程序员，你很可能在你编程生涯中犯过编码错误。即使地球上最优秀的程序员也犯过错误。更糟糕的是，我们可能直到测试程序时才发现错误。

第二，也许更重要的是，JavaScript 通常会默默失败；没有错误信息告诉你发生了什么错误，或者错误发生在哪里，假设你没有使用任何测试单元或工具来测试你的 JavaScript。因此，如果你 JavaScript 程序有错误，很难或根本没有办法知道发生了什么。

### 注意

在微软的 Internet Explorer 中，你实际上可以看到是否有任何 JavaScript 错误。你需要打开**脚本调试**，这在**工具** | **Internet 选项** | **高级** | **脚本调试**中找到。开启**脚本调试**后，如果你有任何 JavaScript 错误，你将在 IE7 或 IE8 的左下角看到一个黄色的'yield'图标。点击这个图标，你会得到一个窗口，你可以在其中点击**显示详细信息**来获取有关错误的更多信息。

第三，即使有方法可以通知你 JavaScript 错误，比如启用**脚本调试**，如上所述，但仍有某些错误是无法通过这些方法检测到的。例如，你的程序语法可能是一百分之一百的正确，但你的算法或程序逻辑可能是有误的。这意味着即使你的 JavaScript 可以执行，你的输出可能是错误的。

最后，测试 JavaScript 可以帮助你识别跨浏览器兼容性问题。因为大约有五种主要类型的浏览器（不计算不同版本）需要支持——即微软的 Internet Explorer、Mozilla 的 Firefox、谷歌的 Chrome、苹果的 Safari 和 Opera 网络浏览器——你肯定需要测试以确保你的网站或应用程序在所有浏览器上都能工作，因为不同的浏览器有不同的 DOM 兼容性。

确保程序正确意味着确认并检查输入是正确的，然后输出是我们期望的结果。

# 错误类型

在我开始介绍 JavaScript 错误之前，我们需要了解 JavaScript 和网页浏览器的工作原理。一般来说，用户从服务器请求一个网页文档，这个文档被加载到用户的网页浏览器中。假设这个网页文档中嵌入了 JavaScript（无论是通过外部 JavaScript 文件还是通过内联 JavaScript），JavaScript 将与网页文档一起被加载（从上到下）。当网页浏览器加载网页文档时，网页浏览器的 JavaScript 引擎将开始解释网页文档中嵌套的 JavaScript。这个过程将继续，直到 JavaScript（和网页文档）完全加载到用户的网页浏览器中，为交互做好准备。然后，用户可能开始通过点击可能附有 JavaScript 事件链接或按钮来与网页文档进行交互。

现在，带着上面的过程在心中，我们将开始介绍不同类型的 JavaScript 错误，通过使用简单的例子。

## 加载错误

我们首先讨论的错误类型是加载错误。加载错误是在文档加载过程中由网页浏览器的 JavaScript 引擎捕获的错误。

换句话说，加载错误发生在 JavaScript 有机会运行之前。这些错误通常在代码有机会执行之前被 JavaScript 引擎发现。

带着前面提到的事情在心中，现在让我们经历一下加载错误是如何发生的。

# 行动时间——加载错误的具体表现

现在我们将看到加载错误的具体表现。我们实际上并没有看到它，但你将学习到一些加载错误的最常见原因。

### 注意

这个例子的完整代码可以在源代码文件夹`第一章`中找到，文件名为`chapter1-loading-errors.html`

1.  打开你的文本编辑器并创建一个新文档。

1.  将以下代码输入到你的文档中：

    ```js
    <html>
    <head><title>JavaScript Errors - Loading Errors</title></head>
    <body>
    <script type="text/javascript">/*
    1\. Loading Errors
    */
    /*
    // Example 1 - syntax errors
    var tests = "This is a test"; // note two s
    document.write(test); // note one s
    */
    /*
    // Example 2 - syntax errors as the keyword "var" is not used
    Var Messsage = "This is a test"; // note three s's
    document.write(Message); // note two s's
    */
    /*
    // Example 3 - error caused by using a key word
    var for = "this is a test";
    document.write(in);
    */
    </script>
    </body>
    </html>

    ```

1.  现在，取消注释掉例子 1 周围的`/*`和`*/`，保存文档并在浏览器中加载它。你应该在你的网页浏览器中看到一个空白页面。

1.  重复上述步骤，对例子 2 和例子 3 也这样做。你应该看到例子 2 和例子 3 都是一个空白页面。

## 刚才发生了什么？

你刚刚创建了一个带有错误 JavaScript 代码的 HTML 文档。从代码中的注释，你应该意识到错误主要是由于语法错误引起的。当这种错误发生时，网页浏览器中的 JavaScript 没有任何响应。

常见的语法错误示例包括缺少括号、缺少分号和错误的变量名。

通常情况下，只要你的代码在语法上是正确的，那么你应该能够避免加载错误。

现在，你可能会问，如果 JavaScript 代码的某些部分是错误的会发生什么？这将取决于错误发生的地点。

### 部分正确的 JavaScript

通常情况下，JavaScript 是从上到下执行或加载的。这意味着首先加载第一行代码，然后是下一行，直到最后加载最后一行代码。这对部分正确的 JavaScript 有重要的影响。

# 行动时间——加载错误在行动中

现在我们将看到部分正确的 JavaScript 代码在行动中及其影响。

### 注意

这个示例的完整源代码可以在源代码文件夹中找到，文件名为`Chapter1-loading-errors-modified.html`。

1.  打开你的文本编辑器，创建一个新文档，将以下代码输入到你的文档中：

    ```js
    <html>
    <head><title>JavaScript Errors - Loading Errors</title></head>
    <body>
    <script type="text/javascript">/*
    1\. Loading Errors - modified
    */
    // this is correct code
    var tests = "This is a CORRECT test";
    document.write(tests);
    // this is incorrect code. The variable name referred is incorrect
    var Messsage = "This is a FIRSTtest";
    document.write(Message);
    // this is correct code
    var testing = "this is a SECOND test";
    document.write(testing);
    </script>
    </body>
    </html>

    ```

1.  现在保存你的文档并在你的网页浏览器中加载你的文档。你应该在浏览器中看到文字**这是一个测试在**。

## 刚才发生了什么？

如果你追踪代码，你应该看到 JavaScript 是从上到下执行的。当它遇到一个错误时，它会在`document.write()`中引用一个错误的变量名而停止执行。因为它在遇到错误时停止执行，所以剩下的 JavaScript 代码将不会被执行。

如果你的 JavaScript 代码是按照函数来组织的，那么情况会有所不同。在这种情况下，语法错误的函数将无法执行，而语法正确的函数将继续工作，无论其在代码中的顺序如何。

到现在为止，你应该对加载错误以及如何通过确保你的代码在语法上是正确的来防止它们有一个大致的了解。

现在让我们继续讨论下一类错误——运行时错误。

### 运行时错误

你还记得 JavaScript 是如何与网页文档一起加载到浏览器中的吗？在网页文档完全加载到网页浏览器后，它准备好响应各种事件，这也导致了 JavaScript 代码的执行。

运行时错误发生在执行过程中；例如，考虑一个带有 JavaScript 事件的 HTML 按钮。假设一个 JavaScript 函数被分配给了一个事件，那么如果 JavaScript 函数有错误，当用户点击 HTML 按钮时，该函数将不会被执行。

其他形式的运行时错误发生在你对对象、变量或方法误用，或者你引用了尚不存在的对象或变量时。

# 行动时间——运行时错误在行动中

现在我们将看到运行时错误的三个常见原因在行动。

### 注意

代码示例保存在第一章的源代码文件夹中，名为：`chapter1-runtime-errors.html`。

1.  打开你的文本编辑器，在新的文档中输入以下代码：

    ```js
    <html>
    <head><title>JavaScript Errors</title></head>
    <script type="text/javascript">/*
    2\. Runtime Errors
    */
    alert (window.innerHTML);
    var Test = "a variable that is defined";
    alert(Test); // if variables is wrongly typed, than nothing wil happen
    // nothing happens when the user clicks on the HTML button, which invokes the following function
    function incorrectFunction(){
    alert(noSuchVariable);
    }
    </script>
    <body>
    <input type="button" value="click me" onclick="incorrectFunction()" />
    </body>
    </html>

    ```

1.  保存文档，并将其加载到你的网页浏览器中。

1.  在将文档加载到浏览器后，你将看到两个警告框：第一个框显示**未定义**，第二个警告框显示**已定义的变量**。然后你会看到一个写着**点击我**的 HTML 按钮。

1.  点击按钮，你会发现什么也没有发生。

## 刚才发生了什么？

你所看到的第一个警告框显示了一个由方法误用引起的错误。`window.innerHTML`不存在，因为`.innerHTML`是应用于 HTML 元素，而不是`window`。第二个警告框显示一个在`alert()`引用它之前已定义的变量。最后，当你点击 HTML 按钮时，什么也不会发生，因为应该被调用的函数引用了未定义的变量。因此，在`onclick()`事件中没有执行。

在这个例子中，你应该意识到代码的逻辑非常重要，你需要在使用它们之前定义你的变量或对象。还要确保应用的方法或属性是正确的。否则，你最终会得到一个运行时错误。

现在，我们将进入 JavaScript 错误的最后一种形式——逻辑错误。

### 逻辑错误

逻辑错误很难解释。但一般来说，你可以将逻辑错误视为代码运作不符合你预期的方式时产生的错误。通过亲身体验逻辑错误，你更容易理解它们是什么。所以，让我们采取一些行动。

# 行动时间——逻辑错误在行动

在这个最后一个例子中，你会看到逻辑错误。

1.  打开你的文本编辑器，在新的文档中输入以下代码：

    ```js
    <html>
    <head><title>JavaScript Errors</title>
    <script type="text/javascript">
    /* Logic Errors */
    //saving some input in wrong variables
    function amountOfMoneySaved(amount){
    var amountSpent, amountSaved;
    amountSpent = amount; // where you really meant amountSaved
    var currentAmount = 100;
    var totalAmountSaved = currentAmount - amountSpent;
    alert("The total amount of money you have now is " +
    totalAmountSaved );
    }
    function checkInput(amount){
    if(amount>0 && amount<99)
    alert("is number");
    else
    alert("NOT number");
    }
    </script>
    </head>
    <body>
    <!-- this shows an infinite loop, an obvious logic error-->
    <script>
    // an infinite loop
    for(var i = 0; i<10; i--){
    document.write(i + "<br>");
    }
    </script>
    <form id="moneyForm">
    You currently have 100 dollars.
    The amount of money you have saved is: <input type="text" id="money" name="money" /><br />
    <input type="submit" value="Submit"
    onclick="amountOfMoneySaved(moneyForm.money.value)" />
    </form>
    </body>
    </html>

    ```

1.  现在，保存代码并在浏览器中打开文档。

1.  你会看到两个简单的表单。第一个表单包含文本：**您目前有 100 美元。您所拥有的金额是** " "，后面是一个输入框。第二个表单包含文本：**检查你是否输入了一个数字**，后面是一个输入框。

1.  现在尝试输入一个大于 99 的数字（比如，999）。

    你可能注意到了，在输入你的输入后，总金额似乎减少了。这是一个逻辑错误的例子，你应该将输入加起来，但函数却减去了输入。程序为什么没有按照预期的方式工作？

## 刚才发生了什么？

你刚刚见证了一个简单的逻辑错误行动例子。逻辑错误可以有多种形式。你可能注意到了上面例子中被注释掉的一段代码。

```js
<script type="text/javascript">// example 1: infinite loop
for(var i = 0; i<10; i--){
document.write(i + "<br>");
}
</script>

```

这是一个无限 `for` 循环的例子。在这个循环中，你可能会注意到语句 `document.write(i+<br>")`; 应该执行 10 次（从 `var i = 0` 到 `i = 9`）。然而，在 `for` 语句内的初始化器中的第三个表达式是递减的（`i--`）。

因此，变量 `i` 永远不可能达到 `i>10` 的条件。如果你取消注释代码，你会注意到语句 `document.write(i"<br>")`; 将会继续执行，直到网页浏览器挂起；如果你在 Windows 机器上使用 Firefox，网页浏览器将会挂起，你将不得不使用任务管理器退出浏览器。

# 一些编写无错误 JavaScript 的建议

到现在为止，你应该对 JavaScript 错误类型有一个大致的了解。虽然我们通常无法避免错误，但我们在编写代码时应该尽量减少错误。在本节中，我将简要讨论一些作为初学 JavaScript 程序员可以采取的策略，以最小化可能发生的错误量。

## 总是检查对象、变量和函数的正确名称

正如上面错误形式所看到的，你总是应该确保你正确地使用了对象、变量和函数的名称。因为这样的错误不会在你的网页浏览器中显示，当你编写**代码时，总是检查名称的正确使用是一个好主意**。

这还包括为不同的变量、对象和函数使用独特的名称。记住，JavaScript 是大小写敏感的；因此一定要记得检查你是否正确地使用了变量、对象和函数的大小写。

## 检查语法是否正确

因为你在使用 JavaScript，至少在这本书中，你应该在运行你的程序之前检查你是否使用了正确的语法。在此之前，我们讨论了语言语法的一些关键特性，例如，每个语句都以分号结束，使用正确和匹配的括号，使用正确或独特的函数名称等。

## 编码前规划

在实际编码过程之前的规划有助于减少逻辑错误的可能性。这有助于你仔细思考你的程序，并在代码中找出明显的逻辑错误。规划还可以帮助你检查盲点，例如缺失的功能或函数。

## 编写代码时检查正确性

在你编写程序的过程中，总是检查你在完成代码的某些部分时是否有错误是一个好主意。例如，如果你的程序由六个函数组成，总是明智（且减少错误）地检查每个函数的正确性。在移动到下一个函数之前，确保你编写的每个函数都是正确的是一个好习惯，这可以在你编写大型程序时节省你很多麻烦。

## 通过选择合适的文本编辑器来预防错误

我个人认为，一个合适的文本编辑器（或 IDE）是减少编码错误的关键步骤。请注意，我没有说你需要一个“好”的文本编辑器，而是需要一个“合适”的文本编辑器。这是因为不同的编程语言有不同的特性和不同的功能。

例如，如果您已经使用过 Python 编程，您会注意到您不需要具备检查匹配括号的能力，因为 Python 基于代码块（制表或空格来表示代码块）。然而，在 JavaScript 的情况下，您肯定需要您的文本编辑器帮助您检查匹配（或缺失）的括号。可以实现上述功能的代码编辑器包括 Dreamweaver（商业的）和 Eclipse（免费的）。

除了匹配括号检查之外，以下是一些在您使用 JavaScript 编码时将为您提供帮助的其他功能：

1.  自动制表或关键字后的空格或匹配括号：这将帮助您 visually inspect 代码结构，并将减少编码错误。

1.  自动完成或自动建议功能：这意味着当你输入代码时，编辑器足够智能，可以建议你程序中使用的一些单词（或代码），这样你就可以在编写代码时快速引用它们。这对于检查用户定义的变量、对象和函数特别有用。

1.  语法高亮：这将帮助您识别是否误用了任何关键字。还记得运行时错误吗？运行时错误可能由关键字的误用引起。如果您正在使用任何用户定义的变量、对象或函数的关键字，语法高亮将帮助您识别这一点。

# 总结

哇，我们在这一章中涵盖了好多内容。本章涵盖的大部分内容构成了我们后续章节需要使用的构建块。具体来说，我们介绍了以下主题：

+   我们在网页中学到了 HTML、CSS 和 JavaScript。总的来说，HTML 提供内容，CSS 为网络文档设置样式，JavaScript 为网页提供行为和交互性。

+   我们已经学习了 HTML、CSS 和 JavaScript 的语法。

+   我们已经学习了如何使用 ID 和类选择器的关键技术，以便 CSS 能够引用各种 HTML 元素，并对引用的 HTML 元素执行样式操作。

+   对于 JavaScript，我们学习了三种重要的技术，以便 JavaScript 能够引用 HTML 元素。这三种技术（或者说内置方法）是：`document.getElementById()`，`document.getElementsByName()`和`document.ElementsByTagName()`。

+   接下来，我们学习了测试以及为什么我们需要进行测试。总的来说，测试是为了确保程序正确运行——也就是说，对于给定的输入，我们得到正确的输出。此外，测试有助于发现语法错误，并确认程序以我们预期的方式运行。

+   我们讨论了 JavaScript 错误的类型，具体包括加载错误、运行时错误和逻辑错误。我们还讨论了每种错误类型的一些简单示例以及它们常见的原因。

+   我们讨论了一些编写无错误代码的重要技巧和建议。

现在我们已经介绍了 JavaScript 测试的基本构建块，你将看到我们如何利用它们来执行即兴测试，这将在下一章中介绍。你会注意到本章中使用的一些函数和内置方法将在下一章中使用。


# 第二章：JavaScript 中的随兴测试和调试

> 在本章中，我们将正式进入测试我们实际创建的 JavaScript 程序。但在我开始之前，我想向你简要介绍一下你可以期待在本章中看到的内容。在本章中，你将学习到两个主要概念，第一个概念是不同的浏览器如何影响 JavaScript 测试，第二个主要概念是你如何通过使用 alert()来测试你的 JavaScript 程序。你还将学习如何访问表单上的值，操作这些值，并最终以有意义的方式输出这些值。

你还将看到前一章中介绍的许多技术被广泛使用。

更具体地说，我们将学习以下主题：

+   随兴测试的目的

+   当浏览器遇到 JavaScript 错误时会发生什么

+   浏览器差异及需要在多个浏览器中测试的需求

+   常见的浏览器消息及其含义

+   如何找出你的代码是否得到了正确的输出，以及是否在代码中把正确的值放在了正确的位置

+   如何访问表单上的值以及如何访问网页的其他部分

+   当你的 JavaScript 程序没有给你期望的结果时该怎么办的技巧

+   脚本如果不运行该怎么办

+   如何进行视觉检查

+   如何使用`alert()`测试你的 JavaScript 程序

+   为了简化测试，注释掉代码的某些部分

+   为什么随兴测试并不总是足够

所以在进入本章的主要内容之前，我会简要提到在继续本章其余内容之前你应该理解的两个基本概念。

# 随兴测试的目的——让脚本运行

第一个基本概念涉及随兴测试的目的。随兴测试的主要目的是快速让你的代码运行起来，然后看看你的代码是否有任何错误。如前所述，JavaScript 的三种不同错误类型包括加载、运行时和逻辑错误。

随兴测试的主要优点是它允许你测试你的 JavaScript 程序，而不会让你感到困惑。它适用于那些想要节省时间的人，尤其是测试小段代码时。

# 当浏览器遇到 JavaScript 错误时会发生什么

现在是第二个基本概念的时候了。在前一章中，我已经简要描述了一个网页是如何被加载到浏览器中，然后在网页浏览器中渲染，等待与用户交互。我还提到，通常来说，JavaScript 是默默失败的；它不会明确告诉你或显示发生了什么错误（如果有的话）。这是因为你的浏览器没有开启任何形式的调试。

然而，现代网络浏览器具有内置的方式，让浏览器告诉用户网页上发生了某种错误。当你明确打开或安装网络浏览器的调试工具时，就会发生这种情况。对于某些浏览器，您还需要明确打开错误控制台，才能找出发生了什么错误。

如果您想知道如何利用这些内置功能，以下是一些简单的指导说明，帮助您开始使用：

1.  对于 Firefox——打开你的网络浏览器，前往**工具**。点击**错误控制台**。

1.  对于 Internet Explorer——你需要前往**工具 | 互联网选项 | 高级**。滚动到底部**浏览**，并检查**显示关于每个脚本错误的通知**。

现在你已经理解了为什么我们要进行临时测试的基本概念。接下来，我们将进入一个更复杂的话题——浏览器差异如何影响你的 JavaScript 程序。

# 浏览器差异及在多个浏览器中进行测试的需要

一般来说，浏览器具有不同的功能。对我们来说最重要的区别，至少在这本书中，是不同浏览器使用的 JavaScript 引擎。不同的 JavaScript 引擎以不同的方式处理 JavaScript。这对我们有很大的影响。一个网络浏览器支持的某些 JavaScript 函数或方法可能在另一个浏览器上不受支持。

JavaScript 的主要本质是它通过 DOM 操作提供网页的行为；不同的浏览器对 DOM 的支持有不同的级别。

我们不会尝试深入讨论各种浏览器支持和不支持的内容。相反，我们会指向这个网站：[`www.quirksmode.org/compatibility.html`](http://www.quirksmode.org/compatibility.html)。

这个链接提供了不同选择器下各种网络浏览器不兼容性的总结。对于我们这里的目的，我们应该更关注 DOM 选择器，因为我们关心的是 JavaScript。可以随意浏览该网站以获取详细信息。但现在，你需要理解的主要观点是，浏览器差异导致了不兼容性，因此我们需要测试浏览器兼容性。

大多数初学者 JavaScript 程序员经常会想知道他们如何可以找出访问者使用的浏览器。毕竟，如果你能找出你的访问者使用什么浏览器，你就能创建出兼容的 JavaScript 代码。这在很大程度上是正确的；所以现在我们首先要学习如何检查访问者的浏览器。

# 是时候行动了——检查功能和嗅探浏览器

在本节中，我们想向您介绍 navigator 对象。navigator 对象是一个内置对象，为您提供有关访问者浏览器的信息。我们试图做的是向您展示 navigator 对象是如何工作的，以及您可以如何根据浏览器信息进行编程决策。

### 注意

此示例的源代码可以在源代码文件夹`第二章`中找到，文件名为`browser-testing-sample-1.html`和`browser-testing-sample-2.html`。

1.  如果您还没有这样做，请启动您的文本编辑器，然后在您的文本编辑器中输入以下代码：

    ```js
    <html>
    <head><title>Testing for Browser - Example 1</title></head>
    <body>
    <script type="text/javascript">// Sample 1
    var browserType ="Your Browser Information Is As Follows:\n";
    for( var propertyName in navigator){
    browserType += propertyName + ": " + navigator[propertyName] + "\n";
    }
    alert(browserType);
    </script>
    </body>
    </html>

    ```

    下面是之前代码中发生的事情：我们定义了一个变量`browserType`。之后我们使用了一个`for`循环并定义了另一个变量`propertyName`。

1.  所说的`for( var propertyName in navigator )`意味着我们正在尝试获取`navigator`对象中的所有属性。

1.  这样做之后，我们将`propertyName`和信息添加到`browserType`变量中。最后，我们在一个警告框中输出这些信息。

1.  现在，将文件加载到您的网页浏览器中，您应该会看到一个包含有关您网页浏览器信息的弹出窗口。

    注意，警告框包含了有关您网页浏览器各种类型的信息。您还可以访问浏览器的特定属性以供您自己使用。我们接下来要做的就是这件事。

    您已经学会了如何使用 navigator 对象，现在该看看我们如何利用这些信息来执行编程决策了：

1.  创建另一个新文档，并在其中输入以下代码：

    ```js
    <html>
    <head><title>Testing for Browser - Example 2</title></head>
    <body>
    <script type="text/javascript">// Sample 2
    var typeOfBrowser = navigator.appName;
    document.write(typeOfBrowser);
    if(typeOfBrowser == "Netscape"){
    alert("do code for Netscape browsers");
    }
    else{
    alert("do something else");
    }
    </script>
    </body>
    </html>

    ```

在上一个示例代码中，我们已经定义了变量`typeOfBrowser`，用于决定执行哪个操作。一个简单的方法是使用`if else`语句根据浏览器名称选择执行的代码。

## 刚才发生了什么？

在前面的示例中，您已经看到了如何使用 navigator 对象执行“浏览器嗅探”，并根据给定信息执行适当的操作。

除了使用 navigator 对象，您还可以基于浏览器的能力测试浏览器之间的差异。这意味着您可以测试用户浏览器是否具有某些功能。这种技术也被称为功能测试。现在，我们将简要看看您如何执行功能测试。

## 通过功能测试测试浏览器差异

功能测试是应对浏览器不兼容的重要且强大的方法。例如，您可能想使用某个可能在不同浏览器上不受支持的函数。您可以包含一个测试，以查看此功能是否受支持。然后，根据这些信息，您可以为您的访问者执行适当的代码。

# 行动时间——针对不同浏览器的功能测试

在本节中，我们将简要介绍一个简单易用的方法，可以帮助你快速测试某个特性。我们要使用的方法是`.hasFeature()`方法。现在，让我们深入了解并看看它在实际中的应用。

### 注意

这个示例的源代码可以在`source code`文件夹中的`第二章`找到，文件名为`browser-testing-by-feature-2.html`和`browser-testing-by-feature.html`。

1.  启动你的文本编辑器，然后在文本编辑器中输入以下代码：

    ```js
    <html>
    <head><title>Testing browser capabilities using .hasFeature()</title></head>
    <body>
    <script type="javascript/text">
    var hasCore = document.implementation.hasFeature("Core","2.0");
    document.write("Availability of Core is "+ hasCore + "<br>");
    var hasHTML = document.implementation.hasFeature("HTML","2.0");
    document.write("Availability of HTML is "+ hasHTML + "<br>");
    var hasXML = document.implementation.hasFeature("XML","2.0");
    document.write("Availability of XML is "+ hasXML + "<br>");
    var hasStyleSheets = document.implementation.hasFeature("StyleSheets","2.0");
    document.write("Availability of StyleSheets is "+ hasStyleSheets + "<br>" );
    var hasCSS = document.implementation.hasFeature("CSS","2.0");
    document.write("Availability of CSS is "+ hasCSS + "<br>" );
    var hasCSS2 = document.implementation.hasFeature("CSS2","2.0");
    document.write("Availability of CSS2 is "+ hasCSS2 + "<br>");
    </script>
    </body>
    </html>

    ```

    为了使事情更清晰，我为每个特性和版本号定义了变量。一般来说，`.hasFeature()`的使用如下所示：

    ```js
    .hasFeature(feature, version);
    // feature refers to the name of the feature to test in string
    // version refers to the DOM version to test

    ```

1.  现在将文件加载到你的网页浏览器中，你应该会看到屏幕上动态创建各种类型的文本。

    同样，你可以使用从用户浏览器中得到的信息以与之前示例中看到的方式类似地执行各种决策。

    因此，为了简化和解释的目的，这里是你可以如何使用`.hasFeature()`进行程序决策的示例。

1.  创建另一个新文档，并将以下代码输入其中：

    ```js
    <html>
    <head><title>Testing browser capabilities using .hasFeature() - Example 2</title></head>
    <body>
    <script type="text/javascript">
    var hasCore = document.implementation.hasFeature("Core","2.0");
    if(hasCore){
    document.write("Core is supported, perform code based on the feature<br>");
    }
    else{
    document.write("Feature is not supported, do alternative code to enable your program<br>");
    }
    </script>
    </body>
    </html>

    ```

上面的示例代码是自解释的，因为它与`browser-testing-sample-2.html`中的示例类似。

## 刚才发生了什么？

之前的示例是你测试浏览器差异可以做到的事情的一个简单扩展。它与第一个示例类似，后者明确“嗅探”浏览器信息，而使用`.hasFeature()`的方法是基于功能能力的。

测试浏览器差异没有对错之分。然而，一个普遍的做法是使用`.hasFeature()`来测试程序功能。也就是说，我们经常使用`.hasFeature()`以确保我们的 JavaScript 功能在不同浏览器中可用。

之前的示例展示了你可以通过`.hasFeature()`测试的一些特性。以下是使用`.hasFeature()`可以测试的其他特性列表：

+   事件

+   用户界面事件

+   鼠标事件

+   网页事件

+   变异事件

+   范围

+   遍历

+   视图

既然你已经对如何测试浏览器差异有了一些了解，是时候讨论下一个话题了——得到输出并将值放在正确的地方。

# 你得到正确的输出并将值放在正确的地方了吗？

在本节中，我们将学习如何确保我们得到输出并将正确的值放在正确的地方。这意味着我们需要了解如何使用 JavaScript 与 HTML 表单配合。

## 访问表单中的值

一般来说，“获取”值通常意味着用户会在 HTML 文档中输入一些值到表单中，然后我们的程序从网络表单中“获取”输入。此外，这些值可能被其他函数处理，也可能不被处理；初始用户输入可能作为参数传递给其他函数，然后被处理。

这可以通过使用 JavaScript 的内置工具来实现；JavaScript 为您提供了几种访问表单值的方式，这样您就可以稍后使用这些值。通常，JavaScript 会在**"获取"表单的** `onsubmit` 事件中。

# 行动时间——从表单中获取值

在以下示例中，我们将从简单的 HTML 表单开始。你将学习到访问不同表单元素的各种技术。这里发生的是，我们首先通过使用`onsubmit`事件提交表单。`onsubmit`事件允许我们将表单通过一个 JavaScript 函数发送出去，该函数帮助我们从各种表单元素类型中提取值。所以在这个示例中，我需要你放松并理解前面提到的技术。

### 注意

本例的源代码可在`source code`文件夹的`Chapter 2`中找到，文件名为`accessing-values-from-form.html`。

1.  再次，将以下代码输入到您在新建文档中最喜欢的编辑器中：

    ```js
    <html>
    <head><title>Getting Values from a HTML form</title>
    <script type="text/javascript">/*
    In this example, we'll access form values using
    the following syntax:
    document.NameOfForm.NameOfElement
    where:
    NameOfForm is the name of corresponding form
    NameOfElement is the name of the element ( within the corresponding form)
    */
    function checkValues(){
    var userInput = document.testingForm.enterText.value;
    alert(userInput);
    var userInputTextArea = document.testingForm.enterTextArea.value;
    alert(userInputTextArea);
    var userCheckBox = document.testingForm.clickCheckBox.value;
    // this is for checkbox
    if(document.testingForm.clickCheckBox.checked){
    userCheckBox = true;
    }
    else{
    userCheckBox = false;
    }
    alert(userCheckBox);
    var userSelectBox = document.testingForm.userSelectBox.value;
    alert(userSelectBox);
    // here's another way you can "loop" through your form elements
    alert(document.testingForm.radioType.length);
    for(var counter = 0; counter<document.testingForm.radioType.length;counter++){
    if(document.testingForm.radioType[counter].checked){
    var userRadioButton = document.testingForm.radioType[counter].value;
    alert(userRadioButton);
    }
    }
    }
    </script>
    </head>
    <body>
    <h1>A simple form showing how values are accessed by JavaScript</h1>
    <form name="testingForm" onsubmit="return checkValues()">
    <p>Enter something in text field:<input type="text" name="enterText" /></p>
    <p>Enter something in textarea:<textarea rows="2" cols="20" name="enterTextArea"></textarea></p>
    <p>Check on the checkbox:<input type="checkbox" name="clickCheckBox" /></p>
    <p>Select an option:
    <select name="userSelectBox">
    <option value="EMPTY">--NIL--</option>
    <option value="option1">option1</option>
    <option value="option2">option2</option>
    <option value="option3">option3</option>
    <option value="option4">option4</option>
    </select>
    </p>
    <p>Select a radio buttons:<br />
    <input type="radio" name="radioType" value="python" /> Python
    <br />
    <input type="radio" name="radioType" value="javascript" /> JavaScript
    <br />
    <input type="radio" name="radioType" value="java" /> Java
    <br />
    <input type="radio" name="radioType" value="php" /> PHP
    <br />
    <input type="radio" name="radioType" value="actionscript" /> ActionScript 3.0
    </p>
    <input type="submit" value="Submit form" />
    </form>
    </body>
    </html>

    ```

    你应该注意到有各种输入类型，比如`text`、`textarea`、`checkbox`、`select`和`radio`。

1.  保存表单，然后将其加载到网页浏览器中。你应该在屏幕上看到一个简单的 HTML 表单。

1.  继续输入字段的值，然后点击**提交表单**。你应该看到一系列的警告窗口，重复你输入的值。

## 刚才发生了什么？

在之前提到的简单示例中，你通过一个 JavaScript 事件`onsubmit`提交了一个表单。`onsubmit`事件调用了一个名为`checkValues()`的 JavaScript 函数，该函数帮助我们访问不同表单元素中的值。

通常，访问表单元素的语法如下：

```js
document.formName.elementName.value 

```

其中`formName`是指表单的名称，`elementName`指的是元素的名称。

正如**之前的示例中，表单名是** `testingForm`，正如在`<form name="testingForm" onsubmit="return checkValues()">`中所看到的，输入文本元素的名字是`enterText`，正如在`<input type="text" name="enterText" />`中所看到的。因此，基于这段代码片段，我们将通过以下方式访问表单值：

`document.testingForm.enterText.value`

我们可以将这个值赋给一个可以稍后保存的变量，如代码示例所示。

之前的示例应该很容易理解。但在这个简短的示例中，我还介绍了一些其他有用的方法。考虑以下代码片段，它可以在示例中找到：

```js
for(var counter = 0; counter<document.testingForm.radioType.length;counter++){ 
if(document.testingForm.radioType[counter].checked){
var userRadioButton = document.testingForm.radioType[counter].value;
alert(userRadioButton);
}
}

```

请注意，在突出显示的行中，我使用了`length`属性；`document.testingForm.radioType.length`意味着我在名为`testingForm`的表单中计算了名为`radioType`的元素的数量。这个属性返回一个整数，然后可以在这个整数上使用循环，如之前代码片段中的`for`循环。然后你可以遍历表单元素，并使用前面提到的方法检查它们的值。

另一个**重要的技术可以在下面的代码片段中找到**：

```js
if(document.testingForm.clickCheckBox.checked){ 
userCheckBox = true;
}

```

突出显示的行中**发生的事情是**`document.testingForm.clickCheckBox.checked`返回一个`true`或`false`。你可以使用这个技术来检查你引用的表单元素是否有输入。然后你可以利用这个信息来执行决策。

### 访问表单值的另一种技术

正如你可能已经注意到的，我们通过使用`name`属性来访问表单元素。我们很可能会（很可能）使用`name`属性来访问表单元素，因为它更容易引用这些元素。但无论如何，这里有一个你可以快速查看的替代方法：

而不是写

```js
document.formName.elementName.value 

```

你可以写这个：

```js
document.forms[integer].elementName.value 

```

这里你正在使用`forms`对象，`elementName`指的是输入的名称。

上述代码样例的一个例子可能是：

`document.forms[0].enterText.value`

注意`forms`对象后面跟了`[0]`。这意味着`forms`对象被当作数组一样处理；`forms[0]`指的是网页上的第一个表单，依此类推。

既然你已经理解了访问表单值的基础知识，你在下一节将学习如何确保你在正确的地方获取正确的值。

## 访问网页的其他部分

在本节中，你将学习如何访问网页的其他部分。通常，你已经学习了通过使用`getElementById`、`getElementsByTag`和`getElementsByTagName`来访问网页不同部分的构建块。现在你将进一步使用这些方法，以及新学到的从表单中访问值的技术。

# 行动时间—在正确的地方获取正确的值

在这个例子中，你将看到到目前为止你所学习技术的综合应用。你将学习如何访问表单值、操纵它们、对它们执行操作，最后，把新的输出放置在网页的其他部分。为了帮助你更好地可视化我要描述的内容，以下是完成例子的截图：

![行动时间—在正确的地方获取正确的值](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-test-bgd/img/0004_02_01.jpg)

接下来要使用的例子**是一个简单的 JavaScript 程序，用于检查你是否能在你想要退休的年龄退休。它会要求你提供一些基本信息**。根据提供的信息，它将确定你能否在那个时间退休，**基于**你退休时想要拥有的**金额**。

你将构建一个表单（实际上有两个表单，泛泛而言），用户将被要求在第一个表单（在左边）输入基本信息，在输入每个字段所需的 information 后，将在字段右边动态出现另一个输入字段（在网页的**中间**），**如果输入正确**。

当你输入信息时，一个 JavaScript 事件将触发一个 JavaScript 函数来检查输入的正确性。如果输入正确，将在刚刚接受输入的字段右侧创建一个新的字段，并且左侧的字段将被禁用。

在左侧**字段正确填写后，你会注意到一个完整的表单正在页面中间**被填写。点击**提交**后，代码将进行计算，并根据你指定的年龄和你需要的金额，确定你是否可以退休。

这个示例的基本要求如下：

+   必须输入正确的值。例如，如果字段要求你输入你的年龄，该字段只能接受整数，不允许字符。

+   如果字段需要文本输入，例如你的名字，将不允许整数。

### 注意

这个示例的完整源代码可以在`第二章`的源代码文件夹中找到，文件名为`getting-values-in-right-places.html`。

那么现在，让我们开始这个示例：

1.  让我们先从构建这个示例的基本界面开始。所以，请将以下代码（HTML 和样式）输入到你的文本编辑器中。

    ```js
    <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
    <html >
    <head><title>Getting the right values</title>
    <style>
    input{
    padding:5px;
    margin:5px;
    font-size:10px;
    }
    .shown{
    display:none;
    }
    .response{
    padding:5px;
    margin:5px;
    width:inherit;
    color:red;
    font-size:16px;
    float:left;
    }
    #container{
    position:absolute;
    width:800px;
    padding:5px;
    border: 2px solid black;
    height:430px;
    }
    #left{
    height:inherit;
    width:370px;
    border-right:2px solid black;
    float:left;
    padding:5px;
    }
    #right{
    height:inherit;
    width:300px;
    float:left;
    padding:5px;
    }
    #bottom{
    float:left;
    bottom:5px;
    padding:5px;
    }
    #finalResponse{
    float:left;
    width:780px;
    height:250px;
    border:3px solid blue;
    padding:5px;
    }
    /* this is for debugging messages */
    #debugging{
    float:left;
    margin-left:820px;
    height:95%;
    width:350px;
    border:solid 3px red;
    padding:5px;
    color:red;
    font-size:10px;
    }
    </style>
    <script type=”javascript/text”>
    // some Javascript stuff in here
    var globalCounter = 0;
    </script>
    <body>
    <div id="container">
    <div id="left">
    <h3>Enter your information here</h3>
    <form name="testForm" >
    <input type="text" name="enterText" id="nameOfPerson" onblur="submitValues(this)" size="50" value="Enter your name"/><br>
    <input type="text" name="enterText" id="birth" onblur="submitValues(this)" size="50" value="Enter your place of birth"/><br>
    <input type="text" name="enterNumber" id="age" onblur="submitValues(this)" size="50" maxlength="2" value="Enter your age"/><br>
    <input type="text" name="enterNumber" id="spending" onblur="submitValues(this)" size="50" value="Enter your spending per month"/><br>
    <input type="text" name="enterNumber" id="salary" onblur="submitValues(this)" size="50" value="Enter your salary per month"/><br>
    <input type="text" name="enterNumber" id="retire" onblur="submitValues(this)" size="50" maxlength="3" value="Enter your age you wish to retire at" /><br>
    <input type="text" name="enterNumber" id="retirementMoney" onblur="submitValues(this)" size="50"
    value="Enter the amount of money you wish to have for retirement"/><br>
    </form>
    </div>
    <div id="right">
    <h3>Response</h3>
    <form name="testFormResponse" id="formSubmit" onsubmit="checkForm(this);return false">
    </form>
    </div>
    <div id="finalResponse"><h3>Final response: </h3></div>
    </div>
    </body>
    </html>

    ```

1.  你可能想保存这个文件并在浏览器中加载它，看看你是否得到了与之前看到的前屏幕截图相同的输出。

    请注意，在上面的 HTML 表单中，有一个 JavaScript 事件`onblur`。`onblur`是一个发生在一个元素失去焦点时的 JavaScript 事件。所以你应该看到所有输入元素都有一个`onblur`，它触发了`submitValues()`函数。

    你也应该注意到`submitValues()`有一个`this`作为参数。`this`是 JavaScript 中最强大的关键词之一，指的是它所指向的相应元素。一个例子是`<input type="text" name="enterText" id="nameOfPerson" onblur="submitValues(this)" size="50" value="Enter your name"/>`。在这段代码中，`submitValues(this)`将通过名称`enterText`提交 HTML 表单元素对象。

    现在，是时候进行 JavaScript 编程了。根据之前的解释，当发生 JavaScript 事件`onblur`时，它将提交 HTML 表单元素对象到`submitValues()`函数。因此，我们首先从这个函数开始。

1.  现在，请将以下代码插入`<script type="javascript/text">`标签之间：

    ```js
    function submitValues(elementObj){
    // using regular expressions here to check for digits
    var digits = /^\d+$/.test(elementObj.value);
    // using regular expressions
    // here to check for characters which
    // includes spaces as well
    var letters = /^[a-zA-Z\s]*$/.test(elementObj.value);
    // check to see if the input is empty
    if(elementObj.value==""){
    alert("input is empty");
    return false;
    }
    // input is not relevant; we need a digit for input elements with name "enterNumber"
    else if(elementObj.name == "enterNumber" && digits == false){
    alert("the input must be a digit!");
    return false;
    }
    // input is not relevant; we need a digit for input elements with name "enterNumber"
    else if(elementObj.name == "enterText" && letters == false){
    alert("the input must be characters only!");
    return false;
    }
    // theinput seems to have no problem, so we'll process the input
    else{
    elementObj.disabled = true;
    addResponseElement(elementObj.value,elementObj.id);
    return true;
    }
    }

    ```

    我对代码正在做什么进行了注释，但我将重点介绍之前函数中使用的一些技术。

    我们在这里要做的就是检查输入的正确性。对于这个示例，我们只接受纯数字或纯字符（包括空格）。以下代码片段就是这样做：

    ```js
    var digits = /^\d+$/.test(elementObj.value);
    var characters = /^[a-zA-Z\s]*$/.test(elementObj.value);

    ```

    在这里，我们利用正则表达式来检查输入的正确性。`/^\d+$/`和`/^[a-zA-Z\s]*$/`都是正则表达式，它们都附加上`test`方法。`test`方法测试 HTML 表单对象的值。例如，如果`var digits = /^\d+$/.test(elementObj.value)`的确是数字，它将返回`true`，否则返回`false`。同样，`var characters = /^[a-zA-Z\s]*$/.test(elementObj.value)`如果是字符（包括空格）将返回`true`，否则返回`false`。

    如果您想了解更多关于使用正则表达式的信息，可以参考[`www.w3schools.com/jsref/jsref_obj_regexp.asp`](http://www.w3schools.com/jsref/jsref_obj_regexp.asp)并了解其工作原理。

    这些信息将在`if-else`语句的决策过程中使用。`if-else`语句检查 HTML 对象的名称；`enterNumber`期望一个整数输入。如果不是`enterNumber`，它期望一个字符输入。

    您应该注意到，如果输入没有问题，我们将禁用输入元素，并将 HTML 表单对象的`value`和`id`传递给一个函数`addResponseElement()`，之后我们将`return true`，表示代码成功执行并提交了表单值。

    现在，我们将进入`addResponseElement()`函数：

1.  继续当前文档，在`submitValues()`函数下方添加以下代码：

    ```js
    function addResponseElement(messageValue, idName){
    globalCounter++;
    var totalInputElements = document.testForm.length;
    var container = document.getElementById('formSubmit');
    container.innerHTML += "<input type=\"text\" value=\"" +messageValue+ "\"name=\""+idName+"\" /><br>";
    if(globalCounter == totalInputElements){
    container.innerHTML += "<input type=\"submit\" value=\"Submit\" />";
    }
    }

    ```

    `addResponseElement()`所做的就是尝试动态地将输入元素添加到表单的原始输入表单右侧。在这里，您应该发现`var container = document.getElementById('formSubmit')`很熟悉。它寻找一个 ID 为 formSubmit 的 HTML 元素。之后，我们通过`innerHTML`方法向这个表单添加 HTML。`container.innerHTML += "<input type=\"text\" value=\"" +messageValue+ "\"name=\""+idName+"\" /><br>";`尝试将输入添加到`<form>`标签之间。

    您还应该注意到`var totalInputElements = document.testForm.length`;。这段代码通过使用`length`属性确定`testForm`中的输入元素总数。我们利用这个信息来确定是否处于表单的最后一个输入字段，以便在另一个表单上添加一个提交按钮。

    接下来，我们将创建一个函数，它在第二个名为`testFormResponse`的表单提交后调用。

1.  继续在**当前文档中，在** `addResponseElement()`函数下方添加以下代码：

    ```js
    function checkForm(formObj){
    var totalInputElements = document.testFormResponse.length;
    var nameOfPerson = document.testFormResponse.nameOfPerson.value;
    var birth = document.testFormResponse.birth.value;
    var age = document.testFormResponse.age.value;
    var spending = document.testFormResponse.spending.value;
    var salary = document.testFormResponse.salary.value;
    var retire = document.testFormResponse.retire.value;
    var retirementMoney = document.testFormResponse.retirementMoney.value;
    var confirmedSavingsByRetirement;
    var ageDifference = retire - age; // how much more time can the user have to prepare for retirement
    var salaryPerYear = salary * 12; // salary per year
    var spendingPerYear = spending * 12; // salary per year
    // income per year, can be negative
    // if negative means cannot retire
    // need to either increase spending
    // or decrease spending
    var incomeDifference = salaryPerYear - spendingPerYear;
    if(incomeDifference <= 0){
    buildFinalResponse(nameOfPerson,-1,-1,-1,incomeDifference);
    return true;
    }
    else{
    // income is positive, and there is chance of retirement
    confirmedSavingsByRetirement = incomeDifference * ageDifference;
    if(confirmedSavingsByRetirement <= retirementMoney){
    var shortChange = retirementMoney - confirmedSavingsByRetirement;
    var yearsNeeded = shortChange/12;
    buildFinalResponse(nameOfPerson,false,yearsNeeded,retire, shortChange);
    return true;
    }
    else{
    var excessMoney = confirmedSavingsByRetirement - retirementMoney;
    buildFinalResponse(name,true,-1,retire,excessMoney);
    return true;
    }
    }
    }

    ```

    这个函数中发生的事情相当直接。各种表单值被分配给各种变量。然后我们开始进行一些简单的计算，以查看用户是否有足够的钱退休。您可以通过查看函数中的注释来了解计算的逻辑。

    通常，我们会调用函数`buildFinalResponse()`，无论用户能否按时退休，以及是否有足够的钱。所以这是`buildFinalResponse()`。

    继续当前文档，在`checkForm ()`函数下方添加以下代码：

    ```js
    function buildFinalResponse(name,retiring,yearsNeeded,retire, shortChange){
    var element = document.getElementById("finalResponse");
    if(retiring == false){
    element.innerHTML += "<p>Hi <b>" + name + "</b>,<p>";
    element.innerHTML += "<p>We've processed your information and we have noticed a problem.<p>";
    element.innerHTML += "<p>Base on your current spending habits, you will not be able to retire by <b>" + retire + " </b> years old.</p>";
    element.innerHTML += "<p>You need to make another <b>" + shortChange + "</b> dollars before you retire inorder to acheive our goal</p>";
    element.innerHTML += "<p>You either have to increase your income or decrease your spending.<p>";
    }
    /*
    else if(retiring == -1){
    element.innerHTML += "<p>Hi <b>" + name + "</b>,<p>";
    element.innerHTML += "<p>We've processed your information and we have noticed HUGE problem.<p>";
    element.innerHTML += "<p>Base on your current spending habits, you will not be able to retire by <b>" + retire + " </b> years old.</p>";
    element.innerHTML += "<p>This is because you spend more money than you make. You spend <b>" + shortChange + "</b> in excess of what you make</p>";
    element.innerHTML += "<p>You either have to increase your income or decrease your spending.<p>";
    }
    */
    else{
    // able to retire but....
    element.innerHTML += "<p>Hi <b>" + name + "</b>,<p>";
    element.innerHTML += "<p>We've processed your information and are pleased to announce that you will be able to retire on time.<p>";
    element.innerHTML += "<p>Base on your current spending habits, you will be able to retire by <b>" + retire + "</b> years old.</p>";
    element.innerHTML += "<p>Also, you'll have ' <b>" + shortChange + "</b> amount of excess cash when you retire.</p>";
    element.innerHTML += "<p>Congrats!<p>";
    }
    }

    ```

函数`buildFinalResponse()`与`addResponseElement()`函数类似。**它只是寻找所需的 HTML 元素，并将所需的** HTML 添加到该元素中。

在这里，**你可以清楚地看到在这本书中学到的 JavaScript 函数、方法和技巧**。

保存文件。**你可以尝试玩弄这个例子，看看它对你来说是如何工作的**。

## 刚才发生了什么？

在前一个例子中，你看到了如何访问表单的值，对输入进行操作，然后将输出放置在网页的不同部分。你可能会注意到我们广泛使用了`getElementById`。我们还使用了`form`对象和`value`方法来访问表单中各个元素的值。然后，通过使用`getElementById`，我们寻找所需的 HTML 元素，并将输出添加到 HTML 元素中。

但是，在这个时候，你可能会想知道如果你在程序中犯错误，你应该做什么。这就是我们下一节将重点关注的内容。

# 脚本给出了预期的结果吗？

我的观点是，在我们开始任何有意义的讨论之前，我们必须理解“**预期结果**”的含义。

“预期结果（s）”**可以有几种含义，至少对于这本书的目的来说是这样。例如，如前所述，每个输入的输出都应该是正确的；这里指的是最终的输出。还有一种输出，它以“**视觉输出**”的形式出现。例如，对于每个用户交互或事件，我们的网络应用程序通常会提供一种视觉提示，让用户知道正在发生的事情。在这种情况下，我们的视觉提示按照我们的意图行事，将被认为是“**预期结果**”。

一个简单的提示，为了检查脚本是否给你预期的结果，就是使用简单的输入并进行自己的计算。确保你的计算是正确的，并测试你的程序。

在本章的后半部分，我们将详细讨论两种相关技术。但首先，让我们看看如果我们的脚本没有运行，我们可以采取哪些行动。

# 脚本不运行时怎么办

如果脚本运行不了，很可能是因为加载或运行时出现了错误，这取决于你的程序是如何编写的。例如，在你刚刚创建的前一个程序中，如果你在输入第一个输入字段后没有回应，并且焦点不再在第一个输入字段上，那么你就知道程序没有在运行。

在这个例子中，有几种可能性（这些都归结于前面章节中提到的 JavaScript 错误的三个基本形式）。首先，可能在 JavaScript 事件的输入字段中存在语法错误，或者在由 JavaScript 事件调用的函数中存在严重的错误。如果不是，可能是逻辑错误。

无论错误可能是什么，通常很难猜测错误是什么以及在哪里。因此，如果您的代码没有运行，我将介绍三种重要的测试代码的技术。

## visually inspecting the code（视觉检查代码）

视觉检查代码意味着你将扮演一个人类编译器，并 visually check for errors in your code（视觉检查代码中的错误）。我的看法是，对于视觉检查有一些预设条件和小贴士：

+   必须有良好的代码块结构。这意味着代码应该适当地隔开并缩进，以提高视觉清晰度。一眼看上去，你应该能够看出哪段代码嵌套在哪个`if-else`语句下，或者它属于哪个函数。

+   你使用的代码编辑器有很大的不同。一个常见的错误是括号或反引号的不匹配。因此，一个允许高亮显示匹配括号的代码编辑器将帮助你发现这类错误。

+   检查每个语句(statement)后面的分号。

+   检查变量是否已初始化。如果变量在程序的后部分使用但未初始化，将会造成严重的错误。

之前的操作是我如果脚本没有运行或者没有按照我预期的运行方式来运行时会做的一些事情。然而，尽管我们有意愿，但对代码的视觉检查只能对小于 30 到 50 行代码的小程序有用。如果程序再大一些，或者如果它们包含在事件中调用的各种函数，使用 `alert` 函数来检查我们的代码可能更好（也更有效率）。

## 使用 alert[] 来查看正在运行的代码

`alert` 方法可以用来检查正在运行的代码是否被适当地使用。我们还没有正式介绍 alert 方法。但是以防万一，您可以在 JavaScript 程序中的几乎任何地方使用 alert 函数来创建弹出窗口。语法如下：

`alert(message)`

其中 `message` 可以接受几乎任意数量的值（或者如果它已经被定义或初始化，可以是变量）。由于 `alert` 方法的灵活性，它也可以用来显示值、字符串和对象类型。

使用 `alert` 的问题源于在代码中放置 `alert` 的位置。这将在下一个动手示例中展示。

## 使用 alert() 来查看正在使用哪些值

正如前面提到的，`alert` 方法可以用来显示几乎任何类型的值。因此，常见的用法是将一个变量传递给 `alert` 方法，看看值是否是我们需要的或预期的。

同样，我们需要知道在哪里应用`alert`方法，以确保我们的代码检查是正确的。

在这一点上，示例将是查看我们如何使用`alert`方法检查代码错误的最合适方式。那么，让我们来看看这个是如何工作的。

# 行动时间——使用 alert 检查你的代码

这个示例与你之前所做的类似。在这个示例中，你需要将`alert`插入到适当的位置，以检查哪部分代码正在运行。在某些情况下，你需要向`alert`方法传递值，并看看这个值是否是你想要的。

坦白说，告诉你一步一步应该放置`alert`方法会很繁琐，尤其是因为本例中大部分代码与上一个类似。然而，为了让你更容易跟随，我们将从整个程序开始，然后向你解释`alert`方法的位置和传递给`alert`方法的价值背后的原因。

### 注意

以下示例的源代码可以在源代码文件夹的`第二章`中找到，文件名为`getting-values-in-right-places-using-alert.html`。

1.  这个示例与上一个类似，不同之处在于 JavaScript 代码略有改动。用以下代码替换上一个示例中的 JavaScript 代码：

    ```js
    var globalCounter = 0;
    function submitValues(elementObj){
    alert("submitValues");
    alert(elementObj.name);
    var totalInputElements = document.testForm.length;
    alert("total elements: " + totalInputElements);
    var digits = /^\d+$/.test(elementObj.value);
    var characters = /^[a-zA-Z\s]*$/.test(elementObj.value);
    alert (characters);
    if(elementObj.value==""){
    alert("input is empty");
    return false;
    }
    else if(elementObj.name == "enterNumber" && digits == false){
    alert("the input must be a digit!");
    return false;
    }
    else if(elementObj.name == "enterText" && characters == false){
    alert("the input must be characters only!");
    return false;
    }
    else{
    alert("you've entered : " + elementObj.value);
    elementObj.disabled = true;
    alert(elementObj.value);
    addResponseElement(elementObj.value,elementObj.id);
    return true;
    }
    }
    function addResponseElement(messageValue, idName){
    alert("addResponseElement");
    globalCounter++;
    var totalInputElements = document.testForm.length;
    alert("totalInputElements");
    var container = document.getElementById('formSubmit');
    container.innerHTML += "<input type=\"text\" value=\"" +messageValue+ "\"name=\""+idName+"\" /><br>";
    if(globalCounter == totalInputElements){
    container.innerHTML += "<input type=\"submit\" value=\"Submit\" />";
    }
    }
    function checkForm(formObj){
    alert("checkForm");
    var totalInputElements = document.testFormResponse.length;
    alert(totalInputElements);
    var nameOfPerson = document.testFormResponse.nameOfPerson.value;
    alert(nameOfPerson);
    var birth = document.testFormResponse.birth.value;
    alert(birth);
    var age = document.testFormResponse.age.value;
    alert(age);
    var spending = document.testFormResponse.spending.value;
    alert(spending);
    var salary = document.testFormResponse.salary.value;
    alert(salary);
    var retire = document.testFormResponse.retire.value;
    alert(retire);
    var retirementMoney = document.testFormResponse.retirementMoney.value;
    alert(retirementMoney);
    var confirmedSavingsByRetirement;
    var ageDifference = retire - age; // how much more time can the user have to prepare for retirement
    alert(ageDifference);
    var salaryPerYear = salary * 12; // salary per year
    alert(salaryPerYear);
    var spendingPerYear = spending * 12; // salary per year
    alert(spendingPerYear);
    var incomeDifference = salaryPerYear - spendingPerYear;
    alert(incomeDifference);
    if(incomeDifference <= 0){
    buildFinalResponse(nameOfPerson,-1,-1,-1,incomeDifference);
    return true;
    }
    else{
    confirmedSavingsByRetirement = incomeDifference * ageDifference;
    if(confirmedSavingsByRetirement <= retirementMoney){
    var shortChange = retirementMoney - confirmedSavingsByRetirement;
    alert(shortChange);
    var yearsNeeded = shortChange/12;
    buildFinalResponse(nameOfPerson,false,yearsNeeded,retire, shortChange);
    return true;
    }
    else{
    var excessMoney = confirmedSavingsByRetirement - retirementMoney;
    alert(excessMoney);
    buildFinalResponse(name,true,-1,retire,excessMoney);
    return true;
    }
    }
    }
    function buildFinalResponse(name,retiring,yearsNeeded,retire, shortChange){
    alert("buildFinalResponse");
    var element = document.getElementById("finalResponse");
    if(retiring == false){
    alert("if retiring == false");
    element.innerHTML += "<p>Hi <b>" + name + "</b>,<p>";
    element.innerHTML += "<p>We've processed your information and we have noticed a problem.<p>";
    element.innerHTML += "<p>Base on your current spending habits, you will not be able to retire by <b>" + retire + " </b> years old.</p>";
    element.innerHTML += "<p>You need to make another <b>" + shortChange + "</b> dollars before you retire inorder to acheive our goal</p>";
    element.innerHTML += "<p>You either have to increase your income or decrease your spending.<p>";
    }
    else{
    // able to retire but....
    alert("retiring == true");
    element.innerHTML += "<p>Hi <b>" + name + "</b>,<p>";
    element.innerHTML += "<p>We've processed your information and are pleased to announce that you will be able to retire on time.<p>";
    element.innerHTML += "<p>Base on your current spending habits, you will be able to retire by <b>" + retire + "</b> years old.</p>";
    element.innerHTML += "<p>Also, you'll have <b>" + shortChange + "</b> amount of excess cash when you retire.</p>";
    element.innerHTML += "<p>Congrats!<p>";
    }
    }

    ```

1.  保存文档并在网页浏览器中加载它。玩转示例，看看警告框是如何通知你哪部分代码正在执行，以及输入了哪些值。

## 刚刚发生了什么？

如果你浏览了之前的示例，你会注意到`alert()`通常放在函数的开始处，以及在变量被初始化时。为了检查函数，我们通常会手动输入函数的名称，并将其作为参数传递给`alert`方法，以通知我们程序的互动过程中发生了什么。同样，我们将定义的变量（表单元素的值）作为参数传递给`alert`方法，以通知我们用户输入了哪些值。

因此，通过使用一个`alert()`方法，我们能够找出正在运行的代码和正在使用的值。然而，这个方法可能有些过于繁琐或令人沮丧，因为警告框会不断地在你的窗口上弹出。这里有一个简单的替代方法，用于检查正在运行的代码，以及检查输入元素。

## 检查代码正在运行以及使用哪些值的一种不那么侵扰性的方法

为了以一种不那么侵扰的方式测试我们的代码，我们会写一个简单的调试函数。这个调试函数应该打印出函数的名称和其他一些变量。为了简单起见，我们将展示一个简单的调试函数，它打印出函数的名称和正在使用的 HTML 元素。那么，让我们开始吧。

# 行动时间—检查值的使用是否突兀

如上所述，我们将演示一个非常简单的调试函数，帮助你识别正在运行的代码以及正在使用的 HTML 元素。在这里，你会对如何以一种不那么突兀的方式测试你的代码有一些基本了解。

再次，这个例子与上一个例子相似，但有一些重要的元素我们将添加到上一个例子中。本质上，我们将在其中添加一个函数、一些 HTML 和 CSS。

然而，你可能会发现回头参考上一个例子并给上一个例子添加新元素很繁琐。因此，建议你跟随这个例子。

### 注意

另外，你可以在源代码文件夹`第二章`中查看源代码，文件名为`getting-value-in-right-places-complete.html`。

所以，不再赘述，让我们马上开始：

1.  在`<style>`标签之间插入以下 CSS 代码：

    ```js
    /* this is for debugging messages */
    #debugging{
    float:left;
    margin-left:820px;
    height:95%;
    width:350px;
    border:solid 3px red;
    padding:5px;
    color:red;
    font-size:10px;
    }

    ```

1.  现在，对于将包含调试信息的 HTML 容器，请在`</body>`标签前输入以下代码片段：

    ```js
    <div id="debugging"><h3>Debugging messages: </h3></div>

    ```

    在这里发生的情况是，之前的 HTML 元素将被用来在调试信息与简单应用程序本身之间提供视觉分隔。现在保存文件，然后用网页浏览器打开它，你会看到一个类似于下一张截图中的示例：

    ![行动时间—检查值的使用是否突兀](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-test-bgd/img/0004_02_02.jpg)

1.  接下来，你需要将以下代码添加到你的 JavaScript 代码中：

    ```js
    function debuggingMessages(functionName, objectCalled, message){
    var elementName;
    if(objectCalled.name){
    elementName = objectCalled.name;
    }
    else if(objectCalled.id){
    elementName = objectCalled.id;
    }
    else{
    elementName = message;
    }
    var element = document.getElementById("debugging");
    element.innerHTML += "Function name :" +functionName+ "<br>element :" +elementName+"<br>";
    }

    ```

    前面提到的函数用于捕获当前使用的函数名称；这相当于当前正在使用什么代码，因为我们的程序是事件驱动的，函数通常是由用户触发的。

    这三个参数如下：

    +   `functionName`指的是当前使用的函数的 functionName。在下一步，你将看到动态获取这个值的方法。

    +   `objectCalled`指的是正在使用的 HTML 对象。

    +   `Message`指的是一个字符串。这可以是任何你想要的消息；它的目的是为你提供在屏幕上编写调试消息的灵活性。

        此外，我们使用了`.innerHTML`方法将消息追加到 ID 为"debugging"的 HTML`div`元素中。

1.  现在最后，是时候看看我们如何使用这个函数了。通常，我们按照以下方式使用函数：

    ```js
    debuggingMessages("name of function", elementObj,"empty");

    ```

    如果你查看源代码，你会看到前面提到的函数在程序中谨慎使用。考虑以下代码片段：

    ```js
    function submitValues(elementObj){
    //alert("submitValues");
    debuggingMessages("submitValues", elementObj,"empty"); 
    //alert(elementObj.name);
    var totalInputElements = document.testForm.length;
    //alert("total elements: " + totalInputElements);

    ```

    在前一个案例中，"`submitValues`"的值将被传递，因为`submitValues`是函数的名称。注意我们也把函数参数`elementObj`传递给`debuggingMessages()`，以便通知我们当前函数中使用了什么。

1.  最后，你可能想要在 JavaScript 程序中的每个函数中添加`debuggingMessages("function name", elementObj,"empty")`。如果你不确定应该在哪个地方使用这个函数，请参考给出的源代码。

    如果你自己正在输入函数，那么请注意你可能需要更改参数名称以适应每个函数。通常，`debuggingMessages()`可以替代`alert()`方法。所以，如果你不确定应该在哪个地方使用`debuggingMessages()`，你可以将`debuggingMessages()`用于前一个示例中用于检查代码的每个`alert()`。

1.  如果你已经执行了整个程序，你会看到类似于下一张截图的东西：![行动时间—不侵扰地检查使用哪些值](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-test-bgd/img/0004_02_03.jpg)

## 刚才发生了什么？

你刚刚创建了一个函数，它允许你以一种不那么侵扰的方式检查你的代码，这是通过利用 JavaScript 的一些内置方法实现的，包括`.innerHTML`方法。这里发生的事情是另一个例子，展示了你如何访问值、操纵它们，然后将这些值输出到所需的 HTML 元素，以使检查变得更不侵扰。

如果你查看源代码，你可能会注意到我在不同的情况下使用了不同的消息；如果你使用的话，这将为你的调试函数带来更多的灵活性。

# 注释掉脚本的一部分以简化测试

注释掉脚本的一部分是测试你的 JavaScript 代码的另一种重要且简单易用的权宜之计。本质上，你注释掉那些立即不会使用的代码。

因为我们还没有介绍如何进行多行注释，所以我借此机会向你展示如何使用它。语法如下：

```js
/*
This is a multiple line comment
*/

```

注释掉脚本的一部分可以用来简化测试的方法如下：我们通常会注释掉所有我们一开始不会使用的其他代码。例如，`getting-values-right-places-complete.html`中使用的第一个函数是`submitValues()`函数。

我们会在取消注释用于的第二个函数之前，确保`submitValues()`函数是正确的，这个第二个函数是`addResponseElement()`函数。

这个过程一直持续到所有函数都被取消注释，这意味着代码是正确的。

考虑到所有这些点，我们现在将转到基于前一个示例的简单练习。

# 行动时间——简化检查过程

在这个例子中，不会有源代码供你复制。相反，你可以使用在`getting-values-right-places-complete.html`中找到的前一个示例，并尝试以下步骤：

1.  滚动到源代码的 JavaScript 部分。注释掉所有除了`submitValues()`和`addResponseElement()`之外的函数。

1.  保存文件并加载到你的网页浏览器中。现在测试一下这个程序。

    您应该注意到，您的程序仍然可以运行，但是当所有输入字段都正确填写后，您将无法成功提交表单。

    这是因为您注释掉了`checkForm()`函数，这个函数对于第二次表单提交是必需的。

    这意味着什么？这意味着`submitValues()`和`addResponseElement()`函数运行正常，现在可以安全地进行下一步。

1.  现在，取消注释`checkForm()`、`buildFinalResponse()`和`debuggingMessages()`函数，保存文件并在浏览器中重新加载。继续测试您的程序，直到您提交表单。

    您应该注意到，在提交第二份表单之前，所有事情都进行得很顺利。这是因为您在上一个步骤中已经测试过，所以预料到了这种情况。

    现在，在您完成所有输入字段后，提交表单。因为您已经取消注释了`checkForm()`和`buildFinalResponse()`函数，现在提交表单后您应该期待有一个回应。

1.  最后，取消注释`debuggingMessages()`函数。保存文件并在浏览器中加载它

现在，同样地，像往常一样使用程序，您应该看到所有必要的功能都像以前一样正常工作。

## 刚才发生了什么？

您刚刚通过取消注释代码的不同部分，以一种有用的方法测试了您的代码。您可能注意到我们从第一个将要使用的函数开始，然后继续到下一个。这个过程将帮助我们找到包含错误的代码块。

这种技术也可以应用于代码语句。我们注释掉了函数中的代码，因为根据示例，这样更容易跟踪。

# 时机差异——确保在交互之前 HTML 已经准备好了

记住 JavaScript 的本质是通过操作 DOM 元素为网页提供行为吗？这是一个关键点——如果 HTML 在例如执行改变表单颜色的 JavaScript 函数时不可用，那么 JavaScript 函数将无法工作。

在这种情况下，问题不是由于 JavaScript 错误，比如逻辑、运行时和加载错误，而是由于时机问题。

如前章所述，网络浏览器（客户端）从服务器下载一个网页，通常是从上到下读取网页（文档）。因此，例如，如果您有一个大型的 HTML 文档（例如一个在主体中有大图像的 HTML 文档），您的 JavaScript 可能无法与 HTML DOM 交互，因为没有 HTML 可以与之交互。

有两条解决方法可以让我们解决这个问题：

1.  使用`<body>`标签的 JavaScript 事件`onload`。这可以按照以下方式进行：

    ```js
    <html>
    <head>
    <script>
    function aSimpleFunction()
    {
    alert(window.status);
    }
    </script>
    </head>
    <body onload="aSimpleFunction()">
    </body>
    </html>

    ```

    高亮的行意味着`aSimpleFunction()`仅在`<body>`标签中的内容加载完成后执行。您可以利用这个技术确保在执行您的 JavaScript 函数之前，您的 HTML 内容已经加载完成。

    这里有一个（可能是更受欢迎的方法）：

1.  将你的 JavaScript 函数放在`</body>`标签之前。

这个方法通常被使用；你可以看到提供分析服务的公司通常要求其用户在`</body>`标签之前放置跟踪代码（通常是 JavaScript，如 Google 分析）。这意味着 JavaScript 代码片段将在`<body>`标签中的所有内容加载完成后加载，确保 HTML DOM 将与 JavaScript 交互。

# 为什么临时测试永远不够

到目前为止，你可能已经注意到，为临时测试介绍的方法在应用到你的代码时可能会变得重复。例如，`alert`方法需要你手动在不同代码部分输入`alert`函数，包含不同的值，以便你检查代码。这可能会变得繁琐且低效，尤其是当程序开始变得更大时。简单地说，当程序变得太大时，它将无法扩展。同时，`alert`方法可能会相当显眼。因此，我们创建了一个简单的调试功能。

我们创建的简单调试功能较为不显眼；你可以与程序互动，并在屏幕上获得几乎即时的反馈。尽管它具有不太显眼的优点，但它有两个主要的缺点。第一个缺点是它可能既繁琐又低效，这与`alert`方法相似。第二个缺点是调试功能的优劣在很大程度上取决于 JavaScript 程序员的技能。然而，作为 JavaScript 的初学者，我们可能有没有创建健壮调试功能的技能。

因此，当需要时，还有其他更强大的工具可以帮助我们完成工作，我们将在后面的章节中讨论这些工具。

# 总结

在本章中，我们在前一章学到的基础知识上进行了构建，并扩展了我们可以使用本章介绍的各种技术进行临时测试的知识。

总的来说，我们将前一章和本章介绍的各种方法和技巧结合起来，以帮助我们进行临时测试。我们经常通过`getElementById`查找所需的元素，然后通过`form`对象访问表单值。我们还使用了`alert()`方法进行某种形式的临时测试。

具体来说，我们已经介绍了以下主题：

+   我们学习了如何使用`form`对象及其方法访问表单上的值，操纵值，并使用前一章学到的技术将值输出到网页的其他部分，例如`getElementById`。我们通过`.innerHTML`将 HTML 内容附加到特定的 HTML 元素上。

+   如果脚本没有提供预期的输出，我们可以采取的行动，即使用`alert()`方法测试脚本并注释掉代码。这引导我们进行临时测试。

+   执行临时性测试的各种技术，最值得注意的是，通过使用`alert()`方法。由于它明显的干扰性，我们创建了一个简单的调试函数，提供了一种不那么干扰的测试方式。

+   时间差异：我们必须始终确保 HTML DOM 在 JavaScript 可以与其交互之前是可用的。

+   由于可扩展性和效率问题，临时性测试永远不够。

既然我们已经理解并尝试了临时性测试，现在是时候学习一些关于 JavaScript 测试的更高级内容了。如前所述，尽管临时性测试快速简单，但它并不一定能带来更好的 JavaScript 代码（除了它其他缺点之外）。在下一章，我们将学习如何验证 JavaScript。尽管这个概念听起来简单，但你在实际编码和设计过程中，以及可以帮助你验证你的 JavaScript 程序的其他因素方面，你会学到更多关于 JavaScript 的概念。
