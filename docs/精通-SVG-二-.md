# 精通 SVG（二）

> 原文：[`zh.annas-archive.org/md5/1F43360C7693B2744A58A3AE0CFC5935`](https://zh.annas-archive.org/md5/1F43360C7693B2744A58A3AE0CFC5935)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：JavaScript 和 SVG

到目前为止，您已经在本书中学到了很多关于 SVG 的知识。您花了很多时间研究 SVG 规范的细节，以及 SVG 与 CSS 和 HTML 交互的不同方式。希望对您来说和对我一样有趣。

尽管一切都很有趣，但正是在这一章中，我们将把所有工具整合在一起，真正释放 SVG 的力量。将 JavaScript 添加到其中会开启大量新的可能性。

可以肯定，有许多网页开发人员和设计师永远不会使用 SVG 进行动画、动态可视化或其他交互式工作。对于他们来说，全面了解 SVG 本身作为标记的工作方式以及它如何与其他静态网页技术结合是非常有价值的。这在我们刚刚详细了解的 SVG 和 CSS 的交集中尤为重要。

话虽如此，SVG 最令人兴奋的是它如何轻松地与 JavaScript 一起工作，以增强您网站的交互性。所有这些开放网络技术都旨在以创造超越个别规范总和的方式相互配合。尽管有专门的专家在所有这些不同的技术上工作，但他们大多数情况下是公开的，并且通常是作为微软、谷歌或 Mozilla 等更大组织的一部分，因此他们真正希望确保这些技术以最佳方式相互配合。

SVG 和 JavaScript 的交集绝对是这样一个案例。

在本章中，我们将学习 JavaScript 和 SVG 之间的低级接口。这包括 SVG 的 DOM 接口。这是重要的内容，尽管我们也将学习使用 SVG 的库和框架。即使您已经从事网页开发一段时间，并熟悉 JavaScript 和 DOM，了解常规 HTML DOM 和 SVG 元素接口之间的差异也是重要的。如果您对原始 DOM 操作不太熟悉（许多在 jQuery 时代及以后开始的开发人员并不熟悉），那么本章将为您提供一整套有用的技能。

在本章中，我们将学习以下内容：

+   SVG 基本 DOM 接口-在 JavaScript 中访问和操作 SVG 元素

+   SVG 特定的 DOM 接口

+   动态处理 SVG 和 CSS

# JavaScript 版本和工具

在我们开始编码之前，我认为重要的是了解不同的 JavaScript 版本以及它们在本书中的使用方式。我还想介绍一下我将如何呈现需要工具的示例。

# JavaScript 版本

您可能已经注意到，在过去几年中，围绕 JavaScript 编程语言的发展进行了大量工作。其中一些工作确实非常出色。事实上，目前网络上主要的库和框架都是用不同版本和变体的 JavaScript 写成的，这些 JavaScript 并不是在所有网络浏览器中都通用。使用最新版本的语言，包括特定于框架的扩展，是可能的，因为使用了转译器（[`scotch.io/tutorials/javascript-transpilers-what-they-are-why-we-need-them`](https://scotch.io/tutorials/javascript-transpilers-what-they-are-why-we-need-them)），这是一种软件，它将用一种语言（或在本例中是语言的一个版本）编写的软件代码转换为另一种语言（在本例中是语言的一个较旧但完全支持的版本）。这种转译步骤使我们能够用我们喜欢的 JavaScript 风格编写应用程序，然后将其转换为可以在任何地方运行的浏览器标准 JavaScript。

本节概述了您将在本书中遇到的不同 JavaScript 版本。下一节将简要介绍我们将如何呈现所需的工具，以使用转译器使您的最新代码在常见的网络浏览器中运行。

需要注意的是，这是对这个主题的最广泛的介绍。随着情况的出现，书中将涵盖更多细节，但即使如此，也只是触及了这个广泛主题的表面。

虽然我在整本书中都称呼并将继续称呼这种语言为 JavaScript，但这个商标名称（由 Oracle 商标，后者从 Sun Microsystems 获得商标，后者又从 Netscape 获得商标）并不是这种语言的官方名称。这种语言的官方名称是 **ECMAScript**，基于 Ecma ([`www.ecma-international.org/`](https://www.ecma-international.org/))，这个组织主持编写规范的标准机构。

# ECMAScript 5

**ECMAScript 5** (**ES5**) 是当今浏览器中最完全支持的语言版本，也是转译器的目标版本，因为它可以在任何地方运行。标准化于 2009 年，截至撰写本文时，这个版本在超过 90%的浏览器中得到了全面支持，在约 97%的浏览器中得到了部分支持。通过添加 ES5 polyfills ([`github.com/es-shims/es5-shim`](https://github.com/es-shims/es5-shim))，你可以几乎实现对 ES5 的普遍覆盖。一些代码，特别是第七章中的 Angular 1 和 jQuery 部分，*常见的 JavaScript 库和 SVG*，将直接以 ES5 编写。这是因为大多数人对 Angular 1 和 jQuery 都是以 ES5 风格的接口熟悉。文件顶部的注释如下所示，表示正在使用这个版本：

```xml
/*
 ECMAScript 5
 */
```

# ECMAScript 2015

ECMAScript 2015 以前被称为 **ECMAScript 6** (**ES6**)。这个版本于 2015 年完成，现在正在进入浏览器。它在所有主要浏览器的最新版本（Edge、Firefox、Chrome 和 Safari）中都有部分支持。一般来说，本书中编写的 JavaScript 代码（除了前面提到的例子）将使用 ES6。除了 *React* 部分，它使用了更高级的功能和一些 React 特定的扩展，其他使用的功能都在最新版本的 Chrome、Edge 和 Firefox 中得到支持。因此，如果你使用这些浏览器之一，你不必为这些示例实际运行转译器。如果你想将这些代码投入生产，那就是另一回事，超出了本书的范围。

文件顶部的注释如下所示，表示正在使用这个版本：

```xml
/*
 ECMAScript 6
 */
```

# TypeScript

Angular ([`angular.io/`](https://angular.io/)) 部分将使用 TypeScript ([`www.typescriptlang.org/`](https://www.typescriptlang.org/)) 编写。TypeScript 是 JavaScript 的一个超集，它通过类型注解添加了某些可选功能，最显著的是静态类型化。TypeScript 被 Angular 团队用来为开发环境添加一些核心功能。因为并非每个人都有 TypeScript 的经验，所以示例中的 TypeScript 语言特性将被指出，以尽量减少混淆。

在这方面的好消息是，一旦脚本启动并运行，任何 Angular 组件的主体都可以用普通的旧 JavaScript 编写。

# 工具化

直到目前为止，我们在工具方面没有做太多工作。几乎所有的例子在本地文件系统上提供服务时都可以正常工作。

未来情况可能不会如此。在最简单的情况下，例如任何需要进行 HTTP 请求的示例，都将依赖于 node 包 serve ([`www.npmjs.com/package/serve`](https://www.npmjs.com/package/serve)) 来建立一个简单的本地服务器。

特别是 React 和 Angular 示例需要更广泛的工具。至少，您需要安装 Node.js（[`nodejs.org/en/`](https://nodejs.org/en/)），并且您需要按照一些步骤进行设置。最终，您将运行一个本地 Web 服务器，并且将有几个进程监视您的 JavaScript 或 Typescript 文件的更改。当您进行更改时，相关进程将捕捉更改并执行操作（例如将代码从 Typescript 转换为 JavaScript）以确保代码在本地服务器上更新。

每个相应部分都将提供有关如何使用代码示例的说明。

另外，请记住所有工作代码都可以在 GitHub 上找到（[`github.com/roblarsen/mastering-svg-code`](https://github.com/roblarsen/mastering-svg-code)）。

在所有这些之后，让我们看一些不需要除了较新的 Web 浏览器之外的任何东西就可以在本地运行的代码。

# SVG 的 DOM 接口

DOM 是用于访问、更新、创建和删除基于 XML 的文档的元素、属性和内容的 API。这包括相关但不严格符合 XML 语法的文档，例如最新的 HTML 规范。

对于普通开发人员来说，进行大量的纯 DOM 操作在今天是相当罕见的。多年前 jQuery 就解决了这个问题，而且从来没有再流行起来。我可以从经验中说，了解 DOM 操作的内部工作原理仍然很有用，这样当您遇到库或框架无法提供的东西时，您就可以自己编写代码来解决问题。

这也说明了在使用不同技术时可用的可能性。拥有对图书馆或框架作者感兴趣的东西的访问权限是一回事，但如果你熟悉底层代码，你只受你的想象力和目标浏览器中可用的东西的限制。

SVG DOM 基于 Dom Level 2 规范（[`www.w3.org/TR/2000/REC-DOM-Level-2-Core-20001113/core.html`](https://www.w3.org/TR/2000/REC-DOM-Level-2-Core-20001113/core.html)）。它支持大多数具有 DOM 和 HTML 经验的人所期望的内容，并添加了几组 SVG 特定接口，您可以使用这些接口来操作 SVG 文档。

本节将介绍 SVG 特定 DOM 方法的基本类，并说明它们的用法。除非您正在编写库，否则您不需要了解这些低级工具的所有内容。本章将作为一个介绍，让您对它们有一个良好的了解，并知道要寻找什么。

# 初始探索

要开始，让我们看一些 DOM 方法和属性，这些方法和属性可用于任意（常见的）SVG 元素`rect`。为此，您可以查看`SVGRectElement`元素文档（[`developer.mozilla.org/en-US/docs/Web/API/SVGRectElement`](https://developer.mozilla.org/en-US/docs/Web/API/SVGRectElement)）。那将是一个不错的选择。

您还可以直接检查`rect`元素，使用您选择的浏览器的开发人员工具。这将看起来像以下的屏幕截图。这将是您许多人接触 SVG 元素的可用方法和属性的方式：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/0c5d8309-264d-45b1-bcb5-2ed63a3fdbd3.png)

虽然这些是常见的，但您也可以做一些像以下的事情，这是向脚本化 SVG 迈出的一大步。

在此代码示例中，我们使用`document.getElementById`访问`rect`元素，并将其存储在变量`rect`中。`document.getElementById`是您将用于访问 SVG 和 HTML 本身中的 DOM 元素的常见 DOM 访问器方法之一。您将在本章中看到其更多用法示例。

接下来，我们将通过简单的`for...in`循环遍历`rect`循环的属性，使用方括号表示法将变量和属性写入控制台，其中`prop`是`rect`元素上的属性或方法的名称：

```xml
<!doctype html>
<html lang="en">

<head>
    <meta charset="utf-8">
    <title>Mastering SVG- SVG Basic SVG DOM Manipulation</title>
</head>

<body>
    <svg  width="500" height="500"
     viewBox="0 0 500 500" version="1.1">
        <rect x="20" y="20" fill="blue" width="460" height="460"
         id="rect"></rect>
    </svg>
    <script>
    /*
        ES6
    */
        document.addEventListener("DOMContentLoaded",()=> 
            const rect = document.getElementById("rect");
            for (let prop in rect){
                let val = rect[prop];
                console.log(`${prop} = ${val}`);
            }
        });
    </script>
</body>

</html>
```

输出如下截图所示。您会注意到前几个属性和方法都是特定于 SVG 的。这个列表在下面的几个屏幕上继续，但列表中的第一个都是 SVG 特定的。这是因为`for...in`循环从`SVGRectElement`的最内部属性开始，然后沿着原型链向上工作，直到`SVGElement`、`Element`和`Node`的属性（最通用的 DOM 接口）。其中一些属性非常明显和立即有用，比如`x`、`y`、`width`和`height`。

其他可能不那么明显有用，比如`getBBox`或`isPointInFill`（尽管您可能能够猜到它们的作用），但您可以开始看到当您访问一个元素时，有很多可用的内容：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/8e8c0200-55c1-4a7d-bc41-ed89c3724924.png)

基于这个基本的基础和探索的想法，让我们开始构建一个小型应用程序，让您以简单的方式操作 SVG 画布。接下来的部分将重点介绍逐步构建一个小工具，允许您向 SVG 画布添加简单的 SVG 元素（`text`、`rect`和`circle`）并以不同的方式操作它们。这个小演示将很容易理解，并将演示与 SVG 交互的许多不同方式。

# SVG DOM 操作器

我们要构建的应用程序将允许您点击并向 SVG 画布添加三种不同类型的 SVG 元素。界面将允许您点击要添加的项目（`rect`、`circle`或`text`），然后您将能够点击画布并将该元素添加到特定的`(x,y)`坐标处。选择该元素后，您将能够通过更改几个可用的属性来编辑它。

这个示例将使用 Bootstrap 来简化布局不同的表单字段，并创建一个简单的模态框来编辑属性。因此，jQuery 也将被包含在内，尽管至少在这个演示版本中，jQuery 的交互将被保持在最低限度；我们将专注于原始的 DOM 操作。

完成后，它将如下截图所示，显示了屏幕顶部的 SVG 画布，用黑色边框。之后是简单的说明，然后在屏幕底部有三个按钮，允许您选择要添加到画布的矩形、圆形或文本元素：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/3719fc64-62cd-404d-9134-3b06ef2966b6.png)

这一次，与其一次性添加整个代码示例并解释整个内容，不如我们在示例中构建并讨论每个代码块。

让我们从页面的骨架开始。这个初始状态完全没有任何 JavaScript，但它为我们提供了一些结构和一些稍后会用到的工具。

在`head`中，我们从**内容传送网络**（**CDN**）链接到 Bootstrap，从 Google 字体链接到 Raleway 字体，然后为我们的页面设置一些基本样式，将 Raleway 添加为正文字体，给我们的画布 SVG 元素加上边框，然后改变 SVG 精灵按钮的颜色。

在 body 中，我们使用 Bootstrap 的实用类来创建一个填满整个屏幕宽度的流体布局。SVG 元素将缩放以适应这个 Bootstrap 容器。

布局分为两部分：目标 SVG 元素，用于绘图的地方，和第二部分用于 UI 控件。目前，UI 控件只是包裹在 SVG 精灵周围的三个`button`元素。

接下来，我们有一个隐藏的 SVG 元素，其中包含一系列定义了我们精灵的`symbol`元素。

最后，我们链接到一些第三方 JavaScript，以便连接一些 Bootstrap 功能：

```xml
<!doctype html>
<html lang="en">

<head>
  <meta charset="utf-8">
  <title>Mastering SVG- SVG Basic The DOM Manipulator</title>
  <link rel="stylesheet" 
   href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.
    min.css" integrity="sha384-
    Gn5384xqQ1aoWXA+058RXPxPg6fy4IWvTNh0E263XmFcJlSAwiGgFAW/dAiS6JXm"
    crossorigin="anonymous">
  <link href="https://fonts.googleapis.com/css?family=Raleway" 
    rel="stylesheet">
  <style type="text/css">
    body {
      font-family: Raleway, sans-serif;
    }
    svg.canvas {
      border: 1px solid black;
    }

    button svg {
      fill: cornflowerblue;
      stroke: cornflowerblue;
      max-width: 50px;
    }
  </style>
</head>

<body>

  <div class="container-fluid">
    <div class="row">
        <div class="col-12">
            <svg  viewBox="0 0 500 
              200" version="1.1" id="canvas" class="canvas">
            </svg>
        </div>
    </div>
    <div class="row">
      <div class="col-5 offset-2">
        <h2>Pick an SVG element to add to the canvas. </h2>
        <p>Click on an item to select it and then click on the canvas
             to place it in the SVG element.</p>
      </div>
    </div>
    <div class="row">
      <div class="col-4 text-center">
        <button class="btn btn-link" title="click to add a circle">
          <svg  role="img">
            <use xlink:href="#circle"></use>
          </svg>
        </button>
      </div>
      <div class="col-4 text-center" title="click to add a square">
        <button class="btn btn-link">

          <svg  role="img">
            <use xlink:href="#square"></use>
          </svg>
        </button>
      </div>
      <div class="col-4 text-center">
        <button class="btn btn-link" title="click to add a text box">
          <svg  role="img">
            <use xlink:href="#text"></use>
          </svg>
        </button>
      </div>
    </div>
  </div>

  <svg  style="display:none">
    <defs>
      <symbol id="circle" viewBox="0 0 512 512">
        <circle cx="256" cy="256" r="256"></circle>
      </symbol>
      <symbol id="square" viewBox="0 0 512 512">
        <rect x="6" y="6" height="500" width="500"></rect>
      </symbol>
      <symbol id="text" viewBox="0 0 512 512">
        <rect x="6" y="106" height="300" width="500" fill="none" 
            stroke-width="10px"></rect>
        <text x="6" y="325" font-size="150">TEXT</text>
      </symbol>
      <!--
      Font Awesome Free 5.0.2 by @fontawesome - http://fontawesome.com
      License - http://fontawesome.com/license (Icons: CC BY 4.0,
         Fonts: SIL OFL 1.1, Code: MIT License)
      -->
      <symbol id="edit" viewBox="0 0 576 512">
          <title id="edit-title">Edit</title>
          <path d="M402.6 83.2l90.2 90.2c3.8 3.8 3.8 10 0 13.8L274.4 
            405.6l-92.8 10.3c-12.4 1.4-22.9-9.1-21.5-21.5l10.3-
            92.8L388.8 83.2c3.8-3.8 10-3.8 13.8 0zm162-22.9l-48.8-
            48.8c-15.2-15.2-39.9-15.2-55.2 0l-35.4 35.4c-3.8 3.8-3.8 10 
            0 13.8l90.2 90.2c3.8 3.8 10 3.8 13.8 0l35.4-35.4c15.2-15.3 
            15.2-40 0-55.2zM384 346.2V448H64V128h229.8c3.2 0 6.2-1.3 
            8.5-3.5l40-40c7.6-7.6 2.2-20.5-8.5-20.5H48C21.5 64 0 85.5 0 
            112v352c0 26.5 21.5 48 48 48h352c26.5 0 48-21.5 48-
            48V306.2c0-10.7-12.9-16-20.5-8.5l-40 40c-2.2 2.3-3.5 5.3-
            3.5 8.5z"></path>
        </symbol>
    </defs>
  </svg>
  <script>

  </script>
  <script src="img/jquery-3.2.1.slim.min.js"
     integrity="sha384-KJ3o2DKtIkvYIK3UENzmM7KCkRr/rE9/Qpg6aAZGJwFDMVNA/GpGFF93hXpG5KkN"
    crossorigin="anonymous"></script>
  <script 
   src="img/>    per.min.js" integrity="sha384-
    ApNbgh9B+Y1QKtv3Rn7W3mgPxhU9K/ScQsAP7hUibX39j7fakFPskvXusvfa0b4Q"
    crossorigin="anonymous"></script>
  <script 
   src="img/>    n.js" integrity="sha384-
    JZR6Spejh4U02d8jOt6vLEHfe/JQGiRRSQQxSfFWpi1MquVdAyjUar5+76PVCmYl"
    crossorigin="anonymous"></script>
</body>

</html>
```

现在我们已经了解了页面的基础知识，让我们开始添加一些交互性。

虽然页面上有 jQuery，但我不打算在任何 DOM 操作中使用它，这样我们就可以看一下原始的交互。我们将在第七章中看到 jQuery 和 SVG，所以不要担心。

我们要做的第一件事是创建一些事件处理程序来处理不同的交互。我们将添加的第一个事件处理程序是按钮上的`click`事件处理程序。想法是你点击按钮将一个 SVG 元素加载到你的光标上，然后再点击一次将其放置在画布上。这段代码还没有处理将元素添加到 SVG 画布中，但它确实展示了在处理 SVG 和 JavaScript 时的一些问题。

这是一个例子，有些你可能从老式 DOM 操作中知道的东西可能会让你失望。如果你一直在直接操作 HTML DOM，你可能习惯于使用`Element.className`属性。在 HTML 元素上，`className`属性是一个`读/写`字符串，对应于 HTML 元素上的`class`属性。在这种情况下，你可以操作字符串，改变会反映在 DOM 中。

DOM 接口`SVGElement`确实有一个`className`属性，但它不是一个简单的字符串。它是一个`SVGAnimatedString`属性，有两个字符串值，`AnimVal`和`BaseVal`。因为有了这一层额外的东西，而且因为我选择的替代接口现代化且更清晰，我决定使用`SVGElement.classList`属性来操作 CSS 类。`classList`是元素上 CSS 类的结构化接口。直接访问时，`classList`是`只读`的，但有可用的方法来查询和操作类列表。

让我们深入了解一下这段代码是如何工作的。

我们通过添加一个在`DOMContentLoaded`事件上触发的函数来开始整个过程。这个事件在 DOM 被浏览器读取时触发一个函数。如果你想在浏览器读取标记时在页面上使用一个元素，这是开始操作 DOM 的最安全的地方。然后我们设置了两个本地引用，一个是通过变量`doc`引用`document`，另一个是通过`canvas`变量引用 SVG 画布本身。

我们创建本地引用 DOM 属性和元素，因为 DOM 查找可能很慢。保存本地引用 DOM 属性和元素是一种常见的性能模式。

然后我们使用`querySelectorAll`获取按钮的集合，并依次循环遍历每个按钮，为每个按钮添加一个点击事件处理程序。在点击事件处理程序的主体中，我们最初设置了两个本地引用，`classlist`是指向目标 SVG 元素的`classList`的引用，还有一个`const`，引用了被请求的元素的`type`。这个类型是通过`use`元素上的`data-*`属性传递的。`data-*`是一种在 DOM 元素上存储任意数据的方法。

然后我们使用该类型和一个简单的`if...else`语句来确保目标 SVG 元素上有适当的类。在第一个`if`块中，我们测试当前类是否与当前类型匹配，并且它具有`active`类。如果它们匹配当前类型并且元素具有活动类，我们将删除这些类。这个动作是为了在我们已经用特定类型加载了光标并且想要通过单击相同的按钮来重置它的情况。下一个块检查光标是否处于活动状态但不是当前选定的类型。在这种情况下，我们删除所有类型类以确保清除所选类型，然后再添加当前选定的类型。在最后一个块中，光标不活动，所以我们只是添加`active`类和类型类，加载光标：

```xml
    /*
    Ecmascript 6
    */
    document.addEventListener("DOMContentLoaded", () => {
      let doc = document;
      let canvas = doc.getElementById("canvas");
      doc.querySelectorAll(".controls .btn").forEach((element) => {
        element.addEventListener("click", (event) => {
          let classlist = canvas.classList;
          const type = event.srcElement.dataset.type;
          if (classlist.contains("active") && classlist.contains(type)){
            classlist.remove("active",type);
          }
          else if (classlist.contains("active")){
            classlist.remove("circle","text","square");
            classlist.add(type);
          } else {
            classlist.remove("circle","text","square");
            classlist.add("active",type);
          }
        });
      });
    });
```

活动光标的 CSS 如下。在新的 CSS 中，我们简单地为每个活动光标的光标属性传递了一个 PNG 的 URL 引用：

```xml
    svg.canvas.active.square{
      cursor:url(square.png), crosshair;
    }
    svg.canvas.active.circle{
      cursor:url(circle.png), crosshair;
    }
    svg.canvas.active.text{
      cursor:url(text.png), crosshair;
    }

```

加载了一个圆形元素的光标如下截图所示：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/c46bf8db-e534-4b6b-be7d-fbef9eb946cc.png)

接下来，我们将逐步介绍在单击目标 SVG 元素时添加元素的过程。函数`add`是魔术发生的地方。首先我们设置了一些变量。我们首先使用五个常量。第一个是对`document`的引用，存储为`doc`，第二个是对目标 SVG 元素的引用，存储为`canvas`，第三个是目标 SVG 的`classList`，存储为`classes`，然后是 SVG 命名空间 URL 的引用，存储为**namespace**（**NS**），最后是创建并存储为`point`的`SVGpoint`。前三个应该很简单；`NS`变量的使用将很快解释。

`point`立即被使用。这是常规 DOM 操作和处理 SVG DOM 之间的一个主要区别，所以让我们来看看发生了什么。这段代码的基本目的是将点击事件的屏幕坐标转换为 SVG 元素内的正确（可能是变换或缩放后的）坐标。如果你一直在关注 SVG 的一般缩放方式以及变换如何与 SVG 元素一起工作的方式，你应该能够看到，根据文档的设置方式，屏幕像素可能与 SVG 文档中的用户单位匹配或不匹配。由于我们有一个静态的`viewbox`设置为 500 个用户单位，并且一个 SVG 元素被缩放以适应整个页面，我们需要使用一些 SVG 工具来访问当前的变换矩阵，并将该矩阵应用到点击的点上。

为了做到这一点，我们需要经历一些步骤。`point`是通过`createSVGPoint`创建的，这是一个返回当前 SVG 坐标系中点的方法。初始返回值有两个属性，`x`和`y`，都设置为零。我们立即用点击事件的鼠标坐标填充该变量。这些坐标作为事件对象的一部分自动传递给函数作为`event.offsetX`和`event.offsetY`。接下来，我们使用`getScreenCTM()`方法来获取**当前用户单位变换矩阵**（**CTM**）的逆。CTM 表示从屏幕坐标系转换到 SVG 文档中所需的变换步骤。调用`inverse()`方法返回从 SVG 用户单位坐标系转换到屏幕坐标系所需的步骤。因此，将该矩阵应用到 point 中定义的`(x,y)`点，将这些点移动到 SVG 文档中的正确位置。

最后，我们创建一个空变量`elem`，稍后将用要添加到文档中的元素填充。

接下来，我们实际创建元素。

如果目标 SVG 元素上有活动类，那么我们将向其添加一个元素。无论我们要创建哪种类型的元素，模式都是相同的：

1.  我们测试活动元素的类型。

1.  我们创建元素。

1.  在将其添加到 DOM 之前，我们对其设置了一些属性。

再次，如果你熟悉 DOM 操作，你会注意到这里有一些不同。这就是`NS`变量发挥作用的地方。由于这不是纯 HTML，实际上是一个完全不同的文档定义，我们需要提供该命名空间以正确创建元素。因此，我们不是使用`document.createElement`，而是必须使用`document.createElementNS`，并通过`NS`变量引用 SVG 命名空间的第二个参数。

元素创建后，我们使用`elem.setAttribute`设置相关属性。对于`rect`，我们设置`x`、`y`、`width`和`height`。对于`circle`，我们设置`r`、`cx`和`cy`。对于`text`元素，我们设置`x`、`y`，然后使用`elem.textContent`设置文本内容，如果你习惯使用`innerHTML`更新文本和/或 HTML 节点，这是一个新的变化。正如之前提到的，SVG 元素没有`innerHTML`。

一旦`elem`使用基线属性定义，我们就使用`appendChild`方法将其插入到文档中。最后，我们从目标 SVG 元素中删除`"active"`类，这将防止意外添加更多元素：

```xml
  function add(event) {
        const classes = canvas.classList;
        const NS = canvas.getAttribute('xmlns');
        const point = canvas.createSVGPoint()
        point.x = event.offsetX;
        point.y = event.offsetY;
        const svgCoords = 
        point.matrixTransform(canvas.getScreenCTM().inverse());
        let elem;
        if (classes.contains("active")) {
          if (classes.contains("square")) {
            elem = doc.createElementNS(NS, "rect");
            elem.setAttribute("x", svgCoords.x);
            elem.setAttribute("y", svgCoords.y);
            elem.setAttribute("width", 50);
            elem.setAttribute("height", 50);

          } else if (classes.contains("circle")) {
            elem = doc.createElementNS(NS, "circle");
            elem.setAttribute("r", 10);
            elem.setAttribute("cx", svgCoords.x);
            elem.setAttribute("cy", svgCoords.y);
          } else if (classes.contains("text")) {
            elem = doc.createElementNS(NS, "text");
            elem.setAttribute("x", svgCoords.x);
            elem.setAttribute("y", svgCoords.y);
            elem.textContent = "TEXT"
          }
          elem.setAttribute("fill", "#ff8000");
          canvas.appendChild(elem);
          classes.remove("active");
        }
      }
```

这是 SVG 画布上新添加的正方形元素如下：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/2089ef8b-202f-45e8-8501-c7e7e74fdf34.png)

虽然我们现在已经将事件绑定到文档并可以向屏幕添加元素，但这个演示还没有完成。我们需要做的是允许用户更新放置在目标 SVG 元素上的元素。虽然我们可以以越来越复杂的方式来做到这一点（点击和拖动，用鼠标或手指绘制新元素，复制和粘贴元素），但为了这个演示，我们只是允许用户点击 SVG 元素并打开一个小的 Bootstrap 模态框，让他们可以编辑基本的 SVG 属性。这将说明在不深入研究任何一组交互的情况下操纵底层 DOM 属性。这是特别重要的，因为许多最复杂的交互都最好由单独的库或框架处理。正如你将看到的，即使在最好的情况下，完全手工完成这些工作也可能很麻烦。

所以让我们开始吧。我们要做的第一件事是更新`add`函数的一行。这一行将点击事件处理程序添加到`elem`，这将触发`edit`函数。因此，看一下`add`函数底部，我们可以看到新代码：

```xml
          elem.setAttribute("fill", "#ff8000");
          canvas.appendChild(elem);
          classes.remove("active");  
 elem.addEventListener("click", edit, false);
```

在查看编辑功能之前，让我们先看一下模态框标记。如果你以前使用过 Bootstrap，这应该很熟悉。如果没有，基本知识是相当简单的。Bootstrap `modal`包装器类和`modal-`类的模式添加了 Bootstrap 模态框布局，并且这些类还指示 Bootstrap JavaScript 应该将 Bootstrap 特定的事件绑定到这个特定元素。我们很快将看到其中一个事件的作用。

每个模态框都有一个`id`，以便从我们的函数中引用，以及更新所选元素所需的特定表单字段。

第一个模态框用于编辑`rect`元素。它有一个`color`类型的`input`，允许用户选择新的背景颜色，两个`number`类型的`input`来更新`x`和`y`坐标，以及两个`number`类型的`input`来更新元素的`height`和`width`。

`number`和`color`类型的输入是较新的 HTML5 输入类型。

第二个模态框用于编辑`circle`元素。它提供了一个`color`输入来更改背景颜色，两个`number`输入来更改`cx`和`cy`属性，以及一个最终的`number`输入来更改圆的半径。

最终的模态框用于编辑`text`元素。它提供了一个`color` `input`来改变文本的颜色，两个`number` `inputs`来改变元素的`x`和`y`位置，以及一个`text` `input`来改变`text`元素的实际文本：

```xml
<div class="modal" tabindex="-1" role="dialog" id="rect-edit-modal">
    <div class="modal-dialog" role="document">
      <div class="modal-content">
        <div class="modal-header">
          <h5 class="modal-title">Edit your element</h5>
          <button type="button" class="close" data-dismiss="modal"
             aria-label="Close">
            <span aria-hidden="true">&times;</span>
          </button>
        </div>
        <div class="modal-body">
          <div class="row">
            <div class="col-4">
              <label for="rect-color">Background color:</label>
            </div>
            <div class="col-8">
              <input type="color" id="rect-color">
            </div>
          </div>
          <div class="row">
            <div class="col-2">
              <label for="rect-x">x:</label>
            </div>
            <div class="col-4">
              <input type="number" id="rect-x" class="form-control">
            </div>
            <div class="col-2">
              <label for="rect-y">y:</label>
            </div>
            <div class="col-4">
              <input type="number" id="rect-y" class="form-control">
            </div>
          </div>
          <div class="row">
            <div class="col-2">
              <label for="rect-width">width:</label>
            </div>
            <div class="col-4">
              <input type="number" id="rect-width" class="form-
                control">
            </div>
            <div class="col-2">
              <label for="rect-height">height:</label>
            </div>
            <div class="col-4">
              <input type="number" id="rect-height" class="form-
                control">
            </div>
          </div>
        </div>
        <div class="modal-footer">
          <button type="button" class="btn btn-primary" id="rect-
            save">Save changes</button>
          <button type="button" class="btn btn-secondary" data-
            dismiss="modal">Close</button>
        </div>
      </div>
    </div>
  </div>
  <div class="modal" tabindex="-1" role="dialog" id="circle-edit-
    modal">
    <div class="modal-dialog" role="document">
      <div class="modal-content">
        <div class="modal-header">
          <h5 class="modal-title">Edit your element</h5>
          <button type="button" class="close" data-dismiss="modal" 
              aria-label="Close">
            <span aria-hidden="true">&times;</span>
          </button>
        </div>
        <div class="modal-body">
          <div class="row">
            <div class="col-4">
              <label for="circle-color">Background color:</label>
            </div>
            <div class="col-8">
              <input type="color" id="circle-color">
            </div>
          </div>
          <div class="row">
            <div class="col-2">
              <label for="cirlce-cx">cx:</label>
            </div>
            <div class="col-4">
              <input type="number" id="circle-cx" class="form-control">
            </div>
            <div class="col-2">
              <label for="circle-cy">cy:</label>
            </div>
            <div class="col-4">
              <input type="number" id="circle-cy" class="form-control">
            </div>
          </div>
          <div class="row">
            <div class="col-2">
              <label for="circle-radius">radius:</label>
            </div>
            <div class="col-4">
              <input type="number" id="circle-radius" class="form-
                control">
            </div>

          </div>
        </div>
        <div class="modal-footer">
          <button type="button" class="btn btn-primary" id="circle-
            save">Save changes</button>
          <button type="button" class="btn btn-secondary" data-
            dismiss="modal">Close</button>
        </div>
      </div>
    </div>
  </div>
  <div class="modal" tabindex="-1" role="dialog" id="text-edit-modal">
    <div class="modal-dialog" role="document">
      <div class="modal-content">
        <div class="modal-header">
          <h5 class="modal-title">Edit your element</h5>
          <button type="button" class="close" data-dismiss="modal"
             aria-label="Close">
            <span aria-hidden="true">&times;</span>
          </button>
        </div>
        <div class="modal-body">
          <div class="row">
            <div class="col-4">
              <label for="text-color">Color:</label>
            </div>
            <div class="col-8">
              <input type="color" id="text-color">
            </div>
          </div>
          <div class="row">
            <div class="col-2">
              <label for="text-x">x:</label>
            </div>
            <div class="col-4">
              <input type="number" id="text-x" class="form-control">
            </div>
            <div class="col-2">
              <label for="text=y">y:</label>
            </div>
            <div class="col-4">
              <input type="number" id="text-y" class="form-control">
            </div>
          </div>
          <div class="row">
            <div class="col-2">
              <label for="text-text">content:</label>
            </div>
            <div class="col-10">
              <input type="text" id="text-text" class="form-control">
            </div>

          </div>
        </div>
        <div class="modal-footer">
          <button type="button" class="btn btn-primary" id="text-
            save">Save changes</button>
          <button type="button" class="btn btn-secondary" data-
            dismiss="modal">Close</button>
        </div>
      </div>
    </div>
  </div>
```

现在让我们来看一下`edit`函数。这里大部分有趣的事情都是基于`event 参数`。`event`引用了有关触发的事件的各种信息。`edit`检查`event.srcElement.nodeName`来查看点击了什么类型的元素。然后，函数对每种元素类型都做三件事。

1.  它使用带有`"show"`选项调用的`$().modal`方法打开正确的编辑模态框。

1.  它使用 jQuery 的`$().data()`方法存储对当前元素的引用。`$().data`允许您将任意数据绑定到元素上。我们将在第七章中查看更多 jQuery 功能，*常见的 JavaScript 库和 SVG*，但由于我们已经在使用 jQuery 来获取 Bootstrap 方法，让我们在这里使用`$().data()`为了方便起见。

1.  它从单击的元素中加载当前值并将其加载到表单字段中。这有多个实例，但在大多数情况下它们遵循相同的模式。`form`字段通过`id`引用，并使用`event.srcElement.getAttribute`访问的当前值进行设置。唯一的例外是通过`event.srcElement.textContent`属性访问的文本元素的文本值。

因此，一旦单击元素，模态框就会打开，并填充当前值，准备进行操作：

```xml
      function edit(event) {
        let elem = event.srcElement;

        if (event.srcElement.nodeName.toLowerCase() === "rect") {
          $("#rect-edit-modal").modal("show").data("current-element",
             elem);
          document.getElementById("rect-color").value = 
            elem.getAttribute("fill");
          document.getElementById("rect-x").value =
             elem.getAttribute("x");
          document.getElementById("rect-y").value = 
            elem.getAttribute("y");
          document.getElementById("rect-width").value =
             elem.getAttribute("width");
          document.getElementById("rect-height").value =
             elem.getAttribute("height");
        }
        else if (event.srcElement.nodeName.toLowerCase() === "circle") {
          $("#circle-edit-modal").modal("show").data("current-element",
             elem);
          document.getElementById("circle-color").value = 
            elem.getAttribute("fill");
          document.getElementById("circle-cx").value =
             elem.getAttribute("cx");
          document.getElementById("circle-cy").value = 
             elem.getAttribute("cy");
          document.getElementById("circle-radius").value =
             elem.getAttribute("r");
        }
        else if (event.srcElement.nodeName.toLowerCase() === "text") {
          $("#text-edit-modal").modal("show").data("current-element",
             event.srcElement);
          document.getElementById("text-color").value =
             elem.getAttribute("fill");
          document.getElementById("text-x").value =
             elem.getAttribute("x");
          document.getElementById("text-y").value = 
            elem.getAttribute("y");
          document.getElementById("text-text").value = 
            elem.textContent;
        }
      }
```

以下是打开的模态框的样子：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/a256e53c-283b-4153-8488-27544cfe6e6b.png)

为了捕获更改，我们需要向文档添加一些更多的事件处理程序和一些更多的函数来保存数据。这是通过向三个模态框保存按钮添加一些点击处理程序，并定义三个不同的函数来处理更改来完成的。

正如您在下一个示例中所看到的，事件处理程序很简单。您可以使用`document.getElementById`获取每个保存按钮的引用，并使用`addEventListener`将正确的保存处理程序添加到每个元素中：

```xml
 document.getElementById("rect-save").addEventListener("click",
  rectSave);
 document.getElementById("circle-save").addEventListener("click",
 circleSave);
 document.getElementById("text-save").addEventListener("click", 
  textSave);
```

各种保存函数也很简单。它们最初都使用`$.modal()`方法隐藏打开的模态框，并传递`hide`参数。之后，函数使用`$().data()`方法的 get 签名存储对当前单击元素的引用，并将其存储为本地变量`elem`。然后，根据类型，函数从表单中访问值，并在所选元素上设置新值。`rectSave`访问`fill`、`x`、`y`、`height`和`width`属性。`circleSave`访问`fill`、`cx`、`cy`和`r`属性。`text``Save`访问`fill`、`x`、`y`和`text`属性：

```xml
function rectSave() {
        $("#rect-edit-modal").modal("hide");
        let elem = $("#rect-edit-modal").data("current-element")
        elem.setAttribute("fill", document.getElementById("rect-
        color").value);
        elem.setAttribute("x", document.getElementById("rect-
        x").value);
        elem.setAttribute("y", document.getElementById("rect-
        y").value);
        elem.setAttribute("height", document.getElementById("rect-
        height").value);
        elem.setAttribute("width", document.getElementById("rect-
        width").value);
      }
      function circleSave() {
        $("#circle-edit-modal").modal("hide");
        let elem = $("#circle-edit-modal").data("current-element")
        elem.setAttribute("fill", document.getElementById("circle-
        color").value);
        elem.setAttribute("cx", document.getElementById("circle-
        cx").value);
        elem.setAttribute("cy", document.getElementById("circle-
         cy").value);
        elem.setAttribute("r", document.getElementById("circle-
        radius").value);
      }
      function textSave() {
        $("#text-edit-modal").modal("hide");
        let elem = $("#text-edit-modal").data("current-element")
        elem.setAttribute("fill", document.getElementById("text-
        color").value);
        elem.setAttribute("x", document.getElementById("text-
        x").value);
        elem.setAttribute("y", document.getElementById("text-
        y").value);
        elem.textContent = document.getElementById("text-text").value;
      }
```

对`text`元素运行`edit`函数的效果如下截图所示：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/c013c260-996f-449f-8e11-e6e48bfa6965.png)

应用这些值会产生以下输出：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/86da3adf-b9df-4341-8580-65c8d1f2c132.png)

虽然我们可以为这个小的 SVG 编辑演示添加许多更多的功能，但这个例子既足够简单，可以在一个章节中理解，也可以让我们说明用于在屏幕上添加、访问和更新 SVG 元素的基本模式。如果您以前有一些原始 DOM 操作的经验，这对您来说应该是很熟悉的。如果没有，这是一组有用的技能，您在这里看到的基本模式是 SVG 和 HTML 领域中所有工作的方式。一旦您访问了一个元素，您就可以访问和更新它的属性，并在其上调用各种方法来调整它在屏幕上的位置。有了这个基础，您将能够解决一些可能不容易通过库或框架解决的问题，无论是在 SVG 还是 HTML 中。

# 总结

在本章中，您创建了一个小型应用程序，允许您在目标 SVG 画布上添加和编辑 SVG 元素。通过这个应用程序，您学习了各种 DOM 功能和功能，包括：

+   使用`document.getElementById`和`document.querySelectorAll`两种不同的方式访问 DOM 元素

+   如何使用`document.createElementNS`和`appendChild`插入 SVG 元素

+   如何使用`addEventListener`将事件绑定到 HTML 和 SVG 元素

+   如何使用`classList`接口从 SVG 元素获取、设置和移除 CSS 类

+   如何使用`getAttribute`和`setAttribute`操纵常见的 SVG 属性

+   如何使用`getScreenCTM`方法在浏览器坐标系和 SVG 元素坐标系之间进行转换，以获取*C*urrent 用户单位* T *ransformation * M *atrix 的逆

+   如何使用`textContent`设置 SVG 文本元素的文本内容

除了您已经在本书中学到的知识，本章学到的知识将使您能够在各种任务中以非常高的水平使用 SVG。如果您熟悉原始 DOM 接口，创建、访问和操作 DOM 元素的模式就是您构建最复杂的 Web 应用程序和可视化所需的一切。

在此基础上，我们将把到目前为止学到的所有知识应用到其他库和框架上，这样您就可以利用 jQuery、React 和 D3 等库以及 Angular 等框架在原始 DOM 接口之上提供的强大和便利功能。


# 第七章：常见的 JavaScript 库和 SVG

现在你已经看过了 SVG 的原始 DOM 接口，是时候看看 SVG 与一些更常见的 JavaScript 库和框架之间的接口了。借鉴于第六章中学到的*JavaScript 和 SVG*的经验，我们将研究在使用 jQuery、AngularJS（1.*）、Angular（2+）和 ReactJS 时使 SVG 正常工作时出现的一些特殊情况。这些示例不会很深入，但应该都能说明在处理 SVG 和这些其他代码库时存在的基本问题。这里的目标不是要完全向你介绍这些库和框架。只会有足够的介绍让你能够开始运行，然后每个部分都将处理该库或框架以及 SVG 的具体问题。

在本章中，我们将涵盖：

+   使用广受欢迎的 jQuery 库和 SVG

+   Angular 1 和 Angular（2+）与 SVG 之间的接口

+   SVG 和 ReactJS，这是 Facebook 的流行库

# 使用 jQuery 操纵 SVG

我们将首先看的库是 jQuery。jQuery 并不像以前那样热门，但它仍然是地球上最流行的 JavaScript 库，了解在 SVG 中使用 jQuery 的特殊情况仍然可能是有用的。

由于 jQuery 作为常见 DOM 交互的友好替代，本节将展示我们在第六章中进行的 DOM 操作演示的基于 jQuery 的重写，JavaScript 和 SVG。

它使用完全相同的标记，因此在本章中我们需要查看的唯一位置是底部的脚本块。

此代码将以惯用的 jQuery/ES5 编写。

我们将首先看一下我们将在 jQuery 的`DOMContentLoaded`事件的等价事件上触发的函数，即`$(document).ready()`。`$(document).ready()`接受一个函数作为参数。正如其名称所示，当文档的 DOM 内容加载完成时，该函数将被执行。

虽然你可以传入一个函数表达式，但我们将定义一个传递给`$(document).ready()`的传统命名的函数`init`。

在其中，我们设置了一些事件处理程序。第一个是我们按钮的`click`事件处理程序。它触发`loadCursor`函数。第二到第四个事件处理程序为每种不同的 SVG 元素类型创建`save`事件。最后一个将`add`函数添加到`#canvas`元素中，以便在画布元素上单击时知道要将所选的 SVG 元素放到页面上：

```xml
  function init() {
      $(".controls .btn").on("click", loadCursor); 
      $("#rect-save").on("click", rectSave);
      $("#circle-save").on("click", circleSave);
      $("#text-save").on("click", textSave);
      $("#canvas").on("click", add);
    }
$().ready(init);
```

现在我们已经看过了启动应用程序的函数，让我们依次看看其他函数。首先我们将看看`add`函数的新版本。`add`有一个主要的问题，然后还有几个较小的问题。

我们首先通过获取一个加载了 jQuery 引用的`$("#canvas")` SVG 元素来开始。之后，初始化与函数的纯 JavaScript 版本类似。

这包括一个主要的问题，即 jQuery 的预期行为失败的地方。虽然常见的 jQuery 元素创建方法如`$("<rect>")`适用于 SVG 元素，并将`<rect>`元素插入页面，但它们仍然需要使用正确的命名空间进行创建。没有命名空间，就像你在上一章中学到的那样，它们将被浏览器视为任意的 HTML 元素，并不会按预期渲染。因此，就像纯 JS 示例中一样，我们需要向元素创建添加命名空间。因此，我们使用与仅 JavaScript 示例中相同的`elem = doc.createElementNS(NS, "rect");`模式来执行此操作。一旦元素被创建，它就可以像通常一样被插入到 DOM 中并用 jQuery 进行操作。

元素创建后，`square`、`circle`和`text`的各个选项都与仅 JavaScript 示例类似地处理。在这种情况下，我们只是使用 jQuery 的便利方法`$().hasClass()`和`$().attr()`来测试类名并设置各种属性。

最后，我们使用更多的 jQuery 便利方法将元素添加到`$canvas`元素中，移除`"active"`类，并添加`click`事件处理程序来编辑元素：

```xml
function add($event) {
      var $canvas = $("#canvas");
      var elem;
      var doc = document;
      var NS = canvas.getAttribute('xmlns');
      var point = canvas.createSVGPoint();
      var $elem;
      point.x = $event.offsetX;
      point.y = $event.offsetY;
      var svgCoords = 
        point.matrixTransform(canvas.getScreenCTM().inverse());
      if ($canvas.hasClass("active")) {
        if ($canvas.hasClass("square")) {
          elem = doc.createElementNS(NS, "rect");
          $elem = $(elem).attr({
            "x": svgCoords.x,
            "y": svgCoords.y,
            "width": 50,
            "height": 50
          });

        } else if ($canvas.hasClass("circle")) {
          elem = doc.createElementNS(NS, "circle");

          $elem = $(elem).attr({
            "cx": svgCoords.x,
            "cy": svgCoords.y,
            "r": 10
          });
        } else if ($canvas.hasClass("text")) {
          elem = doc.createElementNS(NS, "text");
          $elem = $(elem).attr({
            "x": svgCoords.x,
            "y": svgCoords.y,
            "width": 50,
            "height": 50
          });
          $elem.text("TEXT");

        }
        $elem.attr("fill", "#ff8000");
        $canvas.append($elem);
        $canvas.removeClass("active");
        $elem.on("click", edit);
      }
    }
```

三个编辑函数再次遵循与普通 JS 示例相同的模式。在每个函数中，我们获取一个加载的 jQuery 引用到`target`元素，并将其存储为`$elem`。然后我们使用 jQuery 方法`$().prop`，它查找对象属性，以测试调用对象的`nodeName`。然后我们显示正确的模态，使用 Bootstrap 模态方法调用`"show"`参数，并使用 jQuery `$().data`方法设置当前元素。`$().data`，正如你在第六章中记得的，*JavaScript 和 SVG*，在元素上获取和设置任意数据。然后我们使用`$().val()`方法的组合，它获取或设置表单输入的值，和`$().attr()`方法，它获取或设置元素属性，来填充表单值。`$().val()`在这里用于通过读取 SVG 元素的值来设置表单的值，使用`$().attr()`调用`getter`（没有参数）并将该值作为`$().val()`的参数：

```xml
   function edit($event) {
      var $elem = $($event.target);
      if ($elem.prop("nodeName") === "rect") {
        $("#rect-edit-modal").modal("show").data("current-element",
         $elem);

        $("#rect-color").val($elem.attr("fill"));
        $("#rect-x").val($elem.attr("x"));
        $("#rect-y").val($elem.attr("y"));
        $("#rect-width").val($elem.attr("width"));
        $("#rect-height").val($elem.attr("height"));
      }
      else if ($elem.prop("nodeName") === "circle") {
        $("#circle-edit-modal").modal("show").data("current-element",
         $elem);
        $("#circle-color").val($elem.attr("fill"));
        $("#circle-cx").val($elem.attr("cx"));
        $("#circle-cy").val($elem.attr("cy"));
        $("#circle-radius").val($elem.attr("r"));
      }
      else if ($elem.prop("nodeName") === "text") {
        $("#text-edit-modal").modal("show").data("current-element",
         $elem);
        $("#text-color").val($elem.attr("fill"));
        $("#text-x").val($elem.attr("x"));
        $("#text-y").val($elem.attr("y"));
        $("#text-text").val($elem.text());
      }
    }
```

最后，我们有各种`save`方法。这些遵循与之前示例相同的模式。这与普通 JS 示例的基本工作流程相同，但我们再次能够使用完整的 jQuery 便利方法来操作我们的 SVG 元素：使用 Bootstrap 方法隐藏模态，使用`$().data()`方法获取对当前元素的引用，然后使用`$().attr()`方法设置属性，称为`setter`，和`$().val()`称为`getter`，作为参数：

```xml
    function rectSave() {
      $("#rect-edit-modal").modal("hide");
      var $elem = $("#rect-edit-modal").data("current-element");
      $elem.attr({
        "fill": $("#rect-color").val(),
        "x": $("#rect-x").val(),
        "y": $("#rect-y").val(),
        "height": $("#rect-height").val(),
        "width": $("#rect-width").val()
      });
    }
    function circleSave() {
      $("#circle-edit-modal").modal("hide");
      var $elem = $("#circle-edit-modal").data("current-element");
      $elem.attr({
        "fill": $("#circle-color").val(),
        "cx": $("#circle-cx").val(),
        "cy": $("#circle-cy").val(),
        "r": $("#circle-radius").val()
      });
    }
    function textSave() {
      $("#text-edit-modal").modal("hide");
      var $elem = $("#text-edit-modal").data("current-element");
      $elem.attr({
        "fill": $("#text-color").val(), "x": $("#text-x").val(),
        "y": $("#text-y").val()
      });
      $elem.text($("#text-text").val());
    }
```

正如你所看到的，除了元素创建之外，使用 SVG 和 jQuery 是直接的。元素创建需要使用标准 DOM 方法，但与 SVG 元素的其他交互可以使用适当的 jQuery 方法。

# 使用 AngularJS 和 SVG

现在是时候看看在更完整的应用程序框架中使用 SVG。我们将从 AngularJS 开始，这是 Google 广受欢迎的应用程序框架的原始版本。虽然 AngularJS（Angular 1.*）在 Web 框架的背景下已经过时，但它仍然受欢迎，并在许多环境中使用。它也为许多人所熟悉，并且被广泛部署，因此从多个角度来看，了解如何在 AngularJS 应用程序中使用 SVG 是有用的。

这个和接下来的示例将比 jQuery 和纯 JavaScript 演示更简单。这有两个原因。首先，你已经在 SVG 和 JavaScript 在 DOM 中的交互方面看到了很多细节。你实际上已经准备好自己处理 SVG DOM 操作，因此在不同框架中涵盖大量变化可能甚至不那么有益。覆盖基础知识应该足够让你自己去做。

其次，我们不希望太多关于实际库和框架的细节。将每个介绍保持在最低限度意味着我们可以专注于讨论的 SVG 部分。为此，我们将看看最简单的演示，它将展示在应用程序中使用元素的两个最重要方面：将动态 SVG 元素插入 DOM，并通过用户交互对其进行操作。

演示将如下所示：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/78f442d6-4ff8-45d9-bad1-4181bb70b9c4.png)

这段代码将以惯用的 ES5 方式编写。

以下是代码。这个示例的所有代码都在一个单独的 HTML 文件中。这通常不是您构建 AngularJS 应用程序的方式，但对于这个示例来说，它完全可以。

文档`head`使用必要的脚本和样式设置应用程序。我们链接到 Bootstrap，jQuery 和 Angular：

```xml
<head>
  <link rel="stylesheet" 
   href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.
    min.css" integrity="sha384-
    Gn5384xqQ1aoWXA+058RXPxPg6fy4IWvTNh0E263XmFcJlSAwiGgFAW/dAiS6JXm"
    crossorigin="anonymous">
  <link rel="stylesheet" href="style.css" />
  <script src="img/jquery-3.3.1.min.js" 
          integrity="sha256-
            FgpCb/KJQlLNfOu91ta32o/NMZxltwRo8QtmkMRdAu8="
            crossorigin="anonymous"></script>
  <script  
   src="img/>    min.js"></script>
</head>
```

有趣的部分从`body`元素开始。这是我们设置 Angular 应用程序的地方。`ng-app`属性表示 Angular 应该处理`body`元素及其所有子元素，并将 Angular 的特殊解析规则应用于其中包含的标记。我们很快会看到`ng-app`值`"angularSVG"`的引用指的是什么。

接下来的标记是我们将 UI 与 Angular 功能和功能绑定在一起的地方。Angular 使用特殊属性和自定义 HTML 元素的组合来创建动态界面。

从我们的角度来看，最重要的部分是使用`ng-attr`前缀来处理`fill`、`cx`、`cy`和`r`属性。Angular 允许您在标记中引用当前控制器作用域中的变量，只要它包含在`{{}}`模式中，Angular 就会用模型中的值替换该引用。这是一个实时引用，它将在常规周期中自动更新。

这个非常方便的特性*不*与某些 SVG 属性兼容。虽然在您玩转应用程序并将值从 Angular 令牌转换为数值后，以下内容最终会起作用，但在文档加载时会出现错误：

```xml
<circle
      fill="{{fill}}" 
      cx="{{cx}}" 
      cy="{{cy}}" 
      r="{{r}}" />
```

错误可以在以下截图中看到。SVG 解析器期望一个`length`值，而实际上得到的是一个字符串：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/e81c74fe-a429-4888-844f-5b0231f501e3.png)

修复这个问题需要使用`ng-attr`前缀。这个前缀告诉 Angular 在插值步骤中使用`allOrNothing`标志。简单来说，这意味着如果属性的值是`undefined`，则不会将属性呈现到文档中。一旦它有一个值，它就会像正常一样呈现。

这个标记的第二个有趣部分是自定义 HTML 元素`angular-rect`。`angular-rect`是 Angular 中所谓的**指令**。指令是 Angular 用来创建自定义 HTML 元素和属性的机制，允许您通过自己设计的可重用代码块来扩展和增强常见的 HTML 元素和文档。虽然这个很简单，但很快你会看到，这个自定义元素将简洁地说明 Angular 指令如何与 SVG 一起工作。

标记中唯一有趣的部分是使用`ng-model`属性将 JavaScript 变量值绑定到表单字段中。这个特殊的 AngularJS 属性在标记和 Angular 控制器之间建立了双向数据绑定。我们很快会看到这些变量是如何在控制器中设置的，但请记住一点，一旦建立了这种连接，AngularJS 会保持它的活力，并在`form`字段更新时自动更新 SVG 元素中的值：

```xml
<body ng-app="angularSVG">
  <div ng-controller="circleController" class="container">
    <svg  width="150" height="150" 
     viewBox="0 0 150 150" version="1.1">
      <circle
      ng-attr-fill="{{fill}}" 
      ng-attr-cx="{{cx}}" 
      ng-attr-cy="{{cy}}" 
      ng-attr-r="{{r}}" />
      <angular-rect></angular-rect>
    </svg>
    <div class="row">
      <div class="col-4">
        <label>Background color:</label>
      </div>
      <div class="col-8">
        <input type="color" ng-model="fill" id="circle-color">
      </div>
    </div>
    <div class="row">
      <div class="col-2">
        <label>cx:</label>
      </div>
      <div class="col-4">
        <input type="number" ng-model="cx" id="circle-cx" class="form-
          control">
      </div>
      <div class="col-2">
        <label>cy:</label>
      </div>
      <div class="col-4">
        <input type="number" ng-model="cy" id="circle-cy" class="form-
         control">
      </div>
    </div>
    <div class="row">
      <div class="col-2">
        <label>radius:</label>
      </div>
      <div class="col-4" height="{{cx}}>
        <input type="number" ng-model="r" id="circle-radius" 
          class="form-control">
      </div>
    </div>
  </div>
```

JavaScript 非常简单。只需几行 JavaScript 代码，就可以将表单字段的值动态调整为圆的高度、宽度和填充颜色。第一部分是`angular.module()`方法调用，创建了一个名为`"angularSVG"`的 Angular 应用程序。这个引用是 Angular 在标记中寻找的，以便知道页面上是否有一个 Angular 应用程序。如果它在`ng-app`中找到这个值，它会解析该标记并将基于 Angular 的魔术应用到页面上。

接下来是我们小的控制器定义，`circleController`。`circleController`有一个参数，即 Angular 的`$scope`变量。如果您对 Angular 不熟悉，可以将`$scope`视为函数的`this`值的受控别名。它是控制器的内部状态，`$scope`中的属性和方法对 JavaScript 代码和对 Angular 感知的标记都是可用的。

在控制器内部，我们只是在`$scope`上设置了一些变量。这些变量作为圆的基线值，并且由于它们绑定到 Angular 的`$scope`，它们自动成为与圆和表单字段中相应值的活动、双向链接。

之后，我们创建了一个简单的 Angular 指令`angularRect`，它只是在 SVG DOM 中插入一个`rect`元素。我们不会在这里讨论 Angular 指令的复杂性，但有一个特定的细节对于 SVG 元素非常重要。返回对象的`templateNamespace`属性指示 Angular 应将该指令视为 SVG。没有它，就像 jQuery 的常见 DOM 创建模式和 DOM 方法`document.createElement`一样，该指令将被插入文档，但它不会被创建为一个正确的 SVG 元素。它会存在，但在渲染时不会显示为一个正方形：

Angular 在 JavaScript 中使用友好的驼峰命名法，然后在将元素插入文档时使用短横线命名法。

```xml
 <script>
    angular.module('angularSVG', [])
      .controller('circleController', function ($scope) {
        $scope.cx = 75;
        $scope.cy = 75;
        $scope.r = 50;
        $scope.fill = "#ff0000";
      }).directive('angularRect', function() {
        return {
            restrict: 'E',
            templateNamespace: 'svg',
            template: '<rect x="125" y="125" width="10" height="10"
             stroke="blue" fill="none"></rect>',
            replace: true
        };
});
  </script>
```

在浏览器中运行并调整数值后，效果如下截图所示。初始截图显示了加载初始数值的演示：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/679721ca-ec4c-472c-8dab-93db93e873f8.png)

第二个截图显示了调整后的数值和圆形元素相应地发生了变化：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/61019910-73f6-4104-a8fe-b2d9f22c609b.png)

现在我们已经了解了 AngularJS，让我们来看看 Angular 的新进化，Angular 2.0+。这个版本的框架被称为 Angular，与之前的版本非常不同，功能非常强大。

让我们快速看一下。

# 使用 Angular 操作 SVG

从 AngularJS 转向，让我们来看看 Angular 的现代进化。Angular 2.0+（简称为 Angular）是一个非常现代的框架。它通常是用 TypeScript 编写的，这是 JavaScript 的一个超集，它添加了一些可选功能，Angular 利用这些功能为库添加了一些非常方便的功能和功能。

# 开始使用 Angular

由于 Angular 是一个较新的框架，占用的空间较大，我们将介绍一些设置步骤。下载示例中的代码将可以工作，但了解如何到达那里是非常有用的。所以，让我们开始设置。

这个 Angular 示例将复制使用 Angular 代码重新制作的与 AngularJS 示例提供的完全相同的演示。正如您可能已经感觉到并将继续学习的那样，无论您使用哪种库或框架，动态 SVG 的基本问题都是相同的；解决方案只是略有不同。

您可以使用任何您喜欢的文本编辑器来进行 Angular 示例，但我建议使用微软的 VS Code。它是免费的，得到很好的支持，经常更新，并且与 TypeScript 非常兼容。

# 安装 Node、npm 和 Angular Cli

在您开始使用 Angular 之前，您需要设置好实际运行代码所需的工具。一切的基础是 Node.js 和 Node 的包管理器`npm`。因此，如果您还没有安装，您应该首先安装它们。最简单的方法是转到[nodejs.org](http://nodejs.org)并下载适用于您操作系统的安装程序。

安装完成后，您可以继续安装 Angular 的**命令行工具**（**CLI**）。Angular CLI 使得启动 Angular 项目变得非常容易，您很快就会看到。以下命令将在您的计算机上全局安装 Angular CLI：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/e6996342-dc66-40a8-aeca-cacbb33cd7b7.png)

1.  安装完成后，使用`ng new`命令创建一个项目。`ng new`将创建一个新的文件夹，其中包含启动 Angular 项目所需的一切。我们不会详细介绍，但运行此命令后，您应该已经准备好开始使用您的应用程序了：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/69ce9e39-72c3-4440-91bb-e24b1e65ee66.png)

1.  下一步是进入您刚创建的文件夹并运行`npm install`：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/4260a2d0-c0bf-4637-8a08-bce5d90db340.png)

`npm install`将确保所有依赖项都安装在`node_modules`中，并且您的应用程序将准备就绪。

1.  从 VS Code 的以下屏幕截图显示了初始化应用程序并运行`npm` install 后的布局：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/a23bd629-8d25-487a-b286-285ec1c0a6de.png)

1.  由于我们在这个演示版本中也使用 Bootstrap，因此需要确保它可用。通过运行以下命令完成：

```xml
npm install --save bootstrap 
```

这将把 Bootstrap 安装到您的`node_modules`中：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/d9e8b949-b4ea-493c-ba95-60fb6ede1ca3.png)

然后，您可以在`angular-cli.json`中进行连接。`angular-cli.json`是您配置 Angular CLI 安装的不同方面的地方。在这种情况下，我们只需要将 Bootstrap CSS 添加到 styles 属性中，以便它将与应用程序的其余部分捆绑在一起：

在幕后，Angular CLI 使用 Webpack 来捆绑脚本和样式，并以多种方式处理它们，以便将它们准备好交付到开发服务器以及生产环境。使用 Angular CLI 的最大好处之一是它简化了使用 Webpack 的复杂性。Webpack 非常强大，但学习曲线陡峭。Angular CLI 让它变得简单易用。

```xml
 "apps": [
    {
      "root": "src",
      "outDir": "dist",
      "assets": [
        "assets",
        "favicon.ico"
      ],
      "index": "index.html",
      "main": "main.ts",
      "polyfills": "polyfills.ts",
      "test": "test.ts",
      "tsconfig": "tsconfig.app.json",
      "testTsconfig": "tsconfig.spec.json",
      "prefix": "app",
      "styles": [
        "../node_modules/bootstrap/dist/css/bootstrap.css",
        "styles.css"
      ],
      "scripts": [],
      "environmentSource": "environments/environment.ts",
      "environments": {
        "dev": "environments/environment.ts",
        "prod": "environments/environment.prod.ts"
      }
    }
  ],
```

在这种简单状态下运行应用程序将允许我们开始开发应用程序，并针对在本地运行的开发服务器进行测试。这是使用`ng serve`命令完成的。在编译代码后，使用`--open`选项将打开一个 Web 浏览器：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/1be8b908-3865-4ae3-852d-ab260405e18a.png)

这将在浏览器中自动重新加载代码，每当对代码进行更改时。

因此，现在是时候开始编写一些 TypeScript 并与 SVG 进行交互了。

我们要做的第一件事是编辑应用程序的主模块。`app.module.ts`是应用程序的根模块，它是应用程序的所有部分连接在一起的地方。大部分都是由`Angular CLI`自动连接的。我们只需要使用新的 ES6 模块模式（`import` `module from src`）从 Angular 核心导入`FormsModule`。然后将其添加到`@NgModule`装饰器的`imports`数组中。这允许`FormsModule`的指令和属性在此应用程序中可用：

```xml
import { BrowserModule } from '@angular/platform-browser';
import { NgModule } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { AppComponent } from './app.component';

@NgModule({
  declarations: [
    AppComponent,
    AngularRectComponent
  ],
  imports: [
    BrowserModule,
    FormsModule
  ],
  providers: [],
  bootstrap: [AppComponent]
})
export class AppModule { }
```

接下来，我们将完全编辑`app.component.ts`文件以表示我们的（简单）组件。在其中，我们从 Angular 导入`Component`和`FormsModule`，在`@Component`装饰器中进行一些标准的维护工作，然后导出`AppComponent`类，其中包含四个设置的属性。这种模式值得一些解释，因为它可能很熟悉，但又有足够的不同之处，可能会让人费解。首先，所有这些都是使用`public`关键字创建的。这表示这些属性应该在类的范围之外可用。接下来是变量名称本身，后跟冒号和类型注释，指示变量的预期类型。TypeScript 允许您基于其他 TypeScript 类创建自定义类型，但对于我们的目的，我们只是使用标准的 JavaScript 原语，`number`和`string`。最后，我们为它们设置默认值，以便我们的应用程序有东西可以依靠：

```xml
import { Component } from '@angular/core';
import { FormsModule } from '@angular/forms';

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.css']
})
export class AppComponent {
  public cx:number = 75;
  public cy:number = 75;
  public r:number = 50
  public color:string = "#cc0000";
}
```

接下来是标记，与之前的示例类似。它都包含在`app.component.html`中。与 AngularJS 版本有一些相似之处。例如，动态属性必须以类似的方式处理，仍然不能直接绑定到 SVG 属性而不引起错误，因此仍然必须显式地管理它们。在这种情况下，您使用`attr.`前缀而不是在 AngularJS 中使用的`ng-attr-`前缀。您还会注意到属性周围的方括号。

使用简单的方括号`[]`表示这是单向数据绑定；模板从我们之前定义的组件属性中读取。稍后，在输入中，我们看到了使用方括号/括号`[()]`语法围绕属性的显式双向数据绑定的示例。`ngModel`是我们使用`FormsModule`导入的指令。它允许我们从表单元素到组件属性进行双向数据绑定。这样，表单中的条目再次表示为 SVG `circle`元素的属性，并且随着对`form`字段的更改而显示更改。

```xml
<div class="container">
  <svg  width="150" height="150" viewBox="0 0 150 150" version="1.1">
    <svg:circle
    [attr.fill]="color"
    [attr.cx]="cx"
    [attr.cy]="cy"
    [attr.r]="r" />
  </svg>
  <div class="row">
    <div class="col-4">
      <label>Background color:</label>
    </div>
    <div class="col-8">
      <input type="color" [(ngModel)]="color" id="circle-color">
    </div>
  </div>
  <div class="row">
    <div class="col-2">
      <label>cx:</label>
    </div>
    <div class="col-4">
      <input type="number" id="circle-cx" [(ngModel)]="cx" class="form-
        control">
    </div>
    <div class="col-2">
      <label>cy:</label>
    </div>
    <div class="col-4">
      <input type="number" id="circle-cy" [(ngModel)]="cy" class="form-
        control">
    </div>
  </div>
  <div class="row">
    <div class="col-2">
      <label>radius:</label>
    </div>
    <div class="col-4">
      <input type="number" id="circle-radius" [(ngModel)]="r" 
        class="form-control">
    </div>
  </div>
</div>
```

我们只需要做一件事情，就可以使这个 Angular 示例与之前的 AngularJS 示例匹配，那就是添加一个代表小蓝色`rect`元素的子组件。这里有一些有趣的地方。首先是展示了 Angular CLI 的强大之处。使用 Angular CLI，如果需要连接一个组件，可以使用`ng new`命令。在我们的例子中，我们将运行`ng new component angular-rect`，这将生成组成 Angular 组件的各种文件，并将实际将组件连接到`app.module.ts`中：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/4e746339-5776-421b-9d45-09f97e6b244b.png)

您可以在以下更新的代码示例中看到`app.module.ts`的样子，其中导入了新的`AngularRectComponent`组件并将其添加到`@NgModule`声明中：

```xml
import { BrowserModule } from '@angular/platform-browser';
import { NgModule } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { AppComponent } from './app.component';
import { AngularRectComponent } from './angular-rect/angular-rect.component';

@NgModule({
  declarations: [
    AppComponent,
    AngularRectComponent
  ],
  imports: [
    BrowserModule,
    FormsModule
  ],
  providers: [],
  bootstrap: [AppComponent]
})
export class AppModule { }
```

还有一些与 SVG 直接相关的问题，需要指出才能将这个自定义元素放到页面上。首先是需要在`angular-rect`组件中的元素中添加`svg:`前缀。这告诉 Angular，您猜对了，它应该在创建这些元素时使用 SVG 命名空间：

```xml
<svg:rect x="125" y="125" width="10" height="10" stroke="blue" fill="none"></svg:rect>
```

下一个问题是一个两部分的问题。对于由简单 HTML 元素组成的组件，您可以像这样做，这与您在 AngularJS 中看到的类似。您可以按照以下方式将元素添加到页面中：

```xml
<angular-rect></angular-rect>
```

这将在 Web 检查器中的实时视图中呈现如下：

```xml
<angular-rect _ngcontent-c0="" _nghost-c1=""><rect _ngcontent-c1="" fill="none" height="10" stroke="blue" width="10" x="125" y="125"></rect>
</angular-rect>
```

从标记的角度来看，这看起来很好，但在浏览器中，蓝色矩形消失了。整个元素没有渲染，即使它在 DOM 中。

在 HTML5 中，这种做法可以工作，因为 HTML5 解析器已经被设计成对未知元素（以及格式不正确的标记）宽容，并且您可以使用 CSS 操作自定义元素。另一方面，SVG 仍然是严格的 XML 语法，因此除非元素在 SVG 规范中，或者您可以指向定义该特定元素的基于 XML 的**文档类型定义**（**DTD**），否则它不会正确渲染。幸运的是，有一个与 Angular 组件的功能完全兼容的 SVG 形状解决方案。您可以使用 Angular 绑定自定义组件到`g`元素的能力来创建几乎相同的效果。

以下代码示例显示了如何做到这一点。

首先，让我们看看`angular-rect`组件本身。需要注意的是，大部分文件都是样板文件，唯一需要注意的是`@Component`装饰器中的选择器被包裹在方括号`[]`中。由于它被包裹在方括号中，这告诉解析器它是一个属性选择器，而不是您在应用程序组件本身中看到的常见元素选择器。这意味着 Angular 将查找元素的属性中是否存在`angular-rect`，并将其替换为我们的新自定义组件：

```xml
import { Component, OnInit } from '@angular/core';

@Component({
  selector: '[angular-rect]',
  templateUrl: './angular-rect.component.html',
  styleUrls: ['./angular-rect.component.css']
})
export class AngularRectComponent implements OnInit {

  constructor() {}

  ngOnInit() {}

}
```

接下来，我们将看到如何在标记中使用。我们再次将`svg:`前缀添加到`g`元素，然后我们只需添加`angular-rect`属性，组件就会正确渲染：

```xml
  <svg  width="150" height="150" viewBox="0 0 150 150" version="1.1">
    <svg:circle
    [attr.fill]="color"
    [attr.cx]="cx"
    [attr.cy]="cy"
    [attr.r]="r" />
    <svg:g angular-rect></svg:g>
  </svg>
```

Angular 到此为止。

# 使用 React 和 SVG

我们要看的最后一个库是 React。React 是一个非常流行的库，它在 AngularJS 变得陈旧之际出现，而在 Angular 准备好投入使用之前出现。在某些圈子里非常受欢迎。它基于 ES6，并具有一些特定于 React 的扩展。

其中许多内容对你来说可能很熟悉，仅仅基于你在本章中迄今所看到的内容，特别是如果你做过任何严肃的 Web 应用程序开发。

开始使用 React 并不像使用 Angular 那样直接。Angular 在内部可能更复杂，但 Angular CLI 消除了许多问题，因此作为开发人员，你几乎不会（或很少）看到复杂性。React 更像是一个库而不是一个完整的框架，因此为了启动和运行，你可能需要做出更多的决定。幸运的是，虽然有许多方法可以实现这一点，但没有任何方法像 Angular CLI 对 Angular 那样对项目至关重要（它们在文档和社区中紧密耦合），但有一些方法可以像 Angular CLI 一样简单地实现。也许甚至更简单，因为根本不需要安装任何东西。

假设你的机器上安装了 Node 版本>6，你只需要运行一个命令就可以创建演示代码中使用的简单应用程序：

```xml
$ npx create-react-app react-svg 
```

`create-react-app`是 Facebook 的一个实用工具，可以启动一个完全功能的 React 应用程序。运行它看起来像以下两个屏幕截图（完整滚动将占据书的许多页面）。

这很酷。它创建文件夹，下载所有的依赖项并安装所有内容，然后给你一系列命令，以便与你新创建的 React 应用程序进行交互：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/a6f94d94-1a97-46a0-8436-e2e5318f92d0.png)

持续结果：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/1fe0854b-769e-4e42-9028-6600aa34dd1f.png)

更深入地看，它创建了一个看起来像以下屏幕截图的目录。它包含了`node_modules`文件夹和所有的依赖项，`public`是编译后文件的存放位置（当你浏览你的工作代码时，它们是从这里提供的），`src`是你的应用程序的所有源文件的存放位置。其他文件都是`git/npm/yarn-based project`的标准文件：

Yarn 是`npm`的替代品。我们不会详细介绍两者之间的区别，因为这超出了本书的范围，而且说实话，也不是很有趣。可以说，yarn 是`npm`的并行工具，因此你将使用 yarn 做与`npm`相同的事情。语法偶尔有所不同，在运行`yarn install`时会创建一个不同的文件（`yarn.lock`）。但就本书而言，你不需要关心这些区别。

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/b8d327e3-5bdf-48bf-9436-adf481b64ec3.png)

如前所述，应用程序代码在`src`中。你可以在以下屏幕截图中看到该文件夹的布局。

`App.css`、`App.js`和`App.test.js`是你的应用程序的核心所在。`index.js`文件是你的应用程序的主要入口点，它会引导你的 React 应用程序。`registerServiceWorker.js`是框架提供的一个文件，用于从本地缓存中提供资源。但是，在这个简单的应用程序中，你实际上不会碰它：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/3d1c8368-67d7-4232-a3a3-9a3ab354ee50.png)

从项目文件夹的根目录运行`yarn start`将编译所有的 React 代码和 CSS，并将启动一个可在 localhost:`3000`访问的开发服务器：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/39ac6a11-a210-4555-bddb-b0f7b913ad87.png)

启动应用程序如下，以防你想知道。我们将很快消除它：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/22df7d11-f3c3-4a30-b55a-1b1f8f0c707a.png)

在我们开始深入研究 SVG 和 React 之前，让我们看一下`create-react-app`生成的基本 React 组件。你之前已经看到它的渲染；现在让我们看看它是如何工作的。

React 组件的基本格式如下。它是一个 ES6 模块，带有`import`语句、一个类和一个导出。有一个特定于 React 的元素值得注意。

文件顶部显示了 ES6 导入。这可以包括 CSS 文件（我们马上就会看到）和 SVG 图像。Webpack 实际上会读取这些导入语句并优化这些导入，就像 Webpack 与 Angular 装饰器一样工作。

接下来是文件中的唯一一个类。`App`，它扩展自 React 的基本`Component`类。它有一个方法`render()`，它使用了一种称为 JSX 的 JavaScript 扩展。JSX 允许您将 XML 和 JavaScript 混合在一起。老实说，我从来不太喜欢这种格式，当他们发布它时我几乎感到震惊，但我已经开始欣赏它的意图，即使我不喜欢它。如果 JSX 属性被引用，则它们被解析为字符串。否则，它们被视为 JavaScript 表达式。在这种情况下，`logo.svg`的路径被转换为有用的路径，并在浏览器中呈现出 logo。

最后，我们导出默认类`App`，其他应用程序可以导入它：

```xml
import React, { Component } from 'react';
import logo from './logo.svg';
import './App.css';

class App extends Component {
  render() {
    return (
      <div className="App">
        <header className="App-header">
          <img src={logo} className="App-logo" alt="logo" />
          <h1 className="App-title">Welcome to React</h1>
        </header>
        <p className="App-intro">
          To get started, edit <code>src/App.js</code> and save to 
            reload.
        </p>
      </div>
    );
  }
}

export default App;
```

快速浏览一下`index.js`，因为我们实际上没有做太多事情，这将展示应用程序如何加载。

文件顶部有几个 ES6 模块导入。React 和 ReactDOM 是核心，驱动基本的 React 库并添加 ReactDOM 接口。它们主要驱动我们在这个小演示中要做的大部分工作。

导入还包括`index.css`文件。

除此之外，我们还导入了两个 JavaScript 模块：`App`，这是我们要进行工作的模块，以及之前提到的`registerServiceWorker`，我们将完全不使用它。

一旦所有内容都被导入，我们运行两个小函数。`ReactDOM.render`被调用时带有两个参数，`<App />`表示由 App 组件创建的自定义元素，`document.getElementById("root")`表示应接收新元素的节点：

```xml
import React from 'react';
import ReactDOM from 'react-dom';
import './index.css';
import App from './App';
import registerServiceWorker from './registerServiceWorker';

ReactDOM.render(<App />, document.getElementById('root'));
registerServiceWorker();
```

现在我们已经快速浏览了基本的 React 架构，让我们来看看我们的演示。

除了基本的 React 应用程序之外，Bootstrap 也通过运行以下命令安装到该项目中。我们将继续使用相同的标记来做另一个简单的表单/SVG 演示，这是有道理的：

```xml
npm install --save bootstrap
```

让我们看看我们的`App.js`。它以几个导入语句开始。我们从 React 中导入`React`和`component`。然后我们导入两个 CSS 文件，我们自己的自定义`App.css`和刚刚安装的`Bootstrap CSS`，链接到项目的`node_modules`中的文件。最后，我们从`rect`模块导入我们独立的`ReactRect`组件。

然后是`App`类的定义。它实际上只有几件事情。在构造函数中，我们创建一个基本的`state`对象，其中包含我们标准 SVG 属性`cx`、`cy`、`r`和`color`的默认值。然后我们设置一个方法`handleChange`来处理对底层模型的更改。

这个方法很简单。它接收`event`对象，创建一个`target`常量，然后进一步检查该对象以获取输入的`name`和`value`。然后它使用`setState`方法（从`props`继承）来设置应用程序状态的值。

接下来是`render`函数。

浏览一下，您会注意到您不需要做太多工作就可以让 React 正确地呈现 SVG。

首先，我们使用 ES6 解构赋值模式为各种属性设置本地变量。一旦这些变量设置好了，只需将需要由 React 解释的变量添加到适当属性的大括号`{}`中。SVG 元素和表单输入中的变量引用以相同的方式处理，不需要任何特殊处理。

我们只需将`handleChange`方法直接绑定到标记中的`onChange`事件，一切都会如预期般运行。

我们导入的`ReactRect`被添加到 SVG 元素中。React 负责导入该组件，我们很快就会看到它，并将其呈现到文档中。

自定义组件需要以大写字母开头。以小写字母开头的标记被解释为 HTML 元素。

```xml
import React, { Component } . from 'react';
import './App.css';
import 'bootstrap/dist/css/bootstrap.css';
import ReactRect from './rect';

class App extends Component {
  constructor(props) {
    super(props);
    this.state = {
      cx: 75,
      cy: 75,
      r: 50,
      color: "#cc0000"
    };
    this.handleChange = this.handleChange.bind(this);
  }
  handleChange(event) {
    const target = event.target;
    const value = target.value;
    const name = target.name;
    this.setState({
      [name]: value
    });
  }
  render() {
    const { cx,cy,r,color } = this.state;
    return (
      <div className="container">
      <svg  width="150" height="150" 
        viewBox="0 0 150 150" version="1.1">
        <circle
        r={r}
        cy={cy}
        cx={cx}
        fill={color}
        ></circle>
        <ReactRect></ReactRect>
      </svg>
      <div className="row">
        <div className="col-4">
          <label>Background color:</label>
        </div>
        <div className="col-8">
          <input type="color" id="circle-color" value={color}
          name="color"
          onChange={this.handleChange} />
        </div>
      </div>
      <div className="row">
        <div className="col-2">
          <label>cx:</label>
        </div>
        <div className="col-4">
          <input type="number" id="circle-cx" className="form-control" 
            value={cx}
          name="cx"
          onChange={this.handleChange} />
        </div>
        <div className="col-2">
          <label>cy:</label>
        </div>
        <div className="col-4">
          <input type="number" id="circle-cy" className="form-control" 
            value={cy}
          name="cy"
          onChange={this.handleChange} />
        </div>
      </div>
      <div className="row">
        <div className="col-2">
          <label>radius:</label>
        </div>
        <div className="col-4">
          <input type="number" id="circle-radius" className="form-
            control" value={r}
          name="r"
          onChange={this.handleChange} />
        </div>
      </div>
    </div>
    );
  }
}

export default App;
```

我们的自定义元素非常简单。它只是一个简单的 React 组件，返回我们的`rect`元素：

```xml
import React, { Component } from 'react';

class ReactRect extends Component {
  render() {
    return (
      <rect x="125" y="125" width="10" height="10" stroke="blue" 
        fill="none"></rect>

    );
  }
}

export default ReactRect;
```

正如您所看到的，使用动态 SVG 和 React 非常简单。React 团队努力确保 SVG 元素和属性都能正常工作，因此这归功于他们的辛勤工作。谢谢，React 团队！

# 总结

在本章中，您将使用四个常见的库和框架，将这些强大的工具与 SVG 集成在一起。

从 jQuery 开始，通过 AngularJS、Angular 和 React，您现在具有将 SVG 与地球上四个最受欢迎的库和框架之一集成的基本经验。

具体来说，您学习了如何使用每个框架设置应用程序，如何创建具有 SVG 元素和属性的动态组件，以及如何以动态方式操纵这些属性。

您还了解了在使用 SVG 和这些库时的多个注意事项，包括确保元素在 jQuery 中正确创建以及确保在 Angular 框架中正确处理动态属性的方法。


# 第八章：SVG 动画和可视化

这一章讨论了 SVG 的最具动态和令人印象深刻的用例：使用 SVG 进行数据可视化和动画。您已经了解的工具，SVG、JavaScript 和 CSS，以及一些新工具，将汇集在一起，为您构建动态站点和应用程序提供强大的选择。

在这一章中，我们将学到以下内容：

+   如何使用 SVG、JavaScript 和结构化数据生成静态数据可视化

+   动画 SVG 的一般技术概述

+   使用 Vivus 对 SVG 进行动画处理

+   使用 GSAP 进行动画

在完成本章中的示例后，您将能够使用 SVG 创建动画和数据可视化，并了解使用 SVG 和动画的两种最佳工具。

让我们开始吧。

# 创建 SVG 数据可视化

这一部分将专注于使用 SVG 和 JavaScript 组合基本数据可视化。这个特定的可视化将关注一个插图，即相对于平均值的正/负差异。在这种情况下，它将说明棒球选手大卫·奥尔蒂兹在波士顿红袜队生涯中每个赛季击出的本垒打数量与他在红袜队生涯中的平均本垒打数量的比较。

从 2003 年到 2016 年，大卫·奥尔蒂兹在为红袜队效力期间，每个赛季最少击出 23 个本垒打，最多击出 54 个。他的平均每个赛季 34.5 个。这个可视化将展示他每年本垒打总数相对于 34.5 平均值的正/负差异。他击出比平均值多的年份将以绿色显示。击出比平均值少的年份将以红色显示。

我们需要经历的步骤如下：

1.  我们将获取数据并计算总年数、总本垒打数量，然后计算平均值。

1.  我们将循环遍历数据，并计算每年的正/负偏移量。

1.  我们将根据可用的屏幕空间计算一些指标。

1.  我们将在屏幕上垂直居中绘制一个基准线。

1.  我们将在适当的位置绘制一系列矩形，其高度适当以指示正/负的差异，以及一些简单的标签指示年份和本垒打的数量。

1.  我们将添加一个图例，指示本垒打的平均数量和年数。

最终的可视化将如下所示：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/eb90380e-2dd8-4c7d-92a3-facb795e4e45.png)

现在我们已经计划好了基础知识，让我们详细看看这是如何工作的。

我们将从标记开始，这非常简单。我们首先包括 Bootstrap 和 Raleway 字体作为我们标准模板的一部分。然后，我们设置 SVG 元素的背景，并设置两种不同类型文本元素的字体系列、大小和颜色。然后我们只需包括目标 SVG 元素和运行可视化的 JavaScript 文件：

```xml
<!doctype html>
<html lang="en">

<head>
  <meta charset="utf-8">
  <title>Mastering SVG- SVG Data Visualization</title>
  <link rel="stylesheet" 
   href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.
    min.css" integrity="sha384-
    Gn5384xqQ1aoWXA+058RXPxPg6fy4IWvTNh0E263XmFcJlSAwiGgFAW/dAiS6JXm"
    crossorigin="anonymous">
  <link href="https://fonts.googleapis.com/css?family=Raleway" 
    rel="stylesheet">
  <style type="text/css">
    body {
      font-family: Raleway, sans-serif;
    }
    svg.canvas {
     background: #0C2340;
    }
    text {
      font-family: Raleway, sans-serif;
      font-size: .75em;
      fill: #fff;
    }
    text.large {
      font-size: 1.5em;
    }
  </style>
</head>

<body>

  <div class="container-fluid">
    <div class="row">
      <div class="col-12">
        <svg  viewBox="0 0 1000 450" 
          width="1000" height="450" version="1.1" id="canvas" 
            class="canvas">
        </svg>
      </div>
    </div>
  </div>
  <script src="img/scripts.js"></script>
</body>

</html>
```

包含的 JavaScript 文件是真正的工作所在。

这个 JavaScript 文件使用了几个 ES6 特性。

`scripts.js`本身基本上是一个大函数，`viz`。

在`viz`的顶部，我们有`data`变量。这个变量是一个 JavaScript 对象数组。每个对象都有两个属性，`year`和`hrs`，表示相关年份和奥尔蒂兹在那一年击出的本垒打数量：

```xml
function viz() {
  /*
    ES6
  */
  const data = [
    {
      "year": 2003,
      "hrs": 31
    },
    {
      "year": 2004,
      "hrs": 41
    },
    {
      "year": 2005,
      "hrs": 47
    },
    {
      "year": 2006,
      "hrs": 54
    },
    {
      "year": 2007,
      "hrs": 35
    },
    {
      "year": 2008,
      "hrs": 23
    },
    {
      "year": 2009,
      "hrs": 28
    },
    {
      "year": 2010,
      "hrs": 32
    },
    {
      "year": 2011,
      "hrs": 29
    },
    {
      "year": 2012,
      "hrs": 23
    },
    {
      "year": 2013,
      "hrs": 30
    },
    {
      "year": 2014,
      "hrs": 35
    },
    {
      "year": 2015,
      "hrs": 37
    },
    {
      "year": 2016,
      "hrs": 38
    }
  ];
```

如果您正在交互式地运行此可视化，要么接受用户的输入，要么将 Web 服务调用的结果插入到可视化中，您只需要具有正确的结构（对象数组）和格式（`hrs`和`year`），其他一切都会自动完成。在查看填充文件的其余变量和方法时，请记住这一点。

从`data`开始，我们设置了几个不同的变量，我们将在可视化过程中使用，除了`data`之外：

+   `doc`：对文档的引用

+   `canvas`：引用具有`id`为`#canvas`的 SVG 元素

+   `NS`：从`SVG`元素派生的命名空间的引用

+   `elem`：我们将创建的元素的占位符变量

```xml
  const doc = document;
  const canvas = doc.getElementById("canvas");
  const NS = canvas.getAttribute('xmlns');
  let elem;
```

接下来是我们用来填充可视化值和元素的几个实用方法。

第一个函数`addText`让我们可以向可视化添加文本标签。它接受一个坐标对象`coords`，要输入的`text`，最后是一个可选的 CSS 类`cssClass`。我们将在一个示例中探讨 CSS 类参数的用例。前两个参数应该很简单，是必需的。

在`addText`之后，有一个`addLine`函数，它允许我们在屏幕上绘制线条。它接受一个坐标对象`coords`（在这种情况下包含四个坐标）和一个可选的`stroke`颜色。您会注意到`stroke`在函数签名中创建了一个默认值。如果没有提供描边颜色，`stroke`将是`#ff8000`。

接下来是`addRect`函数，它允许我们向屏幕添加矩形。它接受一个坐标对象`coords`，其中包含`height`和`width`属性，以及可选的`stroke`和`fill`颜色。

最后，有一个函数`maxDiffer`，它计算出一组正负数之间的最大差值。获取这个范围，然后使用这个最大差确保无论数字如何分布，基线上方或下方所需的最大高度都能适应屏幕：

```xml
  function addText(coords, text, cssClass) {
    elem = doc.createElementNS(NS, "text");
    elem.setAttribute("x", coords.x);
    elem.setAttribute("y", coords.y);
    elem.textContent = text;
    if (cssClass){
      elem.classList.add(cssClass);
    }
    canvas.appendChild(elem);
  }
  function addLine(coords, stroke = "#ff8000") {
    elem = doc.createElementNS(NS, "line");
    elem.setAttribute("x1", coords.x1);
    elem.setAttribute("y1", coords.y1);
    elem.setAttribute("x2", coords.x2);
    elem.setAttribute("y2", coords.y2);
    elem.setAttribute("stroke", stroke);
    canvas.appendChild(elem);
  }
  function addRect(coords, fill = "#ff8000", stroke = "#ffffff") {
    elem = doc.createElementNS(NS, "rect");
    elem.setAttribute("x", coords.x);
    elem.setAttribute("y", coords.y);
    elem.setAttribute("width", coords.width);
    elem.setAttribute("height", coords.height);
    elem.setAttribute("fill", fill);
    elem.setAttribute("stroke", stroke);
    canvas.appendChild(elem);
  }
  function maxDiffer(arr) {
    let maxDiff = arr[1] - arr[0];
    for (let i = 0; i < arr.length; i++) {
      for (let j = i + 1; j < arr.length; j++) {
        if (arr[j] - arr[i] > maxDiff) {
          maxDiff = arr[j] - arr[i];
        }
      }
    }
    return maxDiff;
  }

```

在这些实用函数之后，我们有定义可视化核心的代码。它发生在一个在`DOMContentLoaded`事件上运行的函数中。

当函数运行时，我们创建多个变量，保存我们需要生成可视化的不同属性。以下是它们的作用：

+   `viewBox`是 SVG 元素`viewBox`的本地引用。我们将这个和后续的 DOM 引用存储在本地，这样我们就可以节省`viewBox`的 DOM 查找次数。

+   `width`是对 SVG 元素`viewBox`中宽度的本地引用。

+   `height`是对`viewBox`中`height`的本地引用。

+   `x`是对`viewBox`中`x`点的本地引用。

+   `y`是对`viewBox`中`y`点的本地引用。

+   `padding`是一个任意的常数，用于创建几个填充计算。

+   `vizWidth`定义了 SVG 画布的可见宽度。这定义了我们可以安全地将元素绘制到 SVG 元素中的区域。

+   `years`是数据集中的年数的引用。

+   `total`是一个计算出的值，代表整个数据集中击出的全垒打总数。

+   `avg`是每年击出的全垒打的平均数，通过将`total`除以`years`得出。

+   `verticalMidPoint`表示 SVG 元素的垂直中点。这是正负差异绘制的基准线。

+   `diffs`是一个数组，保存了每年击出的全垒打平均数和实际击出的全垒打数之间的正负差异。

+   `maxDiff`是每年击出的全垒打的平均数和实际击出的全垒打数之间的最大差异。

+   `yInterval`是每个全垒打的像素数。这确保了方框在垂直方向上根据每年击出的全垒打数正确地进行缩放。

+   `xInterval`是每年的像素数。这个值允许我们均匀地在 SVG 元素中放置方框，无论数据集中有多少年：

```xml
  document.addEventListener("DOMContentLoaded", () => {
    const viewBox = canvas.viewBox.baseVal;
    const width = viewBox.width;
    const height = viewBox.height;
    const x = viewBox.x;
    const y = viewBox.y;
    const padding = width / 200;
    const vizWidth = width - padding;
    const years = data.length;
    const total = data.reduce((total, item) => {
      return total + item.hrs;
    }, 0);
    const avg = total / years;
    const verticalMidPoint = (y + height) / 2;
    const diffs = data.map((item) => {
      return item.hrs - avg;
    });
    const maxDiff = maxDiffer(diffs);
    const yIntervals = verticalMidPoint / maxDiff;
    const xInterval = (vizWidth / years);
```

在创建所有这些变量之后，我们开始绘制不同的框并添加标签。为此，我们使用`for...in`循环来循环遍历`diffs`数组，进行两个计算以创建两个新变量`newX`和`newY`。`newX`是基于`i`的值乘以我们之前创建的`intervalX`变量的常规间隔。`newY`变量是通过将`diffs[i]`的值（当前差异）乘以`yInterval`常量来计算的。这为我们提供了一个距离，用于计算矩形的高度，以表示每年的本垒打数量。

接下来，我们测试当前`diff`是否大于或小于零。如果大于零，我们希望绘制一个从`verticalMidPoint`向上的框。如果当前`diff`小于零，则我们绘制一个从`verticalMidPoint`向下的框。由于矩形的方向和相关的锚点在每种情况下都不同，我们需要以不同的方式处理它们。我们还将使用不同的颜色来突出显示这两种变化，以便进行次要指示。

虽然这个`if`的两个分支之间存在差异，但两个分支都调用了`addRect`和`addText`。让我们看看`if`的两个分支之间的相似之处和差异之处。

首先，每次调用`addRect`都遵循相同的模式，对于`x`和`width`属性。`x`始终是`newX`值加上`padding`，而`width`是`xInterval`值加上`padding`。

`y`和`height`值由两个分支处理。

如果当前差异小于零，则新的`y`坐标为`verticalMidpoint`。这将使框的顶部锚定在可视化中表示零的线上，并指示框将悬挂在该线下方。如果当前差异大于零，则`y`坐标设置为`verticalMidPoint`减去`newY`。这将使新矩形的顶部值为`newY`在表示零的线上方。

如果当前差异小于零，则`height`是传入`Math.abs()`的`newY`值。无法向 SVG 元素传递负值，因此需要使用`Math.abs()`将负值转换为正值。如果当前差异大于零，则`height`就是`newY`值，因为它已经是正数。

在`if`的每个分支中调用`addText`的位置不同。如果`newY`值为负数，则再次使用`Math.abs`将`newY`值转换为正数。否则，保持不变。

随后，我们使用`addLine`调用将零线添加到垂直中点。传入的参数是`viewBox`的未更改的`x`和`width`，左右两个点的`verticalMidpint`作为`y`值。

最后，我们添加了一些解释可视化基础知识的文本。在这里，我们使用了`cssClass`参数可选项来调用`addLine`，传入`large`，以便我们可以制作稍大一些的文本。`x`和`y`参数利用了`x`和`height`变量以及`padding`变量，将文本放置在 SVG 元素的左下角略微偏移。

最后一行代码只是调用`viz()`函数来启动可视化。

```xml
for (const i in diffs) {
      const newX = xInterval * i;
      const newY = diffs[i] * yInterval;
      if (diffs[i] < 0) {
        addRect({
          "x": newX + padding,
          "y": verticalMidPoint,
          "width": xInterval - padding,
          "height": Math.abs(newY),
        }, "#C8102E", "#ffffff");
        addText({
          "x": newX + padding,
          "y": verticalMidPoint + Math.abs(newY) + (padding * 3)
        }, `${data[i].hrs} in ${data[i].year}`);
      }
      else if (diffs[i] > 0) {
        addRect({
          "x": newX + padding,
          "y": verticalMidPoint - newY,
          "width": xInterval - padding,
          "height": newY,
        }, "#4A777A", "#ffffff");
        addText({
          "x": newX + padding,
          "y": verticalMidPoint - newY - (padding * 2)
        }, `${data[i].hrs} in ${data[i].year}`);
      }
      addLine({
        x1: x,
        y1: verticalMidPoint,
        x2: width,
        y2: verticalMidPoint
      }, "#ffffff");
      addText({
        "x": x + padding,
        "y": height - (padding * 3)
      }, `Based on an average of ${avg} home runs over ${years} years`,
            "large");
    }
  });

}
viz();
```

如果这是一个用于生产或更通用用途的可视化，那么我们仍然需要对其进行一些处理。敏锐的读者会发现，我们实际上并没有处理本垒打数量恰好等于平均本垒打数量的情况，例如。也就是说，对于本书的目的，这里的细节足以说明如何使用 JavaScript、SVG 和数据来以可视化的方式讲述数据集的故事。

现在我们已经看过静态可视化了，让我们来看一下如何在屏幕上添加一些动作。下一节将介绍在浏览器中可以对 SVG 进行动画的多种方式。

# 动画 SVG 的一般技术

本节将介绍各种用于动画 SVG 的一般技术。虽然有不同的工具可用于完成这项工作（您将在本章后面遇到两种），但了解在没有框架或库的帮助下如何完成这些工作是很有用的。本节将提供这方面的基础知识。

您之前已经看到了一些这些技术，但是在动画的上下文中再次查看它们是很好的。

# 使用纯 JavaScript 进行动画

在 CSS 关键帧动画和 CSS 过渡出现之前，我们不得不手动使用 JavaScript 在浏览器中制作所有动画和有趣的效果；在循环中更新属性并手动优化帧速率。最终，诸如 jQuery 之类的库出现并消除了对了解这些工作原理的需求，通过将动画作为其 API 的一部分呈现出来。幸运的是，如今，除了您选择的工具中可用的动画方法之外，您还可以利用 CSS 动画来完成许多以前需要使用 JavaScript 的事情，因此现在越来越少需要人们学习这些技能。

也就是说，有些地方 CSS 动画无法胜任，因此了解它在幕后如何工作并且不依赖库是有好处的。

这个简单的动画将会将一个圆形元素从左到右地在 SVG 元素上移动。我们需要计算几个指标来创建动画，所以即使它很简单，它也会说明你在编写这种代码时可能遇到的许多挑战。

让我们来看一下代码。

`head`中没有任何有趣的内容，所以让我们直接跳到页面的`body`。`body`中有我们在整本书中一直使用的标准 Bootstrap 标记。在主`div`内部，我们有一个包含单个`circle`元素的`SVG`元素，位于`75, 225`，半径为`50`像素。它的`id`是`circle`：

```xml
  <div class="container-fluid">
    <div class="row">
      <div class="col-12">
        <svg  viewBox="0 0 1000 450" 
          width="1000" height="450" version="1.1" id="canvas" 
           class="canvas">
          <circle cx="75" cy="225" r="50" fill="blue" id="circle">
        </circle>
        </svg>
      </div>
    </div>
  </div>
```

JavaScript 很简单。

它包括一个添加到`DOMContentLoaded`事件的函数。该函数执行一些熟悉的操作。它创建了对`doc`、`canvas`和`circle`的本地引用，以便我们可以在整个动画过程中轻松地引用这些元素。接下来创建了几个变量来存储`viewBox`的属性：`viewBox`本身，`height`，`width`和`x`。然后设置了两个常量，表示动画运行的秒数和我们动画的**每秒帧数**（**fps**）。

接下来，我们将当前圆形元素的`x`值作为变量`currX`。然后计算结束点`newX`，通过使用圆的半径乘以 3 来计算。这给我们一个舒适的结束点，视觉上。

接下来，我们创建一些变量来运行动画。首先，`diffX`是当前`x`值和目标`newX`值之间的差值的计算。然后我们将`diffX`除以秒数，再乘以每秒帧数。这将创建三秒的间隔来进行动画。

最后，我们创建了动画变量`animX`，这是我们在每一帧中将要处理的变量，因为我们要将元素动画移动到屏幕上。

接下来，有一个函数会在每一帧调整元素在屏幕上的位置。它有三个作用。它将间隔添加到`animX`上，以通过计算的间隔移动元素。然后设置元素的`cx`属性，将其移动到新位置。最后，使用`window.requestAnimationFrame`递归调用自身。

`requestAnimationFrame`是一种允许浏览器优化 JavaScript 动画绘制到屏幕上的方法。它通常优化到每秒`60`帧，但从技术上讲，它将匹配设备的显示刷新率。

所有这些都发生在一个`if`块内，当动画完成时停止动画。如果`animX`小于`newX`，则执行代码，再次调用`animate`来启动下一帧。如果`animX`大于或等于`newX`，则动画停止：

```xml
document.addEventListener("DOMContentLoaded", () => {

 const doc = document;
 const canvas = doc.getElementById("canvas");
 const circle = doc.getElementById('circle');
 const viewBox = canvas.viewBox.baseVal;
 const width = viewBox.width;
 const height = viewBox.height;
 const x = viewBox.x;
 const padding = width / 200;
 const seconds = 3;
 const fps = 60;
 let currX = circle.cx.baseVal.value;
 let newX = width - (circle.r.baseVal.value * 3);
 let diffX = newX - currX;
 let intervalX = diffX / (fps * seconds);
 let animX = currX;
 function animate() {
    if (animX < newX) {
        animX = animX + intervalX;
        circle.setAttribute("cx", animX);
        window.requestAnimationFrame(animate);
     }
 }
 animate();
 });
```

这不是最复杂的动画，但使用`window.requestAnimationFrame`意味着在浏览器中看起来相当不错。

虽然有其他选项可以对 SVG 进行动画，你应该了解它们并在适当的地方使用它们，但 JavaScript 将是最强大且最灵活的选择。如果你的动画需要在尽可能多的浏览器中运行，那么你需要使用 JavaScript。

好消息是，正如你将在本章后面看到的，有很好的工具可以简化使用 JavaScript 进行动画。

在我们看几个用于处理 SVG 的 JavaScript 库之前，让我们看一下使用核心 Web 技术对 SVG 进行动画的另外两个选项：CSS 和 SMIL。

# 使用 CSS 进行动画

使用 CSS 对 SVG 进行动画是直接的，它的工作方式与 CSS 动画和过渡与常规 HTML 元素的工作方式相同。你定义一些 CSS 属性，根据你是否使用关键帧动画或过渡，你创建特定的 CSS 规则来处理它们在一段时间内的渲染。这个过程的问题在于，只有演示属性，它们驱动了 SVG 的许多内容，也可以作为 CSS 属性使用，才能用 CSS 进行操作。正如你在下面的网站上看到的，根据 SVG 1.1 的定义，缺少许多重要的属性：[`www.w3.org/TR/SVG/propidx.html`](https://www.w3.org/TR/SVG/propidx.html)。SVG 2.0 添加了更多属性，但对这些新属性的支持并不是普遍的，不幸的是，没有一个适当的手册来说明哪些属性在哪里得到支持。

换句话说，根据你的浏览器支持矩阵的情况，使用这些技术可能会有一些潜在的问题。

无论如何，即使有这样一个有些粗糙的故事，看到这些技术的实际应用仍然是值得的。

这里有三个例子。两个显示了类似于之前的 JavaScript 动画的动画；它们将一个蓝色圆圈移动到屏幕上。它们以两种不同的方式实现。这说明了根据你的目标浏览器的不同，你可能会看到实现上的差异。第一个例子使用 CSS 变换和 CSS 动画来将元素沿屏幕移动。这种技术具有更广泛的浏览器支持。第二个例子使用更简单的方法，在 SVG 元素悬停时设置`cx`属性的过渡，然后更改值。在 Chrome 中，`cx`作为 CSS 属性可用，因此在该浏览器中，这是更简单的方法。

第三个例子展示了元素上`fill`的过渡，以说明在这种情况下将计算留给浏览器和 CSS 是非常有益的一个例子。如果不清楚如何从一个颜色值动画到另一个颜色值，那么你可能至少能看到一个将繁重的工作留给浏览器的绝佳用例。

让我们按顺序看一下这些例子。

第一个例子很简单。在这个例子中，我们有与之前的 JavaScript 例子相同的标记，只有一个例外：通过 CSS 设置`cx`属性。我们在文档的`head`中的`#circle`选择器中这样做。

此外，我们在该选择器上设置了一个`transition`属性，监视`cx`属性的变化，并在其变化时进行三秒的过渡。在下一个选择器`svg:hover #circle`中，我们通过父 SVG 元素上的悬停事件触发动画，将`cx`值设置为最终目的地`875`像素。

有了这个 CSS，当你在 SVG 元素上悬停鼠标时，新的`cx`被设置，浏览器将在 SVG 元素的*X*轴上在`75`和`875`像素之间进行动画处理：

```xml
<!doctype html>
<html lang="en">

<head>
  <meta charset="utf-8">
  <title>Mastering SVG- SVG Animation with CSS</title>
  <link rel="stylesheet" 
  href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.m
    in.css" integrity="sha384-
    Gn5384xqQ1aoWXA+058RXPxPg6fy4IWvTNh0E263XmFcJlSAwiGgFAW/dAiS6JXm"
    crossorigin="anonymous">
  <style type="text/css">
    #circle {
      transition: cx 3s;
      cx: 75px;
    }
    svg:hover #circle {
      cx: 875px;
    }
  </style>

</head>

<body>

  <div class="container-fluid">
    <div class="row">
      <div class="col-12">
        <svg  viewBox="0 0 1000 450"
         width="1000" height="450" version="1.1" id="canvas" 
          class="canvas">
          <circle cy="225" r="50" fill="blue" id="circle"></circle>
        </svg>
      </div>
    </div>
  </div>

</body>

</html>
```

下一个例子设置类似。它与前一个例子具有完全相同的 SVG 标记，并由 JavaScript 进行动画处理。区别再次在于 CSS。

有两个感兴趣的部分。第一部分定义了一个名为`animate-circle`的两关键帧动画。第一个关键帧，在`0%`处，使用`transform: translateX`在*X*轴上进行`0px`的平移。第二个关键帧，在`100%`处，将该变换增加到`800px`。

然后，在`#circle`选择器中，我们使用命名动画定义`animation`属性，持续时间为三秒，线性缓动。然后我们将`animation-fill-mode`设置为 forwards，表示动画应该向前运行一次并完成，保持动画元素处于最终状态。

当这个运行时，圆圈会平滑地在屏幕上进行动画处理：

```xml
<!doctype html>
<html lang="en">

<head>
  <meta charset="utf-8">
  <title>Mastering SVG- SVG CSS Animation</title>
  <link rel="stylesheet" 
   href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.
    min.css" integrity="sha384-
    Gn5384xqQ1aoWXA+058RXPxPg6fy4IWvTNh0E263XmFcJlSAwiGgFAW/dAiS6JXm"
    crossorigin="anonymous">
  <style type="text/css">
    @keyframes animate-circle {
      0% {
        transform: translateX(0)
      }
      100% {
        transform: translateX(800px)
      }
    }

    #circle {
      animation: animate-circle 3s linear;
      animation-fill-mode: forwards;
    }
  </style>

</head>

<body>

  <div class="container-fluid">
    <div class="row">
      <div class="col-12">
        <svg  viewBox="0 0 1000 450" 
         width="1000" height="450" version="1.1" id="canvas" 
          class="canvas">
          <circle cx="75" cy="225" r="50" fill="blue" id="circle">
        </circle>
        </svg>
      </div>
    </div>
  </div>

</body>

</html>
```

最后一个例子也使用了过渡，这次是将`fill`属性从蓝色动画到红色。这个属性是早期在 CSS 中定义为可用的演示属性之一，因此在当前时间，它在浏览器中的支持要比`cx`等属性好得多。

CSS 定义非常简单。在`#circle`定义上设置了一个`fill`属性，以及一个`transition`，用于监视`fill`的变化，并在 2 秒内进行过渡。

在`#circle:hover`中，我们将`fill`更改为蓝色。在浏览器中运行并悬停在圆圈上，将会使圆圈元素的颜色进行动画处理，而无需使用任何 JavaScript，并且无需弄清楚如何从一个命名颜色动画到另一个。

```xml
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Mastering SVG- SVG Data Visualization</title>
  <link rel="stylesheet" 
  href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.m
  in.css" integrity="sha384-
  Gn5384xqQ1aoWXA+058RXPxPg6fy4IWvTNh0E263XmFcJlSAwiGgFAW/dAiS6JXm"
    crossorigin="anonymous">
  <style type="text/css">
    #circle {
      fill: red;
      transition: fill 3s;
    }
    #circle:hover {
      fill: blue;
    }
  </style>
</head>
<body>
  <div class="container-fluid">
    <div class="row">
      <div class="col-12">
        <svg  viewBox="0 0 450 450"
         width="450" height="450" version="1.1" id="canvas" 
            class="canvas">
          <circle cx="225" cy="225" r="225" fill="blue" id="circle">
        </circle>
        </svg>
      </div>
    </div>
  </div>
</body>
</html>
```

所有这些例子都是故意基本的，正如前面提到的，它们的浏览器支持很弱（例如，在 IE 旧版本中都不起作用）；但它们仍然很强大。如果你的浏览器支持矩阵偏向于最新和最好的浏览器，那么你可以在 CSS 和 SVG 中玩得很开心。

# 使用 SMIL 对 SVG 进行动画处理

SVG 动画的另一个有趣且强大的选项与 CSS 具有类似令人沮丧的支持矩阵。SMIL 在 Microsoft 浏览器中根本不受支持，甚至曾一度被 Chrome 弃用。

这是一件遗憾的事，因为 SMIL 有一些很好的特点。它是一种清晰的、声明式的动画元素的方式。它不像 JavaScript 那样强大，也不像 CSS 那样常用作通用技术，但它仍然相当不错。

看一个例子。

在其中，我们有我们现在熟悉的标记：一个简单的`circle`在一个空的 SVG 元素上。这次有一个小小的变化。`animate`元素作为`circle`元素的子元素。`animate`元素是动画定义的地方。它有几个属性，我们需要看一下：

+   `xlink:href`属性指向将要进行动画处理的`#circle`元素。`animate`元素是`circle`元素的子元素，这样就自动将动画与其关联起来。使用`xlink:href`属性可以确保连接被准确定义。

+   `attributeName`定义将要进行动画处理的属性。在这种情况下，它是`cx`属性。

+   `from`和`to`属性表示动画的起点和终点。在这种情况下，我们将从`"75"`移动到`"900"`。

+   `dur`指示动画的持续时间。在这种情况下，它被定义为`"3s"`，持续三秒。

+   `begin`属性指示动画应该何时开始。这让你可以根据需要延迟动画。在我们的例子中，我们立即开始动画，设置为`"0s"`。

+   `fill`属性，与常见的`fill`属性同名，表示动画值在动画结束后是否保留在元素上。这个值`"freeze"`表示元素应该在动画结束时保持在达到的状态上。

在 SVG 的上下文中，似乎没有很好的理由将`fill`重载为执行两个基本不相关的任务。这很不幸。

在浏览器中运行这个动画会创建一个类似于本章中几个实例中看到的动画；球从左边开始，在三秒内移动到右边。

```xml
<!doctype html>
<html lang="en">

<head>
 <meta charset="utf-8">
 <title>Mastering SVG- SVG Animation with SMIL</title>
 <link rel="stylesheet" 
  href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.m
    in.css" integrity="sha384-
    Gn5384xqQ1aoWXA+058RXPxPg6fy4IWvTNh0E263XmFcJlSAwiGgFAW/dAiS6JXm"
    crossorigin="anonymous">
</head>

<body>

 <div class="container-fluid">
 <div class="row">
 <div class="col-12">
 <svg  viewBox="0 0 1000 450" 
    width="1000" height="450" version="1.1" id="canvas" class="canvas">
    <circle cx="75" cy="225" r="50" fill="blue" id="circle">
 <animate 
 xlink:href="#circle"
 attributeName="cx"
 from="75"
 to="900" 
 dur="3s"
 begin="0s"
 fill="freeze" />
 </circle>
 </svg>
 </div>
 </div>
 </div>
</body>

</html>
```

现在我们已经看了 SVG 中数据可视化和动画的手动方法，让我们来看一些可以帮助动画元素的工具。

# 使用 Vivus 对 SVG 进行动画

Vivus 是一个只做一件事情并且做得非常好的库([`maxwellito.github.io/vivus/`](https://maxwellito.github.io/vivus/))。Vivus 允许您在一段时间内“绘制”SVG 元素的描边。

以下一系列截图展示了它的效果。这是一个很好的效果。

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/ed8a7cc6-8324-4d72-b7ea-194f55650f43.png)

需要注意的是，本章中的三个示例都使用了相同的插图。书中打印的代码示例截断了每个路径元素的`d`属性，以缩短代码示例的长度。如果您想看完整的示例，请参考 GitHub 上的代码([`github.com/roblarsen/mastering-svg-code`](https://github.com/roblarsen/mastering-svg-code)[)。 ](https://github.com/roblarsen/mastering-svg-code)

只要`stroke`设置了一个值并且`fill`设置为`none`，只需包含 Vivus JavaScript 文件（在这种情况下，我们通过在 Vivus 文件夹中运行`npm install`，然后链接到`node_modules`文件夹中的 JavaScript 文件来实现），然后创建一个新的 Vivus 实例就可以了。

创建一个新的 Vivus 实例非常容易。使用`new`关键字，您可以用两个参数实例化一个新的 Vivus 对象。第一个是 SVG 元素的`id`。第二个是配置对象。在这种情况下，我们只传入一个选项，即`duration`参数，将动画的持续时间设置为三秒（3,000 毫秒）。

以下代码示例展示了使用 Vivus 有多么容易：

```xml
<!doctype html>
<html lang="en">

<head>
  <meta charset="utf-8">
  <title>Mastering SVG- SVG Animation with Vivus</title>
  <style>
  .stroke{
    stroke-linejoin: round;
  }
  </style>
</head>

<body>

 <div class="container-fluid">
 <div class="row">
 <div class="col-12">
 <svg id="loader"  viewBox="0 0 
    250.23 131.83"><title>Logo</title><path fill="none" stroke="#000"
     d="M160.9,26.9l-.37.25c6.81,8.24,10.62,17.49"/>
<path fill="none" stroke="#000" 
 d="M28.14,92.59c1.43,1.56,2.81,3,4,4.45,3.56,4.31,6.05"/>
<path fill="none" stroke="#000" d="M80.3,57.58c.27,4.74.54,9.34.81,14l-
 19.33,1v8.1a4.56,4.56,"/>
<path fill="none" stroke="#000" 
 d="M160.9,26.9a5.89,5.89,0,0,1,1.08.74c11.41,"/>
<path fill="none" stroke="#000" d="M28.14,92.59c-3.72,5.21-7.28,"/>
<path fill="none" stroke="#000" 
 d="M80.3,57.58,59.18,59.36V56.54h21C79.42,"/>
<path fill="none" stroke="#000" 
 d="M43.87,73.26a5.31,5.31,0,0,1-.24,5.8c-1.51-.76-1.58-.91-1-2.4Z"/><path fill="none" stroke="#000" d="M103.13,55.28,90"/></svg>
 </div>
 </div>
 </div>
<script src="img/vivus.js"></script>
<script>
 new Vivus('loader', {duration: 3000});
</script>
</body>

</html>
```

Vivus 还有其他配置选项，您可以在这里找到它们：[`github.com/maxwellito/vivus#option-list`](https://github.com/maxwellito/vivus#option-list)。我们不会全部讨论，但我们将说明另一个非常有用的选项，即在动画完成后运行回调函数。

除了我们定义一个简单的回调函数`callback`，它遍历所有具有类`stroke`的元素的实例并将它们的描边更改为不同的颜色，其他都与之前的 Vivus 示例相同。

最终结果看起来像以下的截图。一旦动画完成并且回调函数执行，文本将变为红色：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/9e79b6c5-b695-4721-8f6c-a5f78f63d1e2.png)

回调函数作为可选的第三个参数传递给 Vivus 构造函数。然后在动画完成时执行。

以下代码示例展示了它是如何工作的：

```xml
<!doctype html>
<html lang="en">

<head>
  <meta charset="utf-8">
  <title>Mastering SVG- SVG Animation with Vivus</title>
  <style>
  .stroke{
    stroke-linejoin: round;
  }
  </style>
</head>

<body>
  <div class="container-fluid">
    <div class="row">
      <div class="col-12">
          <svg id="loader"  
            viewBox="0 0 250.23 131.83"><title>Logo</title><path
             fill="none" stroke="#000" 
             d="M160.9,26.9l-.37.25c6.81,8.24,10.62,17.49"/>
<path fill="none" stroke="#000" d="M28.14,92.59c1.43,1.56,2.81,3,4,4.45,3.56,4.31,6.05"/>
<path fill="none" stroke="#000" d="M80.3,57.58c.27,4.74.54,9.34.81,14l-19.33,1v8.1a4.56,4.56,"/>
<path fill="none" stroke="#000" d="M160.9,26.9a5.89,5.89,0,0,1,1.08.74c11.41,"/>
<path fill="none" stroke="#000" d="M28.14,92.59c-3.72,5.21-7.28,"/>
<path fill="none" stroke="#000" d="M80.3,57.58,59.18,59.36V56.54h21C79.42,"/>
<path fill="none" stroke="#000" d="M43.87,73.26a5.31,5.31,0,0,1-.24,5.8c-1.51-.76-1.58-.91-1-2.4Z"/><path fill="none" stroke="#000" d="M103.13,55.28,90"/></svg>
      </div>
    </div>
  </div>
<script src="img/vivus.js"></script>
<script>
  function callback(){
    for (const element of document.getElementsByClassName("stroke")){
      element.style.stroke = "#cc0033";
    };
  }
  new Vivus('loader', {duration: 500}, callback);
</script>
</body>

</html>
```

现在我们已经看了一个只做一件事的动画库，让我们来看看一个更全面的动画库**GreenSock Animation Platform (GSAP)**。

# 使用 GSAP 对 SVG 进行动画

GSAP 是用于 Web 动画的一组强大的 JavaScript 工具。它与 SVG 非常配合。

GSAP 是一组强大的工具，深入探索它所提供的所有内容需要跨越多个章节。*这还只是免费版本*。还有一个高级版本，其中包括更多功能和功能。

好消息是，尽管它非常强大，但 GSAP API 很简单，所以一旦找到所需的功能并查看了强大的文档（[`greensock.com/docs`](https://greensock.com/docs)），您将能够非常快速地做很多事情。

让我们看两个单独的示例，为您介绍 GSAP 可以做什么以及它是如何做到的。

这个第一个示例复制了我们在本章中已经做过几次的相同动画。我们将一个球从 SVG 元素的一边移动到另一边。这个实际上使用了最初 JavaScript 示例中的一些熟悉代码来计算最终位置。

标记与我们迄今为止看到的一样。它是一个 SVG 元素中的一个`circle`元素，带有`circle`的`id`。

要开始使用 GSAP，我们需要在演示中包含他们的 JavaScript。在这种情况下，我们包含了 TweenMax 脚本。在项目文件夹中运行`npm install`将安装 GSAP，然后我们可以从项目的`node_modules`文件夹中包含它。

GSAP 提供了两个不同的 Tween*模块：`TweenLite`和`TweenMax`。

它们的描述如下：

TweenLite 是一个非常快速，轻量级和灵活的动画工具，它是 GSAP 的基础。TweenLite 实例处理任何对象（或对象数组）的一个或多个属性随时间的变化。

TweenMax 扩展了 TweenLite，添加了许多有用（但非必要）的功能，如 repeat()，repeatDelay()，yoyo()等。它还默认包含许多额外的插件，使其功能非常齐全。

我们将在此演示中使用 TweenMax。如果您要开始尝试 GSAP，TweenMax 将为您提供最大的工具集。它稍微慢一些，但更强大，而且在您尝试使用它时，拥有一切都会更有趣。

现在我们已经加载了 JavaScript 文件，让我们开始使用它。

JavaScript 应该看起来很熟悉，至少起初是这样。我们设置了几个熟悉的常量：`doc`作为`document`的别名，`canvas`作为 SVG 元素的引用，`circle`作为我们要动画的圆的本地引用，`viewBox`作为 SVG 元素的`viewBox`的本地引用，`width`作为`viewBox.width`，`newX`作为圆元素的计算完成位置。

GSAP 特定的新代码如下，当我们调用`TweenMax.to`时。`TweenMax.to`是一个方法，用于将 HTML 元素动画到特定状态。参数如下：

+   `"#circle"`是用于匹配我们要动画的元素的 CSS 选择器。

+   `1`是动画将运行的次数。

+   最后，有一个配置对象来定义动画。在我们的示例中，我们将`newX`变量作为`cx`元素的新值传入。

就是这样；GSAP 处理剩下的部分，平滑地将圆圈从屏幕的一端移动到另一端：

```xml
<!doctype html>
<html lang="en">

<head>
  <meta charset="utf-8">
  <title>Mastering SVG- SVG Animation with GSAP</title>

</head>

<body>

  <div class="container-fluid">
    <div class="row">
      <div class="col-12">
        <svg  viewBox="0 0 1000 450" 
        width="1000" height="450" version="1.1" id="canvas" 
        class="canvas">
          <circle cx="75" cy="225" r="50" fill="blue" id="circle">
        </circle>
        </svg>
      </div>
    </div>
  </div>

<script src="img/TweenMax.min.js"></script>
<script>
const doc = document;
const canvas = doc.getElementById("canvas");
const circle = doc.getElementById('circle');
const viewBox = canvas.viewBox.baseVal;
const width = viewBox.width;
const newX = width - (circle.r.baseVal.value * 3);
TweenMax.to("#circle", 1, {attr:{cx:newX}, ease:Linear.easeNone});
</script>
</body>

</html>
```

下一个示例具有相同的设置，但更改了传递到`TweenMax.to`的参数，并添加了另一个链接方法调用以更改动画的持续时间。在这个示例中，我们传入四个单独的属性来对元素进行动画处理，`cx`，`cy`，`r`和`fill`。这个示例展示了 GSAP 的真正力量之一。您不必弄清楚关于这些多个属性动画的时间，各个间隔的样子，或者如何同步它们并解析它们以使它们平稳运行。您只需给 GSAP 一个最终状态，然后观察它的魔力。

此外，我们正在添加一个新的方法，链接到对`TweenMax.to`的调用的末尾。调用`TweenMax.duration`会改变动画的持续时间。在这里，我们传入`5`，以延长动画的持续时间为整整五秒。这种链接的接口允许您以类似于使用 jQuery 和许多其他 JavaScript 库的方式处理动画。这是一个强大而友好的接口。

```xml
<!doctype html>
<html lang="en">

<head>
  <meta charset="utf-8">
  <title>Mastering SVG- SVG Animation with GSAP</title>

</head>

<body>

  <div class="container-fluid">
    <div class="row">
      <div class="col-12">
        <svg  viewBox="0 0 1000 450" 
         width="1000" height="450" version="1.1" id="canvas" 
         class="canvas">
          <circle cx="75" cy="225" r="50" fill="blue" id="circle">
        </circle>
        </svg>
      </div>
    </div>
  </div>

<script src="img/TweenMax.min.js"></script>
<script>
const doc = document;
const canvas = doc.getElementById("canvas");
const circle = doc.getElementById('circle');
const viewBox = canvas.viewBox.baseVal;
const width = viewBox.width;
const height= viewBox.height;
TweenMax.to("#circle", 1, {attr:{cx:width,cy:0,r:height,fill:"red"}, ease:Linear.easeNone}).duration(5);
</script>
</body>

</html>
```

在浏览器中运行上面的代码会产生以下输出：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/775b243b-51ae-4631-a379-da143bb5840e.png)

# 摘要

在本章中，您了解了关于 SVG 的可视化和动画。这包括使用纯 JavaScript、SMIL、CSS 以及两个用于动画的库：GSAP 和 Vivus。

在本章中，我们看到了：

+   使用 JavaScript、SVG 和 CSS 创建自定义数据可视化。您使用 JavaScript 处理了一组数据，并使用结果创建了一个漂亮的可视化，以便以易于阅读的方式说明一组数据。

+   使用 JavaScript 创建自定义 SVG 动画。这包括计算增量以在每秒 60 帧的速度下进行动画，并使用`requestAnimationFrame`作为一种方法，以确保您提供最流畅的体验。

+   使用 CSS 对 SVG 进行动画。您了解到，用于对 SVG 进行动画的强大选项具有不确定的浏览器支持。

+   使用 SMIL 对 SVG 进行动画，这也带来了不确定的浏览器支持。

+   使用 Vivus 库对 SVG 进行动画，这使得在 SVG 中实现“绘图”动画就像包含库并添加一行 JavaScript 代码一样简单。

+   最后，您对强大的 GSAP 库有了一瞥，它为 SVG 和其他元素的动画提供了非常强大的选项。

现在我们已经将一些库引入到混合中，将顺利过渡到一个关于 SVG、Snap.svg 和 SVG.js 的辅助库的整个章节。这些是重要的工具，如果您想要在 SVG 上进行高级的自定义工作，它们将是非常宝贵的。
