# jQuery 参考指南（一）

> 原文：[`zh.annas-archive.org/md5/0AC785FD3E3AB038A029EF6BA3FEE889`](https://zh.annas-archive.org/md5/0AC785FD3E3AB038A029EF6BA3FEE889)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 序言

jQuery 是一个强大但易于使用的 JavaScript 库，它帮助 Web 开发人员和设计师向他们的网站添加动态、交互式元素，消除浏览器不一致性，并大大减少开发时间。在*jQuery 参考指南*中，您可以以全面、易于访问的格式调查此库的特性。

本书提供了每个 jQuery 方法、函数和选择器的有序菜单。每个条目都附有详细描述和有用的示例，这些示例将帮助您充分利用 jQuery，并避免与 JavaScript 和其他客户端语言常见的陷阱。如果您仍然渴望更多，本书还会向您展示如何利用 jQuery 的优雅插件架构来编写自己的扩展。

当你一次又一次地返回到这个指南时，你会发现 jQuery 提供了未被发掘的可能性，并且会磨练你的技能。

本书示例的演示可以在以下网址找到：[http:\\book.learningjquery.com](http://http:\\book.learningjquery.com)。

# 本书涵盖内容

在第一章 中，我们将开始解剖一个可用的 jQuery 示例。此脚本将作为本书的路线图，指导您查找包含有关特定 jQuery 功能更多信息的章节。

本书的核心是一系列参考章节，让您可以快速查找任何 jQuery 方法的详细信息。第二章 列出了用于查找页面元素的每个可用选择器。

第三章 在前一章的基础上，列举了一系列用于查找页面元素的 jQuery 方法。

第四章 描述了检查和修改页面 HTML 结构的每一个机会。

第五章 详细介绍了 jQuery 可以触发和响应的每个事件。

第六章 定义了 jQuery 中内置的动画范围，以及用于构建自己动画的工具包。

第七章 列出了 jQuery 可以启动和响应服务器通信而无需刷新页面的方式。

第八章 涵盖了 jQuery 库中剩余的不容易归类到其他类别的功能。

在最后三章中，您将深入探讨 jQuery 提供的扩展机制。第九章 揭示了使用插件增强 jQuery 已经强大功能的四种主要方式。

第十章 介绍了流行的尺寸插件中可用的高级测量工具。

第十一章 赋予您将 AJAX 技术和 HTML 表单结合在一起的能力，这个过程由表单插件轻松实现。

附录 A 提供了一些关于 jQuery、JavaScript 和 Web 开发的各种主题的信息性网站。

附录 B 推荐了一些有用的第三方程序和工具，用于在您的个人开发环境中编辑和调试 jQuery 代码。

# 这本书是为谁准备的？

本书适用于希望为其设计创建交互元素的网页设计师，以及希望为其 Web 应用程序创建最佳用户界面的开发人员。

读者需要了解 HTML 和 CSS 的基础，并且应该熟悉 JavaScript 的语法。不假设对 jQuery 的了解，也不要求对其他任何 JavaScript 库有经验。

# 约定

在本书中，您会发现一些文本样式，用于区分不同类型的信息。以下是这些样式的一些示例，以及它们的含义解释。

代码有三种风格。文本中的代码词如下所示：“综合起来，`$()` 和 `.addClass()` 足以实现我们改变诗歌文本外观的目标。”

代码块将设置如下所示：

```js
$(document).ready(function() {
  $('span:contains(language)').addClass('emphasized');
});
```

当我们希望引起您对代码块的特定部分的注意时，相关的行或项目将被加粗显示：

```js
$(document).ready(function() {
 $('a[@href$=".pdf"]').addClass('pdflink');
});
```

**新术语** 和 **重要单词** 以粗体字体介绍。您在屏幕上看到的单词，例如菜单或对话框中的单词，会以我们的文本形式出现，如：“下一步是通过点击**全部**按钮来运行这些测试”。

### 注意

重要提示将显示在这样的框中。

### 提示

提示和技巧会像这样显示。


# 第一章：jQuery 脚本的结构

> 他有一个崭新的开始
> 
> 现在他是一个快乐的人
> 
> —Devo，
> 
> "快乐的人"

典型的 jQuery 脚本使用库提供的各种方法。选择器，DOM 操作，事件处理等根据手头任务的需要而使用。为了最大程度地利用 jQuery，我们需要牢记它提供的广泛功能范围。

本书将列举 jQuery 库中的每种方法和函数。由于有许多方法和函数需要整理，因此了解方法的基本类别以及它们在 jQuery 脚本中的作用方式将非常有用。在这里，我们将看到一个完全可用的脚本，并查看 jQuery 的不同方面在脚本的每个部分中如何被利用。

# 一个动态目录

作为 jQuery 实践的例子，我们将构建一个小脚本，动态提取 HTML 文档中的标题，并将它们组装成该页面的目录。

我们的目录将位于页面的右上角：

![一个动态目录](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-ref-gd/img/3810_01_01.jpg)

我们将其最初折叠如上所示，但点击将其展开至全高度：

![一个动态目录](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-ref-gd/img/3810_01_02.jpg)

同时，我们将为主体文本添加一个功能。页面上文本的介绍不会最初加载，但当用户点击**介绍**一词时，将从另一个文件中插入介绍文本：

![一个动态目录](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-ref-gd/img/3810_01_03.jpg)

在我们揭示执行这些任务的脚本之前，我们应该先了解脚本所在的环境。

## 获取 jQuery

官方的 jQuery 网站 ([`jquery.com/`](http://jquery.com/)) 总是与该库相关的代码和新闻的最新资源。要开始，我们需要一份 jQuery 的副本，可以直接从网站的主页下载。在任何时候可能有几个版本的 jQuery 可用；最新的未压缩版本最适合我们。

jQuery 不需要安装。要使用 jQuery，我们只需将其放置在网站的公共位置即可。由于 JavaScript 是一种解释性语言，所以不需要担心编译或构建阶段。每当我们需要一个页面具有 jQuery 时，我们只需在 HTML 文档中引用文件的位置即可。

## 设置 HTML 文档

大多数 jQuery 使用示例分为三个部分— HTML 文档本身，用于样式的 CSS 文件，以及用于对其进行操作的 JavaScript 文件。在本例中，我们将使用包含书籍文本的页面：

```js
<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
	"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html  xml:lang="en" lang="en">
  <head>
  	<meta http-equiv="Content-Type" content="text/html;
                                                   charset=utf-8"/>
  	<title>Doctor Dolittle</title>
    <link rel="stylesheet" href="dolittle.css" type="text/css" />
  	<script src="img/jquery.js" type="text/javascript"></script>
  	<script src="img/dolittle.js" type="text/javascript"></script>
  </head>
  <body>
    <div id="container">
      <h1>Doctor Dolittle</h1>
      <div class="author">by Hugh Lofting</div>
      <div id="introduction">
        <h2><a href="introduction.html">Introduction</a></h2>
      </div>
      <div id="content">
        <h2>Puddleby</h2>
        <p>ONCE upon a time, many years ago when our grandfatherswere little children--there was a doctor; and his name wasDolittle-- John Dolittle, M.D.  &quot;M.D.&quot; means that he was a proper doctor and knew a whole lot.</p>

           <!-- More text follows... -->

      </div>
    </div>
  </body>
</html>
```

### 注意

服务器上文件的实际布局并不重要。从一个文件到另一个文件的引用只需要调整以匹配我们选择的组织结构即可。在本书的大多数示例中，我们将使用相对路径来引用文件（`../images/foo.png`），而不是绝对路径（`/images/foo.png`）。这样可以使代码在本地运行而无需 web 服务器。

样式表立即在标准的`<head>`元素之后加载。以下是影响我们动态元素的样式表部分：

```js
/* -----------------------------------
   Page Table of Contents
-------------------------------------- */
#page-contents {
  position: absolute;
  text-align: left;
  top: 0;
  right: 0;
  width: 15em;
  border: 1px solid #ccc;
  border-top-width: 0;
  border-right-width: 0;
  background-color: #e3e3e3;
}
#page-contents h3 {
  margin: 0;
  padding: .25em .5em .25em 15px;
  background: url(arrow-right.gif) no-repeat 0 2px;
  font-size: 1.1em;
  cursor: pointer;
}
#page-contents h3.arrow-down {
  background-image: url(arrow-down.gif);
}
#page-contents a {
  display: block;
  font-size: 1em;
  margin: .4em 0;
  font-weight: normal;
}
#page-contents div {
  padding: .25em .5em .5em;  
  display: none;
  background-color: #efefef;
}

/* -----------------------------------
   Introduction
-------------------------------------- */
.dedication {
  margin: 1em;
  text-align: center;
  border: 1px solid #555;
  padding: .5em;
}
```

样式表被引用后，JavaScript 文件被包含。重要的是，jQuery 库的脚本标签必须在我们自定义脚本的标签之前放置*之前*；否则，当我们的代码尝试引用它时，jQuery 框架将不可用。

## 编写 jQuery 代码

我们的自定义代码将放在第二个当前为空的 JavaScript 文件中，我们将其包含在 HTML 中使用 `<script src="img/dolittle.js" type="text/javascript"></script>`。尽管它能够完成很多工作，但脚本相当简短：

```js
jQuery.fn.toggleNext = function() {
  this.toggleClass('arrow-down')
    .next().slideToggle('fast');
};

$(document).ready(function() {
  $('<div id="page-contents"></div>')
    .prepend('<h3>Page Contents</h3>')
    .append('<div></div>')
    .prependTo('body'); 

  $('#content h2').each(function(index) {
    var $chapterTitle = $(this);
    var chapterId = 'chapter-' + (index + 1);
    $chapterTitle.attr('id', chapterId);
    $('<a></a>').text($chapterTitle.text())
      .attr({
        'title': 'Jump to ' + $chapterTitle.text(),
        'href': '#' + chapterId
      })
      .appendTo('#page-contents div');
  });

  $('#page-contents h3').click(function() {
    $(this).toggleNext();
  });

  $('#introduction > h2 a').click(function() {
    $('#introduction').load(this.href);
    return false;
  });
});
```

现在我们有了一个动态的目录，可以将用户带到文本的相关部分，并且可以按需加载介绍部分。

# 脚本解剖

选择此脚本是因为它展示了 jQuery 库的广泛功能。现在我们已经将代码作为一个整体看过了，我们可以确定其中使用的方法类别。

### 注意

我们不会在这里详细讨论此脚本的操作，但是类似的脚本作为 Learning jQuery 网志上的教程呈现：[`www.learningjquery.com/2007/06/ automatic-page-contents`](http://www.learningjquery.com/2007/06/)。

## 选择器表达式

在我们可以对 HTML 文档进行操作之前，我们需要找到相关部分。在我们的脚本中，有时我们会使用一种简单的方法来查找元素：

```js
$('#introduction')

```

此表达式创建一个新的 jQuery 对象，该对象引用具有`introduction` ID 的元素。另一方面，有时我们需要一个更复杂的选择器：

```js
$('#introduction > h2 a')

```

在这里，我们产生了一个可能引用许多元素的 jQuery 对象。如果它们是锚点标签，则包括这些元素，但仅在它们是`introduction` ID 元素的子元素的`<h2>`元素的后代时。

这些**选择器表达式**可以简单也可以复杂，取决于我们的需要。第二章 将列举我们可用的所有选择器以及它们如何组合使用。

## DOM 遍历方法

有时我们有一个 jQuery 对象，它已经引用了一组 DOM 元素，但我们需要对一个不同的相关元素执行操作。在这些情况下，**DOM 遍历**方法很有用。我们可以在我们的脚本的一部分中看到这一点：

```js
this.toggleClass('arrow-down')
 .next()
  .slideToggle('fast');
```

由于代码片段的上下文，关键字`this`指的是一个 jQuery 对象（通常指的是 DOM 元素）。在我们的情况下，这个 jQuery 对象又指向目录的`<h3>`标题。`.toggleClass`方法调用操纵了这个标题元素。随后的`.next()`操作改变了我们正在处理的元素，因此接下来的`.slideToggle`方法调用作用于包含目录的`<div>`而不是其标题。允许我们自由移动 DOM 树的方法在第三章中列出。

## DOM 操作方法

找到元素还不够；我们还希望能够修改它们。这些变化可以像更改单个属性一样简单：

```js
$chapterTitle.attr('id', chapterId);

```

在这里，我们即时修改了匹配元素的 ID。

有时候，这些变化影响更深远：

```js
$('<div id="page-contents"></div>')
  .prepend('<h3>Page Contents</h3>')
  .append('<div></div>')
  .prependTo('body'); 
```

脚本的这一部分说明了**DOM 操作**方法不仅可以就地更改元素，还可以删除、重排和插入它们。这些代码在`<div id="page-contents">`的开头添加了一个新的标题，将另一个`<div>`容器插入到其末尾，并将整个内容放在文档主体的开头。第四章将详细介绍这些以及修改 DOM 树的许多其他方法。

## 事件方法

即使我们可以随意修改页面，我们的页面仍然会静止不动，不响应。我们需要**事件方法**来对用户输入做出反应，以在适当的时候进行更改：

```js
$('#introduction > h2 a').click(function() {
  $('#introduction').load(this.href);
  return false;
});
```

在这个片段中，我们注册了一个处理程序，每次选择的锚点标签被点击时都会执行。点击事件是最常见的事件之一，但还有许多其他事件；与它们交互的 jQuery 方法在第五章中讨论。

第五章还讨论了一个非常特殊的事件方法`.ready`：

```js
$(document).ready(function() {
  // ...
});
```

这个方法允许我们注册行为，当 DOM 结构可用于我们的代码时立即发生——甚至在图片加载之前。

## 效果方法

事件方法使我们能够对用户输入做出反应；**效果方法**让我们以一种有型的方式做到这一点。我们可以通过动画来隐藏和显示元素，而不是立即执行：

```js
this.toggleClass('arrow-down')
  .next()
 .slideToggle('fast');

```

这个方法在元素上执行快速的滑动过渡，每次调用时交替隐藏和显示它。内置效果方法在第六章中列出，创建新效果方法的方法也在其中。

## AJAX 方法

许多现代网站采用技术在请求时加载内容，而不需要刷新页面；jQuery 可以轻松实现这一点。**AJAX 方法**启动这些内容请求，并允许我们监视其进度：

```js
$('#introduction > h2 a').click(function() {
 $('#introduction').load(this.href);
  return false;
});
```

这里的`.load`方法允许我们从服务器获取另一个 HTML 文档，并将其插入到当前文档中，所有这些都可以通过一行代码完成。从服务器检索信息的更复杂机制以及其他信息列在第七章中。

## 其他方法

有些方法比其他方法更难分类。jQuery 库包含几种作为常见 JavaScript 习语的简写的**其他方法**。

即使是基本的迭代任务，通过 jQuery 也可以简化：

```js
$('#content h2').each(function(index) {
  // ...
});
```

在这里看到的`.each`方法逐个遍历匹配的元素，对所有匹配的元素执行封闭的代码。在本例中，该方法帮助我们收集页面中的所有标题，以便我们可以编写完整的目录。类似的帮助函数可以在第八章中找到。

## 插件 API

我们不需要限制自己在内置功能中。jQuery 中的**插件 API**允许我们扩展已存在的功能，增加符合我们需求的新功能。即使在我们编写的小脚本中，我们也发现了插件的用处：

```js
jQuery.fn.toggleNext = function() {
  this.toggleClass('arrow-down')
    .next().slideToggle('fast');
};
```

这段代码定义了一个新的`.toggleNext` jQuery 方法，可以展开或关闭后续元素。我们可以在需要时随时调用我们的新方法：

```js
$('#page-contents h3').click(function() {
  $(this).toggleNext();
});
```

每当代码可以在当前脚本之外重复使用时，将其作为插件会更好。第九章将介绍用于构建这些扩展的插件 API。

# 摘要

我们现在已经看到了一个完整的、功能的 jQuery 脚本。尽管这个示例很小，但它为页面带来了相当多的交互性和可用性。这个脚本展示了 jQuery 提供的主要工具类型。我们观察了脚本如何在 DOM 中查找项目并根据需要更改它们。我们见证了对用户操作的响应以及为用户在操作后提供反馈的动画。我们甚至看到了如何在不刷新页面的情况下从服务器获取信息，以及如何教会 jQuery 通过插件学习全新的技巧。

我们将逐章逐节地讲解 jQuery 库中的每个函数、方法和选择器表达式。在许多情况下，一个自定义日志函数将有助于我们的示例。这个`.log`方法将文本打印到屏幕上，以便我们理解；在第九章的最后，我们将解析它作为插件的示例。

每个方法都将以其语法摘要、参数列表和返回值列表的总结介绍。然后我们将提供讨论，提供适用的示例。有关任何方法的更多信息，请参考附录 A 中列出的在线资源。


# 第二章：选择器表达式

> 你让我仰望高处
> 
> 你让我搜索到最低处
> 
> —Devo，
> 
> "Jerkin' Back 'n' Forth"

借鉴了 CSS 1-3 和基本 XPath，然后添加了自己的内容，jQuery 提供了一组强大的选择器表达式，用于在文档中匹配一组元素。在本章中，我们将依次检查 jQuery 提供的每个选择器表达式。

# CSS 选择器

以下选择器基于 W3C 制定的 CSS 1-3。有关规范的更多信息，请访问[`www.w3.org/Style/CSS/#specs`](http://www.w3.org/Style/CSS/#specs)。

## 元素：T

所有标签名为`T`的元素。

### 示例

1.  `$('div')`: 选择文档中所有标签名为 `div` 的元素

1.  `$('em')`: 选择文档中所有标签名为 `em` 的元素

### 描述

jQuery 使用 JavaScript 的 `getElementsByTagName()` 函数进行标签名选择器。

## ID：#myid

具有 ID 等于 `myid` 的唯一元素。

### 示例

1.  `$('#myid')`: 选择具有 `id='myid'` 的唯一元素，无论其标签名是什么

1.  `$('p#myid')`: 选择具有 `'myid'` `id` 的单个段落；换句话说，选择唯一的元素 `<p id='myid'>`

### 描述

每个 `id` 值在文档中只能使用一次。如果有多个元素被分配了相同的 `id`，那些使用该 `id` 的查询将只选择 DOM 中匹配的第一个元素。

可能不会立即清楚为什么有人想要指定与特定 `id` 关联的标签名，因为该 `id` 本身必须是唯一的。然而，在某些用户生成 DOM 的情况下，可能需要更具体的表达式以避免误报。此外，当相同的脚本在多个页面上运行时，可能需要识别 `id` 的元素，因为页面可能将相同的 `id` 与不同的元素关联起来。例如，页面 A 可能具有 `<h1 id='title'>` 而页面 B 具有 `<h2 id='title'>`。

对于简单的 `id` 选择器，例如上面的示例 2，jQuery 使用 JavaScript 函数 `getElementById()`。如果脚本的执行速度至关重要，则应使用简单的 `id` 选择器。

## 类：.myclass

所有具有类名为 `myclass` 的元素。

### 示例

1.  `$('.myclass')`: 选择所有具有类名为 `myclass` 的元素

1.  `$('p.myclass')`: 选择所有具有类名为 `myclass` 的段落

1.  `$('.myclass.otherclass')`: 选择所有具有类名为 `myclass` 和 `otherclass` 的元素

### 描述

就速度而言，示例 2 通常比示例 1 更可取（如果我们可以限制查询到给定的标签名称），因为它首先使用本机 JavaScript 函数 `getElementsByTagName()` 来过滤其搜索，然后在匹配的 DOM 元素子集中查找类。相反，目前没有本机的 `getElementsByClassName()` 供 jQuery 使用，因此使用裸类名会迫使 jQuery 将其与 DOM 中的每个元素匹配。然而，速度上的差异取决于页面的复杂性和 DOM 元素的数量。

一如既往，请记住开发时间通常是最宝贵的资源。除非明确需要改善性能，否则不要专注于选择器速度的优化。

作为 CSS 选择器，现代所有网络浏览器都支持示例 3 的多类语法，但不包括 Internet Explorer 6 及以下版本，这使得该语法特别适用于通过 jQuery 跨浏览器应用样式。

## 后代：E F

所有由 `F` 匹配的元素，这些元素是由 `E` 匹配的元素的后代。

### 举例

1.  `$('#container p')`: 选择所有由`<p>`匹配的元素，这些元素是具有`container` id 的元素的后代。

1.  `$('a img')`: 选择所有由 `<a>` 匹配的元素的后代 `<img>` 元素。

### 描述

元素的后代可以是该元素的子元素、孙子元素、曾孙元素等等。例如，在以下 HTML 中，`<img>` 元素是 `<span>、<p>、<div id="inner">` 和 `<div id="container">` 元素的后代：

```js
<div id="container">
  <div id="inner">
    <p>
      <span><img src="img/example.jpg" alt="" /></span>
    </p>
  </div>
</div>
```

## 子级：E > F

所有由 `F` 匹配的元素，这些元素是由 `E` 匹配的元素的子级。

### 举例

1.  `$('li > ul')`: 选择所有由`<li>`匹配的元素的子元素`<ul>`。

1.  `$('p > code')`: 选择所有由`<p>`匹配的元素的子元素`<code>`。

### 描述

作为 CSS 选择器，子级组合器被所有现代网络浏览器支持，包括 Safari、Mozilla/Firefox 和 Internet Explorer 7，但显然不包括 Internet Explorer 6 及以下版本。示例 1 是选择所有嵌套无序列表（即除了顶层之外）的方便方法。

子级组合器可以被视为（单空格）后代组合器的更具体形式，因为它只选择第一级后代。因此，在以下 HTML 中，`<img>` 元素只是 `<span>` 元素的子元素。

```js
<div id="container">
  <div id="inner">
    <p>
      <span><img src="img/example.jpg" alt="" /></span>
    </p>
  </div>
</div>
```

## 相邻兄弟：E + F

所有由`F`匹配且*紧接着*跟在与`E`匹配的元素相同父级的元素。

### 举例

1.  `$('ul + p')`: 选择所有由 `<ul>`（无序列表）匹配的兄弟元素后立即跟随的元素`<p>`（段落）。

1.  `$('strong + em')`: 选择所有由 `<strong>` 匹配的兄弟元素后立即跟随的元素`<em>`。

### 描述

要考虑的一个重要点是`+`组合器和`~`组合器（下面介绍）只选择兄弟元素。 考虑以下 HTML：

```js
<div id="container">
  <ul>
    <li></li>
    <li></li>
  </ul>
  <p>
    <img/>
  </p>
</div>
```

`$('ul + p')`选择`<p>`，因为它紧接在`<ul>`后面，并且这两个元素共享相同的父级，即`<div id="container">`。

`$('ul + img')`不选择任何东西，因为（除其他原因外）`<ul>`在 DOM 树中比`<img>`高一个级别。

`$('li + img')`不选择任何内容，因为即使`<li>`和`<img>`在 DOM 树中处于同一级别，它们也不共享相同的父级。

## 一般兄弟：E ~ F

所有由`E`匹配的元素，其后跟一个由`E`匹配的元素，并且具有相同的父级。

### 例子

1.  `$('p ~ ul')`：选择所有由`<p>`匹配的元素，后跟由`<ul>`匹配的兄弟元素

1.  `$('code ~ code')`：选择所有由`<code>`匹配的元素，后跟由`<code>`匹配的兄弟元素

### 描述

要考虑的一个重要点是`+`组合器和`~`组合器只选择*兄弟元素*。 两者之间的显着区别在于它们各自的范围。 虽然`+`组合器仅达到*紧接着*的下一个兄弟元素，但`~`组合器将该范围扩展到*所有*后续兄弟元素。

考虑以下 HTML：

```js
<ul>
  <li class="first"></li>
  <li class="second"></li>
  <li class="third></li>
</ul>
<ul>
  <li class="fourth"></li>
  <li class="fifth"></li>
  <li class="sixth"></li>
</ul>
```

`$('li.first ~ li')`选择`<li class="second">`和`<li class="third">`。

`$('li.first + li')`选择`<li class="second">`。

## 多个元素：E,F,G

选择所有由选择器表达式`E, F`或`G`匹配的元素。

### 例子

1.  `$('code, em, strong')`：选择所有由`<code>`或`<em>`或`<strong>`匹配的元素

1.  `$('p strong, .myclass')`：选择所有由`<p>`匹配的元素的后代 `<strong>` 以及具有 `myclass` 类的所有元素

### 描述

这个逗号（,）组合器是选择不同元素的有效方式。 这个组合器的另一个选择是在第三章中描述的`.add()`方法。

## Nth Child（:nth-child(n)）

所有是其父级的第`n`个子元素的元素。

### 例子

1.  `$('li:nth-child(2)')`：选择所有由`<li>`匹配的元素，它们是其父级的第二个子元素

1.  `$('p:nth-child(5)')`：选择所有由`<p>`匹配的元素，它们是其父级的第五个子元素

### 描述

因为 jQuery 对 `:nth-child(n)` 的实现严格来自 CSS 规范，因此 `n` 的值是*基于 1 的*，这意味着计数从 1 开始。 但是，对于所有其他选择器表达式，jQuery 遵循 JavaScript 的“基于 0 的”计数。 因此，鉴于一个包含两个 `<li>` 的单个 `<ul>`，`$('li:nth-child(1)')`选择第一个 `<li>`，而`$('li:nth(1)')`选择第二个。

由于两者看起来非常相似，`:nth-child(n)` 伪类很容易与 `:nth(n)` 混淆，尽管正如我们刚刚看到的，它们可能会导致截然不同的匹配元素。 使用 `:nth-child(n)`，所有子元素都被计数，无论它们是什么，只有当它们与附加到伪类的选择器匹配时才会选择指定的元素。 使用 `:nth(n)` 仅计数附加到伪类的选择器，不限于任何其他元素的子元素，并选择第 n 个元素。 为了证明这一区别，让我们来看看以下 HTML 给出的几个选择器表达式的结果：

```js
<div>
  <h2></h2>
  <p></p>
  <h2></h2>
  <p></p>
  <p></p>
</div>
```

`$('p:nth(1)')` 选择第二个 `<p>`，因为 `:nth(n)` 的编号从 `0` 开始。

`$('p:nth-child(1)')` 选择不到任何内容，因为没有 `<p>` 元素是其父元素的第一个子元素。

`$('p:nth(2)')` 选择第三个 `<p>`。

`$('p:nth-child(2)')` 选择第一个 `<p>`，因为它是其父元素的第二个子元素。

除了接受整数外，`:nth-child(n)` 还可以接受 `even` 或 `odd`。 当文档中出现多个表格时，这使得它特别适用于表行条纹解决方案。 再次考虑上面的 HTML 片段：

`$('p:nth-child(even)')` 选择第一个和第三个 `<p>`，因为它们是其父元素的第二个和第四个子元素（都是偶数）。

## 第一个子元素 (:first-child)

所有是其父元素的第一个子元素的元素：

### 示例

1.  `$('li:first-child')`: 选择所有与 `<li>` 匹配的元素，它们是其父元素的第一个子元素。

1.  `$(strong:first-child')`: 选择所有与 `<strong>` 匹配的元素，它们是其父元素的第一个子元素。

### 描述

`:first-child` 伪类是 `:nth-child(1)` 的简写。 关于 `:X-child` 伪类的更多信息，请参阅 `:nth-child(n)` 的讨论。

## 最后一个子元素 (:last-child)

所有是其父元素的最后一个子元素的元素。

### 示例

1.  `$('li:last-child')`: 选择所有与 `<li>` 匹配的元素，它们是其父元素的最后一个子元素。

1.  `$('code:last-child')`: 选择所有与 `<code>` 匹配的元素，它们是其父元素的最后一个子元素。

### 描述

关于 `:X-child` 伪类的更多信息，请参阅 `:nth-child(n)` 的讨论。

## 只有一个子元素 :only-child

所有只有一个子元素的元素。

### 示例

1.  `$(':only-child')`: 选择所有只有一个子元素的元素。

1.  `$('code:only-child')`: 选择所有只有一个子元素的 `<code>` 元素。

## 不是 :not(s)

所有不匹配选择器 `s` 的元素。

### 示例

1.  `$('li:not(.myclass)')`: 选择所有与 `<li>` 匹配的元素，它们没有 `class="myclass"`。

1.  `$('li:not(:last-child)')`: 选择所有与 `<li>` 匹配的元素，它们不是其父元素的最后一个子元素。

## 空 :empty

所有没有子元素（包括文本节点）的元素。

### 示例

1.  `$(':empty')`: 选择所有没有子元素的元素。

1.  `$('p:empty')`: 选择所有与 `<p>` 匹配的元素，它们没有子元素。

### 描述

W3C 建议`<p>`元素至少有一个子节点，即使该子节点只是文本（请参阅[`www.w3.org/TR/html401/struct/text.html#edef-P`](http://www.w3.org/TR/html401/struct/text.html#edef-P)）。另一方面，一些其他元素是空的（即没有子元素）：例如`<input>, <img>, <br>`和`<hr>`。

注意使用`:empty`（和`:parent`）时的一件重要事情是*子元素包括文本节点*。

## 通用：*

所有元素。

### 例子

1.  `$('*')`：选择文档中的所有元素

1.  `$('p > *')`：选择所有作为段落元素的子元素的元素

### 描述

当与其他元素结合形成更具体的选择器表达式时，`*`选择器尤其有用。

# XPath 选择器

仿照文件系统的目录树导航，XPath 选择器表达式提供了一种替代方式来访问 DOM 元素。尽管 XPath 是为 XML 文档开发的选择器语言，但 jQuery 提供了一组基本的选择器，可用于 XML 和 HTML 文档。

有关 XPath 1.0 的更多信息，请访问 W3C 的规范：[`www.w3.org/TR/xpath`](http://www.w3.org/TR/xpath)。

## 后代：E//F

所有由`E`匹配的元素的后代，这些元素是由`F`匹配的元素的后代。

### 例子

1.  `$('div//code')`：选择所有由`<div>`匹配的元素的后代 `<code>`

1.  `$('//p//a')`：选择所有由`<p>`匹配的元素的后代 `<a>`

### 描述

此 XPath 后代选择器与相应的 CSS 后代选择器`($('E F'))`的工作方式相同，只是 XPath 版本可以指定从文档根开始，这在查询 XML 文档时可能很有用。

在示例 2 中，初始的`//p`告诉 jQuery 从文档根开始匹配所有`<p>`元素及其后代。请注意，如果此选择器表达式跟随 DOM 遍历方法（如`.find()`），则此语法将不会选择任何内容，因为文档根不能是任何其他元素的子元素。由于 jQuery 允许自由混合 CSS 和 XPath 选择器，因此初始的`//`是多余的，因此可以省略。

## 子元素：E/F

所有由`E`匹配的元素的子元素，这些元素是由`F`匹配的元素的子元素。

### 例子

1.  `$('div/p')`：选择所有由`<div>`匹配的元素的子元素 `<p>`

1.  `$('p/a')`：选择所有由`<p>`匹配的元素的子元素 `<a>`

1.  `$('/docroot/el')`：选择所有由`<docroot>`匹配的元素的子元素 `<el>`，只要`<docroot>`实际上位于文档根

### 描述

XPath 子选择器 `$('E/F')` 是 CSS 子选择器 `$('E > F')` 的替代方案。如果选择器表达式以单斜杠开头，例如示例 3 中的情况，则紧随斜杠之后的选择器必须位于文档根目录。在 HTML 文档中不推荐以单斜杠开头，因为它始终必须跟随 `body` 才能匹配页面上的任何元素。然而，在 XML 文档中，识别文档根中的特定元素或属性可能是有用的。

## 父元素：E/..

所有与 `E` 匹配的元素的父元素。

### 示例

1.  `$('.myclass/..')`: 选择所有具有类名为 `myclass` 的元素的父元素。

1.  `$('.myclass/../')`: 选择所有是具有类名为 `myclass` 的元素的父元素的子元素。换句话说，它选择所有具有类名为 `myclass` 的元素，以及它们的兄弟元素。

1.  `$('.myclass/../p')`: 选择所有匹配 `<p>` 的元素，这些元素是具有类名为 `myclass` 的元素的父元素的子元素。

### 描述

让我们看一些示例 HTML 来帮助理解这个选择器：

```js
<div>
  <p id="firstp"></p>
  <div id="subdiv"></div>
  <p id="secondp">
    <span class="myclass"></span>
  </p>
</div>
<div>
  <p></p>
</div>
```

`$('span.myclass/..')` 选择 `<p id="secondp">`，因为它是 `<span class="myclass">` 的父元素。

`$('#firstp/../')` 选择 `<p id="firstp">, <div id="subdiv">` 和 `<p id="secondp">`，因为选择器 (a) 以 `<p id="firstp">` 开头， (b) 在 DOM 树中向上遍历一级（到第一个顶级 `<div>` 元素），以及 (c) 选择该 `<div>` 的所有子元素。

`$('.myclass/../../p')` 选择 `<p id="firstp">` 和 `<p id="secondp">`，因为选择器 (a) 以 `<span class="myclass">` 开头， (b) 在 DOM 树中向上遍历两级（到第一个顶级 `<div>` 元素），以及 (c) 选择所有 `<p>` 元素，这些元素是该 `<div>` 的子元素。

## 包含: [F]

包含由 `F` 匹配的所有元素。

### 示例

1.  `$('div[p]')`: 选择所有匹配 `<div>` 的元素，这些元素包含匹配 `<p>` 的元素。

1.  `$('p[.myclass]')`: 选择所有匹配 `<p>` 的元素，其中包含类名为 `myclass` 的元素。

### 描述

这个选择器类似于后代选择器的反向（`E//F` 或 `E F`），它选择所有具有匹配 `F` 的后代元素，而不是所有由其他元素的后代匹配 `F` 的元素。

XPath 的 *包含* 选择器不应与 CSS 的 *属性* 选择器混淆，后者共享此语法。jQuery 也使用 XPath 风格的表达式来表示属性选择器，如下文 *属性选择器* 部分所述。

# 属性选择器

因为 jQuery 支持 CSS 和 XPath 样式的表达式，并且两者在使用方括号时冲突，jQuery 采用 XPath 符号来表示属性选择器，以 `@` 符号开头。

使用以下任何属性选择器时，我们应考虑具有多个、以空格分隔的值的属性。由于这些选择器将属性值视为单个字符串，因此，例如此选择器 `$('[a@rel=nofollow]')` 将选择 `<a rel="nofollow" href="example.html">Some text</a>`，但 *不会* 选择 `<a rel="nofollow self" href="example.html">Some text</a>`。

选择器表达式中的属性值可以写成裸字或用引号括起来。因此，以下变体同样正确：

+   裸字：`$('[a@rel=nofollow self]')`

+   单引号内部的双引号：`$('[a@rel="nofollow self"]')`

+   双引号内部的单引号：`$("[a@rel='nofollow self']")`

+   在单引号内部转义单引号：`$('[a@rel=\'nofollow self\']')`

+   在双引号内部转义双引号：`$("[a@rel=\"nofollow self\"]")`

我们选择的变体通常是风格或便利性的问题。

## 具有属性：[@foo]

所有具有 `foo` 属性的元素。

### 示例

1.  `$('a[@rel]')`：选择所有具有 `rel` 属性的 `<a>` 元素

1.  `$('p[@class]')`：选择所有具有 `class` 属性的 `<p>` 元素

### 描述

关于此属性选择器的更多信息，请参见上面的 *属性选择器* 介绍。

## 属性值等于：[@foo=bar]

具有值完全等于 `bar` 的 `foo` 属性的元素。

### 示例

1.  `$('a[@rel=nofollow]')`：选择所有具有 `rel` 值完全等于 `nofollow` 的 `<a>` 元素

1.  `$('input[@name=myname]')`：选择所有具有 `name` 值完全等于 `myname` 的 `<input>` 元素

### 描述

关于此属性选择器的更多信息，请参见上面的 *属性选择器* 介绍。

## 属性值不等于：[@foo!=bar]

所有不具有值完全等于 `bar` 的 `foo` 属性的元素。

### 示例

1.  `$('a[@rel!=nofollow]')`：选择所有没有 `rel` 属性值完全等于 `nofollow` 的 `<a>` 元素

1.  `$('input[@name!=myname]')`：选择所有不具有 `name` 值完全等于 `myname` 的 `<input>` 元素

### 描述

由于这些选择器将属性值视为单个字符串，因此 `$('[a@rel!=nofollow]')` 我们 *将* 选择 `<a rel="nofollow self" href="example.htm">Some text</a>`。

如果我们需要仅选择 `<a>` 元素，并且它们的 `rel` 属性中没有任何地方包含 `nofollow`，我们可以使用以下选择器表达式代替：`$('a:not([@rel*=nofollow])')`。

## 属性值开头：[@foo^=bar]

所有具有值 *以* 字符串 `bar` 开头的 `foo` 属性的元素。

### 示例

1.  `$('a[@rel^=no]')`：选择所有具有 `rel` 属性值以 `no` 开头的 `<a>` 元素

1.  `$('input[@name^=my]')`：选择所有具有 `name` 值以 `my` 开头的 `<input>` 元素

### 描述

由于这些选择器将属性值视为单个字符串，`$('[a@rel^=no]')` 将选择 `<a rel="nofollow self" href="example.htm">Some text</a>`，但不选择 `<a rel="self nofollow" href="example.htm">Some text</a>`。

## 属性值结尾: [@foo$=bar]

所有具有以字符串 `bar` 结尾的值的 `foo` 属性的元素。

### 示例

1.  `$('a[@href$=index.htm]')`：选择所有 `href` 值以 `index.htm` 结尾的 `<a>` 元素

1.  `$('a[@rel$=self]')`：选择所有 `class` 值以 `bar` 结尾的 `<p>` 元素

### 描述

由于这些选择器将属性值视为单个字符串，`$('[a@rel$=self]')` 将选择 `<a rel="nofollow self" href="example.htm">Some text</a>`，但不选择 `<a rel="self nofollow" href="example.htm">Some text</a>`。

## 属性值包含: [@foo*=bar]

所有具有包含子字符串 `bar` 的 `foo` 属性的元素。

### 示例

1.  `$('p[@class*=bar]')`：选择所有 `class` 值包含 `bar` 的 `<p>` 元素

1.  `$('a[@href*=example.com]')`：选择所有 `href` 值包含 `example.com` 的 `<a>` 元素

### 描述

这是 jQuery 属性选择器中最宽松的选择器。如果选择器的字符串出现在元素的属性值的任何位置，它都将选择该元素。因此，`$('p[@class*=my]')` 将选择 `<p class="yourclass myclass">Some text</p>, <p class="myclass yourclass">Some text</p>` 和 `<p class="thisismyclass">Some text</p>`。

# 表单选择器

以下选择器可用于访问各种状态下的表单元素。在使用除 `:input` 外的任何表单选择器时，建议同时提供标签名（例如，使用 `input:text` 而不是 `:text`）。

+   所有表单元素（`<input>`（所有类型），`<select>, <textarea>, <button>`）

+   所有文本字段（`<input type="text">`)

+   所有密码字段（`<input type="password">`)

+   所有单选按钮字段（`<input type="radio">`)

+   所有复选框字段（`<input type="checkbox">`)

+   所有提交输入和按钮元素（`<input type="submit">, <button>`）

+   所有图像输入（`<input type="image">）

+   所有重置按钮（`<input type="reset">`)

+   所有按钮元素和类型为 `button` 的输入元素（`<button>,<input type="button">`）

+   所有已启用的用户界面元素

+   所有已禁用的用户界面元素

+   所有已选中的用户界面元素—复选框和单选按钮

+   所有元素，包括 `<input type="hidden" />`，都处于隐藏状态

欲了解更多信息，请参阅下文的 *自定义选择器* 部分中关于 `:hidden` 的讨论。

# 自定义选择器

以下选择器被添加到 jQuery 库中，以满足 CSS 或基本 XPath 无法满足的常见 DOM 遍历需求。

## 偶数元素 (:even) 奇数元素 (:odd)

所有具有偶数索引的元素：

`:even`

所有具有奇数索引的元素：

`:odd`

### 示例

1.  `$('li:even')`: 选择所有 `<li>` 元素匹配的元素，其 `index` 值为偶数

1.  `$('tr:odd')`: 选择所有被 `<tr>` 匹配的元素，其 `index` 值为奇数

### 描述

因为自定义的 `:even` 和 `:odd` 伪类基于它们的 `index` 匹配元素，它们使用 JavaScript 的本机基于零的编号。

有些令人感到反直觉，因此，`:even` 选择第一、第三、第五（等等）个元素，而 `:odd` 选择第二、第四、第六（等等）个元素。

这条规则的唯一例外是 `:nth-child(n)` 选择器，它是基于一的。所以，`:nth-child(even)` 选择其父级的第二、第四、第六（等等）个子元素。还值得注意的是，在与 `:nth-child()` 一起使用 `even` 或 `odd` 时，没有冒号前缀。

## 第 N 个元素（:eq(n)，:nth(n)）

具有索引值等于 n 的元素。

### 举例

1.  `$('li:eq(2)')`: 选择第三个 `<li>` 元素

1.  `$('p:nth(1)')`: 选择第二个 `<p>` 元素

### 描述

由于 JavaScript 的 `index` 是基于零的，`:eq(0)` 和 `:nth(0)` 选择第一个匹配的元素，`:eq(1)` 和 `:nth(1)` 选择第二个，依此类推。

## 大于 :gt(n)

所有索引大于 N 的元素。

### 举例

1.  `$('li:gt(1)')`: 选择所有被 `<li>` 元素匹配的元素，第二个之后的

1.  `$('a:gt(2)')`: 选择所有被 `<a>` 匹配的元素，第三个之后的

### 描述

由于 JavaScript 的 `index` 是基于零的，`:gt(1)` 选择从第三个开始的所有匹配的元素，`:gt(2)` 选择从第四个开始的所有匹配的元素，依此类推。考虑以下 HTML：

```js
<ul>
  <li id="first">index 0</li>
  <li id="second">index 1</li>
  <li id="third">index 2</li>
  <li id="fourth">index 3</li>
</ul>
```

`$('li:gt(1)')` 选择 `<li id="third">` 和 `<li id="fourth">`，因为它们的 `indexes` 大于 `1`。

`$(li:gt(2)')` 选择 `<li id="fourth">`，因为它的 `index` 大于 `2`。

## 小于 : lt(n)

所有索引小于 `N` 的元素。

### 举例

1.  `$('li:lt(2)')`: 选择所有被 `<li>` 元素匹配的元素，第三个之前的；换句话说，前两个 `<li>` 元素

1.  `$('p:lt(3)')`: 选择所有被 `<p>` 元素匹配的元素，第四个之前的；换句话说，前三个 `<p>` 元素

### 描述

由于 JavaScript 的 `index` 是基于零的，`:lt(2)` 选择前两个匹配的元素，或者选择第三个之前的所有匹配的元素；`:lt(3)` 选择前三个匹配的元素，或者选择第四个之前的所有匹配的元素；依此类推。

## 第一个 :first

元素的第一个实例。

### 举例

1.  `$('li:first')`: 选择第一个 `<li>` 元素

1.  `$('a:first')`: 选择第一个 `<a>` 元素

### 讨论

`:first` 伪类是 `:eq(0)` 的简写。它也可以写为 `:lt(1)`。

## 最后 :last

元素的最后一个实例。

### 举例

1.  `$('li:last)`: 选择最后一个 `<li>` 元素

1.  `$('#container .myclass:last)`: 选择具有 `class` 为 `myclass` 的最后一个元素，并且是具有 `id` 为 `container` 的元素的后代

### 描述

虽然`:first`具有等效选择器（`nth（0）和 eq（0）`），但`:last`伪类在仅选择匹配元素集中的最后一个元素方面是独特的。

## 父元素：:parent

所有是另一个元素的父元素的元素，包括文本。

### 示例

1.  `$(':parent')`: 选择所有是另一个元素的父元素的元素，包括文本

1.  `$(td:parent')`: 选择所有是另一个元素的父元素的`<td>`匹配的元素，包括文本

### 描述

W3C 建议`<p>`元素至少有一个子节点，即使该子节点只是文本（参见[`www.w3.org/TR/html401/struct/text.html#edef P`](http://www.w3.org/TR/html401/struct/text.html#edef)）。例如，另一方面，某些元素是空的（即没有子元素）：`<input>, <img>, <br>`和`<hr>`。

使用`:parent`（和`:empty`），一个重要的要注意的是子元素包括文本节点。

## 包含：:contains(text)

所有包含指定文本的元素。

### 示例

1.  `$('p:contains(nothing special)')`: 选择所有包含文本`nothing special`的`<p>`匹配的元素

1.  `$('li:contains(second)')`: 选择所有包含文本`second`的`<li>`匹配的元素

### 描述

匹配的文本可以出现在选择器元素中或该元素的任何后裔中。因此，示例 1 仍将选择以下段落：

```js
<p>This paragraph is <span>nothing <strong>special</strong>
                                                          </span></p>
```

与属性值选择器一样，`:contains()`括号内的文本可以写为裸体词或用引号括起来。另外，要被选择，文本必须匹配大小写。

## 可见：:visible

所有可见的元素。

### 示例

1.  `$('li:visible')`: 选择所有匹配`<li>`的可见元素

1.  `$('input:visible')`: 选择所有匹配`<input>`的可见元素

### 讨论

`:visible`选择器包括具有`block`或`inline`（或任何其他值而不是`none`）的显示和`visible`的可见性的元素。排除具有`type="hidden"`的表单元素。

需要注意的是，即使元素的父元素（或其他祖先）的显示是`none`，只要它们自身的显示是`block`或`inline`（或任何其他值而不是`none`），它们将被`:visible`伪类选择。因此，元素可能被隐藏但仍然被`:visible`选择。

考虑以下 HTML：

```js
<div id="parent" style="display:none">
  <div id="child" style="display:block">
  </div>
</div>
```

尽管由于其父元素的显示属性，`<div id="child">`在网页上看不见，但它仍然被`$('div:visible')`选择。

## 隐藏：:hidden

所有隐藏的元素

### 示例

1.  `$('li:hidden)`: 选择所有匹配`<li>`的隐藏元素

1.  `$('input:hidden)`: 选择所有匹配`<input>`的隐藏元素

#### 描述

`:hidden`选择器包括具有`display:none`或`visibility:hidden`的 CSS 声明的元素，以及带有`type="hidden"`的表单元素。

如果一个元素之所以从视图中隐藏，是因为其父级（或其他祖先）元素具有 `none` 的显示或 `hidden` 的可见性，当其自身的 `display` 属性不是 `none` 且其 `visibility` 属性不是 `hidden` 时，它将不会被 `:hidden` 选择。

考虑以下 HTML：

```js
<div id="parent" style="display:none">
  <div id="child" style="display:block">
  </div>
</div>
```

尽管子级 `<div>` 在网页上不可见是因为其父级 `<div>` 的显示属性，`$('div:hidden')` 只选择 `<div id="parent">`。


# 第三章：DOM 遍历方法

> 因为有火车驶入车站
> 
> 但它正朝着新的目的地前进
> 
> —Devo，
> 
> “对我来说没有关系”

除了 第二章 中描述的选择器表达式之外，jQuery 还具有各种 DOM 遍历方法，帮助我们在文档中选择元素。这些方法提供了很大的灵活性，甚至允许我们在单个链中对多个元素集进行操作，如下所示：

```js
$('div.section > p').addClass('lit').lt(1).addClass('profound');

```

有时，在选择器表达式和相应的 DOM 遍历方法之间的选择仅仅是品味的问题，但毫无疑问，结合在一起的表达式和方法集合构成了一个极为强大的工具集，可以获取我们想要的任何内容。

截至 jQuery 1.1 版本，DOM 遍历方法不会修改它们发送的 jQuery 对象。相反，会构造一个新的 jQuery 对象，其中包含对原始对象的引用。可以使用 `.end` 方法检索原始对象。

# jQuery 工厂函数

以下函数支撑整个 jQuery 库，因为它允许我们创建所有其他方法附加到的 jQuery 对象。

# $()

| 在 DOM 中创建匹配元素的新 jQuery 对象。

```js
$(selector[, context])
$(element)
$(elementArray)
$(object)
$(html)

```

|

## 参数（第一个版本）

+   选择器：包含选择器表达式的字符串

+   上下文（可选）：要在其中搜索的 DOM 树的部分

## 参数（第二个版本）

+   元素：要包装在 jQuery 对象中的 DOM 元素

## 参数（第三个版本）

+   elementArray：包含要包装在 jQuery 对象中的一组 DOM 元素的数组

## 参数（第四个版本）

+   object：要克隆的现有 jQuery 对象

## 参数（第五个版本）

+   html：包含描述要创建的新 DOM 元素的 HTML 片段的字符串

## 返回值

新构造的 jQuery 对象。

## 描述

在上述列出的第一种公式中，`$()` 会在 DOM 中搜索与提供的选择器匹配的任何元素，并创建一个新的 jQuery 对象，该对象引用这些元素：

```js
$('div.foo');

```

在 第二章 中，我们探讨了可在此字符串中使用的选择器表达式的范围。

## 选择器上下文

默认情况下，选择器会从文档根开始在 DOM 中执行搜索。但是，可以通过使用 `$()` 函数的可选第二个参数为搜索提供替代上下文。例如，如果在回调函数中我们希望搜索元素，则可以限制该搜索：

```js
$('div.foo').click(function() {
  $('span', this).addClass('bar');
});
```

由于我们将 span 选择器限制为 `this` 的上下文，因此只有点击的元素内的 span 才会获得额外的类。

选择器上下文对于 XML 文档也很有用，因为它们不属于默认的 DOM 树的一部分。例如，如果 AJAX 调用返回了一个名为 data 的 XML 结构，则我们可以在该结构内执行搜索：

```js
$('//foo/bar', data)

```

在内部，选择器上下文是使用 `.find` 方法实现的，因此 `$(selector, context)` 等效于 `$(context).find(selector)`。

### 注意

虽然 jQuery API 只指定 DOM 元素、DOM 元素数组和 jQuery 对象作为有效的上下文，但在实践中，选择器和 HTML 片段也可以在这里使用。

## 包装 DOM 元素

此函数的第二和第三种表达形式使我们能够使用其他方式已经找到的 DOM 元素或元素来创建一个 jQuery 对象。此功能的常见用法是对作为关键字`this`传递给回调函数的元素执行 jQuery 方法：

```js
$('div.foo').click(function() {
  $(this).slideUp();
});
```

该示例导致元素在单击时使用滑动动画隐藏。在调用 jQuery 方法之前，必须将元素包装在 jQuery 对象中，因为处理程序将接收关键字`this`中的单击项目作为裸 DOM 元素。

## 克隆 jQuery 对象

当一个 jQuery 对象被传递给`$()`作为参数时，将创建一个引用相同 DOM 元素的新 jQuery 对象。然后可以修改初始对象而不影响新对象。

## 创建新元素

如果将字符串作为参数传递给`$()`，jQuery 会检查字符串是否看起来像 HTML。如果不是，则将字符串解释为选择器表达式，如上所述。但是如果该字符串看起来像 HTML 片段，jQuery 会尝试根据 HTML 描述创建新的 DOM 元素。然后将创建并返回一个引用这些元素的 jQuery 对象。我们可以对此对象执行任何通常的 jQuery 方法：

```js
$('<p>My <em>new</em> paragraph</p>').appendTo('body');

```

实际创建元素的工作由浏览器的**innerHTML**机制处理。具体来说，jQuery 创建一个新的`<div>`元素，并将元素的 innerHTML 属性设置为传入的 HTML 片段。这意味着为了确保跨平台兼容性，片段必须是格式良好的。始终应将可以包含其他元素的标签与闭合标签配对：

```js
$('<a></a>');

```

不能包含元素的标签应快速关闭：

```js
$('<img />');

```

# 过滤方法

这些方法会从由 jQuery 对象匹配的集合中移除元素。

## .filter()

| 将匹配选择器或通过函数测试的元素集减少到那些匹配的元素。

```js
.filter(selector)
.filter(function)

```

|

### 参数（第一版本）

+   选择器：包含要与元素匹配的选择器表达式的字符串

### 参数（第二版本）

+   函数：用作集合中每个元素的测试的函数

### 返回值

新的 jQuery 对象。

### 描述

给定表示一组 DOM 元素的 jQuery 对象，`.filter`方法会根据匹配元素的子集构造一个新的 jQuery 对象。针对每个元素测试提供的选择器；所有匹配选择器的元素都将包括在结果中。

考虑一个带有简单列表的页面：

```js
<ul>
  <li>list item 1</li>
  <li>list item 2</li>
  <li>list item 3</li>
  <li>list item 4</li>
  <li>list item 5</li>
  <li>list item 6</li>
</ul>
```

我们可以将此方法应用于列表项集：

```js
$('li').filter(':even')

```

此调用的结果是一个包装项`1, 3`和`5`的 jQuery 对象，因为它们匹配选择器（请记住，:even 和:odd 使用基于 0 的索引）。

### 使用过滤函数

此方法的第二种形式允许我们针对函数而不是选择器来过滤元素。假设我们有一个更复杂的 HTML 片段：

```js
<ul>
  <li><strong>list</strong> item 1 - one strong</li>
  <li><strong>list</strong> item <strong>2</strong> - two <span>strongs</span></li>
  <li>list item 3</li>
  <li>list item 4</li>
  <li>list item 5</li>
  <li>list item 6</li>
</ul>
```

我们可以选择列表项，然后根据它们的内容进行过滤：

```js
$('li').filter(function(index) {
  return $("strong", this).length == 1;
})
```

这个表达式的结果将只是第一个列表项，因为它只包含一个 `<strong>` 标签。在过滤函数中，`this`依次引用每个 DOM 元素。传递给函数的参数告诉我们该 DOM 元素在由 jQuery 对象匹配的集合中的索引。

我们还可以利用通过函数传递的`index`：

```js
$('li').filter(function(index) {
  return index % 3 == 2;
})
```

这个表达式的结果将是第三和第六个列表项，因为它使用模运算符（%）来选择每个索引值除以 3 余数为 2 的项。

## .not()

| 从匹配元素的集合中移除元素。

```js
.not(selector) 
.not(elements) 

```

|

### 参数（第一个版本）

+   selector: 包含要匹配元素的选择器表达式的字符串

### 参数（第二个版本）

+   elements: 一个或多个要从匹配集合中删除的 DOM 元素

### 返回值

新的 jQuery 对象。

### 描述

给定一个表示一组 DOM 元素的 jQuery 对象，`.not` 方法会从匹配元素的子集构造一个新的 jQuery 对象。提供的选择器会被测试以匹配每个元素；不匹配选择器的元素将包含在结果中。

考虑一个简单列表的页面：

```js
<ul>
  <li>list item 1</li>
  <li>list item 2</li>
  <li>list item 3</li>
  <li>list item 4</li>
  <li>list item 5</li>
</ul>
```

我们可以将此方法应用于列表项集合：

```js
$('li').not(':even')

```

这个调用的结果是一个包含项`2`和`4`的 jQuery 对象，因为它们不匹配选择器（请回忆一下，:even 和 :odd 使用的是基于 0 的索引）。

### 移除特定元素

`.not` 方法的第二个版本允许我们从匹配集合中移除元素，假设我们以其他方式找到了这些元素。例如，假设我们的列表中的一个项目有一个标识符：

```js
<ul>
  <li>list item 1</li>
  <li>list item 2</li>
  <li id="notli">list item 3</li>
  <li>list item 4</li>
  <li>list item 5</li>
</ul>
```

我们可以使用原生 JavaScript 的 `getElementById` 函数获取第三个列表项，然后从 jQuery 对象中移除它：

```js
$('li').not(document.getElementById('notli'))

```

此表达式产生一个匹配项 `1, 2, 4` 和 `5` 的 jQuery 对象。我们本可以用更简单的 jQuery 表达式来完成同样的事情，但是这种技术在其他库提供对普通 DOM 节点的引用时可能会有用。

## .contains()

| 将匹配元素集合减少到包含指定文本的元素。

```js
.contains(text)

```

|

### 参数

+   text: 要搜索的文本字符串

### 返回值

新的 jQuery 对象。

### 描述

给定一个表示一组 DOM 元素的 jQuery 对象，`.contains` 方法会从匹配元素的子集构造一个新的 jQuery 对象。提供的文本会在每个元素中进行搜索；包含文本的所有元素（即使在后代元素中）都将包含在结果中。

考虑一个简单列表的页面：

```js
<ul>
  <li>list item 1</li>
  <li>list <strong>item</strong> 2</li>
  <li>list item 3</li>
  <li>list item 4</li>
  <li>list item 5</li>
</ul>
```

我们可以将此方法应用于列表项集合：

```js
$('li').contains('item 2')

```

此调用的结果是包含指定文本的`item 2`的 jQuery 对象。使用 jQuery 的`.text`方法执行搜索，因此搜索文本可以位于匹配元素或其任何后代的文本字符串的连接中的任何位置。

## .eq()

| 将匹配元素的集合减少到指定索引处的一个元素。

```js
.eq(index)

```

|

### 参数

+   index：指示元素的*从 0 开始计数*的位置的整数

### 返回值

新的 jQuery 对象。

### 描述

给定表示一组 DOM 元素的 jQuery 对象，`.eq`方法从匹配元素中构造一个新的 jQuery 对象。提供的索引标识集合中此元素的位置。

考虑一个包含简单列表的页面：

```js
<ul>
  <li>list item 1</li>
  <li>list item 2</li>
  <li>list item 3</li>
  <li>list item 4</li>
  <li>list item 5</li>
</ul>
```

我们可以将此方法应用于列表项的集合：

```js
$('li').eq(2)

```

此调用的结果是包含`item 3`的 jQuery 对象。注意，提供的索引是*从 0 开始计数*的，并且是指 jQuery 对象内元素的位置，*而不是*DOM 树内的位置。

## .lt()

| 将匹配元素的集合减少到指定索引之前的元素。

```js
.lt(index)

```

|

### 参数

+   index：指示选择元素之前的*从 0 开始计数*的位置的整数

### 返回值

新的 jQuery 对象。

### 描述

给定表示一组 DOM 元素的 jQuery 对象，`.lt`方法从匹配元素的子集中构造一个新的 jQuery 对象。提供的`index`标识集合中一个元素的位置；此元素之前的所有元素都将包含在结果中。

考虑一个包含简单列表的页面：

```js
<ul>
  <li>list item 1</li>
  <li>list item 2</li>
  <li>list item 3</li>
  <li>list item 4</li>
  <li>list item 5</li>
</ul>
```

我们可以将此方法应用于列表项的集合：

```js
$('li').lt(2)

```

此调用的结果是包含项目`1`和`2`的 jQuery 对象。注意，提供的索引是*从 0 开始计数*的，并且是指 jQuery 对象内的元素位置，*而不是*DOM 树内的位置。

## .gt()

| 将匹配元素的集合减少到指定索引之后的元素。

```js
.gt(index)

```

|

### 参数

+   index：指示选择元素之后的*从 0 开始计数*的位置的整数

### 返回值

新的 jQuery 对象。

### 描述

给定表示一组 DOM 元素的 jQuery 对象，`.gt`方法从匹配元素的子集中构造一个新的 jQuery 对象。提供的`index`标识集合中一个元素的位置；此元素之后的所有元素都将包含在结果中。

考虑一个包含简单列表的页面：

```js
<ul>
  <li>list item 1</li>
  <li>list item 2</li>
  <li>list item 3</li>
  <li>list item 4</li>
  <li>list item 5</li>
</ul>
```

我们可以将此方法应用于列表项的集合：

```js
$('li').gt(2)

```

此调用的结果是包含项目 4 和 5 的 jQuery 对象。注意，提供的索引是*从 0 开始计数*的，并且是指 jQuery 对象内的元素位置，*而不是*DOM 树内的位置。

# 树遍历方法

这些方法利用 DOM 树的结构来定位一组新的元素。

## .find()

| 获取当前匹配的每个元素的后代，该后代经过选择器筛选。

```js
.find(selector)

```

|

### 参数

+   selector：包含要匹配元素的选择器表达式的字符串

### 返回值

新的 jQuery 对象。

### 描述

给定一个代表一组 DOM 元素的 jQuery 对象，`.find` 方法允许我们在 DOM 树的后代中搜索这些元素，并从匹配的元素构建一个新的 jQuery 对象。`.find` 和 `.children` 方法类似，不同之处在于后者只向下遍历 DOM 树的一级。

该方法接受与我们可以传递给 `$()` 函数的相同类型的选择器表达式。将通过测试它们是否与此选择器匹配来过滤元素。

考虑一个带有基本嵌套列表的页面：

```js
<ul class="level-1">
  <li class="item-i">I</li>
  <li class="item-ii">II
    <ul class="level-2">
      <li class="item-a">A</li>
      <li class="item-b">B
        <ul class="level-3">
          <li class="item-1">1</li>
          <li class="item-2">2</li>
          <li class="item-3">3</li>
        </ul>
      </li>
      <li class="item-c">C</li>
    </ul>
  </li>
  <li class="item-iii">III</li>
</ul>
```

如果我们从项目 II 开始，我们可以找到其中的列表项：

```js
$('li.item-ii').find('li')

```

这次调用的结果是一个包含项 `A, B, 1, 2, 3` 和 `C` 的 jQuery 对象。即使项目 `II` 匹配了选择器表达式，它也不会被包含在结果中；只有后代被视为匹配项的候选者。

如 *jQuery 工厂函数* 部分所讨论的，选择器上下文是使用 `.find` 方法实现的；因此，`$('li.item-ii').find('li')` 等效于 `$('li', 'li.item-ii')`。

### 注意

与其它树遍历方法不同，在调用 `.find()` 时需要选择器表达式。如果我们需要检索所有后代元素，可以传递选择器 * 来完成此操作。

## .children()

| 获取匹配元素集合中每个元素的子元素，可选择性地通过选择器进行过滤。

```js
.children([selector])

```

|

### 参数

+   选择器（可选）：包含一个选择器表达式以匹配元素的字符串

### 返回值

新的 jQuery 对象。

### 描述

给定一个代表一组 DOM 元素的 jQuery 对象，`.children` 方法允许我们在 DOM 树中搜索这些元素的直接子元素，并从匹配的元素构建一个新的 jQuery 对象。`.find` 和 `.children` 方法类似，不同之处在于后者只向下遍历 DOM 树的一级。

该方法可选择地接受与我们可以传递给 `$()` 函数的相同类型的选择器表达式。如果提供了选择器，则将通过测试它们是否与选择器匹配来过滤元素。

考虑一个带有基本嵌套列表的页面：

```js
<ul class="level-1">
  <li class="item-i">I</li>
  <li class="item-ii">II
    <ul class="level-2">
      <li class="item-a">A</li>
      <li class="item-b">B
        <ul class="level-3">
          <li class="item-1">1</li>
          <li class="item-2">2</li>
          <li class="item-3">3</li>
        </ul>
      </li>
      <li class="item-c">C</li>
    </ul>
  </li>
  <li class="item-iii">III</li>
</ul>
```

如果我们从第二级列表开始，我们可以找到它的子元素：

```js
$('ul.level-2').children()

```

这次调用的结果是一个包含项 `A, B` 和 `C` 的 jQuery 对象。由于我们没有提供选择器表达式，所有子元素都是对象的一部分。如果我们提供了一个，只有这三个中的匹配项将被包含在内。

## .parents()

| 获取匹配元素集合中每个元素的祖先元素，可选择性地通过选择器进行过滤。

```js
.parents([selector])

```

|

### 参数

+   选择器（可选）：包含一个选择器表达式以匹配元素的字符串

### 返回值

新的 jQuery 对象。

### 描述

给定表示一组 DOM 元素的 jQuery 对象，`.parents` 方法允许我们在 DOM 树中搜索这些元素的祖先，并从匹配的元素构造一个新的 jQuery 对象。`.parents()` 和 `.parent()` 方法是类似的，不同之处在于后者只在 DOM 树中向上移动一个级别。

方法可选地接受与我们可以传递给 `$()` 函数的相同类型的选择器表达式。如果提供了选择器，则将通过测试它们是否匹配选择器来过滤元素。

考虑一个上面有一个基本嵌套列表的页面：

```js
<ul class="level-1">
  <li class="item-i">I</li>
  <li class="item-ii">II
    <ul class="level-2">
      <li class="item-a">A</li>
      <li class="item-b">B
        <ul class="level-3">
          <li class="item-1">1</li>
          <li class="item-2">2</li>
          <li class="item-3">3</li>
        </ul>
      </li>
      <li class="item-c">C</li>
    </ul>
  </li>
  <li class="item-iii">III</li>
</ul>
```

如果我们从项目 `A` 开始，我们可以找到它的祖先：

```js
$('li.item-a').parents()

```

这个调用的结果是一个包装着 `level-2` 列表、`item ii` 和 `level-1` 列表的 jQuery 对象（一直向上直到 `<html>` 元素的 DOM 树）。因为我们没有提供选择器表达式，所有祖先都是对象的一部分。如果我们提供了一个，只有这些匹配的项会被包含在其中。

## .parent()

| 获取当前匹配的每个元素的父级，可以选择使用选择器进行过滤。

```js
.parent([selector])

```

|

### 参数

+   选择器（可选）：包含要将元素与之匹配的选择器表达式的字符串。

### 返回值

新的 jQuery 对象。

### 描述

给定表示一组 DOM 元素的 jQuery 对象，`.parent` 方法允许我们在 DOM 树中搜索这些元素的父级，并从匹配的元素构造一个新的 jQuery 对象。`.parents` 和 `.parent` 方法是类似的，不同之处在于后者只在 DOM 树中向上移动一个级别。

方法可选地接受与我们可以传递给 `$()` 函数的相同类型的选择器表达式。如果提供了选择器，则将通过测试它们是否匹配选择器来过滤元素。

考虑一个上面有一个基本嵌套列表的页面：

```js
<ul class="level-1">
  <li class="item-i">I</li>
  <li class="item-ii">II
    <ul class="level-2">
      <li class="item-a">A</li>
      <li class="item-b">B
        <ul class="level-3">
          <li class="item-1">1</li>
          <li class="item-2">2</li>
          <li class="item-3">3</li>
        </ul>
      </li>
      <li class="item-c">C</li>
    </ul>
  </li>
  <li class="item-iii">III</li>
</ul>
```

如果我们从项目 `A` 开始，我们可以找到它的父元素：

```js
$('li.item-a').parent()

```

这个调用的结果是一个包装着 `level-2` 列表的 jQuery 对象。因为我们没有提供选择器表达式，父元素明确包括在对象中。如果我们提供了一个，那么在包含之前会对元素进行匹配测试。

## .siblings()

| 获取匹配元素集合中每个元素的同级，可以选择使用选择器进行过滤。

```js
.siblings([selector])

```

|

### 参数

+   选择器（可选）：包含要将元素与之匹配的选择器表达式的字符串

### 返回值

新的 jQuery 对象。

### 描述

给定表示一组 DOM 元素的 jQuery 对象，`.siblings` 方法允许我们在 DOM 树中搜索这些元素的兄弟元素，并从匹配的元素构造一个新的 jQuery 对象。

方法可选地接受与我们可以传递给 `$()` 函数的相同类型的选择器表达式。如果提供了选择器，则将通过测试它们是否匹配选择器来过滤元素。

考虑一个上面有一个简单列表的页面：

```js
<ul>
   <li>list item 1</li>
   <li>list item 2</li>
   <li class="third-item">list item 3</li>
   <li>list item 4</li>
   <li>list item 5</li>
</ul>
```

如果我们从第三个项目开始，我们可以找到它的兄弟：

```js
$('li.third-item').siblings()

```

此调用的结果是一个包裹着`1, 2, 4`和`5`项的 jQuery 对象。因为我们没有提供选择器表达式，所以所有的兄弟元素都是对象的一部分。如果我们提供了一个选择器，那么这四个元素中的匹配项才会被包含。

在兄弟元素中不包括原始元素，这一点在我们希望找到 DOM 树特定级别的所有元素时很重要。

## .prev()

| 获取匹配元素集合中每个元素的紧邻前序兄弟元素，可选择性地通过选择器进行过滤。

```js
.prev([selector])

```

|

### 参数

+   selector（可选）: 包含用于匹配元素的选择器表达式的字符串

### 返回值

新的 jQuery 对象。

### 描述

给定一个代表一组 DOM 元素的 jQuery 对象，`.prev`方法允许我们在 DOM 树中搜索这些元素的前驱，并从匹配的元素构建一个新的 jQuery 对象。

此方法可选择性地接受与我们可以传递给`$()`函数的相同类型的选择器表达式。如果提供了选择器，则将通过测试它们是否与选择器匹配来对元素进行过滤。

考虑一个简单列表的页面：

```js
<ul>
   <li>list item 1</li>
   <li>list item 2</li>
   <li class="third-item">list item 3</li>
   <li>list item 4</li>
   <li>list item 5</li>
</ul>
```

如果我们从第三项开始，我们可以找到它之前的元素：

```js
$('li.third-item').prev()

```

此调用的结果是一个包裹着`item 2`的 jQuery 对象。因为我们没有提供选择器表达式，所以这个前序元素明确地被包含在对象中。如果我们提供了一个选择器，那么在包含之前会测试该元素是否匹配。

## .next()

| 获取匹配元素集合中每个元素的紧邻后续兄弟元素，可选择性地通过选择器进行过滤。

```js
.next([selector])

```

|

### 参数

+   selector（可选）: 包含用于匹配元素的选择器表达式的字符串

### 返回值

新的 jQuery 对象。

### 描述

给定一个代表一组 DOM 元素的 jQuery 对象，`.next`方法允许我们在 DOM 树中搜索这些元素的后继，并从匹配的元素构建一个新的 jQuery 对象。

此方法可选择性地接受与我们可以传递给`$()`函数的相同类型的选择器表达式。如果提供了选择器，则将通过测试它们是否与选择器匹配来对元素进行过滤。

考虑一个简单列表的页面：

```js
<ul>
   <li>list item 1</li>
   <li>list item 2</li>
   <li class="third-item">list item 3</li>
   <li>list item 4</li>
   <li>list item 5</li>
</ul>
```

如果我们从第三项开始，我们可以找到它之后的元素：

```js
$('li.third-item').next()

```

此调用的结果是一个包裹着`item 4`的 jQuery 对象。因为我们没有提供选择器表达式，所以这个后续元素明确地被包含在对象中。如果我们提供了一个选择器，那么在包含之前会测试该元素是否匹配。

# 杂项遍历方法

这些方法提供了在 jQuery 对象中操作匹配的 DOM 元素集合的其他机制。

## .add()

| 将元素添加到匹配元素集合中。

```js
.add(selector)
.add(elements)
.add(html)

```

|

### 参数（第一版本）

+   selector: 包含用于匹配额外元素的选择器表达式的字符串

### 参数（第二版本）

+   元素：要添加到匹配元素集的一个或多个元素

### 参数（第三个版本）

+   html：要添加到匹配元素集的 HTML 片段

### 返回值

新的 jQuery 对象。

### 描述

给定一个代表一组 DOM 元素的 jQuery 对象，`.add`方法从这些元素的并集和传递给该方法的元素构造一个新的 jQuery 对象。`.add`的参数几乎可以是`$()`接受的任何东西，包括一个 jQuery 选择器表达式、对 DOM 元素的引用或者一个 HTML 片段。

考虑一个页面，有一个简单的列表和一个随后的段落：

```js
<ul>
  <li>list item 1</li>
  <li>list item 2</li>
  <li>list item 3</li>
</ul>
<p>a paragraph</p>
```

我们可以通过使用选择器或对 DOM 元素本身的引用作为`.add`方法的参数来选择列表项，然后选择段落：

```js
$('li').add('p') or
$('li').add(document.getElementsByTagName('p')[0])

```

此调用的结果是一个包装了所有四个元素的 jQuery 对象。

使用 HTML 片段作为`.add`方法的参数（如第三个版本中所示），我们可以动态创建额外的元素，并将这些元素添加到匹配的元素集中。举个例子，假设我们想要将一个`foo`类添加到列表项、段落以及一个新创建的段落中：

```js
$('li').add('p').add('<p id="new">new paragraph</p>').addClass('foo')

```

尽管新的段落已经被创建并且其`foo`类已添加，但它仍然不会出现在页面上。为了将其放置在页面上，我们可以在链中添加一个插入方法。

关于插入方法的更多信息，请参阅第四章。

## .is()

| 检查当前匹配的元素集是否与选择器匹配，并在至少有一个元素匹配选择器时返回`true`。

```js
.is(selector)

```

|

### 参数

+   选择器：一个包含用于匹配元素的选择器表达式的字符串。

### 返回值

一个布尔值，指示元素是否与选择器匹配。

### 描述

与本章其他方法不同，`.is()`不会创建新的 jQuery 对象。相反，它允许我们在不修改 jQuery 对象的情况下测试其内容。这在回调函数中经常很有用，比如事件处理程序。

假设我们有一个列表，其中两个项目包含一个子元素：

```js
<ul>
  <li>list <strong>item 1</strong></li>
  <li><span>list item 2</span></li>
  <li>list item 3</li>
</ul>
```

我们可以将单击处理程序附加到`<ul>`元素上，然后限制代码只在单击列表项本身时触发，而不是其子元素之一时触发：

```js
$('ul').click(function(event) {
  if ($(event.target).is('li') ) {
    $(event.target).remove();
  }
});
```

现在，当用户在第一项中单击`list`这个词或者在第三项的任何位置单击时，被点击的列表项将会从文档中移除。然而，当用户在第一项中的`item 1`或者在第二项的任何位置单击时，不会发生任何事情，因为对于这些事件的目标分别是`<strong>`和`<span>`。

## .end()

| 结束当前链中最近的过滤操作，并将匹配的元素集返回到其先前的状态。

```js
.end()

```

|

### 参数

无。

### 返回值

前一个 jQuery 对象。

### 描述

本章中的大多数方法操作一个 jQuery 对象并产生一个新的对象，匹配不同的 DOM 元素集。当这种情况发生时，就好像一个新的元素集被推送到对象内部维护的堆栈上一样。每个连续的过滤方法都会将一个新的元素集推送到堆栈上。如果我们需要一个旧的元素集，可以使用 `.end()` 将集合从堆栈中弹出。

假设我们在页面上有几个简短的列表：

```js
<ul class="first">
   <li class="foo">list item 1</li>
   <li>list item 2</li>
   <li class="bar">list item 3</li>
</ul>
<ul class="second">
   <li class="foo">list item 1</li>
   <li>list item 2</li>
   <li class="bar">list item 3</li>
</ul>
```

`.end` 方法主要在利用 jQuery 的链接属性时很有用。当不使用链接时，通常可以通过变量名调用前一个对象，这样我们就不需要操作堆栈。但是，使用 `.end()`，我们可以将所有方法调用串在一起：

```js
$('ul.first').find('.foo').addClass('some-class').end() .find('.bar').addClass('another-class');

```

此链在第一个列表中搜索具有类 `foo` 的项目，并向其添加类 `some-class`。然后 `.end()` 将对象返回到调用 `.find()` 之前的状态，因此第二个 `.find()` 不仅在该列表的 `<li class="foo">` 中查找 `.bar`，而且在 `<ul class="first">` 中查找，然后将类 `another-class` 添加到匹配的元素上。结果是第一个列表的项目 `1` 和 `3` 添加了一个类，而第二个列表的项目没有添加任何类。

长长的 jQuery 链可以被视为一个结构化的代码块，其中过滤方法提供了嵌套块的开头，而 `.end` 方法则关闭它们：

```js
$('#example-traversing-end ul.first').find('.foo')
  .addClass('some-class')
    .end()
      .find('.bar')
        .addClass('another-class');
.end();
```

最后一个 `.end()` 是不必要的，因为我们随后立即丢弃了 jQuery 对象。但是，当代码以这种形式编写时，`.end()` 提供了视觉对称性和闭合性——至少在某些开发人员眼中，这样做可以使程序更易读。
