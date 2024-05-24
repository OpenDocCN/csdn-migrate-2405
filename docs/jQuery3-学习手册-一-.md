# jQuery3 学习手册（一）

> 原文：[`zh.annas-archive.org/md5/B3EDC852976B517A1E8ECB0D0B64863C`](https://zh.annas-archive.org/md5/B3EDC852976B517A1E8ECB0D0B64863C)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

我从 2007 年开始使用 jQuery，到现在仍在使用。当然，自那时以来发生了很多事情：新的 JavaScript 库，浏览器之间更一致的性能，以及对 JavaScript 本身的增强。10 年来唯一没有改变的事情是 jQuery 的表现力和简洁性。即使今天有很多新潮的东西，jQuery 仍然是快速高效完成工作的首选工具。

这本书有着悠久的历史，已经在第五版中保持完整。这本书之所以成功，是因为它直截了当，易于理解。我尽力保留了这本书效果良好的部分。我的目标是将学习 jQuery 现代化，适应当前的 Web 开发环境。

# 本书涵盖内容

第一章，*入门*，让你初步了解 jQuery JavaScript 库。本章首先描述了 jQuery 及其对你的作用。然后，它将指导你下载和设置库，以及编写你的第一个脚本。

第二章，*选择元素*，教你如何使用 jQuery 的选择器表达式和 DOM 遍历方法在页面上找到元素，无论它们在哪里。你将使用 jQuery 对各种页面元素应用样式，有时以纯 CSS 无法实现的方式。

第三章，*处理事件*，引导你了解 jQuery 的事件处理机制，以在浏览器事件发生时触发行为。你将看到 jQuery 如何轻松地不显眼地将事件附加到元素，甚至在页面加载完成之前。此外，你将获得更深入的主题概述，如事件冒泡、委托和命名空间。

第四章，*样式与动画*，向你介绍了 jQuery 的动画技术以及如何使用令人愉悦且有用的效果隐藏、显示和移动页面元素。

第五章，*操作 DOM*，教你如何随时更改你的页面。本章还将教你如何改变 HTML 文档的结构，并在其内容上添加内容。

第六章，*使用 Ajax 发送数据*，指导你通过许多方式使用 jQuery 轻松访问服务器端功能，而不必借助笨拙的页面刷新。掌握了库的基本组件，你将准备好探索库如何扩展以适应你的需求。

第七章，*使用插件*，向你展示如何查找、安装和使用插件，包括强大的 jQuery UI 和 jQuery Mobile 插件库。

第八章，*开发插件*，教你如何充分利用 jQuery 令人印象深刻的扩展能力从零开始开发自己的插件。您将创建自己的实用函数，添加 jQuery 对象方法，并探索 jQuery UI 组件工厂。接下来，您将再次浏览 jQuery 的基本组成部分，学习更高级的技术。

第九章，*高级选择器和遍历*，完善您对选择器和遍历的知识，获得优化选择器以提高性能、操纵 DOM 元素堆栈以及编写扩展选择和遍历功能的插件的能力。

第十章，*高级事件*，深入探讨诸如委托和节流等技术，这些技术可以大大提高事件处理的性能。您还将创建自定义和特殊事件，为 jQuery 库添加更多功能。

第十一章，*高级效果*，向您展示如何微调 jQuery 的视觉效果，通过制作自定义缓动函数和对每个动画步骤做出反应来实现。您将获得操作动画的能力，以及使用自定义队列安排操作的能力。

第十二章，*高级 DOM 操作*，为您提供了更多练习，通过诸如向元素附加任意数据的技术来修改 DOM。您还将学习如何扩展 jQuery 处理元素 CSS 属性的方式。

第十三章，*高级 Ajax*，帮助您更好地了解 Ajax 交易，包括用于处理稍后可能可用的数据的 jQuery deferred 对象系统。

附录 A，*使用 QUnit 进行 JavaScript 测试*，教你关于 QUnit 库，该库用于对 JavaScript 程序进行单元测试。这个库将成为您开发和维护高度复杂的网络应用程序工具包的重要补充。

附录 B，*快速参考*，提供了整个 jQuery 库的概览，包括其每一个方法和选择器表达式。其易于扫描的格式非常适合在您知道要做什么，但不确定正确的方法名称或选择器时使用。

# 本书所需内容

为了运行本书示例中演示的示例代码，您需要一款现代的网络浏览器，如 Google Chrome、Mozilla Firefox、Apple Safari 或 Microsoft Edge。

要尝试示例和完成章节结尾的练习，您还需要以下内容：

+   基本文本编辑器

+   浏览器的 Web 开发工具，例如 Chrome 开发者工具或 Firebug（如 第一章 *入门* 中所述的 *使用开发工具* 部分）

+   每一章的完整代码包，其中包括 jQuery 库的副本（见 *下载示例代码* 部分）

此外，要运行 第六章 *使用 Ajax 发送数据* 及其后面的一些 Ajax 示例，您将需要安装 Node.js。

# 这本书适合谁

这本书非常适合客户端 JavaScript 开发人员。您不需要有任何 jQuery 的先前经验，尽管需要基本的 JavaScript 编程知识。

# 约定

在本书中，您会发现一些用于区分不同类型信息的文本样式。以下是这些样式的一些示例及其含义的解释。

文本中的代码字词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄以如下方式显示："当我们指示 jQuery 查找所有具有 `collapsible` 类的元素并隐藏它们时，无需遍历每个返回的元素。"

代码块设置如下：

```js
body { 
  background-color: #fff; 
  color: #000; 
  font-family: Helvetica, Arial, sans-serif; 
}
h1, h2, h3 { 
  margin-bottom: .2em; 
}
.poem { 
  margin: 0 2em; 
} 
.highlight { 
  background-color: #ccc; 
  border: 1px solid #888; 
  font-style: italic; 
  margin: 0.5em 0; 
  padding: 0.5em; 
} 

```

**新术语** 和 **重要单词** 以粗体显示。您在屏幕上看到的词，例如菜单或对话框中的词，会以这种方式出现在文本中："Sources 标签允许我们查看页面上加载的所有脚本的内容。"

警告或重要提示会以此类框的形式出现。

提示和技巧以这种方式出现。


# 第一章：入门

今天的**万维网**（**WWW**）是一个动态的环境，其用户对站点的样式和功能设置了很高的标准。为了构建有趣和交互式的站点，开发人员正在转向 JavaScript 库，如 jQuery，来自动执行常见任务并简化复杂任务。jQuery 库之所以成为热门选择的原因之一是其能够帮助完成各种任务。

由于 jQuery 执行了许多不同的功能，因此很难知道从哪里开始。然而，该库的设计具有一致性和对称性；许多概念都借鉴自**HTML**和**层叠样式表**（**CSS**）的结构。这种设计适合对编程经验较少的设计师快速入门，因为许多人对这些技术的了解比对 JavaScript 更多。事实上，在本章中，我们将只用三行代码编写一个功能齐全的 jQuery 程序。另一方面，有经验的程序员也会欣赏到这种概念上的一致性。

在本章中，我们将涵盖：

+   jQuery 的主要特性

+   设置 jQuery 代码环境

+   一个简单的工作中的 jQuery 脚本示例

+   选择 jQuery 而不是普通 JavaScript 的原因

+   常见的 JavaScript 开发工具

# jQuery 做了什么？

jQuery 库为常见的网页脚本提供了一个通用的抽象层，因此在几乎每种脚本情况下都很有用。它的可扩展性意味着我们永远无法在一本书中涵盖所有可能的用途和功能，因为插件不断被开发用来添加新的功能。然而，核心特性却能帮助我们完成以下任务：

+   **访问文档中的元素**：没有 JavaScript 库，Web 开发人员通常需要编写许多代码行来遍历**文档对象模型**（**DOM**）树并定位 HTML 文档结构的特定部分。有了 jQuery，开发人员可以使用强大而高效的选择器机制，轻松地检索需要检查或操作的文档的确切部分。

```js
$('div.content').find('p'); 

```

+   **修改网页的外观**：CSS 提供了一种影响文档呈现方式的强大方法，但当不是所有的 web 浏览器都支持相同的标准时，它会显得不足。使用 jQuery，开发人员可以弥补这一差距，依赖于所有浏览器的相同标准支持。此外，jQuery 可以在页面呈现后改变应用于文档部分的类别或个别样式属性。

```js
$('ul > li:first').addClass('active'); 

```

+   **修改文档的内容**：jQuery 不仅仅局限于表面上的改变，它可以用几个按键来修改文档本身的内容。文本可以被更改，图像可以被插入或交换，列表可以被重新排序，甚至可以用单个易于使用的**应用程序编程接口**（**API**）重写和扩展 HTML 的整个结构。

```js
$('#container').append('<a href="more.html">more</a>'); 

```

+   **响应用户的交互**: 即使是最复杂和强大的行为，如果我们无法控制它们发生的时间，也是没有用的。jQuery 库提供了一种优雅的方式来拦截各种事件，比如用户点击链接，而不需要用事件处理程序来混杂 HTML 代码本身。

```js
$('button.show-details').click(() => { 
  $('div.details').show(); 
});

```

+   **动画文档中正在进行的更改**: 要有效地实现这样的交互行为，设计者还必须为用户提供视觉反馈。jQuery 库通过提供一系列效果，如淡入淡出和擦除，以及用于制作新效果的工具包，来促进这一点。

```js
$('div.details').slideDown(); 

```

+   **在不刷新页面的情况下从服务器检索信息**: 这种模式被称为 **Ajax**，最初代表 **异步 JavaScript 和 XML**，但后来已经成为了一套更大的用于客户端和服务器之间通信的技术集合。jQuery 库从这个过程中移除了特定于浏览器的复杂性，使开发者可以专注于服务器端功能。

```js
$('div.details').load('more.html #content');

```

# 为什么 jQuery 的效果好？

随着对动态 HTML 的兴趣重新涌现，JavaScript 框架也在不断涌现。有些是专门的，只关注先前提到的一两个任务。其他尝试列出每一个可能的行为和动画，并提供预打包的。为了保持先前列出的广泛功能范围，同时保持相对紧凑，jQuery 采用了几种策略：

+   **利用 CSS 知识**: 通过基于 CSS 选择器定位页面元素的机制，jQuery 继承了一种简洁而易读的表达文档结构的方式。由于专业网页开发的先决条件是对 CSS 语法的了解，因此 jQuery 库成为了设计师想要为其页面添加行为的入口点。

+   **支持扩展**: 为了避免“功能蔓延”，jQuery 将特殊用例委托给插件。创建新插件的方法简单而且有文档说明，这推动了各种富有创意和有用的模块的开发。即使基本 jQuery 下载包中的大多数功能都是通过插件架构内部实现的，如果需要，也可以删除，从而获得更小的库。

+   **抽象出浏览器的怪癖**: 网页开发的一个不幸现实是，每个浏览器都有自己的一套与发布标准不一致的特性。任何一个网页应用的一个重要部分都可能被归类为在每个平台上以不同方式处理功能。虽然不断发展的浏览器环境使得对于某些高级功能来说，无法实现完全与浏览器无关的代码库成为可能，但 jQuery 添加了一个抽象层，规范了常见任务，减少了代码量的同时极大地简化了它。

+   **始终与集合一起工作**：当我们指示 jQuery 查找所有具有 `collapsible` 类的元素并隐藏它们时，没有必要遍历每个返回的元素。相反，像 `.hide()` 这样的方法被设计为自动在对象集合上工作，而不是在单个对象上工作。这种技术称为*隐式迭代*，意味着许多循环结构变得不再必要，大大减少了代码量。

+   **允许一行中进行多个操作**：为了避免过多使用临时变量或者重复浪费，jQuery 使用一种被称为*链式调用*的编程模式来执行其大多数方法。这意味着对对象的大多数操作的结果都是对象本身，准备好接受下一个操作。

这些策略使 jQuery 包的文件大小保持较小，同时为我们的自定义代码提供了保持紧凑的技巧，以及使用该库。

这个库的优雅部分是由设计部分和由项目周围蓬勃发展的活跃社区所推动的进化过程造成的。jQuery 的用户聚集在一起讨论的不仅是插件的开发，还包括对核心库的增强。用户和开发人员还协助不断改进官方项目文档，这些文档可以在 [`api.jquery.com`](http://api.jquery.com) 找到。

尽管构建这样一个灵活而强大的系统需要付出巨大的努力，但最终产品却是供所有人免费使用的。这个开源项目在 MIT 许可证下授权，允许在任何网站上免费使用 jQuery，并促进其在专有软件中的使用。如果一个项目需要，开发者可以重新将 jQuery 授权为 GNU 公共许可证，以便包含在其他 GNU 许可的开源项目中。

# jQuery 3 有什么新特性？

与 jQuery 2 引入的变化相比，jQuery 3 引入的变化相当微妙。大多数变化都在幕后进行。让我们简要地看一下一些变化以及它们对现有 jQuery 项目的影响。您可以在阅读本书的同时查看细粒度的详细信息（[`jquery.com/upgrade-guide/3.0`](https://jquery.com/upgrade-guide/3.0)）。

# 浏览器支持

jQuery 3 中浏览器支持的最大变化是 Internet Explorer。不得不支持此浏览器的旧版本是任何网页开发人员的噩梦。jQuery 3 通过仅支持 IE9+ 迈出了重要的一步。其他浏览器的支持政策是当前版本和上一个版本。

Internet Explorer 的时代已经屈指可数。微软发布了 IE 的继任者 Edge。这个浏览器是完全独立于 IE 的项目，不会受到一直困扰 IE 的问题的影响。此外，最近版本的 Microsoft Windows 实际上推动 Edge 成为默认浏览器，并且更新是定期且可预测的。再见了，IE，真是一去不复返。

# 延迟对象

`Deferred` 对象在 jQuery 1.5 中引入，作为更好地管理异步行为的手段。它们有点像 ES2015 的 promises，但不同之处足以使它们不能互换。现在，随着 ES2015 版本的 JavaScript 在现代浏览器中变得普遍，`Deferred` 对象与原生 `Promise` 对象完全兼容。这意味着旧的 `Deferred` 实现发生了相当大的变化。

# 异步文档准备

起初，文档准备好的回调函数被异步执行的想法可能看起来有些违反直觉。在 jQuery 3 中之所以会这样，有几个原因。首先，`$(() => {})` 表达式返回一个 `Deferred` 实例，这些现在的行为类似于原生 Promise。第二个原因是存在一个 `jQuery.ready` promise，在文档准备好时解析。正如你在本书后面将看到的，你可以在 DOM 准备好渲染之前使用此 promise 以及其他 promise 来执行其他异步任务。

# 其他所有内容

在 jQuery 3 中引入了许多其他 API 的破坏性更改，我们在这里不会详细讨论。我之前提到的升级指南详细介绍了每个更改以及如何处理它们。然而，当我们在本书中逐步进行时，我会指出 jQuery 3 中的新功能或不同之处。

# 制作我们的第一个由 jQuery 驱动的网页

现在我们已经介绍了使用 jQuery 提供的一系列功能，我们可以看看如何将库投入实际运用。要开始，我们需要下载 jQuery 的副本。

# 下载 jQuery

无需安装。要使用 jQuery，我们只需要一个公开可用的文件副本，无论该副本是在外部站点还是我们自己的站点上。由于 JavaScript 是一种解释性语言，因此无需担心编译或构建阶段。每当我们需要一个页面具有可用的 jQuery，我们只需在 HTML 文档中的 `<script>` 元素中引用文件的位置即可。

官方 jQuery 网站 ([`jquery.com/`](http://jquery.com/)) 总是具有最新的稳定版本的库，可以直接从网站的首页下载。任何时候可能有几个版本的 jQuery 可用；对于我们作为站点开发人员而言，最合适的版本将是库的最新未压缩版本。在生产环境中，可以用压缩版本替换此版本。

随着 jQuery 的普及，公司已经通过其 **内容交付** **网络**（**CDN**）免费提供文件。尤其是 Google ([`developers.google.com/speed/libraries/devguide`](https://developers.google.com/speed/libraries/devguide))、Microsoft ([`www.asp.net/ajaxlibrary/cdn.ashx`](http://www.asp.net/ajaxlibrary/cdn.ashx)) 和 jQuery 项目本身 ([`code.jquery.com`](http://code.jquery.com)) 在全球范围内分布了强大、低延迟的服务器上提供该文件，以便用户快速下载，而不管用户位于何处。尽管由 CDN 托管的 jQuery 副本具有由于服务器分发和缓存而带来的速度优势，但在开发过程中使用本地副本可能更加方便。在本书中，我们将使用存储在我们自己系统上的文件副本，这样无论我们是否连接到互联网，都可以运行我们的代码。

为了避免意外错误，始终使用特定版本的 jQuery。例如，3.1.1。一些 CDN 允许您链接到库的最新版本。同样，如果您使用 `npm` 安装 jQuery，请始终确保您的 `package.json` 需要特定版本。

# 在 HTML 文档中设置 jQuery

大多数 jQuery 使用示例都由三部分组成：HTML 文档、用于样式的 CSS 文件，以及用于操作的 JavaScript 文件。对于我们的第一个示例，我们将使用一个包含书摘的页面，其中有许多类应用于其部分。此页面包括对 jQuery 库的最新版本的引用，我们已经下载并将其重命名为 `jquery.js`，并放置在我们的本地项目目录中：

```js
<!DOCTYPE html> 

<html lang="en"> 
  <head> 
    <meta charset="utf-8"> 
    <title>Through the Looking-Glass</title> 

    <link rel="stylesheet" href="01.css"> 

    <script src="img/jquery.js"></script> 
    <script src="img/01.js"></script> 
  </head> 

  <body>   
    <h1>Through the Looking-Glass</h1> 
    <div class="author">by Lewis Carroll</div> 

    <div class="chapter" id="chapter-1"> 
      <h2 class="chapter-title">1\. Looking-Glass House</h2> 
      <p>There was a book lying near Alice on the table, 
        and while she sat watching the White King (for she 
        was still a little anxious about him, and had the 
        ink all ready to throw over him, in case he fainted 
        again), she turned over the leaves, to find some 
        part that she could read, <span class="spoken"> 
        "&mdash;for it's all in some language I don't know," 
        </span> she said to herself.</p> 
      <p>It was like this.</p> 
      <div class="poem"> 
        <h3 class="poem-title">YKCOWREBBAJ</h3> 
        <div class="poem-stanza"> 
          <div>sevot yhtils eht dna ,gillirb sawT'</div> 
          <div>;ebaw eht ni elbmig dna eryg diD</div> 
          <div>,sevogorob eht erew ysmim llA</div> 
          <div>.ebargtuo shtar emom eht dnA</div> 
        </div> 
      </div> 
      <p>She puzzled over this for some time, but at last 
        a bright thought struck her. <span class="spoken"> 
        "Why, it's a Looking-glass book, of course! And if 
        I hold it up to a glass, the words will all go the 
        right way again."</span></p> 
      <p>This was the poem that Alice read.</p> 
      <div class="poem"> 
        <h3 class="poem-title">JABBERWOCKY</h3> 
        <div class="poem-stanza"> 
          <div>'Twas brillig, and the slithy toves</div> 
          <div>Did gyre and gimble in the wabe;</div> 
          <div>All mimsy were the borogoves,</div> 
          <div>And the mome raths outgrabe.</div> 
        </div> 
      </div> 
    </div> 
  </body> 
</html> 

```

在普通的 HTML 前导部分之后，加载样式表。对于本示例，我们将使用一个简单的样式表：

```js
body { 
  background-color: #fff; 
  color: #000; 
  font-family: Helvetica, Arial, sans-serif; 
}
h1, h2, h3 { 
  margin-bottom: .2em; 
}
.poem { 
  margin: 0 2em; 
} 
.highlight { 
  background-color: #ccc; 
  border: 1px solid #888; 
  font-style: italic; 
  margin: 0.5em 0; 
  padding: 0.5em; 
} 

```

获取示例代码

您可以从以下 GitHub 存储库访问示例代码：

[`github.com/PacktPublishing/Learning-jQuery-3`](https://github.com/PacktPublishing/Learning-jQuery-3)。

在引用样式表之后，包含 JavaScript 文件。重要的是，jQuery 库的 `script` 标签应放在我们自定义脚本的标签之前；否则，当我们的代码尝试引用它时，jQuery 框架将不可用。

在本书的其余部分，将仅打印 HTML 和 CSS 文件的相关部分。完整的文件可从该书的伴随代码示例中获取：[`github.com/PacktPublishing/Learning-jQuery-3`](https://github.com/PacktPublishing/Learning-jQuery-3)。

现在，我们的页面看起来像这样：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/image_01_001-1.jpg)

我们将使用 jQuery 为诗文文字应用新样式。

此示例旨在演示 jQuery 的简单用法。在现实世界的情况下，此类样式可以纯粹通过 CSS 执行。

# 添加我们的 jQuery 代码

我们的自定义代码将放在第二个目前为空的 JavaScript 文件中，我们通过`<script src="img/01.js"></script>`从 HTML 中包含。对于这个示例，我们只需要三行代码：

```js
$(() => {
  $('div.poem-stanza').addClass('highlight')
});

```

在本书中，我将使用更新的 ES2015 **箭头函数**语法来编写大多数回调函数。唯一的原因是它比在各处使用`function`关键字更简洁。然而，如果你更喜欢`function() {}`语法，那么请尽管使用它。

现在让我们逐步分析这个脚本，看看它是如何工作的。

# 查找诗歌文本

jQuery 中的基本操作是选择文档的一部分。这通过`$()`函数完成。通常，它以字符串作为参数，该参数可以包含任何 CSS 选择器表达式。在本例中，我们希望找到文档中所有应用了`poem-stanza`类的`<div>`元素，因此选择器非常简单。但是，我们将在本书的过程中涵盖更多复杂的选项。我们将在第二章中介绍许多定位文档部分的方法，*选择元素*。

当调用`$()`函数时，它会返回一个新的 jQuery 对象实例，这是我们将要使用的基本构建块。该对象封装了零个或多个 DOM 元素，并允许我们以多种不同的方式与它们交互。在这种情况下，我们希望修改页面的这些部分的外观，并通过更改应用于诗歌文本的类来实现这一目标。

# 注入新类

`.addClass()`方法，像大多数 jQuery 方法一样，其名称具有自解释性；它将一个 CSS 类应用于我们选择的页面部分。它的唯一参数是要添加的类的名称。这个方法及其相对应的`.removeClass()`方法将允许我们轻松地观察到 jQuery 在我们探索可用的不同选择器表达式时的作用。目前，我们的示例仅添加了`highlight`类，我们的样式表将其定义为具有灰色背景和边框的斜体文本。

注意，不需要迭代即可将类添加到所有诗歌的段落中。正如我们讨论的那样，jQuery 在诸如`.addClass()`之类的方法内部使用隐式迭代，因此只需一个函数调用即可更改文档中的所有选定部分。

# 执行代码

综合起来，`$()`和`.addClass()`足以实现我们改变诗歌文本外观的目标。但是，如果单独将这行代码插入文档头部，它将不会产生任何效果。JavaScript 代码一旦在浏览器中遇到就会运行，在处理标题时，尚未存在要样式化的 HTML。我们需要延迟执行代码，直到 DOM 可供我们使用。

使用 `$(() => {})` 构造（传递函数而不是选择器表达式），jQuery 允许我们安排函数调用，以便一旦 DOM 加载完成，即可触发，而不必等待图像完全渲染。虽然这种事件调度在没有 jQuery 的情况下也是可能的，但 `$(() => {})` 提供了一种特别优雅的跨浏览器解决方案，其中包括以下特性：

+   当可用时，它使用浏览器的本机 DOM 就绪实现，并添加 `window.onload` 事件处理程序作为一个安全网

+   即使在浏览器事件已经发生后调用，它也会执行传递给 `$()` 的函数

+   它异步处理事件调度，以允许脚本延迟执行，如果有必要的话

`$()` 函数的参数可以接受对已定义函数的引用，如以下代码片段所示：

```js
function addHighlightClass()  { 
  $('div.poem-stanza').addClass('highlight'); 
} 

$(addHighlightClass); 

```

列表 1.1

然而，如在脚本的原始版本中演示的，并在*列表 1.2*中重复的，该方法也可以接受匿名函数：

```js
$(() =>
  $('div.poem-stanza').addClass('highlight')
); 

```

列表 1.2

这种匿名函数惯用法在 jQuery 代码中对于接受函数作为参数的方法很方便，当该函数不可重用时。此外，它创建的闭包可以是一种高级且强大的工具。如果您使用箭头函数，您还可以获得词法绑定的 `this` 作为上下文，这避免了绑定函数的需要。然而，如果不小心处理，它可能会产生意想不到的后果和内存使用方面的影响。

# 成品

现在我们的 JavaScript 就位了，页面看起来是这样的：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/image_01_002-1.jpg)

诗歌的节现在已经用盒子括起来，如 `01.css` 样式表所指定的，由于 JavaScript 代码插入了 `highlight` 类。

# 纯 JavaScript 对比 jQuery

即使是这样简单的任务，如果没有 jQuery 支持，也可能会变得复杂。在纯 JavaScript 中，我们可以这样添加 `highlight` 类：

```js
window.onload = function() {
  const divs = document.getElementsByTagName('div');
  const hasClass = (elem, cls) =>
    new RegExp(` ${cls} `).test(` ${elem.className} `);

  for (let div of divs) {
    if (hasClass(div, 'poem-stanza') && !hasClass(div, 'highlight')) {
      div.className += ' highlight';
    }
  }
};

```

列表 1.3

尽管其长度较长，但这种解决方案并没有处理 jQuery 在*列表 1.2*中为我们处理的许多情况，例如：

+   正确地尊重其他 `window.onload` 事件处理程序

+   一旦 DOM 准备就绪就开始行动

+   使用现代 DOM 方法优化元素检索和其他任务

我们可以看到，我们使用 jQuery 驱动的代码比其纯 JavaScript 等价物更容易编写、更容易阅读，并且执行速度更快。

# 使用开发工具

正如这个代码对比所显示的，jQuery 代码通常比其基本的 JavaScript 等价物更短更清晰。然而，这并不意味着我们将总是写出没有错误的代码，或者我们会在任何时候直观地理解页面上正在发生的事情。有了标准的开发工具，我们的 jQuery 编码体验将会更加顺畅。

所有现代浏览器都提供了高质量的开发工具。我们可以自由选择最适合我们的环境。选项包括以下内容：

+   Microsoft Edge（[`developer.microsoft.com/zh-CN/microsoft-edge/platform/documentation/f12-devtools-guide/`](https://developer.microsoft.com/zh-CN/microsoft-edge/platform/documentation/f12-devtools-guide/)）

+   Internet Explorer 开发者工具（[`msdn.microsoft.com/zh-CN/library/dd565628.aspx`](http://msdn.microsoft.com/zh-CN/library/dd565628.aspx)）

+   Safari Web 开发工具（[`developer.apple.com/zh-CN/safari/tools/`](https://developer.apple.com/zh-CN/safari/tools/)）

+   Chrome 开发者工具（[`developer.chrome.com/devtools`](https://developer.chrome.com/devtools)）

+   Firefox 开发者工具（[`developer.mozilla.org/zh-CN/docs/Tools`](https://developer.mozilla.org/zh-CN/docs/Tools)）

每个工具包都提供类似的开发功能，包括：

+   探索和修改 DOM 的各个方面

+   调查 CSS 与其对页面呈现的影响之间的关系

+   通过特殊方法方便地追踪脚本执行

+   暂停正在运行的脚本的执行并检查变量值

尽管这些功能的细节因工具而异，但一般概念仍然相同。在本书中，一些示例将需要使用其中一个工具包；我们将使用 Chrome 开发者工具进行这些演示，但其他浏览器的开发工具也是很好的替代方案。

# Chrome 开发者工具

最新的 Chrome 开发者工具的访问和使用说明可以在项目的文档页面上找到：[`developer.chrome.com/devtools`](https://developer.chrome.com/devtools)。这些工具涉及太多，无法在此处详细探讨，但对一些最相关的功能进行概述将对我们有所帮助。

理解这些屏幕截图

Chrome 开发者工具是一个快速发展的项目，因此以下屏幕截图可能与您的环境不完全匹配。

当激活 Chrome 开发者工具时，会出现一个新的面板，提供有关当前页面的信息。在此面板的默认元素标签中，我们可以在左侧看到页面结构的表示，右侧可以看到所选元素的详细信息（例如适用于它的 CSS 规则）。此标签对于调查页面结构和调试 CSS 问题特别有用：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/image_01_01-1.png)

“源”标签允许我们查看页面上加载的所有脚本的内容。通过右键单击行号，我们可以设置断点，设置条件断点，或在达到另一个断点后使脚本继续到该行。断点是暂停脚本执行并逐步检查发生情况的有效方法。在页面右侧，我们可以输入要在任何时间知道其值的变量和表达式列表：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/image_01_02.png)

在学习 jQuery 时，控制台选项卡将是我们最频繁使用的。面板底部的字段允许我们输入任何 JavaScript 语句，然后语句的结果将显示在面板中。

在这个例子中，我们执行了与 *列表 1.2* 中相同的 jQuery 选择器，但是我们没有对所选元素执行任何操作。即便如此，该语句也给我们提供了有趣的信息：我们看到选择器的结果是一个指向页面上两个 `.poem-stanza` 元素的 jQuery 对象。我们可以随时使用此控制台功能快速尝试 jQuery 代码，直接从浏览器中进行：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/image_01_03.png)

另外，我们可以直接从我们的代码中使用 `console.log()` 方法与控制台进行交互：

```js
$(() => {
  console.log('hello');
  console.log(52);
  console.log($('div.poem-stanza'));
});

```

列表 1.4

这段代码说明了我们可以将任何类型的表达式传递给 `console.log()` 方法。简单值如字符串和数字直接打印出来，而像 jQuery 对象这样的复杂值则以我们的检查方式进行了良好的格式化：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/image_01_04.png)

这个 `console.log()` 函数（在我们之前提到的每个浏览器开发工具中都有效）是 JavaScript `alert()` 函数的一个便利替代品，并且在我们测试 jQuery 代码时将非常有用。

# 摘要

在本章中，我们学习了如何使 jQuery 在我们的网页上的 JavaScript 代码中可用，使用 `$()` 函数来定位具有给定类的页面的某个部分，调用 `.addClass()` 来为页面的这部分应用附加样式，并调用 `$(() => {})` 来使该函数在加载页面时执行。我们还探讨了在编写、测试和调试我们的 jQuery 代码时将依赖的开发工具。

现在我们知道为什么开发人员选择使用 JavaScript 框架而不是从头编写所有代码，即使是最基本的任务也是如此。我们还看到了 jQuery 作为框架的一些优点，以及为什么我们可能会选择它而不是其他选项，以及通常情况下，jQuery 使哪些任务更容易。

我们一直使用的简单示例展示了 jQuery 的工作原理，但在实际情况下并不太有用。在下一章中，我们将通过探索 jQuery 的复杂选择器语言来扩展这段代码，找到这种技术的实际用途。


# 第二章：选择元素

jQuery 库利用 **层叠样式表** (**CSS**) 选择器的力量，让我们能够快速轻松地访问 **文档对象模型** (**DOM**) 中的元素或元素组。

在本章中，我们将涵盖：

+   网页上元素的结构

+   如何使用 CSS 选择器在页面上查找元素

+   当 CSS 选择器的特异性发生变化时会发生什么

+   自定义 jQuery 扩展到标准的 CSS 选择器集

+   DOM 遍历方法，提供了更大的灵活性，用于访问页面上的元素

+   使用现代 JavaScript 语言功能有效地迭代 jQuery 对象

# 理解 DOM

jQuery 最强大的方面之一是其使得在 DOM 中选择元素变得容易。DOM 作为 JavaScript 和网页之间的接口；它提供了 HTML 源代码的表示，作为对象网络，而不是作为纯文本。

这个网络采用了页面上元素的家族树形式。当我们提到元素彼此之间的关系时，我们使用与指家庭关系时相同的术语：父母、子女、兄弟姐妹等。一个简单的例子可以帮助我们理解家族树隐喻如何适用于文档：

```js
<html> 
  <head> 
    <title>the title</title> 
  </head> 
  <body> 
    <div> 
      <p>This is a paragraph.</p> 
      <p>This is another paragraph.</p> 
      <p>This is yet another paragraph.</p> 
    </div> 
  </body> 
</html> 

```

在这里，`<html>` 是所有其他元素的祖先；换句话说，所有其他元素都是 `<html>` 的后代。`<head>` 和 `<body>` 元素不仅是 `<html>` 的后代，而且是其子元素。同样，除了是 `<head>` 和 `<body>` 的祖先之外，`<html>` 还是它们的父元素。`<p>` 元素是 `<div>` 的子元素（和后代），是 `<body>` 和 `<html>` 的后代，以及彼此的兄弟元素。

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/3145OS_02_01.png)

为了帮助可视化 DOM 的家族树结构，我们可以使用浏览器的开发者工具检查任何页面的 DOM 结构。当您好奇某个其他应用程序的工作方式，并且想要实现类似功能时，这特别有帮助。

有了这些元素的树结构，我们将能够使用 jQuery 高效地定位页面上的任何一组元素。我们实现这一目标的工具是 jQuery **选择器** 和 **遍历方法**。

# 使用 $() 函数

由 jQuery 的选择器和方法生成的元素集合始终由 jQuery 对象表示。当我们想要实际对页面上找到的东西进行操作时，这些对象非常容易使用。我们可以轻松地将事件绑定到这些对象上，并向它们添加视觉效果，以及将多个修改或效果链接在一起。

请注意，jQuery 对象与普通 DOM 元素或节点列表不同，因此在某些任务上不一定提供相同的方法和属性。在本章的最后部分，我们将探讨直接访问 jQuery 对象中收集的 DOM 元素的方法。

要创建一个新的 jQuery 对象，我们使用 `$()` 函数。这个函数通常接受一个 CSS 选择器作为其唯一参数，并充当工厂，返回一个指向页面上相应元素的新 jQuery 对象。几乎任何可以在样式表中使用的东西也可以作为字符串传递给此函数，使我们能够将 jQuery 方法应用于匹配的元素集。

使 jQuery 与其他 JavaScript 库协同工作

在 jQuery 中，美元符号 `($)` 只是 `jQuery` 的别名。因为 `$()` 函数在 JavaScript 库中非常常见，所以如果在同一页中使用了多个这些库，可能会出现冲突。我们可以通过在自定义 jQuery 代码中将每个 `$` 实例替换为 `jQuery` 来避免这种冲突。有关此问题的其他解决方案将在第十章 *高级事件*中讨论。另一方面，jQuery 在前端开发中非常突出，因此库通常不会动 `$` 符号。

选择器的三个主要构建块是**标签名**、**ID**和**类**。它们可以单独使用，也可以与其他选择器组合使用。以下简单示例说明了这三个选择器在代码中的应用方式：

| **选择器类型** | **CSS** | **jQuery** | **功能** |
| --- | --- | --- | --- |
| **标签名** | `p { }` | `$('p')` | 这选择了文档中的所有段落。 |
| **ID** | `#some-id { }`                             | `$('#some-id')`                           | 这选择了文档中具有 ID 为 `some-id` 的单个元素。 |
| **类** | `.some-class { }`                                                | `$('.some-class')`                                         | 这选择了文档中具有类 `some-class` 的所有元素。 |

如第一章 *入门*中所述，当我们调用 jQuery 对象的方法时，自动隐式地循环遍历了我们传递给 `$()` 的选择器所引用的元素。因此，我们通常可以避免显式迭代，比如 `for` 循环，在 DOM 脚本中经常需要。

现在我们已经介绍了基础知识，我们准备开始探索一些更强大的选择器使用方法。

# CSS 选择器

jQuery 库支持 CSS 规范 1 到 3 中包含的几乎所有选择器，详细信息请参见万维网联盟的网站：[`www.w3.org/Style/CSS/specs`](http://www.w3.org/Style/CSS/specs)。这种支持允许开发人员增强其网站，而无需担心哪些浏览器可能不理解更高级的选择器，只要浏览器启用了 JavaScript。

渐进增强

负责任的 jQuery 开发者应始终将渐进增强和优雅降级的概念应用于其代码，确保页面在禁用 JavaScript 时渲染的准确性与启用 JavaScript 时一样，即使不那么美观。我们将在本书中继续探讨这些概念。有关渐进增强的更多信息，请访问[`en.wikipedia.org/wiki/Progressive_enhancement`](http://en.wikipedia.org/wiki/Progressive_enhancement)。话虽如此，这些天即使在移动浏览器上也很少遇到禁用 JavaScript 的用户。

要开始学习 jQuery 如何与 CSS 选择器配合工作，我们将使用许多网站上经常出现的结构，通常用于导航——嵌套的无序列表：

```js
<ul id="selected-plays"> 
  <li>Comedies 
    <ul> 
      <li><a href="/asyoulikeit/">As You Like It</a></li> 
      <li>All's Well That Ends Well</li> 
      <li>A Midsummer Night's Dream</li> 
      <li>Twelfth Night</li> 
    </ul> 
  </li> 
  <li>Tragedies 
    <ul> 
      <li><a href="hamlet.pdf">Hamlet</a></li> 
      <li>Macbeth</li> 
      <li>Romeo and Juliet</li> 
    </ul> 
  </li> 
  <li>Histories 
    <ul> 
      <li>Henry IV (<a href="mailto:henryiv@king.co.uk">email</a>) 
         <ul> 
           <li>Part I</li> 
           <li>Part II</li>  
         </ul> 
      <li><a href="http://www.shakespeare.co.uk/henryv.htm">Henry V</a></li>
      <li>Richard II</li> 
    </ul> 
  </li> 
</ul> 

```

可下载的代码示例

您可以从以下 Github 仓库访问示例代码：[`github.com/PacktPublishing/Learning-jQuery-3`](https://github.com/PacktPublishing/Learning-jQuery-3)。

注意，第一个`<ul>`具有`selecting-plays`的 ID，但没有任何`<li>`标签与之关联的类。没有应用任何样式，列表看起来像这样：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_02_02.png)

嵌套列表呈现我们所期望的样子——一组垂直排列的项目，根据它们的级别缩进。

# 设计列表项级别

假设我们只想要顶级项——喜剧、悲剧和历史——以及仅仅是顶级项水平排列。我们可以首先在样式表中定义一个`horizontal`类：

```js
.horizontal { 
  float: left; 
  list-style: none; 
  margin: 10px; 
} 

```

`horizontal`类使元素浮动到其后面的左侧，如果是列表项，则删除其标志，并在其四周添加 10 像素的边距。

不直接在我们的 HTML 中添加`horizontal`类，而是仅将其动态添加到顶级列表项，以演示 jQuery 对选择器的使用：

```js
$(() => {
  $('#selected-plays > li')
    .addClass('horizontal');
}); 

```

列表 2.1

如第一章所述，*入门*，我们通过调用`$(() => {})`开始 jQuery 代码，该代码在 DOM 加载后运行传递给它的函数，但在此之前不会运行。

第二行使用子级组合符（`>`）仅向所有顶级项添加`horizontal`类。实际上，`$()`函数内的选择器表示“找到每个列表项（`li`），它是具有 ID 为`selected-plays`（`#selected-plays`）的元素的子级（`>`）”。

现在应用了该类，样式表中为该类定义的规则生效，这意味着列表项水平排列而不是垂直排列。现在，我们的嵌套列表看起来是这样的：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_02_03.png)

对所有其他项进行样式设置--即不在顶级的项--有很多种方法。由于我们已经将`horizontal`类应用于顶级项目，选择所有子级项目的一种方法是使用否定伪类来标识所有没有`horizontal`类的列表项：

```js
$(() => {
  $('#selected-plays > li')
    .addClass('horizontal'); 
  $('#selected-plays li:not(.horizontal)')
    .addClass('sub-level');
}); 

```

列表 2.2

这一次我们选择了每个列表项（`<li>`），它：

+   是具有 ID 为`selected-plays`的元素的后代（`#selected-plays`）

+   没有`horizontal`类（`:not(.horizontal)`）

当我们向这些项目添加`sub-level`类时，它们将接收到样式表中定义的阴影背景：

```js
.sub-level { 
  background: #ccc; 
} 

```

现在嵌套列表看起来是这样的：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_02_04.png)

# 选择器的具体性

在 jQuery 中，选择器的具体性有一个范围，从非常通用的选择器到非常具体的选择器。目标是选择正确的元素，否则你的选择器就会失效。jQuery 初学者的倾向是为所有东西实现非常具体的选择器。也许通过反复试验，他们已经通过为给定的选择器添加更多的具体性来修复选择器错误。然而，这并不总是最好的解决方案。

让我们看一个例子，增加顶级`<li>`文本的首字母大小。这是我们要应用的样式：

```js
.big-letter::first-letter {
   font-size: 1.4em;
 }

```

下面是列表项文本的样式：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/Screenshot-from-2016-11-27-11-02-54-3.png)

正如你所见，喜剧，悲剧和历史如预期地应用了`big-letter`样式。为了做到这一点，我们需要一个比仅仅选择`$('#selected-plays li')`更具体的选择器，后者会将样式应用于每一个`<li>`，甚至子元素。我们可以改变 jQuery 选择器的具体性以确保我们只获得我们所期望的：

```js
$(() => { 
  $('#selected-plays > li') 
    .addClass('big-letter'); 

  $('#selected-plays li.horizontal')
    .addClass('big-letter'); 

  $('#selected-plays li:not(.sub-level)') 
    .addClass('big-letter'); 
});

```

列表 2.3

所有这三个选择器都做了同样的事情--将`big-letter`样式应用于`#selected-plays`中的顶级`<li>`元素。每个选择器的具体性都不同。让我们回顾一下每个选择器的工作原理以及它们的优势：

+   `#selected-plays > li`：这找到了直接是`#selected-plays`的子元素的`<li>`元素。这易于阅读，并且在 DOM 结构上语义相关。

+   `#selected-plays li.horizontal`：这找到了`#selected-plays`的`<li>`元素或子元素，并具有`horizontal`类。这也很容易阅读，并强制执行特定的 DOM 模式（应用`horizontal`类）。

+   `#selected-plays li:not(.sub-level)`：这很难阅读，效率低下，并且不反映实际的 DOM 结构。

在实际应用中，选择器的具体性经常会成为一个无穷的例子。每个应用都是独特的，正如我们刚才所看到的，实现选择器的具体性并没有一个正确的方法。重要的是，我们要通过考虑选择器对 DOM 结构的影响以及因此对应用或网站的可维护性的影响来行使良好的判断力。

# 属性选择器

属性选择器是 CSS 选择器的一个特别有用的子集。它们允许我们通过其 HTML 属性之一来指定一个元素，例如链接的`title`属性或图像的`alt`属性。例如，要选择所有具有`alt`属性的图像，我们写成这样：

```js
$('img[alt]') 

```

# 设置链接的样式

属性选择器接受受到正则表达式启发的通配符语法，用于标识字符串开头（`^`）或结尾（`$`）的值。它们还可以采用星号（`*`）来表示字符串中任意位置的值，感叹号（`!`）表示否定值。

假设我们希望为不同类型的链接使用不同的样式。我们首先在样式表中定义样式：

```js
a { 
  color: #00c;  
} 
a.mailto { 
  background: url(images/email.png) no-repeat right top; 
  padding-right: 18px; 
} 
a.pdflink { 
  background: url(images/pdf.png) no-repeat right top; 
  padding-right: 18px; 
} 
a.henrylink { 
  background-color: #fff; 
  padding: 2px; 
  border: 1px solid #000; 
} 

```

然后，我们使用 jQuery 将三个类--`mailto`、`pdflink` 和 `henrylink`--添加到相应的链接中。

要为所有电子邮件链接添加一个类，我们构造一个选择器，查找所有具有`href`属性的锚元素（`a`），该属性以`mailto:`开头（`^="mailto:"`），如下所示：

```js
$(() => {
  $('a[href^="mailto:"]')
    .addClass('mailto');
}); 

```

列表 2.4

由于页面样式表中定义的规则，邮件链接后会出现一个信封图像。

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_02_05-1.png)

要为所有 PDF 文件的链接添加一个类，我们使用美元符号而不是插入符号。这是因为我们选择的是链接，其`href`属性以`.pdf`结尾：

```js
$(() => { 
  $('a[href^="mailto:"]')
    .addClass('mailto'); 
  $('a[href$=".pdf"]')
    .addClass('pdflink'); 
}); 

```

*列表 2.5*

新添加的`pdflink`类的样式表规则会导致每个指向 PDF 文档的链接后面都出现 Adobe Acrobat 图标，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_02_06-1.png)

属性选择器也可以组合使用。例如，我们可以将类`henrylink`添加到所有链接的`href`值既以`http`开头又在任何地方包含`henry`的链接中：

```js
$(() => { 
  $('a[href^="mailto:"]')
    .addClass('mailto'); 
  $('a[href$=".pdf"]')
    .addClass('pdflink'); 
  $('a[href^="http"][href*="henry"]') 
    .addClass('henrylink'); 
}); 

```

列表 2.6

有了应用于三种类型链接的三个类，我们应该看到以下效果：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_02_07-1.png)

注意 Hamlet 链接右侧的 PDF 图标，电子邮件链接旁边的信封图标，以及 Henry V 链接周围的白色背景和黑色边框。

# 自定义选择器

jQuery 在广泛的 CSS 选择器基础上添加了自己的自定义选择器。这些自定义选择器增强了 CSS 选择器定位页面元素的能力。

性能说明

在可能的情况下，jQuery 使用浏览器的原生 DOM 选择器引擎来查找元素。当使用自定义 jQuery 选择器时，这种极快的方法是不可能的。因此，建议在原生选项可用时避免频繁使用自定义选择器。

大多数自定义选择器都允许我们从已经找到的一组元素中选择一个或多个元素。自定义选择器的语法与 CSS 伪类的语法相同，选择器以冒号（`:`）开头。例如，要从具有`horizontal`类的一组 `<div>` 元素中选择第二个项目，我们写成这样：

```js
$('div.horizontal:eq(1)') 

```

请注意，`:eq(1)`选择集合中的第二个项目，因为 JavaScript 数组编号是以零为基础的，这意味着它从零开始。相比之下，CSS 是以 1 为基础的，因此像`$('div:nth-child(1)')`这样的 CSS 选择器将选择所有作为其父元素的第一个子元素的`div`选择器。由于很难记住哪些选择器是基于零的，哪些是基于一的，当存在疑惑时，我们应该在 jQuery API 文档[`api.jquery.com/category/selectors/`](http://api.jquery.com/category/selectors/)中查阅 jQuery API 文档。

# 风格化交替行

在 jQuery 库中有两个非常有用的自定义选择器是`:odd`和`:even`。让我们看看我们如何使用其中一个来对基本表格进行条纹处理，如下表格所示：

```js
<h2>Shakespeare's Plays</h2> 
<table> 
  <tr> 
    <td>As You Like It</td> 
    <td>Comedy</td> 
    <td></td> 
  </tr> 
  <tr> 
    <td>All's Well that Ends Well</td> 
    <td>Comedy</td> 
    <td>1601</td> 
  </tr> 
  <tr> 
    <td>Hamlet</td> 
    <td>Tragedy</td> 
    <td>1604</td> 
  </tr> 
  <tr> 
    <td>Macbeth</td> 
    <td>Tragedy</td> 
    <td>1606</td> 
  </tr> 
  <tr> 
    <td>Romeo and Juliet</td> 
    <td>Tragedy</td> 
    <td>1595</td> 
  </tr> 
  <tr> 
    <td>Henry IV, Part I</td> 
    <td>History</td> 
    <td>1596</td> 
  </tr> 
  <tr> 
    <td>Henry V</td> 
    <td>History</td> 
    <td>1599</td> 
  </tr> 
</table> 
<h2>Shakespeare's Sonnets</h2> 
<table> 
  <tr> 
    <td>The Fair Youth</td> 
    <td>1-126</td> 
  </tr> 
  <tr> 
    <td>The Dark Lady</td> 
    <td>127-152</td> 
  </tr> 
  <tr> 
    <td>The Rival Poet</td> 
    <td>78-86</td> 
  </tr> 
</table> 

```

从我们的样式表中应用最小的样式后，这些标题和表格看起来相当普通。表格具有纯白色背景，没有样式区分一行和下一行，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_02_08-1.png)

现在，我们可以向样式表中的所有表格行添加样式，并对奇数行使用`alt`类：

```js
tr { 
  background-color: #fff;  
} 
.alt { 
  background-color: #ccc;  
} 

```

最后，我们编写我们的 jQuery 代码，将类附加到奇数行的表格行（`<tr>`标签）：

```js
$(() => { 
  $('tr:even').addClass('alt'); 
}); 

```

列表 2.7

但等等！为什么使用`:even`选择器来选择奇数行？好吧，就像使用`:eq()`选择器一样，`:even`和`:odd`选择器使用 JavaScript 的本地从零开始的编号。因此，第一行计为零（偶数）和第二行计为一（奇数），依此类推。有了这一点，我们可以期望我们简单的代码生成如下所示的表格：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_02_09.png)

请注意，对于第二个表格，这个结果可能不是我们想要的。由于剧目表中最后一行具有交替的灰色背景，而十四行诗表中的第一行具有普通的白色背景。避免这种问题的一种方法是使用`:nth-child()`选择器，该选择器计算元素相对于其父元素的位置，而不是相对于到目前为止选择的所有元素的位置。此选择器可以使用数字、`奇数`或`偶数`作为参数：

```js
$(() => {
  $('tr:nth-child(odd)').addClass('alt'); 
}); 

```

列表 2.8

与之前一样，请注意`:nth-child()`是唯一一个以 1 为基础的 jQuery 选择器。为了实现与之前相同的行条纹效果--但对于第二个表格具有一致的行为，我们需要使用`奇数`而不是`偶数`作为参数。使用此选择器后，两个表格现在都有很好的条纹，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_02_10.png)

`:nth-child()`选择器是现代浏览器中本机的 CSS 选择器。

# 基于文本内容查找元素

对于最后一个自定义选择器，假设出于某种原因，我们希望突出显示任何一个表格单元格，该单元格提到了亨利的剧目。我们只需--在样式表中添加一个使文本加粗和斜体的类（`.highlight {font-weight:bold; font-style: italic;}`）--在我们的 jQuery 代码中使用`:contains()`选择器添加一行：

```js
$(() => { 
  $('tr:nth-child(odd)')
    .addClass('alt'); 
  $('td:contains(Henry)')
    .addClass('highlight'); 
}); 

```

列表 2.9

因此，现在我们可以看到我们可爱的带有亨利剧集的条纹表格突出显示：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_02_11.png)

需要注意的是，`:contains()` 选择器区分大小写。使用不带大写 "H" 的 `$('td:contains(henry)')` 将不选择任何单元格。还需要注意的是，`:contains()` 可能会导致灾难性的性能下降，因为需要加载匹配第一部分选择器的每个元素的文本，并将其与我们提供的参数进行比较。当 `:contains()` 有可能搜索数百个节点以查找内容时，是时候重新考虑我们的方法了。

诚然，有多种方法可以实现行条纹和文本突出显示，而不需要 jQuery，或者说，根本不需要客户端编程。尽管如此，在动态生成内容且我们无法访问 HTML 或服务器端代码的情况下，jQuery 与 CSS 是这种类型样式的绝佳选择。

# 表单选择器

自定义选择器的功能不仅限于根据位置定位元素。例如，在处理表单时，jQuery 的自定义选择器和补充的 CSS3 选择器可以轻松选择我们需要的元素。以下表格描述了其中一些表单选择器：

| **选择器** | **匹配** |
| --- | --- |
| `:input` | 输入、文本区域、选择器和按钮元素 |
| `:button` | 按钮元素和带有 `type` 属性等于 `button` 的输入元素 |
| `:enabled` | 已启用的表单元素 |
| `:disabled` | 已禁用的表单元素 |
| `:checked` | 已选中的单选按钮或复选框 |
| `:selected` | 已选择的选项元素 |

与其他选择器一样，表单选择器可以组合使用以提高特异性。例如，我们可以选择所有已选中的单选按钮（但不包括复选框）：`$('input[type="radio"]:checked')`，或选择所有密码输入和禁用的文本输入：`$('input[type="password"], input[type="text"]:disabled')`。即使使用自定义选择器，我们也可以使用相同的基本 CSS 原理来构建匹配元素列表。

我们在这里仅仅触及了可用选择器表达式的皮毛。我们将在第九章，*高级选择器和遍历*中深入探讨这个主题。

# DOM 遍历方法

到目前为止，我们探索的 jQuery 选择器允许我们在 DOM 树中向下导航并过滤结果，如果这是选择元素的唯一方式，我们的选择会受到一定限制。在许多情况下，选择父元素或祖先元素至关重要；这就是 jQuery 的 DOM 遍历方法发挥作用的地方。使用这些方法，我们可以轻松地在 DOM 树中向上、向下和周围移动。

一些方法在选择器表达式中具有几乎相同的对应项。例如，我们首先用来添加`alt`类的行，`$('tr:even').addClass('alt')`，可以使用`.filter()`方法重写如下：

```js
$('tr')
  .filter(':even')
  .addClass('alt'); 

```

然而，在很大程度上，这两种选择元素的方式互补。此外，特别是`.filter()`方法具有巨大的威力，因为它可以将函数作为其参数。该函数允许我们为是否应将元素包含在匹配的集合中创建复杂的测试。例如，假设我们想要为所有外部链接添加一个类：

```js
a.external { 
  background: #fff url(images/external.png) no-repeat 100% 2px; 
  padding-right: 16px; 
} 

```

jQuery 没有这种选择器。如果没有过滤函数，我们将被迫显式地遍历每个元素，分别测试每个元素。但是，有了下面的过滤函数，我们仍然可以依赖于 jQuery 的隐式迭代，并保持我们的代码简洁：

```js
$('a')
  .filter((i, a) =>
    a.hostname && a.hostname !== location.hostname
  )
  .addClass('external'); 

```

列表 2.10

提供的函数通过两个标准筛选`<a>`元素集：

+   链接必须具有域名(`a.hostname`)的`href`属性。我们使用此测试来排除邮件链接，例如。

+   它们链接到的域名（再次，`a.hostname`）不得与当前页面的域名（`location.hostname`）匹配。

更精确地说，`.filter()`方法遍历匹配的元素集，每次调用函数并测试返回值。如果函数返回`false`，则从匹配的集合中删除该元素。如果返回`true`，则保留该元素。

使用`.filter()`方法后，Henry V 链接被设置为外部链接的样式：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_02_12.png)

在下一节中，我们将再次查看我们条纹表格示例，看看遍历方法还有什么其他可能性。

# 样式化特定单元格

早些时候，我们向所有包含文本 Henry 的单元格添加了`highlight`类。要改为样式化每个包含 Henry 的单元格旁边的单元格，我们可以从已经编写的选择器开始，并简单地在结果上调用`.next()`方法：

```js
$(() => {
  $('td:contains(Henry)')
    .next()
    .addClass('highlight'); 
}); 

```

列表 2.11

现在表格应该是这样的：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_02_13.png)

`.next()`方法仅选择紧接的下一个同级元素。要突出显示包含 Henry 的单元格后面的所有单元格，我们可以改用`.nextAll()`方法：

```js
$(() => {
  $('td:contains(Henry)')
    .nextAll()
    .addClass('highlight'); 
}); 

```

列表 2.12

由于包含 Henry 的单元格位于表格的第一列中，此代码会导致这些行中的其余单元格被突出显示：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_02_14.png)

正如我们可能预期的那样，`.next()`和`.nextAll()`方法有对应的方法：`.prev()`和`.prevAll()`。此外，`.siblings()`选择同一 DOM 级别的所有其他元素，无论它们是在之前还是之后选择的元素之后。

要包含原始单元格（包含 Henry 的单元格）以及随后的单元格，我们可以添加`.addBack()`方法：

```js
$(() => {
  $('td:contains(Henry)')
    .nextAll()
    .addBack() 
    .addClass('highlight'); 
}); 

```

列表 2.13

使用这个修改后，该行中的所有单元格都从`highlight`类中获取其样式：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_02_15.png)

我们可以通过多种选择器和遍历方法的组合来选择相同的元素集。例如，这里是另一种选择每行中至少一个单元格包含 Henry 的方法：

```js
$(() => { 
  $('td:contains(Henry)')
    .parent()
    .children() 
    .addClass('highlight'); 
}); 

```

列表 2.14

我们不是沿着兄弟元素遍历，而是在 DOM 中向上移动到带有 `.parent()` 的 `<tr>` 标记，然后用 `.children()` 选择所有行的单元格。

# 链式调用

我们刚刚探索过的遍历方法组合展示了 jQuery 的链式调用能力。使用 jQuery，可以在一行代码中选择多个元素集并对其执行多个操作。这种链式调用不仅有助于保持 jQuery 代码简洁，而且在替代重新指定选择器的情况下，还可以改善脚本的性能。

链式调用的工作原理

几乎所有的 jQuery 方法都会返回一个 jQuery 对象，因此可以对结果应用更多的 jQuery 方法。我们将在第八章中探讨链式调用的内部工作原理，*开发插件*。

为了提高可读性，也可以将一行代码分成多行。例如，在本章中我们一直在做的就是这样。例如，一个单独的链式方法序列可以写在一行中：

```js
$('td:contains(Henry)').parent().find('td:eq(1)') 
    .addClass('highlight').end().find('td:eq(2)') 
                           .addClass('highlight'); 

```

列表 2.15

这些方法的顺序也可以用七行来写：

```js
$('td:contains(Henry)') // Find every cell containing "Henry" 
  .parent() // Select its parent 
  .find('td:eq(1)') // Find the 2nd descendant cell 
  .addClass('highlight') // Add the "highlight" class 
  .end() // Return to the parent of the cell containing "Henry" 
  .find('td:eq(2)') // Find the 3rd descendant cell 
  .addClass('highlight'); // Add the "highlight" class 

```

列表 2.16

此示例中的 DOM 遍历是刻意的，不建议使用。我们可以清楚地看到，我们可以使用更简单、更直接的方法。这个例子的重点只是展示了链式调用给我们带来的巨大灵活性，特别是当需要进行多次调用时。

链式调用就像在一个呼吸里说完整个段落的话语一样——可以快速完成工作，但对于其他人来说可能很难理解。将其分成多行并添加适当的注释可以在长远来看节省更多时间。

# 迭代 jQuery 对象

jQuery 3 中的新功能是使用 `for...of` 循环迭代 jQuery 对象。这本身并不是什么大不了的事情。首先，我们很少需要明确地迭代 jQuery 对象，特别是当使用 jQuery 函数中的隐式迭代也能得到相同的结果时。但有时，无法避免明确迭代。例如，想象一下你需要将一个元素数组（一个 jQuery 对象）减少为一个字符串值数组。`each()` 函数在这里是一种选择：

```js
const eachText = [];

$('td')
  .each((i, td) => {
    if (td.textContent.startsWith('H')) {
      eachText.push(td.textContent);
    }
  });

console.log('each', eachText);
 // ["Hamlet", "Henry IV, Part I", "History", "Henry V", "History"]

```

列表 2.17

我们首先用 `$('td')` 选择器得到了一个 `<td>` 元素数组。然后，通过将 `each()` 函数传递一个回调来将每个以 "H" 开头的字符串推到 `eachText` 数组中，我们将其减少为一个字符串数组。这种方法没有问题，但是为这样一个简单的任务编写回调函数似乎有点过分了。下面是使用 `for...of` 语法实现相同功能的代码：

```js
 const forText = [];

 for (let td of $('td')) {
   if (td.textContent.startsWith('H')) {
     forText.push(td.textContent);
   }
 }

 console.log('for', forText);
 // ["Hamlet", "Henry IV, Part I", "History", "Henry V", "History"]

```

列表 2.18

通过简单的`for`循环和`if`语句，我们现在可以缩减 jQuery 对象。我们将在本书后面重新讨论这种`for...of`方法，以适用更高级的使用场景，包括生成器。

# 访问 DOM 元素

每个选择器表达式和大多数 jQuery 方法都返回一个 jQuery 对象。这几乎总是我们想要的，因为它提供了隐式迭代和链接的功能。

然而，在我们的代码中可能会有一些情况需要直接访问 DOM 元素。例如，我们可能需要使生成的元素集合可供其他 JavaScript 库使用，或者可能需要访问元素的标签名称，这作为 DOM 元素的一个属性可用。对于这些明显罕见的情况，jQuery 提供了`.get()`方法。例如，要访问 jQuery 对象引用的第一个 DOM 元素，我们会使用`.get(0)`。因此，如果我们想要知道 ID 为`my-element`的元素的标签名称，我们会这样写：

```js
$('#my-element').get(0).tagName; 

```

为了更加便利，jQuery 提供了`.get()`的简写。我们可以直接在选择器后面使用方括号来代替前面的行：

```js
$('#my-element')[0].tagName; 

```

这种语法看起来像是将 jQuery 对象视为 DOM 元素的数组并不是偶然的；使用方括号就像是把 jQuery 层剥离出去，得到节点列表，并包括索引（在这种情况下，`0`），就像是取出 DOM 元素本身。

# 总结

通过本章介绍的技巧，现在我们应该能够以各种方式在页面上定位元素集合。特别是，我们学习了如何使用基本的 CSS 选择器来为嵌套列表的顶层和子层项目设置样式，如何使用属性选择器为不同类型的链接应用不同的样式，如何使用自定义的 jQuery 选择器`:odd`和`:even`或高级 CSS 选择器`:nth-child()`为表格添加基本的条纹，并通过链接 jQuery 方法来突出显示特定表格单元格中的文本。

到目前为止，我们一直在使用`$(() => {})`文档准备处理程序来给匹配的元素集合添加类。在下一章中，我们将探讨在响应各种用户触发事件中添加类的方法。

# 进一步阅读

选择器和遍历方法的主题将在第九章《高级选择器和遍历》中更详细地探讨。jQuery 的选择器和遍历方法的完整列表可在本书的附录 B 中找到，也可在官方的 jQuery 文档[`api.jquery.com/`](http://api.jquery.com/)中找到。

# 练习

挑战练习可能需要使用官方的 jQuery 文档 [`api.jquery.com/`](http://api.jquery.com/)：

1.  为嵌套列表的第二级所有`<li>`元素添加一个`special`类。

1.  为表格的第三列中的所有单元格添加一个`year`类。

1.  在含有单词`Tragedy`的第一行表格行中添加`special`类。

1.  这里有一个挑战给你。选择所有包含链接（`<a>`）的列表项（`<li>`）。给所选项后面的兄弟列表项添加类`afterlink`。

1.  这里有另一个挑战给你。给任何`.pdf`链接最近的祖先`<ul>`添加类`tragedy`。


# 第三章：处理事件

JavaScript 有几种内置的方式来响应用户交互和其他事件。为了使页面动态和响应灵活，我们需要利用这种能力，以便在适当的时候使用你迄今为止学到的 jQuery 技巧和你以后将学到的其他技巧。虽然我们可以用原生 JavaScript 来做到这一点，但 jQuery 增强和扩展了基本的事件处理机制，使其具有更优雅的语法，同时使其更加强大。

在本章中，我们将涵盖：

+   当页面准备就绪时执行 JavaScript 代码

+   处理用户事件，如鼠标点击和按键

+   事件通过文档的流动，以及如何操纵该流动

+   模拟事件，就像用户发起了它们一样

# 在页面加载时执行任务

我们已经看到如何使 jQuery 响应网页加载。 `$(() => {})` 事件处理程序可用于运行依赖于 HTML 元素的代码，但还有一些其他内容需要讨论。

# 代码执行的时间

在第一章中，*入门*，我们注意到 `$(() => {})` 是 jQuery 在页面加载时执行任务的主要方式。然而，这并不是我们唯一的选择。本地的 `window.onload` 事件也可以做同样的事情。虽然这两种方法相似，但重要的是要认识到它们在时间上的差异，尤其是依赖于加载的资源数量的情况下，这可能是相当微妙的。

当文档完全下载到浏览器时，`window.onload` 事件将触发。这意味着页面上的每个元素都可以被 JavaScript 操纵，这对于编写功能丰富的代码而不用担心加载顺序是一个福音。

另一方面，使用 `$(() => {})` 注册的处理程序在 DOM 完全准备就绪时被调用。这也意味着所有元素都可以被我们的脚本访问，但并不意味着每个相关文件都已经被下载。一旦 HTML 文件被下载并解析成 DOM 树，代码就可以运行。

样式加载和代码执行

为了确保页面在 JavaScript 代码执行之前也已经被样式化，将 `<link rel="stylesheet">` 和 `<style>` 标签放在文档的 `<head>` 元素内的任何 `<script>` 标签之前是一种良好的做法。

例如，考虑一个展示图库的页面；这样的页面上可能有许多大图，我们可以用 jQuery 隐藏、显示、移动和其他方式来操纵它们。如果我们使用 `onload` 事件来设置我们的接口，用户将不得不等待每个图像完全下载后才能使用这些功能。更糟糕的是，如果行为尚未附加到具有默认行为的元素（如链接）上，用户交互可能会产生意想不到的结果。然而，当我们使用 `$(() => {})` 进行设置时，界面更早地准备好使用，并具有正确的行为。

什么被加载了，什么没有被加载？

使用`$(() => {})`几乎总是优于使用`onload`处理程序，但我们需要记住，因为支持文件可能尚未加载，因此此时可能不一定可用图像高度和宽度等属性。如果需要这些属性，有时我们也可以选择实现`onload`处理程序；这两种机制可以和平共处。

# 处理一个页面上的多个脚本

通过 JavaScript 注册事件处理程序的传统机制（而不是直接在 HTML 内容中添加处理程序属性）是将函数分配给 DOM 元素的相应属性。例如，假设我们已定义了以下函数：

```js
function doStuff() { 
  // Perform a task... 
} 

```

然后，我们可以在 HTML 标记中分配它：

```js
<body onload="doStuff();"> 

```

或者，我们可以从 JavaScript 代码中分配它：

```js
window.onload = doStuff; 

```

这两种方法都会在页面加载时执行函数。第二种的优点是行为与标记清晰地分开。

引用与调用函数

当我们将函数分配为处理程序时，我们使用函数名但省略尾括号。带括号时，函数会立即调用；不带括号时，名称仅标识或*引用*函数，并且可以在以后调用它。

通过一个函数，这种策略运行得相当不错。然而，假设我们有一个第二个函数如下：

```js
function doOtherStuff() { 
  // Perform another task... 
} 

```

然后，我们可以尝试将此函数分配为在页面加载时运行：

```js
window.onload = doOtherStuff; 

```

但是，这个赋值会覆盖第一个。`.onload`属性一次只能存储一个函数引用，所以我们不能添加到现有的行为。

`$(() => {})`机制优雅地处理了这种情况。每次调用都会将新函数添加到内部行为队列中；当页面加载时，所有函数都将执行。函数将按照注册的顺序运行。

公平地说，jQuery 并不是唯一解决此问题的方法。我们可以编写一个 JavaScript 函数，调用现有的`onload`处理程序，然后调用传入的处理程序。这种方法避免了像`$(() => {})`这样的竞争处理程序之间的冲突，但缺少了我们讨论过的其他一些优点。在现代浏览器中，可以使用 W3C 标准的`document.addEventListener()`方法触发`DOMContentLoaded`事件。但是，`$(() => {})`更简洁而优雅。

# 将参数传递给文档准备好的回调

在某些情况下，同时在同一页面上使用多个 JavaScript 库可能会被证明是有用的。由于许多库使用`$`标识符（因为它简短而方便），我们需要一种方法来防止库之间的冲突。

幸运的是，jQuery 提供了一个名为`jQuery.noConflict()`的方法，将`$`标识符的控制权返回给其他库。`jQuery.noConflict()`的典型用法如下所示：

```js
<script src="img/prototype.js"></script> 
<script src="img/jquery.js"></script> 
<script> 
  jQuery.noConflict(); 
</script> 
<script src="img/myscript.js"></script> 

```

首先，包括其他库（本例中的`prototype.js`）。然后，`jquery.js`自身被包括，接管`$`以供自己使用。接下来，调用`.noConflict()`释放`$`，以便将其控制权恢复到第一个包括的库（`prototype.js`）。现在在我们的自定义脚本中，我们可以同时使用这两个库，但每当我们想使用 jQuery 方法时，我们需要将标识符写为`jQuery`而不是`$`。

`$(() => {})` 文档准备就绪处理程序在这种情况下还有一个技巧可以帮助我们。我们传递给它的回调函数可以接受一个参数--`jQuery`对象本身。这使我们可以有效地重新命名它，而不必担心冲突，使用以下语法：

```js
jQuery(($) => { 
  // In here, we can use $ like normal! 
}); 

```

# 处理简单事件

除了页面加载之外，还有其他时间点，我们可能希望执行某些任务。就像 JavaScript 允许我们拦截页面加载事件一样，使用`<body onload="">`或`window.onload`，它为用户触发的事件提供了类似的挂钩，如鼠标点击（`onclick`）、表单字段被修改（`onchange`）和窗口尺寸变化（`onresize`）。当直接分配给 DOM 中的元素时，这些挂钩也具有类似于我们为`onload`概述的缺点。因此，jQuery 也提供了处理这些事件的改进方式。

# 一个简单的样式切换器

为了说明一些事件处理技术，假设我们希望根据用户输入以多种不同的样式呈现单个页面；我们将提供按钮，允许用户在正常视图、文本受限于窄列的视图和内容区域为大字体的视图之间切换。

逐步增强

在一个真实的例子中，一个良好的网络公民将在这里应用逐步增强原则。在第五章，*操作 DOM*中，您将学到如何可以从我们的 jQuery 代码直接注入类似于这种样式切换器的内容，以便没有可用 JavaScript 的用户不会看到无效的控件。

样式切换器的 HTML 标记如下：

```js
<div id="switcher" class="switcher"> 
  <h3>Style Switcher</h3> 
  <button id="switcher-default"> 
    Default 
  </button> 
  <button id="switcher-narrow"> 
    Narrow Column 
  </button> 
  <button id="switcher-large"> 
    Large Print 
  </button> 
</div> 

```

获取示例代码

您可以访问下面的 GitHub 存储库中的示例代码：[`github.com/PacktPublishing/Learning-jQuery-3`](https://github.com/PacktPublishing/Learning-jQuery-3)。

结合页面的其余 HTML 标记和一些基本的 CSS，我们得到了一个看起来像以下的页面：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_03_01.png)

首先，我们将让大字体按钮起作用。我们需要一些 CSS 来实现我们页面的另一种视图，如下所示：

```js
body.large .chapter { 
  font-size: 1.5em; 
} 

```

因此，我们的目标是将`large`类应用于`<body>`标签。这将允许样式表适当地重新格式化页面。根据您在第二章学到的，*选择元素*，我们已经知道完成这个任务所需的语句：

```js
$('body').addClass('large'); 

```

然而，我们希望这发生在按钮被点击时，而不是在页面加载时，就像我们迄今所见的那样。为此，我们将介绍`.on()`方法。该方法允许我们指定任何 DOM 事件并附加行为。在这种情况下，事件被称为`click`，而行为是由我们之前的一行函数组成：

```js
$(() => {
  $('#switcher-large')
    .on('click', () => { 
      $('body').addClass('large'); 
    }); 
}); 

```

列表 3.1

现在当按钮被点击时，我们的代码运行，文字被放大：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_03_02.png)

这就是将行为绑定到事件的全部内容。我们讨论的`$(() => {})`文档就绪处理程序的优势在这里同样适用。多次调用`.on()`可以很好地共存，根据需要向同一事件附加附加行为。

这并不一定是实现此任务的最优雅或高效方式。随着我们继续学习本章，我们将扩展和完善这段代码，使之成为我们可以自豪的东西。

# 启用其他按钮

现在我们有了有效运行的大字按钮，但我们需要对其他两个按钮（默认和窄栏）应用类似的处理以使它们执行其任务。这很简单：我们使用`.on()`为每个按钮添加一个`click`处理程序，根据需要删除和添加类。新代码如下所示：

```js
$(() => {
  $('#switcher-default')
    .on('click', () => { 
      $('body')
        .removeClass('narrow')
        .removeClass('large'); 
    });

  $('#switcher-narrow')
    .on('click', () => { 
      $('body')
        .addClass('narrow')
        .removeClass('large'); 
    }); 

  $('#switcher-large')
    .on('click', () => { 
      $('body')
        .removeClass('narrow')
        .addClass('large'); 
    }); 
}); 

```

列表 3.2

这与`narrow`类的 CSS 规则相结合：

```js
body.narrow .chapter { 
  width: 250px; 
} 

```

现在，在点击"窄栏"按钮后，其相应的 CSS 被应用，文本布局不同了：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_03_03.png)

点击"Default"按钮会从`<body>`标签中移除两个类名，使页面恢复到最初的渲染状态。

# 利用事件处理程序上下文

我们的切换器行为正确，但我们没有向用户提供有关当前活动按钮的任何反馈。我们处理的方法是在点击时将`selected`类应用到按钮上，并从其他按钮上删除这个类。`selected`类只是使按钮的文字加粗：

```js
.selected { 
  font-weight: bold; 
} 

```

我们可以像之前一样通过引用每个按钮的 ID 并根据需要应用或移除类来实现此类修改，而是，我们将探讨一种更加优雅和可扩展的解决方案，利用事件处理程序运行的上下文。

当任何事件处理程序被触发时，关键字`this`指代的是附加行为的 DOM 元素。早些时候我们注意到`$()`函数可以将 DOM 元素作为参数；这是为何该功能可用的关键原因之一。在事件处理程序中写入`$(this)`，我们创建了一个对应于该元素的 jQuery 对象，我们可以像使用 CSS 选择器定位一样对其进行操作。

有了这个思路，我们可以写出以下内容：

```js
$(this).addClass('selected'); 

```

在每个处理程序中放置这行代码会在按钮被点击时添加类。要从其他按钮中移除类，我们可以利用 jQuery 的隐式迭代功能，并写入：

```js
$('#switcher button').removeClass('selected'); 

```

此行从样式切换器中的每个按钮中移除类。

当文档准备就绪时，我们还应该向默认按钮添加类。因此，将这些放置在正确的顺序中，代码如下所示：

```js
$(() => { 
  $('#switcher-default') 
    .addClass('selected') 
    .on('click', function() { 
      $('body')
        .removeClass('narrow'); 
        .removeClass('large'); 
      $('#switcher button')
        .removeClass('selected'); 
      $(this)
        .addClass('selected'); 
    });

  $('#switcher-narrow')
    .on('click', function() { 
        $('body')
          .addClass('narrow')
          .removeClass('large'); 
        $('#switcher button')
          .removeClass('selected'); 
        $(this)
          .addClass('selected'); 
  }); 

  $('#switcher-large')
    .on('click', function() { 
      $('body')
        .removeClass('narrow')
        .addClass('large'); 
      $('#switcher button')
        .removeClass('selected'); 
      $(this)
        .addClass('selected'); 
  }); 
}); 

```

列表 3.3

现在样式切换器提供了适当的反馈。

通过使用处理程序上下文概括语句，我们可以更加高效。我们可以将突出显示的例程提取到单独的处理程序中，如*列表 3.4*所示，因为它对所有三个按钮都是相同的：

```js
$(() => {
  $('#switcher-default') 
    .addClass('selected') 
    .on('click', function() { 
      $('body')
        .removeClass('narrow')
        .removeClass('large'); 
    }); 
  $('#switcher-narrow')
    .on('click', () => { 
      $('body')
        .addClass('narrow')
        .removeClass('large'); 
    }); 

  $('#switcher-large')
    .on('click', () => { 
      $('body')
        .removeClass('narrow')
        .addClass('large'); 
    }); 

  $('#switcher button')
    .on('click', function() { 
      $('#switcher button')
        .removeClass('selected'); 
      $(this)
        .addClass('selected'); 
    }); 
}); 

```

列表 3.4

这种优化利用了我们已经讨论过的三个 jQuery 功能。首先，当我们使用单个调用`.on()`将相同的`click`处理程序绑定到每个按钮时，**隐式迭代**再次非常有用。其次，**行为排队**允许我们将两个函数绑定到同一个点击事件，而不会第二个覆盖第一个。

当事件处理程序函数使用`this`引用其上下文时，你不能使用箭头函数（`() => {}`）。这些函数具有**词法上下文**。这意味着当 jQuery 尝试将上下文设置为触发事件的元素时，它不起作用。

# 利用事件上下文合并代码

我们刚刚完成的代码优化是**重构**的一个例子--修改现有代码以以更高效或更优雅的方式执行相同的任务。为了进一步探索重构机会，让我们看一下我们已经绑定到每个按钮的行为。`.removeClass()`方法的参数是可选的；当省略时，它会从元素中删除所有类。我们可以利用这一点稍微简化我们的代码，如下所示：

```js
$(() => {
  $('#switcher-default') 
    .addClass('selected') 
    .on('click', () => { 
      $('body').removeClass(); 
    });
  $('#switcher-narrow')
    .on('click', () => { 
      $('body')
        .removeClass()
        .addClass('narrow'); 
    }); 

  $('#switcher-large')
    .on('click', () => { 
      $('body')
        .removeClass()
        .addClass('large'); 
    }); 

  $('#switcher button')
    .on('click', function() { 
      $('#switcher button')
        .removeClass('selected'); 
      $(this)
        .addClass('selected'); 
    }); 
}); 

```

列表 3.5

请注意，操作顺序有些变化，以适应我们更一般的类移除；我们需要先执行`.removeClass()`，以免它撤消对`.addClass()`的调用，我们同时执行这个调用。

我们只能安全地删除所有类，因为在这种情况下我们负责 HTML。当我们编写可重用的代码（例如用于插件）时，我们需要尊重可能存在的任何类，并保持其不变。

现在我们在每个按钮的处理程序中执行一些相同的代码。这可以很容易地提取出来到我们的通用按钮`click`处理程序中：

```js
$(() => {
  $('#switcher-default')
    .addClass('selected'); 
  $('#switcher button')
    .on('click', function() { 
      $('body')
        .removeClass(); 
      $('#switcher button')
        .removeClass('selected'); 
      $(this)
        .addClass('selected'); 
    });

  $('#switcher-narrow')
    .on('click', () => { 
      $('body')
        .addClass('narrow'); 
    }); 

  $('#switcher-large')
    .on('click', () => { 
      $('body')
        .addClass('large'); 
    }); 
}); 

```

列表 3.6

请注意，现在我们需要将通用处理程序移到特定处理程序之前。`.removeClass()`调用需要在`.addClass()`执行之前发生，我们可以依赖于此，因为 jQuery 总是按照注册顺序触发事件处理程序。

最后，我们可以完全摆脱特定的处理程序，再次利用**事件上下文**。由于上下文关键字`this`给了我们一个 DOM 元素而不是 jQuery 对象，我们可以使用原生 DOM 属性来确定被点击的元素的 ID。因此，我们可以将相同的处理程序绑定到所有按钮上，并在处理程序内为每个按钮执行不同的操作：

```js
$(() => {
  $('#switcher-default')
    .addClass('selected'); 
  $('#switcher button')
    .on('click', function() { 
      const bodyClass = this.id.split('-')[1]; 
      $('body')
        .removeClass()
        .addClass(bodyClass); 
      $('#switcher button')
        .removeClass('selected'); 
      $(this)
        .addClass('selected'); 
    }); 
}); 

```

列表 3.7

`bodyClass`变量的值将是`default`、`narrow`或`large`，具体取决于点击了哪个按钮。在这里，我们有些偏离了以前的代码；当用户单击`<button id="switcher-default">`时，我们为`<body>`添加了一个`default`类。虽然我们不需要应用这个类，但它也没有造成任何损害，代码复杂性的减少完全弥补了一个未使用的类名。

# 快捷事件

绑定事件处理程序（如简单的`click`事件）是一项非常常见的任务，jQuery 提供了一个更简洁的方法来完成它；快捷事件方法与它们的`.on()`对应方法以更少的击键方式工作。

例如，我们的样式切换器可以使用`.click()`而不是`.on()`来编写，如下所示：

```js
$(() => {
  $('#switcher-default')
    .addClass('selected');

  $('#switcher button')
    .click(function() { 
      const bodyClass = this.id.split('-')[1]; 
      $('body')
        .removeClass()
        .addClass(bodyClass); 
      $('#switcher button')
        .removeClass('selected'); 
      $(this)
        .addClass('selected'); 
  }); 
}); 

```

列表 3.8

其他标准 DOM 事件（如`blur`、`keydown`和`scroll`）也存在类似的快捷事件方法。每个快捷方法都会使用相应的名称将处理程序绑定到事件上。

# 显示和隐藏页面元素

假设我们希望在不需要时能够隐藏我们的样式切换器。隐藏页面元素的一种方便方法是使它们可折叠。我们将允许单击标签一次来隐藏按钮，只留下标签。再次单击标签将恢复按钮。我们需要另一个类来隐藏按钮：

```js
.hidden { 
  display: none; 
} 

```

我们可以通过将按钮的当前状态存储在变量中，并在每次单击标签时检查其值，以了解是否应在按钮上添加或删除隐藏类来实现此功能。然而，jQuery 为我们提供了一种简单的方法，根据该类是否已经存在来添加或删除一个类——`.toggleClass()`方法：

```js
$(() => {
  $('#switcher h3')
    .click(function() {
      $(this)
        .siblings('button')
        .toggleClass('hidden');
    });
}); 

```

列表 3.9

第一次点击后，所有按钮都被隐藏了：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_03_04.png)

第二次点击然后将它们恢复到可见状态：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_03_05.png)

再次，我们依赖隐式迭代，这次是为了一举隐藏所有按钮——`<h3>`的兄弟节点。

# 事件传播

为了说明`click`事件能够作用于通常不可点击的页面元素的能力，我们制作了一个界面，没有显示出样式切换器标签——只是一个`<h3>`元素——实际上是页面中等待用户交互的*活动*部分。为了纠正这一点，我们可以给它一个鼠标悬停状态，清楚地表明它以某种方式与鼠标交互：

```js
.hover { 
  cursor: pointer; 
  background-color: #afa; 
} 

```

CSS 规范包括一个名为`:hover`的伪类，允许样式表在用户鼠标悬停在元素上时影响其外观。这在这种情况下肯定可以解决我们的问题，但是我们将利用这个机会介绍 jQuery 的`.hover()`方法，它允许我们使用 JavaScript 来改变元素的样式——事实上，执行任意操作——当鼠标光标进入元素时和离开元素时。

`.hover()`方法接受两个函数参数，与我们迄今为止遇到的简单事件方法不同。第一个函数将在鼠标光标进入所选元素时执行，第二个函数将在鼠标离开时执行。我们可以修改这些时间应用的类来实现鼠标悬停效果：

```js
$(() => { 
  $('#switcher h3')
    .hover(function() { 
      $(this).addClass('hover'); 
    }, function() { 
      $(this).removeClass('hover'); 
    }); 
}); 

```

列表 3.10

我们再次使用隐式迭代和事件上下文来编写简短简单的代码。现在当鼠标悬停在`<h3>`元素上时，我们看到我们的类被应用了：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_03_06.png)

使用`.hover()`还意味着我们避免了 JavaScript 中事件传播引起的头痛。要理解这一点，我们需要看一下 JavaScript 如何决定哪个元素可以处理给定事件。

# 事件的旅程

当页面上发生事件时，整个 DOM 元素层次结构都有机会处理事件。考虑以下页面模型：

```js
<div class="foo"> 
  <span class="bar"> 
    <a href="http://www.example.com/"> 
      The quick brown fox jumps over the lazy dog. 
    </a> 
  </span> 
  <p> 
    How razorback-jumping frogs can level six piqued gymnasts! 
  </p> 
</div> 

```

然后我们将代码可视化为一组嵌套元素：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_03_07.png)

对于任何事件，逻辑上都可能负责响应的多个元素。例如，当单击此页面上的链接时，`<div>`、`<span>`和`<a>`元素都应该有机会响应单击事件。毕竟，这三个元素都在用户鼠标指针下。另一方面，`<p>`元素根本不参与这个交互。

一种允许多个元素响应用户交互的策略称为**事件捕获**。使用事件捕获，事件首先传递给最全面的元素，然后逐渐传递给更具体的元素。在我们的示例中，这意味着首先传递事件给`<div>`元素，然后是`<span>`元素，最后是`<a>`元素，如下图所示：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_03_08.png)

相反的策略称为**事件冒泡**。事件被发送到最具体的元素，然后在此元素有机会响应后，事件向更一般的元素**冒泡**。在我们的示例中，`<a>`元素将首先处理事件，然后按顺序是`<span>`和`<div>`元素，如下图所示：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_03_09.png)

毫不奇怪，不同的浏览器开发者最初决定了不同的事件传播模型。最终开发的 DOM 标准规定应该同时使用这两种策略：首先从一般元素捕获事件到特定元素，然后事件冒泡回 DOM 树的顶部。可以为此过程的任一部分注册事件处理程序。

为了提供一致且易于理解的行为，jQuery 始终为模型的冒泡阶段注册事件处理程序。我们始终可以假设最具体的元素将首先有机会响应任何事件。

# 事件冒泡的副作用

事件冒泡可能会导致意外行为，特别是当错误的元素响应`mouseover`或`mouseout`事件时。考虑一个附加到我们示例中的`<div>`元素的`mouseout`事件处理程序。当用户的鼠标光标退出`<div>`元素时，`mouseout`处理程序按预期运行。由于这是在层次结构的顶部，没有其他元素获得事件。另一方面，当光标退出`<a>`元素时，`mouseout`事件被发送到该元素。然后，此事件将冒泡到`<span>`元素，然后到`<div>`元素，触发相同的事件处理程序。这种冒泡序列可能不是期望的。

`mouseenter`和`mouseleave`事件，无论是单独绑定还是结合在`.hover()`方法中，都意识到了这些冒泡问题，当我们使用它们来附加事件时，我们可以忽略由于错误的元素获取`mouseover`或`mouseout`事件而引起的问题。

刚刚描述的`mouseout`场景说明了限制事件范围的必要性。虽然`.hover()`处理了这种特殊情况，但我们将遇到其他需要在空间上（防止将事件发送到某些元素）或在时间上（在某些时间阻止事件发送）限制事件的情况。

# 改变旅程 - 事件对象

我们已经看到了一种情况，其中事件冒泡可能会引起问题。为了展示一种情况，`.hover()`不能帮助我们的情况，我们将更改我们之前实现的折叠行为。

假设我们希望扩大点击区域，触发样式切换器的折叠或展开。一种方法是将事件处理程序从标签`<h3>`移动到其包含的`<div>`元素中。在*列表 3.9*中，我们向`#switcher h3`添加了一个`click`处理程序；我们将尝试通过将处理程序附加到`#switcher`而不是附加到`#switcher`来进行此更改：

```js
$(() => {
  $('#switcher')
    .click(() => {
      $('#switcher button').toggleClass('hidden'); 
    }); 
}); 

```

列表 3.11

这种改变使得整个样式切换器区域都可点击以切换其可见性。缺点是点击按钮后，样式切换器也会折叠，这是因为事件冒泡；事件首先由按钮处理，然后通过 DOM 树传递，直到达到`<div id="switcher">`元素，在那里我们的新处理程序被激活并隐藏按钮。

要解决这个问题，我们需要访问`event`对象。这是一个传递给每个元素事件处理程序的 DOM 构造，当它被调用时。它提供了有关事件的信息，比如鼠标光标在事件发生时的位置。它还提供了一些可以用来影响事件在 DOM 中的进展的方法。

事件对象参考

有关 jQuery 对事件对象及其属性的实现的详细信息，请参见[`api.jquery.com/category/events/event-object/`](http://api.jquery.com/category/events/event-object/)。

要在处理程序中使用事件对象，我们只需要向函数添加一个参数：

```js
$(() => {
  $('#switcher')
    .click(function(event) { 
      $('#switcher button').toggleClass('hidden'); 
    }); 
}); 

```

请注意，我们将此参数命名为`event`是因为它具有描述性，而不是因为我们需要。将其命名为`flapjacks`或其他任何东西都可以正常工作。

# 事件目标

现在我们可以在处理程序中使用事件对象作为`event`。属性`event.target`可以帮助我们控制事件生效的*位置*。这个属性是 DOM API 的一部分，但在一些较旧的浏览器版本中没有实现；jQuery 根据需要扩展事件对象，以在每个浏览器中提供这个属性。通过`.target`，我们可以确定 DOM 中的哪个元素首先接收到事件。对于`click`事件，这将是实际点击的项。记住`this`给我们提供了处理事件的 DOM 元素，我们可以编写以下代码：

```js
$(() => {
  $('#switcher')
    .click(function(event) {
      if (event.target == this) { 
        $(this)
          .children('button')
          .toggleClass('hidden'); 
      } 
    }); 
}); 

```

列表 3.12

此代码确保所点击的项目是`<div id="switcher">`，而不是其子元素之一。现在，点击按钮将不会使样式切换器折叠，但点击切换器的背景*会*。然而，点击标签`<h3>`现在不起作用，因为它也是一个子元素。我们可以修改按钮的行为来达到我们的目标，而不是在这里放置这个检查。

# 阻止事件传播

事件对象提供了`.stopPropagation()`方法，它可以完全停止事件的冒泡过程。像`.target`一样，这个方法是基本的 DOM 特性，但使用 jQuery 实现会隐藏我们代码中的任何浏览器不一致性。

我们将删除我们刚刚添加的`event.target == this`检查，并在我们的按钮的`click`处理程序中添加一些代码：

```js
$(() => {
  $('#switcher')
    .click((e) => {
      $(e.currentTarget)
        .children('button')
        .toggleClass('hidden'); 
    }); 
}); 
$(() => {
  $('#switcher-default')
    .addClass('selected'); 
  $('#switcher button')
    .click((e) => { 
      const bodyClass = e.target.id.split('-')[1]; 

      $('body')
        .removeClass()
        .addClass(bodyClass); 
      $(e.target)
        .addClass('selected')
        .removeClass('selected'); 

      e.stopPropagation(); 
    }); 
}); 

```

列表 3.13

与以前一样，我们需要在我们用作`click`处理程序的函数中添加一个事件参数：`e`。然后，我们只需调用`e.stopPropagation()`来防止任何其他 DOM 元素对事件作出响应。现在我们的点击由按钮处理，只有按钮；在样式切换器的任何其他地方点击都会使其折叠或展开。

# 防止默认操作

如果我们的`click`事件处理程序是在一个链接元素(`<a>`)上注册的，而不是在一个表单之外的通用`<button>`元素上，我们将面临另一个问题。当用户点击链接时，浏览器会加载一个新页面。这种行为不是我们讨论的事件处理程序的一部分；相反，这是单击链接元素的默认操作。同样，当用户在编辑表单时按下*Enter*键时，可能会在表单上触发`submit`事件，但此后实际上会发生表单提交。

如果这些默认操作是不希望的，调用事件上的`.stopPropagation()`将无济于事。这些操作不会发生在事件传播的正常流程中。相反，`.preventDefault()`方法用于在触发默认操作之前立即停止事件。

在对事件环境进行一些测试后调用`.preventDefault()`通常是有用的。例如，在表单提交期间，我们可能希望检查必填字段是否已填写，并且仅在它们未填写时阻止默认操作。对于链接，我们可以在允许`href`被跟踪之前检查某些前提条件，从本质上讲，在某些情况下禁用链接。

事件传播和默认操作是独立的机制；其中之一可以在另一个发生时停止。如果我们希望同时停止两者，我们可以在事件处理程序的末尾返回`false`，这是对事件同时调用`.stopPropagation()`和`.preventDefault()`的快捷方式。

# 事件委托

事件冒泡并不总是一种阻碍；我们经常可以将其利用到极大的好处中。利用冒泡的一种伟大技术称为**事件委托**。通过它，我们可以使用单个元素上的事件处理程序来完成许多工作。

在我们的示例中，只有三个带有附加`click`处理程序的`<button>`元素。但是如果有多于三个呢？这比你想象的更常见。例如，考虑一个包含每行都有一个需要`click`处理程序的交互项的大型信息表格。隐式迭代使得分配所有这些`click`处理程序变得容易，但性能可能会因为 jQuery 内部的循环和维护所有处理程序的内存占用而受到影响。

相反，我们可以将单个`click`处理程序分配给 DOM 中的祖先元素。由于事件冒泡，无间断的`click`事件最终将到达祖先元素，我们可以在那里完成我们的工作。

举个例子，让我们将这种技术应用于我们的样式切换器（即使项目数量不需要这种方法）。如前面所见的*清单 3.12*，我们可以使用`e.target`属性来检查在发生`click`事件时鼠标光标下的哪个元素。

```js
$(() => { 
  $('#switcher')
    .click((e) => {
      if ($(event.target).is('button')) { 
        const bodyClass = e.target.id.split('-')[1]; 

        $('body')
          .removeClass()
          .addClass(bodyClass); 
        $(e.target)
          .addClass('selected')
          .removeClass('selected'); 

        e.stopPropagation(); 
      }   
    }); 
}); 

```

清单 3.14

我们在这里使用了一个新方法叫做`.is()`。该方法接受我们在上一章中研究的选择器表达式，并测试当前 jQuery 对象是否与选择器匹配。如果集合中至少有一个元素与选择器匹配，`.is()`将返回`true`。在这种情况下，`$(e.target).is('button')`询问被点击的元素是否是一个`<button>`元素。如果是，我们将继续以前的代码，但有一个重大变化：关键字`this`现在指的是`<div id="switcher">`，所以每次我们感兴趣的是点击的按钮时，现在必须使用`e.target`来引用它。

.is() 和 .hasClass()

我们可以使用`.hasClass()`测试元素上类的存在。然而，`.is()`方法更灵活，可以测试任何选择器表达式。

但是，从这段代码中我们还有一个意外的副作用。现在，当单击按钮时，切换器会折叠，就像我们在添加调用`.stopPropagation()`之前的情况一样。切换器可见性切换器的处理程序现在绑定到与按钮的处理程序相同的元素上，因此停止事件冒泡不会阻止切换器触发。为了避开这个问题，我们可以删除`.stopPropagation()`调用，并且改为添加另一个`.is()`测试。另外，由于我们使整个切换器`<div>`元素可点击，所以应该在用户的鼠标位于其任何部分时切换`hover`类：

```js
$(() => {
  const toggleHover = (e) => {
    $(e.target).toggleClass('hover');
  };

  $('#switcher')
    .hover(toggleHover, toggleHover);
});

$(() => {
  $('#switcher')
    .click((e) => {
      if (!$(e.target).is('button')) {
        $(e.currentTarget)
          .children('button')
          .toggleClass('hidden');
      }
    });
});

$(() => {
  $('#switcher-default')
    .addClass('selected');
  $('#switcher')
    .click((e) => {
      if ($(e.target).is('button')) {
        const bodyClass = e.target.id.split('-')[1];

        $('body')
          .removeClass()
          .addClass(bodyClass);
        $(e.target)
          .addClass('selected')
          .siblings('button')
          .removeClass('selected');
      }
  });
});

```

**清单 3.15**

这个例子在大小上有点复杂了，但是随着具有事件处理程序的元素数量的增加，事件委托的好处也会增加。此外，通过组合两个`click`处理程序并使用单个`if-else`语句进行`.is()`测试，我们可以避免一些代码重复：

```js
$(() => {
  $('#switcher-default')
    .addClass('selected'); 
  $('#switcher')
    .click((e) => {
      if ($(e.target).is('button')) { 
        const bodyClass = e.target.id.split('-')[1]; 
        $('body')
          .removeClass()
          .addClass(bodyClass); 
        $(e.target)
          .addClass('selected')
          .removeClass('selected'); 
      } else { 
        $(e.currentTarget)
          .children('button')
          .toggleClass('hidden'); 
      } 
    }); 
}); 

```

**清单 3.16**

虽然我们的代码仍然需要一些微调，但它已经接近我们可以放心使用它的状态了。尽管如此，为了更多地了解 jQuery 的事件处理，我们将回到 *清单 3.15* 并继续修改该版本的代码。

事件委托在我们稍后会看到的其他情况下也很有用，比如当通过 DOM 操作方法（第五章，*操作 DOM*）或 Ajax 例程（第六章，*使用 Ajax 发送数据*）添加新元素时。

# 使用内置的事件委托功能

因为事件委托在很多情况下都很有用，jQuery 包含了一组工具来帮助开发者使用这个技术。我们已经讨论过的`.on()`方法可以在提供适当参数时执行事件委托：

```js
$(() => {
  $('#switcher-default')
    .addClass('selected');
  $('#switcher')
   .on('click', 'button', (e) => {
     const bodyClass = e.target.id.split('-')[1];

     $('body')
       .removeClass()
       .addClass(bodyClass);
     $(e.target)
       .addClass('selected')
       .siblings('button')
       .removeClass('selected');

     e.stopPropagation();
   })
   .on('click', (e) => {
     $(e.currentTarget)
       .children('button')
       .toggleClass('hidden');
   });
});

```

**清单 3.17**

现在看起来很不错了。对于切换器功能中的所有点击事件，我们有两个非常简单的处理程序。我们在`.on()`方法中添加了一个选择器表达式作为第二个参数。具体来说，我们要确保将点击事件上升到`#switch`的任何元素实际上都是按钮元素。这比在事件处理程序中编写一堆逻辑来根据生成它的元素处理事件更好。

我们确实不得不添加一个调用`e.stopPropagation()`的方法。原因是为了使第二个点击处理程序，即处理切换按钮可见性的处理程序，无需担心检查事件来自何处。通常防止事件传播比在事件处理程序代码中引入边缘情况处理更容易。

经过一些小的折衷，我们现在有了一个单一的按钮点击处理函数，它可以处理 3 个按钮，也可以处理 300 个按钮。就是这些小细节使得 jQuery 代码能够很好地扩展。

我们将在第十章，*高级事件*中全面讨论`.on()`的使用。

# 移除事件处理程序

有时候我们会完成之前注册的事件处理程序。也许页面的状态已经改变，使得这个动作不再合理。我们可以在事件处理程序内部使用条件语句处理这种情况，但是完全解绑处理程序会更加优雅。

假设我们希望我们的可折叠样式切换器在页面不使用正常样式时保持展开。当选择窄列或大号字按钮时，单击样式切换器的背景应该没有任何效果。我们可以通过调用 `.off()` 方法来在点击非默认样式切换器按钮时移除折叠处理程序来实现这一点：

```js
$(() => {
  $('#switcher')
    .click((e) => {
      if (!$(e.target).is('button')) {
        $(e.currentTarget)
          .children('button')
          .toggleClass('hidden');
      }
    });
  $('#switcher-narrow, #switcher-large')
    .click(() => {
      $('#switcher').off('click');
    });
});

```

图 3.18

现在当单击诸如窄列之类的按钮时，样式切换器 `<div>` 上的 `click` 处理程序被移除，单击框的背景不再使其折叠。然而，按钮不再起作用！它们也受到样式切换器 `<div>` 的 `click` 事件影响，因为我们重写了按钮处理代码以使用事件委托。这意味着当我们调用 `$('#switcher').off('click')` 时，两种行为都被移除。

# 给事件处理程序命名空间

我们需要使我们的 `.off()` 调用更加具体，以便不移除我们注册的两个点击处理程序。一种方法是使用**事件** **命名空间**。当事件绑定时，我们可以引入附加信息，以便稍后识别特定的处理程序。要使用命名空间，我们需要返回到绑定事件处理程序的非简写方法，即 `.on()` 方法本身。

我们传递给 `.on()` 的第一个参数是我们要监听的事件的名称。在这里，我们可以使用一种特殊的语法，允许我们对事件进行子分类：

```js
$(() => {
  $('#switcher')
    .on('click.collapse', (e) => {
      if (!$(e.target).is('button')) {
        $(e.currentTarget)
          .children('button')
          .toggleClass('hidden');
      }
    });
  $('#switcher-narrow, #switcher-large')
   .click(() => {
     $('#switcher').off('click.collapse');
   });
}); 

```

图 3.19

`.collapse` 后缀对事件处理系统不可见；`click` 事件由此函数处理，就像我们写了`.on('click')`一样。然而，添加命名空间意味着我们可以解绑这个处理程序而不影响我们为按钮编写的单独的 `click` 处理程序。

还有其他使我们的 `.off()` 调用更加具体的方法，我们马上就会看到。然而，事件命名空间是我们工具库中一个有用的工具。在后面的章节中，我们会看到它在插件的创建中是特别方便的。

# 重新绑定事件

现在单击窄列或大号字按钮会导致样式切换器折叠功能被禁用。然而，当单击默认按钮时，我们希望行为恢复。为了做到这一点，我们需要在单击默认按钮时**重新绑定**处理程序。

首先，我们应该给我们的处理程序函数一个名称，这样我们就可以多次使用它而不重复自己：

```js
$(() => {
  const toggleSwitcher = (e) => {
    if (!$(e.target).is('button')) {
      $(e.currentTarget)
        .children('button')
        .toggleClass('hidden');
    }
  };

  $('#switcher')
    .on('click.collapse', toggleSwitcher);
  $('#switcher-narrow, #switcher-large')
    .click((e) => {
      $('#switcher').off('click.collapse');
    });
});

```

图 3.20

请记住，我们正在将`.on()`的第二个参数传递给一个**函数引用**。在引用函数时，重要的是要记住在函数名后省略括号；括号会导致调用函数而不是引用函数。

现在`toggleSwitcher()`函数已经被引用，我们可以在稍后再次绑定它，而无需重复函数定义：

```js
$(() => {
  const toggleSwitcher = (e) => {
    if (!$(e.target).is('button')) {
      $(e.currentTarget)
        .children('button')
        .toggleClass('hidden');
    }
  };

  $('#switcher').on('click.collapse', toggleSwitcher);
  $('#switcher-narrow, #switcher-large')
    .click(() => {
      $('#switcher').off('click.collapse');
    });
  $('#switcher-default')
    .click(() => {
      $('#switcher').on('click.collapse', toggleSwitcher);
    });
}); 

```

列表 3.21

现在，切换行为在文档加载时绑定，在点击“Narrow Column”或“Large Print”后取消绑定，并在此后再次点击“Default”时重新绑定。

由于我们已经命名了函数，因此不再需要使用命名空间。`.off()`方法可以接受一个函数作为第二个参数；在这种情况下，它只取消绑定那个特定的处理程序。但是，我们遇到了另一个问题。请记住，当在 jQuery 中将处理程序绑定到事件时，之前的处理程序仍然有效。在这种情况下，每次点击“Default”时，都会向样式切换器绑定`toggleSwitcher`处理程序的另一个副本。换句话说，每次额外点击，该函数都会多调用一次，直到用户点击“Narrow”或“Large Print”，这样一次性取消所有`toggleSwitcher`处理程序。

当绑定了偶数个`toggleSwitcher`处理程序时，在样式切换器上（而不是在按钮上）点击似乎没有效果。实际上，`hidden`类被多次切换，最终处于与开始时相同的状态。为了解决这个问题，当用户点击*任何*按钮时，我们可以取消绑定处理程序，并且只在确保点击的按钮的 ID 为`switcher-default`后再次绑定：

```js
$(() => {
  const toggleSwitcher = (e) => {
    if (!$(e.target).is('button')) {
      $(e.currentTarget)
        .children('button')
        .toggleClass('hidden');
    }
  };

  $('#switcher')
    .on('click', toggleSwitcher);
  $('#switcher button')
    .click((e) => {
      $('#switcher').off('click', toggleSwitcher);

      if (e.target.id == 'switcher-default') {
        $('#switcher').on('click', toggleSwitcher);
      }
    });
});

```

列表 3.22

在我们希望在事件触发后立即取消绑定事件处理程序的情况下，也有一个快捷方式可用。这个快捷方式称为`.one()`，用法如下：

```js
$('#switcher').one('click', toggleSwitcher); 

```

这会导致切换操作仅发生一次。

# 模拟用户交互

有时，即使事件不是直接由用户输入触发，执行我们绑定到事件的代码也很方便。例如，假设我们希望我们的样式切换器以折叠状态开始。我们可以通过从样式表中隐藏按钮，或者通过添加我们的`hidden`类或从`$(() => {})`处理程序调用`.hide()`方法来实现这一点。另一种方法是模拟点击样式切换器，以触发我们已经建立的切换机制。

`.trigger()`方法允许我们做到这一点：

```js
$(() => { 
  $('#switcher').trigger('click'); 
}); 

```

列表 3.23

当页面加载时，开关器的状态会折叠起来，就好像它已经被点击一样，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_03_10.png)

如果我们要隐藏希望禁用 JavaScript 的人看到的内容，这将是实现**优雅降级**的一个合理方式。尽管，这在如今非常不常见。

`.trigger()` 方法提供了与 `.on()` 相同的快捷方法。当这些快捷方式没有参数时，行为是触发操作而不是绑定它：

```js
$(() => {
  $('#switcher').click(); 
}); 

```

例 3.24

# 对键盘事件的反应

另一个例子，我们可以向我们的样式切换器添加键盘快捷方式。当用户键入其中一个显示样式的第一个字母时，我们将使页面表现得就像相应的按钮被点击一样。要实现此功能，我们需要探索**键盘事件**，它们与**鼠标事件**的行为有些不同。

有两种类型的键盘事件：直接对键盘做出反应的事件（`keyup` 和 `keydown`）以及对文本输入做出反应的事件（`keypress`）。单个字符输入事件可能对应多个键，例如，当*Shift*键与*X*键结合创建大写字母*X*时。虽然具体的实现细节因浏览器而异（不出所料），但一个安全的经验法则是：如果你想知道用户按下了什么键，你应该观察 `keyup` 或 `keydown` 事件；如果你想知道最终在屏幕上呈现了什么字符，你应该观察 `keypress` 事件。对于这个功能，我们只想知道用户何时按下了*D*、*N* 或 *L* 键，所以我们将使用 `keyup`。

接下来，我们需要确定哪个元素应该监听事件。这对于鼠标事件来说不太明显，因为我们有一个可见的鼠标光标来告诉我们事件的目标。相反，键盘事件的目标是当前具有**键盘焦点**的元素。焦点元素可以通过多种方式进行更改，包括使用鼠标点击和按下*Tab*键。而且，并非每个元素都可以获得焦点；只有具有默认键盘驱动行为的项，如表单字段、链接和具有 `.tabIndex` 属性的元素，才是候选项。

在这种情况下，我们并不真的关心哪个元素获得了焦点；我们希望我们的切换器在用户按下这些键时起作用。事件冒泡将再次派上用场，因为我们可以将我们的 `keyup` 事件绑定到 `document` 元素，并确保最终任何键事件都会冒泡到我们这里来。

最后，当我们的 `keyup` 处理程序被触发时，我们需要知道按下了哪个键。我们可以检查 `event` 对象来获取这个信息。事件的 `.which` 属性包含了按下的键的标识符，对于字母键，这个标识符是大写字母的 ASCII 值。有了这个信息，我们现在可以创建一个字母及其相应按钮的**对象文本**。当用户按下一个键时，我们将查看它的标识符是否在映射中，如果是，就触发点击：

```js
$(() => {
  const triggers = {
    D: 'default',
    N: 'narrow',
    L: 'large'
  };

  $(document)
    .keyup((e) => {
      const key = String.fromCharCode(e.which);

      if (key in triggers) {
        $(`#switcher-${triggers[key]}`).click();
      }
    });
});

```

例 3.25

连续按下这三个键现在模拟了对按钮的鼠标点击操作——前提是键盘事件没有被诸如 Firefox 在我开始输入时搜索文本这样的功能所中断。

作为使用`.trigger()`模拟此点击的替代方案，让我们探讨如何将代码因子化为一个函数，以便多个处理程序可以调用它——在这种情况下，`click`和`keyup`处理程序都可以调用它。虽然在本例中并不必要，但这种技术可以有助于消除代码的冗余：

```js
$(() => {
  // Enable hover effect on the style switcher
  const toggleHover = (e) => {
    $(e.target).toggleClass('hover');
  };

  $('#switcher').hover(toggleHover, toggleHover);

  // Allow the style switcher to expand and collapse.
  const toggleSwitcher = (e) => {
    if (!$(e.target).is('button')) {
      $(e.currentTarget)
        .children('button')
        .toggleClass('hidden');
    }
  };

  $('#switcher')
    .on('click', toggleSwitcher)
    // Simulate a click so we start in a collaped state.
    .click();

  // The setBodyClass() function changes the page style.
  // The style switcher state is also updated.
  const setBodyClass = (className) => {
    $('body')
      .removeClass()
      .addClass(className);

    $('#switcher button').removeClass('selected');
    $(`#switcher-${className}`).addClass('selected');
    $('#switcher').off('click', toggleSwitcher);

    if (className == 'default') {
      $('#switcher').on('click', toggleSwitcher);
    }
  };

  // Begin with the switcher-default button "selected"
  $('#switcher-default').addClass('selected');

  // Map key codes to their corresponding buttons to click
  const triggers = {
    D: 'default',
    N: 'narrow',
    L: 'large'
  };

  // Call setBodyClass() when a button is clicked.
  $('#switcher')
    .click((e) => {
      if ($(e.target).is('button')) {
        setBodyClass(e.target.id.split('-')[1]);
      }
    });

  // Call setBodyClass() when a key is pressed.
  $(document)
    .keyup((e) => {
      const key = String.fromCharCode(e.which);

      if (key in triggers) {
        setBodyClass(triggers[key]);
      }
    });
}); 

```

列表 3.26

最终修订版将本章所有先前的代码示例整合在一起。我们将整个代码块移入一个单独的`$(() => {})`处理程序，并使我们的代码不那么冗余。

# 摘要

本章讨论的功能使我们能够对各种用户驱动和浏览器启动的事件作出反应。我们已经学会了如何在页面加载时安全执行操作，如何处理鼠标事件（如单击链接或悬停在按钮上），以及如何解释按键。

此外，我们已经深入研究了事件系统的一些内部工作原理，并可以利用这些知识进行事件委托和更改事件的默认行为。我们甚至可以模拟用户发起事件的效果。

我们可以利用这些功能来构建交互式页面。在下一章中，我们将学习如何在这些交互过程中为用户提供视觉反馈。

# 进一步阅读

事件处理的主题将在第十章“高级事件”中更详细地探讨。jQuery 的事件方法的完整列表可在本书的附录 C 中找到，或者在官方 jQuery 文档中找到：[`api.jquery.com/`](http://api.jquery.com/)。

# 练习

挑战练习可能需要使用官方 jQuery 文档：[`api.jquery.com/`](http://api.jquery.com/)。

1.  当点击查尔斯·狄更斯时，应用`selected`样式。

1.  双击章标题（`<h3 class="chapter-title">`）时，切换章节文本的可见性。

1.  当用户按下右箭头键时，循环到下一个`body`类。右箭头键的键码为`39`。

1.  挑战：使用`console.log()`函数记录鼠标在任何段落上移动时的坐标。（注意：`console.log()`通过 Firefox 的 Firebug 扩展、Safari 的 Web Inspector 或 Chrome 或 Internet Explorer 的开发者工具显示其结果）。

1.  挑战：使用`.mousedown()`和`.mouseup()`来跟踪页面上任何位置的鼠标事件。如果鼠标按钮在按下的地方*上方*释放，将`hidden`类添加到所有段落。如果在按下的地方*下方*释放，将从所有段落中移除`hidden`类。
