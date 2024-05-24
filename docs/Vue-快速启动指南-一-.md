# Vue 快速启动指南（一）

> 原文：[`zh.annas-archive.org/md5/056a1fe7509ea158cc95e0fe373880b7`](https://zh.annas-archive.org/md5/056a1fe7509ea158cc95e0fe373880b7)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

直到几年前，直接 DOM 操作是前端开发的标准，jQuery 一直引领潮流。所有这一切都随着现代 JavaScript 库和框架的普及而开始改变，主要是 Angular 和 React。然后，在 2014 年 2 月，Vue 发布了初始版本。

由于大型 IT 公司都支持 Angular 和 React，Vue 如何确立自己的地位并不清楚。最初由单个开发者 Evan You 开发，在短短四年内，没有公司支持的情况下，Vue 从一个单个开发者的有趣小项目发展成了大公司的不太可能的竞争对手，拥有 300 多名贡献者。这不再是一个人的表演。

如今，NASA、GitLab、阿里巴巴、Grammarly、WizzAir、EuroNews、小米、Adobe、Behance、任天堂、Chess.com 等都在使用 Vue。

结论？Vue 会一直存在。虽然人们可能会讨论到底是更好地学习 Elm，还是 React，还是 Angular，还是 Ember，或者完全不同的东西，但这种讨论基本上是无关紧要的。每个库和框架都有一些可提供的东西，最终，只是试用一下，看看它是否适合你。

我们开发人员需要接受必须跟上技术潮流的必要性，并接受学习新框架和范式只是我们职业生涯的一部分这一事实。因此，问题不是我们应该学习 Vue，还是学习其他经过考验和证明的技术。

Vue 已经取得了它的地位，并且正在与大公司同台竞技。唯一的问题是，“我该如何高效地学习它？”这本书就是试图回答这个问题。

# 这本书适合谁

这本书面向没有使用 Vue 或其他 VDOM JavaScript 库经验的初学者到中级前端开发人员。读者具有一些 JavaScript 和 CSS 知识将会有所帮助。它旨在迅速让读者了解 Vue 的设置方式以及其各个部分是如何协同工作的。它旨在简洁地为您概述几乎整个 Vue 领域，并提供大量示例。

这本书的目标很简单 - 快速高效地向您介绍 Vue，并让您轻松进入框架，而不需要大量的时间和精力投入。预期结果是，通过阅读本书，您将获得巨大的投资回报 - 获得足够的框架实际知识，以至于在您阅读本书的时间不长之后，您就有信心去应对一些更高级的 Vue 项目和概念。

# 本书涵盖的内容

第一章，“介绍 Vue”，讨论了 Vue 是什么，并开始使用 mustache 模板。我们探讨了 Vue 解决的问题以及使用 Vue 的原因。

第二章，“Vue 2 的基本概念”，讨论了响应性、计算属性和方法。我们还介绍了组件、模板、props、watchers 和生命周期钩子。

第三章，“使用 Vue-CLI、组件、Props 和插槽”，展示了如何安装 vue-cli 以及如何设置代码编辑器以更有效地使用 Vue。我们检查了基于 vue-cli 的项目结构，看看如何向子组件添加基本功能，并学习了如何将数据从子组件传递到父组件。

第四章，“过滤器和混入”，描述了如何使用过滤器。我们看看语法、用例和一些示例。我们还研究了如何使用混入。

第五章，“制作自己的指令和插件”，探讨了通过制作自定义指令来扩展 Vue 的方法。我们还从头开始构建自己的插件，并学习如何通过 npm 发布它。

第六章，“过渡和动画”，逐步引导读者比较 CSS 过渡和 CSS 动画，了解它们之间的区别以及如何开始将它们与 Vue 集成。然后，我们讨论了在 Vue 中组织过渡和动画的多种方式 - 使用过渡和过渡组件、使用过渡钩子作为 CSS 类、使用命名过渡钩子以及使用 JavaScript 过渡钩子。

第七章，*使用 Vuex*，从零开始向读者展示了状态的真正含义以及其重要性。它还解释了为什么需要存储中心化状态以及其内部工作原理。我们还会尝试一些代码示例，从这个中心化存储中控制我们的应用程序。

第八章，*使用 Nuxt.js 和 Vue-Router*，描述了单页应用程序的工作原理，它们存在的问题，以及如何通过服务器端渲染和代码拆分来克服这些问题。然后，我们将看到如何使用几个页面和一些添加的过渡效果构建一个非常简单的 Nuxt.js 应用程序。

# 为了从这本书中获得最大收益

如果您能做到以下几点，这本书将对您最有帮助：

+   编写基本的 HTML、CSS 和 JavaScript 代码

+   大致了解互联网和浏览器的工作原理

+   有一些使用代码编辑器和控制台程序的经验

+   愿意下载示例（或从 CodePen 中派生）

本书中的 JavaScript 代码大多以 ES5 编写，但随着书的进展，有时也会出现 ES6。之所以使用 ES5，是因为不假定读者了解 ES6 语法。同样，也不假定读者以前没有使用过它——因此，做出了一个妥协：不专注于 ES6 的特性，但也不完全忽视它们。作者认为，这种方法将把重点转移到重要的地方：理解 Vue。

# 下载示例代码文件

您可以从您在[www.packt.com](http://www.packt.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了这本书，您可以访问[www.packt.com/support](http://www.packt.com/support)并注册，以便文件直接发送到您的邮箱。

您可以按照以下步骤下载代码文件：

1.  在[www.packt.com](http://www.packt.com)上登录或注册。

1.  选择“支持”选项卡。

1.  单击“代码下载和勘误”。

1.  在搜索框中输入书名并按照屏幕上的说明操作。

下载文件后，请确保使用最新版本的解压缩软件解压缩文件夹。

+   WinRAR/7-Zip 适用于 Windows

+   Zipeg/iZip/UnRarX 适用于 Mac

+   7-Zip/PeaZip 适用于 Linux

该书的代码包也托管在 GitHub 上：[`github.com/PacktPublishing/Vue.js-Quick-Start-Guide`](https://github.com/PacktPublishing/Vue.js-Quick-Start-Guide)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还有来自丰富图书和视频目录的其他代码包，可在**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**上找到。去看看吧！

# 下载彩色图片

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图片。您可以在这里下载：[`www.packtpub.com/sites/default/files/downloads/9781789344103_ColorImages.pdf`](https://www.packtpub.com/sites/default/files/downloads/9781789344103_ColorImages.pdf)。

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 用户名。例如："将下载的`WebStorm-10*.dmg`磁盘映像文件挂载为系统中的另一个磁盘。"

代码块设置如下：

```js
...
data: {
  // the model goes here
}
...
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项将以粗体显示：

```js
div,.thetemplate {
  font-size: 30px;
  padding: 20px;
  color: limegreen;
  font-family: Arial;
```

任何命令行输入或输出都以以下方式编写：

```js
cd quickstart-vue
```

**粗体**：表示新术语、重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会以这种方式出现在文本中。例如："从管理面板中选择系统信息。"

警告或重要提示会以这种方式出现。技巧和窍门会以这种方式出现。


# 第一章：介绍 Vue

在本章中，我们将探讨如何开始学习 Vue 2。本章将向您展示快速入门的最简单方法，以及如何借助可用的 SaaS 平台轻松跟踪您的进度。

我们还将探讨 Vue 为什么变得如此受欢迎，以及为什么我们应该使用它。

此外，我们将讨论 Vue 的基本构建模块：mustache 模板、指令、修饰符、方法和计算属性。

在此过程中，我们将看到许多实际的例子。让我们首先看看 Vue 到底是什么。

在本章中，我们将看一下以下主题：

+   什么是 Vue？

+   Vue 解决了哪些问题？

+   为什么使用 Vue？

# 什么是 Vue？

Vue 是一个简单易用的 JS 框架，于 2013 年出现。它成功地将一些优秀的想法从 Angular 和 React 中提取出来，并结合在一个易于使用的包中。

与其他流行的前端框架相比，Vue 在简单性和易用性方面表现出色。

让我们看看如何开始使用它。

# 开始使用 Vue2 的最快方法

在过去的十年里，很多用于网页开发的工具已经转移到了网络上，所以让我们顺应潮流，在[`codepen.io/`](http://codepen.io/)上开始一个新的项目。

您不必成为[`codepen.io/`](https://codepen.io/)的成员才能在那里创建项目——您可以使用用户名`Captain Anonymous`保存它们。但最好还是注册一个账户，这样您的所有实验都在一个地方。

一旦您将浏览器导航到[`codepen.io`](https://codepen.io)，您将看到以下屏幕：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-qk-st-gd/img/a22c888d-87fc-45c2-a410-f1a05a28556b.png)

点击创建下拉菜单（在主导航栏中，位于屏幕右上角），然后点击新建项目。一旦您这样做了，您将看到默认的编辑器设置：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-qk-st-gd/img/054f991f-fa02-48c4-8f43-a86eb87133c1.png)

接下来，点击屏幕右上角的设置按钮，在弹出的窗口中选择 JavaScript：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-qk-st-gd/img/75cbf157-55fa-4267-b981-c4216eeaf22e.png)

接下来，在快速添加下拉字段中，选择 Vue 选项。一旦您这样做了，第一个输入框将填写当前的 Vue 的压缩版本，它是从 Cloudflare CDN 提供的，或者更具体地说，是从这个链接提供的：[`cdnjs.cloudflare.com/ajax/libs/vue/2.5.13/vue.min.js`](https://cdnjs.cloudflare.com/ajax/libs/vue/2.5.13/vue.min.js)。

就是这样！我们已经准备好在我们的 Codepen 项目中开始使用 Vue2 了。

关于 Vue 要理解的一件事是，它使我们的 HTML 动态化。这是通过添加**胡须语法**来实现的。这种语法非常容易理解。我们只需将其插入到 HTML 元素中。例如，我们可以像这样向`h1`标签添加胡须语法：

```js
<h1>{{ heading1 }}</h1>
```

因此，让我们详细了解一下这是如何工作的。随意在您自己的 pen 上工作或在此处查看示例：[`codepen.io/AjdinImsirovic/pen/rKYyvE`](https://codepen.io/AjdinImsirovic/pen/rKYyvE)。

# 胡须模板示例

让我们开始使用我们的第一个 pen：

```js
<div id="entryPoint">
  <h1>Just an h1 heading here</h1>
  <h2>Just an h2 heading here</h2>
  <p>Vue JS is fun</p>
</div>
```

我们现在可以在 CodePen 预览窗格中看到我们的 HTML 正在呈现，屏幕上打印出以下文本：

```js
Just an h1 heading here Just an h2 heading here Vue JS is fun
```

请注意，CodePen 应用程序通常会在不保存的情况下更新预览窗格，这比刷新浏览器要好得多——在本地项目上工作时必须这样做。尽管如此，经常保存您的 CodePen 项目是很好的，以免丢失任何更改（在浏览器冻结或发生其他异常情况时）。

接下来，让我们将以下 Vue 代码添加到我们 pen 内部的 JS 窗格中：

```js
new Vue({
  el: '#entryPoint',
  data: {
     heading1: 'Just an h1 heading here',
     heading2: 'heading 2 here',
     paragraph1: 'Vue JS'
  }
})
```

最后，让我们更新 HTML，以便 Vue 代码可以发挥其魔力：

```js
<div id="entryPoint">
  <h1>{{ heading1 }}</h1>
  <h2>Just an {{ heading2 }}</h2>
  <p>{{paragraph1}} is fun</p>
</div>
```

在前面的代码示例中，我们可以看到我们如何使用胡须模板将数据动态插入到我们的 HTML 中。

通过简单地将数据对象的键传递到我们的 HTML 标记中，并用开放的`{{`和关闭的`}}`标记将键括起来，可以实现胡须模板。

如前所述，CodePen 将自动更新预览窗格，但这不会影响预览，因为我们实际上产生的输出与我们仅使用纯 HTML 时所做的输出相同。

现在我们可以通过简单地更改数据输入中的键值对来玩耍：

```js
new Vue({
  el: '#entryPoint',
  data: {
     heading1: 'This is an h1',
     heading2: 'h2 heading',
     paragraph1: 'Vue2'
  }
})
```

这次，输出将自动更新为这样：

这是一个 h1

只是一个 h2 标题

Vue2 很有趣

我们也可以更改我们的入口点。例如，我们可以让 Vue 只访问`p`标签：

```js
new Vue({
  el: 'p',
  data: {
     heading1: 'This is an h1',
     //heading2: 'h2 heading',
     paragraph1: 'Vue2'
  }
})
```

更改后，我们的预览窗格将显示以下内容：

{{ heading1 }}

只是一个{{ heading2 }}

Vue2 很有趣

从这个输出中，我们可以得出结论，如果发生以下任何一种情况，我们的胡须模板将被呈现为常规文本：

+   我们的入口点没有引用数据

+   我们的数据中不存在的输入

我们还看到了我们的入口点可以是任何类型的选择器。您可以将其视为类似于在 jQuery 中定位不同的元素。

例如，我们可以将更复杂的选择器作为我们应用的入口点：

```js
new Vue({
  el: 'div#entryPoint',
  data: {
     heading1: 'This is an h1',
     heading2: 'h2 heading',
     paragraph1: 'Vue2'
  }
})
```

# 使用 Vue 的数据选项作为函数

请注意，我们的 Vue 实例的`data`选项可以是对象，也可以是函数。数据作为对象的示例可以在先前的代码中看到。使用数据作为函数也很容易。

数据作为对象与可重用组件不兼容。因此，通常来说，将数据作为函数使用是使用 Vue 中数据选项的更有用的方式。

让我们看另一个笔记。这次，我们将使用数据选项作为函数，而不是作为对象。笔记在这里：[`codepen.io/AjdinImsirovic/pen/aKVJgd`](https://codepen.io/AjdinImsirovic/pen/aKVJgd)。我们唯一要做的改变是我们的 Vue 代码：

```js
new Vue({
  el: '#entryPoint',
  data() {
    return {
     heading1: 'Just an h1 heading here',
     heading2: 'heading 2 here',
     paragraph1: 'Vue JS data as a function'
    }
  }
})
```

现在我们熟悉了 Vue 语法的基础知识，让我们看看它可以用来做什么。

# Vue 解决了什么问题？

不打算列出一个详尽的清单，让我们快速地强调一些 Vue 最大的优点：

+   Vue——jQuery 的继任者？

+   Vue 对于初学者来说是一个很好的学习工具

+   Vue 是一个多才多艺和渐进的框架

+   Vue 是一个用于动画和交互的很棒的工具

+   Vue 的方法与其他现代前端框架和库类似

接下来，让我们简要地概述每一点。

# Vue，jQuery 的继任者

著名的 jQuery 库于 2006 年出现。当它出现时，它做了一些非常好的事情：

+   它使得编写跨浏览器的 JavaScript 变得更容易，这在当时是一个很大的优势，因为它大大减少了开发人员处理各种浏览器怪癖和不一致性的需求

+   它有一个简单的语法，使得更容易定位和操作特定的 DOM 节点，这在他们的座右铭“写得更少，做得更多”中表达得很好

+   它是学习 JavaScript 的绝佳入门点

+   它有一个很棒的 API，使得使用 Ajax 变得简单和容易

然而，自那时以来发生了很多变化，变得更好了。

可以说，2006 年至今在 JavaScript 领域发生的最大改进是虚拟 DOM。

虚拟 DOM 是一种范式转变：我们不再需要编写过程化、混乱的 JS 来指示浏览器如何遍历和操作 DOM。我们现在不再告诉浏览器*如何*更新 DOM，而是告诉它*更新*什么。或者更具体地说，我们告诉*一个框架*要更新什么——像 View 或 React 这样的框架。虚拟 DOM 的实际实现是特定于框架的，目前不需要太在意。

我们现在可以通过使用处理底层框架的虚拟 DOM 实现的*声明式*代码来间接地使用 DOM。这种抽象是使 jQuery 或多或少变得多余的一件事。

当然，由于仍然有很多应用程序由 jQuery 提供动力，并且由于遗留代码有粘性的倾向，jQuery 在未来几年内仍将活跃。

然而，我们对 DOM 操作方式的范式转变使得 Vue 成为与 jQuery 竞争激烈的对手，成为当今最受欢迎的游戏。

Vue 还有其他优势：它是学习当今前端开发的绝佳起点。入门门槛非常低。

# 一个初学者的学习工具

如果一个 jQuery 开发人员面临学习现代前端框架/库（React、Angular、Vue、Ember...）的选择，哪一个可能是最容易入门的呢？

当然是 Vue！

正如我们已经看到的，使用 Vue 可以简单到只需导入 CDN。由于我们人类天生喜欢小而频繁的胜利，Vue 似乎是一条快乐的道路。这并不是说开发人员不应该尝试学习其他前端框架。只是 Vue 似乎是最简单的入门方式，也是最快速提高生产力的最佳方式。

# 一个多才多艺的渐进式框架

Vue JS 的官方网站称 Vue 为*渐进式 JavaScript 框架*。这意味着您可以逐步将 Vue 添加到现有的服务器端项目中。基本上，您可以将 Vue 添加到您网站的一个简单部分。难怪 Laravel 选择在其前端与 Vue 捆绑在一起。

但你不必只在这里和那里使用 Vue。您还可以使用 Vuex 和 Vue-Router 进行扩展。这使得 Vue 非常灵活，可以在许多不同的场景中使用。

# 动画和过渡工具

如果您需要进行高性能的动画和过渡效果，那就毫无疑问选择 Vue！Vue 的动画 API 非常易于理解，使用起来非常愉快。在 Vue 中做动画是如此容易，以至于您会惊讶于您在很短的时间内可以完成多少工作。

# 与其他现代前端框架和库类似的功能

与其他现代前端框架（如 React 和 Angular）一样，Vue 也具有以下特点：

+   虚拟 DOM

+   命令行界面（Vue-cli）

+   状态管理（Vuex）

+   路由（Vue-Router）

然而，似乎 Vue 的核心团队正在尽最大努力使 Vue 尽可能易于接近。这在几个例子中是显而易见的：

+   他们为了避免设置 Vue-cli 的麻烦所付出的努力，这使得入门非常容易

+   复杂的工具链的缺乏

+   Vue 的 API 的简单性

就像官方项目的网站所述，Vue 是易于接近，多才多艺和高性能的。

# 为什么使用 Vue？

我们已经在前一节讨论了 Vue 解决的问题。在本节中，我们将看一下为什么与之合作是一种乐趣的实际例子：

+   声明性代码（我们告诉 Vue 要做什么，而不是如何做）

+   易于理解的语法（尽可能简洁）

+   感觉适合各种项目

# 声明性代码

让我们将原生 JavaScript 代码与 Vue JavaScript 代码进行比较。

对于这个例子，我们将打印出一个数组的成员。

在原生 JavaScript 中，这将是代码：

```js
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Document</title>
  <style>
    .list-item {
      background: white;
      color: gray;
      padding: 20px;
      margin: 20px;
    }
  </style>
</head>
<body>

  <script>
    var arr1 = ['a','b','c'];
    var unorderedList = document.createElement('ul');
    unorderedList.style.cssText = "background:tomato; width: 
    400px;height:400px";
    document.body.appendChild(unorderedList);
    for (var i=0; i<3; i++) {
      var listItem = document.createElement('li');
      listItem.className = "list-item";
      unorderedList.appendChild(listItem);
      listItem.innerHTML = arr1[i];
    }
  </script>
</body>
</html>
```

在这个文件中，重点应该放在`script`标签内的代码上。

您可以在此 URL 的表单中看到此示例：[`codepen.io/AjdinImsirovic/pen/xzPdxO`](https://codepen.io/AjdinImsirovic/pen/xzPdxO)。

在这段代码中，我们正在做几件事：

1.  我们正在设置`array1`，它将稍后填充我们将动态创建的列表项

1.  我们正在创建一个`ul`——一个无序列表元素，它将包裹我们所有的列表项（所有我们的`li`元素）

1.  我们正在为我们的`ul`设置样式

1.  我们正在将`unorderedList`附加到我们文档的主体

1.  接下来，我们使用`for`循环创建三个`li`元素

1.  仍然在`for`循环中，我们为每个列表项添加一个类

1.  然后我们将它们中的每一个附加到无序列表元素

1.  最后，我们为每个列表项添加`innerHTML`

对于这段代码，可能会有很多反对意见。我们本可以使用`forEach`；我们本可以避免以我们的方式添加样式，而是从一个单独的文件中调用 CSS。但最大的反对意见是这段代码有多脆弱。让我们将这段代码与用 Vue 编写的相同内容进行对比。

在 Vue 中，我们的代码将如下所示：

```js
<!-- HTML -->
<ul>
  <li v-for="entry in entries">
     {{ entry.content }}
  </li>
</ul>

// JS
var listExample = new Vue ({
  el: "ul",
  data: {
    entries: [
      { content: 'a'},
      { content: 'b'},
      { content: 'c'}
    ]
  }
})
```

此示例的代码可以在这里找到：[`codepen.io/AjdinImsirovic/pen/VdrbYW`](https://codepen.io/AjdinImsirovic/pen/VdrbYW)。

正如我们在简单的一瞥中所看到的，与在原生 JavaScript 中实现的相同代码相比，Vue 的代码更容易理解和推理。

这里的 `el` 是我们 Vue 应用的入口点。`data` 选项是我们的 Vue 应用将使用的实际数据。

这种设置还有另一个主要好处：一旦你了解了 Vue 的工作原理，任何使用 Vue 的其他项目对你来说都会变得简单明了，这将提高生产力和效率。

Vue 的方式促进更快速地完成更多事情。

# 对各种项目来说都是合适的选择

Vue 的一个优点是可以逐步实现。如果你只是想在 Vue 中进行一个快速、简单的实验，没有问题。你可以在不到一分钟的时间内开始使用 Vue。

这使得它非常适合转换传统项目、从头开始构建项目，或者进行简单的实验。

Vue 也在迅速成熟。有一个充满活力的 Vue 社区，许多开发人员在不断地为其努力。例如，人们选择 React 而不是 Vue 的一个论点是 Vue 中缺乏用于构建原生移动应用的框架。这已经不再是问题了：Vue Native 从 2018 年 6 月起就可用了。你可以在 [`github.com/GeekyAnts/vue-native-core`](https://github.com/GeekyAnts/vue-native-core) 查看它，或者在 [`vue-native.io/`](https://vue-native.io/) 了解更多信息。

考虑到所有这些，学习 Vue 对任何人来说都是一个不错的投资回报，尤其是前端开发人员。

# 易于理解的语法

在这个非常简单的 Vue 应用示例中可以注意到一件事，就是使用了 `v-for` HTML 属性。

# 指令

Vue 中的所有 `v-*` 属性都被称为 *指令*，这是从 Angular 中借鉴过来的。

指令的概念非常有趣。它们使代码更易于理解、更易于思考，也更易于使用。

在 Vue 中还有其他指令，我们将在本书中广泛使用。现在，让我们列出其中一些：`v-bind`、`v-cloak`、`v-for`、`v-else`、`v-else-if`、`v-model`、`v-on`、`v-once`、`v-text` 和 `v-html`。

一个有用的指令示例是 `v-model`。`v-model` 指令用于使表单具有响应性；它帮助我们在用户输入事件中更新数据。虽然这个话题对于 Vue 的初学者来说可能有点高级，但这种复杂性被处理得如此优雅，以至于即使初学者也应该很容易看出代码中发生了什么：

```js
<!-- HTML -->
<div id="app">
  <span>Enter the weight in kilograms:</span>
  <input v-model="someNum" type="number">
  <div>The weight in pounds is: {{ someNum * 2.20 }}</div>
</div>

// js
new Vue({
  el: '#app',
  data() {
    return {
      someNum: "1"
    }
  }
})
```

如您所见，`{{ someNum }}`的值绑定到用户在输入字段中键入的任何内容。换句话说，基于用户输入，底层数据模型`someNum`的值将发生变化。

要查看前面示例的 pen，请访问[`codepen.io/AjdinImsirovic/pen/pKdPgX`](https://codepen.io/AjdinImsirovic/pen/pKdPgX)。

# 修饰符

Vue 中的指令还可以通过修饰符进行进一步扩展。

有关指令中修饰符的官方文档链接在此：[`vuejs.org/v2/guide/forms.html#Modifiers`](https://vuejs.org/v2/guide/forms.html#Modifiers)。

要使用修饰符，我们只需将其附加到指令上。最简单的示例可能看起来像这样：

```js
<!-- HTML -->
<div>
  <input v-model.trim="userInput" placeholder="type here">
  <p>You have typed in: {{ userInput }}</p>
</div>

// js
new Vue({
  el: 'div',
  data() {
    return {
      userInput: ""
    }
  }
})
```

我们刚刚将`trim`修饰符附加到`v-model`指令上。

您可以在此链接查看此代码的示例：[`codepen.io/AjdinImsirovic/pen/eKeRXK`](https://codepen.io/AjdinImsirovic/pen/eKeRXK)。

此修饰符将修剪用户在输入字段中键入的任何空白（例如空格或制表符）。

在继续查看 Vue 语法的概述之前，让我们也提一下`v-on`指令，它用于事件处理。这里是一个快速示例：

```js
<!-- HTML -->
<div id="example-1">
 <button v-on:click="counter += 1">Add 1</button>
 <p>The button above has been clicked {{ counter }} times.</p>
</div>

// JS var example1 = new Vue({
 el: '#example-1',
 data: {
 counter: 0
 }
})
```

Vue 甚至为`v-on`提供了快捷语法：`@`符号。因此，我们可以用`@click`替换`v-on:click`，我们的 Vue 计数器仍然可以工作。

要在[`codepen.io/`](http://codepen.io/)中查看此示例，请访问以下网址：[`codepen.io/AjdinImsirovic/pen/PaOjvz`](https://codepen.io/AjdinImsirovic/pen/PaOjvz)。

# Vue 方法

Vue 实例中的`methods`选项只列出了该 Vue 实例（或 Vue 组件）上存在的所有函数。

`methods`选项与 Vue 实例的数据一起工作。接下来是这个概念的一个简单演示：

```js
// HTML
<div id="definitions">
  <!-- 'whatIsVue' and 'whyUseVue' are functions defined in the 'methods' option in the Vue instance -->
  <button id="btn" v-on:click="whatIsVue">What is Vue?</button>
  <button id="btn" v-on:click="whyUseVue">Why use Vue?</button>
</div>

// JS
var definitions = new Vue({
 el: '#definitions',
 data: {
 name: 'Vue.js'
 },
 // define methods (functions) under the `methods` object
 methods: {
   whatIsVue: function () {
    console.info(this.name + ' is a Progressive Front-end Framework')
   },
   whyUseVue: function () {
    alert('Because ' + this.name + ' is nice.')
   }
 }
})
```

正如我们所看到的，`data`选项保存了`Vue.js`字符串，可以通过`name`键访问。

在`methods`选项中，我们可以看到两个函数：`whatIsVue`和`whyUseVue`。`whatIsVue`函数接受点击事件并将`name`中的值记录到控制台。`methods`选项中的`whyUseVue`函数工作方式类似。

此代码可以在此地址的 pen 中查看：[`codepen.io/AjdinImsirovic/pen/yEPXdK`](https://codepen.io/AjdinImsirovic/pen/yEPXdK?editors=1111)。

# 计算属性和观察者

计算属性用于避免复杂逻辑增加视图的臃肿。换句话说，计算属性对于隐藏 HTML 的复杂性是有用的，因此使我们的 HTML 易于理解、易于使用和声明性。换句话说，当我们需要从`data`选项计算一些值时，我们可以借助计算属性来实现。

以下示例的完整代码可以在[`codepen.io/AjdinImsirovic/pen/WyXEOz`](https://codepen.io/AjdinImsirovic/pen/WyXEOz)中查看：

```js
<!-- HTML -->
<div id="example">
  <p>User name: "{{ message }}"</p>
  <p>Message prefixed with a title: "{{ prefixedMessage }}"</p>
</div>

// JS
var example = new Vue({
  el: '#example',
  data: {
    userName: 'John Doe',
    title: ''
  },
  computed: {
    // a computed getter
    prefixedMessage: function () {
      // `this` points to the Vue instance's data option
      return this.title + " " + this.userName
    }
  }
})
```

计算属性是被缓存的。只要计算属性的依赖项没有发生变化，Vue 将返回计算属性的缓存值。

观察者并不像计算属性那样经常使用。换句话说，观察选项要比计算属性选项少用。观察者通常用于具有变化数据的异步或成本高昂的操作。

观察者与响应式编程有关；它们允许我们通过时间观察事件序列并对特定数据属性的变化做出反应。

我们将在后面的章节中介绍计算属性和观察者的主题。目前，知道它们存在于 Vue 中并且被广泛使用就足够了。

# 总结

在本章中，我们看了如何通过[codepen.io](http://codepen.io)快速开始使用 Vue。我们还讨论了 Vue 中一些最重要的思想和概念，例如学习 Vue 2 的最快和最开发者友好的方式。我们了解了 Vue 解决了什么问题，它的优势是什么，以及为什么有时被称为*新的 jQuery*。我们了解了花括号模板、Vue 的声明性代码和易于理解的语法。最后，我们介绍了指令、修饰符、方法、计算属性和观察者。

在下一章中，我们将看到什么是响应式编程以及它如何应用在 Vue 中。我们还将进一步扩展本章涵盖的概念，并介绍 Vue 的一些其他特性。


# 第二章：Vue 2 的基本概念

在本章中，我们将讨论 Vue 中的数据驱动视图。我们还将研究如何使用指令来操作 DOM。接下来，我们将学习组件是什么以及如何创建它们，并涵盖与模板、方法、数据、计算属性和观察者相关的概念。

所有组件都有一个生命周期，并且我们有特殊的方法在其生命周期的某些时刻访问组件。这些方法被称为**生命周期钩子**，我们也将在本章中对它们进行讨论。

在本章中，我们将学习以下内容：

+   Vue 中的数据驱动视图

+   计算属性和方法以及如何使用它们

+   理解组件、模板和属性

+   在 Vue 中构建组件模板的方式

+   使用 Vue 组件和`v-*`指令快速原型网站

+   在 Vue 中利用观察者

+   生命周期钩子的重要性以及如何在 Vue 中插入这种功能

# Vue 中的数据驱动视图

Vue 中的数据驱动视图是通过响应性来实现的。

# 什么是响应性？

为了更好地理解这个概念，让我们看一个例子代码，其中没有响应性。我们将使用一个非常类似于我们在上一章中比较 Vue 和原生 JS 时的例子。在原始的例子中，使用 JavaScript，我们创建了一个无序列表，里面有三个列表项。三个列表项的值是从我们声明的数组中添加的，并且使用 for 循环将无序列表填充了这些列表项。

这一次，我们将做一些稍微不同的事情。要将示例作为一个 pen 查看，请访问[`codepen.io/AjdinImsirovic/pen/JZOZdR`](https://codepen.io/AjdinImsirovic/pen/JZOZdR)。

在这个非响应式的例子中，我们预先定义了数组的成员作为变量。然后我们用这些变量填充数组，并将它们作为无序列表的列表项打印到屏幕上，这个无序列表被附加到文档中：

```js
var a = 1;
var b = a + 1;
var c = b + 2;
var arr1 = [a,b,c];
var unorderedList = document.createElement('ul');
document.body.appendChild(unorderedList);
for (var i=0; i<3; i++) {
  var listItem = document.createElement('li');
  listItem.className = "list-item";
  unorderedList.appendChild(listItem);
  listItem.innerHTML = arr1[i];
}
arr1[0] = 2;
for (var i=0; i<3; i++) {
  var listItem = document.createElement('li');
  listItem.className = "list-item";
  unorderedList.appendChild(listItem);
  listItem.innerHTML = arr1[i];
}
```

然而，当我们改变数组的一个成员并再次重复 for 循环时会发生什么？正如我们在代码中所看到的，第一个和第四个列表项是不同的。第一个值是`1`，第二个值是`2`。为了更明显，这些项目是以粗体红色文本和灰色背景显示的。第一个值是`var a`的初始值。第二个值是使用这行代码更新的`var a`的值：`arr1[0] = 2`。

然而，变量`b`和`c`的值在第二个 for 循环中没有更新，尽管我们已经分别定义了变量`b`和`c`，它们分别是变量`a`增加 1 和 2。

因此，我们可以看到 JavaScript 本身并没有响应性。

就 Vue 而言，响应性是指 Vue 跟踪变化的方式。换句话说，响应性是指状态变化如何在 DOM 中反映出来。实际上，这意味着当对`data`进行更改时，该更改将传播到页面，以便用户可以看到它。因此，说*Vue 是响应式*就等同于说*Vue 跟踪变化*。作为一个概念，就是这么简单。

# Vue 是如何实现这一点的呢？

Vue 将其数据存储在`data`选项中，这可以是一个函数或一个对象：

```js
...
data: {
  // the model goes here
}
...
```

`data`模型的任何变化都会反映在视图（屏幕）上。Vue 通过 getter 和 setter 实现了这种响应性。当`data`对象被 Vue 实例接收时，`data`对象的所有属性都将被更新为 getter 和 setter。这是通过`Object.defineProperty`API 来实现的。

# 计算属性和方法

Vue 中响应性的实用性可以用计算属性和方法之间的区别来描述。

正如我们之前提到的，Vue 实例可以有计算属性、方法，或者计算属性和方法两者兼有。那么，这两者之间有什么区别呢？

方法只是在被调用时运行。另一方面，计算属性是被缓存的，这意味着它们只在基础数据模型发生变化时才会运行。这通常是以计算属性的依赖关系来描述的。此外，方法可以有参数，而计算属性则不行。

# 这些依赖关系到底是什么？

考虑这个简单的 Vue 应用程序，可以在这个链接中找到：[`codepen.io/AjdinImsirovic/pen/qKVyry`](https://codepen.io/AjdinImsirovic/pen/qKVyry)。

这是这个简单应用程序的代码：

```js
<!--HTML-->
<div id="example">
  <p>Enter owner name and the thing that is owned:
    <input v-model="ownerName" placeholder="enter owner">
    <input v-model="thing" placeholder="enter thing">
  </p>
  <span>{{ ownerName }}</span>
  <span> has a </span>
  <span>{{ thing }}</span>
</div>

// JS
var example = new Vue({
  el: '#example',
  data: {
    ownerName: 'e.g Old McDonald',
    thing: 'e.g cow'
  },
  computed: {
    // a computed getter
    ownerHasThing: function () {
      // `this` points to the Vue instance's data option
      return this.ownerName + " " + this.thing
    }
  }
})
```

这段代码将在屏幕上产生这样的输出：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-qk-st-gd/img/63e6e381-cd03-4ea3-a4d6-3225799a5d85.png)

首先，我们可以看到视图中有这样一个奇怪的“has a”文本行。问题在于我们没有使用我们的`ownerHasThing`计算属性。换句话说，HTML 中的这三行是完全多余的：

```js
<span>{{ ownerName }}</span>
<span> has a </span>
<span>{{ thing }}</span>
```

另外，如果我们只想在两个输入字段都填写完毕并且焦点已经移出输入框，或者按下*Enter*键后才运行计算属性，该怎么办呢？

这可能看起来是一个相对复杂的事情。幸运的是，在 Vue 中非常容易实现。

让我们来看一下更新后的代码（也可以在这里找到：[`codepen.io/AjdinImsirovic/pen/aKVjqj`](https://codepen.io/AjdinImsirovic/pen/aKVjqj)）：

```js
<!--HTML-->
<div id="example">
  <p>Enter owner name:
    <input v-model.lazy="ownerName" placeholder="enter owner">
  </p>
  <p>Enter thing owned:
    <input v-model.lazy="thing" placeholder="enter thing">
  </p>
  <h1 v-if="ownerName && thing">{{ ownerHasThing }}</h1>
</div>
```

JavaScript 代码只有轻微的不同：

```js
var example = new Vue({
  el: '#example',
  data: {
    ownerName: '',
    thing: ''
  },
  computed: {
    // a computed getter
    ownerHasThing: function () {
      // `this` points to the Vue instance's data option
      return this.ownerName + " has a " + this.thing
    }
  }
})
```

我们可以得出结论，计算属性只是一些数据依赖关系，对它们进行了一些计算。换句话说，`ownerHasThing`是一个计算属性，它的依赖是`ownerName`和`thing`。

每当`ownerName`或`thing`发生变化时，`ownerHasThing`计算属性也会更新。

然而，`ownerHasThing`不会总是更新，因为它被缓存了。相反，方法总是会更新；也就是说，它总是会运行，无论数据模型是否发生了变化。

这可能看起来不是非常重要的区别，但考虑一种情况，你的方法需要从第三方 API 获取数据，或者有很多代码需要运行。这可能会减慢速度，这就是为什么在这种情况下，使用计算属性是正确的方法。

在我们结束本节之前，让我们快速回顾一下之前示例中的代码。

在 HTML 中，我们使用了`v-model.lazy`。`lazy`修饰符会等待用户要么点击输入框外部，要么按下键盘上的*Enter*键，或者离开输入框（比如按下*Tab*键）。

在 HTML 中，我们还使用了`v-if`指令，并给它传递了`ownerName && thing`。然后，我们添加了双大括号模板：`{{ ownerHasThing }}`。`v-if`指令会等待直到`ownerName`和`thing`在数据对象中更新。因此，一旦两个输入框都填写完毕并且不再聚焦，计算属性才会更新底层数据模型，然后才会在屏幕上打印出`{{ ownerHasThing }}`消息。

在下一节中，我们将看看如何使用模板和组件。

# 理解组件、模板和 props

首先，让我们看看如何在 Vue 中创建一个组件。首先，我们像这样指定组件：

```js
Vue.component('custom-article', {
  template: `
    <article>
      Our own custom article component!<span></span>
    </article>`
})
new Vue({
    el: '#app'
})
```

组件是一段我们给予自定义名称的代码块。这个自定义名称可以是我们想到的任何东西，它是*整个代码块的一个单一标签*，以自定义 HTML 标签的形式。在前面的例子中，我们将`article`和`span`标签分组，并给该自定义标签命名为`custom-article`。

组件使用 kebab-case 命名。

这个组件的代码可以在 Codepen 上找到：[`codepen.io/AjdinImsirovic/pen/xzpOaJ`](https://codepen.io/AjdinImsirovic/pen/xzpOaJ)。

现在，要创建我们组件的一个实例，我们只需在我们的 HTML 中使用`<custom-article>`开放和关闭标签，就像这样：

```js
<main id="app">
    <custom-article></custom-article>
</main>
```

我们的 custom-article 组件被称为*子*组件。

父级是实际的 Vue 实例。

请注意，即使没有组件，您也可以使用字符串模板。您只需将模板选项添加到您的 Vue 实例中，就像这样：

```js
//HTML
<main id="app"></main>
//JS
new Vue({
  el: '#app',
  template: '<article>A string template without a component!<span></span></article>'
})
```

前面例子的示例代码可以在这里找到：[`codepen.io/AjdinImsirovic/pen/RJxMae`](https://codepen.io/AjdinImsirovic/pen/RJxMae)。

接下来，我们将看到如何通过`props`和`data`选项来改进我们的组件。

# 添加 props 和 data 以改进组件

为了使我们的`custom-article`组件更有用，我们将向其添加一个`props`选项，就像这样：

```js
Vue.component('custom-article', {
  props: ['content'],
  template: '<article>{{content}}</article>'
})
new Vue({
  el: '#app'
})
```

Props 是从父级向子级传递数据的一种方式。它们是父级和子级之间数据的单向流动。Props 总是被定义为一个数组。

前面例子的代码可以在这里找到：[`codepen.io/AjdinImsirovic/pen/KeZNPr`](https://codepen.io/AjdinImsirovic/pen/KeZNPr)。

我们在组件中注册了一个 prop，现在我们可以在 HTML 中使用它作为一个名为与我们的 prop 相同的属性：

```js
<main id="app">
  <custom-article content="This component was made with the help of a prop."> 
  </custom-article>
</main>
```

当我们需要对组件进行较小的更改而不必制作一个全新的组件时，我们使用 props。它们帮助我们重复使用我们已经拥有的东西。

在下一节中，我们将使用 Vue 实例的`data`对象向我们的`custom-article`组件添加内容。

# 使用数据对象向我们的组件添加内容

这个例子的代码笔可以在[`codepen.io/AjdinImsirovic/pen/QxadmE`](https://codepen.io/AjdinImsirovic/pen/QxadmE)找到。

在我们的 HTML 中，我们将代码更改为以下内容：

```js
<main id="app">
  <custom-article v-bind:content="datacontent"> 
  </custom-article>
</main>
```

在我们的 JS 中，我们将更新我们的 Vue 代码如下：

```js
Vue.component('custom-article', {
  props: ['content'],
  template: '<article>{{content}}</article>'
})
new Vue({
    el: '#app',
    data: {
      datacontent: 'This component was made with the help of a data object in the Vue instance'
    }
})
```

在前面的例子中，我们使用`v-bind`指令将我们的`custom-article`组件中的`content`prop 绑定到我们的`data`对象的`datacontent`属性。

如果你仔细思考这段代码，你会发现 props 几乎就像是命名变量（在示例中，prop 的变量`name`是`content`）。Props 只是将从父组件接收到的数据传递给子组件。

我们还可以用另一种方式来做这件事。我们可以将数据传递给组件，而不是在 Vue 实例内部使用数据；只是这一次它必须是一个数据函数。以下是此实现的完整代码：

```js
// HTML
<main id="app">
  <custom-article></custom-article>
</main>

// JS
Vue.component('custom-article', {
  template: '<article>{{datacontent}}</article>',
  data: function() {
    return {
      datacontent: 'This component was made with the help of a data function in the Vue component called custom-article'
    }
  }
})
new Vue({
    el: '#app'
})
```

要查看上一个示例的代码，请访问[`codepen.io/AjdinImsirovic/pen/VdyQzW`](https://codepen.io/AjdinImsirovic/pen/VdyQzW)。

如果我们将数据作为对象而不是函数使用，那么响应性将适用于组件的所有实例。由于组件的主要目的是可重用的，因此重要的是要记住在这种情况下数据必须是一个函数。

Props 也可以被定义为对象，这样我们可以给它们更多的信息：验证传入的数据，设置默认值（如果没有数据传入的话），等等。

在以下示例中，我们声明我们的`custom-article`组件期望父组件传递一个名为`message`的 prop，或者是字符串类型，这是必需的：

```js
<!--HTML-->
<div id="app">
  <custom-article :message-being-passed="datacontent"></custom-article>
</div>

//JS
Vue.component('custom-article', {
  props: {
    messageBeingPassed: {
      type: String,
      required: true,
      default: 'Hello Vue'
    }
  },
  template: `<div class="thetemplate">{{ message }}</div>`
});

new Vue({
  el: "#app",
  data: function() {
    return {
      datacontent: 'This component was made with the help of a data function in the Vue component called custom-article, and the data passed was validated with the help of the props object inside the Vue component'
    }
  }
})

//CSS
.thetemplate {
  font-size: 30px;
  padding: 20px;
  color: limegreen;
  font-family: Arial;
  border: 3px solid green;
  border-radius: 10px;
}
```

此示例可在[`codepen.io/AjdinImsirovic/pen/mKpxGZ`](https://codepen.io/AjdinImsirovic/pen/mKpxGZ)找到。

假设我们注释掉了 Vue 实例的`data`函数中的`datacontent`属性。你能猜到会发生什么吗？

换句话说，如果`datacontent`没有提供正确的数据会发生什么？子组件将简单地回到`props`对象中的`default`属性。

要看到这个实例的效果，请访问此链接：[`codepen.io/AjdinImsirovic/pen/BVJxKL`](https://codepen.io/AjdinImsirovic/pen/BVJxKL)。

# Vue 中构建组件模板的其他方法

到目前为止，我们已经看过将模板定义为字符串（使用单引号或双引号）和模板字面量（使用反引号）。还有许多其他处理组件模板的方法：

+   内联模板

+   X-templates

+   渲染函数

+   单文件组件

+   JSX

它们大多都有各自的优缺点。例如，在 Vue 中使用 JSX 是可能的，但通常不被赞同，因为这不是 Vue 的做事方式。内联模板是使用 HTML 中的`inline-template`属性制作的。

如果你在 HTML 的 script 标签中添加`type=''text/x-template''`，你将创建一个 Vue x-template。以下是一个例子：

```js
// HTML
<div id="app">
  <script type="text/x-template" id="custom-article-template">
    <p>{{ name }}</p>
  </script>
</div>

// JS
Vue.component('custom-article', {
  template: '#custom-article-template',
  props: ['name']
})
new Vue({
    el: '#app'
})
```

此示例的代码笔可在此处找到：[`codepen.io/AjdinImsirovic/pen/NzXyem`](https://codepen.io/AjdinImsirovic/pen/NzXyem)。

单文件模板可能是在 Vue 中创建模板的最实用方式。您可以将所有的 HTML、JS 和样式都放在一个文件中（使用`.vue`文件扩展名），然后使用构建过程（如 Webpack）编译此文件。在后面的章节中，当我们使用 Vue-cli（借助 Vue 中 Webpack 的使用）时，我们将深入研究这一点。

# 通过组件构建简单的网页

正如我们在前一节中所看到的，Vue 中构建组件的方式有很多种，这可能会使事情看起来比必须复杂。虽然重要的是要意识到 Vue 为我们构建组件的各种方式带来的多样性，但在本节中，我们将看一种简单的使用组件构建网页的方式。

在开始构建我们的页面之前，有一件事情应该对我们清楚：Vue 中的每个组件也只是另一个 Vue 实例。这意味着每个组件都需要一个选项对象，其中包含与任何其他 Vue 实例相同的键值对。唯一的例外是根 Vue 实例具有一些额外的选项，只能在其中使用。

在这些介绍性的澄清之后，让我们看看如何将组件添加到 Vue 实例中。

# 将简单组件添加到 Vue 实例中

在开始这个示例之前，我们将从一个简单的 Vue 实例开始。

在我们的 JavaScript 文件中，让我们创建一个最简单的 Vue 实例，以`#app`元素作为其入口点：

```js
new Vue({
  el: '#app',
  data: {}
})
```

接下来，让我们在我们的 HTML 中添加一个 div，这样我们的 Vue 实例就有了页面中的一个元素来访问其 DOM：

```js
<div id="app"></div>
```

现在我们将在我们的 JavaScript 文件中添加另一个组件。让我们通过将以下代码添加到顶部来扩展我们现有的 JS 文件：

```js
Vue.component('the-header', {
  template: '<h1 class="header css classes go here">Our example header</h1>'
})
```

现在，我们可以在我们的 HTML 中简单地添加自定义的`the-header`组件：

```js
<div id="app">
  <the-header></the-header>
</div>
```

这样做将在屏幕上呈现我们的示例标题文本。

既然我们已经看到了向我们的 Vue 应用程序添加一个简单组件有多么容易，让我们再添加一个来加强这一点。

我们将从扩展我们的 JS 文件开始，添加另一个组件`the-footer`：

```js
Vue.component('the-header', {
  template: '<h1 class="header css classes go here">Our example header</h1>'
});

Vue.component('the-footer', {
  template: '<h1 class="footer css classes go here">Our example header</h1>'
});

//Root Instance
new Vue({
  el: '#app',
  data: {}
})
```

当然，我们需要更新我们的 HTML 以使其工作：

```js
<div id="app">
  <the-header></the-header>
  <the-footer></the-footer>
</div>
```

在命名自定义组件时，我们需要使用连字符。这样做是为了确保与常规 HTML 元素没有命名冲突。

本节示例代码可在此处找到：[`codepen.io/AjdinImsirovic/pen/qypBbz`](https://codepen.io/AjdinImsirovic/pen/qypBbz)。

现在我们了解了如何向 Vue 实例添加简单组件，让我们通过添加一个更复杂的例子来练习。

# 在 Vue 中创建由组件组成的更复杂的页面

首先，让我们向我们的新 Vue 实例中添加一个组件。这次，我们将在自定义组件的选项对象中使用数据选项。

这是我们开始的代码：

```js
Vue.component('the-header', {
  template: '<h1 class="h1 text-success">{{header}}</h1>',
  data: function() {
    return {
      header: 'Just another simple header'
    }
  }
});

//Root Instance
new Vue({
  el: '#app',
  data: {}
})
```

在这段代码中，我们已经在模板中添加了 mustache 语法。然后我们利用了数据选项来返回将在模板中插值的文本。mustache 语法告诉我们的组件在数据选项中查找`header`。

此示例的代码在此处可用：[`codepen.io/AjdinImsirovic/pen/wxpvxy`](https://codepen.io/AjdinImsirovic/pen/wxpvxy)。

接下来，在我们的页眉下，我们将添加一些 Bootstrap 卡片。

为简单起见，我们将使用官方 Bootstrap 文档中的现有示例，该示例位于以下 URL：[`getbootstrap.com/docs/4.0/components/card/#using-grid-markup`](https://getbootstrap.com/docs/4.0/components/card/#using-grid-markup)。

该示例提供了以下代码：

```js
<div class="row">
  <div class="col-sm-6">
    <div class="card">
      <div class="card-body">
        <h5 class="card-title">Special title treatment</h5>
        <p class="card-text">
          With supporting text below as a natural lead-in to additional 
          content.    
        </p>
        <a href="#" class="btn btn-primary">Go somewhere</a>
      </div>
    </div>
  </div>
  <div class="col-sm-6">
    <div class="card">
      <div class="card-body">
        <h5 class="card-title">Special title treatment</h5>
        <p class="card-text">
          With supporting text below as a natural lead-in to additional 
          content.
        </p>
        <a href="#" class="btn btn-primary">Go somewhere</a>
      </div>
    </div>
  </div>
</div>
```

尽管 Bootstrap 框架不是本书的主题，但对我们来说，给出一个在实践中使用 Vue 组件的真实例子将是有用的。由于 Bootstrap 基本上已成为前端框架的行业标准，它是展示 Vue 组件不仅如何一般使用，而且如何与其他前端技术结合的完美候选者。

现在让我们看看如何向我们的 Vue 网页示例中添加一个单个卡片。这是要添加到我们的 JS 中的代码：

```js
Vue.component('the-card', {
  template: '<div class="card"><div class="card-body"><h5 class="card-title">Special title treatment</h5><p class="card-text">With supporting text below as a natural lead-in to additional content.</p><a href="#" class="btn btn-primary">Go somewhere</a></div></div></div>',
});
```

我们代码开发的这个阶段的代码在这里可用：[`codepen.io/AjdinImsirovic/pen/VByYeW`](https://codepen.io/AjdinImsirovic/pen/VByYeW)。

接下来，让我们将我们的卡片组件添加到我们的 HTML 中。完整的更新代码将如下所示：

```js
<div id="app">
 <div class="container">
    <the-header></the-header>
    <div class="row">
      <div class="col-sm-6">
        <the-card></the-card>
      </div>
      <div class="col-sm-6">
        <the-card></the-card>
      </div>
    </div>
</div>
```

将上述代码添加到我们的 HTML 中，并根据之前描述的进行 JS 更新，我们将得到以下结果：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-qk-st-gd/img/063612e2-9c2b-4121-8243-2e3a46dac0d3.png)

我们在 JS 中添加了一个单独的卡片组件；然而，正如我们在之前的例子中看到的，我们现在可以根据需要在 HTML 中重复使用它。

这为我们提供了一个绝佳的机会，借助 Vue 快速原型设计完整的网页。

我们甚至可以进一步进行，正如我们将在下一节中看到的。

# 使用 v-for 改进我们基于 Vue 的布局

在这一部分，我们将通过 Vue 指令来改进我们现有的网页。

我们的具体目标是尝试在组件实例中使用数据选项，并结合 Vue 指令的功能来进一步改进我们的 Vue 应用程序。

此部分的代码可在[`codepen.io/AjdinImsirovic/pen/Epoamy`](https://codepen.io/AjdinImsirovic/pen/Epoamy)中找到。

让我们使用 ES6 的反引号语法使我们的 JS 更容易阅读。这种语法允许我们编写跨多行的 JavaScript 字符串：

```js
Vue.component('the-header', {
  template: '<h1 class="h1 text-success">{{header}}</h1>',
  data: function() {
    return {
      header: 'Just another simple header'
    }
  }
});

Vue.component('the-card', {
  template: `
    <div class="card">
      <div class="card-body">
        <h5 class="card-title">Special title treatment</h5>
        <p class="card-text">
          With supporting text below as a natural lead-in to addtional 
          content.
        </p>
        <a href="#" class="btn btn-primary">Go somewhere</a>
      </div>
    </div>`,
});

//Root Instance
new Vue({
  el: '#app',
  data: {}
})
```

现在，让我们将`data`选项添加到`the-card` Vue 组件中：

```js
  data: function() {
    return {
      customCard: [{
        heading: 'John Doe',
        text: 'John.doe@acme.org'
      }, 
      {
        heading: 'John Doe',
        text: 'John.doe@acme.org'
      }
     ]}
  }
```

正如我们在前面的代码中所看到的，我们返回了一个包含特定`heading`和`text`的`customCard`对象数组。

接下来，我们可以在我们的模板中使用`v-for`指令，就像这样：

```js
Vue.component('the-card', {
  template: `
    <div class="card">
      <div class="card-body" v-for="customCard in customCards">
        <h5 class="card-title">{{customCard.heading}}</h5>
        <p class="card-text">
          {{customCard.text}}
        </p>
        <a href="#" class="btn btn-primary">Go somewhere</a>
      </div>
    </div>`,
```

我们在具有`card-body`类的`div`中引入`v-for`指令。我们循环遍历我们的`customCards`集合中的每个`customCard`，并为我们`customCard`数组中的每个对象的`h5`文本内容插入`customCard.heading`。

最后，让我们在 HTML 中添加一个 Bootstrap 类，这样我们网页的`h1`标签就不会紧贴在视口的顶部。为此，我们将使用 Bootstrap 的间距实用程序。您可以在这里阅读有关它们的信息：[`getbootstrap.com/docs/4.0/utilities/spacing/`](https://getbootstrap.com/docs/4.0/utilities/spacing/)。

我们的 HTML 中的更改将是最小的，只是添加了另一个 CSS 类：`mt-5`。

最后，以下是改进页面的完整 JS 代码。首先，我们注册主标题组件：

```js
//Register main title component
Vue.component("main-title-component", {
  template: '<h1 class="text-center mt-5 mb-4">{{title}}</h1>',
  data: function() {
    return {
      title: "Just another title"
    };
  }
});
```

然后我们注册`list group`组件：

```js
//Register list group component
Vue.component("list-group-component", {
  template: `
    <ul class="list-group">
      <li class="list-group-item" v-for="item in items">{{item.description}}</li>
    </ul>`,
  data: function() {
    return {
      items: [
        {
          description: "Description one"
        },
        {
          description: "Description two"
        },
        {
          description: "Description three"
        }
      ]
    };
  }
});
```

之后，我们注册了`card`组件：

```js
// Register card component
Vue.component("card-component", {
  template: `
    <div class="card">
      <div class="card-body">
        <h5 class="card-title">{{title}}</h5>
        <p class="card-text">{{text}}</p>
        <a href="#" class="btn btn-primary">Go somewhere</a>
      </div>
    </div>`,
  data: function() {
    return {
      title: "This is the card title",
      text: "This is the card text"
    };
  }
});
```

我们还添加了`root instance`：

```js
//root Instance
new Vue({
  el: "#app",
    data: {}
});
```

这是 HTML：

```js
<div id="app">
  <div class="container mt-5 mb-5">
    <main-title-component></main-title-component>
    <div class="row">
      <div class="col">
        <list-group-component></list-group-component>
      </div>
      <div class="col">
        <card-component></card-component>
      </div>
    </div>
  </div>
</div>
```

添加上述代码的结果可以在此截图中看到：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-qk-st-gd/img/fe9ea47d-d62d-4da1-88a5-c7a3f0c12356.png)

在这一部分，我们已经看过组件以及如何开始使用它们。接下来，我们将讨论 Vue 中的观察者。

# Vue 中的观察者

Vue 中的每个组件都有一个观察者。

为了理解这是如何工作的，让我们从本章的一个早期例子开始。这个例子来自*计算属性*部分，链接在这里：[`codepen.io/AjdinImsirovic/pen/qKVyry`](https://codepen.io/AjdinImsirovic/pen/qKVyry)。这是我们的起始代码。正如我们从前一节知道的，这里有两个输入字段，我们正在打印出这些输入字段中输入的值在表单下的一些 span 标签中。

让我们扩展我们的例子。初始代码是一样的；我们只会添加一个观察者。更新后的代码可以在这个 Codepen URL 找到：[`codepen.io/AjdinImsirovic/pen/jprwKe`](https://codepen.io/AjdinImsirovic/pen/jprwKe)。

可以观察到，我们对原始笔记本唯一的更新是添加了观察者选项，如下所示：

```js
  watch: {
    ownerName(previousValue,currentValue) {
      console.log(`The value in the first input has changed from:   
        ${previousValue} to: ${currentValue}`);
    }
  },
```

之前的观察者是如何工作的？它允许我们使用一个方法，该方法的名称必须与我们在 HTML 中观察的计算属性相同。观察者有可选参数，我们可以将这些参数传递给它，在方法体中使用；在这种情况下，我们给我们的可选参数一些好的和描述性的名称：`previousValue`和`currentValue`。

在`watch`方法的主体中，我们正在记录输入值的更改到 JavaScript 控制台。测试这样工作的一个优雅的方法是，例如，突出显示第一个输入字段的初始值的*例如*部分，然后简单地擦除它，只留下输入中的*Old McDonald*的值。

这样做会导致以下句子被记录到控制台中：

```js
The value in the first input has changed from: e.g Old McDonald to: Old McDonald.
```

在下一节中，我们将看看如何在组件的生命周期的各个阶段挂钩，并在那个特定点用自定义代码改变其行为。

# 生命周期钩子

生命周期钩子是让我们在组件生命周期的各个阶段改变组件行为的方法。

# 什么是组件的生命周期？

这只是组件*生命周期*的自然进展。

因此，我们可以说生命周期钩子是这个旅程中每个组件都需要经历的*点*。在组件生命周期的这些特定*点*，我们可以使用这些方法来改变组件的行为。

Vue 团队为这些生命周期方法选择了非常描述性的名称。接下来是按组件生命周期的自然进展顺序组织的生命周期钩子列表：

+   `beforeCreate`

+   `created`

+   `beforeMount`

+   `mounted`

+   `beforeUpdate`

+   `updated`

+   `activated`

+   `deactivated`

+   `beforeDestroy`

+   `destroyed`

这个组件生命周期的可视化表示可以在这个地址找到：[`vuejs.org/images/lifecycle.png`](https://vuejs.org/images/lifecycle.png)。

请注意，打印出这张图片并随身携带直到完全理解它所传达的信息将是有益的。这将对更深入地理解 Vue 总体以及其组件生命周期特别有帮助。

正如我们所看到的，组件的生命周期有五个不同的阶段，每个阶段在特定阶段开始之前有一个生命周期钩子，以及在完成后有另一个生命周期钩子。

重要的是要注意，一个组件可以根据数据模型的变化被多次挂载。这在之前的提示框中引用的生命周期图中是可以验证的。然而，同样重要的是要理解，当底层数据发生变化时，DOM 重新渲染可能会导致组件被有效地*卸载*，尽管这在生命周期图中没有明确提到。

# 我们如何使用生命周期钩子？

让我们看一个简单的例子，可以在这个 Codepen 网址找到：[`codepen.io/AjdinImsirovic/pen/jprmoa`](https://codepen.io/AjdinImsirovic/pen/jprmoa)。

首先，让我们添加 HTML：

```js
<div> Lorem ipsum dolor sit amet</div>
<div id="app">
  <custom-article :message="datacontent"></custom-article>
</div>
```

接下来，让我们添加 CSS：

```js
div,.thetemplate {
 font-size: 30px;
 padding: 20px;
 color: limegreen;
 font-family: Arial;
  border: 3px solid green;
  border-radius: 10px;
}
```

最后，JS 部分：

```js
Vue.component('custom-article', {
  props: {
    message: {
      type: String,
      required: true,
      default: 'Hello Vue'
    }
  },
  template: `<div class="thetemplate">{{ message }}</div>`
});

new Vue({
  el: "#app",
  beforeCreate() {
    alert("Lifecycle hook beforeCreate has been run");
  },
  created() {
    setTimeout(function(){
      alert('This message is showing 5 seconds after the \'created\' life cycle hook');
    },5000);
  },
  data: function() {
    return {
      datacontent: 'This component was made with the help of a data function in the Vue component called custom-article, and the data passed was validated with the help of the props object inside the Vue component'
    }
  }
});
```

如在提供的 Codepen 中所示，很容易在 Vue 中钩入生命周期方法。只需要在 Vue 实例中的生命周期钩子方法名称中提供所需的代码（功能）即可。

在前面的示例中，我们展示了`beforeCreate()`方法的警报，并且在`created()`方法运行后 5 秒钟显示另一个警报。

生命周期钩子还有许多有用的用途，这将在接下来的章节中介绍。

# 总结

在本章中，我们了解了 Vue 中的一些基本概念。我们描述了为什么这些概念很重要以及它们如何被使用。我们还看了一些在实践中使用这些概念的简单例子。

我们了解了 Vue 中的数据驱动视图以及响应性作为跟踪数据模型变化的一种方式。我们看了使用计算属性和方法、指令及其修饰符的方法。我们已经看到了一些关于组件、模板和 props 的实际例子，以及在 Vue 中构建组件模板的不同方法。

我们学习了如何使用 Vue 组件和指令原型化网站，并在本章中结束时，我们看了一下 watchers 和生命周期钩子，作为改变组件行为的强大方式，可以在它们的生命周期的任何时刻进行。

在下一章中，我们将进一步深入研究 Vue 中的响应式编程，重点关注组件、props 和插槽。


# 第三章：使用 Vue-CLI，组件，props 和插槽工作

上一章是对 Vue 基本概念的介绍。我们将以更现实的方式开始本章：我们将介绍 Vue-cli。我们将查看组件层次结构，全局和本地组件以及组件之间的通信。我们将介绍插槽，并且我们还将检查插槽和 props 之间的区别。

在本章中，我们将涵盖以下主题：

+   Vue 组件层次结构，全局和本地组件

+   使用 Vue-cli

+   设置代码编辑器以与 Vue 一起使用

+   基于 Vue-cli 的项目结构

+   向子组件添加基本功能

+   向我们的`HelloAgain.vue`添加 props

+   插槽介绍

# Vue 组件层次结构，全局和本地组件

正如我们在第二章中学到的，*Vue 2 的基本概念*，要运行一个新的 Vue 实例，我们使用 new Vue：

```js
new Vue(
  el: "#app",
  // the rest of the Vue instance code here
)
```

我们的`app`组件位于这个 Vue 实例中。

app 组件通常有一个子组件，就像我们在第二章中看到的例子一样，*Vue 2 的基本概念*：[`codepen.io/AjdinImsirovic/pen/xzpOaJ`](https://codepen.io/AjdinImsirovic/pen/xzpOaJ)：

```js
Vue.component('custom-article', {
  template: `
    <article>
      Our own custom article component!
    </article>`
})
new Vue({
    el: '#app'
})
```

在上一章中我们没有提到的是：

+   子组件可以根据需要重复使用

+   子组件也可以有自己的子组件

这个例子可以在以下 pen 中找到：[`codepen.io/AjdinImsirovic/pen/ZjdOdK`](https://codepen.io/AjdinImsirovic/pen/ZjdOdK)。

以下是演示这两个原则的代码：

```js
// JS
Vue.component('custom-article', {
  template: `
    <article>
      Our own custom article component!
    </article>`
})
Vue.component('another-custom-article', {
  template: `
    <article>
      Another custom article component! 
      This one has it's own child component too!
      Here it is:
      <custom-article></custom-article>
    </article>`
})
new Vue({
    el: '#app'
})

/* CSS */
article {
  font-size: 40px;
  padding: 20px;
  color: limegreen;
  font-family: Arial;
  border: 3px solid green;
  border-radius: 10px;
}

<!-- HTML -->
<main id="app">
    <custom-article></custom-article>
    <custom-article></custom-article>
    <another-custom-article></another-custom-article>
</main>
```

如已经看到的，要向我们的 Vue 实例添加一个组件，我们使用以下语法：

```js
Vue.component('another-custom-article', { // etc...
```

在 Vue 术语中，我们使用这段代码来**注册**一个组件。如前所述，它被称为**全局注册**。还有**本地注册**。

本地注册与`Vue.component`语法类似。代码中唯一的区别是我们引入本地组件的方式与全局组件相比。在之前的代码中，我们有以下全局组件：

```js
Vue.component('custom-article', {
  template: `
    <article>
      Our own custom article component!
    </article>`
})
```

将这个全局组件转换为本地组件就像删除这段代码一样简单：

```js
Vue.component('custom-article'
```

与之前的代码不同，我们将简单地创建一个新变量，并给它与我们在全局组件中使用的完全相同的选项对象，就像这样：

```js
var customArticle = {
  template: `
    <article>
      Our own custom article component!
    </article>`
}
```

为了在 Vue 实例中使用这个本地组件，我们将引入`components`选项，就像这样：

```js
new Vue({
    el: '#app',
    components: { 
      'custom-article': customArticle
    }
})
```

这里有一个使用本地组件的示例：[`codepen.io/AjdinImsirovic/pen/ZMzrpr`](https://codepen.io/AjdinImsirovic/pen/ZMzrpr)。

然而，前面的示例是故意不完整的。正如我们所看到的，`customArticle`本地组件只能在主 Vue 实例中使用，而不能在`anotherCustomArticle`组件中使用。

为了使其正常工作并完成示例，我们需要调整这部分代码：

```js
Vue.component('another-custom-article', {
  template: `
    <article>
      Another custom article component! 
      This one has it's own child component too!
      Here it is:
      <custom-article></custom-article>
    </article>`,
    //components: {
    // 'customArticle': customArticle
    //}
})
```

我们只需删除这三行注释：

```js
    components: {
     'customArticle': customArticle
    }
```

通过这样做，我们已经在全局组件`anotherCustomArticle`中注册了本地组件`customArticle`。基本上，我们正在遵循在主 Vue 实例中注册本地组件的相同过程，并且我们正在应用相同的方法在`anotherCustomArticle`全局组件中注册本地组件。

要了解全局和本地注册的细微差别，您可以参考官方 Vue 文档的这一部分：

[`vuejs.org/v2/guide/components-registration.html`](https://vuejs.org/v2/guide/components-registration.html)。

在下一节中，我们将开始使用 Vue-cli。

# 使用 Vue-CLI

为了开始使用 Vue-cli，我们需要在计算机上设置 Node.js，并且我们还需要在我们选择的操作系统上安装一个命令行应用程序。

例如，我的首选工具是 Windows 10 和 Git bash for Windows。

有许多不同的操作系统和命令行应用程序，您可能会使用其中之一。

如果在安装本节中提到的任何工具时遇到问题，值得查看这篇关于在操作系统上安装 Node.js 的深入指南：

[`www.packtpub.com/mapt/book/web_development/9781788626859/2`](https://www.packtpub.com/mapt/book/web_development/9781788626859/2)

# 安装 Git bash

您首先需要访问[`git-scm.com/downloads`](https://git-scm.com/downloads)，该网站可以让您在 macOS X、Windows 和 Linux/Unix 安装之间进行选择。点击 Windows 下载后，您可以按照 Git bash 的安装步骤进行安装。在安装过程中，只需按照默认预设选项进行操作即可。

# 安装 nvm

要下载 Windows 的 Node 版本管理器，请访问此链接：

[`github.com/coreybutler/nvm-windows/releases`](https://github.com/coreybutler/nvm-windows/releases)

一旦进入页面，点击`nvm-setup.zip`文件进行下载，然后运行下载的`nvm-setup.exe`并按照常规安装步骤进行操作。

接下来，以管理员权限启动 Git bash，并运行以下命令：

```js
nvm install 8.11.4
```

以下消息将被记录到控制台：

```js
Downloading node.js version 8.11.4 (64-bit)...
```

# 为什么使用 nvm？

有两个主要原因：

+   安全关键升级

+   在不同项目中更轻松地切换 Node 版本

这里列出的第一个原因与 Node.js 的未来更新有关。假设在本书出版几个月后有一个重大的安全补丁，更新系统上的 Node 将是明智的选择。使用 nvm 可以轻松实现这一点，这也带来了第二点。即使没有可供升级的 Node 的主要版本，您仍然可以根据不同项目的需求运行不同版本的 Node。无论如何，使用 nvm 都是值得的。

下载完成后，在我们的 Git bash 中，我们可以简单地运行此命令：

```js
nvm use 8.11.4
```

现在，我们准备好使用 Vue-cli 了。

# 安装和更新 Vue-cli

值得注意的是，Vue-cli 是对 Webpack 的封装，经过调整和优化，以便在开发和发布 Vue 应用程序时提供最佳体验。这对开发人员来说是一个重大优势，因为这种设置让我们能够专注于编码，而不必长时间地与工具链搏斗。

让我们打开 Git bash 并运行以下命令：

```js
npm install -g vue-cli
```

由于 Vue-cli 是一个`npm`包，您可以在这里阅读更多信息：[`www.npmjs.com/package/vue-cli`](https://www.npmjs.com/package/vue-cli)。

要检查系统上安装的 Vue-cli 当前版本，请运行此命令：

```js
vue -V
```

请注意，Vue-cli 版本 2 和 3 之间有一个重大升级。为了确保您在系统上使用的是最新版本，您可以运行此命令：

```js
npm install @vue/cli
```

此命令将更新您的 Vue-cli 版本为最新版本。更新是本地的，这意味着它将放在您运行上一个命令的文件夹的`node_modules`文件夹中。请注意，由于需要安装的所有依赖项，此操作可能需要一些时间。

在使用 Vue-cli 初始化项目之前，快速列出 Vue-cli 版本 3 带来的改进将是有益的。希望这将强化第一章中关于 Vue 易用性的一些关键点，*介绍 Vue*。

Vue-cli 版本 3 的目标如下：

+   简化和优化工具链，避免前端开发中的工具疲劳

+   遵循最佳实践的工具，并使其成为 Vue 应用程序的默认选择

新版本的 Vue-cli 还有一系列功能和升级：

+   为热模块替换、树摇和其他功能预设 Webpack 配置

+   ES2017 功能

+   Babel 7 支持

+   PostCSS 支持

+   可选集成 Typescript、PWA、Jest、E2E 测试等

简而言之，Vue.js 跟上了时代的步伐，Vue-cli 只是更多的证据。

# 使用 Vue-cli 初始化一个新项目

安装完成后，我们可以使用以下命令初始化一个新项目：

```js
vue create quickstart-vue
```

我们给我们的 Vue 应用程序命名为*quickstart-vue*。我们也可以给它取其他任何名字。

一旦运行了上述命令，我们可以选择使用预设，或者手动选择要使用的功能：

```js
$ vue create quickstart-vue
 ? Please pick a preset: (Use arrow keys)
 > default (babel, eslint)
 Manually select features
```

我们可以选择默认预设，但作为一个小练习，让我们选择手动选择功能选项。然后我们将选择`npm`而不是`yarn`。这将导致屏幕上显示以下输出：

```js
$ vue create quickstart-vue
 ? Please pick a preset: (Use arrow keys)
 ? Please pick a preset: default (babel, eslint)
 ? Pick the package manager to use when installing dependencies: (Use arrow keys)
 ? Pick the package manager to use when installing dependencies: NPM
Installing CLI plugins. This might take a while...
```

当您看到这条消息时，您将知道插件已安装：

```js
...
Successfully created project quickstart-vue.
Get started with the following commands:
$ cd quickstart-vue
 $ npm run serve
```

现在我们可以简单地按照先前的说明，切换到`quickstart-vue`目录：

```js
cd quickstart-vue
```

接下来，我们将运行服务器（实际上是在后台运行 Webpack 开发服务器）：

```js
npm run serve
```

我们的应用程序可在端口`8080`上使用，将在控制台中记录。因此，让我们在`http://localhost:8080`上打开浏览器，查看默认站点：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-qk-st-gd/img/7ffa1c92-53e9-4b24-b12b-7e03948fe060.png)

在下一节中，我们将设置两个编辑器以与我们的新 Vue 项目一起使用。这些编辑器是 Sublime Text 和 Visual Studio Code。

# 设置代码编辑器以与 Vue 一起使用

有许多代码编辑器和**IDEs**（**集成开发环境**）可以用来处理 Vue。其中一些比较流行的包括：

+   Sublime Text [`www.sublimetext.com/`](https://www.sublimetext.com/)

+   Visual Studio Code (VS Code), [`code.visualstudio.com/`](https://code.visualstudio.com/)

+   Atom, [`atom.io/`](https://atom.io/)

+   WebStorm, [`www.jetbrains.com/webstorm/`](https://www.jetbrains.com/webstorm/)

+   Visual Studio 2017, [`visualstudio.microsoft.com/downloads/`](https://visualstudio.microsoft.com/downloads/)

在本节中，我们将看看如何在 Sublime Text 和 VS Code 中使用 Vue.js。

# 在 Sublime Text 3 中使用 Vue.js

Sublime Text 是一个成熟且有趣的文本编辑器，因此我们将下载并设置它以用于我们的 Vue.js 项目。

# 下载 Sublime Text 3

我们将从下载页面开始下载 Sublime Text 3：

[`www.sublimetext.com/3`](https://www.sublimetext.com/3)

接下来，访问网站[`packagecontrol.io/`](https://packagecontrol.io/)，这是 Sublime Text 的软件包管理器的主页。

# 安装软件包管理器

在软件包管理器网站上，单击页面右上角的立即安装按钮，然后按照这些安装步骤进行操作：

1.  选择并复制 Sublime Text 3 标签内的所有文本。

1.  打开新安装的 Sublime Text 3。

1.  在 Sublime Text 3 中，按下*Ctrl* + *`*（按住并按下控制键，然后按下反引号键）的键盘快捷键。在大多数键盘上，反引号字符位于键盘的字母数字部分的 1 号键左侧。

1.  将从[`packagecontrol.io`](https://packagecontrol.io)复制的代码粘贴到上一步中打开的底部输入字段中。

完成这些步骤后，重新启动 Sublime Text，您将可以通过此键盘快捷键访问快速启动安装程序：*Ctrl* + *Shift* + *P*。

这个键盘组合将在屏幕中间显示一个小输入框，您可以在其中输入单词`install`。这将显示不同的选项，您可以使用鼠标单击或使用`箭头上`和`箭头下`键进行突出显示，然后使用`Enter`键运行：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-qk-st-gd/img/951589bd-b6ae-4cda-985d-1a8a667b29c3.png)

接下来，选择读取“Package control: Install package”的选项。

这是我们将安装的软件包列表：

+   Vue Syntax Highlight，网址为[`packagecontrol.io/packages/Vue%20Syntax%20Highlight`](https://packagecontrol.io/packages/Vue%20Syntax%20Highlight)

+   Vuejs Snippets，网址为[`packagecontrol.io/packages/Vuejs%20Snippets`](https://packagecontrol.io/packages/Vuejs%20Snippets)

+   JavaScript Beautify，网址为[`packagecontrol.io/packages/Javascript%20Beautify`](https://packagecontrol.io/packages/Javascript%20Beautify)

有趣的是，Chrome 浏览器最近*也获得了类似的快速启动功能，可以通过相同的快捷键使用。要查看它的操作，您可以简单地使用*F12*键打开开发者工具实用程序，然后运行*Ctrl* + *Shift* + *P*快捷键。

例如，在打开的启动器中，您可以输入单词`node`，然后单击下拉菜单中的第一个命令`Capture node screenshot`。此命令将捕获您当前在 DOM 树中的元素的屏幕截图。

* 几个月前

在下一节中，我们将学习如何在 VS Code 中设置基于 Vue 的项目。

# 在 VS Code 中使用 Vue.js

尽管 Sublime Text 具有成熟和对系统资源消耗较少的优势，这使得它在较慢的机器上易于使用，但 VS Code 是一个可行的替代方案。

# 安装 VS Code 和扩展

让我们导航到[`code.visualstudio.com/download`](https://code.visualstudio.com/download)，并下载适合我们操作系统的 VS Code 版本。

如果您使用的是 Windows 10，您可以轻松地查看系统是 32 位还是 64 位。只需使用快捷键*Winkey* + *X*，然后在上下文菜单中单击 System。一个新窗口将打开，您将在`Device Specifications | System type`区域看到您的系统是 32 位还是 64 位。

一旦您下载并打开了 VS Code，就可以轻松地向其添加扩展。只需单击屏幕左侧最下方的图标（扩展图标）：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-qk-st-gd/img/97362cf0-30ec-4c01-8ea5-b8c44ab19cce.png)

单击该图标将打开扩展窗格，您可以在其中输入 Vue 并获得类似于此的结果：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-qk-st-gd/img/bc0a53e8-0fd8-45cf-b294-b43753a24bda.png)

接下来，只需选择 Vue VS Code Extension Packs 中的任一选项，然后单击绿色的 Install 按钮。此包含的扩展包括语法高亮、代码片段、代码检查和错误检查、格式化（如 js-beautify）、自动完成、悬停信息、自动重命名标签、VS Code 的 npm 支持、ES6 代码片段、ESLint 等。

或者，如果您想避免在 VS Code 扩展中出现臃肿，您可以通过安装 Pine Wu 的 Vetur 扩展来减少一些扩展，而不是之前提到的 Vue 扩展包。

安装完成后，我们只需单击标有 Reload 的按钮来重新启动 VS Code 并激活扩展。最后，要返回到项目的树结构，只需单击屏幕左侧 VS Code 主菜单下方的最顶部图标。

# 基于 Vue-cli 的项目结构

在这一部分，我们将看一下使用 Vue-cli 设置的 Vue 项目的文件结构。我们的`quickstart-vue`文件夹结构如下：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-qk-st-gd/img/411b4431-89b9-476b-ae41-c3f3b6d522ff.png)

让我们首先检查`main.js`文件的内容：

```js
import Vue from 'vue'
import App from './App.vue'

Vue.config.productionTip = false

new Vue({
  render: h => h(App)
}).$mount('#app')
```

我们首先从`vue`文件夹中导入`Vue`。这个`vue`文件夹位于你的`node_modules`文件夹中。

接下来，我们从`App.vue`中导入`App`。

正如我们已经学到的，`new Vue`创建了一个 Vue 实例，然后我们将选项对象传递给它。

在选项对象中，我们只设置了`render`属性。正如我们所看到的，`render`属性的值是一个箭头函数：

```js
h => h(App)
```

箭头函数接受作为其参数我们在`main.js`文件的第二行导入的`App`组件。

正如你可能已经注意到的，前面的函数是用 ES6 编写的。转译为 ES5 后，它会变成这样：

```js
function(h) {
  return h(App); }
```

前面的函数接收一个要呈现的 Vue 模板。它将在我们的`index.html`页面中呈现，替换我们传递给`$mount()`函数的 DOM 的任何静态部分。

它将在 DOM 中的位置取决于我们将什么作为参数传递给`$mount()`函数。在前面的代码中，我们传递了`#app`参数。

`'#app'`来自哪里？它来自`App`组件，更具体地来说，来自位于我们的`src`文件夹中的`App.vue`文件。

`src`文件夹包含我们 Vue 项目的所有实际应用程序代码。

请注意，`main.js`是我们项目中唯一的实际 JavaScript 文件——`src`文件夹中的所有文件都具有`.vue`扩展名。每个`.vue`文件都有三个部分：模板定义了组件的 HTML，脚本定义了 JS，样式标签定义了 CSS。此外，Vue-cli（在底层使用 Webpack）将所有这些放在一起，因为它知道如何处理`.vue`文件。

让我们修改我们`src`文件夹中的`App.vue`文件，使其看起来像这样：

```js
<template>
  <div id="app">
    <HelloWorld msg="Welcome to Vue Quickstart!"/>
    <HelloAgain />
  </div>
</template>

<script>
import HelloWorld from './components/HelloWorld.vue';
import HelloAgain from './components/HelloAgain.vue'

export default {
  name: 'app',
  components: {
    HelloWorld, HelloAgain
  }
}
</script>

<style>
#app {
  font-family: sans-serif;
  text-align: center;
  color: #2c3e50;
  margin-top: 60px;
}
</style>
```

让我们也改变`HelloWorld.vue`的内容，使其看起来像这样：

```js
<template>
  <div class="hello">
    <h1>{{ msg }}</h1>
    <p>
      This is the beginning of something great.
    </p>
 </div>
</template>

<script>
export default {
  name: 'HelloWorld',
  props: {
    msg: String
  }
}
</script>

<!-- Add "scoped" attribute to limit CSS to this component only -->
<style scoped>
p {
  font-size: 20px;
  font-weight: 600;
  text-align: center;
}
</style>
```

最后，让我们在`src/components/`文件夹中添加另一个组件。我们将其命名为`HelloAgain.vue`，并给它以下代码：

```js
<template>
 <p class="hello-again">
 This is another component.
 </p>
</template>

<script>
export default {
 name: 'HelloAgain'
}
</script>

<style scoped>
p {
 font-size: 16px;
 text-align: center;
 color: tomato;
}
</style>
```

在这三个文件中，我们主要只是删除了一些额外的代码，以更清楚地展示以下几点：

+   每个`vue`文件都包含一个单文件组件

+   每个单文件组件的结构都遵循相同的模式：顶部是模板，中间是脚本，底部是样式

+   样式可以针对每个单独的文件进行作用域限定

+   `App.vue`文件从`components`文件夹导入组件并导出自身，以便`main.js`可以使用它

+   `HelloWorld`和`HelloAgain`组件只是将自己导出到父组件`App.vue`文件中

+   为了使用新引入的组件（`HelloAgain`组件），`App.vue`文件需要在其`<template>`标签内添加它

+   `App.vue`文件还需要导入和导出`HelloAgain`单文件模板，以便`main.js`可以使用它

`App.vue`，`HelloWorld.vue`和`HelloAgain.vue`是单文件组件的示例。单文件组件是我们 Vue 项目中使用组件的首选方式。

如果您按照前面描述的更改文件，您应该在浏览器中的`http://localhost:8080`看到以下屏幕：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-qk-st-gd/img/36843230-2832-419a-8797-b07bdbab04fa.png)

现在我们已经看到了`vue/components/`文件夹的组织方式和基本工作原理，我们将列出我们 Vue 项目中的其他重要文件：

1.  不应该被 Git 源代码版本控制跟踪的文件列表：`.gitignore`

1.  Babel 的配置文件：`.babel.config.js`

1.  列出我们基于 npm 的项目的依赖项和其他信息的文件：`package.json`

1.  我们应用的 markdown 格式手册：`README.md`

当然，还有一个公共文件夹，其中包含我们编译后的应用程序，从`index.html`文件中引用。这个文件最终将在浏览器中呈现和重新呈现，因为我们的 Vue 应用程序不断编译。`index`文件的内容非常简单：

```js
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width,initial-scale=1.0">
    <link rel="icon" href="<%= BASE_URL %>favicon.ico">
    <title>quickstart-vue</title>
  </head>
  <body>
    <noscript>
      <strong>
        We're sorry but quickstart-vue doesn't work properly 
        without JavaScript enabled. Please enable it to continue.
      </strong>
    </noscript>
    <div id="app"></div>
    <!-- built files will be auto injected -->
  </body>
</html>
```

如前所述，`id`属性设置为`app`的`div`是我们 Vue 应用程序的入口点。

现在我们对项目结构有了更好的理解，我们将继续构建子组件。

在下一节中，我们将向我们的`HelloAgain`组件添加一些基本功能。

# 向子组件添加基本功能

在这一部分，我们将向子组件添加一些非常基本的功能。在我们深入了解如何做到这一点之前，我们还需要安装官方的 Vue Chrome 扩展。

Chrome 的 Vue 开发者工具扩展可以在此 URL 找到：[`bit.ly/2Pkpk2I`](http://bit.ly/2Pkpk2I)。

安装官方的 Vue Chrome 扩展很简单；您只需像安装其他 Chrome 扩展一样安装它。

安装完成后，你将在 Chrome 右上角看到一个 Vue 标志，点击该标志将会给你以下消息：

Vue.js 在此页面上被检测到。打开 DevTools 并查找 Vue 面板。

打开 DevTools 很容易：只需按 F12 键。然后你可以在具有以下标签的区域中找到 Vue 面板：元素、控制台、源等。你应该会得到类似以下屏幕的东西：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-qk-st-gd/img/57fb3263-e102-4969-a3d2-8b4dc908bc44.png)

回到 VS Code，让我们打开`HelloAgain.vue`组件，并更新代码的模板部分，使其看起来像这样：

```js
<template>
 <p class="hello-again">
 This is another component.
 <button v-on:click="incrementUp">Add One</button>
 <br>
 <span>Current value of the counter: {{ counter }}</span>
 </p>
</template>
```

让我们也更新`script`标签，就像这样：

```js
<script>
export default {
 name: 'HelloAgain',
 data() {
     return {
         counter: 0
     }
 },
 methods: {
     incrementUp: function() {
         this.counter++
     }
 }
}
</script>
```

最后，我们将更新样式，使我们的按钮看起来更漂亮：

```js
<style scoped>
p {
 font-size: 16px;
 text-align: center;
 color: tomato;
}
button {
    display: block;
    margin: 10px auto;
    background: tomato;
    color: white;
    border: none;
    padding: 5px 10px;
    font-size: 16px;
    border-radius: 4px;
    cursor: pointer;
}
</style>
```

这次更新的最终结果将在我们的浏览器中呈现如下：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-qk-st-gd/img/36b70dfd-26c2-402f-a6ae-6657f22cc9bd.png)

现在我们已经看过构建模板和使用一些基本功能，让我们把重点转移到另一个重要的主题：组件之间的通信。我们将从重新审视 props 开始，这是一种在父组件和子组件之间通信的方式。

# 向我们的 HelloAgain.vue 添加 props

在这一部分，我们将简要回顾 props，看一个在 Vue 中如何在父组件和子组件之间通信的实际例子。换句话说，我们想从父组件获取一些数据并将其传递给子组件。我们将要传递的数据只是要包含在我们的`quickstart-vue`应用程序的计数器中的额外数字。

在我们的`App.vue`文件中，我们将添加一个按钮：

```js
<template>
  <div id="app">
    <HelloWorld msg="Welcome to Vue Quickstart!"/>
    <button v-on:click="addTen">Add 10</button>
    <HelloAgain v-bind:counterFromParent="countUp"/>
  </div>
</template>
```

按钮放置在我们已经拥有的两个组件之间。我们已经添加了`v-on`指令，跟踪按钮上的点击事件。点击事件将触发`addTen`方法，因此我们将在`App.vue`文件的`<script>`标签之间指定它：

```js
  methods: {
    addTen() {
      this.countUp += 10
    }
  },
```

`addTen`方法正在使用`countUp`数据片段，所以让我们也将这个新数据添加到我们的`<script>`中：

```js
  data: function() {
    return {
      countUp: 0
    };
  },
```

因此，最初，我们在`App.vue`中的`data`函数返回零的`countUp`。每当用户点击我们的`App.vue`组件中的按钮时，`countUp`的值增加 10。这个值是我们想要传递给子组件的数据，即`HelloAgain.vue`子组件中计数器中存储的值。

这就是`props`语法的用法。为了告诉我们的`HelloAgain.vue`组件它应该期望来自父组件的数据，我们将添加以下代码：

```js
props: ['counterFromParent']
```

`props`键的值是一个数组，我们在其中添加了子组件应该从父组件那里期望的`props`字符串。

请注意，`props`选项也可以是一个对象。使用对象作为我们`props`选项的示例是，例如，如果我们想要验证从父组件传递给子组件的数据。我们将在本书的后面章节中验证`props`。

在`HelloAgain.vue`中，我们将修改其模板内的`<span>`标签，就像这样：

```js
<span>Current value of the counter: {{ counter + counterFromParent }}</span>
```

现在我们已经在父组件和子组件中设置了代码，只需将数据从一个传递到另一个。我们将在`App.vue`模板中通过在`<HelloAgain />`标签上添加`v-bind`指令来实现这一点。以下是更新后的`App.vue`模板：

```js
<template>
  <div id="app">
    <HelloWorld msg="Welcome to Vue Quickstart!"/>
    <button v-on:click="addTen">Add 10</button>
    <HelloAgain v-bind:counterFromParent="countUp"/>
  </div>
</template>
```

请注意，我们将`counterFromParent`绑定到`countUp`的值。`countUp`的值从零开始，每次点击父组件按钮时，将运行`addTen`方法，我们在父组件`<script>`标签的`methods`选项中指定了这一点。

`addTen`方法将 10 添加到`countUp`的当前值。

在子组件`HelloAgain.vue`中，我们只需将`counterFromParent`的当前值添加到我们的`counter`变量中。要获取`counterFromParent`的值，我们将其列在`HelloAgain.vue`组件的`<script>`标签的`props`数组中。

# 从子组件传递数据到父组件

要从子组件传递数据到父组件，我们使用以下语法：

```js
this.$emit();
```

`$`符号用于表示内置的 Vue 函数。这个特定的`$emit`函数用于向父组件发送自定义事件。我们传递给`$emit`函数的第一个参数是自定义事件的名称。例如，我们可以将计数器重置为零，所以我们可以像这样命名自定义事件：

```js
this.$emit('counterHasBeenReset')
```

第二个参数是要传递的数据，所以我们将传递当前的计数器值，就像这样：

```js
this.$emit('counterHasBeenReset', this.countUp);
```

当然，这意味着我们需要更新`countUp`的值，使其返回到零。为了做到这一点，我们需要更新`HelloAgain`子组件的`<script>`标签中的`methods`选项，使其看起来像这样：

```js
 methods: {
     incrementUp: function() {
         this.counter++
     },
     resetTheCounter() {
         this.countUp = 0;
         this.$emit('counterHasBeenReset', this.countUp);
     }
 }
```

基本上，我们在方法选项中说，每当运行`resetTheCounter`方法时，`countUp`的值应该被重置为`0`。接下来，我们通过在`counterHasBeenReset`自定义事件中发出这个更新后的值来跟进。

现在让我们在子组件`template`标签中添加一个重置按钮，也在`HelloAgain.vue`中。我们只需在`template`标签中添加另一行即可：

```js
<button v-on:click="resetTheCounter">Reset parent-added values</button>
```

正如我们在这里看到的，按钮点击将运行`resetTheCounter`方法。

现在我们正在发出事件，我们将使用以下语法在父组件中捕获它：

```js
<HelloAgain v-bind:counterFromParent="countUp" v-on:counterHasBeenReset="countUp = $event" />
```

正如我们在这里看到的，我们在父组件中的`<HelloAgain>`标签中添加了内容。具体来说，我们添加了一个`v-on`指令，如下所示：

```js
v-on:counterHasBeenReset="countUp = $event" />
```

该组件正在监听`counterHasBeenReset`自定义事件，该事件将从子组件中发出。当在父组件中捕获到这样的事件时，`countUp`的值将被设置为事件本身中的值。由于我们将其设置为零，它就是零。

在 Vue 中，有其他的方式来在组件之间进行通信（包括父到子和子到子），我们将在后面的章节中讨论它们，当我们讨论 Vuex 时。

这个练习的最终结果是，我们将重置从父组件中添加的计数器中的值，但该事件不会影响从子组件中添加的值。

现在我们已经了解了自定义事件，我们可以通过查看插槽来继续讨论组件。

# 插槽介绍

插槽是重用组件的一种方式。通过 props，我们将数据传递给组件。但是，如果我们想要将整个组件传递给其他组件怎么办？这就是插槽的用武之地。

插槽只是一种将更复杂的代码传递给我们的组件的方法。它们可以是一些 HTML，甚至是整个组件。

要将 HTML 元素从父组件插入到子组件中，我们在子组件内部使用`slot`元素：

```js
<slot></slot>
```

插槽的实际内容在父组件中指定。

这是插槽使用的一个例子：

```js
<!-- HTML -->
<div id="app"></div>

// JS
Vue.component("basicComponent", {
  template: `
    <div>
      <slot name="firstSlot"></slot>
      <slot name="secondSlot"></slot>
      <slot></slot>
    </div>
  `
});

new Vue({
  el: "#app",
  template: `
    <basicComponent>
      <p slot="firstSlot">
        This content will populate the slot named 'firstSlot' 
        in the 'basicComponent' template
      </p>
      <p slot="secondSlot">
        This content will populate the slot named 'secondSlot' 
        in the 'basicComponent' template
      </p>
    </basicComponent>
  `
});

/* CSS */
div {
  font-size: 30px;
  padding: 20px;
  color: darkgoldenrod;
  font-family: Arial;
  border: 3px solid darkgoldenrod;
  border-radius: 0px;
}
```

这个例子可以在这里实时查看：[`codepen.io/AjdinImsirovic/pen/ERoLQM`](https://codepen.io/AjdinImsirovic/pen/ERoLQM)。

在处理插槽时有几个关键点：

+   插槽是基于 Web 组件规范草案实现的

+   插槽的样式由子组件中的作用域样式标签确定

+   插槽使可组合组件的使用成为可能

+   您可以在插槽中使用任何模板代码

+   如果您有多个插槽，可以为它们命名（使用`name`属性）

+   如果您有多个插槽，可以在其中一个插槽中省略`name`属性，那个插槽将成为默认插槽

+   从 Vue 2.1.0 开始，插槽可以被作用域化

+   插槽作用域可以使用 ES2015 表达式解构进行解构

要向插槽添加默认信息，只需在插槽标记中添加内容。

只需将插槽标记的代码从这个：

```js
<slot></slot>
```

更改为这个：

```js
<slot>This is some default information</slot>
```

如果您通过在提供的示例笔中添加上面引用的默认未命名插槽代码来更新它，您会注意到即使我们没有在 Vue 实例中引用它，插槽也会被填充。

# 总结

在本章中，我们讨论了 Vue 的组件。我们讨论了 Vue 组件层次结构以及全局和本地组件之间的区别。我们启动了 Vue-cli v3 并学习了如何使用它。我们使用`.vue`文件并在几个代码编辑器中设置了开发环境。我们了解了如何向子组件添加功能以及 props 和 slots 的用例。最后，我们看了 Vue 中的组件通信。

在下一章中，我们将讨论过滤器作为改变屏幕上呈现内容的一种方式，而不影响其背后的数据。我们还将看到如何在编程中遵循 DRY 规则，借助混合来实现。
