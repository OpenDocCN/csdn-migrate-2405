# Vue2 和 Laravel5 全栈开发（一）

> 原文：[`zh.annas-archive.org/md5/e47ac4de864f495f2e21aebfb4a63e4f`](https://zh.annas-archive.org/md5/e47ac4de864f495f2e21aebfb4a63e4f)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

现在是 2014 年，**单页应用**（SPA）解决方案的战争真正激烈。有许多竞争对手：Angular、React、Ember、Knockout 和 Backbone 等等。然而，最受关注的战斗是在谷歌的 Angular 和 Facebook 的 React 之间。

直到这一点，SPA 之王 Angular 是一个完整的框架，遵循熟悉的 MVC 范例。而 React，这个不太可能的挑战者，与其核心库只处理视图层，而且标记完全由 JavaScript 编写，相比之下似乎相当奇怪！虽然 Angular 占据着更大的市场份额，但 React 在开发人员思考 Web 应用设计的方式上引起了巨大的变革，并提高了框架的大小和性能。

与此同时，一位名叫 Evan You 的开发人员正在尝试自己的新框架 Vue.js。它将结合 Angular 和 React 的最佳特性，实现简单和强大之间的完美平衡。你的愿景与其他开发人员的共鸣如此之好，以至于 Vue 很快就成为最受欢迎的 SPA 解决方案之一。

尽管竞争激烈，但 Vue 迅速获得了关注。这在一定程度上要归功于 Laravel 的创始人 Taylor Otwell，他在 2015 年初发推特称赞 Vue 的印象深刻。这条推文引起了 Laravel 社区对 Vue 的极大兴趣。

Vue 和 Laravel 的合作将在 2016 年 9 月发布的 Laravel 5.3 版本中进一步紧密结合，当时 Vue 被包含为默认的前端库。对于具有相同理念的两个软件项目来说，这是一个完全合乎逻辑的联盟：简单和开发者体验的重点。

如今，Vue 和 Laravel 为开发 Web 应用提供了一个非常强大和灵活的全栈框架，正如你将在本书中发现的那样，它们是非常愉快的工作对象。

# 本书涵盖的内容

构建一个全栈应用需要广泛的知识，不仅仅是关于 Vue 和 Laravel，还包括 Vue Router、Vuex 和 Webpack，更不用说 JavaScript、PHP 和 Web 开发的一般知识了。

因此，作为作者，我面临的最大挑战之一是决定应该包括什么，不应该包括什么。我最终确定的主题是对以下两个问题的回答：

+   读者在所有或大多数 Vue.js 应用中将使用的基本特性、工具和设计模式是什么？

+   相对于其他架构，设计和构建全栈 Vue.js 应用的关键问题是什么？

以下是本书各章节涉及的主题分布：

第一章《你好 Vue - Vue.js 简介》介绍了 Vue.js 的概述，以及本书的案例研究项目*Vuebnb*。

第二章《原型设计 Vuebnb，你的第一个 Vue.js 项目》提供了 Vue.js 基本特性的实际介绍，包括安装、模板语法、指令、生命周期钩子等。

第三章《设置 Laravel 开发环境》展示了如何为全栈 Vue.js 应用设置一个新的 Laravel 项目。

第四章《使用 Laravel 构建 Web 服务》是关于为我们的案例研究项目的后端奠定基础，包括设置数据库、模型和 API 端点。

第五章《使用 Webpack 集成 Laravel 和 Vue.js》解释了一个复杂的 Vue 应用将需要构建步骤，并介绍了用于捆绑项目资产的 Webpack。

第六章《使用 Vue.js 组件构建小部件》教授了组件是现代 UI 开发的一个基本概念，也是 Vue.js 最强大的功能之一。

第七章《使用 Vue Router 构建多页面应用》介绍了 Vue Router，并展示了如何在前端应用中添加虚拟页面。

第八章《使用 Vuex 管理应用状态》解释了状态管理是管理复杂 UI 数据的必备功能。我们介绍了 Flux 模式和 Vuex。

第九章，“使用 Passport 添加用户登录和 API 身份验证”，专注于全栈应用程序中最棘手的部分之一——身份验证。本章展示了如何使用 Passport 进行安全的 AJAX 调用到后端。

第十章，“将全栈应用部署到云端”，描述了如何构建和部署我们完成的项目到基于云的服务器，并使用 CDN 来提供静态资产。

# 你需要为这本书做好准备

在你开始案例研究项目的开发之前，你必须确保你有正确的软件和硬件。

# 操作系统

你可以使用基于 Windows 或 Linux 的操作系统。不过我是 Mac 用户，所以本书中使用的所有终端命令都将是 Linux 命令。

请注意我们将使用 Homestead 虚拟开发环境，其中包括 Ubuntu Linux 操作系统。如果你 SSH 进入这个虚拟机并从那里运行所有终端命令，你可以使用和我一样的命令，即使你使用的是 Windows 主机操作系统。

# 开发工具

下载项目代码将需要 Git。如果你还没有安装 Git，请按照这个指南中的说明进行：[`git-scm.com/book/en/v2/Getting-Started-Installing-Git`](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git)。

要开发一个 JavaScript 应用程序，你需要 Node.js 和 NPM。它们可以从同一个软件包中安装；请参阅这里的说明：[`nodejs.org/en/download/`](https://nodejs.org/en/download/)。

我们还将使用 Laravel Homestead。第三章将提供设置 Laravel 开发环境的说明。

# 浏览器

Vue 需要 ECMAScript 5，这意味着你可以使用任何主流浏览器的最新版本来运行它。我建议你使用 Google Chrome，因为我将为 Chrome Dev Tools 提供调试示例，如果你也使用 Chrome，那么你跟着学会会更容易。

在选择浏览器时，你还应该考虑与 Vue Devtools 的兼容性。

# Vue Devtools

Vue Devtools 浏览器扩展使得调试 Vue 变得轻而易举，在本书中我们将大量使用它。这个扩展是为 Google Chrome 设计的，但也可以在 Firefox 中使用（还有 Safari，需要稍微修改一下）。

查看以下链接以获取更多信息和安装说明：[`github.com/vuejs/vue-devtools`](https://github.com/vuejs/vue-devtools)

# IDE

当然，你需要一个文本编辑器或 IDE 来开发案例研究项目。

# 硬件

你需要一台配置足够安装和运行上述软件的计算机。最消耗资源的程序将是 VirtualBox 5.2（或 VMWare 或 Parallels），我们将使用它来设置 Homestead 虚拟开发环境。

你还需要一个互联网连接来下载源代码和项目依赖。

# 这本书适合谁

这本书是为寻求使用 Vue.js 和 Laravel 进行全栈开发的 Laravel 开发者而写的，提供了实用和最佳实践的方法。

任何对这个主题感兴趣的网页开发者都可以成功使用这本书，只要他们满足以下条件：

| 主题 | 级别 |
| --- | --- |
| HTML 和 CSS | 中级知识 |
| JavaScript | 中级知识 |
| PHP | 中级知识 |
| Laravel | 基础知识 |
| Git | 基础知识 |

请注意读者不需要有 Vue.js 或其他 JavaScript 框架的经验。

# 约定

在本书中，你会发现一些文本样式，用来区分不同类型的信息。以下是一些这些样式的例子和它们的含义解释。

文本中的代码单词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 用户名都显示如下：“例如，在这里我创建了一个自定义元素，`grocery-item`，它呈现为`li`。”

代码块设置如下：

```php
<div id="app">
  <!--Vue has dominion within this node-->
</div>
<script> new Vue({ el: '#app'
  }); </script>
```

任何命令行输入或输出都以以下方式编写：

```php
$ npm install
```

**新术语**和**重要词汇**以粗体显示。屏幕上看到的词语，例如菜单或对话框中的词语，会以这样的方式出现在文本中："Vue 不允许这样做，如果你尝试会出现这个错误：不要将 Vue 挂载到 <html> 或 <body> - 而是挂载到普通元素上。"

警告或重要提示会以这样的方式出现在一个框中。提示和技巧会以这样的方式出现。


# 第一章：你好 Vue - Vue.js 简介

欢迎来到《全栈 Vue.js 2 和 Laravel 5》！在本章中，我们将对 Vue.js 进行高层次的概述，让您熟悉它的功能，为学习如何使用它做好准备。

我们还将熟悉本书中的主要案例研究项目 Vuebnb。

本章涵盖的主题：

+   Vue 的基本特性，包括模板、指令和组件

+   Vue 的高级特性，包括单文件组件和服务器端渲染

+   Vue 生态系统中的工具，包括 Vue Devtools、Vue Router 和 Vuex

+   您将在本书中逐步构建的主要案例研究项目是 Vuebnb

+   安装项目代码的说明

# 介绍 Vue.js

截至 2017 年底，Vue.js 的版本是 2.5。在首次发布不到四年的时间里，Vue 已经成为 GitHub 上最受欢迎的开源项目之一。这种受欢迎程度部分是由于其强大的功能，也是由于其强调开发者体验和易于采用。

Vue.js 的核心库，像 React 一样，只用于从 MVC 架构模式中操纵视图层。然而，Vue 有两个官方支持库，Vue Router 和 Vuex，分别负责路由和数据管理。

Vue 不像 React 和 Angular 那样得到科技巨头的支持，而是依赖于少数公司赞助商和专门的 Vue 用户的捐赠。更令人印象深刻的是，Evan You 目前是唯一的全职 Vue 开发人员，尽管来自世界各地的 20 多名核心团队开发人员协助开发、维护和文档编写。

Vue 的关键设计原则如下：

+   **重点**：Vue 选择了一个小而集中的 API，它的唯一目的是创建 UI

+   **简单性**：Vue 的语法简洁易懂

+   **紧凑**：核心库脚本压缩后约为 25 KB，比 React 甚至 jQuery 都要小

+   **速度**：渲染基准超过了许多主要框架，包括 React

+   **多功能性**：Vue 非常适合小型任务，您可能会使用 jQuery，但也可以扩展为合法的 SPA 解决方案

# 基本特性

现在让我们对 Vue 的基本特性进行高层次的概述。如果您愿意，您可以在计算机上创建一个 HTML 文件，如下所示，然后在浏览器中打开它，并按照以下示例进行编码。

如果你宁愿等到下一章，当我们开始进行案例研究项目时，那也可以，因为我们这里的目标只是为了感受一下 Vue 能做什么：

```php
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <title>Hello Vue</title>
</head>
<body>
  <!--We'll be adding stuff here!-->
</body>
</html>
```

# 安装

尽管 Vue 可以在更复杂的设置中作为 JavaScript 模块使用，但它也可以简单地作为外部脚本包含在 HTML 文档的主体中：

```php
<script src="https://unpkg.com/vue/dist/vue.js"></script>
```

# 模板

默认情况下，Vue 将使用 HTML 文件作为其模板。包含的脚本将声明 Vue 的一个实例，并在配置对象中使用`el`属性告诉 Vue 在模板中的哪个位置挂载应用程序：

```php
<div id="app">
  <!--Vue has dominion within this node-->
</div>
<script> new Vue({ el: '#app'
  }); </script>
```

我们可以通过将其创建为`data`属性并使用 mustache 语法将其打印到页面中，将数据绑定到我们的模板中：

```php
<div id="app"> {{ message }} <!--Renders as "Hello World"-->
</div>
<script> new Vue({ el: '#app', data: { message: 'Hello World'
    }
  }); </script>
```

# 指令

与 Angular 类似，我们可以使用**指令**向我们的模板添加功能。这些是我们添加到以`v-`前缀开头的 HTML 标签的特殊属性。

假设我们有一个数据数组。我们可以使用`v-for`指令将这些数据呈现为页面上的连续 HTML 元素：

```php
<div id="app">
  <h3>Grocery list</h3>
  <ul>
    <li v-for="grocery in groceries">{{ grocery }}</li>
  </ul>
</div>
<script> var app = new Vue({ el: '#app', data: { groceries: [ 'Bread', 'Milk' ]
    }
  }); </script>
```

上述代码呈现如下：

```php
<div id="app">
  <h3>Grocery list</h3>
  <ul>
    <li>Bread</li>
    <li>Milk</li>
  </ul>
</div>
```

# 响应性

Vue 设计的一个关键特性是其响应性系统。当您修改数据时，视图会自动更新以反映这一变化。

例如，如果我们创建一个函数，在页面已经呈现后将另一个项目推送到我们的杂货项目数组中，页面将自动重新呈现以反映这一变化：

```php
setTimeout(function() { app.groceries.push('Apples');
}, 2000);
```

初始渲染后两秒，我们看到了这个：

```php
<div id="app">
  <h3>Grocery list</h3>
  <ul>
    <li>Bread</li>
    <li>Milk</li>
    <li>Apples</li>
  </ul>
</div>
```

# 组件

组件扩展了基本的 HTML 元素，并允许您创建自己的可重用自定义元素。

例如，这里我创建了一个自定义元素`grocery-item`，它渲染为一个`li`。该节点的文本子节点来自自定义 HTML 属性`title`，在组件代码内部可以访问到：

```php
<div id="app">
  <h3>Grocery list</h3>
  <ul>
    <grocery-item title="Bread"></grocery-item>
    <grocery-item title="Milk"></grocery-item>
  </ul>
</div>
<script> Vue.component( 'grocery-item', { props: [ 'title' ], template: '<li>{{ title }}</li>'
  });

  new Vue({ el: '#app'
  }); </script>
```

这样渲染：

```php
<div id="app">
  <h3>Grocery list</h3>
  <ul>
    <li>Bread</li>
    <li>Milk</li>
  </ul>
</div>
```

但使用组件的主要原因可能是它更容易构建一个更大的应用程序。功能可以被分解为可重用的、自包含的组件。

# 高级功能

如果你迄今为止一直在跟着示例编码，那么请关闭你的浏览器，直到下一章，因为以下高级片段不能简单地包含在浏览器脚本中。

# 单文件组件

使用组件的一个缺点是，你需要在主 HTML 文件之外的 JavaScript 字符串中编写你的模板。虽然有办法在 HTML 文件中编写模板定义，但这样就会在标记和逻辑之间产生尴尬的分离。

一个方便的解决方案是**单文件组件**：

```php
<template>
  <li v-on:click="bought = !bought" v-bind:class="{ bought: bought }">
    <div>{{ title }}</div>
  </li>
</template>
<script> export default { props: [ 'title' ], data: function() {
      return { bought: false
      };
    }
  } </script>
<style> .bought {
    opacity: 0.5;
  } </style>
```

这些文件的扩展名是`.vue`，它们封装了组件模板、JavaScript 配置和样式，全部在一个文件中。

当然，网页浏览器无法读取这些文件，因此它们需要首先通过 Webpack 这样的构建工具进行处理。

# 模块构建

正如我们之前所看到的，Vue 可以作为外部脚本直接在浏览器中使用。Vue 也可以作为 NPM 模块在更复杂的项目中使用，包括像 Webpack 这样的构建工具。

如果你对 Webpack 不熟悉，它是一个模块打包工具，可以将所有项目资产捆绑在一起，形成可以提供给浏览器的东西。在捆绑过程中，你也可以转换这些资产。

使用 Vue 作为模块，并引入 Webpack，可以开启以下可能性：

+   单文件组件

+   当前浏览器不支持的 ES 功能提案

+   模块化的代码

+   预处理器，如 SASS 和 Pug

我们将在第五章中更深入地探索 Webpack，*使用 Webpack 集成 Laravel 和 Vue.js*。

# 服务器端渲染

服务器端渲染是增加全栈应用程序加载速度感知度的好方法。用户在加载您的网站时会得到一个完整的页面，而不是直到 JavaScript 运行时才会填充的空页面。

假设我们有一个使用组件构建的应用。如果我们使用浏览器开发工具在页面加载后查看我们的页面 DOM，我们将看到我们完全渲染的应用：

```php
<div id="app">
  <ul>
    <li>Component 1</li>
    <li>Component 2</li>
    <li>
      <div>Component 3</div>
    </li>
  </ul>
</div>
```

但是，如果我们查看文档的源代码，也就是`index.html`，就像服务器发送时一样，你会看到它只有我们的挂载元素：

```php
<div id="app"></div>
```

为什么？因为 JavaScript 负责构建我们的页面，因此 JavaScript 必须在页面构建之前运行。但是通过服务器端渲染，我们的`index`文件包含了浏览器在下载和运行 JavaScript 之前构建 DOM 所需的 HTML。应用程序加载速度并没有变快，但内容会更快地显示出来。

# Vue 生态系统

虽然 Vue 是一个独立的库，但与其生态系统中的一些可选工具结合使用时，它会变得更加强大。对于大多数项目，你将在前端堆栈中包含 Vue Router 和 Vuex，并使用 Vue Devtools 进行调试。

# Vue 开发者工具

Vue Devtools 是一个浏览器扩展，可以帮助你开发 Vue.js 项目。除其他功能外，它允许你查看应用程序中组件的层次结构和组件的状态，这对调试很有用：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/e2a740c8-9968-41bd-abc5-bd75678dc1e8.png)图 1.1 Vue Devtools 组件层次结构

我们将在本节的后面看到它还能做什么。

# Vue 路由

Vue Router 允许你将 SPA 的不同状态映射到不同的 URL，给你虚拟页面。例如，`mydomain.com/`可能是博客的首页，并且有这样的组件层次结构：

```php
<div id="app">
  <my-header></my-header>
  <blog-summaries></blog-summaries>
  <my-footer></my-footer>
</div>
```

而`mydomain.com/post/1`可能是博客中的一个单独的帖子，看起来像这样：

```php
<div id="app">
  <my-header></my-header>
  <blog-post post-id="id">
  <my-footer></my-footer>
</div>
```

从一个页面切换到另一个页面不需要*重新加载*页面，只需交换中间组件以反映 URL 的状态，这正是 Vue Router 所做的。

# Vuex

Vuex 提供了一种强大的方式来管理应用程序的数据，随着 UI 的复杂性增加，它将应用程序的数据集中到一个单一的存储中。

我们可以通过检查 Vue Devtools 中的存储来获取应用程序状态的快照：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/bf4b939f-e14b-4b6f-9ab0-a1610a226a53.png)图 1.2 Vue Devtools Vuex 标签

左侧列跟踪对应用程序数据所做的更改。例如，用户保存或取消保存项目。您可以将此事件命名为`toggleSaved`。Vue Devtools 允许您在事件发生时查看此事件的详细信息。

我们还可以在不触及代码或重新加载页面的情况下恢复到数据的任何先前状态。这个功能称为*时间旅行调试*，对于调试复杂的 UI 来说，您会发现它非常有用。

# 案例研究项目

在快速概述了 Vue 的主要特性之后，我相信您现在渴望开始真正学习 Vue 并将其投入使用。让我们首先看一下您将在整本书中构建的案例研究项目。

# Vuebnb

Vuebnb 是一个现实的全栈 Web 应用程序，它利用了 Vue、Laravel 和本书中涵盖的其他工具和设计模式的许多主要特性。

从用户的角度来看，Vuebnb 是一个在线市场，可以在世界各地的城市租用短期住宿。您可能会注意到 Vuebnb 和另一个名字类似的住宿在线市场之间的一些相似之处！

您可以在此处查看 Vuebnb 的完成版本：[`vuebnb.vuejsdevelopers.com`](http://vuebnb.vuejsdevelopers.com)。

如果您现在没有互联网访问权限，这里有两个主要页面的截图。首先是主页，用户可以在这里搜索或浏览住宿选项：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/e7edf13d-6cd8-4425-805a-8859ba7c33ca.png)图 1.3 Vuebnb 主页

其次是列表页面，用户可以在这里查看特定于可能有兴趣租用的单个住宿的信息：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/8b696452-b4fe-4c1f-9e5e-bef57ff51798.png)图 1.4 Vuebnb 列表页面

# 代码库

案例研究项目贯穿整本书的整个持续时间，因此一旦您创建了代码库，您可以逐章添加内容。最终，您将从头开始构建和部署一个全栈应用程序。

代码库位于 GitHub 存储库中。您可以将其下载到计算机上通常放置项目的任何文件夹中，例如`~/Projects`：

```php
$ cd ~/Projects
$ git clone https://github.com/PacktPublishing/Full-Stack-Vue.js-2-and-Laravel-5
$ cd Full-Stack-Vue.js-2-and-Laravel-5
```

与其直接克隆此存储库，不如首先进行*分叉*，然后再克隆。这样可以让您随意进行任何更改，并将您的工作保存到您自己的远程存储库。这里有一个关于在 GitHub 上进行分叉存储库的指南：[`help.github.com/articles/fork-a-repo/`](https://help.github.com/articles/fork-a-repo/)。

# 文件夹

代码库包含以下文件夹：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/518ac8ab-b6d2-40e6-895e-3104c7e15fb3.png)图 1.5 代码库目录内容

以下是每个文件夹的用途概述：

+   `Chapter02`到`Chapter10`包含每章的代码的*完成状态*（不包括本章）

+   *images*目录包含 Vuebnb 中用于使用的示例图片。这将在第四章中进行解释，*使用 Laravel 构建 Web 服务*

+   *vuebnb*是您将在第三章开始工作的主要案例研究项目的项目代码，*设置 Laravel 开发环境*

+   *vuebnb-prototype*是 Vuebnb 原型的项目代码，我们将在第二章中构建，*原型设计 Vuebnb，您的第一个 Vue.js 项目*

# 总结

在本章中，我们对 Vue.js 进行了高层次的介绍，涵盖了模板、指令和组件等基本特性，以及单文件组件和服务器端渲染等高级特性。我们还看了 Vue 生态系统中的工具，包括 Vue Router 和 Vuex。

然后我们对 Vuebnb 进行了概述，这是您在阅读本书时将要构建的全栈项目，并了解了如何从 GitHub 安装代码库。

在下一章中，我们将适当地了解 Vue 的基本特性，并开始通过构建 Vuebnb 的原型来使用它们。


# 第二章：Vuebnb 原型，您的第一个 Vue.js 项目

在本章中，我们将学习 Vue.js 的基本特性。然后，我们将把这些知识付诸实践，通过构建 Vuebnb 的案例研究项目原型。

本章涵盖的主题：

+   Vue.js 的安装和基本配置

+   Vue.js 的基本概念，如数据绑定、指令、观察者和生命周期钩子

+   Vue 的响应系统是如何工作的

+   案例研究项目的项目要求

+   使用 Vue.js 添加页面内容，包括动态文本、列表和页眉图像

+   使用 Vue 构建图像模态 UI 功能

# Vuebnb 原型

在本章中，我们将构建 Vuebnb 的原型，这是本书持续运行的案例研究项目。原型将只是列表页面，到本章结束时将会是这样的：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/9596f4dc-9623-43d0-8f51-f6ab7f04aa46.png)图 2.1 Vuebnb 原型

一旦我们在第三章 *设置 Laravel 开发环境*和第四章 *使用 Laravel 构建 Web 服务*中设置好了我们的后端，我们将把这个原型迁移到主项目中。

# 项目代码

在开始之前，您需要通过从 GitHub 克隆代码库将其下载到您的计算机上。在第一章的*代码库*部分中给出了说明，*你好 Vue - Vue.js 简介*。

`vuebnb-prototype`文件夹中包含了我们将要构建的原型的项目代码。切换到该文件夹并列出其中的内容：

```php
$ cd vuebnb-prototype
$ ls -la
```

文件夹内容应该如下所示：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/da98e41f-aca7-4d8c-9f95-07ea87433c5a.png)图 2.2 vuebnb-prototype 项目文件除非另有说明，本章中所有后续的终端命令都假定您在`vuebnb-prototype`文件夹中。

# NPM 安装

您现在需要安装此项目中使用的第三方脚本，包括 Vue.js 本身。NPM `install`方法将读取包含的`package.json`文件并下载所需的模块：

```php
$ npm install
```

您现在会看到您的项目文件夹中出现了一个新的`node_modules`目录。

# 主要文件

在 IDE 中打开`vuebnb-prototype`目录。请注意，包含了以下`index.html`文件。它主要由样板代码组成，但也包括一些结构标记在`body`标签中。

还要注意，该文件链接到`style.css`，我们的 CSS 规则将被添加在那里，以及`app.js`，我们的 JavaScript 将被添加在那里。

`index.html`：

```php
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Vuebnb</title>
  <link href="node_modules/open-sans-all/css/open-sans.css" rel="stylesheet">
  <link rel="stylesheet" href="style.css" type="text/css">
</head>
<body>
<div id="toolbar">
  <img class="icon" src="logo.png">
  <h1>vuebnb</h1>
</div>
<div id="app">
  <div class="container"></div>
</div>
<script src="app.js"></script>
</body>
</html>
```

目前`app.js`是一个空文件，但我已经在`style.css`中包含了一些 CSS 规则来帮助我们入门。

`style.css`：

```php
body {
  font-family: 'Open Sans', sans-serif; color: #484848; font-size: 17px;
  margin: 0;
}

.container {
  margin: 0 auto;
  padding: 0 12px;
}

@media (min-width: 744px) {
  .container {
      width: 696px;
  }
}

#toolbar {
  display: flex;
  align-items: center;
  border-bottom: 1px solid #e4e4e4;
  box-shadow: 0 1px 5px rgba(0, 0, 0, 0.1);
}

#toolbar .icon {
  height: 34px;
  padding: 16px 12px 16px 24px;
  display: inline-block;
}

#toolbar h1 {
  color: #4fc08d;
  display: inline-block;
  font-size: 28px;
  margin: 0;
}
```

# 在浏览器中打开

要查看项目，请在 Web 浏览器中找到`index.html`文件。在 Chrome 中，只需点击文件*| 打开文件*。加载完成后，您将看到一个大部分为空白的页面，除了顶部的工具栏。

# 安装 Vue.js

现在是时候将`Vue.js`库添加到我们的项目中了。Vue 已作为我们的 NPM 安装的一部分下载，所以现在我们可以简单地使用`script`标签链接到`Vue.js`的浏览器构建版本。

`index.html`：

```php
<body>
<div id="toolbar">...</div>
<div id="app">...</div>
<script src="node_modules/vue/dist/vue.js"></script>
<script src="app.js"></script>
</body>
```

在我们自定义的`app.js`脚本之前，包含 Vue 库是很重要的，因为脚本是按顺序运行的。

Vue 现在将被注册为全局对象。我们可以通过转到浏览器并在 JavaScript 控制台中输入以下内容来测试：

```php
console.log(Vue);
```

这是结果：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/25755703-7819-4ee5-b148-6b33180bb963.png)图 2.3 检查 Vue 是否注册为全局对象

# 页面内容

当我们的环境设置好并安装好了起始代码后，我们现在已经准备好开始构建 Vuebnb 原型的第一步了。

让我们向页面添加一些内容，包括页眉图像、标题和*关于*部分。我们将在我们的 HTML 文件中添加结构，并使用`Vue.js`在需要时插入正确的内容。

# Vue 实例

查看我们的`app.js`文件，现在让我们通过使用`Vue`对象的`new`运算符来创建 Vue.js 的根实例。

`app.js`：

```php
var app = new Vue();
```

当你创建一个`Vue`实例时，通常会希望将一个配置对象作为参数传递进去。这个对象是定义项目的自定义数据和函数的地方。

`app.js`：

```php
var app = new Vue({ el: '#app'
});
```

随着我们的项目的进展，我们将在这个配置对象中添加更多内容，但现在我们只是添加了`el`属性，告诉 Vue 在页面中的哪里挂载自己。

你可以将其分配为一个字符串（CSS 选择器）或 HTML 节点对象。在我们的例子中，我们使用了`#app`字符串，它是一个 CSS 选择器，指的是具有`app`ID 的元素。

`index.html`：

```php
<div id="app">
  <!--Mount element-->
</div>
```

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/b44d2a8b-d651-4e4c-8f99-85ee662df265.png)图 2.5。包含模拟列表示例的页面

`index.html`：

```php
<body>
<div id="toolbar">...</div>
<div id="app">
  <!--Vue only has dominion here-->
  <div class="header">...</header> ... </div>
<script src="node_modules/vue/dist/vue.js"></script>
<script src="app.js"></script>
</body>
```

从现在开始，我们将把我们的挂载节点及其子节点称为我们的模板。

# 数据绑定

Vue 的一个简单任务是将一些 JavaScript 数据绑定到模板上。让我们在配置对象中创建一个`data`属性，并为其分配一个包含`title`属性和`'My apartment'`字符串值的对象。

`app.js`：

```php
var app = new Vue({ el: '#app', data: { title: 'My apartment'
  }
});
```

这个`data`对象的任何属性都将在我们的模板中可用。为了告诉 Vue 在哪里绑定这些数据，我们可以使用*mustache*语法，也就是双花括号，例如，`{{ myProperty }}`。当 Vue 实例化时，它会编译模板，用适当的文本替换 mustache 语法，并更新 DOM 以反映这一点。这个过程被称为*文本插值*，并在下面的代码块中进行了演示。

`index.html`：

```php
<div id="app">
  <div class="container">
    <div class="heading">
      <h1>{{ title }}</h1>
    </div>
  </div>
</div>
```

将呈现为：

```php
<div id="app">
  <div class="container">
    <div class="heading">
      <h1>My apartment</h1>
    </div>
  </div>
</div>
```

现在让我们添加一些更多的数据属性，并增强我们的模板以包含更多的页面结构。

`app.js`：

```php
var app = new Vue({ el: '#app', data: { title: 'My apartment', address: '12 My Street, My City, My Country', about: 'This is a description of my apartment.'
  }
});
```

`index.html`：

```php
<div class="container">
  <div class="heading">
    <h1>{{ title }}</h1>
    <p>{{ address }}</p>
  </div>
  <hr>
  <div class="about">
    <h3>About this listing</h3>
    <p>{{ about }}</p>
  </div>
</div>
```

让我们也添加一些新的 CSS 规则。

`style.css`：

```php
.heading {
  margin-bottom: 2em;
}

.heading h1 {
  font-size: 32px;
  font-weight: 700;
}

.heading p {
  font-size: 15px;
  color: #767676;
}

hr {
  border: 0;
  border-top: 1px solid #dce0e0;
}

.about {
  margin-top: 2em;
}

.about h3 {
  font-size: 22px;
}

.about p {
  white-space: pre-wrap;
}
```

如果你现在保存并刷新你的页面，它应该看起来像这样：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/bbb14c0f-4e35-413a-8b62-2250d8786bec.png)图 2.4。带有基本数据绑定的列表页面

# 模拟列表

当我们开发时，最好使用一些模拟数据，这样我们就可以看到我们完成的页面将会是什么样子。我已经在项目中包含了`sample/data.js`，就是为了这个原因。让我们在我们的文档中加载它，确保它在我们的`app.js`文件之上。

`index.html`：

```php
<body>
<div id="toolbar">...</div>
<div id="app">...</div>
<script src="node_modules/vue/dist/vue.js"></script>
<script src="sample/data.js"></script>
<script src="app.js"></script>
</body>
```

看一下文件，你会看到它声明了一个`sample`对象。我们现在将在我们的数据配置中利用它。

`app.js`：

```php
data: { title: sample.title, address: sample.address, about: sample.about }
```

一旦你保存并刷新，你会在页面上看到更真实的数据：

在这种方式中使用分布在不同脚本文件中的全局变量并不是一种理想的做法。不过，我们只会在原型中这样做，稍后我们将从服务器获取这个模拟列表示例。

# 页眉图像

没有一个房间列表会完整而没有一个大而光滑的图片来展示它。我们的模拟列表中有一个页眉图像，现在我们将其包含进来。将这个标记添加到页面中。

Vue 对其挂载的元素和任何子节点都具有支配权。到目前为止，对于我们的项目，Vue 可以操作具有`header`类的`div`，但无法操作具有`toolbar`ID 的`div`。放置在后者`div`中的任何内容对 Vue 来说都是不可见的。

```php
<div id="app">
  <div class="header">
    <div class="header-img"></div>
  </div>
  <div class="container">...</div>
</div>
```

并将其添加到 CSS 文件中。

`style.css`：

```php
.header {
  height: 320px;
}

.header .header-img {
  background-repeat: no-repeat;
  background-size: cover;
  background-position: 50% 50%;
  background-color: #f5f5f5;
  height: 100%;
}
```

你可能会想为什么我们使用`div`而不是`img`标签。为了帮助定位，我们将把我们的图像设置为具有`header-img`类的`div`的背景。

# 样式绑定

要设置背景图像，我们必须在 CSS 规则中提供 URL 作为属性，就像这样：

```php
.header .header-img {
  background-image: url(...);
}
```

显然，我们的页眉图像应该针对每个单独的列表进行特定设置，所以我们不想硬编码这个 CSS 规则。相反，我们可以让 Vue 将数据中的 URL 绑定到我们的模板上。

Vue 无法访问我们的 CSS 样式表，但它可以绑定到内联`style`属性：

```php
<div class="header-img" style="background-image: url(...);"></div>
```

你可能会认为在这里使用文本插值是解决方案，例如：

```php
<div class="header-img" style="background-image: {{ headerUrl }}"></div>
```

但这不是有效的 Vue.js 语法。相反，这是另一个 Vue.js 功能称为`指令`的工作。让我们先探索指令，然后再来解决这个问题。

# 指令

Vue 的指令是带有*v-*前缀的特殊 HTML 属性，例如`v-if`，它提供了一种简单的方法来为我们的模板添加功能。您可以为元素添加的一些指令的示例包括：

+   `v-if`：有条件地渲染元素

+   `v-for`：基于数组或对象多次渲染元素

+   `v-bind`：将元素的属性动态绑定到 JavaScript 表达式

+   `v-on`：将事件监听器附加到元素

在整本书中，我们将探索更多内容。

# 用法

就像普通的 HTML 属性一样，指令通常是形式为`name="value"`的名称/值对。要使用指令，只需将其添加到 HTML 标记中，就像添加属性一样，例如：

```php
<p v-directive="value">
```

# 表达式

如果指令需要一个值，它将是一个*表达式*。

在 JavaScript 语言中，表达式是小的、可评估的语句，产生单个值。表达式可以在期望值的任何地方使用，例如在`if`语句的括号中：

```php
if (expression) {
  ...
}
```

这里的表达式可以是以下任何一种：

+   数学表达式，例如`x + 7`

+   比较，例如`v <= 7`

+   例如 Vue 的`data`属性，例如`this.myval`

指令和文本插值都接受表达式值：

```php
<div v-dir="someExpression">{{ firstName + " " + lastName }}</div>
```

# 示例：v-if

`v-if`将根据其值是否为*真*表达式有条件地渲染元素。在下面的情况下，`v-if`将根据`myval`的值删除/插入`p`元素：

```php
<div id="app">
  <p v-if="myval">Hello Vue</p>
</div>
<script> var app = new Vue({ el: '#app', data: { myval: true
    }
  }); </script>
```

将呈现为：

```php
<div id="app">
  <p>Hello Vue</p>
</div>
```

如果我们添加一个带有`v-else`指令的连续元素（一个不需要值的特殊指令），它将在`myval`更改时对称地删除/插入：

```php
<p v-if="myval">Hello Vue</p>
<p v-else>Goodbye Vue</p>
```

# 参数

一些指令需要一个*参数*，在指令名称后面加上冒号表示。例如，`v-on`指令监听 DOM 事件，需要一个参数来指定应该监听哪个事件：

```php
<a v-on:click="doSomething">
```

参数不一定是`click`，也可以是`mouseenter`，`keypress`，`scroll`或任何其他事件（包括自定义事件）。

# 样式绑定（续）

回到我们的页眉图像，我们可以使用`v-bind`指令和`style`参数将值绑定到`style`属性。

`index.html`：

```php
<div class="header-img" v-bind:style="headerImageStyle"></div>
```

`headerImageStyle`是一个表达式，它评估为设置背景图像到正确 URL 的 CSS 规则。听起来很混乱，但当你看到它工作时，就会很清楚。

现在让我们创建`headerImageStyle`作为数据属性。当绑定到样式属性时，可以使用一个对象，其中属性和值等同于 CSS 属性和值。

`app.js`：

```php
data: {
  ... headerImageStyle: {
    'background-image': 'url(sample/header.jpg)'
  }
},
```

保存代码，刷新页面，页眉图像将显示：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/6601a188-3ce0-4e1e-8b6e-7480bb40e6ff.png)图 2.6。包括页眉图像的页面

使用浏览器开发工具检查页面，并注意`v-bind`指令的评估方式：

```php
<div class="header-img" style="background-image: url('sample/header.jpg');"></div>
```

# 列表部分

我们将要添加到页面的下一部分是`Amenities`和`Prices`列表：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/2b06075a-4384-4cc7-88c9-ce8d3e540bd0.png)图 2.7。列表部分

如果您查看模拟列表示例，您会看到对象上的`amenities`和`prices`属性都是数组。

`sample/data.js`：

```php
var sample = { title: '...', address: '...', about: '...', amenities: [
    { title: 'Wireless Internet', icon: 'fa-wifi'
    },
    { title: 'Pets Allowed', icon: 'fa-paw'
    },
    ...
  ], prices: [
    { title: 'Per night', value: '$89'
    },
    { title: 'Extra people', value: 'No charge'
    },
    ...
  ]
}
```

如果我们可以轻松地遍历这些数组并将每个项目打印到页面上，那不是很容易吗？我们可以！这就是`v-for`指令的作用。

首先，让我们将这些添加为根实例上的数据属性。

`app.js`：

```php
data: {
  ... amenities: sample.amenities, prices: sample.prices }
```

# 列表渲染

`v-for`指令需要一种特殊类型的表达式，形式为`item in items`，其中`items`是源数组，`item`是当前正在循环的数组元素的别名。

让我们首先处理`amenities`数组。该数组的每个成员都是一个具有`title`和`icon`属性的对象，即：

```php
{ title: 'something', icon: 'something' }
```

我们将在模板中添加`v-for`指令，并将其分配的表达式设置为`amenity in amenities`。表达式的别名部分，即`amenity`，将在整个循环序列中引用数组中的每个对象，从第一个开始。

`index.html`：

```php
<div class="container">
  <div class="heading">...</div>
  <hr>
  <div class="about">...</div>
  <div class="lists">
    <div v-for="amenity in amenities">{{ amenity.title }}</div>
  </div>
</div>
```

它将呈现为：

```php
<div class="container">
  <div class="heading">...</div>
  <hr>
  <div class="about">...</div>
  <div class="lists">
    <div>Wireless Internet</div>
    <div>Pets Allowed</div>
    <div>TV</div>
    <div>Kitchen</div>
    <div>Breakfast</div>
    <div>Laptop friendly workspace</div>
  </div>
</div>
```

# 图标

我们设施对象的第二个属性是`icon`。这实际上是与 Font Awesome 图标字体中的图标相关的类。我们已经安装了 Font Awesome 作为 NPM 模块，因此现在可以将其添加到页面的头部以使用它。

`index.html`：

```php
<head> ... <link rel="stylesheet" href="node_modules/open-sans-all/css/open-sans.css">
  <link rel="stylesheet" href="node_modules/font-awesome/css/font-awesome.css">
  <link rel="stylesheet" href="style.css" type="text/css">
</head>
```

现在，我们可以在模板中完成我们的设施部分的结构。

`index.html`：

```php
<div class="lists">
  <hr>
  <div class="amenities list">
    <div class="title"><strong>Amenities</strong></div>
    <div class="content">
      <div class="list-item" v-for="amenity in amenities">
        <i class="fa fa-lg" v-bind:class="amenity.icon"></i>
        <span>{{ amenity.title }}</span>
      </div>
    </div>
  </div>
</div>
```

`style.css`：

```php
.list {
  display: flex;
  flex-wrap: nowrap;
  margin: 2em 0;
}

.list .title {
  flex: 1 1 25%;
}

.list .content {
  flex: 1 1 75%;
  display: flex;
  flex-wrap: wrap;
}

.list .list-item {
  flex: 0 0 50%;
  margin-bottom: 16px;
}

.list .list-item > i {
  width: 35px;
}

@media (max-width: 743px) {
  .list .title {
    flex: 1 1 33%;
  }

  .list .content {
    flex: 1 1 67%;
  }

  .list .list-item {
    flex: 0 0 100%;
  }
}
```

# 键

正如你所期望的那样，由`v-for="amenity in amenities"`生成的 DOM 节点与`amenities`数组具有响应性绑定。如果`amenities`的内容发生变化，Vue 将自动重新渲染节点以反映更改。

在使用`v-for`时，建议为列表中的每个项目提供一个唯一的`key`属性。这使得 Vue 能够定位需要更改的确切 DOM 节点，从而使 DOM 更新更有效率。

通常，键将是一个数字 ID，例如：

```php
<div v-for="item in items" v-bind:key="item.id"> {{ item.title }} </div>
```

对于设施和价格列表，内容在应用程序的生命周期内不会发生变化，因此我们不需要提供键。一些代码检查工具可能会警告您，但在这种情况下，可以安全地忽略警告。

# 价格

现在让我们也将价格列表添加到我们的模板中。

`index.html`：

```php
<div class="lists">
  <hr>
  <div class="amenities list">...</div>
  <hr>
  <div class="prices list">
    <div class="title">
      <strong>Prices</strong>
    </div>
    <div class="content">
      <div class="list-item" v-for="price in prices"> {{ price.title }}: <strong>{{ price.value }}</strong>
      </div>
    </div>
  </div>
</div>
```

我相信您会同意，循环模板比逐个项目编写要容易得多。但是，您可能会注意到这两个列表之间仍然存在一些常见的标记。在本书的后面，我们将利用组件使模板的这一部分更加模块化。

# 显示更多功能

现在我们遇到了一个问题，即“列表”部分在“关于”部分之后。关于部分的长度是任意的，在我们将要添加的一些模拟列表中，您会看到这部分非常长。

我们不希望它主导页面并迫使用户进行大量不受欢迎的滚动以查看“列表”部分，因此我们需要一种方法，如果文本太长，则隐藏一些文本，但允许用户选择查看完整文本。

让我们添加一个“显示更多”UI 功能，它将在一定长度后裁剪“关于”文本，并为用户提供一个按钮来显示隐藏的文本：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/2097c214-5dcc-43d3-82d1-2d682fe49996.png)图 2.8. 显示更多功能

我们将首先向包含`about`文本插值的`p`标签添加一个`contracted`类。此类的 CSS 规则将限制其高度为 250 像素，并隐藏溢出元素的任何文本。

`index.html`：

```php
<div class="about">
  <h3>About this listing</h3>
  <p class="contracted">{{ about }}</p>
</div>
```

`style.css`：

```php
.about p.contracted {
  height: 250px;
  overflow: hidden;
}
```

我们还将在`p`标签之后放置一个按钮，用户可以单击该按钮将该部分展开到完整高度。

`index.html`：

```php
<div class="about">
  <h3>About this listing</h3>
  <p class="contracted">{{ about }}</p>
  <button class="more">+ More</button>
</div>
```

这是所需的 CSS，包括一个通用按钮规则，该规则将为项目中将要添加的所有按钮提供基本样式。

`style.css`：

```php
button {
  text-align: center;
  vertical-align: middle;
  user-select: none;
  white-space: nowrap;
  cursor: pointer;
  display: inline-block;
  margin-bottom: 0;
}

.about button.more {
  background: transparent;
  border: 0;
  color: #008489;
  padding: 0;
  font-size: 17px;
  font-weight: bold;
}

.about button.more:hover, 
.about button.more:focus, 
.about button.more:active {
  text-decoration: underline;
  outline: none;
}
```

为了使其工作，我们需要一种方法，在用户单击“更多”按钮时删除`contracted`类。看起来指令是一个很好的选择！

# 类绑定

我们将采取的方法是动态绑定`contracted`类。让我们创建一个`contracted`数据属性，并将其初始值设置为`true`。

`app.js`：

```php
data: {
  ... contracted: true
}
```

与我们的样式绑定一样，我们可以将此类绑定到一个对象。在表达式中，`contracted`属性是要绑定的类的名称，`contracted`值是对同名数据属性的引用，它是一个布尔值。因此，如果`contracted`数据属性评估为`true`，那么该类将绑定到元素，如果评估为`false`，则不会绑定。

`index.html`：

```php
<p v-bind:class="{ contracted: contracted }">{{ about }}</p>
```

因此，当页面加载时，`contracted`类被绑定：

```php
<p class="contracted">...</p>
```

# 事件监听器

现在，我们希望在用户单击“更多”按钮时自动删除`contracted`类。为了完成这项工作，我们将使用`v-on`指令，该指令使用`click`参数监听 DOM 事件。

`v-on`指令的值可以是一个表达式，将`contracted`赋值为`false`。

`index.html`：

```php
<div class="about">
  <h3>About this listing</h3>
  <p v-bind:class="{ contracted: contracted }">{{ about }}</p>
  <button class="more" v-on:click="contracted = false">+ More</button>
</div>
```

# 响应性

当我们单击“更多”按钮时，`contracted`值会发生变化，Vue 将立即更新页面以反映此更改。

Vue 是如何知道做到这一点的？要回答这个问题，我们必须首先了解 getter 和 setter 的概念。

# 获取器和设置器

为 JavaScript 对象的属性分配值就像这样简单：

```php
var myObj = { prop: 'Hello'
}
```

要检索它就像这样简单：

```php
myObj.prop
```

这里没有什么诀窍。不过，我想要表达的是，我们可以通过使用 getter 和 setter 来替换对象的正常赋值/检索机制。这些是特殊函数，允许自定义逻辑来获取或设置属性的值。

当一个属性的值由另一个属性确定时，getter 和 setter 特别有用。这里有一个例子：

```php
var person = { firstName: 'Abraham', lastName: 'Lincoln',
  get fullName() {
    return this.firstName + ' ' + this.lastName;
  },
  set fullName(name) {
    var words = name.toString().split(' ');
    this.firstName = words[0] || '';
    this.lastName = words[1] || '';
  }
}
```

当我们尝试对`fullName`属性进行正常赋值/检索时，`fullName`属性的`get`和`set`函数将被调用：

```php
console.log(person.fullName); // Abraham Lincoln person.fullName = 'George Washington'; console.log(person.firstName); // George console.log(person.lastName) // Washington
```

# 响应式数据属性

Vue 的另一个初始化步骤是遍历所有数据属性并为其分配 getter 和 setter。如果您查看以下截图，您可以看到我们当前应用程序中的每个属性都添加了`get`和`set`函数：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/66c022e6-0030-4d84-a3ad-c05e38b395a6.png)图 2.9 获取器和设置器

Vue 添加了这些 getter 和 setter，以使其能够在访问或修改属性时执行依赖跟踪和更改通知。因此，当`contracted`值通过`click`事件更改时，将触发其`set`方法。`set`方法将设置新值，但也将执行通知 Vue 值已更改的次要任务，并且可能需要重新渲染依赖它的页面的任何部分。

如果您想了解更多关于 Vue 的响应系统的信息，请查看文章*Vue.js 中的响应性（及其陷阱）*，网址为[`vuejsdevelopers.com/2017/03/05/vue-js-reactivity/`](https://vuejsdevelopers.com/2017/03/05/vue-js-reactivity/)。

# 隐藏更多按钮

一旦“关于”部分被展开，我们希望隐藏“更多”按钮，因为它不再需要。我们可以使用`v-if`指令与`contracted`属性一起实现这一点。

`index.html`：

```php
<button v-if="contracted" class="more" v-on:click="contracted = false"> + More
</button>
```

# 图片模态窗口

为了防止我们的页眉图片占据页面，我们对其进行了裁剪并限制了其高度。但是，如果用户想要以全貌查看图片呢？允许用户专注于单个内容项的一个很好的 UI 设计模式是*模态窗口*。

当打开时，我们的模态框将如下所示：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/2d1ce89f-6747-4219-9540-615a7a3f6d17.png)图 2.10 页眉图片模态

我们的模态框将提供一个适当缩放的页眉图片视图，这样用户就可以专注于住宿的外观，而不会被页面的其他部分分散注意力。

书中稍后，我们将在模态框中插入一个图片轮播，这样用户就可以浏览整个房间图片集合！

不过，现在我们的模态框需要以下功能：

1.  通过点击页眉图片打开模态框

1.  冻结主窗口

1.  显示图片

1.  使用关闭按钮或*Escape*键关闭模态窗口

# 打开

首先，让我们添加一个布尔数据属性，表示我们模态框的打开或关闭状态。我们将其初始化为`false`。

`app.js`：

```php
data: {
  ... modalOpen: false
}
```

我们将使点击页眉图片打开模态框。我们还将在页眉图片的左下角叠加一个标有“查看照片”的按钮，以向用户发出更强烈的信号，告诉他们应该点击以显示图片。

`index.html`：

```php
<div 
  class="header-img" 
  v-bind:style="headerImageStyle" 
  v-on:click="modalOpen = true" >
  <button class="view-photos">View Photos</button>
</div>
```

请注意，通过将点击监听器放在包装`div`上，无论用户点击`button`还是`div`，都将捕获点击事件，这是由于 DOM 事件传播。

我们将为页眉图片添加一些 CSS，使光标成为*指针*，让用户知道可以点击页眉，并为页眉添加相对位置，以便在其中定位按钮。我们还将添加样式规则来设计按钮。

`style.css`：

```php
.header .header-img { ... cursor: pointer;
  position: relative;
}

button {
  border-radius: 4px;
  border: 1px solid #c4c4c4;
  text-align: center;
  vertical-align: middle;
  font-weight: bold;
  line-height: 1.43;
  user-select: none;
  white-space: nowrap;
  cursor: pointer;
  background: white;
  color: #484848;
  padding: 7px 18px;
  font-size: 14px;
  display: inline-block;
  margin-bottom: 0;
}

.header .header-img .view-photos {
  position: absolute;
  bottom: 20px;
  left: 20px;
}
```

现在让我们为模态框添加标记。我把它放在页面的其他元素之后，尽管这并不重要，因为模态框将脱离文档的常规流程。我们通过在以下 CSS 中给它一个`fixed`位置来将其从流程中移除。

`index.html`：

```php
<div id="app">
  <div class="header">...</div>
  <div class="container">...</div>
  <div id="modal" v-bind:class="{ show : modalOpen }"></div>
</div>
```

主模态`div`将充当其余模态内容的容器，同时也是将覆盖主窗口内容的背景面板。为了实现这一点，我们使用 CSS 规则将其拉伸到完全覆盖视口，给它设置`top`、`right`、`bottom`和`left`值为`0`。我们将`z-index`设置为一个较高的数字，以确保模态框叠放在页面中的任何其他元素之前。

还要注意，`display`最初设置为`none`，但我们会动态地将一个名为`show`的类绑定到模态框，使其显示为块级元素。当然，添加/删除这个类将绑定到`modalOpen`的值。

`style.css`：

```php
#modal {
  display: none;
  position: fixed;
  top: 0;
  right: 0;
  bottom: 0;
  left: 0;
  z-index: 2000;
}

#modal.show {
  display: block;
}
```

# 窗口

现在让我们为将覆盖在背景面板上的窗口添加标记。窗口将具有宽度约束，并将居中显示在视口中。

`index.html`：

```php
<div id="modal" v-bind:class="{ show : modalOpen }">
  <div class="modal-content">
    <img src="sample/header.jpg"/>
  </div>
</div>
```

`style.css`：

```php
.modal-content {
  height: 100%;
  max-width: 105vh;
  padding-top: 12vh;
  margin: 0 auto;
  position: relative;
}

.modal-content img {
  max-width: 100%;
}
```

# 禁用主窗口

当模态框打开时，我们希望防止与主窗口的任何交互，并且清楚地区分主窗口和子窗口。我们可以通过以下方式实现这一点：

+   调暗主窗口

+   防止 body 滚动

# 调暗主窗口

当模态框打开时，我们可以简单地隐藏我们的主窗口，但是最好让用户仍然能够意识到他们在应用程序流程中的位置。为了实现这一点，我们将在半透明面板下*调暗*主窗口。

我们可以通过给我们的模态面板添加不透明的黑色背景来实现这一点。

`style.css`：

```php
#modal { ... background-color: rgba(0,0,0,0.85);
}
```

# 防止 body 滚动

不过，我们有一个问题。尽管我们的模态面板是全屏的，但它仍然是`body`标签的子元素。这意味着我们仍然可以*滚动*主窗口！我们不希望用户在模态框打开时以任何方式与主窗口进行交互，因此我们必须禁用`body`上的滚动。

诀窍是向`body`标签添加 CSS `overflow`属性，并将其设置为`hidden`。这样做的效果是裁剪任何*溢出*（即，当前不在视图中的页面的部分），其余内容将变为不可见。

我们需要动态添加和删除这个 CSS 规则，因为当模态框关闭时，我们显然希望能够滚动页面。因此，让我们创建一个名为`modal-open`的类，当模态框打开时，我们可以将其应用于`body`标签。

`style.css`：

```php
body.modal-open {
  overflow: hidden;
 position: fixed;
}
```

我们可以使用`v-bind:class`来添加/删除这个类，对吗？不幸的是，不行。请记住，Vue 只对它挂载的元素有控制权：

```php
<body>
  <div id="app"> 
    <!--This is where Vue has dominion and can modify the page freely-->
  </div>
  <!--Vue is unable to change this part of the page or any ancestors-->
</body>
```

如果我们向`body`标签添加指令，它将*不会*被 Vue 看到。

# Vue 的挂载元素

如果我们只是在`body`标签上挂载 Vue，那么这样做能解决我们的问题吗？例如：

```php
new Vue({ el: 'body' 
});
```

Vue 不允许这样做，如果您尝试这样做，您将收到此错误：不要将 Vue 挂载到<html>或<body> - 而是挂载到普通元素。

请记住，Vue 必须编译模板并替换挂载节点。如果您的脚本标签作为挂载节点的子元素存在（通常是`body`），或者如果您的用户有修改文档的浏览器插件（很多都有），那么当 Vue 替换该节点时，页面可能会出现各种问题。

如果您定义了自己的具有唯一 ID 的根元素，则不应该出现这种冲突。

# 观察者

那么，如果`body`不在 Vue 的控制范围之内，我们如何向`body`添加/删除类？我们将不得不用浏览器的 Web API 以老式的方式来做。当模态框打开或关闭时，我们需要运行以下语句：

```php
// Modal opens document.body.classList.add('modal-open');

// Modal closes document.body.classList.remove('modal-closed');
```

正如讨论的那样，Vue 为每个数据属性添加了响应式的 getter 和 setter，以便在数据更改时知道如何适当地更新 DOM。Vue 还允许您编写自定义逻辑，以通过名为*watchers*的功能钩入响应式数据更改。

要添加观察者，首先向 Vue 实例添加`watch`属性。将一个对象分配给这个属性，其中每个属性都有一个声明的数据属性的名称，每个值都是一个函数。该函数有两个参数：旧值和新值。

每当数据属性更改时，Vue 将触发任何声明的观察者方法：

```php
var app = new Vue({ el: '#app' data: { message: 'Hello world'
  }, watch: { message: function(newVal, oldVal) { console.log(oldVal, ', ', newVal);
    }
  }
});

setTimeout(function() { app.message = 'Goodbye world';
  // Output: "Hello world, Goodbye world";
}, 2000);
```

Vue 不能为我们更新`body`标签，但它可以触发将要更新的自定义逻辑。让我们使用一个观察者来在我们的模态框打开和关闭时更新`body`标签。

`app.js`：

```php
var app = new Vue({ data: { ... }, watch: { modalOpen: function() {
      var className = 'modal-open';
      if (this.modalOpen) { document.body.classList.add(className);
      } else { document.body.classList.remove(className);
      }
    }
  }
});
```

现在当您尝试滚动页面时，您会发现它不会动！

# 关闭

用户需要一种关闭他们的模态框并返回到主窗口的方法。我们将在右上角叠加一个按钮，当点击时，会评估一个表达式来将`modalOpen`设置为`false`。我们包装`div`上的`show`类将随之被移除，这意味着`display` CSS 属性将返回到`none`，从而将模态框从页面中移除。

`index.html`：

```php
<div id="modal" v-bind:class="{ show : modalOpen }">
  <button v-on:click="modalOpen = false" class="modal-close"> &times; </button>
  <div class="modal-content">
    <img src="sample/header.jpg"/>
  </div>
</div>
```

`style.css`：

```php
.modal-close {
  position: absolute;
  right: 0;
  top: 0;
  padding: 0px 28px 8px;
  font-size: 4em;
  width: auto;
  height: auto;
  background: transparent;
  border: 0;
  outline: none;
  color: #ffffff;
  z-index: 1000;
  font-weight: 100;
  line-height: 1;
}
```

# Escape 键

为我们的模态框添加一个关闭按钮很方便，但大多数人关闭窗口的本能动作是按下*Escape*键。

`v-on`是 Vue 监听事件的机制，似乎是这项工作的一个很好的选择。添加`keyup`参数将在此输入聚焦时按下*任何*键后触发处理程序回调：

```php
<input v-on:keyup="handler">
```

# 事件修饰符

Vue 通过为`v-on`指令提供*修饰符*来轻松监听*特定*键。修饰符是由点(`.`)表示的后缀，例如：

```php
<input v-on:keyup.enter="handler">
```

正如您可能猜到的那样，`.enter`修饰符告诉 Vue 仅在事件由*Enter*键触发时调用处理程序。修饰符使您无需记住特定的键码，还使您的模板逻辑更加明显。Vue 提供了各种其他键修饰符，包括：

+   `tab`

+   `delete`

+   `空间`

+   `esc`

考虑到这一点，似乎我们可以使用这个指令关闭我们的模态框：

```php
v-on:keyup.esc="modalOpen = false"
```

但是我们应该将这个指令附加到哪个标签呢？不幸的是，除非有一个输入被聚焦，否则键事件将从`body`元素分派，而我们知道这是 Vue 无法控制的！

为了处理这个事件，我们将再次求助于 Web API。

`app.js`：

```php
var app = new Vue({ 
  ... 
}); document.addEventListener(</span>'keyup', function(evt) {
  if (evt.keyCode === 27 && app.modalOpen) { app.modalOpen = false;
  }
});
```

这个方法可以工作，但有一个警告（在下一节中讨论）。但是 Vue 可以帮助我们使它完美。

# 生命周期钩子

当您的主脚本运行并设置了 Vue 的实例时，它会经历一系列的初始化步骤。正如我们之前所说的，Vue 将遍历您的数据对象并使它们具有反应性，同时编译模板并挂载到 DOM 上。在生命周期的后期，Vue 还将经历更新步骤，然后是拆卸步骤。

这是从[`vuejs.org`](http://vuejs.org)获取的生命周期实例图。其中许多步骤涉及到我们尚未涵盖的概念，但您应该能够理解大意：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/9f308e86-bbbe-489c-9f93-06abe2675081.png)图 2.11. Vue.js 生命周期图

Vue 允许您通过*生命周期钩子*在这些不同的步骤执行自定义逻辑，这些钩子是在配置对象中定义的回调函数。

例如，这里我们利用了`beforeCreate`和`created`钩子：

```php
new Vue({ data: { message: 'Hello'
  }, beforeCreate: function() { console.log('beforeCreate message: ' + this.message);
    // "beforeCreate message: undefined"
  }, created: function() { console.log('created: '+ this.message);
    // "created message: Hello"
  },
});
```

在`beforeCreate`钩子被调用之后但在`created`钩子被调用之前，Vue 将数据属性别名为上下文对象，因此在前者中`this.message`是`undefined`。

我之前提到的关于*Escape*键监听器的警告是：虽然不太可能，但如果在按下*Escape*键并且我们的回调在 Vue 代理数据属性之前被调用，`app.modalOpen`将是`undefined`而不是`true`，因此我们的`if`语句将无法像我们期望的那样控制流程。

为了克服这个问题，我们可以在`created`生命周期钩子中设置监听器，该监听器将在 Vue 代理数据属性之后调用。这给了我们一个保证，当回调运行时，`modalOpen`将被定义。

`app.js`：

```php
function escapeKeyListener(evt) {
  if (evt.keyCode === 27 && app.modalOpen) { app.modalOpen = false;
  }
}

var app = new Vue({ data: { ... }, watch: { ... }, created: function() { document.addEventListener('keyup', escapeKeyListener);
  }
});
```

# 方法

Vue 配置对象还有一个*方法*部分。方法不是响应式的，因此您可以在 Vue 配置之外定义它们，而在功能上没有任何区别，但 Vue 方法的优势在于它们作为上下文传递了 Vue 实例，因此可以轻松访问您的其他属性和方法。

让我们重构我们的`escapeKeyListener`成为一个`Vue`实例方法。

`app.js`：

```php
var app = new Vue({ data: { ... }, methods: { escapeKeyListener: function(evt) {
      if (evt.keyCode === 27 && this.modalOpen) {
        this.modalOpen = false;
      }
    }
  }, watch: { ... },
 created: function() { document.addEventListener('keyup', this.escapeKeyListener);
  }
});
```

# 代理属性

你可能已经注意到我们的`escapeKeyListener`方法可以引用`this.modalOpen`。难道不应该是`this.methods.modalOpen`吗？

当 Vue 实例被构建时，它会将任何数据属性、方法和计算属性代理到实例对象。这意味着在任何方法中，你可以引用`this.myDataProperty`、`this.myMethod`等，而不是`this.data.myDataProperty`或`this.methods.myMethod`，正如你可能会假设的那样：

```php
var app = new Vue({ data: { myDataProperty: 'Hello'
  }, methods: { myMethod: function() {
      return this.myDataProperty + ' World';
    }
  }
}); console.log(app.myMethod());
// Output: 'Hello World' 
```

你可以通过在浏览器控制台中打印 Vue 对象来查看这些代理属性：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/d6771753-2628-41d4-809f-4e0f2ab6381e.png)图 2.12。我们应用的 Vue 实例

现在文本插值的简单性可能更有意义，它们具有 Vue 实例的上下文，并且由于代理属性的存在，可以像`{{ myDataProperty }}`一样被引用。

然而，虽然代理到根使语法更简洁，但一个后果是你不能用相同的名称命名你的数据属性、方法或计算属性！

# 移除监听器

为了避免任何内存泄漏，当 Vue 实例被销毁时，我们还应该使用`removeEventListener`来摆脱监听器。我们可以使用`destroy`钩子，并调用我们的`escapeKeyListener`方法来实现这个目的。

`app.js`：

```php
new Vue({ data: { ... }, methods: { ... }, watch: { ... }, created: function() { ... }, destroyed: function () { document.removeEventListener('keyup', this.escapeKeyListener);
  }
});
```

# 摘要

在本章中，我们熟悉了 Vue 的基本特性，包括安装和基本配置、数据绑定、文本插值、指令、方法、观察者和生命周期钩子。我们还了解了 Vue 的内部工作原理，包括响应系统。

然后，我们利用这些知识来设置一个基本的 Vue 项目，并为 Vuebnb 原型创建页面内容，包括文本、信息列表、页眉图像，以及 UI 小部件，如“显示更多”按钮和模态窗口。

在下一章中，我们将暂时离开 Vue，同时使用 Laravel 为 Vuebnb 设置后端。


# 第三章：设置 Laravel 开发环境

在本书的前两章中，我们介绍了 Vue.js。您现在应该对其基本功能非常熟悉。在本章中，我们将启动一个 Laravel 开发环境，准备构建 Vuebnb 的后端。

本章涵盖的主题：

+   Laravel 简介

+   设置 Homestead 虚拟开发环境

+   配置 Homestead 以托管 Vuebnb

# Laravel

Laravel 是一个用于构建强大的 Web 应用程序的 PHP 开源 MVC 框架。Laravel 目前版本为 5.5，是最受欢迎的 PHP 框架之一，因其优雅的语法和强大的功能而备受喜爱。

Laravel 适用于创建各种基于 Web 的项目，例如以下项目：

+   具有用户认证的网站，如客户门户或社交网络

+   Web 应用程序，如图像裁剪器或监控仪表板

+   Web 服务，如 RESTful API

在本书中，我假设您对 Laravel 有基本的了解。您应该熟悉安装和设置 Laravel，并熟悉其核心功能，如路由、视图和中间件。

如果您是 Laravel 新手或认为自己可能需要温习一下，您应该花一两个小时阅读 Laravel 的优秀文档，然后再继续阅读本书：[`laravel.com/docs/5.5/`](https://laravel.com/docs/5.5/)。

# Laravel 和 Vue

Laravel 可能看起来像一个庞大的框架，因为它包括了构建几乎任何类型的 Web 应用程序的功能。然而，在幕后，Laravel 实际上是许多独立模块的集合，其中一些是作为 Laravel 项目的一部分开发的，一些来自第三方作者。Laravel 之所以伟大，部分原因在于它对这些组成模块的精心策划和无缝连接。

自 Laravel 5.3 版本以来，Vue.js 一直是 Laravel 安装中包含的默认前端框架。没有官方原因说明为什么选择 Vue 而不是其他值得选择的选项，如 React，但我猜想是因为 Vue 和 Laravel 分享相同的理念：简单和对开发者体验的重视。

无论出于什么原因，Vue 和 Laravel 都提供了一个非常强大和灵活的全栈框架，用于开发 Web 应用程序。

# 环境

我们将使用 Laravel 5.5 作为 Vuebnb 的后端。这个版本的 Laravel 需要 PHP 7、几个 PHP 扩展和以下软件：

+   Composer

+   一个 Web 服务器，如 Apache 或 Nginx

+   数据库，如 MySQL 或 MariaDB

Laravel 的完整要求列表可以在安装指南中找到：[`laravel.com/docs/5.5#installation`](https://laravel.com/docs/5.5#installation)。

我强烈建议您使用*Homestead*开发环境，而不是在计算机上手动安装 Laravel 的要求，因为 Homestead 已经预先安装了所有您需要的东西。

# Homestead

Laravel Homestead 是一个虚拟的 Web 应用程序环境，运行在 Vagrant 和 VirtualBox 上，可以在任何 Windows、Mac 或 Linux 系统上运行。

使用 Homestead 将为您节省从头开始设置开发环境的麻烦。它还将确保您拥有与我使用的相同环境，这将使您更容易跟随本书的内容。

如果您的计算机上没有安装 Homestead，请按照 Laravel 文档中的说明进行操作：[`laravel.com/docs/5.5/homestead`](https://laravel.com/docs/5.5/homestead)。使用默认配置选项。

安装了 Homestead 并使用`vagrant up`命令启动了 Vagrant 虚拟机后，您就可以继续了。

# Vuebnb

在第二章中，*原型设计 Vuebnb，您的第一个 Vue.js 项目*，我们制作了 Vuebnb 前端的原型。原型是从一个单独的 HTML 文件创建的，我们直接从浏览器加载。

现在我们将开始处理全栈 Vuebnb 项目，原型很快将成为其中的关键部分。这个主要项目将是一个完整的 Laravel 安装，带有 Web 服务器和数据库。

# 项目代码

如果您还没有这样做，您需要从 GitHub 克隆代码库到您的计算机上。在第一章的*代码库*部分中给出了说明，*Hello Vue - Vue.js 简介*。

代码库中的`vuebnb`文件夹包含我们现在想要使用的项目代码。切换到此文件夹并列出内容：

```php
$ cd vuebnb
$ ls -la
```

文件夹内容应该如下所示：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/ae64ccdf-f60f-4333-b560-70d02ca66d37.png)图 3.1。vuebnb 项目文件

# 共享文件夹

`Homestead.yaml`文件的`folders`属性列出了您希望在计算机和 Homestead 环境之间共享的所有文件夹。

确保代码库与 Homestead 共享，以便我们在本章后期可以从 Homestead 的 Web 服务器上提供 Vuebnb。

`~/Homestead/Homestead.yaml`*：*

```php
folders:
  - map: /Users/anthonygore/Projects/Full-Stack-Vue.js-2-and-Laravel-5
    to: /home/vagrant/projects
```

# 终端命令

本书中的所有进一步的终端命令都将相对于项目目录给出，即*vuebnb*，除非另有说明。

然而，由于项目目录在主机计算机和 Homestead 之间共享，终端命令可以从这两个环境中的任何一个运行。

Homestead 可以避免您在主机计算机上安装任何软件。但如果您不这样做，许多终端命令可能无法正常工作，或者在主机环境中可能无法正常工作。例如，如果您的主机计算机上没有安装 PHP，您就无法从中运行 Artisan 命令：

```php
$ php artisan --version
-bash: php: command not found
```

如果您是这种情况，您需要首先通过 SSH 连接在 Homestead 环境中运行这些命令：

```php
$ cd ~/Homestead
$ vagrant ssh
```

然后，切换到操作系统中的项目目录，同样的终端命令现在将起作用：

```php
$ cd ~/projects/vuebnb
$ php artisan --version
Laravel Framework 5.5.20
```

从 Homestead 运行命令的唯一缺点是由于 SSH 连接而变慢。我将让您决定您更愿意使用哪一个。

# 环境变量

Laravel 项目需要在`.env`文件中设置某些环境变量。现在通过复制环境文件示例来创建一个：

```php
$ cp .env.example .env
```

通过运行此命令生成应用程序密钥：

```php
$ php artisan key:generate
```

我已经预设了大多数其他相关的环境变量，所以除非您已经按照我不同的方式配置了 Homestead，否则您不需要更改任何内容。

# Composer 安装

要完成安装过程，我们必须运行`composer install`来下载所有所需的软件包：

```php
$ composer install
```

# 数据库

我们将使用关系数据库来在后端应用程序中持久保存数据。Homestead 默认情况下运行 MySQL；您只需在`.env`文件中提供配置以在 Laravel 中使用它。默认配置将在没有进一步更改的情况下工作。

`.env`：

```php
DB_CONNECTION=mysql
DB_HOST=192.168.10.10
DB_PORT=3306
DB_DATABASE=vuebnb
DB_USERNAME=homestead
DB_PASSWORD=secret
```

无论您为数据库选择什么名称（即`DB_DATABASE`的值），都要确保将其添加到`Homestead.yaml`文件中的`databases`数组中。

`~/Homestead/Homestead.yaml`：

```php
databases:
  ... - vuebnb
```

# 提供项目

主要的 Vuebnb 项目现在已安装。让我们让 Web 服务器在本地开发域`vuebnb.test`上提供它。

在 Homestead 配置文件中，将`vuebnb.test`映射到项目的`public`文件夹。

`~/Homestead/Homestead.yaml`：

```php
sites:
  ... - map: vuebnb.test
    to: /home/vagrant/vuebnb/public
```

# 本地 DNS 条目

我们还需要更新计算机的主机文件，以便它理解`vuebnb.test`和 Web 服务器的 IP 之间的映射。Web 服务器位于 Homestead 框中，默认情况下 IP 为`192.168.10.10`。

要在 Mac 上配置这个，打开您的主机文件`/etc/hosts`，在文本编辑器中添加这个条目：

```php
192.168.10.10 vuebnb.test
```

在 Windows 系统上，hosts 文件通常可以在`C:\Windows\System32\Drivers\etc\hosts`找到。

# 访问项目

配置完成后，我们现在可以从`Homestead`目录中运行`vagrant provision`来完成设置：

```php
$ cd ~/Homestead
$ vagrant provision
# The next command will return you to the project directory
$ cd -
```

当配置过程完成时，我们应该能够在浏览器中输入`http://vuebnb.test`来看到我们的网站运行：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/a6d139d3-da0b-4ba3-8c5d-18e0b9e26642.png)图 3.2. Laravel 欢迎视图

现在我们准备开始开发 Vuebnb！

# 总结

在这个简短的章节中，我们讨论了开发 Laravel 项目的要求。然后安装并配置了 Homestead 虚拟开发环境来托管我们的主要项目 Vuebnb。

在下一章中，我们将通过构建一个 Web 服务来为 Vuebnb 的前端提供数据，开始我们的主要项目工作。
