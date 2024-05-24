# Vue2 Web 开发项目（一）

> 原文：[`zh.annas-archive.org/md5/632F664CBB74089B16065B30D26C6055`](https://zh.annas-archive.org/md5/632F664CBB74089B16065B30D26C6055)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

作为一个相对较新的 UI 库，Vue 是当前领先的库（如 Angular 和 React）的一个非常严肃的挑战者。它有很多优点--它简单、灵活、非常快速，但它仍然提供了构建现代 Web 应用程序所需的所有功能。

它的渐进性使得很容易上手，然后您可以使用更高级的功能来扩展您的应用程序。Vue 还拥有一个丰富的生态系统，包括官方的一级库，用于路由和状态管理、引导和单元测试。Vue 甚至支持开箱即用的服务器端渲染！

所有这些都得益于一个令人惊叹的社区和一个驱动网络创新的出色核心团队，使 Vue 成为一个可持续的开源项目。

为了帮助您学习 Vue 并使用它构建应用程序，本书被构建为一系列六个指南。每个指南都是一个具体的项目，在其中您将自己构建一个真正的应用程序。这意味着到最后，您将有六个 Vue 应用程序正在运行！

就像 Vue 一样，这些项目是渐进的，并逐步引入新的主题，以使您的学习体验更加轻松。最初的项目不需要大量的配置或构建工具，因此您可以立即制作具体的应用程序。然后，更高级的主题将逐步添加到项目中，以便您在本书结束时将拥有完整的技能。

# 本书涵盖的内容

第一章，开始使用 Vue，介绍了如何使用指令创建一个具有动态模板和基本交互性的基本 Vue 应用程序。

第二章，项目 1 - Markdown 笔记本，探讨了如何创建一个完整的 Vue 应用程序，具有计算属性、方法、生命周期钩子、列表显示、DOM 事件、动态 CSS、模板条件和过滤器格式。

第三章，项目 2 - 城堡决斗浏览器游戏，解释了作为可重用组件树的浏览器卡牌游戏的创建，这些组件相互通信。它还具有动画和动态 SVG 图形。

第四章，高级项目设置，着重介绍如何使用官方的 Vue 命令行工具来使用 webpack、babel 和更多构建工具来启动一个完整的项目。它还涵盖了单文件组件格式，使读者能够创建组件作为构建模块。

第五章*，项目 3 - 支持中心*，带您了解如何使用官方路由库来构建多页面应用程序--嵌套路由、动态参数、导航守卫等。该项目还包括一个自定义用户登录系统。

第六章*，项目 4 - 地理定位博客*，介绍了一个特色是 Google OAuth 登录和 Google Maps API 的应用程序的创建过程。本章还涵盖了使用官方 VueX 库进行状态管理以及快速功能组件的重要主题。

第七章*，项目 5 - 在线商店和扩展*，概述了高级开发技术，如使用 ESLint 检查代码质量，使用 Jest 对 Vue 组件进行单元测试，将应用程序翻译成多种语言，以及通过服务器端渲染来提高速度和 SEO。

第八章*，项目 6 - 使用 Meteor 实时仪表板*，教您如何在 Meteor 应用程序中使用 Vue，以利用这个全栈框架的实时能力。

# 这本书需要什么

要遵循这本书，您只需要一个文本或代码编辑器（推荐使用 Visual Studio Code 和 Atom）和一个网络浏览器（最好使用 Firefox 或 Chrome 的最新版本进行开发工具）。

# 这本书适合谁

如果您是一名网页开发人员，现在想要使用 Vue.js 创建丰富和交互式的专业应用程序，那么这本书适合您。假定您具有 JavaScript 的先验知识。熟悉 HTML、Node.js 和 npm、webpack 等工具将有所帮助，但并非必需。

# 约定

在这本书中，您将找到许多不同类型信息的文本样式。以下是一些样式的示例，以及它们的含义解释。

文本中的代码单词显示如下: "我们可以通过`d3.select`函数选择 HTML 元素。"

代码块设置如下:

```js
class Animal
{
public:
virtual  void Speak(void) const //virtual in the base class {
  //Using the Mach 5 console print
  M5DEBUG_PRINT("...\n");
}
```

```js
New terms and important words are shown in bold. Words that you see on the screen, in menus or dialog boxes for example, appear in the text like this: "Clicking the Next button moves you to the next screen."
```

警告或重要说明会以这样的方式出现在一个框中。

提示和技巧会以这种方式出现。


# 第一章：开始使用 Vue

Vue ([`vuejs.org/`](https://vuejs.org/))是一个专注于构建 Web 用户界面的 JavaScript 库。在本章中，我们将了解这个库，并在简要介绍之后，我们将开始创建一个 Web 应用程序，为我们在本书中一起构建的不同项目奠定基础。

# 为什么需要另一个前端框架？

Vue 在 JavaScript 前端领域是一个相对新手，但是对当前主要的库来说是一个非常严肃的挑战者。它简单、灵活、非常快速，同时还提供了许多功能和可选工具，可以帮助您高效地构建现代 Web 应用程序。它的创造者*Evan You*称其为**渐进式框架**：

+   Vue 是可以逐步采用的，核心库专注于用户界面，您可以在现有项目中使用它

+   你可以制作小型原型，一直到大型复杂的 Web 应用程序

+   Vue 是易于接近的-初学者可以轻松掌握这个库，而经验丰富的开发人员可以很快提高生产力

Vue 大致遵循模型-视图-视图模型架构，这意味着视图（用户界面）和模型（数据）是分开的，视图模型（Vue）是两者之间的中介。它会自动处理更新，并已经为您进行了优化。因此，您不必指定视图的哪一部分应该更新，因为 Vue 会选择正确的方式和时间来进行更新。

该库还从其他类似的库（如 React、Angular 和 Polymer）中汲取灵感。以下是其核心特性的概述：

+   一个反应灵敏的数据系统可以自动更新您的用户界面，具有轻量级的虚拟 DOM 引擎和最小的优化工作是必需的

+   灵活的视图声明-艺术家友好的 HTML 模板、JSX（JavaScript 内的 HTML）或超文本渲染函数（纯 JavaScript）

+   可组合的用户界面，具有可维护和可重用的组件

+   官方伴随库提供了路由、状态管理、脚手架和更高级的功能，使 Vue 成为一个非武断但完全成熟的前端框架

# 一个热门项目

*Evan You*在 2013 年开始在谷歌工作时着手开发了 Vue 的第一个原型，当时他正在使用 Angular。最初的目标是拥有 Angular 的所有很酷的特性，比如数据绑定和数据驱动的 DOM，但不包含使这个框架武断和难以学习和使用的额外概念。

2014 年 2 月，第一个公开版本发布，第一天就取得了巨大成功，在 HackerNews 的首页、`/r/javascript`排名第一，并且官方网站访问量达到了 1 万次。

第一个主要版本 1.0 于 2015 年 10 月发布，到年底，npm 下载量飙升至 382k，GitHub 仓库获得了 11k 颗星，官方网站访问量达到了 363k，流行的 PHP 框架 Laravel 选择了 Vue 作为其官方前端库，而不是 React。

第二个主要版本 2.0 于 2016 年 9 月发布，采用了基于虚拟 DOM 的新渲染器和许多新功能，如服务器端渲染和性能改进。这就是本书中将使用的版本。现在它是最快的前端库之一，甚至在与 React 团队精心比较后，超过了 React（[`vuejs.org/v2/guide/comparison`](https://vuejs.org/v2/guide/comparison)）。撰写本书时，Vue 是 GitHub 上第二受欢迎的前端库，拥有 72k 颗星，仅次于 React，领先于 Angular 1（[`github.com/showcases/front-end-javascript-frameworks`](https://github.com/showcases/front-end-javascript-frameworks)）。

路线图上该库的下一个发展阶段包括更多与 Vue 原生库（如 Weex 和 NativeScript）的集成，以创建具有 Vue 的原生移动应用程序，以及新功能和改进。

如今，Vue 被许多公司使用，如微软、Adobe、阿里巴巴、百度、小米、Expedia、任天堂和 GitLab。

# 兼容性要求

Vue 没有任何依赖，可以在任何符合 ECMAScript 5 最低标准的浏览器中使用。这意味着它与 Internet Explorer 8 或更低版本不兼容，因为它需要相对较新的 JavaScript 功能，如`Object.defineProperty`，这在旧版浏览器上无法进行 polyfill。

在本书中，我们使用 JavaScript 版本 ES2015（以前是 ES6）编写代码，因此在前几章中，您需要一个现代浏览器来运行示例（如 Edge、Firefox 或 Chrome）。在某个时候，我们将介绍一个名为*Babel*的编译器，它将帮助我们使我们的代码与旧版浏览器兼容。

# 一分钟设置

话不多说，让我们开始用一个非常快速的设置创建我们的第一个 Vue 应用程序。Vue 足够灵活，可以通过简单的`script`标签包含在任何网页中。让我们创建一个非常简单的网页，其中包括该库，一个简单的`div`元素和另一个`script`标签：

```js
<html>
<head>
  <meta charset="utf-8">
  <title>Vue Project Guide setup</title>
</head>
<body>

  <!-- Include the library in the page -->
  <script src="https://unpkg.com/vue/dist/vue.js"></script>

  <!-- Some HTML -->
  <div id="root">
    <p>Is this an Hello world?</p>
  </div>

  <!-- Some JavaScript -->
  <script>
  console.log('Yes! We are using Vue version', Vue.version)
  </script>

</body>
</html>
```

在浏览器控制台中，我们应该有类似这样的东西：

```js
Yes! We are using Vue version 2.0.3
```

正如您在前面的代码中所看到的，该库公开了一个包含我们需要使用它的所有功能的`Vue`对象。我们现在准备好了。

# 创建一个应用程序

目前，我们的网页上没有任何 Vue 应用程序在运行。整个库都是基于**Vue 实例**的，它们是视图和数据之间的中介。因此，我们需要创建一个新的 Vue 实例来启动我们的应用程序：

```js
// New Vue instance
var app = new Vue({
  // CSS selector of the root DOM element
  el: '#root',
  // Some data
  data () {
    return {
      message: 'Hello Vue.js!',
    }
  },
})
```

使用`new`关键字调用 Vue 构造函数来创建一个新实例。它有一个参数--选项对象。它可以有多个属性（称为选项），我们将在接下来的章节中逐渐发现。目前，我们只使用了其中的两个。

使用`el`选项，我们告诉 Vue 在哪里使用 CSS 选择器在我们的网页上添加（或“挂载”）实例。在这个例子中，我们的实例将使用`<div id="root">` DOM 元素作为其根元素。我们也可以使用 Vue 实例的`$mount`方法而不是`el`选项：

```js
var app = new Vue({
  data () {
    return {
      message: 'Hello Vue.js!',
    }
  },
})
// We add the instance to the page
app.$mount('#root')
```

大多数 Vue 实例的特殊方法和属性都以美元符号开头。

我们还将在`data`选项中初始化一些数据，其中包含一个包含字符串的`message`属性。现在 Vue 应用程序正在运行，但它还没有做太多事情。

您可以在单个网页上添加尽可能多的 Vue 应用程序。只需为它们中的每一个创建一个新的 Vue 实例，并将它们挂载在不同的 DOM 元素上。当您想要将 Vue 集成到现有项目中时，这将非常方便。

# Vue devtools

Vue 的官方调试工具在 Chrome 上作为一个名为 Vue.js devtools 的扩展可用。它可以帮助您查看您的应用程序的运行情况，以帮助您调试您的代码。您可以从 Chrome Web Store（[`chrome.google.com/webstore/search/vue`](https://chrome.google.com/webstore/search/vue)）或 Firefox 附加组件注册表（[`addons.mozilla.org/en-US/firefox/addon/vue-js-devtools/?src=ss`](https://addons.mozilla.org/en-US/firefox/addon/vue-js-devtools/?src=ss)）下载它。

对于 Chrome 版本，您需要设置一个额外的设置。在扩展设置中，启用允许访问文件 URL，以便它可以检测到从本地驱动器打开的网页上的 Vue：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/8e6ecee5-8be1-4e90-aa44-d5fb9661f379.png)

在您的网页上，使用*F12*快捷键（或在 OS X 上使用*Shift* + *command* + *c*）打开 Chrome Dev Tools，并搜索 Vue 标签（它可能隐藏在 More tools...下拉菜单中）。一旦打开，您可以看到一个树，其中包含我们的 Vue 实例，按照惯例命名为 Root。如果单击它，侧边栏将显示实例的属性：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/9d2b149a-ce2b-486e-aa66-413add014eaf.png)您可以随意拖动`devtools`选项卡。不要犹豫将其放在前面的选项卡中，因为在 Vue 不处于开发模式或根本没有运行时，它将被隐藏在页面中。

您可以使用`name`选项更改实例的名称：

```js
var app = new Vue({
  name: 'MyApp',
  // ...
})
```

这将帮助您在拥有更多实例时看到它们在开发工具中的位置：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/9a2be243-fc01-44c2-b0b3-ac9e5cb4f6b1.png)

# 模板使您的 DOM 动态化

使用 Vue，我们有几个系统可供编写我们的视图。现在，我们将从模板开始。模板是描述视图的最简单方式，因为它看起来很像 HTML，但有一些额外的语法，使 DOM 动态更新非常容易。

# 显示文本

我们将看到的第一个模板功能是**文本插值**，用于在网页内显示动态文本。文本插值语法是一对双大括号，其中包含任何类型的 JavaScript 表达式。当 Vue 处理模板时，其结果将替换插值。用以下内容替换`<div id="root">`元素：

```js
<div id="root">
  <p>{{ message }}</p>
</div>
```

此示例中的模板具有一个`<p>`元素，其内容是`message` JavaScript 表达式的结果。它将返回我们实例的 message 属性的值。现在，您的网页上应该显示一个新的文本--Hello Vue.js！。看起来不像什么，但 Vue 在这里为我们做了很多工作--我们现在的 DOM 与我们的数据连接起来了。

为了证明这一点，打开浏览器控制台，更改`app.message`的值，然后按键盘上的*Enter*：

```js
app.message = 'Awesome!'
```

消息已更改。这称为**数据绑定**。这意味着 Vue 能够在数据更改时自动更新 DOM，而无需您的任何操作。该库包括一个非常强大和高效的响应系统，可以跟踪所有数据，并能够在某些内容更改时更新所需的内容。所有这些都非常快速。

# 使用指令添加基本交互性

让我们为我们原本相当静态的应用程序添加一些互动，例如，一个文本输入框，允许用户更改显示的消息。我们可以在模板中使用特殊的 HTML 属性，称为**指令**来实现这一点。

Vue 中的所有指令都以`v-`开头，并遵循 kebab-case 语法。这意味着您应该用破折号分隔单词。请记住，HTML 属性不区分大小写（它们是大写还是小写都无关紧要）。

我们在这里需要的指令是`v-model`，它将绑定我们的`<input>`元素的值与我们的`message`数据属性。在模板中添加一个带有`v-model="message"`属性的新的`<input>`元素：

```js
<div id="root">
  <p>{{ message }}</p>
  <!-- New text input -->
  <input v-model="message" />
</div>
```

当输入值发生变化时，Vue 现在会自动更新`message`属性。您可以尝试更改输入内容，以验证文本随着您的输入而更新，devtools 中的值也会发生变化：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/fbc3442c-5df2-4b7c-a7ec-c96f05a10278.png)

Vue 中有许多其他指令可用，甚至可以创建自己的指令。不用担心，我们将在后面的章节中介绍这些内容。

# 摘要

在本章中，我们快速设置了一个网页，开始使用 Vue 并编写了一个简单的应用程序。我们创建了一个 Vue 实例来挂载 Vue 应用程序，并编写了一个模板来使 DOM 动态化。在这个模板中，我们使用了 JavaScript 表达式来显示文本，感谢文本插值。最后，我们通过一个输入元素添加了一些互动，将其与`v-model`指令绑定到我们的数据上。

在下一章中，我们将使用 Vue 创建我们的第一个真正的 Web 应用程序--一个 Markdown 笔记本。我们将需要更多的 Vue 超能力，将这个应用程序的开发变成一个有趣而迅速的体验。


# 第二章：项目 1 - Markdown 笔记本

我们将创建的第一个应用是一个 Markdown 笔记本，逐步使用几个 Vue 功能。我们将重复使用我们在第一章中看到的内容，*使用 Vue 入门*，并在此基础上添加更多元素，如有用的指令，用户交互的事件，更多实例选项和用于处理值的过滤器。

在我们开始编写代码之前，让我们谈谈这个应用并回顾我们的目标：

+   笔记本应用将允许用户以 Markdown 格式编写笔记

+   Markdown 将实时预览

+   用户可以添加任意数量的笔记

+   下次用户访问应用时，笔记将被恢复

为了做到这一点，我们将把用户界面分成三个部分：

+   中间的主要部分，带有笔记编辑器

+   右侧窗格，预览当前笔记的 Markdown

+   左侧窗格，显示笔记列表和添加新笔记的按钮

在本章结束时，它将看起来像这样：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/26d6cfab-5fd8-4e60-a85b-6116232af19c.png)

# 一个基本的笔记编辑器

我们将从一个非常简单的 Markdown 笔记应用开始，只在左侧显示文本编辑器和右侧显示 Markdown 预览。然后，我们将把它变成一个具有多个笔记支持的完整笔记本。

# 设置项目

对于这个项目，我们将准备好一些文件来帮助我们开始：

1.  首先，下载*simple-notebook*项目文件并将其解压缩到同一个文件夹中。打开`index.html`文件，并添加一个带有`notebook` ID 的`div`元素和一个带有`main`类的嵌套`section`元素。文件内应包含以下内容：

```js
      <html>
      <head>
        <title>Notebook</title>
        <!-- Icons & Stylesheets -->
        <link href="https://fonts.googleapis.com/icon?                   
        family=Material+Icons" rel="stylesheet">
        <link rel="stylesheet" href="style.css" />
      </head>
      <body>
        <!-- Include the library in the page -->
        <script src="https://unpkg.com/vue/dist/vue.js"></script>

        <!-- Notebook app -->
        <div id="notebook">

          <!-- Main pane -->
          <section class="main">

          </section>

        </div>

        <!-- Some JavaScript -->
        <script src="script.js"></script>
      </body>
      </html>
```

1.  现在，打开`script.js`文件添加一些 JavaScript。就像你在第一章中所做的那样，*使用 Vue 入门*，创建一个 Vue 实例，挂载在`#notebook`元素上，使用 Vue 构造函数：

```js
      // New VueJS instance
      new Vue({
        // CSS selector of the root DOM element
        el: '#notebook',
      })
```

1.  然后，添加一个名为`content`的数据属性，用于保存笔记的内容：

```js
      new Vue({
        el: '#notebook',

        // Some data
        data () {
          return {
            content: 'This is a note.',
          }
        },
      })
```

现在你已经准备好创建你的第一个真正的 Vue 应用了。

# 笔记编辑器

现在我们的应用正在运行，让我们添加文本编辑器。我们将使用一个简单的`textarea`元素和我们在第一章中看到的`v-model`指令，*使用 Vue 入门*。

创建一个`section`元素并将`textarea`放入其中，然后添加绑定到我们的`content`属性的`v-model`指令：

```js
<!-- Main pane -->
<section class="main">
  <textarea v-model="content"></textarea>
</section>
```

现在，如果你改变笔记编辑器中的文本，`content`的值应该会自动在 devtools 中改变。

`v-model`指令不仅限于文本输入。你还可以在其他表单元素中使用它，比如复选框、单选按钮，甚至是自定义组件，正如我们将在本书中看到的那样。

# 预览窗格

要将笔记 markdown 编译为有效的 HTML，我们将需要一个名为 Marked 的额外库（[`www.npmjs.com/package/marked`](https://www.npmjs.com/package/marked)）：

1.  在引用 Vue 的`script`标签后，将库包含在页面中：

```js
      <!-- Include the library in the page -->
      <script src="https://unpkg.com/vue/dist/vue.js"></script>
      <!-- Add the marked library: -->
      <script src="https://unpkg.com/marked"></script>
```

`marked`非常容易使用--只需用 markdown 文本调用它，它就会返回相应的 HTML。

1.  尝试使用一些 markdown 文本来测试库：

```js
      const html = marked('**Bold** *Italic* [link]   
      (http://vuejs.org/)')
      console.log(html)
```

你应该在浏览器控制台中看到以下输出：

```js
<p><strong>Bold</strong> <em>Italic</em>
<a href="http://vuejs.org/">link</a></p>
```

# 计算属性

Vue 非常强大的一个特性是**计算属性**。它允许我们定义新的属性，结合任意数量的属性并使用转换，比如将 markdown 字符串转换为 HTML--这就是为什么它的值由一个函数定义。计算属性具有以下特点：

+   该值被缓存，因此如果不需要，函数就不会重新运行，从而防止无用的计算

+   当函数内部使用的属性发生变化时，它会根据需要自动更新

+   计算属性可以像任何属性一样使用（你可以在其他计算属性中使用计算属性）

+   直到在应用程序的某个地方真正使用它之前，它都不会被计算。

这将帮助我们自动将笔记 markdown 转换为有效的 HTML，这样我们就可以实时显示预览。我们只需要在`computed`选项中声明我们的计算属性：

```js
// Computed properties
computed: {
  notePreview () {
    // Markdown rendered to HTML
    return marked(this.content)
  },
},
```

# 文本插值转义

让我们尝试使用文本插值在新窗格中显示我们的笔记：

1.  创建一个带有`preview`类的`<aside>`元素，显示我们的`notePreview`计算属性：

```js
      <!-- Preview pane -->
      <aside class="preview">
        {{ notePreview }}
      </aside>
```

现在我们应该在应用程序的右侧看到预览窗格显示我们的笔记。如果你在笔记编辑器中输入一些文本，你应该会看到预览自动更新。然而，我们的应用程序存在一个问题，当你使用 markdown 格式时会出现问题。

1.  尝试使用`**`将文本加粗，如下所示：

```js
      I'm in **bold**!
```

我们的计算属性应该返回有效的 HTML，并且我们的预览窗格中应该呈现一些粗体文本。相反，我们可以看到以下内容：

```js
I'm in <strong>bold</strong>!
```

我们刚刚发现文本插值会自动转义 HTML 标记。这是为了防止注入攻击并提高我们应用程序的安全性。幸运的是，有一种方法可以显示一些 HTML，我们马上就会看到。然而，这会迫使您考虑使用它来包含潜在有害的动态内容。

例如，您可以创建一个评论系统，任何用户都可以在您的应用页面上写一些评论。如果有人在评论中写入一些 HTML，然后在页面上显示为有效的 HTML，会怎么样？他们可以添加一些恶意的 JavaScript 代码，您的应用程序的所有访问者都会变得脆弱。这被称为跨站脚本攻击，或者 XSS 攻击。这就是为什么文本插值总是转义 HTML 标记。

不建议在应用程序的用户创建的内容上使用`v-html`。他们可以在`<script>`标签内编写恶意 JavaScript 代码，这将被执行。然而，通过正常的文本插值，您将是安全的，因为 HTML 不会被执行。

# 显示 HTML

现在我们知道出于安全原因文本插值无法渲染 HTML，我们将需要另一种方式来渲染动态 HTML--`v-html`指令。就像我们在第一章中看到的`v-model`指令一样，这是一个特殊的属性，为我们的模板添加了一个新功能。它能够将任何有效的 HTML 字符串渲染到我们的应用程序中。只需将字符串作为值传递，如下所示：

```js
<!-- Preview pane -->
<aside class="preview" v-html="notePreview">
</aside>
```

现在，markdown 预览应该可以正常工作，并且 HTML 会动态插入到我们的页面中。

我们`aside`元素内的任何内容都将被`v-html`指令的值替换。您可以使用它来放置占位内容。

这是您应该得到的结果：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/a68e9943-826c-4926-823e-c780269c4f51.png)对于文本插值，还有一个等效的指令`v-text`，它的行为类似于`v-html`，但会像经典文本插值一样转义 HTML 标记。

# 保存笔记

目前，如果关闭或刷新应用程序，您的笔记将丢失。在下次打开应用程序时保存和加载它是个好主意。为了实现这一点，我们将使用大多数浏览器提供的标准`localStorage` API。

# 观察变化

我们希望在笔记内容发生变化时立即保存笔记。这就是为什么我们需要一些在`content`数据属性发生变化时被调用的东西，比如**观察者**。让我们向我们的应用程序添加一些观察者！

1.  在 Vue 实例中添加一个新的`watch`选项。

这个选项是一个字典，其中键是被观察属性的名称，值是一个观察选项对象。这个对象必须有一个`handler`属性，它可以是一个函数或者一个方法的名称。处理程序将接收两个参数--被观察属性的新值和旧值。

这是一个带有简单处理程序的例子：

```js
new Vue({
  // ...

  // Change watchers
  watch: {
    // Watching 'content' data property
    content: {
      handler (val, oldVal) {
        console.log('new note:', val, 'old note:', oldVal)
      },
    },
  },
})
```

现在，当你在笔记编辑器中输入时，你应该在浏览器控制台中看到以下消息：

```js
new note: This is a **note**! old note: This is a **note**
```

这将在笔记发生变化时非常有帮助。

你可以在`handler`旁边使用另外两个选项：

+   `deep`是一个布尔值，告诉 Vue 递归地观察嵌套对象内的变化。这在这里并不有用，因为我们只观察一个字符串。

+   `immediate`也是一个布尔值，强制处理程序立即被调用，而不是等待第一次变化。在我们的情况下，这不会有实质性的影响，但我们可以尝试一下来注意它的影响。

这些选项的默认值是`false`，所以如果你不需要它们，你可以完全跳过它们。

1.  将`immediate`选项添加到观察者中：

```js
      content: {
        handler (val, oldVal) {
          console.log('new note:', val, 'old note:', oldVal)      
        },
        immediate: true,
      },
```

一旦你刷新应用程序，你应该在浏览器控制台中看到以下消息弹出：

```js
new note: This is a **note** old note: undefined
```

毫不奇怪，笔记的旧值是`undefined`，因为观察者处理程序在实例创建时被调用。

1.  我们这里真的不需要这个选项，所以继续删除它：

```js
      content: {
        handler (val, oldVal) {
          console.log('new note:', val, 'old note:', oldVal)
        },
      },
```

由于我们没有使用任何选项，我们可以通过跳过包含`handler`选项的对象来使用更短的语法：

```js
content (val, oldVal) {
  console.log('new note:', val, 'old note:', oldVal)
},
```

这是当你不需要其他选项时观察者的最常见语法，比如`deep`或`immediate`。

1.  让我们保存我们的笔记。使用`localStorage.setItem()` API 来存储笔记内容：

```js
      content (val, oldVal) {
        console.log('new note:', val, 'old note:', oldVal)
        localStorage.setItem('content', val)
      },
```

要检查这是否起作用，编辑笔记并在应用程序或存储选项卡中打开浏览器开发工具（取决于你的浏览器），你应该在本地存储部分下找到一个新的条目：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/a0f073bb-c9be-4778-b02f-7b2e1378d589.png)

# 使用一个方法

有一个很好的编码原则说*不要重复自己*，我们真的应该遵循它。这就是为什么我们可以在可重用的函数中写一些逻辑，称为**methods**。让我们把我们的保存逻辑移到一个方法中：

1.  在 Vue 实例中添加一个新的`methods`选项，并在那里使用`localStorage` API：

```js
      new Vue({
        // ...

        methods: {
          saveNote (val) {
            console.log('saving note:', val)
            localStorage.setItem('content', val)
          },
        },
      })
```

1.  我们现在可以在观察者的`handler`选项中使用方法名：

```js
      watch: {
        content: {
          handler: 'saveNote',
        },
      },
```

或者，我们可以使用更短的语法：

```js
watch: {
  content: 'saveNote',
},
```

# 访问 Vue 实例

在方法内部，我们可以使用`this`关键字访问 Vue 实例。例如，我们可以调用另一个方法：

```js
methods: {
  saveNote (val) {
    console.log('saving note:', val)
    localStorage.setItem('content', val)
    this.reportOperation('saving')
  },
  reportOperation (opName) {
    console.log('The', opName, 'operation was completed!')
  },
},
```

在这里，`saveNote`方法将从`contentChanged`方法中调用。

我们还可以通过`this`访问 Vue 实例的其他属性和特殊函数。我们可以删除`saveNote`参数并直接访问`content`数据属性：

```js
methods: {
  saveNote () {
    console.log('saving note:', this.content)
    localStorage.setItem('content', this.content)
  },
},
```

这也适用于我们在*监视更改*部分创建的观察程序处理程序：

```js
watch: {
  content (val, oldVal) {
    console.log('new note:', val, 'old note:', oldVal)
    console.log('saving note:', this.content)
    localStorage.setItem('content', this.content)
  },
},
```

基本上，您可以在任何绑定到它的函数中使用`this`访问 Vue 实例：方法、处理程序和其他钩子。

# 加载保存的笔记

现在我们每次更改时保存笔记内容，当应用程序重新打开时，我们需要恢复它。我们将使用`localStorage.getItem()` API。在您的 JavaScript 文件末尾添加以下行：

```js
console.log('restored note:', localStorage.getItem('content'))
```

当您刷新应用程序时，您应该在浏览器控制台中看到保存的笔记内容。

# 生命周期钩子

恢复我们的笔记内容到 Vue 实例的第一种方式是在创建实例时设置内容数据属性。

每个 Vue 实例都遵循一个精确的生命周期，有几个步骤--它将被创建、挂载到页面上、更新，最后销毁。例如，在创建步骤期间，Vue 将使实例数据具有反应性。

钩子是一组特定的函数，在某个时间点自动调用。它们允许我们自定义框架的逻辑。例如，我们可以在创建 Vue 实例时调用一个方法。

我们有多个可用的钩子来在每个步骤发生时执行逻辑，或者在这些步骤之前执行逻辑：

+   `beforeCreate`：在 Vue 实例对象创建时调用（例如，使用`new Vue({})`），但在 Vue 对其进行任何操作之前调用。

+   `created`：在实例准备就绪并完全运行后调用。请注意，在此时，实例尚未在 DOM 中。

+   `beforeMount`：在实例添加（或挂载）到网页上之前调用。

+   `mounted`：当实例在页面上可见时调用。

+   `beforeUpdate`：当实例需要更新时调用（通常是在数据或计算属性发生变化时）。

+   `updated`：在数据更改应用到模板后调用。请注意，DOM 可能尚未更新。

+   `beforeDestroy`：在实例被拆除之前调用。

+   `destroyed`：在实例完全移除时调用。

目前，我们将仅使用`created`钩子来恢复笔记内容。要添加生命周期钩子，只需将具有相应名称的函数添加到 Vue 实例选项中：

```js
new Vue({
  // ...

  // This will be called when the instance is ready
  created () {
    // Set the content to the stored value
    // or to a default string if nothing was saved
    this.content = localStorage.getItem('content') || 'You can write in **markdown**'
  },
})
```

现在，当您刷新应用程序时，`created`钩子将在实例创建时自动调用。这将把`content`数据属性值设置为恢复的结果，或者如果结果为假，则设置为`'You can write in **markdown**'`，以防我们之前没有保存任何内容。

在 JavaScript 中，当值等于`false`、`0`、空字符串、`null`、`undefined`或`NaN`（不是一个数字）时，该值为假。在这里，如果对应的键在浏览器本地存储数据中不存在，`localStorage.getItem()`函数将返回`null`。

我们设置的观察者也被调用，因此笔记被保存，您应该在浏览器控制台中看到类似于这样的内容：

```js
new note: You can write in **markdown** old note: This is a note
saving note: You can write in **markdown**
The saving operation was completed!
```

我们可以看到，当调用 created 钩子时，Vue 已经设置了数据属性及其初始值（这里是*This is a note*）。

# 直接在数据中初始化

另一种方法是直接使用恢复的值初始化`content`数据属性：

```js
new Vue({
  // ...

  data () {
    return {
      content: localStorage.getItem('content') || 'You can write in **markdown**',
    }
  },

  // ...
})
```

在上述代码中，观察者处理程序不会被调用，因为我们初始化了`content`值而不是改变它。

# 多个笔记

只有一个笔记的笔记本并不那么有用，所以让我们将其变成一个多笔记本。我们将在左侧添加一个新的侧边栏，其中包含笔记列表，以及一些额外的元素，例如重命名笔记的文本字段和一个收藏切换按钮。

# 笔记列表

现在，我们将为包含笔记列表的侧边栏奠定基础：

1.  在主要部分之前添加一个带有`side-bar`类的新`aside`元素：

```js
      <!-- Notebook app -->
      <div id="notebook">

        <!-- Sidebar -->
        <aside class="side-bar">
          <!-- Here will be the note list -->
        </aside>

        <!-- Main pane -->
        <section class="main">
      ...
```

1.  添加一个名为`notes`的新数据属性--它将是包含所有笔记的数组：

```js
      data () {
        return {
          content: ...
          // New! A note array
          notes: [],
        }
      },
```

# 创建一个新笔记的方法

我们的每个笔记将是一个具有以下数据的对象：

+   `id`：这将是笔记的唯一标识符

+   `title`：这将包含在列表中显示的笔记名称

+   `content`：这将是笔记的 markdown 内容

+   `created`：这将是笔记创建的日期

+   `favorite`：这将是一个布尔值，允许将要在列表顶部显示的笔记标记为收藏

让我们添加一个方法，它将创建一个新的笔记并将其命名为`addNote`，它将创建一个具有默认值的新笔记对象：

```js
methods:{
  // Add a note with some default content and select it
  addNote () {
    const time = Date.now()
    // Default new note
    const note = {
      id: String(time),
      title: 'New note ' + (this.notes.length + 1),
      content: '**Hi!** This notebook is using [markdown](https://github.com/adam-p/markdown-here/wiki/Markdown-Cheatsheet) for formatting!',
      created: time,
      favorite: false,
    }
    // Add to the list
    this.notes.push(note)
  },
}
```

我们获取当前时间（这意味着自 1970 年 1 月 1 日 00:00:00 UTC 以来经过的毫秒数），这将是在每个笔记上具有唯一标识符的完美方式。我们还设置默认值，比如标题和一些内容，以及`created`日期和`favorite`布尔值。最后，我们将笔记添加到 notes 数组属性中。

# 使用 v-on 绑定按钮和点击事件

现在，我们需要一个按钮来调用这个方法。在具有 toolbar 类的`div`元素内创建一个新的按钮元素：

```js
<aside class="side-bar">
  <!-- Toolbar -->
  <div class="toolbar">
    <!-- Add note button -->
    <button><i class="material-icons">add</i> Add note</button>
  </div>
</aside>
```

当用户单击按钮时调用`addNote`方法时，我们将需要一个新的指令--`v-on`。值将是在捕获事件时调用的函数，但它还需要一个参数来知道要监听哪个事件。但是，你可能会问，我们如何将参数传递给指令呢？这很简单！在指令名称后添加一个`:`字符，然后是参数。这是一个例子：

```js
<button v-directive:argument="value">
```

在我们的情况下，我们正在使用`v-on`指令，事件名称作为参数，更具体地说，是`click`事件。它应该是这样的：

```js
<button v-on:click="callback">
```

当我们点击按钮时，我们的按钮应该调用`addNote`方法，所以继续修改我们之前添加的按钮：

```js
<button v-on:click="addNote"><i class="material-icons">add</i> Add note</button>
```

`v-on`指令还有一个可选的特殊快捷方式--`@`字符，允许你将前面的代码重写为以下内容：

```js
<button @click="addNote"><i class="material-icons">add</i> Add note</button>
```

现在我们的按钮已经准备好了，试着添加一些笔记。我们还没有在应用程序中看到它们，但你可以打开开发工具并注意到笔记列表的变化：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/d7a2f1ea-e8f8-436b-8699-5ec0629dcb6b.png)

# 使用 v-bind 绑定属性

如果工具提示显示了我们在“添加笔记”按钮上已经有的笔记数量，那将会很有帮助，不是吗？至少我们可以介绍另一个有用的指令！

工具提示是通过 title HTML 属性添加的。这是一个例子：

```js
<button title="3 note(s) already">
```

在这里，它只是一个静态文本，但我们希望使它动态。幸运的是，有一个指令允许我们将 JavaScript 表达式绑定到属性--`v-bind`。像`v-on`指令一样，它需要一个参数，这个参数是目标属性的名称。

我们可以用 JavaScript 表达式重写前面的例子如下：

```js
<button v-bind:title="notes.length + ' note(s) already'">
```

现在，如果你把鼠标光标放在按钮上，你会得到笔记的数量：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/1629233d-8be8-4523-9296-3080cf6680f9.png)

就像`v-on`指令一样，`v-bind`有一个特殊的快捷语法（两者都是最常用的指令）--你可以跳过`v-bind`部分，只放置带有属性名称的`:`字符。示例如下：

```js
<button :title="notes.length + ' note(s) already'">
```

使用`v-bind`绑定的 JavaScript 表达式将在需要时自动重新评估，并更新相应属性的值。

我们也可以将表达式移到一个计算属性中并使用它。计算属性可以如下所示：

```js
computed: {
  ...

  addButtonTitle () {
    return notes.length + ' note(s) already'
  },
},
```

然后，我们将重写绑定的属性，如下所示：

```js
<button :title="addButtonTitle">
```

# 使用`v-for`显示列表

现在，我们将在工具栏下方显示笔记列表。

1.  在工具栏正下方，添加一个带有`notes`类的新的`div`元素：

```js
      <aside class="side-bar">
        <div class="toolbar">
          <button @click="addNote"><i class="material-icons">add</i>        
          Add note</button>
        </div>
        <div class="notes">
          <!-- Note list here -->
        </div>
      </aside>
```

现在，我们想要显示多个 div 元素的列表，每个笔记一个。为了实现这一点，我们需要`v-for`指令。它以`item of items`的形式接受一个特殊的表达式作为值，将迭代`items`数组或对象，并为模板的这一部分公开一个`item`值。以下是一个示例：

```js
<div v-for="item of items">{{ item.title }}</div>
```

你也可以使用`in`关键字代替`of`：

```js
<div v-for="item in items">{{ item.title }}</div>
```

假设我们有以下数组：

```js
data () {
  return {
    items: [
      { title: 'Item 1' },
      { title: 'Item 2' },
      { title: 'Item 3' },
    ]
  }
}
```

最终呈现的 DOM 将如下所示：

```js
<div>Item 1</div>
<div>Item 2</div>
<div>Item 3</div>
```

正如你所看到的，放置`v-for`指令的元素在 DOM 中重复出现。

1.  让我们回到我们的笔记本，并在侧边栏显示笔记。我们将它们存储在 notes 数据属性中，所以我们需要对它进行迭代：

```js
      <div class="notes">
        <div class="note" v-for="note of notes">{{note.title}}</div>
      </div>
```

现在，我们应该在按钮下方看到笔记列表显示出来：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/ee4871d5-a8b1-4345-8f7e-1b0d0acb7ba0.png)

使用按钮添加几个笔记，你应该看到列表正在自动更新！

# 选择一个笔记

当选择一个笔记时，它将成为应用程序中间和右侧窗格的上下文--文本编辑器修改其内容，预览窗格显示其格式化的 markdown。让我们实现这个行为！

1.  添加一个名为`selectedId`的新数据属性，它将保存所选笔记的 ID：

```js
      data () {
        return {
          content: localStorage.getItem('content') || 'You can write in         
          **markdown**',
          notes: [],
          // Id of the selected note
          selectedId: null,
        }
      },
```

我们也可以创建一个`selectedNote`属性，保存笔记对象，但这将使保存逻辑更复杂，没有任何好处。

1.  我们需要一个新的方法，当我们点击列表中的一个笔记时将被调用以选择 ID。让我们称之为`selectNote`：

```js
      methods: {
        ...

        selectNote (note) {
          this.selectedId = note.id
        },
      }
```

1.  就像我们为添加笔记按钮所做的那样，我们将使用`v-on`指令在列表中的每个笔记项上监听`click`事件：

```js
      <div class="notes">
        <div class="note" v-for="note of notes"         
        @click="selectNote(note)">{{note.title}}</div>
      </div>
```

现在，当你点击一个笔记时，你应该看到更新的`selectedId`数据属性。

# 当前的笔记

现在我们知道当前选中的笔记是哪一个，我们可以替换一开始创建的旧`content`数据属性。很有用的是，我们可以创建一个计算属性来轻松访问选中的笔记，所以我们现在将创建一个：

1.  添加一个新的计算属性叫做`selectedNote`，它返回与我们的`selectedId`属性匹配的笔记：

```js
      computed: {
        ...

        selectedNote () {
          // We return the matching note with selectedId
          return this.notes.find(note => note.id === this.selectedId)
        },
      }
```

`note => note.id === this.selectedId`是来自 ES2015 JavaScript 版本的箭头函数。在这里，它接受一个`note`参数，并返回`note.id === this.selectedId`表达式的结果。

我们需要在我们的代码中用`selectedNote.content`替换旧的`content`数据属性。

1.  首先修改模板中的编辑器：

```js
      <textarea v-model="selectedNote.content"></textarea>
```

1.  然后，将`notePreview`计算属性改为现在使用`selectedNote`：

```js
      notePreview () {
        // Markdown rendered to HTML
        return this.selectedNote ? marked(this.selectedNote.content) :          
        ''
      },
```

现在，当你在列表中点击一个笔记时，文本编辑器和预览窗格将显示所选的笔记。

你可以安全地移除不再在应用程序中使用的`content`数据属性、它的观察者和`saveNote`方法。

# 动态 CSS 类

当笔记在笔记列表中被选中时，添加一个`selected`CSS 类会很好（例如，显示不同的背景颜色）。幸运的是，Vue 有一个非常有用的技巧来帮助我们实现这一点--`v-bind`指令（`:`字符是它的简写）有一些魔法可以使 CSS 类的操作更容易。你可以传递一个字符串，也可以传递一个字符串数组：

```js
<div :class="['one', 'two', 'three']">
```

我们将在 DOM 中得到以下内容：

```js
<div class="one two three">
```

然而，最有趣的特性是你可以传递一个对象，其键是类名，值是布尔值，用于确定是否应该应用每个类。以下是一个例子：

```js
<div :class="{ one: true, two: false, three: true }">
```

这个对象表示法将产生以下 HTML：

```js
<div class="one three">
```

在我们的情况下，我们只想在笔记被选中时应用选中的类。因此，我们将简单地写成如下形式：

```js
<div :class="{ selected: note === selectedNote }">
```

笔记列表现在应该是这样的：

```js
<div class="notes">
  <div class="note" v-for="note of notes" @click="selectNote(note)"
  :class="{selected: note === selectedNote}">{{note.title}}</div>
</div>
```

你可以将静态的`class`属性与动态的属性结合起来。建议将非动态类放入静态属性中，因为 Vue 会优化静态值。

现在，当你点击列表中的一个笔记来选择它时，它的背景颜色会改变：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/d0218a83-4367-4dad-9aa3-2973bbe607bd.png)

# 带有 v-if 的条件模板

在测试我们的更改之前，我们还需要最后一件事；如果没有选择笔记，主窗格和预览窗格不应该显示--对用户来说没有意义，让用户拥有指向空白的编辑器和预览窗格，并且会使我们的代码崩溃，因为`selectedNote`将是`null`。幸运的是，`v-if`指令可以在我们希望时动态地从模板中取出部分。它的工作原理就像 JavaScript 的`if`关键字一样，有一个条件。

在这个例子中，只要`loading`属性为假，`div`元素根本不会出现在 DOM 中：

```js
<div v-if="loading">
  Loading...
</div>
```

还有另外两个有用的指令，`v-else`和`v-else-if`，它们将按照你的预期工作：

```js
<div v-if="loading">
  Loading...
</div>

<div v-else-if="processing">
  Processing
</div>

<div v-else>
  Content here
</div>
```

回到我们的应用程序中，在主窗格和预览窗格中添加`v-if="selectedNote"`条件，以便它们在没有选择笔记时不会添加到 DOM 中：

```js
<!-- Main pane -->
<section class="main" v-if="selectedNote">
  ...
</section>

<!-- Preview pane -->
<aside class="preview" v-if="selectedNote" v-html="notePreview">
</aside>
```

这里的重复有点不幸，但 Vue 已经为我们做好了准备。你可以用一个特殊的`<template>`标签将两个元素包围起来，它的作用就像 JavaScript 中的大括号：

```js
<template v-if="selectedNote">
  <!-- Main pane -->
  <section class="main">
    ...
  </section>

  <!-- Preview pane -->
  <aside class="preview" v-html="notePreview">
  </aside>
</template>
```

此时，应用程序应该看起来像这样：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/7ba0db17-d712-407b-b3fd-5064e0d86990.png)`<template>`标签不会出现在 DOM 中；它更像是一个幽灵元素，用于将真实元素聚集在一起。

# 使用深度选项保存笔记

现在，我们想要在会话之间保存和恢复笔记，就像我们为笔记内容所做的那样：

1.  让我们创建一个新的`saveNotes`方法。由于我们不能直接将对象数组保存到`localStorage` API 中（它只接受字符串），我们需要先用`JSON.stringify`将其转换为 JSON 格式：

```js
      methods: {
        ...

        saveNotes () {
          // Don't forget to stringify to JSON before storing
          localStorage.setItem('notes', JSON.stringify(this.notes))
```

```js
          console.log('Notes saved!', new Date())
        },
      },
```

就像我们为之前的`content`属性所做的那样，我们将监视`notes`数据属性的更改来触发`saveNotes`方法。

1.  在观察选项中添加一个观察者：

```js
      watch: {
        notes: 'saveNotes',
      }
```

现在，如果你尝试添加一些任务，你应该在控制台中看到类似这样的东西：

```js
Notes saved! Mon Apr 42 2042 17:40:23 GMT+0100 (Paris, Madrid)
Notes saved! Mon Apr 42 2016 17:42:51 GMT+0100 (Paris, Madrid)
```

1.  在`data`钩子中更改`notes`属性的初始化，从`localStorage`中加载存储的列表：

```js
      data () {
        return {
          notes: JSON.parse(localStorage.getItem('notes')) || [],
          selectedId: null,
        }
      },
```

刷新页面后，新添加的笔记应该被恢复。然而，如果你尝试更改一个笔记的内容，你会注意到它不会触发`notes`观察者，因此，笔记不会被保存。这是因为，默认情况下，观察者只观察目标对象的直接更改--分配简单值，向数组中添加、删除或移动项目。例如，以下操作将被默认检测到：

```js
// Assignment
this.selectedId = 'abcd'

// Adding or removing an item in an array
this.notes.push({...})
this.notes.splice(index, 1)

// Sorting an array
this.notes.sort(...)
```

然而，所有其他操作，比如这些，都不会触发观察者：

```js
// Assignment to an attribute or a nested object
this.myObject.someAttribute = 'abcd'
this.myObject.nestedObject.otherAttribute = 42

// Changes made to items in an array
this.notes[0].content = 'new content'
```

在这种情况下，您需要在观察者中添加`deep`选项：

```js
watch: {
  notes: {
    // The method name
    handler: 'saveNotes',
    // We need this to watch each note's properties inside the array
    deep: true,
  },
}
```

这样，Vue 也将递归地监视我们`notes`数组内部的对象和属性。现在，如果你在文本编辑器中输入，笔记列表应该被保存--`v-model`指令将修改所选笔记的`content`属性，并且使用`deep`选项，观察者将被触发。

# 保存选择

如果我们的应用程序能够选择上次选择的笔记，那将非常方便。我们只需要存储和加载`selectedId`数据属性，用于存储所选笔记的 ID。没错！再一次，我们将使用一个观察者来触发保存：

```js
watch: {
  ...

  // Let's save the selection too
  selectedId (val) {
    localStorage.setItem('selected-id', val)
  },
}
```

此外，我们将在属性初始化时恢复值：

```js
data () {
  return {
    notes: JSON.parse(localStorage.getItem('notes')) || [],
    selectedId: localStorage.getItem('selected-id') || null,
  }
},
```

好了！现在，当你刷新应用程序时，它应该看起来和你上次离开时一样，选择的笔记也是一样的。

# 带有额外功能的笔记工具栏

我们的应用程序仍然缺少一些功能，比如删除或重命名所选笔记。我们将在一个新的工具栏中添加这些功能，就在笔记文本编辑器的上方。继续创建一个带有`toolbar`类的新的`div`元素；放在主要部分内部：

```js
<!-- Main pane -->
<section class="main">
  <div class="toolbar">
    <!-- Our toolbar is here! -->
  </div>
  <textarea v-model="selectedNote.content"></textarea>
</div>
```

我们将在这个工具栏中添加三个新功能：

+   重命名笔记

+   删除笔记

+   将笔记标记为收藏

# 重命名笔记

这个第一个工具栏功能也是最简单的。它只包括一个与所选笔记的`title`属性绑定的文本输入，使用`v-model`指令。

在我们刚创建的工具栏`div`元素中，添加这个带有`v-model`指令和`placeholder`的`input`元素，以通知用户其功能：

```js
<input v-model="selectedNote.title" placeholder="Note title" />
```

你应该在文本编辑器上方有一个功能性的重命名字段，并且在输入时，你应该看到笔记名称在笔记列表中自动更改：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/f0942004-709f-461e-bdec-e67bede061fe.png)由于我们在`notes`观察者上设置了`deep`选项，所以每当您更改所选笔记的名称时，笔记列表都将被保存。

# 删除笔记

这个第二个功能有点复杂，因为我们需要一个新的方法：

1.  在重命名文本输入框后添加一个`button`元素：

```js
      <button @click="removeNote" title="Remove note"><i        
      class="material-icons">delete</i></button>
```

正如你所看到的，我们使用`v-on`简写（`@`字符）来监听`click`事件，调用我们即将创建的`removeNote`方法。此外，我们将适当的图标放在按钮内容中。

1.  添加一个新的`removeNote`方法，询问用户确认，然后使用`splice`标准数组方法从`notes`数组中删除当前选择的笔记：

```js
      removeNote () {
        if (this.selectedNote && confirm('Delete the note?')) {
          // Remove the note in the notes array
          const index = this.notes.indexOf(this.selectedNote)
          if (index !== -1) {
            this.notes.splice(index, 1)
          }
        }
      }
```

现在，如果您尝试删除当前笔记，您应该注意到以下三件事情发生了：

+   笔记从左侧的笔记列表中删除

+   文本编辑器和预览窗格被隐藏

+   笔记列表已根据浏览器控制台保存

# 收藏的笔记

最后一个工具栏功能是最复杂的。我们希望重新排列笔记列表，使收藏的笔记首先显示出来。为此，每个笔记都有一个`favorite`布尔属性，可以通过按钮切换。除此之外，笔记列表中还会显示一个星形图标，以明确显示哪些笔记是收藏的，哪些不是：

1.  首先，在删除笔记按钮之前的工具栏中添加另一个按钮：

```js
      <button @click="favoriteNote" title="Favorite note"><i        
      class="material-icons">{{ selectedNote.favorite ? 'star' :               
      'star_border' }}</i></button>
```

再次使用`v-on`简写来调用我们将在下面创建的`favoriteNote`方法。我们还将根据所选笔记的`favorite`属性的值显示一个图标--如果为`true`，则显示一个实心星形图标，否则显示一个轮廓星形图标。

最终结果将如下所示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/f4496b4b-718c-4f8b-a564-4bdc0e7441a2.png)

在左侧，有一个按钮，用于当笔记不是收藏时，右侧是当笔记是收藏时，点击它后。

1.  让我们创建一个非常简单的`favoriteNote`方法，它只是反转所选笔记上的`favorite`布尔属性的值：

```js
      favoriteNote () {
        this.selectedNote.favorite = !this.selectedNote.favorite
      },
```

我们可以使用异或运算符重写这个：

```js
favoriteNote () {
  this.selectedNote.favorite = this.selectedNote.favorite ^ true
},
```

这可以很好地简化，如下所示：

```js
favoriteNote () {
  this.selectedNote.favorite ^= true
},
```

现在，您应该能够切换收藏按钮，但它目前还没有任何实际效果。

我们需要以两种方式对笔记列表进行排序--首先，我们按创建日期对所有笔记进行排序，然后对它们进行排序，使收藏的笔记排在最前面。幸运的是，我们有一个非常方便的标准数组方法--`sort`。它接受一个参数，即一个具有两个参数的函数--要比较的两个项目。结果是一个数字，如下所示：

+   `0`，如果两个项目处于等价位置

+   `-1`，如果第一个项目应该在第二个项目之前

+   `1`，如果第一个项目应该在第二个项目之后

您不仅限于`1`这个数字，因为您可以返回任意的数字，正数或负数。例如，如果您返回`-42`，它将与`-1`相同。

第一个排序操作将通过这个简单的减法代码实现：

```js
sort((a, b) => a.created - b.created)
```

在这里，我们比较了两个笔记的创建日期，我们将其存储为毫秒数，感谢`Date.now()`。我们只需将它们相减，这样如果`b`在`a`之后创建，我们就会得到一个负数，或者如果`a`在`b`之后创建，我们就会得到一个正数。

第二次排序是用两个三元操作符完成的：

```js
sort((a, b) => (a.favorite === b.favorite)? 0 : a.favorite? -1 : 1)
```

如果两个笔记都是收藏的，我们不改变它们的位置。如果`a`是收藏的，我们返回一个负数将其放在`b`之前。在另一种情况下，我们返回一个正数，所以`b`会在列表中放在`a`之前。

最好的方法是创建一个名为`sortedNotes`的计算属性，它将被 Vue 自动更新和缓存。

1.  创建新的`sortedNotes`计算属性：

```js
      computed: {
        ...

        sortedNotes () {
          return this.notes.slice()
            .sort((a, b) => a.created - b.created)
            .sort((a, b) => (a.favorite === b.favorite)? 0
              : a.favorite? -1    
              : 1)
        },
      }
```

由于`sort`直接修改源数组，我们应该使用`slice`方法创建一个副本。这将防止`notes`观察者的不必要触发。

现在，我们可以在用于显示列表的`v-for`指令中简单地将`notes`替换为`sortedNotes`--它现在会自动按我们的预期对笔记进行排序：

```js
<div v-for="note of sortedNotes">
```

我们还可以使用之前介绍的`v-if`指令，只有在笔记被收藏时才显示星标图标：

```js
<i class="icon material-icons" v-if="note.favorite">star</i>
```

1.  使用上述更改修改笔记列表：

```js
      <div class="notes">
        <div class="note" v-for="note of sortedNotes"
        :class="{selected: note === selectedNote}"
        @click="selectNote(note)">
          <i class="icon material-icons" v-if="note.favorite">
          star</i> 
          {{note.title}}
        </div>
      </div>
```

应用程序现在应该如下所示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/30ce8ce9-6cf9-45de-9ca1-4c05c0b7af68.png)

# 状态栏

我们将添加到应用程序的最后一个部分是状态栏，在文本编辑器底部显示一些有用的信息--笔记创建日期，以及行数、单词数和字符数。

创建一个带有`toolbar`和`status-bar`类的新`div`元素，并将其放在`textarea`元素之后：

```js
<!-- Main pane -->
<section class="main">
  <div class="toolbar">
    <!-- ... -->
  </div>
  <textarea v-model="selectedNote.content"></textarea>
  <div class="toolbar status-bar">
    <!-- The new status bar here! -->
  </div>
</section>
```

# 带有过滤器的创建日期

我们现在将在状态栏中显示所选笔记的创建日期。

1.  在状态栏`div`元素中，创建一个新的`span`元素如下：

```js
      <span class="date">
        <span class="label">Created</span>
        <span class="value">{{ selectedNote.created }}</span>
      </span>
```

现在，如果你在浏览器中查看结果，你应该看到表示笔记创建日期的毫秒数：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/58a60c05-cdb9-4c97-951b-aa0a0b4aa28e.png)

这一点一点也不用户友好！

我们需要一个新的库来帮助我们将日期格式化为更易读的结果--`momentjs`，这是一个非常流行的时间和日期处理库。

1.  像我们为`marked`库所做的那样将其包含在页面中：

```js
      <script src="https://unpkg.com/moment"></script>
```

要格式化日期，我们首先会创建一个`moment`对象，然后我们将使用`format`方法，就像下面这样：

```js
      moment(time).format('DD/MM/YY, HH:mm')
```

现在是介绍本章最后一个 Vue 特性的时候--**过滤器**。这些是在模板内部使用的函数，用于在显示或传递给属性之前轻松处理数据。例如，我们可以有一个大写过滤器，将字符串转换为大写字母，或者一个货币过滤器，在模板中实时转换货币。该函数接受一个参数--要由过滤器处理的值。它返回处理后的值。

因此，我们将创建一个新的`date`过滤器，它将接受一个日期时间并将其格式化为人类可读的格式。

1.  使用`Vue.filter`全局方法注册此过滤器（在 Vue 实例创建代码之外，例如在文件开头）：

```js
 Vue.filter('date', time => moment(time)
        .format('DD/MM/YY, HH:mm'))
```

现在，我们可以在模板中使用这个`date`过滤器来显示日期。语法是 JavaScript 表达式，后跟一个管道运算符和过滤器的名称，就像我们之前使用的那样：

```js
{{ someDate | date }}
```

如果`someDate`包含一个日期，它将在 DOM 中输出类似于我们之前定义的`DD/MM/YY, HH:mm`格式的内容：

```js
12/02/17, 12:42
```

1.  将 stat 模板更改为这样：

```js
      <span class="date">
        <span class="label">Created</span>
        <span class="value">{{ selectedNote.created | date }}</span>
      </span>
```

我们应该在我们的应用程序中有一个格式良好的日期显示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/e5766d56-229f-4660-b907-65a8adcff067.png)

# 文本统计

我们可以显示的最后统计数据更多地面向“写作者”--行数、单词数和字符数：

1.  让我们为每个计数器创建三个新的计算属性，使用一些正则表达式来完成工作：

```js
      computed: {
        linesCount () {
          if (this.selectedNote) {
            // Count the number of new line characters
            return this.selectedNote.content.split(/\r\n|\r|\n/).length
          }
        },

        wordsCount () {
          if (this.selectedNote) {
            var s = this.selectedNote.content
            // Turn new line cahracters into white-spaces
            s = s.replace(/\n/g, ' ')
            // Exclude start and end white-spaces
            s = s.replace(/(^\s*)|(\s*$)/gi, '')
            // Turn 2 or more duplicate white-spaces into 1
            s = s.replace(/\s\s+/gi, ' ')
            // Return the number of spaces
            return s.split(' ').length
          }
        },

        charactersCount () {
          if (this.selectedNote) {
            return this.selectedNote.content.split('').length
          }
        },
      }
```

在这里，我们添加了一些条件，以防止代码在当前未选择任何笔记时运行。这将避免在这种情况下使用 Vue devtools 检查应用程序时出现崩溃，因为它将尝试计算所有属性。

1.  现在，您可以添加三个新的 stat `span`元素，带有相应的计算属性：

```js
      <span class="lines">
        <span class="label">Lines</span>
        <span class="value">{{ linesCount }}</span>
      </span>
      <span class="words">
        <span class="label">Words</span>
        <span class="value">{{ wordsCount }}</span>
      </span>
      <span class="characters">
        <span class="label">Characters</span>
        <span class="value">{{ charactersCount }}</span>
      </span>
```

最终的状态栏应该是这样的：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/54df01f4-25c9-4868-aac9-ad1edc8658d6.png)

# 总结

在本章中，我们创建了我们的第一个真正的 Vue 应用程序，具有几个有用的功能，如实时的 Markdown 预览，笔记列表以及笔记的本地持久化。我们介绍了不同的 Vue 功能，比如计算属性，它们会根据需要自动更新和缓存，方法可以在函数内重复使用逻辑，观察者可以在属性更改时触发代码，生命周期钩子可以在 Vue 实例创建时执行代码，过滤器可以轻松处理模板中的表达式。我们还在模板中使用了许多 Vue 指令，比如`v-model`来绑定表单输入，`v-html`来显示来自 JavaScript 属性的动态 HTML，`v-for`来重复元素并显示列表，`v-on`（或`@`）来监听事件，`v-bind`（或`:`）来动态绑定 HTML 属性到 JavaScript 表达式或动态应用 CSS 类，以及`v-if`来根据 JavaScript 表达式包含或不包含模板部分。我们看到所有这些功能共同构建了一个完全功能的 Web 应用程序，Vue 的超能力帮助我们完成工作而不会妨碍。

在下一章中，我们将开始一个新项目——基于卡片的浏览器游戏。我们将介绍一些新的 Vue 功能，并将继续重复利用我们所知道的一切，以继续构建更好、更漂亮的 Web 应用程序。


# 第三章：项目 2 - 城堡决斗浏览器游戏

在本章中，我们将创建一个完全不同的应用程序--一个浏览器游戏。它将由两名玩家组成，每个玩家指挥一座令人印象深刻的城堡，并试图通过行动卡将对手的食物或伤害水平降低到零来摧毁对方。

在这个项目和接下来的项目中，我们将把我们的应用程序分成可重用的组件。这是框架的核心，其所有 API 都是围绕这个想法构建的。我们将看到如何定义和使用组件，以及如何使它们相互通信。结果将是我们应用程序的更好结构。

# 游戏规则

以下是我们将在游戏中实施的规则：

+   两名玩家轮流进行游戏

+   每个玩家游戏开始时拥有 10 点健康值，10 点食物和 5 张手牌

+   玩家的健康和食物值不能超过 10 点。

+   当玩家的食物或健康值达到零时，玩家将失败。

+   两名玩家都可以在平局中失败。

+   在一个玩家的回合中，每个玩家唯一可能的行动是打出一张卡牌，然后将其放入弃牌堆

+   每个玩家在回合开始时从抽牌堆中抽一张牌（除了他们的第一回合）

+   由于前两条规则，每个玩家在开始他们的回合时手中正好有五张牌

+   如果玩家抽牌时抽牌堆为空，则将弃牌堆重新填满抽牌堆

+   卡片可以修改玩家或对手的健康和食物值

+   有些卡片还可以让玩家跳过他们的回合。

游戏玩法建立在玩家每回合只能打出一张卡牌，并且大多数卡牌会对他们产生负面影响（最常见的是失去食物）。你必须在出牌前考虑好你的策略。

应用程序将由两层组成--世界，游戏对象（如风景和城堡）在其中绘制，以及用户界面。

世界将有两座城堡彼此对峙，一个地面和一个天空，有多个动画云；每座城堡将有两面旗帜--绿色的代表玩家的食物，红色的代表玩家的健康--并显示剩余食物或健康值的气泡：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/66e1a50b-ee36-4040-998f-f14783618466.png)

UI 界面顶部将有一个条形菜单，显示回合计数器和两名玩家的姓名。屏幕底部，手牌将显示当前玩家的卡牌。

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/c23e599c-d371-4475-9db2-e39f306bedab.png)

除此之外，还会定期显示一些叠加层，隐藏手牌。其中一个将显示接下来轮到的玩家的名字：

！[](assets/f8d92822-cde6-4725-ae5b-9b2889da3c15.png)

接下来将是另一个叠加层，显示对手上一轮打出的牌。这将允许游戏在同一屏幕上进行（例如，平板电脑）。

！[](assets/0f3ed8f3-ae57-404b-863a-bd3f274f1e13.png）

第三个叠加层只有在游戏结束时才会显示，显示玩家是赢了还是输了。单击此叠加层将重新加载页面，允许玩家开始新游戏。

！[](assets/1744d0e2-78e2-44a2-8ad8-2a6ab7656f5c.png)

# 设置项目

下载`第二章`文件并将项目设置提取到一个空文件夹中。您应该有以下内容：

+   `index.html`：网页

+   `style.css`：CSS 文件

+   `svg`：包含游戏的所有 SVG 图像

+   `cards.js`：所有卡片数据都已准备好使用

+   `state.js`：我们将在这里整合游戏的主要数据属性

+   `utils.js`：我们将编写有用的函数的地方

+   `banner-template.svg`：我们稍后将使用此文件的内容

我们将从我们的主 JavaScript 文件开始--创建一个名为`main.js`的新文件。

打开`index.html`文件，并在`state.js`之后添加一个引用新文件的新脚本标记：

```js
<!-- Scripts -->
<script src="img/utils.js"></script>
<script src="img/cards.js"></script>
<script src="img/state.js"></script>
<script src="img/main.js"></script>
```

让我们在`main.js`文件中创建我们应用程序的主要实例：

```js
new Vue({
  name: 'game',
  el: '#app',
})
```

我们现在已经准备好了！

# 风平浪静

在这一部分，我们将介绍一些新的 Vue 功能，这些功能将帮助我们构建游戏，比如组件、props 和事件发射！

# 模板选项

如果您查看`index.html`文件，您会看到`＃app`元素已经存在且为空。实际上，我们不会在里面写任何东西。相反，我们将直接在定义对象上使用模板选项。让我们尝试一个愚蠢的模板：

```js
new Vue({
  name: 'game',
  el: '#app',

  template: `<div id="#app">
    Hello world!
  </div>`,
})
```

在这里，我们使用了新的 JavaScript 字符串，带有`` ` ``字符（反引号）。它允许我们编写跨越多行的文本，而不必编写冗长的字符串连接。

现在，如果你打开应用程序，你应该看到`'Hello world!'`文本显示出来。正如你猜到的那样，从现在开始我们不会将模板内联到`#app`元素中。

# 应用程序状态

正如之前解释的那样，`state.js` 文件将帮助我们将应用程序的主要数据整合到一个地方。这样，我们将能更容易地编写游戏逻辑函数，而不会用大量方法污染定义对象。

1.  `state.js` 文件声明了我们将用作应用程序数据的数据变量。我们可以直接将其用作数据选项，如下所示：

```js
      new Vue({
        // …
        data: state,
      })
```

现在，如果你打开开发工具，你应该看到状态对象中已经声明的唯一数据属性：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/06ba9d2b-5ad4-4ed0-ae51-c1774600dde0.png)

世界比例是一个表示我们应该如何缩放游戏对象以适应窗口的数字。例如，`.6`表示世界应该以其原始大小的 60%进行缩放。它是在`utils.js`文件中使用`getWorldRatio`函数计算的。

有一件事情还缺少 - 当窗口大小调整时它不会被重新计算。这是我们必须自己实现的。在 Vue 实例构造函数之后，添加一个事件监听器到窗口对象，以便在窗口大小调整时检测。

1.  在处理程序内，更新状态的`worldRatio`数据属性。你也可以在模板中显示`worldRatio`：

```js
      new Vue({
        name: 'game',
        el: '#app',

        data: state,

        template: `<div id="#app">
          {{ worldRatio }}
        </div>`,
      })

      // Window resize handling
      window.addEventListener('resize', () => {
        state.worldRatio = getWorldRatio()
      })
```

尝试水平调整浏览器窗口大小 - `worldRatio` 数据属性在 Vue 应用中被更新。

*等等！我们正在修改状态对象，而不是 Vue 实例...*

你是对的！然而，我们使用`state`对象设置了 Vue 实例`数据`属性。这意味着 Vue 已经在其上设置了响应性，并且我们可以改变它的属性来更新我们的应用程序，正如我们将在下面看到的那样。

1.  为了确保`state`是应用的反应性数据，请尝试比较实例数据对象和全局状态对象：

```js
      new Vue({
        // ...
        mounted () {
          console.log(this.$data === state)
        },
      })
```

这些是我们使用数据选项设置的相同对象。所以当你这样做时：

```js
this.worldRatio = 42
```

你也在做这个：

```js
this.$data.worldRatio = 42
```

这实际上和以下一样：

```js
state.worldRatio = 42
```

这将在游戏功能中非常有用，该功能将使用状态对象来更新游戏数据。

# 全能的组件

组件是构成我们应用程序的构建块 - 这是 Vue 应用程序的核心概念。它们是视图的小部分，应该相对小，可重用，并且尽可能自包含 - 使用组件来构建应用程序将有助于维护和发展它，特别是当应用程序变得庞大时。事实上，这已经成为以高效和可管理的方式创建庞大 Web 应用程序的标准方法。

具体而言，你的应用程序将是一个由小组件组成的巨大树：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/b20410bf-c9fc-47ea-8474-f65537e325f3.png)

例如，你的应用程序可能有一个表单组件，其中可以包含多个输入组件和按钮组件。每个组件都是 UI 的一个非常具体的部分，并且它们可以在整个应用程序中重复使用。作用域非常小，它们很容易理解和推理，因此更容易维护（修复问题）或发展。

# 构建用户界面

我们将创建的第一个组件是 UI 层的一部分。它将包括一个带有玩家姓名和回合计数器的顶端栏、带有名称和描述的卡片、当前玩家卡片的手牌和三个叠加层。

# 我们的第一个组件 - 顶端栏

顶端栏，我们的第一个组件，将被放置在页面的顶部，并且在中间显示两个玩家的姓名和回合计数器。它还将显示一个箭头指向当前正在进行回合的玩家的姓名。

它将如下所示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/8739ced8-2ec7-4a72-af0f-fa01f814c080.png)

# 在状态中添加一些游戏数据

在创建组件之前，我们需要一些新的数据属性：

+   `turn`: 当前回合数；从 1 开始

+   `players`: 玩家对象的数组

+   `currentPlayerIndex`: `players` 数组中当前玩家的索引

在 `state.js` 文件中将它们添加到状态中：

```js
// The consolidated state of our app
var state = {
  // World
  worldRatio: getWorldRatio(),
  // Game
  turn: 1,
  players: [
    {
      name: 'Anne of Cleves',
    },
    {
      name: 'William the Bald',
    },
  ],
  currentPlayerIndex: Math.round(Math.random()),
}
```

`Math.round(Math.random())` 将使用随机选择 `0` 或 `1` 来确定谁先行。

我们将使用这些属性来在顶端栏中显示玩家姓名和回合计数器。

# 定义和使用组件

我们将在一个新的文件中编写我们的 UI 组件：

1.  创建一个 `components` 文件夹并在其中创建一个新的 `ui.js` 文件。在主 `index.html` 页面中引入它，就在主要脚本之前：

```js
      <!-- Scripts -->
      <script src="img/utils.js"></script>
      <script src="img/cards.js"></script>
      <script src="img/state.js"></script>
      <script src="img/ui.js"></script>
      <script src="img/main.js"></script>
```

在这个文件中，我们将注册我们的组件，所以主要的 Vue 实例创建在后面而不是前面，否则，我们将得到组件不存在的错误。

要注册一个组件，我们可以使用全局的 `Vue.component()` 函数。它接受两个参数；我们注册组件的名称，以及它的定义对象，该对象使用了我们已经了解的 Vue 实例的完全相同的选项。

1.  让我们在 `ui.js` 文件中创建`top-bar`组件：

```js
 Vue.component('top-bar', {
        template: `<div class="top-bar">
          Top bar
        </div>`,
      })
```

现在，我们可以在模板中使用 `top-bar` 组件，就像使用任何其他 HTML 标签一样，例如 `<top-bar>`。

1.  在主模板中，添加一个新的 `top-bar` 标签：

```js
      new Vue({
        // ...
        template: `<div id="#app">
          <top-bar/>
        </div>`,
      })
```

这个模板将创建一个新的 `top-bar` 组件，并使用我们刚刚定义的定义对象在 `#app` 元素内呈现它。如果你打开开发工具，你应该会看到两个条目：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/8ea8c881-2a6b-4eb0-be9e-4c711323bb9c.png)

每个都是一个 Vue 实例--Vue 实际上使用我们为顶端栏组件提供的定义创建了第二个实例。

# 使用 props 进行从父组件到子组件的通信

正如我们在强大的组件部分中所见，我们基于组件的应用程序将具有一系列组件，并且我们需要它们相互通信。目前，我们只关注下行、从父级到子级的通信。这通过"props"完成。

我们的`top-bar`组件需要知道玩家是谁，当前正在玩谁，以及当前回合数是多少。因此，我们将需要三个 props--`players`、`currentPlayerIndex`和`turn`。

要向组件定义添加 props，请使用`props`选项。目前，我们只会简单列出我们的 props 的名称。但是，你应该知道还有一种更详细的符号，使用对象代替，我们将在接下来的章节中介绍。

1.  让我们将 props 添加到我们的组件中：

```js
      Vue.component('top-bar', {
        // ...
        props: ['players', 'currentPlayerIndex', 'turn'],
      })
```

在父组件中，即根应用程序中，我们可以以与 HTML 属性相同的方式设置 props 值。

1.  继续使用`v-bind`简写将 props 值与主模板中的应用程序数据进行连接：

```js
      <top-bar :turn="turn" :current-player-index="currentPlayerIndex"         
      :players="players" />
```

请注意，由于 HTML 不区分大小写并且按照惯例，建议在 JavaScript 代码中使用连字符的 kebab-case（带有短横线）名称和 props 的骆驼式命名。

现在，我们可以像数据属性一样在我们的`top-bar`组件中使用 props。例如，你可以这样写：

```js
Vue.component('top-bar', {
  // ...
  created () {
    console.log(this.players)
  },
})
```

这将在浏览器控制台中打印由父组件（我们的应用程序）发送的`players`数组。

# 我们模板中的 props

现在，我们将在`top-bar`组件的模板中使用我们创建的 props。

1.  更改`top-bar`模板以使用`players` prop 显示玩家的名称：

```js
      template: `<div class="top-bar">
        <div class="player p0">{{ players[0].name }}</div>
        <div class="player p1">{{ players[1].name }}</div>
      </div>`,
```

正如你在上述代码中所看到的，我们也像在模板中使用属性一样使用 props。你应该在应用程序中看到玩家名称显示。

1.  继续使用`turn` prop 在`players`之间显示回合计数器：

```js
      template: `<div class="top-bar">
        <div class="player p0">{{ players[0].name }}</div>
        <div class="turn-counter">
        <div class="turn">Turn {{ turn }}</div>
        </div>
        <div class="player p1">{{ players[1].name }}</div>
        </div>`,
```

除了标签外，我们还希望显示一个面向当前玩家的大箭头，以使其更加明显。

1.  在`.turn-counter`元素内添加箭头图像，并使用我们在第二章*Markdown 笔记本*中使用的`v-bind`简写为`currentPlayerIndex` prop 添加动态类：

```js
      template: `<div class="top-bar" :class="'player-' + 
 currentPlayerIndex">
        <div class="player p0">{{ players[0].name }}</div>
        <div class="turn-counter">
          <img class="arrow" src="img/turn.svg" />
          <div class="turn">Turn {{ turn }}</div>
        </div>
        <div class="player p1">{{ players[1].name }}</div>
      </div>`,
```

现在，应用程序应该显示具有两个玩家、名称和它们之间的回合计数器的完整功能顶栏。你可以通过在浏览器控制台中输入这些命令来测试 Vue 自动反应性：

```js
state.currentPlayerIndex = 1
state.currentPlayerIndex = 0
```

你应该看到箭头转向正确的玩家名称，这将被强调：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/a667ef7b-5325-4e1a-bf9f-4555b64d5b38.png)

# 显示一张卡片

所有的卡片都在`cards.js`文件中声明的卡片定义对象中描述。你可以打开它，但你不应该修改其内容。每个卡片定义都具有以下字段：

+   `id`：每张卡片的唯一标识符

+   `type`：更改颜色背景以帮助区分卡片

+   `title`：卡片的显示名称

+   `description`：解释卡片功能的 HTML 文本

+   `note`：一个可选的 HTML 风格文本

+   `play`：当卡片被玩时我们将调用的函数

我们需要一个新组件来显示任何卡片，无论是在玩家手中还是在覆盖层中，描述对手上一轮玩的是什么牌。它将如下所示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/bdcb0ac6-585b-4c0f-a2e3-fdbe7c28385b.png)

1.  在 `components/ui.js` 文件中，创建一个新的 `card` 组件：

```js
 Vue.component('card', {
        // Definition here
      })
```

1.  此组件将接收一个 `def` 属性，该属性将是我们上面描述的卡片定义对象。声明它与我们为 `top-bar` 组件所做的方式相同的 `props` 选项：

```js
      Vue.component('card', {
        props: ['def'],
      })
```

1.  现在，我们可以添加模板。从主要的 `div` 元素开始，带有 `card` 类：

```js
      Vue.component('card', {
        template: `<div class="card">
        </div>`,
        props: ['def'],
      })
```

1.  根据卡片类型更改背景颜色，添加一个使用卡片对象的 `type` 属性的动态 CSS 类：

```js
      <div class="card" :class="'type-' + def.type">
```

例如，如果卡片具有 `'attack'` 类型，则元素将获得 `type-attack` 类。然后，它将具有红色背景。

1.  现在，添加带有相应类的卡片标题：

```js
      <div class="card" :class="'type-' + def.type">
        <div class="title">{{ def.title }}</div>
      </div>
```

1.  添加分隔图像，该图像将在卡片标题和描述之间显示一些线条：

```js
      <div class="title">{{ def.title }}</div>
      <img class="separator" src="img/card-separator.svg" />
```

图像后附加描述元素。

注意，由于卡片对象的 `description` 属性是 HTML 格式化的文本，我们需要使用第二章介绍的特殊 `v-html` 指令。

1.  使用 `v-html` 指令来显示描述：

```js
      <div class="description"><div v-html="def.description"></div>             
      </div>
```

你可能已经注意到我们添加了一个嵌套的 `div` 元素，它将包含描述文本。这是为了使用 CSS flexbox 垂直居中文本。

1.  最后，添加卡片注释（也是 HTML 格式化的文本）。注意，有些卡片没有注释，因此我们必须在这里使用 `v-if` 指令：

```js
      <div class="note" v-if="def.note"><div v-html="def.note"></div>        
      </div>
```

现在卡片组件应该看起来像这样：

```js
Vue.component('card', {
  props: ['def'],
  template: `<div class="card" :class="'type-' + def.type">
    <div class="title">{{ def.title }}</div>
    <img class="separator" src="img/card-separator.svg" />
    <div class="description"><div v-html="def.description"></div></div>
    <div class="note" v-if="def.note"><div v-html="def.note"></div></div>
  </div>`,
})
```

现在，我们可以在主应用程序组件中尝试我们的新卡片组件。

1.  编辑主模板如下，并在顶部栏后添加一个 `card` 组件：

```js
      template: `<div id="#app">
        <top-bar :turn="turn" :current-player-             
         index="currentPlayerIndex" :players="players" />
        <card :def="testCard" />
      </div>`,
```

1.  我们还需要定义一个临时计算属性：

```js
 computed: {
        testCard () {
          return cards.archers
        },
      },
```

现在，您应该看到一个红色的攻击卡片，带有标题、描述和口味文本：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/6b8c4676-e72a-41bb-915f-24b2ed0c0023.png)

# 监听组件上的原生事件

让我们尝试在我们的卡片上添加一个点击事件处理程序：

```js
<card :def="testCard" @click="handlePlay" />
```

在主要组件中使用愚蠢的方法：

```js
methods: {
  handlePlay () {
    console.log('You played a card!')
  }
}
```

如果你在浏览器中测试这个，你可能会惊讶地发现它不像预期那样工作。控制台什么也没有输出……

这是因为 Vue 有自己的组件事件系统，称为“自定义事件”，我们马上就会学到。该系统与浏览器事件分开，因此在这里 Vue 期望一个自定义的 `'click'` 事件，而不是浏览器事件。因此，`handler` 方法不会被调用。

为了解决这个问题，你应该在 `v-on` 指令上使用 `.native` 修饰符，如下所示：

```js
<card :def="testCard" @click.native="handlePlay" />
```

现在，当你点击卡片时，`handlePlay` 方法会按预期调用。

# 使用自定义事件进行子到父的通信

以前，我们使用 props 从父组件向其子组件通信。现在，我们想要做相反的事情，即从一个子组件向其父组件通信。对于我们的卡片组件，我们想要告诉父组件，当玩家点击卡片时，卡片正在被玩家播放。我们不能在这里使用 props，但是我们可以使用自定义事件。在我们的组件中，我们可以发出事件，父组件可以使用`$emit`特殊方法捕获。它接受一个必需的参数，即事件类型：

```js
this.$emit('play')
```

我们可以使用`$on`特殊方法在同一个 Vue 实例内监听自定义事件：

```js
this.$on('play', () => {
  console.log('Caught a play event!')
})
```

`$emit`方法还向父组件发送一个`'play'`事件。我们可以像以前一样在父组件模板中使用`v-on`指令来监听它：

```js
<card v-on:play="handlePlay" />
```

您还可以使用`v-bind`的快捷方式：

```js
<card @play="handlePlay" />
```

我们也可以添加任意数量的参数，这些参数将传递给处理程序方法：

```js
this.$emit('play', 'orange', 42)
```

在这里，我们发出了一个带有以下两个参数的`'play'`事件-- `'orange'`和`42`。

在处理中，我们可以通过参数获取它们，如下所示：

```js
handlePlay (color, number) {
  console.log('handle play event', 'color=', color, 'number=', number)
}
```

`color`参数将具有`'orange'`值，`number`参数将具有`42`值。

正如我们在前一节中所看到的，自定义事件与浏览器事件系统完全分开。特殊方法--`$on`和`$emit`--不是标准`addEventListener`和`dispatchEvent`的别名。这就解释了为什么我们需要在组件上使用`.native`修饰符来监听浏览器事件，如`'click'`。

回到我们的卡片组件，我们只需要发出一个非常简单的事件，告诉父组件卡片正在被播放：

1.  首先，添加会触发事件的方法：

```js
 methods: {
        play () {
          this.$emit('play')
        },
      },
```

1.  我们想在用户点击卡片时调用此方法。只需在主卡片`div`元素上监听浏览器点击事件：

```js
      <div class="card" :class="'type-' + def.type" @click="play">
```

1.  我们完成了卡片组件。要测试这一点，在主组件模板中监听`'play'`自定义事件：

```js
      <card :def="testCard" @play="handlePlay" />
```

现在，每当发出`'play'`事件时，将调用`handlePlay`方法。

我们本可以只监听本机点击事件，但通常最好使用自定义事件在组件之间进行通信。例如，当用户使用其他方法时，例如使用键盘选择卡片并按*Enter*键，我们也可以发出`'play'`事件；尽管我们不会在本书中实现该方法。

# 手牌

我们的下一个组件将是当前玩家的手牌，持有他们手中的五张牌。它将使用 3D 过渡进行动画处理，并且还将负责卡片动画（当卡片被抽取时，以及当它被打出时）。

1.  在`components/ui.js`文件中，添加一个具有`'hand'`ID 和一个基本模板的组件注册，带有两个`div`元素：

```js
 Vue.component('hand', {
        template: `<div class="hand">
          <div class="wrapper">
            <!-- Cards -->
          </div>
        </div>`,
      })
```

包装元素将帮助我们定位和动画处理卡片。

手中的每张卡片将由一个对象表示。目前，它将具有以下属性：

+   `id`：卡片定义的唯一标识符

+   `def`：卡片定义对象

作为提醒，所有的卡片定义都在 `cards.js` 文件中声明。

1.  我们的手部组件将通过一个名为 `cards` 的新数组属性接收代表玩家手牌的卡对象：

```js
      Vue.component('hand', {
        // ...
        props: ['cards'],
      })
```

1.  现在，我们可以使用 `v-for` 指令添加卡片组件了：

```js
      <div class="wrapper">
        <card v-for="card of cards" :def="card.def" />
      </div>
```

1.  为了测试我们的手部组件，我们将在应用程序状态中创建一个名为 `testHand` 的临时属性（在 `state.js` 文件中）：

```js
      var state = {
        // ...
        testHand: [],
      }
```

1.  在主组件中添加一个 `createTestHand` 方法（在 `main.js` 文件中）：

```js
      methods: {
        createTestHand () {
          const cards = []
          // Get the possible ids
          const ids = Object.keys(cards)

          // Draw 5 cards
          for (let i = 0; i < 5; i++) {
            cards.push(testDrawCard())
          }

          return cards
        },
      },
```

1.  为了测试手部，我们还需要这个临时的 `testDrawCard` 方法来模拟随机抽卡：

```js
      methods: {
        // ...
        testDrawCard () {
          // Choose a card at random with the ids
          const ids = Object.keys(cards)
          const randomId = ids[Math.floor(Math.random() * ids.length)]
          // Return a new card with this definition
          return {
            // Unique id for the card
            uid: cardUid++,
            // Id of the definition
            id: randomId,
            // Definition object
            def: cards[randomId],
          }
        }
      }
```

1.  使用 `created` 生命周期钩子来初始化手部：

```js
 created () {
        this.testHand = this.createTestHand()
      },
```

`cardUid` 是玩家抽取的卡片上的唯一标识符，对于识别手中的每张卡片都很有用，因为许多卡片可能共享完全相同的卡片定义，我们需要一种区分它们的方法。

1.  在主模板中，添加手部组件：

```js
      template: `<div id="#app">
        <top-bar :turn="turn" :current-player-           
         index="currentPlayerIndex" :players="players" />
        <hand :cards="testHand" />
      </div>`,
```

在您的浏览器中的结果应如下所示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/928716a8-049d-4deb-a1f5-c3827a3f597f.png)

# 使用过渡动画手部

在游戏过程中，当显示任何叠加时，手部将被隐藏。为了使应用程序更美观，当手部从 DOM 中添加或移除时，我们将对其进行动画处理。为此，我们将与强大的 Vue 工具--特殊的 `<transition>` 组件一起使用 CSS 过渡。它将帮助我们在使用 `v-if` 或 `v-show` 指令添加或移除元素时使用 CSS 过渡。

1.  首先，在 `state.js` 文件中的应用程序状态中添加一个新的 `activeOverlay` 数据属性：

```js
      // The consolidated state of our app
      var state = {
        // UI
        activeOverlay: null,
        // ...
      }
```

1.  在主模板中，我们将仅在 `activeOverlay` 未定义时显示手部组件，感谢 `v-if` 指令：

```js
      <hand :cards="testHand" v-if="!activeOverlay" />
```

1.  现在，如果您在浏览器控制台中将 `state.activeOverlay` 更改为任何真值，手部将消失：

```js
      state.activeOverlay = 'player-turn'
```

1.  另外，如果将其设置回 `null`，手部将再次显示：

```js
      state.activeOverlay = null
```

1.  当使用 `v-if` 或 `v-show` 指令添加或移除组件时应用过渡，请像这样将其包裹在过渡组件中：

```js
      <transition>
        <hand v-if="!activeOverlay" />
      </transition>
```

注意，这也适用于 HTML 元素：

```js
<transition>
  <h1 v-if="showTitle">Title</h1>
</transition>
```

`<transition>` 特殊组件不会出现在 DOM 中，就像我们在第二章 *Markdown Notebook* 中使用的 `<template>` 标签一样。

当元素被添加到 DOM 中（进入阶段）时，过渡组件将自动向元素应用以下 CSS 类：

+   `v-enter-active`：在进入过渡处于活动状态时应用此类。此类在元素插入到 DOM 中之前添加，并在动画完成时删除。您应该在此类中添加一些 `transition` CSS 属性，并定义它们的持续时间。

+   `v-enter`：元素的起始状态。此类在元素插入前添加，在元素插入后一帧删除。例如，你可以在此类中将不透明度设置为 `0`。

+   `v-enter-to`：元素的目标状态。此类在元素插入后一帧添加，与删除 `v-enter` 时同时发生。在动画完成时删除。

当元素从 DOM 中移除时（离开阶段），它们将被以下内容替换：

+   `v-leave-active`：在离开过渡处于活动状态时应用。此类在离开过渡触发时添加，并在元素从 DOM 中移除后删除。您应该在此类中添加一些`transition` CSS 属性并定义它们的持续时间。

+   `v-leave`：元素被移除时的起始状态。这个类也会在离开过渡触发时添加，并在一帧后删除。

+   `v-leave-to`：元素的目标状态。此类在离开过渡触发一帧后添加，与`v-leave`同时删除。当元素从 DOM 中移除时，它将被删除。

在离开阶段，元素不会立即从 DOM 中移除。在过渡完成后才会移除它，以便用户可以看到动画。

这里是一个总结了两个进入和离开阶段以及相应的 CSS 类的模式图：

![图](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/6159a0e0-22b4-4c34-aef2-b7e7730b7cd2.png)过渡组件将自动检测应用在元素上的 CSS 过渡的持续时间。

1.  我们需要编写一些 CSS 来制作我们的动画。创建一个新的`transitions.css`文件并将其包含在网页中：

```js
      <link rel="stylesheet" href="transitions.css" />
```

首先尝试基本的淡入淡出动画。我们希望在 1 秒钟内对不透明度 CSS 属性应用 CSS 过渡。

1.  为此，请同时使用`v-enter-active`和`v-leave-active`类，因为它们是相同的动画：

```js
      .hand.v-enter-active,
      .hand.v-leave-active {
        transition: opacity 1s;
      }
```

当手被添加或从 DOM 中移除时，我们希望它的不透明度为`0`（因此它将完全透明）。

1.  使用`v-enter`和`v-leave-to`类来应用这种完全透明：

```js
      .hand.v-enter,
      .hand.v-leave-to {
        opacity: 0;
      }
```

1.  回到主模板，使用过渡特殊组件将手组件包围起来：

```js
      <transition>
        <hand v-if="!activeOverlay" :cards="testHand" />
      </transition>
```

现在，当您隐藏或显示手时，它将淡入淡出。

1.  由于我们可能需要重用此动画，我们应该给它一个名称：

```js
      <transition name="fade">
        <hand v-if="!activeOverlay" :cards="testHand" />
      </transition>
```

我们必须更改我们的 CSS 类，因为 Vue 现在将使用`fade-enter-active`而不是`v-enter-active`。

1.  在`transition.css`文件中，修改 CSS 选择器以匹配此更改：

```js
      .fade-enter-active,
      .fade-leave-active {
        transition: opacity 1s;
      }

      .fade-enter,
      .fade-leave-to {
        opacity: 0;
      }
```

现在，我们可以在任何带有`<transition name="fade">`的元素上重复使用此动画。

# 更漂亮的动画

现在我们将制作一个更复杂但更好的动画，带有一些 3D 效果。除了手之外，我们还将为`.wrapper`元素（用于 3D 翻转）和`.card`元素添加动画。卡片将开始堆叠，并逐渐扩展到手中的预期位置。最后，它将以玩家从桌子上拿起卡片的方式进行动画。

1.  首先创建新的过渡 CSS 类，使用`'hand'`名称代替`'fade'`：

```js
      .hand-enter-active,
      .hand-leave-active {
        transition: opacity .5s;
      }

      .hand-enter,
      .hand-leave-to {
        opacity: 0;
      }
```

1.  在主模板中也更改过渡名称：

```js
      <transition name="hand">
        <hand v-if="!activeOverlay" :cards="testHand" />
      </transition>
```

1.  让我们对.wrapper 元素进行动画处理。使用 CSS transform 属性将 3D 变换应用于元素：

```js
      .hand-enter-active .wrapper,
      .hand-leave-active .wrapper {
        transition: transform .8s cubic-bezier(.08,.74,.34,1);
        transform-origin: bottom center;
      }

      .hand-enter .wrapper,
      .hand-leave-to .wrapper {
        transform: rotateX(90deg);
      }
```

右旋转轴是水平轴，即`x`。这将使卡片动画看起来就像被玩家拿起一样。请注意，定义了一个立方贝塞尔缓动函数，以使动画更平滑。

1.  最后，通过设置负的水平边距来为卡片本身添加动画，这样它们看起来就像是堆叠起来的：

```js
      .hand-enter-active .card,
      .hand-leave-active .card {
        transition: margin .8s cubic-bezier(.08,.74,.34,1);
      }

      .hand-enter .card,
      .hand-leave-to .card {
        margin: 0 -100px;
      }
```

现在，如果您像以前那样使用浏览器控制台隐藏和显示手牌，它将有一个漂亮的动画。

# 打出一张牌

现在，我们需要处理手牌组件中的`'play'`事件，当用户点击它们时，我们会发出一个新的`'card-play'`事件到主组件，并附加一个额外的参数--所打出的牌。

1.  首先，创建一个名为`handlePlay`的新方法。它接受一个`card`参数，并向父组件发出新事件：

```js
      methods: {
        handlePlay (card) {
          this.$emit('card-play', card)
        },
      },
```

1.  然后，为我们的卡片添加一个对`'play'`事件的监听器：

```js
      <card v-for="card of cards" :def="card.def" 
      @play="handlePlay(card) />
```

正如您在这里看到的，我们直接使用了`v-for`循环的迭代变量`card`。这样，我们就不需要卡片组件发出它的`card`项目，因为我们已经知道它是什么。

为了测试牌的打出，我们现在只会从手牌中移除它。

1.  在`main.js`文件的主组件中创建一个名为`testPlayCard`的新临时方法：

```js
      methods: {
        // ...
        testPlayCard (card) {
          // Remove the card from player hand
          const index = this.testHand.indexOf(card)
          this.testHand.splice(index, 1)
        }
      },
```

1.  在主模板中的`hand`组件上添加`'card-play'`事件的事件侦听器：

```js
      <hand v-if="!activeOverlay" :cards="testHand" @card-play="testPlayCard" />
```

如果您点击一张卡片，它现在应该向手牌组件发出一个`'play'`事件，然后手牌组件将向主组件发出一个`'card-play'`事件。接着，它将从手牌中移除该卡片，使其消失。为了帮助您调试这种情况，开发工具有一个事件选项卡：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/32fa4cee-0203-43fe-b413-eafcccce1ea5.png)

# 为卡片列表添加动画

对于我们的手牌，有三个缺失的动画--当一张牌被添加或从玩家手牌中移除时，以及当它被移动时。当回合开始时，玩家会抽一张牌。这意味着我们将向手牌列表中添加一张牌，并且它将从右侧滑入手牌。当打出一张牌时，我们希望它上移并变大。

要为一系列元素添加动画，我们将需要另一个特殊的组件--`<transition-group>`。当它们被添加、移除和移动时，它会对子元素进行动画处理。在模板中，它看起来像这样：

```js
<transition-group>
  <div v-for="item of items" />
</transition-group>
```

与`<transition>`元素不同，过渡组在 DOM 中默认显示为一个`<span>`元素。您可以使用`tag`属性更改 HTML 元素：

```js
<transition-group tag="ul">
  <li v-for="item of items" />
</transition-group>
```

在我们`hand`组件的模板中，用一个过渡组件将卡片组件包起来，指定我们将调用的过渡的名称为`"card"`，并添加`"cards"` CSS 类：

```js
<transition-group name="card" tag="div" class="cards">
  <card v-for="card of cards" :def="card.def" @play="handlePlay(card) />
</transition-group>
```

在我们继续之前，还缺少一个重要的事情--过渡组的子元素必须通过唯一键来标识。

# 关键特殊属性

当 Vue 在`v-for`循环中更新 DOM 元素列表时，它会尽量减少应用于 DOM 的操作数量，如添加或移除元素。这是在大多数情况下更新 DOM 的非常高效的方法，可以提高性能。

为了做到这一点，Vue 会尽可能地重复使用元素，并且只在需要的地方打补丁来达到所需的结果。这意味着重复的元素将在原地打补丁，如果列表中添加或删除项，则不会被移动。然而，这也意味着如果我们对它们应用过渡，它们就不会发生动画。

以下是这样运作的示意图：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/607e2253-c68b-41da-89b6-689de2112ef8.png)

在这个示例中，我们移除了列表中的第三个项目，即`c`。然而，第三个`div`元素不会被销毁--它将会被重复利用，使用列表中的第四个项目`d`。实际上，这是第四个被销毁的`div`元素。

幸运的是，我们可以告诉 Vue 每个元素如何被识别，这样它就可以重复使用和重新排序它们。为了做到这一点，我们需要使用`key`特殊属性指定一个唯一标识。例如，我们的每个项目都可以有一个我们将用作关键字的唯一 ID：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/8daeec3d-58b6-44e3-a822-86c57e8e518b.png)

在这里，我们指定了关键字，以便 Vue 知道第三个`div`元素应该被销毁，第四个 div 元素应该被移动。

关键特殊属性的工作方式与标准属性类似，因此，如果我们想为其分配动态值，就需要使用`v-bind`指令。

回到我们的卡片，我们可以使用卡片上的唯一标识作为关键字：

```js
<card v-for="card of cards" :def="card.def" :key="card.uid" @play="handlePlay(card) />
```

现在，如果我们在 JavaScript 中添加、移动或删除一个卡片项，它将会在 DOM 中以正确的顺序体现出来。

# CSS 过渡

与之前一样，我们有以下六个可用的 CSS 类，以我们的组过渡名称`'card'`为前缀：`card-enter-active`, `card-enter`, `card-enter-to`, `card-leave-active`, `card-leave`, 和 `card-leave-to`。它们将被应用于组过渡的直接子元素，也就是我们的卡片组件。

1.  组过渡器中对于移动的元素有一个额外的类名--`v-move`。Vue 会使用 CSS 的`transform`属性来使它们移动，所以我们只需要为其应用至少带有持续时间的 CSS 过渡就行了：

```js
      .card-move {
        transition: transform .3s;
      }      
```

现在，当你点击卡片进行打出时，它应该消失，而其余的卡片将移动到它们的新位置。你也可以向手牌中添加卡片。

1.  在 Vue devtools 中选择主组件，并在浏览器控制台中执行以下内容：

```js
      state.testHand.push($vm.testDrawCard())
```

在 devtools 中选择一个组件会在浏览器控制台中公开它作为`$vm`。

就像我们对手牌做的那样，当卡片进入手牌时，我们也会为它们添加动画，当它们被打出时（因此离开手牌）。

1.  由于我们需要在卡片上始终以相同时机过渡多个 CSS 属性（除了在离开过渡期间），我们将刚刚写的`.card-move`规则改成这样：

```js
 .card {
        /* Used for enter, move and mouse over animations */
        transition: all .3s;
      }
```

1.  对于进入动画，请指定卡片的状态作为过渡的开始：

```js
 .card-enter {
        opacity: 0;
        /* Slide from the right */
        transform: scale(.8) translateX(100px);
      }
```

1.  离开动画需要更多规则，因为打出卡片的动画更复杂，涉及将卡片向上缩放：

```js
 .card-leave-active {
        /* We need different timings for the leave transition */
        transition: all 1s, opacity .5s .5s;
        /* Keep it in the same horizontal position */
        position: absolute !important;
        /* Make it painted over the other cards */
        z-index: 10;
        /* Unclickable during the transition */
        pointer-events: none;
      }

      .card-leave-to {
        opacity: 0;
        /* Zoom the card upwards */
        transform: translateX(-106px) translateY(-300px) scale(1.5);
      }
```

这就足以使你的卡片都正确地动画化。你可以尝试再次玩耍并添加卡片到手中，看看结果。

# 叠加层

我们需要的最后一个 UI 元素是叠加层。以下是其中的三个：

+   '新回合'叠加层在轮到当前玩家时显示当前玩家的名字。点击'新回合'玩家会切换到'上一回合'叠加层。

+   '上一回合'叠加层显示玩家之前对手做的事情。它显示以下内容之一：

    +   上一回合对手出的卡片

    +   提醒玩家他们的回合被跳过了

+   '游戏结束'叠加层显示玩家或两个玩家输掉时。它显示玩家的名字与短语“获胜”或“被击败”。点击'游戏结束'叠加层重新加载游戏。

所有这些叠加层有两个共同点--当用户点击它们时它们会执行某些操作，并且它们具有类似的布局设计。因此，我们应该在这里做得更聪明，结构化我们的组件以在合适的地方尽可能地重用代码。这里的想法是创建一个通用的叠加层组件，该组件将负责处理点击事件和布局以及三个特定的叠加层内容组件，用于我们需要的每个叠加层。

在开始之前，在`state.js`文件中的应用状态中添加一个新的`activeOverlay`属性：

```js
// The consolidated state of our app
var state = {
  // UI
  activeOverlay: null,
  // ...
}
```

这将保存当前显示的叠加层的名称，如果没有显示叠加层，则为`null`。

# 使用插槽进行内容分发

如果我们可以在主模板中的叠加层组件中放置内容，这将非常方便，就像这样：

```js
<overlay>
  <overlay-content-player-turn />
</overlay>
```

我们将在`overlay`组件中封装额外的布局和逻辑，同时仍然能够放置任何内容。这是通过一个特殊的元素--`<slot>`完成的。

1.  让我们创建我们的`overlay`组件，并加上两个`div`元素：

```js
 Vue.component('overlay', {
        template: `<div class="overlay">
          <div class="content">
            <!-- Our slot will be there -->
          </div>
        </div>`,
      })
```

1.  在`.overlay` div 上添加点击事件监听器，调用`handleClick`方法：

```js
      <div class="overlay" @click="handleClick">
```

1.  然后，在我们发出自定义`'close'`事件的地方添加上述方法：

```js
      methods: {
        handleClick () {
          this.$emit('close')
        },
      },
```

此事件将有助于知道何时在回合开始时从一个叠加层切换到下一个。

1.  现在，在`.content` div 中放置一个`<slot>`元素：

```js
      template: `<div class="overlay" @click="handleClick">
        <div class="content">
          <slot />
        </div>
      </div>`,
```

现在，如果我们在使用我们的组件时在`overlay`标签之间放置了一些内容，它将被包含在 DOM 中，并替换`<slot>`标签。例如，我们可以这样做：

```js
<overlay>
  Hello world!
</overlay>
```

另外，它将在页面中呈现如下：

```js
<div class="overlay">
  <div class="content">
    Hello world!
  </div>
</div>
```

它与任何内容一起使用，因此您也可以放置 HTML 或 Vue 组件，它仍将以相同的方式工作！

1.  该组件已准备好在主模板中使用，因此将其添加到最后：

```js
      <overlay>
        Hello world!
      </overlay>
```

这三个叠加层内容将是独立的组件：

+   `overlay-content-player-turn` 显示回合的开始

+   `overlay-content-last-play` 显示上一回合对手打出的最后一张卡片

+   `overlay-content-game-over`在游戏结束时显示

在深入研究这些内容之前，我们需要有关状态中两个玩家的一些更多数据。

1.  回到`state.js`文件，并为每个玩家添加以下属性：

```js
      // Starting stats
      food: 10,
      health: 10,
      // Is skipping is next turn
      skipTurn: false,
      // Skiped turn last time
      skippedTurn: false,
      hand: [],
      lastPlayedCardId: null,
      dead: false,
```

现在，你应该在`players`数组中有两个具有相同属性的项目，除了玩家名称。

# '玩家回合'叠加层

第一个叠加层将向当前玩家显示两条不同的消息，具体取决于是否跳过了他们的回合。玩家属性将接收当前玩家，以便我们可以访问其数据。我们将使用`v-if`指令与`v-else`指令和刚刚添加到玩家的`skipTurn`属性：

```js
 Vue.component('overlay-content-player-turn', {
        template: `<div>
          <div class="big" v-if="player.skipTurn">{{ player.name }},      <br>your turn is skipped!</div>
          <div class="big" v-else>{{ player.name }},<br>your turn has       come!</div>
          <div>Tap to continue</div>
        </div>`,
        props: ['player'],
      })
```

# '最后一次出牌'叠加层

这个比较复杂。我们需要一个新函数来获取玩家最后打出的卡片。在`utils.js`文件中，添加新函数`getLastPlayedCard`：

```js
function getLastPlayedCard (player) {
  return cards[player.lastPlayedCardId]
}
```

我们现在可以通过传递`opponent`prop 在`lastPlayedCard`计算属性中使用此函数：

```js
Vue.component('overlay-content-last-play', {
  template: `<div>
    <div v-if="opponent.skippedTurn">{{ opponent.name }} turn was skipped!</div>
    <template v-else>
      <div>{{ opponent.name }} just played:</div>
      <card :def="lastPlayedCard" />
    </template>
  </div>`,
  props: ['opponent'],
  computed: {
    lastPlayedCard () {
      return getLastPlayedCard(this.opponent)
    },
  },
})
```

请注意，我们是直接重用了之前创建的`card`组件来展示卡片。

# '游戏结束'叠加层

对于这个，我们将创建另一个组件，名为`player-result`，它将显示玩家是胜利还是失败。我们将通过一个 prop 传递玩家的名称。我们将使用计算属性为该玩家计算结果，并将其作为动态 CSS 类使用：

```js
Vue.component('player-result', {
  template: `<div class="player-result" :class="result">
    <span class="name">{{ player.name }}</span> is
    <span class="result">{{ result }}</span>
  </div>`,
  props: ['player'],
  computed: {
    result () {
      return this.player.dead ? 'defeated' : 'victorious'
    },
  },
})
```

现在，我们可以通过循环遍历`players`属性并使用`player-result`组件来创建游戏结束叠加层：

```js
Vue.component('overlay-content-game-over', {
  template: `<div>
    <div class="big">Game Over</div>
    <player-result v-for="player in players" :player="player" />
  </div>`,
  props: ['players'],
})
```

# 动态组件

现在，是时候将所有这些内容放入我们的叠加层组件中，并使用之前定义的`activeOverlay`属性。

1.  添加组件并在主模板中使用相应的`activeOverlay`值来显示它们：

```js
      <overlay v-if="activeOverlay">
        <overlay-content-player-turn
          v-if="activeOverlay === 'player-turn'" />
        <overlay-content-last-play
          v-else-if="activeOverlay === 'last-play'" />
        <overlay-content-game-over
          v-else-if="activeOverlay === 'game-over'" />
      </overlay>
```

如果`activeOverlay`属性等于`null`，我们将完全移除叠加层。

在添加 props 之前，我们将需要修改`state.js`文件中的应用程序状态，并添加一些 getter 函数。

1.  第一个将从`currentPlayerIndex`属性返回`player`对象：

```js
      get currentPlayer () {
        return state.players[state.currentPlayerIndex]
      },
```

1.  第二个将返回对手的`player`索引：

```js
      get currentOpponentId () {
        return state.currentPlayerIndex === 0 ? 1 : 0
      },
```

1.  最后，第三个将返回相应的玩家对象：

```js
      get currentOpponent () {
        return state.players[state.currentOpponentId]
      },
```

1.  现在，我们可以为叠加层内容添加 props：

```js
      <overlay v-if="activeOverlay">
        <overlay-content-player-turn
          v-if="activeOverlay === 'player-turn'"
          :player="currentPlayer" />
        <overlay-content-last-play
          v-else-if="activeOverlay === 'last-play'"
          :opponent="currentOpponent" />
        <overlay-content-game-over
          v-else-if="activeOverlay === 'game-over'"
          :players="players" />
      </overlay>
```

你可以通过在浏览器控制台中设置`activeOverlay`属性来测试这些叠加层：

```js
state.activeOverlay = 'player-turn'
state.activeOverlay = 'last-play'
state.activeOverlay = 'game-over'
state.activeOverlay = null
```

如果你想测试`last-play`叠加层，你需要为玩家的`lastPlayedCardId`属性指定一个有效的值，如`'catapult'`或`'farm'`。

我们的代码开始变得杂乱，在三个条件语句中。幸运的是，有一个特殊的组件可以将自身转换为任何组件 - 那就是`component`组件。只需将其`is`属性设置为组件名称，组件定义对象，甚至是 HTML 标签，它将变形为该组件：

```js
<component is="h1">Title</component>
<component is="overlay-content-player-turn" />
```

它就像任何其他的 prop 一样，所以我们可以使用`v-bind`指令来通过 JavaScript 表达式动态改变组件的本质。如果我们使用我们的`activeOverlay`属性来做到这一点会怎么样？我们的覆盖层内容组件是否方便地以相同的`'over-content-'`前缀命名？看一下：

```js
<component :is="'overlay-content-' + activeOverlay" />
```

就是这样。现在，通过改变`activeOverlay`属性的值，我们将改变覆盖层内显示的组件。

1.  在添加回 props 后，主模板中的覆盖层应该如下所示：

```js
      <overlay v-if="activeOverlay">
        <component :is="'overlay-content-' + activeOverlay"
          :player="currentPlayer" :opponent="currentOpponent"
          :players="players" />
      </overlay>
```

别担心，未使用的 props 不会影响不同覆盖层的工作方式。

# 覆盖层动画

就像我们用手做的那样，我们将使用过渡来动画显示覆盖层。

1.  在覆盖层组件周围添加一个名为“zoom”的过渡：

```js
      <transition name="zoom">
        <overlay v-if="activeOverlay">
          <component :is="'overlay-content-' + activeOverlay"                    
          :player="currentPlayer" :opponent="currentOpponent"                      
          :players="players" />
        </overlay>
      </transition>
```

1.  在`transition.css`文件中添加以下 CSS 规则：

```js
      .zoom-enter-active,
      .zoom-leave-active {
        transition: opacity .3s, transform .3s;
      }

      .zoom-enter,
      .zoom-leave-to {
        opacity: 0;
        transform: scale(.7);
      }
```

这是一个简单的动画，会在淡出的同时缩小覆盖层。

# 关键属性

现在，如果您在浏览器中尝试动画，它应该只在两种情况下起作用：

+   当您没有显示任何覆盖层，并且您设置了一个时

+   当您有一个显示的覆盖层，并且您将`activeOverlay`设置为`null`以隐藏它时

如果您在不同的覆盖层之间切换，动画将不起作用。这是由于 Vue 更新 DOM 的方式；正如我们在*关键特殊属性*部分中看到的那样，它将尽可能地重用 DOM 元素以优化性能。在这种情况下，我们需要使用关键特殊属性来向 Vue 发出提示，表明我们希望将不同的覆盖层视为单独的元素。因此，当我们从一个覆盖层过渡到另一个覆盖层时，两者都将存在于 DOM 中，并且可以播放动画。

让我们给我们的覆盖层组件添加键，这样 Vue 在更改`activeOverlay`值时将其视为多个单独的元素：

```js
<transition name="zoom">
  <overlay v-if="activeOverlay" :key="activeOverlay">
    <component :is="'overlay-content-' + activeOverlay" :player="currentPlayer" :opponent="currentOpponent" :players="players" />
  </overlay>
</transition>
```

现在，如果我们将`activeOverlay`设置为`'player-turn'`，覆盖层将具有键为`'player-turn'`。然后，如果我们将`activeOverlay`设置为`'last-play'`，将创建一个完全新的键为`'last-play'`的覆盖层，我们可以在两者之间进行过渡动画。您可以在浏览器中通过将不同的值设置为`state.activeOverlay`来尝试此操作。

# 覆盖层背景

此时，有些东西丢失了--覆盖层背景。我们不能将其包含在覆盖层组件内部，因为在动画期间它会被放大--这会非常尴尬。相反，我们将使用我们已经创建的简单`fade`动画。

在主模板中，在`zoom`过渡和`overlay`组件之前添加一个带有`overlay-background`类的新的`div`元素：

```js
<transition name="fade">
  <div class="overlay-background" v-if="activeOverlay" />
</transition>
```

使用`v-if`指令，只有在显示任何覆盖层时才会显示它。

# 游戏世界和场景

我们大部分完成了 UI 元素，所以现在我们可以进入游戏场景组件。我们将有一些新组件要做--玩家城堡，每个城堡都有一个健康和食物气泡，以及一些背景中的动画云，以增加乐趣。

在`components`文件夹中创建一个新的`world.js`文件，并在页面中包含它：

```js
<!-- ... -->
<script src="img/ui.js"></script>
<script src="img/world.js"></script>
<script src="img/main.js"></script>
```

让我们从城堡开始。

# 城堡们

这个实际上相当简单，因为它仅包含两个图像和一个城堡旗帜组件，主要负责显示健康和食物状态：

1.  在`world.js`文件中，创建一个新的城堡组件，其中包含接受`players`和`index`属性的两个图像：

```js
 Vue.component('castle', {
        template: `<div class="castle" :class="'player-' + index">
          <img class="building" :src="img/castle' + index + '.svg'" />
          <img class="ground" :src="img/ground' + index + '.svg'" />
          <!-- Later, we will add a castle-banners component here -->
        </div>`,
        props: ['player', 'index'],
      })
```

对于此组件，每个玩家有一个城堡和一个地面图像；这意味着总共有四幅图像。例如，对于索引为`0`的玩家，有`castle0.svg`和`ground0.svg`图像。

1.  在主模板中，在`top-bar`组件的正下方，创建一个具有`world` CSS 类的新`div`元素，循环遍历玩家以显示两座城堡，并添加另一个具有`land`类的`div`元素：

```js
      <div class="world">
        <castle v-for="(player, index) in players" :player="player"                 
         :index="index" />
        <div class="land" />
      </div>
```

在浏览器中，应该看到每个玩家的一个城堡，如下所示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/fb8e96b4-1277-46dd-b2e7-8fe28baddcad.png)

# 城堡旗帜

城堡旗帜将显示城堡的健康和食物。`castle-banners`组件内部将包含两个组件：

+   一个垂直的横幅，其高度根据状态的数量而变化

+   一个显示实际数字的气泡

它将看起来像这样：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/9673ab25-0535-4f51-a154-facc7e9087d3.png)

1.  首先，创建一个只包含状态图标和一个`player`属性的新`castle-banners`组件：

```js
 Vue.component('castle-banners', {
        template: `<div class="banners">
          <!-- Food -->
          <img class="food-icon" src="img/food-icon.svg" />
          <!-- Bubble here -->
          <!-- Banner bar here -->

          <!-- Health -->
          <img class="health-icon" src="img/health-icon.svg" />
          <!-- Bubble here -->
          <!-- Banner bar here -->
        </div>`,
        props: ['player'],
      })
```

1.  我们还需要两个计算属性来计算健康和食物比例：

```js
      computed: {
        foodRatio () {
          return this.player.food / maxFood
        },
        healthRatio () {
          return this.player.health / maxHealth
        },
      }
```

`maxFood`和`maxHealth`变量在`state.js`文件的开头定义。

1.  在`castle`组件中添加新的`castle-banners`组件：

```js
      template: `<div class="castle" :class="'player-' + index">
        <img class="building" :src="img/castle' + index + '.svg'" />
        <img class="ground" :src="img/ground' + index + '.svg'" />
        <castle-banners :player="player" />
      </div>`,
```

# 食物和健康气泡

此组件包含一个图像和一个显示城堡食物或健康当前数量的文本。其位置将根据此数量变化--当数量减少时会上升，而在重新补充时会下降。

对于这个组件，我们将需要三个属性：

+   `type`是食物或健康之一；它将用于 CSS 类和图像路径

+   `value`是在气泡中显示的数量

+   `ratio`是数量除以最大数量

我们还需要一个计算属性来计算气泡随`ratio`属性的垂直位置。位置将在 40 像素到 260 像素之间变化。因此，位置值由以下表达式给出：

```js
(this.ratio * 220 + 40) * state.worldRatio + 'px'
```

记得要用`worldRatio`值将每个位置或大小相乘，这样游戏才能考虑窗口大小（如果窗口更大，则它变大，反之亦然）。

1.  让我们编写我们的新`bubble`组件：

```js
 Vue.component('bubble', {
        template: `<div class="stat-bubble" :class="type + '-bubble'"               
        :style="bubbleStyle">
          <img :src="img/' + type + '-bubble.svg'" />
          <div class="counter">{{ value }}</div>
        </div>`,
        props: ['type', 'value', 'ratio'],
        computed: {
          bubbleStyle () {
            return {
              top: (this.ratio * 220 + 40) * state.worldRatio + 'px',
            }
          },
        },
      })
```

它有一个根`div`元素，具有`stat-bubble` CSS 类，以及一个动态类（根据`type`属性值，可以是`'food-bubble'`或`'health-bubble'`），再加上我们用`bubbleStyle`计算属性设置的动态 CSS 样式。

它包含一个 SVG 图像，食物和健康不一样，并且一个具有`counter`类的`div`元素显示数量。

1.  向`castle-banners`组件添加一个食物和一个健康气泡：

```js
      template: `<div class="banners">
        <!-- Food -->
        <img class="food-icon" src="img/food-icon.svg" />
        <bubble type="food" :value="player.food" :ratio="foodRatio" />
        <!-- Banner bar here -->

        <!-- Health -->
        <img class="health-icon" src="img/health-icon.svg" />
        <bubble type="health" :value="player.health"             
      :ratio="healthRatio" />
        <!-- Banner bar here -->
      </div>`,
```

# 横幅条

我们需要的另一个组件是挂在城堡塔楼上的垂直横幅。其长度将根据食物或健康的数量而变化。这一次，我们将创建一个动态 SVG 模板，以便我们可以修改横幅的高度。

1.  首先，使用两个属性（颜色和比例）和计算属性`height`创建组件：

```js
 Vue.component('banner-bar', {
        props: ['color', 'ratio'],
        computed: {
          height () {
            return 220 * this.ratio + 40
          },
        },
      })
```

到目前为止，我们以两种不同的方式定义了我们的模板——我们要么使用了我们页面的 HTML，要么将字符串设置为组件的`template`选项。我们将使用另一种编写组件模板的方法——在 HTML 中使用特殊的脚本标签。通过在此脚本标签内部编写带有唯一 ID 的模板，并在定义组件时引用此 ID，它的工作原理是。

1.  打开`banner-template.svg`文件，其中包含我们将用作动态模板的横幅图像的 SVG 标记。复制文件的内容。

1.  在`<div id="app">`元素后的`index.html`文件中，添加一个`script`标签，类型为`text/x-template`，并带有`banner`ID，然后粘贴`svg`内容：

```js
      <script type="text/x-template" id="banner">
        <svg viewBox="0 0 20 260">
          <path :d="`m 0,0 20,0 0,${height} -10,-10 -10,10 z`"                    
          :style="`fill:${color};stroke:none;`" />
        </svg>
      </script>
```

正如您所看到的，这是一个标准模板，具有可用于使用的所有语法和指令。在这里，我们两次使用了`v-bind`指令的缩写。请注意，您可以在所有 Vue 模板中使用 SVG 标记。

1.  现在，回到我们的组件定义中，添加`template`选项，并使用井号标记前面的脚本标签模板的 ID：

```js
      Vue.component('banner-bar', {
        template: '#banner',
        // ...
      })
```

完成！该组件现在将查找页面中带有`banner`ID 的脚本标签模板，并将其用作模板。

1.  在`castle-banners`组件中，使用相应的颜色和比例添加另外两个`banner-bar`组件：

```js
      template: `<div class="banners">
        <!-- Food -->
        <img class="food-icon" src="img/food-icon.svg" />
        <bubble type="food" :value="player.food" :ratio="foodRatio" />
        <banner-bar class="food-bar" color="#288339" :ratio="foodRatio"        
        />

        <!-- Health -->
        <img class="health-icon" src="img/health-icon.svg" />
        <bubble type="health" :value="player.health"                   
        :ratio="healthRatio" />
        <banner-bar class="health-bar" color="#9b2e2e"                         
       :ratio="healthRatio" />
      </div>`,
```

现在，您应该能够看到悬挂在城堡上的横幅，并且如果您更改食物和健康值，则它们会收缩。

# 动画化数值

如果我们可以在它们收缩或扩展时对它们进行动画处理，这些横幅会更漂亮。我们不能依赖于 CSS 过渡，因为我们需要动态更改 SVG 路径，所以我们需要另一种方式——我们将动画化模板中使用的`height`属性的值。

1.  首先，让我们将模板的计算属性重命名为`targetHeight`：

```js
      computed: {
        targetHeight () {
          return 220 * this.ratio + 40
        },
      },
```

`targetHeight`属性将在比例变化时仅计算一次。

1.  添加一个新的`height`数据属性，我们将能够在`targetHeight`更改时对其进行动画处理：

```js
 data () {
        return {
          height: 0,
        }
      },
```

1.  在组件创建后，在`created`钩子中将`height`的值初始化为`targetHeight`的值：

```js
 created () {
        this.height = this.targetHeight
      },
```

为了使高度值动画化，我们将使用流行的`**TWEEN.js**`库，该库已经包含在`index.html`文件中。该库通过创建一个新的`Tween`对象来工作，该对象采用起始值、缓动函数和结束值。它提供了诸如`onUpdate`之类的回调，我们将使用这些回调来更新动画的`height`属性。

1.  我们希望在`targetHeight`属性更改时启动动画，因此添加一个带有以下动画代码的监视程序：

```js
 watch: {
        targetHeight (newValue, oldValue) {
          const vm = this
          new TWEEN.Tween({ value: oldValue })
            .easing(TWEEN.Easing.Cubic.InOut)
            .to({ value: newValue }, 500)
            .onUpdate(function () {
              vm.height = this.value.toFixed(0)
            })
            .start()
        },
      },
```

`onUpdate` 回调中的 `this` 上下文是 `Tween` 对象，而不是 Vue 组件实例。这就是为什么我们需要一个好的临时变量来保存组件实例 `this`（这里，`vm` 变量就是那个）。

1.  我们需要最后一件事来使我们的动画工作。在 `main.js` 文件中，请求浏览器从浏览器请求绘画帧以使 `TWEEN.js` 库滴答作响，感谢浏览器的 `requestAnimationFrame` 函数：

```js
      // Tween.js
      requestAnimationFrame(animate);

      function animate(time) {
        requestAnimationFrame(animate);
        TWEEN.update(time);
      }
```

如果标签在后台，则 `requestAnimationFrame` 函数将等待标签再次变为可见。这意味着如果用户看不到页面，动画将不会播放，从而节省计算机资源和电池电量。请注意，CSS 过渡和动画也是如此。

现在当你改变玩家的食物或健康状态时，横幅将逐渐缩小或增大。

# 动态云

为了为游戏世界增添一些生气，我们将创建一些在天空中滑动的云。它们的位置和动画持续时间将是随机的，它们将从窗口的左侧移动到右侧。

1.  在 `world.js 文件` 中，添加云动画的最小和最大持续时间：

```js
      const cloudAnimationDurations = {
        min: 10000, // 10 sec
        max: 50000, // 50 sec
      }
```

1.  然后，创建云组件，包括图像和 `type` 属性：

```js
 Vue.component('cloud', {
        template: `<div class="cloud" :class="'cloud-' + type" >
          <img :src="img/strong> + '.svg'" />
        </div>`,
        props: ['type'],
      })
```

将有五个不同的云，因此 `type` 属性将从 1 到 5。

1.  我们将需要使用一个响应式的 `style` 数据属性来更改组件的 `z-index` 和 `transform` CSS 属性：

```js
 data () {
        return {
          style: {
            transform: 'none',
            zIndex: 0,
          },
        }
      },
```

1.  使用 `v-bind` 指令应用这些样式属性：

```js
      <div class="cloud" :class="'cloud-' + type" :style="style">
```

1.  让我们创建一个方法来使用 `transform` CSS 属性设置云组件的位置：

```js
      methods: {
        setPosition (left, top) {
          // Use transform for better performance
          this.style.transform = `translate(${left}px, ${top}px)`
        },
      }
```

1.  当图片加载时，我们需要初始化云的水平位置，使其位于视口之外。创建一个新的 `initPosition`，它使用 `setPosition` 方法：

```js
      methods: {
        // ...
        initPosition () {
          // Element width
          const width = this.$el.clientWidth
          this.setPosition(-width, 0)
        },
      }
```

1.  在图像上添加一个事件监听器，使用 `v-on` 指令缩写监听 `load` 事件并调用 `initPosition` 方法：

```js
      <img :src="img/cloud' + type + '.svg'" @load="initPosition" />
```

# 动画

现在，让我们继续进行动画本身。就像我们为城堡横幅所做的那样，我们将使用 `TWEEN.js` 库：

1.  首先，创建一个新的 `startAnimation` 方法，计算一个随机的动画持续时间，并接受一个延迟参数：

```js
      methods: {
        // ...

        startAnimation (delay = 0) {
          const vm = this

          // Element width
          const width = this.$el.clientWidth

          // Random animation duration
          const { min, max } = cloudAnimationDurations
          const animationDuration = Math.random() * (max - min) + min

          // Bing faster clouds forward
          this.style.zIndex = Math.round(max - animationDuration)

          // Animation will be there
        },
      }
```

云越快，其动画持续时间就越低。更快的云将在较慢的云之前显示，这要归功于 `z-index` CSS 属性。

1.  在 `startAnimation` 方法内部，计算云的随机垂直位置，然后创建一个 `Tween` 对象。它将以延迟动画水平位置，并在每次更新时设置云的位置。当它完成时，我们将以随机延迟启动另一个动画：

```js
      // Random position
      const top = Math.random() * (window.innerHeight * 0.3)

      new TWEEN.Tween({ value: -width })
        .to({ value: window.innerWidth }, animationDuration)
        .delay(delay)
        .onUpdate(function () {
          vm.setPosition(this.value, top)
        })
        .onComplete(() => {
          // With a random delay
          this.startAnimation(Math.random() * 10000)
        })
        .start()
```

1.  在组件的 `mounted` 钩子中，调用 `startAnimation` 方法开始初始动画（带有随机延迟）：

```js
 mounted () {
        // We start the animation with a negative delay
        // So it begins midway
        this.startAnimation(-Math.random() *                   
      cloudAnimationDurations.min)
      },
```

我们的云组件已准备好。

1.  在 `world` 元素的主模板中添加一些云：

```js
      <div class="clouds">
        <cloud v-for="index in 10" :type="(index - 1) % 5 + 1" />
      </div>
```

要小心将值传递给 `type` 属性，其取值范围为 1 到 5。在这里，我们使用 `%` 运算符来返回 5 的除法余数。

它应该是这样的：

![图片](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/52782d12-755c-4eb2-bbe8-811741339acf.png)

# 游戏过程

所有的组件都完成了！ 我们只需要为应用添加一些游戏逻辑，使其可玩。 游戏开始时，每个玩家都会抽取他们的初始手牌。

然后，每个玩家的回合都按照以下步骤进行：

1.  `player-turn`覆盖层显示，以便玩家知道轮到他们了。

1.  `last-play`覆盖层显示了上次游戏中另一位玩家打出的牌。

1.  玩家通过点击卡片来出牌。

1.  卡片从他们的手中移除，并应用其效果。

1.  我们稍等一下，以便玩家可以看到这些效果的发生。

1.  然后，回合结束，并将当前玩家切换到另一个玩家。

# 抽牌

在抽牌之前，我们需要在`state.js`文件中的应用状态中添加两个属性：

```js
var state = {
  // ...
  drawPile: pile,
  discardPile: {},
}
```

`drawPile`属性是玩家可以抽取的牌堆。 它使用在`cards.js`文件中定义的`pile`对象进行初始化。 每个键都是卡片定义的 ID，值是此类型卡片在堆叠中的数量。

`discardPile`属性是`drawPile`属性的等价物，但它有不同的用途--玩家打出的所有卡片都将从他们的手中移除并放入弃牌堆中。 在某个时刻，如果抽牌堆为空，它将被弃牌堆重新填充（弃牌堆将被清空）。

# 初始手牌

游戏开始时，每个玩家都会抽取一些牌。

1.  在`utils.js`文件中，有一个函数用于抽取玩家的手牌：

```js
      drawInitialHand(player)
```

1.  在`main.js`文件中，添加一个调用`drawInitialHand`函数为每个玩家发牌的新的`beginGame`函数：

```js
      function beginGame () {
        state.players.forEach(drawInitialHand)
      }
```

1.  当应用准备就绪时，在`main.js`文件中我们的主组件的`mounted`钩子内调用此函数：

```js
 mounted () {
        beginGame()
      },
```

# 手牌

要显示当前玩家手中的卡片，我们需要在应用状态中添加一个新的 getter：

1.  在`state.js`文件中的`state`对象中添加`currentHand`的 getter：

```js
      get currentHand () {
        return state.currentPlayer.hand
      },
```

1.  我们现在可以在主模板中删除`testHand`属性，并用`currentHand`替换它： 

```js
      <hand v-if="!activeOverlay" :cards="currentHand" @card-            
      play="testPlayCard" />
```

1.  你也可以移除`main`组件上为测试目的编写的`createTestHand`方法和这个`created`钩子：

```js
      created () {
        this.testHand = this.createTestHand()
      },
```

# 出牌

出牌分为以下三个步骤：

1.  我们将卡片从玩家手中移除并将其添加到堆叠中。 这会触发卡片动画。

1.  我们等待卡片动画完成。

1.  我们应用卡片的效果。

# 不允许作弊

在游戏中，不应允许作弊。 在编写游戏逻辑时，我们应该记住这一点：

1.  让我们首先在`state.js`文件中的应用状态中添加一个新的`canPlay`属性：

```js
      var state = {
        // ...
        canPlay: false,
      }
```

这将阻止玩家在他们的回合中重复出牌--我们有很多动画和等待，所以我们不希望他们作弊。

我们将在玩家出牌时使用它来检查他们是否已经出过牌，并且还将在 CSS 中使用它来禁用手牌上的鼠标事件。

1.  因此，在主组件中添加一个 `cssClass` 计算属性，如果 `canPlay` 属性为真，则添加 `can-play` CSS 类：

```js
      computed: {
        cssClass () {
          return {
            'can-play': this.canPlay,
          }
        },
      },
```

1.  并在主模板的根 `div` 元素上添加一个动态 CSS 类：

```js
      <div id="#app" :class="cssClass">
```

# 从手牌中移除卡牌

当卡牌被打出时，它应该从当前玩家手中移除；按照以下步骤执行：

1.  在 `main.js` 文件中创建一个新的 `playCard` 函数，接受一张卡牌作为参数，检查玩家是否可以打出卡牌，然后将卡牌从手牌中移除，放入弃牌堆中使用 `utils.js` 文件中定义的 `addCardToPile` 函数：

```js
      function playCard (card) {
        if (state.canPlay) {
          state.canPlay = false
          currentPlayingCard = card

          // Remove the card from player hand
          const index = state.currentPlayer.hand.indexOf(card)
          state.currentPlayer.hand.splice(index, 1)

          // Add the card to the discard pile
          addCardToPile(state.discardPile, card.id)
        }
      }
```

我们将玩家打出的卡牌存储在 `currentPlayingCard` 变量中，因为我们稍后需要应用其效果。

1.  在主组件中，用一个新的 `handlePlayCard` 方法替换 `testPlayCard` 方法，调用 `playCard` 函数：

```js
      methods: {
        handlePlayCard (card) {
          playCard(card)
        },
      },
```

1.  别忘了在主模板中更改对 `hand` 组件的事件监听器：

```js
      <hand v-if="!activeOverlay" :cards="currentHand" @card- 
 play="handlePlayCard" />
```

# 等待卡牌过渡结束

当卡牌被打出时，也就是从手牌列表中移除时，它会触发一个离开动画。我们希望在继续之前等待它完成。幸运的是，`transition` 和 `transition-group` 组件会发出事件。

我们这里需要的是 `'after-leave'` 事件，但是每个转换阶段都对应着其他事件——`'before-enter'`、`'enter'`、`'after-enter'`等。

1.  在 `hand` 组件中，添加一个 `'after-leave'` 类型的事件监听器：

```js
      <transition-group name="card" tag="div" class="cards" @after- 
 leave="handleLeaveTransitionEnd">
```

1.  创建相应的方法，向主模板发出 `'card-leave-end'` 事件：

```js
      methods: {
        // ...
        handleLeaveTransitionEnd () {
          this.$emit('card-leave-end')
        },
      },
```

1.  在主模板中，在 `hand` 组件上添加一个 `'card-leave-end'` 类型的新事件监听器：

```js
      <hand v-if="!activeOverlay" :cards="currentHand" @card-                
      play="handlePlayCard" @card-leave-end="handleCardLeaveEnd" />
```

1.  创建相应的方法：

```js
      methods: {
        // ...

        handleCardLeaveEnd () {
          console.log('card leave end')
        },
      }
```

我们稍后会编写它的逻辑。

# 应用卡牌效果

动画播放后，将为玩家应用卡牌效果。例如，它可能增加当前玩家的食物量或减少对手的生命值。

1.  在 `main.js` 文件中，添加使用 `utils.js` 文件中定义的 `applyCardEffect` 的 `applyCard` 函数：

```js
      function applyCard () {
        const card = currentPlayingCard

        applyCardEffect(card)
      }
```

然后，我们将等待一段时间，以便玩家能够看到效果被应用，并了解正在发生的事情。然后，我们将检查至少有一名玩家是否已死亡以结束游戏（借助 `utils.js` 中定义的 `checkPlayerLost` 函数），或者继续下一回合。

1.  在 `applyCard` 函数中，添加以下相应逻辑：

```js
      // Wait a bit for the player to see what's going on
      setTimeout(() => {
        // Check if the players are dead
        state.players.forEach(checkPlayerLost)

        if (isOnePlayerDead()) {
          endGame()
        } else {
          nextTurn()
        }
      }, 700)
```

1.  现在，就在 `applyCard` 函数之后添加空的 `nextTurn` 和 `endGame` 函数：

```js
      function nextTurn () {
        // TODO
      }

      function endGame () {
        // TODO
      }
```

1.  现在我们可以在主组件中修改 `handleCardLeaveEnd` 方法，调用我们刚刚创建的 `applyCard` 函数：

```js
      methods: {
        // ...

        handleCardLeaveEnd () {
          applyCard()
        },
      }
```

# 下一个回合

`nextTurn` 函数非常简单——我们将回合计数器增加一，更改当前玩家，并显示玩家回合覆盖层。

将相应的代码添加到 `nextTurn` 函数中：

```js
function nextTurn () {
  state.turn ++
  state.currentPlayerIndex = state.currentOpponentId
  state.activeOverlay = 'player-turn'
}
```

# 新的回合

在覆盖层之后，回合开始时我们还需要一些逻辑：

1.  首先是`newTurn`函数，它隐藏了任何活动的叠加层；它要么跳过当前玩家的回合，因为有一张卡片，要么开始回合：

```js
      function newTurn () {
        state.activeOverlay = null
        if (state.currentPlayer.skipTurn) {
          skipTurn()
        } else {
          startTurn()
        }
      }
```

如果玩家的`skipTurn`属性为 true，那么他们的回合将被跳过——这个属性将由一些卡片设置。他们还有一个`skippedTurn`属性，我们需要在`last-play`叠加层中向下一个玩家显示，告诉他们对手已经跳过了上一回合。

1.  创建`skipTurn`函数，将`skippedTurn`设置为`true`，将`skipTurn`属性设置为`false`并直接进入下一轮：

```js
      function skipTurn () {
        state.currentPlayer.skippedTurn = true
        state.currentPlayer.skipTurn = false
        nextTurn()
      }
```

1.  创建`startTurn`函数，它重置了玩家的`skippedTurn`属性，并使他们在第二轮时抽一张卡片（这样他们每回合开始时都有五张卡片）：

```js
      function startTurn () {
        state.currentPlayer.skippedTurn = false
        // If both player already had a first turn
        if (state.turn > 2) {
          // Draw new card
          setTimeout(() => {
            state.currentPlayer.hand.push(drawCard())
            state.canPlay = true
          }, 800)
        } else {
          state.canPlay = true
        }
      }
```

就在这一刻，我们可以使用`canPlay`属性允许玩家打出一张卡片。

# 叠加关闭动作

现在，我们需要处理当用户点击每个叠加层时触发的动作。我们将创建一个映射，键为叠加层类型，值为触发动作时调用的函数。

1.  将其添加到`main.js`文件中：

```js
      var overlayCloseHandlers = {
        'player-turn' () {
          if (state.turn > 1) {
            state.activeOverlay = 'last-play'
          } else {
            newTurn()
          }
        },

        'last-play' () {
          newTurn()
        },
        'game-over' () {
          // Reload the game
          document.location.reload()
        },
      }
```

对于玩家回合叠加层，只有在第二轮或更多轮时才切换到`last-play`叠加层，因为在第一轮开始时，对手不会打出任何卡片。

1.  在主组件中，添加`handleOverlayClose`方法，该方法调用与当前活动叠加层对应的动作函数，并传入`activeOverlay`属性：

```js
      methods: {
        // ...
        handleOverlayClose () {
          overlayCloseHandlers[this.activeOverlay]()
        },
      },
```

1.  在叠加层组件上，添加一个`'close'`类型的事件侦听器，当用户点击叠加层时触发：

```js
      <overlay v-if="activeOverlay" :key="activeOverlay"                  
      @close="handleOverlayClose">
```

# 游戏结束！

最后，在`endGame`函数中将`activeOverlay`属性设置为`'game-over'`：

```js
function endGame () {
  state.activeOverlay = 'game-over'
}
```

如果至少有一个玩家死亡，这将显示`game-over`叠加层。

# Summary

我们的纸牌游戏结束了。我们看到了 Vue 提供的许多新功能，使我们能够轻松创建丰富和交互式的体验。然而，在本章中介绍和使用的最重要的一点是基于组件的 Web 应用程序开发方法。这有助于我们通过将前端逻辑拆分为小型、隔离和可重用的组件来开发更大的应用程序。我们介绍了如何使组件彼此通信，从父组件到子组件使用 props，从子组件到父组件使用自定义事件。我们还为游戏添加了动画和过渡（使用`<transition>`和`<transition-group>`特殊组件），使其更加生动。我们甚至在模板中操纵了 SVG，并使用特殊的`<component>`组件动态显示了一个组件。

在下一章中，我们将使用 Vue 组件文件等其他功能来设置一个更高级的应用程序，这些功能将帮助我们构建更大的应用程序。
