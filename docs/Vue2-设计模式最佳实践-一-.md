# Vue2 设计模式最佳实践（一）

> 原文：[`zh.annas-archive.org/md5/6E739FB94554764B9B3B763043E30DA8`](https://zh.annas-archive.org/md5/6E739FB94554764B9B3B763043E30DA8)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

Vue.js 是一个允许您创建高性能 Web 应用程序的 JavaScript 框架。它比竞争对手拥有更小的学习曲线，并且具有详细的文档，其中包含各种示例和用例。Vue.js 应用程序可以使用 Vue CLI 创建，也可以通过`script`标签将其包含在页面中，因此在没有构建系统的项目中使用非常简单。

与其他现代 Web 框架/库类似，Vue.js 是组件驱动的，这意味着您可以创建具有自己视图/数据逻辑的自包含单元。这使得我们的应用程序可以随着规模的扩大而扩展，因为任何更改都可以从彼此中封装起来。

在扩展应用程序时，状态管理是前端领域的热门话题，Vue.js 通过`Vuex`库解决了这个问题。这使我们能够在应用程序中定义操作并相应地行事，为我们提供可预测的状态，可用于构建用户界面和其他交互的基础。

本书探讨了所有这些内容，还提供了如何将这些原则应用于新旧 Vue.js 应用程序的示例。

# 这本书适合谁

这本书适合有兴趣使用 JavaScript 创建 Web 和移动应用程序的人。具有 HTML5/ES2015 的先验经验将有所帮助，因为本书中使用了现代 JavaScript 概念。您可能希望利用这些知识在个人项目或工作角色中创建交互式基于 Web 的体验。

# 本书涵盖的内容

第一章，*Vue.js 原理和比较*，向读者介绍了 Vue.js，并激励他们将其用作创建 Web 应用程序的框架。读者将了解 Vue.js 与其他流行框架（如 React 和 Angular）之间的区别。

第二章，*Vue 项目的正确创建*，探讨了创建 Vue 项目的适当方式。这包括使用 Webpack、Babel/TypeScript（用于 ES6）、`.vue`文件、linting 等。

第三章《使用 Vue 编写干净、精简的代码》深入研究了 Vue.js 实例和不同的保留属性，如`data`、`computed`和`watch`，以及创建 getter 和 setter。本章特别考虑了何时使用计算属性和何时使用观察属性。它还概述了为什么模板应该特别精简以便更容易维护。

第四章《Vue.js 指令》介绍了开发人员在编写响应式 Vue 应用程序时可以访问一组强大指令，如`v-for`、`v-if`、`v-model`等。本章详细介绍了每个指令，以及最佳实践和模式。此外，读者还将介绍使用事件绑定的简写语法。

第五章《使用 Vue.js 组件进行安全通信》更深入地研究了 Vue 组件，包括组件通信。我们将研究传递属性，以及验证属性类型和考虑不同类型的属性和数据流。

第六章《创建更好的 UI》着重介绍了 Vue 的常见 UI 模式。它再次介绍了如何使用`v-model`从用户那里获取输入，以及绑定到文本、复选框、单选按钮等输入的方法。还介绍了下拉框和动态输入。最后，本章涵盖了表单提交和各种修饰符，如惰性绑定、数字类型转换和字符串修剪。

第七章《HTTP 和 WebSocket 通信》介绍了将 HTTP 整合到 Vue.js 应用程序的最佳实践。它介绍了`Axios`以及发送 HTTP 请求的各种方法（即`根实例/组件/导航守卫`）。本章还介绍了使用`socket.io`，以及创建用于实时集成的基本 Node/Express API。

第八章《Vue 路由模式》描述了路由是任何 SPA 的重要组成部分。本章重点介绍了 Vue 路由，并探讨了如何在多个页面之间进行路由。它涵盖了从匹配路径和组件到使用导航参数、正则表达式等动态匹配的所有内容。

第九章，*使用 Vuex 进行状态管理*，演示了使用 Vuex 进行状态管理。首先介绍了 Flux 架构和单向数据流。然后，它介绍了 Vuex，这是 Vue 的状态管理系统。本章还讨论了在应用程序中实现这一点，以及常见的陷阱和使用模式。它还介绍了`Vue-devtools`来捕获操作和 Vue 实例数据。

第十章，*测试 Vue.js 应用程序*，展示了测试是任何项目的重要部分，无论是哪种框架或语言。本章将讨论如何测试我们的应用程序以及如何编写可测试的代码。然后，我们将使用 Jasmine 和 Karma 测试我们的应用程序，以及在测试 mutations 时测试我们的 Vuex 代码。

第十一章，*优化*，概述了部署 Vue 应用程序和任何潜在的性能优化。然后，它介绍了将应用程序转换为**渐进式 Web 应用程序**（**PWA**）并添加`ServiceWorkers`、离线支持等。它还探讨了减少整体捆绑大小的方法，以及使用 SVG 获得性能优势。

第十二章，*使用 Nuxt 进行服务器端渲染*，展示了使用 Nuxt 创建服务器端渲染的 Vue 应用程序。该项目将使用 Vue CLI 创建，并且我们将从配置到路由、中间件和测试 Nuxt，一直到部署都会进行讨论。

第十三章，*模式*，帮助读者避免编写 Vue.js 应用程序时的常见反模式。提出了一份样式指南，以及关键问题，如使用`$parent`、`$ref`耦合问题、内联表达式等。

# 为了充分利用本书

1.  您应该已经了解并掌握 JavaScript（ES2015+）、HTML5 和 CSS3。

1.  本书不需要具备 Vue.js 的经验，尽管有其他 JavaScript 框架的经验将有助于比较和类似功能。

# 下载示例代码文件

您可以从[www.packtpub.com](http://www.packtpub.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，可以访问[www.packtpub.com/support](http://www.packtpub.com/support)并注册，以便文件直接发送到您的邮箱。

您可以按照以下步骤下载代码文件：

1.  在[www.packtpub.com](http://www.packtpub.com/support)登录或注册。

1.  选择“支持”选项卡。

1.  单击“代码下载和勘误”。

1.  在搜索框中输入书名，然后按照屏幕上的说明操作。

下载文件后，请确保使用以下最新版本的软件解压或提取文件夹：

+   WinRAR/7-Zip 适用于 Windows

+   Zipeg/iZip/UnRarX 适用于 Mac

+   7-Zip/PeaZip 适用于 Linux

该书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Vue.js-2-Design-Patterns-and-Best-Practices`](https://github.com/PacktPublishing/Vue.js-2-Design-Patterns-and-Best-Practices)。

我们还有来自丰富图书和视频目录的其他代码包，可在**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**上找到。去看看吧！

# 下载彩色图片

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图片。您可以在这里下载：[`www.packtpub.com/sites/default/files/downloads/Vuejs2DesignPatternsandBestPractices_ColorImages.pdf.`](https://www.packtpub.com/sites/default/files/downloads/Vuejs2DesignPatternsandBestPractices_ColorImages.pdf)

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。例如："将下载的`WebStorm-10*.dmg`磁盘映像文件挂载为系统中的另一个磁盘。"

代码块设置如下：

```js
// my-module.js
export default function add(x, y) {
 return x + y
}
```

任何命令行输入或输出都以以下方式编写：

```js
$ npm install
$ npm run dev
```

**粗体**：表示新术语、重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会以这种方式出现在文本中。例如："从管理面板中选择系统信息。"

警告或重要说明会以这种方式出现。提示和技巧会以这种方式出现。


# 第一章：Vue.js 的原则和比较

在本章中，我们将探讨为什么 Vue 是一个重要的 Web 开发框架，以及如何设置我们的开发环境。如果我们打算在下一个项目中使用 Vue，重要的是我们意识到这样做的影响、时间投资和学习曲线。您将考虑 Vue 与其他前端开发项目的对比，以及使用 Vue 创建您的第一个应用程序。

总之，我们将考虑以下几点：

+   下载书籍先决条件

+   了解 Vue 在前端框架中的定位

+   为什么您应该考虑将 Vue 作为下一个项目的框架

+   调查 Vue 的灵活性及其在移动开发中的作用

# 先决条件

尽管你可以在没有 Node 的情况下开发 Vue 应用程序，但我们将在本书中始终使用 Node.js 来管理依赖关系并与 Vue **命令行界面** (**CLI**) 交互。这使我们能够更快地启动项目，并且可以默认使用 ECMAScript 2015，从而为我们提供更好的开发体验。让我们快速回顾一下如何设置开发环境。

# Windows

在 Windows 上安装 Node 就像访问[`nodejs.org`](https://nodejs.org/)并下载最新版本一样简单。确保在按照安装步骤时选择 Add to PATH，这样我们就可以在终端中访问 node 命令。

完成后，通过输入`node -v`和`npm -v`来检查 Node 安装是否成功。如果你得到两个版本号（即每个版本一个），那么你就可以继续进行本书的其余部分了！

# Mac

在 Mac 上安装 Node 需要比简单地从 Node 网站下载安装程序更多的工作。虽然可以使用来自[`nodejs.org`](https://nodejs.org/)的安装程序，但由于需要`sudo`，不建议这样做。

如果我们这样做，我们将不得不在所有的`npm`命令前加上`sudo`，这可能会使我们的系统容易受到潜在的脚本攻击，并且不方便。相反，我们可以通过 Homebrew 软件包管理器安装 Node，然后我们可以与`npm`交互，而不必担心必须以`sudo`身份运行事务。

使用 Homebrew 安装 Node 的另一个好处是它会自动添加到我们的 PATH 中。这意味着我们将能够在不必费力地调整我们的环境文件的情况下输入 node 命令。

# 通过 Homebrew 安装 Node

获取 Homebrew 的最快方法是访问[`brew.sh`](http://brew.sh/)并获取安装脚本。它应该看起来有点像这样：

```js
/usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
```

只需将其粘贴到您的终端中，它将下载 Homebrew 软件包管理器到您的 Mac 上。然后我们可以使用 brew install node 在系统上安装 Node 而不必担心任何问题。

完成后，通过输入`node -v`和`npm -v`来检查您的 Node 安装是否正常工作。如果您得到两个版本号（即每个版本一个），那么您就可以继续阅读本书的其余部分了！

为了管理不同的 Node 版本，我们还可以安装**Node Version Manager**（**NVM**）。但请注意，目前仅 Mac 支持此功能，不支持 Windows。要安装 NVM，我们可以使用 Homebrew，就像这样：

```js
--use Brew to install the NVM
brew install nvm

--File directory
mkdir ~/.nvm

--Install latest version
nvm install --lts

--Ensure latest version is used
nvm use node

--Remember details across sessions
nano ~/.bash_profile

--Execute in every session
export NVM_DIR="$HOME/.nvm"
 . "$(brew --prefix nvm)/nvm.sh"
```

# 编辑器

可以使用各种编辑器，如 Visual Studio Code，Sublime Text，Atom 和 WebStorm。我推荐使用 Visual Studio Code ([`code.visualstudio.com`](https://code.visualstudio.com))，因为它有频繁的发布周期和丰富的 Vue 扩展，可以用来改善我们的工作流程。

# 浏览器

我们将使用 Google Chrome 来运行我们的项目，因为它有一个名为 Vue devtools 的扩展，对我们的开发工作流程至关重要。如果您不使用 Google Chrome，请确保您的浏览器具有可供使用的相同 Vue devtools 扩展。

# 安装 Vue devtools

前往 Google Chrome 扩展商店并下载 Vue.js devtools ([`goo.gl/Sc3YU1`](https://goo.gl/Sc3YU1))。安装后，您将可以在开发者工具中访问 Vue 面板。在下面的示例中，我们能够看到 Vue 实例中的数据对象：

```js
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-     
  scale=1.0">
  <meta http-equiv="X-UA-Compatible" content="ie=edge">
  <title>Vue.js</title>
</head>
<body>
  <div id="app"></div>
  <script src="http://unpkg.com/vue"></script>
  <script>
   Vue.config.devtools = true
   new Vue({
     el: '#app',
     data: {
       name: 'Vue.js Devtools',
       browser: 'Google Chrome'
     },
     template: `
      <div>
        <h1> I'm using {{name}} with {{browser}}</h1>
      </div>
     `
   });
  </script>
</body>
</html>
```

然后，我们转到浏览器并打开开发工具，我们可以看到 Vue 已被检测到，并且我们的消息已经输出到屏幕上：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/1154a7c6-8c1c-461f-89a9-b86d0c9e7e79.png)

我们将在整本书中使用它来更深入地了解我们的应用程序。请注意，开发者工具只会在本地服务器上提供 Vue 项目时才能识别您的 Vue 项目。

# Vue CLI

为了充分利用 Vue 的所有功能，我们将使用 Vue CLI。这使我们能够使用各种起始模板创建项目，并具有适当的捆绑/转译配置。在确保安装了 Node 的情况下，将以下内容输入到您的终端中：

```js
$ npm install vue-cli -g
```

这为我们未来的章节做好了准备，使用起始模板显著增强了我们的工作流程。

# Vue.js 的比较

本书旨在概述如何使用常见的开发模式、最佳实践和要避免的反模式来最佳地构建 Vue 应用程序。

我们的旅程始于看看 Vue 与其他常见项目的比较，如果你通过 GitHub 星标来衡量你的框架，Vue 显然是未来的赢家。根据[`bestof.js.org`](https://bestof.js.org)，2017 年它的每日星标数目为 114，而 React 为 76，Angular 为 32。

谈论现代 Web 开发技术时，对框架的讨论是一个有趣的话题。很少能找到一个真正客观的比较...但没关系！重点不在于哪个框架或库最好，而在于什么对你的团队、项目目标、消费者以及其他数百个变量最好。作为一个 Vue 开发者，你可能是一个想要用简单、易于使用的 API 构建响应式 Web 应用的人。

正是这种适应性强、易于使用的 API 使得 Vue 很愉快地使用，也许 Vue 最强大的地方之一就是简单而专注的文档。它的门槛非常低：只需从 CDN 添加一个脚本文件，初始化一个新的 Vue 实例...然后你就可以开始了！当然，Vue 比这更复杂得多，但与一些完整的框架如 Angular 相比，你可能会原谅自己认为它是如此简单。

Vue 使用模板、声明式绑定和基于组件的架构来分离关注点，使项目更易于维护。当考虑在企业内部使用哪个框架时，这变得尤为重要。通常情况下，这就是 Angular 等项目的闪光之处，因为它能够在整个项目中强制执行标准。

我们已经确定它很容易使用，但是与竞争对手相比，Vue 还很年轻...我们怎么知道这不全是炒作呢？有人在生产中使用它吗？当然有！GitLab 最近写了一篇关于他们为什么选择 Vue.js 的文章（[`about.gitlab.com/2016/10/20/why-we-chose-vue/`](https://about.gitlab.com/2016/10/20/why-we-chose-vue/)），他们列举的主要优点是易用性、代码量少和假设少。其他公司如 Laravel、任天堂、Sainsbury's 和阿里巴巴都在追随这条路线，甚至像 Rever Shine 这样的公司也将他们的 Web 客户端从 Angular 2.x 重写为 Vue 2.x（[`medium.com/reverdev/why-we-moved-from-angular-2-to-vue-js-and-why-we-didnt-choose-react-ef807d9f4163`](https://medium.com/reverdev/why-we-moved-from-angular-2-to-vue-js-and-why-we-didnt-choose-react-ef807d9f4163)）。

不仅是公开面向的 Web 应用程序正在利用 Vue.js——NativeScript Sidekick（[`www.nativescript.org/blog/announcing-the-nativescript-sidekick-public-preview`](https://www.nativescript.org/blog/announcing-the-nativescript-sidekick-public-preview)）是一个专注于改进 NativeScript 开发体验的项目，它是使用 Electron 和 Vue.js 构建的。

如果我们从 Sacha Greif（[`twitter.com/SachaGreif`](https://twitter.com/SachaGreif)）和 Michael Rambeau（[`michaelrambeau.com/`](http://michaelrambeau.com/)）的 JavaScript 调查中获得一些见解，我们可以看到惊人的**89%**的人在之前使用过 Vue，并希望再次使用它。其他库如 React 的满意度率也达到了**92%**，但是 Angular 2 及以后的版本并没有得到太多的喜爱，只有**65%**的人希望再次使用它。

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/c4a92ed0-fa01-40d4-8f55-f7b42de01887.png)

作为前端开发人员，我们还有哪些其他选择？它们与 Vue 相比如何？让我们从 React 开始。

# React

React 是由 Facebook 开发和维护的 JavaScript 库，与 Vue 最为接近，因为它们的目标非常相似。与 Vue 一样，React 是基于组件的，并利用了虚拟 DOM 的概念。这允许对 DOM 节点进行高性能渲染，因为使用了不同的算法来确定 DOM 的哪些部分发生了变化，以及如何在变化时最好地渲染/更新它们。

在模板方面，React 使用 JSX 来渲染屏幕上的项目。它采用了更冗长的方式来创建 DOM 元素，使用`React.createElement`并简化如下：

这是没有 JSX 的样子：

```js
React.createElement</span>(  MyButton,  {color:  'red',  shadowSize: 5},  'Click Me' )
```

以下是 JSX 的样子。如你所见，两者看起来非常不同：

```js
<MyButton color="red" shadowSize={5}>
 Click  Me </MyButton>
```

对于新手开发者来说，与 Vue 的简单 HTML 模板相比，这增加了一些学习负担，但也正是这一点赋予了 React 其声明性的力量。它有一个使用`setState()`的状态管理系统，但也与 Redux 和 MobX 等第三方状态容器兼容。Vue 也具有类似的功能，使用`Vuex`库，我们将在本书的后面部分更详细地讨论这一点。

使用 React 的一个常见最近关注点是 BSD +专利许可协议，如果你是企业的一部分，这是需要牢记的事情。由于这个许可证，Apache 最近宣布，不会有任何 Apache 软件产品使用 React。另一个例子是[Wordpress.com](http://Wordpress.com)宣布他们不再在 Gutenberg 项目中使用 React（[`ma.tt/2017/09/on-react-and-wordpress/`](https://ma.tt/2017/09/on-react-and-wordpress/)）。这并不一定意味着你不应该在你的项目中使用 React，但还是值得指出的。

一些担心的开发者选择使用替代方案，如 Preact，但最近更多地选择了 Vue.js，因为它满足了 React 开发者在开发应用程序时寻求的许多目标。为此，微软（[`dev.office.com/fabric#/components`](http://dev.office.com/fabric#/components)）、苹果（[`developer.apple.com/documentation`](https://developer.apple.com/documentation)）和其他无数公司都发布了使用 React 的产品-你可以从中得出什么结论。

# Angular

Angular 是由 Google 开发和维护的一种有主见的 JavaScript 框架。在撰写本文时，它目前接近第 5 版，并提供了一种基于结构化标准的网页开发方法。它使用 TypeScript 来强制执行类型安全和 ECMAScript 2015>支持。

与 Angular 相比，Vue 似乎强制执行一组更小的约束，并允许开发人员有更多的选择。Angular 的核心竞争力之一是在任何地方都使用 TypeScript。大多数从 Angular.js 过来的开发人员在 Angular 2 宣布时第一次听说 TypeScript，我注意到有相当多的反对意见，因为需要“学习一门新语言”。事实上，JavaScript 就是 TypeScript，增加工具（自动完成、重构、类型安全等）的价值是不容忽视的。

特别是在处理企业项目时，随着项目复杂性和团队规模的增加，入门挑战变得更加困难。有了 TypeScript，我们能够更好地推理代码之间的关系。这种结构化的开发体验是 Angular 的主要优势。这就是为什么 Angular 团队选择 TypeScript 作为主要开发工具的原因。TypeScript 的好处不仅限于 Angular；我们将在本书后面看看如何将 Vue 与 TypeScript 集成以获得同样的好处。

使用 Angular 作为开发框架有什么缺点吗？不一定。当与 Vue 进行比较时，入门体验是非常不同的。

# 移动开发

在开发移动应用程序时，像 Angular 和 React 这样的项目是开发面向移动的应用程序的绝佳选择。NativeScript、React Native 和 Ionic Framework 项目的成功大大提升了这些框架的流行度。例如，Ionic Framework 目前在 GitHub 上的星标比 Angular 还要多！

Vue 在这一领域取得了一定的成就，例如 NativeScript Vue、Weex 和 Quasar Framework 等项目。所有列出的项目都相对较新，但只需要一个项目真正地提升 Vue 在生产中的流行度。以 NativeScript Vue 为例，只需要 43 行代码就可以创建一个连接到 REST API 并在屏幕上显示结果的跨平台移动应用程序。如果你想自己尝试一下，可以运行：

```js
# Install the NativeScript CLI
npm install nativescript -g

# New NativeScript Vue project
tns create NSVue --template nativescript-vue-template

# Change directory
cd NSVue

# Run on iOS
tns run ios
```

然后，我们可以将以下内容放在`app/app.js`中：

```js
const Vue = require('nativescript-vue/dist/index');
const http = require('http');
Vue.prototype.$http = http;

new Vue({
    template: `
    <page>
        <action-bar class="action-bar" title="Posts"></action-bar>
        <stack-layout>
            <list-view :items="posts">
                <template scope="post">
                    <stack-layout class="list">
                        <label :text="post.title"></label>
                        <label :text="post.body"></label>
                    </stack-layout>
                </template>
            </list-view>
        </stack-layout>
    </page>
    `,    
    data: {
        posts: []
    },
    created(args) {
        this.getPosts();
    },
    methods: {
        getPosts() {
            this.$http
                .getJSON(`https://jsonplaceholder.typicode.com/posts`)
                .then(response => {
                    this.posts = response.map(
                        post => {
                            return {
                                title: post.title,
                                body: post.body
                            }
                        }
                    )
                });
        }
    }
}).$start();
```

如果我们运行我们的代码，就可以看到一个帖子列表。你会注意到我们的 Vue 代码是声明式的，而且我们可以用更少的代码获得更大框架的功能：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/533f7db4-3b7c-495c-9897-88cd50b6da2f.jpg)

# 服务器端渲染（SSR）

服务器端渲染允许我们将前端 JavaScript 应用程序渲染为服务器上的静态 HTML。这很重要，因为它可以显著加快我们的应用程序，因为浏览器只需解析关键的 HTML/CSS。最大化性能是现代 Web 应用程序的关键组成部分，随着渐进式 Web 应用程序和 AMP 等项目的预期不断增长。React、Angular 和 Vue 都能够使用各种不同的模式进行服务器端渲染。

让我们看看如何实现一个简单的服务器端渲染的 Vue 应用程序：

```js
# Create a new folder named vue-ssr:
$ mkdir vue-ssr
$ cd vue-ssr

# Create a new file named server.js
$ touch server.js

# Install dependencies
$ npm install vue vue-server-renderer express
```

在`server.js`中，我们可以创建一个新的 Vue 实例，并使用 Vue 渲染器将我们实例的内容输出为 HTML：

```js
const Vue = require("vue");
const server = require("express")();
const renderer = require("vue-server-renderer").createRenderer();

server.get("*", (req, res) => {
  const app = new Vue({
    data: {
      date: new Date()
    },
    template: `
    <div>
    The visited time: {{ date }}
    </div>`
  });

  renderer.renderToString(app, (err, html) => {
    if (err) {
      res.status(500).end("Internal Server Error");
      return;
    }
    res.end(`
      <!DOCTYPE html>
      <html lang="en">
        <head><title>Hello</title></head>
        <body>${html}</body>
      </html>
    `);
  });
});

server.listen(8080);
```

要运行应用程序，请在终端中输入以下内容：

```js
$ node server.js
```

然后我们可以在浏览器中打开`http://localhost:8080`，我们会在屏幕上看到当前的日期和时间。这只是一个简单的例子，但我们能够看到我们的应用程序是使用`vue-server-renderer`渲染的。请注意，我们没有定义一个目标元素来在我们的 Vue 实例中渲染内容；这是由`renderer.renderToString`函数处理的。

您还会注意到我们在 DOM 节点上有`data-server-rendered="true"`属性，这在客户端渲染的 Vue 应用程序中是不存在的。这使我们能够用服务器端实例来滋养我们的客户端实例，这是我们将在后面关于 Nuxt 的章节中更详细地讨论的内容（[`nuxtjs.org/`](https://nuxtjs.org/)）。

# 结论

企业中的 Web 框架选择总是取决于项目、团队和组织优先事项的目标。没有一个框架是正确的选择，因为最佳选择取决于上下文。每个框架或库都有其独特的优点、缺点和优先事项。如果您的优先事项是快速创建并扩展 Web 应用程序，Vue 可以与其他市场解决方案竞争。

Vue 功能丰富、声明式且高度可读。尽管它是一个简单的框架，但 Vue 的声明性质使我们能够快速启动而不必担心过于复杂的模式。

# 总结

在本章中，我们看了如何设置开发环境以及 Vue 在整个行业中的应用。我们了解到 Vue 是一个简单但强大的前端开发框架。此外，我们考虑了与其他流行项目（如 Angular 和 React）相比，Vue 的表现如何。我们还看了 Vue 如何与其他技术（如 NativeScript）配合使用，创建跨平台原生移动应用程序。最后，我们以高层次调查了 SSR，并为接下来的章节做好了铺垫。希望到现在你已经相信学习 Vue 是值得的，并且期待着利用它所提供的一切！

在下一章中，我们将看一下 Vue CLI 以及如何利用诸如 Webpack 之类的工具来创建我们的 Vue 项目。此外，我们还将探讨如何利用静态类型和 TypeScript 以及在 Vue 中使用 RxJS 的响应式可观察模式。


# 第二章：正确创建 Vue 项目

在本章中，我们将看看如何创建可维护的 Vue 项目，并充分利用许多可用的工具和模式。如果您目前在开发工作流程中没有充分利用这些功能，您可能会发现本章讨论的大部分概念也适用于其他技术。

在本章中，我们将研究以下内容：

+   Vue devtools

+   Visual Studio Code 扩展

+   TypeScript 集成

+   使用 RxJS 进行响应式编程

# Visual Studio Code 扩展

我们的开发环境是应用程序开发的重要部分。在使用 Visual Studio Code 创建 Vue 应用程序时，建议安装以下扩展：

+   Vetur

+   Vue 2 Snippets

让我们更详细地看看这两个。

# Vetur

Vetur 由 Vue 语言服务器提供支持，为我们提供语法高亮、Emmet（用于增加 HTML/CSS 工作流程）、代码片段、linting、IntelliSense 等功能。这极大地改善了我们的开发体验，并得到了广泛的支持，在 GitHub 上有超过 1,000 个星标。要安装该扩展，点击 Visual Studio Code 中的扩展图标，然后输入`Vetur`；从这里，您可以选择安装，它将自动在您的项目中使用：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/cc72dedd-cdee-4a3a-ae5d-12840c66693a.png)安装 Vetur

这样我们就可以访问到诸如`scaffold`之类的代码片段，它为我们在 Vue 组件中生成了一个新的空模板、脚本和样式对象：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/15c16209-2768-4463-9632-9d735b08bc6e.jpg)搭建一个新的 Vue 项目

# Vue 2 Snippets

代码片段是应用程序开发的重要部分；与 Emmet 类似，它们允许我们快速搭建应用程序中常见的模式。我们还将安装另一个名为 Vue 2 Snippets 的 Visual Studio Code 扩展，该扩展为我们提供了各种常用的代码片段。

这样可以节省大量时间，否则我们将不得不花费时间编写相同的样板代码。接下来的例子，虽然它很简单，但我们可以得到代码片段的描述，然后按下*Tab*键，它就会扩展为我们预定义的代码：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/234a2a64-d70c-44f4-902d-6c6c603f10be.jpg)充分利用 Vue 代码片段

# Vue CLI

Vue **命令行界面**（**CLI**）允许我们快速使用各种不同的模板选项搭建新的 Vue 项目。目前，可用的模板选项包括 Webpack、Browserify 和渐进式 Web 应用程序功能等技术。

当然，我们可以创建自己的 Vue 应用程序，并手动添加诸如 Webpack 之类的工具，但这会在技术上增加负担，因为我们必须学习、构建和维护我们的配置。Vue CLI 可以为我们做到这一点，同时保持一组官方模板，但不限制我们修改生成的 Webpack 配置。所有这些都允许我们生成新的无偏见的 Vue 项目。

要开始使用 Vue CLI，让我们确保已经安装了它：

```js
npm install vue-cli -g
```

然后，我们可以使用 Vue `init`命令使用 Webpack 模板搭建一个新的 Vue 项目：

```js
vue init webpack-simple my-vue-project
```

输入上述命令后，我们应该在终端上看到以下内容：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/ddc98095-267c-405f-bed1-fda9f1cfd584.png)使用 Vue init 创建项目

如果我们分解这个，实质上我们正在基于 webpack-simple 模板初始化一个新的 Vue 项目，名为 my-vue-project。然后我们会进入一个向导过程，询问我们关于项目的更多元数据。这些元数据和配置将根据您选择的模板而有所不同。

让我们来研究模板创建的文件和文件夹：

| **文件/文件夹** | **描述** |
| --- | --- |
| `src/` | 这个文件夹包含我们项目的所有代码。我们将在 src 中花费大部分时间。 |
| `.bablrc` | 这是我们的 Babel 配置文件，允许我们编写 ES2015 并进行适当的转译。 |
| `index.html` | 这是我们的默认 HTML 文件。 |
| `package.json` | 这个文件包含我们的依赖和其他项目特定的元数据。 |
| `webpack.config.js` | 这是我们的 Webpack 配置文件，允许我们使用`.vue`文件、Babel 等。 |

注意我们不再使用`.js`文件，现在我们的`src`目录里有`.vue`文件。Vue 文件被称为单文件组件，它包含模板、脚本和样式标签，允许我们将所有内容限定在这个组件内部。

这是可能的，因为我们有一个自定义的“loader”。这是如何工作的？在看这个之前，让我们快速了解一下现代 JavaScript 构建系统。

# JavaScript 模块

为了创建可重用的模块化代码，我们的目标应该是在大多数情况下每个功能有一个文件。这使我们能够避免可怕的“意大利面代码”反模式，其中我们有强耦合和关注点分离很少。继续以意大利面为主题，解决这个问题的方法是采用更小、松散耦合、分布式模块的“意大利饺子代码”模式，这样更容易处理。JavaScript 模块是什么样子的？

在 ECMAScript2015 中，模块只是使用`export`关键字的文件，并允许其他模块导入该功能：

```js
// my-module.js
export default function add(x, y) {
 return x + y
}
```

然后我们可以从另一个模块中`import` `add`：

```js
// my-other-module.js
import { add } from './my-other-module'

add(1, 2) // 3
```

由于浏览器尚未完全跟上模块导入的步伐，我们经常使用工具来辅助打包过程。在这个领域常见的项目有 Babel、Bublé、Webpack 和 Browserify。当我们使用 Webpack 模板创建一个新项目时，它使用 Vue-loader 将我们的 Vue 组件转换为标准的 JavaScript 模块。

# Vue-loader

在标准的`webpack-simple`模板中的`./webpack-config.js`内，我们有一个模块对象，允许我们设置我们的加载器；这告诉 Webpack 我们想要在项目中使用`.vue`文件：

```js
module: {
 rules: [{
  test: /\.vue$/,
  loader: 'vue-loader',
  options: {
   loaders: {}
  // other vue-loader options go here
 }
}]
```

为了使其工作，Webpack 对与`.vue`匹配的任何内容运行正则表达式，然后将其传递给我们的`vue-loader`，以转换为普通的 JavaScript 模块。在这个简单的例子中，我们正在加载扩展名为`.vue`的文件，但`vue-loader`可以进一步定制，您可能希望进一步了解这一点（[`goo.gl/4snNfD`](https://goo.gl/4snNfD)）。我们当然可以自己进行这种配置，但希望您能看到使用 Vue CLI 生成我们的 Webpack 项目的好处。

# 在没有 Webpack 的情况下加载模块

尽管 Webpack 在更多方面帮助我们，但我们目前可以在浏览器中本地加载 JavaScript 模块。在写作时，它的性能往往不如打包工具（但这可能会随着时间的推移而改变）。

为了演示这一点，让我们转到终端，并在基于简单模板的项目中创建一个简单的计数器。这个模板有效地启动了一个新的 Vue 项目，没有任何打包工具：

```js
# New Vue Project
vue init simple vue-modules

# Navigate to Directory
cd vue-modules

# Create App and Counter file
touch app.js
touch counter.js
```

然后我们可以编辑我们的`index.html`，添加来自`type="module"`的脚本文件，这使我们可以使用之前概述的导出/导入语法：

```js
<!-- index.html -->
<!DOCTYPE html>
<html>
<head>
 <title>Vue.js Modules - Counter</title>
 <script src="https://unpkg.com/vue"></script>
</head>
<body>
 <div id="app">
 </div>
 <script type="module" src="counter.js"></script>
 <script type="module" src="app/app.js"></script>
</body>
</html>
```

警告：确保您的浏览器是最新的，以便上述代码可以成功运行。

然后，在我们的`counter.js`中，我们可以导出一个新的`default`对象，它充当一个新的 Vue 实例。它充当一个简单的计数器，允许我们增加或减少一个值：

```js
export default {
 template: `
  <div>
   <h1>Counter: {{counter}}</h1>
   <button @click="increment">Increment</button>
   <button @click="decrement">Decrement</button>
  </div>`,
 data() {
  return {
   counter: 1
  };
 },
 methods: {
  increment() {
   this.counter++;
  },
 decrement() {
   this.counter--;
  }
 }
};
```

然后我们可以在`app.js`中导入`counter.js`文件，从而演示我们可以导入/导出模块的方式。为了在我们的根 Vue 实例中显示计数器，我们将计数器注册为此实例中的一个组件，并将模板设置为`<counter></counter>`，这是我们组件的名称：

```js
import Counter from './counter.js';

const app = new Vue({
 el: '#app',
 components: {
  Counter
 },
 template: `<counter></counter>`
});
```

我们将在本书的后续部分更详细地讨论这一点，但在这一点上，你需要知道的是它实际上充当另一个 Vue 实例。当我们在我们的实例中注册组件时，我们只能从该实例中访问这个组件。

太棒了！这是我们模块导入/导出的结果：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/0439ff73-38f9-4452-88a0-6c0695188524.png)Vue.js 模块

在下一节中，我们将深入了解调试 Vue 应用程序以及 Vue devtools 在其中的作用。

# VueJS devtools

能够准确调试我们的应用程序是开发工作流程的重要部分。在上一章中，我们安装了 VueJS devtools，并将在本节中更详细地使用它。让我们创建一个示例项目：

```js
# New project
vue init webpack-simple vue-devtools

# Change directory
cd vue-devtools

# Install dependencies
npm install

# Run application
npm run dev
```

然后，我们可以打开开发者控制台并导航到 Vue 选项卡。当我们从组件列表中选择 App 时，我们可以看到该组件的数据对象和其他信息。默认情况下，我们有一个`msg`变量，然后我们将其绑定到我们的模板中，并且我们可以在开发者工具中看到这一点：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/9b7c49cd-7e51-45ff-9ba0-992d0231b6cc.png)检查 Vue 实例

不过，这两种方式都是可以的 - 我们可以使用`$vm0.$data`来访问 Vue 实例中的对象，将其范围限定为`msg`。要在控制台中查看这一点，选择`<Root>`然后选择`<App>`将在控制台中显示`msg`。我们可以更改这个值，由于 Vue 正在监视这个值，它将自动在屏幕上更改。

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/e5e7927c-b0ee-4b93-a634-9116253f9c37.png)从控制台编辑 Vue 实例数据

注意我们的消息已更改为`"Hello Vue Devtools!"`；如果我们有多个 Vue 实例，将会有其他带有`$vm1`，`$vm2`等前缀版本的 Vue。在本书后面当我们开始使用`Vuex`时，我们会经常使用这个。接下来，让我们看看如何将 TypeScript 集成到我们的 Vue 项目中。这对于具有 Angular 背景或任何希望利用静态类型的人都很有用。

# TypeScript 和 Vue

您可能以前使用过 TypeScript，或者您可能对如何在 Vue 项目中利用 TypeScript 提供的额外工具感到好奇。为什么要使用 TypeScript？高等人最近的一项研究发现，TypeScript/静态类型工具将提交的错误减少了 15%（[`goo.gl/XUTPf4`](https://goo.gl/XUTPf4)）。

如果您以前使用过 Angular，这种语法应该让您感到非常亲切，因为我们将使用装饰器和 ES2015 类。让我们研究一下如何将 TypeScript 添加到使用 Vue CLI 构建的项目中：

```js
# Create a new Vue project
vue init webpack-simple typescript-vue

# Change directory
cd typescript-vue

# Install dependencies
npm install
```

您应该在终端上获得以下输出：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/c023a2c4-80d8-4527-aca1-b542d61685d3.png)

如果我们按照说明导航到我们的项目目录并运行 `npm install`，然后我们需要安装 TypeScript 加载器并编辑我们的 Webpack 配置。这允许我们在项目内加载`.ts`文件，并且因为我们使用了`webpack-simple`模板，所以只需安装加载器并进行一些更改即可。同时，我们还可以将 TypeScript 安装到项目中：

```js
# Install TypeScript and the TypeScript Loader
npm install typescript ts-loader --save-dev  
```

然后我们需要对我们的 Webpack 配置进行一些更改，以添加新的加载器。热模块替换默认启用，因此加载后无需刷新即可看到任何更改。

记得从命令行运行项目，并输入 `npm dev`。

我们需要将入口点更改为`main.ts`（并随后重命名它），并定义`ts-loader`并删除`babel-loader`以执行此操作，并编辑`webpack.config.js`文件，粘贴以下内容：

```js
var path = require('path');
var webpack = require('webpack');

module.exports = {
 entry: './src/main.ts',
 output: {
 path: path.resolve(__dirname, './dist'),
 publicPath: '/dist/',
 filename: 'build.js'
 },
 module: {
 rules: [
 {
 test: /\.vue$/,
 loader: 'vue-loader',
 options: {
 loaders: {}
 }
 },
 {
 test: /\.tsx?$/,
 loader: 'ts-loader',
 exclude: /node_modules/,
 options: {
 appendTsSuffixTo: [/\.vue$/]
 }
 },
 {
 test: /\.(png|jpg|gif|svg)$/,
 loader: 'file-loader',
 options: {
 name: '[name].[ext]?[hash]'
 }
 }
 ]
 },
 resolve: {
 extensions: ['.ts', '.js', '.vue'],
 alias: {
 vue$: 'vue/dist/vue.esm.js'
 }
 },
 devServer: {
 historyApiFallback: true,
 noInfo: true
 },
 performance: {
 hints: false
 },
 devtool: '#eval-source-map'
};

if (process.env.NODE_ENV === 'production') {
 module.exports.devtool = '#source-map';
 // http://vue-loader.vuejs.org/en/workflow/production.html
 module.exports.plugins = (module.exports.plugins || []).concat([
 new webpack.DefinePlugin({
 'process.env': {
 NODE_ENV: '"production"'
 }
 }),
 new webpack.optimize.UglifyJsPlugin({
 sourceMap: true,
 compress: {
 warnings: false
 }
 }),
 new webpack.LoaderOptionsPlugin({
 minimize: true
 })
 ]);
}
```

之后，我们可以在项目根目录内创建一个`tsconfig.json`，负责适当配置我们的 TypeScript 设置：

```js
{
 "compilerOptions": {
 "lib": ["dom", "es5", "es2015"],
 "module": "es2015",
 "target": "es5",
 "moduleResolution": "node",
 "experimentalDecorators": true,
 "sourceMap": true,
 "allowSyntheticDefaultImports": true,
 "strict": true,
 "noImplicitReturns": true
 },
 "include": ["./src/**/*"]
}
```

现在我们的项目中已经设置了 TypeScript，但要真正利用它在我们的 Vue 应用程序中，我们还应该使用`vue-class-component`。这使我们能够利用组件属性的静态类型，并将组件定义为本机 JavaScript 类：

```js
# Install TypeScript helpers
npm install vue-class-component --save-dev
```

然后，我们可以通过首先将其指定为具有`lang="ts"`属性的脚本来定义我们的`App.vue`文件。然后像往常一样导入 Vue，但除此之外，我们还从`vue-class-component`导入`Component`，以便在此文件中用作装饰器。这允许我们将其指定为新的 Vue 组件，并且使用 Component 装饰器，我们可以定义属性、模板等。

在我们的 Component 装饰器内部，我们正在指定一个模板，其中包含一个输入框和按钮。此示例允许我们看到如何绑定到类属性，以及从我们的类中调用方法。以下代码应替换已在`App.vue`文件中的代码：

```js
<script lang="ts">
import Vue from 'vue';
import Component from 'vue-class-component';

@Component({
 template: `
 <div>
   <input type="text" v-model="name" />
   <button @click="sayHello(name)">Say Hello!</button>
</div>
`
})
export default class App extends Vue {
 name: string = 'Paul';

 sayHello(name: string): void {
   alert(`Hello ${name}`)
 }
}
</script>
```

运行上述代码后，您应该会得到类似以下的结果：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/d9abed5a-93a7-495b-8592-96c52b9268ec.png)

# 生命周期钩子

生命周期钩子，如`created()`、`mounted()`、`destroyed()`等，可以在类中定义为函数。

+   `created()`

这允许在将组件添加到 DOM 之前执行操作。使用此钩子允许访问数据和事件。

+   `mounted()`

Mounted 在组件呈现之前和呈现后都可以访问。它提供了与 DOM 和组件进行交互的完全访问权限。

+   `destroyed()`

附加到组件的所有内容都已被销毁。它允许在组件从 DOM 中移除时进行清理。

它们将被识别并且与预期的方式一样起作用，而不需要 TypeScript。在使用`created`和`mounted`钩子时的示例：

```js
// Omitted
export default class App extends Vue {
 name: string = 'Paul';

 created() {
 console.log(`Created: Hello ${this.name}`)
 }

 mounted() {
 console.log(`Mounted: Hello ${this.name}`);
 }
}
```

现在，如果我们转到控制台，我们可以看到“Hello”的消息与 Paul 的名称一起输出：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/429bcf4f-96d4-4d7e-a833-13c72456ac3a.png)

# 属性

我们已经看到了如何创建类并使用 Component 装饰器；现在让我们看看如何在我们的类中使用`vue-property-decorator`定义“props”：

```js
# Install Vue Property Decorator
npm install vue-property-decorator --save-dev
```

这取决于`vue-class-component`，因此每次安装`vue-property-decorator`时，您都需要确保也安装了`vue-class-component`。然后，我们可以使用`@Prop`装饰器定义一个`Component`属性：

```js
<script lang="ts">
import Vue from 'vue';
import { Component, Prop } from 'vue-property-decorator';

// Omitted
@Component({
})
export default class App extends Vue {
@Prop({ default: 'Paul Halliday' }) name: string;
}
</script>
```

请注意，我们现在从`'vue-property-decorator'`而不是`vue-class-component`中导入`Component`。这是因为它将其作为模块导出供我们导入。然后，我们使用名称键和`'Paul Halliday'`的`default`值定义了一个新的组件属性；在使用 TypeScript 之前，它看起来应该是这样的：

```js
export default {
 props: {
 name: {
  type: String,
  default: 'Paul Halliday'
  }
 }
}
```

# 计算属性

计算属性允许传递多个表达式，Vue 实例上的这些属性需要使用类的 getter/setter。因此，如果我们想要获取我们名字的反转版本，我们可以简单地传递以下内容：

```js
@Component({
 template: `
   <div>
     <input type="text" v-model="name" />
     <button @click="sayHello(name)">Say Hello!</button>
     <p>{{nameReversed}}</p>
   </div>
 `
})
export default class App extends Vue {
 @Prop({ default: 'Paul Halliday' }) name: string;

 // Computed values
 get nameReversed() {
  return this.name.split("").reverse().join("");
 }

 sayHello(name: string): void {
  alert(`Hello ${name}`)
 }
}
```

否则，这将等同于：

```js
export default {
 computed: {
  nameReversed() {
   return this.name.split("").reverse().join("");
  }
 }
}
```

其他装饰器也可以使用，比如`@Watch`、`@Inject`、`@Model`和`@Provide`。每个装饰器都允许一致的实现，并为原始 Vue 实例提供类似的 API。在下一节中，我们将看看如何使用 RxJS 增强 Vue 应用程序的响应性。

# RxJS 和 Vue

如果你来自 Angular 背景，你很可能会对 RxJS 的基本概念感到非常熟悉。这意味着我们通常处理诸如 Observables、Subjects 和各种操作符之类的东西。如果你以前没有使用过它们，不用担心——我们将调查 RxJS 是什么，以及为什么我们想要在 Vue 中使用它。

# RxJS 是什么？

如果我们查看 RxJS 文档，我们会看到以下定义：“**ReactiveX 是一个通过使用可观察序列来组合异步和基于事件的程序的库**”([`reactivex.io/intro.html`](http://reactivex.io/intro.html))。乍一看，这并不是一个让我们在项目中感到舒适的描述。

RxJS 帮助我们在应用程序中使用响应式编程原则，通常被称为更具声明性而不是命令性的风格。当我们谈论命令式编程风格时，我们通常是在告诉计算机如何执行特定任务的确切步骤。声明式风格允许我们更多地关注预期的结果而不是实现。

在 JavaScript 中，我们可以通过以下方式创建一个`event`流：

```js
document.addEventListener('click', event => {
 console.log(event);
 }); 
```

这样我们就可以观察文档上的任何鼠标点击。我们可以捕获诸如点击坐标、目标、事件类型等内容。显然，这是一个异步的可观察数据流。我们不知道什么时候有人会点击屏幕，也不在乎。我们所做的就是观察，并在事件发生时执行特定的操作。

我们可以使用 RxJS 将这些原则应用到我们的现代应用程序中，其中一切都是一个流。我们可以有一个可观察的数据流，从 Facebook 动态到文档点击事件，定时器，任何东西！一切都可以是一个流。

# 与 Vue 集成

要将 RxJS 与 Vue 集成，我们需要创建一个新的 Vue 项目，并安装 RxJS 和 Vue-Rx。使用 Vue-Rx 插件的一个很棒的地方是它得到了 Vue.js 团队的官方支持，这让我们有信心它将在长期内得到支持。

让我们使用 Vue CLI 创建一个新项目，并集成 RxJS：

```js
# New Vue project
vue init webpack-simple vue-rxjs

# Change directory
cd vue-rxjs

# Install dependencies
npm install

# Install rxjs and vue-rx
npm install rxjs vue-rx

# Run project
npm run dev
```

我们现在需要告诉 Vue 我们想要使用`VueRx`插件。这可以通过`Vue.use()`来完成，并且不是特定于这个实现。每当我们想要向我们的 Vue 实例添加新的插件时，调用`Vue.use()`会内部调用插件的`install()`方法，扩展全局范围的新功能。要编辑的文件将是我们的`main.js`文件，位于`src/main.js`。我们将在本书的后面章节更详细地讨论插件：

```js
import Vue from "vue";
import App from "./App.vue";
import VueRx from "vue-rx";
import Rx from "rxjs";

// Use the VueRx plugin with the entire RxJS library
Vue.use(VueRx, Rx);

new Vue({
 el: "#app",
 render: h => h(App)
});
```

注意到前面的实现中有什么问题吗？嗯，在应用性能和减少捆绑包大小的利益上，我们应该只导入我们需要的内容。这样就变成了：

```js
import Vue from "vue";
import App from "./App.vue";
import VueRx from "vue-rx";

// Import only the necessary modules
import { Observable } from "rxjs/Observable";
import { Subject } from "rxjs/Subject"; 

// Use only Observable and Subject. Add more if needed.
Vue.use(VueRx, {
Observable,
Subject
});

new Vue({
el: "#app",
render: h => h(App)
});
```

然后，我们可以在 Vue 应用程序内创建一个`Observable`数据流。让我们转到`App.vue`，并从 RxJS 导入必要的模块：

```js
// Required to create an Observable stream
import { Observable } from 'rxjs/Observable';
import 'rxjs/add/observable/of';
```

然后，我们可以创建一个新的数据`Observable`；在这个例子中，我们将使用一个简单的人员数组：

```js
// New Observable stream of string array values
const people$ = Observable.of(['Paul', 'Katie', 'Bob']);
```

这样一来，我们就可以在订阅对象内订阅这个`Observable`。如果您以前使用过 Angular，这样可以让我们访问`Observable`（并处理必要的取消订阅），类似于 Async 管道：

```js
export default {
  data () {
    return {
      msg: 'Welcome to Your Vue.js App'
    }
  },
  /**
   * Bind to Observable using the subscriptions object.
   * Allows us to then access the values of people$ inside of our template.
   * Similar to the Async pipe within Angular
   **/
  subscriptions: {
    people$
  }
}
```

除此之外，如果我们想要为每个组件创建一个新的`Observable`实例，我们可以将我们的订阅声明为一个函数：

```js
 subscriptions() {
   const people$ = Observable.of(['Paul', 'Katie', 'Bob'])
   return {
     people$
   }
 }
```

最后，我们可以在我们的模板中显示`Observable`的结果。我们可以使用`v-for`指令来遍历数组并在屏幕上显示结果。这是如何工作的？使用以下示例，`v-for`语法使用`item in items`语法，可以在我们的上下文中被认为是`person in people$`。这允许我们访问我们的`people$` Observable（或任何其他数组）中的每个项目与插值绑定：

```js
<template>
  <div id="app"> 
    <ul>
      <li
        v-for="(person,index) in people$":key="index"> {{person}}
      </li>
    </ul>
  </div>
</template>
```

正如您在浏览器中所看到的，我们的三个项目现在已经出现在列表项中的屏幕上：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/2230e189-f1b4-412e-9141-6a0dfc296b15.png)遍历 RxJS Observables

# 总结

在本章中，我们看了如何利用 Vue CLI 来搭建新的 Vue 项目，并配置适当的打包配置和 ES2015 支持。我们看到这不仅给了我们额外的能力，而且在长远来看也节省了大量时间。我们不必记住如何创建 Webpack 或 Babel 配置，因为这一切都由起始模板为我们处理；但即使如此，如果我们想添加额外的配置选项，我们也可以。

然后我们看了如何使用 Webpack 和`ts-loader`来实现 TypeScript，以及利用属性装饰器来利用常见的 TypeScript 和 Vue 模式。这使我们能够利用核心工具，并帮助减少代码中的错误。

最后，我们还在我们的应用程序中实现了 RxJS 和 Vue-Rx，以利用 Observable 模式。如果您有兴趣在项目中使用 RxJS，这是未来集成的良好起点。

在下一章中，我们将更深入地了解 Vue.js 实例和不同的保留属性，比如 data、computed、watch，以及创建 getter 和 setter。本章特别考虑了何时应该使用 computed 来使用或监视属性。

在本节中，我们将通过查看 Vue 如何处理来了解 Vue.js 实例在更低级别上是如何工作的。我们还将查看实例上的各种属性，如 data、computed、watch，以及在使用每个属性时的最佳实践。此外，我们将查看 Vue 实例中可用的各种生命周期钩子，允许我们在应用程序的各个阶段调用特定函数。最后，我们将调查**文档对象模型**（**DOM**）以及 Vue 为了增强性能而实现虚拟 DOM。

在本章结束时，您将：

+   更好地理解`this`关键字在 JavaScript 中的工作原理

+   了解 Vue 如何在 Vue 实例中代理`this`关键字

+   使用数据属性创建响应式绑定

+   使用计算属性基于我们的数据模型创建声明性函数

+   使用 watched 属性访问异步数据，并在计算属性的基础上构建

+   使用生命周期钩子在 Vue 生命周期的特定阶段激活功能

+   调查 DOM 和虚拟 DOM，了解 Vue 如何将数据渲染到屏幕上

首先，让我们来看看这在 JavaScript 中是如何工作的，以及这与我们 Vue 实例中的上下文有什么关系。

# 代理

到目前为止，你可能已经与 Vue 应用程序互动，并且想过：`this`是如何工作的呢？在了解 Vue.js 如何处理`this`之前，让我们先看看它在 JavaScript 中是如何工作的。

# 在 JavaScript 中'this'的工作原理

在 JavaScript 中，`this`有不同的上下文，从全局窗口上下文到 eval、newable 和函数上下文。由于默认上下文与全局作用域相关，因此这是我们的 window 对象：

```js
/**
 * Outputting the value of this to the console in the global context returns the Window object
 */
console.log(this);

/**
 * When referencing global Window objects, we don't need to refer to them with this, but if we do, we get the same behavior
 */
alert('Alert one');
this.alert('Alert two');
```

在作用域中，this 的上下文会发生变化。这意味着，如果我们有一个`Student`对象，其中包含特定的值，比如`firstName`、`lastName`、`grades`等等，那么`this`的上下文将与对象本身相关：

```js
/**
 * The context of this changes when we enter another lexical scope, take our Student object example:
 */
const Student = {
 firstName: 'Paul',
 lastName: 'Halliday',
 grades: [50, 95, 70, 65, 35],
 getFullName() {
  return `${this.firstName} ${this.lastName}` 
 },
 getGrades() {
  return this.grades.reduce((accumulator, grade) => accumulator + grade);
 },
 toString() {
  return `Student ${this.getFullName()} scored ${this.getGrades()}/500`;
 }
}
```

当我们用`console.log(Student.toString())`运行上述代码时，我们得到了这个结果：`Student Paul Halliday scored 315/500`，因为此时`this`的上下文现在是对象本身，而不是全局窗口作用域。

如果我们想要在文档中显示这个，我们可以这样做：

```js
let res = document.createTextNode(Student.toString());
let heading = document.createElement('h1');
heading.appendChild(res);
document.body.appendChild(heading);
```

请注意，通过上述代码，我们再次不需要使用`this`，因为它在全局上下文中是不需要的。

现在我们对`this`的基本工作原理有了一定的了解，我们可以研究 Vue 如何代理我们实例中的`this`，以便更轻松地与各种属性进行交互。

# Vue 如何处理'this'

到目前为止，你可能已经注意到我们能够使用`this`语法引用数据、方法和其他对象中的值，但我们实例的实际结构是`this.data.propertyName`或`this.methods.methodName`；所有这些都是由于 Vue 代理了我们实例的属性。

让我们来看一个非常简单的 Vue 应用程序，它只有一个实例。我们有一个`data`对象，其中有一个`message`变量和一个名为`showAlert`的方法；Vue 是如何知道如何通过`this.message`访问我们的警报文本的呢？

```js
<template>
 <button @click="showAlert">
 Show Alert</button>
</template>

<script>
export default {
 data() {
  return {
   message: 'Hello World!',
  };
 },
 methods: {
  showAlert() {
   alert(this.message);
  },
 },
};
</script>
```

Vue 将实例属性代理到顶层对象，使我们能够通过`this`访问这些属性。如果我们将实例记录到控制台（借助 Vue.js 开发工具），我们会得到以下结果：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/41cc6781-067d-452c-8da3-53bb10569abb.png)控制台输出

在前面的截图中要查看的关键属性是`message`和`showAlert`，它们都在我们的 Vue 实例上定义，但在初始化时被代理到根对象实例。

# 数据属性

当我们向数据对象添加一个变量时，实质上是创建了一个响应式属性，它会在任何更改时更新视图。这意味着，如果我们有一个数据对象，其中有一个名为`firstName`的属性，那么每次该值更改时，该属性都会在屏幕上重新渲染：

```js
<!DOCTYPE html>
<html>
<head>
 <title>Vue Data</title>
 <script src="https://unpkg.com/vue"></script>
</head>
<body>
 <div id="app">
  <h1>Name: {{ firstName }}</h1>
  <input type="text" v-model="firstName">
 </div>

 <script>
 const app = new Vue({
  el: '#app',
  data: {
   firstName: 'Paul'
  }
 });
 </script>
</body>
</html>
```

这种响应性不会扩展到在数据对象之外创建的对象添加到我们的 Vue 实例之后。如果我们有另一个例子，但这次包括将另一个属性（如`fullName`）附加到实例本身：

```js
<body>
 <div id="app">
  <h1>Name: {{ firstName }}</h1>
  <h1>Name: {{ name }}</h1>
  <input type="text" v-model="firstName">
 </div>

 <script>
 const app = new Vue({
  el: '#app',
  data: {
   firstName: 'Paul'
  }
 });
 app.fullName = 'Paul Halliday';
 </script>
</body>
```

即使这个项目在根实例上（与我们的`firstName`变量一样），`fullName`也不是响应式的，不会在任何更改时重新渲染。这是因为当 Vue 实例初始化时，它会遍历每个属性并为每个数据属性添加 getter 和 setter，因此，如果我们在初始化后添加一个新属性，它就缺少了这个并且不是响应式的。

Vue 如何实现响应式属性？目前，它使用`Object.defineProperty`为实例内的项目定义自定义 getter/setter。让我们在具有标准`get`/`set`功能的对象上创建自己的属性：

```js
 const user = {};
 let fullName = 'Paul Halliday';

 Object.defineProperty(user, 'fullName', {
  configurable: true,
  enumerable: true,
  get() {
   return fullName;
  },
  set(v) {
   fullName = v;
  }
 });

 console.log(user.fullName); // > Paul Halliday
 user.fullName = "John Doe";
 console.log(user.fullName); // > John Doe
```

由于观察者是使用自定义属性的 setter/getter 设置的，因此在初始化后仅仅添加一个属性到实例中并不会实现响应性。这可能会在 Vue 3 中发生变化，因为它将使用更新的 ES2015+ Proxy API（但可能缺乏对旧版浏览器的支持）。

我们的 Vue 实例不仅仅是一个数据属性！让我们使用计算属性来创建基于数据模型内项目的响应式派生值。

# 计算属性

在本节中，我们将查看 Vue 实例中的计算属性。这使我们能够创建基于数据模型内项目的小型声明性函数，返回一个基于数据模型内项目的单一值。为什么这很重要？如果我们将所有逻辑都放在模板内，我们的团队成员和未来的自己都需要更多的工作来理解我们的应用程序在做什么。

因此，我们可以使用计算属性来大大简化我们的模板，并创建我们可以引用的变量，而不是逻辑本身。它不仅仅是一个抽象；计算属性是被缓存的，并且只有在依赖项发生变化时才会重新计算。

让我们创建一个简单的项目来看看它的实际效果：

```js
# Create a new Vue.js project
$ vue init webpack-simple computed 

# Change directory
$ cd computed

# Install dependencies
$ npm install

# Run application
$ npm run dev
```

插值是强大的；例如，在我们的 Vue.js 模板中，我们可以使用 `reverse()` 方法来取一个字符串（例如，`firstName`）并将其反转：

```js
<h1>{{  firstName.split('').reverse().join('') }}</h1>
```

现在我们将展示一个反转后的 `firstName`，所以 Paul 将变成 luaP。这样做的问题在于，在模板中保留逻辑并不是非常实际的。如果我们想要反转多个字段，我们必须在每个属性上添加另一个 `split()`、`reverse()` 和 `join()`。为了使这更具声明性，我们可以使用计算属性。

在 `App.vue` 中，我们可以添加一个新的计算对象，其中包含一个名为 `reversedName` 的函数；这个函数包含了我们反转字符串的逻辑，并允许我们将其抽象成一个包含逻辑的函数，否则会污染模板：

```js
<template>
 <h1>Name: {{ reversedName }}</h1>
</template>

<script>
export default {
 data() {
  return {
   firstName: 'Paul'
  }
 },
 computed: {
  reversedName() {
   return this.firstName.split('').reverse().join('')
  }
 }
}
</script>
```

然后我们可以在 Vue.js devtools 中看到关于我们计算属性的更多信息：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/016c15d1-b6a4-4798-a04f-f37bcdc56ba3.png)使用 devtools 显示数据

在我们的简单例子中，重要的是要意识到，虽然我们可以将这个方法，但是有理由将其保留为一个计算属性。计算属性是被缓存的，除非它们的依赖项发生了变化，它们不会被重新渲染，这在我们有一个更大的数据驱动应用程序时尤其重要。

# 监视属性

计算属性并不总是解决我们的响应式数据问题的答案，有时我们需要创建自己的自定义监视属性。计算属性只能是同步的，必须是纯的（例如，没有观察到的副作用），并且返回一个值；这与监视属性形成了鲜明对比，后者通常用于处理异步数据。

一个被监视的属性允许我们在数据改变时反应性地执行一个函数。这意味着我们可以在数据对象中的每个项目改变时调用一个函数，并且我们将可以访问到这个改变的值作为参数。让我们通过一个简单的例子来看一下：

注意：`Axios` 是一个需要添加到项目中的库。要这样做，前往 [`github.com/axios/axios`](https://github.com/axios/axios) 并按照提供的安装步骤进行操作。

```js
<template>
 <div>
  <input type="number" v-model="id" />
  <p>Name: {{user.name}}</p>
  <p>Email: {{user.email}}</p>
  <p>Id: {{user.id}}</p>
 </div>
</template>

<script>
import axios from 'axios';

export default {
 data() {
  return {
   id: '',
   user: {}
  }
 },
 methods: {
  getDataForUser() { 
   axios.get(`https://jsonplaceholder.typicode.com/users/${this.id}`)
 .then(res => this.user = res.data);
  }
 },
 watch: {
  id() {
   this.getDataForUser();
  }
 }
}
</script>
```

在这个例子中，每当我们的文本框使用新的`id`（1-10）更改时，我们会得到关于特定用户的信息，如下所示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/63948d07-5f10-4348-ab27-e44f5bc310e8.png)

这实际上是在监视`id`上的任何更改，并调用`getDataForUser`方法，检索有关此用户的新数据。

尽管观察属性确实具有很大的威力，但计算属性在性能和易用性方面的好处不容忽视；因此，在可能的情况下，应优先选择计算属性而不是观察属性。

# 生命周期钩子

我们可以访问各种生命周期钩子，在创建 Vue 实例的过程中的特定时刻触发。这些钩子从`beforeCreate`到实例`mounted`、`destroyed`等等。

如下图所示，创建新的 Vue 实例会在实例生命周期的不同阶段触发函数。

我们将在本节中看看如何激活这些钩子：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/1ad4f9ba-c04c-44f6-b6a5-3b6e4e297c38.png)Vue.js 实例生命周期钩子

利用生命周期钩子（[`vuejs.org/v2/guide/instance.html`](https://vuejs.org/v2/guide/instance.html)）可以以与 Vue 实例上的任何其他属性类似的方式完成。让我们看看如何与每个钩子交互，从顶部开始；我将基于标准的`webpack-simple`模板创建另一个项目：

```js
// App.vue
<template>
</template>

<script>
export default {
 data () {
   return {
    msg: 'Welcome to Your Vue.js App'
   }
 },
 beforeCreate() {
  console.log('beforeCreate'); 
 },
 created() {
  console.log('created');
 }
}
</script>
```

请注意，我们只是将这些函数添加到我们的实例中，而没有任何额外的导入或语法。然后我们在控制台中得到两个不同的日志声明，一个是在创建实例之前，另一个是在创建之后。我们实例的下一个阶段是`beforeMounted`和`mounted`钩子；如果我们添加这些，我们将能够再次在控制台上看到一条消息：

```js
beforeMount() {
 console.log('beforeMount');
},
mounted() {
 console.log('mounted');
}
```

如果我们修改模板，使其具有更新我们的数据属性的按钮，我们将能够触发`beforeUpdated`和`updated`钩子：

```js
<template>
 <div>
  <h1>{{msg}}</h1>
  <button @click="msg = 'Updated Hook'">Update Message</button>
 </div>
</template>

<script>
export default {
 data () {
   return {
    msg: 'Welcome to Your Vue.js App'
   }
 },
 beforeCreate() {
  console.log('beforeCreate'); 
 },
 created() {
  console.log('created');
 },
 beforeMount() {
  console.log('beforeMount');
 },
 mounted() {
  console.log('mounted');
 },
 beforeUpdated() {
  console.log('beforeUpdated'); 
 },
 updated() {
  console.log('updated');
 }
}
</script>
```

每当我们选择`Update Message`按钮时，我们的`beforeUpdated`和`updated`钩子都会触发。这使我们能够在生命周期的这个阶段执行操作，只剩下`beforeDestroy`和`destroyed`尚未涵盖。让我们向我们的实例添加一个按钮和一个调用`$destroy`的方法，从而触发适当的生命周期钩子：

```js
<template>
  <div>
    <h1>{{msg}}</h1>
    <button @click="msg = 'Updated Hook'">Update Message
    </button>
    <button @click="remove">Destroy instance</button>
  </div>
</template>
```

然后我们可以将`remove`方法添加到我们的实例中，以及允许我们捕获适当的钩子的函数：

```js
methods: {
  remove(){
   this.$destroy();
  }
},
// Other hooks
  beforeDestroy(){
  console.log("Before destroy");
},
  destroyed(){
  console.log("Destroyed");
}
```

当我们选择`destroy`实例按钮时，`beforeDestroy`和`destroy`生命周期钩子将触发。这使我们能够在销毁实例时清理任何订阅或执行任何其他操作。在实际场景中，生命周期控制应该交给数据驱动的指令，比如`v-if`和`v-for`。我们将在下一章更详细地讨论这些指令。

# Vue.js 和虚拟 DOM

在性能改进方面，让我们考虑为什么 Vue.js 广泛使用虚拟 DOM 来在屏幕上呈现我们的元素。在看虚拟 DOM 之前，我们需要对 DOM 的实际含义有一个基本的理解。

# DOM

DOM 用于描述 HTML 或 XML 页面的结构。它创建了一个类似树状的结构，使我们能够在 JavaScript 中进行创建、读取、更新和删除节点以及遍历树等许多功能。让我们考虑以下 HTML 页面：

```js
<!DOCTYPE html>
<html lang="en">
<head>
 <title>DOM Example</title>
</head>
<body>
 <div&gt;
  <p>I love JavaScript!</p>
  <p>Here's a list of my favourite frameworks:</p>
  <ul>
   <li>Vue.js</li>
   <li>Angular</li>
   <li>React</li>
  </ul>
 </div>

 <script src="app.js"></script>
</body>
</html>
```

我们可以查看 HTML，看到我们有一个**div**，两个**p**，一个**ul**和**li**标签。浏览器解析这个 HTML 并生成 DOM 树，高层次上看起来类似于这样：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/cb087b90-2dfe-4994-ab62-1da34db49db7.jpg)

然后我们可以与 DOM 交互，通过`document.getElementsByTagName()`按`TagName`获取这些元素的访问权限，返回一个 HTML 集合。如果我们想要映射这些集合对象，我们可以使用`Array.from`创建一个这些元素的数组。以下是一个例子：

```js
const paragraphs = Array.from(document.getElementsByTagName('p'));
const listItems = Array.from(document.getElementsByTagName('li'));

paragraphs.map(p => console.log(p.innerHTML));
listItems.map(li => console.log(li.innerHTML));
```

这样应该会在我们的数组中将每个项目的`innerHTML`记录到控制台中，从而显示我们如何访问 DOM 中的项目：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/dda3c743-af98-4890-90ef-62707cec011e.png)

# 虚拟 DOM

更新 DOM 节点的计算成本很高，取决于应用程序的大小，这可能会大大降低应用程序的性能。虚拟 DOM 采用了 DOM 的概念，并为我们提供了一个抽象，允许使用差异算法来更新 DOM 节点。为了充分利用这一点，这些节点不再使用 document 前缀访问，而是通常表示为 JavaScript 对象。

这使得 Vue 能够准确地确定*什么*发生了变化，并且只重新渲染与之前不同的实际 DOM 中的项目。

# 总结

在本章中，我们更多地了解了 Vue 实例以及如何利用各种属性类型，如数据、监视器、计算值等。我们了解了 JavaScript 中`this`的工作原理，以及在 Vue 实例中使用它时的区别。此外，我们还调查了 DOM 以及 Vue 为什么使用虚拟 DOM 来创建高性能应用程序。

总之，数据属性允许我们在模板中使用响应式属性，计算属性允许我们将模板和过滤逻辑分离成可在模板中访问的高性能属性，而监视属性则允许我们处理异步操作的复杂性。

在下一章中，我们将深入研究 Vue 指令，比如`v-if`、`v-model`、`v-for`，以及它们如何用于创建强大的响应式应用程序。


# 第三章：使用 Vue 编写干净、精简的代码

在本节中，我们将调查 Vue.js 实例在更低级别上的工作方式，看看 Vue 是如何处理 this 的。我们还将查看实例上的各种属性，如数据、计算、观察，以及在使用每个属性时的最佳实践。此外，我们将查看 Vue 实例中可用的各种生命周期钩子，允许我们在应用程序的各个阶段调用特定函数。最后，我们将调查**文档对象模型**（**DOM**）以及为什么 Vue 实现了虚拟 DOM 以提高性能。

在本章结束时，您将：

+   更好地理解 JavaScript 中`this`关键字的工作原理

+   了解 Vue 如何在 Vue 实例中代理`this`关键字

+   使用数据属性创建响应式绑定

+   使用计算属性基于我们的数据模型创建声明性函数

+   使用观察属性访问异步数据，并在计算属性的基础上构建

+   使用生命周期钩子在 Vue 生命周期的特定阶段激活功能

+   调查 DOM 和虚拟 DOM，以了解 Vue 如何将数据渲染到屏幕上

首先，让我们来看看在 JavaScript 中 this 是如何工作的，以及它如何与我们的 Vue 实例中的上下文相关联。

# 代理

到目前为止，您可能已经与 Vue 应用程序进行了交互，并想过：`this`是如何工作的？在查看 Vue.js 如何处理`this`之前，让我们先看看它在 JavaScript 中是如何工作的。

# 了解 JavaScript 中的'this'工作原理

在 JavaScript 中，`this`具有不同的上下文，从全局窗口上下文到 eval、可实例化和函数上下文。由于默认上下文与全局范围相关，因此 this 是我们的窗口对象：

```js
/**
 * Outputting the value of this to the console in the global context returns the Window object
 */
console.log(this);

/**
 * When referencing global Window objects, we don't need to refer to them with this, but if we do, we get the same behavior
 */
alert('Alert one');
this.alert('Alert two');
```

this 的上下文会根据我们所处的范围而改变。这意味着，如果我们有一个`Student`对象，具有特定的值，比如`firstName`、`lastName`、`grades`等，那么`this`的上下文将与对象本身相关联：

```js
/**
 * The context of this changes when we enter another lexical scope, take our Student object example:
 */
const Student = {
 firstName: 'Paul',
 lastName: 'Halliday',
 grades: [50, 95, 70, 65, 35],
 getFullName() {
  return `${this.firstName} ${this.lastName}` 
 },
 getGrades() {
  return this.grades.reduce((accumulator, grade) => accumulator + grade);
 },
 toString() {
  return `Student ${this.getFullName()} scored ${this.getGrades()}/500`;
 }
}
```

当我们运行上述代码并使用`console.log(Student.toString())`时，我们会得到这个结果：`Student Paul Halliday scored 315/500`，因为此时 this 的上下文现在是对象本身，而不是全局窗口范围。

如果我们想要在文档中显示 this，我们可以这样做：

```js
let res = document.createTextNode(Student.toString());
let heading = document.createElement('h1');
heading.appendChild(res);
document.body.appendChild(heading);
```

请注意，在上述代码中，我们再次不必使用`this`，因为它在全局上下文中不需要。

现在我们对`this`的基本工作原理有了一定的了解，我们可以调查 Vue 如何在实例内部代理`this`，以便更轻松地与各种属性进行交互。

# Vue 如何处理'this'

到目前为止，您可能已经注意到我们能够使用`this`语法引用数据、方法和其他对象中的值，但实例的实际结构是`this.data.propertyName`或`this.methods.methodName`；所有这些都是由 Vue 代理我们的实例属性实现的。

让我们来看一个非常简单的 Vue 应用程序，它只有一个实例。我们有一个`data`对象，其中有一个`message`变量和一个名为`showAlert`的方法；Vue 如何知道如何通过`this.message`访问我们的警报文本？

```js
<template>
 <button @click="showAlert">
 Show Alert</button>
</template>

<script>
export default {
 data() {
  return {
   message: 'Hello World!',
  };
 },
 methods: {
  showAlert() {
   alert(this.message);
  },
 },
};
</script>
```

Vue 将实例属性代理到顶层对象，使我们可以通过 this 访问这些属性。如果我们将实例记录到控制台（借助 Vue.js 开发工具），我们会得到以下结果：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/50163bb3-787a-4250-b7fd-4f3aec51aad6.png)控制台记录

在前面的屏幕截图中要查看的关键属性是`message`和`showAlert`，它们都在我们的 Vue 实例上定义，但在初始化时代理到根对象实例。

# 数据属性

当我们向数据对象添加变量时，实质上是创建了一个在任何更改时更新视图的响应式属性。这意味着，如果我们有一个名为`firstName`的属性的数据对象，每次该值更改时，该属性都会在屏幕上重新渲染：

```js
<!DOCTYPE html>
<html>
<head>
 <title>Vue Data</title>
 <script src="https://unpkg.com/vue"></script>
</head>
<body>
 <div id="app">
  <h1>Name: {{ firstName }}</h1>
  <input type="text" v-model="firstName">
 </div>

 <script>
 const app = new Vue({
  el: '#app',
  data: {
   firstName: 'Paul'
  }
 });
 </script>
</body>
</html>
```

这种响应性不会扩展到在创建 Vue 实例后添加到实例之外的数据对象。如果我们有另一个示例，但这次包括向实例本身添加另一个属性，例如`fullName`：

```js
<body>
 <div id="app">
  <h1>Name: {{ firstName }}</h1>
  <h1>Name: {{ name }}</h1>
  <input type="text" v-model="firstName">
 </div>

 <script>
 const app = new Vue({
  el: '#app',
  data: {
   firstName: 'Paul'
  }
 });
 app.fullName = 'Paul Halliday';
 </script>
</body>
```

尽管此项位于根实例上（与我们的`firstName`变量相同），但`fullName`不是响应式的，不会在任何更改时重新渲染。这是因为当 Vue 实例初始化时，它会遍历每个属性，并为每个数据属性添加 getter 和 setter，因此，如果在初始化后添加新属性，则缺少此属性并且不是响应式的。

Vue 如何实现响应式属性？目前，它使用`Object.defineProperty`为实例内部的项目定义自定义的 getter/setter。让我们在具有标准`get`/`set`功能的对象上创建自己的属性：

```js
 const user = {};
 let fullName = 'Paul Halliday';

 Object.defineProperty(user, 'fullName', {
  configurable: true,
  enumerable: true,
  get() {
   return fullName;
  },
  set(v) {
   fullName = v;
  }
 });

 console.log(user.fullName); // > Paul Halliday
 user.fullName = "John Doe";
 console.log(user.fullName); // > John Doe
```

由于观察者是使用自定义属性 setter/getter 设置的，所以在初始化之后仅仅添加一个属性到实例中并不会导致响应性。这在 Vue 3 中可能会发生变化，因为它将使用更新的 ES2015+ Proxy API（但可能不支持旧版浏览器）。

我们的 Vue 实例不仅仅是一个数据属性！让我们使用计算属性来创建基于数据模型中的项目的反应性派生值。

# 计算属性

在这一部分，我们将看看 Vue 实例中的计算属性。这允许我们创建小的、声明性的函数，根据数据模型中的项目返回一个单一的值。为什么这很重要呢？嗯，如果我们把所有的逻辑都放在模板里，我们的团队成员和未来的自己都需要做更多的工作来理解我们的应用程序在做什么。

因此，我们可以使用计算属性来大大简化我们的模板，并创建我们可以引用的变量，而不是逻辑本身。它不仅仅是一个抽象；计算属性是被缓存的，除非依赖项发生变化，否则不会重新计算。

让我们创建一个简单的项目来看看它的运作方式：

```js
# Create a new Vue.js project
$ vue init webpack-simple computed 

# Change directory
$ cd computed

# Install dependencies
$ npm install

# Run application
$ npm run dev
```

插值是强大的；例如，在我们的 Vue.js 模板中，我们可以使用`reverse()`方法来取一个字符串（例如`firstName`）并将其反转：

```js
<h1>{{  firstName.split('').reverse().join('') }}</h1>
```

现在我们将展示我们的`firstName`的反转版本，所以 Paul 会变成 luaP。这样做的问题是，在模板内部保持逻辑并不是很实际。如果我们想要反转多个字段，我们就必须在每个属性上添加另一个`split()`、`reverse()`和`join()`。为了使这更具声明性，我们可以使用计算属性。

在`App.vue`中，我们可以添加一个包含名为`reversedName`的函数的新计算对象；这个函数采用我们反转字符串的逻辑，并允许我们将其抽象成一个包含逻辑的函数，否则会污染模板：

```js
<template>
 <h1>Name: {{ reversedName }}</h1>
</template>

<script>
export default {
 data() {
  return {
   firstName: 'Paul'
  }
 },
 computed: {
  reversedName() {
   return this.firstName.split('').reverse().join('')
  }
 }
}
</script>
```

然后我们可以在 Vue.js devtools 中看到关于我们计算属性的更多信息：

使用 devtools 显示数据

在我们简单的例子中，重要的是要意识到，虽然我们可以把这个方法做成一个方法，但是有理由让它作为一个计算属性。计算属性是被缓存的，除非它们的依赖项发生变化，否则它们不会被重新渲染，这在我们有一个更大的数据驱动应用程序时尤为重要。

# 观察属性

计算属性并不总是解决我们的响应式数据问题的答案，有时我们需要创建自己的自定义监视属性。计算属性只能是同步的，必须是纯的（例如，没有观察到的副作用），并返回一个值；这与监视属性形成鲜明对比，后者通常用于处理异步数据。

监视属性允许我们在数据更改时反应性地执行函数。这意味着我们可以在数据对象中的每个项目更改时调用函数，并且我们将可以访问此更改后的值作为参数。让我们通过一个简单的例子来看一下： 

注意：`Axios`是一个需要添加到项目中的库。要这样做，请前往[`github.com/axios/axios`](https://github.com/axios/axios)并按照提供的安装步骤进行操作。

```js
<template>
 <div>
  <input type="number" v-model="id" />
  <p>Name: {{user.name}}</p>
  <p>Email: {{user.email}}</p>
  <p>Id: {{user.id}}</p>
 </div>
</template>

<script>
import axios from 'axios';

export default {
 data() {
  return {
   id: '',
   user: {}
  }
 },
 methods: {
  getDataForUser() { 
   axios.get(`https://jsonplaceholder.typicode.com/users/${this.id}`)
 .then(res => this.user = res.data);
  }
 },
 watch: {
  id() {
   this.getDataForUser();
  }
 }
}
</script>
```

在这个例子中，每当我们的文本框以新的`id`（1-10）更改时，我们就会获得有关该特定用户的信息，如下所示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/1224f47e-0825-4425-8944-6b071bbcb57d.png)

这实际上是在监视`id`上的任何更改，并调用`getDataForUser`方法，检索有关此用户的新数据。

尽管监视属性确实具有很大的能力，但计算属性在性能和易用性方面的优势不容小觑；因此，在可能的情况下，应优先考虑计算属性而不是监视属性。

# 生命周期钩子

我们可以在创建 Vue 实例期间的特定时间点触发各种生命周期钩子。这些钩子从`beforeCreate`之前的创建到`mounted`之后，`destroyed`等等。

如下图所示，创建一个新的 Vue 实例会在实例生命周期的不同阶段触发函数。

我们将看看如何在本节中激活这些钩子：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/97a8afa9-3bb9-4a72-8ee6-c4e2da52ebcc.png)Vue.js 实例生命周期钩子

利用生命周期钩子（[`vuejs.org/v2/guide/instance.html`](https://vuejs.org/v2/guide/instance.html)）可以以与 Vue 实例上的任何其他属性类似的方式进行。让我们看看如何与每个钩子进行交互，从顶部开始；我将基于标准的`webpack-simple`模板创建另一个项目：

```js
// App.vue
<template>
</template>

<script>
export default {
 data () {
   return {
    msg: 'Welcome to Your Vue.js App'
   }
 },
 beforeCreate() {
  console.log('beforeCreate'); 
 },
 created() {
  console.log('created');
 }
}
</script>
```

请注意，我们只是简单地将这些函数添加到我们的实例中，而没有任何额外的导入或语法。然后我们在控制台中得到两个不同的日志声明，一个是在创建实例之前，另一个是在创建实例之后。我们实例的下一个阶段是`beforeMounted`和`mounted`钩子；如果我们添加这些，我们将能够再次在控制台上看到一条消息：

```js
beforeMount() {
 console.log('beforeMount');
},
mounted() {
 console.log('mounted');
}
```

如果我们修改我们的模板，使其有一个按钮来更新我们的数据属性，我们将能够触发`beforeUpdated`和`updated`钩子：

```js
<template>
 <div>
  <h1>{{msg}}</h1>
  <button @click="msg = 'Updated Hook'">Update Message</button>
 </div>
</template>

<script>
export default {
 data () {
   return {
    msg: 'Welcome to Your Vue.js App'
   }
 },
 beforeCreate() {
  console.log('beforeCreate'); 
 },
 created() {
  console.log('created');
 },
 beforeMount() {
  console.log('beforeMount');
 },
 mounted() {
  console.log('mounted');
 },
 beforeUpdated() {
  console.log('beforeUpdated'); 
 },
 updated() {
  console.log('updated');
 }
}
</script>
```

每当我们选择`Update Message`按钮时，我们的`beforeUpdated`和`updated`钩子都会触发。这使我们能够在生命周期的这个阶段执行一个操作，只留下`beforeDestroy`和`destroyed`尚未覆盖。让我们向我们的实例添加一个按钮和一个调用`$destroy`的方法，从而触发适当的生命周期钩子：

```js
<template>
  <div>
    <h1>{{msg}}</h1>
    <button @click="msg = 'Updated Hook'">Update Message
    </button>
    <button @click="remove">Destroy instance</button>
  </div>
</template>
```

然后我们可以向我们的实例添加`remove`方法，以及允许我们捕获适当钩子的函数：

```js
methods: {
  remove(){
   this.$destroy();
  }
},
// Other hooks
  beforeDestroy(){
  console.log("Before destroy");
},
  destroyed(){
  console.log("Destroyed");
}
```

当我们选择`destroy`实例按钮时，`beforeDestroy`和`destroy`生命周期钩子将触发。这使我们能够在销毁实例时清理任何订阅或执行任何其他操作。在现实世界的场景中，生命周期控制应该交给数据驱动的指令，比如`v-if`和`v-for`。我们将在下一章更详细地讨论这些指令。

# Vue.js 和虚拟 DOM

在性能改进方面，让我们考虑为什么 Vue.js 广泛使用虚拟 DOM 来在屏幕上渲染我们的元素。在看虚拟 DOM 之前，我们需要对 DOM 的实际含义有一个基础的理解。

# DOM

DOM 用于描述 HTML 或 XML 页面的结构。它创建了一个类似树状的结构，使我们能够在 JavaScript 中进行从创建、读取、更新和删除节点到遍历树等许多功能。让我们考虑以下 HTML 页面：

```js
<!DOCTYPE html>
<html lang="en">
<head>
 <title>DOM Example</title>
</head>
<body>
 <div>
  <p>I love JavaScript!</p>
  <p>Here's a list of my favourite frameworks:</p>
  <ul>
   <li>Vue.js</li>
   <li>Angular</li>
   <li>React</li>
  </ul>
 </div>

 <script src="app.js"></script>
</body>
</html>
```

我们能够查看 HTML 并看到我们有一个**div**，两个**p**，一个**ul**和**li**标签。浏览器解析这个 HTML 并生成 DOM 树，从高层次上看，它看起来类似于这样：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/485fcd82-ca94-4e09-ba7e-97939f5f35bc.jpg)

然后，我们可以通过`document.getElementsByTagName()`与 DOM 交互，返回一个 HTML 集合。如果我们想要映射这些集合对象，我们可以使用`Array.from`创建一个这些元素的数组。以下是一个例子：

```js
const paragraphs = Array.from(document.getElementsByTagName('p'));
const listItems = Array.from(document.getElementsByTagName('li'));

paragraphs.map(p => console.log(p.innerHTML));
listItems.map(li => console.log(li.innerHTML));
```

这样应该会在我们的数组中记录每个项目的`innerHTML`到控制台，从而展示我们如何访问 DOM 中的项目：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/7d4c9117-6dba-4c11-97fd-50b7cfa44e38.png)

# 虚拟 DOM

更新 DOM 节点在计算上是昂贵的，取决于应用程序的大小，这可能会大大降低应用程序的性能。虚拟 DOM 采用 DOM 的概念，并为我们提供了一个抽象，允许使用差异算法来更新 DOM 节点。为了充分利用这一点，这些节点不再使用 document 前缀访问，而是通常表示为 JavaScript 对象。

这使得 Vue 能够准确地确定*什么*发生了变化，并且只重新渲染实际 DOM 中与之前不同的项目。

# 总结

在本章中，我们更多地了解了 Vue 实例以及如何利用各种属性类型，如数据、watchers、计算值等。我们了解了在 JavaScript 中`this`的工作原理，以及在 Vue 实例中使用它时的区别。此外，我们调查了 DOM 以及为什么 Vue 使用虚拟 DOM 来创建高性能的应用程序。

总之，数据属性允许我们在模板中使用响应式属性，计算属性允许我们将模板和过滤逻辑分离成高性能的属性，可以在模板中访问，而 watched 属性允许我们处理异步操作的复杂性。

在下一章中，我们将深入了解 Vue 指令，比如`v-if`，`v-model`，`v-for`，以及它们如何用于创建强大的响应式应用程序。
