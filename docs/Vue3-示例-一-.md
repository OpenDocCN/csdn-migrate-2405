# Vue3 示例（一）

> 原文：[`zh.annas-archive.org/md5/84EBE0BE98F4DE483EBA9EF82A25ED12`](https://zh.annas-archive.org/md5/84EBE0BE98F4DE483EBA9EF82A25ED12)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

Vue 是主要框架之一，拥有庞大的生态系统，并因其在开发应用时的易用性以及能够帮助你快速实现令人印象深刻的开发结果而不断增加采用率。本书探讨了最新的 Vue 版本——Vue 3.0——以及如何有效地利用它。

你将通过基于示例的方法学习，从探索 Vue 3 的基础开始，创建一个简单的应用，并学习组件、指令等功能的使用。为了增强你的知识并让你对应用构建技能有信心，本书将向你展示如何使用 Jest 和 Vue Test Utils 测试应用。之后，你将学习如何使用 Vue 3 编写非 Web 应用，并使用 Electron 插件创建跨平台桌面应用。你还将学习如何使用 Vue 和 Ionic 创建多用途移动应用。随着学习的深入，你将学习如何使用 Vue 3 开发与 GraphQL API 良好交互的 Web 应用。最后，你将构建一个实时聊天应用，使用 Vue 3 和 Laravel 进行实时通信。

通过本书，你将通过完成一系列使用 Vue 3 构建应用的项目，掌握实际技能。

# 这本书适合谁

这本书适合对使用 Vue 3 进行前端 Web 开发和创建专业应用感兴趣的 Web 开发人员。如果你想学习如何使用 Vue.js 3.0 作为前端创建全栈 Web 应用，你也会发现本书很有用。要充分利用本书，需要具备基本的 JavaScript 编程知识。

# 本书涵盖内容

第一章《在 Vue 3 中创建你的第一个应用》将介绍如何使用 Vue 3 创建简单的应用。你将从构建最基本的应用开始，然后逐渐转向构建更复杂的解决方案。

第二章《构建 Vue 3 渐进式 Web 应用》将教你如何使用 Vue 3 创建一个 GitHub 渐进式 Web 应用（PWA）。在构建项目的过程中，你将深入了解 Vue 应用的内部工作原理，探讨基本构建模块，并创建包含组件的 Vue 应用，以及组件的组成部分和工作原理。

第三章，使用测试构建滑块拼图游戏，将通过让你使用 Vue 3 创建一个简单的游戏来介绍 Vue。你将学习如何使用不同的方法、混合、指令和计算属性添加到项目中。

第四章，构建照片管理桌面应用，将帮助你使用 Vue Electron 插件构建照片管理桌面应用。你将学习如何使用 Electron 和 Vue 轻松构建跨平台桌面应用程序。

第五章，使用 Ionic 构建多功能计算器移动应用，将帮助你创建一个多功能计算器移动应用。你将使用 Vuex 来管理状态并保存结果数据，以便以后在本地存储中使用。最后，你将掌握货币转换、单位转换和小费计算。

第六章，使用 PrimeVue UI 框架构建度假预订应用，将教你如何创建一个具有管理员功能的旅行预订应用。管理员界面将是用户管理预订的仪表板。它将涉及使用状态管理和路由来创建一个功能齐全的应用程序。后端将很简单，这样你就可以更多地专注于 Vue。还需要使用 Vuex 进行状态管理和 Vue Router 进行路由。

第七章，使用 GraphQL 创建购物车系统，将帮助你创建一个 Vue 3 应用并将其与 GraphQL API 一起使用。你将学习如何在 Vue 3 应用程序中使用 GraphQL 客户端。API 将具有查询、变异和数据库交互，你将学习如何使用 Express 创建 GraphQL API。

第八章，使用 Vue 3、Laravel 和 Socket.IO 构建聊天应用，将教你如何使用 Vue 3、socket.io 和 Laravel 创建聊天应用。这个应用将进行 HTTP 请求并进行实时通信。它可以被多个用户使用。

# 为了充分利用本书

为了更好地利用本书，您应该了解现代 JavaScript 的基础知识。了解从 2015 年以后引入的 JavaScript 特性将使您更容易理解本书。基本的 TypeScript 概念，如定义接口和高级数据类型，将在*第五章*，*使用 Ionic 构建多用途计算器移动应用*中使用。

此外，*第八章*，*使用 Vue 3、Laravel 和 Socket.IO 构建聊天应用*，涵盖了需要对 PHP 有基本了解的 Laravel。更高级项目的后端部分还需要了解非常基本的 SQL 语法。`Select`、`Insert`和`Create table`等命令将会有所帮助。

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-ex/img/B14405_Preface_table_1.1.jpg)

其他所需的是最新版本的 Node.js 和 Visual Studio Code。Visual Studio Code 支持 JavaScript 和 TypeScript 开发。需要 Node.js 来运行 Vue CLI 和 Ionic CLI。

阅读本书后，您应该尝试通过创建自己的项目来进行更多练习。这样，您将能够运用从本书中获得的知识。仅仅从教程中学习只是一个开始；独立创建项目将使您熟练掌握技能。

**如果您使用的是本书的数字版本，我们建议您自己输入代码或通过 GitHub 存储库访问代码（链接在下一节中提供）。这样做将有助于避免与复制和粘贴代码相关的潜在错误。**

# 下载示例代码文件

您可以从[www.packt.com](http://www.packt.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了这本书，可以访问[www.packtpub.com/support](http://www.packtpub.com/support)并注册，文件将直接通过电子邮件发送给您。

您可以按照以下步骤下载代码文件：

1.  在[www.packt.com](http://www.packt.com)上登录或注册。

1.  选择**支持**选项卡。

1.  点击**代码下载**。

1.  在**搜索**框中输入书名，并按照屏幕上的说明操作。

下载文件后，请确保使用最新版本的解压缩软件解压文件夹：

+   WinRAR/7-Zip 适用于 Windows

+   Zipeg/iZip/UnRarX 适用于 Mac

+   7-Zip/PeaZip 适用于 Linux

该书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/-Vue.js-3-By-Example`](https://github.com/PacktPublishing/-Vue.js-3-By-Example)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还有其他代码包，来自我们丰富的书籍和视频目录，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)上找到。去看看吧！

# 使用的约定

本书中使用了许多文本约定。

`文本中的代码`：表示文本中的代码单词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。这是一个例子：“将下载的`WebStorm-10*.dmg`磁盘映像文件挂载为系统中的另一个磁盘。”

代码块设置如下：

```js
html, body, #map {
 height: 100%; 
 margin: 0;
 padding: 0
}
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```js
[default]
exten => s,1,Dial(Zap/1|30)
exten => s,2,Voicemail(u100)
exten => s,102,Voicemail(b100)
exten => i,1,Voicemail(s0)
```

任何命令行输入或输出都以以下方式编写：

```js
$ mkdir css
$ cd css
```

**粗体**：表示新术语、重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词以这种方式出现在文本中。这是一个例子：“从**管理**面板中选择**系统信息**。”

提示或重要说明

以这种方式出现。


# 第一章：在 Vue 3 中创建您的第一个应用程序

**Vue 3**是流行的 Vue.js 框架的最新版本。它专注于改善开发人员的体验和速度。它是一个基于组件的框架，让我们可以轻松创建模块化、可测试的应用程序。它包括其他框架常见的概念，如 props、过渡、事件处理、模板、指令、数据绑定等。本章的主要目标是让您开始开发您的第一个 Vue 应用程序。本章侧重于如何创建组件。

在本章中，我们将学习如何使用 Vue 3 从头开始创建简单的应用程序。我们将从构建最基本的应用程序开始，然后在接下来的几章中构建更复杂的解决方案。

我们将涵盖的主要主题如下：

+   了解 Vue 作为一个框架

+   设置 Vue 项目

+   Vue 3 核心功能-组件和内置指令

+   使用 Vue.js Devtools 进行调试

# 技术要求

本章的代码位于[`github.com/PacktPublishing/-Vue.js-3-By-Example/tree/master/Chapter01`](https://github.com/PacktPublishing/-Vue.js-3-By-Example/tree/master/Chapter01)。

# 了解 Vue 作为一个框架

正如我们在介绍中提到的，Vue 中有一些概念可以从其他框架中获得。指令可以像在 Angular.js 和 Angular 中一样操作**文档对象模型**（**DOM**）。模板可以像我们在 Angular 中一样渲染数据。它还有自己特殊的语法用于数据绑定和添加指令。

Angular 和 React 都有 props，用于在组件之间传递数据。我们还可以循环遍历数组和对象条目，以显示列表中的项目。与 Angular 一样，我们可以向 Vue 项目添加插件以扩展其功能。

Vue.js 独有的概念包括计算属性，这些属性是从其他属性派生出来的组件属性。此外，Vue 组件具有 watchers，让我们可以监视响应式数据的变化。响应式数据是由 Vue.js 监视的数据，当响应式数据发生变化时，操作会自动执行。

随着响应式数据的变化，组件的其他部分和引用这些值的其他组件都会自动更新。这就是 Vue 的魔力。这也是我们可以用如此少的代码做如此多事情的原因之一。它替我们负责监视数据变化的任务，这样我们就不必自己做了。

Vue 3 的另一个独特功能是，我们可以使用脚本标签添加框架及其库。这意味着，如果我们有一个旧的前端，我们仍然可以使用 Vue 3 及其库来增强旧的前端。此外，我们不需要添加构建工具来构建我们的应用程序。这是大多数其他流行框架所没有的一个很棒的功能。

还有流行的 Vue Router 库用于路由，以及 Vuex 库用于状态管理。它们都已更新为与 Vue 3 兼容，因此我们可以安全地使用它们。这样，我们就不必像在使用其他框架（如 React）时担心要使用哪个路由器和状态管理库。Angular 自带其自己的路由，但没有指定标准状态管理库。

# 使用 Vue CLI 和脚本标签设置 Vue 项目

有几种方法可以创建 Vue 项目或向现有前端添加脚本标签。对于原型设计或学习目的，我们可以通过添加以下代码来添加 Vue 3 的最新版本：

```js
<script src="https://unpkg.com/vue@next"></script>
```

这将始终在我们的应用程序中包含最新版本的 Vue。如果我们在生产中使用它，我们应该包含版本号，以避免新版本的意外更改破坏我们的应用程序。如果我们想指定版本，版本号可以替换`next`这个词。

我们还可以通过安装包来安装 Vue。为此，我们可以运行以下命令：

```js
npm install vue@next
```

这将在我们的 JavaScript 项目中安装最新版本的 Vue。

如果我们使用旧版本的 Vue CLI 从头创建了一个 Vue 项目，那么我们可以使用 CLI 为我们生成所有文件并安装所有包。这是开始使用 Vue 项目的最简单的方法。对于 Vue 3，我们应该使用 Vue CLI v4.5，通过运行以下命令：

```js
yarn global add @vue/cli@next
```

我们还可以通过运行以下命令安装 Vue 调色板：

```js
npm install -g @vue/cli@next
```

然后，要将我们的 Vue 项目升级到 Vue 3，我们可以运行以下命令：

```js
vue upgrade –-next
```

Vite 构建工具将让我们从头开始创建一个 Vue 3 项目。它可以比 Vue CLI 更快地为我们提供项目服务，因为它可以原生地处理模块。我们可以通过使用 NPM 运行以下命令来从头开始设置 Vue 项目：

```js
$ npm init vite-app <project-name>
$ cd <project-name>
$ npm install
$ npm run dev
```

使用 Yarn，我们必须运行以下命令：

```js
$ yarn create vite-app <project-name>
$ cd <project-name>
$ yarn
$ yarn dev
```

在任何情况下，我们都可以用我们选择的项目名称替换`<project-name>`。

我们可以使用各种版本的 Vue。其中一组是 CDN 版本，不带捆绑器。我们可以通过文件名中的`vue(.runtime).global(.prod).js`模式来识别它们。这些可以直接通过脚本标签包含。

我们使用它们与直接添加到 HTML 中的模板一起。`vue.global.js`文件是完整的构建，包括编译器和运行时，因此它可以从 HTML 动态编译模板。`vue.runtime.global.js`文件只包含运行时，并且需要在构建步骤中预编译模板。

开发和生产分支是硬编码的，我们可以通过检查文件是否以`.prod.js`结尾来区分它们。这些文件已经准备好用于生产，因为它们已经被压缩。这些不是**通用模块定义**（**UMD**）构建。它们包含用于常规脚本标签的 IIFE。

如果我们使用诸如 Webpack、Rollup 或 Parcel 之类的捆绑器，那么我们可以使用`vue(.runtime).esm-bundler.js`文件。开发和生产分支由`process.env.NODE_ENV`属性确定。它还有完整版本，它可以在运行时动态编译模板和运行时版本。

在本章中，我们将通过 Vue 的脚本标签版本介绍 Vue 的基本功能。在随后的章节中，我们将继续使用 Vue CLI 来创建我们的 Vue 3 项目。这样，我们可以专注于探索 Vue 3 的基本功能，这在我们转向创建更复杂的项目时会很有用。让我们开始创建一个 Vue 实例。

## 创建您的 Vue 实例

现在我们已经设置好了我们的 Vue 项目，我们可以更仔细地看一下 Vue 实例。所有 Vue 3 应用程序都有一个 Vue 实例。Vue 实例充当应用程序的入口点。这意味着这是首先加载的内容。它是应用程序的根组件，它有一个模板和一个组件选项对象，用于控制模板在浏览器中的呈现方式。

要创建我们的第一个 Vue 3 应用程序，我们必须将以下代码添加到`index.html`文件中：

```js
<!DOCTYPE html>
<html lang="en">
  <head>
    <title>Vue App</title>
    <script src="https://unpkg.com/vue@next"></script>
  </head>
  <body>
    <div id="app">
      count: {{ count }}
    </div>
    <script>
      const Counter = {
        data() {
          return {
            count: 0
          };
        }
      };
      Vue.createApp(Counter).mount("#app");
    </script>
  </body>
</html>
```

在我们的第一个 Vue 3 应用程序中，我们首先添加了`script`标签以添加 Vue 框架脚本。它还不是最终版本，所以我们添加了 Vue 脚本的下一个版本。

在 body 中，我们有一个 ID 为 app 的`div`，我们用它来容纳模板。模板中唯一的内容将由 Vue 3 附带的模板编译器编译。在下面，我们有一个`script`标签来创建我们的应用程序。它提供了`Counter`对象，其中包含我们可以用来创建应用程序的属性。

Vue 组件作为对象提供，Vue 将使用它们来创建任何必要的组件。`data`属性是一个特殊属性，返回我们状态的初始值。这些状态是自动响应的。`count`状态是一个我们可以更新的响应式状态。它与模板中的相同。花括号中的任何内容必须是包含响应式属性或其他 JavaScript 表达式的表达式。

如果我们在花括号之间添加响应式状态，它们将被更新。由于`count`响应式属性被初始化为`0`，模板中的`count`属性也是`0`。`Counter`对象被传递到`Vue.createApp`方法中，以编译模板并连接响应式属性，将花括号内的表达式渲染为最终结果。因此，我们应该在渲染的输出中看到`count: 0`。

`mount()`方法接受一个 CSS 选择器字符串作为参数。选择器是要在其中渲染应用程序的模板。其中的任何内容都将被视为 Vue 表达式，并相应地进行渲染。花括号中的表达式将被渲染，属性将被 Vue 解释为 props 或指令，具体取决于它们的编写方式。

在下一节中，我们将看一下 Vue.js 3 的核心特性。

# Vue 3 核心特性 - 组件和内置指令

现在我们已经创建了一个带有 Vue 实例的基本 Vue 应用程序，我们可以更仔细地看一下如何使它做更多的事情。Vue 3 是一个基于组件的框架。因此，组件是用于构建完整的生产质量 Vue 3 应用程序的核心构建块。组件是可以组合成完整应用程序并且可重用的部分。Vue 3 组件有几个部分，包括模板、组件选项对象和样式。样式是我们应用于渲染元素的 CSS 样式。模板是在浏览器屏幕上呈现的内容。它包含 HTML 代码和 JavaScript 表达式，形成在浏览器中呈现的内容。

模板从相应的组件选项对象获取数据。此外，组件模板可以具有指令，控制内容的呈现方式以及将数据从模板绑定到响应式属性。

## 组件

我们用一个 Vue 实例创建了一个基本的 Vue 应用。现在，我们必须找到一种管理我们应用的方法。Vue 3 是一个基于组件的前端框架。这意味着使用 Vue 3 创建的应用是由多个组件组合而成的。这样，我们可以保持应用的每个部分都很小，这有助于使测试变得容易，也容易调试。这对我们来说很重要，因为我们正在创建一个为用户提供功能的非平凡应用。

在 Vue 3 中，组件是具有一些预定义选项的 Vue 实例。要在另一个组件中使用组件，我们必须注册它们。要创建一个 Vue 组件，我们可以调用`app.component()`方法。第一个参数是组件，称为`string`，而第二个参数是一个包含组件选项的对象。

一个最小的组件应该至少包含添加到对象中的模板属性。这样，它将在我们的组件中显示一些内容，使其有用。我们将首先创建一个用于显示待办事项的组件。为了显示我们的待办事项，我们可以创建一个`todo-item`组件。此外，组件很可能需要接受 props 来显示来自其父组件的数据。**prop**是一个特殊的属性，让 Vue 组件将一些数据传递给子组件。子组件具有`props`属性来定义它将接受的值的类型。为此，我们可以编写以下代码：

```js
<!DOCTYPE html>
<html lang="en">
  <head>
    <title>Vue App</title>
    <script src="https://unpkg.com/vue@next"></script>
  </head>
  <body>
    <div id="app">
      <div>
        <ol>
           ...
            ]
          };
        }
      };
      const app = Vue.createApp(App);
      app.component("todo-item", {
        props: ["todo"],
        template: `<li>{{todo.description}}</li>`
      });
      app.mount("#app");
    </script>
  </body>
</html>
```

我们调用了`app.component()`方法来创建`todo-item`组件。它包含了`props`属性，其中包含一个接受`todo`prop 的 prop 名称数组。我们定义 prop 的方式意味着我们可以接受任何值作为`todo`prop 的值。我们还可以指定它们的值类型，设置它是否是必需的，或为其提供默认值。`template`属性让我们在需要时呈现它。我们只需将其设置为一个字符串，它将像任何其他模板一样呈现项目。

`li`元素在模板中呈现。花括号的工作方式与任何其他模板相同。它用于插值值。要访问 prop 的值，我们只需在组件中将其作为 this 的属性访问，或者在模板中直接使用 prop 名称本身。

要将`todo`属性从根 Vue 实例传递给`todo-item`组件，我们需要使用冒号前缀属性名称，以指示它是一个 prop。冒号是`v-bind`的简写。`v-bind`指令是 Vue 的内置指令，它让我们将数据作为 prop 传递给子组件。如果 prop 名称是驼峰式命名，则它将被映射到 HTML 中的 kebab-case 名称，以保持其有效。这是因为有效的属性应该具有 kebab-case 名称。Vue 3 附带的模板编译器将自动执行映射。因此，我们只需遵循惯例，然后我们就可以正确传递我们的 props。

如果我们使用`v-for`指令，我们应该添加 key 属性，以便 Vue 3 可以正确跟踪项目。使用`v-for`指令，我们可以循环遍历数组或对象，并显示它们的条目。值应该是一个唯一的 ID，以便 Vue 可以正确渲染项目，即使我们交换项目的位置并添加或删除项目并在列表中执行其他操作。为此，我们可以编写以下代码：

```js
<!DOCTYPE html>
<html lang="en">
  <head>
    <title>Vue App</title>
    <script src="https://unpkg.com/vue@next"></script>
  </head>
  <body>
  ...
    </div>
    <script>
      const App = {
        data() {
          return {
            todos: [
              { id: 1, description: "eat" },
              { id: 2, description: "drink" },
              { id: 3, description: "sleep" }
            ]
          };
          ...
      app.mount("#app");
    </script>
  </body>
</html>
```

每个`id`属性值对于 Vue 的列表跟踪是唯一的。

Vue 组件看起来像 Web 组件规范中的自定义元素，但 Vue 组件不是自定义元素。它们不能互换使用。这只是一种使用熟悉的语法来创建组件的方式，这是标准的。Vue 组件中有一些特性在自定义元素中是不可用的。在自定义元素中没有跨组件数据流、自定义事件通信和构建工具集成。然而，所有这些特性都在 Vue 组件中可用。我们将在接下来的部分中介绍 Vue 组件的这些特性。

### 组件生命周期

每个 Vue 3 组件都有自己的生命周期，每个生命周期阶段都有自己的方法。如果达到了生命周期的给定阶段，并且在组件中定义了该方法，那么该方法将被运行。

在使用`app.mount()`挂载应用程序后，事件和生命周期被初始化。当组件加载时将运行的第一个方法是`beforeCreate()`方法。然后，组件被初始化为响应式属性。然后运行`created()`方法。由于在这个阶段初始化了响应式属性，我们可以在这个方法和之后加载的方法中访问这些响应式属性。

然后，运行组件的模板或渲染函数来呈现项目。内容加载完成后，将运行`beforeMount`。一旦运行了`beforeMount`，应用程序将被挂载到我们在`app.mount()`方法中传递给选择器指定的元素中。

一旦应用程序被挂载到元素中，就会运行挂载钩子。现在，当任何响应属性发生变化时，将运行`beforeUpdate`钩子。然后，重新渲染虚拟 DOM，并从响应属性的最新值呈现最新的项目。这是运行任何外部库的初始化代码的好地方。完成后，将运行`updated`钩子。

`beforeDestroy`在组件卸载之前运行。这是在销毁组件之前运行任何清理代码的好地方。当组件被销毁时，将运行`destroyed`钩子。在这里，响应属性将不可用。

### 响应属性

响应属性是组件选项对象的属性，它们让我们同步模板中显示的内容，并根据我们对它们进行的操作而改变。对响应属性所做的任何更改都会在引用它们的任何地方传播到整个应用程序中。

在前面的示例中，我们向我们的应用程序添加了`count`响应属性。要更新它，我们只需更新响应属性的值本身：

```js
<!DOCTYPE html>
<html lang="en">
  <head>
    <title>Vue App</title>
    <script src="https://unpkg.com/vue@next"></script>
  </head>
  <body>
    <div id="app">
      <button @click="count++">increment</button>
      count: {{ count }}
    </div>
    <script>
      const Counter = {
        data() {
          return {
            count: 0
          };
        }
      };
      Vue.createApp(Counter).mount("#app");
    </script>
  </body>
</html>
```

在这里，我们有`@click="count++"`表达式，它监听按钮的点击，并在点击增加按钮时将计数增加`1`。最新的值将在任何地方都得到反映，因为它是一个响应属性。Vue 可以自动捕捉到响应属性的变化。`@click`是`v-on:click`的简写。

此外，我们可以将表达式重写为方法。为此，我们可以编写以下代码：

```js
<!DOCTYPE html>
<html lang="en">
  <head>
    <title>Vue App</title>
    <script src="https://unpkg.com/vue@next"></script>
  </head>
  <body>
    <div id="app">
      <button @click="increment">increment</button>
      count: {{ count }}
    </div>
    <script>
      const Counter = {
        data() {
          return {
            count: 0
          };
        },
        methods: {
          increment() {
            this.count++;
          }
        }
      };
      Vue.createApp(Counter).mount("#app");
    </script>
  </body>
</html>
```

引用 Vue 实例对象中的`count`响应属性，我们必须将其作为`this`的属性引用。因此，在 Vue 实例对象中的`this.count`与模板中的`count`是相同的。`this`关键字指的是组件实例。我们应该记住这一点，这样我们就不会在以后遇到问题。

此外，我们将方法的属性添加到组件对象中。这是一个特殊的属性，用于在我们的代码中保存我们可以在 Vue 实例的其他部分或模板中引用的方法。与响应属性一样，方法在 Vue 实例对象中被引用为`this`的属性，并且在模板中省略了`this`。

因此，当我们点击按钮时，我们运行`methods`属性中的增量方法。当我们点击按钮时，计数值将增加`1`，我们应该在浏览器的输出中看到它显示。

### 处理用户输入

大多数应用程序需要用户向表单输入内容。我们可以使用 Vue 3 的`v-model`指令轻松实现这一点。它将输入的值与我们在 Vue 实例中定义的响应属性进行同步。

要使用它，我们只需将`v-model`属性添加到输入框中。为此，我们可以编写以下代码：

```js
<!DOCTYPE html>
<html lang="en">
  <head>
    <title>Vue App</title>
    <script src="https://unpkg.com/vue@next"></script>
  </head>
  <body>
    <div id="app">
      <p>{{ message }}</p>
      <input v-model="message" />
    </div>
    <script>
      const App = {
        data() {
          return {
            message: "hello world."
          };
        }
      };
      Vue.createApp(App).mount("#app");
    </script>
  </body>
</html>
```

在这里，我们有`message`响应属性，它已初始化为'hello world.'字符串。我们可以通过将其设置为`v-model`指令的值，在模板中使用相同的值。它将在输入的值和`message`响应属性之间进行同步，以便我们输入的任何内容都会传播到 Vue 实例的其余部分。

因此，'hello world.'字符串既显示在输入框中，也显示在段落元素中。当我们在输入框中输入内容时，它也会显示在段落元素中。它将更新`message`响应属性的值。这是 Vue 3 带来的一个很棒的功能，我们将在许多地方使用它。

### 条件和循环

Vue 3 的另一个非常有用的功能是我们可以在模板中有条件地渲染内容。为此，我们可以使用`v-if`指令，它让我们有条件地显示某些内容。`v-if`指令只有在我们分配给它的条件为真时，才将元素放入 DOM 中。`v-show`指令使用 CSS 显示和隐藏它绑定的元素，并且该元素始终在 DOM 中。如果它的值为真，我们将在模板中看到它显示。否则，我们不会看到该项显示。

它通过有条件地将项目附加到 DOM 来工作。只有当`v-if`值为真时，具有`v-if`指令的元素或组件内的元素和组件才会被附加到 DOM 中。否则，它们不会附加到 DOM 中。

例如，假设我们有以下代码：

```js
<!DOCTYPE html>
<html lang="en">
  <head>
    <title>Vue App</title>
    <script src="https://unpkg.com/vue@next"></script>
  </head>
  <body>
    <div id="app">
      <span v-if="show">hello world</span>
    </div>
    <script>
      const App = {
        data() {
          return {
            show: true
          };
        }
      };
      Vue.createApp(App).mount("#app");
    </script>
  </body>
</html>
```

在这里，'hello world'将被显示，因为`show`是`true`。如果我们有以下代码，我们将看不到任何显示，因为 span 没有附加到 DOM 上：

```js
<!DOCTYPE html>
<html lang="en">
  <head>
    <title>Vue App</title>
    <script src="https://unpkg.com/vue@next"></script>
  </head>
  <body>
    <div id="app">
      <span v-if="show">hello world</span>
    </div>
    <script>
      const App = {
        data() {
          return {
            show: false
          };
        }
      };
      Vue.createApp(App).mount("#app");
    </script>
  </body>
</html>
```

要在模板中呈现项目数组和最终输出，我们可以使用`v-for`指令。我们放置一个特殊的 JavaScript 表达式，让我们循环遍历数组。我们可以通过编写以下代码来使用`v-for`指令：

```js
<!DOCTYPE html>
<html lang="en">
  <head>
    <title>Vue App</title>
    <script src="https://unpkg.com/vue@next"></script>
  </head>
  <body>
    <div id="app">
      <ol>
        <li v-for="todo in todos" :keu="todo.id">
          {{ todo.description }}
        </li>
      </ol>
    </div>
    <script>
      const App = {
        data() {
          return {
            todos: [
              { description: "eat", id: 1 },
              { description: "drink", id: 2 },
              { description: "sleep", id: 3 }
            ]
          };
        }
      };
      Vue.createApp(App).mount("#app");
    </script>
  </body>
</html>
```

我们在`li`元素中使用了`v-for`指令。`'todo in todos'`循环遍历`todo`数组并呈现标签之间的项目。`todo`变量是正在迭代的单个*todos*条目。我们访问描述属性，以便我们可以在列表中显示描述的值。

完成后，我们将看到一个带有`todo`文本的编号列表。

### 模板语法

我们已经广泛使用了模板。我们主要使用插值来显示数据和一些指令来呈现数据。此外，我们可以使用`@`或`v-on`指令来监听发出的事件，例如点击和输入值更改。

还有其他有用的语法，我们可以用来创建模板。其中之一是使用插值表达式显示原始 HTML。默认情况下，Vue 3 会转义所有 HTML 实体，以便它们按原样显示。`v-html`指令让我们将 HTML 代码显示为真正的 HTML，而不是纯文本。

例如，让我们编写以下代码：

```js
<!DOCTYPE html>
<html lang="en">
  <head>
    <title>Vue App</title>
    <script src="https://unpkg.com/vue@next"></script>
  </head>
  <body>
    <div id="app">
      <span v-html="rawHtml"></span>
    </div>
    <script>
      const App = {
        data() {
          return {
            rawHtml: `<b>hello world</b>`
          };
        }
      };
      const app = Vue.createApp(App);
      app.mount("#app");
    </script>
  </body>
</html>
```

在这里，我们将`rawHtml`响应式属性设置为`v-html`的值，这样我们就可以看到`b`标签被呈现为粗体文本，而不是以原始形式呈现的字符。

### JavaScript 表达式和模板

我们可以在大括号之间放置任何 JavaScript 表达式。它只能是单个表达式。

例如，以下代码片段显示了大括号之间的有效内容：

```js
{{ number + 1 }} 
{{ areYouSure ? 'YES' : 'NO' }}
{{ message.split('').reverse().join('') }}
```

但是，我们不能在大括号之间放置任何 JavaScript 语句。例如，我们不能写`{{ var foo = 1 }}`或`{{ if (yes) { return message } }}`。

### 计算属性

**计算属性**是从其他响应式属性派生出来的特殊响应式属性。计算属性被添加到计算属性对象中作为函数。它们总是返回从其他响应式属性派生出来的东西。因此，它们必须是同步函数。

要创建计算属性，我们可以编写以下代码：

```js
<!DOCTYPE html>
<html lang="en">
  <head>
    <title>Vue App</title>
    <script src="https://unpkg.com/vue@next"></script>
  </head>
  <body>
    <div id="app">
      <p>{{message}}</p>
      <p>{{reversedMessage}}</p>
    </div>
    <script>
      const App = {
        data() {
          return {
            message: "hello world"
          };
        },
        computed: {
          reversedMessage() {
            return
             this.message.split("").reverse().join("");
          }
        }
      };
      const app = Vue.createApp(App);
      app.mount("#app");
    </script>
  </body>
</html>
```

在这里，我们创建了`reversedMessage`计算属性，它是`message`响应式属性的反转。我们返回了字符顺序反转后的消息。每当`message`响应式属性更新时，`reversedMessage()`方法将再次运行并返回最新的值。因此，我们可以在同一个模板中看到`'hello world'`和`'dlrow olleh'`。这些计算属性的返回值必须包含其他响应式属性，以便在其他响应式属性更新时它们也会更新。

## 指令

组件可能没有足够的能力做我们想要的事情。最重要的缺失是操作 DOM 并将输入数据与响应式属性同步的能力。指令是以`v-`前缀开头的特殊属性。它们期望单个 JavaScript 表达式作为值。我们已经看到一些内置指令，比如`v-if`、`v-for`、`v-bind`和`v-on`被用于各种目的。指令除了值之外还可以带参数。

例如，我们可以写`<a v-on:click="doSomething"> ... </a>`来监听锚元素上的点击事件。`v-on`部分是指令的名称。冒号和等号之间的部分是指令的参数，所以`click`是指令的参数。`doSomething`是指令的值。它是我们想要调用的方法的名称。

指令参数可以是动态的。要添加动态参数，我们可以将它们放在方括号之间：

```js
<a v-bind:[attributeName]="url"> ... </a>
```

`attributeName`是我们想要用来设置参数值的响应式属性。它应该是一个字符串。我们也可以用`v-on`指令做同样的事情：

```js
<a v-on:[eventName]="doSomething"> ... </a>
```

我们使用给定的`eventName`来监听事件。`eventName`也应该是一个字符串。

### 指令修饰符

指令可以带有修饰符，让我们改变指令的行为。修饰符是以点表示的特殊后缀。它们可以链接在一起以提供更多的改变。它们表示指令应该以某种特殊的方式绑定。例如，如果我们需要监听`submit`事件，我们可以添加`prevent`修饰符来调用`event.preventDefault()`，这将阻止默认的提交行为。我们可以通过编写以下代码来实现：

```js
<form v-on:submit.prevent="onSubmit">...</form>
```

接下来，我们将看看如何使用 Vue.js Devtools 浏览器扩展轻松调试 Vue 3 项目。

# 使用 Vue.js Devtools 进行调试

现在，我们没有简单的方法来调试我们的应用程序。我们只能在代码中添加`console.log`语句来查看值。使用 Vue.js Devtools，我们可以更清晰地看到我们的应用程序。Vue.js Devtools 是一个 Chrome 或 Firefox 扩展，我们可以用它来调试我们的 Vue.js 应用程序。它可以用于使用 Vite 创建的项目，也可以通过包含 Vue 3 的`script`标签从头开始创建的项目。我们可以通过在各自浏览器的应用商店中搜索 Vue.js Devtools 扩展来安装该扩展。

重要提示：

安装 Chrome 版本的 Vue.js Devtools 的 URL 在[`chrome.google.com/webstore/detail/vuejs-devtools/nhdogjmejiglipccpnnnanhbledajbpd`](https://chrome.google.com/webstore/detail/vuejs-devtools/nhdogjmejiglipccpnnnanhbledajbpd)。

Firefox 版本的插件在[`addons.mozilla.org/en-CA/firefox/addon/vue-js-devtools/?utm_source=addons.mozilla.org&utm_medium=referral&utm_content=search`](https://addons.mozilla.org/en-CA/firefox/addon/vue-js-devtools/?utm_source=addons.mozilla.org&utm_medium=referral&utm_content=search)。

安装完成后，我们应该在浏览器的开发控制台中看到 Vue 选项卡。通过它，我们可以检查 Vue 加载的响应式属性。如果我们的组件有一个`name`属性，那么它将显示在应用程序的组件树中。例如，假设我们有以下代码：

```js
<!DOCTYPE html>
<html lang="en">
  <head>
    <title>Vue App</title>
    <script src="https://unpkg.com/vue@next"></script>
  </head>
  <body>
    <div id="app">
      <foo></foo>
    </div>
    <script>
      const App = {
        data() {
          return {};
        }
      };
      const app = Vue.createApp(App);
      app.component("foo", {
        data() {
          return {
            message: "I am foo."
          };
        },
        name: "foo",
        template: `<p>{{message}}</p>`
      });
      app.mount("#app");
    </script>
  </body>
</html>
```

在这里，由于我们将`foo`组件的`name`属性设置为`'foo'`，我们将在组件树中看到它的列表。此外，`foo`组件具有`message`响应式属性，因此我们还将看到`message`属性及其值的显示。在组件树上方，有一个搜索框，让我们可以找到具有给定名称的响应式属性。我们还可以在**查找组件**`…`输入框中搜索组件。

以下截图显示了我们的 Vue 3 应用程序中 Vue Devtools 扩展中的响应式属性的值：

![图 1.1-使用 Vue Devtools 检查响应式属性](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-ex/img/Figure_1.1_B14405.jpg)

图 1.1-使用 Vue Devtools 检查响应式属性

还有“时间轴”菜单项，我们可以用它来检查被触发的事件。例如，假设我们有以下代码：

```js
<!DOCTYPE html>
<html lang="en">
<head>
  <title>Vue App</title>
  <script src="https://unpkg.com/vue@next"></script>
</head>
<body>
  <div id="app">
    <button @click="count++">increment</button>
    count: {{ count }}
  </div>
  <script>
    const Counter = {
      data() {
        return {
          count: 0
        };
      }
    };
    Vue.createApp(Counter).mount("#app");
  </script>
</body>
</html>
```

当我们点击“增加”按钮时，我们将在“时间轴”部分看到鼠标事件的记录。事件触发的时间也将被记录。

在**全局设置**部分，我们可以看到**规范化组件名称**设置，它让我们可以改变组件名称的显示方式。我们可以以帕斯卡命名法或短横线命名法显示原始名称。**主题**选项让我们可以改变 Vue 标签的主题颜色。

# 总结

在本章中，我们了解到 Vue 3 是一个基于组件的框架，并且我们看了组件的不同部分。我们涵盖的一个重要部分是响应式属性。它们是组件的属性，我们可以更改以更新引用响应式属性的应用程序的所有部分。这些属性可以手动监视，任何值的更改也会被 Vue 3 自动捕捉到，以便自动更新引用响应式属性的应用程序的任何部分。组件被组合在一起，以便在可能的情况下可以重复使用。

然后，我们继续了解了每个组件中模板的作用。模板也是每个组件的一部分。它们必须在屏幕上渲染出一些东西。模板可以包含 HTML 元素、其他组件和修改模板中元素和组件渲染方式的指令。模板中可以包含 JavaScript 表达式，这样我们就可以对事件做出反应。然后，我们看到了组件中计算属性的重要性。计算属性是依赖于其他响应式属性的特殊响应式属性。它们是同步的函数，并根据其他响应式属性的组合返回一个值。

我们看到的另一个重要点是内置在 Vue 3 中的`v-model`指令。Vue 3 提供了`v-model`指令，这样我们就可以将响应式属性绑定到表单控件的值上。指令是特殊的 Vue 代码，让我们可以改变 DOM 元素的渲染方式。Vue 3 提供了许多内置指令，可以做诸如从数组中渲染元素、将表单控件的值绑定到响应式属性等事情。

在最后一节中，我们学习了如何使用 Vue.js Devtools 来简化调试。这是一个适用于 Chromium 浏览器和 Firefox 的浏览器扩展，让我们可以观察组件的响应式属性值，并查看渲染的组件。它还会记录组件中元素触发的任何事件。

在下一章中，我们将学习如何构建一个简单的 GitHub 应用程序，进行 HTTP 请求。


# 第二章：构建 Vue 3 渐进式 Web 应用

在本章中，我们将学习如何使用 Vue 3 创建 GitHub **渐进式 Web 应用**（**PWA**）。在构建项目的过程中，我们将深入了解 Vue 应用的内部工作原理，查看基本构建块。我们将使用组件创建 Vue 应用，并在创建过程中，我们将查看组件的组成部分以及它们的工作原理。

在需要时，我们还将使用更高级的功能，比如指令。指令让我们能够操纵**文档对象模型**（**DOM**）而不会使组件的代码混乱。它们为我们提供了一种干净的方式来访问 DOM 元素并以可重用的方式处理它们。这有助于简化测试，并帮助我们模块化我们的代码。

Vue 3 带有许多内置指令，我们将使用它们。在上一章中，我们简要概述了这些指令。在本章中，我们将更详细地了解它们的工作原理。这些指令提供了易于使用的抽象，使许多事情对我们来说更容易，并且是 Vue 3 的基本特性，我们无法离开它们。

我们将使用组件来显示我们想要的数据，它们将通过 props 接收输入，以便我们可以获取适当的数据并显示它。在每个组件中，我们将添加自己的方法，并利用一些组件生命周期方法。为了减少代码的重复，我们使用混入来抽象出组件中常用的功能，并将它们合并到我们的组件中。

在本章中，我们将学习以下主题：

+   组件和 PWA 的基本理论

+   介绍 GitHub 作品集应用程序

+   创建 PWA

+   提供 PWA 服务

# 技术要求

本章的代码可以在[`github.com/PacktPublishing/-Vue.js-3-By-Example/tree/master/Chapter02`](https://github.com/PacktPublishing/-Vue.js-3-By-Example/tree/master/Chapter02)找到。

# 组件和 PWA 的基本理论

在开始构建 Vue 应用之前，让我们先熟悉一下组件和 PWA。Vue 3 允许我们使用组件构建前端 Web 应用。通过组件，我们可以将应用程序分成小的、可重用的部分，然后将它们组合在一起形成一个大应用程序。这种组合是通过嵌套实现的。为了使应用程序的不同部分组合在一起，我们可以在它们之间传递数据。组件可以来自库，也可以由我们自己创建。

组件由几个部分组成；它包括模板、脚本和样式。模板是在屏幕上呈现的内容。它包含**超文本标记语言**（**HTML**）元素、指令和组件。组件和 HTML 元素可以添加属性和事件监听器。属性用于从父组件传递数据到子组件。

**事件监听器**让我们可以监听从子组件到父组件发出的事件。事件可以携带有效负载，其中包含数据。这使我们能够实现子组件到父组件的通信。将这两者结合起来，我们就有了一个完整的系统，可以在父子组件之间进行通信。

任何非平凡的应用程序都会有多个需要相互通信的组件。

PWAs 是特殊的网络应用程序，可以安装在用户的计算机上，浏览器管理这些安装的应用程序。它们与常规网络应用程序不同，因为它们让我们可以原生地访问一些计算机硬件。当我们在浏览器中访问 PWA 时，我们可以选择安装 PWA，然后可以从应用商店中打开我们的应用程序。

PWAs 不需要特殊的捆绑或分发程序。这意味着它们可以像任何其他网络应用程序一样部署到服务器上。许多现代浏览器——如 Mozilla Firefox、Google Chrome、Apple Safari 和 Microsoft Edge——都支持 PWAs。这意味着我们可以使用它们安装应用程序。

PWAs 的特殊特性包括能够为每个用户工作，无论浏览器选择如何。它们还具有响应式，这意味着它们可以在任何设备上工作，例如台式机、笔记本电脑、平板电脑或移动设备。初始加载也很快，因为它们应该在第一次加载时被缓存。

它们也应该能够在没有互联网连接的情况下工作。服务工作者在后台运行，让我们可以在离线或低质量网络上使用 PWAs。这也是 PWAs 可用的缓存的另一个好处。

尽管 PWAs 是从浏览器中运行的，但它们的行为就像应用程序一样。它们具有类似应用程序的交互和导航样式。显示的内容也始终是最新的，因为服务工作者在后台运行以更新数据。

PWAs 的另一个重要好处是安全性。它们只能通过**HTTP 安全**（**HTTPS**）提供，因此外部人员无法窥视连接。这样，我们就知道连接没有被篡改。

PWA 还支持推送通知，以便与用户互动并通知他们更新。

它们也可以从**统一资源定位符**（**URL**）链接，并且 PWA 在我们可以使用它之前不需要安装过程——安装是完全可选的。安装后，它会在我们的浏览器上提供一个主屏幕图标，这样我们就可以点击它并开始使用它。

Vue 3 有一个`@vue/cli-plugin-pwa`插件，让我们可以在 Vue 3 项目中添加 PWA 功能，而无需进行任何手动配置。我们只需运行一个命令，所有文件和配置就会自动添加给我们。有了这个插件，我们可以使用 Vue 3 开发我们的 PWA，并且包含的服务工作者将在生产中运行。既然我们已经解决了这个问题，我们将看看如何创建可重用的组件。

# 介绍 GitHub 作品集应用程序

本章的主要项目是一个 GitHub 作品集应用程序。它是一个 PWA，这意味着它具有本章*组件和 PWA 的基本理论*部分列出的所有功能。这些功能是由`@vue/cli-plugin-pwa`插件自动提供的。我们可以通过一个命令添加我们需要的代码，以添加服务工作者和任何其他所需的配置。这样，当我们创建 Vue 项目时，我们就不必从头开始自己配置所有东西了。

为了开始我们的应用项目，我们将使用 Vite 来创建它。我们进入我们想要项目的文件夹，然后运行 Vite 来创建 Vue 3 应用项目。为此，我们使用**Node Package Manager**（**npm**）运行以下命令：

1.  第一个命令，在下面的代码片段中显示，运行 npm 全局安装 Vue **命令行界面**（**CLI**）：

```js
npm install -g @vue/cli@next
```

1.  我们运行 Vue CLI 来创建 Vue 3 项目。我们的项目文件夹名称是`vue-example-ch2-github-app`。需要运行以下命令来创建项目文件夹，并添加所有文件和设置，以便我们不必自己添加它们。这个命令进入我们刚创建的项目文件夹，并在询问时选择 Vue 3 项目：

```js
npm vue create vue-example-ch2-github-app 
```

1.  然后，我们运行以下命令来运行开发服务器，这样我们就可以在浏览器中看到项目，并在编写代码时刷新应用程序预览：

```js
npm run serve
```

或者，我们可以使用**另一种资源协商器**（**YARN**）运行以下命令：

1.  我们运行`yarn global add`来全局安装 Vue CLI，如下所示：

```js
yarn global add @vue/cli@next
```

1.  要创建 Vue 3 项目，我们运行以下命令，并在被询问时选择 Vue 3 项目：

```js
yarn create vue-example-ch2-github-app
```

1.  然后，我们运行以下命令来启动开发服务器，这样我们就可以在浏览器中看到项目，并在编写代码时刷新应用程序预览：

```js
yarn serve
```

所有前述命令都是相同的，它们都以相同的方式创建项目；只是我们想要使用哪个包管理器来创建我们的 Vue 3 项目的问题。此时，项目文件夹将包含我们的 Vue 3 项目所需的文件。

我们的 GitHub 作品集应用是一个渐进式 Web 应用程序，我们可以使用现有的 Vue CLI 插件轻松创建这个应用程序。创建项目后，我们可以开始创建我们的 Vue 3 PWA。

# 创建 PWA

首先，我们需要一种简单的方式通过其**表述状态转移**（**REST**）**应用程序编程接口**（**API**）访问 GitHub 数据。幸运的是，一位名为*Octokit*的开发人员制作了一个 JavaScript 客户端，让我们可以使用我们创建的访问令牌访问 GitHub REST API。我们只需要从**内容分发网络**（**CDN**）导入该包，就可以从浏览器中访问 GitHub REST API。它还有一个 Node 包，我们可以安装和导入。然而，Node 包只支持 Node.js 应用程序，因此无法在我们的 Vue 3 应用程序中使用。

Vue 3 是一个客户端 Web 框架，这意味着它主要在浏览器上运行。我们不应该混淆只在 Node 上运行的包和支持浏览器的包，否则当我们在浏览器中使用不受支持的包时，就会出现错误。

要开始，我们对现有文件进行一些更改。首先，我们从`index.css`中删除样式代码。在这个项目中，我们专注于应用程序的功能，而不是样式。此外，我们将`index.html`文件中的标题标签内文本重命名为`GitHub App`。

然后，为了使我们构建的应用成为 PWA，我们必须运行另一个命令来添加服务工作者，以整合诸如硬件访问支持、安装和离线使用支持等功能。为此，我们使用`@vue/cli-plugin-pwa`插件。我们可以通过运行以下命令来添加这个插件：

```js
vue add pwa
```

这将添加我们需要整合的所有文件和配置，使我们的 Vue 3 项目成为 PWA 项目。

Vue CLI 创建了一个使用单文件组件并对大部分应用程序使用**ECMAScript 6**（**ES6**）模块的 Vue 项目。当我们构建项目时，这些文件被捆绑在一起，然后在 Web 服务器上提供并在浏览器上运行。使用 Vue CLI 创建的项目以`main.js`作为入口点，它运行创建 Vue 应用所需的所有代码。

我们的`main.js`文件应包含以下代码：

```js
import { createApp } from 'vue'
import App from './App.vue'
import './registerServiceWorker'
createApp(App).mount('#app')
```

该文件位于`src`文件夹的根目录，Vue 3 将在应用程序首次加载或刷新时自动运行此文件。`createApp`函数将通过传入入口点组件来创建 Vue 3 应用程序。入口点组件是我们首次加载应用程序时首先运行的组件。在我们的项目中，我们导入了`App`并将其传递给`createApp`。

此外，`index.css`文件是从同一文件夹导入的。这是我们应用程序的全局样式，这是可选的，所以如果我们不想要任何全局样式，我们可以省略它。然后导入`registerServiceWorker.js`文件。仅使用文件名导入意味着文件中的代码直接运行，而不是我们从模块中导入任何内容。

`registerServiceWorker.js`文件应包含以下代码：

```js
/* eslint-disable no-console */
import { register } from 'register-service-worker'
if (process.env.NODE_ENV === 'production') {
...
    offline () {
      console.log('No internet connection found. App is running          in offline mode.')
    },
    error (error) {
      console.error('Error during service worker          registration:', error)
    }
  })
}
```

这是我们运行`vue add pwa`时创建的。如果应用程序处于`production`模式，我们调用`register`函数来注册服务工作者。当我们运行`npm run build`命令时，服务工作者将被创建，我们可以使用创建的服务工作者让用户从我们提供的构建代码中访问功能，例如缓存和硬件访问。服务工作者仅在`production`模式下创建，因为我们不希望在开发环境中缓存任何内容。我们始终希望看到显示最新数据，以便我们可以创建代码并调试它，而不会被缓存所困扰。

我们需要做的另一件事是从`src/components`文件夹中删除`HelloWorld.vue`组件，因为我们的应用程序不需要这个。我们稍后还将删除`App.vue`中对`HelloWorld`组件的任何引用。

现在我们已经对现有代码文件进行了编辑，我们可以创建新文件。为此，我们执行以下步骤：

1.  在`components`文件夹中，我们添加了一个`repo`文件夹；在`repo`文件夹中，我们添加了一个`issue`文件夹。在`repo`文件夹中，我们添加了`Issues.vue`组件文件。

1.  在`components/repo/issue`文件夹中，我们添加`Comments.vue`文件。`Issues.vue`用于显示 GitHub 代码存储库的问题。`Comments.vue`用于显示添加到代码存储库问题的评论。

1.  在`components`文件夹本身，我们添加`GitHubTokenForm.vue`文件以便我们输入和存储 GitHub 令牌。

1.  我们还将`Repos.vue`文件添加到相同的文件夹中，以显示 GitHub 访问令牌所指向的用户的代码存储库。最后，我们将`User.vue`文件添加到`components`文件夹中，以便显示用户信息。

1.  在`src`文件夹中创建一个`mixins`文件夹以添加一个 mixin，让我们使用 GitHub 访问令牌创建 Octokit GitHub 客户端。

我们将`octokitMixin.js`文件添加到`mixins`文件夹中以添加空的 mixin。现在，我们将它们全部留空，因为我们准备添加文件。

## 为我们的应用程序创建 GitHub 客户端

我们通过创建 GitHub `Client`对象来启动项目，该对象将在整个应用程序中使用。

首先，在`src/mixins/octokitMixin.js`文件中，我们添加以下代码：

```js
import { Octokit } from "https://cdn.skypack.dev/@octokit/rest";
export const octokitMixin = {
  methods: {
    createOctokitClient() {
      return new Octokit({
        auth: localStorage.getItem("github-token"),
      });
    }
  }
}
```

上述文件是一个 mixin，它是一个我们合并到组件中以便我们可以在组件中正确使用它的对象。Mixin 具有与组件相同的结构。添加`methods`属性以便我们可以创建并合并到组件中的方法。为了避免命名冲突，我们应该避免在我们的组件中命名任何方法为`createOctokitClient`，否则我们可能会得到意外的错误或行为。`createOctokitClient()`方法使用 Octokit 客户端通过获取`github-token`本地存储项来创建客户端，然后将其设置为`auth`属性。`auth`属性是我们的 GitHub 访问令牌。

`Octokit`构造函数来自我们从[`github.com/octokit/rest.js/releases?after=v17.1.0`](https://github.com/octokit/rest.js/releases?after=v17.1.0)添加的`octokit-rest.min.js`文件。我们找到`v16.43.1`标题，点击**Assets**，下载`octokit-rest.min.js`文件，并将其添加到`public`文件夹中。然后，在`public/index.html`中，我们添加一个`script`标签来引用该文件。我们应该在`index.html`文件中有以下代码：

```js
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-
      width,initial-scale=1.0">
    <link rel="icon" href="<%= BASE_URL %>favicon.ico">
    <title><%= htmlWebpackPlugin.options.title %></title>
    <script src="<%= BASE_URL %>octokit-rest.min.js">
      </script>
  </head>
  <body>
    <noscript>
      <strong>We're sorry but <%= htmlWebpackPlugin.
          options.title %> doesn't work properly without 
           JavaScript enabled. Please enable it to 
            continue.</strong>
    </noscript>
    <div id="app"></div>
    <!-- built files will be auto injected -->
  </body>
</html>
```

## 添加问题和评论的显示

然后，在`src/components/repo/issue/Comments.vue`文件中，我们添加以下代码：

```js
<template>
  <div>
    <div v-if="comments.length > 0">
      <h4>Comments</h4>
      <div v-for="c of comments" :key="c.id">
        {{c.user && c.user.login}} - {{c.body}}
      </div>
    </div>
  </div>
...
        repo,
        issue_number: issueNumber,
      });
      this.comments = comments;
    }
  },
  watch: {
    owner() {
      this.getIssueComments();
    },
    repo() {
      this.getIssueComments();
    },
    issueNumber() {
      this.getIssueComments();
    }
  }
};
</script>
```

在这个组件中，我们有一个`template`部分和一个`script`部分。`script`部分包含了从问题中获取评论的逻辑。`name`属性包含了我们组件的名称。我们可以在其他组件中使用这个名称来引用我们的组件。`props`属性包含了组件接受的 props，如下面的代码片段所示：

```js
  props: {
    owner: {
      type: String,
      required: true,
    },
    repo: {
      type: String,
      required: true,
    },
    issueNumber: {
      type: Number,
      required: true,
    },
  },
```

该组件接受`owner`、`repo`和`issueNumber`三个 props。我们使用一个对象来定义 props，这样我们可以通过`type`属性轻松验证类型。`owner`和`repo`的类型值为`String`，因此它们必须是字符串。`issueNumber`属性的类型值设置为`Number`，因此它必须是一个数字。

`required`属性被设置为`true`，这意味着当我们在另一个组件中使用`Comments`组件时，必须设置这个`prop`。

`data()`方法用于返回一个具有响应式属性初始值的对象。`comments`响应式属性的初始值设置为空数组。

`mixins`属性让我们设置要合并到我们应用程序中的 mixin。由于`octokitMixin`有一个`methods`属性，其中的内容将被添加到我们组件的`methods`属性中，以便我们可以直接调用组件，就像我们将在这个组件的`methods`属性中所做的那样。

我们将 mixin 合并到我们的组件对象中，如下所示：

```js
mixins: [octokitMixin],
```

在`methods`属性中，我们的`Comments`组件有一个方法。我们使用`getIssueComments()`方法来获取问题的评论。其代码如下所示：

```js
  ...
  methods: {  
    ...
    async getIssueComments(owner, repo, issueNumber) {
      if (
        typeof owner !== "string" ||
        typeof repo !== "string" ||
        typeof issueNumber !== "number"
      ) {
        return;
      }
      const octokit = this.createOctokitClient();
      const { data: comments } = await 
        octokit.issues.listComments({
        owner,
        repo,
        issue_number: issueNumber,
      });
      this.comments = comments;
    },
    ...
  }
  ...
}
```

我们需要`owner`、`repo`和`issueNumber`属性。`owner`参数是拥有存储库的用户的用户名，`repo`参数是存储库名称，`issueNumber`参数是问题的问题编号。

我们检查每个类型，以确保它们是我们期望的类型，然后才使用`octokit.issue.listComments()`方法发出获取问题的请求。Octokit 客户端是通过我们的 mixin 的`createOctokitClient()`方法创建的。`listComments()`方法返回一个解析带有评论数据的问题的 promise。

之后，我们有 `watch` 属性来添加我们的监视器。属性的键是我们正在监视的 props 的名称。每个对象都有一个 `immediate` 属性，它使监视器在组件加载时立即开始监视。`handler` 方法具有在 prop 值更改或组件加载时运行的处理程序，因为我们将 `immediate` 属性设置为 `true`。

我们从此处的属性中传入所需的值，以及 `val` 来调用 `getIssueComments()` 方法。`val` 参数具有我们正在监视的任何 prop 的最新值。这样，如果我们设置了所有 prop 的值，我们总是可以获得最新的评论。

在模板中，我们通过引用 `comments` 响应式属性来加载评论。值是由在监视器中运行的 `getIssueComments()` 方法设置的。使用 `v-for` 指令，我们循环遍历每个项目并呈现值。`c.user.login` 属性具有发布评论的用户的用户名，`c.body` 具有评论的正文。

接下来，我们将以下代码添加到 `src/components/Issues.vue` 文件中：

```js
...
<script>
import { octokitMixin } from "../../mixins/octokitMixin";
import IssueComments from "./issue/Comments.vue";
export default {
  name: "RepoIssues",
  components: {
    IssueComments,
  },
  props: {
    owner: {
      type: String,
      required: true,
    },
    repo: {
      type: String,
      required: true,
    },
  },
  mixins: [octokitMixin],
  ...
};
</script>
```

上述代码为显示问题添加了一个组件。在 `Comments.vue` 组件中我们有类似的代码。我们使用相同的 `octokitMixin` 混合来整合来自混合的 `createOctokitClient()` 方法。

不同之处在于我们有 `getRepoIssues()` 方法来获取给定 GitHub 存储库的问题，而不是给定问题的评论，并且我们有两个 props 而不是三个。`owner` 和 `repo` props 都是字符串，并且我们以相同的方式将它们设置为必需的并验证它们的类型。

在 `data()` 方法中，我们有 `issues` 数组，当我们调用 `getRepoIssues` 时设置。这在以下代码片段中显示：

src/components/Issues.vue

```js
  data() {
    return {
      issues: [],
      showIssues: false,
    };
  },
```

`octokit.issues.listForRepo()` 方法返回一个解析给定存储库的问题的 promise。`showIssue` 响应式属性让我们切换是否显示问题。

我们还有获取 GitHub 问题的方法，如下面的代码片段所示：

src/components/Issues.vue

```js
  methods: {
    async getRepoIssues(owner, repo) {
      const octokit = this.createOctokitClient();
      const { data: issues } = await 
        octokit.issues.listForRepo({
        owner,
        repo,
      });
      this.issues = issues;
    },
  },
```

`showIssues` 响应式属性由 **显示问题** 按钮控制。我们使用 `v-if` 指令在 `showIssues` 响应式属性为 `true` 时显示问题。外部的 `div` 标签用于检查问题的长度属性，这样当长度大于 `0` 时，我们只显示 **显示问题** 按钮和问题列表。

该方法由观察者触发，如下所示：

src/components/Issues.vue

```js
  watch: {
    owner: {
      handler(val) {
        this.getRepoIssues(val, this.repo);
      },
    },
    repo: {
      handler(val) {
        this.getRepoIssues(this.owner, val);
      },
    },
  },
  created () {
    this.getRepoIssues(this.owner, this.repo);
  }
```

在`components`属性中，我们将导入的`IssueComments`组件（之前创建的组件）放入我们的组件对象中。如果我们将组件放入`components`属性中，那么它将在组件中注册，我们可以在模板中使用它。

接下来，我们按如下方式将模板添加到文件中：

src/components/Issues.vue

```js
<template>
  <div v-if="issues.length > 0">
    <button @click="showIssues = !showIssues">{{showIssues 
       ? 'Hide' : 'Show'}} issues</button>
    <div v-if="showIssues">
      <div v-for="i of issues" :key="i.id">
        <h3>{{i.title}}</h3>
        <a :href="i.url">Go to issue</a>
        <IssueComments :owner="owner" :repo="repo" 
          :issueNumber="i.number" />
      </div>
    </div>
  </div>
</template>
```

当我们使用`v-for`指令时，需要包括`key`属性，以便正确显示条目，以便 Vue 3 跟踪它们。`key`的值必须是唯一的 ID。我们在模板中引用了我们注册的`IssueComments`组件，并向其传递了`props`。`:`符号是`v-bind`指令的简写，表示我们正在向组件传递 props，而不是设置属性。

## 让用户使用 GitHub 令牌访问 GitHub 数据

接下来，我们将在`src/components/GitHubTokenForm.vue`文件上进行工作，如下所示：

```js
<template>
  <form @submit.prevent="saveToken">
    <div>
      <label for="githubToken">Github Token</label>
      <br />
      <input id="githubToken" v-model="githubToken" />
    </div>
    <div>
      <input type="submit" value="Save token" />
      <button type="button" @click="clearToken">Clear token
         </button>
...
    clearToken() {
      localStorage.clear();
    },
  },
};
</script>
```

我们有一个表单，其中有一个输入框，让我们输入 GitHub 访问令牌。这样，我们可以在提交表单时保存它。此外，我们还有一个类型为`submit`的输入框。它的`value`属性显示为**提交**按钮的文本。我们还有一个按钮，可以让我们清除令牌。`@submit.prevent`指令让我们运行`saveToken`提交处理程序，并同时调用`event.preventDefault()`。`@`符号是`v-on`指令的简写，它监听表单发出的提交事件。

文本输入框具有`v-model`指令，将输入值绑定到`githubToken`响应式属性。为了使我们的输入对屏幕阅读器可访问，我们有一个带有`for`属性的标签，引用输入框的 ID。标签之间的文本显示在标签中。

表单提交后，`saveToken()`方法将运行，将输入的值保存到本地存储中，键为`github-token`字符串。`created()`方法是一个生命周期钩子，让我们可以从本地存储中获取值。通过访问具有`github-token`键的项目，可以获取保存的令牌。

`clearToken()`方法用于清除令牌，并在单击**清除令牌**按钮时运行。

接下来，我们将以下代码添加到`src/components/Repos.vue`组件中：

```js
<template>
  <div>
    <h1>Repos</h1>
    <div v-for="r of repos" :key="r.id">
      <h2>{{r.owner.login}}/{{r.name}}</h2>
      <Issues :owner="r.owner.login" :repo="r.name" />
    </div>
  </div>
</template>
<script>
import Issues from "./repo/Issues.vue";
import { octokitMixin } from "../mixins/octokitMixin";
export default {
  name: "Repos",
  components: {
    Issues,
  },
  data() {
    return {
      repos: [],
    };
  },
  mixins: [octokitMixin],
  async mounted() {
    const octokit = this.createOctokitClient();
    const { data: repos } = await 
       octokit.request("/user/repos");
    this.repos = repos;
  },
};
</script>
```

我们使用`octokit.request()`方法向 GitHub REST API 的`/user/repos`端点发出请求。再次，`octokit`对象是使用之前使用的相同的 mixin 创建的。我们注册`Issues`组件，以便我们可以使用它来显示代码存储库的问题。我们循环遍历`repos`响应式属性，该属性被分配了`octokit.request()`方法的值。

数据在模板中呈现。`r.owner.login`属性具有 GitHub 存储库所有者的用户名，`r.name`属性具有存储库名称。我们将这两个值作为 props 传递给`Issues`组件，以便`Issues`组件加载给定存储库的问题。

同样，在`src/components/User.vue`文件中，我们编写以下代码：

```js
<template>
  <div>
    <h1>User Info</h1>
    <ul>
      <li>
        <img :src="userData.avatar_url" id="avatar" />
      </li>
      <li>username: {{userData.login}}</li>
      <li>followers: {{userData.followers}}</li>
      <li>plan: {{userData.pla && userData.plan.name}}</li>
    </ul>
  </div>
...
    const { data: userData } = await 
      octokit.request("/user");
    this.userData = userData;
  },
};
</script>
<style scoped>
#avatar {
  width: 50px;
  height: 50px;
}
</style>
```

`scoped`关键字意味着样式仅应用于当前组件。

该组件用于显示我们可以从 GitHub 访问令牌访问的用户信息。我们使用相同的 mixin 为 Octokit 客户端创建`octokit`对象。通过调用`request()`方法，向用户端点发出请求以获取用户数据。

然后，在模板中，我们使用`avatar_url`属性显示用户数据。`username.login`属性具有令牌所有者的用户名，`userData.followers`属性具有用户的关注者数量，`userData.plan.name`属性具有计划名称。

最后，为了将整个应用程序放在一起，我们在`App.vue`组件中使用`GitHubTokenForm`，`User`和`Repo`组件。`App.vue`组件是加载应用程序时加载的`root`组件。

在`src/App.vue`文件中，我们编写以下代码：

```js
<template>
  <div>
    <h1>Github App</h1>
    <GitHubTokenForm />
    <User />
    <Repos />
  </div>
</template>
<script>
import GitHubTokenForm from "./components/GitHubTokenForm.vue";
import Repos from "./components/Repos.vue";
import User from "./components/User.vue";
export default {
  name: "App",
  components: {
    GitHubTokenForm,
    Repos,
    User,
  },
};
</script>
```

我们通过将它们放在`components`属性中注册所有三个组件来注册它们。然后，我们在模板中使用它们。

现在，我们应该看到以下屏幕：

![图 2.1 - 仓库列表](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-ex/img/Figure_2.1_B14405.jpg)

图 2.1 - 仓库列表

我们看到显示的存储库列表，如果有为它们记录的问题，我们会看到**显示问题**按钮，让我们看到给定存储库的任何问题。这可以在以下截图中看到：

![图 2.2 - 显示问题按钮](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-ex/img/Figure_2.2_B14405.jpg)

图 2.2 - 显示问题按钮

我们可以点击**隐藏问题**来隐藏它们。如果有任何评论，那么我们应该在问题下面看到它们。

# 提供 PWA

现在我们已经构建了应用程序，我们可以提供它，以便我们可以在浏览器中安装它。让我们开始，如下所示：

1.  要构建该应用程序，我们运行以下命令：

```js
npm run build
```

1.  我们可以使用`browser-sync`包，通过运行以下命令来安装它：

```js
npm install –g browser-sync
```

上述命令将安装一个 Web 服务器。

1.  我们可以进入`dist`文件夹，其中包含构建的文件，并运行`browser-sync`来提供 PWA。

1.  现在，要运行应用程序，我们需要从我们的 GitHub 帐户获取 GitHub 身份验证令牌。如果您没有 GitHub 帐户，那么您将不得不注册一个。

1.  一旦我们创建了一个帐户，那么我们就可以获得令牌。要获取令牌，请登录到您的 GitHub 帐户。

1.  前往[`github.com/settings/tokens`](https://github.com/settings/tokens)。

1.  页面加载完成后，点击**个人访问令牌**链接。

1.  点击**生成新令牌**以生成令牌。一旦创建，将令牌复制到某个地方，以便我们可以通过在应用程序中输入它来使用它。

我们应该看到类似这样的东西：

![图 2.3 – 获取令牌的屏幕](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-ex/img/Figure_2.3_B14405.jpg)

图 2.3 – 获取令牌的屏幕

1.  一旦您获得了令牌，返回到我们在浏览器中加载的应用程序。

1.  将令牌输入到**GitHub Token**输入中，点击**保存令牌**，然后刷新页面。如果有任何存储库以及相关问题和评论，它们应该显示在页面中。

1.  一旦我们在浏览器中，我们应该在 URL 栏的右侧看到一个加号（**+**）标志。这个按钮让我们安装 PWA。

1.  一旦我们安装它，我们应该在主屏幕上看到它。我们可以转到`chrome://apps` URL，以查看我们刚刚安装的应用程序，如下截图所示：![图 2.4 – 我们 PWA 中的 GitHub 存储库列表](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-ex/img/Figure_2.4_B14405.jpg)

图 2.4 – 我们 PWA 中的 GitHub 存储库列表

1.  如果您使用的是 Chrome 或任何其他 Chromium 浏览器，如 Edge，您可以按下*F12*打开开发者控制台。

1.  点击**应用程序**选项卡，然后点击左侧的**服务工作者**链接，让我们测试服务工作者，如下截图所示：![图 2.5 – 应用程序选项卡中的服务工作者部分](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-ex/img/Figure_2.5_B14405.jpg)

图 2.5 – 应用程序选项卡中的服务工作者部分

1.  我们可以选中**离线**复选框，模拟它在离线时的行为。选中**重新加载时更新**将在刷新页面时重新加载应用程序，并获取最新的数据。URL 应该与您的应用程序运行的 URL 相同。这是我们的 GitHub PWA 注册的服务工作者。

1.  **注销**链接将注销服务工作者。当我们再次运行应用程序时，应该重新注册它。

我们现在已经完成了使用 Vue 3 创建我们的渐进式 Web 应用程序。我们可以在浏览器中安装它，然后像设备上的任何其他应用程序一样使用它。

# 总结

通过构建 GitHub PWA，我们学会了如何创建可重用的组件。我们还研究了如何添加 props，以便从父组件向子组件传递数据。在子组件中，我们通过检查数据类型并指定 prop 是否必需来验证 props。这样，我们可以轻松地看到 prop 是否具有意外的值。

我们还研究了如何使用观察者来监视响应式属性值的变化。观察者可以添加以监视任何响应式属性的变化。我们可以监视本地被改变的数据，也可以监视 props 的值。它们都是响应式的，因此它们都会触发观察者方法。我们可以在观察者中运行异步代码，这是计算属性无法做到的。

此外，我们还研究了组件的生命周期钩子。每个组件也有自己的生命周期钩子。我们可以向生命周期方法中添加我们自己的代码，以便在需要时运行代码。组件生命周期的各个阶段都有生命周期钩子，包括加载时的开始阶段，更新和销毁。

最后，我们学会了如何使用命令行插件将我们的 Vue 3 web 应用程序转换为 PWA。我们可以向我们的 Vue 项目添加插件来创建 PWA。通过它，服务工作者将在我们的应用程序中注册，以处理不同的连接类型和缓存。

在下一章中，我们将使用 Vue 3 创建一个滑块拼图，并编写自动化测试来测试应用程序的每个部分。


# 第三章：使用测试构建滑块拼图游戏

在上一章中，我们使用 Vue 创建了一个简单的 GitHub 应用，并添加了一些组件。在本章中，我们将构建一个简单的滑块拼图游戏。游戏的目标是重新排列图片的部分，直到它看起来像我们期望的样子。它将有一个计时器来计算经过的时间，并在屏幕上显示出来。一旦我们正确地重新排列了图像的部分，我们将看到一个“你赢了”的消息，并且如果它是前 10 名最快的时间，经过的时间将被记录在本地存储中。我们有多个拼图可以选择，这样我们的游戏就会更加有趣。这比只有一个拼图更有趣。

为了构建应用程序，我们将构建具有计算属性和计时器的组件来计算经过的时间。此外，一些组件将从本地存储中获取和设置数据。每当我们从本地存储中获取数据时，结果将被显示出来。我们将使用本地存储来存储最快的时间。本地存储只能存储字符串，因此我们将把结果转换为字符串并存储起来。

我们将使用计时器来计时玩家赢得游戏的时间，并使用计算属性来确定玩家赢得游戏的时间。此外，为了确保我们的游戏能够正常运行，我们将为每个部分添加单元测试，以自动测试每个组件。

在本章中，我们将深入研究组件，并涵盖以下主题：

+   理解组件和混合的基础知识

+   设置我们的 Vue 项目

+   创建用于洗牌图片的组件

+   让用户重新排列幻灯片

+   根据时间计算得分

+   使用 Jest 进行单元测试

# 技术要求

本章的源代码位于[`github.com/PacktPublishing/-Vue.js-3-By-Example/tree/master/Chapter03`](https://github.com/PacktPublishing/-Vue.js-3-By-Example/tree/master/Chapter03)。

# 理解组件和混合的基础知识

组件还有比我们在*第二章*中所做的更多，*构建一个 Vue 3 渐进式 Web 应用*，来创建 GitHub 渐进式 Web 应用。这些组件是最基本的部分。我们将在我们的组件中使用定时器，而不仅仅是获取数据并显示它的组件。此外，我们将看看何时以及如何使用计算属性，以便我们可以创建从其他响应式属性派生值的响应式属性。这样可以避免创建我们不需要的额外方法或不必要地使用指令。

此外，我们将看看如何使用计算属性来返回从其他响应式属性派生的值。**计算属性**是返回值的方法，这些值是从一个或多个其他响应式属性派生而来的。它们本身也是响应式属性。它们最常见的用法是作为 getter。然而，计算属性既可以有 getter 也可以有 setter。它们的返回值被缓存，以便在一个或多个响应式属性的值更新之前不会运行。它们可用于以高效的方式替换复杂的模板表达式和方法。

组件还可以发出自定义事件。一个事件可以包含一个或多个与事件一起发出的有效负载。它们有自己的事件名称，我们可以通过使用`v-on`指令来监听事件。我们可以使用`$event`变量或事件处理程序方法的参数来获取发出的有效负载。

Vue 3 应用的另一个重要部分是**测试**。当我们提到测试时，通常是指自动化测试。测试有许多形式，对捕捉各种类型的错误都很有用。它们经常用于捕捉回归，即在我们更改已经成为应用一部分的代码后创建的错误。我们可以通过几种测试来检查回归。我们可以创建的最小测试是**单元测试**，它测试一个组件及其部分的隔离。它通过在测试环境中挂载我们的组件来工作。任何阻止我们的测试隔离运行的依赖项都被模拟，以便我们可以在隔离环境中运行我们的测试。这样，我们可以在任何环境和任何顺序下运行我们的测试。

每个测试都是独立的，所以我们不应该在任何地方运行它们时出现任何问题，即使没有互联网连接。这很重要，因为它们应该是可移植的。此外，诸如 API 数据和定时器之类的外部资源非常不稳定。它们也是异步的，这使它们难以测试。因此，我们必须确保我们的测试不需要它们，因为我们希望结果是一致的。

Vue 支持 JavaScript 测试框架，如**Jest**和**Mocha**。这是使用 Vue CLI 创建 Vue 项目的一个巨大好处。我们不必自己创建所有测试代码的脚手架。

另一种测试是*端到端*测试。这些测试模拟用户如何使用我们的应用程序。我们通常会创建一个从头开始然后关闭的环境来运行这些测试。这是因为我们希望我们的测试中始终有新鲜的数据。测试必须能够以一致的方式运行。如果我们要像用户一样使用应用程序，我们需要一致的数据来完成这项工作。

在本章中，我们将主要关注前端应用程序的单元测试。它们可以提供类似于端到端测试的 DOM 交互，但它们更快速，体积更小。它们也运行得更快，因为我们不必每次运行测试时都创建一个干净的环境。环境的创建和用户交互测试总是比单元测试慢。因此，我们应该有许多单元测试和少量端到端测试，用于测试应用程序最关键的部分。

# 设置 Vue 项目

现在我们已经学会了计算属性和 getter 和 setter 的基础知识，我们准备深入研究我们将需要的组件部分并创建项目。

要创建项目，我们再次使用 Vue CLI。这次，我们必须选择一些选项，而不是选择默认选项。但在这之前，我们将创建一个名为`vue-example-ch3-slider-puzzle`的项目文件夹。然后，我们必须进入文件夹并使用`npm`运行以下命令：

1.  首先，我们必须全局安装 Vue CLI，以便我们可以使用它创建和运行我们的项目：

```js
npm install -g @vue/cli@next
```

1.  现在，我们可以进入我们的项目文件夹并运行以下命令来创建我们的项目：

```js
vue create .
```

同样地，我们可以使用 Yarn 运行以下命令：

1.  首先，我们必须全局安装 Vue CLI，以便我们可以使用它创建和运行我们的项目：

```js
yarn global add @vue/cli@next
```

1.  然后，我们可以进入我们的项目文件夹并运行以下命令来创建我们的项目：

```js
yarn create .
```

无论哪种情况，我们都应该看到 Vue CLI 命令行程序并获得如何选择项目的说明。如果我们被问及是否要在当前文件夹中创建项目，我们可以输入*Y*并按*Enter*来执行。然后，我们应该看到我们可以使用的项目类型，我们应该选择`Manually select features`，然后选择`Vue 3`来创建一个 Vue 3 项目：

![图 3.1 - 在 Vue CLI 向导中创建项目类型的选择](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-ex/img/Figure_3.1_B14405.jpg)

图 3.1 - 在 Vue CLI 向导中创建项目类型的选择

在下一个屏幕上，我们应该看到我们可以添加到项目中的内容。选择`Unit` `Testing`，然后您需要选择`Testing` `with` `Jest`，这样我们就可以为我们的应用程序添加测试。

一旦我们完成了编写代码，这个项目将为许多组件提供测试：

![图 3.2 - 我们应该为这个项目选择的选项](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-ex/img/Figure_3.2_B14405.jpg)

图 3.2 - 我们应该为这个项目选择的选项

一旦我们让 Vue CLI 完成项目的创建，我们应该在`src`文件夹中看到代码文件。测试应该在`tests/unit`文件夹中。Vue CLI 为我们节省了大量精力，因为我们不需要自己编写测试代码。它带有一个我们可以扩展的示例测试。

一旦我们选择了这些选项，我们就可以开始创建我们的应用程序。在这个项目中，我们将从 Unsplash 获取一些图片，该网站为我们提供了免版税的图片。然后，我们将获取这些图片并将它们分成九个部分，以便我们可以在`slider puzzle`组件中显示它们。我们需要整张图片和切割后的部分。在这个例子中，我们将从以下链接获取图片：

+   [`unsplash.com/photos/EfhCUc_fjrU`](https://unsplash.com/photos/EfhCUc_fjrU)

+   [`unsplash.com/photos/CTvtrspsPQs`](https://unsplash.com/photos/CTvtrspsPQs)

+   [`unsplash.com/photos/XoCyW2JVmiE`](https://unsplash.com/photos/XoCyW2JVmiE)

当我们进入每个页面时，我们必须点击**下载**按钮来下载图片。一旦我们下载了图片，我们必须转到[`www.imgonline.com.ua/eng/cut-photo-into-pieces.php`](https://www.imgonline.com.ua/eng/cut-photo-into-pieces.php)自动将图片切成九块。

在*section 1*中，我们选择我们的图片文件。在*section 2*中，我们将**宽度分成的部分**和**高度分成的部分**都设置为`3`。这样，我们可以将我们的图片分成九个部分。一旦我们做到了这一点，我们就可以下载生成的 ZIP 文件，然后将所有的图片提取到一个文件夹中。这应该对每个图片都重复进行。

一旦我们有了所有的整个和切割的图像片段，我们应该把它们都放到我们刚刚创建的 Vue 3 项目文件夹的`src/assets`文件夹中。这样，我们就可以从我们的应用程序访问并显示这些图像。第一张图片显示了一朵粉色的花，所以整个图片被命名为`pink.jpg`，切割后的图片在`cut-pink`文件夹中。生成的切割图片的文件名保持不变。第二张图片是一朵紫色的花，所以整个图片被命名为`purple.jpg`，切割后的图片文件夹被命名为`cut-purple`。第三张图片是一朵红色的花。因此，它被命名为`red.jpg`，包含图像切割片段的文件夹被命名为`cut-red`。

现在我们已经处理了图片，我们可以创建我们的组件。

首先，我们必须从`src/components`文件夹中删除`HelloWorld.vue`，因为我们不再需要它了。我们还必须从`App.vue`文件中删除对它的任何引用。

接下来，在`components`文件夹中，我们必须创建`Puzzles.vue`文件，以便让我们选择拼图。它有一个模板，这样我们就可以显示我们选择的拼图。在`component options`对象中，我们有一个包含要显示的拼图数据的数组。此外，我们有一个方法，让我们向我们的父组件发出事件，即`App.vue`组件。这样，我们就可以在我们将创建的滑块拼图组件中显示正确的拼图。为此，在`src/components/Puzzles.vue`中，我们必须添加以下模板代码：

```js
<template>
  <div>
    <h1>Select a Puzzle</h1>
    <div v-for="p of puzzles" :key="p.id" class="row">
      <div>
        <img :src="require(`../assets/${p.image}`)" />
      </div>
      <div>
        <h2>{{p.title}}</h2>
      </div>
      <div class="play-button">
        <button @click="selectPuzzle(p)">Play</button>
      </div>
    </div>
  </div>
</template>
```

然后，我们必须添加以下脚本和样式标签：

```js
<script>
export default {
  data() {
    return {
      puzzles: [
        { id: 'cut-pink', image: "pink.jpg", title: "Pink 
          Flower" },
        { id: 'cut-purple', image: "purple.jpg", title: 
          "Purple Flower" },
        { id: 'cut-red', image: "red.jpg", title: "Red 
          Flower" },
      ],
    };
  },
...
<style scoped>
.row {
  display: flex;
  max-width: 90vw;
  flex-wrap: wrap;
  justify-content: space-between;
}
.row img {
  width: 100px;
}
.row .play-button {
  padding-top: 25px;
}
</style>
```

在脚本标签之间，我们有`component options`对象，其中包含`data()`方法，以及在脚本标签之间的拼图的响应属性。它有一个包含`id`、`image`和`title`属性的对象数组。`id`属性是一个唯一的 ID，我们在使用`v-for`指令渲染条目时使用它。我们还向`App.vue`发出 ID，这样我们就可以从那里将其作为属性传递给我们的滑块拼图组件。`title`是我们以人类可读的方式在模板中显示的标题。

在`methods`属性中，我们有一个`selectPuzzle()`方法，它接受谜题对象作为参数。它调用`this.$emit`来触发 puzzle-changed 事件。第一个参数是`name`。第二个参数是我们想要在事件中触发的`payload`属性。我们可以通过在父组件中为元素添加`v-on`指令来监听事件，无论这个组件在哪里被引用。

在模板中，我们使用`h1`组件显示`title`。`v-for`指令循环遍历谜题的`array`响应属性中的项目并显示它们。像往常一样，我们需要为每个条目设置`key`属性，以便为 Vue 3 正确跟踪值设置唯一 ID。我们还必须添加一个`class`属性，以便我们可以样式化行。要显示图像，我们可以调用`require`，这样 Vue 3 可以直接解析路径。Vue CLI 使用 Webpack，因此它可以将图像作为模块加载。我们可以将其设置为`src`属性的值，它将显示图像。我们加载整个图像并显示它们。

此外，在行中，我们有一个按钮，当我们点击它时调用`selectPuzzle()`方法。这将设置谜题的选择并将其传播到我们将创建的滑块谜题组件，以便我们可以看到正确的谜题显示。

`.row img select`的宽度设置为`100px`，以显示整个图像的缩略图。此外，我们可以以一种与其他子元素对齐的方式显示按钮。

接下来，我们必须创建`src/components/Records.vue`文件，以添加一个包含速度记录的组件。这提供了一个最快完成游戏的时间列表。最快的时间记录存储在本地存储中，以便轻松访问。在这个组件中，我们只是显示组件。

要创建这个组件，我们必须在`src/components/Records.vue`中编写以下代码：

```js
<template>
  <div>
    <h1>Records</h1>
    <button @click="getRecords">Refresh</button>
    <div v-for="(r, index) of records" :key="index">{{
      index + 1}} - {{r.elapsedTime}}</div>
  </div>
</template>
<script>
export default {
  data() {
    return {
      records: [],
    };
  },
  created() {
    this.getRecords();
  },
  methods: {
    getRecords() {
      const records = JSON.parse(localStorage.getItem(
        "records")) || [];
      this.records = records;
    },
  },
};
</script>
```

在`component`对象中，我们有`getRecords()`方法，它从本地存储中获取最快的时间记录。`localStorage.getItem()`方法通过其键获取数据。参数是映射到我们想要获取的数据的键。它返回一个包含数据的字符串。因此，为了将字符串转换为对象，我们必须调用`JSON.parse`将 JSON 字符串解析为对象。它应该是一个数组，因为我们将创建一个数组并将其字符串化为 JSON 字符串，然后记录它。本地存储只能保存字符串；因此，这是一个必需的步骤。

一旦我们从本地存储中检索到记录，我们可以将其设置为`this.records`响应式属性的值。如果本地存储中没有带有`records`键的项目，我们必须将默认值设置为空数组。这样，我们总是将一个数组分配给`this.records`。

此外，我们还有`beforeMount`钩子，它让我们在组件挂载之前获取记录。这样，当组件挂载时，我们将看到记录。

在模板中，我们使用`v-for`指令显示速度记录，以循环遍历项目并显示它们。数组条目中的`v-for`指令在括号中有第一个项目。括号中的第二个项目是索引。我们可以将`key`属性设置为索引，因为它们是唯一的，而且我们不会移动条目。我们在列表中显示两者。

此外，我们有一个按钮，当我们点击它时调用`getRecords`方法以获取最新条目。

现在我们已经创建了最简单的组件，我们可以继续创建滑块拼图组件。

# 创建洗牌图片的组件

滑块拼图游戏提供了滑块拼图，玩家将拼图洗牌成图片以赢得比赛，显示经过的时间，重新排列拼图的逻辑，检查我们是否赢得比赛的逻辑，以及计算自游戏开始以来经过的时间的计时器。

为了轻松计算经过的时间，我们可以使用`moment`库。要安装该库，我们可以运行`npm install moment`。一旦我们安装了包，我们就可以开始编写必要的代码。

让我们创建`src/components/SliderPuzzle.vue`文件。该文件的完整代码可以在[`github.com/PacktPublishing/-Vue.js-3-By-Example/blob/master/Chapter03/src/components/SliderPuzzle.vue`](https://github.com/PacktPublishing/-Vue.js-3-By-Example/blob/master/Chapter03/src/components/SliderPuzzle.vue)找到。

我们将首先通过`script`标签创建组件：

```js
<script>
import moment from "moment";
const correctPuzzleArray = [
  "image_part_001.jpg",
  "image_part_002.jpg",
  "image_part_003.jpg",
  "image_part_004.jpg",
  "image_part_005.jpg",
  "image_part_006.jpg",
  "image_part_007.jpg",
  "image_part_008.jpg",
  "image_part_009.jpg",
];
...
</script>
```

首先，我们导入`moment`库来计算经过的时间。接下来，我们定义`correctPuzzleArray`变量，并将其分配给一个具有文件正确顺序的数组。我们根据这个数组来确定玩家是否赢得了比赛。

然后，我们开始创建组件选项的对象。`props`属性包含我们自己的属性。`puzzleId`是一个包含玩家正在玩的谜题的 ID 的字符串。我们必须确保它是一个字符串。我们将其默认值设置为`'cut-pink'`，这样我们就始终有一个谜题集。

`data()`方法包含我们的初始状态。我们返回一个包含它们的对象。这样，我们可以确保响应属性的值始终与我们应用程序中的其他组件隔离。`correctPuzzleArray`响应属性就是我们之前定义的。我们只是将其设置为一个属性，使其成为一个响应属性。这使它可以与我们的`isWinning`计算属性一起使用，因为我们希望在此数组更新时更新值：

```js
<script>
...
export default {
  name: "SliderPuzzle",
  props: {
    puzzleId: {
      type: String,
      default: "cut-pink",
    },
  },
  data() {
    return {
      correctPuzzleArray,
      shuffledPuzzleArray: [...correctPuzzleArray].sort(
        () => Math.random() - 0.5
      ),
      indexesToSwap: [],
      timer: undefined,
      startDateTime: new Date(),
      currentDateTime: new Date(),
    };
  },
  ...
};
</script>
```

`shuffledPuzzleArray`是`correctPuzzleArray`响应属性的副本，但项目被洗牌，以便玩家必须重新排列项目才能赢得游戏。为了创建属性的值，首先我们必须用扩展运算符复制`correctPuzzleArray`数组。然后，我们必须使用`callback`调用`sort`。`callback`是一个使用`Math.random()`生成介于`-0.5`和`0.5`之间的数字的函数。我们需要一个在这个范围内的随机数，以便值随机排序。`callback`是一个比较函数。它可以接受两个参数；也就是说，前一个和当前数组条目，这样我们就可以比较它们：

```js
<script>
...
export default {
  ...
  computed: {
    isWinning() {
      for (let i = 0; i < correctPuzzleArray.length; i++) {
        if (correctPuzzleArray[i] !== 
          this.shuffledPuzzleArray[i]) {
          return false;
        }
      }
      return true;
    },
    elapsedDiff() {
      const currentDateTime = moment(this.currentDateTime);
      const startDateTime = moment(this.startDateTime);
      return currentDateTime.diff(startDateTime);
    },
    elapsedTime() {
      return moment.utc(this.elapsedDiff).format(
        "HH:mm:ss");
    },
  },
};
</script>
```

由于我们是随机排序物品，所以不需要进行任何比较。如果比较器回调返回负数或`0`，则项目的顺序不变。否则，我们要排序的数组中的项目顺序会改变。`sort()`方法返回一个按顺序排列的新数组。

`indexesToSwap`响应属性用于添加我们想要交换的图像文件名的索引。当我们点击`swap()`方法时，我们向`indexesToSwap`响应属性推送一个新值，这样当`indexesToSwap`数组中有两个项目时，我们就可以交换这两个项目。

`timer`响应属性可能包含由`setInterval`函数返回的计时器对象。`setInterval`函数让我们周期性地运行代码。它接受一个包含我们想要运行的代码的回调作为第一个参数。第二个参数是回调之间的时间间隔，以毫秒为单位。

`startDateTime`响应属性包含游戏开始时的日期和时间。它是一个包含当前时间的`Date`实例。`currentDateTime`响应属性具有当前日期和时间的`Date`实例。随着游戏在我们传递给`setInterval`函数的`callback`属性中进行处理，它会被更新。

`data()`方法包含了所有响应式属性的初始值。

`computed`属性包含了计算属性。计算属性是同步函数，返回一些基于其他响应式属性的值。计算属性本身也是响应式属性。当计算属性函数中引用的响应式属性更新时，它们的值也会更新。在这个组件中，我们定义了三个计算属性：`isWinning`、`elapsedDiff`和`elapsedTime`。

`isWinning`计算属性是包含游戏状态的属性。如果它返回`true`，那么玩家赢得了游戏。否则，玩家还没有赢得游戏。为了检查玩家是否赢得了游戏，我们循环遍历`correctPuzzleArray`响应式属性，并检查它的每个条目是否与`shuffledPuzzleArray`响应式属性数组中的条目相同。

`correctPuzzleArray`包含了正确的项目列表。因此，如果`shuffledPuzzleArray`数组的每个项目与`correctPuzzleArray`中的条目匹配，那么我们知道玩家已经赢了。否则，玩家还没有赢。因此，如果`correctPuzzleArray`和`shuffledPuzzleArray`之间有任何差异，那么它返回 false。否则，返回 true。

`elapsedDiff`计算属性计算了经过的时间（毫秒）。这是我们使用`moment`库从`startDateTime`到`currentDateTime`计算经过时间的地方。我们使用`moment`库来进行这个计算，因为它让我们的工作变得更容易。它有一个`diff()`方法，我们可以用它来计算这个和另一个`moment`对象之间的差异。以毫秒为单位返回差异。

一旦我们计算出`elapsedDiff`计算属性，我们就可以使用它来使用`moment`格式化经过的时间为人类可读的时间格式，即 HH:mm:ss。`elapsedTime`计算属性返回一个字符串，其中包含格式化后的经过时间。`moment.utc()`方法是一个函数，它接受一个 UTC 时间段，然后返回一个`moment`对象，我们可以调用`format()`方法来计算时间。

现在我们已经定义了所有的响应式和计算属性，我们可以定义我们的方法，这样我们就可以将幻灯片重新排列成正确的图片。

# 重新排列幻灯片

我们可以通过编写以下代码为`SliderPuzzle.vue`组件添加所需的`methods`：

```js
<script>
...
export default {
  ...
  methods: {
    swap(index) {
      if (!this.timer) {
        return;
      }
      if (this.indexesToSwap.length < 2) {
        this.indexesToSwap.push(index);
      }
      if (this.indexesToSwap.length === 2) {
...
      this.resetTime();
      clearInterval(this.timer);
    },
    resetTime() {
      this.startDateTime = new Date();
      this.currentDateTime = new Date();
    },
    recordSpeedRecords() {
      let records = JSON.parse(localStorage.getItem(
        "records")) || [];
...
      localStorage.setItem("records", stringifiedRecords);
    },
  },
};
</script>
```

逻辑定义在`methods`属性中。我们有`swap()`方法让我们交换切割图像幻灯片。`start()`方法让我们将响应式属性重置为初始状态，洗牌切割照片幻灯片，然后启动计时器计算经过的时间。我们还在每次运行计时器代码时检查玩家是否获胜。`stop()`方法让我们停止计时器。`resetTime()`方法让我们将`startDateTime`和`currentDateTime`重置为它们的当前日期时间。`recordSpeedRecords()`方法让我们记录玩家赢得游戏所花费的时间，如果他们进入前 10 名。

我们从逻辑上交换幻灯片开始，定义`swap()`方法。它接受一个参数，即我们想要交换的幻灯片之一的索引。当玩家点击幻灯片时，将调用此方法。这样，我们将要与另一个幻灯片交换的项目之一的索引添加到`indexesToSwap`计算属性中。因此，如果玩家点击两张幻灯片，它们的位置将彼此交换。

`swap()`方法体检查`indexesToSwap`响应式属性是否包含少于两个幻灯片索引。如果少于两个，则调用`push`将幻灯片追加到`indexesToSwap`数组中。接下来，如果`indexesToSwap`响应式属性数组中有索引，则进行交换。

为了进行交换，我们从`indexToSwap`响应式属性中解构索引。然后，我们再次使用解构赋值进行交换：

```js
[this.shuffledPuzzleArray[index1], this.shuffledPuzzleArray[index2]] = [this.shuffledPuzzleArray[index2], this.shuffledPuzzleArray[index1]];
```

要交换数组中的项目，我们只需将`shuffledPuzzleArray`的`index2`分配给`index1`的项目。然后，原本在`shuffledPuzzleArray`的`index1`处的项目以相同的方式放入`shuffledPuzzleArray`的`index2`槽中。最后，我们确保清空`indexesToSwap`数组，以便让玩家交换另一对幻灯片。由于`shuffledPuzzleArray`是一个响应式属性，它会随着模板中的`v-for`指令更新而自动呈现在模板中。

`start()`方法让我们可以启动计时器，计算从点击**开始**按钮开始游戏到游戏结束或用户点击**退出**按钮时的经过时间。首先，该方法通过将这些值设置为当前日期时间来重置`startDateTime`和`currentDateTime`响应式属性，我们通过实例化`Date`构造函数来获取当前日期时间。然后，我们通过复制`correctPuzzleArray`，然后调用 sort 来对`correctPuzzle`数组的副本进行排序来洗牌幻灯片。此外，我们将`indexesToSwap`属性设置为空数组，以清除任何已存在的项目，使我们可以重新开始。

一旦我们完成了所有重置，我们就可以调用`setInterval`来启动计时器。这将使用当前日期和时间更新`currentDateTime`响应式属性，以便我们可以计算`elapsedDiff`和`elapsedTime`计算属性。接下来，我们检查`isWinning`响应式属性是否为 true。如果是，那么我们就调用`this.recordSpeedRecords`方法来记录玩家获胜时的最快时间。

如果玩家获胜，即`isWinning`为`true`，我们还可以调用`stop()`方法来停止计时器。`stop()`方法只是调用`resetTime()`方法来重置所有时间。然后，它调用`clearInterval`来清除计时器。

要显示滑块拼图，我们可以添加`template`标签：

```js
<template>
  <div>
    <h1>Swap the Images to Win</h1>
    <button @click="start" id="start-button">Start 
      Game</button>
    <button @click="stop" id="quit-button">Quit</button>
    <p>Elapsed Time: {{ elapsedTime }}</p>
    <p v-if="isWinning">You win</p>
    <div class="row">
      <div
        class="column"
        v-for="(s, index) of shuffledPuzzleArray"
        :key="s"
        @click="swap(index)"
      >
        <img :src="require(`../assets/${puzzleId}/${s}`)" 
          />
      </div>
    </div>
  </div>
</template>
```

然后，我们可以通过编写以下代码来添加所需的样式：

```js
<style scoped>
.row {
  display: flex;
  max-width: 90vw;
  flex-wrap: wrap;
}
.column {
  flex-grow: 1;
  width: 33%;
}
.column img {
  max-width: 100%;
}
</style>
```

在`styles`标签中，我们有用于样式化滑块拼图的样式。我们需要滑块拼图，这样我们就可以在一行中显示三个幻灯片，总共三行。这样，我们可以在 3x3 的网格中显示所有幻灯片。`row`类的属性设置为`flex`，这样我们就可以使用 flexbox 来布局幻灯片。我们还将`flex-wrap`属性设置为`wrap`，这样我们就可以将任何溢出的项目包装到下一行。`max-width`设置为`90vw`，这样滑块拼图网格就会保持在屏幕上。

`column`类的`flex-grow`属性设置为`1`，这样它就是在一行中显示的三个项目之一。

在模板中，我们使用`h1`元素显示游戏的`title`。我们有一个**开始游戏**按钮，当我们点击按钮开始游戏计时器时，它调用`start()`方法。此外，我们有一个**退出**按钮，当我们点击它停止计时器时，它调用`stop()`方法。`elapsedTime`计算属性显示方式与其他响应属性相同。如果用户获胜，即`isWinning`响应属性返回 true，我们将看到**'You Win'**消息。

要显示幻灯片，我们只需使用`v-for`指令循环遍历所有`shuffledPuzzleArray`响应属性，并呈现所有幻灯片。当我们点击每个幻灯片时，将调用`swap()`方法并传入索引。一旦我们在`indexesToSwap`响应属性中有两个索引，我们就交换幻灯片。由于它们是唯一的，所以将`key`属性设置为文件名。要显示幻灯片图像，我们使用图像路径调用`require`，以便显示图像。

由于我们有 flexbox 样式来以三行三列的方式显示项目，所有九个图像将自动显示在 3x3 的网格中。现在我们已经完成了滑块拼图游戏逻辑，我们只需要添加记录时间得分的逻辑到本地存储中。

# 根据时间计算得分

这是在`recordSpeedRecords()`方法中完成的。它通过从本地存储中获取具有*键*记录的本地存储项来获取记录。然后，我们获取`elapsedTime`和`elapsedDiff`响应属性的值，并将它们推入`records`数组中。

接下来，我们使用`sort()`方法对记录进行排序。这一次，我们不是随机排序项目，而是按照`elapsedDiff`响应属性的时间跨度进行排序，该时间以毫秒为单位。我们传入一个带有`a`和`b`参数的回调函数，它们分别是先前和当前的数组条目，然后返回它们之间的差异。这样，如果它返回一个负数或 0，那么它们之间的顺序不变。否则，我们交换顺序。然后，我们调用`slice`方法，使用第一个和最后一个索引来包含它在分配给`sortedRecords`常量的返回数组中。`slice()`方法返回一个包含第一个索引的项目一直到最后一个索引减去 1 的数组。

最后，我们使用`JSON.stringify()`方法将数组*stringify*为字符串，将`sortedRecords`数组转换为字符串。然后，我们调用`localStorage.setItem`将该项放入具有`'records'`键的项中。

最后，我们必须将`App.vue`文件的内容更改为以下内容：

```js
<template>
  <div>
    <Puzzles @puzzle-changed="selectedPuzzleId = $event" />
    <Records />
    <SliderPuzzle :puzzleId="selectedPuzzleId" />
  </div>
</template>
<script>
import SliderPuzzle from "./components/SliderPuzzle.vue";
import Puzzles from "./components/Puzzles.vue";
import Records from "./components/Records.vue";
export default {
  name: "App",
  components: {
    SliderPuzzle,
    Puzzles,
    Records,
  },
  data() {
    return {
      selectedPuzzleId: "cut-pink",
    };
  },
};
</script>
```

我们将之前创建的组件添加到屏幕上进行渲染。`selectedPuzzleId`默认情况下具有我们选择的拼图的 ID。

现在我们已经有了所有的代码，如果我们还没有运行过项目，我们可以在项目文件夹中运行`npm run serve`来运行项目。然后，当我们访问 Vue CLI 指示的 URL 时，我们将看到以下内容：

![图 3.3 - 滑块拼图游戏的屏幕截图](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-ex/img/Figure_3.3_B14405.jpg)

图 3.3 - 滑块拼图游戏的屏幕截图

现在我们已经完成了 Web 应用的代码，我们必须找到一种简单的方法来测试它的所有部分。

# 使用 Jest 进行单元测试

测试是任何应用程序的重要部分。当我们提到测试时，通常指的是自动化测试。这些是我们可以快速重复运行的测试，以确保我们的代码没有出错。当任何测试失败时，我们知道我们的代码没有像以前那样工作。要么我们创建了一个 bug，要么测试已经过时。因为我们可以快速运行它们，所以我们可以编写许多测试并在构建代码时运行它们。

这比手动测试要好得多，手动测试必须由一个人一遍又一遍地执行相同的操作。手动测试对测试人员来说很无聊，容易出错，而且非常慢。这对任何人来说都不是一种愉快的体验。因此，最好尽可能多地编写自动化测试，以最小化手动测试。

如果按照 Vue CLI 中显示的说明进行操作，很容易在不进行任何额外工作的情况下添加骨架测试代码。单元测试文件应该会自动生成给我们。我们的代码中应该有一个`tests/unit`文件夹，用于将我们的测试代码与我们的生产代码分开。

**Jest**是一个 JavaScript 测试框架，我们可以用它来运行单元测试。它为我们提供了一个有用的 API，让我们描述我们的测试组并定义我们的测试。此外，我们还可以轻松地模拟通常使用的任何外部依赖项，如定时器、本地存储和状态。要模拟`localStorage`依赖项，我们可以使用`jest-localstorage-mock`包。我们可以通过运行`npm install jest-localstorage-mock –save-dev`来安装它。`–save-dev`标志让我们将包保存为开发依赖项，因此它只会安装在开发环境中，而不会安装在其他地方。此外，在`package.json`文件中，我们将添加一个`jest`属性作为`root`属性。为此，我们可以编写以下代码：

```js
"jest": {
"setupFiles": [
"jest-localstorage-mock"
  ]
}
```

我们在`package.json`中有这些属性，这样当我们运行我们的测试时，`localStorage`依赖项将被模拟，以便我们可以检查它的方法是否已被调用。连同其他属性一起，我们的`package.json`文件应该看起来像以下内容：

```js
{
  "name": "vue-example-ch3-slider-puzzle",
  "version": "0.1.0",
  "private": true,
  "scripts": {
    "serve": "vue-cli-service serve",
    "build": "vue-cli-service build",
    "test:unit": "vue-cli-service test:unit",
    "lint": "vue-cli-service lint"
  },
  "dependencies": {
    "core-js": "³.6.5",
    "lodash": "⁴.17.20",
    "moment": "².28.0",
    "vue": "³.0.0-0"
  },
  "devDependencies": {
...
    "eslint-plugin-vue": "⁷.0.0-0",
    "jest-localstorage-mock": "².4.3",
    "typescript": "~3.9.3",
    "vue-jest": "⁵.0.0-0"
  },
  "jest": {
    "setupFiles": [
      "jest-localstorage-mock"
    ]
  }
}
```

完成后，我们可以添加我们的测试。

## 为 Puzzles.vue 组件添加测试

首先，我们必须从`tests/unit`文件夹中删除现有文件。然后，我们可以开始编写我们的测试。我们可以先为`Puzzles.vue`组件编写测试。为此，我们必须创建`tests/unit/puzzles.spec.js`文件并编写以下代码：

```js
import { mount } from '@vue/test-utils'
import Puzzles from '@/components/Puzzles.vue'
describe('Puzzles.vue', () => {
  it('emit puzzled-changed event when Play button is 
    clicked', () => {
    const wrapper = mount(Puzzles)
    wrapper.find('.play-button button').trigger('click');
    expect(wrapper.emitted()).toHaveProperty('puzzle-
      changed');
  })
  it('emit puzzled-changed event with the puzzle ID when 
    Play button is clicked', () => {
    const wrapper = mount(Puzzles)
    wrapper.find('.play-button button').trigger('click');
    const puzzleChanged = wrapper.emitted('puzzle-
      changed');
    expect(puzzleChanged[0]).toEqual([wrapper.vm.puzzles[0].id]
 );
  })
})
```

`describe`函数接受一个字符串，其中包含测试组的描述。第二个参数是一个包含测试的回调函数。`describe`函数创建一个块，将几个相关的测试组合在一起。它的主要目的是使测试结果在屏幕上更容易阅读。

`it()`函数让我们描述我们的测试。它也被称为`test()`方法。它的第一个参数是测试的`name`属性，以字符串形式表示。第二个参数是带有测试代码的回调函数。它还接受一个可选的第三个参数，其中包含毫秒为单位的`timeout`，以便我们的测试不会永远运行下去。默认超时时间为 5 秒。

如果从`it`或`test`函数返回一个`promise`，Jest 将等待`promise`解析完成后再完成测试。如果我们在`it`或`test`函数中提供一个参数，通常称为`done`，Jest 也会等待。如果在`it`或`test`回调中添加了`done`参数，则调用`done`函数表示测试已完成。

`it`或`test`函数不一定要在我们传递给`describe`的回调函数内部。它也可以被**独立调用**。然而，最好将相关的测试与`describe`一起分组，这样我们可以更容易地阅读结果。

第一个测试测试了当点击**播放**按钮时，会发出`puzzle-changed`事件。正如我们从`Puzzles.vue`组件中所看到的，`puzzle-changed`事件是通过`this.$emit()`方法发出的。为了创建我们的测试，我们调用`mount`来挂载我们的组件。它以我们要测试的组件作为参数。它还接受第二个参数，其中包含我们想要覆盖的组件选项的对象。在这个测试中，因为我们没有覆盖任何内容，所以我们没有传入任何东西作为第二个参数。

`mount()`方法返回`wrapper`对象，这是我们正在测试的组件的`wrapper`对象。它有一些方便的方法，我们可以用来进行测试。在这个测试中，我们调用`find()`方法来获取具有给定选择器的 HTML 元素。它返回 HTML DOM 对象，我们将调用`trigger()`方法来触发我们在测试中想要的事件。

这样，我们可以触发键盘和鼠标事件，以模拟用户交互。因此，以下代码用于获取具有`.play-button button`选择器的元素，然后触发其上的点击事件：

```js
wrapper.find('.play-button button').trigger('click');
```

测试的最后一行用于检查是否发出了`puzzle-changed`事件。`emitted()`方法返回一个具有名称的属性的对象。这些是发出的事件的事件名称。`toHaveProperty()`方法让我们检查作为参数传入的属性名称是否在返回的对象中。这是由`expect()`方法返回的对象的属性。

在第二个测试中，我们再次挂载组件并在同一元素上触发`click`事件。然后，我们使用事件名称调用`emitted()`方法，以便通过返回的对象获取与事件一起发出的有效负载。`puzzleChanged`数组包含作为第一个元素发出的有效负载。然后，为了检查是否发出了`puzzles[0].id`属性，我们在最后一行进行检查。`wrapper.vm`属性包含挂载的组件对象。因此，`wrapper.vm.puzzles`是`Puzzles`组件的拼图的响应属性。因此，这意味着我们正在检查`Puzzles`组件中拼图的响应属性的`id`属性是否已发出。

## 为 Records 组件添加测试

接下来，我们必须为`Records`组件编写测试。为此，我们必须创建`tests/unit/records.spec.js`文件，并编写以下代码：

```js
import { shallowMount } from '@vue/test-utils'
import 'jest-localstorage-mock';
import Records from '@/components/Records.vue'
describe('Records.vue', () => {
  it('gets records from local storage', () => {
    shallowMount(Records, {})
    expect(localStorage.getItem).       toHaveBeenCalledWith('records');
  })
})
```

这是我们使用`jest-localstorage-mock`包的地方。我们只需导入包文件；然后，文件中的代码将运行并为我们模拟`localStorage`依赖项。在测试中，我们调用`shallowMount`来挂载我们的`Records`组件，然后我们可以检查`localStorage.getItem`是否使用`'records'`参数调用。使用`jest-localstorage-mocks`包，我们可以直接传递`localStorage.getItem`以期望它进行检查。`toHaveBeenCalledWith()`方法让我们检查它所调用的参数。

由于我们在`beforeMount()`方法中调用了`localStorage.getItem()`方法，因此这个测试应该通过，因为我们在加载组件时调用了它。

## 为 SliderPuzzle 组件添加测试

最后，我们必须为`SliderPuzzle`组件编写一些测试。我们将添加`tests/unit/sliderPuzzle.spec.js`文件，并编写以下代码：

```js
import { mount } from '@vue/test-utils'
import SliderPuzzle from '@/components/SliderPuzzle.vue'
import 'jest-localstorage-mock';
jest.useFakeTimers();
describe('SliderPuzzle.vue', () => {
  it('inserts the index of the image to swap when we click 
    on an image', () => {
    const wrapper = mount(SliderPuzzle)
    wrapper.find('#start-button').trigger('click')
...
    expect(firstImage).toBe(newSecondImage);
    expect(secondImage).toBe(newFirstImage);
  })
  ...
  })
  afterEach(() => {
    jest.clearAllMocks();
  });
})
```

在“在单击图像时插入要交换的图像的索引”测试中，我们挂载`SliderPuzzle`组件，然后在`img`元素上触发`click`事件。`img`元素是滑块拼图的第一张幻灯片。应调用`swap()`方法，以便`indexesToSwap`响应属性具有添加的第一张图像的索引。`toBeGreaterThan()`方法让我们检查我们期望的返回值是否大于某个数字。

在“当点击 2 个图像时交换图像顺序”测试中，我们再次挂载`SliderPuzzle`组件。然后，我们获取`wrapper.vm.shuffledPuzzleArray`以获取早期数组中的索引并解构它们的值。我们将在稍后使用它来比较来自同一数组的值，以查看在我们点击了两个图像后它们是否已经被交换。

接下来，我们使用`wrapper.get()`方法触发幻灯片上的点击，以获取图像元素。然后，我们调用`trigger()`方法来触发点击事件。接着，我们检查在交换完成后`indexesToSwap`响应属性的长度是否为`0`。然后，在最后三行中，我们再次从`wrapper.vm.shuffledPuzzleArray`中获取项目并比较它们的值。由于条目在两个幻灯片之后应该被交换，我们有以下代码来检查交换是否真的发生了：

```js
expect(firstImage).toBe(newSecondImage);
expect(secondImage).toBe(newFirstImage);
```

在“启动方法调用时启动计时器”测试中，我们再次挂载`SliderPuzzle`组件。这次，我们调用`start()`方法来确保计时器实际上是通过`setInterval`创建的。我们还检查`setInterval`函数是否以函数和 1,000 毫秒的方式调用。为了让我们轻松测试任何与计时器有关的内容，包括测试任何调用`setTimeout`或`setInterval`的内容，我们调用`jest.useFakeTimers()`来模拟这些函数，以便我们的测试不会干扰其他测试的操作：

```js
import { mount } from '@vue/test-utils'
import SliderPuzzle from '@/components/SliderPuzzle.vue'
import 'jest-localstorage-mock';
jest.useFakeTimers();
describe('SliderPuzzle.vue', () => {
  ...
  it('starts timer when start method is called', () => {
    const wrapper = mount(SliderPuzzle);
    wrapper.vm.start();
    expect(setInterval).toHaveBeenCalledTimes(1);
    expect(setInterval).toHaveBeenLastCalledWith(expect.any(
      Function), 1000);
  })
  ...
  afterEach(() => {
    jest.clearAllMocks();
  });
})
```

`toHaveBeenCalledTimes()`方法检查我们传递给`expect()`方法的函数是否被调用了指定次数。由于我们调用了`jest.useFakeTimers()`，`setInterval`实际上是真正`setInterval`函数的一个间谍，而不是真正的版本。我们只能在函数与`expect`、`toHaveBeenCalledTimes`和`toHaveBeenCalledWith`一起使用间谍。所以，我们的代码将起作用。`toHaveBeenLastCalledWith()`方法用于检查我们的函数间谍被调用的参数类型。我们确保第一个参数是一个函数，第二个参数是 1,000 毫秒。

在“停止方法调用时停止计时器”测试中，我们通过挂载组件然后调用`stop()`方法来做类似的事情。我们确保在调用`stop()`方法时实际上调用了`clearInterval`。

```js
import { mount } from '@vue/test-utils'
import SliderPuzzle from '@/components/SliderPuzzle.vue'
import 'jest-localstorage-mock';
jest.useFakeTimers();
describe('SliderPuzzle.vue', () => {
  ...
  it('stops timer when stop method is called', () => {
    const wrapper = mount(SliderPuzzle);
    wrapper.vm.stop();
    expect(clearInterval).toHaveBeenCalledTimes(1);
  })
  it('shows the elapsed time', () => {
    const wrapper = mount(SliderPuzzle, {
      data() {
        return {
          currentDateTime: new Date(2020, 0, 1, 0, 0, 1),
          startDateTime: new Date(2020, 0, 1, 0, 0, 0),
        }
      }
    });
    expect(wrapper.html()).toContain('00:00:01')
  })
  ...
  afterEach(() => {
    jest.clearAllMocks();
  });
})
```

接下来，我们添加`'将记录保存到本地存储'`的测试。我们再次利用`jest-localstorage-mock`库来模拟`localStorage`依赖项。在这个测试中，我们以不同的方式挂载`SliderPuzzle`组件。第二个参数是一个包含`data()`方法的对象。这是我们在组件的`options`对象中拥有的`data()`方法。我们用传入的值覆盖了组件原始的响应式属性值，以便设置日期，以便我们可以对其进行测试。

然后，我们调用`wrapper.vm.recordSpeedRecords()`方法来测试是否调用了`localStorage.setItem()`方法。我们调用了挂载组件中的方法。然后，我们创建了`stringifiedRecords` JSON 字符串，以便我们可以将其与`localStrorage.setItem`调用进行比较。`toHaveBeenCalledWith`只适用于`localStorage.setItem`，因为我们导入了`jest-localstorage-mock`库来从实际的`localStorage.setItem()`方法创建一个间谍。这让 Jest 可以检查方法是否被调用以及给定的参数。

为了测试当点击**开始**按钮时计时器是否启动，我们有`'点击开始按钮启动计时器'`的测试。我们只需使用`get()`方法按其 ID 获取**开始**按钮，并在其上触发`click`事件。然后，我们检查`setInterval`函数是否被调用。与`localStorage`一样，我们使用`jest.useFakeTimers()`方法模拟`setInterval`函数，以从实际的`setInterval`函数创建一个间谍。这让我们可以检查它是否被调用。

类似地，我们有`'点击退出按钮停止计时器'`的测试，以检查是否在点击**退出**按钮时调用了`clearInterval`函数。

最后，我们有`'显示经过的时间'`的测试，以使用不同的值挂载组件的`currentDateTime`和`startDateTime`响应式属性。它们被设置为我们想要的值，并且它们在测试中保持不变。然后，为了检查`elapsedTime`计算属性是否正确显示，我们调用`wrapper.html()`方法来返回包装组件中呈现的 HTML，并检查其中是否包含我们正在寻找的经过的时间字符串。

为了在每个测试后清理模拟，以便在每个测试后重新开始，我们调用 `jest.clearAllMocks()` 方法来清除每个测试后的所有模拟。`afterEach` 函数接受一个在每个测试完成后运行的回调函数。

## 运行所有测试

运行测试，我们运行 `npm run test:unit`。通过这样做，我们会看到类似以下的内容：

![图 3.4 - 我们的单元测试结果](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-ex/img/Figure_3.4_B14405.jpg)

图 3.4 - 我们的单元测试结果

由于所有测试都通过了，我们项目中的代码正在按照我们的预期运行。运行所有测试只需要大约 4 秒，比手动测试我们的代码要快得多。

# 总结

在本章中，我们通过在组件中定义计算属性来更深入地了解组件。此外，我们为组件添加了测试，以便可以单独测试组件的各个部分。通过 Vue CLI，在我们的应用程序中轻松添加了测试文件和依赖项。

在我们的组件内部，我们可以使用 `this.$emit()` 方法发出传播到父组件的事件。它接受一个事件名称的字符串。其他参数是我们希望从父组件传递到子组件的有效负载。

为了向我们的 Vue 3 应用程序添加单元测试并运行测试，我们使用了 Jest 测试框架。Vue 3 为 Jest 添加了自己特定的 API，以便我们可以使用它来测试 Vue 3 组件。为了测试组件，我们使用 `mount` 和 `shallowMount` 函数来挂载组件。`mount` 函数让我们挂载组件本身，包括嵌套组件。`shallowMount` 函数只挂载组件本身，而不包括子组件。它们都返回我们组件的 `wrapper`，以便我们可以使用它与组件交互进行测试。

我们应该确保我们的测试是独立运行的。这就是为什么我们要模拟外部依赖关系。我们不希望运行任何需要外部测试和项目代码可用的代码。此外，如果需要，我们必须确保在测试中清理任何依赖关系。如果有任何模拟，我们必须清理它们，以便它们不会传递到另一个测试中。否则，我们可能会有依赖于其他测试的测试，这会使故障排除测试变得非常困难。

在下一章中，我们将学习如何创建一个照片库应用程序，通过将要保存的数据发送到后端 API 来保存数据。我们将介绍使用 Vue Router，以便我们可以导航到不同的页面。
