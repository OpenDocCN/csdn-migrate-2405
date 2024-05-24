# NuxtJS Web 开发实用指南（一）

> 原文：[`zh.annas-archive.org/md5/95454EEF6B1A13DFE0FAD028BE716A19`](https://zh.annas-archive.org/md5/95454EEF6B1A13DFE0FAD028BE716A19)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

Nuxt.js（本书中将其称为 Nuxt）是建立在 Vue.js 之上的渐进式 Web 框架（本书中将其称为 Vue）用于服务器端渲染（SSR）。使用 Nuxt 和 Vue，构建通用和静态生成的应用程序比以往任何时候都更容易。本书将帮助您快速了解 Nuxt 的基础知识以及如何将其与最新版本的 Vue 集成，使您能够使用 Nuxt 和 Vue.js 构建整个项目，包括身份验证、测试和部署。您将探索 Nuxt 的目录结构，并通过使用 Nuxt 的页面、视图、路由和 Vue 组件以及编写插件、模块、Vuex 存储和中间件来创建您的 Nuxt 项目。此外，您还将学习如何使用 Koa.js（本书中将其称为 Koa）、PHP 标准建议（PSRs）、MongoDB 和 MySQL 从头开始创建 Node.js 和 PHP API 或数据平台，以及使用 WordPress 作为无头 CMS 和 REST API。您还将使用 Keystone.js 作为 GraphQL API 来补充 Nuxt。您将学习如何使用 Socket.IO 和 RethinkDB 创建实时 Nuxt 应用程序和 API，最后使用 Nuxt 从远程 API 生成静态站点并流式传输资源（图像和视频），无论是 REST API 还是 GraphQL API。

# 本书适合对象

这本书适用于任何想要构建服务器端渲染的 Vue.js 应用程序的 JavaScript 或全栈开发人员。对 Vue.js 框架的基本理解将有助于理解本书涵盖的关键概念。

# 本书内容

第一章《介绍 Nuxt》是您将了解 Nuxt 的主要特点的地方。您将了解今天有哪些类型的 Web 应用程序，以及 Nuxt 属于哪些类别。然后，您将在接下来的章节中了解您可以使用 Nuxt 做什么。

第二章《开始使用 Nuxt》是您将安装 Nuxt 的地方，使用脚手架工具，或者从头开始创建您的第一个基本 Nuxt 应用程序。您将了解 Nuxt 项目中的默认目录结构，配置 Nuxt 以适应您的项目，并理解资源服务。

第三章《添加 UI 框架》是您将添加自定义 UI 框架，例如 Zurb Foundation，Motion UI，Less CSS 等等，以使您在 Nuxt 中的 UI 开发更加轻松和有趣。

第四章，“添加视图、路由和过渡”，是您将在 Nuxt 应用程序中创建导航路由、自定义页面、布局和模板的地方。您将学习如何添加过渡和动画，创建自定义错误页面，自定义全局 meta 标签，并为单个页面添加特定标签。

第五章，“添加 Vue 组件”，是您将在 Nuxt 应用程序中添加 Vue 组件的地方。您将学习如何创建全局和局部组件并重用它们，编写基本和全局 mixin，并定义符合命名约定的组件名称。

第六章，“编写插件和模块”，是您将在 Nuxt 应用程序中创建和添加插件、模块和模块片段的地方。您将学习如何创建 Vue 插件并将其安装在您的 Nuxt 项目中，编写全局函数并注册它们。

第七章，“添加 Vue 表单”，是您将使用`v-model`和`v-bind`创建表单的地方，验证表单元素并通过使用修饰符进行动态值绑定。您还将学习如何使用 Vue 插件 VeeValidate，使前端验证变得更加简单。

第八章，“添加服务器端框架”，是您将使用 Koa 作为服务器端框架创建 API 来补充您的 Nuxt 应用程序的地方。您将学习如何安装 Koa 及其必要的 Node.js 包以创建一个完全可用的 API，并将其与您的 Nuxt 应用程序集成。此外，您还将学习如何在 Nuxt 中使用异步数据从 Koa API 获取数据，通过异步数据访问 Nuxt 上下文，监听查询变化，处理错误，并使用 Axios 作为请求 API 数据的 HTTP 客户端。

第九章，“添加服务器端数据库”，是您将使用 MongoDB 管理 Nuxt 应用程序的数据库的地方。您将学习如何安装 MongoDB，编写基本的 MongoDB 查询，向 MongoDB 数据库添加一些虚拟数据，将 MongoDB 与上一章的 Koa API 集成，然后从 Nuxt 应用程序中获取数据。

第十章，*添加 Vuex 存储*，是您将使用 Vuex 管理和集中存储 Nuxt 应用程序数据的地方。您将了解 Vuex 架构，使用存储的变异和操作方法来改变存储数据，当存储变得更大时如何以模块化的方式构建您的存储程序，以及如何在 Vuex 存储中处理表单。

第十一章，*编写路由中间件和服务器中间件*，是您将在 Nuxt 应用程序中创建路由中间件和服务器中间件的地方。您将学习如何使用 Vue Router 创建中间件，使用 Vue CLI 创建 Vue 应用程序，并使用 Express.js（本书中称为 Express）、Koa 和 Connect.js（本书中称为 Connect）作为服务器中间件。

第十二章，*创建用户登录和 API 身份验证*，是您将在 Nuxt 应用程序中为受限页面添加身份验证的地方，使用会话、cookies、JSON Web Tokens（JWTs）、Google OAuth 以及您在上一章中学到的路由中间件。您将学习如何使用 JWT 在后端进行身份验证，在 Nuxt 应用程序中在客户端和服务器端使用 cookies（前端身份验证），以及在后端和前端身份验证中添加 Google OAuth。

第十三章，*编写端到端测试*，是您将使用 AVA、jsdom 和 Nightwatch.js 创建端到端测试的地方。您将学习如何安装这些工具，设置测试环境，并为上一章中 Nuxt 应用程序的页面编写测试。

第十四章，*使用 Linter、格式化程序和部署命令*，是您将使用 ESLint、Prettier 和 StandardJS 来保持代码清洁、可读和格式化的地方。您将学习如何安装和配置这些工具以满足您的需求，并在 Nuxt 应用程序中集成不同的 linter。最后，您将学习如何使用 Nuxt 命令部署您的 Nuxt 应用程序，并了解发布应用程序的托管服务。

第十五章，*使用 Nuxt 创建 SPA*，您将学习如何在 Nuxt 中开发**单页应用程序**（**SPA**），了解 Nuxt 中 SPA 与经典 SPA 的区别，并生成静态 SPA 以部署到静态托管服务器 GitHub Pages。

第十六章，*为 Nuxt 创建一个与框架无关的 PHP API*，您将使用 PHP 创建 API 来补充您的 Nuxt 应用程序。您将学习如何安装 Apache 服务器和 PHP 引擎，了解 HTTP 消息和 PHP 标准，将 MySQL 安装为您的数据库系统，为 MySQL 编写 CRUD 操作，通过遵守 PHP 标准创建与框架无关的 PHP API，然后将您的 API 与 Nuxt 应用程序集成。

第十七章，*使用 Nuxt 创建实时应用程序*，您将使用 RethinkDB、Socket.IO 和 Koa 开发实时 Nuxt 应用程序。您将学习如何安装 RethinkDB，介绍 ReQL，将 RethinkDB 集成到您的 Koa API 中，将 Socket.IO 添加到 API 和 Nuxt 应用程序中，最终将您的 Nuxt 应用程序转换为具有 RethinkDB changefeeds 的实时 Web 应用程序。

第十八章，*使用 CMS 和 GraphQL 创建 Nuxt 应用程序*，您将使用（无头）CMS 和 GraphQL 来补充您的 Nuxt 应用程序。您将学习如何将 WordPress 转换为无头 CMS，在 WordPress 中创建自定义文章类型并扩展 WordPress REST API。您将学习如何在 Nuxt 应用程序中使用 GraphQL，了解 GraphQL 模式和解析器，使用 Appolo Server 创建 GraphQL API，并使用 Keystone.js GraphQL API。此外，您还将学习如何安装和保护 PostgreSQL 和 MongoDB，使用 Nuxt 生成静态站点，并从远程 API 流式传输资源（图像和视频），无论是 REST API 还是 GraphQL API。

# 本书最大的收获

在整本书中，您将需要一个 Nuxt.js 的版本-最新版本，如果可能的话。所有代码示例都是在 Ubuntu 20.10 上使用 Nuxt 2.14.x 进行测试的。以下是本书的其他必要软件、框架和技术列表：

| **书中涵盖的软件/硬件** | **操作系统要求** |
| --- | --- |
| Koa.js v2.13.0 | 任何平台 |
| Axios v0.19.2 | 任何平台 |
| Keystone.js v11.2.0 | 任何平台 |
| Socket.IO v2.3.0 | 任何平台 |
| MongoDB v4.2.6  | 任何平台 |
| MySQL v10.3.22-MariaDB  | 任何平台 |
| RethinkDB v2.4.0 | Linux, macOS |
| PHP v7.4.5  | 任何平台 |
| Foundation v6.6.3 | 任何平台 |
| Swiper.js v6.0.0 | 任何平台 |
| Node.js v12.18.2 LTS (至少 v8.9.0)   | 任何平台 |
| NPM v6.14.7 | 任何平台 |

**如果您使用本书的数字版本，我们建议您自己输入代码或通过 GitHub 存储库访问代码（链接在下一节中提供）。这样做将有助于避免与复制和粘贴代码相关的潜在错误。**

## 下载示例代码文件

您可以从您在[www.packt.com](http://www.packt.com)的账户中下载本书的示例代码文件。如果您在其他地方购买了本书，您可以访问[www.packtpub.com/support](https://www.packtpub.com/support)并注册，文件将直接发送到您的邮箱。

您可以按照以下步骤下载代码文件：

1.  登录或注册网址为[www.packt.com](http://www.packt.com)。

1.  选择“支持”选项卡。

1.  点击“代码下载”。

1.  在搜索框中输入书名，并按照屏幕上的说明进行操作。

下载文件后，请确保使用最新版本的解压缩软件解压缩文件夹：

+   Windows 的 WinRAR/7-Zip

+   Mac 的 Zipeg/iZip/UnRarX

+   Linux 的 7-Zip/PeaZip

该书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Hands-on-Nuxt.js-Web-Development`](https://github.com/PacktPublishing/Hands-on-Nuxt.js-Web-Development)。如果代码有更新，将在现有的 GitHub 存储库中进行更新。

我们还有来自丰富书籍和视频目录的其他代码包，可在**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**上找到。快去看看吧！

## 使用的约定

本书中使用了许多文本约定。

`CodeInText`：指示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。例如："然后，您可以在 `.css` 文件中创建过渡样式。"

代码块设置如下：

```js
// pages/about.vue
<script>
export default {
  transition: {
    name: 'fade'
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```js
[default]
exten => s,1,Dial(Zap/1|30)
exten => s,2,Voicemail(u100)
exten => s,102,Voicemail(b100)
exten => i,1,Voicemail(s0)
```

任何命令行输入或输出都以如下形式书写：

```js
$ npm i less --save-dev
$ npm i less-loader --save-dev
```

**粗体**：表示一个新术语，一个重要词，或者屏幕上看到的词。例如，菜单或对话框中的单词会以这种方式出现在文本中。这是一个例子：“选择手动选择功能以从提示你选择的选项中选择路由器，以选择你需要的功能。”

警告或重要提示会显示为这样。提示和技巧会显示为这样。


# 第一部分：你的第一个 Nuxt 应用程序

在本节中，我们将简要介绍 Nuxt，其特点，文件夹结构等。然后，我们将通过一些简单的步骤开始构建我们的第一个 Nuxt 应用程序，并集成 Nuxt 路由，配置，Vue 组件等。

本节包括以下章节：

+   第一章，*介绍 Nuxt*

+   第二章，*开始使用 Nuxt*

+   第三章，*添加 UI 框架*


介绍 Nuxt

欢迎来到您的*Nuxt.js Web 开发实践*之旅。在本章中，我们将深入了解 Nuxt，看看构成这个框架的是什么。我们将带您了解 Nuxt 的特性，您将了解 Nuxt 所属的不同类型应用程序的优缺点。最后但同样重要的是，您将发现使用 Nuxt 作为通用 SSR 应用程序、静态站点生成器和单页面应用程序的巨大潜力。

在本章中，我们将涵盖以下主题：

+   从 Vue 到 Nuxt

+   为什么使用 Nuxt？

+   应用程序类型

+   Nuxt 作为通用 SSR 应用程序

+   Nuxt 作为静态站点生成器

+   Nuxt 作为单页面应用程序

让我们开始吧！

# 第一章：从 Vue 到 Nuxt

Nuxt 是一个更高级的 Node.js Web 开发框架，用于创建可以以两种不同模式开发和部署的 Vue 应用程序：通用（SSR）或单页面应用程序（SPA）。此外，您可以在 Nuxt 中部署 SSR 和 SPA 作为静态生成的应用程序。尽管您可以选择 SPA 模式，但 Nuxt 的全部潜力在于其通用模式或用于构建通用应用程序的服务器端渲染（SSR）。通用应用程序用于描述可以在客户端和服务器端都执行的 JavaScript 代码。但是，如果您希望开发经典（或标准/传统）的 SPA，仅在客户端执行的 SPA，您可能希望考虑使用纯 Vue。

请注意，SPA 模式的 Nuxt 应用程序与经典 SPA 略有不同。您将在本书的后面和本章中简要了解更多信息。

Nuxt 是建立在 Vue 之上的，具有一些额外功能，如异步数据、中间件、布局、模块和插件，可以先在服务器端执行您的应用程序，然后再在客户端执行。这意味着应用程序通常比传统的服务器端（或多页面）应用程序渲染更快。

Nuxt 预装了以下软件包，因此您无需像在标准 Vue 应用程序中那样安装它们：

+   Vue（[`vuejs.org/`](https://vuejs.org/)）

+   Vue 路由器（[`router.vuejs.org/`](https://router.vuejs.org/)）

+   Vuex（[`vuex.vuejs.org/`](https://vuex.vuejs.org/)）

+   Vue 服务器渲染器（[`ssr.vuejs.org/`](https://ssr.vuejs.org/)）

+   Vue 元（[`vue-meta.nuxtjs.org/`](https://vue-meta.nuxtjs.org/)）

除此之外，Nuxt 使用 webpack 和 Babel 来编译和捆绑您的代码，使用以下 webpack 加载器：

+   Vue 加载器（[`vue-loader.vuejs.org/`](https://vue-loader.vuejs.org/)）

+   Babel Loader ([`webpack.js.org/loaders/babel-loader/`](https://webpack.js.org/loaders/babel-loader/))

简而言之，webpack 是一个模块打包工具，它将 JavaScript 应用程序中的所有脚本、样式、资产和图像捆绑在一起，而 Babel 是一个 JavaScript 编译器，它将下一代 JavaScript（ES2015+）编译或转译为浏览器兼容的 JavaScript（ES5），以便您可以在当前浏览器上运行您的代码。

有关 webpack 和 Babel 的更多信息，请分别访问[`webpack.js.org/`](https://webpack.js.org/)和[`babeljs.io/`](https://babeljs.io/)。

webpack 使用他们称之为加载器的东西来预处理您通过 JavaScript `import`语句或`require`方法导入的文件。您可以编写自己的加载器，但在编译 Vue 文件时，您无需这样做，因为它们已经由 Babel 社区和 Vue 团队为您创建。我们将在下一节中发现 Nuxt 带来的伟大功能以及这些加载器贡献的功能。

# 为什么使用 Nuxt？

由于传统 SPA 和**多页面应用**（**MPA**）的缺点，存在诸如 Nuxt 之类的框架。我们可以将 Nuxt 视为服务器端渲染 MPA 和传统 SPA 的混合体。因此，它被称为“通用”或“同构”。因此，能够进行服务器端渲染是 Nuxt 的定义特性。在本节中，我们将为您介绍 Nuxt 的其他突出特性，这将使您的应用开发变得简单而有趣。我们将首先介绍的功能允许您通过在文件中使用`.vue`扩展名来编写单文件 Vue 组件。

## 编写单文件组件

我们可以使用几种方法来创建 Vue 组件。全局 Vue 组件是通过使用`Vue.component`创建的，如下所示：

```js
Vue.component('todo-item', {...})
```

另一方面，可以使用普通 JavaScript 对象创建本地 Vue 组件，如下所示：

```js
const TodoItem = {...}
```

这两种方法在小型项目中使用 Vue 是可管理和可维护的，但是当你一次拥有大量具有不同模板、样式和 JavaScript 方法的组件时，对于大型项目来说，管理变得困难。

因此，单文件组件来拯救，我们只使用一个`.vue`文件来创建每个 Vue 组件。如果您的应用程序需要多个组件，只需将它们分开成多个`.vue`文件。在每个文件中，您可以只编写与该特定组件相关的模板、脚本和样式，如下所示：

```js
// pages/index.vue
<template>
  <p>{{ message }}</p>
</template>

<script>
export default {
  data () {
    return { message: 'Hello World' }
  }
}
</script>

<style scoped>
p {
  font-size: 2em;
  text-align: center;
}
</style>
```

在这里，您可以看到我们有一个 HTML 模板，它从 JavaScript 脚本中打印消息，并且描述模板的 CSS 样式，全部在一个`.vue`文件中。这使得您的代码更加结构化、可读和可组织。很棒，不是吗？这只能通过`vue-loader`和 webpack 实现。在 Nuxt 中，我们只在`.vue`文件中编写组件，无论它们是`/components/`、`/pages/`还是`/layouts/`目录中的组件。我们将在第二章中更详细地探讨这一点，*开始使用 Nuxt*。现在，我们将看一下 Nuxt 功能，它允许您直接编写 ES6 JavaScript。

## 编写 ES2015+

Nuxt 在不需要您担心配置和安装 Babel 在 webpack 的情况下，即可编译您的 ES6+代码。这意味着您可以立即编写 ES6+代码，并且您的代码将被编译为可以在旧版浏览器上运行的 JavaScript。例如，当使用`asyncData`方法时，您经常会看到以下解构赋值语法：

```js
// pages/about.vue
<script>
export default {
  async asyncData ({ params, error }) {
    //...
  }
}
</script>
```

在前面的代码中，使用解构赋值语法将 Nuxt 上下文中的属性解包到不同的变量中，以便我们可以在`asyncData`方法中使用这些变量进行逻辑处理。

有关 Nuxt 上下文和 ECMAScript 2015 功能的更多信息，请分别访问[`nuxtjs.org/api/context`](https://nuxtjs.org/api/context)和[`babeljs.io/docs/en/learn/`](https://babeljs.io/docs/en/learn)。

在 Nuxt 中编写 ES6 只能通过`babel-loader`和 webpack 实现。在 Nuxt 中，您可以编写更多内容，包括`async`函数、`await`运算符、`箭头`函数、`import`语句等。那么 CSS 预处理器呢？如果您使用 Sass、Less 或 Stylus 等流行的 CSS 预处理器编写 CSS 样式，但如果您是 Sass 用户而不是 Less 用户或 Stylus 用户，Nuxt 是否支持它们中的任何一个？简短的答案是是。我们将在下一节中找出这个问题的长答案。

## 使用预处理器编写 CSS

在 Nuxt 中，您可以选择喜欢的 CSS 预处理器来编写应用程序的样式，无论是 Sass、Less 还是 Stylus。它们已经在 Nuxt 中为您预配置。您可以在[`github.com/nuxt/nuxt.js/blob/dev/packages/webpack/src/config/base.js`](https://github.com/nuxt/nuxt.js/blob/dev/packages/webpack/src/config/base.js)查看它们的配置。因此，您只需要在 Nuxt 项目中安装预处理器及其 webpack 加载程序。例如，如果您想将 Less 作为 CSS 预处理器，只需在 Nuxt 项目中安装以下依赖项：

```js
$ npm i less --save-dev
$ npm i less-loader --save-dev
```

然后，您可以通过在`<style>`块中将`lang`属性设置为"less"来开始编写您的 Less 代码，如下所示：

```js
// pages/index.vue
<template>
  <p>Hello World</p>
</template>

<style scoped lang="less">
@align: center;
p {
  text-align: @align;
}
</style>
```

从这个例子中，您可以看到在 Nuxt 中编写现代 CSS 样式就像在 Nuxt 中编写现代 JavaScript 一样容易。您只需要安装您喜欢的 CSS 预处理器及其 webpack 加载程序。在本书的后续章节中，我们将使用 Less，但现在让我们找出 Nuxt 提供了哪些其他功能。

有关这些预处理器及其 webpack 加载程序的更多信息，请访问以下链接：

+   [`lesscss.org/`](http://lesscss.org) 用于 Less

+   [`webpack.js.org/loaders/less-loader/`](https://webpack.js.org/loaders/less-loader/) 用于 less-loader

+   [`sass-lang.com/`](https://sass-lang.com/) 用于 Sass

+   [`webpack.js.org/loaders/sass-loader/`](https://webpack.js.org/loaders/sass-loader/) 用于 sass-loader

+   [`stylus-lang.com/`](https://stylus-lang.com/) 用于 Stylus

+   [`github.com/shama/stylus-loader`](https://github.com/shama/stylus-loader) 用于 stylus-loader

尽管 PostCSS 不是预处理器，但如果您想在 Nuxt 项目中使用它，请访问提供的指南[`nuxtjs.org/faq/postcss-plugins`](https://nuxtjs.org/faq/postcss-plugins)。

## 使用模块和插件扩展 Nuxt

Nuxt 是建立在模块化架构之上的。这意味着您可以使用无数的模块和插件来扩展它，适用于您的应用程序或 Nuxt 社区。这也意味着您可以从 Nuxt 和 Vue 社区中选择大量的模块和插件，这样您就不必为您的应用程序重新发明它们。这些链接如下：

+   Nuxt.js 的精彩模块[`github.com/nuxt-community/awesome-nuxt#official`](https://github.com/nuxt-community/awesome-nuxt#official)

+   在[`github.com/vuejs/awesome-vue#components--libraries`](https://github.com/vuejs/awesome-vue#components--libraries)上查看令人敬畏的 Vue.js，用于 Vue 组件、库和插件

模块和插件只是 JavaScript 函数。现在不用担心它们之间的区别；我们将在第六章中讨论这个问题，*编写插件和模块*。

## 在路由之间添加过渡

与传统的 Vue 应用程序不同，在 Nuxt 中，您不必使用包装器`<transition>`元素来处理元素或组件上的 JavaScript 动画、CSS 动画和 CSS 过渡。例如，如果您想在导航到特定页面时应用`fade`过渡，您只需将过渡名称（例如`fade`）添加到该页面的`transition`属性中：

```js
// pages/about.vue
<script>
export default {
  transition: {
    name: 'fade'
  }
}
</script>
```

然后，你可以在`.css`文件中创建过渡样式：

```js
// assets/transitions.css
.fade-enter,
.fade-leave-to {
  opacity: 0;
}

.fade-leave,
.fade-enter-to {
  opacity: 1;
}

.fade-enter-active,
.fade-leave-active {
  transition: opacity 3s;
}
```

当导航到`/about`路由时，“fade”过渡将自动应用于`about`页面。很酷，不是吗？如果此时代码或类名看起来有点令人不知所措，不要担心；我们将在第四章中更详细地了解和探索这个过渡特性。

## 管理`<head>`元素

此外，与传统的 Vue 应用程序不同，您可以直接管理应用程序的`<head>`块，而无需安装额外处理它的 Vue 包`vue-meta`。您只需通过`head`属性向任何页面添加所需的`<title>`、`<meta>`和`<link>`数据。例如，您可以通过应用程序的 Nuxt 配置文件管理全局`<head>`元素：

```js
// nuxt.config.js
export default {
  head: {
    title: 'My Nuxt App',
    meta: [
      { charset: 'utf-8' },
      { name: 'viewport', content: 'width=device-width, initial-scale=1' },
      { hid: 'description', name: 'description', content: 'My Nuxt app is 
       about...' }
    ],
    link: [
      { rel: 'icon', type: 'image/x-icon', href: '/favicon.ico' }
    ]
  }
}
```

Nuxt 将为您将此数据转换为 HTML 标记。同样，我们将在第四章中更详细地了解和探索此功能，*添加视图、路由和过渡*。

## 使用 webpack 捆绑和拆分代码

Nuxt 使用 webpack 将您的代码捆绑、缩小并拆分为可以加快应用程序加载时间的块。例如，在一个简单的 Nuxt 应用程序中有两个页面，index/home 和 about，您将为客户端获得类似的块：

```js
Hash: 0e9b10c17829e996ef30 
Version: webpack 4.43.0 
Time: 4913ms 
Built at: 06/07/2020 21:02:26 
                         Asset       Size  Chunks                         Chunk Names 
../server/client.manifest.json   7.77 KiB          [emitted]               
                      LICENSES  389 bytes          [emitted]               
                app.3d81a84.js   51.2 KiB       0  [emitted] [immutable]  app 
        commons/app.9498a8c.js    155 KiB       1  [emitted] [immutable]  commons/app 
commons/pages/index.8dfce35.js   13.3 KiB       2  [emitted] [immutable]  commons/pages/index 
        pages/about.c6ca234.js  357 bytes       3  [emitted] [immutable]  pages/about 
        pages/index.f83939d.js   1.21 KiB       4  [emitted] [immutable]  pages/index 
            runtime.3d677ca.js   2.38 KiB       5  [emitted] [immutable]  runtime 
 + 2 hidden assets 
Entrypoint app = runtime.3d677ca.js commons/app.9498a8c.js app.3d81a84.js 
```

您将为服务器端获取的块如下所示：

```js
Hash: 8af8db87175486cd8e06 
Version: webpack 4.43.0 
Time: 525ms 
Built at: 06/07/2020 21:02:27 
               Asset       Size  Chunks             Chunk Names 
      pages/about.js   1.23 KiB       1  [emitted]  pages/about 
      pages/index.js   6.06 KiB       2  [emitted]  pages/index 
           server.js   80.9 KiB       0  [emitted]  app 
server.manifest.json  291 bytes          [emitted]   
 + 3 hidden assets 
Entrypoint app = server.js server.js.map 
```

这些块和构建信息是在使用 Nuxt `npm run build` 命令构建应用以进行部署时生成的。我们将在第十四章中更详细地了解这一点，*使用 Linters、Formatters 和部署命令*。

除此之外，Nuxt 还使用了 webpack 的其他出色功能和插件，比如静态文件和资源服务（资源管理），热模块替换，CSS 提取（`extract-css-chunks-webpack-plugin`），构建和监视时的进度条（webpackbar）等等。更多信息，请访问以下链接：

+   [`webpack.js.org/guides/code-splitting/`](https://webpack.js.org/guides/code-splitting/) 用于代码拆分

+   [`webpack.js.org/concepts/manifest/`](https://webpack.js.org/concepts/manifest/) 用于清单

+   [`webpack.js.org/guides/asset-management/`](https://webpack.js.org/guides/asset-management/) 用于资源管理

+   [`webpack.js.org/concepts/hot-module-replacement/`](https://webpack.js.org/concepts/hot-module-replacement/) 用于热模块替换

+   [`webpack.js.org/plugins/mini-css-extract-plugin/`](https://webpack.js.org/plugins/mini-css-extract-plugin/) 用于 CSS 提取

+   [`github.com/nuxt/webpackbar`](https://github.com/nuxt/webpackbar) 用于 `webpackbar`（Nuxt 核心团队开发的插件）

来自 webpack、Babel 和 Nuxt 本身的这些出色功能将使您的现代项目开发变得有趣且轻松。现在，让我们看看各种应用类型，看看在构建下一个 web 应用时，为什么应该或不应该使用 Nuxt。

# 应用类型

今天的 web 应用与几十年前的应用非常不同。在那些日子里，我们的选择和解决方案更少。今天，它们正在蓬勃发展。无论我们称它们为“应用”还是“应用程序”，它们都是一样的。在本书中，我们将称它们为“应用”。因此，我们可以将我们当前的 web 应用分类如下：

+   传统的服务器端渲染应用

+   传统的单页应用

+   通用 SSR 应用

+   静态生成的应用

让我们逐个了解它们，并了解其利弊。我们首先来看最古老的应用类型 - 传统的服务器端渲染应用。

## 传统的服务器端渲染应用

服务器端呈现是向浏览器客户端传递数据和 HTML 的最常见方法。在网络行业刚刚开始时，这是唯一的做事方式。在传统的服务器呈现的应用程序或动态网站中，每个请求都需要从服务器重新呈现新页面到浏览器。这意味着您将在每次发送请求到服务器时重新加载所有脚本、样式和模板。重新加载和重新呈现的想法一点也不吸引人。尽管如今可以通过使用 AJAX 来减轻一些重新加载和重新呈现的负担，但这会给应用程序增加更多复杂性。

让我们来看看这些类型应用程序的优缺点。

**优势**：

+   **更好的 SEO 性能：**因为客户端（浏览器）得到了包含所有数据和 HTML 标记的完成页面，特别是属于页面的元标记，搜索引擎可以爬取页面并对其进行索引。

+   **更快的初始加载时间：**因为页面和内容是由服务器端脚本语言（如 PHP）在发送到客户端浏览器之前在服务器端呈现的，所以我们在客户端很快就能得到呈现的页面。此外，无需像传统的单页应用程序那样在 JavaScript 文件中编译网页和内容，因此应用程序在浏览器上加载更快。

**缺点**：

+   **用户体验较差：**因为每个页面都必须重新呈现，这个过程在服务器上需要时间，用户必须等待直到在浏览器上重新加载所有内容，这可能会影响用户体验。大多数情况下，我们只希望在提供新请求时获得新数据；我们不需要重新生成 HTML 基础，例如导航栏和页脚，但仍然会重新呈现这些基本元素。我们可以利用 AJAX 来仅呈现特定组件，但这会使开发变得更加困难和复杂。

+   后端和前端逻辑的紧密耦合：视图和数据通常在同一个应用程序中处理。例如，在典型的 PHP 框架应用程序中，如 Laravel，您可以在路由中使用模板引擎（如 Laravel Pug）渲染视图。或者，如果您正在为传统的服务器端渲染应用程序使用 Express，您可以使用模板引擎（如 Pug 或 vuexpress）来渲染视图。在这两个框架中，视图与后端逻辑耦合在一起，即使我们可以使用模板引擎提取视图层。后端开发人员必须知道每个特定路由或控制器要使用的视图（例如`home.pug`）。另一方面，前端开发人员必须在与后端开发人员相同的框架中处理视图。这给项目增加了更多复杂性。

## 传统的单页面应用程序（SPA）

与服务器端渲染应用程序相反，SPA 是客户端渲染（CSR）应用程序，它使用 JavaScript 在浏览器中渲染内容，而不需要在使用过程中重新加载新页面。因此，您不会将内容呈现到 HTML 文档中，而是从服务器获取基本的 HTML，然后在浏览器中使用 JavaScript 加载内容。

```js
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Vue App</title>
</head>
<body>
  <div id="app"></div>
  <script src="https://unpkg.com/vue/dist/vue.js" type="text/javascript"></script>
  <script src="/path/to/app.js"type="text/javascript"></script>
</body>
</html>
```

这是一个非常简单的 Vue 应用程序，其中您有一个容器`<div>`，只有`app`作为其 ID，里面没有其他内容，然后是两个`<script>`元素。第一个`<script>`元素将加载 Vue.js 库，而第二个将加载渲染应用程序内容的 Vue 实例。

```js
// path/to/app.js
const app = new Vue({
  data: {
    greeting:'Hello World!'
  },
  template: '<p>{{ greeting }}</p>'
}).$mount('#app')
```

让我们来看看这种类型应用程序的优缺点。

优点：

+   更好的用户体验：SPA 在初始加载后渲染内容时非常快速。大多数资源，如 CSS 样式、JavaScript 代码和 HTML 模板，在应用程序的整个生命周期中只加载一次。之后只是来回发送数据；基本的 HTML 和布局保持不变，从而提供了流畅和更好的用户体验。

+   **开发和部署更容易：** 单页应用程序的开发相对容易，无需服务器和服务器端脚本语言。您可以从本地机器上简单地启动开发，使用`file://URI`。部署也更容易，因为它由 HTML、JavaScript 和 CSS 文件组成；您只需将它们放到远程服务器上，立即上线。

**缺点：**

+   **搜索引擎性能差：** 单页应用程序通常是裸骨的单个 HTML 页面，大多数情况下没有标题和段落标签供搜索引擎爬虫爬取。SPA 内容是通过 JavaScript 加载的，而爬虫通常无法执行 JavaScript，因此 SPA 在搜索引擎优化方面通常表现不佳。

+   **初始加载时间慢：** 大多数资源，如 CSS 样式、JavaScript 代码和 HTML 模板，在应用程序的整个生命周期中只加载一次，因此我们需要在开始时一次性加载大量这些资源文件。通过这样做，应用程序通常在初始加载时间方面变慢，特别是在大型单页应用程序中。

## 通用服务器端渲染应用（SSR）

正如我们在前一节中所学到的，传统的服务器端渲染应用程序和单页应用程序都有优点和缺点。编写单页应用程序有好处，但也有一些你会失去的东西：网络爬虫遍历您的应用程序的能力以及应用程序初始加载时的性能较慢。这与编写传统的服务器端渲染应用程序相反，还有一些你没有的东西，比如更好的用户体验和单页应用程序中客户端开发的乐趣。理想情况下，客户端和服务器端渲染可以平衡用户体验和性能。这就是通用服务器端渲染（SSR）的用武之地。

自从 2009 年 Node.js 发布以来，JavaScript 已经成为一种等同的语言。通过等同，我们指的是代码可以在客户端和服务器端都运行。等同（通用）JavaScript 可以被定义为客户端和服务器端应用程序的混合体。这是网页应用程序的一种新方法，以弥补传统 SSR 应用程序和传统 SPA 的缺点。这就是 Nuxt 所属的类别。

在通用 SSR 中，您的应用程序将首先在服务器端预加载，预渲染页面，并在切换到客户端操作其余寿命之前将呈现的 HTML 发送到浏览器。从头开始构建通用 SSR 应用程序可能会很繁琐，因为在实际开发过程开始之前需要大量的配置。这就是 Nuxt 的目标，它通过为您预设创建 SSR Vue 应用程序所需的所有配置来轻松实现。

尽管通用 SSR 应用程序在我们现代的 Web 开发中是一个很好的解决方案，但这些类型的应用程序仍然有优点和缺点。让我们来看看它们。

**优点**：

+   **更快的初始加载时间：**在通用 SSR 中，JavaScript 和 CSS 被分割成块，资源被优化，并且页面在服务器端呈现后再提供给客户端浏览器。所有这些选项都有助于加快初始加载时间。

+   **更好的 SEO 支持：**由于所有页面在服务器端呈现时都带有适当的元内容、标题和段落，然后再提供给客户端，搜索引擎爬虫可以遍历页面，以提高应用程序的 SEO 性能。

+   **更好的用户体验：**通用 SSR 应用程序在初始加载后的工作方式类似于传统的 SPA，因为页面和路由之间的转换是无缝的。只有数据来回传输，而不重新渲染 HTML 内容持有者。所有这些功能都有助于提供更好的用户体验。

**缺点**：

+   **需要 Node.js 服务器：**在服务器端运行 JavaScript 需要一个 Node.js 服务器，因此在使用 Nuxt 和编写应用程序之前必须设置服务器。

+   **复杂的开发：**在通用 SSR 应用程序中运行 JavaScript 代码可能会令人困惑，因为一些 JavaScript 插件和库只能在客户端运行，比如用于样式和 DOM 操作的 Bootstrap 和 Zurb Foundation。

## 静态生成的应用程序

静态生成的应用程序是通过静态站点生成器预先生成的，并存储为静态 HTML 页面在托管服务器上。Nuxt 带有一个`nuxt generate`命令，可以为您从您在 Nuxt 中开发的通用 SSR 或 SPA 应用程序生成**静态页面**。它在构建过程中为每个路由预渲染 HTML 页面到生成的`/dist/`文件夹中，如下所示：

```js
-| dist/
----| index.html
----| favicon.ico
----| about/
------| index.html
----| contact/
------| index.html
----| _nuxt/
------| 2d3427ee2a5aa9ed16c9.js
------| ...
```

您可以将这些静态文件部署到静态托管服务器，而无需 Node.js 或任何服务器端支持。因此，当应用程序最初在浏览器上加载时 - 无论您请求的是哪个路由 - 您都将立即获得完整的内容（如果它是从通用 SSR 应用程序中导出的），之后应用程序将像传统的单页面应用程序一样运行。

让我们来看看这些类型应用程序的优势和劣势。

**优势：**

+   **快速的初始加载时间：** 由于每个路由都被预先生成为具有自己内容的静态 HTML 页面，因此在浏览器上加载速度很快。

+   **有利于 SEO：** 静态生成的 Web 应用程序允许您的 JavaScript 应用程序被搜索引擎完美地抓取，就像传统的服务器端渲染应用程序一样。

+   **部署更容易：** 因为静态生成的 Web 应用程序只是静态文件，这使它们易于部署到静态托管服务器，如 GitHub Pages。

**劣势：**

+   **没有服务器端支持：** 因为静态生成的 Web 应用程序只是静态 HTML 页面，并且仅在客户端上运行，这意味着没有运行时支持 Nuxt 的`nuxtServerInit`动作方法和 Node.js HTTP 请求和响应对象，这些仅在服务器端可用。所有数据将在构建步骤中预先呈现。

+   **没有实时渲染：** 静态生成的 Web 应用程序适用于只提供**静态页面**的应用程序，这些页面在**构建时**预先呈现。如果您正在开发一个需要从服务器实时渲染的复杂应用程序，那么您应该使用通用 SSR 来充分利用 Nuxt 的全部功能。

从这些类别中，你可能已经发现 Nuxt 符合通用 SSR 应用程序和静态生成的应用程序。除此之外，它也符合单页面应用程序，但与传统的单页面应用程序不同，你将在第十五章“使用 Nuxt 创建单页面应用程序”中了解更多信息。

现在，让我们更好地了解 Nuxt 在本书中将要创建的应用程序类型。我们将从 Nuxt 作为通用 SSR 应用程序开始。

# Nuxt 作为通用 SSR 应用程序

许多年前，我们有服务器端脚本语言，如 ASP、Java、服务器端 JavaScript、PHP 和 Python 来创建具有模板引擎的传统服务器端应用程序来渲染我们应用程序的视图。这导致了我们在前一节中经历的紧耦合的缺点。

因此，随着 Nuxt、Next（[`nextjs.org/`](https://nextjs.org/)）和 Angular Universal（[`angular.io/guide/universal`](https://angular.io/guide/universal)）等通用 SSR 框架的兴起，我们可以充分利用它们的力量，通过替换模板引擎（如 Pug（[`pugjs.org/`](https://pugjs.org/)）、Handlebars（[`handlebarsjs.com/`](https://handlebarsjs.com/)）、Twig（[`twig.symfony.com/`](https://twig.symfony.com/)）等）来彻底解耦视图和服务器端脚本应用。如果我们将 Nuxt 视为**前端服务器端**应用程序，Express（或其他）视为**后端服务器端**应用程序，我们可以看到它们如何完美地互补。例如，我们可以使用 Express 在 API 路由（例如`/`）上创建一个**后端服务器端**应用程序，以 JSON 格式提供数据，位于`localhost:4000`上。

```js
{
  "message": "Hello World"
}
```

然后，在前端服务器端，我们可以使用 Nuxt 作为一个通用的 SSR 应用程序，在`localhost:3000`上运行，通过从 Nuxt 应用程序中的页面发送 HTTP 请求来消耗上述数据，如下所示：

```js
// pages/index.vue
async asyncData ({ $http }) {
  const { message } = await $http.$get('http://127.0.0.1:4000')
  return { message }
}
```

现在，我们将 Nuxt 作为服务器和客户端来处理我们应用的视图和模板，而 Express 只处理我们的服务器端逻辑。我们不再需要模板引擎来呈现我们的内容。因此，也许我们不需要学习那么多模板引擎，也不需要担心它们之间的竞争，因为现在我们有了通用的 Nuxt。

我们将向您展示如何使用 Nuxt 和 Koa（另一个类似于 Express 的 Node.js 服务器端框架）创建跨域应用程序，详见第十二章，*创建用户登录和 API 身份验证*。

请注意，在上述代码中，我们使用了 Nuxt HTTP 模块来发出 HTTP 请求。然而，在本书中，我们将主要使用原始的 Axios 或 Nuxt Axios 模块来进行 HTTP 请求。有关 Nuxt HTTP 模块的更多信息，请访问[`http.nuxtjs.org/`](https://http.nuxtjs.org/)。

您还可以使用 Nuxt Content 模块作为无头 CMS，以便从 Markdown、JSON、YAML、XML 和 CSV 文件中提供应用程序内容，这些文件可以“本地”存储在您的 Nuxt 项目中。但是，在本书中，我们将使用和创建外部 API 来提供我们的内容，以避免我们在传统服务器端应用程序中发现的紧密耦合问题。有关 Nuxt Content 模块的更多信息，请访问[`content.nuxtjs.org/`](https://content.nuxtjs.org/)。

# Nuxt 作为静态站点生成器

尽管服务器端渲染是 Nuxt 的主要特性，但它也是一个静态站点生成器，可以在静态站点中预渲染您的 Nuxt 应用程序，就像静态生成的应用程序类别中提供的示例一样。它可能是传统单页面应用程序和服务器端渲染应用程序之间最好的结合。通过静态 HTML 内容获益，以获得更好的 SEO，您不再需要来自 Node.js 和 Nuxt 的运行时支持。但是，您的应用程序仍将像 SPA 一样运行。

更重要的是，在静态生成期间，Nuxt 具有一个爬虫，用于爬取应用程序中的链接以生成动态路由，并将它们的数据从远程 API 保存为`payload.js`文件，存储在`/dist/`文件夹内的`/static/`文件夹中。然后使用这些负载来提供最初从 API 请求的数据。这意味着您不再调用 API。这可以保护您的 API 免受公众和可能的攻击者的侵害。

您将学习如何在第十四章中使用远程 API 从 Nuxt 生成静态站点，以及在本书的最后一章第十八章中创建具有 CMS 和 GraphQL 的 Nuxt 应用程序。

# Nuxt 作为单页面应用程序

如果您有任何原因不希望将 Nuxt 用作服务器端渲染应用程序，那么 Nuxt 非常适合开发单页面应用程序。正如我们在本章开头提到的，Nuxt 有两种开发应用程序的模式：`universal`和`spa`。这意味着您只需在项目配置的`mode`属性中指定`spa`，我们将在下一章中更详细地探讨这一点。

因此，你可能会想，如果我们可以使用 Nuxt 开发 SPA，那为什么还要费心使用 Vue 呢？事实上，你从 Nuxt 开发的 SPA 与从 Vue 开发的 SPA 略有不同。你从 Vue 构建的 SPA 是传统的 SPA，而从 Nuxt 构建的 SPA 是“静态”SPA（让我们称之为 Nuxt SPA）——你的应用页面在构建时进行了预渲染。这意味着部署 Nuxt SPA 在技术上与静态生成 Nuxt 通用 SSR 应用是相同的——两者都需要相同的 Nuxt 命令：`nuxt generate`。

这可能会让人感到困惑，你可能想问静态生成的 SSR 应用和静态生成的 SPA 之间有什么区别？区别非常明显——与静态生成的 SSR 应用相比，静态生成的 SPA 没有页面内容。静态生成的 SPA 是使用你的应用页面和“空”HTML 预渲染的，就像传统的 SPA 一样——没有页面内容。这很令人困惑，但请放心，我们将在本书的后续章节中弄清楚这一切。特别是，你将了解在 Nuxt 中开发 SPA 的权衡以及如何克服它们。

你将学习如何开发 Nuxt SPA，并在第十五章中使用远程 API 生成静态 Nuxt SPA，*使用 Nuxt 创建 SPA*。

# 总结

干得好！你已经完成了进入 Nuxt 的旅程的第一章。在本章中，你了解了 Nuxt 框架的组成部分；即 Vue（Nuxt 的起源）、webpack 和 Babel。你了解了 Nuxt 提供的各种功能，比如你可以编写 Vue 单文件组件（`.vue`文件）、ES2015+ JavaScript（ES6）、使用预处理器的 CSS（Sass、Less、Stylus）。你还可以通过模块和插件扩展你的应用，为应用的路由添加过渡效果，管理`<head>`元素和应用中每个路由或页面的元内容。除此之外，你还涵盖了从 webpack 和 Babel 导入的大量出色功能，比如打包、压缩和代码分割。你还了解到，你可以从 Nuxt 社区获取大量插件和模块用于你的 Nuxt 项目。

除了这些强大的功能之外，您还了解了每种可用应用类型的优缺点：传统的服务器端渲染应用程序、传统的单页面应用（SPA）、通用服务器端渲染应用程序（SSR）和静态生成应用程序。您还了解到 Nuxt 应用实际上符合通用 SSR 应用程序和静态生成应用程序的类别。然后，您了解到 Nuxt 也符合单页面应用的类别，但与传统的 SPA 不同。最后，您还了解了如何在本书中更多地了解如何使用 Nuxt 来进行通用 SSR 应用程序、静态生成应用程序和单页面应用。

在下一章中，您将学习如何安装 Nuxt 并创建一个简单的 Nuxt 应用程序，并了解 Nuxt 脚手架工具提供的默认目录结构。您还将学习如何自定义您的 Nuxt 应用程序，并了解 Nuxt 中提供的资源。所以，请继续关注！


开始使用 Nuxt

本章将指导您完成从头开始安装 Nuxt 项目或使用 Nuxt 脚手架工具的过程。在开发 Nuxt 应用程序时，安装 Nuxt 是您应该做的第一件事。在本书中，我们将为所有示例应用程序使用 Nuxt 脚手架工具，因为它会自动生成必要的项目文件夹和文件（我们将在本章中探讨），但当然，您也可以从头开始进行小型应用程序开发。我们将介绍目录结构以及每个目录的用途和目的。如果您从头开始安装 Nuxt 项目，您仍需要了解目录结构和 Nuxt 将自动从您的项目中读取的官方目录。您还将学习如何配置 Nuxt 以满足您的应用程序特定的需求，即使 Nuxt 已经默认配置以涵盖大多数实际情况。因此，我们将指导您了解配置的要点。此外，我们将介绍 Nuxt 应用程序中的资源服务，特别是用于提供图像。

本章我们将涵盖的主题如下：

+   安装 Nuxt

+   了解目录结构

+   了解自定义配置

+   了解资源服务

# 第二章：技术要求

您应该熟悉以下术语：

+   JavaScript ES6

+   服务器端和客户端开发基础知识

+   应用程序编程接口（API）

支持的操作系统如下：

+   Windows 10 或更高版本，带有 PowerShell

+   带有终端的 macOS（Bash 或 Oh My Zsh）

+   具有终端的 Linux 系统（如 Ubuntu）

建议的跨平台软件如下：

+   Node.js：[`nodejs.org/`](https://nodejs.org/)

+   Node Package Manager（npm）：[`www.npmjs.com/`](https://www.npmjs.com/)

# 安装 Nuxt

有两种简单的方法可以开始使用 Nuxt。最简单的方法是使用 Nuxt 脚手架工具`create-nuxt-app`，它会自动为您安装所有 Nuxt 依赖项和默认目录。另一种方法是仅使用`package.json`文件从头开始。让我们来了解如何做到这一点。

## 使用 create-nuxt-app

`create-nuxt-app`是 Nuxt 团队创建的一个脚手架工具，您可以使用它快速安装项目。您需要做的是在您喜欢的终端上使用`npx`来运行`create-nuxt-app`：

```js
$ npx create-nuxt-app <project-name>
```

npx 从 npm 5.2.0 开始默认安装，但您可以通过在终端上检查其版本来确保已安装：

```js
$ npx --version
6.14.5
```

在安装 Nuxt 项目的过程中，您将被要求回答一些问题，以便与 Nuxt 集成，如下所示：

+   选择一种编程语言：

```js
JavaScript 
TypeScript 
```

+   选择一个包管理器：

```js
Yarn 
Npm 
```

+   选择一个 UI 框架：

```js
None
Ant Design Vue  
Bootstrap Vue 
...
```

+   选择一个测试框架：

```js
None
Jest
AVA
WebdriverIO 
```

让我们使用 npx 创建您的第一个 Nuxt 应用程序，名为`first-nuxt`。因此，请选择您机器上的本地目录，在该目录上打开终端，并运行`npx create-nuxt-app first-nuxt`。在安装过程中遇到类似之前提到的问题时，请选择`JavaScript`作为编程语言，Npm 作为包管理器，以及`None`作为 UI 框架和测试框架。然后，跳过其余的问题（只是不要选择任何选项），以便我们在需要时稍后添加它们。您的终端上应该有一个类似以下问题的问题列表，以及我们建议的相同选项：

```js
**$ npx create-nuxt-app first-nuxt** 
create-nuxt-app v3.1.0
:: Generating Nuxt.js project in /path/to/your/project/first-nuxt 
? Project name: first-nuxt 
? Programming language: JavaScript 
? Package manager: Npm 
? UI framework: None 
? Nuxt.js modules: (Press <space> to select, <a> to toggle all, <i> to invert selection) 
? Linting tools: (Press <space> to select, <a> to toggle all, <i> to invert selection) 
? Testing framework: None 
? Rendering mode: Universal (SSR / SSG) 
? Deployment target: Server (Node.js hosting) 
? Development tools: (Press <space> to select, <a> to toggle all, <i> to invert selection) 
```

对于有关渲染模式的问题，您应该选择`Universal (SSR / SSG)`。我们将在第十五章中涵盖单页面应用程序（SPA）的选项，*使用 Nuxt 创建 SPA*。在本书中的所有示例应用程序中，除了第十五章中的示例之外，我们将使用 SSR。我们还将在本书中使用`npm`作为我们的包管理器，因此请确保您选择此选项。安装完成后，我们可以启动它：

```js
$ cd first-nuxt
$ npm run dev
```

该应用现在正在`localhost:3000`上运行。当您在您喜爱的浏览器中运行该地址时，您应该会看到 Nuxt 生成的默认索引页面。使用脚手架工具安装 Nuxt 项目是不是很容易？但有时您可能不需要像这样的完整安装；您可能只需要一个“最基本”的安装。如果是这样，请让我们在下一节中了解如何从头开始安装 Nuxt。

您可以在我们的 GitHub 存储库的`/nuxt-packt/chapter-2/scaffolding/`中找到此简单应用程序的源文件。

## 从头开始

如果您不想使用 Nuxt 脚手架工具，您可以使用`package.json`文件和`npm`为您安装 Nuxt 应用程序。让我们通过以下步骤了解如何操作：

1.  在您的根项目中创建一个`package.json`文件：

```js
{
  "name": "nuxt-app",
  "scripts": {
    "dev": "nuxt"
  }
}
```

1.  通过 npm 在项目中安装 Nuxt：

```js
$ npm i nuxt
```

1.  在您的根项目中创建一个`/pages/`目录，然后在其中创建一个`index.vue`页面：

```js
// pages/index.vue
<template>
  <h1>Hello world!</h1>
</template>
```

1.  使用 npm 启动项目：

```js
$ npm run dev
```

应用程序现在正在`localhost:3000`上运行。当你在你喜欢的浏览器中运行该地址时，你应该会看到你创建的带有`Hello world!`消息的索引页面。

然而，无论你选择“最基本”还是完整的堆栈选项，你都应该了解 Nuxt 运行应用程序所需的默认目录。因此，让我们在下一节中找出这些目录是什么。

你可以在我们的 GitHub 存储库的`/nuxt-packt/chapter-2/scratch/`中找到这个简单的应用程序。

# 理解目录结构

如果你成功使用`create-nuxt-app`脚手架工具安装了一个 Nuxt 项目，你应该在项目文件夹中得到以下默认目录和文件：

```js
-| your-app-name/
---| assets/
---| components/
---| layouts/
---| middleware/
---| node_modules/
---| pages/
---| plugins/
---| static/
---| store/
---| nuxt.config.js
---| package.json
---| README.md
```

让我们逐个了解它们，并在接下来的章节中理解它们的用途。

## 资源目录

`/assets/`目录用于包含项目的资源，例如图片、字体和 Less、Stylus 或 Sass 文件，这些文件将由 webpack 编译。例如，你可能有一个 Less 文件，如下所示：

```js
// assets/styles.less
@width: 10px;
@height: @width + 10px;

header {
  width: @width;
  height: @height;
}
```

webpack 将把前面的代码编译成你的应用程序的以下 CSS：

```js
header {
  width: 10px;
  height: 20px;
}
```

我们将在本章后面讨论在该目录中提供图像的好处，并在本书中生成静态页面时经常使用该目录。

## 静态目录

`/static/`目录用于包含不希望被 webpack 编译或无法被编译的文件，例如 favicon 文件。如果你不想在`/assets/`目录中提供你的资源，比如图片、字体和样式，你可以将它们放在`/static/`目录中。该目录中的所有文件都直接映射到服务器根目录，因此可以直接在根 URL 下访问。例如，`/static/1.jpg`被映射为`/1.jpg`，因此可以通过以下方式访问它：

```js
http://localhost:3000/1.jpg
```

我们将在本章后面讨论在`/assets/`和`/static/`目录之间提供图像的区别。请注意，当你使用 Nuxt 脚手架工具时，默认情况下会在该目录中得到一个`favicon.ico`文件，但你可以创建自己的 favicon 文件来替换它。

## 页面目录

`/pages/`目录用于包含应用程序的视图和路由。Nuxt 将读取并转换该目录内的所有`.vue`文件，并为你自动生成应用程序路由。例如，看下面的例子：

```js
/pages/about.vue
/pages/contact.vue
```

Nuxt 将采用前面的文件名（不带`.vue`扩展名）并为你的应用程序创建以下路由：

```js
localhost:3000/about
localhost:3000/contact
```

如果您通过`create-nuxt-app`安装 Nuxt，将会自动为您创建一个`index.vue`文件，并且您可以在`localhost:3000`上看到这个页面。

我们将在第四章中更详细地查看这个目录，*添加视图、路由和过渡*。

## 布局目录

`/layouts/`目录用于包含应用程序的布局。当您使用 Nuxt 脚手架工具时，默认情况下会得到一个名为`default.vue`的布局。您可以修改这个默认布局或者在这个目录中添加新的布局。

我们将在第四章中更详细地查看这个目录，*添加视图、路由和过渡*。

## 组件目录

`/components/`目录用于包含 Vue 组件。当您使用 Nuxt 脚手架工具时，默认情况下会得到一个名为`Logo.vue`的组件。这个目录中的`.vue`文件与`/pages/`目录中的文件的明显和重要区别在于，您不能为这个目录中的组件使用`asyncData`方法；但是，如果需要，您可以使用`fetch`方法来设置它们。您应该将小型和可重用的组件放在这个目录中。

我们将在第五章中更详细地查看这个目录，*添加 Vue 组件*。

## 插件目录

`/plugins/`目录用于包含 JavaScript 函数，比如您想要在根 Vue 实例实例化之前运行的全局函数。例如，您可能想要创建一个新的`axios`实例，专门发送 API 请求到[`jsonplaceholder.typicode.com`](https://jsonplaceholder.typicode.com)，并且您可能希望在全局范围内使用这个实例，而不是每次导入`axios`并创建一个新实例。您可以创建一个插件，将其注入和插入到 Nuxt 上下文中，如下所示：

```js
// plugins/axios-typicode.js
import axios from 'axios'

const instance = axios.create({
  baseURL: 'https://jsonplaceholder.typicode.com'
})

export default (ctx, inject) => {
  ctx.$axiosTypicode = instance
  inject('axiosTypicode', instance)
}
```

然后，您可以通过调用`$axiosTypicode`在任何页面上使用这个`axios`实例，如下所示：

```js
// pages/users/index.vue
export default {
  async asyncData ({ $axiosTypicode, error }) {
    let { data } = await $axiosTypicode.get('/users')
  }
}
```

我们将在第六章中更详细地查看这个目录，*编写插件和模块*。

请注意，`axios`是一个我们在本书中经常使用的 HTTP 客户端。在导入前，您需要在项目目录中安装它。有关这个 Node.js 包的更多信息，请访问[`github.com/axios/axios`](https://github.com/axios/axios)。

## 存储目录

`/store/`目录用于包含 Vuex 存储文件。您不需要在 Nuxt 中安装 Vuex，因为它已经与 Nuxt 一起提供。它默认情况下是禁用的，您只需在此目录中添加一个`index.js`文件即可启用它。例如，如果您想要一个名为`auth`的属性，可以在整个应用程序中访问。

您将在`index.js`文件中将该属性存储在`state`变量中，如下所示：

```js
// store/index.js:
export const state = () => ({
  auth: null
})
```

我们将在第十章中更详细地查看此目录，*添加 Vuex 存储*。

## 中间件目录

`/middleware/`目录用于包含中间件文件，这些文件是在渲染页面或一组页面之前运行的 JavaScript 函数。例如，您可能希望有一个只有在用户经过身份验证时才能访问的秘密页面。您可以使用 Vuex 存储来存储经过身份验证的数据，并创建一个中间件，如果`state`存储中的`auth`属性为空，则抛出`403`错误：

```js
// middleware/auth.js
export default function ({ store, error }) {
  if (!store.state.auth) {
    error({
      message: 'You are not connected',
      statusCode: 403
    })
  }
}
```

我们将在第十一章中更详细地查看此目录，*编写路由中间件和服务器中间件*。

## package.json 文件

`package.json`文件用于包含 Nuxt 应用程序的依赖项和脚本。例如，如果您使用 Nuxt 脚手架工具，则在此文件中会获得以下默认脚本和依赖项：

```js
// package.json
{
  "scripts": {
    "dev": "nuxt",
    "build": "nuxt build",
    "start": "nuxt start",
    "generate": "nuxt generate"
  },
  "dependencies": {
    "nuxt": "².14.0"
  }
}
```

我们将在第八章中大量使用此文件，*添加服务器端框架*，以及在第十四章中，*使用检查器、格式化程序和部署命令*。

## nuxt.config.js 文件

`nuxt.config.js`文件用于包含应用程序特定的自定义配置。例如，当您使用 Nuxt 脚手架工具时，默认情况下会为 HTML 的`<head>`块获取这些自定义的元标记、标题和链接：

```js
export default {
  head: {
    title: process.env.npm_package_name || '',
    meta: [
      { charset: 'utf-8' },
      { name: 'viewport', content: 'width=device-width, initial-scale=1' },
      { hid: 'description', name: 'description', content: 
        process.env.npm_package_description || '' }
    ],
    link: [
      { rel: 'icon', type: 'image/x-icon', href: '/favicon.ico' }
    ]
  }
}
```

我们可以修改前面的自定义头部块。您将在第四章中学习如何做到这一点，*添加视图、路由和转换*。除了`head`之外，还有其他关键属性可用于进行自定义配置，我们将在接下来的部分中介绍。

## 别名

在 Nuxt 中，`~` 或 `@` 别名用于与 `srcDir` 属性关联，`~~` 或 `@@` 别名用于与 `rootDir` 属性关联。例如，如果您想将图像链接到 `/assets/` 目录，可以使用 `~` 别名，如下所示：

```js
<template>
  <img src="~/assets/sample-1.jpg"/>
</template>
```

另一方面，如果您想将图像链接到 `/static/` 目录，可以使用 `~` 别名，如下所示：

```js
<template>
  <img src="~/static/sample-1.jpg"/>
</template>
```

请注意，您也可以在不使用这些别名的情况下链接到 `/static/` 目录中的资源：

```js
<template>
  <img src="/sample-1.jpg"/>
</template>
```

`srcDir` 的值默认与 `rootDir` 的值相同，即 `process.cwd()`。我们将在下一节中介绍这两个选项，您将学习如何更改它们的默认值。因此，让我们探讨如何在项目中自定义配置。

# 理解自定义配置

您可以通过在项目的根目录中添加一个 `nuxt.config.js` 文件（本书中将其称为**Nuxt 配置文件**）来配置您的 Nuxt 应用以适应您的项目。如果您使用 Nuxt 脚手架工具，默认情况下会得到这个文件。当您打开此文件时，应该会得到以下选项（或属性）：

```js
// nuxt.config.js
export default {
  mode: 'universal',
  target: 'server',
  head: { ... },
  css: [],
  plugins: [],
  components: true,
  buildModules: [],
  modules: [],
  build: {}
}
```

其中大多数为空，除了 `mode`、`target`、`head` 和 `components`。您可以通过这些选项定制 Nuxt 以适应您的项目。让我们逐个了解它们，然后再看看其他选项，看看您可以如何使用它们。

## `mode` 选项

`mode` 选项用于定义应用的“性质” - 无论是通用应用还是单页应用。其默认值为 *universal*。如果您正在使用 Nuxt 开发单页应用，那么将此值更改为 `spa`。在本书的即将到来的章节中，我们将专注于通用模式，除了 第十五章 *使用 Nuxt 创建单页应用*。

## `target` 选项

`target` 选项用于设置应用的部署目标 - 无论是作为服务器端渲染应用还是静态生成应用进行部署。其默认值为服务器端渲染部署的 `server`。本书中大多数示例应用的部署目标是服务器端渲染。在最后一章 - 第十八章 *使用 CMS 和 GraphQL 创建 Nuxt 应用* 中，我们也会针对静态生成部署进行目标设置。

## `head` 选项

`head`选项用于在我们应用程序的`<head>`块中定义所有默认的元标签。如果您使用 Nuxt 脚手架工具，您将在 Nuxt 配置文件中获得以下自定义`head`配置：

```js
// nuxt.config.js
export default {
  head: {
    title: process.env.npm_package_name || '',
    meta: [
      { charset: 'utf-8' },
      { name: 'viewport', content: 'width=device-width, initial-scale=1' },
      { hid: 'description', name: 'description', content: 
        process.env.npm_package_description || '' }
    ],
    link: [
      { rel: 'icon', type: 'image/x-icon', href: '/favicon.ico' }
    ]
  }
}
```

您可以修改上述配置或添加更多自定义配置 - 例如，添加一些对项目所需的 JavaScript 和 CSS 库：

```js
// nuxt.config.js
export default {
  head: {
    titleTemplate: '%s - Nuxt App',
    meta: [
      //...
    ],
    script: [
      { src: 'https://cdnjs.cloudflare.com/.../jquery.min.js' },
      { src: 'https://cdn.jsdelivr.net/.../foundation.min.js' },
    ],
    link: [
      { rel: 'stylesheet', href: 
      'https://cdn.jsdelivr.net/.../foundation.min.css' },
    ]
  }
}
```

我们将在第三章的*添加 UI 框架*和第四章的*添加视图、路由和转换*中更详细地介绍这个选项。请注意，jQuery 是 Foundation（Zurb）的核心依赖项，我们将在第三章的*添加 UI 框架*中进行探讨。因此，目前需要在项目中安装 jQuery 才能使用 Foundation。这在未来的版本中可能会变成可选项。

## css 选项

`css`选项用于添加全局 CSS 文件。这些可以是`.css`、`.less`或`.scss`文件。它们也可以是直接从项目中的 Node.js `/node_modules/`目录加载的模块和库。例如，看下面的例子：

```js
// nuxt.config.js
export default {
  css: [
    'jquery-ui-bundle/jquery-ui.min.css',
    '@/assets/less/styles.less',
    '@/assets/scss/styles.scss'
  ]
}
```

在上述配置中，我们从安装在`/node_modules/`目录中的 jQuery UI 模块加载 CSS 文件，以及存储在`/assets/`目录中的 Less 和 Sass 文件。请注意，如果您使用`.less`和`.scss`文件编写样式，您需要安装 Less 和 Sass 模块以及它们的 webpack 加载器，如下所示：

```js
$ npm i less less-loader --save-dev
$ npm i node-sass --save-dev
$ npm i sass-loader --save-dev
```

我们将在第三章的*添加 UI 框架*和[第四章](https://cdp.packtpub.com/hands_on_web_development_with_nuxt_js_2_0/wp-admin/post.php?post=27&action=edit)的*添加视图、路由和转换*中更多地使用这个选项。

## 插件选项

`plugins`选项用于添加在根 Vue 实例之前运行的 JavaScript 插件。例如，看下面的例子：

```js
// nuxt.config.js
export default {
  plugins: ['~/plugins/vue-notifications']
}
```

我们经常与前面的章节中介绍的`/plugins/`目录一起使用这个选项。我们将在第六章的*编写插件和模块*中大量使用这个选项。

## 组件选项

components 选项用于设置/components/目录中的组件是否应该自动导入。如果你有大量组件需要导入到布局或页面中，这个选项非常有用。如果将此选项设置为 true，则无需手动导入它们。它的默认值为 false。我们在本书中为所有应用程序将此选项设置为 true。

有关此选项的更多信息和（高级）用法，请访问 https://github.com/nuxt/components。

## buildModules 选项

buildModules 选项用于注册仅构建的模块 - 仅在开发和构建时需要的模块。在本书中，请注意我们将仅利用 Nuxt 社区中的一些模块，并创建在 Node.js 运行时需要的自定义模块。但是，有关 buildModules 选项和仅构建时需要的模块的更多信息，请访问 https://nuxtjs.org/guide/modules#build-only-modules。

## 模块选项

modules 选项用于向项目添加 Nuxt 模块。例如，可以使用以下内容：

```js
// nuxt.config.js
export default {
  modules: [
    '@nuxtjs/axios',
    '~/modules/example.js'
  ]
}
```

我们还可以直接使用此选项创建内联模块：

```js
// nuxt.config.js
export default {
  modules: [
    function () {
      //...
    }
  ]
}
```

Nuxt 模块本质上是 JavaScript 函数，就像插件一样。我们将在第六章《编写插件和模块》中讨论它们之间的区别。就像经常与/plugins/目录一起使用的 plugins 选项一样，modules 选项经常与/modules/目录一起使用。我们将在第六章《编写插件和模块》中经常使用这个选项。

## 构建选项

build 选项用于自定义 webpack 配置，以便按照您喜欢的方式构建 Nuxt 应用程序。例如，您可能希望在项目中全局安装 jQuery，这样每次需要时就不必使用 import。您可以使用 webpack 的 ProvidePlugin 函数自动加载 jQuery，如下所示：

```js
// nuxt.config.js
import webpack from 'webpack'

export default {
  build: {
    plugins: [
      new webpack.ProvidePlugin({
        $: "jquery"
      })
    ]
  }
}
```

我们将在[第四章](https://cdp.packtpub.com/hands_on_web_development_with_nuxt_js_2_0/wp-admin/post.php?post=27&action=edit)中再次使用`build`选项，*添加视图、路由和转换*，在第六章中，*编写插件和模块*，以及在[第十四章](https://cdp.packtpub.com/hands_on_web_development_with_nuxt_js_2_0/wp-admin/post.php?post=37&action=edit)中，*使用 Linter、格式化程序和部署命令*。

有关你的 Nuxt 应用可以使用这个选项做些什么的更多细节和示例，请访问[`nuxtjs.org/api/configuration-build`](https://nuxtjs.org/api/configuration-build)。有关 webpack 的`ProvidePlugin`函数的更多信息，请访问[`webpack.js.org/plugins/provide-plugin/`](https://webpack.js.org/plugins/provide-plugin/)。如果你是 webpack 的新手，我们鼓励你访问并从[`webpack.js.org/guides/`](https://webpack.js.org/guides/)学习。

以下部分概述了一些额外的选项，可以用来进一步和更具体地定制你的 Nuxt 应用。让我们探索一些在你的项目中可能有用的选项。其中一些在本书中经常使用。所以，让我们开始吧！

## dev 选项

`dev`选项用于定义你的应用的`开发`或`生产`模式。它不会被添加到 Nuxt 配置文件中，但当你需要时可以手动添加。它只接受布尔类型，其默认值设置为`true`。它总是被`nuxt`命令强制为`true`，并且总是被`nuxt build`、`nuxt start`和`nuxt generate`命令强制为`false`。

因此，从技术上讲，你*不能*自定义它，但你可以在 Nuxt 模块中使用这个选项，如下所示：

```js
// modules/sample.js
export default function (moduleOptions) {
  console.log(this.options.dev)
}
```

你将得到`true`或`false`，取决于你使用哪个 Nuxt 命令。我们将在[第六章](https://cdp.packtpub.com/hands_on_web_development_with_nuxt_js_2_0/wp-admin/post.php?post=29&action=edit)中介绍这个模块，*编写插件和模块*。或者，你可以在将 Nuxt 作为包导入服务器端框架时使用这个选项，如下所示：

```js
// server/index.js
import { Nuxt, Builder } from 'nuxt'
import config from './nuxt.config.js'

const nuxt = new Nuxt(config)

if (nuxt.options.dev) {
  new Builder(nuxt).build()
}
```

当`dev`选项为`true`时，`new Builder(nuxt).build()`行将被运行。我们将在[第八章](https://cdp.packtpub.com/hands_on_web_development_with_nuxt_js_2_0/wp-admin/post.php?post=31&action=edit)中介绍服务器端框架，*添加服务器端框架*。

您可以在我们的 GitHub 存储库的`/chapter-2/configuration/dev/`中找到此选项的示例应用程序。

## rootDir 选项

`rootDir`选项用于定义 Nuxt 应用程序的工作空间。例如，假设您的项目位于以下位置：

```js
/var/www/html/my-project/
```

然后，您的项目的`rootDir`选项的默认值为`/var/www/html/my-project/`。但是，您可以按以下方式在`package.json`文件中使用 Nuxt 命令更改它：

```js
// my-project/package.json
{
  "scripts": {
    "dev": "nuxt ./app/"
  }
}
```

现在，您的 Nuxt 应用程序的工作空间位于`/var/www/html/my-project/app/`，您的应用程序结构已变为以下内容：

```js
-| my-project/
---| node_modules/
---| app/
------| nuxt.config.js
------| pages/
------| components/
------| ...
---| package.json
```

请注意，现在 Nuxt 配置文件必须放在`/app/`目录中。我们将在[第十四章](https://cdp.packtpub.com/hands_on_web_development_with_nuxt_js_2_0/wp-admin/post.php?post=37&action=edit)中介绍 Nuxt 命令，*使用 Linter、Formatter 和部署命令*。

您可以在我们的 GitHub 存储库的`/chapter-2/configuration/rooDir/`中找到此选项的示例应用程序。

## srcDir 选项

`srcDir`选项用于定义 Nuxt 应用程序的源目录。`srcDir`的默认值是`rootDir`的值。您可以按以下方式更改它：

```js
// nuxt.config.js
export default {
  srcDir: 'src/'
}
```

现在，您的应用程序结构已变为以下内容：

```js
-| my-project/
---| node_modules/
---| src/
------| pages/
------| components/
------| ...
---| nuxt.config.js
---| package.json
```

请注意，Nuxt 配置文件位于`/src/`目录之外。

您可以在我们的 GitHub 存储库的`/chapter-2/configuration/srcDir/`中找到此选项的示例应用程序。

## 服务器选项

`server`选项用于配置 Nuxt 应用程序的服务器连接变量。它具有以下默认服务器连接详细信息：

```js
export default {
  server: {
    port: 3000,
    host: 'localhost',
    socket: undefined,
    https: false,
    timing: false
  }
}
```

您可以按以下方式更改它们：

```js
export default {
  server: {
    port: 8080,
    host: '0.0.0.0'
  }
}
```

现在，您的应用程序正在`0.0.0.0:8080`上运行。

您可以在我们的 GitHub 存储库的`/chapter-2/configuration/server/`中找到此选项的示例应用程序。

## env 选项

`env`选项用于为 Nuxt 应用程序的客户端和服务器端设置环境变量。此选项的默认值为空对象`{}`。当您在项目中使用`axios`时，此选项非常有用。

采用以下示例：

```js
// nuxt.config.js
export default {
  env: {
    baseUrl: process.env.BASE_URL || 'http://localhost:3000'
  }
}
```

然后，您可以按以下方式在`axios`插件中设置`env`属性：

```js
// plugins/axios.js
import axios from 'axios'

export default axios.create({
  baseURL: process.env.baseUrl
})
```

现在，`baseURL`选项设置为`localhost:3000`，或者如果定义了`BASE_URL`，则为`BASE_URL`。我们可以在`package.json`中设置`BASE_URL`，如下所示：

```js
// package.json
"scripts": {
  "start": "cross-env BASE_URL=https://your-domain-name.com nuxt start"
}
```

您需要在 Windows 上安装`cross-env`才能使上述示例工作：

```js
$ npm i cross-env --save-dev
```

我们将在[第六章](https://cdp.packtpub.com/hands_on_web_development_with_nuxt_js_2_0/wp-admin/post.php?post=29&action=edit)中介绍插件，*编写插件和模块*。在创建跨域应用程序时，我们将在本书中经常使用`env`选项。

您可以在我们的 GitHub 存储库的`/chapter-2/configuration/env/`中找到此选项的示例应用程序。

## 路由器选项

`router`选项用于覆盖 Vue 路由器上的默认 Nuxt 配置。默认 Vue 路由器配置如下：

```js
{
  mode: 'history',
  base: '/',
  routes: [],
  routeNameSplitter: '-',
  middleware: [],
  linkActiveClass: 'nuxt-link-active',
  linkExactActiveClass: 'nuxt-link-exact-active',
  linkPrefetchedClass: false,
  extendRoutes: null,
  scrollBehavior: null,
  parseQuery: false,
  stringifyQuery: false,
  fallback: false,
  prefetchLinks: true
}
```

您可以按以下方式更改此配置：

```js
// nuxt.config.js
export default {
  router: {
    base: '/app/'
  }
}
```

现在，您的应用正在`localhost:3000/app/`上运行。

有关此属性及其余配置的更多信息，请访问[`nuxtjs.org/api/configuration-router`](https://nuxtjs.org/api/configuration-router)。

您可以在我们的 GitHub 存储库的`/chapter-2/configuration/router/`中找到此选项的示例应用程序。

## dir 选项

`dir`选项用于定义 Nuxt 应用中的自定义目录。默认目录如下：

```js
{
  assets: 'assets',
  layouts: 'layouts',
  middleware: 'middleware',
  pages: 'pages',
  static: 'static',
  store: 'store'
}
```

您可以按以下方式更改它们：

```js
// nuxt.config.js
export default {
  dir: {
    assets: 'nuxt-assets',
    layouts: 'nuxt-layouts',
    middleware: 'nuxt-middleware',
    pages: 'nuxt-pages',
    static: 'nuxt-static',
    store: 'nuxt-store'
  }
}
```

现在，您可以按以下方式使用前面的自定义目录：

```js
-| app/
---| nuxt-assets/
---| components/
---| nuxt-layouts/
---| nuxt-middleware/
---| node_modules/
---| nuxt-pages/
---| plugins/
---| modules/
---| nuxt-static/
---| nuxt-store/
---| nuxt.config.js
---| package.json
---| README.md
```

您可以在我们的 GitHub 存储库的`/chapter-2/configuration/dir/`中找到此选项的示例应用程序。

## 加载选项

`loading`选项用于自定义 Nuxt 应用中的默认加载组件。如果您不想使用这个默认加载组件，可以将其设置为`false`，如下所示：

```js
// nuxt.config.js
export default {
  loading: false
}
```

我们将在[第四章](https://cdp.packtpub.com/hands_on_web_development_with_nuxt_js_2_0/wp-admin/post.php?post=27&action=edit)中更详细地介绍这个选项，*添加视图、路由和转换*。

## 页面转换和布局转换选项

`pageTransition`和`layoutTransition`选项用于自定义 Nuxt 应用中页面和布局转换的默认属性。页面转换的默认属性设置如下：

```js
{
  name: 'page',
  mode: 'out-in',
  appear: false,
  appearClass: 'appear',
  appearActiveClass: 'appear-active',
  appearToClass: 'appear-to'
}
```

**布局**转换的默认属性设置如下：

```js
{
  name: 'layout',
  mode: 'out-in'
}
```

您可以按以下方式更改它们：

```js
// nuxt.config.js
export default {
  pageTransition: {
    name: 'fade'
  },
  layoutTransition: {
    name: 'fade-layout'
  }
}
```

我们将在[第四章](https://cdp.packtpub.com/hands_on_web_development_with_nuxt_js_2_0/wp-admin/post.php?post=27&action=edit)中更详细地介绍这些选项，*添加视图、路由和转换*。

## 生成选项

`generate`选项用于告诉 Nuxt 如何为静态 Web 应用程序生成动态路由。动态路由是通过在 Nuxt 中使用下划线创建的路由。我们将在[第四章](https://cdp.packtpub.com/hands_on_web_development_with_nuxt_js_2_0/wp-admin/post.php?post=27&action=edit) *添加视图、路由和过渡*中介绍这种类型的路由。如果我们希望将 Nuxt 应用导出为静态 Web 应用程序或 SPA，而不是将 Nuxt 用作通用应用程序（SSR），则使用`generate`选项来处理动态路由，这些动态路由*无法被 Nuxt 爬虫自动检测到*。例如，如果爬虫无法检测到您的应用中的以下动态路由（分页）：

```js
/posts/pages/1
/posts/pages/2
/posts/pages/3
```

然后，您可以使用此`generate`选项将每个路由的内容生成和转换为 HTML 文件，如下所示：

```js
// nuxt.config.js
export default {
  generate: {
    routes: [
      '/posts/pages/1',
      '/posts/pages/2',
      '/posts/pages/3'
    ]
  }
}
```

我们将向您展示如何使用此选项来生成路由，如果爬虫无法检测到它们，可以在第十五章 *创建 Nuxt SPA*和第十八章 *使用 CMS 和 GraphQL 创建 Nuxt 应用*中找到。

有关此`generate`选项的更多信息和更高级的用法，请访问[`nuxtjs.org/api/configuration-generate`](https://nuxtjs.org/api/configuration-generate)。

随着我们的学习，我们将在接下来的章节中涵盖和发现其他配置选项。然而，这些是您现在应该了解的基本自定义配置选项。现在，让我们在下一个主题中进一步探索 webpack 中的资源服务。

# 了解资源服务

Nuxt 使用`vue-loader`、`file-loader`和`url-loader`webpack 加载程序来提供应用程序中的资产。首先，Nuxt 将使用`vue-loader`处理`<template>`和`<style>`块，使用`css-loader`和`vue-template-compiler`来编译这些块中的元素，例如`<img src="...">`、`background-image: URL(...)`和这些块中的 CSS `@import`为模块依赖项。举个例子：

```js
// pages/index.vue
<template>
  <img src="~/assets/sample-1.jpg">
</template>

<style>
.container {
  background-image: url("~assets/sample-2.jpg");
}
</style>
```

在前述`<template>`和`<style>`块中的图像元素和资产将被编译和转换为以下代码和模块依赖项：

```js
createElement('img', { attrs: { src: require('~/assets/sample-1.jpg') }})
require('~/assets/sample-2.jpg')
```

请注意，从 Nuxt 2.0 开始，`~/`别名在样式中将无法正确解析，因此请改用`~assets`或`@/`别名。

在前面的编译和翻译之后，Nuxt 将使用`file-loader`来解析`import/require`模块依赖关系为 URL，并将资产发射（复制并粘贴）到输出目录 - 或者，使用`url-loader`将资产转换为 Base64 URI，如果资产小于 1KB。然而，如果资产大于 1KB 的阈值，它将退回到`file-loader`。这意味着任何小于 1KB 的文件将被`url-loader`内联为 Base64 数据 URL，如下所示：

```js
<img src="data:image/png;base64,iVBO...">
```

这可以让您更好地控制应用程序向服务器发出的 HTTP 请求的数量。内联资产会减少 HTTP 请求，而任何超过 1KB 的文件都将被复制并粘贴到输出目标，并以版本哈希命名以获得更好的缓存。例如，前述`<template>`和`<style>`块中的图像将被发射如下（通过`npm run build`）：

```js
img/04983cb.jpg 67.3 KiB [emitted]
img/cc6fc31.jpg 85.8 KiB [emitted]
```

您将在浏览器的前端看到以下图像：

```js
<div class="links">
  <img src="/_nuxt/img/04983cb.jpg">
</div>
```

以下是这两个 webpack 加载程序（`url-loader`和`file-loader`）的默认配置：

```js
[
  {
    test: /\.(png|jpe?g|gif|svg|webp)$/i,
    use: [{
      loader: 'url-loader',
      options: Object.assign(
        this.loaders.imgUrl,
        { name: this.getFileName('img') }
      )
    }]
  },
  {
    test: /\.(woff2?|eot|ttf|otf)(\?.)?$/i,
    use: [{
      loader: 'url-loader',
      options: Object.assign(
        this.loaders.fontUrl,
        { name: this.getFileName('font') }
      )
    }]
  },
  {
    test: /\.(webm|mp4|ogv)$/i,
    use: [{
      loader: 'file-loader',
      options: Object.assign(
        this.loaders.file,
        { name: this.getFileName('video') }
      )
    }]
  }
]
```

您可以像我们在前面的主题中所做的那样使用 webpack 配置的`build`选项来自定义此默认配置。

有关`file-loader`和`url-loader`的更多信息，请访问[`webpack.js.org/loaders/file-loader/`](https://webpack.js.org/loaders/file-loader/)和[`webpack.js.org/loaders/url-loader/`](https://webpack.js.org/loaders/url-loader/)。

有关`vue-loader`和`vue-template-compiler`的更多信息，请访问[`vue-loader.vuejs.org/`](https://vue-loader.vuejs.org/)和[`www.npmjs.com/package/vue-template-compiler`](https://www.npmjs.com/package/vue-template-compiler)。

如果您对 webpack 不熟悉，请访问[`webpack.js.org/concepts/`](https://webpack.js.org/concepts/)。另请访问[`webpack.js.org/guides/asset-management/`](https://webpack.js.org/guides/asset-management/)了解其资产管理指南。简而言之，webpack 是 JavaScript 应用程序的静态模块打包工具。它的主要目的是捆绑 JavaScript 文件，但也可以用于转换 HTML、CSS、图像和字体等资产。如果您不想以 webpack 为您提供的方式提供资产，您也可以使用`/static/`目录用于静态资产，就像我们在前一节“理解目录结构”中提到的那样。然而，使用 webpack 提供资产也有好处。让我们在下一节中了解它们是什么。

## webpack 资产与静态资产

使用 webpack 提供资产的好处之一是它会为生产进行优化，无论是图像、字体还是预处理样式，如 Less、Sass 或 Stylus。webpack 可以将 Less、Sass 和 Stylus 转换为通用 CSS，而静态文件夹只是一个放置所有静态资产的地方，这些资产将*永远*不会被 webpack 触及。在 Nuxt 中，如果您不想为项目使用`/assets/`目录中的 webpack 资产，可以使用`/static/`目录代替。

例如，我们可以从`/static/`目录中使用静态图像，如下所示：

```js
// pages/index.vue
<template>
  <img src="/sample-1.jpg"/>
</template>
```

另一个很好的例子是 Nuxt 配置文件中的 favicon 文件：

```js
// nuxt.config.js
export default {
  head: {
    link: [
      { rel: 'icon', type: 'image/x-icon', href: '/favicon.ico' }
    ]
  }
}
```

请注意，如果您使用`~`别名来链接`/static/`目录中的资产，webpack *将*处理这些资产，就像`/assets/`目录中的资产一样，如下所示：

```js
// pages/index.vue
<template>
  <img src="~/static/sample-1.jpg"/>
</template>
```

我们将在[第三章](https://cdp.packtpub.com/hands_on_web_development_with_nuxt_js_2_0/wp-admin/post.php?post=26&action=edit)中大量使用`/assets/`目录来提供资产，*添加 UI 框架*，以及在[第四章](https://cdp.packtpub.com/hands_on_web_development_with_nuxt_js_2_0/wp-admin/post.php?post=27&action=edit)中，*添加视图、路由和转换*，以及在[第五章](https://cdp.packtpub.com/hands_on_web_development_with_nuxt_js_2_0/wp-admin/post.php?post=28&action=edit)中，*添加 Vue 组件*，以动态方式提供资产。现在，让我们总结一下您在本章中学到的内容。

您可以在我们的 GitHub 存储库的`/chapter-2/assets/`中找到一个用于从这两个目录提供资产和文件的示例应用程序。

# 总结

在本章中，您学会了如何使用`create-nuxt-app`安装 Nuxt，以及如何从头开始安装它，以及 Nuxt 脚手架工具安装的默认目录。您还学会了如何使用`nuxt.config.js`文件来自定义您的应用程序。最后，您学会了了解 Nuxt 中资产的工作方式以及使用 webpack 和`/static/`文件夹进行资产提供之间的区别。

在即将到来的章节中，您将学习如何为您的应用程序安装自定义 UI 框架、库和工具，例如 Zurb Foundation、Motion UI、jQuery UI 和 Less CSS。您将编写一些基本代码来为您的首页添加样式并为其添加一些动画。您还将开始使用我们在本章中刚刚介绍的一些目录，如`/assets/`、`/plugins/`和`/pages/`目录，来开发您的 Nuxt 应用程序。


添加 UI 框架

在本章中，我们将指导您安装一些前端 UI 框架到您的 Nuxt 项目中，这些框架将为您的应用模板添加样式。本书中我们选择的框架有 Foundation 用于设计布局，Motion UI 用于创建动画，Less 作为样式表语言，jQuery UI 用于为 DOM 添加动画，AOS 用于在滚动时为内容添加动画，以及 Swiper 用于创建轮播图像。这些框架可以加快 Nuxt 项目的前端开发速度，使其变得有趣且简单。

本章我们将涵盖的主题如下：

+   添加基础和 Motion UI

+   添加 Less（更轻量的样式表）

+   添加 jQuery UI

+   添加 AOS

+   添加 Swiper

# 第三章：添加基础和 Motion UI

Foundation 是一个用于创建响应式网站的前端框架。它提供了用于网格布局、排版、按钮、表格、导航、表单等的 HTML 和 CSS 模板，以及可选的 JavaScript 插件。它适用于任何设备，移动或桌面，并且是 Bootstrap（https://getbootstrap.com/）的另一种流行的前端框架。我们在本书中专注于 Foundation。因此，就像在上一章中一样，当使用`create-nuxt-app`脚手架安装 Nuxt 项目的骨架时，我们有一系列建议的 UI 框架供您选择。我们应该选择`None`，以便我们可以添加 Foundation 作为 UI 框架：

```js
? Choose UI framework (Use arrow keys)
❯ None
  Ant Design Vue
  Bootstrap Vue
  ...
```

一旦您回答了安装过程中的问题，导航到您的项目目录，然后您可以安装并集成 Foundation 到您的 Nuxt 应用程序中。最简单的方法是使用**内容交付网络**（**CDN**），但不鼓励这样做。最简单的原因是，如果您离线开发，CDN 链接将无法工作。此外，您将失去对源文件的控制，因为它们由大型网络公司（如 Google、Microsoft 和 Amazon）处理。但是，如果您想在 Nuxt 项目中使用 CDN 快速启动，只需将 CDN 源添加到 Nuxt 配置文件中的`head`选项中，如下所示：

```js
// nuxt.config.js
export default {
  head: {
    script: [
      { src: 'https://cdn.jsdelivr.net/.../foundation.min.js' },
    ],
    link: [
      { rel: 'stylesheet', href: 
      'https://cdn.jsdelivr.net/.../foundation.min.css' },
    ],
  },
}
```

您可以在官方 Foundation 网站上找到最新的 CDN 链接：https://get.foundation/sites/docs/installation.html#cdn-links。

这很容易，不是吗？但如果您想要在本地托管源文件，这并不理想。让我们在以下步骤中找出与 Nuxt 集成的正确方法：

1.  通过 npm 在终端上安装 Foundation 及其依赖项（jQuery 和 what-input）：

```js
$ npm i foundation-sites
$ npm i jquery
$ npm i what-input
```

1.  从`/node_modules/`文件夹中的 Foundation CSS 源添加到 Nuxt 配置文件中的`css`选项中，如下所示：

```js
// nuxt.config.js
export default {
  css: [
    'foundation-sites/dist/css/foundation.min.css'
  ],
}
```

1.  在`/plugins/`目录中创建一个`foundation.client.js`文件，并添加以下代码：

```js
// plugins/client-only/foundation.client.js
import 'foundation-sites'
```

这个插件将确保 Foundation 仅在客户端运行。我们将在第六章中更详细地介绍插件和模块。

1.  在 Nuxt 配置文件的`plugins`选项中注册上述 Foundation 插件，如下所示：

```js
// nuxt.config.js
export default {
  plugins: [
    '~/plugins/client-only/foundation.client.js',
  ],
}
```

1.  然后，您可以在需要的任何页面中使用 Foundation 的 JavaScript 插件，例如：

```js
// layouts/form.vue
<script>
import $ from 'jquery'

export default {
  mounted () {
    $(document).foundation()
  }
}
</script>
```

就是这样。您已经成功在您的 Nuxt 项目中安装并成功集成了它。现在，让我们在下一节中探讨如何使用 Foundation 创建网格结构布局和网站导航，以加速前端网页开发。

## 使用 Foundation 创建网格布局和网站导航

我们应该首先看一下 Foundation 的网格系统，它被称为 XY Grid。在网页开发中，网格系统是一种将我们的 HTML 元素结构化为基于网格的布局的系统。Foundation 带有我们可以轻松使用的 CSS 类来结构化我们的 HTML 元素，例如：

```js
<div class="grid-x">
  <div class="cell medium-6">left</div>
  <div class="cell medium-6">right</div>
</div
```

这将在大屏幕上（例如 iPad，Windows Surface）将我们的元素响应地结构化为两列，但在小屏幕上（例如 iPhone）将其结构化为单列。让我们在默认的`index.vue`页面和由`create-nuxt-app`脚手架工具生成的`default.vue`布局中创建一个响应式布局和网站导航：

1.  删除`/components/`目录中的`Logo.vue`组件。

1.  删除`/pages/`目录中`index.vue`页面中的`<style>`和`<script>`块，但用以下元素和网格类替换`<template>`块：

```js
// pages/index.vue
<template>
  <div class="grid-x">
    <div class="medium-6 cell">
      <img src="~/assets/images/sample-01.jpg">
    </div>
    <div class="medium-6 cell">
      <img src="~/assets/images/sample-02.jpg">
    </div>
  </div>
</template>
```

在这个模板中，当页面在大屏幕上加载时，图像会并排结构。但当页面调整大小或在小屏幕上加载时，它们会自适应地堆叠在一起。

1.  删除`/layouts/`目录中`default.vue`布局中的`<style>`和`<script>`块，但用以下导航替换`<template>`块：

```js
// layouts/default.vue
<template>
  <div>
    <ul class="menu align-center">
      <li><nuxt-link to="/">Home</nuxt-link></li>
      <li><nuxt-link to="/form">Form</nuxt-link></li>
      <li><nuxt-link to="/motion-ui">Motion UI</nuxt-link></li>
    </ul>
    <nuxt />
  </div>
</template>
```

在这个新布局中，我们只是创建了一个基本的网站水平菜单，其中包含一个填充有三个`<li>`元素和`<nuxt-link>`组件的`<ul>`元素，并通过在`<ul>`元素后添加`.align-center`类将菜单项对齐到中心。

就是这样。现在您拥有一个可以在任何设备上完美运行的具有响应式布局和导航的网站。您可以看到，您可以在不编写任何 CSS 样式的情况下快速完成它。很棒，不是吗？但 JavaScript 呢？Foundation 还附带了一些 JavaScript 实用程序和插件，我们也可以利用它们。让我们在下一节中找出。

有关 Foundation 中 XY 网格和导航的更多信息，请访问[`get.foundation/sites/docs/xy-grid.html`](https://get.foundation/sites/docs/xy-grid.html)和[`get.foundation/sites/docs/menu.html`](https://get.foundation/sites/docs/menu.html)。

## 使用 Foundation 的 JavaScript 实用程序和插件

Foundation 附带许多有用的 JavaScript 实用程序，例如 MediaQuery。此 MediaQuery 实用程序可用于获取应用程序中创建响应式布局所需的屏幕大小断点（小，中，大，超大）。让我们在以下步骤中找出如何使用它：

1.  创建一个`utils.js`文件，将您的自定义全局实用程序保存在`/plugins/`目录中，并添加以下代码：

```js
// plugins/utils.js
import Vue from 'vue'
Vue.prototype.$getCurrentScreenSize = () => {
  window.addEventListener('resize', () => {
    console.log('Current screen size: ' +
     Foundation.MediaQuery.current)
  })
}
```

在这段代码中，我们创建了一个全局插件（即 JavaScript 函数），它将从 MediaQuery 实用程序的`current`属性中获取当前屏幕大小，并在浏览器的屏幕大小更改时记录输出。通过使用 JavaScript 的`EventTarget`方法`addEventListener`，将调整大小事件监听器添加到 window 对象中。然后通过将其命名为`$getCurrentScreenSize`将此插件注入到 Vue 实例中。

1.  在默认布局中调用`$getCurrentScreenSize`函数如下：

```js
// layouts/default.vue
<script>
export default {
  mounted () {
    this.$getCurrentScreenSize()
  }
}
</script>
```

因此，如果您在 Chrome 浏览器上打开控制台选项卡，当您调整屏幕大小时，您应该会看到当前屏幕大小的日志，例如`当前屏幕大小：中等`。

有关 Foundation MediaQuery 和其他实用程序的更多信息，请访问[`get.foundation/sites/docs/javascript-utilities.html#mediaquery`](https://get.foundation/sites/docs/javascript-utilities.html#mediaquery)和[`get.foundation/sites/docs/javascript-utilities.html`](https://get.foundation/sites/docs/javascript-utilities.html)。

有关 JavaScript EventTarget 和 addEventListener 的更多信息，请访问[`developer.mozilla.org/en-US/docs/Web/API/EventTarget`](https://developer.mozilla.org/en-US/docs/Web/API/EventTarget)和[`developer.mozilla.org/en-US/docs/Web/API/EventTarget/addEventListener`](https://developer.mozilla.org/en-US/docs/Web/API/EventTarget/addEventListener)。

除了 JavaScript 实用程序之外，Foundation 还提供了许多 JavaScript 插件，例如 Dropdown Menu 用于创建下拉导航，Abide 用于表单验证，Tooltip 用于在 HTML 页面中显示元素的扩展信息。这些插件可以通过简单地将它们的类名添加到您的元素中来激活。此外，您可以通过编写 JavaScript 来修改和与它们交互，就像我们在本节中向您展示的那样。让我们在以下步骤中看一下 Abide 插件：

1.  创建包含提交按钮和重置按钮的最后一个`<div>`块，如下所示：

```js
// pages/form.vue
<template>
  <form data-abide novalidate>
    <div class="grid-container">
      <div class="grid-x">
        <div class="cell small-12">
          <div data-abide-error class="alert callout" 
           style="display: none;">
            <p><i class="fi-alert"></i> There are errors in your 
             form.</p>
          </div>
        </div>
      </div>
    </div>
    <div class="grid-container">
      <div class="grid-x">
        //...
      </div>
    </div>
  </form>
</template>
```

在这个表单中，第一个网格容器包含一般错误消息，而第二个容器将包含表单输入字段。我们通过向表单元素添加`data-abide`来激活 Abide 插件。我们还向表单元素添加了一个`novalidate`属性，以防止浏览器的本机验证，这样我们就可以将工作交给 Abide 插件。

1.  创建一个包含`.cell`和`.small-12`类的`<div>`块，其中包含一个电子邮件`<input>`元素和两个默认错误消息`<span>`元素，如下所示：

```js
// pages/form.vue
<div class="cell small-12">
  <label>Email (Required)
    <input type="text" placeholder="hello@example.com" required
      pattern="email">
    <span class="form-error" data-form-error-on="required">
      Sorry, this field is required.
    </span>
    <span class="form-error" data-form-error-on="pattern">
      Sorry, invalid Email
    </span>
  </label>
</div>
```

创建两个包含两个`<input>`元素的`<div>`块，用于收集密码，其中第二个密码用于通过在第二个密码`<input>`元素中添加`data-equalto`属性来匹配第一个密码，如下所示：

1.  在`/pages/`目录中创建一个`form.vue`页面，其中包含以下 HTML 元素，以创建包含两个`.grid-container`元素的表单：

```js
// pages/form.vue
<div class="cell small-12">
  <label>Password Required
    <input type="password" placeholder="chewieR2D2" required >
    <span class="form-error">
      Sorry, this field is required.
    </span>
  </label>
</div>
<div class="cell small-12">
  <label>Re-enter Password
    <input type="password" placeholder="chewieR2D2" required
      pattern="alpha_numeric"
      data-equalto="password">
    <span class="form-error">
      Sorry, passwords are supposed to match!
    </span>
  </label>
</div>
```

1.  在这个单元格块中，有三个来自 Foundation 的自定义属性：`pattern`属性用于验证电子邮件字符串，`data-form-error-on`属性用于显示与`required`和`pattern`属性相应的输入错误，`placeholder`属性用于在输入字段中显示输入提示。请注意，`required`属性是 HTML5 的默认属性。

```js
// pages/form.vue
<div class="cell small-12">
  <button class="button" type="submit" value="Submit">Submit</button>
  <button class="button" type="reset" value="Reset">Reset</button>
</div>
```

1.  在 Vue 组件挂载时，在`<script>`块中初始化 Foundation JavaScript 插件：

```js
// pages/form.vue
<script>
import $ from 'jquery'

export default {
  mounted () {
    $(document).foundation()
  }
}
</script>
```

就是这样。不需要编写任何 JavaScript，只需添加带有类和属性的 HTML 元素，就可以创建一个漂亮的前端表单验证。这非常有用！

有关 Foundation 中 Abide 插件的更多信息，请访问[`get.foundation/sites/docs/abide.html`](https://get.foundation/sites/docs/abide.html)。

除了 JavaScript 实用程序和插件外，Zurb Foundation 还有一些有用的库，我们可以从中受益：Motion UI 用于创建 Sass/CSS 动画，Panini 用于使用可重用部分创建页面和布局，Style Sherpa 用于为代码库创建样式指南。我们将在下一节中探讨如何使用 Motion UI 创建 CSS 动画和过渡。让我们找出！

## 使用 Motion UI 创建 CSS 动画和过渡

Motion UI 是 Zurb Foundation 的一个方便的 Sass 库，用于快速创建 CSS 过渡和动画。您可以从 Motion UI 网站下载 Starter Kit 并进行调试，但这缺乏自己的控制，因为它带有许多内置的默认值和效果，您必须遵循。因此，如果您想要更多的控制并充分利用 Motion UI，您必须知道如何自定义和编译 Sass 代码。让我们在以下步骤中找出如何编写您的 Sass 动画：

1.  通过 npm 在终端上安装 Motion UI 及其依赖项（Sass 和 Sass loader）：

```js
$ npm i motion-ui --save-dev
$ npm i node-sass --save-dev
$ npm i sass-loader --save-dev
```

1.  在`/assets/`目录中的`/css/`文件夹中创建一个`main.scss`文件，并按以下方式导入 Motion UI：

```js
// assets/scss/main.scss
@import 'motion-ui/src/motion-ui';
@include motion-ui-transitions;
@include motion-ui-animations;
```

1.  随后是自定义 CSS 动画如下：

```js
// assets/scss/main.scss
.welcome {
  @include mui-animation(fade);
  animation-duration: 2s;
}
```

1.  在 Nuxt 配置文件的`css`选项中注册自定义 Motion UI CSS 资源：

```js
// nuxt.config.js
export default {
  css: [
    'assets/scss/main.scss'
  ]
}
```

1.  通过使用其类名将动画应用于任何元素，例如：

```js
// pages/index.vue
<img class="welcome" src="~/assets/images/sample-01.jpg">
```

然后，您应该看到上述图像在页面加载时逐渐淡入需要 2 秒钟的时间。

Motion UI 还提供了两个公共函数，我们可以与其交互以触发其内置动画和过渡：`animationIn`和`animateOut`。让我们在以下步骤中找出如何使用它们：

1.  在`/plugins/`目录中创建一个`motion-ui.client.js`文件，其中包含以下代码：

```js
// plugins/client-only/motion-ui.client.js
import Vue from 'vue'
import MotionUi from 'motion-ui'
Vue.prototype.$motionUi = MotionUi
```

此插件将确保 Motion UI 仅在客户端运行。我们将在第六章中更详细地介绍插件和模块的内容。

1.  在 Nuxt 配置文件的`plugins`选项中注册上述 Motion UI 插件如下：

```js
// nuxt.config.js
export default {
  plugins: [
    '~/plugins/client-only/motion-ui.client.js',
  ],
}
```

1.  在模板中随意使用 Motion UI 函数，例如：

```js
// pages/motion-ui.vue
<template>
  <h1 data-animation="spin-in">Hello Motion UI</h1>
</template>

<script>
import $ from 'jquery'

export default {
  mounted () {
    $('h1').click(function() {
      var $animation = $('h1').data('animation')
      this.$motionUi.animateIn($('h1'), $animation)
    })
  }
}
</script>
```

在此页面中，我们将过渡名称`spin-in`存储在元素的`data`属性中，然后将其传递给 Motion UI 的`animateIn`函数，在元素被点击时应用动画。请注意，我们使用 jQuery 从`data`属性中获取数据。

如果您想了解其余内置过渡名称，请访问[`get.foundation/sites/docs/motion-ui.html#built-in-transitions`](https://get.foundation/sites/docs/motion-ui.html#built-in-transitions)。

这很酷，不是吗？如果您需要在元素上使用 CSS 动画或过渡，而又不想自己编写大量的 CSS 代码，这将非常方便。这可以使您的 CSS 样式保持简洁，并专注于模板的主要和自定义呈现。说到节省时间和不必亲自编写通用代码，还值得一提的是 Zurb Foundation 提供的常用图标字体——Foundation Icon Font 3。让我们在下一节中了解一下您可以从中受益的方式。

有关 Motion UI 的更多信息，请访问[`get.foundation/sites/docs/motion-ui.html`](https://get.foundation/sites/docs/motion-ui.html)。至于 Panini 和 Style Sherpa，请访问[`get.foundation/sites/docs/panini.html`](https://get.foundation/sites/docs/panini.html)和[`get.foundation/sites/docs/style-sherpa.html`](https://get.foundation/sites/docs/style-sherpa.html)。

## 使用 Foundation Icon Fonts 3 添加图标

Foundation Icon Fonts 3 是我们可以在前端开发项目中使用的有用图标字体集之一。它可以帮助您避免自己创建常见的图标，例如社交媒体图标（Facebook、Twitter、YouTube）、箭头图标（向上箭头、向下箭头等）、辅助功能图标（轮椅、电梯等）、电子商务图标（购物车、信用卡等）和文本编辑器图标（加粗、斜体等）。让我们在以下步骤中了解如何在您的 Nuxt 项目中安装它：

1.  通过 npm 安装 Foundation Icon Fonts 3：

```js
$ npm i foundation-icon-fonts
```

1.  在 Nuxt 配置文件中全局添加 Foundation Icon Fonts 的路径：

```js
// nuxt.config.js
export default {
  css: [
    'foundation-icon-fonts/foundation-icons.css',
  ]
}
```

1.  使用图标名称前缀为`fi`的任何`<i>`元素应用图标，例如：

```js
<i class="fi-heart"></i>
```

您可以在[`zurb.com/playground/foundation-icon-fonts-3`](https://zurb.com/playground/foundation-icon-fonts-3)找到其余图标名称。

干得好！在本节和之前关于将 Foundation 添加到您的 Nuxt 项目的章节中，您已经成功地使用了网格系统来构建您的布局，并使用 Sass 创建了 CSS 动画。但是，添加网格系统和编写 CSS 动画还不足以构建一个应用程序；我们需要特定的 CSS 来描述 Nuxt 应用程序中 HTML 文档和 Vue 页面的呈现。我们可以在整个项目中使用 Sass 来创建无法仅通过使用 Foundation 完成的自定义样式，但让我们尝试另一种流行的样式预处理器并将其添加到您的 Nuxt 项目中——**Less**。让我们在下一节中找出。

您可以在我们的 GitHub 存储库的`/chapter-3/nuxt-universal/adding-foundation/`中找到到目前为止学到的所有示例代码。

# 添加 Less（**Leaner Style Sheets**）

Less 代表 Leaner Style Sheets，是 CSS 的语言扩展。它看起来就像 CSS，因此非常容易学习。Less 只对 CSS 语言进行了一些方便的添加，这也是它可以被迅速学习的原因之一。您可以在使用 Less 编写 CSS 时使用变量、mixin、嵌套、嵌套 at-rules 和冒泡、操作、函数等等；例如，以下是变量的样子：

```js
@width: 10px;
@height: @width + 10px;
```

这些变量可以像其他编程语言中的变量一样使用；例如，您可以在普通的 CSS 中以以下方式使用前面的变量：

```js
#header {
  width: @width;
  height: @height;
}
```

上述代码将转换为以下 CSS，我们的浏览器将理解：

```js
#header {
  width: 10px;
  height: 20px;
}
```

这非常简单和整洁，不是吗？在 Nuxt 中，您可以通过在`<style>`块中使用`lang`属性来将 Less 作为您的 CSS 预处理器使用：

```js
<style lang="less">
</style>
```

如果您想要将本地样式应用于特定页面或布局，这种方式是很好和可管理的。您应该在`lang`属性之前添加一个`scoped`属性，以便本地样式仅在特定页面上本地应用，并且不会干扰其他页面的样式。但是，如果您有多个页面和布局共享一个公共样式，那么您应该在项目的`/assets/`目录中全局创建样式。因此，让我们看看您如何在以下步骤中使用 Less 创建全局样式：

1.  通过终端在 npm 上安装 Less 及其 webpack 加载器：

```js
$ npm i less --save-dev
$ npm i less-loader --save-dev
```

1.  在`/assets/`目录中创建一个`main.less`文件，并添加以下样式：

```js
// assets/less/main.less @borderWidth: 1px;
@borderStyle: solid;

.cell {
  border: @borderWidth @borderStyle blue;
}

.row {
  border: @borderWidth @borderStyle red;
}

```

1.  在 Nuxt 配置文件中安装上述全局样式如下：

```js
// nuxt.config.js
export default {
  css: [
    'assets/less/main.less'
  ]
}
```

1.  例如，在项目的任何地方应用上述样式：

```js
// pages/index.vue
<template>
  <div class="row">
    <div class="grid-x">
      <div class="medium-6 cell">
        <img class="welcome" src="~/assets/images/sample-01.jpg">
      </div>
      <div class="medium-6 cell">
        <img class="welcome" src="~/assets/images/sample-02.jpg">
      </div>
    </div>
  </div>
</template>
```

当你在浏览器上启动应用程序时，你应该看到刚刚添加到 CSS 类的边框。这些边框在开发布局时可以作为指南，因为网格系统下面的网格线是“不可见的”，没有可见的线可能很难将它们可视化。

你可以在我们的 GitHub 存储库的`/chapter-3/nuxt-universal/adding-less/`中找到上述代码。

由于我们在本节中涵盖了 CSS 预处理器，值得一提的是我们可以在`<style>`块、`<template>`块或`<script>`块中使用任何预处理器，例如：

+   如果你想用 CoffeeScript 编写 JavaScript，可以按照以下步骤进行：

```js
<script lang="coffee">
export default data: ->
  { message: 'hello World' }
</script>
```

有关 CoffeeScript 的更多信息，请访问[`coffeescript.org/`](https://coffeescript.org/)。

+   如果你想在 Nuxt 中使用 Pug 编写 HTML 标签，可以按照以下步骤进行：

```js
<template lang="pug">
  h1.blue Greet {{ message }}!
</template>
```

有关 Pug 的更多信息，请访问[`pugjs.org/`](https://pugjs.org/)。

+   如果你想使用 Sass（Syntactically Awesome Style Sheets）或 Scss（Sassy Cascaded Style Sheets）来编写 CSS 样式，可以按照以下步骤进行：

```js
<style lang="sass">
.blue
  color: blue
</style>

<style lang="scss">
.blue {
  color: blue;
}
</style>
```

有关 Sass 和 Scss 的更多信息，请访问[`sass-lang.com/`](https://sass-lang.com/)。

在本书中，我们在各章节中主要使用 Less、原生 HTML 和 JavaScript（主要是 ECMAScript 6 或 ECMAScript 2015）。但你可以自由选择任何我们提到的预处理器。现在让我们来看看在 Nuxt 项目中为 HTML 元素添加效果和动画的另一种方法——jQuery UI。

# 添加 jQuery UI

jQuery UI 是建立在 jQuery 之上的一组用户界面（UI）交互、效果、小部件和实用工具。它对设计师和开发人员都是一个有用的工具。与 Motion UI 和 Foundation 一样，jQuery UI 可以帮助你用更少的代码在项目中做更多事情。它可以通过使用 CDN 资源和以 jQuery 为依赖项轻松地添加到普通 HTML 页面中，例如：

```js
<script src="https://code.jquery.com/jquery-3.5.1.min.js"></script>
<script src="https://code.jquery.com/ui/1.12.1/jquery-ui.js"></script>
<link rel="stylesheet" href="https://code.jquery.com/ui/1.12.1/themes/base/jquery-ui.css">

<div id="accordion">...</div>

<script>
  $('#accordion').accordion()
</script>
```

再次强调，与 Foundation 一样。当你想要将 jQuery UI 与 Nuxt 集成时会有一些复杂。我们可以使用上述 CDN 资源，并将它们添加到 Nuxt 配置文件中的`head`选项中，如下所示：

```js
// nuxt.config.js
export default {
  head: {
    script: [
      { src: 'https://cdnjs.cloudflare.com/.../jquery.min.js' },
      { src: 'https://code.jquery.com/.../jquery-ui.js' },
    ],
    link: [
      { rel: 'stylesheet', href: 
       'https://code.jquery.com/.../jquery-ui.css' },
    ]
  }
}
```

但是，就像与 Foundation 集成一样，不鼓励这样做。以下是正确的做法：

1.  在终端上通过 npm 安装 jQuery UI：

```js
$ npm i jquery-ui-bundle
```

1.  将 jQuery UI 的 CSS 源文件从`/node_modules/`文件夹添加到 Nuxt 配置文件的`css`选项中：

```js
// nuxt.config.js
module.exports = {
  css: [
    'jquery-ui-bundle/jquery-ui.min.css'
  ]
}
```

1.  在`/plugins/`目录中创建一个名为`jquery-ui-bundle.js`的文件，并按以下方式导入 jQuery UI：

```js
// plugins/client-only/jquery-ui-bundle.client.js
import 'jquery-ui-bundle'
```

再次强调，此插件将确保 jQuery UI 仅在客户端上运行，并且我们将在第六章中更详细地介绍插件和模块的内容。

1.  在 Nuxt 配置文件的`plugins`选项中注册前面的 jQuery UI 插件，如下所示：

```js
// nuxt.config.js
export default {
  plugins: [
    '~/plugins/client-only/jquery-ui-bundle.client.js',
  ],
}
```

1.  现在您可以在任何地方使用 jQuery UI，例如：

```js
// pages/index.vue
<template>
  <div id="accordion">...</div>
</template>

<script>
import $ from 'jquery'

export default {
  mounted () {
    $('#accordion').accordion()
  }
}
</script>
```

在此示例中，我们使用了 jQuery UI 的一个小部件 Accordion 来显示可折叠的内容面板。您可以在[`jqueryui.com/accordion/`](https://jqueryui.com/accordion/)找到 HTML 代码的详细信息。

除了小部件，jQuery UI 还带有动画缓动效果等效果。让我们看看如何在以下步骤中使用缓动效果创建动画：

1.  在`/pages/`目录中创建一个名为`animate.vue`的新页面，并在`<template>`块中添加以下元素：

```js
// pages/animate.vue
<h1>Hello jQuery UI</h1>
```

1.  在`<template>`块中使用 jQuery 的`animate`函数和 jQuery UI 的缓动效果创建动画，如下所示：

```js
// pages/animate.vue
import $ from 'jquery'

export default {
  mounted () {
    var state = true
    $('h1').on('click', function() {
      if (state) {
        $(this).animate({
          color: 'red', fontSize: '10em'
        }, 1000, 'easeInQuint', () => {
          console.log('easing in done')
        })
      } else {
        $(this).animate({
          color: 'black', fontSize: '2em'
        }, 1000, 'easeOutExpo', () => {
          console.log('easing out done')
        })
      }
      state = !state
    })
  }
}
```

在此代码中，当单击元素时，我们使用`easeInQuint`缓动效果，再次单击时使用`easeOutExpo`缓动效果。单击时，元素的字体大小从`2em`变化到`10em`，再次单击时从`10em`变化到`2em`。对于文本颜色也是一样，当单击元素时，它在`red`和`black`之间进行动画变化。

1.  刷新您的浏览器，您应该会看到我们已经将动画和缓动效果应用到`H1`上。

有关更多缓动效果，请访问[`api.jqueryui.com/easings/`](https://api.jqueryui.com/easings/)，有关 jQuery 动画函数的更多信息，请访问[`api.jquery.com/animate/`](https://api.jquery.com/animate/)。

如果您想了解 jQuery UI 的其他效果、小部件和实用工具，请访问[`jqueryui.com/`](https://jqueryui.com/)。

尽管您可以使用 CSS 使用 Motion UI 创建动画和过渡效果，但是 jQuery UI 是另一种选项，可以使用 JavaScript 对 HTML 元素应用动画。除了 jQuery 和 jQuery UI 之外，还有其他 JavaScript 库，我们可以从中受益，以特定方式交互地和有趣地呈现我们的内容，例如在向上或向下滚动页面时对内容进行动画处理，以及从左侧或右侧滑入内容。我们将在接下来的部分中了解这两个动画工具，即 AOS 和 Swiper。让我们在下一节中进行。

您可以在我们的 GitHub 存储库的`/chapter-3/nuxt-universal/adding-jquery-ui/`中找到本节中使用的所有代码。

# 添加 AOS

AOS 是一个 JavaScript 动画库，可以在您向下（或向上）滚动页面时将 DOM 元素美观地动画显示出来。这是一个小型库，非常容易使用，可以在滚动页面时触发动画，而无需自己编写代码。要对元素进行动画处理，只需使用`data-aos`属性：

```js
<div data-aos="fade-in">...</div>
```

就像这样简单，当您滚动页面时，元素将逐渐淡入。您甚至可以设置动画完成的持续时间。因此，让我们找出如何在以下步骤中将此库添加到您的 Nuxt 项目中：

1.  在终端上通过 npm 安装 AOS：

```js
$ npm i aos
```

1.  将以下元素添加到`index.vue`中：

```js
// pages/index.vue
<template>
  <div class="grid-x">
    <div class="medium-6 medium-offset-3 cell" data-aos="fade-up">
      <img src="~/assets/images/sample-01.jpg">
    </div>
    <div class="medium-6 medium-offset-3 cell" data-aos="fade-up">
      <img src="~/assets/images/sample-02.jpg">
    </div>
    <div class="medium-6 medium-offset-3 cell" data-aos="fade-up">
      <img src="~/assets/images/sample-03.jpg">
    </div>
  </div>
</template>
```

在此模板中，我们使用 Foundation 为元素添加网格结构，并通过使用`data-aos`属性在每个元素上应用 AOS `fade-up`动画。

1.  在`<script>`块中导入 AOS JavaScript 和 CSS 资源，并在 Vue 组件挂载时初始化 AOS：

```js
// pages/index.vue
<script>
import 'aos/dist/aos.css'
import aos from 'aos'

export default {
  mounted () {
    aos.init()
  }
}
</script>
```

当您刷新屏幕时，您应该看到元素逐个向上淡入，按顺序出现，就像您向下滚动页面一样。这样可以让您如此轻松地美观地呈现您的内容，是不是很棒？

然而，我们刚刚应用 AOS 的方式并不适合如果您还有其他页面需要进行动画处理。您需要将前面的脚本复制到需要 AOS 动画的每个页面上。因此，如果您有多个页面需要使用 AOS 进行动画处理，那么您应该进行全局注册和初始化。让我们在以下步骤中找出如何做到这一点：

1.  在`/plugins/`目录中创建一个`aos.client.js`插件，导入 AOS 资源，并初始化 AOS 如下：

```js
// plugins/client-only/aos.client.js
import 'aos/dist/aos.css'
import aos from 'aos'

aos.init({
  duration: 2000,
})
```

在这个插件中，我们指示 AOS 全局地花费 2 秒来动画化我们的元素。您可以在 https://github.com/michalsnik/aos#1-initialize-aos 找到其余的设置选项。

1.  在 Nuxt 配置文件的`plugins`选项中注册前面的 AOS 插件如下：

```js
// nuxt.config.js
module.exports = {
  plugins: [
    '~/plugins/client-only/aos.client.js',
  ],
}
```

就是这样。现在您可以将 AOS 动画应用于多个页面，而无需复制脚本。

请注意，我们在 AOS 插件中直接导入 CSS 资源，而不是通过 Nuxt 配置文件中的`css`选项全局导入，与我们在以前的部分中为 Foundation 和 Motion UI 所做的相反。因此，如果您想为 Foundation 做同样的事情，可以直接将其 CSS 资源导入到插件文件中，如下所示：

```js
// plugins/client-only/foundation-site.client.js
import 'foundation-sites/dist/css/foundation.min.css'
import 'foundation-sites'
```

然后，您无需在 Nuxt 配置文件中使用全局的`css`选项。如果您希望保持配置文件“轻量”并将 UI 框架的 CSS 和 JavaScript 资源保留在其插件文件中，这种方式是首选。

您可以在我们的 GitHub 存储库的`/chapter-3/nuxt-universal/adding-aos/`中找到此示例 Nuxt 应用程序的源代码。

如果您想了解有关 AOS 和其余动画名称的更多信息，请访问 https://michalsnik.github.io/aos/。

现在让我们探索最后一个 JavaScript 助手，可以帮助加速您的前端开发 - **Swiper**。

# 添加 Swiper

Swiper 是一个 JavaScript 触摸滑块，可用于现代 Web 应用程序（桌面或移动）和移动本机或混合应用程序。它是 Framework7（https://framework7.io/）和 Ionic Framework（https://ionicframework.com/）的一部分，用于构建移动混合应用程序。我们可以像在以前的部分中使用 CDN 资源一样轻松地为 Web 应用程序设置 Swiper。但让我们看看您如何在以下步骤中以正确的方式在 Nuxt 中安装和使用它：

1.  在您的 Nuxt 项目中通过终端使用 npm 安装 Swiper：

```js
$ npm i swiper
```

1.  添加以下 HTML 元素以在`<template>`块中创建图像滑块：

```js
// pages/index.vue
<template>
  <div class="swiper-container">
    <div class="swiper-wrapper">
      <div class="swiper-slide"><img 
       src="~/assets/images/sample-01.jpg">
      </div>
      <div class="swiper-slide"><img 
       src="~/assets/images/sample-02.jpg">
      </div>
      <div class="swiper-slide"><img 
       src="~/assets/images/sample-03.jpg">
      </div>
    </div>
    <div class="swiper-button-next"></div>
    <div class="swiper-button-prev"></div>
  </div>
</template>
```

从这些元素中，我们希望创建一个图像滑块，其中包含三个图像，可以从左侧或右侧滑入视图，以及两个按钮 - 下一个按钮和上一个按钮。

1.  在`<script>`块中导入 Swiper 资源并在页面挂载时创建一个新的 Swiper 实例：

```js
// pages/index.vue
<script>
import 'swiper/swiper-bundle.css'
import Swiper from 'swiper/bundle'

export default {
  mounted () {
    var swiper = new Swiper('.swiper-container', {
      navigation: {
        nextEl: '.swiper-button-next',
        prevEl: '.swiper-button-prev',
      },
    })
  }
}
</script>
```

在这个脚本中，我们向 Swiper 提供了我们图像滑块的类名，以便可以初始化一个新实例。此外，我们通过 Swiper 的`pagination`选项将下一个和上一个按钮注册到新实例。

您可以在[`swiperjs.com/api/`](https://swiperjs.com/api/)找到用于初始化 Swiper 和与实例交互的 API 的其余设置选项。

1.  在`<style>`块中添加以下 CSS 样式来自定义图像滑块：

```js
// pages/index.vue
<style>
  .swiper-container {
    width: 100%;
    height: 100%;
  }
  .swiper-slide {
    display: flex;
    justify-content: center;
    align-items: center;
  }
</style>
```

在这个样式中，我们只想通过在 CSS 的`width`和`height`属性上使用 100%，并通过使用 CSS 的`flex`属性将图像置于滑块容器中央，使幻灯片占据整个屏幕。

1.  现在，您可以运行 Nuxt 并在浏览器中加载页面，您应该会看到一个交互式图像滑块很好地工作。

您可以在 Swiper 官方网站[`swiperjs.com/demos/`](https://swiperjs.com/demos/)找到一些很棒的示例幻灯片。

请注意，我们刚刚使用的 Swiper 方式仅适用于单个页面。如果您想在多个页面上创建滑块，则可以通过插件全局注册 Swiper。因此，让我们在以下步骤中了解如何做到这一点：

1.  在`/plugins/`目录中创建一个名为`swiper.client.js`的插件，导入 Swiper 资源，并创建一个名为`$swiper`的属性。将 Swiper 附加到此属性，并将其注入到 Vue 实例中，如下所示：

```js
// plugins/client-only/swiper.client.js
import 'swiper/swiper-bundle.css'
import Vue from 'vue'
import Swiper from 'swiper/bundle'

Vue.prototype.$swiper = Swiper
```

1.  在 Nuxt 配置文件的`plugins`选项中注册此 Swiper 插件：

```js
// nuxt.config.js
export default {
  plugins: [
    '~/plugins/client-only/swiper.client.js',
  ],
}
```

1.  现在，您可以通过使用`this`关键字调用`$swiper`属性，在应用的多个页面中创建 Swiper 的新实例，例如：

```js
// pages/global.vue
<script>
export default {
  mounted () {
    var swiper = new this.$swiper('.swiper-container', { ... })
  }
}
</script>
```

同样，我们将 CSS 资源组织在插件文件中，而不是通过 Nuxt 配置文件中的`css`选项全局注册它。但是，如果您想要全局覆盖这些 UI 框架和库中的一些样式，那么通过在`css`选项中全局注册它们的 CSS 资源，然后在`/assets/`目录中存储的 CSS 文件中添加自定义样式，更容易覆盖它们。

您可以从我们的 GitHub 存储库的`/chapter-3/nuxt-universal/adding-swiper/`中下载本章的源代码。如果您想了解更多关于 Swiper 的信息，请访问[`swiperjs.com/`](https://swiperjs.com/)。

干得好！您已经成功掌握了我们为您选择的一些流行的 UI 框架和库，以加速您的前端开发。我们希望它们将对您未来创建的 Nuxt 项目有所帮助。在接下来的章节中，我们将偶尔使用这些框架和库，特别是在最后一章 - [第十八章]《使用 CMS 和 GraphQL 创建 Nuxt 应用》中。现在，让我们总结一下您在本章学到的内容。

# 总结

在本章中，您已经将 Foundation 安装为 Nuxt 项目中的主要 UI 框架，并使用 Foundation 的网格系统、JavaScript 实用程序和插件来创建简单的网格布局、表单和导航。您已经使用 Foundation 的 Motion UI 来创建 Sass 动画和过渡，还使用了 Foundation Icon Fonts 3 来向 HTML 页面添加常见和有用的图标。您已经安装了 Less 作为样式预处理器，并在 Less 样式表中创建了一些变量。

您已经安装了 jQuery UI，并将其手风琴小部件添加到您的应用程序中，并使用其缓动效果创建了动画。您已经安装了 AOS，并在向下或向上滚动页面时使用它来使元素动画进入视口。最后，您已经安装了 Swiper 来创建一个简单的图像幻灯片。最后但同样重要的是，您已经学会了如何通过 Nuxt 配置文件全局安装这些框架和库，或者仅在特定页面上局部使用它们。

在接下来的章节中，我们将介绍 Nuxt 中的视图、路由和过渡。您将创建自定义页面、路由和 CSS 过渡，并学习如何使用`/assets/`目录来提供图像和字体等资源。此外，您还将学习如何自定义默认布局并在`/layouts/`目录中添加新的布局。我们将提供一个简单的网站示例，该示例使用了所有这些 Nuxt 功能，以便您可以从本书中学到的内容中获得具体用途的感觉。因此，让我们在下一章中进一步探索 Nuxt！
