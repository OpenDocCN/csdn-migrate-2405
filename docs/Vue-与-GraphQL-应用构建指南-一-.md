# Vue 与 GraphQL 应用构建指南（一）

> 原文：[`zh.annas-archive.org/md5/60CC414A1AE322EC97E6A0F8A5BBE3AD`](https://zh.annas-archive.org/md5/60CC414A1AE322EC97E6A0F8A5BBE3AD)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

自 2012 年 Facebook 发布以来，GraphQL 已经席卷了互联网。像 Airbnb 和 Audi 这样的大公司已经开始采用它，而中小型公司现在也意识到了这种基于查询的 API 的潜力。

GraphQL 起初可能看起来很奇怪，但当你开始阅读和体验更多时，你就不会再想使用 REST API 了。

通过本书中的示例，你将学习如何从头开始构建一个完整的实时聊天应用程序。首先创建一个 AWS Amplify 环境，然后深入开发你的第一个 GraphQL 模式。然后学习如何添加 AppSync GraphQL 客户端并创建你的第一个 GraphQL 变异。本书还将帮助你发现 GraphQL 的简单性和数据获取能力，使前端开发人员能够轻松与服务器通信。最后，你将了解如何使用 Quasar Framework 创建应用程序组件和布局。最后，你将了解如何在应用程序中创建 Vuex 模块来管理应用程序状态，使用 GraphQL 客户端获取数据，并将应用程序部署到 Web 上。

# 这本书适合谁

这本书适合中级 Vue.js 开发人员，他们想迈出全栈开发的第一步。如果你想了解更多关于使用自定义业务规则开发 Vuex 以及创建入门级企业架构应用程序，那么这本书适合你。在开始阅读本书之前，需要具备 Vue.js 和 JavaScript 的基础知识。

# 这本书涵盖了什么

第一章，*数据绑定、表单验证、事件和计算属性*，讨论了基本的 Vue 开发和组件概念，包括`v-model`、事件监听器、计算属性和`for`循环。读者将介绍如何使用 Vuelidate 插件进行表单验证以及如何在 Vue 组件上使用它，以及如何使用`vue-devtools`调试 Vue 组件。

第二章，*组件、混入和功能组件*，引导读者通过不同的方法构建组件，包括用于内容的自定义插槽、验证的 props、功能组件以及为了代码重用性而创建的混入。然后介绍了一系列不同的方法来访问子组件的数据，创建依赖注入组件和动态注入组件，以及如何延迟加载组件。

第三章，“设置我们的聊天应用程序-AWS Amplify 环境和 GraphQL”，介绍了 AWS Amplify CLI，介绍了如何创建 Amplify 环境。创建他们的身份验证网关与 AWS Cognito，一个 S3 文件托管桶，最后创建 GraphQL API。在这个过程中，读者将创建用于前端和后端通信的驱动程序。

第四章，“创建自定义应用程序组件和布局”，从现在开始，读者将开始开发应用程序。在这一章中，读者将创建用于聊天应用程序页面的组件。读者将创建组件，如`PasswordInput`，`AvatarInput`，`EmailInput`等。

第五章，“创建用户 Vuex、页面和路由”，引导读者构建应用程序的第一个 Vuex 模块，用于管理用户业务规则和存储用户数据。然后读者将创建用户相关的注册、编辑和验证页面。最后，读者将把这些页面添加到 vue-router 模式中。

第六章，“创建聊天和消息 Vuex、页面和路由”，读者将继续创建应用程序的 Vuex 模块。现在是创建聊天模块的时候了。这个模块将包含用户之间通信的业务规则和存储聊天数据。最后，用户将创建与聊天列表和聊天页面相关的页面，然后将其添加到 vue-router 模式中。

第七章，“将您的应用程序转变为 PWA 并部署到 Web”，在这最后一章中，读者将通过将应用程序转变为 PWA 应用程序，为 iOS 设备添加更新通知和安装横幅来完成应用程序。最后，用户将把应用程序部署到 Web 上。

# 为了充分利用本书

本书从 第二章 *组件、混合和功能组件* 开始使用 Vue.js 2.7，因为这是写作时 Quasar Framework 的最新支持版本。本书将在 第三章 *设置我们的聊天应用 - AWS Amplify 环境和 GraphQL* 中使用 Vue.js 3 的代码。所有代码将在 GitHub 存储库的最终版本发布时进行更新：[`github.com/PacktPublishing/Building-Vue.js-Applications-with-GraphQL`](https://github.com/PacktPublishing/Building-Vue.js-Applications-with-GraphQL)

您需要安装 Node.js 12+，将 Vue CLI 更新到最新版本，并且需要一个良好的代码编辑器。其他要求将在每个示例中介绍。所有软件要求都适用于 Windows、macOS 和 Linux。

以下是总结所有要求的表格：

| **章节编号** | **书中涉及的软件/硬件** | **下载链接** | **操作系统要求** |
| --- | --- | --- | --- |
| 1 到 7 | Vue CLI 4.X | [`cli.vuejs.org/`](https://cli.vuejs.org/) | Windows / Linux / macOS |
| 3 到 7 | Quasar-CLI 1.X | [`quasar.dev/`](https://quasar.dev/) | Windows / Linux / macOS |
| 3 到 7 | Visual Studio Code 1.4.X 和 IntelliJ WebStorm 2020.2 | [`code.visualstudio.com/`](https://code.visualstudio.com/) | Windows / Linux / macOS |
| 3 到 7 | AWS Amplify CLI 3.3.X | [`aws.amazon.com/appsync/resources/`](https://aws.amazon.com/appsync/resources/) | Windows / Linux / macOS |
| 1 到 7 | Node.js 12+- | [`nodejs.org/en/download/`](https://nodejs.org/en/download/) | Windows / Linux / macOS |

**如果您使用的是本书的数字版本，我们建议您自己输入代码或通过 GitHub 存储库访问代码（链接在下一部分中提供）。这样做将帮助您避免与复制和粘贴代码相关的任何潜在错误。**

## 下载示例代码文件

您可以从您在 [www.packt.com](http://www.packt.com) 的帐户中下载本书的示例代码文件。如果您在其他地方购买了这本书，您可以访问 [www.packtpub.com/support](https://www.packtpub.com/support) 并注册，以便文件直接通过电子邮件发送给您。

您可以按照以下步骤下载代码文件：

1.  在 [www.packt.com](http://www.packt.com) 上登录或注册。

1.  选择 Support 选项卡。

1.  点击 Code Downloads。

1.  在 Search 框中输入书名，并按照屏幕上的说明操作。

一旦文件下载完成，请确保使用最新版本的解压软件解压文件夹：

+   Windows 的 WinRAR/7-Zip

+   Mac 的 Zipeg/iZip/UnRarX

+   Linux 的 7-Zip/PeaZip

本书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Building-Vue.js-Applications-with-GraphQL`](https://github.com/PacktPublishing/Building-Vue.js-Applications-with-GraphQL)。如果代码有更新，将在现有的 GitHub 存储库上更新。

我们还有其他代码包，来自我们丰富的图书和视频目录，可以在**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**上找到。去看看吧！

## 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词，数据库表名，文件夹名，文件名，文件扩展名，路径名，虚拟 URL，用户输入和 Twitter 账号。这是一个例子：“为了做到这一点，以管理员身份打开 PowerShell 并执行`> npm install -g windows-build-tools`命令。”

一个代码块设置如下：

```js
<template>
 <header>
 <div id="blue-portal" />
 </header>
</header>
```

任何命令行输入或输出都以以下方式书写：

```js
> npm run serve
```

**粗体**：表示一个新术语，一个重要词，或者你在屏幕上看到的词。例如，菜单或对话框中的单词会以这种方式出现在文本中。这是一个例子：“点击**电子邮件**按钮，将被重定向到**电子邮件注册**表格”

警告或重要说明会以这种方式出现。提示和技巧会以这种方式出现。

# 部分

在本书中，你会经常看到几个标题（*准备工作*，*如何做*，*它是如何工作的*，*还有更多*，和*另请参阅*）。

为了清晰地说明如何完成一个食谱，使用以下部分：

## 准备工作

这一部分告诉你在食谱中可以期待什么，并描述如何设置任何软件或食谱所需的任何初步设置。

## 如何做…

这一部分包含了遵循食谱所需的步骤。

## 它是如何工作的…

这一部分通常包括对前一部分发生的事情的详细解释。

## 还有更多…

这一部分包括了有关食谱的额外信息，以使你对食谱更加了解。

## 另请参阅

这一部分为食谱提供了其他有用信息的链接。


# 第一章：数据绑定、事件和计算属性

**数据**是当今世界上最有价值的资产，知道如何管理它是必须的。在 Vue 中，我们有权利选择如何收集这些数据，按照我们的意愿进行操作，并将其传递到服务器。

在本章中，我们将更多地了解数据处理和数据处理过程，表单验证，数据过滤，如何向用户显示这些数据，以及如何以与应用程序内部不同的方式呈现它。

我们将学习如何使用各种`vue-devtools`，以便我们可以深入了解 Vue 组件并查看我们的数据和应用程序发生了什么。

在本章中，我们将涵盖以下配方：

+   使用 Vue CLI 创建您的第一个项目

+   创建 hello world 组件

+   创建具有双向数据绑定的输入表单

+   在元素上添加事件监听器

+   从输入中删除`v-model`指令

+   创建动态待办事项列表

+   创建计算属性并了解它们的工作原理

+   使用自定义过滤器显示更清洁的数据和文本

+   为列表创建过滤器和排序器

+   创建条件过滤器以对列表数据进行排序

+   添加自定义样式和过渡

+   使用`vue-devtools`调试您的应用程序

让我们开始吧！

# 技术要求

在本章中，我们将使用**Node.js**和**Vue CLI**。

注意，Windows 用户 - 您需要安装一个名为`windows-build-tools`的`npm`包，以便能够安装以下所需的包。要做到这一点，以管理员身份打开 PowerShell 并执行

`> npm install -g windows-build-tools`命令。

要安装**Vue CLI**，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> npm install -g @vue/cli @vue/cli-service-global
```

# 使用 Vue CLI 创建您的第一个项目

当 Vue 团队意识到开发人员在创建和管理他们的应用程序时遇到问题时，他们看到了一个机会，可以创建一个工具来帮助世界各地的开发人员。有了这个，Vue CLI 项目诞生了。

Vue CLI 工具是一个在 terminal 命令行中使用的 CLI 工具，如 Windows PowerShell、Linux Bash 或 macOS Terminal。它被创建为 Vue 开发的起点，开发人员可以启动一个项目并顺利地管理和构建它。Vue CLI 团队的重点是为开发人员提供更多时间思考代码，花费更少的时间在工具上，将他们的代码投入生产，添加新的插件或简单的 `hot-module-reload`。

Vue CLI 工具已经进行了调整，无需在将其投入生产之前将工具代码弹出 CLI。

当版本 3 发布时，Vue UI 项目被添加到 CLI 中作为主要功能，将 CLI 命令转换为更完整的可视解决方案，并增加了许多新的功能和改进。

## 准备工作

这个配方的先决条件是 Node.js 12+。

这个配方所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

## 如何做...

要创建一个 Vue CLI 项目，请按照以下步骤进行：

1.  我们需要在 Terminal (macOS 或 Linux) 或 Command Prompt/PowerShell (Windows) 中执行以下命令：

```js
> vue create my-first-project
```

1.  CLI 会询问一些问题，这些问题将帮助你创建项目。你可以使用箭头键进行导航，*Enter* 键继续，*Spacebar* 选择选项：

```js
?  Please pick a preset: (Use arrow keys)  default (babel, eslint) ❯ **Manually select features** ‌
```

1.  有两种方法可以启动一个新项目。默认方法是一个基本的 `babel` 和 `eslint` 项目，没有任何插件或配置，但也有 `手动` 模式，你可以选择更多模式、插件、linters 和选项。我们将选择 `手动` 模式。

1.  在这一点上，我们将被询问关于我们希望为我们的项目选择的功能。这些功能是一些 Vue 插件，如 Vuex 或 Router (Vue-Router)、测试器、linters 等。对于这个项目，我们将选择 `CSS 预处理器` 并按 *Enter* 继续：

```js
? Check the features needed for your project: (Press <space> to 
  select, <a> to toggle all, <i> to invert selection)
 ❯ Choose Vue version
 ❯ Babel
 TypeScript
 Progressive Web App (PWA) Support
 Router
 Vuex
 CSS Pre-processors
 ❯ Linter / Formatter
 Unit Testing
 E2E Testing
```

1.  CLI 会要求你选择一个 Vue 版本来启动你的应用程序。我们将在这里选择 `3.x (Preview)`。按 *Enter* 继续：

```js
? Choose a version of Vue.js that you want to start the project with 
 (Use arrow keys)
 2.x 
❯ 3.x (Preview)
```

1.  可以选择与 Vue 一起使用的主要 **层叠样式表** (**CSS**) 预处理器，即 `Sass`、`Less` 和 `Stylus`。由你选择哪种最适合你的设计并且最适合你：

```js
?  Pick a CSS pre-processor (PostCSS, Autoprefixer and CSS Modules
  are supported by default): (Use arrow keys) Sass/SCSS (with dart-sass)  Sass/SCSS (with node-sass)  **Less** ❯ Stylus 
```

1.  现在是时候格式化您的代码了。您可以在`AirBnB`、`Standard`和`Prettier`之间进行选择，并使用基本配置。在`ESLint`中导入的这些规则总是可以自定义，没有任何问题，并且有一个完美的规则适合您的需求。找出对您来说最好的方法，然后执行以下操作：

```js
?  Pick a linter / formatter config: (Use arrow keys) ESLint with error prevention only ❯ **ESLint + Airbnb config** ESLint + Standard config 
  ESLint + Prettier
```

1.  一旦代码检查规则被设置，我们需要定义它们何时应用于我们的代码。它们可以在保存时应用，或者在提交时进行修复：

```js
? Pick additional lint features: 
 Lint on save
❯ Lint and fix on commit 
```

1.  一旦所有这些插件、代码检查器和处理器都被定义，我们需要选择设置和配置存储的位置。最好的存储位置是在一个专用文件中，但也可以将它们存储在`package.json`文件中：

```js
?  Where do you prefer placing config for Babel, ESLint, etc.?  (Use  
  arrow keys) ❯ **In dedicated config files** In package.json
```

1.  现在，您可以选择是否将此选择作为将来项目的预设，这样您就不需要再次重新选择所有内容。

```js
?  Save this as a preset for future projects?  (y/N) n
```

1.  CLI 将自动创建以*步骤 1*中设置的名称命名的文件夹，安装所有内容并配置项目。

有了这些，现在您可以导航并运行项目了。Vue CLI 项目的基本命令如下：

+   `npm run serve`：在本地运行开发服务器

+   `npm run build`：用于构建和缩小应用程序以进行部署

+   `npm run lint`：对代码执行 lint

您可以通过终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）执行这些命令。

## 还有更多...

CLI 内部有一个名为 Vue UI 的工具，可帮助您管理 Vue 项目。这个工具将负责项目的依赖关系、插件和配置。

Vue UI 工具中的每个`npm`脚本都被称为一个任务，在这些任务中，您可以收集实时统计数据，如资产、模块和依赖项的大小；错误或警告的数量；以及更深入的网络数据，以微调您的应用程序。

要进入 Vue UI 界面，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> vue ui
```

## 另请参阅

+   您可以在[`cli.vuejs.org/guide/`](https://cli.vuejs.org/guide/)找到有关 Vue CLI 项目的更多信息。

+   你可以在[`cli.vuejs.org/dev-guide/plugin-dev.html`](https://cli.vuejs.org/dev-guide/plugin-dev.html)找到有关 Vue CLI 插件开发的更多信息。

# 创建 hello world 组件

Vue 应用程序是由各种组件组合在一起，并由 Vue 框架编排的。知道如何制作您的组件是很重要的。每个组件就像墙上的一块砖，需要以一种方式制作，当放置时，不需要其他砖块以不同的方式重新塑造。在这个教程中，我们将学习如何制作一个基础组件，同时遵循一些重要的原则，重点放在组织和清晰的代码上。

## 准备工作

本教程的先决条件是 Node.js 12+。

本教程所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

要开始我们的组件，我们可以使用 Vue CLI 创建我们的 Vue 项目，就像我们在*使用 Vue CLI 创建你的第一个项目*中学到的那样，或者开始一个新的项目。

## 操作步骤...

要开始一个新的组件，打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> vue create my-component
```

**命令行界面**（**CLI**）将询问一些问题，这些问题将帮助您创建项目。您可以使用箭头键导航，使用*Enter*键继续，使用*Spacebar*选择选项。选择**`default`**选项：

```js
?  Please pick a preset: **(Use arrow keys)** ❯ default (babel, eslint) 
  Manually select features  ‌
```

通过以下步骤创建我们的第一个`hello world`组件：

1.  让我们在`src/components`文件夹中创建一个名为`CurrentTime.vue`的新文件。

1.  在这个文件中，我们将从组件的`<template>`部分开始。它将是一个阴影框卡片，显示当前日期，格式化：

```js
<template>
  <div class='cardBox'>
    <div class='container'>
      <h2>Today is:</h2>
      <h3>{{ getCurrentDate }}</h3>
    </div>
  </div>
</template>
```

1.  现在，我们需要创建`<script>`部分。我们将从`name`属性开始。这将在使用`vue-devtools`调试我们的应用程序时使用，以识别我们的组件，并帮助**集成开发环境**（**IDE**）。对于`getCurrentDate`计算属性，我们将创建一个`computed`属性，它将返回当前日期，由`Intl`浏览器函数格式化：

```js
<script>
export default {
  name: 'CurrentTime',
  computed: {
    getCurrentDate() {
      const browserLocale =
        navigator.languages && navigator.languages.length
          ? navigator.languages[0]
          : navigator.language;
      const intlDateTime = new Intl.DateTimeFormat(
        browserLocale, 
        {
          year: 'numeric',
          month: 'numeric',
          day: 'numeric',
          hour: 'numeric',
          minute: 'numeric'
        });

      return intlDateTime.format(new Date());
    }
  }
};
</script>
```

1.  为了为我们的盒子设置样式，我们需要在`src`文件夹中创建一个`style.css`文件，然后将`cardBox`样式添加到其中：

```js
.cardBox {
  box-shadow: 0 5px 10px 0 rgba(0, 0, 0, 0.2);
  transition: 0.3s linear;
  max-width: 33%;
  border-radius: 3px;
  margin: 20px;
}

.cardBox:hover {
  box-shadow: 0 10px 20px 0 rgba(0, 0, 0, 0.2);
}

.cardBox>.container {
  padding: 4px 18px;
}

[class*='col-'] {
  display: inline-block;
}

@media only screen and (max-width: 600px) {
  [class*='col-'] {
    width: 100%;
  }

  .cardBox {
    margin: 20px 0;
  }
}

@media only screen and (min-width: 600px) {
  .col-1 {width: 8.33%;}
  .col-2 {width: 16.66%;}
  .col-3 {width: 25%;}
  .col-4 {width: 33.33%;}
  .col-5 {width: 41.66%;}
  .col-6 {width: 50%;}
  .col-7 {width: 58.33%;}
  .col-8 {width: 66.66%;}
  .col-9 {width: 75%;}
  .col-10 {width: 83.33%;}
  .col-11 {width: 91.66%;}
  .col-12 {width: 100%;}
}

@media only screen and (min-width: 768px) {
  .col-1 {width: 8.33%;}
  .col-2 {width: 16.66%;}
  .col-3 {width: 25%;}
  .col-4 {width: 33.33%;}
  .col-5 {width: 41.66%;}
  .col-6 {width: 50%;}
  .col-7 {width: 58.33%;}
  .col-8 {width: 66.66%;}
  .col-9 {width: 75%;}
  .col-10 {width: 83.33%;}
  .col-11 {width: 91.66%;}
  .col-12 {width: 100%;}
}

@media only screen and (min-width: 992px) {
  .col-1 {width: 8.33%;}
  .col-2 {width: 16.66%;}
  .col-3 {width: 25%;}
  .col-4 {width: 33.33%;}
  .col-5 {width: 41.66%;}
  .col-6 {width: 50%;}
  .col-7 {width: 58.33%;}
  .col-8 {width: 66.66%;}
  .col-9 {width: 75%;}
  .col-10 {width: 83.33%;}
  .col-11 {width: 91.66%;}
  .col-12 {width: 100%;}
}

@media only screen and (min-width: 1200px) {
  .col-1 {width: 8.33%;}
  .col-2 {width: 16.66%;}
  .col-3 {width: 25%;}
  .col-4 {width: 33.33%;}
  .col-5 {width: 41.66%;}
  .col-6 {width: 50%;}
  .col-7 {width: 58.33%;}
  .col-8 {width: 66.66%;}
  .col-9 {width: 75%;}
  .col-10 {width: 83.33%;}
  .col-11 {width: 91.66%;}
  .col-12 {width: 100%;}
}
```

1.  在`App.vue`文件中，我们需要导入我们的组件，这样我们才能看到它：

```js
<template>
  <div id='app'>
    <current-time />
  </div>
</template>

<script>
import CurrentTime from './components/CurrentTime.vue';

export default {
  name: 'app',
  components: {
    CurrentTime
  }
}
</script>
```

1.  在`main.js`文件中，我们需要导入`style.css`文件，以便它包含在 Vue 应用程序中：

```js
import { createApp } from 'vue'; import './style.css'; import App from './App.vue';   createApp(App).mount('#app');
```

1.  要运行服务器并查看您的组件，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> npm run serve
```

记住始终执行命令`npm run lint --fix`，以自动修复任何代码 lint 错误。

这是渲染和运行的组件：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/bd-vue-app-gql/img/e36e209b-3257-4c7f-9aaa-203af1535c44.png)

## 它是如何工作的...

Vue 组件几乎与 Node.js 包一样工作。要在代码中使用它，您需要导入组件，然后在要使用的组件的`components`属性中声明它。

就像一堵砖墙，Vue 应用程序由调用和使用其他组件的组件组成。

对于我们的组件，我们使用了`Intl.DateTimeFormat`函数，这是一个本机函数，可用于将日期格式化和解析为声明的位置。为了获得本地格式，我们使用了 navigator 全局变量。

## 另请参阅

+   您可以在[`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/DateTimeFormat`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/DateTimeFormat)找到有关`Intl.DateTimeFormat`的更多信息。

+   您可以在[`v3.vuejs.org/guide/single-file-component.html`](https://v3.vuejs.org/guide/single-file-component.html)找到有关 Vue 组件的更多信息。

# 使用双向数据绑定创建输入表单

在网上收集数据，我们使用 HTML 表单输入。在 Vue 中，可以使用双向数据绑定方法，其中 DOM 上输入的值传递给 JavaScript，反之亦然。

这使得 Web 表单更加动态，使您有可能在保存或将数据发送回服务器之前管理、格式化和验证数据。

## 准备工作

此配方的先决条件是 Node.js 12+。

此配方所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

要启动我们的组件，我们可以使用 Vue CLI 创建我们的 Vue 项目，就像我们在*使用 Vue CLI 创建您的第一个项目*配方中学到的那样，或者使用*创建 hello world 组件*配方中的项目。

## 如何做...

按照以下步骤创建具有双向数据绑定的输入表单：

1.  让我们在`src/components`文件夹中创建一个名为`TaskInput.vue`的新文件。

1.  在这个文件中，我们将创建一个组件，它将有一个文本输入和一些显示文本。这个文本将基于文本输入中键入的内容。在组件的`<template>`部分，我们需要创建一个 HTML 输入和一个`mustache`变量，用于接收和呈现数据：

```js
<template>
  <div class='cardBox'>
    <div class='container tasker'>
      <strong>My task is: {{ task }}</strong>
      <input 
        type='text'
        v-model='task'
        class='taskInput' />
    </div>
  </div>
</template>
```

1.  现在，在组件的`<script>`部分，我们将对其命名并将任务添加到`data`属性中。由于数据始终需要返回一个`Object`，我们将使用箭头函数直接返回一个`Object`：

```js
<script>
export default {
  name: 'TaskInput',
  data: () => ({
    task: '',
  }),
};
</script>
```

1.  我们需要为这个组件添加一些样式。在组件的`<style>`部分，我们需要添加`scoped`属性，以便样式仅保持在组件中，不会与其他**层叠样式表**（**CSS**）规则混合：

```js
<style scoped>
  .tasker{
    margin: 20px;
  }
  .tasker .taskInput {
    font-size: 14px;
    margin: 0 10px;
    border: 0;
    border-bottom: 1px solid rgba(0, 0, 0, 0.75);
  }
  .tasker button {
    border: 1px solid rgba(0, 0, 0, 0.75);
    border-radius: 3px;
    box-shadow: 0 1px 2px 0 rgba(0, 0, 0, 0.2);
  }
</style>
```

1.  现在，我们需要将这个组件导入到我们的`App.vue`文件中：

```js
<template>
  <div id='app'>
  <current-time class='col-4' />
  <task-input class='col-6' />
  </div> </template>   <script> import CurrentTime from './components/CurrentTime.vue'; import TaskInput from './components/TaskInput.vue';   export default {
  name: 'TodoApp',
  components: {
  CurrentTime,
  TaskInput,
  }, }; </script> 
```

1.  要运行服务器并查看您的组件，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> npm run serve
```

请记住始终执行命令`npm run lint --fix`，以自动修复任何代码 lint 错误。

这是渲染和运行的组件：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/bd-vue-app-gql/img/87548754-ee45-4945-b465-041190016424.png)

## 它是如何工作的...

当您创建一个 HTML`input`元素并为其添加`v-model`时，您正在传递一个内置到 Vue 中的指令，该指令检查输入类型并为输入提供糖语法。这处理更新变量和 DOM 的值。

这个模型被称为**双向数据绑定**。如果变量被代码更改，DOM 将重新渲染，如果它被 DOM 通过用户输入更改，比如`input-form`，那么 JavaScript 代码可以执行一个函数。

## 另请参阅

您可以在[`v3.vuejs.org/guide/forms.html`](https://v3.vuejs.org/guide/forms.html)找到有关表单输入绑定的更多信息。

# 向元素添加事件侦听器

在 Vue 中，父子通信的最常见方法是通过 props 和 events。在 JavaScript 中，通常会向 DOM 树的元素添加事件侦听器，以在特定事件上执行函数。在 Vue 中，可以添加监听器并根据需要命名，而不是坚持 JavaScript 引擎上存在的名称。

在这个配方中，我们将学习如何创建自定义事件以及如何发出它们。

## 准备工作

这个配方的先决条件是 Node.js 12+。

这个配方所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

要启动我们的组件，我们可以使用 Vue CLI 创建我们的 Vue 项目，就像我们在*使用 Vue CLI 创建您的第一个项目*配方中学到的那样，或者使用*使用双向数据绑定创建输入表单*配方中的项目。

## 如何做...

按照以下步骤为 Vue 中的元素添加事件监听器：

1.  创建一个新组件或打开`TaskInput.vue`文件。

1.  在`<template>`部分，我们将添加一个按钮元素，并使用`v-on`指令为按钮点击事件添加一个事件监听器。我们将从组件中删除`{{ task }}`变量，因为从现在开始，它将被发出并且不再显示在组件上：

```js
<template>
  <div class='cardBox'>
    <div class='container tasker'>
      <strong>My task is:</strong>
      <input 
        type='text' 
        v-model='task' 
        class='taskInput' />
      <button 
        v-on:click='addTask'>
            Add Task
      </button>
    </div>
  </div>
</template>
```

1.  在组件的`<script>`部分，我们需要添加一个处理点击事件的方法。这个方法将被命名为`addTask`。它将发出一个名为`add-task`的事件，并将任务发送到数据中。之后，组件上的任务将被重置：

```js
<script>
export default {
 name: 'TaskInput',
 data: () => ({
 task: '',
 }),
  methods: {
    addTask(){
      this.$emit('add-task', this.task);
      this.task = '';
    },
  }
};
</script>
```

1.  在`App.vue`文件中，我们需要为组件添加一个事件监听器绑定。这个监听器将附加到`add-task`事件上。我们将使用`v-on`指令的缩写版本`@`。当它被触发时，事件将调用`addNewTask`方法，该方法将发送一个警报，说明已添加了一个新任务：

```js
<template>
  <div id='app'>
    <current-time class='col-4' />
    <task-input 
      class='col-6'
      @add-task='addNewTask'
    />
  </div>
</template>
```

1.  现在，让我们创建`addNewTask`方法。这将接收任务作为参数，并向用户显示一个警报，说明已添加了任务：

```js
<script> import CurrentTime from './components/CurrentTime.vue'; import TaskInput from './components/TaskInput.vue';   export default {
  name: 'TodoApp',
  components: {
  CurrentTime,
  TaskInput,
  },
  methods: {
  addNewTask(task) {
    alert(`New task added: ${task}`);
  },
  }, }; </script> 
```

1.  要运行服务器并查看您的组件，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> npm run serve
```

请记住始终执行命令`npm run lint --fix`，以自动修复任何代码 lint 错误。

以下是渲染和运行的组件：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/bd-vue-app-gql/img/10282a27-e2db-4efe-8182-9e896614c2e7.png)

## 它是如何工作的...

Vue 使用`v-on`事件处理指令来读取 HTML 事件。当我们将`v-on:click`指令附加到按钮时，我们为按钮添加了一个监听器，以便在用户单击按钮时执行一个函数。

该函数在组件方法中声明。当调用此函数时，将发出一个事件，表示任何使用此组件作为子组件的组件都可以使用`v-on`指令监听它。

## 另请参阅

您可以在[`v3.vuejs.org/guide/events.html`](https://v3.vuejs.org/guide/events.html)找到有关事件处理的更多信息。

# 从输入中删除 v-model 指令

如果我告诉你，在`v-model`的魔术背后，有很多代码使我们的魔术糖语法发生？如果我告诉你，兔子洞可以深入到足以控制输入的事件和值的一切？

在这个配方中，我们将学习如何提取`v-model`指令的糖语法，并将其转换为其背后的基本语法。

## 准备工作

这个配方的先决条件是 Node.js 12+。

本配方所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

要启动我们的组件，我们可以使用 Vue CLI 创建我们的 Vue 项目，就像我们在*使用 Vue CLI 创建您的第一个项目*配方中学到的那样，或者使用*向元素添加事件监听器*配方中的项目。

## 如何操作...

通过执行以下步骤，我们将从输入中删除`v-model`指令的糖语法：

1.  打开`TaskInput.vue`文件。

1.  在组件的`<template>`块中，找到`v-model`指令。我们需要删除`v-model`指令。然后，我们需要向输入添加一个新的绑定，称为`v-bind:value`或缩写版本`:value`，以及一个事件监听器到 HTML`input`元素。我们需要在`input`事件上添加一个事件监听器，使用`v-on:input`指令或缩写版本`@input`。输入绑定将接收任务值作为参数，事件监听器将接收一个值赋值，其中它将使任务变量等于事件值的值：

```js
<template>
  <div class='cardBox'>
    <div class='container tasker'>
      <strong>My task is:</strong>
      <input 
        type='text' 
        :value='task' 
        @input='task = $event.target.value' 
        class='taskInput' 
      />
      <button v-on:click='addTask'>
        Add Task
      </button>
    </div>
  </div>
</template>
```

1.  要运行服务器并查看您的组件，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> npm run serve 
```

记得始终执行命令`npm run lint --fix`，以自动修复任何代码 lint 错误。

## 它是如何工作的...

作为一种语法糖，`v-model`指令可以自动声明绑定和事件监听器到元素中。然而，副作用是你无法完全控制可以实现什么。

正如我们所见，绑定的值可以是变量、方法、计算属性或 Vuex getter 等。在事件监听器方面，它可以是一个函数或直接声明一个变量赋值。当事件被触发并传递给 Vue 时，`$event`变量用于传递事件。在这种情况下，与普通 JavaScript 一样，要捕获输入的值，我们需要使用`event.target.value`值。

## 另请参阅

您可以在[`v3.vuejs.org/guide/events.html`](https://v3.vuejs.org/guide/events.html)找到有关事件处理的更多信息。

# 创建一个动态的待办事项列表

每个程序员在学习一门新语言时创建的第一个项目之一就是待办事项列表。这样做可以让我们更多地了解在处理状态和数据时遵循的语言流程。

我们将使用 Vue 制作我们的待办事项列表。我们将使用之前教程中学到的知识和创建的内容。

## 准备工作

这个教程的先决条件是 Node.js 12+。

这个教程所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

要启动我们的组件，我们可以使用 Vue CLI 创建 Vue 项目，就像我们在*使用 Vue CLI 创建第一个项目*这个教程中学到的那样，或者使用*从输入中删除 v-model 指令*这个教程中的项目。

## 如何做...

制作待办事项应用程序涉及一些基本原则-它必须包含一个任务列表，任务可以标记为已完成和未完成，并且列表可以进行过滤和排序。现在，我们将学习如何将任务添加到任务列表中。

按照以下步骤使用 Vue 和从之前教程中获得的信息创建一个动态的待办事项列表：

1.  在`App.vue`文件中，我们将创建我们的任务数组。每当`TaskInput.vue`组件发出消息时，这个任务将被填充。我们将向这个数组添加一个包含任务以及任务创建的当前日期的对象。目前，任务完成的日期将被留空。为了做到这一点，在组件的`<script>`部分，我们需要创建一个接收任务并将任务与当前日期添加到`taskList`数组中的方法：

```js
<script>
import CurrentTime from './components/CurrentTime.vue';
import TaskInput from './components/TaskInput.vue';

export default {
  name: 'TodoApp',
  components: {
    CurrentTime,
    TaskInput,
  },
  data: () => ({
    taskList: [],
  }),
  methods:{
    addNewTask(task){
      this.taskList.push({
        task,
        createdAt: Date.now(),
        finishedAt: undefined,
      })
    },
  },
}
</script>
```

1.  现在，我们需要在`<template>`部分渲染这个列表。我们将使用 Vue 的`v-for`指令来遍历任务列表。当我们将这个指令与数组一起使用时，它会给我们访问两个属性-项目本身和项目的索引。我们将使用项目本身进行渲染，使用索引来创建元素的键以进行渲染过程。我们需要添加一个复选框，当选中时，调用一个改变任务状态的函数，并显示任务完成的时间：

```js
<template>
  <div id='app'>
    <current-time class='col-4' />
    <task-input class='col-6' @add-task='addNewTask' />
    <div class='col-12'>
      <div class='cardBox'>
        <div class='container'>
          <h2>My Tasks</h2>
          <ul class='taskList'>
            <li 
              v-for='(taskItem, index) in taskList'
              :key='`${index}_${Math.random()}`'
            >
              <input type='checkbox' 
                :checked='!!taskItem.finishedAt' 
                @input='changeStatus(index)'
              /> 
              {{ taskItem.task }} 
              <span v-if='taskItem.finishedAt'>
                {{ taskItem.finishedAt }}
              </span>
            </li>
          </ul>
        </div>
      </div>
    </div>
  </div>
</template>
```

始终重要的是要记住迭代器中的键必须是唯一的。这是因为`render`函数需要知道哪些元素已更改。在此示例中，我们添加了`Math.random()`函数到索引中以生成唯一键，因为当减少元素数量时，数组的第一个元素的索引始终是相同的数字。

1.  我们需要在`App.vue`文件的`methods`属性上创建`changeStatus`函数。此函数将接收任务的索引作为参数，然后转到任务数组并更改`finishedAt`属性，这是我们标记任务完成的标记。

```js
changeStatus(taskIndex){
  const task = this.taskList[taskIndex];
    if(task.finishedAt){
      task.finishedAt = undefined;
    } else {
      task.finishedAt = Date.now();
    }
}
```

1.  现在，我们需要将任务文本添加到屏幕左侧。在组件的`<style>`部分，我们将使其具有作用域并添加自定义类：

```js
<style scoped>
  .taskList li{
    text-align: left;
  }
</style>
```

1.  运行服务器并查看您的组件，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> npm run serve
```

请记住始终执行命令`npm run lint --fix`，以自动修复任何代码 lint 错误。

这是渲染和运行的组件：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/bd-vue-app-gql/img/8ea10da5-7222-4bc8-9f5b-55f65fdabe55.png)

## 它是如何工作的...

当我们从组件接收到发射的消息时，我们使用更多数据对消息进行了处理，并将其推送到本地数组变量中。

在模板中，我们迭代此数组，将其转换为任务列表。这显示了我们需要完成的任务、标记任务完成的复选框以及任务完成的时间。

当用户单击复选框时，它会执行一个函数，该函数将当前任务标记为已完成。如果任务已经完成，该函数将将`finishedAt`属性设置为`undefined`。

## 另请参阅

+   您可以在[`v3.vuejs.org/guide/list.html#mapping-an-array-to-elements-with-v-for`](https://v3.vuejs.org/guide/list.html#mapping-an-array-to-elements-with-v-for)找到有关列表渲染的更多信息。

+   您可以在[`v3.vuejs.org/guide/conditional.html#v-if`](https://v3.vuejs.org/guide/conditional.html#v-if)找到有关条件渲染的更多信息。

+   您可以在[`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Math/random`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Math/random)找到有关`Math.random`的更多信息。

# 创建计算属性并了解其工作原理

想象一下，每次您需要获取处理过的数据时，您都需要执行一个函数。想象一下，您需要获取需要经过一些处理的特定数据，并且您需要每次通过函数执行它。这种类型的工作不容易维护。计算属性存在是为了解决这些问题。使用计算属性使得更容易获取需要预处理甚至缓存的数据，而无需执行任何其他外部记忆函数。

## 准备工作

这个配方的先决条件是 Node.js 12+。

此处所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

您可以继续进行我们的待办事项项目，或者按照我们在*使用 Vue CLI 创建您的第一个项目*中学到的内容创建一个新的 Vue 项目。

## 操作步骤

按照以下步骤创建一个计算属性并了解它的工作原理：

1.  在`App.vue`文件的`<script>`部分，我们将在`data`和`method`之间添加一个新属性，称为`computed`。这是`computed`属性将被放置的地方。我们将创建一个名为`displayList`的新计算属性，用于在模板上呈现最终列表：

```js
<script>
import CurrentTime from './components/CurrentTime.vue';
import TaskInput from './components/TaskInput.vue';

export default {
  name: 'TodoApp',
  components: {
    CurrentTime,
    TaskInput
  },
  data: () => ({
    taskList: []
  }),
  computed: {
    displayList(){
      return this.taskList;
    },
  },
  methods: {
    addNewTask(task) {
      this.taskList.push({
        task,
        createdAt: Date.now(),
        finishedAt: undefined
      });
    },
    changeStatus(taskIndex){
      const task = this.taskList[taskIndex];
      if(task.finishedAt){
        task.finishedAt = undefined;
      } else {
        task.finishedAt = Date.now();
      }
    }
  }
};
</script>
```

目前，`displayList`属性只是返回变量的缓存值，而不是直接的变量本身。

1.  现在，对于`<template>`部分，我们需要改变列表的获取位置：

```js
<template>
  <div id='app'>
    <current-time class='col-4' />
    <task-input class='col-6' @add-task='addNewTask' />
    <div class='col-12'>
      <div class='cardBox'>
        <div class='container'>
          <h2>My Tasks</h2>
          <ul class='taskList'>
            <li 
              v-for='(taskItem, index) in displayList'
              :key='`${index}_${Math.random()}`'
            >
              <input type='checkbox' 
                :checked='!!taskItem.finishedAt' 
                @input='changeStatus(index)'
              /> 
              {{ taskItem.task }} 
              <span v-if='taskItem.finishedAt'>
                {{ taskItem.finishedAt }}
              </span>
            </li>
          </ul>
        </div>
      </div>
    </div>
  </div>
</template>
```

1.  要运行服务器并查看您的组件，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> npm run serve 
```

记得始终执行命令`npm run lint --fix`，以自动修复任何代码 lint 错误。

## 工作原理

当使用`computed`属性将一个值传递给模板时，这个值现在被缓存。这意味着只有在值更新时才会触发渲染过程。同时，我们确保模板不使用变量进行渲染，以便它不能在模板上更改，因为它是变量的缓存副本。

使用这个过程，我们可以获得最佳的性能，因为我们不会浪费处理时间重新渲染对数据显示没有影响的更改的 DOM 树。这是因为如果有什么变化，结果是一样的，`computed`属性会缓存结果，并且不会更新最终结果。

## 另请参阅

你可以在[`v3.vuejs.org/guide/computed.html`](https://v3.vuejs.org/guide/computed.html)找到更多关于计算属性的信息。

# 使用自定义过滤器显示更清晰的数据和文本

有时，您可能会发现用户，甚至您自己，无法阅读 Unix 时间戳或其他`DateTime`格式。我们如何解决这个问题？在 Vue 中呈现数据时，可以使用我们称之为过滤器的东西。

想象一系列数据通过的管道。数据以一种形式进入每个管道，以另一种形式退出。这就是 Vue 中的过滤器的样子。您可以在同一个变量上放置一系列过滤器，以便对其进行格式化、重塑，并最终以不同的数据显示，而代码保持不变。在这些管道中，初始变量的代码是不可变的。

## 准备工作

本教程的先决条件是 Node.js 12+。

本教程所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

我们可以继续进行我们的待办事项项目，或者按照我们在*使用 Vue CLI 创建您的第一个项目*教程中学到的内容创建一个新的 Vue 项目。

## 如何做...

按照以下步骤创建您的第一个自定义 Vue 过滤器：

1.  在`App.vue`文件中，在`<script>`部分，在方法中，创建一个`formatDate`函数。这个函数将接收`value`作为参数并输入过滤器管道。我们可以检查`value`是否是一个数字，因为我们知道我们的时间是基于 Unix 时间戳格式的。如果它是一个数字，我们将根据当前浏览器位置进行格式化，并返回该格式化的值。如果值不是一个数字，我们只是返回传递的值。

```js
<script>
  import CurrentTime from './components/CurrentTime.vue';
  import TaskInput from './components/TaskInput.vue';

  export default {
    name: 'TodoApp',
    components: {
      CurrentTime,
      TaskInput
    },
    data: () => ({
      taskList: []
    }),
    computed: {
      displayList() {
        return this.taskList;
      }
    },
    methods: {
      formatDate(value) {
        if (!value) return '';
        if (typeof value !== 'number') return value;

        const browserLocale =
          navigator.languages && navigator.languages.length
            ? navigator.languages[0]
            : navigator.language;
        const intlDateTime = new Intl.DateTimeFormat(
          browserLocale, 
          {
            year: 'numeric',
            month: 'numeric',
            day: 'numeric',
            hour: 'numeric',
            minute: 'numeric'
          });

        return intlDateTime.format(new Date(value));
      },
      addNewTask(task) {
        this.taskList.push({
          task,
          createdAt: Date.now(),
          finishedAt: undefined
        });
      },
      changeStatus(taskIndex) {
        const task = this.taskList[taskIndex];
        if (task.finishedAt) {
          task.finishedAt = undefined;
        } else {
          task.finishedAt = Date.now();
        }
      }
    }
  };
</script>
```

1.  对于组件的`<template>`部分，我们需要将变量传递给过滤器方法。为了做到这一点，我们需要找到`taskItem.finishedAt`属性，并将其作为`formatDate`方法的参数。我们将添加一些文本来表示任务是在日期的开头“完成于：”。

```js
<template>
  <div id='app'>
    <current-time class='col-4' />
    <task-input class='col-6' @add-task='addNewTask' />
    <div class='col-12'>
      <div class='cardBox'>
        <div class='container'>
          <h2>My Tasks</h2>
          <ul class='taskList'>
            <li 
              v-for='(taskItem, index) in displayList'
              :key='`${index}_${Math.random()}`'
            >
              <input type='checkbox' 
                :checked='!!taskItem.finishedAt' 
                @input='changeStatus(index)'
              /> 
              {{ taskItem.task }} 
              <span v-if='taskItem.finishedAt'> | 
                Done at: 
                {{ formatDate(taskItem.finishedAt) }}
              </span>
            </li>
          </ul>
        </div>
      </div>
    </div>
  </div>
</template>
```

1.  要运行服务器并查看您的组件，请打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> npm run serve
```

请记住始终执行命令`npm run lint --fix`，以自动修复任何代码 lint 错误。

这是渲染和运行的组件：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/bd-vue-app-gql/img/8ea29522-f5dc-41bb-9162-747cec4936b3.png)

## 它是如何工作的...

过滤器是接收一个值并必须返回一个值以在文件的`<template>`部分中显示或在 Vue 属性中使用的方法。

当我们将值传递给`formatDate`方法时，我们知道它是一个有效的 Unix 时间戳，因此可以调用一个新的`Date`类构造函数，将`value`作为参数传递，因为 Unix 时间戳是一个有效的日期构造函数。

我们过滤器背后的代码是`Intl.DateTimeFormat`函数，这是一个本地函数，可用于格式化和解析日期到指定的位置。要获取本地格式，我们可以使用全局变量`navigator`。

## 另请参阅

您可以在[`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/DateTimeFormat`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/DateTimeFormat)找到有关`Intl.DateTimeFormat`的更多信息。

# 为列表创建过滤器和排序器

在处理列表时，通常会遇到原始数据。有时，您需要对这些数据进行过滤，以便用户可以阅读。为此，我们需要一组计算属性来形成最终的过滤器和排序器。

在这个教程中，我们将学习如何创建一个简单的过滤器和排序器，来控制我们最初的待办任务列表。

## 准备工作

这个教程的先决条件是 Node.js 12+。

本教程所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

我们可以继续进行待办事项列表项目，或者按照我们在*使用 Vue CLI 创建您的第一个项目*教程中学到的内容，创建一个新的 Vue 项目。

## 如何做...

按照以下步骤为您的列表添加一组过滤器和排序器：

1.  在`App.vue`文件的`<script>`部分，我们将添加新的计算属性；这些将用于排序和过滤。我们将添加三个新的计算属性：`baseList`，`filteredList`和`sortedList`。`baseList`属性将是我们的第一个操作。我们将通过`Array.map`向任务列表添加一个`id`属性。由于 JavaScript 数组从零开始，我们将在数组的索引上添加`1`。`filteredList`属性将过滤`baseList`属性，并返回未完成的任务，而`sortedList`属性将对`filteredList`属性进行排序，以便最后添加的`id`属性将首先显示给用户：

```js
<script>
import CurrentTime from "./components/CurrentTime.vue";
import TaskInput from "./components/TaskInput";

export default {
  name: "TodoApp",
  components: {
    CurrentTime,
    TaskInput
  },
  data: () => ({
    taskList: [],
  }),
  computed: {
    baseList() {
      return [...this.taskList]
        .map((t, index) => ({
            ...t,
            id: index + 1
          }));
    },
    filteredList() {
      return [...this.baseList]
            .filter(t => !t.finishedAt);
    },
    sortedList() {
      return [...this.filteredList]
          .sort((a, b) => b.id - a.id);
    },
    displayList() {
      return this.sortedList;
    }
  },
  methods: {
    formatDate(value) {
      if (!value) return "";
      if (typeof value !== "number") return value;

      const browserLocale =
        navigator.languages && navigator.languages.length
          ? navigator.languages[0]
          : navigator.language;
      const intlDateTime = new Intl.DateTimeFormat(browserLocale, {
        year: "numeric",
        month: "numeric",
        day: "numeric",
        hour: "numeric",
        minute: "numeric"
      });

      return intlDateTime.format(new Date(value));
    },
    addNewTask(task) {
      this.taskList.push({
        task,
        createdAt: Date.now(),
        finishedAt: undefined
      });
    },
    changeStatus(taskIndex) {
      const task = this.taskList[taskIndex];

      if (task.finishedAt) {
        task.finishedAt = undefined;
      } else {
        task.finishedAt = Date.now();
      }
    }
  }
};
</script>
```

1.  在`<template>`部分，我们将添加`Task ID`并更改`changeStatus`方法发送参数的方式。因为索引现在是可变的，我们不能将其用作变量；它只是数组上的临时索引。我们需要使用任务的`id`：

```js
<template>
  <div id="app">
    <current-time class="col-4" />
    <task-input class="col-6" @add-task="addNewTask" />
    <div class="col-12">
      <div class="cardBox">
        <div class="container">
          <h2>My Tasks</h2>
          <ul class="taskList">
            <li 
              v-for="(taskItem, index) in displayList"
              :key="`${index}_${Math.random()}`"
            >
              <input type="checkbox" 
                :checked="!!taskItem.finishedAt" 
                @input="changeStatus(taskItem.id)"
              /> 
              #{{ taskItem.id }} - {{ taskItem.task }} 
              <span v-if="taskItem.finishedAt"> | 
                Done at: 
                {{ formatDate(taskItem.finishedAt) }}
              </span>
            </li>
          </ul>
        </div>
      </div>
    </div>
  </div>
</template>
```

1.  我们还需要更新`changeStatus`方法中的函数。由于索引现在从`1`开始，我们需要将数组的索引减一，以便在更新之前获得元素的真实索引：

```js
changeStatus(taskId) {
    const task = this.taskList[taskId - 1];

    if (task.finishedAt) {
      task.finishedAt = undefined;
    } else {
      task.finishedAt = Date.now();
    }
}
```

1.  要运行服务器并查看组件，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> npm run serve
```

记得始终执行命令`npm run lint --fix`，以自动修复任何代码 lint 错误。

这是渲染和运行的组件：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/bd-vue-app-gql/img/b8319597-b627-4f82-b44f-7109c197afac.png)

## 它是如何工作的...

`computed`属性一起工作，作为列表的缓存，并确保在操作元素时没有副作用：

1.  对于`baseList`属性，我们创建了一个具有相同任务的新数组，但为任务添加了一个新的`id`属性。

1.  对于`filteredList`属性，我们使用`baseList`属性，只返回未完成的任务。

1.  对于`sortedList`属性，我们按照它们的 ID，按降序对`filteredList`属性上的任务进行排序。

当所有操作完成时，`displayList`属性返回了被操作的数据的结果。

## 另请参阅

+   您可以在[`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/map`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/map)找到有关`Array.prototype.map`的更多信息。

+   您可以在[`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/filter`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/filter)找到有关`Array.prototype.filter`的更多信息。

+   您可以在[`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/sort`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/sort)找到有关`Array.prototype.sort`的更多信息。

# 创建条件过滤器以对列表数据进行排序

现在您已经完成了上一个食谱，您的数据应该被过滤和排序，但您可能需要检查过滤后的数据或需要更改排序方式。在这个食谱中，您将学习如何创建条件过滤器并对列表上的数据进行排序。

使用一些基本原则，可以收集信息并以许多不同的方式显示它。

## 准备就绪

此食谱的先决条件是 Node.js 12+。

此食谱所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

我们可以继续进行我们的待办事项列表项目，或者按照我们在 *使用 Vue CLI 创建您的第一个项目* 食谱中学到的内容创建一个新的 Vue 项目。

## 如何做...

按照以下步骤添加条件过滤器以对列表数据进行排序：

1.  在 `App.vue` 文件的 `<script>` 部分，我们将更新 `computed` 属性；即 `filteredList`、`sortedList` 和 `displayList`。我们需要向我们的项目添加三个新变量：`hideDone`、`reverse` 和 `sortById`。所有三个变量都将是布尔变量，并且将以默认值 `false` 开始。`filteredList` 属性将检查 `hideDone` 变量是否为 `true`。如果是，它将具有相同的行为，但如果不是，它将显示完整的列表而不进行过滤。`sortedList` 属性将检查 `sortById` 变量是否为 `true`。如果是，它将具有相同的行为，但如果不是，它将按任务的完成日期对列表进行排序。最后，`displayList` 属性将检查 `reverse` 变量是否为 `true`。如果是，它将颠倒显示的列表，但如果不是，它将具有相同的行为：

```js
<script>
import CurrentTime from "./components/CurrentTime.vue";
import TaskInput from "./components/TaskInput";

export default {
  name: "TodoApp",
  components: {
    CurrentTime,
    TaskInput
  },
  data: () => ({
    taskList: [],
    hideDone: false,
    reverse: false,
    sortById: false,
  }),
  computed: {
    baseList() {
      return [...this.taskList]
        .map((t, index) => ({
            ...t,
            id: index + 1
          }));
    },
    filteredList() {
      return this.hideDone
        ? [...this.baseList]
            .filter(t => !t.finishedAt)
        : [...this.baseList];
    },
    sortedList() {
      return [...this.filteredList]
          .sort((a, b) => (
            this.sortById
              ? b.id - a.id
              : (a.finishedAt || 0) - (b.finishedAt || 0)
          ));
    },
    displayList() {
      const taskList = [...this.sortedList];

      return this.reverse 
      ? taskList.reverse() 
      : taskList;
    }
  },
  methods: {
    formatDate(value) {
      if (!value) return "";
      if (typeof value !== "number") return value;

      const browserLocale =
        navigator.languages && navigator.languages.length
          ? navigator.languages[0]
          : navigator.language;

      const intlDateTime = new Intl.DateTimeFormat(browserLocale, {
        year: "numeric",
        month: "numeric",
        day: "numeric",
        hour: "numeric",
        minute: "numeric"
      });

      return intlDateTime.format(new Date(value));
    },
    addNewTask(task) {
      this.taskList.push({
        task,
        createdAt: Date.now(),
        finishedAt: undefined
      });
    },
    changeStatus(taskId) {
      const task = this.taskList[taskId - 1];

      if (task.finishedAt) {
        task.finishedAt = undefined;
      } else {
        task.finishedAt = Date.now();
      }
    }
  }
};
</script>
```

1.  对于 `<template>` 部分，我们需要为这些变量添加控制器。我们将创建三个复选框，直接通过 `v-model` 指令与变量链接：

```js
<template>
  <div id="app">
    <current-time class="col-4" />
    <task-input class="col-6" @add-task="addNewTask" />
    <div class="col-12">
      <div class="cardBox">
        <div class="container">
          <h2>My Tasks</h2>
          <hr /> 
          <div class="col-4">
            <input 
              v-model="hideDone"
              type="checkbox"
              id="hideDone"
              name="hideDone"
            />
            <label for="hideDone">
              Hide Done Tasks
            </label>
          </div>
          <div class="col-4">
            <input 
              v-model="reverse"
              type="checkbox"
              id="reverse"
              name="reverse"
            />
            <label for="reverse">
              Reverse Order
            </label>
          </div>
          <div class="col-4">
            <input 
              v-model="sortById"
              type="checkbox"
              id="sortById"
              name="sortById"
            />
            <label for="sortById">
              Sort By Id
            </label>
          </div>
          <ul class="taskList">
            <li 
              v-for="(taskItem, index) in displayList"
              :key="`${index}_${Math.random()}`"
            >
              <input type="checkbox" 
                :checked="!!taskItem.finishedAt" 
                @input="changeStatus(taskItem.id)"
              /> 
              #{{ taskItem.id }} - {{ taskItem.task }} 
              <span v-if="taskItem.finishedAt"> | 
                Done at: 
                {{ formatDate(taskItem.finishedAt) }}
              </span>
            </li>
          </ul>
        </div>
      </div>
    </div>
  </div>
</template>
```

1.  要运行服务器并查看您的组件，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> npm run serve 
```

请记住始终执行命令 `npm run lint --fix`，以自动修复任何代码 lint 错误。

组件已呈现并运行：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/bd-vue-app-gql/img/0015cb11-98a7-418f-82fb-6c2a80859358.png)

## 工作原理...

`computed` 属性一起作为列表的缓存，并确保在操作元素时没有任何副作用。通过条件过程，可以通过变量更改过滤和排序过程的规则，并且显示会实时更新：

1.  对于 `filteredList` 属性，我们取 `baseList` 属性并仅返回未完成的任务。当 `hideDone` 变量为 `false` 时，我们返回完整的列表而不进行任何过滤。

1.  对于`sortedList`属性，我们对`filteredList`属性上的任务进行了排序。当`sortById`变量为`true`时，列表按 ID 降序排序；当为`false`时，按任务的完成时间升序排序。

1.  对于`displayList`属性，当`reverse`变量为`true`时，最终列表被反转。

当所有操作完成时，`displayList`属性将返回被操作的数据的结果。

这些`computed`属性由用户屏幕上的复选框控制，因此用户可以完全控制他们可以看到什么以及如何看到它。

## 另请参阅

+   您可以在[`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/map`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/map)找到有关`Array.prototype.map`的更多信息。

+   您可以在[`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/filter`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/filter)找到有关`Array.prototype.filter`的更多信息。

+   您可以在[`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/sort`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/sort)找到有关`Array.prototype.sort`的更多信息。

# 添加自定义样式和过渡效果

向您的组件添加样式是一个很好的做法，因为它可以让您更清楚地向用户展示发生了什么。通过这样做，您可以向用户显示视觉响应，并为他们提供更好的应用体验。

在这个示例中，我们将学习如何添加一种新的条件类绑定。我们将使用混合了 CSS 效果和每个新的 Vue 更新带来的重新渲染。

## 准备工作

此示例的先决条件是 Node.js 12+。

此处所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

我们可以继续进行待办事项列表项目，或者使用 Vue CLI 创建一个新的 Vue 项目，就像我们在*使用 Vue CLI 创建您的第一个项目*中学到的那样。

## 如何做...

按照以下步骤为您的组件添加自定义样式和过渡效果：

1.  在`App.vue`文件中，我们将为已完成的任务的列表项添加一个条件类：

```js
<template>
  <div id="app">
    <current-time class="col-4" />
    <task-input class="col-6" @add-task="addNewTask" />
    <div class="col-12">
      <div class="cardBox">
        <div class="container">
          <h2>My Tasks</h2>
          <hr /> 
          <div class="col-4">
            <input 
              v-model="hideDone"
              type="checkbox"
              id="hideDone"
              name="hideDone"
            />
            <label for="hideDone">
              Hide Done Tasks
            </label>
          </div>
          <div class="col-4">
            <input 
              v-model="reverse"
              type="checkbox"
              id="reverse"
              name="reverse"
            />
            <label for="reverse">
              Reverse Order
            </label>
          </div>
          <div class="col-4">
            <input 
              v-model="sortById"
              type="checkbox"
              id="sortById"
              name="sortById"
            />
            <label for="sortById">
              Sort By Id
            </label>
          </div>
          <ul class="taskList">
            <li 
              v-for="(taskItem, index) in displayList"
              :key="`${index}_${Math.random()}`"
              :class="!!taskItem.finishedAt ? 'taskDone' : ''"
            >
              <input type="checkbox" 
                :checked="!!taskItem.finishedAt" 
                @input="changeStatus(taskItem.id)"
              /> 
              #{{ taskItem.id }} - {{ taskItem.task }} 
              <span v-if="taskItem.finishedAt"> | 
                Done at: 
                {{ formatDate(taskItem.finishedAt) }}
              </span>
            </li>
          </ul>
        </div>
      </div>
    </div>
  </div>
</template>
```

1.  对于组件的`<style>`部分，我们将为`taskDone` CSS 类创建 CSS 样式表类。我们需要使列表在项目之间有一个分隔符；然后，我们将使列表具有条纹样式。当它们被标记为已完成时，背景将带有一个效果。为了在行和条纹列表或斑马样式之间添加分隔符，我们需要添加一个 CSS 规则，该规则适用于我们列表的每个`even nth-child`：

```js
<style scoped>
  .taskList li {
    list-style: none;
    text-align: left;
    padding: 5px 10px;
    border-bottom: 1px solid rgba(0,0,0,0.15);
  }

  .taskList li:last-child {
    border-bottom: 0px;
  }

  .taskList li:nth-child(even){
    background-color: rgba(0,0,0,0.05);
  }
</style>
```

1.  要在任务完成时将效果添加到背景中，在`<style>`部分的末尾，我们将添加一个 CSS 动画关键帧，指示背景颜色的变化，并将此动画应用于`.taskDone` CSS 类：

```js
<style scoped>
  .taskList li {
    list-style: none;
    text-align: left;
    padding: 5px 10px;
    border-bottom: 1px solid rgba(0,0,0,0.15);
  }

  .taskList li:last-child {
    border-bottom: 0px;
  }

  .taskList li:nth-child(even){
    background-color: rgba(0,0,0,0.05);
  }

  @keyframes colorChange {
    from{
      background-color: inherit;
    }
    to{
      background-color: rgba(0, 160, 24, 0.577); 
    }
  }

  .taskList li.taskDone{
    animation: colorChange 1s ease;
    background-color: rgba(0, 160, 24, 0.577);
  }
</style>
```

1.  要运行服务器并查看您的组件，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> npm run serve 
```

请记住始终执行命令`npm run lint --fix`，以自动修复任何代码 lint 错误。

这是渲染和运行的组件：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/bd-vue-app-gql/img/03cbe64b-7a4b-465b-aea8-1cacbc764f87.png)

## 工作原理...

每当我们的应用程序中的新项目被标记为已完成时，`displayList`属性都会更新并触发组件的重新渲染。

因此，我们的`taskDone` CSS 类附加了一个动画，该动画在渲染时执行，显示绿色背景。

## 参见

+   您可以在[`developer.mozilla.org/en-US/docs/Web/CSS/CSS_Animations/Using_CSS_animations`](https://developer.mozilla.org/en-US/docs/Web/CSS/CSS_Animations/Using_CSS_animations)找到有关 CSS 动画的更多信息。

+   您可以在[`v3.vuejs.org/guide/class-and-style.html`](https://v3.vuejs.org/guide/class-and-style.html)找到有关类和样式绑定的更多信息

# 使用 vue-devtools 调试您的应用程序

`vue-devtools`对于每个 Vue 开发人员都是必不可少的。这个工具向我们展示了 Vue 组件、路由、事件和 Vuex 的深度。

借助`vue-devtools`扩展，可以调试我们的应用程序，在更改代码之前尝试新数据，执行函数而无需直接在代码中调用它们，等等。

在本教程中，我们将学习如何使用各种开发工具来了解我们的应用程序，并了解它们如何帮助我们的调试过程。

## 准备工作

本教程的先决条件是 Node.js 12+。

本教程所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

您需要在浏览器中安装`vue-devtools`扩展程序：

+   Chrome 扩展程序：[`bit.ly/chrome-vue-devtools`](http://bit.ly/chrome-vue-devtools)

+   Firefox 扩展程序：[`bit.ly/firefox-vue-devtools`](http://bit.ly/firefox-vue-devtools)

我们可以继续进行我们的待办事项列表项目，或者使用 Vue CLI 创建一个新的 Vue 项目，就像我们在*使用 Vue CLI 创建您的第一个项目*中学到的那样。

## 如何做...

在开发任何 Vue 应用程序时，始终将`vue-devtools`作为良好的实践进行开发。

按照以下步骤了解如何使用`vue-devtools`以及如何正确调试 Vue 应用程序：

1.  要进入`vue-devtools`，您需要在浏览器中安装它，因此请查看本教程的*准备就绪*部分，获取 Chrome 或 Firefox 扩展程序的链接。在您的 Vue 开发应用程序中，进入浏览器开发者检查器模式。将出现一个名为 Vue 的新标签页：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/bd-vue-app-gql/img/c08fd0d0-ff90-4257-933d-b53c85b29b28.png)

1.  您将看到的第一个标签页是组件标签页。此标签显示应用程序组件树。如果单击组件，您将能够查看所有可用数据，计算属性以及插件（如`vuelidate`，`vue-router`或`vuex`）注入的额外数据。您可以编辑此数据以实时查看应用程序中的更改：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/bd-vue-app-gql/img/fbab0838-bec5-4d25-8106-38bd57b51ebd.png)

1.  第二个标签页用于 Vuex 开发。此标签将显示变化的历史记录，当前状态和获取器。可以检查每个变化的传递负载，并进行时间旅行变化，以*回到过去*并查看状态中的 Vuex 更改：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/bd-vue-app-gql/img/450a5c02-da10-4793-9290-996b13cc3845.png)

1.  第三个标签页专门用于应用程序中的事件发射器。在此处显示应用程序中发射的所有事件。您可以通过单击事件来检查发射的事件。通过这样做，您可以看到事件的名称，类型，事件源（在本例中是组件）以及负载：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/bd-vue-app-gql/img/88c382ae-8d0a-44ce-9e50-6ae3e9c24f06.png)

1.  第四个标签页专门用于 vue-router 插件。在那里，您可以查看其导航历史，以及传递给新路由的所有元数据。这是您可以检查应用程序中所有可用路由的地方：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/bd-vue-app-gql/img/5431685c-f94f-4bf8-8eba-6e0ca4fcd486.png)

1.  第五个选项卡是性能选项卡。在这里，您可以检查组件的加载时间以及应用程序实时运行的每秒帧数。以下屏幕截图显示了当前应用程序的每秒帧数，以及所选组件的每秒帧数：

！[](assets/833ad7aa-88bb-49d0-9522-fbba99d168c5.png)

以下屏幕截图显示了组件的生命周期钩子性能以及执行每个钩子所需的时间：

！[](assets/c539f0f6-7f06-4dba-95a6-dbc587b1702e.png)

1.  第六个选项卡是您的设置选项卡。在这里，您可以管理扩展程序并更改其外观，内部行为以及在 Vue 插件中的行为：

！[](assets/5ded148d-1d5b-4239-9746-9a4ac0fc912e.png)

1.  最后一个选项卡是`vue-devtools`的刷新按钮。有时，当发生`热模块重新加载`或当应用程序组件树中发生一些复杂事件时，扩展程序可能会丢失对发生情况的跟踪。此按钮强制扩展程序重新加载并再次读取 Vue 应用程序状态。

## 另请参阅

您可以在[`github.com/vuejs/vue-devtools`](https://github.com/vuejs/vue-devtools)找到有关`vue-devtools`的更多信息。


# 第二章：组件、混合和功能性组件

构建 Vue 应用就像拼图一样。每个拼图的一部分都是一个组件，每个拼图都有一个槽要填充。

组件在 Vue 开发中扮演着重要角色。在 Vue 中，你的代码的每一部分都将是一个组件 - 它可以是布局、页面、容器或按钮，但最终，它都是一个组件。学习如何与它们交互和重用它们是清理代码和提高 Vue 应用性能的关键。组件是最终会在屏幕上渲染出东西的代码，无论它的大小是多少。

在这一章中，我们将学习如何制作一个可在多个地方重复使用的可视化组件。我们将使用插槽在组件内放置数据，为了快速渲染创建功能性组件，实现父子组件之间的直接通信，并异步加载我们的组件。

然后，我们将把所有这些部分放在一起，创建一个既是美丽的拼图又是 Vue 应用的拼图。

在这一章中，我们将涵盖以下示例：

+   创建一个可视化模板组件

+   使用插槽和命名插槽在组件内放置数据

+   向您的组件传递数据并验证数据

+   创建功能性组件

+   访问子组件的数据

+   创建一个动态注入组件

+   创建一个依赖注入组件

+   创建一个`mixin`组件

+   延迟加载您的组件

让我们开始吧！

# 技术要求

在这一章中，我们将使用**Node.js**和**Vue-CLI**。

**注意 Windows 用户**：您需要安装一个名为`windows-build-tools`的`npm`包才能安装所需的包。为此，请以管理员身份打开 PowerShell 并执行`> npm install -g windows-build-tools`命令。

要安装**Vue CLI**，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> npm install -g @vue/cli @vue/cli-service-global
```

# 创建一个可视化模板组件

组件可以是数据驱动的、无状态的、有状态的或简单的可视化组件。但是什么是可视化组件？可视化组件是一个只有一个目的的组件：视觉操作。

一个可视化组件可以有一个简单的作用域 CSS 和一些`div` HTML 元素，或者它可以是一个更复杂的组件，可以实时计算元素在屏幕上的位置。

在这个示例中，我们将创建一个遵循 Material Design 指南的卡片包装组件。

## 准备工作

此示例的先决条件是 Node.js 12+。

此示例所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

## 如何做...

要启动我们的组件，我们需要使用 Vue CLI 创建一个新的 Vue 项目。打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> vue create visual-component
```

CLI 将询问一些问题，这些问题将帮助您创建项目。您可以使用箭头键导航，使用*Enter*键继续，并使用*空格键*选择选项。选择`default`选项：

```js
?  Please pick a preset: **(Use arrow keys)** ❯ default (babel, eslint) 
  Manually select features  ‌
```

现在，按照以下步骤创建一个视觉模板组件：

1.  在`src/components`文件夹中创建一个名为`MaterialCardBox.vue`的新文件。

1.  在此文件中，我们将开始处理组件的模板。我们需要为卡片创建一个框。通过使用 Material Design 指南，此框将具有阴影和圆角：

```js
<template>
  <div class="cardBox elevation_2">
    <div class="section">
      This is a Material Card Box
    </div>
  </div>
</template>
```

1.  在我们组件的`<script>`部分中，我们将只添加我们的基本名称：

```js
<script>
  export default {
    name: 'MaterialCardBox',
  };
</script>
```

1.  我们需要创建我们的高程 CSS 规则。为此，请在`style`文件夹中创建一个名为`elevation.css`的文件。在那里，我们将创建从`0`到`24`的高程，以便我们可以遵循 Material Design 指南提供的所有高程：

```js
.elevation_0 {
  border: 1px solid rgba(0, 0, 0, 0.12);
}

.elevation_1 {
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.2),
  0 1px 1px rgba(0, 0, 0, 0.14),
  0 2px 1px -1px rgba(0, 0, 0, 0.12);
}

.elevation_2 {
  box-shadow: 0 1px 5px rgba(0, 0, 0, 0.2),
  0 2px 2px rgba(0, 0, 0, 0.14),
  0 3px 1px -2px rgba(0, 0, 0, 0.12);
}

.elevation_3 {
  box-shadow: 0 1px 8px rgba(0, 0, 0, 0.2),
  0 3px 4px rgba(0, 0, 0, 0.14),
  0 3px 3px -2px rgba(0, 0, 0, 0.12);
}

.elevation_4 {
  box-shadow: 0 2px 4px -1px rgba(0, 0, 0, 0.2),
  0 4px 5px rgba(0, 0, 0, 0.14),
  0 1px 10px rgba(0, 0, 0, 0.12);
}

.elevation_5 {
  box-shadow: 0 3px 5px -1px rgba(0, 0, 0, 0.2),
  0 5px 8px rgba(0, 0, 0, 0.14),
  0 1px 14px rgba(0, 0, 0, 0.12);
}

.elevation_6 {
  box-shadow: 0 3px 5px -1px rgba(0, 0, 0, 0.2),
  0 6px 10px rgba(0, 0, 0, 0.14),
  0 1px 18px rgba(0, 0, 0, 0.12);
}

.elevation_7 {
  box-shadow: 0 4px 5px -2px rgba(0, 0, 0, 0.2),
  0 7px 10px 1px rgba(0, 0, 0, 0.14),
  0 2px 16px 1px rgba(0, 0, 0, 0.12);
}

.elevation_8 {
  box-shadow: 0 5px 5px -3px rgba(0, 0, 0, 0.2),
  0 8px 10px 1px rgba(0, 0, 0, 0.14),
  0 3px 14px 2px rgba(0, 0, 0, 0.12);
}

.elevation_9 {
  box-shadow: 0 5px 6px -3px rgba(0, 0, 0, 0.2),
  0 9px 12px 1px rgba(0, 0, 0, 0.14),
  0 3px 16px 2px rgba(0, 0, 0, 0.12);
}

.elevation_10 {
  box-shadow: 0 6px 6px -3px rgba(0, 0, 0, 0.2),
  0 10px 14px 1px rgba(0, 0, 0, 0.14),
  0 4px 18px 3px rgba(0, 0, 0, 0.12);
}

.elevation_11 {
  box-shadow: 0 6px 7px -4px rgba(0, 0, 0, 0.2),
  0 11px 15px 1px rgba(0, 0, 0, 0.14),
  0 4px 20px 3px rgba(0, 0, 0, 0.12);
}

.elevation_12 {
  box-shadow: 0 7px 8px -4px rgba(0, 0, 0, 0.2),
  0 12px 17px 2px rgba(0, 0, 0, 0.14),
  0 5px 22px 4px rgba(0, 0, 0, 0.12);
}

.elevation_13 {
  box-shadow: 0 7px 8px -4px rgba(0, 0, 0, 0.2),
  0 13px 19px 2px rgba(0, 0, 0, 0.14),
  0 5px 24px 4px rgba(0, 0, 0, 0.12);
}

.elevation_14 {
  box-shadow: 0 7px 9px -4px rgba(0, 0, 0, 0.2),
  0 14px 21px 2px rgba(0, 0, 0, 0.14),
  0 5px 26px 4px rgba(0, 0, 0, 0.12);
}

.elevation_15 {
  box-shadow: 0 8px 9px -5px rgba(0, 0, 0, 0.2),
  0 15px 22px 2px rgba(0, 0, 0, 0.14),
  0 6px 28px 5px rgba(0, 0, 0, 0.12);
}

.elevation_16 {
  box-shadow: 0 8px 10px -5px rgba(0, 0, 0, 0.2),
  0 16px 24px 2px rgba(0, 0, 0, 0.14),
  0 6px 30px 5px rgba(0, 0, 0, 0.12);
}

.elevation_17 {
  box-shadow: 0 8px 11px -5px rgba(0, 0, 0, 0.2),
  0 17px 26px 2px rgba(0, 0, 0, 0.14),
  0 6px 32px 5px rgba(0, 0, 0, 0.12);
}

.elevation_18 {
  box-shadow: 0 9px 11px -5px rgba(0, 0, 0, 0.2),
  0 18px 28px 2px rgba(0, 0, 0, 0.14),
  0 7px 34px 6px rgba(0, 0, 0, 0.12);
}

.elevation_19 {
  box-shadow: 0 9px 12px -6px rgba(0, 0, 0, 0.2),
  0 19px 29px 2px rgba(0, 0, 0, 0.14),
  0 7px 36px 6px rgba(0, 0, 0, 0.12);
}

.elevation_20 {
  box-shadow: 0 10px 13px -6px rgba(0, 0, 0, 0.2),
  0 20px 31px 3px rgba(0, 0, 0, 0.14),
  0 8px 38px 7px rgba(0, 0, 0, 0.12);
}

.elevation_21 {
  box-shadow: 0 10px 13px -6px rgba(0, 0, 0, 0.2),
  0 21px 33px 3px rgba(0, 0, 0, 0.14),
  0 8px 40px 7px rgba(0, 0, 0, 0.12);
}

.elevation_22 {
  box-shadow: 0 10px 14px -6px rgba(0, 0, 0, 0.2),
  0 22px 35px 3px rgba(0, 0, 0, 0.14),
  0 8px 42px 7px rgba(0, 0, 0, 0.12);
}

.elevation_23 {
  box-shadow: 0 11px 14px -7px rgba(0, 0, 0, 0.2),
  0 23px 36px 3px rgba(0, 0, 0, 0.14),
  0 9px 44px 8px rgba(0, 0, 0, 0.12);
}

.elevation_24 {
  box-shadow: 0 11px 15px -7px rgba(0, 0, 0, 0.2),
  0 24px 38px 3px rgba(0, 0, 0, 0.14),
  0 9px 46px 8px rgba(0, 0, 0, 0.12);
}
```

1.  在组件的`<style>`部分中为我们的卡片设置样式，我们需要在`<style>`标签内设置`scoped`属性。这确保了视觉样式不会干扰应用程序中的任何其他组件。我们将使此卡片遵循 Material Design 指南。我们需要导入`Roboto`字体系列并将其应用于此组件内部的所有元素：

```js
<style scoped>
  @import url('https://fonts.googleapis.com/css? 
    family=Roboto:400,500,700&display=swap');
  @import '../style/elevation.css';

  * {
    font-family: 'Roboto', sans-serif;
  }

  .cardBox {
    width: 100%;
    max-width: 300px;
    background-color: #fff;
    position: relative;
    display: inline-block;
    border-radius: 0.25rem;
  }

  .cardBox > .section {
    padding: 1rem;
    position: relative;
  }
</style>
```

1.  在`App.vue`文件中，我们需要导入我们的组件以便能够看到它：

```js
<template>
  <div id='app'>
    <material-card-box />
  </div>
</template>

<script>
import MaterialCardBox from './components/MaterialCardBox.vue';

export default {
  name: 'app',
  components: {
    MaterialCardBox
  }
}
</script>
```

1.  要运行服务器并查看您的组件，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> npm run serve
```

请记住始终执行命令`npm run lint --fix`，以自动修复任何代码 lint 错误。

这是渲染和运行的组件：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/bd-vue-app-gql/img/653a5ed9-5429-4c27-b2d7-6e26c147418c.png)

## 工作原理...

视觉组件是一个将包装任何组件并将包装数据与自定义样式放在一起的组件。由于此组件与其他组件混合，因此它可以形成一个新的组件，而无需您在代码中重新应用或重写任何样式。

## 另请参阅

+   关于 Scoped CSS 的更多信息，请访问[`vue-loader.vuejs.org/guide/scoped-css.html#child-component-root-elements`](https://vue-loader.vuejs.org/guide/scoped-css.html#child-component-root-elements)。

+   关于 Material Design 卡片的更多信息，请访问[`material.io/components/cards/`](https://material.io/components/cards/)。

+   查看[`fonts.google.com/specimen/Roboto`](https://fonts.google.com/specimen/Roboto)上的 Roboto 字体系列。

# 使用插槽和命名插槽将数据放入组件中

有时，拼图的一些部分会丢失，你会发现自己有一个空白的地方。想象一下，你可以用自己制作的一块填补那个空白的地方 - 而不是拼图盒子里原来的那块。这大致类似于 Vue 插槽的作用。

Vue 插槽就像是组件中的开放空间，其他组件可以用文本、HTML 元素或其他 Vue 组件填充。你可以在组件中声明插槽的位置和行为方式。

通过这种技术，你可以创建一个组件，并在需要时轻松自定义它。

## 准备工作

这个食谱的先决条件是 Node.js 12+。

此食谱所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

要完成这个食谱，我们将使用我们的 Vue 项目和 Vue CLI，就像在*创建可视化模板组件*食谱中所做的那样。

## 操作步骤

按照以下说明在组件中创建插槽和命名插槽：

1.  在`components`文件夹中打开`MaterialCardBox.vue`文件。

1.  在组件的`<template>`部分，我们需要为卡片添加四个主要部分。这些部分基于 Material Design 卡片的结构，分别是`header`、`media`、`main section`和`action`区域。我们将使用默认插槽来放置`main section`；其余部分都将是命名插槽。对于一些命名插槽，我们将添加一个回退配置，如果用户没有为插槽选择任何设置，则将显示该配置：

```js
<template>
  <div class="cardBox elevation_2">
  <div class="header">
  <slot
  v-if="$slots.header"
  name="header"
  />
  <div v-else>
  <h1 class="cardHeader cardText">
      Card Header
  </h1>
  <h2 class="cardSubHeader cardText">
      Card Sub Header
  </h2>
  </div>
  </div>
  <div class="media">
  <slot
  v-if="$slots.media"
  name="media"
  />
  <img
  v-else
  src="https://via.placeholder.com/350x250"
  >
  </div>
  <div
  v-if="$slots.default"
  class="section cardText"
  :class="{
    noBottomPadding: $slots.action,
    halfPaddingTop: $slots.media,
  }"
  >
  <slot/>
  </div>
  <div
  v-if="$slots.action"
  class="action"
  >
  <slot name="action"/>
  </div>
  </div> </template>
```

1.  现在，我们需要为组件创建文本 CSS 规则。在`style`文件夹中，创建一个名为`cardStyles.css`的新文件。在这里，我们将添加卡片文本和标题的规则：

```js
h1, h2, h3, h4, h5, h6 {
  margin: 0;
}

.cardText {
  -moz-osx-font-smoothing: grayscale;
  -webkit-font-smoothing: antialiased;
  text-decoration: inherit;
  text-transform: inherit;
  font-size: 0.875rem;
  line-height: 1.375rem;
  letter-spacing: 0.0071428571em;
}

h1.cardHeader {
  font-size: 1.25rem;
  line-height: 2rem;
  font-weight: 500;
  letter-spacing: .0125em;
}

h2.cardSubHeader {
  font-size: .875rem;
  line-height: 1.25rem;
  font-weight: 400;
  letter-spacing: .0178571429em;
  opacity: .6;
}
```

1.  在组件的`<style>`部分，我们需要创建一些遵循设计指南规则的 CSS：

```js
<style scoped>
  @import url("https://fonts.googleapis.com/css?family=Roboto:400,500,700&display=swap");
  @import "../style/elevation.css";
  @import "../style/cardStyles.css";    * {
  font-family: "Roboto", sans-serif;
  }    .cardBox {
  width: 100%;
  max-width: 300px;
  border-radius: 0.25rem;
  background-color: #fff;
  position: relative;
  display: inline-block;
  box-shadow: 0 1px 5px rgba(0, 0, 0, 0.2), 0 2px 2px rgba(0, 0,
      0, 0.14),
  0 3px 1px -2px rgba(0, 0, 0, 0.12);
  }    .cardBox > .header {
  padding: 1rem;
  position: relative;
  display: block;
  }    .cardBox > .media {
  overflow: hidden;
  position: relative;
  display: block;
  max-width: 100%;
  }    .cardBox > .section {
  padding: 1rem;
  position: relative;
  margin-bottom: 1.5rem;
  display: block;
  }    .cardBox > .action {
  padding: 0.5rem;
  position: relative;
  display: block;
  }    .cardBox > .action > *:not(:first-child) {
  margin-left: 0.4rem;
  }    .noBottomPadding {
  padding-bottom: 0 !important;
  }    .halfPaddingTop {
  padding-top: 0.5rem !important;
  } </style>
```

1.  在`src`文件夹中的`App.vue`文件中，我们需要向这些插槽添加元素。这些元素将被添加到每个命名插槽以及默认插槽。我们将更改文件的`<template>`部分内的组件。要添加命名插槽，我们需要使用一个名为`v-slot：`的指令，然后添加我们想要使用的插槽的名称：

```js
<template>
  <div id="app">
  <MaterialCardBox>
  <template v-slot:header>
  <strong>Card Title</strong><br>
  <span>Card Sub-Title</span>
  </template>
  <template v-slot:media>
  <img src="https://via.placeholder.com/350x150">
  </template>
  <p>Main Section</p>
  <template v-slot:action>
  <button>Action Button</button>
  <button>Action Button</button>
  </template>
  </MaterialCardBox>
  </div> </template>
```

对于默认插槽，我们不需要使用指令；它只需要包裹在组件内部，以便可以放置在组件的`<slot />`部分内。

1.  要运行服务器并查看您的组件，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> npm run serve
```

请记住始终执行命令`npm run lint --fix`，以自动修复任何代码 lint 错误。

这是渲染和运行的组件：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/bd-vue-app-gql/img/8f8c0945-dabc-4cfe-bee4-1871cbfc651c.png)

## 它是如何工作的...

插槽是可以放置任何可以呈现到 DOM 中的东西的地方。我们选择插槽的位置，并告诉组件在接收到任何信息时在哪里呈现。

在这个示例中，我们使用了命名插槽，这些插槽旨在与需要多个插槽的组件一起使用。要在 Vue 单文件（`.vue`）的`<template>`部分中放置组件内的任何信息，您需要添加`v-slot：`指令，以便 Vue 知道在哪里放置传递下来的信息。

## 另请参阅

+   您可以在[`v3.vuejs.org/guide/component-slots.html`](https://v3.vuejs.org/guide/component-slots.html)找到有关 Vue 插槽的更多信息。

+   您可以在[`material.io/components/cards/#anatomy`](https://material.io/components/cards/#anatomy)找到有关 Material Design 卡片解剖的更多信息。

# 向组件传递数据并验证数据

到目前为止，您知道如何通过插槽将数据放入组件中，但这些插槽是为 HTML DOM 元素或 Vue 组件而设计的。有时，您需要传递诸如字符串、数组、布尔值甚至对象之类的数据。

整个应用程序就像一个拼图，其中每个部分都是一个组件。组件之间的通信是其中的重要部分。向组件传递数据是连接拼图的第一步，而验证数据是连接部件的最后一步。

在这个示例中，我们将学习如何向组件传递数据并验证传递给它的数据。

## 准备工作

这个食谱的先决条件是 Node.js 12+。

这个食谱所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

要完成这个食谱，我们将继续使用来自 *使用插槽和命名插槽在组件内放置数据* 食谱的项目。

## 如何做...

按照以下说明传递数据给组件并验证它：

1.  打开 `src/components` 文件夹中的 `MaterialCardBox.vue` 文件。

1.  在组件的 `<script>` 部分，我们将创建一个名为 `props` 的新属性。这个属性接收组件的数据，可以用于视觉操作、代码内的变量，或者需要执行的函数。在这个属性中，我们需要声明属性的名称、类型、是否必需，以及验证函数。这个函数将在运行时执行，以验证传递的属性是否有效：

```js
<script> export default {
  name: 'MaterialCardBox',
  inheritAttrs: false,
  props: {
  header: {
    type: String,
    required: false,
    default: '',
    validator: (v) => typeof v === 'string',
  },
  subHeader: {
    type: String,
    required: false,
    default: '',
    validator: (v) => typeof v === 'string',
  },
  mainText: {
    type: String,
    required: false,
    default: '',
    validator: (v) => typeof v === 'string',
  },
  showMedia: {
    type: Boolean,
    required: false,
    default: false,
    validator: (v) => typeof v === 'boolean',
  },
  imgSrc: {
    type: String,
    required: false,
    default: '',
    validator: (v) => typeof v === 'string',
  },
  showActions: {
    type: Boolean,
    required: false,
    default: false,
    validator: (v) => typeof v === 'boolean',
  },
  elevation: {
    type: Number,
    required: false,
    default: 2,
    validator: (v) => typeof v === 'number',
  },
  },
  computed: {}, }; </script>
```

1.  在组件的 `<script>` 部分的 `computed` 属性中，我们需要创建一组用于渲染卡片的视觉操作规则。这些规则被称为 `showMediaContent`、`showActionsButtons`、`showHeader` 和 `cardElevation`。每个规则将检查接收到的 `props` 和 `$slots` 对象，以检查是否需要渲染相关的卡片部分：

```js
computed: {
  showMediaContent() {
  return (this.$slots.media || this.imgSrc) && this.showMedia;
  },
  showActionsButtons() {
  return this.showActions && this.$slots.action;
  },
  showHeader() {
  return this.$slots.header || (this.header || this.subHeader);
  },
  showMainContent() {
  return this.$slots.default || this.mainText;
  },
  cardElevation() {
  return `elevation_${parseInt(this.elevation, 10)}`;
  }, },
```

1.  在添加了视觉操作规则之后，我们需要将创建的规则添加到组件的 `<template>` 部分。它们将影响我们卡片的外观和行为。例如，如果没有定义头部插槽，但定义了头部属性，我们将显示备用头部。这个头部包含通过 `props` 传递下来的数据：

```js
<template>
  <div
  class="cardBox"
  :class="cardElevation"
  >
  <div
    v-if="showHeader"
    class="header"
  >
    <slot
      v-if="$slots.header"
      name="header"
    />
    <div v-else>
      <h1 class="cardHeader cardText">
        {{ header }}
      </h1>
      <h2 class="cardSubHeader cardText">
        {{ subHeader }}
      </h2>
    </div>
  </div>
  <div
    v-if="showMediaContent"
    class="media"
  >
    <slot
      v-if="$slots.media"
      name="media"
    />
    <img
      v-else
      :src="imgSrc"
    >
  </div>
  <div
    v-if="showMainContent"
    class="section cardText"
    :class="{
      noBottomPadding: $slots.action,
      halfPaddingTop: $slots.media,
    }"
  >
    <slot v-if="$slots.default" />
    <p
      v-else
      class="cardText"
    >
      {{ mainText }}
    </p>
  </div>
  <div
    v-if="showActionsButtons"
    class="action"
  >
    <slot
      v-if="$slots.action"
      name="action"
    />
  </div>
  </div> </template>
```

1.  要运行服务器并查看你的组件，你需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows），并执行以下命令：

```js
> npm run serve
```

记得总是执行命令 `npm run lint --fix`，自动修复任何代码 lint 错误。

这是渲染和运行的组件：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/bd-vue-app-gql/img/c8fc07a8-43b1-4ce7-9448-e781a6647fb4.png)

## 它是如何工作的...

每个 Vue 组件都是一个 JavaScript 对象，有一个渲染函数。当需要在 HTML DOM 中渲染它时，会调用这个渲染函数。单文件组件是这个对象的一个抽象。

当我们声明我们的组件具有可以传递的唯一 props 时，它为其他组件或 JavaScript 打开了一个小门，以在我们的组件内放置信息。然后，我们可以在组件内使用这些值来渲染数据，进行一些计算，或者制定视觉规则。

在我们的情况下，使用单文件组件，我们将这些规则作为 HTML 属性传递，因为`vue-template-compiler`将获取这些属性并将其转换为 JavaScript 对象。

当这些值传递给我们的组件时，Vue 会检查传递的属性是否与正确的类型匹配，然后我们对每个值执行验证函数，以查看它是否与我们期望的匹配。

完成所有这些后，组件的生命周期继续，我们可以渲染我们的组件。

## 另请参阅

+   您可以在[`v3.vuejs.org/guide/component-props.html`](https://v3.vuejs.org/guide/component-props.html)找到有关`props`的更多信息。

+   您可以在[`vue-loader.vuejs.org/guide/`](https://vue-loader.vuejs.org/guide)找到有关`vue-template-compiler`的更多信息。

# 创建功能组件

功能组件的美丽之处在于它们的简单性。它们是无状态组件，没有任何数据、计算属性，甚至生命周期。它们只是在传递的数据发生变化时调用的渲染函数。

您可能想知道这有什么用。嗯，功能组件是 UI 组件的完美伴侣，它们不需要在内部保留任何数据，或者只是渲染组件而不需要任何数据操作的可视组件。

顾名思义，它们类似于函数组件，除了渲染函数外没有其他内容。它们是组件的精简版本，专门用于性能渲染和可视元素。

## 准备工作

此配方的先决条件是 Node.js 12+。

此配方所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

要完成此配方，我们将使用我们的 Vue 项目和 Vue CLI，就像在*将数据传递给您的组件并验证数据*配方中所做的那样。

## 如何做...

按照以下说明创建一个 Vue 功能组件：

1.  在`src/components`文件夹中创建一个名为`MaterialButton.vue`的新文件。

1.  在这个组件中，我们需要验证我们将接收的 prop 是否是有效的颜色。为此，在项目中安装`is-color`模块。您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> npm install --save is-color
```

1.  在我们组件的`<script>`部分，我们需要创建`props`对象，函数组件将接收该对象。由于函数组件只是一个没有状态的渲染函数，因此它是无状态的 - 组件的`<script>`部分被简化为`props`，`injections`和`slots`。将有四个`props`对象：`backgroundColor`，`textColor`，`isRound`和`isFlat`。在安装组件时，这些将不是必需的，因为我们在`props`中定义了默认值：

```js
<script> import isColor from 'is-color';   export default {
  name: 'MaterialButton',
  props: {
  backgroundColor: {
    type: String,
    required: false,
    default: '#fff',
    validator: (v) => typeof v === 'string' && isColor(v),
  },
  textColor: {
    type: String,
    required: false,
    default: '#000',
    validator: (v) => typeof v === 'string' && isColor(v),
  },
  isRound: {
    type: Boolean,
    required: false,
    default: false,
  },
  isFlat: {
    type: Boolean,
    required: false,
    default: false,
  },
  }, }; </script>
```

1.  我们需要创建一个带有基本`class`属性按钮的 HTML 元素，并且一个基于接收到的`props`对象的动态`class`属性。与普通组件相比，我们需要指定`props`属性以使用函数组件。对于按钮的样式，我们需要创建一个基于`$props`的动态`style`属性。为了直接将所有事件监听器传递给父级，我们可以调用`v-bind`指令并传递`$attrs`属性。这将绑定所有事件监听器，而无需我们声明每一个。在按钮内部，我们将添加一个用于视觉增强的`div`HTML 元素，并添加`<slot>`，文本将放置在其中：

```js
<template>
  <button
  tabindex="0"
  class="button"
  :class="{
    round: $props.isRound,
    isFlat: $props.isFlat,
  }"
  :style="{
    background: $props.backgroundColor,
    color: $props.textColor
  }"
  v-bind="$attrs"
  >
  <div
    tabindex="-1"
    class="button_focus_helper"
  />
  <slot/>
  </button> </template>
```

1.  现在，让我们把它弄得漂亮一点。在组件的`<style>`部分，我们需要为这个按钮创建所有的 CSS 规则。我们需要在`<style>`中添加`scoped`属性，以便 CSS 规则不会影响我们应用程序中的任何其他元素：

```js
<style scoped>
  .button {
  user-select: none;
  position: relative;
  outline: 0;
  border: 0;
  border-radius: 0.25rem;
  vertical-align: middle;
  cursor: pointer;
  padding: 4px 16px;
  font-size: 14px;
  line-height: 1.718em;
  text-decoration: none;
  color: inherit;
  background: transparent;
  transition: 0.3s cubic-bezier(0.25, 0.8, 0.5, 1);
  min-height: 2.572em;
  font-weight: 500;
  text-transform: uppercase;
  }
  .button:not(.isFlat){
  box-shadow: 0 1px 5px rgba(0, 0, 0, 0.2),
  0 2px 2px rgba(0, 0, 0, 0.14),
  0 3px 1px -2px rgba(0, 0, 0, 0.12);
  }    .button:not(.isFlat):focus:before,
 .button:not(.isFlat):active:before,
 .button:not(.isFlat):hover:before {
  content: '';
  position: absolute;
  top: 0;
  right: 0;
  bottom: 0;
  left: 0;
  border-radius: inherit;
  transition: 0.3s cubic-bezier(0.25, 0.8, 0.5, 1);
  }    .button:not(.isFlat):focus:before,
 .button:not(.isFlat):active:before,
 .button:not(.isFlat):hover:before {
  box-shadow: 0 3px 5px -1px rgba(0, 0, 0, 0.2),
  0 5px 8px rgba(0, 0, 0, 0.14),
  0 1px 14px rgba(0, 0, 0, 0.12);
  }    .button_focus_helper {
  position: absolute;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  pointer-events: none;
  border-radius: inherit;
  outline: 0;
  opacity: 0;
  transition: background-color 0.3s cubic-bezier(0.25, 0.8, 0.5, 1),
  opacity 0.4s cubic-bezier(0.25, 0.8, 0.5, 1);
  }    .button_focus_helper:after, .button_focus_helper:before {
  content: '';
  position: absolute;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  opacity: 0;
  border-radius: inherit;
  transition: background-color 0.3s cubic-bezier(0.25, 0.8, 0.5, 1),
  opacity 0.6s cubic-bezier(0.25, 0.8, 0.5, 1);
  }    .button_focus_helper:before {
  background: #000;
  }    .button_focus_helper:after {
  background: #fff;
  }    .button:focus .button_focus_helper:before,
 .button:hover .button_focus_helper:before {
  opacity: .1;
  }    .button:focus .button_focus_helper:after,
 .button:hover .button_focus_helper:after {
  opacity: .6;
  }    .button:focus .button_focus_helper,
 .button:hover .button_focus_helper {
  opacity: 0.2;
  }    .round {
  border-radius: 50%;
  } </style>
```

1.  在`App.vue`文件中，我们需要导入我们的组件才能看到它：

```js
<template>
  <div id="app">
    <MaterialCardBox
      header="Material Card Header"
      sub-header="Card Sub Header"
      show-media
      show-actions
      img-src="https://picsum.photos/300/200"
      :main-text="`
        The path of the righteous man is beset on all sides by the 
          iniquities of the selfish and the tyranny of evil men.`"
      >
      <template v-slot:action>
        <MaterialButton
          background-color="#027be3"
          text-color="#fff"
        >
          Action 1
        </MaterialButton>
        <MaterialButton
          background-color="#26a69a"
          text-color="#fff"
          is-flat
        >
          Action 2
        </MaterialButton>
      </template>
    </MaterialCardBox>
  </div>
</template>

<script>
import MaterialCardBox from './components/MaterialCardBox.vue';
import MaterialButton from './components/MaterialButton.vue';

export default {
  name: 'App',
  components: {
    MaterialButton,
    MaterialCardBox,
  },
};
</script>
<style>
  body {
    font-size: 14px;
  }
</style>
```

1.  要运行服务器并查看您的组件，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
npm run serve
```

记得总是执行命令`npm run lint --fix`，以自动修复任何代码 lint 错误。

这是渲染和运行的组件：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/bd-vue-app-gql/img/8c3b16c4-2334-48eb-855a-dbbf1b9a534a.png)

## 它是如何工作的...

函数组件就像渲染函数一样简单。它们没有任何类型的数据、函数或对外部世界的访问。

它们最初是作为 JavaScript 对象`render()`函数在 Vue 中引入的；后来，它们被添加到`vue-template-compiler`中，用于 Vue 单文件应用程序。

功能性组件通过接收两个参数`createElement`和`context`来工作。正如我们在单文件中看到的，我们只能访问元素，因为它们不在 JavaScript 对象的`this`属性中。这是因为当上下文传递给渲染函数时，没有`this`属性。

功能性组件在 Vue 上提供了最快的渲染速度，因为它不依赖于组件的生命周期来检查渲染；它只在数据改变时渲染。

## 另请参阅

+   您可以在[`www.npmjs.com/package/is-color`](https://www.npmjs.com/package/is-color)找到有关`is-color`模块的更多信息。

# 访问您的子组件的数据

通常，父子通信是通过事件或 props 来完成的。但有时，您需要访问存在于子函数或父函数中的数据、函数或计算属性。

Vue 为我们提供了双向交互的方式，从而打开了使用 props 和事件监听器等通信和事件的大门。

还有另一种访问组件之间数据的方法：直接访问。这可以通过在单文件组件中使用模板中的特殊属性来完成，或者通过直接调用 JavaScript 中的对象来完成。有些人认为这种方法有点懒惰，但有时确实没有其他方法可以做到这一点。

## 准备工作

这个食谱的先决条件是 Node.js 12+。

这个食谱所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

为了完成这个食谱，我们将使用我们的 Vue 项目和 Vue CLI，就像在*创建功能性组件*的食谱中一样。

## 如何做...

我们将把这个食谱分成四个部分。前三部分将涵盖新组件的创建-`StarRatingInput`、`StarRatingDisplay`和`StarRating`，而最后一部分将涵盖数据和函数访问的直接父子操作。

### 创建星级评分输入

在这个食谱中，我们将创建一个基于五星评级系统的星级评分输入。

按照以下步骤创建自定义星级评分输入：

1.  在`src/components`文件夹中创建一个名为`StarRatingInput.vue`的新文件。

1.  在组件的 `<script>` 部分中，在 `props` 属性中创建一个 `maxRating` 属性，它是一个数字，非必需，并具有默认值 `5`。在 `data` 属性中，我们需要创建我们的 `rating` 属性，其默认值为 `0`。在 `methods` 属性中，我们需要创建三种方法：`updateRating`、`emitFinalVoting` 和 `getStarName`。`updateRating` 方法将评分保存到数据中，`emitFinalVoting` 将调用 `updateRating` 并通过 `final-vote` 事件将评分传递给父组件，`getStarName` 将接收一个值并返回星星的图标名称：

```js
<script>
  export default {
  name: 'StarRatingInput',
  props: {
  maxRating: {
  type: Number,
  required: false,
  default: 5,
  },
  },
  data: () => ({
  rating: 0,
  }),
  methods: {
  updateRating(value) {
  this.rating = value;
  },
  emitFinalVote(value) {
  this.updateRating(value);
  this.$emit('final-vote', this.rating);
  },
  getStarName(rate) {
  if (rate <= this.rating) {
      return 'star';
  }
  if (Math.fround((rate - this.rating)) < 1) {
      return 'star_half';
  }
  return 'star_border';
  },
  },
  }; </script>
```

1.  在组件的 `<template>` 部分中，我们需要创建一个 `<slot>` 组件，以便我们可以在星级评分之前放置文本。我们将根据通过 `props` 属性接收到的 `maxRating` 值创建一个动态星星列表。创建的每个星星都将在 `mouseenter`、`focus` 和 `click` 事件中附加一个监听器。当触发 `mouseenter` 和 `focus` 时，将调用 `updateRating` 方法，而 `click` 将调用 `emitFinalVote`：

```js
<template>
  <div class="starRating">
  <span class="rateThis">
  <slot/>
  </span>
  <ul>
  <li
  v-for="rate in maxRating"
  :key="rate"
  @mouseenter="updateRating(rate)"
  @click="emitFinalVote(rate)"
  @focus="updateRating(rate)"
  >
  <i class="material-icons">
      {{ getStarName(rate) }}
  </i>
  </li>
  </ul>
  </div> </template>
```

1.  我们需要将 Material Design 图标导入到我们的应用程序中。在 `styles` 文件夹中创建一个名为 `materialIcons.css` 的新样式文件，并添加 `font-family` 的 CSS 规则：

```js
@font-face {
  font-family: 'Material Icons';
  font-style: normal;
  font-weight: 400;
  src: url(https://fonts.gstatic.com/s/materialicons/v48/flUhRq6tzZclQEJ- Vdg-IuiaDsNcIhQ8tQ.woff2) format('woff2');
}

.material-icons {
  font-family: 'Material Icons' !important;
  font-weight: normal;
  font-style: normal;
  font-size: 24px;
  line-height: 1;
  letter-spacing: normal;
  text-transform: none;
  display: inline-block;
  white-space: nowrap;
  word-wrap: normal;
  direction: ltr;
  -webkit-font-feature-settings: 'liga';
  -webkit-font-smoothing: antialiased;
}
```

1.  打开 `main.js` 文件并将创建的样式表导入其中。`css-loader` webpack 将处理 JavaScript 文件中导入的 `.css` 文件。这将有助于开发，因为您无需在其他地方重新导入文件：

```js
import { createApp } from 'vue'; import App from './App.vue'; import './style/materialIcons.css';   createApp(App).mount('#app'); 
```

1.  为了给我们的组件设置样式，我们将在 `src/style` 文件夹中创建一个名为 `starRating.css` 的通用样式文件。在那里，我们将添加在 `StarRatingDisplay` 和 `StarRatingInput` 组件之间共享的通用样式：

```js
.starRating {
  user-select: none;
  display: flex;
  flex-direction: row; }   .starRating * {
  line-height: 0.9rem; }   .starRating .material-icons {
  font-size: .9rem !important;
  color: orange; }   ul {
  display: inline-block;
  padding: 0;
  margin: 0; }   ul > li {
  list-style: none;
  float: left; }
```

1.  在组件的 `<style>` 部分中，我们需要创建所有的 CSS 规则。然后，在位于 `src/components` 文件夹中的 `StarRatingInput.vue` 组件文件中，我们需要向 `<style>` 添加 `scoped` 属性，以便不影响应用程序中的任何其他元素的 CSS 规则。在这里，我们将导入我们创建的通用样式并添加新的输入样式：

```js
<style scoped>
  @import '../style/starRating.css';    .starRating {
  justify-content: space-between;
  }    .starRating * {
  line-height: 1.7rem;
  }    .starRating .material-icons {
  font-size: 1.6rem !important;
  }    .rateThis {
  display: inline-block;
  color: rgba(0, 0, 0, .65);
  font-size: 1rem;
  } </style>
```

1.  运行服务器并查看您的组件，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> npm run serve
```

记住始终执行命令 `npm run lint --fix`，以自动修复任何代码 lint 错误。

这是渲染和运行的组件：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/bd-vue-app-gql/img/70f63b67-42a3-4f42-bb6c-5372703ab62d.png)

### 创建 StarRatingDisplay 组件

现在我们有了输入，我们需要一种方法来向用户显示所选的选择。按照以下步骤创建`StarRatingDisplay`组件：

1.  在`src/components`文件夹中创建一个名为`StarRatingDisplay.vue`的新组件。

1.  在组件的`<script>`部分，在`props`属性中，我们需要创建三个新属性：`maxRating`，`rating`和`votes`。它们三个都将是数字，非必需的，并具有默认值。在`methods`属性中，我们需要创建一个名为`getStarName`的新方法，该方法将接收一个值并返回星星的图标名称：

```js
<script>
  export default {
  name: 'StarRatingDisplay',
  props: {
  maxRating: {
  type: Number,
  required: false,
  default: 5,
  },
  rating: {
  type: Number,
  required: false,
  default: 0,
  },
  votes: {
  type: Number,
  required: false,
  default: 0,
  },
  },
  methods: {
  getStarName(rate) {
  if (rate <= this.rating) {
      return 'star';
  }
  if (Math.fround((rate - this.rating)) < 1) {
      return 'star_half';
  }
  return 'star_border';
  },
  },
  }; </script>
```

1.  在`<template>`中，我们需要根据通过`props`属性接收到的`maxRating`值创建一个动态星星列表。在列表之后，我们需要显示我们收到的投票，如果我们收到更多的投票，我们也会显示它们：

```js
<template>
  <div class="starRating">
  <ul>
  <li
  v-for="rate in maxRating"
  :key="rate"
  >
  <i class="material-icons">
      {{ getStarName(rate) }}
  </i>
  </li>
  </ul>
  <span class="rating">
  {{ rating }}
  </span>
  <span
  v-if="votes"
  class="votes"
  >
  ({{ votes }})
  </span>
  </div> </template>
```

1.  在组件的`<style>`部分，我们需要创建所有的 CSS 规则。我们需要向`<style>`添加`scoped`属性，以便没有任何 CSS 规则影响我们应用程序中的任何其他元素。在这里，我们将导入我们创建的通用样式，并添加新的样式以供显示：

```js
<style scoped>
  @import '../style/starRating.css';    .rating, .votes {
  display: inline-block;
  color: rgba(0, 0, 0, .65);
  font-size: .75rem;
  margin-left: .4rem;
  } </style>
```

1.  要运行服务器并查看您的组件，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> npm run serve
```

请记住始终执行命令`npm run lint --fix`，以自动修复任何代码 lint 错误。

这是渲染和运行的组件：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/bd-vue-app-gql/img/96ac3614-2ef5-41ae-8b26-2dc7f6d30f61.png)

### 创建 StarRating 组件

现在我们已经创建了输入和显示，我们需要将它们合并到一个单独的组件中。这个组件将是我们在应用程序中使用的最终组件。

按照以下步骤创建最终的`StarRating`组件：

1.  在`src/components`文件夹中创建一个名为`StarRating.vue`的新文件。

1.  在组件的`<script>`部分，我们需要导入`StarRatingDisplay`和`StarRatingInput`组件。在`props`属性中，我们需要创建三个新属性：`maxRating`，`rating`和`votes`。所有这三个属性都将是数字，非必需的，并具有默认值。在`data`属性中，我们需要创建我们的`rating`属性，其默认值为`0`，以及一个名为`voted`的属性，其默认值为`false`。在`methods`属性中，我们需要添加一个名为`vote`的新方法，它将接收`rank`作为参数。它将把`rating`定义为接收到的值，并将`voted`组件的内部变量定义为`true`：

```js
<script>
  import StarRatingInput from './StarRatingInput.vue';
  import StarRatingDisplay from './StarRatingDisplay.vue';    export default {
  name: 'StarRating',
  components: { StarRatingDisplay, StarRatingInput },
  props: {
  maxRating: {
  type: Number,
  required: false,
  default: 5,
  },
  rating: {
  type: Number,
  required: false,
  default: 0,
  },
  votes: {
  type: Number,
  required: false,
  default: 0,
  },
  },
  data: () => ({
  rank: 0,
  voted: false,
  }),
  methods: {
  vote(rank) {
  this.rank = rank;
  this.voted = true;
  },
  },
  }; </script>
```

1.  对于`<template>`部分，我们将在这里放置两个组件，从而显示评分的输入：

```js
<template>
  <div>
  <StarRatingInput
  v-if="!voted"
  :max-rating="maxRating"
  @final-vote="vote"
  >
  Rate this Place
  </StarRatingInput>
  <StarRatingDisplay
  v-else
  :max-rating="maxRating"
  :rating="rating || rank"
  :votes="votes"
  />
  </div> </template>
```

### 子组件中的数据操作

现在我们所有的组件都准备好了，我们需要将它们添加到我们的应用程序中。基础应用程序将访问子组件，并将评分设置为 5 星。

按照以下步骤来理解和操作子组件中的数据：

1.  在`App.vue`文件中，在组件的`<template>`部分，删除`MaterialCardBox`组件的`main-text`属性，并将其设置为组件的默认插槽。

1.  在放置的文本之前，我们将添加`StarRating`组件。我们将为其添加一个`ref`属性。这个属性将告诉 Vue 将这个组件直接链接到组件的`this`对象中的一个特殊属性。在操作按钮中，我们将为点击事件添加监听器 - 一个用于`resetVote`，另一个用于`forceVote`：

```js
<template>
  <div id="app">
  <MaterialCardBox
  header="Material Card Header"
  sub-header="Card Sub Header"
  show-media
  show-actions
  img-src="https://picsum.photos/300/200"
  >
  <p>
  <StarRating
      ref="starRating"
  />
  </p>
  <p>
  The path of the righteous man is beset on all sides by the
  iniquities of the selfish and the tyranny of evil men.
  </p>
  <template v-slot:action>
  <MaterialButton
      background-color="#027be3"
      text-color="#fff"
      @click="resetVote"
  >
      Reset
  </MaterialButton>
  <MaterialButton
      background-color="#26a69a"
      text-color="#fff"
      is-flat
      @click="forceVote"
  >
      Rate 5 Stars
  </MaterialButton>
  </template>
  </MaterialCardBox>
  </div> </template>
```

1.  在组件的`<script>`部分，我们将创建一个`methods`属性，并添加两个新方法：`resetVote`和`forceVote`。这些方法将访问`StarRating`组件并重置数据或将数据设置为 5 星评分：

```js
<script>
  import MaterialCardBox from './components/MaterialCardBox.vue';
  import MaterialButton from './components/MaterialButton.vue';
  import StarRating from './components/StarRating.vue';    export default {
  name: 'App',
  components: {
  StarRating,
  MaterialButton,
  MaterialCardBox,
  },
 methods: {
    resetVote() {
      this.$refs.starRating.vote(0);
      this.$refs.starRating.voted = false;
    },
    forceVote() {
      this.$refs.starRating.vote(5);
    },
  }, 
```

## 工作原理...

当`ref`属性添加到组件时，Vue 会将对被引用元素的链接添加到 JavaScript 的`this`属性对象内的`$refs`属性中。从那里，您可以完全访问组件。

这种方法通常用于操作 HTML DOM 元素，而无需调用文档查询选择器函数。

然而，该属性的主要功能是直接访问 Vue 组件，使您能够执行函数并查看组件的计算属性、变量和已更改的变量 - 这就像从外部完全访问组件一样。

## 还有更多...

与父组件可以访问子组件的方式相同，子组件可以通过在`this`对象上调用`$parent`来访问父组件。事件可以通过调用`$root`属性来访问 Vue 应用程序的根元素。

## 另请参阅

您可以在[`v3.vuejs.org/guide/migration/custom-directives.html#edge-case-accessing-the-component-instance`](https://v3.vuejs.org/guide/migration/custom-directives.html#edge-case-accessing-the-component-instance)找到有关父子通信的更多信息。

# 创建一个动态注入的组件

有些情况下，您的组件可以根据您收到的变量的类型或您拥有的数据类型来定义；然后，您需要在不需要设置大量 Vue `v-if`、`v-else-if`和`v-else`指令的情况下即时更改组件。

在这些情况下，最好的做法是使用动态组件，当计算属性或函数可以定义要呈现的组件时，并且决定是实时进行的。

如果有两种响应，这些决定有时可能很容易做出，但如果有一个长的开关情况，那么它们可能会更复杂，其中您可能有一个需要使用的长列表可能组件。

## 准备就绪

此配方的先决条件是 Node.js 12+。

此配方所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

为了完成这个配方，我们将使用我们的 Vue 项目和 Vue CLI，就像我们在*访问你的子组件数据*配方中所做的那样。

## 如何做...

按照以下步骤创建一个动态注入的组件：

1.  打开`StarRating.vue`组件。

1.  在组件的`<script>`部分，我们需要创建一个带有名为`starComponent`的新计算值的`computed`属性。此值将检查用户是否已投票。如果他们没有，它将返回`StarRatingInput`组件；否则，它将返回`StarRatingDisplay`组件：

```js
<script>
  import StarRatingInput from './StarRatingInput.vue';
  import StarRatingDisplay from './StarRatingDisplay.vue';    export default {
  name: 'StarRating',
  components: { StarRatingDisplay, StarRatingInput },
  props: {
  maxRating: {
  type: Number,
  required: false,
  default: 5,
  },
  rating: {
  type: Number,
  required: false,
  default: 0,
  },
  votes: {
  type: Number,
  required: false,
  default: 0,
  },
  },
  data: () => ({
  rank: 0,
  voted: false,
  }),
  computed: {
  starComponent() {
  if (!this.voted) return StarRatingInput;
  return StarRatingDisplay;
  },
  },
  methods: {
  vote(rank) {
  this.rank = rank;
  this.voted = true;
  },
  },
  }; </script>
```

1.  在组件的`<template>`部分，我们将删除现有组件，并用一个名为`<component>`的特殊组件替换它们。这个特殊组件有一个命名属性，您可以指向任何返回有效的 Vue 组件的地方。在我们的例子中，我们将指向计算属性`starComponent`。我们将把由这两个其他组件定义的所有绑定属性放在这个新组件中，包括放在`<slot>`中的文本：

```js
<template>
  <component
    :is="starComponent"
    :max-rating="maxRating"
    :rating="rating || rank"
    :votes="votes"
    @final-vote="vote"
  >
    Rate this Place
  </component>
</template>
```

## 它是如何工作的...

使用 Vue 特殊的`<component>`组件，我们声明了根据计算属性设置的规则应该渲染什么组件。

作为一个通用组件，您总是需要保证每个可以渲染的组件都会有一切。这样做的最佳方式是使用`v-bind`指令与需要定义的 props 和规则，但也可以直接在组件上定义，因为它将作为一个 prop 传递下来。

## 另请参阅

您可以在[`v3.vuejs.org/guide/component-dynamic-async.html#dynamic-async-components`](https://v3.vuejs.org/guide/component-dynamic-async.html#dynamic-async-components)找到有关动态组件的更多信息。

# 创建一个依赖注入组件

直接从子组件或父组件访问数据而不知道它们是否存在可能非常危险。

在 Vue 中，可以使您的组件行为像一个接口，并且具有一个在开发过程中不会改变的常见和抽象函数。依赖注入的过程是开发世界中的一个常见范例，并且在 Vue 中也已经实现。

使用 Vue 的内部依赖注入有一些优缺点，但这总是一种确保您的子组件在开发时知道从父组件可以期望什么的好方法。

## 准备工作

这个配方的先决条件是 Node.js 12+。

这个配方所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

要完成这个配方，我们将使用我们的 Vue 项目和 Vue CLI，就像在*创建一个动态注入组件*配方中所做的那样。

## 如何做到...

按照以下步骤创建一个依赖注入组件：

1.  打开`StarRating.vue`组件。

1.  在组件的`<script>`部分，添加一个名为`provide`的新属性。在我们的情况下，我们将只是添加一个键值来检查组件是否是特定组件的子组件。在属性中创建一个包含`starRating`键和`true`值的对象：

```js
<script> import StarRatingInput from './StarRatingInput.vue'; import StarRatingDisplay from './StarRatingDisplay.vue';   export default {
  name: 'StarRating',
  components: { StarRatingDisplay, StarRatingInput },
  provide: {
  starRating: true,
  },
  props: {
  maxRating: {
    type: Number,
    required: false,
    default: 5,
  },
  rating: {
    type: Number,
    required: false,
    default: 0,
  },
  votes: {
    type: Number,
    required: false,
    default: 0,
  },
  },
  data: () => ({
  rank: 0,
  voted: false,
  }),
  computed: {
  starComponent() {
    if (!this.voted) return StarRatingInput;
    return StarRatingDisplay;
  },
  },
  methods: {
  vote(rank) {
    this.rank = rank;
    this.voted = true;
  },
  }, }; </script>
```

1.  打开`StarRatingDisplay.vue`文件。

1.  在组件的`<script>`部分，我们将添加一个名为`inject`的新属性。这个属性将接收一个名为`starRating`的键的对象，值将是一个包含`default()`函数的对象。

如果这个组件不是`StarRating`组件的子组件，这个函数将记录一个错误：

```js
<script> export default {
  name: 'StarRatingDisplay',
  props: {
  maxRating: {
    type: Number,
    required: false,
    default: 5,
  },
  rating: {
    type: Number,
    required: false,
    default: 0,
  },
  votes: {
    type: Number,
    required: false,
    default: 0,
  },
  },
  inject: {
  starRating: {
    default() {
      console.error('StarRatingDisplay need to be a child of 
           StarRating');
    },
  },
  },
  methods: {
  getStarName(rate) {
    if (rate <= this.rating) {
      return 'star';
    }
    if (Math.fround((rate - this.rating)) < 1) {
      return 'star_half';
    }
    return 'star_border';
  },
  }, }; </script>
```

1.  打开`StarRatingInput.vue`文件。

1.  在组件的`<script>`部分，我们将添加一个名为`inject`的新属性。这个属性将接收一个名为`starRating`的键的对象，值将是一个包含`default()`函数的对象。如果这个组件不是`StarRating`组件的子组件，这个函数将记录一个错误：

```js
<script> export default {
  name: 'StartRatingInput',
  props: {
  maxRating: {
    type: Number,
    required: false,
    default: 5,
  },
  },
  inject: {
  starRating: {
    default() {
      console.error('StarRatingInput need to be a child of 
          StartRating');
    },
  },
  },
  data: () => ({
  rating: 0,
  }),
  methods: {
  updateRating(value) {
    this.rating = value;
  },
  emitFinalVote(value) {
    this.updateRating(value);
    this.$emit('final-vote', this.rating);
  },
  getStarName(rate) {
    if (rate <= this.rating) {
      return 'star';
    }
    if (Math.fround((rate - this.rating)) < 1) {
      return 'star_half';
    }
    return 'star_border';
  },
  }, }; </script>
```

## 它是如何工作的...

在运行时，Vue 将检查`StarRatingDisplay`和`StarRatingInput`组件中的`starRating`的注入属性，如果父组件没有提供这个值，它将在控制台中记录一个错误。

使用组件注入通常用于提供和维护绑定组件之间的公共接口，比如菜单和项目。项目可能需要一些存储在菜单中的函数或数据，或者我们可能需要检查它是否是菜单的子组件。

依赖注入的主要缺点是共享元素上不再具有响应性。因此，它主要用于共享函数或检查组件链接。

## 另请参阅

您可以在[`v3.vuejs.org/guide/component-provide-inject.html#provide-inject`](https://v3.vuejs.org/guide/component-provide-inject.html#provide-inject)找到有关组件依赖注入的更多信息。

# 创建一个组件 mixin

有时你会发现自己一遍又一遍地重写相同的代码。然而，有一种方法可以防止这种情况，并让自己更加高效。

为此，您可以使用所谓的`mixin`，这是 Vue 中的一个特殊代码导入，它将外部代码部分连接到当前组件。

## 准备工作

这个食谱的先决条件是 Node.js 12+。

这个食谱所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

为了完成这个示例，我们将使用我们的 Vue 项目和 Vue CLI，就像我们在*创建一个依赖注入组件*示例中所做的那样。

## 如何做...

按照以下步骤创建一个组件混合：

1.  打开`StarRating.vue`组件。

1.  在`<script>`部分，我们需要将`props`属性提取到一个名为`starRatingDisplay.js`的新文件中，我们需要在`mixins`文件夹中创建这个新文件。这个新文件将是我们的第一个`mixin`，看起来会像这样：

```js
export default {
  props: {
  maxRating: {
  type: Number,
  required: false,
  default: 5,
  },
  rating: {
  type: Number,
  required: false,
  default: 0,
  },
  votes: {
  type: Number,
  required: false,
  default: 0,
  },
  }, };
```

1.  回到`StarRating.vue`组件，我们需要导入这个新创建的文件，并将其添加到一个名为`mixin`的新属性中。

```js
<script>
  import StarRatingInput from './StarRatingInput.vue';
  import StarRatingDisplay from './StarRatingDisplay.vue';
  import StarRatingDisplayMixin from '../mixins/starRatingDisplay';    export default {
  name: 'StarRating',
  components: { StarRatingDisplay, StarRatingInput },
  mixins: [StarRatingDisplayMixin],
  provide: {
  starRating: true,
  },
  data: () => ({
  rank: 0,
  voted: false,
  }),
  computed: {
  starComponent() {
  if (!this.voted) return StarRatingInput;
  return StarRatingDisplay;
  },
  },
  methods: {
  vote(rank) {
  this.rank = rank;
  this.voted = true;
  },
  },
  }; </script>
```

1.  现在，我们将打开`StarRatingDisplay.vue`文件。

1.  在`<script>`部分，我们将`inject`属性提取到一个名为`starRatingChild.js`的新文件中，该文件将被创建在`mixins`文件夹中。这将是我们的`inject`属性的`mixin`：

```js
export default {
  inject: {
    starRating: {
      default() {
        console.error('StarRatingDisplay need to be a child of 
          StarRating');
      },
    },
  },
};
```

1.  回到`StarRatingDisplay.vue`文件，在`<script>`部分，我们将`methods`属性提取到一个名为`starRatingName.js`的新文件中，该文件将被创建在`mixins`文件夹中。这将是我们的`getStarName`方法的`mixin`：

```js
export default {
  methods: {
    getStarName(rate) {
      if (rate <= this.rating) {
        return 'star';
      }
      if (Math.fround((rate - this.rating)) < 1) {
        return 'star_half';
      }
      return 'star_border';
    },
  },
};
```

1.  回到`StarRatingDisplay.vue`文件，我们需要导入这些新创建的文件，并将它们添加到一个名为`mixin`的新属性中：

```js
<script> import StarRatingDisplayMixin from '../mixins/starRatingDisplay'; import StarRatingNameMixin from '../mixins/starRatingName'; import StarRatingChildMixin from '../mixins/starRatingChild';   export default {
  name: 'StarRatingDisplay',
  mixins: [
  StarRatingDisplayMixin,
  StarRatingNameMixin,
  StarRatingChildMixin,
  ], }; </script>
```

1.  打开`StarRatingInput.vue`文件。

1.  在`<script>`部分，删除`inject`属性并将`props`属性提取到一个名为`starRatingBase.js`的新文件中，该文件将被创建在`mixins`文件夹中。这将是我们的`props`属性的`mixin`：

```js
export default {
  props: {
    maxRating: {
      type: Number,
      required: false,
      default: 5,
    },
    rating: {
      type: Number,
      required: false,
      default: 0,
    },
  },
};
```

1.  回到`StarRatingInput.vue`文件，我们需要将`rating`数据属性重命名为`rank`，并且在`getStarName`方法中，我们需要添加一个新的常量，它将接收`rating`属性或`rank`数据。最后，我们需要导入`starRatingChildMixin`和`starRatingBaseMixin`：

```js
<script>
  import StarRatingBaseMixin from '../mixins/starRatingBase';
  import StarRatingChildMixin from '../mixins/starRatingChild';    export default {
  name: 'StarRatingInput',
  mixins: [
  StarRatingBaseMixin,
  StarRatingChildMixin,
  ],
  data: () => ({
  rank: 0,
  }),
  methods: {
  updateRating(value) {
  this.rank = value;
  },
  emitFinalVote(value) {
  this.updateRating(value);
  this.$emit('final-vote', this.rank);
  },
  getStarName(rate) {
  const rating = (this.rating || this.rank);
  if (rate <= rating) {
      return 'star';
  }
  if (Math.fround((rate - rating)) < 1) {
      return 'star_half';
  }
  return 'star_border';
  },
  },
  }; </script>
```

## 工作原理...

混合将对象合并在一起，但请确保不要用导入的对象替换组件中已经存在的属性。

`mixins`属性的顺序也很重要，因为它们将被作为`for`循环进行检查和导入，因此最后一个`mixin`不会改变任何祖先的属性。

在这里，我们将代码中的许多重复部分拆分成了四个不同的小的 JavaScript 文件，这样更容易维护并提高了生产力，而无需重写代码。

## 另请参阅

您可以在[`v3.vuejs.org/guide/mixins.html#mixins`](https://v3.vuejs.org/guide/mixins.html#mixins)找到有关混合的更多信息。

# 延迟加载您的组件

`webpack`和 Vue 天生就是一对。当将`webpack`作为 Vue 项目的打包工具时，可以使组件在需要时异步加载。这通常被称为延迟加载。

## 准备工作

此教程的先决条件是 Node.js 12+。

此教程所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

要完成此教程，我们将使用我们的 Vue 项目和 Vue CLI，就像在*创建组件混合*教程中所做的那样。

## 如何做...

按照以下步骤使用延迟加载技术导入您的组件：

1.  打开`App.vue`文件。

1.  在组件的`<script>`部分，从 Vue 中导入`defineAsyncComponent` API，并将`lazyLoad`组件函数作为`defineAsyncComponent`函数的参数传递：

```js
<script>
import { defineAsyncComponent } from 'vue';
import StarRating from './components/StarRating.vue';
export default {
  name: 'App',
  components: {
    StarRating,
    MaterialButton: defineAsyncComponent(() => import('./components/MaterialButton.vue')),
    MaterialCardBox: defineAsyncComponent(() => import('./components/MaterialCardBox.vue')),
  },
  methods: {
    resetVote() {
      this.$refs.starRating.vote(0);
      this.$refs.starRating.voted = false;
    },
    forceVote() {
      this.$refs.starRating.vote(5);
    },
  },
};
</script>

<style>
  body {
    font-size: 14px;
  }
</style>
```

## 它是如何工作的...

Vue 现在使用一个名为`defineAsyncComponent`的新 API 来将组件标识为异步组件，并将另一个返回`import()`方法的函数作为参数传递。

当我们为每个组件声明一个返回`import()`函数的函数时，`webpack`知道这个导入函数将进行代码拆分，并将使组件成为捆绑包中的一个新文件。

## 另请参阅

+   您可以在[`v3.vuejs.org/guide/component-dynamic-async.html#dynamic-async-components`](https://v3.vuejs.org/guide/component-dynamic-async.html#dynamic-async-components)找到有关异步组件的更多信息。

+   您可以在[`github.com/tc39/proposal-dynamic-import`](https://github.com/tc39/proposal-dynamic-import)找到有关 TC39 动态导入的更多信息。
