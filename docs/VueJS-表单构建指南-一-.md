# VueJS 表单构建指南（一）

> 原文：[`zh.annas-archive.org/md5/89D4502ECBF31F487E1AF228404A6AC0`](https://zh.annas-archive.org/md5/89D4502ECBF31F487E1AF228404A6AC0)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

Vue.js 是世界领先和增长最快的前端开发框架之一。其平缓的学习曲线和充满活力和乐于助人的社区使其成为许多新开发人员寻求利用前端框架的力量的不二选择。此外，其灵活性和强大性使其成为高级开发人员和公司选择将其作为强大、动态和精简应用程序和网站的主要工具。

在*使用 Vue.js 构建表单*中，我们将探索前端开发的一个特定部分——表单。我们将一起旅行，从创建最基本的表单，一直到理解完全动态、基于模式的表单是如何工作的。

# 这本书是为谁准备的

*使用 Vue.js 构建表单*旨在面向具有 Vue.js 框架基本理解的前端开发人员，他们想要了解如何更好地创建强大且可重用的表单。

# 本书涵盖的内容

第一章，“设置演示项目”，将指导您设置项目的基础，我们将在整本书中构建该项目。建议您按照章节的顺序学习本书，因为它们是基于前面章节学习的概念构建的。但是，如果您想要跳过，每章的完成代码将在每章的开头提供。

第二章，“最简单的形式中的表单”，展示了构建基本网络表单的基础知识，以及将输入连接到应用程序状态的过程。您还将了解提交表单的基础知识，并使用 Axios 库进行异步调用后端。

第三章，“创建可重用的表单组件”，将教您如何将表单分解为可以在整个应用程序中重复使用的组件。您将了解`v-model`指令的工作原理，以及主应用程序和表单如何利用这些组件。

第四章，“使用 v-mask 进行输入掩码”，涉及使用`v-mask`库来实现输入掩码以改善用户体验。您将学习如何实现第三方插件，以及如何将它们合并到自定义组件中。

第五章，*使用 Vuelidate 进行输入验证*，将带你了解如何向项目中添加 Vuelidate——一个强大的表单验证库，创建验证规则并将其应用到你的表单，以及如何将其整合到你的自定义组件中。

第六章，*使用 Vuex 转移到全局状态*，通过利用 Vuex 的强大功能，将当前应用程序的本地状态转移到全局状态。我们将把 Vuelidate 和我们的自定义组件整合在一起。

第七章，*创建基于模式的表单*，将所有先前的概念整合在一起，带你了解并创建一个渲染器组件，使你的应用程序完全基于模式驱动。它将对模拟 API 提供的 API 更改做出反应，并解释如何生成一个完全构建的表单，包括向模拟后端提交数据的方法。

# 为了充分利用这本书

为了让你更容易地跟随这本书，我必须对你已有的一些知识做一些假设。以下是你需要的基本要求清单，以便充分利用这本书：

+   你之前使用过 HTML、CSS 和 JavaScript，并且能够轻松创建基本的 Web 应用程序。

+   你熟悉`console.log`语句和在浏览器中调试 Web 应用程序的一般方法，比如 Chrome。

+   基本的终端命令知识。你至少应该知道如何使用`cd`命令导航文件夹。

+   你了解 Vue 的基本概念，比如状态、响应性、插值、计算属性和方法。确保查看官方指南的基本部分以供参考：[`vuejs.org/v2/guide/`](https://vuejs.org/v2/guide/)。

+   你有一台电脑和互联网连接，可以下载和安装所需的库和项目文件。

在本书的第一章中，我们将介绍如何按照简单的步骤列表设置你的项目。

# 下载示例代码文件

您可以从[www.packt.com](http://www.packt.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，可以访问[www.packtpub.com/support](https://www.packtpub.com/support)注册，直接将文件发送到您的邮箱。

您可以按照以下步骤下载代码文件：

1.  在[www.packt.com](http://www.packt.com)上登录或注册。

1.  选择“支持”标签页。

1.  点击“代码下载”。

1.  在搜索框中输入书名，并按照屏幕上的说明操作。

下载文件后，请确保使用最新版本的以下软件解压或提取文件夹：

+   WinRAR/7-Zip for Windows

+   Zipeg/iZip/UnRarX for Mac

+   7-Zip/PeaZip for Linux

本书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Building-Forms-with-Vue.js`](https://github.com/PacktPublishing/Building-Forms-with-Vue.js)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还有来自丰富书籍和视频目录的其他代码包，可在**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**上找到。快去看看吧！

# 下载彩色图像

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图像。您可以在这里下载：[`static.packt-cdn.com/downloads/9781839213335_ColorImages.pdf`](https://static.packt-cdn.com/downloads/9781839213335_ColorImages.pdf)。

# 代码演示

访问以下链接查看代码运行的视频：

[`bit.ly/2puBGN1`](http://bit.ly/2puBGN1)

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。这是一个例子：“让我们开始安装`v-mask`库。”

代码块设置如下：

```js
<input 
 type="text"
 v-model="form.telephone"
 v-mask="'(###)###-####'"
>
```

任何命令行输入或输出都将按照以下方式书写：

```js
> npm install v-mask
```

**粗体**：表示新术语、重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会以这种方式出现在文本中。这是一个例子：“返回到第一个标签页，响应和正文。”

警告或重要提示会以这种方式出现。提示和技巧会以这种方式出现。


# 第一章：设置演示项目

每一个伟大的应用程序部署都始于一行代码，而在我们面前还有很长的路要走，我们应该从一开始就开始。

在本书中，我们将使用 Vue CLI 3 来设置我们的项目结构。Vue CLI 是一个令人惊叹的工具，可以快速搭建 Vue 应用程序。Vue CLI 诞生于成为搭建应用程序的首选工具。尽管还有其他令人惊叹的解决方案，比如 Nuxt，但了解 Vue CLI 的基础知识将让您在大多数项目中上手。如果您以前没有使用过它，不用担心：我们将一起逐步深入设置。

在本章中，我们将涵盖以下主题：

+   将 Vue CLI 安装到我们的计算机上

+   创建我们的新项目

+   快速查看项目结构

# 技术要求

本章的要求如下：

+   您需要一台可以访问终端程序的计算机，例如苹果的终端或 Windows 的命令提示符。

+   Node 版本 8.9 或更高版本和**Node 包管理器**（**npm**）：本章将提供安装说明。

+   您将需要一个您喜欢的**集成开发环境**（**IDE**）。一个很棒的免费 IDE 可以在[`code.visualstudio.com/`](https://code.visualstudio.com/)找到

本章的代码文件可以在以下 GitHub 存储库中找到：

[`github.com/PacktPublishing/Building-Forms-with-Vue.js/tree/master/Chapter01`](https://github.com/PacktPublishing/Building-Forms-with-Vue.js/tree/master/Chapter01)。

观看以下视频，查看代码运行情况：

[`bit.ly/2OXLxpg`](http://bit.ly/2OXLxpg)

# 将 Vue CLI 安装到我们的计算机上

在撰写本文时，Vue CLI 要求使用 Node 版本 8.9 或更高版本（建议使用 8.11.0+），因此我们需要确保您首先在开发计算机上设置了这个。

要检查是否已安装，请执行以下步骤：

1.  打开一个终端（也称为命令行！）

1.  执行`node -v`命令

如果您得到一个带有版本标签的输出，那么您已经安装了它，可以跳过。

如果您还没有安装 Node，请在浏览器中转到以下链接：[nodejs.org](https://nodejs.org/en)。

您应该看到一个主屏幕和两个大绿色的下载按钮。我们将使用标有“Current”的按钮，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/bd-frm-vue/img/7bd0d0c7-f7d5-4923-92ab-fb56c1466a69.png)

因此，请继续点击按钮并按照您自己操作系统的安装说明进行安装。

安装完成后，请验证一切是否正常工作：

1.  打开您的终端

1.  执行`node -v`命令

您应该得到类似 v12.2.0 的输出，验证了 node 已经正确安装到您的系统中。

然而，要将 Vue CLI 实际安装到我们的系统中，我们仍然需要使用包管理器。

现在，当您安装 Node 时，实际上免费在系统上安装了`npm`的副本。您可以通过在终端中输入`npm -v`来验证这一点，和以前一样，您将得到一个版本号作为输出。

请注意，Vue CLI 要求 Node 版本在 8.9 或以上（推荐 8.11.0+），但请确保您在阅读本书时检查以下链接以获取确切的版本号：[vuejs.org/guide/installation.html](https://vuejs.org/v2/guide/installation.html)。

最后，现在是真正开始运行事情的时候了。再次打开您的终端，并运行以下命令：

```js
> npm install --global @vue/cli
```

终端将继续下载所有所需的文件到您的计算机，并在全局可访问的路径中设置它们，以便您可以在计算机的任何地方使用此 CLI 工具。很棒，对吧？

请注意此命令上的`--global`标志。这意味着您在计算机上全局安装此软件包。简而言之，这意味着您可以在文件系统的任何位置使用命令，而无需导航到特定文件夹。

供以后参考，您还可以使用`--global`的简写，即简单的`-g`。

再次，让我们通过在终端上运行`vue --version`来检查一切是否安装正确。您应该会得到 Vue CLI 的版本号。

现在我们已经设置好了 CLI，我们可以开始创建我们的新项目。让我们在下一节深入了解如何做到这一点。

# 创建我们的新项目

进入您选择的一个文件夹，该文件夹将保存您的项目文件。不用担心，我们不需要设置服务器、虚拟主机或任何类似的东西。Vue CLI 实际上会在我们每次运行项目脚本时为我们设置一个开发服务器，因此您可以在任何您喜欢的地方创建它。

您现在要运行的命令是`vue create <name>`，其中`<name>`是您的项目名称，也是将要创建的文件夹。

我们将通过运行以下命令来创建我们的新项目：

```js
> vue create vuetiful-forms
```

`vuetiful-forms` 部分的命令将命名项目文件夹。当然，你可以根据自己的需要自由命名。

运行此命令后，Vue CLI 将显示一个向导，让你配置项目的设置方式：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/bd-frm-vue/img/d89013d8-42cc-420b-a12a-5a9d88046923.png)

我们将选择手动选择功能，因为我们想要尝试并查看可以切换开关的选项。请注意，我们在这里做出的决定并不是最终的。任何东西都可以随后添加或移除，所以不用担心！

第一个屏幕向我们展示了可以选择的不同功能和包：

1.  选择 Babel 和 Lint/Formatter，这是默认的两个选项。在本书的后面，我们将手动向项目添加 Vuex。

1.  按下空格键选择任何选项，按下 *Enter* 键继续到下一个屏幕。

1.  在 linter/formatter 配置屏幕上，使用仅包含错误预防的 ESLint 配置。

1.  在下一个屏幕上，我们将选择在保存时进行代码检查。（如果你不喜欢自动代码检查，可以选择其他选项。）

1.  对于我们的配置，选择将其存储在专用配置文件中，以尽可能保持我们的 `package.json` 文件整洁。

1.  最后，如果你愿意，可以将此保存为未来项目的预设。

另外，请注意，根据你的选择，你可能会看到不同于我在这里解释的配置。

终端将再次开始工作，在幕后为你的新项目创建项目结构：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/bd-frm-vue/img/a5394fb3-b7b9-4152-9163-cc468befff20.png)

通过这个易于遵循的向导，你可以轻松地搭建所有项目，但是如果在此阶段没有选择特定选项，不用担心；Vue CLI 使得随后添加和移除插件变得非常容易！现在让我们快速看一下我们的项目。

# 项目结构的快速概览

打开你的新的 `vuetiful-forms` 文件夹在你喜欢的代码编辑器中。如果你还没有用于开发的集成开发环境，你可以从 [code.visualstudio.com](https://code.visualstudio.com) 免费获取一个非常好的。

你的项目结构将如下截图所示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/bd-frm-vue/img/438a6ef1-ed27-4151-87d0-5ebd85a69318.png)

以下是你可以在结构中找到的快速概述：

+   node_modules: 这里保存着你的依赖项——你可以使用 `npm` 安装或移除的代码包。

+   public：这个文件夹将保存`index.html`，当您导航到应用程序的 URL 时，您的 Web 服务器将加载它。Vue 会自动注入它所需的所有文件，因此您不需要担心这里发生的事情。

+   src：这是您将放置所有代码、组件、资产等的地方。

在您的项目根目录中，您将看到一个名为`.eslintrc.js`的配置文件，用于您的 ESLint 配置，`.gitignore`用于 Git，`package.json`和`package-lock.json`或`yarn.lock`文件用于包管理，以及根据您之前的选择而定的其他文件。

这些文件用于更改每个服务的偏好设置，如果您没有调整它们的经验，可以安全地忽略它们。

# 总结

到目前为止，您已经了解了使用 Vue CLI 构建应用程序的所有基础知识，并且已经初步了解了项目结构。

在下一章中，我们将启动并运行我们的项目，并开始处理实际的表单！


# 第二章：最简单的表单

好的！让我们毫不犹豫地开始（在美化之前稍作一些绕路）。我们将创建一个非常简单的带有表单的页面。这个表单将向用户询问一些基本的个人数据，表单的第二部分将用于更具体的问题。

在本章结束时，您将对如何在 Vue 中构建基本表单有扎实的理解，而且您还将快速复习基本的 Vue 概念，如`v-model`、事件和属性。

在本章中，我们将涵盖以下主题：

+   使用 Bootstrap 入门

+   实际编写一些代码

+   将输入绑定到本地状态

+   提交表单数据

+   引入 Axios

# 技术要求

本章的代码可以在以下 GitHub 存储库中找到：

[`github.com/PacktPublishing/Building-Forms-with-Vue.js/tree/master/Chapter02`](https://github.com/PacktPublishing/Building-Forms-with-Vue.js/tree/master/Chapter02)。

查看以下视频以查看代码的实际操作：

[`bit.ly/35F6340`](http://bit.ly/35F6340)

# 使用 Bootstrap 入门

让我们首先将 Bootstrap 4 作为项目的依赖项添加到我们的项目中，这样我们就不必考虑设计，可以专注于我们表单的功能。

Bootstrap 是一个流行的开源工具包，它为我们提供了一些预定义的类和样式，这样我们就可以让我们的应用程序看起来漂亮，而不必太担心样式。

要安装 Bootstrap 并为我们的项目设置，请按照以下步骤进行：

1.  打开项目文件夹的终端，并使用以下命令安装依赖项：

```js
> npm install bootstrap
```

1.  太棒了！这将把包添加到我们的`node_modules`文件夹和`package.json`中。现在，继续并将必要的样式导入到`src/main.js`中。使用以下命令来执行：

```js
import 'bootstrap/dist/css/bootstrap.min.css';
```

我们不会使用 Bootstrap 的脚本，所以我们只需要最小化的 CSS 就可以了。

让我们对我们的`App.vue`文件进行一些清理，因为现在我们只有一些样板代码，但我们想要重新开始！所以，让我们开始清理：

1.  用以下代码替换`App.vue`中的所有内容：

```js
<template>
  <div id="app">
  </div>
</template>

<script>
export default {
  name: 'app'
}
</script>
```

1.  通过在终端上运行以下命令来启动开发服务器：

```js
> npm run serve
```

1.  打开终端显示的链接（显示为本地）并在浏览器中应该看到一个空白屏幕。

瞧，这是伟大和重要的第一步的空白画布！耶！

让我们继续并开始着手实际的表单工作。现在是写一些代码的时候了。

# 实际编写一些代码

好了，够了设置——让我们写一些代码！我们将从一个非常简单的表单开始，这样我们的用户可以填写他们的个人信息。没什么疯狂的，只是小步走。

我们将向我们的表单添加三个字段。一个`firstName`输入，一个`lastName`输入和一个`email`输入。最后，我们将添加一个`Submit`按钮。

还记得我们安装 Bootstrap 吗？这就是它发挥作用的地方。我们要添加到标记中的所有类都将由 Bootstrap 自动样式化。

对您的`App.vue`文件进行以下更改：

```js
<template>
  <div id="app" class="container py-4">
    <div class="row">
      <div class="col-12">
        <form>
          <div class="form-group">
            <label>First Name:</label>
            <input type="text" class="form-control">
          </div>

          <div class="form-group">
            <label>Last Name:</label>
            <input type="text" class="form-control">
          </div>

          <div class="form-group">
            <label>Email:</label>
            <input type="email" class="form-control">
          </div>

          <div class="form-group">
            <button type="submit" class="btn btn-primary">Submit</button>
          </div>
        </form>
      </div>
    </div>
  </div>
</template>
```

在上一个代码示例中，我们设置了一个带有`row`的容器。在这个`row`中，我们用三个不同的输入填充了它，两个`text`类型（一个用于名字，一个用于姓氏），以及一个`email`类型的输入。最后，我们添加了`<button>`，它将作为提交表单的主要方式。

保存您的文件并检查您的浏览器。如果服务器仍在运行，您应该会自动看到更改。好吧，我同意这有点令人失望，但我确实说过我们从一个简单的例子开始，这就是最简单的例子！

表单是完全功能的，甚至可以单击提交按钮使其提交给自身并实现绝对没有任何作用。很棒！但让我们用一些 Vue 来调味一下。

# 将输入绑定到本地状态

Web 应用程序中表单的目的是捕获一些用户输入并能够对其进行操作。在我们的示例中，我们仍然没有任何方法使用 JavaScript 访问用户的输入以进行我们美好的 Vuetiful 计划，所以让我们从那里开始。

请注意，您不一定要将表单数据包装在次要对象中，但我发现这样更清晰——特别是当您开始向组件添加其他数据属性时，这些属性可能与您的表单无关。

在您的`App.vue`文件的实例上创建一个新的`data`属性。在其中，我们将声明一个`form`对象，它将依次包含每个输入的属性：

```js
<script>
export default {
  name: 'app',
  data() {
    return {
      form: {
        firstName: '',
        lastName: '',
        email: ''
      }
    }
  }
}
</script>
```

为了将我们的输入值绑定到内部状态，我们需要使用 Vue 的`v-model`属性。因此，让我们为每个输入添加`v-model`。这样，每当用户输入或删除信息时，输入元素的值将绑定到我们的`data`属性。

请记住，`v-model`不是一个*神奇*的属性。它是两件事的简写：

+   它绑定了我们输入框的`input`事件：

```js
v-on:input="form.name = $event.target.value"
```

+   它将`value`属性绑定到我们的`data`属性：

```js
 v-bind:value="form.firstName"
```

继续在所有输入中添加`v-model`：

```js
...
<div class="form-group">
  <label>First Name:</label>
  <input 
    v-model="form.firstName" 
    type="text" 
    class="form-control"
  >
</div>
<div class="form-group">
  <label>Last Name:</label>
  <input 
    v-model="form.lastName" 
    type="text" 
    class="form-control"
  >
</div>
<div class="form-group">
  <label>Email:</label>
  <input
    v-model="form.email"
    type="email"
    class="form-control"
  >
</div>
```

下面的屏幕截图显示了 Vue 开发者工具显示我们的表单与数据内部状态之间的双向数据绑定：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/bd-frm-vue/img/3de882c9-f5d0-4299-8ec2-c0c7c3852100.png)

干得好！现在，这并不是非常令人印象深刻，但我们正在为未来打下基础。

在接下来的部分中，我们将看看如何处理表单提交并发送到 API 端点。

# 提交表单数据

目前，当单击提交按钮时，表单将提交到相同的 URL。这不是 Vue 的魔法 - 这只是默认的`<form>`行为，特别是因为我们没有在标签上指定`action`属性。

在大多数实际场景中，您希望在提交表单之前执行一些操作。最常见的操作可能是验证一些输入，或者甚至使用诸如 Axios 之类的库进行异步调用来覆盖默认的提交行为。

首先，我们需要确保当用户单击提交按钮时，我们阻止表单自行提交。我们还希望绑定一个新的方法来处理点击。

让我们首先绑定表单的`submit`事件。请记住，我们希望为事件添加`.prevent`修饰符，以便在提交表单时，不会触发默认行为，而我们的函数将按预期运行：

```js
<form @submit.prevent="onSubmit">
  ...
</form>
```

太棒了！现在我们需要在`App.vue`文件的配置中创建这个新的`onSubmit`方法。在进一步详细说明之前，让我们在`click`方法处理程序内使用`console.log`来验证它是否有效。

将此代码作为`export default`声明内的属性添加：

```js
methods: {
  onSubmit() {
    console.log('click');
  }
}
```

只是为了验证一切是否正常工作，继续打开浏览器，点击几次提交按钮。检查控制台；日志应该显示点击。到目前为止，一切都很好 - 我们已经成功控制了表单的行为。

让我们创建一个*非常*基本的验证方法作为示例。我们将验证三个字段的输入长度是否`> 0`（不为空）。在后面的章节中，我们将介绍 Vuelidate，它将为我们的表单提供更深入和强大的验证。

让我们创建一个名为`formIsValid`的新计算属性，它将检查我们刚刚讨论的条件。将以下内容添加到`App.vue`中：

```js
computed: {
  formIsValid() {
    return (
      this.form.firstName.length > 0 && 
      this.form.lastName.length > 0 && 
      this.form.email.length > 0
    );
 }
}
```

现在我们有一个计算属性来检查我们表单的状态，让我们在`onSubmit`方法中实际使用它。我们将验证`this.formIsValid`是否为`true`，如果不是，我们将简单地返回并阻止表单提交。现在，我们将仅使用`console.log`进行确认。

将`onSubmit`方法调整为以下内容：

```js
onSubmit() {
  if (!this.formIsValid) return;
  console.log('Send my form!');
}
```

在浏览器上进行测试。如果您缺少任何字段，您将无法得到`console.log`，因为验证将失败。如果您填写它们并点击提交按钮，您将在控制台中收到消息。

在下一个块中，我们将引入第三方库 Axios，以帮助我们发送数据。

# 引入 Axios

我们表单的下一步是实际上让表单将用户的数据发送到我们的服务器。举例来说，数据实际上不会被存储在任何地方，但我们将看一下创建 POST 调用的步骤，大多数表单将用于将数据传输到 API 或服务器端点。

Axios 是一个非常棒和流行的库，用于向服务器发送和接收数据。我个人推荐它作为您的 Vue 应用程序中进行任何 HTTP 调用时的首选。您可以在这里找到官方的 GitHub 页面：[github.com/axios/axios](http://github.com/axios/axios)。

按照以下步骤准备好您的项目中的 Axios：

1.  打开您的终端并运行以下命令：

```js
> npm install axios
```

1.  我们需要一个 API 端点来进行调用。由于我们手头没有任何服务器，为了保持简单，我们将使用一个名为 Mockoon 的应用程序。前往[mockoon.com/#download](http://mockoon.com/#download)下载适用于您操作系统的应用程序。安装完成后，启动它。

1.  在第二列中，您将看到两个示例路由；我们感兴趣的是 POST 路由到/dolphins（坦白说，我更喜欢海獭，但我会接受这个）。继续点击顶部的绿色播放三角形；这将在`localhost:3000`上启动一个服务器，默认情况下，但如果默认设置不适用于您，您可以更改端口。

1.  现在，Axios 已经作为项目的依赖项添加，我们可以将其导入到`App.vue`中，以利用其不同的方法。

1.  在`App.vue`文件的顶部添加导入语句，就在开头的`<script>`标签之后，在`export default {`行之前：

```js
import axios from 'axios';
```

通过这个导入，我们现在可以在这个组件的任何地方使用 Axios。请记住，如果以后我们想在另一个组件或文件中使用它，我们将不得不再次导入它。

1.  让我们再次更新`onSubmit`按钮。这一次，我们将摆脱`console.log`，然后用 Axios 进行`async`调用：

```js
onSubmit() {
  if (!this.formIsValid) return;
  axios
    .post('http://localhost:3000/dolphins', { params: this.form })
    .then(response =>   {
      console.log('Form has been posted', response);
    }).catch(err => {
      console.log('An error occurred', err);
    });
}
```

每个 Axios 方法都返回一个 promise，这是一个原始的 JavaScript 对象。当这个 promise 解析时，也就是说，当实际的 HTTP 请求完成时，`then`块就会被调用！关于 promises 的更多信息，MDN 在[developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Promise](http://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Promise)上有一个很好的资源。

如果你现在去浏览器尝试一下，你会发现，当点击提交按钮时，我们的`onSubmit`方法被触发，`console.log`成功执行。在这一点上，我们可以说我们有一个非常基本的（但可悲的无用）表单！

让我们再走一步，实际上在表单有效之前禁用输入按钮。（请记住，我们的验证现在非常薄弱，但我们以后会加强它。）

回到你的模板，让我们将按钮的`:disabled`属性与我们的计算属性`formIsValid`关联起来：

```js
<button 
  :disabled="!formIsValid" 
  @click.prevent="onSubmit" 
  type="submit" 
  class="btn btn-primary"
> 
  Submit
</button>
```

再次在浏览器中测试一下，你会发现在表单实际填写之前，输入按钮是灰色的。很整洁！

# 总结

在本章中，我们已经迈出了创建一个简单数据收集表单的第一步。我们使用 Bootstrap 对其进行了样式化，并钩入了`<form>`事件。最后，我们使用 Axios 和 Mockoon 将数据发送到一个虚拟后端进行测试。

在下一章中，我们将探讨利用 Vue 的强大功能来构建可重用的表单组件。


# 第三章：创建可重用的表单组件

Vue 最强大的部分之一是它能够创建组件。

组件是可重用的代码片段，通常包括模板、脚本和样式。组件的惊人之处在于，你可以将特定元素或一组元素的所有逻辑封装到一个单元中。

开始以组件的方式思考的一个好方法是将日常物品分解为简单的、更小的部分。（请在你的脑海中！）

举个例子，你正在使用的计算机。作为一个整体，整个系统可以称为计算机。现在再进一步分解——它有一个显示器、一个键盘和一些电缆。现在拿键盘来分解。现在你有一个容器，这个容器有键。每个键都是一个单一的组件，它重复出现，具有一些在它们之间变化的属性。键上的标签会改变，有时也会改变大小。

那么这个关键组件呢？你能进一步分解吗？也许可以！但是值得吗？键盘键是一个很好的单一组件。它有清晰的属性来定义它，我们可以清晰地定义它的内部功能。当它被按下时，我们需要告诉包含它的人，一个键被按下，以及该键的值。

这种将某物进行分解的过程也可以应用到任何 Vue 应用程序中。从整个应用程序作为一个整体单元开始，然后将其分解。

现在，我们当前的表单是一个大块在`App.vue`中，这不是理想的。让我们创建一些组件！

在本章中，我们将涵盖以下主题：

+   将应用程序分解为可重用组件

+   理解自定义组件中的`v-model`

+   实现自定义输入和选择组件

# 技术要求

本章的代码可以在以下 GitHub 存储库中找到：

[`github.com/PacktPublishing/Building-Forms-with-Vue.js/tree/master/Chapter03`](https://github.com/PacktPublishing/Building-Forms-with-Vue.js/tree/master/Chapter03)。

查看以下视频以查看代码的实际操作：

[`bit.ly/2qgj7wx`](http://bit.ly/2qgj7wx)

# 将表单分解为组件

看看`App.vue`，让我们从我们可以创建的最小可能组件开始。如果你仔细看，你会发现代码中有一个重复的模式——这通常是一个好迹象，表明某些东西可能成为一个很好的组件！

在我们的`<form>`元素中，我们有三个不同的文本输入。其中两个是`text`类型，一个是`email`类型。看起来我们需要一种方法将这些值分配给`type`属性。属性对象可能是一个简单的解决方案！

作为一个快速提醒，这是表单的当前代码：

```js
<div class="form-group">
  <label>First Name:</label>
  <input v-model="form.firstName" type="text" class="form-control">
</div>
<div class="form-group">
  <label>Last Name:</label>
  <input v-model="form.lastName" type="text" class="form-control">
</div>
<div class="form-group">
  <label>Email:</label>
  <input v-model="form.email" type="email" class="form-control">
</div>
```

继续在`src/components`文件夹中创建一个新文件，命名为`BaseInput.vue`。就我个人而言，我喜欢以`Base`开头命名我的基本输入组件；这样，我就知道它是我在应用程序中能找到的最简单的输入形式。

如果我需要制作一个扩展或以某种方式使用`Base`的组件，那么我只需导入`BaseInput`组件，并进行一些调整！但是，您可以随意使用任何您喜欢的命名约定。如果您想要一些关于命名组件的实际样式指南和最佳实践，请参考官方指南：[`vuejs.org/v2/style-guide/`](https://vuejs.org/v2/style-guide/)。

让我们将`App.vue`中的第一个输入复制到我们的新组件中的`<template>`标签中，这样我们就有了一个基础来工作：

```js
<template>
  <div class="form-group">
    <label>Name:</label>
    <input v-model="form.firstName" type="text" class="form-control">
  </div>
</template>
<script>
export default {

}
</script>
```

我们需要做的第一件事是弄清楚如何摆脱硬编码的值；毕竟，将代码提取到组件中的目的是使其具有动态性和可重用性。

让我们创建一个属性对象来保存`label`的值（名称为`string`）：

```js
<script>
export default {
  props: {
    label: {
      type: String,
      required: true
    }
  }
}
</script>
```

我们将使用对象表示法来声明属性，这样我们可以确保任何使用我们组件的人至少会在浏览器控制台中被警告，如果他们忘记定义标签。

现在，让我们回到模板，实际上用新创建的属性对象替换这个值：

```js
<template>
  <div class="form-group">
    <label>{{ label }}</label>
    <input v-model="form.firstName" type="text" class="form-control">
  </div>
</template>
```

还有一个，类型呢？我们可能会想要在电子邮件和最终密码字段中使用这个（我们会的）。

让我们为此创建一个新的属性对象，并像以前一样绑定它：

```js
props: {
  label: {
    type: String,
    required: true
  },
  type: {
    type: String,
    default: 'text',
    validator(value) {
      return ['text', 'email', 'password'].includes(value);
    }
  }
}
```

我们的新属性类型有一个默认值，在组件实现时，如果该属性缺失，将使用默认值。

`validator`是一个函数，它验证！它接受一个参数，即传递到属性的值，并且必须返回一个布尔值来验证该值是否可接受用于属性（`validator`验证！）。

在这种特殊情况下，我们只是检查它是否是我们允许的三个选择之一：`text`，`email`或`password`。

既然我们已经准备好了，让我们更新`<input>`：

```js
<input v-model="form.firstName" :type="type" class="form-control">
```

到目前为止，一切都很好！除了还有一件事情还缺少，我们需要重构。你能发现吗？

到目前为止，我们已经看到了如何将表单分解为组件。现在让我们更深入地了解`v-model`，以及在创建动态组件时的重要性。

# 在自定义组件中理解 v-model

正如你所知，`v-model`是`v-on:input`和`v-bind:value="value"`的简写形式。它允许我们双向绑定特定元素的值，以及它发出的事件到我们内部状态属性之一。

然而，在谈论组件组合时，我们需要考虑额外的事情。

为了让自定义组件能够实现`v-model`协议，我们必须确保发生两件事。没错！我们需要确保组件有一个`value`属性，并且它`$emits`一个输入事件。

有一种方法可以通过使用`model`属性来更改这种默认行为，但这超出了本书的范围。如果你想告诉你的组件使用不同的属性或不同的事件来使用`v-model`，请查看[`vuejs.org/v2/api/#model`](https://vuejs.org/v2/api/#model)。

让我们将这个理论付诸实践。我们将修改我们的`BaseInput`组件，以便能够使用`v-model`绑定。首先，让我们添加一个`value`属性，并将其挂钩到`<input>`上：

```js
props: {
  label: {
    type: String,
    required: true
  },
  type: {
    type: String,
    default: 'text',
    validator(value) {
      return ['text', 'email', 'password'].includes(value);
    }
  },

  // Add this new prop
  value: {
    type: String,
    required: true
  }
}
```

现在我们有了新的`value`属性，我们需要将其绑定到`<input>`的值上。不过，一定要将旧的`v-model`从中移除！看一下下面的例子：

```js
<input :value="value" type="text" class="form-control">
```

差不多了；现在我们需要确保`<input>`在更新时触发输入事件。因此，我们需要添加一个事件处理程序来`$emit`这个信息。

**重要！**在我们继续之前，让我告诉你一个非常常见的*陷阱*，当使用`v-model`和表单时。并非所有的输入都是一样的！`<input>`文本元素（`text`，`email`和`password`）和`<textarea>`很容易。它们触发我们可以监听到用于`v-model`绑定的输入事件。但是，`select`，`checkboxes`和`radio`呢？

Vue 文档非常清晰，所以我要引用一下：

“*`v-model`在内部使用不同的属性并为不同的输入元素发出不同的事件：*

+   *`text`和`textarea`元素使用`value`属性和`input`事件；*

+   *`checkboxes`和`radiobuttons`使用`checked`属性和`change`事件；*

+   *`select`字段使用`value`作为属性和`change`作为事件。*

现在我们已经搞清楚了这个理论，让我们实际监听我们的事件：

```js
<input 
  :value="value" 
  :type="type" 
  class="form-control"
  @input="$emit('input', $event.target.value)"
> 
```

恭喜！我们的`BaseInput`组件已经准备好使用了。

现在我们对`v-model`和自定义组件有了清晰的理解，我们将在表单中使用我们的组件。这将使它更易读、动态和易于维护。

# 实现自定义输入组件

创建可重用的自定义组件是 Vue 的核心部分，但是为了使组件真正有用，我们必须实际上*使用*它们！

打开您的`App.vue`文件，让我们用我们的自定义组件替换三个`<div class="form-group">`元素。

首先要做的是将组件导入到我们的文件中。让我们先搞定这个。在`<script>`元素的顶部添加以下导入，如下所示：

```js
import BaseInput from '@/components/BaseInput';
```

仅仅导入文件是不够的；我们实际上必须将组件添加到文件的组件属性中，这样我们才能在模板中使用它。我们目前在 Vue 实例中没有这样的属性，所以让我们在`name`和`data()`之间创建一个：

```js
...
components: { BaseInput },
...
```

现在我们已经注册了我们的组件，并在`App.vue`文件中导入了它，我们可以进入模板，用我们的新组件替换旧的输入：

```js
<BaseInput 
  label="First Name:" 
  v-model="form.firstName" 
/>
<BaseInput 
  label="Last Name:" 
  v-model="form.lastName" 
/>
<BaseInput 
  label="Email:" 
  v-model="form.email" 
  type="email" 
/>
```

回到您的浏览器，玩一下这个应用程序。您会发现，即使实际上没有发生任何变化，表单现在是由可重用的输入组件驱动的——例如，如果我们需要更新输入的 CSS，我们只需在那个文件中更改一次，整个应用程序就会更新以反映这些变化。

再次打开 Vue DevTools，并确保选择了第一个图标（组件结构的图标）。深入结构，您将看到三个`BaseInput`组件在那里表示。

您甚至可以点击每一个，属性面板将清楚地显示每一个的独特之处——属性！

在下面的截图中，您可以看到，当我在“名称：”字段中输入我的名字时，<BaseInput>组件会在其值属性中反映出来：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/bd-frm-vue/img/eb3fa2e1-52a8-49f4-a9b7-3adfbecd54f6.png)

还有一件事！在表单中输入一些值，然后查看 props 框，它将实时更新您的值属性中的双向绑定。现在，点击 DevTools 中的第三个图标，看起来像一堆点——这是事件视图。

再次在其中一个输入框中输入一些值，您会看到事件框将填满条目。点击其中一个，您会注意到我们的输入事件在每次按键时都被触发。

这是两种不同的*操作*——值得到更新和输入事件被触发构成了`v-model`在工作中所做的工作，正如我们之前讨论的那样！

让我们看一下以下的屏幕截图：

！[](assets/8da52196-dedc-4554-94eb-2c40913540cc.png)

在前面的屏幕截图中，您可以看到`<BaseInput>`组件是如何发出输入事件的——`payload`是用户在表单中输入的内容。

# 再来一次——带有下拉选项！

在我们结束本章之前，让我们构建一个自定义组件，它包装了一个下拉输入，以便回顾我们迄今为止学到的知识。

首先创建组件文件——我们将其命名为`BaseSelect.vue`，并将其放在`components`文件夹中。

就像我们对`BaseInput`所做的那样，首先我们将定义我们的 HTML 模板。我们现在会留一些属性为空，因为我们稍后会绑定它们。我们还将设置一些虚拟数据以便轻松测试。在组件创建中，您会发现小步骤是前进的方式！

将以下代码添加为`BaseSelect`的模板：

```js
<template>
  <div class="form-group">
 <label>Label here</label>
 <select class="form-control">
 <option value="">Test!</option>
 <option value="">Me!</option>
 <option value="">:D</option>
 </select>
  </div>
</template>
```

看起来不错！让我们将这个新组件导入到`App.vue`中，并在我们的模板中，以便我们可以在浏览器中测试它的功能。按照给定的步骤来做：

1.  在`script`元素的顶部导入组件，紧挨着`BaseInput`导入语句：

```js
import BaseSelect from '@/components/BaseSelect';
```

1.  将`BaseSelect`添加到您的`components`声明中：

```js
components: { BaseInput, BaseSelect },
```

1.  在`<template>`元素内创建`BaseSelect`的实例，就在最后一个`BaseInput`组件下面，也在包含输入按钮的`div`之前：

```js
...
<BaseSelect />
... 
```

检查您的浏览器，您会看到我们新选择的组件正在发挥作用。她不是很漂亮吗？

让我们再进一步，我们迫切需要一些`props`。让我们从添加`label`开始；我们可以从模板中看到它需要被动态化。

在新的`script`元素内创建您的`props`对象，并将其添加到列表中：

```js
<script>
export default {
  props: {
    label: {
      type: String,
      required: true
    }
  }
}
</script>
```

现在，前往模板并动态绑定它们。我们需要使用一些插值使`<label>`的内容动态化：

```js
<template>
  <div class="form-group">
    <label>{{ label }}</label>
    <select class="form-control">
      <option value="">Test!</option>
      <option value="">Me!</option>
      <option value="">:D</option>
    </select>
  </div>
</template>
```

到目前为止，一切都很好！回到`App.vue`，并将这些新的`props`添加到我们的示例组件中：

```js
<BaseSelect 
  label="What do you love most about Vue?" 
/>
```

在浏览器中测试一下，确保没有出现问题。到目前为止，组件运行得相当顺利，但它显示的选项仍然是硬编码的。让我们实现一个`options`属性，这次它将是一个对象数组，我们将用它来填充`select`选项。

回到`BaseSelect.vue`，并创建新的属性：

```js
options: {
  type: Array,
  required: true,
  validator(opts) {
    return !opts.find(opt => typeof opt !== 'object');
  }
}
```

对于`validator`对象，我们将使用 JavaScript 数组，以找到一种方法来查看数组中是否存在一个不是对象的元素。如果找到了某些东西，`find`方法将返回它，`!`将对其进行评估为`false`，这将引发控制台错误。如果找不到任何东西（并且所有元素都是对象），那么`find`将返回`undefined`，`!`将转换为`true`，并且验证将通过。

有关`find`方法的更多信息，请查看以下链接：[`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/find`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/find)。

让我们在`<select>`元素内部实现一个`v-for`循环：

```js
<select class="form-control">
  <option 
    v-for="opt in options"
    :key="opt.value"
    :value="opt.value"
    >
    {{ opt.label || 'No label' }}  
  </option>
</select>
```

`v-for`循环将抓取 options 中的每个元素，并在`<select>`内创建一个新的`<option>`元素；不要忘记设置`:key`属性！

如果您想了解更多关于`:key`的信息，即何时使用它以及原因，请查看我在以下链接中的文章：[`www.telerik.com/blogs/in-vue-when-do-i-actually-need-the-key-attribute-and-why`](https://www.telerik.com/blogs/in-vue-when-do-i-actually-need-the-key-attribute-and-why)。

我们需要确保 options 中的每个对象都有`label`和`value`属性，但如果`label`缺失，我们将提供一个默认值。

回到`App.vue`，我们将在`data()`内部创建一个名为`loveOptions`的新内部`state`属性，它将保存特定`<Select>`的选项：

```js
return {
  form: ...,
  loveOptions: [
    { label: 'Fun to use', value: 'fun' },
    { label: 'Friendly learning curve', value: 'curve' },
    { label: 'Amazing documentation', value: 'docs' },
    { label: 'Fantastic community', value: 'community' }
  ]
}
```

现在我们已经设置好了，去模板并将其绑定到我们的`BaseSelect`组件的`options` prop 上：

```js
<BaseSelect 
  label="What do you love most about Vue?" 
  :options="loveOptions"
/>
```

保存后返回浏览器并检查选项。它活了！

还有一件事情缺失，我们需要将其添加到这个组件中，即`v-model`功能。我们需要创建一个`value` prop，使所选的`option`属性使用它，并确保我们从组件内部触发输入事件。

“记住，记住，`v-model` 的规则，属性绑定和发射。我不知道任何理由，`v-model` 系统，应该被遗忘。” - Vue Fawkes

在这种情况下，由于我们将使用 `v-model` 与 `select`，请记住我们需要监听变化，甚至是内部的变化！另一个需要注意的是，您可能会想要在 `select` 标签上放置一个 `:value` 绑定，这不是与选择一起工作的正确方式！

HTML 中的 `<select>` 元素没有 `value` 属性；它所做的是将 `selected` 属性应用到其中的 `option` 元素，该元素保存当前值。

1.  添加 `value` 属性：

```js
      value: {
        type: String,
        required: true
      }
```

1.  您将使用 `value` 属性来检查此选项的值是否等于它。确保在 `select` 元素触发 `change` 事件时发出 `input`：

```js
      <select 
        class="form-control"
        @change="$emit('input', $event.target.value)"
       >
        <option
          v-for="opt in options"
          :key="opt.value"
          :value="opt.value"
          :selected="value === opt.value"
          >
          {{ opt.label || 'No label' }}  
        </option>
      </select>
```

1.  返回到 `App.vue` 并将 `v-model` 绑定到这个新元素。您需要在 `data()` 中的 `form` 属性中创建一个名为 `love` 的新属性，并将 `v-model` 属性添加到 `BaseSelect` 元素中：

```js
      form: {
        firstName: '',
        lastName: '',
        email: '',
        love: 'fun'
      },
```

`BaseSelect` 元素现在将具有 `v-model` 绑定：

```js
<BaseSelect 
        label="What do you love most about Vue?" 
        :options="loveOptions"
        v-model="form.love"
      />
```

最后，检查您的浏览器，看看一切是否正常。进入 DevTools 并检查您的 App 组件 - 当您切换选择的值时，它也会更新！

# 总结

在本章中，我们已经通过将单例应用程序或表单解构为可重用的动态组件的过程。我们已经涵盖了一些重要的核心 Vue 功能，比如 `v-model`，属性和事件。

在下一章中，我们将加快速度，实现一个与用户体验（UX）相关的功能，即输入掩码！


# 第四章：使用 v-mask 进行输入掩码

任何成功表单的关键方面之一是清晰度。如果用户发现表单易于使用和理解，他们更有可能填写并提交表单。在本章中，我们将研究输入掩码。您将学习如何快速轻松地将掩码应用于表单输入，并使用真实示例（如电话号码）根据您的需求进行配置。

究竟什么是输入掩码？它们是预定义的结构，用于显示输入的数据。例如，如果您要对电话输入进行掩码处理，您可能希望它显示为**(123) 234-5555**，而不仅仅是**1232345555**。您可以清楚地看到，第一个示例不仅更容易阅读，而且还传达了字段试图实现的含义。

输入掩码是一个很好的功能，可以将您的 UX 提升到另一个水平，而且非常容易实现，这要归功于开源库，如`v-mask`。GitHub 存储库页面可以在以下链接找到：[`github.com/probil/v-mask`](https://github.com/probil/v-mask)。

在本章中，我们将快速了解如何在现有项目的基础上实现此库。

在本章中，我们将涵盖以下主题：

+   安装`v-mask`库

+   探索`v-mask`指令

+   增强我们的自定义输入

# 技术要求

本章的代码可以在以下 GitHub 存储库中找到：

[`github.com/PacktPublishing/Building-Forms-with-Vue.js/tree/master/Chapter04`](https://github.com/PacktPublishing/Building-Forms-with-Vue.js/tree/master/Chapter04)。

查看以下视频以查看代码的实际操作：

[`bit.ly/31jFmyH`](http://bit.ly/31jFmyH)

# 安装 v-mask 库

让我们开始安装`v-mask`库。为了让我们的项目使用它所提供的功能，我们首先需要将其添加到我们的项目依赖项中。按照以下步骤执行此操作：

1.  打开您的终端并输入以下命令将库添加到我们的依赖项中：

```js
> npm install v-mask
```

1.  我们需要将其添加到 Vue 作为插件，因此转到`main.js`，让我们导入它并让 Vue 知道我们要将其注册为所有应用程序的插件。在`import App`行之后添加以下代码：

```js
import VueMask from 'v-mask'
Vue.use(VueMask);
```

现在我们已经注册了我们的插件，我们可以访问一个新的指令：`v-mask`。我们可以直接将这个新指令添加到我们的`<input>`元素上，该库将通过读取用户的输入并调整字段的显示来处理幕后的掩码。

首先让我们在常规输入上尝试一下，然后我们将向我们项目的组件添加一些属性：

1.  转到`App.vue`，在电子邮件输入后创建一个新的`<input>`元素：

```js
<input type="text" />
```

如果我们在此字段中输入电话号码，我们将获得默认的输入行为。什么都可以。因此，让我们对其应用`telephone`号码掩码。我们的新`v-mask`库要求我们将其应用到的每个字段都需要进行 v 模型化，因此让我们首先完成这项工作。

1.  在`form`对象的`data()`中添加一个新的`telephone`属性：

```js
form: {
    ...
 telephone: ''
},
```

1.  现在，返回到我们的新`<input>`元素并应用`v-model`。我们现在还将添加`v-mask`指令，如下所示：

```js
<input 
 type="text"
 v-model="form.telephone"
 v-mask="'(###)###-####'"
>
```

返回浏览器，再次尝试输入。当您输入时，您将看到它被很好地格式化为我们期望的电话号码。

在五个简单的步骤中，我们已经为我们的一个表单字段添加了输入掩码。在下一节中，我们将更深入地了解`v-mask`指令为我们做了什么。

# 探索 v-mask 指令

当我们将`v-mask`库添加到我们的项目中，并在`main.js`中添加了插件时，该库为我们创建了一个新的指令`v-mask`。但是，指令到底是什么？我们知道它看起来像 HTML 属性，但还有什么？

指令可以定义如下：

“指令是带有`v-`前缀的特殊属性。指令属性值预期是*单个 JavaScript 表达式*（除了`v-for […]`之外）。指令的作用是在其表达式的值发生变化时，对 DOM 应用响应式的副作用。”- 官方 Vue 文档。

好的，看起来我们有一个特殊的属性可以修改元素。这听起来就像我们在应用到输入元素时看到的情况。但是，我们放入此指令的实际表达式或值是如何工作的呢？

我们从示例中知道我们正在传递一个字符串，并且您可以看到在组成`v-mask=""`属性的双引号内，我们设置了一对新的单引号（`'`）。这意味着此属性内的表达式是 JavaScript，并且我们正在传递给它一个字符串值。

从查看`v-mask`库文档，我们知道我们有一些*特殊*的占位符字符，可以在我们的掩码中使用。这些特殊字符如下表所示：

| `#` | 数字（0-9） |
| --- | --- |
| `A` | 任何大小写字母（a-z，A-Z） |
| `N` | 数字或字母 |
| `X` | 任何符号 |
| `?` | 可选的（下一个字符） |

以显示一天中的时间为例；您可以将其定义如下：

```js
v-mask="'##:##'"
```

这意味着此输入将接受两个数字，从 0 到 9（`##`），后跟一个`:`字符，然后是另外两个数字（`##`）。

任何不符合此模式的内容都将被输入忽略。

`v-mask`是一个非常强大的库，它允许我们通过组合这些简单的规则来自定义我们希望输入如何显示。在下一节中，我们将修改我们的自定义输入，以便能够利用输入掩码的功能。

# 增强我们的自定义输入

我们已经付出了很多工作来创建我们的令人敬畏的自定义`BaseInput`，所以我们肯定希望继续使用它！

按照以下步骤修改`BaseInput`并允许输入掩码：

1.  回到`App.vue`并将`<input>`元素切换为`<BaseInput>`组件：

```js
<BaseInput 
label="Telephone"
 type="text"
 v-model="form.telephone"
/>
```

现在让我们进入`BaseInput.vue`并创建一个新的 prop；我们将称其为`mask`，并将其默认为一个空字符串。重要的是将其默认为一个空字符串，否则指令将尝试匹配它，如果没有声明掩码，我们将无法在字段中输入！

1.  将其添加到您的`props`对象中：

```js
...,
mask: {
type: String,
required: false
}
```

1.  现在，回到`App.vue`并更新我们的电话`BaseInput`以使用`mask`属性：

```js
<BaseInput 
label="Telephone"
type="text" 
v-model="form.telephone"
 :mask="'(###)###-####'"
/>
```

全部完成！返回到您的浏览器，并在字段中添加一些数字，您应该可以看到一个漂亮的电话掩码与您的自定义组件一起工作！

# 总结

在本章中，我们已经学会了如何利用`v-mask`库的强大功能来对我们的表单应用输入掩码。输入掩码是一种强大而简单的方式，可以为用户提供更好的体验，在构建甚至是最简单的表单时，不应忽视它！

在下一章中，我们将进一步学习并查看如何使用强大的库`Vuelidate`进行表单验证！


# 第五章：使用 Vuelidate 进行输入验证

在生产就绪的表单中，验证用户输入是必须的。即使在服务器端，应用程序也应该对传递给它们的所有数据进行双重检查，同时在前端对数据进行预验证应该是任何有经验的开发人员的强制性实践。

在这一章中，我们将看一下一个非常著名和强大的表单验证库 Vuelidate。您将学习如何在项目中使用这个库，并且能够成功地用它来验证用户输入。

值得庆幸的是，在 Vue 中，我们有一些不同的选项可以选择第三方库，比如 Vuelidate、VeeValidate，甚至 Vuetify 都有自己的验证方法。

在这一章中，我们将涵盖 Vuelidate。从安装到创建规则并将其应用于我们的表单输入，以及使用错误状态来通知用户存在问题。

本章将涵盖以下主题：

+   安装依赖项

+   创建验证规则

+   将验证移入我们的自定义输入

+   添加最后的修饰

# 技术要求

本章的代码可以在以下 GitHub 存储库中找到：

[`github.com/PacktPublishing/Building-Forms-with-Vue.js/tree/master/Chapter05`](https://github.com/PacktPublishing/Building-Forms-with-Vue.js/tree/master/Chapter05)。

查看以下视频，看看代码是如何运行的：

[`bit.ly/2VJIL8E`](http://bit.ly/2VJIL8E)

# 安装依赖项

让我们首先将 Vuelidate 作为一个依赖项安装到我们的项目中，然后我们将用它进行验证。按照以下步骤进行：

1.  打开终端并执行以下命令：

```js
> npm install vuelidate
```

一旦库被安装，我们必须将其导入到`main.js`中并将其用作插件，以便它在全局范围内对所有组件都可用。

1.  在`main.js`中添加以下代码，放在导入`Vue`和`App`的代码之后：

```js
import Vuelidate from 'vuelidate';
Vue.use(Vuelidate);
```

现在 Vuelidate 已经安装并成为我们项目依赖的一部分，我们准备让它承担一些繁重的工作。在下一节中，我们将创建我们的验证规则。

# 创建验证规则

当我们通过`Vue.use`将 Vuelidate 添加到我们的项目中时，该库会在我们的组件上添加一个新的保留属性：`validations`。

这个属性被添加到组件的配置对象上，与`data()`、`computed`等一起。它也将是一个对象，为我们想要验证的每个输入保留一个属性。

让我们创建这个属性并设置一个新的输入，没有自定义组件包装器进行测试。一旦我们理解了基础知识，我们就可以开始将所有这些内容翻译成我们的`BaseInput`和`BaseSelect`组件。

按照以下步骤创建验证规则：

1.  在`App.vue`中的`BaseInput`的`telephone`对象下面创建一个新的`<input>`表单：

```js
<input type="text" v-model="form.website" />
```

1.  记得将这个新属性`website`添加到`data()`的`form`对象中：

```js
form: {
  firstName: '',
  lastName: '',
  email: '',
  love: 'fun',
  telephone: '',
  website: ''
},
```

现在，让我们实际创建一个`validations`属性；现在，我们只会添加`form.website`的验证。

1.  将其放置在`component`对象的顶层，与您的`data()`和计算属性处于同一级别：

```js
validations: {
  form: {
    website: {
      // our validations will go here
    }
  }
}
```

对于这个特定的字段，我们希望确保验证用户提供的输入是一个有效的 URL。在 Vuelidate 中，我们有几个内置的验证器可以直接使用。完整列表可以在[`vuelidate.netlify.com/#sub-builtin-validators`](https://vuelidate.netlify.com/#sub-builtin-validators)找到。

为了验证输入是否为有效的 URL，我们有 URL 验证器。但是，为了将其添加到我们网站的`validators`对象中，我们必须首先导入它。Vuelidate 允许我们只导入我们实际要使用的验证器；这样，我们可以确保我们部署的代码保持较小。

1.  在`App.vue`中的其他导入附近添加以下导入语句：

```js
import { url } from 'vuelidate/lib/validators';
```

1.  现在我们已经导入了语句，我们最终可以将其添加到`validations.website`对象中：

```js
validations: {
  form: {
    website: {
      url // Validate that the "website" input is a valid URL
    }
   }
 },
```

设置好规则就够了。记得我们之前创建的新的`<input>`表单来保存`v-model="form.website"`吗？我们需要对`v-model`的设置进行一些调整，以便 Vuelidate 负责验证。

除了我们之前用来设置规则的`validations`属性之外，Vuelidate 还为我们在组件实例内部提供了一个新属性：`$v`。

`$v`是一个特殊的对象，它保存了我们验证结构的副本。除其他事项外，一个显著的特点是，它为我们添加到`validations`中的每个元素都有一个`$model`属性。Vuelidate 将成为我们的*中介*模型，并且反过来，它将自动绑定到我们`data()`中的`form.website`属性。

让我们来看看实际操作中是怎样的：

1.  更新`<input>`网站元素，使用 Vuelidate 期望的新的`v-model`格式。此外，我们将在其下插入`$v`对象，以便您可以更清楚地看到幕后发生了什么，如下所示：

```js
<input type="text" v-model="$v.form.website.$model" />
<pre>{{ $v }}</pre>
```

1.  回到你的浏览器，看看`$v`对象的结构，在你在新的表单字段中输入任何内容之前。

要特别注意的第一件事是`form.website`对象。在此对象内部，Vuelidate 将保持此输入的验证状态。`$model`属性将保存用户的输入，就像我们告诉`v-model`要做的那样。`$error`属性实际上将切换布尔值，并且会告诉我们输入是否有错误。

尝试在字段中输入一些随机的胡言乱语，并观察更新的属性。`$error`属性将更新为`true`，表示存在错误。与 URL 规则直接关联的`url`属性将切换为`false`，表示未满足 URL 验证条件。

1.  让我们在`<input>`上添加一些 CSS 绑定，以便在我们的输入上直观显示出未通过验证的情况：

```js
<input 
  type="text"
  v-model="$v.form.website.$model" 
  class="form-control"
  :class="{ 
    'is-valid': !$v.form.website.$error && $v.form.website.$dirty,
    'is-invalid': $v.form.website.$error
  }"
/>
```

在我们进一步解释之前，请在浏览器中尝试一下。尝试输入一个有效的 URL，例如[`google.com`](http://google.com)，并注意输入如何反映您的更改。

`:class`绑定是一种在 Vue 中有条件地向任何 HTML 元素添加类的方法。在我们这里使用的语法类型中，它允许我们设置一个键值对，其中键定义了我们要切换的类，例如`is-valid`。

该值是一个将被评估的 JavaScript 条件，以确定是否应该应用该类。这些条件是响应式的，并且每当条件的依赖项发生变化时，将被重新执行。

在我们的示例中，只要没有`$error`并且输入是`$dirty`，`is-valid`就会被切换为*on*。如果你想知道为什么我们还要检查`$dirty`，请尝试删除条件的这一部分，然后重新加载浏览器。您会立即注意到，即使元素中没有任何值，输入上也会出现绿色边框和复选标记。我们确定`<input>`是否在任何时候被用户修改的方式是通过`$dirty`属性；在这种情况下，从用户体验的角度来看，直到实际有一些输入时才显示有效的视觉提示是有意义的。

在`is-invalid`的情况下，我们正在检查字段中是否存在任何`$errors`，并使用漂亮的红色边框和 x 图标设置字段。

现在我们已经有了一些基本规则，让我们继续下一节，在那里我们将学习如何将所有这些内容合并到我们的自定义组件中。

# 将验证移入我们的自定义输入中

拥有自定义组件的惊人之处在于您可以以任何您喜欢的方式来打造它们。在本章中，我们将为我们的组件添加对有效和无效状态的支持。主要的验证逻辑仍将由父组件`App.vue`持有，因为它是包含表单的组件。

按照以下步骤添加验证：

1.  首先，让我们为每个输入添加新的规则。将以下内容添加到`validations`属性中：

```js
validations: {
form: {
first_name: { alpha, required },
last_name: { alpha },
    email: { email, required },
  telephone: {
      validPhone: phone => phone.match(/((\(\d{3}\) ?)|(\d{3}-))? 
      \d{3}-\d{4}/) !== null
    },
    website: { url },
    love: { required }
  }
},
```

1.  不要忘记更新您的导入语句，以引入我们现在使用的新验证器，如下所示：

```js
import { url, alpha, email, required } from 'vuelidate/lib/validators';
```

让我们来看看新的验证器：

+   `alpha`：这将限制字段只能包含字母数字字符。

+   `required`：此字段使字段成为必填项；如果没有值，则无效。

+   `email`：此字段确保输入保持有效的电子邮件格式。

对于`telephone`字段，我们将进行一些自定义验证，因为该字段被掩码为特定格式`(###)###-####`，我们需要编写自己的验证函数。

在这种情况下，我们正在调用验证器`validPhone`，它是一个返回布尔值的函数。这个布尔值是通过将电话与正则表达式进行匹配并确保它不为空来计算的；也就是说，它确实有一个匹配项。

现在我们已经将所有的`validations`放在了适当的位置，我们需要更新我们的`App.vue`模板。我们的`BaseInput`组件和`BaseSelect`组件需要更新`v-model`，以便它指向 Vuelidate 模型而不是我们的本地状态。此外，我们需要将我们的网站输入更新为完整的`BaseInput`组件。

1.  对您的代码进行以下更改；我们正在更新`v-model`和输入类型：

```js
<form>
  <BaseInput 
    label="First Name:" 
    v-model="$v.form.firstName.$model" 
  />
  <BaseInput 
    label="Last Name:" 
    v-model="$v.form.lastName.$model" 
  />
  <BaseInput 
    label="Email:" 
    v-model="$v.form.email.$model" 
    type="email" 
  />
  <BaseInput 
    label="The URL of your favorite Vue-made website"
    v-model="$v.form.website.$model"
  />
  <BaseInput 
    label="Telephone"
    type="text" 
    v-model="$v.form.telephone.$model"
    :mask="'(###)###-####'"
  />
  <BaseSelect 
    label="What do you love most about Vue?" 
    :options="loveOptions"
    v-model="$v.form.love.$model"
  />
  <div class="form-group">
    <button 
      :disabled="!formIsValid" 
      @click.prevent="onSubmit" 
      type="submit" 
      class="btn btn-primary"
    >Submit</button>
  </div>
</form>
```

为了使我们的自定义组件显示正确的 CSS 类，我们将为它们添加一个名为`validator`的新属性，并将引用传递给与特定元素匹配的 Vuelidate 对象的 prop。

1.  打开`BaseInput.vue`并创建`validator`属性，如下所示：

```js
validator: {
type: Object,
  required: false,
  validator($v) {
    return $v.hasOwnProperty('$model');
  }
}
```

在属性的“验证器”方法中，我们将检查作为属性传递的“验证器”对象中是否有一个`$model`属性（即“验证器.$model”），这对于 Vuelidate 的所有字段属性都是 true。这样，我们可以确保我们可以访问我们需要的属性。

接下来，让我们将之前在<input>元素上的:class 绑定带过来，但我们会做一些小的调整，以适应这是一个组件属性。

1.  将以下内容添加到 BaseInput.vue 中的<input>元素：

```js
:class="{
  'is-valid': validator && !validator.$error && validator.$dirty,
  'is-invalid': validator && validator.$error
}"
```

由于验证器不是我们组件上的必需属性，我们必须再次检查实际设置的条件，然后再检查它的$error 和$dirty 属性。

1.  最后，回到 App.vue 并为所有的 BasicInput 元素添加:validator 属性：

```js
<BaseInput 
  label="First Name:" 
  v-model="$v.form.firstName.$model" 
  :validator="$v.form.firstName"
/>
<BaseInput 
  label="Last Name:" 
  v-model="$v.form.lastName.$model" 
  :validator="$v.form.lastName"
/>
<BaseInput 
  label="Email:" 
  v-model="$v.form.email.$model" 
  :validator="$v.form.email"
  type="email" 
/>
<BaseInput 
  label="The URL of your favorite Vue-made website"
  v-model="$v.form.website.$model"
  :validator="$v.form.website"
/>
<BaseInput 
  label="Telephone"
  type="text" 
  v-model="$v.form.telephone.$model"
  :validator="$v.form.telephone"
  :mask="'(###)###-####'"
/>
```

回到你的浏览器，玩弄一下输入框，现在它们都在后台由 Vuelidate 进行验证！

哇，这是相当多的信息 - 休息一下，吃点鳄梨土司；你值得拥有！在下一节中，我们将对我们的表单、BaseSelect 和 onSubmit 方法进行一些最终的更改，以便我们可以结束这一切。

# 添加最后的修饰

在我们结束本章之前，还有一些事情需要做。首先，让我们处理 BaseSelect；它仍然需要一个验证器属性和一些:class 绑定。

按照以下步骤找出我们如何做到这一点：

1.  首先，在 BaseSelect.vue 中添加验证器属性：

```js
validator: {
type: Object,
 required: false,
  validator($v) {
   return $v.hasOwnProperty('$model');
  }
}
```

现在，让我们添加:class 绑定；但这里，我们不会根据$dirty 进行检查，因为我们没有初始空值。

1.  将以下代码添加到<select>元素中：

```js
:class="{
  'is-valid': validator && !validator.$error,
  'is-invalid': validator && validator.$error
}"
```

1.  现在组件准备好了，回到 App.vue 并更新我们的 BaseSelect 元素，加上它自己的:validator 属性：

```js
<BaseSelect 
  label="What do you love most about Vue?" 
  :options="loveOptions"
  v-model="$v.form.love.$model"
  :validator="$v.form.love"
/>
```

1.  回到你的浏览器，验证元素是否按预期行为。

另一件我们不应忘记改变的事情是 App.vue 上的 onSubmit 方法。现在，我们正在使用一个计算属性，它在检查表单的有效性方面做得很差。让我们通过利用 Vuelidate 的更多功能来检查我们的表单是否准备好提交来解决这个问题。为了做到这一点，让我们首先删除我们的 formIsValid 计算属性。

Vuelidate 在`$v`对象的根部有一个`$invalid`属性，我们可以检查它来查看表单是否准备好提交。我们将在下一分钟内用于我们的`onSubmit`方法。

1.  完全删除`formIsValid` `computed`属性：

```js
computed: {}
```

默认情况下，所有表单最初都处于`$invalid`状态，因为 Vuelidate 在用户`$touches`并修改输入字段时触发其验证。我们需要进行一些微调以适应我们的提交按钮与此行为的兼容性。

1.  首先更改按钮的`:disabled`属性，以便根据`$error`而不是我们旧的`computed`属性进行检查：

```js
<button 
 :disabled="$v.$error" 
  @click.prevent="onSubmit" 
  type="submit" 
  class="btn btn-primary"
>Submit</button>
```

1.  接下来，让我们修改`onSubmit`方法，强制执行所有输入的`$touch`方法（并触发所有输入的验证），然后检查表单是否实际上是有效的并准备好提交：

```js
onSubmit() {
  this.$v.$touch();
  if (!this.$v.$invalid) return;   
  axios.post('http://localhost:3000/dolphins', { params:        
  this.form }).then(response => {
  console.log('Form has been posted', response);
  }).catch(err => {
  console.log('An error occurred', err);
  });
}
```

返回到您的浏览器并重新加载窗口以清除输入。不输入任何内容，点击提交按钮。您会看到`$v.$touch()`方法将触发，无效的输入（例如必填项）将变成红色，表示存在问题。

在下面的截图中，您可以看到`validator`是如何工作的，以及它如何直观地向用户确认发生了什么：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/bd-frm-vue/img/11fd20c9-49ef-4626-893d-e6b33dfd20b7.png)

就是这样！当涉及到表单验证时，Vuelidate 是一个很棒的工具——它非常灵活，并允许连接到外部数据源，比如 Vuex，我们将在下一章中看到。

# 摘要

在本章中，您已经学会了如何将 Vuelidate 作为 Vue 项目的依赖项，并获得了在常规输入和自定义组件上设置和管理表单验证的技能。在下一章中，我们将更进一步，看看全局状态管理——*鼓声*——Vuex！


# 第六章：使用 Vuex 进行全局状态管理

Vuex 是一种状态管理模式和库。等等，什么？让我们把所有的技术术语放在一边，如果你想阅读官方的技术解释，你可以在官方的 Vuex 网站上找到，什么是 Vuex？[`vuex.vuejs.org/`](https://vuex.vuejs.org/)。

在这一章中，你将学习如何使用全局状态管理模式和库 Vuex 来设置你的项目。Vuex 将允许你将组件中的局部状态提取到一个全局的、无所不知的状态中。如果你对这种模式不熟悉，比如 React 的 Redux，不用担心！继续阅读，我们将一步步来。

我们将以“这对我意味着什么”的水平来处理它。你可能知道，在 Vue 中，组件之间的通信是通过从父组件到子组件的 props 和从子组件到父组件的事件。在某些情况下，子组件将希望向其父组件发送数据。也许你想提醒父组件，它内部的某些东西被点击了，或者某些数据被改变了。在我们之前的例子中，我们的`BasicInput`和`BasicSelect`组件在改变时向父组件`$emit`值。

在某些情况下，父组件有自己的父组件，并向上发送`$emit`。有时，这第三个父组件也有父组件，依此类推。这可能很快就会变成一个非常复杂的组件网络，它们之间完美平衡地进行通信。或者你以为是这样。

你接到客户的电话：他们希望你在应用程序上进行 API 调用，以在标题中显示当前用户的名称，并且如果当前有用户登录，他们希望你预先填充表单上的一些字段。你该怎么办？也许你正在考虑在`App.vue`父组件上进行 API 调用，并开始构建一个需要它的组件链，但当这些数据在其中一个子组件上发生变化时会发生什么呢？你会将值`$emit`回父组件并创建一个庞大的链吗？

解决方案是使用 Vuex。Vuex 将为你提供一个全局状态，它不直接附加到任何组件上，但所有组件都可以访问它。在本章中，我们将从上一章的工作中获取我们的工作，并将整个表单迁移到 Vuex。我们还将进行一个模拟 API 调用，以获取已登录用户的数据，并使用一些值预先填充我们的全局存储。

本章将涵盖以下主题：

+   将 Vuex 添加到我们的项目中

+   创建模拟 API 端点

+   创建全局状态

+   添加一些变异

+   灯光，Vue，行动！

+   Vuelidate 和 Vuex

# 技术要求

本章的完整代码可以在以下 GitHub 存储库中找到：

[`github.com/PacktPublishing/Building-Forms-with-Vue.js/tree/master/Chapter06`](https://github.com/PacktPublishing/Building-Forms-with-Vue.js/tree/master/Chapter06)。

查看以下视频以查看代码的运行情况：

[`bit.ly/31l16Kg`](http://bit.ly/31l16Kg)

# 将 Vuex 添加到我们的项目中

让我们首先将 Vuex 添加到我们的项目中。按照以下步骤进行：

1.  打开终端并运行以下命令，以将 Vuex 添加到项目中作为依赖项：

```js
> npm install vuex
```

1.  现在我们已经安装了库，我们需要将其添加为应用程序的插件。转到`main.js`，导入它并使用以下代码添加它。您可以将它们放在`Vue`和`App`导入语句之后：

```js
import Vuex from 'vuex';
Vue.use(Vuex);
const store = new Vuex.store({
  // Our global store
});
```

`store`变量将保存我们的全局状态，包括我们的操作和变异。我们很快将详细讨论这些内容。为了使`store`对整个应用程序可用，我们还缺少最后一步。我们需要将`store`变量注入到我们的`Vue`实例中。

1.  在`main.js`中，继续转到新`Vue`实例的配置选项，并将`store`注入其中作为属性：

```js
new Vue({
store: store,
  render: h => h(App),
}).$mount('#app');
```

干得好！现在我们已经将 Vuex 设置为项目依赖项，我们几乎可以开始创建我们的存储了——在那之前只有一件微小的事情要做。我们将为我们的测试创建一个快速的模拟 API 端点。

# 创建模拟 API 端点

为了模拟我们正在调用 API 以获取用户详细信息，我们需要首先使用 Mockoon 进行设置。如果您还没有设置它，请查看本书的*Bringing in Axios*部分中第二章中如何安装它的说明。

让我们看看如何创建模拟 API 端点。按照以下步骤进行：

1.  打开应用程序，然后单击第二列中的“添加路由”按钮。这将在同一列中的列表中添加一个新路由。单击它以选择它，右侧的窗格将更新以显示此特定路由的信息：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/bd-frm-vue/img/a532791e-c587-4e3a-9409-0d8c8eed836e.png)

1.  在路由设置下，你可以输入路由的名称，将动词保留为 GET，并将端点的名称设置为`user`：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/bd-frm-vue/img/f1fe164c-b3ac-4d65-b0a0-19be952aee8c.png)

1.  现在，转到面板的 Body 部分，并设置我们将从调用中返回的虚拟数据。当然，你可以随意填写你自己的名称和虚拟信息，如下所示：

```js
{ 
   "firstName": "Marina",
   "lastName": "Mosti",
    "email": "marina@test.com",
    "love": "fun",
    "telephone": "(800)555-5555",
    "website": "http://dev.to/marinamosti"
}

```

下面的截图显示了虚拟信息的样子：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/bd-frm-vue/img/5d1fb153-5f88-447f-a538-353c8239f878.png)

1.  在我们开始模拟服务器之前还有一件事。转到面板顶部的 Headers 选项卡，并添加一个新的头部。左侧应该写 Content-Type，右侧应该写`application/json`，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/bd-frm-vue/img/9bfc2033-8e96-4743-9864-482c3b02f783.png)

最后，确保你使用工具栏上的绿色播放图标启动服务器。如果服务器已经在运行，点击停止按钮然后重新启动。

Mockoon 是一个非常简单但功能强大的工具，通过这些简单的步骤，我们已经有了一个完全功能的端点来运行测试。在下一节中，我们将最终开始创建我们的存储和全局状态。

# 创建全局状态

现在我们已经完成了设置，可以回到`main.js`并开始处理我们的全局状态。

在新的`Vuex.Store`配置中，我们将添加一个叫做`state`的保留属性。`state`是一个响应式对象，类似于本地状态`data()`的工作方式，因此我们将在这里重新定义我们的表单结构，不过，由于它现在不直接与表单绑定，我们将把它重命名为`user`。

回到`main.js`，继续在新的`Vuex.Store`对象中设置以下状态：

```js
state: {
  user: {
    firstName: '',
    lastName: '',
    email: '',
    love: 'fun',
   telephone: '',
    website: ''
  }
},
```

你可能想知道为什么我们将保存用户数据的全局属性命名为`user`，而不是之前的`form`。首先，让我澄清一点，你可以根据你的应用程序需求自由地命名状态变量！然而，在这种情况下，`form`并不能一目了然地表明我们将在这里存储什么样的数据；另一方面，`user`则非常具有描述性。

一个常见的做法是在这里将`user`属性初始化为 null。在这种情况下，您可以通过简单的`if`语句来检查他们是否已经通过认证，例如`if (!user)`。在这种情况下，我选择了这种设置来清晰地表明结构。当然，在`App.vue`中，用户的数据将用于填充一个表单，但在我们应用程序的另一个部分中，它可能会用于在任何类型的表单之外显示一些用户的数据。

学习如何设置您的存储是成功拥有功能全局状态的第一步。在接下来的部分，我们将添加修改此存储的能力与变异。

# 向我们的存储添加一些变异

关于 Vuex 的一个重要事情是，尽管全局状态可以从我们的任何组件中访问，但我们不应该直接改变或修改它。要修改我们的用户的内容，我们需要创建一个叫做**变异**的东西。变异是具有一个单一任务的方法：接受一个值或有效载荷，并对状态进行修改。这样，Vuex 就可以监视哪些组件正在对状态进行修改，而不会变得混乱不堪！

让我们创建我们的第一个变异；我们将称之为`updateUser`。

这个变异将接受两个参数：第一个是`state`。每个变异都会始终接收状态作为第一个参数；它默认由 Vuex 注入到变异中。第二个参数将是当您调用它时该变异将获得的值——在这种情况下，我们将称之为`user`，因为这是我们将传递给它的内容。重要的是要知道，变异*不能*执行异步代码。每个变异都需要是同步的，因为它们直接对我们的状态进行更改。

在`Vuex.Store`配置中创建一个名为`mutations`的新属性，然后将我们的以下新变异添加到其中：

```js
mutations: {
 updateUser(state, user) {
    state.user = user;
  },
},
```

当提交此变异时，它将通过调用`state.user = user`来更新全局状态，并传递我们传递的用户。现在，我们到底想要提交这个新的变异在哪里呢？

早些时候，我们设置了一个 API 端点来获取我们的模拟*已登录*用户。我们仍然需要设置一个调用此端点的方法，以便我们的应用程序在启动时可以使用它来检查 API 中是否有用户。

# 灯光，Vue，操作！

Vuex 的第三个关键部分称为**操作**。操作是方法，就像变异一样，但它们可以在其中执行异步代码。

操作接收两个参数，如下所示：

+   第一个是`context`，它是一个对象，保存对状态、getter 的引用，以及提交 mutations 和调度其他 actions 的能力。

+   第二个（可选）参数是用户定义的；这意味着我们可以在需要时向我们的 actions 发送额外的信息，但这也可以安全地忽略。

在基于 Vuex 的应用程序中的一个常见模式是将 HTTP 调用放在 Vuex actions 中 - 这样，如果需要的话，它们可以被应用程序内的任何组件调度。这些 HTTP 调用通常修改或利用状态，这非常方便，因为我们可以通过`context`轻松访问所有这些内容。

让我们回到手头的问题。我们需要调用我们的`/users`端点来获取用户信息。我们将创建一个名为`getLoggedInUser`的 Vuex action，它将知道如何为我们进行这个调用，并将自动将其获取的信息提交到状态。

按照以下步骤进行：

1.  由于我们将使用 Axios，确保首先在`main.js`文件中与其他导入语句一起导入它：

```js
import axios from 'axios';
```

1.  现在，在`Vuex.Store`配置对象中创建一个名为`actions`的属性；这个属性也是一个保留字。在其中，我们将创建我们的`getLoggedInUser`函数：

```js
getLoggedInUser(context) {
    axios.get('http://localhost:3000/user')
    .then(response => {
      context.commit('updateUser', response.data);
    });
  },
```

记住，Axios 返回一个 JavaScript promise，所以我们将在调用中附加一个`.then`块，在其中我们将使用响应数据提交我们的`updateUser` mutation。这些数据正是我们在 Mockoon 中定义的 JSON 对象。请记住，现实生活中的应用程序可能会涉及更复杂的流程，以检查用户是否实际上已登录；一个常见的做法是向端点传递一个 ID，或者甚至后端将通过来回传递令牌来处理会话。然而，这超出了本书的范围，因此我们将继续使用这个虚假场景进行演示目的。

现在我们的 action 已经准备好了，我们需要一个地方来调度它。在这种情况下，我们假设我们的应用程序希望尽快检查已登录的用户，因此我们将利用`App.vue`文件中的`created()`钩子：

1.  转到`App.vue`并在组件上添加`created`方法：

```js
created() {
 this.$store.dispatch('getLoggedInUser');
}
```

1.  打开您的浏览器，刷新页面，并在开发者工具的网络选项卡中检查。您会看到，页面加载后，我们对`http://localhost:3000/user`的 Axios 调用被触发，并且用户的数据被加载。如果出现错误，请记住首先在 Mockoon 上启动服务器！

1.  在我们继续修改我们的表单之前，让我们创建一个新的`<TheHeader>`组件来展示我们新的全局状态的强大功能。在`components`文件夹内创建一个新文件`TheHeader.vue`，并复制以下代码：

```js
<template>
 <div class="row">
    <div class="col-12 text-right">
      <p v-if="$store.state.user">
        Welcome back, {{ $store.state.user.firstName }}!
      </p>
    </div>
  </div>
</template>
```

在这个组件中，我们将使用插值来输出`$store.state.user.firstName`，这将访问我们的全局状态，在状态内部和用户内部查找`firstName`属性并在这里显示它。

1.  返回`App.vue`并导入组件：

```js
import 'TheHeader' from '@/components/TheHeader' 
```

不要忘记在`components`属性内声明它，如下所示：

```js
components: { BaseInput, BaseSelect, TheHeader },
```

1.  最后，在模板中添加我们的新组件，就在开头的`<div>`元素下方，并在浏览器中查看。您应该可以直接从全局状态中看到我们用户的名称被输出：

```js
<div id="app" class="container py-4">
    <TheHeader />
    ...
```

现在您已经了解了操作和突变，我们可以提高难度。在下一节中，我们将整合我们的两个主要库——Vuex 和 Vuelidate。

# Vuelidate 和 Vuex

为了让我们的表单在使用 Vuelidate 和 Vuex 的同时继续工作，我们需要对我们的数据设置进行一些调整，以便在输入上进行双向绑定。别担心，我们会一步一步来做。现在我们已经将 Vuex 整合到我们的应用程序中，我们希望我们的表单使用全局状态而不是我们在`App.vue`内的`data() { form: {...} }`中的局部状态。因此，我们需要在模板中进行一些更改，以告诉双向绑定使用 Vuex 而不是局部状态。

我们将从我们表单中删除所有的`v-model`语句。相反，我们将通过设置`:value`绑定和`@input`监听器来手动创建我们的双向绑定。

首先，我们将创建一个名为`updateUser`的新方法，它将接收两个参数，如下所示：

+   第一个将在我们的表单中被更新的是`property`，例如`firstName`或`lastName`。

+   第二个参数将是这个新属性将接收的`value`。

所以，让我们从将这个新方法添加到我们的`App.vue`组件开始：

```js
updateUser(property, value) {
  this.$store.dispatch('updateUserData', {
    property,
    value
  });

  this.$v.form[property].$touch();
}
```

这种方法将触发一个新的动作，我们将在接下来创建一个名为`updateUserData`的动作；它将发送一个包含`property`和方法获取的`value`的有效负载。

让我们停下来看一下第二个陈述。由于 Vuelidate 将不再连接到我们的本地状态，它将需要我们告诉它何时重新计算输入的脏状态，并检查验证错误。

由于`updateUser`方法将负责对我们的全局状态进行更改，我们将通过`$v.form[property]`访问 Vuelidate 的输入对象，并在其上强制`$touch()`。

现在我们的状态将是全局的，我们不再需要我们的`form: {...}`本地状态，所以你可以继续删除它。你的`data()`属性现在应该如下所示：

```js
data() {
  return {
    loveOptions: [
      { label: 'Fun to use', value: 'fun' },
      { label: 'Friendly learning curve', value: 'curve' },
      { label: 'Amazing documentation', value: 'docs' },
      { label: 'Fantastic community', value: 'community' }
    ]
  }
},
```

然而，为了让 Vuelidate 能够访问我们的全局状态，我们需要使用一个 Vuex 辅助函数将其映射到计算属性上。在这种情况下，我们想要使用`mapState`。想象一下，如果你不得不为我们的每一个用户属性创建一个计算属性，你将不得不逐个创建大量重复的代码，就像下面的例子一样：

```js
firstName() {
  return this.$store.state.user.firstName;
}
```

想象一下，如果你不得不为表单的所有属性都这样做，可能会很快变得乏味，对吧？

在这些情况下，Vuex 有一些方便的映射函数可以利用，所以让我们继续并将`mapState`导入到我们的`App.vue`文件的顶部：

```js
import { mapState } from 'vuex';
```

接下来，我们将在`App.vue`组件中添加一个`computed`属性，并使用`mapState`函数将整个状态映射到计算属性上：

```js
computed: {
  ...mapState({form: 'user'}),
},
```

我们将传递一个对象给`mapState`，告诉函数我们想要将整个全局状态的哪一部分映射到我们的计算属性上。在这种情况下，我们告诉它将用户全局状态中的所有内容映射到本地表单中。由于用户是一个具有多个子属性的对象，它将为每一个创建一个绑定，因此当`App.vue`调用，例如，`this.form.firstName`时，它将在全局状态中的`this.$store.state.user.firstName`中找到。很棒，对吧？！

请记住，`mapState`返回一个对象，因此我们可以在这里使用 JavaScript ES6 的展开运算符将新创建的对象合并到我们的`computed: {}`属性中。如果您以后想要添加一些不是从 Vuex 映射而来的计算属性，这将非常方便。

如果您想了解更多关于展开运算符的信息，请参考以下文章：[`dev.to/marinamosti/understanding-the-spread-operator-in-javascript-485j`](https://dev.to/marinamosti/understanding-the-spread-operator-in-javascript-485j)。

在我们去处理`updateUserData`动作之前，让我们对我们的输入进行`v-model`更改。删除所有`v-model`语句，并将它们替换为以下内容：

```js
<BaseInput 
  label="First Name:"
  :value="$store.state.user.firstName"
  @input="updateUser('firstName', $event)"
  :validator="$v.form.firstName"
/>
<BaseInput  
  label="Last Name:"
  :value="$store.state.user.lastName"
  @input="updateUser('lastName', $event)"
  :validator="$v.form.lastName"
/>
<BaseInput 
  label="Email:" 
  :value="$store.state.user.email"
  @input="updateUser('email', $event)"
  :validator="$v.form.email"
  type="email" 
/>
<BaseInput 
  label="The URL of your favorite Vue-made website"
  :value="$store.state.user.website"
  @input="updateUser('website', $event)"
  :validator="$v.form.website"
/>
<BaseInput 
  label="Telephone"
  type="text" 
  :value="$store.state.user.telephone"
  @input="updateUser('telephone', $event)"
  :validator="$v.form.telephone"
  :mask="'(###)###-####'"
/>
<BaseSelect 
  label="What do you love most about Vue?" 
  :options="loveOptions"
  :value="$store.state.user.love"
  @input="updateUser('love', $event)"
  :validator="$v.form.love"
/>
```

`：value`属性将绑定到我们的全局状态，也就是我们在本章开头创建的状态。`$store`属性通过 Vuex 在整个应用程序中都可以访问，我们可以使用它直接访问状态，甚至在模板中也可以。`@input`监听器将直接指向`updateUser`，将属性设置为字符串，并将`$event`的有效负载作为值传递。

转到`main.js`；我们必须创建我们的`updateUser`方法正在调用的新动作。我们将利用我们已经存在的突变`updateUser`，来更新用户的一个属性。您还可以将其重构为一个专门更新一个属性而不是覆盖整个对象的突变。在这种情况下，对象非常小，性能不是问题。将以下动作添加到您的存储中：

```js
updateUserData(context, payload) {
const userCopy = {...context.state.user};
  userCopy[payload.property] = payload.value;
  context.commit('updateUser', userCopy);
}
```

在动作的第一行，我们将使用 ES6 的展开运算符对用户状态进行浅拷贝。重要的是要记住，状态永远不应该在突变之外改变，所以如果我们直接将新属性值分配给我们的状态中的用户，我们将会做到这一点。

在制作副本之后，我们将属性设置为新值，并在我们的`updateUser`突变上调用`commit`。返回浏览器并重新加载页面；确保你的虚拟 Mockoon API 正在运行，这样我们的 Axios 调用才能正常工作并查看结果：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/bd-frm-vue/img/3f665a06-5041-4f63-bb28-f51a7f653e4a.png)

就是这样！通过对我们应用程序的这些小改动，我们成功地使全局状态不仅控制我们的表单，而且还利用了 Vuelidate 的灵活性和强大功能，直接连接到全局状态。

# 总结

在本章中，您已经掌握了设置、创建和使用 Vuex 作为全局状态模式和库所需的技能。您还学会了如何将 Vuelidate 与 Vuex 连接起来，以便您的验证直接与全局状态连接。

在下一章中，我们将进入最后阶段——如何将我们所做的一切以及我们的形式转化为完全基于模式驱动的形式。
