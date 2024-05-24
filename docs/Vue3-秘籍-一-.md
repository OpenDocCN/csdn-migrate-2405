# Vue3 秘籍（一）

> 原文：[`zh.annas-archive.org/md5/915E62C558C25E5846A894A1C2157B6C`](https://zh.annas-archive.org/md5/915E62C558C25E5846A894A1C2157B6C)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

Vue 是一个最小的前端框架，赋予开发人员创建 Web 应用程序、原型、大型企业应用程序、桌面应用程序和移动应用程序的能力。

Vue 3 是 Vue 的完全重写，并对框架的所有核心 API 进行了更改。这次重写改变了用 TypeScript 编写的代码。在 Vue 3 中，我们暴露了所有核心 API，使每个人都有可能使用 Vue。

本书从实现 Vue 3 的新功能到迁移现有 Vue 应用程序到最新版本的方法开始。您将学习如何在 Vue 中使用 TypeScript，并找到解决常见挑战和问题的简洁解决方案，从实现组件、派生物和动画，到构建插件、添加状态管理、路由和开发完整的单页应用程序（SPA）。

本书中使用的一些库、插件和框架可能会在本书编写和您阅读之间接收更新。因此，请注意任何可能导致破坏性变化的 API 更改或版本更改。

# 本书适合对象

这本书适用于希望了解更多关于 Vue 并希望提高他们的 Vue 技能的 Web 开发人员。我们将从介绍 Vue 3 和 TypeScript 技术开始。在接下来的章节中，读者将了解 Vue 中的新概念及其生态系统插件、UI 框架和高级技巧。

通过从头到尾地阅读本书，您将能够创建一个 Vue 应用程序，使用所有必要的 Vue 插件，并使用顶级 Vue UI 框架。如果您已经熟悉 Vue，您将发现相关的新模式。

# 本书涵盖内容

第一章，*理解 Vue 3 和创建组件*，为读者提供了如何使用新的 Vue 3 API 创建自定义 Vue 组件的方法，并使用 Vue 的暴露核心 API 和组合 API。本章还帮助读者将 Vue 2 应用程序初步升级到 Vue 3。

第二章，*介绍 TypeScript 和 Vue 生态系统*，向读者介绍了 TypeScript 超集以及如何使用它，从基本类型、接口和类型注解开始。读者将准备好使用 Vue CLI、TypeScript 和`vue-class-component`开发 Vue 应用程序。

第三章，“数据绑定、表单验证、事件和计算属性”，讨论了基本的 Vue 开发和组件概念，包括`v-model`、事件监听器、计算属性和`for`循环。读者将介绍 Vuelidate 插件用于表单验证以及如何在 Vue 组件上使用它，以及如何使用`vue-devtools`调试 Vue 组件。

第四章，“组件、混合和功能组件”，向读者介绍了使用不同方法构建组件，包括用于内容的自定义插槽、验证的 props、功能组件以及创建用于代码重用的混合。然后，它向读者介绍了一系列不同的方法来访问子组件的数据，创建依赖注入组件和动态注入组件，以及如何延迟加载组件。

第五章，“通过 HTTP 请求从 Web 获取数据”，向读者展示了如何在 JavaScript 上为 HTTP 调用创建 Fetch API 的自定义包装器，如何在 Vue 中使用该包装器，以及如何在 Vue 上实现自定义异步函数。读者还将学习如何在 axios 中替换包装器的 Fetch API，以及如何在 axios 上实现自定义处理程序。

第六章，“使用 vue-router 管理路由”，介绍了 Vue 的路由插件以及如何在 Vue 上使用它为 Vue 应用程序的页面创建路由。它介绍了管理路由路径的过程，路由路径上带有参数的动态路径，页面组件的延迟加载，为路由创建身份验证中间件，以及使用别名和重定向。

第七章，“使用 Vuex 管理应用程序状态”，探讨了 Vue 状态管理插件，帮助读者了解 Vuex 的工作原理以及如何应用于他们的应用程序。本章还为读者提供了创建 Vuex 模块、操作、突变和获取器的配方，并探讨了如何为存储定义基本状态。

第八章，*使用过渡和 CSS 为您的应用程序添加动画*，通过提供基于 CSS 的自定义动画示例，探讨了 CSS 动画和过渡的基础知识。这些将与 Vue 自定义组件一起使用，以实现一个外观漂亮的应用程序，并为应用程序的用户提供最佳体验。

第九章，*使用 UI 框架创建漂亮的应用程序*，介绍了流行的 UI 框架。读者将使用 Buefy、Vuetify 和 Ant-Design 构建用户注册表单，并了解它们的设计概念。本章的目的是教会读者如何使用 UI 框架创建一个外观良好的应用程序。

第十章，*将应用程序部署到云平台*，展示了如何在 Vercel、Netlify 和 Google Firebase 等自定义第三方主机上部署 Vue 应用程序。通过本章的示例，读者将学会如何使用集成的存储库钩子和自动部署功能自动部署他们的应用程序。

第十一章，*专业联赛-指令、插件、SSR 和更多*，探讨了 Vue 的高级主题，包括模式、最佳实践、如何创建插件和指令，以及如何使用 Quasar 和 Nuxt.js 等高级框架创建应用程序。

# 为了充分利用本书

Vue 3 beta 是撰写本书时可用的版本。所有的代码将在 GitHub 存储库的最终版本上进行更新：[`github.com/PacktPublishing/Vue.js-3.0-Cookbook`](https://github.com/PacktPublishing/Vue.js-3.0-Cookbook)

您需要安装 Node.js 12+，将 Vue CLI 更新到最新版本，并拥有某种良好的代码编辑器。其他要求将在每个示例中介绍。所有软件要求都适用于 Windows、macOS 和 Linux。

要开发 iOS 移动应用程序，您需要一台 macOS 机器以便访问 Xcode 和 iOS 模拟器。以下是总结所有要求的表格：

| **书中涵盖的软件/硬件** | **操作系统要求** |
| --- | --- |
| Vue CLI 4.X | Windows / Linux / macOS |
| TypeScript 3.9.X | Windows / Linux / macOS |
| Quasar-CLI 1.X | Windows / Linux / macOS |
| Nuxt-CLI 3.X.X | Windows / Linux / macOS |
| Visual Studio Code 1.4.X 和 IntelliJ WebStorm 2020.2 | Windows / Linux / macOS |
| Netlify-CLI | Windows / Linux / macOS |
| Vercel-CLI | Windows / Linux / macOS |
| Firebase-CLI | Windows / Linux / macOS |
| Node.js 12+- | Windows / Linux / macOS |
| Python 3 | Windows / Linux / macOS |
| Xcode 11.4 和 iOS 模拟器 | macOS |

**如果您使用本书的数字版本，我们建议您自己输入代码或通过 GitHub 存储库（链接在下一节中提供）访问代码。这样做将帮助您避免与复制和粘贴代码相关的任何潜在错误。**

## 下载示例代码文件

您可以从[www.packt.com](http://www.packt.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，可以访问[www.packtpub.com/support](https://www.packtpub.com/support)注册，直接将文件发送到您的邮箱。

您可以按照以下步骤下载代码文件：

1.  在[www.packt.com](http://www.packt.com)上登录或注册。

1.  选择“支持”选项卡。

1.  单击“代码下载”。

1.  在搜索框中输入书名，然后按照屏幕上的说明操作。

下载文件后，请确保使用以下最新版本解压缩或提取文件夹：

+   Windows 下的 WinRAR/7-Zip

+   Mac 下的 Zipeg/iZip/UnRarX

+   Linux 下的 7-Zip/PeaZip

该书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Vue.js-3.0-Cookbook`](https://github.com/PacktPublishing/Vue.js-3.0-Cookbook)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还有来自我们丰富图书和视频目录的其他代码包，可在**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**上找到。快来看看吧！

## 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词，数据库表名，文件夹名，文件名，文件扩展名，路径名，虚拟 URL，用户输入和 Twitter 句柄。 例如："将下载的`WebStorm-10*.dmg`磁盘映像文件挂载为系统中的另一个磁盘。"

代码块设置如下：

```js
<template>
 <header>
 <div id="blue-portal" />
 </header>
</header>
```

任何命令行输入或输出都以以下方式编写：

```js
$ npm run serve
```

**粗体**：表示新术语，重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会在文本中以这种方式出现。例如："单击**电子邮件**按钮，将被重定向到**电子邮件注册**表单"

警告或重要说明会以这种方式出现。提示和技巧会以这种方式出现。

# 部分

在本书中，您会经常看到几个标题（*准备工作*，*如何做*，*它是如何工作的*，*还有更多*，和*另请参阅*）。

为了清晰地说明如何完成食谱，请按照以下部分使用这些部分：

## 准备工作

本节告诉您在食谱中可以期待什么，并描述如何设置食谱所需的任何软件或初步设置。

## 如何做…

本节包含了遵循食谱所需的步骤。

## 它是如何工作的…

本节通常包括对前一节发生的事情的详细解释。

## 还有更多…

本节包括有关食谱的其他信息，以使您对食谱更加了解。

## 另请参阅

本节为食谱提供了其他有用信息的链接。


# 第一章：了解 Vue 3 和创建组件

Vue 3 带来了许多新功能和变化，所有这些都旨在帮助开发并改善框架的整体稳定性、速度和可维护性。借鉴其他框架和库的灵感，Vue 核心团队设法在 API 上实现了很高的抽象水平，现在任何人都可以使用 Vue，无论他们是前端开发人员还是后端开发人员。

在本章中，我们将学习如何将我们的 Vue 项目升级到新版本，以及一些新的 Vue 功能，比如多个根元素，新的属性继承引擎，我们如何在另一个应用程序中使用暴露的响应性 API，以及如何使用新的组合 API 创建组件。

在本章中，您将学习以下内容：

+   Vue 3 有什么新功能

+   将您的 Vue 2 应用程序升级到 Vue 3

+   使用多个根元素创建组件

+   使用属性继承创建组件

+   在 Vue 范围之外使用响应性和可观察 API

+   使用组合 API 创建组件

# Vue 3 有什么新功能

你可能想知道一个框架的新版本怎么会在互联网上引起如此大的轰动？想象一下把一辆汽车开上高速公路，做一个完整的 360 度翻滚，然后继续朝着同一个方向全速前进。这将引起一场戏剧性的场面，这正是描述 Vue 将从 2 版本升级到 3 版本的完美方式。

在本章的第一部分，我将向您介绍 Vue 的改进，框架中添加了什么，发生了什么变化，以及它将如何影响您编写 Vue 应用程序的方式。

## 框架的改进

在这个新版本中，Vue 框架有许多改进；所有这些改进都集中在尽可能使框架更好。以下是一些可能影响用户和开发人员日常开发和使用框架的改进。

### 底层

外壳看起来和旧的一样，但引擎是一件艺术品。在新版本中，没有留下来自 Vue 2 的代码。核心团队使用 TypeScript 从头开始构建了框架，并重写了一切，以最大程度地提高框架的性能。

选择了 TypeScript 来创建 Vue 核心团队和开源社区更易于维护的代码库，并改进自动完成功能，如 IDE 和代码编辑器提供的**IntelliSense**或**typeahead**，无需特殊的插件和扩展。

### 渲染引擎

对于 Vue 3，使用了一种新的算法开发了一个新的渲染引擎，用于影子 DOM。这个新的渲染引擎默认情况下完全暴露在框架的核心中，无需由框架执行。这使得可以实现一个全新的渲染函数的新实现，可以注入到框架中并替换原始的渲染引擎。

在这个新版本的 Vue 中，从头开始编写了一个新的模板编译器。这个新的编译器使用了一种新的缓存操作和管理渲染元素的新技术，并应用了一种新的提升方法来创建 VNodes。

对于缓存操作，应用了一种新的方法来控制元素的位置，其中元素可以是具有计算数据的动态元素，也可以是对可以被改变的函数的响应。

Vue 核心团队制作了一个浏览器，可以看到新模板编译器如何渲染最终的`render`函数。可以在[`vue-next-template-explorer.netlify.app/`](https://vue-next-template-explorer.netlify.app/)上查看。

### 暴露的 API

通过所有这些修改，可以在 Vue 应用程序范围之外的文件中渲染所有暴露给使用的 Vue API。可以在 React 应用程序中使用 Vue 响应性或影子 DOM，而无需在 React 应用程序内部渲染 Vue 应用程序。这种可扩展性是将 Vue 转变为更多功能的框架的一种方式，它可以在任何地方使用，不仅仅是在前端开发中。

## 新的自定义组件

Vue 3 引入了三个新的自定义组件，开发人员可以使用这些组件来解决旧问题。这些组件在 Vue 2 中也存在，但作为第三方插件和扩展。现在它们由 Vue 核心团队制作，并添加到 Vue 核心框架中。

### 片段

在 Vue 2 中，我们总是需要在单文件组件内部的组件周围有一个父节点。这是由于 Vue 2 的渲染引擎的构造方式所致，需要在每个节点上都有一个根元素。

在 Vue 2 中，我们需要有一个包装元素，封装将要呈现的元素。在这个例子中，我们有一个`div` HTML 元素，包装了两个`p` HTML 子元素，这样我们就可以在页面上实现多个元素：

```js
<template>
 <div>
 <p>This is two</p>
  <p>children elements</p>
  </div> </template>
```

现在，在 Vue 3 中，可以在单文件组件中声明任意数量的根元素，而无需使用新的 Fragments API 特殊插件，它将处理多个根元素。这有助于为用户保持更清洁的最终代码，而无需为包装元素而创建空壳：

```js
<template>
 <p>This is two</p>
  <p>root elements</p> </template>
```

正如我们在 Vue 3 代码中看到的，我们能够有两个根`p` HTML 元素，而无需包装元素。

### Teleport

`Teleport`组件，也称为 Portal 组件，顾名思义，是一个可以使元素从一个组件移动到另一个组件的组件。这一开始可能看起来很奇怪，但它有许多应用，包括对话框、自定义菜单、警报、徽章和许多其他需要出现在特殊位置的自定义 UI。

想象一个标题组件，您希望在组件上放置一个自定义插槽，以便放置组件：

```js
<template>
  <header>
    <div id="blue-portal" />
  </header>
</header>  
```

然后，您想在此标题上显示一个自定义按钮，但您希望从页面上调用此按钮。您只需要执行以下代码：

```js
<template>
  <page>
   <Teleport to="blue-portal">
     <button class="orange-portal">Cake</button>
   </Teleport>
  </page>
</template>
```

现在，您的按钮将显示在标题上，但代码将在页面上执行，从而访问页面范围。

### 悬念

当等待数据的时间比您想要的时间长时，如何为用户显示自定义加载程序？现在这是可能的，而无需自定义代码；Vue 将为您处理。`Suspense`组件将管理此过程，在数据加载完成后显示默认视图，并在加载数据时显示备用视图。

您可以编写一个特殊的包装器，如下所示：

```js
<template>
  <Suspense>
    <template #default>
      <data-table />
    </template>
    <template #fallback>
      <loading-gears />
    </template>
  </Suspense>
</template>
```

新的 Vue 组合 API 将了解组件的当前状态，因此它将能够区分组件是正在加载还是准备好显示。

## API 更改

Vue 3 进行了一些 API 更改，这些更改是为了清理 Vue API 并简化开发而必要的。其中一些是破坏性的更改，另一些是新增的。但不用担心；Vue 2 对象开发并没有被移除，它仍然存在，并将继续使用。这种声明方法是许多开发人员选择 Vue 而不是其他框架的原因之一。

Vue 3 中将出现一些重要的变化，这些变化很重要，需要更多了解。我们将讨论 Vue 3 中将引入的最重要的变化，以及如何处理它们。

在 Vue 3 中，正在引入一种创建组件的新方法——组合 API。这种方法将使您的代码更易于维护，并为您提供更可靠的代码，您将拥有 TypeScript 的全部功能。

### 一些较小的变化

在 Vue 3 中存在一些较小的变化，需要提及。这些变化涉及我们以前用来编写代码的一种方法，现在在使用 Vue 3 时已经被替换。这并不是一项艰巨的工作，但您需要了解这些变化。

#### 再见过滤器，你好过滤器！Vue 过滤器 API

在 Vue 2 中，我们使用`filters`的方式已经不再可用。Vue 过滤器已从 API 中删除。这一变化是为了简化渲染过程并加快速度。最终，所有过滤器都是接收一个字符串并返回一个字符串的函数。

在 Vue 2 中，我们使用`filters`如下：

```js
{{ textString | filter }}
```

现在，在 Vue 3 中，我们只需要传递一个`function`来操作`string`：

```js
{{ filter(textString) }}
```

#### 公交车刚刚离开车站！事件总线 API

在 Vue 2 中，我们能够利用全局 Vue 对象的力量创建一个新的 Vue 实例，并使用这个实例作为一个事件总线，可以在组件和函数之间传输消息而不需要任何麻烦。我们只需要发布和订阅事件总线，一切都很完美。

这是在组件之间传输数据的一个好方法，但对于 Vue 框架和组件来说是一种反模式的方法。在 Vue 中，在组件之间传输数据的正确方式是通过父子通信或状态管理，也被称为状态驱动架构。

在 Vue 3 中，`$on`、`$off`和`$once`实例方法已被移除。现在，要使用事件总线策略，建议使用第三方插件或框架，如 mitt（[`github.com/developit/mitt`](https://github.com/developit/mitt)）。

#### 不再有全局 Vue——挂载 API

在 Vue 2 中，我们习惯于导入 Vue，并在挂载应用程序之前，使用全局 Vue 实例来添加`plugins`、`filters`、`components`、`router`和`store`。这是一种很好的技术，我们可以向 Vue 实例添加任何内容，而无需直接附加到挂载的应用程序上。它的工作原理如下：

```js
import Vue from 'vue';
import Vuex from 'vuex';
import App from './App.vue';

Vue.use(Vuex);
const store = new Vuex.store({});

new Vue({
  store,
  render: (h) => h(App),
}).$mount('#app');
```

现在，在 Vue 3 中，这是不再可能的。我们需要直接将每个`component`、`plugin`、`store`和`router`附加到挂载的实例上：

```js
import { createApp } from 'vue';
import { createStore } from 'vuex';
import App from './App.vue';

const store = createStore({});

createApp(App)
  .use(store)
  .mount('#app');
```

使用这种方法，我们可以在同一个全局应用程序中创建不同的 Vue 应用程序，而不会相互干扰。

#### v-model，v-model，v-model - 多个 v-model

在开发单文件组件时，我们被限制为只能使用一个`v-model`指令和一个`.sync`选项来进行第二次更新更改。这意味着我们需要使用大量自定义事件发射器和巨大的对象负载来处理组件内的数据。

在这次重大变化中，引入了一个相关的破坏性变化，导致 Vue API 中的`model`属性被移除。这个属性用于自定义组件，以前可以做与新的 v-model 指令现在所做的相同的事情。

使用`v-model`指令的新方法将改变糖语法的工作方式。在 Vue 2 中，要使用`v-model`指令，我们需要创建一个组件，期望接收`props`为`"value"`，当有变化时，我们需要发出一个`'input'`事件，就像下面的代码：

```js
<template>
  <input 
    :value="value" 
    @input="$emit('input', $event)" 
  />
</template>
<script>
export default {
  props: {
    value: String,
  },
}
</script>
```

在 Vue 3 中，为了使语法糖工作，组件将接收的`props`属性和事件发射器将发生变化。现在，组件期望一个名为`modelValue`的`props`，并发出一个名为`'update:modelValue'`的事件，就像下面的代码：

```js
<template>
  <input 
    :modelValue="modelValue" 
    v-on:['update:modelValue']="$emit('update:modelValue', $event)" 
  />
</template>
<script>
export default {
  props: {
    modelValue: String,
  },
}
</script>
```

但是多个`v-model`指令呢？理解`v-model`的破坏性变化是了解多个`v-model`新方法如何工作的第一步。

要创建多个`v-model`组件，我们需要创建各种`props`，并使用`'update:value'`事件发出值作为模型指令的名称：

```js
<script>
export default {
  props: {
    name: String,
    email: String,
  },
  methods: {
   updateUser(name, email) {
    this.$emit('update:name', name);
    this.$emit('update:email', email);
   }
  }
}
</script>
```

在我们想要使用多个`v-model`指令的组件中，使用以下代码：

```js
<template>
  <custom-component
    v-model:name="name"
    v-model:email="email"
  />
</template>
```

组件将有每个`v-model`指令，绑定到子组件正在发出的事件。在这种情况下，子组件发出`'update:email'`（父组件）以便能够使用`v-model`指令与 email 修饰符。例如，您可以使用`v-model:email`来创建组件和数据之间的双向数据绑定。

### 组合 API

这是 Vue 3 最受期待的功能之一。组合 API 是创建 Vue 组件的一种新方式，以优化的方式编写代码，并在组件中提供完整的 TypeScript 类型检查支持。这种方法以更简单和更高效的方式组织代码。

在这种声明 Vue 组件的新方式中，你只需要一个`setup`属性，它将被执行并返回组件执行所需的一切，就像这个例子：

```js
<template>
 <p @click="increaseCounter">{{ state.count }}</p> </template> <script> import { reactive, ref } from 'vue';   export default {
  setup(){
  const state = reactive({
  count: ref(0)
 });    const increaseCounter = () => {
  state.count += 1;
 }    return { state, increaseCounter }
 } } </script>
```

您将从 Vue 核心导入`reactivity` API，以在对象类型数据属性中启用它，例如`state`。`ref` API 可以使基本类型值（如`count`）具有反应性，它是一个数字。

最后，函数可以在`setup`函数内部声明，并在返回的对象中传递。然后，所有内容都可以在`<template>`部分中访问。

现在，让我们继续进行一些示例。

# 技术要求

在本章中，我们将使用**Node.js**和**Vue-CLI**。

注意 Windows 用户！您需要安装一个名为`windows-build-tools`的 NPM 包，以便能够安装以下必需的包。为此，请以管理员身份打开 Power Shell 并执行以下命令：

`> npm install -g windows-build-tools`

要安装 Vue-CLI，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> npm install -g @vue/cli @vue/cli-service-global
```

## 创建基本文件

在本章的所有示例中，我们将使用这个基本模板，现在我们将创建它。确保在开始示例之前按照以下步骤创建文件：

1.  在任何文件夹中创建一个新的`.html`文件并打开它。

1.  创建一个`html`标签，并添加一个`head`HTML 元素作为子元素。在`head`HTML 元素内部，添加一个带有`src`属性定义为`http://unpkg.com/vue@next`的`script`HTML 元素：

```js
<html>  <head>
 <script src="https://unpkg.com/vue@next"></script>
 </head>
</html>
```

1.  作为`head`HTML 元素的同级，创建一个`body`HTML 元素。在`body`HTML 元素内部，添加一个带有属性`id`定义为`"app"`的`div`HTML 元素：

```js
<body>
 <div id="app">
 </div>
</body>
```

1.  最后，作为`div`HTML 元素的同级，创建一个带有空内容的`script`HTML 元素。这将是我们放置示例代码的地方：

```js
<script></script>
```

# 将您的 Vue 2 应用程序升级到 Vue 3

将您的项目从 Vue 2 升级到 Vue 3 有时可以自动完成，但在其他情况下，需要手动完成。这取决于您在应用程序中使用 Vue API 的深度。

对于由 Vue-CLI 制作和管理的项目，这个过程将变得更加顺畅，并且与使用自定义框架包装 CLI 的项目相比，将有更加简单的方法。

在这个食谱中，您将学习如何使用 Vue-CLI 升级您的应用程序以及如何手动升级项目和依赖项。

## 准备工作

这个食谱的先决条件如下：

+   Node.js 12+

所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

## 如何做...

为了将您的 Vue 2 项目升级到 Vue 3，您将需要将升级分为不同的部分。我们有框架本身的升级，然后是生态系统组件，比如`vue-router`和`vuex`，最后是将所有内容汇总的捆绑器。

框架升级带来了一些破坏性的变化。本章的*Vue 3 中的新内容*部分介绍了一些破坏性的变化，还有一些可能出现在更高级的 API 模式中。您必须手动更新并检查您的组件是否适用于框架的升级。

### 使用 Vue-CLI 升级项目

使用最新版本的 Vue-CLI，您将能够在项目中使用 Vue 3，并且您将能够将当前项目更新到 Vue 3。

要将 Vue-CLI 更新到最新版本，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> npm install @vue/cli-service@latest
```

### 手动升级项目

要手动升级项目，您首先需要将项目依赖项升级到它们的最新版本。您不能在 Vue 3 中使用旧版本的 Vue 生态系统插件。要做到这一点，请执行以下步骤：

1.  我们需要升级 Vue 框架、ESLint 插件（Vue 依赖的插件）和捆绑器的`vue-loader`。要升级它，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> npm install vue@next eslint-plugin-vue@next vue-loader@next
```

1.  我们需要将新的 Vue 单文件组件编译器作为项目的依赖项添加进去。要安装它，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> npm install @vue/compiler-sfc@latest
```

1.  如果您在项目中使用单元测试和`@vue/test-utils`包，您还需要升级此依赖项。要升级它，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> npm install @vue/test-utils@next @vue/server-test-utils@latest
```

1.  对于 Vue 生态系统插件，如果你使用`vue-router`，你也需要升级它。要升级它，你需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows），并执行以下命令：

```js
> npm install vue-router@next
```

1.  如果你的应用程序使用`vuex`作为默认状态管理，你也需要升级它。要升级它，你需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows），并执行以下命令：

```js
> npm install vuex@next
```

#### 更改起始文件

使用新版本的包，我们需要改变我们的起始文件。在使用 Vue-CLI 起始工具创建的 Vue 项目中，你会找到一个名为`main.js`或`main.ts`的文件。如果你使用 TypeScript，该文件位于`src`文件夹中。现在按照以下说明进行操作：

1.  打开项目中`src`文件夹中的`main.js`文件。在文件顶部，导入包的位置，你会看到以下代码：

```js
import Vue from 'vue';
```

我们需要将其更改为新的 Vue 暴露的 API 方法。为此，我们需要从 Vue 包中导入`createApp`，如下所示：

```js
import { createApp } from 'vue';
```

1.  从你的代码中移除全局 Vue 静态属性定义的`Vue.config.productionTip`。

1.  应该改变你的应用程序的挂载函数。旧的 API 看起来像这样：

```js
new Vue({
  router,
  store,
  render: (h) => h(App),
}).$mount('#app');
```

旧的 API 应该改为新的`createApp` API，如下所示：

```js
createApp(App)
  .use(router)
  .use(store)
  .mount('#app')
```

1.  打开你的`vuex`存储实例化文件（通常，该文件位于`src/store`，命名为`store.js`或`index.js`）。

1.  将存储的创建从实例化一个新的`vuex`类改为新的`createStore` API。`vuex` v3 类的实例化可能看起来像这样：

```js
import Vue from 'vue';
import Vuex from 'vuex';

Vue.use(Vuex);

export default new Vuex.Store({
  state: { /* ... */ },
  mutations: { /* ... */ },
  actions: { /* ... */ },
  getters: { /* ... */ },
  modules: { /* ... */ },
});
```

你需要用`createStore` API 替换它的内容，例如：

```js
import { createStore } from 'vuex';

export default createStore({
  state: { /* ... */ },
  mutations: { /* ... */ },
  actions: { /* ... */ },
  getters: { /* ... */ },
  modules: { /* ... */ },
});
```

1.  在`vue-router`生态系统中，我们需要用新的 API 替换路由器创建的旧 API。为此，打开路由器创建文件（在`src/router`文件夹中，通常命名为`router.js`或`index.js`）。

1.  最后，在创建文件中，用新的`createRouter` API 替换旧的`vue-router`类实例化。`vue-router` v3 类的实例化可能看起来像这样：

```js
import Vue from 'vue';
import VueRouter from 'vue-router';

Vue.use(VueRouter);

export default new VueRouter({
  routes: [{
    path: '/',
    name: 'HomePage',
    component: () => import('pages/home'),
  }]
});
```

你还需要用新的`createRouter`和`createWebHistory` API 替换`new VueRouter`的实例化，就像这个例子一样：

```js
import {
  createRouter,
  createWebHistory,
} from 'vue-router';

Vue.use(VueRouter);

export default createRouter({
  history: createWebHistory(),
  routes: [{
    path: '/',
    name: 'HomePage',
    component: () => import('pages/home'),
  }]
});
```

## 它是如何工作的...

在升级过程中，Vue 为我们提供了两种更新项目的方式。第一种方式是使用 Vue-CLI 插件，它试图自动化几乎所有升级所需的过程和更改。

第二种方法是手动升级项目。这种方法需要开发人员将所有依赖项升级到最新版本，安装新的单文件组件编译器`@vue/compiler-sfc`，并将 Vue 应用程序、路由器和存储的入口文件更改为新的 API。

在项目的起始结构更改后，开发人员需要检查组件，看看是否存在任何 Vue 3 破坏性更改，将组件重构为新的 Vue 3 API，并从 Vue 2 中删除已弃用的 API。

# 创建具有多个根元素的组件

在 Vue 3 中，可以创建具有多个根元素的组件，无需包装元素。这个选项也被称为片段。

在 React 中，这已经很久了，但在 Vue 中，您需要使用自定义的第三方插件，如`vue-fragment`（[`github.com/Thunberg087/vue-fragment`](https://github.com/Thunberg087/vue-fragment)）来使用此功能。

在这个教程中，您将学习如何创建一个具有多个根元素的组件，以及如何将其与`<template>`部分和`render`函数一起使用。

## 如何做...

在这个教程中，我们将创建两个多个根元素组件的示例，一个是使用`<template>`结构，另一个是使用`render`函数。为了做到这一点，这个教程将分为两部分。

### 使用<template>结构创建组件

为了在我们的示例中使用`<template>`结构，我们将使用 Vue 对象的`template`属性，我们可以将字符串或模板字符串作为值传递，这将由 Vue 脚本插值并呈现在屏幕上：

1.  使用“创建基本文件”部分的基本示例，创建一个名为`template.html`的新文件并打开它。

1.  在空的`<script>` HTML 元素中，通过对象解构`Vue`全局常量，创建常量`defineComponent`和`createApp`：

```js
const {
  defineComponent,   createApp, } = Vue;
```

1.  创建一个名为`component`的常量，定义为`defineComponent`方法，传递一个 JavaScript 对象作为参数，其中有三个属性：`data`、`methods`和`template`：

```js
const component = defineComponent({
  data: () => ({}),
  methods: {},
  template: `` });
```

1.  在`data`属性中，将其定义为一个单例函数，返回一个 JavaScript 对象，其中有一个名为`count`的属性，并且默认值为`0`：

```js
data: () => ({
  count: 0 }),
```

1.  在`methods`属性中，创建一个名为`addOne`的属性，这是一个函数，将通过`1`增加`count`的值：

```js
methods: {
  addOne() {
  this.count += 1;
  }, },
```

1.  在`template`属性中，在模板字符串中，创建一个带有标题的`h1` HTML 元素。然后，作为兄弟元素，创建一个带有绑定到`click`事件的事件监听器的`button` HTML 元素，当执行时触发`addOne`函数：

```js
template: `
  <h1>  This is a Vue 3 Root Element!  </h1>
 <button @click="addOne">  Pressed {{ count }} times.  </button> `
```

1.  最后，调用`createApp`函数，将`component`常量作为参数传递。然后，原型链连接`mount`函数，并将`div` HTML 元素的`id`属性`("#app")`作为函数的参数：

```js
createApp(component)
  .mount('#app');
```

### 使用渲染函数创建组件

为了在我们的示例中使用`<template>`结构，我们将使用 Vue 对象的`template`属性，我们可以将字符串或模板字符串作为值传递，Vue 脚本将对其进行插值处理并在屏幕上呈现：

1.  使用“创建基本文件”部分的基本示例，创建一个名为`render.html`的新文件并打开它。

1.  在空的`<script>` HTML 元素中，使用对象解构方法创建将要使用的函数的常量，从`Vue`全局常量中调用`defineComponent`、`h`和`createApp`方法：

```js
const {
  defineComponent,
 h,  createApp, } = Vue;
```

1.  创建一个名为`component`的常量，定义为`defineComponent`方法，传递一个 JavaScript 对象作为参数，该对象有三个属性：`data`、`methods`和`render`：

```js
const component = defineComponent({
  data: () => ({}),
  methods: {},
  render() {},  });
```

1.  在`data`属性中，将其定义为一个单例函数，返回一个具有名为`count`且默认值为`0`的 JavaScript 对象：

```js
data: () => ({
  count: 0 }),
```

1.  在`methods`属性中，创建一个名为`addOne`的属性，它是一个函数，将`count`的值增加`1`：

```js
methods: {
  addOne() {
  this.count += 1;
  }, },
```

1.  在`render`属性中，执行以下步骤：

+   创建一个名为`h1`的常量，并将其定义为`h`函数，将`'h1'`作为第一个参数传递，将要使用的标题作为第二个参数。

+   创建一个名为`button`的常量，它将是`h`函数，将`"button"`作为第一个参数传递，将一个具有`onClick`属性且值为`this.addOne`的 JavaScript 对象作为第二个参数传递，将`button`的内容作为第三个参数。

+   返回一个数组，第一个值为`h1`常量，第二个值为`button`常量：

```js
render() {
  const h1 = h('h1', 'This is a Vue 3 Root Element!');
  const button = h('button', {
  onClick: this.addOne,
  }, `Pressed ${this.count} times.`);    return [
  h1,
  button,
  ]; },
```

1.  最后，调用`createApp`函数，将`component`常量作为参数传递，原型链连接`mount`函数，并将`div` HTML 元素的`id`属性`("#app")`作为函数的参数：

```js
createApp(component)
  .mount('#app');
```

## 工作原理...

新的 Vue 组件创建 API 需要由一个函数`defineComponent`执行，并且作为参数传递的 JavaScript 对象几乎保持与 Vue 2 中的旧结构相同。在示例中，我们使用了相同的属性`data`、`render`、`methods`和`template`，这些属性都存在于 Vue 2 中。

在具有`<template>`结构的示例中，我们不必创建包装元素来封装应用程序组件的内容，并且可以直接在组件上有两个根元素。

在`render`函数示例中，发生了相同的行为，但最终示例使用了新的暴露的`h` API，它不再是`render`函数的参数。在按钮创建中出现了一个重大变化；我们必须在数据 JavaScript 对象内部使用`onClick`属性，而不是`on`属性和`click`方法。这是因为 Vue 3 的 VNode 的新数据结构。

# 使用属性继承创建组件。

自 Vue 2 以来，组件上已经可以使用属性继承，但在 Vue 3 中，属性继承变得更好，并且具有更可靠的 API 可用于组件中。

组件中的属性继承是一种模式，它可以更快地开发基于 HTML 元素的自定义组件（例如自定义输入、按钮、文本包装器或链接）。

在这个示例中，我们将创建一个具有属性继承的自定义输入组件，直接应用于`input` HTML 元素。

## 如何做...

在这里，我们将创建一个组件，该组件将在 DOM 树上的选定元素上具有完整的属性继承：

1.  使用*创建基本文件*部分的基本示例，创建一个名为`component.html`的新文件并打开它。

1.  在空的`<script>` HTML 元素中，使用对象解构方法创建将要使用的函数的常量，调用`Vue`全局常量的`defineComponent`和`createApp`方法：

```js
const {
  defineComponent,   createApp, } = Vue;
```

1.  创建一个名为`nameInput`的常量，定义为`defineComponent`方法，传递一个 JavaScript 对象作为参数，具有四个属性：`name`、`props`、`template`和`inheritAttrs`。然后，我们将`inheritAttrs`的值定义为`false`：

```js
const nameInput = defineComponent({
  name: 'NameInput',
  props: {},
  inheritAttrs: false,
  template: `` });
```

1.  在`props`属性中，添加一个名为`modelValue`的属性，并将其定义为`String`：

```js
props: {
  modelValue: String, },
```

1.  在模板属性中，在模板字符串内部，我们需要执行以下操作：

+   创建一个`label` HTML 元素，并将一个`input` HTML 元素作为子元素添加。

+   在`input` HTML 元素中，将`v-bind`指令定义为一个 JavaScript 对象，其中包含`this.$attrs`的解构值。

+   将变量属性`value`定义为接收到的 prop 的`modelValue`。

+   将`input`属性`type`设置为`"text"`。

+   将匿名函数添加到`change`事件监听器中，该函数接收一个`event`作为参数，然后发出一个名为`"update:modeValue"`的事件，载荷为`event.target.value`：

```js
template: ` <label>
 <input
 v-bind="{  ...$attrs,  }"
 :value="modelValue" type="text" @change="(event) => $emit('update:modelValue', 
                             event.target.value)"
  /> </label>`
```

1.  创建一个名为`appComponent`的常量，定义为`defineComponent`方法，传递一个 JavaScript 对象作为参数，其中包含两个属性，`data`和`template`：

```js
const component = defineComponent({
  data: () => ({}),
  template: ``,  });
```

1.  在`data`属性中，将其定义为一个单例函数，返回一个具有名为`name`的属性的 JavaScript 对象，其默认值为`''`：

```js
data: () => ({
  name: ''  }),
```

1.  在模板属性中，在模板字符串中，我们需要执行以下操作：

+   创建一个`NameInput`组件，其中`v-model`指令绑定到`name`数据属性。

+   创建一个带有值`"border:0; border-bottom: 2px solid red;"`的`style`属性。

+   创建一个带有值`"name-input"`的`data-test`属性：

```js
template: ` <name-input
 v-model="name" style="border:0; border-bottom: 2px solid red;"
 data-test="name-input" />`
```

1.  创建一个名为`app`的常量，并将其定义为`createApp`函数，将`component`常量作为参数传递。然后，调用`app.component`函数，将要注册的组件的名称作为第一个参数传递，组件作为第二个参数传递。最后，调用`app.mount`函数，将`"#app"`作为参数传递：

```js
const  app  =  createApp(component);  app.component('NameInput', nameInput); app.mount('#app');
```

## 工作原理...

在 Vue 3 中，为了创建一个组件，我们需要执行`defineComponent`函数，传递一个 JavaScript 对象作为参数。这个对象保持了几乎与 Vue 2 相同的组件声明结构。在示例中，我们使用了相同的属性，`data`，`methods`，`props`和`template`，这些属性都存在于 V2 中。

我们使用`inheritAttrs`属性来阻止将属性自动应用于组件上的所有元素，仅将其应用于具有`v-bind`指令和解构`this.$attrs`对象的元素。

要在 Vue 应用程序中注册组件，我们首先使用`createApp` API 创建应用程序，然后执行`app.component`函数在应用程序上全局注册组件，然后渲染我们的应用程序。

# 在 Vue 范围之外使用响应性和可观察 API

在 Vue 3 中，使用暴露的 API，我们可以在不需要创建 Vue 应用程序的情况下使用 Vue reactivity 和 reactive 变量。这使得后端和前端开发人员可以充分利用 Vue `reactivity` API。

在这个示例中，我们将使用`reactivity`和`watch` API 创建一个简单的 JavaScript 动画。

## 如何做...

在这里，我们将使用 Vue 暴露的`reactivity` API 创建一个应用程序，以在屏幕上呈现动画：

1.  使用“创建基本文件”部分中的基本示例，创建一个名为`reactivity.html`的新文件并打开它。

1.  在`<head>`标签中，添加一个新的`<meta>`标签，属性为`chartset`定义为`"utf-8"`：

```js
<meta charset="utf-8"/>
```

1.  在`<body>`标签中，删除`div#app` HTML 元素，并创建一个`div` HTML 元素，`id`定义为`marathon`，`style`属性定义为`"font-size: 50px;"`：

```js
<div
  id="marathon"
  style="font-size: 50px;" > </div>
```

1.  在空的`<script>` HTML 元素中，使用对象解构方法创建将要使用的函数的常量，调用`Vue`全局常量中的`reactivity`和`watch`方法：

```js
const {
  reactive,
  watch, } = Vue;
```

1.  创建一个名为`mod`的常量，定义为一个函数，接收两个参数`a`和`b`。然后返回一个算术运算，`a`模`b`：

```js
const mod = (a, b) => (a % b);
```

1.  创建一个名为`maxRoadLength`的常量，其值为`50`。然后，创建一个名为`competitor`的常量，其值为`reactivity`函数，传递一个 JavaScript 对象作为参数，其中`position`属性定义为`0`，`speed`定义为`1`：

```js
const maxRoadLength = 50; const competitor  = reactive({
  position: 0,
  speed: 1, });
```

1.  创建一个`watch`函数，传递一个匿名函数作为参数。在函数内部，执行以下操作：

+   创建一个名为`street`的常量，并将其定义为一个大小为`maxRoadLength`的`Array`，并用`*'_'*`*.*填充它。

+   创建一个名为`marathonEl`的常量，并将其定义为 HTML DOM 节点`#marathon`。

+   选择数组索引中`competitor.position`的`street`元素，并将其定义为`*"![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-cb/img/c8b07311-36a4-4df3-98fd-3b68200deed3.png)"*`，如果`competitor.position`是偶数，或者如果数字是奇数，则定义为`*"![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-cb/img/562ed724-a630-4193-a9c6-4e143a9690e2.png)"*`。

+   将`marathonEl.innertHTML`定义为`*""*`和`street.reverse().join('')`：

本示例中使用的表情符号是**跑步的人**和**行走的人**。表情符号图像可能因您的操作系统而异。本示例中呈现的图像是苹果操作系统的表情符号。

```js
watch(() => {
  const street = Array(maxRoadLength).fill('_');
  const marathonEl = document.getElementById('marathon');
  street[competitor.position] = (competitor.position % 2 === 1)
  ? '![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-cb/img/c8b07311-36a4-4df3-98fd-3b68200deed3.png)'
  : '![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-cb/img/562ed724-a630-4193-a9c6-4e143a9690e2.png)';    marathonEl.innerHTML = '';
  marathonEl.innerHTML = street.reverse().join(''); });
```

1.  创建一个`setInterval`函数，将一个匿名函数作为参数传递。在函数内部，将`competitor.position`定义为`mod`函数，将`competitor.position`加上`competitor.speed`作为第一个参数，将`maxRoadLength`作为第二个参数：

```js
setInterval(() => {
 competitor.position = mod(competitor.position +competitor.speed, 
    maxRoadLength) }, 100);
```

## 它是如何工作的...

使用 Vue 暴露的`reactive`和`watch`API，我们能够创建一个具有 Vue 框架中的响应性的应用程序，但不使用 Vue 应用程序。

首先，我们创建了一个响应式对象`competitor`，它的工作方式与 Vue 的`data`属性相同。然后，我们创建了一个`watch`函数，它的工作方式与`watch`属性相同，但是作为匿名函数使用。在`watch`函数中，我们为竞争者开辟了一条跑道，并创建了一个简单的动画，使用两个不同的表情符号，根据在道路上的位置进行更改，以模拟屏幕上的动画。

最后，我们在屏幕上打印了当前的跑步者，并创建了一个`setInterval`函数，每 100 毫秒改变竞争者在道路上的位置：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-cb/img/aa026d03-a44e-4d9b-ac15-3246bccda09f.png)

# 使用组合 API 创建组件

组合 API 是一种编写 Vue 组件的新方法，基于使用函数来组合组件，它使代码的组织和可重用性更好。

这种方法受到 React Hooks 的启发，并引入了创建特殊函数来组合应用程序的技术，这些函数可以在不需要在 Vue 应用程序内部的情况下共享，因为使用了暴露的 Vue API。

在这个示例中，我们将学习如何创建一个外部函数，用于获取用户的地理位置并在屏幕上显示这些数据，使用组合 API。

## 如何做...

在这里，我们将使用组合 API 创建一个组件，该组件将获取用户的 GPS 位置并在屏幕上显示该信息：

1.  使用“创建基本文件”部分的基本示例，创建一个名为`component.html`的新文件并打开它。

1.  在空的`<script>` HTML 元素中，使用对象解构方法创建将要使用的函数的常量，从`Vue`全局常量中调用`createApp`、`defineComponent`、`setup`、`ref`、`onMounted`和`onUnmounted`方法：

```js
const {
  createApp,
  defineComponent,
  setup,
  ref,
  onMounted,
  onUnmounted, } = Vue;
```

1.  创建一个`fetchLocation`函数，在其中创建一个名为`watcher`的`let`变量。然后，创建一个名为`geoLocation`的常量，并将其定义为`navigator.geolocation`。接下来，创建一个名为`gpsTime`的常量，并将其定义为`ref`函数，将`Date.now()`函数作为参数传递。最后，创建一个名为`coordinates`的常量，并将其定义为`ref`函数，将一个 JavaScript 对象作为参数传递，其中的属性`accuracy`、`latitude`、`longitude`、`altitude`、`altitudeAccuracy`、`heading`和`speed`都定义为`0`：

```js
function fetchLocation() {
  let watcher;
  const geoLocation = navigator.geolocation;
  const gpsTime = ref(Date.now());
  const coordinates = ref({
  accuracy: 0,
  latitude: 0,
  longitude: 0,
  altitude: 0,
  altitudeAccuracy: 0,
  heading: 0,
  speed: 0,
  }); }
```

1.  然后，在`fetchLocation`函数内部，在常量创建之后，创建一个名为`setPosition`的函数，带有一个名为`payload`的参数。在函数内部，将`gpsTime.value`定义为`payload.timestamp`参数，将`coordinates.value`定义为`payload.coords`参数：

```js
function setPosition(payload) {
  gpsTime.value = payload.timestamp
  coordinates.value = payload.coords
}  
```

1.  在创建`setPosition`函数之后，调用`onMounted`函数，将一个匿名函数作为参数传递。在函数内部，检查浏览器是否可用`geoLocation` API，并将`watcher`定义为`geoLocation.watchPostion`函数，将`setPosition`函数作为参数传递：

```js
onMounted(() => {
  if (geoLocation) watcher = geoLocation.watchPosition(setPosition); });
```

1.  调用`onMounted`函数后，创建一个`onUnmounted`函数，将一个匿名函数作为参数传递。在函数内部，检查`watcher`是否已定义，然后执行`geoLocation.clearWatch`函数，将`watcher`作为参数传递：

```js
onUnmounted(() => {
  if (watcher) geoLocation.clearWatch(watcher); });
```

1.  最后，在`fetchLocation`函数中，返回一个 JavaScript 对象，并将`coordinates`和`gpsTime`常量作为属性/值传递：

```js
return {
  coordinates,
  gpsTime, };
```

1.  创建一个名为`appComponent`的常量，并将其定义为`defineComponent`函数，将一个具有`setup`和`template`属性的 JavaScript 对象作为参数传递：

```js
const appComponent = defineComponent({
  setup() {},
  template: `` });
```

1.  在`setup`函数中，创建一个常量，这是一个对象解构，包括`fetchLocation`函数的`coordinates`和`gpsTime`属性：

```js
setup() {
  const {
  coordinates,
  gpsTime,
  } = fetchLocation(); }
```

1.  在`setup`函数内部，创建另一个名为`formatOptions`的常量，并将其定义为一个具有`year`、`month`、`day`、`hour`和`minute`属性的 JavaScript 对象，其值均为`'numeric'`。然后，将属性`hour12`定义为`true`：

```js
const formatOptions = {
  year: 'numeric',
  month: 'numeric',
  day: 'numeric',
  hour: 'numeric',
  minute: 'numeric',
  hour12: true,
  };
```

1.  在创建`formatOptions`常量之后，创建一个名为`formatDate`的常量，并将其定义为一个函数，该函数接收一个名为`date`的参数。然后，返回一个新的`Intl.DateTimeFormat`函数，将`navigator.language`作为第一个参数，将`formatOption`常量作为第二个参数。然后，原型链连接`format`函数，传递`date`参数：

```js
const formatDate = (date) => (new 
  Intl.DateTimeFormat(navigator.language, 
     formatOptions).format(date)); 
```

1.  最后，在`setup`函数的末尾，返回一个 JavaScript 对象，其属性定义为`coordinates`、`gpsTime`和`formatDate`常量：

```js
return {
  coordinates,
  gpsTime,
  formatDate };
```

1.  在`template`属性中，进行以下操作：

+   创建一个带有文本“我的地理位置在{{ formatDate(new Date(gpsTime) }}”的`h1` HTML 元素。

+   创建一个`ul` HTML 元素，并添加三个`li` HTML 元素作为子元素。

+   在第一个子元素中，添加文本“纬度：{{ coordinates.latitude }}”。

+   在第二个子元素中，添加文本“经度：{{ coordinates.longitude }}”。

+   在第三个子元素中，添加文本“海拔：{{ coordinates.altitude }}”：

```js
template: `
  <h1>My Geo Position at {{formatDate(new 
                          Date(gpsTime))}}</h1>
 <ul>
 <li>Latitude: {{ coordinates.latitude }}</li>
 <li>Longitude: {{ coordinates.longitude }}</li>
 <li>Altitude: {{ coordinates.altitude  }}</li>
 </ul> `
```

1.  最后，调用`createApp`函数，传递`appComponent`常量作为参数。然后，原型链连接`mount`函数，并将`div` HTML 元素的`id`属性`("#app")`作为函数的参数：

```js
createApp(appComponent)
  .mount('#app');
```

## 它是如何工作的...

在这个示例中，首先我们导入了暴露的 API - `createApp`、`defineComponent`、`setup`、`ref`、`onMounted`和`onUnmounted` - 作为常量，我们将使用它们来创建组件。然后，我们创建了`fetchLocation`函数，它负责获取用户的地理位置数据，并将其作为响应式数据返回，当用户更改位置时可以自动更新。

能够获取用户 GPS 位置是因为现代浏览器上存在的`navigator.geolocation` API，它能够获取用户当前的 GPS 位置。利用浏览器提供的数据，我们能够用它来定义由 Vue `ref` API 创建的变量。

我们使用 Vue 对象声明的`setup`函数创建了组件，因此渲染知道我们正在使用新的组合 API 作为组件创建方法。在`setup`函数内部，我们导入了`fetchLocation`函数的动态变量，并创建了一个方法，用于在模板上使用日期格式化。

然后我们返回导入的变量和过滤器，以便它们可以在模板部分中使用。在模板部分中，我们创建了一个标题，添加了最后一次 GPS 位置的时间，使用过滤器进行格式化，并创建了用户的纬度、经度和海拔的列表。

最后，我们使用`createApp`公开的 API 创建了应用程序，并挂载了 Vue 应用程序。

## 另请参阅

您可以在[`developer.mozilla.org/en-US/docs/Web/API/Navigator/geolocation`](https://developer.mozilla.org/en-US/docs/Web/API/Navigator/geolocation)找到有关`Navigator.geolocation`的更多信息。

您可以在[`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Intl/DateTimeFormat`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Intl/DateTimeFormat)找到有关`Intl.DateTimeFormat`的更多信息。


# 第二章：介绍 TypeScript 和 Vue 生态系统

TypeScript 是一种基于 Vue 的新语言，在**Vue 3**上得到了充分支持。现在可以使用类型化的 JSX（也称为 TSX），类型注解，代码的静态验证等等。

Vue 生态系统每天都在变得更加庞大，为了帮助我们，Vue 团队开发了一些工具来改善项目处理和管理。这些工具是 Vue CLI 和 Vue UI，它们是本地 Vue 开发的主要工具。

Vue CLI 工具是每个项目的开始；通过它，你可以选择基本功能或者你之前创建的预设，来创建一个新的 Vue 项目。项目创建后，你可以使用 Vue UI 来管理项目，添加新功能，检查项目的状态，以及几乎可以在命令行界面（CLI）中做的所有事情，还有更多功能。

在这些章节中，你将更多地了解 TypeScript 作为 JavaScript 的扩展，以及如何使用 Vue CLI 工具和 Vue UI 一起来启动和运行整个应用程序。

在本章中，我们将涵盖以下内容：

+   创建一个 TypeScript 项目

+   理解 TypeScript

+   创建你的第一个 TypeScript 类

+   使用 Vue CLI 创建你的第一个项目

+   使用 Vue UI 向 Vue CLI 项目添加插件

+   将 TypeScript 添加到 Vue CLI 项目中

+   使用`vue-class-component`创建你的第一个 TypeScript Vue 组件

+   使用`vue-class-component`创建自定义 mixin

+   使用`vue-class-component`创建自定义函数装饰器

+   将自定义钩子添加到`vue-class-component`

+   将`vue-property-decorator`添加到`vue-class-component`

# 技术要求

在本章中，我们将使用**Node.js**，**Vue CLI**和**TypeScript**。

注意，Windows 用户需要安装一个名为`windows-build-tools`的 npm 包，以便安装以下所需的包。要做到这一点，以管理员身份打开 PowerShell 并执行以下命令：

`> npm install -g windows-build-tools`。

要安装**Vue CLI**工具，打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows），执行以下命令：

```js
> npm install -g @vue/cli @vue/cli-service-global
```

要安装**TypeScript**，打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows），执行以下命令：

```js
> npm install -g typescript
```

# 创建一个 TypeScript 项目

TypeScript 是 JavaScript 的类型扩展，在编译时会生成纯 JavaScript 代码。它看起来像是一种新语言，但最终还是 JavaScript。

使用 TypeScript 的优势是什么？主要优势在于类型化的语法，有助于静态检查和代码重构。您仍然可以使用所有 JavaScript 库，并且可以直接使用最新的 ECMAScript 功能进行编程。

编译后，TypeScript 将生成一个纯 JavaScript 文件，可以在任何浏览器、Node.js 或任何能够执行 ECMAScript 3 或更新版本的 JavaScript 引擎上运行。

## 准备工作

要启动我们的项目，我们需要创建一个`npm`项目。打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows），并执行以下命令：

```js
> npm init -y
```

您还需要安装 TypeScript，因此打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows），并执行以下命令：

```js
> npm install typescript --only=dev
```

## 如何操作...

环境准备就绪后，我们需要启动我们的 TypeScript 项目。让我们创建一个`.ts`文件并进行编译：

1.  要启动我们的 TypeScript 项目，打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows），并执行以下命令：

```js
> tsc --init
```

这将在我们的文件夹中创建一个`tsconfig.json`文件。这是一个编译器设置文件。在这里，您可以定义目标，开发中可用的 JavaScript 库，目标 ECMAScript 版本，模块生成等等。

在为 Web 开发时，不要忘记在`tsconfig.json`文件的`compilerOption`属性中添加**文档对象模型**（**DOM**）库，这样在开发时就可以访问 window 和 document 对象。

1.  现在，我们需要创建我们的`index.ts`文件。让我们在`index.ts`文件中创建一些简单的代码，以便在终端中记录一个数学计算：

```js
function sum(a: number, b: number): number {
    return a + b;
}

const firstNumber: number = 10;

const secondNumber: number = 20;

console.log(sum(firstNumber, secondNumber));
```

这个函数接收两个参数，`a`和`b`，它们的类型都设置为`number`，并且函数预计返回一个`number`。我们创建了两个变量，`firstNumber`和`secondNumber`，在这种情况下都设置为`number`类型——分别是`10`和`20`，因此，将它们传递给函数是有效的。如果我们将它们设置为其他类型，比如字符串、布尔值、浮点数或数组，编译器会在变量和函数执行的静态类型检查方面抛出错误。

1.  现在，我们需要将这段代码编译成 JavaScript 文件。打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows），并执行以下命令：

```js
> tsc ./index.ts
```

编译后，我们可以在`index.js`中看到最终文件。如果我们查看文件内部，最终代码将类似于这样：

```js
function sum(a, b) {
    return a + b;
}
var firstNumber = 10;
var secondNumber = 20;
console.log(sum(firstNumber, secondNumber));
```

你可能会想：“我的类型在哪里？”由于 ECMAScript 是一种动态语言，TypeScript 的类型只存在于超集级别，并不会传递到 JavaScript 文件中。

你的最终 JavaScript 文件将以转译文件的形式存在，其中包含在`tsconfig.json`文件中定义的配置。

## 它是如何工作的...

当我们创建 TypeScript 项目时，一个名为`tsconfig.json`的文件会在我们的文件夹中创建。这个文件协调了编译器和开发过程中的静态类型检查的所有规则。所有的开发都基于这个文件中定义的规则。每个环境都依赖于需要导入的特定规则和库。

在开发过程中，我们可以直接为常量、变量、函数参数、返回值等分配类型。这些类型定义可以防止基本类型错误和代码重构。

开发完成并编译项目后，最终产品将是一个纯 JavaScript 文件。由于 JavaScript 的动态类型，这个文件不会有任何类型检查。

这个 JavaScript 文件被转译成目标模型，并在配置文件中定义，所以我们可以无问题地执行它。

## 另请参阅

您可以在[`www.typescriptlang.org/docs/home.html`](https://www.typescriptlang.org/docs/home.html)找到有关 TypeScript 的更多信息。

有一个关于从 JavaScript 迁移的指南在[`www.typescriptlang.org/docs/handbook/migrating-from-javascript.html`](https://www.typescriptlang.org/docs/handbook/migrating-from-javascript.html)。

可以在[`www.typescriptlang.org/docs/handbook/typescript-in-5-minutes.html`](https://www.typescriptlang.org/docs/handbook/typescript-in-5-minutes.html)找到一个关于 TypeScript 的 5 分钟课程。

# 了解 TypeScript

TypeScript 是一种基于类型的语言。它的很多功能来自于能够使用静态代码分析与 JavaScript。这得益于存在于 TypeScript 环境内的工具。

这些工具包括编译器，在开发过程中和编译后可以提供静态分析，以及 ECMAScript 转译器，可以使您的代码在几乎任何 JavaScript 引擎上运行。

让我们更多地了解这种语言，以及它是如何工作的。

## 准备好了吗？

首先，我们需要创建一个`npm`项目。打开 Terminal（macOS 或 Linux）或 Command Prompt/PowerShell（Windows）并执行以下命令：

```js
> npm init -y
```

您还需要安装 TypeScript，因此打开 Terminal（macOS 或 Linux）或 Command Prompt/PowerShell（Windows）并执行以下命令：

```js
> npm install typescript --only=dev
```

## 类型

使用 TypeScript 的主要特性是**类型**。在本节中，我们将学习有关类型的知识，如何声明它们以及如何使用它们。

这些是静态类型语言中的一些基本类型：

+   字符串

+   数字

+   布尔

+   数组

+   元组

+   枚举

+   任意

+   空

+   对象

让我们谈谈其中一些类型，并展示它们在 TypeScript 中的使用方式。

### 字符串

JavaScript 中的所有文本数据都将被视为**字符串**。要声明一个字符串，我们总是需要用双引号`(")`或单引号`(')`括起来，或者用反引号`(`)`，通常称为模板字符串。

在文本中声明模板字符串对 TypeScript 来说不是问题。模板字符串是 ECMAScript 中的一个功能，它使得可以在字符串中添加变量而无需进行连接：

```js
const myText: string = 'My Simple Text';
const myTextAgain: string = "My Simple Text";
const greeting: string = `Welcome back ${myName}!`;
```

### 数字

在 JavaScript 中，所有数字都是浮点值。在 TypeScript 中也是如此。这些数字得到了**数字**类型。除了十六进制和十进制数字外，ECMAScript 2015 中引入的二进制和八进制字面量也被视为数字：

```js
const myAge: number = 31;
const hexNumber: number = 0xf010d;
const binaryNumber: number = 0b1011;
const octalNumber: number = 0o744;
```

### 布尔

编程语言中最基本的类型是**布尔**值——简单的 1 或 0，true 或 false。这被称为**布尔**：

```js
const isTaskDone: boolean = false;
const isGreaterThen: boolean = 10 > 5;
```

### 数组

大多数语言中的一组元素通常被称为**数组**。在 TypeScript 中，我们可以以两种不同的方式声明它。

最简单的方法就是声明元素的类型，后面跟着`[]`（方括号）来表示它是一个声明类型的**数组**：

```js
const primeNumbers: number[] = [1, 3, 5, 7, 11];
```

或者，您可以使用`Array<type>`声明进行通用声明。这不是最常用的方式，但根据您正在开发的代码，您可能需要使用它：

```js
const switchInstructions: Array<boolean> = [true, false, false, true];
```

### 元组

**元组**是一种具有特定结构的变量类型。在结构上，元组是一个包含两个元素的数组；这两个元素由编译器和用户知道其类型，但这些元素不需要具有相同的类型：

```js
let person: [string, number];
person = ['Heitor', 31];

console.log(`My name is ${person[0]} and I am ${person[1]} years old`);
```

如果尝试访问已知索引之外的元素，将会收到错误。

### 枚举

**枚举**类似于 JavaScript 对象，但它们具有一些特殊的属性，可以帮助开发应用程序。您可以为数字值设置友好的名称，或者为函数可以接受的变量的常量提供更受控制的环境。

可以创建一个数字枚举而不需要任何声明。通过这样做，它将从`0`的初始值开始，并以最终索引号的值结束；或者，您可以通过传递枚举值的索引来获取枚举的名称：

```js
enum ErrorLevel { 
    Info, 
    Debug, 
    Warning, 
    Error, 
    Critical,
}

console.log(ErrorLevel.Error); // 3
console.log(ErrorLevel[3]); // Error
```

或者，可以声明一个带有值的枚举。它可以是 TypeScript 编译器将解释其余元素作为第一个元素的增量，或者是一个单独的声明：

```js
enum Color {
    Red = '#FF0000',
    Blue = '#0000FF',
    Green = '#00FF00',
}

enum Languages {
    JavaScript = 1,
    PHP,
    Python,
    Java = 10,
    Ruby,
    Rust,
    TypeScript,
}

console.log(Color.Red) // '#FF0000'
console.log(Languages.TypeScript) // 13
```

### 任意

由于 JavaScript 是一种动态语言，TypeScript 需要实现一个没有定义值的类型，因此它实现了**any**类型。any 类型最常用的情况是在使用来自第三方库的值时。在这种情况下，我们知道我们正在放弃类型检查：

```js
let maybeIs: any = 4;
maybeIs = 'a string?';
maybeIs = true;
```

任何类型的主要用途是当您将传统 JavaScript 项目升级到 TypeScript 时，您可以逐渐向变量和函数添加类型和验证。

### 空

与 any 相反，**void**是完全没有类型的。最常用的情况是在不返回任何值的函数中：

```js
function logThis(str: string): void{
    console.log(str);
}
```

使用 void 来对变量进行类型设置是没有意义的，因为它只能被赋值为 undefined 和 null。

### 对象

TypeScripts 中的**对象**有一种特殊的声明形式，因为它可以声明为接口，作为直接的**对象**，或者作为自己的类型。

将对象声明为接口时，您必须在使用之前声明接口，必须传递所有属性，并且需要设置类型：

```js
interface IPerson {
    name: string;
    age: number;
}

const person: IPerson = {
    name: 'Heitor',
    age: 31,
};
```

在将对象作为直接输入传递给函数时，有时是常见的：

```js
function greetingUser(user: {name: string, lastName: string}) {
    console.log(`Hello, ${user.name} ${user.lastName}`);
}
```

最后，它们用于声明对象的类型并重用它：

```js
type Person = {
    name: string,
    age: number,
};

const person: Person = {
    name: 'Heitor',
    age: 31,
};

console.log(`My name is ${person.name}, I am ${person.age} years old`);
```

### 函数

在 TypeScript 中，最难声明的类型之一是**函数**。它可以在一个简单的函数链的连接中变得非常复杂。

在 TypeScript 中声明函数是函数将接收的参数和函数将返回的最终类型的组合。

你可以在常量内声明一个简单的函数，就像这样：

```js
const sumOfValues: (a:number, b:number): number = (a: number, b: number): number => a + b;
```

一个更复杂的函数在常量内声明可以像这样声明：

```js
const complexFunction: (a: number) => (b:number) => number = (a: number): (b: number) => number => (b: number): number => a + b;
```

当声明一个函数作为普通函数时，其类型方式几乎与常量方式相同，但你不需要声明这些函数是一个函数。以下是一个例子：

```js
function foo(a: number, b:number): number{
    return a + b;
}
```

## 接口

TypeScript 检查变量的值是否是正确的类型，同样的原则也适用于类、对象或代码之间的合同。这通常被称为“鸭子类型”或“结构子类型”。接口存在是为了填补这个空间并定义这些合同或类型。

让我们尝试通过这个例子来理解一个**接口**：

```js
function greetingStudent(student: {name: string}){
    console.log(`Hello ${student.name}`);
}

const newStudent = {name: 'Heitor'};

greetingStudent(newStudent);
```

这个函数将知道对象上有一个名为 name 的属性，并且可以调用它是有效的。

我们可以使用接口类型来重写它，以便更好地管理代码：

```js
interface IStudent {
    name: string;
    course?: string;
    readonly university: string;
}

function greetingStudent(student: IStudent){
    console.log(`Hello ${student.name}`);
    if(student.course){
        console.log(`Welcome to the ${student.course}` semester`);
    }
}

const newStudent: IStudent = { name: 'Heitor', university: 'UDF' };

greetingStudent(newStudent);
```

正如你所看到的，我们有一个新的属性叫做`course`，在它上面声明了一个`?`。这表示这个属性可以是 null 或 undefined。这被称为可选属性。

有一个声明为只读属性的属性。如果我们在变量创建后尝试更改它，我们将收到一个编译错误，因为它使属性变为只读。

## 装饰器

ECMAScript 6 引入了一个新特性——类。随着这些特性的引入，装饰器的使用也成为了 JavaScript 引擎上的可能。

**装饰器**提供了一种在类声明及其成员上添加注解和元编程语法的方式。由于它已经在 TC-39 委员会（其中**TC**代表**技术委员会**）上处于最终批准状态，TypeScript 编译器已经可以使用它。

要启用它，你可以在`tsconfig.json`文件中设置标志：

```js
{
    "compilerOptions": {
        "target": "ES5",
        "experimentalDecorators": true
    }
}
```

装饰器是一种特殊的声明，可以附加到类、方法、存取器属性或参数上。它们以`@expression`的形式使用，其中表达式是一个在运行时将被调用的函数。

一个可以应用于类的装饰器的例子可以在以下代码片段中看到：

```js
function classSeal(constructor: Function) {
    Object.seal(constructor);
    Object.seal(constructor.prototype);
}
```

当你创建这个函数时，你是在说构造函数的对象和它的原型将被封闭。

在类内部使用它非常简单：

```js
@classSeal
class Animal {
    sound: string;
    constructor(sound: string) {
        this.sound = sound;
    }
    emitSound() {
        return "The animal says, " + this.sound;
    }
}
```

这些只是一些装饰器及其功能的例子，可以帮助你使用 TypeScript 进行**面向对象编程**（**OOP**）的开发。

## 总结

总之，类型只是在使用 TypeScript 和 JavaScript 进行开发过程中让我们的生活变得更加轻松的一种方式。

因为 JavaScript 是一种动态语言，没有静态类型，TypeScript 中声明的所有类型和接口都严格地只被 TypeScript 使用。这有助于编译器捕捉错误、警告，并且语言服务器可以帮助**集成开发环境**（**IDE**）在开发过程中分析你的代码。

这是 TypeScript 的基本介绍，涵盖了有关这种类型语言的基础知识，以及如何理解和使用它。关于它的使用还有很多要学习，比如泛型、模块、命名空间等等。

通过这个介绍，你可以了解新的**Vue 3**核心是如何工作的，以及如何在项目中使用 TypeScript 的基础知识，并利用项目中的类型语言。

关于 TypeScript，总是有更多的知识可以获取，因为它是建立在 JavaScript 之上的一种不断发展的“语言”，并且拥有一个不断增长的社区。

不要忘记查看 TypeScript 文档，以了解更多信息，以及它如何从现在开始改进你的代码。

## 另请参阅

你可以在[`www.typescriptlang.org/docs/handbook/basic-types.html`](https://www.typescriptlang.org/docs/handbook/basic-types.html)找到有关 TypeScript 基本类型的更多信息。

你可以在[`www.typescriptlang.org/docs/handbook/functions.html`](https://www.typescriptlang.org/docs/handbook/functions.html)找到有关 TypeScript 函数的更多信息。

你可以在[`www.typescriptlang.org/docs/handbook/enums.html`](https://www.typescriptlang.org/docs/handbook/enums.html)找到有关 TypeScript 枚举的更多信息。

你可以在[`www.typescriptlang.org/docs/handbook/advanced-types.html`](https://www.typescriptlang.org/docs/handbook/advanced-types.html)找到有关 TypeScript 高级类型的更多信息。

你可以在[`www.typescriptlang.org/docs/handbook/decorators.html`](https://www.typescriptlang.org/docs/handbook/decorators.html)找到有关 TypeScript 装饰器的更多信息。

在[`rmolinamir.github.io/typescript-cheatsheet/#types`](https://rmolinamir.github.io/typescript-cheatsheet/#types)上查看 TypeScript 类型的速查表。

# 创建你的第一个 TypeScript 类

在 TypeScript 中，没有一种主要的范式来编写程序。你可以选择面向对象的、结构化的，甚至是函数式的。

在大多数情况下，我们会看到使用面向对象编程范例。在这个配方中，我们将学习如何在 TypeScript 中创建一个类，它的继承，接口，以及代码中可以使用的其他属性。

## 做好准备

要开始我们的项目，我们需要创建一个`npm`项目。要做到这一点，打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows），并执行以下命令：

```js
> npm init -y
```

您还需要安装 TypeScript**。**要做到这一点，打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows），并执行以下命令：

```js
> npm install typescript --only=dev
```

## 如何做到这一点...

在 TypeScript 文件中编写类时，我们首先需要考虑这个类将做什么，这个类可以是什么，它如何通过继承被另一个类扩展，以及它如何在这个过程中受到影响。

想象一下，我们有一个基本的`Animal`类。这个类可以有一些基本属性，比如它的`name`，它是否发出`sound`，它的`family`，以及这种动物所吃的基本`food chain`。

1.  让我们从过程的基础开始，`food chain`。我们需要确保它是一个不可枚举的列表，并且每个使用它的文件最终都有相同的值。我们只需要调用一个常量变量：

```js
export enum FoodChainType {
    Carnivorous = 'carnivorous',
    Herbivorous = 'herbivorous',
    Omnivorous = 'omnivorous',
}
```

1.  现在，我们想为我们的动物制作基本的`interface`。我们知道我们的动物有一个`name`，可以发出一个`sound`，可以成为一个`family`的一部分，并且属于`food chain`类别。在类中使用接口，我们在类和将要暴露的内容之间建立了一个合同，有助于开发过程：

```js
interface IAnimal {
    name: string;
    sound?: string;
    family: string;
    foodChainType: FoodChainType;
}
```

1.  有了这一切，我们可以制作我们的`Animal`类。每个类都可以有它的构造函数。类构造函数可以很简单，只包含一些变量作为参数，也可以更复杂，有一个对象作为参数。如果你的构造函数将有任何参数，需要一个接口或声明每个参数的类型。在这种情况下，我们的构造函数将是一个对象，只有一个参数，与`Animal`相同，所以它将扩展`IAnimal`接口：

```js
interface IAnimalConstructor extends IAnimal { 
}
```

1.  现在，为了创建我们的类，我们声明了将要使用的接口和枚举。我们将首先声明该类将实现`IBasicAnimal`接口。为此，我们需要添加一些我们的类将具有的公共元素，并也声明这些元素。我们需要实现函数来显示它是什么动物以及它发出什么声音。现在，我们有了一个包含所有动物属性的基本类。它具有类和构造函数的单独接口。食物链的枚举以一种易于阅读的方式声明，因此该库的 JavaScript 导入可以无问题执行：

```js
interface IBasicAnimal extends IAnimal {
  whoAmI: () => void;
  makeSound: () => void;
}

export class Animal implements IBasicAnimal {
  public name: string;
  public sound: string;
  public family: string;
  public foodChainType: FoodChainType;

  constructor(params: IAnimalConstructor) {
    this.name = params.name;
    this.sound = params.sound || '';
    this.family = params.family;
    this.foodChainType = params.foodChainType;
  }

  public whoAmI(): void {
    console.log(`I am a ${this.name}, my family is ${this.family}. 
    My diet is ${this.foodChainType}.`);
    if (this.sound) {
      console.log([...Array(2).fill(this.sound)].join(', '));
    }
  }

  public makeSound(): void {
    console.log(this.sound);
  }
}
```

1.  让我们用几行代码扩展这个类，将这个`Animal`转换成`Dog`：

```js
import {Animal, FoodChainType} from './Animal';

class Dog extends Animal {
  constructor() {
    super({
      name: 'Dog',
      sound: 'Wof!',
      family: 'Canidae',
      foodChainType: FoodChainType.Carnivorous,
    });
  }n
}
```

这是一种简单的方式，通过扩展父类并使用父类的子类定义来组成一个几乎与父类具有相同接口的新类。

## 它是如何工作的...

TypeScript 中的类与 Java 或 C#等语言中的其他类一样工作。编译器在开发和编译过程中评估这些共同的原则。

在这种情况下，我们创建了一个简单的类，其中有一些公共属性是子类固有的。这些变量都是可读的，可以被改变。

## 还有更多...

在 TypeScript 中，我们有各种可能的类的用法，比如抽象类、特殊修饰符，以及将类用作接口。我们在这里只是涵盖了类的基础知识，为我们提供了一个良好的起点。如果你想深入了解，TypeScript 文档非常有帮助，并且有很多例子可以帮助学习过程。

## 另请参阅

您可以在[`www.typescriptlang.org/docs/handbook/classes.html`](https://www.typescriptlang.org/docs/handbook/classes.html)找到有关 TypeScript 类的更多信息。

在[`rmolinamir.github.io/typescript-cheatsheet/#classes`](https://rmolinamir.github.io/typescript-cheatsheet/#classes)上查看 TypeScript 类的速查表。

# 使用 Vue CLI 创建您的第一个项目

当 Vue 团队意识到开发人员在创建和管理他们的应用程序时遇到问题时，他们看到了一个机会，可以创建一个工具来帮助全世界的开发人员。Vue CLI 项目诞生了。

Vue CLI 工具是一个在终端命令中使用的 CLI 工具，如 Windows PowerShell、Linux Bash 或 macOS Terminal。它被创建为 Vue 开发的起点，开发人员可以开始一个项目并顺利地管理和构建它。Vue CLI 团队在开发时的重点是为开发人员提供更多时间来思考代码，花费更少的时间在工具上，以将他们的代码投入生产，添加新的插件或简单的`热模块重载`。

Vue CLI 工具被调整得无需在将其投入生产之前将您的工具代码弹出 CLI 之外。

当版本 3 发布时，Vue UI 项目被添加到 CLI 作为主要功能，将 CLI 命令转换为更完整的可视解决方案，并增加了许多新的功能和改进。

## 准备工作

此食谱的先决条件如下：

+   Node.js 12+

所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

## 如何做…

要创建 Vue CLI 项目，请按照以下步骤进行：

1.  我们需要打开 Terminal（macOS 或 Linux）或 Command Prompt/PowerShell（Windows）并执行以下命令：

```js
> vue create my-first-project
```

1.  CLI 将询问一些问题，这些问题将有助于创建项目。您可以使用箭头键进行导航，*Enter*键继续，*Spacebar*键选择选项：

```js
?  Please pick a preset: (Use arrow keys)  default (babel, eslint) ❯ **Manually select features** ‌
```

1.  有两种方法可以启动一个新项目。默认方法是一个基本的`babel`和`eslint`项目，没有任何插件或配置，还有`手动`模式，您可以选择更多的模式、插件、linters 和选项。我们将选择`手动`。

1.  现在，我们被问及我们将在项目中需要的功能。这些功能是一些 Vue 插件，如 Vuex 或 Router（Vue-Router）、测试工具、linters 等：

```js
?  Check the features needed for your project: (Use arrow keys)  ❯ Babel
 TypeScript Progressive Web App (PWA) Support Router Vuex  CSS Pre-processors  ❯  Linter / Formatter
 Unit Testing  ❯ **E2E Testing**
```

1.  对于这个项目，我们将选择`CSS 预处理器`并按*Enter*继续：

```js
?  Check the features needed for your project: (Use arrow keys) ❯ Babel
 TypeScript Progressive Web App (PWA) Support Router Vuex ❯ CSS Pre-processors ❯ **Linter / Formatter**
 Unit Testing **E2E Testing**
```

1.  可以选择要与 Vue 一起使用的主要**层叠样式表**（**CSS**）预处理器——`Sass`、`Less`和`Stylus`。由您选择哪种最适合您：

```js
?  Pick a CSS pre-processor (PostCSS, Autoprefixer and CSS Modules
  are supported by default): (Use arrow keys) Sass/SCSS (with dart-sass)  Sass/SCSS (with node-sass)  **Less** ❯ Stylus 
```

1.  现在是格式化您的代码的时候了。您可以在`AirBnB`、`Standard`和`Prettier`之间进行选择，并使用基本配置。那些在`ESLint`中导入的规则可以随时进行自定义，没有任何问题，并且有一个完美的规则适合您的需求。您知道什么对您最好：

```js
?  Pick a linter / formatter config: (Use arrow keys) ESLint with error prevention only ❯ **ESLint + Airbnb config** ESLint + Standard config 
  ESLint + Prettier
```

1.  设置完 linting 规则后，我们需要定义它们何时应用于您的代码。它们可以在保存时应用，也可以在提交时进行修复：

```js
?  Pick additional lint features: (Use arrow keys) **Lint on save** ❯ Lint and fix on commit
```

1.  在定义所有这些插件、linters 和处理器之后，我们需要选择设置和配置存储的位置。存储它们的最佳位置是在一个专用文件中，但也可以将它们存储在`package.json`文件中：

```js
?  Where do you prefer placing config for Babel, ESLint, etc.?  (Use arrow keys) ❯ **In dedicated config files** In package.json
```

1.  现在，您可以选择是否要将此选择设置为将来项目的预设，以便您无需再次重新选择所有内容：

```js
?  Save this as a preset for future projects?  (y/N) n
```

1.  CLI 将自动创建具有您在第一步中设置的名称的文件夹，安装所有内容并配置项目。

您现在可以浏览和运行项目了。Vue CLI 项目的基本命令如下：

+   `npm run serve`—用于在本地运行开发服务器

+   `npm run build`—用于构建和缩小应用程序以进行部署

+   `npm run lint`—对代码执行 lint

您可以通过 Terminal（macOS 或 Linux）或 Command Prompt/PowerShell（Windows）执行这些命令。

## 还有更多...

CLI 内部有一个名为 Vue UI 的工具，可帮助管理 Vue 项目的过程。该工具将处理项目的依赖关系、插件和配置。

Vue UI 工具中的每个`npm`脚本都被命名为任务，在这些任务中，您可以获得实时统计数据，例如资产、模块和依赖项的大小；错误或警告的数量；以及更深入的网络数据，以微调您的应用程序。

要进入 Vue UI 界面，您需要在 Terminal（macOS 或 Linux）或 Command Prompt/PowerShell（Windows）中执行以下命令：

```js
> vue ui
```

## 另请参阅

在[`cli.vuejs.org/guide/`](https://cli.vuejs.org/guide/)找到有关 Vue CLI 项目的更多信息。

请在[`cli.vuejs.org/dev-guide/plugin-dev.html`](https://cli.vuejs.org/dev-guide/plugin-dev.html)找到有关 Vue CLI 插件开发的更多信息。

# 使用 Vue UI 向 Vue CLI 项目添加插件

Vue UI 工具是 Vue 开发中最强大的附加工具之一。它可以让开发人员的生活更轻松，同时可以帮助管理 Vue 项目。

## 准备就绪

此配方的先决条件如下：

+   Node.js 12+

所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

## 操作步骤...

首先，我们需要创建我们的 Vue CLI 项目。要找到如何创建 Vue CLI 项目，请查看“使用 Vue CLI 创建您的第一个项目”食谱。我们可以使用上一个食谱中创建的项目，也可以开始一个新项目。现在，按照说明添加插件：

1.  打开 Vue UI 界面。打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows），并执行以下命令：

```js
> vue ui
```

1.  将会出现一个新的浏览器窗口，其中包含**Vue UI**界面：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-cb/img/d3a3cfad-348f-4b99-972b-20e8b4a17da9.png)

在这里，您可以列出您的项目，创建一个新项目，或导入一个现有项目。

1.  现在，我们将导入我们创建的插件：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-cb/img/cbac28b4-9fc3-48bb-8ef2-3e12936b53a2.png)

您需要找到您创建的文件夹，然后单击“导入此文件夹”。

1.  文件夹导入后，项目的默认仪表板将出现：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-cb/img/6ae2b814-b9ef-4075-aef8-80c1269a3df3.png)

在这里，可以通过点击顶部的“自定义”按钮来自定义您的仪表板，添加新的小部件：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-cb/img/d3ce5759-4e4b-4b90-8670-6f06c3fda5b6.png)

1.  要添加新插件，必须单击左侧边栏中的“插件”菜单：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-cb/img/ac05cafd-3d9e-4954-941e-0ea1cd682c0f.png)

您在 Vue CLI 工具中添加的基本插件将已列在此处。

1.  现在，我们将添加基本的 Vue 生态系统插件—**vuex **和 **vue-router**：

**![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-cb/img/dd4f6c07-9065-4bd2-b501-a8cde63ce9f4.png)**

1.  如果您检查您的代码，您将看到`main.js`文件已更改，并且`vuex（store）`和`vue-router（router）`插件现在已导入并注入到 Vue 实例中：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-cb/img/224ff0ce-2ab6-4940-9384-b76e880e4e97.png)

## 工作原理...

Vue UI 插件与`npm`或`yarn`配合使用，自动安装项目中的软件包，然后在可能的情况下注入 Vue 实例所需的条件。

如果插件是一个可视化、指令或非直接实例化的插件，Vue UI 将安装并管理它，但您需要导入它以在应用程序中使用。

# 向 Vue CLI 项目添加 TypeScript

在 JavaScript 项目中使用 TypeScript，即使是用于静态类型检查，也是一个好的做法。它有助于最小化项目内部的错误和对象问题。

通过 Vue UI 的帮助向 Vue 项目添加 TypeScript 非常简单，您将能够使用 TypeScript 的 JavaScript 代码。

## 准备就绪

此食谱的先决条件如下：

+   Node.js 12+

所需的 Node.js 全局对象如下

+   `@vue/cli`

+   `@vue/cli-service-global`

## 如何做...

首先，我们需要创建我们的 Vue CLI 项目。要了解如何创建 Vue CLI 项目，请查看“使用 Vue CLI 创建您的第一个项目”食谱。我们可以使用上一个食谱中创建的项目，或者开始一个新项目。

要将 TypeScript 添加到 Vue CLI 项目中，请按照以下步骤进行：

1.  打开 Vue UI 界面。打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows），并执行以下命令：

```js
> vue ui
```

1.  在您的项目中，转到插件管理器，点击+添加插件，然后搜索`@vue/cli-plugin-typescript`：

**![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-cb/img/5e9f0beb-adf6-49ea-a689-c99b5ef8598f.png)**

1.  现在，点击页面底部的安装@vue/cli-plugin-typescript 按钮：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-cb/img/6bd694d2-d2f2-4b02-859a-2666ea0aba88.png)

1.  在插件下载完成之后，在最终安装之前，会要求您进行一些配置设置：

+   **使用类样式组件语法？**使用 TypeScript 的`vue-class-component`插件。

+   **与 TypeScript 一起使用 Babel（现代模式所需，自动检测的 polyfill，转译 JSX）？**激活 Babel 以在 TypeScript 编译器之外转译 TypeScript。

+   **使用 ESLint？**将 ESLint 用作`.ts`和`.tsx`文件的检查器。

+   **将所有.js 文件转换为.ts 文件？**在安装过程中自动将所有`.js`文件转换为`.ts`文件。

+   **允许编译.js 文件？**激活`tsconfig.json`标志以接受编译器中的`.js`文件。

1.  选择您的选项后，点击完成安装。

1.  现在，您的项目是一个 TypeScript Vue 项目，所有文件都已配置好，准备好进行编码：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-cb/img/b809b9f4-90dc-47fb-b188-896995149b1c.png)

## 它是如何工作的...

Vue UI 作为插件管理器将为您下载为 Vue 制作的 TypeScript 包，并安装和配置它以符合您选择的设置。

您的项目将根据您的规格进行更改和修改，然后准备好进行开发。

## 另请参阅

在[`github.com/typescript-eslint/typescript-eslint`](https://github.com/typescript-eslint/typescript-eslint)找到有关 TypeScript ESLint 的更多信息

在[`github.com/vuejs/vue-class-component`](https://github.com/vuejs/vue-class-component)找到有关`vue-class-component`的更多信息。

# 使用 vue-class-component 创建您的第一个 TypeScript Vue 组件

由于 Vue 组件是基于对象的，并且与 JavaScript 对象的`this`关键字有着密切的关系，因此开发 TypeScript 组件会有点混乱。

`vue-class-component`插件使用 ECMAScript 装饰器提案将静态类型的值直接传递给 Vue 组件，并使编译器更容易理解发生了什么。

## 准备工作

这个配方的前提条件如下：

+   Node.js 12+

所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

## 如何做...

首先，我们需要创建我们的 Vue CLI 项目。我们可以使用上一个配方中创建的项目，或者开始一个新的项目。要了解如何在 Vue CLI 项目中添加 TypeScript，请查看'*向 Vue CLI 项目添加 TypeScript*'配方。

按照说明使用 Typescript 和`vue-class-component`创建你的第一个 Vue 组件：

1.  在`src/components`文件夹内创建一个名为`Counter.vue`的新文件。

1.  现在，让我们开始制作 Vue 组件的脚本部分。我们将创建一个包含数字数据的类，两个方法——一个用于增加，另一个用于减少——最后，一个计算属性来格式化最终数据：

```js
<script lang="ts">
import Vue from 'vue';
import Component from 'vue-class-component';

@Component
export default class Counter extends Vue {
  valueNumber: number = 0;

  get formattedNumber() {
    return `Your total number is: ${this.valueNumber}`;
  }

  increase() {
    this.valueNumber += 1;
  }

  decrease() {
    this.valueNumber -= 1;
  }
}
</script>
```

1.  现在是时候为这个组件创建模板和渲染了。这个过程与 JavaScript Vue 文件相同。我们将添加增加和减少数值的按钮，并显示格式化的文本：

```js
<template>
  <div>
    <fieldset>
      <legend>{{ formattedNumber }}</legend>
        <button @click="increase">Increase</button>
        <button @click="decrease">Decrease</button>
    </fieldset>
  </div>
</template>
```

1.  在`App.vue`文件中，我们需要导入刚刚创建的组件：

```js
<template>
  <div id="app">
    <Counter />
  </div>
</template>

<script lang="ts">
import { Component, Vue } from 'vue-property-decorator';
import Counter from './components/Counter.vue';

@Component({
  components: {
    Counter,
  },
})
export default class App extends Vue {

}
</script>
<style lang="stylus">
  #app
    font-family 'Avenir', Helvetica, Arial, sans-serif
    -webkit-font-smoothing antialiased
    -moz-osx-font-smoothing grayscale
    text-align center
    color #2c3e50
    margin-top 60px
</style>
```

1.  现在，当你在终端(macOS 或 Linux)或命令提示符/PowerShell(Windows)上运行`npm run serve`命令时，你将看到你的组件在屏幕上运行和执行：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-cb/img/949d26cc-b0dc-4c6c-b2e7-0797000fc14a.png)

## 工作原理...

`vue-class-component`插件利用装饰器的新提案来向 TypeScript 类注入和传递一些属性。

这种注入有助于简化使用与 Vue 常见对象相比更符合 TypeScript 语法的组件开发过程。

## 另请参阅

在[`github.com/vuejs/vue-class-component`](https://github.com/vuejs/vue-class-component)找到更多关于`vue-class-component`的信息。

# 使用 vue-class-component 创建自定义 mixin

在 Vue 中，`mixin`是一种在其他 Vue 对象中重用相同代码的方式，就像将`mixin`的所有属性混合到组件中一样。

在使用 mixin 时，Vue 首先声明`mixin`属性，然后是组件值，因此组件始终是最后且有效的值。此合并以深度模式进行，并且已在框架内声明了特定的方式，但可以通过特殊配置进行更改。

通过使用 mixin，开发人员可以编写小段的代码并在许多组件中重用它们。

这种方法简化了您的工作，并允许您更快地完成任务。

## 准备工作

此食谱的先决条件如下：

+   Node.js 12+

所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

## 如何做...

首先，我们需要创建我们的 Vue CLI 项目。我们可以使用上一个食谱中创建的项目，或者开始一个新项目。要了解如何使用 TypeScript 创建 Vue CLI 项目，请查看'*使用 vue-class-component 创建您的第一个 TypeScript Vue 组件*'食谱。

在这个食谱中，我们将其分为两个独立的部分。首先，我们将创建计数器组件，然后我们将使用共享的代码来创建 mixin。

### 创建计数器组件

现在，按照以下说明使用`vue-class-component`创建自定义 mixin：

1.  我们需要在`src/components`文件夹中创建一个名为`CounterByTen.vue`的新组件。

1.  现在，让我们开始制作 Vue 组件的脚本部分。我们将创建一个类，其中将有一个类型为数字的变量和默认值为`0`；两种方法，一种是增加`10`，另一种是减少`10`；最后，一个计算属性来格式化最终数据：

```js
<script lang="ts">
import Vue from 'vue';
import Component from 'vue-class-component';

@Component
export default class CounterByTen extends Vue {
  valueNumber: number = 0;

  get formattedNumber() {
    return `Your total number is: ${this.valueNumber}`;
  }

  increase() {
    this.valueNumber += 10;
  }

  decrease() {
    this.valueNumber -= 10;
  }
}
</script>
```

1.  是时候为这个组件创建模板和渲染了。该过程与 JavaScript Vue 文件相同。我们将添加增加和减少值的按钮以及显示格式化文本的按钮：

```js
<template>
  <div>
    <fieldset>
      <legend>{{ this.formattedNumber }}</legend>
        <button @click="increase">Increase By Ten</button>
        <button @click="decrease">Decrease By Ten</button>
    </fieldset>
  </div>
</template>
```

1.  在`App.vue`文件中，我们需要导入刚刚创建的组件：

```js
<template>
  <div id="app">
    <Counter />
    <hr />
    <CounterByTen />
  </div>
</template>

<script lang="ts">
import { Component, Vue } from 'vue-property-decorator';
import Counter from './components/Counter.vue';
import CounterByTen from './components/CounterByTen.vue';

@Component({
  components: {
    Counter,
    CounterByTen,
  },
})
export default class App extends Vue {

}
</script>
<style lang="stylus">
  #app
    font-family 'Avenir', Helvetica, Arial, sans-serif
    -webkit-font-smoothing antialiased
    -moz-osx-font-smoothing grayscale
    text-align center
    color #2c3e50
    margin-top 60px
</style>
```

### 提取相似的代码以用于 mixin

由于这两个组件具有相似的代码，我们可以提取这些相似的代码并创建一个 mixin。这个 mixin 可以在这两个组件中导入，它们的行为将是相同的：

1.  在`src/mixins`文件夹中创建一个名为`defaultNumber.ts`的文件。

1.  为了编写我们的 mixin，我们将从`vue-class-component`插件中导入`Component`和`Vue`修饰符，作为 mixin 的基础。我们需要采用类似的代码并将其放入 mixin 中：

```js
import Vue from 'vue';
import Component from 'vue-class-component';

@Component
export default class DefaultNumber extends Vue {
  valueNumber: number = 0;

  get formattedNumber() {
    return `Your total number is: ${this.valueNumber}`;
  }
}
```

1.  准备好 mixin 后，打开`src/components`文件夹中的`Counter.vue`组件并导入它。为此，我们需要从`vue-class-component`中导入一个特殊的导出，称为`mixins`，并将其与我们想要扩展的 mixin 扩展。这将删除`Vue`和`Component`装饰器，因为它们已经在 mixin 上声明了：

```js
<template>
  <div>
    <fieldset>
      <legend>{{ this.formattedNumber }}</legend>
      <button @click="increase">Increase By Ten</button>
      <button @click="decrease">Decrease By Ten</button>
    </fieldset>
  </div>
</template>

<script lang="ts">
import Vue from 'vue';
import Component, { mixins } from 'vue-class-component';
import DefaultNumber from '../mixins/defaultNumber';

@Component
export default class CounterByTen extends mixins(DefaultNumber) {
  increase() {
    this.valueNumber += 10;
  }

  decrease() {
    this.valueNumber -= 10;
  }
}
</script>
```

1.  现在，当您在终端（macOS 或 Linux）上运行`npm run serve`命令或在命令提示符/PowerShell（Windows）上运行时，您将看到您的组件在屏幕上运行和执行：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-cb/img/0d752567-7437-4e71-8ef5-4371d4a6f9a4.png)

## 它是如何工作的...

使用 TypeScript 使用 mixins 的过程与使用 Vue 对象的过程相同。共享的代码可以拆分成更小的文件，并在组件中调用，以便更轻松地编码。

在使用 TypeScript 和`vue-class-component`时，需要在 mixins 上声明`Vue`和`Component`装饰器，因为将使用 mixin 的类已经具有此扩展，因为它扩展了此 mixin。

我们将相同的代码片段放在两个组件中，然后将其放在一个新文件中，然后在两个组件中调用它。

## 另请参阅

了解有关`vue-class-component` mixins 的更多信息，请访问[`github.com/vuejs/vue-class-component#using-mixins`](https://github.com/vuejs/vue-class-component#using-mixins)。

了解有关 Vue mixins 的更多信息，请访问[`v3.vuejs.org/guide/mixins.html`](https://v3.vuejs.org/guide/mixins.html)

# 使用 vue-class-component 创建自定义函数装饰器

装饰器是在 ECMAScript 2015 中引入的。装饰器是一种高阶函数，它用另一个函数包装一个函数。

这为代码带来了许多新的改进，以及更大的生产力，因为它采用了函数式编程的原则并简化了它。

## 准备工作

此处的先决条件如下：

+   Node.js 12+

所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

## 如何做...

首先，我们需要创建我们的 Vue CLI 项目。要了解如何创建 Vue CLI 项目，请查看“*使用 Vue CLI 创建您的第一个项目*”食谱。我们可以使用上一个食谱中创建的项目，或者开始一个新项目。

按照以下步骤使用`vue-class-component`创建自定义函数装饰器：

1.  在`src/decorators`文件夹中创建一个名为`componentMount.js`的文件。

1.  我们需要从`vue-class-component`中导入`createDecorator`函数，以便在基于`vue-class-component`的组件上使用它，并开始编写我们的装饰器：

```js
import { createDecorator } from 'vue-class-component';
import componentMountLogger from './componentLogger';

export default createDecorator((options) => {
  options.mixins = [...options.mixins, componentMountLogger];
});
```

`createDecorator`函数就像 Vue vm *(View-Model)*的扩展，因此它不会有 ECMAScript 装饰器的属性，但会作为 Vue 装饰器的功能。

1.  我们需要在我们的装饰器中使用`componentLogger.js`文件。这个函数将获取在“装饰”组件中设置的所有数据值，并对其添加一个监视器。每当它改变时，这个监视器将记录新值和旧值。这个函数只有在调试数据设置为`true`时才会执行：

```js
export default {
  mounted() {
    if (this.debug) {
      const componentName = this.name || '';
      console.log(`The ${componentName} was mounted 
                                       successfully.`);

      const dataKeys = Object.keys(this.$data);

      if (dataKeys.length) {
        console.log('The base data are:');
        console.table(dataKeys);

        dataKeys.forEach((key) => {
          this.$watch(key, (newValue, oldValue) => {
            console.log(`The new value for ${key} is: 
                            ${newValue}`);
            console.log(`The old value for ${key} is: 
                            ${oldValue}`);
          }, {
            deep: true,
          });
        });
      }
    }
  },
};
```

1.  现在，我们需要将装饰器导入到位于`src/components`文件夹中的`Counter.vue`组件文件中，并向其添加调试器数据：

```js
<template>
  <div>
    <fieldset>
      <legend>{{ this.formattedNumber }}</legend>
      <button @click="increase">Increase</button>
      <button@click="decrease">Decrease</button>
    </fieldset>
  </div>
</template>

<script lang="ts">
import Vue from 'vue';
import Component from 'vue-class-component';
import componentMount from '../decorators/componentMount';

@Component
@componentMount
export default class Counter extends Vue {
  valueNumber: number = 0;

  debug: boolean = true;

  get formattedNumber() {
    return `Your total number is: ${this.valueNumber}`;
  }

  increase() {
    this.valueNumber += 1;
  }

  decrease() {
    this.valueNumber -= 1;
  }
}
</script>
```

## 它是如何工作的...

`createDecorator`函数是一个工厂函数，它扩展了 Vue vm（View Model），产生了 Vue 组件的扩展，比如一个 Vue mixin。Vue mixin 是 Vue 组件的一个属性，可以用来在组件之间共享和重用代码。

当我们调用 mixin 时，它将当前组件作为第一个参数的选项（如果它附加到属性，则为键），以及它的索引。

我们添加了一个动态调试器，只有在存在调试数据并且设置为`true`时才会附加。这个调试器将记录当前数据，并为数据的更改设置监视器，每次数据更改时都会在控制台上显示日志。

## 还有更多...

在使用 linters 时，一些规则可能会成为装饰器的问题。因此，明智的做法是仅在出现规则问题的文件上禁用它们，这些规则是代码正常工作所必需的。

例如，在 AirBnB 风格中，`no-param-reassign`规则是必需的，因为装饰器使用选项作为传递值的引用。

## 另请参阅

在[`github.com/vuejs/vue-class-component#create-custom-decorators`](https://github.com/vuejs/vue-class-component#create-custom-decorators)找到有关使用`vue-class-component`创建自定义装饰器的更多信息。

在[`www.typescriptlang.org/docs/handbook/decorators.html`](https://www.typescriptlang.org/docs/handbook/decorators.html)找到有关 ECMAScript 装饰器的更多信息。

# 向 vue-class-component 添加自定义钩子

在 Vue 中，可以通过插件**应用程序编程接口（API）**向其生命周期添加钩子。最基本的例子是`vue-router`与导航守卫，例如`beforeRouterEnter`和`beforeRouterLeave`函数钩子。

钩子，顾名思义，是每次发生某事时调用的小函数。

您可以利用这些钩子，使它们更加强大，为您的组件添加新的功能，例如检查特殊安全访问、添加**搜索引擎优化**（**SEO**）甚至预取数据。

## 准备工作

此配方的先决条件如下：

+   Node.js 12+

所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

## 如何做...

首先，我们需要创建我们的 Vue CLI 项目。我们可以使用上一个配方中创建的项目，也可以开始一个新项目。要了解如何在 Vue CLI 项目中添加 TypeScript，请查看'*向 Vue CLI 项目添加 TypeScript*'配方。

现在，按照以下步骤，使用 TypeScript 和`vue-class-component`为您的 Vue 项目添加自定义钩子：

1.  我们需要将`vue-router`添加到项目中。这可以在创建 Vue CLI 项目时完成，也可以在创建项目后的 Vue UI 界面中完成。

如果提示选择模式，应该运行`vue-router`。请注意，选择**History**选项将在部署时需要特殊的服务器配置。

1.  打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows），执行`npm run serve`命令，您将看到`vue-router`正在工作，并且有两个工作路由器：`home`和`about`。

1.  让我们开始创建并命名我们的钩子以注册到主应用程序。为此，我们需要在`src/classComponentsHooks`文件夹中创建一个`vue-router.js`文件：

```js
import Component from 'vue-class-component';

Component.registerHooks([
  'beforeRouteEnter',
  'beforeRouteLeave',
]);
```

1.  我们需要将这个文件导入到`main.ts`文件中，因为它需要在应用程序最终构建之前被调用：

```js
import './classComponentsHooks/vue-router';

import Vue from 'vue';
import App from './App.vue';
import router from './router';

Vue.config.productionTip = false;

new Vue({
 router,
 render: h => h(App),
}).$mount('#app');
```

1.  现在，我们已经在`vue-class-component`中注册了这些钩子，并且它们可以在 TypeScript 组件中使用。

1.  我们需要在`src/views`文件夹中创建一个名为`Secure.vue`的新路由位置。安全页面将有一个输入密码，`vuejs`。当用户输入此密码时，路由守卫将授予权限，用户可以看到页面。如果密码错误，用户将被带回到主页。当他们离开页面时，警报将向用户显示一条消息：

```js
<template>
  <div class="secure">
    <h1>This is an secure page</h1>
  </div>
</template>

<script lang="ts">
import { Component, Vue } from 'vue-property-decorator';
import { Route, RawLocation } from 'vue-router';

type RouteNext = (to?: RawLocation | false | ((vm: Vue) => any) | 
   void) => void;

@Component
export default class Home extends Vue {
  beforeRouteEnter(to: Route, from: Route, next: RouteNext) {
    const securePassword = 'vuejs';

    const userPassword = prompt('What is the password?');

    if (userPassword === securePassword) {
      next();
    } else if (!userPassword) {
      next('/');
    }
  }

  beforeRouteLeave(to: Route, from: Route, next: RouteNext) {
    alert('Bye!');
    next();
  }
}
</script>
```

1.  现在我们的页面已经完成，我们需要将其添加到`router.ts`文件中，以便在 Vue 应用程序中调用它：

```js
import Vue from 'vue';
import Router from 'vue-router';
import Home from './views/Home.vue';

Vue.use(Router);

export default new Router({
  routes: [
    {
      path: '/',
      name: 'home',
      component: Home,
    },
    {
      path: '/about',
      name: 'about',
      component: () => import('./views/About.vue'),
    },
    {
      path: '/secure',
      name: 'secure',
      component: () => import('./views/Secure.vue'),
    },
  ],
});
```

1.  路由添加完成并创建视图后，最后一步是将链接添加到主`App.vue`文件中，这样我们就会得到一个集成了钩子的组件：

```js
<template>
  <div id="app">
    <div id="nav">
      <router-link to="/">Home</router-link> |
      <router-link to="/about">About</router-link> |
      <router-link to="/secure">Secure</router-link>
    </div>
    <router-view/>
  </div>
</template>
<style lang="stylus">
#app
  font-family 'Avenir', Helvetica, Arial, sans-serif
  -webkit-font-smoothing antialiased
  -moz-osx-font-smoothing grayscale
   text-align center
   color #2c3e50

#nav
  padding 30px
  a
    font-weight bold
    color #2c3e50
    &.router-link-exact-active
      color #42b983
</style>
```

## 它是如何工作的...

在执行 Vue 应用程序之前，类组件需要了解被添加到 Vue 原型的导航守卫是什么。因此，我们需要在`main.ts`文件的第一行导入自定义钩子。

在组件中，通过注册钩子，可以将它们添加为方法，因为`vue-class-component`已经将所有这些自定义导入转换为组件装饰器的基本方法。

我们使用了两个`vue-router`导航守卫的钩子。这些钩子在每次路由进入或离开时都会被调用。我们没有使用的前两个参数`to`和`from`是携带有关未来路由和过去路由的信息的参数。

`next`函数总是必需的，因为它执行路由更改。如果在函数中没有传递参数，路由将继续使用被调用的路由，但如果想要即时更改路由，可以传递参数来改变用户将要前往的位置。

## 另请参阅

在[`router.vuejs.org/guide/advanced/navigation-guards.html`](https://router.vuejs.org/guide/advanced/navigation-guards.html)中了解更多关于 vue-router 导航守卫的信息。

在[`github.com/vuejs/vue-class-component#adding-custom-hooks`](https://github.com/vuejs/vue-class-component#adding-custom-hooks)中了解更多关于 vue-class-component 钩子的信息。

# 将 vue-property-decorator 添加到 vue-class-component

Vue 中一些最重要的部分在`vue-class-component`中以 TypeScript 装饰器的形式缺失。因此，社区制作了一个名为`vue-property-decorator`的库，这个库得到了 Vue 核心团队的全力支持。

这个库引入了一些缺失的部分，如 ECMAScript 提案装饰器，比如`props`、`watch`、`model`、`inject`等。

## 准备工作

这个教程的先决条件如下：

+   Node.js 12+

所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

## 如何做...

首先，我们需要创建 Vue CLI 项目。我们可以使用上一个示例中创建的项目，也可以开始一个新项目。要了解如何使用 TypeScript 创建 Vue CLI 项目，请查看'*使用 vue-class-component 创建自定义 mixin*'示例。

按照以下步骤将`vue-property-decorator`添加到 Vue`基于类的组件`中：

1.  我们需要将`vue-property-decorator`添加到我们的项目中。打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows），并执行以下命令：

```js
> npm install -S vue-property-decorator
```

1.  在组件的 mixin 中，我们将添加一个装饰器来接收一个 prop，这将是我们计算的数字的值：

```js
import {
  Vue,
  Component,
  Prop,
} from 'vue-property-decorator';

@Component
export default class DefaultNumber extends Vue {
  valueNumber: number = 0;

  @Prop(Number) readonly value: number | undefined;

  get formattedNumber() {
    return `Your total number is: ${this.valueNumber}`;
  }
}
```

1.  有了这个数字，当值发生变化时，我们需要使观察者向父组件发出事件，并在父组件内部值发生变化时更新值。为此，我们需要在`src/mixins`文件夹内创建一个名为`numberWatcher.ts`的新文件：

```js
import {
  Watch,
  Mixins,
} from 'vue-property-decorator';
import DefaultNumber from './defaultNumber';

export default class NumberWatchers extends Mixins(DefaultNumber) {
  @Watch('valueNumber')
  onValueNumberChanged(val: number) {
    this.$emit('input', val);
  }

  @Watch('value', { immediate: true })
  onValueChanged(val: number) {
    this.valueNumber = val;
  }
}
```

在 Vue 中，`v-model`指令的工作原理类似于糖语法，它是 Vue `$emit`函数和 Vue `props`函数的组合。当值发生变化时，组件需要使用`'input'`名称进行`$emit`，并且组件需要在`props`函数中有一个`value`键，这将是从父组件传递到子组件的值。

1.  随着我们的 mixin 更新，我们的组件也需要更新。首先，我们将更新`Counter.vue`组件，将导入的 mixin 从`defaultNumber.ts`文件更改为`numberWatcher.ts`：

```js
<template>
  <div>
    <fieldset>
      <legend>{{ this.formattedNumber }}</legend>
      <button @click="increase">Increase</button>
      <button @click="decrease">Decrease</button>
    </fieldset>
  </div>
</template>

<script lang="ts">
import Vue from 'vue';
import Component, { mixins } from 'vue-class-component';
import NumberWatcher from '../mixins/numberWatcher';

@Component
export default class Counter extends mixins(NumberWatcher) {
  increase() {
    this.valueNumber += 1;
  }

  decrease() {
    this.valueNumber -= 1;
  }
}
</script>
```

1.  现在，我们将更新`CounterByTen.vue`组件，并添加新创建的 mixin：

```js
<template>
  <div>
    <fieldset>
      <legend>{{ this.formattedNumber }}</legend>
      <button @click="increase">Increase By Ten</button>
      <button @click="decrease">Decrease By Ten</button>
    </fieldset>
  </div>
</template>

<script lang="ts">
import Vue from 'vue';
import Component, { mixins } from 'vue-class-component';
import NumberWatcher from '../mixins/numberWatcher';

@Component
export default class CounterByTen extends mixins(NumberWatcher) {
  increase() {
    this.valueNumber += 10;
  }

  decrease() {
    this.valueNumber -= 10;
  }
}
</script>
```

1.  一切就绪后，我们只需要更新`App.vue`组件。这一次，我们将在组件中存储一个变量，该变量将传递给两个子组件，当组件发出更新事件时，此变量将自动更改，也会更新其他组件：

```js
<template>
  <div id="app">
    <Counter
      v-model="amount"
    />
    <hr />
    <CounterByTen
      v-model="amount"
    />
  </div>
</template>

<script lang="ts">
import { Component, Vue } from 'vue-property-decorator';
import Counter from './components/Counter.vue';
import CounterByTen from './components/CounterByTen.vue';

@Component({
  components: {
    Counter,
    CounterByTen,
  },
})
export default class App extends Vue {
  amount: number = 0;
}
</script>
<style lang="stylus">
  #app
    font-family 'Avenir', Helvetica, Arial, sans-serif
    -webkit-font-smoothing antialiased
    -moz-osx-font-smoothing grayscale
    text-align center
    color #2c3e50
    margin-top 60px
</style>
```

## 工作原理...

通过在`vue-class-components`中注入装饰器，`vue-property-decorator`帮助 TypeScript 编译器检查 Vue 代码的类型和静态分析。

我们使用了两个可用的装饰器，`@Watch`和`@Prop`装饰器。

当我们将代码的常见部分拆分成 mixin 的形式时，流程实现变得更加容易。

父组件向子组件传递了一个属性，传递了初始值和随后更新的值。

这个值在子组件内部进行检查和更新，用于更新计算函数使用的本地变量。当计算完成并且值发生变化时，watcher 会发出一个事件，传递给父组件，父组件更新主变量，循环继续。

## 还有更多...

还有另一个库，它与`vue-property-decorator`相同，但用于`vuex`插件，名为`vuex-class`。

这个库使用与`vue-property-decorator`相同的过程。它在组件中创建一个 inject 装饰器。这些装饰器帮助 TypeScript 编译器在开发过程中检查类型。

您可以在[`github.com/ktsn/vuex-class/`](https://github.com/ktsn/vuex-class/)找到有关这个库的更多信息。

## 另请参阅

您可以在[`github.com/kaorun343/vue-property-decorator`](https://github.com/kaorun343/vue-property-decorator)找到有关`vue-property-decorator`的更多信息。
