# Vue 快速启动指南（三）

> 原文：[`zh.annas-archive.org/md5/056a1fe7509ea158cc95e0fe373880b7`](https://zh.annas-archive.org/md5/056a1fe7509ea158cc95e0fe373880b7)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：使用 Vuex

在本章中，我们将学习如何通过使用 Vuex 在 Vue 中管理复杂状态。Vuex 有助于处理 Vue 应用程序中状态管理和深度嵌套组件的问题。

在本章结束时，您将了解 Vuex 解决了什么问题以及它是如何解决这些问题的，您应该了解所有移动部分的适用位置。您还将了解如何构建一个简单的 Vuex 应用程序以及在考虑扩展它时应采取的方法。

具体来说，我们将讨论以下主题：

+   理解状态

+   状态管理、数据存储和单向数据流

+   热重载

+   构建一个非常简单的 Vuex 应用程序

+   如何从 Vue DevTools 的 Vuex 选项卡更新状态

+   构建一个更复杂的 Vuex 应用程序

让我们首先了解状态到底是什么。

# 什么是状态？

应用程序的状态是其在某一时间点的所有数据。由于我们通常关注当前应用程序的状态，我们可以将其重新表述为以下内容：状态是应用程序当前的数据，是由应用程序采取的先前步骤和应用程序内部的函数对用户交互做出响应而产生的。

那么，在我们的应用程序中是什么改变了它的状态呢？当然是函数。用户与我们的应用程序交互，触发函数来将当前状态更改为其他状态。

然而，随着我们的应用程序增长，组件嵌套几层是很常见的。如果我们说状态是应用程序在任何给定时间应该显示在屏幕上的“真相之源”，那么让我们尽可能地使这个真相之源易于理解和简单易用对我们来说是有益的。

很不幸，在复杂的应用程序中，这并不容易。我们应用的任何部分，应用内的任何组件都可能影响应用的任何其他部分。在我们的应用程序中管理状态有点像玩打地鼠游戏：应用程序中的一个部分的交互会导致应用程序的其他部分出现问题。

关于如何在前端应用程序中管理复杂状态的最佳实践的思考导致了诸如“数据存储”和“单向数据流”等概念。

# 状态管理、数据存储和单向数据流

管理复杂状态问题的常见解决方案是存储的概念：一个保持应用程序状态所有数据的唯一真相源。一旦我们有了这个中心位置—**存储**—我们就可以更容易地理解状态，因为现在只需要将状态数据发送到那些在应用程序生命周期中任何时候都需要它的组件。

为了使状态更新更简单，我们需要限制这些更新的方式。这就是单向数据流的作用。通过单向数据流，我们规定了数据在应用程序内部流动的规则，这意味着数据（状态）只能以有限的方式流动，使得在需要时更容易理解状态和调试状态。这种方法也是一个很好的时间节省者，因为现在作为开发者，我们知道可以期待什么；也就是说，要寻找我们知道状态是**可变**的地方。

# Vuex 状态管理模式

Vuex 是 Vue 的一个插件，由 Vue 的核心团队开发。设置非常简单。如果您需要一个快速的原型，您可以简单地从 CodePen 在线编辑器的设置中添加 Vuex 库，如第一章中所述，*介绍 Vue*。

您还可以通过 npm 安装它，使用以下命令：

```js
npm install --save vuex
```

当试图理解 Vuex 的工作原理时，通常会在网上找到描述 Vuex 作为受 Flux 强烈影响的状态管理模式的参考资料。这在一定程度上是正确的，但有趣的是 Flux 本身受到了 Elm 架构的启发。不管怎样，在 Vuex 中，数据流如下：

+   **Vue 组件**到动作

+   **动作**到变化

+   **变化**到状态

+   **状态**到 Vue 组件

数据总是以一种方式流动，最终回到起点，更新组件，然后*分发动作*，然后*提交变化*，然后*改变状态*，然后*渲染组件*，循环重复。因此，从略微不同的角度看单向数据流，我们可以重新表述它，专注于动词来描述存储中数据发生的情况：

+   动作被*分发*

+   变化被*提交*

+   状态被*改变*

+   组件被*渲染*

再次看一下这种单向数据流，我们现在可以用这些名词来描述数据流：*组件*、*动作*、*突变*和*状态*。用动词描述数据流，我们可以将这个过程视为：*分发*、*提交*、*突变*和*渲染*。

在 Vuex 中查看数据流的这两种方式是同一个硬币的两面，是状态更新的同一个循环，因此将这两个简短的列表都记住并不会有害，因为它将有助于加快对基本 Vuex 概念的理解。

为了在视觉上加强这些解释，可以在官方的 Vuex 文档中找到这种单向数据流的图表，网址是：[`vuex.vuejs.org/vuex.png`](https://vuex.vuejs.org/vuex.png)。

你可能会问，为什么要采取这种间接的方式？为什么组件不能直接改变状态？这样做有两个主要原因：首先，在 JavaScript 世界中，异步代码只是一个事实，因此选择在 Vuex 中分离异步和同步操作。因此，动作被设置为异步的，所以它们可以，例如，从服务器获取一些数据，只有在这个异步数据获取完成后才能*提交* *突变*；由于突变是严格同步的，在服务器调用完成之前调用它们是没有意义的。其次，这种分离关注点的方式使得更容易跟踪状态变化，甚至包括时间旅行调试：按时间顺序重新运行突变以跟踪状态的变化并追踪错误。

在 Vuex 状态管理模式中，组件永远不能直接改变全局状态。突变会这样做。

在接下来的部分，我们将看看这些构建块中的每一个。

# store

**store**需要添加到 Vue 实例的根部，以便所有组件都可以共享这个集中的全局状态。通常，我们将 store 声明为`const`，然后在代码中稍后将其添加到作为参数传递给 Vue 构造函数的对象文字中，就像这样：

```js
const store = new Vuex.Store({ 
  // store details go here
})
new Vue({
 el: '#app',
 store: store,
 // etc
})
```

接下来，我们将学习有关获取器的知识。

# Vuex store 中的获取器

我们的 store 也可以有获取器。获取器允许我们在模板中从状态中返回值。它们有点像计算值。它们是只读的，意味着它们不能改变状态。它们的责任只是读取它并对其进行一些非破坏性的操作。然而，底层数据没有被突变。

因此，我们在存储中使用`getters`对全局状态执行一些非破坏性工作。那么我们接下来该怎么做呢？我们如何使用它们？我们在应用程序的另一侧使用它们——在组件内部——我们使用`computed`并从存储中返回`getters`的值。

# Vuex 存储变化

变化，顾名思义，改变状态，并且是同步的。改变状态的函数接收参数：现有状态和有效负载。有效负载参数是可选的。它们负责直接更新 Vuex 中的状态。您可以使用以下语法从操作中执行变化：`state.commit`。

# Vuex 存储中的操作

操作以异步和间接的方式更新状态，通过调用我们在存储中定义的一个或多个变化。因此，操作调用所需的变化。另一方面，在组件内部，要执行一个操作，我们使用存储的分派值，使用以下语法：`store.dispatch`。

现在让我们扩展我们的样板代码，包括我们刚刚讨论的内容：

```js
const store = new Vuex.Store({ 
  // store details go here; they usually have:
  state: {
    // state specified here
  },
  getters: {
    // getters are like computed values - they don't mutate state
 },
 mutations: {
   // they mutate the state and are synchronous, 
   // functions that mutate state can have arguments; these arguments are called 'payload'
 },
 actions: {
   // asynchronous functions that commit mutations
 }
})
new Vue({
 el: '#app',
 store,
 // etc
})
```

在 Vue 构造函数中，我们可以看到，使用 ES6 语法，可以简化构造函数对象字面参数中的`store: store`键值对，只需使用`store`。

# 热重载

另一个由 Webpack 的兴起带来的流行概念是热重载。当您的应用程序正在运行时，更新文件时，例如，在组件的一个文件中添加一些变化的作用域样式，Webpack 将热重载更新的文件，而不使用您应用程序中的状态。换句话说，它不会重新加载整个页面，而只会重新加载受更改影响的应用程序部分。这是有用的原因是，使用热模块替换，状态将被保留，如果刷新页面是不可能的。这带来了更快的开发时间和浏览器中更新的无缝体验的额外好处。

# 使用 Vuex 构建水果计数器应用程序

我们将构建的应用程序只是一个简单的水果计数器应用程序。目标是帮助用户确保每天吃五份水果，我们将设置一个简单的应用程序，开始时有五份水果可供食用，每次点击按钮时，它将减少`1`的数量。这样，我们可以跟踪我们的健康饮食目标。

我们将通过设置初始状态来开始我们的应用程序，其中只有一个键值对：

```js
const store = new Vuex.Store({
  state: {
    count: 5
  },
```

接下来，我们将设置`getters`。正如我们已经学过的，`getters`只返回状态：

```js
  getters: {
    counter(state) {
      return state.count;
    }
  },
```

接下来，我们将添加两个 mutations：第一个 mutation，`decrementCounter`，将通过减去 payload 参数中存储的值来操作计数器。我们将递减 state.count 的值，直到达到`0`。为了确保`state.count`的值不能小于`0`，我们将使用三元语句进行检查，并相应地设置其值。

第二个 mutation，`resetCounter`，将重置计数器的值为初始状态：

```js
  mutations: {
    decrementCounter(state, payload) {
      state.count = state.count - payload;
      state.count<0 ? state.count=0 : state.count
    },
    resetCounter(state) {
      state.count = 5;
    }
  },
```

接下来，我们将设置两个操作，`decrement` 和 `reset`：

```js
  actions: {
    decrement(state, payload) {
      state.commit("decrementCounter", payload);
    },
    reset(state) {
      state.commit("resetCounter");
    }
  }
```

最后，我们正在设置我们的应用，并在其 Vue 构造函数中指定`el`、`store`、`computed`和`methods`选项。

```js
const app = new Vue({
  el: "#app",
  store: store,
  computed: {
    count() {
      return store.getters.counter;
    }
  },
  methods: {
    eatFruit(amount) {
      store.dispatch("decrement", amount);
    },
    counterReset() {
      store.dispatch("reset");
    }
  }
});
```

接下来，在我们的 HTML 中，我们设置了我们简单应用的结构：

```js
<div id="app">
 <h1>Fruit to eat: {{count}}</h1>
 <button v-on:click="eatFruit(1)">Eat fruit!</button>
 <button v-on:click="counterReset()">Reset the counter</button>
</div>
```

可以在以下网址找到工作示例：[`codepen.io/AjdinImsirovic/pen/aRmENx`](https://codepen.io/AjdinImsirovic/pen/aRmENx)。

# 使用 Vue DevTools 插件跟踪我们的 Vuex 状态

如果你在 Chrome 扩展程序网上商店的搜索栏中输入`vuejs devtools`，你会得到一些结果。第一个结果是官方插件的稳定版本。第二个结果是 Vue DevTools 扩展的 beta 版本。要查看正在开发的所有选项，并了解这个插件的发展方向，最好安装 beta 版本。有趣的是，一旦在 Chrome DevTools 中打开，两个版本显示相同的信息。目前，消息显示为`Ready. Detected Vue 2.5.17-beta.0`。

与常规版本相比，实验版本多了一些标签，即`routing`和`performance`。然而，即使是现有的标签也有一些非常有用的改进。例如，Vuex 标签具有直接从 DevTools 内部更新状态的功能。要访问该功能，只需按下*F12*键打开 Chrome DevTools。将 DevTools 定位到使用 Vue 扩展的最佳方法是将其设置为`Dock to bottom`选项。这个选项可以通过按下位于 DevTools 窗格右上角的 DevTools 关闭图标旁边的三个垂直点图标（*自定义和控制 DevTools*图标）来访问。

启用底部停靠后，打开 Vue 标签，然后在其中激活 Vuex 标签，您将看到两个窗格。最初，左窗格列出了基本状态。这个窗格列出了所有的变化，并允许我们进行时间旅行调试。右窗格列出了实际的负载、状态和变化，因此它给了我们更细粒度的视图，让我们了解在任何给定的变化中发生了什么。要进行任何特定变化的时间旅行，只需将鼠标悬停在其上，然后单击“时间旅行”图标。您还可以选择在列出的任何变化上运行“提交”或“还原”。正如您可能猜到的那样，当执行“提交”命令时，将对当前悬停的变化执行提交，而“还原”命令将撤消特定变化的提交。

另一个有用且有趣的功能是能够直接从 Vuex 标签更新状态。例如，假设我们点击了“吃水果！”按钮几次。现在，我们可以点击变化窗格中的任何给定的“减少计数”变化，然后在右窗格中得到以下信息：

```js
▼ mutation
    payload: 1
    type: ''decrementCounter''
▼ state
    count: 1
▼ getters
    counter: 1
```

使用这个窗格非常简单。如果我们需要更新我们的状态，在“状态”条目内悬停在“计数：1”上将触发四个图标的出现：编辑值图标、减号图标、加号图标和“复制值”图标，显示为三个垂直点。在这里，我们还可以看到“getter”是只读的证据。悬停在“getter”条目上不会显示任何编辑图标。与此相反，“状态”和“变化”条目都可以从这个窗格中进行编辑。

# 改进我们的水果计数应用程序

在本节中，我们将对我们的水果计数应用程序进行一些改进。目标是看看我们如何使用 Vuex 来扩展我们的应用程序。

我们将通过添加额外的功能来更新我们的应用程序。即，我们将为不同的水果添加按钮：苹果和梨。要吃的水果数量以及吃的水果的数量和种类也将出现在我们的应用程序中。

这是更新后的 JS 代码。我们首先定义存储中的状态：

```js
const store = new Vuex.Store({
  state: {
    count: 5,
    apples: 0,
    pears: 0
  },
```

接下来，我们设置 getter：

```js
  getters: {
    counter(state) {
      return state.count;
    },
    appleCount(state) {
      return state.apples;
    },
    pearCount(state) {
      return state.pears;
    }
  },
```

在定义变化时，我们需要`decrementWithApplesCounter`和`decrementWithPearsCounter`，以及`resetCounter`功能：

```js
  mutations: {
    decrementWithApplesCounter(state, payload) {
      state.count = state.count - 1;
      state.count < 0 ? (state.count = 0) : (state.count, state.apples 
       += 1);
    },
    decrementWithPearsCounter(state, payload) {
      state.count = state.count - 1;
      state.count < 0 ? (state.count = 0) : (state.count, state.pears 
      += 1);
    },
    resetCounter(state) {
      state.count = 5;
      state.apples = 0;
      state.pears = 0;
    }
  },
```

接下来，我们将列出我们的动作，`decrementWithApples`，`decrementWithPears`和“重置”：

```js
  actions: {
     decrementWithApples(state, payload) {
       setTimeout(() => {
         state.commit("decrementWithApplesCounter", payload);
       }, 1000)
     }, 
    decrementWithPears(state, payload) {
      state.commit("decrementWithPearsCounter", payload);
    },
    reset(state) {
      state.commit("resetCounter");
    }
  }
});
```

我们将通过添加 Vue 构造函数来结束它：

```js
const app = new Vue({
  el: "#app",
  store: store,
  computed: {
    count() {
      return store.getters.counter;
    },
    apples() {
      return store.getters.appleCount;
    },
    pears() {
      return store.getters.pearCount;
    }
  },
  methods: {
    eatApples(payload) {
      store.dispatch("decrementWithApples", payload);
    },
    eatPears(payload) {
      store.dispatch("decrementWithPears", payload);
    },
    counterReset() {
      store.dispatch("reset");
    }
  }
});
```

正如我们在这段代码中看到的，我们可以在 JS 三元运算符中更新多个变量的值。我们还使用`setTimeout()`函数调用来“模拟”对服务器的调用；这是不必要的，但用作更复杂的异步操作的示例。

更新后的 HTML 代码将如下所示：

```js
<div id="app" class="p-3">
  <h1>Fruit to eat: {{ count }}</h1>
  <p>Eaten: {{ apples }} apples, {{ pears }} pears</p>
  <button v-on:click="eatApples(1)" class="btn btn-success">
    An apple!
  </button>
  <button v-on:click="eatPears(1)" class="btn btn-warning">
    A pear!
  </button>
  <button v-on:click="counterReset()" class="btn btn-danger">
    Reset the counter
  </button>
</div>
```

更新后的示例应用程序可以在这里找到：[`codepen.io/AjdinImsirovic/pen/EdNaaO`](https://codepen.io/AjdinImsirovic/pen/EdNaaO)。

# 总结

在本章中，我们了解了 Vuex，这是一个强大的 Vue 插件，可以帮助我们从集中式全局存储管理状态。我们了解了什么是状态，以及为什么需要在更复杂的应用程序中集中数据存储。我们讨论了单向数据流及其在 Vuex 中的实现，通过使用 getter、store mutation 和 store action。我们从理论转向实践，首先构建了一个简单的应用程序，然后学习如何借助 Vue Devtools 扩展来简化我们的开发过程。

在下一节中，我们将使用 Vue-router 进行路由处理，并学习使用 Nuxt 进行服务器端渲染。


# 第八章：使用 Nuxt.js 和 Vue-Router

随着**单页应用**（**SPA**）的兴起，出现了一些特定的问题。针对这些问题已经有了各种尝试，并且一些常见的解决方案也从这些尝试中出现。在本节中，我们将看看围绕 SPA 的问题以及在 Vue 中解决这些问题的方法。

在这一章中，我们将使用 Nuxt.js 和 Vue-Router 来理解一些概念：

+   单页应用

+   初始页面加载

+   服务器端渲染和通用 Web 应用

+   安装 Nuxt.js

+   Nuxt 页面作为路由

+   使用`nuxt-link`标签链接页面

我们将首先了解 SPA 是什么以及它们是如何工作的。

# 单页应用和服务器端渲染

传统上，Web 服务器只提供静态内容。当用户在应用中请求一个链接时，通常服务器会处理该请求并将处理结果作为整个页面发送给客户端，包括 HTML、CSS 和由浏览器提供的 JS。这发生在请求 Web 应用中的每个路由时。如果开发人员想要查看浏览器发送的内容，只需在所选浏览器中运行`view source`命令即可。

查看源代码的快捷键在一些浏览器中传统上是*Ctrl* + *U*，比如 Chrome 和 Firefox。

随着网络体验向桌面端靠拢的推动，近年来我们看到了单页应用（SPA）的兴起。流行的 SPA 示例包括 Gmail、Twitter 和 Google Maps。

单页应用的工作方式是这样的：当用户在网站上浏览不同的页面（路由）时，浏览器不会下载一个全新的页面，也不会向服务器发送一个全新的请求。与其每次用户访问一个路由时从服务器下载完整页面不同，SPA 在客户端渲染所有内容。向服务器的请求仅用于获取新数据。

判断一个 Web 应用是否可以被视为 SPA 的一个好方法是：在应用中访问不同的路由是否会导致整个应用刷新？如果不会，那么它就是一个 SPA。

SPA 从服务器请求新数据，而传统 Web 应用从服务器下载整个页面。

这通常意味着所有的 SPA 代码将在一个页面加载中下载——**初始页面加载**。这包括 HTML、CSS 和 JS——所有的代码，没有这些代码，SPA 将无法运行。这种方法的缺点是，在较慢的网络上运行或者由于应用程序的体积过大时，下载时间可能会相当长，特别是考虑到许多这些 SPA 都充斥着 JavaScript 代码。

然而，如前所述，SPA 的目标是提供出色的用户体验，表现得像桌面应用程序一样，具有即时执行和无延迟。

解决这个问题的一个方法是引入**服务器端渲染**。服务器端渲染简单地说就是前端框架在服务器上准备 HTML、CSS 和 JS 的能力，因此当用户访问我们的 SPA 时，他们的浏览器不需要一次性下载整个应用程序，而只需下载部分代码——完整 SPA 的一部分——尽管如此，用户仍然可以与页面进行交互。通过代码分割和重新注水等概念，SPA 无缝地只下载应用程序的那部分内容，以便开始使用它，然后再下载 SPA 的其余部分，而用户已经在与之交互。这种方法减少了初始加载的延迟。

过去 SPA 的另一个主要问题是搜索引擎爬虫无法读取的问题。由于这些爬虫在爬取 SPA 网站时无法运行 JavaScript，访问的搜索引擎爬虫将无法看到 SPA 的内容。因此，服务器端渲染是加快 web 应用程序速度并使其更易于被搜索引擎爬虫索引的一种优雅方法。

当一个 web 应用程序可以在服务器和客户端上渲染网页时，它被称为**通用 web 应用程序**。通用 web 应用程序基本上是具有 SSR 能力的 SPA。

许多现代前端框架都有自己的 SSR 实现。在 Vue 中，这就是我们所说的 Nuxt.js。

# 安装 Nuxt.js 并预览默认项目

为了提供不同的路由，Nuxt.js 在后台使用 Vue-router。为了保持简单，我们将专注于使用 Nuxt.js。

有几种方法可以开始使用 Nuxt.js。一种选择是通过`vue init`命令。另一种是使用一种常见的实践，即`create-nuxt-app`命令，类似于`create-elm-app`或`create-react-app`。

# 使用 vue init 命令安装 Nuxt.js

让我们首先找到一个位置来保存我们的新 Nuxt 应用程序，然后使用`vue init`命令来创建它：

```js
vue init nuxt-community/stater-template chapter8
```

在未安装`vue init`的情况下运行此命令可能会在控制台中返回以下消息：

```js
Command vue init requires a global addon to be installed. 
Please run yarn global add @vue/cli-init and try again.
```

因此，要纠正问题，只需运行这个命令：

```js
yarn global add @vue/cli-init
```

这将需要一些时间，但最终我们将能够运行`**vue init**`命令：

```js
vue init nuxt-community/starter-template chapter8
```

这次运行前面的命令将导致我们需要回答一些问题，以便根据我们的喜好配置项目。与我们在 Vue-cli 中看到的类似，要接受默认值，我们可以简单地按下*Enter*键。

这是控制台的输出，包括所有问题和答案：

```js
? Project name (chapter8)
? Project name chapter8
? Project description (Nuxt.js project)
? Project description Nuxt.js project
? Author (AuthorName <author@email.com>)
? Author AuthorName <author@email.com>)
   vue-cli Generated "chapter 8"

   To get started:
     cd chapter8
     npm install # Or yarn
     npm run dev
```

让我们按照描述运行这些命令。我们将`cd`进入`chapter8`文件夹，然后运行`npm install`。这将产生一个输出，其中包括 Nuxt 标志的一些漂亮的 ASCII 艺术，贡献者和支持者的列表，以及其他项目信息。现在，我们可以运行`npm run dev`命令，这将产生以下输出：

```js
[11:12:14] Building project
[11:12:14] Builder initialized
...
[11:12:33] Listening on http://localhost:3000
```

如果我们访问`localhost:3000`页面，我们将看到标准的欢迎屏幕，其中有 Nuxt.js 标志，在下面将是我们项目的名称（chapter8），以及两个按钮：链接到文档和项目的 GitHub 存储库。

# 调试 eslint 错误

在撰写本书时，尽管所有软件都是最新的，`eslint`仍然会抛出错误。如果在运行`npm run dev`之后，您打开`localhost:3000`，您可能会在页面的左上角看到以下错误，指出 eslint 模块未定义。

如果发生这种情况，您可以通过打开代码编辑器中的`nuxt.config.js`文件，并将第 23 行后的所有代码替换为以下内容来修复它：

```js
  build: {
    /*
    ** Run ESLint on save
    */
    /*
    extend (config, { isDev, isClient }) {
      if (isDev && isClient) {
        config.module.rules.push({
          enforce: 'pre',
          test: /\.(js|vue)$/,
          loader: 'eslint-loader',
          exclude: /(node_modules)/
        })
      }
    }
    */
    extend(config) {
      if (process.server && process.browser) {
        config.module.rules.push({
          enforce: 'pre',
          test: /\.(js|vue)$/,
          loader: 'eslint-loader',
          exclude: /(node_modules)/
        })
      }
    } 
  }
}
```

在上面的代码中，我们已经注释掉了有问题的代码，并用正确的代码替换，以便比较差异并理解需要修复的内容。

现在我们可以重新运行`npm run dev`命令，我们应该在`localhost:3000`上看到应用程序没有任何错误。

# 使用 create-nuxt-app 安装

或者，我们可以使用`create-nuxt-app`命令。首先，我们需要全局安装它，以便我们可以在计算机的任何地方使用它：

```js
npm install -g create-nuxt-app
```

这个命令是全局安装的，可能需要一些时间。成功安装将在控制台中记录几行，即`create-nuxt-app`已安装在本地驱动器的位置，以及其他一些信息，类似于这样：

```js
+ create-nuxt-app@2.1.1
added 401 packages in 20.234s
```

接下来，让我们将控制台指向所需的文件夹，然后运行这个命令：

```js
create-nuxt-app chapter8b
```

与第一种安装方法类似，这种方法也会产生一些带有预设答案的问题，我们可以通过简单地按下*Enter*键来接受。这是带有默认答案的问题列表：

```js
$ create-nuxt-app chapter8b
> Generating Nuxt.js project in C:\Users\PC\Desktop\chapter8b
? Project name (chapter8b)
? Project name chapter8b
? Project description (My smashing Nuxt.js project)
? Project description My smashing Nuxt.js project
? Use a custom server framework (Use arrow keys)
? Use a custom server framework none
? Use a custom UI framework (Use arrow keys)
? Use a custom UI framework none
? Choose rendering mode (Use arrow keys)
? Choose rendering mode Universal
? Use axios module (Use arrow keys)
? Use axios module no
? Use eslint (Use arrow keys)
? Use eslint no
? Use prettier (Use arrow keys)
? Use prettier no
? Author name (AuthorName)
? Author name AuthorName
? Choose a package manager (Use arrow keys)
? Choose a package manager npm
Initialized empty Git repository in C:/Users/PC/Desktop/chapter8b/.git/
```

与先前的安装类似，我们可以看到运行样板项目的说明如下：

```js
  To get started:

    cd chapter8b
    npm run dev

  To build & start for production:

    cd chapter8b
    npm run build
    npm start
```

所以，让我们运行`cd chapter8b`，然后跟着运行`npm run dev`。输出将几乎与先前的安装方法相同。

# 编辑 index.vue 文件

让我们也编辑我们的`index.vue`文件，在`pages`文件夹中。这是我们应用程序的根路由。我们将进行的更改很小：我们将删除`<div class="links">`标签内的所有代码。更新后，该代码片段应如下所示：

```js
      <div class="links">
        <p>Vue Quickstart is a simple introduction to Vue</p>
      </div>
```

由于后台的 webpack 正在刷新我们的页面，所以在保存更改后，我们应该在浏览器中看到这个更改的结果：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-qk-st-gd/img/509c45c9-eafa-49bb-adc6-18151a4313a8.png)

到目前为止，我们已经看到了两种不同方式初始化新的 Vue Nuxt 项目。在下一节中，我们将看看 Nuxt 风格的实现`约定优于配置`方法：页面作为路由。

# Nuxt 页面作为路由

*约定优于配置*方法是由 Ruby on Rails 推广的。这是一种对 Web 开发的看法，以一种设置和忘记的方式在框架中设置一些东西。当我们说它是有看法的，它只是意味着在处理问题时，框架的开发人员选择了一种特定的方法，而这种方法是做某事的唯一方式。

我们可以说 Nuxt.js 是有看法的，因为它遵循页面作为路由的约定。因此，我们不必在应用程序中手动设置路由，而是遵循简单的约定。在页面文件夹中，`index.vue`文件充当根路由：`/`。这意味着如果我们运行我们的应用程序，访问`localhost:3000`的根路由等同于访问`localhost:3000/index.vue`。

同样地，如果我们创建一个名为`about.vue`的文件并将其放在页面文件夹中，要查看此文件，我们需要访问`localhost:3000/about`路由。

所以，让我们就这样做。在我们的页面文件夹中，我们将创建一个新文件并将其命名为`contact.vue`。在该文件中，我们将添加以下代码：

```js
<template>
  <h1>Contact</h1>
</template>
```

这就是使`/contact`路由可用所需的所有内容，您可以通过导航到`localhost:3000/contact`来查看。我们甚至可以将此文件设置为`contact`文件夹的默认根路由。在这种情况下，我们必须在`pages`文件夹内创建一个子文件夹，并将其命名为`contact`。现在，我们可以在新创建的`contact`文件夹内创建一个`index.vue`文件，路由将保持不变。只是我们在`pages`文件夹内的文件和文件夹结构略有改变，但最终结果是相同的。

然而，将文件分离成子文件夹将使您在添加更多文件时更容易保持组织。

# 通过`components`文件夹向 Nuxt 应用程序添加导航

在我们应用程序开发的这一点上，将导航放在适当的位置将是很好的。导航本身不是一个页面；它是一个应该存在于我们应用程序的每个页面中的组件。因此，让我们通过打开`components`文件夹并添加一个新文件来创建它，我们将其称为`Navigation.vue`。让我们向其中添加这段代码：

```js
<template>
  <div class="navigation">
    <ul>
        <li><nuxt-link to="/">Home</nuxt-link></li>
        <li><nuxt-link to="/contact">Contact</nuxt-link></li>
        <li><nuxt-link to="/news">News</nuxt-link></li>
    </ul>
  </div>
</template>

<style scoped>
.navigation {
    width: 100%;
    margin: 0;
    padding: 20px;
    background: orange;
    color: #444;
    font-family: Arial, sans-serif;
    font-size: 20px;
}
ul {
    list-style: none;
}
ul li {
    display: inline-block;
}
</style>
```

请注意`<nuxt-link>`标签。它只是 Vue-router 实现的一个包装器，`to="..."`属性的值是我们指定的实际 URL，它只是`pages`文件夹内特定文件的名称。

接下来，让我们找到`layouts`文件夹，在其中的`default.vue`文件中，让我们在模板中添加`Navigation`组件，使其看起来像这样：

```js
<template>
 <div>
 <Navigation></Navigation>
 <nuxt />
 </div>
</template>
```

请注意，我们可以自我关闭组件，所以我们可以写简写版本，而不是`<Navigation></Navigation>`，简写版本就是`<Navigation />`。

我们需要确保通过在`template`标签下方添加`script`标签来导入`Navigation`组件：

```js
<script>
import Navigation from '@/components/Navigation'
export default {
 components: {
 Navigation
 }
}
</script>
```

在这一点上，我们的主页，通过导航更新，将如下所示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-qk-st-gd/img/becea943-004f-400d-aadf-bd52bdbea07e.png)

现在我们的导航已经就位，我们将添加另一个页面，我们将其称为`News.vue`，代码如下：

```js
<template>
  <h1>News</h1>
</template>
```

在这一点上，我们的导航中有三个链接，现在我们可以专注于向每个页面添加更多内容。

# 向我们的 Nuxt 应用程序页面添加内容

让我们更新`News.vue`组件：

```js
<template>
  <section class="news">
    <h1>News</h1>
    <hr>
    <article>
        <h2>We are taking orders for our new product</h2>
        <div>
            Lorem ipsum dolor sit amet, consectetur adipisicing elit. Laudantium perspiciatis dolorem blanditiis maxime doloremque quibusdam obcaecati autem enim ipsum deserunt. Aliquid dolor consequatur repellendus odit, dolores possimus ab cum et voluptatem placeat sunt perferendis porro, eligendi perspiciatis harum pariatur veniam quo sed, reprehenderit voluptates maiores hic! Sint, facilis voluptatibus animi!
        </div>
    </article>
    <article>
        <h2>Our website is live</h2>
        <div>
            Lorem ipsum dolor sit amet, consectetur adipisicing elit. Delectus unde fugit quod, tempore enim obcaecati quam eius explicabo voluptates quo consequatur! Ad iste consequuntur dolorem minima at cupiditate veniam saepe voluptatum, qui hic corporis modi repellendus illum natus optio aut! Omnis praesentium placeat pariatur neque dolorum eaque, labore at et dignissimos impedit nobis, commodi rerum. Debitis est exercitationem ipsa, commodi nihil! Inventore minus ex, quam, facilis ut fuga unde harum possimus dolore ea voluptatum non debitis nihil ipsum repellendus aut dolorum nam nostrum assumenda eveniet corrupti consequatur obcaecati provident alias! Ad est minus repudiandae aliquid maxime provident labore. Asperiores, qui!
        </div>
    </article>
  </section>
</template>

<script>

</script>

<style scoped>
    .news {
        max-width: 500px;
        margin: 0 auto;
        padding-top: 30px;
        font-size: 20px;
    }
    .news article div {
        line-height: 30px;
    }
    h1, h2 {
        padding-top: 20px;
        padding-bottom: 20px;
    }
</style>
```

现在新闻链接将如下所示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-qk-st-gd/img/af719e3e-0cd8-476e-b961-e7a0e5eb12d0.png)

接下来，让我们更新`Contact.vue`组件：

```js
<template>
  <section class="contact">
    <h1>Contact</h1>
    <hr>
    <article>
        <h2>Feel free to get in touch!</h2>
        <div>
            <p>Our managers:</p>
            <ul>
                <li>John Doe, +01 123 4567</li>
                <li>Jane Doe, +01 124 4567</li>
                <li>Another Person, +01 125 4567</li>
            </ul>
        </div>
    </article>
  </section>
</template>

<script>

</script>

<style scoped>
    .contact {
        max-width: 500px;
        margin: 0 auto;
        padding-top: 30px;
        font-size: 20px;
    }
    .contact article div {
        line-height: 30px;
    }
    h1, h2 {
        padding-top: 20px;
        padding-bottom: 20px;
    }
</style>
```

我们不会改变 Nuxt.js 项目的原始主页。有限的更改原因是我们只需要有一些带有虚拟内容的页面，这样我们就可以继续到下一节，在那里我们将看到如何将页面过渡效果添加到我们的 Nuxt.js 应用程序中。

# 向我们的 Nuxt.js 应用程序添加页面过渡效果

正如我们在第六章中学到的，Vue 提供了许多方法来为我们的应用程序添加交互性、过渡效果和动画。为了加快这个过程，我们将使用`Animate.css`中的动画，稍作修改。

在 Nuxt 中，我们可以像我们已经学过的那样使用页面过渡钩子。我们只需将`.v-*`过渡钩子中的`v`字母替换为`.page-*`。所有的功能以及一切的工作方式都将保持不变。

让我们从打开`pages/index.vue`文件并在其`style`标签的顶部添加以下代码开始：

```js
.page-enter-active, .page-leave-active {
  transition: opacity 1s;
}
.page-enter, .page-leave-active {
  opacity: 0;
}
```

接下来，我们将打开`contact.vue`文件，并在其`style`标签的顶部添加以下代码：

```js
.page-enter-active {
    animation: zoomIn .5s;
} 
@keyframes zoomIn {
from {
    opacity: 0;
    transform: scale3d(0.4, 0.4, 0.4);
}

50% {
    opacity: 1;
}
}

.zoomIn {
animation-name: zoomIn;
}
```

最后，我们将使用以下代码更新`news.vue`的`style`标签顶部：

```js
.page-enter-active {
    animation: bounce .5s;
} 
.page-leave-active {
    animation: bounce .5s;
} 
@keyframes bounce {
    from,
    20%,
    55%,
    85%,
    to {
        animation-timing-function: cubic-bezier(0.320, 0.70, 0.355, 1);
        transform: translate3d(0, 0, 0);
    }

    40%,
    43% {
        animation-timing-function: cubic-bezier(0.700, 0.05, 0.855, 
         0.06);
        transform: translate3d(0, -30px, 0);
    }

    70% {
        animation-timing-function: cubic-bezier(0.700, 0.05, 0.855, 
        0.06);
        transform: translate3d(0, -15px, 0);
    }

    90% {
        transform: translate3d(0, -4px, 0);
    }
}
```

在这一点上，随时测试您的应用程序，并看看您如何通过对路由文件中的`style`标签进行少量更改来实现显著的视觉改进。

在本章中，我们了解了构建基本 Nuxt.js 应用程序的基础知识。有许多方法可以改进和扩展这一点。要继续构建更好的应用程序并了解更多关于在 Node 上运行 Vue 应用程序的知识，请随时参考 Packt 图书馆中的其他标题，比如*使用 Vue.js 和 Node 进行全栈 Web 开发*。

# 总结

在本章中，我们学习了关于单页面应用程序的知识，以及导致它们出现的想法，以及它们的实施带来的挑战，比如初始页面加载的问题。我们还学习了与 SPA 相关问题的解决方案，比如服务器端渲染，以及 Nuxt.js 如何帮助我们构建通用的 Web 应用程序。我们学习了如何安装 Nuxt.js 并设置 Nuxt.js 页面作为路由。我们使用`nuxt-link`标签链接了我们的 Vue 应用程序的路由，并为每个页面添加了一些内容。最后，为了建立在前几章学到的知识基础上，我们为更流畅的用户体验添加了一些页面过渡效果。

这就是*Vue JS 快速入门*的结尾。我们已经介绍了一整套基本的 Vue JS 概念。简要概述一下，我们可以重申一些我们所涵盖的内容：mustache 模板、指令、修饰符、方法、计算属性、观察者、组件（全局和本地）、props、生命周期钩子、vue-cli、插槽、父子组件通信、过滤器、混合、自定义指令和插件、过渡、动画、过渡组件、集成第三方动画、绑定样式、处理过渡组和 JavaScript 动画钩子、SPA、状态和存储的概念、单向数据流、使用 Vuex、处理初始页面加载、Nuxt、SSR 和通用 Web 应用程序。

在这本简短的书中，我们涵盖了很多内容。为了看到 Vue JS 的所有组成部分的全貌，我们必须保持基本。接下来该去哪里呢？

有几种方法可以进一步提高您的 Vue 相关技能。您可以专注于了解如何使用服务器端技术，比如 Node、Laravel 或.NET Core。您也可以使用 VuePress——一种使用 Vue 构建静态 JS 站点的方式。或者您可能想查看*Vuex 快速入门指南*。

为了更容易地继续提高您的 Vue.js 技能，Packt 图书馆中有超过两打本书可供您选择，其中包括涉及本摘要中列出的主题的书籍。
