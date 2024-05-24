# Vue2 Web 开发完全手册（八）

> 原文：[`zh.annas-archive.org/md5/E8B4B21F7ACD89D5DD2A27CD73B2E070`](https://zh.annas-archive.org/md5/E8B4B21F7ACD89D5DD2A27CD73B2E070)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十八章：使用 Vuex 的大型应用程序模式

在本章中，我们将涵盖以下配方：

+   在 vue-router 中动态加载页面

+   为应用程序状态构建一个简单的存储

+   理解 Vuex 的 mutations

+   在 Vuex 中列出你的操作

+   使用模块分离关注点

+   构建 getter 来帮助检索数据

+   测试你的存储

# 介绍

在本章中，你将学习 Vuex 的工作原理以及如何使用它来支持可扩展的应用程序。Vuex 实现了一种在前端框架中流行的模式，它包括将不同的关注点分开来管理一个大型全局应用程序状态。mutations 是唯一可以改变状态的东西，所以你只需要在一个地方查找它。大部分逻辑，以及所有的异步逻辑，都包含在 actions 中；最后，getters 和 modules 进一步帮助分散认知负荷，当涉及计算派生状态和将代码拆分成不同的文件时。

除了配方，你还会发现我在开发真正大型应用程序时发现有用的智慧之言；有些与命名约定有关，有些与避免错误的小技巧有关。

如果你完成了所有的配方，你将准备好开发大型前端应用程序，减少错误并实现无缝协作。

# 在 vue-router 中动态加载页面

很快，你将建立大量组件的大型 Vue 网站。加载大量 JavaScript 可能会产生浪费和无用的前期延迟。

# 准备工作

这个配方需要了解 vue-router。

# 如何做...

通过创建新目录并运行以下命令来使用`vue-cli`创建一个新项目：

```js
vue init webpack
```

你可以根据自己的喜好回答问题，只要在要求时将`vue-router`添加到模板中即可。

我们将创建两个组件：一个将是我们的主页，它将是小而轻的，另一个组件将非常大且加载速度很慢。我们想要实现的是立即加载主页，而不必等待浏览器下载巨大的组件。

打开`components`文件夹中的`Hello.vue`文件。删除所有内容，只留下以下内容：

```js
<template>
  <div>
    Lightweight hello
  </div>
</template>
```

在同一个文件夹中，创建另一个名为`Massive.vue`的文件，并在其中写入以下内容：

```js
<template>
  <div>
   Massive hello
  </div>
</template>

<script>
/* eslint-disable no-unused-vars */
const a = `
```

在最后一行留一个开放的反引号，因为我们必须用大量无用的数据膨胀文件。保存并关闭`Massive.vue`。

在控制台中，转到存储文件的相同目录，并使用以下文件将大量垃圾放入其中：

```js
yes "XXX" | head -n $((10**6)) >> Massive.vue
```

这个命令的作用是将`XXX`行重复附加到文件中 10⁶次；这将向文件添加 400 万字节，使其对于快速浏览体验来说太大了。

现在我们需要关闭我们打开的反引号。不要尝试现在打开文件，因为你的文本编辑器可能无法打开这样一个庞大的文件；相反，使用以下命令：

```js
echo '`</script>' >> Massive.vue
```

我们的`Massive`组件现在已经完成。

打开`router`文件夹中的`index.js`并添加组件及其路由：

```js
import Massive from '@/components/Massive'
...
export default new Router({
  routes: [
    {
      path: '/',
      name: 'Hello',
      component: Hello
    },
 {
 path: '/massive',
 name: 'Massive',
 component: Massive
 }
  ]
})
```

使用`npm install`安装所有依赖项后，我们现在可以使用`npm run dev`命令启动我们非常庞大的应用程序了。

该应用程序将加载得非常快，但这是因为它直接从您的本地存储加载；为了模拟更真实的情况，打开开发者工具中的网络选项卡，并选择网络限制。选择一些慢的东西，比如 GPRS 或者好的 3G，这是我们大多数人可能拥有的：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/cpl-vue2-web-dev/img/f48c0eb8-f26b-46a4-8776-b55eb26bb7a9.png)

现在右键单击刷新按钮，选择硬刷新以绕过缓存（或按*Shift* + *Cmd* + *R*）：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/cpl-vue2-web-dev/img/f2b2d058-173a-4601-bdc1-1c92008de325.png)

你会注意到页面加载需要几分钟的时间。当它变成 X 时，你可以通过再次单击刷新按钮来停止页面的加载。

为了解决这个问题，回到`router`文件夹中的`index.js`文件。删除以下行，其中你导入`Massive`组件：

```js
import Massive from '@/components/Massive'
```

前一行告诉 Webpack 将`Massive`组件中包含的所有代码都包含在一个单独的 js 捆绑包中。相反，我们希望告诉 Webpack 将`Massive`组件保持为一个单独的捆绑包，并且只在必要时加载它。

不要直接导入组件，使用以下代码声明`Massive`：

```js
const Massive = resolve =>
 require(['../components/Massive.vue'], resolve)
```

Webpack 将把这种特殊语法转换为一个单独的文件，它将被懒加载。保存并在仍然设置为慢速的限制下进行另一次硬刷新（比如 GPRS 到好的 3G）。几秒钟后，你应该能够看到 hello 页面。如果你想加载`Massive`组件，只需将`massive`添加到 URL 中，但你将需要等待一段时间。

# 它是如何工作的...

显然，在真实的应用程序中，你不会有这样一个庞大的组件，但你可以很容易地看到，如果`Massive`组件代表了你的应用程序的所有其他组件，它们很快就会累积成这样一个庞大的大小。

这里的诀窍是异步加载它们；Webpack 将帮助您将它们分成更小的包，这样它们只会在需要时加载。

# 还有更多...

有一种替代语法可以懒惰地导入组件。这可能会成为未来的 ECMA 标准，所以你应该意识到这一点。打开`router`目录内的`index.js`文件，并完全删除`Massive`组件的导入，或者我们在这个示例中添加的`Massive`常量行。

在路由内，当指定`/massive`路由的组件时，尝试以下操作：

```js
routes: [ {  path:  '/',
  name:  'Hello',
  component:  Hello
 }, {     path:  '/massive',
  name:  'Massive',
 component: import('@/components/Massive') } ] 
```

这将等同于我们之前所做的，因为 Webpack 将获取这行，并且不会直接导入 Massive 组件的代码，而是创建一个不同的 js 文件，懒加载加载。

# 为应用程序状态构建一个简单的存储

在这个示例中，您将了解在构建大型应用程序时 Vuex 的基本原理。这个示例有点不正统，因为为了理解 Vuex 存储的工作原理，我们将直接操作它；在真实应用程序中，你永远不应该这样做。

# 准备工作

在尝试这个示例之前，您应该知道如何让组件与 Vuex 通信。

# 如何做...

在一个新的目录中运行以下命令，基于 Webpack 模板创建一个新项目：

```js
vue init webpack
```

你如何回答这个问题并不重要。运行`npm intall`并使用`npm install vuex --save`或者如果你使用 yarn，使用`yarn add vuex`来安装 Vuex。

打开`src`文件夹内的`main.js`文件，并添加以下突出显示的行以完成安装 Vuex：

```js
import Vue from 'vue'
import App from './App'
import router from './router'
import store from './store'

/* eslint-disable no-new */
new Vue({
 el: '#app',
 router,
 store,
 template: '<App/>',
 components: { App }
})
```

当然，现在没有`store`模块，所以你需要创建一个。为此，在`src`文件夹下创建一个名为`store`的文件夹。在其中，创建一个名为`index.js`的文件。在`main.js`文件中，我们没有指定使用`index.js`文件，但当没有指定文件而只有文件夹时，这是默认行为。

我们将实现的是一个简化的股票市场。我们有三种资产：星星（STAR）、灯（LAMP）和钻石（DIAM）。我们将定义两条路线：一条用于 STAR/LAMP 市场，另一条用于 LAMP/DIAM 市场。

在存储文件夹中的`index.js`文件中，写入以下内容：

```js
import Vue from 'vue'
import Vuex from 'vuex'
Vue.use(Vuex)
const store = new Vuex.Store({
  state: {
    STAR: 100,
    LAMP: 100,
    DIAM: 100,
    rate: {
      STAR: {
        LAMP: 2
      },
      LAMP: {
        DIAM: 0.5
      }
    }
  }
})
export default store
```

我们正在创建一个新的`Vuex`存储，用于保存我们的余额。最初，我们每种资产有 100 个；在存储中，星星和灯之间的汇率以及灯和钻石之间的汇率也是固定的。

在`components`目录下创建一个名为`Market.vue`的新组件。它将具有以下模板：

```js
<template>
  <div class="market">
    <h2>{{symbol1}}/{{symbol2}} Stock Exchange</h2>
    <div class="buy-sell">
      <input v-model.number="amount">{{symbol1}}
      <button @click="buy">
        Buy for {{rate*amount}} {{symbol2}}
      </button>
      <button @click="sell">
        Sell for {{rate*amount}} {{symbol2}}
      </button>
    </div>
  </div>
</template>
```

`symbol1`和`symbol2`代表两种交易的资产。在这个组件的 JavaScript 中，我们定义了`sell`和`buy`方法，直接在全局`Vuex`存储上操作：

```js
<script>
export default {
  name: 'market',
  data () {
    return {
      amount: 0
    }
  },
  computed: {
    rate () {
      return this.$store.state.rate[this.symbol1][this.symbol2]
    }
  },
  props: ['symbol1', 'symbol2'],
  methods: {
    buy () {
      this.$store.state[this.symbol1] += this.amount
      this.$store.state[this.symbol2] -= this.amount * this.rate
    },
    sell () {
      this.$store.state[this.symbol1] -= this.amount
      this.$store.state[this.symbol2] += this.amount * this.rate
    }
  }
}
</script>
```

您不应该像我在这里所做的那样直接触摸状态。您应该始终使用 mutations。在这里，我们跳过中间人以保持食谱的最小化。关于 mutations 的更多内容将在下一个食谱中介绍。

您必须在`router`文件夹中的`index.js`中以以下方式使用此组件：

```js
import Vue from 'vue'
import Router from 'vue-router'
import Market from '@/components/Market'
Vue.use(Router)
export default new Router({
  routes: [
    {
      path: '/',
      redirect: '/STAR/LAMP'
    },
    {
      path: '/:symbol1/:symbol2',
      component: Market,
      props: true
    }
  ]
})
```

在上述代码中，我们对包含一对交易符号的任何路由使用`Market`组件。作为主页，我们使用 STAR/LAMP 市场。

为了显示一些导航链接到不同的市场和我们当前的余额，我们可以编辑`App.vue`组件，使用以下模板：

```js
<template>
  <div id="app">
    <nav>
      <ul>
        <li>
          <router-link to="/STAR/LAMP">STAR/LAMP Market</router-link>
        </li><li>
          <router-link to="/LAMP/DIAM">LAMP/DIAM Market</router-link>
        </li>
      </ul>
    </nav>
    <router-view></router-view>
    <div class="balance">
      Your balance is:
      <ul>
        <li>{{$store.state.STAR}} stars</li>
        <li>{{$store.state.LAMP}} lamps</li>
        <li>{{$store.state.DIAM}} diamonds</li>
      </ul>
    </div>
  </div>
</template>
```

对于这个组件，我们不需要任何 JavaScript，所以可以删除`<script>`标签。

我们的应用现在已经准备就绪；启动它并开始交易。以下图片是我们完成的应用程序，不包括`App.vue`中包含的样式：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/cpl-vue2-web-dev/img/95c7b7aa-c82a-487c-b2a0-ef250352da04.png)

# 它是如何工作的...

底部的余额就像全局状态的摘要。通过 Vuex，我们能够通过访问每个组件都被 Vuex 插件注入的`$store`变量来影响其他组件。当您想要基本上扩展变量的范围超出组件本身时，您可以很容易地想象如何在大型应用程序中使用这种策略。

一些状态可能是局部的，例如，如果您需要一些动画或者需要一些变量来显示组件的模态对话框；不将这些值放入存储中是完全可以的。否则，在一个地方拥有结构化的集中状态会帮助很多。在随后的食谱中，您将使用更高级的技术来更好地利用 Vuex 的力量。

# 理解 Vuex 的变异

在 Vuex 应用程序中，变异状态的正确方法是使用 mutations 的帮助。变异是将状态更改分解为原子单位的非常有用的抽象。在这个食谱中，我们将探讨这一点。

# 准备就绪

完成上一个食谱后，可以完成此食谱，而无需太多了解 Vuex。

# 如何做...

将 Vuex 作为项目的依赖项添加（CDN 地址为`https://unpkg.com/vuex`）。我假设您正在使用 JSFiddle 进行跟进；否则，请记住在存储代码之前放置`Vue.use(Vuex)`。

我们将构建的示例应用程序是向网站用户广播通知。

HTML 布局如下所示：

```js
<div id="app">
  <div v-for="(message, index) in messages"> 
    <p style="cursor:pointer">{{message}}
      <span @click="close(index)">[x]</span>
    </p>
  </div>
  <input v-model="newMessage" @keyUp.enter="broadcast">
  <button @click="broadcast">Broadcast</button>
</div>
```

这个想法是有一个文本框来写消息，广播的消息将显示在顶部，最近的消息将首先显示。可以通过点击小 x 来关闭消息。

首先，让我们构建一个存储库，用于保存广播消息列表并列举我们可以对该列表进行的可能变异：

```js
const store = new Vuex.Store({
  state: {
    messages: []
  },
  mutations: {
    pushMessage (state, message) {
      state.messages.push(message)
    },
    removeMessage (state, index) {
      state.messages.splice(index, 1)
    }
  }
})
```

因此，我们有一系列消息；我们可以将其中一个推送到列表的顶部，或者通过知道其索引来删除消息。

接下来，我们需要编写应用程序本身的逻辑：

```js
new Vue({
  store,
  el: '#app',
  data: {
    newMessage: ''
  },
  computed: Vuex.mapState(['messages']),
  methods: {
    broadcast () {
      store.commit('pushMessage', this.newMessage)
      this.newMessage = ''
    },
    close (index) {
      store.commit('removeMessage', index)
    }
  }
})
```

现在，您可以启动应用程序并开始向我们虚构的用户广播消息：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/cpl-vue2-web-dev/img/b0df8753-e8a1-468a-a5a8-9f6d4998a4ef.png)

# 它是如何工作的...

我认为重要的是要注意变异的名称；它们被称为`pushMessage`和`removeMessage`，但在这个应用程序中它们真正做的是在屏幕上显示消息，并（虚构地）向用户广播消息。将它们称为`showMessage`或`broadcastMessage`和`hideMessage`会更好吗？不会，因为变异本身和该变异的特定效果之间必须有明确的意图分离。当我们决定让用户有能力忽略这些通知或者在实际广播通知之前引入延迟时，问题就变得清晰了。然后我们将有一个`showMessage`变异，它实际上并不显示消息。

我们使用的计算语法如下所示：

```js
computed: Vuex.mapState(['messages'])
```

当您将 Vuex 作为 ES6 模块导入时，您不必在表达式中显式使用 Vuex。您只需要写

`import { mapState } from 'Vuex'`。

然后，`mapState`函数将可用。

`mapState`方法以字符串数组作为参数，查找存储中具有相同名称的`state`变量，并创建具有相同名称的计算属性。您可以使用任意数量的变量来做到这一点。

# 还有更多...

如果您在本地 npm 项目上跟随操作，请打开 Vue 开发者工具（不幸的是，在使用 JSFiddle 时，Vue 开发者工具不可用），您将看到每条消息都会发出一个新的变异。考虑一下，您点击了小时钟：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/cpl-vue2-web-dev/img/988d23d1-8897-430e-bf94-be7b51e37be7.png)

实际上，您可以使用它来撤消变异，如下图所示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/cpl-vue2-web-dev/img/19f87abf-9a68-4259-8bfc-55d060a5fce4.png)

请注意，当点击时间旅行选项时，状态并未发生变化；这是因为紫色丝带仍然停留在最后的状态。要查看不同的状态，只需点击变异名称本身。

这种调试机制是可能的，因为变异始终是同步的；这意味着可以在变异之前和之后对状态进行快照，并在时间轴上导航。在下一个食谱中，您将学习如何使用 Vuex 执行异步操作。

# 在 Vuex 中列出您的操作

您的所有变异必须是同步的，那么如何做一些等待超时或使用 Axios 进行 AJAX 请求的事情呢？操作是下一个抽象级别，将帮助您处理这些问题。在操作中，您可以提交多个变异并执行异步操作。

# 准备就绪

变异是操作的构建块，因此强烈建议您在尝试此操作之前完成前面的食谱。

我们将使用“为应用程序状态构建简单存储”食谱中的设置；您也可以使用自己的设置，但无论如何，此食谱都是基于官方 Webpack 模板的轻微修改。

# 如何做...

您将构建一个流行的 Xkcd 网站的克隆。实际上，它将更像是一个包装器，而不是一个真正的克隆，因为我们将重用网站上的面板。

基于 Webpack 模板创建一个 Vue 项目，使用`vue init webpack`命令。我们首先要做的是在`config`文件夹中的`index.js`中将 API 连接到 Xkcd 网站。将以下行放入`proxyTable`对象中：

```js
module.exports = {
  ...
  dev: {
    proxyTable: {
      '/comic': {
        target: 'https://xkcd.com',
        changeOrigin: true,
        pathRewrite: (path, req) => {
          const num = path.split('/')[2]
          return `/${num}/info.0.json`
        }
      }
    },
  ...
```

这将把我们发出的所有请求重定向到`/comic`到 Xkcd 网站。

在`src`目录下，创建一个新的`store`目录，并在其中创建一个`index.js`文件；在这里，开始构建应用程序存储：

```js
import Vue from 'vue'
import Vuex from 'vuex'

Vue.use(Vuex)

const store = new Vuex.Store({
  state: {
    currentPanel: undefined,
    currentImg: undefined,
    errorStack: []
  },
  actions: {},
  mutations: {}
}

export default store
```

您应该像以前的食谱一样在`main.js`中导入这个。我们想要跟踪当前面板编号，面板图像的链接以及可能的错误。修改状态的唯一方法是通过变异，而操作可以执行异步工作。

当应用程序加载时，我们计划显示最新的漫画。为此，我们创建一个动作：

```js
actions: {
  goToLastPanel ({ commit }) {
    axios.get(endpoint)
      .then(({ data }) => {
        commit('setPanel', data.num)
        commit('setImg', data.img)
      }).catch(error => {
        commit('pushError', error)
      })
  }
 ...
```

为了使此代码工作，我们需要声明端点并安装 Axios：

```js
...
import axios from 'axios'
...
const endpoint = '/comic/'
```

对于您来说，编写相应的突变应该很容易：

```js
mutations: {
  setPanel (state, num) {
    state.currentPanel = num
  },
  setImg (state, img) {
    state.currentImg = img
  },
  pushError (state, error) {
    state.errorStack.push(error)
  }
}
```

我们将重用`Hello.vue`组件，并在其中放入以下模板：

```js
<template>
  <div class="hello">
    <h1>XKCD</h1>
    <img :src="currentImg">
  </div>
</template>
```

为了在加载时显示最后一个面板，您可以在组件中使用以下 JavaScript：

```js
<script>
import { mapState } from 'vuex'
export default {
  name: 'hello',
  computed: mapState(['currentImg']),
  created () {
    this.$store.dispatch('goToLastPanel')
  }
}
</script>
```

此外，您可以删除大部分`App.vue`模板，只留下以下内容：

```js
<template>
  <div id="app">
    <router-view></router-view>
  </div>
</template>
```

# 它是如何工作的...

`proxyTable`对象将配置`http-proxy-middleware`。每当我们开发大型 Web 应用程序的 UI 并在`localhost`上启动开发服务器，但我们的 API 响应到另一个 Web 服务器时，这将非常有用。当我们想要使用 CORS 并且不允许其他网站使用我们的 API 时，这一点尤为重要。Xkcd API 不允许`localhost`消耗 Web 服务。这就是为什么，即使我们尝试直接使用 Xkcd API，我们的浏览器也不会让我们这样做。`changeOrigin`选项将以 Xkcd 为主机发送请求，从而使 CORS 变得不必要。

要从组件中调用一个动作，我们使用了`dispatch`函数。还可以传递第二个参数，第一个是动作本身的名称。然后在定义动作时将第二个参数传递。

关于命名的最后说明——在我的看法中，由于动作是异步的，而突变是同步的，因此无需在动作的名称中显式地表明异步性。

# 使用模块分离关注点

构建大型应用程序时，Vuex 存储可能会变得拥挤。幸运的是，可以使用模块将应用程序的不同关注点分成单独的区块。

# 准备工作

如果您想使用模块，这个示例可以作为参考。您应该已经对 Vuex 有足够的了解。

对于这个示例，您需要对 Webpack 有一定的了解。

# 如何做...

在这个示例中，我们将以稍微简化的方式对一个完全功能的人体进行建模。每个器官都将有一个单独的模块。

使用`vue init webpack`和`npm install vuex`创建一个新的 Webpack 模板。在其中创建一个包含`src/store/index.js`文件的新目录。在其中，写入以下内容：

```js
import Vue from 'vue'
import Vuex from 'vuex'

Vue.use(Vuex)

const store = new Vuex.Store({
  modules: {
    brain,
    heart
  }
})

export default store
```

`heart`模块是这样的；将其放在存储声明之前：

```js
const heart = {
  state: { loves: undefined },
  mutations: {
    love (state, target) {
      state.loves = target
    },
    unlove (state) {
      state.loves = undefined
    }
  }
}
```

请注意，传递给突变的状态不是根状态，而是模块的本地状态。

然后是大脑，它分为左叶叶和右叶叶；在存储之前写入以下内容：

```js
const brain = {
  modules: {
    left: leftLobe,
    right: rightLobe
  }
}
```

你可以将它们实现为简单的布尔状态（在它们所依赖的大脑之前写入）：

```js
const leftLobe = {
  namespaced: true,
  state: { reason: true },
  mutations: {
    toggle (state) { state.reason = !state.reason }
  }
}
const rightLobe = {
  namespaced: true,
  state: { fantasy: true },
  mutations: {
   toggle (state) { state.fantasy = !state.fantasy }
  }
}
```

将`namespaced`设置为 true 会修改你调用 mutator 的方式。因为它们都被称为`toggle`，现在你可以指定哪个叶叶，例如，对于左叶叶，变异字符串变成了`left/toggle`，其中`left`表示它是大脑中用来指代左叶叶的键。

要查看你的存储在运行中的情况，你可以创建一个使用所有变异的组件。对于大脑，我们可以有两张叶叶的图片，如下所示：

```js
<img 
 :class="{ off: !$store.state.brain.left.reason }"
 src="http://i.imgur.com/n8B6wuY.png"
 @click="left"><img
 :class="{ off: !$store.state.brain.right.fantasy }"
 src="http://i.imgur.com/4BbfVur.png"
 @click="right">
```

这将用红色铅笔创建两个大脑叶叶的图画；注意嵌套方式中模块名称的使用。以下的`off` CSS 规则会使叶叶变灰：

```js
.off {
  filter: grayscale(100%)
}
```

要调用变异，我们在正确的方法中使用上述字符串：

```js
methods: {
  left () {
    this.$store.commit('left/toggle')
  },
  right () {
    this.$store.commit('right/toggle')
  }
}
```

你也可以创建一个输入文本框，并调用其他两个变异，如下所示：

```js
...
love () {
  this.$store.commit('love', this.partner)
},
clear () {
  this.$store.commit('unlove')
  this.partner = undefined
}
...
```

这很容易，但是如何检索叶叶的名称呢？你可以在你的模板中放上这些大括号：

```js
<p> loves: {{$store.state.heart.loves}}</p>
<input v-model="partner" @input="love">
<button @click="clear">Clear</button>
```

显然，你必须在你的 Vue 实例上声明`partner`变量：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/cpl-vue2-web-dev/img/dfd584ca-c301-4db6-acda-b82b5e5b36c6.png)

# 它是如何工作的...

我们已经看到了如何使用模块将你的应用程序关注点分成不同的单元。随着项目规模的增长，这种能力可能变得很重要。

常见模式是，在变异中，你可以直接访问本地状态：

```js
const leftLobe = {
  namespaced: true,
  state: { reason: true },
  mutations: {
    toggle (state) {
      // here state is the left lobe state
      state.reason = !state.reason
    }
  }
}
```

在变异中，只有访问本地状态是有意义的。例如，大脑不能改变心脏，反之亦然，但动作呢？如果我们在模块内声明一个动作，我们会得到一个名为上下文的对象，看起来像这样：

```js
{
  "getters":{},
  "state":{
    "reason":true
  },
  "rootGetters":{},
  "rootState":{
    "brain":{
      "left":{
        "reason":true
      },
      "right":{
        "fantasy":false
      }
    },
    "heart":{
      "loves": "Johnny Toast"
    }
  }
}
```

因此，如果我们想在左叶叶中声明一个动作，并且想要影响心脏，我们必须做类似以下的事情：

```js
actions: {
  beNerd ({ rootState }) {
    rootState.heart.loves = 'Math & Physics'
  }
}
```

# 构建 getter 来帮助检索你的数据

你不想在你的状态中保存太多数据。保留重复或派生数据可能特别危险，因为它很容易失去同步。Getter 可以帮助你做到这一点，而不会将负担转移到组件上，因为它将所有逻辑都保存在一个地方。

# 准备工作

如果你已经具有一些 Vuex 知识并且想要拓展你的视野，那么这个教程适合你。

# 如何做...

想象一下，你正在构建一个比特币钱包。你想给你的用户一个余额概览，并且你希望他们看到它对应多少欧元。

使用`vue init webpack`和`npm install vuex`创建一个新的 Webpack 模板。创建一个新的`src/store/index.js`文件，并在其中写入以下内容：

```js
import Vue from 'vue'
import Vuex from 'vuex'

Vue.use(Vuex)

const store = new Vuex.Store({
  state: {
    bitcoin: 600,
    rate: 1000,
    euro: 600000
  }
})

export default store
```

这段代码容易出错。如果我们没有正确进行乘法运算，第一个错误可能是欧元金额的错误计算。第二种错误可能是在交易过程中告诉用户“比特币”和“欧元”余额，导致其中一种金额过时和错误。

为了解决这些问题，我们使用`getters`：

```js
const store = new Vuex.Store({
  state: {
    bitcoin: 600,
    rate: 1000
  },
  getters: {
    euro: state => state.bitcoin * state.rate
  }
})
```

这样，“欧元”金额永远不会在状态中，而是始终计算。此外，它是集中在存储中，因此我们不需要向我们的组件添加任何内容。

现在，从模板中轻松检索两个金额：

```js
<template>
  <div>
    <h1>Balance</h1>
    <ul>
      <li>{{$store.state.bitcoin}}฿</li>
      <li>{{$store.getters.euro}}&euro;</li>
    </ul>
  </div>
</template>
```

在这里，`&#3647 ;`是比特币符号的 HTML 实体。

# 它是如何工作的...

如果我们不谈论输入数据，为派生数据设置一个 getter 总是一个好主意。我们尚未讨论的 getter 的一个显着特点是它们能够与其他 getter 进行交互并接受参数。

# 访问其他 getter

调用 getter 时传递的第二个参数是包含其他`getters`的对象：

```js
getters:  {
 ...
  getCatPictures: state => state.pictures.filter(pic => isCat(pic)) getKittens:  (state, getters)  =>  {
 return getters.getCatPictures().filter(cat  => !isAdult(cat))
 } } 
```

在我们的示例中，我们可以调用`euro`getter 来获得一些更多的派生数据，比如我们可以用 150,000 欧元的平均价格大致计算出我们可以用比特币购买多少房屋：

```js
const store = new Vuex.Store({
  state: {
    bitcoin: 600,
    rate: 1000
  },
  getters: {
    euro: state => state.bitcoin * state.rate,
    houses: (state, getters) => getters.euro() / 150000
})
```

# 传递参数

如果 getter 返回一个带有参数的函数，那么该参数将成为 getter 的参数：

```js
getters: {
  ...
  getWorldWonder: state => nth => state.worldWonders[nth]
}
```

在我们的示例中，一个实际的例子可以指定前一段中的 getter 中房屋的平均成本：

```js
const store = new Vuex.Store({
  state: {
    bitcoin: 600,
    rate: 1000
  },
  getters: {
    euro: state => state.bitcoin * state.rate,
    houses: (state, getters) => averageHousePrice => {
 return getters.euro() / averageHousePrice
 }
})
```

# 测试您的 store

在这个示例中，您将为 Vuex 存储编写测试。

# 准备就绪

这个示例需要对单元测试和端到端测试有所了解，并且对 Vuex 有一些了解。

# 如何做...

首先，我将定义我们的存储必须实现的一些功能；然后，您将编写证明这些功能存在且正常工作的测试。

# 软件要求

我们的存储包括待办事项列表中的项目，如下所示：

```js
state: {
  todo: [
    { id: 43, text: 'Buy iPhone', done: false },
    ...
  ],
  archived: [
    { id: 2, text: 'Buy gramophone', done: true },
    ...
  ]
}
```

我们有两个要求：

+   我们必须有一个`MARK_ITEM_AS_DONE`mutation，将`done`字段从 false 更改为 true。

+   我们必须有一个`downloadNew`操作，从服务器下载最新项目并将其添加到列表中。

# 测试 mutations

为了能够测试您的 mutations，您必须使它们可用于您的测试文件。为此，您必须从存储中提取 mutation 对象。考虑类似于这样的东西：

```js
import Vuex from 'vuex'
import Vue from 'vue'

Vue.use(Vuex)

const store = new Vuex.Store({
  ...
  mutations: {
    ...
    MARK_ITEM_AS_DONE (state, itemId) {
      state.todo.filter(item => {
        return item.id === itemId
      }).forEach(item => {
        item.done = true
      })
      state.archived.filter(item => {
        return item.id === itemId
      }).forEach(item => {
        item.done = true
      })
    }
  }
}) 

export default store
```

您必须将其提取为类似于这样的东西：

```js
export const mutations = { ... }

const store = new Vuex.Store({ ... })

export default store
```

这样，您可以在测试文件中使用以下行导入突变：

```js
import { mutations } from '@/store'
```

对第 1 个要求的测试可以编写如下：

```js
describe('mutations', () => {
  it(`MARK_ITEM_AS_DONE mutation must change the
        done field from false to true for a todo`, () => {
    const state = {
      todo: [
        { id: 43, text: 'Buy iPhone', done: false }
      ],
      archived: [
        { id: 40, text: 'Buy cat', done: false }
      ]
    }
    mutations.MARK_ITEM_AS_DONE(state, 43)
    expect(state.todo[0].done).to.be.true
  })
})
```

如果您使用官方的 Webpack 模板，可以使用`npm run unit`运行测试。这默认使用 PhantomJS，它不实现一些功能。您可以使用 Babel polyfills，或者简单地进入`karma.conf.js`并在`browsers`数组中写入`Chrome`而不是`PhantomJS`。记得使用`npm install karma-chrome-launcher --save-dev`安装 Chrome 启动器。

# 测试行动

**测试行动**意味着测试行动是否提交了预期的突变。我们对突变本身不感兴趣（至少在单元测试中不感兴趣），因为它们已经单独测试过了。不过，我们可能需要模拟一些依赖关系。

为了避免依赖于 Vue 或 Vuex（因为我们不需要它们，它们可能会污染测试），我们在`store`目录中创建了一个新的`actions.js`文件。使用`npm install axios`安装 Axios。`actions.js`文件可以如下所示：

```js
import axios from 'axios'

export const actions = {
  downloadNew ({ commit }) {
    axios.get('/myNewPosts')
      .then(({ data }) => {
        commit('ADD_ITEMS', data)
      })
  }
}
```

为了测试第 2 个要求，我们首先模拟应该下载新待办事项的服务器调用：

```js
describe('actions', () => {
const actionsInjector = 
  require('inject-loader!@/store/actions')
const buyHouseTodo = {
  id: 84,
  text: 'Buy house',
  done: true
}
const actions = actionsInjector({
  'axios': {
    get () {
      return new Promise(resolve => {
        resolve({
          data: [buyHouseTodo]
        })
      })
    }
  }
}).default
}
```

这将确保对`axios`的`get`方法的任何调用都将始终返回一个新的待办事项。

然后，我们希望确保在调度时调用`ADD_ITEMS`突变：

```js
describe('actions', () => {
  const actionsInjector = 
    require('inject-loader!@/store/actions')
    const buyHouseTodo = {
      id: 84,
      text: 'Buy house',
      done: true
    }
    const actions = actionsInjector({
      'axios': {
        get () {
          return new Promise(resolve => {
            resolve({ data: [buyHouseTodo] })
          })
        }
      }
    }).default
    it(`downloadNew should commit ADD_ITEMS
    with the 'Buy house' todo when successful`, done => {
    const commit = (type, payload) => {
      try {
        expect(type).to.equal('ADD_ITEMS')
        expect(payload).to.deep.equal([buyHouseTodo])
        done()
      } catch (error) {
        done(error)
      }
    }
  actions.downloadNew({ commit })
  })
})
```

# 它是如何工作的...

对突变的测试非常简单，但我认为对行动的测试需要更多的解释。

由于我们不想依赖外部服务来执行操作，我们不得不模拟`axios`服务。我们使用`inject-loader`，它接受原始库并用任意代码模拟我们指定的部分（`@`符号是`src`的简写）；在我们的情况下，我们模拟了`axios`库，特别是`get`方法。我们必须使用 CommonJS 语法（带有`require`）因为这是告诉 Webpack 在导入时使用加载器的唯一方法。

在测试中，我们还模拟了`commit`函数。通常，这个函数调用一个修改状态的突变。我们只想知道是否调用了正确的突变，并且带有正确的参数。此外，我们必须将所有内容包装在`try`块中；如果没有它，测试将因超时而失败，我们将丢失错误。相反，现在我们立即失败，我们可以从控制台中读取导致测试失败的错误。


# 第十九章：与其他框架集成

在本章中，我们将探讨以下主题：

+   使用 Electron 构建通用应用程序

+   使用 Vue 与 Firebase

+   使用 Feathers 创建实时应用程序

+   使用 Horizon 创建一个响应式应用程序

# 介绍

Vue 很强大，但如果您需要后端，它单独做不了太多；至少您需要一个服务器来部署您的软件。在本节中，您将使用流行的框架实际构建小型但完整且可工作的应用程序。Electron 用于将 Vue 应用程序带到桌面。Firebase 是一个现代的云后端，最后，FeatherJS 是一个简约但功能齐全的 JavaScript 后端。完成这些后，您将拥有与它们交互并快速构建专业应用程序所需的所有工具。

# 使用 Electron 构建通用应用程序

Electron 是一个用于在 Mac、Linux 和 Windows 上运行通用应用程序的框架。它的核心是一个精简版的 Web 浏览器。它已被用于创建广泛使用的应用程序，如 Slack 和 Visual Studio Code 等。在这个示例中，您将使用 Electron 构建一个简单的应用程序。

# 准备工作

为了构建这个应用程序，我们将只使用基本的 Vue 功能。Electron 超出了本书的范围，但对于这个示例，不需要了解 Electron；事实上，这是学习更多关于 Electron 的好起点。

# 如何做...

在这个示例中，我们将构建一个小型但完整的应用程序--一个番茄钟应用程序。番茄钟是大约 25 个时间单位的间隔，您应该集中精力工作。之所以这样称呼它，是因为通常使用番茄形状的厨房计时器来测量时间。这个应用程序将跟踪时间，这样您就不必购买昂贵的厨房计时器了。

使用 Electron-Vue 模板是使用 Electron 快速启动 Vue 项目的最佳方法（你不说！）。可以通过以下命令轻松实现：

```js
vue init simulatedgreg/electron-vue pomodoro
```

您可以使用默认值进行回答，但当被问及要安装哪个插件时，只需选择`vue-electron`。使用`npm intall`安装所有依赖项，如果愿意，您可以在进行必要修改时保持应用程序处于热重新加载状态，方法是使用`npm run dev`。您可以通过单击角落的*x*来隐藏开发工具：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/cpl-vue2-web-dev/img/4b663c58-90af-4055-8293-1f5093f0c3a7.png)

首先，我们希望我们的应用程序尽可能小。让我们转到`app/src/main/index.js`文件；这个文件控制我们应用程序的生命周期。将窗口大小更改为以下内容：

```js
mainWindow = new BrowserWindow({
  height: 200,
  width: 300
})
```

然后，我们并不真的想要`app/src/render/components`文件夹中的样板组件，所以您可以删除所有内容。相反，创建一个`Pomodoro.vue`文件，并将此模板放入其中：

```js
<template>
  <div class="pomodoro">
    <p>Time remaining: {{formattedTime}}</p>
    <button v-if="remainingTime === 1500" @click="start">Start</button>
    <button v-else @click="stop">Stop</button>
  </div>
</template>
```

为了使其工作，我们还必须编写 JavaScript 部分，如下所示：

```js
<script>
export default {
  data () {
    return {
      remainingTime: 1500,
      timer: undefined
    }
  },
  methods: {
    start () {
      this.remainingTime -= 1
      this.timer = setInterval(() => {
        this.remainingTime -= 1
        if (this.remainingTime === 0) {
          clearInterval(this.timer)
        }
      }, 1000)
    },
    stop () {
      clearInterval(this.timer)
      this.remainingTime = 1500
    }
  }
}
</script>
```

这样，单击程序中的开始按钮将每秒减少 1 秒。单击停止按钮将清除计时器并将剩余时间重置为 1500 秒（25 分钟）。计时器对象基本上是`setInterval`操作的结果，`clearInterval`只是停止计时器正在执行的任何操作。

在我们的模板中，我们希望有一个`formattedTime`方法，以便以`mm:ss`格式查看时间，这比仅剩秒数更易读（即使更极客），因此我们需要添加计算函数：

```js
computed: {
  formattedTime () {
    const pad = num => ('0' + num).substr(-2)
    const minutes = Math.floor(this.remainingTime / 60)
    const seconds = this.remainingTime - minutes * 60
    return `${minutes}:${pad(seconds)}`
  }
}
```

要将此组件添加到应用程序中，请转到`App.vue`文件并编辑以下行，替换`landingPage`占位符元素：

```js
<template>
  <div id="#app">
 <pomodoro></pomodoro>
  </div>
</template>

<script>
 import Pomodoro from 'components/Pomodoro'
  export default {
    components: {
 Pomodoro
    }
  }
</script>
```

使用`npm run dev`启动应用程序，现在您应该能够在工作或学习时跟踪时间了：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/cpl-vue2-web-dev/img/fd0d4dbe-3de4-4f47-8468-3efb6f9b5281.png)

甚至可以使用`npm run build`命令构建应用程序的可分发版本。

# 工作原理...

我们实现的计时器方式对于时间跟踪来说并不特别准确。让我们来审查一下代码：

```js
this.timer = setInterval(() => {
  this.remainingTime -= 1
  if (this.remainingTime === 0) {
    clearInterval(this.timer)
  }
}, 1000)
```

这意味着我们每秒减少剩余时间。问题在于`setInterval`函数本身并不是 100%准确的，可能会在 1000 毫秒之前或之后触发函数，这取决于机器的计算负载；这样，误差会积累并变成相当大的数量。更好的方法是在每次循环时检查时钟并调整误差，尽管我们不会在这里涵盖这个问题。

# 使用 Vue 和 Firebase

使用 Vue 和 Firebase 作为后端非常容易，这要归功于 VueFire--一个包含 Firebase 绑定的插件。在这个示例中，您将开发一个完全功能的气味数据库。

# 准备工作

Firebase 超出了本书的范围，但是我将假设，对于这个示例，您对基本概念有所了解。除此之外，您真的没有太多需要了解的，因为我们将在此基础上构建一个非常基本的 Vue 应用程序。

# 如何做到这一点...

在开始编写代码之前，我们需要创建一个新的 Firebase 应用程序。要做到这一点，您必须登录[`firebase.google.com/`](https://firebase.google.com/)并创建一个新的应用程序。在我们的情况下，它将被称为`smell-diary`。您还需要记下您的 API 密钥，该密钥可以在项目设置中找到：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/cpl-vue2-web-dev/img/2c8d1943-fd1a-4a0f-a952-330556a2550d.png)

此外，您需要禁用身份验证；转到数据库部分，在规则选项卡中，将读取和写入都设置为 true：

```js
{
  "rules": {
    ".read": true,
    ".write": true
  }
}
```

我们已经完成了 Firebase 配置。

打开一个干净的 HTML5 样板或 JSFiddle，使用`Vue`作为库。我们需要将以下依赖项表示为文件头中的脚本标记：

```js
 <script src="https://unpkg.com/vue/dist/vue.js"></script>
 <script src="https://www.gstatic.com/firebasejs/3.6.9/firebase.js"></script>
 <script src="https://unpkg.com/vuefire/dist/vuefire.js"></script>
```

VueFire 将自动检测 Vue（因此顺序很重要）并将自身安装为插件。我们将构建一个非常简单的数据库来跟踪我们周围事物的气味。以下是我们应用程序的 HTML 布局：

```js
<div id="app">
  <ul>
    <li v-for="item in items">
      {{item.name}}: {{item.smell}}
    <button @click="removeItem(item['.key'])">X</button>
    </li>
  </ul>
  <form @submit.prevent="addItem">
    <input v-model="newItem" />
    smells like
    <input v-model="newSmell" />
    <button>Add #{{items.length}}</button>
  </form>
</div>
```

在我们应用程序的 JavaScript 部分，我们需要指定 API 密钥以用于与 Firebase 进行身份验证，写入以下内容：

```js
const config = {
  databaseURL: 'https://smell-diary.firebaseio.com/'
}
```

然后，我们将配置提供给 Firebase 并获取数据库的控制权：

```js
const firebaseApp = firebase.initializeApp(config)
 const db = firebaseApp.database()
```

这可以在`Vue`实例之外完成。VueFire 插件在`Vue`实例中安装了一个名为`firebase`的新选项；我们必须指定我们要使用`item`变量在 Firebase 应用程序中访问`/items`：

```js
new Vue({
  el: '#app',
  firebase: {
    items: db.ref('/items')
  }
})
```

`newItem`和`newSmell`变量将临时保存我们在输入框中输入的值；然后，`addItem`和`removeItem`方法将发布和从我们的数据库中删除数据：

```js
data: {
  newItem: '',
  newSmell: ''
},
methods: {
  addItem () {
    this.$firebaseRefs.items
      .push({
        name: this.newItem,
        smell: this.newSmell
      })
    this.newItem = ''
    this.newSmell = ''
  },
  removeItem (key) {
    this.$firebaseRefs.items
      .child(key).remove()
  }
}
```

如果您现在启动应用程序，您已经可以添加您最喜欢的香味以及嗅探它们的方式：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/cpl-vue2-web-dev/img/33587a24-2780-443a-b692-6cca4ef04804.png)

# 它是如何工作的...

Firebase 作为一个简单的键值存储。在我们的情况下，我们从不存储值，而是始终添加子项；您可以在 Firebase 控制台中查看您创建的内容：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/cpl-vue2-web-dev/img/aca1d8a4-febe-4a72-899a-5b6178349530.png)

密钥是自动生成的，它们包含空值和 32 级嵌套数据。我们使用一级嵌套来为每个对象插入名称和气味。

# 使用 Feathers 创建实时应用程序

大多数现代应用程序都是实时的，不是传统意义上的实时，而是它们不需要重新加载页面就可以更新。实现这一点最常见的方式是通过 WebSockets。在这个配方中，我们将利用 Feathers 和 Socket.io 来构建一个猫数据库。

# 准备工作

这个配方没有先决条件，但如果您想要更多上下文，可以在开始这个配方之前完成*创建 REST 客户端（和服务器！）*配方。

# 如何操作...

要完成这个配方，您需要 Feathers 的命令行；使用以下命令安装它：

```js
npm install -g feathers-cli
```

现在运行`feathers generate`，它将为您创建所有样板。在询问 API 时，选择 Socket.io：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/cpl-vue2-web-dev/img/8a98454d-93a9-44cf-b5ee-60dc29281d9b.png)

其他所有问题都可以保持默认值。在 Feather 控制台中，输入`generate service`来创建一个新的服务。您可以将其命名为 cats，并将其他问题保持默认值。

在`public`文件夹中，打开`index.html`并删除除了 HTML5 样板之外的所有内容。您需要在头部引入三个依赖项：

```js
 <script src="//cdnjs.cloudflare.com/ajax/libs/vue/2.1.10/vue.js"></script>
 <script src="//cdnjs.cloudflare.com/ajax/libs/socket.io/1.7.3/socket.io.js"></script>
 <script src="//unpkg.com/feathers-client@¹.0.0/dist/feathers.js"></script>
```

在`body`标签中编写 HTML 布局如下：

```js
<div id="app">
  <div v-for="cat in cats" style="display:inline-block">
    <img width="100" height="100" :src="cat.url" />
    <p>{{cat.name}}</p>
  </div>
  <form @submit.prevent="addCat">
    <div>
      <label>Cat Name</label>
      <input v-model="newName" />
    </div>
    <div>
      <label>Cat Url</label>
      <input v-model="newUrl" />
    </div>
    <button>Add cat</button>
    <img width="30" height="30" :src="newUrl" />
  </form>
</div>
```

第一个`<div>`标签是猫的画廊。然后，构建一个表单来添加您收集的猫的新图像。

在`body`标签中，您可以始终使用以下行配置 Feathers 服务：

```js
<script>
  const socket = io('http://localhost:3030')
  const app = feathers()
    .configure(feathers.socketio(socket))
  const catService = app.service('cats')
```

这是为了配置将连接到 WebSockets 的浏览器的客户端。`catService`方法是对猫数据库的处理。接下来，我们编写`Vue`实例：

```js
  new Vue({
    el: '#app',
    data: {
      cats: [],
      newName: '',
      newUrl: ''
    },
    methods: {
      addCat () {
        catService.create({
          name: this.newName,
          url: this.newUrl
        })
        this.newName = ''
        this.newUrl = ''
      }
    },
```

最后，我们需要在启动时请求数据库中的所有猫，并安装一个监听器以防其他用户创建新的猫：

```js
    mounted () {
      catService.find()
        .then(page => {
          this.cats = page.data
        })
      catService.on('created', cat => {
        this.cats.push(cat)
      })
    }
 })
 </script>
```

如果您使用`npm start`运行应用程序，可以导航到控制台中写的 URL 以查看您的新应用程序。打开另一个浏览器窗口，看看它如何实时变化：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/cpl-vue2-web-dev/img/39dea8ec-785d-4f97-94e6-d3e7d7ecaec7.png)

# 工作原理...

实时查看添加的猫显然是现代应用程序的选择。Feathers 让您可以轻松创建它们，并且只需少量代码，这要归功于底层的 Socket.io，后者又使用了 WebSockets。

WebSockets 实际上并不那么复杂，Feathers 在这种情况下所做的就是监听通道中的消息，并将它们与像向数据库添加内容这样的操作关联起来。

当你可以轻松切换数据库和 WebSocket 提供程序，或者切换到 REST 而不用触碰你的 Vue 代码时，Feathers 的强大之处就显而易见了。

# 使用 Horizon 创建一个反应式应用程序

Horizon 是一个构建反应式、实时可扩展应用程序的平台。它在内部使用 RethinkDB，并且与 Vue 立即兼容。在这个教程中，你将建立一个自动个人日记。

# 准备工作

这个教程只需要一点 Vue 基础知识，但真的没有其他什么。

不过，在开始之前，请确保你安装了 RethinkDB。你可以在他们的网站上找到更多信息（[`www.rethinkdb.com/docs/install/`](https://www.rethinkdb.com/docs/install/)）。如果你有 Homebrew，你可以用`brew install rethinkdb`来安装它。

此外，你还需要一个 Clarifai 令牌。要免费获取一个，请转到[`developer.clarifai.com/`](https://developer.clarifai.com/)并注册。你将看到你应该在你的应用程序中写的代码，就像下面的图片中一样：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/cpl-vue2-web-dev/img/fad87256-e661-42aa-baed-71c4f57ee058.png)

特别是，你将需要`clientId`和`clientSecret`，它们以这种方式显示：

```js
var app = new Clarifai.App( 'your client id would be printed here',
 'your client secret would be here' );
```

记下这段代码，或者准备好将其复制粘贴到你的应用程序中。

# 如何做...

写日记是一项艰巨的任务，每天都要写很多。在这个教程中，我们将建立一个基于我们白天拍摄的照片为我们写作的自动日记。

Horizon 将帮助我们记住一切，并在我们的设备之间同步日记。安装 RethinkDB 后，使用以下命令安装 Horizon：

```js
npm install -g horizon
```

现在，你将有一个新的命令`hz`可用。输入`hz -h`来检查它；你应该会看到类似以下的内容：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/cpl-vue2-web-dev/img/155e763b-076e-44c8-8d7e-dfdeb22442c2.png)

要创建一个将托管我们的新应用程序的目录，请输入以下内容：

```js
hz init vue_app
```

然后，进入新创建的`vue_app`目录，查看`dist`文件夹中的`index.html`。这个文件将是我们服务器的入口点，用编辑器打开它。

你可以清除一切，只留下一个空的 HTML5 样板，其中包含一个空的`<head>`和`<body>`。在头部部分，我们需要声明对 Vue、Horizon 和 Clarifai 的依赖，如下所示：

```js
 <script src="https://unpkg.com/vue"></script>
 <script src="/horizon/horizon.js"></script>
 <script src="https://sdk.clarifai.com/js/clarifai-latest.js"></script>
```

请注意，Horizon 并不是来自 CDN，而是来自本地依赖。

我们首先为我们的日记制定一个模板。我们有两部分。在第一部分中，我们将列出过去做过的事情。在 HTML 的主体中写入以下内容：

```js
<div id="app">
  <div>
    <h3>Dear diary...</h3>
    <ul>
      <li v-for="entry in entries">
        {{ entry.datetime.toLocaleDateString() }}:
        {{ entry.text }}
      </li>
    </ul>
  </div>
...
```

在第二部分中，我们将输入新条目：

```js
  ...
  <h3>New Entry</h3>
  <img
    style="max-width:200px;max-height:200px"
    :src="data_uri"
  />
  <input type="file" @change="selectFile" ref="file">
  <p v-if="tentativeEntries.length">Choose an entry</p>
  <button v-for="tentativeEntry in tentativeEntries" @click="send(tentativeEntry)">
    {{tentativeEntry}}
  </button>
</div>
```

在此之后，打开一个`<script>`标签，我们将在其中编写以下所有 JavaScript。

首先，我们需要登录到 Clarifai：

```js
var app = new Clarifai.App(
 '7CDIjv_VqEYfmFi_ygwKsKAaDe-LwEzc78CcW1sA',
 'XC0S9GHxS0iONFsAdiA2xOUuBsOhAT0jZWQTx4hl'
 )
```

显然，您希望输入 Clarifai 的`clientId`和`clientSecret`。

然后，我们需要启动 Horizon 并获得我们将创建的`entries`集合的句柄：

```js
const horizon = new Horizon()
const entries = horizon('entries')
```

现在，我们最终编写我们的`Vue`实例，其中包含三个状态变量：

```js
new Vue({
  el: '#app',
  data: {
    tentativeEntries: [],
    data_uri: undefined,
    entries: []
  },
  ...
```

`tentativeEntries`数组将包含我们可以选择的日记的可能条目列表；`data_uri`将包含我们想要用作今天所做事情的参考的图像（`base64`代码）；`entries`是所有过去的条目。

当我们加载图像时，我们要求 Clarifai 提出可能的条目：

```js
...
methods: {
  selectFile(e) {
  const file = e.target.files[0]
  const reader = new FileReader()
  if (file) {
    reader.addEventListener('load', () => {
      const data_uri = reader.result
      this.data_uri = data_uri
      const base64 = data_uri.split(',')[1]
      app.models.predict(Clarifai.GENERAL_MODEL, base64)
        .then(response => {
          this.tentativeEntries =
            response.outputs[0].data.concepts
            .map(c => c.name)
        })
      })
    reader.readAsDataURL(file)
  }
},
...
```

然后，当我们按下发送按钮时，我们告诉 Horizon 条目集存储这个新条目：

```js
    ...
    send(concept) {
      entries.store({
        text: concept,
         datetime: new Date()
      }).subscribe(
        result => console.log(result),
        error => console.log(error)
      )
      this.tentativeEntries = []
      this.$refs.file.value = ''
      this.data_uri = undefined
    }
  }
})
```

最后，我们希望在页面加载时确保屏幕上有最后十个条目，并且每次添加新条目时，它都会实时弹出。在 Vue 实例中的方法之后添加以下钩子：

```js
created() {
  entries.order('datetime', 'descending').limit(10).watch()
    .subscribe(allEntries => {
      this.entries = [...allEntries].reverse()
  })
}
```

要运行 Horizon 服务器，请使用以下命令：

```js
hz serve --dev
```

上述代码的输出如下：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/cpl-vue2-web-dev/img/8a109c8a-6316-4f4a-a920-b7ceb71cb750.png)

转到指定的地址（第一行，而不是管理界面），您将看到以下内容：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/cpl-vue2-web-dev/img/16bc7b43-df69-42e9-b206-4f7b7a30daa2.png)

您会注意到，如果您打开其他浏览器窗口，它们将实时更新。现在您终于可以每天写日记而不用打字了！

# 工作原理...

我们的应用程序使用一种称为响应式的模式。它的核心可以清楚地在创建的句柄中看到：

```js
entries.order('datetime', 'descending').limit(10).watch()
  .subscribe(allEntries => {
    this.entries = [...allEntries].reverse()
  })
```

第一行返回了所谓的响应式可观察对象。可观察对象可以被视为事件源。每次触发事件时，订阅者将对该事件进行处理。在我们的情况下，我们正在获取整个条目集合，并且抛出的事件是对该集合的修改。每当我们收到这种类型的事件时，我们就会更新`entries`数组。

我不会在这里提供有关响应式编程的深入解释，但我想强调这种模式非常有助于可扩展性，因为您可以轻松实现数据流的控制；`limit(10)`就是一个例子。


# 第二十章：Vue 路由模式

路由是任何**单页面应用**（**SPA**）的重要组成部分。本章重点介绍了如何最大化使用 Vue 路由器，并从用户页面之间的路由、参数到最佳配置进行了讨论。

到本章结束时，我们将涵盖以下内容：

+   在 Vue.js 应用程序中实现路由

+   使用动态路由匹配创建路由参数

+   将路由参数作为组件属性传递

# 单页面应用程序

现代 JavaScript 应用程序实现了一种称为 SPA 的模式。在其最简单的形式中，它可以被认为是根据 URL 显示组件的应用程序。由于模板被映射到路由，因此无需重新加载页面，因为它们可以根据用户导航的位置进行注入。

路由器的工作。

通过这种方式创建我们的应用程序，我们能够提高感知和实际速度，因为我们的应用程序更加动态。

# 使用路由器

让我们启动一个游乐项目并安装`vue-router`库。这使我们能够在应用程序内利用路由，并为我们提供现代 SPA 的功能。

在终端中运行以下命令：

```js
# Create a new Vue project
$ vue init webpack-simple vue-router-basics

# Navigate to directory
$ cd vue-router-basics

# Install dependencies
$ npm install

# Install Vue Router
$ npm install vue-router

# Run application
$ npm run dev
```

由于我们在构建系统中使用 webpack，我们已经使用`npm`安装了路由器。然后我们可以在`src/main.js`中初始化路由器：

```js
import Vue from 'vue';
import VueRouter from 'vue-router';

import App from './App.vue';

Vue.use(VueRouter);

new Vue({
  el: '#app',
  render: h => h(App)
});
```

这实际上将`VueRouter`注册为全局插件。插件只是一个接收`Vue`和`options`作为参数的函数，并允许诸如`VueRouter`之类的库向我们的 Vue 应用程序添加功能。

# 创建路由

然后，我们可以在`main.js`文件中定义两个简单的组件，它们只是有一个模板，显示带有一些文本的`h1`：

```js
const Hello = { template: `<h1>Hello</h1>` };
const World = { template: `<h1>World</h1>`};
```

然后，为了在特定的 URL（如`/hello`和`/world`）上在屏幕上显示这些组件，我们可以在应用程序内定义路由：

```js
const routes = [
  { path: '/hello', component: Hello },
  { path: '/world', component: World }
];
```

现在我们已经定义了我们想要使用的组件以及应用程序内的路由，我们需要创建一个新的`VueRouter`实例并传递路由。

尽管我们使用了`Vue.use(VueRouter)`，但我们仍需要创建一个新的`VueRouter`实例并初始化我们的路由。这是因为仅仅将`VueRouter`注册为插件，就可以让我们在 Vue 实例中访问路由选项：

```js
const router = new VueRouter({
  routes
});
```

然后，我们需要将`router`传递给我们的根 Vue 实例：

```js
new Vue({
  el: '#app',
  router,
  render: h => h(App)
});
```

最后，要在我们的`App.vue`组件中显示路由的组件，我们需要在`template`中添加`router-view`组件：

```js
<template>
  <div id="app">
    <router-view/>
  </div>
</template>
```

如果我们导航到`/#/hello/`或`/#/world`，将显示相应的组件：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/cpl-vue2-web-dev/img/b3d1083e-1788-45d4-a2cf-b4bdd945c407.png)

# 动态路由

我们还可以根据特定参数动态匹配路由。这可以通过在参数名之前指定一个冒号的路由来实现。以下是使用类似问候组件的示例：

```js
// Components
const Hello = { template: `<h1>Hello</h1>` };
const HelloName = { template: `<h1>Hello {{ $route.params.name}}` }

// Routes
const routes = [
 { path: '/hello', component: Hello },
 { path: '/hello/:name', component: HelloName },
]
```

如果我们的用户导航到`/hello`，他们将看到带有文本`Hello`的`h1`。否则，如果他们导航到`/hello/{name}`（即 Paul），他们将看到带有文本`Hello Paul`的`h1`。

我们取得了很大的进展，但重要的是要知道，当我们导航到参数化的 URL 时，如果参数发生变化（即从`/hello/paul`到`/hello/katie`），组件的生命周期钩子不会再次触发。我们很快会看到这一点！

# 路由 props

让我们将我们的`/hello/name`路由更改为将`name`参数作为`component`属性传递，这可以通过在路由中添加`props: true`标志来完成：

```js
const routes = [
  { path: '/hello', component: Hello },
  { path: '/hello/:name', component: HelloName, props: true},
]
```

然后，我们可以更新我们的组件以接受一个带有`name`的`id`属性，并在生命周期钩子中将其记录到控制台中：

```js
const HelloName = {
  props: ['name'],
  template: `<h1>Hello {{ name }}</h1>`,
  created() {
    console.log(`Hello ${this.name}`)
  }
}
```

如果我们尝试导航到不同的动态路由，我们会发现`created`钩子只会触发一次（除非我们刷新页面），即使我们的页面显示了正确的名称：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/cpl-vue2-web-dev/img/dde3492f-a29a-427f-a5e8-734c819d56f3.png)

# 组件导航守卫

我们如何解决生命周期钩子问题？在这种情况下，我们可以使用所谓的导航守卫。这允许我们钩入到路由器的不同生命周期中，比如`beforeRouteEnter`、`beforeRouteUpdate`和`beforeRouteLeave`方法。

# beforeRouteUpdate

让我们使用`beforeRouteUpdate`方法来访问有关路由更改的信息：

```js
const HelloName = {
  props: ['name'],
  template: `<h1>Hello {{ name }}</h1>`,
  beforeRouteUpdate(to, from, next) {
    console.log(to);
    console.log(from);
    console.log(`Hello ${to.params.name}`)
  },
}
```

如果我们在导航到`/hello/{name}`下的不同路由后检查 JavaScript 控制台，我们将能够看到用户要去的路由以及他们来自哪里。`to`和`from`对象还为我们提供了对`params`、查询、完整路径等的访问权限。

虽然我们正确地得到了日志记录，但如果我们尝试在路由之间导航，你会注意到我们的应用程序不会使用参数`name`属性进行更新。这是因为我们在守卫内完成任何计算后没有使用`next`函数。让我们添加进去：

```js
  beforeRouteUpdate(to, from, next) {
    console.log(to);
    console.log(from);
    console.log(`Hello ${to.params.name}`)
    next();
  },
```

# beforeRouteEnter

我们还可以利用`beforeRouteEnter`来在进入组件路由之前执行操作。这里有一个例子：

```js
 beforeRouteEnter(to, from, next) {
  console.log(`I'm called before entering the route!`)
  next();
 }
```

我们仍然必须调用`next`来将堆栈传递给下一个路由处理程序。

# beforeRouteLeave

我们还可以钩入`beforeRouteLeave`来在离开路由时执行操作。由于我们已经在这个钩子的上下文中在这个路由上，我们可以访问组件实例。让我们看一个例子：

```js
 beforeRouteLeave(to, from, next) {
 console.log(`I'm called before leaving the route!`)
 console.log(`I have access to the component instance, here's proof! 
 Name: ${this.name}`);
 next();
 }
```

再次，我们必须在这种情况下调用`next`。

# 全局路由钩子

我们已经研究了组件导航守卫，虽然这些守卫是基于组件的，但你可能想要建立全局钩子来监听导航事件。

# beforeEach

我们可以使用`router.beforeEach`来全局监听应用程序中的路由事件。如果你有认证检查或其他应该在每个路由中使用的功能，这是值得使用的。

这里有一个例子，简单地记录用户要去的路由和来自的路由。以下每个示例都假定路由器存在于类似以下范围的上下文中：

```js
const router = new VueRouter({
  routes
})

router.beforeEach((to, from, next) => {
 console.log(`Route to`, to)
 console.log(`Route from`, from)
 next();
});
```

再次，我们必须调用`next()`来触发下一个路由守卫。

# beforeResolve

`beforeResolve`全局路由守卫在确认导航之前触发，但重要的是要知道，这只是在所有特定于组件的守卫和异步组件已经解析之后。

这里有一个例子：

```js
router.beforeResolve((to, from, next) => {
 console.log(`Before resolve:`)
 console.log(`Route to`, to)
 console.log(`Route from`, from)
 next();
});
```

# afterEach

我们还可以钩入全局的`afterEach`函数，允许我们执行操作，但我们无法影响导航，因此只能访问`to`和`from`参数：

```js
router.afterEach((to, from) => {
 console.log(`After each:`)
 console.log(`Route to`, to)
 console.log(`Route from`, from)
});
```

# 解析堆栈

现在我们已经熟悉了提供的各种不同的路由生命周期钩子，值得调查的是，每当我们尝试导航到另一个路由时，整个解析堆栈。

1.  **触发路由更改**：这是任何路由生命周期的第一阶段，当我们*尝试*导航到新路由时触发。一个例子是从`/hello/Paul`到`/hello/Katie`。在这一点上还没有触发任何导航守卫。

1.  **触发组件离开守卫**：接下来，任何离开守卫都会被触发，比如在加载的组件上的`beforeRouteLeave`。

1.  **触发全局 beforeEach 守卫**：由于全局路由中间件可以通过`beforeEach`创建，这些函数将在任何路由更新之前被调用。

1.  **在重用组件中触发本地 beforeRouteUpdate 守卫**：正如我们之前看到的，每当我们使用不同的参数导航到相同的路由时，生命周期钩子不会被触发两次。相反，我们使用`beforeRouteUpdate`来触发生命周期更改。

1.  **在组件中触发 beforeRouteEnter**：这在导航到任何路由之前每次都会被调用。在这个阶段，组件还没有被渲染，因此无法访问`this`组件实例。

1.  **解析异步路由组件**：然后尝试解析项目中的任何异步组件。这里有一个例子：

```js
const MyAsyncComponent = () => ({
component: import ('./LazyComponent.vue'),
loading: LoadingComponent,
error: ErrorComponent,
delay: 150,
timeout: 3000
})
```

1.  **在成功激活的组件中触发 beforeRouteEnter**：

现在我们可以访问`beforeRouteEnter`钩子，并在解析路由之前执行任何操作。

1.  **触发全局 beforeResolve 钩子**：提供了组件内的守卫和异步路由组件已经解析，我们现在可以钩入全局的`router.beforeResolve`方法，允许我们在这个阶段执行操作。

1.  **导航**：所有先前的导航守卫都已触发，用户现在成功导航到了一个路由。

1.  **触发 afterEach 钩子**：虽然用户已经导航到了路由，但事情并没有到此为止。接下来，路由器会触发一个全局的`afterEach`钩子，该钩子可以访问`to`和`from`参数。由于路由在这个阶段已经解析，它没有下一个参数，因此不能影响导航。

1.  **触发 DOM 更新**：路由已经解析，Vue 可以适当地触发 DOM 更新。

1.  **在 beforeRouteEnter 中的 next 中触发回调**：由于`beforeRouteEnter`无法访问组件的`this`上下文，`next`参数接受一个回调函数，在导航时解析为组件实例。一个例子可以在这里看到：

```js
beforeRouteEnter (to, from, next) {   
 next(comp => {
  // 'comp' inside this closure is equal to the component instance
 }) 
```

# 程序化导航

我们不仅限于使用`router-link`进行模板导航；我们还可以在 JavaScript 中以编程方式将用户导航到不同的路由。在我们的`App.vue`中，让我们暴露`<router-view>`并让用户能够选择一个按钮，将他们导航到`/hello`或`/hello/:name`路由：

```js
<template>
  <div id="app">
    <nav>
      <button @click="navigateToRoute('/hello')">/Hello</button>
      <button 
       @click="navigateToRoute('/hello/Paul')">/Hello/Name</button>
    </nav>
    <router-view></router-view>
  </div>
</template>
```

然后我们可以添加一个方法，将新的路由推送到路由堆栈中*：*

```js
<script>
export default {
  methods: {
    navigateToRoute(routeName) {
      this.$router.push({ path: routeName });
    },
  },
};
</script>
```

此时，每当我们选择一个按钮，它应该随后将用户导航到适当的路由。`$router.push()`函数可以接受各种不同的参数，取决于你如何设置你的路由。这里有一些例子：

```js
// Navigate with string literal
this.$router.push('hello')

// Navigate with object options
this.$router.push({ path: 'hello' })

// Add parameters
this.$router.push({ name: 'hello', params: { name: 'Paul' }})

// Using query parameters /hello?name=paul
this.$router.push({ path: 'hello', query: { name: 'Paul' }})
```

# router.replace

不要推送导航项到堆栈上，我们也可以用 `router.replace` 替换当前的历史堆栈。以下是一个例子：

```js
this.$router.replace({ path: routeName });
```

# router.go

如果我们想要向后或向前导航用户，我们可以使用 `router.go`；这本质上是对 `window.history` API 的抽象。让我们看一些例子：

```js
// Navigate forward one record
this.$router.go(1);

// Navigate backward one record
this.$router.go(-1);

// Navigate forward three records
this.$router.go(3);

// Navigate backward three records
this.$router.go(-3);
```

# 延迟加载路由

我们还可以延迟加载我们的路由，以利用 webpack 的代码拆分。这使我们比急切加载路由时拥有更好的性能。为此，我们可以创建一个小型的试验项目。在终端中运行以下命令来执行： 

```js
# Create a new Vue project
$ vue init webpack-simple vue-lazy-loading

# Navigate to directory
$ cd vue-lazy-loading

# Install dependencies
$ npm install

# Install Vue Router
$ npm install vue-router

# Run application
$ npm run dev
```

让我们开始创建两个组件，名为 `Hello.vue` 和 `World.vue`，在 `src/components` 中：

```js
// Hello.vue
<template>
  <div>
    <h1>Hello</h1>
    <router-link to="/world">Next</router-link>
  </div>
</template>

<script>
export default {};
</script>
```

现在我们已经创建了我们的 `Hello.vue` 组件，让我们创建第二个 `World.vue`：

```js
// World.vue
<template>
  <div>
    <h1>World</h1>
    <router-link to="/hello">Back</router-link>
  </div>
</template>

<script>
export default {};
</script>
```

然后我们可以像通常一样初始化我们的路由器，在 `main.js` 中：

```js
import Vue from 'vue';
import VueRouter from 'vue-router';

Vue.use(VueRouter);
```

主要区别在于导入组件的方式。这需要使用 `syntax-dynamic-import` Babel 插件。通过在终端中运行以下命令将其安装到项目中：

```js
$ npm install --save-dev babel-plugin-syntax-dynamic-import
```

然后我们可以更新 `.babelrc` 来使用新的插件：

```js
{
 "presets": [["env", { "modules": false }], "stage-3"],
 "plugins": ["syntax-dynamic-import"]
}
```

最后，这使我们能够异步导入我们的组件，就像这样：

```js
const Hello = () => import('./components/Hello');
const World = () => import('./components/World');
```

然后我们可以定义我们的路由并初始化路由器，这次引用异步导入：

```js
const routes = [
 { path: '/', redirect: '/hello' },
 { path: '/hello', component: Hello },
 { path: '/World', component: World },
];

const router = new VueRouter({
 routes,
});

new Vue({
 el: '#app',
 router,
 render: h => h(App),
});
```

然后我们可以通过在 Chrome 中查看开发者工具 | 网络选项卡来查看其结果，同时浏览我们的应用程序：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/cpl-vue2-web-dev/img/ff7dcc30-147c-4a86-a2de-d3d406500244.png)

每个路由都添加到自己的捆绑文件中，随后使我们的性能得到改善，因为初始捆绑文件要小得多：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/cpl-vue2-web-dev/img/cd3f60f3-23a1-4d33-b4ac-3238740e8329.png)

# 一个单页应用项目

让我们创建一个使用 RESTful API 和我们刚学到的路由概念的项目。在终端中运行以下命令来创建一个新项目：

```js
# Create a new Vue project
$ vue init webpack-simple vue-spa

# Navigate to directory
$ cd vue-spa

# Install dependencies
$ npm install

# Install Vue Router and Axios
$ npm install vue-router axios

# Run application
$ npm run dev
```

# 启用路由

我们可以通过在应用程序中启用 `VueRouter` 插件来开始。为此，我们可以在 `src/router` 中创建一个名为 `index.js` 的新文件。我们将使用这个文件来包含所有特定于路由的配置，但根据底层功能将每个路由分离到不同的文件中。

让我们导入并添加路由插件：

```js
import Vue from 'vue';
import VueRouter from 'vue-router';

Vue.use(VueRouter)
```

# 定义路由

为了将路由分离到应用程序中的不同文件中，我们首先可以在 `src/components/user` 下创建一个名为 `user.routes.js` 的文件。每当我们有一个需要路由的不同功能集时，我们可以创建自己的 `*.routes.js` 文件，然后将其导入到路由的 `index.js` 中。

目前，我们只需导出一个新的空数组：

```js
export const userRoutes = [];
```

然后我们可以将路由添加到我们的 `index.js` 中（即使我们还没有定义任何路由）：

```js
import { userRoutes } from '../components/user/user.routes';

const routes = [...userRoutes];
```

我们正在使用 ES2015+ 的展开运算符，它允许我们使用数组中的每个对象而不是数组本身。

然后，我们可以初始化路由，创建一个新的 `VueRouter` 并传递路由，如下所示：

```js
const router = new VueRouter({
  // This is ES2015+ shorthand for routes: routes
  routes,
});
```

最后，让我们导出路由，以便它可以在我们的主 Vue 实例中使用：

```js
export default router;
```

在 `main.js` 中，让我们导入路由并将其添加到实例中，如下所示：

```js
import Vue from 'vue';
import App from './App.vue';
import router from './router';

new Vue({
 el: '#app',
 router,
 render: h => h(App),
});
```

# 创建 UserList 路由

我们应用程序的第一部分将是一个主页，显示来自 API 的用户列表。我们过去曾使用过这个例子，所以你应该对涉及的步骤很熟悉。让我们在 `src/components/user` 下创建一个名为 `UserList.vue` 的新组件。

组件将看起来像这样：

```js
<template>
  <ul>
    <li v-for="user in users" :key="user.id">
      {{user.name}}
    </li>
  </ul> 
</template>

<script>
export default {
  data() {
    return {
      users: [
        {
          id: 1,
          name: 'Leanne Graham',
        }
      ],
    };
  },
};
</script>
```

此时可以随意添加自己的测试数据。我们将很快从 API 请求这些数据。

由于我们已经创建了组件，我们可以在 `user.routes.js` 中添加一个路由，当激活 `'/'`（或您选择的路径）时显示此组件：

```js
import UserList from './UserList';

export const userRoutes = [{ path: '/', component: UserList }];
```

为了显示这个路由，我们需要更新 `App.vue`，随后将内容注入到 `router-view` 节点中。让我们更新 `App.vue` 来处理这个问题：

```js
<template>
 <div>
  <router-view></router-view>
 </div>
</template>

<script>
export default {};
</script>

<style>

</style>
```

我们的应用程序应该显示单个用户。让我们创建一个 HTTP 实用程序来从 API 获取数据。

# 从 API 获取数据

在 `src/utils` 下创建一个名为 `api.js` 的新文件。这将用于创建 `Axios` 的基本实例，然后我们可以在其上执行 HTTP 请求：

```js
import axios from 'axios';

export const API = axios.create({
 baseURL: `https://jsonplaceholder.typicode.com/`
})
```

然后我们可以使用 `beforeRouteEnter` 导航守卫，在某人导航到 `'/'` 路由时获取用户数据：

```js
<template>
  <ul>
    <li v-for="user in users" :key="user.id">
      {{user.name}}
    </li>
  </ul> 
</template>

<script>
import { API } from '../../utils/api';
export default {
  data() {
    return {
      users: [],
    };
  },
  beforeRouteEnter(to, from, next) {
    API.get(`users`)
      .then(response => next(vm => (vm.users = response.data)))
      .catch(error => next(error));
  },
};
</script>
```

然后我们发现屏幕上显示了用户列表，如下截图所示，每个用户都表示为不同的列表项。下一步是创建一个 `detail` 组件，注册详细路由，并找到链接到该路由的方法：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/cpl-vue2-web-dev/img/7eeabc93-4aaa-486c-8426-2df9838d78cb.png)

# 创建详细页面

为了创建详细页面，我们可以创建 `UserDetail.vue` 并按照与上一个组件类似的步骤进行操作：

```js
<template>
  <div class="container">
    <div class="user">
      <div class="user__name">
        <h1>{{userInfo.name}}</h1>
        <p>Person ID {{$route.params.userId}}</p>
        <p>Username: {{userInfo.username}}</p>
        <p>Email: {{userInfo.email}}</p>
      </div>
      <div class="user__address" v-if="userInfo && userInfo.address">
        <h1>Address</h1>
        <p>Street: {{userInfo.address.street}}</p>
        <p>Suite: {{userInfo.address.suite}}</p>
        <p>City: {{userInfo.address.city}}</p>
        <p>Zipcode: {{userInfo.address.zipcode}}</p>
        <p>Lat: {{userInfo.address.geo.lat}} Lng: 
        {{userInfo.address.geo.lng}} </p>
      </div>

      <div class="user__other" >
        <h1>Other</h1>
        <p>Phone: {{userInfo.phone}}</p>
        <p>Website: {{userInfo.website}}</p>
        <p v-if="userInfo && userInfo.company">Company: 
        {{userInfo.company.name}}</p>
      </div>
    </div>
  </div>
</template>

<script>
import { API } from '../../utils/api';

export default {
  data() {
    return {
      userInfo: {},
    };
  },
  beforeRouteEnter(to, from, next) {
    next(vm => 
      API.get(`users/${to.params.userId}`)
        .then(response => (vm.userInfo = response.data))
        .catch(err => console.error(err))
    )
  },
};
</script>

<style>
.container {
 line-height: 2.5em;
 text-align: center;
}
</style>
```

由于在我们的详细页面中永远不应该有多个用户，因此`userInfo`变量被创建为 JavaScript 对象而不是数组。

然后我们可以将新组件添加到我们的`user.routes.js`中：

```js
import UserList from './UserList';
import UserDetail from './UserDetail';

export const userRoutes = [
 { path: '/', component: UserList },
 { path: '/:userId', component: UserDetail },
];
```

为了链接到这个组件，我们可以在我们的`UserList`组件中添加`router-link`：

```js
<template>
  <ul>
    <li v-for="user in users" :key="user.id">
      <router-link :to="{ path: `/${user.id}` }">
      {{user.name}}
      </router-link>
    </li>
  </ul> 
</template>
```

如果我们然后在浏览器中查看，我们可以看到只有一个用户列出，下面的信息来自于与该用户关联的用户详细信息：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/cpl-vue2-web-dev/img/362ddaab-acc1-4f18-bb20-8129a048dcfe.png)

# 子路由

我们还可以从我们的 API 中访问帖子，因此我们可以同时显示帖子信息和用户信息。让我们创建一个名为`UserPosts.vue`的新组件：

```js
<template>
  <div>
    <ul>
      <li v-for="post in posts" :key="post.id">{{post.title}}</li>
    </ul>
  </div>
</template>

<script>
import { API } from '../../utils/api';
export default {
  data() {
    return {
      posts: [],
    };
  },
  beforeRouteEnter(to, from, next) {
       next(vm =>
          API.get(`posts?userId=${to.params.userId}`)
          .then(response => (vm.posts = response.data))
          .catch(err => console.error(err))
     )
  },
};
</script>
```

这允许我们根据我们的`userId`路由参数获取帖子。为了将此组件显示为子视图，我们需要在`user.routes.js`中注册它：

```js
import UserList from './UserList';
import UserDetail from './UserDetail';
import UserPosts from './UserPosts';

export const userRoutes = [
  { path: '/', component: UserList },
  {
    path: '/:userId',
    component: UserDetail,
    children: [{ path: '/:userId', component: UserPosts }],
  },
];
```

然后我们可以在`UserDetail.vue`组件内部添加另一个`<router-view>`标签来显示子路由。模板现在看起来像这样：

```js
<template>
  <div class="container">
    <div class="user">
        // Omitted
    </div>
    <div class="posts">
      <h1>Posts</h1>
      <router-view></router-view>
    </div>
  </div>
</template>
```

最后，我们还添加了一些样式，将用户信息显示在左侧，帖子显示在右侧：

```js
<style>
.container {
  line-height: 2.5em;
  text-align: center;
}
.user {
  display: inline-block;
  width: 49%;
}
.posts {
  vertical-align: top;
  display: inline-block;
  width: 49%;
}
ul {
  list-style-type: none;
}
</style>
```

如果我们然后转到我们的浏览器，我们可以看到数据的显示方式正如我们计划的那样，用户信息显示在左侧，帖子显示在右侧：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/cpl-vue2-web-dev/img/8bfff65d-623a-47b0-98c0-fef25fe81962.png)

哒哒！我们现在创建了一个具有多个路由、子路由、参数等的 Vue 应用程序！

# 总结

在这一部分，我们学习了关于 Vue Router 以及如何使用它来创建单页面应用程序。因此，我们涵盖了从初始化路由插件到定义路由、组件、导航守卫等方面的所有内容。我们现在有了必要的知识来创建超越单一组件的 Vue 应用程序。

既然我们扩展了我们的知识并了解了如何使用 Vue Router，我们可以继续在下一章节中处理`Vuex`中的状态管理。
