# Vue2 Web 开发项目（三）

> 原文：[`zh.annas-archive.org/md5/632F664CBB74089B16065B30D26C6055`](https://zh.annas-archive.org/md5/632F664CBB74089B16065B30D26C6055)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：项目 4 - 地理定位博客

在本章中，我们将构建我们的第四个应用程序。我们将涵盖新的主题，例如：

+   使用官方的 Vuex 库来管理应用程序的状态的集中式存储

+   使用 Google OAuth API 将我们的用户连接到应用程序

+   使用`vue-googlemaps`第三方库将 Google 地图集成到我们的应用程序中

+   渲染函数和 JSX

+   功能组件--制作更轻量和更快的组件

该应用程序将是一个地理定位博客，主要显示一个大地图，用户将在其中添加博客文章。以下是该应用程序的主要功能：

+   登录页面将要求用户使用他们的 Google 帐户进行身份验证

+   主视图将是嵌入应用程序中的 Google 地图，每个帖子都有一个标记

+   单击标记将在右侧显示内容，包括位置描述、帖子、点赞计数和评论列表

+   在地图的其他任何位置单击将在侧边栏中显示一个表单，以便用户可以在此位置创建新的帖子

+   应用程序的顶部栏将显示当前用户的头像和名称，以及一个按钮，用于将地图居中显示在他们的位置，并另一个按钮用于注销

最终应用程序将如下所示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/4a34b78b-fc86-4bb3-b430-6072c71f2716.png)

# Google 身份验证和状态管理

在这个第一部分中，我们将创建我们的第一个 Vuex 存储，以帮助我们管理应用程序的状态。我们将使用它来存储通过 Google OAuth API 登录的当前用户，这允许他们使用他们的 Google 帐户连接到我们的应用程序。

# 项目设置

首先，让我们设置新项目的基本结构。我们将继续使用路由器和第五章的一些部分，*项目 3 - 支持中心*。

# 创建应用程序

在本节中，我们将为我们的地理定位博客设置基本应用程序结构。

1.  就像我们在第五章中所做的那样，*项目 3 - 支持中心*，我们将使用`vue-init`初始化一个 Vue 项目，并安装 babel、routing 和 stylus 包：

```js
 vue init webpack-simple geoblog</strong>
 **cd geoblog**
 **npm install**
 **npm install --save vue-router babel-polyfill**
 **npm install --save-dev stylus stylus-loader babel-preset-vue**
```

不要忘记在`.babelrc`文件中添加`"vue"`预设。

1.  然后删除`src`目录的内容。

1.  我们将重用我们在第五章中制作的`$fetch`插件，因此也将`src/plugins/fetch.js`文件复制到新项目中。

1.  在`src`文件夹中，添加启动我们应用程序的`main.js`文件，就像我们在第五章，*项目 3-支持中心*中所做的那样：

```js
      import 'babel-polyfill'
      import Vue from 'vue'
      import VueFetch, { $fetch } from './plugins/fetch'
      import App from './components/App.vue'
      import router from './router'
      import * as filters from './filters'

      // Filters
      for (const key in filters) {
        Vue.filter(key, filters[key])
      }

      Vue.use(VueFetch, {
        baseUrl: 'http://localhost:3000/',
      })

      function main () {
        new Vue({
          ...App,
          el: '#app',
```

```js
          router,
        })
      }

      main()
```

1.  我们仍然会使用`moment.js`来显示日期，所以您可以使用以下命令安装它：

```js
 npm i -S moment
```

这种更短的表示法等同于`npm install --save`。对于开发依赖项，您可以使用`npm i -D`而不是`npm install --save-dev`。

1.  在新的`src/filters.js`文件中创建与之前相同的简单日期过滤器：

```js
      import moment from 'moment'

      export function date (value) {
        return moment(value).format('L')
      }
```

1.  在`$fetch`插件中，您可以删除对`state.js`文件的引用，因为这次我们不会有这个文件：

```js
      // Remove this line
      import state from '../state'
```

1.  如果请求收到`403` HTTP 代码时登出用户的方式也将不同，因此您也可以删除相关代码：

```js
      } else if (response.status === 403) {
        // If the session is no longer valid
        // We logout
        // TODO
      } else {
```

1.  最后，下载（[`github.com/Akryum/packt-vue-project-guide/tree/master/chapter6-full/client/src/styles`](https://github.com/Akryum/packt-vue-project-guide/tree/master/chapter6-download/styles)）并将它们放在`src/styles`目录中。

# 一些路由

应用程序将有三个页面：

+   带有“使用 Google 登录”按钮的登录页面

+   带有地图的主地理定位博客页面

+   一个“未找到”页面

现在我们将创建主组件并使用简单组件设置这些页面：

1.  创建一个新的`src/components`文件夹，并从第五章，*项目 3-支持中心*中复制`NotFound.vue`组件。

1.  然后添加`App.vue`文件，其中包含`router-view`组件和主要的 stylus 文件：

```js
      <template>
        <div class="app">
          <router-view />
        </div>
      </template>

      <style lang="stylus">
      @import '../styles/main';
      </style>
```

1.  添加`GeoBlog.vue`文件，目前将非常简单：

```js
      <template>
        <div class="geo-blog">
          <!-- More to come -->
        </div>
      </template>
```

1.  添加带有“使用 Google 登录”按钮的`Login.vue`文件。按钮调用`openGoogleSignin`方法：

```js
      <template>
        <div class="welcome">
          <h1>Welcome</h1>

          <div class="actions">
            <button @click="openGoogleSignin">
              Sign in with Google
            </button>
          </div>
        </div>
      </template>

      <script>
      export default {
        methods: {
          openGoogleSignin () {
            // TODO
          },
        },
      }
      </script>
```

1.  创建一个类似于我们在第五章中所做的`router.js`文件，*项目 3-支持中心*。它将包含三个路由：

```js
      import Vue from 'vue'
      import VueRouter from 'vue-router'

      import Login from './components/Login.vue'
      import GeoBlog from './components/GeoBlog.vue'
      import NotFound from './components/NotFound.vue'

      Vue.use(VueRouter)

      const routes = [
        { path: '/', name: 'home', component: GeoBlog,
          meta: { private: true } },
        { path: '/login', name: 'login', component: Login },
        { path: '*', component: NotFound },
      ]

      const router = new VueRouter({
        routes,
        mode: 'history',
        scrollBehavior (to, from, savedPosition) {
          if (savedPosition) {
            return savedPosition
          }
          if (to.hash) {
            return { selector: to.hash }
          }
          return { x: 0, y: 0 }
        },
      })

      // TODO Navigation guards
```

```js
      // We will get to that soon

      export default router
```

路由应该已经在主文件中导入并注入到应用程序中。我们现在准备继续！

# 使用 Vuex 进行状态管理

这是本章的激动人心的部分，我们将使用第二个非常重要的官方 Vue 库--Vuex！

Vuex 允许我们使用集中式存储来管理应用程序的全局状态。

# 我为什么需要这个？

一个重要的问题是为什么我们首先需要一个集中式状态管理解决方案。您可能已经注意到在以前的项目中，我们已经使用了一个非常简单的`state.js`文件，其中包含我们在组件之间需要的全局数据的对象。Vuex 是朝着这个方向迈出的下一步。它引入了一些新概念，以帮助我们以正式和高效的方式管理和调试应用程序的状态。

当您的应用程序增长时，您或您的团队将添加许多更多的功能和组件（可能超过一百个）。其中许多将共享数据。随着组件之间相互连接的复杂性增加，您最终会陷入一团糟，有太多组件需要保持同步的数据。在这一点上，您的应用程序状态将不再可预测和可理解，您的应用程序将变得非常难以发展或维护。例如，想象一下，在组件树中深藏的四五个组件中的一个按钮需要打开位于远处的侧边栏--您可能需要使用大量事件和 props 通过许多组件传递信息。您实际上有两个数据源，这意味着两个组件共享数据，必须以某种方式同步，否则您的应用程序将崩溃，因为您不再知道哪个组件是正确的。

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/144ef140-e938-4882-8d42-2b3a06745c72.jpg)

这个问题的推荐解决方案是来自 Veu 的 Vuex。它受到了 Facebook 开发的 Flux 概念的启发，这一概念诞生了 Redux 库（在 React 社区中非常知名）。Flux 是一组指导原则，强调通过集中式存储在组件之间使用单向信息流。好处是，您的应用逻辑和流程将更容易理解，因此大大提高了可维护性。缺点是您可能需要理解一些新概念，并且可能需要写更多的代码。Vuex 有效地实现了这些原则中的一些，以帮助您改进应用程序的架构。

一个真实的例子是 Facebook 的通知系统--聊天系统已经足够复杂，以至于很难确定您已经看过哪条消息。有时，您可能会收到一条您已经阅读过的新消息的通知，因此 Facebook 致力于通过改变应用程序架构来解决这个问题。

对于我们的第一个示例，按钮和侧面板组件不需要在整个应用程序中同步其状态。相反，它们使用集中式存储获取数据并分派操作--这意味着它们不需要彼此了解，也不依赖其祖先或子组件来同步其数据。这意味着现在有一个单一的真相来源，即集中式存储--您不再需要在组件之间同步数据。

>![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/b543f062-f694-4f8b-b6a9-cfcb04216376.jpg)

我们现在将围绕 Vuex 库及其原则来设计我们的应用程序。

Vuex 建议用于大多数应用程序，但如果不必要，您不必使用它，例如原型或简单小部件等非常小的项目。

# Vuex 存储库

Vuex 的中心元素是存储库。它是一个特殊对象，允许您将应用程序的数据集中到遵循良好设计模式并有助于防止我们在上一节中看到的错误的模型中。它将是我们的数据的主要架构以及我们对其的处理方式。

存储库包含以下内容：

+   状态，这是一个包含应用程序状态的响应式数据对象

+   获取器，这是存储库的计算属性等效物

+   变异，用于修改应用程序状态的函数

+   操作，通常调用异步 API，然后变异的函数

因此，存储库应该如下所示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/0259bc16-604e-4ffa-b499-fef0bb82b39d.png)

这是很多新词汇需要理解的，所以让我们在学习这些新概念的同时创建一个存储库。您会发现这并不像看起来那么困难：

1.  使用'npm i -S vuex'命令下载 vuex。创建一个新的`store`文件夹，并添加一个安装 Vuex 插件的`index.js`文件：

```js
      import Vue from 'vue'
      import Vuex from 'vuex'

      Vue.use(Vuex)
```

1.  使用`Vuex.Store`构造函数创建存储库：

```js
      const store = new Vuex.Store({
        // TODO Options
      })
```

1.  像路由器一样将其默认导出：

```js
      export default store
```

1.  在主`main.js`文件中，导入存储库：

```js
      import store from './store'
```

Webpack 将检测到`store`是一个文件夹，并将自动导入其中的`index.js`文件。

1.  要在我们的应用程序中启用存储库，我们需要像路由器一样注入它：

```js
      new Vue({
        ...App,
        el: '#app',
        router,
        // Injected store
        store,
      })
```

1.  所有组件现在都可以通过`$store`特殊属性访问存储库，类似于`vue-router`特殊对象，如`$router`和`$route`。例如，您可以在组件内部编写以下内容：

```js
    this.$store
```

# 状态是真相的来源

存储的主要部分是它的状态。它代表了应用程序中组件之间共享的数据。第一个原则是--这是您共享数据的**唯一数据源**。由于组件将从中读取数据，并且它将始终是正确的。

目前，状态将只有一个`user`属性，其中包含已登录用户的数据：

1.  在存储选项中，将一个返回对象的函数添加到状态中：

```js
      const store = new Vuex.Store({
        state () {
          return {
            user: null,
          }
        },
      })
```

另一个非常重要的原则是--状态是**只读**的。您不应直接修改状态，否则将失去使用 Vuex 的好处（使共享状态易于理解）。如果有很多组件在应用程序的任何地方随意修改状态，那么将更难以跟踪数据流并使用开发工具进行调试。更改状态的唯一有效方式是通过 mutations，我们将很快看到。

1.  为了尝试读取状态，让我们在`components`文件夹中创建`AppMenu.vue`组件。它将显示用户信息，`center-on-user`按钮和`logout`按钮：

```js
      <template>
        <div class="app-menu">
          <div class="header">
            <i class="material-icons">place</i>
            GeoBlog
          </div>

          <div class="user">
            <div class="info" v-if="user">
              <span class="picture" v-if="userPicture">
                <img :src="userPicture" />
              </span>
              <span class="username">{{ user.profile.displayName }}
              </span>
            </div>
            <a @click="centerOnUser"><i class="material-
            icons">my_location</i>                  
            </a>
            <a @click="logout"><i class="material-
            icons">power_settings_new</i>              
            </a>
          </div>
        </div>
      </template>

      <script>
      export default {
        computed: {
          user () {
            return this.$store.state.user
          },
          userPicture () {
            return null // TODO
          },
        },
        methods: {
          centerOnUser () {
            // TODO
          },
          logout () {
            // TODO
          },
        },
      }
      </script>
```

`user`对象将具有来自 Google 的 profile 属性，其中包含用户的显示名称和照片。

1.  在`GeoBlog.vue`中添加这个新的`AppMenu`组件：

```js
      <template>
        <div class="geo-blog">
          <AppMenu />
          <!-- Map & content here -->
        </div>
      </template>

      <script>
      import AppMenu from './AppMenu.vue'

      export default {
        components: {
          AppMenu,
        },
      }
      </script>
```

目前我们的用户没有登录，所以什么也没有显示。

# Mutations 更新状态

由于我们将状态视为只读，修改它的唯一方式是通过 mutations。Mutation 是一个同步函数，它以状态作为第一个参数和一个可选的有效负载参数，然后更新状态。这意味着您不允许在 mutation 中执行异步操作（比如向服务器发出请求）。

1.  让我们添加我们的第一个 mutation，类型为`'user'`，它将更新状态中的用户：

```js
      const store = new Vuex.Store({
        state () { /* ... */ },

        mutations: {
          user: (state, user) => {
            state.user = user
          },
        },
      })
```

Mutations 非常类似于事件--它们有一个类型（这里是`'user'`）和一个处理程序函数。

用于指示我们正在调用 mutation 的词是**commit**。我们不能直接调用它们--就像事件一样，我们要求存储触发与特定类型对应的 mutations。

要调用我们的 mutation 处理程序，我们需要使用`commit`存储方法：

```js
store.commit('user', userData)
```

1.  让我们在`AppMenu`组件的`logout`函数中尝试这样做，这样我们就可以测试 mutation：

```js
      logout () {
        // TODO
        if (!this.user) {
          const userData = {
            profile: {
              displayName: 'Mr Cat',
            },
          }
          this.$store.commit('user', userData)
        } else {
          this.$store.commit('user', null)
        }
      },
```

现在，如果您点击注销按钮，您应该看到用户信息被切换。

# 严格模式

出于调试原因，突变是同步的。状态处理方式使得很容易跟踪和调试应用程序中的故障行为，因为开发工具可以对其进行快照。但是，如果您的突变进行异步调用，那么调试器无法知道突变之前和之后的状态，使其无法追踪：

1.  为了帮助您避免在同步突变之外修改状态，您可以这样启用严格模式：

```js
      const store = new Vuex.Store({
        strict: true,
        // ...
      })
```

当状态在同步突变之外被修改时，这将引发错误，阻止调试工具正常工作。

您不应该在生产中启用严格模式，因为它会影响性能。使用这个表达式来做到这一点--`strict: process.env.NODE_ENV !== 'production'`，这将确保`NODE_ENV`标准环境变量告诉您处于哪种开发模式（通常是开发、测试或生产）。

1.  让我们尝试直接在`logout`测试方法中更改状态：

```js
      logout () {
        if (!this.user) {
          // ...
          this.$store.state.user = userData
        } else {
          this.$store.state.user = null
        }
      },
```

然后再次点击登出按钮并打开浏览器控制台--您应该看到 Vuex 抛出了错误，因为您正在修改状态而不是通过正确的突变：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/8fb4e4be-c081-4d85-bf19-d87c4de3d609.png)

# 时间旅行调试

使用 Vuex 方法的一个好处是调试体验。在更复杂的应用程序中，这对于逐个突变跟踪应用程序状态非常有用。

回到`logout`方法中的突变调用。点击几次登出按钮，然后打开 Vue 开发工具并打开 Vuex 选项卡。您应该看到一系列提交到存储的突变列表：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/882a450b-d415-46d8-ae14-e2a973358052.png)

在右侧，您可以看到为所选突变记录的状态及其有效负载（传递给它的参数）。

您可以通过悬停在突变上并单击时间旅行图标按钮来返回任何状态快照：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/f833a1fb-d016-4c38-a4e8-e8164f2ab673.png)

您的应用程序将恢复到最初的状态！现在您可以逐步回放应用程序状态的演变，就像突变被提交一样。

# Getter 计算并返回数据

Getter 就像计算属性一样工作。它们是接受状态和 getter 作为参数的函数，并返回一些状态数据：

1.  让我们创建一个返回状态中保存的用户的`user` getter：

```js
      const store = new Vuex.Store({
        // ...
        getters: {
          user: state => state.user,
        },
      })
```

1.  在我们的`AppMenu`组件中，我们可以使用这个 getter 来代替直接访问状态：

```js
      user () {
        return this.$store.getters.user
      },
```

这似乎与以前没有什么不同。但直接访问状态并不推荐——你应该始终使用 getter，因为它允许你修改获取数据的方式，而无需更改使用它的组件。例如，你可以更改状态的结构并调整相应的 getter，而不会对组件产生影响。

1.  让我们还添加一个`userPicture` getter，我们将在有真实的 Google 个人资料时实现它：

```js
      userPicture: () => null,
```

1.  在`AppMenu`组件中，我们已经可以使用它：

```js
      userPicture () {
        return this.$store.getters.userPicture
      },
```

# 存储操作的操作

组成存储的最终元素是动作。它们与突变不同，因为它们不直接修改状态，但它们可以**提交突变**并进行**异步操作**。与突变类似，动作是用类型和处理程序声明的。处理程序不能直接调用，你需要像这样调度一个动作类型：

```js
store.dispatch('action-type', payloadObject)
```

动作处理程序需要两个参数：

+   `context`，它提供了与存储相关的`commit`、`dispatch`、`state`和`getters`实用程序

+   `有效负载`，这是提供给`dispatch`调用的参数

1.  让我们添加我们的第一个动作，类型为'login'和'logout'，它们不需要有效负载：

```js
      const store = new Vuex.Store({
        // ...
        actions: {
          login ({ commit }) {
            const userData = {
             profile: {
                displayName: 'Mr Cat',
              },
            }
            commit('user', userData)
          },

          logout ({ commit }) {
            commit('user', null)
          },
        }
      })
```

1.  在`AppMenu`组件中，我们可以通过替换与两个按钮对应的方法的代码来测试它们：

```js
      methods: {
        centerOnUser () {
          // TODO
          // Testing login action
          this.$store.dispatch('login')
        },
        logout () {
          this.$store.dispatch('logout')
        },
      },
```

现在，如果你点击菜单中的按钮，你应该看到用户资料出现和消失。

与 getter 类似，你应该始终在组件内部使用动作而不是突变。你的应用程序的功能很可能会发展，所以能够更改动作代码而不是组件代码是一个好主意（例如，如果你需要调用一个新的额外突变）。把动作看作是你的一般应用逻辑的抽象。

# 映射助手

Vuex 提供了一些辅助函数来添加状态、getter、mutation 和 action。由于我们应该只在组件中使用 getter 和 action 来帮助将状态和相关逻辑与组件分离，所以我们只会使用`mapGetters`和`mapActions`。

这些函数为依赖于存储中相应 getter 和动作的组件生成适当的计算属性和方法，因此您不必每次都输入`this.$store.getters`和`this.$store.dispatch`。参数要么是：

+   与组件相同名称的映射的类型数组

+   一个对象，其键是组件上的别名，值是类型

例如，使用数组语法的以下代码：

```js
mapGetters(['a', 'b'])
```

在组件中相当于这个：

```js
{
  a () { return this.$store.getters.a },
  b () { return this.$store.getters.b },
}
```

并使用对象语法的以下代码：

```js
mapGetters({ x: 'a', y: 'b' })
```

相当于这个：

```js
{
  x () { return this.$store.getters.a },
  y () { return this.$store.getters.b },
}
```

让我们重构我们的`AppMenu`组件来使用这些帮助程序：

1.  首先在组件中导入这些：

```js
      import { mapGetters, mapActions } from 'vuex'
```

1.  然后，我们可以像这样重写组件：

```js
      export default {
        computed: mapGetters([
          'user',
          'userPicture',
        ]),
        methods: mapActions({
          centerOnUser: 'login',
          logout: 'logout',
        }),
      }
```

现在，组件将有两个计算属性，返回相应的存储器 getter，并且两个方法分派`'login'`和`'logout'`动作类型。

# 用户状态

在这一部分，我们将添加用户系统，允许用户使用他们的 Google 账户登录。

# 设置 Google OAuth

在我们可以使用 Google API 之前，我们必须在 Google 开发者控制台中配置一个新项目：

1.  转到[console.developers.google.com](https://accounts.google.com/ServiceLogin/signinchooser?service=cloudconsole&passive=1209600&osid=1&continue=https%3A%2F%2Fconsole.developers.google.com%2F%3Fref%3Dhttps%3A%2F%2Fcdp.packtpub.com%2Fvue_js_2_project_guide%2Fwp-admin%2Fpost.php%3Fpost%253D366%2526post_type%253Dchapter%2526action%253Dedit&followup=https%3A%2F%2Fconsole.developers.google.com%2F%3Fref%3Dhttps%3A%2F%2Fcdp.packtpub.com%2Fvue_js_2_project_guide%2Fwp-admin%2Fpost.php%3Fpost%253D366%2526post_type%253Dchapter%2526action%253Dedit&flowName=GlifWebSignIn&flowEntry=ServiceLogin)的开发者控制台。

1.  使用页面顶部的项目下拉菜单创建一个新项目，并给它命名。项目创建完成后，选择它。

1.  要检索用户配置文件，我们需要启用 Google+ API。转到 API 和服务 | 图书馆，然后在社交 API 部分下点击 Google+ API。在 Google+ API 页面上，点击启用按钮。然后你应该看到一个带有一些空图表的使用仪表板。

1.  接下来，我们需要创建应用凭据，以便将我们的服务器验证到 Google。转到 API 和服务 | 凭据，然后选择 OAuth 同意屏幕选项卡。确保你选择一个电子邮件地址，并输入一个*向用户显示的产品名称*。

1.  选择凭证选项卡，点击创建凭证下拉菜单，然后选择 OAuth 客户端 ID。选择 Web 应用程序作为应用程序类型，然后在授权的 JavaScript 起源字段中输入服务器将启动的 URL。目前，它将是`http://localhost:3000`。按下*Enter*键将其添加到列表中。然后将 Google 登录屏幕后 Google 将重定向用户的 URL 添加到授权重定向 URI--`http://localhost:3000/auth/google/callback`并按下*Enter*键。此 URL 对应服务器上的特殊路由。完成后，点击创建客户端 ID 按钮。

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/aaf1ebe9-cfb0-4497-8017-b8829913d19b.png)

1.  然后复制或下载包含客户端 ID 和秘钥的凭证，这些信息不应该与团队外的任何人分享。这两个密钥将允许 Google API 对您的应用进行身份验证，并在用户通过 Google 登录页面登录时显示其名称。

1.  下载项目的 API 服务器（[`github.com/Akryum/packt-vue-project-guide/tree/master/chapter6-full/server`](https://github.com/Akryum/packt-vue-project-guide/tree/master/chapter6-full/server)），并将其提取到`Vue app`目录之外。在这个新文件夹中打开一个新的终端，并使用通常的命令安装服务器依赖项。

```js
 npm install
```

1.  接下来，您需要导出两个`GOOGLE_CLIENT_ID`和`GOOGLE_CLIENT_SECRET`环境变量，并在从 Google Developers Console 下载的凭证文件中使用相应的值。例如，在 Linux 上：

```js
      export GOOGLE_CLIENT_ID=xxx
      export GOOGLE_CLIENT_SECRET=xxx
```

或者在 Windows 上：

```js
      set GOOGLE_CLIENT_ID=xxx
      set GOOGLE_CLIENT_SECRET=xxx
```

每次您想要在新的终端会话中启动服务器时都需要这样做。

1.  您可以使用`start`脚本启动服务器：

```js
 npm run start
```

# 登录按钮

`Login`组件包含应该打开弹出窗口显示 Google 登录页面的按钮。弹出窗口将首先加载 Node.js 服务器上的路由，然后将重定向到 Google OAuth 页面。当用户登录并授权我们的应用程序时，弹出窗口将再次重定向到我们的 nodejs 服务器，并在关闭之前向主页面发送消息：

1.  编辑`openGoogleSignin`方法以在服务器上打开到`/auth/google`路由的弹出窗口，该路由将重定向用户到 Google：

```js
 openGoogleSignin () {
        const url = 'http://localhost:3000/auth/google'
        const name = 'google_login'
        const specs = 'width=500,height=500'
        window.open(url, name, specs)
      },
```

用户通过 Google 成功验证后，服务器上的回调页面将使用标准 postMessage API 向 Vue 应用窗口发送消息。

当我们收到消息时，我们需要检查它是否来自正确的域（我们服务器的`localhost:3000`）。

1.  创建一个带有解构消息参数的新`handleMessage`方法：

```js
 handleMessage ({data, origin}) {
        if (origin !== 'http://localhost:3000') {
          return
        }

        if (data === 'success') {
          this.login()
        }
      },
```

1.  我们将向存储分发`'login'`动作类型，它将很快获取用户数据。将其映射到组件：

```js
      import { mapActions } from 'vuex'

      export default {
        methods: {
          ...mapActions([
            'login',
          ]),

          // ...
        },
      }
```

1.  然后我们使用`mounted`生命周期钩子（在方法之外）向窗口添加事件侦听器：

```js
 mounted () {
        window.addEventListener('message', this.handleMessage)
      },
```

1.  最后，在组件被销毁时，不要忘记删除此侦听器：

```js
 beforeDestroy () {
        window.removeEventListener('message', this.handleMessage)
      },
```

# 存储中的用户

存储将有两个与用户相关的动作--`login`和`logout`。我们已经有了它们，现在我们需要实现它们将做什么。我们还将在本节中添加一些与用户相关的功能，例如在应用程序启动时加载用户会话并在顶部栏显示其个人资料图片：

1.  让我们在存储中实现`login`动作。它将获取用户数据，就像我们在第五章中的*项目 3-支持中心*中所做的那样，然后将数据`commit`到状态中（不要忘记导入`$fetch`）：

```js
      async login ({ commit }) {
        try {
          const user = await $fetch('user')
          commit('user', user)

          if (user) {
            // Redirect to the wanted route if any or else to home
            router.replace(router.currentRoute.params.wantedRoute ||
              { name: 'home' })
          }
        } catch (e) {
          console.warn(e)
        }
      },
```

如您所见，动作可以执行异步操作，例如在此处向服务器请求数据。如果用户已连接，我们将重定向他们到他们想要的页面或主页，就像我们在第五章中的*项目 3-支持中心*中所做的那样。

1.  `'logout'`动作需要向服务器发送`/logout`请求，并且如果当前路由是私有的，则将用户重定向回登录页面：

```js
      logout ({ commit }) {
        commit('user', null)

        $fetch('logout')

        // If the route is private
        // We go to the login screen
        if (router.currentRoute.matched.some(r => r.meta.private)) {
          router.replace({ name: 'login', params: {
            wantedRoute: router.currentRoute.fullPath,
          }})
        }
      },
```

根据我们在`router.js`文件中放置的信息，如果用户在`'home'`路由上，将被重定向到登录页面。

# 调整路由

现在我们需要像在第五章中的*项目 3-支持中心*一样，将导航守卫恢复到路由中，这样用户就无法在未连接时进入私有路由：

在`router.js`文件中，通过使用`user`存储获取器恢复`beforeEach`导航守卫，以检查用户是否已连接。这应该与我们已经实现的那个非常相似：

```js
      import store from './store'

      router.beforeEach((to, from, next) => {
        console.log('to', to.name)
        const user = store.getters.user
        if (to.matched.some(r => r.meta.private) && !user) {
          next({
            name: 'login',
            params: {
              wantedRoute: to.fullPath,
            },
          })
          return
        }
        if (to.matched.some(r => r.meta.guest) && user) {
          next({ name: 'home' })
          return
        }
        next()
      })
```

# 调整 fetch 插件

由于我们需要在会话过期时注销用户，`$fetch`插件也需要一些更改：

1.  在这种情况下，我们只需要分发`'logout'`动作：

```js
      } else if (response.status === 403) {
        // If the session is no longer valid
        // We logout
        store.dispatch('logout')
      } else {
```

1.  不要忘记导入存储：

```js
      import store from '../store'
```

您现在可以尝试通过 Google 登录到您的应用程序！

# 检查用户会话的开始

应用程序启动时，我们希望检查用户是否有活动会话，就像我们在第五章中所做的那样，*项目 3 - 支持中心*：

1.  为此，我们将在存储中创建一个新的通用的`'init'`操作；这将分派`'login'`操作，但最终可能会分派更多操作：

```js
      actions: {
        async init ({ dispatch }) {
          await dispatch('login')
        },

        // ...
      },
```

1.  在`main.js`文件中，我们现在可以分发并等待此操作：

```js
      async function main () {
        await store.dispatch('init')

        new Vue({
          ...App,
          el: '#app',
          router,
          store,
        })
      }

      main()
```

现在，您可以通过 Google 登录并在不被带回登录页面的情况下刷新页面。

# 个人资料图片

最后，我们可以实现`userPicture` getter，以返回 Google 个人资料的`photos`数组中包含的第一个值：

```js
userPicture: (state, getters) => {
  const user = getters.user
  if (user) {
    const photos = user.profile.photos
    if (photos.length !== 0) {
      return photos[0].value
    }
  }
},
```

如您所见，我们可以使用第二个参数在其他 getter 中重用现有的 getter！

当您连接时，应用程序中应显示完整的工具栏：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/ffc64515-9e15-4962-b75d-f009eee655cc.png)

# 同步存储和路由器

我们可以使用官方的`vuex-router-sync`包将路由器集成到存储中。它将在状态（`state.route`）中公开当前路由，并且每次路由更改时都会提交一个 mutation：

1.  使用常规命令进行安装：

```js
 npm i -S vuex-router-sync
```

1.  要使用它，我们需要在主`main.js`文件中使用`sync`方法：

```js
      import { sync } from 'vuex-router-sync'

      sync(store, router)
```

现在，您可以访问`state.route`对象，并且时间旅行调试也将适用于路由器。

# 嵌入 Google 地图

在这第二部分中，我们将在主页上添加一个地图，并通过 Vuex 存储对其进行控制。

# 安装

要集成 Google 地图，我们将需要一个 API 和一个名为`vue-googlemaps`的第三方包。

# 获取 API 密钥

要在我们的应用程序中使用 Google 地图，我们需要启用相应的 API 并生成 API 密钥：

1.  在 Google 开发者控制台中，返回到 API 和服务*|*库，然后单击 Google 地图 API 下的 Google 地图 JavaScript API。在 API 页面上，单击启用按钮。

1.  然后转到凭据并创建一个新的 API 密钥。

# 安装库

我们现在将安装`vue-googlemaps`库，这将帮助我们将 Google 地图集成到我们的应用程序中。

1.  在应用程序中，使用以下命令安装`vue-googlemaps`包：

```js
 npm i -S vue-googlemaps
```

1.  在主`main.js`文件中，您可以使用来自 Google 的 API 密钥在应用程序中启用它：

```js
      import VueGoogleMaps from 'vue-googlemaps'

      Vue.use(VueGoogleMaps, {
        load: {
          apiKey: '*your_api_key_here*',
          libraries: ['places'],
        },
      })
```

我们还指定要加载 Google 地图 Places 库，用于显示位置信息。

现在我们可以访问库的组件了！

1.  在`App.vue`组件中，添加库的样式：

```js
      <style lang="stylus">
      @import '~vue-googlemaps/dist/vue-googlemaps.css'
      @import '../styles/main'
      </style>
```

我们使用`~`字符，因为 Stylus 不支持绝对路径。在这里，我们想要访问一个 npm 模块，所以我们添加这个来告诉`stylus-loader`这是一个绝对路径。

# 添加地图

地图将是应用程序的主要组件，它将包含：

+   用户位置指示器

+   每个帖子的标记

+   最终正在创建的帖子的“幽灵”标记

我们现在将设置一个简单的地图，将填充主页面：

1.  创建一个新的`BlogMap.vue`组件，具有`center`和`zoom`属性：

```js
      <template>
        <div class="blog-map">
          <googlemaps-map
            :center="center"
            :zoom="zoom"
            :options="mapOptions"
            @update:center="setCenter"
            @update:zoom="setZoom"
          />
        </div>
      </template>

      <script>
      export default {
        data () {
          return {
            center: {
              lat: 48.8538302,
              lng: 2.2982161,
            },
            zoom: 15,
          }
        },

        computed: {
          mapOptions () {
            return {
              fullscreenControl: false,
            }
          },
        },

        methods: {
         setCenter (value) {
            this.center = value
          },
          setZoom (value) {
            this.zoom = value
          },
        },
      }
      </script>
```

1.  然后，您需要将其添加到`GeoBlog.vue`组件中：

```js
      <template>
        <div class="geo-blog">
          <AppMenu />
          <div class="panes">
            <BlogMap />
            <!-- Content here -->
          </div>
        </div>
      </template>
```

不要忘记导入它并将其放入`components`选项中！

# 连接 BlogMap 和 store

目前与地图相关的状态是局部的`BlogMap`组件--让我们将其移到 store 中！

# Vuex 模块

在 Vuex store 中，我们可以将我们的状态分成模块，以便更好地组织。一个模块包含一个状态、getter、mutation 和 action，就像主 store 一样。store 和每个模块都可以包含任意数量的模块，因此 store 可以在其他模块内包含嵌套模块--这取决于您找到适合项目的最佳结构。

在此应用程序中，我们将创建两个模块：

+   与地图相关的`maps`

+   与博客帖子和评论相关的`posts`

现在，我们将专注于`maps`模块。最好至少将每个模块分开放在不同的文件或目录中：

1.  在`store`文件夹中创建一个新的`maps.js`文件，将模块定义和地图的状态作为默认导出：

```js
      export default {
        namespaced: true,

        state () {
          return {
            center: {
              lat: 48.8538302,
              lng: 2.2982161,
            },
            zoom: 15,
          }
        },
      }
```

1.  然后将模块添加到 store 中，在`store/index.js`文件中的新`modules`选项中放置它：

```js
      import maps from './maps'

      const store = new Vuex.Store({
        // ...
        modules: {
          maps,
        },
      })
```

默认情况下，模块的 getter、mutation 和 action 的状态将是此模块的状态。这里将是`store.state.maps`。

# 命名空间模块

`namespaced`选项告诉 Vuex 在模块的 getter、mutation 和 action 类型之前也添加`'maps/'`命名空间。它还会将它们添加到命名空间模块内的`commit`和`dispatch`调用中。

让我们添加一些 getter，这些 getter 将被`BlogMap`组件使用：

```js
getters: {
  center: state => state.center,
  zoom: state => state.zoom,
},
```

`maps/center`和`maps/zoom` getter 将被添加到 store 中。要读取它们，您可以这样做：

```js
this.$store.getters['maps/center']
```

使用 getter 帮助程序：

```js
mapGetters({
  center: 'maps/center',
  zoom: 'maps/zoom',
})
```

您还可以指定命名空间参数：

```js
...mapGetters('maps', [
  'center',
  'zoom',
]),
...mapGetters('some/nested/module', [
  // ...
]),
```

这样做的最后一种方法是使用`createNamespacedHelpers`方法基于特定命名空间生成帮助程序：

```js
import { createNamespacedHelpers } from vuex
const { mapGetters } = createNamespacedHelpers('maps')

export default {
  computed: mapGetters([
    'center',
    'zoom',
  ]),
}
```

# 访问全局元素

在命名空间模块的 getter 中，你可以像这样访问根状态和根 getter（也就是任何 getter）：

```js
someGetter: (state, getters, rootState, rootGetters) => { /* ... */ }
```

在动作中，你可以在上下文中访问`rootGetters`，并且你可以在`commit`和`dispatch`调用中使用`{ root: true }`选项：

```js
myAction ({ dispatch, commit, getters, rootGetters }) {
  getters.a // store.getters['maps/a']
  rootGetters.a // store.getters['a']
  commit('someMutation') // 'maps/someMutation'
  commit('someMutation', null, { root: true }) // 'someMutation'
  dispatch('someAction') // 'maps/someAction'
  dispatch('someAction', null, { root: true }) // 'someAction'
}
```

# BlogMap 模块和组件

在这一部分，我们将把`BlogMap`组件与`maps`命名空间模块连接起来。

# 变化

让我们在`maps`模块中添加`center`和`zoom`的变化：

```js
mutations: {
  center (state, value) {
    state.center = value
  },
  zoom (state, value) {
    state.zoom = value
  },
},
```

# 动作

然后，我们设置提交这些变化的动作：

```js
actions: {
  setCenter ({ commit }, value) {
    commit('center', value)
  },

  setZoom ({ commit }, value) {
    commit('zoom', value)
  },
},
```

# 组件中的映射

回到我们的`BlogMap`组件；我们可以使用辅助工具来映射 getter 和动作：

```js
import { createNamespacedHelpers } from 'vuex'

const {
  mapGetters,
  mapActions,
} = createNamespacedHelpers('maps')

export default {
  computed: {
    ...mapGetters([
      'center',
      'zoom',
    ]),

    mapOptions () {
      // ...
    },
  },

  methods: mapActions([
    'setCenter',
    'setZoom',
  ]),
}
```

现在地图的状态是在 Vuex 存储中管理的！

# 用户位置

现在，我们将添加用户位置指示器，这样我们就可以获取位置并将其存储在存储中：

1.  在地图中添加`googlemaps-user-position`组件：

```js
      <googlemaps-map
        ...
      >
        <!-- User Position -->
        <googlemaps-user-position
          @update:position="setUserPosition"
        />
      </googlemaps-map>
```

1.  现在我们需要在`maps`模块中添加`userPosition`信息：

```js
      state () {
        return {
          // ...
          userPosition: null,
        }
      },
      getters: {
        // ...
        userPosition: state => state.userPosition,
      },
      mutations: {
        // ...
        userPosition (state, value) {
          state.userPosition = value
        },
      },
      actions: {
        // ...
        setUserPosition ({ commit }, value) {
          commit('userPosition', value)
        },
      }
```

1.  然后在`BlogMap`组件中映射`setUserPosition`的动作，使用适当的辅助工具。

现在我们应该在存储中提交用户位置（假设你已经给予浏览器访问你位置的权限）。

# 居中用户

这个用户位置将非常有用，可以把地图居中在用户位置上：

1.  让我们在`maps`模块中创建一个新的`centerOnUser`动作：

```js
      async centerOnUser ({ dispatch, getters }) {
        const position = getters.userPosition
        if (position) {
          dispatch('setCenter', position)
        }
      },
```

有了这个，我们还可以改变`setUserPosition`的动作——如果这是我们第一次获取用户位置（也就是在状态中是`null`），我们应该把地图居中在用户位置上。

1.  `setUserPosition`动作现在应该是这样的：

```js
      setUserPosition ({ dispatch, commit, getters }, value) {
        const position = getters.userPosition
        commit('userPosition', value)
        // Initial center on user position
        if (!position) {
          dispatch('centerOnUser')
        }
      },
```

现在你可以尝试一下，地图会以一个小蓝点居中在你的位置上。

默认情况下，如果你的位置精度超过 1,000 米，用户指示器将被禁用，所以这取决于你的硬件，可能不起作用。你可以使用`googlemaps-user-position`组件的`minmumAccuracy`属性来使用更高的值。

1.  我们在工具栏中还有一个“居中用户”按钮，所以我们需要替换`AppMenu`组件中的`centerOnUser`动作映射：

```js
      methods: mapActions({
        logout: 'logout',
        centerOnUser: 'maps/centerOnUser',
      }),
```

# 博客文章和评论

在最后一部分中，我们将把博客内容添加到应用程序中。每篇博客文章都将有一个位置和一个来自 Google 地图的可选地点 ID（因此可以描述地点，例如“餐厅 A”）。我们将加载适合地图可见范围的帖子，并且每个帖子都将显示为带有自定义图标的标记。单击标记时，右侧面板将显示帖子内容和评论列表。单击地图上的其他任何位置将在 Vuex 存储中创建一个草稿帖子，并显示一个表单来编写其内容并将其保存在右侧面板中。

# 帖子存储模块

让我们首先创建一个新的`posts`命名空间的 Vuex 模块，以管理与博客帖子相关的共享数据：

1.  创建一个新的`store/posts.js`文件，其中包含以下状态属性：

```js
      export default {
        namespaced: true,

        state () {
          return {
            // New post being created
            draft: null,
            // Bounds of the last fetching
            // To prevent refetching
            mapBounds: null,
            // Posts fetched in those map bounds
            posts: [],
            // ID of the selected post
            selectedPostId: null,
          }
        },
      }
```

1.  接下来我们需要一些 getter：

```js
 getters: {
        draft: state => state.draft,
        posts: state => state.posts,
        // The id field on posts is '_id' (MongoDB style)
        selectedPost: state => state.posts.find(p => p._id ===                  
        state.selectedPostId),
        // The draft has more priority than the selected post
        currentPost: (state, getters) => state.draft || 
        getters.selectedPost,
      },
```

1.  还有一些 mutations（请注意，我们同时改变`posts`和`mapBounds`，以便它们保持一致）：

```js
 mutations: {
        addPost (state, value) {
          state.posts.push(value)
        },

        draft (state, value) {
          state.draft = value
        },

        posts (state, { posts, mapBounds }) {
          state.posts = posts
          state.mapBounds = mapBounds
        },

        selectedPostId (state, value) {
          state.selectedPostId = value
        },

        updateDraft (state, value) {
          Object.assign(state.draft, value)
        },
      },
```

1.  最后，像我们为`maps`模块做的那样将其添加到商店中：

```js
      import posts from './posts'

      const store = new Vuex.Store({
        // ...
        modules: {
          maps,
          posts,
        },
      })
```

# 渲染函数和 JSX

在第四章中，*高级项目设置*，我已经写过关于渲染函数和 JSX 的内容，这些是除了模板之外编写组件视图的不同方式。在继续之前，我们将更详细地了解这些内容，然后将它们付诸实践。

# 使用渲染函数在 JavaScript 中编写视图

Vue 将我们的模板编译成`render`函数。这意味着所有组件视图最终都是 JavaScript 代码。这些渲染函数将组成要在页面真实 DOM 中显示的虚拟 DOM 树。

大多数情况下，模板都很好用，但您可能会遇到需要使用 JavaScript 的全部编程能力来创建组件视图的情况。您可以编写一个`render`函数来代替指定模板给您的组件。例如：

```js
export default {
  props: ['message'],
  render (createElement) {
    return createElement(
      // Element or Component
      'p',
      // Data Object
      { class: 'content' },
      // Children or Text content
      this.message
    )
  },
}
```

第一个参数是`createElement`，这是您需要调用以创建元素（可以是 DOM 元素或 Vue 组件）的函数。它最多接受三个参数：

+   `element`（必需），可以是 HTML 标签的名称，已注册组件的 ID，或者直接是组件定义对象。它可以是返回其中一个的函数。

+   `data`（可选）是数据对象，用于指定诸如 CSS 类、props、事件等内容。

+   `children`（可选）可以是文本字符串，也可以是使用`createElement`构建的子元素数组。

我们将使用`h`作为`createElement`的别名，`render`函数的参数，因为这是每个人都使用的常用名称（并且在稍后我们将看到，它是 JSX 所必需的）。`h`来自于描述“使用 JavaScript 编写 HTML”的超文本术语。

第一个示例将等同于此模板：

```js
<template>
  <p class="content">{{ message }}</p>
</template>
```

# 动态模板

直接编写渲染函数的主要优势在于它们更接近编译器，并且您可以充分利用 JavaScript 的全部功能来操作模板。显而易见的缺点是它看起来不再像 HTML，但这可以通过 JSX 来缓解，我们将在*什么是 JSX*部分中看到。

例如，您可以创建一个在任何级别渲染标题的组件：

```js
Vue.component('my-title', {
  props: ['level'],
  render (h) {
    return h(
      // Tag name
      `h${this.level}`,
      // Default slot content
      this.$slots.default,
    )
  }
})
```

在这里，我们省略了数据对象参数，因为它是可选的。我们只传递了标签名称和内容。

然后，例如，我们可以在我们的模板中使用它来渲染一个`<h2>`标题元素：

```js
<my-title level="2">Hello</my-title>
```

在模板中的等效写法将会相当冗长：

```js
<template>
  <h1 v-if="level === 1">
    <slot></slot>
  </h1>
  <h2 v-else-if="level === 2">
    <slot></slot>
  </h2>
  <h3 v-else-if="level === 3">
    <slot></slot>
  </h3>
  <h4 v-else-if="level === 4">
    <slot></slot>
  </h4>
  <h5 v-else-if="level === 5">
    <slot></slot>
  </h5>
  <h6 v-else-if="level === 6">
    <slot></slot>
  </h6>
</template>
```

# 数据对象

第二个可选参数是数据对象，它允许您传递有关要传递给`createElement`（或`h`）的元素的其他信息。例如，您可以以与我们在经典模板中使用`v-bind:class`指令相同的方式指定 CSS 类，或者可以添加事件侦听器。

这是一个覆盖大多数功能的数据对象的示例：

```js
{
  // Same API as `v-bind:class`
  'class': {
    foo: true,
    bar: false
  },
  // Same API as `v-bind:style`
  style: {
    color: 'red',
    fontSize: '14px'
  },
  // Normal HTML attributes
  attrs: {
    id: 'foo'
  },
  // Component props
  props: {
    myProp: 'bar'
  },
  // DOM properties
  domProps: {
    innerHTML: 'baz'
  },
  // Event handlers are nested under "on", though
  // modifiers such as in v-on:keyup.enter are not
  // supported. You'll have to manually check the
  // keyCode in the handler instead.
  on: {
    click: this.clickHandler
  },
  // For components only. Allows you to listen to
  // native events, rather than events emitted from
  // the component using vm.$emit.
  nativeOn: {
    click: this.nativeClickHandler
  },
  // Custom directives. Note that the binding's
  // oldValue cannot be set, as Vue keeps track
  // of it for you.
  directives: [
    {
      name: 'my-custom-directive',
      value: '2'
      expression: '1 + 1',
      arg: 'foo',
      modifiers: {
        bar: true
      }
    }
  ],
  // The name of the slot, if this component is the
  // child of another component
  slot: 'name-of-slot'
  // Other special top-level properties
  key: 'myKey',
  ref: 'myRef'
}
```

例如，如果标题级别低于特定数字，我们可以应用特殊的 CSS 类：

```js
Vue.component('my-title', {
  props: ['level'],
  render (h) {
    return h(
      // Tag name
      `h${this.level}`,
      // Data object
      {
        'class': {
          'important-title': this.level <= 3,
        },
      },
      // Default slot content
      this.$slots.default,
    )
  }
})
```

我们还可以添加一个点击事件侦听器，调用组件的一个方法：

```js
Vue.component('my-title', {
  props: ['level'],
  render (h) {
    return h(
      // Tag name
      `h${this.level}`,
      // Data object
      {
        on: {
          click: this.clickHandler,
        },
      },
      // Default slot content
      this.$slots.default,
    )
  },
  methods: {
    clickHandler (event) {
      console.log('You clicked')
    },
  },
})
```

您可以在官方文档中找到此对象的完整描述（[`vuejs.org/v2/guide/render-function.html#The-Data-Object-In-Depth`](https://vuejs.org/v2/guide/render-function.html#The-Data-Object-In-Depth)）。

正如我们所见，Vue 在我们的模板底层使用纯 JavaScript 的渲染函数！我们甚至可以编写自己的渲染函数，使用`createElement`（或`h`）函数来构造要添加到虚拟 DOM 中的元素。

这种编写视图的方式比模板更灵活、更强大，但也更复杂、更冗长。当您感到舒适时，请使用它！

# 虚拟 DOM

`render`函数的结果是使用`createElement`（或`h`）函数创建的节点树；在 Vue 中，这些被称为**VNodes**。它代表了 Vue 持有的虚拟 DOM 中组件的视图。DOM 中的每个元素都是一个节点--HTML 元素、文本，甚至注释都是节点：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/a1be10b7-445c-47b5-bb36-b8944629d491.png)

Vue 不会直接用新的虚拟 DOM 树替换真实的 DOM 树，因为这可能会产生大量的 DOM 操作（添加或删除节点），这是昂贵的。为了更高效，Vue 将在两个树之间创建差异，并且只会执行必要的 DOM 操作，以使真实 DOM 与虚拟 DOM 匹配。

所有这些都是自动发生的，这样 Vue 在应用程序中的数据发生变化时，就可以保持真实 DOM 的最新状态。

# 什么是 JSX？

JSX 是一种语言，用于在`render`函数的 JavaScript 代码中编写更像 HTML 的代码。它实际上是 JavaScript 的一种类似 XML 的扩展。我们之前的例子在 JSX 中看起来是这样的：

```js
export default {
  props: ['message'],
  render (h) {
    return <p class="content">
      {this.message}
    </p>
  },
}
```

这得益于 Babel，这个库负责将我们的 ES2015 JavaScript（或更高版本）代码编译成旧的 ES5 JavaScript，这样就可以在旧浏览器（如 Internet Explorer）中运行。Babel 还可以用来实现 JavaScript 语言的新功能（比如可能出现在以后版本中的草案功能）或者完全新的扩展，比如 JSX。

`babel-preset-vue`中包含的`babel-plugin-transform-vue-jsx`负责将 JSX 代码转换为使用`h`函数的真实 JavaScript 代码。因此，之前的 JSX 示例将被转换回：

```js
export default {
  props: ['message'],
  render (h) {
    return h('p', { class: 'content' }, this.message)
  },
}
```

这就是为什么在使用 JSX 时，我们需要使用`h`而不是`createElement`。

感谢，vue-cli 已经启用了这个功能，所以我们可以在`.vue`文件中编写 JSX 代码！

# 博客内容结构（在 JSX 中！）

让我们创建一个新的`src/components/content`文件夹，并在其中创建一个新的`BlogContent.vue`文件。这个组件代表右侧面板，负责显示右侧组件：

+   如果在地图上选择了位置，则可能会显示位置地址和名称的`LocationInfo.vue`组件

+   下面，它将显示以下内容之一：

+   如果没有选择位置，则会出现`NoContent.vue`组件，点击地图提示

+   如果有草稿帖子，则会出现`CreatePost.vue`组件，带有表单

+   如果选择了真实的帖子，则会出现`PostContent.vue`组件，带有内容和评论列表

1.  让我们在`content`目录中也创建这些组件，带有空模板：

```js
      <template></template>
```

回到我们的`BlogContent.vue`组件！我们将使用 JSX 编写这个新组件来练习它。

1.  首先创建命名空间助手：

```js
      <script>
      import { createNamespacedHelpers } from 'vuex'

      // posts module
      const {
        mapGetters: postsGetters,
        mapActions: postsActions,
      } = createNamespacedHelpers('posts')

      </script>
```

最好将命名空间助手重命名，因为将来可能会为另一个模块添加助手。例如，如果不这样做，你可能会得到两个`mapGetters`，这是不可能的。在这里，我们将`mapGetters`重命名为`postsGetters`，将`mapActions`重命名为`postsActions`。

1.  然后让我们编写组件定义：

```js
      export default {
        computed: {
          ...postsGetters([
            'draft',
            'currentPost',
          ]),

          cssClass () {
            return [
              'blog-content',
              {
                'has-content': this.currentPost,
              },
            ]
          },
        },
      }
```

`has-content` CSS 类将在智能手机上使用，当没有选择帖子或没有编辑草稿时，它将隐藏面板（它将全屏显示）。

1.  接下来，我们需要用 JSX 编写渲染函数：

```js
 render (h) {
        let Content
        if (!this.currentPost) {
          Content = NoContent
        } else if (this.draft) {
          Content = CreatePost
        } else {
          Content = PostContent
        }

        return <div class={this.cssClass}>
          <LocationInfo />
          <Content />
        </div>
      },
```

不要忘记也导入其他四个组件！

在 JSX 中，标签的第一个字母的大小写很重要！如果以小写字母开头，它将被视为`createElement`函数的字符串参数，并将解析为 HTML 元素或已注册的组件（例如`<div>`）。另一方面，如果第一个字母是大写的，它将被视为变量！在我们之前的代码中，`LocationInfo`直接从导入中使用。例如：

```js
import LocationInfo from './LocationInfo.vue'

export default {
  render (h) {
    return <LocationInfo />
  }
}
```

我们还使用这个来动态选择将显示哪个组件，感谢`Component`本地变量（注意大写的`C`）。如果变量名的第一个字母是小写的话，它是行不通的。

1.  让我们将`GeoBlog.vue`组件改写为 JSX，并添加`BlogContent`组件：

```js
      <script>
      import AppMenu from './AppMenu.vue'
      import BlogMap from './BlogMap.vue'
      import BlogContent from './content/BlogContent.vue'

      export default {
        render (h) {
          return <div class="geo-blog">
            <AppMenu />
            <div class="panes">
              <BlogMap />
              <BlogContent />
            </div>
          </div>
        }
      }
      </script>
```

不要忘记在文件中删除`<template>`部分！你不能同时拥有渲染函数和模板。

# 没有内容

在继续之前，让我们快速添加`NoContent.vue`组件的模板，它只在没有选择帖子时显示提示：

```js
<template>
  <div class="no-content">
    <i class="material-icons">explore</i>
    <div class="hint">Click on the map to add a post</div>
  </div>
</template>
```

# 创建帖子

当用户在地图上点击没有标记的位置时，我们创建一个草稿帖子；然后右侧面板中的表单将编辑其内容。当用户点击创建按钮时，我们将草稿发送到服务器，并将结果（新帖子数据）添加到帖子列表中。

# 草稿存储操作

在`posts`命名空间存储模块中，我们将需要一些新的操作来创建、更新和清除草稿帖子：

添加`clearDraft`、`createDraft`、`setDraftLocation`和`updateDraft`操作：

```js
 actions: {
        clearDraft ({ commit }) {
          commit('draft', null)
        },

        createDraft ({ commit }) {
          // Default values
          commit('draft', {
            title: '',
            content: '',
            position: null,
            placeId: null,
          })
        },

        setDraftLocation ({ dispatch, getters }, { position, placeId }) {
          if (!getters.draft) {
            dispatch('createDraft')
          }
          dispatch('updateDraft', {
            position,
            placeId,
          })
        },

        updateDraft ({ dispatch, commit, getters }, draft) {
          commit('updateDraft', draft)
        },
      },
```

用户点击地图时，我们称之为`setDraftLocation`的操作将自动创建一个新的草稿，如果没有的话，并更新其位置。

# 博客地图变更

我们需要对`BlogMap`组件进行一些更改，以整合我们的 Vuex 存储。

1.  在`BlogMap.vue`组件中，我们可以为`posts`命名空间模块添加 Vuex 助手，同时重命名我们已经为`maps`模块拥有的助手：

```js
      // Vuex mappers
      // maps module
      const {
        mapGetters: mapsGetters,
        mapActions: mapsActions,
      } = createNamespacedHelpers('maps')
      // posts module
      const {
        mapGetters: postsGetters,
        mapActions: postsActions,
      } = createNamespacedHelpers('posts')
```

1.  添加`draft` getter：

```js
 computed: {
        ...mapsGetters([
          'center',
          'zoom',
        ]),
        ...postsGetters([
          'draft',
        ]),
        // ...
      },
```

1.  也添加`setDraftLocation`动作：

```js
 methods: {
        ...mapsActions([
          'setCenter',
          'setUserPosition',
          'setZoom',
        ]),

        ...postsActions([
          'setDraftLocation',
        ]),
      },
```

# 点击处理程序

我们还需要处理地图上的点击，以创建新的博客帖子。

1.  在地图上添加`click`处理程序：

```js
      <googlemaps-map
        :center="center"
        :zoom="zoom"
        :options="mapOptions"
        @update:center="setCenter"
        @update:zoom="setZoom"
        @click="onMapClick"
      >
```

1.  添加相应的方法，调度`setDraftLocation`动作，并带有可能的`latLng`（位置）和来自 Google Maps 的`placeId`：

```js
 onMapClick (event) {
        this.setDraftLocation({
          position: event.latLng,
          placeId: event.placeId,
        })
      },
```

现在您可以尝试在地图上点击--两个变化（一个用于创建草稿，一个用于更新其位置）应该在开发工具中记录下来。

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/435f77ad-0ade-480b-8a5e-734329233d70.png)

# 幽灵标记

我们想在草稿的位置显示一个透明标记。要使用的组件是`googlemaps-marker`：

在`googlemaps-map`组件中添加一个新的标记，该标记使用`draft` getter 的信息：

```js
      <!-- New post marker -->
      <googlemaps-marker
        v-if="draft"
        :clickable="false"
        :label="{
          color: 'white',
          fontFamily: 'Material Icons',
          text: 'add_circle',
        }"
        :opacity=".75"
        :position="draft.position"
        :z-index="6"
      />
```

如果您看不到新的标记，请刷新页面。

尝试在地图上点击，看看幽灵标记的效果：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/d375c3c2-a67a-4a0d-b825-ce6883bff7b8.png)

# 帖子表单

继续到`CreatePost.vue`组件！这个组件将显示一个表单，用于输入新帖子的详细信息，比如标题和内容。

1.  让我们首先用一个简单的表单创建它的模板：

```js
      <template>
        <form
          class="create-post"
          @submit.prevent="handleSubmit">
    <input
            name="title"
            v-model="title"
            placeholder="Title"
            required />

          <textarea
            name="content"
            v-model="content"
            placeholder="Content"
            required />

          <div class="actions">
            <button
              type="button"
              class="secondary"
              @click="clearDraft">
              <i class="material-icons">delete</i>
              Discard
            </button>
            <button
              type="submit"
              :disabled="!formValid">
              <i class="material-icons">save</i>
              Post
            </button>
          </div>
        </form>
      </template>
```

1.  然后映射来自`posts`模块的 Vuex 助手：

```js
      <script>
      import { createNamespacedHelpers } from 'vuex'

      // posts module
      const {
        mapGetters: postsGetters,
        mapActions: postsActions,
      } = createNamespacedHelpers('posts')
      </script>
```

1.  添加必要的 getter 和方法：

```js
      export default {
        computed: {
          ...postsGetters([
            'draft',
          ]),
        },
        methods: {
          ...postsActions([
            'clearDraft',
            'createPost', // We will create this one very soon
            'updateDraft',
          ]),
        },
      }
```

1.  然后我们将添加一些计算属性，这些属性与表单输入元素绑定，使用`v-model`指令：

```js
 title: {
        get () {
          return this.draft.title
        },
        set (value) {
          this.updateDraft({
            ...this.draft,
            title: value,
          })
        },
      },

      content: {
        get () {
          return this.draft.content
        },
        set (value) {
          this.updateDraft({
            ...this.draft,
            content: value,
          })
        },
      },

      formValid () {
        return this.title && this.content
      },
```

如您所见，我们可以用两种方式在此对象表示法中使用计算属性：使用 getter 和使用 setter！这样，我们可以用它们来读取一个值，但也可以轻松地改变它：

+   `get()`在首次读取计算属性时或者需要重新计算时被调用

+   当属性被赋值时调用`set(value)`，例如`this.a = 'new value'`

这在使用 Vuex 和表单时非常有用，因为它允许我们为`get`部分使用 Vuex getter，为`set`部分使用 Vuex 动作！

1.  我们还需要一个`handleSubmit`方法，该方法调度`createPost`动作，我们很快将创建它：

```js
      handleSubmit () {
        if (this.formValid) {
          this.createPost(this.draft)
        }
      },
```

# 发出请求

我们现在将实现一个动作，将新的地理位置博客帖子发送到服务器。

1.  让我们在`posts` Vuex 模块中创建新的`createPost`动作（不要忘记导入`$fetch`）：

```js
      async createPost ({ commit, dispatch }, draft) {
        const data = {
          ...draft,
          // We need to get the object form
          position: draft.position.toJSON(),
        }

        // Request
        const result = await $fetch('posts/new', {
          method: 'POST',
          body: JSON.stringify(data),
        })
        dispatch('clearDraft')

        // Update the posts list
        commit('addPost', result)
        dispatch('selectPost', result._id)
      },
```

这是我们迄今为止最复杂的操作！它准备数据（注意我们如何将 Google Maps 的`position`对象序列化为与 JSON 兼容的普通对象）。然后我们向服务器的`/posts/new`路径发送 POST 请求，并检索结果，这是新的真实帖子对象（其`_id`字段已设置）。最后，草稿被清除，新帖子被添加到存储并被选中。

1.  我们还需要一个新的`selectPost`操作，这样新帖子将自动被选中：

```js
      async selectPost ({ commit }, id) {
        commit('selectedPostId', id)
        // TOTO fetch the post details (comments, etc.)
      },
```

现在你可以通过点击地图来创建帖子！

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/3b59b9f1-15d7-400b-b937-534a89b0cb57.png)

# 获取帖子

在这一部分，我们将从服务器获取帖子并在地图上显示它们。

# 存储操作

每当地图边界由于用户平移或缩放地图而改变时，我们都会获取帖子。

# 获取帖子操作

让我们创建获取帖子的操作，但首先我们需要解决一个问题。以下会发生什么：

1.  用户移动地图。

1.  向服务器发出请求 A。

1.  用户再次移动地图。

1.  发送请求 B。

1.  由于某种原因，我们在请求 A 之前收到了请求 B 的响应。

1.  我们从请求 B 设置帖子列表。

1.  收到了请求 A 的响应。

1.  帖子列表被替换为不再是最新的请求。

这就是为什么我们需要在发出新请求时中止先前的请求。为了做到这一点，我们将为每个请求使用一个唯一标识符：

1.  在`posts.js`文件的顶部声明唯一标识符：

```js
      let fetchPostsUid = 0
```

1.  现在我们可以添加新的`fetchPosts`操作，它只在地图边界与上次不同的情况下获取帖子（在负载中有一个额外的`force`参数）：

```js
      async fetchPosts ({ commit, state }, { mapBounds, force }) {
        let oldBounds = state.mapBounds
        if (force || !oldBounds || !oldBounds.equals(mapBounds)) {
          const requestId = ++fetchPostsUid

          // Request
          const ne = mapBounds.getNorthEast()
          const sw = mapBounds.getSouthWest()
          const query = `posts?ne=${
            encodeURIComponent(ne.toUrlValue())
          }&sw=${
            encodeURIComponent(sw.toUrlValue())
          }`
          const posts = await $fetch(query)

          // We abort if we started another query
          if (requestId === fetchPostsUid) {
            commit('posts', {
              posts,
              mapBounds,
            })
          }
        }
      },
```

`++fetchPostsUid`表达式将 1 添加到`fetchPostsUid`，然后返回新值。我们将地图边界编码为两个点：东北和西南。

我们中止查询的方式是通过比较我们在发出请求之前存储的唯一 ID（`requestId`）和当前 ID 计数器（`fetchPostsUid`）。如果它们不同，我们就不提交结果，因为这意味着另一个请求已经发出（因为我们每次增加计数器）。

# 操作分派

在`maps`存储中，让我们创建一个`setBounds`操作，当地图在平移或缩放后处于空闲状态时将被分派。这个操作将从`posts`模块中分派`fetchPosts`：

1.  使用`{ root: true }`选项以非命名空间方式分派操作，这样你就可以访问`posts`模块：

```js
 setBounds ({ dispatch }, value) {
        dispatch('posts/fetchPosts', {
          mapBounds: value,
        }, {
          root: true,
        })
      },
```

我们在`maps`模块中创建了另一个动作，因为它与地图有关，而且将来可能会做更多的事情，而不仅仅是分派另一个动作。

1.  在`BlogMap.vue`组件中，在右侧辅助器上映射新的`setBounds`动作，并在地图上添加一个`'map'`引用和一个`'idle'`事件监听器：

```js
      <googlemaps-map
        ref="map"
        :center="center"
        :zoom="zoom"
        :options="mapOptions"
        @update:center="setCenter"
        @update:zoom="setZoom"
        @click="onMapClick"
        @idle="onIdle"
      >
```

1.  并添加相应的`onIdle`方法来分派`setBounds`动作并传递地图边界：

```js
 onIdle () {
        this.setBounds(this.$refs.map.getBounds())
      },
```

刷新应用程序，并在您平移或缩放地图时查看开发工具中的`posts`突变。

# 显示标记

仍然在`BlogMap`组件中，我们将再次使用`googlemaps-marker`来循环遍历帖子并为每个帖子显示一个标记。在右侧辅助器上映射`posts`和`currentPost`获取器，以及`selectPost`动作，并在`googlemaps-map`组件内部添加标记循环：

```js
<googlemaps-marker
  v-for="post of posts"
  :key="post._id"
  :label="{
    color: post === currentPost ? 'white' : 'black',
    fontFamily: 'Material Icons',
    fontSize: '20px',
    text: 'face',
  }"
  :position="post.position"
  :z-index="5"
  @click="selectPost(post._id)"
/>
```

您现在可以刷新应用程序，并看到您之前添加的帖子出现在地图上！如果您点击帖子标记，其图标也应该变成白色。

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/7d9e15e1-1cf4-4e0c-9ea0-ed7506a2f990.png)

# 登录和注销

我们还没有完成帖子获取--我们需要对用户登录或退出做出反应：

+   当用户注销时，我们将清除帖子列表和上次注册的地图边界，以便可以再次获取帖子

+   用户登录时，我们将再次获取帖子，并最终重新选择先前选择的帖子

# 注销

首先，我们将实现注销动作。

1.  让我们在`posts` Vuex 模块中添加一个`logout`动作，清除帖子获取数据：

```js
 logout ({ commit }) {
        commit('posts', {
          posts: [],
          mapBounds: null,
        })
      },
```

1.  我们可以从主存储中的`logout`动作（在`store/index.js`文件中）调用此动作：

```js
      logout ({ commit, dispatch }) {
        commit('user', null)
        $fetch('logout')
        // ...
        dispatch('posts/logout')
      },
```

这将起作用，但我们可以改进这段代码--我们可以将`posts`命名空间子模块的`logout`动作定义为根动作。这样，当我们分派`'logout'`动作时，将同时调用`logout`和`posts/logout`！

1.  在`posts`模块中使用此对象表示法来进行`logout`动作：

```js
      logout: {
        handler ({ commit }) {
          commit('posts', {
            posts: [],
            mapBounds: null,
          })
        },
        root: true,
      },
```

`handler`属性是在此动作上调用的函数，`root`属性指示此是否为根动作。现在，`logout`动作在动作分派系统方面不再是命名空间的，并且如果分派了非命名空间的`'logout'`动作，将被调用。

在此`logout`动作中进行的状态、获取器、提交和分派仍然是命名空间的。只有它的调用不再是命名空间的！

1.  您可以从主存储中的`logout`动作中删除`dispatch('posts/logout')`行。

# 登录

当用户成功登录时，我们将调度一个非命名空间的`'logged-in'`动作。

1.  回到`posts`模块，在新对象表示法中添加`logged-in`动作：

```js
 'logged-in': {
        handler ({ dispatch, state }) {
          if (state.mapBounds) {
            dispatch('fetchPosts', {
              mapBounds: state.mapBounds,
              force: true,
            })
          }
          if (state.selectedPostId) {
            dispatch('selectPost', state.selectedPostId)
          }
        },
        root: true,
      },
```

1.  在主存储`login`动作中，如果用户成功验证，则调度这个新的`logged-in`动作：

```js
      if (user) {
        // ...
        dispatch('logged-in')
      }
```

# 选择一篇文章

这是本章的最后一部分！我们现在将创建文章内容组件，它将显示标题、内容、位置信息和评论列表。文章详情对象与文章对象相同，还包括作者数据、评论列表和每条评论的作者。

# 文章详情

让我们首先修改我们的`posts` Vuex 模块，为文章详情做准备。

# 文章选择和发送的存储更改

1.  在状态中添加一个`selectedPostDetails`数据属性，并添加相应的 getter 和 mutation：

```js
      state () {
        return {
          // ...
          // Fetched details for the selected post
          selectedPostDetails: null,
        }
      },

      getters: {
        // ...
        selectedPostDetails: state => state.selectedPostDetails,
      },

      mutations: {
        // ...
        selectedPostDetails (state, value) {
          state.selectedPostDetails = value
        },
      },
```

1.  在`selectPost`中，使用对服务器上`/post/<id>`路由的请求获取详情：

```js
      async selectPost ({ commit }, id) {
        commit('selectedPostDetails', null)
        commit('selectedPostId', id)
        const details = await $fetch(`posts/${id}`)
        commit('selectedPostDetails', details)
      },
```

1.  还要添加一个新的`unselectPost`动作：

```js
 unselectPost ({ commit }) {
        commit('selectedPostId', null)
      },
```

# 文章内容组件

当用户在地图上点击博客标记时，我们需要在侧边栏中显示其内容。我们将在一个专用的`PostContent`组件中实现这一点。

1.  让我们通过开始初始模板来实现`content/PostContent.vue`组件：

```js
      <template>
        <div class="post-content">
          <template v-if="details">
            <div class="title">
              <img :src="details.author.profile.photos[0].value" />
              <span>
                <span>{{ details.title }}</span>
                <span class="info">
                  <span class="name">
                    {{ details.author.profile.displayName }}</span>
                  <span class="date">{{ details.date | date }}</span>
                </span>
              </span>
            </div>
            <div class="content">{{ details.content }}</div>
            <!-- TODO Comments -->
            <div class="actions">
              <button
                type="button"
                class="icon-button secondary"
                @click="unselectPost">
                <i class="material-icons">close</i>
              </button>
              <!-- TODO Comment input -->
            </div>
          </template>
          <div class="loading-animation" v-else>
            <div></div>
          </div>
        </div>
      </template>
```

第一部分是带有作者头像、标题、作者姓名和创建日期的标题。然后我们显示文章内容，接着是评论列表，以及底部的操作工具栏。在我们从服务器接收到文章详情响应之前，它还会显示一个加载动画。

1.  然后我们需要一个带有`details` getter 和`posts`模块中的`unselectPost`动作的脚本部分：

```js
      <script>
      import { createNamespacedHelpers } from 'vuex'

      // posts module
      const {
        mapGetters: postsGetters,
        mapActions: postsActions,
      } = createNamespacedHelpers('posts')

      export default {
        computed: {
          ...postsGetters({
            details: 'selectedPostDetails',
          }),
        },

        methods: {
          ...postsActions([
            'unselectPost',
          ]),
        },
      }
      </script>
```

现在你可以尝试选择一篇文章标记，并在右侧面板中看到其内容显示出来：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/ca28bb2a-f800-4cc5-92f9-bb56bd5d761b.png)

# 位置信息和作用域插槽

我们将在右侧边栏顶部显示关于当前文章位置的信息，包括名称和地址。我们将要使用`vue-googlemaps`中的组件来利用 Vue 的一个特性，叫做“作用域插槽”。

# 作用域插槽以将数据传递给父组件

你应该已经知道什么是插槽——它们允许我们将元素或组件放入其他组件中。有了作用域插槽，声明`<slot>`部分的组件可以将数据传递给嵌入在插槽中的视图。

例如，我们可以有一个带有默认插槽的组件，其中`results`属性中有一系列结果：

```js
<template>
  <div class="search">
    <slot />
  </div>
</template>

<script>
export default {
  computed: {
    results () {
      return /* ... */
    },
  },
}
</script>
```

我们可以通过插槽将此属性传递给包含模板部分的外部视图，就像这样：

```js
<slot :results="results" />
```

在使用此组件时，您可以通过在带有`slot-scope`属性的模板中包装代码来检索作用域数据。所有作用域数据将在此属性对象中可用：

```js
<Search>
  <template slot-scope="props">
    <div>{{props.results.length}} results</div>
  </template>
</Search>
```

如果只有一个子元素，则不需要`<template>`标签。

这是`vue-googlemaps`库的组件，我们很快将从中获取来自 Google Maps 的数据。

作用域插槽在与循环结合时也非常有用：

```js
<slot v-for="r of results" :result="r" />
```

在使用它时，插槽的内容将被重复，并将传递当前项目：

```js
<Search>
  <div slot-scope="props" class="result">{{props.result.label}}</div>
</Search>
```

在这个例子中，如果`results`计算属性返回三个项目，我们将有三个显示结果标签的`<div>`。

# 组件的实现

我们现在将使用这个新的作用域插槽概念来显示与博客帖子相关的地点信息。

1.  让我们在`components/content`文件夹中创建一个名为`PlaceDetails.vue`的小组件，显示位置的名称和地址：

```js
      <script>
      export default {
        props: {
          name: String,
          address: String,
        },

        render (h) {
          return <div class="details">
            <div class="name"><i class="material-icons">place</i>   
             {this.name}</div>
            <div class="address"> {this.address}</div>
          </div>
        },
      }
      </script>
```

然后我们将实现`LocationInfo.vue`组件。

1.  首先是模板，我们在其中使用`googlemaps-place-details`组件，如果我们在帖子上存储了 Google Maps 的`placeId`，或者使用`googlemaps-geocoder`组件，它将从帖子的位置找到最相关的对应地址，并通过作用域插槽检索结果：

```js
      <template>
        <div class="location-info" v-if="currentPost">
          <!-- Place -->
          <googlemaps-place-details
            v-if="currentPost.placeId"
            :request="{
              placeId: currentPost.placeId
            }">
            <PlaceDetails
              slot-scope="props"
              v-if="props.results"
              :name="props.results.name"
              :address="props.results.formatted_address" />
          </googlemaps-place-details>

          <!-- Position only -->
          <googlemaps-geocoder
            v-else
            :request="{
              location: currentPost.position,
            }">
            <PlaceDetails
              slot-scope="props"
              v-if="props.results"
              :name="props.results[1].placeDetails.name"
              :address="props.results[0].formatted_address" />
          </googlemaps-geocoder>
        </div>
        <div v-else></div>
      </template>
```

1.  在脚本部分，将`posts`模块中的`currentPost` getter 映射到，并导入我们刚刚创建的`PlaceDetails`组件：

```js
      <script>
      import PlaceDetails from './PlaceDetails.vue'
      import { createNamespacedHelpers } from 'vuex'

      // posts module
      const {
        mapGetters: postsGetters,
      } = createNamespacedHelpers('posts')

      export default {
        components: {
          PlaceDetails,
        },

        computed: postsGetters([
    'currentPost',
      ]),
      }
      </script>
```

现在，如果您选择或起草一篇帖子，您应该在右侧面板顶部看到位置信息显示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/4f709430-71bb-473d-898f-05052dfa5146.png)

# 评论 - 功能组件

这是本章的最后一部分，我们将在其中实现帖子组件，并了解更多关于更快的功能组件的知识。

# 存储更改以供评论使用

在进入功能组件之前，我们需要在 Vue 中奠定基础

1.  在`posts` Vuex 模块中，我们需要一个新的 mutation，它将直接向帖子添加评论：

```js
 addComment (state, { post, comment }) {
        post.comments.push(comment)
      },
```

1.  还要添加新的`sendComment`动作，它将向服务器发送查询到`/posts/<id>/comment`路由，并将其添加到所选的帖子中：

```js
      async sendComment({ commit, rootGetters }, { post, comment }) {
        const user = rootGetters.user
        commit('addComment', {
          post,
          comment: {
            ...comment,
            date: new Date(),
            user_id: user._id,
            author: user,
          },
        })

        await $fetch(`posts/${post._id}/comment`, {
          method: 'POST',
```

```js
          body: JSON.stringify(comment),
        })
      },
```

我们从操作上下文中使用`rootGetters`来检索用户数据，因为它不在这个命名空间模块中。

# 功能组件

Vue 中的每个组件实例在创建时都必须设置一些内容，例如数据反应性系统、组件生命周期等。还有一种称为函数组件的轻量级组件。它们没有自己的状态（无法使用`this`关键字），也无法在开发工具中显示，但在某些情况下有一个非常好的优势——它们速度更快，占用的内存更少！

我们博客文章上的评论是很好的函数组件候选，因为我们可能需要显示很多评论。

要创建一个函数组件，将`functional: true`选项添加到其定义对象中：

```js
export default {
  functional: true,
  render (h, { props, children }) {
    return h(`h${props.level}`, children)
  },
}
```

由于组件没有状态，我们无法访问`this`，`render`函数会得到一个新的`context`参数，其中包含 props、事件监听器、子内容、插槽和其他数据。您可以在官方文档中找到完整的列表（[`vuejs.org/v2/guide/render-function.html#Functional-Components`](https://vuejs.org/v2/guide/render-function.html#Functional-Components)）。

在编写函数组件时，您不总是需要声明 props。您可以将所有内容作为 props 获取，但它们也会在`context.data`中传递下来。

请注意，您还可以使用带有`functional`属性的模板，而不是`functional: true`选项：

```js
<template functional>
  <div class="my-component">{{ props.message }}</div>
</template>
```

1.  现在在`PostContent.vue`旁边创建一个新的`Comment.vue`组件：

```js
      <script>
      import { date } from '../../filters'

      export default {
        functional: true,

        render (h, { props }) {
          const { comment } = props
          return <div class="comment">
            <img class="avatar" src=
            {comment.author.profile.photos[0].value} /&gt;
            <div class="message">
              <div class="info">
              <span class="name">{comment.author.profile.displayName}
              </span>
                <span class="date">{date(comment.date)}</span>
              </div>
              <div class="content">{comment.content}</div>
            </div>
          </div>
        },
      }
      </script>
```

1.  回到我们的`PostContent`组件；让我们在窗格中央添加评论列表，并在窗格底部添加评论表单：

```js
      <div class="comments">
        <Comment
          v-for="(comment, index) of details.comments"
          :key="index"
          :comment="comment" />
      </div>
      <div class="actions">
        <!-- ... -->
        <input
          v-model="commentContent"
          placeholder="Type a comment"
          @keyup.enter="submitComment" />
        <button
          type="button"
          class="icon-button"
          @click="submitComment"
          :disabled="!commentFormValid">
          <i class="material-icons">send</i>
        </button>
      </div>
```

1.  然后在脚本部分添加`Comment`组件、`commentContent`数据属性、`commentFormValid`计算属性、`sendComment` Vuex 动作和`submitComment`方法：

```js
      import Comment from './Comment.vue'

      export default {
        components: {
          Comment,
        },
        data () {
          return {
            commentContent: '',
          }
        },
        computed: {
          ...postsGetters({
            details: 'selectedPostDetails',
          }),
          commentFormValid () {
            return this.commentContent
          },
        },
        methods: {
          ...postsActions([
            'sendComment',
            'unselectPost',
          ]),
          async submitComment () {
            if (this.commentFormValid) {
              this.sendComment({
                post: this.details,
                comment: {
                  content: this.commentContent,
                },
              })
              this.commentContent = ''
            }
          },
        },
      }
```

您现在可以向所选的帖子添加评论：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/caf312a5-de5f-4fb8-bf99-92854abc262f.png)

# 总结

在本章中，我们介绍了通过使用官方的 Vuex 库来进行状态管理的非常重要的概念。这将帮助您构建更复杂的应用程序，并大大提高其可维护性。我们使用 Google OAuth API 对用户进行身份验证，嵌入 Google 地图和整个地理定位博客！所有这些都是通过在我们的应用程序中集成 Vuex 存储来实现的，使我们的组件更简单，代码更易于演变。

如果您想进一步改进应用程序，以下是一些想法：

+   显示帖子标记上的点赞数

+   允许编辑或删除评论

+   使用 Web-sockets 添加实时更新

在下一章中，我们将学习更多关于服务器端渲染、国际化、测试和部署的知识。
