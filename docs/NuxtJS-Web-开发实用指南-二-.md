# NuxtJS Web 开发实用指南（二）

> 原文：[`zh.annas-archive.org/md5/95454EEF6B1A13DFE0FAD028BE716A19`](https://zh.annas-archive.org/md5/95454EEF6B1A13DFE0FAD028BE716A19)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第二部分：视图、路由、组件、插件和模块

在本节中，我们将开始添加路由、页面、模板、组件、插件、模块和 Vue 表单，使我们的 Nuxt 应用程序变得更加复杂和有趣。

本节包括以下章节：

+   第四章，*添加视图、路由和过渡*

+   第五章，*添加 Vue 组件*

+   第六章，*编写插件和模块*

+   第七章，*添加 Vue 表单*


添加视图、路由和过渡

在前一章中，您为前端 UI 框架和库创建了一些简单的页面、路由，甚至布局，但它们只是非常基本的。因此，在本章中，我们将深入研究每一个，以及 Nuxt 中的模板。您将自定义默认模板和布局，并创建自定义模板。您还将学习如何自定义全局 meta 标签，并将特定的 meta 标签添加到应用程序的各个页面。如果信息是有用的。您将为页面过渡创建 CSS 和 JavaScript 过渡和动画。因此，在本章结束时，您将能够通过本章学到的知识以及在上一章中学到的知识，交付一个简单但完全功能的 Web 应用程序或网站（带有一些虚拟数据）。

本章我们将涵盖的主题如下：

+   创建自定义路由

+   创建自定义视图

+   创建自定义过渡

# 第四章：创建自定义路由

如果我们要了解 Nuxt 中路由器的工作原理，我们首先应该了解它在 Vue 中的工作原理。然后我们可以理解如何在我们的 Nuxt 应用程序中实现它。传统 Vue 应用程序中的自定义路由是通过 Vue Router 创建的。因此，让我们首先了解一下 Vue Router 是什么。

## 介绍 Vue Router

Vue Router 是一个 Vue 插件，允许您在单页面应用程序（SPA）中创建强大的路由，而无需刷新页面即可在页面之间导航。一个快速的用法是，例如，如果我们想要一个用于所有用户但具有不同用户 ID 的`User`组件。您可以如下使用此组件：

```js
const User = {
  template: '<div>User {{ $route.params.id }}</div>'
}

const router = new VueRouter({
  routes: [
    { path: '/user/:id', component: User }
  ]
})
```

在这个例子中，任何以`/user`开头的路由后跟一个 ID（例如，`/user/1`或`user/2`）将被定向到`User`组件，该组件将使用该 ID 呈现模板。这仅在安装了 Vue 插件时才可能，因此让我们看看如何在下一节为 Vue 应用程序安装它，然后学习它在 Nuxt 应用程序中的工作原理。

有关 Vue Router 的更多信息，请访问[`router.vuejs.org/`](https://router.vuejs.org/)。

## 安装 Vue Router

在 Vue 中，您必须*显式*安装 Vue Router 以在传统的 Vue 应用程序中创建路由。即使您使用 Vue CLI（我们将在第十一章中介绍*编写路由中间件和服务器中间件*），您也必须选择手动选择功能以从提示您选择的选项中选择 Router，以选择您需要的功能。因此，让我们看看如何在本节中*手动*安装它。安装 Vue Router 有两种选项：

+   您可以使用 npm：

```js
$ npm install vue-router
```

然后，在应用程序根目录中，通过`Vue.use()`显式导入`vue-router`：

```js
import Vue from 'vue'
import VueRouter from 'vue-router'

Vue.use(VueRouter)
```

+   或者，您可以使用 CDN 或直接下载：

```js
<script src="/path/to/vue.js"></script>
<script src="/path/to/vue-router.js"></script>
```

如果您使用 CDN，只需在 Vue 核心之后添加`vue-router`，其余安装将自行处理。安装 Vue Router 完成后，您可以使用它创建路由。

## 使用 Vue Router 创建路由

如果您使用 CDN 选项，首先在项目根目录中创建一个`.html`文件，其中包含以下基本 HTML 结构，并在`<head>`块中包含 CDN 链接：

```js
<!DOCTYPE html>
<html>
  <head>
    <script src="https://unpkg.com/vue/dist/vue.js"></script>
    <script src="https://unpkg.com/vue-router/dist/vue-router.js"></script>
  </head>
  <body>
    //...
  </body>
</html>
```

之后，您可以通过以下步骤快速启动 Vue Router：

1.  在`<body>`块中使用以下标记创建应用程序基础：

```js
<div id="app">
  <h1>Hello App!</h1>
  <p>
    <router-link to="/about">About</router-link>
    <router-link to="/contact">Contact</router-link>
  </p>
  <router-view></router-view>
</div>
<script type="text/javascript">
  //...
</script>
```

`<router-link>`组件用于指定目标位置，并将呈现为带有`href`的`<a>`标记，而`<router-view>`组件用于呈现请求的内容，这是我们将在下一步中创建的 Vue 组件。

1.  在`<script>`块中定义两个 Vue 组件：

```js
const About = { template: '<div>About</div>' }
const Contact = { template: '<div>Contact</div>' }
```

1.  创建一个名为`routes`的常量变量，并将 Vue 组件添加到`component`属性中，该属性与`<router-link>`中的链接匹配：

```js
const routes = [
  { path: '/about', component: About },
  { path: '/contact', component: Contact }
]
```

1.  使用`new`运算符创建路由实例，并传入`routes`常量：

```js
const router = new VueRouter({
  routes
})
```

请注意，上述代码块中的`route`是 ES6/ES2015 中`routes: routes`的简写形式（简写属性名称）。有关简写属性名称的更多信息，请访问[`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/Object_initializer`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/Object_initializer)。

1.  使用`new`运算符创建 Vue 实例，并传入`router`实例，然后将`#app`元素挂载到根实例：

```js
const app = new Vue({
  router
}).$mount('#app')
```

1.  在浏览器中运行应用程序，然后您应该在屏幕上看到关于和联系链接。当您导航到`/about`和`/contact`时，您应该看到它们的组件如预期般成功呈现在屏幕上。

您可以在我们的 GitHub 存储库中的`/chapter-4/vue/vue-route/basic.html`中找到前面应用的代码，并在您喜欢的浏览器中运行它，以查看它的工作原理。

现在，让我们探索 Nuxt 如何通过 Vue Router 为我们生成前面的路由。在 Nuxt 中创建路由的过程更简单，因为`vue-router`在 Nuxt 中已经预装。这意味着从技术上讲，您可以跳过传统 Vue 应用程序中的安装步骤。您还可以跳过前面的 JavaScript 步骤-步骤 3 到 5。Nuxt 将自动扫描`/pages/`目录中的`.vue`文件树，并为您生成路由。因此，让我们探索 Nuxt 如何为您创建和处理路由。我们将首先开始创建基本路由。

## 创建基本路由

基本路由是通过简单地将具有固定文件名的`.vue`文件添加到`/pages/`目录中来创建的。您还可以通过将`.vue`文件组织到不同的文件夹中来创建子路由。接下来看一个例子：

```js
pages/
--| users/
-----| index.vue
-----| john-doe.vue
--| index.vue
```

然后，Nuxt 将为您生成以下路由，而无需您编写任何路由：

```js
router: {
  routes: [
    {
      name: 'index',
      path: '/',
      component: 'pages/index.vue'
    },
    {
      name: 'users',
      path: '/users',
      component: 'pages/users/index.vue'
    },
    {
      name: 'users-john-doe',
      path: '/users/john-doe',
      component: 'pages/users/john-doe.vue'
    }
  ]
}
```

您可以在我们的 GitHub 存储库中的`/chapter-4/nuxt-universal/routing/basic-routes/`中找到此示例应用程序。

您应该熟悉上一章中的这些基本路由。这种类型的路由适用于顶级页面，例如`/about`、`/contact`和`/posts`。但是，如果在每个顶级页面中有多个子页面，并且它们会随着时间动态增加，那么您应该使用动态路由来处理这些子页面的路由。让我们在下一节中了解如何创建动态路由。

## 创建动态路由

当使用下划线时，Nuxt 会生成动态路由。在更复杂的应用程序中，动态路由是有用且不可避免的。因此，如果您想创建动态路由，只需创建一个带有前缀下划线后跟文件名（或目录）的`.vue`文件（或目录）。接下来看一个例子：

```js
pages/
--| _slug/
-----| index.vue
--| users/
-----| _id.vue
--| index.vue
```

然后，您将从 Nuxt 获得以下路由，而无需您编写任何路由：

```js
router: {
  routes: [
    {
      name: 'index',
      path: '/',
      component: 'pages/index.vue'
    },
    {
      name: 'users-id',
      path: '/users/:id?',
      component: 'pages/users/_id.vue'
    },
    {
      name: 'slug',
      path: '/:slug',
      component: 'pages/_slug/index.vue'
    }
  ]
}
```

您可以在我们的 GitHub 存储库中的`/chapter-4/nuxt-universal/routing/dynamic-routes/`中找到此示例应用程序。

动态路由适用于共享相同布局的页面。例如，如果您使用相同布局的`/about`和`/contact`路由（这是相当不太可能的情况），那么前面动态路由示例代码中的`/_slug/`目录是一个不错的选择。因此，就像在`/users`路由下共享相同布局的子页面一样，`/_id.vue`文件方法对于这种情况是一个不错的选择。

除了使用这个（简单的）动态路由为`/users`路由下的子页面创建子路由之外，我们还可以为它们使用更复杂的动态路由-嵌套路由。这是一种情况，当渲染子页面时，您不希望父布局完全被子布局替换；换句话说，当您希望在父布局*内*呈现子页面时。让我们在下一节中了解如何实现这一点。

## 创建嵌套路由

简而言之，从嵌套组件生成的路由称为嵌套路由。在某些情况下，您可能希望组合嵌套在其他组件（父组件）内的组件（子组件），并且您希望在父组件的特定视图中呈现这些子组件，而不是将父组件替换为子组件。

要在 Vue 应用程序中执行此操作，您需要在父组件中插入一个`<router-view>`组件，用于加载子组件的内容。例如，假设您有一个`Users`父组件，并且当调用特定用户时，您希望加载单个用户的内容到此父组件中。然后，您可以按照以下步骤为它们创建嵌套路由：

1.  创建一个父组件：

```js
const Users = {
  template: `
    <div class="user">
      <h2>Users</h2>
      <router-link to="/user/1">1</router-link>
      <router-link to="/user/2">2</router-link>
      <router-link to="/user/3">3</router-link>
      <router-view></router-view>
    </div>
  `
}
```

如果将前面的代码放入图表中，可以如下进行可视化解释：

```js
+-------------------+
| users             |
| +---------------+ |
| | 1, 2, 3       | |
| +---------------+ |
| +---------------+ |
| | <router-view> | |
| +---------------+ |
+-------------------+
```

1.  创建一个子组件，用于显示单个用户的内容或信息：

```js
const User = { template: '<div>User {{ $route.params.id }}</div>' }
```

1.  使用`children`属性创建嵌套路由，如下所示：

```js
const routes = [
  {
    path: '/users',
    component: Users,
    children: [
      {
        path: ':id',
        component: User,
        name: 'user-id'
      }
    ]
  }
]
```

1.  定义路由实例并传入前面的嵌套路由，然后将路由器注入 Vue 根实例：

```js
const router = new VueRouter({
  routes
})

const app = new Vue({
  router
}).$mount('#app')
```

然后，当单击子链接时，前面的代码将生成以下可视化内容；例如，子编号`1`和`/users/1`将动态生成为其路由：

```js
/users/1
+-------------------+
| users             |
| +---------------+ |
| | 1, 2, 3       | |
| +---------------+ |
| +---------------+ |
| | User 1        | |
| +---------------+ |
+-------------------+
```

1.  但我们还没有完成，因为当尚未调用任何用户时，我们仍然需要处理`/users`中的空视图。因此，为了解决这个问题，您将创建一个索引子组件，如下所示：

```js
const Index = { template: '<div>Users Index</div>' }
```

1.  在`children`块中添加前面的索引组件，使用空字符串`''`作为`path`键的值：

```js
const routes = [
  {
    path: '/users',
    component: Users,
    children: [
      {
        path: '',
        component: Index,
        name: 'user-index'
      },
      //...
    ]
  }
]
```

1.  现在，如果你在浏览器中导航到`/users`，你应该会得到以下结果：

```js
/users
+-------------------+
| users             |
| +---------------+ |
| | 1, 2, 3       | |
| +---------------+ |
| +---------------+ |
| | Users Index   | |
| +---------------+ |
+-------------------+
```

你可以看到`children`选项只是另一个路由配置对象的数组，就像`routes`常量本身一样。因此，你可以根据需要保持嵌套视图的层级。但是，为了更好地维护，我们应该尽量避免深层嵌套，保持我们的应用尽可能简单。

你可以在我们的 GitHub 仓库的`/chapter-4/vue/vue-route/nested-route.html`中找到前面示例的代码。

在 Nuxt 中也是一样的；你可以通过使用`vue-router`的子路由来创建嵌套路由。如果你想定义嵌套路由的父组件，你只需要创建一个与包含子视图的目录同名的 Vue 文件。看下面的例子：

```js
pages/
--| users/
-----| _id.vue
-----| index.vue
--| users.vue
```

Nuxt 将自动生成以下路由：

```js
router: {
  routes: [
    {
      path: '/users',
      component: 'pages/users.vue',
      children: [
        {
          path: '',
          component: 'pages/users/index.vue',
          name: 'users'
        },
        {
          path: ':id',
          component: 'pages/users/_id.vue',
          name: 'users-id'
        }
      ]
    }
  ]
}
```

你可以看到 Nuxt 生成的路由与在 Vue 应用中一样。请注意，在 Nuxt 中，我们在父组件（`.vue`文件）中包含`<nuxt-child/>`，而在 Vue 中，我们在父组件中包含`<router-view></router-view>`，就像前面的`User`示例一样。让我们通过一个练习更好地理解这一点，就像我们在 Vue 应用中做的那样：

1.  创建一个带有`<nuxt-child/>`组件的父组件：

```js
// pages/users.vue
<template>
  <div>
    <h1>Users</h1>
    <nuxt-child/>
  </div>
</template>
```

1.  创建一个索引子组件来保存用户列表：

```js
// pages/users/index.vue
<template>
  <ul>
    <li v-for="user in users" v-bind:key="user.id">
      <nuxt-link :to="`users/${user.id}`">
        {{ user.name }}
      </nuxt-link>
    </li>
  </ul>
</template>

<script>
import axios from 'axios'
export default {
  async asyncData () {
    let { data } = await 
    axios.get('https://jsonplaceholder.typicode.com/users')
    return { users: data }
  }
}
</script>
```

请注意，在本章的即将到来的部分中，我们将介绍`asyncData`方法和第五章中的`axios`，所以现阶段不用担心它们。

1.  创建一个单独的子组件，其中包含返回到子索引页面的链接：

```js
// pages/users/_id.vue
<template>
  <div v-if="user">
    <h2>{{ user.name }}</h2>
    <nuxt-link class="button" to="/users">
      Users
    </nuxt-link>
  </div>
</template>

<script>
import axios from 'axios'
export default {
  async asyncData ({ params }) {
    let { data } = await 
    axios.get('https://jsonplaceholder.typicode.com/users/'
     + params.id)
    return { user: data }
  }
}
</script>
```

你可以看到 Nuxt 已经帮你省去了在 Vue 应用中配置嵌套路由的步骤，使用了`children`属性（如前面 Vue 应用示例中的*步骤 3*所示）。

因此，在这个 Nuxt 应用中，当子页面渲染后，`users.vue`中的`<h1>Users</h1>`元素将始终可见。包含列表元素的`<ul>`元素将始终被子页面替换。如果父级信息在子页面中是持久的，这将非常有用，因为在子页面渲染时不需要重新请求父级信息。

你可以在我们的 GitHub 仓库的`/chapter-4/nuxt-universal/routes/nested-routes/`中找到这个示例应用。

由于存在用于“升级”基本路由的动态路由，您可能会问，嵌套路由的动态路由呢？从技术上讲，是的，这是可能的，它们被称为动态嵌套路由。因此，让我们在下一节中了解更多关于它们的信息。

## 创建动态嵌套路由

我们已经看到了动态路由和嵌套路由的工作原理，因此从理论上和技术上讲，可以将这两个选项结合起来，通过在动态父级（例如`_topic`）中拥有动态子级（例如`_subTopic`）来创建动态嵌套路由。以下是最佳示例结构：

```js
pages/
--| _topic/
-----| _subTopic/
--------| _slug.vue
--------| index.vue
-----| _subTopic.vue
-----| index.vue
--| _topic.vue
--| index.vue
```

Nuxt 将自动生成以下路由：

```js
router: {
  routes: [
    {
      path: '/',
      component: 'pages/index.vue',
      name: 'index'
    },
    {
      path: '/:topic',
      component: 'pages/_topic.vue',
      children: [
        {
          path: '',
          component: 'pages/_topic/index.vue',
          name: 'topic'
        },
        {
          path: ':subTopic',
          component: 'pages/_topic/_subTopic.vue',
          children: [
            {
              path: '',
              component: 'pages/_topic/_subTopic/index.vue',
              name: 'topic-subTopic'
            },
            {
              path: ':slug',
              component: 'pages/_topic/_subTopic/_slug.vue',
              name: 'topic-subTopic-slug'
            }
          ]
        }
      ]
    }
  ]
}
```

您可以看到路由变得更加复杂，这可能会使您的应用程序在阅读和尝试理解文件目录树时更难开发，因为它相当抽象，如果增长“更大”，它可能会变得过于抽象。将应用程序设计和结构化为尽可能简单是一个良好的实践。以下示例路由是这种类型路由的一个很好的例子：

+   `/_topic/`的一些示例如下：

```js
/science
/arts
```

+   `/_topic/_subTopic/`的一些示例如下：

```js
/science/astronomy
/science/geology
/arts/architecture
/arts/performing-arts
```

+   `/_topic/_subTopic/_slug.vue`的一些示例如下：

```js
/science/astronomy/astrophysics
/science/astronomy/planetary-science
/science/geology/biogeology
/science/geology/geophysics
/arts/architecture/interior-architecture
/arts/architecture/landscape-architecture
/arts/performing-arts/dance
/arts/performing-arts/music
```

您可以在我们的 GitHub 存储库的`/chapter-4/nuxt-universal/routing/dynamic-nested-routes/`中找到此类型路由的示例应用程序。

创建动态路由和页面始终需要路由中的参数（换句话说，路由参数），以便我们可以将它们（无论是 ID 还是 slug）传递给动态页面进行处理。但在处理和响应参数之前，验证它们是一个好主意。因此，让我们看看如何在下一个主题中验证路由参数。

## 验证路由参数

您可以在组件中使用`validate`方法来验证动态路由的参数，在进一步处理或异步获取数据之前验证参数。这种验证*应该*始终返回`true`以继续前进；如果得到`false`布尔值，Nuxt 将停止路由并立即抛出 404 错误页面。例如，您希望确保 ID 必须是一个数字：

```js
// pages/users/_id.vue
export default {
  validate ({ params }) {
    return /^\d+$/.test(params.id)
  }
}
```

因此，如果您使用`localhost:3000/users/xyz`请求页面，您将收到一个带有“此页面找不到”消息的 404 页面。如果要自定义 404 消息，可以使用`throw`语句抛出带有`Error`对象的异常，如下所示：

```js
// pages/users/_id.vue
export default {
  validate ({ params }) {
    let test = /^\d+$/.test(params.id)
    if (test === false) {
      throw new Error('User not found')
    }
    return true
  }
}
```

你还可以在`validate`方法中使用`async`进行`await`操作：

```js
async validate({ params }) {
  // ...
}
```

你还可以在`validate`方法中使用`return`承诺：

```js
validate({ params }) {
  return new Promise(...)
}
```

你可以在`/chapter-4/nuxt-universal/routing/validate-route-params/`中找到前面示例应用程序的 ID 验证。

在我们的 GitHub 存储库中。

验证路由参数是处理无效或未知路由的一种方式，但另一种处理它们的方式是使用`_.vue`文件来捕捉它们。所以，让我们在下一节中找出如何做。

## 使用 _.vue 文件处理未知路由

除了使用`validate`方法抛出*通用*404 页面外，你还可以使用`_.vue`文件抛出自定义错误页面。让我们通过以下步骤来探讨这是如何工作的：

1.  在`/pages/`目录中创建一个空的`_.vue`文件，如下所示：

```js
pages/
--| _.vue
--| index.vue
--| users.vue
--| users/
-----| _id.vue
-----| index.vue
```

1.  为这个`_.vue`文件添加任何自定义内容，如下所示：

```js
// pages/_.vue
<template>
  <div>
    <h1>Not found</h1>
    <p>Sorry, the page you are looking for is not found.</p>
  </div>
</template>
```

1.  启动应用程序并导航到以下路由，你会发现 Nuxt 将调用这个`_.vue`文件来处理这些请求，这些请求不匹配正确的路由级别：

```js
/company
/company/careers
/company/careers/london
/users/category/subject
/users/category/subject/type
```

1.  如果你想在特定级别上抛出一个更具体的 404 页面 - 例如，仅在`/users`路由中 - 那么在`/users/`文件夹中创建另一个`_.vue`文件，如下所示：

```js
pages/
--| _.vue
--| index.vue
--| users.vue
--| users/
-----| _.vue
-----| _id.vue
-----| index.vue
```

1.  为这个`_.vue`文件添加自定义内容，如下所示：

```js
// pages/users/_.vue
<template>
  <div>
    <h1>User Not found</h1>
    <p>Sorry, the user you are looking for is not found.</p>
  </div>
</template>
```

1.  再次导航到以下路由，你会发现 Nuxt 不再调用这个`/pages/_.vue`文件来处理不匹配的请求：

```js
/users/category/subject
/users/category/subject/type
```

相反，Nuxt 现在调用`/pages/users/_.vue`文件来处理它们。

你可以在我们的 GitHub 存储库的`/chapter-4/nuxt-universal/routing/unknown-routes/`中找到这个示例应用程序。

我们希望到现在为止，你应该知道如何以各种方式创建适合你的应用程序的路由，但是在 Nuxt 中，路由和页面是密不可分的，不可分割的，所以你还需要知道如何创建 Nuxt 页面，这些页面是自定义视图。你将在下一个主题中学习如何做到这一点。

# 创建自定义视图

你在上面创建的自定义路由中的每个路由都将落在一个“页面”上，该页面具有我们希望在前端显示的所有 HTML 标记和内容。从软件架构的角度来看，这些 HTML 标记和内容，包括元信息、图像和字体，都是你的应用程序的视图或呈现层。在 Nuxt 中，我们可以轻松地创建和自定义我们的视图。让我们来了解一下 Nuxt 视图的组成部分以及如何自定义它。

## 了解 Nuxt 视图

Nuxt 中的视图结构包括应用程序模板、HTML 头部、布局和页面层。你可以使用它们来为应用程序路由创建视图。在一个更复杂的应用程序中，你可以使用来自 API 的数据填充它们，而在一个简单的应用程序中，你可以直接手动嵌入虚拟数据。我们将在接下来的章节中逐一介绍这些层。在深入了解之前，请花一点时间研究下面的图表，它将为你提供 Nuxt 视图的完整视图：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/hsn-nuxt-web-dev/img/68280e28-fc1c-49b0-8bfa-422ee8202972.png)

参考来源：[`nuxtjs.org/guide/views`](https://nuxtjs.org/guide/views)

你可以看到文档-HTML 文件是 Nuxt 视图的最外层，其后是布局、页面和可选的页面子层和 Vue 组件层。文档-HTML 文件是你的 Nuxt 应用程序的应用程序模板。让我们首先从这个最基本的层开始，学习如何在下一节中自定义它。

## 自定义应用程序模板

Nuxt 在幕后为你创建 HTML 应用程序模板，因此基本上你不必费心去创建它。然而，你仍然可以自定义它，比如添加脚本或样式，如果你想的话。默认的 Nuxt HTML 模板就是这么简单：

```js
<!DOCTYPE html>
<html {{ HTML_ATTRS }}>
 <head>
 {{ HEAD }}
 </head>
 <body {{ BODY_ATTRS }}>
 {{ APP }}
 </body>
</html>
```

如果你想要更改或覆盖这个默认值，只需在根目录中创建一个`app.html`文件。看下面的例子：

```js
// app.html
<!DOCTYPE html>
<!--[if IE 9]><html lang="en-US" class="lt-ie9 ie9" {{ HTML_ATTRS }}><![endif]-->
<!--[if (gt IE 9)|!(IE)]><!--><html {{ HTML_ATTRS }}><!--<![endif]-->
  <head>
    {{ HEAD }}
  </head>
  <body {{ BODY_ATTRS }}>
    {{ APP }}
  </body>
</html>
```

重新启动你的应用程序，你会看到你的自定义应用程序 HTML 模板已经替换了 Nuxt 的默认模板。

你可以在我们的 GitHub 存储库的`/chapter-4/nuxt-universal/view/app-template/`中找到这个例子。

接下来最接近 HTML 文档（即`<html>`元素）的一层是 HTML 头部，即`<head>`元素，其中包含重要的元信息以及页面的脚本和样式。我们不会直接在应用程序模板中添加或自定义这些数据，而是在 Nuxt 配置文件和`/pages/`目录中的文件中进行。因此，让我们在下一节中了解如何做到这一点。

## 创建自定义 HTML 头部

一个 HTML 的`<head>`元素由`<title>`、`<style>`、`<link>`和`<meta>`元素组成。手动添加这些元素可能是一项繁琐的任务。因此，Nuxt 会在你的应用程序中为你处理这些元素。在第二章中，*开始使用 Nuxt*，你学到了它们是由 Nuxt 从 JavaScript 对象中的数据生成的，这些数据是用花括号（`{}`）在 Nuxt 配置文件中编写的，如下所示：

```js
// nuxt.config.js
export default {
  head: {
    title: 'Default Title',
    meta: [
      { charset: 'utf-8' },
      { name: 'viewport', content: 'width=device-width, initial-scale=1' },
      { hid: 'description', name: 'description', content: 'parent' }
    ],
    link: [
      { rel: 'icon', type: 'image/x-icon', href: '/favicon.ico' }
    ]
  }
}
```

在本主题中，我们对 Nuxt 配置文件中的`meta`块和`/pages/`目录中的页面感兴趣。Nuxt 使用 Vue Meta 插件来管理这些元属性。因此，要了解它在 Nuxt 中的工作原理，我们首先应该了解它在传统 Vue 应用程序中的工作原理。

### 介绍 Vue Meta

Vue Meta 是一个用于在 Vue 中管理和创建 HTML 元数据的 Vue 插件，具有内置的 Vue 响应性。您只需向任何 Vue 组件添加`metaInfo`特殊属性，它将自动呈现为 HTML 元标记，如下所示：

```js
// Component.vue
export default {
  metaInfo: {
    meta: [
      { charset: 'utf-8' },
      { name: 'viewport', content: 'width=device-width, initial-scale=1' }
    ]
  }
}
```

上述的 JavaScript 代码块将被呈现为您页面中的以下 HTML 标签：

```js
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
```

有关 Vue Meta 的更多信息，请访问[`vue-meta.nuxtjs.org/`](https://vue-meta.nuxtjs.org/)。

您可以看到，您只需要在 JavaScript 对象中提供元数据。现在，让我们安装它并学习如何为 Vue 应用程序配置它。

### 安装 Vue Meta

像所有其他 Vue 插件一样，您可以通过以下步骤安装 Vue Meta 并将其连接到您的 Vue 应用程序中：

1.  通过 npm 安装 Vue Meta：

```js
$ npm i vue-meta
```

或者，您可以通过 CDN 使用`<script>`元素安装它，如下所示：

```js
<script src="https://unpkg.com/vue-meta@1.5.8/lib/vue-meta.js"></script>
```

1.  在您的主应用程序文件中使用 Vue Router 导入 Vue Meta，如果您正在编写一个 ES6 JavaScript 应用程序：

```js
//main.js
import Vue from 'vue'
import Router from 'vue-router'
import Meta from 'vue-meta'

Vue.use(Router)
Vue.use(Meta)
export default new Router({
  //...
})
```

1.  然后，您可以在任何 Vue 组件中使用它，如下所示：

```js
// app.vue
var { data } = await axios.get(...)
export default {
  metaInfo () {
    return {
      title: 'Nuxt',
      titleTemplate: '%s | My Awesome Webapp',
      meta: [
        { vmid: 'description', name: 'description', content: 'My
          Nuxt portfolio' }
      ]
    }
  }
}
```

在这个例子中，因为我们使用`axios`来异步获取数据，我们必须使用`metaInfo`方法从异步数据中注入元信息，而不是使用`metaInfo`属性。您甚至可以使用`titleTemplate`选项为您的页面标题添加模板，就像前面的例子一样。接下来，我们将创建一个简单的 Vue 应用程序，并使用这个插件，以便您可以更全面地了解如何使用它。

### 在 Vue 应用程序中使用 Vue Meta 创建元数据

像往常一样，我们可以在单个 HTML 页面上启动和运行 Vue 应用程序。让我们开始吧：

1.  在`<head>`块中包含 CND 链接：

```js
<script src="https://unpkg.com/vue/dist/vue.js"></script>
<script src="https://unpkg.com/vue-router/dist/vue-router.js"></script>
<script src="https://unpkg.com/vue-meta@1.5.8/lib/vue-meta.js"></script>
```

1.  在`<script>`块中创建以下带有元数据的组件：

```js
const About = {
  name: 'about',
  metaInfo: {
    title: 'About',
    titleTemplate: null,
    meta: [
      { vmid: 'description', name: 'description', content: 'About 
        my Nuxt...' 
      }
    ]
  }
}
const Contact = {
  name: 'contact',
  metaInfo: {
    title: 'Contact',
    meta: [
      { vmid: 'description', name: 'description', content: 
       'Contact me...' }
    ]
  }
}
```

1.  然后，在根实例中添加默认的元数据：

```js
const app = new Vue({
  metaInfo: {
    title: 'Nuxt',
    titleTemplate: '%s | My Awesome Webapp',
    meta: [
      { vmid: 'description', name: 'description', content: 'My 
        Nuxt portfolio' 
      }
    ]
  },
  router
}).$mount('#app')
```

请注意，我们可以通过在子组件的`titleTemplate`选项中简单地添加`null`来覆盖组件中的默认元数据模板，就像前面的`About`组件一样。

您可以在我们的 GitHub 存储库的`/chapter-4/vue/vue-meta/basic.html`中找到此示例应用程序。

在此示例中，由于我们不使用`axios`异步获取数据，因此可以直接使用`metaInfo`属性，而不是使用`metaInfo`方法来使用异步数据注入 meta 信息。然后，当您在刚刚创建的路由周围导航时，您将看到页面标题和 meta 信息在浏览器中发生变化。在 Vue 应用程序中使用此插件非常容易，不是吗？现在，我们应该看看它在 Nuxt 应用程序中的工作原理。

### 自定义 Nuxt 应用程序中的默认 meta 标签

在 Nuxt 应用程序中创建和自定义 meta 信息更简单，因为 Vue Meta 默认包含在 Nuxt 中。这意味着您无需像在 Vue 应用程序中那样安装它。您只需在 Nuxt 配置文件中使用`head`属性来定义应用程序的默认`<meta>`标签，如下所示：

```js
// nuxt.config.js
head: {
  title: 'Nuxt',
  titleTemplate: '%s | My Awesome Webapp',
  meta: [
    { charset: 'utf-8' },
    { name: 'viewport', content: 'width=device-width, initial-scale=1' },
    { hid: 'description', name: 'description', content: 'My 
      Nuxt portfolio' }
  ]
}
```

然而，Nuxt 和 Vue 应用程序之间的区别在于，在 Nuxt 中必须使用`hid`键，而在 Vue 中使用`vmid`。您应该*始终*使用`hid`来防止在子组件中定义它们（meta 标签）时重复 meta 标签的发生。另外，请注意，`metaInfo`键仅在 Vue 中使用，而`title`键在 Nuxt 中使用，用于添加我们的元信息。

这就是您如何为您的 Nuxt 应用程序添加和自定义标题和 meta 标签。但是，它们是全局添加的，这意味着它们适用于应用程序中的所有页面。那么，如何将它们特定地添加到页面并在 Nuxt 配置文件中覆盖全局的呢？让我们在下一节中找出答案。

### 为 Nuxt 页面创建自定义 meta 标签

如果要为特定页面添加自定义 meta 标签或在 Nuxt 配置文件中覆盖默认的 meta 标签，只需直接在该特定页面上使用`head`方法，该方法将返回一个包含`title`和`meta`选项数据的 JavaScript 对象，如下所示：

```js
// pages/index.vue
export default {
  head () {
    return {
      title: 'Hello World!',
      meta: [
        { hid: 'description', name: 'description', content: 'My 
          Nuxt portfolio' }
      ]
    }
  }
}
```

然后，您将获得此页面的输出：

```js
<title data-n-head="true">Hello World! | My Awesome Webapp</title>
<meta data-hid="description" name="description" content="My Nuxt portfolio" data-n-head="true">
```

您可以在我们的 GitHub 存储库中的`/chapter-4/nuxt-universal/view/html-head/`中找到此示例应用程序。

所以，就是这样。这就是关于 Nuxt 中应用模板和 HTML 头的全部内容。Nuxt 视图中的下一个内部层是布局，我们将在下一节中指导您如何创建自定义布局。让我们开始吧。

## 创建自定义布局

布局是您的页面和组件的支柱。您可能希望在应用程序中拥有多个不同的布局。在使用`npx create-nuxt-app`脚手架工具安装应用程序时，`/layouts/`目录中会自动生成一个名为`default.vue`的布局。就像应用程序模板一样，您可以修改此默认布局或创建自己的自定义布局。

### 修改默认布局

默认布局始终用于没有特定或自定义布局的页面。如果您转到`/layouts/`目录并打开此布局，您应该看到其中只有三行代码用于呈现您的页面组件：

```js
// layouts/default.vue
<template>
  <nuxt/>
</template>
```

让我们修改这个默认布局，如下所示：

```js
// layouts/default.vue
<template>
  <div>
    <div>...add a navigation bar here...</div>
    <nuxt/>
  </div>
</template>
```

您应该看到您在那里添加的任何内容 - 例如，应用程序中所有页面上的导航栏。请注意，无论您是修改此布局还是创建新布局，都要确保在您想要 Nuxt 导入页面组件的地方有`<nuxt/>`组件。让我们在下一节中探讨如何创建自定义布局。

### 创建新的自定义布局

有时，我们需要更多的布局来构建更复杂的应用程序。我们可能需要为某些页面创建不同的布局。对于这种情况，您需要创建自定义布局。您可以使用`.vue`文件创建自定义布局，然后将它们放在`/layouts/`目录中。看下面的例子：

```js
// layouts/about.vue
<template>
  <div>
    <div>...add an about navigation bar here....</div>
    <nuxt/>
  </div>
</template>
```

然后，您可以在页面组件中使用`layout`属性将此自定义布局分配给该页面，如下所示：

```js
// pages/about.vue
export default {
  layout: 'about'
  // OR
  layout (context) {
    return 'about'
  }
}
```

现在，Nuxt 将使用`/layouts/about.vue`文件作为此页面组件的基本布局。但是用于显示未知和无效路由的错误页面的布局又是什么呢？让我们在下一节中找出这是如何制作的。

### 创建自定义错误页面

每个安装的 Nuxt 应用程序都带有一个默认错误页面，存储在`@nuxt`包中的`/node_modules/`目录中，Nuxt 用于显示错误，如 404、500 等。您可以通过在`/layouts/`目录中添加`error.vue`文件来自定义它。让我们通过以下步骤了解如何实现这一点：

1.  在`/layouts/`目录中创建自定义错误页面，如下所示：

```js
// layouts/error.vue
<template>
  <div>
    <h2 v-if="error.statusCode === 404">Page not found</h2>
    <h2 v-else>An error occurred</h2>
    <nuxt-link to="/">Home page</nuxt-link>
  </div>
</template>

<script>
export default {
  props: ['error']
}
</script>
```

请注意，错误页面是一个页面组件。起初，它似乎有违直觉和令人困惑，因为它放在`/layouts/`目录而不是`/pages/`目录中。但是，即使它在`/layouts/`目录中，它也应该被视为一个页面。

1.  就像其他页面组件一样，您可以为此错误页面创建自定义布局，如下所示：

```js
// layouts/layout-error.vue
<template>
  <div>
    <h1>Error!</h1>
    <nuxt/>
  </div>
</template>
```

1.  然后，只需将`layout-error`添加到错误页面的`layout`选项中：

```js
// layouts/error.vue
<script>
export default {
  layout: 'layout-error'
}
</script>
```

1.  现在，如果您导航到任何以下未知路由，Nuxt 将调用此自定义错误页面和自定义错误布局：

```js
/company
/company/careers
/company/careers/london
/users/category/subject
/users/category/subject/type
```

你可以在我们的 GitHub 存储库的`/chapter-4/nuxt-universal/view/custom-layouts/404/`中找到这个 404 示例。

就是这样。这就是 Nuxt 中关于布局的全部内容。Nuxt 视图中的下一个内部层是页面，您将在下一节中学习如何为您的应用程序创建自定义页面。所以，请继续阅读。

## 创建自定义页面

页面是 Nuxt 视图的一部分，就像应用程序模板、HTML 头部和布局一样，我们已经介绍过了。`/pages/`目录是您存储页面的地方。您将在这个目录中花费大部分时间来为您的 Nuxt 应用程序创建页面。但是，创建页面并不是什么新鲜事——在上一节中，我们在`/layouts/`目录中创建了一个简单的错误页面，并且在学习如何为我们的应用程序创建自定义路由时创建了许多页面。因此，当您想为特定路由创建自定义页面时，只需在`/pages/`目录中创建一个`.vue`文件；例如，我们可以创建以下页面：

```js
pages/
--| index.vue
--| about.vue
--| contact.vue
```

但是，创建自定义页面需要更多。我们需要了解 Nuxt 中附带的页面属性和函数。尽管页面是 Nuxt 应用程序开发的重要部分，但在 Vue 应用程序开发中并没有强调，它们与 Vue 组件密切相关，并且与组件的工作方式有些不同。因此，要创建页面并充分利用它，我们首先需要了解 Nuxt 中的页面是什么。让我们找出来。

## 理解页面

页面本质上是一个 Vue 组件。它与标准 Vue 组件的区别在于仅在 Nuxt 中添加的属性和函数。我们使用这些特殊的属性和函数在呈现页面之前设置或获取数据，如下所示：

```js
<template>
  <p>{{ message }}!</p>
</template>

<script>
export default {
  asyncData (context) {
    return { message: 'Hello World' }
  }
}
</script>
```

在前面的示例中，我们使用了一个名为`asyncData`的函数来设置消息键中的数据。这个`asyncData`函数是您在 Nuxt 应用程序中经常看到并经常使用的函数之一。让我们深入了解专门为 Nuxt 页面设计的属性和函数。

### asyncData 方法

`asyncData`方法是页面组件中最重要的函数。Nuxt 总是在初始化页面组件*之前*调用这个函数。这意味着每次请求页面时，这个函数都会在页面渲染之前首先被调用。它以 Nuxt 上下文作为第一个参数，并且可以异步使用，如下所示：

```js
<h1>{{ title }}</h1>

export default {
  async asyncData ({ params }) {
    let { data } = await axios.get(
    'https://jsonplaceholder.typicode.com/posts/' + params.id)
    return { title: data.title }
  }
}
```

在这个例子中，我们使用 ES6 解构赋值语法来解开 Nuxt 上下文中打包的属性，而这个特定的属性是`params`。换句话说，

`{ params }`是`context.params`的简写。我们还可以使用解构赋值语法来解开从`axios`的异步结果中的`data`属性。请注意，如果在页面组件的`data`函数中设置了数据集，它将始终与`asyncData`中的数据合并。然后，合并后的数据可以在`<template>`块中使用。让我们创建一个简单的示例来演示`asyncData`如何与`data`函数合并：

```js
<h1>{{ title }}</h1>

export default {
  data () {
    return { title: 'hello world!' }
  },
  asyncData (context) {
    return { title: 'hey nuxt!' }
  }
}
```

从`data`和`asynData`方法返回的数据对象有两组，但是你将得到以下代码的输出：

```js
<h1>hey nuxt!</h1>
```

你可以看到，如果它们都使用*相同*的数据键，`asyncData`函数中的数据将始终*替换*`data`函数中的数据。另外，请注意，我们不能在`asyncData`方法中使用`this`关键字，因为这个方法在页面组件初始化*之前*被调用。因此，你*不能*使用这个方法来更新数据，比如`this.title = data.title`。我们将在第八章中更详细地介绍`asyncData`，*添加服务器端框架*。

有关解构赋值的更多信息，请访问[`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/Destructuring_assignment`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/Destructuring_assignment)。

### fetch 方法

`fetch`方法与`asyncData`方法的工作方式相同，只是它在`created`Vue 生命周期钩子之后被调用——换句话说，在组件初始化之后。与`asyncData`方法一样，它也可以异步使用；例如，你也可以使用它来设置页面组件中的数据。

```js
// pages/users/index.vue
<li v-for="user in users" v-bind:key="user.id">
  <nuxt-link :to="`users/${user.id}`">
    {{ user.name }}
  </nuxt-link>
</li>

import axios from 'axios'
export default {
  data () {
    return { users: [] }
  },
  async fetch () {
    let { data } = await axios.get
    ('https://jsonplaceholder.typicode.com/users')
    this.users = data
  }
}
```

请注意，`data`方法必须与`fetch`方法一起使用来设置数据。由于它在页面组件初始化后调用，我们可以使用`this`关键字来访问`data`方法中的对象。我们还可以使用这个方法从页面组件中将数据设置到 Vuex 存储中，如下所示：

```js
// pages/posts/index.vue
<li v-for="post in $store.state.posts" v-bind:key="post.id">
  <nuxt-link :to="`posts/${post.id}`">
    {{ post.title }}
  </nuxt-link>
</li>

import axios from 'axios'
export default {
  async fetch () {
    let { data } = await axios.get(
    'https://jsonplaceholder.typicode.com/posts')
    const { store } = this.$nuxt.context
    store.commit('setPosts', data)
  }
}
```

我们将在第十章中更详细地介绍与 Vuex 存储一起使用的`fetch`方法，*添加一个 Vuex 存储*。

您可以在我们的 GitHub 存储库的`/chapter-4/nuxt-universal/view/custom-pages/fecth-method/`部分找到上述代码。

有关`fetch`方法的更多信息，请访问[`nuxtjs.org/api/pages-fetch`](https://nuxtjs.org/api/pages-fetch)和[`nuxtjs.org/blog/understanding-how-fetch-works-in-nuxt-2-12/`](https://nuxtjs.org/blog/understanding-how-fetch-works-in-nuxt-2-12/)。

### 头部方法

`head`方法用于在页面上设置`<meta>`标签，我们在*创建自定义 HTML 头部*部分中已经介绍过。它也可以与`/components/`目录中的组件一起使用。

### 布局属性

`layout`键（或属性）用于指定页面在`/layouts/`目录中的布局，我们在*创建自定义布局*部分中已经介绍过。

### 加载属性

`loading`属性允许您禁用默认的加载进度条或在特定页面上设置自定义加载进度条。我们在第二章中简要介绍过，因此我们知道可以在 Nuxt 配置文件中配置全局默认加载组件，如下所示：

```js
// nuxt.config.js
export default {
  loading: {
    color: '000000'
  }
}
```

然而，由于我们在`localhost`上，并且不需要太多时间来处理数据，通常我们不会看到这个加载条在工作中。为了看到它的工作情况，让我们演示一下这个加载组件是如何工作和看起来的，通过*延迟*组件中数据的加载时间来演示（但请注意，这个演示*不应该*在生产环境中进行）：

1.  在`/pages/`目录中创建一个名为`index.vue`的页面，其中包含以下代码：

```js
// pages/index.vue
<template>
  <div class="container">
    <p>Hello {{ name }}!</p>
    <NuxtLink to="/about">
      Go to /about
    </NuxtLink>
  </div>
</template>

<script>
export default {
  asyncData () {
    return new Promise((resolve) => {
      setTimeout(function () {
        resolve({ name: 'world' })
      }, 1000)
    })
  }
}
</script>
```

1.  在`/pages/`目录中创建另一个名为`about.vue`的页面，其中包含以下代码：

```js
// pages/about.vue
<template>
  <div class="container">
    <p>About Page</p>
    <NuxtLink to="/">
      Go to /
    </NuxtLink>
  </div>
</template>

<script>
export default {
  asyncData () {
    return new Promise((resolve) => {
      setTimeout(function () {
        resolve({})
      }, 1000)
    })
  }
}
</script>
```

在这两个页面中，我们使用`setTimeout`来延迟 1 秒钟的数据响应。因此，当在页面之间导航时，您应该在请求页面加载之前看到顶部出现黑色加载条。

您可以在我们的 GitHub 存储库中的`/chapter-4/nuxt-universal/view/custom-pages/loading-page/`中找到此示例。

1.  当然，我们可以通过在`/components/`目录中创建组件来创建自定义加载栏或层。参考以下示例：

```js
// components/loading.vue
<template>
  <div v-if="loading" class="loading-page">
    <p>Loading...</p>
  </div>
</template>

<script>
export default {
  data () {
    return { loading: false }
  },
  methods: {
    start () { this.loading = true },
    finish () { this.loading = false },
  }
}
</script>

<style scoped>
.loading-page {
  position: fixed;
  //...
}
</style>
```

请注意，自定义加载组件中必须暴露`start`和`finish`方法，以便 Nuxt 在路由更改时调用您的组件并使用这些方法（调用`start`方法）并加载（调用`finish`方法）。

因此，在这个组件中，加载元素始终是隐藏的，因为`data`方法中默认将`loading`属性设置为`false`。只有在路由更改时`loading`属性设置为`true`时，加载元素才会变为可见。然后在路由完成加载后，`loading`属性再次设置为`false`时，它会再次隐藏。

有关这些和其他可用方法的更多信息，请访问[`nuxtjs.org/api/configuration-loading`](https://nuxtjs.org/api/configuration-loading)。

1.  在 Nuxt 配置文件的`loading`属性中包含前面自定义组件的路径：

```js
// nuxt.config.js
export default {
  loading: '~/components/loading.vue'
}
```

您可以在我们的 GitHub 存储库中的`/chapter-4/nuxt-universal/view/custom-pages/loading-global-custom/`中找到此示例。

1.  我们还可以根据特定页面配置加载行为，如下所示：

```js
// pages/about.vue
export default {
  loading: false
}
```

1.  如果页面上`loading`键的值为`false`，它将自动停止调用`this.$nuxt.$loading.finish()`和`this.$nuxt.$loading.start()`方法，这允许您在脚本中*手动*控制它们，如下所示：

```js
// pages/about.vue
<span class="link" v-on:click="goToFinal">
  click here
</span>

export default {
  loading: false,
  mounted () {
    setTimeout(() => {
      this.$nuxt.$loading.finish()
    }, 5000)
  },
  methods: {
    goToFinal () {
      this.$nuxt.$loading.start()
      setTimeout(() => {
        this.$router.push('/final')
      }, 5000)
    }
  }
}

```

1.  然后，在`/pages/`目录中创建`final.vue`页面：

```js
// pages/final.vue
<template>
  <div class="container">
    <p>Final Page</p>
    <NuxtLink to="/">
      Go to /
    </NuxtLink>
  </div>
</template>
```

在这个例子中，您可以看到您可以使用`this.$nuxt.$loading.finish()`和`this.$nuxt.$loading.start()`手动控制加载栏。加载栏在`mounted`方法中需要 5 秒钟才能完成。当您触发`goToFinal`方法时，加载栏立即开始，并且需要 5 秒钟才能将路由更改为`/final`。

您可以在我们的 GitHub 存储库中的`/chapter-4/nuxt-universal/view/custom-pages/loading-page/`中找到此示例。

### 过渡属性

`transition`属性用于指定页面的过渡。您可以使用字符串、对象或带有此键的函数，如下所示：

```js
// pages/about.vue
export default {
  transition: ''
  // or
  transition: {}
  // or
  transition (to, from) {}
}
```

我们将在本章后面的*创建自定义过渡*部分深入介绍`transition`属性。

### scrollToTop 属性

`scrollToTop`键用于在呈现页面之前使嵌套路由中的页面从顶部开始。默认情况下，当您转到另一个页面时，Nuxt 会滚动到顶部，但在嵌套路由的子页面上，Nuxt 会保持在前一个子路由的相同滚动位置。因此，如果您希望告诉 Nuxt 在这些页面上滚动到顶部，则将`scrollToTop`设置为`true`，如下所示：

```js
// pages/users/_id.vue
export default {
  scrollToTop: true
}
```

### 验证方法

`validate`方法是动态路由的验证器，我们已经在*验证路由参数*部分中进行了介绍。

### 中间件属性

`middleware`属性用于指定页面的中间件。分配的中间件将始终在页面呈现之前执行，如下所示：

```js
// pages/secured.vue
export default {
  middleware: 'auth'
}
```

在此示例中，`auth`是您将在`/middleware/`目录中创建的中间件的文件名，如下所示：

```js
// middleware/auth.js
export default function ({ route }) {
  //...
}
```

我们将在第十一章中深入讨论中间件，*编写路由中间件和服务器中间件*。

所以，就是这样。您已经完成了关于 Nuxt 视图的部分，从应用程序模板、HTML 头部和布局到页面。干得好！我们将在下一章中讨论 Vue 组件。但现在，我们应该看的下一件事是在 Nuxt 中创建自定义页面之间的过渡，因为过渡和页面是密切相关的，就像您之前简要介绍过的页面`transition`属性一样。所以，让我们继续进行本章的最后一个主题，您将在其中了解如何创建自定义过渡。

# 创建自定义过渡

到目前为止，您已经成功为 Nuxt 应用程序创建了多个路由和页面，并在页面之间切换时添加了一个加载栏。这已经使得应用程序看起来相当不错。但这并不是您在 Nuxt 中可以做的全部。您可以在*页面之间*添加更多令人惊叹的效果和过渡。这就是页面中的`transition`属性（例如，`/pages/about.vue`）以及 Nuxt 配置文件中的`pageTransition`和`layoutTransition`选项的用处。

我们可以通过 Nuxt 配置文件*全局*应用过渡，或者*特定*应用于某些页面。我们将指导您了解这个主题。但是，要理解 Nuxt 中过渡的工作原理，我们首先应该了解它在 Vue 中是如何工作的，然后我们可以学习如何在路由更改时在我们的页面上实现它。让我们开始吧。

## 理解 Vue 过渡

Vue 依赖于 CSS 过渡，并使用`<transition>`Vue 组件来包裹 HTML 元素或 Vue 组件以添加 CSS 过渡，如下所示：

```js
<transition>
  <p>hello world</p>
</transition>
```

你可以看到这有多么容易 - 你可以像吃蛋糕一样轻松地用`<transition>`组件包裹任何元素。当这种情况发生时，Vue 会在适当的时间添加和移除以下 CSS 过渡类到该元素：

+   `.v-enter`和`.v-leave`类定义了过渡开始之前你的元素的外观。

+   `.v-enter-to`和`.v-leave-to`类是你的元素的“完成”状态。

+   `.v-enter-active`和`.v-leave-active`类是元素的活动状态。

这些类是 CSS 过渡发生的地方。例如，在 HTML 页面中进行的过渡可能如下所示：

```js
.element {
  opacity: 1;
  transition: opacity 300ms;
}
.element:hover {
  opacity: 0;
}
```

如果我们将前面的过渡转换为 Vue 上下文，我们将得到以下结果：

```js
.v-enter,
.v-leave-to {
  opacity: 0;
}
.v-leave,
.v-enter-to {
  opacity: 1;
}
.v-enter-active,
.v-leave-active {
  transition: opacity 300ms;
}
```

我们可以将这些 Vue 过渡类简单地可视化为以下图表：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/hsn-nuxt-web-dev/img/64eacc73-de5b-460b-8d5b-29af57a3c3c8.png)

参考来源：[`vuejs.org/v2/guide/transitions.html`](https://vuejs.org/v2/guide/transitions.html)

Vue 默认使用`v-`作为过渡类的前缀，但如果你想更改这个前缀，只需在`<transition>`组件上使用`name`属性来指定一个名称 - 例如，`<transition name="fade">`；然后，你可以"重构"你的 CSS 过渡类，如下所示：

```js
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
  transition: opacity 300ms;
}
```

让我们将前面的过渡应用到一个简单的 Vue 应用程序中，步骤如下：

1.  创建两个简单的路由，并用`<transition>`组件包裹`<router-view>`组件，如下所示：

```js
<div id="app">
  <p>
    <router-link to="/about">About</router-link>
    <router-link to="/contact">Contact</router-link>
  </p>
  <transition name="fade" mode="out-in">
    <router-view></router-view>
  </transition>
</div>
```

1.  添加一个带有前缀`fade-`的 CSS 过渡类的`<style>`块：

```js
<style type="text/css">
  .fade-enter,
  //...
</style>
```

当你在浏览器上运行应用程序时，你会发现在切换路由时，路由组件淡入淡出需要 300 毫秒。

你可以在我们的 GitHub 存储库的`/chapter-4/vue/transitions/basic.html`中找到这个例子。

你可以看到，过渡需要一些 CSS 类来使其工作，但对于 Vue 应用程序来说，掌握它们并不难。现在，让我们看看如何在下一节中在 Nuxt 中应用过渡。

## 使用 pageTransition 属性进行过渡

在 Nuxt 中，不再需要`<transition>`组件。它会默认为您添加，所以您只需在`/assets/`目录或任何特定页面的`<style>`块中创建过渡效果。在 Nuxt 配置文件中使用`pageTransition`属性来设置页面过渡的默认属性。Nuxt 中过渡属性的默认值如下：

```js
{
  name: 'page',
  mode: 'out-in'
}
```

因此，Nuxt 默认使用`page-`作为过渡类的前缀，而 Vue 使用`v-`作为前缀。Nuxt 中默认的过渡模式设置为`out-in`。让我们通过以下步骤来看看 Nuxt 中的过渡是如何实现的：为所有页面创建全局过渡，以及为特定页面创建局部过渡。

1.  在`/assets/`目录中创建一个`transition.css`文件，并添加以下过渡效果：

```js
// assets/css/transitions.css
.page-enter,
.page-leave-to {
  opacity: 0;
}
.page-leave,
.page-enter-to {
  opacity: 1;
}
.page-enter-active,
.page-leave-active {
  transition: opacity 300ms;
}
```

1.  将前面的 CSS 过渡资源的路径添加到 Nuxt 配置文件中：

```js
// nuxt.config.js
export default {
  css: [
    'assets/css/transitions.css'
  ]
}
```

1.  请记住，默认前缀是`page-`，所以如果您想使用不同的前缀，可以在 Nuxt 配置文件中使用`pageTransition`属性来更改前缀：

```js
// nuxt.config.js
export default {
  pageTransition: 'fade'
  // or
  pageTransition: {
    name: 'fade',
    mode: 'out-in'
  }
}
```

1.  然后，在`transitions.css`中将所有默认类名的前缀更改为`fade`，如下所示：

```js
// assets/css/transitions.css
.fade-enter,
.fade-leave-to {
  opacity: 0;
}
```

当路由改变时，这个例子将在所有页面上全局应用过渡效果。

1.  然而，如果我们想要为特定页面应用不同的过渡效果，或者在页面中覆盖全局过渡效果，可以在该页面的`transition`属性中进行设置，如下所示：

```js
// pages/about.vue
export default {
  transition: {
    name: 'fade-about',
    mode: 'out-in'
  }
}
```

1.  然后，在`transitions.css`中为`fade-about`创建 CSS 过渡效果：

```js
// assets/css/transitions.css
.fade-about-enter,
.fade-about-leave-to {
  opacity: 0;
}
.fade-about-leave,
.fade-about-enter-to {
  opacity: 1;
}
.fade-about-enter-active,
.fade-about-leave-active {
  transition: opacity 3s;
}
```

在这个例子中，淡入和淡出`about`页面需要 3 秒，而其他页面只需要 300 毫秒。

您可以在我们的 GitHub 存储库的`/chapter-4/nuxt-universal/transition/page-transition-property/`中找到这个特定页面的例子和全局例子。

您可以看到，Nuxt 再次为您解决了一些重复的任务，并为您提供了创建自定义前缀类名的灵活性。而且，您甚至可以创建*布局之间*的过渡效果！让我们在下一节中了解如何做到这一点。

## 使用`layoutTransition`属性进行过渡

CSS 过渡不仅适用于页面组件，还适用于布局。`layoutTransition`属性的默认值如下：

```js
{
  name: 'layout',
  mode: 'out-in'
}
```

因此，默认情况下布局转换类的前缀是`layout`，默认转换模式是`out-in`。让我们看看如何通过以下步骤为所有布局创建全局转换：

1.  在`/layouts/`目录中创建`about.vue`和`user.vue`布局，如下所示：

```js
// layouts/about.vue
<template>
  <div>
    <p>About layout</p>
    //...
    <nuxt />
  </div>
</template>
```

1.  将前述布局应用于`/pages/`目录中的`about.vue`和`users.vue`页面，如下所示：

```js
// pages/about.vue
<script>
export default {
  layout: 'about'
}
</script>
```

1.  在`/assets/`目录中创建`transition.css`文件，并将以下转换添加到其中：

```js
// assets/css/transitions.css
.layout-enter, 
.layout-leave-to {
  opacity: 0;
}
.layout-leave,
.layout-enter-to {
  opacity: 1;
}
.layout-enter-active,
.layout-leave-active {
  transition: opacity .5s;
}
```

1.  将前面的 CSS 转换资源的路径添加到 Nuxt 配置文件中：

```js
// nuxt.config.js
export default {
  css: [
    'assets/css/transitions.css'
  ]
}
```

1.  默认前缀是`layout-`，但如果您想使用不同的前缀，可以在 Nuxt 配置文件中使用`layoutTransition`属性进行更改：

```js
// nuxt.config.js
export default {
  layoutTransition: 'fade-layout'
  // or
  layoutTransition: {
    name: 'fade-layout',
    mode: 'out-in'
  }
}
```

1.  在`transitions.css`中将所有默认类名的前缀更改为`fade-layout`，如下所示：

```js
// assets/css/transitions.css
.fade-layout-enter,
.fade-layout-leave-to {
  opacity: 0;
}
```

在此示例中，淡入淡出*整个*布局（包括导航）需要 0.5 秒。当您在使用*不同布局*的页面之间导航时，您将看到此转换，但不会在使用相同布局的页面上看到；例如，如果您在`/`和`/contact`之间导航，您将不会得到前面的布局转换，因为它们都使用*相同的布局*，即`/layouts/default.vue`。

您可以在我们的 GitHub 存储库中的`/chapter-4/nuxt-universal/transition/layout-transition-property/`中找到此示例。

再次，您可以看到为布局创建转换非常容易，并且可以自定义其前缀类名称，就像页面转换一样。除了使用 CSS 转换来转换页面和布局之外，我们还可以使用 CSS 动画。因此，让我们在下一节中了解一下。

## 使用 CSS 动画进行转换

CSS 转换仅在**两个状态**之间执行动画：开始和结束。但是，当您需要更多中间状态时，应该使用 CSS 动画，以便通过在开始和结束状态之间添加多个百分比的关键帧来获得更多控制。请看以下示例：

```js
@keyframes example {
  0% { // 1st keyframe or start state.
    background-color: red;
  }
  25% { // 2nd keyframe.
    background-color: yellow;
  }
  50% { // 3rd keyframe.
    background-color: blue;
  }
  100% { // 4th keyframe end state.
    background-color: green;
  }
}
```

`0%`是动画的起始状态，而`100%`是结束状态。您可以通过添加增量百分比（例如`10%`，`20%`，`30%`等）在这两个状态之间添加更多中间状态。但是，CSS 转换没有这种添加关键帧的能力。因此，我们可以说 CSS 转换是 CSS 动画的简单形式。

由于 CSS 过渡实际上是“实际上”是 CSS 动画，我们可以在 Vue/Nuxt 应用程序中应用 CSS 动画，就像我们应用 CSS 过渡一样。让我们通过以下步骤了解如何做到这一点：

1.  将以下 CSS 动画代码添加到`transitions.css`文件中，就像您在上一节中所做的那样：

```js
// assets/css/transitions.css
.bounce-enter-active {
  animation: bounce-in .5s;
}
.bounce-leave-active {
  animation: bounce-in .5s reverse;
}
@keyframes bounce-in {
  0% {
    transform: scale(0);
  }
  50% {
    transform: scale(1.5);
  }
  100% {
    transform: scale(1);
  }
}
```

1.  在 Nuxt 配置文件中将全局默认的`page-`前缀更改为`bounce-`：

```js
// nuxt.config.js
export default {
  pageTransition: 'bounce'
}
```

一旦您添加了上述代码，请刷新您的浏览器，您将会看到在页面之间切换时页面会弹入和弹出。

您可以在我们的 GitHub 存储库的`/chapter-4/nuxt-universal/transition/css-animations/`中找到这个示例。

根据您想要进行动画的复杂程度和详细程度，以及您的 CSS 动画技能水平，您可以为页面和布局创建非常令人惊叹的过渡效果。您只需专注于编写代码并通过 Nuxt 配置文件注册它，然后 Nuxt 将负责在适当的时间添加和删除 CSS 动画类的其余工作。但 JavaScript 呢？我们可以使用 jQuery，或者任何其他 JavaScript 动画库来创建页面和布局的过渡动画吗？答案是肯定的，您可以。让我们在下一节中了解如何做到这一点。

## 使用 JavaScript 钩子进行过渡

除了使用 CSS 进行过渡，您还可以通过在 Vue 应用程序的`<transition>`组件中添加以下钩子来使用 JavaScript 进行过渡：

```js
<transition
  v-on:before-enter="beforeEnter"
  v-on:enter="enter"
  v-on:after-enter="afterEnter"
  v-on:enter-cancelled="enterCancelled"
  v-on:before-leave="beforeLeave"
  v-on:leave="leave"
  v-on:after-leave="afterLeave"
  v-on:leave-cancelled="leaveCancelled"
>
  //..
</transition>
```

请注意，您也可以在开头不添加`v-on`的情况下声明钩子。因此，将钩子写为`:before-enter`与写`v-on:before-enter`是相同的。

然后，在 JavaScript 方面，您应该在`methods`属性中有以下默认方法，以对应上述的钩子：

```js
methods: {
  beforeEnter (el) { ... },
  enter (el, done) {
    // ...
    done()
  },
  afterEnter (el) { ... },
  enterCancelled (el) { ... },
  beforeLeave (el) { ... },
  leave (el, done) {
    // ...
    done()
  },
  afterLeave (el) { ... },
  leaveCancelled (el) { ... }
}
```

您可以单独使用这些 JavaScript 钩子，也可以与 CSS 过渡一起使用。如果您单独使用它们，则必须在`enter`和`leave`钩子（方法）中使用`done`回调，否则这两个方法将同步运行，并且您尝试应用的动画或过渡将立即结束。此外，如果它们单独使用，您还应该在`<transition>`包装器上使用`v-bind:css="false"`，这样 Vue 将安全地忽略您的元素，以防万一您的应用程序中也有 CSS 过渡，但它正在用于其他元素。让我们通过以下步骤创建一个简单的 Vue 应用程序，使用这些 JavaScript 钩子：

1.  将以下 CDN 链接添加到 HTML 的`<head>`块中：

```js
<script src="https://unpkg.com/vue/dist/vue.js"></script>
<script src="https://unpkg.com/vue-router/dist/vue-router.js"></script>
<script src="https://code.jquery.com/jquery-3.3.1.min.js"></script>
```

1.  在`<body>`块中添加应用标记和`<transition>`组件与钩子：

```js
<div id="app">
  <p>
    <router-link to="/about">About</router-link>
    <router-link to="/contact">Contact</router-link>
  </p>
  <transition
    appear
    v-bind:css="false"
    v-on:before-enter="beforeEnter"
    v-on:enter="enter"
    v-on:leave="leave"
    v-on:after-leave="afterLeave">
    <router-view></router-view>
  </transition>
</div>
```

1.  接下来使用以下方法在`<script>`块中协调前面的钩子：

```js
const app = new Vue({
  name: 'App',
  methods: {
    beforeEnter (el) { $(el).hide() },
    enter (el, done) {
      $(el).fadeTo('slow', 1)
      done()
    },
    leave (el, done) {
      $(el).fadeTo('slow', 0, function () {
        $(el).hide()
      })
      done()
    },
    afterLeave (el) { $(el).hide() }
  }
}).$mount('#app')
```

在这个例子中，我们使用 jQuery 的`fadeTo`方法来控制过渡，而不是使用纯 CSS。当在路由组件之间切换时，您应该看到它们淡入淡出，就像`.v-enter`和`.v-leave`CSS 过渡一样。

您可以在我们的 GitHub 存储库的`/chapter-4/vue/transition/js-hooks.html`中找到这个例子。

在 Nuxt 中，我们不需要将 JavaScript 钩子定义为`<transition>`组件，只需要在 Nuxt 配置文件的`pageTransition`中定义 JavaScript 方法，以及在`/pages/`目录中的任何`.vue`文件中定义`transition`。让我们在 Nuxt 应用程序中创建一个快速示例，步骤如下：

1.  在终端上通过 npm 安装 jQuery：

```js
$ npm i jquery
```

1.  由于我们在 Nuxt 配置文件和其他页面中使用 jQuery，我们可以通过 Nuxt 配置文件在 webpack 中*全局*加载 jQuery：

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

1.  在 Nuxt 配置文件的`pageTransition`选项中使用 jQuery 创建全局过渡：

```js
// nuxt.config.js
export default {
  pageTransition: {
    mode: 'out-in',
    css: false,
    beforeEnter: el => { $(el).hide() },
    enter: (el, done) => {
      $(el).fadeTo(1000, 1)
      done()
    },
    //...
  }
}
```

当路由更改时，此示例将在所有页面*全局*应用过渡。此外，我们通过将`css`选项设置为`false`来关闭 CSS 过渡。

请注意，我们将 JavaScript 函数写为对象键的替代方法，以便与过渡组件中的属性钩子关联。

1.  在`/pages/`目录中创建一个`about.vue`页面，并通过`about.vue`页面上的`transition`属性应用不同的过渡，以覆盖前面的全局过渡：

```js
// pages/about.vue
export default {
  transition: {
    mode: 'out-in',
    css: false,
    beforeEnter: el => { $(el).hide() },
    enter: (el, done) => {
      $(el).fadeTo(3000, 1)
      done()
    },
    //...
  }
}
```

因此，在这个例子中，这个特定页面的过渡需要 3 秒钟，而其他页面只需要 1 秒钟。

请注意，如果在 Nuxt 配置文件中未加载 jQuery，则必须将 jQuery 导入`.vue`页面；例如，假设您只想在这个特定页面上设置过渡：

```js
// pages/about.vue
import $ from 'jquery'

export default {
  transition: {
    beforeEnter (el) { $(el).hide() },
    //...
  }
}
```

一旦代码就位，刷新您的浏览器，您应该看到页面在页面路由更改时淡入淡出，就像 Vue 应用程序在页面之间切换时一样。

您可以在我们的 GitHub 存储库的`/chapter-4/nuxt-universal/transition/js-hooks/`中找到这个例子。

干得好；您已经完成了在 Nuxt 中创建过渡的部分！您可以看到 JavaScript 是在 Nuxt 应用程序中编写过渡和动画的另一种很好的方式。但在结束本章之前，让我们来看看我们在过渡部分一直看到的过渡模式。因此，让我们找出它们的用途。

请注意，尽管如今不鼓励使用 jQuery，但在本书中偶尔会使用它，因为它是 Foundation 的依赖项，您在上一章中了解过。因此，我们有时会重新使用它。或者，您可以使用 Anime.js 来制作 JavaScript 动画。有关此库的更多信息，请访问[`animejs.com/`](https://animejs.com/)。

## 理解过渡模式

您可能想知道`mode="out-in"`（在 Vue 中）或`mode: 'out-in'`（在 Nuxt 中）是什么意思-例如，在我们以前的 Vue 应用程序中，其中包含`<div>about</div>`和`<div>contact</div>`组件。它们存在是因为`<div>about</div>`和`<div>contact</div>`之间的过渡是同时渲染的。这是`<transition>`的默认行为：同时进入和离开。但有时，您可能不希望这种同时过渡，因此 Vue 提供了以下过渡模式的解决方案：

+   **`in-out`模式**

此模式用于让新元素首先过渡进入，直到其过渡完成，然后当前元素将过渡出去。

+   **`out-in`模式**

此模式用于让当前元素首先过渡出去，直到其过渡完成，然后新元素将过渡进入。

因此，您可以按以下方式使用这些模式：

+   在 Vue.js 应用程序中，使用它们如下：

```js
<transition name="fade" mode="out-in">
  //...
</transition>
```

+   在 Nuxt 应用程序中，使用它们如下：

```js
export default {
  transition: {
    name: 'fade',
    mode: 'out-in'
  }
}
```

+   在 JavaScript hooks 中，使用它们如下：

```js
export default {
  methods: {
    enter (el, done) {
      done() // equivalent to mode="out-in"
    },
    leave (el, done) {
      done() // equivalent to mode="out-in"
    }
  }
}
```

在创建 Nuxt/Vue 应用程序的自定义过渡方面，我们已经走了很长的路。您现在可以根据本章学到的知识制作一些体面的过渡和动画。因此，由于本书空间有限，我们不会进一步深入探讨这个主题，但是有关 Vue 过渡和动画的更多信息和进一步阅读，请访问[`vuejs.org/v2/guide/transitions.html`](https://vuejs.org/v2/guide/transitions.html)。现在让我们总结一下您在本章学到的内容！

# 总结

在本章中，您学习了 Nuxt 中页面的概念以及如何为应用程序创建不同类型的路由。您学会了如何自定义默认应用程序模板和布局，以及如何创建新的布局和 404 页面。您学会了如何使用 CSS 过渡和动画，以及 JavaScript 钩子和方法，使应用程序页面之间的过渡变得有趣。如果您从头开始一直在跟随指南，那么现在您应该能够交付一个外观漂亮的小项目了。您可以在我们的 GitHub 存储库中的`/chapter-4/nuxt-universal/sample-website/`找到一个网站示例，该示例使用了我们在本章和之前章节中学到的知识。

在下一章中，我们将探索`/components/`目录。您将学习如何在 Nuxt 应用程序中使用它，以便通过更详细地了解 Vue 组件来完善本章中涵盖的布局和页面，包括从页面和布局组件向它们传递数据，创建单文件 Vue 组件，注册全局和本地 Vue 组件等。此外，您还将学习如何使用 mixin 编写可重用的代码，使用 Vue 风格指南中的命名约定来定义组件名称，以便使您的组件组织和标准化，以便更好地进行未来维护。所有这些知识和探索都是值得的。所以，让我们开始吧。
