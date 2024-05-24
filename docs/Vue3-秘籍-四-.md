# Vue3 秘籍（四）

> 原文：[`zh.annas-archive.org/md5/915E62C558C25E5846A894A1C2157B6C`](https://zh.annas-archive.org/md5/915E62C558C25E5846A894A1C2157B6C)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：使用 vue-router 管理路由

您的应用程序的主要部分之一是路由管理。在这里，可以将无限的组件组合在一个地方。

路由能够协调组件的渲染，并根据 URL 指示应用程序应该在哪里。有许多方法可以增加`vue-router`的定制化。您可以添加路由守卫来检查特定路由是否可由访问级别导航，或在进入路由之前获取数据以管理应用程序中的错误。

在本章中，您将学习如何创建应用程序路由、动态路由、别名和信任路由，以及嵌套路由视图。我们还将看看如何管理错误，创建路由守卫，并延迟加载您的页面。

在本章中，我们将涵盖以下教程：

+   创建一个简单的路由

+   创建一个程序化导航

+   创建一个动态路由路径

+   创建一个路由别名

+   创建一个路由重定向

+   创建一个嵌套路由视图

+   创建一个 404 错误页面

+   创建一个身份验证中间件

+   异步延迟加载您的页面

# 技术要求

在本章中，我们将使用**Node.js**和**Vue-CLI**。

注意 Windows 用户：您需要安装一个名为`windows-build-tools`的 npm 包，以便能够安装以下所需的包。为此，请以管理员身份打开 PowerShell 并执行以下命令：

`> npm install -g windows-build-tools`

要安装 Vue-CLI，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> npm install -g @vue/cli @vue/cli-service-global
```

# 创建一个简单的路由

在您的应用程序中，您可以创建无限组合的路由，可以导向任意数量的页面和组件。

`vue-router`是这个组合的维护者。我们需要使用它来设置如何创建路径并为我们的访问者建立路由的指令。

在这个教程中，我们将学习如何创建一个初始路由，该路由将引导到不同的组件。

## 准备工作

这个教程的先决条件如下：

+   Node.js 12+

所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

## 如何做…

创建一个 Vue-CLI 项目，按照以下步骤进行：

1.  我们需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> vue create initial-routes
```

1.  CLI 将询问一些问题，这些问题将有助于创建项目。您可以使用箭头键导航，*Enter*键继续，*Spacebar*选择选项。

1.  有两种方法可以启动新项目。默认方法是基本的 Babel 和 ESLint 项目，没有任何插件或配置，还有`手动`模式，您可以选择更多模式、插件、代码检查器和选项。我们将选择`手动`：

```js
?  Please pick a preset: (Use arrow keys) default (babel, eslint**)** ❯ **Manually select features** ‌
```

1.  现在我们被问及项目中想要的功能。这些功能包括一些 Vue 插件，如 Vuex 或 Vue Router（Vue-Router）、测试器、代码检查器等。选择`Babel`、`Router`和`Linter / Formatter`**：**

```js
?  Check the features needed for your project: (Use arrow keys) ❯ Babel
 TypeScript Progressive Web App (PWA) Support ❯ Router
 Vuex  CSS Pre-processors ❯ Linter / Formatter
 Unit Testing E2E Testing
```

1.  现在 Vue-CLI 会询问您是否要在路由管理中使用历史模式。我们会选择`Y`（是）：

```js
?  Use history mode for router? (Requires proper server setup for
  index fallback in production)  (Y**/n) y**
```

1.  继续此过程，选择一个代码检查器和格式化程序。在我们的情况下，我们将选择`ESLint + Airbnb config`：

```js
?  Pick a linter / formatter config: (Use arrow keys) ESLint with error prevention only ❯ **ESLint + Airbnb config** ESLint + Standard config 
  ESLint + Prettier
```

1.  设置完代码检查规则后，我们需要定义它们何时应用于您的代码。它们可以在保存时应用，也可以在提交时修复：

```js
?  Pick additional lint features: (Use arrow keys)  Lint on save ❯ Lint and fix on commit
```

1.  在定义了所有这些插件、代码检查器和处理器之后，我们需要选择设置和配置存储的位置。最佳存储位置是专用文件，但也可以将它们存储在`package.json`中：

```js
?  Where do you prefer placing config for Babel, ESLint, etc.?  (Use arrow keys) ❯ **In dedicated config files****In package.json** 
```

1.  现在您可以选择是否要将此选择作为将来项目的预设，这样您就不需要再次重新选择所有内容：

```js
?  Save this as a preset for future projects?  (y/N) n
```

我们的步骤将分为五个部分：

+   创建`NavigationBar`组件

+   创建联系页面

+   创建关于页面

+   更改应用程序的主要组件

+   创建路由

让我们开始吧。

### 创建 NavigationBar 组件

现在我们将创建将在我们的应用程序中使用的`NavigationBar`组件。

#### 单文件组件<script>部分

在这一部分，我们将创建单文件组件的<script>部分。按照这些说明正确创建组件：

1.  在`src/components`文件夹中创建一个`navigationBar.vue`文件并打开它。

1.  创建组件的默认`export`对象，具有 Vue 属性`name`：

```js
<script> export default {
  name: 'NavigationBar', }; </script>
```

#### 单文件组件<template>部分

在这一部分，我们将创建单文件组件的<template>部分。按照这些说明正确创建组件：

1.  创建一个带有`id`属性定义为`"nav"`的`div` HTML 元素，并在其中创建三个`RouterLink`组件。这些组件将指向`Home`、`About`和`Contact`路由。在`RouterLink`组件中，我们将添加一个`to`属性，分别定义为每个组件的路由，并将文本内容定义为菜单的名称： 

```js
<div id="nav">
 <router-link to="/">
  Home
  </router-link> |
  <router-link to="/about">
  About
  </router-link> |
  <router-link to="/contact">
  Contact
  </router-link> </div>
```

### 创建联系页面

我们需要确保当用户输入`/contact` URL 时，联系页面会被渲染。为此，我们需要创建一个单文件组件，用作联系页面。

#### 单文件组件 <script> 部分

在这部分，我们将创建单文件组件的`<script>`部分。按照以下说明正确创建组件：

1.  在`src/views`文件夹中，创建一个名为`contact.vue`的新文件并打开它。

1.  创建组件的默认`export`对象，其中包含 Vue 属性`name`：

```js
<script> export default {
  name: 'ContactPage', }; </script>
```

#### 单文件组件 <template> 部分

在这部分，我们将创建单文件组件的`<template>`部分。按照以下说明正确创建组件：

1.  创建一个`div` HTML 元素，其中`class`属性定义为`"contact"`。

1.  在`<h1>`HTML 元素内部，添加一个显示当前页面的文本内容：

```js
<template>
 <div class="contact">
 <h1>This is a contact page</h1>
 </div> </template>
```

### 创建关于页面

我们需要确保当用户输入`/about` URL 时，关于页面会被渲染。在接下来的小节中，我们将为关于页面创建单文件组件。

#### 单文件组件 <script> 部分

在这部分，我们将创建单文件组件的`<script>`部分。按照以下说明正确创建组件：

1.  在`src/views`文件夹中，创建一个名为`About.vue`的新文件并打开它。

1.  创建组件的默认导出对象，其中包含 Vue 属性`name`：

```js
<script> export default {
  name: 'AboutPage', }; </script>
```

#### 单文件组件 <template> 部分

在这部分，我们将创建单文件组件的`<template>`部分。按照以下说明正确创建组件：

1.  创建一个`div` HTML 元素，其中`class`属性定义为`"about"`。

1.  在其中，放置一个带有显示当前页面文本内容的`<h1>`元素：

```js
<template>
 <div class="about">
 <h1>This is an about page</h1>
 </div> </template>
```

### 更改应用程序的主要组件

创建页面和导航栏后，我们需要更改应用程序的主要组件，以便能够渲染路由并在顶部拥有导航栏。

#### 单文件组件 <script> 部分

在这部分中，我们将创建单文件组件的`<script>`部分。按照以下说明正确创建组件：

1.  在`src`文件夹中打开`App.vue`。

1.  导入`NavigationBar`组件：

```js
import NavigationBar from './components/navigationBar.vue';
```

1.  在 Vue 的`components`属性中，声明导入的`NavigationBar`：

```js
export default {
  components: { NavigationBar }, };
```

#### 单文件组件`<template>`部分

在这部分中，我们将创建单文件组件的`<template>`部分。在`div` HTML 元素内，添加`NavigationBar`组件和`RouterView`组件：

```js
<template>
 <div id="app">
 <navigation-bar />
 <router-view/>
 </div> </template>
```

### 创建路由

现在我们需要在应用程序中使路由可用。为此，首先需要声明路由和路由将呈现的组件。按照以下步骤正确创建 Vue 应用程序路由：

1.  在`src/router`文件夹中，打开`index.js`文件。

1.  导入`Contact`组件页面：

```js
import Vue from 'vue'; import VueRouter from 'vue-router'; import Home from '../views/Home.vue'; import Contact from '../views/contact.vue';
```

1.  在`routes`数组中，我们需要创建一个新的`route`对象。该对象将具有`path`属性定义为`'/contact'`，`name`定义为`'contact'`，并且`component`指向导入的`Contact`组件：

```js
{
  path: '/contact',
  name: 'contact',
  component: Contact, },
```

要运行服务器并查看组件，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> npm run serve
```

这是您的组件呈现并运行的地方：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-cb/img/62dcc997-24fa-40f8-b29c-13cd4caca6cd.png)

## 工作原理...

当将`vue-router`添加到 Vue 作为插件时，它开始监视`window.location.pathname`和其他 URL 属性的更改，以检查当前 URL 在浏览器上的权重与路由配置中的 URL 列表的匹配情况。

在这种情况下，我们使用直接 URL 和非动态 URL。因此，`vue-router`插件只需要检查 URL 路径的直接匹配，而不需要将可能的匹配与正则表达式验证器进行比较。

匹配 URL 后，`router-view`组件充当**动态组件**，并呈现我们在`vue-router`配置中定义的组件。

## 另请参阅

您可以在[`router.vuejs.org/.`](https://router.vuejs.org/)找到有关`vue-router`的更多信息。

您可以在[`cli.vuejs.org/.`](https://cli.vuejs.org/)找到有关 Vue CLI 的更多信息。

# 创建程序化导航

使用`vue-router`时，还可以通过函数执行来更改应用程序的当前路由，而无需特殊的`vue-router`组件来创建链接。

使用程序化导航，您可以确保所有路由重定向可以在代码的任何位置执行。使用此方法可以使用特殊的路由方向，例如传递参数和使用路由名称进行导航。

在这个食谱中，我们将学习如何执行程序化导航函数，以及它提供的额外可能性。

## 准备工作

此食谱的先决条件如下：

+   Node.js 12+

所需的 Node.js 全局对象如下：

+   @vue/cli

+   `@vue/cli-service-global`

## 如何做...

要启动我们的组件，我们可以使用在“*创建简单路由*”中创建的 Vue 项目与 Vue-CLI，或者我们可以开始一个新的项目。

要开始一个新的项目，打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows），并执行以下命令：

```js
> vue create route-project
```

选择手动功能并将`Router`作为所需功能添加，如“*如何做...*”部分和“*创建简单路由*”食谱中所示。

我们的食谱将分为两部分：

+   更改应用程序的主要组件

+   更改联系视图

让我们开始吧。

### 更改应用程序的主要组件

我们将从`App.vue`文件开始。我们将添加一个在超时后执行的程序化导航函数，该函数将添加到组件生命周期钩子中。

#### 单文件组件`<script>`部分

在这部分中，我们将创建单文件组件的`<script>`部分。按照以下说明正确创建组件：

1.  在`src`文件夹中打开`App.vue`。

1.  添加一个`mounted`属性：

```js
mounted() {}
```

1.  在`mounted`属性中，我们需要添加一个`setTimeout`函数，该函数将执行`$router.push`函数。当执行时，此函数将接收一个 JavaScript 对象作为参数，其中包含两个属性，`name`和`params`：

```js
mounted() {
  setTimeout(() => {
  this.$router.push({
  name: 'contact',
  params: {
  name: 'Heitor Ribeiro',
  age: 31,
 }, }); }, 5000); },
```

### 更改联系视图

在联系视图上，我们需要添加一个事件侦听器，该侦听器将抓取路由更改并执行操作。

#### 单文件组件`<script>`部分

在这部分中，我们将创建单文件组件的`<script>`部分。按照以下说明正确创建组件：

1.  在`src/views`文件夹中打开`contact.vue`。

1.  添加一个新的`mounted`属性：

```js
mounted() {}
```

1.  在此属性中，我们将添加一个验证，检查`$route.params`对象上是否有任何参数，并显示具有该`$route.params`的`alert`：

```js
mounted() {
  if (Object.keys(this.$route.params).length) {
  alert(`Hey! I've got some parameter! 
       ${JSON.stringify(this.$route.params)}`);
  } },
```

要运行服务器并查看您的组件，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> npm run serve
```

这是您的组件呈现和运行的方式：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-cb/img/751bd657-b3cf-44c2-9fbc-ad4027477d67.png)

## 它是如何工作的...

当执行`$router.push`函数时，告诉`vue-router`改变应用程序所在的位置，在这个过程中，您将向新的路由器传递一些参数，这些参数将替换当前路由。在这些参数中，有一个名为`params`的属性，它将一组参数发送到新的路由器。

当进入这个新的路由器时，我们将从路由器内部调用的所有参数都将在`$route.params`对象中可用；在那里，我们可以在我们的视图或组件中使用它。

## 还有更多...

在程序化导航中，可以通过`$router.push`函数导航到路由器，并将它们添加到浏览器历史记录中，但也可以使用其他函数。

`$router.replace`函数将替换用户导航历史记录为新的历史记录，使其无法返回到上一页。

`$router.go`用于以步骤方式移动用户导航历史记录。要前进，您需要传递正数，要后退，您需要传递负数。

## 参见

您可以在[`router.vuejs.org/guide/essentials/navigation.html`](https://router.vuejs.org/guide/essentials/navigation.html)找到有关`vue-router`程序化导航的更多信息。

# 创建动态路由器路径

向您的应用程序添加路由是必不可少的，但有时您需要的不仅仅是简单的路由。在这个食谱中，我们将看看动态路由是如何发挥作用的。通过动态路由，您可以定义可以通过 URL 设置的自定义变量，并且您的应用程序可以从这些变量开始定义。

在这个食谱中，我们将学习如何在 CRUD 列表上使用动态路由器路径。

## 准备就绪

这个食谱的先决条件如下：

+   Node.js 12+

所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

## 如何做...

要启动我们的组件，我们将使用在第五章中完成的 Vue 项目和 Vue-CLI，*通过 HTTP 请求从 Web 获取数据*中的'*使用 axios 和 Vuesax 创建 CRUD 界面*'食谱。在接下来的步骤中，我们将通过 Vue UI 仪表板向项目添加`vue-router`：

1.  首先，您需要打开`vue ui`。要做到这一点，打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> vue ui
```

1.  在那里，您需要通过定位项目文件夹来导入项目。导入`vue ui`后，您将被重定向到仪表板。

1.  通过转到插件管理页面并单击“添加 vue-router”按钮，将`vue-router`添加到插件中。然后，单击“继续”按钮。

1.  Vue-CLI 将自动为我们在项目上安装和配置 vue-router。现在我们需要为**列表**，**视图**和**编辑**页面创建每个视图。

要开始视图开发，我们将首先进入用户列表路由。在每个路由中，我们将解构我们之前制作的旧组件，并将其重新创建为视图。

我们的步骤将分为八个部分：

+   更改应用程序的主要组件

+   更改路由 mixin

+   Axios 实例配置

+   用户列表视图

+   用户创建视图

+   用户信息视图

+   用户更新视图

+   创建动态路由

让我们开始吧。

### 更改应用程序的主要组件

添加 vue-router 插件后，`App.vue`将发生变化。我们需要撤销安装`vue-router`所做的更改。这是因为当`vue-ui`添加`vue-router`插件时，它会更改`App.vue`，添加我们不需要的示例代码。

#### 单文件组件<template>部分

在这部分中，我们将创建单文件组件的`<template>`部分。按照以下说明正确创建组件：

1.  在`src`文件夹中打开`App.vue`。

1.  删除所有内容，只留下`div#app` HTML 元素和`router-view`组件：

```js
<template>
 <div id="app">
 <router-view/>
 </div> </template>
```

### 更改路由 mixin

在上一个步骤中，我们使用了一个`changeComponent` mixin。现在我们要使用路由，我们需要将此 mixin 更改为`changeRoute` mixin 并更改其行为。在接下来的步骤中，我们将更改 mixin 的工作方式，以便能够更改路由而不是组件：

1.  在`src/mixin`文件夹中，将`changeComponent.js`重命名为`changeRoute.js`并打开它。

1.  我们将删除`changeComponent`方法并创建一个名为`changeRoute`的新方法。这个新方法将接收两个参数，`name`和`id`。`name`参数是路由名称，在`vue-router`配置中设置，`id`将是我们将在路由更改中传递的用户 id 参数。此方法将执行`$router.push`，将这些参数作为参数传递：

```js
export default {
  methods: {
  async changeRoute(name, id = 0) {
  await this.$router.push({
 name,
  params: {
 id,
  },
  });
  },
  } }
```

### Axios 实例配置

要在 MirageJS 服务器中获取数据，我们需要在 axios 实例中定义一些选项。现在，在以下步骤中，我们将配置 axios 实例以与新的路由系统一起工作：

1.  在`src/http`文件夹中，打开`baseFetch.js`文件。

1.  在`axios`的`localApi`实例的创建者中，我们需要添加一个`options`对象，传递`baseURL`属性。这个`baseURL`将是当前浏览器导航的 URL：

```js
const localApi = createAxios({
  baseURL: `${document.location.protocol}//${document.location.host}`, });
```

### 用户列表视图

为了创建我们的视图，我们将从`list.vue`组件中提取代码，并将其重塑为页面视图。

#### 单文件组件<script>部分

在这部分，我们将创建单文件组件的`<script>`部分。按照以下说明正确创建组件：

1.  将`list.vue`文件从`components`移动到`views`文件夹，并将其重命名为`List.vue`。

1.  删除旧的`changeComponent` mixin 导入，并导入新的`changeRoute` mixin：

```js
import changeRouteMixin from '@/mixin/changeRoute';
```

1.  在 Vue 的`mixins`属性中，我们需要用`changeRoute`替换`changeComponent`：

```js
mixins: [changeRouteMixin],
```

1.  在`getAllUsers`和`deleteUser`方法中，我们需要从`getHttp`和`deleteHttp`函数参数中删除`${window.location.href}`：

```js
methods: {
  async getAllUsers() {
  const { data } = await getHttp(`api/users`);
  this.userList = data;
  },
  async deleteUser(id) {
  await deleteHttp(`api/users/${id}`);
  await this.getAllUsers();
  }, }
```

#### 单文件组件<template>部分

在这部分，我们将创建单文件组件的`<template>`部分。按照以下说明正确创建组件：

1.  我们需要用`VsRow`和`VsCol`组件包装`VsCard`组件及其子内容。`VsCol`组件将`vs-type`属性定义为`'flex'`，`vs-justify`定义为`'left'`，`vs-align`定义为`'left'`，`vs-w`定义为`12`：

```js
<template>
 <vs-row>
 <vs-col
  vs-type="flex"
  vs-justify="left"
  vs-align="left"
  vs-w="12">
 <vs-card... />
    </vs-col>
  </vs-row>
</template>
```

1.  在操作按钮上，我们将把`changeComponent`函数改为`changeRoute`：

```js
<vs-td :data="data[index].id">
 <vs-button
  color="primary"
  type="filled"
  icon="remove_red_eye"
  size="small"
  @click="changeRoute('view', data[index].id)"
  />
 <vs-button
  color="success"
  type="filled"
  icon="edit"
  size="small"
  @click="changeRoute('edit', data[index].id)"
  />
 <vs-button
  color="danger"
  type="filled"
  icon="delete"
  size="small"
  @click="deleteUser(data[index].id)"
  /> </vs-td>
```

1.  在`VsCard`的页脚处，我们需要将操作按钮的`changeComponent`方法改为`changeRoute`方法：

```js
<template slot="footer">
 <vs-row vs-justify="flex-start">
 <vs-button
  color="primary"
  type="filled"
  icon="fiber_new"
  size="small"
  @click="changeRoute('create')"
  >
  Create User
    </vs-button>
 </vs-row> </template>
```

### 用户创建视图

为了创建我们的视图，我们将从`create.vue`组件中提取代码，并将其重塑为页面视图。

#### 单文件组件<script>部分

在这部分，我们将创建单文件组件的`<script>`部分。按照以下说明正确创建组件：

1.  将`create.vue`文件从`components`移动到`views`文件夹，并将其重命名为`Create.vue`。

1.  删除旧的`changeComponent` mixin 导入，并导入新的`changeRoute` mixin：

```js
import changeRouteMixin from '@/mixin/changeRoute';
```

1.  在 Vue 的`mixins`属性中，我们需要用`changeRoute`替换`changeComponent`：

```js
mixins: [changeRouteMixin],
```

1.  在`getUserById`方法中，我们需要从`postHttp`函数的 URL 中移除`${window.location.href}`，并将`changeComponent`函数更改为`changeRoute`：

```js
async createUser() {
  await postHttp(`/api/users`, {
  data: {
  ...this.userData,
  }
 });
  this.changeRoute('list'); },
```

#### 单文件组件<template>部分

在这部分，我们将创建单文件组件的`<template>`部分。按照这些说明正确创建组件：

1.  我们需要用`VsRow`和`VsCol`组件包裹`VsCard`组件及其子内容。`VsCol`组件将定义`vs-type`属性为`'flex'`，`vs-justify`属性为`'left'`，`vs-align`属性为`'left'`，`vs-w`属性为`12`：

```js
<template>
 <vs-row>
 <vs-col
  vs-type="flex"
  vs-justify="left"
  vs-align="left"
  vs-w="12">
 <vs-card... />
    </vs-col>
  </vs-row>
</template>
```

1.  在`VsCard`的页脚上，我们需要将`Cancel`按钮的`changeComponent`函数更改为`changeRoute`：

```js
<vs-button
  color="danger"
  type="filled"
  icon="cancel"
  size="small"
  style="margin-left: 5px"
  @click="changeRoute('list')" >
  Cancel
</vs-button>
```

### 用户信息视图

为了创建我们的视图，我们将从`view.vue`组件中提取代码，并将其重塑为页面视图。

#### 单文件组件<script>部分

在这部分，我们将创建单文件组件的`<script>`部分。按照这些说明正确创建组件：

1.  将`view.vue`文件从`src/components`移动到`src/views`文件夹，并将其重命名为`View.vue`。

1.  移除旧的`changeComponent`混入导入，并导入新的`changeRoute`：

```js
import changeRouteMixin from '@/mixin/changeRoute';
```

1.  在 Vue 的`mixins`属性中，我们需要用`changeRoute`替换`changeComponent`：

```js
mixins: [changeRouteMixin],
```

1.  在`component`对象中创建一个新的`computed`属性，属性为`userId`，它将返回`$route.params.id`：

```js
computed: {
  userId() {
  return this.$route.params.id;
  }, },
```

1.  在`getUserById`方法中，我们需要从`getHttp`函数的 URL 中移除`${window.location.href}`：

```js
methods: {
  async getUserById() {
  const { data } = await getHttp(`api/users/${this.userId}`);
  this.userData = data;
  }, }
```

#### 单文件组件<template>部分

在这部分，我们将创建单文件组件的`<template>`部分。按照这些说明正确创建组件：

1.  我们需要用`VsRow`和`VsCol`组件包裹`VsCard`组件及其子内容。`VsCol`组件将定义`vs-type`属性为`'flex'`，`vs-justify`属性为`'left'`，`vs-align`属性为`'left'`，`vs-w`属性为`12`：

```js
<template>
 <vs-row>
 <vs-col
  vs-type="flex"
  vs-justify="left"
  vs-align="left"
  vs-w="12">
 <vs-card... />
    </vs-col>
  </vs-row>
</template>
```

1.  在`VsCard`的页脚上，我们需要将返回按钮的`changeComponent`函数更改为`changeRoute`：

```js
<vs-button
  color="primary"
  type="filled"
  icon="arrow_back"
  size="small"
  style="margin-left: 5px"
  @click="changeRoute('list')" >
  Back
</vs-button>
```

### 用户更新视图

为了创建我们的视图，我们将从`update.vue`组件中提取代码，并将其重塑为页面视图。

#### 单文件组件<script>部分

在这部分，我们将创建单文件组件的`<script>`部分。按照这些说明正确创建组件：

1.  将`update.vue`文件从`src/components`移动到`src/views`文件夹，并将其重命名为`Edit.vue`。

1.  移除旧的`changeComponent`混入导入，并导入新的`changeRoute`混入：

```js
import changeRouteMixin from '@/mixin/changeRoute';
```

1.  在 Vue 的`mixins`属性中，我们需要用`changeRoute`替换`changeComponent`：

```js
mixins: [changeRouteMixin],
```

1.  在`component`对象中创建一个新的`computed`属性，具有`userId`属性，它将返回`$route.params.id`：

```js
computed: {
  userId() {
  return this.$route.params.id;
  }, },
```

1.  在`getUserById`和`updateUser`方法中，我们需要移除

从`getHttp`和`patchHttp`函数的 URL 中删除`${window.location.href}`，并将`changeComponent`函数改为`changeRoute`：

```js
methods: {
  async getUserById() {
  const { data } = await getHttp(`api/users/${this.userId}`);
  this.userData = data;
  },
  async updateUser() {
  await patchHttp(`api/users/${this.userData.id}`, {
  data: {
  ...this.userData,
  }
 });
  this.changeRoute('list');
  }, },
```

#### 单文件组件的<template>部分

在这部分，我们将创建单文件组件的`<template>`部分。按照以下说明正确创建组件：

1.  我们需要用`VsRow`和`VsCol`组件包裹`VsCard`组件及其子内容。`VsCol`组件将`vs-type`属性定义为`'flex'`，`vs-justify`定义为`'left'`，`vs-align`定义为`'left'`，`vs-w`定义为`12`：

```js
<template>
 <vs-row>
 <vs-col
  vs-type="flex"
  vs-justify="left"
  vs-align="left"
  vs-w="12">
 <vs-card... />
    </vs-col>
  </vs-row>
</template>
```

1.  在`VsCard`的页脚上，我们需要把`Cancel`按钮的`changeComponent`函数改为`changeRoute`：

```js
<vs-button
  color="danger"
  type="filled"
  icon="cancel"
  size="small"
  style="margin-left: 5px"
  @click="changeRoute('list')" >
  Cancel
</vs-button>
```

### 创建动态路由

现在，我们已经创建了页面视图，我们需要创建路由并使其接受参数，将它们转换为动态路由。在接下来的步骤中，我们将创建应用程序的动态路由：

1.  打开`src/router`文件夹中的`index.js`。

1.  首先，我们需要导入四个新页面 - `List`，`View`，`Edit`，`Create`和`Update`：

```js
import List from '@/views/List.vue'; import View from '@/views/View.vue'; import Edit from '@/views/Edit.vue'; import Create from '@/views/Create.vue'; 
```

1.  在`routes`数组上，我们将为每个导入的页面添加一个新的路由对象。在这个对象中，将有三个属性：`name`，`path`和`component`。

1.  对于`list`路由，我们将把`name`定义为`'list'`，`path`定义为`'/'`，并把`component`定义为导入的`List`组件：

```js
{
  path: '/',
  name: 'list',
  component: List, },
```

1.  在`view`路由上，我们将把`name`定义为`'view'`，`path`定义为`'/view/:id'`，并把`component`定义为导入的`View`组件：

```js
{
  path: '/view/:id',
  name: 'view',
  component: View, },
```

1.  在`edit`路由上，我们将把`name`定义为`'edit'`，`path`定义为`'/edit/:id'`，并把`component`定义为导入的`Edit`组件：

```js
{
  path: '/edit/:id',
  name: 'edit',
  component: Edit, },
```

1.  最后，在`create`路由上，我们将把`name`定义为`'create'`，`path`定义为`'/create'`，并把`component`定义为导入的`Create`组件：

```js
{
  path: '/create',
  name: 'create',
  component: Create, },
```

1.  当创建`VueRouter`时，我们将添加`mode`选项属性，并将其设置为`'history'`：

```js
const router = new VueRouter({
  mode: 'history',
  base: process.env.BASE_URL,
  routes });
```

要运行服务器并查看您的组件，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> npm run serve
```

这是您的组件渲染和运行的方式：

+   **列表视图路由 -** `/`将是您的用户列表页面，包含应用程序中所有用户的列表以及查看、编辑和删除用户的按钮，以及创建新用户的按钮：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-cb/img/4ba80475-521f-446f-8c30-8be4c9b739ed.png)

+   **用户视图路由 -** `/view/:id`将是您的用户查看页面，您可以在此页面查看用户信息，例如用户的姓名、电子邮件、国家、生日和电话号码：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-cb/img/10c4f103-0042-4f58-8c55-74f4ac6fbbef.png)

+   **用户编辑路由 -** `/update/:id`将是您的用户编辑页面，您可以在此页面编辑用户信息，更改用户的姓名、电子邮件、国家、生日和电话号码：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-cb/img/9010ffcc-0c76-4b96-be5e-d363d55d90d6.png)

+   **创建用户路由别名 -** `/update/:id`将是您的用户创建页面，您可以在系统上创建新用户：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-cb/img/42da8529-0e65-41c5-a7af-81b391e14ab0.png)

## 它是如何工作的...

当创建`vue-router`并将路由传递进行匹配时，路由分析会根据每个路由的权重定义的正则表达式来寻找最佳匹配路由。

当定义路由并在其路径中有一个变量时，您需要在变量参数之前添加`:`。此参数通过`$route.params`属性传递给组件。

## 另请参阅

您可以在[`router.vuejs.org/guide/essentials/dynamic-matching.html`](https://router.vuejs.org/guide/essentials/dynamic-matching.html)找到有关动态路由匹配的更多信息。

# 创建路由别名

每个应用程序都是一个活生生的有机体-它不断发展、突变和变化。有时，这些进化可以通过路由更改的形式来实现，以获得更好的命名或废弃的服务。在`vue-router`中，可以使所有这些更改对用户不可见，因此当他们使用旧链接时，仍然可以访问应用程序。

在这个教程中，我们将学习如何为我们的应用程序创建路由别名并使用它。

## 准备工作

此教程的先决条件如下：

+   Node.js 12+

所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

## 如何做到这一点...

要启动我们的组件，我们将使用在“创建动态路由路径”配方中完成的 Vue 项目，或者我们可以开始一个新的项目。

要开始一个新的项目，打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> vue create http-project
```

选择手动功能，并按照“如何做…”部分的指示，将`router`添加为必需功能。

现在，在以下步骤中，我们将创建路由别名：

1.  在`src/router`文件夹中打开`index.js`。

1.  在`list`对象中，我们将把`path`属性从`'/'`改为`'/user'`，并为`alias`属性设置为`'/'`：

```js
{
  path: '/user',
  name: 'list',
  alias: '/',
  component: List, },
```

1.  在`view`对象中，我们将把`path`属性从`'/view/:id'`改为`'/user/:id'`，并将`alias`属性设置为`'/view/:id'`：

```js
{
  path: '/user/:id',
  name: 'view',
  alias: '/view/:id',
  component: View, },
```

1.  在`edit`对象中，我们将把`path`属性从`'/edit/:id'`改为`'/user/edit/:id'`，并将`alias`属性设置为`'/edit/:id'`。

```js
{
  path: '/user/edit/:id',
  name: 'edit',
  alias: '/edit/:id',
  component: Edit, },
```

1.  最后，在`create`对象中，我们将把`path`属性从`'/create'`改为`'/user/create'`，并将`alias`属性设置为`'/create'`：

```js
{
  path: '/user/create',
  name: 'create',
  alias: '/create',
  component: Create, },
```

## 工作原理…

当用户进入您的应用程序时，`vue-router`将尝试将路径与用户尝试访问的路径匹配。如果路由对象中有一个名为`alias`的属性，则`vue-router`将使用此属性在幕后维护旧路由，并使用别名路由。如果找到别名，则渲染该别名的组件，并且路由器保持为别名，不向用户显示更改，使其透明。

在我们的场景中，我们对应用程序进行了转换，现在处理所有在`/user`命名空间上调用的用户，但仍保持旧的 URL 结构，以便如果旧访问者尝试访问网站，他们将能够正常使用应用程序。

## 另请参阅

您可以在[`router.vuejs.org/guide/essentials/redirect-and-alias.html#alias`](https://router.vuejs.org/guide/essentials/redirect-and-alias.html#alias)找到有关`vue-router`别名的更多信息。

# 创建路由重定向

路由重定向几乎与路由别名相同，但主要区别在于用户确实被重定向到新的 URL。使用此过程，您可以管理如何加载新路由。

## 准备工作

此配方的先决条件如下：

+   Node.js 12+

所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

## 如何做...

要启动我们的组件，我们将使用在'*创建路由别名*'配方中完成的 Vue-CLI 中的 Vue 项目，或者我们可以启动一个新的项目。

要启动一个新的项目，打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> vue create http-project
```

选择手动功能并将`Router`作为必需的功能添加到'*如何做...*'步骤中的'*创建一个简单路由*'配方中。

现在，在这些步骤中，我们将创建路由重定向规则：

1.  打开`src/router`文件夹中的`index.js`。

1.  在`routes`数组的末尾插入一个新的路由对象。这个对象将有两个属性，`path`和`redirect`。在`path`属性中，我们需要定义用户将输入的路径，`'/create-new-user'`，在`redirect`中，用户将被重定向到的路径，在这种情况下是`'/user/create'`。

```js
{
  path: '/create-new-user',
  redirect: '/user/create', },
```

1.  创建一个新对象，这个对象将有两个属性，`path`和`redirect`。在`path`属性中，我们需要定义用户将输入的路径，`'/users'`，在`redirect`中，我们将创建一个具有名为`name`的属性的对象，并将值设置为`'list'`。

```js
{
  path: '/users',
  redirect: {
  name: 'list',
  }, },
```

1.  创建一个新对象。这个对象将有两个属性，`path`和`redirect`。在`path`属性中，我们需要定义用户将输入的路径，`'/my-user/:id?'`，在`redirect`中，我们将创建一个函数，该函数将接收一个参数`to`，这是当前路由的对象。我们需要检查路由中是否存在用户 ID，以便将用户重定向到编辑页面。否则，我们将把他们重定向到用户列表。

```js
{
  path: '/my-user/:id?',
  redirect(to) {
  if (to.params.id) {
  return '/user/:id';
  }
  return '/user';
  }, },
```

1.  最后，在最后，我们将创建一个具有两个属性，`path`和`redirect`的路由对象。在`path`属性中，我们需要定义用户将输入的路径，`'/*'`，在`redirect`中，我们需要将`redirect`属性定义为`'/'`。

```js
{
  path: '*',
  redirect: '/', },
```

请记住，具有`'*'`的最后一个路由将始终是在用户尝试输入的 URL 中没有匹配时呈现的路由。

## 它是如何工作的...

当我们将`redirect`定义为一个新的路由时，它的工作方式类似于别名，但是`redirect`属性可以接收三种类型的参数：一个字符串，当重定向到路由本身时，对象，当使用其他参数重定向时，例如路由的名称，最后但并非最不重要的是函数类型，`redirect`可以处理并返回前两个对象中的一个，以便用户可以被重定向。

## 另请参阅

您可以在[`router.vuejs.org/guide/essentials/redirect-and-alias.html#redirect`](https://router.vuejs.org/guide/essentials/redirect-and-alias.html#redirect)找到有关`vue-router`重定向的更多信息。

# 创建嵌套路由视图

在`vue-router`中，嵌套路由就像是路由的命名空间，您可以在同一个路由内拥有多个级别的路由，使用基本视图作为主视图，并在其中呈现嵌套路由。

在多模块应用程序中，这用于处理像 CRUD 这样的路由，其中您将拥有一个基本路由，而子路由将是 CRUD 视图。

在这个配方中，您将学习如何创建嵌套路由。

## 准备工作

此配方的先决条件如下：

+   Node.js 12+

所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

## 如何操作...

要启动我们的组件，我们将使用在“创建动态路由路径”配方中使用的 Vue 项目与 Vue-CLI，或者我们可以开始一个新的项目。

要开始一个新的，打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> vue create http-project
```

选择手动功能，并在“*如何操作...*”部分中将`Router`添加为必需功能，如“创建简单路由”配方中所示。

我们的配方将分为两部分：

+   在布局上创建`router-view`

+   更改路由文件

让我们开始吧。

### 在布局上创建`router-view`

在使用带有子路由的`vue-router`时，我们需要创建主视图，它将具有一个名为`RouterView`的特殊组件。此组件将在您呈现的布局或页面内呈现当前路由。

现在，在接下来的步骤中，我们将为页面创建布局：

1.  在`src/views`文件夹中，我们需要创建一个名为`user`的新文件夹，并将`Create`、`Edit`、`List`、和`View`页面移动到这个新文件夹中。

1.  在`user`文件夹中创建一个名为`Index.vue`的新文件并打开它。

1.  在单文件组件`<template>`部分中，添加一个`router-view`组件：

```js
<template>
  <router-view/>
</template>
<script>
  export default {
    name: 'User',
  }
</script>
```

### 更改路由文件

我们将创建一个新文件来管理用户的特定路由，这将帮助我们维护代码并使其更清晰。

#### 用户路由

在接下来的步骤中，我们将为用户创建路由：

1.  在`src/router`文件夹中创建一个名为`user.js`的新文件。

1.  导入`Index`、`List`、`View`、`Edit`和`Create`视图：

```js
import Index from '@/views/user/Index.vue'; import List from '@/views/user/List.vue'; import View from '@/views/user/View.vue'; import Edit from '@/views/user/Edit.vue'; import Create from '@/views/user/Create.vue';
```

1.  创建一个数组，并将其设置为文件的默认导出。在这个数组中，添加一个`route`对象，具有四个属性-`path`，`name`，`component`和`children`。将`path`属性设置为`'/user'`，将`name`属性定义为`'user'`，将`component`定义为导入的`Index`组件，最后，将`children`属性定义为空数组：

```js
export default [
 {  path: '/user',
  name: 'user',
  component: Index,
  children: [],
  }, ] 
```

1.  在`children`属性中，添加一个新的路由对象，具有三个属性-`path`，`name`和`component`。将`path`定义为`''`，`name`定义为`'list'`，最后，将`component`属性定义为导入的`List`组件：

```js
{
  path: '',
  name: 'list',
  component: List, },
```

1.  为视图路由创建一个路由对象，并使用与上一个`route`对象相同的结构。将`path`属性定义为`':id'`，将`name`定义为`'view'`，将`component`定义为导入的`View`组件：

```js
{
  path: ':id',
  name: 'view',
  component: View, },
```

1.  为`edit`路由创建一个路由对象，并使用与上一个`route`对象相同的结构。将`path`属性定义为`'edit/:id'`，将`name`定义为`'edit'`，将`component`定义为导入的`Edit`组件：

```js
{
  path: 'edit/:id',
  name: 'edit',
  component: Edit, },
```

1.  为`create`路由创建一个路由对象，使用与上一个`route`对象相同的结构。将`path`属性定义为`'create'`，将`name`定义为`'create'`，将`component`定义为导入的`Create`组件：

```js
{
  path: 'create',
  name: 'create',
  component: Create, },
```

#### 路由管理器

在以下步骤中，我们将创建路由管理器，该管理器将控制应用程序中的所有路由：

1.  在`src/router`文件夹中打开`index.js`。

1.  在`src/router`文件夹中导入新创建的`user.js`文件：

```js
import Vue from 'vue'; import VueRouter from 'vue-router'; import UserRoutes from './user';
```

1.  在`routes`数组中，将导入的`UserRoutes`作为解构数组添加：

```js
const routes = [
  ...UserRoutes,
  {
  path: '*',
  redirect: '/user',
  }, ];
```

## 工作原理...

`vue-router`提供了使用子路由作为当前视图或布局的内部组件的能力。这使得可以创建具有特殊布局文件的初始路由，并通过`RouterView`组件在此布局中呈现子组件。

这种技术通常用于在应用程序中定义布局并为模块设置命名空间，其中父路由可以具有一组特定顺序，这些顺序将对其每个子路由都可用。

## 另请参阅

您可以在[`router.vuejs.org/guide/essentials/nested-routes.html#nested-routes`](https://router.vuejs.org/guide/essentials/nested-routes.html#nested-routes)找到有关嵌套路由的更多信息。

# 创建 404 错误页面

有时您的用户可能会尝试输入旧链接或输入拼写错误，无法到达正确的路由，这应该直接导致找不到错误。

在这个配方中，您将学习如何在`vue-router`中处理 404 错误。

## 准备工作

此配方的先决条件如下：

+   Node.js 12+

所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

## 如何做...

要开始我们的组件，我们将使用在“*创建嵌套路由视图*”配方中使用的 Vue 项目与 Vue-CLI，或者我们可以开始一个新的。

要开始一个新的，打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows），并执行以下命令：

```js
> vue create http-project
```

选择手动功能并将`Router`添加为所需功能，如“*如何做...*”部分在“*创建简单路由*”配方中所示。

我们的配方将分为两部分：

+   创建`NotFound`视图

+   更改路由文件

让我们开始吧。

### 创建 NotFound 视图

我们需要创建一个新的视图，当应用程序上没有匹配的路由时，将显示给用户。这个页面将是一个简单的通用页面。

#### 单文件组件<template>部分

在这部分中，我们将创建单文件组件的`<template>`部分。按照这些说明正确创建组件：

1.  在`src/views`文件夹中，创建一个名为`NotFound.vue`的新文件并打开它。

1.  创建一个`VsRow`组件，在其中创建四个`VsCol`组件。所有这些组件都将具有属性`vs-w`定义为`12`和`class`定义为`text-center`：

```js
<vs-row>
 <vs-col vs-w="12" class="text-center">
 <!-- Icon --> </vs-col>
 <vs-col vs-w="12" class="text-center">
 <!-- Title --> </vs-col>
 <vs-col vs-w="12" class="text-center">
 <!-- Text --> </vs-col>
 <vs-col vs-w="12" class="text-center">
 <!-- Button --> </vs-col> </vs-row>
```

1.  在第一个`VsCol`组件中，我们将添加一个`VsIcon`组件，并将属性 icon 定义为`sentiment_dissatisfied`，并将`size`定义为`large`：

```js
<vs-icon
  icon="sentiment_dissatisfied"
  size="large" />
```

1.  在第二个`VsCol`组件中，我们将为页面添加一个标题：

```js
<h1>Oops!</h1>
```

1.  在第三个`VsCol`组件中，我们需要创建将放置在页面上的文本：

```js
<h3>The page you are looking for are not here anymore...</h3>
```

1.  最后，在第四个`VsCol`组件上，我们将添加`VsButton`组件。此按钮将具有属性`type`定义为`relief`和`to`定义为`'/'`：

```js
<vs-button
  type="relief"
  to="/" >
  Back to Home...
</vs-button>
```

#### 单文件组件<style>部分

在这部分中，我们将创建单文件组件的`<style>`部分。按照这些说明正确创建组件：

1.  在`<style>`标签中添加`scoped`标签：

```js
<style scoped> </style>
```

1.  创建一个名为`.text-center`的新规则，其中`text-align`属性定义为`center`，`margin-bottom`定义为`20px;`：

```js
.text-center {
  text-align: center;
  margin-bottom: 20px; }  
```

### 更改路由文件

创建视图后，我们需要将其添加到路由并使其对用户可用。为此，我们需要将视图路由添加到路由管理器中。

在这些步骤中，我们将更改路由管理器，以添加新的错误页面：

1.  在`src/router`文件夹中打开`index.js`。

1.  导入`NotFound`组件：

```js
import Vue from 'vue'; import VueRouter from 'vue-router'; import UserRoutes from './user'; import NotFound from '@/views/NotFound';
```

1.  在`routes`数组中，在`UserRoutes`之后，添加一个新的`route`对象，具有两个属性，`path`和`redirect`。将`path`属性定义为`'/'`，将`redirect`属性定义为`'/user'`：

```js
{
  path: '/',
  redirect: '/user' },
```

1.  对于未找到的页面，我们需要创建一个新的路由对象，该对象需要放在`routes`数组的最后位置。这个路由对象将有两个属性，`path`和`component`。`path`属性将被定义为`'*'`，`component`将被定义为导入的`NotFound`视图：

```js
{
  path: '*',
  component: NotFound, },  
```

要运行服务器并查看您的组件，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> npm run serve
```

这是您的组件呈现并运行的方式：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-cb/img/1a7706e3-1b9c-4486-8750-851e47e3f35f.png)

## 它是如何工作的...

`vue-router`尝试找到用户想要访问的 URL 的最佳匹配；如果没有匹配项，`vue-router`将使用`'*'`路径作为这些情况的默认值，其中`*`表示用户输入的不在路由列表中的任何值。

因为在`vue-router`中匹配的过程是由路由的权重决定的，所以我们需要将错误页面放在最底部，这样`vue-router`在实际调用`NotFound`路由之前需要通过每个可能的路由。

## 另请参阅

您可以在[`router.vuejs.org/guide/essentials/history-mode.html#caveat`](https://router.vuejs.org/guide/essentials/history-mode.html#caveat)找到有关处理 vue-router 历史模式中的 404 错误的更多信息。

# 创建和应用身份验证中间件

在`vue-router`中，可以创建路由守卫-每次路由更改时运行的函数。这些守卫被用作路由管理过程中的中间件。通常将它们用作身份验证中间件或会话验证器。

在这个示例中，我们将学习如何创建身份验证中间件，向我们的路由添加元数据以使它们受限制，并创建登录页面。

## 准备工作

这个示例的先决条件如下：

+   Node.js 12+

所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

## 如何做到...

要启动我们的组件，我们将使用在“创建 404 错误页面”配方中使用的 Vue-CLI 的 Vue 项目，或者我们可以启动一个新的项目。

要启动一个新的项目，打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> vue create http-project
```

选择手动特性，并在“*如何做...*”部分中添加`Router`作为必需特性，如“创建简单路由”配方中所示。

我们的配方将分为三个部分：

+   创建身份验证中间件

+   向路由添加元数据和中间件

+   将中间件附加到 vue-router 并创建登录页面

让我们开始。

### 创建登录视图

登录视图将是用户在未经过身份验证时看到的页面。我们将构建一个简单的页面，里面有两个输入框 - 一个卡片和一个按钮。

#### 单文件组件<script>部分

在这部分，我们将创建单文件组件的`<script>`部分。按照这些说明正确创建组件：

1.  在`src/views`文件夹中，创建一个名为`Login.vue`的新文件并打开它。

1.  创建一个包含`username`、`password`和`error`的`data`属性：

```js
data: () => ({
  username: '',
  password: '',
  error: false, }),
```

1.  然后创建一个名为`userSignIn`的方法的`methods`属性。此方法将验证`username`和`password`数据是否完整。如果是，它将在`sessionStorage`中创建一个名为`'auth'`的新密钥，其中包含`username`数据的加密字符串化 JSON。然后，将`error`设置为`false`并执行`$router.replace`将用户重定向到用户列表`'/user'`。如果任何字段未通过任何验证，该方法将将错误定义为`true`并返回`false`：

```js
methods: {
  userSignIn() {
  if (this.username && this.password) {
  window.sessionStorage.setItem('auth',
  window.btoa(JSON.stringify({
  username: this.username
          })
 ) );
  this.error = false;
  this.$router.replace('/user');
  }
  this.error = true;
  return false;
  }, }
```

#### 单文件组件<template>部分

在这部分，我们将创建单文件组件的`<template>`部分。按照这些说明正确创建组件：

1.  创建一个带有`VsRow`组件的`div.container`HTML 元素。`VsRow`组件将具有属性`vs-align`定义为`"center"`和`vs-justify`定义为`"center"`：

```js
<div class="container">
 <vs-row
  vs-align="center"
  vs-justify="center"
  >
  </vs-row>
</div>
```

1.  在`VsRow`组件内部，添加一个带有属性`vs-lg`定义为`4`，`vs-sm`定义为`6`和`vs-xs`定义为`10`的`VsCol`组件。然后，在`VsCol`组件内部，我们将创建一个带有`style`属性定义为`margin: 20px;`的`VsCard`组件：

```js
<vs-col
  vs-lg="4"
  vs-sm="6"
  vs-xs="10" >
 <vs-card
  style="margin: 20px;"
  >
  </vs-card>
</vs-col>
```

1.  在`VsCard`组件内部，创建一个带有名称为`header`的`slot`的动态`<template>`，一个`h3`HTML 元素和您的标题：

```js
<template slot="header">
 <h3>
  User Login
  </h3> </template>
```

1.  之后，创建一个`VsRow`组件，其中属性`vs-align`定义为`"center"`，`vs-justify`定义为`"center"`，并在其中放置两个`VsCol`组件，其中属性`vs-w`定义为`12`：

```js
<vs-row
  vs-align="center"
  vs-justify="center" >
 <vs-col vs-w="12">
  </vs-col>
 <vs-col vs-w="12">
  </vs-col>
</vs-row>
```

1.  在第一个`VsCol`组件上，我们将添加一个`VsInput`组件，其中属性`danger`定义为数据`error`的值，`danger-text`定义为错误时显示的文本，`label`定义为`"Username"`，`placeholder`定义为`"Username or e-mail"`，并且`v-model`指令绑定到`username`：

```js
<vs-input
  :danger="error"
  danger-text="Check your username or email"
  label="Username"
  placeholder="Username or e-mail"
  v-model="username" />
```

1.  在第二个`VsCol`组件中，我们将添加一个`VsInput`组件，其中属性`danger`定义为数据`error`的值，`danger-text`定义为错误时显示的文本，`label`定义为`"Password"`，`type`定义为`password`，`placeholder`定义为`"Your password"`，并且`v-model`指令绑定到`password`：

```js
<vs-input
  :danger="error"
  label="Password"
  type="password"
  danger-text="Check your password"
  placeholder="Your password"
  v-model="password" />
```

1.  最后，在卡片页脚中，我们需要创建一个动态的`<template>`，其中包含名为`footer`的插槽。在这个`<template>`中，我们将添加一个`VsRow`组件，其中`vs-justify`属性定义为`flex-start`，并插入一个`VsButton`，其中属性`color`定义为`success`，`type`定义为`filled`，`icon`定义为`account_circle`，`size`定义为`small`，并且`@click`事件监听器指向`userSignIn`方法：

```js
<template slot="footer">
 <vs-row vs-justify="flex-start">
 <vs-button
  color="success"
  type="filled"
  icon="account_circle"
  size="small"
  @click="userSignIn"
  >
  Sign-in
    </vs-button>
 </vs-row> </template>
```

#### 单文件组件<style>部分

在这部分，我们将创建单文件组件的`<style>`部分。按照以下说明正确创建组件：

1.  首先，我们需要使这个部分具有作用域，这样 CSS 规则就不会影响应用程序的任何其他组件：

```js
<style scoped></style>
```

1.  然后，我们需要为`container`类和`VsInput`组件添加规则：

```js
<style scoped>
  .container {
  height: 100vh;
  display: flex;
  flex-wrap: wrap;
  justify-content: center;
  align-content: center;
  }    .vs-input {
  margin: 5px;
  } </style>
```

要运行服务器并查看您的组件，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> npm run serve
```

这是您的组件呈现并运行的方式：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-cb/img/5b60b886-7306-4fd7-86ba-ea430ce27ea8.png)

### 创建中间件

所有`vue-router`中间件也可以称为导航守卫，并且它们可以附加到应用程序路由更改上。这些更改有一些钩子，您可以将其应用于您的中间件。身份验证中间件在路由更改之前发生，因此我们可以处理一切并将用户发送到正确的路由。

1.  在`src/router`文件夹中，创建一个名为`middleware`的新文件夹，然后创建并打开一个名为`authentication.js`的新文件。

1.  在这个文件中，我们将创建一个默认的`export`函数，它将有三个函数参数 - `to`，`from`和`next`。`to`和`from`参数是对象，`next`参数是一个回调函数：

```js
export default (to, from, next) => {  }; 
```

1.  我们需要检查我们被重定向到的路由是否具有设置为`true`的经过身份验证的`meta`属性，并且我们是否有一个具有`'auth'`键的`sessionStorage`项。如果通过了这些验证，我们可以执行`next`回调：

```js
if (to.meta.authenticated && sessionStorage.getItem('auth')) {
  return next(); }
```

1.  然后，如果第一个验证没有通过，我们需要检查我们将用户重定向到的路由是否具有经过身份验证的`meta`属性，并检查它是否为`false`值。如果验证通过，我们将执行`next`回调：

```js
if (!to.meta.authenticated) {
  return next(); }
```

1.  最后，如果我们的任何验证都没有通过，执行`next`回调，传递`'/login'`作为参数：

```js
next('/login');
```

### 将元数据和中间件添加到路由器

创建完我们的中间件后，我们需要定义哪些路由将被验证，哪些路由不会被验证。然后我们需要将中间件导入到路由器中，并在执行时定义它：

1.  在`src/router`文件夹中打开`user.js`。

1.  在每个`route`对象中，添加一个名为`meta`的新属性。这个属性将是一个对象，具有一个经过身份验证的`key`和一个值定义为`true`。我们需要对每个路由都这样做 - 即使是子路由：

```js
import Index from '@/views/user/Index.vue';  import List from '@/views/user/List.vue'; import View from '@/views/user/View.vue'; import Edit from '@/views/user/Edit.vue'; import Create from '@/views/user/Create.vue';   export default [
 {  path: '/user',
  name: 'user',
  component: Index,
  meta: {
  authenticated: true,
  },
  children: [
 {  path: '',
  name: 'list',
  component: List,
  meta: {
  authenticated: true,
  },
  },
  {
  path: ':id',
  name: 'view',
  component: View,
  meta: {
  authenticated: true,
  },
  },
  {
  path: 'edit/:id',
  name: 'edit',
  component: Edit,
  meta: {
  authenticated: true,
  },
  },
  {
  path: 'create',
  name: 'create',
  component: Create,
  meta: {
  authenticated: true,
  },
  },
  ],
  }, ]
```

1.  在`src/router`文件夹中打开`index.js`。

1.  导入新创建的中间件和`Login`视图组件：

```js
import Vue from 'vue'; import VueRouter from 'vue-router'; import UserRoutes from './user'; import NotFound from '@/views/NotFound'; import Login from '@/views/Login'; import AuthenticationMiddleware from './middleware/authentication';
```

1.  为登录页面视图创建一个新的`route`对象。这个路由对象将`path`设置为`'/login'`，`name`定义为`'login'`，`component`定义为`Login`，并且`meta`属性将具有`authenticated`键，其值设置为`false`：

```js
{
  path: '/login',
  name: 'login',
  component: Login,
  meta: {
  authenticated: false,
  }, },
```

1.  在错误处理路由上，我们将定义`meta`属性`authenticated`为`false`，因为登录视图是一个公共路由：

```js
{
  path: '*',
  component: NotFound,
  meta: {
  authenticated: false,
  }, },
```

1.  最后，在创建了`router`构造函数之后，我们需要在`beforeEach`执行中注入中间件：

```js
router.beforeEach(AuthenticationMiddleware);
```

## 它是如何工作的...

路由守卫作为中间件工作；它们在`vue-router`进程的每个生命周期中都有一个钩子被执行。对于这个示例，我们选择了`beforeEach`钩子来添加我们的中间件。

在这个钩子中，我们检查用户是否经过了身份验证，以及用户是否需要身份验证才能导航到该路由。在检查了这些变量之后，我们通过将用户发送到他们需要的路由来继续这个过程。

## 另请参阅

您可以在[`router.vuejs.org/guide/advanced/navigation-guards.html#global-before-guards`](https://router.vuejs.org/guide/advanced/navigation-guards.html#global-before-guards)找到有关 vue-router 路由守卫的更多信息。

# 异步加载您的页面

组件可以在需要时加载，路由也可以。使用`vue-router`的惰性加载技术可以在应用程序中进行更多的代码拆分和更小的最终捆绑包。

在这个配方中，我们将学习如何转换路由以异步加载它们。

## 准备工作

此配方的先决条件如下：

+   Node.js 12+

所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

## 如何做...

要启动我们的组件，我们将使用在“*创建身份验证中间件*”配方中使用的 Vue 项目与 Vue-CLI，或者我们可以启动一个新的项目。

要启动新的路由管理器，请打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows），并执行以下命令：

```js
> vue create http-project
```

选择手动功能，并将`Router`添加为所需的功能，如“*如何做...*”部分和“*创建简单路由*”配方中所示。

我们的配方将分为两部分：

+   更新路由管理器

+   更新用户路由

让我们开始吧。

### 更新路由管理器

要更新路由管理器，请按照以下说明进行操作：

1.  在`src/router`文件夹中打开`index.js`文件。

1.  在每个具有`component`属性的路由中，我们将把组件的直接赋值转换为一个新函数。这将是一个返回 webpack 的`import()`方法的箭头函数：

```js
{
  path: '/login',
  name: 'login',
  component: () => import('@/views/Login'),
  meta: {
  authenticated: false,
 }, },
```

1.  在每个具有`component`属性的`route`对象上重复此过程。

### 更新用户路由

要更新用户路由，请按照以下说明进行操作：

1.  在`src/router`文件夹中打开`user.js`文件。

1.  在每个具有`component`属性的路由中，我们将把组件的直接赋值转换为一个新函数。这将是一个返回 webpack 的`import()`方法的箭头函数。

```js
{
  path: '/user',
  name: 'user',
  component: () => import('@/views/user/Index.vue'),
  meta: {
  authenticated: true,
  },
  children: [], },
```

1.  在每个具有`component`属性的`route`对象上重复此过程。

## 它是如何工作的...

在 ECMAScript 中，当我们使用`export default`方法时，`export`和`import`是具有预定义值的对象。这意味着当我们`import`一个新组件时，该组件已经指向该文件的`default export`。

为了进行延迟加载过程，我们需要传递一个在运行时执行的函数，该函数的返回值将是 webpack 在捆绑过程中分割的代码的一部分。

当我们在`vue-router`中调用这个函数时，`vue-router`不直接导入组件，而是进行验证检查，确保当前组件导入是一个需要执行的函数。在函数执行后，响应被用作将显示在用户屏幕上的组件。

由于 webpack 的`import()`方法是异步的，这个过程可以与其他代码执行同时进行，而不会干扰或阻塞 JavaScript 虚拟机的主线程。

## 另请参阅

您可以在[`router.vuejs.org/guide/advanced/lazy-loading.html`](https://router.vuejs.org/guide/advanced/lazy-loading.html)找到有关`vue-router`延迟加载的更多信息。

您可以在[`webpack.js.org/guides/code-splitting/`](https://webpack.js.org/guides/code-splitting/)找到有关`webpack`代码拆分的更多信息。

您可以在[`github.com/tc39/proposal-dynamic-import`](https://github.com/tc39/proposal-dynamic-import)找到有关 ECMAScript 动态导入提案的更多信息。


# 第七章：使用 Vuex 管理应用程序状态

在兄弟组件之间传输数据可能非常容易，但想象一下让一系列组件对任何数据变化做出反应。你需要在事件总线中触发一个事件，或者通过所有父组件发送事件，直到它到达事件链的顶部，然后再一路发送到所需的组件；这个过程可能非常繁琐和痛苦。如果你正在开发一个大型应用程序，这个过程是不可持续的。

Flux 库是为了帮助这个过程而开发的，其想法是将反应性带出组件边界，因为 Vuex 能够维护数据的唯一真相来源，并且同时也是你制定业务规则的地方。

在这一章中，我们将学习如何使用 Vuex，开发我们的存储，将其应用到我们的组件，并对其进行命名空间，以便我们可以在同一个存储中拥有不同的 Vuex 模块。

在这一章中，我们将涵盖以下的配方：

+   创建一个简单的 Vuex 存储

+   创建和理解 Vuex 状态

+   创建和理解 Vuex 变化

+   创建和理解 Vuex 操作

+   创建和理解 Vuex 获取器

+   使用 Vuex 创建一个动态组件

+   为开发添加热模块重新加载

+   创建一个 Vuex 模块

# 技术要求

在这一章中，我们将使用**Node.js**和**Vue-CLI**。

注意，Windows 用户，你需要安装一个名为`windows-build-tools`的 NPM 包，以便安装以下所需的包。要做到这一点，以管理员身份打开 PowerShell 并执行以下命令：

`> npm install -g windows-build-tools`

要安装 Vue-CLI，你需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> npm install -g @vue/cli @vue/cli-service-global
```

# 创建一个简单的 Vuex 存储

在应用程序中创建一个唯一的真相来源可以让你简化数据流，使数据的反应性流向另一个视角，你不再受限于父子关系。数据现在可以存储在一个地方，每个人都可以获取或请求数据。

在这个配方中，我们将学习如何安装 Vuex 库并创建我们的第一个单一存储，以及如何使用反应式操作和数据获取器来操作它。

## 准备工作

这个配方的先决条件如下：

+   Node.js 12+

所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

## 如何做...

要创建一个 Vue-CLI 项目，请按照以下步骤进行：

1.  我们需要在终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）中执行以下命令：

```js
> vue create initial-vuex
```

1.  CLI 会询问一些问题，这些问题将有助于创建项目。您可以使用箭头键进行导航，使用*Enter*键继续，使用*Spacebar*选择选项。

1.  有两种方法可以启动新项目。默认方法是基本的`babel`和`eslint`项目，没有任何插件或配置，还有`手动`模式，您可以选择更多模式、插件、代码检查工具和选项。我们将选择`手动`：

```js
? Please pick a preset: (Use arrow keys)
 default (babel, eslint)
❯ Manually select features
```

1.  现在我们被问及项目中需要的功能。这些功能包括一些 Vue 插件，如 Vuex 或 Router（`Vue-Router`），测试工具，代码检查工具等。选择`Babel`，`Router`，`Vuex`和`Linter / Formatter`：

```js
?  Check the features needed for your project: (Use arrow keys) ❯ Babel
 TypeScript Progressive Web App (PWA) Support ❯ Router ❯ Vuex
  CSS Pre-processors ❯ Linter / Formatter
 Unit Testing E2E Testing
```

1.  继续此过程，选择一个代码检查工具和格式化工具。在我们的情况下，我们将选择`ESLint + Airbnb`配置：

```js
?  Pick a linter / formatter config: (Use arrow keys) ESLint with error prevention only ❯ **ESLint + Airbnb config** ESLint + Standard config 
  ESLint + Prettier
```

1.  设置了代码检查规则后，我们需要定义它们何时应用于您的代码。它们可以在“保存时”应用，也可以在“提交时”修复：

```js
?  Pick additional lint features: (Use arrow keys)  Lint on save ❯ Lint and fix on commit
```

1.  在定义了所有这些插件、代码检查工具和处理器之后，我们需要选择设置和配置的存储位置。最好的存储位置是专用文件，但也可以将它们存储在`package.json`文件中：

```js
?  Where do you prefer placing config for Babel, ESLint, etc.?  (Use 
  arrow keys) ❯ **In dedicated config files****In package.json** 
```

1.  现在您可以选择是否将此选择作为将来项目的预设，这样您就不需要再次重新选择所有内容：

```js
?  Save this as a preset for future projects?  (y/N) n
```

我们的步骤将分为两部分：

+   创建 store

+   使用 Vuex 创建响应式组件

让我们开始吧。

### 创建 store

现在您已经有了包含 Vuex 库的项目，我们需要创建我们的第一个 store。在接下来的步骤中，我们将创建 Vuex store：

1.  打开`src/store`文件夹中的`index.js`。

1.  在`state`属性中，添加一个名为`counter`的新键，并将值设置为`0`：

```js
state: {
  counter: 0,
},
```

1.  在`mutations`属性中，添加两个新函数，`increment`和`decrement`。这两个函数都将有一个`state`参数，这是当前的 Vuex`state`对象。`increment`函数将`counter`增加`1`，而`decrement`函数将`counter`减少`1`：

```js
mutations: {
  increment: (state) => {
    state.counter += 1;
  },
  decrement: (state) => {
    state.counter -= 1;
  },
},
```

1.  最后，在`actions`属性中，添加两个新函数，`increment`和`decrement`。这两个函数都将有一个解构参数`commit`，它是调用 Vuex mutation 的函数。在每个函数中，我们将执行`commit`函数，将当前函数的名称作为字符串参数传递：

```js
actions: {
 increment({ commit }) {
 commit('increment');
 },
 decrement({ commit }) {
 commit('decrement');
 },
},  
```

### 使用 Vuex 创建响应式组件

现在您已经定义了您的 Vuex 存储，您需要与之交互。我们将创建一个响应式组件，它将在屏幕上显示当前状态的`counter`，并显示两个按钮，一个用于增加`counter`，另一个用于减少`counter`。

#### 单文件组件<script>部分

在这里，我们将编写单文件组件的`<script>`部分：

1.  从`src`文件夹中打开`App.vue`文件。

1.  在文件中创建`<script>`部分，使用`export default`对象：

```js
<script>
  export default {}; </script>
```

1.  在新创建的对象中，添加 Vue `computed`属性，属性名为`counter`。在这个属性中，我们需要返回当前的`$store.state.counter`：

```js
computed: {
  counter() {
  return this.$store.state.counter;
  }, },
```

1.  最后，在 Vue `methods`属性中创建两个函数，`increment`和`decrement`。这两个函数都将执行一个带有函数名称作为字符串参数的`$store.dispatch`：

```js
methods: {
  increment() {
  this.$store.dispatch('increment');
  },
  decrement() {
  this.$store.dispatch('decrement');
  }, },
```

#### 单文件组件<template>部分

让我们编写单文件组件的`<template>`部分：

1.  在`src`文件夹中打开`App.vue`文件。

1.  在`<template>`部分中，删除`div#app`内的所有内容。

1.  创建一个包含计数器变量的`h1`HTML 元素。

1.  创建一个带有`@click`指令的事件监听器的按钮，调用`increment`函数，并将`+`作为标签：

```js
<button @click="increment">+</button>
```

1.  创建一个带有`@click`指令的事件监听器的按钮，调用`decrement`函数，并将`-`作为标签：

```js
<button @click="decrement">-</button>
```

要运行服务器并查看您的组件，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> npm run serve
```

这是您的组件呈现并运行的方式：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-cb/img/0846f103-aada-46b7-a0a2-92e7481f19b5.png)

## 它是如何工作的...

当您声明 Vuex 存储时，您需要创建三个主要属性，`state`，`mutations`和`actions`。这些属性作为一个单一的结构，通过注入的`$store`原型或导出的`store`变量绑定到 Vue 应用程序。

`state`是一个集中的对象，保存您的信息并使其可供`mutation`、`actions`或组件使用。改变`state`始终需要通过`mutation`执行的同步函数。

`mutation`是一个同步函数，可以改变`state`并且是可追踪的，因此在开发时，可以通过 Vuex 存储中执行的所有`mutations`进行时间旅行。

`action`是一个异步函数，可用于保存业务逻辑、API 调用、分派其他`actions`和执行`mutations`。这些函数是 Vuex 存储中任何更改的常见入口点。

Vuex 存储的简单表示可以在此图表中看到：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-cb/img/20737403-4144-48e7-9ee0-6b70a4df9851.png)

## 另请参阅

您可以在[`vuex.vuejs.org/`](https://vuex.vuejs.org/)找到有关 Vuex 的更多信息。

# 创建和理解 Vuex 状态

Vuex 状态似乎很容易理解。但是，随着数据变得更加深入和嵌套，其复杂性和可维护性可能变得更加复杂。

在本配方中，我们将学习如何创建一个 Vuex 状态，该状态可以在**渐进式 Web 应用程序（PWA）**/**单页面应用程序（SPA）**和**服务器端渲染（SSR）**的情景中使用，而无需任何问题。

## 准备就绪

本配方的先决条件如下：

+   Node.js 12+

所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

## 如何做...

要开始我们的组件，我们将使用在第六章中使用的 Vue-CLI 的 Vue 项目，或者我们可以开始一个新的项目。

要启动一个新项目，打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows），并执行以下命令：

```js
> vue create vuex-store
```

选择手动功能，根据'*如何做...*'部分的指示，将`Router`和`Vuex`添加为必需功能。

我们的配方将分为两部分：

+   通过`vue ui`添加 Vuex

+   创建`Vuex`状态

让我们开始吧。

### 通过 vue ui 添加 Vuex

当导入通过 Vue-CLI 创建的旧项目时，可以通过`vue ui`界面自动添加 Vuex，而无需任何努力。我们将学习如何向旧项目添加 Vuex 库，以便继续开发该项目。

在接下来的步骤中，我们将使用`vue ui`界面添加 Vuex。

1.  在项目文件夹中，通过在终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）上执行以下命令来打开`vue ui`：

```js
> vue ui
```

1.  选择你正在工作的正确项目。在右侧边栏中，点击插件菜单图标：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-cb/img/9795f7d3-5585-42ff-b0d1-8d4ea162b369.png)

1.  在插件页面的顶部工具栏上，点击“添加 vuex”按钮。这将触发一个弹出模态窗口，然后点击“继续”按钮完成在应用程序上安装 Vuex：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-cb/img/1494d414-1e39-402d-b8aa-1de4b5fca347.png)

1.  将 Vuex 添加到我们的应用程序将改变应用程序的结构。首先，我们会注意到`src`文件夹中有一个名为`store`的新文件夹，在`main.js`文件中，它被添加到了导入和在 Vue 应用程序中注入`store`：

```js
import './server/server'; import Vue from 'vue'; import App from './App.vue'; import Vuesax from 'vuesax'; import './style.css'; import router from './router' import store from './store'   Vue.use(Vuesax);   Vue.config.productionTip = false;   new Vue({
  router,
  store,
  render: h => h(App) }).$mount('#app');
```

### 创建 Vuex 状态

为了将数据保存在 Vuex 中，您需要有一个初始状态，在用户进入您的应用程序时加载并定义为默认状态。在这里，我们将学习如何创建 Vuex 状态并将其用作单例，以便 Vuex 可以在 SPA 和 SSR 页面中使用：

现在我们将创建一个可以在 SSR 和 SPA 中使用的 Vuex 存储：

1.  在`src/store`文件夹中，创建一个名为`user`的新文件夹，在这个文件夹里创建一个名为`state.js`的新文件。

1.  创建一个新的`generateState`函数。这个函数将返回一个 JavaScript 对象，有三个主要属性，`data`，`loading`和`error`。`data`属性将是一个 JavaScript 对象，其中有一个名为`usersList`的属性，默认为空数组，以及一个名为`userData`的属性，其中包含用户的默认对象。`loading`属性将默认设置为布尔值`false`，`error`将有一个默认值初始化为`null`：

```js
const generateState = () => ({
  data: {
  usersList: [],
  userData: {
  name: '',
  email: '',
  birthday: '',
  country: '',
  phone: '',
  },
  },
  loading: false,
  error: null, });
```

1.  创建函数后，我们将在文件末尾创建一个`export default`对象，它将是一个 JavaScript 对象，并且我们将解构`generateState`函数的返回值：

```js
export default { ...generateState() };
```

1.  在`user`文件夹中创建一个名为`index.js`的新文件并打开它。

1.  导入新创建的`state`：

```js
import state from './state';
```

1.  在文件末尾，创建一个`export default`文件作为 JavaScript 对象。在这个对象中，我们将添加导入的`state`：

```js
export default {
  state, };  
```

1.  打开`src/store`文件夹中的`index.js`文件。

1.  从`user`文件夹中导入`index.js`文件：

```js
import Vue from 'vue'; import Vuex from 'vuex'; import UserStore from './user';
```

1.  在创建一个新的 Vuex store 的`export default`函数中，我们将删除其中的所有属性，并将导入的`UserStore`解构对象放入`Vuex.Store`参数中：

```js
export default new Vuex.Store({
  ...UserStore, })
```

## 工作原理...

当使用`vue ui`将 Vuex 作为插件添加时，`vue ui`将自动添加所需的文件，并导入所有需要的内容。这是创建 Vuex `store`的初始阶段。

首先是创建一个专门管理`state`的文件，我们可以使用它来分离`store`中状态的开始过程以及如何初始化状态。

在这种情况下，我们使用一个函数来生成每次调用时都会生成一个全新的`state`。这是一个很好的做法，因为在 SSR 环境中，服务器的`state`始终是相同的，我们需要为每个新连接创建一个新的`state`。

在创建`state`之后，我们需要创建一个默认文件来导出将在`user`文件夹中创建的 Vuex 文件。这个文件是对将在文件夹中创建的所有文件（`state`，`actions`，`mutation`和`getters`）的简单导入。导入后，我们导出一个带有所需的 Vuex 属性名称的对象，`state`，`actions`，`mutations`和`getters`。

最后，在 Vuex 的`store`中，我们导入了一个文件，将所有内容聚合并解构到我们的 store 中进行初始化。

## 还有更多...

`Vuex` state 是应用程序中的唯一数据源，它就像一个全局数据管理器，不应直接更改。这是因为我们需要防止数据的同时变异。为了避免这种情况，我们总是需要通过 mutations 来改变我们的 state，因为这些函数是同步的，并由 Vuex 控制。

## 另请参阅

在[`vuex.vuejs.org/guide/state.html`](https://vuex.vuejs.org/guide/state.html)找到有关 Vuex state 的更多信息。

# 创建和理解 Vuex mutations

当 Vuex 发生变化时，我们需要一种以异步形式执行这种变化并跟踪它的方式，以便在第一个变化完成之前不会执行另一个变化。

在这种情况下，我们需要 mutations，这些是仅负责改变应用程序状态的函数。

在这个示例中，我们将学习如何创建 Vuex mutations 以及最佳实践。

## 准备工作

此示例的先决条件如下：

+   Node.js 12+

所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

## 如何做...

要开始我们的组件，我们将使用在'*创建和理解 Vuex 状态*'食谱中使用的 Vue 项目与 Vue-CLI，或者我们可以开始一个新的。

要开始一个新的，打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows），并执行以下命令：

```js
> vue create vuex-store
```

选择手动功能，根据'*如何做...*'部分的指示，添加`Router`和`Vuex`作为必需功能。

现在我们创建一个 Vuex mutation 和基本类型的 mutation：

1.  在`src/store`文件夹内的`user`文件夹中创建一个名为`types.js`的新文件，并打开它。

1.  在这个文件中，我们将创建一个`export default`的 JavaScript 对象，其中包含一组键，这些键将是我们 mutations 的名称。这些键将是`LOADING`、`ERROR`、`SET_USER_LIST`、`SET_USER_DATA`、`UPDATE_USER`和`REMOVE_USER`：

```js
export default {
  LOADING: 'LOADING',
  ERROR: 'ERROR',
  SET_USER_LIST: 'SET_USER_LIST',
  SET_USER_DATA: 'SET_USER_DATA',
  UPDATE_USER: 'UPDATE_USER',
  REMOVE_USER: 'REMOVE_USER', }
```

1.  在`user`文件夹中创建一个名为`mutations.js`的新文件，并打开它。

1.  导入新创建的`types.js`文件：

```js
import MT from './types';
```

1.  创建一个名为`setLoading`的新函数，它将接收 Vuex `state`作为参数，并在执行时将状态的 loading 属性定义为`true`。

```js
const setLoading = state => {
  state.loading = true; };
```

1.  创建一个名为`setError`的新函数，它将接收 Vuex `state`和`payload`作为参数。这个函数将把`state`的`loading`属性设置为`false`，将`error`属性设置为接收到的`payload`参数：

```js
const setError = (state, payload) => {
  state.loading = false;
  state.error = payload; };
```

1.  创建一个名为`setUserList`的新函数，它将接收 Vuex `state`和`payload`作为参数。这个函数将把`state.data`的`usersList`属性定义为接收到的`payload`参数，将`state`的`loading`属性设置为`false`，将`error`属性设置为`null`：

```js
const setUserList = (state, payload) => {
  state.data.usersList = payload;
  state.loading = false;
  state.error = null; };
```

1.  创建一个名为`setUserData`的新函数，它将接收 Vuex `state`和`payload`作为参数。这个函数将把`state.data`的`userData`属性定义为接收到的`payload`参数，将`state`的`loading`属性设置为`false`，将`error`属性设置为`null`：

```js
const setUserData = (state, payload) => {
  state.data.userData = payload;
  state.loading = false;
  state.error = null; };
```

1.  创建一个名为`updateUser`的新函数，它将接收 Vuex `state`和`payload`作为参数。这个函数将更新`state.data`的`usersList`属性中的用户数据，将`state`的`loading`属性定义为`false`，将`error`属性定义为`null`：

```js
const updateUser = (state, payload) => {
  const userIndex = state.data.usersList.findIndex(u => u.id === 
     payload.id);
  if (userIndex > -1) {
 state.data.usersList[userIndex] = payload;
  }
 state.loading = false;
  state.error = null; };
```

1.  创建一个名为`removeUser`的新函数，它将接收 Vuex `state`和`payload`作为参数。这个函数将从`state.data`的`usersList`属性中删除用户数据，将`state`的`loading`属性定义为`false`，将`error`属性定义为`null`：

```js
const removeUser = (state, payload) => {
  const userIndex = state.data.usersList.findIndex(u => u.id === 
     payload);
  if (userIndex > -1) {
 state.data.usersList.splice(userIndex, 1);
  }
 state.loading = false;
  state.error = null; };
```

1.  最后，创建一个`export default`对象，其中键是我们在`types.js`文件中创建的类型，并将每个键定义为我们创建的函数：

```js
export default {
 [MT.LOADING]: setLoading,
 [MT.ERROR]: setError,
 [MT.SET_USER_LIST]: setUserList,
 [MT.SET_USER_DATA]: setUserData,
 [MT.UPDATE_USER]: updateUser,
 [MT.REMOVE_USER]: removeUser, }
```

1.  打开`user`文件夹中的`index.js`文件。

1.  导入新创建的`mutations.js`文件，并将其添加到`export default` JavaScript 对象中：

```js
import state from './state';
import mutations from './mutations';

export default {
  state,
  mutations,
};
```

## 它是如何工作的...

每个`mutation`都是一个将作为`commit`调用的函数，并且在 Vuex 存储中具有*标识符*。这个标识符是导出的 JavaScript 对象中的`mutation`键。在这个示例中，我们创建了一个文件，将所有标识符作为对象值保存，以便在我们的代码中作为常量使用。

这种模式有助于我们开发需要知道每个`mutation`名称的 Vuex `actions`。

在导出`mutation` JavaScript 对象时，我们使用常量作为键，相应的函数作为其值，这样 Vuex 存储在调用时可以执行正确的函数。

## 另请参阅

在[`vuex.vuejs.org/guide/mutations.html`](https://vuex.vuejs.org/guide/mutations.html)找到有关 Vuex mutations 的更多信息。

# 创建和理解 Vuex getters

从`Vuex`中访问数据可以通过状态本身完成，这可能非常危险，或者通过 getters 完成。Getters 就像是可以预处理并传递数据而不触及或干扰 Vuex 存储状态的数据。

Getter 背后的整个理念是可以编写自定义函数，可以在需要时从状态中提取数据的单一位置，以便获得所需的数据。

在这个示例中，我们将学习如何创建一个 Vuex getter 和一个可以作为高阶函数使用的动态 getter。

## 准备工作

此示例的先决条件如下：

+   Node.js 12+

所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

## 如何做...

要启动我们的组件，我们将使用在“创建和理解 Vuex mutations”示例中使用的 Vue 项目与 Vue-CLI，或者我们可以启动一个新的项目。

要启动一个新的项目，打开 Terminal（macOS 或 Linux）或 Command Prompt/PowerShell（Windows）并执行以下命令：

```js
> vue create vuex-store
```

选择手动功能，并根据“如何做...”部分中的指示添加 Router 和`Vuex`作为需要的功能。

在接下来的步骤中，我们将创建 Vuex 的 getter：

1.  在`src/store/user`文件夹中创建一个名为`getters.js`的新文件。

1.  创建一个名为`getUsersList`的新函数，并返回`state.data.usersList`属性：

```js
function getUsersList(state) {
  return state.data.usersList;
}
```

在`getter`函数中，函数将始终接收到的第一个参数是 Vuex `store`的当前`state`。

1.  创建一个名为`getUserData`的新函数，并返回`state.data.userData`属性：

```js
function getUserData(state) {
  return state.data.userData; }
```

1.  创建一个名为`getUserById`的新函数，并返回另一个函数，该函数接收`userId`作为参数。这个返回函数将返回与接收到的`userId`相匹配的`state.data.usersList`的搜索结果：

```js
function getUserById(state) {
  return (userId) => {
 return state.data.usersList.find(u => u.id === userId);
  } }
```

1.  创建一个名为`isLoading`的新函数，并返回`state.loading`属性：

```js
function isLoading(state) {
  return state.loading;
}
```

1.  创建一个名为`hasError`的新函数，并返回`state.error`属性：

```js
function hasError(state) {
  return state.error;
}
```

1.  最后，创建一个带有所有创建的函数作为属性的`export default` JavaScript 对象：

```js
export default {
  getUsersList,
  getUserData,
  getUserById,
  isLoading,
  hasError, };  
```

1.  在`src/store/user`文件夹中打开`index.js`文件。

1.  导入新创建的`getters.js`文件，并将其添加到默认导出的 JavaScript 对象中：

```js
import state from './state';
import mutations from './mutations';
import getters from './getters';

export default {
  state,
  mutations,
  getters,
};
```

## 它是如何工作的...

Getter 就像是从对象中获取的 GET 函数，是静态缓存函数-只有在`state`发生变化时才会改变返回值。但是，如果将返回值作为高阶函数添加，就可以赋予它更多的功能，使用更复杂的算法并提供特定的数据。

在这个示例中，我们创建了两种类型的 getter：最基本的，返回简单数据，以及高阶函数，需要作为函数调用以检索所需的值。

## 还有更多...

使用带有业务逻辑的 getter 是收集更多状态数据的好方法。这是一个很好的模式，因为在较大的项目中，它可以帮助其他开发人员更好地理解每个 GET 函数中发生了什么以及它在幕后是如何工作的。

您始终需要记住，getter 是同步函数，并对状态变化具有反应性，因此 getter 上的数据是被记忆和缓存的，直到单一的真相源接收到提交并更改它。

## 参见

您可以在[`vuex.vuejs.org/guide/getters.html`](https://vuex.vuejs.org/guide/getters.html)找到有关 Vuex getters 的更多信息。

# 创建和理解 Vuex actions

你已经准备好了所有的状态，你的数据集，现在你需要从外部来源获取新数据或者在你的应用程序中改变这些数据。这就是操作发挥作用的地方。

操作负责在应用程序和外部世界之间的通信中编排过程。控制数据何时需要在状态上进行变异并返回给操作的调用者。

通常，操作是通过组件或视图进行调度，但有时操作可以调度另一个操作，以在应用程序中创建一系列操作。

在这个配方中，我们将学习如何在我们的应用程序中创建所需的操作，以定义用户列表，更新用户和删除用户。

## 准备工作

这个配方的先决条件如下：

+   Node.js 12+

所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

## 如何做...

要启动我们的组件，我们将使用在“*创建和理解 Vuex getters*”配方中使用的 Vue 项目，或者我们可以启动一个新的项目。

要启动一个新的项目，打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> vue create vuex-store
```

选择手动功能，并根据“*如何做...*”部分和“*创建一个简单的 Vuex 存储*”配方中指示的要求，添加`Router`和`Vuex`作为必需的功能。

现在按照以下步骤创建 Vuex 操作：

1.  在`src/store/user`文件夹中创建一个名为`actions.js`的新文件。

1.  从`fetchApi`包装器中导入变异类型文件（`types.js`）和`getHttp`，`patchHttp`，`postHttp`和`deleteHttp`函数：

```js
import {
  getHttp,
  patchHttp,
  deleteHttp,
  postHttp,
} from '@/http/fetchApi';
import MT from './types';
```

1.  创建一个名为`createUser`的新的`异步`函数，它接收解构的 JavaScript 对象作为第一个参数，其中包含`commit`属性，并将`userData`作为第二个参数，用于创建用户。添加一个`try/catch`语句，在`try`上下文中。首先，我们执行`commit(MT.LOADING)`，然后我们从 API 中获取用户列表，最后，执行`commit(MT.SET_USER_DATA, data)`，将用户列表传递给被突变。如果我们收到异常并进入`Catch`语句，我们将执行`commit(MT.ERROR, error)`，将收到的错误传递给`state`：

```js
async function createUser({ commit }, userData) {
  try {
 commit(MT.LOADING);
  await postHttp(`/api/users`, {
  data: {
  ...userData,
  }
 });
  commit(MT.SET_USER_DATA, userData);
  } catch (error) {
 commit(MT.ERROR, error);
  } }
```

1.  创建一个名为`fetchUsersList`的新的`异步`函数，它接收一个解构的 JavaScript 对象作为第一个参数，其中包含`commit`属性。在`try`上下文中添加一个`try/catch`语句。我们执行`commit(MT.LOADING)`，然后从 API 中获取用户列表，最后执行`commit(MT.SET_USER_LIST, data)`，将用户列表传递给 mutation。如果我们收到异常并进入`catch`语句，我们将执行一个`commit(MT.ERROR, error)`的 mutation，将收到的错误传递给`state`。

```js
async function fetchUsersList({ commit }) {
  try {
  commit(MT.LOADING);
    const { data } = await getHttp(`api/users`);
    commit(MT.SET_USER_LIST, data);
  } catch (error) {
  commit(MT.ERROR, error);
  } }
```

1.  创建一个名为`fetchUsersData`的新的`异步`函数，它接收一个解构的 JavaScript 对象作为第一个参数，其中包含`commit`属性，以及作为第二个参数的将要获取的`userId`。在`try`上下文中添加一个`try/catch`语句。我们执行`commit(MT.LOADING)`，然后从 API 中获取用户列表，最后执行`commit(MT.SET_USER_DATA, data)`，将用户列表传递给 mutation。如果我们收到异常并进入`catch`语句，我们将执行一个`commit(MT.ERROR, error)`的 mutation，将收到的错误传递给`state`。

```js
async function fetchUserData({ commit }, userId) {
  try {
 commit(MT.LOADING);
  const { data } = await getHttp(`api/users/${userId}`);
  commit(MT.SET_USER_DATA, data);
  } catch (error) {
 commit(MT.ERROR, error);
  } }
```

1.  创建一个名为`updateUser`的新的`异步`函数，它接收一个解构的 JavaScript 对象作为第一个参数，其中包含`commit`属性，以及作为第二个参数的`payload`。在`try`上下文中添加一个`try/catch`语句。我们执行`commit(MT.LOADING)`，然后将用户数据提交到 API，最后执行`commit(MT.UPDATE_USER, payload)`，将新的用户数据传递给 mutation。如果我们收到异常并进入`catch`语句，我们将执行一个`commit(MT.ERROR, error)`的 mutation，将收到的错误传递给`state`。

```js
async function updateUser({ commit }, payload) {
  try {
  commit(MT.LOADING);
    await patchHttp(`api/users/${payload.id}`, {
  data: {
  ...payload,
      }
 });
    commit(MT.UPDATE_USER, payload);
  } catch (error) {
  commit(MT.ERROR, error);
  } }
```

1.  创建一个名为`removeUser`的新的`异步`函数，它接收一个解构的 JavaScript 对象作为第一个参数，其中包含`commit`属性，以及作为第二个参数的`userId`。在`try`上下文中添加一个`try/catch`语句。我们执行`commit(MT.LOADING)`，然后从 API 中删除用户数据，最后执行`commit(MT.REMOVE_USER, userId)`，将`userId`传递给 mutation。如果我们收到异常并进入`catch`语句，我们将执行一个`commit(MT.ERROR, error)`的 mutation，将收到的错误传递给`state`。

```js
async function removeUser({ commit }, userId) {
  try {
  commit(MT.LOADING);
    await deleteHttp(`api/users/${userId}`);
    commit(MT.REMOVE_USER, userId);
  } catch (error) {
  commit(MT.ERROR, error);
  } } 
```

1.  最后，我们将创建一个默认导出的 JavaScript 对象，其中包含所有创建的函数作为属性：

```js
export default {
  createUser,
  fetchUsersList,
  fetchUserData,
  updateUser,
  removeUser, }   
```

1.  在`src/store/user`文件夹的`index.js`中导入新创建的`actions.js`文件，并将其添加到`export default` JavaScript 对象中：

```js
import state from './state';
import mutations from './mutations';
import getters from './getters';
import actions from './actions';

export default {
  state,
  mutations,
  getters,
  actions,
};
```

## 它是如何工作的...

操作是所有 Vuex 生命周期更改的初始化程序。当分发时，操作可以执行一个 mutation commit，或者另一个操作 dispatch，甚至是对服务器的 API 调用。

在我们的情况下，我们将我们的 API 调用放在了 actions 中，因此当异步函数返回时，我们可以执行 commit 并将状态设置为函数的结果。

## 另请参阅

在[`vuex.vuejs.org/guide/actions.html`](https://vuex.vuejs.org/guide/actions.html)找到有关 Vuex 操作的更多信息。

# 使用 Vuex 创建动态组件

将 Vuex 与 Vue 组件结合使用，可以在多个组件之间实现响应性，而无需直接进行父子通信，并分担组件的责任。

使用这种方法允许开发人员增强应用程序的规模，无需将数据状态存储在组件本身，而是使用单一真相作为整个应用程序的存储。

在这个配方中，我们将使用最后的配方来改进一个应用程序，其中使用了父子通信，并将其作为整个应用程序中可用的单一真相。

## 准备就绪

这个配方的先决条件如下：

+   Node.js 12+

所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

## 如何做...

要创建我们的动态组件，我们将把组件从有状态转换为无状态，并提取一些可以制作成新组件的部分。

我们将使用在“*创建和理解 Vuex 操作*”配方中使用的 Vue 项目与 Vue-CLI，或者我们可以开始一个新的项目。

要开始一个新的，打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows），并执行以下命令：

```js
> vue create vuex-store
```

选择手动功能，并根据“*如何做...*”部分中“创建简单的 Vuex 存储”配方中的指示添加`Router`和`Vuex`作为所需功能。

我们的配方将分为五个部分：

+   创建用户列表组件

+   编辑用户列表页面

+   编辑用户视图页面

+   编辑用户视图页面

+   编辑用户创建页面

让我们开始吧。

### 创建用户列表组件

因为 Vuex 给了我们在应用程序中拥有单一数据源的能力，我们可以为我们的应用程序创建一个新的组件，该组件将处理用户列表并触发从服务器获取用户列表的 Vuex 操作。这个组件可以是无状态的，并且可以自行执行`Vuex`操作。

#### 单文件组件`<script>`部分

让我们编写单文件组件的`<script>`部分：

1.  在`src/components`文件夹中创建一个名为`userList.vue`的新文件。

1.  从`src/mixin`文件夹导入`changeRouterMixin`：

```js
import changeRouteMixin from '@/mixin/changeRoute'; 
```

1.  创建一个`export default`的 JavaScript 对象，并添加一个名为`mixin`的新 Vue 属性，其默认值为一个数组。将导入的`changeRouteMixin`添加到这个数组中：

```js
mixins: [changeRouteMixin],
```

1.  创建一个名为`computed`的新 Vue 属性。在这个属性中，创建一个名为`userList`的新值。这个属性将是一个返回 Vuex 存储器 getter`getUsersList`的函数：

```js
computed: {
  userList() {
  return this.$store.getters.getUsersList;
  }, },  
```

#### 单文件组件`<template>`部分

在这里，我们将编写单文件组件的`<template>`部分：

1.  打开`views`文件夹内`users`文件夹中的`List.vue`文件，并复制`VsTable`组件的内容和组件。

1.  打开`src/components`文件夹中的`userList.vue`文件。

1.  将你从`List.vue`文件中复制的内容粘贴到`<template>`部分中：

```js
<template>
 <vs-table
  :data="userList"
  search
 stripe pagination max-items="10"
  style="width: 100%; padding: 20px;"
  >
 <template slot="thead">
 <vs-th sort-key="name">
  #
      </vs-th>
 <vs-th sort-key="name">
  Name
      </vs-th>
 <vs-th sort-key="email">
  Email
      </vs-th>
 <vs-th sort-key="country">
  Country
      </vs-th>
 <vs-th sort-key="phone">
  Phone
      </vs-th>
 <vs-th sort-key="Birthday">
  Birthday
      </vs-th>
 <vs-th>
  Actions
      </vs-th>
 </template>
 <template slot-scope="{data}">
 <vs-tr :key="index" v-for="(tr, index) in data">
 <vs-td :data="data[index].id">
  {{data[index].id}}
        </vs-td>
 <vs-td :data="data[index].name">
  {{data[index].name}}
        </vs-td>
 <vs-td :data="data[index].email">
 <a :href="`mailto:${data[index].email}`">
  {{data[index].email}}
          </a>
 </vs-td>
 <vs-td :data="data[index].country">
  {{data[index].country}}
        </vs-td>
 <vs-td :data="data[index].phone">
  {{data[index].phone}}
        </vs-td>
 <vs-td :data="data[index].birthday">
  {{data[index].birthday}}
        </vs-td>
 <vs-td :data="data[index].id">
 <vs-button
  color="primary"
  type="filled"
  icon="remove_red_eye"
  size="small"
  @click="changeRoute('view', data[index].id)"
  />
 <vs-button
  color="success"
  type="filled"
  icon="edit"
  size="small"
  @click="changeRoute('edit', data[index].id)"
  />
 <vs-button
  color="danger"
  type="filled"
  icon="delete"
  size="small"
  @click="deleteUser(data[index].id)"
  />
 </vs-td>
 </vs-tr>
 </template>
 </vs-table> </template>  
```

### 编辑用户列表页面

现在我们已经将用户列表提取到一个新的组件中，我们需要导入这个组件并移除旧的 VsTable，它使我们的视图混乱。

#### 单文件组件`<script>`部分

在这一步中，我们将编写单文件组件的`<script>`部分：

1.  打开`views`文件夹内`users`文件夹中的`List.vue`文件。

1.  从`components`文件夹导入新创建的用户列表组件：

```js
import changeRouteMixin from '@/mixin/changeRoute'; import UserTableList from '@/components/userList';
```

1.  在`export default`的 JavaScript 对象中，添加一个名为`components`的新属性。将该属性声明为 JavaScript 对象，并将导入的`UserTableList`组件添加到对象中：

```js
components: { UserTableList },
```

1.  在`methods`属性中，在`getAllUsers`函数中，我们需要更改内容以在调用时执行一个 Vuex 分发。这个方法将执行`fetchUsersList`的 Vuex 操作：

```js
async getAllUsers() {
  this.$store.dispatch('fetchUsersList'); },
```

1.  最后，在`deleteUser`函数中，我们需要更改内容以在调用时执行一个 Vuex 分发。这个方法将执行`removeUser`的 Vuex 操作，并将`userId`作为参数传递：

```js
async deleteUser(id) {
  this.$store.dispatch('removeUser', id);
  await this.getAllUsers(); },
```

#### 单文件组件`<template>`部分

让我们编写单文件组件的`<template>`部分：

1.  在`view`文件夹内的`users`文件夹中打开`List.vue`文件。

1.  用新导入的`UserTableList`替换`VsTable`组件及其内容：

```js
<vs-col
  vs-type="flex"
  vs-justify="left"
  vs-align="left"
  vs-w="12">
 <user-table-list /> </vs-col>  
```

### 编辑用户视图页面

现在我们可以将 Vuex 添加到用户视图页面。我们将添加 Vuex 操作和获取器来操作数据，并从页面中提取管理责任。

#### 单文件组件的`<script>`部分

现在你要创建单文件组件的`<script>`部分：

1.  从`view`文件夹内的`users`文件夹中打开`View.vue`文件。

1.  删除 Vue 的`data`属性。

1.  在 Vue 的`computed`属性中，添加`userData`，返回一个 Vuex 的 getter，`getUserData`：

```js
userData() {
  return this.$store.getters.getUserData; },
```

1.  最后，在`getUserById`方法中，将内容更改为调度一个 Vuex 操作`fetchUserData`，传递计算的`userId`属性作为参数：

```js
async getUserById() {
  await this.$store.dispatch('fetchUserData', this.userId); },
```

#### 单文件组件的`<template>`部分

是时候编写单文件组件的`<template>`部分了：

1.  在`view`文件夹内的`users`文件夹中打开`View.vue`文件。

1.  在 UserForm 组件中，将`v-model`指令更改为`:value`指令：

```js
<user-form
  :value="userData"
  disabled />
```

当使用只读值，或者需要删除`v-model`指令的语法糖时，可以将输入值声明为`:value`指令，并将值更改事件声明为`@input`事件监听器。

### 编辑用户编辑页面

我们需要编辑我们的用户。在上一个示例中，我们使用了一个有状态的页面，并在页面内执行了所有操作。我们将状态转换为临时状态，并在 Vuex 操作上执行 API 调用。

#### 单文件组件的`<script>`部分

在这里，我们将创建单文件组件的`<script>`部分：

1.  在`view`文件夹内的`users`文件夹中打开`Edit.vue`文件。

1.  在 Vue 的`data`属性中，将数据的名称从`userData`更改为`tmpUserData`：

```js
data: () => ({
  tmpUserData: {
  name: '',
  email: '',
  birthday: '',
  country: '',
  phone: '',
  }, }),
```

1.  在 Vue 的`computed`属性中，添加一个名为`userData`的新属性，它将返回 Vuex 的 getter`getUserData`：

```js
userData() {
  return this.$store.getters.getUserData; }
```

1.  添加一个名为`watch`的新 Vue 属性，并添加一个名为`userData`的新属性，它将是一个 JavaScript 对象。在这个对象中，添加三个属性，`handler`，`immediate`和`deep`。`handler`属性将是一个接收名为`newData`的参数的函数，它将`tmpUserData`设置为这个参数。`immediate`和`deep`属性都是设置为`true`的布尔属性：

```js
watch: {
  userData: {
  handler(newData) {
  this.tmpUserData = newData;
  },
  immediate: true,
  deep: true,
  } },
```

1.  在 Vue 的`methods`属性中，我们需要更改`getUserById`的内容以调度名为`fetchUserData`的 Vuex 动作，并将`computed`属性`userId`作为参数传递：

```js
async getUserById() {
  await this.$store.dispatch('fetchUserData', this.userId); },
```

1.  在`updateUser`方法中，更改内容以调度名为`updateUser`的 Vuex 动作，并将`tmpUserData`作为参数传递：

```js
async updateUser() {
  await this.$store.dispatch('updateUser', this.tmpUserData);
  this.changeRoute('list'); },
```

#### 单文件组件<template>部分

在这部分，我们将编写单文件组件的`<template>`部分：

1.  在`view`文件夹内的`users`文件夹中打开`Edit.vue`。

1.  将`UserForm`组件的`v-model`指令的目标更改为`tmpUserData`：

```js
<vs-col
  vs-type="flex"
  vs-justify="left"
  vs-align="left"
  vs-w="12"
  style="margin: 20px" >
 <user-form
  v-model="tmpUserData"
  /> </vs-col>
```

### 编辑用户创建页面

对于用户创建页面，更改将是最小的，因为它只执行 API 调用。我们需要添加 Vuex 动作调度。

#### 单文件组件<script>部分

在这里，我们将创建单文件组件的`<script>`部分：

1.  在`view`文件夹内的`users`文件夹中打开`Create.vue`文件。

1.  更改`createUser`方法的内容以调度名为`createUser`的 Vuex 动作，并将`userData`作为参数传递：

```js
async createUser() {
  await this.$store.dispatch('createUser', this.userData);
  this.changeRoute('list'); },  
```

## 它是如何工作的...

在所有四个页面中，我们进行了更改，将业务逻辑或 API 调用从页面中移除到 Vuex 存储，并尝试使其对于数据的维护责任更少。

因此，我们可以将一段代码放入一个新组件中，该组件可以放置在应用程序的任何位置，并且将显示当前用户列表，而不受实例化它的容器的任何限制。

这种模式有助于我们开发更突出的应用程序，其中需要的组件不那么业务导向，而更专注于它们的任务。

## 另请参阅

您可以在[`vuex.vuejs.org/guide/structure.html`](https://vuex.vuejs.org/guide/structure.html)找到有关 Vuex 应用程序结构的更多信息。

# 为开发添加热模块重载

**热模块重载**（**HMR**）是一种用于加快应用程序开发的技术，您无需刷新整个页面即可获取您刚刚在编辑器上更改的新代码。HMR 将仅更改和刷新您在编辑器上更新的部分。

在所有 Vue-CLI 项目或基于 Vue 的框架（如 Quasar Framework）中，HMR 存在于应用程序的呈现中。因此，每当您更改任何文件，该文件是 Vue 组件并且正在呈现时，应用程序将在运行时将旧代码替换为新代码。

在这个教程中，我们将学习如何向 Vuex 存储添加 HMR，并能够在不需要刷新整个应用程序的情况下更改 Vuex 存储。

## 准备工作

此教程的先决条件如下：

+   Node.js 12+

所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

## 如何做...

要启动我们的组件，我们将使用在“*使用 Vuex 创建动态组件*”中使用的 Vue 项目和 Vue-CLI，或者我们可以启动一个新的项目。

要启动一个新的项目，请打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> vue create vuex-store
```

选择手动功能，将`Router`和`Vuex`添加为所需功能，如“*如何做...*”部分和“*创建简单的 Vuex 存储*”教程中所示。

在接下来的步骤中，我们将向 Vuex 添加 HMR：

1.  打开`src/store`文件夹中的`index.js`文件。

1.  将`export default`转换为一个名为`store`的常量，并使其可导出：

```js
export const store = new Vuex.Store({
  ...UserStore, });
```

1.  检查 webpack `hot-module-reload`插件是否处于活动状态：

```js
if (module.hot) {}
```

1.  创建一个名为`hmr`的新常量，其中包含`user`文件夹中`index.js`，`getters.js`，`actions.js`和`mutations.js`文件的路径：

```js
const hmr = [
  './user',
  './user/getters',
  './user/actions',
  './user/mutations', ];
```

1.  创建一个名为`reloadCallback`的新函数。在这个函数中，创建三个常量`getters`，`actions`和`mutations`。每个常量将指向`user`文件夹中的等效文件，并调用`store.hotUpdate`函数，将一个对象作为参数传递，其中包含您创建的常量的值：

```js
const reloadCallback = () => {
  const getters = require('./user/getters').default;
  const actions = require('./user/actions').default;
  const mutations =  require('./user/mutations').default;    store.hotUpdate({
  getters,
  actions,
  mutations,
  }) };
```

由于文件的 Babel 输出，您需要在使用 webpack `require`函数动态导入的文件末尾添加`.default`。

1.  执行 webpack HMR 的`accept`函数，将`hmr`常量作为第一个参数传递，将`reloadCallback`作为第二个参数传递：

```js
module.hot.accept(hmr, reloadCallback);
```

1.  最后，默认导出创建的`store`：

```js
export default store;  
```

## 它是如何工作的...

Vuex 存储支持使用 webpack HMR 插件的 API 进行 HMR。

当它可用时，我们创建一个可能需要更新的文件列表，以便 webpack 可以意识到这些文件的任何更新。当这些文件中的任何一个被更新时，将执行您创建的特殊回调。这个回调是使 Vuex 能够完全更新或更改更新文件的行为的回调。

## 另请参阅

您可以在[`vuex.vuejs.org/guide/hot-reload.html`](https://vuex.vuejs.org/guide/hot-reload.html)找到有关 Vuex 热重载的更多信息。

您可以在 [`webpack.js.org/guides/hot-module-replacement/`](https://webpack.js.org/guides/hot-module-replacement/) 找到有关 webpack HMR 的更多信息。

# 创建一个 Vuex 模块

随着我们的应用程序的增长，在单个对象中工作可能非常危险。项目的可维护性和每次更改可能产生的风险都会变得更糟。

Vuex 有一种叫做模块的方法，可以帮助我们将存储分成不同的存储分支。这些分支或模块中的每一个都有不同的状态、变化、获取器和操作。这种模式有助于开发，并减少了向应用程序添加新功能的风险。

在这个教程中，我们将学习如何创建一个模块以及如何与之一起工作，将其分成专用分支。

## 准备工作

这个教程的先决条件如下：

+   Node.js 12+

所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

## 如何做...

要开始我们的组件，我们将使用在“*使用 Vuex 创建动态组件*”中使用的 Vue 项目和 Vue-CLI，或者我们可以开始一个新的项目。

要开始一个新的项目，打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> vue create vuex-store
```

选择手动功能并将 `Router` 和 `Vuex` 添加为必需功能，如“*如何做...*”部分和“*创建简单的 Vuex 存储*”教程中所示。

我们的教程将分为两个部分：

+   创建新的认证模块

+   向 Vuex 添加模块

让我们开始吧。

### 创建新的认证模块

首先，我们需要创建一个新的 `Vuex` 模块。这个示例模块将被称为 `authentication`，并将存储用户的凭据数据。

在这些步骤中，我们将为 `Vuex` 创建 `authentication` 模块：

1.  在 `src/store` 文件夹中创建一个名为 `authentication` 的新文件夹。

1.  在这个新创建的文件夹中，创建一个名为 `state.js` 的新文件，并打开它。

1.  创建一个名为 `generateState` 的函数，它将返回一个具有 `data.username`、`data.token`、`data.expiresAt`、`loading` 和 `error` 属性的 JavaScript 对象：

```js
const generateState = () => ({
  data: {
  username: '',
  token: '',
  expiresAt: null,
  },
  loading: false,
  error: null, });
```

1.  在文件末尾创建一个 `export default` 对象。这个对象将是一个 JavaScript 对象。我们将解构 `generateState` 函数的返回值：

```js
export default { ...generateState() };
```

1.  在 `src/store` 文件夹中的 `authentication` 文件夹中创建一个名为 `index.js` 的新文件，并打开它。

1.  导入新创建的 `state.js` 文件：

```js
import state from './state';
```

1.  在文件末尾创建一个`export default`对象。这个对象将是一个 JavaScript 对象。添加一个名为`namespaced`的新属性，其值设置为`true`，并添加导入的`state`：

```js
export default {
  namespaced: true,
  state, }; 
```

### 将模块添加到 Vuex

现在我们已经创建了我们的模块，我们将把它们添加到 Vuex 存储中。我们可以将新模块与旧代码集成在一起。这不是问题，因为 Vuex 将把新模块处理为一个命名空间对象，具有完全独立的 Vuex 存储。

现在，在这些步骤中，我们将把创建的模块添加到 Vuex 中：

1.  打开`src/store`文件夹中的`index.js`文件。

1.  从`authentication`文件夹中导入`index.js`文件：

```js
import Vue from 'vue'; import Vuex from 'vuex'; import UserStore from './user'; import Authentication from './authentication';
```

1.  在`Vuex.Store`函数中，添加一个名为`modules`的新属性，这是一个 JavaScript 对象。然后添加导入的`User`和`Authentication`模块：

```js
export default new Vuex.Store({
  ...UserStore,
  modules: {   Authentication,
  } })  
```

## 工作原理...

模块的工作方式类似于单一的 Vuex 存储，但在同一个 Vuex 单一的数据源中。这有助于开发更大规模的应用程序，因为你可以维护和处理更复杂的结构，而无需在同一个文件中检查问题。

与此同时，可以使用模块和普通的 Vuex 存储，从传统应用程序迁移，这样你就不必从头开始重写所有内容才能使用模块结构。

在我们的情况下，我们添加了一个名为`authentication`的新模块，只有一个状态存在于存储中，并继续使用旧的用户 Vuex 存储，这样将来我们可以将用户存储重构为一个新模块，并将其分离成更具体的、面向领域的架构。

## 另请参阅

您可以在[`vuex.vuejs.org/guide/modules.html`](https://vuex.vuejs.org/guide/modules.html)找到有关 Vuex 模块的更多信息。
