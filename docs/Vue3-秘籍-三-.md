# Vue3 秘籍（三）

> 原文：[`zh.annas-archive.org/md5/915E62C558C25E5846A894A1C2157B6C`](https://zh.annas-archive.org/md5/915E62C558C25E5846A894A1C2157B6C)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：通过 HTTP 请求从网络获取数据

数据现在是日常生活的一部分。如果没有数据，你就不会读到这本书，也不会试图了解更多关于 Vue 的知识。

了解如何在应用程序中获取和发送数据是开发人员的要求，而不仅仅是一个额外的技能。学习的最佳方式是通过实践，并找出它在幕后是如何完成的。

在这一章中，我们将学习如何使用 Fetch API 和当前最流行的 API 库`axios`来构建自己的 API 数据操作。

在这一章中，我们将涵盖以下的配方：

+   创建一个 Fetch API 的 HTTP 客户端包装器

+   创建一个随机猫图片或 GIF 组件

+   使用`MirageJS`创建本地虚拟 JSON API 服务器

+   使用`axios`作为新的 HTTP 客户端

+   创建不同的`axios`实例

+   为`axios`创建请求和响应拦截器

+   使用`axios`和`Vuesax`创建 CRUD 接口

# 技术要求

在这一章中，我们将使用 Node.js 和 Vue CLI。

注意，Windows 用户！你需要安装一个名为`windows-build-tools`的 NPM 包，以便能够安装以下所需的包。要做到这一点，以管理员身份打开 PowerShell 并执行以下命令：

`> npm install -g windows-build-tools`

要安装 Vue CLI，打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows），并执行以下命令：

```js
> npm install -g @vue/cli @vue/cli-service-global
```

# 创建一个 Fetch API 的 HTTP 客户端包装器

Fetch API 是旧的`XMLHttpRequest`的子代。它有一个改进的 API 和一个基于`Promises`的新而强大的功能集。

Fetch API 既简单又基于两个对象`Request`和`Response`的通用定义，使其可以在浏览器中的任何地方使用。浏览器的 Fetch API 也可以在`window`或`service worker`中执行。对于这个 API 的使用没有限制。

在这个配方中，我们将学习如何创建一个 Fetch API 的包装器，使 API 调用更简单。

## 准备工作

这个配方的先决条件如下：

+   Node.js 12+

所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

## 如何做...

要开始我们的组件，我们可以使用在第二章中创建的使用 Vue CLI 创建的 Vue 项目，或者我们可以开始一个新的项目。

要开始一个新的项目，打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> vue create http-project
```

CLI 将询问一些问题，这些问题将有助于创建项目。您可以使用箭头键导航，*Enter*键继续，*Spacebar*选择选项。选择`default`选项：

```js
?  Please pick a preset: **(Use arrow keys)** ❯ default (babel, eslint) 
  Manually select features  ‌
```

### 创建包装器

首先，我们需要创建一个新的 API 包装器来在这个教程中使用。这将是我们将在所有 HTTP 方法中使用的主要文件。

让我们按照以下步骤创建基本包装器：

1.  在`src/http`文件夹中创建一个名为`baseFetch.js`的新文件。

1.  我们将创建一个异步函数，它将作为参数接收`url`，`method`和`options`的三个变量。这将是一个柯里化函数，第二个函数将接收`type`作为参数：

```js
export default async (url, method, options = {}) => {
  let httpRequest;
  if (method.toUpperCase() === 'GET') {
  httpRequest = await fetch(url, {
  cache: 'reload',
  ...options,
  });
  } else {
  httpRequest = fetch(url, {
  method: method.toUpperCase(),
  cache: 'reload',
  ...options,
  });
  }
  return (type) => {
  switch (type.toLocaleLowerCase()) {
  case 'json':
  return httpRequest.json();
  case 'blob':
  return httpRequest.blob();
  case 'text':
  return httpRequest.text();
  case 'formdata':
  return httpRequest.formData();
  default:
  return httpRequest.arrayBuffer();
  }
 }; };
```

### 创建 API 方法

现在我们需要制作我们的 HTTP 方法函数。这些函数将使用包装器来执行浏览器的 Fetch API 并返回响应。

按照以下步骤创建每一个 API 方法调用：

1.  在`src/http`文件夹中创建一个名为`fetchApi.js`的新文件。

1.  我们需要从我们在第一步创建的文件中导入`baseHttp`：

```js
import baseHttp from './baseFetch';
```

现在在接下来的部分，我们将创建我们包装器中可用的每一个 HTTP 方法。

#### GET 方法函数

在这些步骤中，我们将创建*HTTP GET*方法。按照以下每一条指示来创建`getHttp`函数：

1.  创建一个名为`getHttp`的常量。

1.  定义一个常量作为一个异步函数，接收三个参数，`url`，`type`和`options`。`type`参数将默认值为`'json'`。

1.  在这个函数返回中，我们将执行`baseHttp`函数，传递我们收到的`url`，`'get'`作为第二个参数，`options`作为第三个参数，并立即执行带有我们收到的`type`参数的函数：

```js
export const getHttp = async (url, type = 'json', options) => (await   
   baseHttp(url, 'get', options))(type);
```

#### POST 方法函数

在这部分，我们将创建*HTTP POST*方法。按照以下步骤来创建`postHttp`函数：

1.  创建一个名为`postHttp`的常量。

1.  将一个异步函数分配给该常量，该函数接收四个参数，`url`、`body`、`type`和`options`。`type`参数将具有默认值`'json'`。

1.  在这个函数返回中，我们将执行`baseHttp`函数，传递我们收到的`url`参数和`'post'`作为第二个参数。在第三个参数中，我们将传递一个带有`body`变量和我们收到的解构`options`参数的对象。由于`baseHttp`的柯里化属性，我们将使用收到的`type`参数执行返回的函数。`body`通常是 JSON 或 JavaScript 对象。如果这个请求将是文件上传，`body`需要是一个`FormData`对象：

```js
export const postHttp = async (
  url,
  body,
  type = 'json',
  options,
) => (await baseHttp(url,
  'post',
  {
 body,
  ...options,
  }))(type);
```

#### PUT 方法函数

现在我们正在创建一个*HTTP PUT*方法。使用以下步骤创建`putHttp`函数：

1.  创建一个名为`putHttp`的常量。

1.  将一个异步函数分配给该常量，该函数接收四个参数，`url`、`body`、`type`和`options`。`type`参数将具有默认值`'json'`。

1.  在这个函数返回中，我们将执行`baseHttp`函数，传递我们收到的`url`和`'put'`作为第二个参数。在第三个参数中，我们将传递一个带有`body`变量和我们收到的解构`options`参数的对象。由于`baseHttp`的柯里化属性，我们将使用收到的`type`参数执行返回的函数。`body`通常是 JSON 或 JavaScript 对象，但如果这个请求将是文件上传，`body`需要是一个`FormData`对象：

```js
export const putHttp = async (
  url,
  body,
  type = 'json',
  options,
) => (await baseHttp(url,
  'put',
  {
 body,
  ...options,
  }))(type);
```

#### PATCH 方法函数

是时候创建一个*HTTP PATCH*方法了。按照以下步骤创建`patchHttp`函数：

1.  创建一个名为`patchHttp`的常量。

1.  将一个异步函数分配给该常量，该函数接收四个参数，`url`、`body`、`type`和`options`。`type`参数将具有默认值`'json'`。

1.  在这个函数返回中，我们将执行`baseHttp`函数，传递我们收到的`url`和`'patch'`作为第二个参数。在第三个参数中，我们将传递一个带有`body`变量和我们收到的解构`options`参数的对象。由于`baseHttp`的柯里化属性，我们将使用收到的`type`执行返回的函数。`body`通常是 JSON 或 JavaScript 对象，但如果这个请求将是文件上传，`body`需要是一个`FormData`对象：

```js
export const patchHttp = async (
  url,
  body,
  type = 'json',
  options,
) => (await baseHttp(url,
  'patch',
  {
 body,
  ...options,
  }))(type);  
```

#### 更新方法函数

在这一部分，我们正在创建一个*HTTP UPDATE*方法。按照以下步骤创建`updateHttp`函数：

1.  创建一个名为`updateHttp`的常量。

1.  将一个异步函数分配给该常量，该函数接收四个参数，`url`、`body`、`type`和`options`。`type`参数将具有默认值`'json'`。

1.  在这个函数返回中，我们将执行`baseHttp`函数，传递我们收到的`url`和`'update'`作为第二个参数。在第三个参数中，我们将传递一个带有`body`变量和我们收到的解构`options`参数的对象。由于`baseHttp`的柯里化属性，我们将使用收到的`type`执行返回的函数。`body`通常是 JSON 或 JavaScript 对象，但如果这个请求将是文件上传，`body`需要是一个`FormData`对象：

```js
export const updateHttp = async (
  url,
  body,
  type = 'json',
  options,
) => (await baseHttp(url,
  'update',
  {
 body,
  ...options,
  }))(type);  
```

#### DELETE 方法函数

在这最后一步，我们将创建一个*DELETE HTTP*方法。按照以下步骤创建`deleteHttp`函数：

1.  创建一个名为`deleteHttp`的常量。

1.  将一个异步函数分配给该常量，该函数接收四个参数，`url`、`body`、`type`和`options`。类型参数将具有默认值`'json'`。

1.  在这个函数返回中，我们将执行`baseHttp`函数，传递我们收到的`url`和`'delete'`作为第二个参数。在第三个参数中，我们将传递一个带有`body`变量和我们收到的解构`options`参数的对象。由于`baseHttp`的柯里化属性，我们将使用收到的`type`执行返回的函数。`body`通常是 JSON 或 JavaScript 对象，但如果这个请求将是文件上传，`body`需要是一个`FormData`对象：

```js
export const deleteHttp = async (
 url,
  body,
  type = 'json',
  options,
) => (await baseHttp(url,
  'delete',
  {
 body,
  ...options,
  }))(type);  
```

## 它是如何工作的...

在这个教程中，我们为`window`元素上呈现的`Fetch` API 创建了一个包装器。这个包装器由一个柯里化和闭包函数组成，第一个函数接收 Fetch API 的 URL 数据、方法和选项，而结果函数是 Fetch API 的响应转换器。

在包装器中，函数的第一部分将创建我们的`fetch`请求。在那里，我们需要检查它是否是*GET*方法，所以我们只需要用`url`参数执行它并省略其他参数。函数的第二部分负责将`fetch`响应转换。它将在`type`参数之间切换，并根据正确的参数执行检索函数。

要接收请求的最终数据，您始终需要在请求之后调用响应翻译器，就像以下示例中一样：

```js
getHttp('https://jsonplaceholder.typicode.com/todos/1', 'json').then((response) => { console.log(response)); }
```

这将从 URL 获取数据，并将响应转换为 JSON/JavaScript 对象。

我们制作的第二部分是方法翻译器。我们为每个 REST 动词制作了函数，以便更轻松地使用。 GET 动词没有能力传递任何`body`，但所有其他动词都能够在请求中传递`body`。

## 另请参阅

你可以在[`developer.mozilla.org/en-US/docs/Web/API/Fetch_API`](https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API)找到有关 Fetch API 的更多信息。

您可以在[`developer.mozilla.org/en-US/docs/Web/API/FormData/FormData`](https://developer.mozilla.org/en-US/docs/Web/API/FormData/FormData)找到有关 FormData 的更多信息。

您可以在[`developer.mozilla.org/en-US/docs/Web/API/Body/body`](https://developer.mozilla.org/en-US/docs/Web/API/Body/body)找到有关 Fetch 响应主体的更多信息。 [](https://developer.mozilla.org/en-US/docs/Web/API/Body/body)

您可以在[`developer.mozilla.org/en-US/docs/Web/API/Headers`](https://developer.mozilla.org/en-US/docs/Web/API/Headers)找到有关标头的更多信息。

您可以在[`developer.mozilla.org/`](https://developer.mozilla.org/en-US/docs/Web/API/Request)[en-US/docs/Web/API/Request](https://developer.mozilla.org/en-US/docs/Web/API/Request)找到有关请求的更多信息。

# 创建一个随机猫图像或 GIF 组件

众所周知，互联网上有许多猫的 GIF 和视频。我相信如果我们删除所有与猫有关的内容，我们将会出现网络黑屏。

了解有关 Fetch API 以及如何在组件内使用它的最佳方法是制作一个随机猫图像或 GIF 组件。

## 准备工作

此示例的先决条件如下：

+   Node.js 12+

所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

## 如何做...

要启动我们的组件，我们可以使用在“*将 Fetch API 包装为 HTTP 客户端”配方中使用的 Vue 项目和 Vue CLI，或者我们可以启动一个新的项目。

要启动新的项目，打开 Terminal（macOS 或 Linux）或 Command Prompt/PowerShell（Windows），并执行以下命令：

```js
> vue create http-project
```

CLI 将询问一些问题，这些问题将有助于创建项目。您可以使用箭头键导航，*Enter*键继续，*Spacebar*选择选项。选择`default`选项：

```js
?  Please pick a preset: **(Use arrow keys)** ❯ default (babel, eslint) 
  Manually select features  ‌
```

### 创建组件

在本教程中，我们将使用第四章*组件、混合和功能组件*中创建的组件进行视觉元素。您也可以使用简单的 HTML 元素来实现相同的结果。

我们将把这个组件的创建分为三个步骤：`<script>`、`<template>`和`<style>`。

#### 单文件组件`<script>`部分

按照以下步骤创建单文件组件的`<script>`部分：

1.  在`src/components`文件夹中创建一个名为`RandomCat.vue`的新文件并打开它。

1.  从我们在'*将 Fetch API 包装为 HTTP 客户端创建包装器*'教程中制作的`fetchApi`包装器中导入`getHttp`函数：

```js
import { getHttp } from '../http/fetchApi';
```

1.  在`component`属性中异步导入`MaterialButton`和`MaterialCardBox`组件：

```js
components: {
  MaterialButton: () => import('./MaterialButton.vue'),
  MaterialCardBox: () => import('./MaterialCardBox.vue'), },
```

1.  在`data`属性中，我们需要创建一个名为`kittyImage`的新数据值，默认为空字符串：

```js
data: () => ({
  kittyImage: '', }),
```

1.  在`methods`属性中，我们需要创建`getImage`方法，它将以`Blob`的形式获取图片，并将其作为`URL.createObjectURL`返回。我们还需要创建`newCatImage`方法，它将获取一张新的猫的静态图片，以及`newCatGif`方法，它将获取一个新的猫的 GIF：

```js
methods: {
  async getImage(url) {
  return URL.createObjectURL(await getHttp(url, 'blob'));
  },
  async newCatImage() {
  this.kittyImage = await this.getImage('https://cataas.com/cat');
  },
  async newCatGif() {
  this.kittyImage = await 
          this.getImage('https://cataas.com/cat/gif');
  },
  },
```

1.  在`beforeMount`生命周期钩子中，我们需要将其设置为异步，并执行`newCatImage`方法：

```js
async beforeMount() {
  await this.newCatImage();
  },
```

#### 单文件组件`<template>`部分

按照以下步骤创建单文件组件的`<template>`部分：

1.  首先，我们需要添加带有标题和副标题的`MaterialCardBox`组件，激活`media`和`action`部分，并为`media`和`action`创建`<template>`命名插槽：

```js
<MaterialCardBox
  header="Cat as a Service"
  sub-header="Random Cat Image"
  show-media
 show-actions >
 <template
  v-slot:media>  </template>
 <template v-slot:action>  </template> </MaterialCardBox>
```

1.  在`<template>`中名为`media`的插槽中，我们需要添加一个`<img>`元素，它将接收一个 URI`Blob`，当`kittyImage`变量中有任何数据时，它将显示出来，否则将显示一个加载图标：

```js
<img
  v-if="kittyImage"
  alt="Meow!"
 :src="kittyImage"
  style="width: 300px;" >
 <p v-else style="text-align: center">
 <i class="material-icons">
  cached
   </i>
 </p>
```

1.  在`<template>`中名为`action`的插槽中，我们将创建两个按钮，一个用于获取猫的图片，另一个用于获取猫的 GIF，两者都将在`@click`指令上有一个事件监听器，调用一个函数来获取相应的图片：

```js
<MaterialButton
  background-color="#4ba3c7"
  text-color="#fff"
  @click="newCatImage" >
 <i class="material-icons">
  pets
  </i> Cat Image
</MaterialButton> <MaterialButton
  background-color="#005b9f"
  text-color="#fff"
  @click="newCatGif" >
 <i class="material-icons">
  pets
  </i> Cat GIF
</MaterialButton>
```

#### 单文件组件`<style>`部分

在组件的`<style>`部分中，我们需要设置`body font-size`以便基于`rem`和`em`进行 CSS 样式计算：

```js
<style>
  body {
  font-size: 14px;
  } </style>
```

### 启动和运行您的新组件

按照以下步骤将您的组件添加到 Vue 应用程序中：

1.  在`src`文件夹中的`App.vue`文件中打开。

1.  在`components`属性中，异步导入`RandomCat.vue`组件：

```js
<script> export default {   name: 'App',
  components: {
  RandomCat: () => import('./components/RandomCat'),
  }, }; </script>
```

1.  在文件的`<template>`部分中，声明导入的组件：

```js
<template>
 <div id="app">
 <random-cat />
 </div> </template>
```

要运行服务器并查看您的组件，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> npm run serve
```

这是您的组件呈现并运行的方式：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-cb/img/9adf427e-c7ae-401c-91ac-37c077f575ed.png)

## 它是如何工作的...

使用`getHttp`包装器，组件能够获取 URL 并将其作为`Blob`类型检索出来。有了这个响应，我们可以使用`URL.createObjectUrl`导航方法，并将`Blob`作为参数传递，以获取一个有效的图像 URL，该 URL 可以用作`src`属性。

## 另请参阅

您可以在[`developer.mozilla.org/en-US/docs/Web/API/URL/createObjectURL`](https://developer.mozilla.org/en-US/docs/Web/API/URL/createObjectURL)找到有关`URL.createObjectUrl`的更多信息。

您可以在[`developer.mozilla.org/en-US/docs/Web/API/Body/blob`](https://developer.mozilla.org/en-US/docs/Web/API/Body/blob)找到有关`Blob`响应类型的更多信息。

# 使用 MirageJS 创建您的虚假 JSON API 服务器

为了测试、开发或设计而伪造数据总是一个问题。在开发阶段展示应用程序时，您需要有一个大的 JSON 或者制作一个自定义服务器来处理任何数据更改。

现在有一种方法可以帮助开发人员和 UI 设计师在不需要编写外部服务器的情况下实现这一点 - 一个名为 MirageJS 的新工具，它是在浏览器上运行的服务器模拟器。

在这个配方中，我们将学习如何使用 MirageJS 作为模拟服务器并在其上执行 HTTP 请求。

## 准备工作

此配方的先决条件如下：

+   Node.js 12+

所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

## 如何做...

要启动我们的组件，我们可以使用我们在“*将 Fetch API 作为 HTTP 客户端创建包装器*”配方中使用的 Vue 项目和 Vue CLI，或者我们可以启动一个新的项目。

要启动一个新项目，打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> vue create visual-component
```

CLI 将询问一些问题，这将有助于创建项目。您可以使用箭头键进行导航，使用*Enter*键继续，使用*Spacebar*选择选项。选择`default`选项：

```js
?  Please pick a preset: **(Use arrow keys)** ❯ default (babel, eslint) 
  Manually select features  ‌
```

### 创建模拟服务器

在这个配方中，我们将使用在“将 Fetch API 包装为 HTTP 客户端的创建包装器”配方中制作的`fetchApi`包装器的`getHttp`函数。

通过下一步和部分来创建您的`MirageJS`模拟服务器：

将`MirageJS`服务器安装到您的软件包中。您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> npm install --save miragejs
```

本配方使用的版本是 0.1.32。注意`MirageJS`的任何更改，因为目前还没有当前的 LTS 版本。

现在在接下来的部分中，我们将创建每一个由 MirageJS 服务器模拟的 HTTP 方法。

#### 创建模拟数据库

在这一部分，我们将创建一个`MirageJS`数据库，用于存储临时数据。按照以下步骤创建它：

1.  在`src/server`文件夹中创建一个名为`db.js`的新文件，用于初始加载的数据。

1.  我们需要为这个文件创建一个 JavaScript 对象作为默认导出，其中包含我们希望服务器具有的初始数据：

```js
export default {
  users: [
 {  name: 'Heitor Ramon Ribeiro',
  email: 'heitor@example.com',
  age: 31,
  country: 'Brazil',
  active: true,
  },
  ], };
```

#### 创建 GET 路由函数

在这一部分，我们将创建一个由`MirageJS`服务器模拟的*HTTP GET*方法。按照以下步骤创建它：

1.  对于*GET*方法，我们需要在`src/server`文件夹中创建一个名为`get.js`的新文件。

1.  对于这个配方，我们将创建一个通用的`getFrom`函数，该函数接收一个键作为参数并返回一个函数。这个返回的函数返回一个直接指向本地数据库的指定键：

```js
export const getFrom = key => ({ db }) => db[key];   export default {
  getFrom, };
```

#### 创建 POST 路由函数

在这一部分，我们将创建*HTTP POST*方法，这将由`MirageJS`服务器模拟。按照以下步骤创建它：

1.  对于*POST*方法，我们需要在`src/server`文件夹中创建一个名为`post.js`的新文件。

1.  对于这个配方，我们将创建一个通用的`postFrom`函数，该函数接收一个键作为参数并返回一个函数。这个返回的函数将解析 HTTP 请求体的`data`属性，并返回服务器模式的内部函数，将数据插入数据库。使用`key`参数，模式知道我们正在处理哪个表：

```js
export const postFrom = key => (schema, request) => {
  const { data } = typeof request.requestBody === 'string'
  ? JSON.parse(request.requestBody)
  : request.requestBody;    return schema.db[key].insert(data); };   export default {
  postFrom, };  
```

#### 创建 PATCH 路由函数

在本节中，我们将创建`MirageJS`服务器模拟的*HTTP PATCH*方法。按照以下步骤创建它：

1.  对于*PATCH*方法，我们需要在`src/server`文件夹中创建一个名为`patch.js`的新文件。

1.  对于这个配方，我们将制作一个通用的`patchFrom`函数，该函数接收一个键作为参数并返回一个函数。返回的函数将解析 HTTP 请求体的`data`属性，并返回一个服务器模式的内部函数，该函数更新具有与数据一起传递的`id`属性的特定对象。使用`key`参数，模式知道我们正在处理哪个表：

```js
export const patchFrom = key => (schema, request) => {
  const { data } = typeof request.requestBody === 'string'
  ? JSON.parse(request.requestBody)
  : request.requestBody;    return schema.db[key].update(data.id, data); };   export default {
  patchFrom, };
```

#### 创建 DELETE 路由函数

在本节中，我们将创建`MirageJS`服务器模拟的*HTTP DELETE*方法。按照以下步骤创建它：

1.  对于*DELETE*方法，我们需要在`src/server`文件夹中创建一个名为`delete.js`的新文件。

1.  对于这个配方，我们将制作一个通用的`patchFrom`函数，该函数接收一个键作为参数并返回一个函数。返回的函数将解析 HTTP 请求体的`data`属性，并返回一个服务器模式的内部函数，该函数删除具有通过路由*REST*参数传递给服务器的`id`属性的特定对象。使用`key`参数，模式知道我们正在处理哪个表：

```js
export const deleteFrom = key => (schema, request) => 
   schema.db[key].remove(request.params.id);   export default {
  deleteFrom, };
```

#### 创建服务器

在本节中，我们将创建`MirageJS`服务器和可用的路由。按照以下步骤创建服务器：

1.  在`src/server`文件夹中创建一个名为`server.js`的新文件。

1.  接下来，我们需要导入`Server`类，`baseData`和路由方法：

```js
import { Server } from 'miragejs'; import baseData from './db'; import { getFrom } from './get'; import { postFrom } from './post'; import { patchFrom } from './patch'; import { deleteFrom } from './delete'; 
```

1.  创建一个全局变量`server`，并将此变量设置为`Server`类的新执行：

```js
window.server = new Server({});
```

1.  在`Server`类的构造选项中，添加一个名为`seeds`的新属性。此属性是一个接收服务器（`srv`）作为参数并执行`srv.db.loadData`函数传递`baseDate`作为参数的函数：

```js
seeds(srv) {
 srv.db.loadData({ ...baseData }); },
```

1.  现在我们需要添加相同的构造选项到一个名为`routes`的新属性中，它将创建模拟服务器路由。这个属性是一个函数，在函数体内，我们需要设置模拟服务器的`namespace`和服务器响应的毫秒延迟。将有四个路由。对于**创建**路由，我们将创建一个名为`/users`的新路由，监听*POST*方法。对于**读取**路由，我们将创建一个名为`/users`的新路由，监听*GET*方法。对于**更新**路由，我们将创建一个名为`/users/:id`的新路由，监听*PATCH*方法，最后，对于**删除**路由，我们将创建一个名为`/users`的新路由，监听*DELETE*方法：

```js
routes() {
  this.namespace = 'api';    this.timing = 750;    this.get('/users', getFrom('users'));    this.post('/users', postFrom('users'));    this.patch('/users/:id', patchFrom('users'));    this.delete('/users/:id', deleteFrom('users'));
  },  
```

#### 添加到应用程序

在这一部分，我们将`MirageJS`服务器添加到 Vue 应用程序中。按照以下步骤使服务器对您的 Vue 应用程序可用：

1.  在`src`文件夹中打开`main.js`文件。

1.  我们需要将服务器声明为第一个导入声明，这样它就可以在应用程序的初始加载时可用：

```js
import './server/server'; import Vue from 'vue'; import App from './App.vue';   Vue.config.productionTip = false;   new Vue({
  render: h => h(App), }).$mount('#app');
```

### 创建组件

现在我们有了服务器，我们需要测试它。为了这样做，我们将创建一个简单的应用程序，运行每个 HTTP 方法，并显示每个调用的结果。

在接下来的部分，我们将创建一个简单的 Vue 应用程序。

#### 单文件组件`<script>`部分

在这部分，我们将创建单文件组件的`<script>`部分。按照以下步骤创建它：

1.  在`src`文件夹中打开`App.vue`文件。

1.  从我们在'将 Fetch API 包装为 HTTP 客户端的创建包装器'中制作的`fetchHttp`包装器中导入`getHttp`，`postHttp`，`patchHttp`和`deleteHTTP`方法：

```js
import {
  getHttp,
  postHttp,
  patchHttp,
  deleteHttp, } from './http/fetchApi';
```

1.  在`data`属性中，我们需要创建三个新属性来使用，`response`，`userData`和`userId`：

```js
data: () => ({
  response: undefined,
  userData: '',
  userId: undefined,
  }),
```

1.  在`methods`属性中，我们需要创建四个新方法，`getAllUsers`，`createUser`，`updateUser`和`deleteUser`：

```js
methods: {
  async getAllUsers() {
 },
  async createUser() {
 },
  async updateUser() {
 },
  async deleteUser() {
 }, },
```

1.  在`getAllUsers`方法中，我们将设置响应数据属性为`api/users`路由的`getHttp`函数的结果：

```js
async getAllUsers() {
  this.response = await getHttp(`${window.location.href}api/users`); },
```

1.  在`createUser`方法中，我们将接收一个`data`参数，这将是一个对象，我们将把它传递给`api/users`路由上的`postHttp`，然后执行`getAllUsers`方法：

```js
async createUser(data) {
  await postHttp(`${window.location.href}api/users`, { data });
  await this.getAllUsers(); },
```

1.  对于`updateUser`方法，我们将接收一个`data`参数，这将是一个对象，我们将其传递给`patchHttp`，在`api/users/:id`路由上使用对象上的`id`属性作为路由上的`:id`。之后，我们将执行`getAllUsers`方法：

```js
async updateUser(data) {
  await patchHttp(`${window.location.href}api/users/${data.id}`, 
     { data });
  await this.getAllUsers(); },
```

1.  最后，在`deleteUser`方法中，我们接收用户`id`作为参数，该参数是一个数字，然后我们将其传递给`deleteHttp`，在`api/users/:id`路由上使用 ID 作为`:id`。之后，我们执行`getAllUsers`方法：

```js
async deleteUser(id) {
  await deleteHttp(`${window.location.href}api/users/${id}`, {}, 'text');
  await this.getAllUsers(); },
```

#### 单文件组件<template>部分

在这部分，我们将创建单文件组件的`<template>`部分。按照以下步骤创建它：

1.  在模板的顶部，我们需要添加`response`属性，包裹在一个`<pre>`HTML 元素中：

```js
<h3>Response</h3> <pre>{{ response }}</pre>
```

1.  对于用户的创建和更新，我们需要创建一个带有`v-model`指令绑定到`userData`属性的`textarea`HTML 输入：

```js
<hr/> <h1> Create / Update User </h1> <label for="userData">
 User JSON:
 <textarea
 id="userData"
 v-model="userData"
 rows="10"
 cols="40"
 style="display: block;"
 ></textarea> </label>
```

1.  要发送这些数据，我们需要创建两个按钮，两者都在单击事件上绑定了事件侦听器，使用`@click`指令分别指向`createUser`和`updateUser`，并在执行时传递`userData`：

```js
<button
 style="margin: 20px;"
 @click="createUser(JSON.parse(userData))" >
  Create User
</button> <button
 style="margin: 20px;"
 @click="updateUser(JSON.parse(userData))" >
  Update User
</button>
```

1.  要执行*DELETE*方法，我们需要创建一个类型为`number`的输入 HTML 元素，并将`v-model`指令绑定到`userId`属性：

```js
<h1> Delete User </h1> <label for="userData">
  User Id:
<input type="number" step="1" v-model="userId"> </label>
```

1.  最后，要执行此操作，我们需要创建一个按钮，该按钮将在单击事件上绑定一个事件侦听器，使用`@click`指令，将其指向`deleteUser`方法，并在执行时传递`userId`属性：

```js
<button
 style="margin: 20px;"
 @click="deleteUser(userId)" >
  Delete User
</button>
```

要运行服务器并查看您的组件，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows），并执行以下命令：

```js
> npm run serve
```

这是您的组件呈现并运行的方式：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-cb/img/f170dcb7-058b-45da-ade2-13a97c97fb8a.png)

## 它是如何工作的...

`MirageJS`的工作原理类似于拦截应用程序上发生的每个 HTTP 请求的拦截器。服务器拦截浏览器上的所有**XHR (XMLHttpRequest)**执行，并检查路由，以查看它是否与服务器创建的任何一个路由匹配。如果匹配，服务器将根据相应的路由执行函数。

作为具有基本 CRUD 功能的简单 REST 服务器，服务器具有类似模式的数据库结构，有助于创建用于存储数据的虚拟数据库。

## 另请参阅

您可以在[`github.com/miragejs/miragejs`](https://github.com/miragejs/miragejs)找到有关 MirageJS 的更多信息。

# 使用 axios 作为新的 HTTP 客户端

当您需要一个用于 HTTP 请求的库时，毫无疑问`axios`是您应该选择的。这个库被超过 150 万个开源项目和无数个闭源项目使用，是 HTTP 库之王。

它构建成适用于大多数浏览器，并提供了最完整的选项集之一-您可以自定义请求中的一切。

在这个食谱中，我们将学习如何将我们的 Fetch API 包装器更改为`axios`并开始围绕它工作。

## 准备就绪

这个食谱的先决条件如下：

+   Node.js 12+

所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

## 如何做...

要启动我们的组件，我们可以使用在'*使用 MirageJS 创建您的虚拟 JSON API 服务器*'食谱中制作的 Vue 项目，或者我们可以开始一个新的项目。

要开始一个新的项目，打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> vue create http-project
```

CLI 会询问一些问题，这些问题将有助于创建项目。您可以使用箭头键进行导航，*Enter*键继续，*Spacebar*键选择选项。选择`default`选项：

```js
?  Please pick a preset: **(Use arrow keys)** ❯ default (babel, eslint) 
  Manually select features  ‌
```

### 从 Fetch API 更改为 Axios

在接下来的步骤中，我们将为 HTTP 包装器中使用的 Fetch API 更改为`axios`库。按照以下步骤正确更改它：

1.  在您的包中安装`axios`。您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> npm install --save axios
```

此食谱中使用的版本是 0.19.0。注意`axios`的更改，因为该库尚无 LTS 版本。

1.  打开`src/http`文件夹中的`baseFetch.js`文件。

1.  简化该方法，使其接收三个参数，`url`、`method`和`options`，并返回一个`axios`方法，使用传递给实例构造函数的方法调用 HTTP 请求：

```js
import axios from 'axios';

export default async (url, method, options = {}) => axios({
  method: method.toUpperCase(),
  url,
  ...options,
});
```

#### 更改 GET 方法函数

在这部分中，我们正在更改*HTTP GET*方法。按照以下说明更改`getHttp`函数：

1.  打开`src/http`文件夹中的`fetchApi.js`文件。

1.  在`getHttp`函数中，我们将添加一个新的参数 param，并删除柯里化函数：

```js
export const getHttp = async (
 url,
  params,
  options, ) => baseHttp(url,
  'get',
  {
  ...options,
  params,
  });
```

#### 更改 POST 方法函数

在这部分中，我们正在更改*HTTP POST*方法。按照以下说明更改`postHttp`函数：

1.  打开`http`文件夹中的`fetchApi.js`文件。

1.  在`postHttp`函数中，我们将把`body`参数改为`data`，并删除柯里化函数：

```js
export const postHttp = async (
 url,
  data,
  options, ) => baseHttp(url,
  'post',
  {
 data,
  ...options,
  });
```

#### 更改 PUT 方法函数

在这部分，我们正在更改*HTTP PUT*方法。按照以下说明更改`putHttp`函数：

1.  打开`http`文件夹内的`fetchApi.js`文件。

1.  在`putHttp`函数中，我们将把`body`参数改为`data`，并删除柯里化函数：

```js
export const putHttp = async (
 url,
  data,
  options, ) => baseHttp(url,
  'put',
  {
 data,
  ...options,
  });
```

#### 更改 PATCH 方法函数

在这部分，我们正在更改*HTTP PATCH*方法。按照以下说明更改`patchHttp`函数：

1.  打开`http`文件夹内的`fetchApi.js`文件。

1.  在`patchHttp`函数中，我们将把`body`参数改为`data`，并删除柯里化函数：

```js
export const patchHttp = async (
 url,
  data,
  options, ) => baseHttp(url,
  'patch',
  {
 data,
  ...options,
  });
```

#### 更改 UPDATE 方法函数

在这部分，我们正在更改*HTTP UPDATE*方法。按照以下说明更改`updateHttp`函数：

1.  打开`http`文件夹内的`fetchApi.js`文件。

1.  在`updateHttp`函数中，我们将添加一个新的参数 param，并删除柯里化函数：

```js
export const updateHttp = async (
 url,
  data,
  options, ) => baseHttp(url,
  'update',
  {
 data,
  ...options,
  });
```

#### 更改 DELETE 方法函数

在这部分，我们正在更改*HTTP DELETE*方法。按照以下说明更改`deleteHttp`函数：

1.  打开`http`文件夹内的`fetchApi.js`文件。

1.  在`deleteHttp`函数中，我们将把`body`参数改为`data`，并删除柯里化函数：

```js
export const deleteHttp = async (
 url,
  data,
  options, ) => baseHttp(url,
  'delete',
  {
 data,
  ...options,
  });
```

### 更改组件

在这部分，我们将改变组件与新函数的工作方式。按照以下说明正确更改它：

1.  打开`src`文件夹内的`App.vue`文件。

1.  在`getAllUsers`方法中，我们需要更改响应的定义方式，因为`axios`给我们提供了一个完全不同的响应对象，而不是 Fetch API：

```js
async getAllUsers() {
 const { data } = await getHttp(`${window.location.href}api/users`);
 this.response = data;
 },
```

1.  在`deleteUser`方法中，我们可以直接将 URL 作为参数传递：

```js
async deleteUser(id) {
 await deleteHttp(`${window.location.href}api/users/${id}`);
 await this.getAllUsers();
 },
```

要运行服务器并查看您的组件，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> npm run serve
```

## 它是如何工作的...

当我们为 Fetch API 创建包装器时，我们使用了一种将 API 抽象成另一个接口的技术，这使得从 Fetch API 更改到`axios`库成为可能。通过这样做，我们能够改进方法并简化函数的调用和处理方式。例如，GET 方法现在可以接收一个名为**params**的新参数，这些参数是 URL 查询参数的对象，将自动注入到 URL 中。

我们还必须更改响应的解释方式，因为`axios`比 Fetch API 具有更健壮和完整的响应对象，后者只返回获取的响应本身。

## 另请参阅

您可以在[`github.com/axios/axios`](https://github.com/axios/axios)找到有关`axios`的更多信息。

# 创建不同的 axios 实例

使用`axios`时，您可以运行多个实例，而它们互不干扰。例如，您可以有一个指向版本 1 的用户 API 的实例，另一个指向版本 2 的支付 API，两者共享相同的命名空间。

在这里，我们将学习如何创建各种`axios`实例，因此您可以在不受问题或干扰的情况下使用尽可能多的 API 命名空间。

## 准备工作

此食谱的先决条件如下：

+   Node.js 12+

所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

## 操作步骤...

要启动我们的组件，我们可以使用在“*使用 axios 作为新的 HTTP 客户端*”食谱中使用的 Vue CLI 创建的 Vue 项目，或者我们可以启动一个新的项目。

要启动一个新的实例，请打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> vue create http-project
```

CLI 将询问一些问题，这些问题将有助于创建项目。您可以使用箭头键进行导航，*Enter*键继续，*Spacebar*键选择选项。选择`default`选项：

```js
?  Please pick a preset: **(Use arrow keys)** ❯ default (babel, eslint) 
  Manually select features  ‌
```

### 更改 HTTP 函数

创建多个`axios`实例时，调用`axios`库的过程会发生变化。因此，我们需要更改 HTTP 包装器实例化`axios`库的方式。

在接下来的部分中，我们将改变 HTTP 包装器与创建新的`axios`实例的工作方式，并使其可用于应用程序。

#### 更改 HTTP Fetch 包装器

在接下来的步骤中，我们将创建一个新的自定义`axios`实例，该实例将用于 HTTP 包装器。按照以下说明将新实例添加到应用程序中：

1.  在`src/http`文件夹中打开`baseFetch.js`文件。

1.  我们需要创建一个名为`createAxios`的新工厂函数，以便每次执行时生成一个新的`axios`实例：

```js
export function createAxios(options = {}) {
  return axios.create({
  ...options,
  }); }
```

1.  现在，我们需要创建`localApi`常量，其值将是`createAxios`工厂的执行结果：

```js
const localApi = createAxios();
```

1.  对于`JSONPlaceHolder`，我们将创建一个名为`jsonPlaceholderApi`的常量，该常量将被导出，其值将是`createAxios`工厂的执行。我们还将传递一个对象作为参数，其中包含定义的`baseURL`属性：

```js
export const jsonPlaceholderApi = createAxios({
  baseURL: 'https://jsonplaceholder.typicode.com/', });
```

1.  在`export default`函数中，我们需要从`axios`更改为`localApi`：

```js
export default async (url, method, options = {}) => localApi({
  method: method.toUpperCase(),
  url,
  ...options, });
```

#### 更改 HTTP 方法函数

在这部分，我们将改变 HTTP 方法如何与新的`axios`实例一起工作。按照说明正确执行：

1.  在`src/http`文件夹中打开`fetchApi.js`文件。

1.  我们将从`baseFetch`导入`jsonPlaceholderApi`函数作为额外导入的值：

```js
import baseHttp, { jsonPlaceholderApi } from './baseFetch';
```

1.  我们需要创建一个名为`getTodos`的新常量，该常量将被导出。此常量将是一个函数，将接收`userId`作为参数，并返回`axios`的 GET 函数，其中`userId`参数将在名为`params`的属性的配置对象中接收：

```js
export const getTodos = async userId => jsonPlaceholderApi.get('todos',
  {
  params: {
 userId,
  },
  });
```

#### 更改 MirageJS 服务器

在这部分，我们将更改`MirageJS`服务器如何与新创建的`axios`实例一起工作。按照说明正确执行：

1.  在`src/server`文件夹中打开`server.js`文件。

1.  在构造函数对象的`routes`属性上，我们需要添加一个`passthrough`声明，这将指示 MirageJS 不会拦截对该 URL 的所有调用：

```js
import { Server } from 'miragejs'; import baseData from './db'; import { getFrom } from './get'; import { postFrom } from './post'; import { patchFrom } from './patch'; import { deleteFrom } from './delete';   window.server = new Server({
  seeds(srv) {
 srv.db.loadData({ ...baseData });
  },    routes() {
  this.passthrough();
  this.passthrough('https://jsonplaceholder.typicode.com/**');    this.namespace = 'api';    this.timing = 750;    this.get('/users', getFrom('users'));    this.post('/users', postFrom('users'));    this.patch('/users/:id', patchFrom('users'));    this.delete('/users/:id', deleteFrom('users'));
  }, });
```

### 更改组件

在包装函数、`MirageJS`服务器方法和 HTTP 方法更改后，我们需要将组件更改为已实现的新库。

在接下来的部分，我们将更改组件以匹配已实现的新库。

#### 单文件组件`<script>`部分

在这部分，我们将更改单文件组件的`<script>`部分。按照以下步骤执行：

1.  在`src`文件夹中打开`App.vue`文件。

1.  我们需要按以下方式导入新的`getTodos`函数：

```js
import {
  getHttp,
  postHttp,
  patchHttp,
  deleteHttp,
  getTodos, } from './http/fetchApi'; 
```

1.  在`Vue`对象的`data`属性中，我们需要创建一个名为`userTodo`的新属性，其默认值为一个空数组：

```js
data: () => ({
  response: undefined,
  userData: '',
  userId: undefined,
  userTodo: [], }),
```

1.  在`methods`属性中，我们需要创建一个名为`getUserTodo`的新方法，该方法接收`userId`参数。此方法将获取用户的待办事项列表，并将响应属性分配给`userTodo`属性：

```js
async getUserTodo(userId) {
 this.userTodo = await getTodos(userId); },
```

#### 单文件组件`<template>`部分

在这部分，我们将更改单文件组件的`<template>`部分。按照以下步骤执行：

1.  在`src`文件夹中打开`App.vue`文件。

1.  在模板底部，我们需要创建一个新的`input` HTML 元素，使用`v-model`指令绑定到`userId`属性：

```js
<h1> Get User ToDos </h1> <label for="userData">
  User Id:
  <input type="number" step="1" v-model="userId"> </label>
```

1.  要获取项目列表，我们需要创建一个按钮，该按钮绑定了点击事件的事件监听器，使用`@click`指令，目标是`getUserTodo`，并在执行中传递`userId`：

```js
<button
  style="margin: 20px;"
  @click="getUserTodo(userId)" >
  Fetch Data
</button>
```

要运行服务器并查看您的组件，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> npm run serve
```

这是您的组件呈现并运行的地方：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-cb/img/9364d3c2-9016-4ecc-a920-ab4bdb6d3634.png)

## 它是如何工作的...

当我们创建`axios`的新实例时，会创建一个新对象，并定义新的配置、标头、拦截器和操纵器。这是因为`axios`声明`create`函数与`new Class`相同。它是相同的接口但不同的对象。

利用这个可能性，我们能够创建两个连接驱动程序，一个用于本地 API，另一个用于`JSONPlaceHolder` API，它有一个不同的`baseURL`。

由于 MirageJS 服务器集成，所有 HTTP 请求都被 MirageJS 拦截，因此我们需要在路由构造函数中添加一个指令，指示 MirageJS 不会拦截的路由。

## 另请参阅

您可以在[`jsonplaceholder.typicode.com/`](https://jsonplaceholder.typicode.com/)找到有关 JSONPlaceHolder API 的更多信息。

您可以在[`github.com/axios/axios#creating-an-instance`](https://github.com/axios/axios#creating-an-instance)找到有关`axios`实例的更多信息。

您可以在[`github.com/miragejs/miragejs`](https://github.com/miragejs/miragejs)找到有关 MirageJS 的更多信息。

# 为 axios 创建请求和响应拦截器

在我们的应用程序中使用`axios`作为主要的 HTTP 操作器，允许我们使用请求和响应拦截器。这些用于在将数据发送到服务器之前或在接收数据时操纵数据，然后将其发送回 JavaScript 代码之前对其进行操纵。

拦截器最常用的方式是在 JWT 令牌验证和刷新接收特定错误或 API 错误操纵的请求时使用。

在这个示例中，我们将学习如何创建一个请求拦截器来检查*POST*、*PATCH*和*DELETE*方法以及一个响应错误操纵器。

## 准备工作

此示例的先决条件如下：

+   Node.js 12+

所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

## 如何做...

要启动我们的组件，我们可以使用我们在'*创建不同的 axios 实例*'食谱中制作的 Vue CLI 项目，也可以启动一个新的项目。

要开始一个新的，打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> vue create http-project
```

CLI 将询问一些问题，这些问题将有助于创建项目。您可以使用箭头键导航，*Enter*键继续，*Spacebar*选择选项。选择`default`选项：

```js
?  Please pick a preset: **(Use arrow keys)** ❯ default (babel, eslint) 
  Manually select features  ‌
```

### 创建拦截器

在接下来的步骤中，我们将创建一个`axios`拦截器，它将作为中间件工作。按照说明正确执行：

1.  安装`Sweet Alert`包。要做到这一点，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> npm install --save sweetalert2
```

1.  在`src/http`文件夹中创建一个名为`interceptors.js`的新文件并打开它。

1.  然后，我们导入 Sweet Alert 包：

```js
import Swal from 'sweetalert2';
```

1.  我们需要创建一个包含将被拦截的*POST*方法的数组的常量：

```js
const postMethods = ['post', 'patch'];
```

1.  我们需要创建一个名为`requestInterceptor`的函数并导出它。这个函数将接收一个参数`config`，它是一个`axios`配置对象。我们需要检查请求方法是否包含在我们之前创建的数组中，以及数据主体的`data`属性是否有一个`id`属性。如果任何检查未通过，我们将抛出一个`Error`，否则，我们将返回`config`：

```js
export function requestInterceptor(config) {
  if (
  postMethods.includes(config.method.toLocaleLowerCase()) &&
 Object.prototype.hasOwnProperty.call('id', config.data.data) && 
      !config.data.data.id) 
    {
  throw new Error('You need to pass an ID for this request');
  }    return config; } 
```

1.  对于响应拦截器，我们需要创建一个名为`responseInterceptor`的新函数，它返回响应，因为我们在这个拦截器中不会改变任何东西：

```js
export function responseInterceptor(response) {
  return response; }
```

1.  为了捕获错误，我们需要创建一个`errorInterceptor`函数，它将被导出。这个函数接收一个`error`作为参数，并显示一个`sweetalert2`警报错误消息，并返回一个带有`error`的`Promise.reject`：

```js
export function errorInterceptor(error) {
  Swal.fire({
  type: 'error',
  title: 'Error!',
  text: error.message,
  });    return Promise.reject(error); }
```

### 将拦截器添加到 HTTP 方法函数中

在接下来的步骤中，我们将向 HTTP 方法函数添加`axios`拦截器。按照以下步骤正确执行：

1.  在`src/http`文件夹中打开`baseFetch.js`文件。

1.  我们需要导入刚刚创建的三个拦截器：

```js
import {
  errorInterceptor,
  requestInterceptor,
  responseInterceptor, } from './interceptors';
```

1.  在创建`localApi`实例之后，我们声明了请求和响应拦截器的使用：

```js
localApi.interceptors
  .request.use(requestInterceptor, errorInterceptor);   localApi.interceptors
  .response.use(responseInterceptor, errorInterceptor);
```

1.  在创建`jsonPlaceholderApi`实例之后，我们声明了请求和响应拦截器的使用：

```js
jsonPlaceholderApi.interceptors
  .request.use(requestInterceptor, errorInterceptor);   jsonPlaceholderApi.interceptors
  .response.use(responseInterceptor, errorInterceptor);
```

## 工作原理...

`axios`执行的每个请求都会通过拦截器集中的任何一个。响应也是一样。如果在拦截器上抛出任何错误，它将自动传递给错误处理程序，因此请求根本不会被执行，或者响应将作为错误发送到 JavaScript 代码。

我们检查了每个*POST*，*PATCH*和*DELETE*方法所做的每个请求，以查看在请求体数据中是否有`id`属性。如果没有，我们向用户抛出错误，告诉他们需要为请求传递一个 ID。

## 另请参阅

您可以在[`sweetalert2.github.io`](https://sweetalert2.github.io)找到有关 Sweet Alert 2 的更多信息。

您可以在**[`github.com/axios/axios#interceptors`](https://github.com/axios/axios#interceptors)**找到有关`axios`请求拦截器的更多信息。

# 使用 Axios 和 Vuesax 创建 CRUD 界面

在处理数据时，我们总是需要做一些事情：CRUD 过程。无论您正在开发什么类型的应用程序，都需要 CRUD 界面以便在服务器上输入和操作任何数据，管理面板，应用程序的后端，甚至客户端。

在这里，我们将学习如何使用`Vuesax`框架和`axios`进行 HTTP 请求来创建一个简单的 CRUD 界面。

## 准备工作

此配方的先决条件如下：

+   Node.js 12+

所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

## 如何做...

要启动我们的组件，请使用我们在“*为 axios 创建请求和响应拦截器*”配方中使用的 Vue CLI 的 Vue 项目，或者启动一个新项目。

要启动一个新项目，请打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> vue create http-project
```

CLI 将询问一些问题，这些问题将有助于创建项目。您可以使用箭头键导航，*Enter*键继续，*Spacebar*选择选项。选择`default`选项：

```js
?  Please pick a preset: **(Use arrow keys)** ❯ default (babel, eslint) 
  Manually select features  ‌
```

### 将 Vuesax 添加到应用程序

在接下来的步骤中，我们将介绍如何将`Vuesax`UI 库添加到您的 Vue 应用程序中。按照这些说明正确执行：

1.  打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> npm install --save vuesax material-icons
```

1.  在`src`文件夹中创建一个名为`style.css`的文件并打开它。

1.  导入`vuesax`，`material-icon`和`Open Sans`字体样式表：

```js
@import url('https://fonts.googleapis.com/css?family=Open+Sans:300,300i,400,400i,600,600i,700,700i,800,
    800i&display=swap'); @import url('~vuesax/dist/vuesax.css'); @import url('~material-icons/iconfont/material-icons.css');   * {
  font-family: 'Open Sans', sans-serif; }
```

1.  打开`src`文件夹中的`main.js`文件。

1.  导入`style.css`文件和`Vuesax`。之后，您需要通知 Vue 使用`Vuesax`：

```js
import './server/server'; import Vue from 'vue'; import App from './App.vue'; import Vuesax from 'vuesax'; import './style.css';   Vue.use(Vuesax);   Vue.config.productionTip = false;   new Vue({
  render: h => h(App), }).$mount('#app');
```

### 创建组件路由

我们将在五个部分中继续这个过程：`List`，`Create`，`Read`，`Update`和`Delete`。我们的应用将是一个动态组件应用程序，因此我们将创建五个组件，每个部分一个。这些组件将类似于我们的页面。

首先，我们需要将`App.vue`更改为我们的主路由管理器，并创建一个用于更改组件的混合器。

#### 单文件组件`<script>`部分

在这部分，我们将创建单文件组件的`<script>`部分。按照以下说明正确创建组件：

1.  在`src`文件夹中打开`App.vue`。

1.  导入将在此处创建的每个组件：

```js
import List from './components/list'; import Create from './components/create'; import View from './components/view'; import Update from './components/update';
```

1.  在`data`属性中，创建两个新值：`componentIs`默认值为`'list'`，`userId`默认值为`0`：

```js
data: () => ({
  componentIs: 'list',
  userId: 0, }),
```

1.  我们需要向 Vue 对象添加一个名为`provide`的新属性。该属性将是一个函数，因此提供给组件的值可以是响应式的：

```js
provide () {
  const base = {};    Object.defineProperty(base, 'userId', {
  enumerable: true,
  get: () => Number(this.userId),
 });    return base; },
```

1.  在`computed`属性中，我们需要创建一个名为`component`的新属性。这将是一个 switch case，根据`componentIs`属性返回我们的组件：

```js
computed: {
  component() {
  switch (this.componentIs) {
  case 'list':
  return List;
  case 'create':
  return Create;
  case 'view':
  return View;
  case 'edit':
  return Update;
  default:
  return undefined;
  }
 } },
```

1.  最后，在方法中，我们需要创建一个`changeComponent`方法，将当前组件更新为新组件：

```js
methods: {
  changeComponent(payload) {
  this.componentIs = payload.component;
  this.userId = Number(payload.userId);
  }, },
```

#### 单文件组件`<template>`部分

在这部分，我们将创建单文件组件的`<template>`部分。按照以下说明正确创建组件：

1.  在`div#app` HTML 元素中，我们需要添加一个`vs-row`组件：

```js
<div id="app">
 <vs-row></vs-row> </div>
```

1.  在`vs-row`组件中，我们需要添加一个`vs-col`组件，具有以下属性：`vs-type`定义为`flex`，`vs-justify`定义为`left`，`vs-align`定义为`left`，`vs-w`定义为`12`：

```js
<vs-col
  vs-type="flex"
  vs-justify="left"
  vs-align="left"
  vs-w="12"> </vs-col>
```

1.  最后，在`vs-col`组件内部，我们将添加一个动态组件，该组件具有一个`is`属性，指向计算属性`component`，并将事件侦听器指向将执行`changeComponent`方法的`"change-component"`事件：

```js
<component
 :is="component"
 @change-component="changeComponent" />
```

#### 创建路由混合器

在这部分，我们将创建组件混合器，以便在其他组件中重复使用。按照以下说明正确创建组件：

1.  在`src/mixin`文件夹中创建一个名为`changeComponent.js`的新文件并打开它。

1.  这个混合器将有一个名为`changeComponent`的方法，它将发出一个名为`'change-component'`的事件，其中包含需要呈现的新组件的名称和`userId`：

```js
export default {
  methods: {
    changeComponent(component, userId = 0) {
      this.$emit('change-component', { component, userId });
    },
  }
}
```

### 创建列表组件

列表组件将是索引组件。它将列出应用程序中的用户，并具有其他 CRUD 操作的所有链接。

#### 单文件组件`<script>`部分

在这部分，我们将创建单文件组件的`<script>`部分。按照这些说明正确创建组件：

1.  在`src/components`文件夹中创建一个名为`list.vue`的新文件并打开它。

1.  从`fetchApi`导入`getHttp`和`deleteHttp`，以及`changeComponent`混合器：

```js
import {
  getHttp,
  deleteHttp,
 } from '../http/fetchApi';
  import changeComponent from '../mixin/changeComponent';
```

1.  在组件的`mixins`属性中，我们需要添加导入的`changeComponent`混合器：

```js
mixins: [changeComponent],
```

1.  在组件的`data`属性中，我们添加了一个名为`userList`的新属性，其默认为空数组：

```js
data: () => ({
  userList: [], }),
```

1.  对于方法，我们创建了`getAllUsers`和`deleteUsers`方法。在`getAllUsers`方法中，我们获取用户列表，并将`userList`的值设置为`getHttp`函数执行的响应。`deleteUser`方法将执行`deleteHttp`函数，然后执行`getAllUsers`方法：

```js
methods: {
  async getAllUsers() {
  const { data } = await getHttp(`${window.location.href}api/users`);
  this.userList = data;
  },
  async deleteUser(id) {
  await deleteHttp(`${window.location.href}api/users/${id}`);
  await this.getAllUsers();
  }, }
```

1.  最后，我们将`beforeMount`生命周期钩子异步化，调用`getAllUsers`方法：

```js
async beforeMount() {
  await this.getAllUsers(); },
```

#### 单文件组件<template>部分

在这部分，我们将创建单文件组件的`<template>`部分。按照这些说明正确创建组件：

1.  创建一个带有`style`属性定义为`margin: 20px`的`vs-card`组件：

```js
<vs-card   style="margin: 20px;"
  >
</vs-card>
```

1.  在`vs-card`组件内部，为`header`创建一个动态的`<template>`，其中包含一个`<h3>`标签和您的标题：

```js
<template slot="header">
 <h3>
  Users
  </h3> </template>
```

1.  之后，创建一个`vs-row`组件，其中包含一个`vs-col`组件，具有以下属性：`vs-type`定义为`flex`，`vs-justify`定义为`left`，`vs-align`定义为`left`，`vs-w`定义为`12`：

```js
<vs-row>
 <vs-col
  vs-type="flex"
  vs-justify="left"
  vs-align="left"
  vs-w="12">
  </vs-col>
</vs-row>
```

1.  在`vs-col`组件内部，我们需要创建一个`vs-table`组件。该组件将具有指向`userList`变量的`data`属性，并将`search`，`stripe`和`pagination`属性定义为 true。`max-items`属性将被定义为`10`，`style`属性将具有`width: 100%; padding: 20px;`的值：

```js
<vs-table
  :data="userList"
  search
 stripe pagination max-items="10"
  style="width: 100%; padding: 20px;" ></vs-table>
```

1.  对于表头，我们需要创建一个名为 `thead` 的动态 `<template>`，并为每一列创建一个带有 `sort-key` 属性定义为相应对象键属性和显示为您想要的名称的 `vs-th` 组件：

```js
<template slot="thead">
 <vs-th sort-key="id">
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
  </vs-th> </template>
```

1.  对于表格主体，我们需要创建一个动态的 `<template>`，其中定义了一个 `slot-scope` 属性作为 `data` 属性。在这个 `<template>` 中，我们需要创建一个 `vs-tr` 组件，它将迭代数据属性，并为表格头部设置的每一列创建一个 `vs-td` 组件。每个 `vs-td` 组件都有一个设置为相应列数据对象属性的数据属性，并且内容将是相同的数据渲染。最后一列是操作列，将有三个按钮，一个用于读取，另一个用于更新，最后一个用于删除。读取按钮将在 `"click"` 事件上有一个指向 `changeComponent` 的事件监听器，更新按钮也是如此。删除按钮的 `"click"` 事件监听器将指向 `deleteUser` 方法：

```js
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
  @click="changeComponent('view', data[index].id)"
  />
 <vs-button
  color="success"
  type="filled"
  icon="edit"
  size="small"
  @click="changeComponent('edit', data[index].id)"
  />
 <vs-button
  color="danger"
  type="filled"
  icon="delete"
  size="small"
  @click="deleteUser(data[index].id)"
  />
 </vs-td>
 </vs-tr> </template>
```

1.  最后，在卡片页脚中，我们需要创建一个名为 `footer` 的动态 `<template>`。在这个 `<template>` 中，我们将添加一个带有 `vs-justify` 属性定义为 `flex-start` 的 `vs-row` 组件，并插入一个带有 `color` 属性定义为 `primary`、`type` 属性定义为 `filled`、`icon` 属性定义为 `fiber_new` 和 `size` 属性定义为 `small` 的 `vs-button`。`@click` 事件监听器将以参数 `'create'` 和 `0` 目标 `changeComponent` 方法：

```js
<template slot="footer">
 <vs-row vs-justify="flex-start">
 <vs-button
  color="primary"
  type="filled"
  icon="fiber_new"
  size="small"
  @click="changeComponent('create', 0)"
  >
  Create User
    </vs-button>
 </vs-row> </template>  
```

#### 单文件组件 <style> 部分

在这部分，我们将创建单文件组件的 `<style>` 部分。按照以下说明正确创建组件：

1.  为 `vs-button` 组件类创建一个边距声明：

```js
<style scoped>
  .vs-button {
  margin-left: 5px;
 } </style>
```

1.  要运行服务器并查看您的组件，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> npm run serve
```

这是您的组件渲染和运行的地方：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-cb/img/32cc6d50-9ad1-4037-ad9a-cdf3639463ef.png)

### 创建一个通用的用户表单组件

在接下来的部分，我们将创建一个通用的用户表单组件，它将被其他组件使用。这个组件被认为是通用的，因为它是一个可以被任何人使用的组件。

#### 单文件组件 <script> 部分

在这部分，我们将创建单文件组件的 `<script>` 部分。按照以下说明正确创建组件：

1.  在`src/components`文件夹中创建一个名为`userForm.vue`的新文件并打开它。

1.  在 Vue 的`props`属性中，创建两个名为`value`和`disabled`的新属性，都是对象，并具有`type`、`required`和`default`三个属性。对于`value`属性，`type`将是`Object`，`required`将是`false`，`default`将是返回一个对象的工厂。对于`disabled`属性，`type`将是`Boolean`，`required`将是`false`，`default`也将是`false`：

```js
props: {
  value: {
  type: Object,
  required: false,
  default: () => {
 },
  },
  disabled: {
  type: Boolean,
  required: false,
  default: false,
  } },
```

1.  在`data`属性中，我们需要添加一个名为`tmpForm`的新值，其默认值为一个空对象：

```js
data: () => ({
  tmpForm: {}, }),
```

1.  在 Vue 的`watch`属性中，我们需要为`tmpForm`和`value`创建处理程序。对于`tmpForm` watcher，我们将添加一个`handler`函数，它将在每次更改时发出一个`'input'`事件，带有新的`value`，并将`deep`属性添加为`true`。最后，在`value` watcher 中，我们将添加一个`handler`函数，它将将`tmpForm`的值设置为新的`value`。我们还需要将`deep`和`immediate`属性定义为`true`：

```js
watch: {
  tmpForm: {
  handler(value) {
  this.$emit('input', value);
  },
  deep: true,
  },
  value: {
  handler(value) {
  this.tmpForm = value;
  },
  deep: true,
  immediate: true,
  } },
```

在使用 watchers 时，声明`deep`属性使 watcher 检查数组或对象的深层更改，而`immediate`属性在组件创建时立即执行 watcher。

#### 单文件组件`<template>`部分

在这部分，我们将创建单文件组件的`<template>`部分。按照这些说明正确创建组件：

1.  对于输入包装器，我们需要创建一个`vs-row`组件。在`vs-row`组件内部，我们将为我们的用户表单创建每个输入：

```js
<vs-row></vs-row>
```

1.  对于名称输入，我们需要创建一个`vs-col`组件，其中`vs-type`属性定义为`'flex'`，`vs-justify`定义为`'left'`，`vs-align`定义为`'left'`，`vs-w`定义为`'6'`。在`vs-col`组件内部，我们需要创建一个`vs-input`组件，其中`v-model`指令绑定到`tmpForm.name`，`disabled`属性绑定到`disabled` props，`label`定义为`'Name'`，`placeholder`定义为`'User Name'`，`class`定义为`'inputMargin full-width'`：

```js
<vs-col
  vs-type="flex"
  vs-justify="left"
  vs-align="left"
  vs-w="6">
 <vs-input
  v-model="tmpForm.name"
  :disabled="disabled"
  label="Name"
  placeholder="User Name"
  class="inputMargin full-width"
  /> </vs-col>
```

1.  对于电子邮件输入，我们需要创建一个`vs-col`组件，其中`vs-type`属性定义为`'flex'`，`vs-justify`属性定义为`'left'`，`vs-align`属性定义为`'left'`，`vs-w`属性定义为`'6'`。在`vs-col`组件内部，我们需要创建一个`vs-input`组件，其中`v-model`指令绑定到`tmpForm.email`，`disabled`属性绑定到`disabled`属性，`label`定义为`'Email'`，`placeholder`定义为`'User Email'`，`class`定义为`'inputMargin full-width'`：

```js
<vs-col
  vs-type="flex"
  vs-justify="left"
  vs-align="left"
  vs-w="6">
 <vs-input
  v-model="tmpForm.email"
  :disabled="disabled"
  label="Email"
  placeholder="User Email"
  class="inputMargin full-width"
  /> </vs-col>
```

1.  对于国家输入，我们需要创建一个`vs-col`组件，其中`vs-type`属性定义为`'flex'`，`vs-justify`属性定义为`'left'`，`vs-align`属性定义为`'left'`，`vs-w`属性定义为`'6'`。在`vs-col`组件内部，我们需要创建一个`vs-input`组件，其中`v-model`指令绑定到`tmpForm.country`，`disabled`属性绑定到`disabled`属性，`label`定义为`'Country'`，`placeholder`定义为`'User Country'`，`class`定义为`'inputMargin full-width'`：

```js
<vs-col
  vs-type="flex"
  vs-justify="left"
  vs-align="left"
  vs-w="6">
 <vs-input
  v-model="tmpForm.country"
  :disabled="disabled"
  label="Country"
  placeholder="User Country"
  class="inputMargin full-width"
  /> </vs-col>
```

1.  对于电话输入，我们需要创建一个`vs-col`组件，其中`vs-type`属性定义为`'flex'`，`vs-justify`属性定义为`'left'`，`vs-align`属性定义为`'left'`，`vs-w`属性定义为`'6'`。在`vs-col`组件内部，我们需要创建一个`vs-input`组件，其中`v-model`指令绑定到`tmpForm.phone`，`disabled`属性绑定到`disabled`属性，`label`定义为`'Phone'`，`placeholder`定义为`'User Phone'`，`class`定义为`'inputMargin full-width'`：

```js
<vs-col
  vs-type="flex"
  vs-justify="left"
  vs-align="left"
  vs-w="6">
 <vs-input
  v-model="tmpForm.phone"
  :disabled="disabled"
  label="Phone"
  placeholder="User Phone"
  class="inputMargin full-width"
  /> </vs-col>
```

1.  对于生日输入，我们需要创建一个`vs-col`组件，其中`vs-type`属性定义为`'flex'`，`vs-justify`属性定义为`'left'`，`vs-align`属性定义为`'left'`，`vs-w`属性定义为`'6'`。在`vs-col`组件内部，我们需要创建一个`vs-input`组件，其中`v-model`指令绑定到`tmpForm.birthday`，`disabled`属性绑定到`disabled`属性，`label`定义为`'Birthday'`，`placeholder`定义为`'User Birthday'`，`class`定义为`'inputMargin full-width'`：

```js
<vs-col
  vs-type="flex"
  vs-justify="left"
  vs-align="left"
  vs-w="6">
 <vs-input
  v-model="tmpForm.birthday"
  :disabled="disabled"
  label="Birthday"
  placeholder="User Birthday"
  class="inputMargin full-width"
  /> </vs-col>
```

#### 单文件组件`<style>`部分

在这部分，我们将创建单文件组件的`<style>`部分。按照以下说明正确创建组件：

创建一个名为`inputMargin`的新的作用域类，其中`margin`属性定义为`15px`：

```js
<style>
  .inputMargin {
  margin: 15px;
 } </style>
```

### 创建创建用户组件

要开始我们的用户操作过程，我们需要创建一个初始的基本用户表单，以便在`View`、`Create`和`Update`组件之间共享。

#### 单文件组件<script>部分

在这部分，我们将创建单文件组件的`<script>`部分。按照这些说明正确创建组件：

1.  在`src/components`文件夹中创建一个名为`create.vue`的新文件并打开它。

1.  从`fetchApi`中导入`UserForm`组件、`changeComponent`混合和`postHttp`：

```js
import UserForm from './userForm'; import changeComponent from '../mixin/changeComponent'; import { postHttp } from '../http/fetchApi';
```

1.  在`data`属性中，我们将添加一个`userData`对象，其中`name`、`email`、`birthday`、`country`和`phone`属性都定义为空字符串：

```js
data: () => ({
  userData: {
  name: '',
  email: '',
  birthday: '',
  country: '',
  phone: '',
  }, }),
```

1.  在 Vue 的`mixins`属性中，我们需要添加`changeComponent`：

```js
mixins: [changeComponent],
```

1.  在 Vue 的`components`属性中，添加`UserForm`组件：

```js
components: {
  UserForm, },
```

1.  在`methods`属性中，我们需要创建`createUser`方法，该方法将使用`userData`属性上的数据，并在服务器上创建一个新用户，然后将用户重定向到用户列表：

```js
methods: {
  async createUser() {
  await postHttp(`${window.location.href}api/users`, {
  data: {
  ...this.userData,
  }
 });
  this.changeComponent('list', 0);
  }, },
```

#### 单文件组件<template>部分

在这部分，我们将创建单文件组件的`<template>`部分。按照这些说明正确创建组件：

1.  创建一个`vs-card`组件，其中`style`属性定义为`margin: 20px`：

```js
<vs-card
  style="margin: 20px;"
  >
</vs-card>
```

1.  在`vs-card`组件内部，为`header`创建一个动态的`<template>`插槽，其中包含一个`<h3>`标签和您的标题：

```js
<template slot="header">
 <h3>
 Create User
  </h3> </template>
```

1.  之后，创建一个`vs-row`组件，其中包含一个`vs-col`组件，其属性为`vs-type`定义为`flex`，`vs-justify`定义为`left`，`vs-align`定义为`left`，`vs-w`定义为`12`：

```js
<vs-row>
 <vs-col
  vs-type="flex"
  vs-justify="left"
  vs-align="left"
  vs-w="12">
  </vs-col>
</vs-row>
```

1.  在`vs-col`组件内部，我们将添加`user-form`组件，并将`v-model`指令绑定到`userData`上：

```js
<user-form
  v-model="userData"  />
```

1.  最后，在卡片页脚中，我们需要为`footer`创建一个动态的`<template>`插槽。在这个`<template>`中，我们将添加一个带有`vs-justify`属性定义为`flex-start`的`vs-row`组件，并插入两个`vs-button`组件。第一个将用于创建用户，其属性为`color`定义为`success`，`type`定义为`filled`，`icon`定义为`save`，`size`定义为`small`。`@click`事件监听器将针对`createUser`方法，第二个`vs-button`组件将用于取消此操作并返回到用户列表。它的属性为`color`定义为`danger`，`type`定义为`filled`，`icon`定义为`cancel`，`size`定义为`small`，`style`定义为`margin-left: 5px`，`@click`事件监听器将目标设置为`changeComponent`方法，参数为`'list'`和`0`：

```js
<template slot="footer">
 <vs-row vs-justify="flex-start">
 <vs-button
  color="success"
  type="filled"
  icon="save"
  size="small"
  @click="createUser"
  >
  Create User
    </vs-button>
 <vs-button
  color="danger"
  type="filled"
  icon="cancel"
  size="small"
  style="margin-left: 5px"
  @click="changeComponent('list', 0)"
  >
  Cancel
    </vs-button>
 </vs-row> </template>
```

要运行服务器并查看您的组件，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> npm run serve
```

这是您的组件呈现并运行的地方：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-cb/img/87bf2b8e-ab56-4b75-965a-d7f4f71677ad.png)

### 视图组件

在接下来的部分中，我们将创建可视化组件。此组件仅用于查看用户信息。

#### 单文件组件`<script>`部分

在这部分，我们将创建单文件组件的`<script>`部分。按照以下说明正确创建组件：

1.  在`src/components`文件夹中创建名为`view.vue`的文件并打开它。

1.  导入`UserForm`组件，`changeComponent` mixin 和`fetchApi`中的`getHttp`：

```js
import {
  getHttp, } from '../http/fetchApi'; import UserForm from './userForm'; import changeComponent from '../mixin/changeComponent';
```

1.  在`data`属性中，我们将添加一个`userData`对象，其中`name`，`email`，`birthday`，`country`和`phone`属性都定义为空字符串：

```js
data: () => ({
  userData: {
  name: '',
  email: '',
  birthday: '',
  country: '',
  phone: '',
  }, }),
```

1.  在 Vue 的`mixins`属性中，我们需要添加`changeComponent` mixin：

```js
mixins: [changeComponent],
```

1.  在 Vue 的`inject`属性中，我们需要声明`'userId'`属性：

```js
inject: ['userId'],
```

1.  在 Vue 的`components`属性中，添加`UserForm`组件：

```js
components: {
  UserForm, },
```

1.  对于方法，我们将创建`getUserById`方法。此方法将通过当前 ID 获取用户数据，并将`userData`值设置为`getHttp`函数执行的响应：

```js
methods: {
  async getUserById() {
  const { data } = await getHttp(`${window.location.href}api/users/${this.userId}`);
  this.userData = data;
  }, }
```

1.  在`beforeMount`生命周期钩子中，我们将使其异步，调用`getUserById`方法：

```js
async beforeMount() {
  await this.getUserById(); },
```

#### 单文件组件`<template>`部分

在这部分，我们将创建单文件组件的`<template>`部分。按照以下说明正确创建组件：

1.  创建一个带有`style`属性定义为`margin: 20px`的`vs-card`组件：

```js
<vs-card
  style="margin: 20px;"
  >
</vs-card>
```

1.  在`vs-card`组件内，为`header`创建一个动态的`<template>`，并添加一个`<h3>`标签和您的标题：

```js
<template slot="header">
 <h3>
  View User
  </h3> </template>
```

1.  之后，创建一个带有`vs-col`组件的`vs-row`组件，其中`vs-type`属性定义为`flex`，`vs-justify`属性定义为`left`，`vs-align`属性定义为`left`，`vs-w`属性定义为`12`：

```js
<vs-row>
 <vs-col
  vs-type="flex"
  vs-justify="left"
  vs-align="left"
  vs-w="12">
  </vs-col>
</vs-row>
```

1.  在`vs-col`组件内，我们将添加`UserForm`组件，并将`v-model`指令绑定到`userData`，并将`disabled`属性设置为`true`：

```js
<user-form
  v-model="userData"
  disabled />
```

1.  最后，在卡片页脚中，我们需要为`footer`创建一个动态的`<template>`。在这个`<template>`中，我们将添加一个带有`vs-justify`属性定义为`flex-start`的`vs-row`组件，并插入两个`vs-button`组件。第一个是用于取消此操作并返回到用户列表的。它将具有`color`定义为`danger`，`type`定义为`filled`，`icon`定义为`cancel`，`size`定义为`small`的属性，以及`@click`事件监听器目标为`changeComponent`方法，参数为`'list'`和`0`。第二个`vs-button`组件将用于编辑用户，并具有`color`定义为`success`，`type`定义为`filled`，`icon`定义为`save`，`size`定义为`small`，`style`定义为`margin-left: 5px`，以及`@click`事件监听器目标为`changeComponent`方法，参数为`'list'`和注入的`userId`：

```js
<template slot="footer">
 <vs-row vs-justify="flex-start">
 <vs-button
  color="primary"
  type="filled"
  icon="arrow_back"
  size="small"
  style="margin-left: 5px"
  @click="changeComponent('list', 0)"
  >
  Back
    </vs-button>
 <vs-button
  color="success"
  type="filled"
  icon="edit"
  size="small"
  style="margin-left: 5px"
  @click="changeComponent('edit', userId)"
  >
  Edit User
    </vs-button>
 </vs-row> </template>
```

要运行服务器并查看您的组件，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> npm run serve
```

您的组件已呈现并运行：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-cb/img/2c55f576-a545-4245-a55c-163383606213.png)

### 更新用户组件

我们刚刚查看了用户数据，现在我们想要更新它。我们需要制作一个新的组件，几乎与查看组件相同，但具有更新用户的方法并启用表单。

#### 单文件组件`<script>`部分

在这部分，我们将创建单文件组件的`<script>`部分。按照以下说明正确创建组件：

1.  在`src/components`文件夹中创建名为`update.vue`的文件并打开它。

1.  从`fetchApi`中导入`UserForm`组件、`changeComponent` mixin 以及`getHttp`和`patchHttp`函数：

```js
import UserForm from './userForm'; import changeComponent from '../mixin/changeComponent'; import {
  getHttp,
  patchHttp, } from '../http/fetchApi';
```

1.  在`data`属性中，我们将添加一个`userData`对象，其中包含`name`、`email`、`birthday`、`country`和`phone`属性，全部定义为空字符串：

```js
data: () => ({
  userData: {
  name: '',
  email: '',
  birthday: '',
  country: '',
  phone: '',
  }, }),
```

1.  在 Vue 的`mixins`属性中，我们需要添加`changeComponent` mixin：

```js
mixins: [changeComponent],
```

1.  在 Vue 的`inject`属性中，我们需要声明`'userId'`属性：

```js
inject: ['userId'],
```

1.  在 Vue 的`components`属性中，添加`UserForm`组件：

```js
components: {
  UserForm, },
```

1.  对于方法，我们将创建两个：`getUserById`和`updateUser`。`getUserById`方法将通过当前 ID 获取用户数据，并将`userData`值设置为`getHttp`函数执行的响应，而`updateUser`将通过`patchHttp`函数将当前`userDate`发送到服务器，并重定向回用户列表：

```js
methods: {
  async getUserById() {
  const { data } = await 
      getHttp(`${window.location.href}api/users/${this.userId}`);
  this.userData = data;
  },
  async updateUser() {
  await patchHttp
 (`${window.location.href}api/users/${this.userData.id}`, {
  data: {
  ...this.userData,
  }
 });
  this.changeComponent('list', 0);
  }, },
```

1.  在`beforeMount`生命周期钩子上，我们将使其异步化，调用`getUserById`方法：

```js
async beforeMount() {   await this.getUserById(); },
```

#### 单文件组件`<template>`部分

在这部分，我们将创建单文件组件的`<template>`部分。按照以下说明正确创建组件：

1.  创建一个带有`style`属性定义为`margin: 20px`的`vs-card`组件：

```js
<vs-card
  style="margin: 20px;"
  >
</vs-card>
```

1.  在`vs-card`组件内部，为`header`创建一个动态的`<template>`命名插槽，其中包含一个`<h3>`标签和您的标题：

```js
<template slot="header">
 <h3>
  Update User
  </h3> </template>
```

1.  之后，创建一个带有`vs-col`组件的`vs-row`组件，其中`vs-type`属性定义为`flex`，`vs-justify`属性定义为`left`，`vs-align`属性定义为`left`，`vs-w`属性定义为`12`：

```js
<vs-row>
 <vs-col
  vs-type="flex"
  vs-justify="left"
  vs-align="left"
  vs-w="12">
  </vs-col>
</vs-row>
```

1.  在`vs-col`组件内部，我们将添加`UserForm`组件，其中`v-model`指令绑定到`userData`，并将`disabled`属性设置为`true`：

```js
<user-form
  v-model="userData"
  disabled />
```

1.  最后，在卡片页脚中，我们需要为`footer`创建一个动态的`<template>`命名插槽。在`<template>`内，我们将添加一个带有`vs-justify`属性定义为`flex-start`的`vs-row`组件，并插入两个`vs-button`组件。第一个将用于创建用户，并具有`color`定义为`success`，`type`定义为`filled`，`icon`定义为`save`，`size`定义为`small`的属性，并且`@click`事件监听器指向`updateUser`方法。第二个`vs-button`组件将用于取消此操作并返回到用户列表。它将具有`color`定义为`danger`，`type`定义为`filled`，`icon`定义为`cancel`，`size`定义为`small`，`style`定义为`margin-left: 5px`的属性，并且`@click`事件监听器指向`changeComponent`方法，参数为`'list'`和`0`：

```js
<template slot="footer">
 <vs-row vs-justify="flex-start">
 <vs-button
  color="success"
  type="filled"
  icon="save"
  size="small"
  @click="updateUser"
  >
  Update User
    </vs-button>
 <vs-button
  color="danger"
  type="filled"
  icon="cancel"
  size="small"
  style="margin-left: 5px"
  @click="changeComponent('list', 0)"
  >
  Cancel
    </vs-button>
 </vs-row> </template>
```

要运行服务器并查看您的组件，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> npm run serve
```

这是您的组件渲染并运行的情况：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-cb/img/55f3448e-e4c1-46c5-8a37-35eec0f0695e.png)

## 它是如何工作的...

我们创建的 CRUD 接口就像一个路由应用程序，有三个路由，即索引或列表、查看和编辑路由。每个路由都有自己的屏幕和组件，具有分离的逻辑功能。

我们创建了一个抽象的`UserForm`组件，该组件用于`View`和`Update`组件。这个抽象组件可以在许多其他组件中使用，因为它不需要任何基本逻辑来工作；它就像一个由几个输入组成的输入框。

使用 Vue 的 provide/inject API，我们能够以可观察的方式将`userId`传递给每个组件，这意味着当变量更新时，组件会接收到更新后的变量。这是无法通过普通的 Vue API 实现的，因此我们必须使用`Object.defineProperty`并使用`provide`属性作为返回最终对象的工厂函数。

## 另请参阅

您可以在[`lusaxweb.github.io/vuesax/`](https://lusaxweb.github.io/vuesax/)找到有关`Vuesax`的更多信息。

您可以在[`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/defineProperty`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/defineProperty)找到有关`Object.defineProperty`的更多信息。

您可以在[`vuejs.org/v2/guide/components-edge-cases.html`](https://vuejs.org/v2/guide/components-edge-cases.html)找到有关 Vue provide/inject API 的更多信息。
