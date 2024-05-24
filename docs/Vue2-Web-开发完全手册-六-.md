# Vue2 Web 开发完全手册（六）

> 原文：[`zh.annas-archive.org/md5/E8B4B21F7ACD89D5DD2A27CD73B2E070`](https://zh.annas-archive.org/md5/E8B4B21F7ACD89D5DD2A27CD73B2E070)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十四章：Vue 与互联网通信

在本章中，将涵盖以下配方：

+   使用 Axios 发送基本的 AJAX 请求

+   在发送之前验证用户数据

+   创建一个表单并将数据发送到服务器

+   在请求期间从错误中恢复

+   创建 REST 客户端（和服务器！）

+   实现无限滚动

+   在发送请求之前处理请求

+   防止 XSS 攻击到您的应用程序

# 介绍

Web 应用程序很少能够独立运行。使它们变得有趣的实际上是它们使我们能够以几年前不存在的创新方式与世界进行交流。

Vue 本身不包含任何机制或库来发起 AJAX 请求或打开网络套接字。因此，在本章中，我们将探讨 Vue 如何与内置机制和外部库进行交互，以连接到外部服务。

您将首先使用外部库发起基本的 AJAX 请求。然后，您将探索一些在表单中发送和获取数据的常见模式。最后，有一些具有真实应用程序的配方以及如何构建 RESTful 客户端。

# 使用 Axios 发送基本的 AJAX 请求

Axios 是 Vue 推荐的用于发起 HTTP 请求的库。它是一个非常简单的库，但它具有一些内置功能，可以帮助您执行常见操作。它实现了使用 HTTP 动词进行请求的 REST 模式，并且还可以在函数调用中处理并发（同时发起多个请求）。您可以在[`github.com/mzabriskie/axios`](https://github.com/mzabriskie/axios)找到更多信息。

# 准备工作

对于这个配方，您不需要对 Vue 有任何特定的了解。我们将使用 Axios，它本身使用 JavaScript promises。如果您从未听说过 promises，您可以在[`developers.google.com/web/fundamentals/getting-started/primers/promises`](https://developers.google.com/web/fundamentals/getting-started/primers/promises)上了解一些基础知识。

# 如何做...

您将构建一个简单的应用程序，每次访问网页时都会给您一条明智的建议。

您需要做的第一件事是在应用程序中安装 Axios。如果您使用 npm，只需发出以下命令：

```js
    npm install axios
```

如果您正在处理单个页面，您可以从 CDN 导入以下文件，网址为[`unpkg.com/axios/dist/axios.js`](https://unpkg.com/axios/dist/axios.js)。

不幸的是，我们将使用的建议服务在 JSFiddle 上无法工作，因为服务运行在 HTTP 上，而 JSFiddle 在 HTTPS 上，你的浏览器很可能会抱怨。你可以在本地 HTML 文件上运行这个教程。

我们的 HTML 如下所示：

```js
<div id="app"> 
  <h2>Advice of the day</h2> 
  <p>{{advice}}</p> 
</div>
```

我们的 Vue 实例如下：

```js
new Vue({ 
  el: '#app', 
  data: { 
    advice: 'loading...' 
  }, 
  created () { 
    axios.get('http://api.adviceslip.com/advice') 
      .then(response => { 
        this.advice = response.data.slip.advice 
      }) 
      .catch(error => { 
        this.advice = 'There was an error: ' + error.message 
      }) 
  } 
})
```

打开你的应用程序，获得一条令人耳目一新的智慧建议：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/cpl-vue2-web-dev/img/fe5c736a-4340-4b65-be40-c53492e3e2fc.png)

# 它是如何工作的...

当我们的应用程序启动时，创建的钩子被激活，并将使用 Axios 运行代码。第一行执行一个 GET 请求到 API 端点：

```js
axios.get('http://api.adviceslip.com/advice')
```

这将返回一个 promise。我们可以在任何 promise 上使用`then`方法来处理结果，如果 promise 成功解决：

```js
.then(response => { 
  this.advice = response.data.slip.advice 
})
```

响应对象将包含关于我们请求结果的一些数据。一个可能的响应对象如下：

```js
{ 
  "data": { 
    "slip": { 
      "advice": "Repeat people's name when you meet them.", 
      "slip_id": "132" 
    } 
  }, 
  "status": 200, 
  "statusText": "OK", 
  "headers": { 
    "content-type": "text/html; charset=UTF-8", 
    "cache-control": "max-age=0, no-cache" 
  }, 
  "config": { 
    "transformRequest": {}, 
    "transformResponse": {}, 
    "timeout": 0, 
    "xsrfCookieName": "XSRF-TOKEN", 
    "xsrfHeaderName": "X-XSRF-TOKEN", 
    "maxContentLength": -1, 
    "headers": { 
      "Accept": "application/json, text/plain, */*" 
    }, 
    "method": "get", 
    "url": "http://api.adviceslip.com/advice" 
  }, 
  "request": {} 
}
```

我们导航到我们想要交互的属性；在我们的例子中，我们想要`response.data.slip.advice`，这是一个字符串。我们将字符串复制到实例状态中的建议变量中。

最后一部分是当我们的请求或者第一分支内的代码出现问题时：

```js
.catch(error => { 
  this.advice = 'There was an error: ' + error.message 
})
```

我们将在*在请求期间从错误中恢复*的教程中更深入地探讨错误处理。现在，让我们手动触发一个错误，看看会发生什么。

触发错误的最便宜的方法是在 JSFiddle 上运行应用程序。由于浏览器检测到 JSFiddle 是在安全连接上，而我们的 API 是在 HTTP 上（不安全），现代浏览器会抱怨并阻止连接。你应该看到以下文本：

```js
There was an error: Network Error
```

这只是你可以尝试的许多可能错误之一。考虑到你将 GET 端点编辑为一些不存在的页面：

```js
axios.get('http://api.adviceslip.com/non-existent-page')
```

在这种情况下，你会得到一个 404 错误：

```js
There was an error: Request failed with status code 404
```

有趣的是，即使请求顺利进行，但第一分支中出现错误，你最终会进入错误分支。

将`then`分支更改为这样：

```js
.then(response => { 
  this.advice = undefined.hello 
})
```

众所周知，JavaScript 无法读取未定义对象的“hello”属性：

```js
There was an error: Cannot read property 'hello' of undefined
```

就像我告诉你的那样。

# 在发送用户数据之前验证它的有效性

一般来说，用户讨厌表单。虽然我们无法改变这一点，但我们可以通过提供有关如何填写表单的相关说明来减少他们的挫败感。在这个教程中，我们将创建一个表单，并利用 HTML 标准为用户提供如何完成它的良好指导。

# 准备工作

这个教程不需要先前的知识就可以完成。虽然我们将构建一个表单（*使用 Axios 发送基本 AJAX 请求*教程），但我们将伪造 AJAX 调用并集中在验证上。

# 如何做...

我们将构建一个非常简单的表单：一个用于用户名的字段，一个用于用户电子邮件的字段，以及一个用于提交信息的按钮。

在 HTML 中输入：

```js
<div id="app"> 
  <form @submit.prevent="vueSubmit"> 
    <div> 
      <label>Name</label> 
      <input type="text" required> 
    </div> 
    <div> 
      <label>Email</label> 
      <input type="email" required> 
    </div> 
    <div> 
      <label>Submit</label> 
      <button type="submit">Submit</button> 
    </div> 
  </form> 
</div>
```

Vue 实例很简单，如下所示：

```js
new Vue({ 
  el: '#app', 
  methods: { 
    vueSubmit() { 
      console.info('fake AJAX request') 
    } 
  } 
})
```

运行这个应用程序，尝试提交一个空字段或错误的电子邮件。您应该会看到浏览器本身的帮助：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/cpl-vue2-web-dev/img/89b2c210-31e6-4a6e-b06e-fb5fab39ee29.png)

然后，如果您尝试输入一个无效的电子邮件地址，您将看到以下内容：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/cpl-vue2-web-dev/img/9ae50ef5-524f-432f-82e4-1735525a8179.png)

# 它是如何工作的...

我们正在使用原生的 HTML5 验证 API，它在内部使用模式匹配来检查我们输入的内容是否符合某些规则。

考虑以下行中的 required 属性：

```js
<input type="text" required>
```

这样可以确保当我们提交表单时，字段实际上是填充的，而在另一个输入元素中使用`type="email"`可以确保内容类似于电子邮件格式。

这个 API 非常丰富，您可以在[`developer.mozilla.org/en-US/docs/Web/Guide/HTML/Forms/Data_form_validation`](https://developer.mozilla.org/en-US/docs/Web/Guide/HTML/Forms/Data_form_validation)上阅读更多。

很多时候，问题在于要利用这个 API，我们需要触发原生验证机制。这意味着我们不能阻止提交按钮的默认行为：

```js
<button type="submit" @click.prevent="vueSubmit">Submit</button>
```

这不会触发原生验证，表单将始终被提交。另一方面，如果我们这样做：

```js
<button type="submit" @click="vueSubmit">Submit</button>
```

表单将被验证，但由于我们没有阻止提交按钮的默认行为，表单将被发送到另一个页面，这将破坏单页面应用程序的体验。

诀窍是在表单级别拦截提交：

```js
<form @submit.prevent="vueSubmit">
```

这样，我们可以拥有表单的原生验证和我们真正喜欢的现代浏览体验。

# 创建一个表单并将数据发送到您的服务器

HTML 表单是与用户交互的标准方式。您可以收集他们的数据以在网站内注册，让他们登录，甚至进行更高级的交互。在这个教程中，您将使用 Vue 构建您的第一个表单。

# 准备工作

这个教程非常简单，但它假设您已经了解 AJAX，并且希望将您的知识应用到 Vue 上。

# 如何做...

假设我们有一个博客，并且我们想写一篇新文章。为此，我们需要一个表单。以下是 HTML 的布局方式：

```js
<div id="app"> 
  <h3>Write a new post</h3> 
  <form> 
    <div> 
      <label>Title of your post:</label> 
      <input type="text" v-model="title"> 
    </div> 
    <div> 
      <label>Write your thoughts for the day</label> 
      <textarea v-model="body"></textarea> 
    </div> 
    <div> 
      <button @click.prevent="submit">Submit</button> 
    </div> 
  </form> 
</div>
```

我们有一个用于标题的框，一个用于我们新帖子的正文的框，以及一个发送我们的帖子的按钮。

在我们的 Vue 实例中，这三个东西以及用户 ID 将成为应用程序状态的一部分：

```js
new Vue({ 
  el: '#app', 
  data: { 
    userId: 1, 
    title: '', 
    body: '' 
  } 
})
```

在这一点上，我们只需要在单击“提交”按钮时向服务器发送数据的方法。由于我们没有服务器，我们将使用**Typicode**提供的非常有用的服务。它基本上是一个虚假的 REST 服务器。我们将发送一个请求，服务器将以真实的方式做出响应，即使实际上什么都不会发生。

这是我们的方法：

```js
methods: { 
  submit () { 
    const xhr = new XMLHttpRequest() 
    xhr.open('post', 'https://jsonplaceholder.typicode.com/posts') 
    xhr.setRequestHeader('Content-Type',  
                         'application/json;charset=UTF-8') 
    xhr.onreadystatechange = () => { 
    const DONE = 4 
    const CREATED = 201 
    if (xhr.readyState === DONE) { 
      if (xhr.status === CREATED) { 
          this.response = xhr.response 
        } else { 
          this.response = 'Error: ' + xhr.status 
        } 
      } 
    } 
    xhr.send(JSON.stringify({ 
      title: this.title, 
      body: this.body, 
      userId: this.userId 
    })) 
  } 
}
```

为了查看服务器的实际响应，我们将把响应变量添加到我们的状态中：

```js
data: { 
  userId: 1, 
  title: '', 
  body: '', 
 response: '...' 
}
```

在我们的 HTML 表单之后，添加以下内容：

```js
<h3>Response from the server</h3> 
<pre>{{response}}</pre>
```

当您启动页面时，您应该能够与服务器进行交互。当您写一篇文章时，服务器将回显该文章并回复帖子 ID：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/cpl-vue2-web-dev/img/5b07cbb9-8885-48fa-b2f3-e2722be8aa0b.png)

# 它是如何工作的...

大部分魔法发生在`submit`方法中。在第一行，我们创建了一个`XMLHttpRequest`对象，这是一个用于发出 AJAX 请求的本机 JavaScript 机制：

```js
const xhr = new XMLHttpRequest()
```

然后我们使用`open`和`setRequestHeader`方法来配置一个新的连接；我们要发送一个 POST 请求，并且我们将随之发送一些 JSON：

```js
xhr.open('post', 'http://jsonplaceholder.typicode.com/posts') 
xhr.setRequestHeader('Content-Type', 'application/json;charset=UTF-8')
```

由于我们正在与 RESTful 接口交互，POST 方法意味着我们期望我们的请求修改服务器上的数据（特别是创建一个新的帖子），并且多次发出相同的请求将每次都得到不同的结果（换句话说，我们将创建一个新的、不同的帖子 ID）。

这与更常见的 GET 请求不同，后者不会修改服务器上的数据（除了可能的日志），并且始终会产生相同的结果（假设服务器上的数据在请求之间没有发生变化）。

有关 REST 的更多细节，请查看*创建 REST 客户端（和服务器！）*的内容。

接下来的几行都是关于响应的：

```js
xhr.onreadystatechange = () => { 
  const DONE = 4 
  const CREATED = 201 
  if (xhr.readyState === DONE) { 
    if (xhr.status === CREATED) { 
      this.response = xhr.response 
    } else { 
      this.response = 'Error: ' + xhr.status 
    } 
  } 
}
```

这将在我们的对象发生某种变化时安装一个处理程序。如果`readyState`变为`DONE`，这意味着我们从服务器得到了响应。接下来，我们检查状态码，应该是`201`，表示已创建了一个新资源（我们的新帖子）。如果是这种情况，我们设置放在双大括号中的变量以获得快速反馈。否则，我们将接收到的错误消息放入同一个变量中。

在设置事件处理程序之后，我们需要做的最后一件事是实际发送请求以及我们新帖子的数据：

```js
xhr.send(JSON.stringify({ 
  title: this.title, 
  body: this.body, 
  userId: this.userId 
}))
```

# 更多内容...

另一种解决相同问题的方法是使用 Axios 发送 AJAX 请求。如果你需要了解 Axios 是什么，可以看一下*使用 Axios 发送基本的 AJAX 请求*这个教程。

`submit`方法的代码将变成如下（记得将 Axios 添加为依赖项）：

```js
submit () { 
  axios.post('http://jsonplaceholder.typicode.com/posts', { 
    title: this.title, 
    body: this.body, 
    userId: this.userId 
  }).then(response => { 
    this.response = JSON.stringify(response,null,'  ') 
  }).catch(error => { 
    this.response = 'Error: ' + error.response.status 
  }) 
}
```

这段代码完全等效，但比使用原生浏览器对象更具表现力和简洁。

# 在请求期间从错误中恢复

从计算机的角度来看，对外部服务的请求需要很长时间。从人类的角度来看，就像是把卫星送到木星，然后等待它返回地球。你无法百分之百确定旅行是否会完成，以及旅行实际需要多长时间。网络经常不稳定，最好提前做好准备，以防我们的请求无法成功完成。

# 准备工作

这个教程有点复杂，但并不使用高级概念。然而，你应该熟悉使用 Vue。

我们将在这个教程中使用 Axios。如果你不确定它具体包含什么，可以完成*使用 Axios 发送基本的 AJAX 请求*这个教程。

# 操作步骤

你将为在珠穆朗玛峰上订购比萨的网站建立一个网站。该地区的互联网连接非常差，所以在放弃我们的比萨之前，我们可能需要重试几次。

这是我们的 HTML 代码：

```js
<div id="app"> 
  <h3>Everest pizza delivery</h3> 
  <button @click="order"  
          :disabled="inProgress">Order pizza!</button> 
  <span class="spinner" v-show="inProgress"></span> 
  <h4>Pizza wanted</h4> 
  <p>{{requests}}</p> 
  <h4>Pizzas ordered</h4> 
  <span v-for="pizza in responses"> 
    {{pizza.id}}:{{pizza.req}} 
  </span> 
</div>
```

我们有一个用于下订单的按钮，当订单正在进行时会被禁用--一个正在进行中的订单列表（目前只包含一个订单）和一个已经订购的比萨列表。

我们可以添加一个旋转的小比萨饼来让等待变得更愉快。添加这个 CSS 来让小比萨饼旋转：

```js
@keyframes spin { 
  100% {transform:rotate(360deg);} 
} 
.spinner { 
  width: 1em; 
  height: 1em; 
  padding-bottom: 12px; 
  display: inline-block; 
  animation: spin 2s linear infinite; 
}
```

我们的 Vue 实例将跟踪一些东西；写下这段代码来开始构建实例：

```js
new Vue({ 
  el: '#app', 
  data: { 
    inProgress: false, 
    requests: new Object(null), 
    responses: new Object(null), 
    counter: 0, 
    impatientAxios: undefined 
  } 
})
```

我想要使用 JavaScript 集来处理请求和响应；不幸的是，在 Vue 中，集合不是响应式的；我们可以使用的最接近的东西是一个对象，目前是空的，也就是说，我们正在将请求和响应初始化为空对象。

`impatientAxios`变量将在创建时填充。通常，Axios 会等待浏览器等待响应的时间。由于我们心急，我们将创建一个在 3 秒后断开连接的 Axios：

```js
created () { 
  this.impatientAxios = axios.create({ 
    timeout: 3000  
  }) 
}
```

我们需要构建的最后一件事是订单方法。由于我们没有一个用于实际请求的网络服务器，我们将使用 `http://httpstat.us/200` 端点，它对我们所有的请求都简单地回答 200 OK：

```js
methods: { 
  order (event, oldRequest) { 
    let request = undefined 
    if (oldRequest) { 
      request = oldRequest 
    } else { 
      request = { req: '', id: this.counter++} 
   } 
   this.inProgress = true 
   this.requests[request.id] = request 
   this.impatientAxios.get('http://httpstat.us/200') 
    .then(response => { 
      this.inProgress = false 
      this.responses[request.id] = this.requests[request.id] 
      delete this.requests[request.id] 
    }) 
    .catch(e => { 
      this.inProgress = false 
      console.error(e.message) 
      console.error(this.requests.s) 
      setTimeout(this.order(event, request), 1000) 
    }) 
}
```

为了按预期运行这个程序，用 Chrome 打开它，并用*Cmd* + *Opt* + *I*（在 Windows 上是*F12*）打开开发者工具：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/cpl-vue2-web-dev/img/a50f7cc7-aa6e-41f7-aaed-00600cf52c1f.png)

切换到网络选项卡，并打开下拉菜单，你会看到没有节流：

**![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/cpl-vue2-web-dev/img/3839d7cb-8319-4cd7-9198-0ffe81506b27.png)**

点击它以显示下拉菜单：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/cpl-vue2-web-dev/img/a76b0d43-9f47-45e6-a471-83e2750189b0.png)

添加一个名为`Everest`的新自定义节流，下载和上传速度为`1kb/s`，延迟为`1,000`毫秒，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/cpl-vue2-web-dev/img/4a15fc97-768d-4c46-851b-ed6661401e52.png)

然后你可以选择那种类型的节流并尝试订购一些披萨。如果你幸运的话，你最终应该能够订购一些，这要归功于 Axios 的持久性。

如果你没有成功或者你的所有披萨都被正确地订购了，尝试调整参数；这个过程中很大一部分实际上是随机的，而且高度依赖于机器。

# 它是如何工作的...

有许多处理不稳定连接的方法，也有许多与 Axios 集成并具有更高级重试和重试策略的库。在这里，我们只看到了一种基本策略，但是像**Patience JS**这样的库有更高级的策略，它们并不难使用。

# 创建一个 REST 客户端（和服务器！）

在这个教程中，我们将学习关于 REST 以及如何构建 REST 客户端。要构建一个 REST 客户端，我们需要一个暴露 REST 接口的服务器；我们也将构建它。等一下！在一本关于 Vue 的书中，一个完整的 REST 服务器只是一个附注？只要跟着做，你就不会失望。

# 准备工作

这个示例在某种意义上相当高级，您需要熟悉客户端和服务器的架构，并且至少听说过或阅读过 REST 接口。您还需要熟悉命令行并安装 npm。您可以在*选择开发环境*示例中了解所有相关信息。

还需要安装 Axios；在本章的第一个示例中可以了解更多信息。

# 如何做...

我还记得几年前，构建 REST 服务器可能需要花费几天甚至几周的时间。您可以使用`Feather.js`，它将快速且（希望是）无痛的。打开命令行并使用以下命令通过 npm 安装它：

```js
    npm install -g feathers-cli
```

之后，创建一个目录，在其中运行服务器，然后进入该目录并启动 Feathers：

```js
    mkdir my-server
    cd my-server
    feathers generate app
```

将所有问题的答案都设置为默认值。当进程完成时，键入以下命令以创建新资源：

```js
 feathers generate service
```

其中一个问题是资源的名称；将其命名为`messages`，但除此之外，其他问题都使用默认值。

使用`exit`命令退出 feathers-cli，并使用以下命令启动新服务器：

```js
    npm start
```

几秒钟后，您的 REST 服务器应该已启动，并且应该正在端口`3030`上进行监听。你能诚实地说这很困难吗？

上述命令序列适用于 Feathers 版本 2.0.0

您可能正在使用另一个版本，但是使用后续版本仍然很容易获得相同的结果；请查看[`feathersjs.com/`](https://feathersjs.com/)上的在线安装指南。

接下来，您将构建一个与服务器无缝通信的 Vue 应用程序。现在，由于服务器通过 HTTP 在本地环境中运行，您将无法使用 JSFiddle，因为它在 HTTPS 上运行，并认为 HTTP 是不安全的。您可以使用之前描述的其他方法，或者使用 HTTP 上的服务，例如[codepen.io](http://codepen.io)或其他服务。

您将编写一个管理便签消息的应用程序。我们希望能够查看、添加、编辑和删除它们。

在 HTML 中键入以下内容：

```js
<div id="app"> 
  <h3>Sticky messages</h3> 
  <ol> 
    <li v-for="message in messages"> 
      <button @click="deleteItem(message._id)">Delete</button> 
      <button @click="edit(message._id, message.text)"> 
        edit 
      </button> 
      <input v-model="message.text"> 
    </li> 
  </ol> 
  <input v-model="toAdd"> 
  <button @click="add">add</button> 
</div>
```

我们的 Vue 实例状态将包括一系列记录的消息，以及要添加到列表中的临时消息：

```js
new Vue({ 
  el: '#app', 
  data: { 
    messages: [], 
    toAdd: '' 
  }, 
})
```

我们要做的第一件事是向服务器请求消息列表。为此编写创建的钩子：

```js
created () { 
  axios.get('http://localhost:3030/messages/') 
    .then(response => { 
      this.messages = response.data.data 
    }) 
},
```

要创建新消息，请编写一个绑定到添加按钮的点击事件的方法，并将输入框中的内容发送到服务器：

```js
methods: { 
  add () { 
    axios.post('http://localhost:3030/messages/', { 
      text: this.toAdd 
    }) 
      .then(response => { 
        if (response.status === 201) { 
          this.messages.push(response.data) 
          this.toAdd = '' 
        } 
      }) 
  } 
}
```

同样，编写一个用于删除消息和编辑消息的方法：

```js
deleteItem (id) { 
  console.log('delete') 
  axios.delete('http://localhost:3030/messages/' + id) 
    .then(response => { 
      if (response.status < 400) { 
        this.messages.splice( 
          this.messages.findIndex(e => e.id === id), 1) 
      } 
    }) 
}, 
edit (id, text) { 
  axios.put('http://localhost:3030/messages/' + id, { 
    text 
  }) 
    .then(response => { 
      if (response.status < 400) { 
        console.info(response.status) 
      } 
    }) 
}
```

启动你的应用程序，你将能够管理你的便利贴消息板：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/cpl-vue2-web-dev/img/99b328f2-4364-4d96-8c9d-26d0accb2dc6.png)

为了证明你确实在与服务器通信，你可以刷新页面，或者关闭并重新打开浏览器，你的笔记仍然会在那里。

# 它是如何工作的...

**REST**意味着**REpresentational State Transfer**，也就是说你将传输某个资源状态的表示。在实践中，我们使用一组**动词**来传输我们消息状态的表示。

使用 HTTP 协议，我们可以使用以下动词：

| **动词** | **属性** | **描述** |
| --- | --- | --- |
| `GET` | 幂等，安全 | 用于检索资源的表示 |
| `POST` |  | 用于上传新资源 |
| `PUT` | 幂等 | 用于上传现有资源（修改它） |
| `DELETE` | 幂等 | 用于删除资源 |

幂等意味着如果我们两次使用相同的动词，资源不会发生任何变化，而安全意味着根本不会发生任何变化。

在我们的应用程序中，我们只在创建时使用 GET 动词。当我们看到列表因其他操作而改变时，那只是因为我们在前端上反映了服务器上的操作。

POST 动词用于向列表中添加新消息。请注意，它不是幂等的，因为即使在便利贴消息中使用相同的文本，我们仍然会在按下添加按钮时创建一个 ID 不同的新消息。

按下编辑按钮会触发 PUT，而删除按钮，嗯，你可以想象它使用了 DELETE 动词。

Axios 通过使用动词本身来命名其 API 的方法，使其非常清晰。

# 实现无限滚动

无限滚动是使用 Vue 和 AJAX 的一个很好的例子。它也非常受欢迎，可以改善某些类型内容的交互。你将构建一个可以使用无限滚动的随机单词生成器。

# 准备工作

我们将使用 Axios。查看*使用 Axios 发送基本 AJAX 请求*的示例，了解如何安装它及其基本功能。除此之外，你不需要了解太多就可以跟着做。

# 如何做...

为了使我们的应用程序工作，我们将从[`www.setgetgo.com/randomword/get.php`](http://www.setgetgo.com/randomword/get.php)端点请求随机单词。每次你将浏览器指向这个地址，你都会得到一个随机单词。

整个页面将仅由无限单词列表组成。编写以下 HTML：

```js
<div id="app"> 
  <p v-for="word in words">{{word}}</p> 
</div>
```

随着页面向下滚动，单词列表需要增长。所以我们需要两件事：了解用户何时到达页面底部，以及获取新单词。

要知道用户何时到达页面底部，我们在 Vue 实例中添加一个方法：

```js
new Vue({ 
  el: '#app', 
  methods: { 
    bottomVisible () { 
      const visibleHeight = document.documentElement.clientHeight 
      const pageHeight = document.documentElement.scrollHeight 
      const scrolled = window.scrollY 
      const reachedBottom = visibleHeight + scrolled >= pageHeight 
      return reachedBottom || pageHeight < visibleHeight 
    } 
  } 
})
```

如果页面滚动到底部，或者页面本身比浏览器小，这将返回`true`。

接下来，我们需要添加一个机制，将这个函数的结果绑定到一个状态变量`bottom`，并在用户滚动页面时更新它。我们可以在`created`钩子中做到这一点：

```js
created () { 
  window.addEventListener('scroll', () => { 
    this.bottom = this.bottomVisible() 
  }) 
}
```

状态将由`bottom`变量和随机单词列表组成：

```js
data: { 
  bottom: false, 
  words: [] 
}
```

现在我们需要一个方法来向数组中添加单词。将以下方法添加到现有方法中：

```js
addWord () { 
  axios.get('http://www.setgetgo.com/randomword/get.php') 
    .then(response => { 
      this.words.push(response.data) 
      if (this.bottomVisible()) { 
        this.addWord() 
      } 
    }) 
}
```

该方法将递归调用自身，直到页面有足够的单词填满整个浏览器视图。

由于这个方法需要在每次到达底部时被调用，我们将监视底部变量，并在其为`true`时触发该方法。在`data`之后的 Vue 实例中添加以下选项：

```js
watch: { 
  bottom (bottom) { 
    if (bottom) { 
      this.addWord() 
    } 
  } 
}
```

我们还需要在`created`钩子中调用`addWord`方法来启动页面：

```js
created () { 
  window.addEventListener('scroll', () => { 
    this.bottom = this.bottomVisible() 
  }) 
 this.addWord() 
}
```

如果现在启动页面，你将得到一个无限流的随机单词，这在你需要创建新密码时很有用！

# 工作原理…

在这个教程中，我们使用了一个叫做`watch`的选项，它使用以下语法：

```js
watch: { 
 'name of sate variable' (newValue, oldValue) { 
   ... 
  } 
}
```

这是计算属性的对应物，当我们对一些响应式变量的变化后不感兴趣。事实上，我们只是用它来触发另一个方法。如果我们对一些计算结果感兴趣，我们会使用计算属性。

# 在发送请求之前处理请求

这个教程教你如何使用拦截器在请求发送到互联网之前编辑请求。在某些情况下，这可能很有用，比如当你需要在所有请求到服务器时提供授权令牌，或者当你需要一个单一点来编辑 API 调用的执行方式时。

# 准备工作

这个教程使用了 Axios（*使用 Axios 发送基本 AJAX 请求*教程）；除此之外，最好已经完成了*在发送数据之前如何验证用户数据*教程，因为我们将构建一个小型表单进行演示。

# 如何做...

在这个教程中，您将为一个假设的评论系统构建一个脏话过滤器。假设我们网站上有一篇文章可能会引发争论：

```js
<div id="app"> 
  <h3>Who's better: Socrates or Plato?</h3> 
  <p>Technically, without Plato we wouldn't have<br> 
  much to go on when it comes to information about<br> 
  Socrates. Plato ftw!</p>
```

在那篇文章之后，我们放置了一个评论框：

```js
  <form> 
    <label>Write your comment:</label> 
    <textarea v-model="message"></textarea> 
    <button @click.prevent="submit">Send!</button> 
  </form> 
  <p>Server got: {{response}}</p> 
</div>
```

我们还在表单后面添加了一行来调试我们将从服务器获取的响应。

在我们的 Vue 实例中，我们编写所有支持代码将评论发送到我们的服务器，这种情况下，将是[`jsonplaceholder.typicode.com/comments`](http://www.setgetgo.com/randomword/get.php)，一个假的 REST 接口，将表现得像一个真正的服务器。

这是由按下提交按钮触发的 submit 方法：

```js
methods: { 
  submit () { 
    axios.post('http://jsonplaceholder.typicode.com/comments', 
    { 
      body: this.message 
    }).then(response => { 
      this.response = response.data 
    }) 
  } 
}
```

Vue 实例的状态将只有两个变量：

```js
data: { 
  message: '', 
  response: '...' 
}
```

像往常一样，我们希望将其挂载到`<div>`应用程序中：

```js
new Vue({ 
  el: '#app', 
...
```

一旦实例被挂载，我们希望在 Axios 中安装单词过滤器；为此，我们利用 Vue 的`mounted`钩子：

```js
mounted () { 
  axios.interceptors.request.use(config => { 
    const body = config.data.body.replace(/punk/i, '***') 
    config.data.body = body 
    return config 
  }) 
}
```

现在我们可以启动我们的应用程序并尝试写我们的脏话评论：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/cpl-vue2-web-dev/img/fbf91399-45a4-41e4-88dc-20fe51bfabed.png)

# 它是如何工作的...

在`mounted`钩子中，我们正在安装所谓的`拦截器`。特别是一个请求拦截器，这意味着它将获取我们的请求并在发送到互联网之前对其进行操作：

```js
axios.interceptors.request.use(config => { 
  const body = config.data.body.replace(/punk/i, '***') 
  config.data.body = body 
  return config 
})
```

`config`对象包含许多我们可以编辑的内容。它包含头部和 URL 参数。它还包含 Axios 配置变量。您可以查看 Axios 文档以获取最新列表。

我们正在获取随 POST 请求发送的数据部分，并检查是否存在`punk`这个词。如果是这样，它将被替换为星号。返回的对象将成为当前请求的新配置。

# 防止 XSS 攻击到您的应用程序

在没有考虑安全性的情况下编写应用程序将不可避免地导致漏洞，特别是如果它必须在 Web 服务器上运行。**跨站脚本**（**XSS**）是当今最流行的安全问题之一；即使您不是安全专家，您也应该了解它的工作原理以及如何在 Vue 应用程序中防止它。

# 准备工作

这个步骤不需要任何先前的知识，只需要了解 Axios。您可以在*使用 Axios 发送基本的 AJAX 请求*中找到更多关于 Axios 以及如何安装它的信息。

# 如何做...

您应该首先发现后端是如何给您 CSRF 令牌的（在下一段中会详细介绍）。我们假设服务器会在您的浏览器中放置一个名为 XSRF-TOKEN 的 cookie。

您可以模拟您的服务器，在浏览器控制台中使用`document.cookie = 'XSRF-TOKEN=abc123'`命令设置一个 cookie（在开发者工具中）。

Axios 会自动读取这样的 cookie，并在下一次请求中传输它。

考虑到我们在代码中调用了一个 Axios 的`get`请求，如下所示：

```js
methods: { 
  sendAllMoney () { 
    axios.get('/sendTo/'+this.accountNo) 
  } 
}
```

Axios 会获取该 cookie，并在请求中添加一个名为 X-XSRF-TOKEN 的新标头。您可以通过在 Chrome 的开发者工具的网络选项卡中点击请求的名称来查看这样的标头：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/cpl-vue2-web-dev/img/ccef71e0-e9d4-4a34-af67-ad1bd4625699.png)

# 它是如何工作的...

为了防止 XSS 攻击，您必须确保没有用户输入会出现在您的应用程序中。这意味着您必须非常小心地使用`v-html`属性（*输出原始 HTML*的方法）。

不幸的是，您无法控制页面外发生的事情。如果您的用户之一收到了包含与您的应用程序中的操作相对应的链接的虚假电子邮件，那么点击邮件中的链接将触发该操作。

让我们举个具体的例子；您开发了一个银行应用*VueBank*，您的应用用户收到了以下虚假电子邮件：

```js
Hello user!
Click here to read the latest news.
```

正如您所看到的，这封邮件甚至与我们的应用无关，`here`超链接被隐藏在邮件本身的 HTML 中。实际上，它指向`http://vuebank.com?give_all_my_money_to_account=754839534`地址。

如果我们已经登录了 VueBank，那么链接可能会立即生效。这对我们的财务状况不利。

为了防止这类攻击，我们应该让后端为我们生成一个**CSRF**（**跨站点请求伪造**）令牌。我们将获取该令牌并将其发送到请求中，以证明该请求是由用户发起的。前面的链接将变成

`http://vuebank.com?give_all_my_money_to_account=754839534&csrf=s83Rnj`。

由于令牌每次都是随机生成的，所以邮件中的链接无法被正确伪造，因为攻击者不知道服务器给网页的令牌。

在 Vue 中，我们使用 Axios 来发送令牌。通常，我们不会将其作为链接的一部分发送，而是作为请求的标头；实际上，Axios 会为我们执行此操作，并在下一个请求中自动放入令牌。

您可以通过设置`axios.defaults.xsrfCookieName`变量来更改 Axios 将拾取的 cookie 的名称，并且您可以通过编辑`axios.defaults.xsrfHeaderName`变量来更改将返回令牌的标头的名称。


# 第十五章：单页面应用程序

在本章中，将涵盖以下内容：

+   使用 vue-router 创建 SPA

+   在切换路由之前获取数据

+   使用命名动态路由

+   在页面中有多个 router-view

+   按层次结构组合您的路由

+   使用路由别名

+   在您的路由之间添加过渡

+   管理路由的错误

+   为加载页面添加进度条

+   如何重定向到另一个路由

+   在点击返回时保存滚动位置

# 介绍

许多现代应用程序都基于 SPA 或单页面应用程序模型。从用户的角度来看，这意味着整个网站看起来类似于单个页面中的应用程序。

这很好，因为如果做得正确，它会增强用户体验，主要是减少等待时间，因为没有新页面需要加载-整个网站都在一个页面上。这就是 Facebook、Medium、Google 和许多其他网站的工作方式。

URL 不再指向 HTML 页面，而是指向应用程序的特定状态（通常看起来像不同的页面）。在实践中，在服务器上，假设您的应用程序位于`index.html`页面内，这是通过将请求“关于我”的用户重定向到`index.html`来实现的。

后一页将采用 URL 的后缀，并将其解释为路由，从而创建一个类似页面的具有传记信息的组件。

# 使用 vue-router 创建 SPA

Vue.js 通过其核心插件 vue-router 实现了 SPA 模式。对于 vue-router，每个路由 URL 对应一个组件。这意味着我们将告诉 vue-router 当用户转到特定 URL 时如何行为，以其组件为基础。换句话说，在这个新系统中，每个组件都是旧系统中的一个页面。

# 准备工作

对于这个配方，您只需要安装 vue-router 并对 Vue 组件有一些了解。

要安装 vue-router，请按照[`router.vuejs.org/en/installation.html`](https://router.vuejs.org/en/installation.html)上的说明进行操作。

如果您正在使用 JSFiddle 进行跟踪，您可以添加类似于[`unpkg.com/vue-router/dist/vue-router.js`](https://unpkg.com/vue-router/dist/vue-router.js)的链接。

# 如何做…

我们正在为一家餐厅准备一个现代网站，并且将使用 SPA 模式。

网站将包括三个页面：主页、餐厅菜单和酒吧菜单。

整个 HTML 代码将如下所示：

```js
<div id="app">
  <h1>Choppy's Restaurant</h1>
  <ul>
    <li>Home</li>
    <li>Menu</li>
    <li>Bar</li>
  </ul>
  <router-view></router-view>
</div>
```

`<router-view>`组件是 vue-router 的入口点。它是组件显示为页面的地方。

列表元素将成为链接。目前，它们只是列表元素；要将它们转换为链接，我们可以使用两种不同的语法。将第一个链接包装如下行：

```js
<li><router-link to="/">Home</router-link></li>
```

另一个例子如下：

```js
<li><router-link to="/menu">Menu</router-link></li>
```

我们还可以使用另一种语法（用于“Bar”链接）：

```js
<li>
  <router-link
    tag="li" to="/bar"
      :event="['mousedown', 'touchstart']"
    >
    <a>Bar</a>
  </router-link>
</li>
```

这种更冗长但更明确的语法可以用来将自定义事件绑定到特定路由。

为了告诉 Vue 我们要使用 vue-router 插件，在 JavaScript 中写入以下内容：

```js
Vue.use(VueRouter)
```

我们在开头列出的三个页面部分将由这三个虚拟组件扮演（将它们添加到 JavaScript 中）：

```js
const Home = { template: '<div>Welcome to Choppy's</div>' }
const Menu = { template: '<div>Today we have cookies</div>' }
const Bar = { template: '<div>We serve cocktails</div>' }
```

现在，您可以创建路由器了。代码如下：

```js
const router = new VueRouter({})
```

这个路由器并没有做太多事情；我们需要添加路由（对应 URL）和它们关联的组件：

```js
const router = new VueRouter({
 routes: [ { path: '/', component: Home }, { path: '/menu', component: Menu }, { path: '/bar', component: Bar } ] })
```

现在我们的应用几乎完成了；我们只需要声明一个简单的`Vue`实例：

```js
new Vue({
  router,
  el: '#app'
})
```

我们的应用现在可以工作了；在启动之前，添加这个 CSS 规则以获得稍微更好的反馈：

```js
a.router-link-active, li.router-link-active>a {
  background-color: gainsboro;
}
```

打开应用并点击“Bar”链接时，您应该看到类似以下截图的内容：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/cpl-vue2-web-dev/img/e1fdef9d-2456-47b0-8705-4410c01ad31e.png)

# 工作原理…

您的程序的第一步是将 vue-router 注册为插件。而 vue-router 则注册路由（URL 的一部分）并将组件连接到每个路由。

当我们第一次访问应用程序时，浏览器的 URL（您无法在 JSFiddle 内部看到它在变化，因为它在一个 iframe 内部）将以`index.html/#/`结尾。井号后面的所有内容都是 vue-router 的路由。在这种情况下，它只是一个斜杠（`/`），因此匹配第一个主页路由。

当我们点击链接时，`<router-view>`的内容会根据我们与该路由关联的组件而改变。

# 还有更多…

敏锐的读者肯定会发现可以解释为错误的地方——在运行应用程序之前，我们添加了一些 CSS 样式。每当页面对应于实际指向的链接时，`.router-link-active`类会自动注入到`<router-link>`组件中。

当我们点击“菜单和栏”时，背景颜色会改变，但似乎仍然被选中为主页链接。这是因为`<router-link>`组件执行的匹配不是**精确**的。换句话说，`/bar`和`/menu`包含`/`字符串，因此`/`总是匹配。

一个快速的解决方法是添加属性，与第一个`<router-link>`完全相同：

```js
<li><router-link to="/" exact>Home</router-link></li>
```

现在，只有当路由完全匹配主页链接时，“主页”链接才会被突出显示。

另一个需要注意的事情是规则本身：

```js
a.router-link-active, li.router-link-active>a {
  background-color: gainsboro;
}
```

为什么我们匹配两个不同的东西？这取决于你如何编写路由链接。

```js
<li><router-link to="/" exact>Home</router-link></li>
```

上述代码将被翻译成以下 DOM 部分：

```js
<li><a href="#/" class="router-link-active">Home</a></li>
```

而：

```js
<router-link tag="li" to="/" exact>Home</router-link>
```

变成：

```js
<li class="router-link-active">Home</li>
```

请注意，在第一种情况下，类被应用到子锚点元素；在第二种情况下，它被应用到父元素。

# 在切换路由之前获取数据

在 Vue 的上一个版本中，我们有一个专门的方法从互联网获取数据，然后再改变路由。在 Vue 2 中，我们有一个更通用的方法，它将在切换路由之前处理这个问题，可能还有其他事情。

# 准备工作

要完成这个教程，你应该已经了解了 vue-router 的基础知识以及如何进行 AJAX 请求（更多内容请参见最后一章）。

# 操作步骤…

我们将编写一个简单的网页作品集，由两个页面组成：主页和关于我页面。

对于这个教程，我们需要将 Axios 作为一个依赖项添加进去。

基本布局从以下 HTML 代码中清晰可见：

```js
<div id="app">
  <h1>My Portfolio</h1>
  <ul>
    <li><router-link to="/" exact>Home</router-link></li>
    <li><router-link to="/aboutme">About Me</router-link></li>
  </ul>
  <router-view></router-view>
</div>
```

在 JavaScript 中，你可以开始构建你的`AboutMe`组件：

```js
const AboutMe = {
  template: `<div>Name:{{name}}<br>Phone:{{phone}}</div>`
}
```

它将只显示一个姓名和一个电话号码。让我们在组件的`data`选项中声明这两个变量，如下所示：

```js
data () {
  return {
    name: undefined,
    phone: undefined  
  } 
}
```

在实际加载组件到场景之前，vue-router 将在我们的对象中查找一个名为`beforeRouteEnter`的选项；我们将使用这个选项从服务器加载姓名和电话。我们使用的服务器将提供一些虚假数据，仅用于显示一些内容，如下所示：

```js
beforeRouteEnter (to, from, next) {
  axios.post('https://schematic-ipsum.herokuapp.com/', {
    "type": "object",
    "properties": {
      "name": {
        "type": "string",
        "ipsum": "name"
      },
      "phone": {
        type": "string",
        "format": "phone"
      }
    }
  }).then(response => {
    next(vm => {
      vm.name = response.data.name
      vm.phone = response.data.phone 
    })
  })
}
```

对于另一个组件，主页，我们将只写一个小组件作为占位符：

```js
const Home = { template: '<div>This is my home page</div>' }
```

接下来你需要注册`router`和它的`paths`：

```js
Vue.use(VueRouter)
const router = new VueRouter({
  routes: [
    { path: '/', component: Home },
    { path: '/aboutme', component: AboutMe },  
  ] 
})
```

当然，你还需要注册一个`Vue`根实例，如下所示：

```js
new Vue({
  router,
  el: '#app'
})
```

当你启动应用程序并点击“关于我”链接时，你应该看到类似于这样的东西：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/cpl-vue2-web-dev/img/76e77669-45d2-4132-872c-e4c14814092f.png)

您会注意到当您点击链接时页面不会重新加载，但显示生物信息仍然需要一些时间。这是因为它正在从互联网获取数据。

# 它是如何工作的…

`beforeRouteEnter`钩子接受三个参数：

+   `to`：这是一个代表用户请求的路由的`Route`对象。

+   from：这也是一个代表当前路由的`Route`对象。这是用户在出现错误时将保留在的路由。

+   `next`：这是一个我们可以在准备好切换路由时使用的函数。调用这个函数并传入 false 将阻止路由的改变，并且在出现错误时非常有用。

在调用前面的函数时，我们使用 Axios 调用了一个 web 服务，该服务提供了一个名称和一个电话号码的字符串。

当我们在这个钩子里时，重要的是要记住我们没有访问这个。这是因为这个钩子在组件实际实例化之前运行，所以没有`this`可以引用。

当服务器响应时，我们在`then`函数中，并且想要分配从服务器返回的名称和电话，但是，正如所说，我们无法访问这个。下一个函数接收到我们组件的引用作为参数。我们使用这个来将变量设置为接收到的值：

```js
...
}).then(response => {
  next(vm => {
    vm.name = response.data.name
    vm.phone = response.data.phone
  })
})
```

# 使用命名动态路由

手动注册所有路由可能会耗费时间，而且当路由事先不知道时，这是不可能的。vue-router 允许您使用参数注册路由，这样您就可以为数据库中的所有对象创建链接，并覆盖其他用户选择路由的用例，遵循某种模式，这将导致手动注册太多的路由。

# 准备工作

除了 vue-router 的基础知识（参考*使用 vue-router 创建 SPA*配方），你不需要任何额外的信息来完成这个配方。

# 如何做…

我们将开设一个有十种不同菜品的在线餐厅。我们将为每道菜创建一个路由。

我们网站的 HTML 布局如下：

```js
<div id="app">
  <h1>Online Restaurant</h1>
  <ul>
    <li>
      <router-link :to="{ name: 'home' }" exact>
        Home
      </router-link>
    </li>
    <li v-for="i in 10">
      <router-link :to="{ name: 'menu', params: { id: i } }">
        Menu {{i}}
      </router-link>
    </li>
    </ul>
  <router-view class="view"></router-view>
</div>
```

这将创建 11 个链接，一个用于主页，十个用于菜品。

在 JavaScript 部分注册`VueRouter`后，代码如下：

```js
Vue.use(VueRouter)
```

创建两个组件；一个将是主页的占位符：

```js
const Home = { template: `
  <div>
    Welcome to Online Restaurant
  </div>
` }
```

其他路由将连接到一个`Menu`组件：

```js
const Menu = { template: `
  <div>
    You just ordered
    <img :src="'http://lorempixel.com/200/200/food/' + $route.params.id">
  </div>
` }
```

在前面的组件中，我们使用`$route`引用全局路由对象，并从 URL 中获取`id`参数。`Lorempixel.com`是一个提供示例图片的网站。我们为每个`id`连接不同的图片。

最后，使用以下代码创建路由本身：

```js
const router = new VueRouter({
  routes: [
    { path: '/', name:'home', component: Home }, 
    { path: '/menu/:id', name: 'menu', component: Menu },
  ]
})
```

你可以看到菜单的路径包含`/:id`，这是`id`参数在 URL 中出现的占位符。

最后，写一个根`Vue`实例：

```js
new Vue({
  router,
  el: '#app'
})
```

现在可以启动应用程序，应该能够看到所有的菜单项。点击其中任何一个应该点菜：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/cpl-vue2-web-dev/img/288ffb71-aea5-42d2-878c-860b008d36d1.png)

# 它是如何工作的…

代码的两个主要部分有助于创建不同菜品的路由。

首先，我们使用冒号语法注册了一个通用路由，并为其分配了一个名称，代码如下：

```js
{ path: '/menu/:id', name: 'menu', component: Menu }
```

这意味着我们可以有一个以`/menu/82`结尾的 URL，而`Menu`组件将显示，并且`$route.params.id`变量设置为`82`。因此，下一行应该根据以下进行更改：

```js
<img :src="'http://lorempixel.com/200/200/food/' + $route.params.id">
```

在渲染的 DOM 中，前一行将被以下行替换：

```js
<img src="'http://lorempixel.com/200/200/food/82">
```

不要在现实生活中没有这样的图片这个事实上介意。

注意，我们还为这个路由指定了一个名称。这并不是严格必要的，但它使我们能够编写代码的第二个主要部分，如下所示：

```js
<router-link :to="{ name: 'menu', params: { id: i } }">
  Menu {{i}}
</router-link>
```

我们可以传递一个对象给`to`属性，而不是写一个字符串，并指定`params`。在我们的例子中，`param`由`v-for`包装给出。这意味着，例如，在`v-for`的第四个循环中：

```js
<router-link :to="{ name: 'menu', params: { id: 4} }">
  Menu 4
</router-link>
```

这将导致 DOM 如下：

```js
<a href="#/menu/4" class="">Menu 4</a>
```

# 在你的页面中有多个 router-view

拥有多个`<router-view>`可以让你拥有可以用更复杂布局组织的页面。例如，你可以有一个侧边栏和主视图。这个食谱就是关于这个的。

# 准备工作

这个食谱没有使用任何高级概念。建议你熟悉 vue-router 并学习如何安装它。不过，可以去本章的第一个食谱了解更多信息。

# 如何做…

这个食谱将使用大量代码来阐明观点。不过，不要灰心，机制真的很简单。

我们将建立一个二手硬件商店。我们将有一个主视图和一个侧边栏；这些将是我们的路由视图。侧边栏将包含我们的购物清单，这样我们总是知道我们在购物什么，不会有任何干扰。

整个 HTML 代码非常简短，因为它只包含一个标题和两个`router-view`组件：

```js
<div id="app">
  <h1>Second-Hand Hardware</h1>
    <router-view name="list"></router-view>
    <router-view></router-view>
</div>
```

在这种情况下，列表被命名为`router-view`。第二个没有名称；因此，默认情况下被命名为`Vue`。

在 JavaScript 中注册`vue-router`：

```js
Vue.use(VueRouter)
```

之后，注册路由：

```js
const router = new VueRouter({
  routes: [
    { path: '/',
      components: {
        default: Parts,
        list: List
      }
    },
    { path: '/computer',
      components: {
        default: ComputerDetail,
        list: List
      }
    }
  ]
})
```

组件不再是单个对象；它已经成为一个包含两个组件的对象：一个用于`list`，另一个用于默认的`router-view`。

在路由代码之前编写`list`组件，如图所示：

```js
const List = { template: `
  <div>
    <h2>Shopping List</h2>
      <ul>
        <li>Computer</li>
      </ul>
  </div>
` }
```

这将只显示计算机作为我们应该记得购买的物品。

部分组件如下；在`router`代码之前编写它：

```js
const Parts = { template: `
  <div>
    <h2>Computer Parts</h2>
    <ul>
      <li><router-link to="/computer">Computer</router-link></li>
      <li>CD-ROM</li>
    </ul>
  </div>
` }
```

这包含一个链接，可以查看有关出售计算机的更多信息；下一个组件绑定到该页面，因此在`router`代码之前编写它：

```js
const ComputerDetail = { template: `
  <div>
    <h2>Computer Detail</h2>
    <p>Pentium 120Mhz, CDs sold separately</p>
  </div>
` }
```

当然，不要忘记添加`Vue`实例：

```js
new Vue({
  router,
  el: '#app'
})
```

当你启动应用程序时，你应该看到两个路由视图一个在另一个上面。如果你想让它们并排，你可以添加一些 CSS 样式：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/cpl-vue2-web-dev/img/1bf6ed33-fbcc-4b6e-8be6-530d55471565.png)

# 工作原理…

在页面中添加`<router-view>`组件时，你只需要记住在路由注册期间添加一个名称来引用它：

```js
<router-view name="view1"></router-view>
<router-view name="view2"></router-view>
<router-view></router-view>
```

如果你没有指定名称，路由将被称为默认路由：

```js
routes: [
  { path: '/',
    components: {  
      default: DefaultComponent,
      view1: Component1,
      view2: Component2
    }
  }
]
```

这样，组件将显示在它们各自的`router-view`元素中。

如果你没有为命名视图指定一个或多个组件，与该名称关联的`router-view`将为空。

# 按层次组织您的路由

在许多情况下，你的网站的组织树可能会很复杂。在某些情况下，有一个明确的分层组织，你可以遵循并使用嵌套路由，vue-routes 可以帮助你保持一切井然有序。最好的情况是 URL 的组织方式与组件的嵌套方式完全对应。

# 准备就绪

在这个教程中，你将使用 Vue 的组件和其他基本功能。你还将使用动态路由。去查看*使用命名动态路由*教程，了解更多信息。

# 如何做…

在这个教程中，你将为一个虚构的世界建立一个在线会计网站。我们将有两个用户--`Stark`和`Lannister`--我们将能够看到这两个用户拥有多少黄金和士兵。

我们网站的 HTML 布局如下：

```js
<div id="app">
  <h1>Kindoms Encyclopedia</h1>
  <router-link to="/user/Stark/">Stark</router-link>
  <router-link to="/user/Lannister/">Lannister</router-link>
  <router-view></router-view>
</div>
```

我们有一个标题和两个链接--一个是`Stark`，一个是`Lannister`--最后是`router-view`元素。

我们将`VueRouter`添加到插件中：

```js
Vue.use(VueRouter)
```

然后，我们注册`routes`：

```js
const router = new VueRouter({
  routes: [
    { path: '/user/:id', component: User,
      children: [ 
        {
          path: 'soldiers',
          component: Soldiers
        },
        {
          path: 'gold',
          component: Gold
        }
      ]
    }
  ]
})
```

我们所说的是注册一个动态路由`/user/:id`，并且在`User`组件内部将有另一个 router-view，其中将包含 gold 和 soldiers 的嵌套路径。

刚才提到的三个组件是按照所示编写的；在路由代码之前添加它们：

```js
const User = { template: `
  <div class="user">
    <h1>Kindoms Encyclopedia</h1>
    User {{$route.params.id}}
    <router-link to="gold">Gold</router-link>
    <router-link to="soldiers">Soldiers</router-link>
    <router-view></router-view>
  </div>
`}
```

正如预期的那样，在`User`组件内部有另一个 router-view 入口，将包含嵌套的`routes`组件。

然后，在路由代码之前编写`Soldiers`和`Gold`组件：

```js
const Soldiers = { template: `
  <div class="soldiers">
    <span v-for="soldier in $root[$route.params.id].soldiers"> 

    </span>
  </div>
`}
const Gold = { template: `
   div class="gold">
    <span v-for="coin in $root[$route.params.id].gold">

    </span>
  </div>
`}
```

这些组件将显示与 Vue 根实例数据选项内的 gold 或 soldiers 变量一样多的表情符号。

这是`Vue`根实例的样子：

```js
new Vue({
  router,
  el: '#app',
  data: {
    Stark: {
      soldiers: 100,
      gold: 50  
    },
    Lannister: {
      soldiers: 50,
      gold: 100
    }
  }
})
```

启动应用程序将使您能够直观地表示两个用户的金币和士兵数量：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/cpl-vue2-web-dev/img/4f818cd0-409e-4510-a190-9d3cca882205.png)

# 工作原理…

为了更好地理解嵌套路由的工作原理，有必要看一下以下图表：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/cpl-vue2-web-dev/img/2a35480c-dd86-4a96-bad5-476248c9991c.png)

我们的路由中只有两个级别。第一个级别，即顶级，由大包装矩形表示，对应于`/user/:id`路由，这意味着每个潜在匹配的 ID 都在同一级别。

相反，内部矩形是一个嵌套路由和嵌套组件。它对应于路由 gold 和 Gold 组件。

当嵌套`routes`对应于嵌套组件时，这是正确的选择。还有另外两种情况需要考虑。

当我们有嵌套组件但没有嵌套路由时，我们可以在嵌套路由前加上斜杠`/`。这将使其表现得像顶级路由。

例如，考虑将我们的代码更改为以下内容：

```js
const router = new VueRouter({
  routes: [
    { path: '/user/:id', component: User,
      children: [
        {
          path: 'soldiers',
          component: Soldiers
        },
        {
          path: '/gold',
          component: Gold
        }
      ] 
    }
  ]
})
```

在`/gold`路由前加上前缀将使`Gold`组件在我们将浏览器指向`/gold`URL 时出现，而不是`/user/Lannister/gold`（在这种情况下将导致错误和空白页面，因为用户未指定）。

另一种情况是有嵌套的`routes`但同一级别没有组件。在这种情况下，只需使用常规语法注册路由。

# 使用路由别名

有时需要有多个指向同一页面的 URL。这可能是因为页面已更改名称，或者因为页面在站点的不同部分中被称为不同的名称。

特别是当页面更改名称时，同样重要的是在许多设置中保留以前的名称。链接可能会断裂，页面可能会从网站的某些部分变得无法访问。在这个食谱中，你将防止这种情况发生。

# 准备工作

对于这个食谱，你只需要对 vue-router 组件有一些了解（如何安装和基本操作）。有关 vue-router 的更多信息将从*使用 vue-router 创建单页应用*食谱开始。

# 如何做…

假设我们有一个时尚网站，负责给服装命名的员工 Lisa 为两件衣服创建了两个新链接：

```js
<router-link to="/green-dress-01/">Valentino</router-link>
<router-link to="/green-purse-A2/">Prada</router-link>
```

开发人员在 vue-router 中创建相应的路由：

```js
const router = new VueRouter({
  routes: [
    {
      path: '/green-dress-01',
      component: Valentino01
    },
    {
      path: '/green-purse-A2',
      component: PradaA2
    }
  ]
})
```

后来发现这两件物品不是绿色的，而是红色的。Lisa 并不怪罪，因为她是色盲。

现在你负责更改所有链接以反映列表的真实颜色。你要做的第一件事是改变链接本身。在你编辑后，HTML 布局看起来是这样的：

```js
<div id="app">
  <h1>Clothes Shop</h1>
  <router-link to="/red-dress-01/">Valentino</router-link>
  <router-link to="/red-purse-A2/">Prada</router-link>
  <router-view></router-view>
</div>
```

你向`Vue`添加`VueRouter`插件：

```js
Vue.use(VueRouter)
```

然后，注册新的`routes`以及旧的`aliases`：

```js
const router = new VueRouter({
  routes: [
    {
      path: '/red-dress-01',
      component: Valentino01,
      alias: '/green-dress-01'
    },
    {
      path: '/red-purse-A2',
      component: PradaA2,
      alias: '/green-purse-A2'
    }
  ]
})
```

这些组件看起来是这样的：

```js
const Valentino01 = { template: '<div class="emoji"></div>' }
const PradaA2 = { template: '<div class="emoji"></div>' }
```

在启动应用程序之前，请记住实例化一个`Vue`实例：

```js
new Vue({
  router,
  el: '#app'
})
```

你可以添加一个 CSS 规则，使表情符号看起来像图片，就像下面的截图所示：

```js
.emoji {
  font-size: 3em;
}
```

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/cpl-vue2-web-dev/img/daa0e259-fb4a-43eb-a602-e70db7b232b6.png)

# 工作原理…

即使我们改变了所有的链接，我们也无法控制其他实体如何链接到我们的页面。对于搜索引擎，比如 Google，没有办法告诉它们删除对旧页面的链接并使用新页面。这意味着如果我们不使用别名，我们可能会在形式上遭受大量的坏名声，包括损坏的链接和 404 页面；在某些情况下，甚至是我们支付给链接到一个不存在页面的广告商。

# 在你的路由之间添加过渡效果

我们在*过渡和动画*中详细探讨了过渡效果。在这里，我们将在更改路由时使用它们，而不是更改元素或组件。同样的观察结果在这里也适用。

# 准备工作

在尝试这个食谱之前，我强烈建议你完成*过渡和动画*中的一些食谱，以及这个食谱。这个食谱是到目前为止学到的概念的混合体。

# 如何做…

在这个教程中，我们将为一个鬼魂餐厅建立一个网站。它与普通餐厅的网站并没有太大的不同，除了页面必须淡出而不是立即出现的要求。

让我们先写一些 HTML 布局：

```js
<div id="app">
  <h1>Ghost's Restaurant</h1>
  <ul>
    <li><router-link to="/">Home</router-link></li>
    <li><router-link to="/menu">Menu</router-link></li>  
  </ul>
  <transition mode="out-in">
  <router-view></router-view>
  </transition>
</div>
```

请注意，我们用一个`transition`标签包裹了主路由显示端口。设置了`out-in`模式，因为我们希望消失的组件的动画在另一个组件出现之前完成。如果我们没有设置这个，两个淡出的组件会在短暂的时间内叠加在一起。有关更详细的讨论，您可以参考*在过渡中让元素离开之前进入阶段*的教程。

让我们创建两个页面/组件：

```js
const Home = { template: '<div>Welcome to Ghost's</div>' }
const Menu = { template: '<div>Today: invisible cookies</div>' }
```

现在，让我们注册`routes`：

```js
Vue.use(VueRouter)
const router = new VueRouter({
  routes: [
    { path: '/', component: Home },
    { path: '/menu', component: Menu }
  ]
})
```

在启动应用程序之前，实例化一个`Vue`对象：

```js
new Vue({
  router,
  el: '#app'
})
```

为了使过渡效果生效，您需要添加一些 CSS 规则：

```js
.v-enter-active, .v-leave-active {
  transition: opacity .5s;
}
.v-enter, .v-leave-active {
  opacity: 0
}
```

现在启动您的应用程序。您成功地在页面切换之间添加了一个淡出过渡。

# 它是如何工作的…

把整个`<router-view>`包裹在一个过渡标签中将为所有组件执行相同的过渡。

如果我们想为每个组件设置不同的过渡，我们有另一种选择：我们必须将单独的组件包裹在过渡中。

比如说，我们有两个过渡效果：诡异和美味。我们希望在`Home`组件出现时应用第一个过渡效果，在`Menu`组件出现时应用第二个过渡效果。

我们需要修改我们的组件，如下所示：

```js
const Home = { template: `
  <transition name="spooky">
    <div>Welcome to Ghost's</div>
  </transition>
` }
const Menu = { template: `
  <transition name="delicious">
    <div>Today: insisible cookies!</div>
  </transition>
` }
```

# 为您的路由管理错误

如果我们去的页面找不到或者不起作用，去链接就没有太多意义。传统上，当发生这种情况时，我们会看到一个错误页面。在 SPA 中，我们更加强大，可以阻止用户完全进入那里，并显示一个礼貌的消息，说明页面不可用。这极大地增强了用户体验，因为用户可以立即采取其他行动，而无需返回。

# 准备工作

为了跟上进度，您应该完成*在切换路由之前获取数据*的教程。

这个教程将在此基础上进行，并假设您已经将所有相关的代码放在了适当的位置。

# 如何做…

正如所说，我们将编辑*在切换路由之前获取数据*教程的结果代码来处理错误。只是为了让您记得，当我们去到`/aboutme`页面时，我们正在从互联网上加载信息。如果信息不可用，我们希望避免进入该页面。

对于这个配方，添加 Axios 作为依赖项，就像在以前的配方中一样。

首先，使用突出显示的代码丰富 HTML 布局：

```js
<div id="app">
  <h1>My Portfolio</h1>
  <ul>
    <li><router-link to="/" exact>Home</router-link></li>
    <li><router-link to="/aboutme">About Me</router-link></li>
  </ul>
  <router-view></router-view>
 <div class="toast" v-show="showError"> There was an error </div> </div>
```

这是一个吐司消息，每当出现错误时都会出现在屏幕上。使用这个 CSS 规则为它添加一些样式：

```js
div.toast {
  width: 15em;
  height: 1em;
  position: fixed;
  bottom: 1em;
  background-color: red;
  color: white;
  padding: 1em;
  text-align: center;
}
```

接下来你想做的事情是有一个全局机制来将`showError`设置为`true`。在 JavaScript 代码的顶部，声明`vm`变量：

```js
let vm
```

然后，将我们的`Vue`根实例分配给它：

```js
vm = new Vue({
  router,
  el: '#app',
 data: { showError: false } })
```

我们还将`showError`变量添加到数据选项中。

最后要做的事情实际上是在显示生物信息之前管理我们的数据检索错误。

将突出显示的代码添加到`beforeRouteEnter`钩子中：

```js
beforeRouteEnter (to, from, next) {
  axios.post('http://example.com/', {
    "type": "object",
    "properties": {
      "name": {
        "type": "string",
        "ipsum": "name"
      },
      "phone": {
        "type": "string",
        "format": "phone"
      }
    }
  }).then(response => {
  next(vm => {
    vm.name = response.data.name
    vm.phone = response.data.phone
  })
}).catch(error => {
 vm.showError = true next(false) }) }
```

接下来的（false）命令将使用户停留在原地，我们还编辑了端点到`example.com`，它将在`POST`请求上返回一个错误代码：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/cpl-vue2-web-dev/img/e0fd0601-320f-4fde-ad35-e000ae8d638e.png)

# 它是如何工作的...

Axios 将从`example.com`接收到一个错误，这将触发对我们调用 post 时创建的 promise 的拒绝。promise 的拒绝将反过来触发 catch 中传递的函数。

值得注意的是，在代码的这一点上，`vm`指的是根`Vue`实例；这是因为该代码总是在`Vue`实例初始化并分配给`vm`之后执行的。

# 添加进度条以加载页面

虽然 SPA 用户不必等待新页面加载，但他仍然必须等待数据加载。在*在切换路由之前获取数据*配方中，我们在点击按钮到`/aboutme`页面后还必须等待一段时间。没有任何提示数据正在加载，然后突然页面出现了。如果用户至少有一些反馈页面正在加载，那不是很好吗？

# 准备就绪

为了跟上，您应该完成*在切换路由之前获取数据*配方。

这个配方将在此基础上构建，我假设您已经在适当的位置有了所有相关的代码。

# 如何做...

正如前面所述，我将假设您已经有了*在切换路由之前获取数据*配方中的所有代码，并且已经在适当的位置工作。

对于这个配方，我们将使用一个额外的依赖项--`NProgress`，一个小型实用程序，用于在屏幕顶部显示加载条。

在页面的头部或 JSFiddle 的依赖项列表中添加以下两行（npm 也有一个包）：

```js
<link rel="stylesheet" href="https://cdn.bootcss.com/nprogress/X/nprogress.css">
<script src="https://cdn.bootcss.com/nprogress/X/nprogress.js"></script>
```

在这里，`X`是`NProgress`的版本。在写作时，它是 0.2.0，但您可以在网上查找。

完成这些步骤后，下一步是定义我们希望进度条的行为。

首先，我们希望点击链接后立即出现进度条。为此，我们可以在点击事件上添加一个事件监听器，但如果有一百个链接，这将是一个很差的设计。一个更可持续和干净的方法是通过为路由创建一个新的钩子，并将进度条的出现与路由的切换连接起来。这样还可以提供一致的应用体验：

```js
router.beforeEach((to, from, next) => {
  NProgress.start()
  next()
})
```

同样地，我们希望在成功加载完成后进度条消失。这意味着我们希望在回调函数内部执行它：

```js
beforeRouteEnter (to, from, next) {
  axios.post('http://schematic-ipsum.herokuapp.com/', {
    "type": "object",
    "properties": {
      "name": {
        "type": "string",
        "ipsum": "name"
      },
      "phone": {
        "type": "string",
        "format": "phone"
      }
    }
  }).then(response => {
 NProgress.done()    next(vm => {
      vm.name = response.data.name
      vm.phone = response.data.phone
    })
  })
}
```

现在您可以启动应用程序，您的进度条应该已经工作了：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/cpl-vue2-web-dev/img/6f7b3b8c-e6b9-465b-8403-a2d606f0c5e6.png)

# 工作原理…

这个示例还表明，利用外部库并不难，只要它们易于安装。

由于`NProgress`组件如此简单且有用，我在这里报告它的 API 作为参考：

+   `NProgress.start()`: 显示进度条

+   `NProgress.set(0.4)`: 设置进度条的百分比

+   `NProgress.inc()`: 将进度条递增一点

+   `NProgress.done()`: 完成进度

我们使用了前面两个函数。

作为预防措施，我还建议不要依赖于个别组件调用`done()`函数。我们在`then`函数中调用它，但如果下一个开发人员忘记了呢？毕竟，我们在*任何*路由切换之前都会启动进度条。

最好是在`router`中添加一个新的钩子：

```js
router.afterEach((to, from) => {
  NProgress.done()
})
```

由于`done`函数是幂等的，我们可以随意调用它。因此，这不会修改我们应用的行为，并且可以确保即使将来的开发人员忘记关闭进度条，一旦路由已经改变，它也会自动消失。

# 如何重定向到另一个路由

您可能有无数个原因希望重定向用户。您可能希望用户在访问页面之前登录，或者页面已经移动，您希望用户注意新链接。在这个示例中，您将重定向用户到一个新的主页，以便快速修改网站。

# 准备就绪

这个教程只会使用关于 vue-router 的基本知识。如果您已经完成了*使用 vue-router 创建 SPA*的教程，那么您就可以开始了。

# 如何做…

假设我们有一个在线服装店。

这将是网站的 HTML 布局：

```js
<div id="app">
  <h1>Clothes for Humans</h1>
  <ul>
    <li><router-link to="/">Home</router-link></li>
    <li><router-link to="/clothes">Clothes</router-link></li>
  </ul>
  <router-view></router-view>
</div>
```

这只是一个链接到服装列表的页面。

让我们注册`VueRouter`：

```js
Vue.use(VueRouter)
```

我们的网站有三个页面，分别由以下组件表示：

```js
const Home = { template: '<div>Welcome to Clothes for Humans</div>' }
const Clothes = { template: '<div>Today we have shoes</div>' }
const Sales = { template: '<div>Up to 50% discounts! Buy!</div>' }
```

它们代表着主页、服装列表和去年我们使用过的一些打折的页面。

让我们注册一些`routes`：

```js
const router = new VueRouter({
  routes: [
    { path: '/', component: Home }
    { path: '/clothes', component: Clothes },
    { path: '/last-year-sales', component: Sales }
  ]
})
```

最后，我们添加一个根`Vue`实例：

```js
new Vue({
  router,
  el: '#app'
})
```

您可以启动应用程序，它应该可以正常工作，没有任何问题。

黑色星期五就要到了，我们忘了这是全球时尚界最大的活动。我们没有时间重写主页，但去年的销售页面可以解决问题。我们要做的是将访问我们主页的用户重定向到那个页面。

为了实现这一点，我们需要修改我们注册的`routes`的方式：

```js
const router = new VueRouter({
  routes: [
    { path: '/', component: Home, redirect: '/last-year-sales' },
    { path: '/clothes', component: Clothes },
    { path: '/last-year-sales', component: Sales }
  ]
})
```

只需添加那个重定向，我们就挽救了这一天。现在，每当您访问主页时，都会呈现销售页面。

# 它是如何工作的…

当匹配根路由时，`Home`组件不会被加载。而是匹配`/last-year-sales`的路径。我们也可以完全省略组件，因为它永远不会被加载：

```js
{ path: '/', redirect: '/last-year-sales' }
```

# 还有更多…

在 vue-router 中进行重定向比我们刚才看到的更强大。在这里，我将尝试为我们刚刚创建的应用程序增加更多重定向功能。

# 重定向到 404 页面

重定向未找到的页面是通过在最后一个路由中添加一个捕获所有来完成的。它将匹配所有其他路由未匹配的内容：

```js
...
{ path: '/404', component: NotFound },
{ path: '*', redirect: '/404' }
```

# 命名重定向

重定向可以与命名路由结合使用（参考*使用命名动态路由*教程）。我们可以通过名称指定目的地：

```js
...
{ path: '/clothes', name: 'listing', component: Clothes },
{ path: '/shoes', redirect: { name: 'listing' }}
```

# 带参数重定向

您还可以在重定向时保留参数：

```js
...
{ path: '/de/Schuh/:size', redirect: '/en/shoe/:size' },
{ path: '/en/shoe/:size', component: Shoe }
```

# 动态重定向

这是最终的重定向。您可以访问用户试图访问的路由，并决定要将其重定向到哪里（尽管您无法取消重定向）：

```js
...
{ path: '/air', component: Air },
{ path: '/bags', name: 'bags', component: Bags },
{ path: '/super-shirt/:size', component: SuperShirt },
{ path: '/shirt/:size?', component: Shirt},
{ path: '/shirts/:size?',
  redirect: to => {
    const { hash, params, query } = to
    if (query.colour === 'transparent') {
      return { path: '/air', query: null }
    }
    if (hash === '#prada') {
      return { name: 'bags', hash: '' }
    }
    if (params.size > 10) {
      return '/super-shirt/:size'
    } else {
      return '/shirt/:size?'
    }
  }
}
```

# 在返回时保存滚动位置

在 vue-router 中，有两种导航模式：`hash`和`history`。默认模式和前面的示例中使用的模式是`previouslye`。传统上，当您访问网站，向下滚动一点并单击链接到另一个页面时，新页面将从顶部显示。当您单击浏览器的返回按钮时，页面将从先前滚动的高度显示，并且您刚刚单击的链接可见。

当您在 SPA 中时，这是不正确的，或者至少不是自动的。vue-router 历史模式让您模拟这一点，甚至更好地控制发生在您滚动时发生的事情。

# 准备工作

要完成此示例，我们需要切换到历史模式。历史模式仅在应用程序在正确配置的服务器上运行时才起作用。如何为 SPA 配置服务器超出了本书的范围（但原则是每个路由都从服务器端重定向到`index.html`）。

我们将使用一个 npm 程序来启动一个小型服务器；您应该已经安装了 npm。

# 如何做…

首先，您将安装一个用于 SPA 的紧凑服务器，以便历史模式可以工作。

在您喜欢的命令行中，进入将包含您的应用程序的目录。然后，键入以下命令：

```js
    npm install -g history-server
    history-server .
```

服务器运行后，您将不得不将浏览器指向`http://localhost:8080`，如果您的目录中有一个名为`index.html`的文件，它将显示出来；否则，您将看不到太多。

创建一个名为`index.html`的文件，并填写一些样板，就像在*选择开发环境*示例中一样。我们希望有一个只有`Vue`和`vue-router`作为依赖项的空白页面。我们的空白画布应该如下所示：

```js
<!DOCTYPE html>
<html>
<head>
  <script src="https://unpkg.com/vue/dist/vue.js"></script>
  <script src="https://unpkg.com/vue-router/dist/vue-router.js"></script>
</head>
<body>
  <div id="app">
  </div>
  <script>
    new Vue({
      router,
      el: '#app'
    })
  </script>
</body>
</html>
```

作为 HTML 布局，将其放在 body 中：

```js
<div id="app">
  <h1>News Portal</h1>
    <ul>
      <li><router-link to="/">Home</router-link></li>
      <li><router-link to="/sports">Sports</router-link></li>
      <li><router-link to="/fashion">Fashion</router-link></li>
    </ul>
  <router-view></router-view>
</div>
```

我们有一个带有三个链接和一个 router-view 入口的标题。我们将为体育和时尚页面创建两个长页面：

```js
const Sports = { template: `
  <div>
    <p v-for="i in 30">
      Sample text about sports {{i}}.
    </p>
    <router-link to="/fashion">Go to Fashion</router-link>
    <p v-for="i in 30">
      Sample text about sports {{i + 30}}.
    </p>
  </div>
` }
const Fashion = { template: `
  <div>
    <p v-for="i in 30">
      Sample text about fashion {{i}}.
    </p>
    <router-link to="/sports">Go to Sports</router-link>
    <p v-for="i in 30">
      Sample text about fashion {{i + 30}}.
    </p>
  </div>
` }
```

我们只需要一个主页组件的存根：

```js
const Home = { template: '<div>Welcome to BBCCN</div>' }
```

为这个新闻网站编写一个合理的路由器：

```js
Vue.use(VueRouter)
const router = new VueRouter({
  routes: [
    { path: '/', component: Home },
    { path: '/sports', component: Sports },
    { path: '/fashion', component: Fashion } 
  ]
})
```

如果您现在使用浏览器转到先前指定的地址，您应该可以看到网站正在运行。

转到体育页面，滚动到看到链接为止，然后单击它。

注意您正在访问的页面不是从头开始显示的。这在传统网站中不会发生，也不是理想的。

单击返回按钮，注意我们在上次离开页面的地方；我们希望保留这种行为。

最后，请注意页面的 URL 看起来并不自然，但内部有哈希符号；我们希望 URL 看起来更好：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/cpl-vue2-web-dev/img/6b9f4c57-e3b0-46da-8970-a551188c9d00.png)

为了实现这一点，让我们将路由器代码修改为以下内容：

```js
const router = new VueRouter({
 mode: 'history',  routes: [
    { path: '/', component: Home },
    { path: '/sports', component: Sports },
    { path: '/fashion', component: Fashion }
  ],
 scrollBehavior (to, from, savedPosition) { if (savedPosition) { return savedPosition } else { return { x: 0, y: 0 } } } })
```

我们添加了一行，指定新模式为历史（链接中没有哈希），并定义了`scrollBehavior`函数，以便在有位置时返回到最后位置；如果是新页面，它应该滚动到左上角。

您可以通过刷新浏览器并返回主页来尝试这一点。

打开体育页面并单击页面中间的链接。新页面现在从头开始显示。

单击“返回”，`savedPosition`将被恢复。

请注意现在 URL 看起来更好了：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/cpl-vue2-web-dev/img/ec4bb7b5-df25-4981-a1de-232851a0d5c9.png)

# 它是如何工作的...

当您在浏览器中使用包含哈希符号的 URL 时，浏览器将发送一个不带哈希后缀的 URL 的请求，也就是说，当您在页面内有一个事件，该事件转到相同页面但带有不同的哈希后缀时：

```js
http://example.com#/page1 on  http://example.com#/page2
```

浏览器不会重新加载页面；这就是为什么 vue-router 可以在用户单击仅修改哈希的链接时修改页面的内容，而无需重新加载页面。

当您将模式从`hash`更改为`history`时，vue-router 将放弃哈希标记，并利用“history.pushState（）”函数。

此函数将添加另一个虚拟页面并将 URL 更改为其他内容：

```js
http://example.com/page1 =pushState=> http://example.com/page2
```

浏览器不会发送 GET 请求来查找`page2`; 实际上，它什么也不会做。

当您按下返回按钮时，浏览器会恢复 URL，并且 vue-router 会接收一个事件。然后它将读取 URL（现在是`page1`）并匹配相关的路由。

我们紧凑的历史服务器的作用是将每个 GET 请求重定向到`index.html`页面。这就是为什么当我们尝试直接转到`http://localhost:8080/fashion`时，我们不会收到 404 错误。
