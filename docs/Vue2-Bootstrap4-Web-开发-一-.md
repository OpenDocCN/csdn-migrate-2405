# Vue2 Bootstrap4 Web 开发（一）

> 原文：[`zh.annas-archive.org/md5/7E556BCDBA065D692175F778ABE043D8`](https://zh.annas-archive.org/md5/7E556BCDBA065D692175F778ABE043D8)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第一章：请介绍你自己 - 教程

# 你好，用户

你好亲爱的读者，我的名字是 Olga。你也想介绍一下自己吗？打开[`pleaseintroduceyourself.xyz/`](https://pleaseintroduceyourself.xyz/)给我和其他读者留言。

页面本身看起来并不特别。它只是一个允许用户写消息的网页，然后，这条消息立即与其他用户的消息一起以倒序显示：

![你好，用户](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00002.jpeg)

请介绍你自己页面

你想知道我创建这个页面花了多长时间吗？大约花了我半个小时，我不仅指的是编写 HTML 标记或者倒序排列消息，还包括数据库设置、部署和托管。

你可能注意到第一条消息从未改变，实际上这是我的消息，我写道我喜欢学习和教学。这是真的。这就是为什么我会把这一章节专门用来教你如何在短短 15 分钟内创建完全相同的页面。你准备好了吗？让我们开始吧！

# 在 Firebase 控制台中创建一个项目

如果你还没有谷歌账号，但是你真的想继续这个教程，那么，很抱歉，你这次必须创建一个。Firebase 是由谷歌提供的服务，所以谷歌账号是必须的。

如果你已经有账号，请登录 Firebase 控制台：

[`console.firebase.google.com/`](https://console.firebase.google.com/)。

让我们开始创建你的新 Firebase 项目。点击**添加项目**按钮。给它一个有意义的名字，并从列表中选择你的国家。完成后，点击**创建项目**：

![在 Firebase 控制台中创建一个项目](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00003.jpeg)

使用 Firebase 控制台创建一个项目

完成了！现在，你可以使用 Firebase 后端为你的应用程序提供支持，包括实时数据库、认证机制、托管和分析。

## 向 Firebase 应用程序数据库添加第一个条目

让我们添加第一个数据库条目。点击左侧的**数据库**选项卡。你应该看到类似这样的仪表板：

![向 Firebase 应用程序数据库添加第一个条目](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00004.jpeg)

Firebase 项目仪表板上的实时数据库

通过点击加号来添加一个名为`messages`的条目，以及作为键值对象包含`title`、`text`和`timestamp`的第一条消息：

![向 Firebase 应用程序数据库添加第一个条目](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00005.jpeg)

向 Firebase 实时数据库添加第一个值

点击**添加**按钮，您的数据库将保留添加的条目。添加尽可能多的消息条目，或者保持原样。现在，为了简单起见，让我们改变我们数据库的规则，使其对每个人都可读可写。注意！不要为公共使用的生产环境做这个操作。在这个例子中，我们只是想测试一些 Firebase 功能，但是您未来的应用程序必须是智能和安全的。点击**规则**选项卡，在打开的文本区域中输入以下规则：

```js
{
  "rules": {
    ".read": true,
    ".write": true
  }
}
```

因此，您的**规则**选项卡现在看起来是这样的：

![向 Firebase 应用程序数据库添加第一个条目](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00006.jpeg)

更改规则后的规则选项卡

点击**发布**按钮，您就完成了！现在，开始在我们的应用程序中使用这些数据将会很有趣。但是，首先我们必须创建这个应用程序，并将其连接到我们的项目中。

# 搭建 Vue.js 应用程序

在本节中，我们将创建一个*Vue.js*应用程序，并将其连接到我们在上一步中创建的 Firebase 项目。确保您的系统上已安装*Node.js*。

您还必须安装 Vue.js。请查看官方 Vue 文档的说明页面[`vuejs.org/v2/guide/installation.html`](https://vuejs.org/v2/guide/installation.html)。或者，只需运行`npm install`命令：

```js
**$ npm install -g vue-cli**

```

现在，一切都准备好开始搭建我们的应用程序了。转到您希望应用程序驻留的文件夹，并输入以下代码行：

```js
**vue init webpack please-introduce-yourself**

```

它会问您几个问题。只需选择默认答案，然后对每个问题按*Enter*。初始化后，您就可以安装和运行您的应用程序了：

```js
**cd please-introduce-yourself**
**npm install**
**npm run dev**

```

如果一切正常，以下页面将自动在您的默认浏览器中打开：

![搭建 Vue.js 应用程序](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00007.jpeg)

安装和运行后的默认 Vue.js 应用程序

如果不是，请再次检查 Vue.js 官方安装页面。

## 将 Vue.js 应用程序连接到 Firebase 项目

要能够将您的应用程序连接到 Firebase 项目，您必须安装*Firebase*和*VueFire*。在您的新应用程序的根目录中运行`npm install`命令：

```js
**cd please-introduce-yourself**
**npm install firebase vuefire --save**

```

现在，您可以在应用程序内部使用 Firebase 强大的功能。让我们检查一下是否成功！我们只需执行以下操作：

+   导入 Firebase

+   创建一个包含 Firebase 应用程序 ID、项目域、数据库域和连接到我们项目所需的其他一些内容的`config`对象

+   编写将使用 Firebase API 和创建的`config`文件连接到 Firebase 项目的代码。

+   使用它

我们从哪里获取配置我们的 Firebase 实例所需的信息？转到 Firebase 控制台，单击**概述**选项卡右侧的齿轮图标，然后选择**项目设置**。现在，单击**将 Firebase 添加到您的网络应用**按钮：

![将 Vue.js 应用程序连接到 Firebase 项目](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00008.jpeg)

单击**将 Firebase 添加到您的网络应用**按钮

将打开一个包含我们所需所有信息的弹出窗口：

![将 Vue.js 应用程序连接到 Firebase 项目](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00009.jpeg)

所需的配置对象的所有信息都在这里

好的，现在，只需保留此弹出窗口打开，转到您的 Vue 应用程序，并打开位于应用程序的`src`目录中的`main.js`文件。在这里，我们需要告诉我们的 Vue 应用程序它将使用 VueFire。这样，我们就能在应用程序内部使用 Firebase 提供的所有功能。将以下行添加到`main.js`文件的导入部分：

```js
//main.js
import VueFire from 'vuefire'
**Vue.use(VueFire)**

```

太棒了！现在，打开`App.vue`文件。在这里，我们将导入 Firebase 并在 Vue 应用程序内初始化我们的 Firebase 应用程序。在`<script>`标签内添加以下代码行：

```js
//App.vue
<script>
  import Firebase from 'firebase'

  let config = {
    apiKey: 'YOUR_API_KEY',
    authDomain: 'YOUR_AUTH_DOMAIN',
    databaseURL: 'YOUR_DATABASE_URL',
    projectId: 'YOUR_PROJECT_ID',
    storageBucket: 'YOUR_STORAGE_BUCKET',
    messagingSenderId: 'YOUR_MESSAGING_SENDER_ID'
  }

  let app = Firebase.initializeApp(config)
</script>
```

从我们在上一步中打开的弹出窗口中复制`config`对象信息所需的内容。

现在，我们将获取到我们的消息数据库对象的引用。使用 Firebase API 非常简单：

```js
//App.vue
<script>
  <...>
 **let db = app.database()**
 **let messagesRef = db.ref('messages')**
</script>
```

我们快完成了。现在，我们只需在 Vue 数据对象中导出`messages`对象，以便我们能够在模板部分内使用它。因此，在`export`部分内，添加一个带有`firebase`键的条目，并将`messages`指向`messagesRef`：

```js
export default {
  firebase: {
    messages: messagesRef
  },
}
```

现在，在`<template>`标签内，我们将使用`v-for`指令来遍历`messages`数组并打印有关每条消息的所有信息。请记住，每条消息由`title`、`text`和`timestamp`组成。因此，请在模板中添加以下`<div>`：

```js
//App.vue
<div v-for="message in messages">
  <h4>{{ message.title }}</h4>
  <p>{{ message.text }}</p>
  <p>{{ message.timestamp }}</p>
</div>
```

最后，您的`App.vue`组件将如下所示：

```js
//App.vue
<template>
  <div id="app">
    <div v-for="message in messages">
      <h4>{{ message.title }}</h4>
      <p>{{ message.text }}</p>
      <p>{{ message.timestamp }}</p>
    </div>
  </div>
</template>

<script>
  import Firebase from 'firebase'

  let config = {
    apiKey: 'YOUR_API_KEY',
    authDomain: 'YOUR_AUTH_DOMAIN',
    databaseURL: 'YOUR_DATABASE_URL',
    projectId: 'YOUR_PROJECT_ID',
    storageBucket: 'YOUR_STORAGE_BUCKET',
    messagingSenderId: 'YOUR_MESSAGING_SENDER_ID'
  }

  let app = Firebase.initializeApp(config)
  let db = app.database()
  let messagesRef = db.ref('messages')
  export default {
    name: 'app',
    firebase: {
      messages: messagesRef
    }
  }
</script>
```

如果您在应用程序初始化时选择了默认的代码检查设置，那么您从 Firebase 复制并粘贴到应用程序中的代码将无法通过代码检查。这是因为 Vue-cli 初始化的默认代码检查设置要求使用单引号，并且行尾不使用分号。顺便说一下，*Evan You*特别自豪于这个不使用分号的规则。所以，请让他高兴一下；从复制的代码中删除所有分号，并将双引号替换为单引号。

您难道不好奇去查看页面吗？如果您还没有运行应用程序，请切换到应用程序文件夹并运行它：

```js
**cd please-introduce-yourself**
**npm run dev**

```

我非常确定您看到了以下截图：

![将 Vue.js 应用程序连接到 Firebase 项目](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00010.jpeg)

显示来自 Firebase 数据库的 Vue.js Web 应用程序信息

恭喜！您已成功完成我们教程的第一部分，将 Vue.js 应用程序连接到 Firebase 实时数据库。

# 添加基于 Bootstrap 的标记

让我们通过添加 Bootstrap 并使用其类来为我们的应用程序添加基本样式。

首先，让我们从 Bootstrap 的 CDN 中包含 Bootstrap 的`CSS`和`JS`文件。我们将使用即将推出的版本 4，目前还处于 alpha 版。打开`index.html`文件，在`<head>`部分添加必要的`link`和`script`标签：

```js
//index.html
<link
rel="stylesheet"
href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-alpha.6/css/bootstrap.min.css"crossorigin="anonymous">
<script src="https://code.jquery.com/jquery-3.2.1.min.js"crossorigin="anonymous"></script>
<script src="https://npmcdn.com/tether@1.2.4/dist/js/tether.min.js">
</script>
<script src="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-alpha.6/js/bootstrap.min.js"crossorigin="anonymous">
</script>
```

您可能已经注意到我还添加了*jQuery*和*Tether*依赖项；这是因为 Bootstrap 依赖于它们。

现在，我们可以在应用程序中使用 Bootstrap 类和组件。让我们从使用 Bootstrap 的类开始添加一些样式。

我将整个应用程序`div`标签包装到`jumbotron`类中，然后将其内容包装到`container`类中。因此，模板将会有些不同：

```js
//App.vue
<template>
  <div id="app" class="**jumbotron**">
    <div class="**container**">
      <h1>Hello! Nice to meet you!</h1>
    <hr />
    <div v-for="message in messages">
    <...>
    </div>
  </div>
</div>
</template>
```

查看页面；它看起来不一样吗？现在，我想将每条消息的内容包装在`card`类中。卡片似乎是这种东西的适当容器。查看官方 Bootstrap 关于卡片的文档[`v4-alpha.getbootstrap.com/components/card/`](https://v4-alpha.getbootstrap.com/components/card/)。我将添加一个带有`card-group`类的`div`标签，并将所有带有消息的卡片放在这个容器中。因此，我不需要担心定位和布局。一切都会自动变得响应！因此，消息的标记将如下所示：

```js
//App.vue
<template>
<...>
  <div class="**card-group**">
    <div class="card" v-for="message in messages">
      <div class="**card-block**">
        <h5 class="**card-title**">{{ message.title }}</h5>
        <p class="**card-text**">{{ message.text }}</p>
        <p class="**card-text**"><small class="text-muted">Added on {{ message.timestamp }}</small></p>
      </div>
    </div>
  </div>
</template>
```

查看页面。它看起来几乎很好！在几个步骤中，我们能够很好地显示存储在我们 Firebase 数据库中的消息。尝试使用 Firebase 实时数据库仪表板添加另一条消息。保持网页打开！填写 Firebase 数据库字段：

![使用 Bootstrap 增加标记](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00011.jpeg)

向 Firebase 数据库添加条目

现在，点击“添加”按钮。新消息会自动出现在您的网页上：

![使用 Bootstrap 增加标记](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00012.jpeg)

一旦我们点击“添加”按钮，新消息立即出现在我们的网页上

这不是很棒吗？现在，我们可以添加任意多的消息。我们还可以删除它们并操纵它们，所有的更改都会自动传播到我们的网页上。这很不错，但我们真的想继续在后端数据库上玩耍，看到网页上的变化吗？当然不！我们希望我们网页的用户能够使用我们的页面而不是我们的数据库仪表板来添加他们的消息。让我们回到我们的 Vue.js 应用程序，并添加一个表单，让我们能够添加新的消息。

## 使用 Bootstrap 添加表单

让我们向我们的应用程序添加一个简单的表单，这样我们就可以向我们的留言板添加新消息。查看 Bootstrap 关于表单的文档[`v4-alpha.getbootstrap.com/components/forms/`](https://v4-alpha.getbootstrap.com/components/forms/)。

让我们在消息列表之前添加一个表单。这个表单将包含标题的输入，消息的文本区域和提交按钮。它将看起来像这样：

```js
//App.vue
<template>
  <div id="app" class="jumbotron">
    <div class="container">
      <h1>Hello! Nice to meet you!</h1>
      <hr />
      <form>
        <div>
 **<input maxlength="40" autofocus placeholder="Please introduce yourself :)" />**
        </div>
        <div>
 **<textarea placeholder="Leave your message!"  rows="3">**
 **</textarea>**
        </div>
 **<button type="submit">Send</button>**
      </form>
      <hr />
      <...>
    </div>
  </div>
</template>
```

看看页面。看起来不太美观，是吗？

![使用 Bootstrap 添加表单](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00013.jpeg)

我们的表单看起来不太美观。

实际上，让我们诚实一点，它看起来很丑！但是，使用 Bootstrap 类，修复它真的很容易。如果我们将`form-control`类添加到`input`和`textarea`元素中，将`form-group`类添加到围绕这些元素的每个`div`标签中，可能还将`btn btn-primary`类添加到`submit`按钮中…嗯，我们会得到更好的东西！

![使用 Bootstrap 添加表单](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00014.jpeg)

表格看起来真的很漂亮，使用了 Bootstrap 类

好的，现在我们有一个看起来不错的表单，但是如果我们尝试填写它，什么也不会发生。我们必须使其功能化，为此，我们将使用 Vue.js 的强大功能。

# 使用 Vue.js 使事情功能化

那么，我们想要通过我们的表单实现什么？我们希望创建新消息。这条消息必须由标题、文本和时间戳组成。我们还希望将此消息添加到我们的消息引用数组中。

让我们将这条新消息称为`newMessage`，并将其添加到`App.vue`的`data`属性中：

```js
//App.vue
<script>
  <...>
  export default {
    data () {
      return {
 **newMessage: {**
 **title: '',**
 **text: '',**
 **timestamp: null**
 **}**
      }
    },
  <...>
  }
</script>
```

现在，让我们将`newMessage`对象的标题和文本绑定到表单的`input`和`textarea`上。我们还将一个名为`addMessage`的方法绑定到表单的提交处理程序，使整个表单的标记看起来像这样：

```js
<template>
<...>
  <form **@submit="addMessage"**>
    <div class="form-group">
      <input class="form-control"**v-model="newMessage.title"**maxlength="40"autofocus  placeholder="Please introduce yourself :)" />
    </div>
    <div class="form-group">
      <textarea class="form-control"**v-model="newMessage.text"** placeholder="Leave your message!"  rows="3"></textarea>
    </div>
    <button class="btnbtn-primary" type="submit">Send</button>
  </form>
  <...>
</template>
```

嗯，我们已经将`"addMessage"`方法绑定到表单的`submit`回调，但是我们还没有定义这个方法！因此，让我们定义它。在我们的`App.vue`导出部分添加`methods`对象，并在其中定义`addMessage`方法。此方法将从我们的表单接收事件属性，然后只需获取`newMessage`对象并将其推送到`messagesRef`数组中。听起来很容易吧？

```js
//App.vue
<script>
  export default {
  <...>
 **methods: {**
 **addMessage (e) {**
 **e.preventDefault()**
 **this.newMessage.timestamp = Date.now()**
 **messagesRef.push(this.newMessage)**
 **}**
 **}**
  }
</script>
```

现在，打开页面，填写表单，然后点击**发送**按钮。您会立即看到您的消息出现在消息列表中：

![使用 Vue.js 使事情功能化](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00015.jpeg)

我们在表单中输入的消息立即传播到消息列表中

还有一些东西我们需要修复。我们不希望填写表单的值在消息添加到消息列表后仍然保留在那里。因此，我们需要在`addMessage`方法中清除它。可能，至少对标题进行一些基本检查也会很好。因此，将方法重写如下：

```js
//App.vue
addMessage (e) {
  e.preventDefault()
 **if (this.newMessage.title === '') {**
 **return**
 **}**
  this.newMessage.timestamp = Date.now()
  messagesRef.push(this.newMessage)
 **this.newMessage.text = ''**
 **this.newMessage.title = ''**
 **this.newMessage.timestamp = null**
}
```

现在，如果你开始添加更多的消息，事情看起来有点奇怪。我们显示消息的方式可能不是最适合我们的情况。你还记得我们将消息卡片包装在带有`card-group`类的`div`中吗？让我们尝试用`card-columns`类替换它，看看是否更好看。事实上，是的。让我们保持这样。

## 添加实用函数使事情看起来更美观

我们已经有一个完全功能的单页面应用程序，但它仍然缺少一些令人惊叹的东西。例如，时间显示为时间戳并不真的美观。让我们编写实用函数，将我们的时间戳转换成美观的形式。

我们将使用*Moment.js*库（[`momentjs.com/`](https://momentjs.com/)）。在应用程序文件夹中安装它：

```js
**npm install moment --save**

```

创建一个名为`utils`的文件夹。在这个文件夹中添加一个名为`utils.js`的文件。导入`moment`并编写以下函数：

```js
//utils.js
import moment from 'moment'

function dateToString (date) {
  if (date) {
 **return moment(date).format('MMMM Do YYYY, h:mm:ss a')**
  }
  return''
}
```

在文件的末尾导出它：

```js
//utils.js
<...>
export { dateToString }
```

让我们将这个函数导入到`App.vue`中，并用它来格式化我们的时间戳。打开`App.vue`文件，在`script`部分的开头添加`import`语句：

```js
//App.vue
<script>
  import Firebase from 'firebase'
 **import { dateToString } from './utils/utils'**
  <...>
</script>
```

为了能够在 Vue 模板中使用这个函数，我们必须在`methods`部分导出它。只需向`methods`对象添加一个新条目：

```js
//App.vue
<script>
  export default {
    <...>
    methods: {
 **dateToString: dateToString**,
      <...>
    }
</script>
```

由于我们使用 ES6，我们可以直接编写以下代码行：

```js
methods: {
 **dateToString**
}
```

现在，我们可以在模板部分使用这种方法。只需将`message.timestamp`绑定对象包装在`dataToString`方法中：

```js
<p class="card-text"><small class="text-muted">Added on {{ **dateToString(message.timestamp)** }}</small></p>
```

查看页面！现在，你可以看到美观的日期，而不是 Unix 时间戳。

### 练习

我有一个小练习给你。你看到了将实用函数添加到将时间戳转换为格式良好的日期是多么容易。现在，创建另一个实用函数，将其命名为`reverse`。这个函数应该用于以相反的顺序显示消息数组，所以最近的消息应该首先出现。如果你有疑问，请查看本章的代码。

## 将消息卡片提取到它们自己的组件中

你可能注意到了演示应用程序的第一条消息总是在那里。它不会被其他新消息项移动。所以，它似乎是一种特殊的消息，并且以一种特殊的方式对待。事实上，确实如此。如果你想让一张卡片固定，只需在遍历其他消息的`card`元素之前添加它。你还可以给这张卡片添加一些类，以显示它是真的特别。在我的例子中，我添加了 Bootstrap 的`card-outline-success`类，用漂亮的绿色轮廓显示元素：

```js
//App.vue
<div class="card-columns">
 **<div class="card card-outline-success">**
 **<div class="card-block">**
 **<h5 class="card-title">Hello!</h5>**
 **<p class="card-text">This is our fixed card!</p>**
 **<p class="card-text"><small class="text-muted">Added on {{ dateToString(Date.now()) }}</small></p>**
 **</div>**
 **</div>**
  <div class="card" v-for="message in messages">
    <div class="card-block">
      <h5 class="card-title">{{ message.title }}</h5>
      <p class="card-text">{{ message.text }}</p>
      <p class="card-text"><small class="text-muted">Added on {{ dateToString(message.timestamp) }}</small></p>
    </div>
  </div>
</div>
```

现在，你有一张漂亮的固定卡片，颜色与其他卡片的颜色不同。但是... 你没有看到任何问题吗？我们在模板中重复了完全相同的代码两次。我非常确定你知道任何开发者的黄金法则：DRY—不要重复自己！

让我们将卡片提取到一个单独的组件中。这很容易。在`components`文件夹中添加一个名为`Card.vue`的组件。这个组件的代码非常简单：

```js
//Card.vue
<template>
  <div class="card">
    <div class="card-block">
      <h5 class="card-title">**{{ title }}**</h5>
      <p class="card-text">**{{ text }}**</p>
      <p class="card-text"><small class="text-muted">**{{ footer }}**</small></p>
    </div>
  </div>
</template>

<script>
  export default {
    props: [**'title', 'text', 'footer'**]
  }
</script>
```

现在，让我们在`App.vue`中调用这个组件，为标题、文本和页脚添加不同的值。首先，它应该在 Vue 的`components`对象中被导入和导出：

```js
//App.vue
<script>
<...>
 **import Card from './components/Card'**
  <...>
  export default {
  <...>
 **components: {**
 **Card**
 **}**
  }
</script>
```

现在，我们可以在模板中使用`<card>`元素。我们需要绑定标题、文本和页脚。页脚实际上是显示**添加于...**的文本。因此，第一张卡片的标记看起来像这样：

```js
//App.vue
<template>
  <div class="card-columns">
    <card class="card-outline-success"**:title="'Hello!'":text="'This is our fixed card!'":footer="'Added on ' + dateToString(Date.now())"**></card>
  </div>
</div>
</template>
```

其他消息的列表将遵循相同的逻辑。对于`messages`数组中的每条消息，我们将绑定相应消息的条目（标题、文本和时间戳）。因此，消息卡片列表的标记看起来像这样：

```js
<div class="card-columns">
<...>
  <card v-for="message in messages"**:title="message.title":text="message.text":footer="'Added on ' + dateToString(message.timestamp)"**></card>
</div>
</div>
```

你可以看到，我们用两行代码替换了十四行代码！当然，我们的组件也包含一些代码，但现在，我们可以一遍又一遍地重用它。

### 练习

我们将卡片代码提取到其各自的组件中的方式无疑是很好的，但我们为第一条消息绑定属性的方式有点丑陋。如果在某个时候我们需要更改消息的文本怎么办？首先，很难在标记内找到文本。此外，在标记属性内管理文本非常困难，因为我们必须非常小心，以免弄乱双引号/单引号。而且，承认吧，这很丑陋。您在这个练习中的任务是将第一条消息的标题、文本和日期提取出来，放入数据对象中，并以与绑定其他消息相同的方式绑定它。如果您对这个练习有疑问，请查看本章的代码。

### 注意

不要被提供的代码中的`v-bind`指令所困惑。我们已经在使用它，只是它的缩写版本——在分号后面写绑定属性的名称。因此，例如，`v-bind:messages`与`:messages`是相同的。

# 部署您的应用程序

好了，现在我们手头有一个完全可用的应用程序，是时候将其公开了。为了做到这一点，我们将把它部署到 Firebase 上。

首先安装 Firebase 工具：

```js
**npm install -g firebase-tools**

```

现在，您必须告诉 Firebase 工具，您实际上是一个拥有账户的 Firebase 用户。为此，您必须使用 Firebase 工具登录。运行以下命令：

```js
**firebase login**

```

按照说明进行登录。

现在，您必须在应用程序中初始化 Firebase。从应用程序根目录调用以下内容：

```js
**firebaseinit**

```

您将被问一些问题。对于第一个问题，请选择第三个选项：

![部署您的应用程序](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00016.jpeg)

对于第一个问题，选择 Hosting 选项

从项目列表中选择`PleaseIntroduceYourself`项目以关联到应用程序。

初始化已完成。检查项目文件夹中是否已创建名为`firebase.json`的文件。该文件可以包含无数个配置。在这方面，请查看官方 Firebase 文档[`firebase.google.com/docs/hosting/full-config`](https://firebase.google.com/docs/hosting/full-config)。对于我们来说，部署的公共目录的基本指示就足够了。`vue-cli`构建生产就绪资产的目录称为`dist`；因此，我们希望部署该目录的内容。因此，请将以下代码添加到您的`firebase.json`文件中：

```js
{
  "hosting": {
    "public": "**dist**",
    "ignore": [
      "firebase.json",
      "**/.*",
      "**/node_modules/**"
    ]
  }
}
```

不要忘记保存您的`firebase.json`文件。现在让我们构建和部署我们的应用程序。听起来像是一个很大的 DevOps 任务，对吧？其实并不是很大。运行`npm build`，然后运行`firebase deploy`。

```js
**npm run build**
**firebase deploy**

```

有多难？成功部署后，Firebase 将输出您项目的 URL。现在，您可以开始使用它并将其发送给您的朋友。这可能不是世界上最美丽的 URL，对吧？也许您想将其连接到您的域名？当然，这是可能的！

# 额外里程-将您的 Firebase 项目连接到自定义域

将 Firebase 项目连接到自定义域名非常容易。首先，当然，您需要购买这个域名。对于这个应用程序，我购买了*pleaseintroduceyourself*域名，使用最便宜的顶级域名`.xyz`。在 GoDaddy 上，每年花费我一美元多一点（[`godaddy.com`](https://godaddy.com)）。拥有了您的域名之后，就非常容易了。转到项目的 Firebase Web 控制台。点击左侧的**托管**选项卡。然后，点击**连接域**按钮：

![额外里程-将您的 Firebase 项目连接到自定义域](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00017.jpeg)

点击连接域按钮

在弹出窗口中，输入您的域名：

![额外里程-将您的 Firebase 项目连接到自定义域](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00018.jpeg)

输入您的域名

它会建议您向您的域名添加 TXT DNS 记录。只需打开您的 DNS 提供商页面，选择您的域名，找出如何添加 DNS 记录，并添加类型为`TXT`的记录。在我的情况下，使用 GoDaddy，记录添加部分看起来像这样：

![额外里程-将您的 Firebase 项目连接到自定义域](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00019.jpeg)

向我们的域名添加 DNS TXT 记录

握手建立后（注意，可能需要一些时间），Firebase 将建议您进行最后一步-向您的域名添加**A**记录。按照与上一步完全相同的步骤进行；只是不再添加类型为`TXT`的记录，而是添加类型为**A**的记录。

直到更改完全传播需要一些时间。在我的情况下，大约需要一个小时。过一段时间，您将能够使用`https://<您的域名>.<您的顶级域名>`地址打开您的新页面。在我的情况下，正如您已经知道的那样，它是[`pleaseintroduceyourself.xyz/`](https://pleaseintroduceyourself.xyz/)。

# 总结

在本章中，我们按照教程从头开始开发了一个单页面应用程序。我们使用 Vue.js 框架来构建我们的应用程序，使用 Bootstrap 框架来应用样式，使用 Firebase 平台来管理应用程序的持久层和托管。

尽管能够取得可观的成果（一个完全功能的部署应用程序），但我们在不了解背后发生的事情的情况下完成了所有工作。教程没有解释 Vue.js、Bootstrap 或 Firebase 是什么。我们只是理所当然地接受了它。

在下一章中，我们将详细了解底层技术。我们将做以下事情：

+   仔细研究 Vue.js 框架，从基本理解开始，然后涵盖诸如指令、数据绑定、组件、路由等主题

+   深入了解 Bootstrap 框架，查看可以使用它实现什么以及如何实现

+   更好地了解 Firebase 平台；我们将获得一些基本的了解，并涉及更复杂的主题，如数据存储或函数

+   了解使用这三个不同项目的不同技术，为我们的应用程序增加简单性、强大性和灵活性


# 第二章：底层-教程解释

在上一章中，我们从头开始构建了一个简单的单页面应用程序。我们使用 Vue.js 来实现应用程序的功能，使用 Bootstrap 使其美观，并使用 Firebase 来管理应用程序的后端部分。

在本章中，我们将深入了解所有这些技术，看看它们如何以及为什么能够很好地协同工作。我们将主要讨论 Vue.js，因为这将是我们构建应用程序的首选框架。然后，我们将涉及 Bootstrap 和 Firebase，以基本了解这些技术有多强大。话虽如此，在本章中我们将：

+   讨论 Vue.js 框架、反应性和数据绑定。我们不仅将涵盖 Vue.js 的基础知识，还将深入探讨诸如指令、组件、路由等主题。

+   讨论 Bootstrap 框架。我们将看到它可以实现什么，讨论它如何有助于布局应用程序，并讨论它的组件如何为您的应用程序提供有用的自包含功能。

+   讨论 Firebase 平台。我们将看到它是什么，它提供了哪些功能，并且如何使用其 API 将这些功能带到应用程序中。

+   检查所有提到的技术如何结合在一起，以实现在开发复杂事物时的简单性。

# Vue.js

官方 Vue.js 网站建议 Vue 是一个渐进式 JavaScript 框架：

![Vue.js](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00020.jpeg)

来自官方 Vue.js 网站的截图

这意味着什么？以非常简化的方式，我可以将 Vue.js 描述为一个为 Web 应用程序带来反应性的 JavaScript 框架。

不可否认的是，每个应用程序都有一些数据和一些界面。在某种程度上，界面负责显示数据。数据可能在运行时发生变化，也可能不会。界面通常必须以某种方式对这些变化做出反应。界面可能有一些交互元素，这些元素可能会或可能不会被应用程序的用户使用。数据通常必须对这些交互做出反应，因此，其他界面元素必须对已对数据所做的更改做出反应。所有这些听起来都很复杂。这种复杂架构的一部分可以在后端实现，靠近数据所在的地方；另一部分可能在前端实现，靠近界面。

Vue.js 允许我们简单地将数据绑定到界面并放松。所有数据和界面之间必须发生的反应都将自动发生。让我们看一个非常简单的例子，我们将在页面标题上绑定一条消息。首先定义一个简单的 HTML 结构：

```js
<!DOCTYPE html>
<html>
  <head>
  <meta charset="UTF-8">
    <title>Vue.js - binding data</title>
  </head>
  <body>
    <div id="app">
      <h1>Hello, reader! Let's learn Vue.js</h1>
    </div>
  </body>
</html>
```

现在，让我们在此页面上初始化一个**Vue.js**实例，并将其数据绑定到`<h1>`元素。对于这个简单的例子，我们将使用一个独立的`Vue.js`文件。从 Vue.js 官方页面[`vuejs.org/js/vue.js`](https://vuejs.org/js/vue.js)下载它。在`<script>`标签中导入它。现在让我们初始化一个**Vue**实例。Vue.js 实例需要的最少的是要附加到的**元素**和`data`对象。我们想要将我们的 Vue 实例附加到具有`app` ID 的主`<div>`标记。让我们还创建一个包含名称条目的数据对象：

```js
var data = {name:'Olga'}
```

让我们用这些数据创建我们的 Vue.js 实例：

```js
new Vue({
  el: '#app',
 **data**
})
```

现在让我们将`data`绑定到我们的 HTML 元素上。我们将使用双大括号(`{{}}`)来实现这一点。一旦元素被附加到`Vue`实例上，它内部的所有内容都变得特殊 - 即使是大括号。双大括号内的任何内容都将被解释和计算。因此，如果您在大括号内放入，例如，`2 + 2`，`4`将在页面上呈现。试一试。任何表达式，任何语句都将被编译和计算。不要太激动，不要开始在这些括号内编写大段的 JavaScript 代码。让我们把计算留给脚本逻辑，脚本逻辑写在脚本所在的地方。使用括号访问您传递给`Vue`实例的数据。因此，在我们的例子中，如果您在 HTML 标记中的任何位置插入`{{name}}`，您将看到我们在数据对象中传递给`Vue`实例的名称。例如，用`{{name}}`替换`<h1>`元素中的`reader`：

```js
<h1>Hello, **{{name}}**! Let's learn Vue.js</h1>
```

刷新页面后，您会看到我们传递给 Vue 实例的名称被呈现出来。尝试在开发者工具控制台中更改`data.name`属性。您会立即看到更改被传播。我们在这里看到的是**单向数据绑定** - 数据发生的更改会被动地传播到绑定数据的元素。Vue.js 还支持**双向数据绑定**；因此，页面上元素发生的更改也会传播到绑定元素的数据中。

为了实现这一点，只需使用`v-model`属性将给定的数据片段绑定到元素上。例如，让我们在页面上添加一个文本输入，并将其绑定到数据属性`name`：

```js
<input type="text"**v-model="name"**>
```

现在，一旦您开始在文本输入中输入，更改将立即传播到绑定到此数据片段的任何其他元素：

![Vue.js](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00021.jpeg)

数据的更改会通过所有绑定的元素进行响应式传播

HTML 标记和 JavaScript 代码的完整代码如下：

```js
<body>
  <div id="app">
    <div>
      <label for="name">What's your name? </label>
      <input id="name" type="text" **v-model="name"**>
    </div>
    <h1>Hello, <strong>**{{name}}**</strong>! Let's learn Vue.js</h1>
  </div>
  <script src="vue.js"></script>
  <script>
 **var data = {name:'Olga'}**

 **new Vue({**
 **el: '#app',**
 **data**
 **})**
  </script>
</body>
```

如您所见，这一点都不难。您只需要将`data`传递给`Vue`实例，并将其绑定到页面的元素上。Vue 框架会处理其他所有事情。在接下来的章节中，我们将了解使用 Vue.js 还有哪些可能性，以及如何启动一个 Vue.js 项目。

## Vue 项目-入门

现在，我们知道了 Vue.js 的用途和主要重点，我们想要动手开始一个 Vue.js 项目，并探索所有 Vue.js 的特性。有很多种方式可以将 Vue 包含到项目中。让我们一起来探索它们。

### 直接包含在脚本中

您可以通过下载 Vue.js 并在`<script>`标签中包含它来使用 Vue.js。实际上，在上一节中我们已经这样做了。因此，如果您已经运行了一个项目并想要使用一些 Vue.js 特性，您可以简单地包含`vue.js`文件并使用它。

### CDN

如果您不想自己下载和管理 Vue 版本，可以简单地使用 CDN 版本。只需在项目中包含[`unpkg.com/vue`](https://unpkg.com/vue)脚本，您就可以开始了！它将始终与最新的 Vue 版本同步：

```js
<script src="**https://unpkg.com/vue**"></script>
```

### NPM

如果您全身心投入 Node.js 开发，您可以简单地向您的`package.json`文件添加一个`npm`依赖项。只需在项目的根目录上运行`npm install`：

```js
**npm install vue --save**

```

### Vue-cli

Vue 提供了一个漂亮干净的命令行界面，非常适合启动新项目。首先，您必须安装**vue-cli**：

```js
**npm install --global vue-cli**

```

现在，您可以使用 Vue 命令行界面开始一个全新的项目。查看*vue-cli*存储库，获取详细文档：[`github.com/vuejs/vue-cli`](https://github.com/vuejs/vue-cli)。

如您所见，可以使用不同的模板设置项目——从简单的单个 HTML 页面项目开始，到复杂的 webpack 项目设置。用于搭建 Vue 项目的命令如下：

```js
**vue init <template-name><project-name>**

```

以下模板可用：

+   webpack：这是一个具有`vue-loader`的功能齐全的 webpack 设置。它支持热重载、linting、测试、各种预处理器等等。

+   webpack-simple：这是一个简单的 webpack 设置，对于快速原型设计非常有用。

+   browserify：这是一个具有 vueify 的功能齐全的 browserify 设置，还支持热重载、linting 和单元测试。

+   browserify-simple：这是一个简单的具有 vueify 的 browserify 设置，可用于快速原型设计。

+   simple：这将生成一个包含 Vue.js 的简单 HTML 页面。非常适合快速功能探索。

还可以创建自定义模板。查看[`github.com/vuejs/vue-cli#custom-templates`](https://github.com/vuejs/vue-cli#custom-templates)上的文档并尝试一下。

在本书中，我们将使用`webpack`模板。我们将包括一些加载器，并使用 linters、单元测试和端到端测试技术。要使用`webpack`模板引导项目，只需运行以下代码行：

```js
**vue init webpack my-project**

```

现在我们知道如何使用*vue-cli*搭建项目，让我们看看除了我们在上一节中已经探索过的内容之外，Vue 还提供了什么。

## Vue 指令

Vue 指令只不过是附加到 HTML 元素的**属性**。这些指令为您的模板提供了一些额外的功能。

所有这些指令都以前缀`v-`开头。为什么？因为这是*Vue*！您已经在上一节中使用了其中一些。现在，我们将看看存在哪些指令以及您可以用它们做什么。

### 条件渲染

打开我们的 Hello 页面并删除用户的输入。发生了一些不太美观的事情：

![条件渲染](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00022.jpeg)

“你好，！”

根据用户输入的不同条件，有可能有趣地渲染**你好，**名称消息。如果有名称，则渲染它；如果没有名称，则不渲染。

例如，只有在存在名称时才渲染**你好，**名称消息。指令`v-show`和`v-if`正是用于条件渲染的。打开此示例的`index.html`文件，让我们进行更改。将`Hello, <strong>{{name}}</strong>!`部分包装到`span`中，并添加一个带有`name`值的`v-show`属性：

```js
<h1>**<span v-show="name">**Hello, <strong>{{name}}</strong>! **</span>**Let's learn Vue.js</h1>
```

现在，如果您刷新页面并完全删除输入，消息将只显示**让我们学习 Vue.js**：

![条件渲染](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00023.jpeg)

v-show 属性允许条件渲染

尝试用`v-show`指令替换`v-if`指令。最终结果将是相同的。那么为什么两者都存在呢？查看开发者工具的元素选项卡，尝试添加或删除输入框中的文本。您会发现，在`v-show`的情况下，如果条件不满足，条件性 span 将只获得`display:none`属性。在`v-if`的情况下，元素将完全消失：

![条件渲染](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00024.jpeg)

使用 v-show 属性操作显示 CSS 属性，而使用 v-if 属性会完全添加/删除一个元素

我们何时使用这两个属性？如果有很多元素应该根据一些数据可见（这些数据真的很动态，所以在运行时会经常发生），我建议使用`v-show`属性，因为在 DOM 中添加或删除元素是一个相当昂贵的操作，可能会影响应用程序的性能甚至 DOM 本身。另一方面，如果元素应该有条件地渲染一次，比如在应用程序启动时，请使用`v-if`属性。如果某些元素不应出现，它们将不会被渲染。因此，页面上的元素数量将减少。因此，应用程序的计算成本也将减少，因为现在它要经过和计算的元素更少。

### 文本与 HTML

我相信你已经从上一章中非常了解如何使用胡须语法`{{}}`绑定一些数据。

由于这是一本关于编程的技术书籍，我们必须在这里有一只猫![文本与 HTML](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00025.jpeg)！猫很容易渲染。它的 Unicode 是`U+1F638`；因此，我们只需在 HTML 中添加`&#x1f638;`代码：

```js
<div>**&#x1f638;**</div>
```

当然，我们会有一只猫：

![文本与 HTML](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00026.jpeg)

表情猫对我们说你好

这很好，但是如果我们想用狗代替猫，我们将不得不使用谷歌寻找另一个代表狗的 Unicode 并替换它。如果在某个时候我们想用独角兽替换它，我们将不得不运行相同的过程。此外，仅仅通过查看我们的代码，我们将无法说出我们实际渲染的是什么，除非我们知道所有表情符号代码是`&hearts;`。将表情符号的名称映射到它们的代码可能是一个好主意。

让我们添加一些它们的地图。打开你的 HTML 文件，将以下代码添加到`<script>`区域：

```js
//index.html
<script>
  const animalCodes = {
    dog: '&#x1f436;',
    cat: '&#x1f638;',
    monkey: '&#x1f435;',
    unicorn: '&#x1f984;'
  }
  const data = {
    animalCodes
  }

  new Vue({
    el: '#app',
    data
  })
</script>
```

现在，您可以将此地图的值绑定到您的 HTML 元素。让我们尝试使用 mustache 注释来做到这一点：

```js
<div>{{animalCodes.cat}}</div>
```

刷新页面。结果并不完全符合我们的预期，是吗？

![文本与 HTML](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00027.jpeg)

代码被呈现，而不是实际的猫表情符号

这是因为 mustache 插值实际上是插值文本。使用 mustache 插值与使用`v-text`指令是一样的：

```js
<div **v-text="animalCodes.cat"**></div>
```

我们实际上想要渲染的不是文本；我们想要渲染的是作为 HTML 呈现的表情符号的 Unicode 值！这在 Vue.js 中也是可能的。只需用`v-html`指令替换`v-text`指令：

```js
<div **v-html="animalCodes.cat"**></div>
```

现在，我们将重新获得我们的猫，并且当我们查看代码时，我们确切地知道我们正在渲染什么。

因此，请记住使用`v-text`指令或 mustache 注释进行文本插值，使用`v-html`指令进行纯 HTML 插值。

### 循环

在上一节中，我们在页面上放了一只猫。在本节中，我想要整个动物园！想象一下，我们的动物园有一只猫![循环](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00028.jpeg)，一只狗![循环](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00029.jpeg)，一只猴子![循环](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00030.jpeg)，当然还有一只独角兽![循环](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00031.jpeg)。我们想要在有序列表中显示我们的动物园。当然，您可以编写一个简单的标记，看起来像这样：

```js
<ol>
  <li>&#x1f638;</li>
  <li>&#x1f436;</li>
  <li>&#x1f435;</li>
  <li>&#x1f984;</li>
</ol>
```

然而，这会使您的代码难以阅读，如果您想要向您的动物园添加更多动物或删除其中一个，您必须牢记所有这些代码。在上一节中，我们为 emoji 动物 Unicode 添加了一个地图。让我们在我们的标记中使用它。您已经学会了我们必须使用`v-html`指令，以便代码被插值为 HTML。因此，我们的标记将如下所示：

```js
<div id="app">
  <ol>
    <li v-html="**animalCodes.cat**"></li>
    <li v-html="**animalCodes.dog**"></li>
    <li v-html="**animalCodes.monkey**"></li>
    <li v-html="**animalCodes.unicorn**"></li>
  </ol>
</div>
```

看起来更好了，但仍然有一些可以改进的地方。想象一下，如果您想要渲染来自 emoji 世界的所有动物！有很多。对于每种动物，您都必须重复列表项的代码。每当您想重新排序列表，删除一些元素或添加新元素时，您都必须处理这个标记。如果我们只有一个要渲染的动物数组，然后以某种方式迭代它并渲染其中的内容，那不是很好吗？当然，是的！使用`v-for`指令是可能的。使用以下代码行创建一个动物数组：

```js
const animals = ['dog', 'cat', 'monkey', 'unicorn']
```

将其导出到`vue data`对象中：

```js
var data = {
  name:'Olga',
 **animals**,
  animalCodes
}
```

现在，您可以在`v-for`指令中使用此数组，并仅用一个替换多个`<li>`元素：

```js
<ol>
<h2><span>{{name}}! </span>Here's your Zoo</h2> 
  <li **v-for="animal in animals"** v-html="animalCodes[**animal**]"></li>
</ol>
```

结果将会很好：

![循环](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00032.jpeg)

使用`v-for`指令呈现的 Emoji 动物园

### 绑定数据

在上一节中，我们已经处理了使用 Vue.js 呈现不同数据的许多内容；所以现在，你已经熟悉了不同的绑定方式。你知道如何将数据插值为*文本*和*HTML*，你知道如何迭代数据数组。

我们还看到双向数据绑定是通过`v-model`指令实现的。我们用它将名称绑定到输入元素：

```js
<input id="name" type="text" **v-model="name"**>
```

`v-model`指令只能与`input`、`select`和`textarea`元素一起使用。它还接受一些修饰符一起使用。修饰符是影响输入的特殊关键字。有三个修饰符可以与此指令一起使用：

+   `.lazy`：这将只在更改事件上更新数据（尝试使用我们的输入，你会发现输入的更改只会影响其他部分，当按下*Enter*按钮时，而不是在每次按键时）

+   `.number`：这将把你的输入转换为数字

+   `.trim`：这将修剪用户的输入

也可以链接修饰符：

```js
<input id="name" type="text"**v-model.lazy.trim="name"**>
```

所以现在，我们几乎了解了将数据绑定到元素的一切。如果我们想要将一些数据绑定到元素的属性呢？例如，根据某些数据值动态设置图像源属性或类属性的值。我们该怎么做呢？

为此，Vue 提供了一个`v-bind`指令。使用这个指令，你可以绑定任何你想要的东西！

例如，当名称未定义时，让我们显示一个悲伤的图片，当名称被定义时，让我们显示一个高兴的图片。为此，我创建了两张图片，`glad.png`和`sad.png`，并将它们放入我的应用程序的`images`文件夹中。我还将它们的路径导出到数据对象中：

```js
//index.html
var data = {
  name:'Olga',
  animals,
  animalCodes,
 **sadSrc: 'images/sad.png',**
 **gladSrc: 'images/glad.png'**
}
```

现在，我可以创建一个图像，并使用`v-bind:src`绑定其源，我将提供一个 JavaScript 表达式作为值。这个表达式将检查名称的值。如果它被定义，将应用`glad`图像，如果没有，将应用`sad`图像：

```js
<img width="100%" **v-bind:src="name ? gladSrc : sadSrc"**>
```

`v-bind`指令的快捷方式是`:`，所以我们可以写下以下代码行：

```js
<img width="100%" **:src**="name ? gladSrc : sadSrc">
```

当`name`的值被定义时，我们的页面是这样的：

![绑定数据](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00033.jpeg)

当名称被定义时，快乐的表情图像出现

如果您从输入字段中删除名称，图像将自动更改！打开页面，尝试从输入字段中删除文本，然后再次添加。继续删除和添加，您将看到图像如何快速更改为相应的图像。这是当名称未定义时页面的外观：

![绑定数据](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00034.jpeg)

一旦输入被清除，图像源立即更改

基本上，您可以对任何属性绑定执行完全相同的操作，例如 class：

```js
<label for="name" **v-bind:class="{green: name, red: !name}"**>What's your name? </label>
```

您还可以绑定属性以传递给子组件。我们将在有关组件的部分中看到如何执行此操作。

### 处理事件

除了直接将数据绑定到元素的形式之外，我们还希望处理一些事件，因为这是我们的用户在页面上所做的事情 - 触发一些事件，以便它们发生。他们点击，他们悬停，他们提交表单 - 所有这些事件都必须以某种方式由我们处理。Vue 提供了一种非常好的方法，可以将侦听器附加到任何 DOM 元素上，并提供可以处理这些事件的方法。这些方法的好处是它们可以使用`this`关键字直接访问 Vue 数据。通过这种方式，我们可以使用方法来操作数据，而由于这些数据是响应式的，所有更改将立即传播到绑定了这些数据的元素。

要创建一个方法，您只需在 Vue 应用程序的导出部分添加一个`methods`对象。为了将此方法附加到任何事件侦听器，请在冒号后使用`v-on`指令与相应的事件。这是一个例子：

```js
v-on:sumbit="handleSubmit"
v-on:click="handleClick"
v-on:hover="handleHover"
```

此指令的快捷方式是`@`，因此我们可以将所有这些指令重写如下：

```js
@sumbit="handleSubmit"
@click="handleClick"
@hover="handleHover"
```

这应该对您来说很熟悉。您还记得我们在第一章中遵循的教程吗，*请介绍你自己 - 教程*？您还记得我们正在监听消息的`submit`方法，添加`form`并调用`addMessage`吗？看一下。我们的表单及其`submit`指令如下所示：

```js
//please-introduce-yourself/src/App.vue
<template>
  <form **@submit="addMessage"**>
  <...>
  </form>
</template>
```

然后，在`methods`部分，我们实际上定义了`addMessage`方法：

```js
//please-introduce-yourself/src/App.vue
<script>
  <...>
  export default {
  <...>
    methods: {
      addMessage (e) {
      <...>
      },
    },
  }
</script>
```

现在开始更有意义了吗？

为了更好地理解，让我们在我们的动物园页面上添加一些方法！如果你能组成自己的动物园，那不是很好吗？让我们添加一个多选元素，它将包含所有可能的选项，你的动物园将从你实际选择的东西中填充！所以，让我们这样做：

+   向我们的`animalCodes`映射添加更多动物

+   添加另一个名为`animalsForZoo`的数组

+   在显示动物园的有序列表中使用这个新数组

+   添加一个由`animalCodes`映射的键组成的多选`select`框

+   将一个`@change`监听器附加到这个选择框，它将调用`populateAnimalsForZoo`方法

+   创建一个`populateAnimalsForZoo`方法，它将使用从我们的多选元素中选择的选项填充`animalsForZoo`数组

听起来很容易吧？当然，是的！让我们开始吧。所以，首先，向我们的`animalCodes`映射添加更多动物：

```js
var animalCodes = {
  dog     : '&#x1f436;',
  cat     : '&#x1f638;',
  monkey  : '&#x1f435;',
  unicorn : '&#x1f984;',
  tiger   : '&#x1f42f;',
  mouse   : '&#x1f42d;',
  rabbit  : '&#x1f430;',
  cow     : '&#x1f42e;',
  whale   : '&#x1f433;',
  horse   : '&#x1f434;',
  pig     : '&#x1f437;',
  frog    : '&#x1f438;',
  koala   : '&#x1f43c;'
}
```

让我们重新思考一下我们的`animals`数组，并根据我们的映射生成它。这样，每当我们需要添加新的动物时，我们只需将其键值名称-unicode 添加到映射对象中，而不是维护对象和数组。所以，我们的`animals`数组将如下所示：

```js
var animals = **Object.keys**(animalCodes)
```

现在，我们需要另一个空数组。让我们称之为`animalsForZoo`，并让我们从这个新数组中填充我们的动物园。因为它是空的，我们的动物园也将是空的。然而，我们即将创建一个填充这个数组的方法。所以，创建一个数组很容易，不要忘记在数据对象中导出它：

```js
<script>
<...>
 **var animalsForZoo = []**
  var data = {
    name:'Olga',
    animals,
    animalCodes,
 **animalsForZoo**,
    sadSrc: 'images/sad.png',
    gladSrc: 'images/glad.png'
  }
  new Vue({
    el: '#app',
 **data**
  })
</script>
```

不要忘记用新的`animalsForZoo`数组替换我们动物园展示中对`animals`数组的使用：

```js
<ol>
  <li v-for="animal in **animalsForZoo**"><span class="animal" v-html="animalCodes[animal]"></span></li>
</ol>
```

我知道现在你担心你页面上的动物园是空的，但给我们几分钟，我们会照顾好的！

首先，让我们创建一个多选`select`元素，它将根据`animals`数组进行填充：

```js
<select multiple="multiple" name="animals" id="animals">
  <option **v-for="animal in animals"** :value="animal">**{{animal}}**</option>
</select>
```

现在，最后，我们将给我们的选择框添加一个事件监听器。让我们将监听器附加到 change 事件上。让我们告诉它调用`populateAnimalsForZoo`方法。我们的指令将如下所示：

```js
@change="**populateAnimalsForZoo**"
```

整个`select`元素将获得一个新属性：

```js
<select **@change="populateAnimalsForZoo"** multiple="multiple" name="animals" id="animals">
  <option v-for="animal in animals" :value="animal">{{animal}}</option>
</select>
```

太棒了！但是没有`populateAnimalsForZoo`这样的方法。但是有我们！让我们创建它。这个方法将只是遍历作为输入选择的动物的选中选项，并将它们推入`animalsForZoo`数组中：

```js
new Vue({
  el: '#app',
  data,
  methods: {
 **populateAnimalsForZoo(ev) {**
 **this.animalsForZoo = []**
 **const selected = document.querySelectorAll('#animals option:checked')**
 **for (var i = 0; i < selected.length; i++) {**
 **this.animalsForZoo.push(selected[i].value)**
 **}**
 **}**
  }
})
```

查看在`chapter2/example1-vue-intro/index.html`文件中所有这些更改后整个 HTML 和 JavaScript 代码的样子。这是我们在更改后的测试页面的样子：

![处理事件](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00035.jpeg)

动物园是根据用户的选择进行填充的

页面很混乱，对吧？然而，看看你已经通过使用这个页面学到了多少东西。而且，承认吧，这是一个有趣的学习过程！我们还没有完成。

现在你已经学会了如何添加方法和事件监听器，我将教你如何在没有这个方法和`v-bind:change`的情况下完成完全相同的事情。删除我们刚刚添加的所有代码，只需在我们的`select`元素中添加`v-model`和`animalsForZoo`值：

```js
<select **v-model="animalsForZoo"** multiple="multiple" name="animals" id="animals">
  <option v-for="animal in animals" :value="animal">{{animal}}</option>
</select>
```

现在，我们刚刚在方法中所做的一切都被 Vue 自动处理了！是不是很棒？

## Vue 组件

我们来到这一章时手头上有一个中等大小的 HTML 页面，其中包含了许多不同的部分。我们可以想到更多的事情，比如为动物园中的每只动物添加互动性，添加喂养动物的可能性，或者在每次你悬停在动物图标上时显示每只动物的有趣事实。在某个时候，让我们面对现实吧，HTML 文件以及它的 JavaScript 将变得难以维护。

你也能看到我们的可视化层（HTML）与我们的逻辑层（JavaScript）一起工作吗？所以，它们有点像形成了块、项目、砖块... 例如，我们有一段代码负责**Hello**名称部分。我们有另一个包含我们动物园的块。动物园中的每只动物都是另一个项目。

无论你想怎么称呼这些东西，它们无可否认地是结构和逻辑的分离部分，当它们聚集在一起时，形成了整个拼图。如果你用一块独特的材料建造一堵墙，并决定改变墙的一些部分，这将不是一件容易的事情。

所以，想象一下，你建造了这堵墙，并将一些黄色的星星、蓝色的多边形、红色的正方形等等融入其中。然后，你决定你的黄色星星应该是黑色的。你必须改变所有的星星。然后，你决定你的绿色椭圆应该是一个笑脸。现在怎么办？改变所有的椭圆，但首先你必须找到墙上包含这些椭圆的所有位置。这是你的墙，试着找到其中的所有椭圆：

![Vue 组件](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00036.jpeg)

墙是作为一个整体建造的，其中包含了不同颜色和形状的部分

现在，想象每个部分实际上都存在于它们各自的砖块上。你可以随意更改它们，添加它们，以及移除它们。如果你想改变一些墙体元素的外观，你只需要改变这一个砖块，所有包含这个砖块的墙体部分都会改变，因为*总的来说，它只是墙上的另一块砖*。所以，与其让墙体充满各种奇怪的内嵌部件，你只需要四块砖，然后在需要改变依赖于这块砖的墙体部分时进行更改：

![Vue 组件](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00037.jpeg)

如果你需要改变墙上的一个元素的外观，你只需要改变相应的砖块

墙是由砖块组成的。这些砖块就是我们的组件。如果我们还可以用 HTML、CSS 和 JavaScript 构建组件，并且我们的应用程序可以由这些组件构建呢？我刚刚说“如果”吗？没有“如果”。我们已经有了。Vue.js 支持基于组件的应用程序结构。使用 Vue.js 创建组件非常容易。你需要做的只有三件事：

1.  创建一个组件，并给它一个模板、数据、方法，以及你需要给它的任何东西。

1.  在 Vue 应用程序中注册它，放在`components`对象下面。

1.  在应用程序的模板中使用它。

例如，让我们创建一个简单渲染一个标题元素说**Hello**的组件。让我们称之为`HelloComponent`。它只包含模板字符串：

```js
var HelloComponent = {
  template: '<h1>Hello!</h1>'
}
```

现在，我们可以在 Vue 应用程序初始化代码中注册这个组件：

```js
new Vue({
  el: '#app',
  components: {
 **HelloComponent**
  }
})
```

现在，这个组件实际上可以在 Vue 应用程序元素的 HTML 部分中使用：

```js
<div id="app">
 **<hello-component></hello-component>**
</div>
```

所以，整个部分看起来会是这样的：

```js
<body>
  <div id="app">
    <hello-component></hello-component>
  </div>
  <script src="vue.js"></script>
  <script>
    var HelloComponent = {
      template: '<h1>Hello!</h1>'
    }
    new Vue({
      el: '#app',
      components: {
        HelloComponent
      }
    })
  </script>
</body>
```

有人可能会问，“这些组件有什么强大之处？”实际上，编写的代码量与我只编写了一个做同样事情的 HTML 代码是一样的。有什么意义呢？是的，当然，但在这个例子中，我们的组件只有一个内部模板。一个只有一行的模板。我们可以在里面放一个巨大的模板，并且我们可以在这个组件中添加一些方法和它自己的数据！比如，让我们给这个组件添加一个输入框用于输入名字，并将名字添加到它的数据对象中：

```js
var HelloComponent = {
  template: '<div>' +
  '**<input v-model="name" />**' +
  '<h1>Hello! **<strong>{{name}}</strong>**</h1>' +
  '</div>',
 **data() {**
 **return {**
 **name: ''**
 **}**
 **}**
}
```

如果你需要重复使用这个组件，你可以随意多次使用：

```js
<div id="app">
 **<hello-component></hello-component>**
 **<hello-component></hello-component>**
 **<hello-component></hello-component>**
</div>
```

然后，你将在你的页面上得到三个独立的组件：

![Vue 组件](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00038.jpeg)

使用组件有助于避免重复的代码

这些组件非常好，但仍然有大量的代码写在同一个 JavaScript 代码块中。我们在一个地方声明所有组件，如果组件太多，应用程序将再次变得难以管理。此外，在模板字符串中的 HTML 代码也不是最可维护的东西。

如果你是这样想的，我有一些好消息要告诉你。每个组件都可以存储在自己的文件中，具有自己的 HTML、JavaScript 和 CSS 代码。这些是带有`.vue`扩展名的特殊文件。在每个文件中，有一个用于 JavaScript 代码的`<script>`部分，一个用于 CSS 代码的`<style>`部分，以及一个用于 HTML 代码的`<template>`部分。这不是很方便吗？这些组件被称为单文件组件。看看第一章的代码——有一个名为`App.vue`的主组件，还有我们创建的`MessageCard.vue`组件。是不是很好？

如果你想在你的应用程序中使用单文件组件，你必须使用一些模块化捆绑工具来搭建这个应用程序，例如`webpack`。我们已经谈论过`vue-cli`以及使用`webpack`模板轻松引导 Vue 应用程序的方法。让我们将混乱的动物园页面移植到`webpack`捆绑应用程序中。运行初始化和安装脚本：

```js
**vue init webpack zoo**
**cd zoo**
**npm install**
**npm run dev**

```

现在，打开`App.vue`文件，让我们用混乱的动物园应用程序填充它。`<script>`部分看起来是这样的：

```js
<script>
  <...>
  var data = {
    name: 'Olga',
    animals,
    animalCodes,
    animalsForZoo,
 **sadSrc: '../static/images/sad.png',**
 **gladSrc: '../static/images/glad.png'**
  }
  export default {
    name: 'app',
 **data () {**
 **return data**
 **}**
  }
</script>
```

注意高亮显示的区域。我已经将图片复制到`static`文件夹中。另一个重要的事情是，组件内部的数据应该被用作返回对象的函数，而不是作为对象本身。由于数据对象仍然会成为多个组件中的一个单一实例，整个数据对象及其属性必须在一个专用函数中组装。

脚本的其余部分完全相同。

组件的模板区域与前面示例中的 HTML 结构基本相同。查看`chapter2/example3-components-started`文件夹中的代码。

让我们将一些功能提取到各个单独的组件中。如果我们将动物园提取到单独的组件中，你觉得怎么样？在`components`文件夹中创建一个`Zoo.vue`文件。将动物列表的模板复制到这个组件的`<template>`区域：

```js
//Zoo.vue
<template>
  <div v-if="animals.length > 0">
    <h2><span v-if="name">{{name}}! </span>Here's your Zoo</h2>
    <ol>
      <li v-for="animal in animals"><span class="animal"v-html="animalCodes[animal]"></span></li>
    </ol>
  </div>
</template>
```

现在，我们应该告诉这个组件，它将从调用以下组件的父组件那里接收`animals`、`name`和`animalCodes`属性：

```js
//Zoo.vue
<script>
  export default {
 **props: ['animals', 'animalCodes', 'name']**
  }
</script>
```

现在，打开主`App.vue`组件，导入`Zoo`组件，并在`components`对象中导出它：

```js
//App.vue
<script>
 **import Zoo from './components/Zoo'**
  <...>
  export default {
    name: 'app',
 **components: {**
 **Zoo**
 **}**
  }
</script>
```

现在，我们可以在模板中使用这个组件了！所以，用以下代码替换包含我们动物园的整个`div`标签：

```js
//App.vue
<template>
  <...>
 **<zoo :animals="animalsForZoo" :animalCodes="animalCodes":name="name"></zoo>**
  <...>
</template>
```

查看页面！一切都像以前一样工作！

## 练习

将动物提取为单独的组件，并在`v-for`指令内部调用它在动物园中。每个动物都必须有一个小功能，点击它的脸（在`click`上）时会显示一个小描述。我相信你会很容易解决这个练习。如果你需要帮助，请查看`example4-components/zoo`目录中的本章代码。

## Vue 路由器

**单页应用程序**（**SPA**）很棒。它们让我们的生活变得更加轻松。而且确实如此。通过一点 JavaScript 代码，你可以实现以前必须在服务器端完成的所有功能，而整个页面应该被替换以显示该功能的结果。现在对于 Web 开发人员来说是黄金时代。然而，SPA 试图解决的问题是*导航*。历史 API 和`pushState`方法（[`developer.mozilla.org/en-US/docs/Web/API/History_API`](https://developer.mozilla.org/en-US/docs/Web/API/History_API)）已经在解决这个问题，但直到它成为一种成熟的技术，这个过程已经很长时间了。

我们的用户习惯于使用浏览器的导航按钮来控制他们的“我在哪里”和“我想去哪里”。如果整个功能位于同一页上，这些按钮如何帮助导航？你如何使用 Google 分析来检查你的用户更多地访问哪个页面（实际上是相同的）？整个概念完全不同。当然，这些应用程序速度更快，因为请求的数量大大减少，当然，我们的用户对此表示感激，但他们并没有因为我们改变了实现方式而改变他们的网页浏览习惯。他们仍然想要“返回”。他们期望如果他们刷新页面，页面将在刷新按钮之前的确切位置打开。他们期望通过查看页面的 URL 并检查斜杠后面的内容来理解他们在哪里。例如，如果是`http://mySite/store`，那么这是一个商店；如果是`http://mySite/settings`，那么很可能我在某个地方可以查看我的当前设置并更改它们。

有很多方法可以实现导航，而不必将单页面应用程序转换为多页面应用程序。你可以在应用程序上包含额外的逻辑，并在需要不同 URL 时更改`window.location.href`，这将导致页面刷新，这并不好。你也可以使用 HTML5 的`history` API。这可能不是最简单的维护方式，但可能有效。

我们都知道好的开发者是懒惰的，对吧？懒惰意味着不解决已经有人解决的问题。导航问题正在被许多框架和库解决。你不仅可以使用一些帮助你处理应用程序中路由的第三方库，还可以使用你选择的框架提供的机制。Vue.js 是提供处理路由的框架之一。你只需将 URL 路径映射到你的组件，一切都会正常工作！查看`vue-router`库的官方文档[`router.vuejs.org/en/`](https://router.vuejs.org/en/)。

为了能够使用`vue-router`，你必须为你的项目安装它：

```js
**npm install vue-router –save**

```

可选地，可以在 Vue 项目初始化时选择使用`vue-router`。

现在，你可以在你的应用程序中使用 Vue 路由器。只需告诉 Vue 使用它：

```js
//main.js
import Vue from 'vue'
**import VueRouter from 'vue-router'**

**Vue.use(VueRouter)**

```

让我们创建一个简单的路由示例。我们将有三个组件，其中一个被视为`Home`组件，意味着当有人导航到根路由`/`时应该显示它。让我们称第二个为`Hello`组件，第三个为`Bye`组件。从第二章中打开`example5-router-started`代码文件，*底层-教程解释*。你会在`components`目录中找到所有描述的组件：

![Vue router](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00039.jpeg)

我们将尝试 Vue 路由的示例应用程序的结构

现在，我们必须创建一个`router`实例。构造函数接收`options`对象作为参数。这个对象可以包含不同的可配置值。最重要的是`routes`数组。这个数组的每个条目都应该包含一个指示路由的`path`和其对应`component`的对象。

首先，我们将导入所有需要的组件，然后，我们的`router`实例将如下所示：

```js
//main.js
**import Home from '@/components/Home'**
**import Hello from '@/components/Hello'**
**import Bye from '@/components/Bye'**
<...>
var router = new Router({
  mode: 'history',
  routes: [
    {
      name: 'home',
 **component: Home,**
 **path: '/'**
    },
    {
      name: 'hello',
 **component: Hello,**
 **path: '/hello'**
    },
    {
      name: 'bye',
 **component: Bye,**
 **path: '/bye'**
    }
  ]
})
```

如果你想更好地理解`mode:` `history`选项是什么，请查看文档页面[`router.vuejs.org/en/essentials/history-mode.html`](https://router.vuejs.org/en/essentials/history-mode.html)，它以非常好的方式解释了它。现在，我们必须将路由选项传递给我们的 Vue 应用程序。这个选项将指向我们的新`router`实例：

```js
//main.js
new Vue({
  el: '#app',
  template: '<App/>',
  components: { App },
 **router**
})
```

现在，整个应用程序都知道我们使用了这个路由。还有一个重要的步骤：我们需要将路由组件包含到主组件的模板中。为此，只需在`App.vue`组件的模板中包含`<router-view>`标签即可：

```js
//App.vue
<template>
  <div id="app">
    <img src="./assets/logo.png">
 **<router-view></router-view>**
  </div>
</template>
```

在[`router.vuejs.org/en/api/router-view.html`](https://router.vuejs.org/en/api/router-view.html)中更详细地查看`router-view`组件。

完成！如果你还没有运行应用程序，请运行：

```js
**npm run dev**

```

打开页面`http://localhost:8080`，检查它是否显示我们的主页组件。然后，在浏览器的地址栏中输入`http://localhost:8080/hello`和`http://localhost:8080/bye`。检查页面的内容是否根据 URL 路径实际改变：

![Vue router](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00040.jpeg)

使用 vue-router 进行基本路由

当然，你已经在考虑如何创建一个简单的菜单，将锚点`<a>`元素指向路由器中定义的路径。不要想太多。只需使用一个带有`to`属性的`<router-link>`组件，指向您选择的路径。例如，为了在我们的路由器示例应用程序中显示一个简单的导航菜单，我们可以写出类似这样的东西：

```js
//App.vue
<template>
  <div id="app">
 **<router-link to="/">Home</router-link>**
 **<router-link to="hello">Hello</router-link>**
 **<router-link to="bye">Bye</router-link>**
    <router-view></router-view>
  </div>
</template>
```

或者，如果你不想再次编写你的路径，你可以通过名称引用你的路由，并使用`v-bind:to`指令或简单地使用`:to`：

```js
//App.vue
<template>
  <div id="app">
 **<router-link :to="{name: 'home'}">Home</router-link>**
 **<router-link :to="{name: 'hello'}">Hello</router-link>**
 **<router-link :to="{name: 'bye'}">Bye</router-link>**
    <router-view></router-view>
  </div>
</template>
```

查看`example6-router`文件夹中的代码是什么样子。

打开页面，检查所有链接是否实际上都起作用！多次点击它们，并检查是否在点击浏览器的返回按钮时实际上会返回。这不是很棒吗？

## Vuex 状态管理架构

你还记得我们的`Zoo`和`animal`组件的例子吗？有一些数据必须从主组件传播到子组件的子组件。如果这个孙子组件有可能以某种方式改变数据，这种改变就必须从子组件传播到其父组件，依此类推，直到数据到达主组件。不要认为你可以简单地使用`v-model`绑定属性来做到这一点。Vue 在通过`props`将数据绑定到子组件方面有一些限制。它是严格的单向的。因此，如果父组件改变了数据，子组件的绑定将受到影响，但反过来永远不会发生。查看 Vue 官方文档关于此的说明：[`vuejs.org/v2/guide/components.html#One-Way-Data-Flow`](https://vuejs.org/v2/guide/components.html#One-Way-Data-Flow)。

如果你不相信我，让我们来试试。想象一下，在我们的动物园页面示例中，我们将介绍部分提取到单独的组件中。我在谈论我们混乱的动物园页面的这部分：

![Vuex 状态管理架构](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00041.jpeg)

如果我们想将这部分提取到单独的组件中，会怎样？

看起来很容易。我们必须声明一个组件，比如`Introduction`，告诉它将接收`name`属性，并将`App.vue`中的 HTML 复制粘贴到这个新组件中。在`App.vue`中，我们将导入这个新组件，并在 Vue 实例的`components`对象中导出它。当然，我们将用`<introduction>`标签替换已经复制到新组件的 HTML，并将`name`属性绑定到它。这不是很容易吗？我们的`Introduction.vue`文件将如下所示：

```js
//Introduction.vue
<template>
  <div>
    <label for="name" :class="{green: name, red: !name}">What's your name? </label>
    <input id="name" type="text" v-model.trim="name">
  </div>
</template>
<script>
  export default {
 **props: ['name']**
  }
</script>
```

我们的`App.vue`文件将导入、导出和调用：

```js
//App.vue
<template>
  <div id="app" class="jumbotron">
    <...>
 **<introduction :name="name"></introduction>**
    <...>
  </div>
</template>

<script>
  <...>
 **import Introduction from './components/Introduction'**

  <...>
  export default {
    components: {
      Zoo,
 **Introduction**
    }
    <...>
  }
</script>  

```

在第二章的代码包中查看此代码，*底层-教程解释*在`example7-events-started/zoo`文件夹中运行`npm install`和`npm run`：

```js
**cd example7-events-started/zoo**
**npm install**
**npm run dev**

```

查看页面。它看起来和以前一样。尝试在输入框内更改名称。首先，它不会在应该更改的其他地方更改，其次，我们的开发工具控制台充满了警告和错误：

![Vuex 状态管理架构](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00042.jpeg)

名称没有在应该更新的地方更新，控制台充满了错误

看起来文档是正确的：我们不能更改作为属性传递给子组件的数据的值。那我们该怎么办呢？我们可以发出事件并将事件监听器附加到组件，并在事件上更改数据。我们该怎么做呢？很简单。首先，让我们将被传递的属性称为不是`name`的东西，例如`initialName`。然后，打开`Introduction`组件并创建一个`data`函数，将这个组件的`name`对象绑定到`initialValueprops`。这样，我们至少告诉 Vue，我们并不打算尝试从子组件更改父级的数据。因此，`Introduction.vue`组件的`script`将如下所示：

```js
//Introduction.vue
<script>
  export default {
 **props: ['initialName']**,
    data () {
      return {
 **name: this.initialName**
      }
    }
  }
</script>
```

我们还必须改变我们在`App.vue`中将名称绑定到组件的方式：

```js
//App.vue
<introduction **:initialName="name"**></introduction>
```

现在，如果你检查页面，你至少会看到 Vue 不再抱怨我们试图做一些非法的事情。然而，如果我们试图更改名称，更改不会传播到父级，这是可以理解的；这些更改只影响组件本身的数据。现在，我们必须将`event`附加到`input`元素。这个事件将调用一个最终将事件传递给父组件的方法：

```js
//Introduction.vue
<template>
  <div>
    <...>
    <input id="name" type="text" v-model.trim="name"**@input="onInput"**>
  </div>
</template>
<script>
  export default {
    <...>
    methods: {
 **onInput () {**
 **this.$emit('nameChanged', this.name)**
 **}**
    }
  }
</script>
```

现在，我们唯一需要做的就是将 `nameChanged` 事件监听器绑定到 `<introduction>` 组件，并调用会改变 `App.vue` 数据对象名称的方法：

```js
//App.vue
<template>
<...>
<introduction @nameChanged="onNameChanged" :initialName="name"></introduction>
<...>
</template>
<script>
  export default {
<...>
 **methods: {**
 **onNameChanged (newName) {**
 **this.name = newName**
 **}**
 **}**
  }
</script>
```

检查页面。现在，一切都和以前一样！检查本章的 `example7-events/zoo` 代码文件夹中的解决方案代码。

嗯，这并不是很困难，但是我们是否想要在每次更新状态时发出所有这些事件？如果我们在组件内部有组件呢？如果我们在这些组件内部有其他组件呢？这会是事件处理的地狱吗？如果我们需要改变一些东西，我们是否需要去所有这些组件？啊！有没有一个集中式存储应用程序数据的地方，可以提供一个简单的 API 来管理数据，然后我们只需要调用这个存储的方法来检索和更新数据？嗯，这正是 Vuex 的用途！Vuex 是受 Redux 启发的集中式状态管理。查看它的官方文档 [`vuex.vuejs.org/en/`](http://vuex.vuejs.org/en/)。

现在，简而言之，Vuex store 的三个最重要的部分是 state、getters 和 mutations：

+   **State**：这是应用程序的初始状态，基本上是应用程序的数据

+   **Getters**：这正是你所想的，从 store 返回数据的函数

+   **Mutations**：这些是可以改变 store 上的数据的函数

一个 store 也可以有 actions。这些东西就像是对 mutations 的包装，具有更多的功能。如果你想了解它们是什么，请参考官方文档 [`vuex.vuejs.org/en/mutations.html`](http://vuex.vuejs.org/en/mutations.html)。

让我们将 Vuex store 添加到我们的 `Zoo` 应用程序中，以检查它的工作原理。首先，我们需要安装 `vuex`。打开 第二章 的代码，从 `example8-store-started/zoo` 文件夹中运行 `npm install`：

```js
**cd example8-store-started/zoo**
**npm install vuex --save**

```

让我们创建我们的 store。首先创建一个名为 `store` 的文件夹，里面放有 `index.js` 文件。我们将把所有的 store 数据放在这个文件中。在做这之前，告诉 Vue 我们将使用 Vuex：

```js
//store/index.js
import Vue from 'vue'
import Vuex from 'vuex'
**Vue.use(Vuex)**

```

现在，我们可以创建一个新的 Vuex 实例。它应该接收 `state`、`getters` 和 `mutations`。让我们定义它们：

```js
//store/index.js
import Vue from 'vue'
import Vuex from 'vuex'

Vue.use(Vuex)

const state = {
}

const getters = {
}

const mutations = {
}

export default new Vuex.Store({
  state,
  getters,
  mutations
})
```

不错！现在，让我们将我们应用程序中的所有数据添加到状态中：

```js
//store/index.js
const animalCodes = {
  dog: '&#x1f436;',
  <...>
  koala: '&#x1f43c;'
}
const animalsDescriptions = {
  dog: 'I am a dog, I bark',
  <...>
  koala: 'I am a koala, I love eucalyptus!'
}
const animals = Object.keys(animalCodes)
const state = {
  name: 'Olga',
  animals,
  animalCodes,
  animalsDescriptions,
  animalsForZoo: [],
  sadSrc: '../static/images/sad.png',
  gladSrc: '../static/images/glad.png'
}
```

现在，如果您在 Vue 应用程序初始化时注入存储，所有组件及其子组件都将访问`this.$store`实例。让我们注入它：

```js
//main.js
import Vue from 'vue'
import App from './App'
import store from './store'

new Vue({
  el: '#app',
  template: '<App/>',
  components: { App },
 **store**
})
```

现在，如果我们在`App.vue`中用来自存储的计算属性替换所有数据（除了`animalsForZoo`，它作为我们动物园的属性绑定），应用程序看起来将基本相同：

```js
//App.vue
<script>
  import Zoo from './components/Zoo'
  import Introduction from './components/Introduction'

  export default {
    name: 'app',
    components: {
      Zoo,
      Introduction
    },
    data () {
      return {
        animalsForZoo: []
      }
    },
 **computed: {**
 **name () {**
 **return this.$store.state.name**
 **},**
 **animals () {**
 **return this.$store.state.animals**
 **},**
 **animalCodes () {**
 **return this.$store.state.animalCodes**
 **},**
 **sadSrc () {**
 **return this.$store.state.sadSrc**
 **},**
 **gladSrc () {**
 **return this.$store.state.gladSrc**
 **}**
 **},**
    methods: {
      onNameChanged (newName) {
        this.name = newName
      }
    }
  }
</script>
```

如果您打开页面，什么都没有改变。但是，我们的更改名称交互又不起作用了！

让我们添加`mutation`来改变名称。Mutations 只是接收状态作为第一个参数以及您调用它们的任何其他参数的方法。因此，让我们称我们的 mutation 为`updateName`，并将`newName`作为第二个参数传递给它：

```js
//store/index.js
const mutations = {
 **updateName (state, newName) {**
 **state.name = newName**
 **}**
}
```

现在，我们可以使用此 mutation 来访问负责更新名称的组件`Introduction.vue`中的`this.$store.mutation`属性。我们只需更改`onInput`方法：

```js
//Introduction.vue
methods: {
  onInput (ev) {
 **this.$store.commit('updateName', ev.currentTarget.value)**
  }
}
```

顺便说一句，我们还可以删除属性并直接从存储中传递名称，就像我们在`App.vue`组件中所做的那样。然后，您可以在`App.vue`组件的模板中删除绑定到`introduction`组件的`name`。现在，您可以用来自存储的计算属性替换绑定到 Zoo 组件的属性。看看代码变得多么优雅！例如，看看这行代码：

```js
<introduction></introduction>
```

它看起来不比以下代码行好：

```js
<introduction @nameChanged="onNameChanged" :initialName="name"></introduction>
```

在`example8-store/zoo`代码文件夹中查看本章的最终代码第二章，*Under the Hood – Tutorial Explained*。请注意，我们使用了一个非常简化的版本。我们甚至没有使用任何 getters。对于更复杂的用法，我们将创建`getters`和`actions`，它们将位于它们自己的`actions.js`和`getters.js`文件中。我们还将使用`mapGetters`和`mapActions`助手。但是，对于基本的理解，我们所做的就足够了。请参考官方文档以了解有关 Vuex 存储及其使用方法的更多信息。

# Bootstrap

既然我们几乎了解了关于 Vue.js 的一切，让我们谈谈 Bootstrap。查看官方 Bootstrap 页面[`v4-alpha.getbootstrap.com/`](https://v4-alpha.getbootstrap.com/)。

![Bootstrap](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00043.jpeg)

Bootstrap—响应式项目的框架

简而言之，Bootstrap 为您提供了一组广泛的类，可以以简单轻松的方式构建几乎任何布局。

Bootstrap 为您提供了四个最重要的东西：

+   在[`v4-alpha.getbootstrap.com/layout/overview/`](https://v4-alpha.getbootstrap.com/layout/overview/)上轻松构建布局

+   在[`v4-alpha.getbootstrap.com/content/`](https://v4-alpha.getbootstrap.com/content/)上有广泛的类来为几乎任何 web 元素设置样式

+   自包含组件，如警报、徽章、模态框等，位于[`v4-alpha.getbootstrap.com/components/`](https://v4-alpha.getbootstrap.com/components/)

+   一些用于样式化图像、图表、定位、样式化和添加边框的实用程序位于[`v4-alpha.getbootstrap.com/utilities/`](https://v4-alpha.getbootstrap.com/utilities/)

如何安装 Bootstrap？它可以从 CDN 安装：

```js
<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-alpha.6/css/bootstrap.min.css" integrity="sha384-rwoIResjU2yc3z8GV/NPeZWAv56rSmLldC3R/AZzGRnGxQQKnKkoFVhFQhNUwEyJ" crossorigin="anonymous">
<script src="https://code.jquery.com/jquery-3.1.1.slim.min.js" integrity="sha384-A7FZj7v+d/sdmMqp/nOQwliLvUsJfDHW+k9Omg/a/EheAdgtzNs3hpfag6Ed950n" crossorigin="anonymous"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/tether/1.4.0/js/tether.min.js" integrity="sha384-DztdAPBWPRXSA/3eYEEUWrWCy7G5KFbe8fFjk5JAIxUYHKkDx6Qin1DkWx51bBrb" crossorigin="anonymous"></script>
<script src="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-alpha.6/js/bootstrap.min.js" integrity="sha384-vBWWzlZJ8ea9aCX4pEW3rVHjgjt7zpkNpZk+02D9phzyeVkE+jo0ieGizqPLForn" crossorigin="anonymous"></script>
```

实际上，这正是我们在第一章的`PleaseIntroduceYourself`应用程序中所拥有的，*请介绍你自己 - 教程*，以及在本章中混乱的动物园应用程序中。

## Bootstrap 组件

Bootstrap 有很多组件可以直接使用。

本章不会讨论它们所有，因为在本书的过程中我们会有几次机会去发现它们。让我们看一些只是为了有个概念。

让我们看看警报组件。你可能知道，警报是在成功填写某些表单时出现在页面上的漂亮元素。警报也是那些愤怒的红色元素，告诉你做错了什么。你需要在页面上创建一个警报元素，它会在一段时间后消失，或者给用户关闭它的可能性，只需点击**x**按钮？你可能会创建一个`div`，给它添加一些类，并添加一些 JavaScript，它会在一段时间后从 DOM 树中移除元素。使用 Bootstrap，你只需将`alert`类添加到你的`div`中，并添加另一个类，比如`alert-warning`或`alert-info`来指定警报的类型：

```js
<div class**="alert alert-success"** role="alert">
  <strong>Hello!</strong> You have successfully opened this page!
</div>
<div class**="alert alert-info"** role="alert">
  <strong>Hey!</strong> Important information - this alert cannot be closed.
</div>
<div class**="alert alert-warning"** role="alert">
  <strong>Warning!</strong> It might be raining tonight, take your umbrella!
</div>
<div class**="alert alert-danger** alert-dismissible fade show" role="alert">
  <button type="button" class="close" data-dismiss="alert" aria-label="Close">
    <span aria-hidden="true">&times;</span>
  </button>
  <strong>Failure!</strong> Since you don't like this failure alert you can simply close it.
</div>
```

这段代码将产生漂亮的警报框，看起来像这样：

![Bootstrap 组件](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00044.jpeg)

Bootstrap 警报 - 成功、信息、警告和危险

甚至像按钮这样的简单元素也可以使用 Bootstrap 以数百种不同的方式进行样式设置。同样，您可以有表示成功、危险区域、信息性或只是灰色的按钮。还有可能将按钮分组并使其看起来像链接。代码非常简单：

```js
<button type="**button**" class="**btn btn-primary**">Primary</button>
<button type="**button**" class="**btn btn-secondary**">Secondary</button>
<button type="**button**" class="**btn btn-success**">Success</button>
<button type="**button**" class="**btn btn-info**">Info</button>
<button type="**button**" class="**btn btn-link**">Link</button>
<button type="**button**" class="**btn btn-primary btn-sm**">Small button</button>
```

此代码将生成如下所示的按钮：

![Bootstrap 组件](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00045.jpeg)

Bootstrap 按钮

[`v4-alpha.getbootstrap.com/components/buttons/`](https://v4-alpha.getbootstrap.com/components/buttons)上的官方文档页面。

关于 Bootstrap 我最喜欢的一点是，您可能有一个微不足道的元素，但是当您为其添加一些 Bootstrap 的类时，它突然变得干净而漂亮。例如，创建一个带有一些`<h1>`和`<p>`元素的简单页面：

```js
<div>
  <h1>Jumbotron</h1>
  <p>
    Lorem ipsum dolor sit amet…
  </p>
</div>
```

它看起来正常，简单。现在，将`container`类添加到父`div`中。是不是好多了？还可以将`jumbotron`类添加到其中。

页面之前看起来是这样的：

![Bootstrap 组件](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00046.jpeg)

在添加 Bootstrap 类之前 div 中的内容

突然间，同一个页面看起来是这样的：

![Bootstrap 组件](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00047.jpeg)

在添加 Bootstra 之后 div 中的内容

实际上，如果您检查我们从第一章中的`PleaseIntroduceYourself`示例，*Please Introduce Yourself - Tutorial* (`chapter1/please-introuce-yourself/src/App.vue`), 您会发现这个确切的类被用于父元素。

有很多不同的组件：弹出框，工具提示，模态框等等。我们将在本书的过程中使用所有这些组件。

## Bootstrap 实用程序

您想要具有响应式浮动（向左或向右流动的元素）吗？只需将`float-left`和`float-right`类添加到您的元素中，您就不必再担心了：

```js
<div class="**float-left**">Float left on all viewport sizes</div><br>
<div class="**float-right**">Float right on all viewport sizes</div><br>
<div class="float-none">Don't float on all viewport sizes</div><br>
```

将此代码插入到您的 HTML 页面中（或者只需查看`example11-responsive-floats`文件夹中的`index.html`文件），打开它，调整窗口大小。

您可以使用简单的类轻松控制大小和间距。查看[`v4-alpha.getbootstrap.com/utilities/sizing/`](https://v4-alpha.get.bootstrap.com/utilities/sizing/)和[`v4-alpha.getbootstrap.com/utilities/spacing/.`](https://v4-alpha.get.bootstrap.com/utilities/spacing/.)

甚至可以通过将`d-flex`类添加到容器来启用 flex-box 行为。 *d*来自*display*。通过将更多类附加到您的 flex 元素，您可以控制 flex-box 的对齐和方向。在[`v4-alpha.getbootstrap.com/utilities/flexbox/`](https://v4-alpha.getbootstrap.com/utilities/flexbox/)中查看。

还有很多其他实用程序可以探索，我们将在我们的旅程中了解大部分。

## Bootstrap 布局

使用 Bootstrap，很容易控制系统的布局：

| | *Bootstrap 包括几个组件和选项，用于布置您的项目，包括包装容器，强大的 flexbox 网格系统，灵活的媒体对象和响应式实用程序类。* - ([`v4-alpha.getbootstrap.com/layout/overview/`](https://v4-alpha.getbootstrap.com/layout/overview/)) | |
| --- | --- | --- |
| | --*来自 Bootstrap* |

Bootstrap 的网格系统非常强大且易于理解。它只是由列组成的行。一切都由具有相当自我描述性名称的类来控制，比如`row`和`col`。如果你只给你的列`col`类，`row`元素内的每一列都会有相同的大小。如果你想要不同大小的列，可以玩一下行可以由 12 列组成这个事实。所以，如果你想让一些列，比方说你的一半行，给它一个类**col-6**：

```js
<div class="row">
  <div class="**col**">this is a column with class col</div>
  <div class="**col-6**">this is a column with class col-6</div>
  <div class="**col-2**">this is a column with class col-2</div>
</div>
```

这段代码将产生类似于这样的结果：

![Bootstrap layout](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00048.jpeg)

网格布局系统结合了行和列类

有趣的是，如果你调整窗口大小，你的布局不会破坏。它会相应地调整大小。你不必实现任何 CSS 黑魔法来实现这一点！这就是为什么 Bootstrap 是一个大的![Bootstrap layout](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00049.jpeg)。

# 结合 Vue.js 和 Bootstrap

当我们谈论 Vue 时，我们专门讨论了它的组件。当我们谈论 Bootstrap 时，我们也谈论了组件。这不是同一个概念吗？也许我们可以从 Bootstrap 组件创建 Vue 组件？也许我们可以！实际上，我们已经做到了！打开第一章的`PleaseIntroduceYourself`应用程序的代码。查看我们在`components`文件夹中有什么。有一样东西我们称之为`MessageCard.vue`。实际上，这是一个实现了 Bootstrap 组件的 Vue 组件（[`v4-alpha.getbootstrap.com/components/card/`](https://v4-alpha.getbootstrap.com/components/card/)）！

打开`example13-vue-bootstrap-components-started/components`文件夹。让我们将此项目用作基于 Bootstrap 警报组件创建 Vue 组件的游乐场。运行`npm install`和`run`：

```js
**cd example13-vue-bootstrap-components-started/components**
**npm install**
**npm run dev**

```

让我们创建一个名为`Alert`的 Vue 组件。该组件将包含必要的代码来模拟 Bootstrap 的警报组件行为。

在`components`文件夹内创建一个名为`Alert.vue`的文件，并添加`template`标签。我们的警报肯定会有`alert`类。但是，它的附加类（`alert-danger`，`alert-info`等）应该是可配置的。此外，它的标题和文本应该是从父组件传递的绑定属性。因此，警报组件的模板将如下所示：

```js
//Alert.vue
<template>
  <div class="alert"**:class="additionalClass"** role="alert">
    <strong**>{{title}}**</strong>**{{text}}**
  </div>
</template>
```

让我们将`additionalClass`属性实现为一个计算属性，该属性将根据父组件传递的`type`属性进行计算。因此，`Alert`组件的脚本将如下所示：

```js
//Alert.vue
<script>
export default {
 **props: ['type', 'title', 'text']**,
  computed: {
 **additionalClass () {**
 **if (!this.type) {**
 **return 'alert-success'**
 **}**
 **return 'alert-' + this.type**
 **}**
  },
  name: 'alert'
}
</script>
```

然后，我们可以从我们的主`App.vue`组件中调用它：

```js
//App.vue
<template>
  <div id="app" class="container">
    <img src="./assets/logo.png">
 **<alert :title="title" :text="text"></alert>**
  </div>
</template>

<script>
 **import Alert from './components/Alert'**
  export default {
    data () {
      return {
 **title: 'Vue Bootstrap Component',**
 **text: 'Isn\'t it easy?'**
      }
    },
    name: 'app',
    components: {
 **Alert**
    }
  }
</script>
```

您将在页面上看到一个漂亮的警报：

![结合 Vue.js 和 Bootstrap](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00050.jpeg)

我们刚刚创建了我们的 Alert Vue Bootstrap 组件

## 练习

为警报组件的标题启用默认值。因此，如果未传递`title`，它将默认为**Success**。还应该在`App.vue`父组件内创建组件时将`type`属性绑定到组件上。根据一些任意值将此属性导出为计算属性。例如，基于一些随机数，如果它可以被`3`整除，类型应为**danger**；如果它可以被`5`整除，类型应为**info**；等等。

自己去看看。转到`example13-vue-bootstrap-components/components`文件夹，特别是`App.vue`和`components/Alert.vue`组件。

## 继续结合 Vue.js 和 Bootstrap

因此，我们知道如何基于 Bootstrap 组件创建 Vue 组件。现在感觉好像很棒，可以将所有 Bootstrap 组件创建为 Vue 组件，并在我们的 Vue 应用程序中使用它们，而无需考虑 Bootstrap 类。想象一下 Vue 组件，例如`<button-success></button-success>`或`<button :type="success"></button>`。我们甚至可以基于 Bootstrap 创建一个完整的 Vue 组件库！问题是，如果已经存在，我们应该这样做吗？是的，已经有人为我们做了所有的工作。这些人已经完成了这项工作：

![结合 Vue.js 和 Bootstrap 继续](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00051.jpeg)

Bootstrap-vue 的核心团队

这些可爱的人们开发了一个叫做 Bootstrap-Vue 的东西，它确实做到了你所想的——它包含了作为 Vue.js 组件实现的完整的 Bootstrap 组件集。在[`bootstrap-vue.github.io/`](https://bootstrap-vue.github.io/)上查看它。

让我们来看看，例如，警报组件是如何在[`bootstrap-vue.github.io/docs/components/alert`](https://bootstrap-vue.github.io/docs/components/alert)实现的。它比我们的警报详细一点。数据是通过组件的标签传递的，而不是作为属性，就像我们的情况一样，这也使它更灵活。在整本书的开发过程中，我们将经常使用它。

# 什么是 Firebase？

要了解什么是 Firebase，让我们打开它的网站[`firebase.google.com/`](https://firebase.google.com/)。这是我们看到的：

![什么是 Firebase？](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00052.jpeg)

Google Firebase 首页

对于 Google 来说，Firebase 只是另一个云服务，就像 AWS 是亚马逊的，Azure 是微软的一样，不过简单一些，因为 Google 已经有了庞大的 Google 云平台。

如果你觉得你想在 Firebase 和 AWS 之间做出选择，不要忘记你很可能会去谷歌搜索。无论如何，已经有人为你做过了，所以在 Quora 上有这个问题：[`www.quora.com/Which-is-better-cloud-server-Amazon-AWS-or-Firebase`](https://www.quora.com/Which-is-better-cloud-server-Amazon-AWS-or-Firebase)。

我会说它更类似于 Heroku——它允许您轻松部署您的应用程序并将其与分析工具集成。如果您已经阅读了《Learning Vue.js 2》一书([`www.packtpub.com/web-development/learning-vuejs-2`](https://www.packtpub.com/web-development/learning-vuejs-2))，那么您已经知道我有多么喜欢 Heroku 了。我甚至有 Heroku 袜子！

![什么是 Firebase？](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00053.jpeg)

我美丽的 Heroku 袜子

然而，我觉得 Google Firebase 控制台也非常好用和简单。它还提供后端作为服务。这个后端为您的 Web 和移动应用程序共享，这在开发跨平台和跨设备应用程序时非常有帮助。Firebase 提供以下服务：

+   **身份验证**：这使用 Firebase API 来使用不同的提供者（Facebook、Google、电子邮件等）对用户进行身份验证。

+   **数据库**：这使用 Firebase 数据库 API 来存储和检索数据。无需在不同的数据库提供商之间进行选择，也无需建立连接。只需直接使用 API。

+   **托管**：这使用简单的 shell 命令托管和部署您的应用程序。

+   **存储**：这使用简单的 API 托管静态文件。

再次强调，如果您在考虑如何将您的 Vue 应用程序与 Firebase API 集成，那么请停止思考，因为已经有人为您完成了这项工作。在使用 Firebase 控制台创建项目后，您可以简单地使用 Firebase 的`vuefire`包装器来连接到您的数据库并获取数据。请访问[`github.com/vuejs/vuefire`](https://github.com/vuejs/vuefire)查看。实际上，这正是我们在第一章的`PleaseIntroduceYourself`应用程序中所做的。查看位于`App.vue`组件内的代码：

```js
//PleaseIntroduceYourself/src/App.vue
<script>
**import Firebase from 'firebase'**

let **config** = {
  apiKey: '... ',
  ...
  messagingSenderId: '...'
}

let app = **Firebase.initializeApp**(config)
let db = **app.database()**
let messagesRef = **db.ref('messages')**

export default {
  ...
 **firebase: {**
 **messages: messagesRef.limitToLast(100)**
 **}**
}
</script>
```

Firebase 对象中导出的所有内容都可以通过`this`关键字访问，就像我们访问`data`或`computed`属性一样。我们将在整本书中开发的应用程序中使用`vuefire`来更好地理解它的工作原理。

# 总结

在本章中，我们熟悉了 Vue.js、Bootstrap 和 Firebase。我们还分析了将 Vue.js 与 Bootstrap 以及 Vue.js 与 Firebase 集成的工具。

因此，现在，我们熟悉了使用单文件组件、Bootstrap 的网格系统、组件和 CSS 辅助工具来使我们的生活更轻松，并利用 Google Firebase 控制台的可能性来构建 Vue.js 应用程序。

此外，我们知道如何初始化 Vue.js 项目，并使用 Vue 指令、组件、存储和路由。

您还学会了如何利用 Bootstrap 的网格系统来实现应用程序布局的响应性。

最后但同样重要的是，您学会了如何在 Vue 应用程序中使用 Firebase API，使用`vuefire`绑定。

随着本章的结束，我们旅程的第一部分也告一段落。

在下一章中，我们将深入了解实现细节。就像潜水氧气瓶一样，我们将带走您迄今为止学到的一切！

因此，我们将开始开发整本书中将构建的应用程序，直到准备部署。我们将：

+   定义应用程序将要做什么及其要求

+   定义我们为谁构建应用程序

+   为应用程序构建基本的模型

+   使用 Vue 命令行界面搭建应用程序

你和我一样兴奋吗？那么，让我们进入下一章吧！
