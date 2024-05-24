# Vue2 设计模式最佳实践（三）

> 原文：[`zh.annas-archive.org/md5/6E739FB94554764B9B3B763043E30DA8`](https://zh.annas-archive.org/md5/6E739FB94554764B9B3B763043E30DA8)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：HTTP 和 WebSocket 通信

在本章中，我们将看看如何使用`HTTP`与服务器端 API 进行接口交互。我们将使用`HTTP GET`，`POST`，`PUT`，`PATCH`和`DELETE`创建一个应用程序，以及创建一个利用`Socket.io`库的内存实时聊天应用程序，利用 WebSockets。

在本章结束时，您将知道如何：

+   使用`json-server`创建模拟数据库 API

+   使用`Axios`创建 HTTP 请求

+   使用 WebSockets 和`Socket.io`进行客户端之间的实时通信

# HTTP

让我们首先创建一个新的 Vue.js 项目，作为我们的游乐场项目。在终端中输入以下内容：

```js
# Create a new Vue project
$ vue init webpack-simple vue-http

# Navigate to directory
$ cd vue-http
```

```js
# Install dependencies
$ npm install

# Run application
$ npm run dev
```

在 JavaScript 中有许多创建 HTTP 请求的方法。我们将使用`Axios`库在项目中使用简化的基于 promise 的方法。让我们通过在终端中输入以下内容来安装它：

```js
# Install Axios to our project
$ npm install axios --save
```

我们现在有了创建 HTTP 请求的能力；我们只需要一个 API 来指向`Axios`。让我们创建一个模拟 API。

# 安装 JSON 服务器

为了创建一个模拟 API，我们可以使用`json-server`库。这允许我们通过在项目内创建一个`db.json`文件来快速全局启动。它有效地创建了一个 GET，POST，PUT，PATCH 和 DELETE API，并将数据存储在一个文件中，附加到我们的原始 JSON 文件中。

我们可以通过在终端中运行以下命令来安装它：

```js
# Install the json-server module globally
$ npm install json-server -g
```

由于我们添加了`-g`标志，我们将能够在整个终端中全局访问`json-server`模块。

接下来，我们需要在项目的根目录下创建我们的`db.json`文件。您可以根据需要对数据集进行创意处理；我们只是简单地有一份我们可能感兴趣的课程列表：

```js
{
  "courses": [
    {
      "id": 1,
      "name": "Vue.js Design Patterns"
    },
    {
      "id": 2,
      "name": "Angular: From Beginner to Advanced"
    },
    {
      "id": 3,
      "name": "Cross Platform Native Applications with Fuse"
    }
  ]
}
```

然后我们可以通过在终端中运行以下命令来运行我们的数据库：

```js
# Run the database based on our db.json file
$ json-server db.json --watch
```

如果我们一切顺利，我们应该能够通过`http://localhost:3000`访问我们的数据库，如下成功消息所示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/77705cdb-4486-431d-b8f9-e929efaa77a4.png)

太棒了。我们已经准备好了，现在我们可以获取课程列表。

# HTTP GET

我们需要做的第一件事是将`Axios`导入到我们的`App.vue`组件中。在这种情况下，我们还可以设置一个`ROOT_URL`，因为我们只会寻找`/courses`端点：

```js
<script>
import axios from 'axios'
export default {
  data() {
    return {
      ROOT_URL: 'http://localhost:3000/courses',
      courses: []
    }
  }
}
</script>
```

这样我们就能够钩入`created()`这样的生命周期钩子，并调用一个从我们的 API 请求课程的方法：

```js
export default {
  data() {
    return {
      ROOT_URL: 'http://localhost:3000/courses',
      courses: []
    }
  },
  created() {
    this.getCourseList();
  },
  methods: {
    getCourseList() {
      axios
        .get(this.ROOT_URL)
        .then(response => {
          this.courses = response.data;
        })
        .catch(error => console.log(error));
    }
  }
}
```

这里发生了什么？我们调用了`getCoursesList`函数，该函数向我们的`http://localhost:3000/courses`端点发出了 HTTP`GET`请求。然后，它要么将课程数组设置为数据（也就是说，我们的`db.json`中的所有内容），要么仅仅在出现错误时记录错误。

然后，我们可以使用`v-`指令在屏幕上显示这个：

```js
<template>
  <div class="course-list">
    <h1>Courses</h1>
    <div v-for="course in courses" v-bind:key="course.id">
      <p>
        {{course.name}}
      </p> 
    </div>
  </div>
</template>
```

再加上一点样式，我们得到：

```js
<style>
.course-list {
  background-color: rebeccapurple;
  padding: 10px;
  width: 50%;
  text-align: center;
  margin: 0 auto;
  color: white;
}
</style>
```

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/e65701a2-f9fa-424f-a77e-fb392acbbf3b.png)

让我们继续进行 HTTP POST！

# HTTP POST

我们可以在`courseName` `div`后面添加一个输入框和`button`，允许用户向他们的学习列表中输入一个新的课程：

```js
<div>
 <input type="text" v-model="courseName" placeholder="Course name"> 
 <button @click="addCourse(courseName)">Add</button>
</div>
```

这要求我们将`courseName`变量添加到我们的`data`对象中：

```js
data() {
 return {
  ROOT_URL: 'http://localhost:3000/courses/',
  courses: [],
  courseName: '',
 };
},
```

然后，我们可以创建一个名为`addCourse`的类似方法，该方法以`courseName`作为参数：

```js
methods: {
// Omitted
 addCourse(name) {
  axios
   .post(this.ROOT_URL, { name })
   .then(response => {
     this.courses.push(response.data);
     this.courseName = ''; 
   })
   .catch(error => console.log(error));
 }
}
```

您可能会注意到它与之前的 HTTP 调用非常相似，但这次我们使用的是`.post`而不是`.get`，并传递了一个具有`name`键和值的对象。

发送 POST 请求后，我们使用`this.courses.push(response.data)`来更新客户端数组，因为虽然服务器端（我们的客户端`db.json`文件）已更新，但客户端状态没有更新。

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/5843056b-60f4-42d8-b48e-9106ab582223.png)

# HTTP PUT

接下来，我们想要做的是能够更改列表中的项目。也许在提交项目时我们犯了一个错误，因此我们想要编辑它。让我们添加这个功能。

首先，让我们告诉 Vue 跟踪我们何时正在编辑课程。用户编辑课程的意图是每当他们点击课程名称时；然后我们可以将编辑布尔值添加到我们的`data`对象中：

```js
data() {
 return {
  ROOT_URL: 'http://localhost:3000/courses/',
  courses: [],
  courseName: '',
  editing: false,
 };
},
```

然后我们的模板可以更改以反映这一点：

```js
<template>
 <div class="course-list">
  <h1>Courses</h1>
  <div v-for="course in courses" v-bind:key="course.id">
   <p @click="setEdit(course)" v-if="!editing">
   {{course.name}}
   </p>
  <div v-else>
   <input type="text" v-model="course.name">
   <button @click="saveCourse(course)">Save</button>
  </div> 
  </div>
  <div v-if="!editing">
  <input type="text" v-model="courseName" placeholder="Course name"> 
  <button @click="addCourse(courseName)">Add</button>
  </div>
 </div>
</template>
```

这里到底发生了什么？嗯，我们已经将我们的`courseName`更改为只在我们不编辑时显示（也就是说，我们没有点击课程名称）。相反，使用`v-else`指令，我们显示一个输入框和`button`，允许我们保存新的`CourseName`。

此时，我们还隐藏了添加课程按钮，以保持简单。

代码如下所示：

```js
setEdit(course) {
 this.editing = !this.editing;
},
saveCourse(course) {
 this.setEdit();
 axios
 .put(`${this.ROOT_URL}/${course.id}`, { ...course })
 .then(response => {
 console.log(response.data);
 })
 .catch(error => console.log(error));
}
```

在这里，我们在指向所选课程的端点上使用了我们的`axios`实例上的`.put`方法。作为数据参数，我们使用了展开操作符`{ ...course }`来解构课程变量以与我们的 API 一起使用。

之后，我们只是将结果记录到控制台。当我们将"Vue.js Design Patterns"字符串编辑为简单地说`Vue.js`时，它看起来是这样的：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/bf30fdfc-829c-4a50-ada7-0654d868290d.png)

耶！我们要看的最后一件事是 DELETE 和从我们的数据库中删除项目。

# HTTP DELETE

为了从我们的列表中删除项目，让我们添加一个`button`，这样当用户进入编辑模式（通过点击一个项目）时，他们可以删除那个特定的课程：

```js
<div v-else>
  <input type="text" v-model="course.name">
  <button @click="saveCourse(course)">Save</button>
  <button @click="removeCourse(course)">Remove</button>
</div> 
```

我们的`removeCourse`函数如下：

```js
removeCourse(course) {
  axios
    .delete(`${this.ROOT_URL}/${course.id}`)
    .then(response => {
      this.setEdit();
      this.courses = this.courses.filter(c => c.id != course.id);
    })
    .catch(error => console.error(error));
},
```

我们调用`axios.delete`方法，然后过滤我们的`courses`列表，除了我们删除的课程之外的每个课程。然后更新我们的客户端状态，并使其与数据库一致。

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/69091533-e283-418f-8b4d-46d41fc6048f.png)

在本章的这一部分中，我们根据我们的 REST API 创建了一个简单的“我想学习的课程”列表。它当然可以被抽象为多个组件，但由于这不是应用程序的核心重点，我们只是在一个组件中完成了所有操作。

接下来，让我们使用 Node 和`Socket.io`制作一个实时聊天应用程序。

# 使用 Node 和 Socket.io 制作实时聊天应用程序

在本节中，我们将使用 Node 和`Socket.io`创建一个实时聊天应用程序。我们将使用 Node.js 和 Express 框架编写少量代码，但它都是您所熟悉和喜爱的 JavaScript。

在您的终端中运行以下命令以创建一个新项目：

```js
# Create a new Vue project
$ vue init webpack-simple vue-chat

# Navigate to directory
$ cd vue-chat

# Install dependencies
$ npm install

# Run application
$ npm run dev
```

然后我们可以创建一个服务器文件夹，并初始化一个`package.json`，用于服务器特定的依赖项，如下所示：

```js
# Create a new folder named server
$ mkdir server

# Navigate to directory
$ cd server

# Make a server.js file
$ touch server.js

# Initialise a new package.json
$ npm init -y

# Install dependencies
$ npm install socket.io express --save
```

# 什么是 Socket.io？

在我们之前的例子中，如果我们想要从服务器获取新数据，我们需要发出另一个 HTTP 请求，而使用 WebSockets，我们可以简单地拥有一个一致的事件监听器，每当事件被触发时就会做出反应。

为了在我们的聊天应用程序中利用这一点，我们将使用`Socket.io`。这是一个客户端和服务器端的库，允许我们快速轻松地使用 WebSockets。它允许我们定义和提交事件，我们可以监听并随后执行操作。

# 服务器设置

然后，我们可以使用 Express 创建一个新的 HTTP 服务器，并通过在`server.js`中添加以下内容来监听应用程序连接：

```js
const app = require('express')();
const http = require('http').Server(app);
const io = require('socket.io')(http);
const PORT = 3000;

http.listen(PORT, () => console.log(`Listening on port: ${PORT}`));

io.on('connection', socket => {
  console.log('A user connected.');
});
```

如果我们在`server`文件夹内的终端中运行`node server.js`，我们应该会看到消息“Listening on port: 3000”。这意味着一旦我们在客户端应用程序中实现`Socket.io`，我们就能够监视每当有人连接到应用程序时。

# 客户端连接

为了捕获客户端连接，我们需要在 Vue 应用程序中安装`Socket.io`。我们还将使用另一个名为`vue-socket.io`的依赖项，在 Vue 应用程序中为我们提供更流畅的实现。

在终端中运行以下命令，确保你在根目录下（即不在`server`文件夹中）：

```js
# Install socket.io-client and vue-socket.io
$ npm install socket.io-client vue-socket.io --save
```

# 设置 Vue 和 Socket.io

让我们转到我们的`main.js`文件，这样我们就可以注册`Socket.io`和`Vue-Socket.io`插件。你可能还记得如何在之前的章节中做到这一点：

```js
import Vue from 'vue';
import App from './App.vue';
import SocketIo from 'socket.io-client';
import VueSocketIo from 'vue-socket.io';

export const Socket = SocketIo(`http://localhost:3000`);

Vue.use(VueSocketIo, Socket);

new Vue({
  el: '#app',
  render: h => h(App),
});
```

在上述代码块中，我们导入必要的依赖项，并创建对我们当前运行在端口`3000`上的 Socket.io 服务器的引用。然后我们使用`Vue.use`添加 Vue 插件。

如果我们做的一切都正确，我们的客户端和服务器应该在彼此交流。我们应该在终端中看到以下内容：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/3c4ef978-1ba1-461b-acdd-7ca0f26ea14c.png)

# 确定连接状态

现在我们已经添加了 Vue-Socket.io 插件，我们可以在 Vue 实例内部访问 sockets 对象。这使我们能够监听特定事件，并确定用户是否连接或断开 WebSocket 连接。

在`App.vue`中，让我们在屏幕上显示一条消息，如果我们与服务器连接/断开连接：

```js
<template>
  <div>
    <h1 v-if="isConnected">Connected to the server.</h1>
    <h1 v-else>Disconnected from the server.</h1>
  </div>
</template>

<script>
export default {
  data() {
    return {
      isConnected: false,
    };
  },
  sockets: {
    connect() {
      this.isConnected = true;
    },
    disconnect() {
      this.isConnected = false;
    },
  },
};
</script>
```

除了 sockets 对象之外，这里不应该有太多新的东西。每当我们连接到 socket 时，我们可以在`connect()`钩子内运行任何代码，`disconnect()`也是一样。我们只是翻转一个布尔值，以便在屏幕上显示不同的消息，使用`v-if`和`v-else`指令。

最初，我们得到了 Connected to the server，因为我们的服务器正在运行。如果我们在终端窗口中使用*CTRL* + *C*停止服务器，我们的标题将更改以反映我们不再具有 WebSocket 连接的事实。以下是结果：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/60c8c31c-5543-4391-80a3-23c99418f74c.png)

# 创建连接状态栏

让我们用这个概念玩一些游戏。我们可以创建一个 components 文件夹，然后创建一个名为`ConnectionStatus.vue`的新组件。在这个文件中，我们可以创建一个状态栏，当用户在线或离线时向用户显示：

```js
<template>
  <div>
    <span v-if="isConnected === true" class="bar connected">
      Connected to the server.
    </span>
    <span v-else class="bar disconnected">
      Disconnected from the server.
    </span>
  </div>
</template>

<script>
export default {
  props: ['isConnected'],
};
</script>

<style>
.bar {
  position: absolute;
  bottom: 0;
  left: 0;
  right: 0;
  text-align: center;
  padding: 5px;
}

.connected {
  background: greenyellow;
  color: black;
}

.disconnected {
  background: red;
  color: white;
}
</style>
```

虽然我们当前应用程序中只有一个屏幕，但我们可能希望在多个组件中使用这个组件，所以我们可以在`main.js`中全局注册它：

```js
import App from './App.vue';
import ConnectionStatus from './components/ConnectionStatus.vue';

Vue.component('connection-status', ConnectionStatus);
```

然后，我们可以编辑我们的 `App.vue` 模板以使用此组件，并将当前连接状态作为 prop 传递：

```js
<template>
  <div>
    <connection-status :isConnected="isConnected" />
  </div>
</template>
```

这是我们的结果：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/4663d9db-06e7-4894-a7ce-f5f279ecd755.png)

接下来，我们可以创建一个导航栏组件，使我们的用户界面更完整。

# 导航栏

导航栏组件除了简单显示我们应用程序的名称外，不会有太多用途。您可以更改此功能，以包括其他功能，例如登录/注销、添加新的聊天频道或任何其他特定于聊天的用户操作。

让我们在 `components` 文件夹中创建一个名为 `Navbar.vue` 的新组件：

```js
<template>
  <div v-once>
    <nav class="navbar">
      <span>Socket Chat</span>
    </nav>
  </div>
</template>

<script>
export default {};
</script>

<style>
.navbar {
  background-color: blueviolet;
  padding: 10px;
  margin: 0px;
  text-align: center;
  color: white;
}
</style>
```

您可能会注意到在这个 `div` 上添加了 `v-once` 指令。这是我们第一次看到它，但由于这个组件完全是静态的，我们可以告诉 Vue 不要监听任何更改，只渲染一次。

然后，我们必须删除 HTML body 内部的任何默认填充或边距。在根目录中创建一个名为 `styles.css` 的文件，其中包含这些属性：

```js
body {
 margin: 0px;
 padding: 0px;
}
```

然后，我们可以像这样将其添加到我们的 `index.html` 文件中：

```js
<head>
 <meta charset="utf-8">
 <title>vue-chat</title>
 <link rel="stylesheet" href="styles.css">
</head>
```

接下来，我们需要全局注册此组件。如果您觉得可以的话，请尝试在 `main.js` 中自行完成。

这要求我们导入 `Navbar` 并像这样注册它：

```js
import Navbar from './components/Navbar.vue'

Vue.component('navigation-bar', Navbar);
```

然后我们可以将其添加到我们的 `App.vue` 文件中：

```js
<template>
  <div>
    <navigation-bar />
    <connection-status :isConnected="isConnected" />
  </div>
</template>
```

接下来，让我们创建我们的 `MessageList` 组件来保存消息列表。

# 消息列表

通过创建一个接受消息数组的 prop 的新组件，我们可以在屏幕上显示消息列表。在 `components` 文件夹中创建一个名为 `MessageList.vue` 的新组件：

```js
<template>
 <div>
  <span v-for="message in messages" :key="message.id">
  <strong>{{message.username}}: </strong> {{message.message}}
  </span>
 </div>
</template>

<script>
export default {
 props: ['messages'],
};
</script>

<style scoped>
div {
 overflow: scroll;
 height: 150px;
 margin: 10px auto 10px auto;
 padding: 5px;
 border: 1px solid gray;
}
span {
 display: block;
 padding: 2px;
}
</style>
```

这个组件非常简单；它只是使用 `v-for` 指令遍历我们的 `messages` 数组。我们使用适当的 prop 将消息数组传递给这个组件。

不要将此组件全局注册，让我们在 `App.vue` 组件内部特别注册它。在这里，我们还可以向 `messages` 数组添加一些虚拟数据：

```js
import MessageList from './components/MessageList.vue';

export default {
 data() {
  return {
   isConnected: false,
   messages: [
    {
     id: 1,
     username: 'Paul',
     message: 'Hey!',
    },
    {
     id: 2,
     username: 'Evan',
     message: 'How are you?',
    },
   ],
  };
 },
 components: {
 MessageList,
},
```

然后我们可以将 `message-list` 组件添加到我们的模板中：

```js
 <div class="container">
  <message-list :messages="messages" />
 </div>
```

我们根据数据对象中找到的消息数组将消息作为 prop 传递。我们还可以添加以下样式：

```js
<style>
.container {
 width: 300px;
 margin: 0 auto;
}
</style>
```

这样做将使我们的消息框居中显示在屏幕上，并限制 `width` 以进行演示。

我们正在取得进展！这是我们的消息框：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/6f9659ba-e0cf-4719-9d60-66c855f8e40d.png)

接下来呢？嗯，我们仍然需要能够向我们的列表中添加消息的功能。让我们接下来处理这个。

# 向列表添加消息

在 components 文件夹中创建一个名为`MessageForm.vue`的新组件。这将用于将消息输入到列表中。

我们可以从以下开始：

```js
<template>
  <form @submit.prevent="sendMessage">
    <div>
      <label for="username">Username:</label>
      <input type="text" name="username" v-model="username">
    </div>
    <div>
      <label for="message">Message:</label>
      <textarea name="message" v-model="message"></textarea>
    </div>
    <button type="submit">Send</button>
  </form>
</template>

<script>
export default {
  data() {
    return {
      username: '',
      message: '',
    };
  },
};
</script>

<style>
input,
textarea {
  margin: 5px;
  width: 100%;
}
</style>

```

这本质上允许我们捕获用户对所选`username`和`message`的输入。然后我们可以使用这些信息在`sendMessage`函数中向我们的`Socket.io`服务器发送数据。

通过将`@submit.prevent`添加到我们的表单而不是`@submit`，我们确保覆盖了提交表单的默认行为；这是必要的，否则我们的页面会重新加载。

让我们去注册我们的表单在`App.vue`中，即使我们还没有连接任何操作：

```js
import MessageList from './components/MessageList.vue';

export default {
 // Omitted
 components: {
   MessageList,
   MessageForm,
 },
}
```

然后我们可以将其添加到我们的模板中：

```js
<template>
  <div>
    <navigation-bar />
    <div class="container">
      <message-list :messages="messages" />
      <message-form />
    </div>
    <connection-status :isConnected="isConnected" />
  </div>
</template>
```

现在我们的应用程序看起来是这样的：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/92c939a6-e392-4e4b-b07f-2183edd45d5c.png)

# 使用 Socket.io 进行服务器端事件

为了发送新消息，我们可以在我们的`server.js`文件中监听名为`chatMessage`的事件。

这可以在我们的原始连接事件内完成，确保我们按 socket 逐个 socket 地监听事件：

```js
io.on('connection', socket => {
  console.log('A user connected.');

  socket.on('chatMessage', message => {
    console.log(message);
  })
});
```

如果我们从客户端发送`chatMessage`事件，那么它应该随后在我们的终端内记录出这条消息。让我们试一试！

因为我们对`server.js`文件进行了更改，所以我们需要重新启动 Node 实例。在运行`server.js`的终端窗口中按下*CTRL* + *C*，然后再次运行 node `server.js`。

# Nodemon

或者，您可能希望使用一个名为`nodemon`的模块，在进行任何更改时自动执行此操作。

在您的终端内运行以下命令：

```js
# Install nodemon globally
$ npm install nodemon -g
```

然后我们可以运行：

```js
# Listen for any changes to our server.js file and restart the server
$ nodemon server.js
```

太好了！让我们回到我们的`MessageForm`组件并创建`sendMessage`函数：

```js
methods: {
 sendMessage() {
   this.socket.emit('chatMessage', {
     username: this.username,
     message: this.message,
   });
 },
},
```

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/b7ba289b-f5fc-401e-babe-33f9f49a203a.png)

此时点击发送还没有将消息添加到数组中，但它确实在我们的终端内显示了发送的消息！让我们来看一下：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/ec545d8a-9493-4d3a-ab16-e55ec33fbe42.png)

事实证明，我们不必写太多代码来利用我们的 WebSockets。让我们回到`App.vue`组件并向我们的 sockets 对象添加一个名为`chatMessage`的函数。注意这与事件名称相同，这意味着每次触发此事件时我们都可以运行特定的方法：

```js
export default {
// Omitted
 sockets: {
  connect() {
   this.isConnected = true;
  },
  disconnect() {
   this.isConnected = false;
  },
  chatMessage(messages) {
   this.messages = messages;
  },
 },
}
```

我们的客户端代码现在已经连接并监听`chatMessage`事件。问题在于我们的服务器端代码目前没有向客户端发送任何内容！让我们通过在 socket 内部发出一个事件来解决这个问题：

```js
const app = require('express')();
const http = require('http').Server(app);
const io = require('socket.io')(http);
const PORT = 3000;

http.listen(PORT, () => console.log(`Listening on port: ${PORT}`));

const messages = [];

const emitMessages = () => io.emit('chatMessage', messages);

io.on('connection', socket => {
  console.log('A user connected.');

  emitMessages(messages);

  socket.on('chatMessage', message => {
    messages.push(message);

    emitMessages(messages);
  });
});
```

我们使用一个名为 messages 的数组将消息保存在内存中。每当客户端连接到我们的应用程序时，我们也会向下游发送这些消息（所有先前的消息都将显示）。除此之外，每当数组中添加新消息时，我们也会将其发送给所有客户端。

如果我们打开两个 Chrome 标签，我们应该能够进行自我导向的对话！

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/597f3540-a0de-4b8e-9ea6-0f7ced878124.png)

然后我们可以在另一个标签页中与自己交谈！

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/a4adcb16-28ff-4fa1-b43b-b8e88bfe7dd3.png)

# 总结

在本章中，我们学习了如何使用`Axios`库和`json-server`在 Vue 中创建 HTTP 请求。这使我们能够与第三方 API 进行交互，并增强我们的 Vue 应用程序。

我们还学习了如何使用 WebSockets 和`Socket.io`创建一个更大的应用程序。这使我们能够与连接到我们的应用程序的其他客户端进行实时通信，从而实现更多的可能性。

我们已经走了很长的路！为了真正利用 Vue，我们需要掌握路由器并了解高级状态管理概念。这将在接下来的章节中讨论！


# 第八章：Vue 路由模式

路由是任何**单页应用程序**（**SPA**）的重要组成部分。本章重点介绍了最大化 Vue 路由器，并涵盖了从在页面之间路由用户到参数到最佳配置的一切。

在本章结束时，我们将涵盖以下内容：

+   在 Vue.js 应用程序中实现路由

+   使用动态路由匹配创建路由参数

+   将路由参数作为组件属性传递

# 单页应用程序

现代 JavaScript 应用程序实现了一种称为 SPA 的模式。在其最简单的形式中，它可以被认为是根据 URL 显示组件的应用程序。由于模板被映射到路由，因此无需重新加载页面，因为它们可以根据用户导航的位置进行注入。

这是路由器的工作。

通过这种方式创建我们的应用程序，我们能够增加感知和实际速度，因为我们的应用程序更加动态。如果我们加入在上一章学到的概念（HTTP），你会发现它们与 SPA 模型紧密相连。

# 使用路由器

让我们启动一个游乐场项目并安装 `vue-router` 库。这使我们能够在我们的应用程序内利用路由，并为我们提供现代 SPA 的功能。

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

由于我们在构建系统中使用 webpack，我们已经用 `npm` 安装了路由器。然后我们可以在 `src/main.js` 中初始化路由器：

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

这实际上将 `VueRouter` 注册为全局插件。插件只是一个接收 `Vue` 和 `options` 作为参数的函数，并允许诸如 `VueRouter` 这样的库向我们的 Vue 应用程序添加功能。

# 创建路由

然后我们可以在 `main.js` 文件中定义两个小组件，它们只是有一个模板，显示带有一些文本的 `h1`：

```js
const Hello = { template: `<h1>Hello</h1>` };
const World = { template: `<h1>World</h1>`};
```

然后，为了在特定的 URL（如 `/hello` 和 `/world`）上在屏幕上显示这些组件，我们可以在我们的应用程序内定义路由：

```js
const routes = [
  { path: '/hello', component: Hello },
  { path: '/world', component: World }
];
```

现在我们已经定义了我们想要在应用程序中使用的组件以及路由，我们需要创建一个新的 `VueRouter` 实例并传递路由。

尽管我们使用了 `Vue.use(VueRouter)`，但我们仍然需要创建一个新的 `VueRouter` 实例并初始化我们的路由。这是因为仅仅将 `VueRouter` 注册为插件，就可以让我们在 Vue 实例中访问路由选项：

```js
const router = new VueRouter({
  routes
});
```

然后我们需要将`router`传递给我们的根 Vue 实例：

```js
new Vue({
  el: '#app',
  router,
  render: h => h(App)
});
```

最后，为了在我们的`App.vue`组件内显示路由组件，我们需要在`template`内添加`router-view`组件：

```js
<template>
  <div id="app">
    <router-view/>
  </div>
</template>
```

如果我们然后导航到`/#/hello/`或`/#/world`，将显示适当的组件：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/4c87430e-b1d6-41bc-9401-153bae4b2ec1.png)

# 动态路由

我们还可以根据特定参数动态匹配路由。这可以通过在参数名称前指定带有冒号的路由来实现。以下是使用类似问候组件的示例：

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

我们取得了很大的进展，但重要的是要知道，当我们导航到参数化的 URL 时，如果参数发生变化（即从`/hello/paul`到`/hello/katie`），组件生命周期钩子不会再次触发。我们很快会看到这一点！

# 路由 props

让我们将我们的`/hello/name`路由更改为将`name`参数作为`component` prop 传递，可以通过在路由中添加`props: true`标志来实现：

```js
const routes = [
  { path: '/hello', component: Hello },
  { path: '/hello/:name', component: HelloName, props: true},
]
```

然后我们可以更新我们的组件以接受具有`id`名称的 prop，并在生命周期钩子中将其记录到控制台中：

```js
const HelloName = {
  props: ['name'],
  template: `<h1>Hello {{ name }}</h1>`,
  created() {
    console.log(`Hello ${this.name}`)
  }
}
```

如果我们尝试导航到不同的动态路由，我们会看到创建的钩子只触发一次（除非我们刷新页面），即使我们的页面显示了正确的名称：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/e76bda75-afd5-40c1-8476-ec547d867264.png)

# 组件导航守卫

我们如何解决生命周期钩子问题？在这种情况下，我们可以使用所谓的导航守卫。这允许我们钩入路由器的不同生命周期，例如`beforeRouteEnter`、`beforeRouteUpdate`和`beforeRouteLeave`方法。

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

如果我们在导航到`/hello/{name}`下的不同路由后检查 JavaScript 控制台，我们将能够看到用户要去哪里以及他们来自哪里。`to`和`from`对象还让我们访问`params`、查询、完整路径等等。

虽然我们正确地获得了日志声明，但是如果我们尝试在路由之间导航，您会注意到我们的应用程序不会使用参数`name` prop 进行更新。这是因为在守卫内完成任何计算后，我们没有使用`next`函数。让我们添加进去：

```js
  beforeRouteUpdate(to, from, next) {
    console.log(to);
    console.log(from);
    console.log(`Hello ${to.params.name}`)
    next();
  },
```

# beforeRouteEnter

我们还可以利用`beforeRouteEnter`在进入组件路由之前执行操作。这里有一个例子：

```js
 beforeRouteEnter(to, from, next) {
  console.log(`I'm called before entering the route!`)
  next();
 }
```

我们仍然必须调用`next`将堆栈传递给下一个路由处理程序。

# beforeRouteLeave

我们还可以钩入`beforeRouteLeave`，以便在我们从一个路由导航离开时执行操作。由于我们已经在这个钩子的上下文中在这个路由上，我们可以访问组件实例。让我们来看一个例子：

```js
 beforeRouteLeave(to, from, next) {
 console.log(`I'm called before leaving the route!`)
 console.log(`I have access to the component instance, here's proof! 
 Name: ${this.name}`);
 next();
 }
```

再次，在这个实例中，我们必须调用`next`。

# 全局路由钩子

我们已经了解了组件导航守卫，虽然这些守卫是基于组件的，但您可能希望建立全局钩子来监听导航事件。

# beforeEach

我们可以使用`router.beforeEach`来全局监听应用程序中的路由事件。如果您有身份验证检查或其他应该在每个路由中使用的功能，这是值得使用的。

这是一个简单记录用户要去和来自的路由的示例。以下每个示例都假定路由器存在于类似以下的范围内：

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

在确认导航之前触发`beforeResolve`全局路由守卫，但重要的是要知道，这仅在所有特定于组件的守卫和异步组件已解析之后才会发生。

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

我们还可以钩入全局`afterEach`函数，允许我们执行操作，但我们无法影响导航，因此只能访问`to`和`from`参数：

```js
router.afterEach((to, from) => {
 console.log(`After each:`)
 console.log(`Route to`, to)
 console.log(`Route from`, from)
});
```

# 解析堆栈

现在我们已经熟悉了各种不同的路由生命周期钩子，值得在尝试导航到另一个路由时调查整个解析堆栈：

1.  **触发路由更改**：这是任何路由生命周期的第一阶段，也是我们*尝试*导航到新路由时触发的。例如，从`/hello/Paul`到`/hello/Katie`。此时尚未触发任何导航守卫。

1.  **触发组件离开守卫**：接下来，任何离开守卫都会被触发，例如`beforeRouteLeave`，在加载的组件上。

1.  **触发全局 beforeEach 守卫**：由于可以使用`beforeEach`创建全局路由中间件，这些函数将在任何路由更新之前被调用。

1.  **触发重用组件中的本地 beforeRouteUpdate 守卫**：正如我们之前看到的，每当我们使用不同的参数导航到相同的路由时，生命周期钩子不会被触发两次。相反，我们使用`beforeRouteUpdate`来触发生命周期更改。

1.  **在组件中触发 beforeRouteEnter**：在导航到任何路由之前每次都会调用这个。在这个阶段，组件没有被渲染，因此没有访问`this`组件实例。

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

1.  **触发全局 beforeResolve 钩子**：在组件内提供守卫和异步路由组件已经被解析后，我们现在可以钩入全局的`router.beforeResolve`方法，允许我们在这个阶段执行操作。

1.  **导航**：所有先前的导航守卫都已触发，用户现在成功导航到了一个路由。

1.  **触发 afterEach 钩子**：虽然用户已经被导航到了路由，但事情并没有到此为止。接下来，路由器会触发一个全局的`afterEach`钩子，该钩子可以访问`to`和`from`参数。由于在这个阶段路由已经被解析，它没有下一个参数，因此不能影响导航。

1.  **触发 DOM 更新**：路由已经被解析，Vue 可以适当地触发 DOM 更新。

1.  **在 beforeRouteEnter 中触发 next 中的回调**：由于`beforeRouteEnter`没有访问组件的`this`上下文，`next`参数采用一个回调函数，在导航时解析为组件实例。一个例子可以在这里看到：

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

然后，我们可以添加一个方法，将新的路由推送到路由堆栈上*:*。

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

在这一点上，每当我们选择一个按钮，它应该随后将用户导航到适当的路由。`$router.push()`函数可以采用各种不同的参数，这取决于你如何设置你的路由。以下是一些例子：

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

我们还可以用`router.replace`替换当前的历史堆栈，而不是将导航项推送到堆栈上。这是一个例子：

```js
this.$router.replace({ path: routeName });
```

# router.go

如果我们想要向用户后退或前进导航，我们可以使用`router.go`；这本质上是`window.history` API 的一个抽象。让我们看一些例子：

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

我们还可以延迟加载我们的路由，以利用 webpack 的代码拆分。这使我们比急切加载路由时拥有更好的性能。为了做到这一点，我们可以创建一个小型的试验项目。在终端中运行以下命令：

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

让我们首先创建两个组件，命名为`Hello.vue`和`World.vue`，放在`src/components`目录下：

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

现在我们已经创建了`Hello.vue`组件，让我们创建第二个`World.vue`：

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

然后我们可以像通常一样在`main.js`中初始化我们的路由：

```js
import Vue from 'vue';
import VueRouter from 'vue-router';

Vue.use(VueRouter);
```

主要区别在于导入组件的方式。这需要使用`syntax-dynamic-import` Babel 插件。通过在终端中运行以下命令将其安装到您的项目中：

```js
$ npm install --save-dev babel-plugin-syntax-dynamic-import
```

然后我们可以更新`.babelrc`以使用新的插件：

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

然后我们可以通过在 Chrome 中查看开发者工具|网络选项卡来查看其结果，同时浏览我们的应用程序：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/62c576a9-3b61-4e57-960e-160e30b8d7bc.png)

每个路由都被添加到自己的捆绑文件中，随后我们得到了改进的性能，因为初始捆绑文件要小得多：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/1ca0081c-83e0-46f9-939d-5f4d4acaac13.png)

# 一个 SPA 项目

让我们创建一个使用 RESTful API 和我们刚学到的路由概念的项目。通过在终端中运行以下命令来创建一个新项目：

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

我们可以首先在应用程序中启用`VueRouter`插件。为了做到这一点，我们可以在`src/router`目录下创建一个名为`index.js`的新文件。我们将使用这个文件来包含所有特定于路由的配置，但根据底层功能将每个路由分别放在不同的文件中。

让我们导入并添加路由插件：

```js
import Vue from 'vue';
import VueRouter from 'vue-router';

Vue.use(VueRouter)
```

# 定义路由

为了将路由分离到应用程序中的不同文件中，我们首先可以在`src/components/user`下创建一个名为`user.routes.js`的文件。每当我们有一个需要路由的不同功能集时，我们可以创建我们自己的`*.routes.js`文件，然后将其导入到路由的`index.js`中。

现在，我们只需导出一个新的空数组：

```js
export const userRoutes = [];
```

然后我们可以将路由添加到我们的`index.js`中（即使我们还没有定义任何路由）：

```js
import { userRoutes } from '../components/user/user.routes';

const routes = [...userRoutes];
```

我们正在使用 ES2015+扩展运算符，它允许我们使用数组中的每个对象而不是数组本身。

然后初始化路由，我们可以创建一个新的`VueRouter`并传递路由，如下所示：

```js
const router = new VueRouter({
  // This is ES2015+ shorthand for routes: routes
  routes,
});
```

最后，让我们导出路由，以便在我们的主 Vue 实例中使用它：

```js
export default router;
```

在`main.js`中，让我们导入路由并将其添加到实例中，如下所示：

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

我们应用程序的第一部分将是一个主页，显示来自 API 的用户列表。我们过去曾使用过这个例子，所以你应该熟悉涉及的步骤。让我们在`src/components/user`下创建一个名为`UserList.vue`的新组件。

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

现在可以随意添加自己的测试数据。我们将很快从 API 请求这些数据。

当我们创建了我们的组件后，我们可以在`user.routes.js`中添加一个路由，每当激活'/'（或您选择的路径）时显示这个组件：

```js
import UserList from './UserList';

export const userRoutes = [{ path: '/', component: UserList }];
```

为了显示这个路由，我们需要更新`App.vue`，以便随后将内容注入到`router-view`节点中。让我们更新`App.vue`来处理这个问题：

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

我们的应用程序应该显示一个单一的用户。让我们创建一个 HTTP 实用程序来从 API 获取数据。

# 从 API 获取数据

在`src/utils`下创建一个名为`api.js`的新文件。这将用于创建`Axios`的基本实例，然后我们可以在其上执行 HTTP 请求：

```js
import axios from 'axios';

export const API = axios.create({
 baseURL: `https://jsonplaceholder.typicode.com/`
})
```

然后我们可以使用`beforeRouteEnter`导航守卫来在有人导航到'/'路由时获取用户数据：

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

然后我们发现屏幕上显示了用户列表，如下截图所示，每个用户都表示为不同的列表项。下一步是创建一个`detail`组件，注册详细路由，并找到一种链接到该路由的方法：

！[](assets/985caab3-024e-44ae-bbdc-a24caf20342f.png)

# 创建详细页面

为了创建一个详细页面，我们可以创建`UserDetail.vue`并按照与上一个组件类似的步骤进行操作：

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

由于我们的详细页面中永远不应该有多个用户，因此`userInfo`变量被创建为 JavaScript 对象而不是数组。

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

然后我们在浏览器中看一下，我们可以看到只有一个用户列出，下面的信息来自于与该用户相关联的用户详细信息：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/4fbeea0a-1218-4af9-bee1-f67dbd6d2cad.png)

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

然后我们可以在我们的`UserDetail.vue`组件中添加另一个`<router-view>`标签来显示子路由。模板现在看起来像这样：

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

然后我们转到浏览器，我们可以看到数据的显示方式正如我们计划的那样，用户信息显示在左侧，帖子显示在右侧：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/e23a65d4-d0d5-425a-96e6-490e124b718b.png)

哒哒！我们现在已经创建了一个具有多个路由、子路由、参数等的 Vue 应用程序！

# 摘要

在本节中，我们学习了 Vue Router 以及如何使用它来创建单页面应用程序。因此，我们涵盖了从初始化路由器插件到定义路由、组件、导航守卫等等的所有内容。我们现在有必要的知识来创建超越单一组件的 Vue 应用程序。

现在我们已经扩展了我们的知识，并了解了如何使用 Vue Router，我们可以在下一章中继续处理`Vuex`中的状态管理。


# 第九章：使用 Vuex 进行状态管理

在本章中，我们将研究使用`Vuex`的状态管理模式。`Vuex`可能并非每个应用程序都需要，但当适合使用它时，了解它的重要性以及如何实现它是非常重要的。

在本章结束时，您将完成以下工作：

+   了解了`Vuex`是什么以及为什么应该使用它

+   创建您的第一个 Vuex 存储

+   调查了 actions、mutations、getters 和 modules

+   使用 Vue devtools 逐步执行`Vuex`变化

# 什么是 Vuex？

状态管理是现代 Web 应用程序的重要组成部分，随着应用程序的增长，管理这些状态是每个项目都面临的问题。`Vuex`旨在通过强制使用集中式存储来帮助我们实现更好的状态管理，本质上是应用程序内的单一真相来源。它遵循类似于 Flux 和 Redux 的设计原则，并且还与官方 Vue devtools 集成，为出色的开发体验。

到目前为止，我已经谈到了*状态*和*状态管理*，但您可能仍然对这对于您的应用程序意味着什么感到困惑。让我们更深入地定义这些术语。

# 状态管理模式（SMP）

我们可以将状态定义为组件或应用程序中变量/对象的当前值。如果我们将我们的函数视为简单的`输入->输出`机器，那么这些函数外部存储的值构成了我们应用程序的当前状态。

注意我已经区分了**组件级**和**应用级**状态。组件级状态可以定义为限定在一个组件内的状态（即我们组件内的数据函数）。应用级状态类似，但通常用于多个组件或服务之间。

随着我们的应用程序不断增长，跨多个组件传递状态变得更加困难。我们在本书的前面看到，我们可以使用事件总线（即全局 Vue 实例）来传递数据，虽然这样可以实现，但最好将我们的状态定义为一个统一的集中存储的一部分。这使我们能够更容易地思考应用程序中的数据，因为我们可以开始定义**actions**和**mutations**，这些总是生成状态的新版本，并且管理状态变得更加系统化。

事件总线是一种简单的状态管理方法，依赖于单一视图实例，在小型 Vuex 项目中可能有益，但在大多数情况下，应该使用 Vuex。随着我们的应用变得更大，使用 Vuex 清晰地定义我们的操作和预期的副作用，使我们能够更好地管理和扩展项目。

所有这些是如何结合在一起的一个很好的例子可以在以下截图中看到（[`vuex.vuejs.org/en/intro.html`](https://vuex.vuejs.org/en/intro.html)）：

Vuex 状态流

让我们将这个例子分解成一个逐步的过程：

1.  初始**状态**在 Vue 组件内呈现。

1.  Vue 组件分派一个**Action**来从**后端 API**获取一些数据。

1.  然后触发一个**Commit**事件，由**Mutation**处理。这个**Mutation**返回一个包含来自**后端 API**的数据的新版本的状态。

1.  然后可以在 Vue **Devtools**中看到这个过程，并且您有能力在应用程序中发生的先前状态的不同版本之间“时间旅行”。

1.  然后在 Vue 组件内呈现新的**状态**。

我们 Vuex 应用程序的主要组件是存储，它是我们所有组件的单一真相来源。存储可以被读取但不能直接改变；它必须有变异函数来进行任何更改。虽然这种模式一开始可能看起来很奇怪，如果您以前从未使用过状态容器，但这种设计允许我们以一致的方式向我们的应用程序添加新功能。

由于 Vuex 是原生设计用于与 Vue 一起工作，因此存储默认是响应式的。这意味着从存储内部发生的任何更改都可以实时看到，无需任何黑客技巧。

# 思考状态

作为一个思考练习，让我们首先定义我们应用程序的目标以及任何状态、操作和潜在的变化。您现在不必将以下代码添加到您的应用程序中，所以请随意继续阅读，我们将在最后把它全部整合在一起。

让我们首先将状态视为键/值对的集合：

```js
const state = {
 count: 0 // number
}
```

对于我们的计数器应用程序，我们只需要一个状态元素——当前计数。这可能有一个默认值为`0`，类型为数字。因为这很可能是我们应用程序内唯一的状态，所以您可以考虑这个状态在这一点上是应用程序级别的。

接下来，让我们考虑用户可能想要在我们的计数器应用程序中执行的任何动作类型。

然后，这三种动作类型可以被分派到 store，因此我们可以执行以下变化，每次返回一个新的状态版本：

+   **增加**：将当前计数加一（0 -> 1）

+   **减少**：将当前计数减一（1 -> 0）

+   **重置**：将当前计数重置为零（n -> 0）

我们可以想象，此时我们的用户界面将使用正确的绑定版本更新我们的计数。让我们实现这一点，使其成为现实。

# 使用 Vuex

现在我们已经详细了解了由`Vuex`驱动的应用程序的组成部分，让我们创建一个游乐项目，以利用这些功能！

在终端中运行以下命令：

```js
# Create a new Vue project
$ vue init webpack-simple vuex-counter

# Navigate to directory
$ cd vuex-counter

# Install dependencies
$ npm install

# Install Vuex
$ npm install vuex

# Run application
$ npm run dev
```

# 创建一个新的 store

让我们首先创建一个名为`index.js`的文件，放在`src/store`内。这是我们将用来创建新 store 并整合各种组件的文件。

我们可以先导入`Vue`和`Vuex`，并告诉 Vue 我们想要使用`Vuex`插件：

```js
import Vue from 'vue';
import Vuex from 'vuex';

Vue.use(Vuex);
```

然后我们可以导出一个包含所有应用程序状态的状态对象的新`Vuex.Store`。我们导出这个对象，以便在必要时在其他组件中导入状态：

```js
export default new Vuex.Store({
  state: {
    count: 0,
  },
}); 
```

# 定义动作类型

然后我们可以在`src/store`内创建一个名为`mutation-types.js`的文件，其中包含用户可能在我们应用程序中执行的各种操作：

```js
export const INCREMENT = 'INCREMENT';
export const DECREMENT = 'DECREMENT';
export const RESET = 'RESET';
```

虽然我们不必像这样明确地定义我们的动作，但尽可能使用常量是一个好主意。这使我们能够更好地利用工具和 linting 技术，并且能够一目了然地推断整个应用程序中的动作。

# 动作

我们可以使用这些动作类型来提交一个新的动作，随后由我们的 mutations 处理。在`src/store`内创建一个名为`actions.js`的文件：

```js
import * as types from './mutation-types';

export default {
  types.INCREMENT {
    commit(types.INCREMENT);
  },
  types.DECREMENT {
    commit(types.DECREMENT);
  },
  types.RESET {
    commit(types.RESET);
  },
};
```

在每个方法内部，我们正在解构返回的`store`对象，只取`commit`函数。如果我们不这样做，我们将不得不像这样调用`commit`函数：

```js
export default {
 types.INCREMENT {
  store.commit(types.INCREMENT);
 }
}
```

如果我们重新查看我们的状态图，我们可以看到在提交一个动作后，该动作会被变化器捕捉到。

# 变化

变化是存储状态可以改变的唯一方法；这是通过提交/分派一个动作来完成的，就像之前看到的那样。让我们在`src/store`内创建一个名为`mutations.js`的新文件，并添加以下内容：

```js
import * as types from './mutation-types';

export default {
  types.INCREMENT {
    state.count++;
  },
  types.DECREMENT {
    state.count--;
  },
  types.RESET {
    state.count = 0;
  },
};
```

您会注意到，我们再次使用我们的动作类型来定义方法名；这是可能的，因为 ES2015+ 中有一个名为计算属性名的新功能。现在，每当一个动作被提交/分发时，改变器将知道如何处理这个动作并返回一个新的状态。

# 获取器

现在我们可以提交动作，并让这些动作返回状态的新版本。下一步是创建获取器，以便我们可以在整个应用程序中返回状态的切片部分。让我们在 `src/store` 中创建一个名为 `getters.js` 的新文件，并添加以下内容：

```js
export default {
  count(state) {
    return state.count;
  },
};
```

由于我们有一个微不足道的例子，为这个属性使用获取器并不是完全必要的，但是当我们扩展我们的应用程序时，我们将需要使用获取器来过滤状态。把它们想象成状态中的值的计算属性，所以如果我们想要返回这个属性的修改版本给视图层，我们可以这样做：

```js
export default {
  count(state) {
    return state.count > 3 ? 'Above three!' : state.count;
  },
};
```

# 组合元素

为了将所有这些整合在一起，我们必须重新访问我们的 `store/index.js` 文件，并添加适当的 `state`、`actions`、`getters` 和 `mutations`：

```js
import Vue from 'vue';
import Vuex from 'vuex';

import actions from './actions';
import getters from './getters';
import mutations from './mutations';

Vue.use(Vuex);

export default new Vuex.Store({
  state: {
    count: 0,
  },
  actions,
  getters,
  mutations,
});
```

在我们的 `App.vue` 中，我们可以创建一个 `template`，它将给我们当前的计数以及一些按钮来 `增加`、`减少` 和 `重置` 状态：

```js
<template>
  <div>
    <h1>{{count}}</h1>
    <button @click="increment">+</button>
    <button @click="decrement">-</button>
    <button @click="reset">R</button>
  </div>
</template>
```

每当用户点击按钮时，一个动作将从以下方法中分发：

```js
import * as types from './store/mutation-types';

export default {
  methods: {
    increment() {
      this.$store.dispatch(types.INCREMENT);
    },
    decrement() {
      this.$store.dispatch(types.DECREMENT);
    },
    reset() {
      this.$store.dispatch(types.RESET);
    },
  },
}
```

我们再次使用常量来提供更好的开发体验。接下来，为了利用我们之前创建的获取器，让我们定义一个 `computed` 属性：

```js
export default {
  // Omitted
  computed: {
    count() {
      return this.$store.getters.count;
    },
  },
}
```

然后我们就有了一个显示当前计数并可以增加、减少或重置的应用程序。

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/89a16d62-66d5-4e32-90f7-7d8d8e0c604b.png)

# 负载

如果我们想让用户决定要增加计数的数量怎么办？假设我们有一个文本框，我们可以在其中添加一个数字，并按照这个数字增加计数。如果文本框设置为 `0` 或为空，我们将增加计数 `1`。

因此，我们的模板将如下所示：

```js
<template>
  <div>
    <h1>{{count}}</h1>

    <input type="text" v-model="amount">

    <button @click="increment">+</button>
    <button @click="decrement">-</button>
    <button @click="reset">R</button>
  </div>
</template>
```

我们将金额值放在我们的本地组件状态上，因为这不一定需要成为主要的 Vuex 存储的一部分。这是一个重要的认识，因为这意味着如果有必要，我们仍然可以拥有本地数据/计算值。我们还可以更新我们的方法，将金额传递给我们的动作/改变器：

```js
export default {
  data() {
    return {
      amount: 0,
    };
  },
  methods: {
    increment() {
      this.$store.dispatch(types.INCREMENT, this.getAmount);
    },
    decrement() {
      this.$store.dispatch(types.DECREMENT, this.getAmount);
    },
    reset() {
      this.$store.dispatch(types.RESET);
    },
  },
  computed: {
    count() {
      return this.$store.getters.count;
    },
    getAmount() {
      return Number(this.amount) || 1;
    },
  },
};
```

然后我们需要更新`actions.js`，因为现在它接收`state`对象和我们的`amount`作为参数。当我们使用`commit`时，让我们也将`amount`传递给 mutation：

```js
import * as types from './mutation-types';

export default {
  types.INCREMENT {
    commit(types.INCREMENT, amount);
  },
  types.DECREMENT {
    commit(types.DECREMENT, amount);
  },
  types.RESET {
    commit(types.RESET);
  },
};
```

因此，我们的 mutation 看起来与以前类似，但这次我们根据数量增加/减少：

```js
export default {
  types.INCREMENT {
    state.count += amount;
  },
  types.DECREMENT {
    state.count -= amount;
  },
  types.RESET {
    state.count = 0;
  },
};
```

哒哒！现在我们可以根据文本值增加计数：

！[](assets/4061a26c-2e6b-4d07-bbd9-2a3648259a74.png)

# Vuex 和 Vue devtools

现在我们有了一种一致的通过动作与存储进行交互的方式，我们可以利用 Vue devtools 来查看我们的状态随时间的变化。如果您还没有安装 Vue devtools，请访问第二章，*Vue 项目的正确创建*，以获取更多关于此的信息。

我们将使用计数器应用程序作为示例，以确保您已经运行了此项目，并在 Chrome（或您的浏览器的等效物）中右键单击检查元素。如果我们转到 Vue 选项卡并选择 Vuex，我们可以看到计数器已加载初始应用程序状态：

！[](assets/ca392021-f7a8-4315-aa1b-cf5cf83597a1.png)

从上面的截图中，您可以看到计数状态成员以及任何 getter 的值。让我们点击几次增量按钮，看看会发生什么：

！[](assets/156c812f-8a82-40c6-92c6-4f76d75b84d2.png)

太棒了！我们可以看到 INCREMENT 动作以及状态和 getter 的后续更改，以及有关 mutation 本身的更多信息。让我们看看如何在我们的状态中进行时间旅行：

！[](assets/6af553b2-d7ed-4625-bfa0-e254c368672a.png)

在上面的截图中，我选择了第一个动作的时间旅行按钮。然后您可以看到我们的状态恢复到计数：1，这也反映在其余的元数据中。然后应用程序会更新以反映状态的更改，因此我们可以逐个步骤地查看每个动作在屏幕上的结果。这不仅有助于调试，而且我们向应用程序添加的任何新状态都将遵循相同的过程，并以这种方式可见。

让我们点击一个动作的提交按钮：

！[](assets/e644b281-6abc-4363-bd02-da43536bdea9.png)

正如您所看到的，这将合并我们点击提交时的所有动作，然后成为我们的基本状态的一部分。因此，计数属性等于您提交到基本状态的动作。

# 模块和可扩展性

目前，我们的一切都在根状态下。随着我们的应用程序变得更大，利用模块的好处将是一个不错的主意，这样我们就可以适当地将容器分割成不同的部分。让我们通过在`store`文件夹内创建一个名为`modules/count`的新文件夹，将我们的计数器状态转换为自己的模块。

然后，我们可以将`actions.js`、`getters.js`、`mutations.js`和`mutation-types.js`文件移动到计数模块文件夹中。这样做后，我们可以在文件夹内创建一个`index.js`文件，该文件仅导出此模块的`state`、`actions`、`getters`和`mutations`：

```js
import actions from './actions';
import getters from './getters';
import mutations from './mutations';

export const countStore = {
  state: {
    count: 0,
  },
  actions,
  getters,
  mutations,
};

export * from './mutation-types';
```

我还选择从`index.js`文件中导出 mutation 类型，这样我们就可以在组件内按模块使用这些类型，只需从`store/modules/count`导入。由于在此文件中导入了多个内容，我给 store 命名为`countStore`。让我们在`store/index.js`中定义新模块：

```js
import Vue from 'vue';
import Vuex from 'vuex';
import { countStore } from './modules/count';

Vue.use(Vuex);

export default new Vuex.Store({
  modules: {
    countStore,
  },
});
```

我们的`App.vue`稍作修改；我们不再引用 types 对象，而是专门从这个模块引用 types：

```js
import * as fromCount from './store/modules/count';

export default {
  data() {
    return {
      amount: 0,
    };
  },
  methods: {
    increment() {
      this.$store.dispatch(fromCount.INCREMENT, this.getAmount);
    },
    decrement() {
      this.$store.dispatch(fromCount.DECREMENT, this.getAmount);
    },
    reset() {
      this.$store.dispatch(fromCount.RESET);
    },
  },
  computed: {
    count() {
      return this.$store.getters.count;
    },
    getAmount() {
      return Number(this.amount) || 1;
    },
  },
};
```

然后，我们可以通过使用与我们的计数示例相同的文件/结构来向我们的应用程序添加更多的模块。这使我们能够在应用程序不断增长时进行扩展。

# 摘要

在本章中，我们利用了`Vuex`库来实现 Vue 中的一致状态管理。我们定义了什么是状态，以及组件状态和应用程序级状态。我们学会了如何适当地将我们的 actions、getters、mutations 和 store 分割成不同的文件以实现可扩展性，以及如何在组件内调用这些项目。

我们还研究了如何使用`Vuex`与 Vue devtools 来逐步执行应用程序中发生的 mutations。这使我们能够更好地调试/推理我们在开发应用程序时所做的决定。

在下一章中，我们将学习如何测试我们的 Vue 应用程序以及如何让我们的测试驱动我们的组件设计。
