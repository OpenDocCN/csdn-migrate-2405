# Vue2 设计模式最佳实践（二）

> 原文：[`zh.annas-archive.org/md5/6E739FB94554764B9B3B763043E30DA8`](https://zh.annas-archive.org/md5/6E739FB94554764B9B3B763043E30DA8)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：Vue.js 指令

在编写 Vue 应用程序时，我们可以访问各种强大的指令，这些指令允许我们塑造内容在屏幕上的呈现方式。这使我们能够通过对 HTML 模板进行添加来打造高度交互式的用户体验。本章将详细介绍这些指令，以及任何缩写和模式，使我们能够改进我们的工作流程。

在本章结束时，您将学会：

+   使用属性绑定来有条件地改变元素行为

+   研究了使用`v-model`的双向绑定

+   使用`v-if`，`v-else`和`v-if-else`有条件地显示信息

+   使用`v-for`在集合中对项目进行迭代

+   监听事件（如键盘/输入）使用`v-on`

+   使用事件修饰符来改变指令的绑定

+   使用过滤器来改变绑定的视图数据

+   看了一下我们如何可以使用简写语法来节省时间并更具有声明性

# 模型

任何业务应用程序最常见的需求之一就是文本输入。Vue 通过`v-model`指令来满足我们的需求。它允许我们在表单输入事件上创建反应式的双向数据绑定，使得处理表单变得更加容易。这是对获取表单值和输入事件的一种方便的抽象。为了探索这一点，我们可以创建一个新的 Vue 项目：

```js
# Create a new Vue project
$ vue init webpack-simple vue-model

# Navigate to directory
$ cd vue-model

# Install dependencies
$ npm install

# Run application
$ npm run dev
```

我们可以转到我们的根`App.vue`文件，从模板中删除所有内容，而是添加一个包含`label`和`form`输入的新`div`：

```js
<template>
 <div id="app">
  <label>Name:</label>
  <input type="text">
 </div>
</template>
```

这使我们能够向输入元素添加文本，即提示用户输入他们的姓名。我想捕获这个值并在姓名元素下方显示出来以进行演示。为了做到这一点，我们需要在输入元素中添加`v-model`指令；这将允许我们捕获用户输入事件并将值放入一个变量中。我们将这个变量称为`name`，并随后将其添加到我们 Vue 实例中的`data`对象中。现在值已经被捕获为一个变量，我们可以在模板中使用插值绑定来显示这个值：

```js
<template>
  <div id="app">
    <label>Name:</label>
    <input type="text" v-model="name">
    <p>{{name}}</p>
  </div>
</template>

<script>
export default {
  data () {
    return {
     name: ''
    }
  }
}
</script>
```

结果可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/57e1b1bd-0dc7-4d39-91f1-945d91e28b95.png)

在使用`v-model`时，我们不仅限于处理文本输入，还可以在选择时捕获单选按钮或复选框。以下示例展示了这一点：

```js
 <input type="checkbox" v-model="checked">
 <span>Am I checked? {{checked ? 'Yes' : 'No' }}</span>
```

然后在我们的浏览器中显示如下：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/e61b09d2-ec24-4925-a376-4471e6a09a50.png)

`v-model`的好处是，它非常适应各种表单控件，让我们对 HTML 模板具有声明性的控制权。

# 使用 v-for 进行迭代

如果我们有想要重复一定次数的内容，我们可以使用`v-for`。这通常用于使用数据集填充模板。例如，假设我们有一个杂货清单，并且我们想要在屏幕上显示这个清单；我们可以使用`v-for`来做到这一点。我们可以创建一个新项目来看看它的运行情况：

```js
# Create a new Vue project
$ vue init webpack-simple vue-for

# Navigate to directory
$ cd vue-for

# Install dependencies
$ npm install

# Run application
$ npm run dev
```

首先，让我们创建一个包含杂货清单的数组，我们可以在屏幕上显示。每个项目都有`id`，`name`和`quantity`：

```js
<script>
export default {
  name: 'app',
  data () {
    return {
      groceries: [
        {
          id: 1,
          name: 'Pizza',
          quantity: 1
        },
        {
          id: 2,
          name: 'Hot Sauce',
          quantity: 5
        },
        {
          id: 3,
          name: 'Salad',
          quantity: 1
        },
        {
          id: 4,
          name: 'Water',
          quantity: 1
        },
        {
          id: 4,
          name: 'Yoghurt',
          quantity: 1
        }
      ]
    }
  }
}
</script>

<style>
#app {
  font-family: 'Avenir', Helvetica, Arial, sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  text-align: center;
  color: #2c3e50;
  margin-top: 60px;
}

ul {
  list-style-type: none;
  padding: 0;
}

li {
  display: block;
}

</style>
```

然后，我们可以遍历我们的杂货清单中的每个项目，并修改 DOM 以在屏幕上显示它们：

```js
<template>
  <div id="app">
    <h1>Shopping List</h1>
    <ul>
      <li v-for="item in groceries" v-bind:key="item.id">
        {{item.name}}
      </li>
    </ul>
  </div>
</template>
```

请注意，我们在`li`元素上有一个`v-bind:key="item.id"`。这使得 Vue 在随时间变化的迭代中更好地工作，并且应尽可能添加一个键：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/1ef683ca-2198-4e34-9033-b7a37aa89275.png)

# 绑定

在这一部分，我们将看看如何在 Vue 应用程序中动态切换 CSS 类。我们将首先调查`v-bind`指令，看看如何将其应用于`class`和`style`属性。这对于根据特定业务逻辑有条件地应用样式非常有用。让我们为此示例创建一个新的 Vue 项目：

```js
# Create a new Vue project
$ vue init webpack-simple vue-bind

# Navigate to directory
$ cd vue-bind

# Install dependencies
$ npm install

# Run application
$ npm run dev
```

在我们的项目中，我们可以创建代表应用程序不同状态的复选框。我们将从一个名为`red`的开始。正如您可能推断的那样，通过检查这个复选框，我们可以将特定的文本颜色变为`red`，然后通过取消选中它将其变为黑色。

在`App.vue`中创建一个名为`red`的`data`对象，其值为`false`：

```js
<script>
export default {
 data () {
  return {
   red: false
  }
 }
}
</script>
```

这代表了我们复选框的值，我们将能够使用`v-model`指令来设置它：

```js
<template>
 <div id="app">
  <h1>Vue Bindings</h1>

  <input type="checkbox" v-model="red" >
  <span>Red</span>
 </div>
</template>
```

此时，我们可以为我们的颜色创建一个新的 CSS 类：

```js
<style>
.red {
 color: red;
}
</style>
```

正如您在浏览器中所看到的，如果我们打开开发工具，可以看到文本的颜色当前设置为`blue`：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/e906133c-b558-45a1-ab86-4cd6523d2b20.png)

最后，为了根据`red`变量的上下文添加/删除类，我们需要在我们的`h1`上添加`v-bind:class`指令，如下所示：

```js
<h1 v-bind:class="{ 'red': red }">Vue Bindings</h1>
```

现在在我们的浏览器中，我们可以看到我们有能力勾选框来将文本设置为`red`，就像这样：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/dc02a9df-a9dd-4162-b481-5ff39fa36596.png)

# 添加次要属性

如果我们还想要向我们的类绑定添加另一个属性，我们需要在`data`对象中添加另一个属性（比如`strikeThrough`）：

```js
data () {
 return {
  red: false,
  strikeThrough: false
 }
}
```

然后我们可以添加另一个`checkbox`：

```js
<input type="checkbox" v-model="strikeThrough">
<span>Strike Through</span>
```

使用适当的`style`：

```js
<style>
.red {
 color: red;
}

.strike-through {
 text-decoration: line-through;
}
</style>
```

最后，我们需要调整我们的绑定以添加额外的类，就像这样：

```js
<h1 v-bind:class="{ 'red': red, 'strike-through': strikeThrough }">Vue Bindings</h1>
```

这是勾选两个框的结果：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/0aa00a8a-02df-4684-9173-d45a35cd66be.png)

# 样式绑定

我们可能想要向我们的标题添加各种样式，因此，我们可以使用`v-bind:style`。通过在我们的`data`对象中创建一个名为`headingStyles`的新对象，我们可以看到这个功能的实际效果：

```js
data () {
 return {
  headingStyles: {
   color: 'blue',
   fontSize: '20px',
   textAlign: 'center'
  }
 }
}
```

每当我们添加本应为 kebab-case 的 CSS 类（例如`text-align`）时，它们现在在我们的 JavaScript 中变为 camel-case（`textAlign`）。

让我们在模板中为我们的标题添加样式：

```js
<h1 v-bind:style="headingStyles">Vue Bindings</h1>
```

每当编译器看到`v-bind`或`:`时，`"`内的内容都被视为 JavaScript，具有隐式的`this`。

我们还可以将其拆分为一个单独的对象，例如添加`layoutStyles`：

```js
data () {
 return {
  headingStyles: {
   color: 'blue',
   fontSize: '20px',
  },
  layoutStyles: {
   textAlign: 'center',
   padding: '10px'
  }
 }
}
```

所以我们现在需要在`template`中的数组中添加`styles`，就像在`<h1>`标签中使用`v-bind`一样：

```js
<template>
 <h1 v-bind:style="[headingStyles, layoutStyles]">Vue Bindings</h1>
</template>
```

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/54a1ea26-3a11-4a1c-a346-95fd2d5e0363.png)

现在你可以在屏幕上看到我们的样式结果。请注意，数组中的任何后续项目都将优先采用首先声明的样式。

# DOM 事件和 v-on

我们可以使用`v-on`在 Vue 中处理 DOM 事件。通过监听 DOM 事件，我们能够对用户输入做出反应，从按键事件（比如点击*Enter*按钮）到按钮点击事件等等。

让我们创建一个试验项目来尝试在我们自己的项目中使用这个功能：

```js
# Create a new Vue project
$ vue init webpack-simple vue-on

# Navigate to directory
$ cd vue-on

# Install dependencies
$ npm install

# Run application
$ npm run dev
```

假设有一个`input`框，当我们点击添加按钮或按下*Enter*键时，输入将被添加到数组中：

```js
<template>
 <div id="app">
  <ul>
   <li v-for="(p, index) in person" :key="index">
    {{p}}
   </li>
  </ul>
  <input type="text" v-model="person" v-on:keyup.enter="addPerson" />
  <button v-on:click="addPerson">Add {{ person}} </button>
 </div>
</template>

<script>
export default {
 name: 'app',
 data () {
  return {
   person: '',
   people: []
  }
 },
 methods: {
  addPerson() {
   this.people = this.people.concat(
    {id: this.people.length, name: this.person}
   );
  this.person = '';
  }
 }
}
</script>
```

在将其推入之前，您必须复制对象。

这里到底发生了什么？我们使用`v-model`指令捕获了用户输入的值，然后我们监听了`keyup.enter`和`v-on:click`事件，两者都调用了`addPerson`函数，随后将`person`添加到数组中。之后，使用`v-for`指令，我们能够将这个人员列表输出到页面上：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/ace0b21b-bc4c-45b3-98bf-43bf51fed64a.png)

# 按键修饰符

我们不仅仅局限于使用`enter`修饰符，我们还可以使用各种简写修饰符，例如使用@符号和缩短`v-on:event.name` `v-on：`，用@符号替换它。其他缩写方法包括：

+   `@`与`v-on：`相同

+   `@keyup.13`与`@keyup.enter`相同

+   `@key*`可以排队，例如`@keyup.ctrl.alt.delete`

其他修饰符可以在下表中看到：

| **名称** | **描述** | **代码示例** |
| --- | --- | --- |
| `.enter` | 每当按下*Enter*键时。 | `<input v-on:keyup.enter="myFunction" />` |
| `.tab` | 每当按下*Tab*键时。 | `<input v-on:keyup.tab="myFunction" />` |
| `.delete` | 每当按下*Delete*或*Backspace*键时。 | `<input v-on:keyup.delete="myFunction" />` |
| `.esc` | 每当按下*Esc*键时。 | `<input v-on:keyup.esc="myFunction" />` |
| `.up` | 每当按下上箭头键时。 | `<input v-on:keyup.up="myFunction" />` |
| `.down` | 每当按下下箭头键时。 | `<input v-on:keyup.down="myFunction" />` |
| `.left` | 每当按下左箭头键时。 | `<input v-on:keyup.left="myFunction" />` |
| `.right` | 每当按下右箭头键时。 | `<input v-on:keyup.right="myFunction" />` |

# 事件修饰符

通常在 JavaScript 中处理事件时，我们会修改事件本身的功能。这意味着我们需要在处理程序中添加`event.preventDefault()`或`event.stopPropagation()`。Vue 通过在模板中使用事件修饰符来处理这些调用，帮助我们抽象化这些调用。

这最好通过一个`form`示例来展示。让我们以前面的人员示例为例，并修改为包含一个`form`元素：

```js
<template>
  <div id="app">
    <ul>
      <li v-for="p in people" v-bind:key="p.id" >
        {{p}}
      </li>
    </ul>

    <form v-on:submit="addPerson">
      <input type="text" v-model="person" />
      <button>Add {{ person}} </button>
    </form>
  </div>
</template>
```

如果您尝试运行此示例，您会注意到当我们点击“添加”按钮时，页面会刷新。这是因为这是`form`提交事件的默认行为。由于我们此时没有向服务器 POST 数据，因此我们需要在我们的`submit`事件中添加`.prevent`修饰符：

```js
 <form v-on:submit.prevent="addPerson">
  <input type="text" v-model="person" />
  <button>Add {{ person}} </button>
 </form>
```

现在当我们选择我们的按钮时，`addPerson`函数被调用而不刷新页面。

# 有条件地显示 DOM 元素

在创建业务应用程序时，会有许多时候，您只想在某个条件为**true**或**false**时显示特定的元素。这可能包括用户的年龄，用户是否已登录，是否为管理员或您能想到的任何其他业务逻辑片段。

对于这一点，我们有各种条件指令，如`v-show`、`v-if`、`v-else`和`v-else-if`，它们都以类似但不同的方式起作用。让我们通过创建一个新的示例项目来更详细地了解这一点：

```js
# Create a new Vue project
$ vue init webpack-simple vue-conditionals

# Navigate to directory
$ cd vue-conditionals

# Install dependencies
$ npm install

# Run application
$ npm run dev
```

# v-show

如果我们想要隐藏元素但仍然在 DOM 中拥有它们（有效地`display:none`），我们可以使用`v-show`：

```js
<template>
<div id="app">
 <article v-show="admin">
  <header>Protected Content</header>
 <section class="main">
  <h1>If you can see this, you're an admin!</h1>
 </section>
</article>

 <button @click="admin = !admin">Flip permissions</button>
</div>
</template>

<script>
export default{
name: 'app',
 data (){
  return{
   admin: true
    }
  }
}
</script>
```

例如，如果我们有一个数据变量，可以确定某人是否是管理员，我们可以使用`v-show`只向适当的用户显示受保护的内容：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/41ae3f14-c246-456f-a71c-14bf49db5c8f.jpg)

请注意，在前面的图中，当`admin`设置为`false`时，`display: none`样式被添加到元素中。乍一看，这似乎就是我们想要的，我们的项目已经消失了！在某些情况下，这是正确的，但在其他情况下，使用`v-if`可能更好。

`v-show`不会从 DOM 中移除元素，这意味着一切都会被初始加载，如果没有被使用，就会被隐藏起来。我们的页面将不得不渲染这些内容，如果使用不当可能会导致性能问题；因此在使用`v-show`之前要问这个问题：

我需要再次显示这个组件吗？如果是，会经常显示吗？

如果对这个问题的答案是**是**，那么在这种情况下`v-show`可能更好。否则，如果对这个问题的答案是**否**，那么在这种用例中`v-if`可能更好。

# v-if

如果我们想有条件地从 DOM 中移除元素，我们可以使用`v-if`。让我们用`v-if`替换之前的`v-show`指令：

```js
 <article v-if="admin">
  <header>Protected Content</header>
  <section class="main">
   <h1>If you can see this, you're an admin!</h1>
  </section>
 </article>
```

请注意，现在当我们查看 DOM 时，元素已完全被移除：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/666919bd-0ba3-4999-82dd-830f4bd3e78c.jpg)

# v-else

在显示或隐藏元素时的常见模式是显示不同的内容。虽然我们可以多次使用`v-if`或`v-show`，但我们也可以使用`v-else`指令，它可以直接在显示或隐藏元素之后使用。

让我们更详细地了解一下这一点：

```js
<article v-if="admin">
  <header>Protected Content</header>
  <section class="main">
    <h1>If you can see this, you're an admin!</h1>
  </section>
</article>
<article v-else>
  <header>You're not an admin!</header>
  <section class="main">
    <h1>Perhaps you shouldn't be here.</h1>
  </section>
</article>
```

通过在第二个`<article>`中添加`v-else`指令，我们告诉 Vue 我们希望在第一个条件隐藏时显示这个 DOM 元素。由于这种工作方式，我们不必向`v-else`传递一个值，因为 Vue 明确地在前面的元素中寻找结构指令。

重要的是要意识到，如果在`v-if`和`v-else`指令之间有一个元素，这种方法是行不通的，比如这样： 

```js
<article v-if="admin">
  <header>Protected Content</header>
  <section class="main">
    <h1>If you can see this, you're an admin!</h1>
  </section>
</article>
<h1>The v-else will be ignored.</h1>
<article v-else>
  <header>You're not an admin!</header>
  <section class="main">
    <h1>Perhaps you shouldn't be here.</h1>
  </section>
</article>
```

# v-else-if

虽然`v-else`在标准的**IF NOT A** then **B**场景中运行良好，但您可能希望测试多个值并显示不同的模板。类似于`v-else`，我们可以使用`v-else-if`来改变应用程序的行为。在这个例子中，我们将通过使用 ES2015 引入的生成器来玩耍。

要使用生成器，我们需要安装`babel-polyfill`包；这也允许我们更好地处理`async`和`await`等内容：

```js
$ npm install babel-polyfill --save-dev
```

安装完成后，我们可以修改我们的 Webpack 配置（`webpack.config.js`）将其包含在我们的入口文件中：

```js
module.exports = {
 entry: ['babel-polyfill', './src/main.js'],
 output: {
  path: path.resolve(__dirname, './dist'),
  publicPath: '/dist/',
  filename: 'build.js',
 },
 // Omitted
```

如果我们没有安装适当的 polyfill，我们将无法在项目中使用生成器功能。让我们创建一个名为`returnRole()`的新方法，当调用时给我们三个用户中的一个“角色”：

```js
export default {
 name: 'app',
 data() {
  return {
   role: '',
  }
 },
  methods: {
   *returnRole() {
    yield 'guest';
    yield 'user';
    yield 'admin';
  }
 }
};
```

如果您以前从未见过生成器函数，您可能会想知道我们在函数名前面加上的星号（`*`）以及`yield`关键字是什么。这实质上允许我们通过捕获它的实例来逐步执行函数。例如，让我们创建一个返回迭代器的数据值，我们可以在其上调用`next()`：

```js
 data() {
  return {
   role: '',
   roleList: this.returnRole()
  }
 },
 methods: {
  getRole() {
   /**
    * Calling this.roleList.next() gives us an Iterator object with the interface of:
    * { value: string, done: boolean}
    * We can therefore check to see whether this was the >last< yielded value with done, or get the result by calling .value
    */

    this.role = this.roleList.next().value;
 },
```

因此，我们可以制作一个模板，利用`v-if-else`来根据用户角色显示不同的消息：

```js
<template>
 <div id="app">
  <article v-if="role === 'admin'">
   <header>You're an admin!</header>
   <section class="main">
    <h1>If you can see this, you're an admin!</h1>
   </section>
  </article>
  <article v-else-if="role === 'user'">
   <header>You're a user!</header>
   <section class="main">
    <h1>Enjoy your stay!</h1>
   </section>
  </article>
 <article v-else-if="role === 'guest'">
  <header>You're a guest!</header>
  <section class="main">
   <h1>Maybe you should make an account.</h1>
  </section>
 </article>
 <h1 v-else>You have no role!</h1>
 <button @click="getRole()">Switch Role</button>
 </div>
</template>
```

屏幕上显示的消息取决于用户角色。如果用户没有角色，我们使用`v-else`来显示一条消息，说明“您没有角色！”。这个例子展示了我们如何利用结构指令根据应用程序状态真正改变 DOM。

# 过滤器

在本节中，我们将研究过滤器；您可能在诸如 Angular（管道）之类的框架中遇到过过滤器。也许我们想创建一个允许我们以可读格式（DD/MM/YYYY）格式化日期的过滤器。让我们创建一个探索项目来进一步研究这个问题：

```js
# Create a new Vue project
$ vue init webpack-simple vue-filters

# Navigate to directory
$ cd vue-filters

# Install dependencies
$ npm install

# Run application
$ npm run dev
```

如果我们有一些测试人员，并使用`v-for`指令在屏幕上显示它们，我们将得到以下结果：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/90cd6697-f297-41f9-81e3-81584b5e8a08.png)

要获得前面截图中显示的结果，我们通过`v-for`指令显示我们的测试人员与适当的数据，我们需要添加以下代码：

```js
<template>
 <div id="app">
  <ul>
   <li v-for="person in people" v-bind:key="person.id">
    {{person.name}} {{person.dob}}
   </li>
  </ul>
 </div>
</template>

<script>
export default {
 name: 'app',
 data() {
  return {
   people: [
    {
     id: 1,
     name: 'Paul',
     dob: new Date(2000, 5, 29),
    },
    {
     id: 2,
     name: 'Terry',
     dob: new Date(1994, 10, 25),
    },
    {
     id: 3,
     name: 'Alex',
     dob: new Date(1973, 4, 15),
    },
    {
     id: 4,
     name: 'Deborah',
     dob: new Date(1954, 2, 5),
    },
   ],
  };
 },
};
</script>
```

我们可以自己做日期转换的工作，但在可能的情况下，值得寻找是否有可信赖的第三方组件可以做同样的事情。我们将使用 moment ([`momentjs.com`](https://momentjs.com)) 来实现这一点。

让我们为我们的项目安装 `moment`：

```js
$ npm install moment --save
```

然后我们可以将其添加到我们的 `App.vue` 中：

```js
<script>
import moment from 'moment';

export default {
 // Omitted
}
</script>
```

# 本地注册的过滤器

然后我们有一个选择：将过滤器添加到此 Vue 实例的本地，或者将其全局添加到整个项目中。我们首先看看如何在本地添加它：

首先，我们将创建一个函数，该函数接受一个值，并使用 `moment` 返回格式化的日期：

```js
const convertDateToString = value => moment(String(value)).format('MM/DD/YYYY');
```

然后我们可以在我们的 Vue 实例中添加一个 filters 对象，并通过一个 `key` 来引用它，比如 `date`。当我们在模板中调用 `date` 过滤器时，值将传递给这个过滤器，而我们将在屏幕上显示转换后的日期。这可以通过使用 `|` 键来实现，如下面的代码所示：

```js
 <ul>
  <li v-for="person in people" v-bind:key="person.id">
   {{person.name}} {{person.dob | date}}
  </li>
 </ul>
```

最后，要将其添加到本地 Vue 实例中，我们可以添加一个引用我们函数的 `filters` 对象：

```js
export default {
 filters: {
  date: convertDateToString,
 },
```

这样的结果显示了预期的日期：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/fad4697a-7219-4dec-96b0-372a6c51fe20.png)

# 全局注册的过滤器

如果我们想在其他地方使用这个过滤器，我们可以将这个函数抽象成自己的文件，并再次引用我们的过滤器，或者，我们可以在应用程序中全局注册 `date` 过滤器。让我们将我们的 `convertDateToString` 函数抽象成自己的文件，放在 `src/filters/date/date.filter.js` 中：

```js
import moment from 'moment';

export const convertDateToString = value =>
 moment(String(value)).format('MM/DD/YYYY');
```

之后，我们可以在我们的 `main.js` 中定义过滤器的接口：`Vue.filter('filterName', filterFunction())`。由于我们已经将函数抽象成了自己的文件，我们可以导入它并像这样定义它：

```js
import Vue from 'vue';
import App from './App.vue';
import { convertDateToString } from './filters/date/date.filter';

Vue.filter('date', convertDateToString);

new Vue({
 el: '#app',
 render: h => h(App),
});
```

如果您再次检查我们的应用程序，您会看到我们得到了与之前相同的结果。因此，重要的是要考虑过滤器在项目中的使用位置和次数。如果您在特定组件/实例上使用它（一次），那么应该将它放在本地；否则，将其放在全局。

# 总结

在本章中，我们看了很多 Vue 指令及其用法。这使我们有能力以声明方式改变模板在屏幕上的显示方式，包括捕获用户输入、挂接事件、过滤视图数据等等。每当您想在 Vue.js 应用程序中实现指令时，都应该将本章用作参考。

基于组件的架构是一个重要的概念，它使我们能够构建从个人到企业的可扩展项目。在下一章中，我们将看看如何创建这些可重用的组件，以封装项目中的功能部分。


# 第五章：与 Vue.js 组件进行安全通信

在现代 Web 应用程序中，注意到组件驱动的架构并不需要花费太多精力。在短时间内，开发需求发生了变化，Web 从一个简单的文档查看器发展为承载具有显着庞大代码库的复杂应用程序。因此，能够创建可重用的组件使我们作为前端开发人员的生活变得更加轻松，因为我们可以将核心功能封装到单一块中，减少总体复杂性，实现更好的关注点分离，协作和可扩展性。

在本章中，我们将把前面的概念应用到我们的 Vue 应用程序中。在本章结束时，您将实现：

+   创建自己的 Vue 组件的能力

+   对单文件组件的更深入理解

+   创建特定于每个组件的样式的能力

+   能够在本地和全局注册组件，并理解选择其中一个的原因

+   使用 props 在父子组件之间进行通信的能力

+   使用全局事件总线在整个应用程序中进行通信的能力

+   使用插槽使您的组件更加灵活

让我们从*您的第一个 Vue 组件*开始。

# 您的第一个 Vue 组件

事实证明，我们一直在 Vue 应用程序中使用组件！使用`webpack-simple`模板，我们支持**单文件组件**（**SFC**），它本质上只是一个带有`.vue`扩展名的模板、脚本和样式标签：

```js
# Create a new Vue project
$ vue init webpack-simple vue-component-1

# Navigate to directory
$ cd vue-component-1

# Install dependencies
$ npm install

# Run application
$ npm run dev
```

由于我们正在使用 Visual Studio Code 的 Vetur 扩展，我们可以输入`scaffold`并按*Tab*键，然后创建一个可以在项目中使用的 SFC。如果我们用一个空组件覆盖`App.vue`，根据我们当前的定义，它将如下所示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/50fc5112-77cf-4a01-b677-652be6042fff.png)

就是这样！有点。我们仍然需要向我们的组件添加一些功能，并且如果我们要创建一个新文件（即不使用默认的`App.vue`组件），则需要在某个地方注册它以供使用。让我们通过在`src/components/FancyButton.vue`下创建一个新文件来看看这个过程：

```js
<template>
 <button>
  {{buttonText}}
 </button>
</template>

<script>
export default {
 data() {
  return {
   buttonText: 'Hello World!'
  }
 }
}
</script>

<style>
 button {
  border: 1px solid black;
  padding: 10px;
 }
</style>
```

我们的`FancyButton`组件只是一个说'Hello World!'的按钮，并带有一点点样式。立即，我们需要考虑可以做些什么来使其更具可扩展性：

+   允许在此组件上输入以更改按钮文本

+   当我们为`button`元素设置样式（甚至如果我们添加了类），我们需要一种方法来阻止样式泄漏到应用程序的其他部分

+   注册此组件，以便可以在整个应用程序中全局使用

+   注册此组件，以便可以在组件内部本地使用

+   还有更多！

让我们从最简单的开始，注册组件，以便在我们的应用程序中使用。

# 全局注册组件

我们可以使用以下接口创建组件并全局注册它们：`Vue.component(name: string, options: Object<VueInstance>)`。虽然不是必需的，但在命名我们的组件时，遵循 W3C 自定义元素规范设置的命名约定很重要（[`www.w3.org/TR/custom-elements/#valid-custom-element-name`](https://www.w3.org/TR/custom-elements/#valid-custom-element-name)），即全部小写并且必须包含连字符。

在我们的`main.js`文件中，让我们首先从适当的路径导入`FancyButton`组件，然后注册它：

```js
import FancyButton from './components/FancyButton.vue';
```

之后，我们可以使用`Vue.component`注册组件，可以在`main.js`中看到加粗的结果代码如下：

```js
import Vue from 'vue';
import App from './App.vue';
import FancyButton from './components/FancyButton.vue';

Vue.component('fancy-button', FancyButton);

new Vue({
  el: '#app',
  render: h => h(App)
});
```

塔达！我们的组件现在已经全局注册了。现在...我们如何在`App.vue`组件内部使用它呢？好吧，记得我们指定的标签吗？我们只需将其添加到`template`中，如下所示：

```js
<template>
 <fancy-button/>
</template>
```

这是我们辛苦工作的结果（放大到 500%）：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/dd7723c0-2989-49a4-a855-663dcf1121d7.png)

# 作用域样式

太棒了！如果我们添加另一个按钮元素会发生什么？因为我们直接用 CSS 为`button`元素设置了样式：

```js
<template>
  <div>
    <fancy-button></fancy-button>
    <button>I'm another button!</button>
  </div>
</template>
```

如果我们转到浏览器，我们可以看到我们创建的每个按钮：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/604d7493-d3d5-436a-880b-63d7fa46c240.png)

哦哦！这个其他按钮不是`fancy-button`，那么为什么它会得到样式？幸运的是，阻止样式泄漏到组件外部很简单，我们只需要在`style`标签中添加`scoped`属性：

```js
<style scoped>
 button {
 border: 1px solid black;
 padding: 10px;
 }
</style>
```

`scoped`属性不是 Vue 默认的一部分，这来自我们的 Webpack `vue-loader`。您会注意到，在添加此属性后，按钮样式仅适用于我们的`fancy-button`组件。如果我们看一下以下截图中两个按钮之间的区别，我们可以看到一个只是一个按钮，另一个是使用随机生成的数据属性为按钮设置样式。这可以阻止浏览器在这种情况下将样式应用于两个按钮元素。

在 Vue 中使用作用域 CSS 时，请记住组件内创建的规则不会在整个应用程序中全局访问：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/8fa8f269-da22-4751-a067-7e77a88331e6.png)

# 在本地注册组件

我们也可以在应用程序内部局部注册我们的组件。这可以通过将其添加到我们的 Vue 实例中来实现，例如，让我们将`main.js`中的全局注册注释掉，然后导航到`App.vue`：

```js
// Vue.component('fancy-button', FancyButton);
```

在将任何代码添加到我们的应用程序组件之前，请注意，我们的按钮现在已经消失，因为我们不再全局注册它。要在本地注册这个，我们需要首先导入组件，类似于之前的操作，然后将其添加到实例中的`component`对象中：

```js
<template>
 <div>
 <fancy-button></fancy-button>
 <button>I'm another button!</button>
 </div>
</template>

<script>
import FancyButton from './components/FancyButton.vue';

export default {
 components: {
 FancyButton
 }
}
</script>

<style>

</style>
```

我们的按钮现在再次出现在屏幕上。在决定注册组件的位置时，考虑它们在整个项目中可能需要被多频繁使用。

# 组件通信

现在我们有了创建可重用组件的能力，这使我们能够在项目中封装功能。为了使这些组件可用，我们需要让它们能够相互通信。我们首先要看的是组件属性的单向通信（称为“props”）。

组件通信的目的是保持我们的功能分布、松散耦合，并从而使我们的应用程序更容易扩展。为了实现松散耦合，您不应尝试在子组件中引用父组件的数据，而应仅使用`props`传递。让我们看看如何在我们的`FancyButton`上创建一个改变`button`文本的属性：

```js
<template>
 <button>
  {{buttonText}}
 </button>
</template>

<script>
export default {
 props: ['buttonText'],
}
</script>

<style scoped>
 button {
 border: 1px solid black;
 padding: 10px;
 }
</style>
```

请注意，我们能够在模板中绑定到`buttonText`值，因为我们创建了一个包含每个组件属性的字符串或对象值的`props`数组。设置这个可以通过连字符形式作为组件本身的属性，这是必需的，因为 HTML 是不区分大小写的：

```js
<template>
 <fancy-button button-text="I'm set using props!"></fancy-button>
</template>
```

这给我们带来了以下结果：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/1fe36d71-ca38-4d17-b80d-6200a13f6a7e.png)

# 配置属性值

我们还可以通过将属性值设置为对象来进一步配置它们。这使我们能够定义默认值、类型、验证器等。让我们用我们的`buttonText`属性来做这个：

```js
export default {
 props: {
  buttonText: {
   type: String,
   default: "Fancy Button!",
   required: true,
   validator: value => value.length > 3
  }
 },
}
```

首先，我们确保只能将 String 类型传递到此属性中。我们还可以检查其他类型，例如：

+   数组

+   布尔值

+   函数

+   数字

+   对象

+   字符串

+   符号

根据 Web 组件的良好实践，向 props 发送原始值是一种良好的实践。

在底层，这是针对属性运行`instanceof`运算符，因此它也可以针对构造函数类型运行检查，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/02c1a8f7-dd5b-4275-9888-7f65a618fbfd.png)

与此同时，我们还可以使用数组语法检查多种类型：

```js
export default {
 props: {
  buttonText: {
   type: [String, Number, Cat],
  }
 },
}
```

接下来，我们将默认文本设置为`FancyButton!`，这意味着默认情况下，如果未设置该属性，它将具有该值。我们还将`required`设置为`true`，这意味着每次创建`FancyButton`时，都必须包含`buttonText`属性。

目前这是一个术语上的矛盾（即默认值和必需性），但有时您可能希望在属性不是必需的情况下设置默认值。最后，我们将为此添加一个验证函数，以指定每次设置此属性时，它的字符串长度必须大于三。

我们如何知道属性验证失败了？在开发模式下，我们可以检查开发控制台，应该会有相应的错误。例如，如果我们忘记在组件上添加`buttonText`属性：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/7bbf0577-2965-4753-b81a-366e98da34bf.png)

# 自定义事件

我们取得了很大的进展。我们现在有一个可以接受输入、可以全局或局部注册、具有作用域样式、验证等功能的组件。现在我们需要让它具有向其父组件发送事件的能力，以便在`FancyButton`按钮被点击时进行通信，这是通过编辑`$emit`事件的代码来实现的：

```js
<template>
 <button 
  @click.prevent="clicked">
  {{buttonText}}
 </button>
</template>

<script>
export default {
 props: {
  buttonText: {
   type: String,
   default: () => {
     return "Fancy Button!" 
   },
   required: true,
   validator: value => value.length > 3
  }
 },
 methods: {
  clicked() {
   this.$emit('buttonClicked');
  }
 }
}
</script>
```

在我们的示例中，我们将`clicked`函数附加到按钮的点击事件上，这意味着每当它被选中时，我们就会发出`buttonClicked`事件。然后我们可以在`App.vue`文件中监听此事件，将我们的元素添加到 DOM 中：

```js
<template>
  <fancy-button 
   @buttonClicked="eventListener()" 
   button-text="Click 
   me!">
  </fancy-button>
</template>

<script>
import FancyButton from './components/FancyButton.vue';

export default {
  components: {
    'fancy-button': FancyButton
  },
  methods: {
    eventListener() {
      console.log("The button was clicked from the child component!");
    }
  }
}
</script>

<style>

</style>
```

请注意，此时我们正在使用`@buttonClicked="eventListener()"`。这使用`v-on`事件在事件被触发时调用`eventListener()`函数，随后将消息记录到控制台。我们现在已经演示了在两个组件之间发送和接收事件的能力。

# 发送事件值

为了使事件系统更加强大，我们还可以将值传递给我们的另一个组件。让我们在`FancyButton`组件中添加一个输入框（也许我们需要重新命名它或考虑将输入分离成自己的组件！）：

```js
<template>
 <div>
  <input type="text" v-model="message">
  <button 
  @click.prevent="clicked()">
   {{buttonText}}
  </button>
 </div>
</template>

<script>
export default {
 data() {
  return {
   message: ''
  };
 },
 // Omitted
}
```

接下来要做的是在我们的`$emit`调用中传递消息值。我们可以在`clicked`方法中这样做：

```js
 methods: {
  clicked() {
   this.$emit('buttonClicked', this.message);
  }
 }
```

此时，我们可以将事件作为`eventListener`函数的参数来捕获：

```js
<template>
 <fancy-button @buttonClicked="eventListener($event)" button-text="Click me!"></fancy-button>
</template>
```

此时要做的最后一件事也是匹配函数的预期参数：

```js
 eventListener(message) {
  console.log(`The button was clicked from the child component with this message: ${message}`);
 }
```

然后我们应该在控制台中看到以下内容：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/8ede1eca-f3fc-49d7-9b60-9ef5042cb653.png)

我们现在有能力在父子组件之间真正发送事件，以及我们可能想要发送的任何数据。

# 事件总线

当我们想要创建一个应用程序范围的事件系统（即，不仅限于父子组件），我们可以创建所谓的事件总线。这允许我们通过一个单一的 Vue 实例“管道”所有事件，从而实现超出父子组件通信的可能。除此之外，对于那些不想使用第三方库如`Vuex`，或者处理不多动作的小型项目来说，这也是有用的。让我们创建一个新的示例项目来演示它：

```js
# Create a new Vue project
$ vue init webpack-simple vue-event-bus

# Navigate to directory
$ cd vue-event-bus

# Install dependencies
$ npm install

# Run application
$ npm run dev
```

首先，在`src`文件夹中创建一个`EventsBus.js`。从这里，我们可以导出一个新的 Vue 实例，我们可以像以前一样使用`$emit`来发出事件：

```js
import Vue from 'vue';

export default new Vue();
```

接下来，我们可以创建两个组件，`ShoppingInput`和`ShoppingList`。这将允许我们输入新项目，并在购物清单上显示输入项目的列表，从我们的`ShoppingInput`组件开始：

```js
<template>
 <div>
  <input v-model="itemName">
  <button @click="addShoppingItem()">Add Shopping Item</button>
 </div>
</template>

<script>
import EventBus from '../EventBus';

export default {
 data() {
  return {
   itemName: ''
  }
 },
 methods: {
  addShoppingItem() {
   if(this.itemName.length > 0) {
    EventBus.$emit('addShoppingItem', this.itemName)
    this.itemName = "";
   }
  }
 },
}
</script>
```

这个组件的关键是，我们现在导入`EventBus`并使用`$emit`，而不是使用`this`，将我们的应用程序事件系统从基于组件变为基于应用程序。然后，我们可以使用`$on`来监视任何组件中的更改（以及随后的值）。让我们用下一个组件`ShoppingList`来看一下：

```js
<template>
 <div>
  <ul>
   <li v-for="item in shoppingList" :key="item">
    {{item}}
   </li>
  </ul>
 </div>
</template>

<script>
import EventBus from '../EventBus';
export default {
 props: ['shoppingList'],
 created() {
  EventBus.$on('addShoppingItem', (item) => {
   console.log(`There was an item added! ${item}`);
  })
 }
}
</script>
```

看看我们的`ShoppingList`组件，我们可以看到`$on`的使用，这允许我们监听名为`addShoppingItem`的事件（与我们发出的相同事件名称，或者您想要监听的任何其他事件）。这将返回该项，然后我们可以将其记录到控制台或在此时执行任何其他操作。

我们可以将所有这些放在我们的`App.vue`中：

```js
<template>
 <div>
  <shopping-input/>
  <shopping-list :shoppingList="shoppingList"/>
 </div>
</template>

<script>
import ShoppingInput from './components/ShoppingInput';
import ShoppingList from './components/ShoppingList';
import EventBus from './EventBus';

export default {
 components: {
  ShoppingInput,
  ShoppingList
 },
 data() {
  return {
   shoppingList: []
  }
 },
 created() {
  EventBus.$on('addShoppingItem', (itemName) => {
   this.shoppingList.push(itemName);
  })
 },
}
```

我们定义了两个组件，并在创建的生命周期钩子内监听`addShoppingItem`事件。就像以前一样，我们得到了`itemName`，然后我们可以将其添加到我们的数组中。我们可以将数组传递给另一个组件作为 prop，比如`ShoppingList`，以在屏幕上呈现。

最后，如果我们想要停止监听事件（完全或每个事件），我们可以使用`$off`。在`App.vue`内，让我们创建一个新的按钮来进一步展示这一点：

```js
<button @click="stopListening()">Stop listening</button>
```

然后我们可以这样创建`stopListening`方法：

```js
methods: {
 stopListening() {
  EventBus.$off('addShoppingItem')
 }
},
```

如果我们想要停止监听所有事件，我们可以简单地使用：

```js
EventBus.$off();
```

到目前为止，我们已经创建了一个事件系统，可以让我们与任何组件进行通信，而不受父/子关系的影响。我们可以通过`EventBus`发送事件并监听事件，从而更灵活地处理组件数据。

# 插槽

当我们组合组件时，我们应该考虑它们将如何被我们自己和团队使用。使用插槽允许我们动态地向组件添加具有不同行为的元素。让我们通过创建一个新的示例项目来看看它的作用：

```js
# Create a new Vue project
$ vue init webpack-simple vue-slots

# Navigate to directory
$ cd vue-slots

# Install dependencies
$ npm install

# Run application
$ npm run dev
```

然后，我们可以继续创建一个名为`Message`（`src/components/Message.vue`）的新组件。我们可以为这个组件添加一些特定的内容（比如下面的`h1`），以及一个`slot`标签，我们可以用它来从其他地方注入内容：

```js
<template>
 <div>
   <h1>I'm part of the Message component!</h1>
   <slot></slot>
 </div>
</template>

<script>
export default {}
</script>
```

如果我们在`App.vue`内注册了我们的组件，并将其放置在我们的模板内，我们就可以像这样在`component`标签内添加内容：

```js
<template>
 <div id="app">
   <message>
     <h2>What are you doing today?</h2>
   </message>
   <message>
     <h2>Learning about Slots in Vue.</h2>
   </message>
 </div>
</template>

<script>
import Message from './components/Message';

export default {
 components: {
  Message
 }
}
</script>
```

此时，`message`标签内的所有内容都被放置在`Message`组件内的`slot`中：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/5e0e881f-2107-4293-be22-e51d09c8a94d.png)

注意，每次声明`Message`组件时，我们都会看到"I'm part of the Message component!"，这表明即使我们向这个空间注入内容，我们仍然可以每次显示特定于组件的模板信息。

# 默认值

虽然我们可以向插槽中添加内容，但我们可能希望添加默认内容，以便在我们没有自己添加任何内容时显示。这意味着我们不必每次都添加内容，如果需要的话，我们可以在特定情况下覆盖它。

我们如何向我们的插槽添加默认行为？这很简单！我们只需要在`slot`标签之间添加我们的元素，就像这样：

```js
<template>
 <div>
  <h1>I'm part of the Message component!</h1>
  <slot>
   <h2>I'm a default heading that appears <em>only</em> when no slots 
   have been passed into this component</h2>
   </slot>
 </div>
</template>
```

因此，如果我们添加另一个`message`元素，但这次没有任何标记，我们会得到以下结果：

```js
<template>
 <div id="app">
  <message>
   <h2>What are you doing today?</h2>
  </message>
  <message>
   <h2>Learning about Slots in Vue.</h2>
  </message>
  <message></message>
 </div>
</template>
```

现在，如果我们转到浏览器，我们可以看到我们的消息如预期般显示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/aa5a2942-93ea-4bdb-92e8-832840de3cef.png)

# 命名插槽

我们还可以通过命名插槽进一步进行。假设我们的`message`组件希望同时有`date`和`messageText`输入，其中一个是插槽，另一个是组件的属性。我们使用这个的情况可能是，也许我们想以不同的方式显示日期，添加不同的信息，或者根本不显示它。

我们的消息组件变成了：

```js
<template>
 <div>
  <slot name="date"></slot>
  <h1>{{messageText}}</h1>
 </div>
</template>

<script>
export default {
 props: ['messageText']
}
</script>
```

请注意我们在`slot`标签上的`name="date"`属性。这使我们能够在运行时动态地将我们的内容放在正确的位置。然后我们可以构建一个小型的聊天系统来展示这一点，让我们确保在继续之前在我们的项目中安装了`moment`：

```js
$ npm install moment --save
```

你可能还记得在第四章中使用`moment`，*Vue.js 指令*，我们还将重用之前创建的`Date`管道。让我们升级我们的`App.vue`，包含以下内容：

```js
<template>
 <div id="app">

  <input type="text" v-model="message">
  <button @click="sendMessage()">+</button>

  <message v-for="message in messageList" :message-text="message.text" :key="message">
   <h2 slot="date">{{ message.date | date }}</h2>
  </message>
 </div>
</template>

<script>
import moment from 'moment';
import Message from './components/Message';

const convertDateToString = value => moment(String(value)).format('MM/DD/YYYY');

export default {
 data() {
  return {
   message: '',
   messageList: []
  }
 },
 methods: {
  sendMessage() {
   if ( this.message.length > 0 ) {
    this.messageList.push({ date: new Date(), text: this.message });
    this.message = ""
   }
  }
 },
 components: {
  Message
 },
 filters: {
  date: convertDateToString
 }
}
</script>
```

这里发生了什么？在我们的模板中，我们正在遍历我们的`messageList`，每次添加新消息时都会创建一个新的消息组件。在组件标签内部，我们期望`messageText`会出现（因为我们将其作为 prop 传递，并且标记是在 Message 组件内部定义的），但我们还动态添加了日期使用`slot`：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/d6f662a6-2aca-4b6a-9232-96ddf8f48212.png)

如果我们从 h2 中删除`slot="date"`会发生什么？日期还会显示吗？不会。这是因为当我们只使用命名插槽时，没有其他地方可以添加插槽。只有当我们将我们的`Message`组件更改为接受一个未命名插槽时，它才会出现，如下所示：

```js
<template>
 <div>
  <slot name="date"></slot>
  <slot></slot>
  <h1>{{messageText}}</h1>
 </div>
</template>
```

# 总结

本章使我们有能力创建可重用的组件，这些组件可以相互通信。我们已经看到了如何可以在整个项目中全局注册组件，或者在特定实例中本地注册组件，从而给我们带来了灵活性和适当的关注点分离。我们已经看到了这种强大的功能，从简单属性的添加到复杂验证和默认值的例子。

在下一章中，我们将研究如何创建**更好的 UI**。我们将更多地关注指令，比如在表单、动画和验证的上下文中使用`v-model`。


# 第六章：创建更好的 UI

过渡和动画是在我们的应用程序中创建更好用户体验的好方法。由于有很多不同的选项和用例，它们可以使应用程序的感觉得以或败。我们将在本章中进一步探讨这个概念。

我们还将使用名为`Vuelidate`的第三方库来进行表单验证。这将允许我们创建随着应用程序规模而扩展的表单。我们还将获得根据表单状态更改 UI 的能力，以及显示有用的验证消息来帮助用户。

最后，我们将看看如何使用`render`函数和 JSX 来使用 Vue 组合用户界面。虽然这并不适用于每种情况，但在某些情况下，您可能希望充分利用模板中的 JavaScript，并使用功能组件模型创建智能/表现组件。

到本章结束时，您将拥有：

+   学习了 CSS 动画

+   创建自己的 CSS 动画

+   使用`Animate.css`创建交互式 UI，工作量很小

+   调查并创建自己的 Vue 过渡

+   利用`Vuelidate`在 Vue 中验证表单

+   使用`render`函数作为模板驱动 UI 的替代方案

+   使用 JSX 来组合类似于 React 的 UI

让我们首先了解为什么我们应该关心项目中的动画和过渡。

# 动画

动画可以用来吸引特定 UI 元素的注意，并通过使其生动起来来改善用户的整体体验。当没有明确的开始状态和结束状态时，应该使用动画。动画可以自动播放，也可以由用户交互触发。

# CSS 动画

CSS 动画不仅是强大的工具，而且在项目中使用它们只需要很少的知识就可以轻松维护。

将它们添加到界面中可以是捕获用户注意力的直观方法，它们也可以用于轻松指向用户特定的元素。动画可以定制和自定义，使它们成为各种项目中许多用例的理想选择。

在深入研究 Vue 过渡和其他动画可能性之前，我们应该了解如何进行基本的 CSS3 动画。让我们创建一个更详细地查看这一点的简单项目：

```js
# Create a new Vue project
$ vue init webpack-simple vue-css-animations

# Navigate to directory
$ cd vue-css-animations

# Install dependencies
$ npm install

# Run application
$ npm run dev
```

在`App.vue`中，我们可以首先创建以下样式：

```js
<style>
button {
 background-color: transparent;
 padding: 5px;
 border: 1px solid black;
}

h1 {
 opacity: 0;
}

@keyframes fade {
 from { opacity: 0; }
 to { opacity: 1; }
}

.animated {
 animation: fade 1s;
 opacity: 1;
}
</style>
```

如您所见，没有什么特别的。我们使用`@keyframes`命名为`fade`来声明 CSS 动画，基本上给 CSS 两个我们希望元素处于的状态-`opacity: 1`和`opacity: 0`。它并没有说明这些关键帧持续多长时间或是否重复；这一切都在`animated`类中完成。我们在将类添加到元素时应用`fade`关键帧为`1`；与此同时，我们添加`opacity: 1`以确保在动画结束后它不会消失。

我们可以通过利用`v-bind:class`根据`toggle`的值动态添加/删除类来组合这些：

```js
<template>
 <div id="app">
  <h1 v-bind:class="{ animated: toggle }">I fade in!</h1>
  <button @click="toggle = !toggle">Toggle Heading</button>
 </div> 
</template>

<script>
export default {
 data () {
  return {
   toggle: false
  }
 }
}
</script>
```

很好。现在我们可以根据`Boolean`值淡入一个标题。但如果我们能做得更好呢？在这种特殊情况下，我们可以使用过渡来实现类似的结果。在更详细地查看过渡之前，让我们看看我们可以在项目中使用 CSS 动画的其他方式。

# Animate.css

`Animate.css`是一种很好的方式，可以轻松地将不同类型的动画实现到项目中。这是由 Daniel Eden 创建的开源 CSS 库([`daneden.me/`](https://daneden.me/))，它为我们提供了"即插即用"的 CSS 动画。

在将其添加到任何项目之前，前往[`daneden.github.io/animate.css/`](https://daneden.github.io/animate.css/)预览不同的动画样式。有许多不同的动画可供选择，每种都提供不同的默认动画。这些可以进一步定制，我们稍后将在本节中详细讨论。

继续运行以下命令在我们的终端中创建一个游乐项目：

```js
 Create a new Vue project
$ vue init webpack-simple vue-animate-css

# Navigate to directory
$ cd vue-animate-css

# Install dependencies
$ npm install

# Run application
$ npm run dev
```

设置项目后，继续在所选的编辑器中打开`index.html`文件。在`<head>`标签内，添加以下样式表：

```js
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/animate.css/3.5.2/animate.min.css">
```

这是项目中需要的样式表引用，以使`Animate.css`在项目中起作用。

# 使用 Animate.css

现在我们在项目中有了`Animate.css`，我们可以将`App.vue`更改为具有以下`template`：

```js
<template>
 <h1 class="animated fadeIn">Hello Vue!</h1>
</template>
```

在添加任何动画之前，我们首先需要添加 animated 类。接下来，我们可以从`Animate.css`库中选择任何动画；我们选择了`fadeIn`作为示例。然后可以将其替换为其他动画，如`bounceInLeft`，`shake`，`rubberBand`等等！

我们可以将之前的示例转换为基于布尔值的绑定类值，但过渡可能更有趣。

# 过渡

过渡效果是通过从一个特定状态开始，然后过渡到另一个状态并在中间插值数值来实现的。过渡不能在动画中涉及多个步骤。想象一对窗帘从打开到关闭：第一个状态将是打开的位置，而第二个状态将是关闭的位置。

Vue 有自己的标签来处理过渡，称为`<transition>`和`<transition-group>`。这些标签是可定制的，可以很容易地与 JavaScript 和 CSS 一起使用。实际上，并不一定需要有`transition`标签来使过渡生效，因为你只需将状态变量绑定到可见属性，但标签通常提供更多控制和潜在更好的结果。

让我们来看看之前的`toggle`示例，并创建一个使用`transition`的版本：

```js
<template>
 <div id="app">
  <transition name="fadeIn"
  enter-active-class="animated fadeIn"
  leave-active-class="animated fadeOut">
   <h1 v-if="toggle">I fade in and out!</h1>
  </transition>
  <button @click="toggle = !toggle">Toggle Heading</button>
 </div> 
</template>

<script>
export default {
 data () {
  return {
   toggle: false
  }
 }
}
</script>
```

让我们更详细地看看各个部分的运作方式。

我们将元素包裹在`<transition>`标签中，当`<h1>`进入 DOM 时，它会应用`animated fadeIn`的`enter-active-class`。这是通过`v-if`指令触发的，因为`toggle`变量最初设置为`false`。单击按钮会切换我们的布尔值，触发过渡并应用适当的 CSS 类。

# 过渡状态

每个进入/离开过渡都会应用最多六个类，这些类由进入场景时的过渡、过程中和离开场景时的过渡组成。第一组`(v-enter-*)`指的是最初进入然后移出的过渡，而第二组`(v-leave-*)`指的是结束过渡最初进入然后移出：

| **名称** | **描述** |
| --- | --- |
| `v-enter` | 这是进入的起始状态。在元素插入后的一帧后被移除。 |
| `v-enter-active` | `enter-active`是`enter`的活动状态。它在整个活动阶段都是活动的，并且只有在过渡或动画结束后才会被移除。该状态还管理进一步的指令，如延迟、持续时间等。 |
| `v-enter-to` | 这是进入的最后状态，在元素插入后的一帧后添加，与`v-enter`被移除的时间相同。一旦过渡/动画结束，`enter-to`就会被移除。 |
| `v-leave` | 这是离开的起始状态。一旦离开过渡被触发，就会在一帧后被移除。 |
| `v-leave-active` | `leave-active`是`leave`的活动状态。在整个离开阶段都是活动的，只有在过渡或动画结束时才会被移除。 |
| `v-leave-to` | 离开的最后状态，在离开触发后的一帧后添加，与`v-leave`同时移除。当过渡/动画结束时，`leave-to`也会被移除。 |

每个`enter`和`leave`过渡都有一个前缀，在表中显示为`v`的默认值，因为过渡本身没有名称。当将 enter 或 leave 过渡添加到项目中时，理想情况下应该应用适当的命名约定，以充当唯一标识符。如果您计划在项目中使用多个过渡，这可以帮助，并且可以通过简单的赋值操作完成：

```js
<transition name="my-transition">
```

# 表单验证

在本书中，我们已经看过了各种不同的捕获用户输入的方式，比如`v-model`。我们将使用一个名为**Vuelidate**的第三方库来根据特定规则进行模型验证。让我们通过在终端中运行以下命令来创建一个示例项目：

```js
# Create a new Vue project
$ vue init webpack-simple vue-validation

# Navigate to directory
$ cd vue-validation

# Install dependencies
$ npm install

# Install Vuelidate
$ npm install vuelidate

# Run application
$ npm run dev
```

# 什么是 Vuelidate？

`Vuelidate`是一个开源的轻量级库，帮助我们使用各种验证上下文进行模型验证。验证可以被功能组合，并且它也可以很好地与其他库（如`Moment`、`Vuex`等）配合使用。由于我们已经在项目中使用`npm install vuelidate`安装了它，现在我们需要在`main.js`中将其注册为插件。

```js
import Vue from 'vue';
import Vuelidate from 'vuelidate';
import App from './App.vue';

Vue.use(Vuelidate);

new Vue({
  el: '#app',
  validations: {},
  render: h => h(App),
});
```

将空验证对象添加到我们的主 Vue 实例中，可以在整个项目中引导 Vuelidate 的`$v`。这样我们就可以使用`$v`对象来获取关于表单当前状态的信息，跨越所有组件的 Vue 实例。

# 使用 Vuelidate

让我们创建一个基本表单，允许我们输入`firstName`、`lastName`、`email`和`password`。这将允许我们使用`Vuelidate`添加验证规则，并在屏幕上可视化它们：

```js
<template>
  <div>
    <form class="form" @submit.prevent="onSubmit">
      <div class="input">
        <label for="email">Email</label>
        <input 
        type="email" 
        id="email" 
        v-model.trim="email">
      </div>
      <div class="input"> 
        <label for="firstName">First Name</label>
        <input 
        type="text"
        id="firstName" 
        v-model.trim="firstName">
      </div>
      <div class="input">
        <label for="lastName">Last Name</label>
        <input 
        type="text" 
        id="lastName" 
        v-model.trim="lastName">
      </div>
      <div class="input">
        <label for="password">Password</label>
        <input 
        type="password" 
        id="password" 
        v-model.trim="password">
      </div>
      <button type="submit">Submit</button>
    </form>
  </div>
</template>
<script>
export default {
  data() {
    return {
      email: '',
      password: '',
      firstName: '',
      lastName: '',
    };
  },
  methods: {
    onSubmit(){
    }
  },
}
</script>
```

这里涉及很多内容，让我们一步一步来分解：

1.  我们正在创建一个新的表单，使用`@submit.prevent`指令，这样当表单提交时页面不会重新加载，这与在表单上调用 submit 并在事件上使用`preventDefault`是一样的。

1.  接下来，我们将在每个表单输入元素中添加`v-model.trim`，以便修剪任何空白并将输入捕获为变量

1.  我们在数据函数中定义这些变量，以便它们是响应式的

1.  `submit`按钮被定义为`type="submit"`，这样当点击它时，表单的`submit`函数就会运行

1.  我们正在创建一个空白的`onSubmit`函数，很快就会创建它

现在我们需要添加`@input`事件，并在每个`input`元素上调用`touch`事件，绑定到数据属性`v-model`，并为字段提供验证，如下所示：

```js
<div class="input">
  <label for="email">Email</label>
  <input 
  type="email" 
  id="email" 
  @input="$v.email.$touch()"
  v-model.trim="email">
</div>
<div class="input"> 
  <label for="firstName">First Name</label>
  <input 
  type="text"
  id="firstName" 
  v-model.trim="firstName"
  @input="$v.firstName.$touch()">
</div>
<div class="input">
  <label for="lastName">Last Name</label>
  <input 
  type="text" 
  id="lastName" 
  v-model.trim="lastName"
  @input="$v.lastName.$touch()">
</div>
<div class="input">
  <label for="password">Password</label>
  <input 
  type="password" 
  id="password" 
  v-model.trim="password"
  @input="$v.password.$touch()">
</div>
```

然后，通过从`Vuelidate`导入它们并添加与表单元素对应的`validations`对象，将验证添加到我们的 Vue 实例中。

`Vuelidate`将使用相同的名称与我们的`data`变量绑定，如下所示：

```js
import { required, email } from 'vuelidate/lib/validators';

export default {
 // Omitted
  validations: {
    email: {
      required,
      email,
    },
    firstName: {
      required,
    },
    lastName: {
      required,
    },
    password: {
      required,
    }
  },
}
```

我们只需导入所需的电子邮件验证器并将其应用于每个模型项。这基本上确保了我们所有的项目都是必需的，并且电子邮件输入与电子邮件正则表达式匹配。然后，我们可以通过添加以下内容来可视化表单和每个字段的当前状态：

```js
 <div class="validators">
  <pre>{{$v}}</pre>
 </div>
```

然后，我们可以添加一些样式来显示右侧的验证和左侧的表单：

```js
<style>
.form {
 display: inline-block;
 text-align: center;
 width: 49%;
}
.validators {
 display: inline-block;
 width: 49%;
 text-align: center;
 vertical-align: top;
}
.input {
 padding: 5px;
}
</style>
```

如果一切都按计划进行，我们应该会得到以下结果：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/6747ab00-f573-40a4-b9cf-d8a5e3ea85b6.png)

# 显示表单错误

我们可以使用`$invalid`布尔值来显示消息或更改表单字段的外观和感觉。让我们首先添加一个名为`error`的新类，它在输入字段周围添加了`red` `border`：

```js
<style>
input:focus {
  outline: none;
}
.error {
  border: 1px solid red;
}
</style>
```

然后，我们可以在字段无效且已触摸时有条件地应用此类，使用`v-bind:class`：

```js
<div class="input">
  <label for="email">Email</label>
  <input 
  :class="{ error: $v.email.$error }"
  type="email" 
  id="email" 
  @input="$v.email.$touch()"
  v-model.trim="email">
</div>
<div class="input"> 
  <label for="firstName">First Name</label>
  <input 
  :class="{ error: $v.firstName.$error }"
  type="text"
  id="firstName" 
  v-model.trim="firstName"
  @input="$v.firstName.$touch()">
</div>
<div class="input">
  <label for="lastName">Last Name</label>
  <input 
  :class="{ error: $v.lastName.$error}"
  type="text" 
  id="lastName" 
  v-model.trim="lastName"
  @input="$v.lastName.$touch()">
</div>
<div class="input">
  <label for="password">Password</label>
  <input 
  :class="{ error: $v.password.$error }"
  type="password" 
  id="password" 
  v-model.trim="password"
  @input="$v.password.$touch()">
</div>
```

这样，每当字段无效或有效时，我们就会得到以下结果：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/9736943a-4ffe-449b-a97e-648983eacdd7.png)

随后，如果是这种情况，我们可以显示错误消息。这可以通过多种方式来完成，具体取决于您想要显示的消息类型。让我们以`email`输入为例，当`email`字段具有无效的电子邮件地址时显示错误消息：

```js
<div class="input">
  <label for="email">Email</label>
  <input 
  :class="{ error: $v.email.$error }"
  type="email" 
  id="email" 
  @input="$v.email.$touch()"
  v-model.trim="email">

  <p class="error-message" v-if="!$v.email.email">Please enter a valid email address</p>
</div>

// Omitted
<style>
.error-message {
 color: red;
}
</style>
```

从我们的`$v`对象的表示中，我们可以看到当字段具有有效的电子邮件地址时，电子邮件布尔值为 true，如果不是，则为 false。虽然这检查电子邮件是否正确，但它并不检查字段是否为空。让我们添加另一个基于`required`验证器的检查这一点的错误消息：

```js
 <p class="error-message" v-if="!$v.email.email">Please enter a valid email address.</p>
 <p class="error-message" v-if="!$v.email.required">Email must not be empty.</p>
```

如果我们愿意，甚至可以更进一步，创建自己的包装组件，用于呈现每个字段的各种错误消息。让我们填写剩下的错误消息，以及检查表单元素是否已被触摸（即`$dirty`）：

```js
<div class="input">
  <label for="email">Email</label>
  <input 
  :class="{ error: $v.email.$error }"
  type="email" 
  id="email" 
  @input="$v.email.$touch()"
  v-model.trim="email">

  <div v-if="$v.email.$dirty">
    <p class="error-message" v-if="!$v.email.email">Please enter a 
    valid email address.</p>
    <p class="error-message" v-if="!$v.email.required">Email must not 
    be empty.</p>
  </div>

</div>
<div class="input"> 
  <label for="firstName">First Name</label>
  <input 
  :class="{ error: $v.firstName.$error }"
  type="text"
  id="firstName" 
  v-model.trim="firstName"
  @input="$v.firstName.$touch()">

  <div v-if="$v.firstName.$dirty">
    <p class="error-message" v-if="!$v.firstName.required">First Name 
  must not be empty.</p>
  </div>
</div>
<div class="input">
  <label for="lastName">Last Name</label>
  <input 
  :class="{ error: $v.lastName.$error}"
  type="text" 
  id="lastName" 
  v-model.trim="lastName"
  @input="$v.lastName.$touch()">

  <div v-if="$v.lastName.$dirty">
    <p class="error-message" v-if="!$v.lastName.required">Last Name 
   must not be empty.</p>
  </div>
</div>
<div class="input">
  <label for="password">Password</label>
  <input 
  :class="{ error: $v.password.$error }"
  type="password" 
  id="password" 
  v-model.trim="password"
  @input="$v.password.$touch()">

  <div v-if="$v.password.$dirty">
    <p class="error-message" v-if="!$v.password.required">Password must 
  not be empty.</p>
  </div>
</div>
```

# 密码验证

在创建用户帐户时，密码往往会被输入两次，并符合最小长度。让我们添加另一个字段和一些更多的验证规则来强制执行这一点：

```js
import { required, email, minLength, sameAs } from 'vuelidate/lib/validators';

export default {
 // Omitted
  data() {
    return {
      email: '',
      password: '',
      repeatPassword: '',
      firstName: '',
      lastName: '',
    };
  },
  validations: {
    email: {
      required,
      email,
    },
    firstName: {
      required,
    },
    lastName: {
      required,
    },
    password: {
      required,
      minLength: minLength(6),
    },
    repeatPassword: {
      required,
      minLength: minLength(6),
      sameAsPassword: sameAs('password'),
    },
  },
}
```

我们已经完成了以下工作：

1.  将`repeatPassword`字段添加到我们的数据对象中，以便它可以保存重复的密码

1.  从`Vuelidate`导入了`minLength`和`sameAs`验证器

1.  将`password`验证器的`minLength`添加为`6`个字符

1.  添加了`sameAs`验证器来强制`repeatPassword`应遵循与`password`相同的验证规则

现在我们已经有了适当的密码验证，我们可以添加新字段并显示任何错误消息：

```js
<div class="input">
 <label for="email">Email</label>
 <input 
 :class="{ error: $v.email.$error }"
 type="email" 
 id="email" 
 @input="$v.email.$touch()"
 v-model.trim="email">

 <div v-if="$v.email.$dirty">
 <p class="error-message" v-if="!$v.email.email">Please enter a valid email address.</p>
 <p class="error-message" v-if="!$v.email.required">Email must not be empty.</p>
 </div>

</div>
<div class="input"> 
 <label for="firstName">First Name</label>
 <input 
 :class="{ error: $v.firstName.$error }"
 type="text"
 id="firstName" 
 v-model.trim="firstName"
 @input="$v.firstName.$touch()">

 <div v-if="$v.firstName.$dirty">
 <p class="error-message" v-if="!$v.firstName.required">First Name must not be empty.</p>
 </div>
</div>
<div class="input">
 <label for="lastName">Last Name</label>
 <input 
 :class="{ error: $v.lastName.$error}"
 type="text" 
 id="lastName" 
 v-model.trim="lastName"
 @input="$v.lastName.$touch()">

 <div v-if="$v.lastName.$dirty">
 <p class="error-message" v-if="!$v.lastName.required">Last Name must not be empty.</p>
 </div>
</div>
<div class="input">
 <label for="password">Password</label>
 <input 
 :class="{ error: $v.password.$error }"
 type="password" 
 id="password" 
 v-model.trim="password"
 @input="$v.password.$touch()">

 <div v-if="$v.password.$dirty">
 <p class="error-message" v-if="!$v.password.required">Password must not be empty.</p>
 </div>
</div>
<div class="input">
 <label for="repeatPassword">Repeat Password</label>
 <input 
 :class="{ error: $v.repeatPassword.$error }"
 type="password" 
 id="repeatPassword" 
 v-model.trim="repeatPassword"
 @input="$v.repeatPassword.$touch()">

 <div v-if="$v.repeatPassword.$dirty">
 <p class="error-message" v-if="!$v.repeatPassword.sameAsPassword">Passwords must be identical.</p>

 <p class="error-message" v-if="!$v.repeatPassword.required">Password must not be empty.</p>
 </div>
</div>
```

# 表单提交

接下来，如果表单无效，我们可以禁用我们的“提交”按钮：

```js
<button :disabled="$v.$invalid" type="submit">Submit</button>
```

我们还可以在 JavaScript 中使用`this.$v.$invalid`来获取此值。以下是一个示例，演示了如何检查表单是否无效，然后根据我们的表单元素创建用户对象：

```js
methods: {
  onSubmit() {
    if(!this.$v.$invalid) {
      const user = { 
        email: this.email,
        firstName: this.firstName,
        lastName: this.lastName,
        password: this.password,
        repeatPassword: this.repeatPassword
      }

      // Submit the object to an API of sorts
    }
  },
},
```

如果您希望以这种方式使用您的数据，您可能更喜欢设置您的数据对象如下：

```js
data() {
  return {
    user: {
      email: '',
      password: '',
      repeatPassword: '',
      firstName: '',
      lastName: '',
    }
  };
},
```

我们现在已经创建了一个具有适当验证的表单！

# 渲染/功能组件

我们将改变方向，从验证和动画转向考虑使用功能组件和渲染函数来提高应用程序性能。您可能也会听到它们被称为“呈现组件”，因为它们是无状态的，只接收数据作为输入属性。

到目前为止，我们只声明了组件的标记，使用了`template`标签，但也可以使用`render`函数（如`src/main.js`中所示）：

```js
import Vue from 'vue'
import App from './App.vue'

new Vue({
  el: '#app',
  render: h => h(App)
})
```

`h`来自超文本，它允许我们用 JavaScript 创建/描述 DOM 节点。在`render`函数中，我们只是渲染`App`组件，将来我们会更详细地看这个。Vue 创建了一个虚拟 DOM，使得处理实际 DOM 变得更简单（以及在处理大量元素时提高性能）。

# 渲染元素

我们可以用以下对象替换我们的`App.vue`组件，该对象接受一个`render`对象和`hyperscript`，而不是使用`template`：

```js
<script>
export default {
 render(h) {
  return h('h1', 'Hello render!')
 }
}
</script>
```

然后渲染一个带有文本节点`'Hello render!'`的新`h1`标签，这就是所谓的**VNode**（**虚拟节点**），复数形式为**VNodes**（**虚拟 DOM 节点**），它描述了整个树。现在让我们看看如何在`ul`中显示一个项目列表：

```js
  render(h){
    h('ul', [
      h('li', 'Evan You'),
      h('li', 'Edd Yerburgh'),
      h('li', 'Paul Halliday')
    ])
 }
```

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/8b05f288-e17e-427c-ae97-8e2b22d23db7.png)

重要的是要意识到，我们只能用超文本渲染一个根节点。这个限制对我们的模板也是一样的，所以我们预期将我们的项目包裹在一个`div`中，就像这样：

```js
render(h) {
 return h('div', [
  h('ul', [
   h('li', 'Evan You'),
   h('li', 'Edd Yerburgh'),
   h('li', 'Paul Halliday')
  ])
 ])
}
```

# 属性

我们还可以向我们渲染的项目传递样式元素和各种其他属性。以下是一个使用`style`对象来将每个项目的颜色更改为`red`的示例：

```js
 h('div', [
  h('ul', { style: { color: 'red' } }, [
   h('li', 'Evan You'),
   h('li', 'Edd Yerburgh'),
   h('li', 'Paul Halliday')
  ])
 ])
```

正如你可以想象的那样，我们可以添加尽可能多的`style`属性，以及我们期望的额外选项，比如`props`、`directives`、`on`（点击处理程序）等。让我们看看如何映射元素以渲染带有`props`的组件。

# 组件和 props

让我们在`components/ListItem.vue`下创建一个`ListItem`组件，其中有一个 prop，`name`。我们将在我们的`li`的位置渲染这个组件，并在包含各种`names`的数组上进行映射。请注意，我们还向我们的 Vue 实例添加了`functional: true`选项；这告诉 Vue 这纯粹是一个呈现组件，它不会有任何自己的状态：

```js
<script>
export default {
 props: ['name'],
 functional: true
}
</script>
```

在我们的`render`函数中，`h`通常也被称为`createElement`，因为我们在 JavaScript 上下文中，我们能够利用数组操作符，如`map`、`filter`、`reduce`等。让我们用`map`替换静态名称，用动态生成的组件：

```js
import ListItem from './components/ListItem.vue';

export default {
 data() {
  return {
   names: ['Evan You', 'Edd Yerburgh', 'Paul Halliday']
  }
 },
 render(createElement) {
  return createElement('div', [
   createElement('ul',
    this.names.map(name => 
     createElement(ListItem, 
      {props: { name: name } })
     ))
   ])
 }
}
```

我们需要做的最后一件事是向我们的组件添加一个`render`函数。作为第二个参数，我们能够访问上下文对象，这使我们能够访问`props`等`options`。在这个例子中，我们假设`name` prop 总是存在且不是`null`或`undefined`：

```js
export default {
 props: ['name'],
 functional: true,
 render(createElement, context) {
  return createElement('li', context.props.name)
 }
}
```

再次，我们现在有一个包含作为`prop`传递的项目的元素列表：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/9982a92b-38a0-4b0f-aaca-ae5e0e436865.png)

# JSX

虽然这是一个很好的思考练习，但在大多数情况下，模板更优越。也许有时您想在组件内部使用`render`函数，在这种情况下，使用 JSX 可能更简单。

让我们通过在终端中运行以下命令将 JSX 的 babel 插件添加到我们的项目中：

```js
**$ npm i -D babel-helper-vue-jsx-merge-props babel-plugin-syntax-jsx babel-plugin-transform-vue-jsx** 
```

然后我们可以更新我们的`.babelrc`以使用新的插件：

```js
{
 "presets": [
 ["env", { "modules": false }],
 "stage-3"
 ],
 "plugins": ["transform-vue-jsx"]
}
```

这使我们能够重写我们的`render`函数，以利用更简单的语法：

```js
render(h) {
 return (
  <div>
   <ul>
    { this.names.map(name => <ListItem name={name} />) }
   </ul>
  </div>
 )
}
```

这更具有声明性，而且更容易维护。在底层，它被转译为以前的`hyperscript`格式与 Babel 一起。

# 总结

在本章中，我们学习了如何在 Vue 项目中利用 CSS 动画和过渡。这使我们能够使用户体验更流畅，并改善我们应用程序的外观和感觉。 

我们还学习了如何使用`render`方法构建我们的 UI；这涉及使用 HyperScript 创建 VNodes，然后使用 JSX 进行更清晰的抽象。虽然您可能不想在项目中使用 JSX，但如果您来自 React 背景，您可能会觉得更舒适。
