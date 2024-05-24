# NuxtJS Web 开发实用指南（三）

> 原文：[`zh.annas-archive.org/md5/95454EEF6B1A13DFE0FAD028BE716A19`](https://zh.annas-archive.org/md5/95454EEF6B1A13DFE0FAD028BE716A19)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

添加 Vue 组件

正如我们在上一章中所述，Vue 组件是 Nuxt 视图的**可选部分**。您已经了解了 Nuxt 视图的各种组成部分：应用程序模板、HTML 头部、布局和页面。但是，我们还没有涵盖 Nuxt 中最小的单位-**Vue 组件**。因此，在本章中，您将学习它的工作原理以及如何利用`/components/`创建自定义组件。然后，您将学习如何创建全局和本地组件，以及基本和全局 mixin，并了解一些用于开发 Vue 或 Nuxt 应用程序的命名约定。最令人兴奋的是，您将发现如何将数据从父组件传递到子组件，以及如何从子组件向父组件发出数据。

在本章中，我们将涵盖以下主题：

+   理解 Vue 组件

+   创建单文件 Vue 组件

+   注册全局和本地组件

+   编写基本和全局 mixin

+   定义组件名称并使用命名约定

让我们开始吧！

# 第五章：理解 Vue 组件

我们在第二章中简要介绍了`/components/`目录，*开始使用 Nuxt*，但我们还没有亲自动手。到目前为止，我们知道如果使用 Nuxt 脚手架工具安装 Nuxt 项目，则该目录中有一个`Logo.vue`组件。该目录中的所有组件都是**Vue 组件**，就像`/pages/`目录中的页面组件一样。主要区别在于`/components/`目录中的这些组件不支持`asyncData`方法。让我们以`/chapter-4/nuxt-universal/sample-website/`中的`copyright.vue`组件为例：

```js
// components/copyright.vue
<template>
  <p v-html="copyright"></p>
</template>

<script>
export default {
  data () {
    return { copyright: '&copy; Lau Tiam Kok' }
  }
}
</script>
```

让我们尝试用`asyncData`函数替换前面代码中的`data`函数，如下所示：

```js
// components/copyright.vue
export default {
  asyncData () {
    return { copyright: '&copy; Lau Tiam Kok' }
  }
}
```

您将收到警告错误，浏览器控制台上会显示“属性或方法“copyright”未定义...”。那么，我们如何动态获取版权目的的数据呢？我们可以使用`fetch`方法直接在组件中使用 HTTP 客户端（例如`axios`）请求数据，如下所示：

1.  在项目目录中通过 npm 安装`axios`包：

```js
$ npm i axios
```

1.  导入`axios`并在`fetch`方法中请求数据，如下所示：

```js
// components/copyright.vue
import axios from 'axios'

export default {
  data () {
    return { copyright: null }
  },
  fetch () {
    const { data } = axios.get('http/path/to/site-info.json')
    this.copyright = data.copyright  
  }
}
```

这种方法可以正常工作，但是最好不要使用 HTTP 请求从有效负载中获取少量数据，最好是请求一次，然后将数据从父作用域传递到其子组件中，如下所示：

```js
// components/copyright.vue
export default {
  props: ['copyright']
}
```

在前面的片段中，子组件是`/components/`目录中的`copyright.vue`文件。这个解决方案的奥妙就在于在组件中使用`props`属性。这样更简单、更整洁，因此是一个优雅的解决方案！但是，如果我们要理解它是如何工作的，以及如何使用它，我们需要了解 Vue 的组件系统。

## 什么是组件？

组件是单一的、自包含的、可重用的 Vue 实例，具有自定义名称。我们使用 Vue 的`component`方法来定义组件。例如，如果我们想定义一个名为`post-item`的组件，我们会这样做：

```js
Vue.component('post-item', {
  data () {
    return { text: 'Hello World!' }
  },
  template: '<p>{{ text }}</p>'
})
```

做完这些之后，当使用`new`语句创建根 Vue 实例时，我们可以在 HTML 文档中将此组件用作`<post-item>`，如下所示：

```js
<div id="post">
  <post-item></post-item>
</div>

<script type="text/javascript">
  Vue.component('post-item', { ... }
  new Vue({ el: '#post' })
</script>
```

所有组件本质上都是 Vue 实例。这意味着它们具有与`new Vue`相同的选项（`data`、`computed`、`watch`、`methods`等），只是少了一些根特定的选项，比如`el`。此外，组件可以嵌套在其他组件中，并最终成为类似树状的组件。然而，当这种情况发生时，传递数据变得棘手。因此，在特定组件中直接使用`fetch`方法获取数据可能更适合这种情况。或者，您可以使用 Vuex 存储，您将在第十章中发现它，“添加 Vuex 存储”。

然而，我们将暂时搁置深度嵌套的组件，专注于本章中简单的父子组件，并学习如何在它们之间传递数据。数据可以从父组件传递到它们的子组件，也可以从子组件传递到父组件。但是我们如何做到这一点呢？首先，让我们找出如何从父组件向子组件传递数据。

## 使用 props 将数据传递给子组件

让我们通过创建一个名为`user-item`的子组件来创建一个小型的 Vue 应用，如下所示：

```js
Vue.component('user-item', {
  template: '<li>John Doe</li>'
})
```

你可以看到它只是一个静态组件，没有太多功能；你根本无法抽象或重用它。只有在我们可以动态地将数据传递到模板内部的`template`属性中时，它才变得可重用。这可以通过`props`属性来实现。让我们对组件进行重构，如下所示：

```js
Vue.component('user-item', {
  props: ['name'],
  template: '<li>{{ name }}</li>'
})
```

在某种意义上，`props`的行为类似于变量，我们可以使用`v-bind`指令为它们设置数据，如下所示：

```js
<ol>
  <user-item
    v-for="user in users"
    v-bind:name="user.name"
    v-bind:key="user.id"
  ></user-item>
</ol>
```

在这个重构的组件中，我们使用`v-bind`指令将`item.name`绑定到`name`，如`v-bind:name`。组件内的 props 必须接受`name`作为该组件的属性。然而，在一个更复杂的应用程序中，我们可能需要传递更多的数据，为每个数据写多个 props 可能会适得其反。因此，让我们重构`<user-item>`组件，使其接受一个名为`user`的单个 prop：

```js
<ol>
  <user-item
    v-for="user in users"
    v-bind:user="user"
    v-bind:key="user.id"
  ></user-item>
</ol>
```

现在，让我们再次重构组件代码，如下所示：

```js
Vue.component('user-item', {
  props: ['user'],
  template: '<li>{{ user.name }}</li>'
})
```

让我们将我们在这里所做的事情放到一个单页 HTML 中，这样您就可以看到更大的图片：

1.  在`<head>`块中包含以下 CDN 链接：

```js
<script src="https://cdn.jsdelivr.net/npm/vue/dist/vue.js"></script>
```

1.  在`<body>`块中创建以下标记：

```js
<div id="app">
  <ol>
    <user-item
      v-for="user in users"
      v-bind:user="user"
      v-bind:key="user.id"
    ></user-item>
  </ol>
</div>
```

1.  将以下代码添加到`<script>`块中：

```js
Vue.component('user-item', {
  props: ['user'],
  template: '<li>{{ user.name }}</li>'
})

new Vue({
  el: '#app',
  data: {
    users: [
      { id: 0, name: 'John Doe' },
      { id: 1, name: 'Jane Doe' },
      { id: 2, name: 'Mary Moe' }
    ]
  }
})
```

在这个例子中，我们将应用程序分解成了更小的单元：一个子组件和一个父组件。然而，它们通过`props`属性进行绑定。现在，我们可以进一步完善它们，而不用担心它们相互干扰。

您可以在本书的 GitHub 存储库中的`/chapter-5/vue/component/basic.html`中找到这个示例代码。

然而，在一个真实而复杂的应用程序中，我们应该将这个应用程序分成更可管理的单独文件（单文件组件）。我们将在*创建单文件 Vue 组件*部分向您展示如何创建它们。但现在，让我们发现如何从子组件将数据传递给父组件。

## 监听子组件事件

到目前为止，您已经学会了如何使用`props`属性将数据传递给子组件。但是如何从子组件将数据传递给父组件呢？我们可以通过使用`$emit`方法和自定义事件来实现这一点，如下所示：

```js
$emit(<event>)
```

您可以选择任何名称作为要在子组件中广播的自定义事件的名称。然后，父组件可以使用`v-on`指令来监听这个广播事件，并决定接下来要做什么。

```js
v-on:<event>="<event-handler>"
```

因此，如果您正在发出一个名为`done`的自定义事件，那么父组件将使用`v-on:done`指令来监听这个`done`事件，然后是一个事件处理程序。这个事件处理程序可以是一个简单的 JavaScript 函数，比如`v-on:done=handleDone`。让我们创建一个简单的应用程序来演示这一点：

1.  创建应用程序的标记，如下所示：

```js
<div id="todos">
  <todo-item
    v-on:completed="handleCompleted"
  ></todo-item>
</div>
```

1.  创建一个子组件，如下所示：

```js
Vue.component('todo-item', {
  template: '<button v-on:click="clicked">Task completed</button>',
  methods: {
    clicked () {
      this.$emit('completed')
    }
  }
})
```

1.  创建一个 Vue 根实例作为父级：

```js
new Vue({
  el: '#todos',
  methods: {
    handleCompleted () {
      alert('Task Done')
    }
  }
})
```

在这个例子中，当`clicked`方法在子组件中触发时，子组件将发出一个`completed`事件。在这里，父组件通过`v-on`接收事件，然后在其端触发`handleCompleted`方法。

您可以在本书的 GitHub 存储库中的`/chapter-5/vue/component/emit/emit-basic.html`中找到这个例子。

### 通过事件发出值

然而，有时仅仅发出一个事件是不够的。在某些情况下，使用带有值的事件更有用。我们可以通过在`$emit`方法中使用第二个参数来实现这一点，如下所示：

```js
$emit(<event>, <value>)
```

然后，当父组件监听事件时，可以以以下格式使用`$event`访问发出的事件的值：

```js
v-on:<event>="<event-handler> = $event"
```

如果事件处理程序是一个方法，那么该值将是该方法的第一个参数，格式如下：

```js
methods: {
  handleCompleted (<value>) { ... }
}
```

因此，现在，我们可以简单地修改前面的应用程序，如下所示：

```js
// Child
clicked () {
  this.$emit('completed', 'Task done')
}

// Parent
methods: {
  handleCompleted (value) {
    alert(value)
  }
}
```

在这里，您可以看到在父组件和子组件之间传递数据是有趣且容易的。但是，如果您的子组件中有一个`<input>`元素，如何将输入字段中的值传递给父组件进行双向数据绑定呢？如果我们了解 Vue 中双向数据绑定的“底层”发生了什么，这并不难。我们将在下一节中学习这个知识点。

您可以在本书的 GitHub 存储库中的`/chapter-5/vue/component/emit/value.html`中找到这个简单的例子，以及在`/chapter-5/vue/component/emit/emit-value-with-props.html`中找到更复杂的例子。

## 使用 v-model 创建自定义输入组件

我们还可以使用组件创建自定义的双向绑定输入，其工作方式与`v-model`指令相同，用于向父组件发出事件。让我们创建一个基本的自定义输入组件：

```js
<custom-input v-model="newTodoText"></custom-input>

Vue.component('custom-input', {
  props: ['value'],
  template: `<input v-on:input="$emit('input', $event.target.value)">`,
})
```

它是如何工作的？要理解这一点，我们需要了解`v-model`在幕后是如何工作的。让我们使用一个简单的`v-model`输入：

```js
<input v-model="handler">
```

前面的`<input>`元素是以下内容的简写：

```js
<input
  v-bind:value="handler"
  v-on:input="handler = $event.target.value"
>
```

因此，在我们的自定义输入中编写`v-model="newTodoText"`是以下内容的简写：

```js
v-bind:value="newTodoText"
v-on:input="newTodoText = $event.target.value"
```

这意味着这个简写下面的组件必须在`props`属性中具有`value`属性，以便让数据从顶部传递下来。它必须发出一个带有`$event.target.value`的`input`事件，以便将数据传递到顶部。

因此，在这个例子中，当用户在`custom-input`子组件中输入时，我们发出值，而父组件通过`v-model="newTodoText"`监听更改，并更新`data`对象中`newTodoText`的值：

```js
<p>{{ newTodoText }}</p>

new Vue({
  el: '#todos',
  data: {
    newTodoText: null
  }
})
```

当你了解 Vue 中双向数据绑定的机制——`v-model`指令时，这就变得很合理了，不是吗？但是，如果你不想使用复选框输入和单选按钮元素的默认值呢？在这种情况下，你会想要将自定义的值发送到父组件中。我们将在下一节中学习如何做到这一点。

你可以在`/chapter-5/vue/component/custom-inputs/basic.html`找到这个简单的例子，在`/chapter-5/vue/component/custom-inputs/props.html`中找到一个更复杂的例子，这两个例子都可以在这本书的 GitHub 存储库中找到。

### 自定义输入组件中的模型定制

默认情况下，自定义输入组件中的模型使用`value`属性作为 prop，`input`作为事件。使用我们之前例子中的`custom-input`组件，可以写成如下形式：

```js
Vue.component('custom-input', {
  props: {
    value: null
  },
  model: {
    prop: 'value', // <-- default
    event: 'input' // <-- default
  }
})
```

在这个例子中，我们不需要指定`prop`和`event`属性，因为它们是该组件模型的默认行为。但是当我们不想对某些输入类型使用这些默认值时，这将变得很有用，比如复选框和单选按钮。

我们可能希望在这些输入中使用`value`属性来实现不同的目的，比如在提交的数据中与复选框的`name`一起发送特定的值，如下所示：

```js
Vue.component('custom-checkbox', {
  model: {
    prop: 'checked',
    event: 'change'
  },
  props: {
    checked: Boolean
  },
  template: `
    <input
      type="checkbox"
      v-bind:checked="checked"
      v-on:change="changed"
      name="subscribe"
      value="newsletter"
    >
  `
  ,
  methods: {
    changed ($event) {
      this.$emit('change', $event.target.checked)
    }
  }
})
```

在这个例子中，我们想要将这两个数据发送到服务器：

```js
name="subscribe"
value="newsletter"
```

我们还可以在使用`JSON.stringify`进行序列化后以 JSON 格式进行：

```js
[{
  "name":"subscribe",
  "value":"newsletter"
}]
```

所以，假设我们在这个组件中没有设置以下自定义模型：

```js
model: {
  prop: 'checked',
  event: 'change'
}
```

在这种情况下，我们只能将以下默认数据发送到服务器：

```js
[{
  "name":"subscribe",
  "value":"on"
}]
```

你可以在这本书的 GitHub 存储库中的`/chapter-5/vue/component/custom-inputs/checkbox.html`中找到这个例子。

当你知道 Vue 组件底层是什么，并且可以通过一点努力进行定制时，这就变得合理了。`/components/`目录中的 Vue 组件与你刚刚学习的组件的工作方式相同。但在深入编写 Nuxt 应用程序的组件之前，你应该了解在使用`v-for`指令时为什么`key`属性很重要。让我们找出来。

## 理解`v-for`循环中的`key`属性

在这本书的许多先前的例子和练习中，你可能注意到了所有`v-for`循环中的`key`属性，如下所示：

```js
<ol>
  <user-item
    v-for="user in users"
    v-bind:user="user"
    v-bind:key="user.id"
  ></user-item>
</ol>
```

也许你会想知道它是什么，它是用来做什么的。`key`属性是每个 DOM 节点的唯一标识，以便 Vue 可以跟踪它们的变化，从而重用和重新排序现有元素。使用`index`作为 key 属性的跟踪是 Vue 默认的行为，因此像这样使用`index`作为 key 属性是多余的：

```js
<div v-for="(user, index) in users" :key="index">
  //...
</div>
```

因此，如果我们希望 Vue 准确地跟踪每个项目的标识，我们必须通过使用`v-bind`指令将每个 key 属性绑定到一个唯一的值，如下所示：

```js
<div v-for="user in users" :key="user.id">
  //...
</div>
```

我们可以使用缩写`:key`来绑定唯一的值，就像前面的例子中所示的那样。还要记住，`key`是一个保留属性。这意味着它不能作为组件 prop 使用：

```js
Vue.component('user-item', {
  props: ['key', 'user']
})
```

在`props`属性中使用`key`将导致浏览器控制台中出现以下错误：

```js
[Vue warn]: "key" is a reserved attribute and cannot be used as 
component prop.
```

当使用`v-for`与组件时，`key`属性是必需的。因此，最好在可能的情况下明确地使用`key`与`v-for`，无论您是否将其与组件一起使用。

为了演示这个问题，让我们创建一个 Vue 应用程序，我们将在其中使用`index`作为我们的`key`，并借助一点 jQuery 的帮助：

1.  在`<head>`块中包含所需的 CDN 链接，以及一些 CSS 样式：

```js
<script src="https://cdn.jsdelivr.net/npm/vue/dist/vue.js"></script>
<script src="http://code.jquery.com/jquery-3.3.1.js"></script>
<style type="text/css">
  .removed {
    text-decoration: line-through;
  }
  .removed button {
    display: none;
  }
</style>
```

1.  在`<body>`块中创建所需的应用程序 HTML 标记：

```js
<div id="todo-list-example">
  <form v-on:submit.prevent="addNewTodo">
    <label for="new-todo">Add a todo</label>
    <input
      v-model="newTodoText"
      id="new-todo"
      placeholder="E.g. Feed the cat"
    >
    <button>Add</button>
  </form>
  <ul>
    <todo-item
      v-for="(todo, index) in todos"
      v-bind:key="index"
      v-bind:title="todo.title"
    ></todo-item>
  </ul>
</div>
```

1.  在`<script>`块中创建所需的组件：

```js
Vue.component('todo-item', {
  template: `<li>{{ title }} <button v-
   on:click="remove($event)">Remove</button></li>`,
  props: ['title'],
  methods: {
    remove: function ($event) {
      $($event.target).parent().addClass('removed')
    }
  }
})
```

1.  创建所需的待办任务列表，如下所示：

```js
new Vue({
  el: '#todo-list-example',
  data: {
    newTodoText: '',
    todos: [
      { id: 1, title: 'Do the dishes' },
      //...
    ],
    nextTodoId: 4
  },
  methods: {
    addNewTodo: function () {
      this.todos.unshift({
        id: this.nextTodoId++,
        title: this.newTodoText
      })
      this.newTodoText = ''
    }
  }
})
```

在这个例子中，我们通过在我们的`todos`数组上发生`unshift`来将一个新的待办任务添加到列表的顶部。我们通过向`li`元素添加`removed`类名来删除一个待办任务。然后，我们使用 CSS 为已删除的待办任务添加删除线，并隐藏删除按钮。

1.  让我们移除`洗碗`。你会看到以下内容：

```js
Do the dishes  (with a strike-through)
```

1.  现在，添加一个名为`喂猫`的新任务。你会看到以下内容：

```js
Feed the cat (with a strike-through)
```

这是因为`喂猫`现在已经占据了`洗碗`的索引，即 0。Vue 只是重用元素而不是渲染新元素。换句话说，无论对项目进行了何种更改，Vue 都将根据数组中的索引更新 DOM 元素。这意味着我们得到了一个意外的结果。

你可以在这本书的 GitHub 存储库中的`/chapter-5/vue/component/key/using-index.html`中找到这个例子。在浏览器上运行它，看看问题出在哪里。然后，将其与在`/chapter-5/vue/component/key/using-id.html`中使用`id`作为键的情况进行比较。你会发现你得到了正确的行为。

使用索引作为 key 的问题也可以通过以下伪代码来解释，其中正在生成一组数字，并为每个数字设置索引作为 key：

```js
let numbers = [1,2,3]

<div v-for="(number, index) in numbers" :key="index">
  // Which turns into number - index
  1 - 0
  2 - 1
  3 - 2
</div>
```

这看起来很棒，乍一看工作正常。但是如果你添加数字 4，索引信息就变得无用了。这是因为现在每个数字都得到了一个新的索引：

```js
<div v-for="(number, index) in numbers" :key="index">
  4 - 0
  1 - 1
  2 - 2
  3 - 3
</div>
```

如你所见，1、2 和 3 失去了它们的状态，必须重新渲染。这就是为什么对于这种情况，使用唯一的 key 是必需的。对于每个项目来说，保持其索引号并且不在每次更改时重新分配是很重要的：

```js
<user-item
  v-for="(user, index) in users"
  v-bind:key="user.id"
  v-bind:name="user.name"
></user-item>
```

作为一个经验法则，每当你以一种导致索引变化的方式操纵列表时，使用 key，这样 Vue 可以在之后正确地更新 DOM。这些操纵包括以下内容：

+   在数组中的任何位置添加一个项目

+   从数组中删除一个项目，从除数组末尾以外的任何位置

+   以任何方式重新排序数组

如果你的列表在组件的生命周期内从未改变过，或者你只是使用 push 函数而不是`unshift`函数添加项目，就像前面的例子一样，那么使用索引作为 key 是可以的。但是如果你试图追踪你何时需要使用索引和何时不需要使用索引，最终你会遇到“bug”，因为你可能会误解 Vue 的行为。

如果你不确定是否要使用索引作为 key，那么最好在`v-for`循环中使用带有不可变 ID 的`key`属性。使用具有唯一值的`key`属性不仅对`v-for`指令很重要，而且对 HTML 表单中的`<input>`元素也很重要。我们将在下一节中讨论这个问题。

## 使用 key 属性控制可重用的元素

为了提供更好的性能，我们发现 Vue 总是重用 DOM 节点而不是重新渲染，这可能会产生一些不良结果，正如前一节所示。这里有另一个没有使用`v-for`的示例，以演示为什么拥有 key 属性是相当重要的：

```js
<div id="app">
  <template v-if="type === 'fruits'">
    <label>Fruits</label>
    <input />
  </template>
  <template v-else>
    <label>Vegetables</label>
    <input />
  </template>
  <button v-on:click="toggleType">Toggle Type</button>
</div>

<script type="text/javascript">
  new Vue({
    el: '#app',
    data: { type: 'fruits' },
    methods: {
      toggleType: function () {
        return this.type = this.type === 'fruits' ? 'vegetables' : 'fruits'
      }
    }
  })
</script>
```

在这个例子中，如果你在输入水果的名字并切换类型，你仍然会在`vegetables`输入框中看到你刚刚输入的名字。这是因为 Vue 试图尽可能地重用相同的`<input>`元素以获得最快的结果。但这并不总是理想的。你可以通过为每个`<input>`元素添加`key`属性以及一个唯一值来告诉 Vue 不要重用相同的`<input>`元素，如下所示：

```js
<template v-if="type === 'fruits'">
  <label>Fruits</label>
  <input key="fruits-input"/>
</template>
<template v-else>
  <label>Vegetables</label>
  <input key="vegetables-input"/>
</template>
```

因此，如果您刷新页面并再次测试，输入字段现在应该按预期工作，而不会在切换它们时“重用”彼此。这不适用于`<label>`元素，因为它们没有`key`属性。但是，从视觉上来看，这不是问题。

您可以在本书的 GitHub 存储库的`/chapter-5/vue/component/key/`目录中的`toggle-with-key.html`和`toggle-without-key.html`文件中找到此示例代码。

这就是您需要了解的关于 Vue 组件基本性质的全部内容。因此，到目前为止，您应该已经掌握了足够的基本知识，可以开始使用单文件组件创建 Vue 组件的下一个级别。让我们开始吧！

如果您想了解更多关于 Vue 组件以及 Vue 组件更深入的部分，例如插槽，请访问[`vuejs.org/v2/guide/components.html`](https://vuejs.org/v2/guide/components.html)。

# 创建单文件 Vue 组件

我们一直在使用单个 HTML 页面编写 Vue 应用程序，以便快速获得我们想要看到的结果。但是在 Vue 或 Nuxt 的实际开发项目中，我们不希望编写这样的东西：

```js
const Foo = { template: '<div>foo</div>' }
const Bar = { template: '<div>bar</div>' }
```

在前面的代码中，我们在一个地方（例如在单个 HTML 页面中）使用 JavaScript 对象创建了两个 Vue 组件，但最好将它们分开，并在单独的`.js`文件中创建每个组件，如下所示：

```js
// components/foo.js
Vue.component('page-foo', {
  data: function () {
    return { message: 'foo' }
  },
  template: '<div>{{ count }}</div>'
})
```

这对于简单的组件可以很好地工作，其中 HTML 布局很简单。但是，在涉及更复杂的 HTML 标记的更复杂布局中，我们希望避免在 JavaScript 文件中编写 HTML。这个问题可以通过具有`.vue`扩展名的单文件组件来解决，如下所示：

```js
// index.vue
<template>
  <p>{{ message }}</p>
</template>

<script>
export default {
  data () {
    return { message: 'Hello World!' }
  }
}
</script>

<style scoped>
p {
  font-size: 2em;
  text-align: center;
}
</style>
```

然而，我们不能只是在浏览器上运行该文件，而不使用构建工具（如 webpack 或 rollup）进行编译。在本书中，我们使用 webpack。这意味着，从现在开始，我们将不再使用 CDN 或单个 HTML 页面来创建复杂的 Vue 应用程序。相反，我们将使用`.vue`和`.js`文件，只有一个`.html`文件来创建我们的 Vue 应用程序。我们将在接下来的部分指导您如何使用 webpack 来帮助我们做到这一点。让我们开始吧。

## 使用 webpack 编译单文件组件

要编译`.vue`组件，我们需要将`vue-loader`和`vue-template-compiler`安装到 webpack 构建过程中。但在此之前，我们必须在项目目录中创建一个`package.json`文件，列出我们项目依赖的 Node.js 包。您可以在[`docs.npmjs.com/creating-a-package-json-file`](https://docs.npmjs.com/creating-a-package-json-file)上查看`package.json`字段的详细信息。最基本和必需的是`name`和`version`字段。让我们开始吧：

1.  在项目目录中创建一个`package.json`文件，其中包含以下必填字段和值：

```js
// package.json
{
  "name": "vue-single-file-component",
  "version": "1.0.0"
}
```

1.  打开一个终端，将目录更改为您的项目，并安装`vue-loader`和`vue-template-compiler`：

```js
$ npm i vue-loader --save-dev 
$ npm i vue-template-compiler --save-dev
```

您应该在终端上看到一个警告，因为您在此处安装的 Node.js 包需要其他 Node.js 包，其中最显着的是 webpack 包。在本书中，我们在本书的 GitHub 存储库中的`/chapter-5/vue/component-webpack/basic/`中设置了一个基本的 webpack 构建过程。我们将在大多数即将推出的 Vue 应用程序中使用此设置。我们已将 webpack 配置文件分成了三个较小的配置文件：

+   `webpack.common.js`包含在开发和生产过程中共享的常见 webpack 插件和配置。

+   `webpack.dev.js`仅包含开发过程的插件和配置。

+   `webpack.prod.js`仅包含生产过程的插件和配置。

以下代码显示了我们如何在`script`命令中使用这些文件：

```js
// package.json
"scripts": {
  "start": "webpack-dev-server --open --config webpack.dev.js",
  "watch": "webpack --watch",
  "build": "webpack --config webpack.prod.js"
}
```

请注意，在本书中，我们假设您已经知道如何使用 webpack 来编译 JavaScript 模块。如果您对 webpack 还不熟悉，请访问[`webpack.js.org/`](https://webpack.js.org/)获取更多信息。

1.  因此，在安装了`vue-loader`和`vue-template-compiler`之后，我们需要在`webpack.common.js`（或`webpack.config.js`，如果您使用单个配置文件）中配置`module.rules`，如下所示：

```js
// webpack.common.js
const VueLoaderPlugin = require('vue-loader/lib/plugin')

module.exports = {
  mode: 'development',
  module: {
    rules: [
      {
        test: /\.vue$/,
        loader: 'vue-loader'
      },
      {
        test: /\.js$/,
        loader: 'babel-loader'
      },
      {
        test: /\.css$/,
        use: [
          'vue-style-loader',
          'css-loader'
        ]
      }
    ]
  },
  plugins: [
    new VueLoaderPlugin()
  ]
}
```

1.  然后，我们可以使用在`package.json`中设置的以下命令来查看我们的应用程序运行情况：

+   `$ npm run start`用于在`localhost:8080`进行实时重新加载和开发

+   `$ npm run watch`用于在`/path/to/your/project/dist/`进行开发

+   `$ npm run build`用于在`/path/to/your/project/dist/`编译我们的代码

就是这样。现在你有了一个基本的构建流程来开发 Vue 应用程序与 webpack。所以，从现在开始，在更复杂的应用程序中，我们将编写单文件组件，并使用这种方法来编译它们。我们将在下一节中创建一个简单的 Vue 应用程序。

## 在单文件组件中传递数据和监听事件

到目前为止，我们一直在使用单个 HTML 页面进行我们的“todo”演示。这一次，我们将使用单文件组件来创建一个简单的“todo”购物清单。让我们开始：

1.  在`<div>`元素中创建一个带有`"todos"`ID 的`index.html`文件，以便 Vue 运行 Vue 实例：

```js
// index.html
<!doctype html>
<html>
  <head>
    <title>Todo Grocery Application (Single File 
     Components)</title>
  </head>
  <body>
    <div id="todos"></div>
  </body>
</html>
```

1.  在项目根目录中创建一个`/src/`目录，并在其中创建一个`entry.js`文件作为文件入口点，以指示 webpack 应该使用哪些模块来开始构建我们的应用程序内部依赖图。webpack 还将使用此文件来找出入口点依赖的其他模块和库（直接和间接）。

```js
// src/entry.js
'use strict'

import Vue from 'vue/dist/vue.js'
import App from './app.vue'

new Vue({
  el: 'todos',
  template: '<App/>',
  components: {
    App
  }
})
```

1.  在`<script>`块中创建一个提供虚拟数据的父组件，其中包含项目列表：

```js
// src/app.vue
<template>
  <div>
    <ol>
      <TodoItem
        v-for="thing in groceryList"
        v-bind:item="thing"
        v-bind:key="item.id"
        v-on:add-item="addItem"
        v-on:delete-item="deleteItem"
      ></TodoItem>
    </ol>
    <p><span v-html="&pound;"></span>{{ total }}</p>
  </div>
</template>

<script>
import TodoItem from './todo-item.vue'
export default {
  data () {
    return {
      cart: [],
      total: 0,
      groceryList: [
        { id: 0, text: 'Lentils', price: 2 },
        //...
      ]
    }
  },
  components: {
    TodoItem
  }
}
</script>
```

在上面的代码中，我们简单地将子组件作为`TodoItem`导入，并使用`v-for`从`groceryList`中生成它们的列表。

1.  在`methods`对象中添加以下方法以添加和删除项目。然后，在`computed`对象中添加一个方法，计算购物车中项目的总成本：

```js
// src/app.vue
methods: {
  addItem (item) {
    this.cart.push(item)
    this.total = this.shoppingCartTotal
  },
  deleteItem (item) {
    this.cart.splice(this.cart.findIndex(e => e === item), 1)
    this.total = this.shoppingCartTotal
  }
},
computed: {
  shoppingCartTotal () {
    let prices = this.cart.map(item => item.price)
    let sum = prices.reduce((accumulator, currentValue) =>
     accumulator + currentValue, 0)
    return sum
  }
}
```

1.  创建一个子组件，通过`props`显示从父级传递下来的项目：

```js
// src/todo-item.vue
<template>
  <li>
    <input type="checkbox" :name="item.id" v-model="checked"> {{
     item.text }}
    <span v-html="&pound;"></span>{{ item.price }}
  </li>
</template>

<script>
export default {
  props: ['item'],
  data () {
    return { checked: false }
  },
  methods: {
    addToCart (item) {
      this.$emit('add-item', item)
    }
  },
  watch: {
    checked (boolean) {
      if (boolean === false) {
        return this.$emit('delete-item', this.item)
      }
      this.$emit('add-item', this.item)
    }
  }
}
</script>
```

在这个组件中，我们还有一个`checkbox`按钮。这用于发出`delete-item`或`add-item`事件，并将项目数据传递给父级。现在，如果你用`$ npm run start`运行应用程序，你应该看到它在`localhost:8080`加载。

干得好！你已经成功构建了一个使用 webpack 的 Vue 应用程序，这就是 Nuxt 在幕后使用的编译和构建你的 Nuxt 应用程序。了解已建立系统下方运行的内容总是有用的。当你知道如何使用 webpack 时，你可以使用刚学到的 webpack 构建设置来进行各种 JavaScript 和 CSS 相关的项目。

你可以在本书的 GitHub 存储库中的`/chapter-5/vue/component-webpack/todo/`中找到这个示例。

在下一节中，我们将把前面几节学到的内容应用到`/chapter-5/nuxt-universal/local-components/sample-website/`中的`sample website`示例网站中，这个示例可以在本书的 GitHub 存储库中找到。

## 在 Nuxt 中添加 Vue 组件

在示例网站中，我们只有两个`.vue`文件可以使用 Vue 组件进行改进：`/layouts/default.vue`和`/pages/work/index.vue`。首先，我们应该改进`/layouts/default.vue`。在这个文件中，我们只需要改进三件事：导航、社交媒体链接和版权。

### 重构**导航**和**社交链接**

我们将从重构导航和社交媒体链接开始：

1.  在`/components/`目录中创建一个导航组件，如下所示：

```js
// components/nav.vue
<template>
  <li>
    <nuxt-link :to="item.link" v-html="item.name">
    </nuxt-link>
  </li>
</template>

<script>
export default {
  props: ['item']
}
</script>
```

1.  在`/components/`目录中也创建一个社交链接组件，如下所示：

```js
// components/social.vue
<template>
  <li>
    <a :href="item.link" target="_blank">
      <i :class="item.classes"></i>
    </a>
  </li>
</template>

<script>
export default {
  props: ['item']
}
</script>
```

1.  将它们导入到布局的`<script>`块中，如下所示：

```js
// layouts/default.vue
import Nav from '~/components/nav.vue'
import Social from '~/components/social.vue'

components: {
  Nav,
  Social
}
```

请注意，如果您在 Nuxt 配置文件中将`components`选项设置为`true`，则可以跳过此步骤。

1.  从`<template>`块中删除现有的导航和社交链接块：

```js
// layouts/default.vue
<template v-for="item in nav">
  <li><nuxt-link :to="item.link" v-html="item.name">
  </nuxt-link></li>
</template>

<template v-for="item in social">
  <li>
    <a :href="item.link" target="_blank">
      <i :class="item.classes"></i>
    </a>
  </li>
</template>
```

1.  用导入的`Nav`和`Social`组件替换它们，如下所示：

```js
// layouts/default.vue
<Nav
  v-for="item in nav"
  v-bind:item="item"
  v-bind:key="item.slug"
 ></Nav>

<Social
  v-for="item in social"
  v-bind:item="item"
  v-bind:key="item.name"
 ></Social>
```

有了这些，你就完成了！

### 重构**版权组件**

现在，我们将重构已经存在于`/components/`目录中的版权组件。让我们开始吧：

1.  从`/components/base-copyright.vue`文件的`<script>`块中删除`data`函数：

```js
// components/copyright.vue
export default {
  data () {
    return { copyright: '&copy; Lau Tiam Kok' }
  }
}
```

1.  用`props`属性替换前面的`data`函数，如下所示：

```js
// components/copyright.vue
export default {
  props: ['copyright']
}
```

1.  将版权数据添加到`<script>`块中，而不是`/layouts/default.vue`中：

```js
// layouts/default.vue
data () {
  return {
    copyright: '&copy; Lau Tiam Kok',
  }
}
```

1.  从`<template>`块中删除现有的`<Copyright />`组件：

```js
// layouts/default.vue
<Copyright />
```

1.  添加一个新的`<Copyright />`组件，并将版权数据绑定到它：

```js
// layouts/default.vue
<Copyright v-bind:copyright="copyright" />
```

到此为止，您应该已经成功将数据从默认页面（父级）传递给组件（子级），在默认页面中保留了您的数据。干得好！这就是`/layouts/default.vue`的全部内容。我们还可以改进工作页面，我们已经为您在`/chapter-5/nuxt-universal/local-components/sample-website/`中完成了这项工作，这可以在本书的 GitHub 存储库中找到。如果您在本地安装此示例网站并在本地机器上运行它，您将看到我们已经很好地应用了我们的组件。通过这个例子，您可以看到在理解了 Vue 组件系统的工作原理后，将布局中的元素抽象化为组件是多么容易。但是，如何将数据传递给父组件呢？为此，我们创建了一个示例应用程序，其中子组件向父组件发出事件，位于`/chapter-5/nuxt-universal/local-components/emit-events/`，这可以在本书的 GitHub 存储库中找到。我们还向应用程序添加了自定义输入和复选框组件，请查看一下。以下是一个示例片段：

```js
// components/input-checkbox.vue
<template>
  <input
    type="checkbox"
    v-bind:checked="checked"
    v-on:change="changed"
    name="subscribe"
    value="newsletter"
  >
</template>

<script>
export default {
  model: {
    prop: 'checked',
    event: 'change'
  },
  props: { checked: Boolean },
  methods: {
    changed ($event) {
      this.$emit('change', $event.target.checked)
    }
  }
}
</script>
```

在这里，您可以看到我们在 Nuxt 应用程序中使用的组件代码与我们在 Vue 应用程序中编写的代码相同。这些类型的组件是嵌套组件。`props`属性和`$emit`方法用于在父组件和子组件之间传递数据。这些嵌套组件也是本地的，因为它们只在导入它们的组件（父级）的范围内可用。因此，从另一个角度来看，Vue 组件可以被归类为本地组件和全局组件。自从*什么是组件？*部分以来，您一直在学习全局组件。但是，您只学会了如何在 Vue 应用程序中使用它们。在接下来的部分中，我们将看看如何为 Nuxt 应用程序注册全局组件。但在跳入其中之前，让我们从整体的角度重新审视 Vue 组件：全局组件和本地组件。

# 注册全局和本地组件

我们已经创建了许多组件，无论是使用`Vue.component()`、纯 JavaScript 对象还是单文件组件引擎。我们创建的一些组件是全局组件，而另一些是本地组件。例如，在上一节中刚刚创建的`/components/`目录中的所有重构组件都是本地组件，而在*什么是组件？*部分中创建的组件都是全局组件。无论它们是本地组件还是全局组件，如果您想使用它们，都必须进行注册。其中一些在创建时注册，而另一些则需要手动注册。在接下来的部分中，您将学习如何全局和本地注册它们。您还将了解两种类型的注册将如何影响您的应用程序。我们将学习如何注册 Vue 组件，而不是传递它们。

## 在 Vue 中注册全局组件

全局组件，正如它们的名称所示，可以在整个应用程序中全局使用。当您使用`Vue.component()`创建它们时，它们会被全局注册：

```js
Vue.component('my-component-name', { ... })
```

全局组件必须在根 Vue 实例实例化之前注册。注册后，它们可以在根 Vue 实例的模板中使用，如下所示：

```js
Vue.component('component-x', { ... })
Vue.component('component-y', { ... })
Vue.component('component-z', { ... })

new Vue({ el: '#app' })

<div id="app">
  <component-x></component-x>
  <component-y></component-y>
  <component-z></component-z>
</div>
```

在这里，您可以看到注册全局组件非常容易 - 在创建它们时，您甚至可能意识不到注册过程。我们将很快在*Nuxt 中注册全局组件*部分中研究这种类型的注册。但现在，我们将学习如何注册本地组件。

## 在 Vue/Nuxt 中注册本地组件

在本章中，我们已经看到并使用了 Vue 和 Nuxt 应用中的本地组件。这些组件是通过使用纯 JavaScript 对象创建的，如下所示：

```js
var ComponentX = { ... }
var ComponentY = { ... }
var ComponentZ = { ... }
```

然后，它们可以通过`components`选项进行注册，如下所示：

```js
new Vue({
  el: '#app',
  components: {
    'component-x': ComponentX,
    'component-y': ComponentY,
    'component-z': ComponentZ
  }
})
```

还记得我们在本书的 GitHub 存储库中的`/chapter-5/vue/component/basic.html`文件中创建的 Vue 应用吗？该应用中的`user-item`组件是一个全局组件。现在，让我们对其进行重构并将其变成一个本地组件：

1.  移除以下全局组件：

```js
Vue.component('user-item', {
  props: ['user'],
  template: '<li>{{ user.name }}</li>'
})
```

1.  使用以下方式替换为本地组件：

```js
const UserItem = {
  props: ['user'],
  template: '<li>{{ user.name }}</li>'
}
```

1.  使用`components`选项注册本地组件：

```js
new Vue({
  el: '#app',
  data: {
    users: [
      { id: 0, name: 'John Doe' },
      //...
    ]
  },
  components: {
    'user-item': UserItem
  }
})
```

该应用程序将与以前的方式相同工作。唯一的区别是`user-item`不再全局可用。这意味着它在任何其他子组件中都不可用。例如，如果您想要在`ComponentZ`中使`ComponentX`可用，那么您必须手动"附加"它：

```js
var ComponentX = { ... }

var ComponentZ = {
  components: {
    'component-x': ComponentX
  }
}
```

如果您正在使用 babel 和 webpack 编写 ES2015 模块，您可以将`ComponentX`作为单文件组件，然后导入它，如下所示：

```js
// components/ComponentZ.vue
import Componentx from './Componentx.vue'

export default {
  components: {
    'component-x': ComponentX
  }
}

<component-x
  v-for="item in items"
  ...
></component-x>
```

您还可以从`components`选项中省略`component-x`，并直接在其中使用`ComponentX`变量，如下所示：

```js
// components/ComponentZ.vue
export default {
  components: {
    ComponentX
  }
}
```

在 ES2015+中使用诸如`ComponentX`之类的变量作为 JavaScript 对象的简写形式为`ComponentX: ComponentX`。由于`component-x`从未注册过，所以您需要在模板中使用`<ComponentX>`而不是`<component-x>`。

```js
<ComponentX
  v-for="item in items"
  ...
></ComponentX>
```

在前面的单文件组件中编写 ES2015 与我们在 Nuxt 中编写`.vue`文件的方式相同。因此，到目前为止，您应该已经意识到我们一直在 Nuxt 应用程序中编写本地组件，例如`/components/copyright.vue`和`/components/nav.vue`。但是在 Nuxt 应用程序中如何编写全局组件呢？这就是`/plugins/`目录发挥作用的地方。在下一节中，您将学习如何在 Nuxt 中进行此操作。

您可以在本书的 GitHub 存储库中的`/chapter-5/vue/component/registering-local-components.html`中找到前面的应用程序。

## 在 Nuxt 中注册全局组件

我们在第二章中学习了目录结构，*开始使用 Nuxt*，`/plugins/`目录是我们可以创建 JavaScript 文件并在实例化根 Vue 应用程序之前运行的最佳位置。因此，这是注册我们的全局组件的最佳位置。

让我们创建我们的第一个全局组件：

1.  在`/plugins/`目录中创建一个简单的 Vue 组件，如下所示：

```js
// components/global/sample-1.vue
<template>
  <p>{{ message }}</p>
</template>

<script>
export default {
  data () {
    return {
      message: 'A message from sample global component 1.'
    }
  }
}
</script>
```

1.  在`/plugins/`目录中创建一个`.js`文件，并导入前面的组件，如下所示：

```js
// plugins/global-components.js
import Vue from 'vue'
import Sample from '~/components/global/sample-1.vue'

Vue.component('sample-1', Sample)
```

1.  我们还可以直接在`/plugins/global-components.js`中创建第二个全局组件，如下所示：

```js
Vue.component('sample-2', {
  render (createElement) {
    return createElement('p', 'A message from sample global
     component 2.')
  }
})
```

1.  告诉 Nuxt 在 Nuxt 配置文件中在实例化根应用程序之前先运行它们，如下所示：

```js
// nuxt.config.js
plugins: [
  '~/plugins/global-components.js',
]
```

请注意，此组件将在 Nuxt 应用程序的客户端和服务器端都可用。如果您只想在特定端上运行此组件，例如仅在客户端上运行，则可以注册它，如下所示：

```js
// nuxt.config.js
plugins: [
  { src: '~/plugins/global-components.js',  mode: 'client' }
]
```

现在，这个组件只能在客户端使用。但是，如果你只想在服务器端运行它，只需在前面的`mode`选项中使用`server`。

1.  我们可以在任何地方使用这些全局组件，而无需手动再次导入它们，如下面的代码所示：

```js
// pages/about.vue
<sample-1 />
<sample-2 />
```

1.  在浏览器上运行应用程序。你应该得到以下输出：

```js
<p>A message from sample global component 1.</p>
<p>A message from sample global component 2.</p>
```

就是这样！这就是你可以通过涉及各种文件在 Nuxt 中注册全局组件的方法。全局注册的底线是使用`Vue.component`，就像我们在 Vue 应用程序中所做的那样。然而，全局注册通常不是理想的，就像它的“表兄弟”全局混入一样，我们将在下一节中介绍。例如，全局注册组件但在大多数情况下不需要它们对于服务器和客户端来说都是不必要的。现在，让我们继续看看混入是什么，以及如何编写它们。

你可以在本书的 GitHub 存储库中的`/chapter-5/nuxt-universal/global-components/`中找到这个例子。

# 编写基本和全局混入

混入只是一个 JavaScript 对象，可以用来包含任何组件选项，比如`created`，`methods`，`mounted`等等。它们可以用来使这些选项可重用。我们可以通过将它们导入到组件中，并将它们与该组件中的其他选项“混合”来实现这一点。

在某些情况下，使用混入可能是有用的，比如在第二章中，*开始使用 Nuxt*。我们知道，当 Vue Loader 编译单文件组件中的`<template>`块时，它会将遇到的任何资源 URL 转换为 webpack 模块请求，如下所示：

```js
<img src="~/assets/sample-1.jpg">
```

前面的图像将被转换为以下 JavaScript 代码：

```js
createElement('img', {
  attrs: {
    src: require('~/assets/sample-1.jpg') // this is now a module request
  }
})
```

如果您手动插入图像，这并不难。但在大多数情况下，我们希望动态插入图像，如下所示：

```js
// pages/about.vue
<template>
  <img :src="'~/assets/images' + post.image.src" :alt="post.image.alt">
</template>

const post = {
  title: 'About',
  image: {
    src: '/about.jpg',
    alt: 'Sample alt 1'
  }
}

export default {
  data () {
    return { post }
  }
}
```

在这个例子中，当您在控制台上使用`:src`指令时，图像将会得到 404 错误，因为 Vue Loader 在构建过程中从未编译它。为了解决这个问题，我们需要手动将模块请求插入到`:src`指令中。

```js
<img :src="require('~/assets/images/about.jpg')" :alt="post.image.alt">
```

然而，这也不好，因为更倾向于动态图像解决方案。因此，这里的解决方案如下：

```js
<img :src="loadAssetImage(post.image.src)" :alt="post.image.alt">
```

在这个解决方案中，我们编写了一个可重用的`loadAssetImage`函数，以便在任何需要的 Vue 组件中调用它。因此，在这种情况下，我们需要混合。有几种使用混合的方法。我们将在接下来的几节中看一些常见的用法。

## 创建基本混合/非全局混合

在非单文件组件 Vue 应用程序中，我们可以这样定义一个混合对象：

```js
var myMixin = {
  created () {
    this.hello()
  },
  methods: {
    hello () { console.log('hello from mixin!') }
  }
}
```

然后，我们可以使用`Vue.extend()`将其“附加”到一个组件中：

```js
const Foo = Vue.extend({
  mixins: [myMixin],
  template: '<div>foo</div>'
})
```

在这个例子中，我们只将这个混合附加到`Foo`，所以当调用这个组件时，你只会看到`console.log`消息。

你可以在这本书的 GitHub 存储库的`/chapter-5/vue/mixins/basic.html`中找到这个例子。

对于 Nuxt 应用程序，我们在`/plugins/`目录中创建并保存混合对象，保存在`.js`文件中。让我们来演示一下：

1.  在`/plugins/`目录中创建一个`mixin-basic.js`文件，其中包含一个在浏览器控制台上打印消息的函数，当 Vue 实例被创建时：

```js
// plugins/mixin-basic.js
export default {
  created () {
    this.hello()
  },
  methods: {
    hello () {
      console.log('hello from mixin!')
    }
  }
}
```

1.  在需要的地方随时导入它，如下所示：

```js
// pages/about.vue
import Mixin from '~/plugins/mixin-basic.js'

export default {
  mixins: [Mixin]
}
```

在这个例子中，只有当你在`/about`路由上时，你才会得到`console.log`消息。这就是我们创建和使用非全局混合的方法。但在某些情况下，我们需要全局混合适用于应用程序中的所有组件。让我们看看我们如何做到这一点。

你可以在这本书的 GitHub 存储库的`/chapter-5/nuxt-universal/mixins/basic/`中找到这个例子。

## 创建全局混合

我们可以通过使用`Vue.mixin()`来创建和应用全局混合：

```js
Vue.mixin({
  mounted () {
    console.log('hello from mixin!')
  }
})
```

全局混合必须在实例化 Vue 实例之前定义：

```js
const app = new Vue({
  //...
}).$mount('#app')
```

现在，你创建的每个组件都将受到影响并显示该消息。你可以在这本书的 GitHub 存储库的`/chapter-5/vue/mixins/global.html`中找到这个例子。如果你在浏览器上运行它，你会看到`console.log`消息出现在每个路由上，因为它在所有路由组件中传播。通过这种方式，我们可以看到如果被滥用可能造成的潜在危害。在 Nuxt 中，我们以相同的方式创建全局混合；也就是使用`Vue.mixin()`。让我们来看一下：

1.  在`/plugins/`目录中创建一个`mixin-utils.js`文件，以及用于从`/assets/`目录加载图像的函数：

```js
// plugins/mixin-utils.js
import Vue from 'vue'

Vue.mixin({
  methods: {
    loadAssetImage (src) {
      return require('~/assets/images' + src)
    }
  }
})
```

1.  在 Nuxt 配置文件中包含前面的全局混合路径：

```js
// nuxt.config.js
module.exports = {
  plugins: [
    '~/plugins/mixin-utils.js'
  ]
}
```

1.  现在，你可以在你的组件中随意使用`loadAssetImage`函数，如下所示：

```js
// pages/about.vue
<img :src="loadAssetImage(post.image.src)" :alt="post.image.alt">
```

请注意，我们不需要像导入基本混入那样导入全局混入，因为我们已经通过`nuxt.config.js`全局注入了它们。但同样，要谨慎而谨慎地使用它们。

您可以在本书的 GitHub 存储库中的`/chapter-5/nuxt-universal/mixins/global/`中找到这个混入的示例。

混入非常有用。全局混入如全局 Vue 组件在数量过多时很难管理，因此会使您的应用难以预测和调试。因此，明智而谨慎地使用它们。我们希望您现在知道 Vue 组件是如何工作的以及如何编写它们。然而，仅仅知道它们是如何工作和如何编写它们是不够的 - 我们应该了解编写可读性和未来可管理性时需要遵守的标准规则。因此，在结束本章之前，我们将看一些这些规则。

# 定义组件名称和使用命名约定

在本章和前几章中，我们已经看到并创建了许多组件。我们创建的组件越多，我们就越需要遵循组件的命名约定。否则，我们将不可避免地会遇到混淆和错误，以及反模式。我们的组件将不可避免地会相互冲突 - 甚至与 HTML 元素相冲突。幸运的是，有一个官方的 Vue 风格指南，我们可以遵循以提高我们应用的可读性。在本节中，我们将介绍一些特定于本书的规则。

## 多词组件名称

我们现有和未来的 HTML 元素都是单词（例如`article`，`main`，`body`等），因此为了防止冲突发生，我们在命名组件时应该使用多个单词（除了根应用组件）。例如，以下做法被认为是不好的：

```js
// .js
Vue.component('post', { ... })

// .vue
export default {
  name: 'post'
}
```

组件的名称应该按照以下方式书写：

```js
// .js
Vue.component('post-item', { ... })

// .vue
export default {
  name: 'PostItem'
}
```

## 组件数据

我们应该始终使用`data`函数而不是`data`属性来处理组件的数据，除了在根 Vue 实例中。例如，以下做法被认为是不好的：

```js
// .js
Vue.component('foo-component', {
  data: { ... }
})

// .vue
export default {
  data: { ... }
}
```

上述组件中的数据应该按照以下方式书写：

```js
// .js
Vue.component('foo-component', {
  data () {
    return { ... }
  }
})

// .vue
export default {
  data () {
    return { ... }
  }
}

// .js or .vue
new Vue({
  data: { ... }
})
```

但是为什么呢？这是因为当 Vue 初始化数据时，它会从`vm.$options.data`创建一个对`data`的引用。因此，如果数据是一个对象，并且一个组件有多个实例，它们都将使用相同的`data`。更改一个实例中的数据将影响其他实例。这不是我们想要的。因此，如果`data`是一个函数，Vue 将使用`getData`方法返回一个只属于当前初始化实例的新对象。因此，根实例中的数据在所有其他组件实例中共享，这些实例包含它们自己的数据。你可以通过`this.$root.$data`从任何组件实例中访问根数据。你可以在本书的 GitHub 存储库中的`/chapter-5/vue/component-webpack/data/`和`/chapter-5/vue/data/basic.html`中查看一些示例。

你可以在[`github.com/vuejs/vue/blob/dev/src/core/instance/state.js#L112`](https://github.com/vuejs/vue/blob/dev/src/core/instance/state.js#L112)上查看 Vue 源代码，了解数据是如何初始化的。

## 属性定义

我们应该在`props`属性中定义属性，以便尽可能详细地指定它们的类型（至少）。只有在原型设计时才可以不进行详细定义。例如，以下做法被认为是不好的：

```js
props: ['message']
```

这应该这样写：

```js
props: {
  message: String
}
```

或者，更好的做法是这样写：

```js
props: {
  message: {
    type: String,
    required: false,
    validator (value) { ... }
  }
}
```

## 组件文件

我们应该始终遵守“一个文件一个组件”的政策；也就是说，一个文件中只写一个组件。这意味着你不应该在一个文件中有多个组件。例如，以下做法被认为是不好的：

```js
// .js
Vue.component('PostList', { ... })

Vue.component('PostItem', { ... })
```

它们应该拆分成多个文件，如下所示：

```js
components/
|- PostList.js
|- PostItem.js
```

如果你在`.vue`中编写组件，应该这样做：

```js
components/
|- PostList.vue
|- PostItem.vue
```

## 单文件组件文件名大小写

我们应该只为单文件组件的文件名使用 PascalCase 或 kebab-case。例如，以下做法被认为是不好的：

```js
components/
|- postitem.vue

components/
|- postItem.vue
```

它们应该这样写：

```js
// PascalCase
components/
|- PostItem.vue

// kebab-case
components/
|- post-item.vue
```

## 自闭合组件

当我们的单文件组件中没有内容时，应该使用自闭合格式，除非它们在 DOM 模板中使用。例如，以下做法被认为是不好的：

```js
// .vue
<PostItem></PostItem>

// .html
<post-item/>
```

它们应该这样写：

```js
// .vue
<PostItem/>

// .html
<post-item></post-item>
```

这些只是一些基本的规则。还有更多规则，比如编写多属性元素的规则，指令简写，带引号的属性值等等。但是我们在这里突出显示的选定规则应该足够让你完成本书。你可以在[`vuejs.org/v2/style-guide/`](https://vuejs.org/v2/style-guide/)找到其他规则和完整的样式指南。

# 摘要

干得好！在本章中，你学会了全局和局部 Vue 组件之间的区别，如何在 Nuxt 应用程序中注册全局组件，以及如何创建局部和全局 mixin。你还学会了如何通过`props`属性将数据传递给子组件，如何使用`$emit`方法从子组件向父组件发出数据，以及如何创建自定义输入组件。然后，你学会了为组件使用`key`属性的重要性。之后，你学会了如何使用 webpack 编写单文件组件。最后但同样重要的是，你了解了在 Nuxt 和 Vue 应用程序开发中应该遵循的一些规则。

在下一章中，我们将进一步探讨`/plugins/`目录的使用，通过编写 Vue 中的自定义插件并导入它们来扩展 Nuxt 应用程序。我们还将研究如何从 Vue 社区导入外部 Vue 插件，通过将它们注入到 Nuxt 的`$root`和`context`组件中创建全局函数，编写基本/异步模块和模块片段，并使用 Nuxt 社区的外部 Nuxt 模块。我们将会对这些进行详细的指导，敬请关注！


编写插件和模块

还记得自从第三章以来在 Nuxt 应用程序中编写一些简单的插件吗，*添加 UI 框架*？正如我们之前提到的，插件本质上是**JavaScript 函数**。在 web 开发中，您总是需要编写自定义函数以适应您的情况，在本书中我们将创建相当多的函数。在本章中，我们将更详细地了解为您的 Nuxt 应用程序创建自定义插件，以及自定义模块。您将学习在 Vue 应用程序中创建自定义插件并在 Nuxt 应用程序中实现它们。然后，您将学习如何在插件之上创建自定义 Nuxt 模块。您还将学习导入和安装现有的 Vue 插件和 Nuxt 模块，这些插件和模块是来自 Vue 和 Nuxt 社区的贡献，可以在您的 Nuxt 应用程序中使用。无论是自定义的还是外部导入的，学习和理解 Vue 插件和 Nuxt 模块都很重要，因为在接下来的章节中我们将经常使用其中的一些。

本章我们将涵盖以下主题：

+   编写 Vue 插件

+   在 Nuxt 中编写全局函数

+   编写 Nuxt 模块

+   编写异步 Nuxt 模块

+   编写 Nuxt 模块片段

# 第六章：编写 Vue 插件

插件是封装在`.js`文件中的全局 JavaScript 函数，可以通过使用`Vue.use`全局方法在应用程序中安装。我们在第四章的过去示例中使用了一些 Vue 插件，例如`vue-router`和`vue-meta`。这些插件必须在使用`new`语句初始化根 Vue 之前通过`Vue.use`方法安装，如下例所示：

```js
// src/entry.js
import Vue from 'vue'
import Meta from 'vue-meta'

Vue.use(Meta)
new VueRouter({ ... })
```

您可以通过`Vue.use`将选项传递到插件中以配置插件的格式：

```js
Vue.use(<plugin>, <options>)
```

例如，我们可以将以下选项传递到`vue-meta`插件中：

```js
Vue.use(Meta, {
  keyName: metaData, // default => metaInfo
  refreshOnceOnNavigation: true // default => false
})
```

选项是可选的。这意味着您可以在不传递任何选项的情况下使用插件本身。`Vue.use`还可以防止您意外多次注入相同的插件，因此多次调用插件将只安装一次。

您可以查看`awesome-vue`，这是一个庞大的社区贡献的插件和库集合，网址为`https://github.com/vuejs/awesome-vuecomponents--libraries`。

现在让我们在下一节中探讨如何创建 Vue 插件。

## 在 Vue 中编写自定义插件

编写 Vue 插件相当容易。您只需要在插件中使用一个`install`方法来接受`Vue`作为第一个参数和`options`作为第二个参数：

```js
// plugin.js
export default {
  install (Vue, options) {
    // ...
  }
}
```

让我们为标准 Vue 应用程序创建一个简单的自定义问候插件，以不同的语言。可以通过`options`参数配置语言；当没有提供选项时，将使用英语作为默认语言：

1.  在`/src/`目录中创建一个`/plugins/`文件夹，并在其中创建一个`basic.js`文件，其中包含以下代码：

```js
// src/plugins/basic.js
export default {
  install (Vue, options) {
    if (options === undefined) {
      options = {}
    }
    let { language } = options
    let languages = {
      'EN': 'Hello!',
      'ES': 'Hola!'
    }
    if (language === undefined) {
      language = 'EN'
    }
    Vue.prototype.$greet = (name) => {
      return languages[language] + ' ' + name
    }
    Vue.prototype.$message = 'Helló Világ!'
  }
}
```

在这个简单的插件中，我们还添加了一个名为`$message`的实例属性，其默认值为匈牙利语的“Hello World!”（`Helló Világ!`），当此插件在组件中使用时可以进行修改。请注意，`{ language } = options`是使用 ES6 编写`language = options.language`的方式。此外，我们应该使用`$`作为方法和属性的前缀，因为这是一种惯例。

1.  安装和配置此插件如下：

```js
// src/entry.js
import PluginSample from './plugins/basic'
Vue.use(PluginBasic, {
  language: 'ES'
})
```

1.  然后我们可以在任何 Vue 组件中全局使用该插件，就像以下示例中一样：

```js
// src/components/home.vue
<p>{{ $greet('John') }}</p>
<p>{{ $message }}</p>
<p>{{ messages }}</p>

export default {
  data () {
    let helloWorld = []
    helloWorld.push(this.$message)

    this.$message = 'Ciao mondo!'
    helloWorld.push(this.$message)

    return { messages: helloWorld }
  }
}
```

因此，当您在浏览器上运行应用程序时，您应该在屏幕上看到以下输出：

```js
Hola! John
Ciao mondo!
[ "Helló Világ!", "Ciao mondo!" ]
```

您还可以在插件中使用`component`或`directive`，就像以下示例中一样：

```js
// src/plugins/component.js
export default {
  install (Vue, options) {
    Vue.component('custom-component', {
     // ...
    })
  }
}

// src/plugins/directive.js
export default {
  install (Vue, options) {
    Vue.directive('custom-directive', {
      bind (el, binding, vnode, oldVnode) {
        // ...
      }
    })
  }
}
```

我们还可以使用`Vue.mixin()`将插件注入到所有组件中，如下所示：

```js
// src/plugins/plugin-mixin.js
export default {
  install (Vue, options) {
    Vue.mixin({
      // ...
    })
  }
}
```

您可以在我们的 GitHub 存储库的`/chapter-6/vue/webpack/`中找到前面的示例 Vue 应用程序。

就是这样。创建一个可以在 Vue 应用程序中安装和使用的 Vue 插件非常简单，不是吗？那么在 Nuxt 应用程序中呢？我们如何在 Nuxt 应用程序中安装前面的自定义 Vue 插件？让我们在下一节中找出答案。

## 将 Vue 插件导入到 Nuxt 中

在 Nuxt 应用程序中，该过程基本相同。所有插件都必须在初始化根 Vue 之前运行。因此，如果我们想要使用 Vue 插件，就像之前的示例插件一样，我们需要在启动 Nuxt 应用程序之前设置插件。让我们将我们的自定义`basic.js`插件复制到 Nuxt 应用程序的`/plugins/`目录中，然后执行以下步骤来安装它：

1.  创建一个`basic-import.js`文件，以以下方式在`/plugins/`目录中导入`basic.js`：

```js
// plugins/basic-import.js
import Vue from 'vue'
import PluginSample from './basic'

Vue.use(PluginSample)
```

这次在使用`Vue.use`方法安装插件时，我们跳过了选项。

1.  将`basic-import.js`的文件路径添加到 Nuxt 配置文件的`plugins`选项中，如下所示：

```js
export default {
  plugins: [
    '~/plugins/basic-import',
  ]
}
```

1.  在任何喜欢的页面中使用此插件-就像我们在 Vue 应用程序中所做的那样：

```js
// pages/index.vue
<p>{{ $greet('Jane') }}</p>
<p>{{ $message }}</p>
<p>{{ messages }}</p>

export default {
  data () {
    let helloWorld = []
    helloWorld.push(this.$message)

    this.$message = 'Olá Mundo!'
    helloWorld.push(this.$message)

    return { messages: helloWorld }
  }
}
```

1.  在浏览器上运行 Nuxt 应用程序，您应该在屏幕上看到以下输出：

```js
Hello! Jane
Olá Mundo!
[ "Helló Világ!", "Olá Mundo!" ]
```

这次我们使用`$greet`方法得到了英文版的“Hello!”，因为在安装插件时没有设置任何语言选项。此外，在这个索引页面的`<template>`块中，你将得到“Olá Mundo!”的`$message`，而在其他页面（例如`/about`、`/contact`）上，你将得到“Helló Világ!”，因为我们只在索引页面上设置了这个葡萄牙语版本的“Hello World!”，即`this.$message = 'Olá Mundo!'`。

正如我们在本章开头提到的，有一个庞大的社区贡献的 Vue 插件集合，可能对你的 Nuxt 应用程序有用，但是一些插件可能只在浏览器中工作，因为它们缺乏 SSR（服务器端渲染）支持。因此，在接下来的部分，我们将看看如何解决这种类型的插件。

## 导入没有 SSR 支持的外部 Vue 插件

在 Nuxt 中，有一些 Vue 插件已经预先安装好了，比如`vue-router`、`vue-meta`、`vuex`和`vue-server-renderer`。未安装的插件可以按照我们在上一节中安装自定义 Vue 插件的步骤轻松排序。以下是我们如何在 Nuxt 应用程序中使用`vue-notifications`的示例：

1.  使用 npm 安装插件：

```js
$ npm i vue-notification
```

1.  导入并注入插件，就像我们使用自定义插件一样：

```js
// plugins/vue-notifications.js
import Vue from 'vue'
import VueNotifications from 'vue-notifications'

Vue.use(VueNotifications)
```

1.  将文件路径包含到 Nuxt 配置文件中：

```js
// nuxt.config.js:
export default {
  plugins: ['~/plugins/vue-notifications']
}
```

对于没有 SSR 支持的插件，或者当你只想在客户端上使用这个插件时，你可以在`plugins`选项中使用`mode: 'client'`选项，以确保这个插件不会在服务器端执行，就像下面的例子一样：

```js
// nuxt.config.js
export default {
  plugins: [
    { src: '~/plugins/vue-notifications', mode: 'client' }
  ]
}
```

如你所见，安装 Vue 插件只需要三个步骤，无论是外部插件还是自定义插件。总之，Vue 插件是通过使用`Vue.use`方法将全局 JavaScript 函数注入到 Vue 实例中，并通过在插件内部暴露`install`方法来实现的。但在 Nuxt 本身中，还有其他创建全局函数的方法，可以将它们注入到 Nuxt 上下文（`context`）和 Vue 实例（`$root`）中，而无需使用`install`方法。我们将在接下来的部分中探讨这些方法。

有关`vue-notifications`的更多信息，请访问`https://github.com/euvl/vue-notification`。

# 在 Nuxt 中编写全局函数

在 Nuxt 中，我们可以通过将它们注入到以下三个项目中来创建“插件”或全局函数：

+   Vue 实例（客户端）：

```js
// plugins/<function-name>.js
import Vue from 'vue'
Vue.prototype.$<function-name> = () => {
  //...
}
```

+   Nuxt 上下文（服务器端）：

```js
// plugins/<function-name>.js
export default (context, inject) => {
  context.app.$<function-name> = () => {
    //...
  }
}
```

+   Vue 实例和 Nuxt 上下文：

```js
// plugins/<function-name>.js
export default (context, inject) => {
  inject('<function-name>', () => {
    //...
  })
}
```

使用上述格式，你可以轻松地为你的应用编写全局函数。在接下来的章节中，我们将指导你通过一些示例函数。所以让我们开始吧。

## 将函数注入到 Vue 实例中

在这个例子中，我们将创建一个用于计算两个数字之和的函数，例如，1 + 2 = 3。我们将通过以下步骤将这个函数注入到 Vue 实例中：

1.  创建一个`.js`文件，导入`vue`，并将函数附加到`vue.prototype`中的`/plugins/`目录中：

```js
// plugins/vue-injections/sum.js
import Vue from 'vue'
Vue.prototype.$sum = (x, y) => x + y
```

1.  将函数文件路径添加到 Nuxt 配置文件的`plugins`属性中：

```js
// nuxt.config.js
export default {
  plugins: ['~/plugins/vue-injections/sum']
}
```

1.  在任何你喜欢的地方使用这个函数，例如：

```js
// pages/vue-injections.vue
<p>{{ this.$sum(1, 2) }}</p>
<p>{{ sum }}</p>

export default {
  data () {
    return {
      sum: this.$sum(2, 3)
    }
  }
}
```

1.  在浏览器上运行页面，你应该在屏幕上得到以下输出（即使刷新页面）：

```js
3
5
```

## 将函数注入到 Nuxt 上下文中

在这个例子中，我们将创建一个用于计算一个数字的平方的函数，例如，5 * 5 = 25。我们将通过以下步骤将这个函数注入到 Nuxt 上下文中：

1.  创建一个`.js`文件，并将函数附加到`context.app`中：

```js
// plugins/ctx-injections/square.js
export default ({ app }, inject) => {
  app.$square = (x) => x * x
}
```

1.  将函数文件路径添加到 Nuxt 配置文件的`plugins`选项中：

```js
// nuxt.config.js
export default {
  plugins: ['~/plugins/ctx-injections/square']
}
```

1.  在任何你喜欢的页面上使用这个函数，只要你可以访问到上下文，例如在`asyncData`方法中：

```js
// pages/ctx-injections.vue
<p>{{ square }}</p>

export default {
  asyncData (context) {
    return {
      square: context.app.$square(5)
    }
  }
}
```

1.  在浏览器上运行页面，你应该在屏幕上得到以下输出（即使刷新页面）：

```js
25
```

请注意，`asyncData`总是在页面组件初始化之前调用，你不能在这个方法中访问`this`。因此，你不能在`asyncData`方法中使用你注入到 Vue 实例（`$root`）中的函数，比如我们在前面例子中创建的`$sum`函数（我们将在第八章中更详细地了解`asyncData`）。同样，我们也不能在 Vue 的生命周期钩子/方法（例如`mounted`、`updated`等）中调用上下文注入的函数，比如这个例子中的`$square`函数。但是，如果你想要一个可以从`this`和`context`中使用的函数，让我们看看如何通过在下一节中将这种函数注入到 Vue 实例和 Nuxt 上下文中来实现。

## 将函数注入到 Vue 实例和 Nuxt 上下文中

在这个例子中，我们将创建一个用于计算两个数字之积的函数，例如，2 * 3 = 6。我们将通过以下步骤将这个函数注入到 Vue 实例和 Nuxt 上下文中：

1.  创建一个`.js`文件，并使用`inject`函数封装您的函数：

```js
// plugins/combined-injections/multiply.js
export default ({ app }, inject) => {
  inject('multiply', (x, y) => x  y)
}
```

请注意，`$`会自动添加到您的函数前缀，因此您不必担心将其添加到您的函数中。

1.  将函数文件路径添加到 Nuxt 配置文件的`plugins`属性中：

```js
// nuxt.config.js
export default {
  plugins: ['~/plugins/combined-injections/multiply']
}
```

1.  在任何您可以访问`context`和`this`（Vue 实例）的页面上使用该函数，例如以下示例：

```js
// pages/combined-injections.vue
<p>{{ this.$multiply(4, 3) }}</p>
<p>{{ multiply }}</p>

export default {
  asyncData (context) {
    return { multiply: context.app.$multiply(2, 3) }
  }
}
```

1.  在浏览器上运行页面，您应该在屏幕上得到以下输出（即使在刷新页面时也是如此）：

```js
12
6
```

您可以在任何 Vue 生命周期钩子中使用该函数，例如以下示例：

```js
mounted () {
  console.log(this.$multiply(5, 3))
}
```

您应该在浏览器控制台上得到`15`的输出。此外，您还可以从`Vuex store`的`actions`和`mutations`对象/属性中访问该函数，我们将在第十章中介绍*添加一个 Vuex Store*。

1.  创建一个`.js`文件，并将以下函数封装在`actions`和`mutations`对象中：

```js
// store/index.js
export const state = () => ({
  xNumber: 1,
  yNumber: 3
})

export const mutations = {
  changeNumbers (state, newValue) {
    state.xNumber = this.$multiply(3, 8)
    state.yNumber = newValue
  }
}

export const actions = {
  setNumbers ({ commit }) {
    const newValue = this.$multiply(9, 6)
    commit('changeNumbers', newValue)
  }
}
```

1.  在任何您喜欢的页面上使用前面的存储`action`方法，例如以下示例：

```js
// pages/combined-injections.vue
<p>{{ $store.state }}</p>
<button class="button" v-on:click="updateStore">Update Store</button>

export default {
  methods: {
    updateStore () {
      this.$store.dispatch('setNumbers')
    }
  }
}
```

1.  在浏览器上运行页面，您应该在屏幕上得到以下输出（即使在刷新页面时也是如此）：

```js
{ "xNumber": 1, "yNumber": 3 }
```

1.  单击“更新存储”按钮，前面的数字将更改为存储默认状态如下：

```js
{ "xNumber": 24, "yNumber": 54 }
```

这很棒。通过这种方式，我们可以编写一个在客户端和服务器端都能工作的插件。但有时，我们需要能够在服务器端或客户端独占地使用的函数。为了做到这一点，我们必须指示 Nuxt 如何专门运行我们的函数。让我们在下一节中找出如何做到这一点。

## 注入仅客户端或仅服务器端的插件

在这个例子中，我们将创建一个用于除法的函数，例如，8 / 2 = 4，以及另一个用于减法的函数，例如，8 - 2 = 6。我们将将第一个函数注入到 Vue 实例中，并使其专门用于客户端使用，而将第二个函数注入到 Nuxt 上下文中，并使其专门用于服务器端使用。

1.  创建两个函数，并将它们分别附加`.client.js`和`.server.js`：

```js
// plugins/name-conventions/divide.client.js
import Vue from 'vue'
Vue.prototype.$divide = (x, y) => x / y

// plugins/name-conventions/subtract.server.js
export default ({ app }, inject) => {
  inject('subtract', (x, y) => x - y)
}
```

附加`.client.js`的函数文件将仅在客户端运行，而附加`.server.js`的函数文件将仅在服务器端运行。

1.  将函数文件路径添加到 Nuxt 配置文件的`plugins`属性中：

```js
// nuxt.config.js:
export default {
  plugins: [
    '~/plugins/name-conventions/divide.client.js',
    '~/plugins/name-conventions/subtract.server.js'
  ]
}
```

1.  在任何你喜欢的页面上使用这些插件，比如以下示例：

```js
// pages/name-conventions.vue
<p>{{ divide }}</p>
<p>{{ subtract }}</p>

export default {
  data () {
    let divide = ''
    if (process.client) {
      divide = this.$divide(8, 2)
    }
    return { divide }
  },
  asyncData (context) {
    let subtract = ''
    if (process.server) {
      subtract = context.app.$subtract(10, 4)
    }
    return { subtract }
  }
}
```

1.  在浏览器上运行页面，你应该在屏幕上得到以下输出：

```js
4
6
```

请注意，当你在浏览器上首次运行页面时，你将得到前面的结果，即使在刷新页面时也是如此。但是在第一次加载后，如果你通过`<nuxt-link>`导航到这个页面，你将在屏幕上得到以下输出：

```js
4
```

另外，请注意我们必须将`$divide`方法包裹在`process.client`的 if 条件中，因为它是一个只在客户端执行的函数。如果你移除`process.client`的 if 条件，你将在浏览器中得到一个服务器端错误：

```js
this.$divide is not a function
```

对于`$subtract`方法也是一样的：我们必须将其包裹在`process.server`的 if 条件中，因为它是一个只在服务器端执行的函数。如果你移除`process.server`的 if 条件，你将在浏览器上得到一个客户端错误：

```js
this.$subtract is not a function
```

将函数包裹在`process.server`中可能不是理想的做法

`process.client`的 if 条件每次使用时都会被阻塞。但是在仅在客户端被调用的 Vue 生命周期钩子/方法上，比如`mounted`钩子，你不需要使用`process.client`的 if 条件。因此，你可以在不使用 if 条件的情况下安全地使用你的仅客户端函数，就像以下示例中一样：

```js
mounted () {
  console.log(this.$divide(8, 2))
}
```

你将在浏览器控制台中得到`4`的输出。下表显示了八个 Vue 生命周期钩子/方法，值得知道的是在 Nuxt 应用中只有其中两个会在两端被调用：

| **服务器和客户端** | **仅客户端** |
| --- | --- |

|

+   beforeCreate ()

+   created ()

|

+   beforeMount ()

+   mounted ()

+   beforeUpdate ()

+   updated ()

+   beforeDestroy ()

+   destroyed ()

|

请注意，我们在 Vue 和 Nuxt 应用中一直在使用的`data`方法会在两端被调用，就像`asyncData`方法一样。因此，你可以在**仅客户端**列表下的钩子中使用`$divide`方法，它是专门为客户端使用而制作的，而不需要 if 条件。而对于`$subtract`方法，它是专门为仅在服务器端使用而制作的，你可以在`nuxtServerInit`动作中安全地使用它，就像以下示例中一样：

```js
export const actions = {
  nuxtServerInit ({ commit }, context) {
    console.log(context.app.$subtract(10, 4))
  }
}
```

当您的应用在服务器端运行时，即使刷新页面（任何页面），您将得到`6`的输出。值得知道的是，只能通过这些方法访问 Nuxt 上下文：`nuxtServerInit`和`asyncData`。`nuxtServerInit`操作可以作为第二个参数访问上下文，而`asyncData`方法可以作为第一个参数访问上下文。我们将在第十章中介绍`nuxtServerInit`操作，*添加一个 Vuex Store*，但是，现在在下一节中，我们将看一下在`nuxtServerInit`操作之后，但在 Vue 实例和插件之前以及在`$root`和 Nuxt 上下文注入的函数之前注入到 Nuxt 上下文中的 JavaScript 函数。这种类型的函数称为 Nuxt 模块，通过本章末尾，您将知道如何编写这些模块。让我们开始吧。

# 编写 Nuxt 模块

模块只是一个顶级的 JavaScript 函数，在 Nuxt 启动时执行。Nuxt 会按顺序调用每个模块，并在继续调用 Vue 实例、Vue 插件和要注入到`$root`和 Nuxt 上下文中的全局函数之前等待所有模块完成。因为模块在它们之前被调用（即 Vue 实例等），我们可以使用模块来覆盖模板、配置 webpack 加载器、添加 CSS 库以及执行其他应用所需的任务。此外，模块也可以打包成 npm 包并与 Nuxt 社区共享。您可以查看以下链接，了解由 Nuxt 社区制作的生产就绪模块：

[`github.com/nuxt-community/awesome-nuxt#official`](https://github.com/nuxt-community/awesome-nuxt#official)

让我们试试 Axios 模块，这是一个与 Axios 集成的模块（[`github.com/axios/axios`](https://github.com/axios/axios)）用于 Nuxt。它具有一些功能，例如自动设置客户端和服务器端的基本 URL。我们将在接下来的章节中发现它的一些特性。如果您想了解更多关于这个模块的信息，请访问[`axios.nuxtjs.org/`](https://axios.nuxtjs.org/)。现在，让我们看看如何在以下步骤中使用这个模块：

1.  使用 npm 安装它：

```js
$ npm install @nuxtjs/axios
```

1.  在 Nuxt 配置文件中进行配置：

```js
// nuxt.config.js
module.exports = {
  modules: [
    '@nuxtjs/axios'
  ]
}
```

1.  在任何地方使用，例如在页面的`asyncData`方法中：

```js
// pages/index.vue
async asyncData ({ $axios }) {
  const ip = await $axios.$get('http://icanhazip.com')
  console.log(ip)
}
```

您还可以在`mounted`方法（或`created`，`updated`等）中使用它，如下所示：

```js
// pages/index.vue
async mounted () {
  const ip = await this.$axios.$get('http://icanhazip.com')
  console.log(ip)
}
```

每次导航到`/about`页面时，您应该在浏览器控制台上看到您的 IP 地址。您应该注意到现在您可以像使用原始 Axios 一样发送 HTTP 请求，而无需在需要时导入它，因为它现在通过模块全局注入。很棒，不是吗？接下来，我们将通过从基本模块开始编写您的模块来指导您。

## 编写基本模块

正如我们已经提到的，模块是函数，它们可以选择地打包为 npm 模块。这是您创建模块所需的非常基本的结构：

```js
// modules/basic.js
export default function (moduleOptions) {
  // ....
}
```

您只需在项目根目录中创建一个`/modules/`目录，然后开始编写您的模块代码。请注意，如果您想将模块发布为 npm 包，必须包含以下行：

```js
module.exports.meta = require('./package.json')
```

如果您想创建模块并将其发布为 npm 包，请按照 Nuxt 社区的此模板：

[`github.com/nuxt-community/module-template/tree/master/template`](https://github.com/nuxt-community/module-template/tree/master/template)

无论您是为 Nuxt 社区还是仅为自己的项目创建模块，每个模块都可以访问以下内容：

+   **模块选项：**

我们可以从配置文件中向模块传递 JavaScript 对象中的一些选项，例如：

```js
// nuxt.config.js
export default {
  modules: [
    ['~/modules/basic/module', { language: 'ES' }],
  ]
}
```

然后，您可以在模块函数的第一个参数中将前述选项作为`moduleOptions`访问，如下所示：

```js
// modules/basic/module.js
export default function (moduleOptions) {
  console.log(moduleOptions)
}
```

您将获得从配置文件中传递的以下选项：

```js
{
  language: 'ES'
}
```

+   **配置选项：**

我们还可以创建一个自定义选项（例如`token`，`proxy`或`basic`），并将一些特定选项传递给模块（这个自定义选项可以在模块之间共享使用），如下例所示：

```js
// nuxt.config.js
export default {
  modules: [
    ['~/modules/basic/module'],
  ],
  basic: { // custom option
    option1: false,
    option2: true,
  }
}
```

然后，您可以使用`this.options`访问前述自定义选项，如下所示：

```js
// modules/basic/module.js
export default function (moduleOptions) {
  console.log(this.options['basic'])
}
```

您将获得从配置文件中传递的以下选项：

```js
{
  option1: false,
  option2: true
}
```

然后我们可以将`moduleOptions`和`this.options`组合如下：

```js
// modules/basic/module.js
export default function (moduleOptions) {
  const options = {
    ...this.options['basic'],
    ...moduleOptions
  }
  console.log(options)
}
```

您将获得从配置文件中传递的以下组合选项：

```js
{
  option1: false,
  option2: true
}
```

+   **Nuxt 实例：**

您可以使用`this.nuxt`来访问 Nuxt 实例。请访问以下链接以获取可用方法（例如`hook`方法，我们可以使用它在 Nuxt 启动时创建特定事件的某些任务）：

[`nuxtjs.org/api/internals-nuxt`](https://nuxtjs.org/api/internals-nuxt)

+   **`ModuleContainer`实例：**

您可以使用 `this` 来访问 `ModuleContainer` 实例。请访问以下链接以获取可用方法（例如，`addPlugin` 方法，我们在模块中经常使用它来注册插件）：

[`nuxtjs.org/api/internals-module-container`](https://nuxtjs.org/api/internals-module-container)

+   **`module.exports.meta` 代码行：**

如果您将您的模块发布为 npm 包，则此行是必需的，正如我们之前提到的。但在本书中，我们将指导您完成为您的项目创建模块的步骤。让我们通过以下步骤开始创建一个非常基本的模块：

1.  创建一个带有以下代码的 `module` 文件：

```js
// modules/basic/module.js
const { resolve } = require('path')

export default function (moduleOptions) {
  const options = {
    ...this.options['basic'],
    ...moduleOptions
  }

  // Add plugin.
  this.addPlugin({
    src: resolve(__dirname, 'plugin.js'),
    fileName: 'basic.js',
    options
  })
}
```

1.  创建一个带有以下代码的 `plugin` 文件：

```js
// modules/basic/plugin.js
var options = []

<% if (options.option1 === true) { %>
  options.push('option 1')
<% } %>

<% if (options.option2 === true) { %>
  options.push('option 2')
<% } %>

<% if (options.language === 'ES') { %>
  options.push('language ES')
<% } %>

const basic = function () {
  return options
}

export default ({ app }, inject) => {
  inject('basic', basic)
}
```

请注意，`<%= %>` 符号是 Lodash 用于在 `template` 函数中插入数据属性的插值分隔符。我们稍后将在本章再次介绍它们。有关 Lodash `template` 函数的更多信息，请访问 [`lodash.com/docs/4.17.15#template`](https://lodash.com/docs/4.17.15#template)。

1.  仅在 Nuxt 配置文件中包含模块文件路径（`/modules/basic/module.js`），并提供一些选项，如下所示使用 `basic` 自定义选项：

```js
// nuxt.config.js
export default {
  modules: [
    ['~/modules/basic/module', { language: 'ES' }],
  ],

  basic: {
    option1: false,
    option2: true,
  }
}
```

1.  您可以在任何地方使用它，例如：

```js
// pages/index.vue
mounted () {
  const basic = this.$basic()
  console.log(basic)
}
```

1.  每次访问主页时，您应该在浏览器控制台上看到以下输出：

```js
["option 2", "language ES"]
```

请注意 `module.js` 如何处理高级配置细节，例如语言和选项。它还负责注册 `plugin.js` 文件，该文件执行实际工作。正如您所看到的，该模块是围绕插件的一个包装器。我们将在接下来的章节中更详细地学习这一点。

请注意，如果您只为构建时间和开发编写模块，则应在 Nuxt 配置文件中使用 `buildModules` 选项来注册您的模块，而不是在 Node.js 运行时使用 `modules` 选项。有关此选项的更多信息，请访问 [`nuxtjs.org/guide/modules#build-only-modules`](https://nuxtjs.org/guide/modules#build-only-modules) 和 [`nuxtjs.org/api/configuration-modules`](https://nuxtjs.org/api/configuration-modules)。

# 编写异步 Nuxt 模块

如果您需要在模块中使用 `Promise` 对象，例如，使用 HTTP 客户端从远程 API 获取一些异步数据，那么 Nuxt 可以完美支持。以下是一些选项，您可以使用这些选项编写您的 async 模块。

## 使用 async/await

您可以在您的模块中使用 ES6 的 async/await 与 Axios，这是我们自第四章以来一直在使用的 HTTP 客户端，例如以下示例中：

```js
// modules/async-await/module.js
import axios from 'axios'

export default async function () {
  let { data } = await axios.get(
   'https://jsonplaceholder.typicode.com/posts')
  let routes = data.map(post => '/posts/' + post.id)
  console.log(routes)
}

// nuxt.config.js
modules: [
  ['~/modules/async-await/module']
]
```

在前面的例子中，我们使用 Axios 的`get`方法从远程 API JSONPlaceholder（[`jsonplaceholder.typicode.com/`](https://jsonplaceholder.typicode.com/)）获取所有帖子。当您第一次启动 Nuxt 应用程序时，您应该在终端上看到以下输出：

```js
[
  '/posts/1',
  '/posts/2',
  '/posts/3',
  ...
]
```

## 返回一个 Promise

您可以在您的模块中使用 promise 链并返回`Promise`对象，就像以下示例中一样：

```js
// modules/promise-sample/module.js
import axios from 'axios'

export default function () {
  return axios.get('https://jsonplaceholder.typicode.com/comments')
    .then(res => res.data.map(comment => '/comments/' + comment.id))
    .then(routes => {
      console.log(routes)
    })
}

// nuxt.config.js
modules: [
  ['~/modules/promise-sample/module']
]
```

在这个例子中，我们使用 Axios 的`get`方法从远程 API 获取所有评论。然后我们使用`then`方法来`链`Promise 并打印结果。当您第一次启动 Nuxt 应用程序时，您应该在终端上看到以下输出：

```js
[
  '/comments/1',
  '/comments/2',
  '/comments/3',
  ...
]
```

您可以在我们的 GitHub 存储库的`/chapter-6/nuxt-universal/modules/async/`中找到这两个示例。

有了这两个异步选项和您从前面部分学到的基本模块编写技能，您可以轻松开始创建您的 Nuxt 模块。我们将在下一节中通过编写模块的小片段来查看更多示例 - **片段**。

# 编写 Nuxt 模块片段

在这个主题中，我们将把我们创建的自定义模块分解成小片段。

您可以在我们的 GitHub 存储库的`/chapter-6/nuxt-universal/module-snippets/`中找到所有以下代码。

## 使用顶级选项

记住我们在*编写基本模块*部分中说过的可以传递到模块中的配置选项吗？模块选项是在 Nuxt 配置文件中注册我们的模块的顶级选项。我们甚至可以结合来自不同模块的多个选项，并且它们的选项可以共享。让我们尝试在以下步骤中一起使用`@nuxtjs/axios`和`@nuxtjs/proxy`的示例：

1.  使用 npm 一起安装这两个模块：

```js
$ npm i @nuxtjs/axios
$ npm i @nuxtjs/proxy
```

这两个模块被很好地集成在一起，以防止 CORS 问题，我们将在本书的后面看到并讨论跨域应用程序的开发。不需要手动注册`@nuxtjs/proxy`模块，但它确实需要在您的`package.json`文件的依赖项中。

1.  在 Nuxt 配置文件中注册`@nuxtjs/axios`模块并设置这两个模块的顶级选项：

```js
// nuxt.config.js
export default {
  modules: [
    '@nuxtjs/axios'
  ],
  axios: {
    proxy: true
  },
  proxy: {
    '/api/': { target: 'https://jsonplaceholder.typicode.com/', 
     pathRewrite: {'^/api/': ''} },
  }
}
```

`axios` 自定义选项中的 `proxy: true` 选项告诉 Nuxt 使用 `@nuxtjs/proxy` 模块作为代理。`proxy` 自定义选项中的 `/api/: {...}` 选项告诉 `@nuxtjs/axios` 模块将 [`jsonplaceholder.typicode.com/`](https://jsonplaceholder.typicode.com/) 作为 API 服务器的目标地址，而 `pathRewrite` 选项告诉 `@nuxtjs/axios` 模块在 HTTP 请求期间从地址中删除 `/api/`，因为目标 API 中没有带有 `/api` 的路由。

1.  接下来，在任何组件中无缝使用它们，就像以下示例中一样：

```js
// pages/index.vue
<template>
  <ul>
    <li v-for="user in users">
      {{ user.name }}
    </li>
  </ul>
</template>

<script>
export default {
  async asyncData({ $axios }) {
    const users = await $axios.$get('/api/users')
    return { users }
  }
}
</script>
```

现在，使用这两个模块，我们可以在请求方法（例如 `get`、`post` 和 `put`）中只写更短的 API 地址，比如 `/api/users` 而不是 `https://jsonplaceholder.typicode.com/users`。这样可以使我们的代码更整洁，因为我们不必在每次调用时都写完整的 URL。请注意，我们在 Nuxt 配置文件中配置的 `/api/` 地址将被添加到对 API 端点的所有请求中。因此，我们使用 `pathRewrite`，如我们已经解释的那样，在发送请求时删除它。

你可以在以下链接中找到这两个模块提供的更多信息和顶层选项：

+   [`axios.nuxtjs.org/options`](https://axios.nuxtjs.org/options) 用于 `@nuxtjs/axios`

+   [`github.com/nuxt-community/proxy-module`](https://github.com/nuxt-community/proxy-module) 用于 `@nuxtjs/proxy`

你可以在我们的 GitHub 仓库的 `/chapter-6/nuxt-universal/module-snippets/top-level/` 中找到我们刚创建的示例模块片段。

## 使用 addPlugin 辅助函数

还记得我们在 *编写基本模块* 部分介绍过的 `ModuleContainer` 实例和 `this.addPlugin` 辅助方法吗？在这个示例中，我们将使用这个辅助函数创建一个模块，该模块通过这个辅助函数提供了一个插件，这个插件就是 `bootstrap-vue`，它将被注册到 Vue 实例中。让我们按照以下步骤创建这个模块片段：

1.  安装 Bootstrap 和 BootstrapVue：

```js
$ npm i bootstrap-vue
$ npm i bootstrap
```

1.  创建一个插件文件来导入 `vue` 和 `bootstrap-vue`，然后使用 `use` 方法注册 `bootstrap-vue`：

```js
// modules/bootstrap/plugin.js
import Vue from 'vue'
import BootstrapVue from 'bootstrap-vue/dist/bootstrap-vue.esm'

Vue.use(BootstrapVue)
```

1.  创建一个模块文件，使用 `addPlugin` 方法添加我们刚创建的插件文件：

```js
// modules/bootstrap/module.js
import path from 'path'

export default function (moduleOptions) {
  this.addPlugin(path.resolve(__dirname, 'plugin.js'))
}
```

1.  在 Nuxt 配置文件中添加这个 `bootstrap` 模块的文件路径：

```js
// nuxt.config.js
export default {
  modules: [
    ['~/modules/bootstrap/module']
  ]
}
```

1.  在任何喜欢的组件上开始使用 `bootstrap-vue`；例如，让我们创建一个按钮来切换 Bootstrap 中的警报文本，如下所示：

```js
// pages/index.vue
<b-button @click="toggle">
  {{ show ? 'Hide' : 'Show' }} Alert
</b-button>
<b-alert v-model="show">
  Hello {{ name }}!
</b-alert>

import 'bootstrap/dist/css/bootstrap.css'
import 'bootstrap-vue/dist/bootstrap-vue.css'

export default {
  data () {
    return {
      name: 'BootstrapVue',
      show: true
    }
  }
}
```

有了这个模块片段，我们不必每次在组件上需要时导入`bootstrap-vue`，因为它已经通过前面的片段模块全局添加了。我们只需要导入它的 CSS 文件。在使用示例中，我们使用 Bootstrap 的自定义`<b-button>`组件来切换 Bootstrap 的自定义`<b-alert>`组件。然后，`<b-button>`组件将在该按钮上切换文本“隐藏”或“显示”。

有关 BootstrapVue 的更多信息，请访问[`bootstrap-vue.js.org/`](https://bootstrap-vue.js.org/)。您可以在我们的 GitHub 存储库中的`/chapter-6/nuxt-universal/module-snippets/provide-plugin/`中找到我们刚刚创建的示例模块片段。

## 使用 Lodash 模板

再次，这是我们在*编写基本模块*部分创建的自定义模块中熟悉的内容-利用 Lodash 模板通过使用 if 条件块来改变注册插件的输出。再次，Lodash 模板是一段代码，我们可以用`<%= %>`插值分隔符插入数据属性。让我们在以下步骤中尝试另一个简单的例子：

1.  创建一个插件文件来导入`axios`并添加 if 条件块，以确保为`axios`提供请求 URL，并在您的 Nuxt 应用程序以`dev`模式（`npm run dev`）运行时在终端上打印请求结果以进行调试：

```js
// modules/users/plugin.js
import axios from 'axios'

let users = []
<% if (options.url) { %>
  users = axios.get('<%= options.url %>')
<% } %>

<% if (options.debug) { %>
  // Dev only code
  users.then((response) => {
    console.log(response);
  })
  .catch((error) => {
    console.log(error);
  })
<% } %>

export default ({ app }, inject) => {
  inject('getUsers', async () => {
    return users
  })
}
```

1.  创建一个`module`文件，使用`addPlugin`方法添加我们刚刚创建的插件文件，使用`options`选项传递请求 URL 和`this.options.dev`的布尔值给这个插件：

```js
// modules/users/module.js
import path from 'path'

export default function (moduleOptions) {
  this.addPlugin({
    src: path.resolve(__dirname, 'plugin.js'),
    options: {
      url: 'https://jsonplaceholder.typicode.com/users',
      debug: this.options.dev
    }
  })
}
```

1.  将此模块的文件路径添加到 Nuxt 配置文件中：

```js
// nuxt.config.js
export default {
  modules: [
      ['~/modules/users/module']
    ]
}
```

1.  在任何您喜欢的组件上开始使用`$getUsers`方法，就像以下示例中一样：

```js
// pages/index.vue
<li v-for="user in users">
  {{ user.name }}
</li>

export default {
  async asyncData({ app }) {
    const { data: users } = await app.$getUsers()
    return { users }
  }
}
```

在上面的示例中，Nuxt 将在将插件复制到项目时将`options.url`替换为`https://jsonplaceholder.typicode.com/users`。`options.debug`的 if 条件块将在生产构建时从插件代码中剥离，因此您在生产模式（`npm run build`和`npm run start`）中将看不到终端上的`console.log`输出。

您可以在我们的 GitHub 存储库中的`/chapter-6/nuxt-universal/module-snippets/template-plugin/`中找到我们刚刚创建的示例模块片段。

## 添加 CSS 库

在*使用 addPlugin 助手*部分的模块片段示例中，我们创建了一个模块，允许我们在应用程序中全局使用`bootstrap-vue`插件，而无需使用`import`语句来引入此插件，如下例所示：

```js
// pages/index.vue
<b-button size="sm" @click="toggle">
  {{ show ? 'Hide' : 'Show' }} Alert
</b-button>

import 'bootstrap/dist/css/bootstrap.css'
import 'bootstrap-vue/dist/bootstrap-vue.css'
export default {
  //...
}
```

这看起来非常整洁，因为我们不必每次都导入`bootstrap-vue`，而只需导入 CSS 样式即可。但是，通过模块，我们仍然可以节省几行代码，将样式添加到应用程序的全局 CSS 堆栈中。让我们创建一个新的示例，并看看我们如何在以下步骤中执行该操作：

1.  创建一个模块文件，其中包含一个名为`options`的`const`变量，用于将模块和顶层选项传递给插件文件，以及一个 if 条件块，用于确定是否使用原始 JavaScript 的`push`方法将 CSS 文件推送到 Nuxt 配置文件中的`css`选项中：

```js
// modules/bootstrap/module.js
import path from 'path'
export default function (moduleOptions) {
  const options = Object.assign({}, this.options.bootstrap, 
    moduleOptions)

  if (options.styles !== false) {
    this.options.css.push('bootstrap/dist/css/bootstrap.css')
    this.options.css.push('bootstrap-vue/dist/bootstrap-vue.css')
  }

  this.addPlugin({
    src: path.resolve(__dirname, 'plugin.js'),
    options
  })
}
```

1.  创建一个插件文件，其中注册了`bootstrap-vue`插件，并使用 if 条件 Lodash-template 块打印从模块文件处理的选项：

```js
// modules/bootstrap/plugin.js
import Vue from 'vue'
import BootstrapVue from 'bootstrap-vue/dist/bootstrap-vue.esm'

Vue.use(BootstrapVue)

<% if (options.debug) { %>
  <% console.log (options) %>
<% } %>
```

1.  将模块文件的文件路径添加到 Nuxt 配置文件中，模块选项指定是否在模块文件中禁用 CSS 文件。还要添加顶层选项`bootstrap`，以将布尔值传递给`debug`选项：

```js
// nuxt.config.js
export default {
  modules: [
    ['~/modules/bootstrap/module', { styles: true }]
  ],

  bootstrap: {
    debug: process.env.NODE_ENV === 'development' ? true : false
  }
}
```

1.  从我们的组件中删除 CSS 文件：

```js
// pages/index.vue
<script>
- import 'bootstrap/dist/css/bootstrap.css'
- import 'bootstrap-vue/dist/bootstrap-vue.css'
export default {
  //...
}
</script>
```

因此，最终，我们可以在组件中使用`bootstrap-vue`插件及其 CSS 文件，而无需全部导入它们。以下是将 Font Awesome 的`css`选项快速推送到 Nuxt 配置文件的模块片段的另一个示例：

```js
// modules/bootstrap/module.js
export default function (moduleOptions) {
  if (moduleOptions.fontAwesome !== false) {
    this.options.css.push('font-awesome/css/font-awesome.css')
  }
}
```

如果您想了解有关 Font Awesome 的更多信息，请访问[`fontawesome.com/`](https://fontawesome.com/)。

您可以在我们的 GitHub 存储库的`/chapter-6/nuxt-universal/module-snippets/css-lib/`中找到我们刚刚创建的示例模块片段。

## 注册自定义 webpack 加载器

当我们想要在 Nuxt 中扩展 webpack 配置时，通常会在`nuxt.config.js`中使用`build.extend`来完成。但是，我们也可以通过使用`this.extendBuild`和以下模块/加载器模板来通过模块执行相同的操作：

```js
export default function (moduleOptions) {
  this.extendBuild((config, { isClient, isServer }) => {
    //...
  })
}
```

例如，假设我们想要使用`svg-transform-loader`扩展我们的 webpack 配置，这是一个用于添加或修改 SVG 图像中标记和属性的 webpack 加载器。该加载器的主要目的是允许我们在 SVG 图像上使用`fill`、`stroke`和其他操作。我们还可以在 CSS、Sass、Less、Stylus 或 PostCSS 中使用它；例如，如果您想要用白色填充 SVG 图像，可以使用`fill`将`fff`（CSS 颜色白色代码）添加到图像中，如下所示：

```js
.img {
  background-image: url('./img.svg?fill=fff');
}
```

如果您想要在 Sass 中使用变量`stroke` SVG 图像，可以这样做：

```js
$stroke-color: fff;

.img {
  background-image: url('./img.svg?stroke={$stroke-color}');
}
```

让我们创建一个示例模块，将此加载器注册到 Nuxt webpack 默认配置中，以便我们可以通过以下步骤在 Nuxt 应用程序中操作 SVG 图像：

1.  使用 npm 安装加载器：

```js
$ npm i svg-transform-loader
```

1.  使用我们之前提供的模块/加载器模板创建一个模块文件，如下所示：

```js
// modules/svg-transform-loader/module.js
export default function (moduleOptions) {
  this.extendBuild((config, { isClient, isServer }) => {
    //...
  })
}
```

1.  在`this.extendBuild`的回调函数中，添加以下行以查找文件加载器并从其现有规则测试中删除`svg`：

```js
const rule = config.module.rules.find(
  r => r.test.toString() === '/\\.(png|jpe?g|gif|svg|webp)$/i'
)
rule.test = /\.(png|jpe?g|gif|webp)$/i
```

1.  在前面的代码块之后添加以下代码块，将`svg-transform-loader`加载器推入默认 webpack 配置的模块规则：

```js
config.module.rules.push({
  test: /\.svg(\?.)?$/, // match img.svg and img.svg?param=value
  use: [
    'url-loader',
    'svg-transform-loader'
  ]
})
```

模块现在已经完成，我们可以继续*步骤 5*。

1.  将此模块的文件路径添加到 Nuxt 配置文件中：

```js
// nuxt.config.js
export default {
  modules: [
    ['~/modules/svg-transform-loader/module']
  ]
}
```

1.  开始转换我们组件中的任何 SVG 图像，例如以下内容：

```js
// pages/index.vue
<template>
  <div>
    <div class="background"></div>
    <img src="~/assets/bug.svg?stroke=red&stroke-
     width=4&fill=blue">
  </div>
</template>

<style lang="less">
.background {
   height: 100px;
   width: 100px;
   border: 4px solid red;
   background-image: url('~assets/bug.svg?stroke=red&stroke-
    width=2');
}
</style>
```

您可以在[`www.npmjs.com/package/svg-transform-loader`](https://www.npmjs.com/package/svg-transform-loader)找到有关`svg-transform-loader`的更多信息。如果您想了解有关规则测试的更多信息，并查看 Nuxt 默认 webpack 配置的完整内容，请访问以下链接：

+   [`webpack.js.org/configuration/module/ruletest`](https://webpack.js.org/configuration/module/#ruletest) webpack 规则测试

+   [`github.com/nuxt/nuxt.js/blob/dev/packages/webpack/src/config/base.js`](https://github.com/nuxt/nuxt.js/blob/dev/packages/webpack/src/config/base.js) Nuxt 默认 webpack 配置

您可以在我们的 GitHub 存储库中的`/chapter-6/nuxt-universal/module-snippets/webpack-loader/`中找到我们刚刚创建的示例模块片段。

## 注册自定义 webpack 插件

Nuxt 模块不仅允许我们注册 webpack 加载器，还允许我们使用以下模块/插件架构注册 webpack 插件：`this.options.build.plugins.push`。

```js
export default function (moduleOptions) {
  this.options.build.plugins.push({
    apply(compiler) {
      compiler.hooks.<hookType>.<tap>('<PluginName>', (param) => {
        //...
      })
    }
  })
}
```

`<tap>`取决于挂钩类型；它可以是`tapAsync`，`tapPromise`或`tap`。让我们按照以下步骤通过 Nuxt 模块创建一个非常简单的“Hello World”webpack 插件：

1.  使用我们提供的模块/插件架构创建一个模块文件，以打印“Hello World!”，如下所示：

```js
// modules/hello-world/module.js
export default function (moduleOptions) {
  this.options.build.plugins.push({
    apply(compiler) {
      compiler.hooks.done.tap('HelloWordPlugin', (stats) => {
        console.log('Hello World!')
      })
    }
  })
}

```

请注意，在`done`挂钩被触发时，`stats`（统计信息）被传递为参数。

1.  将此模块的文件路径添加到 Nuxt 配置文件中：

```js
// nuxt.config.js
export default {
 modules: [
 ['~/modules/hello-world/module']
}
```

1.  使用`$ npm run dev`运行你的 Nuxt 应用程序，你应该在终端上看到“Hello World!”。

请注意，`apply`方法，`compiler`，`hooks`和`tap`都是构建 webpack 插件的关键部分。

如果你是新手 webpack 插件开发者，并想了解更多关于如何为 webpack 开发插件，请访问[`webpack.js.org/contribute/writing-a-plugin/`](https://webpack.js.org/contribute/writing-a-plugin/)。

你可以在我们的 GitHub 存储库中的`/chapter-6/nuxt-universal/module-snippets/webpack-plugin/`中找到我们刚刚创建的示例模块片段。

## 在特定挂钩上创建任务

如果你需要在 Nuxt 启动时对特定生命周期事件（例如，当所有模块加载完成时）执行某些任务，你可以创建一个模块，并使用`hook`方法来监听该事件，然后执行任务。请考虑以下示例：

+   如果你想在所有模块加载完成后做一些事情，请尝试以下操作：

```js
export default function (moduleOptions) {
  this.nuxt.hook('modules:done', moduleContainer => {
    //...
  })
}
```

+   如果你想在渲染器创建后做一些事情，请尝试以下操作：

```js
export default function (moduleOptions) {
  this.nuxt.hook('render:before', renderer => {
    //...
  })
}
```

+   如果你想在编译器（webpack 是默认值）启动之前做一些事情，请尝试以下操作：

```js
export default function (moduleOptions) {
  this.nuxt.hook('build:compile', async ({ name, compiler }) => {
    //...
  })
}
```

+   如果你想在 Nuxt 生成页面之前做一些事情，请尝试以下操作：

```js
export default function (moduleOptions) {
  this.nuxt.hook('generate:before', async generator => {
    //...
  })
}
```

+   如果你想在 Nuxt 准备就绪时做一些事情，请尝试以下操作：

```js
export default function (moduleOptions) {
  this.nuxt.hook('ready', async nuxt => {
    //...
  })
}
```

让我们按照以下步骤创建一个简单的模块来监听`modules:done`挂钩/事件：

1.  创建一个模块文件，在所有模块加载完成时打印`'All modules are loaded'`：

```js
// modules/tasks/module.js
export default function (moduleOptions) {
  this.nuxt.hook('modules:done', moduleContainer => {
    console.log('All modules are loaded')
  })
}
```

1.  创建几个模块来打印`'Module 1'`，`'Module 2'`，`'Module 3'`等，如下所示：

```js
// modules/module1.js
export default function (moduleOptions) {
  console.log('Module 1')
}
```

1.  将挂钩模块的文件路径和其他模块添加到 Nuxt 配置文件中：

```js
// nuxt.config.js
export default {
  modules: [
    ['~/modules/tasks/module'],
    ['~/modules/module3'],
    ['~/modules/module1'],
    ['~/modules/module2']
  ]
}
```

1.  使用`$ npm run dev`运行你的 Nuxt 应用程序，你应该在终端上看到以下输出：

```js
Module 3
Module 1
Module 2
All modules are loaded
```

你可以看到挂钩模块总是最后打印，而其余的根据它们在`modules`选项中的顺序打印。

挂钩模块可以是异步的，无论你是使用`async/await`函数还是返回`Promise`。

有关上述钩子和 Nuxt 生命周期事件中的其他钩子的更多信息，请访问以下链接：

+   [模块容器内部钩子](https://nuxtjs.org/api/internals-module-container#hooks) 用于 Nuxt 的模块生命周期事件（`ModuleContainer`类）

+   [构建器内部钩子](https://nuxtjs.org/api/internals-builder#hooks) 用于 Nuxt 的构建生命周期事件（`Builder`类）

+   [生成器内部钩子](https://nuxtjs.org/api/internals-generator#hooks) 用于 Nuxt 的生成生命周期事件（`Generator`类）

+   [渲染器内部钩子](https://nuxtjs.org/api/internals-renderer#hooks) 用于 Nuxt 的渲染生命周期事件（`Renderer`类）

+   [Nuxt 内部钩子](https://nuxtjs.org/api/internals-nuxt#hooks) 用于 Nuxt 本身的生命周期事件（`Nuxt`类）

您可以在我们的 GitHub 存储库的`/chapter-6/nuxt-universal/module-snippets/hooks/`中找到我们刚刚创建的示例模块片段。

# 总结

在本章中，我们已成功涵盖了 Nuxt 中的插件和模块。您已经了解到它们在技术上是您可以为项目创建的 JavaScript 函数，或者从外部来源导入它们。此外，您已经学会了通过将它们注入到 Vue 实例或 Nuxt 上下文中（或两者都有）来为您的 Nuxt 应用创建全局函数，以及创建仅客户端和仅服务器端的函数。最后，您已经学会了通过使用`addPlugin`助手添加 JavaScript 库的模块片段，全局添加 CSS 库，使用 Lodash 模板有条件地更改已注册插件的输出，向 Nuxt 默认 webpack 配置添加 webpack 加载器和插件，以及使用 Nuxt 生命周期事件钩子创建任务，例如`modules:done`。

在接下来的章节中，我们将探索 Vue 表单并将其添加到 Nuxt 应用程序中。您将了解`v-model`在 HTML 元素（如`text`、`textarea`、`checkbox`、`radio`和`select`）中的工作原理。您将学会如何在 Vue 应用程序中验证这些元素，绑定默认和动态数据，并使用`.lazy`和`.trim`等修饰符来修改或强制输入值。您还将学会使用 Vue 插件`vee-validate`对它们进行验证，然后将其应用到 Nuxt 应用程序中。我们将引导您顺利地完成所有这些领域。敬请关注。
