# Vue2 秘籍（五）

> 原文：[`zh.annas-archive.org/md5/dd7447834c754d87cebc9999e0cff7f3`](https://zh.annas-archive.org/md5/dd7447834c754d87cebc9999e0cff7f3)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：高级 Vue.js - 指令、插件和渲染函数

在本章中，我们将讨论以下主题：

+   创建一个新的指令

+   在 Vue 中使用 WebSockets

+   为 Vue 编写插件

+   手动渲染一个简单的组件

+   渲染带有子元素的组件

+   使用 JSX 渲染组件

+   创建一个功能性组件

+   使用高阶组件构建响应式表格

# 介绍

指令和插件是以可重用的方式打包功能并使其在应用程序和团队之间易于共享的方法；在本章中，您将构建其中的一些。渲染函数是 Vue 在幕后实际工作的方式，将模板转换为 Vue 语言，然后再次转换为 HTML 和 JavaScript；如果您需要优化应用程序的性能并处理一些特殊情况，它们将非常有用。

通常情况下，应尽量避免在可能的情况下使用这些高级功能，因为它们在过去有点被滥用。通常，许多问题可以通过编写一个良好的组件并分发组件本身来解决；只有在这种情况不成立时，您才应该考虑使用高级功能。

本章面向稍有经验的开发者，您可能不会在其他示例中找到逐步详细说明的水平，但我努力使它们完整。

# 创建一个新的指令

指令类似于小型函数，您可以使用它们快速地插入到您的代码中，主要是为了改善用户体验，并向您的图形界面添加新的低级功能。

# 准备工作

尽管这个示例在高级章节中，但它非常容易完成。指令之所以被称为“高级”是因为通常应该优先选择组合来为应用程序添加功能和样式。当组件无法满足需求时，可以使用指令。

# 如何操作...

我们将构建一个`v-pony`指令，将任何元素转换为小马元素。小马元素具有粉色背景，并在单击时更改颜色。

小马元素的 HTML 代码如下所示：

```js
<div id="app">

  <p v-pony>I'm a pony paragraph!</p>

  <code v-pony>Pony code</code>

  <blockquote>Normal quote</blockquote>

  <blockquote v-pony>I'm a pony quote</blockquote>

</div>

```

为了显示差异，我包含了一个普通的`blockquote`元素。在我们的 JavaScript 部分，写入以下内容：

```js
Vue.directive('pony', {

  bind (el) {

    el.style.backgroundColor = 'hotpink'

  }

})

```

这是如何声明新指令的。当指令绑定到元素时，将调用`bind`钩子。现在我们只是设置背景颜色。我们还希望在每次点击后更改颜色。要做到这一点，您必须添加以下代码：

```js
Vue.directive('pony', {

  bind (el) {

    el.style.backgroundColor = 'hotpink'

    el.onclick = () => {

 const colGen = () => 

 Math.round(Math.random()*255 + 25)

 const cols =

 [colGen() + 100, colGen(), colGen()]

 const randRGB =

 `rgb(${cols[0]}, ${cols[1]}, ${cols[2]})`

 el.style.backgroundColor = randRGB

 }

  }

})

```

在这里，我们正在创建一个`onclick`监听器，它将生成一个偏向红色的随机颜色，并将其分配为新的背景颜色。

在我们的 JavaScript 末尾，不要忘记创建一个`Vue`实例：

```js
new Vue({

  el: '#app'

})

```

您可以启动应用程序以查看指令的效果：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-cb/img/Image00159.jpg)

不要忘记点击文本以更改背景颜色！

# 工作原理...

声明新指令的语法如下所示：

```js
Vue.directive(<name: String>, {

  // hooks

})

```

这将注册一个新的全局指令。在 hooks 对象内部，您可以定义两个重要的函数：`bind`，您在本示例中使用的函数，以及`update`，它在其中包含的组件每次更新时触发。

每个钩子函数至少被调用三个参数：

+   `el`：HTML 元素

+   `binding`：指令可以接收一个参数；binding 是一个包含参数值的对象

+   `vnode`：此元素的 Vue 内部表示

我们使用`el`参数直接编辑元素的外观。

# 在 Vue 中使用 WebSockets

WebSockets 是一种新技术，它使用户和托管应用程序的服务器之间可以进行双向通信。在这项技术出现之前，只有浏览器可以发起请求和连接。如果页面上有更新，浏览器必须不断地轮询服务器。使用 WebSockets，这不再是必需的；在建立连接后，服务器只有在需要时才能发送更新。

# 准备工作

您不需要为此示例做任何准备，只需要了解 Vue 的基础知识。如果您不知道什么是 WebSockets，您实际上不需要知道，只需将其视为服务器和浏览器之间连续双向通信的通道。

# 如何操作...

对于这个示例，我们需要一个充当客户端的服务器和浏览器。我们不会构建一个服务器；相反，我们将使用一个已经存在的服务器，通过 WebSockets 将您发送的任何内容回显。因此，如果我们发送`Hello`消息，服务器将回复`Hello`。

您将构建一个聊天应用程序，该应用程序将与此服务器进行通信。编写以下 HTML 代码：

```js
<div id="app">

  <h1>Welcome</h1>

  <pre>{{chat}}</pre>

  <input v-model="message" @keyup.enter="send">

</div>

```

`<pre>`标签将帮助我们渲染聊天记录。由于我们不需要`<br/>`元素来换行，我们可以使用特殊字符`n`表示换行。

为了使我们的聊天工作，我们首先必须在 JavaScript 中声明我们的 WebSocket：

```js
 const ws = new WebSocket('ws://echo.websocket.org')

```

之后，我们声明我们的`Vue`实例，其中包含一个`chat`字符串（用于保存到目前为止的聊天记录）和一个`message`字符串（用于保存我们当前正在编写的消息）：

```js
new Vue({

  el: '#app',

  data: {

    chat: '',

    message: ''

  }

})

```

我们仍然需要定义`send`方法，该方法在文本框中按下*Enter*时调用：

```js
new Vue({

  el: '#app',

  data: {

    chat: '',

    message: ''

  },

  methods: {

 send () {

 this.appendToChat(this.message)

 ws.send(this.message)

 this.message = ''

 },

 appendToChat (text) {

 this.chat += text + 'n'

 }

 }

}

```

我们将`appendToChat`方法分解出来，因为我们将使用它来附加我们收到的所有消息。为此，我们必须等待组件被实例化。`created`钩子是一个安全的地方：

```js
...

created () {

  ws.onmessage = event => {

    this.appendToChat(event.data)

  }

}

...

```

现在启动应用程序与您的个人回声室聊天：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-cb/img/Image00160.jpg)

# 工作原理...

要查看您构建的内容的内部，请打开 Chrome 开发者工具（！[](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-cb/img/Image00161.jpg) | 更多工具 | 开发者工具或*Opt* + *Cmd* + *I*）：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-cb/img/Image00162.jpg)

转到网络选项卡并重新加载页面；您应该看到`echo.websocket.orl` WebSocket，如屏幕截图所示。输入一些内容，消息将出现在帧选项卡中，如下所示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-cb/img/Image00163.jpg)

绿色消息是您发送的消息，而白色消息是您接收的消息。您还可以检查消息的长度（以字节为单位）以及发送或接收的确切时间。

# 为 Vue 编写一个插件

插件是我们想要在应用程序中拥有的一组实用工具或全局新行为。Vuex 和 vue-router 是 Vue 插件的两个著名例子。插件可以是任何东西，因为编写插件意味着在非常低的层次上进行操作。你可以编写不同类型的插件。对于这个示例，我们将专注于构建具有全局属性的指令。

# 准备工作

这个示例将基于*创建一个新的指令*，只是我们将添加一些用于全局协调的功能。

# 如何做...

对于这个示例，我们将为一个袋鼠欣赏俱乐部建立一个网站。主页 HTML 的布局如下：

```js
<div id="app">

  <h1>Welcome to the Kangaroo club</h1>

  <img src="https://goo.gl/FVDU1I" width="300px" height="200px">

  <img src="https://goo.gl/U1Hvez" width="300px" height="200px">

  <img src="https://goo.gl/YxggEB" width="300px" height="200px">

  <p>We love kangaroos</p>

</div>

```

你可以将袋鼠图片的链接更改为你喜欢的链接。

在 JavaScript 部分，我们暂时实例化一个空的`Vue`实例：

```js
new Vue({

  el: '#app'

})

```

如果我们现在打开页面，会得到这个结果：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-cb/img/Image00164.jpg)

现在，我们想在网站上添加一个有趣的注释。我们希望页面上的元素（除了标题）以随机的时间间隔跳动。

为了实现这个目标，你将实现的策略是将所有需要跳动的元素注册到一个数组中，然后定期选择一个随机元素并使其跳动。

我们首先需要定义 CSS 中的跳动动画：

```js
@keyframes generateJump {

  20%{transform: translateY(0);}

  40%{transform: translateY(-30px);}

  50%{transform: translateY(0);}

  60%{transform: translateY(-15px);}

  80%{transform: translateY(0);}

}

.kangaroo {

  animation: generateJump 1.5s ease 0s 2 normal;

}

```

这样做的效果是创建一个名为`kangaroo`的类，当应用于一个元素时，它会沿着 y 轴跳动两次。

接下来，编写一个函数，在 JavaScript 中将这个类添加到指定的元素上：

```js
const jump = el => {

  el.classList.add('kangaroo')

  el.addEventListener('animationend', () => {

    el.classList.remove('kangaroo')

  })

}

```

`jump`函数会添加`kangaroo`类，并在动画完成后将其移除。

我们希望在注册的元素中随机选择一个执行此操作：

```js
const doOnRandomElement = (action, collection) => {

  if (collection.length === 0) {

    return

  }

  const el = 

    collection[Math.floor(Math.random()*collection.length)]

  action(el)

}

```

`doOnRandomElement`函数接受一个动作和一个集合，并将该动作应用于一个随机选择的元素。然后，我们需要在随机的时间间隔内调度它：

```js
const atRandomIntervals = action => {

  setTimeout(() => {

    action()

    atRandomIntervals(action)

  }, Math.round(Math.random() * 6000))

}

```

`atRandomIntervals`函数接受指定的函数，并在小于 6 秒的随机时间间隔内调用它。

现在我们已经拥有了构建使元素跳跃的插件所需的所有函数：

```js
const Kangaroo = {

  install (vueInstance) {

    vueInstance.kangaroos = []

    vueInstance.directive('kangaroo', {

      bind (el) {

       vueInstance.kangaroos.push(el)

      }

    })

    atRandomIntervals(() => 

      doOnRandomElement(jump, vueInstance.kangaroos))

  }

}

```

Kangaroo 插件在安装时创建一个空数组；它声明了一个新的指令`kangaroo`，该指令将所有包含在其中的元素注册到数组中。

然后在随机的时间间隔内，从数组中随机选择一个元素，并调用跳跃函数。

要激活插件，在声明`Vue`实例之前（但在声明`Kangaroo`之后）需要添加一行代码：

```js
Vue.use(Kangaroo)

new Vue({

  el: '#app'

})

```

我们必须选择跳动的元素，也就是除了标题以外的所有元素：

```js
 <div id="app">

   <h1>Welcome to the Kangaroo club</h1>

   <img v-kangaroo

 src="https://goo.gl/FVDU1I" width="300px" height="200px">

   <img v-kangaroo

 src="https://goo.gl/U1Hvez" width="300px" height="200px">

   <img v-kangaroo

 src="https://goo.gl/YxggEB" width="300px" height="200px">

   <p v-kangaroo

>We love kangaroos</p>

 </div>

```

如果现在运行您的应用程序，您将看到图像或文本每隔几秒钟像袋鼠一样跳动。

# 工作原理...

本质上，Vue 插件只是一种将一些功能组合在一起的方式。没有太多限制，创建插件的唯一要做的就是声明一个安装函数。一般的语法如下所示：

```js
MyPlugin.install = (vueInstance, option) => {

  // ...

}

```

要使用您刚刚创建的插件，编写以下代码：

```js
Vue.use(MyPlugin, { 

/* any option you need */

 }) 

```

这里，第二个参数是传递给`install`函数的可选对象。

由于插件是全局实体，您应该尽量少使用它们，只用于您预见会影响整个应用程序的功能。

# 手动渲染一个简单的组件

Vue 将您的 HTML 模板转换为渲染函数。通常，您应该坚持使用模板，因为它们更简单。有几种情况下，渲染函数变得非常有用。在这里，我们展示了一个简单的例子，其中渲染函数很有用。

# 准备工作

这是有关渲染函数的第一个示例。如果您已经了解 Vue 的基础知识，您将理解其中的一切。

# 如何实现...

渲染函数的第一个用例是当您只想要一个显示另一个组件的`Vue`实例时。

编写一个空的 HTML 布局，如下所示：

```js
 <div id="app"></div>

```

我们有一个名为 Greeter 的组件，我们希望将其显示为主要的`Vue`实例。在 JavaScript 部分，添加以下代码：

```js
const Greeter = {

  template: '<p>Hello World</p>'

}

```

在这里，我们必须想象我们从其他地方获取了`Greeter`组件，并且由于组件已经很好地打包，我们不想修改它。相反，我们将它传递给`Vue`主实例：

```js
const Greeter = {

  template: '<p>Hello World</p>'

}

new Vue({

 el: '#app',

 render: h => h(Greeter)

})

```

如果我们现在启动应用程序，我们只会看到`Greeter`组件。主`Vue`实例只充当包装器。

# 工作原理...

渲染函数替换了`Vue`实例中的模板。当调用渲染函数时，传递的参数是所谓的`createElement`函数。为了简洁起见，我们将其命名为`h`。这个函数接受三个参数，但现在只需要注意我们传递的第一个参数（也是唯一一个参数）是`Greeter`组件。

理论上，您可以在`h`函数内联编写组件。在实际项目中，这并不总是可能的，这取决于运行时是否存在 Vue 模板编译器。当您使用官方的 Webpack 模板时，您会被问到是否要在分发软件时包含 Vue 模板编译器。

`createElement`函数的参数在这里列出：

1.  作为第一个参数，唯一必需的参数，您可以选择传递三种不同的内容：

+   Vue 组件的选项，就像我们的示例中一样

+   表示 HTML 标签的字符串（例如`div`、`h1`和`p`）

+   一个返回 Vue 组件的选项对象或表示 HTML 标签的字符串的函数

1.  第二个参数必须是一个名为**Data Object**的对象。这个对象将在下一个示例中解释。

1.  第三个参数是一个数组或字符串：

+   数组表示要放在组件内部的元素、文本或组件的列表

+   您可以编写一个将被渲染为文本的字符串

# 渲染带有子元素的组件

在这个示例中，您将使用渲染函数完全构建一个简单的网页，其中包含一些元素和组件。这将让您近距离观察 Vue 如何编译您的模板和组件。如果您想构建一个高级组件，并且想要一个完整的示例来启动，这可能会很有用。

# 准备工作

这是一个完整的构建组件的渲染函数的示例。通常情况下，您不需要在实践中这样做；这只推荐给高级读者。

# 如何做到这一点...

您将为一个水管工俱乐部构建一个页面。页面将如下所示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-cb/img/Image00165.jpg)

每当我们在名称文本框中写入一个名称时，它将被写入问候中，就像`v-model`指令一样。

对于这个示例，我们从末尾开始而不是从开头开始，因为通常当您不得不使用`render`函数时，您对您想要的结果有一个非常清晰的想法。

在我们应用程序的 HTML 部分，让我们从一个空标签开始：

```js
<div id="app"></div>

```

在 JavaScript 中，在`render`函数中写入一个空的`<div>`元素：

```js
new Vue({

  el: '#app',

  render: h => h('div')

})

```

我们将首先放入的是标题，如下所示：

```js
new Vue({

  el: '#app',

  render: h => h(

    'div',

    [

 h('h1', 'The plumber club page')

 ]

  )

})

```

所有其他的元素和组件都将适应我们刚刚为标题创建的数组。

我们需要一个`<input>`元素，它将接收值并显示问候语。为此，我们可以构建一个`Vue`组件。

在下面的代码中，我们使用的是一个常规的 JavaScript 函数，而不是箭头函数；这是因为我们想要一个对组件本身的引用。箭头函数不允许您修改`this`的作用域，而`this`取决于函数的调用方式，并且可以选择地绑定到常规函数中的任何变量。在我们的情况下，它将绑定到实例组件。

在页面标题之后，我们在同一个数组中添加以下组件：

```js
h(

  {

    render: function (h) {

      const self = this

      return h('div', [

        'Your name is ',

        h('input', {

          domProps: {

            value: self.name

          },

          on: {

            input (event) {

              self.name = event.target.value

            }

          }

        }),

        h(

          'p',

          'Hello ' + self.name + 

            (self.exclamation ? '!' : ''))

      ])

    },

    data () { return { name: '' } },

    props: ['exclamation']

  },

  {

    props: {

      exclamation: true

    }

  }

)

```

该组件有三个选项：`render`，`data`和`props`函数。

`createElement`函数的第二个参数是为我们的 props 实际分配值：

```js
{

  props: {

    exclamation: true

  }

}

```

这将等同于在声明组件时写`：exclamation="true"`。

您可以轻松理解组件的`data`和`props`选项。让我们来看看我们在`render`函数中写了什么。

在函数的第一行，我们将`self = this`设置为一种方便的方式，以便在添加任何嵌套函数时引用组件。然后，我们返回一个`createElement`函数（`h`）的结果，该函数在一个 div 标签内将三个元素放置在 DOM 中。第一个是原始文本`Your name is`，然后是两个元素：一个输入框和一个段落。

在使用渲染函数时，我们没有`v-model`指令的直接等价物。相反，我们手动实现它。我们将值绑定到名称，然后添加一个监听器到输入事件，该事件将把状态变量`name`的值设置为文本框中的内容。

然后，我们插入一个段落元素，根据`exclamation`属性的值添加一个感叹号，组成问候语。

在组件之后，我们可以在同一个数组中添加以下内容，如图所示：

```js
 'Here you will find ', h('i', 'a flood '), 'of plumbers.'

```

如果您做得正确，您应该能够运行应用程序并看到整个页面。

# 它是如何工作的...

在这个例子中，我们看到了 Vue 在编译我们的模板时发生的一瞥；再次强调，您不建议在常规组件中这样做。大多数情况下，结果将更冗长，几乎没有收益。另一方面，有几种情况下编写渲染函数实际上可能会产生更好或更健壮的代码，并涵盖一些难以用模板表达的功能。

# 使用 JSX 渲染组件

JSX 在 React 社区非常流行。在 Vue 中，您不必使用 JSX 来构建组件的模板；您可以使用更熟悉的 HTML。然而，如果您被迫编写大量的渲染函数，JSX 是您可以做的下一件最好的事情。

# 准备工作

在尝试这个示例之前，最好先玩一下渲染函数。之前的示例提供了一些练习。

# 如何做...

JSX 需要一个 Babel 插件才能工作。在这个示例中，我假设你是在 webpack 模板中工作。

要安装 Babel 插件，可以运行以下命令：

```js
npm install

 babel-plugin-syntax-jsx

 babel-plugin-transform-vue-jsx

 babel-helper-vue-jsx-merge-props

 --save-dev

```

在`.babelrc`文件中，在`plugins`数组中添加以下内容：

```js
 "

plugins" 

: [

 ...

  "

transform-vue-jsx" 

]

```

像往常一样运行`npm install`来安装所有依赖项。

现在，打开`main.js`并删除其中的所有内容。用以下代码替换它：

```js
import Vue from 'vue'

/* eslint-disable no-new */

new Vue({

  el: '#app',

  render (h) {

    return <div>{this.msg}</div>

  },

  data: {

    msg: 'Hello World'

  }

})

```

如果你从未见过 JSX，那么这一行是有点奇怪的。只要注意我们在前面的代码中没有在`render`选项中使用箭头函数。这是因为我们在内部使用了`this`，我们希望它绑定到组件上。

你可以使用`npm run dev`命令看到你的页面已经工作了。

# 它是如何工作的...

Babel 插件将把 JSX 代码转换为 JavaScript 的`render`函数。

我不建议在 Vue 中使用 JSX。我唯一能想到它有用的时候是当你需要将`render`函数与 JavaScript 混合使用，并且需要一种快速和可读的方式来定义模板。除此之外，使用 JSX 没有太多优势。

# 更多内容...

让我们稍微复杂一点的代码，至少让我们了解 JSX 如何与 props 配合使用。

在主`Vue`实例之前定义一个新的组件：

```js
const myComp = {

  render (h) {

    return <p>{this.myProp}</p>

  },

  props: ['myProp']

}

```

让我们在我们的`Vue`实例中使用这个组件，并通过 props 传递`msg`变量：

```js
new Vue({

  el: '#app',

  render (h) {

    return <div>

      <myComp myProp={this.msg}/>

    </div>

  },

  data: {

    msg: 'Hello World'

  },

  components: {

    myComp

  }

})

```

语法与 HTML 模板略有不同。特别要注意如何传递 props 以及如何使用驼峰命名和自闭合标签。

# 创建一个功能组件

组件的一个轻量级版本是功能组件。功能组件没有实例变量（因此没有`this`）并且没有状态。在这个示例中，我们将编写一个简单的功能组件，它通过 HTML 接收一些指令并将它们转换为绘图。

# 准备就绪

在尝试这个示例之前，你至少应该熟悉 Vue 中的渲染函数。你可以使用之前的示例来做到这一点。

# 如何实现...

当你编写一个`<svg>`元素时，通常需要将数据放在其中的元素的属性中才能真正绘制形状。例如，如果你想绘制一个三角形，你需要写以下内容：

```js
<svg>

  <path d="M 100 30 L 200 30 L 150 120 z"/>

</svg>

```

`d`属性内的文本是一系列指令，用于移动虚拟光标进行绘制：`M`将光标移动到`<svg>`内的坐标(100, 30)，然后`L`绘制一条线直到(200, 30)，然后再次绘制到坐标(150, 120)。最后，`z`关闭我们正在绘制的路径，结果始终是一个三角形。

我们想要用一个组件来绘制一个三角形，但我们不喜欢属性，而且我们想用我们自己的语言来编写，所以我们会写以下内容以获得相同的结果：

```js
<orange-line>

  moveTo 100 30 traceLine 200 30 traceLine 150 120 closePath

</orange-line>

```

这是一个完美的功能组件的工作，因为没有需要管理的状态，只是从一个组件到一个元素的转换。

你的 HTML 布局将简单地如下所示：

```js
<div id="app">

  <orange-line>

    moveTo 100 30 traceLine 200 30 traceLine 150 120 closePath

  </orange-line>

</div>

```

然后，在 JavaScript 中布局你的功能性组件：

```js
const OrangeLine = {

  functional: true,

  render (h, context) {

    return h('svg',

      []

    )

  }

}

```

你必须指定组件将是功能性的，使用`functional: true`；然后渲染函数与通常略有不同。第一个参数仍然是`createElement`函数，但传递的第二个参数是我们组件的上下文。

我们可以通过`context.children`访问组件 HTML 中写的文本（绘制命令）。

你可以看到我已经添加了一个空的`<svg>`元素。在其中，有一个空的子元素数组；我们将只把`<path>`元素放在那里，如下所示：

```js
render (h, context) {

  return h('svg',

    [

      h('path', {

 attrs: {

 d: context.children.map(c => {

 return c.text

 .replace(/moveTo/g, 'M')

 .replace(/traceLine/g, 'L')

 .replace(/closePath/g, 'z')

 }).join(' ').trim(),

 fill: 'black',

 stroke: 'orange',

 'stroke-width': '4'

 }

 })

    ]

  )

}

```

这段代码创建了一个路径元素，然后设置了一些属性，比如`fill`和`stroke`。`d`属性从组件内部获取文本，进行一些替换，然后返回它。

我们只需要在 JavaScript 中创建`Vue`实例：

```js
new Vue({

  el: '#app',

  components: {

    OrangeLine

  }

})

```

现在，加载应用程序，我们应该看到一个三角形，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-cb/img/Image00166.jpg)

# 工作原理...

Vue 允许您创建非常轻量级的组件，因为它们没有任何内部状态。但是这也带来了一些限制，例如，我们可以将一些逻辑放在哪里来处理用户输入（以元素的子元素或 props 的形式）只能在渲染函数中。

我们传递的上下文包含以下属性：

+   `props`：这是由用户传递的。

+   `children`：这实际上是一个虚拟节点数组，是我们组件在模板中的子元素。在这里我们没有实际的 HTML 元素，只有 Vue 的表示。

+   `slots`：这是一个返回插槽的函数（在某些情况下可以替代 children）。

+   `data`：这是传递给组件的整个数据对象。

+   `parent`：这是对父组件的引用。

在我们的代码中，我们通过以下方式提取了组件内部的文本：

```js
context.children.map(c => {

  return c.text

    .replace(/moveTo/g, 'M')

    .replace(/traceLine/g, 'L')

    .replace(/closePath/g, 'z')

}).join(' ').trim()

```

我们正在获取包含在 children 中的虚拟节点数组，并将每个节点映射到其文本。由于我们只在 HTML 中放置了一些文本，节点数组将是一个单例，只有一个节点：我们输入的文本。因此，在这种特殊情况下，执行`var a = children.map(c => someFunction(c))`等同于执行`var a = [someFunction(children[0])]`。

我们不仅提取文本，还替换了一些我发明的用于描述`svg`命令的术语，用真实的命令替换。`join`函数将把数组中的所有字符串（在我们的情况下只有一个）拼接在一起，`trim`函数将删除所有的空格和换行符。

# 使用高阶组件构建响应式表格

当我们需要决定要实际包装哪个组件时，功能组件是非常好的包装器。在这个示例中，您将编写一个响应式表格，根据浏览器宽度显示不同的列。

# 准备工作

这个示例是关于功能组件的。如果您想热身一下，可以尝试完成前一个示例。

# 如何实现...

对于这个示例，我们将使用优秀的语义 UI CSS 框架。要使用它，您必须将 CSS 库作为依赖项或`<link>`标签包含进来。例如，您可以将以下代码放在 HTML 的`<head>`中：

```js
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/semantic-ui/2.2.7/semantic.css" />

```

如果您使用的是 JSFiddle，内部的链接就足够了。

您还需要在页面中添加另一个标签，以便在移动设备上显示良好：

```js
<meta name="viewport" content="width=device-width">

```

这告诉移动浏览器页面的宽度等于设备的宽度。如果您不添加这个，移动设备可能会认为页面比手机大得多，并试图显示全部内容，从而显示您的应用的缩小版本。

我们将设计一个猫品种的表格。您可以在 Vue 实例状态中看到所有的数据。在您的 JavaScript 中编写如下代码：

```js
new Vue({

  el: '#app',

  data: {

    width: document.body.clientWidth,

  breeds: [

    { name: 'Persian', colour: 'orange', affection: 3, shedding: 5 },

    { name: 'Siberian', colour: 'blue', affection: 5, shedding: 4 },

    { name: 'Bombay', colour: 'black', affection: 4, shedding: 2 }

  ]

  },

  created() {

    window.onresize = event => {

      this.width = document.body.clientWidth

    }

  },

  components: {

    BreedTable

  }

})

```

我们声明了`width`变量来改变页面的布局，由于页面的宽度本质上不是响应式的，我们还在`window.onresize`上安装了一个监听器。对于一个真实的项目，您可能需要更复杂的东西，但对于这个示例，这就足够了。

另外，请注意我们如何使用`BreedTable`组件，代码如下：

```js
const BreedTable = {

  functional: true,

  render(h, context) {

    if (context.parent.width > 400) {

      return h(DesktopTable, context.data, context.children)

    } else {

      return h(MobileTable, context.data, context.children)

    }

  }

}

```

我们的组件所做的就是将所有的`context.data`和`context.children`传递给另一个组件，这个组件将是`DesktopTable`或`MobileTable`，具体取决于分辨率。

我们的 HTML 布局如下：

```js
<div id="app">

  <h1>Breeds</h1>

  <breed-table :breeds="breeds"></breed-table>

</div>

```

`breeds`属性将传递给`context.data`中的选定组件。

我们的桌面表格看起来很普通：

```js
const DesktopTable = {

  template: `

    <table class="ui celled table unstackable">

      <thead>

        <tr>

          <th>Breed</th>

          <th>Coat Colour</th>

          <th>Level of Affection</th>

          <th>Level of Shedding</th>

        </tr>

      </thead>

      <tbody>

        <tr v-for="breed in breeds">

          <td>{{breed.name}}</td>

          <td>{{breed.colour}}</td>

          <td>{{breed.affection}}</td>

          <td>{{breed.shedding}}</td>

        </tr>

      </tbody>

    </table>

  `,

  props: ['breeds']

}

```

顶部的类是语义 UI 的一部分，它们将使我们的表格看起来更好。特别是`unstackable`类，它禁用了 CSS 执行的自动堆叠。我们将在下一节中详细介绍这个。

对于移动端的表格，我们不仅希望编辑样式，还希望对列进行分组。品种将与颜色一起显示，情感与脱毛程度一起显示。此外，我们希望以紧凑的样式来表达它们。表头将如下所示：

```js
const MobileTable = {

  template: `

    <table class="ui celled table unstackable">

      <thead>

       <tr>

         <th>Breed</th>

         <th>Affection & Shedding</th>

       </tr>

     </thead>

   ...

```

我们不仅仅是拼写外套的颜色，还会画一个小圆圈来表示颜色：

```js
...

<tbody>

  <tr v-for="breed in breeds">

    <td>{{breed.name}}

      <div 

        class="ui mini circular image"

        :style="'height:35px;background-color:'+breed.colour"

      ></div>

    </td>

  ...

```

此外，我们在移动端表格中使用心形和星级评分代替了情感和脱毛程度的数字：

```js
      ...

      <td>

        <div class="ui heart rating">

          <i 

            v-for="n in 5"

            class="icon"

            :class="{ active: n <= breed.affection }"

          ></i>

        </div>

        <div class="ui star rating">

          <i 

            v-for="n in 5"

            class="icon"

            :class="{ active: n <= breed.shedding }"

          ></i>

        </div>

      </td>

    </tr>

  </tbody>

</table>

```

同时，不要忘记像`DesktopTable`组件中那样声明`breeds`属性。

现在在浏览器中启动你的应用程序。你可以看到当表格被压缩到足够小的时候，它会将列进行分组：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-cb/img/Image00167.jpg)

下面的截图显示了数字被心形和星级评分所替代：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-cb/img/Image00168.jpg)

# 它的工作原理是...

响应式页面根据浏览器的宽度来改变布局，在用户使用平板电脑或智能手机浏览网站时非常重要。

大多数组件只需要开发一次，响应式页面只需要根据不同的尺寸多次进行样式设计。与为移动端优化的独立网站相比，这样可以节省很多开发时间。

通常，在响应式页面中，表格从列式布局变为堆叠式布局，如下图所示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-cb/img/Image00169.jpg)

我从来不喜欢这种方法，但它的一个明显缺点是，如果你让表格在一侧看起来很好，那么在另一侧看起来就不那么好。这是因为你必须以相同的方式设计单元格，而响应式布局会将它们堆叠起来。

我们的`BreedTable`组件会动态地在两个组件之间切换，而不仅仅依赖于 CSS。由于它是一个功能性组件，与完整组件相比非常轻量级。

在实际应用中，使用`onresize`事件是有问题的，主要是因为性能受损。在生产系统中，通过 JavaScript 实现响应性的解决方案需要更加结构化。例如，考虑使用定时器或使用`matchMedia`。

最后要注意的是，Vue 实例从未注册这两个子组件；这是因为它们从未出现在模板中，而是直接在代码中作为对象引用。


# 第九章：使用 Vuex 的大型应用程序模式

在本章中，我们将介绍以下配方：

+   在 vue-router 中动态加载页面

+   构建一个简单的应用程序状态存储

+   了解 Vuex 的 mutations

+   在 Vuex 中列出您的操作

+   使用模块分离关注点

+   构建 getter 以帮助检索数据

+   测试您的存储

# 介绍

在本章中，您将学习 Vuex 的工作原理以及如何使用它来支持可扩展的应用程序。Vuex 实现了一种在前端框架中流行的模式，它将不同的关注点分开管理一个大型全局应用程序状态。只有 mutations 可以改变状态，所以您只需要在一个地方查找。大部分逻辑以及所有异步逻辑都包含在 actions 中；最后，getters 和 modules 进一步帮助在计算派生状态和将代码拆分为不同文件时分散认知负荷。

除了配方之外，您还会发现在开发实际的大型应用程序时我发现有用的一些智慧之粒；有些与命名约定有关，有些则是为了避免错误的小技巧。

如果您完成了所有的配方，您将准备好开发具有较少错误和无缝协作的大型前端应用程序。

# 在 vue-router 中动态加载页面

很快，您将构建具有大量组件的大型 Vue 网站。加载大量 JavaScript 可能会产生浪费和无用的前期延迟。在第四章的*关于组件的一切*中的*异步加载组件*配方中，我们已经看到了如何远程检索组件的提示。在这里，我们将使用类似的技术来加载由 vue-router 路由加载的组件。

# 准备就绪

这个配方需要了解 vue-router。如果您愿意，您可以通过在第四章的*关于组件的一切*中的*异步加载组件*来更好地了解发生了什么。

# 如何操作...

通过创建一个新目录并运行以下命令，使用`vue-cli`创建一个新项目：

```js
vue init webpack

```

你可以根据自己的喜好回答问题，只要在要求时将`vue-router`添加到模板中即可。

我们将创建两个组件：一个将是我们的主页，它将是小而轻巧的，另一个组件将非常大且加载速度非常慢。我们想要实现的是立即加载主页，而不必等待浏览器下载巨大的组件。

在`components`文件夹中打开`Hello.vue`文件。删除所有内容，只留下以下内容：

```js
<template>

  <div>

    Lightweight hello

  </div>

</template>

```

在同一文件夹中，创建另一个名为`Massive.vue`的文件，并在其中写入以下内容：

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

在最后一行留下一个打开的反引号，因为我们必须用大量无用的数据膨胀文件。保存并关闭`Massive.vue`。

在控制台中，进入与文件存储在同一目录的位置，并使用以下文件将大量垃圾数据放入其中：

```js
yes "XXX" | head -n $((10**6)) >> Massive.vue

```

这个命令的作用是将`XXX`行重复附加到文件中 10⁶次；这将使文件增加 400 万字节，使其对于快速浏览体验来说太大了。

现在我们需要关闭我们打开的反引号。现在不要尝试打开文件，因为你的文本编辑器可能无法打开这么大的文件；相反，使用以下命令：

```js
echo '`</script>' >> Massive.vue

```

我们的`Massive`组件现在已经完成。

打开`router`文件夹中的`index.js`文件，并添加组件及其路由：

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

使用`npm install`安装所有依赖项后，我们现在可以使用`npm run dev`命令启动我们非常大的应用程序了。

应用程序将加载得非常快，但这是因为它直接从本地存储加载；为了模拟更真实的情况，打开开发者工具的网络选项卡，并选择网络限制。选择一些慢速的网络，比如 GPRS 或者较好的 3G，这是我们大多数人可能拥有的：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-cb/img/Image00170.jpg)

现在右键单击刷新按钮，选择强制刷新以绕过缓存（或按*Shift* + *Cmd* + *R*）：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-cb/img/Image00171.jpg)

您会注意到页面在几分钟内不会加载。您可以通过在刷新按钮变成 X 时再次点击来停止页面的加载。

要修复这个问题，请返回到`router`文件夹中的`index.js`文件。删除以下行，其中导入`Massive`组件：

```js
import Massive from '@/components/Massive'

```

前面的行告诉 Webpack 将`Massive`组件中包含的所有代码包含在一个 js 包中。相反，我们希望告诉 Webpack 将`Massive`组件保持为一个单独的包，并且只在必要时加载它。

不要直接导入组件，使用以下代码声明`Massive`：

```js
const Massive = resolve =>

 require(['../components/Massive.vue'], resolve)

```

Webpack 将把这个特殊的语法转换成一个单独的文件，它将被懒加载。保存并进行另一个硬刷新，同时将限制速度设置为较慢的速度（如 GPRS 到良好的 3G）。几秒钟后，您应该能够看到 hello 页面。如果您想加载`Massive`组件，只需将`massive`添加到 URL 中，但您将需要等待一段时间。

# 它是如何工作的...

现在显然在真实应用程序中不会有这么大的组件，但您可以很容易地看到，如果`Massive`组件代表应用程序的所有其他组件，它们可能很快达到如此大的大小。

这里的技巧是异步加载它们；Webpack 将帮助您将它们分成较小的包，以便只在需要时加载。

# 还有更多...

有一种替代的语法可以懒加载导入组件。它可能成为未来的 ECMA 标准，所以您应该知道它。打开`router`目录中的`index.js`文件，并完全删除对`Massive`组件的导入或我们在这个示例中添加的`Massive`常量行。

在路由中，尝试在指定`/massive`路由的组件时使用以下代码：

```js
routes:

 [ 

 { 

path:

'/'

, 

name:

'Hello'

, 

component:

Hello 

 }, 

 {

 path:

'/massive'

, 

name:

'Massive'

, 

 component: import('@/components/Massive') 

 } 

] 

```

这将等同于我们之前所做的，因为 Webpack 将获取该行，并且不会直接导入 Massive 组件的代码，而是创建一个不同的 js 文件，进行懒加载加载。

# 为应用程序状态构建一个简单的存储

在这个示例中，您将了解在构建大型应用程序时使用 Vuex 的基本原理。这个示例有点不正规，因为为了理解 Vuex 存储的工作原理，我们将直接操作它；在真实的应用程序中，您永远不应该这样做。

# 准备就绪

在尝试这个示例之前，您应该完成*第四章*中的“使用 Vuex 使两个组件通信”。

# 操作步骤如下...

在一个新目录中运行以下命令，基于 Webpack 模板创建一个新项目：

```js
vue init webpack

```

您如何回答这个问题并不重要。运行`npm intall`并使用`npm install vuex --save`或`yarn add vuex`（如果使用 yarn）安装 Vuex。

打开`src`文件夹中的`main.js`文件，并添加以下突出显示的行以完成安装 Vuex：

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

当然，现在没有`store`模块，所以您需要创建一个。为此，请在`src`文件夹下创建一个文件夹，并将其命名为`store`。在其中创建一个名为`index.js`的文件。在`main.js`文件中，我们没有指定使用`index.js`文件，但当没有指定文件而只有文件夹时，这是默认行为。

我们将实现一个简化的股票市场。我们有三种资产：星星（STAR），灯（LAMP）和钻石（DIAM）。我们将定义两个路线：一个用于 STAR/LAMP 市场，另一个用于 LAMP/DIAM 市场。

在 store 文件夹中的`index.js`文件中编写以下内容：

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

我们正在创建一个新的`Vuex`存储，用于保存我们的余额。最初，我们每种资产有 100 个；在存储中，星星和灯之间以及灯和钻石之间的汇率也是固定的。

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

`symbol1`和`symbol2`代表两个交易的资产。在这个组件的 JavaScript 中，我们定义了`sell`和`buy`方法，直接在全局的`Vuex`存储中进行操作：

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

你永远不应该像我在这里所做的那样直接操作状态。你应该始终使用 mutations。在这里，我们跳过了中间人，以保持这个示例的简洁性。在下一个示例中会更多地介绍 mutations。

你需要在`index.js`中的`router`文件夹中以以下方式使用这个组件：

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

在上面的代码中，我们使用`Market`组件来处理包含一对交易符号的任何路由。作为主页，我们使用了 STAR/LAMP 市场。

为了显示一些导航链接到不同的市场和我们当前的余额，我们可以使用以下模板编辑`App.vue`组件：

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

对于这个组件，我们不需要任何 JavaScript 代码，所以你可以删除`<script>`标签。

我们的应用现在已经准备好了；启动它并开始进行交易。下面的图片是我们完成的应用程序，不包含在`App.vue`中的样式：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-cb/img/Image00172.jpg)

# 它是如何工作的...

底部的余额就像是全局状态的一个总结。通过访问每个组件中由 Vuex 插件注入的`$store`变量，我们可以影响其他组件。当你想要将变量的作用域扩展到组件本身之外时，你可以很容易地想象如何使用这种策略在一个大型应用程序中。

一些状态可能是局部的，例如如果你需要一些动画或者你需要一些变量来显示组件的模态对话框；不把这些值放在存储中是完全可以的。否则，在一个地方拥有一个结构化的集中状态会有很大帮助。在接下来的示例中，你将使用更高级的技术来更好地利用 Vuex 的强大功能。

# 理解 Vuex 的 mutations

在 Vuex 应用程序中，改变状态的正确方式是通过 mutations 的帮助。mutations 是一种非常有用的抽象，用于将状态变化分解为原子单位。在这个示例中，我们将探索这一点。

# 准备工作

虽然不需要对 Vuex 了解太多就可以完成这个示例，但建议先完成前一个示例。

# 如何操作...

将 Vuex 作为项目的依赖项添加进来（CDN 地址为`https://unpkg.com/vuex`）。我假设你正在使用 JSFiddle 进行跟随；否则，请记得在存储代码之前放置`Vue.use(Vuex)`。

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

我们的想法是有一个文本框用于编写消息，广播的消息将显示在顶部，最新的消息将首先显示。可以通过点击小 x 来关闭消息。

首先，让我们构建一个存储库，用于保存广播消息的列表，并枚举我们可以对该列表进行的可能的变化：

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

所以，我们有一个消息列表；我们可以将一个消息推送到列表的顶部，或者通过知道其索引来删除一个消息。

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

现在，您可以启动应用程序并开始向我们的虚拟用户广播消息了：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-cb/img/Image00173.jpg)

# 工作原理...

我认为值得注意的是突变的名称；它们被称为`pushMessage`和`removeMessage`，但在这个应用程序中它们实际上是在屏幕上显示消息并（虚构地）向用户广播消息。将它们称为`showMessage`或`broadcastMessage`和`hideMessage`会更好吗？不，因为突变本身和突变的特定效果之间必须有明确的意图分离。当我们决定让用户有能力忽略这些通知或在实际广播通知之前引入延迟时，问题就变得清晰了。然后我们将有一个`showMessage`突变，它实际上不显示消息。

我们使用的计算语法如下所示：

```js
computed: Vuex.mapState(['messages'])

```

当您将 Vuex 作为 ES6 模块导入时，您不必在表达式中显式使用 Vuex。您只需要写

`import { mapState } from 'Vuex'`。

然后，`mapState`函数将可用。

`mapState`方法接受一个字符串数组作为参数，在存储中查找与字符串同名的`state`变量，并创建一个同名的计算属性。您可以使用任意多个变量进行此操作。

# 还有更多...

如果您在本地 npm 项目上跟随，打开 Vue 开发者工具（不幸的是，在使用 JSFiddle 时无法使用 Vue 开发者工具），您将看到每个消息都会发出一个新的突变。考虑一下，您点击了小时钟：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-cb/img/Image00174.jpg)

实际上，您可以使用它来撤消突变，如下图所示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-cb/img/Image00175.jpg)

注意当点击时间旅行选项时，状态没有改变；这是因为紫色丝带仍然在最后一个状态。要检查不同的状态，只需点击突变名称。

这个调试机制是可能的，因为突变总是同步的；这意味着可以在突变之前和之后对状态进行快照，并通过时间进行导航。在下一个示例中，您将学习如何使用 Vuex 执行异步操作。

# 在 Vuex 中列出您的操作

您的所有突变都必须是同步的，那么如何等待超时或使用 Axios 进行 AJAX 请求呢？操作是下一级的抽象层，将帮助您解决这个问题。在操作内部，您可以提交多个突变并进行异步操作。

# 准备就绪

突变是操作的构建块，因此强烈建议您在尝试此操作之前完成前面的示例。

我们将使用“构建应用程序状态的简单存储”示例中的设置；您也可以使用自己的设置，但无论如何，此示例都基于官方 Webpack 模板的轻微修改。

# 如何做...

您将构建一个流行的 Xkcd 网站的克隆。实际上，它将更像是一个包装器，而不是一个真正的克隆，因为我们将重用网站上的面板。

基于 Webpack 模板创建一个 Vue 项目，使用`vue init webpack`。我们将首先在`config`文件夹中的`index.js`中将 API 连接到 Xkcd 网站。将以下行放入`proxyTable`对象中：

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

这将将我们发出的所有请求重定向到`/comic`到 Xkcd 网站。

在`src`中，创建一个新的`store`目录，并在其中创建一个`index.js`文件；在这里，开始构建应用程序存储：

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

您应该像在之前的示例中那样在`main.js`中导入它。我们想要跟踪当前面板编号、面板图像的链接和可能的错误。修改状态的唯一方法是通过突变，而操作可以执行异步工作。

当应用程序加载时，我们计划显示最新的漫画。为此，我们创建一个操作：

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

编写相应的变异应该很容易：

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

我们将重用`Hello.vue`组件，并将以下模板放在其中：

```js
<template>

  <div class="hello">

    <h1>XKCD</h1>

    <img :src="currentImg">

  </div>

</template>

```

要在加载时显示最后一个面板，可以在组件中使用以下 JavaScript 代码：

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

此外，您可以删除大部分`App.vue`模板，只保留以下内容：

```js
<template>

  <div id="app">

    <router-view></router-view>

  </div>

</template>

```

# 它是如何工作的...

`proxyTable`对象将配置`http-proxy-middleware`。每当我们开发一个较大的 Web 应用程序的 UI，并在`localhost`上启动我们的开发服务器时，这非常有用，但我们的 API 响应到另一个 Web 服务器。当我们想要使用 CORS 并且不允许其他网站使用我们的 API 时，这一点尤为重要。Xkcd API 不允许`localhost`使用 Web 服务。这就是为什么，即使我们尝试直接使用 Xkcd API，我们的浏览器也不会让我们这样做。`changeOrigin`选项将使用 Xkcd 作为主机发送请求，从而使 CORS 变得不必要。

要从组件中调用一个动作，我们使用了`dispatch`函数。还可以传递第二个参数，第一个参数是动作本身的名称。然后，在定义动作时，将第二个参数作为第二个参数传递。

关于命名的最后一点说明——在我的观点中，动作是异步的，而变异是同步的，因此没有必要在动作的名称中显式地表明异步性。

# 使用模块分离关注点

在构建大型应用程序时，Vuex 存储可能会变得拥挤。幸运的是，可以使用模块将应用程序的不同关注点分成单独的部分。

# 准备工作

如果您想使用模块，可以将此示例作为参考。您应该已经了解足够多的 Vuex 知识。

对于这个示例，您需要对 Webpack 有一定的了解。

# 如何操作...

在这个示例中，我们将以稍微简化的方式对一个完全功能的人体进行建模。每个器官都将有一个单独的模块。

使用 `vue init webpack` 创建一个新的 Webpack 模板，并安装 `npm install vuex`。创建一个包含 `src/store/index.js` 文件的新目录。在其中，写下以下内容：

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

`heart` 模块是这样的；在 store 声明之前放置它：

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

注意，在 mutations 中传递的状态不是根状态，而是模块的本地状态。

然后是大脑，它被分为左右两个脑叶；在 store 之前写下以下内容：

```js
const brain = {

  modules: {

    left: leftLobe,

    right: rightLobe

  }

}

```

你可以将它们实现为简单的布尔状态（在它们所依赖的大脑之前写下它们）：

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

将 `namespaced` 设置为 true 会修改你调用 mutator 的方式。由于它们都被称为 `toggle`，现在你可以指定是哪个脑叶，例如，对于左脑，突变字符串变为 `left/toggle`，其中 `left` 表示它是大脑中用于引用左脑的键。

要查看你的 store 在运行中的情况，你可以创建一个使用所有 mutations 的组件。对于大脑，我们可以有两个脑叶的图片，如下所示：

```js
<img 

 :class="{ off: !$store.state.brain.left.reason }"

 src="http://i.imgur.com/n8B6wuY.png"

 @click="left"><img

 :class="{ off: !$store.state.brain.right.fantasy }"

 src="http://i.imgur.com/4BbfVur.png"

 @click="right">

```

这将创建两个红铅笔绘制的脑叶图；注意嵌套方式中模块名称的使用。以下的 `off` CSS 规则将使脑叶变灰：

```js
.off {

  filter: grayscale(100%)

}

```

为了调用 mutations，我们在正确的方法中使用上述字符串：

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

你还可以创建一个输入文本框并调用其他两个 mutations，如下所示：

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

这很简单，但是如何获取所爱的名称呢？你可以在模板中使用这些胡子：

```js
<p>

 loves: {{$store.state.heart.loves}}</p>

<input v-model="partner" @input="love">

<button @click="clear">Clear</button>

```

显然，你必须在 Vue 实例上声明 `partner` 变量：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-cb/img/Image00177.jpg)

# 它是如何工作的...

我们已经看到如何使用模块将应用程序的关注点分割成不同的单元。随着项目规模的增长，这种能力可能变得重要。

通常的模式是，在一个 mutation 中，你可以直接访问本地状态：

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

在 mutation 中，只能访问本地状态是有意义的。例如，大脑不能改变心脏，反之亦然，但是动作呢？如果我们在模块内声明一个动作，我们会传递一个名为 context 的对象，它看起来像这样：

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

所以，如果我们想在左侧叶子中声明一个动作，并且我们想要影响心脏，我们必须做以下操作：

```js
actions: {

  beNerd ({ rootState }) {

    rootState.heart.loves = 'Math & Physics'

  }

}

```

# 构建 getter 来帮助检索数据

你不想在状态中保留太多数据。保留重复或派生数据尤其危险，因为它很容易使数据不同步。Getter 可以帮助你解决这个问题，而不会将负担转移到组件上，因为所有逻辑都集中在一个地方。

# 准备工作

如果你已经具备一些 Vuex 知识并且想要扩展你的视野，那么这个教程适合你。

# 如何做到这一点...

想象一下，你正在构建一个比特币钱包。你想给用户一个关于他们余额的概览，并且你希望他们看到对应的欧元数量。

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

这段代码容易出错。第一个错误可能是欧元金额的计算错误，如果我们没有正确进行乘法运算。第二种错误可能是在交易过程中告诉用户`bitcoin`和`euro`余额，导致其中一个金额过时和错误。

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

这样，`euro`金额永远不会在状态中，而是始终计算得出。此外，它集中在存储中，所以我们不需要在组件中添加任何内容。

现在，从模板中轻松检索两个金额：

```js
<template>

  <div>

    <h1>Balance</h1>

    <ul>

      <li>{{$store.state.bitcoin}}฿

</li>

      <li>{{$store.getters.euro}}&euro;</li>

    </ul>

  </div>

</template>

```

这里，`&#3647 ;`是比特币符号的 HTML 实体。

# 它是如何工作的...

如果我们不谈论输入数据，那么为派生数据设置一个`getter`总是一个好主意。我们还没有讨论过 getter 的一个显著特点是它们能够与其他 getter 进行交互并接受一个参数。

# 访问其他 getter

当调用 getter 时传递的第二个参数是包含其他`getter`的对象：

```js
getters

:

{ 

 ...

  getCatPictures: state => state.pictures.filter(pic => isCat(pic)) 

 getKittens

:

(

state

,

 getters

)

=

>

{ 

 return

 getters

.

getCatPictures()

.

filter

(cat

=

>

 !isAdult(cat)

) 

 } 

} 

```

在我们的示例中，我们可以调用`euro` getter 来获得一些派生数据，例如我们可以用平均价格为 150,000 欧元的比特币购买多少房屋：

```js
const store = new Vuex.Store({

  state: {

    bitcoin: 600,

    rate: 1000

  },

  getters: {

    euro: state => state.bitcoin * state.rate,

    houses: (state, getters) => 

getters.euro() / 150000

})

```

# 传递参数

如果一个 getter 返回一个带有参数的函数，那么该参数将是 getter 的参数：

```js
getters: {

  ...

  getWorldWonder: state => nth => state.worldWonders[nth]

}

```

在我们的示例中，一个实际的例子可以在前一段中的 getter 中指定房屋的平均成本：

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

# 测试你的商店

正如你从*第七章*中所了解的，测试是专业软件中最重要的部分。由于商店通常定义应用程序的业务逻辑，因此对其进行测试对于应用程序可能是至关重要的。在这个示例中，你将为 Vuex 商店编写测试。

# 准备工作

这个示例需要来自*第七章*的知识，即*单元测试和端到端测试*以及对 Vuex 的熟悉；你可以从本章的早期示例中获得它。

# 如何做...

首先，我将定义一些我们的商店必须实现的功能；然后你将编写测试来证明这些功能是否存在并且正常工作。

# 软件要求

我们的商店由待办事项列表中的项目组成，如下所示：

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

+   我们必须有一个`MARK_ITEM_AS_DONE`变异，将`done`字段从 false 更改为 true

+   我们必须有一个`downloadNew`操作，从服务器下载最新的项目并将它们添加到列表中

# 测试变异

要能够测试你的变异，你必须使它们在测试文件中可用。为此，你必须从商店中提取变异对象。考虑类似于这样的东西：

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

您必须将其提取到类似以下的内容中：

```js
export const mutations = { ... }

const store = new Vuex.Store({ ... })

export default store

```

这样，您可以在测试文件中使用以下代码导入 mutations：

```js
import { mutations } from '@/store'

```

满足需求 1 的测试可以编写如下：

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

如果您使用官方的 Webpack 模板，可以使用`npm run unit`运行测试。默认情况下，这将使用 PhantomJS，它不实现某些功能。您可以使用 Babel polyfills，或者只需进入`karma.conf.js`并在`browsers`数组中将`PhantomJS`替换为`Chrome`。记得使用`npm install karma-chrome-launcher --save-dev`安装 Chrome launcher。

# 测试 actions

**测试 actions**意味着测试操作是否提交了预期的 mutations。我们对 mutations 本身不感兴趣（至少在单元测试中不感兴趣），因为它们已经单独测试过了。但是，我们可能需要模拟一些依赖项。

为了避免依赖于 Vue 或 Vuex（因为我们不需要它们，而且它们可能会污染测试），我们在 store 目录中创建一个新的`actions.js`文件。使用`npm install axios`安装 Axios。`actions.js`文件可以如下所示：

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

为了测试需求 2，我们首先模拟应该下载新的待办事项的服务器调用：

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

这将确保对`axios`的 get 方法的任何调用都将始终返回一个新的待办事项。

然后，我们希望确保在调度时调用`ADD_ITEMS` mutation：

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

# 工作原理如下... 

虽然对 mutations 的测试非常简单，但我认为对 actions 的测试值得更多解释。

由于我们不想依赖外部服务来执行操作，我们不得不模拟`axios`服务。我们使用了`inject-loader`，它接受原始库并使用任意代码模拟我们指定的部分（`@`符号是`src`的简写）；在我们的情况下，我们模拟了`axios`库，特别是`get`方法。我们必须使用 CommonJS 语法（使用`require`）因为这是告诉 Webpack 在导入时使用加载器的唯一方式。

在测试中，我们所做的是模拟`commit`函数。通常，这个函数调用一个修改状态的 mutation。我们只想知道是否调用了正确的 mutation，并且传入了正确的参数。此外，我们不得不将所有内容包装在一个`try`块中；如果没有它，测试将超时失败，我们将丢失错误信息。相反，现在我们立即失败，并且可以从控制台中读取导致测试失败的错误。
