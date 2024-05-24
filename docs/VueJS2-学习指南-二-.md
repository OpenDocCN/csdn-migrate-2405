# VueJS2 学习指南（二）

> 原文：[`zh.annas-archive.org/md5/0B1D097C4A60D3760752681016F7F246`](https://zh.annas-archive.org/md5/0B1D097C4A60D3760752681016F7F246)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三章：组件-理解和使用

在上一章中，你学习了 Vue.js 的工作原理。你了解了幕后情况，甚至对 Vue.js 核心代码进行了轻微的调试。你学习了一些 Vue 的关键概念。你还学习并尝试了不同的安装 Vue.js 的方式。我们已经启动了应用程序；从本章开始，我们将开发和增强它。我们还学会了如何调试和测试我们的应用程序。

在第一章中，我们谈论了组件，甚至创建了一些。在本章中，我们将在我们的应用程序中使用组件，并看到一些有趣的指令在其中的作用。也就是说，在本章中，我们将做以下事情：

+   重新讨论组件主题并回顾组件的定义

+   为我们的应用程序创建组件

+   学习什么是单文件组件

+   学习如何使用特殊属性实现响应式 CSS 过渡

# 重新讨论组件

正如你在之前的章节中肯定记得的，组件是 Vue 应用程序的特殊部分，具有自己的数据和方法范围。组件可以在整个应用程序中被使用和重复使用。在上一章中，你学到了组件是通过使用`Vue.extend({...})`方法创建的，并且使用`Vue.component()`语法进行注册。因此，为了创建和使用一个组件，我们需要编写以下 JavaScript 代码：

```js
//creating component 
var HelloComponent = Vue.extend({ 
  template: '<h1>Hello</h1>' 
}); 
//registering component 
Vue.component('hello-component', HelloComponent); 

//initializing the Vue application 
new Vue({ 
  el: '#app' 
}); 

```

然后，我们将在 HTML 中使用`hello-component`：

```js
<div id='app'> 
  <hello-component></hello-component> 
</div> 

```

### 提示

初始化和注册都可以写成单个`Vue.component`调用，带有相应的选项：

`Vue.component('hello-component', { template: '<h1>Hello</h1>' });`

# 使用组件的好处

在深入了解组件并重写应用程序之前，有一些东西我们需要学习。在本节中，我们将涵盖处理组件内的`data`和`el`属性、组件模板、作用域和预处理器等内容。

## 在 HTML 中声明模板

在我们之前的例子中，我们创建了一个 Vue 组件，模板是以字符串形式编写的。这实际上很容易和不错，因为我们在组件内有我们需要的一切。现在想象一下我们的组件具有更复杂的 HTML 结构。编写复杂的 HTML 字符串模板容易出错，丑陋，并且违反最佳实践。

### 提示

通过最佳实践，我指的是清晰和可维护的代码。将复杂的 HTML 写成字符串是不可维护的。

Vue 允许在特殊的`<template>`标签内声明模板！

因此，为了重写我们的示例，我们将声明一个带有相应标记的 HTML 标签模板：

```js
<template id="hello"> 
  <h1>Hello</h1> 
</template> 

```

然后，在我们的组件内部，我们将只使用模板的 ID，而不是 HTML 字符串：

```js
Vue.component('hello-component', { 
  template: '#hello' 
}); 

```

我们的整个代码将如下所示：

```js
<body> 
  **<template id="hello">** 
    <h1>Hello</h1> 
  **</template>** 

  <div id="app"> 
    <hello-component></hello-component> 
  </div> 

  <script src="vue.js"></script> 
  <script> 
    Vue.component('hello-component', { 
      template: '**#hello**' 
    }); 

    new Vue({ 
      el: '#app' 
    }); 
  </script> 
</body> 

```

在前面的示例中，我们只使用了组件的`template`属性。让我们继续看看`data`和`el`属性在组件内部应该如何处理。

## 处理组件内的数据和 el 属性

如前所述，组件的语法与 Vue 实例的语法相同，但必须扩展 Vue 而不是直接调用它。基于这一前提，创建一个组件似乎是正确的：

```js
var HelloComponent = Vue.extend({ 
  el: '#hello', 
  data: { msg: 'Hello' } 
}); 

```

但这会导致作用域泄漏。每个`HelloComponent`实例将共享相同的`data`和`el`。这并不是我们想要的。这就是为什么 Vue 明确要求将这些属性声明为函数的原因：

```js
var HelloComponent = Vue.component('hello-component', { 
  el: **function ()** { 
    return '#hello'; 
  }, 
  data: **function ()** { 
    return { 
      msg: 'Hello' 
    } 
  } 
}); 

```

即使您犯了错误，并将`data`或`el`属性声明为对象或元素，Vue 也会友好地警告您：

![处理组件内的数据和 el 属性](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00260.jpeg)

在 Vue 组件内将数据作为对象而不是函数使用时，Vue 会友好地警告

## 组件的作用域

如前所述，所有组件都有自己的作用域，其他组件无法访问。然而，全局应用程序作用域可被所有注册的组件访问。您可以将组件的作用域视为局部作用域，将应用程序作用域视为全局作用域。它是一样的。然而，在组件内部使用父级的数据并不直观。您必须在组件内明确指示应该使用`prop`属性访问哪些父级数据属性，并使用`v-bind`语法将它们绑定到组件实例。让我们看看它在我们的`HelloComponent`示例中是如何工作的。

让我们从声明包含属性`msg`的数据的`HelloComponent`开始：

```js
Vue.component('hello-component', { 
  data: function () { 
    return { 
      **msg: 'Hello'** 
    } 
  } 
}); 

```

现在，让我们创建一个带有一些数据的`Vue`实例：

```js
new Vue({ 
  el: '#app', 
  **data: { 
    user: 'hero' 
  }** 
});  

```

在我们的 HTML 中，让我们创建一个模板并将其应用到具有模板 ID 的组件上：

```js
//template declaration 
<template id="hello"> 
  <h1>**{{msg}} {{user}}**</h1> 
</template> 

//using template in component 
Vue.component('hello-component', { 
  **template: '#hello',** 
  data: function () { 
    return { 
      msg: 'Hello' 
    } 
  } 
}); 

```

为了在页面上看到组件，我们应该在`app`容器的 HTML 中调用它：

```js
<div id="app"> 
  **<hello-component></hello-component>** 
</div> 

```

如果您在浏览器中打开页面，您只会看到**`Hello`**；`user`数据属性仍然没有绑定到组件：

![组件的作用域](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00261.jpeg)

父级的数据属性尚未绑定到我们的 Vue 组件

为了将数据绑定到父 Vue 应用程序，我们必须做以下两件事：

+   在组件的`prop`属性中指示此属性

+   将其绑定到`hello-component`调用：

```js
//calling parent's data attributes in the component 
Vue.component('hello-component', { 
  template: '#hello', 
  data: function () { 
    return { 
      msg: 'Hello' 
    } 
  }, 
  **props: ['user']** 
}); 

//binding a user data property to the component 
<div id="app"> 
  <hello-component **v-bind:user="user"**></hello-component> 
</div> 

```

刷新页面，您将看到它现在向您呈现问候语：

![组件的范围](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00262.jpeg)

在正确绑定父级的`data`属性到组件之后，一切都按预期运行。

### 提示

实际上，`v-bind:user`语法可以通过以下方式进行快捷操作：

`:user<hello-component **:user="user"**></hello-component>`

## 组件内部的组件

组件的美妙之处在于它们可以像乐高积木和积木一样在其他组件内部被使用和重复使用！让我们构建另一个组件；让我们称之为**greetings**，它将由两个子组件组成：一个要求用户姓名的表单和我们的`hello`组件。

为了做到这一点，让我们声明表单的模板和我们已经熟悉的`hello`模板：

```js
<!--template for the form--> 
<template id="form"> 
  <div> 
    <label for="name">What's your name?</label> 
    <input **v-model="user"** type="text" id="name"> 
  </div> 
</template> 

//template for saying hello 
<template id="hello"> 
  <h1>{{msg}} {{user}}</h1> 
</template> 

```

现在我们将基于这些模板注册两个 Vue 组件：

```js
//register form component 
Vue.component('**form-component**', { 
  template: '**#form**', 
  props: ['user'] 
}); 
//register hello component 
Vue.component('**hello-component**', { 
  template: '**#hello**', 
  data: function () { 
    return { 
      msg: 'Hello' 
    } 
  }, 
  props: ['user'] 
}); 

```

最后，我们将创建我们的 greetings 模板，它将使用`form`和`hello`组件。不要忘记我们必须在组件调用时绑定`user`属性：

```js
<template id="greetings"> 
  <div> 
    <form-component **:user="user"**></form-component> 
    <hello-component **:user="user"**></hello-component> 
  </div> 
</template> 

```

在这一点上，我们可以创建我们的 greetings 组件，并在其中使用 greetings 模板。让我们初始化，使用此组件中用户的`data`函数：

```js
//create greetings component based on the greetings template 
Vue.component('greetings-component', { 
  template: '**#greetings**', 
  data: function () { 
    return { 
      user: 'hero' 
    } 
  } 
}); 

```

在我们的主应用程序容器内，我们现在将调用 greetings 组件：

```js
<div id="app"> 
  **<greetings-component></greetings-component>** 
</div> 

```

不要忘记初始化 Vue 应用程序：

```js
new Vue({ 
  el: '#app' 
}); 

```

在浏览器中打开页面。您应该看到类似以下的内容：

![组件内部的组件](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00263.jpeg)

由各种 Vue 组件构建的页面

尝试在输入框中更改名称。您期望它在问候标题中也发生变化，因为我们将其绑定到了它。但奇怪的是，它并没有改变。嗯，这实际上是正常的行为。默认情况下，所有属性都遵循单向数据绑定。这意味着如果在父级范围内更改数据，这些更改会传播到子组件，但反之则不会。这样做是为了防止子组件意外地改变父状态。但是，可以通过调用事件来强制子组件与其父组件通信。请查看 Vue 文档[`vuejs.org/guide/components.html#Custom-Events`](https://vuejs.org/guide/components.html#Custom-Events)。

在我们的案例中，我们可以将用户模型绑定到我们的表单`input`组件，并在用户在输入框中输入时发出`input`事件。我们通过使用`v-on:input`修饰符来实现这一点，就像在[`vuejs.org/guide/components.html#Form-Input-Components-using-Custom-Events`](https://vuejs.org/guide/components.html#Form-Input-Components-using-Custom-Events)中描述的那样。

因此，我们必须将`v-model:user`传递给`form-component`：

```js
<form-component **v-model="user"**></form-component> 

```

然后，`form-component`应该接受`value`属性并发出`input`事件：

```js
Vue.component('form-component', { 
  template: '#form', 
  props: [**'value'**], 
  methods: { 
    **onInput: function (event) { 
      this.$emit('input', event.target.value) 
    }** 
  } 
}); 

```

`form-component`模板中的输入框应将`v-on:input`和`onInput`方法绑定到`v-on:input`修饰符：

```js
<input **v-bind:value="value"** type="text" id="name" **v-on:input="onInput"**> 

```

### 提示

实际上，在 Vue 2.0 之前，可以通过显式告知使用`.sync`修饰符绑定的属性来实现组件与其父级之间的双向同步：`<form-component :user.sync="user"></form-component>`

刷新页面。现在您可以更改输入框中的名称，并立即传播到父级范围，从而传播到依赖该属性的其他子组件：

![组件内部的其他组件](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00264.jpeg)

使用`.sync`修饰符绑定属性允许父级和子级组件之间的双向数据绑定

您可以在 JSFiddle 中找到此示例的完整代码[`jsfiddle.net/chudaol/1mzzo8yn/`](https://jsfiddle.net/chudaol/1mzzo8yn/)。

### 提示

在 Vue 2.0 发布之前，还有一个数据绑定修饰符`.once`。使用此修饰符，数据将仅绑定一次，任何其他更改都不会影响组件的状态。比较以下内容：

`<form-component **:user="user"**></form-component>`

`<form-component **:user.sync="user"**></form-component>`

`<form-component **:user.once="user"**></form-component>`

# 使用简单组件重写购物清单

既然我们已经对组件有了很多了解，让我们使用它们来重写我们的购物清单应用程序。

### 提示

在重写应用程序时，我们将使用这个版本的购物清单应用程序作为基础：[`jsfiddle.net/chudaol/vxfkxjzk/3/`](https://jsfiddle.net/chudaol/vxfkxjzk/3/)。

我们之前已经做过了，当我们开始讨论组件时。但那时，我们在组件选项中使用了字符串模板。现在让我们使用刚学会的模板来做。让我们再看一下界面，并再次识别组件：

![使用简单组件重写购物清单](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00265.jpeg)

我们的购物清单应用程序将有四个组件

因此，我建议我们的购物清单应用程序由以下四个组件组成：

+   `AddItemComponent`：负责向购物清单添加新项目的组件

+   `ItemComponent`：负责在购物清单中呈现新项目的组件

+   `ItemsComponent`：负责渲染和管理`ItemComponent`列表的组件

+   `ChangeTitleComponent`：负责更改列表标题的组件

## 为所有组件定义模板

假设这些组件已经定义并注册，让我们为这些组件创建模板。

### 注意

**`驼峰命名法 VS 短横线命名法`** 您可能已经注意到，当我们声明描述组件的变量时使用驼峰命名法（`var HelloComponent=Vue.extend({...})`），但我们在短横线命名法中命名它们：`Vue.component('hello-component', {...})`。我们这样做是因为 HTML 属性不区分大小写的特性。因此，我们购物清单应用程序的组件将被称为：

`add-item-component`

`item-component`

`items-component`

`change-title-component`

看一下我们之前的标记是怎样的（[`jsfiddle.net/chudaol/vxfkxjzk/3/`](https://jsfiddle.net/chudaol/vxfkxjzk/3/)）。

让我们使用模板和组件名称重写它。在这部分，我们只关心呈现层，将数据绑定和操作处理留给将来实现。我们只需复制粘贴应用程序的 HTML 部分，并将其分发到我们的组件上。我们的四个模板将看起来像下面这样：

```js
<!--add new item template--> 
<template id="**add-item-template**"> 
  <div class="input-group"> 
    <input @keyup.enter="addItem" v-model="newItem" 
      placeholder="add shopping list item" type="text" 
      class="form-control"> 
    <span class="input-group-btn"> 
      <button @click="addItem" class="btn btn-default" 
        type="button">Add!</button> 
    </span> 
  </div> 
</template> 

<!--list item template--> 
<template id="**item-template**"> 
  <li :class="{ 'removed': item.checked }"> 
    <div class="checkbox"> 
      <label> 
        <input type="checkbox" v-model="item.checked"> {{ item.text }} 
      </label> 
    </div> 
  </li> 
</template> 

<!--items list template--> 
<template id="**items-template**"> 
  <ul> 
    <item-component v-for="item in items" :item="item">
    </item-component> 
  </ul> 
</template> 

<!--change title template--> 
<template id="**change-title-template**"> 
  <div> 
    <em>Change the title of your shopping list here</em> 
    <input **v-bind:value="value" v-on:input="onInput"**/> 
  </div> 
</template> 

```

因此，我们的主要组件标记将由一些组件组成：

```js
<div id="app" class="container"> 
  <h2>{{ title }}</h2> 
  **<add-item-component></add-item-component> 
  <items-component :items="items"></items-component>** 
  <div class="footer"> 
    <hr/> 
    **<change-title-component v-model="title"</change-title-component>** 
  </div> 
</div> 

```

正如您所看到的，每个模板的大部分内容都是对应 HTML 代码的简单复制粘贴。

然而，也有一些显著的不同之处。例如，列表项模板略有改变。您已经学习并在以前使用了`v-for`指令。在以前的示例中，我们将此指令与`<li>`等 HTML 元素一起使用。现在您可以看到它也可以与 Vue 自定义组件一起使用。

您可能还注意到更改标题模板中的一个小差异。现在它有一个绑定的值，并发出`onInput`方法绑定到`v-on:input`修饰符。正如您在上一节中学到的，子组件不能直接影响父组件的数据，这就是为什么我们必须使用事件系统的原因。

## 定义和注册所有组件

看一下我们以前的购物清单应用程序中的 JavaScript 代码：[`jsfiddle.net/chudaol/c8LjyenL/`](https://jsfiddle.net/chudaol/c8LjyenL/)。让我们添加创建 Vue 组件的代码。我们将使用已定义模板的 ID 作为它们的`template`属性。还要不要忘记`props`属性，以从父应用程序传递属性。因此，我们添加以下代码：

```js
//add item component 
Vue.component('add-item-component', { 
  template: '**#add-item-template**', 
  data: function () { 
    return { 
      **newItem**: '' 
    } 
  } 
}); 
//item component 
Vue.component('item-component', { 
  template: '**#item-template**', 
  props: ['**item**'] 
}); 
//items component 
Vue.component('items-component', { 
  template: '**#items-template**', 
  props: ['**items**'] 
}); 
//change title component 
Vue.component('change-title-component', { 
  template: '**#change-title-template**', 
  props: ['**value**'], 
  methods: { 
    onInput: function (event) { 
      this.$emit('input', event.target.value) 
    } 
  } 
}); 

```

正如您所看到的，在每个组件的`props`中，我们传递了不同的数据属性，只涉及到该组件的属性。我们还将`newItem`属性移动到`add-item-component`的`data`属性中。在`change-title-component`中，我们添加了`onInput`方法，该方法发出输入事件，因此父组件中的标题受到用户在输入框中输入的任何内容的影响。

在浏览器中打开 HTML 文件。界面与之前完全相同！我们在本节中所做的所有代码可以在 JSFiddle 中找到：[`jsfiddle.net/chudaol/xkhum2ck/1/`](https://jsfiddle.net/chudaol/xkhum2ck/1/)。

# 练习

尽管我们的应用程序看起来与之前一样，但其功能已经丢失。它不仅不添加项目，而且还在 devtools 控制台中显示了丑陋的错误。

请使用事件发射系统将添加项目的功能带回来。

此练习的一个可能解决方案可以在附录*练习解决方案*中找到。

# 单文件组件

从旧的最佳实践中，我们知道将 HTML 与 CSS 和 JavaScript 文件分开总是一个好主意。一些现代框架如 React 正在放松并逐渐取消这一规则。如今，看到包含自己标记、样式和应用代码的小文件或组件并不会让你感到震惊。实际上，对于小组件来说，我们甚至发现这样的架构更加方便。Vue 也允许在同一个文件中定义与同一组件相关的所有内容。这种组件被称为单文件组件。

### 注意：

单文件 Vue 组件是一个扩展名为`.vue`的文件。包含这些组件的应用程序可以使用`webpack vue`配置构建。使用这种配置搭建应用程序的最简单方法是使用`vue-cli`（[`github.com/vuejs-templates/webpack`](https://github.com/vuejs-templates/webpack)）。

Vue 组件可以包含最多三个部分：

+   `<script>`

+   `<template>`

+   `<style>`

这些部分中的每一个都负责你所想的确切内容。在`<template>`标签中放入 HTML 模板应该负责的内容，在`<script>`标签中放入 Vue 组件的 JavaScript 代码、方法、数据、props 等。`<style>`标签应该包含给定组件的 CSS 样式。

你还记得我们的`hello-component`吗？在[`jsfiddle.net/chudaol/mf82ts9a/2/`](https://jsfiddle.net/chudaol/mf82ts9a/2/)的 JSFiddle 中看一下它。

首先使用`vue-cli`使用`webpack-simple`配置搭建应用程序：

```js
**npm install -g vue-cli vue init webpack-simple hello**

```

要将其重写为 Vue 组件，我们创建我们的`HelloComponent.vue`文件并添加以下代码：

```js
<template> 
  <h1>{{ msg }}</h1> 
</template> 

<script> 
**export default { 
  data () { 
    return { 
      msg: 'Hello!' 
    } 
  } 
}** 
</script> 

```

请注意，我们不需要在 JavaScript 组件定义中指定模板。作为单文件组件，隐含的是应该使用的模板是在此文件中定义的模板。您可能也注意到我们在这里使用了 ES6 风格。另外，不要忘记`data`属性应该是一个函数而不是一个对象。

在我们的主脚本中，我们必须创建 Vue 应用程序并指示它使用`HelloComponent`：

```js
import Vue from 'vue' 
**import HelloComponent** from './HelloComponent.vue' 

new Vue({ 
  el: '#app', 
  **components: { HelloComponent }** 
}); 

```

我们的`index.html`标记不会改变。它仍然会调用`hello-component`：

```js
<body> 
  <div id="app"> 
    **<hello-component></hello-component>** 
  </div> 
  <script src="./dist/build.js"></script> 
</body> 

```

现在我们只需要安装`npm`依赖项（如果你还没有这样做）并构建应用程序：

```js
**npm install 
npm run dev**

```

一旦你这样做了，你的浏览器将自动打开`localhost:8080`页面！

在[chapter3/hello](https://github.com/PacktPublishing/Learning-Vue.js-2/tree/master/chapter3/hello)文件夹中查看完整的代码。

您还可以在[`www.webpackbin.com/N1LbBIsLb`](http://www.webpackbin.com/N1LbBIsLb)的 webpackbin 中测试、修改、重新测试和检查`hello`组件。

### 提示

Webpackbin 是一个很好的服务，可以运行和测试使用 Webpack 构建的应用程序。尽管它仍处于测试阶段，但它是一个非常好的工具。由于它还很年轻，所以仍然存在一些小问题。例如，如果您尝试下载整个项目的软件包，它将无法构建。

## IDE 的插件

Vue 的创建者和贡献者考虑到了开发人员，并为一系列现代 IDE 开发了插件。您可以在[`github.com/vuejs/awesome-vue#syntax-highlighting`](https://github.com/vuejs/awesome-vue#syntax-highlighting)找到它们。如果您像我一样使用的是 IntelliJ 的 WebStorm IDE，请按照以下说明安装 Vue 支持插件：

1.  转到**`Preferences`** | **`P`****`lugins`**。

1.  点击**`浏览存储库`**。

1.  在搜索框中输入`vue`。

1.  选择**`Vue.js`**，然后点击**`Install`**按钮：

![IDE 的插件](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00266.jpeg)

安装 WebStorm IDE 的 Vue 插件

## 样式和范围

很明显，模板和组件的脚本只属于它。然而，样式并不适用于相同的规则。例如，尝试向我们的`hello`组件添加`style`标签，并添加 CSS 规则，使`<h1>`标签变成红色：

```js
<style> 
  h1 { 
    color: red; 
  } 
</style> 

```

现在，当页面刷新时，可以预期`Hello!`标题的颜色会变成红色。现在尝试将`<h1>`标签添加到主`index.html`文件中。你可能会感到惊讶，但它也会是红色的：

```js
<div id="app"> 
  <h1>This is a single file component demo</h1> 
  <hello-component></hello-component> 
</div> 

```

![样式和范围](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00267.jpeg)

所有的`<h1>`标签都具有我们在组件内定义的样式

为了使样式只附加到组件的范围内，我们需要在`<style>`标签中指定`scoped`属性：

```js
<style **scoped**> 
  h1 { 
    color: red; 
  } 
</style> 

```

看看页面，你会发现只有`Hello!`文本是红色的，其他的`h1`都是默认样式。

## 热重载

您可能已经注意到，现在我不再要求您刷新页面，而是要求您查看页面。这是因为在使用`vue-cli`Webpack 脚手架方法引导应用程序时，每次更改时页面都会自动刷新。这个魔法是由`vue-hot-reload` API 实现的，它监视应用程序的文件，并告诉浏览器在每次有变化时自动重新加载！耶！

## 预处理器

如果您喜欢预处理器，欢迎在您的`.vue`组件中使用它们。这是由于`vue-loader`允许使用 Webpack 加载程序。

### 注意

您可以在教程中找到有关`vue-loader`和预处理器的更多信息[`vue-loader.vuejs.org/en/`](http://vue-loader.vuejs.org/en/)。

### HTML 预处理器

为了能够在单文件 Vue 组件中使用预处理器，只需在`<template>`标签中添加`lang`属性！不要忘记安装相应的节点模块：

```js
**npm install jade --save-dev** 

```

例如，在我们的`hello`组件模板中使用`jade`将会非常简单：

```js
<template lang="jade"> 
  h1 {{ msg }} 
</template> 

```

### CSS 预处理器

相同的逻辑也适用于 CSS 预处理器。让我们看看如何使用，例如，sass 预处理器：

```js
<style lang="sass" scoped> 
  $red: red; 
  h1 { 
    color: $red; 
  } 
</style> 

```

### 提示

就像在前面的例子中一样，不要忘记安装相应的加载程序才能使其工作：`npm install sass-loader node-sass --save-dev`

### JavaScript 预处理器

也可以使用任何 JavaScript 预处理器。就像在前面的两个例子中一样，只需使用`lang`属性指定要使用的预处理器。并且不要忘记通过`npm`安装它！

```js
**> npm install coffee-loader coffee-script --save-dev 
<script lang="coffee"> 
  exports.default = data: -> 
  { msg: 'Hello!' } 
</script>** 

```

# 使用单文件组件重写我们的购物清单应用程序

现在我们已经了解了组件以及如何使用它们，还知道了使我们的代码更容易编写的好技巧，让我们回到我们的购物清单，并将其重写为单文件组件的 Vue 应用程序。为了简单设置，我们可以使用带有 Webpack 配置的`vue-cli`。实际上，我们已经在第二章*基础知识-安装和使用*中完成了。所以，只需找到这个应用程序，并准备开始工作。如果找不到，您可以轻松创建它：

```js
**#install vue-cli if you still hadn't installed it 
$ npm install vue-cli -g 
#bootstrap the application 
$ vue init webpack shopping-list 
$ cd shopping-list 
$ npm install 
$ npm run dev** 

```

确保您的`index.html`文件看起来像下面这样：

```js
<!DOCTYPE html> 
<html> 
  <head> 
    <meta charset="utf-8"> 
    <title>shopping-list</title> 
    <link rel="stylesheet" 
      href="https://maxcdn.bootstrapcdn.com/bootstrap/
      3.3.6/css/bootstrap.min.css"> 
  </head> 
  <body> 
    **<app></app>** 
  </body> 
</html> 

```

您的`main.js`文件应该看起来像下面这样：

```js
import Vue from 'vue' 
import App from './App' 

new Vue({ 
  **el: 'app'**, 
  components: { App } 
}) 

```

我们现在准备创建我们的组件并用它们填充我们的应用程序。当然，您记得我们的购物清单基本上有四个组件：

+   `AddItemComponent`：负责向购物清单添加新项目的组件

+   `ItemComponent`：负责在购物清单项目列表中呈现新项目的组件

+   `ItemsComponent`：负责渲染和管理`ItemComponent`列表的组件

+   ChangeTitleComponent：负责更改列表标题的组件

让我们在`components`文件夹中创建它们。首先，只需在每个组件中包含三个空的部分`(<template>`、`<script>`和`<style>`)，并在主`App.vue`组件中的正确位置调用它们。请在模板中放入一些内容，以便我们可以在页面上清楚地识别不同的组件。因此，我们所有四个组件的代码将如下所示：

![使用单文件组件重写我们的购物清单应用程序](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00268.jpeg)

购物清单应用程序的所有四个组件的代码

现在打开`App.vue`组件。这是我们的主要组件，将所有组件组装在一起。

从`<template>`、`<script>`和`<style>`标签中删除所有内容。我们现在将开始构建我们的应用程序。

首先，我们必须导入`App.vue`将使用的组件（在本例中，全部）。

### 提示

不要忘记，由于我们在这个应用程序中使用了 ES2015，我们可以使用 import/export 和所有其他美丽的 ES2015 功能。

在`<script>`标签内，让我们导入组件并导出包含导入组件和返回购物清单项目的数据函数的对象：

```js
<script> 
  import **AddItemComponent** from './components/AddItemComponent' 
  import **ItemsComponent** from './components/ItemsComponent' 
  import **ChangeTitleComponent** from './components/ChangeTitleComponent' 

  export default { 
    components: { 
      **AddItemComponent, 
      ItemsComponent, 
      ChangeTitleComponent** 
    }, 
    data () { 
      return { 
        **items: [{ text: 'Bananas', checked: true }, 
                { text: 'Apples', checked: false }]** 
      } 
    }, 
    methods: { 
      addItem (text) { 
        this.items.push({ 
          text: text, 
          checked: false 
        }) 
      } 
    } 
  } 
</script> 

```

我们的模板基本上可以与使用简单组件构建的购物清单应用程序中的模板相同。让我们暂时删除有关模型和数据绑定的所有内容。首先，插入负责添加项目的组件，然后是包含所有项目的组件，然后在页脚中，负责更改标题的组件。

然后，我们的模板将如下所示：

```js
<template> 
  <div id="app" class="container"> 
    <h2>{{ title }}</h2> 
    **<add-item-component></add-item-component> 
    <items-component></items-component>** 
    <div class="footer"> 
      <hr/> 
      **<change-title-component></change-title-component>** 
    </div> 
  </div> 
</template> 

```

你还记得组件变量的名称是驼峰式的，当它们在模板内部使用时，应该使用 kebab-case 进行调用，对吧？好的，让我们看看它在浏览器中的样子：

![使用单文件组件重写我们的购物清单应用程序](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00269.jpeg)

使用单文件组件构建的购物清单应用程序

看起来不太美观，对吧？让我们为每个组件填充它们的模板。

### 提示

我们将继续在这个应用程序中使用 Bootstrap 的 CSS 样式。在`index.html`文件中全局包含它：`<link rel="stylesheet" href=" https://maxcdn.bootstrapcdn.com/bootstrap/3.3.6/css/bootstrap.min.css">`

## 添加 ItemComponent

打开`AddItemComponent.vue`。让我们填充它的`<template>`。它将如下所示：

```js
<template> 
  <div> 
    <div class="input-group"> 
      <input type="text" class="input form-control" 
        placeholder="add shopping list item"> 
      <span class="input-group-btn"> 
        <button class="btn btn-default" type="button">Add!</button> 
      </span> 
    </div> 
  </div> 
</template> 

```

如果你在浏览器中查看页面，你会发现它已经改变，变得更加像我们的购物清单应用程序。

## 配置 ItemComponent 和 ItemsComponent

现在让我们转到`ItemComponent`。我们只需复制并粘贴简单组件示例中的 HTML：

```js
//ItemComponent.vue 
<template> 
  <li :class="{ 'removed': item.checked }"> 
    <div class="checkbox"> 
      <label> 
        <input type="checkbox" v-model="item.checked"> {{ item.text }} 
      </label> 
    </div> 
  </li> 
</template> 

```

让我们还为这个组件添加一些`scoped`样式。这个组件的特定样式是与`<li>`、`<span>`和类`.removed`有关的样式。让我们将它们复制并粘贴到这个组件中：

```js
//ItemComponent.vue 
<style scoped> 
  .removed { 
    color: gray; 
  } 
  .removed span { 
    text-decoration: line-through; 
  } 
  li { 
    list-style-type: none; 
  } 
  li span { 
    margin-left: 5px; 
  } 
</style> 

```

现在打开`ItemsComponents`。你记得，它是`ItemComponent`元素的列表。即使你不记得，我猜这个组件名称的复数特征就表明了这一点。为了能够使用`ItemComponent`，它必须导入并在`components`属性中注册。所以，让我们先修改脚本：

```js
//ItemsComponent.vue 
<script> 
  import **ItemComponent** from './ItemComponent' 

  export default { 
    components: { 
      **ItemComponent** 
    } 
  } 
</script> 

```

现在你可以在`<template>`中使用`item-component`了！你还记得如何在`vue.js`中进行迭代吗？当然记得！这就是为什么你现在打开`<template>`标签并编写以下代码：

```js
//temsComponent.vue 
<template> 
  <div> 
    <item-component v-for="item in items" :item="item">
    </item-component> 
  </div> 
</template> 

```

如果你现在检查页面，你会惊讶地发现事情实际上并没有工作。网页控制台充满了错误。你能想出原因吗？

你还记得当子组件想要访问父组件的数据时，它们必须在组件初始化时声明“props”吗？这正是我们在`ItemsComponent`和`ItemComponent`的声明中忘记的事情。

首先，在`App.vue`中，将 items 绑定到`items-component`调用：

```js
//App.vue  
<items-component **:items="items"**></items-component> 

```

然后将`props`属性添加到`ItemsComponent`中：

```js
//ItemsComponent.vue 
<script> 
  import ItemComponent from './ItemComponent' 

  export default { 
    components: { 
      ItemComponent 
    }, 
    **props: ['items']** 
  } 
</script> 

```

现在回到`ItemComponent`并添加`props`属性：

```js
//temComponent.vue 
<script> 
  export default { 
    props: ['item'] 
  } 
</script>  

```

现在检查页面。现在它确实包含了物品列表，并且在我们第一次创建它时几乎具有相同的外观和感觉。在[chapter3/shopping-list](https://github.com/PacktPublishing/Learning-Vue.js-2/tree/master/chapter3/shopping-list)文件夹中检查此部分的完整代码。

# 练习

完成购物清单应用程序，使其具有与以前相同的功能。

剩下的不多了，我相信你会在不到半个小时内完成它。这个练习的可能解决方案可以在附录中找到，*练习的解决方案*。

# 使用单文件组件重写番茄钟应用程序

我希望你还记得并可能甚至使用了我们在本书第一章开发的番茄钟应用程序。

我现在想重新审视它，并做与上一节相同的练习——定义应用程序的组件并使用这些组件重写它。

让我们来看看我们的番茄钟应用程序。现在我要给你一个惊喜：我将包含一个屏幕截图，其中包含在休息时间显示的小猫，使用[`thecatapi.com/api`](http://thecatapi.com/api)：

![使用单文件组件重写番茄钟应用程序](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00270.jpeg)

番茄钟应用程序处于休息状态

有一些容易识别的组件：

+   控制组件（开始，暂停，结束）的组件，让我们称之为`**ControlsComponent**`

+   倒计时组件，`**CowntdownComponent**`

+   当前状态的标题组件（**`Work!`**/**`Rest!`**），`**StateTitleComponent**`

+   取决于状态（工作或休息）的小猫渲染组件`**KittensComponent**`（这是我最喜欢的！）

现在，请停止盯着小猫，让我们开始使用单文件组件来实现我们的番茄钟应用程序！一些用于搭建应用程序的第一步如下：

1.  首先打开前一章中的脚手架式番茄钟应用程序，或者基于 Webpack 模板创建一个新的应用程序。

1.  在`application`文件夹中运行`npm install`和`npm run dev`。

1.  确保你的`index.html`看起来像下面这样：

```js
      <!DOCTYPE html> 
      <html> 
        <head> 
          <meta charset="utf-8"> 
          <title>pomodoro</title> 
        </head> 
        <body> 
          <app></app> 
        </body> 
      </html> 

```

1.  确保你的`main.js`文件看起来像下面这样：

```js
      import Vue from 'vue' 
      import App from './App' 

      /* eslint-disable no-new */ 
      new Vue({ 
        el: 'app', 
        components: { App } 
      }) 

```

1.  打开你的浏览器到页面`localhost:8080`。

1.  然后，就像在之前的例子中一样，转到`components`文件夹并创建所有必要的`.vue`组件。

1.  转到`App.vue`，并导入和注册所有创建的组件。

1.  在每个组件的`<template>`部分，放入一些可以唯一标识它的东西，这样我们在检查页面时可以轻松识别它。

你几乎肯定会看到结构和初始代码，看起来像下面这样：

使用单文件组件重写番茄钟应用程序

使用单文件组件实现的番茄钟应用程序的最初状态

现在，假设我们的组件已经准备好使用，让我们将它们放在应用程序的布局中应该放置的位置。

我只是稍微提醒一下整个应用程序的标记之前是什么样子的：

```js
<div id="app" class="container"> 
  <h2> 
    <span>Pomodoro</span> 
    **// Looks like our ControlsComponent** 
    <button > 
      <i class="glyphicon glyphicon-play"></i> 
    </button> 
    <button > 
      <i class="glyphicon glyphicon-pause"></i> 
    </button> 
    <button > 
      <i class="glyphicon glyphicon-stop"></i> 
    </button> 
  </h2> 
  **// Looks like our StateTitleComponent** 
  <h3>{{ title }}</h3> 
  **// Looks like our CountdownComponent** 
  <div class="well"> 
    <div class="pomodoro-timer"> 
      <span>{{ min }}</span>:<span>{{ sec }}</span> 
    </div> 
  </div> 
  **// Looks like our KittensComponent** 
  <div class="well"> 
    <img :src="catImgSrc" /> 
  </div> 
</div> 

```

你可能已经注意到，我删除了一些负责类绑定或操作处理程序的部分。不要担心。还记得《飘》中的斯嘉丽·奥哈拉吗？她过去常说，

> “我现在不能考虑那个。我明天再想。”

（[`goo.gl/InYm8e`](http://goo.gl/InYm8e)）。斯嘉丽·奥哈拉是一个聪明的女人。像斯嘉丽·奥哈拉一样。目前，我们将只关注`App.vue`的`<template>`标签。其他的东西以后再说。现在我们基本上可以复制并粘贴这个 HTML 片段，并替换我们识别出来的部分，比如组件和它们的 kebab-case 名称。因此，`App.vue`中的模板将如下所示：

```js
//App.vue 
<template> 
  <div id="app" class="container"> 
    <h2> 
      <span>Pomodoro</span> 
      **<controls-component></controls-component>** 
    </h2> 
    **<state-title-component></state-title-component> 
    <countdown-component></countdown-component> 
    <kittens-component></kittens-component>** 
  </div> 
</template> 

```

有点小了，对吧？打开你的应用程序的浏览器检查一下。不是很漂亮，肯定与我们的番茄钟应用程序无关，但是...它起作用！

使用单文件组件重写番茄钟应用程序

番茄钟应用程序作为单文件组件应用程序引导

现在我们该怎么办？将相应的标记复制到它们组件的`<template>`部分。请自己进行这个小小的复制粘贴，让它成为一个小小的家庭练习。但是，如果你想检查一下自己，可以看一下[chapter3/pomodoro](https://github.com/PacktPublishing/Learning-Vue.js-2/tree/master/chapter3/pomodoro)文件夹。目前就是这样了！所有的数据绑定和有趣的东西将在下一章中出现。所以不要关闭这本书。但是，不要忘记休息一下。

# CSS 过渡的响应式绑定

在*转到下一章之前，我们将详细讨论不同类型的数据绑定，我想给你一点有趣的味道，即可以绑定的一些有趣的东西。我知道你非常关注文字，亲爱的读者。所以，到目前为止，你已经发现了两次过渡这个词，你可能已经猜到我们实际上可以将 CSS 过渡绑定到数据变化上。

因此，想象一下，如果您有一个元素，只有在`data`属性`show`为`true`时才应该显示。这很容易，对吧？您已经了解了`v-if`指令：

```js
<div v-if="show">hello</div> 

```

因此，每当`show`属性发生变化时，这个`<div>`就会相应地行为。想象一下，在隐藏/显示时，您希望应用一些 CSS 过渡。使用 Vue，您可以使用特殊的`transition`包装组件来指定数据更改时要使用的过渡：

```js
<transition name="fade">  
  <div v-if="show" transition="my">hello</div> 
</transition> 

```

之后，您只需为`fade-enter`、`fade-leave`、`fade-enter-active`和`fade-leave-active`类定义 CSS 规则。查看有关这些类的官方 Vue 文档页面[`vuejs.org/v2/guide/transitions.html#Transition-Classes`](https://vuejs.org/v2/guide/transitions.html#Transition-Classes)。

让我们看看在我们的`kittens`组件示例中它是如何工作的。首先，让我们在`App.vue`中的`kittens-component`中添加`v-if`指令：

```js
<template> 
  <...> 
  <kittens-component **v-if="kittens"**></kittens-component> 
  <...> 
</template> 

```

此外，我们应该在`App.vue`的`<script>`标签中添加`data`函数（还要使其全局，以便我们可以从 devtools 控制台修改它）：

```js
<script> 
// ... // 
window.data = { 
  kittens: true 
}; 

export default { 
  //.....// 
  data () { 
    return window.data 
  } 
} 
</script> 

```

查看浏览器：一切似乎没有改变。打开 devtools 控制台，输入以下内容：

```js
data.kittens = false 

```

您将看到`kittens`组件将从页面中消失。如果您输入以下内容，它将再次出现：

```js
data.kittens = true 

```

### 提示

我希望您没有忘记在主`index.html`文件中包含 Bootstrap 的 CSS。如果没有，您将看不到任何出现/消失，因为我们的`<div>`标签既没有信息也没有应用任何类：`<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.6/css/bootstrap.min.css">`

但是，我们正在谈论*CSS*过渡，而不是简单地隐藏/显示东西。现在让我们将 CSS`fade`过渡应用到我们的`kittens`组件上。只需添加一个带有名称属性`fade`的包装组件`transition`：

```js
<template> 
  <...> 
  **<transition name="fade">** 
    <kittens-component v-if="kittens"></kittens-component> 
  **</transition>** 
  <...> 
</template> 

```

现在，如果我们为正确的类定义良好的规则，我们将看到一个漂亮的 CSS 过渡。让我们来做吧。在`<style>`标签内添加以下 CSS 规则：

```js
<style scoped> 
  **.fade-enter-active, .fade-leave-active** { 
    transition: opacity .5s 
  } 
  **.fade-enter, .fade-leave-active** { 
    opacity: 0 
  } 
</style> 

```

再次查看页面。打开控制台，输入`data.kittens = false`和`data.kittens = true`。现在您可以看到在每次数据更改时发生漂亮的`fade`过渡。在下一章中，我们将更多地讨论 Vue.js 中的过渡，并将其应用到我们的应用程序中。

# 摘要

在本章中，您了解了 Vue 组件以及如何使用它们。您看到了如何使用经典方法（使用 HTML、CSS 和 JavaScript 的应用程序）创建和注册它们，还看到了使用单文件组件方法创建和操作它们是多么容易。需要记住的事情：

+   虽然变量是使用驼峰格式创建的，但为了能够在模板内部使用组件，你必须应用相应的短横线格式，例如，`MyBeautifulComponent` -> `my-beautiful-component`

+   组件内部的属性`data`和`el`必须是函数而不是对象：`{data: function () {}}`

+   如果你不希望组件的样式泄漏到全局范围，请给它添加一个`scoped`属性：`<style scoped></style>`

我们还使用单文件组件重写了我们的应用程序，并稍微涉及了数据绑定到 CSS 过渡。

在下一章中，我们将深入探讨所有类型的数据绑定，包括 CSS 和 JavaScript 过渡。我们将使用数据绑定使我们的应用程序重焕生机。最后但并非最不重要的是，我们将看到更多的猫！


# 第四章：反应性-将数据绑定到您的应用程序

在上一章中，您学习了 Vue.js 中最重要的概念之一：组件。您看到了如何创建组件，如何注册，如何调用以及如何使用和重用它们。您还学习了单文件组件的概念，甚至在购物清单和番茄钟应用程序中使用了它们。

在本章中，我们将深入探讨数据绑定的概念。我们之前已经谈论过它，所以你已经很熟悉了。我们将以所有可能的方式在我们的组件中绑定数据。

总之，在本章中，我们将：

+   重新审视数据绑定语法

+   在我们的应用程序中应用数据绑定

+   遍历元素数组，并使用相同的模板渲染每个元素

+   重新审视并应用数据和事件绑定的速记方式在我们的应用程序中

# 重新审视数据绑定

我们从第一章开始就一直在谈论数据绑定和反应性。所以，你已经知道数据绑定是一种从数据到可见层以及反之的变化传播机制。在本章中，我们将仔细审视所有不同的数据绑定方式，并在我们的应用程序中应用它们。

# 插入数据

让我们想象一下以下的 HTML 代码：

```js
<div id="hello"></div> 

```

还想象以下 JavaScript 对象：

```js
var data = { 
  msg: 'Hello' 
}; 

```

我们如何在页面上呈现数据条目的值？我们如何访问它们，以便我们可以在 HTML 中使用它们？实际上，在过去的两章中，我们已经在 Vue.js 中大量做了这个。理解并一遍又一遍地做这件事并没有问题。

> “重复是学习之母”

如果您已经是数据插值的专业人士，只需跳过本节，然后继续表达式和过滤器。

那么，我们应该怎么做才能用`msg`的值填充`<div>`？如果我们按照老式的 jQuery 方式，我们可能会做类似以下的事情：

```js
$("#hello").text(data.msg); 

```

但是，在运行时，如果您更改`msg`的值，并且希望这种更改传播到 DOM，您必须手动执行。仅仅改变`data.msg`的值，什么也不会发生。

例如，让我们编写以下代码：

```js
var data = { 
  msg: 'Hello' 
}; 
$('#hello').text(data.msg); 
data.msg = 'Bye'; 

```

然后出现在`<div>`中的文本将是`Hello`。在[`jsfiddle.net/chudaol/uevnd0e4/`](https://jsfiddle.net/chudaol/uevnd0e4/)上检查这个 JSFiddle。

使用 Vue，最简单的插值是用`{{ }}`（句柄注释）完成的。在我们的示例中，我们将编写以下 HTML 代码：

```js
<div id="hello">**{{ msg }}**</div> 

```

因此，`<div>`的内容将与`msg`数据绑定。每次`msg`更改时，`div`的内容都会自动更改其内容。请查看[`jsfiddle.net/chudaol/xuvqotmq/1/`](https://jsfiddle.net/chudaol/xuvqotmq/1/)上的 jsfiddle 示例。Vue 实例化后，`data.msg`也会更改。屏幕上显示的值是新的值！

这仍然是单向绑定的插值。如果我们在 DOM 中更改值，数据将不会发生任何变化。但是，如果我们只需要数据的值出现在 DOM 中，并相应地更改，这是一种完美有效的方法。

此时，应该非常清楚，如果我们想在模板中使用`data`对象的值，我们应该用`{{}}`将它们括起来。

让我们向我们的番茄钟应用程序添加缺失的插值。请在[chapter4/pomodoro](https://github.com/PacktPublishing/Learning-Vue.js-2/tree/master/chapter4/pomodoro)文件夹中检查当前情况。如果您运行`npm run dev`并查看打开的页面，您将看到页面如下所示：

![插入数据](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00273.jpeg)

我们番茄钟应用程序中缺少的插值

从对页面的第一眼扫视中，我们能够确定那里缺少什么。

页面缺少计时器、小猫、番茄钟状态的标题（显示**`工作！`**或**`休息！`**）、以及根据番茄钟状态显示或隐藏小猫占位符的逻辑。让我们首先添加番茄钟状态的标题和番茄钟计时器的分钟和秒。

## 添加番茄钟状态的标题

首先，我们应该决定这个元素应该属于哪个组件。看看我们的四个组件。很明显，它应该属于`StateTitleComponent`。如果您查看以下代码，您将看到它实际上已经在其模板中插值了标题：

```js
//StateTitleComponent.vue 
<template> 
  <h3>**{{ title }}**</h3> 
</template> 

<style scoped> 
</style> 

<script> 
</script> 

```

好！在上一章中，我们已经完成了大部分工作。现在我们只需要添加必须被插值的数据。在这个组件的`<script>`标签中，让我们添加带有`title`属性的`data`对象。现在，让我们将其硬编码为可能的值之一，然后决定如何更改它。你更喜欢什么？**`工作！`** 还是 **`休息！`**？我想我知道答案，所以让我们将以下代码添加到我们的`script`标签中：

```js
//StateTitleComponent.vue 
<script> 
  export default { 
    data () { 
      return { 
        **title: 'Learning Vue.js!'** 
      } 
    } 
  } 
</script> 

```

现在就让它保持这样。我们将在以后的方法和事件处理部分回到这个问题。

## 练习

以与我们添加 Pomodoro 状态标题相同的方式，请将分钟和秒计时器计数器添加到`CountDownComponent`中。它们现在可以是硬编码的。

# 使用表达式和过滤器

在前面的例子中，我们在`{{}}`插值中使用了简单的属性键。实际上，Vue 在这些花括号中支持更多的内容。让我们看看在那里可能做些什么。

## 表达式

这可能听起来出乎意料，但 Vue 支持在数据绑定括号内使用完整的 JavaScript 表达式！让我们去 Pomodoro 应用程序的任何一个组件，并在模板中添加任何 JavaScript 表达式。你可以在[chapter4/pomodoro2](https://github.com/PacktPublishing/Learning-Vue.js-2/tree/master/chapter4/pomodoro2)文件夹中进行一些实验。

例如，尝试打开`StateTitleComponent.vue`文件。让我们在其模板中添加一些 JavaScript 表达式插值，例如：

```js
{{ Math.pow(5, 2) }} 

```

实际上，你只需要取消注释以下行：

```js
//StateTitleComponent.vue 
<!--<p>--> 
  <!--{{ Math.pow(5, 2) }}--> 
<!--</p>--> 

```

你将在页面上看到数字**`25`**。很好，不是吗？让我们用 JavaScript 表达式替换 Pomodoro 应用程序中的一些数据绑定。例如，在`CountdownComponent`组件的模板中，每个用于`min`和`sec`的指令可以被一个表达式替换。目前它看起来是这样的：

```js
//CountdownComponent.vue 
<template> 
  <div class="well"> 
    <div class="pomodoro-timer"> 
      **<span>{{ min }}</span>:<span>{{ sec }}</span>** 
    </div> 
  </div> 
</template> 

```

我们可以用以下代码替换它：

```js
//CountdownComponent.vue 
<template> 
  <div class="well"> 
    <div class="pomodoro-timer"> 
      <span>{{ min + ':' + sec }}</span> 
    </div> 
  </div> 
</template> 

```

还有哪些地方可以添加一些表达式呢？让我们看看`StateTitleComponent`。此刻，我们使用的是硬编码的标题。然而，我们知道它应该以某种方式依赖于番茄钟的状态。如果它处于“工作”状态，它应该显示**`Work!`**，否则应该显示**`Rest!`**。让我们创建这个属性并将其命名为`isworking`，然后将其分配给主`App.vue`组件，因为它似乎属于全局应用状态。然后我们将在`StateTitleComponent`组件的`props`属性中重用它。因此，打开`App.vue`，添加布尔属性`isworking`并将其设置为`true`：

```js
//App.vue 
<...> 
window.data = { 
  kittens: true, 
  **isworking: true** 
}; 

export default { 
  <...> 
  data () { 
    return window.data 
  } 
} 

```

现在让我们在`StateTitleComponent`中重用这个属性，在每个可能的标题中添加两个字符串属性，并最后在模板中添加表达式，根据当前状态有条件地渲染一个标题或另一个标题。因此，组件的脚本将如下所示：

```js
//StateTitleComponent.vue 
<script> 
  export default { 
    data () { 
      return { 
        **workingtitle: 'Work!', 
        restingtitle: 'Rest!'** 
      } 
    }, 
    **props: ['isworking']** 
  } 
</script> 

```

现在我们可以根据`isworking`属性有条件地渲染一个标题或另一个标题。因此，`StateTitleComponent`的模板将如下所示：

```js
<template> 
  <div> 
    <h3> 
      {{ isworking ? workingtitle : restingtitle }} 
    </h3> 
  </div> 
</template> 

```

看一下刷新后的页面。奇怪的是，它显示**`Rest!`**作为标题。如果`App.vue`中的`isworking`属性设置为`true`，那么这是怎么发生的？我们只是忘记在`App.vue`模板中的组件调用上绑定这个属性！打开`App.vue`组件，并在`state-title-component`调用上添加以下代码：

```js
<state-title-component **v-bind:isworking="isworking"**></state-title-component> 

```

现在，如果你查看页面，正确的标题会显示为**`Work!`**。如果你打开开发工具控制台并输入`data.isworking = false`，你会看到标题改变。

如果`isworking`属性为`false`，标题为**`Rest!`**，如下截图所示：

![Expressions](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00274.jpeg)

如果`isworking`属性为`true`，标题为**`Work!`**，如下截图所示：

![Expressions](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00275.jpeg)

## 过滤器

除了花括号内的表达式之外，还可以使用应用于表达式结果的过滤器。过滤器只是函数。它们是由我们创建的，并且通过使用管道符号`|`应用。如果你创建一个将字母转换为大写的过滤器并将其命名为`uppercase`，那么要应用它，只需在双大括号内的管道符号后面使用它：

```js
<h3> {{ title | lowercase }} </h3> 

```

你可以链接尽可能多的过滤器，例如，如果你有过滤器`A`，`B`，`C`，你可以做类似`{{ key | A | B | C }}`的事情。过滤器是使用`Vue.filter`语法创建的。让我们创建我们的`lowercase`过滤器：

```js
//main.js 
Vue.filter('lowercase', (key) => { 
  return key.toLowerCase() 
}) 

```

让我们将其应用到主`App.vue`组件中的 Pomodoro 标题。为了能够使用过滤器，我们应该将`'Pomodoro'`字符串传递到句柄插值符号内。我们应该将它作为 JavaScript 字符串表达式传递，并使用管道符号应用过滤器：

```js
<template> 
  <...> 
    <h2> 
      <span>**{{ 'Pomodoro' | lowercase }}**</span> 
      <controls-component></controls-component> 
    </h2> 
  <...> 
</template> 

```

检查页面；**`Pomodoro`**标题实际上将以小写语法显示。

让我们重新审视我们的`CountdownTimer`组件并查看计时器。目前，只有硬编码的值，对吧？但是当应用程序完全功能时，值将来自某些计算。值的范围将从 0 到 60。计时器显示**`20:40`**是可以的，但少于十的值是不可以的。例如，当只有 1 分钟和 5 秒时，它将是**`1:5`**，这是不好的。我们希望看到类似**`01:05`**的东西。所以，我们需要`leftpad`过滤器！让我们创建它。

转到`main.js`文件，并在大写过滤器定义之后添加一个`leftpad`过滤器：

```js
//main.js 
Vue.filter(**'leftpad'**, (value) => { 
  if (value >= 10) { 
    return value 
  } 
  return '0' + value 
}) 

```

打开`CountdownComponent`组件，让我们再次将`min`和`sec`拆分到不同的插值括号中，并为每个添加过滤器：

```js
//CountdownComponent.vue 
<template> 
  <div class="well"> 
    <div class="pomodoro-timer"> 
      <span>**{{ min | leftpad }}:{{ sec | leftpad }}**</span> 
    </div> 
  </div> 
</template> 

```

用 1 和 5 替换数据中的`min`和`sec`，然后查看。数字出现了前面的"0"！

## 练习

创建两个过滤器，`大写`和`addspace`，并将它们应用到标题**`Pomodoro:`**

+   `大写`过滤器必须做到它所说的那样

+   `addspace`过滤器必须在给定的字符串值右侧添加一个空格

不要忘记**`Pomodoro`**不是一个关键字，所以在插值括号内，它应该被视为一个字符串！在这个练习之前和之后的标题看起来应该是这样的：

![练习](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00276.jpeg)

在应用过滤器大写和添加空格之前和之后的 Pomodoro 应用程序的标题

自己检查：查看[chapter4/pomodoro3](https://github.com/PacktPublishing/Learning-Vue.js-2/tree/master/chapter4/pomodoro3)文件夹。

# 重新审视和应用指令

在上一节中，我们看到了如何插值应用程序的数据以及如何将其绑定到可视层。尽管语法非常强大，并且提供了高可能性的数据修改（使用过滤器和表达式），但它也有一些限制。例如，尝试使用 `{{}}` 符号来实现以下内容：

+   在用户输入中使用插值数据，并在用户在输入中键入时将更改应用到相应的数据

+   将特定元素的属性（例如 `src`）绑定到数据

+   有条件地渲染一些元素

+   遍历数组并渲染一些组件与数组的元素

+   在元素上创建事件监听器

让我们至少尝试第一个。例如，打开购物清单应用程序（在 [chapter4/shopping-list](https://github.com/PacktPublishing/Learning-Vue.js-2/tree/master/chapter4/shopping-list) 文件夹中）。在 `App.vue` 模板中创建一个 `input` 元素，并将其值设置为 `{{ title }}`：

```js
<template> 
  <div id="app" class="container"> 
    <h2>{{ title }}</h2> 
    **<input type="text" value="{{ title }}">** 
    <add-item-component></add-item-component> 
    <...> 
  </div> 
</template> 

```

哦不！到处都是错误。**`已删除属性内的插值`**，它说。这是否意味着在 Vue 2.0 之前，您可以轻松地在属性内使用插值？是的，也不是。如果您在属性内使用插值，您将不会收到错误，但在输入框内更改标题将不会产生任何结果。在 Vue 2.0 中，以及在之前的版本中，为了实现这种行为，我们必须使用指令。

### 注意

**指令**是具有 `v-` 前缀的元素的特殊属性。为什么是 `v-`？因为 Vue！指令提供了一种微小的语法，比简单的文本插值提供了更丰富的可能性。它们有能力在每次数据更改时对可视层应用一些特殊行为。

## 使用 `v-model` 指令进行双向绑定

双向绑定是一种绑定类型，不仅数据更改会传播到 DOM 层，而且 DOM 中绑定数据发生的更改也会传播到数据中。要以这种方式将数据绑定到 DOM，我们可以使用 `v-model` 指令。

我相信您仍然记得第一章中使用 `v-model` 指令的方式：

```js
<input type="text" **v-model="title"**> 

```

这样，标题的值将出现在输入框中，如果您在此输入框中输入内容，相应的更改将立即应用到数据，并反映在页面上所有插值的值中。

只需用 `v-model` 替换花括号符号，并打开页面。

尝试在输入框中输入一些内容。您将看到标题立即更改！

只记住，这个指令只能用于以下元素：

+   `<input>`

+   `<select>`

+   `<textarea>`

尝试所有这些然后删除这段代码。我们的主要目的是能够使用更改标题组件来更改标题。

## 组件之间的双向绑定

从上一章中记得，使用`v-model`指令不能轻松实现组件之间的双向绑定。由于架构原因，Vue 只是阻止子组件轻松地改变父级作用域。

这就是为什么我们在上一章中使用事件系统来能够从子组件更改购物清单的标题。

我们将在本章中再次进行。等到我们到达`v-on`指令的部分之前再等几段时间。

## 使用`v-bind`指令绑定属性

`v-bind`指令允许我们将元素的`属性`或`组件`属性绑定到一个表达式。为了将其应用于特定属性，我们使用冒号分隔符：

```js
v-bind:attribute 

```

例如：

+   `v-bind:src="src"`

+   `v-bind:class="className"`

任何表达式都可以写在`""`内。数据属性也可以像之前的例子一样使用。让我们在我们的 Pomodoro 应用程序中的`KittenComponent`中使用`thecatapi`作为来源添加小猫图片。从[chapter4/pomodoro3](https://github.com/PacktPublishing/Learning-Vue.js-2/tree/master/chapter4/pomodoro3)文件夹打开我们的 Pomodoro 应用程序。

打开`KittenComponent`，将`catimgsrc`添加到组件的数据中，并使用`v-bind`语法将其绑定到图像模板的`src`属性：

```js
<template> 
  <div class="well"> 
    <img **v-bind:src="catImgSrc"** /> 
  </div> 
</template> 

<style scoped> 
</style> 

<script> 
  export default { 
    data () { 
      return { 
        **catimgsrc: "http://thecatapi.com/api/images/get?size=med"** 
      } 
    } 
  } 
</script> 

```

打开页面。享受小猫！

![使用 v-bind 指令绑定属性](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00277.jpeg)

应用了源属性的 Pomodoro KittenComponent

## 使用 v-if 和 v-show 指令进行条件渲染

如果您在前面的部分中已经付出了足够的注意，并且如果我要求您有条件地渲染某些内容，您实际上可以使用插值括号`{{ }}`内的 JavaScript 表达式来实现。

但是，尝试有条件地渲染某个元素或整个组件。这可能并不像在括号内应用表达式那么简单。

`v-if`指令允许有条件地渲染整个元素，这个元素也可能是一个组件元素，取决于某些条件。条件可以是任何表达式，也可以使用数据属性。例如，我们可以这样做：

```js
<div v-if="1 < 5">hello</div> 

```

或者：

```js
<div v-if="Math.random() * 10 < 6">hello</div> 

```

或者：

```js
<div v-if="new Date().getHours() >= 16">Beer Time!</div> 

```

或者使用组件的数据：

```js
<template> 
  <div> 
    <h1 **v-if="!isadmin"**>Beer Time!</h1> 
  </div> 
</template> 
<script> 
  export default { 
    data () { 
      return { 
        **isadmin: false** 
      } 
    } 
  } 
</script> 

```

`v-show`属性做的是同样的工作。唯一的区别是，`v-if`根据条件渲染或不渲染元素，而`v-show`属性总是渲染元素，只是在条件结果为`false`时应用`display:none` CSS 属性。让我们来看看区别。在[chapter4/beer-time](https://github.com/PacktPublishing/Learning-Vue.js-2/tree/master/chapter4/beer-time)文件夹中打开`beer-time`项目。运行`npm install`和`npm run dev`。打开`App.vue`组件，尝试使用`true`/`false`值，并尝试用`v-show`替换`v-if`。打开 devtools 并检查**`elements`**标签页。

让我们首先检查在`isadmin`属性值中使用`v-if`切换`true`和`false`时的外观。

当条件满足时，一切都如预期般出现；元素被渲染并出现在页面上：

![使用 v-if 和 v-show 指令进行条件渲染](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00278.jpeg)

使用`v-if`指令进行条件渲染。条件满足。

当条件不满足时，元素不会被渲染：

![使用 v-if 和 v-show 指令进行条件渲染](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00279.jpeg)

使用`v-if`指令进行条件渲染。条件不满足。

请注意，当条件不满足时，相应的元素根本不会被渲染！

使用`v-show`指令来玩弄条件结果值。当条件满足时，它的外观与使用`v-if`的前一种情况完全相同：

![使用 v-if 和 v-show 指令进行条件渲染](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00280.jpeg)

使用`v-show`指令进行条件渲染。条件满足。

现在让我们来看看当条件不满足时，使用`v-show`指令的元素会发生什么：

![使用 v-if 和 v-show 指令进行条件渲染](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00281.jpeg)

使用`v-show`指令进行条件渲染。条件不满足。

在这种情况下，当条件满足时，一切都是一样的，但当条件不满足时，元素也会被渲染，使用`display:none` CSS 属性。

你如何决定使用哪一个更好？在第一次渲染时，如果条件不满足，`v-if`指令将根本不渲染元素，从而减少初始渲染时的计算成本。但是，如果属性在运行时频繁更改，渲染/移除元素的成本高于仅应用`display:none`属性。因此，对于频繁更改的属性，请使用`v-show`，对于在运行时不会太多更改的条件，请使用`v-if`。

让我们回到我们的番茄钟应用程序。当番茄钟不处于工作状态时，应该有条件地呈现`KittensComponent`。因此，打开[chapter4/pomodoro4](https://github.com/PacktPublishing/Learning-Vue.js-2/tree/master/chapter4/pomodoro4)文件夹中的 Pomodoro 应用程序代码。

你认为应该使用什么？`v-if`还是`v-show`？让我们分析一下。无论我们使用什么，这个元素在初始渲染时都应该可见吗？答案是否定的，因为在初始渲染时，用户开始工作并启动番茄钟计时器。也许最好使用`v-if`，以免在没有必要时产生初始渲染的成本。但是，让我们分析另一个因素——使小猫组件可见/不可见的状态切换的频率。这将在每个番茄钟间隔发生，对吧？在工作 15-20 分钟后，然后在 5 分钟的休息间隔后，实际上并不那么频繁，不会对渲染造成太大影响。在这种情况下，在我看来，无论你使用哪种，都无所谓。让我们使用`v-show`。打开`App.vue`文件，并将`v-show`指令应用于`kittens-component`的调用：

```js
<template> 
  <div id="app" class="container"> 
    <...> 
    <transition name="fade"> 
      <kittens-component **v-show="!isworking"**></kittens-component> 
    </transition> 
  </div> 
</template> 

```

打开页面，尝试在 devtools 控制台中切换`data.isworking`的值。您将看到**小猫**容器的出现和消失。

## 使用 v-for 指令进行数组迭代

你可能记得，数组迭代是使用`v-for`指令完成的，具体语法如下：

```js
<div v-for item in items> 
  item 
</div> 

```

或者使用组件：

```js
<component v-for item in items v-bind:**componentitem="item"**></component> 

```

对于数组中的每个项目，这将呈现一个组件，并将组件的`item`属性绑定到项目的值。当然，你记得在绑定语法的`""`内部，你可以使用任何 JavaScript 表达式。所以，要有创意！

### 提示

不要忘记，在绑定语法（`componentitem`）中使用的属性应该存在于组件的数据中！

例如，看看我们的购物清单应用程序（[chapter4/shopping-list](https://github.com/PacktPublishing/Learning-Vue.js-2/tree/master/chapter4/shopping-list)文件夹）。它已经在`ItemsComponent`中使用了`v-for`语法来渲染物品列表：

```js
<template> 
  <ul> 
    <item-component **v-for="item in items"** :item="item"></item-component> 
  </ul> 
</template> 

```

`ItemComponent`，反过来，使用`props`声明了`item`属性：

```js
<script> 
  export default { 
    **props: ['item']** 
  } 
</script> 

```

现在，让我们用我们的购物清单应用程序做一些有趣的事情。到目前为止，我们只处理了一个购物清单。想象一下，你想为不同类型的购物准备不同的购物清单。例如，你可能有一个常规的购物清单，用于正常的杂货购物日。你可能有一个不同的购物清单用于假期。当你买新房子时，你可能也想有一个不同的购物清单。让我们利用 Vue 组件的可重用性，将我们的购物清单应用程序转换为购物清单列表！我们将使用 Bootstrap 的选项卡面板来显示它们；有关更多信息，请参考[`getbootstrap.com/javascript/#tabs`](http://getbootstrap.com/javascript/#tabs)。

在 IDE 中打开您的购物清单应用程序（[chapter4/shopping-list](https://github.com/PacktPublishing/Learning-Vue.js-2/tree/master/chapter4/shopping-list)文件夹）。

首先，我们应该添加 Bootstrap 的 JavaScript 文件和 jQuery，因为 Bootstrap 依赖它来进行其惊人的魔术。继续手动将它们添加到`index.html`文件中：

```js
  <body> 
    <...> 
    <script src="https://code.jquery.com/jquery-3.1.0.js"></script> 
    <script 
      src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js"> 
    </script> 
    <...> 
  </body> 

```

现在，让我们逐步概述一下，我们应该做些什么，以便将我们的应用程序转换为购物清单列表：

1.  首先，我们必须创建一个新组件。让我们称之为`ShoppingListComponent`，并将我们当前的`App.vue`内容移动到那里。

1.  我们的新`ShoppingListComponent`应该包含`props`属性，其中包括它将从`App.vue`接收的`title`和`items`。

1.  `ItemsComponent`应该从`props`属性接收`items`，而不是硬编码它。

1.  在`App`组件的`data`中，让我们声明并硬编码（暂时）一个`shoppinglists`数组，每个项目应该有一个标题，一个物品数组和一个 ID。

1.  `App.vue`应该导入`ShoppingListComponent`，并在模板中遍历`shoppinglists`数组，并为每个构建`html/jade`结构的选项卡面板。

好的，那么，让我们开始吧！

### 创建 ShoppingListComponent 并修改 ItemsComponent

在`components`文件夹内，创建一个新的`ShoppingListComponent.vue`。将`App.vue`文件的内容复制粘贴到这个新文件中。不要忘记声明将包含`title`和`items`的`props`，并将`items`绑定到模板内的`items-component`调用。此组件的最终代码应该类似于以下内容：

```js
//ShoppingListComponent.vue 
<template> 
  **<div>** 
    <h2>{{ title }}</h2> 
    <add-item-component></add-item-component> 
    **<items-component v-bind:items="items"></items-component>** 
    <div class="footer"> 
      <hr /> 
      <change-title-component></change-title-component> 
    **</div>** 
  </div> 
</template> 

<script> 
  import AddItemComponent from './AddItemComponent' 
  import ItemsComponent from './ItemsComponent' 
  import ChangeTitleComponent from './ChangeTitleComponent' 

  export default { 
    components: { 
      AddItemComponent, 
      ItemsComponent, 
      ChangeTitleComponent 
    } 
    **props: ['title', 'items']** 
  } 
</script> 

<style scoped> 
  **.footer { 
    font-size: 0.7em; 
    margin-top: 20vh; 
  }** 
</style> 

```

请注意，我们删除了父`div`的容器样式和容器的`class`的部分。这部分代码应该留在`App.vue`中，因为它定义了全局应用程序的容器样式。不要忘记`props`属性和将`props`绑定到`items-component`！

打开`ItemsComponent.vue`，确保它包含带有`items`的`props`属性：

```js
<script> 
  <...> 
  export default { 
    **props: ['items'],** 
    <...> 
  } 
</script> 

```

### 修改 App.vue

现在转到`App.vue`。删除`<script>`和`<template>`标签内的所有代码。在`script`标签中，导入`ShoppingListComponent`并在`components`属性内调用它：

```js
//App.vue 
<script> 
  import **ShoppingListComponent** from './components/ShoppingListComponent' 

  export default { 
    **components: { 
      ShoppingListComponent 
    }** 
  } 
</script> 

```

添加一个`data`属性并在那里创建一个`shoppinglists`数组。为该数组添加任意数据。该数组的每个对象应该具有`id`、`title`和`items`属性。正如你记得的那样，`items`必须包含`checked`和`text`属性。例如，你的`data`属性可能如下所示：

```js
//App.vue 
<script> 
  import ShoppingListComponent from './components/ShoppingListComponent' 

  export default { 
    components: { 
      ShoppingListComponent 
    }, 
    **data () { 
      return { 
        shoppinglists: [ 
          { 
            id: 'groceries', 
            title: 'Groceries', 
            items: [{ text: 'Bananas', checked: true }, 
                    { text: 'Apples', checked: false }] 
          }, 
          { 
            id: 'clothes', 
            title: 'Clothes', 
            items: [{ text: 'black dress', checked: false }, 
                    { text: 'all stars', checked: false }] 
          } 
        ] 
      } 
    }** 
  } 
</script> 

```

比我更有创意：添加更多的清单，更多的项目，一些漂亮有趣的东西！

现在让我们为基于购物清单的迭代创建组合 bootstrap 标签面板的结构！让我们首先定义标签工作所需的基本结构。让我们添加所有必要的类和 jade 结构，假装我们只有一个元素。让我们还用大写锁定写出所有将从我们的购物清单数组中重复使用的未知部分：

```js
//App.vue 
<template> 
  <div id="app" class="container"> 
    <ul class="nav nav-tabs" role="tablist"> 
      <li role="presentation"> 
        <a href="**ID**" aria-controls="**ID**" role="tab" data-toggle="tab">**TITLE**</a> 
      </li> 
    </ul> 
    <div class="tab-content"> 
      <div class="tab-pane" role="tabpanel" id="**ID**"> 
        **SHOPPING LIST COMPONENT** 
      </div> 
    </div> 
  </div> 
</template> 

```

有两个元素需要在购物清单数组上进行迭代——包含`<a>`属性的`<li>`标签和`tab-pane` div。在第一种情况下，我们必须将每个购物清单的 ID 绑定到`href`和`aria-controls`属性，并插入标题。在第二种情况下，我们需要将`id`属性绑定到`id`属性，并呈现购物清单项目并将`items`数组和`title`绑定到它。简单！让我们开始。首先向每个元素添加`v-for`指令（对`<li>`和`tab-pane div`元素）：

```js
//App.vue 
<template> 
  <div id="app" class="container"> 
    <ul class="nav nav-tabs" role="tablist"> 
      <li **v-for="list in shoppinglists"** role="presentation"> 
        <a href="ID" aria-controls="ID" role="tab" data-
          toggle="tab">TITLE</a> 
      </li> 
    </ul> 
    <div class="tab-content"> 
      <div **v-for="list in shoppinglists"** class="tab-pane" 
        role="tabpanel" 
        id="ID"> 
        **SHOPPING LIST COMPONENT** 
      </div> 
    </div> 
  </div> 
</template> 

```

现在用正确的绑定替换大写锁定部分。记住，对于`bind`属性，我们使用`v-bind:<corresponding_attribute>="expression"`语法。

对于锚元素的`href`属性，我们必须定义一个表达式，将 ID 选择器`#`附加到`id: v-bind:href="'#' + list.id"`。`aria-controls`属性应该绑定到 ID 的值。`title`可以使用简单的`{{ }}`符号插值进行绑定。

对于`shopping-list-component`，我们必须将`title`和`items`绑定到列表项的相应值。你还记得我们在`ShoppingListComponent`的`props`中定义了`title`和`items`属性吗？因此，绑定应该看起来像`v-bind:title=list.title`和`v-bind:items=list.items`。

因此，在适当的绑定属性之后，模板将如下所示：

```js
//App.vue 
<template> 
  <div id="app" class="container"> 
    <ul class="nav nav-tabs" role="tablist"> 
      <li v-for="list in shoppinglists" role="presentation"> 
        <a **v-bind:href="'#' + list.id" v-bind:aria-controls="list.id"**           role="tab" data-toggle="tab">**{{ list.title }}**</a> 
      </li> 
    </ul> 
    <div class="tab-content"> 
      <div v-for="list in shoppinglists" class="tab-pane" role="tabpanel"
        **v-bind:id="list.id"**> 
        **<shopping-list-component v-bind:** 
 **v-bind:items="list.items"></shopping-list-component>** 
      </div> 
    </div> 
  </div> 
</template> 

```

我们快完成了！如果你现在打开页面，你会看到标签的标题都出现在页面上：

![修改 App.vue](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00282.jpeg)

修改后屏幕上看到的标签标题

如果你开始点击标签标题，相应的标签窗格将打开。但这不是我们期望看到的，对吧？我们期望的是第一个标签默认可见（活动状态）。为了实现这一点，我们应该将`active`类添加到第一个`li`和第一个`tab-pane div`中。但是，如果代码对所有标签都是相同的，因为我们正在遍历数组，我们该怎么做呢？

幸运的是，Vue 允许我们在`v-for`循环内不仅提供*迭代项*，还提供`index`，然后在模板中的表达式中重用这个`index`变量。因此，我们可以使用它来有条件地渲染`active`类，如果索引是"0"的话。在`v-for`循环内使用`index`变量就像下面这样简单：

```js
v-for="**(list, index)** in shoppinglists" 

```

类绑定的语法与其他所有内容的语法相同（`class`也是一个属性）：

```js
**v-bind:class= "active"** 

```

你还记得我们可以在引号内写任何 JavaScript 表达式吗？在这种情况下，我们想要编写一个条件，评估`index`的值，如果是"0"，则类的值是`active`：

```js
v-bind:class= "index===0 ? 'active' : ''" 

```

将`index`变量添加到`v-for`修饰符和`li`和`tab-pane`元素的`class`绑定中，使得最终的模板代码看起来像下面这样：

```js
<template> 
  <div id="app" class="container"> 
    <ul class="nav nav-tabs" role="tablist"> 
      <li **v-bind:class= "index===0 ? 'active' : 
        ''" v-for="(list, index) in shoppinglists"** role="presentation"> 
        <a v-bind:href="'#' + list.id" v-bind:aria-controls="list.id" 
          role="tab" data-toggle="tab">{{ list.title }}</a> 
      </li> 
    </ul> 
    <div class="tab-content"> 
      <div **v-bind:class= "index===0 ? 'active' : ''" 
        v-for="(list,index) in shoppinglists"** class="tab-pane" 
        role="tabpanel" v-bind:id="list.id"> 
        <shopping-list-component v-bind: 
          v-bind:items="list.items"></shopping-list-component> 
      </div> 
    </div> 
  </div> 
</template> 

```

看看这页。现在你应该看到漂亮的标签，它们默认显示内容：

![修改 App.vue](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00283.jpeg)

正确的类绑定后的购物清单应用程序的外观和感觉

在进行这些修改后，最终的购物清单应用程序代码可以在[chapter4/shopping-list2](https://github.com/PacktPublishing/Learning-Vue.js-2/tree/master/chapter4/shopping-list2)文件夹中找到。

## 使用 v-on 指令的事件监听器

使用 Vue.js 监听事件并调用回调非常容易。事件监听也是使用特定修饰符的特殊指令完成的。该指令是`v-on`。修饰符在冒号之后应用：

```js
v-on:click="myMethod" 

```

好的，你说，我在哪里声明这个方法？你可能不会相信，但所有组件的方法都是在`methods`属性内声明的！因此，要声明名为`myMethod`的方法，你应该这样做：

```js
<script> 
  export default { 
    methods: { 
      myMethod () { 
        //do something nice  
      }  
    } 
  } 
</script> 

```

所有`data`和`props`属性都可以使用`this`关键字在方法内部访问。

让我们添加一个方法来向`items`数组中添加新项目。实际上，在上一章中，当我们学习如何在父子组件之间传递数据时，我们已经做过了。我们只是在这里回顾一下这部分。

为了能够在属于`ShoppingListComponent`的购物清单中向`AddItemComponent`内添加新项目，我们应该这样做：

+   确保`AddItemComponent`有一个名为`newItem`的`data`属性。

+   在`AddItemComponent`内创建一个名为`addItem`的方法，该方法推送`newItem`并触发`add`事件。

+   使用`v-on:click`指令为**`Add!`**按钮应用一个事件监听器。此事件监听器应调用已定义的`addItem`方法。

+   在`ShoppingListComponent`内创建一个名为`addItem`的方法，该方法将接收`text`作为参数，并将其推送到`items`数组中。

+   将`v-on`指令与自定义的`add`修饰符绑定到`ShoppingListComponent`内的`add-item-component`的调用上。此监听器将调用此组件中定义的`addItem`方法。

那么，让我们开始吧！使用[chapter4/shopping-list2](https://github.com/PacktPublishing/Learning-Vue.js-2/tree/master/chapter4/shopping-list2)文件夹中的购物清单应用程序并进行操作。

首先打开`AddItemComponent`，并为**`Add!`**按钮和`addItem`方法添加缺失的`v-on`指令：

```js
//AddItemComponent.vue 
<template> 
  <div class="input-group"> 
    <input type="text" **v-model="newItem"** 
      placeholder="add shopping list item" class="form-control"> 
    <span class="input-group-btn"> 
      <button **v-on:click="addItem"** class="btn btn-default" 
        type="button">Add!</button> 
    </span> 
  </div> 
</template> 

<script> 
  export default { 
    data () { 
      return { 
        **newItem: ''** 
      } 
    }, 
    **methods: { 
      addItem () { 
        var text 

        text = this.newItem.trim() 
        if (text) { 
          this.$emit('add', this.newItem) 
          this.newItem = '' 
        } 
      } 
    }** 
  } 
</script> 

```

切换到`ShoppingListComponent`，并将`v-on:add`指令绑定到`template`标签内的`add-item-component`的调用上：

```js
//ShoppingListComponent.vue 
<template> 
  <div> 
    <h2>{{ title }}</h2> 
    <add-item-component **v-on:add="addItem"**></add-item-component> 
    <items-component v-bind:items="items"></items-component> 
    <div class="footer"> 
      <hr /> 
      <change-title-component></change-title-component> 
    </div> 
  </div> 
</template> 

```

现在在`ShoppingListComponent`内创建`addItem`方法。它应该接收文本，并将其推入`this.items`数组中：

```js
//ShoppingListComponent.vue 
<script> 
  import AddItemComponent from './AddItemComponent' 
  import ItemsComponent from './ItemsComponent' 
  import ChangeTitleComponent from './ChangeTitleComponent' 

  export default { 
    components: { 
      AddItemComponent, 
      ItemsComponent, 
      ChangeTitleComponent 
    }, 
    props: ['title', 'items'], 
    **methods: { 
      addItem (text) { 
        this.items.push({ 
          text: text, 
          checked: false 
        }) 
      } 
    }** 
  } 
</script> 

```

打开页面，尝试通过在输入框中输入并点击按钮来将项目添加到列表中。它有效！

现在，我想请你将角色从应用程序的开发人员切换到其用户。在输入框中输入新项目。项目介绍后，用户显而易见的动作是什么？难道你不是想按*Enter*按钮吗？我敢打赌你是！当什么都没有发生时，这有点令人沮丧，不是吗？别担心，我的朋友，我们只需要向输入框添加一个事件侦听器，并调用与**`Add!`**按钮相同的方法。

听起来很容易，对吧？我们按*Enter*按钮时触发了什么事件？对，就是 keyup 事件。因此，我们只需要在冒号分隔符后使用`v-on`指令和`keyup`方法。问题是，当我们按下新的购物清单项目时，每次引入新字母时，该方法都会被调用。这不是我们想要的。当然，我们可以在`addItem`方法内添加一个条件，检查`event.code`属性，并且只有在它是`13`（对应*Enter*键）时，我们才会调用方法的其余部分。幸运的是，对于我们来说，Vue 提供了一种机制，可以为此方法提供按键修饰符，这样我们只能在按下特定按键时调用方法。它应该使用点（`.`）修饰符实现。在我们的情况下，如下所示：

```js
v-on:keyup.enter 

```

让我们将其添加到我们的输入框中。转到`AddItemComponent`，并将`v-on:keyup.enter`指令添加到输入中，如下所示：

```js
<template> 
  <div class="input-group"> 
    <input type="text" **v-on:keyup.enter="addItem"** v-model="newItem" 
      placeholder="add shopping list item" class="form-control"> 
    <span class="input-group-btn"> 
      <button v-on:click="addItem" class="btn btn-default" 
        type="button">Add!</button> 
    </span> 
  </div> 
</template> 

```

打开页面，尝试使用*Enter*按钮将项目添加到购物清单中。它有效！

让我们对标题更改做同样的事情。唯一的区别是，在添加项目时，我们使用了自定义的`add`事件，而在这里我们将使用原生的输入事件。我们已经做到了。我们只需要执行以下步骤：

1.  在`ShoppingListComponent`的模板中，使用`v-model`指令将模型标题绑定到`change-title-component`。

1.  在`ChangeTitleComponent`的`props`属性中导出`value`。

1.  在`ChangeTitleComponent`内创建一个`onInput`方法，该方法将使用事件目标的值发出原生的`input`方法。

1.  将 `value` 绑定到 `ChangeTitleComponent` 组件模板中的 `input`，并使用带有 `onInput` 修饰符的 `v-on` 指令。

因此，在 `ShoppingListComponent` 模板中的 `change-title-component` 调用将如下所示：

```js
//ShoppingListComponent.vue 
<change-title-component **v-model="title"**></change-title-component> 

```

`ChangeTitleComponent` 将如下所示：

```js
//ChangeTitleComponent.vue 
<template> 
  <div> 
    <em>Change the title of your shopping list here</em> 
    <input **v-bind:value="value" v-on:input="onInput"**/> 
  </div> 
</template> 

<script> 
  export default { 
    props: ['value'], 
    methods: { 
      **onInput (event) { 
        this.$emit('input', event.target.value) 
      }** 
    } 
  } 
</script>  

```

此部分的最终代码可以在 [chapter4/shopping-list3](https://github.com/PacktPublishing/Learning-Vue.js-2/tree/master/chapter4/shopping-list3) 文件夹中找到。

## 简写

当然，每次在代码中写 `v-bind` 或 `v-on` 指令并不费时。开发人员倾向于认为每次减少代码量，我们就赢了。Vue.js 允许我们赢！只需记住 `v-bind` 指令的简写是冒号（`:`），`v-on` 指令的简写是 `@` 符号。这意味着以下代码做了同样的事情：

```js
v-bind:items="items"  :items="items" 
v-bind:class=' $index === 0 ? "active" : ""'  
:class=' $index===0 ? "active" : ""' 
v-on:keyup.enter="addItem"  @keyup.enter="addItem" 

```

## 练习

使用我们刚学到的快捷方式重写购物清单应用程序中的所有 `v-bind` 和 `v-on` 指令。

通过查看 [chapter4/shopping-list4](https://github.com/PacktPublishing/Learning-Vue.js-2/tree/master/chapter4/shopping-list4) 文件夹来检查自己。

# 小猫

在本章中，我们并没有涉及到我们的番茄钟应用程序及其可爱的小猫。我向您保证，我们将在下一章中大量涉及它。与此同时，我希望这只小猫会让您开心：

![小猫](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00284.jpeg)

小猫问：“接下来做什么？”

# 总结

在本章中，我们对将数据绑定到我们的表示层的所有可能方式进行了广泛的概述。您学会了如何简单地使用句柄括号（`{{ }}`）插值数据。您还学会了如何在这样的插值中使用 JavaScript 表达式和过滤器。您学习并应用了诸如 `v-bind`、`v-model`、`v-for`、`v-if` 和 `v-show` 等指令。

我们修改了我们的应用程序，使它们使用更丰富和更高效的数据绑定语法。

在下一章中，我们将讨论 Vuex，这是受 Flux 和 Redux 启发的状态管理架构，但具有简化的概念。

我们将为我们的两个应用程序创建全局应用程序状态管理存储，并通过使用它来探索它们的潜力。
