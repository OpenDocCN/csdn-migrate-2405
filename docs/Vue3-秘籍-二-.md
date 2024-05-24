# Vue3 秘籍（二）

> 原文：[`zh.annas-archive.org/md5/915E62C558C25E5846A894A1C2157B6C`](https://zh.annas-archive.org/md5/915E62C558C25E5846A894A1C2157B6C)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三章：数据绑定、表单验证、事件和计算属性

数据是当今世界上最宝贵的资产，知道如何管理它是必须的。在 Vue 中，我们有权利选择如何收集这些数据，按照我们的意愿进行操作，并将其传递到服务器。

在本章中，我们将更多地了解数据处理和数据处理过程、表单验证、数据过滤、如何向用户显示这些数据以及如何以与我们应用程序内部不同的方式呈现它。

我们将学习如何使用`vue-devtools`深入了解 Vue 组件并查看我们的数据和应用程序发生了什么。

在本章中，我们将涵盖以下内容：

+   创建“hello world”组件

+   创建具有双向数据绑定的输入表单

+   向元素添加事件侦听器

+   从输入中删除 v-model

+   创建动态待办事项列表

+   创建计算属性并探索其工作原理

+   使用自定义过滤器显示更清晰的数据和文本

+   使用 Vuelidate 添加表单验证

+   为列表创建过滤器和排序器

+   创建条件过滤以对列表数据进行排序

+   添加自定义样式和过渡

+   使用`vue-devtools`调试您的应用程序

# 技术要求

在本章中，我们将使用**Node.js**和**Vue CLI**。

注意，Windows 用户需要安装一个名为`windows-build-tools`的`npm`包，以便安装以下所需的软件包。为此，请以管理员身份打开 PowerShell 并执行以下命令：

`> npm install -g windows-build-tools`。

要安装**Vue CLI**，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> npm install -g @vue/cli @vue/cli-service-global
```

# 创建“hello world”组件

Vue 应用程序是各种组件的组合，由 Vue 框架绑定在一起并进行编排。知道如何制作您的组件很重要。每个组件就像墙上的一块砖，需要以一种方式制作，以便在放置时不需要其他砖块以不同的方式重新塑造。我们将学习如何制作一个基本组件，其中包含一些侧重于组织和清晰代码的重要原则。

## 准备工作

本教程的先决条件如下：

+   Node.js 12+

所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

## 如何做到这一点... 

要启动我们的组件，我们可以使用 Vue CLI 创建我们的 Vue 项目，就像在“使用 Vue CLI 创建您的第一个项目”中学到的那样，或者开始一个新的项目。

要启动一个新的组件，打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows），并执行以下命令：

```js
> vue create my-component
```

**命令行界面**（**CLI**）将询问一些问题，这些问题将有助于创建项目。您可以使用箭头键导航，*Enter*键继续，*空格键*选择选项。选择**`default`**选项：

```js
?  Please pick a preset: **(Use arrow keys)** ❯ default (babel, eslint) 
  Manually select features  ‌
```

让我们创建我们的第一个“hello world”组件，按照以下步骤进行：

1.  让我们在`src/components`文件夹中创建一个名为`CurrentTime.vue`的新文件。

1.  在这个文件中，我们将从组件的`<template>`部分开始。它将是一个显示当前日期格式化的阴影框卡：

```js
<template>
  <div class='cardBox'>
    <div class='container'>
      <h2>Today is:</h2>
      <h3>{{ getCurrentDate }}</h3>
    </div>
  </div>
</template>
```

1.  现在，我们需要创建`<script>`部分。我们将从`name`属性开始。这将在使用`vue-devtools`调试我们的应用程序时使用，也有助于**集成开发环境**（**IDE**）。对于`getCurrentDate`计算属性，我们将创建一个`computed`属性，它将返回当前日期，由`Intl`浏览器函数格式化：

```js
<script>
export default {
  name: 'CurrentTime',
  computed: {
    getCurrentDate() {
      const browserLocale =
        navigator.languages && navigator.languages.length
          ? navigator.languages[0]
          : navigator.language;
      const intlDateTime = new Intl.DateTimeFormat(
        browserLocale, 
        {
          year: 'numeric',
          month: 'numeric',
          day: 'numeric',
          hour: 'numeric',
          minute: 'numeric'
        });

      return intlDateTime.format(new Date());
    }
  }
};
</script>
```

1.  为了为我们的框添加样式，我们需要在`src`文件夹中创建一个`style.css`文件，然后将`cardBox`样式添加到其中：

```js
.cardBox {
  box-shadow: 0 5px 10px 0 rgba(0, 0, 0, 0.2);
  transition: 0.3s linear;
  max-width: 33%;
  border-radius: 3px;
  margin: 20px;
}

.cardBox:hover {
  box-shadow: 0 10px 20px 0 rgba(0, 0, 0, 0.2);
}

.cardBox>.container {
  padding: 4px 18px;
}

[class*='col-'] {
  display: inline-block;
}

@media only screen and (max-width: 600px) {
  [class*='col-'] {
    width: 100%;
  }

  .cardBox {
    margin: 20px 0;
  }
}

@media only screen and (min-width: 600px) {
  .col-1 {width: 8.33%;}
  .col-2 {width: 16.66%;}
  .col-3 {width: 25%;}
  .col-4 {width: 33.33%;}
  .col-5 {width: 41.66%;}
  .col-6 {width: 50%;}
  .col-7 {width: 58.33%;}
  .col-8 {width: 66.66%;}
  .col-9 {width: 75%;}
  .col-10 {width: 83.33%;}
  .col-11 {width: 91.66%;}
  .col-12 {width: 100%;}
}

@media only screen and (min-width: 768px) {
  .col-1 {width: 8.33%;}
  .col-2 {width: 16.66%;}
  .col-3 {width: 25%;}
  .col-4 {width: 33.33%;}
  .col-5 {width: 41.66%;}
  .col-6 {width: 50%;}
  .col-7 {width: 58.33%;}
  .col-8 {width: 66.66%;}
  .col-9 {width: 75%;}
  .col-10 {width: 83.33%;}
  .col-11 {width: 91.66%;}
  .col-12 {width: 100%;}
}

@media only screen and (min-width: 992px) {
  .col-1 {width: 8.33%;}
  .col-2 {width: 16.66%;}
  .col-3 {width: 25%;}
  .col-4 {width: 33.33%;}
  .col-5 {width: 41.66%;}
  .col-6 {width: 50%;}
  .col-7 {width: 58.33%;}
  .col-8 {width: 66.66%;}
  .col-9 {width: 75%;}
  .col-10 {width: 83.33%;}
  .col-11 {width: 91.66%;}
  .col-12 {width: 100%;}
}

@media only screen and (min-width: 1200px) {
  .col-1 {width: 8.33%;}
  .col-2 {width: 16.66%;}
  .col-3 {width: 25%;}
  .col-4 {width: 33.33%;}
  .col-5 {width: 41.66%;}
  .col-6 {width: 50%;}
  .col-7 {width: 58.33%;}
  .col-8 {width: 66.66%;}
  .col-9 {width: 75%;}
  .col-10 {width: 83.33%;}
  .col-11 {width: 91.66%;}
  .col-12 {width: 100%;}
}
```

1.  在`App.vue`文件中，我们需要导入我们的组件才能看到它：

```js
<template>
  <div id='app'>
    <current-time />
  </div>
</template>

<script>
import CurrentTime from './components/CurrentTime.vue';

export default {
  name: 'app',
  components: {
    CurrentTime
  }
}
</script>
```

1.  在`main.js`文件中，我们需要导入`style.css`文件以包含在 Vue 应用程序中：

```js
import Vue from 'vue';
import App from './App.vue';
import './style.css';

Vue.config.productionTip = false

new Vue({
  render: h => h(App),
}).$mount('#app')
```

1.  要运行服务器并查看您的组件，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows），并执行以下命令：

```js
> npm run serve
```

这是您的组件呈现和运行的方式：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-cb/img/b99bd21c-bcb6-42d3-9983-ab6b05c8c47b.png)

## 它是如何工作的...

Vue 组件几乎与 Node.js 包一样工作。要在代码中使用它，您需要导入组件，然后在要使用的组件的`components`属性中声明它。

就像一堵砖墙一样，Vue 应用程序由调用和使用其他组件的组件组成。

对于我们的组件，我们使用了`Intl.DateTimeFormat`函数，这是一个本机函数，可用于将日期格式化和解析为声明的位置。为了获得本地格式，我们使用了`navigator`全局变量。

## 另请参见

您可以在[`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/DateTimeFormat`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/DateTimeFormat)找到有关`Intl.DateTimeFormat`的更多信息。

您可以在[`v3.vuejs.org/guide/single-file-component.html`](https://v3.vuejs.org/guide/single-file-component.html)找到有关 Vue 组件的更多信息

# 创建具有双向数据绑定的输入表单

为了收集网页上的数据，我们使用 HTML 表单输入。在 Vue 中，可以使用双向数据绑定方法，其中输入在**文档对象模型**（**DOM**）上的值传递到 JavaScript，反之亦然。

这使得 Web 表单更加动态，使您有可能在保存或发送数据回服务器之前管理、格式化和验证数据。

## 准备就绪

此处的先决条件如下：

+   Node.js 12+

所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

## 操作步骤...

要启动我们的组件，我们可以使用 Vue CLI 创建 Vue 项目，就像在第二章的“使用 Vue CLI 创建第一个项目”中学到的那样，或者使用“创建'hello world'组件”中的项目。

现在，让我们按照以下步骤创建具有双向数据绑定的输入表单：

1.  让我们在`src/components`文件夹中创建一个名为`TaskInput.vue`的新文件。

1.  在这个文件中，我们将创建一个组件，其中将包含一个文本输入和一个显示文本。这个文本将基于文本输入中键入的内容。在组件的`<template>`部分，我们需要创建一个 HTML 输入和一个`mustache`变量，用于接收和呈现数据：

```js
<template>
  <div class='cardBox'>
    <div class='container tasker'>
      <strong>My task is: {{ task }}</strong>
      <input 
        type='text'
        v-model='task'
        class='taskInput' />
    </div>
  </div>
</template>
```

1.  现在，在组件的`<script>`部分，我们将命名它并将任务添加到`data`属性中。由于数据始终需要返回一个`Object`，我们将使用箭头函数直接返回一个`Object`：

```js
<script>
export default {
  name: 'TaskInput',
  data: () => ({
    task: '',
  }),
};
</script>
```

1.  我们需要为这个组件添加一些样式。在组件的`<style>`部分，我们需要添加`scoped`属性，以便样式仅绑定到组件，不会与其他**层叠样式表**（**CSS**）规则混合：

```js
<style scoped>
  .tasker{
    margin: 20px;
  }
  .tasker .taskInput {
    font-size: 14px;
    margin: 0 10px;
    border: 0;
    border-bottom: 1px solid rgba(0, 0, 0, 0.75);
  }
  .tasker button {
    border: 1px solid rgba(0, 0, 0, 0.75);
    border-radius: 3px;
    box-shadow: 0 1px 2px 0 rgba(0, 0, 0, 0.2);
  }
</style>
```

1.  现在，我们需要将这个组件导入到我们的`App.vue`文件中：

```js
<template>
  <div id='app'>
    <current-time class='col-4' />
    <task-input class='col-6' />
  </div>
</template>

<script>
import CurrentTime from './components/CurrentTime.vue';
import TaskInput from './components/TaskInput';

export default {
  name: 'app',
  components: {
    CurrentTime,
    TaskInput,
  }
}
</script>
```

1.  要运行服务器并查看您的组件，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> npm run serve
```

这是您的组件呈现并运行的方式：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-cb/img/b95c0f20-649c-45cf-a412-60aa5e1ff24c.png)

## 它是如何工作的...

当您创建一个 HTML`input`元素并为其添加`v-model`时，您正在传递一个内置于 Vue 中的指令，该指令检查输入类型并为我们提供输入的糖语法。这处理了变量值和 DOM 的更新。

这个模型被称为双向数据绑定。如果变量被代码改变，DOM 将重新渲染，如果它被 DOM 通过用户输入改变，比如`input-form`，那么 JavaScript 代码就可以执行一个函数。

## 另请参阅

在[`v3.vuejs.org/guide/forms.html`](https://v3.vuejs.org/guide/forms.html)找到有关表单输入绑定的更多信息

# 向元素添加事件监听器

在 Vue 中，父子通信最常见的方法是通过 props 和 events。在 JavaScript 中，通常会向 DOM 树的元素添加事件监听器，以便在特定事件上执行函数。在 Vue 中，可以添加监听器并根据需要命名，而不是坚持 JavaScript 引擎上存在的名称。

在这个配方中，我们将学习如何创建自定义事件以及如何发出它们。

## 准备就绪

这个配方的先决条件如下：

+   Node.js 12+

所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

## 如何做...

启动我们的组件，我们可以使用 Vue CLI 创建 Vue 项目，就像在“*使用 Vue CLI 创建您的第一个项目*”一章中学到的那样，或者使用“*使用双向数据绑定创建输入表单*”一章中的项目。

按照以下步骤在 Vue 中的元素上添加事件监听器：

1.  创建一个新组件或打开`TaskInput.vue`文件。

1.  在`<template>`部分，我们将添加一个按钮元素，并使用`v-on`指令为按钮点击事件添加事件监听器。我们将从组件中删除`{{ task }}`变量，因为从现在开始它将被发出并不再显示在组件上：

```js
<template>
  <div class='cardBox'>
    <div class='container tasker'>
      <strong>My task is:</strong>
      <input 
        type='text' 
        v-model='task' 
        class='taskInput' />
      <button 
        v-on:click='addTask'>
            Add Task
      </button>
    </div>
  </div>
</template>
```

1.  在组件的`<script>`部分，我们需要添加一个处理点击事件的方法。该方法将被命名为`addTask`。该方法将触发一个名为`add-task`的事件，并将任务发送到数据中。之后，组件上的任务将被重置：

```js
<script>
export default {
  name: 'TaskInput',
  data: () => ({
    task: '',
  }),
  methods: {
    addTask(){
      this.$emit('add-task', this.task);
      this.task = '';
    },
  }
};
</script>
```

1.  在`App.vue`文件中，我们需要在组件上添加一个事件监听器绑定。此侦听器将附加到`add-task`事件。我们将使用`v-on`指令的缩写版本`@`。当它被触发时，事件将调用`addNewTask`方法，该方法将发送一个警报，说明已添加了一个新任务：

```js
<template>
  <div id='app'>
    <current-time class='col-4' />
    <task-input 
      class='col-6'
      @add-task='addNewTask'
    />
  </div>
</template>
```

1.  现在，让我们创建`addNewTask`方法。这将接收任务作为参数，并向用户显示一个警报，显示任务已添加：

```js
<script>
import CurrentTime from './components/CurrentTime.vue';
import TaskInput from './components/TaskInput';

export default {
  name: 'app',
  components: {
    CurrentTime,
    TaskInput,
  },
  methods:{
    addNewTask(task){
      alert(`New task added: ${task}`);
    },
  },
}
</script>
```

1.  要运行服务器并查看您的组件，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> npm run serve
```

这是您的组件呈现并运行的方式：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-cb/img/80b3e48c-93f9-41ef-b73b-58aff9641f67.png)

## 它是如何工作的...

HTML 事件通过`v-on`事件处理指令由 Vue 读取。当我们将`v-on:click`指令附加到按钮时，我们向按钮添加了一个监听器，以便在用户单击按钮时执行一个函数。

该函数在组件方法中声明。该函数在调用时将发出一个事件，表示使用此组件作为子组件的任何组件都可以使用`v-on`指令监听它。

## 另请参阅

您可以在[`v3.vuejs.org/guide/events.html`](https://v3.vuejs.org/guide/events.html)找到有关事件处理的更多信息

# 从输入中删除 v-model

如果我告诉您，在`v-model`的魔术背后有很多代码，使我们的魔术糖语法发生？如果我告诉您，兔子洞可以深入到足以控制输入的事件和值发生的一切？

我们将学习如何提取`v-model`指令的糖语法，并将其转换为其背后的基本语法。

## 准备就绪

此配方的先决条件如下：

+   Node.js 12+

所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

## 如何做到...

要启动我们的组件，我们可以使用 Vue CLI 创建我们的 Vue 项目，就像在第二章*，介绍 TypeScript 和 Vue 生态系统*中学到的那样，或者使用“向元素添加事件侦听器”配方中的项目。

在接下来的步骤中，我们将从输入中删除`v-model`指令的语法糖：

1.  打开`TaskInput.vue`文件。

1.  在组件的`<template>`块中，找到`v-model`指令。我们将删除`v-model`指令。然后，我们需要向输入添加一个新的绑定，称为`v-bind:value`或缩写版本`:value`，以及一个事件侦听器到 HTML`input`元素。我们需要向`input`事件添加一个事件侦听器，使用`v-on:input`指令或缩写版本`@input`。输入绑定将接收任务值作为参数，事件侦听器将接收一个值赋值，其中它将使任务变量等于事件值的值。

```js
<template>
  <div class='cardBox'>
    <div class='container tasker'>
      <strong>My task is:</strong>
      <input 
        type='text' 
        :value='task' 
        @input='task = $event.target.value' 
        class='taskInput' 
      />
      <button v-on:click='addTask'>
        Add Task
      </button>
    </div>
  </div>
</template>
```

1.  要运行服务器并查看您的组件，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> npm run serve 
```

## 它是如何工作的...

作为一种语法糖，`v-model`指令可以自动为您声明绑定和元素的事件侦听器，但副作用是您无法完全控制可以实现的内容。

正如我们所见，绑定的值可以是变量、方法、计算属性或 Vuex getter，例如。对于事件侦听器，它可以是一个函数或一个变量赋值的直接声明。当事件被触发并传递给 Vue 时，`$event`变量用于传递事件。在这种情况下，就像在普通 JavaScript 中一样，要捕获输入的值，我们需要使用`event.target.value`值。

## 另请参阅

您可以在[`v3.vuejs.org/guide/events.html`](https://v3.vuejs.org/guide/events.html)找到有关事件处理的更多信息

# 创建一个动态的待办事项列表

每个程序员在学习一种新语言时创建的第一个项目之一就是待办事项列表。这样做可以让我们更多地了解围绕状态和数据操作的语言过程。

我们将使用 Vue 制作我们的待办事项列表。我们将使用我们在之前的配方中学到和创建的内容。

## 准备工作

这个配方的先决条件如下：

+   Node.js 12+

所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

## 如何做...

制作待办事项应用程序涉及一些基本原则——它必须有一个任务列表；这些任务可以标记为已完成和未完成，并且列表可以进行过滤和排序。现在，我们将学习如何将任务添加到任务列表中。

要启动我们的组件，我们可以使用 Vue CLI 创建 Vue 项目，就像在第二章*，介绍 TypeScript 和 Vue 生态系统*中学到的“使用 Vue CLI 创建你的第一个项目”一节中所述，或者使用“从输入中删除 v-model”一节中的项目。

现在，按照以下步骤使用 Vue 和之前的方法创建一个动态的待办事项列表：

1.  在`App.vue`文件中，我们将创建我们的任务数组。每当`TaskInput.vue`组件发出消息时，这个任务将被填充。我们将向这个数组添加一个带有任务和创建任务的当前日期的对象。目前，任务完成时的日期将是未定义的。为了做到这一点，在组件的`<script>`部分，我们需要创建一个接收任务并将该任务与当前日期添加到`taskList`数组中的方法：

```js
<script>
import CurrentTime from './components/CurrentTime.vue';
import TaskInput from './components/TaskInput';

export default {
  name: 'TodoApp',
  components: {
    CurrentTime,
    TaskInput,
  },
  data: () => ({
    taskList: [],
  }),
  methods:{
    addNewTask(task){
      this.taskList.push({
        task,
        createdAt: Date.now(),
        finishedAt: undefined,
      })
    },
  },
}
</script>
```

1.  现在，我们需要在`<template>`部分呈现这个列表。我们将使用 Vue 的`v-for`指令来迭代任务列表。当我们将这个指令与数组一起使用时，它会给我们访问两个属性——项目本身和项目的索引。我们将使用项目来呈现它，使用索引来创建元素的键以进行呈现。我们需要添加一个复选框，当选中时，调用一个函数来改变任务的状态和任务完成时的显示：

```js
<template>
  <div id='app'>
    <current-time class='col-4' />
    <task-input class='col-6' @add-task='addNewTask' />
    <div class='col-12'>
      <div class='cardBox'>
        <div class='container'>
          <h2>My Tasks</h2>
          <ul class='taskList'>
            <li 
              v-for='(taskItem, index) in taskList'
              :key='`${index}_${Math.random()}`'
            >
              <input type='checkbox' 
                :checked='!!taskItem.finishedAt' 
                @input='changeStatus(index)'
              /> 
              {{ taskItem.task }} 
              <span v-if='taskItem.finishedAt'>
                {{ taskItem.finishedAt }}
              </span>
            </li>
          </ul>
        </div>
      </div>
    </div>
  </div>
</template>
```

始终重要的是要记住迭代器中的键必须是唯一的。这是因为呈现函数需要知道哪些元素已经改变。在这个例子中，我们将`Math.random()`函数添加到索引中以生成一个唯一的键，因为当元素的数量减少时，数组的前几个元素的索引始终是相同的数字。

1.  我们需要在`App.vue`的`methods`属性上创建`changeStatus`函数。这个函数将接收任务的索引作为参数，然后去改变任务数组中的`finishedAt`属性，这是我们标记任务完成的标志：

```js
changeStatus(taskIndex){
  const task = this.taskList[taskIndex];
    if(task.finishedAt){
      task.finishedAt = undefined;
    } else {
      task.finishedAt = Date.now();
    }
}
```

1.  现在，我们需要将任务文本添加到屏幕的左侧。在组件的`<style>`部分，我们将使其具有作用域并添加自定义类：

```js
<style scoped>
  .taskList li{
    text-align: left;
  }
</style>
```

1.  要运行服务器并查看您的组件，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> npm run serve
```

这是您的组件渲染并运行的地方：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-cb/img/6f496750-540a-434a-9446-11731175ea7c.png)

## 工作原理...

当我们从组件接收到发射的消息时，我们用更多的数据来填充消息，并将其推送到本地数组变量中。

在模板中，我们遍历这个数组，使其成为任务列表。这显示了我们需要做的任务，标记任务完成时的复选框以及任务完成的时间。

当用户点击复选框时，它会执行一个函数，将当前任务标记为已完成。如果任务已经完成，函数将把`finishedAt`属性设置为`undefined`。

## 另请参阅

您可以在[`v3.vuejs.org/guide/list.html#mapping-an-array-to-elements-with-v-for`](https://v3.vuejs.org/guide/list.html#mapping-an-array-to-elements-with-v-for)找到有关列表渲染的更多信息

您可以在[`v3.vuejs.org/guide/conditional.html#v-if`](https://v3.vuejs.org/guide/conditional.html#v-if)找到有关条件渲染的更多信息

您可以在[`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Math/random`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Math/random)找到有关`Math.random`的更多信息。

# 创建计算属性并了解其工作原理

想象一下，每次您必须获取操作过的数据时，都需要执行一个函数。想象一下，您需要获取需要经过一些处理的特定数据，并且每次都需要通过函数执行它。这种类型的工作不容易维护。计算属性存在是为了解决这些问题。使用计算属性可以更容易地获取需要预处理甚至缓存的数据，而无需执行任何其他外部记忆函数。

## 准备工作

此示例的先决条件如下：

+   Node.js 12+

所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

## 操作步骤...

我们将继续我们的待办事项项目，或者您可以按照第二章中学到的'*使用 Vue CLI 创建您的第一个项目*'中的步骤创建一个新的 Vue 项目，介绍 TypeScript 和 Vue 生态系统。

现在，按照以下步骤创建计算属性并了解其工作原理：

1.  在`App.vue`文件的`<script>`部分，我们将在`data`和`method`之间添加一个名为`computed`的新属性。这是`computed`属性将被放置的地方。我们将创建一个名为`displayList`的新计算属性，它将用于在模板上呈现最终列表：

```js
<script>
import CurrentTime from './components/CurrentTime.vue';
import TaskInput from './components/TaskInput';

export default {
  name: 'TodoApp',
  components: {
    CurrentTime,
    TaskInput
  },
  data: () => ({
    taskList: []
  }),
  computed: {
    displayList(){
      return this.taskList;
    },
  },
  methods: {
    addNewTask(task) {
      this.taskList.push({
        task,
        createdAt: Date.now(),
        finishedAt: undefined
      });
    },
    changeStatus(taskIndex){
      const task = this.taskList[taskIndex];
      if(task.finishedAt){
        task.finishedAt = undefined;
      } else {
        task.finishedAt = Date.now();
      }
    }
  }
};
</script>
```

`displayList`属性目前只返回变量的缓存值，而不是直接的变量本身。

1.  现在，在`<template>`部分，我们需要更改列表的获取位置：

```js
<template>
  <div id='app'>
    <current-time class='col-4' />
    <task-input class='col-6' @add-task='addNewTask' />
    <div class='col-12'>
      <div class='cardBox'>
        <div class='container'>
          <h2>My Tasks</h2>
          <ul class='taskList'>
            <li 
              v-for='(taskItem, index) in displayList'
              :key='`${index}_${Math.random()}`'
            >
              <input type='checkbox' 
                :checked='!!taskItem.finishedAt' 
                @input='changeStatus(index)'
              /> 
              {{ taskItem.task }} 
              <span v-if='taskItem.finishedAt'>
                {{ taskItem.finishedAt }}
              </span>
            </li>
          </ul>
        </div>
      </div>
    </div>
  </div>
</template>
```

1.  要运行服务器并查看组件，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> npm run serve
```

## 它是如何工作的...

使用`computed`属性将值传递到模板时，该值现在被缓存。这意味着只有在值更新时才会触发渲染过程。同时，我们确保模板不使用变量进行渲染，因此它不能在模板上更改，因为它是变量的缓存副本。

使用这个过程，我们可以获得最佳性能，因为我们不会浪费处理时间重新渲染对数据显示没有影响的更改的 DOM 树。这是因为如果有什么变化，而结果是相同的，`computed`属性会缓存结果并不会更新最终结果。

## 另请参阅

您可以在[`v3.vuejs.org/guide/computed.html`](https://v3.vuejs.org/guide/computed.html)找到有关计算属性的更多信息。

# 使用自定义过滤器显示更清晰的数据和文本

有时您可能会发现用户甚至您自己无法阅读 Unix 时间戳或其他`DateTime`格式。我们如何解决这个问题？在 Vue 中渲染数据时，可以使用我们称之为过滤器的东西。

想象一系列管道，数据通过这些管道流动。数据以一种形式进入每个管道，以另一种形式退出。这就是 Vue 中的过滤器的样子。您可以在同一变量上放置一系列过滤器，因此它会被格式化，重塑，并最终以不同的数据显示，而代码保持不变。在这些管道中，初始变量的代码是不可变的。

## 准备工作

此食谱的先决条件如下：

+   Node.js 12+

所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

## 如何做...

我们将继续我们的待办事项列表项目，或者您可以像在第二章中学到的那样，使用 Vue CLI 创建一个新的 Vue 项目，介绍 TypeScript 和 Vue 生态系统。

按照以下步骤创建您的第一个自定义 Vue 过滤器：

1.  在`App.vue`文件的`<script>`部分，在方法中，创建一个`formatDate`函数。此函数将接收`value`作为参数并进入过滤器管道。我们可以检查`value`是否是一个数字，因为我们知道我们的时间是基于 Unix 时间戳格式的。如果它是一个数字，我们将根据当前浏览器位置进行格式化，并返回该格式化的值。如果传递的值不是一个数字，我们只需返回传递的值。

```js
<script>
  import CurrentTime from './components/CurrentTime.vue';
  import TaskInput from './components/TaskInput';

  export default {
    name: 'TodoApp',
    components: {
      CurrentTime,
      TaskInput
    },
    data: () => ({
      taskList: []
    }),
    computed: {
      displayList() {
        return this.taskList;
      }
    },
    methods: {
      formatDate(value) {
        if (!value) return '';
        if (typeof value !== 'number') return value;

        const browserLocale =
          navigator.languages && navigator.languages.length
            ? navigator.languages[0]
            : navigator.language;
        const intlDateTime = new Intl.DateTimeFormat(
          browserLocale, 
          {
            year: 'numeric',
            month: 'numeric',
            day: 'numeric',
            hour: 'numeric',
            minute: 'numeric'
          });

        return intlDateTime.format(new Date(value));
      },
      addNewTask(task) {
        this.taskList.push({
          task,
          createdAt: Date.now(),
          finishedAt: undefined
        });
      },
      changeStatus(taskIndex) {
        const task = this.taskList[taskIndex];
        if (task.finishedAt) {
          task.finishedAt = undefined;
        } else {
          task.finishedAt = Date.now();
        }
      }
    }
  };
</script>
```

1.  在组件的`<template>`部分，我们需要将变量传递给过滤器方法。为此，我们需要找到`taskItem.finishedAt`属性，并将其作为`formatDate`方法的参数。我们将添加一些文本来表示任务在日期开始时已完成：

```js
<template>
  <div id='app'>
    <current-time class='col-4' />
    <task-input class='col-6' @add-task='addNewTask' />
    <div class='col-12'>
      <div class='cardBox'>
        <div class='container'>
          <h2>My Tasks</h2>
          <ul class='taskList'>
            <li 
              v-for='(taskItem, index) in displayList'
              :key='`${index}_${Math.random()}`'
            >
              <input type='checkbox' 
                :checked='!!taskItem.finishedAt' 
                @input='changeStatus(index)'
              /> 
              {{ taskItem.task }} 
              <span v-if='taskItem.finishedAt'> | 
                Done at: 
                {{ formatDate(taskItem.finishedAt) }}
              </span>
            </li>
          </ul>
        </div>
      </div>
    </div>
  </div>
</template>
```

1.  要运行服务器并查看组件，请打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows），并执行以下命令：

```js
> npm run serve
```

这是您的组件呈现并运行的样子：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-cb/img/f6bf169d-8204-4639-b374-a87b46760d46.png)

## 工作原理...

过滤器是接收一个值并必须返回一个值以在文件的`<template>`部分显示或在 Vue 属性中使用的方法。

当我们将值传递给`formatDate`方法时，我们知道它是一个有效的 Unix 时间戳，因此可以调用新的`Date`类构造函数，将`value`作为参数传递，因为 Unix 时间戳是一个有效的日期构造函数。

我们过滤器背后的代码是`Intl.DateTimeFormat`函数，这是一个原生函数，可用于格式化和解析日期到声明的位置。为了获得本地格式，我们使用`navigator`全局变量。

## 另请参阅

您可以在[`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/DateTimeFormat`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/DateTimeFormat)找到有关`Intl.DateTimeFormat`的更多信息。

# 使用 Vuelidate 添加表单验证

最初，JavaScript 仅用于在将 HTML 表单发送到服务器之前验证这些表单；我们没有任何 JavaScript 框架或今天我们拥有的 JavaScript 生态系统。然而，有一件事仍然是相同的：在将表单发送到服务器之前，应该首先由 JavaScript 引擎进行表单验证。

我们将学习如何使用 Vue 生态系统中最受欢迎的库之一，在发送之前验证我们的输入表单。

## 准备工作

这个配方的先决条件如下：

+   Node.js 12+

所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

## 怎么做...

我们将继续我们的待办事项项目，或者您可以使用 Vue CLI 创建一个新的 Vue 项目，就像在第二章的“使用 Vue CLI 创建您的第一个项目”中学到的那样。

现在，按照以下步骤将表单验证添加到您的 Vue 项目和表单组件中：

1.  要安装**Vuelidate**，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> npm install vuelidate --save
```

1.  要将 Vuelidate 插件添加到 Vue 应用程序中，我们需要在`src`文件夹中的`main.js`文件中导入并添加它：

```js
import Vue from 'vue';
import App from './App.vue';
import Vuelidate from 'vuelidate';
import './style.css';

Vue.config.productionTip = false
Vue.use(Vuelidate);

new Vue({
  render: h => h(App),
}).$mount('#app')
```

1.  在`TaskInput.vue`文件中，我们将向 Vue 对象添加一个新属性。这个属性由安装的新插件解释。在对象的末尾，我们将添加`validations`属性，并在该属性内添加模型的名称。模型是插件将检查验证的数据或计算属性的直接名称：

```js
<script>
export default {
  name: 'TaskInput',
  data: () => ({
    task: ''
  }),
  methods: {
    addTask() {
      this.$emit('add-task', this.task);
      this.task = '';
    }
  },
  validations: {
    task: {}
  }
};
</script>
```

1.  现在，我们需要导入已经存在于我们想要使用的插件上的规则，这些规则将是`required`和`minLength`。导入后，我们将这些规则添加到模型中：

```js
<script>
import { required, minLength } from 'vuelidate/lib/validators';

export default {
  name: 'TaskInput',
  data: () => ({
    task: ''
  }),
  methods: {
    addTask() {
      this.$emit('add-task', this.task);
      this.task = '';
    }
  },
  validations: {
    task: {
      required,
      minLength: minLength(5),
    }
  }
};
</script>
```

1.  现在，我们需要在发出事件之前添加验证。我们将使用`$touch`内置函数告诉插件该字段已被用户触摸，并进行验证。如果有任何字段与用户有任何交互，插件将相应地设置标志。如果没有错误，我们将发出事件，并使用`$reset`函数重置验证。为此，我们将更改`addTask`方法：

```js
addTask() {
    this.$v.task.$touch();

    if (this.$v.task.$error) return false;

    this.$emit('add-task', this.task);
    this.task = '';
    this.$v.task.$reset();
    return true;
}
```

1.  为了提醒用户字段上存在一些错误，我们将使输入更改样式为完整的红色边框，并具有红色文本。为此，我们需要在输入字段上创建一个条件类。这将直接附加到模型的`$error`属性上：

```js
<template>
  <div class='cardBox'>
    <div class='container tasker'>
      <strong>My task is:</strong>
      <input 
        type='text' 
        :value='task' 
        @input='task = $event.target.value' 
        class='taskInput'
        :class="$v.task.$error ? 'fieldError' : ''" 
      />
      <button v-on:click='addTask'>Add Task</button>
    </div>
  </div>
</template>
```

1.  对于类，我们可以在`src`文件夹中的`style.css`文件中创建一个`fieldError`类：

```js
.fieldError {
  border: 2px solid red !important;
  color: red;
  border-radius: 3px;
}
```

1.  要运行服务器并查看您的组件，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> **npm run serve**
```

这是您的组件呈现并运行的方式：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-cb/img/284f804c-a701-4420-8b1b-ae7e4aafb1b9.png)

## 它是如何工作的...

安装后，Vuelidate 插件会向 Vue 原型添加一个新的`$v`属性，并在 Vue 对象中检查一个名为`validations`的新对象属性。当定义了此属性并具有一些规则时，插件会在每次更新时检查模型的规则。

使用这个新的 Vue 原型，我们可以在我们的代码中检查我们定义的规则内的错误，并执行函数来告诉插件该字段已被用户触摸以标记为脏字段或重置它。使用这些功能，我们能够根据我们在任务模型上定义的规则添加一个新的条件类。

任务模型是必需的，并且至少有五个字符。如果不满足这些规则，插件将标记模型有错误。我们获取此错误并使用它来向用户显示任务字段有活动错误。当用户满足要求时，错误的显示消失，事件可以被触发。

## 另请参阅

您可以在[`vuelidate.netlify.com/`](https://vuelidate.netlify.com/)找到有关 Vuelidate 的更多信息。

您可以在[`v3.vuejs.org/guide/class-and-style.html`](https://v3.vuejs.org/guide/class-and-style.html)找到有关类和样式绑定的更多信息

# 为列表创建过滤器和排序器

在处理列表时，通常会发现自己有原始数据。有时，您需要对这些数据进行过滤，以便用户可以阅读。为此，我们需要一组计算属性来形成最终的过滤器和排序器。

在这个示例中，我们将学习如何创建一个简单的过滤器和排序器，来控制我们最初的待办任务列表。

## 准备工作

此示例的先决条件如下：

+   Node.js 12+

所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

## 如何做...

我们将继续我们的待办事项列表项目，或者您可以像在第二章中学到的那样，使用 Vue CLI 创建一个新的 Vue 项目，介绍 TypeScript 和 Vue 生态系统。

按照以下步骤添加一组过滤器和排序到您的列表中：

1.  在`App.vue`文件的`<script>`部分，我们将添加新的计算属性；这些将用于排序和过滤。我们将添加三个新的计算属性，`baseList`，`filteredList`和`sortedList`。`baseList`属性将是我们的第一个操作。我们将通过`Array.map`向任务列表添加一个`id`属性。由于 JavaScript 数组从零开始，我们将在数组的索引上添加`1`。`filteredList`属性将过滤`baseList`属性，并返回未完成的任务，`sortedList`属性将对`filteredList`属性进行排序，以便最后添加的`id`属性将首先显示给用户：

```js
<script>
import CurrentTime from "./components/CurrentTime.vue";
import TaskInput from "./components/TaskInput";

export default {
  name: "TodoApp",
  components: {
    CurrentTime,
    TaskInput
  },
  data: () => ({
    taskList: [],
  }),
  computed: {
    baseList() {
      return [...this.taskList]
        .map((t, index) => ({
            ...t,
            id: index + 1
          }));
    },
    filteredList() {
      return [...this.baseList]
            .filter(t => !t.finishedAt);
    },
    sortedList() {
      return [...this.filteredList]
          .sort((a, b) => b.id - a.id);
    },
    displayList() {
      return this.sortedList;
    }
  },
  methods: {
    formatDate(value) {
      if (!value) return "";
      if (typeof value !== "number") return value;

      const browserLocale =
        navigator.languages && navigator.languages.length
          ? navigator.languages[0]
          : navigator.language;
      const intlDateTime = new Intl.DateTimeFormat(browserLocale, {
        year: "numeric",
        month: "numeric",
        day: "numeric",
        hour: "numeric",
        minute: "numeric"
      });

      return intlDateTime.format(new Date(value));
    },
    addNewTask(task) {
      this.taskList.push({
        task,
        createdAt: Date.now(),
        finishedAt: undefined
      });
    },
    changeStatus(taskIndex) {
      const task = this.taskList[taskIndex];

      if (task.finishedAt) {
        task.finishedAt = undefined;
      } else {
        task.finishedAt = Date.now();
      }
    }
  }
};
</script>
```

1.  在`<template>`部分，我们将`Task ID`添加为指示器，并更改`changeStatus`方法发送参数的方式。因为现在索引是可变的，我们不能将其用作变量；它只是数组上的临时索引。我们需要使用任务`id`：

```js
<template>
  <div id="app">
    <current-time class="col-4" />
    <task-input class="col-6" @add-task="addNewTask" />
    <div class="col-12">
      <div class="cardBox">
        <div class="container">
          <h2>My Tasks</h2>
          <ul class="taskList">
            <li 
              v-for="(taskItem, index) in displayList"
              :key="`${index}_${Math.random()}`"
            >
              <input type="checkbox" 
                :checked="!!taskItem.finishedAt" 
                @input="changeStatus(taskItem.id)"
              /> 
              #{{ taskItem.id }} - {{ taskItem.task }} 
              <span v-if="taskItem.finishedAt"> | 
                Done at: 
                {{ formatDate(taskItem.finishedAt) }}
              </span>
            </li>
          </ul>
        </div>
      </div>
    </div>
  </div>
</template>
```

1.  在`changeStatus`方法中，我们也需要更新我们的函数。由于索引现在从`1`开始，我们需要将数组的索引减一，以获取更新前元素的真实索引：

```js
changeStatus(taskId) {
    const task = this.taskList[taskId - 1];

    if (task.finishedAt) {
    task.finishedAt = undefined;
    } else {
    task.finishedAt = Date.now();
    }
}
```

1.  要运行服务器并查看您的组件，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows），并执行以下命令：

```js
> npm run serve
```

这是您的组件呈现和运行的方式：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-cb/img/ac7a3ae0-6182-43c6-9398-c6de789ffe45.png)

## 它是如何工作的...

`computed`属性一起作为列表的缓存工作，并确保对元素的操作没有副作用：

1.  在`baseList`属性中，我们创建了一个新数组，其中包含相同的任务，但为任务添加了一个新的`id`属性。

1.  在`filteredList`属性中，我们取出了`baseList`属性，并且只返回了未完成的任务。

1.  在`sortedList`属性上，我们按照它们的 ID，按降序对`filteredList`属性上的任务进行排序。

当所有操作完成时，`displayList`属性将返回被操作的数据的结果。

## 另请参阅

您可以在[`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/map`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/map)找到有关`Array.prototype.map`的更多信息。

您可以在[`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/filter`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/filter)找到有关`Array.prototype.filter`的更多信息。

您可以在[`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/sort`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/sort)找到有关`Array.prototype.sort`的更多信息。

# 创建条件过滤器以对列表数据进行排序

完成上一个食谱后，您的数据应该已经被过滤和排序，但您可能需要检查过滤后的数据或需要更改排序方式。在这个食谱中，我们将学习如何创建条件过滤器并对列表上的数据进行排序。

使用一些基本原则，可以收集信息并以许多不同的方式显示它。

## 准备工作

此食谱的先决条件如下：

+   Node.js 12+

所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

## 如何做...

我们将继续我们的待办事项列表项目，或者您可以按照*在第二章*中学到的，在 Vue CLI 中创建一个新的 Vue 项目，介绍 TypeScript 和 Vue 生态系统。

现在，按照以下步骤添加条件过滤器以对列表数据进行排序：

1.  在`App.vue`文件的`<script>`部分，我们将更新`computed`属性，`filteredList`，`sortedList`和`displayList`。我们需要向我们的项目添加三个新变量，`hideDone`，`reverse`和`sortById`。所有三个变量都将是布尔变量，并且默认值为`false`。`filteredList`属性将检查`hideDone`变量是否为`true`。如果是，它将具有相同的行为，但如果不是，它将显示整个列表而不进行任何过滤。`sortedList`属性将检查`sortById`变量是否为`true`。如果是，它将具有相同的行为，但如果不是，它将按任务完成日期对列表进行排序。`displayList`属性将检查`reverse`变量是否为`true`。如果是，它将颠倒显示的列表，但如果不是，它将具有相同的行为：

```js
<script>
import CurrentTime from "./components/CurrentTime.vue";
import TaskInput from "./components/TaskInput";

export default {
  name: "TodoApp",
  components: {
    CurrentTime,
    TaskInput
  },
  data: () => ({
    taskList: [],
    hideDone: false,
    reverse: false,
    sortById: false,
  }),
  computed: {
    baseList() {
      return [...this.taskList]
        .map((t, index) => ({
            ...t,
            id: index + 1
          }));
    },
    filteredList() {
      return this.hideDone
        ? [...this.baseList]
            .filter(t => !t.finishedAt)
        : [...this.baseList];
    },
    sortedList() {
      return [...this.filteredList]
          .sort((a, b) => (
            this.sortById
              ? b.id - a.id
              : (a.finishedAt || 0) - (b.finishedAt || 0)
          ));
    },
    displayList() {
      const taskList = [...this.sortedList];

      return this.reverse 
      ? taskList.reverse() 
      : taskList;
    }
  },
  methods: {
    formatDate(value) {
      if (!value) return "";
      if (typeof value !== "number") return value;

      const browserLocale =
        navigator.languages && navigator.languages.length
          ? navigator.languages[0]
          : navigator.language;

      const intlDateTime = new Intl.DateTimeFormat(browserLocale, {
        year: "numeric",
        month: "numeric",
        day: "numeric",
        hour: "numeric",
        minute: "numeric"
      });

      return intlDateTime.format(new Date(value));
    },
    addNewTask(task) {
      this.taskList.push({
        task,
        createdAt: Date.now(),
        finishedAt: undefined
      });
    },
    changeStatus(taskId) {
      const task = this.taskList[taskId - 1];

      if (task.finishedAt) {
        task.finishedAt = undefined;
      } else {
        task.finishedAt = Date.now();
      }
    }
  }
};
</script>
```

1.  在`<template>`部分，我们需要为这些变量添加控制器。我们将创建三个复选框，直接通过`v-model`指令与变量链接：

```js
<template>
  <div id="app">
    <current-time class="col-4" />
    <task-input class="col-6" @add-task="addNewTask" />
    <div class="col-12">
      <div class="cardBox">
        <div class="container">
          <h2>My Tasks</h2>
          <hr /> 
          <div class="col-4">
            <input 
              v-model="hideDone"
              type="checkbox"
              id="hideDone"
              name="hideDone"
            />
            <label for="hideDone">
              Hide Done Tasks
            </label>
          </div>
          <div class="col-4">
            <input 
              v-model="reverse"
              type="checkbox"
              id="reverse"
              name="reverse"
            />
            <label for="reverse">
              Reverse Order
            </label>
          </div>
          <div class="col-4">
            <input 
              v-model="sortById"
              type="checkbox"
              id="sortById"
              name="sortById"
            />
            <label for="sortById">
              Sort By Id
            </label>
          </div>
          <ul class="taskList">
            <li 
              v-for="(taskItem, index) in displayList"
              :key="`${index}_${Math.random()}`"
            >
              <input type="checkbox" 
                :checked="!!taskItem.finishedAt" 
                @input="changeStatus(taskItem.id)"
              /> 
              #{{ taskItem.id }} - {{ taskItem.task }} 
              <span v-if="taskItem.finishedAt"> | 
                Done at: 
                {{ formatDate(taskItem.finishedAt) }}
              </span>
            </li>
          </ul>
        </div>
      </div>
    </div>
  </div>
</template>
```

1.  要运行服务器并查看您的组件，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> npm run serve
```

这是您的组件呈现和运行的方式：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-cb/img/4d8eb6dc-0d68-4c98-9a23-594d2b8df916.png)

## 工作原理...

`computed`属性一起作为列表的缓存工作，并确保在元素操作中没有任何副作用。通过条件处理，可以通过变量更改过滤和排序规则，并且显示会实时更新：

1.  在`filteredList`属性处，我们取出了`baseList`属性，并返回了未完成的任务。当`hideDone`变量为`false`时，我们返回整个列表而不进行任何过滤。

1.  在`sortedList`属性处，我们对`filteredList`属性上的任务进行了排序。当`sortById`变量为`true`时，列表按 ID 降序排序；当为`false`时，按任务完成时间升序排序。

1.  在`displayList`属性处，当`reverse`变量为`true`时，最终列表被颠倒。

当所有操作都完成时，`displayList`属性返回了被操作的数据的结果。

这些`computed`属性由用户屏幕上的复选框控制，因此用户可以完全控制他们可以看到什么以及如何看到它。

## 另请参阅

您可以在[`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/map`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/map)找到有关`Array.prototype.map`的更多信息。

您可以在[`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/filter`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/filter)找到有关`Array.prototype.filter`的更多信息。

您可以在[`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/sort`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/sort)找到有关`Array.prototype.sort`的更多信息。

# 添加自定义样式和过渡效果

在组件中添加样式是一个很好的做法，因为它可以让用户更清楚地看到发生了什么。通过这样做，您可以向用户显示视觉响应，也可以为您的应用程序提供更好的体验。

在这个示例中，我们将学习如何添加一种新的条件类绑定。我们将使用 CSS 效果与每个新的 Vue 更新带来的重新渲染相结合。

## 准备就绪

此处的先决条件如下：

+   Node.js 12+

所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

## 如何做...

我们将继续我们的待办事项清单项目，或者您可以像在第二章“使用 Vue CLI 创建您的第一个项目”中学到的那样，使用 Vue CLI 创建一个新的 Vue 项目。

按照以下步骤为您的组件添加自定义样式和过渡效果：

1.  在`App.vue`文件中，我们将为已完成的任务的列表项添加一个条件类：

```js
<template>
  <div id="app">
    <current-time class="col-4" />
    <task-input class="col-6" @add-task="addNewTask" />
    <div class="col-12">
      <div class="cardBox">
        <div class="container">
          <h2>My Tasks</h2>
          <hr /> 
          <div class="col-4">
            <input 
              v-model="hideDone"
              type="checkbox"
              id="hideDone"
              name="hideDone"
            />
            <label for="hideDone">
              Hide Done Tasks
            </label>
          </div>
          <div class="col-4">
            <input 
              v-model="reverse"
              type="checkbox"
              id="reverse"
              name="reverse"
            />
            <label for="reverse">
              Reverse Order
            </label>
          </div>
          <div class="col-4">
            <input 
              v-model="sortById"
              type="checkbox"
              id="sortById"
              name="sortById"
            />
            <label for="sortById">
              Sort By Id
            </label>
          </div>
          <ul class="taskList">
            <li 
              v-for="(taskItem, index) in displayList"
              :key="`${index}_${Math.random()}`"
              :class="!!taskItem.finishedAt ? 'taskDone' : ''"
            >
              <input type="checkbox" 
                :checked="!!taskItem.finishedAt" 
                @input="changeStatus(taskItem.id)"
              /> 
              #{{ taskItem.id }} - {{ taskItem.task }} 
              <span v-if="taskItem.finishedAt"> | 
                Done at: 
                {{ formatDate(taskItem.finishedAt) }}
              </span>
            </li>
          </ul>
        </div>
      </div>
    </div>
  </div>
</template>
```

1.  在组件的`<style>`部分，我们将为`taskDone`的 CSS 类创建 CSS 样式表类。我们需要让列表项之间有一个分隔符；然后，我们将使列表具有条纹样式；当它们被标记为完成时，背景将发生变化。要在行之间添加分隔符和条纹列表或斑马样式，我们需要添加一个 CSS 样式表规则，适用于我们列表的每个`even nth-child`：

```js
<style scoped>
  .taskList li {
    list-style: none;
    text-align: left;
    padding: 5px 10px;
    border-bottom: 1px solid rgba(0,0,0,0.15);
  }

  .taskList li:last-child {
    border-bottom: 0px;
  }

  .taskList li:nth-child(even){
    background-color: rgba(0,0,0,0.05);
  }
</style>
```

1.  在`<style>`部分的末尾添加 CSS 动画关键帧，指示背景颜色变化，并将此动画应用于`.taskDone` CSS 类，以在任务完成时添加背景效果

```js
<style scoped>
  .taskList li {
    list-style: none;
    text-align: left;
    padding: 5px 10px;
    border-bottom: 1px solid rgba(0,0,0,0.15);
  }

  .taskList li:last-child {
    border-bottom: 0px;
  }

  .taskList li:nth-child(even){
    background-color: rgba(0,0,0,0.05);
  }

  @keyframes colorChange {
    from{
      background-color: inherit;
    }
    to{
      background-color: rgba(0, 160, 24, 0.577); 
    }
  }

  .taskList li.taskDone{
    animation: colorChange 1s ease;
    background-color: rgba(0, 160, 24, 0.577);
  }
</style>
```

1.  要运行服务器并查看您的组件，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> npm run serve
```

这是您的组件呈现和运行的地方：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-cb/img/b6bfb646-97a9-4db1-a4f4-ff5e1722f1d5.png)

## 它是如何工作的...

每当我们的应用程序中的新项目被标记为已完成时，`displayList`属性都会更新并触发组件的重新渲染。

因此，我们的`taskDone` CSS 类附加了一个在渲染时执行的动画，显示绿色背景。

## 另请参阅

您可以在[`developer.mozilla.org/en-US/docs/Web/CSS/CSS_Animations/Using_CSS_animations`](https://developer.mozilla.org/en-US/docs/Web/CSS/CSS_Animations/Using_CSS_animations)找到有关 CSS 动画的更多信息。

您可以在[`v3.vuejs.org/guide/class-and-style.html`](https://v3.vuejs.org/guide/class-and-style.html)找到有关类和样式绑定的更多信息

# 使用 vue-devtools 调试您的应用程序

`vue-devtools`对于每个 Vue 开发人员都是必不可少的。这个工具向我们展示了 Vue 组件、路由、事件和 vuex 的深度。

借助`vue-devtools`扩展程序，可以调试我们的应用程序，在更改代码之前尝试新数据，执行函数而无需直接在代码中调用它们，等等。

在这个配方中，我们将学习如何使用 devtools 找到有关您的应用程序的更多信息，以及如何使用它来帮助您的调试过程。

## 准备就绪

此配方的先决条件如下：

+   Node.js 12+

所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

您需要在浏览器中安装`vue-devtools`扩展程序：

+   Chrome 扩展程序-[`bit.ly/chrome-vue-devtools`](http://bit.ly/chrome-vue-devtools)

+   Firefox 扩展程序-[`bit.ly/firefox-vue-devtools`](http://bit.ly/firefox-vue-devtools)

## 如何做...

我们将继续进行待办事项列表项目，或者您可以按照第二章*，介绍 TypeScript 和 Vue 生态系统*中学到的内容，使用 Vue CLI 创建一个新的 Vue 项目。

在开发任何 Vue 应用程序时，始终最好使用`vue-devtools`进行开发。

按照这些步骤来了解如何使用`vue-devtools`以及如何正确调试 Vue 应用程序：

1.  要进入`vue-devtools`，首先需要在浏览器中安装它，所以请查看本教程的“准备就绪”部分，获取 Chrome 或 Firefox 的扩展链接。在 Vue 开发应用程序中，进入**浏览器开发者检查器**模式。一个名为 Vue 的新标签页必须出现：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-cb/img/423ad7ca-5967-4855-9f18-ed65a80156c6.png)

1.  您首先看到的是**组件**标签页。该标签页显示了您的应用程序组件树。如果单击组件，您将能够查看所有可用数据，计算属性，以及由插件（如`vuelidate`，`vue-router`或`vuex`）注入的额外数据。您可以编辑数据以实时查看应用程序中的更改：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-cb/img/510f837e-67e8-4f55-9988-82e00cf76724.png)

1.  第二个标签页是用于**vuex 开发**的。该标签页将显示变化的历史记录、当前状态和 getter。可以检查每个变化传递的有效负载，并进行时间旅行变化，以在 vuex 状态中“回到过去”：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-cb/img/30c2819a-19b2-4d5f-98ce-ed4915549aaf.png)

1.  第三个标签页专门用于应用程序中的**事件发射器**。在此处显示了应用程序中发射的所有事件。您可以通过单击事件来检查发射的事件。您可以查看事件的名称、类型，事件的来源（在本例中是一个组件），以及有效负载：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-cb/img/e211f6da-af01-4328-ad00-4bc3860f88f8.png)

1.  第四个标签页专门用于**vue-router**插件。在那里，您可以查看导航历史记录，以及传递给新路由的所有元数据。您可以查看应用程序中所有可用的路由：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-cb/img/64d52f48-5546-4437-98bb-b71640903cff.png)

1.  第五个标签页是**性能**标签页。在这里，您可以检查组件的加载时间，应用程序运行的每秒帧数，以及实时发生的事件。第一张截图显示了当前应用程序的每秒帧数，以及所选组件的每秒帧数：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-cb/img/8eb92c33-2f51-465f-a770-136dfcc1db6d.png)

第二张截图显示了组件生命周期钩子的性能，以及执行每个钩子所需的时间：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-cb/img/0147e07e-1a25-4646-9d96-be9825945a4e.png)

1.  第六个标签是您的**设置**标签；在这里，您可以管理扩展程序，更改外观，内部行为以及在 Vue 插件中的行为方式：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-cb/img/14845284-4326-4234-99f5-96a2e6712e31.png)

1.  最后一个标签是`vue-devtools`的刷新按钮。有时，当`hot-module-reload`发生或者应用程序组件树中发生一些复杂事件时，扩展程序可能会失去对发生情况的跟踪。这个按钮强制扩展程序重新加载并再次读取 Vue 应用程序状态。

## 另请参阅

您可以在[`github.com/vuejs/vue-devtools`](https://github.com/vuejs/vue-devtools)找到有关`vue-devtools`的更多信息。


# 第四章：组件，混合和功能组件

构建 Vue 应用程序就像拼图一样。拼图的每一块都是一个组件，每一块都有一个插槽要填充。

组件在 Vue 开发中扮演着重要的角色。在 Vue 中，您的代码的每一部分都将是一个组件——它可以是布局，页面，容器或按钮，但最终，它都是一个组件。学习如何与它们交互并重用它们是清理代码和提高 Vue 应用性能的关键。组件是最终会在屏幕上呈现出某些东西的代码，无论大小如何。

在本章中，我们将学习如何制作一个可视化组件，可以在许多地方重复使用。我们将使用插槽将数据放入我们的组件中，为了严格快速的渲染，创建功能性组件，实现父子组件之间的直接通信，最后，看看如何异步加载您的组件。

让我们把所有这些部分放在一起，创建一个美丽的拼图，即 Vue 应用程序。

在本章中，我们将涵盖以下配方：

+   创建一个可视化模板组件

+   使用插槽和命名插槽将数据放入您的组件中

+   将数据传递给您的组件并验证数据

+   创建功能性组件

+   访问您的子组件数据

+   创建一个动态注入的组件

+   创建一个依赖注入组件

+   创建一个组件`mixin`

+   延迟加载您的组件

# 技术要求

在本章中，我们将使用**Node.js**和**Vue-CLI**。

注意 Windows 用户：您需要安装一个名为`windows-build-tools`的 NPM 包，以便能够安装以下所需的包。为此，请以管理员身份打开 PowerShell 并执行以下命令：

> npm install -g windows-build-tools

要安装**Vue-CLI**，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> npm install -g @vue/cli @vue/cli-service-global
```

# 创建一个可视化模板组件

组件可以是数据驱动的，无状态的，有状态的，或者是一个简单的可视化组件。但是什么是可视化组件？可视化组件是一个只有一个目的的组件：可视化操作。

一个可视化组件可以有一个简单的带有一些`div` HTML 元素的作用域 CSS，或者它可以是一个更复杂的组件，可以实时计算元素在屏幕上的位置。

我们将创建一个遵循 Material Design 指南的卡片包装组件。

## 准备工作

此食谱的先决条件如下：

+   Node.js 12+

所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

## 如何做...

要启动我们的组件，我们可以使用带有 Vue-CLI 的 Vue 项目，就像我们在第二章中的“使用 Vue CLI 创建您的第一个项目”食谱中所做的那样，*介绍 TypeScript 和 Vue 生态系统***，或者我们可以开始一个新的项目。

要启动一个新项目，打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows），并执行以下命令：

```js
> vue create visual-component
```

CLI 将询问一些问题，这些问题将有助于创建项目。您可以使用箭头键导航，*Enter*键继续，*空格键*选择选项。选择`default`选项：

```js
?  Please pick a preset: **(Use arrow keys)** ❯ default (babel, eslint) 
  Manually select features  ‌
```

现在，让我们按照这些步骤创建一个可视化模板组件：

1.  让我们在`src/components`文件夹中创建一个名为`MaterialCardBox.vue`的新文件。

1.  在这个文件中，我们将从组件的模板开始。我们需要为卡片创建一个框。通过使用 Material Design 指南，这个框将有阴影和圆角：

```js
<template>
 <div class="cardBox elevation_2">
 <div class="section">
 This is a Material Card Box
 </div>
 </div>
</template>
```

1.  在我们组件的`<script>`部分中，我们将只添加我们的基本名称：

```js
<script>
  export default {
   name: 'MaterialCardBox',
  };
</script>
```

1.  我们需要创建我们的高程 CSS 样式表规则。为此，请在`style`文件夹中创建一个名为`elevation.css`的文件。在那里，我们将创建从`0`到`24`的高程，以遵循 Material Design 指南上的所有高程：

```js
.elevation_0 {
    border: 1px solid rgba(0, 0, 0, 0.12);
}

.elevation_1 {
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.2),
        0 1px 1px rgba(0, 0, 0, 0.14),
        0 2px 1px -1px rgba(0, 0, 0, 0.12);
}

.elevation_2 {
    box-shadow: 0 1px 5px rgba(0, 0, 0, 0.2),
        0 2px 2px rgba(0, 0, 0, 0.14),
        0 3px 1px -2px rgba(0, 0, 0, 0.12);
}

.elevation_3 {
    box-shadow: 0 1px 8px rgba(0, 0, 0, 0.2),
        0 3px 4px rgba(0, 0, 0, 0.14),
        0 3px 3px -2px rgba(0, 0, 0, 0.12);
}

.elevation_4 {
    box-shadow: 0 2px 4px -1px rgba(0, 0, 0, 0.2),
        0 4px 5px rgba(0, 0, 0, 0.14),
        0 1px 10px rgba(0, 0, 0, 0.12);
}

.elevation_5 {
    box-shadow: 0 3px 5px -1px rgba(0, 0, 0, 0.2),
        0 5px 8px rgba(0, 0, 0, 0.14),
        0 1px 14px rgba(0, 0, 0, 0.12);
}

.elevation_6 {
    box-shadow: 0 3px 5px -1px rgba(0, 0, 0, 0.2),
        0 6px 10px rgba(0, 0, 0, 0.14),
        0 1px 18px rgba(0, 0, 0, 0.12);
}

.elevation_7 {
    box-shadow: 0 4px 5px -2px rgba(0, 0, 0, 0.2),
        0 7px 10px 1px rgba(0, 0, 0, 0.14),
        0 2px 16px 1px rgba(0, 0, 0, 0.12);
}

.elevation_8 {
    box-shadow: 0 5px 5px -3px rgba(0, 0, 0, 0.2),
        0 8px 10px 1px rgba(0, 0, 0, 0.14),
        0 3px 14px 2px rgba(0, 0, 0, 0.12);
}

.elevation_9 {
    box-shadow: 0 5px 6px -3px rgba(0, 0, 0, 0.2),
        0 9px 12px 1px rgba(0, 0, 0, 0.14),
        0 3px 16px 2px rgba(0, 0, 0, 0.12);
}

.elevation_10 {
    box-shadow: 0 6px 6px -3px rgba(0, 0, 0, 0.2),
        0 10px 14px 1px rgba(0, 0, 0, 0.14),
        0 4px 18px 3px rgba(0, 0, 0, 0.12);
}

.elevation_11 {
    box-shadow: 0 6px 7px -4px rgba(0, 0, 0, 0.2),
        0 11px 15px 1px rgba(0, 0, 0, 0.14),
        0 4px 20px 3px rgba(0, 0, 0, 0.12);
}

.elevation_12 {
    box-shadow: 0 7px 8px -4px rgba(0, 0, 0, 0.2),
        0 12px 17px 2px rgba(0, 0, 0, 0.14),
        0 5px 22px 4px rgba(0, 0, 0, 0.12);
}

.elevation_13 {
    box-shadow: 0 7px 8px -4px rgba(0, 0, 0, 0.2),
        0 13px 19px 2px rgba(0, 0, 0, 0.14),
        0 5px 24px 4px rgba(0, 0, 0, 0.12);
}

.elevation_14 {
    box-shadow: 0 7px 9px -4px rgba(0, 0, 0, 0.2),
        0 14px 21px 2px rgba(0, 0, 0, 0.14),
        0 5px 26px 4px rgba(0, 0, 0, 0.12);
}

.elevation_15 {
    box-shadow: 0 8px 9px -5px rgba(0, 0, 0, 0.2),
        0 15px 22px 2px rgba(0, 0, 0, 0.14),
        0 6px 28px 5px rgba(0, 0, 0, 0.12);
}

.elevation_16 {
    box-shadow: 0 8px 10px -5px rgba(0, 0, 0, 0.2),
        0 16px 24px 2px rgba(0, 0, 0, 0.14),
        0 6px 30px 5px rgba(0, 0, 0, 0.12);
}

.elevation_17 {
    box-shadow: 0 8px 11px -5px rgba(0, 0, 0, 0.2),
        0 17px 26px 2px rgba(0, 0, 0, 0.14),
        0 6px 32px 5px rgba(0, 0, 0, 0.12);
}

.elevation_18 {
    box-shadow: 0 9px 11px -5px rgba(0, 0, 0, 0.2),
        0 18px 28px 2px rgba(0, 0, 0, 0.14),
        0 7px 34px 6px rgba(0, 0, 0, 0.12);
}

.elevation_19 {
    box-shadow: 0 9px 12px -6px rgba(0, 0, 0, 0.2),
        0 19px 29px 2px rgba(0, 0, 0, 0.14),
        0 7px 36px 6px rgba(0, 0, 0, 0.12);
}

.elevation_20 {
    box-shadow: 0 10px 13px -6px rgba(0, 0, 0, 0.2),
        0 20px 31px 3px rgba(0, 0, 0, 0.14),
        0 8px 38px 7px rgba(0, 0, 0, 0.12);
}

.elevation_21 {
    box-shadow: 0 10px 13px -6px rgba(0, 0, 0, 0.2),
        0 21px 33px 3px rgba(0, 0, 0, 0.14),
        0 8px 40px 7px rgba(0, 0, 0, 0.12);
}

.elevation_22 {
    box-shadow: 0 10px 14px -6px rgba(0, 0, 0, 0.2),
        0 22px 35px 3px rgba(0, 0, 0, 0.14),
        0 8px 42px 7px rgba(0, 0, 0, 0.12);
}

.elevation_23 {
    box-shadow: 0 11px 14px -7px rgba(0, 0, 0, 0.2),
        0 23px 36px 3px rgba(0, 0, 0, 0.14),
        0 9px 44px 8px rgba(0, 0, 0, 0.12);
}

.elevation_24 {
    box-shadow: 0 11px 15px -7px rgba(0, 0, 0, 0.2),
        0 24px 38px 3px rgba(0, 0, 0, 0.14),
        0 9px 46px 8px rgba(0, 0, 0, 0.12);
}
```

1.  为了在组件的`<style>`部分中设置样式，我们需要在`<style>`标签内设置`scoped`属性，以确保视觉样式不会干扰应用程序中的任何其他组件。我们将使这张卡遵循 Material Design 指南。我们需要导入`Roboto`字体系列并将其应用于将包装在此组件内的所有元素：

```js
<style scoped>
  @import url('https://fonts.googleapis.com/css?family=Roboto:400,500,700&display=swap');
  @import '../style/elevation.css';

  *{
    font-family: 'Roboto', sans-serif;
  }
  .cardBox{
      width: 100%;
  max-width: 300px;
    background-color: #fff;
    position: relative;
    display: inline-block;
    border-radius: 0.25rem;
  }
  .cardBox > .section {
    padding: 1rem;
    position: relative;
  }
</style>
```

1.  要运行服务器并查看您的组件，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> npm run serve
```

这是您的组件呈现并运行的方式：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-cb/img/5f9be750-4b22-4898-a28a-c02bba7912d9.png)

## 它是如何工作的...

可视化组件是一个将包装任何组件并使用自定义样式放置包装数据的组件。由于此组件与其他组件混合，它可以形成一个新的组件，而无需在代码中重新应用或重写任何样式。

## 参见

您可以在[`vue-loader.vuejs.org/guide/scoped-css.html#child-component-root-elements`](https://vue-loader.vuejs.org/guide/scoped-css.html#child-component-root-elements)找到有关作用域 CSS 的更多信息。

您可以在[`material.io/components/cards/`](https://material.io/components/cards/)找到有关 Material Design 卡片的更多信息。

在[`fonts.google.com/specimen/Roboto`](https://fonts.google.com/specimen/Roboto)上查看 Roboto 字体系列。

# 使用插槽和命名插槽在组件中放置数据

有时候，拼图的一些部分会丢失，你会发现自己有一个空白的地方。想象一下，你可以用自己制作的一块填充那个空白的地方，而不是原来随拼图盒子一起的那块。这是 Vue 插槽的一个粗略类比。

Vue 插槽就像是组件中的开放空间，其他组件可以用文本、HTML 元素或其他 Vue 组件填充。您可以在组件中声明插槽的位置和行为方式。

使用这种技术，您可以创建一个组件，并在需要时轻松自定义它。

## 准备工作

这个配方的先决条件如下：

+   Node.js 12+

所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

## 如何做...

要开始我们的组件，我们可以像在第二章的*使用 Vue CLI 创建您的第一个项目*中那样使用 Vue-CLI 创建我们的 Vue 项目，或者使用*创建可视化模板组件*中的项目。

按照以下说明在组件中创建插槽和命名插槽：

1.  让我们打开组件文件夹中的名为`MaterialCardBox.vue`的文件。

1.  在组件的`<template>`部分，我们需要在卡片上添加四个主要部分。这些部分基于 Material Design 卡片解剖学，分别是`header`、`media`、`main section`和`action`区域。我们将使用默认插槽来放置`main section`，其余部分都将是命名作用域。对于一些命名插槽，我们将添加一个备用配置，如果用户没有在插槽上选择任何设置，将显示该配置：

```js
<template>
  <div class="cardBox elevation_2">
    <div class="header">
      <slot
        v-if="$slots.header"
        name="header"
      />
      <div v-else>
        <h1 class="cardHeader cardText">
          Card Header
        </h1>
        <h2 class="cardSubHeader cardText">
          Card Sub Header
        </h2>
      </div>
    </div>
    <div class="media">
      <slot
        v-if="$slots.media"
        name="media"
      />
      <img
        v-else
        src="https://via.placeholder.com/350x250"
      >
    </div>
    <div
      v-if="$slots.default"
      class="section cardText"
      :class="{
        noBottomPadding: $slots.action,
        halfPaddingTop: $slots.media,
      }"
    >
      <slot />
    </div>
    <div
      v-if="$slots.action"
      class="action"
    >
      <slot name="action" />
    </div>
  </div>
</template>
```

1.  现在，我们需要为组件创建文本 CSS 样式表规则。在`style`文件夹中，创建一个名为`cardStyles.css`的新文件，在那里我们将添加卡片文本和标题的规则：

```js
h1, h2, h3, h4, h5, h6{
    margin: 0;
}
.cardText{
    -moz-osx-font-smoothing: grayscale;
    -webkit-font-smoothing: antialiased;
    text-decoration: inherit;
    text-transform: inherit;
    font-size: 0.875rem;
    line-height: 1.375rem;
    letter-spacing: 0.0071428571em;
}
h1.cardHeader{
    font-size: 1.25rem;
    line-height: 2rem;
    font-weight: 500;
    letter-spacing: .0125em;
}
h2.cardSubHeader{
    font-size: .875rem;
    line-height: 1.25rem;
    font-weight: 400;
    letter-spacing: .0178571429em;
    opacity: .6;
}
```

1.  在组件的`<style>`部分，我们需要创建一些 CSS 样式表来遵循我们的设计指南的规则：

```js
<style scoped>
@import url("https://fonts.googleapis.com/css?family=Roboto:400,500,700&display=swap");
@import "../style/elevation.css";
@import "../style/cardStyles.css";

* {
  font-family: "Roboto", sans-serif;
}

.cardBox {
  width: 100%;
  max-width: 300px;
  border-radius: 0.25rem;
  background-color: #fff;
  position: relative;
  display: inline-block;
  box-shadow: 0 1px 5px rgba(0, 0, 0, 0.2), 0 2px 2px rgba(0, 0, 0, 0.14),
    0 3px 1px -2px rgba(0, 0, 0, 0.12);
}
.cardBox > .header {
  padding: 1rem;
  position: relative;
  display: block;
}
.cardBox > .media {
  overflow: hidden;
  position: relative;
  display: block;
  max-width: 100%;
}
.cardBox > .section {
  padding: 1rem;
  position: relative;
  margin-bottom: 1.5rem;
  display: block;
}
.cardBox > .action {
  padding: 0.5rem;
  position: relative;
  display: block;
}
.cardBox > .action > *:not(:first-child) {
  margin-left: 0.4rem;
}
.noBottomPadding {
  padding-bottom: 0 !important;
}
.halfPaddingTop {
  padding-top: 0.5rem !important;
}
</style>
```

1.  在`src`文件夹中的`App.vue`文件中，我们需要向这些插槽添加元素。这些元素将被添加到每个命名插槽和默认插槽中。我们将更改文件的`<template>`部分中的组件。要添加命名插槽，我们需要使用一个名为`v-slot:`的指令，然后是我们想要使用的插槽的名称：

```js
<template>
  <div id="app">
    <MaterialCardBox>
      <template v-slot:header>
        <strong>Card Title</strong><br>
        <span>Card Sub-Title</span>
      </template>
      <template v-slot:media>
        <img src="https://via.placeholder.com/350x150">
      </template>
      <p>Main Section</p>
      <template v-slot:action>
        <button>Action Button</button>
        <button>Action Button</button>
      </template>
    </MaterialCardBox>
  </div>
</template>
```

对于默认插槽，我们不需要使用指令；它只需要包装在组件中，以放置在组件的`<slot />`部分中。

1.  要运行服务器并查看您的组件，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> npm run serve
```

这是您的组件渲染并运行的方式：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-cb/img/82443046-abca-438a-9a1a-0be3390fecda.png)

## 它是如何工作的...

插槽是可以放置任何可以呈现到 DOM 中的地方。我们选择插槽的位置，并告诉组件在接收到任何信息时在何处呈现。

在这个教程中，我们使用了命名插槽，它们旨在与需要多个插槽的组件一起使用。要在 Vue 单文件（`.vue`）的`<template>`部分中向该组件放置任何信息，您需要添加`v-slot:`指令，以便 Vue 能够知道在何处放置传递下来的信息。

## 另请参阅

您可以在[`vuejs.org/v2/guide/components-slots.html`](https://vuejs.org/v2/guide/components-slots.html)找到有关 Vue 插槽的更多信息。

您可以在[`material.io/components/cards/#anatomy`](https://material.io/components/cards/#anatomy)找到有关 Material Design 卡片解剖的更多信息。

# 向您的组件传递数据并验证数据

您现在知道如何通过插槽将数据放入组件中，但这些插槽是为 HTML DOM 元素或 Vue 组件而设计的。有时，您需要传递诸如字符串、数组、布尔值甚至对象之类的数据。

整个应用程序就像一个拼图，其中每个部分都是一个组件。组件之间的通信是其中的重要部分。向组件传递数据的可能性是连接拼图的第一步，然后验证数据是连接这些部分的最后一步。

在这个教程中，我们将学习如何向组件传递数据并验证传递给组件的数据。

## 准备工作

先决条件如下：

+   Node.js 12+

Node.js 所需的全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

## 如何做...

要启动我们的组件，我们可以像在第二章“介绍 TypeScript 和 Vue 生态系统”中的*使用 Vue CLI 创建您的第一个项目*食谱中那样，使用 Vue-CLI 创建我们的 Vue 项目，或者使用*使用插槽和命名插槽将数据放入组件*食谱中的项目。

按照这些说明将数据传递给组件并进行验证：

1.  让我们在`src/components`文件夹中打开名为`MaterialCardBox.vue`的文件。

1.  在组件的`<script>`部分，我们创建一个名为`props`的新属性。该属性接收组件数据，该数据可以用于视觉操作、代码内的变量或需要执行的函数。在此属性中，我们需要声明属性的名称、类型、是否必需以及验证函数。此函数将在运行时执行，以验证传递的属性是否有效：

```js
<script>
export default {
  name: 'MaterialCardBox',
  inheritAttrs: false,
  props: {
    header: {
      type: String,
      required: false,
      default: '',
      validator: v => typeof v === 'string',
    },
    subHeader: {
      type: String,
      required: false,
      default: '',
      validator: v => typeof v === 'string',
    },
    mainText: {
      type: String,
      required: false,
      default: '',
      validator: v => typeof v === 'string',
    },
    showMedia: {
      type: Boolean,
      required: false,
      default: false,
      validator: v => typeof v === 'boolean',
    },
    imgSrc: {
      type: String,
      required: false,
      default: '',
      validator: v => typeof v === 'string',
    },
    showActions: {
      type: Boolean,
      required: false,
      default: false,
      validator: v => typeof v === 'boolean',
    },
    elevation: {
      type: Number,
      required: false,
      default: 2,
      validator: v => typeof v === 'number',
    },
  },
  computed: {},
};
</script>
```

1.  在组件的`<script>`部分的`computed`属性中，我们需要创建一组用于呈现卡片的视觉操作规则。这些规则将是`showMediaContent`、`showActionsButtons`、`showHeader`和`cardElevation`。每个规则将检查接收到的`props`和`$slots`对象，以查看是否需要呈现相关的卡片部分：

```js
  computed: {
    showMediaContent() {
      return (this.$slots.media || this.imgSrc) && this.showMedia;
    },
    showActionsButtons() {
      return this.showActions && this.$slots.action;
    },
    showHeader() {
      return this.$slots.header || (this.header || this.subHeader);
    },
    showMainContent() {
      return this.$slots.default || this.mainText;
    },
    cardElevation() {
      return `elevation_${parseInt(this.elevation, 10)}`;
    },
  },
```

1.  在添加了视觉操作规则之后，我们需要将创建的规则添加到组件的`<template>`部分。它们将影响我们卡片的外观和行为。例如，如果没有定义头部插槽，并且定义了头部属性，我们将显示备用头部。该头部是通过`props`传递下来的数据：

```js
<template>
  <div
    class="cardBox"
    :class="cardElevation"
  >
    <div
      v-if="showHeader"
      class="header"
    >
      <slot
        v-if="$slots.header"
        name="header"
      />
      <div v-else>
        <h1 class="cardHeader cardText">
          {{ header }}
        </h1>
        <h2 class="cardSubHeader cardText">
          {{ subHeader }}
        </h2>
      </div>
    </div>
    <div
      v-if="showMediaContent"
      class="media"
    >
      <slot
        v-if="$slots.media"
        name="media"
      />
      <img
        v-else
        :src="imgSrc"
      >
    </div>
    <div
      v-if="showMainContent"
      class="section cardText"
      :class="{
        noBottomPadding: $slots.action,
        halfPaddingTop: $slots.media,
      }"
    >
      <slot v-if="$slots.default" />
      <p
        v-else
        class="cardText"
      >
        {{ mainText }}
      </p>
    </div>
    <div
      v-if="showActionsButtons"
      class="action"
    >
      <slot
        v-if="$slots.action"
        name="action"
      />
    </div>
  </div>
</template>
```

1.  要运行服务器并查看您的组件，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> npm run serve
```

这是您的组件呈现并运行：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-cb/img/ab464f57-6b57-4caa-b845-afec0d64684c.png)

## 工作原理...

每个 Vue 组件都是一个具有渲染函数的 JavaScript 对象。当需要在 HTML DOM 中呈现它时，将调用此渲染函数。单文件组件是该对象的抽象。

当我们声明我们的组件具有可以传递的唯一 props 时，它为其他组件或 JavaScript 打开了一个小门，以便将信息放入我们的组件中。然后，我们可以在组件内使用这些值来渲染数据，进行一些计算或制定可视规则。

在我们的情况下，使用单文件组件，我们将这些规则作为 HTML 属性传递，因为 `vue-template-compiler` 将获取这些属性并将它们转换为 JavaScript 对象。

当这些值传递给我们的组件时，Vue 首先检查传递的属性是否与正确的类型匹配，然后我们在每个值上执行我们的验证函数，以查看它是否与我们期望的匹配。

完成所有这些后，组件的生命周期将继续，我们可以渲染我们的组件。

## 另请参阅

您可以在 [`vuejs.org/v2/guide/components-props.html`](https://vuejs.org/v2/guide/components-props.html) 找到有关 `props` 的更多信息。

您可以在 [`vue-loader.vuejs.org/guide/`](https://vue-loader.vuejs.org/guide/) 找到有关 `vue-template-compiler` 的更多信息。

# 创建功能组件

功能组件的美妙之处在于它们的简单性。它们是无状态组件，没有任何数据、计算属性，甚至没有生命周期。它们只是在传递的数据发生变化时调用的渲染函数。

您可能想知道这有什么用。嗯，功能组件是 UI 组件的完美伴侣，这些组件不需要在内部保留任何数据，或者只是渲染组件，不需要任何数据操作的可视组件。

顾名思义，它们是简单的函数组件，除了渲染函数外没有其他内容。它们是组件的精简版本，专门用于性能渲染和可视元素。

## 准备工作

先决条件如下：

+   Node.js 12+

所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

## 如何做...

要启动我们的组件，请使用 Vue-CLI 创建您的 Vue 项目，就像我们在第二章“引入 TypeScript 和 Vue 生态系统”中的食谱“*使用 Vue CLI 创建您的第一个项目*”中所做的那样，或者使用“将数据传递给您的组件并验证数据”的食谱中的项目。

现在，按照以下说明创建一个 Vue 功能组件：

1.  在`src/components`文件夹中创建一个名为`MaterialButton.vue`的新文件。

1.  在这个组件中，我们需要验证我们将接收的 prop 是否是有效的颜色。为此，在项目中安装`is-color`模块。您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> npm install --save is-color
```

1.  在我们组件的`<script>`部分，我们需要创建功能组件将接收的`props`对象。由于功能组件只是一个没有状态的渲染函数，`<script>`部分被简化为`props`、`injections`和`slots`。将有四个`props`对象：`backgroundColor`、`textColor`、`isRound`和`isFlat`。在安装组件时，这些不是必需的，因为我们在`props`中定义了默认值：

```js
<script>
  import isColor from 'is-color';

  export default {
    name: 'MaterialButton',
    props: {
      backgroundColor: {
        type: String,
        required: false,
        default: '#fff',
        validator: v => typeof v === 'string' && isColor(v),
      },
      textColor: {
        type: String,
        required: false,
        default: '#000',
        validator: v => typeof v === 'string' && isColor(v),
      },
      isRound: {
        type: Boolean,
        required: false,
        default: false,
      },
      isFlat: {
        type: Boolean,
        required: false,
        default: false,
      },
    },
  };
</script>
```

1.  在我们组件的`<template>`部分，我们首先需要向`<template>`标签添加`functional`属性，以指示`vue-template-compiler`这个组件是一个功能组件。我们需要创建一个按钮 HTML 元素，带有基本的`class`属性按钮和一个基于`props`对象接收的动态`class`属性。与普通组件不同，我们需要指定`props`属性以使用功能组件。对于按钮的样式，我们需要创建一个基于`props`的动态`style`属性。为了直接将所有事件监听器传递给父组件，我们可以调用`v-on`指令并传递`listeners`属性。这将绑定所有事件监听器，而无需声明每一个。在按钮内部，我们将添加一个用于视觉增强的`div` HTML 元素，并添加`<slot>`，文本将放置在其中：

```js
<template functional>
  <button
    tabindex="0"
    class="button"
    :class="{
      round: props.isRound,
      isFlat: props.isFlat,
    }"
    :style="{
      background: props.backgroundColor,
      color: props.textColor
    }"
    v-on="listeners"
  >
    <div
      tabindex="-1"
      class="button_focus_helper"
    />
    <slot/>
  </button>
</template>
```

1.  现在，让我们把它弄得漂亮一点。在组件的`<style>`部分，我们需要为这个按钮创建所有的 CSS 样式表规则。我们需要向`<style>`添加`scoped`属性，以便所有的 CSS 样式表规则不会影响我们应用程序中的任何其他元素：

```js
<style scoped>
  .button {
    user-select: none;
    position: relative;
    outline: 0;
    border: 0;
    border-radius: 0.25rem;
    vertical-align: middle;
    cursor: pointer;
    padding: 4px 16px;
    font-size: 14px;
    line-height: 1.718em;
    text-decoration: none;
    color: inherit;
    background: transparent;
    transition: 0.3s cubic-bezier(0.25, 0.8, 0.5, 1);
    min-height: 2.572em;
    font-weight: 500;
    text-transform: uppercase;
  }
  .button:not(.isFlat){
    box-shadow: 0 1px 5px rgba(0, 0, 0, 0.2),
    0 2px 2px rgba(0, 0, 0, 0.14),
    0 3px 1px -2px rgba(0, 0, 0, 0.12);
  }

  .button:not(.isFlat):focus:before,
  .button:not(.isFlat):active:before,
  .button:not(.isFlat):hover:before {
    content: '';
    position: absolute;
    top: 0;
    right: 0;
    bottom: 0;
    left: 0;
    border-radius: inherit;
    transition: 0.3s cubic-bezier(0.25, 0.8, 0.5, 1);
  }

  .button:not(.isFlat):focus:before,
  .button:not(.isFlat):active:before,
  .button:not(.isFlat):hover:before {
    box-shadow: 0 3px 5px -1px rgba(0, 0, 0, 0.2),
    0 5px 8px rgba(0, 0, 0, 0.14),
    0 1px 14px rgba(0, 0, 0, 0.12);
  }

  .button_focus_helper {
    position: absolute;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    pointer-events: none;
    border-radius: inherit;
    outline: 0;
    opacity: 0;
    transition: background-color 0.3s cubic-bezier(0.25, 0.8, 0.5, 1),
    opacity 0.4s cubic-bezier(0.25, 0.8, 0.5, 1);
  }

  .button_focus_helper:after, .button_focus_helper:before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    opacity: 0;
    border-radius: inherit;
    transition: background-color 0.3s cubic-bezier(0.25, 0.8, 0.5, 1),
    opacity 0.6s cubic-bezier(0.25, 0.8, 0.5, 1);
  }

  .button_focus_helper:before {
    background: #000;
  }

  .button_focus_helper:after {
    background: #fff;
  }

  .button:focus .button_focus_helper:before,
  .button:hover .button_focus_helper:before {
    opacity: .1;
  }

  .button:focus .button_focus_helper:after,
  .button:hover .button_focus_helper:after {
    opacity: .6;
  }

  .button:focus .button_focus_helper,
  .button:hover .button_focus_helper {
    opacity: 0.2;
  }

  .round {
    border-radius: 50%;
  }
</style>
```

1.  运行服务器并查看您的组件，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> npm run serve
```

这是您的组件渲染并运行的地方：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-cb/img/da07bacd-c897-42be-9dc2-536e8ae144c6.png)

## 它是如何工作的...

功能组件就像一个渲染函数一样简单。它们没有任何类型的数据、函数或者对外部世界的访问。

它们最初作为 JavaScript 对象`render()`函数在 Vue 中引入；后来，它们被添加到了`vue-template-compiler`中，用于 Vue 单文件应用程序。

功能组件通过接收两个参数来工作：`createElement`和`context`。正如我们在单文件中看到的，我们只能访问元素，因为它们不在 JavaScript 对象的`this`属性中。这是因为当上下文传递给渲染函数时，就没有`this`属性。

功能组件在 Vue 上提供了最快的渲染速度，因为它不依赖于组件的生命周期来检查渲染；它只是在数据更改时每次渲染。

## 另请参阅

您可以在[`vuejs.org/v2/guide/render-function.html#Functional-Components`](https://vuejs.org/v2/guide/render-function.html#Functional-Components)找到有关功能组件的更多信息。

您可以在[`www.npmjs.com/package/is-color`](https://www.npmjs.com/package/is-color)找到有关`is-color`模块的更多信息。

# 访问您的子组件数据

通常，父子通信是通过事件或 props 来完成的。但有时，您需要访问存在于子组件或父组件函数中的数据、函数或计算属性。

Vue 提供了一种双向交互的方式，打开了通信和事件的大门，例如 props 和事件监听器。

还有另一种访问组件之间数据的方式：通过直接访问。这可以通过在单文件组件中使用模板时使用特殊属性，或者在 JavaScript 中直接调用对象来完成。这种方法被一些人认为有点懒惰，但有时确实没有其他方法可以做到这一点。

## 准备工作

先决条件如下：

+   Node.js 12+

所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

## 如何做...

要启动您的组件，请使用 Vue-CLI 创建您的 Vue 项目，就像我们在第二章的'*使用 Vue CLI 创建您的第一个项目*'食谱中所做的那样，*介绍 TypeScript 和 Vue 生态系统*，或者使用'*创建功能组件*'食谱中的项目。

我们将把这个教程分成四个部分。前三部分将涵盖新组件的创建——`StarRatingInput`、`StarRatingDisplay`和`StarRating`——最后一部分将涵盖数据和函数访问的父子直接操作。

### 创建星级评分输入

我们将创建一个基于五星级评分系统的星级评分输入。

按照以下步骤创建自定义星级评分输入：

1.  在`src/components`文件夹中创建一个名为`StarRatingInput.vue`的新文件。

1.  在组件的`<script>`部分，在`props`属性中创建一个`maxRating`属性，它是一个数字，非必需，并且默认值为`5`。在`data`属性中，我们需要创建我们的`rating`属性，其默认值为`0`。在`methods`属性中，我们需要创建三个方法：`updateRating`、`emitFinalVoting`和`getStarName`。`updateRating`方法将保存评分到数据中，`emitFinalVoting`将调用`updateRating`并通过`final-vote`事件将评分传递给父组件，`getStarName`将接收一个值并返回星级的图标名称。

```js
<script>
export default {
  name: 'StarRatingInput',
  props: {
    maxRating: {
      type: Number,
      required: false,
      default: 5,
    },
  },
  data: () => ({
    rating: 0,
  }),
  methods: {
    updateRating(value) {
      this.rating = value;
    },
    emitFinalVote(value) {
      this.updateRating(value);
      this.$emit('final-vote', this.rating);
    },
    getStarName(rate) {
      if (rate <= this.rating) {
        return 'star';
      }
      if (Math.fround((rate - this.rating)) < 1) {
        return 'star_half';
      }
      return 'star_border';
    },
  },
};
</script>
```

1.  在组件的`<template>`部分，我们需要创建一个`<slot>`组件来放置星级评分之前的文本。我们将根据通过`props`属性接收到的`maxRating`值创建一个动态星级列表。创建的每个星级都将在`mouseenter`、`focus`和`click`事件上附加一个监听器。当触发`mouseenter`和`focus`时，将调用`updateRating`方法，而`click`将调用`emitFinalVote`方法。

```js
<template>
  <div class="starRating">
    <span class="rateThis">
      <slot />
    </span>
    <ul>
      <li
        v-for="rate in maxRating"
        :key="rate"
        @mouseenter="updateRating(rate)"
        @click="emitFinalVote(rate)"
        @focus="updateRating(rate)"
      >
        <i class="material-icons">
          {{ getStarName(rate) }}
        </i>
      </li>
    </ul>
  </div>
</template>
```

1.  我们需要将 Material Design 图标导入我们的应用程序。在`styles`文件夹中创建一个名为`materialIcons.css`的新样式文件，并添加`font-family`的 CSS 样式规则。

```js
@font-face {
  font-family: 'Material Icons';
  font-style: normal;
  font-weight: 400;
  src: url(https://fonts.gstatic.com/s/materialicons/v48/flUhRq6tzZclQEJ-
      Vdg-IuiaDsNcIhQ8tQ.woff2) format('woff2');
}

.material-icons {
  font-family: 'Material Icons' !important;
  font-weight: normal;
  font-style: normal;
  font-size: 24px;
  line-height: 1;
  letter-spacing: normal;
  text-transform: none;
  display: inline-block;
  white-space: nowrap;
  word-wrap: normal;
  direction: ltr;
  -webkit-font-feature-settings: 'liga';
  -webkit-font-smoothing: antialiased;
}
```

1.  打开`main.js`文件，并将创建的样式表导入其中。`css-loader`将处理 JavaScript 文件中导入的`.css`文件的处理。这将有助于开发，因为您不需要在其他地方重新导入文件。

```js
import Vue from 'vue';
import App from './App.vue';
import './style/materialIcons.css';

Vue.config.productionTip = false;

new Vue({
  render: h => h(App),
}).$mount('#app');
```

1.  为了给我们的组件添加样式，我们将在`src/style`文件夹中创建一个名为`starRating.css`的通用样式文件。在那里，我们将添加`StarRatingDisplay`和`StarRatingInput`组件之间共享的通用样式。

```js
.starRating {
  user-select: none;
  display: flex;
  flex-direction: row;
}
.starRating * {
  line-height: 0.9rem;
}
.starRating .material-icons {
  font-size: .9rem !important;
  color: orange;
}

ul {
  display: inline-block;
  padding: 0;
  margin: 0;
}

ul > li {
  list-style: none;
  float: left;
}
```

1.  在组件的`<style>`部分，我们需要创建所有的 CSS 样式表规则。然后，在位于`src/components`文件夹中的`StarRatingInput.vue`组件文件上，我们需要向`<style>`添加`scoped`属性，以便所有的 CSS 样式表规则不会影响应用程序中的任何其他元素。在这里，我们将导入我们创建的通用样式，并为输入添加新样式：

```js
<style scoped>
  @import '../style/starRating.css';

  .starRating {
    justify-content: space-between;
  }

  .starRating * {
    line-height: 1.7rem;
  }

  .starRating .material-icons {
    font-size: 1.6rem !important;
  }

  .rateThis {
    display: inline-block;
    color: rgba(0, 0, 0, .65);
    font-size: 1rem;
  }
</style>
```

1.  要运行服务器并查看您的组件，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> npm run serve
```

这是您的组件呈现并运行的样子：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-cb/img/18715858-a5b0-4fa7-97db-d68268fd190d.png)

### 创建 StarRatingDisplay 组件

现在我们有了输入，我们需要一种方法来向用户显示所选的选择。按照以下步骤创建`StarRatingDisplay`组件：

1.  在`src/components`文件夹中创建一个名为`StarRatingDisplay.vue`的新组件。

1.  在组件的`<script>`部分，在`props`属性中，我们需要创建三个新属性：`maxRating`，`rating`和`votes`。它们三个都将是数字，非必需的，并且有默认值。在`methods`属性中，我们需要创建一个名为`getStarName`的新方法，它将接收一个值并返回星星的图标名称：

```js
<script>
export default {
  name: 'StarRatingDisplay',
  props: {
    maxRating: {
      type: Number,
      required: false,
      default: 5,
    },
    rating: {
      type: Number,
      required: false,
      default: 0,
    },
    votes: {
      type: Number,
      required: false,
      default: 0,
    },
  },
  methods: {
    getStarName(rate) {
      if (rate <= this.rating) {
        return 'star';
      }
      if (Math.fround((rate - this.rating)) < 1) {
        return 'star_half';
      }
      return 'star_border';
    },
  },
};
</script>
```

1.  在`<template>`中，我们需要根据通过`props`属性接收到的`maxRating`值创建一个动态星星列表。在列表之后，我们需要显示我们收到的投票数，如果我们收到任何投票，我们也会显示它们：

```js
<template>
  <div class="starRating">
    <ul>
      <li
        v-for="rate in maxRating"
        :key="rate"
      >
        <i class="material-icons">
          {{ getStarName(rate) }}
        </i>
      </li>
    </ul>
    <span class="rating">
      {{ rating }}
    </span>
    <span
      v-if="votes"
      class="votes"
    >
      ({{ votes }})
    </span>
  </div>
</template>
```

1.  在组件的`<style>`部分，我们需要创建所有的 CSS 样式表规则。我们需要向`<style>`添加`scoped`属性，以便所有的 CSS 样式表规则不会影响应用程序中的任何其他元素。在这里，我们将导入我们创建的通用样式，并为显示添加新样式：

```js
<style scoped>
  @import '../style/starRating.css';

  .rating, .votes {
    display: inline-block;
    color: rgba(0,0,0, .65);
    font-size: .75rem;
    margin-left: .4rem;
  }
</style>
```

1.  要运行服务器并查看您的组件，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> npm run serve
```

这是您的组件呈现并运行的样子：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-cb/img/b65b034f-a304-4975-8858-2bd46e378bce.png)

### 创建 StarRating 组件

创建输入和显示后，我们需要将两者合并到一个单独的组件中。这个组件将是我们在应用程序中使用的最终组件。

按照以下步骤创建最终的`StarRating`组件：

1.  在`src/components`文件夹中创建一个名为`StarRating.vue`的新文件。

1.  在组件的`<script>`部分，我们需要导入`StarRatingDisplay`和`StarRatingInput`组件。在`props`属性中，我们需要创建三个新属性：`maxRating`，`rating`和`votes`。它们三个都将是数字，非必需的，并且有一个默认值。在`data`属性中，我们需要创建我们的`rating`属性，其默认值为`0`，并且一个名为`voted`的属性，其默认值为`false`。在`methods`属性中，我们需要添加一个名为`vote`的新方法，它将接收`rank`作为参数。它将把`rating`定义为接收到的值，并将`voted`组件的内部变量定义为`true`：

```js
<script>
import StarRatingInput from './StarRatingInput.vue';
import StarRatingDisplay from './StarRatingDisplay.vue';

export default {
  name: 'StarRating',
  components: { StarRatingDisplay, StarRatingInput },
  props: {
    maxRating: {
      type: Number,
      required: false,
      default: 5,
    },
    rating: {
      type: Number,
      required: false,
      default: 0,
    },
    votes: {
      type: Number,
      required: false,
      default: 0,
    },
  },
  data: () => ({
    rank: 0,
    voted: false,
  }),
  methods: {
    vote(rank) {
      this.rank = rank;
      this.voted = true;
    },
  },
};
</script>
```

1.  在`<template>`部分，我们将放置两个组件，显示评分的输入：

```js
<template>
  <div>
    <StarRatingInput
      v-if="!voted"
      :max-rating="maxRating"
      @final-vote="vote"
    >
      Rate this Place
    </StarRatingInput>
    <StarRatingDisplay
      v-else
      :max-rating="maxRating"
      :rating="rating || rank"
      :votes="votes"
    />
  </div>
</template>
```

### 子组件上的数据操作

现在我们所有的组件都准备好了，我们需要将它们添加到我们的应用程序中。基本应用程序将访问子组件，并将评分设置为 5 星。

现在，按照以下步骤来理解和操作子组件中的数据：

1.  在`App.vue`文件中，在组件的`<template>`部分，删除`MaterialCardBox`组件的`main-text`属性，并将其放置为组件的默认插槽。

1.  在放置的文本之前，我们将添加`StarRating`组件。我们将为其添加一个`ref`属性。此属性将指示 Vue 将此组件直接链接到组件的`this`对象中的一个特殊属性。在操作按钮中，我们将为点击事件添加监听器——一个用于`resetVote`，另一个用于`forceVote`。

```js
<template>
  <div id="app">
    <MaterialCardBox
      header="Material Card Header"
      sub-header="Card Sub Header"
      show-media
      show-actions
      img-src="https://picsum.photos/300/200"
    >
      <p>
        <StarRating
          ref="starRating"
        />
      </p>
      <p>
        The path of the righteous man is beset on all sides by the 
           iniquities of the selfish and the tyranny of evil men.
      </p>
      <template v-slot:action>
        <MaterialButton
          background-color="#027be3"
          text-color="#fff"
          @click="resetVote"
        >
          Reset
        </MaterialButton>
        <MaterialButton
          background-color="#26a69a"
          text-color="#fff"
          is-flat
          @click="forceVote"
        >
          Rate 5 Stars
        </MaterialButton>
      </template>
    </MaterialCardBox>
  </div>
</template>
```

1.  在组件的`<script>`部分，我们将创建一个`methods`属性，并添加两个新方法：`resetVote`和`forceVote`。这些方法将访问`StarRating`组件并重置数据或将数据设置为 5 星投票：

```js
<script>
import MaterialCardBox from './components/MaterialCardBox.vue';
import MaterialButton from './components/MaterialButton.vue';
import StarRating from './components/StarRating.vue';

export default {
  name: 'App',
  components: {
    StarRating,
    MaterialButton,
    MaterialCardBox,
  },
  methods: {
    resetVote() {
      this.$refs.starRating.rank = 0;
      this.$refs.starRating.voted = false;
    },
    forceVote() {
      this.$refs.starRating.rank = 5;
      this.$refs.starRating.voted = true;
    },
  },
};
</script>
```

## 它是如何工作的...

当`ref`属性添加到组件时，Vue 会将对所引用元素的链接添加到 JavaScript 的`this`属性对象内的`$refs`属性中。从那里，您可以完全访问组件。

这种方法通常用于操作 HTML DOM 元素，而无需调用文档查询选择器函数。

然而，此属性的主要功能是直接访问 Vue 组件，使您能够执行函数并查看组件的计算属性、变量和更改的变量，就像从外部完全访问组件一样。

## 还有更多...

与父组件可以访问子组件的方式相同，子组件可以通过在`this`对象上调用`$parent`来访问父组件。事件可以通过调用`$root`属性来访问 Vue 应用程序的根元素。

## 另请参阅

您可以在[`vuejs.org/v2/guide/components-edge-cases.html#Accessing-the-Parent-Component-Instance`](https://vuejs.org/v2/guide/components-edge-cases.html#Accessing-the-Parent-Component-Instance)找到有关父子通信的更多信息。

# 创建动态注入组件

有些情况下，您的组件可以由您收到的变量类型或数据类型来定义；然后，您需要在不需要设置大量 Vue `v-if`、`v-else-if`和`v-else`指令的情况下即时更改组件。

在这些情况下，最好的做法是使用动态组件，当计算属性或函数可以定义要呈现的组件时，并且决定是实时进行的。

如果有两个响应，这些决策有时可能很简单，但在长的 switch case 中可能会更复杂，其中可能有一长串可能要使用的组件。

## 准备工作

先决条件如下：

+   Node.js 12+

所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   ``@vue/cli-service-global``

## 如何做...

要启动我们的组件，我们可以使用 Vue-CLI 创建我们的 Vue 项目，就像我们在第二章中的'*使用 Vue CLI 创建您的第一个项目*'配方中所做的那样，*介绍 TypeScript 和 Vue 生态系统*，或者使用'*访问您的子组件数据*'配方中的项目。

按照以下步骤创建动态注入组件：

1.  打开`StarRating.vue`组件。

1.  在组件的`<script>`部分，我们需要创建一个带有名为`starComponent`的新计算值的`computed`属性。此值将检查用户是否已投票。如果他们没有，它将返回`StarRatingInput`组件；否则，它将返回`StarRatingDisplay`组件：

```js
<script>
import StarRatingInput from './StarRatingInput.vue';
import StarRatingDisplay from './StarRatingDisplay.vue';

export default {
  name: 'StarRating',
  components: { StarRatingDisplay, StarRatingInput },
  props: {
    maxRating: {
      type: Number,
      required: false,
      default: 5,
    },
    rating: {
      type: Number,
      required: false,
      default: 0,
    },
    votes: {
      type: Number,
      required: false,
      default: 0,
    },
  },
  data: () => ({
    rank: 0,
    voted: false,
  }),
  computed: {
    starComponent() {
      if (!this.voted) return StarRatingInput;
      return StarRatingDisplay;
    },
  },
  methods: {
    vote(rank) {
      this.rank = rank;
      this.voted = true;
    },
  },
};
</script>
```

1.  在组件的`<template>`部分，我们将删除现有组件，并用一个名为`<component>`的特殊组件替换它们。这个特殊组件有一个命名属性，您可以指向任何返回有效 Vue 组件的地方。在我们的例子中，我们将指向计算属性`starComponent`。我们将把从这两个组件中定义的所有绑定 props 放在这个新组件中，包括放在`<slot>`中的文本：

```js
<template>
  <component
    :is="starComponent"
    :max-rating="maxRating"
    :rating="rating || rank"
    :votes="votes"
    @final-vote="vote"
  >
    Rate this Place
  </component>
</template>
```

## 工作原理...

使用 Vue 特殊的`<component>`组件，我们声明了根据计算属性设置的规则应该呈现什么组件。

作为通用组件，您总是需要确保每个可以呈现的组件都存在。最好的方法是使用`v-bind`指令与需要定义的 props 和规则，但也可以直接在组件上定义，因为它将作为 prop 传递下去。

## 另请参阅

您可以在[`vuejs.org/v2/guide/components.html#Dynamic-Components`](https://vuejs.org/v2/guide/components.html#Dynamic-Components)找到有关动态组件的更多信息。

# 创建依赖注入组件

直接从子组件或父组件访问数据而不知道它们是否存在可能非常危险。

在 Vue 中，可以使您的组件的行为像一个接口，并拥有一个在开发过程中不会改变的常见和抽象函数。依赖注入的过程是开发世界中的一个常见范例，并且也已经在 Vue 中实现。

使用内部 Vue 依赖注入有一些利弊，但在开发时，确保子组件知道父组件的期望总是一个好方法。

## 准备工作

先决条件如下：

+   Node.js 12+

所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

## 如何做...

要启动我们的组件，我们可以像在第二章中的“使用 Vue CLI 创建您的第一个项目”中那样使用 Vue-CLI 创建我们的 Vue 项目，或者使用“创建动态注入组件”中的项目。

现在，按照以下步骤创建一个依赖注入组件：

1.  打开`StarRating.vue`组件。

1.  在组件的`<script>`部分，添加一个名为`provide`的新属性。在我们的情况下，我们将只添加一个键值来检查组件是否是特定组件的子级。在属性中创建一个对象，其中包含`starRating`键和`true`值：

```js
<script>
import StarRatingInput from './StarRatingInput.vue';
import StarRatingDisplay from './StarRatingDisplay.vue';

export default {
  name: 'StarRating',
  components: { StarRatingDisplay, StarRatingInput },
  provide: {
    starRating: true,
  },
  props: {
    maxRating: {
      type: Number,
      required: false,
      default: 5,
    },
    rating: {
      type: Number,
      required: false,
      default: 0,
    },
    votes: {
      type: Number,
      required: false,
      default: 0,
    },
  },
  data: () => ({
    rank: 0,
    voted: false,
  }),
  computed: {
    starComponent() {
      if (!this.voted) return StarRatingInput;
      return StarRatingDisplay;
    },
  },
  methods: {
    vote(rank) {
      this.rank = rank;
      this.voted = true;
    },
  },
};
</script>
```

1.  打开`StarRatingDisplay.vue`文件。

1.  在组件的`<script>`部分，我们将添加一个名为`inject`的新属性。此属性将接收一个名为`starRating`的键的对象，值将是一个具有`default()`函数的对象。如果此组件不是`StarRating`组件的子级，则此函数将记录错误：

```js
<script>
export default {
  name: 'StarRatingDisplay',
  props: {
    maxRating: {
      type: Number,
      required: false,
      default: 5,
    },
    rating: {
      type: Number,
      required: false,
      default: 0,
    },
    votes: {
      type: Number,
      required: false,
      default: 0,
    },
  },
  inject: {
    starRating: {
      default() {
        console.error('StarRatingDisplay need to be a child of 
          StarRating');
      },
    },
  },
  methods: {
    getStarName(rate) {
      if (rate <= this.rating) {
        return 'star';
      }
      if (Math.fround((rate - this.rating)) < 1) {
        return 'star_half';
      }
      return 'star_border';
    },
  },
};
</script>
```

1.  打开`StarRatingInput.vue`文件。

1.  在组件的`<script>`部分，我们将添加一个名为`inject`的新属性。此属性将接收一个名为`starRating`的键的对象，值将是一个具有`default()`函数的对象。如果此组件不是`StarRating`组件的子级，则此函数将记录错误：

```js
<script>
export default {
  name: 'StarRatingInput',
  props: {
    maxRating: {
      type: Number,
      required: false,
      default: 5,
    },
  },
  inject: {
    starRating: {
      default() {
        console.error('StarRatingInput need to be a child of 
          StarRating');
      },
    },
  },
  data: () => ({
    rating: 0,
  }),
  methods: {
    updateRating(value) {
      this.rating = value;
    },
    emitFinalVote(value) {
      this.updateRating(value);
      this.$emit('final-vote', this.rating);
    },
    getStarName(rate) {
      if (rate <= this.rating) {
        return 'star';
      }
      if (Math.fround((rate - this.rating)) < 1) {
        return 'star_half';
      }
      return 'star_border';
    },
  },
};
</script>
```

## 它是如何工作的...

在运行时，Vue 将检查`StarRatingDisplay`和`StarRatingInput`组件中的`starRating`的注入属性，如果父组件未提供此值，则将在控制台上记录错误。

使用组件注入通常用于在绑定组件之间保持共同接口的方式，例如菜单和项目。项目可能需要存储在菜单中的某些功能或数据，或者我们可能需要检查它是否是菜单的子级。

依赖注入的主要缺点是共享元素上不再具有响应性。因此，它主要用于共享功能或检查组件链接。

## 另请参阅

您可以在[`vuejs.org/v2/guide/components-edge-cases.html#Dependency-Injection`](https://vuejs.org/v2/guide/components-edge-cases.html#Dependency-Injection)找到有关组件依赖注入的更多信息。

# 创建一个组件混合

有时您会发现自己一遍又一遍地重写相同的代码。但是，有一种方法可以防止这种情况，并使自己更加高效。

您可以使用所谓的`mixin`，这是 Vue 中的一个特殊代码导入，它将外部代码部分连接到当前组件。

## 准备工作

先决条件如下：

+   Node.js 12+

所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

## 如何做...

要启动我们的组件，我们可以使用 Vue-CLI 创建我们的 Vue 项目，就像我们在第二章中的'*使用 Vue CLI 创建您的第一个项目*'中所做的那样，或者使用'*创建依赖注入组件*'食谱中的项目。

让我们按照以下步骤创建一个组件`mixin`：

1.  打开`StarRating.vue`组件。

1.  在`<script>`部分，我们需要将`props`属性提取到一个名为`starRatingDisplay.js`的新文件中，我们需要在`mixins`文件夹中创建这个新文件。这个新文件将是我们的第一个`mixin`，并且看起来像这样：

```js
export default {
  props: {
    maxRating: {
      type: Number,
      required: false,
      default: 5,
    },
    rating: {
      type: Number,
      required: false,
      default: 0,
    },
    votes: {
      type: Number,
      required: false,
      default: 0,
    },
  },
};
```

1.  回到`StarRating.vue`组件，我们需要导入这个新创建的文件，并将其添加到一个名为`mixin`的新属性中：

```js
<script>
import StarRatingInput from './StarRatingInput.vue';
import StarRatingDisplay from './StarRatingDisplay.vue';
import StarRatingDisplayMixin from '../mixins/starRatingDisplay';

export default {
  name: 'StarRating',
  components: { StarRatingDisplay, StarRatingInput },
  mixins: [StarRatingDisplayMixin],
  provide: {
    starRating: true,
  },
  data: () => ({
    rank: 0,
    voted: false,
  }),
  computed: {
    starComponent() {
      if (!this.voted) return StarRatingInput;
      return StarRatingDisplay;
    },
  },
  methods: {
    vote(rank) {
      this.rank = rank;
      this.voted = true;
    },
  },
};
</script>
```

1.  现在，我们将打开`StarRatingDisplay.vue`文件。

1.  在`<script>`部分，我们将`inject`属性提取到一个名为`starRatingChild.js`的新文件中，该文件将被创建在`mixins`文件夹中。这将是我们`inject`属性的`mixin`：

```js
export default {
  inject: {
    starRating: {
      default() {
        console.error('StarRatingDisplay need to be a child of 
           StarRating');
      },
    },
  },
};
```

1.  在`StarRatingDisplay.vue`文件中，在`<script>`部分，我们将提取`methods`属性到一个名为`starRatingName.js`的新文件中，该文件将被创建在`mixins`文件夹中。这将是我们`getStarName`方法的`mixin`：

```js
export default {
  methods: {
    getStarName(rate) {
      if (rate <= this.rating) {
        return 'star';
      }
      if (Math.fround((rate - this.rating)) < 1) {
        return 'star_half';
      }
      return 'star_border';
    },
  },
};
```

1.  回到`StarRatingDisplay.vue`文件，我们需要导入这些新创建的文件，并将它们添加到一个名为`mixin`的新属性中：

```js
<script>
import StarRatingDisplayMixin from '../mixins/starRatingDisplay';
import StarRatingNameMixin from '../mixins/starRatingName';
import StarRatingChildMixin from '../mixins/starRatingChild';

export default {
  name: 'StarRatingDisplay',
  mixins: [
    StarRatingDisplayMixin,
    StarRatingNameMixin,
    StarRatingChildMixin,
  ],
};
</script>
```

1.  打开`StarRatingInput.vue`文件。

1.  在`<script>`部分，我们移除`inject`属性，并将`props`属性提取到一个名为`starRatingBase.js`的新文件中，该文件将被创建在`mixins`文件夹中。这将是我们`props`属性的`mixin`：

```js
export default {
  props: {
    maxRating: {
      type: Number,
      required: false,
      default: 5,
    },
    rating: {
      type: Number,
      required: false,
      default: 0,
    },
  },
};
```

1.  回到`StarRatingInput.vue`文件，我们需要将`rating`数据属性重命名为`rank`，并且在`getStarName`方法中，我们需要添加一个新的常量，该常量将接收`rating`属性或`rank`数据。最后，我们需要导入`starRatingChild` `mixin`和`starRatingBase` `mixin`：

```js
<script>
import StarRatingBaseMixin from '../mixins/starRatingBase';
import StarRatingChildMixin from '../mixins/starRatingChild';

export default {
  name: 'StarRatingInput',
  mixins: [
    StarRatingBaseMixin,
    StarRatingChildMixin,
  ],
  data: () => ({
    rank: 0,
  }),
  methods: {
    updateRating(value) {
      this.rank = value;
    },
    emitFinalVote(value) {
      this.updateRating(value);
      this.$emit('final-vote', this.rank);
    },
    getStarName(rate) {
      const rating = (this.rating || this.rank);
      if (rate <= rating) {
        return 'star';
      }
      if (Math.fround((rate - rating)) < 1) {
        return 'star_half';
      }
      return 'star_border';
    },
  },
};
</script>
```

## 它是如何工作的...

`mixins`的工作原理就像对象合并一样，但确保不要用导入的属性替换组件中已经存在的属性。

`mixins`属性的顺序也很重要，因为它们将被检查并作为`for`循环导入，所以最后一个`mixin`不会改变任何祖先的属性。

在这里，我们将我们的代码中的许多重复部分拆分成了四个不同的小 JavaScript 文件，这样更容易维护并提高了生产力，而无需重写代码。

## 另请参阅

您可以在[`vuejs.org/v2/guide/mixins.html`](https://vuejs.org/v2/guide/mixins.html)找到有关 mixins 的更多信息。

# 惰性加载您的组件

`webpack`和 Vue 天生就是一对。当使用`webpack`作为 Vue 项目的打包工具时，可以使组件在需要时或异步加载。这通常被称为惰性加载。

## 准备工作

先决条件如下：

+   Node.js 12+

所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

## 如何做...

要启动我们的组件，我们可以像在第二章中的'*使用 Vue CLI 创建您的第一个项目*'配方中那样使用 Vue-CLI 创建我们的 Vue 项目，或者使用'*创建组件 mixin*'配方中的项目。

现在，按照以下步骤使用惰性加载技术导入您的组件：

1.  打开`App.vue`文件。

1.  在组件的`<script>`部分，我们将在脚本顶部获取导入并将它们转换为每个组件的惰性加载函数：

```js
<script>
export default {
  name: 'App',
  components: {
    StarRating: () => import('./components/StarRating.vue'),
    MaterialButton: () => import('./components/MaterialButton.vue'),
    MaterialCardBox: () => 
      import('./components/MaterialCardBox.vue'),
  },
  methods: {
    resetVote() {
      this.$refs.starRating.rank = 0;
      this.$refs.starRating.voted = false;
    },
    forceVote() {
      this.$refs.starRating.rank = 5;
      this.$refs.starRating.voted = true;
    },
  },
};
</script>
```

## 它是如何工作的...

当我们声明一个为每个组件返回`import()`函数的函数时，`webpack`知道这个导入函数将进行代码拆分，并且它将使组件成为捆绑包中的一个新文件。

`import()`函数是由 TC39 提出的一个模块加载语法的建议。这个函数的基本功能是异步加载任何声明为模块的文件，避免了在第一次加载时放置所有文件的需要。

## 另请参阅

您可以在[`vuejs.org/v2/guide/components-dynamic-async.html#Async-Components`](https://vuejs.org/v2/guide/components-dynamic-async.html#Async-Components)找到有关异步组件的更多信息。

您可以在[`github.com/tc39/proposal-dynamic-import`](https://github.com/tc39/proposal-dynamic-import)找到有关 TC39 动态导入的更多信息。
