# Vue2 设计模式最佳实践（四）

> 原文：[`zh.annas-archive.org/md5/6E739FB94554764B9B3B763043E30DA8`](https://zh.annas-archive.org/md5/6E739FB94554764B9B3B763043E30DA8)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十章：测试 Vue.js 应用程序

在一个紧迫和加速要求的世界中，为我们的应用程序创建自动化测试变得比以往任何时候都更加重要。一个需要考虑的重要因素，大多数开发人员忽视的是，测试是一种技能，仅仅因为你可能习惯编写解决方案，并不意味着你可以自动编写好的单元测试。随着你在这个领域的经验越来越丰富，你会发现自己更经常地编写测试，并想知道在没有它们的情况下你到底是怎么做的！

在本章结束时，我们将涵盖以下内容：

+   了解为什么应该考虑使用自动化测试工具和技术

+   为 Vue 组件编写你的第一个单元测试

+   编写模拟特定函数的测试

+   编写依赖于 Vue.js 事件的测试

+   使用 Wallaby.js 实时查看我们测试的结果

当我们谈论测试我们的 Vue 项目时，根据上下文，我们可能指的是不同的事情。

# 为什么要测试？

自动化测试工具是有原因的。当我们手动测试我们创建的工作时，你会从经验中知道这是一个漫长（有时复杂）的过程，不允许一致的结果。我们不仅需要手动记住一个特定组件是否工作（或者在某个地方写下结果！），而且它也不具有变化的弹性。

这些年来我听到过一些关于测试的话语：

*“但是保罗，如果我为我的应用程序编写测试，将需要三倍的时间！”*

*“我不知道如何编写测试...”*

*“那不是我的工作！”*

...以及其他各种。

关键是测试和开发一样是一种技能。你可能不会立刻擅长其中一种，但是随着时间、练习和毅力，你应该会发现自己处于一种测试感觉自然和软件开发的正常部分的位置。

# 单元测试

自动化测试工具取代了我们每次想要验证我们的功能是否按预期工作时所做的手动工作，并给了我们一种运行测试命令逐个测试我们的断言的方法。然后这些结果会以报告的形式呈现给我们（或者在我们的编辑器中实时显示，正如我们后面会看到的），这使我们有能力重构不按预期工作的代码。

通过使用自动化测试工具，与手动测试相比，我们节省了大量的工作量。

单元测试可以被定义为一种只测试一个“单元”（功能的最小可测试部分）的测试类型。然后，我们可以自动化这个过程，随着应用程序变得更大，不断测试我们的功能。在这一点上，您可能希望遵循测试驱动开发/行为驱动开发的实践。

在现代 JavaScript 测试生态系统中，有各种测试套件可用。这些测试套件可以被认为是给我们提供编写断言、运行测试、提供覆盖报告等功能的应用程序。我们将在项目中使用 Jest，因为这是由 Facebook 创建和维护的快速灵活的测试套件。

让我们创建一个新的游乐场项目，以便我们可以熟悉单元测试。我们将使用`webpack`模板而不是`webpack-simple`模板，因为这允许我们默认配置测试：

```js
# Create a new Vue project
**$ vue init webpack vue-testing** ? Project name vue-testing
? Project description Various examples of testing Vue.js applications
? Author Paul Halliday <hello@paulhalliday.io>
? Vue build runtime
? Install vue-router? Yes
? Use ESLint to lint your code? Yes
? Pick an ESLint preset Airbnb
? Set up unit tests Yes
? Pick a test runner jest
? Setup e2e tests with Nightwatch? No
? Should we run `npm install` for you after the project has been create
d? (recommended) npm

# Navigate to directory
$ cd vue-testing

# Run application
$ npm run dev
```

让我们首先调查`test/unit/specs`目录。这是我们在测试 Vue 组件时放置所有单元/集成测试的地方。打开`HelloWorld.spec.js`，让我们逐行进行：

```js
// Importing Vue and the HelloWorld component
import Vue from 'vue';
import HelloWorld from '@/components/HelloWorld';

// 'describe' is a function used to define the 'suite' of tests (i.e.overall context).
describe('HelloWorld.vue', () => {

  //'it' is a function that allows us to make assertions (i.e. test 
  true/false)
  it('should render correct contents', () => {
    // Create a sub class of Vue based on our HelloWorld component
    const Constructor = Vue.extend(HelloWorld);

    // Mount the component onto a Vue instance
    const vm = new Constructor().$mount();

    // The h1 with the 'hello' class' text should equal 'Welcome to 
   Your Vue.js App'
    expect(vm.$el.querySelector('.hello h1').textContent).toEqual(
      'Welcome to Your Vue.js App',
    );
  });
});
```

然后，我们可以通过在终端中运行`npm run unit`来运行这些测试（确保您在项目目录中）。这将告诉我们有多少个测试通过了以及整体测试代码覆盖率。这个指标可以用作确定应用程序在大多数情况下有多健壮的一种方式；但是，它不应该被当作圣经。在下面的截图中，我们可以清楚地看到有多少个测试通过了：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/86d9e86c-4b1a-405c-a910-2e40e1d5b0c6.png)

# 设置 vue-test-utils

为了获得更好的测试体验，建议使用`vue-test-utils`模块，因为这为我们提供了许多专门用于 Vue 框架的帮助程序和模式。让我们基于`webpack-simple`模板创建一个新项目，并自己集成 Jest 和`vue-test-utils`。在您的终端中运行以下命令：

```js
# Create a new Vue project
$ vue init webpack-simple vue-test-jest

# Navigate to directory
$ cd vue-test-jest

# Install dependencies
$ npm install

# Install Jest and vue-test-utils
$ npm install jest vue-test-utils --save-dev

# Run application
$ npm run dev
```

然后，我们必须在项目中添加一些额外的配置，以便我们可以运行 Jest，我们的测试套件。这可以在项目的`package.json`中配置。添加以下内容：

```js
{
  "scripts": {
    "test": "jest"
  }
}
```

这意味着任何时候我们想要运行我们的测试，我们只需在终端中运行`npm run test`。这将在任何匹配`*.spec.js`名称的文件上运行 Jest 的本地（项目安装）版本。

接下来，我们需要告诉 Jest 如何处理单文件组件（即`*.vue`文件）在我们的项目中。这需要`vue-jest`预处理器。我们还希望在测试中使用 ES2015+语法，因此我们还需要`babel-jest`预处理器。让我们通过在终端中运行以下命令来安装两者：

```js
npm install --save-dev babel-jest vue-jest
```

然后我们可以在`package.json`中定义以下对象：

```js
"jest": {
  "moduleNameMapper": {
    "^@/(.*)$": "<rootDir>/src/$1"
  },
  "moduleFileExtensions": [
    "js",
    "vue"
  ],
  "transform": {
    "^.+\\.js$": "<rootDir>/node_modules/babel-jest",
    ".*\\.(vue)$": "<rootDir>/node_modules/vue-jest"
  }
}
```

这本质上告诉 Jest 如何处理 JavaScript 和 Vue 文件，通过知道要使用哪个预处理器（即`babel-jest`或`vue-jest`），具体取决于上下文。

如果我们告诉 Babel 只为当前加载的 Node 版本转译功能，我们还可以使我们的测试运行更快。让我们在`.babelrc`文件中添加一个单独的测试环境：

```js
{
  "presets": [["env", { "modules": false }], "stage-3"],
  "env": {
    "test": {
      "presets": [["env", { "targets": { "node": "current" } }]]
    }
  }
}
```

现在我们已经添加了适当的配置，让我们开始测试吧！

# 创建一个 TodoList

现在让我们在`src/components`文件夹中创建一个`TodoList.vue`组件。这是我们将要测试的组件，我们将逐步为其添加更多功能：

```js
<template>
  <div>
    <h1>Todo List</h1>
    <ul>
      <li v-for="todo in todos" v-bind:key="todo.id">
        {{todo.id}}. {{todo.name}}</li>
    </ul>
  </div>
</template>

<script>
export default {
  data() {
    return {
      todos: [
        { id: 1, name: 'Wash the dishes' },
        { id: 2, name: 'Clean the car' },
        { id: 3, name: 'Learn about Vue.js' },
      ],
    };
  },
};
</script>

<style>
ul,
li {
  list-style: none;
  margin-left: 0;
  padding-left: 0;
}
</style>
```

正如您所看到的，我们只是一个返回具有不同项目的待办事项数组的简单应用程序。让我们在`src/router/index.js`中创建一个路由器，以匹配我们的新`TodoList`组件并将其显示为根：

```js
import Vue from 'vue';
import Router from 'vue-router';
import TodoList from '../components/TodoList';

Vue.use(Router);

export default new Router({
  routes: [
    {
      path: '/',
      name: 'TodoList',
      component: TodoList,
    },
  ],
});
```

由于我们正在使用`vue-router`，我们还需要安装它。在终端中运行以下命令：

```js
$ npm install vue-router --save-dev
```

然后，我们可以将路由器添加到`main.js`中：

```js
import Vue from 'vue'
import App from './App.vue'
import router from './router';

new Vue({
  el: '#app',
  router,
  render: h => h(App)
})
```

我现在已经添加了`router-view`，并决定从`App.vue`中删除 Vue 标志，这样我们就有了一个更清洁的用户界面。以下是`App.vue`的模板：

```js
<template>
  <div id="app">
    <router-view/>
  </div>
</template>
```

正如我们在浏览器中看到的那样，它显示了我们的模板，其中包括 TodoList 的名称和我们创建的`todo`项目：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/4705e2e3-e78b-4168-843a-f001df506d5d.png)让我们为这个组件编写一些测试

# 编写测试

在`src/components`文件夹中，创建一个名为`__tests__`的新文件夹，然后创建一个名为`TodoList.spec.js`的文件。Jest 将自动找到此文件夹和后续的测试。

让我们首先从测试工具中导入我们的组件和`mount`方法：

```js
import { mount } from 'vue-test-utils';
import TodoList from '../TodoList';
```

`mount`方法允许我们在隔离中测试我们的`TodoList`组件，并且使我们能够模拟任何输入 props、事件，甚至输出。接下来，让我们创建一个描述块，用于包含我们的测试套件：

```js
describe('TodoList.vue', () => {

});
```

现在让我们挂载组件并访问 Vue 实例：

```js
describe('TodoList.vue', () => {
 // Vue instance can be accessed at wrapper.vm
 const wrapper = mount(TodoList);
});
```

接下来，我们需要定义`it`块来断言我们测试用例的结果。让我们做出我们的第一个期望-它应该呈现一个待办事项列表：

```js
describe('TodoList.vue', () => {
  const todos = [{ id: 1, name: 'Wash the dishes' }];
  const wrapper = mount(TodoList);

  it('should contain a list of Todo items', () => {
    expect(wrapper.vm.todos).toContainEqual(todos[0]);
  });
});
```

我们可以通过在终端中运行`$ npm run test -- --watchAll`来观察测试的变化。或者，我们可以在`package.json`内创建一个新的脚本来代替这个操作：

```js
"scripts": {
 "test:watch": "jest --watchAll"
}
```

现在，如果我们在终端内运行`npm run test:watch`，它将监视文件系统的任何更改。

这是我们的结果：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/d9584d12-d6b4-466b-b8ee-6f20344a45fb.png)

这很有趣。我们有一个通过的测试！但是，此时我们必须考虑，这个测试是否脆弱？在实际应用中，我们可能不会在运行时默认拥有`TodoList`中的项目。

我们需要一种方法来在我们的隔离测试中设置属性。这就是设置自己的 Vue 选项的能力派上用场的地方！

# Vue 选项

我们可以在 Vue 实例上设置自己的选项。让我们使用`vue-test-utils`在实例上设置自己的数据，并查看这些数据是否呈现在屏幕上：

```js
describe('TodoList.vue', () => {
  it('should contain a list of Todo items', () => {
    const todos = [{ id: 1, name: 'Wash the dishes' }];
    const wrapper = mount(TodoList, {
      data: { todos },
    });

    // Find the list items on the page
    const liWrapper = wrapper.find('li').text();

    // List items should match the todos item in data
    expect(liWrapper).toBe(todos[0].name);
  });
});
```

正如我们所看到的，我们现在是根据组件内的数据选项来测试屏幕上呈现的项目。

让我们添加一个`TodoItem`组件，以便我们可以动态地渲染带有`todo`属性的组件。然后我们可以根据我们的属性测试这个组件的输出：

```js
<template>
  <li>{{todo.name}}</li>
</template>

<script>
export default {
  props: ['todo'],
};
</script>
```

然后我们可以将其添加到`TodoList`组件中：

```js
<template>
  <div>
    <h1>TodoList</h1>
    <ul>
      <TodoItem v-for="todo in todos" v-bind:key="todo.id" 
      :todo="todo">{{todo.name}}</TodoItem>
    </ul>
  </div>
</template>

<script>
import TodoItem from './TodoItem';

export default {
  components: {
    TodoItem,
  },
  // Omitted
}
```

我们的测试仍然如预期般通过，因为组件在运行时被渲染为`li`。不过，将其更改为查找组件本身可能是一个更好的主意：

```js
import { mount } from 'vue-test-utils';
import TodoList from '../TodoList';
import TodoItem from '../TodoItem';

describe('TodoList.vue', () => {
  it('should contain a list of Todo items', () => {
    const todos = [{ id: 1, name: 'Wash the dishes' }];
    const wrapper = mount(TodoList, {
      data: { todos },
    });

    // Find the list items on the page
    const liWrapper = wrapper.find(TodoItem).text();

    // List items should match the todos item in data
    expect(liWrapper).toBe(todos[0].name);
  });
});
```

让我们为我们的`TodoItem`编写一些测试，并在`components/__tests__`内创建一个`TodoItem.spec.js`：

```js
import { mount } from 'vue-test-utils';
import TodoItem from '../TodoItem';

describe('TodoItem.vue', () => {
  it('should display name of the todo item', () => {
    const todo = { id: 1, name: 'Wash the dishes' };
    const wrapper = mount(TodoItem, { propsData: { todo } });

    // Find the list items on the page
    const liWrapper = wrapper.find('li').text();

    // List items should match the todos item in data
    expect(liWrapper).toBe(todo.name);
  });
});
```

因为我们基本上使用相同的逻辑，所以我们的测试是相似的。主要区别在于，我们不是有一个`todos`列表，而是只有一个`todo`对象。我们使用`propsData`来模拟 props，而不是数据，基本上断言我们可以向这个组件添加属性，并且它呈现正确的数据。让我们看一下我们的测试是否通过或失败：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/b7a2c79e-b9aa-4ad1-a0bc-ae7bd88e18df.png)

# 添加新功能

让我们以测试驱动的方式向我们的应用程序添加新功能。我们需要一种方法来向我们的`todo`列表中添加新项目，所以让我们首先编写我们的测试。在`TodoList.spec.js`内，我们将添加另一个`it`断言，应该向我们的`todo`列表中添加一个项目：

```js
it('should add an item to the todo list', () => {
  const wrapper = mount(TodoList);
  const todos = wrapper.vm.todos;
  const newTodos = wrapper.vm.addTodo('Go to work');
  expect(todos.length).toBeLessThan(newTodos.length);
});
```

如果我们现在运行我们的测试，我们将得到一个失败的测试，这是预期的！：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/ae1c7364-7229-4b62-9446-c816ed199fc3.png)

让我们尽可能少地修复我们的错误。我们可以在 Vue 实例内添加一个名为`addTodo`的方法：

```js
export default {
  methods: {
    addTodo(name) {},
  },
  // Omitted
}
```

现在我们得到了一个新的错误；这次它说无法读取未定义的`length`属性，基本上是说我们没有`newTodos`数组：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/ea3aa57b-9c65-4a84-a90f-9f2b57cbc0b8.png)

让我们使我们的`addTodo`函数返回一个将当前的`todos`与新 todo 结合在一起的数组：

```js
addTodo(name) {
  return [...this.todos, { name }]
},
```

运行`npm test`后，我们得到以下输出：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/207f504d-745c-4ddc-970e-83c8a300387d.png)

塔达！测试通过。

嗯。我记得我们所有的`todo`项目都有适当的`id`，但看起来情况已经不再是这样了。

理想情况下，我们的服务器端数据库应该为我们处理`id`号码，但目前，我们可以使用`uuid`包生成客户端`uuid`。让我们通过在终端中运行以下命令来安装它：

```js
$ npm install uuid
```

然后我们可以编写我们的测试用例，断言添加到列表中的每个项目都有一个`id`属性：

```js
it('should add an id to each todo item', () => {
  const wrapper = mount(TodoList);
  const todos = wrapper.vm.todos;
  const newTodos = wrapper.vm.addTodo('Go to work');

  newTodos.map(item => {
    expect(item.id).toBeTruthy();
  });
});
```

正如你所看到的，终端输出了我们有一个问题，这是因为显然我们没有`id`属性：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/b651c0c2-e3c0-4d1b-b204-fa2c3e02a57e.png)

让我们使用之前安装的`uuid`包来实现这个目标：

```js
import uuid from 'uuid/v4';

export default {
  methods: {
    addTodo(name) {
      return [...this.todos, { id: uuid(), name }];
    },
  },
  // Omitted
};
```

然后我们得到了一个通过的测试：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/19d3db16-8823-471d-bd6b-047022afcf56.png)

从失败的测试开始对多个原因都是有益的：

+   它确保我们的测试实际上正在运行，我们不会花时间调试任何东西！

+   我们知道接下来需要实现什么，因为我们受当前错误消息的驱使

然后我们可以写入最少必要的内容来获得绿色的测试，并继续重构我们的代码，直到我们对解决方案感到满意。在以前的测试中，我们可以写得更少以获得绿色的结果，但为了简洁起见，我选择了更小的例子。

# 点击事件

太好了！我们的方法有效，但这不是用户将与应用程序交互的方式。让我们看看我们是否可以使我们的测试考虑用户输入表单和随后的按钮：

```js
<form @submit.prevent="addTodo(todoName)">
  <input type="text" v-model="todoName">
  <button type="submit">Submit</button>
</form>
```

我们还可以对我们的`addTodo`函数进行小小的改动，确保`this.todos`被赋予新的`todo`项目的值：

```js
addTodo(name) {
 this.todos = [...this.todos, { id: uuid(), name }];
 return this.todos;
},
```

很棒的是，通过进行这种改变，我们可以检查所有以前的用例，并且看到没有任何失败！为自动化测试欢呼！

接下来，让我们创建一个`it`块，我们可以用来断言每当我们点击提交按钮时，都会添加一个项目：

```js
  it('should add an item to the todo list when the button is clicked', () => {
    const wrapper = mount(TodoList);
  })
```

接下来，我们可以使用 find 从包装器中获取表单元素，然后触发事件。由于我们正在提交表单，我们将触发提交事件并传递参数给我们的`submit`函数。然后我们可以断言我们的`todo`列表应该是`1`：

```js
it('should add an item to the todo list when the button is clicked', () => {
 const wrapper = mount(TodoList);
 wrapper.find('form').trigger('submit', 'Clean the car');

 const todos = wrapper.vm.todos;

 expect(todos.length).toBe(1);
})
```

我们还可以检查在表单提交时是否调用了适当的方法。让我们使用`jest`来做到这一点：

```js
it('should call addTodo when form is submitted', () => {
  const wrapper = mount(TodoList);
  const spy = jest.spyOn(wrapper.vm, 'addTodo');

  wrapper.find('form').trigger('submit', 'Clean the car');

  expect(wrapper.vm.addTodo).toHaveBeenCalled();
});
```

# 测试事件

我们取得了很大的进展，但如果我们能测试组件之间触发的事件，那不是很棒吗？让我们通过创建一个`TodoInput`组件来看看这个问题，并将我们的表单抽象到`this`组件中：

```js
<template>
  <form @submit.prevent="addTodo(todoName)">
    <input type="text" v-model="todoName">
    <button type="submit">Submit</button>
  </form>
</template>

<script>
export default {
  data() {
    return {
      todoName: ''
    } 
  },
  methods: {
    addTodo(name) {
      this.$emit('addTodo', name);
    }
  }
}
</script>
```

现在，我们在`this`组件中的`addTodo`方法触发了一个事件。让我们在`TodoInput.spec.js`文件中测试该事件：

```js
import { mount } from 'vue-test-utils';
import TodoInput from '../TodoInput';

describe('TodoInput.vue', () => {
  it('should fire an event named addTodo with todo name', () => {
    const mock = jest.fn()
    const wrapper = mount(TodoInput);

    wrapper.vm.$on('addTodo', mock)
    wrapper.vm.addTodo('Clean the car');

    expect(mock).toBeCalledWith('Clean the car')
  })
});
```

在这个方法中，我们介绍了一个新的概念——`mock`。这允许我们定义自己的行为，并随后确定事件是如何被调用的。

每当`addTodo`事件被触发时，`mock`函数就会被调用。这使我们能够看到我们的事件是否被调用，并确保事件可以携带有效负载。

我们还可以确保`TodoList`处理`this`事件，但首先确保您已经更新了`TodoList`以包括`TodoInput`表单：

```js
<template>
  <div>
    <h1>TodoList</h1>

    <TodoInput @addTodo="addTodo($event)"></TodoInput>

    <ul>
      <TodoItem v-for="todo in todos" v-bind:key="todo.id" :todo="todo">{{todo.name}}</TodoItem>
    </ul>
  </div>
</template>

<script>
import uuid from 'uuid/v4';

import TodoItem from './TodoItem';
import TodoInput from './TodoInput';

export default {
  components: {
    TodoItem,
    TodoInput
  },
  data() {
    return {
      todos: [],
      todoName: ''
    };
  },
  methods: {
    addTodo(name) {
      this.todos = [...this.todos, { id: uuid(), name }];
      return this.todos;
    },
  },
};
</script>
<style>
ul,
li {
  list-style: none;
  margin-left: 0;
  padding-left: 0;
}
</style>
```

然后，在我们的`TodoList.spec.js`中，我们可以首先导入`TodoInput`，然后添加以下内容：

```js
import TodoInput from '../TodoInput';
it('should call addTodo when the addTodo event happens', () => {
  const wrapper = mount(TodoList);

  wrapper.vm.addTodo = jest.fn();
  wrapper.find(TodoInput).vm.$emit('addTodo', 'Clean the car');

  expect(wrapper.vm.addTodo).toBeCalledWith('Clean the car');
})
```

除此之外，我们还可以确保事件执行其预期功能；所以当我们触发事件时，它会向数组添加一个项目，我们正在测试数组的长度：

```js
it('adds an item to the todolist when the addTodo event happens', () => {
 const wrapper = mount(TodoList);
 wrapper.find(TodoInput).vm.$emit('addTodo', 'Clean the car');
 const todos = wrapper.vm.todos;
 expect(todos.length).toBe(1);
});
```

# 使用 Wallaby.js 获得更好的测试体验

我们还可以使用 Wallaby.js 在编辑器中实时查看我们的单元测试结果。这不是一个免费的工具，但在创建面向测试驱动的 Vue 应用程序时，您可能会发现它很有用。让我们首先克隆/下载一个已经设置好 Wallaby 的项目。在您的终端中运行以下命令：

```js
# Clone the repository
$ git clone https://github.com/ChangJoo-Park/vue-wallaby-webpack-template

# Change directory
$ cd vue-wallaby-webpack-template

# Install dependencies
$ npm install

# At the time of writing this package is missing eslint-plugin-node
$ npm install eslint-plugin-node

# Run in browser
$ npm run dev
```

然后，我们可以在编辑器中打开它，并在编辑器中安装 Wallaby.js 扩展。您可以在[`wallabyjs.com/download/`](https://wallabyjs.com/download/)找到受支持的编辑器列表和说明。

我将在 Visual Studio Code 中安装这个，首先在扩展市场中搜索 Wallaby：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/4fe32175-7e93-4710-b862-8276517d2d16.png)

然后，我们可以按下 Mac 上的*CMD* + *SHIFT + =*或 Windows 上的*CTRL* + *SHIFT + =*，告诉 Wallaby 有关项目的配置文件（`wallaby.js`）。从下拉菜单中，单击“选择配置文件”，然后键入`wallaby.js`。这将允许 Wallaby 和 Vue 一起工作。

要启动 Wallaby，我们可以再次打开配置菜单并选择“启动”。然后，我们可以导航到`tests/unit/specs/Hello.spec.js`文件，并在编辑器的行边距中看到不同的块：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/5fa8444b-706f-4426-9556-3106fa8d1712.png)

由于一切都是绿色的，我们知道它已经通过了！如果我们改变测试的实现细节会怎么样？让我们故意让一个或多个测试失败：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/17998166-4cf0-4664-9507-83e3d278c611.png)

除了“应该呈现正确内容”块之外，一切都保持不变，可以在左侧看到。这是因为我们现在有一个失败的断言，但更重要的是，我们不必重新运行测试，它们会立即显示在我们的编辑器中。不再需要在不同窗口之间切换以观看我们的测试输出！

# 摘要

本章让我们了解了如何适当地测试我们的 Vue 组件。我们学会了如何遵循先失败的方法来编写驱动我们开发决策的测试，以及如何利用 Wallaby.js 在编辑器中查看我们测试的结果！

在下一章中，我们将学习如何将我们的 Vue.js 应用与现代渐进式 Web 应用技术相结合，例如服务工作者、应用程序清单等等！


# 第十一章：优化

如果你多年来一直在编写针对 Web 平台的应用程序，你会看到 Web 经历了多少变化。最初只是一个简单的文档查看器，现在我们必须处理复杂的构建步骤、状态管理模式、持续审查性能和兼容性等等。

值得庆幸的是，JavaScript 的流行和随后的工具意味着有模板和经过验证的技术，我们可以用来优化我们的应用程序和部署。

在本章中，我们将看一下以下主题：

+   来自 Vue CLI 的`vue-pwa`模板

+   渐进式 Web 应用程序的特点

+   使用 ngrok 在任何设备上查看本地主机应用程序

+   使用 Firebase 托管部署 Web 应用程序

+   持续集成及其对大型项目的意义

+   在每次 Git`commit`上自动运行测试

+   在每次 Git`commit`上自动部署到 Firebase 托管

# 渐进式 Web 应用程序（PWA）

PWAs 可以被定义为利用现代 Web 的能力来提供周到、引人入胜和互动体验的应用程序。我的对 PWAs 的定义是包含渐进增强原则的。我们当然可以利用 PWAs 所提供的一切，但我们不必这样做（或者至少不是一次性做完）。

这意味着我们不仅在不断改进我们的应用程序，而且遵循这些原则迫使我们以用户的角度思考，用户可能有不稳定的互联网连接，想要离线优先体验，需要主屏幕可访问的应用程序等等。

再次，Vue CLI 让这个过程对我们来说很容易，因为它提供了一个 PWA 模板。让我们使用适当的模板创建一个新的 Vue 应用程序：

```js
# Create a new Vue project
$ vue init pwa vue-pwa

? Project name vue-pwa
? Project short name: fewer than 12 characters to not be truncated on homescreens (default: same as name) 
? Project description A PWA built with Vue.js
? Author Paul Halliday <hello@paulhalliday.io>
? Vue build runtime
? Install vue-router? Yes
? Use ESLint to lint your code? Yes
? Pick an ESLint preset Airbnb
? Setup unit tests with Karma + Mocha? No
? Setup e2e tests with Nightwatch? No

# Navigate to directory
$ cd vue-pwa

# Install dependencies
$ npm install

# Run application
$ npm run dev
```

在本章中，我们将看一下这个模板给我们带来的好处，以及我们如何使我们的应用程序和操作更加渐进。

# Web 应用程序清单

你可能已经看到使用 Web 应用程序清单的应用程序的好处——如果你曾经在一个要求你在主屏幕上安装的网站上，或者如果你注意到在 Android Chrome 上地址栏的颜色从默认灰色变成不同颜色，那就是一个渐进式应用程序。

让我们转到`static/manifest.json`并调查内容：

```js
{
  "name": "vue-pwa",
  "short_name": "vue-pwa",
  "icons": [
    {
      "src": "/static/img/icons/android-chrome-192x192.png",
      "sizes": "192x192",
      "type": "image/png"
    },
    {
      "src": "/static/img/icons/android-chrome-512x512.png",
      "sizes": "512x512",
      "type": "image/png"
    }
  ],
  "start_url": "/index.html",
  "display": "standalone",
  "background_color": "#000000",
  "theme_color": "#4DBA87"
}
```

我们有选项来给我们的应用程序`name`和`short_name`；这些将在设备的主屏幕上安装时显示。

`icons`数组用于为不同大小的图标提供高清体验。`start_url`定义了在用户主屏幕上安装时启动时要加载的文件，因此指向`index.html`。

我们可以通过显示属性在设备上运行 PWA 时更改应用程序的外观。有各种可用选项，如`browser`、`standalone`、`minimal-ui`和`fullscreen`。每个选项都会改变应用程序在设备上的显示方式；[(https://developers.google.com/web/fundamentals/web-app-manifest/)](https://developers.google.com/web/fundamentals/web-app-manifest/)

这里有一个浏览器和独立应用的例子：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/0c9ee94d-9fc1-4205-b005-b02e594ca17b.jpg)显示选项-Web 应用清单

我们还可以利用`background_color`选项来改变 PWA 启动时闪屏背景的颜色，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/ff35908d-7857-4d28-8de5-d8ba20026233.png)

如果我们想要改变工具栏的颜色，我们可以使用`theme_color`选项（随着我们继续前进，我们将看一个例子）。

您可以根据项目的需求自定义您的 Web 应用清单并传递其他选项。您可以在 MDN 上找到有关 Web 应用清单的更多信息[`developer.mozilla.org/en-US/docs/Web/Manifest`](https://developer.mozilla.org/en-US/docs/Web/Manifest)。

# 在设备上进行测试

如果我们想要在设备上测试我们的应用程序而不用担心部署，我们可以使用 ngrok 等工具在本地主机和外部世界之间创建隧道。这允许我们在任何具有公共 URL 的设备上查看我们的应用程序，一旦关闭连接，URL 和随后的应用程序就会消失。

通过导航到[`ngrok.com/download`](https://ngrok.com/download)并按照您的平台的安装步骤来下载 ngrok。

Ngrok 也可以通过`npm`安装，输入：

```js
npm install ngrok -g
```

由于我们的 Vue 应用程序正在 8080 端口上运行，我们可以启动 ngrok 并告诉它从该端口提供服务。在已安装 ngrok 的终端中运行以下命令：

```js
$ ngrok http 8080
```

然后我们在终端中得到以下结果：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/590ca896-1bf2-4b16-82f3-f1ed6210898d.png)

然后我们可以在任何设备上导航到此 URL，并在屏幕上看到以下结果：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/01bef090-dc5b-4f04-85e7-29a8ccc3b00d.png)

这不是更本地化的体验吗？现在我们默认拥有有色的地址/状态栏。在生产模式下，我们还可以通过`ServiceWorker`获得更多功能。在深入了解之前，让我们看看如何使用 Firebase 将我们的应用程序部署到更永久的 URL。

# Firebase 部署

Firebase 是谷歌的一个平台，允许我们利用实时数据库、远程配置、推送通知等等。对于我们的用例来说，更重要的是静态文件部署的潜力，这是我们将要利用的东西。

该平台有三种不同的可用套餐，每种套餐提供不同级别的服务，第一层是免费的，接下来的两层需要付费。

首先，导航到[`firebase.google.com`](https://firebase.google.com)，并通过点击“登录”来使用谷歌账号登录，然后点击右上角的“转到控制台”。

然后，通过在 Firebase 仪表板上选择+添加项目来创建一个新的 Firebase 项目，然后选择项目名称和国家。

然后我们将导航到项目概述，我们可以选择将 Firebase 添加到我们的项目以及各种其他选项。我们正在寻找托管，因为我们有兴趣部署我们的静态内容。从左侧菜单中，点击“托管”：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/ab2db5b9-7017-4dfa-8cc8-365832a10d2b.png)

我们将经常在这个屏幕上，因为它允许我们回滚部署以及查看其他使用指标。由于我们还没有进行第一次部署，屏幕看起来会类似于这样：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/f572484c-22ef-4e0d-93e2-ce4456de2aa4.png)

如果我们点击“开始”，我们将收到一条消息，指出我们需要下载 Firebase 工具。这是一个允许我们在终端内管理 Firebase 项目的 CLI。

通过在终端中运行以下命令来安装 Firebase 工具：

```js
$ npm install firebase-tools -g
```

然后我们可以按照托管向导的下一步中概述的步骤进行操作，但我们暂时不会使用部署步骤。向导应该看起来像这样：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/43546367-de51-43c4-88a0-adc78faae885.png)

让我们通过在终端中运行以下命令来登录 Firebase 控制台：

```js
$ firebase login
```

选择一个谷歌账号并给予适当的权限。然后会出现以下屏幕：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/d5ec4dcb-64d6-4a21-ba96-27426bedf170.png)

然后，我们可以在我们的`vue-pwa`项目中初始化一个新的 Firebase 项目。在终端中运行以下命令：

```js
$ firebase init
```

在这一点上，我们可以使用键盘导航到托管并用空格键选择它。这应该使圆圈变绿，并告诉 Firebase 我们想要在我们的项目中设置托管。

！[](assets/826a6ff0-0808-420e-b37a-1b39cd4ab76b.png)

然后，我们必须将我们的本地项目与 Firebase 仪表板中的项目进行匹配。从列表中选择您之前创建的项目：

！[](assets/a172175d-09f8-4b35-b194-088123863f48.png)

然后它应该问您与设置相关的问题-像这样回答：

！[](assets/aa4c1662-0734-419f-bcb4-1d06be3865b8.png)

我们现在可以随意部署到 Firebase。我们需要为生产构建我们的项目，以适当生成包含我们应用程序内容的`dist`文件夹。让我们在终端中运行以下命令：

```js
$ npm run prod
```

然后，要部署到 Firebase，我们可以运行以下命令：

```js
$ firebase deploy
```

过了一会儿，您应该会收到一个可导航的 URL，其中包含我们通过 HTTPS 提供的应用程序：

！[](assets/b0cf75f6-3328-4737-bbb0-fc4b2294a661.png)

我们的 Firebase 仪表板也已更新以反映我们的部署：

！[](assets/1e582605-e4f4-45f8-a9ca-0e9ab0070b81.png)

如果我们然后导航到 URL，我们应该按预期获得我们的项目：

！[](assets/3d3cb016-af9e-462c-9559-5759a1554014.png)

此外，因为我们使用生产构建构建了我们的应用程序，我们可以断开与 Wi-Fi 的连接或在开发者工具中勾选离线框。这样做后，我们会发现我们的应用程序仍然按预期运行，因为我们在所有生产构建上都运行了`ServiceWorker`。

# 持续集成（CI）

有各种 CI 平台可用，例如 Travis、GitLab、Jenkins 等等。每个平台通常都有一个共同的目标，即自动化部署和随之而来的挑战。

当然，我们可以部署我们的站点，运行我们的测试，并继续进行我们不断增加的构建步骤中的其他项目。这不仅是一个繁琐的过程，而且也给了我们许多犯错的机会。此外，这也意味着每个步骤都必须为团队的每个成员进行记录，文档必须保持最新，并且在整个组织中并不是完全可扩展的。

在我们的示例中，我们将使用 Travis CI，我想要解决的第一个目标是自动运行我们的单元测试。为此，我们需要在项目中有一个或多个单元测试。

# 单元测试

我们在前一章中介绍了如何测试 Vue.js 应用程序，那么每次推送新版本时自动运行测试不是很好吗？让我们快速在项目中设置一些测试，并将其与 Travis 集成：

```js
# Install necessary dependencies
$ npm install jest vue-test-utils babel-jest vue-jest --save-dev
```

然后我们可以添加一个运行`jest`的新脚本：

```js
{
  "scripts": {
    "test": "jest"
  }
}
```

接下来，将`jest`配置添加到您的`package.json`中：

```js
"jest": {
  "moduleNameMapper": {
    "^@/(.*)$": "<rootDir>/src/$1"
  },
  "moduleFileExtensions": [
    "js",
    "vue"
  ],
  "transform": {
    "^.+\\.js$": "<rootDir>/node_modules/babel-jest",
    ".*\\.(vue)$": "<rootDir>/node_modules/vue-jest"
  }
}
```

最后，我们可以在`.babelrc`中更新我们的`babel`配置：

```js
{
  "presets": [
    ["env", {
      "modules": false,
      "targets": {
        "browsers": ["> 1%", "last 2 versions", "not ie <= 8"]
      }
    }],
    "stage-2"
  ],
  "plugins": ["transform-runtime"],
  "env": {
    "test": {
      "presets": [["env", { "targets": { "node": "current" } }]],
      "plugins": [ "istanbul" ]
    }
  }
}
```

然后，在`components/__test__/Hello.spec.js`中创建一个简单的测试，只需检查我们数据中的`msg`是否与一个字符串匹配：

```js
import { mount } from 'vue-test-utils';
import Hello from '../Hello';

describe('Hello.vue', () => {
  it('should greet the user', () => {
    const wrapper = mount(Hello);

    expect(wrapper.vm.msg).toEqual('Welcome to Your Vue.js PWA');
  })
})
```

如预期的那样，我们可以运行`npm test`来执行我们的测试：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/ba19775a-fe4a-45de-9bc8-9b714c48c367.png)

# 创建一个 Git 存储库

要使用 Travis CI 进行持续集成，我们需要将项目上传到 GitHub。如果您的机器上还没有安装 Git，请从[`git-scm.com/`](https://git-scm.com/)下载并随后在[`github.com`](https://github.com)创建一个 GitHub 账户。

在[`github.com/new`](https://github.com/new)为您的项目创建一个新的存储库，或者点击屏幕右上角的+号，然后点击新存储库按钮。

然后，我们可以给我们的存储库命名，并将可见性设置为公共或私有：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/5c6d0311-8217-432f-b93e-4f8225b04c3e.png)

一旦我们点击创建存储库按钮，我们将看到多种上传存储库到 GitHub 的方式。唯一的问题是我们还没有把我们的 PWA 项目变成 Git 存储库。

我们可以在 Visual Studio Code 或命令行中执行此操作。在 Visual Studio Code 中，点击新存储库按钮。如果您刚安装了 Git，您可能需要重新启动编辑器才能看到此按钮。这是它在 Visual Studio Code 中的样子。

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/a3d74b11-3111-427a-8a0c-69d85f7e7deb.png)

然后，我们可以用一个简单的消息进行新提交，比如“第一次提交”，然后点击打勾：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/e4d55968-1c84-4824-a5af-69653acc9f8e.png)

然后，我们可以按照内部突出显示的步骤将这些更改推送到 GitHub 上的存储库...或者按照以下图片中给出的命令行推送现有的存储库：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/b91594d3-5c01-4183-a84d-06c8fb3ff64c.png)

我们对存储库的任何未来更改都将推送到此远程存储库。这很重要，因为当我们创建 Travis 帐户时，它将自动访问我们的所有 GitHub 存储库。

# 连接到 Travis CI

让我们转到[`travis-ci.org/`](https://travis-ci.org/)，并单击使用 GitHub 登录。在给予 Travis 任何必要的权限后，您应该能够看到与您的帐户关联的存储库列表。我们可以告诉 Travis，我们希望它监视此存储库中的更改，方法是将开关切换为绿色：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/cc84b945-494c-4bd3-96d4-93f1134903a1.png)

# 配置 Travis

接下来要做的是向我们的项目添加一个适当的`.travis.yml`配置文件。这将告诉 Travis 每次我们将构建推送到 GitHub 时要做什么。因此，在我们使用 Travis 构建时会发生两个不同的阶段：

+   Travis 在我们的项目内安装任何依赖项

+   Travis 运行构建脚本

我们可以连接到构建过程的各个阶段，例如`before_install`、`install`、`before_script`、`script`、`before_cache`、`after_success`、`after_failure`、`before_deploy`、`deploy`、`after_deploy`和`after_script`。所有这些都相对容易理解，但如果看起来很多，不用担心，我们只会连接其中的一些阶段。

让我们在项目的根目录添加一个名为`.travis.yml`的文件，并逐步添加选项。我们可以首先定义项目的语言，由于我们使用的是 Node，接下来也是 Node 环境的版本：

```js
language: node_js
node_js: 
 - "9.3.0"
```

我选择的`node_js`版本与我的环境相匹配（可以使用`node -v`进行检查），但如果您需要针对特定版本的 Node（或多个版本），您可以在这里添加它们。

接下来，让我们添加我们只想在`master`分支上触发构建：

```js
branches: 
  only:
    - master
```

然后，我们需要告诉 Travis 从`package.json`运行什么脚本。因为我们想运行我们的测试，所以我们将运行测试脚本：

```js
script:
  - npm run test
```

最后，让我们声明我们希望收到每次构建的电子邮件通知：

```js
notifications:
  email:
    recipients:
      - your@email.com
    on_success: always 
    on_failure: always
```

这给我们以下文件：

```js
language: node_js
node_js: 
  - "9.3.0"

branches: 
  only:
    - master

script:
  - npm run build
  - npm run test

notifications:
  email:
    recipients:
      - your@email.com
    on_success: always 
    on_failure: always
```

如果我们将这些更改推送到我们的存储库并与原始存储库同步，我们应该能够观看 Travis 控制台运行我们的测试。Travis 可能需要一些时间来启动构建，所以请耐心等待：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/28aff7c1-1f18-4322-b4be-5b0197661987.png)

如果我们向下滚动日志的底部，您可以看到我们的项目已经为生产和测试构建：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/3aea6f8a-e2c9-45b5-a82e-009aada9e3e9.png)

太棒了！我们现在可以运行我们的测试，并在 Travis CI 的构建过程中连接到各个阶段。鉴于我们正在 Travis 上为生产构建我们的项目，我们应该能够自动将此构建部署到 Firebase。

让我们更改我们的`Hello.vue`组件以显示新消息（并使我们的测试失败）：

```js
export default {
  name: 'hello',
  data() {
    return {
      msg: 'Welcome to Your Vue.js PWA! Deployed to Firebase by Travis CI',
    };
  },
};
```

# 自动部署到 Firebase

我们可以让 Travis 自动处理我们的部署，但是我们需要一种方法让 Travis 访问我们的部署令牌。我们可以通过在终端中运行以下命令来获取 CI 环境的令牌：

```js
$ firebase login:ci
```

再次登录您的 Google 帐户后，您应该在终端内获得一个令牌：

```js
 Success! Use this token to login on a CI server:

# Token here
```

现在保留令牌，因为我们一会儿会用到它。

返回 Travis CI 仪表板，并转到项目的设置。在设置内，我们需要添加一个环境变量，然后我们可以在部署脚本内引用它。

添加`FIREBASE_TOKEN`环境变量，其值等于我们从终端获得的令牌：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/d3a7bf3b-42b6-4cff-a3ed-c2ac301a3bde.png)

然后，我们可以更新我们的`.travis.yml`文件，在我们的 CI 环境中安装 firebase 工具，并且如果一切顺利，然后将它们部署到我们的 Firebase 托管环境：

```js
language: node_js
node_js: 
  - "9.3.0"

branches: 
  only:
    - master

before_script: 
  - npm install -g firebase-tools

script:
  - npm run build
  - npm run test

after_success: 
  - firebase deploy --token $FIREBASE_TOKEN

notifications:
  email:
    recipients:
      - your@email.com
    on_success: always 
    on_failure: always
```

在更改此文件并同步存储库后进行新的提交。然后这应该触发 Travis 上的新构建，我们可以查看日志。

以下是结果：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/ced00187-969a-42df-808a-e10cece1989a.png)

我们的部署失败**因为我们的测试失败。**请注意，我们托管在 Firebase 上的应用程序根本没有更改。这是有意的，这就是为什么我们将部署步骤放在`after_success`内的原因，因为如果我们有失败的测试，我们很可能不希望将此代码推送到生产环境。

让我们修复我们的测试，并将新的`commit`推送到存储库：

```js
import { mount } from 'vue-test-utils';
import Hello from '../Hello'

describe('Hello.vue', () => {
  it('should greet the user', () => {
    const wrapper = mount(Hello);

    expect(wrapper.vm.msg).toEqual('Welcome to Your Vue.js PWA! Deployed to Firebase by Travis CI');
  })
})
```

由于所有脚本的退出代码为 0（没有错误），`after_success`钩子被触发，将我们的项目推送到 Firebase Hosting：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/be614da3-476a-4cbe-a3a4-6aefd5a38048.png)

如果我们在适当的 URL 检查我们的应用程序，我们应该看到一个更新的消息：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/5253fa7f-de41-4e35-adca-685c208b7ddc.png)

# 服务工作者

在使用`vue-pwa`模板为生产构建我们的应用程序时，它包括`ServiceWorker`。这本质上是一个在后台运行的脚本，使我们能够利用首次离线方法、推送通知、后台同步等功能。

我们的应用程序现在还会提示用户将应用程序安装到他们的主屏幕上，如下所示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/41b5d1ea-53c3-4d1f-87e2-f16dc8b9f890.png)

如果我们与互联网断开连接，我们也会获得首次离线体验，因为应用程序仍然可以继续运行。这是在使用`vue-pwa`模板时获得的主要好处之一，如果您想了解更多关于`ServiceWorker`以及如何根据自己的需求自定义它，Google 在[`developers.google.com/web/fundamentals/primers/service-workers/`](https://developers.google.com/web/fundamentals/primers/service-workers/)上有一个很好的入门指南。

# 摘要

在本章中，我们调查了 Vue CLI 中的 PWA 模板，随后看了一下随着应用程序的不断增长，我们如何可以自动部署和测试我们的应用程序。这些原则使我们能够不断确保我们可以花更多的时间开发功能，而不是花时间维护部署文档和每次遵循基本任务。

在接下来的章节中，我们将介绍 Nuxt，这是一个允许我们使用 Vue 创建服务器端渲染/静态应用程序的框架。Nuxt 还具有一个有趣的基于文件夹的路由结构，这在创建 Vue 应用程序时给了我们很大的力量。


# 第十二章：使用 Nuxt 进行服务器端渲染

Nuxt 受到一个名为 Next.js 的流行 React 项目的启发，由 Zeit 构建。这两个项目的目标都是创建应用程序，利用最新的思想、工具和技术，提供更好的开发体验。Nuxt 最近进入了 1.x 版本及更高版本，这意味着它应该被认为是稳定的，可以用于生产网站。

在本章中，我们将更详细地了解 Nuxt，如果你觉得它有用，它可能会成为你创建 Vue 应用程序的默认方式。

在本章中，我们将涵盖以下主题：

+   调查 Nuxt 并理解使用它的好处

+   使用 Nuxt 创建应用程序

+   使用 Nuxt 中间件

+   使用布局定义内容

+   在 Nuxt 中理解路由

+   使用服务器端渲染构建 Vue 项目

+   将 Vue 项目构建为静态站点

# Nuxt

Nuxt 引入了通用 Vue 应用程序的概念，因为它使我们能够轻松地利用服务器端渲染（SSR）。与此同时，Nuxt 还赋予我们生成静态站点的能力，这意味着内容以 HTML、CSS 和 JS 文件的形式呈现，而不需要来回从服务器传输。

这还不是全部——Nuxt 处理路由生成，并且不会减少 Vue 的任何核心功能。让我们创建一个 Nuxt 项目。

# 创建一个 Nuxt 项目

我们可以使用 Vue CLI 使用启动模板创建一个新的 Nuxt 项目。这为我们提供了一个简单的 Nuxt 项目，并避免了手动配置的麻烦。我们将创建一个名为“丰盛家常烹饪”的“食谱列表”应用程序，该应用程序使用 REST API 获取类别和食谱名称。在终端中运行以下命令创建一个新的 Nuxt 项目：

```js
# Create a new Nuxt project
$ vue init nuxt-community/starter-template vue-nuxt

# Change directory
$ cd vue-nuxt

# Install dependencies
$ npm install

# Run the project in the browser
$ npm run dev
```

前面的步骤与创建新的 Vue 项目时所期望的非常相似，相反，我们可以简单地使用 Nuxt 存储库和启动模板来生成一个项目。

如果我们查看我们的`package.json`，你会发现我们没有生产依赖项的列表；相反，我们只有一个`nuxt`：

```js
"dependencies": {
  "nuxt": "¹.0.0"
}
```

这很重要，因为这意味着我们不必管理 Vue 的版本或担心其他兼容的包，因为我们只需要更新`nuxt`的版本。

# 目录结构

如果我们在编辑器中打开我们的项目，我们会注意到我们比以前的 Vue 应用程序有更多的文件夹。我编制了一张表格，概述了它们的含义：

| 文件夹 | 描述 |
| --- | --- |
| `资产` | 用于存储项目资产，例如未编译的图像、js 和 CSS。 使用 Webpack 加载程序作为模块加载。 |
| `组件` | 用于存储应用程序组件。 这些不会转换为路由。 |
| `布局` | 用于创建应用程序布局，例如默认布局、错误布局或其他自定义布局。 |
| `中间件` | 用于定义自定义应用程序中间件。 这允许我们在不同事件上运行自定义功能，例如在页面之间导航。 |
| `页面` | 用于创建组件（`.vue`文件），用作应用程序路由。 |
| `插件` | 用于注册应用程序范围的插件（即使用 `Vue.use`）。 |
| `静态` | 用于存储静态文件；此文件夹中的每个项目都映射到 `/*` 而不是 `/static/*`。 |
| `Store` | 与 Vuex 存储一起使用。 Nuxt 可以与 Vuex 的标准和模块实现一起使用。 |

尽管这可能看起来更复杂，但请记住，这有助于我们分离关注点，结构允许 Nuxt 处理诸如自动生成路由之类的事情。

# Nuxt 配置

让我们向项目添加一些自定义链接，以便我们可以利用 CSS 库、字体等。 让我们向项目添加 Bulma。

Bulma 是一个 CSS 框架，允许我们使用 Flexbox 构建应用程序，并让我们利用许多预制组件。 我们可以通过转到`nuxt.config.js`并在`head`对象内的`link`对象中添加一个新对象来将其添加到我们的项目中，如下所示：

```js
head: {
  // Omitted
  link: [
    { rel: 'icon', type: 'image/x-icon', href: '/favicon.ico' },
    {
      rel: 'stylesheet',
      href:
    'https://cdnjs.cloudflare.com/ajax/libs/bulma/0.6.1/css/bulma.min.css',
    },
  ],
}
```

如果我们使用开发人员工具来检查 HTML 文档中的头部，您会注意到 Bulma 已添加到我们的项目中。 如果我们转到开发人员工具，我们可以看到它确实在项目中使用 Bulma：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/16b5d5fe-0de0-4cc0-9c96-6699a39fb3cc.png)

# 导航

每次我们在页面目录中创建一个新的`.vue`文件，我们都会为我们的应用程序创建一个新的路由。 这意味着每当我们想要创建一个新的路由时，我们只需创建一个带有路由名称的新文件夹，其余工作由 Nuxt 处理。 鉴于我们的`pages`文件夹中有默认的`index.vue`，路由最初看起来像这样：

```js
routes: [
  {
    name: 'index',
    path: '/',
    component: 'pages/index.vue'
  }
]
```

如果我们然后添加一个带有`index.vue`的`categories`文件夹，Nuxt 将生成以下路由：

```js
routes: [
  {
    name: 'index',
    path: '/',
    component: 'pages/index.vue'
  },
  {
    name: 'categories',
    path: '/categories',
    component: 'pages/categories/index.vue'
  }
]
```

如果我们想利用动态路由参数，比如`id`，我们可以在`categories`文件夹内创建一个名为`_id.vue`的组件。这将自动创建一个带有`id`参数的路由，允许我们根据用户的选择采取行动：

```js
routes: [
  {
    name: 'index',
    path: '/',
    component: 'pages/index.vue'
  },
  {
    name: 'categories',
    path: '/categories',
    component: 'pages/categories/index.vue'
  },
  {
    name: 'categories-id',
    path: '/categories/id',
    component: 'pages/categories/_id.vue'
  }
]
```

# 在路由之间导航

我们如何使用 Nuxt 在路由之间导航？嗯，当然是使用`nuxt-link`组件！

这类似于在标准 Vue.js 应用程序中导航链接时使用的`router-link`组件（截至目前为止，它与之相同），但这是用`nuxt-link`组件包装的，以利用未来的预取等功能。

# 布局

我们可以在 Nuxt 项目中创建自定义布局。这允许我们更改页面的排列方式，还允许我们添加共同点，比如静态导航栏和页脚。让我们使用 Bulma 创建一个新的导航栏，以便在我们的站点中的多个组件之间导航。

在`components`文件夹中，创建一个名为`NavigationBar.vue`的新文件，并给它以下标记：

```js
<template>
  <nav class="navbar is-primary" role="navigation" aria-label="main 
  navigation">
    <div class="navbar-brand">
      <nuxt-link class="navbar-item" to="/">Hearty Home Cooking</nuxt-
      link>
    </div>
  </nav>
</template>

<script>
export default {}
</script>
```

然后，我们需要将这个添加到我们默认布局中`layouts`/`default.vue`。我还用适当的 Bulma 类将`nuxt`标签（也就是我们的主`router-view`）包起来，以使我们的内容居中：

```js
<template>
  <div>
    <navigation-bar></navigation-bar>
    <section class="section">
      <nuxt class="container"/>
    </section>
  </div>
</template>

<script>
import NavigationBar from '../components/NavigationBar'

export default {
  components: {
    NavigationBar
  }
}
</script>
```

如果我们然后转到浏览器，我们会看到一个反映我们代码的应用程序：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/8a7ca3de-b6fa-4ec9-86cf-b9ddb618282e.png)

# 模拟 REST API

在创建用于显示我们数据的组件之前，让我们用 JSON Server 模拟一个 REST API。为此，我们需要在项目的根目录下创建一个名为`db.json`的文件，如下所示：

```js
{
  "recipes": [
    { "id": 1, "title": "Blueberry and Chocolate Cake", "categoryId": 1, "image": "https://static.pexels.com/photos/291528/pexels-photo-291528.jpeg" },
    { "id": 2, "title": "Chocolate Cheesecake", "categoryId": 1, "image": "https://images.pexels.com/photos/47013/pexels-photo-47013.jpeg"},
    { "id": 3, "title": "New York and Berry Cheesecake", "categoryId": 1, "image": "https://images.pexels.com/photos/14107/pexels-photo-14107.jpeg"},
    { "id": 4, "title": "Salad with Light Dressing", "categoryId": 2, "image": "https://static.pexels.com/photos/257816/pexels-photo-257816.jpeg"},
    { "id": 5, "title": "Salmon Slices", "categoryId": 2, "image": "https://static.pexels.com/photos/629093/pexels-photo-629093.jpeg" },
    { "id": 6, "title": "Mushroom, Tomato and Sweetcorn Pizza", "categoryId": 3, "image": "https://static.pexels.com/photos/7658/food-pizza-box-chalkboard.jpg" },
    { "id": 7, "title": "Fresh Burger", "categoryId": 4, "image": "https://images.pexels.com/photos/460599/pexels-photo-460599.jpeg" }
  ],
  "categories": [
    { "id": 1, "name": "Dessert", "description": "Delcious desserts that range from creamy New York style cheesecakes to scrumptious blueberry and chocolate cakes."},
    { "id": 2, "name": "Healthy Eating", "description": "Healthy options don't have to be boring with our fresh salmon slices and sweet, crispy salad."},
    { "id": 3, "name": "Pizza", "description": "Pizza is always a popular choice, chef up the perfect meat feast with our recipes!"},
    { "id": 4, "name": "Burgers", "description": "Be the king of the party with our flagship BBQ Burger recipe, or make something lighter with our veggie burgers!"}
  ]
}
```

接下来，请确保您在终端中运行以下命令，以确保您的机器上安装了 JSON Server：

```js
$ npm install json-server -g
```

然后，通过在终端中输入以下命令，我们可以在`3001`端口（或除`3000`之外的任何端口，因为这是 Nuxt 运行的端口）上运行服务器：

```js
$ json-server --watch db.json --port 3001
```

这将监视我们数据库的任何更改，并相应地更新 API。然后我们就能够请求`localhost:3000/recipes/:id`和`localhost:3000/categories/:id`。在 Nuxt 中，我们可以使用`axios`和`asyncData`来做到这一点；让我们接下来看看。

# asyncData

我们可以使用`asyncData`方法在组件加载之前解析组件的数据，实质上是在服务器端请求数据，然后在加载时将结果与组件实例内的数据对象合并。这使得它成为一个很好的地方来添加异步操作，比如从 REST API 获取数据。

我们将使用`axios`库来创建 HTTP 请求，因此我们需要确保已经安装了它。在终端中运行以下命令：

```js
$ npm install axios
```

然后，在`pages`/`index.vue`中，当我们的应用程序启动时，我们将获取一个类别列表来展示给用户。让我们在`asyncData`中做到这一点：

```js
import axios from 'axios'

export default {
  asyncData ({ req, params }) {
    return axios.get(`http://localhost:3001/categories`)
      .then((res) => {
        return {
          categories: res.data
        }
      })
  },
}
```

# 类别

由于`asyncData`与我们的 Vue 实例的数据对象合并，我们可以在视图中访问数据。让我们创建一个`category`组件，用于显示 API 中每个类别的类别：

```js
<template>
  <div class="card">
    <header class="card-header">
      <p class="card-header-title">
        {{category.name}}
      </p>
    </header>
    <div class="card-content">
      <div class="content">
        {{category.description}}
      </div>
    </div>
    <footer class="card-footer">
      <nuxt-link :to="categoryLink" class="card-footer-
      item">View</nuxt-link>
    </footer>
  </div>
</template>

<script>

export default {
  props: ['category'],
  computed: {
    categoryLink () {
      return `/categories/${this.category.id}`
    }
  }
}
</script>

<style scoped>
div {
  margin: 10px;
}
</style>
```

在上面的代码中，我们使用 Bulma 来获取类别信息并将其放在卡片上。我们还使用了一个`computed`属性来生成`nuxt-link`组件的 prop。这使我们能够根据类别`id`导航用户到项目列表。然后我们可以将其添加到我们的根`pages/index.vue`文件中：

```js
<template>
  <div>
    <app-category v-for="category in categories" :key="category.id" 
    :category="category"></app-category>
  </div>
</template>

<script>
import Category from '../components/Category'
import axios from 'axios'

export default {
  asyncData ({ req, params }) {
    return axios.get(`http://localhost:3001/categories`)
      .then((res) => {
        return {
          categories: res.data
        }
      })
  },
  components: {
    'app-category': Category
  }
}
</script>
```

因此，这就是我们的首页现在的样子：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/5f24ca53-a9a5-439a-ac2e-7a886237e951.png)

# 分类详情

为了将用户导航到`category`详细页面，我们需要在`categories`文件夹中创建一个`_id.vue`文件。这将使我们能够在此页面内访问 ID 参数。这个过程与之前类似，只是现在我们还添加了一个`validate`函数来检查`id`参数是否存在：

```js
<script>
import axios from 'axios'

export default {
  validate ({ params }) {
    return !isNaN(+params.id)
  },
  asyncData ({ req, params }) {
    return axios.get(`http://localhost:3001/recipes? 
    categoryId=${params.id}`)
      .then((res) => {
        return {
          recipes: res.data
        }
      })
  },
}
</script>
```

`validate`函数确保该路由存在参数，如果不存在，将会将用户导航到错误（`404`）页面。在本章的后面，我们将学习如何创建自己的错误页面。

现在我们在`data`对象内有一个基于用户选择的`categoryId`的`recipes`数组。让我们在组件文件夹内创建一个`Recipe.vue`组件，用于显示食谱信息：

```js
<template>
  <div class="recipe">
    <div class="card">
      <div class="card-image">
        <figure class="image is-4by3">
          <img :src="recipe.image">
        </figure>
      </div>
      <div class="card-content has-text-centered">
        <div class="content">
          {{recipe.title}}
        </div>
      </div>
    </div>
  </div>
</template>

<script>

export default {
  props: ['recipe']
}
</script>

<style>
.recipe {
  padding: 10px; 
  margin: 5px;
}
</style>
```

我们再次使用 Bulma 进行样式设置，并且能够将一个食谱作为 prop 传递给这个组件。让我们在`_id.vue`组件内迭代所有的食谱：

```js
<template>
  <div>
    <app-recipe v-for="recipe in recipes" :key="recipe.id" 
    :recipe="recipe"></app-recipe>
  </div>
</template>

<script>
import Recipe from '../../components/Recipe'
import axios from 'axios'

export default {
  validate ({ params }) {
    return !isNaN(+params.id)
  },
  asyncData ({ req, params }) {
    return axios.get(`http://localhost:3001/recipes?
    categoryId=${params.id}`)
      .then((res) => {
        return {
          recipes: res.data
        }
      })
  },
  components: {
    'app-recipe': Recipe
  }
}
</script>
```

每当我们选择一个类别，现在我们会得到以下页面，显示所选的食谱：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/96e218fc-6c83-4f8e-ad69-c9f6efe3e9a2.png)

# 错误页面

如果用户导航到一个不存在的路由或者我们的应用程序出现错误怎么办？嗯，我们当然可以利用 Nuxt 的默认错误页面，或者我们可以创建自己的错误页面。

我们可以通过在`layouts`文件夹内创建`error.vue`来实现这一点。让我们继续做这个，并在状态码为`404`时显示错误消息；如果不是，我们将显示一个通用的错误消息：

```js
<template>
  <div>
    <div class="has-text-centered" v-if="error.statusCode === 404">
      <img src="https://images.pexels.com/photos/127028/pexels-photo-
      127028.jpeg" alt="">
        <h1 class="title">Page not found: 404</h1>
        <h2 class="subtitle">
          <nuxt-link to="/">Back to the home page</nuxt-link>
        </h2>
    </div>
    <div v-else class="has-text-centered">
      <h1 class="title">An error occured.</h1>
      <h2 class="subtitle">
        <nuxt-link to="/">Back to the home page</nuxt-link>
      </h2>
    </div>
  </div>
</template>

<script>

export default {
  props: ['error'],
}
</script>
```

如果我们然后导航到`localhost:3000/e`，您将被导航到我们的错误页面。让我们来看看错误页面：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/aa972259-99e1-47fb-a4f0-1f53424f8e5e.png)

# 插件

我们需要能够向我们的应用程序添加配方；因为添加新配方将需要一个表单和一些输入以适当验证表单，我们将使用`Vuelidate`。如果您还记得之前的章节，我们可以使用`Vue.use`添加`Vuelidate`和其他插件。在使用 Nuxt 时，该过程类似，但需要额外的步骤。让我们通过在终端中运行以下命令来安装`Vuelidate`：

```js
$ npm install vuelidate
```

在我们的插件文件夹内，创建一个名为`Vuelidate.js`的新文件。在这个文件内，我们可以导入`Vue`和`Vuelidate`并添加插件：

```js
import Vue from 'vue'
import Vuelidate from 'vuelidate'

Vue.use(Vuelidate)
```

然后，我们可以更新`nuxt.config.js`以添加指向我们的`Vuelidate`文件的插件数组：

```js
plugins: ['~/plugins/Vuelidate']
```

在`build`对象内，我们还将`'vuelidate'`添加到供应商包中，以便将其添加到我们的应用程序中：

```js
build: {
 vendor: ['vuelidate'],
 // Omitted
}
```

# 添加配方

让我们在`pages/Recipes/new.vue`下创建一个新的路由；这将生成一个到`localhost:3000/recipes/new`的路由。我们的实现将是简单的；例如，将食谱步骤作为`string`可能不是生产的最佳选择，但它允许我们在开发中实现我们的目标。

然后，我们可以使用`Vuelidate`添加适当的数据对象和验证：

```js
import { required, minLength } from 'vuelidate/lib/validators'

export default {
  data () {
    return {
      title: '',
      image: '',
      steps: '',
      categoryId: 1
    }
  },
  validations: {
    title: {
      required,
      minLength: minLength(4)
    },
    image: {
      required
    },
    steps: {
      required,
      minLength: minLength(30)
    }
  },
}
```

接下来，我们可以添加适当的模板，其中包括从验证消息到上下文类的所有内容，并在表单有效/无效时启用/禁用`submit`按钮：

```js
<template>
  <form @submit.prevent="submitRecipe">
    <div class="field">
      <label class="label">Recipe Title</label>
      <input class="input" :class="{ 'is-danger': $v.title.$error}" v-
      model.trim="title" @input="$v.title.$touch()" type="text">
      <p class="help is-danger" v-if="!$v.title.required && 
      $v.title.$dirty">Title is required</p>
      <p class="help is-danger" v-if="!$v.title.minLength && 
      $v.title.$dirty">Title must be at least 4 characters.</p>
    </div>

    <div class="field">
      <label class="label">Recipe Image URL</label>
      <input class="input" :class="{ 'is-danger': $v.image.$error}" v-
      model.trim="image" @input="$v.image.$touch()" type="text">
      <p class="help is-danger" v-if="!$v.image.required && 
      $v.image.$dirty">Image URL is required</p>
    </div>

    <div class="field">
      <label class="label">Steps</label>
      <textarea class="textarea" rows="5" :class="{ 'is-danger': 
      $v.steps.$error}" v-model="steps" @input="$v.steps.$touch()" 
      type="text">
      </textarea>
      <p class="help is-danger" v-if="!$v.steps.required && 
      $v.steps.$dirty">Recipe steps are required.</p>
      <p class="help is-danger" v-if="!$v.steps.minLength && 
      $v.steps.$dirty">Steps must be at least 30 characters.</p>
    </div>

    <div class="field">
      <label class="label">Category</label>
      <div class="control">
        <div class="select">
          <select v-model="categoryId" @input="$v.categoryId.$touch()">
            <option value="1">Dessert</option>
            <option value="2">Healthy Eating</option>
          </select>
        </div>
      </div>
    </div>

    <button :disabled="$v.$invalid" class="button is-
    primary">Add</button>
  </form>
</template>
```

要提交食谱，我们需要向我们的 API 发出 POST 请求：

```js
import axios from 'axios'

export default {
  // Omitted
  methods: {
    submitRecipe () {
      const recipe = { title: this.title, image: this.image, steps: 
      this.steps, categoryId: Number(this.categoryId) }
      axios.post('http://localhost:3001/recipes', recipe)
    }
  },
}
```

不要手动导航到`http://localhost:3000/recipes/new` URL，让我们在导航栏中添加一个项目：

```js
<template>
  <nav class="navbar is-primary" role="navigation" aria-label="main navigation">
    <div class="navbar-brand">
      <nuxt-link class="navbar-item" to="/">Hearty Home Cooking</nuxt-
      link>
    </div>
    <div class="navbar-end">
      <nuxt-link class="navbar-item" to="/recipes/new">+ Add New 
      Recipe</nuxt-
     link>
    </div>
  </nav>
</template>
```

现在我们的页面是这样的：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/86996268-e888-47f6-98b1-d0ba3bdb3569.png)

虽然我们还没有在应用程序中使用食谱步骤，但我在这个示例中包含了它作为您可能想要自己包含的功能。

# 转换

在页面之间导航时，Nuxt 使添加过渡效果变得非常简单。让我们通过添加自定义 CSS 来为每个导航操作添加一个`transition`。将名为`transition.css`的文件添加到`assets`文件夹中，然后我们将钩入到不同页面状态中：

```js
.page-enter-active, .page-leave-active {
  transition: all 0.25s;
}

.page-enter, .page-leave-active {
  opacity: 0;
  transform: scale(2);
}
```

添加文件后，我们需要告诉 Nuxt 我们要将其用作`.css`文件。将以下代码添加到您的`nuxt.config.js`中：

```js
 css: ['~/assets/transition.css']
```

现在，我们可以在任何页面之间导航，每次都会有页面过渡效果。

# 为生产构建

Nuxt 为我们提供了多种构建项目用于生产的方式，例如服务器渲染（Universal）、静态或单页应用程序（SPA）模式。所有这些都根据用例提供了不同的优缺点。

默认情况下，我们的项目处于服务器渲染（Universal）模式，并且可以通过在终端中运行以下命令来进行生产构建：

```js
$ npm run build
```

然后我们在项目的`.nuxt`文件夹内得到一个`dist`文件夹；其中包含我们应用程序的构建结果，可以部署到托管提供商：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/0131d6b7-891b-4da5-812e-12653f451922.png)

# 静态

为了以静态模式构建我们的项目，我们可以在终端中运行以下命令：

```js
$ npm run generate
```

这将构建一个静态站点，然后可以部署到诸如 Firebase 之类的静态托管提供商。终端应该如下所示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/1e379bd4-7de1-4bdb-8ef9-6371ba5eae25.png)

# SPA 模式

要以 SPA 模式构建我们的项目，我们需要将以下键值添加到`nuxt.config.js`中：

```js
mode: 'spa'
```

然后我们可以再次构建我们的项目，但这次将使用 SPA 模式构建：

```js
$ npm run build 
```

我们的命令终端现在应该如下所示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/6eba689d-7d87-43a7-b6e7-27c62a6e865f.png)

# 总结

在本章中，我们讨论了如何使用 Nuxt 创建服务器渲染的 Vue 应用程序。我们还讨论了创建新路由有多么容易，以及如何在项目中添加自定义 CSS 库。此外，我们还介绍了如何在页面中添加过渡效果，使在路由之间切换时更加有趣。我们还介绍了如何根据需要构建项目的不同版本，无论是想要一个通用、静态还是 SPA 应用程序。

在最后一章中，我们将讨论 Vue.js 中常见的反模式以及如何避免它们。这对于编写能经受时间考验的一致性软件至关重要。
