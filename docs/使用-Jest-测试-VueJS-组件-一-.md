# 使用 Jest 测试 VueJS 组件（一）

> 原文：[`zh.annas-archive.org/md5/fe8124600bcfb5515d84e359068f7e7c`](https://zh.annas-archive.org/md5/fe8124600bcfb5515d84e359068f7e7c)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

## 关于

本节简要介绍了作者以及本书涵盖的内容。

# 关于本书

在现代基于组件的 JavaScript 框架中进行单元测试并不简单。您需要一个可靠且运行迅速的测试套件。组件彼此相连，浏览器添加了一层 UI，这使得在测试组件时一切都相互依赖。Jest 是一个功能齐全的 JavaScript 测试框架，将为您完成所有工作。

本书向您展示了如何轻松测试 Vue.js 组件，并利用功能齐全的 Jest 测试框架的实际示例。您将学习不同的测试风格及其结构。您还将探索您的 Vue.js 组件如何响应各种测试。您将看到如何应用快照测试、浅渲染、模块依赖模拟和模块别名等技术，使您的测试更加顺畅和清晰。

通过本书，您将了解如何利用 Jest 的功能来测试您的组件。

## 关于作者

亚历克斯·乔弗·莫拉莱斯（Alex Jover Morales）是 Vue.js 核心团队的合作伙伴。他共同组织了阿利坎特前端和 Vue 日活动。他是 Alligatorio 的讲师，对 Web 性能、PWA、代码质量和代码的人性化方面感兴趣。

## 学习目标

+   设置一个 Vue-test 项目，开始使用 Jest。

+   使用浅渲染等技术对组件进行单元测试

+   深入了解如何测试 Vue.js 组件逻辑中的响应部分

+   探索如何测试深度渲染的 Vue.js 组件

+   使用模块依赖模拟、模块别名等方法进行简单快速的测试

+   了解何时以及如何使用快照测试

## 受众

如果您是一名程序员，希望使开发过程更加顺畅和无错，那么这本书非常适合您。一些关于 JavaScript 的先前知识和经验将帮助您快速而轻松地理解本书中解释的概念。

## 方法

本书使用易于理解的语言来解释测试的各种概念。通过理论和实践的完美结合，它向您展示了如何通过利用 Jest 的各种功能轻松测试 Vue.js 组件。


# 第一章：在 Jest 中编写第一个 Vue.js 组件单元测试

官方的 VueJS 测试库，**vue-test-utils** ([`github.com/vuejs/vue-test-utils`](https://github.com/vuejs/vue-test-utils))，基于 **avoriaz** ([`github.com/eddyerburgh/avoriaz`](https://github.com/eddyerburgh/avoriaz))，即将推出。事实上，**@EddYerburgh** ([`twitter.com/EddYerburgh`](https://twitter.com/EddYerburgh)) 在创建它方面做得非常好。这个库提供了所有必要的工具，使得在 VueJS 应用程序中编写单元测试变得容易。

**Jest** ([`facebook.github.io/jest`](https://facebook.github.io/jest))，另一方面，是 Facebook 开发的测试框架，使用一些令人惊叹的功能使得测试变得轻而易举，包括以下内容：

+   几乎没有默认配置

+   非常酷的交互模式

+   并行运行测试

+   开箱即用的间谍、存根和模拟测试

+   内置代码覆盖

+   快照测试

+   模块模拟工具

你可能已经在不使用这些工具的情况下编写了测试，只是使用 Karma、Mocha、Chai、Sinon 等，但你会看到使用这些工具会更容易。

# 设置一个 vue-test 示例项目

让我们通过使用 `vue-cli` ([`github.com/vuejs/vue-cli`](https://github.com/vuejs/vue-cli)) 创建一个新项目，并对所有 yes/no 问题回答 NO：

```js
npm install -g vue-cli
vue init webpack vue-test
cd vue-test
```

然后，我们需要安装一些依赖，如下所示：

```js
# Install dependencies
npm i -D jest vue-jest babel-jest
```

`jest-vue-preprocessor` ([`github.com/vire/jest-vue-preprocessor`](https://github.com/vire/jest-vue-preprocessor)) 是必需的，让 Jest 理解 `.vue` 文件，而 `babel-jest` ([`github.com/facebook/jest/tree/master/packages/babel-jest`](https://github.com/facebook/jest/tree/master/packages/babel-jest)) 是与 Babel 集成所必需的。

现在安装 'vue-test-utils' 库。

```js
npm i -D @vue/test-utils
```

让我们在 `package.json` 中添加以下 Jest 配置：

```js
{
  "jest": {
    "moduleNameMapper": {
      "^vue$": "vue/dist/vue.common.js"
    },
    "moduleFileExtensions": ["js", "vue"],
    "transform": {
      "^.+\\.js$": "<rootDir>/node_modules/babel-jest",
      ".*\\.(vue)$": "<rootDir>/node_modules/vue-jest"
    }
  }
}
```

`moduleFileExtensions` 将告诉 Jest 要查找哪些扩展名，而 `transform` 将告诉 Jest 要使用哪个预处理器来处理文件扩展名。

最后，在 `package.json` 中添加一个 `test` 脚本：

```js
{
  "scripts": {
    "test": "jest"
  }
}
```

# 测试一个组件

我将在这里使用单文件组件，并且我还没有检查它们是否可以分割成它们自己的 `HTML`、`CSS` 或 `js` 文件，所以让我们假设你也在这样做。

首先，在 `src/components` 下创建一个 `MessageList.vue` 组件：

```js
<template>
  <ul>
    <li v-for="message in messages">
      {{ message }}
    </li>
  </ul>
</template>
<script>
  export default {
    name: "list",
    props: ["messages"]
  };
</script>
```

然后更新 `App.vue` 如下使用它：

```js
<template>
  <div id="app">
    <MessageList :messages="messages" />
  </div>
</template>
<script>
  import MessageList from "./components/MessageList";
  export default {
    name: "app",
    data: () => ({ messages: ["Hey John", "Howdy Paco"] }),
    components: {
      MessageList
    }
  };
</script>
```

我们已经有了一些可以测试的组件。让我们在项目根目录下创建一个`test`文件夹和一个`App.test.js`文件：

```js
import Vue from "vue";
import App from "../src/App";
describe("App.test.js", () => {
  let cmp, vm;
  beforeEach(() => {
    cmp = Vue.extend(App); // Create a copy of the original component
    vm = new cmp({
      data: {
        // Replace data value with this fake data
        messages: ["Cat"]
      }
    }).$mount(); // Instances and mounts the component
  });
  it('equals messages to ["Cat"]', () => {
    expect(vm.messages).toEqual(["Cat"]);
  });
});
```

现在，如果我们运行`npm test`（或`npm t`作为缩写版本），测试应该会运行并通过。由于我们正在修改测试，让我们以**watch 模式**运行它：

```js
npm t -- --watch
```

## 嵌套组件的问题

这个测试太简单了。让我们也检查一下输出是否符合预期。为此，我们可以使用 Jest 的惊人快照功能，它将生成输出的快照并与即将到来的运行进行比较。在`App.test.js`中的前一个`it`之后添加：

```js
it("has the expected html structure", () => {
  expect(cmp.element).toMatchSnapshot();
});
```

这将创建一个`test/__snapshots__/App.test.js.snap`文件。让我们打开并检查它：

```js
// Jest Snapshot v1, https://goo.gl/fbAQLP
exports['App.test.js has the expected html structure 1'] = '
<div id="app">
  <ul>
    <li>
      Cat
    </li>
  </ul>
</div>
';
```

如果您对快照不太了解，不用担心；我将在*第九章*，*快照测试*中更深入地介绍它。

如果您还没有注意到，这里有一个大问题：`MessageList`组件也已被渲染。**单元测试**必须作为**独立单元**进行测试，这意味着在`App.test.js`中，我们要测试`App`组件，而不必关心其他任何东西。

这可能是几个问题的原因。例如，想象一下，子组件（在这种情况下是`MessageList`）在`created`钩子上执行副作用操作，比如调用`fetch`，有一个 Vuex 动作，或者状态改变。这绝对不是我们想要的。

幸运的是，**浅渲染**很好地解决了这个问题。

## 什么是浅渲染？

**浅渲染**（[`airbnb.io/enzyme/docs/api/shallow.html`](http://airbnb.io/enzyme/docs/api/shallow.html)）是一种确保您的组件在没有子组件的情况下进行渲染的技术。这对于以下情况很有用：

+   只测试您想要测试的组件（这就是单元测试的含义）

+   避免子组件可能产生的副作用，比如发起 HTTP 调用，调用存储操作等

# 使用 Vue-Test-Utils 测试组件

`vue-test-utils`为我们提供了浅渲染，以及其他功能。我们可以将上一个测试重写如下：

```js
import { shallowMount } from "@vue/test-utils";
import App from "../src/App";
describe("App.test.js", () => {
  let cmp;
  beforeEach(() => {
    cmp = shallowMount(App, {
      // Create a shallow instance of the component
      data: {
        messages: ["Cat"]
      }
    });
  });
  it('equals messages to ["Cat"]', () => {
    // Within cmp.vm, we can access all Vue instance methods
    expect(cmp.vm.messages).toEqual(["Cat"]);
  });
  it("has the expected html structure", () => {
    expect(cmp.element).toMatchSnapshot();
  });
});
```

现在，如果您仍在以`watch`模式运行 Jest，您会发现测试仍然通过，但快照不匹配。按下*u*重新生成它。然后，再次打开并检查它：

```js
// Jest Snapshot v1, https://goo.gl/fbAQLP
exports['App.test.js has the expected html structure 1'] = '
<div id="app">
  <!--  -->
</div>
';
```

你看到了吗？现在，没有子组件被渲染，我们完全隔离地测试了`App`组件。此外，如果子组件中有任何`created`或其他钩子，它们也没有被调用。

如果你对*浅渲染的实现方式*感兴趣，可以查看**源代码**（[`github.com/vuejs/vue-test-utils/blob/dev/packages/test-utils/src/shallow-mount.js`](https://github.com/vuejs/vue-test-utils/blob/dev/packages/test-utils/src/shallow-mount.js)），你会发现它基本上是对`components`键、`render`方法和生命周期钩子进行存根处理。

在同样的思路下，你可以按照以下方式实现`MessageList.test.js`测试：

```js
import { mount } from '@vue/test-utils'
import MessageList from '../src/components/MessageList'
describe('MessageList.test.js', () => {
  let cmp
  beforeEach(() => {
    cmp = mount(MessageList, {
      // Be aware that props is overridden using 'propsData'
      propsData: {
        messages: ['Cat']
      }
    })
  })
  it('has received ['Cat'] as the message property', () => {
    expect(cmp.vm.messages).toEqual(['Cat'])
  })
  it('has the expected html structure', () => {
    expect(cmp.element).toMatchSnapshot()
  })
})
```

你可以在**GitHub**上找到本章的完整示例（[`github.com/alexjoverm/vue-testing-series/tree/lesson-1`](https://github.com/alexjoverm/vue-testing-series/tree/lesson-1)）。


# 第二章：深度渲染 Vue.js 组件的测试

到目前为止，我们已经看到了如何使用浅渲染来测试一个组件，以防止组件的子树渲染。

但在某些情况下，我们希望测试作为一组行为的组件，或者**分子**（[`atomicdesign.bradfrost.com/chapter-2/#molecules`](http://atomicdesign.bradfrost.com/chapter-2/#molecules)）,正如*Atomic Design*中所述。请记住，这适用于**呈现组件**（[`medium.com/@dan_abramov/smart-and-dumb-components-7ca2f9a7c7d0`](https://medium.com/@dan_abramov/smart-and-dumb-components-7ca2f9a7c7d0)），因为它们不知道应用程序的状态和逻辑。在大多数情况下，你可能会希望为容器组件使用浅渲染。

# 添加一个 Message 组件

在`Message`和`MessageList`组件的情况下，除了编写它们各自的单元测试之外，我们可能还想将它们作为一个单元进行测试。

让我们首先创建`components/Message.vue`：

```js
<template>
  <li class="message">{{ message }}</li>
</template>
<script>
  export default {
    props: ["message"]
  };
</script>
```

并更新`components/MessageList.vue`来使用它：

```js
<template>
  <ul>
    <Message :message="message" v-for="message in messages" />
  </ul>
</template>
<script>
  import Message from "./Message";
  export default {
    props: ["messages"],
    components: {
      Message
    }
  };
</script>
```

# 使用 Message 组件测试 MessageList

要使用深度渲染测试`MessageList`，我们只需要在先前创建的`test/MessageList.test.js`中使用`mount`而不是`shallowMount`：

```js
import { mount } from "@vue/test-utils";
import MessageList from "../src/components/MessageList";
describe("MessageList.test.js", () => {
  let cmp;
  beforeEach(() => {
    cmp = mount(MessageList, {
      // Be aware that props is overridden using 'propsData'
      propsData: {
        messages: ["Cat"]
      }
    });
  });
  it('has received ["Cat"] as the message property', () => {
    expect(cmp.vm.messages).toEqual(["Cat"]);
  });
  it("has the expected html structure", () => {
    expect(cmp.element).toMatchSnapshot();
  });
});
```

顺便说一句，你有没有注意到`beforeEach`这个东西？这是一种非常干净的方式，在每个测试之前创建一个干净的组件，这在单元测试中非常重要，因为它定义了测试不应该相互依赖。

`mount`和`shallowMount`使用完全相同的 API；区别在于渲染。随着我们在本系列中的进展，我会逐渐向你展示更多的 API。

如果你运行`npm t`，你会看到测试失败，因为快照与`MessageList.test.js`不匹配。要重新生成它，请使用`-u`选项运行：

```js
npm t -- -u
```

然后，如果你打开并检查`test/__snapshots__/MessageList.test.js.snap`，你会看到`class="message"`在那里，这意味着组件已经被渲染：

```js
// Jest Snapshot v1, https://goo.gl/fbAQLP
exports['MessageList.test.js has the expected html structure 1'] = '
<ul>
  <li class="message">
    Cat
  </li>
</ul>
';
```

请记住，在可能存在副作用的情况下避免深度渲染，因为子组件的钩子，比如`created`和`mount`，将被触发，那里可能会有 HTTP 调用或其他副作用，我们不希望被调用。如果你想尝试一下我说的话，可以在`Message.vue`组件的`created`钩子中添加一个`console.log`：

```js
export default {
  props: ["message"],
  created() {
    console.log("CREATED!");
  }
};
```

然后，如果你再次用`npm t`运行测试，你会在终端输出中看到`"CREATED!"`文本。所以，要小心。

您可以在 GitHub 上找到本章的代码和示例（[`github.com/alexjoverm/vue-testing-series/tree/Test-fully-rendered-Vue-js-Components-in-Jest`](https://github.com/alexjoverm/vue-testing-series/tree/Test-fully-rendered-Vue-js-Components-in-Jest)）。


# 第三章：测试样式和结构

到目前为止，我们使用了**Jest 快照**进行测试（[`facebook.github.io/jest/docs/snapshot-testing.html`](https://facebook.github.io/jest/docs/snapshot-testing.html)）。在大多数情况下，这就是我们会使用的，但有时我们可能想要断言更具体的内容。

虽然你可以通过`cmp.vm`访问 Vue 实例（[`github.com/alexjoverm/vue-testing-series/blob/master/test/MessageList.test.js#L17`](https://github.com/alexjoverm/vue-testing-series/blob/master/test/MessageList.test.js#L17)），但你可以利用一系列工具来更轻松地进行操作。让我们看看我们能做什么。

# 包装对象

`Wrapper`是`vue-test-utils`的主要对象。它是由`mount`，`shallowMount`，`find`和`findAll`函数返回的类型。你可以在**这里**看到整个 API 和类型（[`github.com/vuejs/vue-test-utils/blob/v1.0.0-beta.27/packages/test-utils/types/index.d.ts`](https://github.com/vuejs/vue-test-utils/blob/v1.0.0-beta.27/packages/test-utils/types/index.d.ts)）。

## 查找和查找所有

`find`和`findAll`接受一个**选择器**（[`github.com/vuejs/vue-test-utils/blob/v1.0.0-beta.27/packages/test-utils/types/index.d.ts#L92`](https://github.com/vuejs/vue-test-utils/blob/v1.0.0-beta.27/packages/test-utils/types/index.d.ts#L92)）作为参数，它可以是 CSS 选择器，也可以是 Vue 组件。

因此，我们可以做一些事情，比如：

```js
let cmp = mount(MessageList);
expect(cmp.find(".message").element).toBeInstanceOf(HTMLElement);
// Or even call it multiple times
let el = cmp.find(".message").find("span").element;
// Although for the previous example, we could do it in one
let el = cmp.find(".message span").element;
```

## 断言结构和样式

让我们在`MessageList.test.js`中添加更多测试：

```js
it("is a MessageList component", () => {
  expect(cmp.is(MessageList)).toBe(true);
  // Or with CSS selector
  expect(cmp.is("ul")).toBe(true);
});
it("contains a Message component", () => {
  expect(cmp.contains(Message)).toBe(true);
  // Or with CSS selector
  expect(cmp.contains(".message")).toBe(true);
});
```

在这里，我们使用`is`来断言根组件类型，使用`contains`来检查子组件的存在。就像`find`一样，它们接收一个选择器，可以是 CSS 选择器或组件。

我们有一些工具来断言**Vue 实例**：

```js
it("Both MessageList and Message are vue instances", () => {
  expect(cmp.isVueInstance()).toBe(true);
  expect(cmp.find(Message).isVueInstance()).toBe(true);
});
```

现在我们将更详细地断言**结构**：

```js
it("Message element exists", () => {
  expect(cmp.find(".message").exists()).toBe(true);
});
it("Message is not empty", () => {
  expect(cmp.find(Message).isEmpty()).toBe(false);
});
it('Message has a class attribute set to "message"', () => {
  expect(cmp.find(Message).attributes().class).toBe("message");
});
```

`exists`，`isEmpty`和`attributes`方法对此非常有用。

然后，我们有`classes`和`attributes().style`来断言**样式**。让我们用样式更新`Message.vue`组件，因为`attributes().style`只断言内联样式：

```js
<li style="margin-top: 10px" class="message">{{message}}</li>
```

以下是测试：

```js
it("Message component has the .message class", () => {
  expect(cmp.find(Message).classes()).toContain("message");
});
it("Message component has style padding-top: 10", () => {
  expect(cmp.find(Message).attributes().style).toBe("padding-top: 10px;");
});
```

有一堆工具可以让测试 Vue 组件变得更容易。你可以在**类型文件**中找到它们（[`github.com/vuejs/vue-test-utils/blob/v1.0.0-beta.27/packages/test-utils/types/index.d.ts`](https://github.com/vuejs/vue-test-utils/blob/v1.0.0-beta.27/packages/test-utils/types/index.d.ts)）。

您可以在 **GitHub** 上找到本章的工作代码（[`github.com/alexjoverm/vue-testing-series/blob/Test-Styles-and-Structure-in-Vue-js-and-Jest/test/MessageList.test.js`](https://github.com/alexjoverm/vue-testing-series/blob/Test-Styles-and-Structure-in-Vue-js-and-Jest/test/MessageList.test.js)）。


# 第四章：测试属性和自定义事件

有不同的方法来测试属性、事件和自定义事件。

属性是从父组件传递到子组件的自定义属性。自定义事件则恰恰相反：它们通过事件将数据发送到直接父级。当它们结合在一起时，它们是 Vue.js 组件中交互和通信的线路。

在单元测试中，测试内部和外部（属性和自定义事件）意味着测试组件在隔离状态下接收和发送数据的行为。所以，让我们动手吧。

# 属性

当我们测试组件属性时，我们可以测试当我们传递某些属性时组件的行为。然而，在继续之前，请考虑这个重要的注意事项：

要将属性传递给组件，请使用`propsData`而不是`props`。后者用于定义属性，而不是传递数据。

首先，创建一个`Message.test.js`文件并添加以下代码：

```js
describe("Message.test.js", () => {
  let cmp;
  describe("Properties", () => {
    // @TODO
  });
});
```

我们在`describe`表达式中对测试用例进行分组，它们可以被嵌套。因此，我们可以使用这种策略来分别对属性和事件进行分组测试。

然后，我们将创建一个辅助工厂函数来创建一个消息组件，并给它一些属性：

```js
const createCmp = propsData => mount(Message, { propsData });
```

## 测试属性的存在性

我们可以测试的最明显的事情是属性是否存在。记住`Message.vue`组件有一个`message`属性，所以让我们假设它正确接收了该属性。vue-test-utils 带有一个`hasProp(prop, value)`函数，对于这种情况非常方便：

```js
it("has a message property", () => {
  cmp = createCmp({ message: "hey" });
  expect(cmp.hasProp("message", "hey")).toBeTruthy();
});
```

属性的行为是这样的，只有在组件中声明了它们才会被接收。这意味着如果我们传递了一个未定义的属性，那么它就不会被接收。因此，要检查属性的不存在，可以使用一个不存在的属性：

```js
it("has no cat property", () => {
  cmp = createCmp({ cat: "hey" });
  expect(cmp.hasProp("cat", "hey")).toBeFalsy();
});
```

然而，在这种情况下，测试将失败，因为 Vue 具有非 props 属性。这将其设置为`Message`组件的根部，因此被识别为一个 prop，因此测试将返回`true`。将其更改为`toBeTruty`将使其通过此示例：

```js
it("has no cat property", () => {
  cmp = createCmp({ cat: "hey" });
  expect(cmp.hasProp("cat", "hey")).toBeTruthy();
});
```

我们也可以测试**默认值**。转到`Message.vue`并将`props`更改如下：

```js
props: {
  message: String,
  author: {
    type: String,
    default: 'Paco'
  }
},
```

然后，测试可以如下所示：

```js
it("Paco is the default author", () => {
  cmp = createCmp({ message: "hey" });
  expect(cmp.hasProp("author", "Paco")).toBeTruthy();
});
```

## 断言属性验证

属性可以具有验证规则，确保属性是必需的或者是确定类型的。让我们将`message`属性编写如下：

```js
props: {
  message: {
    type: String,
    required: true,
    validator: message => message.length > 1
  }
}
```

更进一步，您可以使用自定义构造函数类型或自定义验证规则，如您可以在`文档`中看到的（[`vuejs.org/v2/guide/components.html#Prop-Validation`](https://vuejs.org/v2/guide/components.html#Prop-Validation)）。现在不要这样做；我只是举个例子：

```js
class Message {}

props: {
  message: {
    type: Message, // It's compared using instance of
    ...
    }
  }
}
```

每当验证规则不满足时，Vue 会显示`console.error`。例如，对于`createCmp({ message: 1 })`，错误将如下所示：

```js
 [Vue warn]: Invalid prop: type check failed for prop "message". Expected String, got Number.
(found in <Root>)
```

在撰写本文时，`vue-test-utils`没有用于测试这一点的实用程序。我们可以使用`jest.spyOn`来代替测试：

```js
it("message is of type string", () => {
  let spy = jest.spyOn(console, "error");
  cmp = createCmp({ message: 1 });
  expect(spy).toBeCalledWith(
    expect.stringContaining("[Vue warn]: Invalid prop")
  );
  spy.mockReset(); // or mockRestore() to completely remove the mock
});
```

在这里，我们正在监视`console.error`函数，并检查它是否显示包含特定字符串的消息。这不是检查它的理想方式，因为我们正在监视全局对象并依赖副作用。

幸运的是，有一种更简单的方法来做到这一点，那就是通过检查`vm.$options`。这是 Vue 存储的组件选项的扩展。通过扩展，我的意思是您可以以不同的方式定义属性：

```js
props: ["message"];
// or
props: {
  message: String;
}
// or
props: {
  message: {
    type: String;
  }
}
```

但它们最终都会以最扩展的对象形式结束（例如最后一个）。因此，如果我们检查第一个案例的`cmp.vm.$option.props.message`，它们都将以`{ type: X }`格式存在（尽管对于第一个示例，它将是`{ type: null}`）。

考虑到这一点，我们可以编写一个测试套件来测试`message`属性是否具有预期的验证规则：

```js
describe('Message.test.js', () => {
  ...
  describe('Properties', () => {
    ...
    describe('Validation', () => {
      const message = createCmp().vm.$options.props.message
      it('message is of type string', () => {
       expect(message.type).toBe(String)
      })
      it('message is required', () => {
        expect(message.required).toBeTruthy()
      })
      it('message has at least length 2', () => {
        expect(message.validator && message.validator('a')).toBeFalsy()
        expect(message.validator && message.validator('aa')).toBeTruthy()
      })
    })
```

# 自定义事件

我们可以在自定义事件中测试至少两件事：

+   断言在动作之后触发了事件

+   检查事件监听器在触发时是否调用

在`MessageList.vue`和`Message.vue`组件示例中，这被翻译为以下内容：

+   断言`Message`组件在单击消息时触发`message-clicked`。

+   检查`MessageList`以确保当触发`message-clicked`时，会调用`handleMessageClick`函数

首先，转到`Message.vue`并使用`$emit`来触发自定义事件：

```js
<template>
  <li
    style="margin-top: 10px"
    class="message"
    @click="handleClick">
      {{message}}
  </li>
</template>
<script>
export default {
  name: "Message",
  props: ["message"],
  methods: {
    handleClick() {
      this.$emit("message-clicked", this.message)
    }
  }
};
</script>
```

然后，在`MessageList.vue`中，使用`@message-clicked`处理事件：

```js
<template>
  <ul>
    <Message
      @message-clicked="handleMessageClick"
      :message="message"
      v-for="message in messages"
      :key="message"/>
  </ul>
</template>
<script>
import Message from "./Message";
export default {
  name: "MessageList",
  props: ["messages"],
  methods: {
    handleMessageClick(message) {
      console.log(message)
    }
  },
  components: {
    Message
  }
};
</script>
```

现在是时候编写单元测试了。在`test/Message.spec.js`文件中创建一个嵌套的`describe`，并准备前面提到的*"断言`Message`组件在单击消息时触发`message-clicked`"*的基本内容：

```js
describe("Message.test.js", () => {
  describe("Events", () => {
    beforeEach(() => {
      cmp = createCmp({ message: "Cat" });
    });
    it("calls handleClick when click on message", () => {
      // @TODO
    });
  });
});
```

## 测试事件点击是否调用了方法处理程序

我们可以测试的第一件事是，当点击消息时，`handleClick`函数是否被调用。为此，我们可以使用包装组件的`trigger`和使用`spyOn`函数的 Jest 间谍：

```js
it("calls handleClick when click on message", () => {
  const spy = spyOn(cmp.vm, "handleClick");
  cmp.update(); // Forces to re-render, applying changes on template
  const el = cmp.find(".message").trigger("click");
  expect(cmp.vm.handleClick).toBeCalled();
});
```

查看`cmp.update()`。当我们更改模板中使用的内容 - 在这种情况下是`handleClick` - 并且我们希望模板应用这些更改时，我们需要使用`update`函数。

请记住，通过使用间谍，将调用原始的`handleClick`方法。你可能有意想要这样做；然而，通常情况下，我们希望避免这种情况，只需检查点击时是否确实调用了该方法。为此，我们可以使用 Jest Mock 函数：

```js
it("calls handleClick when click on message", () => {
  cmp.vm.handleClick = jest.fn();
  cmp.update();
  const el = cmp.find(".message").trigger("click");
  expect(cmp.vm.handleClick).toBeCalled();
});
```

在这里，我们完全替换了`vm`的`mount`函数返回的包装组件上可访问的`handleClick`方法。

我们可以通过使用官方工具提供的`setMethods`助手来使其更加简单：

```js
it("calls handleClick when click on message", () => {
  const stub = jest.spy();
  cmp.setMethods({ handleClick: stub });
  cmp.update();
  const el = cmp.find(".message").trigger("click");
  expect(stub).toBeCalled();
});
```

使用`setMethods`是建议的方法，因为它是官方工具在 Vue 内部发生变化时提供给我们的抽象。

## 测试自定义事件 message-clicked 是否被触发

我们已经测试了点击方法是否调用了其处理程序，但我们还没有测试处理程序是否发出了`message-clicked`事件。我们可以直接调用`handleClick`方法，并结合 Vue 的`vm` `$on`方法使用 Jest Mock 函数：

```js
it("triggers a message-clicked event when a handleClick method is called", () => {
  const stub = jest.fn();
  cmp.vm.$on("message-clicked", stub);
  cmp.vm.handleClick();
  expect(stub).toBeCalledWith("Cat");
});
```

请注意，这里我们使用了`toBeCalledWith`，因此我们可以确切断言我们期望的参数，使测试更加健壮。这并不是说我们在这里没有使用`cmp.update()`，因为我们没有进行需要传播到模板的更改。

## 测试@message-clicked 是否触发了事件

对于自定义事件，我们不能使用`trigger`方法，因为它只适用于 DOM 事件。但是，我们可以通过获取`Message`组件并使用其`vm.$emit`方法来自己发出事件。因此，在`MessageList.test.js`中添加以下测试：

```js
it("Calls handleMessageClick when @message-click happens", () => {
  const stub = jest.fn();
  cmp.setMethods({ handleMessageClick: stub });
  cmp.update();
  const el = cmp.find(Message).vm.$emit("message-clicked", "cat");
  expect(stub).toBeCalledWith("cat");
});
```

我将把测试`handleMessageClicked`的工作留给你。

# 总结

在本章中，我们探讨了测试属性和事件的几种情况。`vue-test-utils`，官方的 Vue 测试工具，确实使这变得更加容易。

你可以在**GitHub**上找到我们使用的工作代码（[`github.com/alexjoverm/vue-testing-series/tree/Test-Properties-and-Custom-Events-in-Vue-js-Components-with-Jest`](https://github.com/alexjoverm/vue-testing-series/tree/Test-Properties-and-Custom-Events-in-Vue-js-Components-with-Jest)）。


# 第五章：测试计算属性和观察者

计算属性和观察者是 Vue.js 组件逻辑的响应式部分。它们各自具有完全不同的目的，即一个是同步的，另一个是异步的，这使它们的行为略有不同。

在本章中，我们将介绍测试它们的过程，并看看在这一过程中我们可以找到哪些不同的情况。

# 计算属性

计算属性是简单的响应式函数，以另一种形式返回数据。它们的行为与语言标准的`get/set`属性完全相同：

```js
class X {
  get fullName() {
    return `${this.name} ${this.surname}`;
  }
  set fullName(value) {
    // ...
  }
}
```

当您使用普通对象时，情况如下：

```js
export default {
  computed: {
    fullName() {
      return `${this.name} ${this.surname}`;
    }
  }
};
```

您甚至可以添加`set`属性如下：

```js
export default {
  computed: {
    fullName: {
      get() {
        return `${this.name} ${this.surname}`;
      },
      set(value) {
        // ...
      }
    }
  }
};
```

## 测试计算属性

测试计算属性非常简单。有时，您可能不会单独测试计算属性，而是将其作为其他测试的一部分进行测试。但是，大多数情况下最好为其编写测试；无论该计算属性是清理输入还是组合数据，我们都希望确保它按预期工作。所以，让我们开始吧。

首先，创建一个`Form.vue`组件：

```js
<template>
  <div>
    <form>
      <input type="text" v-model="inputValue">
      <span class="reversed">{{ reversedInput }}</span>
    </form>
  </div>
</template>
<script>
export default {
  props: ["reversed"],
  data: () => ({
    inputValue: ""
  }),
  computed: {
    reversedInput() {
      return this.reversed ?
        this.inputValue.split("").reverse().join("") :
        this.inputValue;
    }
  }
};
</script>
```

它将显示一个输入框，旁边是相同的字符串但是反转的。这只是一个愚蠢的例子，但足够测试了。

现在，将其添加到`App.vue`，然后将其放在`MessageList`组件之后，并记得导入它并在`components`组件选项中包含它。然后，创建一个带有我们在其他测试中使用过的基本结构的`test/Form.test.js`文件：

```js
import { shallowMount } from "@vue/test-utils";
import Form from "../src/components/Form";
describe("Form.test.js", () => {
  let cmp;
  beforeEach(() => {
    cmp = shallowMount(Form);
  });
});
```

现在，创建一个包含两个测试用例的测试套件：

```js
describe("Properties", () => {
  it("returns the string in normal order if reversed property is not true", () => {
    cmp.setData({ inputValue: "Yoo" });
    expect(cmp.vm.reversedInput).toBe("Yoo");
  });
  it("returns the reversed string if reversed property is true", () => {
    cmp.setData({ inputValue: "Yoo" });
    cmp.setProps({ reversed: true });
    expect(cmp.vm.reversedInput).toBe("ooY");
  });
});
```

我们可以在`cmp.vm`中访问组件实例，以便访问内部状态、计算属性和方法。然后，测试就是改变值并确保在`reversed`为`false`时返回相同的字符串。

对于第二种情况，几乎相同，唯一的区别是我们必须将`reversed`属性设置为`true`。我们可以通过`cmp.vm...`进行导航来更改它，但`vue-test-utils`给了我们一个辅助方法`setProps({ property: value, ... })`，这使得它非常容易。

就是这样；根据计算属性的不同，可能需要更多的测试用例。

# 观察者

老实说，我还没有遇到过真正需要使用观察者的测试用例，而我的计算属性无法解决的。我也看到它们被滥用，导致组件之间的数据工作流非常不清晰，搞乱了一切。因此，不要急着使用它们，事先考虑一下。

正如您在 Vue.js 文档中所看到的（[`vuejs.org/v2/guide/computed.html#Watchers`](https://vuejs.org/v2/guide/computed.html#Watchers)），观察者经常用于对数据变化做出反应并执行异步操作，比如执行 ajax 请求。

## 测试观察者

假设我们希望在状态中的`inputValue`发生变化时执行某些操作。我们可以执行 ajax 请求，但由于那更复杂（我们将在下一课中更详细地介绍），所以让我们只使用`console.log`函数。在`Form.vue`组件选项中添加一个`watch`属性：

```js
watch: {
  inputValue(newVal, oldVal) {
    if (newVal.trim().length && newVal !== oldVal) {
      console.log(newVal)
    }
  }
}
```

注意`inputValue`观察者函数与状态变量名称匹配。按照惯例，Vue 将通过使用观察者函数名称，在这种情况下是`inputValue`，在`properties`和`data`状态中查找它，并且由于它将在`data`中找到它，它将在那里添加观察者。

请注意，观察者函数将新值作为第一个参数，旧值作为第二个参数。在这种情况下，我们选择仅在值不为空且值不同的情况下记录。通常，我们会根据您的时间和代码的重要性来为每种情况编写测试。

那么，我们应该测试观察者函数的什么内容呢？嗯，这也是我们在下一课中讨论测试方法时会进一步讨论的内容，但让我们假设我们只想知道它在应该调用`console.log`时是否调用。因此，让我们在`Form.test.js`中添加观察者测试套件的基本内容，如下所示：

```js
describe("Form.test.js", () => {
  let cmp;
  describe("Watchers - inputValue", () => {
    let spy;
    beforeAll(() => {
      spy = jest.spyOn(console, "log");
    });
    afterEach(() => {
      spy.mockClear();
    });
    it("is not called if value is empty (trimmed)", () => {
      // TODO
    });
    it("is not called if values are the same", () => {
      // TODO
    });
    it("is called with the new value in other cases", () => {
      // TODO
    });
  });
});
```

在这里，我们使用了`console.log`方法的 spy，在开始任何测试之前对其进行初始化，然后在每个测试之后重置其状态，以便它们从一个干净的 spy 开始。

要测试观察者函数，我们只需要改变被观察的值，这种情况下就是`inputValue`状态。但有一件有趣的事情...让我们从最后一个测试开始：

```js
it("is called with the new value in other cases", () => {
  cmp.vm.inputValue = "foo";
  expect(spy).toBeCalled();
});
```

在这里，我们改变了`inputValue`，所以`console.log` spy 应该被调用，对吗？嗯，它不会被调用。但等等，这有一个解释：与计算属性不同，观察者被*延迟到下一个更新周期*，Vue 用它来查找变化。因此，基本上这里发生的是`console.log`确实被调用，但在测试结束后才被调用。

请注意，我们通过访问`vm`属性以*原始*方式改变了`inputValue`。如果我们想以这种方式做，我们需要使用`vm.$nextTick`（[`vuejs.org/v2/api/#vm-nextTick`](https://vuejs.org/v2/api/#vm-nextTick)）函数将代码推迟到下一个更新周期：

```js
it("is called with the new value in other cases", done => {
  cmp.vm.inputValue = "foo";
  cmp.vm.$nextTick(() => {
    expect(spy).toBeCalled();
    done();
  });
});
```

*请注意这里我们调用了*作为参数接收到的`done` *函数。这是* **Jest 的一种方式** *（[`jestjs.io/docs/en/asynchronous.html`](https://jestjs.io/docs/en/asynchronous.html)）可以测试异步代码。*

然而，有**更好的方法**。`vue-test-utils`给我们的方法，比如`emitted`或`setData`，在幕后处理了这个问题。这意味着最后一个测试可以通过简单地使用`setData`来更清晰地编写：

```js
it("is called with the new value in other cases", () => {
  cmp.setData({ inputValue: "foo" });
  expect(spy).toBeCalled();
});
```

我们也可以对下一个测试应用相同的策略，唯一的区别是间谍不应该被调用：

```js
it("is not called if value is empty (trimmed)", () => {
  cmp.setData({ inputValue: "   " });
  expect(spy).not.toBeCalled();
});
```

最后，测试*如果值相同则不调用*的情况会更复杂一些。默认的内部状态是空的；因此，首先，我们需要改变它，等待下一个时刻，然后清除模拟以重置调用计数，并再次改变它。然后，在第二个时刻之后，我们可以检查间谍并完成测试。

如果我们在开始时重新创建组件，覆盖`data`属性，这将简单得多。请记住，我们可以通过使用`mount`或`shallowMount`函数的第二个参数来覆盖任何组件选项：

```js
it("is not called if values are the same", () => {
  cmp = shallowMount(Form, {
    data: () => ({ inputValue: "foo" })
  });
  cmp.setData({ inputValue: "foo" });
  expect(spy).not.toBeCalled();
});
```

# 总结

在本章中，您已经学会了如何测试 Vue 组件的一部分逻辑：计算属性和观察者。我们已经经历了不同的示例测试用例，这些测试用例在测试它们两者时可能会遇到。您还了解了一些 Vue 内部知识，比如`nextTick`更新周期。

您可以在**GitHub**上找到本章的代码（[`github.com/alexjoverm/vue-testing-series/tree/Test-State-Computed-Properties-and-Methods-in-Vue-js-Components-with-Jest`](https://github.com/alexjoverm/vue-testing-series/tree/Test-State-Computed-Properties-and-Methods-in-Vue-js-Components-with-Jest)）。


# 第六章：测试方法和模拟依赖

在方法中我们应该测试什么？这是我们开始进行单元测试时遇到的问题。一切归结为*测试该方法做了什么，只有那个*。这意味着我们需要*避免调用任何依赖项*，因此我们需要对它们进行模拟。

让我们在上一章中创建的`Form.vue`组件中的表单中添加一个`submit`事件：

```js
<form @submit.prevent="onSubmit(inputValue)"></form>
```

`.prevent`修饰符只是一种方便的方式来调用`event.preventDefault()`，以便它不会重新加载页面。现在，进行一些修改来调用 API，然后通过向数据添加一个`results`数组和一个`onSubmit`方法来存储结果：

```js
export default {
  data: () => ({
    inputValue: "",
    results: []
  }),
  methods: {
    onSubmit(value) {
      axios
        .get("https://jsonplaceholder.typicode.com/posts?q=" + value)
        .then(results => {
          this.results = results.data;
        });
    }
  }
};
```

在这里，该方法使用`axios`执行对`jsonplaceholder`的**posts**端点的 HTTP 调用，这只是这种示例的 RESTful API。另外，通过`q`查询参数，我们可以使用提供的`value`参数搜索帖子。

用于测试`onSubmit`方法：

+   我们不希望调用`axios.get`实际方法。

+   我们希望检查它是否调用了 axios（但不是真正的 axios），并且它返回一个`promise`。

+   该`promise`回调应将`this.results`设置为承诺的结果。

当您有外部依赖项以及返回承诺并在其中执行操作时，这可能是最难测试的事情之一。我们需要做的是**模拟外部依赖项**。

# 模拟外部模块依赖

Jest 提供了一个非常好的模拟系统，可以让您以非常方便的方式模拟所有内容。事实上，您不需要任何额外的库来做到这一点。我们已经看到了`jest.spyOn`和`jest.fn`用于监视和创建存根函数，尽管这对于这种情况还不够。

在这里，我们需要模拟整个`axios`模块。这就是`jest.mock`发挥作用的地方。它允许我们通过在文件顶部编写来轻松模拟模块依赖项：

```js
jest.mock("dependency-path", implementationFunction);
```

您必须知道`jest.mock`*是被提升的*，这意味着它将被放置在顶部：

```js
jest.mock("something", jest.fn);
import foo from "bar";
// ...
```

因此，前面的代码等效于这个：

```js
import foo from "bar";
jest.mock("something", jest.fn); // this will end up above all imports and everything
// ...
```

在撰写本文时，我仍然没有在互联网上找到有关如何在 Jest 中执行我们将在这里执行的操作的信息。幸运的是，您不必经历同样的挣扎。

让我们在`Form.test.js`测试文件的顶部编写`axios`的模拟和相应的测试用例：

```js
jest.mock("axios", () => ({
  get: jest.fn()
}));
import { shallowMount } from "@vue/test-utils";
import Form from "../src/components/Form";
import axios from "axios"; // axios here is the mock from above!
// ...
it("Calls axios.get", () => {
  cmp.vm.onSubmit("an");
  expect(axios.get).toBeCalledWith(
    "https://jsonplaceholder.typicode.com/posts?q=an"
  );
});
```

这很棒。我们确实在模拟`axios`，所以原始的 axios 没有被调用，也没有任何 HTTP 被调用。而且我们甚至通过使用`toBeCalledWith`来检查它是否被正确地调用了。然而，我们仍然缺少一些东西：*我们没有检查它是否返回了* `promise`。

首先，我们需要让我们模拟的`axios.get`方法返回一个`promise`。`jest.fn`接受一个工厂函数作为参数，所以我们可以用它来定义它的实现：

```js
jest.mock("axios", () => ({
  get: jest.fn(() => Promise.resolve({ data: 3 }))
}));
```

然而，我们仍然无法访问`promise`，因为我们没有返回它。在测试中，尽可能从函数中返回一些东西是一个好习惯，因为这样测试会更容易。所以，现在让我们在`Form.vue`组件的`onSubmit`方法中做这个：

```js
export default {
  methods: {
    // ...
    onSubmit(value) {
      const getPromise = axios.get(
        "https://jsonplaceholder.typicode.com/posts?q=" + value
      );
      getPromise.then(results => {
        this.results = results.data;
      });
      return getPromise;
    }
  }
};
```

然后，我们可以在测试中使用非常干净的 ES2017 `async/await`语法来检查 promise 的结果：

```js
it("Calls axios.get and checks promise result", async () => {
  const result = await cmp.vm.onSubmit("an");
  expect(result).toEqual({ data: [3] });
  expect(cmp.vm.results).toEqual([3]);
  expect(axios.get).toBeCalledWith(
    "https://jsonplaceholder.typicode.com/posts?q=an"
  );
});
```

在这里，你可以看到我们不仅检查了 promise 的结果，还检查了组件的`results`内部状态是否按预期更新，通过`expect(cmp.vm.results).toEqual([3])`。

# 保持模拟外部化

Jest 允许我们将所有的模拟分开放在自己的 JavaScript 文件中，将它们放在`__mocks__`文件夹下，并尽可能保持测试的干净。

因此，我们可以将`Form.test.js`文件顶部的`jest.mock...`块移到自己的文件中：

```js
// test/__mocks__/axios.js
module.exports = {
  get: jest.fn(() => Promise.resolve({ data: [3] }))
};
```

就像这样，而且不需要额外的努力，Jest 会自动在所有的测试中应用模拟，这样我们就不必做任何额外的事情，或者在每个测试中手动模拟它。请注意，模块名称必须与文件名匹配。如果再次运行测试，它们应该仍然通过。

请记住，模块注册表和模拟状态保持不变，因此，如果之后再编写另一个测试，可能会得到不良的结果：

```js
it("Calls axios.get", async () => {
  const result = await cmp.vm.onSubmit("an");
  expect(result).toEqual({ data: [3] });
  expect(cmp.vm.results).toEqual([3]);
  expect(axios.get).toBeCalledWith(
    "https://jsonplaceholder.typicode.com/posts?q=an"
  );
});
it("Axios should not be called here", () => {
  expect(axios.get).toBeCalledWith(
    "https://jsonplaceholder.typicode.com/posts?q=an"
  );
});
```

第二个测试应该失败，但它没有。那是因为在测试之前调用了`axios.get`。

因此，清理模块注册表和模拟是一个好习惯，因为它们是由 Jest 操纵的，以便进行模拟。为此，你可以在`beforeEach`中添加：

```js
beforeEach(() => {
  cmp = shallowMount(Form);
  jest.resetModules();
  jest.clearAllMocks();
});
```

这将确保每个测试都从干净的模拟和模块开始，这在单元测试中应该是这样的。

# 总结

Jest 的模拟功能，以及快照测试，是我最喜欢的两个功能。因为它们使通常很难测试的东西变得非常容易，让你可以专注于编写更快速和更好隔离的测试，保持你的代码库无懈可击。

你可以在**GitHub**上找到本章的所有代码（[`github.com/alexjoverm/vue-testing-series/tree/Test-State-Computed-Properties-and-Methods-in-Vue-js-Components-with-Jest`](https://github.com/alexjoverm/vue-testing-series/tree/Test-State-Computed-Properties-and-Methods-in-Vue-js-Components-with-Jest)）。


# 第七章：测试 Vue.js 插槽

插槽是在 Web 组件世界中进行内容分发的一种方式。Vue.js 插槽是根据**Web 组件规范**制作的（[`github.com/w3c/webcomponents/blob/gh-pages/proposals/Slots-Proposal.md`](https://github.com/w3c/webcomponents/blob/gh-pages/proposals/Slots-Proposal.md)），这意味着如果你学会了如何在 Vue.js 中使用它们，它们将对你以后很有用。

它们使组件的结构更加灵活，将管理状态的责任转移到父组件。例如，我们可以有一个`List`组件，以及不同类型的项目组件，比如`ListItem`和`ListItemImage`。它们将被如下使用：

```js
<template>
  <List>
    <ListItem :someProp="someValue" />
    <ListItem :someProp="someValue" />
    <ListItemImage :image="imageUrl" :someProp="someValue" />
  </List>
</template>
```

`List`的内部内容就是插槽本身，可以通过`<slot>`标签访问。因此，`List`的实现如下：

```js
<template>
  <ul>
    <!-- slot here will equal to what's inside <List> -->
    <slot></slot>
  </ul>
</template>
```

现在，假设`ListItem`组件如下所示：

```js
<template>
  <li> {{ someProp }} </li>
</template>
```

然后，Vue.js 渲染的最终结果将是：

```js
<ul>
  <li> someValue </li>
  <li> someValue </li>
  <li> someValue </li> <!-- assume the same implementation for ListItemImage -->
</ul>
```

# 使 MessageList 基于插槽

现在，让我们来看看`MessageList.vue`组件：

```js
<template>
  <ul>
    <Message
      @message-clicked="handleMessageClick"
      :message="message"
      v-for="message in messages"
      :key="message"/>
  </ul>
</template>
```

`MessageList`在内部*硬编码*了`Message`组件。在某种程度上，这更加自动化，但在另一方面，它完全缺乏灵活性。如果你想要不同类型的`Message`组件怎么办？改变它们的结构或样式呢？这就是插槽派上用场的地方。

现在，让我们将`Message.vue`更改为使用插槽。首先，将`<Message...`部分移动到`App.vue`组件中，连同`handleMessageClick`方法，以便在外部使用：

```js
<template>
  <div id="app">
    <MessageList>
      <Message
        @message-clicked="handleMessageClick"
        :message="message"
        v-for="message in messages"
        :key="message"/>
    </MessageList>
  </div>
</template>
<script>
import MessageList from "./components/MessageList";
import Message from "./components/Message";
export default {
  name: "app",
  data: () => ({ messages: ["Hey John", "Howdy Paco"] }),
  methods: {
    handleMessageClick(message) {
      console.log(message);
    }
  },
  components: {
    MessageList,
    Message
  }
};
</script>
```

不要忘记导入`Message`组件，并将其添加到`App.vue`中的`components`选项中。

然后，在`MessageList.vue`中，我们可以删除对`Message`的引用。现在看起来如下：

```js
<template>
  <ul class="list-messages">
    <slot></slot>
  </ul>
</template>
<script>
export default {
  name: "MessageList"
};
</script>
```

# $children 和$slots

Vue 组件有两个实例变量，对于访问插槽非常有用：

+   `$children`：默认插槽的 Vue 组件实例数组

+   `$slots`：一个 VNodes 对象，映射了组件实例中定义的所有插槽

`$slots`对象有更多可用的数据。实际上，`$children`只是`$slots`变量的一部分，可以通过在`$slots.default`数组上进行映射，通过 Vue 组件实例进行过滤来访问相同的方式：

```js
const children = this.$slots.default
  .map(vnode => vnode.componentInstance)
  .filter(cmp => !!cmp);
```

# 测试插槽

我们可能最想测试的插槽方面是它们在组件中的位置，为此，我们可以重复在*第三章*中学到的技能，*在 Jest 中测试 Vue.js 组件的样式和结构*。

现在，`MessageList.test.js`中的大多数测试都会失败，所以让我们移除它们（或者将它们注释掉），并专注于插槽测试。

我们可以测试的一件事是确保`Message`组件最终出现在具有`list-messages`类的`ul`元素中。为了将插槽传递给`MessageList`组件，我们可以使用`mount`或`shallowMount`方法的`options`对象的`slots`属性。因此，让我们创建一个`beforeEach`方法（[`jestjs.io/docs/en/api.html#beforeeachfn-timeout`](https://jestjs.io/docs/en/api.html#beforeeachfn-timeout)），其中包含以下代码：

```js
beforeEach(() => {
  cmp = shallowMount(MessageList, {
    slots: {
      default: '<div class="fake-msg"></div>'
    }
  });
});
```

由于我们只想测试消息是否被渲染，我们可以按如下方式搜索`<div class="fake-msg"></div>`：

```js
it("Messages are inserted in a ul.list-messages element", () => {
  const list = cmp.find("ul.list-messages");
  expect(list.findAll(".fake-msg").length).toBe(1);
});
```

然后就可以进行了。插槽选项还接受组件声明，甚至是数组，所以我们可以编写以下内容：

```js
import AnyComponent from "anycomponent";
shallowMount(MessageList, {
  slots: {
    default: AnyComponent // or [AnyComponent, AnyComponent]
  }
});
```

这种方法的问题在于它非常有限；例如，您不能覆盖 props，而我们需要为`Message`组件做到这一点，因为它有一个必需的属性。这应该影响到您真正需要测试预期组件的插槽的情况；例如，如果您想确保`MessageList`只期望`Message`组件作为插槽。这是在正确的轨道上，并且在某个时候，它将出现在`vue-test-utils`中（[`github.com/vuejs/vue-test-utils/issues/41#issue-255235880`](https://github.com/vuejs/vue-test-utils/issues/41#issue-255235880)）。

作为一种解决方法，我们可以通过使用**渲染函数**（[`vuejs.org/v2/guide/render-function.html`](https://vuejs.org/v2/guide/render-function.html)）来实现这一点。因此，我们可以重写测试以更具体：

```js
beforeEach(() => {
  const messageWrapper = {
    render(h) {
      return h(Message, { props: { message: "hey" } });
    }
  };
  cmp = shallowMount(MessageList, {
    slots: {
      default: messageWrapper
    }
  });
});
it("Messages are inserted in a MessageList component", () => {
  const list = cmp.find(MessageList);
  expect(list.find(Message).isVueInstance()).toBe(true);
});
```

# 测试命名插槽

我们之前使用的未命名插槽称为*默认插槽*，但我们可以通过使用命名插槽来拥有多个插槽。现在让我们给`MessageList.vue`组件添加一个标题：

```js
<template>
  <div>
    <header class="list-header">
      <slot name="header">
        This is a default header
      </slot>
    </header>
    <ul class="list-messages">
      <slot></slot>
    </ul>
  </div>
</template>
```

通过使用`<slot name="header">`，我们为标题定义了另一个插槽。您可以在插槽中看到`这是一个默认标题`文本。当未传递插槽给组件时，这将显示为默认内容，并且适用于默认插槽。

然后，从`App.vue`中，我们可以通过使用`slot="header"`属性为`MessageList`组件添加一个标题：

```js
<template>
  <div id="app">
    <MessageList>
      <header slot="header">
        Awesome header
      </header>
      <Message
        @message-clicked="handleMessageClick"
        :message="message"
        v-for="message in messages"
        :key="message"/>
    </MessageList>
  </div>
</template>
```

现在是时候为它编写一个单元测试了。测试命名插槽就像测试默认插槽一样；相同的动态适用。因此，我们可以首先验证标题插槽是否在`<header class="list-header">`元素内呈现，并且在没有传递标题插槽时呈现默认文本。在`MessageList.test.js`中，我们有以下内容：

```js
it("Header slot renders a default header text", () => {
  const header = cmp.find(".list-header");
  expect(header.text().trim()).toBe("This is a default header");
});
```

然后，相同的，但是在我们模拟`header`插槽时检查默认内容是否被替换：

```js
it("Header slot is rendered withing .list-header", () => {
  const component = shallowMount(MessageList, {
    slots: {
      header: "<div>What an awesome header</div>"
    }
  });
  const header = component.find(".list-header");
  expect(header.text().trim()).toBe("What an awesome header");
});
```

我们可以看到在最后一个测试中使用的标题插槽被包裹在`<div>`中。插槽被包裹在 HTML 标记中非常重要，否则`vue-test-utils`会抱怨。

# 测试上下文插槽规范

我们已经测试了插槽的渲染方式和位置，这可能是最重要的方面。然而，事情并不止于此。如果您将组件实例作为插槽传递，就像我们在`Message`默认插槽中所做的那样，您可以测试与它们相关的功能。

在这里要小心测试什么。这在大多数情况下可能是您不需要做的事情，因为组件的功能测试应该属于该组件的测试范畴。当谈到测试插槽功能时，我们测试插槽在*使用该插槽的组件的上下文中*应该如何行为，这是不太常见的。通常，我们只是传递插槽然后忘记它。所以，不要对下面的示例过于执着 - 它的唯一目的是演示工具的工作原理。

假设出于某种原因，在`MessageList`组件的上下文中，所有`Message`组件的长度都必须大于 5。我们可以这样测试：

```js
it("Message length is higher than 5", () => {
  const messages = cmp.findAll(Message);
  messages.wrappers.forEach(c => {
    expect(c.vm.message.length).toBeGreaterThan(5);
  });
});
```

`findAll`返回一个包含`wrappers`数组的对象，我们可以访问其`vm`组件实例属性。这个测试将失败，因为消息的长度为 3，所以去`beforeEach`函数并使其更长：

```js
beforeEach(() => {
  const messageWrapper = {
    render(h) {
      return h(Message, { props: { message: "hey yo" } });
    }
  };
});
```

然后，它应该通过。

# 总结

测试插槽非常简单。通常，我们希望测试它们是否按照我们的期望放置和渲染，因此这就像测试样式和结构一样，了解插槽的行为或可以进行模拟。您很可能不需要经常测试插槽功能。

请记住，只有在想要测试插槽并且三思而后行时，才应该测试与插槽相关的事物是否属于插槽测试还是组件测试本身。

您可以在 **GitHub** 上找到与本章相关的代码（[`github.com/alexjoverm/vue-testing-series/tree/test-slots`](https://github.com/alexjoverm/vue-testing-series/tree/test-slots)）。


# 第八章：使用模块别名增强 Jest 配置

我们在 JavaScript 社区中拥有的模块管理器，主要是 ES 模块和 CommonJS，并不支持基于项目的路径。它们只支持我们自己模块的相对路径和 `node_modules` 文件夹的路径。当项目稍微增长时，通常会看到以下路径：

```js
import SomeComponent from "../../../../components/SomeComponent";
```

幸运的是，我们有不同的方法来应对这个问题，以便我们可以为相对于项目根目录的文件夹定义别名，这样我们可以将前一行写成如下形式：

```js
import SomeComponent from "@/components/SomeComponent";
```

在这里，`@` 是一个任意字符，用于定义根项目。您可以自行定义。让我们看看我们有哪些可用的解决方案来应用模块别名。让我们从**上一章**中离开的地方开始（[`github.com/alexjoverm/vue-testing-series/tree/test-slots`](https://github.com/alexjoverm/vue-testing-series/tree/test-slots)）。

# Webpack 别名

**Webpack 别名** ([`webpack.js.org/configuration/resolve/#resolve-alias`](https://webpack.js.org/configuration/resolve/#resolve-alias)) 设置非常简单。您只需要在 webpack 配置中添加一个 `resolve.alias` 属性。如果您查看 `build/webpack.base.conf.js`，您会发现它已经定义了：

```js
module.exports = {
  // ...
  resolve: {
    extensions: [".js", ".vue", ".json"],
    alias: {
      vue$: "vue/dist/vue.esm.js"
    }
  }
};
```

以此为起点，我们可以添加一个简单的别名，指向 `src` 文件夹，并将其用作根目录：

```js
module.exports = {
  // ...
  resolve: {
    extensions: [".js", ".vue", ".json"],
    alias: {
      vue$: "vue/dist/vue.esm.js",
      "@": path.join(__dirname, "..", "src")
    }
  }
};
```

仅凭此，我们就可以访问任何东西，以根项目作为 `@` 符号。让我们去 `src/App.vue` 并更改对这两个组件的引用：

```js
import MessageList from "@/components/MessageList";
import Message from "@/components/Message";
// ...
```

如果我们运行 `npm start` 并在 `localhost:8080` 打开浏览器，那应该可以直接使用。

然而，如果我们尝试通过运行 `npm t` 来运行测试，我们会发现 Jest 找不到模块。我们还没有配置 Jest 来做这个。因此，让我们去 `package.json`，Jest 配置所在的地方，并将 `"@/([^\\.]*)$": "<rootDir>/src/$1"` 添加到 `moduleNameMapper` 中：

```js
{
  "jest": {
    "moduleNameMapper": {
      "@(.*)$": "<rootDir>/src/$1",
      "^vue$": "vue/dist/vue.common.js"
    }
  }
}
```

以下是前面代码片段的解释：

+   `@(.*)$`：任何以 `@` 开头，并且继续以任何字符 (`(.*)$`) 直到字符串结束，通过使用括号进行分组。

+   `<rootDir>/src/$1`：`<rootDir>` 是 Jest 的特殊词，表示根目录。然后，我们将其映射到 `src`，并且使用 `$1`，我们将 `(.*)` 语句中的任何子句附加上去。

例如，当你从 `src` 或 `test` 文件夹导入时，`@/components/MessageList` 将被映射到 `../src/components/MessageList`。

就是这样。现在，你甚至可以更新你的`App.test.js`文件来使用别名，因为它也可以在测试中使用：

```js
import { shallowMount } from "@vue/test-utils";
import App from "@/App";
// ...
```

而且，它对`.vue`和`.js`文件都适用。

# 多个别名

经常使用多个别名以方便起见，所以不仅仅使用一个`@`来定义你的根文件夹，你可以使用多个。例如，假设你有一个`actions`文件夹和一个`models`文件夹。如果你为每个文件夹创建一个别名，然后移动文件夹，你只需要改变别名，而不是在代码库中更新所有对它的引用。这就是模块别名的威力 - 它们使得你的代码库更容易维护和更清晰。

现在，让我们在`build/webpack.base.conf.js`中添加一个`components`别名：

```js
module.exports = {
  // ...
  resolve: {
    extensions: [".js", ".vue", ".json"],
    alias: {
      vue$: "vue/dist/vue.esm.js",
      "@": path.join(__dirname, "..", "src"),
      components: path.join(__dirname, "..", "src", "components")
    }
  }
};
```

然后，我们只需要在`package.json`中的 Jest 配置中添加它：

```js
{
  "jest": {
    "moduleNameMapper": {
      "@(.*)$": "<rootDir>/src/$1",
      "components(.*)$": "<rootDir>/src/components/$1",
      "^vue$": "vue/dist/vue.common.js"
    }
  }
}
```

就是这么简单。现在，我们可以在`App.vue`中尝试使用两种形式：

```js
import MessageList from "components/MessageList";
import Message from "@/components/Message";
```

停止并重新运行测试，那应该可以工作。你也可以运行`npm start`来尝试一下。

# 其他解决方案

我看到了**babel-plugin-webpack-alias**（[`github.com/trayio/babel-plugin-webpack-alias`](https://github.com/trayio/babel-plugin-webpack-alias)），特别是用于其他测试框架，比如**mocha**（[`mochajs.org/`](https://mochajs.org/)），它没有模块映射。

我自己还没有尝试过，因为 Jest 已经为你提供了这个功能，但如果你已经这样做了，或者想尝试一下，请分享一下效果如何。

# 总结

添加模块别名非常简单，可以使你的代码库更清晰、更容易维护。Jest 也很容易定义它们；你只需要与 webpack 别名保持同步，然后你就可以告别点地狱的引用了。

你可以在**GitHub**上找到与本章相关的工作代码（[`github.com/alexjoverm/vue-testing-series/tree/Enhance-Jest-configuration-with-Module-Aliases`](https://github.com/alexjoverm/vue-testing-series/tree/Enhance-Jest-configuration-with-Module-Aliases)）。


# 第九章：快照测试

到目前为止，你已经看到了如何测试 Vue.js 组件的结构、样式、方法、计算属性、事件、观察者等等。你已经学会了通过使用各种技术和方法来做到这一点。

但如果我告诉你，你可以通过简单地使用快照测试来测试大部分内容呢？

你已经在*第一章，使用 Jest 编写第一个 Vue.js 组件单元测试*和*第二章，深度测试 Vue.js 组件*中看到了快照测试的使用，但这些章节更多地侧重于解释浅渲染和深渲染，所以我还没有详细解释过它。

快照测试是通过比较两个不同的输出来进行断言的技术。

把它想象成类似于端到端测试中用于检查回归的屏幕截图技术：第一次测试运行时会对屏幕的一部分（例如一个按钮）进行截图，从那一刻起，同一个测试的所有后续运行都会将新的截图与原始截图进行比较。如果它们相同，测试通过；否则就会有回归。

快照测试的工作方式类似，但它不是比较图像，而是比较可序列化的输出，比如 JSON 和 HTML，或者只是字符串。

由于 Vue.js 渲染 HTML，你可以使用快照测试来断言组件在不同状态下渲染的 HTML。

# 重新思考快照

对于这个例子，让我们考虑以下的`ContactBox.vue`组件：

```js
<template>
  <div :class="{ selected: selected }" @click="handleClick">
    <p>{{ fullName }}</p>
  </div>
</template>
<script>
  export default {
    props: ["id", "name", "surname", "selected"],
    computed: {
      fullName() {
        return `${this.name} ${this.surname}`;
      }
    },
    methods: {
      handleClick() {
        this.$emit("contact-click", this.id);
      }
    }
  };
</script>
```

在这种情况下，我们可以测试这个组件的几个方面：

+   `fullName`是`name` + `surname`的组合。

+   当组件被选中时，它具有`selected`类。

+   它会触发`contact-click`事件。

创建验证这些规范的测试的一种方法是分别检查所有内容 - 附加到 DOM 元素的类、HTML 结构、计算属性和状态。

正如你在其他章节中看到的，你可以按照以下方式执行这些测试：

```js
import { mount } from "vue-test-utils";
import ContactBox from "../src/components/ContactBox";
const createContactBox = (id, name, surname, selected) =>
  mount(ContactBox, {
    propsData: { id, name, surname, selected }
  });
describe("ContactBox.test.js", () => {
  it("fullName should be the combination of name + surname", () => {
    const cmp = createContactBox(0, "John", "Doe", false);
    expect(cmp.vm.fullName).toBe("John Doe");
  });
  it("should have a selected class when the selected prop is true", () => {
    const cmp = createContactBox(0, "John", "Doe", true);
    expect(cmp.classes()).toContain("selected");
  });
  it("should emit a contact-click event with its id when the component is clicked", () => {
    const cmp = createContactBox(0, "John", "Doe", false);
    cmp.trigger("click");
    const payload = cmp.emitted("contact-click")[0][0];
    expect(payload).toBe(0);
  });
});
```

但现在，让我们想一想快照测试如何帮助我们。

如果你仔细想想，组件会根据它的状态进行渲染。让我们把这称为**渲染状态**。

通过快照测试，我们可以不用担心检查特定的东西，比如属性、类、方法和计算属性，而是可以检查渲染状态，因为这是组件状态的预期结果。

为此，你可以按照以下方式对先前的测试使用快照测试：

```js
it("fullName should be the combination of name + surname", () => {
  const cmp = createContactBox(0, "John", "Doe", false);
  expect(cmp.element).toMatchSnapshot();
});
```

正如您所看到的，现在不再单独检查事物，我只是断言`cmp.element`的快照，这是组件的呈现 HTML。

如果您现在运行测试套件，应该已经创建了一个`ContactBox.test.js.snap`文件，并且您还会在控制台输出中看到一条消息：

![图 9.1](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/test-vue-cpn-jest/img/Image56419.jpg)

图 9.1

让我们分析生成的快照：

```js
// Jest Snapshot v1, https://goo.gl/fbAQLP
exports[
  `ContactBox.test.js fullName should be the combination of name + surname 1`
] = `
<div
  class=""
>
  <p>
    John Doe
  </p>
</div>
`;
```

这个测试的目的是检查计算属性`fullName`是否将名字和姓氏结合起来，用空格分隔。从快照中可以看出，这是发生的，*John Doe*在那里，所以您可以认为这个测试是有效的。

同样，您也可以使用快照测试编写第二个测试：

```js
it("should have a selected class when the selected prop is true", () => {
  const cmp = createContactBox(0, "John", "Doe", true);
  expect(cmp.element).toMatchSnapshot();
});
```

请注意，这个测试和上一个测试之间唯一改变的方面是将`selected`属性设置为`true`。

这就是快照测试的威力：您可以玩弄*组件的不同状态*，而只需断言呈现状态。

这个测试的目的是验证当属性为`true`时它是否具有`selected`类。现在，让我们再次运行测试套件，如果再次检查`ContactBox.test.js.snap`，您会看到另一个快照已经被添加：

```js
exports[
  `ContactBox.test.js should have a selected class when the selected prop is true 1`
] = `
<div
  class="selected"
>
  <p>
    John Doe
  </p>
</div>
`;
```

并且所选的类在那里，正如预期的那样，所以我们可以认为这个也是有效的。

# 当快照测试无法帮助时

您是否注意到我没有提及第三个测试？为了回忆这个测试，让我们再次检查它：

```js
it("should emit a contact-click with its id when the component is clicked", () => {
  const cmp = createContactBox(0, "John", "Doe", false);
  cmp.trigger("click");
  const payload = cmp.emitted("contact-click")[0][0];
  expect(payload).toBe(0);
});
```

在这种情况下，当组件被点击时，它不执行任何改变组件状态的操作，这意味着呈现状态不会改变。我们在这里只是测试对组件呈现没有影响的行为。

因此，我们可以说*快照测试对于检查呈现状态的变化是有用的*。如果呈现状态不改变，快照测试就无法帮助我们。

# 当测试失败时

生成的快照是决定测试是否有效的真相来源。这就是检查回归的方式，最终取决于您的标准。

例如，转到`ContactBox.vue`组件，并将`fullName`计算属性更改为用逗号分隔：

```js
fullName() {
  return `${this.name}, ${this.surname}`;
}
```

如果您再次运行测试，其中一些测试将失败，因为呈现结果与以前不同。您将收到以下类似的错误：

```js
Received value does not match stored snapshot 1.
  - Snapshot
  + Received
    <div
      class=""
    >
      <p>
  -    John Doe
  +    John, Doe
      </p>
    </div>
```

从那时起，通常与测试相关，你必须决定这是一个有意的变化还是一个回归。你可以按下*'u'*来更新快照：

![图 9.2](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/test-vue-cpn-jest/img/Image56429.jpg)

图 9.2

在应用 TDD 时使用观察模式`npm run test -- --watch`会很方便。这将非常方便，因为 Jest 为更新快照提供了许多选项：

+   按下**'u'**以更新所有快照。

+   按下**'i'**以交互方式逐个更新快照。

# 结论

快照测试**节省了大量时间**。这个例子很基础，但想象一下测试一个具有许多不同渲染状态的更复杂的组件...

当然，你可以针对特定事物进行断言，但这比根据状态断言组件的渲染方式要麻烦得多，因为大多数情况下，如果你改变了代码，就必须根据测试改变断言，而使用快照测试则不需要。

此外，你可以**发现**你没有考虑到的**回归**，也许是你在测试中没有考虑到的东西，或者是改变了组件的渲染，但快照会提醒你这一点。

我现在想提到一些你应该记住的**注意事项**：

+   快照测试并不取代特定的断言。虽然大多数情况下可以这样做，但两种测试方式完全可以结合使用。

+   不要太轻易地更新快照。如果你发现一个测试失败是因为它与快照不匹配，那么在太快更新之前，仔细研究一下。我也有过这样的经历。

如果你想自己尝试一下，你可以在**GitHub**上找到本章中使用的完整示例（[`github.com/alexjoverm/vue-testing-series/tree/chapter-9`](https://github.com/alexjoverm/vue-testing-series/tree/chapter-9)）。
