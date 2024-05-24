# React16 基础知识第二版（一）

> 原文：[`zh.annas-archive.org/md5/3e3e14982ed4c5ebe5505c84fd2fdbb9`](https://zh.annas-archive.org/md5/3e3e14982ed4c5ebe5505c84fd2fdbb9)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

自第一版 React Essentials 以来，React 生态系统发生了很多变化。越来越多的人正在构建 React 应用程序，有成熟的库和框架支持 React 应用程序，React 16 也已发布。React 在如此短的时间内的爆炸式增长可以归因于许多因素：优秀的社区和相关资源，React 生态系统的广泛性以及某些重要项目的成熟，当然还有 React 团队及其愿意将开发者反馈作为项目持续发展的优先事项。

我很荣幸能参与这样一本重要的 React 书籍。正如书名所示，本书旨在教授 React 的基础知识。这个最新版本反映了 React 最新版本的变化，使用 Redux 来管理状态，以及 JavaScript 语言本身的变化。

加入我吧。让我们成为 React 成为构建用户界面的标准的专家。

# 本书内容

第一章，*React 16 有什么新变化*，介绍了 React 16 的重大变化。这包括了底层渲染和协调工作的基本变化，以及通过 API 公开的其他新功能。

第二章，*为你的项目安装强大的工具*，概述了本书的目标，并解释了你需要安装哪些现代工具才能有效构建 React 应用程序。它介绍了每个工具，并提供了逐步说明如何安装每个工具。然后，它为本书中将要构建的项目创建了一个结构。

第三章，*创建你的第一个 React 元素*，解释了如何安装 React 并介绍了虚拟 DOM。然后，它解释了什么是 React 元素，以及如何使用原生 JavaScript 语法创建和渲染一个。最后，它介绍了 JSX 语法，并展示了如何使用 JSX 创建 React 元素。

第四章，*创建你的第一个 React 组件*，介绍了 React 组件。它解释了无状态和有状态 React 组件之间的区别，以及如何决定使用哪种。然后，它指导你完成创建这两种组件的过程。

第五章，使您的 React 组件具有响应性，解释了如何解决 React 的问题，并引导您规划 React 应用程序的过程。它创建了一个封装了整个本书中构建的 React 应用程序的 React 组件。它解释了父子 React 组件之间的关系。

第六章，使用另一个库使用您的 React 组件，探讨了如何在 React 组件中使用第三方 JavaScript 库。它介绍了 React 组件的生命周期，演示了如何使用挂载方法，并展示了如何为本书的项目创建新的 React 组件。

第七章，更新您的 React 组件，介绍了 React 组件生命周期的更新方法。这涵盖了如何在 JavaScript 中使用 CSS 样式。它解释了如何验证和设置组件的默认属性。

第八章，构建复杂的 React 组件，着重于构建更复杂的 React 组件。它探讨了如何实现不同的 React 组件以及如何将它们组合成一个连贯且完全功能的 React 应用程序的细节。

第九章，使用 Jest 测试您的 React 应用程序，解释了单元测试的概念，以及如何使用 Jest 编写和运行单元测试。它还演示了如何测试您的 React 组件。它讨论了测试套件、规范、期望和匹配器。

第十章，使用 Flux 加速您的 React 架构，讨论了如何改进我们的 React 应用程序的架构。它介绍了 Flux 架构，并解释了调度程序、存储和操作创建者的作用。

第十一章，使用 Flux 为您的 React 应用程序做好无痛维护的准备，解释了如何使用 Flux 在您的 React 应用程序中解耦关注点。它重构了我们的 React 应用程序，以便将来可以轻松地进行维护。

第十二章，*用 Redux 完善您的 Flux 应用*，将带您了解 Flux 库的主要特性，然后完全重构一个应用程序，以使用 Redux 作为控制状态的主要机制。

# 本书所需内容

首先，您需要最新版本的现代 Web 浏览器，如 Google Chrome 或 Mozilla Firefox：

+   Google Chrome：[`www.google.com/chrome/browser`](https://www.google.com/chrome/browser)

+   Mozilla Firefox：[`www.mozilla.org/en-US/firefox/new/`](https://www.mozilla.org/en-US/firefox/new/)

其次，您需要安装 Git、Node.js 和 npm。您将在第二章中找到详细的安装和使用说明，*为您的项目安装强大的工具*。

最后，您需要一个代码编辑器。我推荐*Sublime Text*（[`www.sublimetext.com`](http://www.sublimetext.com)）。或者，您可以使用*Atom*（[`atom.io`](https://atom.io)）、*Brackets*（[`brackets.io`](http://brackets.io)）、*Visual Studio Code*（[`code.visualstudio.com`](https://code.visualstudio.com)）或者您选择的任何其他编辑器。

# 这本书是为谁准备的

本书面向希望为 Web 构建可扩展和可维护用户界面的前端开发人员。了解 JavaScript、HTML 和 CSS 的一些核心知识是您开始从 React.js 带入 Web 开发世界的革命性思想中受益的唯一所需。如果您之前有 jQuery 或 Angular.js 的经验，那么您将受益于了解 React.js 的不同之处以及如何利用集成不同库与它。

# 约定

在本书中，您将找到一些区分不同信息类型的文本样式。以下是一些示例以及它们的含义解释。

文本中的代码单词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下：文本中的代码单词显示如下：“我们可以通过使用`include`指令包含其他上下文。”

代码块设置如下：

```jsx
import React from 'react';
import { render } from 'react-dom';

const reactElement = React.createElement(
  'h1', 
  { className: 'header' }
);

render(
  reactElement,
  document.getElementById('react-application')
);
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项将以粗体显示：

```jsx
<!doctype html>
  <html lang="en">
    <head>
      <title>Snapterest</title>
    </head>
    <body>
 **<div id="react-application">**
 **I am about to learn the essentials of React.js.**
 **</div>** <script src="./snapterest.js"></script>
    </body>
  </html>
```

任何命令行输入或输出都以以下方式编写：

```jsx
**cd ~**
**git clone https://github.com/snapkite/snapkite-engine.git**

```

**新术语**和**重要词汇**以粗体显示。屏幕上看到的词语，比如菜单或对话框中的词语，会以这样的方式出现在文本中："点击**下一步**按钮会将您移动到下一个屏幕。"

### 注意

警告或重要提示会出现在这样的框中。

### 提示

提示和技巧会出现在这样。


# 第一章 React 16 的新特性

React 16 的发布包含了足够重要的变化，值得专门撰写一章来讨论。这个特定的发布花了相对较长的时间来完成。这是因为协调内部——React 中负责高效渲染组件变化的部分——是从头开始重写的。兼容性是另一个因素：这次重写没有主要的破坏性 API 变化。

在本章中，您将了解 React 16 中引入的重大变化：

+   对协调内部所做的重大变化，以及对 React 项目的意义，未来的发展

+   通过设置错误边界将错误限制在应用程序的各个部分

+   创建渲染多个元素和渲染字符串的组件

+   渲染到门户

# 重新思考渲染

您不需要深入了解 React 协调内部的工作原理。这样会违背 React 的初衷，以及它如何为我们封装所有这些工作。然而，了解 React 16 中发生的重大内部变化的动机以及它们在更高层次上的工作方式，将有助于您思考如何最好地设计您的组件，无论是今天还是未来的 React 应用。

## 现状

React 已经确立自己作为选择帮助构建用户界面的库的标准之一。这其中的两个关键因素是它的简单性和性能。React 之所以简单，是因为它有一个小的 API 表面，易于上手和实验。React 之所以高性能，是因为它通过协调渲染树中的变化，最小化了需要调用的 DOM 操作数量。

这两个因素之间存在相互作用，这导致了 React 的飞速流行。如果 API 难以使用，React 提供的良好性能就不会有价值。React 的最大价值在于它简单易用，并且开箱即用性能良好。

随着 React 的广泛采用，人们意识到它的内部协调机制可以得到改进。例如，一些 React 应用程序更新组件状态的速度比渲染完成的速度更快。再举一个例子：对于渲染树的一部分的更改，如果在屏幕上看不到，那么它们的优先级应该比用户可以看到的元素低。这些问题足以降低用户体验，使其感觉不如可能的那样流畅。

如何在不破坏 API 和渲染树协调的情况下解决这些问题呢？

## 运行到完成

JavaScript 是单线程的，并且运行到完成。这意味着默认情况下，你运行的任何 JavaScript 代码都会阻止浏览器运行其他任务，比如绘制屏幕。这就是为什么 JavaScript 代码特别重要的原因。然而，在某些情况下，即使 React 协调代码的性能也无法掩盖用户的瓶颈。当面对一个新的树时，React 别无选择，只能阻止 DOM 更新和事件监听器，同时计算新的渲染树。

一个可能的解决方案是将协调工作分成更小的块，并安排它们以防止 JavaScript 运行到完成线程阻塞重要的 DOM 更新。这意味着协调器不必渲染完整的树，然后再次进行渲染，因为在第一次渲染时发生了事件。

让我们来看一个这个问题的视觉示例：

![运行到完成](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-ess-2e/img/B05915_01_01.jpg)

这个图表表明，当 React 组件中的状态发生变化时，直到渲染完成之前都不会发生其他任何事情。正如你所看到的，随着状态变化的不断堆积，协调整个树的成本会变得很高，与此同时，DOM 被阻止做任何事情。

协调渲染树与 JavaScript 的运行到完成语义是一致的。换句话说，React 不能暂停正在进行的工作来让 DOM 更新。现在让我们看看 React 16 如何试图改变前面的图表：

![运行到完成](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-ess-2e/img/B05915_01_02.jpg)

这个版本的 React 渲染/协调过程看起来与之前的版本相似。实际上，左侧组件的任何内容都没有改变——这反映了 React 16 中不变的 API。不过，有一些微妙但重要的区别。

让我们先看看协调器。它不是在每次组件状态改变时构建一个新的渲染树，而是渲染一个部分树。换句话说，它执行一部分工作，导致部分渲染树的创建。它不完成整个树的原因是为了让协调过程暂停，让任何 DOM 更新运行——你可以在图像的右侧看到 DOM 的差异。

当协调器恢复构建渲染树时，它首先检查是否自暂停以来发生了新的状态变化。如果是这样，它会获取部分完成的渲染树，并根据新的状态变化重复使用它可以的部分。然后，它继续进行，直到下一次暂停。最终，协调完成。在协调过程中，DOM 有机会响应事件并渲染任何未完成的更改。在 React 16 之前，这是不可能的——在整个树被渲染之前，DOM 中的任何事情都不会发生。

## 什么是 fiber？

为了将组件的渲染工作分解为更小的工作单元，React 创建了一个名为**fiber**的抽象。Fiber 代表可以暂停和恢复的渲染工作单元。它还具有其他低级属性，如优先级以及完成后应该返回到的 fiber 的输出位置。

React 16 在开发过程中的代号是 React Fiber，因为这个基本抽象使得调度整体渲染工作的片段，以提供更好的用户体验。React 16 标志着这种新的协调架构的初始发布，但它还没有完成。例如，一切仍然是同步的。

## 异步和未来

React 16 为下一个主要版本的异步渲染奠定了基础。这个功能没有包含在 React 16 中的主要原因是因为团队希望将基本的协调变化发布到公众中。还有一些其他需要发布的新功能，我们将在接下来的部分中介绍。 

一旦异步渲染功能引入到 React 中，您不应该修改任何代码。相反，您可能会注意到应用程序中某些区域的性能得到改善，这些区域将受益于优先和计划的渲染。

## 更好的组件错误处理

React 16 为组件引入了更好的错误处理能力。这个概念被称为**错误边界**，它被实现为一个生命周期方法，当任何子组件抛出异常时被调用。实现`componentDidCatch()`的父类就是错误边界。根据您的功能组织方式，您可以在应用程序中有不同的边界。

这种功能的动机是为应用程序提供从某些错误中恢复的机会。在 React 16 之前，如果组件抛出错误，整个应用程序将停止。这可能并不理想，特别是如果一个次要组件的问题导致关键组件停止工作。

让我们创建一个带有错误边界的`App`组件：

```jsx
class App extends Component {
  state = {}

  componentDidCatch(err) {
    this.setState({ err: err.message });
  }

  render() {
    return (<p><MyError err={this.state.err}/></p>);
  }
}
```

`App`组件除了渲染`MyError`之外什么也不做——一个故意抛出错误的组件。当这种情况发生时，`componentDidCatch()`方法将被调用，并将错误作为参数传递。然后，您可以使用这个值来改变组件的状态。在这个例子中，它将错误消息设置为`err`状态。然后，`App`将尝试重新渲染。

正如您所看到的，`this.state.err`被传递给`MyError`作为属性。在第一次渲染期间，这个值是未定义的。当`App`捕获到`MyError`抛出的错误时，错误将被传递回组件。现在让我们看看`MyError`：

```jsx
const MyError = (props) => {
  if (props.err) {
    return <b style={{color: 'red'}}>{props.err}</b>;
  }

  throw new Error('epic fail');
};
```

这个组件抛出一个带有消息'epic fail'的错误。当`App`捕获到这个错误时，它会使用一个`err`属性来渲染`MyError`。当这种情况发生时，它只是以红色呈现错误字符串。这恰好是我为这个应用程序选择的策略；在再次调用错误行为之前，始终检查错误状态。在`MyError`中，通过不执行`throw new Error('epic fail')`来第二次恢复整个应用程序。

使用`componentDidCatch()`，您可以自由地设置任何您喜欢的错误恢复策略。通常，您无法恢复失败的特定组件。

## 渲染多个元素和字符串

自 React 首次发布以来，规则是组件只能渲染一个元素。在 React 16 中有两个重要的变化。首先，您现在可以从组件返回一组元素。这简化了渲染兄弟元素会极大简化事情的情况。其次，您现在可以渲染纯文本内容。

这两个变化都导致页面上的元素减少。通过允许组件渲染兄弟元素，您不必为了返回单个元素而将它们包装起来。通过渲染字符串，您可以将测试内容作为子元素或另一个组件进行渲染，而无需将其包装在元素中。

以下是渲染多个元素的样子：

```jsx
const Multi = () => [
  'first sibling',
  'second sibling'
].map((v, i) => <p key={i}>{v}</p>);
```

请注意，您必须为集合中的元素提供一个`key`属性。现在让我们添加一个返回字符串值的元素：

```jsx
const Label = () => 'Name:';

const MultiWithString = () => [
  'first sibling',
  'second sibling'
].map((v, i) => <p key={i}><Label/> {v}</p>);
```

`Label`组件只是将一个字符串作为其渲染内容返回。`p`元素将`Label`作为子元素呈现，与`{v}`值相邻。当组件可以返回字符串时，您有更多选项来组合构成 UI 的元素。

## 呈现到门户

我想介绍的 React 16 的最终新功能是门户的概念。通常，组件的呈现输出放置在树中 JSX 元素所在的位置。然而，有时我们需要更大的控制权来决定组件的呈现输出最终放在哪里。例如，如果您想要在根 React 元素之外呈现组件怎么办？

门户允许组件在渲染时指定其容器元素。想象一下，您想在应用程序中显示通知。屏幕上不同位置的几个组件需要能够在屏幕上的一个特定位置呈现通知。让我们看看如何使用门户来定位元素：

```jsx
import React, { Component } from 'react';
import { createPortal } from 'react-dom';
class MyPortal extends Component {
  constructor(...args) {
    super(...args);
    this.el = document.createElement('strong');
  }

  componentWillMount() {
    document.body.appendChild(this.el);
  }

  componentWillUnmount() {
    document.body.removeChild(this.el);
  }

  render() {
    return createPortal(
      this.props.children,
      this.el
    );
  }
};
```

在这个组件的构造函数中，目标元素被创建并存储在`el`属性中。然后，在`componentWillMount()`中，该元素被附加到文档主体。实际上，您不需要在组件中创建目标元素——您可以使用现有元素。`componentWillUnmount()`方法会删除此元素。

在`render()`方法中，使用`createPortal()`函数创建门户。它接受两个参数——要呈现的内容和目标 DOM 元素。在这种情况下，它传递了其子属性。让我们看看`MyPortal`是如何使用的：

```jsx
class App extends Component {
  render() {
    return (
      <div>
        <p>Main content</p>
        <MyPortal>Bro, you just notified me!</MyPortal>
      </div>
    );
  }
}
```

最终的结果是传递给`MyPortal`的文本作为一个强元素呈现在根 React 元素之外。在使用门户之前，您必须采取某种命令式的解决方法才能使这样的事情起作用。现在，我们可以在需要的上下文中呈现通知——它只是碰巧被插入到 DOM 的其他位置以正确显示。

# 总结

本章的目标是向您介绍 React 16 的重大变化。值得注意的是，与之前的 React 版本几乎没有兼容性问题。这是因为大部分变化是内部的，不需要更改 API。还添加了一些新功能。

React 16 的头条是它的新协调内部。现在，协调工作被分解成更小的单元，而不是在组件改变状态时尝试协调所有内容。这些单元可以被优先处理、调度、暂停和恢复。在不久的将来，React 将充分利用这种新架构，并开始异步地渲染工作单元。

您还学会了如何在 React 组件中使用新的错误边界功能。使用错误边界可以让您从组件错误中恢复，而不会使整个应用程序崩溃。然后，您了解到 React 组件现在可以返回组件集合。就像渲染一组组件一样。现在您可以直接从组件中执行此操作。最后，您学会了如何使用门户将组件渲染到非标准位置。

在下一章中，您将学习如何构建响应式组件。


# 第二章：为您的项目安装强大的工具

这里有一句查尔斯·F·凯特林的名言：

> “我对未来感兴趣，因为我将在那里度过余生。”

这位杰出的发明家在我们甚至开始思考如何编写软件之前就给软件工程师留下了最重要的建议。然而，半个世纪后，我们仍在弄清楚为什么最终会得到意大利面代码或“意大利面心智模型”。

你是否曾经处于这样一种情况：你继承了前任开发者的代码，并花费了数周的时间试图理解一切是如何工作的，因为没有提供蓝图，而伪自解释的代码变得太难以调试？更糟糕的是，项目不断增长，复杂性也在增加。做出改变或破坏性的改变是危险的，没有人愿意去碰那些“丑陋”的遗留代码。重写整个代码库成本太高，因此目前的代码通过引入新的错误修复和补丁来支持。维护软件的成本远高于最初开发的成本。

写软件是为了未来而今天就开始。我认为关键在于创建一个简单的心智模型，无论项目在未来变得多么庞大，它都不会改变。当项目规模增长时，复杂性始终保持不变。这个心智模型就是你的蓝图，一旦你理解了它，你就会明白你的软件是如何工作的。

如果你看一下现代的 Web 开发，特别是前端开发，你会注意到我们生活在激动人心的时代。互联网公司和个人开发者正在解决速度和开发成本与代码和用户体验质量之间的问题。

2013 年，Facebook 发布了 React——一个用于构建用户界面的开源 JavaScript 库。您可以在[`facebook.github.io/react/`](http://facebook.github.io/react/)上阅读更多信息。2015 年初，来自 Facebook 的 Tom Occhino 总结了 React 的强大之处：

> “React 用声明式 API 包装了一个命令式 API。React 的真正力量在于它让你编写代码。”

声明式编程会导致代码量减少。它告诉计算机要做什么，而不指定如何做，而命令式编程风格描述了如何做。JavaScript 调用 DOM API 就是命令式编程的一个例子。jQuery 就是另一个例子。

Facebook 多年来一直在生产中使用 React，还有 Instagram 和其他公司。它也适用于小型项目；这里有一个使用 React 构建的购物清单的示例：[`fedosejev.github.io/shopping-list-react`](http://fedosejev.github.io/shopping-list-react)。我认为 React 是今天开发人员可以使用的构建用户界面的最好的 JavaScript 库之一。

我的目标是让你理解 React 的基本原则。为了实现这一目标，我将逐步向您介绍 React 的一个概念，解释它，并展示您如何应用它。我们将逐步构建一个实时 Web 应用程序，沿途提出重要问题，并讨论 React 为我们提供的解决方案。

您将了解 Flux/Redux 和数据的单向流动。与 Flux/Redux 和 React 一起，我们将创建一个可预测和可管理的代码库，您将能够通过添加新功能来扩展它，而不会增加其复杂性。您的 Web 应用程序的心智模型将保持不变，无论以后添加了多少新功能。

与任何新技术一样，有些东西的工作方式与您习惯的方式非常不同。React 也不例外。事实上，React 的一些核心概念可能看起来违反直觉，引发思考，甚至看起来像是一种倒退。不要草率下结论。正如您所期望的那样，Facebook 的经验丰富的工程师们在构建和使用 React 的过程中进行了大量思考，这些应用程序在业务关键应用中进行了生产。我给你的建议是，在学习 React 的过程中保持开放的心态，我相信在本书结束时，这些新概念将会让你感到很有意义。

加入我一起学习 React，并遵循查尔斯·F·凯特林的建议。让我们照顾好我们的未来！

# 接近我们的项目

我坚信学习新技术的最好动力是一个激发你兴趣、让你迫不及待地想要构建的项目。作为一名经验丰富的开发者，你可能已经构建了许多成功的商业项目，这些项目共享某些产品特性、设计模式，甚至目标受众。在这本书中，我希望你能建立一个感觉焕然一新的项目。一个你在日常工作中很可能不会构建的项目。它必须是一个有趣的尝试，不仅能教育你，还能满足你的好奇心并拓展你的想象力。然而，假设你是一个忙碌的专业人士，这个项目也不应该成为你长时间的、耗时的承诺。

输入**Snapterest**—一个允许你发现和收集 Twitter 上发布的公共照片的网络应用。把它想象成一个 Pinterest（[www.pinterest.com](http://www.pinterest.com)），唯一的图片来源就是 Twitter。我们将实现一个具有以下核心功能的完全功能的网站：

+   实时接收和显示推文

+   向/从收藏中添加和删除推文

+   审查收集的推文

+   将推文收藏导出为可以分享的 HTML 片段

当你开始着手一个新项目时，你要做的第一件事就是准备好你的工具。对于这个项目，我们将使用一些你可能不熟悉的工具，所以让我们讨论一下它们是什么，以及你如何安装和配置它们。

如果你在安装和配置本章中的工具和模块时遇到任何问题，请访问[`github.com/PacktPublishing/React-Essentials-Second-Edition`](https://github.com/PacktPublishing/React-Essentials-Second-Edition)并创建一个新的问题；描述你正在做什么以及你遇到了什么错误消息。我相信我们的社区会帮助你解决问题。

在这本书中，我假设你正在使用 Macintosh 或 Windows 计算机。如果你是 Unix 用户，那么你很可能非常了解你的软件包管理器，并且应该很容易为你安装本章中将要学习的工具。

让我们从安装 Node.js 开始。

# 安装 Node.js 和 npm

**Node.js**是一个平台，允许我们使用我们都熟悉的客户端语言 JavaScript 编写服务器端应用程序。然而，Node.js 的真正好处在于它使用事件驱动的、非阻塞的 I/O 模型，非常适合构建数据密集型、实时应用程序。这意味着使用 Node.js，我们应该能够处理传入的推文流，并在其到达时立即处理它们；这正是我们项目所需要的。

让我们安装 Node.js。我们将使用 8.7.0 版本，因为在撰写本书时，这是 Node.js 的最新版本。Jest 是 Facebook 的一个测试框架，您将在第九章中了解到，*使用 Jest 测试您的 React 应用程序*。

从以下链接之一下载适用于您操作系统的安装包：

+   OS X：[`nodejs.org/dist/v8.7.0/node-v8.7.0.pkg`](http://nodejs.org/dist/v8.7.0/node-v8.7.0.pkg)

+   Windows 64 位：[`nodejs.org/dist/v8.7.0/node-v8.7.0-x64.msi`](http://nodejs.org/dist/v8.7.0/node-v8.7.0-x64.msi)

+   Windows 32 位：[`nodejs.org/dist/v8.7.0/node-v8.7.0-x86.msi`](http://nodejs.org/dist/v8.7.0/node-v8.7.0-x86.msi)

运行下载的安装包，并按照 Node.js 提示的安装步骤进行操作。完成后，检查是否成功安装了 Node.js。打开终端/命令提示符，并键入以下命令：

```jsx
**node -v**

```

以下是输出结果（如果您的版本不完全匹配，不要担心）：

```jsx
**V8.7.0**

```

Node.js 拥有一个非常丰富的模块生态系统，可供我们使用。模块是一个可以在您自己的 Node.js 应用程序中重复使用的 Node.js 应用程序。在撰写本文时，已有超过 50 万个模块。您如何管理这么广泛的 Node.js 模块？认识一下**npm**，这是一个管理 Node.js 模块的包管理器。事实上，npm 与 Node.js 一起发布，因此您已经安装了它。在终端/命令提示符中键入以下内容：

```jsx
**npm -v**

```

您应该看到以下输出（如果您的版本不完全匹配，不要担心）：

```jsx
**5.5.1**

```

您可以在[www.npmjs.com](http://www.npmjs.com)了解更多关于 npm 的信息。现在我们准备开始安装 Node.js 应用程序。

# 安装 Git

在本书中，我们将使用 Git 来安装 Node.js 模块。如果您还没有安装 Git，请访问[`git-scm.com/book/en/v2/Getting-Started-Installing-Git`](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git)并按照您的操作系统的安装说明进行安装。

# 从 Twitter Streaming API 获取数据

我们的 React 应用程序的数据将来自 Twitter。Twitter 有一个**Streaming API**，任何人都可以接入并开始以 JSON 格式接收无尽的公共推文流。

要开始使用 Twitter Streaming API，您需要执行以下步骤：

1.  创建一个 Twitter 账户。为此，转到[`twitter.com`](https://twitter.com)并注册；或者如果您已经有账户，请登录。

1.  通过转到[`apps.twitter.com`](https://apps.twitter.com)创建一个新的 Twitter 应用程序，并点击**创建新应用程序**。您需要填写**应用程序详细信息**表格，同意**开发者协议**，然后点击**创建您的 Twitter 应用程序**。现在您应该看到您的应用程序页面。切换到**Keys and Access Tokens**选项卡。

在本页的**应用程序设置**部分，您会找到两个重要的信息：

+   **Consumer Key (API Key)**，例如，`jqRDrAlKQCbCbu2o4iclpnvem`

+   **Consumer Secret (API Secret)**，例如，`wJcdogJih7uLpjzcs2JtAvdSyCVlqHIRUWI70aHOAf7E3wWIgD`

记下这些；我们以后会用到它们。

现在我们需要生成一个访问令牌。在同一页上，您会看到空的**您的访问令牌**部分。点击**创建我的访问令牌**按钮。它会创建两个信息：

+   **Access Token**，例如，`12736172-R017ah2pE2OCtmi46IAE2n0z3u2DV6IqsEcPa0THR`

+   **Access Token Secret**，例如，`4RTJJWIezIDcs5VX1PMVZolXGZG7L3Ez7Iz1gMdZucDaM`

也记下这些。访问令牌是唯一的，您不应该与任何人分享。保持私密。

现在我们已经拥有了开始使用 Twitter 的 Streaming API 所需的一切。

# 使用 Snapkite Engine 过滤数据

通过 Twitter Streaming API 接收的推文数量超过您所能消费的数量，因此我们需要找到一种方法将数据流过滤为一组有意义的推文，以便我们可以显示和交互。我建议您快速查看 Twitter Streaming API 文档，特别是查看描述如何过滤传入流的页面。您会注意到 Twitter 提供的过滤器非常少，因此我们需要找到一种方法进一步过滤数据流。

幸运的是，有一个专门用于此目的的 Node.js 应用程序。它被称为**Snapkite Engine**。它连接到 Twitter Streaming API，使用可用的过滤器进行过滤，并根据您定义的规则输出经过过滤的推文到 Web 套接字连接。我们提出的 React 应用程序可以监听该套接字连接上的事件，并在推文到达时处理推文。

让我们安装 Snapkite Engine。首先，您需要克隆 Snapkite Engine 存储库。克隆意味着您正在将源代码从 GitHub 服务器复制到本地目录。在本书中，我将假设您的本地目录是您的主目录。打开终端/命令提示符并输入以下命令：

```jsx
**cd ~**
**git clone https://github.com/snapkite/snapkite-engine.git**

```

这应该创建`~/snapkite-engine/`文件夹。现在我们将安装`snapkite-engine`依赖的所有其他节点模块。其中之一是`node-gyp`模块。根据您使用的平台，Unix 或 Windows，您将需要安装列在此网页上的其他工具：

安装完毕后，您可以安装`node-gyp`模块：

```jsx
**npm install -g node-gyp**

```

现在导航到`~/snapkite-engine`目录：

```jsx
**cd snapkite-engine/**

```

然后运行以下命令：

```jsx
**npm install**

```

这个命令将安装 Snapkite Engine 依赖的 Node.js 模块。现在让我们配置 Snapkite Engine。假设你在`~/snapkite-engine/`目录中，通过运行以下命令将`./example.config.json`文件复制到`./config.json`：

```jsx
**cp example.config.json config.json**

```

或者，如果您使用 Windows，请运行此命令：

```jsx
**copy example.config.json config.json**

```

在您喜欢的文本编辑器中打开`config.json`。我们现在将编辑配置属性。让我们从`trackKeywords`开始。这是我们将告诉要跟踪哪些关键字的地方。如果我们想跟踪`"my"`关键字，那么设置如下：

```jsx
"trackKeywords": "my"
```

接下来，我们需要设置 Twitter Streaming API 密钥。将`consumerKey`，`consumerSecret`，`accessTokenKey`和`accessTokenSecret`设置为创建 Twitter 应用程序时保存的密钥。其他属性可以设置为它们的默认值。如果你想了解它们是什么，请查看 Snapkite Engine 文档[`github.com/snapkite/snapkite-engine`](https://github.com/snapkite/snapkite-engine)。

我们的下一步是安装 Snapkite 过滤器。**Snapkite Filter**是一个根据一组规则验证推文的 Node.js 模块。有许多 Snapkite 过滤器可供使用，我们可以根据需要使用任意组合来过滤我们的推文流。您可以在[`github.com/snapkite/snapkite-filters`](https://github.com/snapkite/snapkite-filters)找到所有可用的 Snapkite 过滤器的列表。

在我们的应用程序中，我们将使用以下 Snapkite 过滤器：

+   **可能敏感**：[`github.com/snapkite/snapkite-filter-is-possibly-sensitive`](https://github.com/snapkite/snapkite-filter-is-possibly-sensitive)

+   **有移动照片**：[`github.com/snapkite/snapkite-filter-has-mobile-photo`](https://github.com/snapkite/snapkite-filter-has-mobile-photo)

+   **是转推**：[`github.com/snapkite/snapkite-filter-is-retweet`](https://github.com/snapkite/snapkite-filter-is-retweet)

+   **有文本**：[`github.com/snapkite/snapkite-filter-has-text`](https://github.com/snapkite/snapkite-filter-has-text)

让我们安装它们。导航到`~/snapkite-engine/filters/`目录：

```jsx
**cd ~/snapkite-engine/filters/**

```

然后通过运行以下命令克隆所有 Snapkite 过滤器：

```jsx
**git clone https://github.com/snapkite/snapkite-filter-is-possibly-sensitive.git**
**git clone https://github.com/snapkite/snapkite-filter-has-mobile-photo.git**
**git clone https://github.com/snapkite/snapkite-filter-is-retweet.git**
**git clone https://github.com/snapkite/snapkite-filter-has-text.git**

```

下一步是配置它们。为了这样做，您需要为每个 Snapkite 过滤器创建一个**JSON**格式的配置文件，并在其中定义一些属性。幸运的是，每个 Snapkite 过滤器都附带了一个示例配置文件，我们可以根据需要复制和编辑。假设您在`~/snapkite-engine/filters/`目录中，运行以下命令（在 Windows 上使用`copy`并将正斜杠替换为反斜杠）：

```jsx
**cp snapkite-filter-is-possibly-sensitive/example.config.json snapkite-filter-is-possibly-sensitive/config.json**
**cp snapkite-filter-has-mobile-photo/example.config.json snapkite-filter-has-mobile-photo/config.json**
**cp snapkite-filter-is-retweet/example.config.json snapkite-filter-is-retweet/config.json**
**cp snapkite-filter-has-text/example.config.json snapkite-filter-has-text/config.json**

```

我们不需要更改这些`config.json`文件中的任何默认设置，因为它们已经配置好以适应我们的目的。

最后，我们需要告诉 Snapkite Engine 应该使用哪些 Snapkite Filters。在文本编辑器中打开`~/snapkite-engine/config.json`文件，查找这个：

```jsx
"filters": []
```

现在用以下内容替换它：

```jsx
"filters": [
  "snapkite-filter-is-possibly-sensitive",
  "snapkite-filter-has-mobile-photo",
  "snapkite-filter-is-retweet",
  "snapkite-filter-has-text"
]
```

干得好！你已经成功安装了带有多个 Snapkite Filters 的 Snapkite Engine。现在让我们检查一下是否可以运行它。导航到`~/snapkite-engine/`并运行以下命令：

```jsx
**npm start**

```

你应该看不到错误消息，但如果你看到了并且不确定如何解决，那么去[`github.com/fedosejev/react-essentials/issues`](https://github.com/fedosejev/react-essentials/issues)，创建一个新的问题，并复制粘贴你得到的错误消息。

接下来，让我们设置项目的结构。

# 创建项目结构

现在是时候创建我们的项目结构了。组织源文件可能听起来像一个简单的任务，但深思熟虑的项目结构组织帮助我们理解我们应用的基础架构。在本书的后面，当我们谈论 Flux 应用程序架构时，你将看到这方面的一个例子。让我们从在你的主目录`~/snapterest/`内创建我们的根项目目录`snapterest`开始。

然后，在其中，我们将创建另外两个目录：

+   `~/snapterest/source/`：在这里，我们将存储我们的源 JavaScript 文件

+   `~/snapterest/build/`：在这里，我们将放置编译后的 JavaScript 文件和一个 HTML 文件

现在，在`~/snapterest/source/`中，创建`components/`文件夹，使得你的项目结构看起来像这样：

+   `~/snapterest/source/components/`

+   `~/snapterest/build/`

现在我们的基本项目结构准备好了，让我们开始用我们的应用文件填充它。首先，我们需要在`~/snapterest/source/`目录中创建我们的主应用文件`app.js`。这个文件将是我们应用的入口点，`~/snapterest/source/app.js`。

现在先留空，因为我们有一个更紧迫的问题要讨论。

# 创建 package.json

你以前听说过**D.R.Y.**吗？它代表**不要重复自己**，并且它提倡软件开发中的核心原则之一——代码重用。最好的代码是你不需要写的代码。事实上，我们在这个项目中的一个目标就是尽可能少地编写代码。你可能还没有意识到，但 React 帮助我们实现了这个目标。它不仅节省了我们的时间，而且如果我们决定在将来维护和改进我们的项目，它将在长远来看节省我们更多的时间。

当涉及到不编写我们的代码时，我们可以应用以下策略：

+   以声明式编程风格编写我们的代码

+   重用他人编写的代码

在这个项目中，我们将使用两种技术。第一种技术由 React 本身提供。React 只能让我们以声明式风格编写 JavaScript 代码。这意味着我们不是告诉网页浏览器如何做我们想要的事情（就像我们用 jQuery 做的那样），而是告诉它我们想要它做什么，而 React 解释了如何做。这对我们来说是一个胜利。

Node.js 和 npm 涵盖了第二种技术。我在本章前面提到，有数十万不同的 Node.js 应用程序可供我们使用。这意味着很可能有人已经实现了我们的应用程序所依赖的功能。

问题是，我们从哪里获取所有这些我们想要重用的 Node.js 应用程序？我们可以通过`npm install <package-name>`命令安装它们。在 npm 上下文中，一个 Node.js 应用程序被称为**包**，每个**npm 包**都有一个描述该包相关元数据的`package.json`文件。您可以在[`docs.npmjs.com/files/package.json`](https://docs.npmjs.com/files/package.json)了解有关存储在`package.json`中的字段的更多信息。

在安装依赖包之前，我们将为我们自己的项目初始化一个包。通常，只有当您想要将您的包提交到 npm 注册表以便其他人可以重用您的 Node.js 应用程序时，才需要`package.json`。我们不打算构建 Node.js 应用程序，也不打算将我们的项目提交到 npm。请记住，`package.json`从技术上讲只是`npm`命令理解的元数据文件，因此我们可以使用它来存储我们的应用程序所需的依赖项列表。一旦我们在`package.json`中存储了依赖项列表，我们就可以随时使用`npm install`命令轻松安装它们；npm 将自动找到它们的位置。

我们如何为我们自己的应用程序创建`package.json`文件？幸运的是，npm 带有一个交互式工具，询问我们一系列问题，然后根据我们的答案为我们的项目创建`package.json`。

确保您位于`~/snapterest/`目录中。在终端/命令提示符中，运行以下命令：

```jsx
**npm init**

```

它将首先询问您的软件包名称。 它将建议一个默认名称，即您所在目录的名称。 在我们的情况下，它应该建议`name：（snapterest）`。 按*Enter*接受建议的默认名称（`snapterest`）。 下一个问题是您软件包的版本，即`version：（1.0.0）`。 按*Enter*。 如果我们计划将软件包提交给 npm 供其他人重用，这两个将是最重要的字段。 因为我们不打算将其提交给 npm，所以我们可以自信地接受我们被问到的所有问题的默认值。 继续按*Enter*，直到`npm init`完成执行并退出。 然后，如果您转到`〜/snapterest/`目录，您将在那里找到一个新文件-`package.json`。

现在我们准备安装其他我们将要重用的 Node.js 应用程序。 由多个单独应用程序构建的应用程序称为**模块化**，而单独的应用程序称为**模块**。 从现在开始，这就是我们将称之为我们的 Node.js 依赖项-Node.js 模块。

# 重用 Node.js 模块

正如我之前提到的，我们的开发过程中将有一个称为**构建**的步骤。 在此步骤中，我们的构建脚本将获取我们的源文件和所有 Node.js 依赖包，并将它们转换为 Web 浏览器可以成功执行的单个文件。 这个构建过程中最重要的部分称为**打包**。 但是我们需要打包什么以及为什么呢？ 让我们考虑一下。 我之前简要提到过，我们并不是在创建一个 Node.js 应用程序，但我们正在谈论重用 Node.js 模块。 这是否意味着我们将在非 Node.js 应用程序中重用 Node.js 模块？ 这可能吗？ 原来有一种方法可以做到这一点。

**Webpack**是一种工具，用于以这样一种方式捆绑所有依赖文件，以便您可以在客户端 JavaScript 应用程序中重用 Node.js 模块。 您可以在[`webpack.js.org`](http://webpack.js.org)了解有关 Webpack 的更多信息。 要安装 Webpack，请从`〜/snapterest/`目录内运行以下命令：

```jsx
**npm install --save-dev webpack**

```

注意`--save-dev`标志。它告诉 npm 将 Webpack 添加到我们的`package.json`文件中作为开发依赖项。将模块名称添加到我们的`package.json`文件中作为依赖项允许我们记录我们正在使用的依赖项，并且如果需要的话，我们可以很容易地使用`npm install`命令稍后安装它们。运行应用程序所需的依赖项与开发应用程序所需的依赖项之间有区别。Webpack 在构建时使用，而不是在运行时，因此它是开发依赖项。因此，使用`--save-dev`标志。如果您现在检查您的`package.json`文件的内容，您会看到这个（如果您的 Webpack 版本不完全匹配，不要担心）：

```jsx
"devDependencies": {
  "webpack": "².2.1"
}
```

npm 在您的`〜/snapterest/`目录中创建了一个名为`node_modules`的新文件夹。这是它放置所有本地依赖模块的地方。

恭喜您安装了您的第一个 Node.js 模块！Webpack 将允许我们在客户端 JavaScript 应用程序中使用 Node.js 模块。它将成为我们构建过程的一部分。现在让我们更仔细地看看我们的构建过程。

# 使用 Webpack 构建

今天，任何现代的客户端应用程序都代表了许多由各种技术单独解决的问题的混合。单独解决每个问题简化了管理项目复杂性的整个过程。这种方法的缺点是，在项目的某个时候，您需要将所有单独的部分组合成一个连贯的应用程序。就像汽车工厂中的机器人从单独的零件组装汽车一样，开发人员有一种称为构建工具的东西，可以从单独的模块中组装他们的项目。这个过程被称为**构建**过程，根据项目的大小和复杂性，构建过程可能需要从毫秒到几个小时不等的时间。

Webpack 将帮助我们自动化我们的构建过程。首先，我们需要配置 Webpack。假设您在`〜/snapterest/`目录中，创建一个新的`webpack.config.js`文件。

现在让我们在`webpack.config.js`文件中描述我们的构建过程。在这个文件中，我们将创建一个描述如何捆绑我们的源文件的 JavaScript 对象。我们希望将该配置对象导出为一个 Node.js 模块。是的，我们将把我们的`webpack.config.js`文件视为一个 Node.js 模块。为了做到这一点，我们将把我们的空配置对象分配给一个特殊的`module.exports`属性：

```jsx
const path = require('path'); 
module.exports = {};
```

`module.exports`属性是 Node.js API 的一部分。这是告诉 Node.js，每当有人导入我们的模块时，他们将获得对该对象的访问权限。那么这个对象应该是什么样子的呢？这就是我建议你去查看 Webpack 文档并阅读关于 Webpack 核心概念的链接：[`webpack.js.org/concepts/`](https://webpack.js.org/concepts/)

我们配置对象的第一个属性将是`entry`属性：

```jsx
module.exports = {
  entry: './source/app.js',
};
```

顾名思义，`entry`属性描述了我们 web 应用的入口点。在我们的例子中，这个属性的值是`./source/app.js`—这是启动我们应用的第一个文件。

我们配置对象的第二个属性将是`output`属性：

```jsx
output: {
  path: path.resolve(__dirname, 'build'),
  filename: 'snapterest.js'
},
```

`output`属性告诉 Webpack 在哪里输出生成的捆绑文件。在我们的例子中，我们说我们希望生成的捆绑文件叫做`snapterest.js`，并且应该保存到`./build`目录中。

Webpack 将每个源文件视为一个模块，这意味着所有我们的 JavaScript 源文件将被视为 Webpack 需要捆绑在一起的模块。我们如何向 Webpack 解释这一点呢？

我们通过配置对象的第三个属性`module`来实现这一点：

```jsx
module: {
  rules: [
    {
      test: /\.js$/,
      use: [
        {
          loader: 'babel-loader',
          options: {
            presets: ['react', 'latest'],
            plugins: ['transform-class-properties']
          }
        }
      ],
      exclude: path.resolve(__dirname, 'node_modules')
    }
  ]
}
```

正如你所看到的，我们的`module`属性得到一个对象作为它的值。这个对象有一个叫做`rules`的属性—一个规则数组，其中每个规则描述了如何从不同的源文件创建 Webpack 模块。让我们更仔细地看看我们的规则。

我们有一个单一规则告诉 Webpack 如何处理我们的源 JavaScript 文件：

```jsx
{
  test: /\.js$/,
  use: [
    {
      loader: 'babel-loader',
      options: {
        presets: ['react', 'latest'],
        plugins: ['transform-class-properties']
      }
    }
  ],
  exclude: path.resolve(__dirname, 'node_modules')
}
```

这个规则有三个属性：`test`，`use`和`exclude`。`test`属性告诉 Webpack 这个规则适用于哪些文件。它通过将我们的源文件名与我们指定为`test`属性值的正则表达式进行匹配来实现：`/\.js$/`。如果你熟悉正则表达式，你会认识到`/\.js$/`将匹配所有以`.js`结尾的文件名。这正是我们想要的：打包所有的 JavaScript 文件。

当 Webpack 找到并加载所有源 JavaScript 文件时，它会尝试将它们解释为普通的 JavaScript 文件。然而，我们的 JavaScript 文件不会是普通的 JavaScript 文件，而是具有 ECMAScript 2016 语法以及 React 特定语法。

Webpack 如何理解所有非普通的 JavaScript 语法？借助于 Webpack 加载器，我们可以将非普通的 JavaScript 语法转换为普通的 JavaScript。Webpack 加载器是应用于源文件的转换。我们的`use`属性描述了我们想要应用的转换列表：

```jsx
use: [
  {
    loader: 'babel-loader',
    options: {
      presets: ['react', 'latest'],
      plugins: ['transform-class-properties']
    }
  }
],
```

我们有一个转换负责将我们的 React 特定语法和 ECMAScript 2016 语法转换为普通 JavaScript：

```jsx
{
  loader: 'babel-loader',
  options: {
    presets: ['react', 'latest'],
    plugins: ['transform-class-properties']
  }
}
```

Webpack 转换是用具有`loader`和`options`属性的对象来描述的。`loader`属性告诉 Webpack 哪个加载器执行转换，`options`属性告诉它应该传递给该加载器哪些选项。将我们的 ECMAScript 2016 和特定于 React 的语法转换为普通 JavaScript 的加载器称为`babel-loader`。这个特定的转换过程称为**转译**或**源到源编译**——它将用一种语法编写的源代码转换为另一种语法编写的源代码。我们今天使用的是最流行的 JavaScript 转译器之一，叫做**Babel**：[`babeljs.io`](https://babeljs.io)。Webpack 有一个使用 Babel 转译器来转换我们源代码的 Babel 加载器。Babel 加载器作为一个独立的 Node.js 模块。让我们安装这个模块并将其添加到我们的开发依赖列表中。假设你在`~/snapterest/`目录中，运行以下命令：

```jsx
**npm install babel-core babel-loader --save-dev**

```

我们的 Webpack 加载器的`options`属性有一些 Babel 预设：`latest`和`react`以及一个 Babel`transform-class-properties`插件：

```jsx
options: {
  presets: ['react', 'latest'],
  plugins: ['transform-class-properties']
}
```

这些是负责转换不同语法的 Babel 插件：`latest`插件将 ECMAScript 2015、ECMAScript 2016 和 ECMAScript 2017 的语法转换为旧的 JavaScript 语法，`react`插件将 React 特定的语法转换为普通的 JavaScript 语法，而`transform-class-properties`插件将类属性转换为普通的 JavaScript 语法。

这些 Babel 插件是作为独立的 Node.js 模块分发的，我们需要单独安装它们。假设你在`~/snapterest/`目录中，运行以下命令：

```jsx
**npm install babel-preset-latest babel-preset-react babel-plugin-transform-class-properties --save-dev**

```

最后，我们在 Webpack 规则中有第三个属性叫做`exclude`：

```jsx
exclude: path.resolve(__dirname, 'node_modules')
```

这个属性告诉 Webpack 在转换过程中排除`node_modules`目录。

现在我们的`webpack.config.js`文件已经准备好了。在我们第一次运行打包过程之前，让我们在`package.json`文件中添加一个名为`start`的新脚本：

```jsx
"scripts": {
  "start": "webpack -p --config webpack.config.js",
  "test": "echo \"Error: no test specified\" && exit 1"
},
```

现在如果你运行`npm run start`或者`npm start`，npm 会运行`webpack -p --config webpack.config.js`命令。这个命令会运行 Webpack，用`webpack.config.js`文件打包我们的源文件以供生产使用。

我们已经准备好打包我们的源文件了！转到你的`~/snapterest/`目录并运行这个命令：

```jsx
**npm start**

```

在输出中，你应该会看到以下内容：

```jsx
**Version: webpack 2.2.1**
**Time: 1151ms**
 **Asset       Size  Chunks             Chunk Names**
**app.js  519 bytes       0  [emitted]  main**
 **[0] ./source/app.js 24 bytes {0} [built]**

```

更重要的是，如果你检查你的项目的`~/snapterest/build/`目录，你会注意到现在有一个`snapterest.js`文件，里面已经有一些代码了——那就是我们（空的）JavaScript 应用程序，里面有一些 Node.js 模块，可以在 web 浏览器中运行！

# 创建一个网页

如果你渴望一些 React 的好处，那么我有个好消息告诉你！我们快要完成了。剩下要做的就是创建一个带有指向我们`snapterest.js`脚本的`index.html`。

在`~/snapterest/build/`目录中创建`index.html`文件。添加以下 HTML 标记：

```jsx
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta http-equiv="x-ua-compatible" content="ie=edge, chrome=1" />
    <title>Snapterest</title>
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css">
  </head>
  <body>
    <div id="react-application">
      I am about to learn the essentials of React.js. </div>
    <script src="./snapterest.js"></script>
  </body>
</html>
```

在 web 浏览器中打开`~/snapterest/build/index.html`。你应该会看到以下文字：**我即将学习 React.js 的基本知识**。没错，我们已经完成了项目的设置，现在是时候了解 React 了！

# 摘要

在本章中，你学到了为什么我们应该使用 React 来构建现代 web 应用程序的用户界面。然后，我们讨论了这本书中我们将要构建的项目。最后，我们安装了所有正确的工具，并创建了项目的结构。

在下一章中，我们将安装 React，更仔细地了解 React 的工作原理，并创建我们的第一个 React 元素。


# 第三章：创建你的第一个 React 元素

今天创建一个简单的网页应用程序涉及编写 HTML、CSS 和 JavaScript 代码。我们使用三种不同的技术的原因是我们想要分离三种不同的关注点：

+   内容（HTML）

+   样式（CSS）

+   逻辑（JavaScript）

这种分离对于创建网页非常有效，因为传统上，我们有不同的人在网页的不同部分工作：一个人使用 HTML 结构化内容并使用 CSS 进行样式设置，然后另一个人使用 JavaScript 实现网页上各种元素的动态行为。这是一种以内容为中心的方法。

今天，我们大多数时候不再把网站看作是一组网页了。相反，我们构建的是可能只有一个网页的网页应用程序，而这个网页并不代表我们内容的布局，而是代表我们网页应用程序的容器。这样一个只有一个网页的网页应用程序称为（不出所料的）**单页应用程序**（**SPA**）。你可能会想知道在 SPA 中如何表示其余的内容？当然，我们需要使用 HTML 标签创建额外的布局。否则，浏览器怎么知道要渲染什么呢？

这些都是合理的问题。让我们看看它是如何工作的。一旦你在浏览器中加载你的网页，它会创建该网页的**文档对象模型**（**DOM**）。DOM 以树结构表示你的网页，此时它反映了你仅使用 HTML 标签创建的布局结构。无论你是在构建传统网页还是 SPA，这都是发生的事情。两者之间的区别在于接下来会发生什么。如果你正在构建传统网页，那么你会完成创建网页的布局。另一方面，如果你正在构建 SPA，那么你需要开始通过 JavaScript 操纵 DOM 来创建额外的元素。浏览器提供了**JavaScript DOM API**来做到这一点。你可以在[`developer.mozilla.org/en-US/docs/Web/API/Document_Object_Model`](https://developer.mozilla.org/en-US/docs/Web/API/Document_Object_Model)了解更多信息。

然而，用 JavaScript 操纵（或改变）DOM 有两个问题：

+   如果你决定直接使用 JavaScript DOM API，你的编程风格将是命令式的。正如我们在上一章讨论的那样，这种编程风格会导致更难维护的代码库。

+   DOM 突变很慢，因为它们无法像其他 JavaScript 代码那样进行速度优化。

幸运的是，React 为我们解决了这两个问题。

# 理解虚拟 DOM

我们为什么需要首先操作 DOM 呢？因为我们的 Web 应用程序不是静态的。它们有一个由**用户界面**（**UI**）表示的状态，Web 浏览器呈现，并且当事件发生时，该状态可以改变。我们在谈论什么样的事件？我们感兴趣的有两种类型的事件：

+   **用户事件**：当用户输入、点击、滚动、调整大小等时

+   **服务器事件**：当应用程序从服务器接收数据或错误时，等等

处理这些事件时会发生什么？通常情况下，我们会更新应用程序依赖的数据，并且这些数据代表我们数据模型的状态。反过来，当我们的数据模型状态发生变化时，我们可能希望通过更新 UI 状态来反映这种变化。看起来我们想要的是一种同步两种不同状态的方法：UI 状态和数据模型状态。我们希望其中一种对另一种的变化做出反应，反之亦然。我们如何才能实现这一点？

将应用程序的 UI 状态与基础数据模型状态同步的一种方法是双向数据绑定。有不同类型的双向数据绑定。其中之一是**键值观察**（**KVO**），它在`Ember.js`、Knockout、Backbone 和 iOS 等中使用。另一个是脏检查，它在 Angular 中使用。

React 提供了一种名为**虚拟 DOM**的不同解决方案，而不是双向数据绑定。虚拟 DOM 是真实 DOM 的快速内存表示，它是一种抽象，允许我们将 JavaScript 和 DOM 视为响应式的。让我们看看它是如何工作的：

1.  每当数据模型的状态发生变化时，虚拟 DOM 和 React 将重新渲染您的 UI 以获得虚拟 DOM 表示。

1.  然后计算两个虚拟 DOM 表示之间的差异：在数据改变之前计算的先前虚拟 DOM 表示和在数据改变之后计算的当前虚拟 DOM 表示。这两个虚拟 DOM 表示之间的差异实际上是真实 DOM 中需要改变的部分。

1.  只更新真实 DOM 中需要更新的部分。

在真实 DOM 中查找虚拟 DOM 的两个表示之间的差异，并且只重新渲染更新的补丁是很快的。而且，最好的部分是——作为 React 开发人员——您不需要担心实际需要重新渲染什么。React 允许您编写代码，就好像每次应用程序状态发生变化时都重新渲染整个 DOM 一样。

如果您想了解更多关于虚拟 DOM、其背后的原理以及如何与数据绑定进行比较，那么我强烈建议您观看 Facebook 的 Pete Hunt 在[`www.youtube.com/watch?v=-DX3vJiqxm4`](https://www.youtube.com/watch?v=-DX3vJiqxm4)上的这个非常信息丰富的讲座。

现在您已经了解了虚拟 DOM，让我们通过安装 React 并创建我们的第一个 React 元素来改变真实 DOM。

# 安装 React

要开始使用 React 库，我们首先需要安装它。

在撰写本文时，React 库的最新版本是 16.0.0。随着时间的推移，React 会得到更新，因此请确保您使用的是最新版本，除非它引入了与本书提供的代码示例不兼容的破坏性更改。访问[`github.com/PacktPublishing/React-Essentials-Second-Edition`](https://github.com/PacktPublishing/React-Essentials-Second-Edition)了解代码示例与 React 最新版本之间的任何兼容性问题。

在第二章中，*为您的项目安装强大的工具*，我向您介绍了**Webpack**，它允许我们使用`import`函数导入应用程序的所有依赖模块。我们将使用`import`来导入 React 库，这意味着我们不再需要向`index.html`文件添加`<script>`标签，而是使用`npm install`命令来安装 React：

1.  转到`~/snapterest/`目录并运行此命令：

```jsx
**npm install --save react react-dom**

```

1.  然后，打开您的文本编辑器中的`~/snapterest/source/app.js`文件，并将 React 和 ReactDOM 库分别导入到`React`和`ReactDOM`变量中：

```jsx
import React from 'react';
import ReactDOM from 'react-dom';
```

`react`包含了与 React 背后的关键思想有关的方法，即以声明方式描述您想要渲染的内容。另一方面，`react-dom`包含了负责渲染到 DOM 的方法。您可以在[`facebook.github.io/react/blog/2015/07/03/react-v0.14-beta-1.html#two-packages`](https://facebook.github.io/react/blog/2015/07/03/react-v0.14-beta-1.html#two-packages)上阅读更多关于为什么 Facebook 的开发人员认为将 React 库分成两个包是一个好主意的内容。

现在我们准备在我们的项目中开始使用 React 库。接下来，让我们创建我们的第一个 React 元素！

# 使用 JavaScript 创建 React 元素

我们将首先熟悉基本的 React 术语。这将帮助我们清晰地了解 React 库的组成。这些术语很可能会随着时间的推移而更新，因此请密切关注官方文档[`facebook.github.io/react/docs/react-api.html`](https://facebook.github.io/react/docs/react-api.html)。

就像 DOM 是节点树一样，React 的虚拟 DOM 是 React 节点树。React 中的核心类型之一称为`ReactNode`。它是虚拟 DOM 的构建块，可以是以下任何一种核心类型之一：

+   `ReactElement`：这是 React 中的主要类型。它是一个轻量级的、无状态的、不可变的、虚拟表示的`DOMElement`。

+   `ReactText`：这是一个字符串或数字。它表示文本内容，是 DOM 中文本节点的虚拟表示。

`ReactElement`和`ReactText`都是`ReactNode`。`ReactNode`的数组称为`ReactFragment`。您将在本章中看到所有这些的示例。

让我们从`ReactElement`的示例开始：

1.  将以下代码添加到您的`~/snapterest/source/app.js`文件中：

```jsx
const reactElement = React.createElement('h1');
ReactDOM.render(reactElement, document.getElementById('react-application'));
```

1.  现在您的`app.js`文件应该完全像这样：

```jsx
import React from 'react';
import ReactDOM from 'react-dom';

const reactElement = React.createElement('h1');
ReactDOM.render(
  reactElement,
  document.getElementById('react-application')
);
```

1.  转到`~/snapterest/`目录并运行此命令：

```jsx
**npm start**

```

您将看到以下输出：

```jsx
**Hash: 826f512cf95a44d01d39**
**Version: webpack 3.8.1**
**Time: 1851ms**

```

1.  转到`~/snapterest/build/`目录，并在 Web 浏览器中打开`index.html`。您将看到一个空白的网页。在 Web 浏览器中打开**开发者工具**，并检查空白网页的 HTML 标记。您应该在其他内容中看到这一行：

```jsx
<h1 data-reactroot></h1>
```

干得好！我们刚刚渲染了您的第一个 React 元素。让我们看看我们是如何做到的。

React 库的入口点是`React`对象。该对象有一个名为`createElement()`的方法，它接受三个参数：`type`、`props`和`children`：

```jsx
React.createElement(type, props, children);
```

让我们更详细地看看每个参数。

## type 参数

`type`参数可以是字符串或`ReactClass`：

+   字符串可以是 HTML 标记名称，例如`'div'`，`'p'`和`'h1'`。React 支持所有常见的 HTML 标记和属性。有关 React 支持的所有 HTML 标记和属性的完整列表，您可以参考[`facebook.github.io/react/docs/dom-elements.html`](https://facebook.github.io/react/docs/dom-elements.html)。

+   通过`React.createClass()`方法创建了一个`ReactClass`类。我将在第四章中更详细地介绍这个问题，*创建您的第一个 React 组件*。

`type`参数描述了 HTML 标记或`ReactClass`类将如何呈现。在我们的例子中，我们正在呈现`h1` HTML 标记。

## props 参数

`props`参数是从父元素传递给子元素（而不是反过来）的 JavaScript 对象，具有一些被视为不可变的属性，即不应更改的属性。

在使用 React 创建 DOM 元素时，我们可以传递`props`对象，其中包含代表 HTML 属性的属性，例如`class`和`style`。例如，运行以下代码：

```jsx
import React from 'react';
import ReactDOM from 'react-dom';

const reactElement = React.createElement(
  'h1', { className: 'header' }
);
ReactDOM.render(
  reactElement,
  document.getElementById('react-application')
);
```

上述代码将创建一个`class`属性设置为`header`的`h1` HTML 元素：

```jsx
<h1 data-reactroot class="header"></h1>
```

请注意，我们将属性命名为`className`而不是`class`。这样做的原因是`class`关键字在 JavaScript 中是保留的。如果您将`class`用作属性名称，React 将忽略它，并在 Web 浏览器的控制台上打印有用的警告消息：

**警告：未知的 DOM 属性类。您是指 className 吗？**

**请改用 className。**

您可能想知道我们的`h1`标签中的`data-reactroot`属性是做什么的？我们没有将其传递给我们的`props`对象，那它是从哪里来的？它是由 React 添加并使用的，用于跟踪 DOM 节点。

## children 参数

`children`参数描述了此 HTML 元素应具有哪些子元素（如果有）。子元素可以是任何类型的`ReactNode`：由`ReactElement`表示的虚拟 DOM 元素，由`ReactText`表示的字符串或数字，或者其他`ReactNode`节点的数组，也称为`ReactFragment`。

让我们看看这个例子：

```jsx
import React from 'react';
import ReactDOM from 'react-dom';

const reactElement = React.createElement(
  'h1',
  { className: 'header' },
  'This is React'
);
ReactDOM.render(
  reactElement,
  document.getElementById('react-application')
);
```

上述代码将创建一个带有`class`属性和文本节点`This is React`的`h1` HTML 元素：

```jsx
<h1 data-reactroot class="header">This is React</h1>
```

`h1`标签由`ReactElement`表示，而`This is React`字符串由`ReactText`表示。

接下来，让我们创建一个 React 元素，它的子元素是一些其他的 React 元素：

```jsx
import React from 'react';
import ReactDOM from 'react-dom';

const h1 = React.createElement(
  'h1',
  { className: 'header', key: 'header' },
  'This is React'
);
const p = React.createElement(
  'p', 
  { className: 'content', key: 'content' },
  'And that is how it works.' );
const reactFragment = [ h1, p ];
const section = React.createElement(
  'section',
  { className: 'container' },
  reactFragment
);

ReactDOM.render(
  section,
  document.getElementById('react-application')
);
```

我们创建了三个 React 元素：`h1`，`p`和`section`。`h1`和`p`都有子文本节点，分别是`'This is React'`和`'And that is how it works.'`。`section`标签有一个子元素，是两个`ReactElement`类型的数组，`h1`和`p`，称为`reactFragment`。这也是一个`ReactNode`数组。`reactFragment`数组中的每个`ReactElement`类型都必须有一个`key`属性，帮助 React 识别该`ReactElement`类型。结果，我们得到以下 HTML 标记：

```jsx
<section data-reactroot class="container">
  <h1 class="header">This is React</h1>
  <p class="content">And that is how it works.</p>
</section>
```

现在我们明白了如何创建 React 元素。如果我们想要创建多个相同类型的 React 元素呢？这意味着我们需要为每个相同类型的元素一遍又一遍地调用`React.createElement('type')`吗？我们可以，但我们不需要，因为 React 为我们提供了一个名为`React.createFactory()`的工厂函数。工厂函数是一个创建其他函数的函数。这正是`React.createFactory(type)`所做的：它创建一个产生给定类型的`ReactElement`的函数。

考虑以下例子：

```jsx
import React from 'react';
import ReactDOM from 'react-dom';

const listItemElement1 = React.createElement(
  'li',
  { className: 'item-1', key: 'item-1' },
  'Item 1'
);
const listItemElement2 = React.createElement(
  'li',
  { className: 'item-2', key: 'item-2' },
  'Item 2'
);
const listItemElement3 = React.createElement(
  'li',
  { className:   'item-3', key: 'item-3' },
  'Item 3'
);

const reactFragment = [
  listItemElement1,
  listItemElement2,
  listItemElement3
];
const listOfItems = React.createElement(
  'ul',
  { className: 'list-of-items' },
  reactFragment
);

ReactDOM.render(
  listOfItems,
  document.getElementById('react-application')
);
```

前面的例子产生了这个 HTML：

```jsx
<ul data-reactroot class="list-of-items">
  <li class="item-1">Item 1</li>
  <li class="item-2">Item 2</li>
  <li class="item-3">Item 3</li>
</ul>
```

我们可以通过首先创建一个工厂函数来简化它：

```jsx
import React from 'react';
import ReactDOM from 'react-dom';

const createListItemElement = React.createFactory('li');

const listItemElement1 = createListItemElement(
  { className: 'item-1', key: 'item-1' },
  'Item 1'
);
const listItemElement2 = createListItemElement(
  { className: 'item-2', key: 'item-2' },
  'Item 2'
);
const listItemElement3 = createListItemElement(
  { className: 'item-3', key: 'item-3' },
  'Item 3'
);

const reactFragment = [
  listItemElement1,
  listItemElement2,
  listItemElement3
];
const listOfItems = React.createElement(
  'ul',
  { className: 'list-of-items' },
  reactFragment
);

ReactDOM.render(
  listOfItems,
  document.getElementById('react-application')
);
```

在前面的例子中，我们首先调用了`React.createFactory()`函数，并将`li` HTML 标签名称作为类型参数传递。然后，`React.createFactory()`函数返回一个新的函数，我们可以将其用作创建`li`类型元素的便捷缩写。我们将这个函数的引用存储在一个名为`createListItemElement`的变量中。然后，我们调用这个函数三次，每次只传递`props`和`children`参数，这些参数对于每个元素都是唯一的。请注意，`React.createElement()`和`React.createFactory()`都期望一个 HTML 标签名称字符串（如`li`）或`ReactClass`对象作为类型参数。

React 为我们提供了许多内置的工厂函数来创建常见的 HTML 标签。您可以从`React.DOM`对象中调用它们；例如，`React.DOM.ul()`，`React.DOM.li()`和`React.DOM.div()`。使用它们，我们甚至可以进一步简化我们之前的例子：

```jsx
import React from 'react';
import ReactDOM from 'react-dom';

const listItemElement1 = React.DOM.li(
  { className: 'item-1', key: 'item-1' },
  'Item 1'
);
const listItemElement2 = React.DOM.li(
  { className: 'item-2', key: 'item-2' },
  'Item 2'
);
const listItemElement3 = React.DOM.li(
  { className: 'item-3', key: 'item-3' },
  'Item 3'
);

const reactFragment = [
  listItemElement1,
  listItemElement2,
  listItemElement3
];
const listOfItems = React.DOM.ul(
  { className: 'list-of-items' },
  reactFragment
);

ReactDOM.render(
  listOfItems,
  document.getElementById('react-application')
);
```

现在，我们知道如何创建`ReactNode`的树。然而，在我们继续之前，有一行重要的代码需要讨论：

```jsx
ReactDOM.render(
  listOfItems,
  document.getElementById('react-application')
);
```

您可能已经猜到了，它将我们的 `ReactNode` 树呈现到 DOM。让我们更仔细地看看它是如何工作的。

# 渲染 React 元素

`ReactDOM.render()` 方法接受三个参数：`ReactElement`、一个常规的 `DOMElement` 容器和一个 `callback` 函数：

```jsx
ReactDOM.render(ReactElement, DOMElement, callback);
```

`ReactElement` 类型是您创建的 `ReactNode` 树中的根元素。常规的 `DOMElement` 参数是该树的容器 DOM 节点。`callback` 参数是在树被渲染或更新后执行的函数。重要的是要注意，如果此 `ReactElement` 类型先前已呈现到父 `DOMElement` 容器，则 `ReactDOM.render()` 将对已呈现的 DOM 树执行更新，并且仅会改变 DOM，因为需要反映 `ReactElement` 类型的最新版本。这就是为什么虚拟 DOM 需要较少的 DOM 变化。

到目前为止，我们假设我们总是在 web 浏览器中创建我们的虚拟 DOM。这是可以理解的，因为毕竟 React 是一个用户界面库，所有用户界面都是在 web 浏览器中呈现的。您能想到在客户端渲染用户界面会很慢的情况吗？你们中的一些人可能已经猜到了，我说的是初始页面加载。初始页面加载的问题是我在本章开头提到的一个问题——我们不再创建静态网页了。相反，当 web 浏览器加载我们的 web 应用程序时，它只会收到通常用作我们的 web 应用程序的容器或父元素的最少 HTML 标记。然后，我们的 JavaScript 代码创建其余的 DOM，但为了这样做，它通常需要从服务器请求额外的数据。然而，获取这些数据需要时间。一旦收到这些数据，我们的 JavaScript 代码开始改变 DOM。我们知道 DOM 变化很慢。我们如何解决这个问题？

解决方案有些出乎意料。我们不是在 web 浏览器中改变 DOM，而是在服务器上改变它，就像我们在静态网页上做的那样。然后，web 浏览器将接收一个 HTML，它完全代表了我们的 web 应用程序在初始页面加载时的用户界面。听起来很简单，但我们不能在服务器上改变 DOM，因为它在 web 浏览器之外不存在。或者我们可以吗？

我们有一个只是 JavaScript 的虚拟 DOM，并且使用 Node.js，我们可以在服务器上运行 JavaScript。因此，从技术上讲，我们可以在服务器上使用 React 库，并且可以在服务器上创建我们的`ReactNode`树。问题是我们如何将其渲染为一个可以发送给客户端的字符串？

React 有一个名为`ReactDOMServer.renderToString()`的方法来做到这一点：

```jsx
import ReactDOMServer from 'react-dom/server';
ReactDOMServer.renderToString(ReactElement);
```

`ReactDOMServer.renderToString()`方法以`ReactElement`作为参数，并将其渲染为初始 HTML。这不仅比在客户端上改变 DOM 更快，而且还提高了您的 Web 应用的搜索引擎优化（SEO）。

说到生成静态网页，我们也可以用 React 来做到这一点：

```jsx
import ReactDOMServer from 'react-dom/server';
ReactDOMServer.renderToStaticMarkup(ReactElement);
```

与`ReactDOMServer.renderToString()`类似，这个方法也以`ReactElement`作为参数，并输出一个 HTML 字符串。然而，它不会创建 React 在内部使用的额外 DOM 属性，从而产生较短的 HTML 字符串，我们可以快速传输到网络。

现在你不仅知道如何使用 React 元素创建虚拟 DOM 树，还知道如何将其渲染到客户端和服务器。我们接下来的问题是是否可以快速且更直观地完成这个过程。

# 使用 JSX 创建 React 元素

当我们通过不断调用`React.createElement()`方法来构建我们的虚拟 DOM 时，将这些多个函数调用视觉上转换为 HTML 标签的层次结构变得非常困难。不要忘记，即使我们正在使用虚拟 DOM，我们仍然在为我们的内容和用户界面创建一个结构布局。通过简单地查看我们的 React 代码，能够轻松地可视化该布局，这不是很好吗？

**JSX**是一种可选的类似 HTML 的语法，允许我们创建虚拟 DOM 树，而不使用`React.createElement()`方法。

让我们来看看我们之前创建的不使用 JSX 的示例：

```jsx
import React from 'react';
import ReactDOM from 'react-dom';

const listItemElement1 = React.DOM.li(
  { className: 'item-1', key: 'item-1' },
  'Item 1'
);
const listItemElement2 = React.DOM.li(
  { className: 'item-2', key: 'item-2' },
  'Item 2'
);
const listItemElement3 = React.DOM.li(
  { className: 'item-3', key: 'item-3' },
  'Item 3'
);

const reactFragment = [
  listItemElement1,
  listItemElement2,
  listItemElement3
];
const listOfItems = React.DOM.ul(
  { className: 'list-of-items' },
  reactFragment
);

ReactDOM.render(
  listOfItems,
  document.getElementById('react-application')
);
```

将此转换为 JSX：

```jsx
import React from 'react';
import ReactDOM from 'react-dom';

const listOfItems = (
  <ul className="list-of-items">
    <li className="item-1">Item 1</li>
    <li className="item-2">Item 2</li>
    <li className="item-3">Item 3</li>
  </ul>
);

ReactDOM.render(
  listOfItems,
  document.getElementById('react-application')
);
```

正如你所看到的，JSX 允许我们在 JavaScript 代码中编写类似 HTML 的语法。更重要的是，我们现在可以清楚地看到我们的 HTML 布局在渲染后会是什么样子。JSX 是一个方便的工具，但它也有一个额外的转换步骤的代价。在我们的“无效”JavaScript 代码被解释之前，必须将 JSX 语法转换为有效的 JavaScript 语法。

在上一章中，我们安装了`babel-preset-react`模块，将我们的 JSX 语法转换为有效的 JavaScript。这种转换发生在我们运行 Webpack 时。转到`~/snapterest/`并运行以下命令：

```jsx
**npm start**

```

为了更好地理解 JSX 语法，我建议您使用 Babel REPL 工具进行实验：[`babeljs.io/repl/`](https://babeljs.io/repl/)——它可以将您的 JSX 语法即时转换为普通的 JavaScript。

使用 JSX，起初可能会感到非常不同寻常，但它可以成为一个非常直观和方便的工具。最好的部分是您可以选择是否使用它。我发现 JSX 可以节省我的开发时间，所以我选择在我们正在构建的项目中使用它。

如果您对我们在本章讨论的内容有疑问，那么您可以参考[`github.com/fedosejev/react-essentials`](https://github.com/fedosejev/react-essentials)并创建一个新的问题。

# 总结

我们从讨论单页面应用程序的问题以及如何解决它们开始了本章。然后，您了解了虚拟 DOM 是什么，以及 React 如何允许我们构建一个虚拟 DOM。我们还安装了 React，并且仅使用 JavaScript 创建了我们的第一个 React 元素。然后，您还学会了如何在 Web 浏览器和服务器上渲染 React 元素。最后，我们看了一种更简单的使用 JSX 创建 React 元素的方法。

在下一章中，我们将更深入地了解 React 组件的世界。


# 第四章：创建您的第一个 React 组件

在上一章中，您学习了如何创建 React 元素以及如何使用它们来渲染 HTML 标记。您看到使用 JSX 生成 React 元素是多么容易。在这一点上，您已经了解了足够多的关于 React 的知识，可以创建静态网页，我们在第三章中讨论了这一点，*创建您的第一个 React 元素*。然而，我敢打赌这不是您决定学习 React 的原因。您不只是想构建由静态 HTML 元素组成的网站。您想要构建对用户和服务器事件做出反应的交互式用户界面。对事件做出反应意味着什么？静态 HTML 元素如何**反应**？React 元素如何反应？在本章中，我们将回答这些问题以及许多其他问题，同时向 React 组件介绍自己。

# 无状态与有状态

反应意味着从一种状态切换到另一种状态。这意味着你需要首先有一个状态，以及改变该状态的能力。我们在 React 元素中提到了状态或改变状态的能力吗？没有。它们是无状态的。它们的唯一目的是构建和渲染虚拟 DOM 元素。事实上，我们希望它们以完全相同的方式渲染，只要我们为它们提供完全相同的参数。我们希望它们保持一致，因为这样可以方便我们理解它们。这是使用 React 的关键好处之一——方便我们理解我们的 Web 应用程序的工作原理。

我们如何向我们的无状态 React 元素添加状态？如果我们不能在 React 元素中封装状态，那么我们应该将 React 元素封装在已经具有状态的东西中。想象一个代表用户界面的简单状态机。每个用户操作都会触发该状态机中的状态变化。每个状态由不同的 React 元素表示。在 React 中，这个状态机被称为**React 组件**。

# 创建您的第一个无状态 React 组件

让我们看看如何创建一个 React 组件的以下示例：

```jsx
import React, { Component } from 'react';
import ReactDOM from 'react-dom';

class ReactClass extends Component {
  render () {
    return (
      <h1 className="header">React Component</h1>
    );
  }
}

const reactComponent = ReactDOM.render(
  <ReactClass/>,
  document.getElementById('react-application')
);
export default ReactClass;
```

之前的一些代码对你来说可能已经很熟悉了，其余部分可以分解为两个简单的步骤：

1.  创建一个 React 组件类。

1.  创建一个 React 组件。

让我们更仔细地看一下如何创建一个 React 组件：

1.  创建一个`ReactClass`类作为`Component`类的子类。在本章中，我们将重点学习如何更详细地创建 React 组件类。

1.  通过调用`ReactDOM.render()`函数并将我们的`ReactClass`元素作为其元素参数提供来创建`reactComponent`。

我强烈建议您阅读 Dan Abramov 的这篇博文，其中更详细地解释了 React 组件、元素和实例之间的区别：[`facebook.github.io/react/blog/2015/12/18/react-components-elements-and-instances.html`](https://facebook.github.io/react/blog/2015/12/18/react-components-elements-and-instances.html)

React 组件的外观和感觉在`ReactClass`中声明。

`Component`类封装了组件的状态并描述了组件的呈现方式。至少，React 组件类需要有一个`render()`方法，以便返回`null`或`false`。以下是一个最简单形式的`render()`方法的示例：

```jsx
class ReactClass extends Component {
  render() {
    return null;
  }
}
```

正如您可以猜到的，`render()`方法负责告诉 React 这个组件应该呈现什么。它可以返回`null`，就像前面的例子中一样，屏幕上将不会呈现任何内容。或者，它可以返回我们在第三章中学习如何创建的 JSX 元素，*创建您的第一个 React 元素*：

```jsx
class ReactClass extends Component {
  render() {
    return (
      <h1 className="header">React Component</h1>
    );
  }
}
```

这个例子展示了我们如何将 React 元素封装在 React 组件中。我们创建了一个带有`className`属性和一些文本作为其子元素的`h1`元素。然后，在调用`render()`方法时返回它。我们将 React 元素封装在 React 组件中的事实并不影响它的呈现方式：

```jsx
<h1 data-reactroot class="header">React Component</h1>
```

正如您所看到的，生成的 HTML 标记与我们在第三章中创建的标记相同，*创建您的第一个 React 元素*，而不使用 React 组件。在这种情况下，您可能会想知道，如果我们可以在没有它的情况下呈现完全相同的标记，那么拥有`render()`方法的好处是什么？

拥有`render()`方法的优势在于，与任何其他函数一样，在返回值之前，它可以选择返回什么值。到目前为止，您已经看到了两个`render()`方法的例子：一个返回`null`，另一个返回一个 React 元素。我们可以合并这两个并添加一个条件来决定要渲染什么：

```jsx
class ReactClass extends Component {
  render() {
    const componentState = {
      isHidden: true
    };

    if (componentState.isHidden) {
      return null;
    }

    return (
      <h1 className="header">React Component</h1>
    );
  }
}
```

在这个例子中，我们创建了`componentState`常量，它引用了一个具有单个`isHidden`属性的对象。这个对象充当我们的 React 组件的状态。如果我们想要隐藏我们的 React 组件，那么我们需要将`componentState.isHidden`的值设置为`true`，我们的`render`函数将返回`null`。在这种情况下，React 将不渲染任何内容。从逻辑上讲，将`componentState.isHidden`设置为`false`，将返回我们的 React 元素并渲染预期的 HTML 标记。您可能会问的问题是，我们如何将`componentState.isHidden`的值设置为`false`？或者设置为`true`？或者如何一般地改变它？

让我们想想我们可能想要改变状态的情况。其中之一是当用户与我们的用户界面交互时。另一个是当服务器发送数据时。或者，当一定时间过去后，现在我们想要渲染其他东西。我们的`render()`方法并不知道所有这些事件，也不应该知道，因为它的唯一目的是根据我们传递给它的数据返回一个 React 元素。我们如何将数据传递给它？

有两种方法可以使用 React API 将数据传递给`render()`方法：

+   `this.props`

+   `this.state`

在这里，`this.props`对您来说应该很熟悉。在第三章*创建您的第一个 React 元素*中，您学习了`React.createElement()`函数接受`props`参数。我们用它来传递属性给我们的 HTML 元素，但我们没有讨论发生了什么以及为什么传递给`props`对象的属性会被渲染。

您放入`props`对象并传递给 JSX 元素的任何数据都可以通过`this.props`在`render()`方法中访问。一旦您从`this.props`访问数据，您可以渲染它：

```jsx
class ReactClass extends Component {
  render() {
    const componentState = {
      isHidden: false
    };

    if (componentState.isHidden) {
      return null;
    }

    return (
      <h1 className="header">{this.props.header}</h1>
    );
  }
}
```

在这个例子中，我们在`render()`方法中使用`this.props`来访问`header`属性。然后，我们直接将`this.props.header`作为子元素传递给`h1 元素`。

在前面的例子中，我们可以将`isHidden`的值作为`this.props`对象的另一个属性传递：

```jsx
class ReactClass extends Component {
  render() {
    if (this.props.isHidden) {
      return null;
    }

    return (
      <h1 className="header">{this.props.header}</h1>
    );
  }
}
```

注意，在这个例子中，我们重复了两次`this.props`。一个`this.props`对象通常有我们想要在`render`方法中多次访问的属性。因此，我建议你首先解构`this.props`：

```jsx
class ReactClass extends Component {
  render() {
    const {
      isHidden,
      header
    } = this.props;

    if (isHidden) {
      return null;
    }

    return (
      <h1 className="header">{this.header}</h1>
    );
  }
}
```

你是否注意到在前面的例子中，我们不是将`isHidden`存储在`render()`方法中，而是通过`this.props`传递它？我们移除了我们的`componentState`对象，因为我们不需要在`render()`方法中担心组件的状态。`render()`方法不应该改变组件的状态或访问真实的 DOM，或以其他方式与 Web 浏览器交互。我们可能希望在服务器上渲染我们的 React 组件，在那里我们没有 Web 浏览器，并且我们应该期望`render()`方法在任何环境下都能产生相同的结果。

如果我们的`render()`方法不管理状态，那么我们如何管理它？我们如何设置状态，以及在处理 React 中的用户或浏览器事件时如何更新它？

在本章的前面，你学到了在 React 中，我们可以用 React 组件表示用户界面。有两种类型的 React 组件：

+   有一个状态

+   没有状态

等一下！我们不是说 React 组件是状态机吗？当然，每个状态机都需要有一个状态。你是对的，但是尽可能保持尽可能多的 React 组件无状态是一个好习惯。

React 组件是可组合的。因此，我们可以有一个 React 组件的层次结构。想象一下，我们有一个父 React 组件，它有两个子组件，每个子组件又有另外两个子组件。所有组件都是有状态的，它们可以管理自己的状态：

![创建你的第一个无状态 React 组件](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-ess-2e/img/B05915_04_01.jpg)

如果层次结构中顶部组件更新其状态，要弄清楚最后一个子组件将渲染什么，会有多容易？不容易。有一种设计模式可以消除这种不必要的复杂性。这个想法是通过两个关注点来分离你的组件：如何处理用户界面交互逻辑和如何渲染数据。

+   你的 React 组件中少数是有状态的。它们应该位于组件层次结构的顶部。它们封装了所有的交互逻辑，管理用户界面状态，并将该状态通过`props`传递到无状态组件的层次结构中。

+   你的 React 组件中大多数是无状态的。它们通过`this.props`接收其父组件的状态数据，并相应地渲染该数据。

在我们之前的例子中，我们通过`this.props`接收了`isHidden`状态数据，然后渲染了该数据。我们的组件是无状态的。

接下来，让我们创建我们的第一个有状态组件。

# 创建您的第一个有状态的 React 组件

有状态的组件是应用程序处理交互逻辑和管理状态的最合适的地方。它们使您更容易理解应用程序的工作原理。这种推理在构建可维护的 Web 应用程序中起着关键作用。

React 将组件的状态存储在`this.state`对象中。我们将`this.state`的初始值分配为`Component`类的公共类字段：

```jsx
class ReactClass extends React.Component {
  state = {
    isHidden: false
  };

  render() {
    const {
      isHidden
    } = this.state;

    if (isHidden) {
      return null;
    }

    return (
      <h1 className="header">React Component</h1>
    );
  }
}
```

现在，`{ isHidden: false }`是我们的 React 组件和用户界面的初始状态。请注意，在我们的`render()`方法中，我们现在从`this.state`而不是`this.props`中解构`isHidden`属性。

在本章的前面，您已经学习到我们可以通过`this.props`或`this.state`将数据传递给组件的`render()`函数。这两者之间有什么区别呢？

+   `this.props`：这存储了从父级传递的只读数据。它属于父级，不能被其子级更改。这些数据应被视为不可变的。

+   `this.state`：这存储了对组件私有的数据。它可以被组件更改。当状态更新时，组件将重新渲染自身。

如何更新组件的状态？您可以使用`setState(nextState, callback)`通知 React 状态变化。此函数接受两个参数：

+   代表下一个状态的`nextState`对象。它也可以是一个带有`function(prevState, props) => newState`签名的函数。此函数接受两个参数：先前的状态和属性，并返回表示新状态的对象。

+   `callback`函数，您很少需要使用，因为 React 会为您保持用户界面的更新。

React 如何保持用户界面的更新？每次更新组件的状态时，包括任何子组件，它都会调用组件的`render()`函数。实际上，每次调用我们的`render()`函数时，它都会重新渲染整个虚拟 DOM。

当您调用`this.setState()`函数并传递表示下一个状态的数据对象时，React 将将下一个状态与当前状态合并。在合并过程中，React 将用下一个状态覆盖当前状态。未被下一个状态覆盖的当前状态将成为下一个状态的一部分。

想象一下这是我们当前的状态：

```jsx
{
  isHidden: true,
  title: 'Stateful React Component'
}
```

我们调用`this.setState(nextState)`，其中`nextState`如下：

```jsx
{
  isHidden: false
}
```

React 将这两个状态合并为一个新的状态：

```jsx
{
  isHidden: false,
  title: 'Stateful React Component'
}
```

`isHidden`属性已更新，`title`属性未被删除或以任何方式更新。

现在我们知道如何更新我们组件的状态，让我们创建一个对用户事件做出反应的有状态组件：

在这个例子中，我们正在创建一个切换按钮，用于显示和隐藏标题。我们首先设置我们的初始状态对象。我们的初始状态有两个属性：`isHeaderHidden`设置为`false`，标题设置为`Stateful React Component`。现在，我们可以通过`this.state`在我们的`render()`方法中访问这个状态对象。在我们的`render()`方法中，我们创建三个 React 元素：`h1`，`button`和`div`。我们的`div`元素充当我们的`h1`和`button`元素的父元素。然而，在某种情况下，我们创建我们的`div`元素有两个子元素，`header`和`button`元素，而在另一种情况下，我们只创建一个子元素，`button`。我们选择的情况取决于`this.state.isHeaderHidden`的值。我们组件的当前状态直接影响`render()`函数将渲染什么。虽然这对您来说应该很熟悉，但在这个例子中有一些新的东西是我们以前没有见过的。

请注意，我们在组件类中添加了一个名为`handleClick()`的新方法。`handleClick()`方法对 React 没有特殊意义。它是我们应用逻辑的一部分，我们用它来处理`onClick`事件。您也可以向 React 组件类添加自定义方法，因为它只是一个 JavaScript 类。所有这些方法都将通过`this`引用可用，您可以在组件类中的任何方法中访问它。例如，我们在`render()`和`handleClick()`方法中都通过`this.state`访问状态对象。

我们的`handleClick()`方法做什么？它通过切换`isHeaderHidden`属性来更新我们组件的状态：

```jsx
this.setState(prevState => ({
  isHeaderHidden: !prevState.isHeaderHidden
}));
```

我们的`handleClick()`方法对用户与用户界面的交互做出反应。我们的用户界面是一个`button`元素，用户可以点击它，我们可以将事件处理程序附加到它上面。在 React 中，您可以通过将它们传递给 JSX 属性来将事件处理程序附加到组件上：

```jsx
<button onClick={this.handleClick}>
  Toggle Header
</button>
```

React 使用**驼峰命名**约定来命名事件处理程序，例如，`onClick`。您可以在[`facebook.github.io/react/docs/events.html#supported-events`](http://facebook.github.io/react/docs/events.html#supported-events)找到所有支持的事件列表。

默认情况下，React 在冒泡阶段触发事件处理程序，但您可以告诉 React 在捕获阶段触发它们，方法是在事件名称后附加`Capture`，例如`onClickCapture`。

React 将浏览器的原生事件封装到`SyntheticEvent`对象中，以确保所有支持的事件在 Internet Explorer 8 及以上版本中表现一致。

`SyntheticEvent`对象提供与原生浏览器事件相同的 API，这意味着您可以像往常一样使用`stopPropagation()`和`preventDefault()`方法。如果出于某种原因，您需要访问原生浏览器事件，那么可以通过`nativeEvent`属性来实现。

请注意，在上一个示例中，将`onClick`属性传递给我们的`createElement()`函数并不会在呈现的 HTML 标记中创建内联事件处理程序：

```jsx
<button class="btn btn-default">Toggle header</button>
```

这是因为 React 实际上并没有将事件处理程序附加到 DOM 节点本身。相反，React 在顶层监听所有事件，使用单个事件侦听器并将它们委托给它们适当的事件处理程序。

在上一个示例中，您学习了如何创建一个有状态的 React 组件，用户可以与之交互并更改其状态。我们创建并附加了一个事件处理程序到`click`事件，以更新`isHeaderHidden`属性的值。但您是否注意到用户交互不会更新我们在状态中存储的另一个属性`title`的值。这对您来说是否奇怪？我们的状态中有一些数据永远不会改变。这个观察引发了一个重要的问题；我们不应该将什么放在我们的状态中？

问问自己，“我可以从组件的状态中删除哪些数据，而仍然保持其用户界面始终更新？”继续问，继续删除数据，直到您绝对确定没有剩下任何要删除的东西，而不会破坏用户界面。

在我们的示例中，我们在状态对象中有`title`属性，我们可以将其移动到我们的`render()`方法中，而不会破坏我们的切换按钮的交互性。组件仍将按预期工作：

```jsx
class ReactClass extends Component {
  state = {
    isHeaderHidden: false
  }

  handleClick = () => {
    this.setState(prevState => ({
      isHeaderHidden: !prevState.isHeaderHidden
    }));
  }

  render() {
    const {
      isHeaderHidden
    } = this.state;

    if (isHeaderHidden) {
      return (
        <button
          className="btn ban-default"
          onClick={this.handleClick}
        >
          Toggle Header
        </button>
      );
    }

    return (
      <div>
        <h1 className="header">Stateful React Component</h1>
        <button
          className="btn ban-default"
          onClick={this.handleClick}
        >
          Toggle Header
        </button>
      </div>
    );
  }
}
```

另一方面，如果我们将`isHeaderHidden`属性移出状态对象，那么我们将破坏组件的交互性，因为我们的`render()`方法将不再被 React 自动触发，每当用户点击我们的按钮时。这是一个破坏交互性的例子。

```jsx
class ReactClass extends Component {
  state = {}
  isHeaderHidden = false

  handleClick = () => {
    this.isHeaderHidden = !this.isHeaderHidden;
  }

  render() {
    if (this.isHeaderHidden) {
      return (
        <button
          className="btn ban-default"
          onClick={this.handleClick}
        >
          Toggle Header
        </button>
      );
    }

    return (
      <div>
        <h1 className="header">Stateful React Component</h1>
        <button
          className="btn ban-default"
          onClick={this.handleClick}
        >
          Toggle Header
        </button>
      </div>
    );
  }
}
```

### 注意

**注意**：为了获得更好的输出结果，请参考代码文件。

这是一个反模式。

请记住这个经验法则：组件的状态应该存储组件的事件处理程序可能随时间改变的数据，以便重新渲染组件的用户界面并保持其最新状态。在`state`对象中保持组件状态的最小可能表示，并根据`state`和`props`中的内容在组件的`render()`方法中计算其余数据。利用 React 会在其状态改变时重新渲染组件的特性。

# 总结

在这一章中，您达到了一个重要的里程碑：您学会了如何封装状态并通过创建 React 组件来创建交互式用户界面。我们讨论了无状态和有状态的 React 组件以及它们之间的区别。我们谈到了浏览器事件以及如何在 React 中处理它们。

在下一章中，您将了解 React 16 中的新功能。


# 第五章：使您的 React 组件具有反应性

现在您知道如何创建具有状态和无状态的 React 组件，我们可以开始组合 React 组件并构建更复杂的用户界面。实际上，是时候开始构建我们在第二章中讨论的名为**Snapterest**的 Web 应用程序，*为您的项目安装强大的工具*。在此过程中，您将学习如何规划您的 React 应用程序并创建可组合的 React 组件。让我们开始吧。

# 使用 React 解决问题

在开始编写您的 Web 应用程序代码之前，您需要考虑您的 Web 应用程序将解决的问题。清晰地定义问题并尽早理解问题是通往成功解决方案——一个有用的 Web 应用程序的最重要步骤。如果您在开发过程中未能早期定义问题，或者定义不准确，那么以后您将不得不停下来，重新思考您正在做的事情，放弃您已经编写的一部分代码，并编写新的代码。这是一种浪费的方法，作为专业软件开发人员，您的时间对您和您的组织都非常宝贵，因此明智地投资时间符合您的最佳利益。在本书的前面，我强调了使用 React 的好处之一是代码重用，这意味着您将能够在更短的时间内做更多的事情。然而，在我们查看 React 代码之前，让我们首先讨论问题，牢记 React。

我们将构建 Snapterest——一个 Web 应用程序，以实时方式从 Snapkite Engine 服务器接收推文，并将它们一次显示给用户。实际上，我们并不知道 Snapterest 何时会收到新的推文，但是当它收到时，它将至少显示该新推文 1.5 秒，以便用户有足够的时间查看并单击它。单击推文将将其添加到现有推文集合中或创建一个新的推文集合。最后，用户将能够将其集合导出为 HTML 标记代码。

这是我们将要构建的内容的一个非常高层次的描述。让我们将其分解为一系列较小的任务列表：

![使用 React 解决问题](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-ess-2e/img/B05915_05_01.jpg)

以下是步骤：

1.  实时从 Snapkite Engine 服务器接收推文。

1.  一次显示一条推文，持续至少 1.5 秒。

1.  在用户点击事件发生时，将推文添加到集合中。

1.  在集合中显示推文列表。

1.  为集合创建 HTML 标记代码并导出它。

1.  从集合中删除推文，当用户点击事件发生时。

您能否确定哪些任务可以使用 React 解决？请记住，React 是一个用户界面库，因此任何描述用户界面和与用户界面交互的内容都可以用 React 解决。在前面的列表中，React 可以处理除第一个任务之外的所有任务，因为它描述的是数据获取而不是用户界面。第一步将使用我们将在下一章讨论的另一个库来解决。第 2 步和第 4 步描述了需要显示的内容。它们是 React 组件的完美候选者。第 3 步和第 6 步描述了用户事件，正如我们在第四章中所看到的，用户事件处理也可以封装在 React 组件中。您能想到如何使用 React 解决第 5 步吗？请记住，在第三章中，我们讨论了`ReactDOMServer.renderToStaticMarkup()`方法，该方法将 React 元素呈现为静态 HTML 标记字符串。这正是我们需要解决第 5 步的方法。

现在，当我们已经为每个单独的任务确定了潜在的解决方案时，让我们考虑如何将它们组合在一起，创建一个完全功能的 Web 应用程序。

构建可组合的 React 应用程序有两种方法：

+   首先，您可以开始构建单独的 React 组件，然后将它们组合成更高级别的 React 组件，沿着组件层次结构向上移动

+   您可以从最顶层的 React 元素开始，然后实现其子组件，沿着组件层次结构向下移动

第二种策略有一个优势，可以看到和理解应用程序架构的整体情况，我认为在我们考虑如何实现各个功能部分之前，了解一切是如何组合在一起的很重要。

# 规划您的 React 应用程序

在规划您的 React 应用程序时，有两个简单的准则需要遵循：

+   每个 React 组件应该代表 Web 应用程序中的单个用户界面元素。它应该封装可能被重用的最小元素。

+   多个 React 组件应该组合成一个单独的 React 组件。最终，您的整个用户界面应该封装在一个 React 组件中。

![规划您的 React 应用程序](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-ess-2e/img/B05915_05_02.jpg)

我们的 React 组件层次结构图

我们将从我们最顶层的 React 组件**Application**开始。它将封装我们整个的 React 应用程序，并且它将有两个子组件：**Stream**和**Collection**组件。**Stream**组件将负责连接到一系列 tweets，接收并显示最新的 tweet。**Stream**组件将有两个子组件：**StreamTweet**和**Header**。**StreamTweet**组件将负责显示最新的 tweet。它将由**Header**和**Tweet**组件组成。**Header**组件将渲染一个标题。它将没有子组件。**Tweet**组件将渲染一条 tweet 的图片。请注意我们计划重复使用**Header**组件两次。

**Collection**组件将负责显示集合控件和一系列 tweets。它将有两个子组件：**CollectionControls**和**TweetList**。**CollectionControls**组件将有两个子组件：**CollectionRenameForm**组件，它将渲染一个重命名集合的表单，以及**CollectionExportForm**组件，它将渲染一个将集合导出到名为**CodePen**的服务的表单，这是一个 HTML、CSS 和 JavaScript 的游乐场网站。您可以在[`codepen.io`](http://codepen.io)了解更多关于 CodePen 的信息。正如您可能已经注意到的，我们将在**CollectionRenameForm**和**CollectionControls**组件中重用**Header**和**Button**组件。我们的**TweetList**组件将渲染一系列 tweets。每条 tweet 将由一个**Tweet**组件渲染。事实上，总共我们将在**Collection**组件中再次重用**Header**组件。事实上，总共我们将在**Collection**组件中再次重用**Header**组件五次。这对我们来说是一个胜利。正如我们在前一章讨论的那样，我们应该尽可能地保持尽可能多的 React 组件无状态。因此，只有 11 个组件中的 5 个将存储状态，它们分别是：

+   **Application**

+   **CollectionControls**

+   **CollectionRenameForm**

+   **流**

+   **StreamTweet**

现在我们有了一个计划，我们可以开始实施它。

# 创建一个容器 React 组件

让我们从编辑我们应用的主 JavaScript 文件开始。用以下代码片段替换`~/snapterest/source/app.js`文件的内容：

```jsx
import React from 'react';
import ReactDOM from 'react-dom';
import Application from './components/Application';

ReactDOM.render(
  <Application />,
  document.getElementById('react-application')
);
```

这个文件只有四行代码，你可以猜到，它们提供了`document.getElementById('react-application')`作为`<Application/>`组件的部署目标，并将`<Application/>`渲染到 DOM 中。我们的 Web 应用程序的整个用户界面将被封装在一个 React 组件`Application`中。

接下来，导航到`~/snapterest/source/components/`并在这个目录中创建`Application.js`文件：

```jsx
import React, { Component } from 'react';
import Stream from './Stream';
import Collection from './Collection';

class Application extends Component {
  state = {
    collectionTweets: {}
  }

  addTweetToCollection = (tweet) => {
    const { collectionTweets } = this.state;

    collectionTweets[tweet.id] = tweet;

    this.setState({
      collectionTweets: collectionTweets
    });
  }

  removeTweetFromCollection = (tweet) => {
    const { collectionTweets } = this.state;

    delete collectionTweets[tweet.id];

    this.setState({
      collectionTweets: collectionTweets
    });
  }

  removeAllTweetsFromCollection = () => {
    this.setState({
      collectionTweets: {}
    });
  }

  render() {
    const {
      addTweetToCollection,
      removeTweetFromCollection,
      removeAllTweetsFromCollection
    } = this;

    return (
      <div className="container-fluid">
        <div className="row">
          <div className="col-md-4 text-center">
            <Stream onAddTweetToCollection={addTweetToCollection}/>
          </div>
          <div className="col-md-8">
            <Collection
              tweets={this.state.collectionTweets}
              onRemoveTweetFromCollection={removeTweetFromCollection}
              onRemoveAllTweetsFromCollection={removeAllTweetsFromCollection}
            />
          </div>
        </div>
      </div>
    );
  }
}

export default Application;
```

这个组件的代码比我们的`app.js`文件要多得多，但这段代码可以很容易地分成三个逻辑部分：

+   导入依赖模块

+   定义一个 React 组件类

+   将 React 组件类作为模块导出

在`Application.js`文件的第一个逻辑部分中，我们使用`require()`函数导入了依赖模块：

```jsx
import React, { Component } from 'react';
import Stream from './Stream';
import Collection from './Collection';
```

我们的`Application`组件将有两个子组件，我们需要导入它们：

+   `Stream`组件将渲染我们用户界面的流部分

+   `Collection`组件将渲染我们用户界面的收藏部分

我们还需要将`React`库作为另一个模块导入。

`Application.js`文件的第二个逻辑部分创建了 React`Application`组件类，并包含以下方法：

+   `addTweetToCollection()`

+   `removeTweetFromCollection()`

+   `removeAllTweetsFromCollection()`

+   `render()`

只有`render()`方法是 React API 的一部分。所有其他方法都是我们应用逻辑的一部分，这个组件封装了这些方法。我们将在讨论这个组件在`render()`方法中渲染的内容之后更仔细地看一下每一个方法：

```jsx
render() {
  const {
    addTweetToCollection,
    removeTweetFromCollection,
    removeAllTweetsFromCollection
  } = this;

  return (
    <div className="container-fluid">
      <div className="row">
        <div className="col-md-4 text-center">
          <Stream onAddTweetToCollection={addTweetToCollection}/>
        </div>
        <div className="col-md-8">
          <Collection
            tweets={this.state.collectionTweets}
            onRemoveTweetFromCollection={removeTweetFromCollection}
            onRemoveAllTweetsFromCollection={removeAllTweetsFromCollection}
          />
        </div>
      </div>
    </div>
  );
}
```

如你所见，它使用 Bootstrap 框架定义了我们网页的布局。如果你不熟悉 Bootstrap，我强烈建议你访问[`getbootstrap.com`](http://getbootstrap.com)并阅读文档。学习这个框架将使你能够快速轻松地原型化用户界面。即使你不懂 Bootstrap，也很容易理解发生了什么。我们将网页分成两列：一个较小的列和一个较大的列。较小的列包含我们的`Stream` React 组件，较大的列包含我们的`Collection`组件。你可以想象我们的网页被分成了两个不等的部分，它们都包含了 React 组件。

这就是我们如何使用我们的`Stream`组件：

```jsx
<Stream onAddTweetToCollection={addTweetToCollection} />
```

`Stream`组件有一个`onAddTweetToCollection`属性，我们的`Application`组件将自己的`addTweetToCollection()`方法作为这个属性的值传递。`addTweetToCollection()`方法将一条推文添加到集合中。这是我们在`Application`组件中定义的自定义方法之一。我们不需要使用`this`关键字，因为该方法被定义为箭头函数，所以函数的作用域自动成为我们的组件。

让我们看看`addTweetToCollection()`方法做了什么：

```jsx
addTweetToCollection = (tweet) => {
  const { collectionTweets } = this.state;

  collectionTweets[tweet.id] = tweet;

  this.setState({
    collectionTweets: collectionTweets
  });
}
```

该方法引用存储在当前状态中的集合推文，将新推文添加到`collectionTweets`对象，并通过调用`setState()`方法更新状态。当在`Stream`组件内部调用`addTweetToCollection()`方法时，会传递一个新推文作为参数。这是子组件如何更新其父组件状态的一个例子。

这是 React 中的一个重要机制，它的工作方式如下：

1.  父组件将回调函数作为属性传递给其子组件。子组件可以通过`this.props`引用访问这个回调函数。

1.  每当子组件想要更新父组件的状态时，它调用该回调函数并将所有必要的数据传递给新的父组件状态。

1.  父组件更新其状态，正如你已经知道的，这个状态更新并触发`render()`方法，根据需要重新渲染所有子组件。

这就是子组件与父组件交互的方式。这种交互允许子组件将应用程序的状态管理委托给其父组件，并且只关注如何渲染自身。现在当你学会了这种模式，你会一遍又一遍地使用它，因为大多数 React 组件应该保持无状态。只有少数父组件应该存储和管理应用程序的状态。这种最佳实践允许我们通过两种不同的关注点逻辑地对 React 组件进行分组：

+   管理应用程序的状态并渲染它

+   只渲染并将应用程序的状态管理委托给父组件

我们的`Application`组件有一个第二个子组件，`Collection`：

```jsx
<Collection
  tweets={this.state.collectionTweets}
  onRemoveTweetFromCollection={removeTweetFromCollection}
  onRemoveAllTweetsFromCollection={removeAllTweetsFromCollection}
/>
```

这个组件有一些属性：

+   `tweets`：这指的是我们当前的推文集合

+   `onRemoveTweetFromCollection`：这是指从我们的收藏中删除特定推文的函数

+   `onRemoveAllTweetsFromCollection`：这是指从我们的收藏中删除所有推文的函数

你可以看到 `Collection` 组件的属性只关心如何执行以下操作：

+   访问应用程序的状态

+   改变应用程序的状态

可以猜到，`onRemoveTweetFromCollection` 和 `onRemoveAllTweetsFromCollection` 函数允许 `Collection` 组件改变 `Application` 组件的状态。另一方面，`tweets` 属性将 `Application` 组件的状态传播到 `Collection` 组件，以便它可以以只读方式访问该状态。

你能认识到 `Application` 和 `Collection` 组件之间数据流的单向性吗？它是如何工作的：

1.  `collectionTweets` 数据在 `Application` 组件的 `constructor()` 方法中初始化。

1.  `collectionTweets` 数据作为 `tweets` 属性传递给 `Collection` 组件。

1.  `Collection` 组件调用 `removeTweetFromCollection` 和 `removeAllTweetsFromCollection` 函数来更新 `Application` 组件中的 `collectionTweets` 数据，然后循环再次开始。

请注意，`Collection` 组件不能直接改变 `Application` 组件的状态。`Collection` 组件通过 `this.props` 对象只能以只读方式访问该状态，并且更新父组件状态的唯一方法是调用父组件传递的回调函数。在 `Collection` 组件中，这些回调函数是 `this.props.onRemoveTweetFromCollection` 和 `this.props.onRemoveAllTweetsFromCollection`。

我们 React 组件层次结构中数据流的简单心智模型将帮助我们增加所使用的组件数量，而不增加用户界面工作方式的复杂性。例如，它可以有多达 10 层嵌套的 React 组件，如下所示：

![创建一个容器 React 组件](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-ess-2e/img/B05915_05_03.jpg)

如果`Component G`想要改变根`Component A`的状态，它会以与`Component B`或`Component F`或此层次结构中的任何其他组件完全相同的方式来做。但是，在 React 中，您不应该直接将数据从`Component A`传递给`Component G`。相反，您应该首先将其传递给`Component B`，然后传递给`Component C`，然后传递给`Component D`，依此类推，直到最终到达`Component G`。`Component B`到`Component F`将不得不携带一些实际上只是为`Component G`准备的“中转”属性。这可能看起来像是浪费时间，但这种设计使我们能够轻松调试我们的应用程序并推理出其工作原理。始终有优化应用程序架构的策略。其中之一是使用**Flux 设计模式**。另一个是使用**Redux**库。我们将在本书的后面讨论这两种方法。

在我们结束讨论`Application`组件之前，让我们看一下改变其状态的两种方法：

```jsx
removeTweetFromCollection = (tweet) => {
  const { collectionTweets } = this.state;

  delete collectionTweets[tweet.id];

  this.setState({
     collectionTweets: collectionTweets
  });
}
```

`removeTweetFromCollection（）`方法从我们存储在`Application`组件状态中的 tweet 集合中删除一个 tweet。它从组件状态中获取当前的`collectionTweets`对象，从该对象中删除具有给定`id`的 tweet，并使用更新后的`collectionTweets`对象更新组件状态。

另一方面，`removeAllTweetsFromCollection（）`方法从组件状态中删除所有 tweet：

```jsx
removeAllTweetsFromCollection = () => {
  this.setState({
    collectionTweets: {}
  });
}
```

这两种方法都是从子`Collection`组件中调用的，因为该组件没有其他方法可以改变`Application`组件的状态。

# 摘要

在本章中，您学会了如何使用 React 解决问题。我们首先将问题分解为较小的单独问题，然后讨论如何使用 React 来解决这些问题。然后，我们创建了一个需要实现的 React 组件列表。最后，我们创建了我们的第一个可组合的 React 组件，并了解了父组件如何与其子组件交互。

在下一章中，我们将实现我们的子组件，并了解 React 的生命周期方法。
