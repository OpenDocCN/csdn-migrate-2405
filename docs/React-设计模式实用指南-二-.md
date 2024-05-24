# React 设计模式实用指南（二）

> 原文：[`zh.annas-archive.org/md5/44C916494039D4C1655C3E1D660CD940`](https://zh.annas-archive.org/md5/44C916494039D4C1655C3E1D660CD940)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：Flux 架构

如果你之前使用过 React，你可能已经听说过 Flux。如果没有，不用担心。Flux 是用于构建 React 用户界面的一种架构模式。我们将从 React 使用的单向数据流模式开始，然后进入 Flux。Flux 的每一个部分都很重要，我强烈建议你在这一章节花一些时间。你至少应该明白如何分离代码以及如何使用 Flux 将应用程序分割成部分。这些相互连接的小服务负责现代移动应用程序所需的一切。

# 单向数据流模式

在我们深入了解 Flux 架构之前，让我们先看看这种模式的历史背景。我希望你能理解为什么要引入它。

当我看到 Facebook 的开发人员谈论 Flux 架构时，我有一种直觉，他们从 **模型-视图-控制器** (**MVC**) 模式转向了 Flux。MVC 模式是将业务模型与视图标记和编码逻辑解耦。逻辑由一个称为控制器的函数封装，并将工作委托给服务。因此，我们说我们的目标是精简控制器。

然而，在像 Facebook 这样的大规模应用中，看起来这种模式还不够。因为它允许双向数据流，很快就变得难以理解，甚至更难追踪。一个事件引起的变化可能会循环回来，并在整个应用程序中产生级联效应。想象一下，如果你必须在这样的架构中找到一个 bug。

# React 的单向数据绑定

React 对上述问题的解决方案始于单向数据绑定。这意味着视图层由组件维护，只有组件才能更新视图。组件的 `render` 函数计算出结果的原生代码，并显示给最终用户。如果视图层需要响应用户的操作，它只能分发由组件处理的事件。它不能直接改变 **state** 或 **props**。

让我们看一下下面的图表，它说明了这个概念：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/hsn-dsn-ptn-rn/img/2e7339a9-76e7-4a9e-a140-b7678fafd51f.png)

**App**块代表了原生视图层的状态。在图中，组件被简化为：属性、状态、`render`函数和事件监听器。一旦属性或状态发生变化，观察者就会调用`render`函数来更新原生视图。一旦用户执行操作，相应的事件就会被分派，然后被事件监听器捕获。

在双向数据绑定模式中，**App**层不需要分派事件。它可以直接修改组件的状态。我们也可以用事件监听器来模拟这一点。其中一个例子就是受控输入，我们在第二章中学习过，*视图模式*。

# 事件问题

*"伴随着巨大的自由而来的是巨大的责任。"*

你可能已经听过这句话。这种情绪适用于我们分派和处理的事件。让我们讨论一些问题。

首先，要监听事件，您需要创建一个事件监听器。何时应该创建它？通常情况下，我们在具有标记的组件中创建事件监听器，并使用`onClick={this.someEventListener}`进行注册。如果这个事件需要导致完全不同的组件发生变化呢？在这种情况下，我们需要将监听器提升到组件树中的某个容器中。

当我们这样做时，我们注意到我们将越来越多的组件紧密耦合，将越来越多的监听器传递到属性链中。如果可能的话，这是我们想要避免的噩梦。

因此，Flux 引入了 Dispatcher 的概念。Dispatcher 将事件发送到所有注册的组件。这样，每个组件都可以对与其相关的事件做出反应，而忽略与其无关的事件。我们将在本章后面讨论这个概念。

# 绑定的进一步问题

仅使用单向数据绑定是不够的，正如你所看到的。我们很快就会陷入模拟双向数据绑定的陷阱，或者遇到前面部分提到的事件问题。

一切都归结为一个问题：我们能处理吗？对于大规模应用程序，答案通常是*不行*。我们需要一个可预测的模型，保证我们能够迅速找出发生了什么以及为什么。如果事件在我们的应用程序中随处发生，开发人员显然将不得不花费大量时间找出具体是什么导致了检测到的错误。

我们如何缩小这个问题？答案是限制。我们需要对事件流施加一些限制。这就是 Flux 架构发挥作用的地方。

# Flux 简介

Flux 架构对组件之间的通信创建了一些限制。其主要原则是普遍的动作。应用程序视图层通过向分发器发送动作对象来响应用户动作。分发器的作用是将每个动作发送到订阅的**存储**。您可以拥有许多存储，每个存储都可以根据用户的动作做出不同的反应。

例如，想象一下你正在构建一个基于购物车的应用程序。用户可以点击屏幕将一些项目添加到购物车中，随后相应的动作被分发，您的购物车存储对此做出反应。此外，分析存储可能会跟踪用户已将此类项目添加到购物车中。两者都对同一动作对象做出反应，并根据需要使用信息。最终，视图层会根据新状态进行更新。

# 替换 MVC

为了增强 MVC 架构，让我们回顾一下它的外观：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/hsn-dsn-ptn-rn/img/a84b5e73-8666-42c0-9dc8-eac8267ef1c3.png)

动作由各自的控制器处理，这些控制器可以访问模型（数据表示）。视图通常与模型耦合，并根据需要对其进行更新。

当我第一次阅读这个架构时，我很难理解它。如果你还没有亲自使用过它，让我给你一些建议：

+   动作：将其视为用户的动作，例如按钮点击、滚动和导航更改。

+   控制器：这是负责处理动作并显示适当的本机视图的部分。

+   模型：这是一个保存信息的数据结构，与视图分离。视图需要模型来根据设计进行视觉显示。

+   视图：这是最终用户所看到的内容。视图描述了所有的标记代码，以后可以进行样式化。视图有时与样式耦合在一起，被称为一个整体。

随着应用程序的增长，小型架构迟早会变成以下的样子：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/hsn-dsn-ptn-rn/img/dc8cf004-b83c-41e8-b5d4-da53234b4c5a.png)

在这个图表中，我试图通过在模型结构中创建缩进来显示一些模型依赖于其他模型。视图也是类似的情况。这不应被视为不好。一般来说，这种架构在某种程度上是有效的。问题出现在当您发现错误时，却无法确定错误出现的位置和原因。更准确地说，您失去了对信息流的控制。您会发现自己处于一个同时发生许多事情的位置，以至于您无法轻易预测是什么导致了失败，也无法理解为什么会发生。有时，甚至很难重现错误或验证它是否实际上是一个错误。

从图表中可以看出，模型-视图通信存在问题：它是双向的。这是软件多年来一直在做的事情。一些聪明的人意识到，在客户端环境中，我们可以承担单向数据流。这将有效地使架构可预测。如果我们的控制器只有一系列输入数据，然后应该提供视图的新状态，那将会更清晰。单元测试可以提供一系列数据，比如输入，并对输出进行断言。同样，跟踪服务可以记录任何错误并保存输入数据系列。

让我们来看一下 Flux 提出的数据流：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/hsn-dsn-ptn-rn/img/0374b19f-0447-4179-aa85-3ea18bc8e2ad.png)

所有操作都通过分发器进行，并且然后发送到注册的存储回调。最终，存储内容被映射到视图。

随着时间的推移，这可能变得复杂，就像下图所示的那样：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/hsn-dsn-ptn-rn/img/1c865594-3e35-4e8e-b74a-d8239804b78f.png)

您可能会有各种不同的存储库，这些存储库在不同的视图或视图部分中使用。我们的视图组合成用户看到的最终视图。如果发生了变化，另一个操作将被分派到存储库中。这些存储库计算新状态并刷新视图。

这样就简单多了。我们现在可以跟踪操作，并查看哪个操作导致了存储中不需要的更改。

# 以示例说明 Flux

在我们深入研究 Flux 之前，让我们使用 Flux 架构创建一个简单的应用程序。为此，我们将使用 Facebook 提供的 Flux 库。该库包括我们需要的所有组件，以便根据新的 Flux 流使应用程序正常运行。安装 Flux 和`immutable`库。随着我们对 Flux 的了解越来越多，`immutable`也对进一步的优势至关重要：

```jsx
yarn add flux immutable
```

我们在 Flux 中构建的应用程序是一个 Tasks 应用程序。我们已经创建的应用程序需要一些调整。首先要做的是创建`Dispatcher`，Tasks 存储和任务操作。

Flux 包提供了我们架构的基础。例如，让我们为我们的 Tasks 应用程序实例化`Dispatcher`：

```jsx
// src / Chapter 4_ Flux patterns / Example 1 / src / data / AppDispatcher.js
import { Dispatcher } from 'flux';   export default new Dispatcher(); 
```

`Dispatcher`将用于调度操作，但我们需要首先创建操作。我将遵循文档建议，首先创建操作类型：

```jsx
// src / Chapter 4_ Flux patterns / Example 1 / src / data / TasksActionTypes.js
**const** ActionTypes = {
 ADD_TASK: 'ADD_TASK' }**;**   export default ActionTypes; 
```

现在我们已经创建了类型，接下来应该跟进操作创建者本身，如下所示：

```jsx
// src / Chapter 4_ Flux patterns / Example 1 / src / data / TaskActions.js
import TasksActionTypes from './TasksActionTypes'; import AppDispatcher from './AppDispatcher';   const Actions = {
    addTask(task) {
 AppDispatcher.dispatch({
 type: TasksActionTypes.ADD_TASK,
  task
 });
  }
};   export default Actions; 
```

到目前为止，我们有了操作和调度它们的工具。缺失的部分是`Store`，它将对操作做出反应。让我们创建`TodoStore`：

```jsx
// src / Chapter 4_ Flux patterns / Example 1 / src / data / TaskStore.js
import Immutable from 'immutable'; import { ReduceStore } from 'flux/utils'; import TasksActionTypes from './TasksActionTypes'; import AppDispatcher from './AppDispatcher';   class TaskStore extends ReduceStore {
    constructor() {
        super(AppDispatcher)**;**
  }

    getInitialState() {
        return Immutable.List([]);
  }

    reduce(state, action) {
 switch (action.type) {
 case TasksActionTypes.ADD_TASK:
 return state; // <= placeholder, to be replaced!!!   default:
 return state;
  }
 }
}

export default new TaskStore(); 
```

要创建存储，我们从`flux/utils`导入`ReduceStore`。存储类应该扩展以提供必要的 API 方法。我们将在以后的部分中介绍这些。就目前而言，您应该已经注意到您需要在构造函数中使用`super`将`Dispatcher`传递给上层类。

另外，让我们为`ADD_TASK`实现`reduce`情况。相同的流程可以调整到您想要创建的任何其他操作类型：

```jsx
reduce(state, action) {
    switch (action.type) {
    case TasksActionTypes.ADD_TASK:
        if (!action.task.name) {
            return state;
  }
        return state.push({
            name: action.task.name,
  description: action.task.description,
  likes: 0
  });
  default:
        return state;
  }
}
```

现在我们已经拥有了 Flux 架构的所有要素（`Action`，`Dispatcher`，`Store`和`View`），我们可以将它们全部连接起来。为此，flux/utils 提供了一个方便的容器工厂方法。请注意，我将重用我们以前任务应用程序的视图。为了清晰起见，我已经删除了喜欢的计数器：

```jsx
// src / Chapter 4 / Example 1 / src / App.js
import { Container } from 'flux/utils'; import TaskStore from './data/TaskStore'; import AppView from './views/AppView';   const getStores = () => [TaskStore]; const getState = () => ({ tasks: TaskStore.getState() })**;**   export default Container.createFunctional(AppView, getStores, getState);
```

如果您没有从头开始阅读本书，请注意我们在这里使用容器组件。这种模式非常重要，需要理解，我们在第一章中已经介绍过了，*React 组件模式*。在那里，您可以学习如何从头开始创建容器组件。

我们的应用程序现在配备了 Flux 架构工具。我们需要做的最后一件事是重构以遵循我们的新原则。

为此，这是我们的任务：

1.  初始化存储与任务，而不是直接将 JSON 数据传递给视图。

1.  创建一个添加任务表单，当提交时会调度一个`ADD_TASK`操作。

第一个相当简单：

```jsx
// src / Chapter 4_ Flux patterns / Example 1 / src / data / TaskStore.js
import data from './tasks.json';

class TaskStore extends ReduceStore {
// ...
    getInitialState() {
 return Immutable.List([...data.tasks]);
  }
// ...
```

第二个要求我们使用`Input`组件。让我们创建一个负责整个功能的单独文件。在这个文件中，我们将为名称和描述创建状态，一个`handleSubmit`函数，该函数会调度`ADD_TASK`操作，以及一个包含表单视图标记的`render`函数：

```jsx
// src / Chapter 4_ Flux patterns / Example 1 / src / views / AddTaskForm.js

export const INITIAL_ADD_TASK_FORM_STATE = {
    name: '',
  description: '' };   class AddTaskForm extends React.Component {
    constructor(props) {
        super(props);
  this.handleSubmit.bind(this);
  }

    state = INITIAL_ADD_TASK_FORM_STATE**;**    handleSubmit = () => {
 TaskActions.addTask({
 name: this.state.name,
  description: this.state.description
  });
  this.setState(INITIAL_ADD_TASK_FORM_STATE);
  }**;**    render = () => (
        <View style={styles.container}>
 <**TextInput**  style={styles.input}
                placeholder="Name"
  onChangeText={name => this.setState({ name })}
                value={this.state.name}
            />
 <**TextInput**  style={styles.input}
                placeholder="Description"
  onChangeText={d => this.setState({ description: d })}
                value={this.state.description}
            />
 <**Button**  title="Add task"
  onPress={() => this.handleSubmit()}
            />
 </View>  ); }

// ... styles
```

完全功能的应用程序将如下所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/hsn-dsn-ptn-rn/img/2e0b32f7-d6bb-4a3a-9988-026c154b6ba9.png)

现在我们已经创建了遵循 Flux 架构的第一个应用程序，是时候深入了解 API 了。

# 详细的 Flux 图

让我们以更正式的方式来看 Flux 架构。这里有一个简化架构的小图表：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/hsn-dsn-ptn-rn/img/94b375ec-5f50-4cfb-bd41-efd662e7ec0d.png)官方文档中的 Flux 图：https://github.com/facebook/flux

在前面的图表中，每个部分都有自己在循环链中的目的：

+   调度程序：应用程序中发生的一切都由它来管理。它管理动作并将它们提供给注册的回调函数。所有动作都需要通过调度程序。调度程序必须公开`register`和`unregister`方法来注册/注销回调，并必须公开`dispatch`方法来分发动作。

+   存储：应用程序由多个在调度程序中注册回调的存储组成。每个存储需要公开一个接受`Dispatcher`参数的`constructor`方法。构造函数负责使用给定的调度程序注册此存储实例。

+   React 视图：这个主题在上一章中已经涵盖过了。如果你没有从头开始阅读这本书，请看一下。

+   操作创建者：这些将数据组合成一个动作对象，然后交付给调度程序。这个过程可能涉及数据获取和其他手段来获取必要的数据。操作创建者可能会导致**副作用**。我们将在下一节中涵盖这个主题。操作创建者必须在最后返回一个普通的动作对象。

您可以在以下链接下找到每个部分的完整 API 参考：

[`facebook.github.io/flux/.`](https://facebook.github.io/flux/)

# 什么是副作用？

副作用是在被调用函数之外发生的应用程序状态更改——确切地说，除了其返回值之外的任何状态更改。

这里有一些副作用的例子：

+   修改全局变量

+   修改父作用域链中的变量

+   写入屏幕

+   写入文件

+   任何网络请求，例如，AJAX 请求

这部分关于副作用的内容旨在让你为下一章做好准备，在那里我们将在 Redux 的上下文中讨论纯函数。此外，我们将在《第九章》《函数式编程模式》中进一步推进这些想法，您将学习如何从函数式编程实践中受益，例如可变和不可变对象，高阶函数和单子。

# 为什么要识别副作用？

副作用操纵的是不属于函数属性的状态。因此，当我们孤立地看待函数时，很难评估函数对应用程序是否有任何负面影响。这不仅在单元测试中成立；在进行数学证明时也很麻烦。一些必须安全的大型应用程序可以努力构建一个经得起考验的数学模型。这样的应用程序使用超出本书材料的数学工具进行验证。

副作用，当被隔离时，可以作为我们应用程序的数据提供者。它们可以在最佳时机“注入”流程，从那时起，数据就被视为变量。从一个无副作用的函数到另一个。这样的无副作用函数链更容易调试，并且在某些情况下可以重播。通过重播，我指的是传递完全相同的输入数据来评估输出，并查看是否符合业务标准。

让我们从 MVC 和 Flux 的角度来看这个概念的实际面。

# 在 MVC 中处理副作用

如果我们遵循经典的 MVC 架构，我们将按照以下关注点的分离工作：模型、视图和控制器。此外，视图可能会暴露直接更新模型的函数。如果发生这种情况，可能会触发副作用。

有几个地方可以放置副作用：

+   控制器初始化

+   控制器相关服务（这项服务是一个解耦的专业逻辑部分）

+   视图，使用作为回调暴露的控制器相关服务

+   在某些情况下，对模型进行更新（服务器-客户端双向模型）

我相信你甚至可以想出更多。

这种自由是以巨大的代价为代价的。我们可以有几乎无限数量的与副作用交织在一起的路径，如下所示：

+   副作用 => 控制器 => 模型 => 视图

+   控制器 => 副作用 => 模型 => 视图

+   控制器 => 视图 => 模型 => 副作用

这会破坏我们以无副作用的方式对整个应用程序进行推理的能力。

MVC 通常如何处理这个问题？答案很简单——大部分时间这种架构并不关心它。只要我们能通过单元测试断言应用程序按预期工作，我们就会很满意。

但后来 Facebook 出现了，并声称我们可以在前端做得更好。由于前端的特殊性质，我们可以更有条理地组织和规定流程，而不会有显著的性能损失。

# 在 Flux 中处理副作用

在 Flux 中，我们仍然保留选择触发副作用的自由，但我们必须尊重单向流。

Flux 中可能的副作用示例包括以下内容：

+   在用户点击时下载数据，然后将其发送给分发器

+   分发器在发送数据给注册的回调之前下载数据

+   存储开始同步副作用以保留更新所需的数据

一个好主意是强制副作用只发生在 Flux 架构中的一个地方。我们可以只在操作触发时执行副作用。例如，当用户点击触发`SHOW_MORE`操作时，我们首先下载数据，然后将完整对象发送给分发器。因此，分发器或任何存储都不需要执行副作用。这个好主意在**Redux Thunk**中被使用。我们将在下一章中学习 Redux 和 Redux Thunk。

了解本书中更高级材料的关键在于副作用。现在我们已经了解了副作用，让我们继续阅读本章摘要。

# 摘要

总之，Flux 对于大型应用程序来说是一个非常好的发明。它解决了经典 MVC 模式难以解决的问题。事件是单向的，这使得通信更加可预测。您的应用程序的领域可以很容易地映射到存储，然后由领域专家维护。

所有这些都得益于一个经过深思熟虑的模式，包括一个分发器、存储和操作。在本章中，我们使用了`flux-utils`，这是 Facebook 的官方库，制作了基于 Flux 的小应用程序。

连接了所有这些部分后，我们准备深入研究一个特定的方面——存储。有一些模式可以让你将存储放在另一个层次上。其中一个是 Redux 库。我们将在下一章中探讨 Redux 提供的不同功能。

# 问题

1.  为什么 Facebook 放弃了经典的 MVC 架构？

答：Facebook 在处理 Facebook 所需的大规模时，发现了 MVC 存在的问题。在前端应用程序中，视图和模型紧密耦合。双向数据流使情况变得更糟：很难调试数据在模型和视图之间的转换以及哪些部分负责最终状态。

1.  Flux 架构的主要优势是什么？

答：观看在*进一步阅读*部分提到的视频**Hacker Way: Rethinking Web App Development at Facebook**，或查看*替换 MVC*部分。

1.  你能画出 Flux 架构的图吗？你能详细地用 Web API 绘制并连接到你的图表吗？

答：查看*详细的 flux 图*部分。

1.  调度程序的作用是什么？

答：如果需要再次查看完整的解释，请查看*Flux 介绍*或*详细的 flux 图*。

1.  你能举四个副作用的例子吗？

答：查看*Flux 介绍*。

1.  Flux 架构中如何解耦副作用？

答：查看*在 Flux 中处理副作用*部分。

# 进一步阅读

+   官方 Flux 文档页面可以在[`facebook.github.io/flux/`](https://facebook.github.io/flux/)找到。

+   GitHub 存储库中的 Flux 示例可以在[`github.com/facebook/flux/tree/master/examples`](https://github.com/facebook/flux/tree/master/examples)找到。

+   Facebook 的会议视频（F8 2014）名为**Hacker Way: Rethinking Web App Development at Facebook**，可在[`www.youtube.com/watch?v=nYkdrAPrdcw`](https://www.youtube.com/watch?v=nYkdrAPrdcw)上观看。

+   **React Native 中的 Flux** - **Yoav Amit**，Wix 工程技术讲座可在[`www.youtube.com/watch?v=m-rMK5ZZM5k`](https://www.youtube.com/watch?v=m-rMK5ZZM5k)上观看。


# 第五章：存储模式

围绕 JavaScript 虚拟存储构建的模式包含了决定应用程序中显示什么的一切所需内容。在我看来，这是理解 Flux 的最重要的部分，因此，我专门为存储模式撰写了一个特别的章节，以便通过许多示例并比较替代方案。由于 React Native 应用程序通常需要离线工作，我们还将学习如何将我们的 JavaScript 存储转换为用户移动设备上的持久存储。这将在用户体验方面将我们的应用程序提升到一个新的水平。

在本章中，您将学到以下内容：

+   如何将 Redux 集成到您的 Flux 架构中

+   Redux 与经典 Flux 的不同之处以及新方法的好处

+   Redux 的核心原则

+   如何创建一个将成为唯一真相来源的存储

+   效果模式和副作用是什么

# 使用 Redux 存储

我花了一段时间才弄清楚如何向您宣传 Redux。您很可能期望它是一种在 Flux 中使用的存储实现。这是正确的；但是，Redux 不仅仅是这样。Redux 是一段精彩的代码，是一个很棒的工具。这个工具可以在许多不同的项目中以许多不同的方式使用。在这本书中，我致力于教会您如何在 React 和 Redux 中思考。

这个介绍受到了 Cheng Lou 在 React Conf 2017 上发表的有用演讲*Taming the Meta Language*的启发。

在[`goo.gl/2SkWAj`](https://goo.gl/2SkWAj)观看。

# Redux 应用程序的最小示例

在我向您展示 Redux 架构之前，让我们看看它的实际运行情况。了解 Redux API 的外观至关重要。一旦我们在 Redux 中开发了最简单的 hello world 应用程序，我们将进行更高级的概述。

我们将构建的 hello world 应用程序是一个计数器应用程序，只有两个按钮（增加和减少）和一个显示当前计数的文本。

在我们深入之前，让我们使用以下命令安装两个软件包：

```jsx
yarn add redux react-redux
```

好的，首先，让我们创建一些基本的 Flux 部分，这些部分我们已经知道，但这次使用 Redux API：

+   `ActionTypes`：

```jsx
// Chapter 5 / Example 1 / src / flux / AppActionTypes.js

const ActionTypes = {
    INC_COUNTER: 'INC_COUNTER',
  DEC_COUNTER: 'DEC_COUNTER' };   export default ActionTypes; 
```

+   `Store`：

```jsx
// Chapter 5 / Example 1 / src / flux / AppStore.js

import { combineReducers, createStore } from 'redux'; import counterReducer from '../reducers/counterReducer';   const rootReducer = combineReducers({
    count: counterReducer            // reducer created later on });   const store = createStore(rootReducer);   export default store; 
```

注意两个新词——`Reducer`和`rootReducer`。`rootReducer`将所有其他 reducer 组合成一个。`Reducer`负责根据已发生的操作生成状态的新版本。如果当前操作与特定的`Reducer`不相关，Reducer 也可以返回旧版本的状态。

+   `CounterReducer`：

```jsx
// Chapter 5 / Example 1 / src / reducers / counterReducer.js

import types from '../flux/AppActionTypes';   const counterReducer = (state = 0, action) => {
    switch (action.type) {
    case types.INC_COUNTER:
        return state + 1;
  case types.DEC_COUNTER:
        return state - 1;
  default:
        return state;
  }
};   export default counterReducer; 
```

+   `Dispatcher`：

```jsx
// Chapter 5 / Example 1 / src / flux / AppDispatcher.js
import store from './AppStore';   export default store.dispatch;  
```

很好，我们已经有了所有的 Flux 组件，所以现在可以继续实际的实现了。

让我们先从简单的事情开始，视图。它应该显示两个`Button`和一个`Text`组件。在按钮按下时，计数器应该增加或减少，如下所示：

```jsx
// Chapter 5 / Example 1 / src / views / CounterView.js

const CounterView = ({ inc, dec, count }) => (
    <View style={styles.panel}>
 <Button title="-" onPress={dec} />
 <Text>{count}</Text>
 <Button title="+" onPress={inc} />
 </View> );   const styles = StyleSheet.create({
    panel: {
        // Check chapter 3: "Style patterns" to learn more on styling
        flex: 1,
  marginTop: 40,
  flexDirection: 'row'
  }, });   export default CounterView;
```

现在是时候向视图提供必要的依赖项了：`inc`，`dec`和`counter`属性。前两个非常简单：

```jsx
// Chapter 5 / Example 1 / src / Counter.js const increaseAction = () => dispatch({ type: types.INC_COUNTER }); const decreaseAction = () => dispatch({ type: types.DEC_COUNTER });
```

现在我们将它们传递给视图。在这里，将使用许多特定的 Redux API 组件。`Provider`用于提供`store`以连接调用。这是可选的 - 如果您真的想手动执行此操作，可以直接将`store`传递给`connect`。我强烈建议使用`Provider.Connect`来创建一个围绕分发和状态的 facade。在状态更改的情况下，组件将自动重新渲染。

Facade 是另一种完全不同的模式。它是一种结构设计模式，用于与复杂的 API 进行交互。如果典型用户对所有功能都不感兴趣，提供一个带有一些默认设置的函数对用户来说非常方便。这样的函数被称为`facade`函数，并且也在 API 中公开。最终用户可以更快地使用它，而无需进行复杂和优化项目所需的深入挖掘。

在下面的片段中检查如何使用`Provider`和`Connect`：

```jsx
// Chapter 5 / Example 1 / src / Counter.js
... import { Provider, connect } from 'react-redux'; ...    const mapStateToProps = state => ({
    count: state.count,
  inc: increaseAction,
  dec: decreaseAction });   const CounterContainer = connect(mapStateToProps)(CounterView);   const CounterApp = () => (
    <Provider store={store}><CounterContainer /></Provider> );   export default CounterApp; 
```

就是这样。我们已经完成了第一个 Redux 应用程序。

# Redux 如何适配 Flux

我们执行的步骤创建了一个`Counter`应用程序，涉及连接 Flux 组件。让我们看看我们使用的图表：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/hsn-dsn-ptn-rn/img/4d9f0c18-5054-4873-95bf-e1b3e4db7a68.png)

首先，我们有**Actions**被分发。然后运行根`Reducer`函数，并且每个 reducer 确定是否需要更改状态。根**Reducer**返回一个新版本的**State**，并且状态传递给**View**根。`connect`函数确定是否应重新渲染特定视图。

请注意，前面的图表遵循 Flux 架构。实际的 Redux 实现，正如您在计数器示例中所看到的，有些不同。分发器由 Store API 封装并作为`store`函数公开。

# 转向 Redux

Redux 不仅可以做简单的状态管理。它也以在具有庞大状态对象和许多业务模型的应用程序中表现出色而闻名。也就是说，让我们将我们的任务应用程序重构为 Redux。

`Tasks`应用程序是在前几章中开发的。如果你直接跳到这一章，请看一下位于 GitHub 存储库中的`src / Chapter 4 / Example 1_ Todo app with Flux`的应用程序。

重构步骤将类似。用 Redux 的部分替换现有的 Flux 部分：

+   `ActionTypes`：实际的实现是可以的：

```jsx
const ActionTypes = {
    ADD_TASK: 'ADD_TASK' };   export default ActionTypes;
```

+   `TaskStore.js`: 重命名为`AppStore.js`。现在，`store`只有一个实例。

此外，我们需要将`reduce`函数移动到一个单独的 reducer 文件中。剩下的部分应该转换为新的语法：

```jsx
// Chapter 5 / Example 2 / src / data / AppStore.js  const rootReducer = combineReducers({ tasks: taskReducer}); const store = createStore(rootReducer); export default store;
```

+   `AppDispatcher.js`：调度程序现在是存储的一部分。

```jsx
// Chapter 5 / Example 2 / src / data / AppDispatcher.js import store from './AppStore';  export default store;
// ATTENTION: To stay consistent with Flux API
// and previous implementation, I return store.
// Store contains dispatch function that is expected. 
```

+   `taskReducer.js`：这是一个我们需要创建的新文件。然而，它的内容是从之前的`reduce`函数中复制过来的：

```jsx
// Chapter 5 / Example 2 / src / reducers / taskReducer.js
...
import data from '../data/tasks.json';

const taskReducer = (state = Immutable.List([...data.tasks]), action) => {
    switch (action.type) {
    case TasksActionTypes.ADD_TASK:
        if (!action.task.name) {
            return state;
  }
        return state.push({
            name: action.task.name,
  description: action.task.description,
  likes: 0
  });
  default:
        return state;
  }
};   export default taskReducer;
```

最后一个必需的步骤是更改应用程序容器，如下所示：

```jsx
// Chapter 5 / Example 2 / src / App.js   const mapStateToProps = state => ({ tasks: state.tasks }); const AppContainer = connect(mapStateToProps)(AppView); const TasksApp = () => (
    <Provider store={store}><AppContainer /></Provider> );   export default TasksApp; 
```

到目前为止，一切顺利。它有效。但这里有一些事情我们跳过了。我会向你展示我们可以做得更好的地方，但首先，让我们学习一些 Redux 的原则。

# Redux 作为一种模式

当 Redux 做得好时，它提供了出色的功能，比如**时间旅行**和**热重载**。时间旅行允许我们根据操作日志看到应用程序随时间的变化。另一方面，热重载允许我们在不重新加载应用程序的情况下替换代码的部分。

在本节中，我们将学习 Redux 的核心原则和一些常见的推荐方法。

请努力阅读 Redux 文档。这是一个很好的免费资源，可以学习如何在 React 和 Redux 中思考。它还将帮助你将 Redux 的使用扩展到 React 生态系统之外，并且可以在以下网址找到：

[`redux.js.org/introduction/examples`](https://redux.js.org/introduction/examples).[ ](https://redux.js.org/introduction/examples)

# Redux 的核心原则

**单一数据源**：整个应用程序的状态存储在单个存储中的对象树中。理想情况下，应该有一个单一的 Redux 存储，可以指导视图渲染整个应用程序。这意味着你应该将所有的状态远离类组件，直接放在 Redux 存储中。这将简化我们在测试中恢复视图的方法，或者当我们进行时间旅行时。

对于一些开发人员来说，有一个单一的存储位置感觉不自然，很可能是因为多年来在后端，我们已经学会了它会导致单片架构。然而，在应用环境中并非如此。不会期望应用窗口在垂直方向上扩展以处理大量用户的负载。也不应该在单个设备上同时被数百名用户使用。

**状态是只读的**：改变状态的唯一方法是发出一个动作——描述发生了什么的对象。我们必须有一个单一的流来影响我们的存储。存储是我们应用状态的表示，不应该被随机代码改变。相反，任何有兴趣改变状态的代码都应该提交一份被称为**动作对象**的**签名文件**。这个动作对象代表了一个已知的在我们库中注册的动作，称为**动作类型**。Reducer 是决定状态变化的逻辑。具有单一流的不可变状态更容易维护和监督。确定是否有变化以及何时发生变化更快。我们可以轻松地创建一个审计数据库。特别是在银行等敏感行业，这是一个巨大的优势。

**通过纯函数进行更改**：为了指定状态树如何通过操作进行转换，您需要编写纯净的 reducer。这是一个我们还没有讨论过的概念。Reducer 需要是纯函数。纯函数保证没有外部情况会影响函数的结果。简而言之，reducer 不能执行 I/O 代码、受时间限制的代码，或者依赖于可变作用域数据的代码。

纯函数是满足两个要求的函数：

+   给定相同的输入参数，它返回相同的输出

+   函数执行不会引起任何副作用

一个很好的例子是常见的数学函数。例如，给定 1 和 3 的加法函数总是返回 4。

这为什么有益并且应该被视为原则可能并不明显。想象一种情况，一个 bug 在开发阶段无意中被引入到你的项目中。或者更糟糕的是，它泄漏到生产环境，并在用户的某个会话期间炸毁了一个关键应用。很可能你有一些错误跟踪，你可以得到异常和堆栈跟踪，显示了一个漫长而模糊的路径通过被压缩的代码。然而，你需要修复它，所以你尝试在你的本地机器上重现完全相同的情况，最终花了连续三天的时间才意识到问题是一些无聊的竞争条件。想象一下，相反，你有一个单一的动作流（没有未跟踪条件的随机交换），你跟踪和记录。此外，你的整个应用依赖于只能根据动作流改变的状态。在失败的情况下，你需要存储的只是动作跟踪，以便回放情况。瞧，我刚刚为你节省了一两天的时间。

当我用类似的例子学习 Redux 时，我仍然很难理解为什么纯函数在这里如此重要。在 Chrome 的 Redux 标签中进行时间旅行的玩耍让我更清楚地看到了实际情况。当你来回进行操作时，一些有状态的组件（即依赖内部状态而不是 Redux 状态的组件）将不会跟随。这是一个巨大的问题，因为它破坏了你的时间旅行，使一些部分处于未来状态。

# 转向单一真相来源

现在是练习的时候了。我们的新目标是重构 Tasks 应用程序，使其具有一个单一的真相来源的存储。

为了做到这一点，我们需要寻找依赖组件状态而不是 Redux 存储的地方。到目前为止，我们有三个视图：

+   `AppView.js`：这个组件相当简单，分为头部、底部和主要内容。

这是一个呈现组件，不持有状态。它的 props 由`AppContainer`提供，后者已经使用了 Redux 存储。`AppView`将主要内容委托给以下两个子视图。

+   `TaskList.js`：这是一个呈现组件，负责在一个简单可滚动的列表中显示待办任务。它的 props 是由`AppView`从`AppContainer`中转发的。

+   `AddTaskForm.js`：这是一个容器组件，基于`TextInput`组件。这个部分使用了内部状态。如果可能的话，我们应该重构这个部分。

如果你曾经读过关于 React 和 Redux 的内容，你可能会发现这个例子与你在网页上找到的内容非常相似，但实际上并不是。如果你在阅读本书的前几章时，可能会有一种直觉；如果没有，我强烈建议你回到“第二章 > 构建表单 > 不受控输入”。

我们的目标是以某种方式将状态从`AddTaskForm`移动到 Redux 存储中。这就是问题开始的地方。你可能已经注意到`TextInput`是 React-Native API 的一部分，我们无法改变它。但`TextInput`是一个有状态的组件。这是在构建 React Native 应用时，你应该意识到的关于 Redux 的第一件事——有些部分需要有状态，你无法绕过它。

幸运的是，`TextInput`的有状态部分只管理焦点。你几乎不太可能需要在 Redux 存储中存储关于它的信息。所有其他状态都属于我们的`AddTaskForm`组件，我们可以解决这个问题。让我们马上做。

在惯用的 Redux 中，你的状态应该被规范化，类似于数据库。在 SQL 数据库中有已知的规范化技术，通常是基于实体之间的 ID 引用。你可以通过使用 Normalizr 库在 Redux 存储中采用这种方法。

首先，我们将重建`AddTaskForm`组件。它需要分派一个新的动作，这将触发一个新的减速器，并改变 Redux 存储中的一个新键（我们将在后面开发后面的部分）：

```jsx
// Chapter 5 / Example 3 / src / views / AddTaskForm.js
class AddTaskForm extends React.Component {
    // ...
    handleSubmit = () => {
        if (this.props.taskForm.name) {
            TaskActions.addTask({
                name: this.props.taskForm.name,
  description: this.props.taskForm.description
  });
  this.nameInput.clear();
  this.descriptionInput.clear()**;**
  }
    };    render = () => (
        <View style={styles.container}>
 <TextInput  style={styles.input}
                placeholder="Name"
  ref={(input) => { this.nameInput = input; }}
                onChangeText={
 name => TaskActions.taskFormChange({
 name,
  description: this.props.taskForm.description
  })
 }
                value={this.props.taskForm.name}
            />
 <TextInput  style={styles.input}
                placeholder="Description"
  ref={(input) => { this.descriptionInput = input; }}
 onChangeText={
 desc => TaskActions.taskFormChange({
 name: this.props.taskForm.name,
  description: desc
 })
 }
 value={this.props.taskForm.description}
            />
 <Button  title="Add task"
  onPress={() => this.handleSubmit()}
            />
 </View>  ); }
```

最困难的部分已经过去了。现在是时候创建一个全新的`taskFormReducer`，如下所示：

```jsx
// Chapter 5 / Example 3 / src / reducers / taskFormReducer.js export const INITIAL_ADD_TASK_FORM_STATE = {
    name: '',
  description: '' };   const taskFormReducer = (
    state = INITIAL_ADD_TASK_FORM_STATE,
  action
) => {
    switch (action.type) {
    case TasksActionTypes.TASK_FORM_CHANGE:
        return action.newFormState;
  default:
        return state;
  }
};   export default taskFormReducer; 
```

接下来，向`TasksActionTypes`添加一个新的动作类型，如下所示：

```jsx
// Chapter 5 / Example 3 / src / data / TasksActionTypes.js
const ActionTypes = {
    ADD_TASK: 'ADD_TASK',
  TASK_FORM_CHANGE: 'TASK_FORM_CHANGE' };
```

然后，添加动作本身，如下所示：

```jsx
// Chapter 5 / Example 3 / src / data / TaskActions.js
const Actions = {
    // ...   taskFormChange(newFormState) {
        AppDispatcher.dispatch({
            type: TasksActionTypes.TASK_FORM_CHANGE,
  newFormState
        });
  }
};
```

接下来，在`AppStore`中注册一个新的减速器，如下所示：

```jsx
// Chapter 5 / Example 3 / src / data / AppStore.js
const rootReducer = combineReducers({
    tasks: taskReducer,
  taskForm: taskFormReducer });
```

最后，我们需要传递新的状态：

```jsx
// Chapter 5 / Example 3 / src / App.js
const mapStateToProps = state => ({
    tasks: state.tasks,
  taskForm: state.taskForm }); 
```

我们将其传递到组件树上的`AppView`，如下所示：

```jsx
// Chapter 5 / Example 3 / src / views / AppView.js
const AppView = props => (
        // ...  <AddTaskForm taskForm={props.taskForm} />
 // ...  );
```

最后，我们连接了所有的部分。享受你的集中式单一真相源 Redux 存储。

或者，看一下`redux-form`库。在写这本书的时候，它是 Redux 中构建表单的行业标准。该库可以在[`redux-form.com`](https://redux-form.com)找到。

# 使用 MobX 创建一个替代方案

在没有强大替代方案的情况下依赖 Redux 是愚蠢的。MobX 就是这样的替代方案之一，它是一个状态管理库，对变化没有那么多意见。MobX 尽可能少地提供样板文件。与 Redux 相比，这是一个巨大的优势，因为 Redux 非常显式，需要大量的样板文件。

在这里，我必须停下来提醒您，React 生态系统倾向于显式性，即构建应用程序而没有太多隐藏的机制。您控制流程，并且可以看到应用程序完成 Flux 的整个周期所需的所有位。毫不奇怪，主流开发人员更喜欢 Redux。有趣的是，Facebook Open Source 支持 MobX 项目。

MobX 更加隐式，可以隐藏一些围绕 Observables 构建的逻辑，并提供整洁的注释，以快速增强您的具有状态的组件与 MobX 流。

一些开发人员可能会发现这是一个更好的方法，最有可能是那些来自面向对象背景并习惯于这些事情的人。我发现 MobX 是一个更容易开始并开发原型或概念验证应用程序的库。然而，由于逻辑被隐藏在我身后，我担心一些开发人员永远不会查看底层。这可能会导致性能不佳，以后很难修复。

让我们看看它在实际操作中的感觉。

# 转向 MobX

在本节中，我们将重构 Tasks 应用程序，以使用 MobX 而不是 vanilla Flux。

任务应用程序是在前几章中开发的。如果您直接跳转到本章，请查看位于 GitHub 存储库中的`src / Chapter 4 / Example 1_ Todo app with Flux`位置的应用程序。

在我们深入之前，使用以下命令安装这两个软件包：

```jsx
yarn add mobx mobx-react
```

好的，首先，让我们清理不需要的部分：

+   `AppDispatcher.js`：MobX 在幕后使用可观察对象进行分发。

+   `TaskActions.js`：操作现在将驻留在`TaskStore`中并在其状态上工作。在 MobX 中，您很可能最终会有许多存储，因此这不是一个大问题-我们将相关的东西放在一起。

+   `TasksActionTypes.js`：没有必要定义这个。MobX 会在内部处理它。

正如您所看到的，在我们开始之前，我们已经去掉了很多开销。这是库的粉丝们提到的 MobX 最大的优势之一。

是时候以 MobX 方式重建存储了。这将需要一些新的关键字，因此请仔细阅读以下代码片段：

```jsx
// Chapter 5 / Example 4 / src / data / TaskStore.js
import { configure, observable, action } from 'mobx'; import data from './tasks.json';   // don't allow state modifications outside actions configure({ enforceActions: true });   export class TaskStore {
    @observable tasks = [...data.tasks]; // default state    @action addTask(task) {
        this.tasks.push({
            name: task.name,
  description: task.description,
  likes: 0
  });
  }
}

const observableTaskStore = new TaskStore(); export default observableTaskStore; 
```

正如您所看到的，有三个新关键字我从 MobX 库中导入：

+   `configure`：这用于设置我们的存储，以便只能通过操作来强制执行变化。

+   `observable`：这用于丰富属性，使其可以被观察到。如果您对流或可观察对象有一些 JavaScript 背景，它实际上是由这些包装的。

+   `action`：这就像任何其他操作一样，但是以装饰器的方式使用。

最后，我们创建了一个存储的实例，并将其作为默认导出传递。

现在我们需要将新的存储暴露给视图。为此，我们将使用 MobX `Provider`，这是 Redux 中找到的类似实用程序：

```jsx
// Chapter 5 / Example 4 / src / App.js
// ... import { Provider as MobXProvider  } from 'mobx-react/native'; // ... const App = () => (
    <MobXProvider store={TaskStore}>
 <AppView /> </MobXProvider> ); export default App; 
```

前面片段的最后一部分涉及重构后代视图。

`AppView`组件向下提供任务到`TaskList`组件。现在让我们从新创建的存储中消耗任务：

```jsx
// Chapter 5 / Example 4 / src / views / AppView.js

import { inject, observer } from 'mobx-react/native'; 
@inject('store') @observer class AppView extends React.Component {
 render = () => (
     // ...
     <AddTaskForm />  <TaskList tasks={this.props.store.tasks} />
     // ...   ); }
```

让我们对`AddTaskForm`做类似的事情，但是不是使用`tasks`，而是使用`addTask`函数：

```jsx
// Chapter 5 / Example 4 / src / views / AddTaskForm.js
// ...

@inject('store') @observer class AddTaskForm extends React.Component {
    // ...   handleSubmit = () => {
        this.props.store.addTask({
            name: this.state.name,
  description: this.state.description
  });
 // ...   };
    // ...  }
```

就是这样！我们的应用程序再次完全可用。

# 使用注释与 PropTypes

如果您跟着做，您可能会感到有点迷茫，因为您的 linter 可能开始抱怨`PropTypes`不足或缺失。让我们来解决这个问题。

对于`AppView`，我们缺少对`tasks`存储的`PropTypes`验证。当类被标注为`@observer`时，这有点棘手-您需要为`wrappedComponent`编写`PropTypes`，如下所示：

```jsx
AppView.wrappedComponent.propTypes = {
    store: PropTypes.shape({
        tasks: PropTypes.arrayOf(PropTypes.shape({
            name: PropTypes.string.isRequired,
  description: PropTypes.string.isRequired,
  likes: PropTypes.number.isRequired
  })).isRequired
    }).isRequired
}; 
```

对于`AddTaskForm`，我们缺少对`addTask`存储操作的`PropTypes`验证。让我们现在来解决这个问题：

```jsx
AddTaskForm.wrappedComponent.propTypes = {
    store: PropTypes.shape({
        addTask: PropTypes.func.isRequired
  }).isRequired
};
```

就是这样，linter 的投诉都消失了。

# 比较 Redux 和 MobX

有一天，我在想如何比较这两者，接下来的想法浮现在脑海中。

这一部分受到了 Preethi Kasireddy 在 React Conf 2017 的演讲的很大影响。请花半个小时观看一下。您可以在[`www.youtube.com/watch?v=76FRrbY18Bs`](https://www.youtube.com/watch?v=76FRrbY18Bs)找到这个演讲。

MobX 就像汽车的道路系统。你创建了一张路线图，让人们开车。有些人会造成事故，有些人会小心驾驶。有些道路可能限制为单向，以限制交通，甚至以某种方式塑造，以便更容易推理汽车流量，就像在曼哈顿一样。另一方面，Redux 就像一辆火车。一次只能有一列火车在轨道上行驶。如果有几列火车同时行驶，前面的火车被阻挡，其他火车就会在后面等待，就像在地铁站一样。有时火车需要把人们送到大陆的另一边，这也是可能的。所有这些火车流量都由一个（分布式）机构管理，规划移动并对火车流量施加限制。

记住这个例子，让我们更加技术性地看看这些库：

+   Redux 使用普通对象，而 MobX 将对象包装成可观察对象。

你可能期待我再次提到一些魔法——不会。残酷的事实是，MobX 是有代价的。它需要包装可观察数据，并为每个对象或集合的每个成员增加一些负担。很容易查看有多少数据：使用`console.log`来查看您的可观察集合。

+   Redux 手动跟踪更新，而 MobX 自动跟踪更新。

+   Redux 状态是只读的，并且可以通过分派操作进行更改，而 MobX 状态可以随时更改，有时只能使用存储 API 公开的操作来更改。此外，在 MobX 中，不需要操作。您可以直接更改状态。

+   在 Redux 中，状态通常是规范化的，或者至少建议这样做。在 MobX 中，您的状态是非规范化的，并且计算值是嵌套的。

+   无状态和有状态组件：这里可能看起来很困难。在前面的信息框中链接的讲座中，Preethi Kasireddy 提到 MobX 只能与智能组件一起使用。在某种程度上，这是正确的，但这与 Redux 没有区别。两者都支持展示组件，因为它们与状态管理库完全解耦！

+   学习曲线——这是非常主观的标准。有些人会发现 Redux 更容易，而其他人会发现 MobX 更容易。普遍的看法是 MobX 更容易学习。我是这方面的例外。

+   Redux 需要更多的样板文件。更加明确，这是非常直接的，但如果您不在乎，也有一些库可以解决这个问题。我不会在这里提供参考资料，因为我建议您进行教育性的使用。

+   Redux 更容易调试。这自然而然地带来了单一流程和消息的轻松重放。这就是 Redux 的亮点。MobX 在这方面更加老派，有点难以预测，甚至对经验丰富的用户来说也不那么明显。

+   当涉及可扩展性时，Redux 胜出。MobX 可能会在大型项目中提出一些可维护性问题，特别是在有很多连接和大型领域的项目中。

+   MobX 在小型、时间受限的项目中更加简洁，发光。如果你参加黑客马拉松，考虑使用 MobX。在大型、长期项目中，你需要在 MobX 的自由基础上采用更有见地的方法。

+   MobX 遵循 Flux 架构，并且不像 Redux 那样对其进行修改。Redux 倾向于一个全局存储（尽管可以与多个一起使用！），而 MobX 在存储的数量上非常灵活，其示例通常展示了与 Flux 早期思想类似的思维方式。

在使用 Redux 时，您需要学习如何处理不同的情况以及如何构建结构。特别是在处理副作用时，您需要学习 Redux Thunk，可能还有 Redux Saga，这将在下一章中介绍。在 MobX 中，所有这些都在幕后神奇地处理，使用响应式流。在这方面，MobX 是有见地的，但却减轻了你的一个责任。

# 在 React Native 中使用系统存储

那些来自原生环境的人习惯于持久存储，比如数据库或文件。到目前为止，每当我们的应用重新启动时，它都会丢失状态。我们可以使用系统存储来解决这个问题。

为此，我们将使用 React Native 附带的`AsyncStorage` API：

“在 iOS 上，AsyncStorage 由存储小值的序列化字典和存储大值的单独文件的本机代码支持。在 Android 上，AsyncStorage 将根据可用的情况使用 RocksDB 或基于 SQLite。”

- 来自 React Native 官方文档，可以在以下网址找到：

[`facebook.github.io/react-native/docs/asyncstorage.html`](https://facebook.github.io/react-native/docs/asyncstorage.html)。

`AsyncStorage` API 非常容易使用。首先，让我们保存数据：

```jsx
import { AsyncStorage } from 'react-native';  try { await AsyncStorage.setItem('@MyStore:key', 'value');
} catch (error) { // Error saving data } 
```

接下来，这是我们如何检索保存的值：

```jsx
try { const  value = await AsyncStorage.getItem('@MyStore:key'); } catch (error) { // Error retrieving data } 
```

然而，文档建议我们在`AsyncStorage`中使用一些抽象：

“建议您在 AsyncStorage 上使用一个抽象，而不是直接使用 AsyncStorage，因为它在全局范围内运行。”

- 可以在 React Native 官方文档中找到：

[`facebook.github.io/react-native/docs/asyncstorage.html`](https://facebook.github.io/react-native/docs/asyncstorage.html)。

因此，让我们遵循标准库`redux-persist`。存储的主题很大，超出了这本书的范围，所以我不想深入探讨这个问题。

让我们使用以下命令安装该库：

```jsx
yarn add redux-persist redux-persist-transform-immutable
```

第一步是通过新的持久性中间件增强我们的`AppStore`定义，如下所示：

```jsx
// Chapter 5 / Example 5 / src / data / AppStore.js
// ... import { persistStore, persistReducer } from 'redux-persist';
import immutableTransform from 'redux-persist-transform-immutable'; import storage from 'redux-persist/lib/storage';   const persistConfig = {
    transforms: [immutableTransform()],
 key: 'root',
  storage }**;**   const rootReducer = combineReducers({
    // ...  }); const persistedReducer = persistReducer(persistConfig, rootReducer)
const store = createStore(persistedReducer); export const persistor = persistStore(store)**;** export default store; 
```

配置完成后，我们需要使用`PersistGate`加载状态。如果有自定义组件，可以将其提供给加载属性：

```jsx
// Chapter 5 / Example 5 / src / App.js
import store, { persistor } from './data/AppStore'; // ... const TasksApp = () => (
    <Provider store={store}>
 <PersistGate loading={null} persistor={persistor}>
 <AppContainer /> </PersistGate> </Provider> ); 
```

看哪！每当重新启动应用程序时，状态将从持久存储加载，并且您将看到上次应用程序启动时的所有任务。

# 效果模式

在处理外部数据时，您需要处理外部因素，如网络或磁盘。这些因素会影响您的代码，因此它需要是异步的。此外，您应该努力将其与可预测的部分解耦，因为网络是不可预测的，可能会失败。我们称这样的事情为副作用，您已经学到了一些关于它们的知识。

为了理解这一点，我想介绍一个大词：效果。

“我们产生纯粹的 JavaScript 对象[...]。我们称这些对象为*效果*。效果就是一个包含一些信息的对象，由中间件解释。您可以将效果视为中间件执行某些操作的指令（例如，调用某些异步函数，向存储分发操作等）。”

- 可以在 Redux Saga 官方文档中找到：

[`redux-saga.js.org/docs/basics/DeclarativeEffects.html`](https://redux-saga.js.org/docs/basics/DeclarativeEffects.html)。

如果在立即范围之外使用这些效果，就会引起所谓的**副作用**，因此得名。最常见的情况是对外部范围变量的改变。

没有副作用是程序正确性的数学证明的关键。我们将在第九章中深入探讨这个话题，*函数式编程模式的要素*。

# 处理副作用

在第四章 *Flux 架构*中，您学会了副作用是什么，以及您可以遵循哪些策略来将其与视图和存储解耦。在使用 Redux 时，您应该坚持这些策略。然而，已经开发了一些很棒的库来解决 Redux 的问题。您将在接下来的章节中了解更多，这些章节专门讨论这个问题:

"我们正在混合两个对人类思维来说非常难以理解的概念：突变和异步性。我称它们为 Mentos 和 Coke。它们分开时都很棒，但一起就会变成一团糟。像 React 这样的库试图通过在视图层中移除异步性和直接 DOM 操作来解决这个问题。然而，管理数据状态留给了你。这就是 Redux 介入的地方。"

- 官方 Redux 文档

# 摘要

在这一章中，我们讨论了存储在我们架构中的重要性。您学会了如何塑造您的应用程序，以满足不同的业务需求，从使用状态和全局状态的混合方法来处理非常脆弱的需求，到允许时间旅行和 UI 重建的复杂需求。

我们不仅关注了 Redux 这一主流解决方案，还探讨了 MobX 库的完全不同的方法。我们发现它在许多领域都非常出色，比如快速原型设计和小型项目，现在您知道在何时以及在哪些项目中选择 MobX 而不是 Redux 是明智的。

# 进一步阅读

+   Redux 官方文档:

[`redux.js.org/`](https://redux.js.org/). [](https://redux.js.org/) 这是文档中特别有用的部分:

[`redux.js.org/faq`](https://redux.js.org/faq).

+   *Redux 时间旅行和热重载介绍* 由 Dan Abramov 在 React Europe 上:

[`www.youtube.com/watch?v=xsSnOQynTHs`](https://www.youtube.com/watch?v=xsSnOQynTHs).

+   Dan Abramov 在 Egghead 上的课程:

[`egghead.io/instructors/dan-abramov`](https://egghead.io/instructors/dan-abramov).

+   Redux GitHub 页面上有已关闭的问题。这包含了大量有用的讨论:

[`github.com/reduxjs/redux/issues?q=is%3Aissue+is%3Aclosed`](https://github.com/reduxjs/redux/issues?q=is%3Aissue+is%3Aclosed).

+   Netflix JavaScript Talks: *RxJS + Redux + React = Amazing*!

[`www.youtube.com/watch?v=AslncyG8whg`](https://www.youtube.com/watch?v=AslncyG8whg).

+   *Airbnb 如何使用 React Native*:

[`www.youtube.com/watch?v=8qCociUB6aQ`](https://www.youtube.com/watch?v=8qCociUB6aQ)。

这不仅仅是关于存储模式，而是说明了如何思考像 Airbnb 这样的大型生产应用程序。

+   您可能需要 Redux：

[`www.youtube.com/watch?v=2iPE5l3cl_s&feature=youtu.be&t=2h7m28s`](https://www.youtube.com/watch?v=2iPE5l3cl_s&feature=youtu.be&t=2h7m28s).

+   最后但并非最不重要的是，Redux 作者为您带来的一个非常重要的话题：

*您可能不需要 Redux*：

[`medium.com/@dan_abramov/you-might-not-need-redux-be46360cf367`](https://medium.com/@dan_abramov/you-might-not-need-redux-be46360cf367).


# 第六章：数据传输模式

在本章中，我们将学习如何在 React Native 应用程序中发送和接收数据。首先，我们将使我们的应用程序更加动态，并且依赖于后端服务器。您将了解到 Thunk 模式，它非常适合 Flux。然后，我们将深入研究一个更高级的库，redux-saga，它基于效果模式。这两种解决方案都将使我们的应用程序能够与服务器无缝交换数据。我还会给您一点关于更高级通信模式的介绍，比如`HATEOAS`和`GraphQL`。尽管这两种模式对于 React Native 开发人员来说很少是关键的，但如果有一天这些模式在 React Native 世界中变得流行，您会发现理解起来更容易。

在本章中，您将学习如何做以下事情：

+   创建一个假的 API

+   从后端获取数据并将其存储在应用程序中

+   设计动作创建者并将获取逻辑与容器解耦

+   使用 Redux Thunk 来有条件地分发动作

+   编写自己的迭代器和生成器

+   从大量依赖于生成器的 saga 中受益

# 准备工作

为了在不依赖外部来源的情况下测试各种 API，我们将创建我们自己的本地 API。您不需要了解任何后端语言，也不需要知道如何公开 API。在本章中，我们将使用一个特殊的库，该库根据我们提供的 JSON 文件构建 API。

到目前为止，我们已经制作了一个漂亮的应用程序来显示任务。现在，我们不再加载本地数据文件，而是使用我们自己的 REST API。克隆任务应用程序以开始。（我将使用第五章中示例二的代码目录，*存储模式*。）

**表述性状态转移**（**REST**）是对 Web 服务施加约束的一组规则。其中一个关键要求是无状态性，这保证了服务器不会存储客户端的数据，而是仅依赖于请求数据。这应该足以向客户端发送回复。

为了创建一个假的 API，我们将使用`json-server`库。该库需要一个 JSON 文件；大多数示例都将其称为`db.json`。根据该文件，该库创建一个静态 API，以响应请求发送数据。

让我们从使用以下命令安装库开始：

```jsx
yarn global add json-server
```

如果您喜欢避免使用`global`，请记住在以下脚本中提供`node_modules/json-server/bin`的相对路径。

库的 JSON 文件应该如下所示：

```jsx
{
  "tasks": [
    // task objects separated by comma 
  ]
}
```

幸运的是，我们的`tasks.json`文件符合这个要求。我们现在可以启动我们的本地服务器。打开`package.json`并添加一个名为`server`的新脚本，如下所示：

```jsx
// src / Chapter 6 / Example 1 / package.jsonn
// ...
"scripts": {
  // ...   "server": "json-server --watch ./src/data/tasks.json" },
// ...
```

现在可以输入`yarn run server`来启动它。数据将在`http://localhost:3000/tasks`上公开。只需使用浏览器访问 URL 以检查是否有效。正确设置的服务器应该打印出以下数据：

```jsx
[
  {
    "name": "Task 1",
    "description": "Task 1 description",
    "likes": 239
  },
  // ... other task objects
]
```

我们现在可以进一步学习如何使用端点。

# 使用内置函数获取数据

首先，让我们从一些相当基础的东西开始。React Native 实现了 Fetch API，这在现在是用于进行 REST API 调用的标准。

# 重构为活动指示器

目前，在`taskReducer.js`文件中从文件加载了默认的任务列表。老实说，从文件或 API 加载都可能耗时。最好最初将任务列表设置为空数组，并通过旋转器或文本消息向用户提供反馈，告知他们数据正在加载。我们将在使用 Fetch API 时实现这一点。

首先，从 reducer 中的文件中删除数据导入。将声明更改为以下内容：

```jsx
(state = Immutable.List([...data.tasks]), action) => {
    // ...
}
```

并用此片段中的代码替换它：

```jsx
(state = Immutable.List([]), action) => {
    // ...
}
```

从文件加载数据也是一种副作用，并且应该遵循与数据获取类似的限制模式。不要被我们以前用于同步加载数据的实现所愚弄。这个快捷方式只是为了集中在特定的学习材料上。

启动应用程序以查看空列表。现在让我们添加一个加载指示器，如下所示：

```jsx
import { View, Text, StyleSheet, ActivityIndicator } from 'react-native';
// ...
const TaskList = ({ tasks, isLoading }) => (
    <View>
  {isLoading
            ? <ActivityIndicator size="large" color="#0000ff" />
  : tasks.map((task, index) => (
                // ...   ))
        }
    </View> ); 
```

在某些情况下，如果加载时间很长，你需要处理一个更复杂的情况：数据正在加载，但用户可能同时添加任务。在以前的实现中，直到从服务器检索到数据之前，任务才会显示出来。这个简单的解决方法是，如果我们有任何任务，无论`isLoading`属性如何，都始终显示任务，这意味着期望有其他一些数据：

```jsx
// src / Chapter 6 / Example 2 / src / views / TaskList.js
const TaskList = ({ tasks, isLoading }) => (
    <View>
  {isLoading && <ActivityIndicator size="large" color="#0000ff" />}
 {tasks.map((task, index) => (
            // ...   ))}
    </View> );
```

由于我们有一个根据`isLoading`属性显示的加载指示器，我们需要考虑我们的获取过程可能产生的其他状态。

# 处理错误情况

在大多数情况下，Fetch 将需要三种状态：

+   **开始**：开始获取，应导致`isLoading`为`true`

+   **成功**：成功获取数据

+   **错误**：Fetch 无法检索数据；应显示适当的错误消息

我们需要处理的最后一个状态是错误。在用户体验指南方面，有几种方法可以处理这个问题：

+   在列表中显示错误消息 - 这为那些关心表中数据的人提供了一个清晰的消息。它可能包括一个可点击的链接或一个重试按钮。您可以将此方法与后续的方法混合使用。

+   在失败时显示浮动通知 - 这在一个角落显示有关错误的消息。消息可能在几秒钟后消失。

+   显示错误模态 - 这会阻止用户通知他们有关错误；它可能包含重试和解除等操作。

我想在这里采取的方法是第一种。这种方法相当容易实现 - 我们需要添加一个`error`属性，并根据它显示消息：

```jsx
const TaskList = ({
    tasks, isLoading, hasError, errorMsg
}) => (
    <View>
  {hasError &&
            <View><Text>{errorMsg}</Text></View>}
        {hasError && isLoading &&
            <View><Text>Fetching again...</Text></View>}
        {isLoading && <ActivityIndicator size="large" color="#0000ff" />}
        {tasks.map((task, index) => (
            // ...   ))}
    </View> );
// ... TaskList.defaultProps = {
    errorMsg: 'Error has occurred while fetching tasks.' };
```

# 天真的有状态组件获取

现在，让我们获取一些数据并使我们的标记完全可用。首先，我们将遵循 React 初学者的方法：在一个有状态组件中使用`fetch`。在我们的情况下，它将是`App.js`：

```jsx
// src / Chapter 6 / Example 2 / src / App.js
class TasksFetchWrapper extends React.Component {
    constructor(props) {
        super(props);
        // Default state of the component
  this.state = {
            isLoading: true,
  hasError: false,
  errorMsg: '',
  tasks: props.tasks
  };
  }

    componentDidMount() {
        // Start fetch and on completion set state to either data or
        // error
        return fetch('http://localhost2:3000/tasks')
            .then(response => response.json())
            .then((responseJSON) => {
                this.setState({
                    isLoading: false,
  tasks: Immutable.List(responseJSON)
                });
  })
            .catch((error) => {
                this.setState({
                    isLoading: false,
  hasError: true,
  errorMsg: error.message
  });
  });
  }

    render = () => (
        <AppView
  tasks={this.state.tasks}
            isLoading={this.state.isLoading}
            hasError={this.state.hasError}
            errorMsg={this.state.errorMsg}
        />
  ); }
  // State from redux passed to wrapper. const mapStateToProps = state => ({ tasks: state.tasks }); const AppContainer = connect(mapStateToProps)(TasksFetchWrapper);
```

这种方法有一些缺点。首先，它不遵循 Fetch API 文档。让我们阅读这个关键的引用：

“从 fetch 返回的 Promise 不会在 HTTP 错误状态下拒绝，即使响应是 HTTP 404 或 500。相反，它将正常解析（ok 状态设置为 false），并且只有在网络故障或任何阻止请求完成时才会拒绝。”

- *可用的 Fetch API 文档：*

[`developer.mozilla.org/en-US/docs/Web/API/Fetch_API/Using_Fetch`](https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API/Using_Fetch)。

如您所见，前面的实现缺乏 HTTP 错误处理。

第二个问题是状态重复，我们维护了一个 Redux 状态，但然后将任务复制到本地组件状态，并甚至用已获取的内容覆盖它。我们可能更关心我们已经在任务中的内容，通过连接两个数组，并找到一种避免再次存储任务的方法。

此外，如果 Redux 状态发生变化，那么先前的组件将完全忽略更新。这太糟糕了，让我们找到一种解决方法。

# Thunk 模式和 Redux Thunk

在这一部分，我们将学习**Thunk 模式**以及如何在**Redux Thunk**库中使用它。首先，我们需要重构上一节中的天真和有缺陷的实现，改为使用 Redux。

# 将状态提升到 Redux

不要依赖组件状态，让我们将其提升到 Redux 存储中。注意我们在这里使用的`Immutable.Map`。此外，`ADD_TASK`动作现在使用`Immutable.js`的`update`函数：

```jsx
// src / Chapter 6 / Example 3 / src / reducers / taskReducer.js

const taskReducer = (state = Immutable.Map({
    entities: Immutable.List([])**,**
  isLoading: false,
  hasError: false,
  errorMsg: **''** }), action) => {
    switch (action.type) {
    case TasksActionTypes.ADD_TASK:
        if (!action.task.name) {
            return state;
  }
        return state.update('entities', entities => entities.push({
            name: action.task.name,
  description: action.task.description,
  likes: 0
  }));
  default:
        return state;
  }
}; 
```

由于我们已经改变了减速器，我们需要修复有状态的组件。它不应该有自己的状态，而是通过动作委托给 Redux 存储。然而，我们将稍后实现这些动作：

```jsx
// src / Chapter 6 / Example 3 / src / App.js
class TasksFetchWrapper extends React.Component {
    componentDidMount() {
        TaskActions.fetchStart();
  return fetch('http://localhost:3000/tasks')
            .then(response => response.json())
            .then((responseJSON) => {
                TaskActions.fetchComplete(Immutable.List(responseJSON));
  })
            .catch((error) => TaskActions.fetchError(error));
  }

    render = () => <AppView tasks={this.props.tasks} />; }
```

将获取逻辑移动到单独的服务是明智的。这将使其他组件在需要触发获取时共享相同的功能。这是你的作业。

你可以将动作分派到构造函数而不是依赖于`componentDidMount`。然而，这可能会引发重构为函数组件的诱惑。这将是一场灾难，因为你将在每次重新渲染时开始获取。此外，`componentDidMount`对我们来说更安全，因为在动作的上下文中，如果有任何可能减慢应用程序的计算，我们可以 100%确定用户已经看到`ActivityIndicator`。

现在，转到动作的实现。你应该能够自己编写它们。如果遇到任何问题，请参阅`src / Chapter 6 / Example 3 / src / data / TaskActions.js`。现在我们将专注于扩展减速器。这是相当多的工作，因为我们需要处理所有三种动作类型：`FETCH_START`，`FETCH_COMPLETE`和`FETCH_ERROR`，如下所示：

```jsx
// src / Chapter 6 / Example 3 / src / reducers / taskReducer.js
const taskReducer = (state = Immutable.Map({
    // ...  }), action) => {
    switch (action.type) {
    case TasksActionTypes.ADD_TASK: {
        // ...   }
    case TasksActionTypes.TASK_FETCH_START: {
        return state.update('isLoading', () => true);
  }
    case TasksActionTypes.TASK_FETCH_COMPLETE: {
        const noLoading = state.update('isLoading', () => false);
  return noLoading.update('entities', entities => (
            // For every task we update the state
            // Homework: do this in bulk
            action.tasks.reduce((acc, task) => acc.push({
                name: task.name,
  description: task.description,
  likes: 0
  }), entities)
        ));
  }
    case TasksActionTypes.TASK_FETCH_ERROR: {
        const noLoading = state.update('isLoading', () => false);
  const errorState = noLoading.update('hasError', () => true);
  return errorState.update('errorMsg', () => action.error.message);
  }
    default: {
        return state;
  }
    }
};
```

基本上就是这样。最后，你还需要更新视图以使用新的结构`Immutable.Map`，如下所示：

```jsx
// src / Chapter 6 / Example 3 / src / views / AppView.js
// ...
<TaskList
  tasks={props.tasks.get('entities')}
    isLoading={props.tasks.get('isLoading')}
    hasError={props.tasks.get('hasError')}
    errorMsg={props.tasks.get('errorMsg')}
/>
// ... 
```

这段代码需要进行一些改进。我现在不会触及它们，因为那些是高级主题，涉及更一般的 JavaScript 函数式编程概念。你将在第八章中学习有关镜头和选择器的内容，*JavaScript 和 ECMAScript 模式*。

# 重构为 Redux 的好处

可能很难看到先前重构的好处。其中一些重构可能在几天后才会显现出来。例如，需要在特定事件上重新获取任务。此事件发生在应用程序的完全不同部分，并且与任务列表无关。在天真的实现中，您需要处理更新过程并保持一切更新。您还需要向另一个组件公开`fetch`函数。这将紧密耦合这两者。灾难。相反，正如您所看到的，您可能更喜欢将获取逻辑复制到第二个独立的组件中。再次，您最终会出现代码重复。因此，您将创建一个由这两个组件共享的父服务。不幸的是，获取与状态紧密耦合，因此您还将状态移动到服务中。然后，您将进行一些技巧，例如使用闭包在服务中存储数据。正如您所看到的，这是这些问题的一个平稳解决方案。

当使用 Redux 存储时，您只有一个通过 reducer 更新的集中状态。获取是使用精心设计的操作将数据发送到 reducer。获取可以在一个单独的服务中执行，该服务由需要获取任务的组件共享。现在，我们将介绍一个使所有这些事情更清洁的库。

# 使用 Redux Thunk

在经典的 Redux 中，没有中间件，您无法调度不是纯对象的东西。使用 Redux Thunk，您可以通过调度函数延迟调度：

"Redux Thunk 中间件允许您编写返回函数而不是操作的操作创建者。thunk 可以用于延迟操作的调度，或者仅在满足某些条件时进行调度。内部函数接收存储方法`dispatch`和`getState`作为参数。"

- Redux Thunk 官方文档，网址：

[`github.com/reduxjs/redux-thunk`](https://github.com/reduxjs/redux-thunk)。

例如，您可以调度一个函数。这样的函数有两个参数：`dispatch`和`getState`。这个函数尚未到达 Redux reducer。它只延迟了老式的 Redux 调度，直到进行必要的检查，例如基于当前状态的检查。一旦我们准备好调度，我们就使用作为`function`参数提供的`dispatch`函数：

```jsx
function incrementIfOdd() {
  return (dispatch, getState) => {
    const { counter } = getState();

    if (counter % 2 === 0) {
      return;
    }

    dispatch(increment());
  };
}

dispatch(incrementIfOdd())
```

在前一节中，我指出`fetch`调用可以是一个单独的函数。如果你还没有做作业，这里是一个重构的例子：

```jsx
const fetchTasks = () => {
    TaskActions.fetchStart();
  return fetch('http://localhost:3000/tasks')
        .then(response => response.json())
        .then((responseJSON) => {
            TaskActions.fetchComplete(Immutable.List(responseJSON));
  })
        .catch(error => TaskActions.fetchError(error)); };   class TasksFetchWrapper extends React.Component {
 componentDidMount = () => this.props.fetchTasks();
  render = () => <AppView tasks={this.props.tasks} />; }

const mapStateToProps = state => ({ tasks: state.tasks }); const mapDispatchToProps = dispatch => ({ fetchTasks }); const AppContainer = connect(mapStateToProps, mapDispatchToProps)(TasksFetchWrapper);
```

然而，我们所谓的`ActionCreators`与`dispatch`紧密耦合，因此不仅创建动作，还有`dispatch`。让我们通过移除 dispatch 来放松它们的责任：

```jsx
// Before  const Actions = {
addTask(task) {
        AppDispatcher.dispatch({
type: TasksActionTypes.ADD_TASK,
  task
        });
  },
  fetchStart() {
        AppDispatcher.dispatch({
type: TasksActionTypes.TASK_FETCH_START
  });
  },
 // ...
}; 
// After
const ActionCreators = {
 addTask: task => ({
type: TasksActionTypes.ADD_TASK,
  task
   }),
  fetchStart: () => ({
type: TasksActionTypes.TASK_FETCH_START
  }),
 // ...
}; 
```

现在，我们需要确保将前面的动作分发到相关的位置。可以通过以下方式实现：

```jsx
const ActionTriggers = {
 addTask: dispatch => task => dispatch(ActionCreators.addTask(task)),
  fetchStart: dispatch => () => dispatch(ActionCreators.fetchStart()),
  fetchComplete: dispatch =>
        tasks => dispatch(ActionCreators.fetchComplete(tasks)),
  fetchError: dispatch =>
        error => dispatch(ActionCreators.fetchError(error))
};
```

对于有编程经验的人来说，这一步可能看起来有点像我们在重复自己。我们在重复函数参数，唯一得到的是调用分发。我们可以用函数模式来解决这个问题。这些改进将作为《第八章》*JavaScript 和 ECMAScript 模式*的一部分进行。

另外，请注意，在这本书中，我没有写很多测试。一旦你养成了写测试的习惯，你就会很快欣赏到这种易于测试的代码。

完成这些后，我们现在可以调整我们的容器组件，如下所示：

```jsx
// src / Chapter 6 / Example 4 / src / App.js export const fetchTasks = (dispatch) => {
    TaskActions.fetchStart(dispatch)();
  return fetch('http://localhost:3000/tasks')
        .then(response => response.json())
        .then(responseJSON =>
            TaskActions.fetchComplete(dispatch)(Immutable.List(responseJSON)))
        .catch(TaskActions.fetchError(dispatch)); };
// ... const mapDispatchToProps = dispatch => ({
fetchTasks: () => fetchTasks(dispatch),
  addTask: TaskActions.addTask(dispatch)
});  
```

好的，这是一个很好的重构，但 Redux Thunk 在哪里？这是一个非常好的问题。我故意延长了这个例子。在许多 React 和 React Native 项目中，我看到了对 Redux Thunk 和其他库的过度使用。我不希望你成为另一个不理解 Redux Thunk 目的并滥用其功能的开发人员。

Redux Thunk 主要让你有条件地决定是否要分发。通过 Thunk 函数访问`dispatch`并不是什么特别的事情。主要的好处是第二个参数`getState`。这让你可以访问当前状态，并根据那里的值做出决定。

这样强大的工具可能会导致你创建不纯的 reducer。怎么会呢？你会创建一个**setter reducer**，它的工作方式类似于类中的 set 函数。这样的 reducer 只会被调用来设置值；然而，值将在 Thunk 函数中计算，使用`getState`函数。这完全是反模式，可能会导致严重的竞争条件破坏。

现在我们知道了危险，让我们继续讨论 Thunk 的真正用途。想象一种情况，您希望有条件地做出决定。如何访问状态以进行`if`语句？一旦我们在 Redux 中使用`connect()`函数，这就变得复杂起来。我们传递给`connect`的`mapDispatchToProps`函数无法访问状态。但我们需要它，这就是 Redux Thunk 的一个有效用法。

以下是需要知道的：如果我们不能使用 Redux Thunk，我们如何制作一个逃生舱？我们可以将部分状态传递给`render`函数，然后使用预期的状态调用原始函数。`if`语句可以在 JSX 中使用常规的`if`。然而，这可能会导致严重的性能问题。

现在是时候在我们的情况下使用 Redux Thunk 了。您可能已经注意到我们的数据集不包含 ID。如果我们两次获取任务，这将是一个巨大的问题，因为我们没有机制告诉哪些任务已经添加，哪些已经存在于我们的 UI 中。当前的方法是添加所有获取到的任务，这将导致任务重复。我们破碎架构的第一个预防机制是在`isLoading`为`true`时停止获取。

现实生活中的情况要么使用 ID，要么在获取时刷新所有任务。如果是这样，`ADD_TASK`需要保证后端服务器中的更改。

在渐进式 Web 应用程序时代，我们需要进一步强调这个问题。考虑一种情况，即在添加新任务之前失去连接。如果您的 UI 在本地添加任务并安排后端更新，一旦网络连接解决，您可能会遇到竞争条件：这意味着任务在`ADD_TASK`更新在后端系统中传播之前被刷新。结果，您最终会得到一个任务列表，其中不包含添加的任务，直到您从后端重新获取所有任务。这可能是非常误导人的，不应该发生在任何金融机构中。

让我们实现这种天真的预防机制来说明 Redux Thunk 的能力。首先，使用以下命令安装库：

```jsx
yarn add redux-thunk
```

然后，我们需要将`thunk`中间件应用到 Redux 中，如下所示：

```jsx
// src / Chapter 6 / Example 4 / src / data / AppStore.js
import { combineReducers, createStore, applyMiddleware } from 'redux'; import thunk from 'redux-thunk';  // ... const store = createStore(rootReducer, applyMiddleware(thunk));  
```

从现在开始，我们可以调度函数。现在让我们修复我们的`fetch`函数，以避免多次请求：

```jsx
// src / Chapter 6 / Example 5 / src / App.js
export const fetchTasks = (dispatch, getState) => {
    if (!getState().tasks.isLoading) {
        // ...   }
    return null; };
// ... const mapDispatchToProps = dispatch => ({
    fetchTasks: () => dispatch(fetchTasks),
 // ...
});
```

正如您所看到的，这是一个非常简单的用例。请明智地使用 Redux Thunk，不要滥用它给您带来的力量。

# 理解 Thunk 模式

Thunk 是另一种模式，不特定于 React 或 Redux。实际上，在许多复杂的解决方案中，如编译器，它被广泛使用。

Thunk 是一种延迟评估的模式，直到无法避免为止。解释这一点的初学者示例之一是简单的加法。示例如下：

```jsx
// immediate calculation, x equals 3
let x = 1 + 2;

// delayed calculation until function call, x is a thunk
let x = () => 1 + 2;
```

一些更复杂的用法，例如在函数式语言中，可能会在整个语言中依赖于这种模式。因此，计算只有在最终应用层需要它们时才执行。通常情况下，不会进行提前计算，因为这样的优化是开发人员的责任。

# 传说模式和 Redux Saga

到目前为止，我们可以使用`fetch`执行简单的 API 调用，并且知道如何组织我们的代码以实现可重用性。然而，在某些领域，如果我们的应用程序需要，我们可以做得更好。在深入研究 Redux Saga 之前，我想介绍两种新模式：迭代器和生成器。

“处理集合中的每个项目是一个非常常见的操作。JavaScript 提供了许多迭代集合的方法，从简单的 for 循环到 map 和 filter。迭代器和生成器直接将迭代的概念引入核心语言，并提供了自定义 for...of 循环行为的机制。”

- MDN web 文档上的 JavaScript 指南：

[`developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Iterators_and_Generators`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Iterators_and_Generators). [](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Iterators_and_Generators)

# 迭代器模式简介

顾名思义，迭代器允许您遍历集合。为了能够这样做，集合需要实现一个可迭代接口。在 JavaScript 中，没有接口，因此迭代器只是实现了一个函数。

当对象知道如何一次从集合中访问项目，并在该序列内跟踪其当前位置时，该对象就是一个迭代器。在 JavaScript 中，迭代器是一个提供 next 方法的对象，该方法返回序列中的下一个项目。此方法返回一个具有两个属性的对象：done 和 value。

- MDN web 文档上的 JavaScript 指南

[`developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Iterators_and_Generators`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Iterators_and_Generators)

以下是 MDN web 文档中此类函数的示例：

```jsx
function createArrayIterator(array) {
    var nextIndex = 0;    return {
        next: function() {
            return nextIndex < array.length ?
                {value: array[nextIndex++], done: false} :
                {done: true};
  }
    }; }
```

# 生成器模式

生成器类似于迭代器；然而，在这里，你会在函数内部精心设计的断点上进行迭代。生成器返回一个迭代器。返回的迭代器在提到的断点上进行迭代，并且每次从函数中返回一些值。

为了表示该函数是一个生成器，我们使用特殊的`*****`符号，例如，`function* idGenerator()`。请在以下代码片段中找到一个示例生成器函数。生成器使用`yield`关键字来返回当前迭代步骤的值。如果调用了它的`next()`函数，迭代器将在下一行恢复，就像这样：

```jsx
function* numberGenerator(numMax) {
    for (let i = 0; i < numMax; i += 1) {
        yield console.log(i);
  }
}
const threeNumsIterator = numberGenerator(3); // logs 0 threeNumsIterator.next(); // logs 1 threeNumsIterator.next(); // logs 2 threeNumsIterator.next(); // logs nothing, the returned object contains a key 'done' set to true
threeNumsIterator.next(); 
```

首先，我们创建一个`generator`函数。`Generator`函数期望一个参数。根据提供的参数，生成器知道何时停止生成新的数字。在函数之后，我们创建一个示例数字迭代器并迭代其值。

# Redux Saga

Redux Saga 在很大程度上依赖于生成器模式。由于这种方法，我们可以将副作用完全解耦到行为就像是一个独立线程的 sagas 中。这是方便的，并且从长远来看，相对于 Thunk 函数提供了一些优势。其中一些依赖于可组合性，sagas 易于测试，并提供更清晰的流程来执行异步代码。现在这些可能听起来不清楚，所以让我们深入了解一下。

本书并不涉及太多关于 React、Redux 和 React Native 的测试。这个主题会让本书变得很长，我认为它值得有一本单独的书。然而，我会强调测试代码的重要性。这个信息框是为了提醒你在 Redux Sagas 中进行测试。在互联网的不同地方（GitHub、论坛、Stack Overflow）我一遍又一遍地看到这个提到：sagas 比 Thunks 更容易测试。你可以自己验证一下，你不会后悔的。

首先，完成安装库和应用中间件的初学者步骤。这些步骤可以在官方的 Redux Saga README 文件中找到，网址为[`redux-saga.js.org/`](https://redux-saga.js.org/)。

现在是时候创建第一个 saga 并将其添加到我们的`rootSaga`中了。还记得获取任务的情况吗？它们可以从许多地方（许多解耦的小部件或功能）请求。saga 的方法与我们之前的解决方案类似，所以让我们看看它如何在以下示例中实现：

```jsx
// src / Chapter 6 / Example 6 / src / sagas / fetchTasks.js
function* fetchTasks() {
    const tasks = yield call(ApiFetch, 'tasks');
  if (tasks.error) {
        yield put(ActionCreators.fetchError(tasks.error));
  } else {
        const json = yield call([tasks.response, 'json']);
  yield put(ActionCreators.fetchComplete(Immutable.List(json)));
  }
}

// whereas ApiFetch is our own util function
// you will want to make a separate file for it
// and take care of environmental variables to determine right endpoint
const ApiFetch = path => fetch(`http://localhost:3000/${path}`)
    .then(response => ({ response }))
    .catch(error => ({ error }));
```

我们的`fetchTasks` saga 非常简单：首先，它获取任务，然后检查是否发生了错误，然后要么分派一个带有获取的数据附加的错误事件，要么分派一个成功事件。

我们如何触发`fetchTasks` saga？为了说服你 saga 的强大之处，让我们更进一步。假设我们的代码库是解耦的，一些功能几乎同时请求任务。我们如何防止触发多个获取任务的作业？Redux Saga 库为此提供了现成的解决方案：`throttle`函数。

"throttle(ms, pattern, saga, ...args) 在与模式匹配的存储器上分派一个动作，然后在生成任务后，它仍然接受传入的动作到底层缓冲区，最多保留 1 个（最近的一个），但同时在 ms 毫秒内不生成新任务（因此它的名称是 - throttle）。其目的是在处理任务时忽略一定时间内的传入动作。"

- 官方 Redux Saga 文档:

[`redux-saga.js.org/docs/api/`](https://redux-saga.js.org/docs/api/).

我们的用例非常简单：

```jsx
// src / Chapter 6 / Example 6 / src / sagas / fetchTasks.js
function* watchLastFetchTasks() {
    yield throttle(2000, TasksActionTypes.TASK_FETCH_START, fetchTasks); }
```

`fetchTasks`函数将在`TASK_FETCH_START`事件上执行。在两秒内，相同的事件不会导致另一个`fetchTasks`函数的执行。

就是这样。最后的几件事之一是将前面的 saga 添加到`rootSaga`中。这不是一个非常有趣的部分，但是如果你感兴趣，我建议你在代码存储库中查看完整的示例，该示例可在[`github.com/Ajdija/hands-on-design-patterns-with-react-native`](https://github.com/Ajdija/hands-on-design-patterns-with-react-native)上找到。

# Redux Saga 的好处

在更复杂的应用程序中，具有明确定义的例程，Redux Saga 比 Redux Thunk 更出色。一旦你遇到需要取消、重新运行或回复流程的一部分，就不会立即明显地知道如何使用 Thunk 或纯 Redux 来完成这些操作。使用可组合的 saga 和良好维护的迭代器，你可以轻松地完成这些操作。即使官方文档也提供了这些问题的解决方案。（有关参考，请参阅本章末尾的*进一步阅读*部分。）

这样一个强大库的阴暗面在于它在旧应用程序中的使用可能会出现问题。这些应用程序可能以基于 promise 或 Thunk 的方式编写功能，可能需要进行重大重构才能与在新应用程序中找到的与 sagas 的使用方式相匹配。例如，从 Thunk 函数调用 saga 并不容易，也不能像在 sagas 中等待分发的函数那样等待 promise。可能有很好的方法来连接这两个世界，但真的值得吗？

# 摘要

在这一章中，我们重点关注了网络模式和随之而来的副作用。我们经历了简单的模式，然后使用了市场上可用的工具。您已经了解了 Thunk 模式，以及迭代器和生成器模式。这三种模式在您未来的编程生涯中都将非常有用，无论是在 React Native 中还是其他地方。

至于 React 生态系统，您已经了解了 Redux Thunk 和 Redux Saga 库的基础知识。它们都解决了大规模应用程序所面临的一些挑战。明智地使用它们，并牢记我在本章中提出的所有警告。

现在我们知道如何显示数据，样式化数据和获取数据，我们已经准备好学习一些应用程序构建模式。特别是在下一章中，您将学习导航模式。在 React Native 中，有很多解决这些问题的解决方案，我很乐意教您如何选择与您项目需求匹配的解决方案。

# 进一步阅读

+   编写测试-Redux 官方文档：

[`redux.js.org/recipes/writing-tests`](https://redux.js.org/recipes/writing-tests).

+   实现撤销历史-Redux 官方文档：

[`redux.js.org/recipes/implementing-undo-history`](https://redux.js.org/recipes/implementing-undo-history).

+   服务器渲染-Redux 官方文档：

[`redux.js.org/recipes/server-rendering`](https://redux.js.org/recipes/server-rendering).

+   规范化状态-Redux 官方文档：

[`redux.js.org/recipes/structuring-reducers/normalizing-state-shape`](https://redux.js.org/recipes/structuring-reducers/normalizing-state-shape).

这在网络模式的背景下非常重要。从后端系统获取的一些数据将需要进行规范化处理。

+   异步操作-Redux 官方文档：

[`redux.js.org/advanced/async-actions`](https://redux.js.org/advanced/async-actions).

+   Redux Saga 食谱-Redux Saga 官方文档：

[`redux-saga.js.org/docs/recipes/`](https://redux-saga.js.org/docs/recipes/)。

这个资源特别有价值，因为它提供了使用 saga 进行节流、去抖动和撤销的食谱。

+   Redux Saga 通道-Redux Saga 官方文档：

“到目前为止，我们已经使用‘take’和‘put’效果与 Redux Store 进行通信。通道将这些效果泛化为与外部事件源或 Sagas 之间进行通信。它们还可以用于从 Store 中排队特定的操作。”

- Redux Saga 官方文档：

[`redux-saga.js.org/docs/advanced/Channels.html`](https://redux-saga.js.org/docs/advanced/Channels.html)。

+   关于 Thunk、saga、抽象和可重用性的惯用 redux 思想：

[`blog.isquaredsoftware.com/2017/01/idiomatic-redux-thoughts-on-thunks-sagas-abstraction-and-reusability/`](https://blog.isquaredsoftware.com/2017/01/idiomatic-redux-thoughts-on-thunks-sagas-abstraction-and-reusability/)。

+   资源库：React Redux 链接/Redux 副作用：

[`github.com/markerikson/react-redux-links/blob/master/redux-side-effects.md`](https://github.com/markerikson/react-redux-links/blob/master/redux-side-effects.md)。

+   关于 Saga 的 Saga：

“术语‘saga’通常在 CQRS 讨论中用来指代协调和路由有界上下文和聚合之间的消息的一段代码。然而，[...]我们更倾向于使用术语‘过程管理器’来指代这种类型的代码构件。”

关于 Saga 的 Saga-Microsoft 文档：

[`docs.microsoft.com/en-us/previous-versions/msp-n-p/jj591569(v=pandp.10)`](https://docs.microsoft.com/en-us/previous-versions/msp-n-p/jj591569(v=pandp.10))。

+   GraphQL-另一种处理副作用的方法。GraphQL 是一个用于 API 的查询语言，既可以用于前端，也可以用于后端。在这里了解更多：

[`graphql.org/learn/`](https://graphql.org/learn/)。

+   Redux Observable-Thunk 和 saga 的竞争对手。介绍了响应式编程模式：

[`github.com/redux-observable/redux-observable`](https://github.com/redux-observable/redux-observable)。

还请查看 RxJS，这是 JavaScript 的响应式编程库：

[`github.com/reactivex/rxjs`](https://github.com/reactivex/rxjs)。

+   表述性状态转移：

[`en.wikipedia.org/wiki/Representational_state_transfer`](https://en.wikipedia.org/wiki/Representational_state_transfer)。

+   HATEOAS（REST 架构的一个组件）：

https://en.wikipedia.org/wiki/HATEOAS


# 第七章：导航模式

几乎每个应用程序的关键部分是导航。直到今天，这个话题仍然让许多 React Native 开发人员头疼。让我们看看有哪些可用的库，以及哪一个适合您的项目。本章从可用库的分解开始。然后，我们将介绍一个新项目并进行操作。我们将一次专注于一个库。完成后，我将带您了解所使用的模式以及这些模式意味着什么，同时您编写导航代码。记得在您的计算机和手机上尝试这些代码。

在本章中，您将了解以下内容：

+   为什么 React Native 有许多替代路由库？

+   导航库面临的挑战是什么？

+   本地导航和 JavaScript 导航有什么区别？

+   如何使用选项卡导航、抽屉导航和堆栈导航。

+   本地解决方案的基础知识：您将首次弹出创建 React Native 应用程序。

# React Native 导航替代方案

通常，如果您是初学者，并尝试在 Google 上搜索*React Native 导航*，您最终会头疼。可用的替代方案数量很多。这是有几个原因的：

+   一些早期的库不再得到维护，因为维护者已经退出

+   一些资源充足的公司开始了一个库，然后将员工的重点转移到其他事情上

+   一些解决方案被证明效率低下，或者实施了更好的解决方案

+   不同方法有架构上的原因，导致需要维护不同的解决方案

我们将在这里专注于最后一点，因为了解哪个库适合您的需求至关重要。我们将讨论解决方案，以便在本章结束时，您将知道为您的项目选择哪个库。

# 设计师的导航模式

在我们深入了解库的世界之前，我想向您展示在应用程序中设计导航的不同方式。通常，这是项目设计师的工作；然而，一旦您了解了权衡，添加代码模式层将会更容易。

移动应用程序由屏幕和过渡组成。总的来说，这些可以用以下图表表示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/hsn-dsn-ptn-rn/img/d751e3ad-7a4c-4b30-b7ae-8e0143930d68.png)

这是一个代表任务应用程序屏幕的示例图表

前面图表的主要要点如下：

+   每个应用程序都包括顶层屏幕（**主页**、**项目**和**搜索**）

+   从顶层屏幕，您可以向前导航并深入树中（**项目** => **项目任务列表**）

+   有时，您会向后过渡（**任务** => **项目任务列表**）

有了这个想法，让我们看看将帮助我们进行这些转换的组件。

# 导航到顶层屏幕

通常使用以下三种替代方案之一导航到顶层屏幕：

+   经典底部导航，就像我们已经实现的那样。这通常使用图标或图标和文本的组合。根据所做的选择，这允许我们放置两到五个链接。这在平板设计上通常是避免的：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/hsn-dsn-ptn-rn/img/6f7d2d47-ab2f-4f80-80ac-53b235e4d5d2.png)

经典底部导航的一个例子

+   导航抽屉，从屏幕侧边打开。其中包含一个链接列表，可能超过五个。这可能是复杂的，并且可以在顶部包括用户配置文件。这往往是通过位于一个上角的汉堡图标打开的：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/hsn-dsn-ptn-rn/img/b6344c65-d72c-4d1c-a21d-ea7dcf667f36.png)

抽屉导航的一个例子

+   标签，放置在屏幕顶部，成对出现，至少如此。标签的数量可以超过四个，在这种情况下，标签可以水平滚动。这不仅用于顶层导航，还用于同一深度屏幕之间的任何导航。

# 在图表的不同级别之间导航

一旦到达一定级别，有时我们想进一步探索特定区域。在任务应用程序的情况下，这意味着选择一个项目或在项目内选择特定任务。

通常，为了在图表中向下导航，我们使用以下方法：

+   容器，包括列表、卡片、图像列表和图像卡片

+   简单按钮、文本链接或图标

然而，为了回到图表的上方，通常我们使用以下方法：

+   返回图标，如箭头，通常位于左上角或左下角

+   按钮或链接，文本如返回|取消|重新开始

+   在编辑/创建屏幕的相关部分放置的交叉图标

对于你们中的一些人来说，这些知识是自然而然的；然而，我遇到了一些明显混淆了这些概念的提案或早期设计草案，最终严重影响了用户体验。尝试是好的，但只能在使用标准和众所周知的模式的受控环境中进行，这些模式对大多数用户来说是自然的。

对于设计实验，您应该实施 A/B 测试。这需要能够在生产中为不同的用户子集运行应用程序的不同版本。借助分析，您可以随后评估 A 或 B 哪个选择更好。最终，所有用户都可以迁移到获胜的方案。

# 在图的同一级别上导航

在更复杂的应用程序中，除了顶层导航之外，您还需要在相同深度的不同屏幕之间进行水平过渡。

要在同一级别的屏幕之间进行过渡，您可以使用以下方法：

+   选项卡，类似于顶层导航部分讨论的内容

+   屏幕滑动（字面上在屏幕之间滑动）

+   在容器中滑动（例如，查看任务描述、连接任务或任务评论）可以与选项卡连接

+   左右箭头，或指示您在级别内位置的点

同样，您也可以用这些来处理数据集合。然而，数据集合提供更多自由，可以使用列表或不受限制的容器，利用顶部/底部滑动。

牢记设计师们如何解决导航问题，现在让我们讨论如何使其性能良好以及如何维护导航图。

# 开发者的导航模式

说实话，一切都归结于这一点——JavaScript 实现是否足够好？如果是，让我们为自己的利益使用它（即，跟踪、JavaScript 中的控制、日志等）。随着时间的推移，看起来 React Native 社区设法创建了一个稳定的东西，称为 React Navigation：

“React Navigation 完全由 React 组件组成，并且状态在 JavaScript 中管理，与应用程序的其余部分在同一线程上。这在许多方面使 React Navigation 变得很棒，但这也意味着您的应用逻辑与 React Navigation 竞争 CPU 时间——每帧可用的 JavaScript 执行时间有限。”

- React Navigation 官方文档，可在以下网址找到：

[`reactnavigation.org/docs/en/limitations.html`](https://reactnavigation.org/docs/en/limitations.html)。

然而，正如前面的引用所讨论的，这与您的应用程序竞争 CPU 周期。这意味着它在一定程度上耗尽资源并减慢应用程序的速度。

JavaScript 导航的优点如下：

+   您可以使用 JavaScript 代码调整和扩展解决方案。

+   当前的实现对于中小型应用程序来说性能足够好。

+   状态在 JavaScript 中管理，并且很容易与 Redux 等状态管理库集成。

+   API 与本机 API 解耦。这意味着如果 React Native 最终超越 Android 和 iOS，API 将保持不变，并且一旦由库维护者实施，这将使您能够为另一个平台使用相同的解决方案。

+   易学。

+   适合初学者。

JavaScript 导航的缺点如下：

+   在性能方面实施起来非常困难。

+   对于大型应用程序来说可能仍然太慢。

+   一些动画与本机动画略有不同。

+   某些手势或动画可能与本机的完全不同（例如，如果本机系统更改了默认设置，或者由于历史更改而不一致）。

+   很难与本机代码集成。

+   根据当前文档，路由应该是静态的。

+   某些解决方案，如果您曾经创建过本机导航，可能不可用（例如，与本机生命周期的连接）。

+   有限的国际支持（例如，截至 2018 年 7 月，某些 JavaScript 导航库不支持从右到左，包括 React Navigation）。

另一方面，让我们看看本机导航。

本机导航的优点如下：

+   本机导航可以通过系统库进行优化，例如，容器化导航堆栈

+   本机导航优于 JavaScript 导航

+   它利用了每个系统的独特能力

+   能够利用本机生命周期并通过动画连接到它

+   大多数实现都集成了状态管理库

本机导航的缺点如下：

+   有时它违背了 React Native 的初衷-它使导航在系统之间分歧，而不是统一。

+   很难在各个平台上提供一致的 API，或者根本不一致。

+   单一真相不再成立-我们的状态泄漏到在特定平台内部管理状态的本机代码。这会破坏时间旅行。

+   问题状态同步 - 所选择的库要么根本不承诺立即状态同步，要么实现了不同的锁定，这会使应用程序变慢，通常会破坏其目的。

一些专家认为 NavigatorIOS 库的开发人员（截至 2018 年 7 月，仍在官方 React Native 文档中提到）在开发工作上做得很好，但它的未来是不确定的。

+   它需要使用本地系统的工具和配置。

+   它旨在针对有经验的开发人员。

在选择其中一个之前，你需要考虑所有这些并做出正确的权衡。但在我们深入代码之前，请专注于下一节。

# 重构你的应用程序

没有人喜欢庞大的单片代码库，所有功能都交织在一起。随着应用程序的增长，我们可以做些什么来防止这种情况发生？确保明智地定位代码文件，并且有一种标准化的做法。

一旦超过 10,000 行，会让你头痛的单片代码库的一个例子是：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/hsn-dsn-ptn-rn/img/20583eb7-7b0d-4ace-9024-327e5662b0ff.png)

一个目录结构的例子，对于大型项目来说并不够好

想象一下有 1,200 个减速器的目录。你可能会使用搜索。相信我，这在有 1,200 个减速器的情况下也会变得困难。

相反，更好的做法是按功能对代码进行分组。由此，我们将清楚地了解在调查应用程序的某个独立部分时要查看的文件范围：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/hsn-dsn-ptn-rn/img/44efa3e0-6d89-497a-be46-6d182e8ce91a.png)

一个对于中大型项目可能有好处的目录结构的例子

要查看这种新结构的实际效果，请查看第七章中`src`文件夹中的`Example 1`的代码文件，*导航模式*。

如果你曾经使用过微服务，可以将其想象成你希望你的功能在前端代码库中成为简单的微服务。一个屏幕可能会要求它们通过发送数据来运行，并期望特定的输出。

在某些架构中，每个这样的实体也会创建自己的 Flux 存储。这对于大型项目来说是一个很好的关注点分离。

# React Navigation

浏览器内置了导航解决方案，React Native 需要有自己的解决方案，这其中是有原因的：

“在 Web 浏览器中，您可以使用锚点（<a>）标签链接到不同的页面。当用户点击链接时，URL 将被推送到浏览器历史堆栈中。当用户按下返回按钮时，浏览器将从历史堆栈的顶部弹出项目，因此活动页面现在是先前访问的页面。React Native 没有像 Web 浏览器那样内置全局历史堆栈的概念 - 这就是 React Navigation 进入故事的地方。”

- React Navigation 官方文档，可在以下网址找到：

[`reactnavigation.org/docs/en/hello-react-navigation.html`](https://reactnavigation.org/docs/en/hello-react-navigation.html)。

总之，我们的移动导航不仅可以像在浏览器中看到的那样处理，而且可以按照我们喜欢的任何自定义方式处理。这要归功于历史原因，因为一些屏幕更改通常与特定操作系统的用户所认可的特定动画相关联。因此，尽可能地遵循它们以使其类似于原生感觉是明智的。

# 使用 React Navigation

让我们通过以下命令安装 React Navigation 库开始我们的旅程：

```jsx
yarn add react-navigation
```

一旦库安装完成，让我们尝试最简单的路径，使用一个类似于浏览器中看到的堆栈导航系统。

对于那些不知道或忘记堆栈是什么的人，堆栈这个名字来源于现实生活中一组物品堆叠在一起的类比。物品可以被推到堆栈中（放在顶部），或者从堆栈中弹出（从顶部取出）。

一个特殊的结构，进一步推动这个想法，类似于一个水平堆栈，可以从底部和顶部访问。这样的结构被称为队列；然而，在本书中我们不会使用队列。

在上一节中，我对我们的文件结构进行了重构。作为重构的一部分，我创建了一个新文件，名为`TaskListScreen`，它由我们代码库中的特性组成：

```jsx
// src / Chapter 7 / Example 2 / src / screens / TaskListScreen.js export const TaskListScreen = () => (
    <View>
 **<AddTaskContainer />    // Please note slight refactor** **<TaskListContainer />   // to two separate containers** </View> );   export default withGeneralLayout(TaskListScreen);
```

`withGeneralLayout` HOC 也是重构的一部分，它所做的就是用头部和底部栏包装屏幕。这样包装的 `TaskList` 组件准备好被称为 `Screen` 并直接提供给 React Navigation 设置：

```jsx
// src / Chapter 7 / Example 2 / src / screens / index.js

export default createStackNavigator({
    TaskList: {
        screen: TaskListScrn,
  path: 'project/task/list', // later on: 'project/:projectId/task/list'
  navigationOptions: { header: null }
    },
  ProjectList: {
        screen: () => <View><Text>Under construction.</Text></View>,
  path: 'project/:projectId'
  },
 // ...
}, {
    initialRouteName: 'TaskList',
  initialRouteParams: {}
}); 
```

在这里，我们使用一个期望两个对象的 `createStackNavigator` 函数：

+   代表应该由这个`StackNavigator`处理的所有屏幕的对象。每个屏幕都应该指定一个代表该屏幕和路径的组件。您还可以使用`navigationOptions`来自定义您的屏幕。在我们的情况下，我们不想要默认的标题栏。

+   代表导航器本身的设置对象。您可能想要定义初始路由名称及其参数。

做完这些，我们已经完成了导航的 hello world - 我们有一个屏幕在工作。

# 使用 React Navigation 的多个屏幕

现在是时候向我们的`StackNavigator`添加一个任务屏幕了。使用你新学到的语法，为任务详情创建一个占位符屏幕。以下是我的实现：

```jsx
// src / Chapter 7 / Example 3 / src / screens / index.js
// ...
Task: {
    screen: () => <View><Text>Under construction.</Text></View>,
  path: 'project/task/:taskId',
  navigationOptions: ({ navigation }) => ({
        title: `Task ${navigation.state.params.taskId} details`  })
},
// ...
```

这一次，我还传递了`navigationOptions`，因为我想使用具有特定标题的默认导航器顶部栏：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/hsn-dsn-ptn-rn/img/65bb51fc-698b-4430-911b-02d7092141a3.png)

新任务屏幕可能的样子

要导航到任务详情，我们需要一个单独的链接或按钮，可以带我们到那里。让我们在我们的目录结构的顶部创建一个可重用的链接，如下所示：

```jsx
// src / Chapter 7 / Example 3 / src / components / NavigateButton.js
// ...
export const NavigateButton = ({
    navigation, to, data, text
}) => (
    <Button
  onPress={() => navigation.navigate(to, data)}
        title={text}
    /> );
// ...
export default withNavigation(NavigateButton);
```

前面片段的最后一行使用了`withNavigation` HOC，这是 React Navigation 的一部分。这个 HOC 为`NavigateButton`提供了导航属性。`To`、`data`和`text`需要手动传递给组件：

```jsx
// src / Chapter 7 / Example 3 / src / features / tasks / views / TaskList.js
// ...
<View style={styles.taskText}>
 <Text style={styles.taskName}>
  {task.name}
    </Text>
 <Text>{task.description}</Text> </View> <View style={styles.taskActions}>
 <NavigateButton  data={{ taskId: task.id }}
 to="Task"
  text="Details" **/>** </View>
// ... 
```

就是这样！让我们看看以下的结果。如果你觉得设计需要一点润色，可以使用第三章 *样式模式*中学到的技巧：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/hsn-dsn-ptn-rn/img/ed751d62-83e8-4209-a870-e3a580005433.png)

每个任务行现在都显示了一个详情链接

现在您可以点击详情按钮导航到任务详情屏幕。

# 标签导航

由于我们已经放置了底部图标控件，使它们工作将非常简单。这是标签导航的一个经典示例：

```jsx
// src / Chapter 7 / Example 4 / src / screens / index.js
export default createBottomTabNavigator(
    {
        Home: createStackNavigator({
            TaskList: {
                // ...
            },
            // ...
        }, {
            // ...
        }),
  Search: () => (
            <View>
 <Text>Search placeholder. Under construction.</Text>
 </View>  ),
  Notifications: () => (
            <View>
 <Text>Notifications placeholder. Under construction.</Text>
 </View>  )
    },
  {
        initialRouteName: 'Home',
  initialRouteParams: {}
    }
); 
```

请注意使用缩写创建屏幕的用法。我直接传递组件，而不是使用对象：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/hsn-dsn-ptn-rn/img/c3ca77f7-38a2-4c25-a493-303606816378.png)

默认情况下，React Navigation 会为我们创建一个底部栏

要禁用标题栏，我们需要传递适当的属性，如下所示：

```jsx
// src / Chapter 7 / Example 4 / src / screens / index.js
// ...
{
    initialRouteName: 'Home',
  initialRouteParams: {},
  navigationOptions: () => ({
 tabBarVisible: false
  })
}
// ...
```

现在，我们需要让我们的图标响应用户的触摸。首先，创建一个`NavigateIcon`组件，你可以在你的应用程序中重用。查看存储库以获取完整的代码示例，但这里提供了一个示例：

```jsx
// src / Chapter 7 / Example 4 / src / components / NavigateIcon.js export const NavigateIcon = ({
    navigation, to, data, ...iconProps
}) => (
    <Ionicons
  {...iconProps}
        onPress={() => navigation.navigate(to, data)}
    /> ); // ... export default withNavigation(NavigateIcon); 
```

用`NavigateIcon`相当简单地替换现有的图标，如下所示：

```jsx
// src / Chapter 7 / Example 4 / src / layout / views / GeneralAppView.js
import NavIonicons from '../../components/NavigateIcon';
<View style={styles.footer}>
 <NavIonicons  to**="Home"**
 // ...   />
 <NavIonicons  to**="Search"**
        // ...   />
 <NavIonicons  to**="Notifications"**
        // ...   /> </View>
```

最后要注意的是一般布局。`Search`和`Notifications`屏幕应该显示我们的自定义底部导航。由于我们学到的 HOC 模式，这 surprisingly 容易：

```jsx
// src / Chapter 7 / Example 4 / src / screens / index.js
// ...
Search: withGeneralLayout(() => (
    <View>
 <Text>Search placeholder. Under construction.</Text>
 </View> )), Notifications: withGeneralLayout(() => (
    <View>
 <Text>Notifications placeholder. Under construction.</Text>
 </View> )) // ...
```

结果显示在以下截图中：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/hsn-dsn-ptn-rn/img/db515245-8a78-4128-88b4-36cf98f04933.png)

搜索屏幕及其占位符。

请通过向`withGeneralLayout` HOC 添加配置对象来修复标题名称。

# 抽屉导航

现在是时候实现抽屉导航，以便用户访问不常用的屏幕，如下所示：

```jsx
// src / Chapter 7 / Example 5 / src / screens / index.js
// ...
export default createDrawerNavigator({
    Home: TabNavigation,
  Profile: withGeneralLayout(() => (
        <View>
 <Text>Profile placeholder. Under construction.</Text>
 </View>  )),
  Settings: withGeneralLayout(() => (
        <View>
 <Text>Settings placeholder. Under construction.</Text>
 </View>  ))
}); 
```

由于我们的默认抽屉已准备就绪，让我们添加一个图标来显示它。汉堡图标是最受欢迎的，通常放置在标题的一个角落：

```jsx
// src / Chapter 7 / Example 5 / src / layout / views / MenuView.js
const Hamburger = props => (<Ionicons
  onPress={() => props.navigation.toggleDrawer()}
    name="md-menu"
  size={32}
    color="black" />); // ...   const MenuView = withNavigation(Hamburger); 
```

现在，只需将其放在`GeneralAppView`组件的标题部分并适当地进行样式设置：

```jsx
// src / Chapter 7 / Example 5 / src / layout / views / GeneralAppView.js
<View style={styles.header}>
 // ...  <View style={styles.headerMenuIcon}>
 <MenuView /> </View> </View> 
```

就是这样，我们的抽屉功能完全可用。您的抽屉可能看起来像这样：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/hsn-dsn-ptn-rn/img/d22aea70-bfc0-4cc9-8961-7ae12d831c35.png)

在 iPhone X 模拟器上打开抽屉菜单。

您可以通过单击右上角的汉堡图标来打开抽屉。

# 重复数据的问题

任务列表组件在成功挂载时获取显示列表所需的数据。然而，没有实现防止数据重复的机制。本书不旨在为常见问题提供解决方案。然而，让我们考虑一些您可以实施的解决方案：

+   更改 API 并依赖于唯一的任务标识符（如 ID、UUID 或 GUID）。确保只允许唯一的标识符。

+   每次请求都清除数据。这很好；然而，在我们的情况下，我们会丢失未保存的（与 API 相关的）任务。

+   保持状态，并且只请求一次。这只适用于我们简单的用例。在更复杂的应用程序中，您将需要更频繁地更新数据。

好的，牢记这一点，让我们最终深入基于本地导航解决方案的库。

# React Native Navigation

在本节中，我们将使用本地解决方案进行导航。React Native Navigation 是 Android 和 iOS 本地导航的包装器。

我们的目标是重新创建我们在上一节中实现的内容，但使用 React Navigation。

# 关于设置的几句话

在本节中，您可能会面临的最大挑战之一是设置库。请遵循最新的安装说明。花点时间——如果您不熟悉工具和生态系统，可能需要超过 8 小时。

按照以下链接中的安装说明进行安装：[`github.com/wix/react-native-navigation`](https://github.com/wix/react-native-navigation)。

本书使用 React Native Navigation 第 2 版的 API。要使用相同的代码示例，您也需要安装第 2 版。

您可能还需要要么退出 Create React Native App，要么使用`react-native init`引导另一个项目并将关键文件复制到那里。如果您在这个过程中遇到困难，请尝试使用`src/Chapter 7/Example 6/`（只是 React Native）或`src/Chapter 7/Example 7/`（整个 React Native Navigation 设置）中的代码。我使用了`react-native init`并将所有重要的东西都复制到那里。

在实现可工作的设置过程中，肯定会出现错误。不要沮丧；在 StackOverflow 上搜索任何错误或在 React Native 和 React Native Navigation 的 GitHub 问题中搜索。

# React Native Navigation 的基础知识

第一个重大变化是缺少`AppRegistry`和`registerComponent`的调用。相反，我们将使用`Navigation.setRoot(...)`来完成工作。只有在确定应用程序成功启动时，才应调用`setRoot`函数，如下所示：

```jsx
// src / Chapter 7 / Example 7 / src / screens / index.js
import { Navigation } from 'react-native-navigation';
// ...
export default () => Navigation.events().registerAppLaunchedListener(() => {
    Navigation.setRoot({
        // ...
    });
});
```

然后，我们的根/入口文件将只调用 React Native Navigation 函数：

```jsx
import start from './src/screens/index';   export default start();
```

好的。更有趣的部分是我们放入`setRoot`函数的内容。基本上，我们在这里有一个选择：堆栈导航或标签导航。根据我们之前的应用程序，顶层应用将是标签导航（抽屉导航在 React Native Navigation 中是解耦的）。

在撰写本书时，使用默认内置的底部栏是保留先前功能的唯一选项。一旦库作者发布 RNN 的第 2 版并修复`Navigation.mergeOptions(...)`，您就可以实现自定义底部栏。

首先，让我们移除默认的顶部栏并自定义底部栏：

```jsx
// src / Chapter 7 / Example 7 / src / screens / index.js
// ...
Navigation.setRoot({
    root: {
        bottomTabs: {
            children: [
            ],
  options: {
                topBar: {
                    visible: false**,**
  drawBehind: true,
  animate: false
  },
  bottomTabs: {   animate: true
  }   }
        }
    }
});
```

完成了这一点，我们准备定义标签。在 React Native Navigation 中要做的第一件事是注册屏幕：

```jsx
// src / Chapter 7 / Example 7 / src / screens / index.js
// ...
Navigation.registerComponent(
    'HDPRN.TabNavigation.TaskList',
  () => TaskStackNavigator, store, Provider
); Navigation.registerComponent(
    'HDPRN.TabNavigation.SearchScreen',
  () => SearchScreen, store, Provider
); Navigation.registerComponent(
    'HDPRN.TabNavigation.NotificationsScreen',
  () => NotificationsScreen, store, Provider
); 
```

当我们注册了所有基本的三个屏幕后，我们可以按照以下方式进行标签定义：

```jsx
// src / Chapter 7 / Example 7 / src / screens / index.js
// ...
children: [
    {
        stack: {
            id: 'HDPRN.TabNavigation.TaskListStack',
            // TODO: Check below, let's handle this separately
        }
    },
  {
        component: {
            id: 'HDPRN.TabNavigation.**SearchScreen**',
  name: 'SearchScreen',
  options: {
                bottomTab: {
                    text: 'Search',
                    // Check sources if you want to know
                    // how to get this icon variable
  icon: search 
                }
            }
        }
    },
 // Notifications config object omitted: similar as for Search
]
```

我们定义了三个单独的标签 - `Tasks`，`Search`和`Notifications`。关于`Tasks`，这是另一个导航器。`Stack`导航器可以配置如下：

```jsx
stack: {
    id: 'HDPRN.TabNavigation.TaskListStack',
  children: [{
        component: {
            id: 'HDPRN.TabNavigation.**TaskList**',
  name: 'HDPRN.TabNavigation.TaskList',
  }
    }],
  options: {
        bottomTab: {
            text: 'Tasks',
  icon: home
        }
    }
}
```

在上面的片段中，`bottomTab`选项设置了底部栏中的文本和图标：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/hsn-dsn-ptn-rn/img/742b3f87-12e2-4516-a3ec-fac4f7712eb2.png)

使用 React Native Navigation 的任务选项卡

# 进一步调查

我将把如何实现导航元素（如抽屉或任务详情屏幕）的调查留给那些勇敢的人。在撰写本文时，React Native Navigation v2 相当不稳定，我选择不再发布来自该库的任何片段。对于大多数读者来说，这应该足够让他们对整体感觉有所了解。

# 总结

在这一章中，我们最终扩展了我们的应用程序，比以前有更多的视图。您已经学会了移动应用程序中不同的导航方法。在 React Native 世界中，要么是原生导航，要么是 JavaScript 导航，或者两者的混合。除了学习导航本身，我们还使用了包括`StackNavigation`、`TabNavigation`和`DrawerNavigation`在内的组件。

这是我们第一次将 Create React Native App 弹出，并从原生导航库中安装了原生代码。我们开始深入研究 React Native。现在是时候退后一步，更新我们的 JavaScript 知识了。我们将学习不仅在 React Native 中有益的模式，而且在整个 JavaScript 中都有益的模式。

# 进一步阅读

+   React Navigation 常见错误-来自官方文档，可在以下链接找到：

[`reactnavigation.org/docs/en/common-mistakes.html`](https://reactnavigation.org/docs/en/common-mistakes.html)。

+   Charles Mangwa 的《在 React Native 中导航的千种方式》：

[`www.youtube.com/watch?v=d11dGHVVahk.`](https://www.youtube.com/watch?v=d11dGHVVahk)

+   React Navigation 的导航游乐场：

[`expo.io/@react-navigation/NavigationPlayground`](https://expo.io/@react-navigation/NavigationPlayground)。

+   Expo 关于导航的文档：

[`docs.expo.io/versions/v29.0.0/guides/routing-and-navigation`](https://docs.expo.io/versions/v29.0.0/guides/routing-and-navigation)。

+   标签的 Material Design：

[`material.io/design/components/tabs.html#placement`](https://material.io/design/components/tabs.html#placement)。

+   在 Awesome React Native 存储库中关于导航的部分：

[`github.com/jondot/awesome-react-native#navigation`](https://github.com/jondot/awesome-react-native#navigation)。
