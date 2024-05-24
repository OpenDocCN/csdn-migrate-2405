# React16 基础知识第二版（三）

> 原文：[`zh.annas-archive.org/md5/3e3e14982ed4c5ebe5505c84fd2fdbb9`](https://zh.annas-archive.org/md5/3e3e14982ed4c5ebe5505c84fd2fdbb9)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十章：使用 Flux 加强您的 React 架构

构建 Web 应用程序的过程具有一种与生命本身的演变过程有些相似的特质——它永远不会结束。与建造桥梁不同，构建 Web 应用程序没有代表开发过程结束的自然状态。由您或您的团队决定何时停止开发过程并发布您已经构建的内容。

在这本书中，我们已经达到了可以停止开发 Snapterest 的点。现在，我们有一个基本功能的小型 React.js 应用程序，它只是简单地运行。

这样就够了吗？

并不完全是这样。在本书的早些部分，我们讨论了维护 Web 应用程序的过程在时间和精力方面要比开发过程昂贵得多。如果我们选择在其当前状态下完成 Snapterest 的开发，我们也将选择开始维护它的过程。

我们准备好维护 Snapterest 了吗？我们知道它的当前状态是否允许我们在以后引入新功能而无需进行重大代码重构吗？

# 分析您的 Web 应用程序架构

为了回答这些问题，让我们从实现细节中放大，并探索我们应用程序的架构：

+   `app.js`文件呈现我们的`Application`组件

+   `Application`组件管理 tweet 集合并呈现我们的`Stream`和`Collection`组件

+   `Stream`组件从`SnapkiteStreamClient`库接收新的 tweets 并呈现`StreamTweet`和`Header`组件

+   `Collection`组件呈现`CollectionControls`和`TweetList`组件

停在那里。您能告诉数据在我们的应用程序内部是如何流动的吗？您知道它是如何进入我们的应用程序的吗？新的 tweet 是如何最终进入我们的集合的？让我们更仔细地检查我们的数据流：

1.  我们使用`SnapkiteStreamClient`库在`Stream`组件内接收新 tweet。

1.  然后，这个新的 tweet 从`Stream`传递到`StreamTweet`组件。

1.  `StreamTweet`组件将其传递给`Tweet`组件，后者呈现 tweet 图像。

1.  用户点击该 tweet 图像将其添加到其集合中。

1.  `Tweet`组件通过`handleImageClick(tweet)`回调函数将`tweet`对象传递给`StreamTweet`组件。

1.  `StreamTweet`组件通过`onAddTweetToCollection(tweet)`回调函数将`tweet`对象传递给`Stream`组件。

1.  `Stream`组件通过`onAddTweetToCollection(tweet)`回调函数将`tweet`对象传递给`Application`组件。

1.  `Application`组件将`tweet`添加到`collectionTweets`对象并更新其状态。

1.  状态更新触发`Application`组件重新渲染，进而使用更新后的推文集合重新渲染`Collection`组件。

1.  然后，`Collection`组件的子组件也可以改变我们的推文集合。

你感到困惑吗？你能长期依赖这种架构吗？你认为它容易维护吗？我不这么认为。

让我们识别当前架构的关键问题。我们可以看到新数据通过`Stream`组件进入我们的 React 应用程序。然后，它沿着组件层次结构一直传递到`Tweet`组件。然后，它一直传递到`Application`组件，那里存储和管理它。

为什么我们要在`Application`组件中存储和管理我们的推文集合？因为`Application`是另外两个组件`Stream`和`Collection`的父组件：它们都需要能够改变我们的推文集合。为了适应这一点，我们的`Application`组件需要将回调函数传递给这两个组件：

+   `Stream`组件：

```jsx
<Stream 
  onAddTweetToCollection={this.addTweetToCollection}
/>
```

+   `Collection`组件：

```jsx
<Collection
  tweets={collectionTweets}
  onRemoveTweetFromCollection={this.removeTweetFromCollection} onRemoveAllTweetsFromCollection={this.removeAllTweetsFromCollection}
/>
```

`Stream`组件获取`onAddTweetToCollection()`函数以将推文添加到集合中。`Collection`组件获取`onRemoveTweetFromCollection()`函数以从集合中移除推文，并获取`onRemoveAllTweetsFromCollection()`函数以移除集合中的所有推文。

然后，这些回调函数会一直传播到组件层次结构的底部，直到它们到达实际调用它们的某个组件。在我们的应用程序中，`onAddTweetToCollection()`函数只在`Tweet`组件中被调用。让我们看看在它被调用之前需要从一个组件传递到另一个组件多少次：

```jsx
Application > Stream > StreamTweet > Tweet
```

`onAddTweetToCollection()`函数在`Stream`和`StreamTweet`组件中都没有被使用，但它们都将其作为属性传递下去，目的是将其传递给它们的子组件。

Snapterest 是一个小型的 React 应用程序，所以这个问题只是一个不便，但以后，如果你决定添加新功能，这个不便很快就会变成一个维护的噩梦：

```jsx
Application > ComponentA > ComponentB > ComponentC > ComponentD > ComponentE > ComponentF > ComponentG > Tweet
```

为了防止这种情况发生，我们将解决两个问题：

+   我们将改变新数据进入我们的应用程序的方式

+   我们将改变组件如何获取和设置数据

我们将借助 Flux 重新思考应用程序内部数据流。

# 理解 Flux

**Flux**是 Facebook 提供的应用程序架构，它与 React 相辅相成。它不是一个框架或库，而是一个解决常见问题的解决方案——如何构建可扩展的客户端应用程序。

使用 Flux 架构，我们可以重新思考数据在我们的应用程序内部的流动方式。Flux 确保我们的所有数据只在一个**单一方向**中流动。这有助于我们理解我们的应用程序如何工作，无论它有多小或多大。使用 Flux，我们可以添加新功能，而不会使应用程序的复杂性或其心智模型爆炸。

您可能已经注意到，React 和 Flux 都共享相同的核心概念——单向数据流。这就是为什么它们自然而然地很好地配合在一起。我们知道数据在 React 组件内部如何流动，但 Flux 如何实现单向数据流呢？

使用 Flux，我们将应用程序的关注点分为四个逻辑实体：

+   操作

+   分发器

+   存储器

+   视图

**操作**是我们在想要改变应用程序状态时创建的对象。例如，当我们的应用程序接收到新推文时，我们创建一个新操作。操作对象有一个“类型”属性，用于标识它是什么操作，以及我们的应用程序需要过渡到新状态的任何其他属性。以下是一个操作对象的示例：

```jsx
const action = {
  type: 'receive_tweet',
  tweet
};
```

如您所见，这是一个`receive_tweet`类型的操作，它有一个`tweet`属性，这是我们的应用程序接收到的新推文对象。通过查看操作的类型，您可以猜测这个操作代表了应用程序状态的什么变化。对于我们的应用程序接收到的每条新推文，它都会创建一个`receive_tweet`操作。

这个操作去哪里？我们的应用程序的哪个部分会接收到这个操作？操作被分发到存储器。

存储器负责管理应用程序的数据。它们提供了访问数据的方法，但不提供更改数据的方法。如果要更改存储器中的数据，必须创建并分发一个操作。

我们知道如何创建一个操作，但如何分发它呢？顾名思义，您可以使用分发器来做这件事。

分发器负责将所有操作分发到所有存储器：

+   所有存储器都向分发器注册。它们提供一个回调函数。

+   所有操作都由调度程序分派到所有已向调度程序注册的存储。

这就是 Flux 架构中数据流的样子：

```jsx
Actions > Dispatcher > Stores
```

您可以看到调度程序在我们的数据流中扮演着一个中心元素的角色。所有操作都由它分派。存储与它注册。所有操作都是同步分派的。您不能在上一个操作分派的中间分派操作。在 Flux 架构中，没有操作可以跳过调度程序。

# 创建调度程序

现在让我们实现这个数据流。我们将首先创建一个调度程序。Facebook 提供了一个我们可以重用的调度程序的实现。让我们利用一下：

1.  导航到 `~/snapterest` 目录并运行以下命令：

```jsx
**npm install --save flux**

```

`flux` 模块带有一个我们将重用的 `Dispatcher` 函数。

1.  接下来，在我们项目的 `~/snapterest/source/dispatcher` 目录中创建一个名为 `dispatcher` 的新文件夹。然后在其中创建 `AppDispatcher.js` 文件：

```jsx
import { Dispatcher } from 'flux';
export default new Dispatcher();
```

首先，我们导入 Facebook 提供的 `Dispatcher`，然后创建并导出一个新的实例。现在我们可以在我们的应用程序中使用这个实例。

接下来，我们需要一种方便的方式来创建和分派操作。对于每个操作，让我们创建一个函数来创建和分派该操作。在 Flux 架构中，这些函数被称为操作创建者函数。

# 创建操作创建者

在我们项目的 `~/snapterest/source/actions` 目录中创建一个名为 `actions` 的新文件夹。然后，在其中创建 `TweetActionCreators.js` 文件：

```jsx
import AppDispatcher from '../dispatcher/AppDispatcher';

function receiveTweet(tweet) {
  const action = {
    type: 'receive_tweet',
    tweet
  };

  AppDispatcher.dispatch(action);
}

export { receiveTweet };
```

我们的操作创建者将需要一个调度程序来分派操作。我们将导入之前创建的 `AppDispatcher`：

```jsx
import AppDispatcher from '../dispatcher/AppDispatcher';
```

然后，我们将创建我们的第一个操作创建者 `receiveTweet()`：

```jsx
function receiveTweet(tweet) {
  const action = {
    type: 'receive_tweet',
    tweet
  };

  AppDispatcher.dispatch(action);
}
```

`receiveTweet()` 函数以 `tweet` 对象作为参数，并创建具有 `type` 属性设置为 `receive_tweet` 的 `action` 对象。它还将 `tweet` 对象添加到我们的 `action` 对象中，现在每个存储都将接收到这个 `tweet` 对象。

最后，`receiveTweet()` 操作创建者通过在 `AppDispatcher` 对象上调用 `dispatch()` 方法来分派我们的 `action` 对象：

```jsx
AppDispatcher.dispatch(action);
```

`dispatch()` 方法将 `action` 对象分派到所有已向 `AppDispatcher` 调度程序注册的存储。

然后我们导出我们的 `receiveTweet` 方法：

```jsx
export { receiveTweet };
```

到目前为止，我们已经创建了 `AppDispatcher` 和 `TweetActionCreators`。接下来，让我们创建我们的第一个存储。

# 创建存储

正如您之前学到的，存储在您的 Flux 架构中管理数据。它们将这些数据提供给 React 组件。我们将创建一个简单的存储，用于管理我们的应用程序从 Twitter 接收到的新推文。

在项目的 `~/snapterest/source/stores` 目录中创建一个名为 `stores` 的新文件夹。然后，在其中创建 `TweetStore.js` 文件：

```jsx
import AppDispatcher from '../dispatcher/AppDispatcher';
import EventEmitter from 'events';

let tweet = null;

function setTweet(receivedTweet) {
  tweet = receivedTweet;
}

function emitChange() {
  TweetStore.emit('change');
}

const TweetStore = Object.assign({}, EventEmitter.prototype, {
  addChangeListener(callback) {
    this.on('change', callback);
  },

  removeChangeListener(callback) {
    this.removeListener('change', callback);
  },

  getTweet() {
    return tweet;
  }
});

function handleAction(action) {
  if (action.type === 'receive_tweet') {
    setTweet(action.tweet);
    emitChange();
  }
}

TweetStore.dispatchToken = AppDispatcher.register(handleAction);

export default TweetStore;
```

`TweetStore.js` 文件实现了一个简单的存储。我们可以将其分为四个逻辑部分：

+   导入依赖模块并创建私有数据和方法

+   创建具有公共方法的 `TweetStore` 对象

+   创建一个操作处理程序并向调度程序注册存储

+   将 `dispatchToken` 分配给我们的 `TweetStore` 对象并导出它。

在我们存储的第一个逻辑部分中，我们只是导入存储所需的依赖模块：

```jsx
import AppDispatcher from '../dispatcher/AppDispatcher';
import EventEmitter from 'events';
```

因为我们的存储将需要向调度程序注册，所以我们导入 `AppDispatcher` 模块。接下来，我们导入 `EventEmitter` 类，以便能够向我们的存储添加和移除事件监听器：

```jsx
import EventEmitter from 'events';
```

导入所有依赖项后，我们定义存储管理的数据：

```jsx
let tweet = null;
```

`TweetStore` 对象管理一个简单的推文对象，我们最初将其设置为 `null`，以标识我们尚未收到新的推文。

接下来，让我们创建两个私有方法：

```jsx
function setTweet(receivedTweet) {
  tweet = receivedTweet;
}

function emitChange() {
  TweetStore.emit('change');
}
```

`setTweet()` 函数用 `receiveTweet` 对象更新 `tweet`。`emitChange` 函数在 `TweetStore` 对象上发出 `change` 事件。这些方法对于 `TweetStore` 模块是私有的，外部无法访问。

`TweetStore.js` 文件的第二个逻辑部分是创建 `TweetStore` 对象：

```jsx
const TweetStore = Object.assign({}, EventEmitter.prototype, {
  addChangeListener(callback) {
    this.on('change', callback);
  },

  removeChangeListener(callback) {
    this.removeListener('change', callback);
  },

  getTweet() {
    return tweet;
  }
});
```

我们希望我们的存储在状态发生变化时能够通知应用程序的其他部分。我们将使用事件来实现这一点。每当我们的存储更新其状态时，它会发出 `change` 事件。对存储状态变化感兴趣的任何人都可以监听这个 `change` 事件。他们需要添加他们的事件监听器函数，我们的存储将在每个 `change` 事件上触发。为此，我们的存储定义了 `addChangeListener()` 方法，用于添加监听 `change` 事件的事件监听器，以及 `removeChangeListener()` 方法，用于移除 `change` 事件监听器。但是，`addChangeListener()` 和 `removeChangeListener()` 依赖于 `EventEmitter.prototype` 对象提供的方法。因此，我们需要将这些方法从 `EventEmitter.prototype` 对象复制到我们的 `TweetStore` 对象中。这就是 `Object.assign()` 函数的作用：

```jsx
targetObject = Object.assign(
  targetObject, 
  sourceObject1,
  sourceObject2
);
```

`Object.assign()`将`sourceObject1`和`sourceObject2`拥有的属性复制到`targetObject`，然后返回`targetObject`。在我们的情况下，`sourceObject1`是`EventEmitter.prototype`，`sourceObject2`是一个定义了我们存储器方法的对象字面量：

```jsx
{
  addChangeListener(callback) {
    this.on('change', callback);
  },

  removeChangeListener(callback) {
    this.removeListener('change', callback);
  },

  getTweet() {
    return tweet;
  }
}
```

`Object.assign()`方法返回从所有源对象复制的属性的`targetObject`。这就是我们的`TweetStore`对象所做的。

你是否注意到我们将`getTweet()`函数定义为`TweetStore`对象的一个方法，而对`setTweet()`函数却没有这样做。为什么呢？

稍后，我们将导出`TweetStore`对象，这意味着它的所有属性都将可供应用程序的其他部分使用。我们希望它们能够从`TweetStore`获取数据，但不能直接通过调用`setTweet()`来更新数据。相反，更新任何存储器中的数据的唯一方法是创建一个操作并将其分派（使用调度程序）到已向该调度程序注册的存储器。当存储器收到该操作时，它可以决定如何更新其数据。

这是 Flux 架构非常重要的一个方面。存储器完全控制管理它们的数据。它们只允许应用程序中的其他部分读取数据，但永远不会直接写入数据。只有操作应该改变存储器中的数据。

`TweetStore.js`文件的第三个逻辑部分是创建一个操作处理程序并向调度程序注册存储器。

首先，我们创建操作处理程序函数：

```jsx
function handleAction(action) {
  if (action.type === 'receive_tweet') {
    setTweet(action.tweet);
    emitChange();
  }
}
```

`handleAction()`函数以`action`对象作为参数，并检查其类型属性。在 Flux 中，所有存储器都会收到所有操作，但并非所有存储器都对所有操作感兴趣，因此每个存储器必须决定自己感兴趣的操作。为此，存储器必须检查操作类型。在我们的`TweetStore`存储器中，我们检查操作类型是否为`receive_tweet`，这意味着我们的应用程序已收到一条新推文。如果是这样，那么我们的`TweetStore`调用其私有的`setTweet()`函数来使用来自`action`对象的新推文更新`tweet`对象，即`action.tweet`。当存储器更改其数据时，它需要告诉所有对数据更改感兴趣的人。为此，它调用其私有的`emitChange()`函数，发出`change`事件并触发应用程序中其他部分创建的所有事件侦听器。

我们的下一个任务是将`TweetStore`商店与调度程序注册。要将商店与调度程序注册，您需要调用调度程序的`register()`方法，并将商店的操作处理程序函数作为回调函数传递给它。每当调度程序分派一个操作时，它都会调用该回调函数并将操作对象传递给它。

让我们来看看我们的例子：

```jsx
TweetStore.dispatchToken = AppDispatcher.register(handleAction);
```

我们在`AppDispatcher`对象上调用`register()`方法，并将`handleAction`函数作为参数传递。`register()`方法返回一个标识`TweetStore`商店的令牌。我们将该令牌保存为我们的`TweetStore`对象的属性。

`TweetStore.js`文件的第四个逻辑部分是导出`TweetStore`对象：

```jsx
export default TweetStore;
```

这就是您创建一个简单商店的方式。现在，既然我们已经实现了我们的第一个操作创建者、调度程序和商店，让我们重新审视 Flux 架构，并看看它是如何工作的：

1.  商店向调度程序注册自己。

1.  操作创建者通过调度程序创建和分派操作到商店。

1.  商店检查相关操作并相应地更改它们的数据。

1.  商店通知所有正在听的人数据变化。

这是有道理的，你可能会说，但是是什么触发了操作创建者？谁在监听商店更新？这些都是非常好的问题。答案等着你在我们的下一章中。

# 总结

在本章中，您分析了我们的 React 应用程序的架构。您学习了 Flux 架构背后的核心概念，并实现了调度程序、操作创建者和商店。

在下一章中，我们将把它们整合到我们的 React 应用程序中，并让我们的架构准备好迎接维护的天堂。


# 第十一章：为 Flux 轻松维护准备您的 React 应用程序

我们决定在 React 应用程序中实现 Flux 架构的原因是我们希望拥有更容易维护的数据流。在上一章中，我们实现了`AppDispatcher`、`TweetActionCreators`和`TweetStore`。让我们快速回想一下它们的用途：

+   TweetActionCreators：这创建并分发动作

+   `AppDispatcher`：这将所有动作分发到所有存储

+   `TweetStore`：这存储和管理应用程序数据

我们数据流中唯一缺失的部分如下：

+   使用`TweetActionCreators`创建动作并启动数据流

+   使用`TweetStore`获取数据

以下是一些重要的问题要问：我们的应用程序中数据流从哪里开始？我们的数据是什么？如果我们回答了这些问题，我们将了解从哪里开始重构我们的应用程序以适应 Flux 架构。

Snapterest 允许用户接收和收集最新的推文。我们的应用程序关心的唯一数据是推文。因此，我们的数据流始于接收新推文。目前，我们的应用程序的哪个部分负责接收新推文？您可能还记得我们的`Stream`组件具有以下`componentDidMount()`方法：

```jsx
componentDidMount() {
  SnapkiteStreamClient.initializeStream(this.handleNewTweet);
}
```

是的，目前，在渲染`Stream`组件后，我们启动了一系列新推文。等等，你可能会问，“我们不是学过 React 组件应该只关注渲染用户界面吗？”你是对的。不幸的是，目前，`Stream`组件负责两件不同的事情：

+   渲染`StreamTweet`组件

+   启动数据流

显然，这是未来潜在的维护问题。让我们借助 Flux 来解耦这两个不同的关注点。

# 使用 Flux 解耦关注点

首先，我们将创建一个名为`WebAPIUtils`的新实用程序模块。在`~/snapterest/source/utils/`目录中创建`WebAPIUtils.js`文件：

```jsx
import SnapkiteStreamClient from ‘snapkite-stream-client’;
import { receiveTweet } from ‘../actions/TweetActionCreators’;

function initializeStreamOfTweets() {
  SnapkiteStreamClient.initializeStream(receiveTweet);
}

export { initializeStreamOfTweets };
```

在这个实用程序模块中，我们首先导入`SnapkiteStreamClient`库和`TweetActionCreators`。然后，我们创建`initializeStreamOfTweets()`函数，该函数初始化一系列新推文，就像`Stream`组件的`componentDidMount()`方法一样。除了一个关键的区别：每当`SnapkiteStreamClient`接收到新推文时，它调用`TweetActionCreators.receiveTweet`方法，并将新推文作为参数传递给它：

```jsx
SnapkiteStreamClient.initializeStream(receiveTweet);
```

记住`receiveTweet`函数期望接收一个`tweet`参数：

```jsx
function receiveTweet(tweet) {
  // ... create and dispatch ‘receive_tweet’ action
}
```

这个推文将作为一个新动作对象的属性被分发。`receiveTweet()`函数创建。

然后，`WebAPIUtils`模块导出我们的`initializeStreamOfTweets()`函数。

现在我们有一个模块，其中有一个方法来启动我们的 Flux 架构中的数据流。我们应该在哪里导入并调用它？由于它与`Stream`组件解耦，实际上，它根本不依赖于任何 React 组件，我们甚至可以在 React 渲染任何内容之前使用它。让我们在我们的`app.js`文件中使用它：

```jsx
import React from ‘react’;
import ReactDOM from ‘react-dom’;
import Application from ‘./components/Application’;
import { initializeStreamOfTweets } from ‘./utils/WebAPIUtils’;

initializeStreamOfTweets();

ReactDOM.render(
  <Application/>,
  document.getElementById(‘react-application’)
);
```

正如你所看到的，我们所需要做的就是导入并调用`initializeStreamOfTweets()`方法：

```jsx
import { initializeStreamOfTweets } from ‘./utils/WebAPIUtils’;

initializeStreamOfTweets();
```

在调用 React 的`render()`方法之前我们这样做：

```jsx
ReactDOM.render(
  <Application/>,
  document.getElementById(‘react-application’)
);
```

实际上，作为一个实验，你可以完全删除`ReactDOM.render()`这行代码，并在`TweetActionCreators.receiveTweet`函数中放一个日志声明。例如，运行以下代码：

```jsx
function receiveTweet(tweet) {

  console.log("I’ve received a new tweet and now will dispatch it together with a new action.");

  const action = {
    type: ‘receive_tweet’,
    tweet
  };

  AppDispatcher.dispatch(action);
}
```

现在运行`npm start`命令。然后，在 Web 浏览器中打开`~/snapterest/build/index.html`，你会看到以下文本呈现在页面上：

**我即将学习 React.js 的基本知识。**

现在打开 JavaScript 控制台，你会看到这个输出：

```jsx
**[Snapkite Stream Client] Socket connected**
**I’ve received a new tweet and now will dispatch it together with a new action.**

```

这个日志消息将被打印出来，每当我们的应用程序接收到一个新的推文时。即使我们没有渲染任何 React 组件，我们的 Flux 架构仍然存在：

1.  我们的应用程序接收到一个新的推文。

1.  它创建并分发一个新的动作。

1.  没有任何存储器已经向分发器注册，因此没有人可以接收新的动作；因此，什么也没有发生。

现在你可以清楚地看到 React 和 Flux 是两个完全不相互依赖的东西。

然而，我们确实希望渲染我们的 React 组件。毕竟，在前面的十章中，我们已经付出了很多努力来创建它们！为了做到这一点，我们需要让我们的`TweetStore`存储器发挥作用。你能猜到我们应该在哪里使用它吗？这里有一个提示：在一个需要推文来呈现自己的 React 组件中——我们的老朋友`Stream`组件。

# 重构 Stream 组件

现在有了 Flux 架构，我们将重新思考我们的 React 组件如何获取它们需要呈现的数据。如你所知，React 组件通常有两个数据来源：

+   调用另一个库，例如调用`jQuery.ajax()`方法，或者在我们的情况下，`SnapkiteStreamClient.initializeStream()`

+   通过`props`对象从父 React 组件接收数据

我们希望我们的 React 组件不使用任何外部库来接收数据。从现在开始，它们将从商店获取相同的数据。牢记这个计划，让我们重构我们的`Stream`组件。

现在它看起来是这样的：

```jsx
import React from ‘react’;
import SnapkiteStreamClient from ‘snapkite-stream-client’;
import StreamTweet from ‘./StreamTweet’;
import Header from ‘./Header’;

class Stream extends React.Component {
  constructor() {
    super();

    this.state = {
      tweet: null
    };
  }

  componentDidMount() {
    SnapkiteStreamClient.initializeStream(this.handleNewTweet);
  }

  componentWillUnmount() {
    SnapkiteStreamClient.destroyStream();
  }

  handleNewTweet = tweet => {
    this.setState({
      tweet
    });
  }

  render() {
    const { tweet } = this.state;
    const { onAddTweetToCollection } = this.props;
    const headerText = "Waiting for public photos from Twitter...";

    if (tweet) {
      return (
        <StreamTweet
          tweet={tweet}
          onAddTweetToCollection={onAddTweetToCollection}
        />
      );
    }

    return (
      <Header text={headerText} />
    );
  }
}

export default Stream;
```

首先，让我们摆脱`componentDidMount()`、`componentWillUnmount()`和`handleNewTweet()`方法，并导入`TweetStore`商店：

```jsx
import React from ‘react’;
import SnapkiteStreamClient from ‘snapkite-stream-client’;
import StreamTweet from ‘./StreamTweet’;
import Header from ‘./Header’;
import TweetStore from ‘../stores/TweetStore’;

class Stream extends React.Component {
  state = {
    tweet: null
  }

  render() {
    const { tweet } = this.state;
    const { onAddTweetToCollection } = this.props;
    const headerText = "Waiting for public photos from Twitter...";

    if (tweet) {
      return (
        <StreamTweet
          tweet={tweet}
          onAddTweetToCollection={onAddTweetToCollection}
        />
      );
    }

    return (
      <Header text={headerText} />
    );
  }
}

export default Stream;
```

也不再需要导入`snapkite-stream-client`模块。

接下来，我们需要改变`Stream`组件如何获取其初始推文。让我们更新它的初始状态：

```jsx
state = {
  tweet: TweetStore.getTweet()
}
```

从代码上看，这可能看起来是一个小改变，但这是一个重大的架构改进。我们现在使用`getTweet()`方法从`TweetStore`商店获取数据。在上一章中，我们讨论了 Flux 中商店如何公开方法，以允许我们应用程序的其他部分从中获取数据。`getTweet()`方法是这些公共方法的一个例子，被称为*getters*。

你可以从商店获取数据，但不能直接在商店上设置数据。商店没有公共的*setter*方法。它们是有意设计成这样的限制，这样当你用 Flux 编写应用程序时，你的数据只能单向流动。当你需要维护 Flux 应用程序时，这将极大地使你受益。

现在我们知道如何获取我们的初始推文，但是我们如何获取以后到达的所有其他新推文呢？我们可以创建一个定时器并重复调用`TweetStore.getTweet()`；然而，这不是最好的解决方案，因为它假设我们不知道`TweetStore`何时更新其推文。然而，我们知道。

如何？记得在上一章中，我们在`TweetStore`对象上实现了以下公共方法，即`addChangeListener()`方法：

```jsx
addChangeListener(callback) {
  this.on(‘change’, callback);
}
```

我们还实现了`removeChangeListener()`方法：

```jsx
removeChangeListener(callback) {
  this.removeListener(‘change’, callback);
}
```

没错。我们可以要求`TweetStore`告诉我们它何时更改其数据。为此，我们需要调用它的`addChangeListener()`方法，并传递一个回调函数，`TweetStore`将为每个新推文调用它。问题是，在我们的`Stream`组件中，我们在哪里调用`TweetStore.addChangeListener()`方法？

由于我们需要在组件的生命周期中只一次向`TweetStore`添加`change`事件监听器，所以`componentDidMount()`是一个完美的选择。在`Stream`组件中添加以下`componentDidMount()`方法：

```jsx
componentDidMount() {
  TweetStore.addChangeListener(this.onTweetChange);
}
```

在这里，我们向`TweetStore`添加了我们自己的`change`事件监听器`this.onTweetChange`。现在当`TweetStore`改变其数据时，它将触发我们的`this.onTweetChange`方法。我们将很快创建这个方法。

不要忘记在卸载 React 组件之前删除任何事件侦听器。为此，将以下`componentWillUnmount()`方法添加到`Stream`组件中：

```jsx
componentWillUnmount() {
  TweetStore.removeChangeListener(this.onTweetChange);
}
```

删除事件侦听器与添加事件侦听器非常相似。我们调用`TweetStore.removeChangeListener()`方法，并将我们的`this.onTweetChange`方法作为参数传递。

现在，是时候在我们的`Stream`组件中创建`onTweetChange`方法了：

```jsx
onTweetChange = () => {
  this.setState({
    tweet: TweetStore.getTweet()
  });
}
```

正如你所看到的，它使用`TweetStore.getTweet()`方法将新的推文存储在`TweetStore`中，并更新组件的状态。

我们需要在我们的`Stream`组件中进行最后一个更改。在本章的后面，您将了解到我们的`StreamTweet`组件不再需要`handleAddTweetToCollection()`回调函数；因此，在这个组件中，我们将更改以下代码片段：

```jsx
return (
  <StreamTweet
    tweet={tweet}
    onAddTweetToCollection={onAddTweetToCollection}
  />
);
```

用以下代码替换它：

```jsx
return (<StreamTweet tweet={tweet} />);
```

现在让我们来看看我们新重构的`Stream`组件：

```jsx
import React from ‘react’;
import StreamTweet from ‘./StreamTweet’;
import Header from ‘./Header’;
import TweetStore from ‘../stores/TweetStore’;

class Stream extends React.Component {
  state = {
    tweet: TweetStore.getTweet()
  }

  componentDidMount() {
    TweetStore.addChangeListener(this.onTweetChange);
  }

  componentWillUnmount() {
    TweetStore.removeChangeListener(this.onTweetChange);
  }

  onTweetChange = () => {
    this.setState({
      tweet: TweetStore.getTweet()
    });
  }

  render() {
    const { tweet } = this.state;
    const { onAddTweetToCollection } = this.props;
    const headerText = "Waiting for public photos from Twitter...";

    if (tweet) {
      return (<StreamTweet tweet={tweet}/>);
    }

    return (<Header text={headerText}/>);
  }
}

export default Stream;
```

让我们回顾一下，看看我们的`Stream`组件如何始终具有最新的推文：

1.  我们使用`getTweet()`方法将组件的初始推文设置为从`TweetStore`获取的最新推文。

1.  然后，我们监听`TweetStore`的变化。

1.  当`TweetStore`改变其推文时，我们使用`getTweet()`方法从`TweetStore`获取最新的推文，并更新组件的状态。

1.  当组件即将卸载时，我们停止监听`TweetStore`的变化。

这就是 React 组件与 Flux 存储区交互的方式。

在我们继续使我们的应用程序其余部分变得更加 Flux 强大之前，让我们来看看我们当前的数据流：

+   `app.js`：这接收新推文并为每个推文调用`TweetActionCreators`

+   `TweetActionCreators`：这将创建并分发一个带有新推文的新操作

+   `AppDispatcher`：这将所有操作分发到所有存储区

+   `TweetStore`：这将向调度程序注册，并在从调度程序接收到新操作时发出更改事件

+   `Stream`：这监听`TweetStore`的变化，从`TweetStore`获取新的推文，更新状态并重新渲染

你能看到我们如何现在可以扩展 React 组件、动作创建者和存储的数量，仍然能够维护 Snapterest 吗？使用 Flux，它将始终是单向数据流。无论我们实现多少新功能，它都将是相同的思维模式。在长期来看，当我们需要维护我们的应用程序时，我们将获得巨大的好处。

我是否提到我们将在我们的应用程序中更多地使用 Flux？接下来，让我们确实这样做。

# 创建 CollectionStore

Snapterest 不仅存储最新的推文，还存储用户创建的推文集合。让我们用 Flux 重构这个功能。

首先，让我们创建一个集合存储。导航到`~/snapterest/source/stores/`目录并创建`CollectionStore.js`文件：

```jsx
import AppDispatcher from ‘../dispatcher/AppDispatcher’;
import { EventEmitter } from ‘events’;

const CHANGE_EVENT = ‘change’;

let collectionTweets = {};
let collectionName = ‘new’;

function addTweetToCollection(tweet) {
  collectionTweets[tweet.id] = tweet;
}

function removeTweetFromCollection(tweetId) {
  delete collectionTweets[tweetId];
}

function removeAllTweetsFromCollection() {
  collectionTweets = {};
}

function setCollectionName(name) {
  collectionName = name;
}

function emitChange() {
  CollectionStore.emit(CHANGE_EVENT);
}

const CollectionStore = Object.assign(
  {}, EventEmitter.prototype, {
  addChangeListener(callback) {
    this.on(CHANGE_EVENT, callback);
  },

  removeChangeListener(callback) {
    this.removeListener(CHANGE_EVENT, callback);
  },

  getCollectionTweets() {
    return collectionTweets;
  },

  getCollectionName() {
    return collectionName;
  }
}
);

function handleAction(action) {

  switch (action.type) {
    case ‘add_tweet_to_collection’:
      addTweetToCollection(action.tweet);
      emitChange();
      break;

    case ‘remove_tweet_from_collection’:
      removeTweetFromCollection(action.tweetId);
      emitChange();
      break;

    case ‘remove_all_tweets_from_collection’:
      removeAllTweetsFromCollection();
      emitChange();
      break;

    case ‘set_collection_name’:
      setCollectionName(action.collectionName);
      emitChange();
      break;

    default: // ... do nothing

  }
}

CollectionStore.dispatchToken = AppDispatcher.register(handleAction);

export default CollectionStore;
```

CollectionStore 是一个更大的存储，但它具有与 TweetStore 相同的结构。

首先，我们导入依赖项并将`CHANGE_EVENT`变量分配给`change`事件名称：

```jsx
import AppDispatcher from ‘../dispatcher/AppDispatcher’;
import { EventEmitter } from ‘events’;

const CHANGE_EVENT = ‘change’;
```

然后，我们定义我们的数据和四个私有方法来改变这些数据：

```jsx
let collectionTweets = {};
let collectionName = ‘new’;

function addTweetToCollection(tweet) {
  collectionTweets[tweet.id] = tweet;
}

function removeTweetFromCollection(tweetId) {
  delete collectionTweets[tweetId];
}

function removeAllTweetsFromCollection() {
  collectionTweets = {};
}

function setCollectionName(name) {
  collectionName = name;
}
```

正如你所看到的，我们在一个最初为空的对象中存储了一系列推文，并且我们还存储了最初设置为`new`的集合名称。然后，我们创建了三个私有函数来改变`collectionTweets`：

+   将`tweet`对象添加到`collectionTweets`对象

+   从`collectionTweets`对象中删除`tweet`对象

+   从`collectionTweets`中删除所有`tweet`对象，将其设置为空对象

然后，我们定义一个私有函数来改变`collectionName`，名为`setCollectionName`，它将现有的集合名称更改为新的名称。

这些函数被视为私有，因为它们在 CollectionStore 模块之外是不可访问的；例如，你*不能*像在任何其他模块中那样访问它们：

```jsx
CollectionStore.setCollectionName(‘impossible’);
```

正如我们之前讨论的，这是有意为之的，以强制在应用程序中实现单向数据流。

我们创建了`emitChange()`方法来发出`change`事件。

然后，我们创建 CollectionStore 对象：

```jsx
const CollectionStore = Object.assign(
  {}, EventEmitter.prototype, {
  addChangeListener(callback) {
    this.on(CHANGE_EVENT, callback);
  },

  removeChangeListener(callback) {
    this.removeListener(CHANGE_EVENT, callback);
  },

  getCollectionTweets() {
    return collectionTweets;
  },

  getCollectionName() {
    return collectionName;
  }
});
```

这与 TweetStore 对象非常相似，只有两种方法不同：

+   获取推文集合

+   获取集合名称

这些方法可以在 CollectionStore.js 文件之外访问，并且应该在 React 组件中用于从 CollectionStore 获取数据。

然后，我们创建 handleAction（）函数：

```jsx
function handleAction(action) {
  switch (action.type) {

    case ‘add_tweet_to_collection’:
      addTweetToCollection(action.tweet);
      emitChange();
      break;

    case ‘remove_tweet_from_collection’:
      removeTweetFromCollection(action.tweetId);
      emitChange();
      break;

    case ‘remove_all_tweets_from_collection’:
      removeAllTweetsFromCollection();
      emitChange();
      break;

    case ‘set_collection_name’:
      setCollectionName(action.collectionName);
      emitChange();
      break;

    default: // ... do nothing

  }
}
```

该函数处理由 AppDispatcher 分发的操作，但与我们 CollectionStore 模块中的 TweetStore 不同，我们可以处理多个操作。实际上，我们可以处理与 Tweet 集合相关的四个操作：

+   add_tweet_to_collection：这将向集合中添加一条 Tweet

+   remove_tweet_from_collection：这将从集合中删除一条 Tweet

+   remove_all_tweets_from_collection：这将从集合中删除所有 Tweet

+   set_collection_name：这将设置集合名称

请记住，所有存储都会接收所有操作，因此 CollectionStore 也将接收 receive_tweet 操作，但是在这个存储中我们只是简单地忽略它，就像 TweetStore 忽略 add_tweet_to_collection，remove_tweet_from_collection，remove_all_tweets_from_collection 和 set_collection_name 一样。

然后，我们使用 AppDispatcher 注册 handleAction 回调，并将 dispatchToken 保存在 CollectionStore 对象中：

```jsx
CollectionStore.dispatchToken = AppDispatcher.register(handleAction);
```

最后，我们将 CollectionStore 作为一个模块导出：

```jsx
export default CollectionStore;
```

现在，由于我们已经准备好了集合存储，让我们创建动作创建函数。

# 创建 CollectionActionCreators

导航到~/snapterest/source/actions/并创建 CollectionActionCreators.js 文件：

```jsx
import AppDispatcher from ‘../dispatcher/AppDispatcher’;

function addTweetToCollection(tweet) {
  const action = {
    type: ‘add_tweet_to_collection’,
    tweet
  };

  AppDispatcher.dispatch(action);
}

function removeTweetFromCollection(tweetId) {
  const action = {
    type: ‘remove_tweet_from_collection’,
    tweetId
  };

  AppDispatcher.dispatch(action);
}

function removeAllTweetsFromCollection() {
  const action = {
    type: ‘remove_all_tweets_from_collection’
  };

  AppDispatcher.dispatch(action);
}

function setCollectionName(collectionName) {
  const action = {
    type: ‘set_collection_name’,
    collectionName
  };

  AppDispatcher.dispatch(action);
}

export default {
  addTweetToCollection,
  removeTweetFromCollection,
  removeAllTweetsFromCollection,
  setCollectionName
};
```

对于我们在 CollectionStore 中处理的每个操作，我们都有一个操作创建函数：

+   将 Tweet 添加到 Collection 中（）：这将创建并分发带有新 Tweet 的 add_tweet_to_collection 动作

+   removeTweetFromCollection（）：这将创建并分发带有必须从集合中删除的 Tweet 的 ID 的 remove_tweet_from_collection 动作

+   removeAllTweetsFromCollection（）：这将创建并分发 remove_all_tweets_from_collection 动作

+   setCollectionName（）：这将创建并分发带有新集合名称的 set_collection_name 动作

现在，当我们创建了 CollectionStore 和 CollectionActionCreators 模块时，我们可以开始重构我们的 React 组件以采用 Flux 架构。

# 重构 Application 组件

我们从哪里开始重构我们的 React 组件？让我们从组件层次结构中的顶层 React 组件 Application 开始。

目前，我们的 Application 组件存储和管理 Tweet 的集合。让我们删除这个功能，因为现在它由集合存储管理。

从`Application`组件中删除`constructor()`、`addTweetToCollection()`、`removeTweetFromCollection()`和`removeAllTweetsFromCollection()`方法：

```jsx
import React from ‘react’;
import Stream from ‘./Stream’;
import Collection from ‘./Collection’;

class Application extends React.Component {
  render() {
    const {
      collectionTweets
    } = this.state;

    return (
      <div className="container-fluid">
        <div className="row">
          <div className="col-md-4 text-center">
            <Stream onAddTweetToCollection={this.addTweetToCollection}/>

          </div>
          <div className="col-md-8">
            <Collection
              tweets={collectionTweets}
              onRemoveTweetFromCollection={this.removeTweetFromCollection}
              onRemoveAllTweetsFromCollection={this.removeAllTweetsFromCollection}
            />
          </div>
        </div>
      </div>
    );
  }
}

export default Application;
```

现在`Application`组件只有`render()`方法来渲染`Stream`和`Collection`组件。由于它不再管理推文集合，我们也不需要向`Stream`和`Collection`组件传递任何属性。

更新`Application`组件的`render()`函数如下：

```jsx
render() {
  return (
    <div className="container-fluid">
      <div className="row">
        <div className="col-md-4 text-center">
          <Stream/>
        </div>
        <div className="col-md-8">
          <Collection/>
        </div>
      </div>

    </div>
  );
}
```

Flux 架构的采用允许`Stream`组件管理最新的推文，`Collection`组件管理推文集合，而`Application`组件不再需要管理任何东西，因此它成为一个容器组件，用额外的 HTML 标记包装`Stream`和`Collection`组件。

实际上，您可能已经注意到我们当前版本的`Application`组件是成为一个功能性 React 组件的一个很好的候选：

```jsx
import React from ‘react’;
import Stream from ‘./Stream’;
import Collection from ‘./Collection’;

const Application = () =>(
  <div className="container-fluid">
    <div className="row">
      <div className="col-md-4 text-center">
        <Stream />
      </div>
      <div className="col-md-8">
        <Collection />
      </div>
    </div>
  </div>
);

export default Application;
```

我们的`Application`组件现在更简单，其标记看起来更清洁。这提高了组件的可维护性。干得好！

# 重构集合组件

接下来，让我们重构我们的`Collection`组件。用以下内容替换现有的`Collection`组件：

```jsx
import React, { Component } from ‘react’;
import ReactDOMServer from ‘react-dom/server’;
import CollectionControls from ‘./CollectionControls’;
import TweetList from ‘./TweetList’;
import Header from ‘./Header’;
import CollectionUtils from ‘../utils/CollectionUtils’;
import CollectionStore from ‘../stores/CollectionStore’;

class Collection extends Component {
  state = {
    collectionTweets: CollectionStore.getCollectionTweets()
  }

  componentDidMount() {
    CollectionStore.addChangeListener(this.onCollectionChange);
  }

  componentWillUnmount() {
    CollectionStore.removeChangeListener(this.onCollectionChange);
  }

  onCollectionChange = () => {
    this.setState({
      collectionTweets: CollectionStore.getCollectionTweets()
    });
  }

  createHtmlMarkupStringOfTweetList() {
    const htmlString = ReactDOMServer.renderToStaticMarkup(
      <TweetList tweets={this.state.collectionTweets}/>
    );

    const htmlMarkup = {
      html: htmlString
    };

    return JSON.stringify(htmlMarkup);
  }

  render() {
    const { collectionTweets } = this.state;
    const numberOfTweetsInCollection = CollectionUtils
      .getNumberOfTweetsInCollection(collectionTweets);
    let htmlMarkup;

    if (numberOfTweetsInCollection > 0) {
      htmlMarkup = this.createHtmlMarkupStringOfTweetList();

      return (
        <div>
          <CollectionControls
            numberOfTweetsInCollection={numberOfTweetsInCollection}
            htmlMarkup={htmlMarkup}
          />

          <TweetList tweets={collectionTweets} />
        </div>
      );
    }

    return (<Header text="Your collection is empty" />);
  }
}

export default Collection;
```

我们在这里改变了什么？有几件事。首先，我们导入了两个新模块：

```jsx
import CollectionUtils from ‘../utils/CollectionUtils’;
import CollectionStore from ‘../stores/CollectionStore’;
```

我们在第九章中创建了`CollectionUtils`模块，*使用 Jest 测试您的 React 应用程序*，在本章中，我们正在使用它。`CollectionStore`是我们获取数据的地方。

接下来，您应该能够发现这四种方法的熟悉模式：

+   在初始状态下，我们将推文集合设置为`CollectionStore`中存储的内容。您可能还记得`CollectionStore`提供了`getCollectionTweets()`方法来获取其中的数据。

+   在`componentDidMount()`方法中，我们向`CollectionStore`添加`change`事件监听器`this.onCollectionChange`。每当推文集合更新时，`CollectionStore`将调用我们的`this.onCollectionChange`回调函数来通知`Collection`组件该变化。

+   在`componentWillUnmount()`方法中，我们移除了在`componentDidMount()`方法中添加的`change`事件监听器。

+   在`onCollectionChange()`方法中，我们将组件的状态设置为当前存储在`CollectionStore`中的内容。更新组件的状态会触发重新渲染。

`Collection`组件的`render()`方法现在更简单、更清晰：

```jsx
render() {
  const { collectionTweets } = this.state;
  const numberOfTweetsInCollection = CollectionUtils
    .getNumberOfTweetsInCollection(collectionTweets);
  let htmlMarkup;

  if (numberOfTweetsInCollection > 0) {
    htmlMarkup = this.createHtmlMarkupStringOfTweetList();

    return (
      <div>
        <CollectionControls
          numberOfTweetsInCollection={numberOfTweetsInCollection}
          htmlMarkup={htmlMarkup}
        />

        <TweetList tweets={collectionTweets}/>
      </div>
    );
  }

  return (<Header text="Your collection is empty"/>);
}
```

我们使用`CollectionUtils`模块来获取集合中的推文数量，并向子组件`CollectionControls`和`TweetList`传递更少的属性。

# 重构`CollectionControls`组件

`CollectionControls`组件也有一些重大改进。让我们先看一下重构后的版本，然后讨论更新了什么以及为什么更新：

```jsx
import React, { Component } from ‘react’;
import Header from ‘./Header’;
import Button from ‘./Button’;
import CollectionRenameForm from ‘./CollectionRenameForm’;
import CollectionExportForm from ‘./CollectionExportForm’;
import CollectionActionCreators from ‘../actions/CollectionActionCreators’;
import CollectionStore from ‘../stores/CollectionStore’;

class CollectionControls extends Component {
  state = {
    isEditingName: false
  }

  getHeaderText = () => {
    const { numberOfTweetsInCollection } = this.props;
    let text = numberOfTweetsInCollection;
    const name = CollectionStore.getCollectionName();

    if (numberOfTweetsInCollection === 1) {
      text = `${text} tweet in your`;
    } else {
      text = `${text} tweets in your`;
    }

    return (
      <span>
        {text} <strong>{name}</strong> collection
      </span>
    );
  }

  toggleEditCollectionName = () => {
    this.setState(prevState => ({
      isEditingName: !prevState.isEditingName
    }));
  }

  removeAllTweetsFromCollection = () => {
    CollectionActionCreators.removeAllTweetsFromCollection();
  }

  render() {
    const { name, isEditingName } = this.state;
    const onRemoveAllTweetsFromCollection = this.removeAllTweetsFromCollection;
    const { htmlMarkup } = this.props;

    if (isEditingName) {
      return (
        <CollectionRenameForm
          name={name}
          onCancelCollectionNameChange={this.toggleEditCollectionName}
        />
      );
    }

    return (
      <div>
        <Header text={this.getHeaderText()} />

        <Button
          label="Rename collection"
          handleClick={this.toggleEditCollectionName}
        />

        <Button
          label="Empty collection"
          handleClick={onRemoveAllTweetsFromCollection}
        />

        <CollectionExportForm htmlMarkup={htmlMarkup} />
      </div>
    );
  }
}

export default CollectionControls;
```

首先，我们导入另外两个模块：

```jsx
import CollectionActionCreators from ‘../actions/CollectionActionCreators’;
import CollectionStore from ‘../stores/CollectionStore’;
```

注意，我们不再在这个组件中管理集合名称。相反，我们从`CollectionStore`模块中获取它：

```jsx
const name = CollectionStore.getCollectionName();
```

然后，我们进行了一个关键的改变。我们用一个新的`removeAllTweetsFromCollection()`方法替换了`setCollectionName()`方法：

```jsx
removeAllTweetsFromCollection = () => {
  CollectionActionCreators.removeAllTweetsFromCollection();
}
```

当用户点击“清空集合”按钮时，将调用`removeAllTweetsFromCollection()`方法。这个用户操作会触发`removeAllTweetsFromCollection()`动作创建函数，它创建并分发动作到存储中。然后，`CollectionStore`会从集合中删除所有推文并发出`change`事件。

接下来，让我们重构我们的`CollectionRenameForm`组件。

# 重构`CollectionRenameForm`组件

`CollectionRenameForm`是一个受控表单组件。这意味着它的输入值存储在组件的状态中，更新该值的唯一方法是更新组件的状态。它具有应该从`CollectionStore`获取的初始值，所以让我们实现这一点。

首先，导入`CollectionActionCreators`和`CollectionStore`模块：

```jsx
import CollectionActionCreators from ‘../actions/CollectionActionCreators’;
import CollectionStore from ‘../stores/CollectionStore’;
```

现在，我们需要删除它现有的`constructor()`方法：

```jsx
constructor(props) {
  super(props);

  const { name } = props;

  this.state = {
    inputValue: name
  };
}
```

用以下代码替换前面的代码：

```jsx
state = {
  inputValue: CollectionStore.getCollectionName()
}
```

正如你所看到的，唯一的区别是现在我们从`CollectionStore`获取初始的`inputValue`。

接下来，让我们更新`handleFormSubmit()`方法：

```jsx
handleFormSubmit = event => {
  event.preventDefault();

  const { onChangeCollectionName } = this.props;
  const { inputValue: collectionName } = this.state;

  onChangeCollectionName(collectionName);
}
```

用以下代码更新前面的代码：

```jsx
handleFormSubmit = event => {
  event.preventDefault();

  const { onCancelCollectionNameChange } = this.props;
  const { inputValue: collectionName } = this.state;

  CollectionActionCreators.setCollectionName(collectionName);

  onCancelCollectionNameChange();
}
```

这里的重要区别在于，当用户提交表单时，我们将创建一个新的操作，在我们的集合存储中设置一个新的名称：

```jsx
CollectionActionCreators.setCollectionName(collectionName);
```

最后，我们需要在`handleFormCancel()`方法中更改集合名称的来源：

```jsx
handleFormCancel = event => {
  event.preventDefault();

  const {
    name: collectionName,
    onCancelCollectionNameChange
  } = this.props;

  this.setInputValue(collectionName);
  onCancelCollectionNameChange();
}
```

用以下代码替换前面的代码：

```jsx
handleFormCancel = event => {
  event.preventDefault();

  const {
    onCancelCollectionNameChange
  } = this.props;

  const collectionName = CollectionStore.getCollectionName();

  this.setInputValue(collectionName);
  onCancelCollectionNameChange();
}
```

再次，我们从集合存储中获取集合名称：

```jsx
const collectionName = CollectionStore.getCollectionName();
```

这就是我们需要在`CollectionRenameForm`组件中更改的全部内容。让我们接下来重构`TweetList`组件。

# 重构`TweetList`组件

`TweetList`组件渲染了一系列推文。每个推文都是一个`Tweet`组件，用户可以点击以将其从集合中移除。听起来好像它可以利用`CollectionActionCreators`吗？

没错。让我们将`CollectionActionCreators`模块添加到其中：

```jsx
import CollectionActionCreators from ‘../actions/CollectionActionCreators’;
```

然后，我们将创建`removeTweetFromCollection()`回调函数，当用户点击推文图片时将被调用：

```jsx
removeTweetFromCollection = tweet => {
  CollectionActionCreators.removeTweetFromCollection(tweet.id);
}
```

正如您所看到的，它使用`removeTweetFromCollection()`函数创建了一个新的动作，并将推文 ID 作为参数传递给它。

最后，我们需要确保实际调用了`removeTweetFromCollection()`。在`getTweetElement()`方法中，找到以下行：

```jsx
const { tweets, onRemoveTweetFromCollection } = this.props;
```

现在用以下代码替换它：

```jsx
const { tweets } = this.props;
const onRemoveTweetFromCollection = this.removeTweetFromCollection;
```

我们已经完成了这个组件。接下来是我们重构之旅中的`StreamTweet`。

# 重构`StreamTweet`组件

`StreamTweet`渲染了用户可以点击以将其添加到推文集合中的推文图片。您可能已经猜到，当用户点击该推文图片时，我们将创建并分发一个新的动作。

首先，将`CollectionActionCreators`模块导入`StreamTweet`组件：

```jsx
import CollectionActionCreators from ‘../actions/CollectionActionCreators’;
```

然后，在其中添加一个新的`addTweetToCollection()`方法：

```jsx
addTweetToCollection = tweet => {
  CollectionActionCreators.addTweetToCollection(tweet);
}
```

当用户点击推文图片时，应调用`addTweetToCollection()`回调函数。让我们看看`render()`方法中的这行代码：

```jsx
<Tweet
  tweet={tweet}
  onImageClick={onAddTweetToCollection}
/>
```

用以下行代码替换前面的代码：

```jsx
<Tweet
  tweet={tweet}
  onImageClick={this.addTweetToCollection}
/>
```

最后，我们需要替换以下行：

```jsx
const { tweet, onAddTweetToCollection } = this.props; 
```

使用这个代替：

```jsx
const { tweet } = this.props;
```

`StreamTweet`组件现在已经完成。

# 构建和超越

这就是将 Flux 架构集成到我们的 React 应用程序中所需的所有工作。如果您比较一下没有 Flux 的 React 应用程序和有 Flux 的 React 应用程序，您很快就会发现当 Flux 成为其中的一部分时，更容易理解应用程序的工作原理。您可以在[`facebook.github.io/flux/`](https://facebook.github.io/flux/)了解更多关于 Flux 的信息。

我认为现在是检查一切是否正常运行的好时机。让我们构建并运行 Snapterest！

导航到`~/snapterest`并在您的终端窗口中运行以下命令：

```jsx
**npm start**

```

确保您正在运行我们在第二章中安装和配置的 Snapkite Engine 应用程序，*为您的项目安装强大的工具*。现在在您的网络浏览器中打开`~/snapterest/build/index.html`文件。您应该会看到新的推文逐个出现在左侧。单击推文将其添加到右侧出现的收藏中。

它是否有效？检查 JavaScript 控制台是否有任何错误。没有错误？

祝贺您将 Flux 架构整合到我们的 React 应用程序中！

# 总结

在这一章中，我们完成了重构我们的应用程序，以使用 Flux 架构。您了解了将 React 与 Flux 结合使用的要求，以及 Flux 所提供的优势。

在下一章中，我们将使用 Redux 库进一步简化我们应用程序的架构。


# 第十二章：使用 Redux 完善 Flux 应用程序

前一章向您介绍了在 Flux 架构之上构建的完整的 React 应用程序的实现。在本章中，您将对此应用程序进行一些修改，以便它使用 Redux 库来实现 Flux 架构。本章的组织方式如下：

+   Redux 的简要概述

+   实现控制状态的减速器功能

+   构建 Redux 动作创建者

+   将组件连接到 Redux 存储库

+   Redux 进入应用程序状态的入口点

# 为什么选择 Redux？

在开始重构应用程序之前，我们将花几分钟时间高层次地了解 Redux。足够激发您的兴趣。准备好了吗？

## 一切由一个存储库控制

传统 Flux 应用程序和 Redux 之间的第一个主要区别是，使用 Redux 时，您只有一个存储库。传统的 Flux 架构可能也只需要一个存储库，但可能有几个存储库。您可能会认为拥有多个存储库实际上可以简化架构，因为您可以通过应用程序的不同部分分离状态。的确，这是一个不错的策略，但在实践中并不一定成立。创建多个存储库可能会导致混乱。存储库是架构中的移动部件；如果您有更多的存储库，就会有更多的可能出现问题的地方。

Redux 通过只允许一个存储库来消除了这一因素。您可能会认为这会导致一个庞大的数据结构，难以供各种应用程序功能使用。但事实并非如此，因为您可以自由地按照自己的意愿构建存储库。

## 更少的移动部件

通过只允许一个存储库，Redux 将移动部件排除在外。Redux 简化架构的另一个地方是消除了对专用调度程序的需求。在传统的 Flux 架构中，调度程序是一个独立的组件，用于向存储库发送消息。由于 Redux 架构中只有一个存储库，您可以直接将操作分派到存储库。换句话说，存储库就是调度程序。

Redux 在代码中减少移动部件数量的最终位置是事件监听器。在传统的 Flux 应用程序中，您必须手动订阅和取消订阅存储事件，以正确地连接一切。当您可以让一个库处理连接工作时，这会分散注意力。这是 Redux 擅长的事情。

## 使用 Flux 的最佳部分

Redux 并不是传统意义上的 Flux。Flux 有一个规范和一个实现它的库。Redux 不是这样的。正如前面所提到的，Redux 是对 Flux 的简化。它保留了所有导致健壮应用架构的 Flux 概念，同时忽略了那些让 Flux 难以实现和最终难以采用的繁琐部分。

# 用减速器控制状态

Redux 的旗舰概念是，状态由减速器函数控制。在本节中，我们将让你了解减速器是什么，然后实现在你的 Snapterest 应用中的减速器函数。

## 什么是减速器？

减速器是函数，它接受一个数据集合，比如对象或数组，并返回一个新的集合。返回的集合可以包含与初始集合相同的数据，也可以包含完全不同的数据。在 Redux 应用中，减速器函数接受一个状态片段，并返回一个新的状态片段。就是这样！你刚刚学会了 Redux 架构的关键。现在让我们看看减速器函数的实际应用。

Redux 应用中的减速器函数可以分成代表它们所处理的应用状态部分的模块。我们将先看看 Snapterest 应用的集合减速器，然后是推文减速器。

## 集合减速器

现在让我们来看看改变应用状态部分的集合减速器函数。首先，让我们来看看完整的函数：

```jsx
const collectionReducer = (
  state = initialState,
  action
) => {
  let tweet;
  let collectionTweets;

  switch (action.type) {
    case 'add_tweet_to_collection':
      tweet = {};
      tweet[action.tweet.id] = action.tweet;

      return {
        ...state,
        collectionTweets: {
          ...state.collectionTweets,
          ...tweet
        }
      };

    case 'remove_tweet_from_collection':
      collectionTweets = { ...state.collectionTweets };
      delete collectionTweets[action.tweetId];

      return {
        ...state,
        collectionTweets
      };

    case 'remove_all_tweets_from_collection':
      collectionTweets = {};

      return {
        ...state,
        collectionTweets
      };

    case 'set_collection_name':
      return {
        ...state,
        collectionName: state.editingName,
        isEditingName: false
      };

    case 'toggle_is_editing_name':
      return {
        ...state,
        isEditingName: !state.isEditingName
      };

    case 'set_editing_name':
      return {
        ...state,
        editingName: action.editingName
      };

    default:
      return state;
  }
};
```

正如你所看到的，返回的新状态是基于分发的动作。动作名称作为参数提供给这个函数。现在让我们来看看这个减速器的不同情景。

### 将推文添加到集合中

让我们来看看`add_tweet_to_collection`动作：

```jsx
case 'add_tweet_to_collection':
  tweet = {};
  tweet[action.tweet.id] = action.tweet;

  return {
    ...state,
    collectionTweets: {
      ...state.collectionTweets,
      ...tweet
    }
  };
```

`switch`语句检测到`动作类型`是`add_tweet_to_collection`。动作还有一个包含要添加的实际推文的`推文`属性。这里使用`推文`变量来构建一个以`推文`ID 为键，`推文`为值的对象。这是`collectionTweets`对象期望的格式。

然后我们返回新状态。重要的是要记住，这应该始终是一个新对象，而不是对其他对象的引用。这是你在 Redux 应用中避免意外副作用的方法。幸运的是，我们可以使用对象扩展运算符来简化这个任务。

### 从集合中删除推文

从`collectionTweets`对象中删除推文意味着我们必须删除具有要删除的`tweet` ID 的键。让我们看看这是如何完成的：

```jsx
case 'remove_tweet_from_collection':
  collectionTweets = { ...state.collectionTweets };
  delete collectionTweets[action.tweetId];

  return {
    ...state,
    collectionTweets
  };
```

注意我们如何将一个新对象分配给`collectionTweets`变量？再次，扩展运算符在这里非常有用，可以避免额外的语法。我们这样做的原因是为了使减速器始终返回一个新的引用。一旦我们从`collectionTweets`对象中删除推文，我们可以返回包括`collectionTweets`作为属性的新状态对象。

另一个推文删除动作是`remove_all_tweets_from_collection`。以下是它的样子：

```jsx
case 'remove_all_tweets_from_collection':
  collectionTweets = {};

  return {
    ...state,
    collectionTweets
  };
```

删除所有推文意味着我们可以用新的空对象替换`collectionTweets`值。

### 设置集合名称

当一组推文被重命名时，我们必须更新 Redux 存储。这是通过在调度`set_collection_name`动作时从状态中获取`editingName`来完成的：

```jsx
case 'set_collection_name':
  return {
    ...state,
    collectionName: state.editingName,
    isEditingName: false
  };
```

您可以看到`collectionName`值设置为`editingName`，`isEditingName`设置为`false`。这意味着自从值被设置以来，我们知道用户不再编辑名称。

### 编辑集合名称

您刚刚看到了如何在用户保存更改后设置集合名称。但是，当涉及在 Redux 存储中跟踪状态时，编辑文本还有更多内容。首先，我们必须允许文本首先被编辑；这给用户一些视觉提示：

```jsx
case 'toggle_is_editing_name':
  return {
    ...state,
    isEditingName: !state.isEditingName
  };
```

然后，用户正在文本输入中积极输入的文本。这也必须在存储中找到一个位置：

```jsx
case 'set_editing_name':
  return {
    ...state,
    editingName: action.editingName
  };
```

这不仅会导致适当的 React 组件重新渲染，而且意味着我们在状态中存储了文本，当用户完成编辑时可以使用。

## 推文减速器

推文减速器只需要处理一个动作，但这并不意味着我们不应该在推特减速器中单独设置模块，以预期未来的推文动作。现在，让我们专注于我们的应用当前的功能。

### 接收推文

让我们看一下处理`receive_tweet`动作的推文减速器代码：

```jsx
const tweetReducer = (state = null, action) => {
  switch(action.type) {
    case 'receive_tweet':
      return action.tweet;
    default:
      return state;
  }
};
```

这个减速器非常简单。当调度`receive_tweet`动作时，`action.tweet`值将作为新状态返回。由于这是一个小的减速器函数，这可能是指出所有减速器函数共同点的好地方。

传递给 reducer 函数的第一个参数是旧状态。这个参数有一个默认值，因为第一次调用 reducer 时，没有状态，这个值用于初始化它。在这种情况下，默认状态是 null。

关于 reducer 的第二点是，当调用时它们总是返回一个新的状态。即使它不产生任何新的状态，reducer 函数也需要返回旧状态。Redux 会将 reducer 返回的任何内容设置为新状态，即使你返回 undefined。这就是为什么在你的 switch 语句中有一个 `default` 标签是个好主意。

### 简化的 action 创建者

在 Redux 中，action 创建者函数比传统的 Flux 对应函数更简单。主要区别在于 Redux 的 action 创建者函数只返回动作数据。在传统的 Flux 中，action 创建者还负责调用分发器。让我们来看看 Snapterest 的 Redux action 创建者函数。

```jsx
export const addTweetToCollection = tweet => ({
  type: 'add_tweet_to_collection',
  tweet
});

export const removeTweetFromCollection = tweetId => ({
  type: 'remove_tweet_from_collection',
  tweetId
});

export const removeAllTweetsFromCollection = () => ({
  type: 'remove_all_tweets_from_collection'
});

export const setCollectionName = collectionName => ({
  type: 'set_collection_name',
  collectionName
});

export const toggleIsEditingName = () => ({
  type: 'toggle_is_editing_name'
});

export const setEditingName = editingName => ({
  type: 'set_editing_name',
  editingName
});

export const receiveTweet = tweet => ({
  type: 'receive_tweet',
  tweet
});
```

正如你所看到的，这些函数返回动作对象，然后可以被分发——它们实际上并不调用分发器。当我们开始将我们的 React 组件连接到 Redux 存储时，你会明白为什么会这样。在 Redux 应用中，action 创建者函数的主要责任是确保返回一个带有正确 `type` 属性的对象，以及与动作相关的属性。例如，`addTweetToCollection()` action 创建者接受一个 tweet 参数，然后通过将其作为返回对象的属性传递给动作。

# 将组件连接到应用状态

到目前为止，我们有处理创建新应用状态的 reducer 函数，以及触发我们的 reducer 函数的 action 创建者函数。我们仍然需要将我们的 React 组件连接到 Redux 存储。在本节中，您将学习如何使用 `connect()` 函数来创建一个连接到 Redux 存储的新版本组件。

## 将状态和 action 创建者映射到 props

Redux 和 React 集成的想法是告诉 Redux 用一个有状态的组件包装你的组件，当 Redux 存储改变时，它的状态也会被设置。我们所要做的就是编写一个函数，告诉 Redux 我们希望状态值以 props 的形式传递给我们的组件。此外，我们还需要告诉组件它可能想要分发的任何操作。

以下是我们连接组件时将遵循的一般模式：

```jsx
connect(
  mapStateToProps,
  mapDispatchToProps
)(Component);
```

这是它的工作原理的分解：

+   来自 React-Redux 包的`connect()`函数返回一个新的 React 组件。

+   `mapStateToProps()`函数接受一个状态参数，并返回一个基于该状态的属性值的对象。

+   `mapDispatchToProps()`函数接受一个`dispatch()`参数，用于分发操作，并返回一个包含可以分发操作的函数的对象。这些函数被添加到组件的 props 中。

+   `Component`是一个你想要连接到 Redux 存储的 React 组件。

当你开始连接组件时，你很快就会意识到 Redux 正在为你处理许多 React 组件的生命周期琐事。在你通常需要实现`componentDidMount()`功能的地方，突然间，你不需要了。这导致了清晰简洁的 React 组件。

### 连接流组件

让我们来看看`Stream`组件：

```jsx
import React, { Component } from 'react';
import { connect } from 'react-redux';

import StreamTweet from './StreamTweet';
import Header from './Header';
import TweetStore from '../stores/TweetStore';

class Stream extends Component {
  render() {
    const { tweet } = this.props;
    const { onAddTweetToCollection } = this.props;
    const headerText = 'Waiting for public photos from Twitter...';

    if (tweet) {
      return (<StreamTweet tweet={tweet}/>);
    }

    return (<Header text={headerText}/>);
  }
}

const mapStateToProps = ({ tweet }) => ({ tweet });

const mapDispatchToProps = dispatch => ({});

export default connect(
  mapStateToProps,
  mapDispatchToProps
)(Stream);
```

从先前的实现中，`Stream`并没有太多改变。主要区别在于我们删除了一些生命周期方法。所有的 Redux 连接代码都在组件声明之后。`mapStateToProps()`函数从状态中返回`tweet`属性。所以现在我们的组件有了一个`tweet`属性。`mapDispatchToProps()`函数返回一个空对象，因为`Stream`不分发任何操作。当没有操作时，实际上不需要提供这个函数。然而，这可能会在将来发生变化，如果函数已经存在，你只需要向对象添加属性。

### 连接 StreamTweet 组件

`Stream`组件渲染了`StreamTweet`组件，所以让我们接着看下去：

```jsx
import React, { Component } from 'react';
import { connect } from 'react-redux';

import ReactDOM from 'react-dom';
import Header from './Header';
import Tweet from './Tweet';
import store from '../stores';
import { addTweetToCollection } from '../actions';

class StreamTweet extends Component {
  render() {
    const { tweet, onImageClick } = this.props;

    return (
      <section>
        <Header text="Latest public photo from Twitter"/>
        <Tweet
          tweet={tweet}
          onImageClick={onImageClick}
        />
      </section>
    );
  }
}

const mapStateToProps = state => ({});

const mapDispatchToProps = (dispatch, ownProps) => ({
  onImageClick: () => {
    dispatch(addTweetToCollection(ownProps.tweet));
  }
});

export default connect(
  mapStateToProps,
  mapDispatchToProps
)(StreamTweet);
```

`StreamTweet`组件实际上并没有使用 Redux 存储中的任何状态。那么为什么要连接它呢？答案是，这样我们就可以将操作分发函数映射到组件 props 上。记住，在 Redux 应用中，操作创建函数只返回操作对象，而不是分发操作。

在这里的`mapDispatchToProps()`函数中，我们通过将其返回值传递给`dispatch()`来分发一个`addTweetToCollection()`操作。Redux 为我们提供了一个简单的分发函数，它绑定到 Redux 存储。每当我们想要分发一个操作时，我们只需要调用`dispatch()`。现在`StreamTweet`组件将有一个`onImageClick()`函数 prop，可以作为事件处理程序来处理点击事件。

### 连接集合组件

现在我们只需要连接`Collection`组件及其子组件。`Collection`组件的样子如下：

```jsx
import React, { Component } from 'react';
import ReactDOMServer from 'react-dom/server';
import { connect } from 'react-redux';

import CollectionControls from './CollectionControls';
import TweetList from './TweetList';
import Header from './Header';
import CollectionUtils from '../utils/CollectionUtils';

class Collection extends Component {
  createHtmlMarkupStringOfTweetList() {
    const { collectionTweets } = this.props;
    const htmlString = ReactDOMServer.renderToStaticMarkup(
      <TweetList tweets={collectionTweets}/>
    );

    const htmlMarkup = {
      html: htmlString
    };

    return JSON.stringify(htmlMarkup);
  }

  render() {
    const { collectionTweets } = this.props;
    const numberOfTweetsInCollection = CollectionUtils
      .getNumberOfTweetsInCollection(collectionTweets);
    let htmlMarkup;

    if (numberOfTweetsInCollection > 0) {
      htmlMarkup = this.createHtmlMarkupStringOfTweetList();

      return (
        <div>
          <CollectionControls
            numberOfTweetsInCollection={numberOfTweetsInCollection}
            htmlMarkup={htmlMarkup}
          />

          <TweetList tweets={collectionTweets} />
        </div>
      );
    }

    return (<Header text="Your collection is empty"/>);
  }
}

const mapStateToProps = state => state.collection;

const mapDispatchToProps = dispatch => ({});

export default connect(
  mapStateToProps,
  mapDispatchToProps
)(Collection);
```

`Collection`组件不会分发任何操作，因此我们的`mapDispatchToProps()`函数返回一个空对象。但它确实使用了 Redux 存储中的状态，所以我们的`mapStateToProps()`实现返回`state.collection`。这是我们如何将整个应用程序的状态切片成组件关心的部分。例如，如果我们的组件除了`Collection`之外还需要访问其他状态，我们将返回一个由整体状态的不同切片组成的新对象。

### 连接集合控件

在`Collection`组件内，我们有`CollectionControls`组件。让我们看看它连接到 Redux 存储后的样子：

```jsx
import React, { Component } from 'react';
import { connect } from 'react-redux';

import Header from './Header';
import Button from './Button';
import CollectionRenameForm from './CollectionRenameForm';
import CollectionExportForm from './CollectionExportForm';
import {
  toggleIsEditingName,
  removeAllTweetsFromCollection
} from '../actions';

class CollectionControls extends Component {
  getHeaderText = () => {
    const { numberOfTweetsInCollection } = this.props;
    const { collectionName } = this.props;
    let text = numberOfTweetsInCollection;

    if (numberOfTweetsInCollection === 1) {
      text = `${text} tweet in your`;
    } else {
      text = `${text} tweets in your`;
    }

    return (
      <span>
        {text} <strong>{collectionName}</strong> collection
      </span>
    );
  }

  render() {
    const {
      collectionName,
      isEditingName,
      htmlMarkup,
      onRenameCollection,
      onEmptyCollection
    } = this.props;

    if (isEditingName) {
      return (
        <CollectionRenameForm name={collectionName}/>
      );
    }

    return (
      <div>
        <Header text={this.getHeaderText()}/>

        <Button
          label="Rename collection"
          handleClick={onRenameCollection}
        />

        <Button
          label="Empty collection"
          handleClick={onEmptyCollection}
        />

        <CollectionExportForm
          html={htmlMarkup}
          title={collectionName}
        />
      </div>
    );
  }
}

const mapStateToProps = state => state.collection;

const mapDispatchToProps = dispatch => ({
  onRenameCollection: () => {
    dispatch(toggleIsEditingName());
  },
  onEmptyCollection: () => {
    dispatch(removeAllTweetsFromCollection());
  }
});

export default connect(
  mapStateToProps,
  mapDispatchToProps
)(CollectionControls);
```

这一次，我们有一个组件需要从`mapStateToProps()`和`mapDispatchToProps()`中获取对象。我们再次需要将集合状态作为 props 传递给这个组件。`onRenameCollection()`事件处理程序分发`toggleIsEditingName()`操作，而`onEmptyCollection()`事件处理程序分发`removeAllTweetsFromCollection()`操作。

### 连接`TweetList`组件

最后，我们有`TweetList`组件；让我们来看一下：

```jsx
import React, { Component } from 'react';
import { connect } from 'react-redux';

import Tweet from './Tweet';
import { removeTweetFromCollection } from '../actions';

const listStyle = {
  padding: '0'
};

const listItemStyle = {
  display: 'inline-block',
  listStyle: 'none'
};

class TweetList extends Component {
  getListOfTweetIds = () =>
    Object.keys(this.props.tweets);

  getTweetElement = (tweetId) => {
    const {
      tweets,
      onRemoveTweetFromCollection
    } = this.props;
    const tweet = tweets[tweetId];

    return (
      <li style={listItemStyle} key={tweet.id}>
        <Tweet
          tweet={tweet}
          onImageClick={onRemoveTweetFromCollection}
        />
      </li>
    );
  }

  render() {
    const tweetElements = this
      .getListOfTweetIds()
      .map(this.getTweetElement);

    return (
      <ul style={listStyle}>
        {tweetElements}
      </ul>
    );
  }
}

const mapStateToProps = () => ({});

const mapDispatchToProps = dispatch => ({
  onRemoveTweetFromCollection: ({ id }) => {
    dispatch(removeTweetFromCollection(id));
  }
});

export default connect(
  mapStateToProps,
  mapDispatchToProps
)(TweetList);
```

这个组件不依赖 Redux 存储的任何状态。但它确实将一个操作分发函数映射到它的 props。我们不一定需要在这里连接分发器。例如，如果这个组件的父组件正在连接函数到分发器，那么函数可以在那里声明并作为 props 传递到这个组件中。好处是`TweetList`将不再需要 Redux。缺点是在一个组件中声明太多的分发函数。幸运的是，您可以使用任何您认为合适的方法来实现您的组件。

### 创建存储并连接您的应用程序

我们几乎完成了将 Snapterest 应用程序从传统的 Flux 架构重构为基于 Redux 的架构。只剩下两件事要做。

首先，我们必须将我们的减速器函数组合成一个单一的函数，以便创建一个存储：

```jsx
import { combineReducers } from 'redux'
import collection from './collection';
import tweet from './tweet';

const reducers = combineReducers({
  collection,
  tweet
})

export default reducers;
```

这使用`combineReducers()`函数来获取我们两个现有的减速器函数，这些函数存在于它们自己的模块中，并产生一个单一的减速器，我们可以用来创建一个 Redux 存储：

```jsx
import { createStore } from 'redux';
import reducers from '../reducers';

export default createStore(reducers);
```

现在我们创建了 Redux 存储库，其中包含默认情况下由减速器函数提供的初始状态。现在我们只需将此存储库传递给我们的顶层 React 组件：

```jsx
import React from 'react';
import ReactDOM from 'react-dom';
import { Provider } from 'react-redux';

import Application from './components/Application';
import { initializeStreamOfTweets } from './utils/WebAPIUtils';
import store from './stores';

initializeStreamOfTweets(store);

ReactDOM.render(
  <Provider store={store}>
    <Application/>
  </Provider>,
  document.getElementById('react-application')
);
```

`Provider`组件包装了我们的顶层应用程序组件，并为其提供了状态更新，以及任何依赖应用程序状态的子组件。

# 总结

在本章中，您学习了如何使用 Redux 库来完善您的 Flux 架构。Redux 应用程序应该只有一个存储库，动作创建者可以很简单，而减速器函数控制着不可变状态的转换。简而言之，Redux 的目标是减少传统 Flux 架构中通常存在的移动部件的数量，同时保留单向数据流。

然后，您使用 Redux 实现了 Snapterest 应用程序。从减速器开始，每当分派有效动作时，您都会为 Redux 存储库返回一个新状态。然后，您构建了动作创建者函数，返回一个带有正确类型属性的对象。最后，您重构了组件，使它们连接到 Redux。您确保组件可以读取存储库数据并分派动作。

这就是这本书的总结。我希望您已经学会了关于 React 开发基础的足够知识，以便通过学习更高级的 React 主题来继续您的发现之旅。更重要的是，我希望您通过构建令人敬畏的 React 应用程序并使其更加完善，从而更多地了解了 React。
