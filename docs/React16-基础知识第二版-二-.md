# React16 基础知识第二版（二）

> 原文：[`zh.annas-archive.org/md5/3e3e14982ed4c5ebe5505c84fd2fdbb9`](https://zh.annas-archive.org/md5/3e3e14982ed4c5ebe5505c84fd2fdbb9)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：使用 React 组件与另一个库

React 是一个用于构建用户界面的优秀库。如果我们想将其与负责接收数据的另一个库集成呢？在上一章中，我们概述了我们的 Snapterest web 应用程序应该能够执行的五项任务。我们决定其中四项与用户界面有关，但其中一项完全是关于接收数据的：实时从 Snapkite Engine 服务器接收推文。

在本章中，您将学习如何将 React 与外部 JavaScript 库集成，以及 React 组件生命周期方法是什么，同时解决接收数据的重要任务。

# 在您的 React 组件中使用另一个库

正如我们在本书前面讨论过的，我们的 Snapterest web 应用程序将消费实时推文流。在第二章中，*为您的项目安装强大的工具*，您安装了**Snapkite Engine**库，该库连接到 Twitter 流 API，过滤传入的推文，并将它们发送到我们的客户端应用程序。反过来，我们的客户端应用程序需要一种连接到该实时流并监听新推文的方法。

幸运的是，我们不需要自己实现这个功能，因为我们可以重用另一个 Snapkite 模块叫做 `snapkite-stream-client`。让我们安装这个模块:

1.  导航到 `~/snapterest` 目录并运行以下命令:

```jsx
**npm install --save snapkite-stream-client**

```

1.  这将安装 `snapkite-stream-client` 模块，并将其添加到 `package.json` 作为一个依赖项。

1.  现在我们已经准备好在我们的一个 React 组件中重用 `snapkite-stream-client` 模块了。

在上一章中，我们创建了 `Application` 组件，其中包含两个子组件：`Stream` 和 `Collection`。在本章中，我们将创建我们的 `Stream` 组件。

让我们首先创建 `~/snapterest/source/components/Stream.js` 文件:

```jsx
import React, { Component } from 'react';
import SnapkiteStreamClient from 'snapkite-stream-client';
import StreamTweet from './StreamTweet';
import Header from './Header.react';

class Stream extends Component {
  state = {
    tweet: null
  }

  componentDidMount() {
    SnapkiteStreamClient.initializeStream(this.handleNewTweet);
  }

  componentWillUnmount() {
    SnapkiteStreamClient.destroyStream();
  }

  handleNewTweet = (tweet) => {
    this.setState({
      tweet: tweet
    });
  }

  render() {
    const { tweet } = this.state;
    const { onAddTweetToCollection } = this.props; 
    const headerText = 'Waiting for public photos from Twitter...';

    if (tweet) {
      return (
        <StreamTweet
          tweet={tweet}
           onAddTweetToCollection={onAddTweetToCollection}
        />
      );
    }

    return (
      <Header text={headerText}/>
    );
  }
}

export default Stream;
```

首先，我们将导入我们的 `Stream` 组件依赖的以下模块:

+   `React` 和 `ReactDOM`: 这是 React 库的一部分

+   `StreamTweet` 和 `Header`: 这些是 React 组件

+   `snapkite-stream-client`: 这是一个实用库

然后，我们将定义我们的 React 组件。让我们来看看我们的 `Stream` 组件实现了哪些方法:

+   `componentDidMount()`

+   `componentWillUnmount()`

+   `handleNewTweet()`

+   `render()`

我们已经熟悉了 `render()` 方法。`render()` 方法是 React API 的一部分。你已经知道任何 React 组件都必须实现至少 `render()` 方法。让我们来看看我们的 `Stream` 组件的 `render()` 方法：

```jsx
render() {
  const { tweet } = this.state;
  const { onAddTweetToCollection } = this.props;
  const headerText = 'Waiting for public photos from Twitter...';

  if (tweet) {
    return (
      <StreamTweet
        tweet={tweet}
        onAddTweetToCollection={onAddTweetToCollection}
      />
    );
  }

  return (
    <Header text={headerText}/>
  );
}
```

正如你所看到的，我们创建了一个新的 `tweet` 常量，引用了组件状态对象的 `tweet` 属性。然后我们将检查该变量是否引用了一个实际的 `tweet` 对象，如果是，我们的 `render()` 方法将返回 `StreamTweet` 组件，否则返回 `Header` 组件。

`StreamTweet` 组件渲染了一个标题和来自流的最新推文，而 `Header` 组件只渲染了一个标题。

你是否注意到我们的 `Stream` 组件本身并不渲染任何东西，而是返回另外两个实际进行渲染的组件之一？`Stream` 组件的目的是封装我们应用的逻辑，并将渲染委托给其他 React 组件。在 React 中，你应该至少有一个组件来封装你应用的逻辑，并存储和管理你应用的状态。这通常是你组件层次结构中的根组件或高级组件之一。所有其他子 React 组件应尽可能不具有状态。如果你将所有的 React 组件都视为 `Views`，那么我们的 `Stream` 组件就是一个 `ControllerView` 组件。

我们的 `Stream` 组件将接收一个无尽的新推文流，并且需要在每次接收到新推文时重新渲染其子组件。为了实现这一点，我们需要将当前推文存储在组件的状态中。一旦我们更新了它的状态，React 将调用它的 `render()` 方法并重新渲染所有的子组件。为此，我们将实现 `handleNewTweet()` 方法：

```jsx
handleNewTweet = (tweet) => {
  this.setState({
    tweet: tweet
  });
}
```

`handleNewTweet()` 方法接受一个 `tweet` 对象，并将其设置为组件状态的 `tweet` 属性的新值。

新的推文是从哪里来的，什么时候来的？让我们来看看我们的 `componentDidMount()` 方法：

```jsx
componentDidMount() {
  SnapkiteStreamClient.initializeStream(this.handleNewTweet);
}
```

该方法调用 `SnapkiteStreamClient` 对象的 `initializeStream()` 属性，并将 `this.handleNewTweet` 回调函数作为其参数传递。`SnapkiteStreamClient` 是一个外部库，具有我们用来初始化推文流的 API。`this.handleNewTweet` 方法将被调用以处理 `SnapkiteStreamClient` 接收到的每条新推文。

为什么我们将这个方法命名为`componentDidMount()`？其实不是我们命名的，是 React 命名的。事实上，`componentDidMount()`方法是 React API 的一部分。它只被调用一次，在 React 完成组件的初始渲染后立即调用。此时，React 已经创建了一个 DOM 树，由我们的组件表示，现在我们可以使用另一个 JavaScript 库访问该 DOM。

`componentDidMount()`库是将 React 与另一个 JavaScript 库集成的完美场所。这是我们使用外部`SnapkiteStreamClient`库连接到推文流的地方。

现在我们知道了在 React 组件中初始化外部 JavaScript 库的时机，但是反过来呢——我们应该在什么时候取消初始化并清理掉在`componentDidMount()`方法中所做的一切呢？在卸载组件之前清理一切是个好主意。为此，React API 为我们提供了另一个组件生命周期方法——`componentWillUnmount()`：

```jsx
componentWillUnmount() {
  SnapkiteStreamClient.destroyStream();
}
```

`componentWillUnmount()`方法在 React 卸载组件之前被调用。正如你在`componentWillUnmount()`方法中所看到的，你正在调用`SnapkiteStreamClient`对象的`destroyStream()`属性。`destroyStream()`属性清理了我们与`SnapkiteStreamClient`的连接，我们可以安全地卸载我们的`Stream`组件。

你可能想知道组件的生命周期方法是什么，以及为什么我们需要它们。

# 了解 React 组件的生命周期方法

想想 React 组件是做什么的？它描述了要渲染什么。我们知道它使用`render()`方法来实现这一点。然而，有时仅有`render()`方法是不够的，因为如果我们想在组件渲染之前或之后做一些事情怎么办？如果我们想决定是否应该调用组件的`render()`方法呢？

看起来我们描述的是 React 组件被渲染的过程。这个过程有各种阶段，例如在渲染之前，渲染和渲染之后。在 React 中，这个过程被称为**组件的生命周期**。每个 React 组件都经历这个过程。我们想要的是一种方法来连接到这个过程，并在这个过程的不同阶段调用我们自己的函数，以便更好地控制它。为此，React 提供了一些方法，我们可以使用这些方法在组件的生命周期过程的不同阶段得到通知。这些方法被称为**组件的生命周期方法**。它们按照可预测的顺序被调用。

所有 React 组件的生命周期方法可以分为三个阶段：

+   **挂载**：当组件被插入 DOM 时发生

+   **更新**：当组件被重新渲染到虚拟 DOM 中以确定实际 DOM 是否需要更新时发生

+   **卸载**：当组件被从 DOM 中移除时发生：

![理解 React 组件的生命周期方法](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-ess-2e/img/B05915_06_01.jpg)

在 React 的术语中，将组件插入 DOM 称为"挂载"，而将组件从 DOM 中移除称为"卸载"。

了解 React 组件的生命周期方法最好的方法是看它们在实际中的应用。让我们创建我们在本章前面讨论过的`StreamTweet`组件。这个组件将实现大部分 React 的生命周期方法。

导航到`~/snapterest/source/components/`并创建`StreamTweet.js`文件：

```jsx
import React, { Component } from 'react';
import Header from './Header';
import Tweet from './Tweet';

class StreamTweet extends Component {

  // define other component lifecycle methods here

  render() {
    console.log('[Snapterest] StreamTweet: Running render()');

    const { headerText } = this.state;
    const { tweet, onAddTweetToCollection } = this.props;

    return (
      <section>
        <Header text={headerText} />
        <Tweet
          tweet={tweet}
          onImageClick={onAddTweetToCollection}
        />
      </section>
    );
  }
}

export default StreamTweet;
```

正如你所看到的，`StreamTweet`组件除了`render()`之外还没有生命周期方法。随着我们的进展，我们将逐一创建并讨论它们。

这四种方法在组件的*挂载*阶段被调用，如下图所示：

![理解 React 组件的生命周期方法](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-ess-2e/img/B05915_06_02.jpg)

正如你从前面的图中所看到的，被调用的方法如下：

+   构造函数()

+   componentWillMount()

+   render()

+   componentDidMount()

在本章中，我们将讨论这四种方法中的两种（除了`render()`）。它们在组件插入 DOM 时只被调用一次。让我们更仔细地看看每一个。

## 挂载方法

现在让我们看一些有用的挂载方法。

### componentWillMount 方法

`componentWillMount()`方法被第二次调用。它在 React 将组件插入 DOM 之前*立即*调用。在您的`StreamTweet`组件的`constructor()`方法之后立即添加此代码：

```jsx
componentWillMount() {
  console.log('[Snapterest] StreamTweet: 1\. Running componentWillMount()');

  this.setState({
    numberOfCharactersIsIncreasing: true,
    headerText: 'Latest public photo from Twitter'
  });

  window.snapterest = {
    numberOfReceivedTweets: 1,
    numberOfDisplayedTweets: 1
  };
}
```

在此方法中，我们做了许多事情。首先，我们记录了调用此方法的事实。实际上，为了演示目的，我们将记录此组件的每个生命周期方法。当您在 Web 浏览器中运行此代码时，应该能够打开 JavaScript 控制台，并看到这些日志消息按预期的升序打印出来。

接下来，我们使用`this.setState()`方法更新组件的状态：

+   将`numberOfCharactersIsIncreasing`属性设置为`true`

+   将`headerText`属性设置为“来自 Twitter 的最新公共照片”

因为这是此组件将呈现的第一条推文，我们知道字符数肯定是从零增加到第一条推文中的字符数。因此，我们将其设置为`true`。我们还将默认文本分配给我们的标题，“来自 Twitter 的最新公共照片”。

如您所知，调用`this.setState()`方法应该触发组件的`render()`方法，因此在组件的挂载阶段似乎会调用两次`render()`。但是，在这种情况下，React 知道尚未呈现任何内容，因此它只会调用一次`render()`方法。

最后，在此方法中，我们使用以下两个属性定义了一个`snapterest`全局对象：

+   接收到的推文数量：此属性计算所有接收到的推文的数量

+   `numberOfDisplayedTweets`：此属性计算仅显示的推文的数量

我们将`numberOfReceivedTweets`设置为`1`，因为我们知道`componentWillMount()`方法仅在接收到第一条推文时调用一次。我们还知道我们的`render()`方法将为这条第一条推文调用，因此我们也将`numberOfDisplayedTweets`设置为`1`：

```jsx
window.snapterest = {
  numberOfReceivedTweets: 1,
  numberOfDisplayedTweets: 1
};
```

这个全局对象不是 React 或我们的 Web 应用程序逻辑的一部分；我们可以删除它，一切仍将按预期工作。在前面的代码中，`window.snapterest`是一个方便的工具，用于跟踪我们在任何时间点处理了多少推文。我们仅出于演示目的使用全局`window.snapterest`对象。我强烈建议您不要在实际项目中向全局对象添加自己的属性，因为您可能会覆盖现有属性，和/或您的属性可能会被稍后由您不拥有的其他 JavaScript 代码覆盖。稍后，如果您决定将 Snapterest 部署到生产环境中，请确保删除全局`window.snapterest`对象以及与`StreamTweet`组件相关的代码。

在网络浏览器中查看 Snapterest 几分钟后，您可以打开 JavaScript 控制台并输入`snapterest.numberOfReceivedTweets`和`snapterest.numberOfDisplayedTweets`命令。这些命令将输出数字，帮助您更好地了解新推文的到达速度以及有多少推文未被显示。在我们的下一个组件生命周期方法中，我们将向`window.snapterest`对象添加更多属性。

### componentDidMount 方法

`componentDidMount()`方法在 React 将组件插入 DOM 后*立即*调用。更新后的 DOM 现在可以访问，这意味着这个方法是初始化其他需要访问该 DOM 的 JavaScript 库的最佳位置。

在本章的早些时候，我们使用了`componentDidMount()`方法创建了我们的`Stream`组件，该方法初始化了外部的`snapkite-stream-client` JavaScript 库。

让我们来看看这个组件的`componentDidMount()`方法。在`componentWillMount()`方法之后，向您的`StreamTweet`组件添加以下代码：

```jsx
componentDidMount = () => {
  console.log('[Snapterest] StreamTweet: 3\. Running componentDidMount()');

  const componentDOMRepresentation = ReactDOM.findDOMNode(this);

  window.snapterest.headerHtml = componentDOMRepresentation.children[0].outerHTML;
  window.snapterest.tweetHtml = componentDOMRepresentation.children[1].outerHTML;
}
```

在这里，我们使用`ReactDOM.findDOMNode()`方法引用表示我们的`StreamTweet`组件的 DOM。我们传递`this`参数，引用当前组件（在本例中为`StreamTweet`）。`componentDOMRepresentation`常量引用了我们可以遍历的 DOM 树，从而访问其各种属性。为了更好地了解这个 DOM 树的样子，让我们更仔细地看一下我们的`StreamTweet`组件的`render()`方法：

```jsx
render() {
  console.log('[Snapterest] StreamTweet: Running render()');

  const { headerText } = this.state;
  const { tweet, onAddTweetToCollection } = this.props;

  return (
    <section>
      <Header text={headerText} />
      <Tweet
        tweet={tweet}
        onImageClick={onAddTweetToCollection}
      />
    </section>
  );
}
```

使用 JSX 的最大好处之一是，我们可以通过查看组件的`render()`方法轻松地确定组件将有多少子元素。在这里，我们可以看到父`<section>`元素有两个子组件：`<Header/>`和`<Tweet/>`。

因此，当我们使用 DOM API 的`children`属性遍历生成的 DOM 树时，我们可以确保它也将有两个子元素：

+   `componentDOMRepresentation.children[0]`：这是我们`<Header />`组件的 DOM 表示

+   `componentDOMRepresentation.children[1]`：这是我们`<Tweet />`组件的 DOM 表示

每个元素的`outerHTML`属性都会得到表示该元素 DOM 树的 HTML 字符串。我们将这个 HTML 字符串分配给我们的全局`window.snapterest`对象，以方便起见，正如我们在本章前面讨论过的那样。

如果您正在使用其他 JavaScript 库，例如**jQuery**，以及 React 一起使用，则可以使用`componentDidMount()`方法作为集成两者的机会。如果您想发送 AJAX 请求，或者使用`setTimeout()`或`setInterval()`函数设置定时器，那么您也可以在这个方法中执行。一般来说，`componentDidMount()`应该是您首选的组件生命周期方法，用于将 React 库与非 React 库和 API 集成。

到目前为止，在本章中，您已经学会了 React 组件提供给我们的基本挂载方法。我们在`StreamTweet`组件中使用了所有三种方法。我们还讨论了`StreamTweet`组件的`render()`方法。这就是我们需要了解的所有内容，以了解 React 将如何最初渲染`StreamTweet`组件。在其第一次渲染时，React 将执行以下方法序列：

+   `componentWillMount()`

+   `render()`

+   `componentDidMount()`

这被称为 React 组件的**挂载阶段**。它只执行一次，除非我们卸载一个组件并再次挂载它。

接下来，让我们讨论 React 组件的**卸载阶段**。

## 卸载方法

现在让我们来看一下流行的卸载方法之一。

### `componentWillUnmount`方法

React 仅为此阶段提供了一种方法，即`componentWillUnmount()`。它在 React 从 DOM 中移除组件并销毁之前立即调用。此方法对清理在组件挂载或更新阶段创建的任何数据非常有用。这正是我们在`StreamTweet`组件中所做的。在`componentDidMount()`方法之后，将此代码添加到您的`StreamTweet`组件中：

```jsx
componentWillUnmount() {
  console.log('[Snapterest] StreamTweet: 8\. Running componentWillUnmount()');

  delete window.snapterest;
}
```

在`componentWillUnmount()`方法中，我们使用`delete`运算符删除全局的`window.snapterest`对象：

```jsx
delete window.snapterest;
```

删除`window.snapterest`将保持我们的全局对象清洁。如果您在`componentDidMount()`方法中创建了任何其他 DOM 元素，则`componentWillUnmount()`方法是删除它们的好地方。您可以将`componentDidMount()`和`componentWillUnmount()`方法视为将 React 组件与另一个 JavaScript API 集成的两步机制。

1.  在`componentDidMount()`方法中初始化它。

1.  在`componentWillUnmount()`方法中终止它。

通过这种方式，需要与 DOM 一起工作的外部 JavaScript 库将与 React 渲染的 DOM 保持同步。

这就是我们需要知道的有关有效卸载 React 组件的全部内容。

# 总结

在本章中，我们创建了我们的`Stream`组件，并学习了如何将 React 组件与外部 JavaScript 库集成。您还了解了 React 组件的生命周期方法。我们还着重讨论了挂载和卸载方法，并开始实现`StreamTweet`组件。

在我们的下一章中，我们将看一下组件生命周期的更新方法。我们还将实现我们的`Header`和`Tweet`组件，并学习如何设置组件的默认属性。


# 第七章：更新您的 React 组件

在上一章中，您已经了解到 React 组件可以经历三个阶段：

+   挂载

+   更新

+   卸载

我们已经讨论了挂载和卸载阶段。在本章中，我们将专注于更新阶段。在此阶段，React 组件已经插入到 DOM 中。这个 DOM 代表了组件的当前状态，当状态发生变化时，React 需要评估新状态将如何改变先前呈现的 DOM。

React 为我们提供了影响更新期间将要呈现的内容以及了解更新发生时的方法。这些方法允许我们控制从当前组件状态到下一个组件状态的过渡。让我们更多地了解 React 组件更新方法的强大性质。

# 理解组件生命周期更新方法

React 组件有五个生命周期方法属于组件的*更新*阶段：

+   `componentWillReceiveProps()`

+   `shouldComponentUpdate()`

+   `componentWillUpdate()`

+   `render()`

+   `componentDidUpdate()`

请参见以下图以获得更好的视图：

![理解组件生命周期更新方法](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-ess-2e/img/B05915_07_01.jpg)

您已经熟悉了`render()`方法。现在让我们讨论其他四种方法。

## componentWillReceiveProps 方法

我们将从`StreamTweet`组件中的`componentWillReceiveProps()`方法开始。在`StreamTweet.js`文件的`componentDidMount()`方法之后添加以下代码：

```jsx
componentWillReceiveProps(nextProps) {
  console.log('[Snapterest] StreamTweet: 4\. Running componentWillReceiveProps()');

  const { tweet: currentTweet } = this.props;
  const { tweet: nextTweet } = nextProps;

  const currentTweetLength = currentTweet.text.length;
  const nextTweetLength = nextTweet.text.length;
  const isNumberOfCharactersIncreasing = (nextTweetLength > currentTweetLength);
  let headerText;

  this.setState({
    numberOfCharactersIsIncreasing: isNumberOfCharactersIncreasing
  });

  if (isNumberOfCharactersIncreasing) {
    headerText = 'Number of characters is increasing';
  } else {
    headerText = 'Latest public photo from Twitter';
  }

  this.setState({
    headerText
  });

  window.snapterest.numberOfReceivedTweets++;
}
```

这个方法首先在组件生命周期的更新阶段被调用。当组件从其父组件接收新属性时，它被调用。

这个方法是一个机会，让我们使用`this.props`对象比较当前组件的属性和使用`nextProps`对象比较下一个组件的属性。基于这个比较，我们可以选择使用`this.setState()`函数来更新组件的状态，在这种情况下不会触发额外的渲染。

让我们看看它的实际应用：

```jsx
const { tweet: currentTweet } = this.props;
const { tweet: nextTweet } = nextProps;

const currentTweetLength = currentTweet.text.length;
const nextTweetLength = nextTweet.text.length;
const isNumberOfCharactersIncreasing = (nextTweetLength > currentTweetLength);
let headerText;

this.setState({
  numberOfCharactersIsIncreasing: isNumberOfCharactersIncreasing
});
```

我们首先获取当前推文和下一条推文的长度。当前推文可以通过`this.props.tweet`获得，下一条推文可以通过`nextProps.tweet`获得。然后，我们通过检查下一条推文是否比当前推文更长来比较它们的长度。比较的结果存储在`isNumberOfCharactersIncreasing`变量中。最后，我们通过将`numberOfCharactersIsIncreasing`属性设置为`isNumberOfCharactersIncreasing`变量的值来更新组件的状态。

然后我们将我们的标题文本设置如下：

```jsx
if (isNumberOfCharactersIncreasing) {
  headerText = 'Number of characters is increasing';
} else {
  headerText = 'Latest public photo from Twitter';
}

this.setState({
  headerText
});
```

如果下一条推文更长，我们将把标题文本设置为`'字符数正在增加'`，否则，我们将把它设置为`'来自 Twitter 的最新公共照片'`。然后，我们通过将`headerText`属性设置为`headerText`变量的值来再次更新组件的状态。

请注意，在我们的`componentWillReceiveProps()`方法中调用了`this.setState()`函数两次。这是为了说明一个观点，即无论在`componentWillReceiveProps()`方法中调用`this.setState()`多少次，都不会触发该组件的额外渲染。React 进行了内部优化，将状态更新批处理在一起。

由于`componentWillReceiveProps()`方法将为`StreamTweet`组件接收到的每条新推文调用一次，因此它是一个很好的地方来计算接收到的推文总数：

```jsx
window.snapterest.numberOfReceivedTweets++;
```

现在我们知道如何检查下一条推文是否比我们当前显示的推文更长，但是我们如何选择根本不渲染下一条推文呢？

## shouldComponentUpdate 方法

`shouldComponentUpdate()`方法允许我们决定下一个组件状态是否应该触发组件的重新渲染。该方法返回一个布尔值，默认为`true`，但您可以返回`false`，那么以下组件方法将不会被调用：

+   `componentWillUpdate()`

+   `render()`

+   `componentDidUpdate()`

跳过对组件的`render()`方法的调用将阻止该组件重新渲染，从而提高应用程序的性能，因为不会进行额外的 DOM 变化。

这个方法在组件生命周期的更新阶段中第二次被调用。

这个方法非常适合我们防止显示下一条推文长度为一或更少字符。在`componentWillReceiveProps()`方法之后，将此代码添加到`StreamTweet`组件中：

```jsx
shouldComponentUpdate(nextProps, nextState) {
  console.log('[Snapterest] StreamTweet: 5\. Running shouldComponentUpdate()');

  return (nextProps.tweet.text.length > 1);
}
```

如果下一个 tweet 的长度大于 1，则 `shouldComponentUpdate()` 返回 `true`，并且 `StreamTweet` 组件渲染下一个 tweet。否则，它返回 `false`，并且 `StreamTweet` 组件不渲染下一个状态。

## `componentWillUpdate` 方法

`componentWillUpdate()` 方法在 React 更新 DOM *之前立即* 被调用。它接收以下两个参数：

+   `nextProps`: 下一个属性对象

+   `nextState`: 下一个状态对象

您可以使用这些参数来准备 DOM 更新。但是，您不能在 `componentWillUpdate()` 方法中使用 `this.setState()`。如果您想要在响应属性更改时更新组件的状态，则在 `componentWillReceiveProps()` 方法中执行此操作，React 在属性更改时会调用该方法。

为了演示 `componentWillUpdate()` 方法何时被调用，我们需要在 `StreamTweet` 组件中记录它。在 `shouldComponentUpdate()` 方法之后添加以下代码：

```jsx
componentWillUpdate(nextProps, nextState) {
  console.log('[Snapterest] StreamTweet: 6\. Running componentWillUpdate()');
}
```

在调用 `componentWillUpdate()` 方法后，React 调用执行 DOM 更新的 `render()` 方法。然后，调用 `componentDidUpdate()` 方法。

## `componentDidUpdate` 方法

`componentDidUpdate()` 方法在 React 更新 DOM *之后立即* 被调用。它接收这两个参数：

+   `prevProps`: 先前的属性对象

+   `prevState`: 先前的状态对象

我们将使用这个方法与更新后的 DOM 进行交互或执行任何后渲染操作。在我们的 `StreamTweet` 组件中，我们将使用 `componentDidUpdate()` 来增加全局对象中显示的推文数量。在 `componentWillUpdate()` 方法之后添加以下代码：

```jsx
componentDidUpdate(prevProps, prevState) {
  console.log('[Snapterest] StreamTweet: 7\. Running componentDidUpdate()');

  window.snapterest.numberOfDisplayedTweets++;
}
```

在调用 `componentDidUpdate()` 后，更新周期结束。当组件的状态更新或父组件传递新属性时，会启动新的周期。或者当您调用 `forceUpdate()` 方法时，它会触发新的更新周期，但会跳过触发更新的组件上的 `shouldComponentUpdate()` 方法。然而，`shouldComponentUpdate()` 会按照通常的更新阶段在所有子组件上调用。尽量避免使用 `forceUpdate()` 方法；这将提高应用程序的可维护性。

这结束了我们对 React 组件生命周期方法的讨论。

# 设置默认的 React 组件属性

正如您从上一章所知，我们的 `StreamTweet` 组件渲染了两个子组件：`Header` 和 `Tweet`。

让我们创建这些组件。要做到这一点，导航到`~/snapterest/source/components/`并创建`Header.js`文件：

```jsx
import React from 'react';

export const DEFAULT_HEADER_TEXT = 'Default header';

const headerStyle = {
  fontSize: '16px',
  fontWeight: '300',
  display: 'inline-block',
  margin: '20px 10px'
};

class Header extends React.Component {

  render() {
    const { text } = this.props;

    return (
      <h2 style={headerStyle}>{text}</h2>
    );
  }
}

Header.defaultProps = {
  text: DEFAULT_HEADER_TEXT
};

export default Header;
```

正如您所看到的，我们的`Header`组件是一个无状态组件，渲染`h2`元素。标题文本作为`this.props.text`属性从父组件传递，这使得该组件灵活，可以在需要标题的任何地方重用。我们稍后将在本书中再次重用此组件。

注意`h2`元素有一个`style`属性。

在 React 中，我们可以在 JavaScript 对象中定义 CSS 规则，然后将该对象作为值传递给 React 元素的`style`属性。例如，在这个组件中，我们定义了`headerStyle`变量，引用了一个对象，其中：

+   每个对象键都是一个 CSS 属性。

+   每个对象值都是一个 CSS 值。

包含连字符的 CSS 属性应转换为**驼峰式**风格；例如，`font-size`变成`fontSize`，`font-weight`变成`fontWeight`。

将 CSS 规则定义在 React 组件内部的优势如下：

+   **可移植性**：您可以轻松地共享一个组件以及其样式，全部在一个 JavaScript 文件中。

+   **封装性**：内联样式可以限制其影响范围。

+   **灵活性**：CSS 规则可以使用 JavaScript 的强大功能进行计算。

使用这种技术的一个显著缺点是**内容安全策略**（**CSP**）可能会阻止内联样式产生任何效果。您可以在[`developer.mozilla.org/en-US/docs/Web/HTTP/CSP`](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)了解更多关于 CSP 的信息。

我们的`Header`组件有一个我们尚未讨论的属性，即`defaultProps`。如果忘记传递一个 React 组件依赖的属性会怎么样？在这种情况下，组件可以使用`defaultProps`属性设置默认属性；请考虑以下示例：

```jsx
Header.defaultProps = {
  text: DEFAULT_HEADER_TEXT
};
```

在这个例子中，我们将`text`属性的默认值设置为`'Default header'`。如果父组件传递了`this.props.text`属性，那么它将覆盖默认值。

接下来，让我们创建我们的`Tweet`组件。要做到这一点，导航到`~/snapterest/source/components/`并创建`Tweet.js`文件：

```jsx
import React from 'react';
import PropTypes from 'prop-types';

const tweetStyle = {
  position: 'relative',
  display: 'inline-block',
  width: '300px',
  height: '400px',
  margin: '10px'
};

const imageStyle = {
  maxHeight: '400px',
  maxWidth: '100%',
  boxShadow: '0px 1px 1px 0px #aaa',
  border: '1px solid #fff'
};

class Tweet extends React.Component {
  handleImageClick() {
    const { tweet, onImageClick } = this.props;

    if (onImageClick) {
      onImageClick(tweet);
    }
  }

  render() {
    const { tweet } = this.props;
    const tweetMediaUrl = tweet.media[0].url;

    return (
      <div style={tweetStyle}>
        <img
          src={tweetMediaUrl}
          onClick={this.handleImageClick}
          style={imageStyle}
        />
      </div>
    );
  }
}

Tweet.propTypes = {
  tweet: (properties, propertyName, componentName) => {
    const tweet = properties[propertyName];

    if (! tweet) {
      return new Error('Tweet must be set.');
    }

    if (! tweet.media) {
      return new Error('Tweet must have an image.');
    }
  },
  onImageClick: PropTypes.func
};

export default Tweet;
```

该组件渲染一个带有子`<img>`元素的`<div>`元素。这两个元素都有内联样式，而`<img>`元素有一个点击事件处理程序，即`this.handleImageClick`。

```jsx
handleImageClick() {
  const { tweet, onImageClick } = this.props;

  if (onImageClick) {
    onImageClick(tweet);
  }
}
```

当用户点击推文的图片时，`Tweet`组件会检查父组件是否将`this.props.onImageClick`回调函数作为属性传递，并调用该函数。`this.props.onImageClick`属性是一个可选的`Tweet`组件属性，因此我们需要检查它是否被传递才能使用它。另一方面，`tweet`是一个必需的属性。

我们如何确保组件接收到所有必需的属性？

# 验证 React 组件属性

在 React 中，有一种方法可以使用组件的`propTypes`对象来验证组件属性：

```jsx
Component.propTypes = {
  propertyName: validator
};
```

在此对象中，您需要指定属性名称和验证函数，该函数将确定属性是否有效。React 为您提供了一些预定义的验证器供您重用。它们都在`prop-types`包的`PropTypes`对象中可用：

+   `PropTypes.number`：这将验证属性是否是数字

+   `PropTypes.string`：这将验证属性是否是字符串

+   `PropTypes.bool`：这将验证属性是否是布尔值

+   `PropTypes.object`：这将验证属性是否是对象

+   `PropTypes.element`：这将验证属性是否是 React 元素

要获取`PropTypes`验证器的完整列表，您可以在[`facebook.github.io/react/docs/typechecking-with-proptypes.html`](https://facebook.github.io/react/docs/typechecking-with-proptypes.html)上查看文档。

默认情况下，您使用`PropTypes`验证器验证的所有属性都是可选的。您可以将它们中的任何一个与`isRequired`链接在一起，以确保在属性丢失时在 JavaScript 控制台上显示警告消息：

```jsx
Component.propTypes = {
  propertyName: PropTypes.number.isRequired
};
```

您还可以指定自己的自定义验证器函数，如果验证失败，应该返回一个`Error`对象：

```jsx
Component.propTypes = {
  propertyName(properties, propertyName, componentName) {
    // ... validation failed
    return new Error('A property is not valid.');
  }
};
```

让我们看看我们`Tweet`组件中的`propTypes`对象：

```jsx
Tweet.propTypes = {
  tweet(properties, propertyName, componentName) {
    const tweet = properties[propertyName];

    if (!tweet) {
      return new Error('Tweet must be set.');
    }

    if (!tweet.media) {
      return new Error('Tweet must have an image.');
    }
  },
  onImageClick: PropTypes.func
};
```

如您所见，我们正在验证两个`Tweet`组件属性：`tweet`和`onImageClick`。

我们使用自定义验证器函数来验证`tweet`属性。React 向此函数传递三个参数：

+   `properties`：这是组件属性对象

+   `propertyName`：这是我们正在验证的属性的名称

+   `componentName`：这是组件的名称

我们首先检查我们的`Tweet`组件是否收到了`tweet`属性：

```jsx
const tweet = properties[propertyName];

if (!tweet) {
  return new Error('Tweet must be set.');
}
```

然后，我们假设`tweet`属性是一个对象，并检查该对象是否没有`media`属性：

```jsx
if (!tweet.media) {
  return new Error('Tweet must have an image.');
}
```

这两个检查都返回一个`Error`对象，将在 JavaScript 控制台中记录。

我们将验证另一个`Tweet`组件的属性`onImageClick`：

```jsx
onImageClick: PropTypes.func
```

我们验证`onImageClick`属性的值是否为函数。在这种情况下，我们重用了`PropTypes`对象提供的验证函数。正如您所看到的，`onImageClick`是一个可选属性，因为我们没有添加`isRequired`。

最后，出于性能原因，`propTypes`仅在 React 的开发版本中进行检查。

# 创建一个 Collection 组件

您可能还记得我们的最顶层层次结构`Application`组件有两个子组件：`Stream`和`Collection`。

到目前为止，我们已经讨论并实现了我们的`Stream`组件及其子组件。接下来，我们将专注于我们的`Collection`组件。

创建`~/snapterest/source/components/Collection.js`文件：

```jsx
import React, { Component } from 'react';
import ReactDOMServer from 'react-dom/server';
import CollectionControls from './CollectionControls';
import TweetList from './TweetList';
import Header from './Header';

class Collection extends Component {
  createHtmlMarkupStringOfTweetList = () => {
    const { tweets } = this.props;

    const htmlString = ReactDOMServer.renderToStaticMarkup(
      <TweetList tweets={tweets} />
    );

    const htmlMarkup = {
      html: htmlString
    };

    return JSON.stringify(htmlMarkup);
  }

  getListOfTweetIds = () =>
    Object.keys(this.props.tweets)

  getNumberOfTweetsInCollection = () =>
    this.getListOfTweetIds().length

  render() {
    const numberOfTweetsInCollection = this.getNumberOfTweetsInCollection();

    if (numberOfTweetsInCollection > 0) {
      const {
        tweets,
        onRemoveAllTweetsFromCollection,
        onRemoveTweetFromCollection
      } = this.props;

      const htmlMarkup = this.createHtmlMarkupStringOfTweetList();

      return (
        <div>
          <CollectionControls
            numberOfTweetsInCollection={numberOfTweetsInCollection}
            htmlMarkup={htmlMarkup}
            onRemoveAllTweetsFromCollection={onRemoveAllTweetsFromCollection}
          />

          <TweetList
            tweets={tweets}
            onRemoveTweetFromCollection={onRemoveTweetFromCollection}
          />

        </div>
      );
    }

    return <Header text="Your collection is empty"/>;
  }
}

export default Collection;
```

我们的`Collection`组件负责渲染两件事：

+   用户收集的推文

+   用于操作该收藏的用户界面控制元素

让我们来看看组件的`render()`方法：

```jsx
render() {
  const numberOfTweetsInCollection = this.getNumberOfTweetsInCollection();

  if (numberOfTweetsInCollection > 0) {
    const {
      tweets,
      onRemoveAllTweetsFromCollection,
      onRemoveTweetFromCollection
    } = this.props;

    const htmlMarkup = this.createHtmlMarkupStringOfTweetList();

    return (
      <div>
        <CollectionControls
          numberOfTweetsInCollection={numberOfTweetsInCollection}
          htmlMarkup={htmlMarkup}
          onRemoveAllTweetsFromCollection={onRemoveAllTweetsFromCollection}
        />

        <TweetList
          tweets={tweets}
          onRemoveTweetFromCollection={onRemoveTweetFromCollection}
        />

      </div>
    );
  }

  return <Header text="Your collection is empty"/>;
}
```

我们首先使用`this.getNumberOfTweetsInCollection()`方法获取收藏中的推文数量：

```jsx
getNumberOfTweetsInCollection = () =>this.getListOfTweetIds().length
```

这种方法又使用另一种方法来获取推文 ID 列表：

```jsx
getListOfTweetIds = () => Object.keys(this.props.tweets);
```

`this.getListOfTweetIds()`函数调用返回一个推文 ID 数组，然后`this.getNumberOfTweetsInCollection()`返回该数组的长度。

在我们的`render()`方法中，一旦我们知道收藏中的推文数量，我们必须做出选择：

+   如果收藏*不*为空，则渲染`CollectionControls`和`TweetList`组件

+   否则，渲染`Header`组件

所有这些组件都渲染什么？

+   `CollectionControls`组件渲染一个带有收藏名称和一组按钮的标题，允许用户重命名、清空和导出收藏

+   `TweetList`组件渲染推文列表

+   `Header`组件只是渲染一个消息头，说明收藏是空的

想法是只有在收藏不为空时才显示收藏。在这种情况下，我们创建了四个变量：

```jsx
const {
  tweets,
  onRemoveAllTweetsFromCollection,
  onRemoveTweetFromCollection
} = this.props;

const htmlMarkup = this.createHtmlMarkupStringOfTweetList();
```

+   `tweets`变量引用了我们从父组件传递的`tweets`属性

+   `htmlMarkup`变量引用了组件的`this.createHtmlMarkupStringOfTweetList()`函数调用返回的字符串

+   `onRemoveAllTweetsFromCollection`和`onRemoveTweetFromCollection`变量引用了从父组件传递的函数

正如其名称所示，`this.createHtmlMarkupStringOfTweetList()`方法创建一个代表通过渲染`TweetList`组件创建的 HTML 标记的字符串：

```jsx
createHtmlMarkupStringOfTweetList = () => {
  const { tweets } = this.props;

  const htmlString = ReactDOMServer.renderToStaticMarkup(
    <TweetList tweets={tweets}/>
  );

  const htmlMarkup = {
    html: htmlString
  };

  return JSON.stringify(htmlMarkup);
}
```

`createHtmlMarkupStringOfTweetList()`方法使用了我们在第三章中讨论过的`ReactDOMServer.renderToStaticMarkup()`函数，*创建你的第一个 React 元素*。我们将`TweetList`组件作为其参数传递：

```jsx
const htmlString = ReactDOMServer.renderToStaticMarkup(
  <TweetList tweets={tweets} />
);
```

这个`TweetList`组件有一个`tweets`属性，引用了父组件传递的`tweets`属性。

`ReactDOMServer.renderToStaticMarkup()`函数产生的结果 HTML 字符串存储在`htmlString`变量中。然后，我们创建一个新的`htmlMarkup`对象，其`html`属性引用了我们的`htmlString`变量。最后，我们使用`JSON.stringify()`函数将我们的`htmlMarkup` JavaScript 对象转换为 JSON 字符串。`JSON.stringify(htmlMarkup)`函数调用的结果就是我们的`createHtmlMarkupStringOfTweetList()`方法返回的内容。

这个方法展示了 React 组件有多么灵活；你可以使用相同的 React 组件来渲染 DOM 元素，也可以生成一个 HTML 标记字符串，可以传递给第三方 API。

另一个有趣的观察是在`render()`方法之外使用 JSX 语法。事实上，你可以在源文件的任何地方使用 JSX，甚至在组件类声明之外。

让我们更仔细地看一下当我们的集合*不*为空时，`Collection`组件返回了什么：

```jsx
return (
  <div>
    <CollectionControls
      numberOfTweetsInCollection={numberOfTweetsInCollection}
      htmlMarkup={htmlMarkup}
      onRemoveAllTweetsFromCollection={onRemoveAllTweetsFromCollection}
    />

    <TweetList
      tweets={tweets}
      onRemoveTweetFromCollection={onRemoveTweetFromCollection}
    />

  </div>
);
```

我们将`CollectionControls`和`TweetList`组件包裹在`<div>`元素中，因为 React 只允许一个根元素。让我们看看每个组件并讨论它的属性。

我们将以下三个属性传递给`CollectionControls`组件：

+   `numberOfTweetsInCollection`属性引用了我们集合中当前的推文数量。

+   `htmlMarkup`属性引用了我们在这个组件中使用`createHtmlMarkupStringOfTweetList()`方法产生的 HTML 标记字符串。

+   `onRemoveAllTweetsFromCollection`属性引用了一个从我们的集合中移除所有推文的函数。这个函数是在`Application`组件中实现的，并在第五章中讨论，*使你的 React 组件响应式*。

我们将这两个属性传递给`TweetList`组件：

+   `tweets`属性引用了从父`Application`组件传递的 tweets。

+   `onRemoveTweetFromCollection`属性引用了一个函数，该函数从我们在`Application`组件的状态中存储的一组 tweets 中移除一个 tweet。我们已经在第五章中讨论过这个函数，*使您的 React 组件响应式*。

这就是我们的`Collection`组件。

# 总结

在本章中，您了解了组件生命周期的更新方法。我们还讨论了如何验证组件属性并设置默认属性值。我们还在我们的 Snapterest 应用程序中取得了良好的进展；我们创建并讨论了`Header`，`Tweet`和`Collection`组件。

在下一章中，我们将专注于构建更复杂的 React 组件，并完成构建我们的 Snapterest 应用程序！


# 第八章：构建复杂的 React 组件

在本章中，我们将通过构建应用程序中最复杂的组件，也就是我们`Collection`组件的子组件，将你到目前为止学到的关于 React 组件的一切付诸实践。我们在本章的目标是获得扎实的 React 经验并增强我们的 React 能力。让我们开始吧！

# 创建 TweetList 组件

如你所知，我们的`Collection`组件有两个子组件：`CollectionControls`和`TweetList`。

我们将首先构建`TweetList`组件。创建以下`~/snapterest/source/components/TweetList.js`文件：

```jsx
import React, { Component } from 'react';
import Tweet from './Tweet'; 
import TweetUtils from '../utils/TweetUtils';

const listStyle = {
  padding: '0'
};

const listItemStyle = {
  display: 'inline-block',
  listStyle: 'none'
};

class TweetList extends Component {

  getTweetElement = (tweetId) => {
    const { tweets, onRemoveTweetFromCollection } = this.props;
    const tweet = tweets[tweetId];
    let tweetElement;

    if (onRemoveTweetFromCollection) {
      tweetElement = (
        <Tweet
          tweet={tweet}
          onImageClick={onRemoveTweetFromCollection}
        />
      );
    } else {
      tweetElement = <Tweet tweet={tweet}/>;
    }

    return (
      <li style={listItemStyle} key={tweet.id}>
        {tweetElement}
      </li>
    );
  }

  render() {
    const tweetElements = TweetUtils
      .getListOfTweetIds()
      .map(this.getTweetElement);

    return (
      <ul style={listStyle}>
        {tweetElements}
      </ul>
    );
  }
}

export default TweetList;
```

`TweetList`组件渲染推文列表：

```jsx
render() {
  const tweetElements = TweetUtils
    .getListOfTweetIds()
    .map(this.getTweetElement);

  return (
    <ul style={listStyle}>
      {tweetElements}
    </ul>
  );
}
```

首先，我们创建一个`Tweet`元素列表：

```jsx
const tweetElements = TweetUtils
  .getListOfTweetIds()
  .map(this.getTweetElement);
```

`TweetUtils.getListOfTweetIds()`方法返回一个推文 ID 数组。

然后，对于数组中的每个推文 ID，我们创建一个`Tweet`组件。为此，我们将在推文 ID 数组上调用`map()`方法，并将`this.getTweetElement`方法作为参数传递：

```jsx
getTweetElement = (tweetId) => {
  const { tweets, onRemoveTweetFromCollection } = this.props;
  const tweet = tweets[tweetId];
  let tweetElement;

  if (onRemoveTweetFromCollection) {
    tweetElement = (
      <Tweet
        tweet={tweet}
        onImageClick={onRemoveTweetFromCollection}
      />
    );
  } else {
    tweetElement = <Tweet tweet={tweet} />;
  }

  return (
    <li style={listItemStyle} key={tweet.id}>
      {tweetElement}
    </li>
  );
}
```

`getTweetElement()`方法返回一个包裹在`<li>`元素中的`Tweet`元素。正如我们已经知道的，`Tweet`组件有一个可选的`onImageClick`属性。我们何时想要提供这个可选属性，何时不想要呢？

有两种情况。在第一种情况下，用户将点击推文图像以将其从推文集合中移除。在这种情况下，我们的`Tweet`组件将对`click`事件做出反应，因此我们需要提供`onImageClick`属性。在第二种情况下，用户将导出一个没有用户交互的静态推文集合。在这种情况下，我们不需要提供`onImageClick`属性。

这正是我们在`getTweetElement()`方法中所做的：

```jsx
const { tweets, onRemoveTweetFromCollection } = this.props;
const tweet = tweets[tweetId];
let tweetElement;

if (onRemoveTweetFromCollection) {
  tweetElement = (
    <Tweet
      tweet={tweet}
      onImageClick={onRemoveTweetFromCollection}
    />
  );
} else {
  tweetElement = <Tweet tweet={tweet}/>;
}
```

我们创建一个`tweet`常量，其中存储了一个由`tweetId`参数提供的推文。然后，我们创建一个常量，其中存储了由父`Collection`组件传递的`this.props.onRemoveTweetFromCollection`属性。

接下来，我们检查`this.props.onRemoveTweetFromCollection`属性是否由`Collection`组件提供。如果是，则我们创建一个带有`onImageClick`属性的`Tweet`元素：

```jsx
tweetElement = (
  <Tweet
    tweet={tweet}
    onImageClick={onRemoveTweetFromCollection}
  />
);
```

如果没有提供，则创建一个没有`handleImageClick`属性的`Tweet`元素：

```jsx
tweetElement = <Tweet tweet={tweet} />;
```

我们在以下两种情况下使用`TweetList`组件：

+   该组件用于在`Collection`组件中呈现推文集合。在这种情况下，提供了`onRemoveTweetFromCollection`属性。

+   当渲染代表`Collection`组件中一系列推文的 HTML 标记字符串时，将使用这个组件。在这种情况下，`onRemoveTweetFromCollection`属性*不会*被提供。

一旦我们创建了我们的`Tweet`元素，并将其放入`tweetElement`变量中，我们就返回带有内联样式的`<li>`元素：

```jsx
return (
  <li style={listItemStyle} key={tweet.id}>
    {tweetElement}
  </li>
);
```

除了`style`属性，我们的`<li>`元素还有一个`key`属性。它被 React 用来标识动态创建的每个子元素。我建议你阅读更多关于动态子元素的内容，网址是[`facebook.github.io/react/docs/lists-and-keys.html`](https://facebook.github.io/react/docs/lists-and-keys.html)。

这就是`getTweetElement()`方法的工作原理。因此，`TweetList`组件返回一个`Tweet`元素的无序列表：

```jsx
return (
  <ul style={listStyle}>
    {tweetElements}
  </ul>
);
```

# 创建`CollectionControls`组件

现在，既然你了解了`Collection`组件渲染的内容，让我们讨论它的子组件。我们将从`CollectionControls`开始。创建以下`~/snapterest/source/components/CollectionControls.js`文件：

```jsx
import React, { Component } from 'react';
import Header from './Header';
import Button from './Button';
import CollectionRenameForm from './CollectionRenameForm';
import CollectionExportForm from './CollectionExportForm';

class CollectionControls extends Component {
  state = {
    name: 'new',
    isEditingName: false
  };

  getHeaderText = () => {
    const { name } = this.state;
    const { numberOfTweetsInCollection } = this.props;
    let text = numberOfTweetsInCollection;

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

  setCollectionName = (name) => {
    this.setState({
      name,
      isEditingName: false
    });
  }

  render() {
    const { name, isEditingName } = this.state;
    const {
      onRemoveAllTweetsFromCollection,
      htmlMarkup
    } = this.props;

    if (isEditingName) {
      return (
        <CollectionRenameForm
          name={name}
          onChangeCollectionName={this.setCollectionName}
          onCancelCollectionNameChange={this.toggleEditCollectionName}
        />
      );
    }

    return (
      <div>
        <Header text={this.getHeaderText()}/>

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

`CollectionControls`组件，顾名思义，渲染一个用户界面来控制一个集合。这些控件允许用户执行以下操作：

+   重命名一个集合

+   清空一个集合

+   导出一个集合

一个集合有一个名称。默认情况下，这个名称是`new`，用户可以更改它。集合名称显示在由`CollectionControls`组件渲染的标题中。这个组件是存储集合名称的完美候选者，由于更改名称将需要组件重新渲染，我们将把那个名称存储在组件的状态对象中：

```jsx
state = {
  name: 'new',
  isEditingName: false
};
```

`CollectionControls`组件可以渲染集合控制元素，也可以渲染一个改变集合名称的表单。用户可以在两者之间切换。我们需要一种方式来表示这两种状态——我们将使用`isEditingName`属性来实现这个目的。默认情况下，`isEditingName`被设置为`false`；因此，当`CollectionControls`组件被挂载时，用户将看不到改变集合名称的表单。让我们来看一下它的`render()`方法：

```jsx
render() {
  const { name, isEditingName } = this.state;
  const {
    onRemoveAllTweetsFromCollection,
    htmlMarkup
  } = this.props;

  if (isEditingName) {
    return (
      <CollectionRenameForm
        name={name}
        onChangeCollectionName={this.setCollectionName}
        onCancelCollectionNameChange={this.toggleEditCollectionName}
      />
    );
  }

  return (
    <div>
      <Header text={this.getHeaderText()}/>

      <Button
        label="Rename collection"
        handleClick={this.toggleEditCollectionName}
      />

      <Button
        label="Empty collection"
        handleClick={onRemoveAllTweetsFromCollection}
      />

      <CollectionExportForm htmlMarkup={htmlMarkup}/>
    </div>
  );
}
```

首先，我们检查组件状态的`this.state.isEditingName`属性是否设置为`true`。如果是，那么`CollectionControls`组件将返回`CollectionRenameForm`组件，它渲染一个改变集合名称的表单：

```jsx
<CollectionRenameForm
  name={name}
  onChangeCollectionName={this.setCollectionName}
  onCancelCollectionNameChange={this.toggleEditCollectionName}
/>
```

`CollectionRenameForm`组件渲染一个改变集合名称的表单。它接收三个属性：

+   引用当前集合名称的`name`属性

+   引用组件方法的`onChangeCollectionName`和`onCancelCollectionNameChange`属性

我们将在本章后面实现`CollectionRenameForm`组件。现在让我们更仔细地看看`setCollectionName`方法：

```jsx
setCollectionName = (name) => {
  this.setState({
    name,
    isEditingName: false
  });
}
```

`setCollectionName()`方法更新集合的名称，并通过更新组件的状态来隐藏编辑集合名称的表单。当用户提交新的集合名称时，我们将调用此方法。

现在，让我们看一下`toggleEditCollectionName()`方法：

```jsx
toggleEditCollectionName = () => {
  this.setState(prevState => ({
    isEditingName: !prevState.isEditingName
  }));
}
```

通过使用`!`运算符将`isEditingName`属性设置为其当前布尔值的相反值，此方法显示或隐藏集合名称编辑表单。当用户单击**重命名集合**或**取消**按钮时，我们将调用此方法，即显示或隐藏集合名称更改表单。

如果`CollectionControls`组件状态的`this.state.isEditingName`属性设置为`false`，那么它将返回集合控件：

```jsx
return (
  <div>
    <Header text={this.getHeaderText()}/>

    <Button
      label="Rename collection"
      handleClick={this.toggleEditCollectionName}
    />

    <Button
      label="Empty collection"
      handleClick={onRemoveAllTweetsFromCollection}
    />

    <CollectionExportForm htmlMarkup={htmlMarkup}/>
  </div>
);
```

我们将`Header`组件、两个`Button`组件和`CollectionExportForm`组件包装在一个`div`元素中。您已经在上一章中熟悉了`Header`组件。它接收一个引用字符串的`text`属性。但是，在这种情况下，我们不直接传递一个字符串，而是调用`this.getHeaderText()`函数：

```jsx
<Header text={this.getHeaderText()} />
```

反过来，`this.getHeaderText()`返回一个字符串。让我们更仔细地看看`getHeaderText()`方法：

```jsx
getHeaderText = () => {
  const { name } = this.state;
  const { numberOfTweetsInCollection } = this.props;
  let text = numberOfTweetsInCollection;

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
```

该方法根据集合中的推文数量生成标题字符串。该方法的重要特点是它不仅返回一个字符串，而是封装该字符串的 React 元素树。首先，我们创建`numberOfTweetsInCollection`常量。它存储了集合中的推文数量。然后，我们创建一个`text`变量，并将其赋值为集合中的推文数量。此时，`text`变量存储一个整数值。我们的下一个任务是根据该整数值的内容将正确的字符串连接到它上：

+   如果`numberOfTweetsInCollection`为`1`，那么我们需要连接`' tweet in your'`

+   否则，我们需要连接`' tweets in your'`

创建标题字符串后，我们将返回以下元素：

```jsx
return (
  <span>
    {text} <strong>{name}</strong> collection
  </span>
);
```

最终字符串封装在`<span>`元素内，包括`text`变量的值、集合名称和`collection`关键字；考虑以下示例：

```jsx
1 tweet in your new collection.
```

一旦`getHeaderText()`方法返回这个字符串，它就作为一个属性传递给`Header`组件。我们在`CollectionControls`组件的`render()`方法中的下一个收藏控制元素是`Button`：

```jsx
<Button
  label="Rename collection"
  handleClick={this.toggleEditCollectionName}
/>
```

我们将`Rename collection`字符串传递给它的`label`属性，将`this.toggleEditCollectionName`方法传递给它的`handleClick`属性。因此，这个按钮将有`Rename collection`标签，并且它将切换一个表单来改变收藏的名称。

下一个收藏控制元素是我们的第二个`Button`组件：

```jsx
<Button
  label="Empty collection"
  handleClick={onRemoveAllTweetsFromCollection}
/>
```

你可以猜到，它将有一个`Empty collection`标签，并且它将从收藏中删除所有的推文。

我们的最终收藏控制元素是`CollectionExportForm`：

```jsx
<CollectionExportForm htmlMarkup={htmlMarkup} />
```

这个元素接收一个表示我们收藏的 HTML 标记字符串，并且它将渲染一个按钮。我们将在本章后面创建这个组件。

现在，既然你了解了`CollectionControls`组件将渲染什么，让我们更仔细地看一下它的子组件。我们将从`CollectionRenameForm`组件开始。

# 创建`CollectionRenameForm`组件

首先，让我们创建`~/snapterest/source/components/CollectionRenameForm.js`文件：

```jsx
import React, { Component } from 'react';
import Header from './Header';
import Button from './Button';

const inputStyle = {
  marginRight: '5px'
};

class CollectionRenameForm extends Component {
  constructor(props) {
    super(props);

    const { name } = props;

    this.state = {
      inputValue: name
    };
  }

  setInputValue = (inputValue) => {
    this.setState({
      inputValue
    });
  }

  handleInputValueChange = (event) => {
    const inputValue = event.target.value;
    this.setInputValue(inputValue);
  }

  handleFormSubmit = (event) => {
    event.preventDefault();

    const { onChangeCollectionName } = this.props;
    const { inputValue: collectionName } = this.state;

    onChangeCollectionName(collectionName);
  }

  handleFormCancel = (event) => {
    event.preventDefault();

    const {
      name: collectionName,
      onCancelCollectionNameChange
    } = this.props;

    this.setInputValue(collectionName);
    onCancelCollectionNameChange();
  }

  componentDidMount() {
    this.collectionNameInput.focus();
  }

  render() {
    const { inputValue } = this.state;

    return (
      <form className="form-inline" onSubmit={this.handleSubmit}>

        <Header text="Collection name:"/>
        <div className="form-group">
          <input
            className="form-control"
            style={inputStyle}
            onChange={this.handleInputValueChange}
            value={inputValue}
            ref={input => { this.collectionNameInput = input; }}
          />
        </div>

        <Button
          label="Change"
          handleClick={this.handleFormSubmit}
        />
        <Button
          label="Cancel"
          handleClick={this.handleFormCancel}
        />
      </form>
    );
  }
}

export default CollectionRenameForm;
```

这个组件渲染一个表单来改变收藏的名称：

```jsx
render() {
  const { inputValue } = this.state;

  return (
    <form className="form-inline" onSubmit={this.handleSubmit}>

      <Header text="Collection name:"/>
      <div className="form-group">
        <input
          className="form-control"
          style={inputStyle}
          onChange={this.handleInputValueChange}
          value={inputValue}
          ref={input => this.collectionNameInput = input}
        />
      </div>

      <Button
        label="Change"
        handleClick={this.handleFormSubmit}
      />
      <Button
        label="Cancel"
        handleClick={this.handleFormCancel}
      />
    </form>
  );
}
```

我们的`<form>`元素包裹着四个元素，它们分别是：

+   一个`Header`组件

+   一个`<input>`元素

+   两个`Button`组件

`Header`组件渲染`"Collection name:"`字符串。`<input>`元素包裹在一个`<div>`元素内，该元素的`className`属性设置为`form-group`。这个名称是我们在第五章中讨论的 Bootstrap 框架的一部分。它用于布局和样式，并不是我们 React 应用程序逻辑的一部分。

`<input>`元素有相当多的属性。让我们仔细看一下它：

```jsx
<input
  className="form-control"
  style={inputStyle}
  onChange={this.handleInputValueChange}
  value={inputValue}
  ref={input => { this.collectionNameInput = input; }}
/>
```

以下是前面代码中使用的属性的描述：

+   `className`属性设置为`form-control`。这是 Bootstrap 框架的一部分，我们将用它来进行样式设置。

+   此外，我们使用`style`属性将我们自己的样式应用到这个`input`元素，该属性引用了一个包含单个样式规则的`inputStyle`对象，即`marginRight`。

+   `value`属性设置为组件状态中存储的当前值，`this.state.inputValue`。

+   `onChange`属性引用了一个`handleInputValueChange`方法，这是一个`onchange`事件处理程序。

+   `ref`属性是一个特殊的 React 属性，你可以附加到任何组件上。它接受一个回调函数，React 会在组件被挂载和卸载后立即执行。它允许我们访问我们的 React 组件渲染的 DOM `input`元素。

我希望你关注最后三个属性：`value`、`onChange`和`ref`。`value`属性设置为组件状态的属性，改变该值的唯一方法是更新其状态。另一方面，我们知道用户可以与输入字段交互并改变其值。这种行为会应用到我们的组件吗？不会。每当用户键入时，我们的输入字段的值不会改变。这是因为组件控制着`<input>`，而不是用户。在我们的`CollectionRenameForm`组件中，`<input>`的值始终反映`this.state.inputValue`属性的值，而不管用户键入了什么。用户没有控制权，而是`CollectionRenameForm`组件有。

那么，我们如何确保我们的输入字段对用户输入做出反应？我们需要监听用户输入，并更新`CollectionRenameForm`组件的状态，这将重新渲染带有更新值的输入字段。在每个输入的`change`事件上这样做将使我们的输入看起来像是正常工作的，用户可以自由地改变其值。

为此，我们为我们的`<input>`元素提供了引用组件的`this.handleInputValueChange`方法的`onChange`属性：

```jsx
handleInputValueChange = (event) => {
  const inputValue = event.target.value;
  this.setInputValue(inputValue);
}
```

正如我们在第四章中讨论的那样，*创建你的第一个 React 组件*，React 将`SyntheticEvent`的实例传递给事件处理程序。`handleInputValueChange()`方法接收一个带有`target`属性的`event`对象，该属性具有一个`value`属性。这个`value`属性存储了用户在输入字段中键入的字符串。我们将这个字符串传递给我们的`this.setInputValue()`方法：

```jsx
setInputValue = (inputValue) => {
  this.setState({
    inputValue
  });
}
```

`setInputValue()`方法是一个方便的方法，它使用新的输入值更新组件的状态。反过来，这个更新将重新渲染带有更新值的`<input>`元素。

当`CollectionRenameForm`组件被挂载时，初始输入的值是多少？让我们来看一下：

```jsx
constructor(props) {
  super(props);

  const { name } = props;

  this.state = {
    inputValue: name
  };
}
```

正如你所看到的，我们从父组件传递了集合的名称，并且我们用它来设置组件的初始状态。

在挂载此组件后，我们希望将焦点设置在输入字段上，以便用户可以立即开始编辑集合的名称。我们知道一旦组件插入到 DOM 中，React 就会调用它的`componentDidMount()`方法。这个方法是我们设置`focus`的最佳机会：

```jsx
componentDidMount() {
  this.collectionNameInput.focus();
}
```

为了做到这一点，我们通过引用`this.collectionNameInput`获取我们的输入元素，并在其上调用`focus()`函数。

我们如何在`componentDidMount()`方法中引用 DOM 元素？记住，我们为我们的`input`元素提供了`ref`属性。然后我们将一个回调函数传递给该`ref`属性，该回调函数反过来将 DOM 输入元素的引用分配给`this.collectionNameInput`。所以现在我们可以通过访问`this.collectionNameInput`属性来获取该引用。

最后，让我们讨论一下我们的两个表单按钮：

+   `Change`按钮提交表单并更改集合名称

+   `Cancel`按钮提交表单，但不会更改集合名称

我们先从一个`Change`按钮开始：

```jsx
<Button
  label="Change"
  handleClick={this.handleFormSubmit}
/>
```

当用户点击它时，将调用`this.handleFormSubmit`方法：

```jsx
handleFormSubmit = (event) => {
  event.preventDefault();

  const { onChangeCollectionName } = this.props;
  const { inputValue: collectionName } = this.state;

  onChangeCollectionName(collectionName);
}
```

我们取消了`submit`事件，然后从组件的状态中获取集合名称，并将其传递给`this.props.onChangeCollectionName()`函数调用。`onChangeCollectionName`函数是由父`CollectionControls`组件传递的。调用此函数将更改我们的集合名称。

现在让我们讨论一下我们的第二个表单按钮：

```jsx
<Button
  label="Cancel"
  handleClick={this.handleFormCancel}
/>
```

当用户点击它时，将调用`this.handleFormCancel`方法：

```jsx
handleFormCancel = (event) => {
  event.preventDefault();

  const {
    name: collectionName,
    onCancelCollectionNameChange
  } = this.props;

  this.setInputValue(collectionName);
  onCancelCollectionNameChange();
}
```

再一次，我们取消了一个`submit`事件，然后获取由父`CollectionControls`组件作为属性传递的原始集合名称，并将其传递给我们的`this.setInputValue()`函数。然后，我们调用`this.props.onCancelCollectionNameChange()`函数，隐藏集合控件。

这是我们的`CollectionRenameForm`组件。接下来，让我们创建我们的`Button`组件，我们在`CollectionRenameForm`组件中重复使用了两次。

# 创建 Button 组件

创建以下`~/snapterest/source/components/Button.js`文件：

```jsx
import React from 'react';

const buttonStyle = {
  margin: '10px 0'
};

const Button = ({ label, handleClick }) => (
  <button
    className="btn btn-default"
    style={buttonStyle}
    onClick={handleClick}
  >
    {label}
  </button>
);

export default Button;
```

`Button`组件渲染一个按钮。

请注意，我们没有声明一个类，而是定义了一个简单的名为`Button`的函数。这是创建 React 组件的功能性方式。实际上，当您的组件的目的纯粹是渲染一些用户界面元素，有或没有任何 props 时，建议您使用这种方法。

您可以将这个简单的 React 组件看作是一个“纯”函数，它以`props`对象的形式作为输入，并以 JSX 作为输出——无论您调用这个函数多少次，输出都是一致的。

理想情况下，大多数组件都应该以这种方式创建——作为“纯”JavaScript 函数。当然，当您的组件具有状态时，这是不可能的，但对于所有无状态组件——有机会！现在看看我们迄今为止创建的所有组件，看看您是否可以将它们重写为“纯”函数，而不是使用类。

我建议您阅读有关功能性与类组件的更多信息：[`facebook.github.io/r`](https://facebook.github.io/r)

您可能想知道为什么为按钮创建一个专用组件的好处，如果您可以直接使用`<button>`元素？将组件视为`<button>`元素和其他内容的包装器。在我们的情况下，大多数`<button>`元素都具有相同的样式，因此将`<button>`和样式对象封装在组件中，并重用该组件是有意义的。因此，有了专用的`Button`组件。它期望从父组件接收两个属性：

+   `label`属性是按钮的标签

+   `handleClick`属性是一个回调函数，当用户点击此按钮时调用

现在，是时候创建我们的`CollectionExportForm`组件了。

# 创建`CollectionExportForm`组件

`CollectionExportForm`组件负责将集合导出到第三方网站（[`codepen.io`](http://codepen.io)）。一旦您的集合在 CodePen 上，您可以保存它并与朋友分享。让我们看看如何做到这一点。

创建`~/snapterest/source/components/CollectionExportForm.js`文件：

```jsx
import React from 'react';

const formStyle = {
  display: 'inline-block'
};

const CollectionExportForm = ({ htmlMarkup }) => (
  <form
      action="http://codepen.io/pen/define"
      method="POST"
      target="_blank"
      style={formStyle}
    >
      <input type="hidden" name="data" value={htmlMarkup}/>
      <button type="submit" className="btn btn-default">
        Export as HTML
      </button>
    </form>
);

export default CollectionExportForm;
```

`CollectionExportForm`组件呈现一个带有`<input>`和`<button>`元素的表单。`<input>`元素是隐藏的，其值设置为由父组件作为`htmlMarkup`属性传递的 HTML 标记字符串。`<button>`元素是此表单中唯一对用户可见的元素。当用户单击**导出为 HTML**按钮时，将提交一个集合到 CodePen，该集合将在新窗口中打开。然后用户可以修改和共享该集合。

恭喜！到目前为止，您已经使用 React 构建了一个完全功能的 Web 应用程序。让我们看看它是如何工作的。

首先，请确保我们在第二章中安装和配置的 Snapkite Engine 正在运行。导航到`~/snapkite-engine/`并运行以下命令：

```jsx
**npm start**

```

然后，打开一个新的终端窗口，导航到`~/snapterest/`，并运行以下命令：

```jsx
**npm start**

```

现在在您的 Web 浏览器中打开`~/snapterest/build/index.html`。您将看到新的推文出现。单击它们将其添加到您的收藏中。再次单击它们将单个推文从收藏中删除。单击**清空收藏**按钮可从收藏中删除所有推文。单击**重命名收藏**按钮，输入新的收藏名称，然后单击**更改**按钮。最后，单击**导出为 HTML**按钮将您的收藏导出到[CodePen.io](http://CodePen.io)。如果您在本章或之前的章节中遇到任何问题，请转到[`github.com/fedosejev/react-essentials`](https://github.com/fedosejev/react-essentials)并创建一个新问题。

# 摘要

在这一章中，您创建了`TweetList`，`CollectionControls`，`CollectionRenameForm`，`CollectionExportForm`和`Button`组件。您完成了构建一个完全功能的 React 应用程序。

在接下来的章节中，我们将使用 Jest 测试这个应用程序，并使用 Flux 和 Redux 进行增强。


# 第九章：使用 Jest 测试您的 React 应用程序

到目前为止，你已经创建了许多 React 组件。其中一些非常简单，但有些足够复杂。建立了这两种组件后，你可能已经获得了一定的信心，让你相信无论用户界面有多复杂，你都可以用 React 构建它，而不会遇到任何重大问题。这是一个很好的信心。毕竟，这就是我们投入时间学习 React 的原因。然而，许多有信心的 React 开发人员陷入的陷阱是不写单元测试。

什么是**单元测试**？顾名思义，它是对应用程序的单个单元进行测试。应用程序中的单个单元通常是一个函数，这意味着编写单元测试意味着为您的函数编写测试。

# 为什么要写单元测试？

你可能想知道为什么要写单元测试。让我给你讲一个我个人经历的故事。我最近发布了一个我建立的网站。几天后，使用该网站的同事给我发了一封电子邮件，附带了两个网站一直拒绝的文件。我仔细检查了这些文件，确保了它们的 ID 匹配的要求都得到满足。然而，文件仍然被拒绝，并且错误消息显示 ID 不匹配。你能猜到问题是什么吗？

我写了一个函数来检查这两个文件的 ID 是否匹配。该函数检查了 ID 的值和类型，因此如果值相同但类型不同，它将返回不匹配；结果证明这正是我同事的文件的情况。

重要的问题是，我如何防止这种情况发生？答案是为我的函数编写一些单元测试。

# 创建测试套件、规范和期望

如何为 JavaScript 函数编写测试？你需要一个测试框架，幸运的是，Facebook 为 JavaScript 构建了自己的单元测试框架，称为**Jest**。它受**Jasmine**的启发，这是另一个著名的 JavaScript 测试框架。熟悉 Jasmine 的人会发现 Jest 的测试方法非常相似。然而，我不会假设你之前有测试框架的经验，首先讨论基础知识。

单元测试的基本思想是，你只测试应用程序中的一个功能片段，通常由一个函数实现。你在隔离环境中测试它，这意味着函数依赖的应用程序的其他部分不会被测试使用。相反，它们会被测试模拟。模拟 JavaScript 对象是创建一个模拟真实对象行为的虚假对象。在单元测试中，虚假对象称为**mock**，创建它的过程称为**mocking**。

当运行测试时，Jest 会自动模拟依赖项。它会自动找到要在存储库中执行的测试。让我们看下面的例子。

首先，在`~/snapterest/source/utils/`目录中创建一个新的`TweetUtils.js`文件：

```jsx
function getListOfTweetIds(tweets) {
  return Object.keys(tweets);
}

export default { getListOfTweetIds };
```

`TweetUtils.js`文件是一个模块，包含我们的应用程序使用的`getListOfTweetIds()`实用函数。给定一个带有推文的对象，`getListOfTweetIds()`返回一个推文 ID 数组。

现在让我们用 Jest 编写我们的第一个单元测试。我们将测试我们的`getListOfTweetIds()`函数。

在`~/snapterest/source/utils/`目录中创建一个`TweetUtils.test.js`文件：

```jsx
import TweetUtils from './TweetUtils';

describe('TweetUtils', () => {
  test('getListOfTweetIds returns an array of tweet ids', () => {
    const tweetsMock = {
      tweet1: {},
      tweet2: {},
      tweet3: {}
    };
    const expectedListOfTweetIds = [
      'tweet1',
      'tweet2',
      'tweet3'
    ];
    const actualListOfTweetIds = TweetUtils.getListOfTweetIds(
      tweetsMock
    );

    expect(actualListOfTweetIds)
      .toEqual(expectedListOfTweetIds);
  });
});
```

首先，我们需要引入`TweetUtils`模块：

```jsx
import TweetUtils from './TweetUtils';
```

接下来，我们调用全局的`describe()` Jest 函数。理解其背后的概念很重要。在我们的`TweetUtils.test.js`文件中，我们不只是创建一个单一的测试，而是创建了一组测试。一组测试是对一个更大的功能单元进行集体测试的集合。例如，一组测试可以包含多个测试，测试更大模块的所有单独部分。在我们的示例中，我们有一个`TweetUtils`模块，可能有多个实用函数。在这种情况下，我们会为`TweetUtils`模块创建一组测试，然后为每个单独的实用函数创建测试，比如`getListOfTweetIds()`。

`describe()`函数定义了一个测试套件，并接受这两个参数：

+   **套件名称**：这是描述此测试套件正在测试的标题

+   **套件实现**：这是实现此套件的函数

在我们的示例中，套件如下：

```jsx
describe('TweetUtils', () => {
  // Test suite implementation goes here
});
```

如何创建单独的测试？在 Jest 中，通过调用另一个全局的 Jest 函数`test()`来创建单独的测试。就像`describe()`一样，`test()`函数接受两个参数：

+   **测试名称**：这是描述此测试正在测试的标题，例如：`'getListOfTweetIds 返回推文 ID 数组'`

+   **测试实现**：这是实现此测试的函数

在我们的示例中，测试如下：

```jsx
test('getListOfTweetIds returns an array of tweet ids', () => {
  // Test implementation goes here... });
```

让我们更仔细地看一下我们测试的实现：

```jsx
const tweetsMock = {
  tweet1: {},
  tweet2: {},
  tweet3: {}
};
const expectedListOfTweetIds = [
  'tweet1',
  'tweet2',
  'tweet3'
];
const actualListOfTweetIds = TweetUtils.getListOfTweetIds(
  tweetsMock
);

expect(actualListOfTweetIds)
  .toEqual(expectedListOfTweetIds);
```

我们测试`TweetUtils`模块的`getListOfTweetIds()`方法是否在给定带有推文对象的对象时返回推文 ID 数组。

首先，我们将创建一个模拟真实推文对象的模拟对象：

```jsx
const tweetsMock = {
  tweet1: {},
  tweet2: {},
  tweet3: {}
};
```

这个模拟对象的唯一要求是将推文 ID 作为对象键。值并不重要，所以我们选择空对象。键名也不重要，所以我们选择将它们命名为`tweet1`、`tweet2`和`tweet3`。这个模拟对象并不能完全模拟真实的推文对象——它的唯一目的是模拟其键是推文 ID 的事实。

下一步是创建预期的推文 ID 列表：

```jsx
const expectedListOfTweetIds = [
  'tweet1',
  'tweet2',
  'tweet3'
];
```

我们知道要期望什么推文 ID，因为我们用相同的 ID 模拟了推文对象。

下一步是从我们模拟的推文对象中提取实际的推文 ID。为此，我们使用`getListOfTweetIds()`方法，该方法接受推文对象并返回推文 ID 数组：

```jsx
const actualListOfTweetIds = TweetUtils.getListOfTweetIds(
  tweetsMock
);
```

我们将`tweetsMock`对象传递给该方法，并将结果存储在`actualListOfTweetIds`常量中。它被命名为`actualListOfTweetIds`的原因是这个推文 ID 列表是由我们正在测试的`getListOfTweetIds()`函数产生的。

最后一步将向我们介绍一个新的重要概念：

```jsx
expect(actualListOfTweetIds)
  .toEqual(expectedListOfTweetIds);
```

让我们思考一下测试的过程。我们需要取得一个由我们正在测试的方法产生的实际值，即`getListOfTweetIds()`，并将其与我们预先知道的预期值进行匹配。匹配的结果将决定我们的测试是否通过或失败。

我们之所以能预先猜测`getListOfTweetIds()`将会返回什么是因为我们已经为它准备了输入；这就是我们的模拟对象：

```jsx
const tweetsMock = {
  tweet1: {},
  tweet2: {},
  tweet3: {}
};
```

因此，我们可以通过调用`TweetUtils.getListOfTweetIds(tweetsMock)`来期望以下输出：

```jsx
[ 'tweet1', 'tweet2', 'tweet3' ]
```

因为在`getListOfTweetIds()`内部可能出现问题，我们无法保证这个结果；我们只能*期望*它。

这就是为什么我们需要创建一个期望。在 Jest 中，**期望**是使用`expect()`函数构建的，该函数接受一个实际值；例如，`actualListOfTweetIds`对象：`expect(actualListOfTweetIds)`。

然后，我们将它与一个**匹配器**函数链接起来，该函数比较实际值与期望值，并告诉 Jest 期望是否得到满足：

```jsx
expect(actualListOfTweetIds)
  .toEqual(expectedListOfTweetIds);
```

在我们的示例中，我们使用`toEqual()`匹配器函数来比较两个数组。您可以在 Jest 的[`facebook.github.io/jest/docs/expect.html`](https://facebook.github.io/jest/docs/expect.html)中找到所有内置匹配器函数的列表

这就是你编写测试的方式。一个测试包含一个或多个期望。每个期望测试您代码的状态。一个测试可以是**通过的测试**或**失败的测试**。只有当所有期望都得到满足时，测试才是通过的测试；否则，它就是失败的测试。

干得好，您已经编写了您的第一个测试套件，其中包含一个期望的单个测试！您如何运行它？

# 安装和运行 Jest

首先，让我们安装**Jest 命令行界面**（**Jest CLI**）模块：

```jsx
**npm install --save-dev jest**

```

这个命令会将 Jest 模块安装并添加为`~/snapterest/package.json`文件的开发依赖项。

在第二章中，*为您的项目安装强大的工具*，我们安装并讨论了 Babel。我们使用 Babel 将我们的新 JavaScript 语法转译为旧的 JavaScript 语法，并将 JSX 语法编译为普通的 JavaScript 语法。在我们的测试中，我们将测试用 JSX 语法编写的 React 组件，但是 Jest 默认不理解 JSX 语法。我们需要告诉 Jest 自动使用 Babel 编译我们的测试。为此，我们需要安装`babel-jest`模块：

```jsx
**npm install --save-dev babel-jest**

```

现在我们需要配置 Babel。为此，在`~/snapterest/`目录中创建以下`.babelrc`文件：

```jsx
{
  "presets": ["es2015", "react"]
```

接下来，让我们编辑`package.json`文件。我们将替换现有的`"scripts"`对象：

```jsx
"scripts": {
  "test": "echo \"Error: no test specified\" && exit 1"
},
```

用以下对象替换前面的对象：

```jsx
"scripts": {
  "test": "jest"
},
```

现在我们准备运行我们的测试套件。转到`~/snapterest/`目录，并运行以下命令：

```jsx
**npm test**

```

您应该在终端窗口中看到以下消息：

```jsx
**PASS  source/utils/TweetUtils.test.js**

```

此输出消息告诉您以下内容：

+   `PASS`：您的测试已通过

+   `source/utils/TweetUtils.test.js`：Jest 从这个文件运行测试

这就是编写和测试一个微小单元测试所需的全部。现在，让我们创建另一个！

# 创建多个测试和期望

这一次，我们将创建并测试集合实用程序模块。在`~/snapterest/source/utils/`目录中创建`CollectionUtils.js`文件：

```jsx
import TweetUtils from './TweetUtils';

function getNumberOfTweetsInCollection(collection) {
  const listOfCollectionTweetIds = TweetUtils
    .getListOfTweetIds(collection);

  return listOfCollectionTweetIds.length;
}

function isEmptyCollection(collection) {
  return getNumberOfTweetsInCollection(collection) === 0;
}

export default {
  getNumberOfTweetsInCollection,
  isEmptyCollection
};
```

`CollectionUtils`模块有两个函数：`getNumberOfTweetsInCollection()`和`isEmptyCollection()`。

首先，让我们讨论`getNumberOfTweetsInCollection()`：

```jsx
function getNumberOfTweetsInCollection(collection) {
  const listOfCollectionTweetIds = TweetUtils
    .getListOfTweetIds(collection);

  return listOfCollectionTweetIds.length;
}
```

正如你所看到的，这个函数调用`TweetUtils`模块的`getListOfTweetIds()`方法，并将`collection`对象作为参数传递。`getListOfTweetIds()`返回的结果存储在`listOfCollectionTweetIds`常量中，由于它是一个数组，`getNumberOfTweetsInCollection()`返回该数组的`length`属性。

现在，让我们来看一下`isEmptyCollection()`方法：

```jsx
function isEmptyCollection(collection) {
  return getNumberOfTweetsInCollection(collection) === 0;
}
```

这个方法重用了我们刚刚讨论的`getNumberOfTweetsInCollection()`方法。它检查调用`getNumberOfTweetsInCollection()`返回的结果是否等于零。然后，它返回该检查的结果，即`true`或`false`。

请注意，我们从这个模块导出了这两个方法：

```jsx
export default {
  getNumberOfTweetsInCollection,
  isEmptyCollection
};
```

我们刚刚创建了我们的`CollectionUtils`模块。我们的下一个任务是测试它。

在`~/snapterest/source/utils/`目录中，创建以下`CollectionUtils.test.js`文件：

```jsx
import CollectionUtils from './CollectionUtils';

describe('CollectionUtils', () => {
  const collectionTweetsMock = {
    collectionTweet7: {},
    collectionTweet8: {},
    collectionTweet9: {}
  };

  test('getNumberOfTweetsInCollection returns a number of tweets in collection', () => {
    const actualNumberOfTweetsInCollection = CollectionUtils
    .getNumberOfTweetsInCollection(collectionTweetsMock);
    const expectedNumberOfTweetsInCollection = 3;

    expect(actualNumberOfTweetsInCollection)
    .toBe(expectedNumberOfTweetsInCollection);
    });

  test('isEmptyCollection checks if collection is not empty', () => {
    const actualIsEmptyCollectionValue = CollectionUtils
      .isEmptyCollection(collectionTweetsMock);

    expect(actualIsEmptyCollectionValue).toBeDefined();
    expect(actualIsEmptyCollectionValue).toBe(false);
    expect(actualIsEmptyCollectionValue).not.toBe(true);
  });
});
```

首先我们定义我们的测试套件：

```jsx
describe('CollectionUtils', () => {
  const collectionTweetsMock = {
    collectionTweet7: {},
    collectionTweet8: {},
    collectionTweet9: {}
  };

// Tests go here... });
```

我们给我们的测试套件命名为我们正在测试的模块的名称—`CollectionUtils`。现在让我们来看一下这个测试套件的实现。与我们之前的测试套件不同，我们不是立即定义测试规范，而是创建了`collectionTweetsMock`对象。那么，我们允许这样做吗？当然可以。测试套件实现函数只是另一个 JavaScript 函数，在定义测试规范之前我们可以做一些工作。

这个测试套件将实现多个测试。我们所有的测试都将使用`collectionTweetsMock`对象，所以在规范范围之外定义它并在规范内重用它是有意义的。你可能已经猜到，`collectionTweetsMock`对象模拟了一组推文。

现在让我们实现单独的测试规范。

我们的第一个规范测试了`CollectionUtils`模块是否返回了集合中的推文数量：

```jsx
test('getNumberOfTweetsInCollection returns a numberof tweets in collection', () => {
  const actualNumberOfTweetsInCollection = CollectionUtils
    .getNumberOfTweetsInCollection(collectionTweetsMock);
  const expectedNumberOfTweetsInCollection = 3;

  expect(actualNumberOfTweetsInCollection)
    .toBe(expectedNumberOfTweetsInCollection);
});
```

我们首先获取我们模拟集合中的实际推文数量：

```jsx
const actualNumberOfTweetsInCollection = CollectionUtils
  .getNumberOfTweetsInCollection(collectionTweetsMock);
```

为此，我们调用`getNumberOfTweetsInCollection()`方法，并将`collectionTweetsMock`对象传递给它。然后，我们定义我们模拟集合中期望的推文数量：

```jsx
const expectedNumberOfTweetsInCollection = 3;
```

最后，我们调用`expect()`全局函数来创建一个期望：

```jsx
expect(actualNumberOfTweetsInCollection)
  .toBe(expectedNumberOfTweetsInCollection);
```

我们使用`toBe()`匹配器函数来匹配实际值和期望值。

如果你现在运行`npm test`命令，你会看到两个测试套件都通过了：

```jsx
**PASS  source/utils/CollectionUtils.test.js**
**PASS  source/utils/TweetUtils.test.js**

```

请记住，要使测试套件通过，它必须只有通过的规范。要使规范通过，它必须满足所有的期望。到目前为止情况就是这样。

怎么样进行一个小小的邪恶实验？

打开你的`~/snapterest/source/utils/CollectionUtils.js`文件，并在`getNumberOfTweetsInCollection()`函数内，找到以下代码行：

```jsx
return listOfCollectionTweetIds.length;
```

现在将其更改为这样：

```jsx
return listOfCollectionTweetIds.length + 1;
```

这个微小的更新将返回任何给定集合中错误的推文数量。现在再次运行`npm test`。你应该看到`CollectionUtils.test.js`中的所有规范都失败了。这是我们感兴趣的一个：

```jsx
**FAIL  source/utils/CollectionUtils.test.js**
 **CollectionUtils › getNumberOfTweetsInCollection returns a number of tweets in collection**

 **expect(received).toBe(expected)**

 **Expected value to be (using ===):**
 **3**
 **Received:**
 **4**

 **at Object.<anonymous> (source/utils/CollectionUtils.test.js:14:46)**

```

我们以前没有看到过失败的测试，所以让我们仔细看看它试图告诉我们什么。

首先，它告诉我们`CollectionUtils.test.js`测试失败了：

```jsx
**FAIL  source/utils/CollectionUtils.test.js**

```

然后，以一种人性化的方式告诉我们哪个测试失败了：

```jsx
 **CollectionUtils › getNumberOfTweetsInCollection returns a number of tweets in collection**

```

然后，出了什么问题-意外的测试结果：

```jsx
**expect(received).toBe(expected)** 
 **Expected value to be (using ===):**
 **3**
 **Received:**
 **4**

```

最后，Jest 打印出一个堆栈跟踪，这应该给我们足够的技术细节，快速确定我们的代码的哪一部分产生了意外的结果：

```jsx
**at Object.<anonymous> (source/utils/CollectionUtils.test.js:14:46)**

```

好了！不要再故意让我们的测试失败了。让我们把`~/snapterest/source/utils/CollectionUtils.js`文件恢复到这个状态：

```jsx
return listOfCollectionTweetIds.length;
```

在 Jest 中，一个测试套件可以有许多规范，测试来自单个模块的不同方法。我们的`CollectionUtils`模块有两种方法。现在让我们讨论第二种方法。

我们在`CollectionUtils.test.js`中的下一个规范检查集合是否不为空：

```jsx
test('isEmptyCollection checks if collection is not empty', () => {
  const actualIsEmptyCollectionValue = CollectionUtils
    .isEmptyCollection(collectionTweetsMock);

  expect(actualIsEmptyCollectionValue).toBeDefined();
  expect(actualIsEmptyCollectionValue).toBe(false);
  expect(actualIsEmptyCollectionValue).not.toBe(true);
});
```

首先，我们调用`isEmptyCollection()`方法，并将`collectionTweetsMock`对象传递给它。我们将结果存储在`actualIsEmptyCollectionValue`常量中。注意我们如何重复使用相同的`collectionTweetsMock`对象，就像在我们之前的规范中一样。

接下来，我们创建了不止一个期望：

```jsx
expect(actualIsEmptyCollectionValue).toBeDefined();
expect(actualIsEmptyCollectionValue).toBe(false);
expect(actualIsEmptyCollectionValue).not.toBe(true);
```

你可能已经猜到我们对`actualIsEmptyCollectionValue`常量的期望。

首先，我们期望我们的集合被定义：

```jsx
expect(actualIsEmptyCollectionValue).toBeDefined();
```

这意味着`isEmptyCollection()`函数必须返回除`undefined`之外的其他东西。

接下来，我们期望它的值是`false`：

```jsx
expect(actualIsEmptyCollectionValue).toBe(false);
```

早些时候，我们使用`toEqual()`匹配器函数来比较数组。`toEqual()`方法进行深度比较，非常适合比较数组，但对于`false`等原始值来说有些过度。

最后，我们期望`actualIsEmptyCollectionValue`不是`true`：

```jsx
expect(actualIsEmptyCollectionValue).not.toBe(true);
```

下一个比较是通过`.not`进行反转的。它将期望与`toBe(true)`的相反值`false`进行匹配。

注意`toBe(false)`和`not.toBe(true)`产生相同的结果。

只有当所有三个期望都得到满足时，这个规范才会通过。

到目前为止，我们已经测试了实用模块，但是如何使用 Jest 测试 React 组件呢？

我们接下来会发现。

# 测试 React 组件

让我们暂时停下来不写代码，谈谈测试用户界面意味着什么。我们究竟在测试什么？我们测试的是我们的用户界面是否按预期呈现。换句话说，如果我们告诉 React 去呈现一个按钮，我们期望它呈现一个按钮，不多，也不少。

现在我们如何检查这一点呢？做到这一点的一种方法是编写一个 React 组件，捆绑我们的应用程序，在 Web 浏览器中运行它，并亲眼看到它显示我们想要显示的内容。这是手动测试，我们至少要做一次。但是这在长期内是耗时且不可靠的。

我们如何自动化这个过程呢？Jest 可以为我们做大部分工作，但是 Jest 没有自己的眼睛，所以它至少需要借用我们的眼睛来测试每个组件一次。如果 Jest“看不到”呈现 React 组件的结果，那么它如何甚至测试 React 组件呢？

在第三章中，*创建您的第一个 React 元素*，我们讨论了 React 元素。它们是描述我们想在屏幕上看到的内容的简单的 JavaScript 对象。

例如，考虑这个 HTML 标记：

```jsx
<h1>Testing</h1>
```

这可以用以下简单的 JavaScript 对象表示：

```jsx
{
  type: 'h1',
  children: 'Testing'
}
```

当我们呈现组件时，拥有代表我们组件产生的输出的简单的 JavaScript 对象，使我们能够描述关于我们组件及其行为的某些期望。让我们看看它的实际效果。

我们将测试的第一个 React 组件将是我们的`Header`组件。在`~/snapterest/source/components/`目录中创建`Header.test.js`文件：

```jsx
import React from 'react';
import renderer from 'react-test-renderer';
import Header, { DEFAULT_HEADER_TEXT } from './Header';

describe('Header', () => {
  test('renders default header text', () => {
    const component = renderer.create(
      <Header/>
    );

    const tree = component.toJSON();
    const firstChild = tree.children[0];

    expect(firstChild).toBe(DEFAULT_HEADER_TEXT);
  });

  test('renders provided header text', () => {
    const headerText = 'Testing';

    const component = renderer.create(
      <Header text={headerText} />
    );

    const tree = component.toJSON();
    const firstChild = tree.children[0];

    expect(firstChild).toBe(headerText);
  });
});
```

到目前为止，您可以认识到我们测试文件的结构。首先，我们定义了测试套件，并给它命名为`Header`。我们的测试套件有两个测试规范，分别命名为`renders default header text`和`renders provided header text`。正如它们的名称所示，它们测试我们的`Header`组件能够呈现默认文本和提供的文本。让我们更仔细地看看这个测试套件。

首先，我们导入 React 模块：

```jsx
import React from 'react';
```

然后，我们导入`react-test-renderer`模块：

```jsx
import renderer from 'react-test-renderer';
```

React 渲染器将 React 组件渲染为纯 JavaScript 对象。它不需要 DOM，因此我们可以使用它在 web 浏览器之外渲染 React 组件。它与 Jest 配合使用效果很好。让我们安装它：

```jsx
**npm install --save-dev react-test-renderer**

```

接下来，为了测试我们的`Header`组件，我们需要导入它：

```jsx
import Header, { DEFAULT_HEADER_TEXT } from './Header';
```

我们还从我们的`Header`模块中导入`DEFAULT_HEADER_TEXT`。我们这样做是因为我们不想硬编码实际的字符串值，即默认的标题文本。这会增加维护这个值的额外工作。相反，由于我们的`Header`组件知道这个值是什么，我们将在测试中导入并重用它。

让我们来看看我们的第一个名为`renders default header text`的测试。我们在这个测试中的第一个任务是将`Header`组件渲染为普通的 JavaScript 对象。`react-test-renderer`模块有一个`create`方法可以做到这一点：

```jsx
const component = renderer.create(
  <Header/>
);
```

我们将`<Header/>`元素作为参数传递给`create()`函数，然后我们得到一个代表我们的`Header`组件实例的 JavaScript 对象。它还不是我们组件的简单表示，所以我们的下一步是使用`toJSON`方法将该对象转换为我们组件的简单树形表示：

```jsx
const tree = component.toJSON();
```

现在，`tree`也是一个 JavaScript 对象，但它也是我们`Header`组件的简单表示，我们可以轻松阅读和理解：

```jsx
{ type: 'h2', props: {}, children: [ 'Default header' ] }
```

我建议你记录`component`和`tree`对象，并看看它们有多不同：

```jsx
console.log(component);
console.log(tree);
```

你会很快发现`component`对象是为了 React 的内部使用而设计的-很难阅读并且难以判断它代表什么。另一方面，`tree`对象非常容易阅读，并且清楚它代表什么。

正如你所看到的，我们目前测试 React 组件的方法是将`<Header/>`转换为`{ type: 'h2', props: {}, children: [ 'Default header' ] }`。现在我们有了一个简单的 JavaScript 对象来代表我们的组件，我们可以检查这个对象是否具有预期的值。如果是，我们可以得出结论，我们的组件将如预期般在 web 浏览器中渲染。如果不是，那么我们可能引入了一个 bug。

当我们渲染我们的`Header`组件没有任何属性时，`<Header/>`，我们期望它渲染出一个默认文本：`'Default header'`。为了检查这是否确实如此，我们需要从我们`Header`组件的树形表示中访问`children`属性：

```jsx
const firstChild = tree.children[0];
```

我们期望我们的`Header`组件只有一个子元素，所以文本元素将是第一个子元素。

现在是时候写我们的期望了：

```jsx
expect(firstChild).toBe(DEFAULT_HEADER_TEXT);
```

在这里，我们期望`firstChild`具有与`DEFAULT_HEADER_TEXT`相同的值。在幕后，`toBe`匹配器使用`===`进行比较。

这就是我们的第一个测试！

在我们名为“渲染提供的标题文本”的第二个测试中，我们正在测试我们的`Header`组件是否具有我们通过`text`属性提供的自定义测试：

```jsx
test('renders provided header text', () => {
  const headerText = 'Testing';

  const component = renderer.create(
    <Header text={headerText}/>
  );

  const tree = component.toJSON();
  const firstChild = tree.children[0];

  expect(firstChild).toBe(headerText);
});
```

现在您理解了测试 React 组件的核心思想：

1.  将您的组件呈现为 JavaScript 对象表示。

1.  在该对象上找到一些值，并检查该值是否符合您的期望。

如您所见，当您的组件很简单时，这是非常直接的。但是，如果您需要测试由其他组件组成的组件等等，会怎样呢？想象一下代表该组件的 JavaScript 对象将会有多复杂。它将具有许多深度嵌套的属性。您可能最终会编写和维护大量用于访问和比较深度嵌套值的代码。这就是写单元测试变得太昂贵的时候，一些开发人员可能选择放弃对其组件进行测试的原因。

幸运的是，我们有两种解决方案可供选择。

以下是其中之一。记住，当直接遍历和修改 DOM 太麻烦时，jQuery 库被创建出来简化这个过程？嗯，对于 React 组件，我们有 Enzyme——这是来自 AirBnB 的 JavaScript 测试实用库，简化了遍历和操作渲染 React 组件产生的输出的过程。

Enzyme 是 Jest 之外的一个独立库。让我们安装它：

```jsx
**npm install --save-dev enzyme jest-enzyme react-addons-test-utils**

```

要与 Jest 一起使用 Enzyme，我们需要安装三个模块。记住，Jest 运行我们的测试，而 Enzyme 将帮助我们编写我们的期望。

现在让我们使用 Enzyme 重写我们的`Header`组件的测试：

```jsx
import React from 'react';
import { shallow } from 'enzyme';
import Header, { DEFAULT_HEADER_TEXT } from './Header';

describe('Header', () => {
  test('renders default header text', () => {
    const wrapper = shallow(
      <Header/>
    );

    expect(wrapper.find('h2')).toHaveLength(1);
    expect(wrapper.contains(DEFAULT_HEADER_TEXT)).toBe(true);
  });

  test('renders provided header text', () => {
    const headerText = 'Testing';

    const wrapper = shallow(
      <Header text={headerText} />
    );

    expect(wrapper.find('h2')).toHaveLength(1);
    expect(wrapper.contains(headerText)).toBe(true);
  });
});
```

首先，我们从`enzyme`模块中导入`shallow`函数：

```jsx
import { shallow } from 'enzyme';
```

然后，在我们的测试中，我们调用`shallow`函数并将我们的`Header`组件作为参数传递：

```jsx
const wrapper = shallow(
  <Header/>
);
```

我们得到的是一个包装渲染我们的`Header`组件结果的对象。这个对象是由 Enzyme 的`ShallowWrapper`类创建的，并且对我们来说有一些非常有用的方法。我们将其称为`wrapper`。

现在我们有了这个`wrapper`对象可供我们使用，我们准备写我们的期望。请注意，与`react-test-renderer`不同，使用 Enzyme 时我们不需要将`wrapper`对象转换为我们组件的简化表示。这是因为我们不会直接遍历我们的`wrapper`对象——它不是一个简单的对象，很难让我们阅读；尝试记录该对象并亲自看看。相反，我们将使用 Enzyme 的`ShallowWrapper` API 提供的方法。

让我们写我们的第一个期望：

```jsx
expect(wrapper.find('h2')).toHaveLength(1);
```

正如您所看到的，我们在`wrapper`对象上调用了`find`方法。这就是 Enzyme 的强大之处。我们不需要直接遍历我们的 React 组件输出对象并找到嵌套的元素，我们只需调用`find`方法并告诉它我们要找什么。在这个例子中，我们告诉 Enzyme 在`wrapper`对象内查找所有的`h2`元素，因为它包裹了我们的`Header`组件的输出，我们期望`wrapper`对象有一个`h2`元素。我们使用 Jest 的`toHaveLength`匹配器来检查这一点。

这是我们的第二个期望：

```jsx
**expect(wrapper.contains(DEFAULT_HEADER_TEXT)).toBe(true);**

```

您可以猜到，我们正在检查我们的 wrapper 对象是否包含`DEFAULT_HEADER_TEXT`。这个检查让我们得出结论，当我们没有提供任何自定义文本时，我们的`Header`组件呈现默认文本。我们使用 Enzyme 的`contains`方法，方便地检查我们的组件是否包含任何节点。在这种情况下，我们正在检查文本节点。

Enzyme 的 API 提供了更多方法，方便我们检查组件的输出。我建议您通过阅读官方文档熟悉这些方法：[`airbnb.io/enzyme/docs/api/shallow.html`](http://airbnb.io/enzyme/docs/api/shallow.html)

您可能想知道如何测试您的 React 组件的行为。

这是我们接下来要讨论的内容！

在`~/snapterest/source/components/`目录中创建`Button.test.js`文件：

```jsx
import React from 'react';
import { shallow } from 'enzyme';
import Button from './Button';

describe('Button', () => {
  test('calls click handler function on click', () => {
    const handleClickMock = jest.fn();

    const wrapper = shallow(
      <Button handleClick={handleClickMock}/>
    );

    wrapper.find('button').simulate('click');

    expect(handleClickMock.mock.calls.length).toBe(1);
  });
});
```

`Button.test.js`文件将测试我们的`Button`组件，特别是检查当您点击它时是否触发点击事件处理程序函数。话不多说，让我们专注于`'calls click handler function on click'`规范的实现：

```jsx
const handleClickMock = jest.fn();

const wrapper = shallow(
  <Button handleClick={handleClickMock} />
);

wrapper.find('button').simulate('click');

expect(handleClickMock.mock.calls.length).toBe(1);
```

在这个规范中，我们正在测试我们的`Button`组件是否调用我们通过`handleClick`属性提供的函数。这是我们的测试策略：

1.  生成一个模拟函数。

1.  使用我们的模拟函数渲染`Button`组件。

1.  在由 Enzyme 创建的包装对象中找到`button`元素，这是渲染我们的`Button`组件的结果。

1.  在`button`元素上模拟点击事件。

1.  检查我们的模拟函数是否确实被调用了一次。

现在我们有了一个计划，让我们实施它。让我们首先创建一个模拟函数：

```jsx
const handleClickMock = jest.fn();
```

`jest.fn()`函数调用返回新生成的 Jest 模拟函数；我们将其命名为`handleClickMock`。

接下来，我们通过调用 Enzyme 的`shallow`函数来获取我们的`Button`组件的输出：

```jsx
const wrapper = shallow(
  <Button handleClick={handleClickMock}/>
);
```

我们将我们的`handleClickMock`函数作为一个属性传递给我们的`Button`组件。

然后，我们找到`button`元素并在其上模拟点击事件：

```jsx
wrapper.find('button').simulate('click');
```

在这一点上，我们期望我们的按钮元素调用它的`onClick`事件处理程序，这种情况下是我们的`handleClickMock`函数。这个模拟函数应该记录它被调用了一次，或者至少这是我们期望我们的`Button`组件的行为。让我们创建这个期望：

```jsx
expect(handleClickMock.mock.calls.length).toBe(1);
```

我们如何检查我们的`handleClickMock`函数被调用了多少次？我们的`handleClickMock`函数有一个特殊的模拟属性，我们可以检查它来找出`handleClickMock`被调用了多少次：

```jsx
handleClickMock.mock.calls.length
```

反过来，我们的`mock`对象有一个`calls`对象，它知道每次调用我们的`handleClickMock`函数的所有信息。`calls`对象是一个数组，在我们的情况下，我们期望它的`length`属性等于 1。

正如你所看到的，使用 Enzyme 更容易编写期望。我们的测试需要更少的工作来编写它们，并且长期维护它们。这很好，因为现在我们有更多的动力来编写更多的测试。

但是我们能让使用 Jest 编写测试变得更容易吗？

原来我们可以。

现在我们将一个 React 组件渲染为一个对象表示，然后使用 Jest 或 Enzyme 的帮助来检查该对象。这种检查要求我们作为开发人员编写额外的代码来使我们的测试工作。我们如何避免这种情况？

我们可以将一个 React 组件渲染为一个文本字符串，这样我们可以轻松地阅读和理解。然后我们可以将这个文本表示存储在我们的代码库中。稍后，当我们再次运行我们的测试时，我们可以简单地创建一个新的文本表示并将其与我们存储的进行比较。如果它们不同，那么这可能意味着我们有意更新了我们的组件，现在我们需要更新我们的文本表示，或者我们向我们的组件引入了一个错误，以至于它现在产生了一个意外的文本表示。

这个想法在 Jest 中被称为**快照测试**。让我们使用快照测试重写我们的`Header`组件的测试。用这段新代码替换你的`Header.test.js`文件中的现有代码：

```jsx
import React from 'react';
import renderer from 'react-test-renderer';
import Header from './Header';

describe('Header', () => {
  test('renders default header text', () => {
    const component = renderer.create(
      <Header/>
    );

    const tree = component.toJSON();

    expect(tree).toMatchSnapshot();
  });

  test('renders provided header text', () => {
    const headerText = 'Testing';

    const component = renderer.create(
      <Header text={headerText} />
    );

    const tree = component.toJSON();

    expect(tree).toMatchSnapshot();
  });
});
```

正如你所看到的，我们在这种情况下没有使用 Enzyme，这对我们来说应该是有意义的，因为我们不再想要检查任何东西。

另一方面，我们再次使用`react-test-renderer`模块来渲染和转换我们的组件为一个名为`tree`的简单 JavaScript 对象：

```jsx
const component = renderer.create(
  <Header/>
);

const tree = component.toJSON();
```

将快照测试付诸实践的关键代码行是这一行：

```jsx
expect(tree).toMatchSnapshot();
```

我们只是告诉 Jest 我们期望我们的`tree`对象与现有的快照匹配。等一下，但我们没有现有的快照。很好的观察！那么在这种情况下会发生什么？Jest 找不到这个测试的现有快照，而是会为这个测试创建一个第一个快照。

让我们运行我们的测试命令：

```jsx
**npm test**

```

所有测试都应该通过，你应该看到这个输出：

```jsx
**Snapshot Summary**
 **› 2 snapshots written in 1 test suite.**

```

在这里，Jest 告诉我们它创建了两个快照——一个用于我们`Header.test.js`测试套件中找到的每个测试。Jest 把这两个快照存储在哪里？如果你检查`~/snapterest/source/components/`目录，你会发现一个新的文件夹：`__snapshots__`。在里面，你会找到`Header.test.js.snap`文件。打开这个文件并查看它的内容：

```jsx
// Jest Snapshot v1, https://goo.gl/fbAQLP

exports[`Header renders default header text 1`] = `
<h2
  style={
    Object {
      "display": "inline-block",
      "fontSize": "16px",
      "fontWeight": "300",
      "margin": "20px 10px",
    }
  }
>
  Default header
</h2>
`;

exports[`Header renders provided header text 1`] = `
<h2
  style={
    Object {
      "display": "inline-block",
      "fontSize": "16px",
      "fontWeight": "300",
      "margin": "20px 10px",
    }
  }
>
  Testing
</h2>
`;
```

在这个文件中，你可以看到我们的`Header`组件在使用 Jest 渲染时产生的输出的文本表示。我们很容易读取这个文件并确认这就是我们期望`Header`组件渲染的内容。现在我们的`Header`组件有了自己的快照。将这些快照视为源代码的一部分进行处理和存储是很重要的。

如果你有 Git 仓库，你应该提交它们，并且你应该注意你对它们所做的任何更改。

既然你已经看到了三种不同的编写 React 测试的方式，你需要自己选择如何测试你的 React 组件。现在我建议你使用快照测试和 Enzyme。

太好了，我们已经编写了四个测试套件。现在是时候运行我们所有的测试了。

导航到`~/snapterest/`并运行这个命令：

```jsx
**npm test**

```

你所有的测试套件都应该`通过`。

```jsx
**PASS  source/components/Button.test.js** 
**PASS  source/components/Header.test.js** 
**PASS  source/utils/CollectionUtils.test.js** 
**PASS  source/utils/TweetUtils.test.js** 

**Snapshot Summary**
 **› 2 snapshots written in 1 test suite.** 

**Test Suites: 4 passed, 4 total** 
**Tests:       6 passed, 6 total** 
**Snapshots:   2 added, 2 total** 
**Time:        2.461s** 
**Ran all test suites.**

```

这样的日志消息会帮助你晚上睡得安稳，放假时也不需要不断检查工作邮件。

干得好！

# 总结

现在你知道如何创建 React 组件并对其进行单元测试了。

在本章中，您学习了 Jest 的基本知识——这是 Facebook 推出的一个与 React 配合良好的单元测试框架。您了解了 Enzyme 库，并学会了如何简化编写 React 组件的单元测试。我们讨论了测试套件、规范、期望和匹配器。我们创建了模拟和模拟点击事件。

在下一章中，您将学习 Flux 架构的基本知识，以及如何提高我们的 React 应用程序的可维护性。
