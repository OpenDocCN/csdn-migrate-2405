# React 和 ReactNative 第二版（三）

> 原文：[`zh.annas-archive.org/md5/CC615F617A68B98794CE06AC588C6A32`](https://zh.annas-archive.org/md5/CC615F617A68B98794CE06AC588C6A32)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：扩展组件

在本章中，您将学习如何通过扩展现有组件来添加新的功能。有两种 React 机制可以用来扩展组件：

+   组件继承

+   使用高阶组件进行组合

您将首先学习基本组件继承，就像面向对象的类继承一样。然后，您将实现一些用于组合 React 组件的高阶组件。

# 组件继承

组件就是类。事实上，当您使用 **ES2015** 类语法实现组件时，您会从 React 扩展基类 `Component`。您可以继续像这样扩展您的类，以创建自己的基本组件。

在本节中，您将看到您的组件可以继承状态、属性，以及几乎任何其他东西，包括 JSX 标记和事件处理程序。

# 继承状态

有时，您有几个使用相同初始状态的 React 组件。您可以实现一个设置此初始状态的基本组件。然后，想要使用此作为其初始状态的任何组件都可以扩展此组件。让我们实现一个设置一些基本状态的基本组件：

```jsx
import { Component } from 'react';
import { fromJS } from 'immutable';

export default class BaseComponent extends Component {
  state = {
    data: fromJS({
      name: 'Mark',
      enabled: false,
      placeholder: ''
    })
  };

  // Getter for "Immutable.js" state data...
  get data() {
    return this.state.data;
  }

  // Setter for "Immutable.js" state data...
  set data(data) {
    this.setState({ data });
  }

  // The base component doesn't actually render anything,
  // but it still needs a render method.
  render() {
    return null;
  }
}
```

状态是不可变的 `Map`。这个基本组件还实现了不可变数据的设置和获取方法。让我们实现一个扩展了这个组件的组件：

```jsx
import React from 'react';
import BaseComponent from './BaseComponent';

// Extends "BaseComponent" to inherit the
// initial component state.
export default class MyComponent extends BaseComponent {
  // This is our chance to build on the initial state.
  // We change the "placeholder" text and mark it as
  // "enabled".
  componentDidMount() {
    this.data = this.data.merge({
      placeholder: 'Enter a name...',
      enabled: true
    });
  }

  // Used to set the name state whenever the input
  // value changes.
  onChange = ({ target: { value } }) => {
    this.data = this.data.set('name', value);
  };

  // Renders a simple input element, that uses the
  // state of this component as properties.
  render() {
    const { enabled, name, placeholder } = this.data.toJS();

    return (
      <label htmlFor="my-input">
        Name:
        <input
          type="text"
          id="my-input"
          disabled={!enabled}
          placeholder={placeholder}
          value={name}
          onChange={this.onChange}
        />
      </label>
    );
  }
}
```

这个组件实际上不需要设置任何初始状态，因为它已经被 `BaseComponent` 设置了。由于状态已经是不可变的 `Map`，您可以在 `componentDidMount()` 中使用 `merge()` 调整初始状态。渲染输出如下所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/e02cbf22-0356-4bdc-9423-4f51752db9b3.png)

如果您删除输入元素中的默认文本，您会发现 `MyComponent` 添加到初始状态的占位文本会如预期般应用：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/fbbf16b0-ddb6-4f53-bd48-c3de4f29d678.png)

您还可以将文本更改为其他内容，`onChange()` 事件处理程序将相应地设置 `name` 状态。

# 继承属性

通过将默认属性值和属性类型定义为基类的静态属性，来实现属性继承。从这个基类继承的任何类也会继承属性值和属性规范。让我们来看一个基类的实现：

```jsx
import { Component } from 'react';
import PropTypes from 'prop-types';

export default class BaseComponent extends Component {
  // The specifiction for these base properties.
  static propTypes = {
    users: PropTypes.array.isRequired,
    groups: PropTypes.array.isRequired
  };

  // The default values of these base properties.
  static defaultProps = {
    users: [],
    groups: []
  };

  render() {
    return null;
  }
} 
```

这个类本身实际上并没有做任何事情。定义它的唯一原因是为了声明默认的属性值和它们的类型约束的地方。分别是`defaultProps`和`propTypes`静态类属性。

现在，让我们看一个继承这些属性的组件：

```jsx
import React from 'react';
import { Map } from 'immutable';

import BaseComponent from './BaseComponent';

// Renders the given "text" as a header, unless
// the given "length" is 0.
const SectionHeader = ({ text, length }) =>
  Map([[0, null]]).get(length, <h1>{text}>/h1>);

export default class MyComponent extends BaseComponent {
  render() {
    const { users, groups } = this.props;

    // Renders the "users" and "groups" arrays. There
    // are not property validators or default values
    // in this component, since these are declared in
    // "BaseComponent".
    return (
      <section>
        <SectionHeader text="Users" length={users.length} />
        <ul>{users.map(i => <li key={i}>{i}</li>)}</ul>

        <SectionHeader text="Groups" length={groups.length} />
        <ul>{groups.map(i => <li key={i}>{i}</li>)}</ul>
      </section>
    );
  }
}
```

让我们尝试渲染`MyComponent`以确保继承的属性按预期工作：

```jsx
import React from 'react';
import { render } from 'react-dom';

import ErrorBoundary from './ErrorBoundary';
import MyComponent from './MyComponent';

const users = ['User 1', 'User 2'];

const groups = ['Group 1', 'Group 2'];

render(
  <section>
    {/* Renders as expected, using the defaults. */}
    <ErrorBoundary>
      <MyComponent />
    </ErrorBoundary>

    {/* Renders as expected, using the "groups" default. */}
    <ErrorBoundary>
      <MyComponent users={users} />
      <hr />
    </ErrorBoundary>

    {/* Renders as expected, using the "users" default. */}
    <ErrorBoundary>
      <MyComponent groups={groups} />
      <hr />
    </ErrorBoundary>

    {/* Renders as expected, providing property values. */}
    <ErrorBoundary>
      <MyComponent users={users} groups={groups} />
    </ErrorBoundary>

    {/* Fails to render, the property validators in the base
         component detect the invalid number type. */}
    <ErrorBoundary>
      <MyComponent users={0} groups={0} />
    </ErrorBoundary>
  </section>,
  document.getElementById('root')
);

```

尽管`MyComponent`没有定义任何属性默认值或类型，但你会得到预期的行为。当你尝试将数字传递给`users`和`groups`属性时，你不会看到任何渲染。这是因为`MyComponent`期望这些属性值上有一个“map（）”方法，而实际上并没有。

这里使用`ErrorBoundary`元素来隔离错误。如果没有它们，任何`MyComponent`元素失败都会导致页面上的其他组件也失败，例如，通过将数字值传递给用户和组。下面是`ErrorBoundary`组件的样子：

```jsx
import { Component } from 'react';

// Uses the componentDidCatch() method to set the
// error state of this component. When rendering,
// if there's an error it gets logged and nothing
// is rendered.
export default class ErrorBoundary extends Component {
  state = { error: null };

  componentDidCatch(error) {
    this.setState({ error });
  }

  render() {
    if (this.state.error === null) {
      return this.props.children;
    } else {
      console.error(this.state.error);
      return null;
    }
  }
}
```

这个组件使用了你在第六章中学到的“componentDidCatch（）”生命周期方法。如果捕获到错误，它会设置错误状态，以便“render（）”方法知道不再渲染导致错误的组件。下面是渲染的内容：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/befae03e-b792-4887-8ac2-7a4d4f504e0c.png)

# 继承 JSX 和事件处理程序

在本节中，你将学习如何继承 JSX 和事件处理程序。如果你有一个单一的 UI 组件，它具有相同的 UI 元素和事件处理逻辑，但在组件使用的位置上初始状态有所不同，那么你可能想使用这种方法。

例如，一个基类会定义 JSX 和事件处理程序方法，而更具体的组件会定义特定于功能的初始状态。下面是一个基类的例子：

```jsx
import React, { Component } from 'react';
import { fromJS } from 'immutable';

export default class BaseComponent extends Component {
  state = {
    data: fromJS({
      items: []
    })
  };

  // Getter for "Immutable.js" state data...
  get data() {
    return this.state.data;
  }

  // Setter for "Immutable.js" state data...
  set data(data) {
    this.setState({ data });
  }

  // The click event handler for each item in the
  // list. The context is the lexically-bound to
  // this component.
  onClick = id => () => {
    this.data = this.data.update('items', items =>
      items.update(
        items.indexOf(items.find(i => i.get('id') === id)),
        item => item.update('done', d => !d)
      )
    );
  };

  // Renders a list of items based on the state
  // of the component. The style of the item
  // depends on the "done" property of the item.
  // Each item is assigned an event handler that
  // toggles the "done" state.
  render() {
    const { items } = this.data.toJS();

    return (
      <ul>
        {items.map(i => (
          <li
            key={i.id}
            onClick={this.onClick(i.id)}
            style={{
              cursor: 'pointer',
              textDecoration: i.done ? 'line-through' : 'none'
            }}
          >
            {i.name}
          </li>
        ))}
      </ul>
    );
  }
} 
```

这个基础组件渲染一个项目列表，当点击时，切换项目文本的样式。默认情况下，这个组件的状态有一个空的项目列表。这意味着可以安全地渲染这个组件，而不设置组件状态。然而，这并不是很有用，所以让我们通过继承基础组件并设置状态来给这个列表添加一些项目：

```jsx
import BaseComponent from './BaseComponent';

export default class MyComponent extends BaseComponent {
  // Initializes the component state, by using the
  // "data" getter method from "BaseComponent".
  componentDidMount() {
    this.data = this.data.merge({
      items: [
        { id: 1, name: 'One', done: false },
        { id: 2, name: 'Two', done: false },
        { id: 3, name: 'Three', done: false }
      ]
    });
  }
} 
```

`componentDidMount()`生命周期方法可以安全地设置组件的状态。基本组件使用您的`data`设置器/获取器来改变组件的状态。这种方法的另一个方便之处是，如果您想要覆盖基本组件的事件处理程序之一，您可以在`MyComponent`中定义该方法。

渲染时，列表的样子如下：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/3a20f49c-5d9d-441f-8cb3-0e358c5947fc.png)

当所有项目都被点击时，列表的样子如下：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/99c1b546-33c7-422f-8203-570bef2b79a7.png)

# 使用高阶组件进行组合

在本节中，您将了解**高阶组件**。如果您熟悉函数式编程中的高阶函数，高阶组件的工作方式是相同的。**高阶函数**是一个以另一个函数作为输入的函数，并返回一个新函数作为输出。返回的函数以某种方式调用原始函数。其思想是通过现有行为组合新行为。

使用高阶 React 组件，您有一个以组件作为输入的函数，并返回一个新组件作为输出。这是在 React 应用程序中组合新行为的首选方式，而且似乎许多流行的 React 库正在朝着这个方向发展，如果它们还没有的话。通过这种方式组合功能时，您会获得更多的灵活性。

# 条件组件渲染

高阶组件的一个用例是条件渲染。例如，根据谓词的结果，渲染组件或不渲染任何内容。谓词可以是特定于应用程序的任何内容，比如权限或类似的东西。

假设您有以下组件：

```jsx
import React from 'react';

// The world's simplest component...
export default () => <p>My component...</p>; 
```

现在，要控制此组件的显示，您可以用另一个组件包装它。包装由高阶函数处理。

如果在 React 的上下文中听到“包装器”这个术语，它可能指的是高阶组件。基本上，它的作用是包装您传递给它的组件。

现在，让我们创建一个高阶 React 组件：

```jsx
import React from 'react';

// A minimal higher-order function is all it
// takes to create a component repeater. Here, we're
// returning a function that calls "predicate()".
// If this returns true, then the rendered
// "<Component>" is returned.
export default (Component, predicate) => props =>
  predicate() && <Component {...props} />; 
```

这个函数的两个参数是`Component`，即您要包装的组件，和要调用的`predicate`。如果对`predicate()`的调用返回`true`，那么将返回`<Component>`。否则，将不会渲染任何内容。

现在，让我们实际使用这个函数来组合一个新的组件，以及渲染一个段落文本的组件：

```jsx
import React from 'react';
import { render } from 'react-dom';

import cond from './cond';
import MyComponent from './MyComponent';

// Two compositions of "MyComponent". The
// "ComposedVisible" version will render
// because the predicate returns true. The
// "ComposedHidden" version doesn't render.
const ComposedVisible = cond(MyComponent, () => true);
const ComposedHidden = cond(MyComponent, () => false);

render(
  <section>
    <h1>Visible</h1>
    <ComposedVisible />
    <h2>Hidden</h2>
    <ComposedHidden />
  </section>,
  document.getElementById('root')
); 
```

您刚刚使用`MyComponent`、`cond()`和`predicate`函数创建了两个新组件。这是渲染输出：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/5314290f-2c48-46df-b1b7-9a790269eb3b.png)

# 提供数据源

让我们通过查看一个更复杂的高阶组件示例来完成本章。您将实现一个数据存储函数，用数据源包装给定的组件。了解这种模式很有用，因为它被 React 库（如**Redux**）使用。这是用于包装组件的`connect()`函数：

```jsx
import React, { Component } from 'react';
import { fromJS } from 'immutable';

// The components that are connected to this store.
let components = fromJS([]);

// The state store itself, where application data is kept.
let store = fromJS({});

// Sets the state of the store, then sets the
// state of every connected component.
export function setState(state) {
  store = state;

  for (const component of components) {
    component.setState({
      data: store
    });
  }
}

// Returns the state of the store.
export function getState() {
  return store;
}

// Returns a higher-order component that's connected
// to the "store".
export function connect(ComposedComponent) {
  return class ConnectedComponent extends Component {
    state = { data: store };

    // When the component is mounted, add it to "components",
    // so that it will receive updates when the store state
    // changes.
    componentDidMount() {
      components = components.push(this);
    }

    // Deletes this component from "components" when it is
    // unmounted from the DOM.
    componentWillUnmount() {
      const index = components.findIndex(this);
      components = components.delete(index);
    }

    // Renders "ComposedComponent", using the "store" state
    // as properties.
    render() {
      return <ComposedComponent {...this.state.data.toJS()} />;
    }
  };
} 
```

这个模块定义了两个内部不可变对象：`components`和`store`。`components`列表保存了监听`store`变化的组件的引用。`store`代表整个应用程序状态。

存储的概念源自**Flux**，这是一组用于构建大规模 React 应用程序的架构模式。我将在本书中介绍 Flux 的想法，但 Flux 远远超出了本书的范围。

这个模块的重要部分是导出的函数：`setState()`，`getState()`和`connect()`。`getState()`函数简单地返回对数据存储的引用。`setState()`函数设置存储的状态，然后通知所有组件应用程序的状态已更改。`connect()`函数是一个高阶函数，用一个新的组件包装给定的组件。当组件被挂载时，它会在存储中注册自己，以便在存储更改状态时接收更新。它通过将`store`作为属性传递来呈现组合的组件。

现在，让我们使用这个实用程序来构建一个简单的过滤器和列表。首先是列表组件：

```jsx
import React from 'react';
import PropTypes from 'prop-types';

// Renders an item list...
const MyList = ({ filterValue, items }) => {
  const filter = new RegExp(filterValue, 'i');

  return (
    <ul>
      {items
        .filter(item => filter.test(item))
        .map(item => <li key={item}>{item}>/li>)}
    </ul>
  );
};

MyList.propTypes = {
  items: PropTypes.array.isRequired
};

export default MyList; 
```

有两个状态片段作为属性传递给这个组件。第一个是来自过滤文本输入的`filterValue`字符串。第二个是要过滤的值数组`items`。通过构建一个不区分大小写的正则表达式并在`filter()`内部使用它来进行过滤。然后，只有与`filterValue`匹配的项目才是这个组件的 JSX 输出的一部分。接下来，让我们看一下`MyInput`：

```jsx
import React from 'react';
import PropTypes from 'prop-types';
import { getState, setState } from './store';

// When the filter input value changes.
function onChange(e) {
  // Updates the state of the store.
  setState(getState().set('filterValue', e.target.value));
}

// Renders a simple input element to filter a list.
const MyInput = ({ value, placeholder }) => (
  <input
    autoFocus
    value={value}
    placeholder={placeholder}
    onChange={onChange}
  />
);

MyInput.propTypes = {
  value: PropTypes.string,
  placeholder: PropTypes.string
};

export default MyInput;
```

`MyInput`组件呈现一个`<input>`元素。`onChange()`处理程序的目标是过滤用户列表，以便仅显示包含当前输入文本的项目。它通过在文本输入更改时设置`filterValue`状态来实现此目的。这将导致`MyList`组件使用新的过滤值重新呈现以过滤项目。

这是渲染的过滤输入和项目列表的样子：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/5484c7d4-8726-42cf-9e9c-25bae93d685e.png)

# 摘要

在本章中，您了解了扩展现有组件的不同方法。您了解的第一种机制是继承。这是使用 ES2015 类语法完成的，对于实现常见方法或 JSX 标记非常有用。

然后，您了解了高阶组件，其中您使用函数来包装一个组件，以便为其提供新的功能。这是新的 React 应用程序正在向其移动的方向，而不是继承。

在下一章中，您将学习如何根据当前 URL 渲染组件。

# 测试你的知识

1.  何时应该继承组件状态？

1.  您不应该继承组件状态

1.  只有当您有许多不同的组件都共享相同的状态结构，但呈现不同的输出时

1.  只有当您想要在两个或更多组件之间共享状态时

1.  什么是高阶组件？

1.  由另一个组件渲染的组件

1.  功能组件的另一个名称

1.  返回另一个组件的组件

1.  如果您从组件继承 JSX，您应该覆盖什么？

1.  没有。您只是继承以为组件提供一个新名称。

1.  您应该只覆盖状态。

1.  您可以在**`componentDidMount()`**中将新的状态值传递给继承的组件。

# 进一步阅读

+   [`reactjs.org/docs/components-and-props.html`](https://reactjs.org/docs/components-and-props.html)


# 第九章：处理路由导航

几乎每个 Web 应用程序都需要**路由**：根据一组路由处理程序声明来响应 URL 的过程。换句话说，从 URL 到渲染内容的映射。然而，这个任务比起初看起来更加复杂。这就是为什么在本章中您将利用`react-router`包，这是 React 的*事实上*的路由工具。

首先，您将学习使用 JSX 语法声明路由的基础知识。然后，您将了解路由的动态方面，例如动态路径段和查询参数。接下来，您将使用`react-router`中的组件实现链接。

# 声明路由

使用`react-router`，您可以将路由与它们渲染的内容放在一起。在本节中，您将看到这是通过使用 JSX 语法来定义路由的。

您将创建一个基本的“hello world”示例路由，以便您可以看到在 React 应用程序中路由是什么样子的。然后，您将学习如何通过功能而不是在一个庞大的模块中组织路由声明。最后，您将实现一个常见的父子路由模式。

# Hello route

让我们创建一个简单的路由，以渲染一个简单的组件。首先，当路由被激活时，您有一个小的 React 组件要渲染：

```jsx
import React from 'react';

export default () => <p>Hello Route!</p>;
```

接下来，让我们看一下路由定义：

```jsx
import React from 'react';
import { render } from 'react-dom';
import { BrowserRouter as Router, Route } from 'react-router-dom';

import MyComponent from './MyComponent';

// The "<Router>" is the root element of the app.
render(
  <Router>
    <Route exact path="/" component={MyComponent} />
  </Router>,
  document.getElementById('root')
);

```

`Router`组件是应用程序的顶层组件。让我们来分解一下，了解路由器内部发生了什么。

您已经将实际路由声明为`<Route>`元素。任何路由的两个关键属性是`path`和`component`。当`path`与活动 URL 匹配时，将渲染`component`。但它到底是在哪里渲染的呢？`Router`组件实际上并不自己渲染任何内容；它负责根据当前 URL 管理其他组件的渲染方式。当您在浏览器中查看此示例时，`<MyComponent>`会如预期地被渲染：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/706173fb-153d-40f6-8b14-cfbf733b4ede.png)

当`path`属性与当前 URL 匹配时，`<Route>`将被`component`属性值替换。在这个例子中，路由将被`<MyComponent>`替换。如果给定路由不匹配，则不会渲染任何内容。

# 路由声明的解耦

路由的困难在于当你的应用程序在单个模块中声明了数十个路由时，因为更难将路由映射到功能上。

为了帮助实现这一点，应用程序的每个顶级功能都可以定义自己的路由。这样，清楚地知道哪些路由属于哪个功能。所以，让我们从`App`组件开始：

```jsx
import React, { Fragment } from 'react';
import {
  BrowserRouter as Router,
  Route,
  Redirect
} from 'react-router-dom';

// Import the routes from our features.
import One from './one';
import Two from './two';

// The feature routes are rendered as children of
// the main router.
export default () => (
  <Router>
    <Fragment>
      <Route exact path="/" render={() => <Redirect to="one" />} />
      <One />
      <Two />
    </Fragment>
  </Router>
); 
```

在这个例子中，应用程序有两个功能：`one` 和 `two`。这些被导入为组件并在`<Router>`内呈现。您必须包含`<Fragment>`元素，因为`<Router>`不喜欢有多个子元素。通过使用片段，您可以传递一个子元素，而不必使用不必要的 DOM 元素。这个路由器中的第一个子元素实际上是一个重定向。这意味着当应用程序首次加载 URL `/` 时，`<Redirect>`组件将把用户发送到 `/one`。`render`属性是`component`属性的替代品，当您需要调用一个函数来呈现内容时。您在这里使用它是因为您需要将属性传递给`<Redirect>`。

这个模块只会变得像应用程序功能的数量一样大，而不是路由的数量，后者可能会大得多。让我们来看看一个功能路由：

```jsx
import React, { Fragment } from 'react';
import { Route, Redirect } from 'react-router';

// The pages that make up feature "one".
import First from './First';
import Second from './Second';

// The routes of our feature. The "<Redirect>"
// handles "/one" requests by redirecting to "/one/1".
export default () => (
  <Fragment>
    <Route
      exact
      path="/one"
      render={() => <Redirect to="/one/1" />}
    />
    <Route exact path="/one/1" component={First} />
    <Route exact path="/one/2" component={Second} />
  </Fragment>
);
```

这个模块，`one/index.js`，导出一个呈现带有三个路由的片段的组件：

+   当匹配路径`/one`时，重定向到`/one/1`

+   当匹配路径`/one/1`时，呈现`First`组件

+   当匹配路径`/one/2`时，呈现`Second`组件

这遵循与路径`/`的`App`组件相同的模式。通常，您的应用程序实际上没有要在功能的根或应用程序本身的根处呈现的内容。这种模式允许您将用户发送到适当的路由和适当的内容。这是您首次加载应用程序时会看到的内容：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/bfcc12ba-2e40-47f0-a7c0-a83b8b16b798.png)

第二个功能遵循与第一个完全相同的模式。以下是组件的初始外观：

```jsx
import React from 'react';

export default () => (
  <p>Feature 1, page 1</p>
);
```

这个例子中的每个功能都使用相同的最小呈现内容。当用户导航到给定路由时，这些组件最终是用户需要看到的内容。通过以这种方式组织路由，您使得您的功能在路由方面是自包含的。

# 父级和子级路由

在前面的例子中，`App`组件是应用程序的主要组件。这是因为它定义了根 URL：`/`。然而，一旦用户导航到特定的功能 URL，`App`组件就不再相关了。

在`react-router`版本 4 之前的版本中，您可以嵌套您的`<Route>`元素，以便随着路径继续匹配当前 URL，相关组件被渲染。例如，路径`/users/8462`将具有嵌套的`<Route>`元素。在版本 4 及以上，`react-router`不再使用嵌套路由来处理子内容。相反，您有您通常的`App`组件。然后，使用`<Route>`元素来匹配当前 URL 的路径，以渲染`App`中的特定内容。

让我们看一下一个父级`App`组件，它使用`<Route>`元素来渲染子组件：

```jsx
import React from 'react';
import {
  BrowserRouter as Router,
  Route,
  NavLink
} from 'react-router-dom';

// The "User" components rendered with the "/users"
// route.
import UsersHeader from './users/UsersHeader';
import UsersMain from './users/UsersMain';

// The "Groups" components rendered with the "/groups"
// route.
import GroupsHeader from './groups/GroupsHeader';
import GroupsMain from './groups/GroupsMain';

// The "header" and "main" properties are the rendered
// components specified in the route. They're placed
// in the JSX of this component - "App".
const App = () => (
  <Router>
    <section>
      <nav>
        <NavLink
          exact
          to="/"
          style={{ padding: '0 10px' }}
          activeStyle={{ fontWeight: 'bold' }}
        >
          Home
        </NavLink>
        <NavLink
          exact
          to="/users"
          style={{ padding: '0 10px' }}
          activeStyle={{ fontWeight: 'bold' }}
        >
          Users
        </NavLink>
        <NavLink
          exact
          to="/groups"
          style={{ padding: '0 10px' }}
          activeStyle={{ fontWeight: 'bold' }}
        >
          Groups
        </NavLink>
      </nav>
      <header>
        <Route exact path="/" render={() => <h1>Home</h1>} />
        <Route exact path="/users" component={UsersHeader} />
        <Route exact path="/groups" component={GroupsHeader} />
      </header>
      <main>
        <Route exact path="/users" component={UsersMain} />
        <Route exact path="/groups" component={GroupsMain} />
      </main>
    </section>
  </Router>
);

export default App;
```

首先，`App`组件渲染一些导航链接。这些链接将始终可见。由于这些链接指向应用程序中的页面，您可以使用`NavLink`组件而不是`Link`组件。唯一的区别是，当其 URL 与当前 URL 匹配时，您可以使用`activeStyle`属性来改变链接的外观。

接下来，您有标题和主要部分。这是您使用`Route`组件来确定在`App`组件的这部分中渲染什么的地方。例如，`<header>`中的第一个路由使用`render`属性在用户位于应用程序的根目录时渲染标题。接下来的两个`Route`组件使用组件属性来渲染其他标题内容。在`<main>`中也使用相同的模式。

嵌套路由可能会很快变得混乱。通过声明路由的扁平结构，更容易扫描代码中的路由，以弄清发生了什么。

此应用程序有两个功能——`users`和`groups`。它们各自都有自己的`App`组件定义。例如，`UsersHeader`用于`<header>`，`UsersMain`用于`<main>`。

这是`UsersHeader`组件的样子：

```jsx
import React from 'react';

export default () => <h1>Users Header</h1>;
```

这是`UsersMain`组件的样子：

```jsx
import React from 'react';

export default () => <p>Users content...</p>;
```

在组中使用的组件几乎与这些完全相同。如果您运行此示例并导航到`/users`，您可以期望看到：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/f491f3ff-e3d4-4a58-9651-4fdc27098853.png)

# 处理路由参数

到目前为止，在本章中您所看到的 URL 都是静态的。大多数应用程序将同时使用静态和动态路由。在本节中，您将学习如何将动态 URL 段传递到您的组件中，如何使这些段可选，以及如何获取查询字符串参数。

# 路由中的资源 ID

一个常见的用例是将资源的 ID 作为 URL 的一部分。这样可以让您的代码轻松获取 ID，然后发出 API 调用以获取相关的资源数据。让我们实现一个渲染用户详细信息页面的路由。这将需要一个包含用户 ID 的路由，然后需要以某种方式将其传递给组件，以便它可以获取用户。

让我们从声明路由的`App`组件开始：

```jsx
import React, { Fragment } from 'react';
import { BrowserRouter as Router, Route } from 'react-router-dom';

import UsersContainer from './UsersContainer';
import UserContainer from './UserContainer';

export default () => (
  <Router>
    <Fragment>
      <Route exact path="/" component={UsersContainer} />
      <Route path="/users/:id" component={UserContainer} />
    </Fragment>
  </Router>
); 
```

`:`语法标记了 URL 变量的开始。`id`变量将传递给`UserContainer`组件，下面是它的实现方式：

```jsx
import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { fromJS } from 'immutable';

import User from './User';
import { fetchUser } from './api';

export default class UserContainer extends Component {
  state = {
    data: fromJS({
      error: null,
      first: null,
      last: null,
      age: null
    })
  };

  // Getter for "Immutable.js" state data...
  get data() {
    return this.state.data;
  }

  // Setter for "Immutable.js" state data...
  set data(data) {
    this.setState({ data });
  }

  componentDidMount() {
    // The dynamic URL segment we're interested in, "id",
    // is stored in the "params" property.
    const { match: { params: { id } } } = this.props;

    // Fetches a user based on the "id". Note that it's
    // converted to a number first.
    fetchUser(Number(id)).then(
      // If the user was successfully fetched, then
      // merge the user properties into the state. Also,
      // make sure that "error" is cleared.
      user => {
        this.data = this.data.merge(user, { error: null });
      },

      // If the user fetch failed, set the "error" state
      // to the resolved error value. Also, make sure the
      // other user properties are restored to their defaults
      // since the component is now in an error state.
      error => {
        this.data = this.data.merge({
          error,
          first: null,
          last: null,
          age: null
        });
      }
    );
  }

  render() {
    return <User {...this.data.toJS()} />;
  }
}

// Params should always be there...
UserContainer.propTypes = {
  match: PropTypes.object.isRequired
};
```

`match.params`属性包含 URL 的任何动态部分。在这种情况下，您对`id`参数感兴趣。然后，将此值的数字版本传递给`fetchUser()`API 调用。如果 URL 完全缺少该段，那么这段代码将根本不运行；路由器将恢复到`/`路由。但是，在路由级别没有进行类型检查，这意味着您需要处理传递非数字的地方期望数字等情况。

在这个例子中，如果用户导航到，例如，`/users/one`，类型转换操作将导致 500 错误。您可以编写一个函数来对参数进行类型检查，并且在出现异常时不会失败，而是响应 404：未找到错误。无论如何，提供有意义的失败模式取决于应用程序，而不是`react-router`库。

现在让我们看一下这个示例中使用的 API 函数：

```jsx
// Mock data...
const users = [
  { first: 'First 1', last: 'Last 1', age: 1 },
  { first: 'First 2', last: 'Last 2', age: 2 }
];

// Returns a promise that resolves the users array.
export function fetchUsers() {
  return new Promise((resolve, reject) => {
    resolve(users);
  });
}

// Returns a promise that resolves to a
// user from the "users" array, using the
// given "id" index. If nothing is found,
// the promise is rejected.
export function fetchUser(id) {
  const user = users[id];

  if (user === undefined) {
    return Promise.reject(`User ${id} not found`);
  } else {
    return Promise.resolve(user);
  }
}
```

`fetchUsers()`函数被`UsersContainer`组件使用来填充用户链接列表。`fetchUser()`函数将在模拟数据的`users`数组中查找并解析值，或者拒绝承诺。如果被拒绝，将调用`UserContainer`组件的错误处理行为。

这是负责渲染用户详细信息的`User`组件：

```jsx
import React from 'react';
import PropTypes from 'prop-types';
import { Map } from 'immutable';

// Renders "error" text, unless "error" is
// null - then nothing is rendered.
const Error = ({ error }) =>
  Map([[null, null]]).get(
    error,
    <p>
      <strong>{error}</strong>
    </p>
  );

// Renders "children" text, unless "children"
// is null - then nothing is rendered.
const Text = ({ children }) =>
  Map([[null, null]]).get(children, <p>{children}</p>);

const User = ({ error, first, last, age }) => (
  <section>
    {/* If there's an API error, display it. */}
    <Error error={error} />

    {/* If there's a first, last, or age value,
         display it. */}
    <Text>{first}</Text>
    <Text>{last}</Text>
    <Text>{age}</Text>
  </section>
);

// Every property is optional, since we might
// have have to render them.
User.propTypes = {
  error: PropTypes.string,
  first: PropTypes.string,
  last: PropTypes.string,
  age: PropTypes.number
};

export default User;
```

当您运行此应用程序并导航到`/`时，您应该看到一个用户列表，看起来像这样：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/b9cb8d10-3f29-43c5-936d-ab00b77d9acf.png)

点击第一个链接应该带您到`/users/0`，看起来像这样：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/bba66852-755f-4517-9f29-030d67c821ef.png)

如果您导航到一个不存在的用户，`/users/2`，您将看到以下内容：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/a4c67402-c41b-4884-9113-603701e443b1.png)

您看到这个错误消息而不是 500 错误的原因是因为 API 端点知道如何处理缺少的资源：

```jsx
if (user === undefined) {
  reject(`User ${id} not found`);
}
```

这导致`UserContainer`设置其错误状态：

```jsx
fetchUser(Number(id)).then(
  user => {
    this.data = this.data.merge(user, { error: null });
  },
  error => {
    this.data = this.data.merge({
      error,
      first: null,
      last: null,
      age: null
    });
  }
);
```

这样就导致`User`组件渲染错误消息：

```jsx
const Error = ({ error }) =>
  Map([[null, null]]).get(
    error,
    <p>
      <strong>{error}</strong>
    </p>
  );

const User = ({ error, first, last, age }) => (
  <section>
    <Error error={error} />
    ...
  </section>
);
```

# 可选参数

有时，您需要可选的 URL 路径值和查询参数。URL 对于简单选项效果最佳，如果组件可以使用许多值，则查询参数效果最佳。

让我们实现一个用户列表组件，它渲染用户列表。可选地，您希望能够按降序对列表进行排序。让我们将这作为此页面的路由定义的可选路径段：

```jsx
import React from 'react';
import { render } from 'react-dom';
import { BrowserRouter as Router, Route } from 'react-router-dom';

import UsersContainer from './UsersContainer';

render(
  <Router>
    <Route path="/users/:desc?" component={UsersContainer} />
  </Router>,
  document.getElementById('root')
); 
```

`:`语法标记一个变量，`?`后缀标记变量为可选。这意味着用户可以在`/users/`后提供任何他们想要的内容。这也意味着组件需要确保提供了字符串`desc`，并且忽略其他所有内容。

组件还需要处理提供给它的任何查询字符串。因此，虽然路由声明不提供定义接受的查询字符串的机制，但路由器仍将原始查询字符串传递给组件。现在让我们来看一下用户列表容器组件：

```jsx
import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { fromJS } from 'immutable';

import Users from './Users';
import { fetchUsers } from './api';

export default class UsersContainer extends Component {
  // The "users" state is an empty immutable list
  // by default.
  state = {
    data: fromJS({
      users: []
    })
  };

  // Getter for "Immutable.js" state data...
  get data() {
    return this.state.data;
  }

  // Setter for "Immutable.js" state data...
  set data(data) {
    this.setState({ data });
  }

  componentDidMount() {
    // The URL and query string data we need...
    const { match: { params }, location: { search } } = this.props;

    // If the "params.desc" value is "desc", it means that
    // "desc" is a URL segment. If "search.desc" is true, it
    // means "desc" was provided as a query parameter.
    const desc =
      params.desc === 'desc' ||
      !!new URLSearchParams(search).get('desc');

    // Tell the "fetchUsers()" API to sort in descending
    // order if the "desc" value is true.
    fetchUsers(desc).then(users => {
      this.data = this.data.set('users', users);
    });
  }

  render() {
    return <Users {...this.data.toJS()} />;
  }
}

UsersContainer.propTypes = {
  params: PropTypes.object.isRequired,
  location: PropTypes.object.isRequired
};

```

在`componentDidMount()`方法中，此组件查找`params.desc`或`search.desc`。它将此作为`fetchUsers()` API 的参数，以确定排序顺序。

`Users`组件如下所示：

```jsx
import React from 'react';
import PropTypes from 'prop-types';

// Renders a list of users...
const Users = ({ users }) => (
  <ul>{users.map(i => <li key={i}>{i}</li>)}</ul>
);

Users.propTypes = {
  users: PropTypes.array.isRequired
};

export default Users;
```

当您导航到`/users`时，将呈现如下内容：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/c2449b0a-5b34-44d4-9a7f-56e6f6ac5024.png)

如果您通过导航到`/users/desc`包含降序参数，我们会得到以下结果：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/d144b061-68fd-40c4-b239-cd96d7bc559b.png)

# 使用链接组件

在本节中，您将学习如何创建链接。您可能会尝试使用标准的`<a>`元素链接到由`react-router`控制的页面。这种方法的问题在于，这些链接将尝试通过发送 GET 请求在后端定位页面。这不是您想要的，因为路由配置已经在浏览器中。

首先，您将看到一个示例，说明`<Link>`元素在大多数方面都像`<a>`元素。然后，您将看到如何构建使用 URL 参数和查询参数的链接。

# 基本链接

在 React 应用程序中，链接的想法是它们指向指向渲染新内容的组件的路由。`Link`组件还负责浏览器历史 API 和查找路由/组件映射。这是一个渲染两个链接的应用程序组件：

```jsx
import React from 'react';
import {
  BrowserRouter as Router,
  Route,
  Link
} from 'react-router-dom';

import First from './First';
import Second from './Second';

const App = () => (
  <Router>
    <section>
      <nav>
        <p>
          <Link to="first">First</Link>
        </p>
        <p>
          <Link to="second">Second</Link>
        </p>
      </nav>
      <section>
        <Route path="/first" component={First} />
        <Route path="/second" component={Second} />
      </section>
    </section>
  </Router>
);

export default App; 
```

`to`属性指定点击时要激活的路由。在这种情况下，应用程序有两个路由—`/first`和`/second`。渲染的链接如下所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/7be082c0-38af-4ec5-9d89-70222dfddc86.png)

当您点击第一个链接时，页面内容会变成这样：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/0bffaa0a-9854-4fd7-9d5b-d271d4d311b3.png)

# URL 和查询参数

构建传递给`<Link>`的路径的动态段涉及字符串操作。路径的所有部分都放在`to`属性中。这意味着您必须编写更多的代码来构建字符串，但也意味着在路由器中发生的幕后魔术更少。

让我们创建一个简单的组件，它将回显传递给回声 URL 段或`echo`查询参数的任何内容：

```jsx
import React from 'react';
import { withRouter } from 'react-router';

// Simple component that expects either an "echo"
// URL segment parameter, or an "echo" query parameter.
export default withRouter(
  ({ match: { params }, location: { search } }) => (
    <h1>{params.msg || new URLSearchParams(search).get('msg')}</h1>
  )
); 
```

`withRouter()`实用程序函数是一个返回新组件的高阶函数。这个新组件将传递给它与路由相关的属性，如果你想要处理路径段变量或查询字符串，这些属性是必需的。你的`Echo`组件使用的两个属性是`match.params`用于 URL 路径变量和`location.search`用于查询字符串。

在`react-router`版本 4 之前，查询字符串被解析并作为对象传递。现在必须在您的代码中处理。在这个例子中，使用了`URLSearchParams`。

现在，让我们来看一下渲染两个链接的`App`组件。第一个将构建一个使用动态值作为 URL 参数的字符串。第二个将使用`URLSearchParams`来构建 URL 的查询字符串部分：

```jsx
import React from 'react';
import PropTypes from 'prop-types';
import { Link } from 'react-router-dom';

const App = ({ children }) => <section>{children}</section>;

App.propTypes = {
  children: PropTypes.node.isRequired
};

// Link parameter and query data...
const param = 'From Param';
const query = new URLSearchParams({ msg: 'From Query' });

App.defaultProps = {
  children: (
    <section>
      {/* This "<Link>" uses a paramter as part of
           the "to" property. */}
      <p>
        <Link to={`echo/${param}`}>Echo param</Link>
      </p>

      {/* This "<Link>" uses the "query" property
           to add query parameters to the link URL. */}
      <p>
        <Link to={`echo?${query.toString()}`} query={query}>
          Echo query
        </Link>
      </p>
    </section>
  )
};

export default App; 
```

当它们被渲染时，这两个链接看起来像这样：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/d894d61b-c4b7-4eea-a6b9-65611090e2aa.png)

参数链接将带您到`/echo/From Param`，看起来像这样：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/e8affd79-21f3-46a3-80d3-49488b8855dc.png)

查询链接将带您到`/echo?echo=From+Query`，看起来像这样：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/da41a9cd-d7d5-4a6b-96ca-9d7fcefa58f0.png)

# 总结

在本章中，您学习了 React 应用程序中的路由。路由的工作是渲染与 URL 对应的内容。`react-router`包是这项工作的标准工具。

您学会了路由是 JSX 元素，就像它们渲染的组件一样。有时，您需要将路由拆分为基于特性的模块。结构化页面内容的常见模式是有一个父组件，根据 URL 的变化来渲染动态部分。

您学会了如何处理 URL 段和查询字符串的动态部分。您还学会了如何使用`<Link>`元素在整个应用程序中构建链接。

在下一章中，您将学习如何在 Node.js 中呈现 React 组件。

# 测试您的知识

1.  `react-router`包是 React 应用程序中用于路由的官方包，因此是唯一的选择。

1.  是的，`react-router`是官方的 React 路由解决方案。

1.  不，`react-router`是多个路由选项之一，您应该花时间查看每个选项。

1.  不，**`react-router`**是 React 的事实标准路由解决方案，除非您有充分的理由不使用它。

1.  `Route`和`Router`组件之间有什么区别？

1.  **`Route`**用于根据 URL 匹配呈现组件，**`Router`**用于声明路由-组件映射。

1.  没有区别。

1.  每个组件都应该声明一个`Router`，以声明组件使用的路由。

1.  当路由更改时，如何仅更改 UI 的某些部分？

1.  您不能仅更改某些部分，必须重新呈现整个组件树，从根开始。

1.  您使用**`Route`**组件根据提供的**`path`**属性呈现特定于任何给定部分的内容。您可以有多个具有相同**`path`**值的**`Route`**。

1.  您将部分名称作为属性值传递给`Route`组件，以及要为该部分呈现的组件。

1.  何时应该使用`NavLink`组件？

1.  当您希望`react-router`自动为您设置活动链接的样式时。

1.  向用户显示哪些链接是导航链接，哪些是常规链接。

1.  当您想要使用**`activeStyle`**或**`activeClassName`**属性为活动链接设置样式时。

1.  如何从 URL 路径中获取值？

1.  您可以通过传递段的索引来获取任何 URL 路径段的值。

1.  您必须自己解析 URL 并找到值。

1.  您使用**`:`**语法来指定这是一个变量，**`react-router`**将此值作为属性传递给您的组件。

# 进一步阅读

有关更多信息，请参考以下链接：

+   [`reacttraining.com/react-router/`](https://reacttraining.com/react-router/)

+   [`developer.mozilla.org/en-US/docs/Web/API/URLSearchParams`](https://developer.mozilla.org/en-US/docs/Web/API/URLSearchParams)


# 第十章：服务器端 React 组件

到目前为止，你在本书中学到的所有内容都是在 Web 浏览器中运行的 React 代码。React 并不局限于浏览器进行渲染，在本章中，你将学习如何从 Node.js 服务器渲染组件。

本章的第一部分简要介绍了高级服务器渲染概念。接下来的四个部分将深入探讨，教你如何使用 React 和 Next.js 实现服务器端渲染的最关键方面。

# 什么是同构 JavaScript？

**服务器端渲染**的另一个术语是**同构 JavaScript**。这是一种花哨的说法，表示 JavaScript 代码可以在浏览器和 Node.js 中运行，而无需修改。在本节中，你将学习同构 JavaScript 的基本概念，然后深入到代码中。

# 服务器是一个渲染目标

React 的美妙之处在于它是一个小的抽象层，位于渲染目标的顶部。到目前为止，目标一直是浏览器，但也可以是服务器。渲染目标可以是任何东西，只要在幕后实现了正确的翻译调用。

在服务器上进行渲染时，组件被渲染为字符串。服务器实际上无法显示渲染的 HTML；它所能做的就是将渲染的标记发送到浏览器。这个想法在下图中有所说明：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/77166a87-3979-4c13-ba5d-00af63f94795.png)

在服务器上渲染 React 组件并将渲染输出发送到浏览器是可能的。问题是，为什么你想在服务器上这样做，而不是在浏览器上呢？

# 初始加载性能

对我个人来说，服务器端渲染背后的主要动机是提高性能。特别是，初始渲染对用户来说感觉更快，这会转化为更好的用户体验。一旦应用程序加载并准备就绪，它有多快并不重要；初始加载时间对用户留下了深刻的印象。

这种方法有三个原因可以提高初始加载的性能：

+   在服务器上进行的渲染生成了一个字符串；不需要计算差异或以任何方式与 DOM 交互。生成一串渲染标记的速度本质上比在浏览器中渲染组件要快。

+   呈现的 HTML 一旦到达就会显示。任何需要在初始加载时运行的 JavaScript 代码都是在用户已经看到内容之后运行的。

+   从 API 获取数据的网络请求更少，因为这些请求已经在服务器上发生，而服务器通常比单个客户端拥有更多的资源。

以下图表说明了这些性能思想：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/8c12fc51-253b-43fa-871b-cdae1b6a5f38.png)

# 在服务器和浏览器之间共享代码

你的应用程序很有可能需要与你无法控制的 API 端点进行通信，例如，由许多不同的微服务端点组成的应用程序。很少有可能直接使用这些服务的数据而不经过修改。相反，你需要编写代码来转换数据，以便 React 组件可以使用。

如果你在 Node.js 服务器上呈现你的组件，那么这个数据转换代码将被客户端和服务器同时使用，因为在初始加载时，服务器需要与 API 通信，而后来浏览器中的组件需要与 API 通信。

这不仅仅是关于转换从这些服务返回的数据。例如，你还需要考虑提供给它们的输入，比如创建或修改资源时。

作为 React 程序员，你需要做的基本调整是假设你实现的任何组件都需要在服务器上呈现。这可能看起来像是一个小的调整，但细节中藏着魔鬼。说到细节，现在让我们来看一些代码示例。

# 呈现为字符串

在 Node.js 中呈现组件意味着呈现为字符串，而不是试图找出将它们插入 DOM 的最佳方法。然后将字符串内容返回给浏览器，浏览器立即显示给用户。让我们来看一个例子。首先，要呈现的组件：

```jsx
import React from 'react';
import PropTypes from 'prop-types';

const App = ({ items }) => (
  <ul>{items.map(i => <li key={i}>{i}</li>)}</ul>
);

App.propTypes = {
  items: PropTypes.arrayOf(PropTypes.string).isRequired
};

export default App;
```

接下来，让我们实现服务器，当浏览器请求时，它将呈现这个组件：

```jsx
import React from 'react';

// The "renderToString()" function is like "render()",
// except it returns a rendered HTML string instead of
// manipulating the DOM.
import { renderToString } from 'react-dom/server';
import express from 'express';

// The component that we're going to render as a string.
import App from './App';

// The "doc()" function takes the rendered "content"
// of a React component and inserts it into an
// HTML document skeleton.
const doc = content =>
  `
  <!doctype html>
  <html>
    <head>
      <title>Rendering to strings</title>
    </head>
    <body>
      <div id="app">${content}</div>
    </body>
  </html>
  `;

const app = express();

// The root URL of the APP, returns the rendered
// React component.
app.get('/', (req, res) => {
  // Some properties to render...
  const props = {
    items: ['One', 'Two', 'Three']
  };

  // Render the "App" component using
  // "renderToString()"
  const rendered = renderToString(<App {...props} />);

  // Use the "doc()" function to build the final
  // HTML that is sent to the browser.
  res.send(doc(rendered));
});

app.listen(8080, () => {
  console.log('Listening on 127.0.0.1:8080');
});
```

现在，如果你在浏览器中访问[`127.0.0.1:8080`](http://127.0.0.1:8080)，你会看到呈现的组件内容：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/5aef47b3-ea22-473b-a86f-b38551709050.png)

在这个例子中有两件事情需要注意。首先是`doc()`函数。它创建了带有渲染的 React 内容占位符的基本 HTML 文档模板。第二个是对`renderToString()`的调用，就像你习惯的`render()`调用一样。这是在服务器请求处理程序中调用的，渲染的字符串被发送到浏览器。

# 后端路由

在前面的例子中，你在服务器上实现了一个单一的请求处理程序，用于响应根 URL(`/`)的请求。你的应用程序需要处理不止一个路由。在上一章中，你学会了如何在路由中使用`react-router`包。现在，你将看到如何在 Node.js 中使用相同的包。 

首先，让我们看一下主要的`App`组件：

```jsx
import React from 'react';
import { Route, Link } from 'react-router-dom';

import FirstHeader from './first/FirstHeader';
import FirstContent from './first/FirstContent';
import SecondHeader from './second/SecondHeader';
import SecondContent from './second/SecondContent';

export default () => (
  <section>
    <header>
      <Route exact path="/" render={() => <h1>App</h1>} />
      <Route exact path="/first" component={FirstHeader} />
      <Route exact path="/second" component={SecondHeader} />
    </header>
    <main>
      <Route
        exact
        path="/"
        render={() => (
          <ul>
            <li>
              <Link to="first">First</Link>
            </li>
            <li>
              <Link to="second">Second</Link>
            </li>
          </ul>
        )}
      />
      <Route exact path="/first" component={FirstContent} />
      <Route exact path="/second" component={SecondContent} />
    </main>
  </section>
); 
```

这个应用程序处理三条路线：

+   `/`：首页

+   `/first`：第一页内容

+   `/second`：第二页内容

`App`内容分为`<header>`和`<main>`元素。在每个部分中，都有一个处理适当内容的`<Route>`组件。例如，`/`路由的主要内容由一个`render()`函数处理，该函数呈现到`/first`和`/second`的链接。

这个组件在客户端上可以正常工作，但在服务器上会工作吗？让我们现在实现一下：

```jsx
import React from 'react';
import { renderToString } from 'react-dom/server';
import { StaticRouter } from 'react-router';
import express from 'express';

import App from './App';

const app = express();

app.get('/*', (req, res) => {
  const context = {};
  const html = renderToString(
    <StaticRouter location={req.url} context={context}>
      <App />
    </StaticRouter>
  );

  if (context.url) {
    res.writeHead(301, {
      Location: context.url
    });
    res.end();
  } else {
    res.write(`
      <!doctype html>
      <div id="app">${html}</div>
    `);
    res.end();
  }
});

app.listen(8080, () => {
  console.log('Listening on 127.0.0.1:8080');
}); 
```

现在你有了前端和后端路由！这到底是如何工作的？让我们从请求处理程序路径开始。这已经改变了，现在是通配符(`/*`)。现在这个处理程序会对每个请求进行调用。

在服务器上，使用`<StaticRouter>`组件代替`<BrowserRouter>`组件。`<App>`组件是子组件，这意味着其中的`<Route>`组件将从`<StaticRouter>`传递数据。这就是`<App>`如何知道根据 URL 呈现正确的内容。调用`renderToString()`得到的`html`值可以作为发送给浏览器的响应文档的一部分。

现在你的应用程序开始看起来像一个真正的端到端的 React 渲染解决方案。这是服务器在你访问根 URL`/`时呈现的内容：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/03d2aca6-d30c-4897-b196-9aa3731215e8.png)

如果你访问`/second` URL，Node.js 服务器将呈现正确的组件：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/7d9175f8-7617-4d54-b069-a128b4861e32.png)

如果您从主页导航到第一页，则请求将返回到服务器。我们需要弄清楚如何将前端代码传递到浏览器，以便它可以在初始呈现后接管。

# 前端协调

上一个示例中缺少的唯一内容是客户端 JavaScript 代码。用户希望使用应用程序，服务器需要传递客户端代码包。这将如何工作？路由必须在浏览器和服务器上工作，而不需要修改路由。换句话说，服务器处理初始请求的路由，然后浏览器在用户开始点击和在应用程序中移动时接管。

让我们为这个示例创建`index.js`模块：

```jsx
import React from 'react';
import { hydrate } from 'react-dom';

import App from './App';

hydrate(<App />, document.getElementById('root')); 
```

这看起来像本书中迄今为止您所见过的大多数`index.js`文件。您在 HTML 文档的根元素中呈现`<App>`组件。在这种情况下，您使用`hydrate()`函数而不是`render()`函数。这两个函数的最终结果是相同的——在浏览器窗口中呈现的 JSX 内容。`hydrate()`函数不同，因为它期望已经放置了呈现的组件内容。这意味着它将执行更少的工作，因为它将假定标记是正确的，不需要在初始呈现时进行更新。

只有在开发模式下，React 才会检查服务器呈现内容的整个 DOM 树，以确保显示正确的内容。如果现有内容与 React 组件的输出之间存在不匹配，您将看到警告，显示出现不匹配的位置，以便您可以去修复它们。

这是您的应用程序将在浏览器和 Node.js 服务器上呈现的`App`组件：

```jsx
import React, { Component } from 'react';

export default class App extends Component {
  state = { clicks: 0 };

  render() {
    return (
      <section>
        <header>
          <h1>Hydrating The Client</h1>
        </header>
        <main>
          <p>Clicks {this.state.clicks}</p>
          <button
            onClick={() =>
              this.setState(state => ({ clicks: state.clicks + 1 }))
            }
          >
            Click Me
          </button>
        </main>
      </section>
    );
  }
}
```

该组件呈现一个按钮，当点击时，将更新`clicks`状态。该状态在按钮上方的标签中呈现。当此组件在服务器上呈现时，将使用默认的点击值 0，并且`onClick`处理程序将被忽略，因为它只是呈现静态标记。让我们接下来看一下服务器端的代码：

```jsx
import fs from 'fs';
import React from 'react';
import { renderToString } from 'react-dom/server';
import express from 'express';

import App from './App';

const app = express();
const doc = fs.readFileSync('./build/index.html');

app.use(express.static('./build', { index: false }));

app.get('/*', (req, res) => {
  const context = {};
  const html = renderToString(<App />);

  if (context.url) {
    res.writeHead(301, {
      Location: context.url
    });
    res.end();
  } else {
    res.write(
      doc
        .toString()
        .replace('<div id="root">', `<div id="root">${html}`)
    );
    res.end();
  }
});

app.listen(8080, () => {
  console.log('Listening on 127.0.0.1:8080');
});
```

让我们浏览一下这个源代码，看看发生了什么：

```jsx
const doc = fs.readFileSync('./build/index.html');
```

这读取由您的 React 构建工具（如`create-react-app/react-scripts`）创建的`index.html`文件，并将其存储在`doc`中：

```jsx
app.use(express.static('./build', { index: false }));
```

这告诉 Express 服务器将`./build`下的文件作为静态文件提供，除了`index.html`。相反，您将编写一个处理程序，以响应站点根目录的请求：

```jsx
app.get('/*', (req, res) => {
  const context = {};
  const html = renderToString(<App />);

  if (context.url) {
    res.writeHead(301, {
      Location: context.url
    });
    res.end();
  } else {
    res.write(
      doc
        .toString()
        .replace('<div id="root">', `<div id="root">${html}`)
    );
    res.end();
  }
});
```

这是 `html` 常量被填充为渲染的 React 内容的地方。然后，它被插入到 HTML 字符串中使用 `replace()`，并作为响应发送。因为你使用了基于构建的 `index.html` 文件，它包含了一个链接到捆绑的 React 应用程序，当在浏览器中加载时将运行。

# 获取数据

如果你的某个组件在完全渲染其内容之前需要获取 API 数据怎么办？这对于在服务器上渲染来说是一个挑战，因为没有简单的方法来定义一个组件，它知道何时在服务器上以及在浏览器中获取数据。

这就是像 **Next.js** 这样的最小化框架发挥作用的地方。Next.js 将服务器渲染和浏览器渲染视为相等。这意味着组件获取数据的麻烦被抽象化了 - 你可以在浏览器和服务器上使用相同的代码。

本书的上一版没有使用任何框架来在服务器上获取 React 组件数据。我认为，如果你要走这条路，不使用框架是一个错误。有太多事情可能会出错，而且没有框架，最终你将对它们负责。

为了处理路由，Next.js 使用页面的概念。**页面** 是一个导出 React 组件的 JavaScript 模块。组件的渲染内容变成页面内容。以下是 `pages` 目录的样子：

```jsx
└── pages
 ├── first.js ├── index.js └── second.js
```

`index.js` 模块是应用程序的根页面：Next.js 根据文件名知道这一点。以下是源代码的样子：

```jsx
import Layout from '../components/MyLayout.js';

export default () => (
  <Layout>
    <p>Fetching component data on the server and on the client...</p>
  </Layout>
);
```

这个页面使用了 `<Layout>` 组件来确保通用组件被渲染，而不需要重复代码。渲染后页面的样子如下：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/238b9e43-d07f-4e63-9f20-57656db13039.png)

除了段落之外，整个应用程序布局还包括导航链接到其他页面。以下是 `Layout` 的源代码样子：

```jsx
import Header from './Header';

const layoutStyle = {
  margin: 20,
  padding: 20,
  border: '1px solid #DDD'
};

const Layout = props => (
  <div style={layoutStyle}>
    <Header />
    {props.children}
  </div>
);

export default Layout;
```

`Layout` 组件渲染一个 `Header` 组件和 `props.children`。`children` 属性是你在页面中传递给 `Layout` 组件的值。现在让我们来看一下 `Header` 组件：

```jsx
import Link from 'next/link';

const linkStyle = {
  marginRight: 15
};

const Header = () => (
  <div>
    <Link href="/">
      <a style={linkStyle}>Home</a>
    </Link>
    <Link href="/first">
      <a style={linkStyle}>First</a>
    </Link>
    <Link href="/second">
      <a style={linkStyle}>Second</a>
    </Link>
  </div>
);

export default Header;
```

这里使用的 `Link` 组件来自于 Next.js。这样，链接就可以按照 Next.js 自动设置的路由正常工作。现在让我们看一个有数据获取要求的页面 - `pages/first.js`：

```jsx
import fetch from 'isomorphic-unfetch';
import Layout from '../components/MyLayout.js';
import { fetchFirstItems } from '../api';

const First = ({ items }) => (
  <Layout>{items.map(i => <li key={i}>{i}</li>)}</Layout>
);

First.getInitialProps = async () => {
  const res = await fetchFirstItems();
  const items = await res.json();

  return { items };
};

export default First;
```

`fetch()` 函数用于获取数据，来自于 `isomorphic-unfetch` 包。这个版本的 `fetch()` 在服务器和浏览器上都可以使用，你不需要检查任何东西。再次强调，`Layout` 组件用于包装页面内容，以保持与其他页面的一致性。

`getInitialProps()` 函数是 Next.js 获取数据的方式——在浏览器和服务器上。这是一个异步函数，意味着你可以花费尽可能长的时间来获取组件属性的数据，而 Next.js 将确保在数据准备好之前不呈现任何标记。让我们来看看 `fetchFirstItems()` API 函数：

```jsx
export default () =>
  new Promise(resolve =>
    setTimeout(() => {
      resolve({
        json: () => Promise.resolve(['One', 'Two', 'Three'])
      });
    }, 1000)
  );
```

这个函数通过返回一个在 1 秒后解析出组件数据的 promise 来模拟 API 的行为。如果你导航到 `/first`，你将在 1 秒后看到以下内容：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/05bfede2-4c36-4470-bc1f-787d72611acf.png)

通过点击第一个链接，你导致了在浏览器中调用 `getInitialProps()` 函数，因为应用程序已经被交付。如果你在 `/first` 页面重新加载页面，你将触发在服务器上调用 `getInitialProps()`，因为这是 Next.js 在服务器上处理的页面。

# 摘要

在本章中，你了解到 React 除了在客户端上渲染外，还可以在服务器上渲染。这样做的原因有很多，比如在前端和后端之间共享通用代码。服务器端渲染的主要优势是在初始页面加载时获得的性能提升。这将转化为更好的用户体验，因此也是更好的产品。

然后，你逐步改进了一个服务器端的 React 应用程序，从单页面渲染开始。然后介绍了路由、客户端协调和组件数据获取，以使用 Next.js 实现完整的后端渲染解决方案。

在接下来的章节中，你将学习如何实现 React Bootstrap 组件来实现移动优先设计。

# 测试你的知识

1.  `react-dom` 中的 `render()` 函数和 `react-dom/server` 中的 `renderToString()` 函数有什么区别？

1.  `render()` 函数仅用于在浏览器中将 React 组件内容与 DOM 同步。`renderToString()` 函数不需要 DOM，因为它将标记呈现为字符串。

1.  这两个函数是可以互换的。

1.  `render()` 函数在服务器上速度较慢，所以 `renderToString()` 是一个更好的选择。

1.  如果必须，应该只在浏览器中使用`render()`。在大多数情况下，`renderToString()`函数更可取。

1.  在服务器上进行路由是必要的，因为：

1.  在服务器上没有路由，实际上无法渲染组件。

1.  您不需要担心在服务器上进行渲染，因为路由将在浏览器中处理。

1.  服务器上的路由将根据请求的 URL 确定渲染的内容。然后将此内容发送到浏览器，以便用户感知到更快的加载时间。

1.  在服务器上进行路由应该手动完成，而不是使用 react-router 中的组件。

1.  在调和服务器渲染的 React 标记与浏览器中的 React 组件时，应该使用哪个函数？

1.  始终在浏览器中使用`render()`。它知道如何对现有标记进行必要的更改。

1.  始终在服务器发送渲染的 React 组件时使用`hydrate()`。与`render()`不同，`hydrate()`期望渲染的组件标记并且可以高效处理它。

# 进一步阅读

查看以下链接以获取更多信息：

+   [`reactjs.org/docs/react-dom-server.html`](https://reactjs.org/docs/react-dom-server.html)

+   [`reacttraining.com/react-router/core/api/StaticRouter`](https://reacttraining.com/react-router/core/api/StaticRouter)

+   [`nextjs.org/learn/`](https://nextjs.org/learn/)


# 第十一章：移动优先 React 组件

在本章中，您将学习如何使用`react-bootstrap`包。该包通过利用 Bootstrap CSS 框架提供移动优先的 React 组件。这不是进行移动优先 React 的唯一选择，但这是一个不错的选择，并且它将网络上最流行的两种技术结合在一起。

我将从采用移动优先设计策略的动机开始。然后您将在本章的其余部分中实现一些`react-bootstrap`组件。

# 移动优先设计背后的原理

移动优先设计是一种将移动设备视为用户界面的主要目标的策略。较大的屏幕，如笔记本电脑或大型显示器，是次要目标。这并不一定意味着大多数用户在手机上访问您的应用程序。这只是意味着移动设备是缩放用户界面的起点。

例如，当移动浏览器首次出现时，习惯上是为普通桌面屏幕设计用户界面，然后在必要时缩小到较小的屏幕。该方法如下所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/b280ba0f-34ce-4d9d-8ad7-ba20ff26b511.png)

这里的想法是，您设计 UI 时要考虑较大的屏幕，以便一次性将尽可能多的功能放在屏幕上。当使用较小的设备时，您的代码必须在运行时使用不同的布局或不同的组件。

这在许多方面都是非常有限的。首先，对于不同的屏幕分辨率，维护大量特殊情况处理的代码非常困难。其次，更具有说服力的反对这种方法的论点是，几乎不可能在不同设备上提供类似的用户体验。如果大屏幕一次显示大量功能，您简单无法在较小的屏幕上复制这一点。不仅是屏幕空间较小，而且较小设备的处理能力和网络带宽也是限制因素。

UI 设计的移动优先方法通过放大 UI 来解决这些问题，而不是试图缩小 UI，如下所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/a0669383-dc7c-41c3-816f-5666d856f7aa.png)

这种方法以前是没有意义的，因为你会限制你的应用程序的功能；周围没有很多平板电脑或手机。但今天情况不同了，人们期望用户能够在他们的移动设备上与应用程序进行交互而不会出现任何问题。现在有更多的移动设备了，移动浏览器完全能够处理你提出的任何要求。

一旦你在移动环境中实现了应用程序功能，将其扩展到更大的屏幕尺寸就是一个相对容易解决的问题。现在，让我们看看如何在 React 应用程序中实现移动优先。

# 使用 react-bootstrap 组件

虽然可以通过自己编写 CSS 来实现移动优先的 React 用户界面，但我建议不要这样做。有许多 CSS 库可以为你处理看似无穷无尽的边缘情况。在这一部分，我将介绍`react-bootstrap`包——Bootstrap 的 React 组件。

`react-bootstrap`包公开了许多组件，它们在你的应用程序和 Bootstrap HTML/CSS 之间提供了一个薄的抽象层。

现在让我们实现一些示例。我向你展示如何使用`react-bootstrap`组件的另一个原因是它们与`react-native`组件相似，你将在下一章中学习到。

以下示例的重点不是深入覆盖`react-bootstrap`，或者 Bootstrap 本身。相反，重点是让你感受一下通过从容器传递状态等方式在 React 中使用移动优先组件的感觉。现在，先看一下`react-bootstrap`文档（[`react-bootstrap.github.io/`](http://react-bootstrap.github.io/)）了解具体内容。

# 实现导航

移动优先设计的最重要方面是导航。在移动设备上很难做到这一点，因为几乎没有足够的空间来放置功能内容，更别提从一个功能到另一个功能的工具了。幸运的是，Bootstrap 为你处理了许多困难。

在这一部分，你将学习如何实现两种类型的导航。你将从工具栏导航开始，然后构建一个侧边栏导航部分。这构成了你将开始的 UI 骨架的一部分。我发现这种方法真的很有用，因为一旦导航机制就位，我在构建应用程序时很容易添加新页面和在应用程序中移动。

让我们从`Navbar.`开始。这是大多数应用程序中的一个组件，静态地位于屏幕顶部。在这个栏中，你将添加一些导航链接。这是这个 JSX 的样子：

```jsx
{/* The "NavBar" is statically-placed across the
   top of every page. It contains things like the
   title of the application, and menu items. */}
<Navbar className="navbar-top" fluid>
  <Navbar.Header>
    <Navbar.Brand>
      <Link to="/">Mobile-First React</Link>
    </Navbar.Brand>

    {/* The "<Navbar.Taggle>" coponent is used to replace any
       navigation links with a drop-down menu for smaller
       screens. */}
    <Navbar.Toggle />
  </Navbar.Header>

  {/* The actual menu with links to makes. It's wrapped
     in the "<Navbar.Collapse>"" component so that it
     work properly when the links have been collapsed. */}
  <Navbar.Collapse>
    <Nav pullRight>
      <IndexLinkContainer to="/">
        <MenuItem>Home</MenuItem>
      </IndexLinkContainer>
      <LinkContainer to="forms">
        <MenuItem>Forms</MenuItem>
      </LinkContainer>
      <LinkContainer to="lists">
        <MenuItem>Lists</MenuItem>
      </LinkContainer>
    </Nav>
  </Navbar.Collapse>
</Navbar> 
```

导航栏的样子如下：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/6ecf6e39-4aed-4963-be2c-94291f0e21b9.png)

`<Navbar.Header>`组件定义了应用程序的标题，并放置在导航栏的左侧。链接本身放在`<Nav>`元素中，`pullRight`属性将它们对齐到导航栏的右侧。你可以看到，你没有使用`react-router`包中的`<Link>`，而是使用了`<LinkContainer>`和`<IndexLinkContainer>`。这些组件来自`react-router-bootstrap`包。它们是必要的，以使 Bootstrap 链接与路由器正常工作。

`<Nav>`元素被包裹在`<Navbar.Collapse>`元素中，头部包含一个`<Navbar.Toggle>`按钮。这些组件是必要的，用于将链接折叠成下拉菜单以适应较小的屏幕。由于它是基于浏览器的宽度，你可以调整浏览器窗口大小来看它的效果：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/54cb73bc-0763-4256-8a2a-629cc125783b.png)

显示的链接现在已经折叠成了一个标准菜单按钮。当点击这个按钮时，相同的链接以垂直方式显示。这在较小的设备上效果更好。但是在较大的屏幕上，将所有导航显示在顶部导航栏可能不是理想的。标准的方法是实现一个带有垂直堆叠导航链接的左侧边栏。让我们现在来实现这个：

```jsx
{/* This navigation menu has the same links
   as the top navbar. The difference is that
   this navigation is a sidebar. It's completely
   hidden on smaller screens. */}
<Col sm={3} md={2} className="sidebar">
  <Nav stacked>
    <IndexLinkContainer to="/">
      <NavItem>Home</NavItem>
    </IndexLinkContainer>
    <LinkContainer to="forms">
      <NavItem>Forms</NavItem>
    </LinkContainer>
    <LinkContainer to="lists">
      <NavItem>Lists</NavItem>
    </LinkContainer>
  </Nav>
</Col> 
```

`<Col>`元素是`<Nav>`的容器，你已经给它添加了自己的类名。你马上就会明白为什么要这样做。在`<Nav>`元素内部，事情看起来和导航工具栏中一样，有链接容器和菜单项。这就是侧边栏的样子：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/16781823-18a2-4b58-a9be-8e3eb1e93751.png)

现在，我们需要给包含元素添加自定义的`sidebar`类名的原因是为了在较小的设备上完全隐藏它。让我们来看一下涉及的 CSS：

```jsx
.sidebar { 
  display: none; 
} 

@media (min-width: 768px) { 
  .sidebar { 
    display: block; 
    position: fixed; 
    top: 60px; 
  } 
} 
```

这个 CSS，以及这个示例的整体结构，都是从 Bootstrap 示例中调整而来：[`getbootstrap.com/examples/dashboard/`](http://getbootstrap.com/examples/dashboard/)。这个媒体查询的背后思想是，如果最小浏览器宽度为`768px`，那么在固定位置显示侧边栏。否则，完全隐藏它，因为我们在一个较小的屏幕上。

在这一点上，您有两个导航组件相互协作，根据屏幕分辨率改变它们的显示方式。

# 列表

在移动和桌面环境中，一个常见的 UI 元素是渲染项目列表。这很容易在没有 CSS 库的支持下完成，但库有助于保持外观和感觉一致。让我们实现一个由一组过滤器控制的列表。首先，您有渲染`react-bootstrap`组件的组件：

```jsx
import React from 'react';
import PropTypes from 'prop-types';

import {
  Button,
  ButtonGroup,
  ListGroupItem,
  ListGroup,
  Glyphicon
} from 'react-bootstrap';

import './FilteredList.css';

// Utility function to get the bootstrap style
// for an item, based on the "done" value.
const itemStyle = done => (done ? { bsStyle: 'success' } : {});

// Utility component for rendering a bootstrap
// icon based on the value of "done".
const ItemIcon = ({ done }) =>
  done ? <Glyphicon glyph="ok" className="item-done" /> : null;

// Renders a list of items, and a set of filter
// controls to change what's displayed in the
// list.
const FilteredList = props => (
  <section>
    {/* Three buttons that control what's displayed
         in the list below. Clicking one of these
         buttons will toggle the state of the others. */}
    <ButtonGroup className="filters">
      <Button active={props.todoFilter} onClick={props.todoClick}>
        Todo
      </Button>
      <Button active={props.doneFilter} onClick={props.doneClick}>
        Done
      </Button>
      <Button active={props.allFilter} onClick={props.allClick}>
        All
      </Button>
    </ButtonGroup>

    {/* Renders the list of items. It passes the
         "props.filter()" function to "items.filter()".
         When the buttons above are clicked, the "filter"
         function is changed. */}
    <ListGroup>
      {props.items.filter(props.filter).map(i => (
        <ListGroupItem
          key={i.name}
          onClick={props.itemClick(i)}
          href="#"
          {...itemStyle(i.done)}
        >
          {i.name}
          <ItemIcon done={i.done} />
        </ListGroupItem>
      ))}
    </ListGroup>
  </section>
);

FilteredList.propTypes = {
  todoFilter: PropTypes.bool.isRequired,
  doneFilter: PropTypes.bool.isRequired,
  allFilter: PropTypes.bool.isRequired,
  todoClick: PropTypes.func.isRequired,
  doneClick: PropTypes.func.isRequired,
  allClick: PropTypes.func.isRequired,
  itemClick: PropTypes.func.isRequired,
  filter: PropTypes.func.isRequired,
  items: PropTypes.array.isRequired
};

export default FilteredList;
```

首先，您有`<ButtonGroup>`和`<Button>`元素。这些是用户可以应用于列表的过滤器。默认情况下，只显示待办事项。但是，他们可以选择按已完成项目进行过滤，或者显示所有项目。

列表本身是一个`<ListGroup>`元素，其子元素是`<ListGroupItem>`元素。该项目根据项目的`done`状态而呈现不同。最终结果如下：

！[](Images/49c26dbd-7540-41ed-aa20-2a38446132a9.png)

您可以通过单击“完成”按钮来切换列表项的完成状态。这个组件的好处在于，如果您正在查看待办事项并将其标记为已完成，它将从列表中删除，因为它不再符合当前的过滤条件。组件重新呈现，因此重新评估过滤器。以下是标记为已完成的项目的外观：

！[](Images/71702a3c-8322-42ce-a9dd-9a75f44f6bad.png)

现在让我们看一下处理过滤器按钮和项目列表状态的容器组件：

```jsx
import React, { Component } from 'react';
import { fromJS } from 'immutable';

import FilteredList from './FilteredList';

class FilteredListContainer extends Component {
  // Controls the state of the the filter buttons
  // as well as the state of the function that
  // filters the item list.
  state = {
    data: fromJS({
      // The items...
      items: [
        { name: 'First item', done: false },
        { name: 'Second item', done: false },
        { name: 'Third item', done: false }
      ],

      // The filter button states...
      todoFilter: true,
      doneFilter: false,
      allFilter: false,

      // The default filter...
      filter: i => !i.done,

      // The "todo" filter button was clicked.
      todoClick: () => {
        this.data = this.data.merge({
          todoFilter: true,
          doneFilter: false,
          allFilter: false,
          filter: i => !i.done
        });
      },

      // The "done" filter button was clicked.
      doneClick: () => {
        this.data = this.data.merge({
          todoFilter: false,
          doneFilter: true,
          allFilter: false,
          filter: i => i.done
        });
      },

      // The "all" filter button was clicked.
      allClick: () => {
        this.data = this.data.merge({
          todoFilter: false,
          doneFilter: false,
          allFilter: true,
          filter: () => true
        });
      },

      // When the item is clicked, toggle it's
      // "done" state.
      itemClick: item => e => {
        e.preventDefault();

        this.data = this.data.update('items', items =>
          items.update(
            items.findIndex(i => i.get('name') === item.name),
            i => i.update('done', done => !done)
          )
        );
      }
    })
  };

  // Getter for "Immutable.js" state data...
  get data() {
    return this.state.data;
  }

  // Setter for "Immutable.js" state data...
  set data(data) {
    this.setState({ data });
  }

  render() {
    return <FilteredList {...this.state.data.toJS()} />;
  }
}

export default FilteredListContainer;
```

这个组件有四个状态和四个事件处理程序函数。三个状态仅仅是跟踪哪个过滤器按钮被选中。`filter`状态是由`<FilteredList>`使用的回调函数，用于过滤项目。策略是根据过滤器选择向子视图传递不同的过滤器函数。

# 表单

在本章的最后一节中，您将从`react-bootstrap`实现一些表单组件。就像您在前一节中创建的过滤按钮一样，表单组件也有需要从容器组件传递下来的状态。

然而，即使是简单的表单控件也有许多组成部分。首先，您将了解文本输入。有输入本身，还有标签，占位符，错误文本，验证函数等等。为了帮助将所有这些部分粘合在一起，让我们创建一个封装了所有 Bootstrap 部分的通用组件：

```jsx
import React from 'react';
import PropTypes from 'prop-types';
import {
  FormGroup,
  FormControl,
  ControlLabel,
  HelpBlock
} from 'react-bootstrap';

// A generic input element that encapsulates several
// of the react-bootstrap components that are necessary
// for event simple scenarios.
const Input = ({
  type,
  label,
  value,
  placeholder,
  onChange,
  validationState,
  validationText
}) => (
  <FormGroup validationState={validationState}>
    <ControlLabel>{label}</ControlLabel>
    <FormControl
      type={type}
      value={value}
      placeholder={placeholder}
      onChange={onChange}
    />
    <FormControl.Feedback />
    <HelpBlock>{validationText}</HelpBlock>
  </FormGroup>
);

Input.propTypes = {
  type: PropTypes.string.isRequired,
  label: PropTypes.string,
  value: PropTypes.any,
  placeholder: PropTypes.string,
  onChange: PropTypes.func,
  validationState: PropTypes.oneOf([
    undefined,
    'success',
    'warning',
    'error'
  ]),
  validationText: PropTypes.string
};

export default Input; 
```

这种方法有两个关键优势。一个是，不需要使用`<FormGroup>`，`<FormControl>`，`<HelpBlock>`等，只需要您的`<Input>`元素。另一个优势是，只需要`type`属性，这意味着`<Input>`可以用于简单和复杂的控件。

现在让我们看看这个组件的实际效果：

```jsx
import React from 'react';
import PropTypes from 'prop-types';
import { Panel } from 'react-bootstrap';

import Input from './Input';

const InputsForm = props => (
  <Panel header={<h3>Inputs</h3>}>
    <form>
      {/* Uses the <Input> element to render
           a simple name field. There's a lot of
           properties passed here, many of them
           come from the container component. */}
      <Input
        type="text"
        label="Name"
        placeholder="First and last..."
        value={props.nameValue}
        onChange={props.nameChange}
        validationState={props.nameValidationState}
        validationText={props.nameValidationText}
      />

      {/* Uses the "<Input>" element to render a
           password input. */}
      <Input
        type="password"
        label="Password"
        value={props.passwordValue}
        onChange={props.passwordChange}
      />
    </form>
  </Panel>
);

InputsForm.propTypes = {
  nameValue: PropTypes.any,
  nameChange: PropTypes.func,
  nameValidationState: PropTypes.oneOf([
    undefined,
    'success',
    'warning',
    'error'
  ]),
  nameValidationText: PropTypes.string,
  passwordValue: PropTypes.any,
  passwordChange: PropTypes.func
};

export default InputsForm;
```

只有一个组件用于创建所有必要的 Bootstrap 部分。所有内容都通过属性传入。这个表单看起来是这样的：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/e57f86f6-a57a-43b2-bacf-3c959d110b81.png)

现在让我们来看看控制这些输入状态的容器组件：

```jsx
import React, { Component } from 'react';
import { fromJS } from 'immutable';

import InputsForm from './InputsForm';

// Validates the given "name". It should have a space,
// and it should have more than 3 characters. There are
// many scenarios not accounted for here, but are easy
// to add.
function validateName(name) {
  if (name.search(/ /) === -1) {
    return 'First and last name, separated with a space';
  } else if (name.length < 4) {
    return 'Less than 4 characters? Srsly?';
  }

  return null;
}

class InputsFormContainer extends Component {
  state = {
    data: fromJS({
      // "Name" value and change handler.
      nameValue: '',
      // When the name changes, we use "validateName()"
      // to set "nameValidationState" and
      // "nameValidationText".
      nameChange: e => {
        this.data = this.data.merge({
          nameValue: e.target.value,
          nameValidationState:
            validateName(e.target.value) === null
              ? 'success'
              : 'error',
          nameValidationText: validateName(e.target.value)
        });
      },
      // "Password" value and change handler.
      passwordValue: '',
      passwordChange: e => {
        this.data = this.data.set('passwordValue', e.target.value);
      }
    })
  };

  // Getter for "Immutable.js" state data...
  get data() {
    return this.state.data;
  }

  // Setter for "Immutable.js" state data...
  set data(data) {
    this.setState({ data });
  }

  render() {
    return <InputsForm {...this.data.toJS()} />;
  }
}

export default InputsFormContainer;
```

输入的事件处理程序是作为状态的一部分传递给`InputsForm`作为属性。现在让我们来看看一些复选框和单选按钮。您将使用`<Radio>`和`<Checkbox>` react-bootstrap 组件：

```jsx
import React from 'react';
import PropTypes from 'prop-types';
import { Panel, Radio, Checkbox, FormGroup } from 'react-bootstrap';

const RadioForm = props => (
  <Panel header={<h3>Radios & Checkboxes</h3>}>
    {/* Renders a group of related radio buttons. Note
         that each radio needs to hae the same "name"
         property, otherwise, the user will be able to
         select multiple radios in the same group. The
         "checked", "disabled", and "onChange" properties
         all come from the container component. */}
    <FormGroup>
      <Radio
        name="radio"
        onChange={props.checkboxEnabledChange}
        checked={props.checkboxEnabled}
        disabled={!props.radiosEnabled}
      >
        Checkbox enabled
      </Radio>
      <Radio
        name="radio"
        onChange={props.checkboxDisabledChange}
        checked={!props.checkboxEnabled}
        disabled={!props.radiosEnabled}
      >
        Checkbox disabled
      </Radio>
    </FormGroup>

    {/* Reanders a checkbox and uses the same approach
         as the radios above: setting it's properties from
         state that's passed in from the container. */}
    <FormGroup>
      <Checkbox
        onChange={props.checkboxChange}
        checked={props.radiosEnabled}
        disabled={!props.checkboxEnabled}
      >
        Radios enabled
      </Checkbox>
    </FormGroup>
  </Panel>
);

RadioForm.propTypes = {
  checkboxEnabled: PropTypes.bool.isRequired,
  radiosEnabled: PropTypes.bool.isRequired,
  checkboxEnabledChange: PropTypes.func.isRequired,
  checkboxDisabledChange: PropTypes.func.isRequired,
  checkboxChange: PropTypes.func.isRequired
};

export default RadioForm; 
```

单选按钮切换复选框的`enabled`状态，复选框切换单选按钮的`enabled`状态。请注意，尽管两个`<Radio>`元素在同一个`<FormGroup>`中，它们需要具有相同的`name`属性值。否则，您将能够同时选择两个单选按钮。这个表单看起来是这样的：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/70854800-97b6-4343-92ee-aca2cff405d1.png)

最后，让我们来看看处理单选按钮和复选框状态的容器组件：

```jsx
import React, { Component } from 'react';
import { fromJS } from 'immutable';

import RadioForm from './RadioForm';

class RadioFormContainer extends Component {
  // Controls the enabled state of a group of
  // radio buttons and a checkbox. The radios
  // toggle the state of the checkbox while the
  // checkbox toggles the state of the radios.
  state = {
    data: fromJS({
      checkboxEnabled: false,
      radiosEnabled: true,
      checkboxEnabledChange: () => {
        this.data = this.data.set('checkboxEnabled', true);
      },
      checkboxDisabledChange: () => {
        this.data = this.data.set('checkboxEnabled', false);
      },
      checkboxChange: () => {
        this.data = this.data.update(
          'radiosEnabled',
          enabled => !enabled
        );
      }
    })
  };

  // Getter for "Immutable.js" state data...
  get data() {
    return this.state.data;
  }

  // Setter for "Immutable.js" state data...
  set data(data) {
    this.setState({ data });
  }

  render() {
    return <RadioForm {...this.data.toJS()} />;
  }
}

export default RadioFormContainer; 
```

# 总结

本章向您介绍了移动优先设计的概念。您简要了解了为什么要使用移动优先策略。归根结底，这是因为将移动设计扩展到更大的设备要比相反方向的扩展容易得多。

接下来，你了解了这在 React 应用程序的上下文中意味着什么。特别是，你希望使用处理我们的缩放细节的框架，比如 Bootstrap。然后，你使用了`react-bootstrap`包中的几个组件来实现了几个示例。

这结束了本书的第一部分。现在你已经准备好处理在网络上运行的 React 项目，包括移动浏览器！移动浏览器变得越来越好，但它们无法与移动平台的本机功能相媲美。本书的第二部分将教你如何使用 React Native。

# 测试你的知识

1.  React 开发者为什么要考虑移动优先的设计方法呢？

1.  因为大多数用户使用移动设备，考虑较大的显示屏并不值得。

1.  因为将移动设备作为应用程序的主要显示屏，可以确保你可以处理移动设备，并且向较大设备的扩展比另一种方式更容易。

1.  这没有意义。你应该首先针对较大的显示屏，然后缩小应用程序以适应移动设备。

1.  如果你使用`react-bootstrap`这样的库，你甚至不需要考虑移动优先的概念。

1.  `react-router`与`react-bootstrap`集成良好吗？

1.  是的。尽管你会想要使用**`react-router-bootstrap`**包，以确保你可以向**`NavItem`**和**`MenuItem`**组件添加链接。

1.  不，你应该在`react-bootstrap`组件中使用常规链接。

1.  是的，但是你应该考虑编写自己的抽象，以便所有类型的`react-bootstrap`按钮与`Link`组件一起工作。

1.  你会如何使用`react-bootstrap`渲染项目列表？

1.  使用`react-bootstrap`中的`<ListGroup>`组件包装`<ul>`元素。

1.  只需使用`<ul>`并将 Bootstrap 类应用于该元素。

1.  使用**`react-bootstrap`**中的**`ListGroup`**和**`ListGroupItem`**组件。

1.  为什么你要为`react-bootstrap`表单组件创建一个抽象？

1.  因为`react-bootstrap`表单组件在功能上缺乏。

1.  因为有许多相关组件需要用于基本输入，创建这种抽象会让生活更轻松。

1.  因为这是使输入验证工作的唯一方法。

# 进一步阅读

更多信息可以查看以下链接：

+   [`react-bootstrap.github.io/`](https://react-bootstrap.github.io/)

+   [`getbootstrap.com/`](https://getbootstrap.com/)
