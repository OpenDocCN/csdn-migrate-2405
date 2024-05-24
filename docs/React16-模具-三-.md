# React16 模具（三）

> 原文：[`zh.annas-archive.org/md5/649B7A05B5FE7684E1D753EE428FF41C`](https://zh.annas-archive.org/md5/649B7A05B5FE7684E1D753EE428FF41C)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：使用 Redux 对应用程序状态进行仪器化

Redux 是在 React 应用程序中管理状态的事实标准库。单独使用 React 应用程序可以使用`setState()`来管理其组件的状态。这种方法的挑战在于没有控制状态更改的顺序（考虑异步调用，如 HTTP 请求）。

本章的目的不是向您介绍 Redux——有很多资源可以做到这一点，包括 Packt 图书和官方 Redux 文档。因此，如果您对 Redux 还不熟悉，您可能希望在继续之前花 30 分钟熟悉 Redux 的基础知识。本章的重点是您可以在 Web 浏览器中启用的工具。我认为 Redux 的重要价值之一来自 Redux DevTools 浏览器扩展。

在本章中，您将学到：

+   如何构建一个基本的 Redux 应用程序（而不深入研究 Redux 概念）

+   安装 Redux DevTools Chrome 扩展

+   选择 Redux 操作并检查其内容

+   如何使用时光旅行调试技术

+   手动触发操作以更改状态

+   导出应用程序状态并稍后导入

# 构建 Redux 应用程序

本章中您将使用的示例应用程序是一个基本的图书管理器。目标是拥有足够的功能来演示不同的 Redux 操作，但又足够简单，以便您可以学习 Redux DevTools 而不感到不知所措。

此应用程序的高级功能如下：

+   呈现您想要跟踪的书籍列表。每本书显示书籍的标题、作者和封面图片。

+   允许用户通过在文本输入中键入来筛选列表。

+   用户可以创建新书籍。

+   用户可以选择一本书查看更多详情。

+   书籍可以被删除。

在您深入研究 Redux DevTools 扩展之前，让我们花几分钟来了解这个应用程序的实现方式。

# App 组件和状态

`App`组件是图书管理应用程序的外壳。您可以将`App`视为呈现的每个其他组件的容器。它负责呈现左侧导航，并定义应用程序的路由，以便在用户移动时挂载和卸载适当的组件。以下是`App`的实现方式：

```jsx
import React, { Component } from 'react';
import { connect } from 'react-redux';
import {
  BrowserRouter as Router,
  Route,
  NavLink
} from 'react-router-dom';
import logo from './logo.svg';
import './App.css';
import Home from './Home';
import NewBook from './NewBook';
import BookDetails from './BookDetails';

class App extends Component {
  render() {
    const { title } = this.props;

    return (
      <Router>
        <div className="App">
          <header className="App-header">
            <img src={logo} className="App-logo" alt="logo" />
            <h1 className="App-title">{title}</h1>
          </header>
          <section className="Layout">
            <nav>
              <NavLink
                exact
                to="/"
                activeStyle={{ fontWeight: 'bold' }}
              >
                Home
              </NavLink>
              <NavLink to="/new" activeStyle={{ fontWeight: 'bold' }}>
                New Book
              </NavLink>
            </nav>
            <section>
              <Route exact path="/" component={Home} />
              <Route exact path="/new" component={NewBook} />
              <Route
                exact
                path="/book/:title"
                component={BookDetails}
              />
            </section>
          </section>
        </div>
      </Router>
    );
  }
}

const mapState = state => state.app;
const mapDispatch = dispatch => ({});
export default connect(mapState, mapDispatch)(App);
```

`react-redux`包中的`connect()`函数用于将`App`组件连接到 Redux 存储（应用程序状态所在的地方）。`mapState()`和`mapDispatch()`函数分别向`App`组件添加 props——状态值和动作分发函数。到目前为止，`App`组件只有一个状态值和没有动作分发函数。

要深入了解如何将 React 组件连接到 Redux 存储，请查看此页面：[`redux.js.org/basics/usage-with-react`](https://redux.js.org/basics/usage-with-react)。

接下来让我们来看一下`app()`reducer 函数：

```jsx
const initialState = {
  title: 'Book Manager'
};

const app = (state = initialState, action) => {
  switch (action.type) {
    default:
      return state;
  }
};

export default app;
```

`App`使用的状态并不多，只有一个`title`。实际上，这个`title`永远不会改变。reducer 函数只是简单地返回传递给它的状态。在这里实际上不需要`switch`语句，因为没有需要处理的动作。然而，`title`状态很可能会根据动作而改变——只是您还不知道。设置这样的 reducer 函数从来不是坏主意，这样您就可以将组件连接到 Redux 存储，一旦确定应该引起状态改变的动作，就有一个准备好处理它的 reducer 函数。

# 主页组件和状态

`Home`组件是作为`App`的子组件首先呈现的组件。`Home`的路由是`/`，这是过滤文本输入和书籍列表呈现的地方。当用户首次加载应用程序时，用户将看到以下内容：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/0a050df1-aad0-4cee-8122-e23050da6408.png)

在左边，您有由`App`组件呈现的两个导航链接。在这些链接的右侧，您有过滤文本输入，然后是书籍列表——React 书籍。现在，让我们来看一下`Home`组件的实现：

```jsx
import React, { Component } from 'react';
import { connect } from 'react-redux';

import { fetchBooks } from '../api';
import Book from './Book';
import Loading from './Loading';
import './Home.css';

class Home extends Component {
  componentWillMount() {
    this.props.fetchBooks();
  }

  render() {
    const {
      loading,
      books,
      filterValue,
      onFilterChange
    } = this.props;
    return (
      <Loading loading={loading}>
        <section>
          <input
            placeholder="Filter"
            onChange={onFilterChange}
            value={filterValue}
          />
        </section>
        <section className="Books">
          {books
            .filter(
              book =>
                filterValue.length === 0 ||
                new RegExp(filterValue, 'gi').test(book.title)
            )
            .map(book => (
              <Book
                key={book.title}
                title={book.title}
                author={book.author}
                imgURL={book.imgURL}
              />
            ))}
        </section>
      </Loading>
    );
  }
}

const mapState = state => state.home;
const mapDispatch = dispatch => ({
  fetchBooks() {
    dispatch({ type: 'FETCHING_BOOKS' });
    fetchBooks().then(books => {
      dispatch({
        type: 'FETCHED_BOOKS',
        books
      });
    });
  },

  onFilterChange({ target: { value } }) {
    dispatch({ type: 'SET_FILTER_VALUE', filterValue: value });
  }
});

export default connect(mapState, mapDispatch)(Home);
```

这里需要注意的关键事项：

+   `componentWillMount()`调用`fetchBooks()`从 API 加载书籍数据

+   `Loading`组件用于在获取书籍时显示加载文本

+   `Home`组件定义了分发动作的函数，这是您希望使用 Redux DevTools 查看的内容

+   书籍和过滤数据来自 Redux 存储

这是处理动作并维护与该组件相关状态的 reducer 函数：

```jsx
const initialState = {
  loading: false,
  books: [],
  filterValue: ''
};

const home = (state = initialState, action) => {
  switch (action.type) {
    case 'FETCHING_BOOKS':
      return {
        ...state,
        loading: true
      };
    case 'FETCHED_BOOKS':
      return {
        ...state,
        loading: false,
        books: action.books
      };

    case 'SET_FILTER_VALUE':
      return {
        ...state,
        filterValue: action.filterValue
      };

    default:
      return state;
  }
};

export default home;
```

如果你看`initialState`对象，你会看到`Home`依赖于一个`books`数组，一个`filterValue`字符串和一个`loading`布尔值。`switch`语句中的每个动作情况都会改变这个状态的一部分。虽然通过查看这个 reducer 代码可能有点棘手，但结合 Redux 浏览器工具，情况变得清晰起来，因为你可以将在应用程序中看到的内容映射回这段代码。

# NewBook 组件和状态

在左侧导航栏的主页链接下面，有一个 NewBook 链接。点击这个链接将带你到一个允许你创建新书的表单。现在让我们来看一下`NewBook`组件的源码：

```jsx
import React, { Component } from 'react';
import { connect } from 'react-redux';

import { createBook } from '../api';
import './NewBook.css';

class NewBook extends Component {
  render() {
    const {
      title,
      author,
      imgURL,
      controlsDisabled,
      onTitleChange,
      onAuthorChange,
      onImageURLChange,
      onCreateBook
    } = this.props;

    return (
      <section className="NewBook">
        <label>
          Title:
          <input
            autoFocus
            onChange={onTitleChange}
            value={title}
            disabled={controlsDisabled}
          />
        </label>
        <label>
          Author:
          <input
            onChange={onAuthorChange}
            value={author}
            disabled={controlsDisabled}
          />
        </label>
        <label>
          Image URL:
          <input
            onChange={onImageURLChange}
            value={imgURL}
            disabled={controlsDisabled}
          />
        </label>
        <button
          onClick={() => {
            onCreateBook(title, author, imgURL);
          }}
          disabled={controlsDisabled}
        >
          Create
        </button>
      </section>
    );
  }
}
const mapState = state => state.newBook;
const mapDispatch = dispatch => ({
  onTitleChange({ target: { value } }) {
    dispatch({ type: 'SET_NEW_BOOK_TITLE', title: value });
  },

  onAuthorChange({ target: { value } }) {
    dispatch({ type: 'SET_NEW_BOOK_AUTHOR', author: value });
  },

  onImageURLChange({ target: { value } }) {
    dispatch({ type: 'SET_NEW_BOOK_IMAGE_URL', imgURL: value });
  },

  onCreateBook(title, author, imgURL) {
    dispatch({ type: 'CREATING_BOOK' });
    createBook(title, author, imgURL).then(() => {
      dispatch({ type: 'CREATED_BOOK' });
    });
  }
});

export default connect(mapState, mapDispatch)(NewBook);
```

如果你看一下用于渲染这个组件的标记，你会看到有三个输入字段。这些字段的值作为 props 传递。与 Redux 存储的连接实际上就是这些 props 的来源。随着它们的状态改变，`NewBook`组件会重新渲染。

映射到这个组件的调度函数负责调度维护这个组件状态的动作。它们的责任如下：

+   `onTitleChange()`: 调度`SET_NEW_BOOK_TITLE`动作以及新的`title`状态

+   `onAuthorChange()`: 调度`SET_NEW_BOOK_AUTHOR`动作以及新的`author`状态

+   `onImageURLChange()`: 调度`SET_NEW_BOOK_IMAGE_URL`动作以及新的`imgURL`状态

+   `onCreateBook()`: 调度`CREATING_BOOK`动作，然后在`createBook()` API 调用返回时调度`CREATED_BOOK`动作

如果你不清楚所有这些动作是如何导致高级应用程序行为的，不要担心。这就是为什么你马上要安装 Redux DevTools，这样你就可以理解应用程序状态的变化情况。

这是处理这些动作的 reducer 函数：

```jsx
const initialState = {
  title: '',
  author: '',
  imgURL: '',
  controlsDisabled: false
};

const newBook = (state = initialState, action) => {
  switch (action.type) {
    case 'SET_NEW_BOOK_TITLE':
      return {
        ...state,
        title: action.title
      };
    case 'SET_NEW_BOOK_AUTHOR':
      return {
        ...state,
        author: action.author
      };
    case 'SET_NEW_BOOK_IMAGE_URL':
      return {
        ...state,
        imgURL: action.imgURL
      };
    case 'CREATING_BOOK':
      return {
        ...state,
        controlsDisabled: true
      };
    case 'CREATED_BOOK':
      return initialState;
    default:
      return state;
  }
};

export default newBook;
```

最后，这就是渲染时新书表单的样子：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/dbcc1d82-4baf-4e9a-9c23-2ce022aad8c2.png)

当你填写这些字段并点击创建按钮时，新书将由模拟 API 创建，并且你将被带回到主页，新书应该会被列出。

# API 抽象

对于这个应用程序，我正在使用一个简单的 API 抽象。在 Redux 应用程序中，您应该能够将您的异步功能（API 或其他）封装在自己的模块或包中。以下是`api.js`模块的样子，其中一些模拟数据已被省略以保持简洁：

```jsx
const LATENCY = 1000;

const BOOKS = [
  {
    title: 'React 16 Essentials',
    author: 'Artemij Fedosejev',
    imgURL: 'big long url...'
  },
  ...
];

export const fetchBooks = () =>
  new Promise(resolve => {
    setTimeout(() => {
      resolve(BOOKS);
    }, LATENCY);
  });

export const createBook = (title, author, imgURL) =>
  new Promise(resolve => {
    setTimeout(() => {
      BOOKS.push({ title, author, imgURL });
      resolve();
    }, LATENCY);
  });

export const fetchBook = title =>
  new Promise(resolve => {
    setTimeout(() => {
      resolve(BOOKS.find(book => book.title === title));
    }, LATENCY);
  });

export const deleteBook = title =>
  new Promise(resolve => {
    setTimeout(() => {
      BOOKS.splice(BOOKS.findIndex(b => b.title === title), 1);
      resolve();
    }, LATENCY);
  });
```

要开始构建您的 Redux 应用程序，这就是您所需要的。这里需要注意的重要一点是，这些 API 函数中的每一个都返回一个`Promise`对象。为了更贴近真实 API，我添加了一些模拟的延迟。您不希望 API 抽象返回常规值，比如对象或数组。如果它们在与真实 API 交互时会是异步的，请确保初始模拟也是异步的。否则，这将非常难以纠正。

# 把所有东西放在一起

让我们快速看一下将所有内容整合在一起的源文件，以便让您感受到完整性。让我们从`index.js`开始：

```jsx
import React from 'react';
import ReactDOM from 'react-dom';
import './index.css';
import Root from './components/Root';
import registerServiceWorker from './registerServiceWorker';

ReactDOM.render(<Root />, document.getElementById('root'));
registerServiceWorker();
```

这看起来就像这本书中到目前为止您所使用的`create-react-app`中的大多数`index.js`文件。它不是渲染一个`App`组件，而是渲染一个`Root`组件。让我们接着看：

```jsx
import React from 'react';
import { Provider } from 'react-redux';
import App from './App';
import store from '../store';

const Root = () => (
  <Provider store={store}>
    <App />
  </Provider>
);

export default Root;
```

`Root`的工作是用`react-redux`中的`Provider`组件包装`App`组件。这个组件接受一个`store`属性，这样您就能确保连接的组件可以访问 Redux store 数据。

接下来让我们看一下`store`属性：

```jsx
import { createStore } from 'redux';
import reducers from './reducers';

export default createStore(
  reducers,
  window.__REDUX_DEVTOOLS_EXTENSION__ &&
    window.__REDUX_DEVTOOLS_EXTENSION__()
);
```

Redux 有一个`createStore()`函数，用于为您的 React 应用程序构建一个 store。第一个参数是处理操作并返回 store 新状态的 reducer 函数。第二个参数是一个增强器函数，可以响应 store 状态的变化。在这种情况下，您需要检查 Redux DevTools 浏览器扩展是否安装，如果安装了，就将其连接到您的 store。如果没有这一步，您将无法使用浏览器工具与您的 Redux 应用程序一起使用。

我们快要完成了。让我们看一下`reducers/index.js`文件，它将您的 reducer 函数组合成一个函数：

```jsx
import { combineReducers } from 'redux';
import app from './app';
import home from './home';
import newBook from './newBook';
import bookDetails from './bookDetails';

const reducers = combineReducers({
  app,
  home,
  newBook,
  bookDetails
});

export default reducers;
```

Redux 只有一个 store。为了将您的 store 细分为映射到应用程序概念的状态片段，您需要命名处理各种状态片段的个体 reducer 函数，并将它们传递给`combineReducers()`。对于这个应用程序，您的 store 有以下状态片段，可以映射到组件：

+   `app`

+   `home`

+   `newBook`

+   `bookDetails`

现在您已经看到了这个应用程序是如何组合和工作的，现在是时候开始使用 Redux DevTools 浏览器扩展对其进行调试了。

# 安装 Redux DevTools

安装 Redux DevTools 浏览器扩展的过程与安装 React Developer Tools 扩展的过程类似。第一步是打开 Chrome Web Store 并搜索`redux`：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/a957174c-636f-4f30-95c0-6003d056f060.png)

您要寻找的扩展很可能是第一个结果：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/4096be9e-1222-468c-9bb0-f7584bcc05f4.png)

点击“添加到 Chrome”按钮。然后，您将看到一个对话框，询问您是否同意安装该扩展，并在向您展示它可以更改的内容后安装该扩展：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/2bd0242f-e927-4bb9-b575-790da2950230.png)

单击“添加扩展”按钮后，您将看到一个通知，指出已安装了该扩展：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/b3d17380-897b-4aee-ada0-3589c61405f5.png)

就像 React Developer Tools 扩展一样，Redux DevTools 图标在打开运行 Redux 并添加了对该工具的支持的页面之前都会保持禁用状态。请记住，您在图书管理应用程序中明确添加了对该工具的支持，使用了以下代码：

```jsx
export default createStore(
  reducers,
  window.__REDUX_DEVTOOLS_EXTENSION__ &&
    window.__REDUX_DEVTOOLS_EXTENSION__()
);
```

现在让我们启动图书管理应用程序，并确保您可以使用该扩展。运行`npm start`并等待 UI 在浏览器选项卡中打开和加载后，React 和 Redux 开发人员工具图标应该都是启用状态：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/16668166-462b-4619-a3bd-8a90e1e74ac4.png)

接下来，打开开发人员工具浏览器窗格。您可以以与访问 React Developer Tools 相同的方式访问 Redux DevTools：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/a4b67925-eece-47eb-9666-4e153302dddf.png)

当您选择 Redux 工具时，您应该看到类似于这样的东西：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/6ba88c51-acc2-466d-bdd3-8546902118ac.png)

Redux DevTools 中的左侧窗格包含最重要的数据——应用程序中的操作。正如在这里反映的，您的图书管理应用程序已经分派了三个操作，因此您知道一切都在运作！

# 选择和检查操作

Redux DevTools 左侧窗格上显示的操作是按时间顺序列出的，根据它们的分派时间。可以选择任何操作，并通过这样做，您可以使用右侧窗格来检查应用程序状态和操作本身的不同方面。在本节中，您将学习如何深入了解 Redux 操作如何驱动您的应用程序。

# 操作数据

通过选择一个动作，你可以查看作为动作一部分分发的数据。但首先，让我们生成一些动作。一旦应用程序加载，就会分发`FETCHING_BOOKS`和`FETCHED_BOOKS`动作。点击 React Native Blueprints 链接，加载书籍数据并转到书籍详情页面。这将导致分发两个新动作：`FETCHING_BOOK`和`FETCHED_BOOK`。渲染的 React 内容应该是这样的：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/e574e27f-5535-4f5e-9eb9-6d67c411b22c.png)

Redux DevTools 中的动作列表应该是这样的：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/62944f30-feff-4817-9ed8-228666916afb.png)

`@@INIT`动作是由 Redux 自动分发的，并且始终是第一个动作。通常情况下，你不需要担心这个动作，除非你需要知道在分发动作之前应用程序的状态是什么样子的——我们将在接下来的部分中介绍这个。

现在，让我们选择`FETCHING_BOOKS`动作。然后，在右侧窗格中，选择动作切换按钮以查看动作数据。你应该看到类似这样的东西：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/0bbf2c89-66a2-4724-85e6-50753006196c.png)

默认情况下选择了动作的树视图。你可以在这里看到动作数据有一个名为`type`的属性，其值是动作的名称。这告诉你 reducer 应该知道如何处理这个动作，而且它不需要任何额外的数据。

现在让我们选择`FETCHED_BOOKS`动作，看看动作数据是什么样子的：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/dd659a0a-b418-478b-a04f-8dedf308ef97.png)

再次，你有一个带有动作名称的`type`属性。这次，你还有一个带有书籍数组的`books`属性。这个动作是作为对 API 数据解析的响应而分发的，以及书籍数据如何进入存储——它是通过动作携带进来的。

通过查看动作数据，你可以比较实际分发的内容与应用程序状态中所看到的内容。改变应用程序状态的唯一方法是通过分发具有新状态的动作。接下来，让我们看看单个动作如何改变应用程序的状态。

# 动作状态树和图表

在前面的部分中，你看到了如何使用 Redux DevTools 来选择特定的动作以查看它们的数据。动作及其携带的数据导致应用程序状态的变化。当你选择一个动作时，你可以查看该动作对整个应用程序状态的影响。

让我们选择`FETCHING_BOOK`操作，然后选择右侧窗格中的状态切换按钮：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/8dd1c0a5-9e74-4e19-a8dc-08f794b32d83.png)

此树视图显示了在分派`FETCHING_BOOK`操作后应用程序的整个状态。在这里，`bookDetails`状态被展开，以便您可以看到该操作对状态的影响。在这种情况下，它是`loading`的值——现在是`true`。

现在让我们选择此操作的图表视图：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/d006104a-453c-4e8d-82a9-199f2a7b6f51.png)

我偏好图表视图而不是树视图，用于可视化应用程序的整个状态。在图表的最左边，您有根状态。在其右侧，您有应用程序状态的主要部分——`app`、`home`、`newBook`和`bookDetails`。随着您向右移动，您会深入到应用程序中组件的具体状态。正如您在这里看到的，最深层次是`home`状态中`books`数组中的个别书籍。

`FETCHING_BOOK`操作仍然被选中，这意味着该图表反映了 reducers 响应该操作后的应用程序状态。此操作改变了`bookDetails`中的`loading`状态。如果您将鼠标指针移动到状态标签上，您将看到它的值：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/aa1973ca-bf4d-427e-bab2-57c092b02fc8.png)

现在让我们选择`FETCHED_BOOK`操作。当书籍详细数据从调用 API 获取解析时，将分派此操作：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/e231a49f-95ce-4e91-8f9b-353b5a3c5717.png)

如果您在切换到不同的操作时保持图表视图处于激活状态，您会注意到图表实际上会动画显示状态的变化。这看起来很酷，毫无疑问，但它也会吸引您注意实际发生变化的值，以便更容易看到。在这个例子中，如果您查看`bookDetails`下的`book`对象，您会发现它现在有了新的属性。您可以将鼠标指针移动到每个属性上以显示其值。您还可以检查`loading`的值——它应该恢复为`false`。

# 操作状态差异

在 Redux DevTools 中查看操作数据的另一种方法是查看从分派操作中产生的状态差异。这个视图不是试图通过查看整个状态树来推断状态的变化，而是只向您展示了发生了什么变化。

让我们尝试添加一本新书来生成一些动作。我要添加你现在正在阅读的这本书。首先，我会粘贴生成输入元素上的更改事件的书名，然后触发`SET_NEW_BOOK_TITLE`动作。如果你选择该动作，你应该会看到以下内容：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/0184a821-7191-4608-bcb9-63c7002f8de5.png)

`newBook`状态的`title`值从空字符串变为了粘贴到标题文本输入框中的值。您无需寻找此更改，它已清晰标记，所有不相关的状态数据都被隐藏起来。

接下来，让我们粘贴作者并选择`SET_NEW_BOOK_AUTHOR`动作：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/0b08d994-a1c6-4b75-8c78-ebfd3e6a0d5f.png)

再次，这里只显示了`author`值，因为它是由于分派`SET_NEW_BOOK_AUTHOR`而发生变化的唯一值。这是最终的表单字段-图像 URL：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/1c1eb8d9-3ba2-4342-bb2f-00ee52fb5a72.png)

通过使用动作的差异视图，您只会看到由于动作而发生变化的数据。如果这不能给您足够的视角，您可以随时跳转到状态视图，以便查看整个应用程序的状态。

让我们通过点击“创建”按钮来创建新书。这将分派两个动作：`CREATING_BOOK`和`CREATED_BOOK`。首先，让我们看看`CREATING_BOOK`：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/422ddb74-c474-4959-95c3-3da974d73a7a.png)

此动作在进行 API 调用*创建书籍*之前分派。这使得您的 React 组件有机会处理用户交互的异步性质。在这种情况下，您不希望用户在请求挂起时能够与任何表单控件进行交互。通过查看此差异，您可以看到`controlsDisabled`值现在为`false`，React 组件可以使用它来禁用任何表单控件。

最后，让我们看一下`CREATED_BOOK`动作：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/04ae06c1-2447-4ed7-96c6-63cd93fbdae2.png)

`title`、`author`和`imgURL`的值都被设置为空字符串，这将重置表单字段的值。通过将`controlsDisabled`设置为`false`，表单字段也被重新启用。

# 时间旅行调试

Redux 中 reducer 函数的一个要求是它们必须是纯函数；也就是说，它们只返回新数据，而不是改变现有数据。这样做的一个结果是它可以实现时间旅行调试。因为没有任何改变，你可以将应用程序的状态向前、向后或者到任意时间点。Redux DevTools 使这变得很容易。

为了看到时间旅行调试的效果，让我们在过滤输入框中输入一些过滤文本：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/4890fad5-a3b9-40bd-b13e-5f0638cb5528.png)

在 Redux DevTools 中查看动作，你应该看到类似以下的内容：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/44479dd4-612e-464c-9b36-686871a88bd3.png)

我选择了最后一个被分发的`SET_FILTER_VALUE`动作。`filterValue`的值应该是`native b`，这反映了当前显示的标题。现在，让我们回到两个动作之前。为了做到这一点，将鼠标指针移动到当前选定动作的两个位置之前的动作上。点击 Jump 按钮，应用程序的状态将被更改为分发`SET_FILTER_VALUE`时的状态：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/2fefa33d-f519-4a4f-a49a-426a1cf58691.png)

你可以看到`filterValue`已经从`native b`变成了`native`。你已经成功地撤销了最后两次按键，相应地更新了状态和 UI：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/b7527dd9-15a2-423a-a19a-a019ebd351ab.png)

要将应用程序状态恢复到当前时间，按照相同的过程但是反向操作。点击最近状态上的 Jump。

# 手动触发动作

在开发 Redux 应用程序时手动触发动作的能力是很有帮助的。例如，你可能已经准备好了组件，但是不确定用户交互会如何工作，或者你只是需要排除一些本应该工作但是却没有的问题。你可以使用 Redux DevTools 通过点击面板底部附近带有键盘图标的按钮来手动触发动作：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/e6616ed3-8773-4ad3-a25e-9d017bd38697.png)

这将显示一个文本输入框，你可以在其中输入动作的载荷。例如，我已经导航到了《React Native By Example》的书籍详情页面：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/d9e90133-2813-482c-9715-d665919f4fc2.png)

我不想点击删除按钮，我只想看看应用程序的状态会发生什么变化，而不触发 DOM 事件或 API 调用。为了做到这一点，我可以点击 Redux DevTools 中的键盘按钮，这样我就可以手动输入一个动作并分派它。例如，这是我如何分派`DELETING_BOOK`动作的方式：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/3b466c6a-a022-42a3-a804-bf839d911c73.png)

这导致动作被分派，因此 UI 被更新。这是`DELETING_BOOK`动作：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/97ce8c9c-12b6-46fd-af51-6546958aa2fc.png)

要将`controlsDisabled`设置回`false`，您可以分派`DELETED_BOOK`动作：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/6e2d96cc-df1f-4e33-8a6b-a6a5d6eea9b0.png)

# 导出和导入状态

随着 Redux 应用程序的规模和复杂性的增长，状态树的大小和复杂性也会同步增长。因此，有时玩弄单个动作并使应用程序进入特定状态可能会太繁琐，无法手动一遍又一遍地执行。

使用 Redux DevTools，您可以导出应用程序的当前状态。然后，当您以后进行故障排除并需要特定状态作为起点时，您可以直接加载它，而不是手动重新创建它。

让我们尝试导出应用程序状态。首先，导航到 React 16 Essentials 的详细信息页面：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/9788df87-be18-4f79-9e26-9fd41416a8a3.png)

要使用 Redux DevTools 导出当前状态，请单击带有向下箭头的按钮：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/7a98ac22-dbe4-4483-afc2-270a94abf852.png)

然后，您可以使用向上箭头导入状态。但在这之前，导航到不同的书名，比如《使用 React VR 入门》：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/a7901dfa-fd1a-495c-8bab-a173b0ddd1d8.png)

现在，您可以在 Redux DevTools 窗格中使用上传按钮：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/bf99d7ef-83a4-44ff-907e-1df3592edd9b.png)

由于您已经在书籍详细信息页面上，加载此状态将替换由此页面上的组件呈现的状态值：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/bf29eba2-d5d9-42c3-81b1-0e61af7e6d61.png)

现在您知道如何将 Redux 存储的状态恢复到您导出并本地保存的任何给定点。这样做的想法是避免记住并按照正确的顺序执行校正操作以达到特定状态。这是容易出错的，导出所需的确切状态可以避免整个过程。

# 摘要

在本章中，你组合了一个简单的图书管理 Redux 应用程序。有了这个应用程序，然后你学会了如何在 Chrome 中安装 Redux DevTools 浏览器扩展。然后，你学会了如何查看和选择动作。

一旦选择了一个动作，就有许多方法可以查看有关应用程序的信息。你可以查看动作的载荷数据。你可以查看整个应用程序状态。你可以查看应用程序状态和上次分发的动作之间的差异。这些都是你可以用来调试 Redux 应用程序的不同方法。

然后，你学会了如何在 Redux DevTools 中进行时间旅行调试。因为在 Redux 中状态变化是不可变的，你可以使用 Redux DevTools 从一个动作跳转到另一个动作。这可以极大地简化调试周期。最后，你学会了如何手动分发动作以及导入/导出应用程序的状态。

在下一章中，你将学习如何使用 Gatsby 从 React 组件生成静态内容。


# 第十章：使用 Gatsby 构建和部署静态 React 站点

Gatsby 是 React 开发人员的静态网站生成工具。本质上，这个工具让你构建 React 组件并捕获它们的渲染输出，以用作静态站点内容。然而，Gatsby 将静态站点生成提升到了一个新的水平。特别是，它提供了将网站数据作为 GraphQL 源并将其转换为更容易被 React 组件消耗的机制。Gatsby 可以处理从单页宣传册站点到跨越数百页的站点的任何内容。

在本章中，您将学到以下内容：

+   为什么要使用 React 组件构建静态站点？

+   使用入门者构建简单的 Gatsby 站点

+   使用来自本地文件系统的数据

+   使用来自 Hacker News 的远程数据

# 为什么要静态 React 站点？

在使用 Gatsby 构建静态网站之前，让我们通过简要讨论为什么要这样做来设定背景。这里有三个关键因素——我们现在将逐个讨论每一个。

# React 应用程序的类型

React 与非常互动和生动变化的数据相关联。这可能对一些应用程序是真实的，甚至可能对大多数应用程序是真实的，但仍然存在用户查看静态数据的情况——即不会改变或很少改变的信息。

考虑一个博客。典型的流程是作者发布一些内容，然后该内容被提供给访问网站的任何人，然后他们可以查看内容。通常情况是，一旦内容发布，它就保持不变，或者保持静态。不寻常的情况是作者更新他们的帖子，但即使是这样，这也是一个不经常的行为。现在，想想你典型的博客发布平台。每当读者访问博客上的页面时，都会执行数据库查询，必须组装内容等。问问自己，如果结果每次都一样，那么发出所有这些查询真的有意义吗？

让我们看另一个例子。您有一个企业级应用程序，一个大型应用程序，有大量数据和大量功能。应用程序的一部分专注于用户交互——添加/更改数据和与几乎实时数据交互。应用程序的另一部分生成报告——基于数据库查询的报告和基于历史数据快照的图表。这个企业应用程序的后半部分似乎不与频繁更改的数据交互，或者根本不交互。也许，将应用程序拆分为两个应用程序会有所好处：一个处理用户与活跃数据的交互，另一个生成几乎不频繁更改或根本不更改的静态内容。

您可能正在构建一个应用程序或较大应用程序的一部分，其中大部分数据都是静态的。如果是这样，您可能可以使用类似 Gatsby 的工具来生成静态渲染的内容。但是为什么要这样做？有什么好处呢？

# 更好的用户体验

构建 React 组件的静态版本最具说服力的原因是为用户提供更好的体验。关键指标在于整体性能的改进。不必触及各种 API 端点并处理提供数据给 React 组件的所有异步方面，而是一切都是预先加载的。

使用静态构建的 React 内容还有一个不太明显的用户体验改进是，由于移动部件较少，网站出现故障的可能性较小，从而减少了用户的挫败感。例如，如果您的 React 组件不必通过网络获取数据，那么这种故障可能性就完全从您的网站中消除了。

# 高效的资源使用

由 Gatsby 静态编译的组件知道如何有效地使用它们消耗的 GraphQL 资源。GraphQL 的一个很棒的地方是，工具在编译时可以轻松解析和生成高效的代码。如果您在继续使用 Gatsby 之前想要更深入地了解 GraphQL，可以在这里找到一个很好的介绍：[`graphql.org/learn/`](http://graphql.org/learn/)。

静态 Gatsby React 应用程序帮助减少资源消耗的另一个地方是后端。这些应用程序不会不断地命中返回相同响应的 API 端点。这段时间可以用来为实际需要动态数据或正在生成新数据的请求提供服务。

# 构建您的第一个 Gatsby 网站

使用 Gatsby 的第一步是全局安装命令行工具：

```jsx
npm install gatsby-cli -g  
```

现在，您可以运行命令行工具来生成您的 Gatsby 项目，就像`create-react-app`的工作方式一样。`gatsby`命令接受两个参数：

+   新项目的名称

+   Gatsby starter 存储库的 URL

项目名称基本上是创建以保存所有项目文件的文件夹的名称。Gatsby starter 有点像模板，使您更容易上手，特别是如果您正在学习。如果您不传递一个 starter，将使用默认的 starter：

```jsx
gatsby new your-first-gatsby-site
```

运行上述命令将与运行以下命令相同：

```jsx
gatsby new your-first-gatsby-site https://github.com/gatsbyjs/gatsby-starter-default
```

在这两种情况下，starter 存储库都会克隆到`your-first-gatsby-site`目录中，然后为您安装依赖项。如果一切顺利，您应该看到类似于这样的控制台输出：

```jsx
info Creating new site from git: https://github.com/gatsbyjs/gatsby-starter-default.git
Cloning into 'your-first-gatsby-site'...
```

```jsx
success Created starter directory layout
info Installing packages...
added 1540 packages from 888 contributors in 29.528s  
```

现在，您可以切换到`your-first-gatsby-site`目录并启动开发服务器：

```jsx
cd your-first-gatsby-site
gatsby develop
```

这将在您的项目中启动 Gatsby 开发服务器。再次强调，这与`create-react-app`的工作方式类似——没有任何配置要处理，Webpack 已经设置好了。启动开发服务器后，您应该在控制台上看到类似于这样的输出：

```jsx
success delete html and css files from previous builds - 0.007 s
success open and validate gatsby-config.js - 0.004 s
success copy gatsby files - 0.014 s
success onPreBootstrap - 0.011 s
success source and transform nodes - 0.022 s
success building schema - 0.070 s
success createLayouts - 0.020 s
success createPages - 0.000 s
success createPagesStatefully - 0.014 s
success onPreExtractQueries - 0.000 s
success update schema - 0.044 s
success extract queries from components - 0.042 s
success run graphql queries - 0.024 s
success write out page data - 0.003 s
success write out redirect data - 0.001 s
success onPostBootstrap - 0.001 s

info bootstrap finished - 1.901 s

DONE  Compiled successfully in 3307ms                                          
```

您现在可以通过导航到`http://localhost:8000/`在浏览器中查看`gatsby-starter-default`。

查看 GraphiQL，一个在浏览器中探索站点数据和模式的 IDE

`http://localhost:8000/___graphql`。

请注意，开发构建未经优化。要创建生产构建，请使用`gatsby build`：

```jsx
WAIT  Compiling... 

DONE  Compiled successfully in 94ms 
```

如果您在 Web 浏览器中访问`http://localhost:8000/`，您应该看到默认内容：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/a34620ae-1efb-49f9-9605-c9f83645e039.png)

默认的 starter 创建了多个页面，这样您就可以看到如何将页面链接在一起。如果您点击“转到第 2 页”链接，您将被带到站点的下一页，看起来像这样：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/9871976b-c9f3-4fb0-b4ee-1f74e97ce782.png)

这是您的默认 Gatsby starter 项目的结构：

```jsx
├── LICENSE
├── README.md
├── gatsby-browser.js
├── gatsby-config.js
├── gatsby-node.js
├── gatsby-ssr.js
├── package-lock.json
├── package.json
├── public
│   ├── index.html
│   ├── render-page.js.map
│   └── static
└── src
 ├── components
 │   └── Header
```

```jsx
 │       └── index.js
 ├── layouts
 │   ├── index.css
 │   └── index.js
 └── pages
 ├── 404.js
 ├── index.js
 └── page-2.js  
```

对于基本的站点设计和编辑，您主要关注`src`目录下的文件和目录。让我们看看您要处理的内容，从`Header`组件开始：

```jsx
import React from 'react' 
import Link from 'gatsby-link' 

const Header = () => ( 
  <div 
    style={{ 
      background: 'rebeccapurple', 
      marginBottom: '1.45rem', 
    }} 
  > 
    <div 
      style={{ 
        margin: '0 auto', 
        maxWidth: 960, 
        padding: '1.45rem 1.0875rem', 
      }} 
    > 
      <h1 style={{ margin: 0 }}> 
        <Link 
          to="/" 
          style={{ 
            color: 'white', 
            textDecoration: 'none', 
          }} 
        > 
          Gatsby 
        </Link> 
      </h1> 
    </div> 
  </div> 
) 

export default Header 
```

该组件定义了紫色的页眉部分。标题目前是静态的，它链接到主页，并定义了一些内联样式。接下来，让我们看一下`layouts/index.js`文件：

```jsx
import React from 'react' 
import PropTypes from 'prop-types' 
import Helmet from 'react-helmet' 

import Header from '../components/Header' 
import './index.css' 

const TemplateWrapper = ({ children }) => ( 
  <div> 
    <Helmet 
      title="Gatsby Default Starter" 
      meta={[ 
        { name: 'description', content: 'Sample' }, 
        { name: 'keywords', content: 'sample, something' }, 
      ]} 
    /> 
    <Header /> 
    <div 
      style={{ 
        margin: '0 auto', 
        maxWidth: 960, 
        padding: '0px 1.0875rem 1.45rem', 
        paddingTop: 0, 
      }} 
    > 
      {children()} 
    </div> 
  </div> 
) 

TemplateWrapper.propTypes = { 
  children: PropTypes.func, 
} 

export default TemplateWrapper 
```

这个模块导出了一个`TemplateWrapper`组件。这个组件的作用是定义网站的布局。就像你可能已经实现的其他容器组件一样，这个组件在网站的每个页面上都会被渲染。这类似于你在`react-router`中所做的事情，只不过在 Gatsby 中，路由已经为你处理好了。例如，处理指向`page-2`的链接的路由是由 Gatsby 自动创建的。同样地，Gatsby 通过确保它在网站的每个页面上都被渲染来自动处理这个布局模块。你所需要做的就是确保它看起来符合你的要求，并且`children()`函数被渲染。现在，你可以将它保持原样。

你也会注意到，布局模块还导入了一个包含与网站布局相关的样式的样式表。

让我们现在来看一下页面组件，从`index.js`开始：

```jsx
import React from 'react' 
import Link from 'gatsby-link' 

const IndexPage = () => ( 
  <div> 
    <h1>Hi people</h1> 
    <p>Welcome to your new Gatsby site.</p> 
    <p>Now go build something great.</p> 
    <Link to="/page-2/">Go to page 2</Link> 
  </div> 
) 

export default IndexPage 
```

就像普通的 HTML 网站有一个`index.html`文件一样，静态的 Gatsby 网站也有一个`index.js`页面，它将内容导出到主页上进行渲染。在这里定义的`IndexPage`组件渲染了一些基本的 HTML，包括指向`page-2`的链接。接下来让我们来看一下`page-2.js`：

```jsx
import React from 'react' 
import Link from 'gatsby-link' 

const SecondPage = () => ( 
  <div> 
    <h1>Hi from the second page</h1> 
    <p>Welcome to page 2</p> 
    <Link to="/">Go back to the homepage</Link> 
  </div> 
)
export default SecondPage 
```

这个页面看起来与主页非常相似。在这里渲染的链接将用户带回到主页。

这只是一个基本的介绍，让你开始使用 Gatsby。你没有使用任何数据源来生成内容；你将在接下来的部分中做到这一点。

# 添加本地文件系统数据

在前面的部分中，你看到了如何启动并运行一个基本的 Gatsby 网站。这个网站并不是很有趣，因为没有数据来驱动它。例如，驱动博客的数据是存储在数据库中的博客条目内容，博客框架使用这些数据来渲染文章列表和文章本身的标记。

你可以用 Gatsby 做同样的事情，但以一种更复杂的方式。首先，标记（或在这种情况下，React 组件）是静态构建和捆绑一次的。然后，这些构建被提供给用户，而无需查询数据库或 API。其次，Gatsby 使用的插件架构意味着你不仅限于一个数据源，不同的数据源经常被结合在一起。最后，GraphQL 是一个查询抽象层，位于所有这些东西的顶部，并将数据传递给你的 React 组件。

要开始，你需要一个数据源来驱动你网站的内容。现在我们将保持简单，使用本地 JSON 文件作为数据源。为此，你需要安装`gatsby-source-filesystem`插件：

```jsx
npm install --save gatsby-source-filesystem
```

安装了这个包之后，你可以通过编辑`gatsby-config.js`文件将其添加到你的项目中：

```jsx
plugins: [ 
  // Other plugins... 
  { 
    resolve: 'gatsby-source-filesystem', 
    options: { 
      name: 'data', 
      path: '${__dirname}/src/data/', 
    }, 
  }, 
] 
```

`name`选项告诉 GraphQL 后端如何组织查询结果。在这种情况下，所有内容都将在`data`属性下。路径选项限制了可读取的文件。在这个例子中使用的路径是`src/data`—随意将文件放入该目录，以便进行查询。

此时，你可以启动 Gatsby 开发服务器。GraphiQL 实用程序可在`http://localhost:8000/___graphql`访问。在开发 Gatsby 网站时，你会经常使用这个工具，因为它允许你创建临时的 GraphQL 查询并立即执行它们。当你首次加载这个界面时，你会看到类似这样的东西：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/516c3d4c-3c8f-4744-92e8-76ce159e7435.png)

左侧面板是你编写 GraphQL 查询的地方，点击上面的播放按钮执行查询，右侧面板显示查询结果。右上角的文档链接是一个探索 Gatsby 为你创建的可用 GraphQL 类型的有用方式。此外，右侧的查询编辑器窗格将在你输入时自动完成，以帮助更轻松地构建查询。

让我们执行你的第一个查询，列出文件系统中关于文件的信息。请记住，你需要至少在`src/data`中有一个文件，才能使你的查询返回任何结果。以下是如何查询数据目录中文件的名称、扩展名和大小：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/0262adc8-b93d-4f2b-a674-c6e5727dcb0d.png)

如你所见，查询中指定了特定的节点字段。右侧面板中的结果显示你得到了你要求的确切字段。GraphQL 的吸引力之一在于你可以创建任意嵌套和复杂的查询，涵盖多个后端数据源。然而，深入研究 GraphQL 的细节远远超出了本书的范围。Gatsby 首页（[`www.gatsbyjs.org/`](https://www.gatsbyjs.org/)）上有一些关于 GraphQL 的很好的资源，包括其他 GraphQL 教程和文档的链接。

这里的要点是，`gatsby-source-filesystem`数据源插件为您完成了所有繁重的 GraphQL 工作。它为您生成了整个模式，这意味着一旦您安装了插件，您就可以启动开发服务器并立即开始使用自动完成和文档。

继续使用这个例子，您可能不需要在 UI 中呈现本地文件数据。所以让我们创建一个带有一些 JSON 内容的`articles.json`文件：

```jsx
[ 
  { "topic": "global", "title": "Global Article 1" }, 
  { "topic": "global", "title": "Global Article 2" }, 
  { "topic": "local", "title": "Local Article 1" }, 
  { "topic": "local", "title": "Local Article 2" }, 
  { "topic": "sports", "title": "Sports Article 1" }, 
  { "topic": "sports", "title": "Sports Article 2" } 
]
```

这个 JSON 结构是一组带有`topic`和`title`属性的文章对象。这是您想要用 GraphQL 查询的数据。为了做到这一点，您需要安装另一个 Gatsby 插件：

```jsx
npm install --save gatsby-transformer-json
```

`gatsby-transformer-json`插件来自 Gatsby 插件的另一类别——转换器。源插件负责向 Gatsby 提供数据，而转换器负责使数据可通过 GraphQL 查询。就像您想要使用的任何插件一样，您需要将它添加到您的项目配置中：

```jsx
plugins: [ 
  // Other plugins... 
  'gatsby-transformer-json', 
], 
```

现在，您在数据目录中有一个带有 JSON 内容的文件，并且安装并启用了`gatsby-transformer-json`插件，您可以回到 GraphiQL 并查询 JSON 内容：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/96aa1a5a-f9cf-44a1-9add-87cbfe07901f.png)

`gatsby-transformer-json`插件使`allArticlesJson`查询成为可能，因为它根据数据源中的 JSON 数据为您定义了 GraphQL 模式。在`node`下，您可以请求特定属性，就像您对任何其他 GraphQL 查询一样。在结果中，您会得到您查询的所有 JSON 数据。

在这个例子中，假设您想要为按主题组织的文章列出三个单独的页面。您需要一种方法来过滤查询返回的节点。您可以直接将过滤器添加到您的 GraphQL 语法中。例如，要仅查找全球文章，您可以执行以下查询：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/a8799f8a-f4bf-419d-82d3-bc5cf1987d2b.png)

这次，一个过滤参数被传递给`allArticlesJson`查询。在这里，查询是要求具有全局主题值的节点。果然，具有全局主题的文章在结果中返回。

GraphiQL 实用程序允许您设计一个 GraphQL 查询，然后可以被您的 React 组件使用。一旦您有一个返回正确结果的查询，您可以简单地将其复制到您的组件中。这个最后的查询返回全球文章，所以您可以将它与用于`pages/global.js`页面的组件一起使用：

```jsx
import React from 'react' 
import Link from 'gatsby-link' 

export default ({ data: { allArticlesJson: { edges } } }) => ( 
  <div>
    <h1>Global Articles</h1> 
    <Link to="/">Home</Link> 
    <ul> 
      {edges.map(({ node: { title } }) => ( 
        <li key={title}>{title}</li> 
      ))} 
    </ul> 
  </div> 
) 

export const query = graphql' 
  query GlobalArticles { 
    allArticlesJson(filter: { topic: { eq: "global" } }) { 
      edges { 
        node { 
          topic 
          title 
        } 
      } 
    } 
  } 
'
```

在这个模块中有两件事需要注意。首先，看一下传递给组件的参数，并注意它是如何与您在 GraphiQL 中看到的结果数据匹配的。然后，注意`query`导出字符串。在构建时，Gatsby 将找到此字符串并执行适当的 GraphQL 查询，以便您的组件具有结果的静态快照。

鉴于您现在知道如何筛选全局文章，您现在可以更新`pages/local.js`页面的筛选器：

```jsx
import React from 'react' 
import Link from 'gatsby-link' 

export default ({ data: { allArticlesJson: { edges } } }) => ( 
  <div> 
    <h1>Local Articles</h1> 
    <Link to="/">Home</Link> 
    <ul> 
      {edges.map(({ node: { title } }) => ( 
        <li key={title}>{title}</li> 
      ))} 
    </ul> 
  </div> 
)
export const query = graphql' 
  query LocalArticles { 
    allArticlesJson(filter: { topic: { eq: "local" } }) { 
      edges { 
        node { 
          topic 
          title 
        } 
      } 
    } 
  } 
' 
```

这是`pages/sports.js`页面的样子：

```jsx
import React from 'react' 
import Link from 'gatsby-link' 

export default ({ data: { allArticlesJson: { edges } } }) => ( 
  <div> 
    <h1>Sports Articles</h1> 
    <Link to="/">Home</Link> 
    <ul> 
      {edges.map(({ node: { title } }) => ( 
        <li key={title}>{title}</li> 
      ))} 
    </ul> 
  </div> 
) 

export const query = graphql' 
  query SportsArticles { 
    allArticlesJson(filter: { topic: { eq: "sports" } }) { 
      edges { 
        node { 
          topic 
          title 
        } 
      } 
    } 
  } 
' 
```

您可能已经注意到这三个组件看起来非常相似。这是因为它们都使用相同的数据。它们唯一的不同之处在于它们的标题。为了减少一些冗余，您可以创建一个接受`name`参数并返回在每个页面上使用的相同基础组件的高阶组件：

```jsx
import React from 'react' 
import Link from 'gatsby-link' 

export default title => ({ data: { allArticlesJson: { edges } } }) => ( 
  <div> 
    <h1>{title}</h1> 
    <Link to="/">Home</Link> 
    <ul> 
      {edges.map(({ node: { title } }) => ( 
        <li key={title}>{title}</li> 
      ))} 
    </ul> 
  </div> 
) 
```

然后，您可以像这样使用它：

```jsx
import React from 'react' 
Import ArticleList from '../components/ArticleList' 

export default ArticleList('Global Articles') 

export const query = graphql' 
  query GlobalArticles { 
    allArticlesJson(filter: { topic: { eq: "global" } }) { 
      edges { 
        node { 
          topic 
          title 
        } 
      } 
    } 
  } 
'
```

为了查看所有这些页面，您需要一个链接到每个页面的索引页面：

```jsx
import React from 'react' 
import Link from 'gatsby-link' 

const IndexPage = () => ( 
  <div> 
    <h1>Home</h1> 
    <p>Choose an article category</p> 
    <ul> 
      <li> 
        <Link to="/global/">Global</Link> 
      </li>
      <li> 
        <Link to="/local/">Local</Link> 
      </li>

      <li> 
        <Link to="/sports/">Sports</Link> 
      </li> 
    </ul> 
  </div> 
) 

export default IndexPage 
```

这是主页的样子：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/4ca67551-6019-4000-9dc4-754b8898244d.png)

如果您点击其中一个主题链接，比如全局，您将进入文章列表页面：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/1e75e46a-857c-4c0c-977a-7499101c790b.png)

# 获取远程数据

Gatsby 拥有丰富的数据源插件生态系统 - 我们没有时间去了解它们所有。Gatsby 源插件通常会在构建时从另一个系统获取数据并通过网络获取数据。`gatsby-source-hacker-news`插件是一个很好的插件，可以让您了解 Gatsby 如何处理这个获取过程。

与其使用 Gatsby 构建自己的 Hacker News 网站，我们将使用[`github.com/ajayns`](https://github.com/ajayns)创建的演示。要开始，您可以克隆他的存储库，如下所示：

```jsx
git clone https://github.com/ajayns/gatsby-hacker-news.git
cd gatsby-hacker-news
```

然后，您可以安装依赖项，包括`gatsby-source-hacker-news`插件：

```jsx
npm install
```

不需要编辑项目配置来启用任何功能，因为这已经是一个 Gatsby 项目。只需像在本章中一样启动开发服务器：

```jsx
gatsby develop
```

与本章中您所工作的其他网站相比，这次构建需要更长的时间才能完成。这是因为 Gatsby 必须通过网络获取数据。还有更多资源需要获取。如果您查看开发服务器的控制台输出，您应该会看到以下内容：

```jsx
success onPreBootstrap - 0.011 s
![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/91b4b10e-2f9a-4b0b-8223-8f057f3c9f05.jpg) starting to fetch data from the Hacker News GraphQL API. Warning, this can take a long time e.g. 10-20 seconds
![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/91b4b10e-2f9a-4b0b-8223-8f057f3c9f05.jpg) source and transform nodesfetch HN data: 10138.119ms
```

这表明由于需要加载 Hacker News 数据而导致构建时间较长。一旦此过程完成，您可以在浏览器中加载站点。您应该看到类似以下内容：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/46022adb-b2be-4880-b79b-b9570374076e.png)

让我们来看一下加载用于呈现此内容的数据的 GraphQL 查询。在`index.js`页面中，您会找到以下查询：

```jsx
query PageQuery { 
  allHnStory(sort: { fields: [order] }, limit: 10) { 
    edges { 
      node { 
        ...Story 
      } 
    } 
  } 
} 
```

不是指定单个节点字段，而是`...Story`。这被称为**片段**，它在`StoryItem`组件中定义：

```jsx
fragment Story on HNStory { 
  id 
  title 
  score 
  order 
  domain 
  url 
  by 
  descendants 
  timeISO(fromNow: true) 
} 
```

`StoryItem`组件定义了这个 GraphQL 片段，因为它使用了这些数据。现在，让我们转到 GraphiQL，组合并执行这个查询：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/f78af049-2082-4b7d-8bbd-87acf0b5fb1e.png)

这就是站点首页如何加载从 Hack News API 获取的数据。以下是首页组件的外观：

```jsx
import React from 'react' 

import StoryItem from '../components/story-item' 

const IndexPage = ({ data, active }) => ( 
  <div> 
    <div> 
      {data.allHnStory.edges.map(({ node }) => ( 
        <StoryItem key={node.id} story={node} active={false} /> 
      ))} 
    </div> 
  </div> 
) 

export default IndexPage 
```

返回的数据的边缘被映射到`StoryItem`组件，传入数据节点。以下是`StoryItem`组件的外观：

```jsx
import React, { Component } from 'react'; 
import Link from 'gatsby-link'; 

import './story-item.css'; 

const StoryItem = ({ story, active }) => ( 
  <div 
    className="story" 
    style={active ? { borderLeft: '6px solid #ff6600' } : {}} 
  > 
    <div className="header"> 
      <a href={story.url}> 
        <h4>{story.title}</h4> 
      </a> 
      <span className="story-domain"> 
        {' '}({story.domain}) 
      </span> 
    </div> 
    <div className="info"> 
      <h4 className="score">▴ {story.score}</h4> 
      {' '} 
      by <span className="author">{story.by}</span> 
      {' '} 
      <span className="time">{story.timeISO}</span> 
      {' '} 
      {active ? ( 
        '' 
      ) : ( 
        <Link to={'/item/${story.id}'} className="comments"> 
          {story.descendants} comments 
        </Link> 
      )} 
    </div> 
  </div> 
); 

export default StoryItem; 
```

在这里，您可以看到这个组件如何使用由传递给更大查询的 GraphQL 片段定义的数据。

现在让我们点击一个故事的评论链接，这将带您到故事的详细页面。新的 URL 应该看起来像`http://localhost:8000/item/16691203`，页面应该看起来像这样：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/7848af2c-c83d-4e35-9e58-91967c4017e1.png)

你可能想知道这个页面是从哪里来的，因为它有一个 URL 参数（故事的 ID）。当使用 Gatsby 构建具有动态 URL 组件的静态页面时，您必须编写一些代码，其工作是告诉 Gatsby 如何根据 GraphQL 查询结果创建页面。这段代码放在`gatsby-node.js`模块中。这是 Hacker News 网站中页面创建的方式：

```jsx
const path = require('path') 

exports.createPages = ({ graphql, boundActionCreators }) => { 
  const { createPage } = boundActionCreators 
  return new Promise((resolve, reject) => { 
    graphql(' 
      { 
        allHnStory(sort: { fields: [order] }, limit: 10) { 
          edges { 
            node { 
              id 
            } 
          } 
        } 
      } 
    ').then(result => { 
      if (result.errors) {
```

```jsx
        reject(result.errors) 
      } 

      const template = path.resolve('./src/templates/story.js') 

      result.data.allHnStory.edges.forEach(({ node }) => { 
        createPage({ 
          path: '/item/${node.id}', 
          component: template, 
          context: { 
            id: node.id, 
          }, 
        }) 
      }) 

      resolve() 
    })
  }) 
} 
```

这个模块导出了一个`createPages()`函数，Gatsby 将在构建时使用它来创建静态的 Hacker News 文章页面。它首先使用`grapghql()`函数执行查询，以找到您需要为其创建页面的所有文章节点：

```jsx
graphql(' 
  { 
    allHnStory(sort: { fields: [order] }, limit: 10) { 
      edges { 
        node { 
          id 
        } 
      } 
    } 
  } 
') 
```

接下来，对每个节点调用`createPage()`函数：

```jsx
const template = path.resolve('./src/templates/story.js') 

result.data.allHnStory.edges.forEach(({ node }) => { 
  createPage({ 
    path: '/item/${node.id}', 
    component: template, 
    context: { 
      id: node.id, 
    },
```

```jsx
  }) 
}) 
```

传递给`createPage()`的属性是：

+   `path`：这是访问时将呈现页面的 URL。

+   `component`：这是呈现页面内容的 React 组件的文件系统路径。

+   `context`：这是传递给 React 组件的数据。在这种情况下，组件知道文章 ID 非常重要。

这是您在使用 Gatsby 时可能会采取的一般方法，每当您有大量基于动态数据生成页面时，但是相同的 React 组件可以用于呈现内容。换句话说，您可能更愿意在 React 组件中编写此代码，而不是为每篇文章单独编写组件。

让我们来看一下用于呈现文章详细信息页面的组件：

```jsx
import React from 'react' 

import StoryItem from '../components/story-item' 
import Comment from '../components/comment' 

const Story = ({ data }) => ( 
  <div> 
    <StoryItem story={data.hnStory} active={true} /> 
    <ul> 
      {data.hnStory.children.map(comment => ( 
        <Comment key={comment.id} data={comment} /> 
      ))} 
    </ul> 
  </div> 
) 

export default Story 

export const pageQuery = graphql' 
  query StoryQuery($id: String!) { 
    hnStory(id: { eq: $id }) { 
      ...Story 
      children { 
        ...Comment 
      } 
    } 
  } 
' 
```

再次，该组件依赖于 Gatsby 执行`pageQuery`常量中的 GraphQL 查询。上下文被传递给`gatsby-node.js`中的`createPage()`。这就是您能够将`$id`参数传递到查询中，以便您可以查询特定的故事数据的方式。

# 总结

在本章中，您了解了 Gatsby，这是一个基于 React 组件生成静态网站的工具。我们在本章开始时讨论了为什么您可能希望考虑构建静态站点，以及为什么 React 非常适合这项工作。静态站点会带来更好的用户体验，因为它们不像常规的 React 应用程序那样利用相同类型的资源。

接下来，您构建了自己的第一个 Gatsby 网站。您了解了 Gatsby 起始模板创建的基本文件布局以及如何将页面链接在一起。然后，您了解到 Gatsby 数据是由插件架构驱动的。Gatsby 能够通过插件支持各种数据源。您开始使用本地文件系统数据。接下来，您了解了转换器插件。这些类型的 Gatsby 插件使特定类型的数据源能够通过 GraphQL 进行查询。

最后，您看了一个使用 Gatsby 构建的 Hacker News 示例。这使您能够获取远程 API 数据作为数据源，并根据 GraphQL 查询结果动态生成页面。

在下一章，也是最后一章中，您将了解有关工具的内容，以便将您的 React 应用程序与其消耗的服务一起进行容器化和部署。


# 第十一章：使用 Docker 容器构建和部署 React 应用程序

在本书的这一部分，你一直在使用各种工具以开发模式运行你的 React 应用程序。在本章中，我们将把重点转向生产环境工具。总体目标是能够将你的 React 应用程序部署到生产环境中。幸运的是，有很多工具可以帮助你完成这项工作，在本章中你将熟悉这些工具。本章的目标是：

+   构建一个基本的消息 React 应用，利用 API

+   使用 Node 容器来运行你的 React 应用

+   将您的应用程序拆分为可部署的容器中运行的服务

+   在生产环境中使用静态 React 构建

# 构建一个消息应用

在没有任何上下文的情况下讨论用于部署 React 应用程序的工具是困难的。为此，你将组合一个基本的消息应用。在本节中，你将看到应用程序的工作原理和构建方式。然后，你将准备好进行剩余章节的学习，学习如何将你的应用程序部署为一组容器。

这个应用的基本思想是能够登录并向你的联系人发送消息，同时也能接收消息。我们会保持它非常简单。在功能上，它几乎可以匹配短信的功能。事实上，这可以是应用的标题——*Barely SMS*。这个想法是有一个 React 应用程序，有足够多的活动部分可以在生产环境中测试，以及一个稍后可以部署在容器中的服务器。

为了视觉效果，我们将使用 Material-UI（[`material-ui-next.com/`](https://material-ui-next.com/)）组件库。然而，UI 组件的选择不应影响本章的教训。

# 启动 Barely SMS

为了熟悉*Barely SMS*，让我们在终端中以与本书中一直以来一样的方式启动它。一旦你切换到本书附带的源代码包中的`building-a-messaging-app`目录中，你可以像任何其他`create-react-app`项目一样启动开发服务器：

```jsx
npm start
```

在另一个终端窗口或选项卡中，你可以通过在同一目录中运行以下命令来启动*Barely SMS*的 API 服务器：

```jsx
npm run api
```

这将启动一个基本的 Express（[`expressjs.com/`](http://expressjs.com/)）应用。一旦服务器启动并监听请求，你应该看到以下输出：

```jsx
API server listening on port 3001!  
```

现在你已经准备好登录了。

# 登录

当您首次加载 UI 时，您应该看到这样的登录屏幕：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/ec33f5d6-91f8-4260-a34d-844e97afd21a.png)

以下模拟用户作为 API 的一部分存在：

+   `user1`

+   `user2`

+   `user3`

+   `user4`

+   `user5`

实际上，密码并没有被验证，所以留空或输入胡言乱语都应该验证之前的任何用户。让我们来看一下呈现此页面的“登录”组件：

```jsx
import React, { Component } from 'react';

import { withStyles } from 'material-ui/styles';
import TextField from 'material-ui/TextField';
import Button from 'material-ui/Button';

import { login } from './api';

const styles = theme => ({
  container: {
    display: 'flex',
    flexWrap: 'wrap'
  },
  textField: {
    marginLeft: theme.spacing.unit,
    marginRight: theme.spacing.unit,
    width: 200
  },
  button: {
    margin: theme.spacing.unit
  }
});

class Login extends Component {
  state = {
    user: '',
    password: ''
  };

  onInputChange = name => event => {
    this.setState({
      [name]: event.target.value
    });
  };

  onLoginClick = () => {
    login(this.state).then(resp => {
      if (resp.status === 200) {
        this.props.history.push('/');
      }
    });
  };

  componentWillMount() {
    this.props.setTitle('Login');
  }

  render() {
    const { classes } = this.props;
    return (
      <div className={classes.container}>
        <TextField
          id="user"
          label="User"
          className={classes.textField}
          value={this.state.user}
          onChange={this.onInputChange('user')}
          margin="normal"
        />
        <TextField
          id="password"
          label="Password"
          className={classes.textField}
          value={this.state.password}
          onChange={this.onInputChange('password')}
          type="password"
          autoComplete="current-password"
          margin="normal"
        />
        <Button
          variant="raised"
          color="primary"
          className={classes.button}
          onClick={this.onLoginClick}
        >
          Login
        </Button>
      </div>
    );
  }
}
export default withStyles(styles)(Login);
```

这里有很多 Material-UI，但可以忽略大部分。重要的是从`api`模块导入的`login()`函数。这用于调用`/api/login`端点。从生产 React 部署的角度来看，这是相关的，因为这是与可能部署为自己的容器的服务进行交互。

# 主页

如果您能成功登录，您将被带到应用程序的主页。您应该看到一个看起来像这样的页面：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/78c26332-ca7d-4f7f-881f-217225d77bd4.png)

*Barely SMS*的主页显示了当前在线的用户联系人。在这种情况下，显然还没有其他用户在线。现在让我们来看一下“主页”组件的源代码：

```jsx
import React, { Component } from 'react';

import { withStyles } from 'material-ui/styles';
import Paper from 'material-ui/Paper';
import Avatar from 'material-ui/Avatar';
import IconButton from 'material-ui/IconButton';

import ContactMail from 'material-ui-icons/ContactMail';
import Message from 'material-ui-icons/Message';

import List, {
  ListItem,
  ListItemAvatar,
  ListItemText,
  ListItemSecondaryAction
} from 'material-ui/List';

import EmptyMessage from './EmptyMessage';
import { getContacts } from './api';

const styles = theme => ({
  root: {
    margin: '10px',
    width: '100%',
    maxWidth: 500,
    backgroundColor: theme.palette.background.paper
  }
});

class Home extends Component {
  state = {
    contacts: []
  };

  onMessageClick = id => () => {
    this.props.history.push(`/newmessage/${id}`);
  };

  componentWillMount() {
    const { setTitle, history } = this.props;

    setTitle('Barely SMS');

    const refresh = () =>
      getContacts().then(resp => {
        if (resp.status === 403) {
          history.push('/login');
        } else {
          resp.json().then(contacts => {
            this.setState({
              contacts: contacts.filter(contact => contact.online)
            });
          });
        }
      });

    this.refreshInterval = setInterval(refresh, 5000);
    refresh();
  }

  componentWillUnmount() {
    clearInterval(this.refreshInterval);
  }

  render() {
    const { classes } = this.props;
    const { contacts } = this.state;
    const { onMessageClick } = this;

    return (
      <Paper className={classes.root}>
        <EmptyMessage coll={contacts}>
          No contacts online
        </EmptyMessage>
        <List component="nav">
          {contacts.map(contact => (
            <ListItem key={contact.id}>
              <ListItemAvatar>
                <Avatar>
                  <ContactMail />
                </Avatar>
              </ListItemAvatar>
              <ListItemText primary={contact.name} />
              <ListItemSecondaryAction>
                <IconButton onClick={onMessageClick(contact.id)}>
                  <Message />
                </IconButton>
              </ListItemSecondaryAction>
            </ListItem>
          ))}
        </List>
      </Paper>
    );
  }
}

export default withStyles(styles)(Home);
```

在`componentWillMount()`生命周期方法中，使用`getContacts()`函数获取联系人 API 端点。然后使用间隔重复此操作，以便当您的联系人登录时，它们会显示在这里。当组件被卸载时，间隔被清除。

为了测试这一点，我将打开 Firefox（实际上使用哪个浏览器并不重要，只要它与您登录为`user1`的地方不同）。从这里，我可以登录为`user2`，这是`user1`的联系人，反之亦然：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/d501457c-2f04-4794-a963-3096931a1049.png)

当我在这里第一次登录时，我看到用户 1 在另一个浏览器上线了：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/ba043e19-7741-4420-bafb-285a5ef83fe1.png)

现在，如果我回到在 Chrome 中登录为用户 1 的地方，我应该看到我的用户 2 联系人已经登录：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/0601e247-9a9b-4618-b9e5-65bdb8116db9.png)

这个应用程序将在其他页面上遵循类似的刷新模式——使用间隔从 API 服务端点获取数据。

# 联系人页面

如果您想查看所有联系人，而不仅仅是当前在线的联系人，您必须转到联系人页面。要到达那里，您必须通过单击标题左侧的汉堡按钮展开导航菜单：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/486fc220-77b9-4373-8e04-54f73ad9299a.png)

当您点击联系人链接时，您将进入看起来像这样的联系人页面：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/3a72390a-a867-4bdd-8c65-e60d836db914.png)

这个页面与主页非常相似，只是显示了所有联系人。您可以向任何用户发送消息，而不仅仅是当前在线的用户。让我们来看看`Contacts`组件：

```jsx
import React, { Component } from 'react';

import { withStyles } from 'material-ui/styles';
import Paper from 'material-ui/Paper';
import Avatar from 'material-ui/Avatar';
import IconButton from 'material-ui/IconButton';

import ContactMail from 'material-ui-icons/ContactMail';
import Message from 'material-ui-icons/Message';

import List, {
  ListItem,
  ListItemAvatar,
  ListItemText,
  ListItemSecondaryAction
} from 'material-ui/List';

import EmptyMessage from './EmptyMessage';
import { getContacts } from './api';

const styles = theme => ({
  root: {
    margin: '10px',
    width: '100%',
    maxWidth: 500,
    backgroundColor: theme.palette.background.paper
  }
});

class Contacts extends Component {
  state = {
    contacts: []
  };

  onMessageClick = id => () => {
    this.props.history.push(`/newmessage/${id}`);
  };

  componentWillMount() {
    const { setTitle, history } = this.props;

    setTitle('Contacts');

    const refresh = () =>
      getContacts().then(resp => {
        if (resp.status === 403) {
          history.push('/login');
        } else {
          resp.json().then(contacts => {
            this.setState({ contacts });
          });
        }
      });

    this.refreshInterval = setInterval(refresh, 5000);
    refresh();
  }

  componentWillUnmount() {
    clearInterval(this.refreshInterval);
  }

  render() {
    const { classes } = this.props;
    const { contacts } = this.state;
    const { onMessageClick } = this;

    return (
      <Paper className={classes.root}>
        <EmptyMessage coll={contacts}>No contacts</EmptyMessage>
        <List component="nav">
          {contacts.map(contact => (
            <ListItem key={contact.id}>
              <ListItemAvatar>
                <Avatar>
                  <ContactMail />
                </Avatar>
              </ListItemAvatar>
              <ListItemText primary={contact.name} />
              <ListItemSecondaryAction>
                <IconButton onClick={onMessageClick(contact.id)}>
                  <Message />
                </IconButton>
              </ListItemSecondaryAction>
            </ListItem>
          ))}
        </List>
      </Paper>
    );
  }
}

export default withStyles(styles)(Contacts);
```

像“主页”组件一样，“联系人”使用间隔模式来刷新联系人。例如，将来如果您想要在此页面上添加一个增强功能，以直观地指示哪些用户在线，您将需要从服务中获取最新数据。

# 消息页面

如果您展开导航菜单并访问消息页面，您会看到类似于这样的内容：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/f0d2b42c-32ae-449d-8ea0-7519231f9f04.png)

还没有消息。在发送消息之前，让我们看看`Messages`组件：

```jsx
import React, { Component } from 'react';
import moment from 'moment';
import { Link } from 'react-router-dom';

import { withStyles } from 'material-ui/styles';
import Paper from 'material-ui/Paper';
import Avatar from 'material-ui/Avatar';
import List, {
  ListItem,
  ListItemAvatar,
  ListItemText
} from 'material-ui/List';

import Message from 'material-ui-icons/Message';

import EmptyMessage from './EmptyMessage';
import { getMessages } from './api';

const styles = theme => ({
  root: {
    margin: '10px',
    width: '100%',
    maxWidth: 500,
    backgroundColor: theme.palette.background.paper
  }
});

class Messages extends Component {
  state = {
    messages: []
  };

  componentWillMount() {
    const { setTitle, history } = this.props;

    setTitle('Messages');

    const refresh = () =>
      getMessages().then(resp => {
        if (resp.status === 403) {
          history.push('/login');
        } else {
          resp.json().then(messages => {
            this.setState({
              messages: messages.map(message => ({
                ...message,
                duration: moment
                  .duration(new Date() - new Date(message.timestamp))
                  .humanize()
              }))
            });
          });
        }
      });

    this.refreshInterval = setInterval(refresh, 5000);
    refresh();
  }

  componentWillUnmount() {
    clearInterval(this.refreshInterval);
  }

  render() {
    const { classes } = this.props;
    const { messages } = this.state;

    return (
      <Paper className={classes.root}>
        <EmptyMessage coll={messages}>No messages</EmptyMessage>
        <List component="nav">
          {messages.map(message => (
            <ListItem
              key={message.id}
              component={Link}
              to={`/messages/${message.id}`}
            >
              <ListItemAvatar>
                <Avatar>
                  <Message />
                </Avatar>
              </ListItemAvatar>
              <ListItemText
                primary={message.fromName}
                secondary={`${message.duration} ago`}
              />
            </ListItem>
          ))}
        </List>
      </Paper>
    );
  }
}

export default withStyles(styles)(Messages);
```

同样，这里也使用了刷新数据的间隔模式。当用户点击其中一条消息时，他们将被带到消息详情页面，可以阅读消息内容。

# 发送消息

让我们回到另一个浏览器（在我这里是 Firefox），您以 User 2 身份登录。点击 User 1 旁边的小消息图标：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/29613984-ecaa-4e82-832f-c4d3753bdbf9.png)

这将带您到新消息页面：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/cad052ae-c842-4543-ab99-7428c3113bc9.png)

继续输入消息，然后点击发送。然后，回到 Chrome，您以 User 1 身份登录。您应该会在消息页面上看到来自 User 2 的新消息：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/269d214d-bbe1-4559-a06d-5b29486a596c.png)

如果您点击消息，您应该能够阅读消息内容：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/15d3bd2d-4a92-4ab9-b7a5-90aff7597e65.png)

在这里，您可以点击“回复”按钮，带您到新消息页面，该页面将发送给 User 2，或者您可以删除消息。在我们查看 API 代码之前，让我们看看`NewMessage`组件：

```jsx
import React, { Component } from 'react';

import { withStyles } from 'material-ui/styles';
import Paper from 'material-ui/Paper';
import TextField from 'material-ui/TextField';
import Button from 'material-ui/Button';

import Send from 'material-ui-icons/Send';

import { getUser, postMessage } from './api';

const styles = theme => ({
  root: {
    display: 'flex',
    flexWrap: 'wrap',
    flexDirection: 'column'
  },
  textField: {
    marginLeft: theme.spacing.unit,
    marginRight: theme.spacing.unit,
    width: 500
  },
  button: {
    width: 500,
    margin: theme.spacing.unit
  },
  rightIcon: {
    marginLeft: theme.spacing.unit
  }
});

class NewMessage extends Component {
  state = {
    message: ''
  };

  onMessageChange = event => {
    this.setState({
      message: event.target.value
    });
  };

  onSendClick = () => {
    const { match: { params: { id } }, history } = this.props;
    const { message } = this.state;

    postMessage({ to: id, message }).then(() => {
      this.setState({ message: '' });
      history.push('/');
    });
  };

  componentWillMount() {
    const {
      match: { params: { id } },
      setTitle,
      history
    } = this.props;

    getUser(id).then(resp => {
      if (resp.status === 403) {
        history.push('/login');
      } else {
        resp.json().then(user => {
          setTitle(`New message for ${user.name}`);
        });
      }
    });
  }

  render() {
    const { classes } = this.props;
    const { message } = this.state;
    const { onMessageChange, onSendClick } = this;

    return (
      <Paper className={classes.root}>
        <TextField
          id="multiline-static"
          label="Message"
          multiline
          rows="4"
          className={classes.textField}
          margin="normal"
          value={message}
          onChange={onMessageChange}
        />
        <Button
          variant="raised"
          color="primary"
          className={classes.button}
          onClick={onSendClick}
        >
          Send
          <Send className={classes.rightIcon} />
        </Button>
      </Paper>
    );
  }
}

export default withStyles(styles)(NewMessage);
```

在这里，使用`postMessage()` API 函数来使用 API 服务发送消息。现在让我们看看`MessageDetails`组件：

```jsx
import React, { Component } from 'react'; 
import { Link } from 'react-router-dom'; 

import { withStyles } from 'material-ui/styles'; 
import Paper from 'material-ui/Paper'; 
import Button from 'material-ui/Button'; 
import Typography from 'material-ui/Typography'; 

import Delete from 'material-ui-icons/Delete'; 
import Reply from 'material-ui-icons/Reply'; 

import { getMessage, deleteMessage } from './api'; 

const styles = theme => ({ 
  root: { 
    display: 'flex', 
    flexWrap: 'wrap', 
    flexDirection: 'column' 
  }, 
  message: { 
    width: 500, 
    margin: theme.spacing.unit 
  }, 
  button: { 
    width: 500, 
    margin: theme.spacing.unit 
  }, 
  rightIcon: { 
    marginLeft: theme.spacing.unit 
  } 
}); 

class NewMessage extends Component { 
  state = { 
    message: {} 
  }; 

  onDeleteClick = () => { 
    const { history, match: { params: { id } } } = this.props; 

    deleteMessage(id).then(() => { 
      history.push('/messages'); 
    }); 
  }; 

  componentWillMount() { 
    const { 
      match: { params: { id } }, 
      setTitle, 
      history 
    } = this.props; 

    getMessage(id).then(resp => { 
      if (resp.status === 403) { 
        history.push('/login'); 
      } else { 
        resp.json().then(message => { 
          setTitle(`Message from ${message.fromName}`); 
          this.setState({ message }); 
        }); 
      } 
    }); 
  } 

  render() { 
    const { classes } = this.props; 
    const { message } = this.state; 
    const { onDeleteClick } = this; 

    return ( 
      <Paper className={classes.root}> 
        <Typography className={classes.message}> 
          {message.message} 
        </Typography> 
        <Button 
          variant="raised" 
          color="primary" 
          className={classes.button} 
          component={Link} 
          to={`/newmessage/${message.from}`} 
        > 
          Reply 
          <Reply className={classes.rightIcon} /> 
        </Button> 
        <Button 
          variant="raised" 
          color="primary" 
          className={classes.button} 
          onClick={onDeleteClick} 
        > 
          Delete 
          <Delete className={classes.rightIcon} /> 
        </Button> 
      </Paper> 
    ); 
  } 
} 

export default withStyles(styles)(NewMessage); 
```

在这里，使用`getMessage()` API 函数来加载消息内容。请注意，这两个组件都没有使用其他组件一直在使用的刷新模式，因为信息从不改变。

# API

API 是您的 React 应用与之交互以检索和操作数据的服务。在考虑部署生产 React 应用程序时，重要的是使用 API 作为抽象，它不仅代表一个服务，还可能代表应用程序与之交互的多个微服务。

说到这里，让我们来看看您的 React 组件使用的 API 函数，这些组件组成了*Barely SMS*：

```jsx
export const login = body => 
  fetch('/api/login', { 
    method: 'post', 
    headers: { 'Content-Type': 'application/json' }, 
    body: JSON.stringify(body), 
    credentials: 'same-origin' 
  }); 

export const logout = user => 
  fetch('/api/logout', { 
    method: 'post', 
    credentials: 'same-origin' 
  }); 

export const getUser = id => 
  fetch(`/api/user/${id}`, { credentials: 'same-origin' }); 

export const getContacts = () => 
  fetch('/api/contacts', { credentials: 'same-origin' }); 

export const getMessages = () => 
  fetch('/api/messages', { credentials: 'same-origin' }); 

export const getMessage = id => 
  fetch(`/api/message/${id}`, { credentials: 'same-origin' }); 

export const postMessage = body => 
  fetch('/api/messages', { 
    method: 'post', 
    headers: { 'Content-Type': 'application/json' }, 
    body: JSON.stringify(body), 
    credentials: 'same-origin' 
  });

export const deleteMessage = id => 
  fetch(`/api/message/${id}`, { 
    method: 'delete', 
    credentials: 'same-origin' 
  }); 
```

这些简单的抽象使用`fetch()`来向 API 服务发出 HTTP 请求。目前，只有一个 API 服务作为单个进程运行，其中包含模拟用户数据，并且所有更改仅在内存中发生，不会持久保存：

```jsx
const express = require('express'); 
const bodyParser = require('body-parser'); 
const cookieParser = require('cookie-parser'); 

const sessions = []; 
const messages = []; 
const users = { 
  user1: { 
    name: 'User 1', 
    contacts: ['user2', 'user3', 'user4', 'user5'], 
    online: false 
  }, 
  user2: { 
    name: 'User 2', 
    contacts: ['user1', 'user3', 'user4', 'user5'], 
    online: false 
  }, 
  user3: { 
    name: 'User 3', 
    contacts: ['user1', 'user2', 'user4', 'user5'], 
    online: false 
  }, 
  user4: { 
    name: 'User 4', 
    contacts: ['user1', 'user2', 'user3', 'user5'], 
    online: false 
  }, 
  user5: { 
    name: 'User 5', 
    contacts: ['user1', 'user2', 'user3', 'user4'] 
  } 
}; 

const authenticate = (req, res, next) => { 
  if (!sessions.includes(req.cookies.session)) { 
    res.status(403).end(); 
  } else { 
    next(); 
  } 
}; 

const app = express(); 
app.use(cookieParser()); 
app.use(bodyParser.json()); 
app.use(bodyParser.urlencoded({ extended: true })); 

app.post('/api/login', (req, res) => { 
  const { user } = req.body; 

  if (users.hasOwnProperty(user)) { 
    sessions.push(user); 
    users[user].online = true; 
    res.cookie('session', user); 
    res.end(); 
  } else { 
    res.status(403).end(); 
  } 
}); 

app.post('/api/logout', (req, res) => { 
  const { session } = req.cookies; 
  const index = sessions.indexOf(session); 

  sessions.splice(index, 1); 
  users[session].online = false; 

  res.clearCookie('session'); 
  res.status(200).end(); 
}); 

app.get('/api/user/:id', authenticate, (req, res) => { 
  res.json(users[req.params.id]); 
}); 

app.get('/api/contacts', authenticate, (req, res) => { 
  res.json( 
    users[req.cookies.session].contacts.map(id => ({ 
      id, 
      name: users[id].name, 
      online: users[id].online 
    })) 
  ); 
}); 

app.post('/api/messages', authenticate, (req, res) => { 
  messages.push({ 
    from: req.cookies.session, 
    fromName: users[req.cookies.session].name, 
    to: req.body.to, 
    message: req.body.message, 
    timestamp: new Date() 
  }); 

  res.status(201).end(); 
}); 

app.get('/api/messages', authenticate, (req, res) => { 
  res.json( 
    messages 
      .map((message, id) => ({ ...message, id })) 
      .filter(message => message.to === req.cookies.session) 
  ); 
}); 

app.get('/api/message/:id', authenticate, (req, res) => { 
  const { params: { id } } = req; 
  res.json({ ...messages[id], id }); 
}); 

app.delete('/api/message/:id', authenticate, (req, res) => { 
  messages.splice(req.params.id, 1); 
  res.status(200).end(); 
}); 

app.listen(3001, () => 
  console.log('API server listening on port 3001!') 
);
```

这是一个 Express 应用程序，它将应用程序数据保存在简单的 JavaScript 对象和数组中。虽然现在所有事情都发生在这一个服务中，但情况可能并非总是如此。其中一些 API 调用可能存在于不同的服务中。这就是将部署到容器如此强大的原因——您可以在高级别上抽象复杂的部署。

# 开始使用 Node 容器

让我们首先通过在 Node.js Docker 镜像中运行*Barely SMS* React 开发服务器来开始。请注意，这不是生产部署的一部分。这只是一个起点，让您熟悉部署 Docker 容器。随着本章剩余部分的进行，您将逐渐向生产级部署迈进。

将 React 应用程序放入容器的第一步是创建一个`Dockerfile`。如果您的系统尚未安装 Docker，请在此处找到安装说明：[`www.docker.com/community-edition`](https://www.docker.com/community-edition)。如果您打开终端并切换到`getting-started-with-containers`目录，您将看到一个名为`Dockerfile`的文件。它看起来是这样的：

```jsx
FROM node:alpine
WORKDIR /usr/src/app
COPY package*.json ./
RUN npm install
COPY . .
EXPOSE 3000
CMD [ "npm", "start" ]
```

这是用于构建镜像的文件。镜像就像是运行 React 应用程序的容器进程的模板。基本上，这些行执行以下操作：

+   `FROM node:alpine`：这个镜像使用的基础镜像是什么。这是一个带有 Node.js 的小型 Linux 版本。

+   `WORKDIR /usr/src/app`：更改容器上的工作目录。

+   `COPY package*.json ./`：将`package.json`和`package-lock.json`复制到容器中。

+   `RUN npm install`：在容器上安装 npm 包依赖项。

+   `COPY . .`：将您的应用程序的源代码复制到容器中。

+   `EXPOSE 3000`：在容器运行时暴露端口`3000`。

+   `CMD [ "npm", "start" ]`：容器启动时运行`npm start`。

接下来要添加的文件是`.dockerignore`文件。此文件列出了您不希望通过`COPY`命令包含在镜像中的所有内容。它看起来像这样：

```jsx
node_modules
npm-debug.log
```

重要的是，您不要复制您在系统上安装的`npm_modules`，因为`npm install`命令将再次安装它们，您将拥有两份库的副本。

在构建可以部署的 Docker 镜像之前，有一些小的更改需要进行。首先，您需要弄清楚您的 IP 地址，以便您可以用它与 API 服务器进行通信。您可以通过在终端中运行`ifconfig`来找到它。一旦您找到了它，您可以更新`package.json`中的`proxy`值。以前是这样的：

```jsx
http://localhost:3001
```

现在它应该有一个 IP 地址，以便您的 Docker 容器在运行时可以访问它。这是我的现在的样子：

```jsx
http://192.168.86.237:3001
```

接下来，您需要将您的 IP 作为参数传递给`server.js`中的`listen()`方法。以前是这样的：

```jsx
app.listen(3001, () => 
  console.log('API server listening on port 3001!') 
); 
```

这是我的现在的样子：

```jsx
app.listen(3001, '192.168.86.237', () => 
  console.log('API server listening on port 3001!') 
); 
```

现在您可以通过运行以下命令来构建 Docker 镜像：

```jsx
docker build -t barely-sms-ui . 
```

这将使用当前目录中找到的`Dockerfile`构建一个 ID 为`barely-sms-ui`的镜像。构建完成后，您可以通过运行`docker images`来查看镜像。输出应该类似于这样：

```jsx
REPOSITORY       TAG      IMAGE ID       CREATED       SIZE
barely-sms-ui    latest   b1526915598d   7 hours ago   267MB
```

现在您可以使用以下命令部署容器：

```jsx
docker run -p 3000:3000 barely-sms-ui
```

要清理旧的未使用的容器，您可以运行以下命令：

```jsx
docker system prune
```

`-p 3000:3000`参数确保容器上的暴露端口`3000`映射到您系统上的端口`3000`。您可以通过打开`http://localhost:3000/`来测试这一点。但是，您可能会看到类似于这样的错误：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/f345d99f-4de5-4ba7-b55b-b200a24620b7.png)

如果您查看容器控制台输出，您将看到类似以下的内容：

```jsx
    Proxy error: Could not proxy request /api/contacts from localhost:3000 to http://192.168.86.237:3001.
    See https://nodejs.org/api/errors.html#errors_common_system_errors for more information (ECONNREFUSED).
```

这是因为您还没有启动 API 服务器。如果您将无效的 IP 地址作为代理地址，您实际上会看到类似的错误。如果您需要更改代理值，您将需要重新构建镜像，然后重新启动容器。如果您在另一个终端中运行`npm run api`来启动 API，然后重新加载 UI，一切应该按预期工作。

# 使用服务构建 React 应用

前一部分的主要挑战是，你有一个作为运行容器的用户界面服务。另一方面，API 服务正在做自己的事情。你将学习如何使用的下一个工具是`docker-compose`。顾名思义，`docker-compose`是用来将较小的服务组合成较大应用程序的工具。*Barely SMS*的下一个自然步骤是使用这个 Docker 工具来制作 API 服务，并将两个服务作为一个应用程序进行控制。

这一次，我们需要两个`Dockerfile`文件。你可以重用前面部分的`Dockerfile`，只需将其重命名为`Dockerfile.ui`。然后，创建另一个几乎相同的`Dockerfile`，将其命名为`Dockerfile.api`并给它以下内容：

```jsx
FROM node:alpine
WORKDIR /usr/src/app
COPY package*.json ./
RUN npm install
COPY . .
EXPOSE 3001
CMD [ "npm", "run", "api" ]
```

两个不同之处是`EXPOSE`端口值和运行的`CMD`。这个命令启动 API 服务器而不是 React 开发服务器。

在构建镜像之前，`server.js`和`package.js`文件需要进行轻微调整。在`package.json`中，代理可以简单地指向`http://api:3001`。在`server.js`中，确保你不再向`listen()`传递特定的 IP 地址。

```jsx
app.listen(3001, () => 
  console.log('API server listening on port 3001!') 
); 
```

构建这两个镜像也需要进行轻微修改，因为你不再使用标准的`Dockerfile`名称。以下是构建 UI 镜像的方法：

```jsx
docker build -f Dockerfile.ui -t barely-sms-ui . 
```

然后，构建 API 镜像：

```jsx
docker build -f Dockerfile.api -t barely-sms-api .
```

在这一点上，你已经准备好创建一个`docker-compose.yml`。这是你在调用时声明`docker-compose`工具应该做什么的方式。它看起来像这样：

```jsx
api:
  image: barely-sms-api
  expose:
    - 3001
  ports:
    - "3001:3001"

ui:
  image: barely-sms-ui
  expose:
    - 3000
  links:
    - api
  ports:
    - "3000:3000"
```

正如你所看到的，这个 YAML 标记分为两个服务。首先是`api`服务，它指向`barely-sms-api`镜像并相应地映射端口。然后是`ui`服务，它做同样的事情，只是它指向`barely-sms-ui`镜像并映射到不同的端口。它还链接到 API 服务，因为你希望在任何浏览器中加载 UI 之前确保 API 服务可用。

要启动服务，你可以运行以下命令：

```jsx
docker-compose up
```

然后，您应该在控制台中看到来自两个服务的日志。然后，如果您访问`http://localhost:3000/`，您应该能够像往常一样使用*Barely SMS*，只是这一次，一切都是自包含的。从这一点开始，您将更有可能根据需求发展您的应用程序。必要时，您可以添加新的服务，并让您的 React 组件与它们通信，就像它们都在与同一个应用程序交谈一样，同时保持服务的模块化和自包含性。

# 生产环境的静态 React 构建

使*Barely SMS*准备好进行生产部署的最后一步是从 UI 服务中删除 React 开发服务器。开发服务器从未被用于生产环境，因为它有许多部分可以帮助开发人员，但最终会减慢整体用户体验，并且在生产环境中没有位置。

您可以使用一个简单的 NGINX HTTP 服务器来代替基于 Node.js 的镜像，该服务器提供静态内容。由于这是一个生产环境，您不需要一个能够即时构建 UI 资产的开发服务器，您可以只使用`create-react-app`构建脚本来构建 NGINX 要提供的静态构件：

```jsx
npm run build
```

然后，您可以更改`Dockerfile.ui`文件，使其看起来像这样：

```jsx
FROM nginx:alpine 
EXPOSE 3000 
COPY nginx.conf /etc/nginx/nginx.conf 
COPY build /data/www 
CMD ["nginx", "-g", "daemon off;"] 
```

这次，镜像是基于一个提供静态内容的 NGINX 服务器，并且我们传递了一个`nginx.conf`文件。这是它的样子：

```jsx
worker_processes 2; 

events { 
  worker_connections 2048; 
} 

http { 
  upstream service_api { 
    server api:3001; 
  } 

  server { 
    location / { 
      root /data/www; 
      try_files $uri /index.html; 
    } 

    location /api { 
      proxy_pass http://service_api; 
    } 
  } 
} 
```

在这里，您可以对 HTTP 请求发送的位置进行精细级别的控制。例如，如果`/api/login`和`/api/logout`端点被移动到它们自己的服务中，您可以在这里控制这个变化，而不必重新构建 UI 图像。

需要做的最后一个变化是`docker-compose.yml`：

```jsx
api: 
  image: barely-sms-api 
  expose: 
    - 3001 
  ports: 
    - "3001:3001" 

ui: 
  image: barely-sms-ui 
  expose: 
    - 80 
  links: 
    - api 
  ports: 
    - "3000:80" 
```

您是否注意到端口`3000`现在映射到`ui`服务中的端口`80`？这是因为 NGINX 在端口`80`上提供服务。如果您运行`docker-compose up`，您应该能够访问`http://localhost:3000/`并与您的静态构建进行交互。

恭喜！没有了 React 开发服务器，您几乎可以从构建工具的角度准备好进行生产。

# 总结

在这一章中，您构建了一个名为“Barely SMS”的简单消息应用程序。然后，您学习了如何将此应用程序部署为 Docker 容器。接着，您学习了如何将服务打包在一起，包括 UI 服务，这样在部署具有许多移动部分的应用程序时，您就有了更高级的抽象层来处理。最后，您学习了如何构建生产就绪的静态资产，并使用工业级的 HTTP 服务器 NGINX 来提供它们。

我希望这是一次启发性的阅读。写作既是挑战，也是快乐。在过去的十年里，Web 开发中的工具应该不应该像它一样困难。像 React 这样的项目和 Chrome 等浏览器供应商开始改变这一趋势。我相信任何技术都取决于其工具。现在您对 React 生态系统中可用的工具有了牢固的掌握，将其充分利用，并让它为您做艰苦的工作。
