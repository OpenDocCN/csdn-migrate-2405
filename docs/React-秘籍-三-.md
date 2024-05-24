# React 秘籍（三）

> 原文：[`zh.annas-archive.org/md5/AADE5F3EA1B3765C530CB4A24FAA7E7E`](https://zh.annas-archive.org/md5/AADE5F3EA1B3765C530CB4A24FAA7E7E)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：精通 Redux

在本章中，将介绍以下配方：

+   创建 Redux 存储

+   创建操作创建者和分派操作

+   使用 Redux 实现 Firebase

# 介绍

Redux 是 JavaScript 应用程序的可预测状态容器。这意味着 Redux 可以与原生 JavaScript 或诸如 Angular 和 jQuery 之类的框架/库一起使用。Redux 主要是一个负责发出状态更新和响应操作的库。Redux 广泛与 React 一起使用。修改应用程序状态的方式是通过发出称为操作的事件来处理，而不是直接修改应用程序的状态。这些事件是函数（也称为操作创建者），始终返回两个关键属性，即`type`（表示正在执行的操作类型，类型通常应定义为字符串常量）和`payload`（要在操作中传递的数据）。这些函数发出的事件由减速器订阅。减速器是纯函数，用于决定每个操作将如何转换应用程序的状态。所有状态更改都在一个地方处理：Redux 存储。

没有 Redux，需要复杂的模式来在应用程序组件之间通信。Redux 通过使用应用程序存储将状态更改广播到组件来简化此过程。在 React Redux 应用程序中，组件将订阅存储，而存储将更改广播到组件。此图表完美地描述了 Redux 的工作原理：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/1864eaa9-7cac-44ea-b7ab-c054633d32e6.png)Redux 建议将 Redux 状态处理为不可变的。然而，JavaScript 中的对象和数组并非如此，这可能会导致我们错误地直接改变状态*。*

这些是 Redux 的三个原则：

+   **单一数据源：**整个应用程序的状态存储在单个存储中的对象树中。

+   **状态是只读的：**更改状态的唯一方法是发出操作，描述发生了什么的对象。

+   **使用纯函数进行更改：**为了指定状态树如何被操作转换，您编写纯减速器。

此信息摘自 Redux 的官方网站。要了解更多，请访问[`redux.js.org/introduction/three-principles`](https://redux.js.org/introduction/three-principles)。

**什么是操作？**

动作是从应用程序发送数据到存储的信息有效载荷。它们是存储的唯一信息来源。您可以使用`store.dispatch()`将它们发送到存储。动作是简单的 JavaScript 对象，必须具有一个名为`type`的属性，指示正在执行的动作类型，以及一个`payload`，其中包含动作中包含的信息。

**什么是不可变性？**

不可变性是 Redux 中的一个基本概念。要更改状态，必须返回一个新对象。

这些是 JavaScript 中的不可变类型：

+   数字

+   字符串

+   布尔值

+   未定义

+   空

这些是 JavaScript 中的可变类型：

+   数组

+   函数

+   对象

**为什么要不可变性？**

+   **更清晰**：我们知道谁改变了状态（reducer）

+   **更好的性能**

+   **易于调试：**我们可以使用 Redux DevTools（我们将在第十二章中介绍该主题，*测试和调试*）

我们可以通过以下方式使用不可变性：

+   ES6：**

+   `Object.assign`

+   `Spread`操作符（...）

+   库：**

+   `Immutable.js`

+   `Lodash`（合并和扩展）

**什么是 reducer？**

reducer 类似于一个绞肉机。在绞肉机中，我们在顶部添加原料（状态和动作），在另一端得到结果（新状态）：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/e9b74645-270f-453e-bbc2-42d4f76337d1.png)

在技术术语中，reducer 是一个纯函数，它接收两个参数（当前状态和动作），并根据动作返回一个新的不可变状态。

**组件类型**

容器：

+   专注于工作原理

+   连接到 Redux

+   分派 Redux 动作

+   由`react-redux`生成

展示性：

+   专注于外观

+   未连接到 Redux

+   通过 props 接收数据或函数

+   大多数时间是无状态的

**Redux 流程**

Redux 流程在从 UI（`React`组件）调用动作时开始。此动作将向存储发送信息（`type`和`payload`），存储将与 reducer 交互以根据动作类型更新状态。一旦 reducer 更新了状态，它将将值返回给存储，然后存储将新值发送到我们的 React 应用程序：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/5814d1cd-42ca-41a5-b92e-365f01b5fd47.png)

# 创建 Redux 存储

存储保存应用程序的整个状态，更改内部状态的唯一方法是分派动作。存储不是一个类；它只是一个带有一些方法的对象。

存储方法如下：

+   `getState()`**: **返回应用程序的当前状态

+   `dispatch(action)`: 分派一个动作，是触发状态改变的唯一方式

+   `subscribe(listener)`: 添加一个变更监听器，每次分派一个动作时都会调用它

+   `replaceReducer(nextReducer)`: 替换当前由存储使用的 reducer 来计算状态

# 准备工作

使用 Redux，我们需要安装以下软件包：

```jsx
npm install redux react-redux 
```

# 如何做...

首先，我们需要为我们的存储创建一个文件，位于`src/shared/redux/configureStore.js`：

1.  让我们继续编写以下代码：

```jsx
 // Dependencies
  import { createStore } from 'redux';

 // Root Reducer
  import rootReducer from '../reducers';

  export default function configureStore(initialState) {
    return createStore(
      rootReducer,
      initialState
    );
  }
```

文件：src/shared/redux/configureStore.js

1.  我们需要做的第二件事是在我们的`public/index.html`文件中创建我们的`initialState`变量。现在，我们将创建一个设备状态，以检测用户是使用手机还是台式机：

```jsx
<body>
  <div id="root"></div>

  <script>
    // Detecting the user device
    const isMobile = /iPhone|Android/i.test(navigator.userAgent);

    // Creating our initialState
    const initialState = {
      device: {
        isMobile
      }
    };

    // Saving our initialState to the window object
    window.initialState = initialState;
  </script>
</body>
```

文件：public/index.html

1.  我们需要在我们的共享文件夹中创建一个`reducers`目录。我们需要创建的第一个 reducer 是`deviceReducer`：

```jsx
export default function deviceReducer(state = {}) {
  return state;
}
```

文件：src/shared/reducers/deviceReducer.js

1.  一旦我们创建了`deviceReducer`，我们需要创建一个`index.js`文件，在这里我们将导入所有我们的 reducer 并将它们组合成一个`rootReducer`：

```jsx
// Dependencies
import { combineReducers } from 'redux';

// Shared Reducers
import device from './deviceReducer';

const rootReducer = combineReducers({
  device
});

export default rootReducer;
```

文件：src/shared/reducers/index.js

1.  现在让我们修改我们的`src/index.js`文件。我们需要创建我们的 Redux 存储并将其传递给我们的提供者：

```jsx
import React from 'react';
import { render } from 'react-dom';
import { BrowserRouter as Router } from 'react-router-dom';
import { Provider } from 'react-redux';
import './index.css';

// Redux Store
import configureStore from './shared/redux/configureStore';

// Routes
import AppRoutes from './routes';

// Configuring Redux Store
const store = configureStore(window.initialState);

// DOM
const rootElement = document.getElementById('root');

// App Wrapper
const renderApp = Component => {
  render(
    <Provider store={store}>
      <Router>
        <Component />
      </Router>
    </Provider>,
    rootElement
  );
};

// Rendering our App
renderApp(AppRoutes);
```

1.  现在我们可以编辑我们的`Home`组件。我们需要使用`react-redux`中的`connect`将我们的组件连接到 Redux，然后使用`mapStateToProps`，我们将检索设备的状态：

```jsx
import React from 'react';
import { bool } from 'prop-types';
import { connect } from 'react-redux';

const Home = props => {
  const { isMobile } = props;

  return (
    <div className="Home">
      <h1>Home</h1>

      <p>
        You are using: 
        <strong>{isMobile ? 'mobile' : 'desktop'}</strong>
      </p>
    </div>
  );
};

Home.propTypes = {
  isMobile: bool
};

function mapStateToProps(state) {
  return {
    isMobile: state.device.isMobile
  };
}

function mapDispatchToProps() {
  return {};
}

export default connect(mapStateToProps, mapDispatchToProps)(Home);
```

# 它是如何工作的...

如果您正确地按照所有步骤进行了操作，您应该能够在桌面上使用 Chrome 看到这个视图：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/44c89862-1ff2-4b18-b5b8-a1ed4df7506e.png)

如果您激活 Chrome 设备模拟器，或者使用真实设备或 iPhone 模拟器，您将看到这个视图：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/5e0f3f18-83f4-4ac5-a99b-5e974353eff2.png)

**什么是 mapStateToProps?**

`mapStateToProps`函数通常会让很多人感到困惑，但它很容易理解。它获取状态的一部分（来自存储），并将其作为`prop`传递给您的组件。换句话说，接收`mapStateToProps`的参数是 Redux 状态，在里面您将拥有您在`rootReducer`中定义的所有 reducer，然后您返回一个包含您需要发送到组件的数据的对象。这里有一个例子：

```jsx
function mapStateToProps(state) {
  return {
    isMobile: state.device.isMobile
  };
}
```

如您所见，状态有一个`device`节点，这是我们的`deviceReducer`；还有其他方法可以做到这一点，大多数情况下会让很多人感到困惑。一种方法是使用 ES6 解构和箭头函数，类似于这样：

```jsx
const mapStateToProps = ({ device }) => ({
  isMobile: device.isMobile
});
```

还有另一种方法可以直接在`connect`中间件中进行。通常，这一开始可能会让人困惑，但一旦习惯了，这就是方法。我通常这样做：

```jsx
export default connect(({ device }) => ({
  isMobile: device.isMobile
}), null)(Home);
```

在将 Redux 状态映射到 props 之后，我们可以像这样检索数据：

```jsx
const { isMobile } = props;
```

如您所见，对于第二个参数`mapDispatchToProps`，我直接发送了一个空值，因为我们还没有在这个组件中分发动作。在下一个示例中，我将讨论`mapDispatchToProps`。

# 创建动作创建者和分发动作

动作是 Redux 中最关键的部分；它们负责触发 Redux Store 中的状态更新。在这个示例中，我们将使用它们的公共 API 显示[`www.coinmarketcap.com`](http://www.coinmarketcap.com)上列出的前 100 种加密货币。

# 准备工作

对于这个示例，我们需要安装 Axios（一个基于承诺的浏览器和 Node.js 的 HTTP 客户端）和 Redux Thunk（thunk 是一个包装表达式以延迟其评估的函数）：

```jsx
npm install axios redux-thunk
```

# 如何做...

我们将使用我们在上一个示例中创建的相同代码（`Repository: /Chapter05/Recipe1/store`）并进行一些修改：

1.  首先，我们需要创建新的文件夹：`src/actions`，`src/reducers`，`src/components/Coins`和`src/shared/utils`。

1.  我们需要创建的第一个文件是`src/actions/actionTypes.js`，在这里我们需要为我们的动作添加常量：

```jsx
export const FETCH_COINS_REQUEST = 'FETCH_COINS_REQUEST';
export const FETCH_COINS_SUCCESS = 'FETCH_COINS_SUCCESS';
export const FETCH_COINS_ERROR = 'FETCH_COINS_ERROR';
```

文件：src/actions/actionTypes.js

1.  也许您想知道为什么我们需要创建一个与字符串相同名称的常量。这是因为在使用常量时，我们不能有重复的常量名称（如果我们错误地重复一个常量名称，我们将会收到错误）。另一个原因是动作在两个文件中使用，在实际的动作文件中以及在我们的减速器中。为了避免重复字符串，我决定创建`actionTypes.js`文件并写入我们的常量。

1.  我喜欢将我的动作分为三部分：`request`，`received`和`error`。我称这些主要动作为基本动作，我们需要在`src/shared/redux/baseActions.js`中为这些动作创建一个文件：

```jsx
// Base Actions
export const request = type => ({
  type
});

export const received = (type, payload) => ({
  type,
  payload
});

export const error = type => ({
  type
});
```

文件：src/shared/redux/baseActions.js

1.  在我们构建了`baseActions.js`文件之后，我们需要为我们的 actions 创建另一个文件，这应该在`src/actions/coinsActions.js`内。对于这个示例，我们将使用`CoinMarketCap`的公共 API（[`api.coinmarketcap.com/v1/ticker/`](https://api.coinmarketcap.com/v1/ticker/)）：

```jsx
// Dependencies
import axios from 'axios';

// Action Types
import {
  FETCH_COINS_REQUEST,
  FETCH_COINS_SUCCESS,
  FETCH_COINS_ERROR
} from './actionTypes';

// Base Actions
 import { request, received, error } from '../shared/redux/baseActions';

export const fetchCoins = () => dispatch => {
  // Dispatching our request action
  dispatch(request(FETCH_COINS_REQUEST));

  // Axios Data
  const axiosData = {
    method: 'GET',
    url: 'https://api.coinmarketcap.com/v1/ticker/',
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/json'
    }
  };

  // If everything is correct we dispatch our received action   
  // otherwise our error action.
  return axios(axiosData)
    .then(response => dispatch(received(FETCH_COINS_SUCCESS, response.data)))
    .catch(err => {
      // eslint-disable-next-line no-console
      console.log('AXIOS ERROR:', err.response); 
      dispatch(error(FETCH_COINS_ERROR));
    });
};
```

文件：src/actions/coinsActions.js

1.  一旦我们的 actions 文件准备好了，我们需要创建我们的 reducer 文件来根据我们的 actions 更新我们的 Redux 状态。让我们在`src/reducers/coinsReducer.js`中创建一个文件：

```jsx
// Action Types
import {
  FETCH_COINS_SUCCESS,
  FETCH_SINGLE_COIN_SUCCESS
} from '../actions/actionTypes';

// Utils
import { getNewState } from '../shared/utils/frontend';

// Initial State
const initialState = {
  coins: []
};

export default function coinsReducer(state = initialState, action) {
  switch (action.type) {
    case FETCH_COINS_SUCCESS: {
      const { payload: coins } = action;

      return getNewState(state, {
        coins
      });
    }

    default:
      return state;
  }
};
```

文件：src/reducers/coinsReducer.js

1.  然后我们需要将我们的 reducer 添加到`src/shared/reducers/index.js`中的`combineReducers`中：

```jsx
// Dependencies
import { combineReducers } from 'redux';

// Components Reducers
import coins from '../../reducers/coinsReducer';

// Shared Reducers
import device from './deviceReducer';

const rootReducer = combineReducers({
  coins,
  device
});

export default rootReducer;
```

文件：src/shared/reducers/index.js

1.  如您所见，我包含了`getNewState`工具；这是一个执行`Object.assign`的基本函数，但更明确和易于理解，所以让我们在`src/shared/utils/frontend.js`中创建我们的`utils`文件。`isFirstRender`函数是我们的组件需要验证我们的数据是否为空的第一次尝试渲染：

```jsx
export function getNewState(state, newState) {
  return Object.assign({}, state, newState);
}

export function isFirstRender(items) {
  return !items || items.length === 0 || Object.keys(items).length === 0;
}
```

文件：src/shared/utils/frontend.js

1.  现在我们需要在`src/components/Coins/index.js`创建一个`Container`组件。在介绍中，我提到了有两种类型的组件：`container`和`presentational`。容器必须连接到 Redux，并且不应该有任何 JSX 代码，只有我们的`mapStateToProps`和`mapDispatchToProps`，然后在导出时，我们可以传递我们要渲染的`presentational`组件，将 actions 的值和我们的 Redux 状态作为 props 传递。要创建我们的`mapDispatchToProps`函数，我们需要使用 Redux 库中的`bindActionCreators`方法。这将把我们的`dispatch`方法绑定到我们传递的所有 actions 上。有不使用`bindActionCreators`的不同方法，但使用这种方法被认为是一个好的做法：

```jsx
// Dependencies
import { connect } from 'react-redux';
import { bindActionCreators } from 'redux';

// Components
import Coins from './Coins';

// Actions
import { fetchCoins } from '../../actions/coinsActions';

// Mapping our Redux State to Props
const mapStateToProps = ({ coins }) => ({
  coins
});

// Binding our fetchCoins action.
const mapDispatchToProps = dispatch => bindActionCreators(
  {
    fetchCoins
  },
  dispatch
);

export default connect(
  mapStateToProps,
  mapDispatchToProps
)(Coins);
```

文件：src/components/Coins/index.js

1.  我们在容器中导入的`Coins`组件如下：

```jsx
// Dependencies
import React, { Component } from 'react';
import { array } from 'prop-types';

// Utils
import { isFirstRender } from '../../shared/utils/frontend';

// Styles
import './Coins.css';

class Coins extends Component {
  static propTypes = {
    coins: array
  };

  componentWillMount() {
    const { fetchCoins } = this.props;

    // Fetching coins action.
    fetchCoins();
  }

  render() {
    const { coins: { coins } } = this.props;

    // If the coins const is an empty array, 
    // then we return null.
    if (isFirstRender(coins)) {
      return null;
    }
```

```jsx

    return (
      <div className="Coins">
        <h1>Top 100 Coins</h1>

        <ul>
          {coins.map((coin, key) => (
            <li key={key}>
              <span className="left">
                {coin.rank} {coin.name} {coin.symbol}
              </span>
              <span className="right">${coin.price_usd}</span>
            </li>
          ))}
        </ul>
      </div>
    );
  }
}

export default Coins;
```

文件：src/components/Coins/Coins.jsx

1.  这个组件的 CSS 如下：

```jsx
.Coins ul {
    margin: 0 auto;
    margin-bottom: 20px;
    padding: 0;
    list-style: none;
    width: 300px;
}

.Coins ul a {
    display: block;
    color: #333;
    text-decoration: none;
    background: #5ed4ff;
}

.Coins ul a:hover {
    color: #333;
    text-decoration: none;
    background: #baecff;
}

.Coins ul li {
    border-bottom: 1px solid black;
    text-align: left;
    padding: 10px;
    display: flex;
    justify-content: space-between;
}
```

文件：src/components/Coins/Coins.css

1.  在我们的`src/shared/redux/configureStore.js`文件中，我们需要导入`redux-thunk`并使用`applyMiddleware`方法在 Redux Store 中使用这个库：

```jsx
// Dependencies
import { createStore, applyMiddleware } from 'redux';
import thunk from 'redux-thunk';

// Root Reducer
import rootReducer from '../reducers';

export default function configureStore(initialState) {
  const middleware = [
    thunk
  ];

  return createStore(
    rootReducer,
    initialState,
    applyMiddleware(...middleware)
  );
}
```

文件：src/shared/redux/configureStore.js

1.  让我们在`Header`组件中添加到`/coins`的链接：

```jsx
import React from 'react';
import PropTypes from 'prop-types';
import { Link } from 'react-router-dom';
import logo from '../../images/logo.svg';

// We created a component with a simple arrow function.
const Header = props => {
  const {
    title = 'Welcome to React',
    url = 'http://localhost:3000'
  } = props;

  return (
    <header className="App-header">
      <a href={url}>
        <img src={logo} className="App-logo" alt="logo" />
      </a>

      <h1 className="App-title">{title}</h1>

      <ul>
        <li><Link to="/">Home</Link></li>
        <li><Link to="/about">About</Link></li>
        <li><Link to="/coins">Coins</Link></li>
        <li><Link to="/notes">Notes</Link></li>
        <li><Link to="/contact">Contact</Link></li>
      </ul>
    </header>
  );
};

// Even with Functional Components we are able to validate our PropTypes.
Header.propTypes = {
  title: PropTypes.string.isRequired,
  url: PropTypes.string
};

export default Header;
```

文件：src/shared/components/layout/Header.jsx

1.  最后，谜题的最后一部分是将我们的组件（容器）添加到我们的`src/routes.jsx`文件中：

```jsx
// Dependencies
import React from 'react';
import { Route, Switch } from 'react-router-dom';

// Components
import App from './components/App';
import About from './components/About';
import Coins from './components/Coins';
import Contact from './components/Contact';
import Home from './components/Home';
import Notes from './components/Notes';
import Error404 from './components/Error/404';

const AppRoutes = () => (
  <App>
    <Switch>
      <Route path="/" component={Home} exact />
      <Route path="/about" component={About} exact />
      <Route path="/coins" component={Coins} exact />
      <Route path="/contact" component={Contact} exact />
      <Route path="/notes" component={Notes} exact />
      <Route path="/notes/:noteId" component={Notes} exact />
      <Route component={Error404} />
    </Switch>
  </App>
);

export default AppRoutes;
```

文件：src/routes.jsx

# 它是如何工作的...

如果您打开 API（[`api.coinmarketcap.com/v1/ticker/`](https://api.coinmarketcap.com/v1/ticker/)），您将看到 JSON 对象如下：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/6194b6fa-fa14-43d5-9f57-8d1c34574af3.png)

我们将获得一个包含前 100 个硬币的对象数组[`coinmarketcap.com`](https://coinmarketcap.com)。如果您正确地按照所有步骤操作，您将能够看到这个视图：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/eb37334a-f135-4f72-a4c7-d2e4515c541f.png)

# 使用 Redux 实现 Firebase

Firebase 是 Google 云平台的一部分的后端即服务（BaaS）。Firebase 最受欢迎的服务之一是实时数据库，它使用 WebSocket 来同步您的数据。Firebase 还提供文件存储、身份验证（社交媒体和电子邮件/密码身份验证）、托管等服务。

您可以主要用 Firebase 来进行实时应用程序，但如果您愿意，您也可以将其用作非实时应用程序的常规数据库。Firebase 支持许多语言（如 JavaScript、Java、Python 和 Go）和平台，如 Android、iOS 和 Web。

Firebase 是免费的，但是如果您需要更多的容量，根据您的项目需求，他们有不同的计划。您可以在[`firebase.google.com/pricing`](https://firebase.google.com/pricing)上查看价格。

对于这个食谱，我们将使用 Firebase 的免费服务来展示一些流行的短语。这意味着您需要使用您的 Google 电子邮件在[`firebase.google.com`](https://firebase.google.com)上创建一个帐户。

# 准备就绪

一旦您在 Firebase 上注册，您需要通过在 Firebase 控制台中点击“添加项目”来创建一个新项目：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/715e8a41-7b17-4d52-a06d-a6c48842b8c6.png)

我将我的项目命名为`codejobs`；当然，您可以根据自己的喜好命名它：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/395ac84e-ed2c-4ea6-9683-7023a52e1cad.png)

如您所见，Firebase 自动向我们的项目 ID 添加了一个随机代码，但如果您希望确保项目 ID 不存在，您可以编辑它，之后您必须接受条款和条件并点击“创建项目”按钮：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/1626d2ba-4dd5-48e9-9003-355a68174fad.png)

现在您必须选择“将 Firebase 添加到您的 Web 应用程序”选项，并且您将获得有关您的应用程序的信息：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/5d8f5531-196f-4fea-8a7c-ef13f09f47c5.png)

不要将这些信息分享给任何人。我与您分享这些信息是因为我想向您展示如何将您的应用程序连接到 Firebase。

现在转到仪表板中的 Develop *|* Database，然后单击“创建数据库”按钮：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/41d1cd5c-ca68-4f27-ba66-6f96aea56046.png)

之后，选择“启动”选项以锁定模式，并单击“启用”按钮：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/30daac69-150e-4c72-b255-57ee04f83bbe.png)

然后，在页面顶部，选择下拉菜单并选择“实时数据库”选项：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/60e337e6-df1d-4d35-a0fa-17a331d2c13d.png)

一旦我们创建了实时数据库，让我们导入一些数据。要做到这一点，您可以在下拉菜单中选择“导入 JSON”选项：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/42dbdd11-3a28-4b18-a838-f0ac5113aa8e.png)

让我们创建一个基本的 JSON 文件来导入我们的短语数据：

```jsx
  {
    "phrases": [
      {
        "phrase": "A room without books is like a body without a 
       soul.",
        "author": "Marcus Tullius Cicero"
      },
      {
        "phrase": "Two things are infinite: the universe and human 
        stupidity; and I'm not sure about the universe.",
        "author": "Albert Einstein"
      },
      {
        "phrase": "You only live once, but if you do it right, once is 
         enough.",
        "author": "Mae West"
      },
      {
        "phrase": "If you tell the truth, you don't have to remember 
         anything.",
        "author": "Mark Twain"
      },
      {
        "phrase": "Be yourself; everyone else is already taken.",
        "author": "Oscar Wilde"
      }
    ]
  }
```

文件：src/data/phrases.json

将此文件保存在数据目录中，然后导入到 Firebase 数据库中：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/e8ac2bee-85ee-4748-88f4-c94389f76e35.png)

正如您在红色警告中所看到的，此位置的所有数据将被覆盖。这意味着如果您在数据库中有任何旧数据，它将被替换，因此在将新数据导入数据库时要小心。

如果您一切都做对了，您应该看到导入的数据如下：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/7a614200-3f94-4d98-8552-969484e31c97.png)

现在我们需要修改我们的权限以便能够在我们的数据库中读取和写入。如果您转到规则选项卡，您将看到类似于这样的内容：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/8771fb35-9746-476e-9866-a2677d68d9ac.png)

现在，让我们将它们更改为 true，然后单击“发布”按钮：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/0beaabd8-51fe-4e63-b360-a9a41da1e97a.png)

最后，我们已经完成了 Firebase 上所有需要的步骤。现在让我们在 React 中创建 Firebase 应用程序。我们将重用`CoinMarketCap`的最后一个配方（`存储库：Chapter05/Recipe2/coinmarketcap`）。我们需要做的第一件事是安装 firebase 依赖项：

```jsx
    npm install firebase      
```

# 如何做...

我从上一个配方中删除了一些组件，我只关注了 Phrases 应用程序。让我们按照以下步骤创建它：

1.  复制您的项目配置并将其替换到文件中：

```jsx
 export const fbConfig = {
    ref: 'phrases',
    app: {
      apiKey: 'AIzaSyASppMJh_6QIGTeXVBeYszzz7iTNTADxRU',
      authDomain: 'codejobs-2240b.firebaseapp.com',
      databaseURL: 'https://codejobs-2240b.firebaseio.com',
      projectId: 'codejobs-2240b',
      storageBucket: 'codejobs-2240b.appspot.com',
      messagingSenderId: '278058258089'
    }
  };
```

文件：src/config/firebase.js

1.  之后，我们需要创建一个文件来管理我们的 Firebase 数据库，并且我们将导出我们的`ref`（我们的短语表）：

```jsx
  import firebase from 'firebase';
  import { fbConfig } from '../../config/firebase';

  firebase.initializeApp(fbConfig.app);

 export default firebase.database().ref(fbConfig.ref);
```

文件：src/shared/firebase/database.js

1.  让我们为我们的组件准备好一切。首先，转到`routes`文件，并将`Phrases`容器添加到路由器的根路径：

```jsx
  // Dependencies
  import React from 'react';
  import { Route, Switch } from 'react-router-dom';

 // Components
  import App from './components/App';
  import Error404 from './components/Error/404';
  import Phrases from './components/Phrases';

  const AppRoutes = () => (
    <App>
      <Switch>
        <Route path="/" component={Phrases} exact />
        <Route component={Error404} />
      </Switch>
    </App>
  );

 export default AppRoutes;
```

文件：src/routes.jsx

1.  现在让我们创建我们的`actionTypes`文件：

```jsx
 export const FETCH_PHRASE_REQUEST = 'FETCH_PHRASE_REQUEST';
  export const FETCH_PHRASE_SUCCESS = 'FETCH_PHRASE_SUCCESS';

  export const ADD_PHRASE_REQUEST = 'ADD_PHRASE_REQUEST';

  export const DELETE_PHRASE_REQUEST = 'DELETE_PHRASE_REQUEST';
  export const DELETE_PHRASE_SUCCESS = 'DELETE_PHRASE_SUCCESS';

  export const UPDATE_PHRASE_REQUEST = 'UPDATE_PHRASE_REQUEST';
  export const UPDATE_PHRASE_SUCCESS = 'UPDATE_PHRASE_SUCCESS';
  export const UPDATE_PHRASE_ERROR = 'UPDATE_PHRASE_ERROR';
```

文件：src/actions/actionTypes.js

1.  现在，在我们的操作中，我们将执行四个任务（获取、添加、删除和更新），就像 CRUD（创建、读取、更新和删除）一样：

```jsx
 // Firebase Database
  import database from '../shared/firebase/database';

 // Action Types
 import {
    FETCH_PHRASE_REQUEST,
    FETCH_PHRASE_SUCCESS,
    ADD_PHRASE_REQUEST,
    DELETE_PHRASE_REQUEST,
    DELETE_PHRASE_SUCCESS,
    UPDATE_PHRASE_REQUEST,
    UPDATE_PHRASE_SUCCESS,
    UPDATE_PHRASE_ERROR
  } from './actionTypes';

  // Base Actions
 import { request, received } from '../shared/redux/baseActions';

  export const fetchPhrases = () => dispatch => {
    // Dispatching our FETCH_PHRASE_REQUEST action
    dispatch(request(FETCH_PHRASE_REQUEST));

    // Listening for added rows
    database.on('child_added', snapshot => {
      dispatch(received(
        FETCH_PHRASE_SUCCESS, 
        { 
          key: snapshot.key, 
          ...snapshot.val() 
        }
      ));
    });

    // Listening for updated rows
    database.on('child_changed', snapshot => {
      dispatch(received(
        UPDATE_PHRASE_SUCCESS, 
        { 
          key: snapshot.key, 
          ...snapshot.val() 
        }
      ));
    });

    // Lisetining for removed rows
    database.on('child_removed', snapshot => {
      dispatch(received(
        DELETE_PHRASE_SUCCESS, 
        { 
          key: snapshot.key 
        }
      ));
    });
  };

 export const addPhrase = (phrase, author) => dispatch => {
    // Dispatching our ADD_PHRASE_REQUEST action
    dispatch(request(ADD_PHRASE_REQUEST));

    // Adding a new element by pushing to the ref.
 // NOTE: Once this is executed the listener    // will be on fetchPhrases (child_added).
    database.push({
      phrase,
      author
    });
  }

  export const deletePhrase = key => dispatch => {
    // Dispatching our DELETE_PHRASE_REQUEST action
    dispatch(request(DELETE_PHRASE_REQUEST));

 // Removing element by key
 // NOTE: Once this is executed the listener 
 // will be on fetchPhrases (child_removed).
    database.child(key).remove();
  }

  export const updatePhrase = (key, phrase, author) => dispatch => {
    // Dispatching our UPDATE_PHRASE_REQUEST action
    dispatch(request(UPDATE_PHRASE_REQUEST));

    // Collecting our data...
    const data = {
      phrase,
      author
    };

    // Updating an element by key and data
    database
      // First we select our element by key
      .child(key) 
      // Updating the data in this point
      .update(data) 
      // Returning the updated data
      .then(() => database.once('value')) 
      // Getting the actual values of the snapshat
      .then(snapshot => snapshot.val()) 
      .catch(error => {
        // If there is an error we dispatch our error action
        dispatch(request(UPDATE_PHRASE_ERROR));

        return {
          errorCode: error.code,
          errorMessage: error.message
        };
      });
  };
```

文件：src/actions/phrasesActions.js 在 Firebase 中，我们不使用常规 ID。相反，Firebase 使用键值作为 ID。导入的数据就像一个基本数组，带有键 0、1、2、3、4 等，因此对于该数据，每个键都被用作 ID。但是当我们通过 Firebase 创建数据时，键将成为具有随机代码的唯一字符串值，例如`-lg4fgFQkfm`。

1.  在我们添加了操作之后，我们可以创建我们的 reducer 文件：

```jsx
  // Action Types
  import {
    FETCH_PHRASE_SUCCESS,
    DELETE_PHRASE_SUCCESS,
    UPDATE_PHRASE_SUCCESS,
  } from '../actions/actionTypes';

  // Utils
  import { getNewState } from '../shared/utils/frontend';

  // Initial State
  const initialState = {
    phrases: []
  };

  export default function phrasesReducer(state = initialState, action) {
    switch (action.type) {
      case FETCH_PHRASE_SUCCESS: {
        const { payload: phrase } = action;

        const newPhrases = [...state.phrases, phrase];

        return getNewState(state, {
          phrases: newPhrases
        });
      }

      case DELETE_PHRASE_SUCCESS: {
        const { payload: deletedPhrase } = action;

        const filteredPhrases = state.phrases.filter(
          phrase => phrase.key !== deletedPhrase.key
        );

        return getNewState(state, {
          phrases: filteredPhrases
        });
      }

      case UPDATE_PHRASE_SUCCESS: {
        const { payload: updatedPhrase } = action;

        const index = state.phrases.findIndex(
          phrase => phrase.key === updatedPhrase.key
        );

        state.phrases[index] = updatedPhrase;

        return getNewState({}, {
          phrases: state.phrases
        });
      }

      default:
       return state;
    }
  };
```

文件：src/reducers/phrasesReducer.js

1.  现在让我们创建我们的 Redux 容器。我们将包括我们将在组件中分派的所有操作，并连接 Redux 以获取短语状态：

```jsx
  // Dependencies
  import { connect } from 'react-redux';
  import { bindActionCreators } from 'redux';

  // Components
  import Phrases from './Phrases';

 // Actions
  import {
    addPhrase,
    deletePhrase,
    fetchPhrases,
    updatePhrase
  } from '../../actions/phrasesActions';

  const mapStateToProps = ({ phrases }) => ({
    phrases: phrases.phrases
  });

  const mapDispatchToProps = dispatch => bindActionCreators(
    {
      addPhrase,
      deletePhrase,
      fetchPhrases,
      updatePhrase
    },
    dispatch
  );

 export default connect(
    mapStateToProps,
    mapDispatchToProps
  )(Phrases);
```

文件：src/components/Phrases/index.js

1.  然后我们的`Phrases`组件将如下所示：

```jsx
  // Dependencies
  import React, { Component } from 'react';
  import { array } from 'prop-types';

  // Styles
  import './Phrases.css';

  class Phrases extends Component {
    static propTypes = {
      phrases: array
    };

    state = {
      phrase: '',
      author: '',
      editKey: false
    };

    componentWillMount() {
      this.props.fetchPhrases();
    }

    handleOnChange = e => {
      const { target: { name, value } } = e;

      this.setState({
        [name]: value
      });
    }

    handleAddNewPhrase = () => {
      if (this.state.phrase && this.state.author) {
        this.props.addPhrase(
          this.state.phrase, 
          this.state.author
        );

        // After we created the new phrase we clean the states
        this.setState({
          phrase: '',
          author: ''
        });
      }
    }

    handleDeleteElement = key => {
      this.props.deletePhrase(key);
    }

    handleEditElement = (key, phrase, author) => {
      this.setState({
        editKey: key,
        phrase,
        author
      });
    }

    handleUpdatePhrase = () => {
      if (this.state.phrase && this.state.author) {
        this.props.updatePhrase(
          this.state.editKey,
          this.state.phrase,
          this.state.author
        );

        this.setState({
          phrase: '',
          author: '',
          editKey: false
        });
      }
    }

    render() {
      const { phrases } = this.props;

      return (
        <div className="phrases">
          <div className="add">
            <p>Phrase: </p>

            <textarea 
              name="phrase" 
              value={this.state.phrase} 
              onChange={this.handleOnChange}
            ></textarea>

            <p>Author</p>

            <input 
              name="author" 
              type="text" 
              value={this.state.author} 
              onChange={this.handleOnChange} 
            />

            <p>
              <button 
                onClick={
                  this.state.editKey 
                    ? this.handleUpdatePhrase 
                    : this.handleAddNewPhrase
                }
              >
                {this.state.editKey 
                  ? 'Edit Phrase' 
                  : 'Add New Phrase'}
              </button>
            </p>
          </div>

          {phrases && phrases.map(({ key, phrase, author }) => (
            <blockquote key={key} className="phrase">
              <p className="mark">
                “
              </p>

              <p className="text">
                {phrase}
              </p>

              <hr />

              <p className="author">
                {author}
              </p>

              <a 
 onClick={() => { 
                  this.handleDeleteElement(key);
                }}
              >
                X
              </a>
              <a 
                onClick={
                  () => this.handleEditElement(key, phrase, author)
                }
              >
                Edit
              </a>
            </blockquote>
          ))}
        </div>
      );
    }
  }

  export default Phrases;
```

文件：src/components/Phrases/Phrases.jsx

1.  最后，我们的样式文件如下：

```jsx
 hr {
    width: 98%;
    border: 1px solid white;
  }

 .phrase {
    background-color: #2db2ff;
    border-radius: 17px;
    box-shadow: 2px 2px 2px 2px #E0E0E0;
    color: white;
    font-size: 20px;
    margin-top: 25px;
    overflow: hidden;
    border-left: none;
    padding: 20px;
  }

 .mark {
    color: white;
    font-family: "Times New Roman", Georgia, Serif;
    font-size: 100px;
    font-weight: bold;
    margin-top: -20px;
    text-align: left;
    text-indent: 20px;
  }

 .text {
    font-size: 30px;
    font-style: italic;
    margin: 0 auto;
    margin-top: -65px;
    text-align: center;
    width: 90%;
  }

 .author {
    font-size: 30px;
  }

  textarea {
    width: 50%;
    font-size: 30px;
    padding: 10px;
    border: 1px solid #333;
  }

  input {
    font-size: 30px;
    border: 1px solid #333;
  }

  a {
    cursor: pointer;
    float: right;
    margin-right: 10px;
  }
```

文件：src/components/Phrases/Phrases.css

# 它是如何工作的...

理解 Firebase 如何与 Redux 配合的关键是，您需要知道 Firebase 使用 WebSocket 来同步数据，这意味着数据是实时流式传输的。检测数据更改的方法是使用`database.on()`方法。

在`fetchPhrases()`操作中，我们有三个 Firebase 监听器：

+   `database.on('child_added')`: 它有两个功能。第一个功能是逐行从 Firebase 中获取数据（第一次）。第二个功能是检测当新行被添加到数据库并实时更新数据。

+   `database.on('child_changed')`: 它检测现有行的更改。当我们更新一行时，它起作用。

+   `database.on('child_removed')`: 检测到行被移除时。

还有另一种方法叫做`database.once('value')`，它与`child_added`做相同的事情，但是返回一个数组中的数据，只有一次。这意味着它不会像`child_added`那样检测动态更改。

如果您运行应用程序，您将看到这个视图：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/2a493371-7335-4d8e-9952-25f69825b101.png)

引用块太大，无法全部放入，但我们的最后一个是这样的：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/f344e1b9-b181-40de-8728-3c64c4d7e994.png)

让我们修改我们的`phrases.json`并添加一个新行：

```jsx
  {
    "phrases": [
      {
        "phrase": "A room without books is like a body without a 
        soul.",
        "author": "Marcus Tullius Cicero"
      },
      {
        "phrase": "Two things are infinite: the universe and human 
         stupidity; and 
         I'm not sure about the universe.",
        "author": "Albert Einstein"
      },
      {
        "phrase": "You only live once, but if you do it right, once is 
        enough.",
        "author": "Mae West"
      },
      {
        "phrase": "If you tell the truth, you don't have to remember 
        anything.",
        "author": "Mark Twain"
      },
      {
        "phrase": "Be yourself; everyone else is already taken.",
        "author": "Oscar Wilde"
      },
      {
        "phrase": "Hasta la vista, baby!",
        "author": "Terminator"
      }
    ]
  }
```

如果我们去 Firebase 并再次导入 JSON，我们将看到实时更新数据而无需刷新页面：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/950edc1d-c677-4a80-b8be-1fc01b41626e.png)

现在，如果您看到一个`X`链接来删除短语，让我们删除第一个（Marcus Tullius Cicero）。如果您在另一个标签页中打开 Firebase 页面，您将看到数据正在实时删除：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/cb3e194a-1ab6-432e-8b3b-66836499fd93.png)

此外，如果您添加新行（使用文本区域和输入），您将实时看到反映出来：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/fc05bfe5-2848-448d-b9b8-d7b6c0b8448e.png)

正如我之前提到的，当我们从 React 应用程序中添加新数据时，Firebase 将为新数据生成唯一键，而不是导入 JSON。在这种情况下，为新添加的短语生成了`-LJSYCHLHEe9QWiAiak4`键。

即使我们更新一行，我们也可以看到更改实时反映出来：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/e5e8e088-2c9f-4881-bfa7-193f5fba29f5.png)

正如您所看到的，所有操作都很容易实现，而且使用 Firebase 我们节省了大量时间，否则将花费在后端服务上。Firebase 太棒了！


# 第六章：使用 Redux Form 创建表单

在本章中，将涵盖以下配方：

+   使用本地状态创建受控表单

+   使用 Redux Form 构建表单

+   在表单中实现验证

# 介绍

表单是任何 Web 应用程序的基本部分，在接下来的配方中，我们将学习如何使用带有或不带有 Redux Form 的表单。

# 使用本地状态创建受控表单

对于这个配方，我们将创建一个简单的待办事项列表，使用我们的本地状态来使用表单。

# 准备工作

对于这个配方，我们需要安装`uuid`包来生成随机 ID，如下面的代码所示：

```jsx
npm install uuid
```

# 如何做…

让我们按照以下步骤创建我们的受控表单：

1.  首先，对于待办事项列表，我们将在`src/components/Todo/index.jsx`中创建一个名为`Todo`的新组件。我们将使用的框架如下所示：

```jsx
import React, { Component } from 'react';
import uuidv4 from 'uuid/v4';
import './Todo.css';

class Todo extends Component {
  constructor() {
    super();

    // Initial state...
    this.state = {
      task: '',
      items: []
    };
  }

  render() {
    return (
      <div className="Todo">
        <h1>New Task:</h1>

        <form onSubmit={this.handleOnSubmit}>
          <input value={this.state.task} />
        </form>
      </div>
    );
  }
}

export default Todo;
```

文件：src/components/Todo/index.jsx

1.  请记住，我们需要将组件添加到我们的`src/routes.jsx`中，如下面的代码所示：

```jsx
// Dependencies
import React from 'react';
import { Route, Switch } from 'react-router-dom';

// Components
import App from './components/App';
import About from './components/About';
import Coins from './components/Coins';
import Contact from './components/Contact';
import Home from './components/Home';
import Notes from './components/Notes';
import Todo from './components/Todo';
import Error404 from './components/Error/404';

const AppRoutes = () => (
  <App>
    <Switch>
      <Route path="/" component={Home} exact />
      <Route path="/about" component={About} exact />
      <Route path="/coins" component={Coins} exact />
      <Route path="/contact" component={Contact} exact />
      <Route path="/notes" component={Notes} exact />
      <Route path="/notes/:noteId" component={Notes} exact />
      <Route path="/todo" component={Todo} exact />
      <Route component={Error404} />
    </Switch>
  </App>
);

export default AppRoutes;
```

文件：src/routes.jsx

1.  如果你去`/todo`，你会看到输入框，但你可能会注意到无法在上面写任何东西，这是因为我们将我们的本地状态(`this.state.task`)连接到我们的输入值，但我们需要一个`onChange`函数来更新我们的状态，如下面的代码所示：

```jsx
import React, { Component } from 'react';
import uuidv4 from 'uuid/v4';
import './Todo.css';

class Todo extends Component {
  constructor() {
    super();

    // Initial state...
    this.state = {
      task: '',
      items: []
    };
  }

  handleOnChange = e => {
    const { target: { value } } = e;

    // Updating our task state with the input value...
    this.setState({
      task: value
    });
  }

  render() {
    return (
      <div className="Todo">
        <h1>New Task:</h1>

        <form onSubmit={this.handleOnSubmit}>
          <input 
 value={this.state.task} 
 onChange={this.handleOnChange} 
          />
        </form>
      </div>
    );
  }
}

export default Todo;
```

文件：src/components/Todo/index.jsx

1.  现在我们可以在输入框中写任何东西，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/5f6a8fe8-212c-425e-9885-da4300381960.png)

1.  为了保存输入的项目，我们需要在`form`标签中添加一个`onSubmit`函数，在这里我们需要更新我们的本地状态以将项目推送到`items`数组中。此外，我们需要包括我们的`List`组件，我们将在其中显示所有的项目。完整的代码如下：

```jsx
import React, { Component } from 'react';
import uuidv4 from 'uuid/v4';
import List from './List';
import './Todo.css';

class Todo extends Component {
  constructor() {
    super();

    // Initial state...
    this.state = {
      task: '',
      items: []
    };
  }

  handleOnChange = e => {
    const { target: { value } } = e;

    // Updating our task state with the input value...
    this.setState({
      task: value
    });
  }

  handleOnSubmit = e => {
    // Prevent default to avoid the actual form submit...
    e.preventDefault();

    // Once is submitted we reset the task value and we push 
    // task to the items array.
    this.setState({
      task: '',
      items: [
        ...this.state.items,
        {
          id: uuidv4(),
          task: this.state.task,
          complete: false
        }
      ]
    });
  }

  render() {
    return (
      <div className="Todo">
        <h1>New Task:</h1>

        <form onSubmit={this.handleOnSubmit}>
          <input 
            value={this.state.task} 
 onChange={this.handleOnChange} 
          />
        </form>

        <List items={this.state.items} />
      </div>
    );
  }
}

export default Todo;
```

文件：src/components/Todo/index.jsx

1.  我们的`List`组件将是一个功能性组件，我们将在其中渲染一个项目列表，如下面的代码所示：

```jsx
import React from 'react';

const List = props => (
  <ul>
    {props.items.map((item, key) => (
      <li key={key}>
        {item.task}
      </li>
    ))}
  </ul>
);

export default List;
```

文件：src/components/Todo/List.jsx

1.  最后，我们需要添加我们的 CSS 文件，如下面的代码所示：

```jsx
.Todo {
    background-color: #f5f5f5;
    border-radius: 4px;
    border: 1px solid #e3e3e3;
    box-shadow: inset 0 1px 1px rgba(0,0,0,.05);
    margin-bottom: 20px;
    margin: 50px auto;
    min-height: 20px;
    padding: 19px;
    text-align: left;
    width: 70%;
}

.Todo ul {
    margin: 20px 0px;
    padding: 0;
    list-style: none;
}

.Todo ul li {
    background-color: #fff;
    border: 1px solid #ddd;
    display: flex;
    justify-content: space-between;
    margin-bottom: -1px;
    padding: 10px 15px;
    position: relative;
}

.Todo form input {
    background-color: #fff;
    border-radius: 4px;
    border: 1px solid #ccc;
    box-shadow: inset 0 1px 1px rgba(0,0,0,.075);
    color: #555;
    font-size: 14px;
    height: 34px;
    line-height: 34px;
    padding: 6px 12px;
    width: 40%;
}

.Todo form button {
    background: #2ba6cb;
    border: 1px solid #1e728c;
    box-shadow: 0 1px 0 rgba(255, 255, 255, 0.5) inset;
    color: white;
    cursor: pointer;
    display: block;
    font-size: 14px;
    font-weight: bold;
    line-height: 1;
    margin: 20px auto;
    padding: 10px 20px 11px;
    position: relative;
    text-align: center;
    text-decoration: none;
}
```

文件：src/components/Todo/Todo.css

1.  我们的待办事项列表将如下截图所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/c5026115-303f-4909-a8bc-410f3a67552b.png)

# 它是如何工作的…

正如您所看到的，从输入表单中检索值的唯一方法是使用本地状态和`onChange`函数来更新输入的值。如果您将状态连接到输入值，但没有添加`onChange`回调来更新它，您将无法写入任何内容，因为虚拟 DOM 没有被更新，唯一的方法是通过更新我们的本地状态。

# 使用 Redux Form 构建表单

**Redux Form**通常用于大型表单或步骤表单，因为它具有 Redux 状态来保持整个表单的值。此外，Redux Form 很方便地验证数据并有效地处理提交。

# 准备工作

对于这个示例，我们需要安装 Redux Form 如下：

```jsx
 npm install redux-form
```

# 如何做到...

对于这个示例，我们将使用 Redux Form 来创建相同的 Todo 列表：

1.  安装了 Redux Form 之后，我们需要对上一个示例的代码进行一些修改以实现 Redux Form。我们需要做的第一件事是为我们的表单添加一个 reducer。为此，我们需要从`redux-form`中导入一个 reducer，并且我们可以将变量的名称更改为`formReducer`以更明确，然后将 reducer 作为一个表单添加到我们的`combineReducers`中，如下面的代码所示：

```jsx
// Dependencies
import { combineReducers } from 'redux';
import { reducer as formReducer } from 'redux-form';

// Components Reducers
import coins from '../../reducers/coinsReducer';

// Shared Reducers
import device from './deviceReducer';

const rootReducer = combineReducers({
  coins,
  device,
  form: formReducer
});

export default rootReducer;
```

文件：src/shared/reducers/index.js

1.  通常，我们使用 Redux Form 创建的所有表单都需要它们的组件，这意味着我们需要创建一个组件来处理我们的 Todo 表单。由于我们需要在`Todo`文件夹中创建一个名为`TodoForm.jsx`的文件，我们组件的代码如下：

```jsx
import React, { Component } from 'react';
import { Field, reduxForm } from 'redux-form';

class TodoForm extends Component {
  // Functional component to render an input...
  renderInput = ({ input }) => <input {...input} type="text" />;

 // This function is useful to handle our 
  onSubmit = values => {
    const { addTask, dispatch, reset } = this.props;

    // Resetting our form, this will clear our input...
    dispatch(reset('todo'));  

    // Executing our addTask method and
    // passing the form values.
    addTask(values);
  }

  render() {
    // handleSubmit is part of Redux Form 
    // to handle the onSubmit event
    const { handleSubmit } = this.props;

    return (
      <form onSubmit={handleSubmit(this.onSubmit)}>
        {/* Field is a Redux Form Component, we need to pass the 
         name of the input and the component we are using to 
         render it */}
        <Field 
          name="task" 
          component={this.renderInput} 
        />
      </form>
    )
  }
}

// With this we named our form reducer for this specific form (todo).  
export default reduxForm({
  form: 'todo'
})(TodoForm);
```

文件：src/components/Todo/TodoForm.jsx

1.  Redux Form 包含许多有用的 props 来处理我们表单中的数据。我标记了我们将在此示例中使用的 props（`addTask`是从另一个组件传递的 prop，因此它不是 Redux Form 的一部分），您可以通过在渲染方法中添加控制台来查看所有的 props `console.log(this.props);`，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/bb4aaf76-a242-46fc-8fab-9ada82003a37.png)

1.  现在让我们修改我们的`Todo`组件，包括`TodoForm`组件，并通过我们的`addTask`方法接收数据，如下面的代码所示：

```jsx
import React, { Component } from 'react';
import uuidv4 from 'uuid/v4';
import List from './List';
import TodoForm from './TodoForm';
import './Todo.css';
class Todo extends Component {
  constructor() {
    super();

    // Initial state...
    this.state = {
      items: []
    };
  }

  addTask = values => {
    // This values are coming from our 
    // onSubmit method in our TodoForm.
    const { task } = values;

    this.setState({
      items: [
        ...this.state.items,
        {
          id: uuidv4(),
          task,
          complete: false
        }
      ]
    });
  }

  render() {
    return (
      <div className="Todo">
        <h1>New Task:</h1>

        <TodoForm addTask={this.addTask} />
        <List items={this.state.items} />
      </div>
    );
  }
}
export default Todo;
```

# 它是如何工作的...

如您所见，Redux Form 很容易实现：

1.  在第一步中，我们将 Redux Form reducer 连接到了我们的 store

1.  在第二步中，我们创建了`TodoForm`组件，在这里我们渲染了表单字段，将表单 reducer 连接到 store，并将值发送回`addTask`回调函数

1.  在最后一步中，我们呈现了我们的`TodoForm`并发送了`addTask`回调，该回调处理任务值并将其插入到本地状态中

最后，我们将看到与上一个示例相同的结果，但现在我们使用 Redux Form，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/907eed37-f3bc-4e2f-af75-1d527358a1f1.png)

# 在表单中实现验证

我们 Redux Form 实现的最后部分是验证。使用上一个示例，让我们添加对输入任务的验证。

# 如何做...

在任何表单中都需要验证，因此让我们为我们的字段添加一些验证：

1.  首先，我们需要修改我们的`TodoForm.jsx`，并且我们需要创建一个`validate`函数，在这个函数中，我们需要验证我们的任务是否不为空。然后，我们需要创建一个`renderError`方法，以便在尝试添加空任务时呈现我们的错误消息，如下面的代码所示：

```jsx
import React, { Component } from 'react';
import { Field, reduxForm } from 'redux-form';
import './TodoForm.css';

class TodoForm extends Component {
  renderInput = ({ input }) => <input {...input} type="text" />;

  onSubmit = values => {
    const { addTask, dispatch, reset } = this.props;

    // Resetting our form...
    dispatch(reset('todo'));

    addTask(values);
  }

  renderError(field) {
    const { meta: { submitFailed, error } } = field;

    if (submitFailed && error) {
      return (
        <div className="error">
          {error}
        </div>
      );
    }

    return null;
  }

  render() {
    const { handleSubmit, submitting } = this.props;

    return (
      <form onSubmit={handleSubmit(this.onSubmit)}>
        <Field name="task" component={this.renderInput} />
        <Field name="task" component={this.renderError} />
      </form>
    );
  }
}

const validate = values => {
  const errors = {};

  if (!values.task) {
    errors.task = 'Task cannot be empty!';
  }

  return errors;
}

export default reduxForm({
  validate,
  form: 'todo'
})(TodoForm);
```

文件：src/components/Todo/TodoForm.jsx

1.  接下来，我们需要创建一个`TodoForm.css`来为我们的错误消息添加一些样式，如下面的代码所示：

```jsx
.error {
  color: red;
  font-size: small;
  margin-top: 10px;
}
```

文件：src/components/Todo/TodoForm.css

# 它是如何工作的...

如果我们尝试添加一个没有任何值的新任务，并按*Enter*提交表单，我们将看到以下屏幕截图中显示的视图：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/09f9546b-3bcc-4ad2-9268-61b2dd935c15.png)
