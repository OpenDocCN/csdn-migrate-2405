# React 秘籍（六）

> 原文：[`zh.annas-archive.org/md5/AADE5F3EA1B3765C530CB4A24FAA7E7E`](https://zh.annas-archive.org/md5/AADE5F3EA1B3765C530CB4A24FAA7E7E)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十一章：实现服务器端渲染

在本章中，将涵盖以下示例：

+   实现服务器端渲染

+   使用服务器端渲染实现承诺

+   实现 Next.js

# 介绍

React 通常使用客户端渲染（CSR）。这意味着它动态地将 HTML 代码注入到目标`div`中（通常使用`#app`或`#root` ID），这就是为什么如果您尝试直接查看页面的代码（右键单击-查看页面代码），您将看到类似于这样的内容：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/76039f9f-fe36-408f-a130-57f991ed7205.png)

查看实际代码的唯一方法是使用 Chrome Dev 工具或其他工具检查网站，以下是 React 使用 CSR 生成的代码：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/34b17d83-a4c8-4d2e-914c-5a2402c18df3.png)

通过检查页面，您可以看到注入到我们的`#root` div 中的代码。*服务器端渲染（SSR）*对于改善我们网站的*SEO*并被主要搜索引擎（如*Google*、*Yahoo*和*Bing*）索引非常有用。如果您不太关心 SEO，可能不需要担心*SSR*。目前，*Googlebot*支持*CSR*，并且可以在*Google*上索引我们的网站，但如果您关心 SEO 并且担心改善其他搜索引擎（如*Yahoo*、*Bing*或*DuckDuckGo*）上的 SEO，则使用*SSR*是正确的选择。

# 实现服务器端渲染

在这个示例中，我们将在我们的项目中实现 SSR。

# 准备工作

我们将使用上一篇示例（*使用 Node.js 与 React/Redux 和 Webpack 4 实现*）中的代码，从第十章*，掌握 Webpack 4.x*，并安装一些其他依赖项：

```jsx
npm install --save-dev webpack-node-externals webpack-dev-middleware webpack-hot-middleware webpack-hot-server-middleware webpack-merge babel-cli babel-preset-es2015
```

# 如何做...

现在让我们来看一下渲染的步骤：

1.  首先，我们需要将 npm 脚本添加到我们的`package.json`文件中：

```jsx
    "scripts": {
      "clean": "rm -rf dist/ && rm -rf public/app",
      "start": "npm run clean & NODE_ENV=development 
 BABEL_ENV=development 
 nodemon src/server --watch src/server --watch src/shared -- 
      exec babel-node --presets es2015",
      "start-analyzer": "npm run clean && NODE_ENV=development 
 BABEL_ENV=development ANALYZER=true babel-node src/server"
    }
```

文件：package.json

1.  现在我们需要更改我们的`webpack.config.js`文件。因为我们要实现 SSR，我们需要将我们的 Webpack 配置分成客户端配置和服务器配置，并将它们作为数组返回。文件应该看起来像这样：

```jsx
  // Webpack Configuration (Client & Server)
  import clientConfig from './webpack/webpack.config.client';
  import serverConfig from './webpack/webpack.config.server';

 export default [
    clientConfig,
    serverConfig
  ];
```

文件：webpack.config.js

1.  现在我们需要在我们的`webpack`文件夹内为我们的客户端配置创建一个文件。我们需要将其命名为`webpack.config.client.js`：

```jsx
  // Dependencies
  import webpackMerge from 'webpack-merge';

  // Webpack Configuration
  import commonConfig from './webpack.config.common';
  import {
    context,
    devtool,
    entry,
    name,
    output,
    optimization,
    plugins,
    target
  } from './configuration';

  // Type of Configuration
  const type = 'client';

  export default webpackMerge(commonConfig(type), {
    context: context(type),
    devtool,
    entry: entry(type),
    name: name(type),
    output: output(type),
    optimization,
    plugins: plugins(type),
    target: target(type)
  });
```

文件：webpack/webpack.config.client.js

1.  现在服务器配置应该是这样的：

```jsx
 // Dependencies
  import webpackMerge from 'webpack-merge';

  // Webpack Configuration
  import commonConfig from './webpack.config.common';

  // Configuration
  import {
    context,
    entry,
    externals,
    name,
    output,
    plugins,
    target
  } from './configuration';

  // Type of Configuration
  const type = 'server';

 export default webpackMerge(commonConfig(type), {
    context: context(type),
    entry: entry(type),
    externals: externals(type),
    name: name(type),
    output: output(type),
    plugins: plugins(type),
    target: target(type)
  });
```

文件：webpack/webpack.config.server.js

1.  正如您所看到的，在这两个文件中，我们正在导入一个包含需要添加到客户端和服务器端的配置的共同配置文件：

```jsx
  // Configuration
  import { module, resolve, mode } from './configuration';
  export default type => ({
    module: module(type),
    resolve,
    mode
  });
```

文件：webpack/webpack.config.common.js

1.  我们需要为 Webpack 节点添加新的配置文件，并修改一些我们已经有的文件。我们需要创建的第一个文件是`context.js`。在这个文件（和其他一些文件）中，我们将导出一个带有类型参数的函数，该参数可以是*client*或*server*，并根据该值返回不同的配置：

```jsx
  // Dependencies
  import path from 'path';
 export default type => type === 'server'
    ? path.resolve(__dirname, '../../src/server')
    : path.resolve(__dirname, '../../src/client');
```

文件：webpack/configuration/context.js

1.  入口文件是我们将添加到捆绑包中的所有文件的位置。我们的入口文件现在应该是这样的：

```jsx
  // Environment
  const isDevelopment = process.env.NODE_ENV !== 'production';

 export default type => {
    if (type === 'server') {
      return './render/serverRender.js';
    }

    const entry = [];

    if (isDevelopment) {
      entry.push(
        'webpack-hot-middleware/client',
        'react-hot-loader/patch'
      );
    }

    entry.push('./index.jsx');

    return entry;
  };
```

文件：webpack/configuration/entry.js

1.  我们需要创建一个名为 externals.js 的文件，其中包含我们不打包的模块（除非它们在白名单上）：

```jsx
  // Dependencies
  import nodeExternals from 'webpack-node-externals';

  export default () => [
    nodeExternals({
      whitelist: [/^redux\/(store|modules)/]
    })
  ];
```

文件：webpack/configuration/externals.js

1.  此外，我们需要修改我们的`module.js`文件，根据环境或配置类型返回我们的规则：

```jsx
  // Dependencies
  import ExtractTextPlugin from 'extract-text-webpack-plugin';

 // Environment
  const isDevelopment = process.env.NODE_ENV !== 'production';

  export default type => {
    const rules = [
      {
        test: /\.(js|jsx)$/,
        use: 'babel-loader',
        exclude: /node_modules/
      }
    ];

    if (!isDevelopment || type === 'server') {
      rules.push({
        test: /\.scss$/,
        use: ExtractTextPlugin.extract({
          fallback: 'style-loader',
          use: [
            'css-loader?minimize=true&modules=true&localIdentName=
            [name]__[local]_[hash:base64]',
            'sass-loader'
          ]
        })
      });
    } else {
      rules.push({
        test: /\.scss$/,
        use: [
          {
            loader: 'style-loader'
          },
          {
            loader: 'css-loader',
            options: {
              modules: true,
              importLoaders: 1,
              localIdentName: '[name]__[local]_[hash:base64]',
              sourceMap: true,
              minimize: true
            }
          },
          {
            loader: 'sass-loader'
          }
        ]
      });
    }

    return {
      rules
    };
  };
```

文件：webpack/configuration/module.js

1.  现在我们需要为名称创建一个节点：

```jsx
  export default type => type;
```

文件：webpack/configuration/name.js

1.  对于输出配置，我们需要根据配置的类型（客户端或服务器端）返回一个对象：

```jsx
  // Dependencies
  import path from 'path';

 export default type => {
    if (type === 'server') {
      return {
        filename: 'server.js',
        path: path.resolve(__dirname, '../../dist'),
        libraryTarget: 'commonjs2'
      };
    }

    return {
      filename: '[name].bundle.js',
      path: path.resolve(__dirname, '../../public/app'),
      publicPath: '/'
    };
  };
```

文件：webpack/configuration/output.js

1.  在我们的`plugins.js`文件中，我们正在验证用户是否发送了`ANALYZER`变量，以便在开发模式下运行应用程序时仅在该情况下显示`BundleAnalyzerPlugin`，而不是每次都显示。

```jsx
  // Dependencies
  import CompressionPlugin from 'compression-webpack-plugin';
  import ExtractTextPlugin from 'extract-text-webpack-plugin';
  import webpack from 'webpack';
  import WebpackNotifierPlugin from 'webpack-notifier';
  import { BundleAnalyzerPlugin } from 'webpack-bundle-analyzer';

 // Environment
  const isDevelopment = process.env.NODE_ENV !== 'production';

  // Analyzer
  const isAnalyzer = process.env.ANALYZER === 'true';

 export default type => {
    const plugins = [
      new ExtractTextPlugin({
        filename: '../../public/css/style.css'
      })
    ];

    if (isAnalyzer) {
      plugins.push(
        new BundleAnalyzerPlugin()
      );
    }

    if (isDevelopment) {
      plugins.push(
        new webpack.HotModuleReplacementPlugin(),
        new webpack.NoEmitOnErrorsPlugin(),
        new WebpackNotifierPlugin({
          title: 'CodeJobs'
        })
      );
    } else {
      plugins.push(
        new CompressionPlugin({
          asset: '[path].gz[query]',
          algorithm: 'gzip',
          test: /\.js$|\.css$|\.html$/,
          threshold: 10240,
          minRatio: 0.8
        })
      );
    }

    return plugins;
  };
```

文件：webpack/configuration/plugins.js

1.  我们需要在我们的解析文件中指定我们的模块；文件应该是这样的：

```jsx
  // Dependencies
  import path from 'path';

  export default {
    extensions: ['.js', '.jsx'],
    modules: [
      'node_modules',
      path.resolve(__dirname, '../../src/client'),
      path.resolve(__dirname, '../../src/server')
    ]
  };
```

文件：webpack/configuration/resolve.js

1.  我们需要创建的最后一个配置是`target.js`文件：

```jsx
 export default type => type === 'server' ? 'node' : 'web';
```

文件：webpack/configuration/target.js

1.  在我们配置了 Webpack 之后，我们需要修改我们的`App.jsx`文件，其中我们需要使用`<BrowserRouter>`组件为客户端创建路由，并使用`<StaticRouter>`为服务器端创建路由：

```jsx
  // Dependencies
  import React from 'react';
  import { 
    BrowserRouter, 
    StaticRouter, 
    Switch, 
    Route 
  } from 'react-router-dom';

 // Components
  import About from '@components/About';
  import Home from '@components/Home';

  export default ({ server, location, context = {} }) => {
    const routes = (
      <Switch>
        <Route exact path="/" component={Home} />
        <Route exact path="/about" component={About} />
      </Switch>
    );

    // Client Router
    let router = (
      <BrowserRouter>
        {routes}
      </BrowserRouter>
    );

    // Server Router
    if (server) {
      router = (
        <StaticRouter location={location} context={context}>
          {routes}
        </StaticRouter>
      );
    }

    return router;
  };
```

文件：src/client/App.jsx

1.  现在我们需要修改我们的服务器文件（`index.js`）以使用我们的*clientRender*和*serverRender*中间件：

```jsx
  // Dependencies
  import express from 'express';
  import path from 'path';
  import webpackDevMiddleware from 'webpack-dev-middleware';
  import webpackHotMiddleware from 'webpack-hot-middleware';
  import webpackHotServerMiddleware from 'webpack-hot-server-middleware';
  import webpack from 'webpack';

  // Utils
  import { isMobile, isBot } from '@utils/device';

  // Client Render
  import clientRender from './render/clientRender';

  // Webpack Configuration
  import webpackConfig from '@webpack';

  // Environment
  const isProduction = process.env.NODE_ENV === 'production';

  // Express Application
  const app = express();

  // Webpack Compiler
  const compiler = webpack(webpackConfig);

  // Public directory
  app.use(express.static(path.join(__dirname, '../../public')));

  // Device Detection
  app.use((req, res, next) => {
    req.isMobile = isMobile(req.headers['user-agent']);
    // We detect if a search bot is accessing...
    req.isBot = isBot(req.headers['user-agent']);

    next();
  });

  // Webpack Middleware
  if (!isProduction) {
    // Hot Module Replacement
    app.use(webpackDevMiddleware(compiler));
    app.use(webpackHotMiddleware(
      compiler.compilers.find(compiler => compiler.name === 'client'))
    );
  } else {
    // GZip Compression just for Production
    app.get('*.js', (req, res, next) => {
      req.url = `${req.url}.gz`;
      res.set('Content-Encoding', 'gzip');
      next();
    });
  }

  // Client Side Rendering
  app.use(clientRender());

  if (isProduction) {
    try {
      // eslint-disable-next-line
      const serverRender = require('../../dist/server.js').default; 

      app.use(serverRender());
    } catch (e) {
      throw e;
    }
  }

  // For Server Side Rendering on Development Mode
  app.use(webpackHotServerMiddleware(compiler));

 // Disabling x-powered-by
  app.disable('x-powered-by');

  // Listen Port...
  app.listen(3000);
```

文件：src/server/index.js

1.  我们需要修改我们的`clientRender.js`文件。如果我们检测到一个搜索引擎爬虫使用`isBot`函数，我们将返回`next()`中间件。否则，我们渲染 HTML 并使用 CSR 执行应用程序：

```jsx
  // HTML
  import html from './html';

  // Initial State
  import initialState from './initialState';

  export default function clientRender() {
    return (req, res, next) => {
      if (req.isBot) {
        return next();
      }

      res.send(html({
        title: 'Codejobs',
        initialState: initialState(req)
      }));
    };
  }
```

文件：src/server/render/clientRender.js

1.  现在让我们创建我们的`serverRender.js`文件。在这里，我们需要使用`react-dom/server`库中的`renderToString`方法来渲染我们的`App`组件：

```jsx
  // Dependencies
  import React from 'react';
  import { renderToString } from 'react-dom/server';
  import { Provider } from 'react-redux';

  // Redux Store
  import configureStore from '@configureStore';

  // Components
  import App from '../../client/App';

  import html from './html';

  // Initial State
  import initialState from './initialState';

  export default function serverRender() {
    return (req, res, next) => {
      // Configuring Redux Store
      const store = configureStore(initialState(req));

      const markup = renderToString(
        <Provider store={store}>
          <App
            server
            location={req.url}
          />
        </Provider>
      );

      res.send(html({
        title: 'Codejobs',
        markup,
        initialState: initialState(req)
      }));
    };
  }
```

文件：src/server/render/serverRender.js

# 它是如何工作的...

您可以通过运行`npm start`命令启动应用程序。

如果您在浏览器（例如 Chrome）中打开`http://localhost:3000`中的应用程序，然后右键单击，然后查看页面源代码，您可能会注意到我们没有使用 SSR：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/35cb0370-fc71-4da4-9af0-a7f60c764cea.png)

这是因为我们将仅将 SSR 用于搜索引擎爬虫。*isBot*函数将检测所有搜索引擎爬虫，仅供测试，我添加了*curl*作为一个爬虫来测试我们的 SSR；这是该函数的代码：

```jsx
  export function isBot(ua) {
    const b = /curl|bot|googlebot|google|baidu|bing|msn|duckduckgo|teoma|slurp|yandex|crawler|spider|robot|crawling/i;
    return b.test(ua);
  }
```

文件：src/shared/utils/device.js

在另一个终端中打开一个新的终端，然后执行以下命令：

```jsx
    curl http://localhost:3000
```

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/41cfa504-72bc-456f-a9e3-bdcb9c524d4f.png)

如您所见，#root div 内的 HTML 代码是使用 SSR 渲染的。

另外，如果您想尝试在 curl 中运行`/about`，您将看到它也将使用 SSR 进行渲染：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/29b3774a-7a5b-4b0a-9e15-d34da262b8c7.png)

Chrome 有一个名为 User-Agent Switcher for Chrome 的扩展，您可以在其中指定要在浏览器中使用的用户代理。通过这种方式，您可以为 Googlebot 添加一个特殊的用户代理，例如：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/cce1b59f-6f77-4908-aecc-59ad8cc815fe.png)

然后，如果您在 User-Agent Switcher 中选择 Chrome | Bot，您会发现当您查看页面源代码时，HTML 代码会将其呈现为 SSR：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/0fa6e9d4-7f9e-4d11-b32e-df15a3694b29.png)

# 还有更多...

当我们使用 SSR 时，当我们尝试在客户端使用 window 对象时，我们必须非常小心。如果您直接使用 SSR，您将收到 ReferenceError，例如：

```jsx
    ReferenceError: window is not defined
```

为了解决这个问题，您可以验证 window 对象是否存在，但这可能非常重复。我更喜欢创建一个可以验证我们是使用浏览器（客户端）还是服务器的函数。您可以这样做：

```jsx
    export function isBrowser() {
      return typeof window !== 'undefined';
    }
```

然后，每次您需要使用 window 对象时，可以这样做：

```jsx
 const store = isBrowser() ? configureStore(window.initialState) : {};
```

# 使用服务器端渲染实现承诺

在上一个示例中，我们看到了 SSR 的工作原理，但该示例仅限于显示具有简单组件的 SSR。在本示例中，我们将学习如何实现承诺以将我们的组件连接到 Redux，使用 API 获取数据并使用 SSR 渲染组件。

# 准备就绪

我们将使用上一个步骤中的相同代码，但我们将进行一些更改。在这个步骤中，我们需要安装这些软件包：

```jsx
    npm install axios babel-preset-stage-0 react-router-dom redux-devtools-extension redux-thunk
```

# 如何做...

对于这个步骤，我们将实现一个基本的待办事项列表，从 API 中拉取数据，以展示如何使用 SSR 将 Redux 连接到我们的应用程序中：

1.  我们需要做的第一件事是添加一个简单的 API 来显示待办事项列表：

```jsx
  import express from 'express';

  const router = express.Router();

  // Mock data, this should come from a database....
  const todo = [
    {
      id: 1,
      title: 'Go to the Gym'
    },
    {
      id: 2,
      title: 'Dentist Appointment'
    },
    {
      id: 3,
      title: 'Finish homework'
    }
  ];

  router.get('/todo/list', (req, res, next) => {
    res.json({
      response: todo
    });
  });

  export default router;
```

文件：src/server/controllers/api.js

1.  第二步是将这个 API 控制器导入到我们的`src/server/index.js`文件中，并将其添加为`/api`路由的中间件：

```jsx
  ...
  // Controllers
  import apiController from './controllers/api';
  ...
  // Express Application
  const app = express();

  // Webpack Compiler
  const compiler = webpack(webpackConfig);

  // Routes
  app.use('/api', apiController);
  ...
```

文件：src/server/index.js

1.  以前，在我们的`serverRender.js`文件中，我们直接渲染了我们的`App`组件。现在我们需要从具有名为`initialAction`的静态方法的组件中获取承诺，将它们保存到一个承诺数组中，解决它们，然后渲染我们的`App`方法：

```jsx
  // Dependencies
  import React from 'react';
  import { renderToString } from 'react-dom/server';
  import { Provider } from 'react-redux';
  import { matchPath } from 'react-router-dom';

  // Redux Store
  import configureStore from '@configureStore';

  // Components
  import App from '../../client/App';

  // HTML
  import html from './html';

  // Initial State
  import initialState from './initialState';

  // Routes
  import routes from '@shared/routes';

  export default function serverRender() {
    return (req, res, next) => {
      // Configuring Redux Store
      const store = configureStore(initialState(req));

      // Getting the promises from the components which has  
      // initialAction.
      const promises = routes.paths.reduce((promises, route) => {
        if (matchPath(req.url, route) && route.component && route.component.initialAction) {          
promises.push(Promise.resolve(store.dispatch(route.component.initialAction())));
        }

        return promises;
      }, []);

      // Resolving our promises
      Promise.all(promises)
        .then(() => {
          // Getting Redux Initial State
          const initialState = store.getState();

          // Rendering with SSR
          const markup = renderToString(
            <Provider store={store}>
              <App
                server
                location={req.url}
              />
            </Provider>
          );

          // Sending our HTML code.
          res.send(html({
            title: 'Codejobs',
            markup,
            initialState
          }));
        })
        .catch(e => {
          // eslint-disable-line no-console
          console.log('Promise Error: ', e); 
        });
    };
  }
```

文件：src/server/render/serverRender.js

1.  在这个步骤中，我们需要在客户端目录中稍微改变我们的文件夹结构。以前，我们有一个`components`目录，我们的组件都在里面。现在我们要将我们的组件封装为小应用程序，在里面我们可以创建我们的操作、API、组件、容器和减速器。我们的新结构应该是这样的：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/e4c2cc9b-d2f6-42b6-b495-2d18c088157a.png)

1.  我们将创建一个待办事项应用程序。为此，首先我们需要添加我们的操作文件夹，在里面我们需要首先创建我们的`actionTypes.js`文件。在这个文件中，我们需要添加我们的`FETCH_TODO`操作。我更喜欢创建一个具有两个函数的对象，一个用于请求，另一个用于成功；当我们在减速器中使用它们并分发我们的操作时，你将看到这一点的优势：

```jsx
  // Actions
  export const FETCH_TODO = {
    request: () => 'FETCH_TODO_REQUEST',
    success: () => 'FETCH_TODO_SUCCESS'
  };
```

文件：src/client/todo/actions/actionTypes.js

1.  在我们的`index.js`文件中，我们将创建一个 fetchTodo 操作，从我们的 API 中检索我们的待办事项列表项：

```jsx
  // Base Actions
  import { request, received } from '@baseActions';

  // Api
  import api from '../api';

  // Action Types
  import { FETCH_TODO } from './actionTypes';

  export const fetchTodo = () => dispatch => {
    const action = FETCH_TODO;
    const { fetchTodo } = api;

    dispatch(request(action));

    return fetchTodo()
      .then(response => dispatch(received(action, response.data)));
  };
```

文件：src/client/todo/actions/index.js

1.  正如你所看到的，我们正在使用基本操作中的两种特定方法（请求和接收）。这些函数将帮助我们轻松地分发我们的操作（你还记得我们在操作中使用了请求和成功方法吗？）：

```jsx
  // Base Actions
  export const request = ACTION => ({
    type: ACTION.request()
  });

  export const received = (ACTION, data) => ({
    type: ACTION.success(),
    payload: data
  });
```

文件：src/shared/redux/baseActions.js

1.  现在让我们创建我们的`api`文件夹，在这里我们需要添加一个`constants.js`文件和我们的`index.js`文件：

```jsx
 export const API = Object.freeze({
    TODO: 'api/todo/list'
  });
```

文件：src/client/todo/api/constants.js

1.  在我们的`index.js`文件中，我们必须创建我们的 Api 类并添加一个名为`fetchTodo`的静态方法：

```jsx
  // Dependencies
  import axios from 'axios';

  // Configuration
  import config from '@configuration';

  // Utils
  import { isBrowser } from '@utils/frontend';

  // Constants
  import { API } from './constants';

  class Api {
    static fetchTodo() {
      // For Node (SSR) we have to specify our base domain  
      // (http://localhost:3000/api/todo/list)
 // For Client Side Render just /api/todo/list.
      const url = isBrowser()
        ? API.TODO
        : `${config.baseUrl}/${API.TODO}`;

      return axios(url);
    }
  }

 export default Api;
```

文件：src/client/todo/api/index.js

1.  在我们的 Todo 容器中，我们需要映射我们的待办事项列表，并将*fetchTodo*动作添加到 Redux 中。我们将导出一个布局组件，然后我们将添加我们的其他组件，并操纵我们想要显示布局的方式：

```jsx
  // Dependencies
  import { connect } from 'react-redux';
  import { bindActionCreators } from 'redux';

  // Components
  import Layout from '../components/Layout';

  // Actions
  import { fetchTodo } from '../actions';

  export default connect(({ todo }) => ({
    todo: todo.list
  }), dispatch => bindActionCreators(
    {
      fetchTodo
    },
    dispatch
  ))(Layout);
```

文件：src/client/todo/container/index.js

1.  我们的布局组件应该是这样的：

```jsx
  // Dependencies
  import React from 'react';

  // Shared Components
  import Header from '@layout/Header';
  import Content from '@layout/Content';
  import Footer from '@layout/Footer';

  // Componenets
  import Todo from '../components/Todo';

  const Layout = props => (
    <main>
      <Header {...props} />
      <Content>
        <Todo {...props} />
      </Content>
      <Footer {...props} />
    </main>
  );
  export default Layout;
```

文件：src/client/todo/components/Layout.jsx

1.  在这个教程中，我们不会看到布局组件（Header、Content 和 Footer），因为它们非常通用，我们在过去的教程中已经使用过它们。现在让我们创建我们的 reducer 文件：

```jsx
  // Utils
  import { getNewState } from '@utils/frontend';

  // Action Types
  import { FETCH_TODO } from '../actions/actionTypes';

  // Initial State
  const initialState = {
    list: []
  };
  export default function todoReducer(state = initialState, action) {
    switch (action.type) {
      case FETCH_TODO.success(): {
        const { payload: { response = [] } } = action;

        return getNewState(state, {
          list: response
        });
      }

      default:
        return state;
    }
  }
```

文件：src/client/todo/reducer/index.js

1.  我们的 Todo 组件将在 componentDidMount 方法中执行我们的 fetchTodo 动作，然后我们将待办事项列表呈现为 HTML 列表；非常简单：

```jsx
  // Dependencies
  import React, { Component } from 'react';

  // Utils
  import { isFirstRender } from '@utils/frontend';

  // Styles
  import styles from './Todo.scss';

  class Todo extends Component {
    componentDidMount() {
      const { fetchTodo } = this.props;

      fetchTodo();
    }

    render() {
      const {
        todo
      } = this.props;

      if (isFirstRender(todo)) {
        return null;
      }

      return (
        <div>
          <div className={styles.Todo}>
            <ol>
              {todo.map((item, key) => 
                <li key={key}>{item.title}</li>)}
            </ol>
          </div>
        </div>
      );
    }
  }

 export default Todo;
```

文件：src/client/todo/components/Todo.jsx

1.  最后，我们需要为我们的待办事项应用程序创建一个`index.jsx`文件，在这个文件中，我们将添加我们的 initialAction（这将返回一个承诺）来执行我们的 fetchTodo 动作，并使用 SSR 呈现这个待办事项列表：

```jsx
  // Dependencies
  import React from 'react';

  // Actions
  import { fetchTodo } from './actions';

  // Main Container
  import Container from './container';

 // Main Component
  const Main = props => <Container {...props} />;

  // Initial Action
  Main.initialAction = () => fetchTodo();

 export default Main;
```

文件：src/client/todo/index.jsx

# 它是如何工作的...

正如您在我们的`serverRender.js`文件中所看到的，我们获取承诺并解决它们，然后我们使用 SSR 渲染我们的应用程序。

如果您想测试该应用程序，您需要在浏览器中转到 http://localhost:3000/todo。

请记住，在我们的应用程序中，我们只是为搜索引擎爬虫和 curl 使用 SSR，否则将使用 CSR。这是因为我们必须使用 SSR 的唯一原因是为了改善我们在 Google、Yahoo 和 Bing 中的 SEO。

如果我们使用 CSR，我们将在 Todo 组件的`componentDidMount()`方法中执行我们的动作；如果我们使用 SSR，我们将使用`initialAction`方法，该方法返回一个将在`serverRender.js`中解决的承诺。

如果您打开页面，您应该会看到这个：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/7487add2-4819-4a66-9a88-9b7742f03046.png)

如果您想查看 SSR 是否正常工作，可以使用`curl`命令并在终端中执行相同的 URL：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/3f0d3e9b-3983-4b55-ad35-2a09ae9f9c5a.png)

正如您所看到的，待办事项列表 reducer 已添加到`initialState`中，从那里，我们可以使用 SSR 渲染列表。

# 实施 Next.js

Next.js 是一个用于服务器渲染的 React 应用程序的极简框架。

在这个教程中，我们将学习如何使用 Sass 实现 Next.js，并且我们还将使用 axios 从服务中获取数据。

# 准备工作

首先，让我们创建一个名为`nextjs`的新目录，初始化`package.json`，最后在其中创建一个新目录：

```jsx
 mkdir nextjs
 cd nextjs
 npm init -y
 mkdir src
```

然后我们需要安装一些依赖项：

```jsx
 npm install next react react-dom axios node-sass @zeit/next-sass
```

# 如何做...

现在我们已经安装了依赖项，让我们创建我们的第一个 Next.js 应用程序：

1.  我们需要做的第一件事是在我们的 package.json 中创建一些脚本。在每个脚本中，我们需要指定`src`目录。否则，它将尝试从根目录而不是`src`路径启动 Next：

```jsx
  "scripts": {
    "start": "next start src",
    "dev": "next src",
    "build": "next build src"
  }
```

文件：package.json

1.  Next 中的主目录称为`pages`。这是我们将使用 Next 渲染的所有`pages`的位置：

```jsx
 cd src && mkdir pages
```

1.  我们需要创建的第一个页面是`index.jsx`：

```jsx
 const Index = () => <h1>Home</h1>;

  export default Index;
```

文件：src/pages/index.jsx

1.  现在让我们使用 dev 脚本运行我们的应用程序：

```jsx
 npm run dev
```

1.  如果一切正常，您应该在终端中看到这个：

！[](assets/f75b2344-5ab1-4d52-af63-01d928622c7d.png)

1.  打开`http://localhost:3000`：

！[](assets/d996d9a6-c555-4412-9451-dce13b0b2d21.png)

Next.js 有自己的 Webpack 配置和热重载功能。这意味着如果您编辑 index.js 文件，您将看到反映这些更改而无需刷新页面。

1.  现在让我们创建一个关于页面，看看路由是如何工作的：

```jsx
 const About = () => <h1>About</h1>;

  export default About;
```

文件：src/pages/about.jsx

1.  现在，如果您转到 http://localhost:3000/about，您将看到关于页面。正如您所看到的，Next.js 会自动为我们创建的每个页面创建一个新路由。这意味着我们不需要安装 React Router 来处理路由。

在 Next 页面中，不需要导入 React，因为 Next 也会自动处理它。

1.  现在我们需要创建一个`next.config.js`文件，并导入 withSass 方法来在我们的项目中使用 Sass。不幸的是，这个文件需要用 ES5 语法编写，因为目前不支持使用 ES6 的 babel 扩展（[`github.com/zeit/next.js/issues/2916`](https://github.com/zeit/next.js/issues/2916)）：

```jsx
 const withSass = require('@zeit/next-sass');

  module.exports = withSass();
```

文件：src/next.config.js 在这个文件中，如果需要，我们还可以添加自定义的 Webpack 配置。

1.  然后我们需要在`pages`目录中创建一个特殊的文件叫做`_document.js`。这个文件会被 Next.js 自动处理，我们可以在这里定义文档的头部和正文：

```jsx
  import Document, { Head, Main, NextScript } from 'next/document';

  export default class MyDocument extends Document {
    render() {
      return (
        <html>
          <Head>
            <title>Codejobs with Next</title>
            <link 
 rel="stylesheet" 
 href="/_next/static/style.css" />
          </Head>

          <body>
            <Main />
            <NextScript />
          </body>
        </html>
      );
    }
  }
```

文件：src/pages/_document.jsCSS 文件的路径（`/_next/static/style.css`）是默认的；我们应该使用它来在我们的项目中使用样式。

1.  现在我们可以创建一些组件来包装我们的页面。我们需要创建的第一个是菜单选项的导航栏：

```jsx
  import Link from 'next/link';
  import './Navbar.scss';

  const Navbar = () => (
    <div className="navbar">
      <ul>
        <li>Codejobs</li>
        <li><Link href="/">Home</Link></li>
        <li><Link href="/about">About</Link></li>
      </ul>
    </div>
  )
 export default Navbar;
```

文件：src/components/Navbar.jsx Link 组件与 React Router Link 不同。有一些区别；例如，React Router Link 使用“to”prop，而 Next Link 使用“href”来指定 URL。

1.  现在我们可以为我们的`navbar`添加 Sass 样式：

```jsx
 .navbar {
    background: black;
    color: white;
    height: 60px;

    ul {
      padding: 0;
      margin: 0;
      list-style: none;

      li {
        display: inline-block;
        margin-left: 30px;
        text-align: center;

        a {
          display: block;
          color: white;
          line-height: 60px;
          width: 150px;

          &:hover {
            background: white;
            color: black;
          }
        }
      }
    }
  }
```

文件：src/components/Navbar.scss

1.  然后我们需要创建我们的 Layout 组件：

```jsx
  import Navbar from './Navbar';
  import './Layout.scss';

  const Layout = ({ children }) => (
    <div className="layout">
      <Navbar />

      <div className="wrapper">
        {children}
      </div>
    </div>
  )

  export default Layout;
```

文件：src/components/Layout.jsx

1.  我们的 Layout 的样式如下：

```jsx
  body {
    font-family: verdana;
    padding: 0;
    margin: 0;
  }

  .layout {
    a {
      text-decoration: none;
    }

    .wrapper {
      margin: 0 auto;
      width: 96%;
    }
  }
```

文件：src/components/Layout.scss

1.  你还记得第五章中的配方，*精通 Redux*，关于从 CoinMarketCap 列出前 100 个加密货币（`Repository: Chapter05/Recipe2/coinmarketcap`）吗？在这个配方中，我们将使用 Next.js 做同样的事情。我们需要做的第一件事是修改页面的`index.js`文件，并在`getInitialProps`方法中进行异步`axios`请求：

```jsx
  import axios from 'axios';
  import Layout from '../components/Layout';
  import Coins from '../components/Coins';

  const Index = ({ coins }) => (
    <Layout>
      <div className="index">
        <Coins coins={coins} />
      </div>
    </Layout>
  );

  Index.getInitialProps = async () => {
    const url = 'https://api.coinmarketcap.com/v1/ticker/';
    const res = await axios.get(url);

    return {
      coins: res.data
    };
  };

 export default Index;
```

文件：src/pages/index.js

1.  现在让我们创建`Coins`组件：

```jsx
  // Dependencies
  import React, { Component } from 'react';
  import { array } from 'prop-types';

  // Styles
  import './Coins.scss';

  const Coins = ({ coins }) => (
    <div className="Coins">
      <h1>Top 100 Coins</h1>

      <ul>
        {coins.map((coin, key) => (
          <li key={key}>
            <span className="left">{coin.rank} {coin.name} <strong>
            {coin.symbol}</strong></span>
            <span className="right">${coin.price_usd}</span>
          </li>
        ))}
      </ul>
    </div>
  );

  Coins.propTypes = {
    coins: array
  };

 export default Coins;
```

文件：src/components/Coins.jsx

1.  `Coins`组件的样式如下：

```jsx
 .Coins {
    h1 {
      text-align: center;
    }

    ul {
      margin: 0 auto;
      margin-bottom: 20px;
      padding: 0;
      list-style: none;
      width: 400px;

      li {
        border-bottom: 1px solid black;
        text-align: left;
        padding: 10px;
        display: flex;
        justify-content: space-between;

        a {
          display: block;
          color: #333;
          text-decoration: none;
          background: #5ed4ff;

          &:hover {
            color: #333;
            text-decoration: none;
            background: #baecff;
          }
        }
      }
    }
  }
```

文件：src/components/Coins.scss

# 它是如何工作的...

现在我们已经创建了所有页面和组件，让我们通过运行`npm run dev`来测试我们的 Next 应用程序：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/3fce3ceb-4c6d-44df-acdc-dcd320c4437f.png)

现在让我们看看它在 HTML 视图中是如何渲染的：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/34746655-239c-4230-8419-333d76ce7bd2.png)

万岁！HTML 以 SSR 方式呈现，非常适合改善 SEO。正如你所看到的，使用 Next 创建应用程序非常快速，而且在启用 SSR 时避免了大量的配置。


# 第十二章：测试和调试

在本章中，将涵盖以下教程：

+   使用 Jest 和 Enzyme 测试我们的第一个组件

+   测试 Redux 容器、操作和减速器

+   使用 React 和 Redux Dev Tools 调试 React 应用程序

+   模拟事件

# 介绍

测试和调试对于任何希望具有高质量的项目来说都非常重要。不幸的是，许多开发人员不关心测试（单元测试），因为他们认为这会减慢开发速度，有些人把它留到项目结束时再做。根据我的个人经验，我可以说，从项目开始就进行测试会节省您的时间，因为最后您将有更少的错误需要修复。React 使用 Jest 来测试其组件、容器、操作和减速器。

在接下来的教程中，我们还将学习如何调试我们的 React/Redux 应用程序。

# 使用 Jest 和 Enzyme 测试我们的第一个组件

在这个教程中，我们将学习如何在项目中安装和配置 Jest。

# 准备工作

在这个教程中，我们需要安装一些包来测试我们的 React 应用程序：

```jsx
npm install --save-dev jest jsdom enzyme enzyme-adapter-react-16 identity-obj-proxy
```

# 如何做…

安装了 Jest 之后，我们需要对其进行配置：

1.  将`tests`脚本和 Jest 配置添加到我们的`package.json`中：

```jsx
  {
    "name": "react-pro",
    "version": "1.0.0",
    "scripts": {
      "clean": "rm -rf dist/ && rm -rf public/app",
      "start": "npm run clean & NODE_ENV=development 
      BABEL_ENV=development nodemon src/server --watch src/server --
      watch src/shared --exec babel-node --presets es2015",
      "start-analyzer": "npm run clean && NODE_ENV=development 
      BABEL_ENV=development ANALYZER=true babel-node src/server",
      "test": "node scripts/test.js src --env=jsdom",
      "coverage": "node scripts/test.js src --coverage --env=jsdom"
    },
    "jest": {
      "setupTestFrameworkScriptFile": "
 <rootDir>/config/jest/setupTestFramework.js",
      "collectCoverageFrom": [
        "src/**/*.{js,jsx}"
      ],
      "setupFiles": [
        "<rootDir>/config/jest/browserMocks.js"
      ],
      "moduleNameMapper": {
        "^.+\\.(scss)$": "identity-obj-proxy"
      }
    },
    "author": "Carlos Santana",
    "license": "MIT",
    "dependencies": {
      "axios": "⁰.18.0",
      "babel-preset-stage-0": "⁶.24.1",
      "express": "⁴.15.4",
      "react": "¹⁶.3.2",
      "react-dom": "¹⁶.3.2",
      "react-redux": "⁵.0.6",
      "react-router-dom": "⁴.2.2",
      "redux": "⁴.0.0",
      "redux-devtools-extension": "².13.2",
      "redux-thunk": "².2.0"
    },
    "devDependencies": {
      "babel-cli": "⁶.26.0",
      "babel-core": "⁶.26.0",
      "babel-eslint": "⁸.2.3",
      "babel-loader": "⁷.1.2",
      "babel-plugin-module-resolver": "³.1.1",
      "babel-preset-env": "¹.6.0",
      "babel-preset-es2015": "⁶.24.1",
      "babel-preset-react": "⁶.24.1",
      "compression-webpack-plugin": "¹.0.0",
      "css-loader": "⁰.28.5",
      "enzyme": "³.3.0",
      "enzyme-adapter-react-16": "¹.1.1",
      "eslint": "⁴.5.0",
      "eslint-plugin-babel": "⁵.1.0",
      "eslint-plugin-import": "².7.0",
      "eslint-plugin-jsx-a11y": "⁶.0.2",
      "eslint-plugin-react": "⁷.8.2",
      "eslint-plugin-standard": "³.0.1",
      "extract-text-webpack-plugin": "4.0.0-beta.0",
      "husky": "⁰.14.3",
      "identity-obj-proxy": "³.0.0",
      "jest": "²³.1.0",
      "jsdom": "¹¹.11.0",
      "node-sass": "⁴.5.3",
      "nodemon": "¹.17.4",
      "react-hot-loader": "⁴.2.0",
      "redux-mock-store": "¹.5.1",
      "sass-loader": "⁷.0.1",
      "style-loader": "⁰.21.0",
      "webpack": "⁴.8.3",
      "webpack-bundle-analyzer": "².9.0",
      "webpack-dev-middleware": "³.1.3",
      "webpack-hot-middleware": "².18.2",
      "webpack-hot-server-middleware": "⁰.5.0",
      "webpack-merge": "⁴.1.0",
      "webpack-node-externals": "¹.6.0",
      "webpack-notifier": "¹.6.0"
    }
  }
```

文件：package.json

1.  正如您在我们的 Jest 配置中所看到的，我们需要添加`setupTestFramework.js`文件，我们将在其中配置我们的 enzyme 以便与 Jest 一起使用：

```jsx
  import { configure } from 'enzyme';
  import Adapter from 'enzyme-adapter-react-16';

  configure({ adapter: new Adapter() });
```

文件：config/jest/setupTestFramework.js

1.  在`setupFiles`节点中，我们可以指定我们的`browserMocks.js`文件，这是我们可以模拟在我们的应用程序中使用的任何浏览器方法的地方。例如，如果您想在应用程序中测试`localStorage`，这个文件就是模拟它的合适位置：

```jsx
  // Browser Mocks
  const requestAnimationFrameMock = callback => {
    setTimeout(callback, 0);
  };

  Object.defineProperty(window, 'requestAnimationFrame', {
    value: requestAnimationFrameMock
  });

  const localStorageMock = (() => {
    let store = {}

    return {
      getItem: key => store[key] || null,
      setItem: (key, value) => store[key] = value.toString(),
      removeItem: key => delete store[key],
      clear: () => store = {}
    };
  })();

  Object.defineProperty(window, 'localStorage', {
    value: localStorageMock
  });
```

文件：config/jest/browserMocks.js

1.  如果您在组件中使用 Sass、Stylus 或 Less，您需要使用正则表达式指定`moduleNameMapper`模式，以匹配项目中的所有`.scss`文件（或`.styl`/`.less`），并使用`identity-obj-proxy`处理这些文件，这是一个模拟 Webpack 导入的包，比如 CSS 模块。

1.  您可能已经注意到我们添加了两个新的 NPM 脚本：一个用于测试我们的应用程序，另一个用于获取覆盖率（覆盖的单元测试百分比）。对于这些，我们使用了一个特殊的脚本，就在`scripts/test.js`，让我们创建这个文件：

```jsx
  // Set the NODE_ENV to test
  process.env.NODE_ENV = 'test';

  // Requiring jest
  const jest = require('jest');

  // Getting the arguments from the terminal
  const argv = process.argv.slice(2);

  // Runing Jest passing the arguments
  jest.run(argv);
```

文件：scripts/test.js

1.  让我们想象我们有这个`Home`组件：

```jsx
  import React from 'react';
  import styles from './Home.scss';

  const Home = props => (
    <h1 className={styles.Home}>Hello {props.name || 'World'}</h1>
  );

 export default Home;
```

文件：src/client/home/index.jsx

1.  如果您想测试这个组件，您需要创建一个同名的文件，但在文件名后面加上`.test`后缀。在这种情况下，我们的测试文件将被命名为`index.test.jsx`：

```jsx
  // Dependencies
  import React from 'react';
  import { shallow } from 'enzyme';

  // Component to test...
  import Home from './index';

  describe('Home', () => {
    const subject = shallow(<Home />);
    const subjectWithProps = shallow(<Home name="Carlos" />);

    it('should render Home component', () => {
      expect(subject.length).toBe(1);
    });

    it('should render by default Hello World', () => {
      expect(subject.text()).toBe('Hello World');
    });

    it('should render the name prop', () => {
      expect(subjectWithProps.text()).toBe('Hello Carlos');
    });

    it('should has .Home class', () => {
      expect(subject.find('h1').hasClass('Home')).toBe(true);
    });
  });
```

文件：src/client/home/index.test.jsx

# 它是如何工作的...

如果您想测试您的应用程序，您需要运行以下命令：

```jsx
    npm test
```

如果您的测试正确，您应该会看到这个结果：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/06f4d070-eb65-4f5e-8c03-3ce0c38da895.png)

`PASS`标签表示该文件中的所有测试都已成功通过；如果您至少有一个测试失败，您将看到`FAIL`标签。让我们修改我们的`"should has .Home class`测试。我将把值改为`"Home2"`以强制失败：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/fafaa5db-75bc-4f49-a392-b8d84e029ed7.png)

正如您所见，现在我们得到了`FAIL`标签，并用 X 指定了失败的测试。此外，`Expected`和`Received`值提供了有用的信息，通过这些信息，我们可以看到期望的值和接收到的值。

# 还有更多...

现在，如果您想查看所有单元测试的覆盖百分比，您可以使用以下命令：

```jsx
 npm run coverage
```

现在我们只有 1 个`Home`组件的单元测试，如您所见是绿色的并且达到了 100%，所有其他文件都是红色的并且为 0%，因为它们还没有被测试：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/4e139a3d-06f8-4f18-b59d-74853a9fe635.png)

此外，覆盖命令会生成结果的 HTML 版本。有一个名为`"coverage"`的目录，里面有一个名为`"Icov-report"`的目录。如果您在浏览器中打开`index.html`，您将看到类似于这样的内容：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/c4d20b1a-8bc7-4bcd-acd3-a656736525f8.png)

# 测试 Redux 容器、操作和减速器

在这个示例中，我们将测试 Redux 容器、操作和减速器。在这个例子中，我们将测试我们在第十一章中创建的待办事项列表，实现服务器端渲染。

请记住，如果您使用现有的示例，您必须先运行 npm install 命令来恢复所有项目依赖项，否则您将收到依赖错误。

# 准备就绪

我们需要安装`redux-mock-store`，`moxios`和`redux-thunk`包来测试我们的 Redux 容器。您需要先运行`npm install`来安装所有依赖项：

```jsx
    npm install // This is to install the previous packages
    npm install redux-mock-store moxios redux-thunk
```

# 如何做...

让我们测试我们的 Redux 容器：

1.  Redux 容器不应该有任何 JSX 代码；最佳实践是在我们的`connect`方法中使用`mapStateToProps`和`mapDispatchToProps`，在导出时传递另一个组件（比如`Layout`组件），例如，让我们看看我们的 Todo List 容器：

```jsx
  // Dependencies
  import { connect } from 'react-redux';
  import { bindActionCreators } from 'redux';

 // Components
  import Layout from '../components/Layout';

  // Actions
  import { fetchTodo } from '../actions';

  export default connect(({ todo }) => ({
    todo: todo.list
  }), dispatch => bindActionCreators(
    {
      fetchTodo
    },
    dispatch
  ))(Layout);
```

文件：src/client/todo/container/index.js

1.  您可能想知道我们需要在这里测试什么。嗯，在容器中最重要的事情是测试动作分发（`fetchTodo`动作）并从 Redux 中获取我们的`todo`状态和数据。也就是说，这是我们的容器单元测试文件：

```jsx
  // Dependencies
  import React from 'react';
  import { shallow } from 'enzyme';
  import configureStore from 'redux-mock-store';

  // Actions
  import { fetchTodo } from '../actions';

  // Testable Container
  import Container from './index';

  // Mocking Initial State
  const mockInitialState = {
    todo: {
      list: [
        {
          id: 1,
          title: 'Go to the Gym'
        },
        {
          id: 2,
          title: 'Dentist Appointment'
        },
        {
          id: 3,
          title: 'Finish homework'
        }
      ]
    }
  };

  // Configuring Mock Store
  const mockStore = configureStore()(mockInitialState);

  // Mocking the Actions
  jest.mock('../actions', () => ({
    fetchTodo: jest.fn().mockReturnValue({ type: 'mock-FETCH_TODO_SUCCESS' })
  }));

  describe('Todo Container', () => {
    let mockParams;
    let container;

    beforeEach(() => {
      fetchTodo.mockClear();
      mockParams = {};
      mockStore.clearActions();
      container = shallow(<Container {...mockParams} store={mockStore} />);
    });

    it('should dispatch fetchTodo', () => {
      const { fetchTodo } = container.props();

      fetchTodo();

      const actions = mockStore.getActions();

      expect(actions).toEqual([{ type: 'mock-FETCH_TODO_SUCCESS' }]);
    });

    it('should map todo and get the todo list from Initial State', () => {
      const { todo } = container.props();
      const { todo: { list }} = mockInitialState;

      expect(todo).toEqual(list);
    });
  });
```

文件：src/client/todo/container/index.test.js

1.  测试`fetchTodo`动作。这是我们的动作文件的代码：

```jsx
  // Base Actions
  import { request, received } from '@baseActions';

 // Api
  import api from '../api';

  // Action Types
  import { FETCH_TODO } from './actionTypes';

  export const fetchTodo = () => dispatch => {
    const action = FETCH_TODO;
    const { fetchTodo } = api;

    dispatch(request(action));

    return fetchTodo()
      .then(response => dispatch(received(action, response.data)));
  };
```

文件：src/client/todo/actions/index.js

1.  这是我们的`actionTypes.js`文件：

```jsx
  // Actions
 export const FETCH_TODO = {
    request: () => 'FETCH_TODO_REQUEST',
    success: () => 'FETCH_TODO_SUCCESS'
  };
```

文件：src/client/todo/actions/actionTypes.js

1.  要测试异步 Redux 动作，我们需要使用`redux-thunk`和`moxios`来测试使用`axios`从服务器检索数据的动作。我们的测试文件应该是这样的：

```jsx
  // Dependencies
  import configureMockStore from 'redux-mock-store';
  import thunk from 'redux-thunk';
  import moxios from 'moxios';

  // Action
  import { fetchTodo } from './index';

  // Action Types
  import { FETCH_TODO } from './actionTypes';

  // Configuring Store with Thunk middleware
  const mockStore = configureMockStore([thunk]);

  // Response Mock
  const todoResponseMock = [
    {
      id: 1,
      title: 'Go to the Gym'
    },
    {
      id: 2,
      title: 'Dentist Appointment'
    },
    {
      id: 3,
      title: 'Finish homework'
    }
  ];

  describe('fetchTodo action', () => {
    beforeEach(() => {
      moxios.install();
    });

    afterEach(() => {
      moxios.uninstall();
    });

    it('should fetch the Todo List', () => {
      moxios.wait(() => {
        const req = moxios.requests.mostRecent();

        req.respondWith({
          status: 200,
          response: todoResponseMock
        });
      });

      const expectedActions = [
        {
          type: FETCH_TODO.request()
        },
        {
          type: FETCH_TODO.success(),
          payload: todoResponseMock
        }
      ];

      const store = mockStore({ todo: [] })

      return store.dispatch(fetchTodo()).then(() => {
        expect(store.getActions()).toEqual(expectedActions);
      });
    });
  });
```

文件：src/client/todo/actions/index.test.js

1.  让我们测试我们的 reducer。这是 Todo reducer 文件：

```jsx
  // Utils
  import { getNewState } from '@utils/frontend';

 // Action Types
  import { FETCH_TODO } from '../actions/actionTypes';

  // Initial State
  const initialState = {
    list: []
  };

  export default function todoReducer(state = initialState, action) {
    switch (action.type) {
      case FETCH_TODO.success(): {
        const { payload: { response = [] } } = action;

        return getNewState(state, {
          list: response
        });
      }

      default:
        return state;
    }
  }
```

文件：src/client/todo/reducer/index.js

1.  我们需要在我们的 reducer 中测试两件事：初始状态和`FETCH_TODO`动作成功时的状态。

```jsx
  // Reducer
  import todo from './index';

  // Action Types
  import { FETCH_TODO } from '../actions/actionTypes';

 // Initial State
  const initialState = {
    list: []
  };

  describe('Todo List Reducer', () => {
    it('should return the initial state', () => {
      const expectedInitialState = todo(undefined, {});

      expect(expectedInitialState).toEqual(initialState);
    });

    it('should handle FETCH_TODO when is success', () => {
      const action = {
        type: FETCH_TODO.success(),
        payload: {
          response: [
            {
              id: 1,
              title: 'Go to the Gym'
            },
            {
              id: 2,
              title: 'Dentist Appointment'
            },
            {
              id: 3,
              title: 'Finish homework'
            }
          ]
        }
      };

      const expectedState = {
        list: action.payload.response
      };

      const state = todo(initialState, action);

      expect(state).toEqual(expectedState);
    });
  });
```

文件：src/client/todo/reducer/index.test.js

# 使用 React 和 Redux Dev Tools 调试 React 应用程序

调试对于任何应用程序都是必不可少的，它帮助我们识别和修复错误。Chrome 有两个强大的工具来调试 React/Redux 应用程序，并将其集成到其开发者工具中。React Dev Tool 和 Redux Dev Tool。

# 准备就绪

使用 Google Chrome，您需要安装这两个扩展程序：

+   **React Developer Tools**：[`chrome.google.com/webstore/detail/react-developer-tools/fmkadmapgofadopljbjfkapdkoienihi`](https://chrome.google.com/webstore/detail/react-developer-tools/fmkadmapgofadopljbjfkapdkoienihi)

+   **Redux DevTools**：[`chrome.google.com/webstore/detail/redux-devtools/lmhkpmbekcpmknklioeibfkpmmfibljd?hl=es`](https://chrome.google.com/webstore/detail/redux-devtools/lmhkpmbekcpmknklioeibfkpmmfibljd?hl=es)

此外，您需要安装`redux-devtools-extension`包：

```jsx
npm install --save-dev redux-devtools-extension 
```

安装了 React Developer Tools 和 Redux DevTools 之后，您需要对其进行配置。

如果您尝试直接使用 Redux DevTools，它不会起作用；这是因为我们需要将`composeWithDevTools`方法传递到我们的 Redux 存储中，这应该是我们的`configureStore.js`文件：

```jsx
  // Dependencies
  import { createStore, applyMiddleware } from 'redux';
  import thunk from 'redux-thunk';
  import { composeWithDevTools } from 'redux-devtools-extension';

  // Root Reducer
  import rootReducer from '@reducers';

 export default function configureStore({ initialState, appName, 
  reducer }) {
    const middleware = [
      thunk
    ];

    return createStore(
      rootReducer,
      initialState,
      composeWithDevTools(applyMiddleware(...middleware))
    );
  }
```

文件：src/shared/redux/configureStore.js

# 如何做...

让我们调试我们的应用程序：

1.  如果您想要调试您的 React 应用程序，请使用 Google Chrome 打开您的应用程序（`http://localhost:3000/todo`），打开 Google Dev Tools（右键单击>检查），选择 React 选项卡，您将看到您的 React 组件：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/6ad319a8-580f-42d5-8dd8-3b8878e0af58.png)

1.  您可以选择要调试的组件，其中最酷的一件事是您可以在组件的右侧看到组件的 props：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/7ea082be-ef33-48bc-9b64-0dda7be0e9a6.png)

1.  如果您想要调试 Redux 并查看应用程序中正在分发的动作，您需要在 Chrome Dev Tools 中选择 Redux 选项卡：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/32c8b4c0-9815-4fd0-8a83-50fda8bef7df.png)

1.  在我们的 Todo 应用程序中，我们正在分发两个动作：`FETCH_TODO_REQUEST`和`FETCH_TODO_SUCCESS`。`@@INIT`动作在 Redux 中默认被分发，这在任何应用程序中都会发生。

1.  如果您选择`FETCH_TODO_REQUEST`动作，您会看到在 Diff 选项卡上显示“(states are equal)”。这意味着在该动作中没有任何更改，但您有四个选项卡：Action、State、Diff 和 Test。

1.  如果您选择 Action 选项卡，您可以看到特定的动作：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/63d061e4-e5f4-40dc-8884-014baa38dfe7.png)

1.  如果您选择`FETCH_TODO_SUCCESS`，您将看到 todo reducer 的数据：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/eb869384-482d-4f3a-be4f-6e607f09a13e.png)

# 模拟事件

在这个示例中，我们将学习如何模拟简单计算器组件上的`onClick`和`onChange`事件。

# 如何做到...

我们将重用上一个示例的代码（`Repository: Chapter12/Recipe3/debugging`）：

1.  我们将创建一个简单的`Calculator`组件来对两个值（输入）进行求和，然后当用户点击等号（`=`）按钮时，我们将得到结果：

```jsx
  import React, { Component } from 'react';
  import styles from './Calculator.scss';

  class Calculator extends Component {
    state = {
      number1: 0,
      number2: 0,
      result: 0
    };

    handleOnChange = e => {
      const { target: { value, name } } = e;

      this.setState({
        [name]: value
      });
    }

    handleResult = () => {
      this.setState({
        result: Number(this.state.number1) + Number(this.state.number2)
      });
    }

    render() {
      return (
        <div className={styles.Calculator}>
          <h1>Calculator</h1>

          <input
            name="number1"
            value={this.state.number1}
            onChange={this.handleOnChange}
          />

          {' + '}

          <input
            name="number2"
            value={this.state.number2}
            onChange={this.handleOnChange}
          />

          <button onClick={this.handleResult}>
            =
          </button>

          <input
            name="result"
            value={this.state.result}
          />
        </div>
      );
    }
  }

  export default Calculator;
```

文件：src/client/calculator/index.jsx

1.  如果您想要在浏览器中查看此组件（它是为测试目的而创建的），您需要在路由文件中包含它：

```jsx
 **import** React **from** 'react';
  **import** { Switch, Route } **from** 'react-router-dom';

 **// Components**
  **import** Calculator **from** '../../client/calculator';

  **const** paths = [
    {
      **component**: Calculator,
      **exact**: true,
      **path**: '/'
    }
  ];

  **const** all = (
 **   <Switch>**
     ** <Route** **exact** **path**={paths[0].**path**} **component**={paths[0].**component**} />
    **</Switch>**
  );

 **export default** {
    paths,
    all
  }; 
```

文件：src/shared/routes/index.jsx

1.  如果您想要查看一些基本样式，我们可以使用这些：

```jsx
  .Calculator {
    padding: 100px;

    input {
        width: 50px;
        height: 50px;
        padding: 40px;
        font-size: 24px;
    }

    button {
        padding: 10px;
        margin: 10px;
    }
  }
```

文件：src/client/calculator/Calculator.scss

1.  在我们的测试文件中，我们需要模拟`onChange`事件来改变输入的值，然后模拟点击等号（`=`）按钮：

```jsx
 ** // Dependencies**
  **import** React **from** 'react';
  **import** { shallow } **from** 'enzyme';

  **// Component to test...**
  **import** Calculator **from** './index';

  **describe**('Calculator', () => {
    **const** subject = **shallow**(<Calculator />);

   ** it**('should render Calculator component', () => {
      **expect**(subject.**length**).**toBe**(1);
    });

   ** it**('should modify the state onChange', () => {
      subject.**find**('input[name="number1"]').**simulate**('change', {
        **target**: {
          **name**: 'number1',
          **value**: 5
        }
      });

      subject.**find**('input[name="number2"]').**simulate**('change', {
        **target**: {
          **name**: 'number2',
          **value**: 15
        }
      });

      **// Getting the values of the number1 and number2 states**
      **expect**(subject.**state**('number1')).**toBe**(5);
      **expect**(subject.**state**('number2')).**toBe**(15);
    });

   ** it**('should perform the sum when the user clicks the = button', 
    () => {
      **// Simulating the click event**
      subject.**find**('button').**simulate**('click');

      **// Getting the result value**
      **expect**(subject.**state**('result')).**toBe**(20);
    });
  }); 
```

# 它是如何工作的...

如果您想要在浏览器中查看组件，请使用`npm start`运行应用程序，您将看到类似于这样的东西：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/9886aeca-21eb-4807-9527-61e5538643b6.png)

现在让我们使用`npm test`命令来测试我们的计算器：

抱歉，我无法识别图片中的文本。
