# React 路由快速启动指南（二）

> 原文：[`zh.annas-archive.org/md5/64054E4C94EED50A4AF17DC3BC635620`](https://zh.annas-archive.org/md5/64054E4C94EED50A4AF17DC3BC635620)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：在服务器端呈现的 React 应用程序中使用 StaticRouter

**服务器端渲染**（**SSR**）是一种在服务器上呈现仅客户端的**单页面应用程序**（**SPAs**）的技术，并将完全呈现的页面作为响应发送给用户的请求。在客户端端 SPAs 中，JavaScript 捆绑包被包含为脚本标签，并且最初页面中没有呈现任何内容。捆绑包首先被下载，然后 DOM 节点通过执行捆绑包中的代码进行填充。这有两个缺点——在较差的连接上，可能需要更长时间来下载捆绑包，并且不执行 JavaScript 的爬虫将无法看到任何内容，从而影响页面的 SEO。

SSR 通过在用户请求时加载 HTML、CSS 和 JavaScript 来解决这些问题；内容在服务器上呈现，并且最终的 HTML 交给爬虫。可以使用 Node.js 在服务器上呈现 React 应用程序，并且 React-Router 中可用的组件可以用来定义应用程序中的路由。

在本章中，我们将看看如何在服务器端呈现的 React 应用程序中使用 React-Router 组件：

+   使用 Node.js 和 Express.js 执行 React 应用程序的 SSR

+   添加`<StaticRouter>`组件并创建路由

+   理解`<StaticRouter>`属性

+   通过在服务器上呈现第一页，然后允许客户端代码接管后续页面的呈现来创建同构 React 应用程序

# 使用 Node.js 和 Express.js 执行 React 应用程序的 SSR

在这个例子中，我们将使用 Node.js 和 Express.js 创建一个服务器端应用程序，该应用程序将在服务器上呈现 React 应用程序。Node.js 是一个用于服务器和应用程序的跨平台 JavaScript 运行时环境。它构建在 Google 的 V8 JavaScript 引擎上，并且使用事件驱动的非阻塞 I/O 模型，使其高效且轻量级。Express.js 是 Node.js 环境中使用的最流行的路由和中间件 Web 框架模块之一。它允许您创建中间件，以帮助处理来自客户端的 HTTP 请求。

# 安装依赖项

让我们首先使用`npm init`命令创建一个服务器端应用程序：

```jsx
npm init -y
```

这将创建一个名为`package.json`的文件，并为各种字段添加默认值。下一步是添加依赖项：

```jsx
npm install --save react react-dom react-router react-router-dom express
```

上述命令将把所有必要的库添加到`package.json`文件中的`dependencies`列表中。请注意，我们不是使用`create-react-app` CLI 创建 React 应用程序；相反，我们将添加所需的依赖项并编写构建应用程序的配置文件。

为了构建应用程序，以下开发依赖项被添加到`devDependencies`列表中：

```jsx
npm install --save-dev webpack webpack-cli nodemon-webpack-plugin webpack-node-externals babel-core babel-loader babel-preset-env babel-preset-react 
```

上述命令将把构建应用程序所需的库添加到`package.json`文件中的`devDependencies`列表中。

下一步是编写构建配置，以便构建服务器端应用程序。

# Webpack 构建配置

这是来自 Webpack 文档的：

**Webpack**的核心是现代 JavaScript 应用程序的*静态模块打包程序*。当 webpack 处理您的应用程序时，它在内部构建一个*依赖图*，该图将映射项目所需的每个模块，并生成一个或多个*捆绑包*。

Webpack 已成为为 JavaScript 应用程序创建捆绑包的事实标准。`create-react-app` CLI 包含内部使用`webpack`为开发和生产环境创建捆绑包的脚本。

创建一个名为`webpack-server.config.babel.js`的文件，并包含以下配置：

```jsx
import path from 'path'; import  webpack  from  'webpack'; import  nodemonPlugin  from  'nodemon-webpack-plugin'; import  nodeExternals  from  'webpack-node-externals'; export  default  { entry:  './src/server/index.js', target:  'node', externals:  [nodeExternals()], output:  { path:  path.resolve(__dirname,  'dist'), filename:  'server.js', publicPath:  '/' },
    module:  { rules:  [ {
                test:  /\.js$/, use:  'babel-loader' }
        ]
    },
    plugins:  [ new  webpack.DefinePlugin({ __isBrowser__:  false }),
        new  nodemonPlugin()
    ]
}
```

根据上述配置，文件`index.js`（位于`./src/server`路径）被指定为入口点，并且生成的输出文件`server.js`被复制到`dist`目录。使用`Webpack`的`babel-loader`插件来使用`Babel`和`Webpack`转译应用程序中的 JavaScript 文件。使用`nodemon-webpack-plugin`来运行`nodemon`实用程序，它将监视应用程序中 JavaScript 文件的更改，并在`webpack`以观察模式运行时重新加载和构建应用程序。

下一步是创建一个`.babelrc`文件，其中将列出构建应用程序所需的预设：

```jsx
{
 "presets": ["env","react"] }
```

`babel-preset-env`和`babel-preset-react`插件用于将 ES6 和 React 代码转译为 ES5。作为最后一步，在`package.json`文件中添加一个脚本命令，以使用`webpack-server.config.babel.js`文件中提到的配置启动应用程序：

```jsx
"scripts": {
 "start": "webpack --config webpack-server.config.babel.js --watch --mode development" }
```

命令`npm start`将构建应用程序，并将监听应用程序中 JavaScript 文件的更改，并在检测到更改时重新构建应用程序。

# 服务器端应用程序

如`webpack`配置中所述，应用程序的入口点位于`/src/server/index.js`。让我们在此路径下创建`index.js`文件，并包含以下代码，该代码在给定端口启动服务器应用程序：

```jsx
import  express  from  'express'; const  PORT  =  process.env.PORT  ||  3001; const  app  =  express(); app.get('*', (req, res) => { res.send(` <!DOCTYPE HTML>
 <html>
 <head>
 <title>React SSR example</title>
 </head>
 <body>
 <main id='app'>Rendered on the server side</main>
 </body>
 </html>
 `); });

app.listen(PORT, () => { console.log(`SSR React Router app running at ${PORT}`); });
```

当您运行`npm start`命令并访问 URL`http://localhost:3001`时，将呈现前面的 HTML 内容。这确保了`webpack`配置构建了应用程序，并在端口`3001`上运行前面的服务器端代码，`nodemon`监视文件的更改。

# 使用 ReactDOMServer.renderToString 呈现 React 应用程序

要在服务器端呈现 React 应用程序，首先让我们创建一个 React 组件文件—`shared/App.js`：

```jsx
import  React, { Component } from  'react'; export  class  App  extends  Component { render() { return ( <div>Inside React App (rendered with SSR)</div> ); }
}
```

然后，在`server/index.js`文件中呈现前面的组件：

```jsx
import  express  from  'express'; import  React  from  'react'; import  ReactDOMServer  from  'react-dom/server'; import { App } from  '../shared/App'; app.get('*', (req, res) => { const  reactMarkup  =  ReactDOMServer.renderToString(<App  />**)**; res.send(` <!DOCTYPE HTML>
        <html>
        ...
 **<main id='app'>**${reactMarkup}</main>   
        ...
        </html>
    `); });
```

`ReactDOMServer`类包括用于在服务器端 Node.js 应用程序中呈现 React 组件的各种方法。`ReactDOMServer`类中的`renderToString`方法在服务器端呈现 React 组件并返回生成的标记。然后，可以将此生成的标记字符串包含在发送给用户的响应中。

当您访问`http://localhost:3001`页面时，您会注意到显示了消息“Inside React App (rendered with SSR)”。

确认内容确实是在服务器端呈现的，您可以右键单击页面，然后从上下文菜单中选择“查看页面源代码”选项。页面源代码将显示在新标签页中，其中包括以下内容：

```jsx
<main id='app'>
 <div data-reactroot=""> Inside React App (rendered with SSR) **</div>** </main>
```

当爬虫访问应用程序时，前面的内容很有帮助。通过在服务器端呈现 React 组件，标记被填充并作为来自服务器的响应包含。然后，此内容将被搜索引擎的爬虫索引，有助于应用程序的 SEO 方面。

# 添加<StaticRouter>并创建路由

`<StaticRouter>`组件是`react-router-dom`包的一部分（在`react-router`中使用`<StaticRouter>`定义），它用于在服务器端呈现 React-Router 组件。`<StaticRouter>`组件类似于其他路由器组件，因为它只接受一个子组件——React 应用程序的根组件（`<App />`）。此组件应该在无状态应用程序中使用，用户不会点击以导航到页面的不同部分。

让我们通过包装应用程序的根组件来包含`<StaticRouter>`组件：

```jsx
import { StaticRouter } from  'react-router-dom'**;** app.get('*', (req, res) => { const  context  = {}; const  reactMarkup  =  ReactDOMServer.renderToString( <StaticRouter  context={context}  location={req.url}> <App  /> </StaticRouter**>**  );

    res.send(` ...
        <main id='app'>${reactMarkup}</main> ...
    `);
});
```

请注意，`<StaticRouter>`组件接受两个属性——`context`和`location`。`context`对象是一个空对象，在`<App />`中的一个`<Route>`组件作为浏览器位置匹配的结果进行渲染时，它会被填充属性。

`location`对象通常是请求的 URL，这些信息对中间件函数是可用的。请求对象（`req`）包含指定请求的 URL 的`url`属性。

让我们在`App.js`中包含一对`<Route>`组件：

```jsx
export  class  App  extends  Component {    render() { return ( <div> Inside React App (rendered with SSR) <Route exact
 path='/' render={() =>  <div>Inside Route at path '/'</div>} />
 <Route path='/home' render={() =>  <div>Inside Home Route at path '/home'</div> }
```

```jsx
 />
            </div> ); }
}
```

`<Route>`组件匹配`<StaticRouter>`组件的`location`属性中指定的请求 URL 并进行渲染。

# 使用`<Redirect>`和`staticContext`进行服务器端重定向

从前面的例子中，让我们使用`<Redirect>`组件将用户从`/`路径重定向到`/home`路径：

```jsx
<Route
 path="/" render={() =>  <Redirect  to="/home"  />**}** exact />
```

当您尝试访问 URL `http://localhost:3001/`时，您会注意到重定向没有发生，浏览器的 URL 也没有更新。在客户端环境中，前面的重定向已经足够了。但是，在服务器端环境中，服务器负责处理重定向。在这种情况下，`<StaticRouter>`组件中提到的`context`对象被填充了必要的细节：

```jsx
{
    "action": "REPLACE",
    "location": {
        "pathname": "/home",
        "search": "",
        "hash": "",
        "state": undefined
    },
    "url": "/home"
}
```

`context`对象包含组件渲染的结果。当组件仅渲染内容时，它通常是一个空对象。但是，当渲染的组件重定向到不同的路径时，它会填充前面的细节。请注意，`url`属性指定了应将用户重定向到的路径——到`'/home'`路径。

可以添加一个检查，看看`context`对象中是否存在`url`属性，然后可以使用`response`对象上的`redirect`方法来重定向用户：

```jsx
...
const  reactMarkup  =  ReactDOMServer.renderToString(
 <StaticRouter  context={context}  location={req.url}> <App  /> </StaticRouter> ); if (context.url) { res.redirect(301, 'http://'  +  req.headers.host  +  context.url); } else { res.send(`
        <!DOCTYPE HTML>
        <html>
            ...
        </html>
    `);
}

```

`response`对象中的`redirect`方法用于执行服务器端重定向，并提到状态代码和要重定向到的 URL。

还可以使用渲染组件中的`staticContext`属性向`context`对象中填充更多属性：

```jsx
<Route
 path="/" exact render={({ staticContext, }) => { if (staticContext) { staticContext.status = 301**;** } return ( <Redirect  to="/home"  /> ) }} />
```

在这里，`staticContext`属性在渲染的组件中可用，并且在使用`<Redirect>`组件重定向用户之前，`status`属性被添加到其中。然后`status`属性在`context`对象中可用：

```jsx
res.redirect(context.status, 'http://'  +  req.headers.host  +  context.url);
```

在这里，`context`对象中的`status`属性用于在使用`redirect`方法重定向用户时设置 HTTP 状态。

# 使用 matchPath 进行请求 URL 匹配

在服务器端渲染 React 应用程序时，了解请求的 URL 是否与应用程序中现有路由中的任何一个匹配也是有帮助的。只有在路由可用时，才应在服务器端呈现相应的组件。但是，如果路由不可用，则应向用户呈现一个未找到页面（404）。`react-router`包中的`matchPath`函数允许您将请求的 URL 与包含路由匹配属性（如`path`，`exact`，`strict`和`sensitive`）的对象进行匹配：

```jsx
import { matchPath } from 'react-router'

app.use('*', (req, res) => {
    const isRouteAvailable = **matchPath(req.url, {** path: '/dashboard/',
 strict: true
 });
    ...

});
```

`matchPath`函数类似于库如何将`<Route>`组件与请求的 URL 路径进行匹配。传递给`matchPath`函数的第一个参数是请求的 URL，第二个参数是请求的 URL 应该匹配的对象。当路由匹配时，`matchPath`函数返回一个详细说明请求的 URL 如何与对象匹配的对象。

例如，如果请求的 URL 是`/dashboard/`，`matchPath`函数将返回以下对象：

```jsx
{
    path: '/dashboard/',
    url: '/dashboard/',
    isExact: true,
    params: {}
}
```

在这里，`path`属性提到了用于匹配请求的 URL 的路径模式，`url`属性提到了 URL 的匹配部分，`isExact`布尔属性如果请求的 URL 和路径完全匹配，则设置为`true`，`params`属性列出了与提供的路径名匹配的参数。考虑以下示例，其中提到了路径中的参数：

```jsx
const  matchedObject  =  matchPath(req.url, '/github/:githubID');
```

在这里，不是将对象指定为第二个参数，而是指定了一个路径字符串。如果要将路径与请求的 URL 进行匹配，并使用`exact`，`strict`和`sensitive`属性的默认值，则这种简短的表示法非常有用。匹配的对象将返回以下内容：

```jsx
{
    path: '/github/:githubID',
    url: '/github/sagar.ganatra',
    isExact: true,
    params: { githubID: 'sagar.ganatra' } 
}
```

请注意，`params`属性现在填充了在`path`中提到的参数列表，并提供了请求的 URL 中的值。

在服务器端，在初始化`<StaticRouter>`并渲染 React 应用程序之前，可以执行检查，以查看请求的 URL 是否与对象集合中定义的任何路由匹配。例如，考虑一个路由对象集合。

在`shared/routes.js`中，我们有以下内容：

```jsx
export  const  ROUTES  = [ { path:  '/', exact:  true  }, { path:  '/dashboard/', strict:  true }, { path:  '/github/:githubId' } ];
```

前面的数组包含路由对象，然后可以在`matchPath`中使用它们来检查请求的 URL 是否与前面列表中的任何路由匹配：

```jsx
app.get('*', (req, res) => {
 const isRouteAvailable = ROUTES.find(route => { return matchPath(req.url, route**)**; })
    ...
});
```

如果找到请求的 URL，则`isRouteAvailalbe`将是`ROUTES`列表中的匹配对象，否则当没有路由对象匹配请求的 URL 时，它被设置为`undefined`。在后一种情况下，可以向用户发送页面未找到的标记：

```jsx
if (!isRouteAvailable) {
 **res**.status(404**);** res.send(` <!DOCTYPE HTML> <html> <head><title>React SSR example</title></head> <body> <main id='app'> Requested page '${req.url}**' not found** </main> </body> </html>`); res.end(); }
```

当用户请求路径，比如`/user`，`ROUTES`中提到的对象都不匹配时，前面的响应被发送，提到`404`HTTP 状态，响应主体提到请求的路径`/user`未找到。

# StaticRouter 上下文属性

`<StaticRouter>`组件接受`basename`、`location`和`context`等 props。与其他路由器实现类似，`<StaticRouter>`中的`basename`属性用于指定`baseURL`位置，`location`属性用于指定位置属性——`pathname`、`hash`、`search`和`state`。

`context`属性仅在`<StaticRouter>`实现中使用，它包含组件渲染的结果。如前所述，`context`对象可以填充 HTTP 状态码和其他任意属性。

在初始化时，上下文对象可以包含属性，然后由渲染的组件消耗：

```jsx
const  context  = { message:  'From StaticRouter\'s context object' **}** const  reactMarkup  =  ReactDOMServer.renderToString( <StaticRouter  context={context}  location={req.url}  > <App  /> </StaticRouter> );
```

在这里，上下文对象包含`message`属性，当找到匹配请求 URL 的`<Route>`组件时，包含此属性的`staticContext`对象可用于渲染组件：

```jsx
<Route
 path='/home' render={({ staticContext }) => { return ( <div> Inside Home Route, Message - {staticContext.message**}** </div> ); }} />
```

当您尝试访问`/home`路径时，前面的`<Route>`匹配，并且在`staticContext`消息属性中提到的值被渲染。

`staticContext`属性仅在服务器端环境中可用，因此，在同构应用程序中尝试引用`staticContext`对象（在下一节中讨论），会抛出一个错误，指出您正在尝试访问未定义的属性消息。可以添加检查以查看`staticContext`是否可用，或者可以检查在 webpack 配置中定义的`__isBrowser__`属性的值：

```jsx
<Route
 path='/home' render={({ staticContext }) => { if (!__isBrowser__) { return ( <div> Inside Home Route, Message - {staticContext.message} </div> ); } return ( <div>Inside Home Route, Message</div> ); }} />
```

在上面的例子中，如果页面在服务器端渲染，则`__isBrowser__`属性将为`false`，并且`staticContext`对象中指定的消息将被渲染。

# 创建同构 React 应用程序

一个应用程序，其中代码可以在服务器端和客户端环境中运行，几乎没有或没有变化，被称为同构应用程序。在同构应用程序中，用户的网络浏览器发出的第一个请求由服务器处理，任何后续请求由客户端处理。通过在服务器端处理和渲染第一个请求，并发送 HTML、CSS 和 JavaScript 代码，提供更好的用户体验，并帮助搜索引擎爬虫索引页面。然后，所有后续请求可以由客户端代码处理，该代码作为服务器的第一个响应的一部分发送。

以下是更新后的请求-响应流程：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rtr-qk-st-gd/img/5968e318-34f0-48bd-8fab-5731d0c8a64d.png)

为了在客户端渲染应用程序，可以使用`<BrowserRouter>`或`<HashRouter>`组件中的任何一个。在本例中，我们将使用`<BrowserRouter>`组件。

添加了用于客户端代码的目录后，应用程序结构如下：

```jsx
/server-side-app
|--/src
|----/client
|------index.js
|----/server
|------index.js
|----/shared
|------App.js
```

在这里，`shared`目录将包含可以被服务器端和客户端代码使用的代码。使用`<BrowserRouter>`组件的客户端特定代码位于`client`目录中的`index.js`文件中：

```jsx
import  React  from  "react"; import  ReactDOM  from  "react-dom"; import { BrowserRouter } from  "react-router-dom"; import { App } from  "../shared/App"; // using hydrate instead of render in SSR app ReactDOM.hydrate( <BrowserRouter> <App  /> </BrowserRouter>, document.getElementById("app") );
```

在这里，`ReactDOM`类中的`hydrate`方法被用来渲染应用程序，而不是调用`render`方法。`hydrate`方法专门设计用来处理初始渲染发生在服务器端（使用`ReactDOMServer`）的情况，以及所有后续的路由更改请求来更新页面的特定部分都由客户端代码处理。`hydrate`方法用于将事件监听器附加到在服务器端渲染的标记上。

下一步是构建应用程序，以便在构建时生成客户端包，并包含在服务器的第一个响应中。

# Webpack 配置

现有的 webpack 配置构建了服务器端应用程序，并运行`nodemon`实用程序来监视更改。为了生成客户端包，我们需要包含另一个 webpack 配置文件—`webpack-client.config.babel.js`：

```jsx
import  path  from  'path'; import  webpack  from  'webpack'; export  default { entry:  './src/client/index.js', output: { path:  path.resolve(__dirname, './dist/public'), filename:  'bundle.js', publicPath:  '/' }, module: { rules: [ { test: /\.js$/, use:  'babel-loader' } ] }, plugins: [ new  webpack.DefinePlugin({ __isBrowser__:  "true" }) ] }
```

前面的配置解析了`/src/client/index.js`文件中的依赖关系，并在`/dist/public/bundle.js`处创建了一个包。这个包包含了运行应用程序所需的所有客户端代码；不仅是`index.js`文件中的代码，还包括`shared`目录中声明的组件。

当前的`npm start`脚本还需要修改，以便客户端应用程序代码与服务器端代码一起构建。让我们创建一个文件，导出服务器和客户端 webpack 配置——`webpack.config.babel.js`：

```jsx
import clientConfig from './webpack-client.config.babel'; import serverConfig from './webpack-server.config.babel'; export default [clientConfig, serverConfig];
```

最后，更新`npm start`脚本，以引用上述配置文件：

```jsx
"start": "webpack --config webpack.config.babel.js --mode development --watch"
```

上述脚本将生成`server.js`，其中包含服务器端代码，以及`bundle.js`，其中包含客户端代码。

# 服务器端配置

最后一步是更新服务器端代码，将客户端 bundle（`bundle.js`）包含在第一个响应中。服务器端代码可以包含一个`<script>`标签，其中指定了`bundle.js`文件的源（`src`）属性：

```jsx
res.send(`
 <!DOCTYPE HTML> <html> <head> <title>React SSR example</title> **<script src='/bundle.js' defer></script>** ...
    </html>
`);
```

另外，为了使我们的 express 服务器能够提供 JavaScript 文件，我们包括了用于提供静态内容的中间件函数：

```jsx
app.use(express.static('dist/public'))
```

上述代码允许从`dist/public`目录提供静态文件，如 JavaScript 文件、CSS 文件和图像。在使用`app.get()`之前，应包含上述语句。

当您访问`/home`路径的应用程序时，第一个响应来自服务器，并且除了渲染与`/home`路径匹配的`<Route>`之外，客户端 bundle——`bundle.js`也包含在响应中。`bundle.js`文件由浏览器下载，然后路由路径的任何更改都由客户端代码处理。

# 摘要

在本章中，我们看了一下如何使用`ReactDOMserver.renderToString`方法在服务器端（使用 Node.js 和 Express.js）呈现 React 应用程序。React-Router 中的`<StaticRouter>`组件可用于包装应用程序的根组件，从而使您能够在服务器端添加与请求的 URL 路径匹配的`<Route>`组件。`<StaticRouter>`组件接受`context`和`location`属性。在渲染的组件中，`staticContext`属性（仅在服务器端可用）包含`context`属性中由`<StaticRouter>`提供的数据。它还可以用于在使用`<Redirect>`组件时添加属性以重定向用户。

`matchPath` 函数用于确定请求的 URL 是否与提供的对象 `{path, exact, strict, sensitive}` 匹配。这类似于库如何将请求的 URL 与页面中可用的 `<Route>` 组件进行匹配。`matchPath` 函数使我们能够确定请求的 URL 是否与集合中的任何路由对象匹配；这为我们提供了一个机会，可以提前发送 404：页面未找到的响应。

还可以创建一个同构的 React 应用程序，它在服务器端渲染第一个请求，然后在客户端渲染后续请求。这是通过在从服务器发送第一个响应时包含客户端捆绑文件来实现的。客户端代码在第一个请求之后接管，这使您能够更新与请求的路由匹配的页面的特定部分。

在第七章中，*在 React Native 应用程序中使用 NativeRouter*，我们将看看如何使用 `NativeRouter` 组件来定义 React-Native 创建的原生移动应用程序中的路由。


# 第七章：在 React Native 应用程序中使用 NativeRouter

React Router 库提供了`react-router-native`包，其中包括用于 React Native 应用程序的`NativeRouter`组件的实现。React Native 框架允许您使用 JavaScript 和 React 构建 iOS 和 Android 的本机移动应用程序。

来自 React Native 文档（[`facebook.github.io/react-native/`](https://facebook.github.io/react-native/)）：

“使用 React Native，您不会构建**移动 Web 应用程序**，**HTML5 应用程序**或**混合应用程序**。您构建的是一个与使用 Objective-C 或 Java 构建的应用程序无异的真实移动应用程序。React Native 使用与常规 iOS 和 Android 应用程序相同的基本 UI 构建块。您只需使用 JavaScript 和 React 将这些构建块组合在一起。”

在本章中，讨论了以下主题：

+   在 React Native 应用程序中使用 NativeRouter

+   NativeRouter 组件及其属性

+   使用`<BackButton>`组件与设备的返回按钮交互

+   使用`<DeepLinking>`组件创建深链接

# 在 React Native 应用程序中使用 NativeRouter

与`create-react-app`CLI 类似，`create-react-native-app`CLI 用于创建一个包含构建脚本的应用程序，可用于开发和生产环境。它还包括`packager`，允许您在 iOS 和 Android 模拟器以及真实设备上测试应用程序。

# 使用 create-react-native-app CLI 创建新项目

让我们首先安装 CLI：

```jsx
npm install -g create-react-native-app
```

上一个命令将 CLI 安装在全局的`node_modules`目录中。下一步是使用 CLI 创建一个 React Native 项目：

```jsx
create-react-native-app react-native-test-app
```

创建了`react-native-test-app`目录，并在`node_modules`目录中下载了所有必需的脚本。

现在，当您运行`npm start`脚本时，构建脚本会启动`packager`，并为您生成一个 QR 码和一个 URL，以便您在真实设备（iOS 或 Android）或模拟器上访问应用程序。此外，如果您已安装 Xcode 或 Android Studio，还可以启动 iOS 或 Android 模拟器。这是一个例子：

```jsx
Your app is now running at URL: exp://192.168.1.100:19000
View your app with live reloading:
Android device:
-> Point the Expo app to the QR code above.
(You'll find the QR scanner on the Projects tab of the app.)
iOS device:
-> Press s to email/text the app URL to your phone.
Emulator:
-> Press a (Android) or i (iOS) to start an emulator.
Your phone will need to be on the same local network as this computer.
For links to install the Expo app, please visit https://expo.io.
Logs from serving your app will appear here. Press Ctrl+C at any time to stop.
› Press a to open Android device or emulator, or i to open iOS emulator.
› Press s to send the app URL to your phone number or email address
› Press q to display QR code.
› Press r to restart packager, or R to restart packager and clear cache.
› Press d to toggle development mode. (current mode: development)
```

在本例中，我们将使用 Xcode 模拟器；当您请求在 iOS 模拟器上查看应用程序时，这是应用程序的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rtr-qk-st-gd/img/f7fd2ef8-6c2e-45db-ae0f-4af41389c7c4.png)

React Native 提供了几个组件，允许您为原生平台构建视图。让我们看一下代码，并了解用于构建前述视图的一些组件。

在`App.js`中，包括以下代码：

```jsx
export  default  class  App  extends  React.Component {    render() { return ( <View  style={styles.container}**>**  <Text>Open up App.js to start working on your app!</Text**>** <Text>Changes you make will automatically reload.</Text> <Text>Shake your phone to open the developer menu.</Text> </View> ); } }
```

在这里，React Native 的`<View>`组件被用来创建一个容器，类似于在 React 应用程序中使用`<div>`或`<section>`创建容器的方式。在 React Native 中，不是使用 HTML 元素，如`<div>`和`<span>`，而是使用 React Native 的组件，如`<View>`和`<Text>`。

# 添加`<NativeRouter>`组件

让我们现在将`react-router-native`包添加到我们刚刚创建的应用程序中：

```jsx
 npm install --save react-router-native
```

`NativeRouter`组件用于在 React Native 应用程序中提供路由和导航支持。它使得诸如`<Route>`和`<Link>`之类的组件可以在原生应用程序中使用。

让我们首先创建一个包含一对`<Link>`组件的侧边菜单：

```jsx
import { Link } from 'react-router-native';

export  class  Menu  extends  Component { render() { return ( <ScrollView  scrollsToTop={false}  style={styles.menu}> <View> <Link  to="/"> <Text>Home</Text> </Link> <Link  to="/dashboard"> <Text>Dashboard</Text> </Link**>** </View> </ScrollView> ) } }
```

`<ScrollView>`组件被用作容器来承载我们的菜单项（`<Link>`组件）。正如其名称所示，`<ScrollView>`组件用于创建可滚动的容器。下一步是向应用程序添加`<Route>`组件：

```jsx
export  class  ContentView  extends  Component { render() { return ( <View  style={styles.container}> <Route path="/" exact component={HomeComponent} /> <Route path="/dashboard" component={DashboardComponent} **/>** </View> ) } }
```

`ContentView`组件将`<Route>`组件包装在`<View>`组件中，从而定义了路径为`/`和`/dashboard`的两个应用程序路由。

作为最后一步，我们现在将使用`react-native-side-menu`中的`<SideMenu>`组件来创建一个抽屉菜单。然后在 App.js 中将此菜单包装在`<NativeRouter>`组件中：

```jsx
export  default  class  App  extends  Component { render() { const  menu  =  <Menu  />**;** return ( <NativeRouter**>** <View  style={styles.container}> <SideMenu  menu={menu}> <ContentView  /> </SideMenu**>** </View> </NativeRouter**>** ); } }
```

类似于其他路由器实现，`NativeRouter`组件包装了应用程序根组件，并使得`<Route>`和`<Link>`组件可以在用户浏览应用程序时更新`history`。

在模拟器上重新构建应用程序后：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rtr-qk-st-gd/img/317f8265-8360-4d55-9354-3a4a7df48933.png)

当您选择任一链接时，`ContentView`将使用由`<Route>`匹配渲染的组件进行更新。

前述功能类似于`BrowserRouter`使您能够浏览应用程序中定义的各种路由。类似于`<Route>`和`<Link>`组件，其他组件，如`<Switch>`、`<Redirect>`和`<NavLink>`在 React Native 应用程序中的行为也是相同的。然而，当您尝试使用`<Prompt>`组件阻止导航时，应该使用 React Native 的`Alert`组件来显示确认消息。

从 NativeRouter 的实现：

```jsx
import { Alert } from  "react-native";

NativeRouter.defaultProps = {
    getUserConfirmation: (message, callback) => {
        Alert.alert("Confirm", message, [
            { text: "Cancel", onPress: () => callback(false) },
            { text: "OK", onPress: () => callback(true) }
        ]);
    }
};
```

NativeRouter 提供了`getUserConfirmation`函数的默认实现，它使用`react-native`包中定义的`Alert`组件来向用户显示确认消息：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rtr-qk-st-gd/img/ebf55586-f7e0-4a03-b0cd-61f6cf419d08.png)

这种默认行为可以通过包括`getUserConfirmation`属性来覆盖：

```jsx
<NativeRouter getUserConfirmation={customGetUserConfirmation}>
...
</NativeRouter>
```

# <NativeRouter>组件

`NativeRouter`组件使用`react-router`包中定义的`MemoryRouter`组件在 React Native 应用程序中提供路由支持。当您希望在内存中保留浏览历史记录而不更新地址栏中的 URL 时，可以使用`MemoryRouter`。这在没有地址栏的非浏览器环境中特别有用。`MemoryRouter`组件使用`history`包中可用的`createMemoryHistory`类创建一个`history`对象。然后将此`history`对象提供给低级别的`<Router>`接口。

在`NativeRotuer.js`中：

```jsx
import  MemoryRouter  from  "react-router/MemoryRouter"; const  NativeRouter  =  props  =>  <MemoryRouter {...props} />;
```

然后，`MemoryRouter`组件使用`createMemoryHistory`在`MemoryRouter.js`中创建一个`history`对象：

```jsx
import { createMemoryHistory  as  createHistory } from  "history"; class  MemoryRouter  extends  React.Component { **history** =  createHistory(this.props**)**;
    ...

    render() {
        return <Router 
                  history={this.history} children={this.props.children}
               />;
    }
}
```

`NativeRouter`组件接受 props：`initialEntries`，`initialIndex`，`getUserConfirmation`，`keyLength`和`children`。如前所述，`NativeRouter`类中包含了`getUserConfirmation`的默认实现，而`keyLength`和`children`属性的行为与前几章中提到的其他路由器组件类似。

让我们来看看`initialEntries`和`initialIndex`属性。

# initialEntries 属性

initialEntries 属性用于使用位置列表填充历史堆栈：

```jsx
export  default  class  App  extends  Component {    render() {
        const  initialEntries  = ['/', '/dashboard'**]**; return ( <NativeRouter  initialEntries={initialEntries**}**> ...
            </NativeRouter>
        );
    }
}
```

在初始化 NativeRouter 时，您可以通过提供位置路径数组来填充历史记录。位置路径可以是字符串，甚至是形状为`{ pathname，search，hash，state }`的对象：

```jsx
const initialEntries = [
    '/' ,
    { 
 pathname: '/dashboard',
 search: '',
 hash: 'test', 
 state: { from: '/'}
 }
];
```

# initialIndex 属性

initialIndex 属性用于指定在应用程序加载时渲染在`initialEntries`数组中的位置的索引值。例如，如果`initialEntries`数组列出了两个位置，那么`initialIndex`值为`1`会加载第二个条目；也就是说，匹配`initialEntries`数组中第二个条目作为路径名的`<Route>`实例会被渲染：

```jsx
export  default  class  App  extends  Component {    render() { const  initialEntries  = ['/', '/dashboard']; const  initialIndex  =  1; return ( <NativeRouter  initialEntries={initialEntries}  initialIndex={initialIndex**}**> ...
            </NativeRouter>
        )
    }
}
```

在这个例子中，`initialIndex`的值设置为`1`，因此当应用程序加载时，匹配位置路径`/dashboard`的`<Route>`被渲染。

# <BackButton>组件

默认情况下，在 Android 设备上按下返回按钮时，应用程序会退出，而不是将用户导航到历史记录中的上一个状态。React Native 库包括一个`BackHandler`类，它允许您自定义设备的硬件返回按钮的行为。React Router 中的`<BackButton>`组件使用`BackHandler`类来自定义 Android 设备上返回按钮的行为：

```jsx
import { NativeRouter, BackButton } from 'react-router-native';

export  default  class  App  extends  Component { render() { return (
            <NativeRouter>
                <View  style={styles.container}>
                    **<BackButton />** <SideMenu  menu={menu}> <ContentView  /> </SideMenu> </View> </NativeRouter> )
    }
}
```

`<BackButton>`组件可以包含在应用程序的任何位置。在前面的示例中，该组件包含在根组件中，不包含任何子组件。请注意，`<BackButton>`组件不会在视口上呈现任何内容；相反，它促进了与设备返回按钮的交互。

以下是工作流程：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rtr-qk-st-gd/img/3ee74a56-b270-4210-a09c-3bc8a798ee30.png)

在仪表板屏幕（路径为`/dashboard`）上，当您点击设备的返回按钮时，用户将被导航到主页（路径为`/`）。

# 使用<DeepLinking>创建深层链接

在 Web 应用程序中，HTTP URL 引用的位置可以通过在浏览器的地址栏中输入来访问。在单页应用程序中，此位置指的是用户可以导航到的特定路由。在移动应用程序的上下文中，`DeepLink`指的是您想要查看的特定页面或内容。例如，当您在移动设备上点击链接时，应用程序会启动，而不是在浏览器窗口中打开新标签，并显示所请求的页面。

与 Web 应用程序不同，移动设备上的应用程序需要为应用程序声明 URI 方案，而不是使用 HTTP 引用特定位置。例如，Twitter 应用程序使用 URI 方案`twitter://`，因此您可以通过引用 URI `twitter://profile` 查看他们的 Twitter 个人资料。当用户点击电子邮件中的链接或访问推送通知消息时，深层链接非常有用，这些链接将用户导航到应用程序以显示所请求的内容。

React Native 提供了接口，允许您在 iOS 和 Android 平台上为设备创建深层链接。在本节中，我们将看看如何在 Android 设备上创建深层链接，因此我们需要安装 Android Studio。Android Studio 允许我们创建虚拟设备（AVD），然后用于测试深层链接。

在 React Native 文档中详细介绍了在 iOS 和 Android 上安装必要组件的逐步指南：[`facebook.github.io/react-native/docs/getting-started.html`](https://facebook.github.io/react-native/docs/getting-started.html)。

安装 Android Studio 并创建 AVD 后，需要为应用程序配置 URI 方案。要添加 URI 方案，需要更新一些本机文件，并且要访问这些本机文件，需要退出当前设置。

# 从 create-react-native-app 中退出

`create-react-native-app` CLI 是一个非常好的选项，可以为 React Native 应用程序提供脚手架和在模拟器上测试应用程序。然而，要测试`DeepLinking`，我们需要在清单文件中包含条目，因此需要使用以下命令退出配置：

```jsx
npm run eject
```

上一个命令将为 iOS 和 Android 平台生成配置文件。这个最基本的配置允许你为 iOS 设备生成一个`.ipa`文件，为 Android 设备生成一个`.apk`文件。在本节中，我们将看到如何生成`.apk`文件，然后部署到 AVD 上。

退出后，你会看到为 iOS 和 Android 生成的各种目录和文件：

```jsx
|--/android
|----/.gradle
|----/app
|----/build
|----/gradle
|----/keystores
|--/ios
|----/chapter7DeepLink
|----/chapter7DeepLink-tvOS |----/chapter7DeepLink-tvOSTests |----/chapter7DeepLink.Xcodeproj |----/chapter7DeepLinkTests
```

下一步是在 Android 设备上构建和运行应用程序：

```jsx
npm run android
```

上一个命令将运行构建脚本并生成`.apk`文件，然后部署到 AVD 上。请确保在执行上一个命令之前虚拟设备正在运行。

要在 Android 设备上配置 URI 方案，需要更新位于`/android/app/src/main`路径的`AndroidManifest.xml`清单文件。在下一节中，我们将看到需要添加到清单文件中的配置。

# 向清单文件添加<intent-filter>

`AndroidManifest.xml`文件包含有关应用程序的元信息，并用于声明应用程序中存在的各种组件。这些组件使用意图过滤器进行激活。清单文件中的`<intent-filter>`实例用于定义应用程序的功能，并定义其他应用程序与应用程序交互的策略。

当你退出配置时，`AndroidManifest.xml`文件将被生成：

```jsx
<manifest  xmlns:android="http://schemas.android.com/apk/res/android"
 **package**="com.chapter7deeplink"> <uses-permission  android:name="android.permission.INTERNET"  /> <uses-permission  android:name="android.permission.SYSTEM_ALERT_WINDOW"/> <application android:name=".MainApplication" android:label="@string/app_name" android:icon="@mipmap/ic_launcher" android:allowBackup="false" android:theme="@style/AppTheme"> <activity android:name=".MainActivity" android:label="@string/app_name" android:configChanges="keyboard|keyboardHidden|orientation|screenSize" android:windowSoftInputMode="adjustResize"> <intent-filter> <action  android:name="android.intent.action.MAIN"  /> <category  android:name="android.intent.category.LAUNCHER"  /> </intent-filter**>** </activity> <activity  android:name="com.facebook.react.devsupport.DevSettingsActivity"  /> </application> </manifest>
```

在这里，`<intent-filter>`为应用程序定义了动作和类别，分别为`android.intent.action.MAIN`和`android.intent.category.LAUNCHER`。前一个`intent-filter`使应用程序能够在用户设备上看到，并且当用户点击应用程序时，应用程序中的`MainActivity`（请参阅 activity 标签）会被触发。

类似地，用于为应用程序定义 URI 方案的`intent-filter`可以添加到清单文件中：

```jsx
<intent-filter  android:label="filter_react_native">
 <action  android:name="android.intent.action.VIEW"  /> <category  android:name="android.intent.category.DEFAULT"  /> <category  android:name="android.intent.category.BROWSABLE"  /> <data  android:scheme="deeplink"  android:host="app.chapter7.com" **/>** </intent-filter>
```

在这里，`<data>`标签用于指定应用程序的 URI 方案。`<data>`标签中的`android:scheme`属性用于指定方案名称，`android:host`属性用于指定应用程序使用的`hostname`类型。因此，`deeplink://app.chapter7.com` URI 用于访问应用程序中的主页。可以使用此 URI 访问具有`/dashboard`路径的路由：`deeplink://app.chapter7.com/dashboard`。

下一步是使用 React Router 的`<DeepLinking>`组件，以便应用程序可以对传入的请求做出反应，并将用户导航到请求的路由。

# 包括<DeepLinking>组件

`react-router-native`包中的`<DeepLinking>`组件使用 React Native 的`Linking`接口来监听 URL 的更改。每当检测到更改时，用户就会通过在历史堆栈中添加条目来导航到请求的路径。

`<DeepLinking>`组件可以包含在应用程序的任何位置：

```jsx
export  class  RootComponent  extends  Component { render() { return ( <View  style={styles.container}> <DeepLinking **/>** <View  style={styles.nav}> <Link  to="/app.chapter7.com">
                        <Text>Home</Text>
                    </Link> <Link  to="/app.chapter7.com/dashboard">
                        <Text>Dashboard</Text>
                    </Link> </View> <View  style={styles.routeContainer}> <Route  path="/app.chapter7.com"  exact  component={HomeComponent}  /> <Route  path="/app.chapter7.com/dashboard"  component={DashboardComponent}  /> </View> </View> ) } }
```

在这里，`<DeepLinking>`组件包含在应用程序的`RootComponent`中，并且`<Route>`路径使用前缀`app.chapter7.com`进行更新，以匹配`AndroidManifest.xml`文件中声明的主机名。

要测试深层链接，请尝试以下命令：

```jsx
adb shell am start -W -a android.intent.action.VIEW -d deeplink://app.chapter7.com/dashboard
```

上一个命令应该在 AVD 上启动应用程序，并将您导航到具有`/dashboard`路径的路由。

# 摘要

在本章中，我们看了一下 React Router 的`<NativeRouter>`组件如何在 React Native 应用程序中使用。`<NativeRouter>`组件包含在`react-router-native`包中，并在内部使用`react-router`包中定义的`<MemoryRouter>`组件。`<NativeRouter>`组件接受 props：`initialEntries`、`initialIndex`、`getUserConfirmation`、`keyLength`和`children`。此外，它为`getUserConfirmation`函数提供了默认实现，该函数使用 React Native 的`Alert`组件显示确认消息。当应用程序中包含`<Prompt>`组件并且用户尝试从当前路由导航时，将显示此确认消息。

`<BackButton>`组件在`react-router-native`中是 React Native 的`BackHandler`类的包装器，它监听设备的返回按钮，并通过历史堆栈中的一个条目将用户导航回去。`<DeepLinking>`组件用于处理应用程序中内容的深层链接。该组件使用 React Native 的`Linking`接口来监听 URL 的更改，并在使用深层链接 URI 方案访问应用程序时将用户导航到请求的路由。要为应用程序定义 URI 方案，需要更新`AndroidManifest.xml`清单文件，为主要活动（`.MainActivity`）添加`<intent-filter>`。`intent-filter`声明要使用的 URI 方案和主机名以访问应用程序内的内容。

在下一章中，我们将看一下状态管理工具 Redux，并了解如何将 React Router 与 Redux 结合使用。


# 第八章：使用 connected-react-router 的 Redux 绑定

在之前的章节中，我们看到了如何使用组件的状态来存储模型数据，以及当模型由于用户操作而更新时，React 如何更新视图。在大型应用程序中，此状态信息不仅应该对当前组件及其子组件可用，还应该对应用程序树中的其他组件可用。有各种状态管理库可用，可帮助使用户界面组件与应用程序状态保持同步。Redux 是一个这样的库，它使用一个中央数据存储来管理应用程序的状态。存储作为真相的来源，应用程序中的组件可以依赖于存储中维护的状态。

在本章中，我们将看一下`connected-react-router`库，它为 React Router 提供了 Redux 绑定。本章讨论以下主题：

+   使用 Redux 进行状态管理-介绍 Redux 概念

+   开始使用`connected-react-router`

+   从 Redux 存储中读取 react-router 状态

+   通过分派操作导航到不同路由

# 使用 Redux 进行状态管理

如前所述，Redux 使用单个存储来管理应用程序的状态。除了`Store`，还有另外两个构建块：`Actions`和`Reducers`。

让我们看看这些构建块如何帮助维护`state`并在`Store`中的`state`更改时更新视图。

# 操作

操作让您定义用户可以执行的操作，以更新应用程序的状态。操作是一个 JavaScript 对象，具有`{ type，payload }`的形状，其中`type`是指用户操作的字符串，`payload`是应该更新状态的数据：

```jsx
let todoId = 0;
export const addTodo = text => ({
    type: 'ADD_TODO'
    payload: {
        text,
        id: todoId++,
        isCompleted: false
    }
})
```

在这里，`addTodo`操作接受 TODO 文本，并指示该操作用于将 TODO 添加到 TODO 列表中。`payload`在这里是一个包含 TODO `text`，TODO `ID`和布尔标志`isCompleted`（设置为 false）的对象。也可以有不需要包含`payload`属性的操作。例如，考虑以下操作：

```jsx
export const increment = () => ({
    type: 'INCREMENT'
})
```

在这里，`action`类型`INCREMENT`表示实体的值必须增加 1。前面的`action`不需要`payload`属性，并且根据操作类型，可以更新实体的状态。

# 减速器

Redux 中的 Reducer 根据分派到存储的操作改变实体的状态。Reducer 是一个纯函数，接受两个参数：`state`和`action`。然后根据存储在`action.type`中的值返回更新后的状态。例如，考虑以下 reducer：

```jsx
const todoReducer  = (state  = [], action) => { switch (action.type) { case  '**ADD_TODO**':
            return [
                ...state,
                {
                    id: action.payload.id,
                    text: action.payload.text,
                    isCompleted: action.payload.isCompleted
                }
            ];  default: return  state; } }
```

`todoReducer`的初始状态设置为空数组（状态参数的默认值），当操作类型为`ADD_TODO`时，TODO 被添加到列表中。Redux 的核心原则之一是不要改变状态树，而是返回一个新的状态树作为组件分派的操作的结果。这有助于保持 reducer 函数的纯净（即没有副作用），并有助于在 React 组件重新渲染视图元素时识别新的状态变化。

同样，可能会有多个更新 TODO 状态的操作（如`MARK_COMPLETED`和`DELETE`），并且根据分派到存储的操作类型，reducer 可以改变 TODO 列表的状态。

# 存储

存储是一个中心数据对象，应用程序的状态可以从中派生。应用程序中的组件订阅存储状态的变化并更新视图。

Redux 中数据的流动方式如下：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rtr-qk-st-gd/img/cb8a8480-c8bd-4a97-af97-49da8821c08d.png)

用户执行操作，比如提交表单或点击按钮，从而向存储分派一个操作。应用程序定义了用户可以执行的各种操作，reducer 被编码以便处理这些操作并更新实体的状态。应用程序中各种实体的状态都在一个中心位置维护：存储。例如，应用程序可能有各种实体，如 Todo 和用户配置文件，存储将维护这些实体的状态信息。每当 reducer 更新存储中特定实体的状态值时，用户界面组件从存储接收更新，更新组件的状态信息并重新渲染视图以显示更新后的状态。

# React 中的 Redux

使用`create-react-app`CLI 创建项目后，包括依赖`redux`和`react-redux`：

```jsx
npm install --save redux react-redux 
```

`redux`库包括`createStore`、`combineReducers`、`bindActionCreators`、`applyMiddleware`和`compose`辅助函数；而`react-redux`库包括 Redux 绑定，帮助你的 React 组件与 Redux 存储通信。

下一步是定义用户可以从用户界面发起的动作。在我们的示例中，我们将创建一个`Counter`组件，该组件可以`增加`和`减少`计数器的值。

在`actions/counter.js`中：

```jsx
export  const  increment  = () => ({ **type:****'INCREMENT'** }); export  const  decrement  = () => ({ type: **'DECREMENT'** });
```

在为我们的计数器实体定义动作之后，需要定义更新`counter`状态的`reducer`：

在`reducers/counter.js`中：

```jsx
const  counterReducer  = (state  =  0, action) => {    switch (action.type) { case  'INCREMENT': return  state  +  1; case  'DECREMENT': return  state  -  1; default: return  state; }
}

export  default **counterReducer**;
```

在这里定义的`reducer`根据用户触发的`action`类型更新`state`值。同样，应用程序中可以有各种 reducers 和 actions，它们在用户触发某个动作时更新实体的状态。

`redux`中的`combineReducers`实用程序允许您将所有 reducers 组合成一个单一的 reducer，然后可以在应用程序的存储中使用它来进行初始化。

在`reducers/index.js`中：

```jsx
import { combineReducers } from  'redux'; import  counterReducer  from  './counter'; const  rootReducer  =  combineReducers({ count:  counterReducer,
    todo: todoReducer }); export  default  rootReducer;
```

使用`combineReducers`函数创建了一个`rootReducer`，它接受一个包含实体和 reducer 键值映射的对象。这里`counterReducer`分配给了`count`实体，`todoReducer`分配给了一个带有`todo`键的实体。

然后在`createStore`函数中使用`rootReducer`来创建一个 store。

在`index.js`中：

```jsx
import { createStore } from 'redux';

const  store  =  createStore(
    rootReducer
);
```

使用`react-redux`库中定义的`<Provider>`组件，将 store 提供给应用程序中的组件：

```jsx
ReactDOM.render(
 **<**Provider  store={store}**>**
 **<**Counter **/>**
 **</**Provider>,
 document.getElementById('root')
);
```

应用程序中的组件现在可以使用`connect`高阶函数订阅存储中实体（`count`和`todo`）的状态更改。创建了一个`Counter`组件，它将显示`count`的当前状态值，并将分发我们在`actions/counter.js`中定义的`increment`和`decrement`动作。

在`components/counter.component.js`中：

```jsx
import { increment, decrement } from  '../actions/counter'; const  Counter  = ({ count, increment, decrement }) => ( <div> <h4>Counter</h4> <button  onClick={decrement}>-</button> <span>{count}</span> <button  onClick={increment}>+</button> </div> )
```

使用以下`connect`方法从`store`中提供`count`、`increment`和`decrement`属性：

```jsx
import { connect } from  'react-redux'; import { increment, decrement } from  '../actions/counter';  ... const  mapStateToProps  =  state  => ({    count:  state.count });

const  mapDispatchToProps  =  dispatch  => ({    increment: () =>  dispatch(increment()),
    decrement: () =>  dispatch(decrement()) })

export  default  connect(mapStateToProps, mapDispatchToProps)(Counter**)**;
```

`react-redux`中的`connect`高阶函数帮助您将 Redux 状态注入到您的 React 组件中。`connect` HOC 接受两个参数：`mapStateToProps`和`mapDispathToProps`。如观察到的，Redux 状态`count`属性在`mapStateToProps`中分配给了组件的状态`count`属性，同样地，组件可以使用`mapDispatchToProps`中指定的`increment`和`decrement`动作向存储分发动作。在这里，为了从 Redux 存储中读取状态值，使用了`mapStateToProps`，`connect`提供了整个状态树给组件，以便组件可以从状态树中的各种对象中读取。为了改变状态树的状态，`mapDispatchToProps`帮助分发与存储注册的动作。`connect` HOC 提供了`dispatch`方法，以便组件可以在存储上调用动作。

# 开始使用 connected-react-router

`connected-react-router`库为 React Router 提供了 Redux 绑定；例如，可以从 Redux 存储中读取应用程序的历史记录，并且可以通过向存储分发动作来导航到应用程序中的不同路由。

让我们首先使用`npm`安装`connected-react-router`和其他库：

```jsx
npm install --save connected-react-router  react-router  react-router-dom  history
```

接下来，我们将更新存储设置。

在`index.js`中：

```jsx
import { applyMiddleware, createStore, compose } from  'redux'; import { ConnectedRouter, connectRouter, routerMiddleware } from  'connected-react-router'; const  history  =  createBrowserHistory(); const  composeEnhancer  =  window.__REDUX_DEVTOOLS_EXTENSION_COMPOSE__  ||  compose; const  store  =  createStore( connectRouter(history)(rootReducer), composeEnhancer(applyMiddleware(routerMiddleware(history))) );
```

`createStore`函数具有以下签名：

```jsx
createStore(reducer, preloadedState, enhancer) 
```

它接受三个参数：第一个参数是`reducer`函数，它根据当前状态树和要处理的动作返回下一个状态树；第二个参数指定应用程序的初始`state`，应该是一个与`combineReducers`中使用的形状相同的对象；第三个参数指定存储`enhancer`，它为存储添加更多功能，如时间旅行、持久性等。

在我们的示例中，第一个参数如下：

```jsx
connectRouter(history)(rootReducer)
```

`connected-react-router`中的`connectRouter`包装`rootReducer`并返回一个带有`router`状态的新根 reducer。`connectRouter` reducer 响应类型为`@@router/LOCATION_CHANGE`的动作以更新路由器状态。注意，`connectRouter`接受`history`对象作为其参数；然后使用`history`对象初始化路由器状态的`location`和`action`属性。

`createStore`的第二个参数是增强器：

```jsx
composeEnhancer  =  window.__REDUX_DEVTOOLS_EXTENSION_COMPOSE__  ||  compose;
... composeEnhancer(applyMiddleware(routerMiddleware(history)))
```

请注意，我们将 `enhancer` 指定为第二个参数。如果 `createStore` 方法的第二个参数是函数，并且未指定 `createStore` 的第三个参数，则将第二个参数标记为 `enhancer`。`redux` 中的 `compose` 实用程序返回通过从右到左组合给定函数获得的函数。在前面的情况下，我们正在检查浏览器中是否可用 `Redux Devtools Extension`，它使您能够查看应用程序中各种实体的状态。

`routerMiddleware` 在 `connected-react-router` 中定义，是一个中间件函数，用于使用提供的 `history` 对象重定向用户。如果分发了一个 `'CALL_HISTORY_METHOD'` 类型的动作，中间件函数将通过调用 `history` 对象上的方法将用户导航到请求的路由。它还阻止了动作 (`CALL_HISTORY_METHOD`) 到达应用程序中定义的其他 reducer 和在 `routerMiddleware` 之后定义的中间件组件。

Redux 中的 `applyMiddleware` 实用程序用于创建存储增强器，它将中间件应用于 Redux 存储的分发方法。

下一步是使用 `<Provider>` 组件使存储（使用 `createStore` 创建）可用于应用程序中的组件：

```jsx
ReactDOM.render(
 **<**Provider  store={store}> <ConnectedRouter  history={history}**>** <App  /> </ConnectedRouter> </Provider>, document.getElementById('root'));
```

在这里，我们将应用程序根组件包装在 `<ConnectedRouter>` 组件内部，而 `<ConnectedRouter>` 组件又包装在 `<Provider>` 组件内部。这是必需的，因为 `ConnectedRouter` 订阅了 `router` 状态的更改，以查看 `location` 属性是否已更改，然后调用 `history.push` 方法将用户导航到请求的路由。

通过这些更改，我们应用程序中的组件现在可以从存储中读取状态信息，并分发动作以导航到应用程序中定义的各种路由。

# 从 Redux 存储中读取状态信息

为了测试上述设置，让我们首先在我们的导航栏中创建一个 `<Link>` 组件和一个相应的具有相同路径名的 `<Route>`：

```jsx
<Link
 **to**={{ pathname: '/dashboard', search: 'q=1', hash: 'test',
        state: { key: 'value' } }**}** > Dashboard </Link> ...
<Route  path='/dashboard'  component={Dashboard}  />
```

请注意，`<Link>` 组件指定了带有 `pathname`、`search`、`hash` 和 `state` 属性的 `to` 对象。我们将从 Redux 存储中读取此信息在我们的渲染组件中：

```jsx
const  Dashboard  = ({ pathname, search, hash, state, count }) => { return ( <div> <h4>In Dashboard</h4> <div> Pathname   : {pathname}  </div> <div> Search     : {search}  </div> <div> Hash       : {hash}  </div> <div> State-Key  : {state? state.key : null} </div>  </div> ) } const  mapStateToProps  =  state  => ({ pathname:  state.router.location.pathname, search:  state.router.location.search, hash:  state.router.location.hash, state:  state.router.location.state  }); export  default  connect(mapStateToProps)(Dashboard);
```

从这段代码中，`pathname`、`search`、`location`和`hash`属性从`state.router.location`中读取。正如前面提到的，`connectRouter`函数创建了`router`状态，并在分发了`LOCATION_CHANGE`类型的动作时更新了值。`<ConnectRouter>`组件监听历史对象的变化，然后在你使用`<Link>`组件尝试导航时分发`LOCATION_CHANGE`动作。

如果你在 Chrome 中安装了 Redux Dev Tools（在 Chrome Web Store 中可用），你可以观察到当你尝试从一个路由导航到另一个路由时分发的动作。

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rtr-qk-st-gd/img/0e48d393-6727-4d43-8fb2-cc9ef8fb8b28.png)

在这个 Dev Tools 窗口中，当你尝试导航时，会分发`@@router/LOCATION_CHANGE`动作，下一节中的动作显示了分发动作时提供的有效载荷。

# 通过分发动作进行导航

`connected-react-router`库提供了可以从组件中分发的动作，以导航到应用程序中定义的路由。这些包括`push`、`replace`、`go`、`goBack`和`goForward`。这些方法调用历史对象上的相应方法，以导航到指定的路径。

前面例子中的`DashboardComponent`现在可以更新为使用`mapDispatchToProps`：

```jsx
import {push, replace} from 'connected-react-router'; const  Dashboard  = ({ pathname, search, hash, state, count, push, replace }) => {    return ( ...
<button  onClick={() => {push('/')}}>HOME</button> <button  onClick={() => {replace('/counter')}}>COUNTER</button>
        ...
 ) } 
const  mapStateToProps  =  state  => ({ ...
}); 
const  mapDispatchToProps  =  dispatch  => ({ push: (path) =>  dispatch(push(path**))**, replace: (path) =>  dispatch(replace(path**))** });

export  default  connect(mapStateToProps, mapDispatchToProps)(Dashboard**)**;
```

前面的组件现在在你点击 HOME 和 COUNTER 按钮时分发`push`和`replace`动作。`mapDispatchToProps`函数使你能够向 store 分发动作，在我们的例子中，`push`和`replace`函数接受一个`pathname`来分发动作。

# 总结

在本章中，我们看到了如何使用 Redux 库创建一个存储来管理应用程序中的各种状态实体。存储接收动作，当分发动作时，减少器改变应用程序的状态。`connected-react-router`库为 React Router 提供了 Redux 绑定，其中包括一个高阶函数`connectRouter`，它包装了`rootReducer`并创建了一个`router`状态。然后在`createStore`函数中使用`connectRouter`函数，使`router`状态可用于应用程序中的组件。

`connected-react-router`中的`<ConnectedRouter>`组件监听`history`位置的变化，并分发`LOCATION_CHANGE`动作来更新`router`状态属性。然后渲染的路由组件可以通过从存储中读取状态信息来读取这个`router`状态属性。

该库还包括`push`、`replace`、`go`、`goBack`和`goForward`动作，组件可以分发这些动作来导航到应用程序中定义的路由。
