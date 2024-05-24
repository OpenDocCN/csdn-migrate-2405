# React 和 Bootstrap Web 开发学习手册（三）

> 原文：[`zh.annas-archive.org/md5/59c715363f0dff298e7d1cff58a50a77`](https://zh.annas-archive.org/md5/59c715363f0dff298e7d1cff58a50a77)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：ReactJS API

在之前的章节中，我们学习了 React 路由器，它允许我们创建单页应用程序，并确保我们的 UI 与 URL 同步。我们还介绍了 React 路由器的优势、动态路由匹配以及如何配置路由器中的组件以与匹配的 URL 在 DOM 中呈现。通过 React 路由器浏览器历史功能，用户可以向后/向前导航并恢复应用程序的先前状态。现在我们将检查如何将 React API 与 Facebook、Twitter 和 Git 等其他 API 集成。

# React 顶级 API

当我们谈论 React API 时，这是进入 React 库的第一步。不同的 React 用法会提供不同的输出。例如，使用 React 的`script`标签将使顶级 API 在`React`全局上可用，使用 npm 的 ES6 将允许我们编写`import React from 'react'`，而使用 npm 的 ES5 将允许我们编写`var React = require('react')`，因此有多种不同特性初始化 React 的方式。

# React API 组件

通常，在处理 React 时，我们正在构建适合其他组件的组件，并且我们假设用 React 构建的任何东西都是一个组件。然而，这并不正确。需要有其他一些方法来编写支持代码，以将外部世界与 React 连接起来。观察以下代码片段：

```jsx
ReactDOM.render(reactElement, domContainerNode)
```

`render`方法用于更新组件的属性，然后我们可以声明一个新元素来再次呈现它。

另一种方法是`unmountComponentAtNode`，用于清理你的代码。当我们使用 React 组件构建 SAP 时，我们必须插入`unmountComponentAtNode`以在正确的时间启动，从而清理应用程序的生命周期。观察以下代码片段：

```jsx
ReactDOM.unmountComponentAtNode(domContainerNode)
```

我经常观察到开发人员不调用`unmountComponentAtNode`方法，这导致他们的应用程序出现内存泄漏问题。

## 挂载/卸载组件

在你的 API 中，建议始终使用自定义包装器 API。假设你有一个或多个根，它将在某个时期被删除，那么在这种情况下，你将不会丢失它。Facebook 就有这样的设置，它会自动调用`unmountComponentAtNode`。

我还建议不要每次调用`ReactDOM.render()`，而是通过库来编写或使用它的理想方式。在这种情况下，应用程序将使用挂载和卸载来进行管理。

创建一个自定义包装器将帮助您在一个地方管理配置，比如国际化、路由器和用户数据。每次在不同的地方设置所有配置都会非常痛苦。

# 面向对象编程

如果我们在声明变量下面再次声明它，它将被覆盖，就像`ReactDOM.render`覆盖了它的声明属性一样：

```jsx
ReactDOM.render(<Applocale="en-US"userID={1}/>,container); 
// props.userID == 1
// props.locale == "en-US" 
ReactDOM.render(<AppuserID={2}/>,container); 
// props.userID == 2
// props.locale == undefined ??!?
```

如果我们只覆盖组件中的一个属性，那么建议使用面向对象编程将覆盖所有声明的属性可能会令人困惑。

您可能会认为我们通常使用`setProps`作为辅助函数，以帮助覆盖选择性属性，但由于我们正在使用 React，我们不能使用它；因此，建议在您的 API 中使用自定义包装器。

在下面的代码中，您将看到一个样板，以帮助您更好地理解它：

```jsx
classReactComponentRenderer{ 
    constructor(componentClass,container){ 
        this.componentClass=componentClass; 
        this.container=container; 
        this.props={}; 
        this.component=null; 
    } 

    replaceProps(props,callback){ 
        this.props={}; 
        this.setProps(props,callback); 
    } 

    setProps(partialProps,callback){ 
        if(this.componentClass==null){ 
            console.warn( 
                'setProps(...): Can only update a mounted or '+ 
                'mounting component. This usually means you called 
                setProps() on '+'an unmounted component. This is a no-op.' 
            ); 
            return; 
        } 
        Object.assign(this.props,partialProps); 
        varelement=React.createElement(this.klass,this.props); 
        this.component=ReactDOM.render(element,this.container,callback); 
    } 

    unmount(){ 
        ReactDOM.unmountComponentAtNode(this.container); 
        this.klass=null; 
    }
}
```

在前面的例子中，似乎我们仍然可以在面向对象的 API 中编写更好的代码，但为此我们必须了解自然的面向对象 API 及其在 React 组件中的使用：

```jsx
classReactVideoPlayer{                                 
    constructor(url,container){ 
        this._container=container; 
        this._url=url; 
        this._isPlaying=false; 
        this._render(); 
    } 

    _render(){ 
        ReactDOM.render( 
            <VideoPlayerurl={this._url}playing={this._isPlaying}/>, 
            this._container 
        ); 
    } 

    geturl(){ 
        returnthis._url; 
    } 

    seturl(value){ 
        this._url=value; 
        this._render(); 
    } 

    play(){ 
        this._isPlaying=true; 
        this._render(); 
    } 

    pause(){ 
        this._isPlaying=false; 
        this._render(); 
    } 

    destroy(){ 
        ReactDOM.unmountComponentAtNode(this._container); 
    }
}
```

我们可以从前面的例子中了解到**命令式**API 和**声明式**API 之间的区别。这个例子还展示了我们如何在声明式 API 或反之上提供命令式 API。在使用 React 创建自定义 Web 组件时，我们可以使用声明式 API 作为包装器。

# React 与其他 API 的集成

React 集成只是通过使用 JSX、Redux 和其他 React 方法将 Web 组件转换为 React 组件。

让我们看一个 React 与另一个 API 集成的实际例子。

## React 与 Facebook API 集成

这个应用将帮助您集成 Facebook API，并且您将可以访问您的个人资料图片以及您在好友列表中有多少个朋友。您还将看到在各自朋友列表中有多少个赞、评论和帖子。

首先，您必须安装 Node.js 服务器并在系统中添加 npm 包。

如果您不知道如何安装 Node.js，请参阅以下说明。

### 安装 Node

首先，我们必须下载并安装 Node.js 版本 0.12.10，如果我们还没有在系统上安装它。我们可以从[`nodejs.org`](http://nodejs.org)下载 Node.js，它包括 npm 包管理器。

设置完成后，我们可以检查 Node.js 是否设置正确。打开命令提示符并运行以下命令：

```jsx
**node  -v** 
```

或者

```jsx
**node --version**
```

这将返回 Node.js 安装的版本，如下所示：

![Installing Node](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_08_001-1.jpg)

您应该能够看到版本信息，这可以确保安装成功。

安装 Node 后，您将拥有`babel-plugin-syntax-object-rest-spread`和`babel-plugin-transform-object-rest-spread`。

这两者之间有一个基本的区别：`spread`只允许您阅读语法，但`transform`将允许您将语法转换回 ES5。

完成此操作后，您将不得不将插件存储到`.babelrc`文件中，如下所示：

```jsx
{ 
  "plugins": ["syntax-object-rest-spread", "transform-object-rest-spread"] 
} 

```

### 设置应用程序

首先，我们需要为我们的项目创建一个`package.json`文件，其中包括项目信息和依赖项。现在，打开命令提示符/控制台并导航到您创建的目录。运行以下命令：

```jsx
**Npm init**
```

这个命令将初始化我们的应用程序，并在创建一个名为`package.json`的 JSON 文件之前询问几个问题。该实用程序将询问有关项目名称、描述、入口点、版本、作者名称、依赖项、许可信息等的问题。一旦执行了该命令，它将在项目的根目录中生成一个`package.json`文件。

我已经根据我的要求创建了`package.json`文件，如下所示：

```jsx
{ 
  "name": "facebook-api-integration-with-react", 
  "version": "1.2.0", 
  "description": "Web Application to check Like, Comments and
  Post of your Facebook Friends, 

```

在上述代码中，您可以看到应用程序的`name`，您的应用程序的`version`和您的应用程序的`description`。观察以下代码片段：

```jsx
  "scripts": { 
    "lint": "eslint src/ server.js config/ webpack/", 
    "start": "npm run dev", 
    "build": "webpack -p --config webpack/webpack.config.babel.js
    --progress --colors --define process.env.NODE_ENV='"production"'", 
    "clean": "rimraf dist/", 
    "deploy": "npm run clean && npm run build", 
    "dev": "./node_modules/.bin/babel-node server.js" 
  }, 

```

从上述代码中，您可以设置您的`scripts`，以详细说明如何`start`您的服务器，如何`build`，如何`clean`，以及`deploy`和`dev`。请确保您在各自变量中定义的路径是正确的，否则您的应用程序将无法按预期工作。观察以下代码片段：

```jsx
  "author": "Mehul Bhatt <mehu_multimedia@yahoo.com>", 
  "license": "MIT", 
  "keywords": [ 
    "react", 
    "babel", 
    "ES6", 
    "ES7", 
    "async", 
    "await", 
    "webpack", 
    "purecss", 
    "Facebook API" 
  ], 

```

上述代码显示了`author`名称，`license`（如果适用）以及您的应用程序的`keywords`。观察以下代码片段：

```jsx
  "devDependencies": { 
    "babel-cli": "⁶.3.17", 
    "babel-core": "⁶.3.26", 
    "babel-eslint": "⁶.0.0", 
    "babel-loader": "⁶.2.0", 
    "babel-plugin-react-transform": "².0.0-beta1", 
    "babel-plugin-transform-regenerator": "⁶.5.2", 
    "babel-polyfill": "⁶.5.0", 
    "babel-preset-es2015": "⁶.3.13", 
    "babel-preset-react": "⁶.3.13", 
    "babel-preset-stage-0": "⁶.5.0", 
    "css-loader": "⁰.23.0", 
    "enzyme": "².4.1", 
    "eslint": "².12.0", 
    "eslint-config-airbnb": "⁹.0.1", 
    "eslint-plugin-import": "¹.8.1", 
    "eslint-plugin-jsx-a11y": "¹.5.3", 
    "eslint-plugin-react": "⁵.2.0", 
    "express": "⁴.13.3", 
    "file-loader": "⁰.9.0", 
    "imports-loader": "⁰.6.5", 
    "json-loader": "⁰.5.4", 
    "lolex": "¹.4.0", 
    "react-transform-catch-errors": "¹.0.1", 
    "react-transform-hmr": "¹.0.1", 
    "redbox-react": "¹.2.0", 
    "rimraf": "².5.0", 
    "sinon": "¹.17.4", 
    "style-loader": "⁰.13.0", 
    "url-loader": "⁰.5.7", 
    "webpack": "¹.12.9", 
    "webpack-dev-middleware": "¹.4.0", 
    "webpack-hot-middleware": "².6.0", 
    "yargs": "⁴.1.0" 
  }, 
  "dependencies": { 
    "classnames": "².2.5", 
    "jss": "⁵.2.0", 
    "jss-camel-case": "².0.0", 
    "lodash.isequal": "⁴.0.0", 
    "react": "¹⁵.0.2", 
    "react-addons-shallow-compare": "¹⁵.0.2", 
    "react-dom": "¹⁵.0.2", 
    "reqwest": "².0.5", 
    "spin.js": "².3.2" 
  } 
} 

```

最后，您可以在上述代码中看到您的应用程序的`dependencies`，这将帮助您设置所需的组件并获取数据，以及前端内容。您还可以看到定义的`devDependencies`及其版本，这些与您的应用程序相关联。

设置`package.json`文件后，我们有如下所示的 HTML 标记，名为`index.html`：

```jsx
<!doctype html> 
<html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>React Integration with Facebook API</title>
        <meta name="viewport" content="width=device-width, 
        initial-scale=1">
    </head>
    <body>
        <div id=" Api-root"></div>
        <script src="dist/bundle.js"></script> 
    </body>
</html>

```

在`config.js`中使用唯一 ID 配置您的应用程序：

```jsx
export default { 
    appId: '1362753213759665', 
    cookie: true, 
    xfbml: false, 
    version: 'v2.5' 
}; 

```

如前所示，您可以将配置放在一个文件中。您可以将其命名为`index.js`。该文件包括您的`appId`，在本地目录中运行应用程序时非常重要。

要获得您的 ID，您必须在 Facebook 上注册您的应用程序[`developers.facebook.com`](https://developers.facebook.com)，然后您将需要按照以下步骤进行操作：

1.  登录到您的 Facebook 开发者帐户：![设置应用程序](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_08_002-1.jpg)

1.  登录后，您将在右侧看到一个名为**我的应用程序**的下拉菜单。点击它并打开列表菜单。在那里，您将找到**添加新应用程序**。点击它将打开一个对话框，显示**创建新应用程序 ID**，如下截图所示：![设置应用程序](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_08_003-1.jpg)

输入所需的详细信息，然后点击**创建应用程序 ID**按钮。

1.  创建应用程序 ID 后，请转到**仪表板**页面，您将看到类似以下的屏幕：![设置应用程序](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_08_004-1.jpg)

1.  在**仪表板**页面上，您左侧的导航显示**设置**链接。请点击该链接设置应用程序的**基本**和**高级**设置：![设置应用程序](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_08_005-1.jpg)

1.  一旦您能够看到前面的屏幕，您将能够看到您动态生成的**应用程序 ID**，**显示名称**类别和**应用程序密钥**自动填充。您还将看到**应用程序域**。在访问应用程序并通知我们需要在此处定义域时，此字段非常重要。但是，如果您直接将您的`localhost`写为域，它将不被接受，您的应用程序将出现错误。

为了使您的本地主机可访问，我们必须定义其平台。现在，请向下滚动一点以访问**+** **添加平台**：

![设置应用程序](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_08_006-1.jpg)

1.  一旦您点击**+添加平台**，您将在屏幕上看到以下选项，并且您必须选择**网站**在本地服务器上运行应用程序：![设置应用程序](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_08_007-1.jpg)

1.  在您选择**网站**作为平台后，将会在屏幕上添加一个字段，如下截图所示：![设置应用程序](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_08_008-2.jpg)

1.  一旦你得到了前面的屏幕，你需要将**站点 URL**定义为`http://localhost:3000/`，然后以类似的方式，在**应用域**字段中定义相同的域，如下面的截图所示：![设置应用程序](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_08_009-3.jpg)

1.  在做了上述更改之后，请通过点击右下角的**保存更改**按钮来保存你的更改：![设置应用程序](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_08_010-1.jpg)

现在你的 ID 已经创建好了，你可以在你的`config.js`文件中使用它来链接你的应用在本地服务器上运行。

在设置好`config.js`文件之后，下一步是在应用程序中设置你所需的文件，并将你的动态内容注入到 HTML ID 中。

你可以在`index.js`文件中导入所需的组件、工具和 CSS，并将其放在不同的文件夹中，这样它就不会与你的配置`index.js`文件冲突：

```jsx
import React from 'react'; 
import { render } from 'react-dom'; 
import App from './components/App'; 

import 'babel-polyfill'; 

// import CSS 

import '../vendor/css/base.css'; 
import '../vendor/css/bootstrap.min.css'; 

render( 
  <App />, 
  document.querySelector('#Api-root') 
); 

```

在前面的代码中，你可以看到我导入了`React`来支持 React 文件，并导入了所需的 CSS 文件。最后一步，`render`方法在定义了你的 HTML ID 之后将为你完成这个技巧。确保`document.querySelector`有正确的选择器，否则你的应用将无法以正确的结构渲染。

你可以在前面的代码中看到，我创建了一个名为`App`的组件并导入了它。

在`App.js`文件中，我导入了几个组件，这些组件帮助我从我的 Facebook 账户中获取数据，借助 Facebook API 集成。

观察一下`App.js`文件的代码结构：

```jsx
/* global Facebook  */ 

import React, { Component } from 'react'; 
import Profile from './Profile'; 
import FriendList from './FriendList'; 
import ErrMsg from './ErrMsg'; 
import config from '../../config'; 
import Spinner from './Spinner'; 
import Login from './Login'; 
import emitter from '../utils/emitter'; 
import { getData } from '../utils/util'; 
import jss from 'jss';

```

前面导入的 JavaScript 文件已经设置好了获取数据的结构，关于它将如何在你的应用程序中执行。

```jsx
const { classes } = jss.createStyleSheet({ 
  wrapper: { 
    display: 'flex' 
  }, 
  '@media (max-width: 1050px)': { 
    wrapper: { 
      'flex-wrap': 'wrap' 
    } 
  } 
}).attach(); 

```

前面的代码定义了常量来为包装器创建样式，在页面在浏览器中渲染时将应用这些样式。

```jsx
class App extends Component { 

  state = { 
    status: 'loading' 
  }; 

  componentWillMount = () => { 
    document.body.style.backgroundColor = '#ffffff'; 
  }; 

  componentWillUnmount = () => { 
    emitter.removeListener('search'); 
  }; 

  componentDidMount = () => { 
    emitter.on('search', query => this.setState({ query })); 

    window.fbAsyncInit = () => { 
      FB.init(config); 

      // show login 
      FB.getLoginStatus( 
        response => response.status !== 'connected' && 
        this.setState({ status: response.status }) 
      ); 

      FB.Event.subscribe('auth.authResponseChange', (response) => { 
        // start spinner 
        this.setState({ status: 'loading' }); 

        (async () => { 
          try { 
            const { profile, myFriends } = await getData(); 
            this.setState({ status: response.status, profile, myFriends }); 
          } catch (e) { 
          this.setState({ status: 'err' }); 
       } 
     })(); 
   }); 
}; 

```

前面的代码扩展了组件，包括挂载/卸载的细节，这些细节我们在之前的章节中已经涵盖过了。如果你对这个领域还不确定，那么请重新查看一下。

`window.fbAsyncInit`将会将 Facebook API 与登录设置同步，并验证登录的状态。

它还将异步获取 Facebook 数据，比如你的个人资料和好友列表，这部分有单独的 JavaScript，将在本章后面进行讲解。

```jsx
    // Load the SDK asynchronously 
    (function (d, s, id) { 
      const fjs = d.getElementsByTagName(s)[0]; 
      if (d.getElementById(id)) { return; } 
      const js = d.createElement(s); js.id = id; 
      js.src = '//connect.facebook.net/en_US/sdk.js'; 
      fjs.parentNode.insertBefore(js, fjs); 
    }(document, 'script', 'facebook-jssdk')); 
  }; 

  _click = () => { 
    FB.login(() => {}, { scope: ['user_posts', 'user_friends'] }); 
  }; 

```

定义一个范围数组意味着我们正在访问用户的 Facebook 好友和帖子。

观察下面的截图：

![设置应用程序](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_08_011-1.jpg)

在上述截图中，您可以看到在创建 Facebook 登录应用程序时**App Review**选项卡中的默认登录权限访问。我们可以提交批准以访问任何其他用户信息：

```jsx
  mainRender = () => { 
    const { profile, myFriends, status, query } = this.state; 
    if (status === 'err') { 
      return (<ErrMsg />); 
    } else if (status === 'unknown' || status === 'not_authorized') { 
      return <Login fBLogin={this._click} />; 
    } else if (status === 'connected') { 
      return ( 
        <div className={classes.wrapper}> 
          <Profile {...profile} /> 
          <FriendList myFriends={myFriends} query={query} /> 
        </div> 
      ); 
    } 
    return (<Spinner />); 
  }; 

  render() { 
    return ( 
      <div> 
        {this.mainRender()} 
      </div> 
    ); 
  } 
}  
export default App; 

```

在上述代码中，`mainRender`方法将呈现`Profile`，`myFriends`（好友列表）和`status`，并且它将在`render return`中返回值。您可以在`render`方法中看到一个`<div>`标签；我称之为`{this.mainRender()}`来在其中注入数据。

正如您所知，这里我们正在处理第三方 API 集成。我们不确定我们将连接到该 API 多长时间以及加载内容需要多长时间。最好有一个内容加载器（旋转器），表示用户需要等待一段时间，因此我们使用以下旋转器来显示页面上内容加载的进度。旋转器的代码也包含在`App.js`文件中。以下是旋转器的样子：

![设置应用程序](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_08_012-1.jpg)

您还可以选择自己的自定义旋转器。

一旦您的应用程序页面准备就绪，最终输出应该如下截图所示，您将看到基本的外观和感觉，以及所需的元素：

![设置应用程序](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/B05743_08_13-1.jpg)

一旦您启动本地服务器，上述屏幕将要求您允许继续登录过程。

一旦您按下**同意**按钮，它将重定向您到 Facebook 登录页面。这可以通过以下代码（`Login.js`）实现：

```jsx
import React, { PropTypes } from 'react'; 
import jss from 'jss'; 
import camelCase from 'jss-camel-case'; 
jss.use(camelCase());  

```

在导入 React `PropTypes`之后，在以下代码中，您将看到我已经定义了一个常量来为登录页面创建样式。您也可以在这里定义样式，并且可以将它们放入一个 CSS 文件中，并且有一个外部文件调用。

```jsx
const { classes } = jss.createStyleSheet({ 
  title: { 
    textAlign: 'center', 
    color: '#008000' 
  }, 
  main: { 
    textAlign: 'center', 
    backgroundColor: 'white', 
    padding: '15px 5px', 
    borderRadius: '3px' 
  },     
  wrapper: { 
    display: 'flex', 
    minHeight: '60vh', 
    alignItems: 'center', 
    justifyContent: 'center' 
  }, 
  '@media (max-width: 600px)': { 
    title: { 
      fontSize: '1em' 
    }, 
    main: { 
      fontSize: '0.9em' 
    } 
  } 
}).attach(); 

```

以下代码显示了登录页面的 HTML 结构，并且还定义了`Login.propTypes`用于登录按钮：

```jsx
const Login = ({ fBLogin }) => ( 
  <div className={classes.wrapper}> 
    <div> 
      <h2 className={classes.title}>Please check your friend list 
      on Facebook</h2> 
        <div className={classes.main}> 
          <h4>Please grant Facebook to access your friend list</h4> 
          <button className="btn btn-primary" 
          onClick={fBLogin}>Agree</button> 
        </div> 
    </div> 
  </div> 
);  

Login.propTypes = { 
  fBLogin: PropTypes.func.isRequired 
}; 

export default Login; 

```

当您点击**同意**按钮时，您的应用程序将被重定向到 Facebook 登录页面。请参考以下截图：

![设置应用程序](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_08_014-1.jpg)

一旦您使用您的凭据登录，它将要求您允许访问您的数据，如下截图所示：

![设置应用程序](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_08_015-1.jpg)

一旦您提供了所需的细节并按下**继续**按钮，它将给您最终屏幕和最终输出。

![设置应用程序](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_08_016-1.jpg)

出于安全原因，我已经模糊了我的朋友的个人资料图片和他们的名字，但是您将在您的 Facebook 账户中获得相同的布局。现在您在考虑在您的应用程序中获取朋友列表，对吧？所以，借助以下代码的帮助，我在我的自定义应用程序中获取了一个列表。

`FriendList.js`被导入到`App.js`文件中：

```jsx
import React, { PropTypes } from 'react'; 
import FriendItem from './FriendItem'; 
import { MAX_OUTPUT } from '../utils/constants'; 
import jss from 'jss'; 
import camelCase from 'jss-camel-case';  

jss.use(camelCase()); 

```

在前面的代码片段中，我们还导入了`React`，`constants`和`FriendItem`来获取数据。在这里，我们只是导入了`FriendItem`，但它将有一个单独的文件来处理这个问题：

```jsx
const { classes } = jss.createStyleSheet({ 
  nodata: { 
    fontSize: '1.5em', 
    display: 'flex', 
    justifyContent: 'center', 
    alignItems: 'center', 
    textAlign: 'center', 
    color: 'white', 
    minHeight: '100vh', 
  }, 
  wrapper: { 
    flex: '3' 
  }, 
  '@media (max-width: 1050px)': { 
    wrapper: { 
      flex: '1 1 100%' 
    }, 
    nodata: { 
      minHeight: 'auto' 
    } 
  } 
}).attach(); 

```

前面的代码定义了朋友列表内容的包装器样式。正如我之前所说，您也可以将它们放在一个单独的 CSS 文件中，并进行外部调用，以便您方便。

```jsx
const emptyResult = (hasFriends, query) => { 
  return ( 
    <div className={classes.nodata}> 
      {hasFriends ? `No results for: "${query}"` : 'No friends to show'} 
    </div> 
  ); 
}; 

```

在前面的代码中，您可以看到一个条件来验证某人是否有朋友或没有朋友。如果某人在他们的 Facebook 账户中没有朋友列表，它将显示上述消息。

```jsx
const renderFriends = ({ myFriends, query }) => { 
  const result = myFriends.reduce((prev, curr, i) => { 
    if (curr.name.match(new RegExp(query, 'i'))) { 
      prev.push(<FriendItem key={i} rank={i + 1} {...curr} />); 
    } 

    return prev; 
    }, []); 
    return result.length > 0 ? result : emptyResult
    (!!myFriends.length, query); 
    }; 

    const FriendList = (props) => ( 
      <div className={classes.wrapper}> 
        {renderFriends(props)} 
      </div> 
    ); 

    FriendList.propTypes = { 
      myFriends: PropTypes.array.isRequired, 
      query: PropTypes.string 
    }; 

export default FriendList; 

```

如果您的账户有朋友，那么您将获得一个包括他们的个人资料图片、点赞、评论和帖子数量的完整朋友列表，因此您也可以通过 React 与 Facebook API 集成。

# 总结

我们已经探索了如何借助 React 集成 Facebook API，您也可以以类似的方式集成其他 API。

我们使用了常量、工具和扩展组件来实现集成并获得预期的输出。

本章中展示的关键示例将帮助您理解或澄清您对将其他 API 与 React 集成的概念。


# 第九章：React 与 Node.js

在之前的章节中，我们已经学习了关于 React 路由、Facebook API 的集成，以及如何配置和处理应用程序的 URL。我们还学习了如何根据 URL 在 DOM 中注册我们的组件。

在本章中，我们将使用 Node.js 构建我们现有的应用程序。我不打算在这里向您展示如何连接服务器和构建服务器端方面，因为这超出了本书的范围。但是，它包含在随书附带的代码文件中。本章我们将涵盖以下内容：

+   使用 npm 安装所有模块

+   运行编译器和预处理器

+   集成添加票务表单

+   提交表单并将其保存在本地存储中

+   存储和读取本地存储数据

+   运行开发 Web 服务器，文件监视器和浏览器重新加载

+   React 调试工具

到目前为止，我们的应用程序完全基于前端，而且它并没有模块化。当然，这意味着我们的应用程序代码看起来很混乱。我们还使用了 React 的每个依赖库的解包文件，浏览器必须去获取每个 JavaScript 文件并进行编译。

我们将不再需要手动连接和压缩，而是可以设置监视我们的文件进行更改并自动进行更改，比如`webpack`和`webpack-hot-middleware`。

让我们继续对我们的项目进行更改，不断重复这个过程将会很繁琐。

# 安装 Node 和 npm

首先，我们需要下载并安装 Node.js。如果您已经安装并配置了 Node，请随意跳过本节。我们可以从[`nodejs.org`](http://nodejs.org)下载 Node.js，并按照以下说明进行操作：

1.  从[`nodejs.org/`](http://nodejs.org/)下载适用于您操作系统的安装程序。Node.js 根据您的平台提供不同的安装程序。在本章中，我们将使用 Windows 安装程序来设置 Node。![安装 Node 和 npm](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_09_001.jpg)

1.  我们还可以从[`nodejs.org/en/download/releases/`](https://nodejs.org/en/download/releases/)下载以前的 Node 版本。在本章中，我们正在使用 Node.js 0.12 分支，所以请确保您正在下载这个版本。

1.  运行我们下载的安装程序和 MSI 文件。

安装向导将询问您要安装的功能选择，并且您可以选择您想要的功能。通常，我们选择默认安装：

![安装 Node 和 npm](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_09_002.jpg)

1.  如果安装要求，然后重新启动您的计算机。

系统重新启动后，我们可以检查 Node.js 是否设置正确。

打开命令提示符并运行以下命令：

```jsx
**node --version // will result something like v0.12.10**
```

您应该能够看到版本信息，这可以确保安装成功。

## React 应用程序设置

首先，我们需要为我们的项目创建一个`package.json`文件，其中包括 npm 模块的项目信息和依赖项。npm 对于 JavaScript 开发人员来说非常有用，可以创建和共享他们创建的可重用代码，以构建应用程序并在开发过程中解决特定问题。

现在，打开命令提示符/控制台并导航到您创建的目录。运行以下命令：

```jsx
**Npm init**
```

此命令将初始化我们的应用程序并询问若干问题以创建名为`package.json`的 JSON 文件。该实用程序将询问有关项目名称、描述、入口点、版本、作者名称、依赖项、许可信息等的问题。一旦命令执行，它将在项目的根目录中生成一个`package.json`文件。

```jsx
{ 
    "name": "react-node", 
    "version": "1.0.0", 
    "description": "ReactJS Project with Nodejs", 
    "scripts": { 
        "start": "node server.js", 
        "lint": "eslint src" 
    }, 
    "author": "Harmeet Singh <harmeetsingh090@gmail.com>", 
    "license": "MIT", 
    "bugs": { 
        "url": "" 
    }, 

```

在上述代码中，您可以看到应用程序的`name`，应用程序的入口点（`start`），应用程序的`version`和应用程序的`description`。

## 安装模块

现在我们需要安装一些 Node 模块，这些模块将帮助我们构建一个带有 Node 的 React 应用程序。我们将使用 Babel、React、React-DOM、Router、Express 等。

以下是通过`npm`安装模块的命令：

```jsx
**npm install <package name> --save**
```

当我们使用`<package name>`运行上述命令时，它将在您的`project folder/node_modules`中安装包并将`package name/version`保存在您的`package.json`中，这将帮助我们在任何系统中安装所有项目依赖项并更新模块。

如果您已经有了带有项目依赖项的`package.json`文件，那么您只需要运行以下命令：

```jsx
**npm install**
```

更新我们需要运行以下命令：

```jsx
**npm update**
```

以下是我们应用程序中具有依赖项的模块列表：

```jsx
"devDependencies": { 
    "babel-core": "⁶.0.20", 
    "babel-eslint": "⁴.1.3", 
    "babel-loader": "⁶.0.1", 
    "babel-preset-es2015": "⁶.0.15", 
    "babel-preset-react": "⁶.0.15", 
    "babel-preset-stage-0": "⁶.0.15", 
    "body-parser": "¹.15.2", 
    "eslint": "¹.10.3", 
    "eslint-plugin-react": "³.6.2", 
    "express": "⁴.13.4", 
    "react-hot-loader": "¹.3.0", 
    "webpack": "¹.12.2", 
    "webpack-dev-middleware": "¹.6.1", 
    "webpack-hot-middleware": "².10.0" 
    }, 
    "dependencies": { 
        "mongodb": "².2.11", 
        "mongoose": "⁴.6.8", 
        "react": "⁰.14.6", 
        "react-dom": "⁰.14.6", 
        "react-router": "¹.0.0-rc1", 
        "style-loader": "⁰.13.1", 
        "url-loader": "⁰.5.7", 
        "css-loader": "⁰.26.0",a 
        "file-loader": "⁰.9.0" 
    } 

```

在上述`dependencies`列表中可能有一些您没有听说过或对您来说是新的模块。好的，让我解释一下：

+   `mongoose`和`mongodb`：这些在应用程序或 MongoDB 中作为中间件工作。安装 MongoDB 和 mongoose 对您来说是可选的，因为我们在应用程序中没有使用它们。我只是为了您的参考而添加了它们。

+   `nodemon`：在 Node.js 应用程序中进行开发时，`nodemon`将监视目录中的文件，如果有任何文件更改，它将自动重新启动您的节点应用程序。

+   `react-hot-loader`：这是 Web 开发中最常用的模块，用于实时代码编辑和项目重新加载。`react-hot-loader`本身对其他模块有一些依赖：

+   `webpack`

+   `webpack-hot-middleware`

+   `webpack-dev-middleware`

+   `webpack-hot-middleware`：这允许您在不使用`webpack-dev-server`的情况下将热重载添加到现有服务器中。它将浏览器客户端连接到 webpack 服务器以接收更新，并订阅来自服务器的更改。然后使用 webpack 的**热模块替换**（**HMR**）API 执行这些更改。

+   `webpack-dev-middleware`：这是 webpack 的包装器，并在连接的服务器上提供从 webpack 发出的文件。在开发过程中具有以下优势：

+   文件不会写入磁盘，而是在内存中处理。

+   在开发过程中，如果在监视模式下更改了文件，则不会提供旧的包，而是在编译完成之前请求会延迟。在文件修改后，我们不需要进行页面刷新。

### 注意

`webpack-dev-middlware`仅在开发中使用。请不要在生产中使用它。

`style-loader`、`url-loader`、`css-loader`和`file-loader`有助于加载静态路径、CSS 和文件。

例如：`import '../vendor/css/bootstrap.min.css'`，其中包括字体 URL 和图像路径。

设置`package.json`文件后，我们的 HTML 标记如下所示，命名为`index.html`：

```jsx
<!doctype html> 
<html>
    <head>
        <title>React Application - EIS</title>
        <script src="//ajax.googleapis.com/ajax/libs/jquery/
        1.11.1/jquery.min.js"></script> 
    </head>
    <body>
        <div id='root'> 
        </div>
        <script src="/static/bundle.js"></script> 
    </body>
</html> 

```

现在我们需要在`server.js`中创建一个服务器来运行我们的应用程序：

```jsx
var path = require('path'); 
var webpack = require('webpack'); 
var express = require('express'); 
var config = require('./webpack.config'); 
var app = express(); 
var compiler = webpack(config); 

app.use(require('webpack-dev-middleware')(compiler, { 
    publicPath: config.output.publicPath 
})); 
app.use(require('webpack-hot-middleware')(compiler));
```

在上述代码中，我们正在配置我们应用程序中的`webpack`。它连接到服务器并接收更新通知以重新构建客户端包：

```jsx
app.get('*', function(req, res) { 
    res.sendFile(path.join(__dirname, 'index.html')); 
}); 

app.listen(3000, function(err) { 
    if (err) { 
        return console.error(err); 
    } console.log('Listening at http://localhost:3000/'); 
}) 

```

在上述代码中，我们正在发送一个 HTML 文件并启动服务器。您可以根据需要更改端口号。

现在让我们来看一下`webpack.config.js`，我们刚刚在`server.js`文件的顶部包含了它。

```jsx
module.exports = { 
    devtool: 'cheap-module-eval-source-map', 
    entry: [ 
        'webpack-hot-middleware/client', 
        './src/index' 
    ], 
    output: { 
        path: path.join(__dirname, 'dist'), 
        filename: 'bundle.js', 
        publicPath: '/static/' 
    }, 
    plugins: [ 
        new webpack.HotModuleReplacementPlugin() 
    ], 

```

在上述代码中，我们正在设置`webpack-hot-middleware`插件并添加我们脚本的入口点来编译和运行：

```jsx
module: { 
    loaders: [{ 
        test: /\.js$/, 
        loaders: ['react-hot', 'babel'], 
        include: path.join(__dirname, 'src') 
    }, 
    { 
        test: /\.css$/, 
        loader: 'style!css', 
        exclude: /node_modules/ 
        }, { 
            test: /\.(woff|woff2|ttf|svg)$/, 
            loader: 'url?limit=100000', 
            exclude: /node_modules/ 
        }, 
        { 
            test: /\.(eot|png)$/, 
            loader: 'file', 
            exclude: /node_modules/ 
        } 
        ] 
    } 
}; 

```

在这里，我们根据应用程序中匹配的文件加载模块。

我们还需要配置 Babel，包括 ECMAScript 版本和`eslint`，以添加一些规则、插件信息等。

`.babelrc`文件包括：

```jsx
{ 
    "presets": ["es2015", "stage-0", "react"] 
} 

```

`.eslintrc`文件包括：

```jsx
{ 
    "ecmaFeatures": { 
        "jsx": true, 
        "modules": true 
    }, 
    "env": { 
        "browser": true, 
        "node": true 
    }, 
    "parser": "babel-eslint", 
    "rules": { 
        "quotes": [2, "single"], 
        "strict": [2, "never"], 
        "react/jsx-uses-react": 2, 
        "react/jsx-uses-vars": 2, 
        "react/react-in-jsx-scope": 2 
    }, 
    "plugins": [ 
        "react" 
    ] 
}
```

请查看以下屏幕截图：

![安装模块](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_09_003.jpg)

上述屏幕截图显示了我们的根目录的文件夹结构。在`src`目录中，我们有所有的脚本，在 vendor 文件夹中，我们有 Bootstrap 字体和 CSS。

# 使用 React 和 Node 创建响应式 Bootstrap 应用程序

我们将包含并模块化我们迄今为止开发的 Bootstrap 应用程序。在这个应用程序中，我们可以看到静态用户配置文件在线提出帮助台工单，并在服务器端渲染 React 组件。我们没有使用任何数据库，所以我们将我们的工单存储在浏览器的本地存储中。我们可以在查看工单中看到工单的提交。

供您参考，我已经在代码片段中包含了 Mongodb 配置和与 db 的连接设置，您可以随本书一起获取。此外，我还包含了 Add Ticket Form 的 mongoose 模式，这样您就可以使用它们。

首先，让我们打开`src`文件夹中脚本文件`index.js`的入口点，并`import` React 模块。

```jsx
import React from 'react'; 
import ReactDOM from 'react-dom'; 
import { Router, Route, Link, IndexRoute,IndexLink, browserHistory } 
from 'react-router' 

```

在版本 15.4.0 中，`React`和`ReactDOM`被分成不同的包。在 React 0.14 中，`React.render()`已被弃用，推荐使用`ReactDOM.render()`，开发人员还完全从 React 中删除了特定于 DOM 的 API。

在 React 15.4.0 中，他们最终将 ReactDOM 实现移动到了 ReactDOM 包中。React 包现在将只包含与渲染器无关的代码，如`React.Component`和`React.createElement()`。

访问此博客获取有关 React 的最新更新：

[`facebook.github.io/react/blog/`](https://facebook.github.io/react/blog/)

现在我们需要导入 Bootstrap、CSS 和 JS 文件：

```jsx
import '../css/custom.css'; 
import '../vendor/css/base.css'; 
import '../vendor/css/bootstrap.min.css'; 
import '../vendor/js/bootstrap.min.js'; 

```

现在让我们用以下命令启动服务器，看看我们的代码和配置是否能够构建：

```jsx
**nodemon start**
```

它监视应用程序文件的更改并重新启动服务器。

或者如果我们没有安装`nodemon`，那么命令应该是：

```jsx
**node server.js**
```

![使用 React 和 Node 创建响应式 Bootstrap 应用程序](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/B05743_09_03-1.jpg)

服务器在 webpack 中启动，将您的代码捆绑到服务器客户端浏览器。如果一切顺利，当构建完成时，您可以获得以下信息：

![使用 React 和 Node 创建响应式 Bootstrap 应用程序](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_09_005.jpg)

目前我们的页面是空白的。因为我们还没有在页面中包含任何组件，所以没有任何内容可显示。

让我们在组件文件夹中创建一个名为`navbar.js`的 Bootstrap 导航组件。

```jsx
module.exports.PageLayout = React.createClass({ 
}) 

```

`module.exports`是 Node.js 中的一个特殊对象，并且在每个 JS 文件中都包含它。它将您在`module.exports`中编写的函数、变量和任何内容公开为一个模块，使您的代码可重用且易于共享。

让我们在其中添加我们的 Bootstrap 导航组件，使用“容器”布局来呈现页面内容：

```jsx
render: function() { 
    return ( 
        <main> 
        <div className="navbar navbar-default navbar-static-top"
        role="navigation"> 
            <div className="container"> 
                <div className="navbar-header"> 
                    <button type="button" className="navbar-toggle"
                    data-toggle="collapse" data-target=".navbar-collapse"> 
                    <span className="sr-only">Toggle navigation</span> 
                    <span className="icon-bar"></span> 
                    <span className="icon-bar"></span> 
                    <span className="icon-bar"></span> 
                    </button> 
                    <Link className="navbar-brand" to="/">EIS</Link> 
                </div> 
            <div className="navbar-collapse collapse"> 
            <ul className="nav navbar-nav"> 
            <li><IndexLink activeClassName="active" to="/">
            Home</IndexLink></li> 
            <li><Link to="/edit" activeClassName="active">
            Edit Profile</Link></li> 
            <li className="dropdown"> 
                <Link to="#" className="dropdown-toggle"
                data-toggle="dropdown">Help Desk <b className="caret">
                </b></Link> 
            <ul className="dropdown-menu"> 
            <li><Link to="/alltickets">View Tickets</Link></li> 
            <li><Link to="/newticket">New Ticket</Link></li> 
            </ul> 
            </li> 
            </ul> 
        </div> 
    </div> 
</div> 

```

我们的页面导航“容器”到此结束。

在这里，我们开始了页面的主要“容器”，我们可以使用`props`来渲染页面内容：

```jsx
<div className="container"> 
    <h1>Welcome to EIS</h1> 
    <hr/> 
    <div className="row"> 
    <div className="col-md-12 col-lg-12"> 
    **{this.props.children}** 
    </div> 
    </div> 
    </div> 
</main> 
); 
}  

```

让我们继续添加主页内容并准备我们的第一个布局：

```jsx
const RightSection = React.createClass({ 
    render: function() { 
        return (<div className="col-sm-9 profile-desc" id="main">  
        <div className="results">  
        <PageTitle/> 
        <HomePageContent/> 
        </div> 
        </div>) 
    } 
}) 
// include Left section content in ColumnLeft component with the wrapper of bootstrap responsive classes classes    

const ColumnLeft = React.createClass({ 
    render: function() { 
        return ( 
        ) 
    } 
}) 
const LeftSection = React.createClass({ 
    render: function() { 
        return (  
        //Left section content          
        ) 
    } 
}) 
const TwoColumnLayout = React.createClass({ 
    render: function() { 
        return ( 
            <div> 
            <ColumnLeft/> 
            <RightSection/> 
            </div> 
        ) 
    } 
})  

```

在这里，我们在这个组件中包含了页面标题和主页内容：

```jsx
const PageTitle = React.createClass({ 
    render: function() { 
        return ( 
            <h2>//page content</h2> 
        ); 
    } 
}); 
const HomePageContent = React.createClass({ 
    render: function() { 
        return ( 
            <p>//page content</p> 
        ); 
    } 
}); 

```

现在我们需要配置路由以在 UI 中呈现组件：

```jsx
ReactDOM.render(( 
    <Router history={browserHistory}> 
    <Route path="/" component={PageLayout}> 
    <IndexRoute component={TwoColumnLayout}/> 
    </Route> 
    </Router> 
), document.getElementById('root')); 

```

我们需要重复与其他组件和页面相同的流程：

![使用 React 和 Node 创建响应式 Bootstrap 应用程序](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_09_006.jpg)

我们的页面看起来很棒；我们已成功将我们的第一个页面与 Node.js 集成。

让我们转到我们的主要组件，并在帮助台部分添加一个工单。

创建一个名为`addTicketForm.js`的文件，并包含以下代码：

```jsx
import React from 'react'; 
import ReactDOM from 'react-dom'; 

```

在每个包含 React 代码的文件中包含 React 模块是很重要的：

```jsx
var max_Char='140'; 
var style = {color: "#ffaaaa"}; 

module.exports.AddTicket = React.createClass({ 
    getInitialState: function() { 
        return {value: '', char_Left: max_Char}; 
    }, 
    handleChange: function(event) { 
        var input = event.target.value; 
        this.setState({value: input.substr(0, max_Char),char_Left:
        max_Char - input.length}); 
        if (input.length == max_Char){ 
            alert("You have reached the max limit") 
        } 
    }, 

```

### 提示

在上述代码中，我们使用与我们在第五章中创建的相同代码来控制`textarea`组件，*使用 React 的 jQuery Bootstrap 组件*。

```jsx
handleSubmitEvent: function (event) { 
    event.preventDefault(); 

var values   = { 
    date: new Date(), 
    email: this.refs.email.value.trim(), 
    issueType: this.refs.issueType.value, 
    department: this.refs.department.value, 
    comment: this.state.value 
}; 
this.props.addTicketList(values); 
localStorage.setItem('Ticket', JSON.stringify(values)); 
}, 

```

之前我们只是在提交表单后在`AddTicket`UI 中显示。现在我们使用本地存储来保存工单。

```jsx
render: function() { 
    return ( 
        <form onSubmit={this.handleSubmitEvent}> 

```

在这里，您需要放入我们之前添加的其他表单元素：

```jsx
<div className="form-group"> 
    <label htmlFor="comments">Comments <span style={style}>*</span>
    </label>(<span>{this.state.char_Left}</span> characters left) 
        <textarea className="form-control" value={this.state.value} 
        maxLength={max_Char} ref="comments" onChange={this.handleChange} /> 
   </div> 
   <div className="btn-group"> 
       <button type="submit" className="btn btn-primary">Submit</button> 
       <button type="reset" className="btn btn-link">cancel</button> 
   </div> 
   </form> 
   ); 
} 
}); 

```

接下来，我们需要创建`addTicketList.js`，在这里我们将这个 JSX 表单包装成组件：

```jsx
<AddTicket addTicketList={this.addTicketList} /> 

```

还需要创建`listView.js`来显示用户提交后的列表：

```jsx
import { AddTicket } from "./addTicketForm.js";
import { List } from "./listView.js";
```

在这里，我们导入了之前创建的`AddTicket`模块，并创建了另一个模块`addTicketForm`来管理更新的表单状态：

```jsx
module.exports.AddTicketsForm = React.createClass({ 
    getInitialState: function () { 
        return { 
            list: {} 
        }; 
    }, 
    updateList: function (newList) { 
        this.setState({ 
            list: newList 
        }); 
    }, 
    addTicketList: function (item) { 
    var list = this.state.list; 
    list[item] = item; 
    this.updateList(list); 
    }, 
    render: function () { 
        var items = this.state.list; 
    return ( 
        <div className="container"> 
        <div className="row"> 
        <div className="col-sm-6"> 
            <List items={items} /> 
            <AddTicket addTicketList={this.addTicketList} /> 
        </div> 
        </div> 
        </div> 
    ); 

```

在`render`方法中，我们将表单和`list`项传递给组件：

```jsx
    } 
}); 
listView.js 
import { ListPanel } from "./ListUI.js"; 

```

在`ListPanel`中，我们有实际的 JSX 代码，用于在用户提交并创建我们在`addTicketList.js`中包含的模块后将票据呈现到 UI 中：

```jsx
module.exports.List = React.createClass({ 
    getListOfIds: function (items) { 
    return Object.keys(items); 
    }, 
    createListElements: function (items) { 
        var item; 
        return ( 
            this 
                .getListOfIds(items) 
                .map(function createListItemElement(itemId,id) { 
                    item = items[itemId]; 
                    return (<ListPanel key={id} item={item} />); 
                    }.bind(this)) 
               .reverse() 
        ); 
    }, 
    render: function () { 
        var items = this.props.items; 
        var listItemElements = this.createListElements(items); 
        return ( 
            <div className={listItemElements.length > 0 ? "":""}> 
            {listItemElements.length > 0 ? listItemElements : ""} 

```

在这里，我们将`listItemElements`呈现到 DOM 中：

```jsx
        </div> 
    ); 
    } 
}); 

```

现在让我们创建`ListUI.js`，最后一个模块，它将完成表单组件的功能：

```jsx
module.exports.ListPanel =  
React.createClass({ 
    render: function () { 
        var item = this.props.item; 
    return ( 
        <div className="panel panel-default"> 
        <div className="panel-body"> 
        Emailid: {item.email}<br/> 
        IssueType: {item.issueType}<br/> 
        IssueType: {item.department}<br/> 
        Message: {item.comment} 
        </div> 
        <div className="panel-footer"> 
       {item.date.toString()} 
       </div> 
       </div> 
    ); 
    } 
}); 

```

让我们看看浏览器中的输出是什么样子的。

确保你已经在你的路由器中包含了以下代码：

```jsx
<Route path="/newticket" component={AddTicketsForm} />
```

观察以下截图：

![使用 React 和 Node 的响应式 Bootstrap 应用程序](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_09_007.jpg)

看起来不错。现在让我们填写这个表单，提交它，然后查看输出：

![使用 React 和 Node 的响应式 Bootstrap 应用程序](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_09_008.jpg)

太棒了；我们的表单按预期工作。

你还可以在浏览器的本地存储中看到以 JSON 表示格式的提交**Ticket**的**Key**和**Value**：

**开发者工具** > **应用程序** > **存储** > **本地存储**

观察以下截图：

![使用 React 和 Node 的响应式 Bootstrap 应用程序](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_09_009.jpg)

现在我们需要从本地存储中获取这个 JSON **Ticket**并在**查看票据**部分向用户显示。

让我们创建另一个模块来获取票据并将其呈现到 Bootstrap 响应式表格中。文件

`allTickets.js`将如下所示：

```jsx
module.exports.allTickets = React.createClass({ 
    getInitialState: function() { 
        return { 
            value :JSON.parse(localStorage.getItem( 'Ticket' )) || 1}; 
        }, 

```

在组件的初始状态中，我们使用`localStorage.getItem`来获取`tickets`并将它们解析为 JSON 来设置状态：

```jsx
getListOfIds: function (tickets) { 
    return Object.keys(tickets); 
    }, 
    createListElements: function (tickets) { 
    var ticket; 
    return ( 
        this 
        .getListOfIds(tickets) 
        .map(function createListItemElement(ticket,id) { 
        ticket = tickets[ticket]; 
        return (<ticketTable key={id} ticket={ticket}/>) 
        }.bind(this)) 
    ); 
}, 

```

使用我们在添加票据时使用的相同方法，我们通过`props`将`ticket key`和值映射到 React 组件中：

```jsx
render: function() { 
    var ticket = this.state.value;
```

在`render`方法中，我们将`state`的值赋给了我们传递到`createListElements`函数中的`ticket`变量：

```jsx
var listItemElements = this.createListElements(ticket); 
return ( 
    <div> 
        <div className={listItemElements.length > 0 ? "":"bg-info"}> 
            {listItemElements.length > 0 ? "" : "You have not raised any ticket yet."} 

```

我们正在使用 JavaScript 三元运算符来检查是否有任何`ticket`，如果没有，则在 UI 中显示消息。

```jsx
</div> 
    <table className="table table-striped table-responsive"> 
        <thead> 
            <tr> 
                <th>Date</th> 
                <th>Email ID</th> 
                <th>Issue Type</th> 
                <th>Department</th> 
                <th>Message</th> 
            </tr> 
        </thead> 
        <tbody> 
        <tr> 
            {listItemElements.length > 0 ? listItemElements : ""} 
        </tr> 
        </tbody> 
    </table> 
</div> 
// In the preceding code, we are creating the table header and appending the ticket list items.
   ); 
   } 
}); 

```

现在我们需要创建包含`<td>`并继承`ticket`数据的组件。`ticketTable.js`将如下所示：

```jsx
module.exports.ticketTable = React.createClass({ 
    render: function () { 
        var ticket = this.props.ticket; 
        return ( 
            <td>{ticket}</td> 
        ); 
    } 
}); 

```

我们还需要在`allTickets.js`文件中导入此模块：

```jsx
const table = require("./ticketTable.js"); 

```

你可能会注意到我使用了`const`对象，而不是使用`import`。你也可以使用`var`。`const`指的是常量；它们是块作用域的，就像变量一样。常量的值不能改变和重新赋值，也不能重新声明。

例如：

```jsx
const MY_CONST = 10; 
// This will throw an error because we have reassigned again. 
MY_CONST = 20; 

// will print 10 
console.log("my favorite number is: " + MY_CONST); 

// const also works on objects 
const MY_OBJECT = {"key": "value"};  

```

这是我们最终的路由器配置：

```jsx
ReactDOM.render(( 
    <Router history={browserHistory}> 
    <Route path="/" component={PageLayout}> 
    <IndexRoute component={TwoColumnLayout}/> 
    <Route path="/profile" component={Profile} /> 
    <Route path="/alltickets" component={allTickets} /> 
    <Route path="/newticket" component={AddTicketsForm} /> 
    </Route> 
    <Route path="*" component={NoMatch}/> 
    </Router> 
), document.getElementById('root')); 

```

## Bootstrap 表格

让我们看看以下要点：

+   **斑马纹行**：在`<table class="table table-striped">`中使用`.table-striped`来为表格行添加斑马纹

+   **带边框的表格**：添加`.table-bordered`以在整个表格和单元格中添加边框

+   **悬停行**：添加`.table-hover`以在表格行上启用悬停状态

+   **紧凑表格**：添加`.table-condensed`以减少单元格填充

+   **上下文类**：使用上下文类（`.active`、`.success`、`.info`、`.warning`、`.danger`）为表格行或单元格添加背景颜色

在表格上应用这些类，看看它们如何影响表格的外观和感觉。

### Bootstrap 响应式表格

在创建响应式表格时，我们需要将任何`.table`包装在`.table-responsive`中，以便在小设备上（小于 768 像素）水平滚动。当我们在大于 768 像素宽的任何设备上查看它们时，你将不会看到这些表格有任何区别。

让我们再次提交票证并快速查看表格。

转到导航中的帮助台下拉菜单，点击查看票证。

![Bootstrap 响应式表格](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_09_010.jpg)

如果你还没有提出任何票证，你将在 UI 中收到适当的消息（**你还没有提出任何票证。**）。

好的，让我们提交新的票证并再次打开这个页面。一旦票证被添加，它将显示在你的表格中：

![Bootstrap 响应式表格](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_09_012.jpg)

我们现在可以在表格中看到我们提交的票证。

# React 开发者工具

React 为开发者提供了调试 React 代码的工具。它允许我们检查一个由 React 渲染的组件，包括组件层次结构、props 和状态。

## 安装

有两个官方扩展可用于 Chrome 和 Firefox 浏览器。

为 Chrome 下载扩展：

[`chrome.google.com/webstore/detail/react-developer-tools/fmkadmapgofadopljbjfkapdkoienihi?hl=en`](https://chrome.google.com/webstore/detail/react-developer-tools/fmkadmapgofadopljbjfkapdkoienihi?hl=en)

和 Firefox：

[`addons.mozilla.org/en-US/firefox/addon/react-devtools/`](https://addons.mozilla.org/en-US/firefox/addon/react-devtools/)

### 注意

一个独立的应用程序仍在开发中，很快将可用。

## 如何使用

一旦你在浏览器中下载或安装了扩展，打开 React 页面上的**开发者工具**。你应该会看到一个名为**React**的额外选项卡：

![如何使用](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_09_013.jpg)

在侧面板中，您可以看到每个 React 组件的**State**和**Props**。如果展开组件的**State**，您将看到组件的完整层次结构，其中包括您在 React 应用程序中使用的组件的名称。

请参阅以下屏幕截图：

![如何使用](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_09_014.jpg)

右键单击侧面板，我们可以检查和编辑右侧面板中当前 props 和 state。

我们还可以通过单击**执行函数**来查看代码执行函数：

![如何使用](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_09_015.jpg)

如果您使用 React 工具检查`allTicket`组件，您可以看到`props`流入子元素的数据流：

![如何使用](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_09_016.jpg)

如果您在**元素**选项卡上检查页面中的 React 元素，然后切换到**React**选项卡，该元素将自动在 React 树中被选中。使用搜索选项卡，我们也可以按名称搜索组件。

如果您还需要跟踪组件的更新，您需要选择顶部复选框**跟踪 React 更新**。

# 总结

在本章中，您学习了如何将我们的 React 独立应用程序转换为 Node.js npm 包，并将 React 组件模块化。我们首先安装了 Node.js 并设置了 React 环境。然后，我们看了如何使用`module.export`导入和导出模块。

我们还学习了如何在一个文件中创建和导入多个模块，例如`react-router`，`{ Router, Route, IndexRoute,IndexLink, Link, browserHistory } = ReactRouter`。

我们还看了如何从本地存储中存储和读取数据。使用 Bootstrap 表格，我们将数据显示在表格网格中。我们还学习了 Bootstrap 表格，样式类可以使您的表格响应，并且看起来更好。


# 第十章：最佳实践

在深入探讨处理 React 时应遵循的最佳实践之前，让我们回顾一下我们在之前章节中所看到的内容。

我们已经涵盖了以下关键点：

+   什么是 ReactJS

+   我们如何使用 React-Bootstrap 和 ReactJS 构建响应式主题

+   与 React 的 DOM 交互

+   ReactJS-JSX

+   React-Bootstrap 组件集成

+   Redux 架构

+   使用 React 进行路由

+   React API 与其他 API 集成

+   与 Node.js 一起使用 React

通过前面的主题，你应该对 ReactJS、响应式主题、自定义组件、JSX、Redux、Flux 以及与其他 API 的集成有了更清晰的理解。希望你喜欢这个旅程。现在我们知道从哪里开始以及如何编写代码，但了解如何遵循最佳实践编写标准代码也很重要。

2015 年，全球范围内有许多关于 React 的新发布和会议，现在我看到很多人在问我们如何在 React 中编写标准代码？

每个人对遵循最佳实践都有自己的看法。到目前为止，我已经与你分享了一些观察和经验，但你可能有不同的看法。

如果你想了解更详细的内容，你可以随时访问 React 的官方网站和教程。

# 在 React 中处理数据

每当我们有具有动态功能的组件时，数据就会出现。同样适用于 React；我们必须处理动态数据，这似乎很容易，但并非总是如此。

听起来有点混乱！

为什么它既容易又困难？因为在 React 组件中，传递属性很容易，构建渲染树的方式有很多，但关于更新视图的清晰度并不多。

2015 年，我们看到了许多 Flux 库，随之而来的是许多功能性和反应性解决方案的发布。

## 使用 Flux

根据我的经验，许多人对 Flux 存在误解，认为它是不必要的。他们使用它是因为他们对它有很好的掌握。

在我们的例子中，我们已经看到 Flux 有一种清晰的方式来存储和更新应用程序的状态，当需要时，它会触发渲染。

我们经常听到这句话：“*每个硬币都有两面*”。同样，Flux 也有利有弊。例如，为应用程序声明全局状态是有益的。假设你必须管理已登录的用户，并且正在定义路由器的状态和活动帐户的状态；当你开始使用 Flux 来管理临时或本地数据时，这将是痛苦的。

从我的角度来看，我不建议仅仅为了管理`/items/:itemIdroute`相关数据而使用 Flux。相反，你可以在你的组件中声明它并将其存储在那里。这有什么好处？答案是，它将依赖于你的组件，所以当你的组件不存在时，它也将不存在。

例如：

```jsx
export default function users(state = initialState, action) { 
    switch (action.type) { 
        case types.ADD_USER: 
            constnewId = state.users[state.users.length-1] + 1; 
            return { 
                ...state, 
                users: state.users.concat(newId), 
                usersById: { 
                    ...state.usersById, 
                    [newId]: { 
                        id: newId, 
                        name: action.name 
                    } 
                }, 
            } 

            case types.DELETE_USER: 
            return { 
                ...state, 
                users: state.users.filter(id => id !== action.id), 
                usersById: omit(state.usersById, action.id) 
            }     

            default: 
            return state; 
    } 
} 

```

在前面基于 Redux 的 reducer 代码中，我们正在管理 reducers 的一部分作为应用程序的`state`。它存储先前的`state`和`action`，并返回下一个状态。

## 使用 Redux

我们知道，在单页应用程序中，当我们必须处理状态和时间时，难以掌握随时间变化的状态。在这里，Redux 非常有帮助。为什么？因为在 JavaScript 应用程序中，Redux 处理两种状态：一种是数据状态，另一种是 UI 状态，这是单页应用程序的标准选项。此外，请记住，Redux 可以与 AngularJS、jQuery 或 React JavaScript 库或框架一起使用。

## Redux 等于 Flux，真的吗？

Redux 是一个工具，而 Flux 只是一个模式，你不能通过即插即用或下载来使用它。我不否认 Redux 从 Flux 模式中获得了一些影响，但我们不能说它与 Flux 完全相似。

让我们继续看一些区别。

Redux 遵循三个指导原则，如下所示。我们还将介绍一些 Redux 和 Flux 之间的区别。

### 单存储方法

我们已经在之前的图表中看到，存储假装是应用程序中所有种类状态修改的*中间人*，而 Redux 通过存储控制两个组件之间的直接通信，具有单一通信点。

Redux 和 Flux 之间的区别在于：Flux 有多个存储方法，而 Redux 有单一存储方法。

### 只读状态

在 React 应用中，组件不能直接改变状态，而必须通过`actions`将更改分派到存储中。

在这里，`store`是一个对象，它有四种方法，如下所示：

+   `store.dispatch(action)`

+   `store.subscribe(listener)`

+   `store.getState()`

+   `replaceReducer(nextReducer)`

Reducer 函数用于改变状态

Reducer 函数将处理`dispatch`动作以改变`state`，因为 Redux 工具不允许两个组件直接通信；因此它也不会改变`state`，而是会描述`state`的改变。

这里的 Reducer 可以被视为纯函数，编写 Reducer 函数的一些特点如下：

+   没有外部数据库或网络调用

+   根据其参数返回值

+   参数是*不可变的*

+   相同的参数返回相同的值

Reducer 函数被称为纯函数，因为它们除了根据其设置的参数返回值之外什么都不做；它们没有任何其他后果。

在 Flux 或 Redux 架构中，总是很难处理 API 返回的嵌套资源，因此建议在组件中使用`normalize`等平面状态。

专业提示：

```jsx
const data = normalize(response,arrayOf(schema.user)) 
state= _.merge(state,data.entities) 

```

## 不可变的 React 状态

在平面状态下，我们可以处理嵌套资源和`不可变`对象的好处，以及声明状态不可修改的好处。

`不可变`对象的另一个好处是，通过它们的引用级别相等检查，我们可以大大改善渲染性能。例如，使用`不可变`对象有`shouldComponentUpdate`：

```jsx
shouldComponentUpdate(nexProps){ 
    // instead of object deep comparsion 
    returnthis.props.immutableFoo!==nexProps.immutableFoo 
} 

```

在 JavaScript 中，使用**不可变深冻结**节点将帮助您在变异之前冻结节点，然后验证结果。以下代码示例显示了相同的逻辑：

```jsx
return{ 
    ...state, 
    foo 
} 

return arr1.concat(arr2) 

```

我希望前面的例子已经阐明了 Immutable.js 及其好处。它也有简单的方法，但并没有被广泛使用：

```jsx
import{fromJS} from 'immutable' 

const state =fromJS({ bar:'biz'}) 
constnewState=foo.set('bar','baz')  

```

在我看来，这是一个非常快速和美丽的功能。

## 可观察和响应式解决方案

我经常听到人们询问 Flux 和 Redux 的替代方案，因为他们想要更多的响应式解决方案。您可以在以下列表中找到一些替代方案：

+   **Cycle.js**：这是一个功能性和响应式的 JavaScript 框架，用于编写更干净的代码。

+   **.rx-flux**：这是带有附加功能 RxJS 的 flux 架构。

+   **redux-rx**：这是用于 Redux 的 RxJS 实用程序。

+   **Mobservable**：这带有三种不同的风味--可观察数据，响应式函数和简单代码。

# React 路由

我们必须在客户端应用程序中使用路由。对于 ReactJS，我们还需要另一个路由库，因此我建议您使用由 React 社区提供的`react-router`。

React 路由的优势包括：

+   在标准化结构中查看声明有助于我们立即识别我们的应用程序视图

+   延迟加载代码

+   使用`react-router`，我们可以轻松处理嵌套视图及其渐进式视图分辨率

+   使用浏览历史功能，用户可以向后/向前导航并恢复视图的状态

+   动态路由匹配

+   导航时的 CSS 过渡

+   标准化的应用程序结构和行为，在团队合作时非常有用

### 注意

React 路由器不提供处理数据获取的任何方法。我们需要使用`async-props`或其他 React 数据获取机制。

## React 如何帮助将您的代码拆分成延迟加载

很少有处理**webpack 模块打包程序**的开发人员知道如何将应用程序代码拆分为多个 JavaScript 文件：

```jsx
require.ensure([],()=>{ 
    const Profile = require('./Profile.js') 
    this.setState({ 
        currentComponent: Profile 
    }) 
}) 

```

为什么需要拆分代码是因为每个代码块并不总是对每个用户有用，并且不需要在每个页面上加载它；这会使浏览器过载。因此，为了避免这种情况，我们应该将应用程序拆分为多个代码块。

现在，您可能会有以下问题：如果我们有更多的代码块，那么我们是否需要更多的 HTTP 请求，这也会影响性能？借助 HTTP/2 多路复用（[`http2.github.io/faq/#why-is-http2-multiplexed`](https://http2.github.io/faq/#why-is-http2-multiplexed)），您的问题将得到解决。观察以下图表：

![React 如何帮助将您的代码拆分成延迟加载](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/B05743_10_07-1.jpg)

访问[`stackoverflow.com/questions/10480122/difference-between-http-pipeling-and-http-multiplexing-with-spdy`](http://stackoverflow.com/questions/10480122/difference-between-http-pipeling-and-http-multiplexing-with-spdy) 获取更多信息。

您还可以将您的代码块与代码块哈希组合，这也将在您更改代码时优化您的浏览器缓存比率。

## JSX 组件

JSX 就是简单地说，只是 JavaScript 语法的扩展。如果您观察 JSX 的语法或结构，您会发现它与 XML 编码类似。

JSX 执行预处理步骤，将 XML 语法添加到 JavaScript 中。您当然可以在没有 JSX 的情况下使用 React，但 JSX 使 React 更加整洁和优雅。与 XML 类似，JSX 标签具有标签名称、属性和子元素。JSX 也类似于 XML，如果属性值被引号括起来，那个值就成为字符串。

XML 使用平衡的开放和关闭标记；JSX 类似地工作，并且有助于创建更易于阅读的大型树，而不是*函数调用*或*对象文字*。

在 React 中使用 JSX 的优势包括：

+   JSX 比 JavaScript 函数更容易理解

+   JSX 中的标记对设计师和团队的其他成员更加熟悉

+   您的标记变得更有语义，结构化和有意义

## 有多容易可视化？

正如我所说，结构和语法在 JSX 中非常容易可视化和注意到。与 JavaScript 相比，它们旨在在 JSX 格式中更清晰和可读。

以下简单的代码片段将给您一个更清晰的想法。让我们看一个简单的 JavaScript `render` 语法：

```jsx
render: function () { 
    returnReact.DOM.div({className:"divider"}, 
        "Label Text", 
        React.DOM.hr() 
    ); 
}  

```

让我们看一下以下 JSX 语法：

```jsx
render: function () { 
    return<div className="divider"> 
        Label Text<hr /> 
    </div>; 
} 

```

希望您非常清楚，对于已经熟悉 HTML 的非程序员来说，使用 JSX 比使用 JavaScript 要容易得多。

## 熟人或理解

在开发领域，有许多团队，如非开发人员，UI 开发人员和 UX 设计师熟悉 HTML，以及质量保证团队负责彻底测试产品。

JSX 是一种清晰而简洁地理解这种结构的好方法。

## 语义/结构化语法

到目前为止，我们已经看到 JSX 语法易于理解和可视化。背后有一个具有语义语法结构的重要原因。

JSX 很容易将您的 JavaScript 代码转换为更有语义，有意义和结构化的标记。这使您能够使用类似 HTML 的语法声明组件结构和信息，知道它将转换为简单的 JavaScript 函数。

React 概述了您在`React.DOM`命名空间中期望的所有 HTML 元素。好处是它还允许您在标记中使用自己编写的自定义组件。

请查看以下 HTML 简单标记，并查看 JSX 组件如何帮助您拥有语义标记：

```jsx
<div className="divider"> 
    <h2>Questions</h2><hr /> 
</div>

```

将此包装在`divider` React 复合组件中后，您可以轻松地像使用任何其他 HTML 元素一样使用它，并且具有更好语义标记的附加好处：

```jsx
<Divider> Questions </Divider> 

```

## 使用类

观察以下代码片段：

```jsx
classHelloMessage extends React.Component{
    render(){ 
        return<div>Hello {this.props.name}</div> 
    } 
}
```

您可能已经注意到，在前面的代码中，`React.Component`被用来代替`creatClass`。如果您使用其中任何一个都没有问题，但许多开发人员对此并不清楚，他们错误地同时使用两者。

## 使用 PropType

了解属性是必须的；它将使您能够更灵活地扩展组件并节省时间。请参考以下代码片段：

```jsx
MyComponent.propTypes={ 
    isLoading:PropTypes.bool.isRequired, 
    items:ImmutablePropTypes.listOf( 
        ImmutablePropTypes.contains({ 
            name:PropTypes.string.isRequired, 
        }) 
    ).isRequired 
} 

```

您还可以验证您的属性，就像我们可以使用 React `ImmutablePropTypes`验证 Immutable.js 的属性一样。

## 高阶组件的好处

观察以下代码片段：

```jsx
PassData({ foo:'bar'})(MyComponent) 

```

高阶组件只是原始组件的扩展版本。

使用它们的主要好处是我们可以在多种情况下使用它们，例如在身份验证或登录验证中：

```jsx
requireAuth({ role: 'admin' })(MyComponent)  

```

另一个好处是，通过高阶组件，您可以单独获取数据并设置逻辑，以简单的方式呈现视图。

## Redux 架构的好处

与其他框架相比，Redux 架构有更多的优点：

+   它可能没有其他副作用

+   正如我们所知，不需要绑定，因为组件不能直接交互

+   状态是全局管理的，因此出现管理不善的可能性较小

+   有时，对于中间件，管理其他副作用可能会很困难

从上述观点来看，Redux 架构非常强大，并且具有可重用性。

# 为您的应用程序定制 Bootstrap

在审查 React 的最佳实践时，我们怎么能忘记我们应用程序的外观和感觉呢？当我们谈论响应性和精美的组件时，只有一个名字会浮现在脑海中：Bootstrap。Bootstrap 为我们提供了一个魔法棒，可以在较少的努力下实现最佳效果，并节省金钱。

如今，响应性非常重要，或者我应该说，它是强制性的。在制作应用程序时，您应该在包中包含 Bootstrap，并且可以利用 Bootstrap 类、Bootstrap 网格和 Bootstrap 准备好的组件。此外，Bootstrap 的响应式主题也可用；有些是免费的，有些需要付费，但它们非常有用。以前，我们在 CSS 中编写媒体查询以实现响应性，但 Bootstrap 通过提供精美的现成功能，真正帮助我们节省了时间、精力和客户的金钱。

## Bootstrap 内容 - 排版

您可能已经注意到，在 Bootstrap 包中，Bootstrap 使用的是全球通用的 Helvetica 字体类型。因此，您不仅可以选择使用 Helvetica，还可以使用一些自定义字体，您可以在[`www.google.com/fonts`](https://www.google.com/fonts)找到。例如，如果我想要从 Google 库中选择**Lato**字体，那么我可以从那里选择字体，并在包中选择所需的字体，如下面的截图所示：

![Bootstrap 内容-排版](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_10_002.jpg)

现在的问题是：我如何在我的系统中使用这个字体？我应该下载它吗？或者有什么办法？有一个非常简单的方法，正如我们在前面的截图中看到的那样；同一个对话框框有一个名为**EMBED**的选项卡。

![Bootstrap 内容-排版](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_10_003.jpg)

当您点击它时，它会显示以下屏幕：

![Bootstrap 内容-排版](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_10_004.jpg)

如**@IMPORT**选项卡中所示，您可以从`@import url()`复制该行，并将其添加到您的`bootstrap.less`文件或`bootstrap.scss`文件的所有 CSS 顶部。然后您可以在应用程序中使用 Lato 字体系列。

此外，如果需要，您还可以自定义其他字体属性，例如字体大小、字体颜色和字体样式。

## Bootstrap 组件-导航栏

在任何应用程序中，导航流非常重要，Bootstrap 的`导航栏`为您提供了一种通过多种选项构建响应式导航的方式。您甚至可以通过定义其大小、颜色和类型来自定义它，如下面的代码所示：

```jsx
@navbar-default-bg: # 962D91; 

```

如前面的代码所示，我们可以根据期望的外观定义任何颜色，以符合我们的`导航栏`及其链接：

```jsx
@navbar-default-color: #008bd1;  
@navbar-default-link-color: #008bd1;  
@navbar-default-link-hover-color: # 962D91;  
@navbar-default-link-active-color: #008bd1; 

```

不仅适用于桌面，也适用于移动导航，您可以根据自己的需求自定义“导航栏默认”颜色设置：

```jsx
@navbar-default-toggle-hover-bg: darken(@navbar-default-bg, 10%);  
@navbar-default-toggle-icon-bar-bg: #008bd1;  
@navbar-default-toggle-border-color: #008bd1;

```

您甚至可以设置`导航栏`的`高度`和`边框`设置，如下面的代码所示：

```jsx
@navbar-height: 50px;  
@navbar-border-radius: 5px; 

```

## Bootstrap 组件-表单

表单非常常用于从用户那里获取数据，您可以使用表单元素并创建诸如查询表单、注册表单、登录表单、联系我们表单等组件。Bootstrap 还提供了`form`组件，其好处在于其响应式行为。它也是可定制的。

在 Bootstrap 包中有一些文件，您可以更改与表单相关的 CSS 并获得预期的输出。

例如，更改`input`字段的`border-radius` CSS 属性：

```jsx
@input-border-radius: 2px;

```

更改`input`字段的`border-focus`颜色：

```jsx
@input-border-focus: #002D64; 

```

我非常喜欢 Bootstrap 最新版本的一个特点，它为每个组件/元素都有单独的部分，就像 React 一样。例如，在混合中，您可以看到单独的文件，其中只有各自的 CSS 属性，因此它们易于理解、调试和更改。

表单控件（`.form-control`）是 Bootstrap`form`组件的一个美丽特性，您可以在以下代码中看到自定义更改是多么容易：

```jsx
.form-control-focus(@color: @input-border-focus) {  
    @color-rgba: rgba(red(@color), green(@color), blue(@color), .3);  
    &:focus {  
        border-color: @color;  
        outline: 1;  
        .box-shadow(~"inset 1px0 1px rgba(0,0,0,.055), 0 0 6px 
        @{color-rgba}");  
    }  
}  

```

在前面的示例中，我们已经看到了如何自定义边框颜色、轮廓和框阴影；如果您不想要框阴影，那么可以注释掉那一行代码，看看没有框阴影的输出，如以下代码所示：

```jsx
//.box-shadow(~"inset 1px 0 1px rgba(0,0,0,.055), 0 0 6px @{color-rgba}"); 

```

您可能已经注意到，我用`//`对代码进行了注释，这是我们通常在 JavaScript 中做的，但在这里也是有效的，我们还可以使用 CSS 标准注释`/* */`来注释一行代码或多行代码。

## Bootstrap 组件 - 按钮

Bootstrap 组件还有一个名为`button`的现成组件，因此无论我们在应用程序中组合什么按钮，都可以使用 Bootstrap 类来增强它。Bootstrap 的`button`组件具有不同的大小、颜色和状态，可以根据您的要求进行自定义：

![Bootstrap 组件 - 按钮](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_10_005.jpg)

我们还可以通过使用 Bootstrap 的按钮类来实现类似的外观和感觉，如下所定义：

```jsx
.btn-default 
.btn-primary 
.btn-success 
.btn-info 
.btn-warning 
.btn-danger 
.btn-link 

```

在编写按钮的 HTML 代码时，您可以在应用程序的`button`标签中定义 Bootstrap 类：

```jsx
<button type="button" class="btnbtn-default">Default</button> 
<button type="button" class="btnbtn-primary">Primary</button> 
<button type="button" class="btnbtn-success">Success</button> 
<button type="button" class="btnbtn-info">Info</button> 
<button type="button" class="btnbtn-warning">Warning</button> 
<button type="button" class="btnbtn-danger">Danger</button> 
<button type="button" class="btnbtn-link">Link</button>

```

在之前的章节中，我们还使用了 Bootstrap 类来实现响应性和 Bootstrap 的默认组件。您可以在以下截图中看到`button`的一个示例，我在其中定义了以下代码。我们还可以更改所有已定义的`button`状态的颜色：

```jsx
<button type="button" class="btnbtn-primary">Agree</button> 

```

请参考以下截图：

![Bootstrap 组件 - 按钮](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/B05743_10_05-2.jpg)

## Bootstrap 主题

正如我之前所说，Bootstrap 还提供了现成的响应式主题，如果需要的话，我们应该使用。有关更多详细信息，您可以查看[`getbootstrap.com/examples/theme/`](http://getbootstrap.com/examples/theme/)。

您还可以访问以下参考资料，了解更多有关 Bootstrap 主题的选项：

+   [`www.blacktie.co/`](http://www.blacktie.co/)

+   [`wrapbootstrap.com/`](https://wrapbootstrap.com/)

+   [`startbootstrap.com/`](http://startbootstrap.com/)

+   [`bootswatch.com/`](http://bootswatch.com/)

## Bootstrap 响应式网格系统

Bootstrap 网格系统有一些预定义的类和行为，因此设置页面布局并为不同的设备和分辨率设置相同布局的不同行为将非常有帮助。

以下截图显示了移动设备和桌面列的设置：

![Bootstrap 响应式网格系统](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_10_007.jpg)

以下截图显示了移动设备、平板和桌面列的设置：

![Bootstrap 响应式网格系统](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_10_008.jpg)

这是如何使用预定义类来设置您的列。在小型和中型设备上，它们将自动调整您的数据以适应分辨率，而不会破坏用户界面。

最后，我想告诉你一些在处理 ReactJS 时需要记住的事情。

# 关于 ReactJS 和 Bootstrap 项目的有趣信息

ReactJS 和 Bootstrap 都被开发者社区广泛使用和关注。有数百万的项目在这两个框架上运行，显然这两个成功框架背后有一个专门的团队。

Bootstrap 总是在他们的最新版本或扩展中推出一些新的有用的东西。我们都知道 Bootstrap 是由 Twitter Bootstrap 拥有的，两位开发者应该得到成功的功劳：Mark Otto (`@mdo`) 和 Jacob Thornton (`@fat`)

有许多关于 Bootstrap 的有用网站，值得在寻找增加知识的过程中访问：

+   [`www.getbootstrap.com`](http://www.getbootstrap.com) | Twitter: `@twbootstrap`

+   [`expo.getbootstrap.com`](http://expo.getbootstrap.com) | Twitter: Mark Otto (`@mdo`)

+   [`www.bootsnipp.com`](http://www.bootsnipp.com) | Twitter: `@BootSnipp` 和 Maksim Surguy (`@msurguy`)

+   [`codeguide.co/`](http://codeguide.co/)

+   [`roots.io/`](http://roots.io/) | Twitter: Ben Word (`@retlehs`)

+   [`www.shoelace.io`](http://www.shoelace.io) | Twitter: Erik Flowers (`@Erik_UX`) 和 Shaun Gilchrist

+   [`github.com/JasonMortonNZ/bs3-sublime-plugin`](https://github.com/JasonMortonNZ/bs3-sublime-plugin) | Twitter: Jason Morton (`@JasonMortonNZ`)

+   [`fortawesome.github.io/Font-Awesome/`](http://fortawesome.github.io/Font-Awesome/) | Twitter: Dave Gandy (`@davegandy`)

+   [`bootstrapicons.com/`](http://bootstrapicons.com/) | Twitter: Brent Swisher (`@BrentSwisher`)

# 有用的 React 项目

在初学者级别，许多开发者发现 React 非常令人困惑，但如果你能够熟练掌握并深入了解它，你会喜欢它。有许多基于 ReactJS 完成的开源项目，我在下面的列表中分享了其中一些；我希望这肯定会帮助你更好地理解 React：

+   **Calypso**：

+   URL：[developer.wordpress.com/calypso](http://developer.wordpress.com/calypso)

+   GitHub：Automattic/wp-calypso

+   开发者：Automattic

+   前端级别技术：React Redux wpcomjs

+   后端级别技术：Node.js ExpressJS

+   **Sentry**：

+   URL：[getsentry.com/welcome](http://getsentry.com/welcome)

+   GitHub：getsentry/sentry

+   前端级别技术：React

+   后端级别技术：Python

+   **SoundRedux**：

+   URL：[soundredux.io/](https://soundredux.io/)

+   GitHub：andrewngu/sound-redux

+   开发者：Andrew Nguyen

+   前端级别技术：React Redux

+   后端级别技术：Node.js

+   **Phoenix Trello**：

+   URL：[phoenix-trello.herokuapp.com/](https://phoenix-trello.herokuapp.com/sign_in)

+   GitHub：bigardone/phoenix-trello

+   开发者：Ricardo García

+   前端级别技术：React Webpack 用于样式表的 Sass React 路由器 Redux ES6/ES7 JavaScript

+   后端级别技术：Elixir Phoenix 框架 Ecto PostgreSQL

+   **Kitematic**：

+   URL：[kitematic.com](https://kitematic.com/)

+   GitHub：docker/kitematic

+   开发者：Docker

+   前端级别技术：React

+   **Google 地图聚类示例**：

+   URL：[istarkov.github.io/google-map-clustering-example](http://istarkov.github.io/google-map-clustering-example/)

+   GitHub：istarkov/google-map-clustering-example

+   开发者：Ivan Starkov

+   前端级别技术：React

+   **Fil**：

+   URL：[fatiherikli.github.io/fil](http://fatiherikli.github.io/fil/)

+   GitHub：fatiherikli/fil

+   开发者：FatihErikli

+   前端级别技术：React Redux

+   **React iTunes 搜索**：

+   URL：[leoj.js.org/react-iTunes-search](http://leoj.js.org/react-iTunes-search/)

+   GitHub：LeoAJ/react-iTunes-search

+   开发者：Leo Hsieh

+   前端级别技术：React 打包组件：Webpack

+   **Sprintly**：

+   URL：[sprintly.ly](https://sprint.ly/)

+   GitHub：sprintly/sprintly-ui

+   开发者：Quick Left

+   前端级别技术：React Flux React Router

+   后端技术：Node.js

+   **Glimpse**：

+   URL：[getglimpse.com/](http://getglimpse.com/)

+   GitHub：Glimpse/Glimpse

+   开发者：Glimpse

+   前端级别技术：React 打包组件：Webpack

+   后端级别技术：Node.js

当您需要对 ReactJS 和 Bootstrap 进行支持时，请参考以下网站：

对于 React：

+   [`facebook.github.io/react/community/support.html`](https://facebook.github.io/react/community/support.html)

对于 Bootstrap：

+   [`getbootstrap.com/`](http://getbootstrap.com/)

+   [`github.com/twbs/bootstrap/issues`](https://github.com/twbs/bootstrap/issues)

# 要记住的事情

请注意以下要记住的要点：

+   在开始使用 React 之前，请始终记住它只是一个视图库，而不是 MVC 框架。

+   建议组件长度较小，以处理类和模块；这也使得在理解代码、单元测试和长期维护组件时更加轻松。

+   React 在其 0.14 版本中引入了 props 函数，建议使用。它也被称为功能组件，有助于拆分您的组件。

+   在处理基于 React 的应用程序时，为了避免痛苦的旅程，请不要使用太多状态。

+   如我之前所说，React 只是一个视图库，因此在处理渲染部分时，我建议使用 Redux 而不是 Flux。

+   如果您想要更多的类型安全性，那么始终使用`PropTypes`，这也有助于早期发现错误并起到文档的作用。

+   我建议使用浅渲染方法来测试 React 组件，这允许渲染单个组件而不触及其子组件。

+   在处理大型 React 应用程序时，始终使用 webpack、NPM、ES6、JSX 和 Babel 来完成您的应用程序。

+   如果您想深入了解 React 的应用程序及其元素，可以使用 Redux-dev 工具。

# 总结

我们在本章中涵盖了很多内容，因此在结束之前让我们回顾一下。

当我们在 React 中处理数据时，每当我们有具有动态功能的组件时，数据就会出现。在 React 中，我们必须处理动态数据，这似乎很容易，但并非总是如此。

从我的个人观点来看，我不建议仅仅为了管理与`/items/:itemIdroute`相关的数据而使用 Flux。相反，您可以在组件内部声明它并将其存储在那里。这有什么好处？答案是：它将依赖于您的组件，因此当您的组件不存在时，它也将不存在。

关于使用 Redux，正如我们所知，在单页应用程序中，当我们必须处理状态和时间时，难以掌握随时间变化的状态。在这里，Redux 非常有帮助。

我们还研究了其他关键因素，如 JSX、平面状态、不可变状态、可观察对象、响应式解决方案、React 路由、React 类、`ReactPropTypes`等等，这些都是 React 应用中最常用的元素。

我们还介绍了 Bootstrap 及其组件的实用性，这将使您在处理不同的浏览器和设备时更加灵活。

最后，我们为您提供了在处理任何 React 应用程序时需要记住的事项，无论是新应用程序还是集成应用程序；这些要点肯定会对您有很大帮助。
