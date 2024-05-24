# React 全栈项目（二）

> 原文：[`zh.annas-archive.org/md5/05F04F9004AE49378ED0525C32CB85EB`](https://zh.annas-archive.org/md5/05F04F9004AE49378ED0525C32CB85EB)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：添加 React 前端以完成 MERN

没有前端的 Web 应用程序是不完整的。这是用户与之交互的部分，对于任何 Web 体验都至关重要。在本章中，我们将使用 React 为我们在上一章开始构建的 MERN 骨架应用程序的后端实现的基本用户和认证功能添加交互式用户界面。

我们将涵盖以下主题，以添加一个可工作的前端并完成 MERN 骨架应用程序：

+   骨架的前端特性

+   使用 React、React Router 和 Material-UI 进行开发设置

+   后端用户 API 集成

+   认证集成

+   主页、用户、注册、登录、用户资料、编辑和删除视图

+   导航菜单

+   基本的服务器端渲染

# 骨架前端

为了完全实现在第三章的*功能拆分*部分中讨论的骨架应用程序功能，即使用 MongoDB、Express 和 Node 构建后端，我们将向基本应用程序添加以下用户界面组件：

+   主页：在根 URL 上呈现的视图，欢迎用户访问 Web 应用程序

+   用户列表页面：获取并显示数据库中所有用户列表的视图，并链接到单个用户资料

+   注册页面：一个带有用户注册表单的视图，允许新用户创建用户账户，并在成功创建后将他们重定向到登录页面

+   登录页面：带有登录表单的视图，允许现有用户登录，以便他们可以访问受保护的视图和操作

+   个人资料页面：获取并显示单个用户信息的组件，只有已登录用户才能访问，并且还包含编辑和删除选项，仅当已登录用户查看自己的个人资料时才可见

+   编辑个人资料页面：一个表单，获取用户的信息，允许他们编辑信息，并且仅当已登录用户尝试编辑自己的个人资料时才可访问

+   删除用户组件：一个选项，允许已登录用户在确认意图后删除自己的个人资料

+   菜单导航栏：列出所有可用和相关的视图的组件，还帮助指示用户在应用程序中的当前位置

以下 React 组件树图显示了我们将开发的所有 React 组件，以构建出这个基本应用程序的视图：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/a7c89a42-7cb4-41d2-a7b8-db331fbb9301.png)

**MainRouter**将是根 React 组件，其中包含应用程序中的所有其他自定义 React 视图。**Home**，**Signup**，**Signin**，**Users**，**Profile**和**EditProfile**将在使用 React Router 声明的各个路由上呈现，而**Menu**组件将在所有这些视图中呈现，**DeleteUser**将成为**Profile**视图的一部分。

本章讨论的代码以及完整的骨架代码都可以在 GitHub 的存储库中找到，网址为[github.com/shamahoque/mern-skeleton](https://github.com/shamahoque/mern-skeleton)。您可以克隆此代码，并在本章的其余部分中阅读代码解释时运行应用程序。

# 文件夹和文件结构

以下文件夹结构显示了要添加到骨架中的新文件夹和文件，以完成具有 React 前端的骨架：

```jsx
| mern_skeleton/
   | -- client/
      | --- assets/
         | ---- images/
      | --- auth/
         | ---- api-auth.js
         | ---- auth-helper.js
         | ---- PrivateRoute.js
         | ---- Signin.js
      | --- core/
         | ---- Home.js
         | ---- Menu.js
      | --- user/
         | ---- api-user.js
         | ---- DeleteUser.js
         | ---- EditProfile.js
         | ---- Profile.js
         | ---- Signup.js
         | ---- Users.js
      | --- App.js
      | --- main.js
      | --- MainRouter.js
  | -- server/
      | --- devBundle.js
  | -- webpack.config.client.js
  | -- webpack.config.client.production.js
```

客户端文件夹将包含 React 组件，辅助程序和前端资产，例如图像和 CSS。除了这个文件夹和用于编译和捆绑客户端代码的 Webpack 配置之外，我们还将修改一些其他现有文件，以整合完整的骨架。

# 为 React 开发设置

在我们可以在现有的骨架代码库中开始使用 React 进行开发之前，我们首先需要添加配置来编译和捆绑前端代码，添加构建交互式界面所需的与 React 相关的依赖项，并在 MERN 开发流程中将所有这些联系在一起。

# 配置 Babel 和 Webpack

为了在开发期间编译和捆绑客户端代码并在生产环境中运行它，我们将更新 Babel 和 Webpack 的配置。

# Babel

为了编译 React，首先安装 Babel 的 React 预设模块作为开发依赖项：

```jsx
npm install babel-preset-react --save-dev
```

然后，更新`.babelrc`以包括该模块，并根据需要配置`react-hot-loader` Babel 插件。

`mern-skeleton/.babelrc`：

```jsx
{
    "presets": [
      "env",
      "stage-2",
      "react"
    ],
    "plugins": [
 "react-hot-loader/babel"
 ]
}
```

# Webpack

在使用 Babel 编译后捆绑客户端代码，并为更快的开发启用`react-hot-loader`，安装以下模块：

```jsx
npm install --save-dev webpack-dev-middleware webpack-hot-middleware file-loader
npm install --save react-hot-loader
```

然后，为了配置前端开发的 Webpack 并构建生产捆绑包，我们将添加一个`webpack.config.client.js`文件和一个`webpack.config.client.production.js`文件，其中包含与第二章中描述的相同配置代码，*准备开发环境*。

# 加载 Webpack 中间件进行开发

在开发过程中，当我们运行服务器时，Express 应用程序应加载与客户端代码设置的配置相关的 Webpack 中间件，以便集成前端和后端开发工作流程。为了实现这一点，我们将使用第二章中讨论的`devBundle.js`文件，*准备开发环境*，设置一个`compile`方法，该方法接受 Express 应用程序并配置它使用 Webpack 中间件。`server`文件夹中的`devBundle.js`将如下所示。

`mern-skeleton/server/devBundle.js`：

```jsx
import config from './../config/config'
import webpack from 'webpack'
import webpackMiddleware from 'webpack-dev-middleware'
import webpackHotMiddleware from 'webpack-hot-middleware'
import webpackConfig from './../webpack.config.client.js'

const compile = (app) => {
  if(config.env === "development"){
    const compiler = webpack(webpackConfig)
    const middleware = webpackMiddleware(compiler, {
      publicPath: webpackConfig.output.publicPath
    })
    app.use(middleware)
    app.use(webpackHotMiddleware(compiler))
  }
}

export default {
  compile
}
```

然后，通过添加以下突出显示的行，导入并调用`express.js`中的`compile`方法，仅在开发时添加。 

`mern-skeleton/server/express.js`：

```jsx
**import devBundle from './devBundle'**
const app = express()
**devBundle.compile(app)** 
```

这两行突出显示的代码仅用于开发模式，在构建生产代码时应将其注释掉。此代码将在 Express 应用程序以开发模式运行时导入中间件和 Webpack 配置，然后启动 Webpack 编译和捆绑客户端代码。捆绑后的代码将放置在`dist`文件夹中。

# 使用 Express 提供静态文件

为了确保 Express 服务器正确处理对静态文件（如 CSS 文件、图像或捆绑的客户端 JS）的请求，我们将通过在`express.js`中添加以下配置来配置它从`dist`文件夹中提供静态文件。

`mern-skeleton/server/express.js`：

```jsx
import path from 'path'
const CURRENT_WORKING_DIR = process.cwd()
app.use('/dist', express.static(path.join(CURRENT_WORKING_DIR, 'dist')))
```

# 更新模板以加载捆绑的脚本

为了在 HTML 视图中添加捆绑的前端代码，我们将更新`template.js`文件，将脚本文件从`dist`文件夹添加到`<body>`标签的末尾。

`mern-skeleton/template.js`：

```jsx
...
<body>
    <div id="root"></div>
    **<script type="text/javascript" src="/dist/bundle.js"></script>**
</body>
```

# 添加 React 依赖项

前端视图将主要使用 React 实现。此外，为了实现客户端路由，我们将使用 React Router，并且为了增强用户体验，使其看起来更加流畅，我们将使用 Material-UI。

# React

在本书中，我们将使用 React 16 来编写前端代码。要开始编写`React`组件代码，我们需要安装以下模块作为常规依赖项：

```jsx
npm install --save react react-dom
```

# React Router

React Router 提供了一组导航组件，可以在 React 应用程序的前端进行路由。为了利用声明式路由并拥有可书签的 URL 路由，我们将添加以下 React Router 模块：

```jsx
npm install --save react-router react-router-dom
```

# Material-UI

为了保持我们的 MERN 应用程序中的 UI 简洁，而不过多涉及 UI 设计和实现，我们将利用`Material-UI`库。它提供了可立即使用和可定制的`React`组件，实现了谷歌的材料设计。要开始使用 Material-UI 组件制作前端，我们需要安装以下模块：

```jsx
npm install --save material-ui@1.0.0-beta.43 material-ui-icons
```

在撰写本文时，Material-UI 的最新预发布版本是`1.0.0-beta.43`，建议安装此确切版本，以确保示例项目的代码不会中断。

将`Roboto`字体按照 Material-UI 的建议添加，并使用`Material-UI`图标，我们将在`template.js`文件的 HTML 文档的`<head>`部分中添加相关的样式链接：

```jsx
<link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Roboto:100,300,400">
<link href="https://fonts.googleapis.com/icon?family=Material+Icons" rel="stylesheet">
```

随着开发配置的全部设置和必要的 React 模块添加到代码库中，我们现在可以开始实现自定义的 React 组件。

# 实现 React 视图

一个功能齐全的前端应该将 React 组件与后端 API 集成，并允许用户根据授权在应用程序中无缝导航。为了演示如何为这个 MERN 骨架实现一个功能齐全的前端视图，我们将从详细说明如何在根路由处呈现主页组件开始，然后涵盖后端 API 和用户认证集成，然后突出实现剩余视图组件的独特方面。

# 呈现主页

在根路由处实现和呈现一个工作的`Home`组件的过程也将暴露骨架中前端代码的基本结构。我们将从顶级入口组件开始，该组件包含整个 React 应用程序，并呈现链接应用程序中所有 React 组件的主路由器组件。

# 在`main.js`的入口点

客户端文件夹中的`client/main.js`文件将是渲染完整 React 应用程序的入口点。在这段代码中，我们导入将包含完整前端并将其呈现到在`template.js`中指定的 HTML 文档中的`div`元素的根或顶级 React 组件。

`mern-skeleton/client/main.js`：

```jsx
import React from 'react'
import { render } from 'react-dom'
import App from './App'

render(<App/>, document.getElementById('root'))
```

# 根 React 组件

定义应用程序前端所有组件的顶层 React 组件在`client/App.js`文件中。在这个文件中，我们配置 React 应用程序以使用定制的 Material-UI 主题渲染视图组件，启用前端路由，并确保 React Hot Loader 可以在我们开发组件时立即加载更改。

# 定制 Material-UI 主题

可以使用`MuiThemeProvider`组件轻松定制 Material-UI 主题，并通过在`createMuiTheme()`中配置自定义值来设置主题变量。

`mern-skeleton/client/App.js`：

```jsx
import {MuiThemeProvider, createMuiTheme} from 'material-ui/styles'
import {indigo, pink} from 'material-ui/colors'

const theme = createMuiTheme({
  palette: {
    primary: {
    light: '#757de8',
    main: '#3f51b5',
    dark: '#002984',
    contrastText: '#fff',
  },
  secondary: {
    light: '#ff79b0',
    main: '#ff4081',
    dark: '#c60055',
    contrastText: '#000',
  },
    openTitle: indigo['400'],
    protectedTitle: pink['400'],
    type: 'light'
  }
}) 
```

对于骨架，我们只需进行最少的定制，通过将一些颜色值设置为 UI 中使用的值。在这里生成的主题变量将传递给我们构建的所有组件，并在其中可用。

# 用 MUI 主题和 BrowserRouter 包装根组件

我们创建的自定义 React 组件将通过`MainRouter`组件中指定的前端路由进行访问。基本上，这个组件包含了为应用程序开发的所有自定义视图。在`App.js`中定义根组件时，我们使用`MuiThemeProvider`将`MainRouter`组件包装起来，以便让它可以访问 Material-UI 主题，并使用`BrowserRouter`启用 React Router 的前端路由。之前定义的自定义主题变量作为 prop 传递给`MuiThemeProvider`，使主题在所有自定义 React 组件中可用。

`mern-skeleton/client/App.js`：

```jsx
import React from 'react'
import MainRouter from './MainRouter'
import {BrowserRouter} from 'react-router-dom'

const App = () => (
  <BrowserRouter>
    <MuiThemeProvider theme={theme}>
      <MainRouter/>
    </MuiThemeProvider>
  </BrowserRouter>
)
```

# 将根组件标记为热导出

在`App.js`中的最后一行代码导出`App`组件使用`react-hot-loader`中的`hot`模块将根组件标记为`hot`。这将在开发过程中启用 React 组件的实时重新加载。

`mern-skeleton/client/App.js`：

```jsx
import { hot } from 'react-hot-loader'
...
export default hot(module)(App)
```

对于我们的 MERN 应用程序，在这一点之后，我们不需要太多更改`main.js`和`App.js`的代码，可以继续通过在`MainRouter`组件中注入新组件来构建 React 应用程序的其余部分。

# 向 MainRouter 添加主页路由

`MainRouter.js`代码将帮助根据应用程序中的路由或位置渲染我们的自定义 React 组件。在这个第一个版本中，我们只会添加根路由来渲染`Home`组件。

`mern-skeleton/client/MainRouter.js`：

```jsx
import React, {Component} from 'react'
import {Route, Switch} from 'react-router-dom'
import Home from './core/Home'
class MainRouter extends Component {
  render() {
    return (<div>
      <Switch>
        <Route exact path="/" component={Home}/>
      </Switch>
    </div>)
  }
}
export default MainRouter
```

随着我们开发更多的视图组件，我们将更新`MainRouter`以在`Switch`组件中为新组件添加路由。

React Router 中的`Switch`组件专门用于呈现路由。换句话说，它只呈现与请求的路由路径匹配的第一个子组件。而不在`Switch`中嵌套时，每个`Route`组件在路径匹配时都会进行包容性渲染。例如，对`'/'`的请求也会匹配`'/contact'`的路由。

# Home 组件

当用户访问根路由时，`Home`组件将在浏览器上呈现，并且我们将使用 Material-UI 组件来组合它。以下屏幕截图显示了`Home`组件和稍后在本章中作为独立组件实现的`Menu`组件，以提供应用程序中的导航：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/c3f41131-6f5c-4a1f-8de4-5451b50a243f.png)

`Home`组件和其他视图组件将按照通用的代码结构在浏览器中呈现给用户进行交互，该结构包含以下部分，按照给定的顺序。

# 导入

组件文件将从 React、Material-UI、React Router 模块、图像、CSS、API fetch 和我们代码中的 auth helpers 中导入所需的特定组件。例如，在`Home.js`中的`Home`组件代码中，我们使用以下导入。

`mern-skeleton/client/core/Home.js`:

```jsx
import React, {Component} from 'react'
import PropTypes from 'prop-types'
import {withStyles} from 'material-ui/styles'
import Card, {CardContent, CardMedia} from 'material-ui/Card'
import Typography from 'material-ui/Typography'
import seashellImg from './../assets/images/seashell.jpg'
```

图像文件保存在`client/assets/images/`文件夹中，并被导入/添加到`Home`组件中。

# 样式声明

在导入之后，我们将根据需要使用`Material-UI`主题变量来定义 CSS 样式，以便对组件中的元素进行样式设置。对于`Home.js`中的`Home`组件，我们有以下样式。

`mern-skeleton/client/core/Home.js`:

```jsx
const styles = theme => ({
  card: {
    maxWidth: 600,
    margin: 'auto',
    marginTop: theme.spacing.unit * 5
  },
  title: {
    padding:`${theme.spacing.unit * 3}px ${theme.spacing.unit * 2.5}px 
    ${theme.spacing.unit * 2}px`,
    color: theme.palette.text.secondary
  },
  media: {
    minHeight: 330
  }
}) 
```

在这里定义的 JSS 样式对象将被注入到组件中，并用于对组件中的元素进行样式设置，就像下面的`Home`组件定义中所示。

Material-UI 使用 JSS，这是一种 CSS-in-JS 的样式解决方案，用于向组件添加样式。JSS 使用 JavaScript 作为描述样式的语言。本书不会详细介绍 CSS 和样式实现，而是更多地依赖于 Material-UI 组件的默认外观和感觉。要了解更多关于 JSS 的信息，请访问[`cssinjs.org/?v=v9.8.1`](http://cssinjs.org/?v=v9.8.1)。要了解如何自定义`Material-UI`组件样式的示例，请查看 Material-UI 文档[`material-ui-next.com/`](https://material-ui-next.com/)。 

# 组件定义

在组件定义中，我们将组合组件的内容和行为。`Home`组件将包含一个 Material-UI 的`Card`，其中包括一个标题、一个图像和一个标题，所有这些都使用之前定义的类进行样式设置，并作为 props 传递进来。

`mern-skeleton/client/core/Home.js`：

```jsx
class Home extends Component {
  render() {
    const {classes} = this.props 
    return (
      <div>
        <Card className={classes.card}>
          <Typography type="headline" component="h2" className=
          {classes.title}>
            Home Page
          </Typography>
          <CardMedia className={classes.media} image={seashellImg} 
          title="Unicorn Shells"/>
          <CardContent>
            <Typography type="body1" component="p">
              Welcome to the Mern Skeleton home page
            </Typography>
          </CardContent>
        </Card>
      </div>
    )
  }
}
```

# PropTypes 验证

为了验证将样式声明作为 props 注入到组件中的要求，我们向已定义的组件添加了`PropTypes`要求验证器。

`mern-skeleton/client/core/Home.js`：

```jsx
Home.propTypes = {
  classes: PropTypes.object.isRequired
}
```

# 导出组件

最后，在组件文件的最后一行代码中，我们将使用`Material-UI`中的`withStyles`导出组件并传递定义的样式。像这样使用`withStyles`创建了一个具有对定义样式对象的访问权限的**Higher-order component** (**HOC**)。

`mern-skeleton/client/core/Home.js`：

```jsx
export default withStyles(styles)(Home)
```

导出的组件现在可以在其他组件中进行组合使用，就像我们在之前讨论的`MainRouter`组件中的路由中使用`Home`组件一样。

在我们的 MERN 应用程序中要实现的其他视图组件将遵循相同的结构。在本书的其余部分，我们将主要关注组件定义，突出已实现组件的独特方面。

# 捆绑图像资源

我们导入到`Home`组件视图中的静态图像文件也必须与编译后的 JS 代码一起包含在捆绑包中，以便代码可以访问和加载它。为了实现这一点，我们需要更新 Webpack 配置文件，添加一个模块规则来加载、捆绑和发射图像文件到输出目录中，该目录包含编译后的前端和后端代码。

更新`webpack.config.client.js`，`webpack.config.server.js`和`webpack.config.client.production.js`文件，在使用`babel-loader`后添加以下模块规则：

```jsx
[ …
    {
       test: /\.(ttf|eot|svg|gif|jpg|png)(\?[\s\S]+)?$/,
       use: 'file-loader'
    }
]
```

这个模块规则使用 Webpack 的`file-loader` npm 模块，需要安装为开发依赖，如下所示：

```jsx
npm install --save-dev file-loader
```

# 运行并在浏览器中打开

到目前为止，客户端代码可以运行，以在根 URL 的浏览器中查看`Home`组件。要运行应用程序，请使用以下命令：

```jsx
npm run development
```

然后，在浏览器中打开根 URL（`http://localhost:3000`）以查看`Home`组件。

这里开发的`Home`组件是一个基本的视图组件，没有交互功能，不需要使用后端 API 来进行用户 CRUD 或身份验证。然而，我们骨架前端的其余视图组件将需要后端 API 和身份验证。

# 后端 API 集成

用户应该能够使用前端视图根据身份验证和授权从数据库中获取和修改用户数据。为了实现这些功能，React 组件将使用 Fetch API 访问后端暴露的 API 端点。

Fetch API 是一个较新的标准，用于发出类似于**XMLHttpRequest**（**XHR**）的网络请求，但使用 promise，从而实现了更简单和更清晰的 API。要了解有关 Fetch API 的更多信息，请访问[`developer.mozilla.org/en-US/docs/Web/API/Fetch_API`](https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API)。

# 用户 CRUD 的获取

在`client/user/api-user.js`文件中，我们将添加用于访问每个用户 CRUD API 端点的方法，React 组件可以使用这些方法与服务器和数据库交换用户数据。

# 创建用户

`create`方法将从视图组件获取用户数据，使用`fetch`进行`POST`调用，在后端创建一个新用户，最后将来自服务器的响应作为一个 promise 返回给组件。

`mern-skeleton/client/user/api-user.js`：

```jsx
const create = (user) => {
  return fetch('/api/users/', {
      method: 'POST',
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(user)
    })
    .then((response) => {
      return response.json()
    }).catch((err) => console.log(err))
}
```

# 列出用户

`list`方法将使用 fetch 进行`GET`调用，以检索数据库中的所有用户，然后将来自服务器的响应作为 promise 返回给组件。

`mern-skeleton/client/user/api-user.js`：

```jsx
const list = () => {
  return fetch('/api/users/', {
    method: 'GET',
  }).then(response => {
    return response.json()
  }).catch((err) => console.log(err))
}
```

# 读取用户配置文件

`read`方法将使用 fetch 进行`GET`调用，按 ID 检索特定用户。由于这是一个受保护的路由，除了将用户 ID 作为参数传递之外，请求组件还必须提供有效的凭据，这种情况下将是成功登录后收到的有效 JWT。

`mern-skeleton/client/user/api-user.js`：

```jsx
const read = (params, credentials) => {
  return fetch('/api/users/' + params.userId, {
    method: 'GET',
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json',
      'Authorization': 'Bearer ' + credentials.t
    }
  }).then((response) => {
    return response.json()
  }).catch((err) => console.log(err))
}
```

JWT 附加到`GET` fetch 调用中的`Authorization`标头，使用`Bearer`方案，然后将来自服务器的响应作为 promise 返回给组件。

# 更新用户数据

`update`方法将从视图组件获取特定用户的更改用户数据，然后使用`fetch`进行`PUT`调用，更新后端现有用户。这也是一个受保护的路由，需要有效的 JWT 作为凭据。

`mern-skeleton/client/user/api-user.js`：

```jsx
const update = (params, credentials, user) => {
  return fetch('/api/users/' + params.userId, {
    method: 'PUT',
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json',
      'Authorization': 'Bearer ' + credentials.t
    },
    body: JSON.stringify(user)
  }).then((response) => {
    return response.json()
  }).catch((err) => {
    console.log(err)
  })
}
```

# 删除用户

`remove`方法将允许视图组件使用 fetch 来删除数据库中的特定用户，发出`DELETE`调用。同样，这是一个受保护的路由，将需要有效的 JWT 作为凭据，类似于`read`和`update`方法。服务器对删除请求的响应将以 promise 的形式返回给组件。

`mern-skeleton/client/user/api-user.js`：

```jsx
const remove = (params, credentials) => {
  return fetch('/api/users/' + params.userId, {
    method: 'DELETE',
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json',
      'Authorization': 'Bearer ' + credentials.t
    }
  }).then((response) => {
    return response.json()
  }).catch((err) => {
    console.log(err)
  }) 
}
```

最后，将用户 API 辅助方法导出，以便根据需要被导入和使用 React 组件。

`mern-skeleton/client/user/api-user.js`：

```jsx
export { create, list, read, update, remove }
```

# 用于认证 API 的 fetch

为了将服务器的认证 API 端点与前端 React 组件集成，我们将在`client/auth/api-auth.js`文件中添加用于获取登录和登出 API 端点的方法。

# 登录

`signin`方法将从视图组件获取用户登录数据，然后使用`fetch`发出`POST`调用来验证后端的用户。服务器的响应将以 promise 的形式返回给组件，其中可能包含 JWT 如果登录成功的话。

`mern-skeleton/client/user/api-auth.js`：

```jsx
const signin = (user) => {
  return fetch('/auth/signin/', {
      method: 'POST',
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
      },
      credentials: 'include',
      body: JSON.stringify(user)
    })
    .then((response) => {
      return response.json()
    }).catch((err) => console.log(err))
}
```

# 登出

`signout`方法将使用 fetch 来向服务器的 signout API 端点发出 GET 调用。

`mern-skeleton/client/user/api-auth.js`：

```jsx
const signout = () => {
  return fetch('/auth/signout/', {
    method: 'GET',
  }).then(response => {
      return response.json()
  }).catch((err) => console.log(err))
}
```

在`api-auth.js`文件的末尾，导出`signin`和`signout`方法。

`mern-skeleton/client/user/api-auth.js`：

```jsx
export { signin, signout }
```

有了这些 API fetch 方法，React 前端可以完全访问后端可用的端点。

# 前端的认证

如前一章所讨论的，使用 JWT 实现认证将责任转移到客户端来管理和存储用户认证状态。为此，我们需要编写代码，允许客户端存储从服务器成功登录时收到的 JWT，在访问受保护的路由时使其可用，当用户退出时删除或使令牌无效，并且还根据用户认证状态限制前端的视图和组件访问。

使用 React Router 文档中的认证工作流示例，我们将编写辅助方法来管理组件之间的认证状态，并且还将使用自定义的`PrivateRoute`组件来向前端添加受保护的路由。

# 管理认证状态

在`client/auth/auth-helper.js`中，我们将定义以下辅助方法来从客户端`sessionStorage`中存储和检索 JWT 凭据，并在用户退出时清除`sessionStorage`：

+   `authenticate(jwt, cb)`: 在成功登录时保存凭据：

```jsx
authenticate(jwt, cb) {
    if(typeof window !== "undefined")
        sessionStorage.setItem('jwt', JSON.stringify(jwt))
    cb()
}
```

+   `isAuthenticated()`: 如果已登录，则检索凭据：

```jsx
isAuthenticated() {
    if (typeof window == "undefined")
      return false

    if (sessionStorage.getItem('jwt'))
      return JSON.parse(sessionStorage.getItem('jwt'))
    else
      return false
}
```

+   `signout(cb)`: 删除凭据并退出登录：

```jsx
signout(cb) {
      if(typeof window !== "undefined")
        sessionStorage.removeItem('jwt')
      cb()
      signout().then((data) => {
          document.cookie = "t=; expires=Thu, 01 Jan 1970 00:00:00 
          UTC; path=/;"
      })
}
```

使用这里定义的方法，我们构建的 React 组件将能够检查和管理用户认证状态，以限制前端的访问，就像在自定义的`PrivateRoute`中所示的那样。

# PrivateRoute 组件

`client/auth/PrivateRoute.js`中定义了`PrivateRoute`组件，如 React Router 文档中的认证流程示例所示。它将允许我们声明受保护的路由，以便前端根据用户认证限制视图访问。

`mern-skeleton/client/auth/PrivateRoute.js`:

```jsx
import React, { Component } from 'react'
import { Route, Redirect } from 'react-router-dom'
import auth from './auth-helper'

const PrivateRoute = ({ component: Component, ...rest }) => (
  <Route {...rest} render={props => (
    auth.isAuthenticated() ? (
      <Component {...props}/>
    ) : (
      <Redirect to={{
        pathname: '/signin',
        state: { from: props.location }
      }}/>
    )
  )}/>
)

export default PrivateRoute
```

在`PrivateRoute`中呈现的组件只有在用户经过认证时才会加载，否则用户将被重定向到`Signin`组件。

随着后端 API 的集成，和认证管理辅助方法在组件中准备就绪，我们可以开始构建剩余的视图组件。

# 用户和认证组件

本节中描述的 React 组件完成了骨架定义的交互功能，允许用户查看、创建和修改存储在数据库中的用户数据，同时考虑认证限制。对于以下每个组件，我们将介绍每个组件的独特方面，以及如何将组件添加到应用程序中的`MainRouter`中。

# Users 组件

`client/user/Users.js`中的`Users`组件显示了从数据库中获取的所有用户的名称，并将每个名称链接到用户配置文件。任何访问应用程序的访问者都可以查看此组件，并且将在路径`'/users'`上呈现：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/896050db-1fcc-47db-b597-a90f8af964a1.png)

在组件定义中，我们首先使用空数组初始化状态。

`mern-skeleton/client/user/Users.js`:

```jsx
class Users extends Component {
  state = { users: [] }
...
```

接下来，在`componentDidMount`中，我们使用`api-user.js`中的`list`方法，从后端获取用户列表，并通过更新状态将用户数据加载到组件中。

`mern-skeleton/client/user/Users.js`:

```jsx
  componentDidMount = () => {
    list().then((data) => {
      if (data.error)
        console.log(data.error)
      else
        this.setState({users: data})
    })
  }
```

`render`函数包含`Users`组件的实际视图内容，并与 Material-UI 组件（如`Paper`、`List`和`ListItems`）组合在一起。这些元素使用定义的 CSS 进行样式化，并作为 props 传递。

`mern-skeleton/client/user/Users.js`：

```jsx
render() {
    const {classes} = this.props
    return (
      <Paper className={classes.root} elevation={4}>
        <Typography type="title" className={classes.title}>
          All Users
        </Typography>
        <List dense>
          {this.state.users.map(function(item, i) {
              return <Link to={"/user/" + item._id} key={i}>
                <ListItem button="button">
                  <ListItemAvatar>
                    <Avatar>
                      <Person/>
                    </Avatar>
                  </ListItemAvatar>
                  <ListItemText primary={item.name}/>
                  <ListItemSecondaryAction>
                    <IconButton>
                      <ArrowForward/>
                    </IconButton>
                  </ListItemSecondaryAction>
                </ListItem>
              </Link>
            })}
        </List>
      </Paper>
    )
  }
```

为了生成每个列表项，我们使用 map 函数遍历状态中的用户数组。

要将此`Users`组件添加到 React 应用程序中，我们需要使用`Route`更新`MainRouter`组件，在`'/users'`路径处呈现此组件。在`Home`路由之后，在`Switch`组件内添加`Route`。

`mern-skeleton/client/MainRouter.js`：

```jsx
<Route path="/users" component={Users}/>
```

要在浏览器中看到此视图呈现，可以暂时在`Home`组件中添加一个`Link`组件，以路由到`Users`组件：

```jsx
<Link to="/users">Users</Link>
```

# 注册组件

`client/user/Signup.js`中的`Signup`组件向用户呈现一个带有名称、电子邮件和密码字段的表单，用于在`'/signup'`路径上注册。

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/b478e453-909d-4348-af22-0a44ac3ff566.png)

在组件定义中，我们首先使用空输入字段值，空错误消息和将对话框打开变量设置为 false 来初始化状态。

`mern-skeleton/client/user/Signup.js`：

```jsx
  constructor() {
    state = { name: '', password: '', email: '', open: false, error: '' }
  ...
```

我们还定义了两个处理函数，当输入值更改或单击提交按钮时将被调用。`handleChange`函数获取输入字段中输入的新值，并将其设置为`state`。

`mern-skeleton/client/user/Signup.js`：

```jsx
handleChange = name => event => {
    this.setState({[name]: event.target.value})
}
```

当表单提交时，将调用`clickSubmit`函数。它从状态中获取输入值，并调用`create`获取方法来注册用户。然后，根据服务器的响应，要么显示错误消息，要么显示成功对话框。

`mern-skeleton/client/user/Signup.js`：

```jsx
  clickSubmit = () => {
    const user = {
      name: this.state.name || undefined,
      email: this.state.email || undefined,
      password: this.state.password || undefined
    } 
    create(user).then((data) => {
      if (data.error)
        this.setState({error: data.error})
      else
        this.setState({error: '', open: true})
    })
  }
```

在`render`函数中，我们使用诸如来自 Material-UI 的`TextField`等组件来组成和样式化注册视图中的表单组件。

`mern-skeleton/client/user/Signup.js`：

```jsx
  render() {
    const {classes} = this.props
    return (<div>
      <Card className={classes.card}>
        <CardContent>
          <Typography type="headline" component="h2" 
                      className={classes.title}>
            Sign Up
          </Typography>
          <TextField id="name" label="Name" 
          className={classes.textField} 
                     value={this.state.name} 
                     onChange={this.handleChange('name')} 
                     margin="normal"/> <br/>
          <TextField id="email" type="email" label="Email" 
                     className={classes.textField} value=
                     {this.state.email} 
                     onChange={this.handleChange('email')}
                     margin="normal"/><br/>
          <TextField id="password" type="password"
          label="Password" className={classes.textField} 
                     value={this.state.password} 
                     onChange={this.handleChange('password')} 
                     margin="normal"/><br/> 
          {this.state.error && ( <Typography component="p" 
           color="error">
              <Icon color="error" 
              className={classes.error}>error</Icon>
              {this.state.error}</Typography>)}
        </CardContent>
        <CardActions>
          <Button color="primary" raised="raised"
                  onClick={this.clickSubmit} 
           className={classes.submit}>Submit</Button>
        </CardActions>
      </Card>
      <Dialog> ... </Dialog>
    </div>)
  }
```

渲染还包含一个错误消息块，以及一个`Dialog`组件，根据服务器的注册响应条件渲染。`Signup.js`中的`Dialog`组件组成如下。

`mern-skeleton/client/user/Signup.js`：

```jsx
<Dialog open={this.state.open} disableBackdropClick={true}>
   <DialogTitle>New Account</DialogTitle>
   <DialogContent>
      <DialogContentText>
         New account successfully created.
      </DialogContentText>
   </DialogContent>
   <DialogActions>
      <Link to="/signin">
         <Button color="primary" autoFocus="autoFocus" variant="raised">
            Sign In
```

```jsx
         </Button>
      </Link>
   </DialogActions>
</Dialog>
```

成功创建帐户后，用户将收到确认，并被要求使用此`Dialog`组件登录，该组件链接到`Signin`组件：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/fc581278-d930-463d-af2b-d9fad6cc69a0.png)

要将`Signup`组件添加到应用程序中，在`Switch`组件中添加以下`Route`到`MainRouter`中。

`mern-skeleton/client/MainRouter.js`：

```jsx
<Route path="/signup" component={Signup}/>
```

这将在`'/signup'`处呈现`Signup`视图。

# 登录组件

`client/auth/Signin.js`中的`Signin`组件也是一个只有电子邮件和密码字段的登录表单。该组件与`Signup`组件非常相似，并将在`'/signin'`路径下呈现。主要区别在于成功登录后重定向和接收 JWT 的存储实现：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/590ab772-2a8f-431e-94ab-7c4fe4a57620.png)

对于重定向，我们将使用 React Router 中的`Redirect`组件。首先，在状态中将`redirectToReferrer`值初始化为`false`，并与其他字段一起使用：

`mern-skeleton/client/auth/Signin.js`：

```jsx
class Signin extends Component {
  state = { email: '', password: '', error: '', redirectToReferrer: false } 
...
```

当用户成功提交表单并且接收到 JWT 存储在`sessionStorage`中时，`redirectToReferrer`应设置为`true`。为了存储 JWT 并在之后重定向，我们将调用`auth-helper.js`中定义的`authenticate()`方法。这段代码将放在`clickSubmit()`函数中，在表单提交时调用。

`mern-skeleton/client/auth/Signin.js`：

```jsx
clickSubmit = () => {
    const user = {
      email: this.state.email || undefined,
      password: this.state.password || undefined
    }
    signin(user).then((data) => {
      if (data.error) {
        this.setState({error: data.error})
      } else {
        auth.authenticate(data, () => {
 this.setState({redirectToReferrer: true})
 })
      }
    })
}
```

基于`redirectToReferrer`值的条件，重定向将在`render`函数中的`Redirect`组件中发生。在返回之前，在 render 函数中添加重定向代码如下：

`mern-skeleton/client/auth/Signin.js`：

```jsx
render() {
    const {classes} = this.props
    const {from} = this.props.location.state || {
 from: {pathname: '/' }
 } 
 const {redirectToReferrer} = this.state
 if (redirectToReferrer)
 return (<Redirect to={from}/>)
    return (...)
  }
}
```

如果渲染`Redirect`组件，将会将应用程序带到上次的位置或根目录下的`Home`组件。

返回将包含类似于`Signup`的表单元素，只有`email`和`password`字段，条件错误消息和`submit`按钮。

要将`Signin`组件添加到应用程序中，在`Switch`组件的`MainRouter`中添加以下路由。

`mern-skeleton/client/MainRouter.js`：

```jsx
<Route path="/signin" component={Signin}/>
```

这将在`"/signin"`处呈现`Signin`组件。

# Profile 组件

`client/user/Profile.js`中的`Profile`组件在`'/user/:userId'`路径中显示单个用户的信息，其中`userId`参数表示特定用户的 ID：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/cb24bc18-4a74-4041-b29f-ab6635c68723.png)

只有在用户登录后，才能从服务器获取此配置文件信息，并且为了验证这一点，组件必须向`read`获取调用提供 JWT，否则用户应该被重定向到登录视图。

在`Profile`组件定义中，我们首先需要用空用户初始化状态，并将`redirectToSignin`设置为`false`。

`mern-skeleton/client/user/Profile.js`：

```jsx
class Profile extends Component {
  constructor({match}) {
    super()
    this.state = { user: '', redirectToSignin: false }
    this.match = match 
  } ...
```

我们还需要访问由`Route`组件传递的匹配 props，其中将包含`:userId`参数值，并且在组件挂载时可以作为`this.match.params.userId`进行访问。

`Profile`组件应在路由中的`userId`参数更改时获取用户信息并呈现它。然而，当应用程序从一个配置文件视图切换到另一个配置文件视图时，只是路由路径中的参数更改，React 组件不会重新挂载。相反，它会在`componentWillReceiveProps`中传递新的 props。为了确保组件在路由参数更新时加载相关用户信息，我们将在`init()`函数中放置`read`获取调用，然后可以在`componentDidMount`和`componentWillReceiveProps`中调用它。

`mern-skeleton/client/user/Profile.js`：

```jsx
init = (userId) => {
    const jwt = auth.isAuthenticated()
    read({
      userId: userId
    }, {t: jwt.token}).then((data) => {
      if (data.error)
        this.setState({redirectToSignin: true})
      else
        this.setState({user: data})
    })
}
```

`init(userId)`函数接受`userId`值，并调用读取用户获取方法。由于此方法还需要凭据来授权登录用户，因此 JWT 是使用`auth-helper.js`中的`isAuthenticated`方法从`sessionStorage`中检索的。一旦服务器响应，要么更新状态与用户信息，要么将视图重定向到登录视图。

`init`函数在`componentDidMount`和`componentWillReceiveProps`中被调用，并传入相关的`userId`值作为参数，以便在组件中获取和加载正确的用户信息。

`mern-skeleton/client/user/Profile.js`：

```jsx
componentDidMount = () => {
  this.init(this.match.params.userId)
}
componentWillReceiveProps = (props) => {
  this.init(props.match.params.userId)
}
```

在`render`函数中，我们设置了条件重定向到登录视图，并返回`Profile`视图的内容：

`mern-skeleton/client/user/Profile.js`：

```jsx
render() {
   const {classes} = this.props
   const redirectToSignin = this.state.redirectToSignin
   if (redirectToSignin)
     return <Redirect to='/signin'/>
   return (...)
 }
```

如果当前登录的用户正在查看另一个用户的配置文件，则`render`函数将返回`Profile`视图，并包含以下元素。

`mern-skeleton/client/user/Profile.js`：

```jsx
<div>
  <Paper className={classes.root} elevation={4}>
    <Typography type="title" className={classes.title}> Profile </Typography>
      <List dense>
        <ListItem>
          <ListItemAvatar>
             <Avatar>
               <Person/>
             </Avatar>
          </ListItemAvatar>
          <ListItemText primary={this.state.user.name} 
                       secondary={this.state.user.email}/>
        </ListItem>
        <Divider/>
        <ListItem>
          <ListItemText primary={"Joined: " + 
              (new Date(this.state.user.created)).toDateString()}/>
        </ListItem>
      </List>
  </Paper>
</div>
```

但是，如果当前登录的用户正在查看自己的配置文件，则可以在`Profile`组件中看到编辑和删除选项，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/a262128f-e3dd-41d9-b1ea-584aa9ffa927.png)

要实现此功能，在`Profile`中的第一个`ListItem`组件中添加一个包含`Edit`按钮和`DeleteUser`组件的`ListItemSecondaryAction`组件，根据当前用户是否查看自己的配置文件来有条件地呈现。

`mern-skeleton/client/user/Profile.js`：

```jsx
{ auth.isAuthenticated().user && auth.isAuthenticated().user._id == this.state.user._id &&
    (<ListItemSecondaryAction>
       <Link to={"/user/edit/" + this.state.user._id}>
         <IconButton color="primary">
           <Edit/>
         </IconButton>
       </Link>
       <DeleteUser userId={this.state.user._id}/>
    </ListItemSecondaryAction>)}
```

`Edit`按钮将路由到`EditProfile`组件，此处使用的自定义`DeleteUser`组件将处理传递给它的`userId`的删除操作。

要将`Profile`组件添加到应用程序中，请将`Route`添加到`Switch`组件中的`MainRouter`中。

`mern-skeleton/client/MainRouter.js`：

```jsx
<Route path="/user/:userId" component={Profile}/>
```

# EditProfile 组件

`client/user/EditProfile.js`中的`EditProfile`组件在实现上与`Signup`和`Profile`组件都有相似之处。它将允许授权用户在类似注册表单的表单中编辑自己的个人资料信息：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/0927ca58-eb21-4f74-97e9-fcc0d81d0943.png)

在`'/user/edit/:userId'`加载时，组件将通过验证 JWT 以获取 ID 的用户信息，然后使用接收到的用户信息加载表单。表单将允许用户仅编辑和提交更改的信息到`update` fetch 调用，并在成功更新后将用户重定向到具有更新信息的`Profile`视图。

`EditProfile`将以与`Profile`组件相同的方式加载用户信息，通过在`componentDidMount`中使用`read`从`this.match.params`获取`userId`参数，并使用`auth.isAuthenticated`的凭据。表单视图将具有与`Signup`组件相同的元素，输入值在更改时更新状态。

在表单提交时，组件将使用`userId`、JWT 和更新后的用户数据调用`update` fetch 方法。

`mern-skeleton/client/user/EditProfile.js`：

```jsx
clickSubmit = () => {
    const jwt = auth.isAuthenticated()
    const user = {
      name: this.state.name || undefined,
      email: this.state.email || undefined,
      password: this.state.password || undefined
    }
    update({
      userId: this.match.params.userId
    }, {
      t: jwt.token
    }, user).then((data) => {
      if (data.error) {
        this.setState({error: data.error})
      } else {
        this.setState({'userId': data._id, 'redirectToProfile': true})
      }
    })
}
```

根据服务器的响应，用户将要么看到错误消息，要么在渲染函数中使用以下`Redirect`组件重定向到更新后的 Profile 页面。

`mern-skeleton/client/user/EditProfile.js`：

```jsx
if (this.state.redirectToProfile)
   return (<Redirect to={'/user/' + this.state.userId}/>)
```

要将`EditProfile`组件添加到应用程序中，这次我们将使用`PrivateRoute`，以限制用户未登录时根本不加载组件。在`MainRouter`中的放置顺序也很重要。

`mern-skeleton/client/MainRouter.js`：

```jsx
<Switch>
  ... <PrivateRoute path="/user/edit/:userId" component={EditProfile}/><>
  <Route path="/user/:userId" component={Profile}/>
</Switch>
```

具有路径`'/user/edit/:userId'`的路由需要放置在具有路径`'/user/:userId'`的路由之前，以便在请求此路由时，编辑路径首先在 Switch 组件中独占匹配，不会与`Profile`路由混淆。

# DeleteUser 组件

`client/user/DeleteUser.js`中的`DeleteUser`组件基本上是一个按钮，我们将其添加到 Profile 视图中，当点击时会打开一个要求用户确认`delete`操作的`Dialog`组件：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/9107c796-0e36-4350-9124-4bcb51662b99.png)

该组件首先使用`open`设置为`false`来初始化`Dialog`组件的状态，并且还将`redirect`设置为`false`，因此首先不会被渲染。

`mern-skeleton/client/user/DeleteUser.js`：

```jsx
class DeleteUser extends Component {
  state = { redirect: false, open: false } 
...
```

接下来，我们需要处理打开和关闭`dialog`按钮的方法。当用户点击`delete`按钮时，对话框将被打开。

`mern-skeleton/client/user/DeleteUser.js`：

```jsx
clickButton = () => {
    this.setState({open: true})
}
```

当用户在对话框上点击`cancel`时，对话框将被关闭。

`mern-skeleton/client/user/DeleteUser.js`：

```jsx
  handleRequestClose = () => {
    this.setState({open: false})
  }
```

该组件将从`Profile`组件中作为属性传递的`userId`，这是调用`remove` fetch 方法所需的，同时还需要 JWT，用户在对话框中确认`delete`操作后。

`mern-skeleton/client/user/DeleteUser.js`：

```jsx
deleteAccount = () => {
    const jwt = auth.isAuthenticated() 
    remove({
      userId: this.props.userId
    }, {t: jwt.token}).then((data) => {
      if (data.error) {
        console.log(data.error)
      } else {
        auth.signout(() => console.log('deleted'))
 this.setState({redirect: true})
      }
    }) 
  }
```

确认后，`deleteAccount`函数使用来自属性的`userId`和来自`isAuthenticated`的 JWT 调用`remove` fetch 方法。在服务器成功删除后，用户将被注销并重定向到主页视图。

渲染函数包含对主页视图的条件性`Redirect`，并返回`DeleteUser`组件元素、`DeleteIcon`按钮和确认`Dialog`：

`mern-skeleton/client/user/DeleteUser.js`：

```jsx
render() {
    const redirect = this.state.redirect
    if (redirect) {
      return <Redirect to='/'/>
    }
    return (<span>
      <IconButton aria-label="Delete" onClick={this.clickButton} 
      color="secondary">
        <DeleteIcon/>
      </IconButton>
      <Dialog open={this.state.open} onClose={this.handleRequestClose}>
        <DialogTitle>{"Delete Account"}</DialogTitle>
        <DialogContent>
          <DialogContentText>
            Confirm to delete your account.
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={this.handleRequestClose} color="primary">
            Cancel
          </Button>
          <Button onClick={this.deleteAccount} color="secondary" 
          autoFocus="autoFocus">
            Confirm
          </Button>
        </DialogActions>
      </Dialog>
    </span>)
}
```

`DeleteUser`将`userId`作为属性传递，用于`delete` fetch 调用，因此我们为所需的属性`userId`添加了`propType`检查。

`mern-skeleton/client/user/DeleteUser.js`：

```jsx
DeleteUser.propTypes = {
  userId: PropTypes.string.isRequired
}
```

由于我们在`Profile`组件中使用`DeleteUser`组件，所以当`Profile`添加到`MainRouter`中时，它将被添加到应用视图中。

# 菜单组件

`Menu`组件将作为整个前端应用程序的导航栏，提供到所有可用视图的链接，并指示应用程序中的当前位置。

为了实现这些导航栏功能，我们将使用 React Router 中的 HOC `withRouter`来访问历史对象的属性。`Menu`组件中的以下代码仅添加了标题、与根路由相关联的`Home`图标以及与`'/users'`路由相关联的`Users`按钮。

`mern-skeleton/client/core/Menu.js`：

```jsx
const Menu = withRouter(({history}) => (<div>
  <AppBar position="static">
    <Toolbar>
      <Typography type="title" color="inherit">
        MERN Skeleton
      </Typography>
      <Link to="/">
        <IconButton aria-label="Home" style={isActive(history, "/")}>
          <HomeIcon/>
        </IconButton>
      </Link>
      <Link to="/users">
        <Button style={isActive(history, "/users")}>Users</Button>
      </Link>
    </Toolbar>
  </AppBar>
</div>))
```

为了指示应用程序的当前位置在`Menu`上，我们将通过条件性地改变颜色来突出显示与当前位置路径匹配的链接。

`mern-skeleton/client/core/Menu.js`：

```jsx
const isActive = (history, path) => {
  if (history.location.pathname == path)
    return {color: '#ff4081'}
  else
    return {color: '#ffffff'}
}
```

`isActive`函数用于在`Menu`中为按钮应用颜色，如下所示：

```jsx
style={isActive(history, "/users")}
```

剩下的链接，如 SIGN IN、SIGN UP、MY PROFILE 和 SIGN OUT，将根据用户是否已登录显示在`Menu`上：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/0771a0a9-9fbc-4b22-b1d7-4b195a068d13.png)

例如，当用户未登录时，注册和登录的链接应该只显示在菜单上。因此，我们需要在`Menu`组件中添加它，并在`Users`按钮之后加上条件。

`mern-skeleton/client/core/Menu.js`：

```jsx
{!auth.isAuthenticated() && (<span>
    <Link to="/signup">
       <Button style={isActive(history, "/signup")}> Sign Up </Button>
    </Link>
    <Link to="/signin">
       <Button style={isActive(history, "/signin")}> Sign In </Button>
    </Link>
</span>)}
```

类似地，只有当用户已登录时，`MY PROFILE`链接和`SIGN OUT`按钮才应该显示在菜单上，并且应该根据这个条件检查添加到`Menu`组件中。

`mern-skeleton/client/core/Menu.js`：

```jsx
{auth.isAuthenticated() && (<span>
   <Link to={"/user/" + auth.isAuthenticated().user._id}>
      <Button style={isActive(history, "/user/" + auth.isAuthenticated().user._id)}>
           My Profile 
      </Button>
   </Link>
   <Button color="inherit" 
           onClick={() => { auth.signout(() => history.push('/')) }}>
        Sign out
   </Button>
 </span>)}
```

`MY PROFILE`按钮使用已登录用户的信息链接到用户自己的个人资料，并且`SIGN OUT`按钮在点击时调用`auth.signout()`方法。当用户已登录时，菜单将如下所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/0cab70a8-b7d1-461c-93f7-6ba69b4281af.png)

为了在所有视图中显示`Menu`导航栏，我们需要在`MainRouter`中添加它，放在所有其他路由之前，并且在`Switch`组件之外。

`mern-skeleton/client/MainRouter.js`：

```jsx
 <Menu/>
    <Switch>
    …
    </Switch>
```

当在路由上访问组件时，这将使`Menu`组件呈现在所有其他组件的顶部。

骨架前端已经完整，包括所有必要的组件，以便用户可以在后端注册、查看和修改用户数据，并考虑到认证和授权限制。然而，目前还不能直接在浏览器地址栏中访问前端路由，只能在前端视图内部链接时访问。为了在骨架应用程序中实现此功能，我们需要实现基本的服务器端渲染。

# 基本的服务器端渲染

目前，当 React Router 路由或路径名直接输入到浏览器地址栏，或者刷新不在根路径的视图时，URL 无法工作。这是因为服务器无法识别 React Router 路由。我们需要在后端实现基本的服务器端渲染，以便服务器在收到对前端路由的请求时能够响应。

在服务器接收到前端路由的请求时，我们需要根据 React Router 和 Material-UI 组件在服务器端正确渲染相关的 React 组件。

React 应用程序服务器端渲染的基本思想是使用`react-dom`中的`renderToString`方法将根 React 组件转换为标记字符串，并将其附加到服务器在接收到请求时渲染的模板上。

在`express.js`中，我们将用代码替换对`'/'`的`GET`请求返回`template.js`的代码，该代码在接收到任何传入的 GET 请求时，生成相关 React 组件的服务器端渲染标记，并将此标记添加到模板中。此代码将具有以下结构：

```jsx
app.get('*', (req, res) => {
     // 1\. Prepare Material-UI styles
     // 2\. Generate markup with renderToString
     // 3\. Return template with markup and CSS styles in the response
})
```

# 用于服务器端渲染的模块

为了实现基本的服务器端渲染，我们需要将以下 React、React Router 和 Material-UI 特定模块导入到服务器代码中。在我们的代码结构中，这些模块将被导入到`server/express.js`中：

+   **React 模块**：用于渲染 React 组件和使用`renderToString`：

```jsx
import React from 'react'
import ReactDOMServer from 'react-dom/server'
```

+   **Router 模块**：`StaticRouter`是一个无状态路由器，它接受请求的 URL 以匹配前端路由和`MainRouter`组件，这是我们前端的根组件：

```jsx
import StaticRouter from 'react-router-dom/StaticRouter'
import MainRouter from './../client/MainRouter'
```

+   **Material-UI 模块**：以下模块将帮助基于前端使用的 Material-UI 主题为前端组件生成 CSS 样式：

```jsx
import { SheetsRegistry } from 'react-jss/lib/jss'
import JssProvider from 'react-jss/lib/JssProvider'
import { MuiThemeProvider, createMuiTheme, createGenerateClassName } from 'material-ui/styles'
import { indigo, pink } from 'material-ui/colors'
```

有了这些模块，我们可以准备、生成和返回服务器端渲染的前端代码。

# 为 SSR 准备 Material-UI 样式

当服务器接收到任何请求时，在响应包含 React 视图的生成标记之前，我们需要准备应该添加到标记中的 CSS 样式，以便 UI 在初始渲染时不会中断。

`mern-skeleton/server/express.js`：

```jsx
const sheetsRegistry = new SheetsRegistry()
const theme = createMuiTheme({
    palette: {
      primary: {
      light: '#757de8',
      main: '#3f51b5',
      dark: '#002984',
      contrastText: '#fff',
    },
    secondary: {
      light: '#ff79b0',
      main: '#ff4081',
      dark: '#c60055',
      contrastText: '#000',
    },
      openTitle: indigo['400'],
      protectedTitle: pink['400'],
      type: 'light'
    },
})
const generateClassName = createGenerateClassName()
```

为了注入 Material-UI 样式，在每个请求上，我们首先生成一个新的`SheetsRegistry`和 MUI 主题实例，与前端代码中使用的相匹配。

# 生成标记

使用`renderToString`的目的是生成要响应请求的用户显示的 React 组件的 HTML 字符串版本：

`mern-skeleton/server/express.js`：

```jsx
const context = {} 
const markup = ReactDOMServer.renderToString(
      <StaticRouter location={req.url} context={context}>
        <JssProvider registry={sheetsRegistry} generateClassName=
 {generateClassName}>
          <MuiThemeProvider theme={theme} sheetsManager={new Map()}>
            <MainRouter/>
          </MuiThemeProvider>
        </JssProvider>
      </StaticRouter>
) 
```

客户端应用程序的根组件`MainRouter`被 Material-UI 主题和 JSS 包裹，以提供`MainRouter`子组件所需的样式属性。在这里使用无状态的`StaticRouter`代替客户端使用的`BrowserRouter`，来包裹`MainRouter`并提供在实现客户端组件时使用的路由属性。基于这些值，例如请求的`location`路由和作为属性传递给包装组件的主题，`renderToString`将返回包含相关视图的标记。

# 发送包含标记和 CSS 的模板

一旦生成了标记，我们首先检查组件中是否有渲染的`redirect`，以便在标记中发送。如果没有重定向，那么我们从`sheetsRegistry`生成 CSS 字符串，并在响应中发送带有标记和注入的 CSS 的模板。

`mern-skeleton/server/express.js`：

```jsx
if (context.url) {
   return res.redirect(303, context.url)
}
const css = sheetsRegistry.toString()
res.status(200).send(Template({
   markup: markup,
   css: css
}))
```

在组件中渲染重定向的一个例子是尝试通过服务器端渲染访问`PrivateRoute`时。由于服务器端无法从客户端的`sessionStorage`访问 auth 令牌，`PrivateRoute`中的重定向将被渲染。在这种情况下，`context.url`将具有`'/signin'`路由，因此不会尝试渲染`PrivateRoute`组件，而是重定向到`'/signin'`路由。

# 更新 template.js

在服务器上生成的标记和 CSS 必须添加到`template.js`的 HTML 代码中，以便在服务器渲染模板时加载。

`mern-skeleton/template.js`：

```jsx
export default ({markup, css}) => {
    return `...
           <div id="root">${markup}</div>
           <style id="jss-server-side">${css}</style> 
           ...`
}
```

# 更新 MainRouter

一旦在服务器端渲染的代码到达浏览器，并且前端脚本接管后，我们需要在主组件挂载时移除服务器端注入的 CSS。这将完全控制 React 应用程序的渲染权力交给客户端：

`mern-skeleton/client/MainRouter.js`：

```jsx
componentDidMount() {
   const jssStyles = document.getElementById('jss-server-side')
   if (jssStyles && jssStyles.parentNode)
      jssStyles.parentNode.removeChild(jssStyles)
}
```

# 用 hydrate 代替 render

现在 React 组件将在服务器端渲染，我们可以更新`main.js`代码，使用`ReactDOM.hydrate()`代替`ReactDOM.render()`：

```jsx
import React from 'react'
import { hydrate } from 'react-dom'
import App from './App'

hydrate(<App/>, document.getElementById('root'))
```

`hydrate`函数用于给已由`ReactDOMServer`渲染的 HTML 内容进行水合。这意味着服务器端渲染的标记将被保留，只有当 React 在浏览器中接管时才会附加事件处理程序，从而使初始加载性能更好。

通过实现基本的服务器端渲染，服务器现在可以正确处理浏览器地址栏对前端路由的直接请求，从而可以将 React 前端视图加入书签。

这里开发的骨架 MERN 应用程序现在是一个具有基本用户功能的完全功能的 MERN Web 应用程序。我们可以扩展这个骨架中的代码，为不同的应用程序添加各种功能。

# 总结

在本章中，我们通过添加一个工作的 React 前端完成了 MERN 骨架应用程序，包括前端路由和 React 视图的基本服务器端渲染。

我们首先更新了开发流程，以包括用于 React 视图的客户端代码捆绑。我们更新了 Webpack 和 Babel 的配置以编译 React 代码，并讨论了如何从 Express 应用程序加载配置的 Webpack 中间件，以便在开发过程中从一个地方启动服务器端和客户端代码的编译。

在更新开发流程并构建前端之前，我们添加了相关的 React 依赖项，以及用于前端路由的 React Router 和用于在骨架应用程序的用户界面中使用现有组件的 Material-UI。

然后，我们实现了顶层根 React 组件，并集成了 React Router，这使我们能够添加用于导航的客户端路由。使用这些路由，我们加载了使用 Material-UI 组件开发的自定义 React 组件，以构成骨架应用程序的用户界面。

为了使这些 React 视图能够与从后端获取的数据动态交互，我们使用 Fetch API 连接到后端用户 API。然后，我们使用`sessionStorage`存储用户特定的细节和从服务器成功登录时获取的 JWT，还通过使用`PrivateRoute`组件限制对某些视图的访问来在前端视图上实现身份验证和授权。

最后，我们修改了服务器代码，实现了基本的服务器端渲染，允许在服务器识别到传入请求实际上是针对 React 路由时，在浏览器中直接加载经服务器端渲染的标记。

在下一章中，我们将利用开发这个基本的 MERN 应用程序时学到的概念，扩展骨架应用程序的代码，构建一个功能齐全的社交媒体应用程序。


# 第五章：从一个简单的社交媒体应用程序开始

社交媒体是当今网络的一个重要组成部分，我们构建的许多以用户为中心的网络应用程序最终都需要社交组件来推动用户参与。

对于我们的第一个真实世界 MERN 应用程序，我们将修改和扩展上一章开发的 MERN 骨架应用程序，以构建一个简单的社交媒体应用程序。

在本章中，我们将介绍以下社交媒体风格功能的实现：

+   带有描述和照片的用户个人资料

+   用户互相关注

+   关注建议

+   发布带有照片的消息

+   来自关注用户的帖子的新闻订阅

+   按用户列出帖子

+   点赞帖子

+   评论帖子

# MERN Social

MERN Social 是一个受现有社交媒体平台（如 Facebook 和 Twitter）启发的具有基本功能的社交媒体应用程序。该应用程序的主要目的是演示如何使用 MERN 堆栈技术来实现允许用户在内容上连接和互动的功能。您可以根据需要进一步扩展这些实现，以实现更复杂的功能：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/677fef10-8bc2-489d-bccd-c58aa24901af.png)完整的 MERN Social 应用程序代码可在 GitHub 的[github.com/shamahoque/mern-social](https://github.com/shamahoque/mern-social)存储库中找到。您可以在阅读本章其余部分的代码解释时，克隆此代码并运行应用程序。

MERN Social 应用程序所需的视图将通过扩展和修改 MERN 骨架应用程序中的现有 React 组件来开发。我们还将添加新的自定义组件来组成视图，包括一个新闻订阅视图，用户可以在其中创建新帖子，并浏览 MERN Social 上关注的所有人的帖子列表。以下组件树显示了构成 MERN Social 前端的所有自定义 React 组件，还公开了我们将用于构建本章其余部分视图的组合结构：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/e782c1f5-ce25-46b7-a015-256e6c5017e8.jpg)

# 更新用户个人资料

骨架应用程序只支持用户的姓名、电子邮件和密码。但在 MERN Social 中，我们将允许用户在注册后编辑个人资料时添加关于自己的描述，并上传个人资料照片：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/d14f75f1-492f-4e8f-aa1c-2d42644348bc.png)

# 添加关于描述

为了存储用户在“关于”字段中输入的描述，我们需要在`server/models/user.model.js`中的用户模型中添加一个`about`字段：

```jsx
about: {
    type: String,
    trim: true
  }
```

然后，为了从用户那里获取描述作为输入，我们在`EditProfile`表单中添加一个多行的`TextField`，并且处理值的变化方式与我们为用户的名称输入所做的方式相同。

`mern-social/client/user/EditProfile.js`：

```jsx
  <TextField
      id="multiline-flexible"
      label="About"
      multiline
      rows="2"
      value={this.state.about}
      onChange={this.handleChange('about')}
   />
```

最后，为了显示添加到用户个人资料页面的“关于”字段的描述文本，我们可以将其添加到现有的个人资料视图中。

`mern-social/client/user/Profile.js`：

```jsx
<ListItem> <ListItemText primary={this.state.user.about}/> </ListItem>
```

通过对 MERN 骨架代码中用户功能的修改，用户现在可以添加和更新有关自己的描述，以便在其个人资料上显示。

# 上传个人资料照片

允许用户上传个人资料照片将需要我们存储上传的图像文件，并在请求时检索它以在视图中加载。考虑到不同的文件存储选项，有多种实现此上传功能的方法：

+   **服务器文件系统**：上传并将文件保存到服务器文件系统，并将 URL 存储到 MongoDB 中

+   **外部文件存储**：将文件保存到外部存储（如 Amazon S3），并将 URL 存储在 MongoDB 中

+   **将数据存储在 MongoDB 中**：将小型文件（小于 16 MB）保存到 MongoDB 中作为缓冲区类型的数据

对于 MERN Social，我们将假设用户上传的照片文件将是小型的，并演示如何将这些文件存储在 MongoDB 中以实现个人资料照片上传功能。在第八章中，*构建媒体流应用程序*，我们将讨论如何使用 GridFS 在 MongoDB 中存储较大的文件。

# 更新用户模型以在 MongoDB 中存储照片

为了直接将上传的个人资料照片存储在数据库中，我们将更新用户模型以添加一个`photo`字段，该字段将文件作为`Buffer`类型的`data`存储，并附带其`contentType`。

`mern-social/server/models/user.model.js`：

```jsx
photo: {
    data: Buffer,
    contentType: String
}
```

# 从编辑表单上传照片

用户将能够在编辑个人资料时从其本地文件中上传图像文件。我们将在`client/user/EditProfile.js`中更新`EditProfile`组件，添加一个上传照片选项，然后将用户选择的文件附加到提交给服务器的表单数据中。

# 使用 Material-UI 的文件输入

我们将利用 HTML5 文件输入类型，让用户从其本地文件中选择图像。当用户选择文件时，文件输入将在更改事件中返回文件名。

`mern-social/client/user/EditProfile.js`：

```jsx
<input accept="image/*" type="file"
       onChange={this.handleChange('photo')} 
       style={{display:'none'}} 
       id="icon-button-file" />
```

为了将此文件`input`与 Material-UI 组件集成，我们将`display:none`应用于隐藏`input`元素，然后在此文件输入的标签中添加一个 Material-UI 按钮。这样，视图将显示 Material-UI 按钮，而不是 HTML5 文件输入元素。

`mern-social/client/user/EditProfile.js`：

```jsx
<label htmlFor="icon-button-file">
   <Button variant="raised" color="default" component="span">
      Upload <FileUpload/>
   </Button>
</label>
```

将`Button`的组件属性设置为`span`，`Button`组件将呈现为`label`元素内的`span`元素。单击`Upload` span 或 label 将由具有与 label 相同 ID 的文件输入注册，因此将打开文件选择对话框。用户选择文件后，我们可以在调用`handleChange(...)`中将其设置为状态，并在视图中显示名称。

`mern-social/client/user/EditProfile.js`：

```jsx
<span className={classes.filename}>
    {this.state.photo ? this.state.photo.name : ''}
</span>
```

# 带有附加文件的表单提交

通过表单将文件上传到服务器需要一个多部分表单提交，与之前的实现中发送的`stringed`对象形成对比。我们将修改`EditProfile`组件，使用`FormData` API 将表单数据存储在编码类型`multipart/form-data`所需的格式中。

首先，我们需要在`componentDidMount()`中初始化`FormData`。

`mern-social/client/user/EditProfile.js`：

```jsx
this.userData = new FormData() 
```

接下来，我们将更新输入`handleChange`函数，以存储文本字段和文件输入的输入值在`FormData`中。

`mern-social/client/user/EditProfile.js`：

```jsx
handleChange = name => event => {
  const value = name === 'photo'
    ? event.target.files[0]
    : event.target.value
  this.userData.set(name, value)
  this.setState({ [name]: value })
}
```

然后在提交时，`this.userData`将与 fetch API 调用一起发送到更新用户。由于发送到服务器的数据的内容类型不再是`'application/json'`，因此我们还需要修改`api-user.js`中的`update` fetch 方法，以在`fetch`调用中从标头中删除`Content-Type`。

`mern-social/client/user/api-user.js`：

```jsx
const update = (params, credentials, user) => {
  return fetch('/api/users/' + params.userId, {
    method: 'PUT',
    headers: {
      'Accept': 'application/json',
      'Authorization': 'Bearer ' + credentials.t
    },
    body: user
  }).then((response) => {
    return response.json()
  }).catch((e) => {
    console.log(e)
  })
}
```

现在，如果用户选择在编辑配置文件时上传个人资料照片，服务器将收到附加文件的请求以及其他字段值。

在[developer.mozilla.org/en-US/docs/Web/API/FormData](https://developer.mozilla.org/en-US/docs/Web/API/FormData)上了解有关 FormData API 的更多信息。

# 处理包含文件上传的请求

在服务器上，为了处理可能包含文件的更新 API 的请求，我们将使用`formidable` npm 模块：

```jsx
npm install --save formidable
```

Formidable 将允许我们读取`multipart`表单数据，从而访问字段和文件（如果有）。如果有文件，`formidable`将在文件系统中临时存储它。我们将从文件系统中读取它，使用`fs`模块检索文件类型和数据，并将其存储到用户模型中的照片字段中。`formidable`代码将放在`user.controller.js`中的`update`控制器中。

`mern-social/server/controllers/user.controller.js`：

```jsx
import formidable from 'formidable'
import fs from 'fs'
const update = (req, res, next) => {
  let form = new formidable.IncomingForm()
  form.keepExtensions = true
  form.parse(req, (err, fields, files) => {
    if (err) {
      return res.status(400).json({
        error: "Photo could not be uploaded"
      })
    }
    let user = req.profile
    user = _.extend(user, fields)
    user.updated = Date.now()
    if(files.photo){
      user.photo.data = fs.readFileSync(files.photo.path)
      user.photo.contentType = files.photo.type
    }
    user.save((err, result) => {
      if (err) {
        return res.status(400).json({
          error: errorHandler.getErrorMessage(err)
        })
      }
      user.hashed_password = undefined
      user.salt = undefined
      res.json(user)
    })
  })
}
```

这将把上传的文件存储为数据库中的数据。接下来，我们将设置文件检索以能够在前端视图中访问和显示用户上传的照片。

# 检索个人资料照片

从数据库中检索文件并在视图中显示的最简单选项是设置一个路由，该路由将获取数据并将其作为图像文件返回给请求的客户端。

# 个人资料照片 URL

我们将为每个用户在数据库中存储的照片设置一个路由，并添加另一个路由，如果给定用户没有上传个人资料照片，则将获取默认照片。

`mern-social/server/routes/user.routes.js`：

```jsx
router.route('/api/users/photo/:userId')
  .get(userCtrl.photo, userCtrl.defaultPhoto)
router.route('/api/users/defaultphoto')
  .get(userCtrl.defaultPhoto)
```

我们将在`photo`控制器方法中查找照片，如果找到，就将其发送到照片路由的请求中作为响应，否则我们调用`next()`来返回默认照片。

`mern-social/server/controllers/user.controller.js`：

```jsx
const photo = (req, res, next) => {
  if(req.profile.photo.data){
    res.set("Content-Type", req.profile.photo.contentType)
    return res.send(req.profile.photo.data)
  }
  next()
}
```

默认照片是从服务器的文件系统中检索并发送的。

`mern-social/server/controllers/user.controller.js`：

```jsx
import profileImage from './../../client/assets/images/profile-pic.png'
const defaultPhoto = (req, res) => {
  return res.sendFile(process.cwd()+profileImage)
}
```

# 在视图中显示照片

设置照片 URL 路由以检索照片后，我们可以简单地在`img`元素的`src`属性中使用这些路由来加载视图中的照片。例如，在`Profile`组件中，我们从状态中获取用户 ID 并使用它来构建照片 URL。

`mern-social/client/user/Profile.js`：

```jsx
const photoUrl = this.state.user._id
          ? `/api/users/photo/${this.state.user._id}?${new Date().getTime()}`
          : '/api/users/defaultphoto'
```

为了确保在编辑中更新照片后`Profile`视图中的`img`元素重新加载，我们还向照片 URL 添加了一个时间值，以绕过浏览器的默认图像缓存行为。

然后，我们可以将`photoUrl`设置为 Material-UI 的`Avatar`组件，该组件在视图中呈现链接的图像：

```jsx
  <Avatar src={photoUrl}/>
```

在 MERN Social 中更新的用户个人资料现在可以显示用户上传的个人资料照片和`about`描述：

！[](assets/8e568b24-3f3c-4d32-aabb-f2eaabbeca3a.png)

# 在 MERN Social 中关注用户

在 MERN Social 中，用户将能够互相关注。每个用户将拥有一个关注者列表和一个他们关注的人的列表。用户还将能够看到他们可以关注的用户列表；换句话说，MERN Social 中他们尚未关注的用户。

# 关注和取消关注

为了跟踪哪个用户正在关注哪些其他用户，我们将不得不为每个用户维护两个列表。当一个用户关注或取消关注另一个用户时，我们将更新一个用户的`following`列表和另一个用户的`followers`列表。

# 更新用户模型

为了在数据库中存储`following`和`followers`列表，我们将使用两个用户引用数组更新用户模型。

`mern-social/server/models/user.model.js`:

```jsx
following: [{type: mongoose.Schema.ObjectId, ref: 'User'}],
followers: [{type: mongoose.Schema.ObjectId, ref: 'User'}]
```

这些引用将指向正在被关注或正在关注给定用户的集合中的用户。

# 更新`userByID`控制器方法

当从后端检索到单个用户时，我们希望`user`对象包括`following`和`followers`数组中引用的用户的名称和 ID。为了检索这些详细信息，我们需要更新`userByID`控制器方法以填充返回的用户对象。

`mern-social/server/controllers/user.controller.js`:

```jsx
const userByID = (req, res, next, id) => {
  User.findById(id)
    .populate('following', '_id name')
    .populate('followers', '_id name')
    .exec((err, user) => {
    if (err || !user) return res.status('400').json({
      error: "User not found"
    })
    req.profile = user
    next()
  })
}
```

我们使用 Mongoose 的`populate`方法来指定从查询返回的用户对象应包含`following`和`followers`列表中引用的用户的名称和 ID。这将在我们使用读取 API 调用获取用户时，给我们`followers`和`following`列表中的用户引用的名称和 ID。

# 关注和取消关注的 API

当用户从视图中关注或取消关注另一个用户时，数据库中的两个用户记录将响应`follow`或`unfollow`请求而更新。

我们将在`user.routes.js`中设置`follow`和`unfollow`路由如下。

`mern-social/server/routes/user.routes.js`:

```jsx
router.route('/api/users/follow')
  .put(authCtrl.requireSignin, userCtrl.addFollowing, userCtrl.addFollower)
router.route('/api/users/unfollow')
  .put(authCtrl.requireSignin, userCtrl.removeFollowing, userCtrl.removeFollower)
```

用户控制器中的`addFollowing`控制器方法将通过将被关注用户的引用推入数组来更新当前用户的`'following'`数组。

`mern-social/server/controllers/user.controller.js`:

```jsx
const addFollowing = (req, res, next) => {
  User.findByIdAndUpdate(req.body.userId, {$push: {following: req.body.followId}}, (err, result) => {
    if (err) {
      return res.status(400).json({
        error: errorHandler.getErrorMessage(err)
      })
    }
    next()
  })
}
```

在`following`数组成功更新后，将执行`addFollower`方法，将当前用户的引用添加到被关注用户的`'followers'`数组中。

`mern-social/server/controllers/user.controller.js`:

```jsx
const addFollower = (req, res) => {
  User.findByIdAndUpdate(req.body.followId, {$push: {followers: req.body.userId}}, {new: true})
  .populate('following', '_id name')
  .populate('followers', '_id name')
  .exec((err, result) => {
    if (err) {
      return res.status(400).json({
        error: errorHandler.getErrorMessage(err)
      })
    }
    result.hashed_password = undefined
    result.salt = undefined
    res.json(result)
  })
}
```

对于取消关注，实现方式类似。`removeFollowing`和`removeFollower`控制器方法通过使用`$pull`而不是`$push`从相应的`'following'`和`'followers'`数组中删除用户引用。

`mern-social/server/controllers/user.controller.js`:

```jsx
const removeFollowing = (req, res, next) => {
  User.findByIdAndUpdate(req.body.userId, {$pull: {following: req.body.unfollowId}}, (err, result) => {
    if (err) {
      return res.status(400).json({
        error: errorHandler.getErrorMessage(err)
      })
    }
    next()
  })
}
const removeFollower = (req, res) => {
  User.findByIdAndUpdate(req.body.unfollowId, {$pull: {followers: req.body.userId}}, {new: true})
  .populate('following', '_id name')
  .populate('followers', '_id name')
  .exec((err, result) => {
    if (err) {
      return res.status(400).json({
        error: errorHandler.getErrorMessage(err)
      })
    }
    result.hashed_password = undefined
    result.salt = undefined
    res.json(result)
  })
}
```

# 在视图中访问关注和取消关注的 API

为了在视图中访问这些 API 调用，我们将使用`api-user.js`更新`follow`和`unfollow` fetch 方法。`follow`和`unfollow`方法将类似，使用当前用户的 ID 和凭据以及被关注或取消关注的用户的 ID 调用相应的路由。`follow`方法将如下所示。

`mern-social/client/user/api-user.js`:

```jsx
const follow = (params, credentials, followId) => {
  return fetch('/api/users/follow/', {
    method: 'PUT',
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json',
      'Authorization': 'Bearer ' + credentials.t
    },
    body: JSON.stringify({userId:params.userId, followId: followId})
  }).then((response) => {
    return response.json()
  }).catch((err) => {
    console.log(err)
  }) 
}
```

`unfollow`的 fetch 方法类似，它获取取消关注的用户 ID，并调用`unfollow` API。

`mern-social/client/user/api-user.js`:

```jsx
const unfollow = (params, credentials, unfollowId) => {
  return fetch('/api/users/unfollow/', {
    method: 'PUT',
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json',
      'Authorization': 'Bearer ' + credentials.t
    },
    body: JSON.stringify({userId:params.userId, unfollowId: unfollowId})
  }).then((response) => {
    return response.json()
  }).catch((err) => {
    console.log(err)
  })
}
```

# 关注和取消关注按钮

该按钮将允许用户有条件地关注或取消关注另一个用户，具体取决于当前用户是否已关注该用户：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/57d66ca2-131d-4717-8bae-2c74b263fbb7.png)

# FollowProfileButton 组件

我们将为关注按钮创建一个单独的组件，称为`FollowProfileButton`，它将添加到`Profile`组件中。该组件将根据当前用户是否已关注个人资料中的用户来显示`Follow`或`Unfollow`按钮。`FollowProfileButton`组件将如下所示。

`mern-social/client/user/FollowProfileButton.js`:

```jsx
class FollowProfileButton extends Component {
  followClick = () => {
    this.props.onButtonClick(follow)
  }
  unfollowClick = () => {
    this.props.onButtonClick(unfollow)
  }
  render() {
    return (<div>
      { this.props.following
        ? (<Button variant="raised" color="secondary" onClick=
       {this.unfollowClick}>Unfollow</Button>)
        : (<Button variant="raised" color="primary" onClick=
       {this.followClick}>Follow</Button>)
      }
    </div>)
  }
}
FollowProfileButton.propTypes = {
  following: PropTypes.bool.isRequired,
  onButtonClick: PropTypes.func.isRequired
}
```

当`FollowProfileButton`添加到个人资料时，`'following'`值将从`Profile`组件确定并作为 prop 发送到`FollowProfileButton`，同时还会发送点击处理程序，该处理程序将特定的`follow`或`unfollow` fetch API 作为参数调用：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/4854d95a-4432-44cf-9139-809cafb413dd.png)

# 更新个人资料组件

在`Profile`视图中，只有在用户查看其他用户的个人资料时才应显示`FollowProfileButton`，因此我们需要修改在查看个人资料时显示`Edit`和`Delete`按钮的条件如下：

```jsx
{auth.isAuthenticated().user && auth.isAuthenticated().user._id == this.state.user._id 
    ? (edit and delete buttons) 
    : (follow button)
}
```

在`Profile`组件中，在`componentDidMount`成功获取用户数据后，我们将检查已登录用户是否已关注个人资料中的用户，并将`following`值设置为状态。

`mern-social/client/user/Profile.js`:

```jsx
let following = this.checkFollow(data) 
this.setState({user: data, following: following}) 
```

为了确定在`following`中设置的值，`checkFollow`方法将检查登录用户是否存在于获取的用户的关注者列表中，如果找到，则返回`match`，否则如果找不到匹配，则返回`undefined`。

`mern-social/client/user/Profile.js`：

```jsx
checkFollow = (user) => {
    const jwt = auth.isAuthenticated()
    const match = user.followers.find((follower)=> {
      return follower._id == jwt.user._id
    })
    return match
}
```

`Profile`组件还将为`FollowProfileButton`定义点击处理程序，因此当关注或取消关注操作完成时，可以更新`Profile`的状态。

`mern-social/client/user/Profile.js`：

```jsx
clickFollowButton = (callApi) => {
    const jwt = auth.isAuthenticated()
    callApi({
      userId: jwt.user._id
    }, {
      t: jwt.token
    }, this.state.user._id).then((data) => {
      if (data.error) {
        this.setState({error: data.error})
      } else {
        this.setState({user: data, following: !this.state.following})
      }
    })
}
```

点击处理程序定义将获取 API 调用作为参数，并在将其添加到`Profile`视图时，将其与`following`值一起作为 prop 传递给`FollowProfileButton`。

`mern-social/client/user/Profile.js`：

```jsx
<FollowProfileButton following={this.state.following} onButtonClick={this.clickFollowButton}/>
```

# 列出关注者和粉丝

在每个用户的个人资料中，我们将添加一个关注者列表和他们正在关注的人的列表：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/5efeb7d7-ccdc-418b-942f-790be8a838b3.png)

在使用`read` API 加载个人资料时，`following`和`followers`列表中引用的用户的详细信息已经在用户对象中。为了呈现这些单独的关注者和正在关注的人列表，我们将创建一个名为`FollowGrid`的新组件。

# FollowGrid 组件

`FollowGrid`组件将接受用户列表作为 props，显示用户的头像和名称，并链接到每个用户的个人资料。我们可以根据需要将此组件添加到`Profile`视图中，以显示`followings`或`followers`。

`mern-social/client/user/FollowGrid.js`：

```jsx
class FollowGrid extends Component {
  render() {
    const {classes} = this.props
    return (<div className={classes.root}>
      <GridList cellHeight={160} className={classes.gridList} cols={4}>
        {this.props.people.map((person, i) => {
           return <GridListTile style={{'height':120}} key={i}>
              <Link to={"/user/" + person._id}>
                <Avatar src={'/api/users/photo/'+person._id} className=
               {classes.bigAvatar}/>
                <Typography className={classes.tileText}>{person.name}
               </Typography>
              </Link>
            </GridListTile>
        })}
      </GridList>
    </div>)
  }
}

FollowGrid.propTypes = {
  classes: PropTypes.object.isRequired,
  people: PropTypes.array.isRequired
}
```

要将`FollowGrid`组件添加到`Profile`视图中，我们可以根据需要将其放置在视图中，并将`followers`或`followings`列表作为`people` prop 传递：

```jsx
<FollowGrid people={this.state.user.followers}/>
<FollowGrid people={this.state.user.following}/>
```

如前所述，在 MERN 社交中，我们选择在`Profile`组件内的选项卡中显示`FollowGrid`组件。我们使用 Material-UI 选项卡组件创建了一个单独的`ProfileTabs`组件，并将其添加到`Profile`组件中。这个`ProfileTabs`组件包含两个`FollowGrid`组件，其中包含关注者和粉丝列表，以及一个`PostList`组件，显示用户的帖子。这将在本章后面讨论。

# 寻找要关注的人

“谁来关注”功能将向登录用户显示 MERN 社交中他们当前未关注的人的列表，提供关注他们或查看他们的个人资料的选项：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/efd564df-5075-4d35-abfe-a7eff7add251.png)

# 获取未关注的用户

我们将在服务器上实现一个新的 API 来查询数据库并获取当前用户未关注的用户列表。

`mern-social/server/routes/user.routes.js`:

```jsx
router.route('/api/users/findpeople/:userId')
   .get(authCtrl.requireSignin, userCtrl.findPeople)
```

在`findPeople`控制器方法中，我们将查询数据库中的用户集合，以查找当前用户`following`列表中没有的用户。

`mern-social/server/controllers/user.controller.js`:

```jsx
const findPeople = (req, res) => {
  let following = req.profile.following
  following.push(req.profile._id)
  User.find({ _id: { $nin : following } }, (err, users) => {
    if (err) {
      return res.status(400).json({
        error: errorHandler.getErrorMessage(err)
      })
    }
    res.json(users)
  }).select('name')
}
```

为了在前端使用这个用户列表，我们将更新`api-user.js`以添加对这个查找用户 API 的获取。

`mern-social/client/user/api-user.js`:

```jsx
const findPeople = (params, credentials) => {
  return fetch('/api/users/findpeople/' + params.userId, {
    method: 'GET',
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json',
      'Authorization': 'Bearer ' + credentials.t
    }
  }).then((response) => {
    return response.json()
  }).catch((err) => console.log(err))
}
```

# FindPeople 组件

为了显示*谁来关注*功能，我们将创建一个名为`FindPeople`的组件，可以添加到任何视图中或单独呈现。在这个组件中，我们将首先通过调用`componentDidMount`中的`findPeople`方法来获取未关注的用户。

`mern-social/client/user/FindPeople.js`:

```jsx
componentDidMount = () => {
   const jwt = auth.isAuthenticated()
   findPeople({
     userId: jwt.user._id
   }, {
     t: jwt.token
   }).then((data) => {
     if (data.error) {
       console.log(data.error)
     } else {
       this.setState({users: data})
     }
   })
}
```

获取的用户列表将被迭代并呈现在 Material-UI 的`List`组件中，每个列表项包含用户的头像、名称、到个人资料页面的链接和`Follow`按钮。

`mern-social/client/user/FindPeople.js`:

```jsx
<List>{this.state.users.map((item, i) => {
          return <span key={i}>
             <ListItem>
                <ListItemAvatar className={classes.avatar}>
                   <Avatar src={'/api/users/photo/'+item._id}/>
                </ListItemAvatar>
                <ListItemText primary={item.name}/>
                <ListItemSecondaryAction className={classes.follow}>
                  <Link to={"/user/" + item._id}>
                    <IconButton variant="raised" color="secondary" 
                     className={classes.viewButton}>
                      <ViewIcon/>
                    </IconButton>
                  </Link>
                  <Button aria-label="Follow" variant="raised" 
                    color="primary" 
                    onClick={this.clickFollow.bind(this, item, i)}>
                    Follow
                  </Button>
                </ListItemSecondaryAction>
             </ListItem>
          </span>
        })
      }
</List>
```

点击`Follow`按钮将调用关注 API，并通过删除新关注的用户来更新要关注的用户列表。

`mern-social/client/user/FindPeople.js`:

```jsx
clickFollow = (user, index) => {
    const jwt = auth.isAuthenticated()
    follow({
      userId: jwt.user._id
    }, {
      t: jwt.token
    }, user._id).then((data) => {
      if (data.error) {
        this.setState({error: data.error})
      } else {
        let toFollow = this.state.users
 toFollow.splice(index, 1)
 this.setState({users: toFollow, open: true, followMessage: 
       `Following ${user.name}!`})
      }
    })
}
```

我们还将添加一个 Material-UI 的`Snackbar`组件，当用户成功关注时会临时打开，告诉用户他们开始关注这个新用户。

`mern-social/client/user/FindPeople.js`:

```jsx
<Snackbar
  anchorOrigin={{ vertical: 'bottom', horizontal: 'right'}}
  open={this.state.open}
  onClose={this.handleRequestClose}
  autoHideDuration={6000}
  message={<span className={classes.snack}>{this.state.followMessage}</span>}
/>
```

`Snackbar`将在页面的右下角显示消息，并在设置的持续时间后自动隐藏：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/104ce6be-98c8-49ef-a7dd-0864653e8fbd.png)

MERN Social 用户现在可以互相关注，查看每个用户的关注和粉丝列表，还可以看到他们可以关注的人的列表。在 MERN Social 中关注另一个用户的主要目的是跟踪他们的社交帖子，所以下一步我们将看一下帖子功能的实现。

# 帖子

MERN Social 中的发布功能将允许用户在 MERN Social 应用平台上分享内容，并通过评论或点赞帖子与其他用户互动：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/fcf7142d-c1e5-42a2-9201-6718b4ac6735.png)

# 用于 Post 的 Mongoose 模式模型

为了存储每个帖子，我们将首先在`server/models/post.model.js`中定义 Mongoose 模式。帖子模式将存储帖子的文本内容、照片、发布者的引用、创建时间、用户对帖子的喜欢以及用户对帖子的评论：

+   **帖子文本**：`文本`将是用户在新帖子创建视图中提供的必填字段：

```jsx
text: {
  type: String,
  required: 'Name is required'
}
```

+   **帖子照片**：`照片`将在帖子创建时从用户的本地文件上传，并类似于用户个人资料照片上传功能存储在 MongoDB 中。每个帖子的照片将是可选的：

```jsx
photo: {
  data: Buffer,
  contentType: String
}
```

+   **发布者**：创建帖子将需要用户首先登录，因此我们可以在`postedBy`字段中存储发布帖子的用户的引用：

```jsx
postedBy: {type: mongoose.Schema.ObjectId, ref: 'User'}
```

+   **创建时间**：`创建`时间将在帖子创建时自动生成在数据库中：

```jsx
created: { type: Date, default: Date.now }
```

+   **喜欢**：喜欢特定帖子的用户的引用将存储在`likes`数组中：

```jsx
likes: [{type: mongoose.Schema.ObjectId, ref: 'User'}]
```

+   **评论**：每条帖子上的评论将包含文本内容、创建时间和发布评论的用户的引用。每个帖子将有一个`comments`数组：

```jsx
comments: [{
    text: String,
    created: { type: Date, default: Date.now },
    postedBy: { type: mongoose.Schema.ObjectId, ref: 'User'}
  }]
```

这个模式定义将使我们能够在 MERN Social 中实现所有与帖子相关的功能。

# 新闻订阅组件

在进一步深入 MERN Social 中的发布功能实现之前，我们将查看 Newsfeed 视图的组成，以展示如何设计共享状态的嵌套 UI 组件的基本示例。`Newsfeed`组件将包含两个主要的子组件——一个新帖子表单和来自关注用户的帖子列表：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/478879e6-50a8-4123-9269-1c037eee5f2e.jpg)

`Newsfeed`组件的基本结构将如下所示，包括`NewPost`组件和`PostList`组件。

`mern-social/client/post/Newsfeed.js`：

```jsx
<Card>
   <Typography type="title"> Newsfeed </Typography>
   <Divider/>
   <NewPost addUpdate={this.addPost}/>
   <Divider/>
   <PostList removeUpdate={this.removePost} posts={this.state.posts}/>
</Card>
```

作为父组件，`Newsfeed`将控制在子组件中呈现的帖子数据的状态。当在子组件中修改帖子数据时，例如在`NewPost`组件中添加新帖子或在`PostList`组件中删除帖子时，它将提供一种更新跨组件的帖子状态的方法。

在这里，Newsfeed 中的`loadPosts`函数首先调用服务器以从当前登录用户关注的人那里获取帖子列表，并将其设置为状态以在`PostList`组件中呈现。 `Newsfeed`组件提供了`addPost`和`removePost`函数给`NewPost`和`PostList`，当创建新帖子或删除现有帖子时，将用于更新`Newsfeed`状态中的帖子列表，并最终在`PostList`中反映出来。

在`Newsfeed`组件中定义的`addPost`函数将获取`NewPost`组件中创建的新帖子，并将其添加到状态中的帖子中。

`mern-social/client/post/Newsfeed.js`：

```jsx
addPost = (post) => {
    const updatedPosts = this.state.posts
    updatedPosts.unshift(post)
    this.setState({posts: updatedPosts})
}
```

在`Newsfeed`组件中定义的`removePost`函数将从`PostList`中的`Post`组件中获取已删除的帖子，并从状态中删除它。

`mern-social/client/post/Newsfeed.js`：

```jsx
removePost = (post) => {
    const updatedPosts = this.state.posts
    const index = updatedPosts.indexOf(post)
    updatedPosts.splice(index, 1)
    this.setState({posts: updatedPosts})
}
```

由于帖子是通过这种方式在`Newsfeed`的状态中更新的，`PostList`将向观众呈现已更改的帖子列表。这种从父组件到子组件再到父组件的状态更新机制将应用于其他功能，例如帖子中的评论更新，以及在`Profile`组件中为单个用户呈现`PostList`时。

# 列出帖子

在 MERN Social 中，我们将在`Newsfeed`和每个用户的个人资料中列出帖子。我们将创建一个通用的`PostList`组件，该组件将呈现提供给它的任何帖子列表，并且我们可以在`Newsfeed`和`Profile`组件中都使用它。

`mern-social/client/post/PostList.js`：

```jsx
class PostList extends Component {
  render() {
    return (
      <div style={{marginTop: '24px'}}>
        {this.props.posts.map((item, i) => {
            return <Post post={item} key={i} 
                         onRemove={this.props.removeUpdate}/>
          })
        }
      </div>
    )
  }
}
PostList.propTypes = {
  posts: PropTypes.array.isRequired,
  removeUpdate: PropTypes.func.isRequired
}
```

`PostList`组件将遍历从`Newsfeed`或`Profile`传递给它的帖子列表，并将每个帖子的数据传递给`Post`组件，该组件将呈现帖子的详细信息。 `PostList`还将传递从父组件作为 prop 发送到`Post`组件的`removeUpdate`函数，以便在删除单个帖子时更新状态。

# 在 Newsfeed 中列出

我们将在服务器上设置一个 API，该 API 查询帖子集合，并从指定用户关注的人那里返回帖子。因此，这些帖子可能会在`Newsfeed`的`PostList`中显示。

# 帖子的 Newsfeed API

这个特定于 Newsfeed 的 API 将在以下路由接收请求，该路由将在`server/routes/post.routes.js`中定义：

```jsx
router.route('/api/posts/feed/:userId')
  .get(authCtrl.requireSignin, postCtrl.listNewsFeed)
```

我们在这条路线中使用`:userID`参数来指定当前登录的用户，并且我们将利用`user.controller`中的`userByID`控制器方法来获取用户详细信息，就像之前一样，并将它们附加到在`listNewsFeed`中访问的请求对象中。因此，还要将以下内容添加到`mern-social/server/routes/post.routes.js`中：

```jsx
router.param('userId', userCtrl.userByID)
```

`post.routes.js`文件将与`user.routes.js`文件非常相似，为了在 Express 应用程序中加载这些新路线，我们需要像对 auth 和 user 路线一样在`express.js`中挂载 post 路线。

`mern-social/server/express.js`：

```jsx
app.use('/', postRoutes)
```

`post.controller.js`中的`listNewsFeed`控制器方法将查询数据库中的 Post 集合以获取匹配的帖子。

`mern-social/server/controllers/post.controller.js`：

```jsx
const listNewsFeed = (req, res) => {
  let following = req.profile.following
  following.push(req.profile._id)
  Post.find({postedBy: { $in : req.profile.following } })
   .populate('comments', 'text created')
   .populate('comments.postedBy', '_id name')
   .populate('postedBy', '_id name')
   .sort('-created')
   .exec((err, posts) => {
     if (err) {
       return res.status(400).json({
         error: errorHandler.getErrorMessage(err)
       })
     }
     res.json(posts)
   })
}
```

在对 Post 集合的查询中，我们找到所有具有与当前用户的关注和当前用户匹配的`postedBy`用户引用的帖子。

# 在视图中获取 Newsfeed 帖子

为了在前端使用此 API，我们将在`client/post/api-post.js`中添加一个获取方法：

```jsx
const listNewsFeed = (params, credentials) => {
  return fetch('/api/posts/feed/'+ params.userId, {
    method: 'GET',
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json',
      'Authorization': 'Bearer ' + credentials.t
    }
  }).then(response => {
    return response.json()
  }).catch((err) => console.log(err))
}
```

这是将加载在`PostList`中呈现的帖子的获取方法，它作为`Newsfeed`组件的子组件添加。因此，需要在`Newsfeed`组件的`loadPosts`方法中调用此获取方法。

`mern-social/client/post/Newsfeed.js`：

```jsx
 loadPosts = () => {
    const jwt = auth.isAuthenticated()
    listNewsFeed({
      userId: jwt.user._id
    }, {
      t: jwt.token
    }).then((data) => {
      if (data.error) {
        console.log(data.error)
      } else {
        this.setState({posts: data})
      }
    })
 }
```

`loadPosts`方法将在`Newsfeed`组件的`componentDidMount`中调用，以最初加载呈现在`PostList`组件中的帖子的状态：

！[](assets/c75625f8-f71b-4493-b7f1-421d636be764.png)

# 在 Profile 中按用户列出

获取特定用户创建的帖子列表并在`Profile`中显示的实现将类似于前一部分中的讨论。我们将在服务器上设置一个 API，该 API 查询 Post 集合，并将特定用户的帖子返回到`Profile`视图。

# 用户的帖子 API

将接收查询以返回特定用户发布的帖子的路线添加到`mern-social/server/routes/post.routes.js`中：

```jsx
router.route('/api/posts/by/:userId')
    .get(authCtrl.requireSignin, postCtrl.listByUser)
```

`post.controller.js`中的`listByUser`控制器方法将查询 Post 集合，以查找在路线中指定的用户的`userId`参数与`postedBy`字段中的匹配引用的帖子。

`mern-social/server/controllers/post.controller.js`：

```jsx
const listByUser = (req, res) => {
  Post.find({postedBy: req.profile._id})
  .populate('comments', 'text created')
  .populate('comments.postedBy', '_id name')
  .populate('postedBy', '_id name')
  .sort('-created')
  .exec((err, posts) => {
    if (err) {
      return res.status(400).json({
        error: errorHandler.getErrorMessage(err)
      })
    }
    res.json(posts)
  })
}
```

# 在视图中获取用户帖子

为了在前端使用此 API，我们将在`mern-social/client/post/api-post.js`中添加一个获取方法：

```jsx
const listByUser = (params, credentials) => {
  return fetch('/api/posts/by/'+ params.userId, {
    method: 'GET',
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json',
      'Authorization': 'Bearer ' + credentials.t
    }
  }).then(response => {
    return response.json()
  }).catch((err) => console.log(err))
}
```

这个`fetch`方法将加载添加到`Profile`视图的`PostList`所需的帖子。我们将更新`Profile`组件以定义一个`loadPosts`方法，该方法调用`listByUser`获取方法。

`mern-social/client/user/Profile.js`：

```jsx
loadPosts = (user) => {
    const jwt = auth.isAuthenticated()
    listByUser({
      userId: user
    }, {
      t: jwt.token
    }).then((data) => {
      if (data.error) {
        console.log(data.error)
      } else {
        this.setState({posts: data})
      }
    })
}
```

在`Profile`组件中，当从服务器中的`init()`函数中获取用户详细信息后，将调用`loadPosts`方法，并传入正在加载的用户的用户 ID。为特定用户加载的帖子将设置为状态，并在添加到`Profile`组件的`PostList`组件中呈现。`Profile`组件还提供了一个`removePost`函数，类似于`Newsfeed`组件，作为`PostList`组件的属性，以便在删除帖子时更新帖子列表。

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/2a98e73d-8d6a-4305-a3ec-d5060cb8db04.png)

# 创建新帖子

创建新帖子功能将允许已登录用户发布消息，并可选择从本地文件上传图片到帖子中。

# 创建帖子 API

在服务器上，我们将定义一个 API 来在数据库中创建帖子，首先声明一个路由，以接受`/api/posts/new/:userId`的 POST 请求，位于`mern-social/server/routes/post.routes.js`中。

```jsx
router.route('/api/posts/new/:userId')
  .post(authCtrl.requireSignin, postCtrl.create)
```

`post.controller.js`中的`create`方法将使用`formidable`模块来访问字段和图像文件（如果有），就像我们为用户配置文件照片更新一样。

`mern-social/server/controllers/post.controller.js`：

```jsx
const create = (req, res, next) => {
  let form = new formidable.IncomingForm()
  form.keepExtensions = true
  form.parse(req, (err, fields, files) => {
    if (err) {
      return res.status(400).json({
        error: "Image could not be uploaded"
      })
    }
    let post = new Post(fields)
    post.postedBy= req.profile
    if(files.photo){
      post.photo.data = fs.readFileSync(files.photo.path)
      post.photo.contentType = files.photo.type
    }
    post.save((err, result) => {
      if (err) {
        return res.status(400).json({
          error: errorHandler.getErrorMessage(err)
        })
      }
      res.json(result)
    })
  })
}
```

# 检索帖子的照片

为了检索上传的照片，我们还将设置一个`photo`路由 URL，以返回具有特定帖子的照片。

`mern-social/server/routes/post.routes.js`：

```jsx
router.route('/api/posts/photo/:postId').get(postCtrl.photo)
```

`photo`控制器将返回存储在 MongoDB 中的`photo`数据作为图像文件。

`mern-social/server/controllers/post.controller.js`：

```jsx
const photo = (req, res, next) => {
    res.set("Content-Type", req.post.photo.contentType)
    return res.send(req.post.photo.data)
}
```

由于照片路由使用`:postID`参数，我们将设置一个`postByID`控制器方法来通过其 ID 获取特定帖子，然后返回给照片请求。我们将在`post.routes.js`中添加 param 调用。

`mern-social/server/routes/post.routes.js`：

```jsx
  router.param('postId', postCtrl.postByID)
```

`postByID`将类似于`userByID`方法，并且它将把从数据库中检索到的帖子附加到请求对象中，以便由`next`方法访问。在此实现中附加的帖子数据还将包含`postedBy`用户引用的 ID 和名称。

`mern-social/server/controllers/post.controller.js`：

```jsx
const postByID = (req, res, next, id) => {
  Post.findById(id).populate('postedBy', '_id name').exec((err, post) => {
    if (err || !post)
      return res.status('400').json({
        error: "Post not found"
      })
    req.post = post
    next()
  })
}
```

# 在视图中获取创建帖子的 API

我们将更新`api-post.js`，添加一个`create`方法来调用创建 API 的`fetch`请求。

`mern-social/client/post/api-post.js`:

```jsx
const create = (params, credentials, post) => {
  return fetch('/api/posts/new/'+ params.userId, {
    method: 'POST',
    headers: {
      'Accept': 'application/json',
      'Authorization': 'Bearer ' + credentials.t
    },
    body: post
  }).then((response) => {
    return response.json()
  }).catch((err) => {
    console.log(err)
  })
}
```

这种方法，就像用户`edit` fetch 一样，将使用一个`FormData`对象发送一个多部分表单提交，其中可以包含文本字段和图像文件。

# NewPost 组件

在`Newsfeed`组件中添加的`NewPost`组件将允许用户撰写包含文本消息和可选图像的新帖子：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/6380d9cd-a320-45c7-817d-14bd5eb04018.png)

`NewPost`组件将是一个标准表单，其中包括一个 Material-UI 的`TextField`和一个文件上传按钮，就像在`EditProfile`中实现的那样，它会获取这些值并将它们设置在一个`FormData`对象中，以便在提交帖子时传递给`create` fetch 方法。

`mern-social/client/post/NewPost.js`:

```jsx
clickPost = () => {
    const jwt = auth.isAuthenticated()
    create({
      userId: jwt.user._id
    }, {
      t: jwt.token
    }, this.postData).then((data) => {
      if (data.error) {
        this.setState({error: data.error})
      } else {
        this.setState({text:'', photo: ''})
        this.props.addUpdate(data)
      }
    })
}
```

`NewPost`组件被添加为`Newsfeed`中的子组件，并且作为一个 prop 给予`addUpdate`方法。在成功创建帖子后，表单视图将被清空，并且将执行`addUpdate`，以便在`Newsfeed`中更新帖子列表。

# 帖子组件

每个帖子中的帖子详细信息将在`Post`组件中呈现，该组件将从`PostList`组件中接收帖子数据作为 props，以及`onRemove` prop，以便在删除帖子时应用。

# 布局

`Post`组件布局将包括一个显示发帖人详细信息的标题，帖子内容，带有赞和评论计数的操作栏，以及*评论*部分：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/069a0ac2-e7cf-4192-99b0-15f8656ddd9d.png)

# 标题

标题将包含诸如姓名、头像、指向发帖用户个人资料的链接以及帖子创建日期等信息。

`mern-social/client/post/Post.js`:

```jsx
<CardHeader
  avatar={<Avatar src={'/api/users/photo/'+this.props.post.postedBy._id}/>}
       action={this.props.post.postedBy._id ===   
           auth.isAuthenticated().user._id &&
           <IconButton onClick={this.deletePost}>
             <DeleteIcon />
           </IconButton>
          }
         title={<Link to={"/user/" + this.props.post.postedBy._id}>
            {this.props.post.postedBy.name}
         </Link>}
    subheader={(new Date(this.props.post.created)).toDateString()}
  className={classes.cardHeader}
/>
```

标题还将有条件地显示一个“删除”按钮，如果已登录用户正在查看自己的帖子。

# 内容

内容部分将显示帖子的文本内容以及帖子包含照片的情况。

`mern-social/client/post/Post.js`:

```jsx
<CardContent className={classes.cardContent}>
  <Typography component="p" className={classes.text}> 
    {this.props.post.text} 
  </Typography>
  {this.props.post.photo && 
    (<div className={classes.photo}>
       <img className={classes.media}
            src={'/api/posts/photo/'+this.props.post._id}/>
    </div>)
  }
</CardContent>
```

# 操作

操作部分将包含一个交互式的“喜欢”选项，显示帖子上的总赞数，以及一个评论图标，显示帖子上的总评论数。

`mern-social/client/post/Post.js`:

```jsx
<CardActions>
  { this.state.like
    ? <IconButton onClick={this.like} className={classes.button}
     aria-label="Like" color="secondary">
        <FavoriteIcon />
      </IconButton>
    :<IconButton onClick={this.like} className={classes.button}
     aria-label="Unlike" color="secondary">
        <FavoriteBorderIcon />
      </IconButton> 
  } <span> {this.state.likes} </span>
  <IconButton className={classes.button}
   aria-label="Comment" color="secondary">
     <CommentIcon/>
  </IconButton> <span>{this.state.comments.length}</span>
</CardActions>
```

# 评论

评论部分将包含`Comments`组件中的所有与评论相关的元素，并将获得诸如`postId`和`comments`数据等`props`，以及一个`state`更新方法，当在`Comments`组件中添加或删除评论时可以调用。

`mern-social/client/post/Post.js`:

```jsx
<Comments postId={this.props.post._id} 
          comments={this.state.comments} 
          updateComments={this.updateComments}/>
```

# 删除帖子

只有在登录用户和`postedBy`用户对于正在呈现的特定帖子是相同时，`delete`按钮才可见。为了从数据库中删除帖子，我们将不得不设置一个删除帖子 API，该 API 在单击`delete`时也将在前端应用中有一个 fetch 方法。

`mern-social/server/routes/post.routes.js`:

```jsx
router.route('/api/posts/:postId')
    .delete(authCtrl.requireSignin, 
              postCtrl.isPoster, 
                  postCtrl.remove)
```

删除路由将在调用帖子上的`remove`之前检查授权，通过确保经过身份验证的用户和`postedBy`用户是相同的用户。`isPoster`方法在执行`next`方法之前检查登录用户是否是帖子的原始创建者。

`mern-social/server/controllers/post.controller.js`:

```jsx
const isPoster = (req, res, next) => {
  let isPoster = req.post && req.auth &&
  req.post.postedBy._id == req.auth._id
  if(!isPoster){
    return res.status('403').json({
      error: "User is not authorized"
    })
  }
  next()
}
```

删除 API 的其余实现与其他 API 实现相同，具有`remove`控制器方法和用于前端的 fetch 方法。在删除帖子功能中的重要区别在于，在成功删除时在`Post`组件中调用`onRemove`更新方法。`onRemove`方法作为 prop 从`Newsfeed`或`Profile`发送，以在成功删除时更新状态中的帖子列表。

在`Post`组件中定义的以下`deletePost`方法在单击帖子上的`delete`按钮时被调用。

`mern-social/client/post/Post.js`:

```jsx
deletePost = () => {
    const jwt = auth.isAuthenticated()
    remove({
      postId: this.props.post._id
    }, {
      t: jwt.token
    }).then((data) => {
      if (data.error) {
        console.log(data.error)
      } else {
        this.props.onRemove(this.props.post)
      }
    })
}
```

此方法调用删除帖子 API 的 fetch 调用，并在成功时通过执行从父组件接收的`onRemove`方法更新状态中的帖子列表。

# 喜欢

`Post`组件操作栏部分的喜欢选项将允许用户喜欢或取消喜欢帖子，并显示帖子的总喜欢数。为了记录喜欢，我们将不得不设置可以在视图中调用的喜欢和取消喜欢 API。

# 喜欢 API

喜欢的 API 将是一个 PUT 请求，用于更新`Post`文档中的`likes`数组。请求将在路由`api/posts/like`接收。

`mern-social/server/routes/post.routes.js`:

```jsx
  router.route('/api/posts/like')
    .put(authCtrl.requireSignin, postCtrl.like)
```

在`like`控制器方法中，将使用请求体中接收的帖子 ID 来查找帖子文档，并通过将当前用户的 ID 推送到`likes`数组来更新它。

`mern-social/server/controllers/post.controller.js`:

```jsx
const like = (req, res) => {
  Post.findByIdAndUpdate(req.body.postId,
 {$push: {likes: req.body.userId}}, {new: true})
  .exec((err, result) => {
    if (err) {
      return res.status(400).json({
        error: errorHandler.getErrorMessage(err)
      })
    }
    res.json(result)
  })
}
```

为了使用此 API，将在`api-post.js`中添加一个名为`like`的 fetch 方法，当用户点击`like`按钮时将使用该方法。

`mern-social/client/post/api-post.js`:

```jsx
const like = (params, credentials, postId) => {
  return fetch('/api/posts/like/', {
    method: 'PUT',
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json',
      'Authorization': 'Bearer ' + credentials.t
    },
    body: JSON.stringify({userId:params.userId, postId: postId})
  }).then((response) => {
    return response.json()
  }).catch((err) => {
    console.log(err)
  })
}
```

# 取消喜欢 API

“不喜欢”API 将类似于喜欢 API 进行实现，其自己的路由在`mern-social/server/routes/post.routes.js`中：

```jsx
  router.route('/api/posts/unlike')
    .put(authCtrl.requireSignin, postCtrl.unlike)
```

控制器中的“不喜欢”方法将通过其 ID 找到帖子，并使用`$pull`而不是`$push`更新`likes`数组，从而删除当前用户的 ID。

`mern-social/server/controllers/post.controller.js`：

```jsx
const unlike = (req, res) => {
  Post.findByIdAndUpdate(req.body.postId, {$pull: {likes: req.body.userId}}, {new: true})
  .exec((err, result) => {
    if (err) {
      return res.status(400).json({
        error: errorHandler.getErrorMessage(err)
      })
    }
    res.json(result)
  })
}
```

不喜欢 API 还将有一个类似于`api-post.js`中的`like`方法的对应获取方法。

# 检查是否喜欢并计算喜欢的数量

当渲染`Post`组件时，我们需要检查当前登录的用户是否喜欢帖子，以便显示适当的`like`选项。

`mern-social/client/post/Post.js`：

```jsx
checkLike = (likes) => {
    const jwt = auth.isAuthenticated()
    let match = likes.indexOf(jwt.user._id) !== -1
    return match
}
```

`checkLike`函数可以在`Post`组件的`componentDidMount`和`componentWillReceiveProps`期间调用，以在检查当前用户是否在帖子的`likes`数组中引用后为帖子设置`like`状态：

！[](assets/93a0e91b-5080-41d1-8d30-777ca5e05b08.png)

使用`checkLike`方法在状态中设置的`like`值可以用于渲染心形轮廓按钮或完整的心形按钮。如果用户尚未喜欢帖子，将呈现心形轮廓按钮，点击后将调用`like`API，显示完整的心形按钮，并增加`likes`计数。完整的心形按钮将指示当前用户已经喜欢了这篇帖子，点击这将调用`unlike`API，呈现心形轮廓按钮，并减少`likes`计数。

当`Post`组件挂载并且通过设置`this.props.post.likes.length`将`likes`值设置为状态时，`likes`计数也会最初设置。

`mern-social/client/post/Post.js`：

```jsx
componentDidMount = () => {
    this.setState({like:this.checkLike(this.props.post.likes), 
                   likes: this.props.post.likes.length, 
                   comments: this.props.post.comments})
}
componentWillReceiveProps = (props) => {
    this.setState({like:this.checkLike(props.post.likes), 
                   likes: props.post.likes.length, 
                   comments: props.post.comments})
}
```

当喜欢或不喜欢操作发生时，更新帖子数据并从 API 调用返回时，`likes`相关的值也会再次更新。

# 处理类似点击

为了处理对“喜欢”和“不喜欢”按钮的点击，我们将设置一个“喜欢”方法，该方法将根据是喜欢还是不喜欢操作调用适当的获取方法，并更新帖子的“喜欢”和“喜欢”计数的状态。

`mern-social/client/post/Post.js`：

```jsx
like = () => {
    let callApi = this.state.like ? unlike : like 
    const jwt = auth.isAuthenticated()
    callApi({
      userId: jwt.user._id
    }, {
      t: jwt.token
    }, this.props.post._id).then((data) => {
      if (data.error) {
        console.log(data.error)
      } else {
        this.setState({like: !this.state.like, likes: 
       data.likes.length})
      }
    }) 
  }
```

# 评论

每篇帖子中的评论部分将允许已登录用户添加评论，查看评论列表，并删除自己的评论。评论列表的任何更改，例如新添加或删除，都将更新评论，以及`Post`组件的操作栏部分中的评论计数：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/84e0c3cf-868d-4c90-ae59-2579d1cd8956.png)

# 添加评论

当用户添加评论时，帖子文档将在数据库中更新为新评论。

# 评论 API

为了实现添加评论 API，我们将设置一个`PUT`路由如下以更新帖子。

`mern-social/server/routes/post.routes.js`:

```jsx
router.route('/api/posts/comment')
    .put(authCtrl.requireSignin, postCtrl.comment)
```

`comment`控制器方法将通过其 ID 找到要更新的相关帖子，并将收到的评论对象推送到帖子的`comments`数组中。

`mern-social/server/controllers/post.controller.js`:

```jsx
const comment = (req, res) => {
  let comment = req.body.comment
  comment.postedBy = req.body.userId
  Post.findByIdAndUpdate(req.body.postId,
 {$push: {comments: comment}}, {new: true})
  .populate('comments.postedBy', '_id name')
  .populate('postedBy', '_id name')
  .exec((err, result) => {
    if (err) {
      return res.status(400).json({
        error: errorHandler.getErrorMessage(err)
      })
    }
    res.json(result)
  })
}
```

在响应中，更新后的帖子对象将与帖子和评论中的`postedBy`用户的详细信息一起发送回来。

要在视图中使用此 API，我们将在`api-post.js`中设置一个 fetch 方法，该方法获取当前用户的 ID、帖子 ID 和视图中的`comment`对象，以便与添加评论请求一起发送。

`mern-social/client/post/api-post.js`:

```jsx
const comment = (params, credentials, postId, comment) => {
  return fetch('/api/posts/comment/', {
    method: 'PUT',
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json',
      'Authorization': 'Bearer ' + credentials.t
    },
    body: JSON.stringify({userId:params.userId, postId: postId, 
    comment: comment})
  }).then((response) => {
    return response.json()
  }).catch((err) => {
    console.log(err)
  })
}
```

# 在视图中写一些东西

`Comments`组件中的*添加评论*部分将允许已登录用户输入评论文本：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/8a7002b9-893f-45ee-a3f0-abea084f1896.png)

它将包含一个带有用户照片的头像和一个文本字段，当用户按下*Enter*键时，将添加评论。

`mern-social/client/post/Comments.js`:

```jsx
<CardHeader
   avatar={<Avatar className={classes.smallAvatar} 
              src={'/api/users/photo/'+auth.isAuthenticated().user._id}/>}
   title={<TextField
             onKeyDown={this.addComment}
             multiline
             value={this.state.text}
             onChange={this.handleChange('text')}
             placeholder="Write something ..."
             className={classes.commentField}
             margin="normal"/>}
   className={classes.cardHeader}
/>
```

当值改变时，文本将存储在状态中，并且在`onKeyDown`事件上，如果按下*Enter*键，`addComment`方法将调用`comment` fetch 方法。

`mern-social/client/post/Comments.js`:

```jsx
addComment = (event) => {
    if(event.keyCode == 13 && event.target.value){
      event.preventDefault()
      const jwt = auth.isAuthenticated()
      comment({
        userId: jwt.user._id
      }, {
        t: jwt.token
      }, this.props.postId, {text: this.state.text}).then((data) => {
        if (data.error) {
          console.log(data.error)
        } else {
          this.setState({text: ''})
          this.props.updateComments(data.comments)
        }
      })
    }
}
```

`Comments`组件从`Post`组件中作为 prop 接收`updateComments`方法（在上一节中讨论）。当添加新评论时，将执行此方法，以更新帖子视图中的评论和评论计数。

# 列出评论

`Comments`组件从`Post`组件中作为 prop 接收特定帖子的评论列表，然后迭代每个评论以呈现评论者的详细信息和评论内容。

`mern-social/client/post/Comments.js`:

```jsx
{this.props.comments.map((item, i) => {
                return <CardHeader
                      avatar={
                        <Avatar src=  
                     {'/api/users/photo/'+item.postedBy._id}/>
                      }
                      title={commentBody(item)}
                      className={classes.cardHeader}
                      key={i}/>
              })
}
```

`commentBody`呈现内容，包括评论者的姓名链接到其个人资料、评论文本和评论创建日期。

`mern-social/client/post/Comments.js`:

```jsx
const commentBody = item => {
  return (
     <p className={classes.commentText}>
        <Link to={"/user/" + item.postedBy._id}>{item.postedBy.name}
        </Link><br/>
        {item.text}
        <span className={classes.commentDate}>
          {(new Date(item.created)).toDateString()} |
          {auth.isAuthenticated().user._id === item.postedBy._id &&
            <Icon onClick={this.deleteComment(item)} 
                  className={classes.commentDelete}>delete</Icon> }
        </span>
     </p>
   )
}
```

如果评论的`postedBy`引用与当前已登录用户匹配，`commentBody`还将呈现评论的删除选项。

# 删除评论

在评论中点击删除按钮将通过从数据库中的`comments`数组中移除评论来更新帖子：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/e20462d0-c78b-4d57-bb3a-52796e7f29f3.png)

# 取消评论 API

我们将在以下 PUT 路由上实现一个`uncomment` API。

`mern-social/server/routes/post.routes.js`：

```jsx
router.route('/api/posts/uncomment')
    .put(authCtrl.requireSignin, postCtrl.uncomment)
```

`uncomment`控制器方法将通过 ID 找到相关的帖子，然后从帖子的`comments`数组中拉取具有已删除评论 ID 的评论。

`mern-social/server/controllers/post.controller.js`：

```jsx
const uncomment = (req, res) => {
  let comment = req.body.comment
  Post.findByIdAndUpdate(req.body.postId, {$pull: {comments: {_id: comment._id}}}, {new: true})
  .populate('comments.postedBy', '_id name')
  .populate('postedBy', '_id name')
  .exec((err, result) => {
    if (err) {
      return res.status(400).json({
        error: errorHandler.getErrorMessage(err)
      })
    }
    res.json(result)
  })
}
```

更新后的帖子将像评论 API 中一样在响应中返回。

为了在视图中使用这个 API，我们还将在`api-post.js`中设置一个 fetch 方法，类似于添加`comment`的 fetch 方法，该方法需要当前用户的 ID、帖子 ID 和已删除的`comment`对象，以发送`uncomment`请求。

# 从视图中移除评论

当评论者点击评论的删除按钮时，`Comments`组件将调用`deleteComment`方法来获取`uncomment` API，并在评论成功从服务器中移除时更新评论以及评论计数。

`mern-social/client/post/Comments.js`：

```jsx
deleteComment = comment => event => {
    const jwt = auth.isAuthenticated()
    uncomment({
      userId: jwt.user._id
    }, {
      t: jwt.token
    }, this.props.postId, comment).then((data) => {
      if (data.error) {
        console.log(data.error)
      } else {
        this.props.updateComments(data.comments)
      }
    })
  }
```

# 评论计数更新

`updateComments`方法用于在`Post`组件中定义，并作为 prop 传递给`Comments`组件，以便在添加或删除评论时更新`comments`和评论计数。

`mern-social/client/post/Post.js`：

```jsx
updateComments = (comments) => {
    this.setState({comments: comments})
}
```

该方法将更新后的评论列表作为参数，并更新保存在视图中的评论列表的状态。当`Post`组件挂载时，评论的初始状态在`Post`组件中设置，并作为 props 接收帖子数据。这里设置的评论作为 props 发送到`Comments`组件，并用于在帖子布局的操作栏中渲染评论计数旁边的点赞操作。

`mern-social/client/post/Post.js`：

```jsx
<IconButton aria-label="Comment" color="secondary">
  <CommentIcon/>
</IconButton> <span>{this.state.comments.length}</span>
```

`Post`组件中评论计数与`Comments`组件中渲染和更新的评论之间的关系，再次简单演示了在 React 中如何在嵌套组件之间共享更改的数据，以创建动态和交互式用户界面。

MERN 社交应用程序已经完整地具备了我们之前为应用程序定义的功能集。用户可以更新其个人资料，上传照片和描述，在应用程序上互相关注，并创建带有照片和文字的帖子，以及对帖子点赞和评论。这里展示的实现可以进一步调整和扩展，以添加更多功能，利用 MERN 堆栈的工作机制。

# 总结

本章开发的 MERN 社交应用程序演示了如何将 MERN 堆栈技术一起使用，构建出具有社交媒体功能的功能齐全的网络应用程序。

我们首先更新了骨架应用程序中的用户功能，允许在 MERN 社交上拥有账户的任何人添加关于自己的描述，并从本地文件上传个人资料图片。在上传个人资料图片的实现中，我们探讨了如何从客户端上传多部分表单数据，然后在服务器上接收它，直接将文件数据存储在 MongoDB 数据库中，然后能够检索回来进行查看。

接下来，我们进一步更新了用户功能，允许用户在 MERN 社交平台上互相关注。在用户模型中，我们添加了维护用户引用数组的功能，以表示每个用户的关注者和关注者列表。扩展了这一功能，我们在视图中加入了关注和取消关注选项，并显示了关注者、被关注者甚至尚未关注的用户列表。

然后，我们添加了允许用户发布内容并通过点赞或评论进行互动的功能。在后端，我们设置了帖子模型和相应的 API，能够存储可能包含或不包含图像的帖子内容，并记录任何用户在帖子上产生的点赞和评论。

最后，在实现发布、点赞和评论功能的视图时，我们探讨了如何使用组件组合和共享组件之间的状态值来创建复杂和交互式视图。

在下一章中，我们将进一步扩展 MERN 堆栈的这些能力，并在扩展 MERN 骨架应用程序的同时，开启新的可能性，开发一个在线市场应用程序。
