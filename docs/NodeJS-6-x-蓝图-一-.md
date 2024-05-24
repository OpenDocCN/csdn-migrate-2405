# NodeJS 6.x 蓝图（一）

> 原文：[`zh.annas-archive.org/md5/9B48011577F790A25E05CA5ABA4F9C8B`](https://zh.annas-archive.org/md5/9B48011577F790A25E05CA5ABA4F9C8B)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

使用 Node.js 构建的 Web 应用程序越来越受到开发人员的欢迎和青睐。如今，随着 Node.js 的不断发展，我们可以看到许多公司都在使用这项技术开发他们的应用程序。其中，Netflix、Paypal 等公司都在生产环境中使用 Node.js。

托管公司也通过在其平台上支持 Node.js 取得了突破。此外，许多构建工具，如任务运行器、生成器和依赖管理器，也使用 Node.js 引擎出现，如 Grunt、Gulp、Bower 等。

本书将向您展示如何使用 Node.js 生态系统中的所有资源从头开始构建和部署 Node.js 应用程序，并探索云服务以进行测试、图像处理和部署。

处理所有这些工具并充分利用它们是一项非常有趣和激动人心的任务。

我们还将介绍 Docker 容器的概念，以及使用不同工具和服务进行持续集成。

在本书中，我们将学习如何充分利用这种开发方法，使用最新和最先进的技术从头到尾构建十个应用程序。

享受吧！

# 本书涵盖的内容

在整本书中，我们将探索构建 Node.js 应用程序的不同方式，并了解使用 MVC 设计模式构建基本博客页面的各个元素。我们将学习如何处理不同类型的视图模板，如 EJS 和 SWIG，以及使用命令行工具部署和运行应用程序等更复杂的内容。

我们将涵盖 Restful API 架构的基本概念，以及使用 jQuery、React.js 和 Angular.js 进行客户端通信。

尽管一些内容较为高级，但您将准备好理解 Node.js 应用程序的核心概念，以及如何处理不同类型的数据库，如 MongoDB、MySQL，以及 Express 和 Loopback 框架。

第一章 *使用 MVC 设计模式构建类似 Twitter 的应用程序*，展示了 MVC 模式应用于 Node.js 应用程序的主要概念，使用 Express 框架、mongoose ODM 中间件和 MongoDB 数据库。我们将了解如何使用 Passport 中间件处理用户会话和身份验证。

第二章 *使用 MySQL 数据库构建基本网站*，是一个真正深入了解使用关系数据库的 Node.js 应用程序。我们将了解如何使用 Sequelize（ORM）中间件与 Mysql 数据库，如何创建数据库关系，以及如何使用迁移文件。

第三章 *构建多媒体应用程序*，教会您如何处理文件存储和上传多媒体文件，如图像和视频。我们还将看到如何在 MongoDB 上保存文件名，并如何检索文件并在用户界面上显示。然后，我们将学习如何使用 Node.js 流 API 进行写入和读取。

第四章 *不要拍照，要创造 - 面向摄影师的应用程序*，涵盖了使用 Cloudnary 云服务上传、存储和处理图像的应用程序，并与 MongoDB 进行交互。此外，我们还将看到如何为用户界面实现 Materialize.css 框架，并介绍使用点文件加载配置变量的方法。

第五章 *使用 MongoDB 地理空间查询创建门店定位应用程序*，解释了使用 MongoDB 进行地理空间数据和地理位置的核心概念，以及支持 GEOJSON 数据格式的最有用的功能之一，即 2dspheres 索引。您将了解如何将 Google Maps API 与 Node.js 应用程序集成。

第六章*，使用 Restful API 和 Loopback.io 构建客户反馈应用程序*，探讨了 loopback.io 框架来构建 Restful API。我们将了解 Loopback CLI 的基础知识，以便使用命令行创建整个应用程序。您将学习如何处理使用 MongoDB 的模型之间的关系，以及如何在客户端使用 React.js 与 API 进行通信。

第七章*，使用 Socket.io 构建实时聊天应用程序*，展示了使用 Socket.io 事件构建聊天应用程序的基础知识，使用 Express 和 jQuery 进行用户界面。它涵盖了任务管理器的基本概念，以及如何使用 Gulp 和 livereload 插件。

第八章*，使用 Keystone CMS 创建博客*，讨论了完全由 Node.js 制作的 CMS，称为 Keystone。这是对 Keystone 应用程序结构的深入探讨，以及如何扩展框架以创建新模型和视图。此外，我们将看到如何自定义和创建新的 Keystone 主题。

第九章*，使用 Node.js 和 NPM 构建前端流程*，特别有趣，因为我们将使用 loopback.io 框架创建一个 Restful 应用程序，并使用 AngularJS 进行用户界面。此外，我们将使用不同的构建工具使用命令行和 Node Package Manager（NPM）来连接、缩小和优化图像。我们还将看到如何使用 Heroku toolbelt CLI 来创建和部署应用程序。

第十章*，使用持续集成和 Docker 创建和部署*，探讨了使用 Node.js 应用程序的持续交付开发过程。您将学习如何将工具集成到您的开发环境中，例如 Github，Codeship 和 Heroku，以处理单元测试和自动部署。本章还教您如何设置环境变量以保护您的数据库凭据，以及如何使用 Docker 容器的概念创建完整的应用程序。

# 您需要为本书准备什么

本书中的所有示例均使用开源解决方案，并可以从每章提供的链接免费下载。

本书的示例使用许多 Node.js 模块和一些 JavaScript 库，例如 jQuery，React.js 和 AngularJS。在撰写本书时，最新版本为 Node.js 5.6 和 6.1。

在第一章*，使用 MVC 设计模式构建类似 Twitter 的应用程序*，您可以按照逐步指南安装 Node 和 Node Package Manager（NPM）。

您可以使用您喜欢的 HTML 编辑器。

现代浏览器也会非常有帮助。我们使用 Chrome，但请随意使用您喜欢的浏览器。我们推荐以下之一：Safari，Firefox，Chrome，IE 或 Opera，均为最新版本。

# 本书的受众

您必须具备 JavaScript、HTML 和 CSS 的基本到中级知识，才能跟随本书中的示例，但在某些章节中可能需要更高级的 Web 开发/Restful API 和 Node.js 模块/中间件知识。不用担心；通过示例，我们将详细介绍所有代码，并为您提供许多有趣的链接。

# 惯例

在本书中，您将找到一些文本样式，用于区分不同类型的信息。以下是一些样式的示例，以及它们的含义解释。

文本中的代码词显示如下：

在继续之前，让我们将欢迎消息从：routes/index.js 文件更改为以下突出显示的代码。

代码块设置如下：

```js
/* GET home page. */
router.get('/', function(req, res, next) {
    res.render('index', { title: 'Express from server folder' });
});
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目会以粗体显示：

```js
/* GET home page. */
router.get('/', function(req, res, next) {
    res.render('index', { title: 'Express from server folder' });
});
```

新术语和重要单词以粗体显示。例如，屏幕上看到的单词，在菜单或对话框中出现的单词会以这样的方式出现在文本中：“点击“下一步”按钮会将您移动到下一个屏幕”。

警告或重要提示会出现在这样的框中。

提示和技巧会出现在这样。

### 注意

警告或重要提示会出现在这样的框中。

### 提示

提示和技巧会出现在这样。


# 第一章：使用 MVC 设计模式构建类似 Twitter 的应用程序

**模型** **视图** **控制器**（**MVC**）设计模式在八十年代在软件行业非常流行。这种模式帮助了许多工程师和公司一段时间内构建更好的软件，而且在 Node.js 的兴起和一些 Node 框架如**Express.js**（有关 Express.js 及其 API 的更多信息，请访问[`expressjs.com/`](http://expressjs.com/)）时仍然有用。

### 注意

正如 Express.js 网站所说，它是“*快速、不偏见、极简的 Node.js 网络框架*”。

Express.js 是最受欢迎的 Node 框架，许多全球公司都采用了它。因此，在我们的第一个应用程序中，让我们看看如何应用 MVC 模式来创建一个仅使用 JavaScript 作为后端的应用程序。

在本章中，我们将涵盖以下主题：

+   安装 Node 和 Express 框架

+   MVC 设计模式

+   处理 Yeoman 生成器

+   如何使用 Express 生成器

+   如何处理 Express 模板引擎

+   用户认证

+   使用 Mongoose Schema 连接 MongoDB

# 安装 Node.js

首先，我们需要安装最新的 Node.js 版本。在撰写本书时，Node.js 的最新更新版本是*v6.3.0*。您可以访问 Node.js 网站[`nodejs.org/en/`](https://nodejs.org/en/)并选择您的平台。对于本书，我们使用的是 Mac OS X，但示例可以在任何平台上进行跟踪。

要检查 Node 和**Node Package Manager** (**NPM**)版本，请打开您的终端/Shell 并输入以下内容：

+   ```js
    node -v

    ```

+   ```js
    npm -v

    ```

该书使用 Node 版本*6.3.0*和 NPM 版本*3.10.3*

## 安装 Yeoman

在本书中，我们将使用一些加速开发过程的工具。其中之一称为**Yeoman**（更多信息可以在[`yeoman.io/`](http://yeoman.io/)找到），一个强大的 Web 应用程序生成器。

现在让我们安装生成器。打开您的终端/Shell 并输入以下代码：

```js
npm install -g yo

```

# 安装 Express 生成器

对于我们的第一个应用程序，让我们使用官方的 Express 生成器。生成器可以帮助我们创建应用程序的初始代码，并且我们可以修改它以适应我们的应用程序。

只需在您的终端或 Shell 中输入以下命令：

```js
npm install -g express

```

请注意，`-g`标志表示在您的计算机上全局安装，以便您可以在任何项目中使用它。

Express 是一个强大的 Node.js 微框架；借助它，可以轻松构建 Web 应用程序。

# 构建基线

现在开始的项目将是一个完全基于服务器端的应用程序。我们不会使用任何界面框架，如 AngularJS，Ember.js 等；让我们只专注于 express 框架。

这个应用程序的目的是利用所有的 express 资源和中间件来创建一个遵循 MVC 设计模式的应用程序。

**中间件**基本上是由 express 的路由层激活的函数。名称指的是当路由被激活直到其返回（从开始到结束）。中间件就像名称所暗示的那样处于中间位置。重要的是要记住，函数是按照它们被添加的顺序执行的。

在代码示例中，我们将使用包括`cookie-parser`、`body-parser`等中间件。

### 注意

您可以直接从 Packt Publishing 网站上的书页下载本书中使用的代码，也可以直接从 GitHub 上下载本章和其他所有章节：

[`github.com/newaeonweb/nodejs-6-blueprints`](https://github.com/newaeonweb/nodejs-6-blueprints)。

每个应用程序都被赋予了相关章节的名称，所以现在让我们深入到我们的代码中。

首先，在您的计算机上创建一个名为`chapter-01`的新文件夹。从现在开始，我们将称这个文件夹为根项目文件夹。在我们继续执行启动项目的命令之前，我们将看到一些关于我们在`express`命令中使用的标志的内容。

我们使用的命令是`express --ejs --css sass -git`，其中：

+   `express`是用于创建应用程序的默认命令

+   `--ejs`表示使用嵌入式 JavaScript 模板引擎，而不是**Jade**（默认）

+   `--css sass`表示使用**SASS**而不是纯**CSS**（默认）

+   `--git`：表示向项目添加一个`.gitignore`文件

由于我正在使用 git 进行版本控制，使用 express 选项向我的应用程序添加一个`.gitignore`文件将非常有用。但我会在书中跳过所有 git 命令。

要查看`express`框架提供的所有选项，可以在终端/Shell 中输入以下内容：

```js
express -h

```

框架为我们提供了启动项目的所有可用命令：

```js
Usage: express [options] [dir]
 Options:
 -h, --help          output usage information
 -V, --version       output the version number
 -e, --ejs           add ejs engine support (defaults to jade)
 --hbs           add handlebars engine support
 -H, --hogan         add hogan.js engine support
 -c, --css <engine>  add stylesheet <engine> support
                   (less|stylus|compass|sass) (defaults to plain css)
 --git           add .gitignore
 -f, --force         force on non-empty directory

```

现在，打开你的终端/Shell 并输入以下命令：

```js
express --ejs --css sass -git

```

终端/Shell 中的输出将如下所示：

```js
 create :
 create : ./package.json
 create : ./app.js
 create : ./.gitignore
 create : ./public
 create : ./public/javascripts
 create : ./public/images
 create : ./public/stylesheets
 create : ./public/stylesheets/style.sass
 create : ./routes
 create : ./routes/index.js
 create : ./routes/users.js
 create : ./views
 create : ./views/index.ejs
 create : ./views/error.ejs
 create : ./bin
 create : ./bin/www
 install dependencies:
 $ cd . && npm install
 run the app:
 $ DEBUG=chapter-01:* npm start

```

正如你在下面的截图中所看到的，生成器非常灵活，只创建了启动项目所需的最小结构：

![构建基线](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-6x-bp/img/image_01_001.jpg)

但在继续之前，我们将进行一些更改。

## 向`package.json`文件添加更改

在根项目文件夹中打开`package.json`并添加以下突出显示的代码行：

```js
{ 
    "name": "chapter-01", 
    "description": "Build a Twitter Like app using the MVC design pattern", 
    "license": "MIT", 
    "author": { 
        "name": "Fernando Monteiro", 
        "url": "https://github.com/newaeonweb/node-6-blueprints" 
    }, 
    "repository": { 
        "type": "git", 
        "url": "https://github.com/newaeonweb/node-6-blueprints.git" 
    }, 
    "keywords": [ 
        "MVC", 
        "Express Application", 
        "Expressjs" 
    ], 
    "version": "0.0.1", 
    "private": true, 
    "scripts": { 
        "start": "node ./bin/www" 
    }, 
    "dependencies": { 
        "body-parser": "~1.13.2", 
        "cookie-parser": "~1.3.5", 
        "debug": "~2.2.0", 
        "ejs": "~2.3.3", 
        "express": "~4.13.1", 
        "morgan": "~1.6.1", 
        "node-sass-middleware": "0.8.0", 
        "serve-favicon": "~2.3.0" 
    } 
} 

```

即使这不是一个高优先级的修改，但将这些信息添加到项目中被认为是一个良好的做法。

现在我们准备运行项目；让我们安装在`package.json`文件中已列出的必要依赖。

在终端/Shell 中，输入以下命令：

```js
npm install

```

最后，我们准备好了！

## 运行应用程序

要运行项目并在浏览器中查看应用程序，请在你的终端/Shell 中输入以下命令：

```js
DEBUG=chapter-01:* npm start

```

你的终端/Shell 中的输出将如下所示：

```js
chapter-01:server Listening on port 3000 +0ms

```

你可以只运行`npm start`，但你不会看到之前带有端口名称的输出；在本章的后面，我们会修复它。

现在，只需查看`http://localhost:3000`。你将看到 express 的欢迎消息。

# 更改应用程序的结构

让我们对应用程序的目录结构进行一些更改，并准备好遵循模型-视图-控制器设计模式。

我将列出这次重构的必要步骤：

1.  在`root`项目文件夹内：

+   创建一个名为`server`的新文件夹

1.  在`server`文件夹内：

+   创建一个名为`config`的新文件夹

+   创建一个名为`routes`的新文件夹

+   创建一个名为`views`的新文件夹。

1.  此时不要担心`config`文件夹；我们稍后会插入它的内容。

1.  现在我们需要将`chapter-01/views`文件夹中的`error.js`和`index.js`文件移动到`chapter-01/server/views`文件夹中。

1.  将`chapter-01/routes`文件夹中的`index.js`和`user.js`文件移动到`chapter-01/server/routes`文件夹中。

1.  这里只有一个非常简单的更改，但在开发过程中，更好地组织我们应用程序的所有文件将非常有用。

我们仍然需要在主应用程序文件`app.js`中更改到这个文件夹的路径。打开项目根文件夹中的`app.js`文件，并更改以下突出显示的行：

```js
... 
var routes = require('./server/routes/index'); 
var users = require('./server/routes/users'); 

var app = express(); 

// view engine setup 
app.set('views', path.join(__dirname, 'server/views')); 
app.set('view engine', 'ejs'); 
... 

```

在我们继续之前，让我们将`routes/index.js`文件中的欢迎消息更改为以下突出显示的代码：

```js
/* GET home page. */ 
router.get('/', function(req, res, next) { 
    res.render('index', { title: 'Express from server folder' }); 
}); 

```

要运行项目并在浏览器中查看应用程序，请按照以下步骤操作：

1.  在你的终端/Shell 中输入以下命令：

```js
DEBUG=chapter-01:* npm start

```

1.  在你的浏览器中打开`http://localhost:3000`。

1.  在你的浏览器中的输出将如下所示：![更改应用程序的结构](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-6x-bp/img/image_01_002.jpg)

应用程序主屏幕

现在我们可以删除以下文件夹和文件：

+   `chapter-01/routes`：

+   `index.js`

+   `user.js`

+   `chapter-01/views`：

+   `error.js`

+   `index.js`

## 更改默认行为以启动应用程序

如前所述，我们将更改应用程序的默认初始化过程。为了完成这个任务，我们将编辑`app.js`文件并添加几行代码：

1.  打开`app.js`，并在`app.use('/users', users);`函数之后添加以下代码：

```js
      // catch 404 and forward to error handler 
      app.use(function(req, res, next) { 
         var err = new Error('Not Found'); 
          err.status = 404; 
          next(err); 
      }); 

```

这是一个简单的拦截*404*错误的`middleware`。

1.  现在在`module.exports = app;`函数之后添加以下代码：

```js
      app.set('port', process.env.PORT || 3000); 
      var server = app.listen(app.get('port'), function() { 
          console.log('Express server listening on port ' + 
          serer.address().port); 
      }); 

```

1.  打开项目根目录下的`package.js`文件，并更改以下代码：

```js
      ... 
      "scripts": { 
         "start": "node app.js" 
      }, 
      ... 

```

### 注意

如果需要，仍然可以使用调试命令：`DEBUG=chapter-01:* npm start`。

1.  `package.json`文件是 Node.js 应用程序中极其重要的文件。它可以存储项目的各种信息，如依赖关系、项目描述、作者、版本等等。

1.  此外，还可以设置脚本来轻松地进行缩小、连接、测试、构建和部署应用程序。我们将在第九章中看到如何创建脚本，*使用 Node.js 和 NPM 构建前端流程*。

1.  让我们测试一下结果；打开你的终端/Shell 并输入以下命令：

```js
 npm start 

```

1.  我们将在控制台上看到相同的输出：

```js
 > node app.js 
Express server listening on port 3000!

```

# 使用部分文件重构视图文件夹

现在我们将对`views`文件夹中的目录结构进行重大更改：我们将添加一个重要的**嵌入式 JavaScript**（**EJS**）资源，用于在我们的模板中创建可重用的文件。

它们被称为部分文件，并将使用`<% = include %>`标签包含在我们的应用程序中。

### 提示

您可以在官方项目页面[`ejs.co/`](http://ejs.co/)上找到有关**EJS**的更多信息。

在`views`文件夹中，我们将创建两个名为`partials`和`pages`的文件夹：

1.  此时`pages`文件夹将如下所示：

1.  现在让我们将在`views`文件夹中的文件移动到`pages`文件夹中。

1.  在`views`文件夹内创建一个`pages`文件夹。

1.  在`views`文件夹内创建一个`partials`文件夹。

+   `server/`

+   `pages/`

+   `index.ejs`

+   `error.ejs`

+   `partials/`

1.  现在我们需要创建将包含在所有模板中的文件。请注意，我们只有两个模板：`index.js`和`error.js`。

1.  创建一个名为`stylesheet.ejs`的文件，并添加以下代码：

```js
      <!-- CSS Files --> 
      <link rel='stylesheet' href='https://cdnjs.cloudflare.com/
       ajax/libs/twitter-bootstrap/4.0.0-alpha/css/bootstrap.min.css'>
      <link rel='stylesheet' href='/stylesheets/style.css' />
```

### 提示

我们将使用最新版本的**Twitter Bootstrap** UI 框架，目前本书编写时的版本是*4.0.0-alpha*。

1.  我们正在使用**内容传送网络**（**CDN**）来获取*CSS*和*JS*文件。

1.  创建一个名为`javascript.ejs`的文件，并添加以下代码：

```js
      <!-- JS Scripts -->
      <script src='https://cdnjs.cloudflare.com/ajax/libs
        /jquery/2.2.1/jquery.min.js'></script>
      <script src='https://cdnjs.cloudflare.com/ajax/libs/
       twitter-bootstrap/4.0.0-alpha/js/bootstrap.min.js'></script>
      </body>
      </html>
```

1.  然后创建一个名为`header.ejs`的文件，并添加以下代码：

```js
      <!-- Fixed navbar --> 
      <div class="pos-f-t"> 
          <div class="collapse" id="navbar-header"> 
              <div class="container bg-inverse p-a-1"> 
                 <h3>Collapsed content</h3> 
                  <p>Toggle able via the navbar brand.</p> 
              </div> 
          </div> 
          <nav class="navbar navbar-light navbar-static-top"> 
               <div class="container"> 
                  <button class="navbar-toggler hidden-sm-up" type=
                    "button"data-toggle="collapse" data-target=
                      "#exCollapsingNavbar2"> 
                      Menu 
                  </button> 
                 <div class="collapse navbar-toggleable-xs"
                   id="exCollapsingNavbar2"> 
                      <a class="navbar-brand" href="/">MVC App</a> 
                      <ul class="nav navbar-nav navbar-right"> 
                          <li class="nav-item"> 
                              <a class="nav-link" href="/login">
                                Sign in
                              </a>
                          </li> 
                          <li class="nav-item"> 
                              <a class="nav-link" href="/signup">
                                Sign up
                              </a> 
                           </li> 
                           <li class="nav-item"> 
                              <a class="nav-link" href="/profile">
                                 Profile</a> 
                           </li> 

                          <li class="nav-item"> 
                              <a class="nav-link" href="/comments">
                                Comments</a> 
                          </li> 
                      </ul> 
                  </div> 
              </div> 
          </nav> 
      </div> 
      <!-- Fixed navbar --> 

```

1.  创建一个名为`footer.ejs`的文件，并添加以下代码：

```js
      <footer class="footer"> 
          <div class="container"> 
              <span>&copy 2016\. Node-Express-MVC-App</span> 
          </div> 
      </footer> 

```

1.  让我们在`app.js`文件中调整视图模板的路径；添加以下代码：

```js
      // view engine setup 
      app.set('views', path.join(__dirname, 'server/views/pages')); 
      app.set('view engine', 'ejs'); 

```

### 提示

请注意，我们只添加了已经存在的`pages`文件夹路径。

1.  现在我们将用以下代码替换`pages/index.ejs`中的代码：

```js
      <!DOCTYPE html>
      <html>
      <head>
        <title><%= title %></title>
         <% include ../partials/stylesheet %>
      </head> 
      <body>
          <% include ../partials/header %>
          <div class="container">
            <div class="page-header m-t-1">
              <h1><%= title %></h1>
            </div> 
            <p class="lead">Welcome to <%= title %></p>
          </div>
          <% include ../partials/footer %>
          <% include ../partials/javascript %>
       </body>
       </html>
```

1.  让我们对`pages/error.ejs`中的错误视图文件做同样的操作：

```js
      <!DOCTYPE html> 
      <html> 
      <head> 
           <title>Wohp's Error</title> 
           <% include ../partials/stylesheet %> 
      </head> 
      <body> 
           <% include ../partials/header %> 

          <div class="container"> 
              <div class="page-header m-t-1"> 
                  <h1>Sorry: <%= message %></h1> 
                  <h2><%= error.status %></h2> 
                  <pre><%= error.stack %></pre> 
              </div> 

          </div> 
           <% include ../partials/footer %> 
           <% include ../partials/javascript %> 
      </body> 
      </html> 

```

我们目前在`server`文件夹中有以下结构：

+   `server/`

+   `pages/`

+   `index.ejs`

+   `error.ejs`

+   `partials/`

+   `footer.ejs`

+   `header.ejs`

+   `javascript.ejs`

+   `stylesheet.ejs2`

# 为登录、注册和个人资料添加模板

现在我们有了一个坚实的基础，可以继续进行项目。此时，我们将为登录、注册和个人资料界面添加一些模板文件。

这些页面的预期结果将如下截图所示：

![为登录、注册和个人资料添加模板](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-6x-bp/img/image_01_003.jpg)

登录界面

![为登录、注册和个人资料添加模板](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-6x-bp/img/image_01_004.jpg)

注册界面

![为登录、注册和个人资料添加模板](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-6x-bp/img/image_01_005.jpg)

个人资料界面

1.  现在让我们创建登录模板。在`views`文件夹中创建一个名为`login.ejs`的新文件，并放入以下代码：

```js
      <!DOCTYPE html> 
      <html> 
      <head> 
          <title><%= title %></title> 
          <% include ../partials/stylesheet %> 
      </head> 
      <body> 
        <% include ../partials/header %> 

        <div class="container"> 
            <% if (message.length > 0) { %> 
                <div class="alert alert-warning alert-dismissible
                   fade in" role="alert"> 
                  <button type="button" class="close" data-dismiss=
                     "alert" aria-label="Close"> 
                    <span aria-hidden="true">&times;</span> 
                  </button> 
                  <strong>Ohps!</strong> <%= message %>. 
                </div> 
             <% } %> 
            <form class="form-signin" action="/login" method="post"> 
            <h2 class="form-signin-heading">Welcome sign in</h2> 
            <label for="inputEmail" class="sr-only">Email address</label> 
            <input type="email" id="email" name="email" class="form-
              control" placeholder="Email address" required=""> 
            <label for="inputPassword" class="sr-only">Password</label> 
            <input type="password" id="password" name="password"
             class="form-control" placeholder="Password" required=""> 
            <button class="btn btn-lg btn-primary btn-block" 
               type="submit">Sign in</button> 
            <br> 
            <p>Don't have an account? <a href="/signup">Signup</a> 
               ,it's free.</p> 
          </form> 
        </div> 

        <% include ../partials/footer %> 
        <% include ../partials/javascript %> 
      </body> 
      </html> 

```

1.  在`routes/index.js`中的索引路由后添加登录路由：

```js
      /* GET login page. */ 
      router.get('/login', function(req, res, next) { 
          res.render('login', { title: 'Login Page', message:
           req.flash('loginMessage') }); 
       }); 

```

### 注意

在模板中，我们正在使用`connect-flash`中间件来显示错误消息。稍后，我们将展示如何安装这个组件；现在不用担心。

1.  让我们将`signup`模板添加到`views/pages`文件夹中。

1.  在`views/pages`中创建一个名为`signup.ejs`的新文件，并添加以下代码：

```js
      <!DOCTYPE html>
      <html>
      <head>
        <title><%= title %></title>
        <% include ../partials/stylesheet %>
      </head>
      <body>
        <% include ../partials/header %>
        <div class="container">
          <% if (message.length > 0) { %>
             <div class="alert alert-warning" role="alert">
               <strong>Warning!</strong> <%= message %>.
             </div>
           <% } %>
           <form class="form-signin" action="/signup" method="post">
             <h2 class="form-signin-heading">Please signup</h2>
             <label for="inputName" class="sr-only">Name address</label>
             <input type="text" id="name" name="name" class="form-control"
              placeholder="Name" required="">
             <label for="inputEmail" class="sr-only">Email address</label>
             <input type="email" id="email" name="email" class=
               "form-control" placeholder="Email address" required="">
             <label for="inputPassword" class="sr-only">Password</label>
             <input type="password" id="password" name="password" 
               class="form-control" placeholder="Password" required="">
             <button class="btn btn-lg btn-primary btn-block" 
               type="submit">Sign in</button> 
              <br> 
              <p>Don't have an account? <a href="/signup">Signup</a>
                  ,it's free.</p>
            </form>
          </div>
          <% include ../partials/footer %>
          <% include ../partials/javascript %>
        </body>
        </html>
```

1.  现在我们需要为注册视图添加路由。打开`routes/index.js`并在`登录路由`之后添加以下代码：

```js
      /* GET Signup */ 
      router.get('/signup', function(req, res) { 
          res.render('signup', { title: 'Signup Page', 
             message:req.flash('signupMessage') }); 
      }); 

```

1.  接下来，我们将在`profile`页面添加模板和路由到此页面。在`view/pages`文件夹内创建一个名为`profile.ejs`的文件，并添加以下代码：

```js
      <!DOCTYPE html> 
      <html> 
      <head> 
          <title><%= title %></title> 
          <% include ../partials/stylesheet %> 
      </head> 
      <body> 
          <% include ../partials/header %> 
          <div class="container"> 
            <h1><%= title %></h1> 
            <div class="datails"> 
              <div class="card text-xs-center"> 
                  <br> 
                <img class="card-img-top" src="img/<%= avatar %>" 
                  alt="Card image cap"> 
                  <div class="card-block"> 
                    <h4 class="card-title">User Details</h4> 
                    <p class="card-text"> 
                        <strong>Name</strong>: <%= user.local.name %><br> 
                        <strong>Email</strong>: <%= user.local.email %> 
                    </p> 
                    <a href="/logout" class="btn btn-default">Logout</a> 
                  </div> 
              </div> 
            </div> 
         </div> 
        <% include ../partials/footer %> 
        <% include ../partials/javascript %> 
      </body> 
      </html> 

```

1.  现在我们需要为 profile 视图添加路由；打开`routes/index.js`并在`signup`路由之后添加以下代码：

```js
      /* GET Profile page. */ 
      router.get('/profile',  function(req, res, next) {
          res.render('profile', { title: 'Profile Page', user : req.user,
          avatar: gravatar.url(req.user.email ,  {s: '100', r: 'x', d:
           'retro'}, true) });
      }); 

```

### 提示

我们正在使用另一个名为`gravatar`的中间件；稍后我们将展示如何安装它。

# 安装额外的中间件

正如您在前面的部分中所看到的，我们使用了一些中间件来显示消息和使用 gravatar 显示用户图标。在本节中，我们将看到如何安装一些非常重要的模块用于我们的应用程序。

由于我们为`signin`、`signup`和`profile`页面创建了模板，我们需要存储具有登录和密码的用户。

这些是我们将用于此任务的中间件，每个中间件的定义如下：

| 组件 | 描述 | 更多细节 |
| --- | --- | --- |
| `connect-flash` | 用户友好的消息 | [`www.npmjs.com/package/connect-flash`](https://www.npmjs.com/package/connect-flash) |
| `connect-mongo` | 用于连接 MongoDB 的驱动程序 | [`www.npmjs.com/package/connect-mongo`](https://www.npmjs.com/package/connect-mongo) |
| `express-session` | 在数据库中存储用户会话 | [`www.npmjs.com/package/express-session`](https://www.npmjs.com/package/express-session) |
| `Gravatar` | 显示随机用户图片 | [`www.npmjs.com/package/gravatar`](https://www.npmjs.com/package/gravatar) |
| `Passport` | 身份验证中间件 | [`www.npmjs.com/package/passport`](https://www.npmjs.com/package/passport) |
| `passport-local` | 本地用户/密码验证 | [`www.npmjs.com/package/passport-local`](https://www.npmjs.com/package/passport-local) |

打开您的终端/Shell 并键入：

```js
npm install connect-flash connect-mongo express-session gravatar
      passport passport-local -save

```

### 注意

正如我们所看到的，我们将使用 MongoDB 来存储用户数据；您可以在[`www.mongodb.org/`](https://www.mongodb.org/)找到有关 MongoDB 的更多信息，并在[`docs.mongodb.org/manual/installation/`](https://docs.mongodb.org/manual/installation/)找到安装过程。我们假设您已经在您的机器上安装了 MongoDB 并且它正在运行。

# 使用新中间件重构 app.js 文件

此时，我们需要对`app.js`文件进行重大重构，以包含我们将使用的新中间件。

我们将逐步向您展示如何包含每个中间件，最后我们将看到完整的文件：

1.  打开`app.js`并在`var app = express()`之前添加以下行：

```js
      // ODM With Mongoose 
      var mongoose = require('mongoose'); 
      // Modules to store session 
      var session    = require('express-session'); 
      var MongoStore = require('connect-mongo')(session); 
      // Import Passport and Warning flash modules 
      var passport = require('passport'); 
      var flash = require('connect-flash'); 

```

这是一个简单的导入过程。

1.  在`app.set('view engine', 'ejs')`之后添加以下行：

```js
      // Database configuration 
      var config = require('./server/config/config.js'); 
      // connect to our database 
      mongoose.connect(config.url); 
      // Check if MongoDB is running 
      mongoose.connection.on('error', function() {
        console.error('MongoDB Connection Error. Make sure MongoDB is
         running.'); 
      }); 

      // Passport configuration 
      require('./server/config/passport')(passport); 

```

1.  请注意，我们在第一行使用了一个`config.js`文件；稍后我们将创建这个文件。

1.  在`app.use(express.static(path.join(__dirname, 'public')))`之后添加以下行：

```js
      // required for passport 
      // secret for session 
      app.use(session({ 
          secret: 'sometextgohere', 
          saveUninitialized: true, 
          resave: true, 
          //store session on MongoDB using express-session +
          connect mongo 
          store: new MongoStore({ 
              url: config.url, 
              collection : 'sessions' 
          }) 
      })); 

      // Init passport authentication 
      app.use(passport.initialize()); 
      // persistent login sessions 
      app.use(passport.session()); 
      // flash messages 
      app.use(flash()); 

```

# 添加配置和护照文件

如前所述，让我们创建一个`config`文件：

1.  在`server/config`内创建一个名为`config.js`的文件，并将以下代码放入其中：

```js
      // Database URL 
      module.exports = { 
          // Connect with MongoDB on local machine 
          'url' : 'mongodb://localhost/mvc-app' 
      }; 

```

1.  在`server/config`上创建一个新文件并命名为`passport.js`。添加以下内容：

```js
      // load passport module 
      var LocalStrategy    = require('passport-local').Strategy; 
      // load up the user model 
      var User = require('../models/users'); 

      module.exports = function(passport) { 
          // passport init setup 
          // serialize the user for the session 
          passport.serializeUser(function(user, done) { 
              done(null, user.id); 
          }); 
          //       deserialize the user 
          passport.deserializeUser(function(id, done) { 
              User.findById(id, function(err, user) { 
                  done(err, user); 
              }); 
          }); 
          // using local strategy 
          passport.use('local-login', new LocalStrategy({ 
              // change default username and password, to email 
              //and password 
              usernameField : 'email', 
              passwordField : 'password', 
              passReqToCallback : true 
          }, 
          function(req, email, password, done) { 
              if (email) 
              // format to lower-case 
              email = email.toLowerCase(); 
              // process asynchronous 
              process.nextTick(function() { 
                  User.findOne({ 'local.email' :  email }, 
                   function(err, user)
                { 
                  // if errors 
                 if (err) 
                   return done(err); 
                 // check errors and bring the messages 
                 if (!user) 
                   return done(null, false, req.flash('loginMessage',
                   'No user found.')); 
                if (!user.validPassword(password)) 
                  return done(null, false, req.flash('loginMessage',
                  'Wohh! Wrong password.')); 
                // everything ok, get user 
                else 
                  return done(null, user); 
                }); 
              }); 
           })); 
          // Signup local strategy 
          passport.use('local-signup', new LocalStrategy({ 
              // change default username and password, to email and 
             //  password 
              usernameField : 'email', 
              passwordField : 'password', 
              passReqToCallback : true 
          }, 
          function(req, email, password, done) { 
              if (email) 
              // format to lower-case 
              email = email.toLowerCase(); 
              // asynchronous 
              process.nextTick(function() { 
                  // if the user is not already logged in: 
                  if (!req.user) { 
                      User.findOne({ 'local.email' :  email },
                       function(err,user) { 
                  // if errors 
                  if (err) 
                    return done(err); 
                  // check email 
                  if (user) { 
                    return done(null, false, req.flash('signupMessage',
                     'Wohh! the email is already taken.')); 
                  }
                  else { 
                    // create the user 
                      var newUser = new User(); 
                      // Get user name from req.body 
                      newUser.local.name = req.body.name; 
                      newUser.local.email = email; 
                      newUser.local.password =
                       newUser.generateHash(password); 
                      // save data 
                     newUser.save(function(err) { 
                   if (err) 
                     throw err; 
                     return done(null, newUser); 
                    }); 
                   } 
                }); 
               } else { 
                 return done(null, req.user); 
               }         }); 
          })); 
      }; 

```

请注意，在第四行，我们正在导入一个名为`models`的文件；我们将使用 Mongoose 创建这个文件。

# 创建一个 models 文件夹并添加一个用户模式

在`server/`内创建一个 models 文件夹，并添加以下代码：

```js
// Import Mongoose and password Encrypt 
var mongoose = require('mongoose'); 
var bcrypt   = require('bcrypt-nodejs'); 

// define the schema for User model 
var userSchema = mongoose.Schema({ 
    // Using local for Local Strategy Passport 
    local: { 
        name: String, 
        email: String, 
        password: String, 
    } 

}); 

// Encrypt Password 
userSchema.methods.generateHash = function(password) { 
    return bcrypt.hashSync(password, bcrypt.genSaltSync(8), null); 
}; 

// Verify if password is valid 
userSchema.methods.validPassword = function(password) { 
    return bcrypt.compareSync(password, this.local.password); 
}; 

// create the model for users and expose it to our app 
module.exports = mongoose.model('User', userSchema); 

```

# 保护路由

到目前为止，我们已经有足够的代码来配置对我们应用程序的安全访问。但是，我们仍然需要添加一些行到登录和注册表单中，以使它们正常工作：

1.  打开`server/routes/index.js`并在`login GET`路由之后添加以下行：

```js
      /* POST login */ 
      router.post('/login', passport.authenticate('local-login', { 
          //Success go to Profile Page / Fail go to login page 
          successRedirect : '/profile', 
          failureRedirect : '/login', 
          failureFlash : true 
      })); 

```

1.  在`signup GET`路由之后添加这些行：

```js
      /* POST Signup */ 
      router.post('/signup', passport.authenticate('local-signup', { 
          //Success go to Profile Page / Fail go to Signup page 
          successRedirect : '/profile',       
          failureRedirect : '/signup', 
          failureFlash : true 
      })); 

```

1.  现在让我们添加一个简单的函数来检查用户是否已登录；在`server/routes/index.js`的末尾添加以下代码：

```js
      /* check if user is logged in */ 
      function isLoggedIn(req, res, next) { 
          if (req.isAuthenticated()) 
              return next(); 
          res.redirect('/login'); 
      } 

```

1.  让我们添加一个简单的路由来检查用户是否已登录，并在`isLoggedIn()`函数之后添加以下代码：

```js
      /* GET Logout Page */ 
      router.get('/logout', function(req, res) { 
          req.logout(); 
          res.redirect('/'); 
      }); 

```

1.  最后的更改是将`isloggedin()`作为 profile 路由的第二个参数。添加以下突出显示的代码：

```js
      /* GET Profile page. */ 
      router.get('/profile', isLoggedIn, function(req, res, next) { 
          res.render('profile', { title: 'Profile Page', user : req.user,
           avatar: gravatar.url(req.user.email ,  {s: '100', r: 'x',
             d:'retro'}, true) }); 
      }); 

```

最终的`index.js`文件将如下所示：

```js
var express = require('express'); 
var router = express.Router(); 
var passport = require('passport'); 
// get gravatar icon from email 
var gravatar = require('gravatar'); 

/* GET home page. */ 
router.get('/', function(req, res, next) { 
    res.render('index', { title: 'Express from server folder' }); 
}); 

/* GET login page. */ 
router.get('/login', function(req, res, next) { 
    res.render('login', { title: 'Login Page', message: req.flash('loginMessage') }); 
}); 
/* POST login */ 
router.post('/login', passport.authenticate('local-login', { 
    //Success go to Profile Page / Fail go to login page 
    successRedirect : '/profile', 
    failureRedirect : '/login', 
    failureFlash : true 
})); 

/* GET Signup */ 
router.get('/signup', function(req, res) { 
    res.render('signup', { title: 'Signup Page', message: req.flash('signupMessage') }); 
}); 
/* POST Signup */ 
router.post('/signup', passport.authenticate('local-signup', { 
    //Success go to Profile Page / Fail go to Signup page 
    successRedirect : '/profile', 
    failureRedirect : '/signup', 
    failureFlash : true 
})); 

/* GET Profile page. */ 
router.get('/profile', isLoggedIn, function(req, res, next) { 
    res.render('profile', { title: 'Profile Page', user : req.user, avatar: gravatar.url(req.user.email ,  {s: '100', r: 'x', d: 'retro'}, true) }); 
}); 

/* check if user is logged in */ 
function isLoggedIn(req, res, next) { 
    if (req.isAuthenticated()) 
        return next(); 
    res.redirect('/login'); 
} 
/* GET Logout Page */ 
router.get('/logout', function(req, res) { 
    req.logout(); 
    res.redirect('/'); 
}); 

module.exports = router; 

```

我们几乎已经设置好了应用程序的最终，但我们仍然需要创建一个评论页面。

# 创建控制器文件夹

我们将使用`controllers`文件夹来创建评论文件的路由和函数，而不是使用`routes`文件夹，这样我们可以分离路由和控制器函数，从而实现更好的模块化：

1.  创建一个名为`controllers`的文件夹。

1.  创建一个名为`comments.js`的文件，并添加以下代码：

```js
      // get gravatar icon from email 
      var gravatar = require('gravatar'); 
      // get Comments model 
      var Comments = require('../models/comments'); 

      // List Comments 
      exports.list = function(req, res) { 
         // List all comments and sort by Date 
          Comments.find().sort('-created').populate('user',
            'local.email').exec(function(error, comments) { 
              if (error) { 
                  return res.send(400, { 
                      message: error       
                  }); 
              } 
              // Render result 
              res.render('comments', { 
                  title: 'Comments Page', 
                  comments: comments, 
                  gravatar: gravatar.url(comments.email,
                     {s: '80', r: 'x', d: 'retro'}, true) 
              }); 
          }); 
      }; 
      // Create Comments 
      exports.create = function(req, res) { 
         // create a new instance of the Comments model with request body 
          var comments = new Comments(req.body); 
          // Set current user (id) 
          comments.user = req.user; 
          // save the data received 
          comments.save(function(error) { 
              if (error) { 
                  return res.send(400, { 
                      message: error 
                  }); 
              } 
              // Redirect to comments 
              res.redirect('/comments'); 
          }); 
      }; 
      // Comments authorization middleware 
      exports.hasAuthorization = function(req, res, next) { 
          if (req.isAuthenticated()) 
              return next(); 
          res.redirect('/login'); 
      }; 

```

1.  让我们在`app.js`文件中导入控制器；在`var users = require('./server/routes/users')`之后添加以下行：

```js
      // Import comments controller
      var comments = require('./server/controllers/comments'); 
```

1.  现在在`app.use('/users', users)`之后添加评论路由：

```js
      // Setup routes for comments 
      app.get('/comments', comments.hasAuthorization, comments.list); 
      app.post('/comments', comments.hasAuthorization, comments.create); 

```

1.  在`server/pages`下创建一个名为`comments.ejs`的文件，并添加以下行：

```js
      <!DOCTYPE html> 
      <html> 
      <head> 
          <title><%= title %></title> 
          <% include ../partials/stylesheet %> 
      </head> 
      <body> 
        <% include ../partials/header %> 
        <div class="container"> 
          <div class="row"> 
            <div class="col-lg-6"> 
              <h4 class="text-muted">Comments</h4> 
            </div> 
            <div class="col-lg-6"> 
              <button type="button" class="btn btn-secondary pull-right"
               data-toggle="modal" data-target="#createPost">
                    Create Comment 
                </button> 
            </div> 
            </div> 
            <!-- Modal --> 
            <div class="modal fade" id="createPost" tabindex="-1"
             role="dialog" aria-labelledby="myModalLabel"
              aria-hidden="true"> 
              <div class="modal-dialog" role="document"> 
                <div class="modal-content"> 
                  <form action="/comments" method="post"> 
                    <div class="modal-header"> 
                      <button type="button" class="close" 
                       data-dismiss="modal" aria-label="Close"> 
                         <span aria-hidden="true">&times;</span> 
                       </button> 
                       <h4 class="modal-title" id="myModalLabel">
                        Create Comment</h4> 
                    </div> 

                    <div class="modal-body"> 
                      <fieldset class="form-group"> 
                         <label  for="inputitle">Title</label> 
                         <input type="text" id="inputitle" name="title"
                           class="form-control" placeholder=
                            "Comment Title" required=""> 
                       </fieldset> 
                       <fieldset class="form-group"> 
                         <label  for="inputContent">Content</label> 
                         <textarea id="inputContent" name="content"
                          rows="8" cols="40" class="form-control"
                          placeholder="Comment Description" required="">
                         </textarea> 
                       </fieldset> 

                       </div> 
                        <div class="modal-footer"> 
                          <button type="button" class="btn btn-secondary"
                           data-dismiss="modal">Close</button> 
                          <button type="submit" class="btn btn-primary">
                           Save changes</button> 
                        </div> 
                  </form> 
                </div> 
              </div> 
            </div> 
              <hr> 
            <div class="lead"> 
              <div class="list-group"> 
                <% comments.forEach(function(comments){ %> 
                  <a href="#" class="list-group-item"> 
                    <img src="img/<%= gravatar %>" alt="" style="float: left;
                      margin-right: 10px"> 
               <div class="comments"> 
                <h4 class="list-group-item-heading">
                  <%= comments.title %></h4> 
                 <p class="list-group-item-text">
                   <%= comments.content %></p> 
                 <small class="text-muted">By: 
                    <%= comments.user.local.email %>
                 </small> 
                </div> 
                </a> 

            <% }); %> 
            </div> 
          </div> 
         </div> 
          <% include ../partials/footer %> 
          <% include ../partials/javascript %> 
      </body> 
      </html> 

```

1.  请注意，我们使用了 Twitter-bootstrap 的简单 Modal 组件来添加评论，如下截图所示：![创建控制器文件夹](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-6x-bp/img/image_01_006.jpg)

创建评论屏幕的模型

1.  最后一步是为评论创建一个模型；让我们在`server/models/`下创建一个名为`comments.js`的文件，并添加以下代码：

```js
      // load the things we need 
      var mongoose = require('mongoose'); 
      var Schema = mongoose.Schema; 

      var commentSchema = mongoose.Schema({ 
          created: { 
              type: Date, 
              default: Date.now 
          }, 
          title: { 
              type: String,       
              default: '', 
              trim: true, 
              required: 'Title cannot be blank' 
          }, 
          content: { 
              type: String, 
              default: '', 
              trim: true 
          }, 
          user: { 
              type: Schema.ObjectId, 
              ref: 'User' 
          } 
      }); 

      module.exports = mongoose.model('Comments', commentSchema); 

```

# 运行应用程序并添加评论

现在是时候测试一切是否正常工作了：

1.  在项目根目录打开终端/Shell，并输入以下命令：

```js
npm start

```

1.  在浏览器中检查：`http://localhost:3000`。

1.  转到`http://localhost:3000/signup`，创建一个名为`John Doe`的用户，邮箱为`john@doe.com`，密码为`123456`。

1.  转到`http://localhost:3000/comments`，点击**创建评论**按钮，并添加以下内容：

```js
      Title: Sample Title 
      Comments: Lorem ipsum dolor sit amet, consectetur adipiscing elit,
       sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.
       Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris
       nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in
       reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla
       pariatur. Excepteur sint occaecat cupidatat non proident, sunt in
       culpa qui officia deserunt mollit anim id est laborum. 

```

1.  以下截图展示了最终结果：![运行应用程序并添加评论](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-6x-bp/img/image_01_007.jpg)

评论屏幕

## 检查错误消息

现在让我们检查 flash-connect 消息。转到`http://localhost:3000/login`，尝试以用户身份登录；我们将使用`martin@tech.com`和密码`123`。

以下截图展示了结果：

![检查错误消息](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-6x-bp/img/image_01_008.jpg)

登录屏幕上的错误消息

现在我们尝试使用已注册的用户进行注册。转到`http://localhost:3000/signup`，并放置以下内容：

```js
name: John Doe 
email: john@doe.com
password: 123456 

```

以下截图展示了结果：

![检查错误消息](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-6x-bp/img/image_01_009.jpg)

注册屏幕上的错误消息

# 总结

在这一章中，我们讨论了如何使用 Node.js 和 express 框架创建 MVC 应用程序，这是一个完全在服务器端的应用程序，与使用 Rails 或 Django 框架创建的应用程序非常相似。

我们还建立了安全路由和非常健壮的身份验证，包括会话控制、会话 cookie 存储和加密密码。

我们使用 MongoDB 来存储用户和评论的数据。

在下一章中，我们将看到如何在 express 和 Node.js 中使用另一个数据库系统。


# 第二章：使用 MySQL 数据库构建基本网站

在本章中，我们将介绍使用关系数据库的 Node.js 应用程序的一些基本概念，本例中为 Mysql。

让我们看一下 MongoDB 的**对象文档映射器**（**ODM**）和**sequelize**和 Mysql 使用的**对象关系映射器**（**ORM**）之间的一些区别。为此，我们将创建一个简单的应用程序，并使用我们可用的资源**sequelize**，这是一个用于创建模型和映射数据库的强大中间件。

我们还将使用另一个名为 Swig 的引擎模板，并演示如何手动添加模板引擎。

在本章中，我们将涵盖：

+   如何使用 Swig 模板引擎

+   将默认路由从 express 生成器更改为 MVC 方法

+   安装 Squelize-CLI

+   如何使用 Sequelize 模型的 ORM

+   使用数据库迁移脚本

+   处理 MySQL 数据库关系

# 我们正在构建的内容

在本章末尾，我们将创建以下示例应用程序。本章假设您已经在计算机上安装并运行了 Mysql 数据库。

![我们正在构建的内容](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-6x-bp/img/image_02_001.jpg)

示例应用程序

# 创建基线应用程序

第一步是创建另一个目录，因为我将所有章节都放在 git 控制下，我将使用与第一章相同的根文件夹，*在 Node.js 中使用 MVC 设计模式构建类似 Twitter 的应用程序*。

1.  创建一个名为`chapter-02`的文件夹。

1.  在此文件夹中打开您的终端/ shell 并键入 express 命令：

```js
 express --git

```

请注意，这次我们只使用了`--git`标志，我们将使用另一个模板引擎，但将手动安装它。

# 安装 Swig 模板引擎

要做的第一步是将默认的 express 模板引擎更改为**Swig**，这是一个非常简单、灵活和稳定的模板引擎，还为我们提供了一个非常类似于 AngularJS 的语法，只需使用双大括号`{{ variableName }}`表示表达式。

### 提示

有关**Swig**的更多信息，请访问官方网站：[`github.com/paularmstrong/swig`](https://github.com/paularmstrong/swig)。

1.  打开`package.json`文件并用以下代码替换`jade`行：

```js
 "swig": "¹.4.2",

```

1.  在项目文件夹中打开终端/ shell 并键入：

```js
 npm install

```

1.  在我们继续之前，让我们对`app.js`进行一些调整，我们需要添加`Swig`模块。打开`app.js`并在`var bodyParser = require('body-parser');`行之后添加以下代码：

```js
      var swig = require('swig');

```

1.  用以下代码替换默认的`jade`模板引擎行：

```js
      var swig = new swig.Swig(); 
      app.engine('html', swig.renderFile); 
      app.set('view engine', 'html'); 

```

# 重构 views 文件夹

与之前一样，让我们将`views`文件夹更改为以下新结构：

`views`

+   `pages/`

+   `partials/`

1.  从`views`文件夹中删除默认的`jade`文件。

1.  在`pages`文件夹中创建一个名为`layout.html`的文件并放入以下代码：

```js
      <!DOCTYPE html> 
      <html> 
      <head> 
      </head> 
      <body> 
          {% block content %} 
          {% endblock %} 
      </body> 
      </html> 

```

1.  在`views/pages`文件夹中创建一个`index.html`并放入以下代码：

```js
      {% extends 'layout.html' %} 
      {% block title %}{% endblock %} 
      {% block content %} 
      <h1>{{ title }}</h1> 
          Welcome to {{ title }} 
      {% endblock %} 

```

1.  在`views/pages`文件夹中创建一个`error.html`页面并放入以下代码：

```js
      {% extends 'layout.html' %} 
      {% block title %}{% endblock %} 
      {% block content %} 
      <div class="container"> 
          <h1>{{ message }}</h1> 
          <h2>{{ error.status }}</h2> 
          <pre>{{ error.stack }}</pre> 
       </div> 
      {% endblock %} 

```

1.  我们需要在`app.js`上调整`views`路径，并在`var app = express();`函数之后用以下代码替换代码：

```js
      // view engine setup 
      app.set('views', path.join(__dirname, 'views/pages'));

```

此时，我们已经完成了启动 MVC 应用程序的第一步。在上一章中，我们基本上使用了 express 命令创建的原始结构，但在本例中，我们将完全使用 MVC 模式，即 Model，View，Controller。

# 创建一个 controllers 文件夹

1.  在根项目文件夹内创建一个名为`controllers`的文件夹。

1.  在`controllers`文件夹中创建一个`index.js`并放入以下代码：

```js
      // Index controller 
      exports.show = function(req, res) { 
      // Show index content 
          res.render('index', { 
              title: 'Express' 
          }); 
      }; 

```

1.  编辑`app.js`文件，并用以下代码替换原始的`index`路由`app.use('/', routes);`：

```js
      app.get('/', index.show); 

```

1.  将控制器路径添加到`app.js`文件中`var swig = require('swig');`声明之后，用以下代码替换原始代码：

```js
      // Inject index controller 
      var index = require('./controllers/index'); 

```

1.  现在是时候检查一切是否如预期般进行了：我们将运行应用程序并检查结果。在您的终端/ shell 中键入以下命令：

```js
 npm start

```

检查以下网址：`http://localhost:3000`，您将看到 express 框架的欢迎消息。

## 删除默认路由文件夹

让我们删除默认的`routes`文件夹：

1.  删除`routes`文件夹及其内容。

1.  从`app.js`中删除`user route`，在索引控制器行之后。

# 为头部和页脚添加部分文件

现在让我们添加头部和页脚文件：

1.  在`views/partials`文件夹中创建一个名为`head.html`的新文件，并放入以下代码：

```js
      <meta charset="utf-8"> 
      <title>{{ title }}</title> 
      <link rel='stylesheet' href='https://cdnjs.cloudflare.com/ajax/libs
       /twitter-bootstrap/4.0.0-alpha.2/css/bootstrap.min.css'> 
      <link rel="stylesheet" href="/stylesheets/style.css"> 

```

1.  在`views/partials`文件夹中创建一个名为`footer.html`的文件，并放入以下代码：

```js
      <script src='https://cdnjs.cloudflare.com/ajax/libs/jquery/2.2.1
       /jquery.min.js'></script> 
      <script src='https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap
       /4.0.0-alpha.2/js/bootstrap.min.js'></script> 

```

1.  现在，是时候使用`include`标签将部分文件添加到`layout.html`页面了。打开`layout.html`并添加以下代码：

```js
      <!DOCTYPE html> 
      <html> 
      <head> 
          {% include "../partials/head.html" %} 
      </head> 
      <body> 
           {% block content %} 
           {% endblock %} 

          {% include "../partials/footer.html" %} 
      </body> 
      </html> 

```

最后，我们准备继续我们的项目。这次，我们的目录结构将如下截图所示：

![为头部和页脚添加部分文件](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-6x-bp/img/image_02_002.jpg)

文件结构

# 安装和配置 Sequelize-cli

**Sequelize-cli**是一个非常有用的命令行界面，用于创建模型、配置和迁移文件到数据库。它与 Sequelize 中间件集成，并与许多关系数据库（如 PostgreSQL、MySQL、MSSQL、Sqlite）一起运行。

### 提示

您可以在以下网址找到有关 Sequelize 中间件实现的更多信息：[`docs.sequelizejs.com/en/latest/`](http://docs.sequelizejs.com/en/latest/)，以及**Sequelize-Cli**的完整文档：[`github.com/sequelize/cli`](https://github.com/sequelize/cli)。

1.  打开终端/Shell 并键入：

```js
 npm install -g sequelize-cli

```

1.  使用以下命令安装`sequelize`：

```js
 npm install sequelize -save

```

### 提示

记住我们总是使用`-save`标志将模块添加到我们的`package.json`文件中。

1.  在根文件夹上创建一个名为`.sequelizerc`的文件，并放入以下代码：

```js
      var path = require('path'); 
      module.exports = { 
        'config': path.resolve('./config', 'config.json'), 
        'migrations-path': path.resolve('./config', 'migrations'), 
        'models-path': path.resolve('./', 'models'), 
        'seeders-path': path.resolve('./config', 'seeders') 
      } 

```

1.  在终端/Shell 上，键入以下命令：

```js
sequelize init

```

1.  在`init`命令之后，终端将显示以下输出消息：

```js
 Sequelize [Node: 6.3.0, CLI: 2.3.1, ORM: 3.19.3] 

      Using gulpfile /usr/local/lib/node_modules/sequelize
      -cli/lib/gulpfile.js 
      Starting 'init:config'... 
      Created "config/config.json" 
      Finished 'init:config' after 4.05 ms 
      Successfully created migrations folder at "/chapter-02/config
      /migrations". 
      Finished 'init:migrations' after 1.42 ms 
      Successfully created seeders folder at "/chapter-02/config
      /seeders". 
      Finished 'init:seeders' after 712 Î¼s 
      Successfully created models folder at "/chapter-02/models". 
      Loaded configuration file "config/config.json". 
      Using environment "development". 
      Finished 'init:models' after 18 msStarting 'init'...

```

此命令还创建了用于存储应用程序模式的 models 目录，一个配置文件，以及用于保存程序和迁移脚本的文件夹。现在不要担心这个，我们将在下一节中查看迁移。

# 使用数据库凭据编辑 config.js 文件

正如我们所看到的，`sequelize`命令创建了许多文件，包括数据库配置文件。该文件具有应用程序数据库的示例配置。

1.  打开`config/config.json`并编辑`development`标签，使用我们的数据库详细信息，如以下突出显示的代码：

```js
      { 
        "development": { 
        "username": "root", 
            "password": "", 
            "database": "mvc_mysql_app", 
            "host": "127.0.0.1", 
            "port": "3306", 
            "dialect": "mysql" 
        }, 
        "test": { 
            "username": "root", 
            "password": null, 
            "database": "database_test", 
            "host": "127.0.0.1", 
            "dialect": "mysql" 
        }, 
        "production": { 
            "username": "root", 
            "password": null, 
            "database": "database_production", 
            "host": "127.0.0.1", 
            "dialect": "mysql" 
        } 
      } 

```

### 提示

请注意，我正在使用没有密码的 root 用户连接我的数据库，如果您使用不同的用户或使用不同的密码，请用您自己的凭据替换上述代码。

# 创建用户模式

借助`Sequelize-cli`，我们将为应用程序用户创建一个简单的模式：

在根项目文件夹中打开终端/Shell，并键入以下命令：

```js
 sequelize model:create --name User --attributes "name:string,
      email:string"

```

您将在终端窗口上看到以下输出：

```js
Sequelize [Node: 6.3.0, CLI: 2.3.1, ORM: 3.19.3]
Loaded configuration file "config/config.json".
Using environment "development".
Using gulpfile /usr/local/lib/node_modules/sequelize-
      cli/lib/gulpfile.js
Starting 'model:create'...
Finished 'model:create' after 13 ms

```

让我们检查`models/User.js`中的用户模型文件，这里使用`define()`函数添加`sequelize`以创建用户模式：

```js
      'use strict'; 
      module.exports = function(sequelize, DataTypes) { 
        var User = sequelize.define('User', { 
          name: DataTypes.STRING, 
          email: DataTypes.STRING 
        },
       { 
          classMethods: { 
           associate: function(models) { 
              // associations can be defined here 
           } 
        } 
       }); 
       return User; 
       }; 

```

请注意，此命令在`models`文件夹中创建了`User.js`文件，并且还创建了一个包含哈希和要在数据库中执行的操作名称的迁移文件在`migrations`文件夹中。

该文件包含创建数据库中用户表所需的样板。

```js
      'use strict'; 
       module.exports = { 
        up: function(queryInterface, Sequelize) { 
          return queryInterface.createTable('Users', { 
            id: { 
              allowNull: false, 
              autoIncrement: true, 
              primaryKey: true, 
              type: Sequelize.INTEGER 
            }, 
            name: { 
                type: Sequelize.STRING 
            }, 
            email: { 
              type: Sequelize.STRING 
            }, 
            createdAt: { 
              allowNull: false, 
              type: Sequelize.DATE 
            }, 
            updatedAt: { 
               allowNull: false, 
               type: Sequelize.DATE 
            } 
          }); 
        }, 
        down: function(queryInterface, Sequelize) { 
            return queryInterface.dropTable('Users'); 
        } 
      }; 

```

# 创建乐队模式

让我们创建一个模式，将在数据库中存储用户在系统中创建的每个乐队的数据。

1.  打开终端/Shell 并键入以下命令：

```js
 sequelize model:create --name Band --attributes "name:string,
       description:string, album:string, year:string, UserId:integer"

```

1.  与上一步一样，创建了两个文件，一个用于迁移数据，另一个用作乐队模型，如下所示的代码：

```js
      'use strict'; 
      module.exports = function(sequelize, DataTypes) { 
        var Band = sequelize.define('Band', { 
          name: DataTypes.STRING, 
          description: DataTypes.STRING, 
          album: DataTypes.STRING, 
          year: DataTypes.STRING, 
          UserId: DataTypes.INTEGER 
        }, { 
          classMethods: { 
             associate: function(models) { 
              // associations can be defined here 
          } 
        } 
      }); 
      return Band; 
      }; 

```

## 在乐队和用户模型之间创建关联

在使用方案迁移脚本之前的最后一步，我们需要创建用户模型和乐队模型之间的关联。我们将使用以下关联：

| **模型** | **关联** |
| --- | --- |
| `Band.js` | `Band.belongsTo(models.User);` |
| `User.js` | `User.hasMany(models.Band);` |

### 提示

您可以在以下链接找到有关关联的更多信息：[`docs.sequelizejs.com/en/latest/docs/associations/`](http://docs.sequelizejs.com/en/latest/docs/associations/)。

1.  打开`User.js`模型并添加以下突出显示的代码：

```js
      'use strict'; 
       module.exports = function(sequelize, DataTypes) { 
         var User = sequelize.define('User', { 
           name: DataTypes.STRING, 
           email: DataTypes.STRING 
         }, { 
           classMethods: { 
             associate: function(models) { 
              // associations can be defined here 
              User.hasMany(models.Band); 
            } 
          } 
         }); 
       return User; 
      }; 

```

1.  打开`Band.js`模型并添加以下突出显示的代码：

```js
      'use strict'; 
       module.exports = function(sequelize, DataTypes) { 
         var Band = sequelize.define('Band', { 
           name: DataTypes.STRING, 
           description: DataTypes.STRING, 
           album: DataTypes.STRING, 
           year: DataTypes.STRING, 
           UserId: DataTypes.INTEGER 
         }, { 
           classMethods: { 
              associate: function(models) { 
              // associations can be defined here 
        Band.belongsTo(models.User); 
         } 
        } 
       }); 
       return Band; 
      }; 

```

# 在 Mysql 上创建数据库

在尝试访问 Mysql 控制台之前，请确保它正在运行。要检查：

1.  打开终端/ shell 并使用以下命令登录您的 Mysql：

```js
 mysql -u root

```

1.  请记住，如果您使用不同的用户名或密码，请使用以下命令并将`youruser`和`yourpassword`替换为您自己的凭据：

```js
 mysql -u youruser -p yourpassword

```

1.  现在让我们创建我们的数据库，输入以下命令：

```js
 CREATE DATABASE mvc_mysql_app;

```

1.  命令执行后的结果将是以下行：

```js
 Query OK, 1 row affected (0,04 sec)

```

这证实了操作是成功的，我们准备继续前进。

## 使用数据库迁移在 Mysql 上插入数据

现在是将模式迁移到数据库的时候了。再次使用`sequelize-cli`进行此迁移。在继续之前，我们需要手动安装一个 Mysql 模块。

1.  打开终端/ shell 并输入以下命令：

```js
 npm install

```

### 提示

请注意，`Sequelize`接口取决于应用程序中使用的每种类型数据库的各个模块，我们的情况下是使用 Mysql

1.  打开您的终端/ shell 并输入以下命令：

```js
 sequelize db:migrate

```

1.  这将是上述操作的结果，您终端的输出：

```js
Sequelize [Node: 6.3.0, CLI: 2.3.1, ORM: 3.19.3, mysql: ².10.2]
Loaded configuration file "config/config.json".
Using environment "development".
Using gulpfile /usr/local/lib/node_modules/sequelize-
      cli/lib/gulpfile.js
Starting 'db:migrate'...
Finished 'db:migrate' after 438 ms
== 20160319100145-create-user: migrating =======
== 20160319100145-create-user: migrated (0.339s)
== 20160319101806-create-band: migrating =======
== 20160319101806-create-band: migrated (0.148s)

```

# 检查数据库表

我们可以使用自己的 Mysql 控制台来查看表是否成功创建。但是我将使用另一个具有图形界面的功能，它极大地简化了工作，因为它允许更快速、更轻松地显示，并且可以快速对基础数据进行操作。

由于我正在使用 Mac OSX，我将使用一个名为**Sequel Pro**的应用程序，这是一个免费且轻量级的应用程序，用于管理 Mysql 数据库。

### 提示

您可以在以下链接找到有关**Sequel Pro**的更多信息：[`www.sequelpro.com/`](http://www.sequelpro.com/)。

前面的命令：`sequelize db:migrate`创建了表，如我们在以下图中所见：

1.  这张图片显示了左侧选择的乐队表，右侧显示了我们在乐队模式上设置的属性的内容：![检查数据库表](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-6x-bp/img/image_02_003.jpg)

乐队表

1.  这张图片显示了左侧选择的`SequelizeMeta`表，右侧显示了`config/migrations`文件夹中生成的`Sequelize`文件的内容：![检查数据库表](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-6x-bp/img/image_02_004.jpg)

迁移文件

1.  这张图片显示了左侧选择的用户表，右侧显示了我们在用户模式上设置的属性的内容：![检查数据库表](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-6x-bp/img/image_02_005.jpg)

用户表

`SquelizeMeta`表以与我们在迁移文件夹中的迁移文件相同的方式保存迁移文件。

现在我们已经为数据库中的数据插入创建了必要的文件，我们准备继续创建应用程序的其他文件。

# 创建应用程序控制器

下一步是为模型 User 和 Band 创建控件：

1.  在`controllers`文件夹中，创建一个名为`User.js`的新文件并添加以下代码：

```js
      var models = require('../models/index'); 
      var User = require('../models/user'); 

      // Create Users 
      exports.create = function(req, res) { 
          // create a new instance of the Users model with request body 
          models.User.create({ 
            name: req.body.name, 
              email: req.body.email 
          }).then(function(user) { 
              res.json(user); 
          }); 
       }; 

       // List Users 
       exports.list = function(req, res) { 
           // List all users 
           models.User.findAll({}).then(function(users) { 
               res.json(users); 
          }); 
      }; 

```

### 提示

请注意，文件的第一行导入了`index`模型；这个文件是创建所有控件的基础，它是用于映射其他模型的`sequelize`。

1.  在`controllers`文件夹中为 Band 控制器做同样的事情；创建一个名为`Band.js`的文件并添加以下代码：

```js
      var models = require('../models/index'); 
      var Band = require('../models/band'); 

      // Create Band 
      exports.create = function(req, res) { 
          // create a new instance of the Bands model with request body 
          models.Band.create(req.body).then(function(band) { 
              //res.json(band); 
              res.redirect('/bands'); 
          }); 
      }; 

      // List Bands 
      exports.list = function(req, res) { 
          // List all bands and sort by Date 
          models.Band.findAll({ 
            // Order: lastest created 
              order: 'createdAt DESC' 
          }).then(function(bands) { 
               //res.json(bands); 
              // Render result 
               res.render('list', { 
                  title: 'List bands', 
                  bands: bands 
               }); 
           });  
      }; 

      // Get by band id 
      exports.byId = function(req, res) { 
          models.Band.find({ 
             where: { 
               id: req.params.id 
            } 
          }).then(function(band) { 
              res.json(band); 
          }); 
       } 
       // Update by id 
       exports.update = function (req, res) { 
           models.Band.find({ 
           where: { 
              id: req.params.id 
           } 
        }).then(function(band) { 
             if(band){ 
               band.updateAttributes({ 
                  name: req.body.name, 
                  description: req.body.description, 
                  album: req.body.album, 
                  year: req.body.year, 
                  UserId: req.body.user_id 
               }).then(function(band) { 
                  res.send(band); 
              }); 
            } 
          }); 
      } 

      // Delete by id 
      exports.delete = function (req, res) { 
          models.Band.destroy({ 
            where: { 
               id: req.params.id 
            } 
          }).then(function(band) { 
              res.json(band); 
          }); 
      } 

```

1.  现在让我们重构`index.js`控制器并添加以下代码：

```js
      // List Sample Bands 
      exports.show = function(req, res) { 
         // List all comments and sort by Date 
         var topBands = [ 
              { 
                  name: 'Motorhead', 
                  description: 'Rock and Roll Band', 
                  album: 'http://s2.vagalume.com/motorhead/discografia
                  /orgasmatron-W320.jpg', year:'1986', 
              }, 
              { 
                  name: 'Judas Priest', 
                  description: 'Heavy Metal band', 
                  album: 'http://s2.vagalume.com/judas-priest/discografia
                   /screaming-for-vengeance-W320.jpg', year:'1982', 
              }, 
              { 
                  name: 'Ozzy Osbourne', 
                  description: 'Heavy Metal Band', 
                  album: 'http://s2.vagalume.com/ozzy-osbourne/discografia
                  /diary-of-a-madman-W320.jpg', year:'1981', 
              } 
         ]; 
           res.render('index', { 
               title: 'The best albums of the eighties', 
               callToAction: 'Please be welcome, click the button below 
               and register your favorite album.', bands: topBands 
           }); 
      }; 

```

请注意，使用前面的代码，我们只是创建了一个简单的列表，以在主屏幕上显示一些专辑。

# 创建应用程序模板/视图

现在让我们创建应用程序视图：

1.  在`views/pages`文件夹中，创建一个名为`band-list.html`的新文件并添加以下代码：

```js
      {% extends 'layout.html' %} 
      {% block title %}{% endblock %} 
      {% block content %} 
      <div class="album text-muted"> 
      <div class="container"> 
      <div class="row"> 
                  {% for band in bands %} 
      <div class="card col-lg-4"> 
      <h2 class="text-lg-center">{{ band.name }}</h2> 
                          {% if band.album == null %} 
       <img src="img/320x320" alt="{{ band.name }}"
        style="height: 320px; width: 100%; display: block;"> 
                          {% endif %} 
                          {% if band.album %} 
       <img src="img/{{ band.album }}" width="100%" height="320px"> 
                          {% endif %} 
       <p class ="card-text">{{ band.description }}</p> 
       </div> 
                   {% endfor %} 
       </div> 
       </div> 
       </div> 
       {% endblock %} 

```

1.  打开`views/pages/index.html`并添加以下代码：

```js
      {% extends 'layout.html' %} 
      {% block title %}{% endblock %} 
      {% block content %}  
      <section class="jumbotron text-xs-center"> 
      <div class="container"> 
        <h1 class="jumbotron-heading">{{ title }}</h1> 
        <p class="lead text-muted">{{ callToAction }}</p> 
        <p> 
        <a href="/bands" class="btn btn-secondary">
          View Full List Albums</a> 
        </p> 
      </div> 
      </section> 
      <div class="album text-muted"> 
        <div class="container"> 
          <div class="row"> 
                  {% for band in bands %} 
          <div class="card col-lg-4"> 
            <h2 class="text-lg-center">{{ band.name }}</h2> 
                          {% if band.album == null %} 
            <img src="img/320x320" alt="{{ band.name }}"
              style="height: 320px; width: 100%; display: block;"> 
                      {% endif %} 
                      {% if band.album %} 
            <img src="img/{{ band.album }}" width="100%" height="320px"> 
                      {% endif %} 
            <p class="card-text">{{ band.description }}</p> 
          </div> 
                  {% endfor %} 
          </div> 
        </div> 
      </div> 
      {% endblock %} 

```

1.  打开`views/pages/layou.html`并添加以下突出显示的代码：

```js
      <!DOCTYPE html> 
      <html> 
      <head> 
          {% include "../partials/head.html" %} 
      </head> 
      <body>
 <div class="navbar-collapse inverse collapse" id="navbar-header"
       aria-expanded="false" style="height: 0px;"> 
      <div class="container-fluid"> 
      <div class="about"> 
        <h4>About</h4> 
        <p class="text-muted">Add some information about the album below,
           the author, or any other background context. Make it a few
           sentences long so folks can pick up some informative tidbits.
           Then, link them off to some social networking sites or contact
           information.
         </p> 
      </div> 
      <div class="social"> 
      <h4>Contact</h4> 
      <ul class="list-unstyled"> 
        <li><a href="#">Follow on Twitter</a></li> 
        <li><a href="#">Like on Facebook</a></li> 
        <li><a href="#">Email me</a></li> 
      </ul> 
      </div> 
      </div> 
      </div> 
      <div class="navbar navbar-static-top navbar-dark bg-inverse"> 
      <div class="container-fluid"> 
        <button class="navbar-toggler collapsed" type="button"
          data-toggle="collapse" data-target="#navbar-header"
          aria-expanded="false"> 
        </button> 
        <a href="/" class="navbar-brand">MVC MySql App</a> 
      </div> 
      </div> 

              {% block content %} 
              {% endblock %} 
      <footer class="text-muted"> 
      <div class="container"> 
        <p class="pull-xs-right"> 
        <a href="#">Back to top</a>  
        </p> 
        <p>Sample Page using Album example from Â© Bootstrap!</p> 
        <p>New to Bootstrap? <a href="http://v4-alpha.getbootstrap.
            com/getting-started/introduction/">Visit the homepage
        </a>.</p> 
      </div> 
      </footer>
           {% include "../partials/footer.html" %} 
      </body> 
      </html> 

```

# 为应用程序添加样式

我们还将在`public/stylesheet`文件中添加一些 CSS 行来为我们的示例应用程序设置样式。

打开`public/stylesheets/style.css`并添加以下代码：

```js
  body { 
    min-height: 75rem; /* Can be removed; just added for demo purposes */ 
  } 
  .navbar { 
    margin-bottom: 0; 
  } 
  .navbar-collapse .container-fluid { 
    padding: 2rem 2.5rem; 
    border-bottom: 1px solid #55595c; 
  } 
  .navbar-collapse h4 { 
    color: #818a91; 
  } 
  .navbar-collapse .text-muted { 
    color: #818a91; 
  } 
  .about { 
    float: left; 
    max-width: 30rem; 
    margin-right: 3rem; 
  } 
  .social a { 
  font-weight: 500; 
    color: #eceeef; 
  } 
  .social a:hover { 
    color: #fff; 
  } 
  .jumbotron { 
    padding-top: 6rem; 
    padding-bottom: 6rem; 
    margin-bottom: 0; 
    background-color: #fff; 
  } 
  .jumbotron p:last-child { 
    margin-bottom: 0; 
  } 
  .jumbotron-heading { 
    font-weight: 300; 
  } 
  .jumbotron .container { 
    max-width: 45rem; 
  } 
  .album { 
    min-height: 50rem; /* Can be removed; just added for demo purposes */ 
    padding-top: 3rem; 
    padding-bottom: 3rem; 
    background-color: #f7f7f7; 
  } 
  .card { 
    float: left; 
    width: 33.333%; 
    padding: .75rem; 
    margin-bottom: 2rem; 
    border: 0; 
  } 
  .card > img { 
    margin-bottom: .75rem; 
  } 
  .card-text { 
    font-size: 85%; 
  } 
  footer { 
    padding-top: 3rem; 
    padding-bottom: 3rem; 
  } 
  footer p { 
    margin-bottom: .25rem; 
  } 

```

# 添加路由和应用程序控制器

我们将编辑`app.js`文件以向`band-list.html`视图添加路由，以及它们各自的控制器：

1.  打开`app.js`并在索引控制器导入后添加以下行：

```js
      // Inject band controller 
      var bands = require('./controllers/band'); 
      // Inject user controller 
      var users = require('./controllers/user'); 

```

1.  在索引路由`app.get('/', index.show);`后添加以下代码：

```js
      // Defining route to list and post 
      app.get('/bands', bands.list); 
      // Get band by ID 
      app.get('/band/:id', bands.byId); 
      // Create band 
      app.post('/bands', bands.create); 
      // Update 
      app.put('/band/:id', bands.update); 
      // Delete by id 
      app.delete('/band/:id', bands.delete); 
      // Defining route to list and post users 
      app.get('/users', users.list); 
      app.post('/users', users.create); 

```

此时，我们几乎完成了应用程序的所有工作； 让我们在浏览器上检查结果。

1.  打开您的终端/ shell，并键入以下命令：

```js
 npm start 

```

1.  打开浏览器并转到此 URL：`http://localhost:3000/`

结果将是以下截图：

![添加路由和应用程序控制器](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-6x-bp/img/image_02_006.jpg)

主屏幕的索引模板

如果我们检查`http://localhost:3000/bands`上的 Band 路由，我们将看到一个空屏幕，`http://localhost:3000/users`也是一样，但在这里我们找到了一个空的**JSON**数组。

让我们为 Band 的路由添加一些内容。

# 添加数据库内容

让我们在数据库中添加一些内容：

1.  创建一个名为`mvc_mysql_app.sql`的新文件，并放入以下代码：

```js
      # Dump of table Bands 
      # ------------------------------------------------------------ 

      DROP TABLE IF EXISTS `Bands`; 

      CREATE TABLE `Bands` ( 
        `id` int(11) NOT NULL AUTO_INCREMENT, 
        `name` varchar(255) DEFAULT NULL, 
        `description` varchar(255) DEFAULT NULL, 
        `album` varchar(255) DEFAULT NULL, 
        `year` varchar(255) DEFAULT NULL, 
        `UserId` int(11) DEFAULT NULL, 
        `createdAt` datetime NOT NULL, 
        `updatedAt` datetime NOT NULL, 
        PRIMARY KEY (`id`) 
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8; 

      LOCK TABLES `Bands` WRITE; 
      /*!40000 ALTER TABLE `Bands` DISABLE KEYS */; 

      INSERT INTO `Bands` (`id`, `name`, `description`, `album`, `year`,
      `UserId`, `createdAt`, `updatedAt`) 
      VALUES 
         (2,'Motorhead','Rock and Roll Band','http://s2.vagalume.com/
          motorhead/discografia/ace-of-spades-W320.jpg','1979',NULL,
          '2016-03-13 21:50:25','2016-03-12 21:50:25'), 
         (4,'Black Sabbath','Heavy Metal Band','http://s2.vagalume.com/
          black-sabbath/discografia/heaven-and-hell W320.jpg','1980',
          NULL,'2016-03-12 22:11:00','2016-03-12 23:08:30'), 
         (6,'Deep Purple','Heavy Metal band','http://s2.vagalume.com
          /deep-purple/discografia/perfect-strangersW320.jpg',
           '1988',NULL,'2016-03-13 23:09:59','2016-03-12 23:10:29'), 
         (7,'White Snake','Heavy Metal band','http://s2.vagalume.com/
           whitesnake/discografia/slip-of-the-tongueW320.jpg','1989',
            NULL,'2016-03-13 01:58:56','2016-03-13 01:58:56'),
         (8,'Iron maiden','Heavy Metal band','http://s2.vagalume.com/
            iron-maiden/discografia/the-number-of-the-beastW320.jpg',
            '1982',NULL,'2016-03-13 02:01:24','2016-03-13 02:01:24'),
         (9,'Queen','Heavy Metal band','http://s2.vagalume.com/queen
            /discografia/greatest-hits-vol-1-W320.jpg','1981',NULL,
            '2016-03-13 02:01:25','2016-03-13 02:01:25'); 

       /*!40000 ALTER TABLE `Bands` ENABLE KEYS */; 
       UNLOCK TABLES; 

       /*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */; 
       /*!40101 SET SQL_MODE=@OLD_SQL_MODE */; 
       /*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */; 
       /*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */; 
       /*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */; 
       /*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */; 

```

1.  打开**Sequel Pro**，单击**文件 > 导入 >**，然后选择 SQL 文件`mvc_mysql_app.sql`。

1.  返回浏览器并刷新`http://localhost:3000/bands`页面； 您将看到以下结果：![添加数据库内容](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-6x-bp/img/image_02_007.jpg)

Band-list.html

# 创建一个乐队表单

现在我们将使用模态功能 bootstrap 创建乐队创建表单：

1.  打开`views/pages/index.html`文件，并在文件末尾添加以下代码：

```js
      <div class="modal fade" id="createBand" tabindex="-1" role="dialog" 
         aria-labelledby="myModalLabel" aria-hidden="true"> 
      <div class="modal-dialog" role="document"> 
      <div class="modal-content"> 
        <form action="/bands" method="post"> 
          <div class="modal-header"> 
            <button type="button" class="close" data-dismiss="modal" 
             aria-label="Close"> 
            <span aria-hidden="true">&times;</span> 
            </button> 
              <h4 class="modal-title" id="myModalLabel">Insert an
               Album</h4> 
          </div> 
          <div class="modal-body"> 
          <fieldset class="form-group"> 
          <label  for="inputname">Band Name</label> 
          <input type="text" id="inputname" name="name" 
           class="form-control" placeholder="Band name" required=""> 
         </fieldset> 
         <fieldset class="form-group"> 
         <label  for="inputdescription">Description</label> 
         <textarea id="nputdescription" name="description" rows="8"
           cols="40" class="form-control" placeholder="Description"
           required="">
         </textarea> 
         </fieldset> 
         <fieldset class="form-group">  
         <label  for="inputalbum">Best Album</label> 
         <input type="text" id="inputalbum" name="album" rows="8" cols="40"  
          class="form-control" placeholder="Link to Album cover">
           </textarea> 
         </fieldset> 
       <fieldset class="form-group"> 
         <label  for="inputyear">Release Year</label> 
         <input type="text" id="inputyear" name="year" rows="8" cols="40" 
          class="form-control" placeholder="Year" required=""></textarea> 
       </fieldset> 

      </div> 
        <div class="modal-footer"> 
          <button type="button" class="btn btn-secondary" 
            data-dismiss="modal">Close</button> 
          <button type="submit" class="btn btn-primary">Save 
            changes</button> 
       </div> 
      </form> 
      </div> 
      </div> 
      </div> 

```

1.  重新启动应用程序，打开您的终端/ shell，并键入以下命令：

```js
 npm start

```

1.  单击**插入专辑**按钮，您可以在模型窗口内看到乐队表单，如下图所示：![创建乐队表单](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-6x-bp/img/image_02_008.jpg)

模态屏幕

## 插入新乐队

现在让我们检查表单的行为：

1.  使用以下数据填写表单：

+   名称：**Sepultura**

+   描述：**巴西垃圾金属乐队**

+   最佳专辑：**https://s2.vagalume.com/sepultura/discografia/roots-W320.jpg**

+   年份：**1996**

1.  单击**保存更改**按钮。

表单处理后，您将被重定向到`band-list.html`，并显示新记录，如下图所示：

![插入新乐队](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-6x-bp/img/image_02_009.jpg)

带有新记录的 Band-list.html 屏幕

`Band.js`控制器上的`create()`函数通过表单`POST`激活，并且`Band.js`控制器中的以下代码用于保存数据并重定向用户：

```js
      // Create Band 
      exports.create = function(req, res) { 
          // create a new instance of the Bands model with request body 
          models.Band.create(req.body).then(function(band) { 
              //res.json(band); 
              res.redirect('/bands'); 
          }); 
      }; 

```

# ODM（mongoose）和 ORM（sequelize）之间的主要区别

两个数据库映射器之间的主要区别是 Sequelize 使用 promises 而 Mongoose 不使用。 Promises 易于处理异步事件。 更明确地说，让我们看一下以下代码来比较这两个中间件：

1.  从上一章的`passport.js`文件中提取的代码块：

```js
      User.findOne({ 'local.email' :  email }, function(err, user) { 
                          // if errors 
                          if (err) 
                          return done(err); 
                          // check email 
                          if (user) { 
                              return done(null, false, 
                               req.flash('signupMessage', 'Wohh! the email
                                is already taken.')); 
                               } else { 
                              // create the user 
                              var newUser = new User(); 
                              // Get user name from req.body 
                              newUser.local.name = req.body.name; 
                              newUser.local.email = email; 
                              newUser.local.password = 
                                newUser.generateHash(password); 
                              // save data 
                              newUser.save(function(err) { 
                                  if (err) 
                                  throw err; 
                                  return done(null, newUser); 
                              }); 
                           } 
               }); 

```

1.  现在使用`sequelize` promises 函数的相同代码块：

```js
      User.findOne({ where: { localemail: email }}) 
          .then(function(user) { 

         if (user) 
             return done(null, false, req.flash('loginMessage', 'That
              email
               is already taken.')); 
          if(req.user) { 

              var user = req.user; 
              user.localemail = email; 
              user.localpassword = User.generateHash(password); 
              user.save() 
                  .then (function() { 
                      done(null, user); 
                  }) 
                  .catch(function (err) { 
                      done(null, false, req.flash('loginMessage',
                       err));}); 
                  }); 
          } else { 
              // create the user 
              var newUser = User.build ({ 
                  localemail: email, 
                  localpassword: User.generateHash(password) 
              }); 
              // store the newUser to the database 
              newUser.save() 
                  .then(function() { 
                      done (null, newUser); 
                  }) 
                  .catch(function(err) { 
                      done(null, false, req.flash('loginMessage',
                       err));}); 
                  } 
              }) 
          .catch(function (e) { 
               done(null, false, req.flash('loginMessage',e.name + " " + 
                   e.message));                  
         }) 

```

请注意，使用`then()`函数处理所有返回。

# 总结

在本章中，我们探索了`sequelize-CLI`命令行的所有功能，以在关系数据库中创建表的映射。 我们看到了如何使用`sequelize model feature create()`交互式地创建模型，还看到了如何将模式文件迁移到数据库。

我们使用标准模板引擎启动了应用程序，并了解了如何重构引擎模板并使用另一个资源，即**Swig**模板库。

我们学习了如何使用一些 SQL 命令连接到 MySQL 数据库以及创建表的一些基本命令。

在下一章中，我们将探索使用 Node.js 和其他重要资源来利用和操作图像。
