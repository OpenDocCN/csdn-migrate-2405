# Angular2 Bootstrap4 Web 开发（六）

> 原文：[`zh.annas-archive.org/md5/1998a305c23fbffe24116fac6b321687`](https://zh.annas-archive.org/md5/1998a305c23fbffe24116fac6b321687)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十章：高级 Angular 技术

本章介绍了高级的 Angular 技术。我们将学习如何在客户端创建身份验证，并在 Firebase 上进行测试。我们将介绍 Webpack 来管理模块及其依赖关系，并将静态资产转换为构建捆绑包。我们将学习如何安装`ng2-bootstrap`，以及它如何使读者能够更轻松地创建应用程序。最后，我们将完成在前几章中开始开发的项目。

在本章结束时，您将对以下内容有扎实的理解：

+   Webpack

+   Firebase 身份验证

+   `ng2-bootstrap`组件

+   Angular CLI

+   JIT 与 AOT 编译

让我们开始：

1.  打开终端，创建名为`ecommerce`的文件夹，并进入其中

1.  将`chapter_10/1.ecommerce-seed`文件夹中的项目内容复制到新项目中。

1.  运行以下脚本以安装`npm`模块：

```ts
 **npm install** 

```

1.  使用以下命令启动 TypeScript 监视器和轻量级服务器：

```ts
 **npm start** 

```

此脚本打开 Web 浏览器并导航到项目的欢迎页面。

# Webpack

到目前为止，我们已经使用 SystemJS 动态加载应用程序中的模块。现在我们将开始使用 Webpack 的方法来与 SystemJS 进行比较。随着本书的章节不断增加，我们的代码也在急剧增长，我们必须决定使用什么策略来加载塑造我们的 Web 应用程序的模块。Webpack 具有核心功能，并支持许多捆绑策略，可以直接使用或使用特定加载器和插件进行扩展。它遍历项目的所需语句，以生成我们定义的捆绑包。我们可以使用插件来执行特定任务，例如最小化，本地化等。以下是支持的功能的小列表：

+   **热模块重新加载**可以在不刷新的情况下立即更新 Angular 2 组件

+   通过**延迟加载**机制根据需要加载捆绑包

+   将应用程序代码分开成捆绑包

+   使用**哈希**在浏览器中高效地缓存 Web 应用程序的捆绑包

+   为捆绑包生成**源映射**，以便轻松调试捆绑包的最小化版本等

# Webpack 迁移

当然，使用 Webpack 需要一些时间的承诺，但我们可以获得管理独立依赖项和性能改进的所有好处。我已经准备了详细的迁移计划，可以轻松地从 SystemJS 迁移到 Webpack。

## 安装 Webpack CLI

在使用之前，我们必须全局安装 Webpack。在终端中运行以下命令以使该命令可用：

```ts
 **npm install -g webpack** 

```

## 更新包

到目前为止，我们一直使用`lite-server`来提供我们的应用程序。Webpack 有自己的`webpack-dev-server`，一个小型的 Node.js Express 服务器，通过 Webpack 中间件来提供捆绑文件。`webpack-dev-server`是一个单独的 npm 包，因此我们需要相应地更新`package.json`中的`devDependencies`：

```ts
"devDependencies": { 
    "typescript": "².0.0", 
    "typings": "¹.0.5", 

    "ts-loader": "⁰.8.2", 
    "webpack": "¹.12.2", 
 **"webpack-dev-server": "¹.12.1"** 

  } 

```

`webpack-dev-server`将提供当前目录中的文件，除非我们对其进行配置。根据以下代码定义，更改`package.json`中的`scripts`部分：

```ts
"scripts": { 
    "start": "webpack-dev-server", 
    "build": "webpack", 
    "postinstall": "typings install" 
  } 

```

## 更新 TypeScript 配置

从一方面，Webpack 是一个模块捆绑器，它使用 CommonJS 或 AMD 格式来解析模块之间的依赖关系。从另一方面，Typescript 编译器支持几种模块代码生成。我们需要选择一个适用于两者的模块格式，所以我决定使用 CommonJS，因为它更方便。请打开`tsconfig.json`文件并使用以下内容进行更新：

```ts
{ 
  "compilerOptions": { 
    "target": "es5", 
 **"module": "commonjs",** 

    "moduleResolution": "node", 
    "sourceMap": true, 
    "emitDecoratorMetadata": true, 
    "experimentalDecorators": true, 
    "removeComments": false, 
    "noImplicitAny": false 
  } 
} 

```

现在，是时候安装所有必要的`npm`模块和`typings`了。打开终端并运行以下命令：

```ts
 **npm install** 

```

## 创建 Webpack 配置文件

有两种配置 Webpack 的方法：

+   通过 CLI，当 Webpack 读取一个名为`webpack.config.js`的文件或我们将其指定为`--config`选项

+   通过 Node.js API，我们将配置对象作为参数传递

第一种方法对我们来说更方便，所以让我们创建`webpack.config.js`文件。Webpack 中的配置文件是一个 CommonJS 模块。我们将所有配置、加载器和与构建相关的其他特定信息放入这个文件中。每个配置文件必须具有两个主要属性：

+   一个或多个捆绑的入口点。

+   输出影响编译结果，告诉 Webpack 如何将编译后的文件写入磁盘。即使我们有多个入口点，也只有一个输出属性。

让我们将以下内容添加到`webpack.config.js`文件中：

```ts
module.exports = { 
    entry: "./app/main", 
    output: { 
        path: __dirname, 
        filename: "./dist/bundle.js" 
    }, 
    resolve: { 
        extensions: ['', '.js', '.ts'] 
    }, 
    devServer: { 
        historyApiFallback: true, 
        open: true, 
        watch: true, 
        inline: true, 
        colors: true, 
        port: 9000 
    }, 
    module: { 
        loaders: [{ 
            test: /\.ts/, loaders: ['ts-loader'],  
              exclude: /node_modules/ 
        }] 
    } 
}; 

```

我们将在 app 文件夹中使用`main.js`文件作为入口点。我们计划将编译结果保存到`dist`目录下的`bundle.js`文件中。`__dirname`是当前执行脚本所在的目录的名称。我添加了一个`extensions`数组，Webpack 将用它来`resolve`模块。

Webpack 只能原生处理 JavaScript，因此我们需要将`ts-loader`添加到`loaders`中以处理 TypeScript 文件。**加载器**允许我们在请求文件时预处理文件。加载器可以链接在一起，并且始终从右到左应用。我们可以在模块`request`中指定加载器，但如果我们想要避免重复性，有一个更好的方法。只需将它们添加到 Webpack 配置文件中，并指定如何将它们应用于不同的文件类型。Webpack 使用加载器的`test`属性来查找特定文件并相应地转换它们的内容。我们可以添加额外的条件来通过`include`和`exclude`条件属性找到文件。条件始终针对绝对路径进行测试，并且可以是以下之一：

+   正则表达式

+   一个带有路径的字符串

+   一个以路径作为参数并返回布尔结果的函数

+   上述任一组合的数组与`and`

最后但同样重要的是开发服务器配置。我们可以通过 CLI 配置`webpack-dev-server`，但更优雅的方法是将`devServer`部分添加到`webpack.config.js`文件中，我们可以在其中放置服务器需要的所有属性：

+   `historyApiFallback`有助于使用 HTML5 历史 API

+   `open`标志只是在 Web 浏览器中打开后端服务器 URL

+   `watch`标志告诉运行时监视源文件，并在更改时重新编译捆绑包

+   `inline`标志将`webpack-dev-server`运行时嵌入到捆绑包中

+   `colors`选项为输出添加一些颜色

+   `port`包含后端服务器 URL 端口号

+   `host`保留服务器 URL 主机

让我们测试 Webpack 如何使用以下命令构建项目：

```ts
 **npm run build** 

```

Webpack 应该在`dist`文件夹内创建`bundle.js`文件。

## 更新标记

接下来要做的是更新`index.html`文件。我们需要删除所有属于 SystemJS 的代码并插入新代码：

```ts
<html> 
  <head> 
    <title>The Dream Bean Grocery Store</title> 
    <base href="/"> 
    <meta charset="UTF-8"> 
    <meta name="viewport"  
          content="width=device-width, initial-scale=1"> 
    <link rel="stylesheet"  
          href="node_modules/bootstrap/dist/css/bootstrap.css"> 
    <link rel="stylesheet"  
          href="https://maxcdn.bootstrapcdn.com/font-awesome/4.6.3/css/font-awesome.min.css"> 
    <link rel="stylesheet" href="assets/ecommerce.css"> 
  </head> 

  <body> 
    <my-app>Loading...</my-app> 
  </body> 

  <script src="node_modules/zone.js/dist/zone.js"></script> 
  <script src="node_modules/reflect-metadata/Reflect.js"></script> 

  <script src="node_modules/jquery/dist/jquery.min.js"></script> 
  <script  
       src="node_modules/tether/dist/js/tether.min.js"></script> 
  <script  
       src="node_modules/bootstrap/dist/js/bootstrap.js"></script> 

 **<script src="dist/bundle.js"></script>** 

</html> 

```

现在我们准备启动`webpack-dev-server`服务器。打开终端并运行以下命令：

```ts
 **npm start** 

```

Webpack 打开 Web 浏览器并导航到以下 Web 地址：`http://localhost:9000`。

### 提示

你可以在`chapter_10/2.ecommerce-webpack`找到此源代码。

# 为生产准备我们的项目

我们可以使用项目，但最好进行一些更改以改进构建流程，以便我们可以准备部署项目结构。让我们创建一个源文件夹，并将我们的源代码、样式和模板文件放在里面。我想将所有资源都包含在包中，并向您展示 Webpack 通过插件的完全潜力使用。

## 三个主要条目

我们的项目代码仍然远未达到生产状态。我们在`index.html`文件中留下了对 JavaScript 资源的引用，另外我们还需要考虑如何加载样式文件、Angular 2 和其他第三方模块。计划非常简单：我们需要将所有依赖项拆分为它们自己的包：

+   `main`文件将保留对我们应用程序的引用

+   `polyfill`文件包含所有必要的 polyfill 的引用

+   `vendor`文件包含我们使用的所有供应商

这种方法的一个好处是，我们可以独立于我们的代码添加和删除 polyfills 和 vendors，因此我们不需要重新编译它。

## Webpack 插件

Webpack 有一组内置插件。我们需要将它们添加到 Webpack 配置文件中的`plugins`属性中。Webpack 将插件按组进行拆分，例如配置、输出、优化、依赖注入、本地化、调试等。您可以在这里找到内置的 Webpack 插件列表：[`webpack.github.io/docs/list-of-plugins.html`](https://webpack.github.io/docs/list-of-plugins.html)。

### DefinePlugin

很明显，我们需要分开开发和生产配置，因为它们具有不同的全局常量和行为。这个插件允许我们在编译时创建全局常量，并在所有其他插件中使用：

```ts
const NODE_ENV = process.env.NODE_ENV; 
//... 
config.plugins = [ 
  new DefinePlugin({ 
    'process.env.NODE_ENV': JSON.stringify(NODE_ENV) 
  }),  
//... 
]; 

```

现在`process.env.NODE_ENV`在全局范围内可用，`main.ts`文件中的以下代码将起作用：

```ts
if (process.env.NODE_ENV === 'production') { 
  enableProdMode(); 
} 

```

### ProvidePlugin

Bootstrap 模块需要包含在我们的应用程序中的第三方库，例如*jQuery*和*Tether*。我们将使用`ProvidePlugin`自动加载这些模块，并使它们在 Bootstrap 中可用：

```ts
new ProvidePlugin({ 
    jQuery: 'jquery', 
    $: 'jquery', 
    jquery: 'jquery', 
    "Tether": 'tether', 
    "window.Tether": "tether" 
}) 

```

### ProgressPlugin

我们使用这个插件在终端中显示编译进度。

### LoaderOptionsPlugin

这个插件允许我们向一些特定的加载器添加选项：

```ts
new LoaderOptionsPlugin({ 
    debug: false, 
    minimize: ENV_PRODUCTION 
}) 

```

如果您开发自己的加载程序，可以将其激活为`debug`模式，将其设置为`true`。在我们的情况下，我们使用`ENV_PRODUCTION`全局常量仅在生产中激活加载程序以最小化模式。

### CommonsChunkPlugin

Webpack 有一个可选择的功能，可以帮助将代码拆分成块并按需加载。此外，我们需要定义拆分点，Webpack 会处理一切，如依赖关系、输出和运行时的东西：

```ts
new CommonsChunkPlugin({ 
  name: ['vendor', 'polyfills'], 
  minChunks: Infinity 
}) 

```

在我们的项目中，我明确地将供应商和 polyfills 文件隔离在它们的包中。`minChunks`选项是模块在移动到公共块之前需要包含的最小块数。它可以包含一个数字、回调函数或`Infinity`关键字。传递`Infinity`会创建一个公共块，而不将模块移动到其中。

### UglifyJsPlugin

这个插件最小化了所有块的 JavaScript 输出：

```ts
new UglifyJsPlugin({ 
  comments: false, 
  compress: { 
    dead_code: true, // eslint-disable-line camelcase 
    screw_ie8: true, // eslint-disable-line camelcase 
    unused: true, 
    warnings: false 
  }, 
  mangle: { 
    screw_ie8: true  // eslint-disable-line camelcase 
  } 
}) 

```

我们只在生产中使用它，它会删除注释，并压缩和混淆 JavaScript 文件中的变量名。

以下是我们项目中使用的几个第三方插件。它们都必须作为单独的 npm 模块安装：

### extract-text-webpack-plugin

我在`main.ts`文件中导入了我们项目的样式文件，如下所示：

```ts
/** 
 * Import styles 
 */ 
import './assets/ecommerce.scss'; 

```

Webpack 将在`bundle.js`文件中包含`ecommerce.scss`文件的代码。这个解决方案在开发中运行得很完美，但我希望在生产中将样式保持为单独的文件，原因如下：

+   CSS 不是 JavaScript 包的一部分

+   CSS 包并行请求到 JavaScript 包

+   CSS 被单独缓存

+   由于代码和 DOM 操作减少，运行时更快

`ExtractTextPlugin` 必须添加到两个地方：

+   在加载程序中提取 CSS 文件

+   在插件中指定结果文件名和编译器的必要行为：

```ts
        config.module.loaders.push({ 
          test: /\.scss$/, 
          loader: ExtractTextPlugin 
                  .extract('css?-autoprefixer!postcss!sass'), 
          include: path.resolve('src/assets/ecommerce.scss') 
        }); 
        config.plugins.push( 
           new ExtractTextPlugin('styles.[contenthash].css') 
        ) 

```

编译后，我们将得到准备好用于生产的样式和源映射文件。

### webpack-md5-hash 插件

每当 Webpack 将资源编译成包时，它会计算每个包的`hash`总和，并将这个数字作为`chunkhash`字符串用于文件名：

```ts
[chunkhash].[id].chunk.js 

```

我更喜欢使用基于 Md5 的哈希生成器插件来替换我们项目中标准的 Webpack `chunkhash`。

### html-webpack-plugin

正如我们所说，Webpack 每次都会计算和生成捆绑包文件名的哈希值，因此我们必须以某种方式更新我们的`index.html`文件中的信息。`html-webpack-plugin`有助于使这个过程变得轻松，并快速地将所有 HTML 生成的捆绑包添加到应用程序中：

```ts
new HtmlWebpackPlugin({ 
  chunkSortMode: 'dependency', 
  filename: 'index.html', 
  hash: false, 
  inject: 'body', 
  template: './src/index.html' 
}) 

```

我使用源文件中的`index.html`作为`模板`，插件将使用它来生成`dist`文件夹中的最终 HTML 文件。我们可以将生成的 JavaScript 捆绑包`注入`到`head`中，但通常我们会将它们添加到页面底部，就在`body`标签关闭之前。该插件将按照依赖关系的顺序添加捆绑包。模板的格式基于**嵌入式 JavaScript**（**EJS**）模板系统，因此我们可以将值传递给插件，它将直接在 HTML 中检索这些值。

## 加载器

项目的最新版本使用了更多的加载器。加载器，就像模块一样，可以通过 npm 安装。我们使用加载器来教导 Webpack 新的功能。您可以在这里找到 Webpack 加载器的列表：[`webpack.github.io/docs/list-of-loaders.html`](https://webpack.github.io/docs/list-of-loaders.html)。

## 加载器命名约定和搜索顺序

通常，加载器的命名为`<context-name>-loader`，以便在配置中通过它们的全名或简称轻松引用它们。您可以通过 Webpack 配置中的`resolveLoader`的`moduleTemplates`属性更改加载器的命名约定和优先搜索顺序：

```ts
["*-webpack-loader", "*-web-loader", "*-loader", "*"] 

```

## bootstrap-loader

`bootstrap-loader`在 Webpack 捆绑包中加载 Bootstrap 样式和脚本。默认情况下，它预先配置为加载 Bootstrap 3。我们可以使用一个特殊的配置文件`.bootstraprc`来调整加载过程的许多细节。`bootstrapVersion`选项告诉加载器要加载哪个 Bootstrap 的主要版本。插件的作者建议使用默认配置作为起点，以防止不必要的升级或错误。您可以以 YAML 或 JSON 格式编写它。您可以在官方网站上找到完整的文档：[`github.com/shakacode/bootstrap-loader`](https://github.com/shakacode/bootstrap-loader)。

## css-loader

`css-loader`可以将 CSS 文件作为捆绑包的一部分下载。它解析和解释`imports`和`url`语句作为`require`：

```ts
url(image.png) => require("./image.png") 

```

默认情况下，`css-loader`会在模块系统指定的情况下最小化 CSS 文件。项目在 GitHub 上的网址是[`github.com/webpack/css-loader`](https://github.com/webpack/css-loader)。

## file-loader

`file-loader`将文件复制到输出文件夹并返回公共 URL：

```ts
var url = require("file!./file.png"); 

```

它处理文件内容以对 MD5 哈希求和，并将其用作结果文件的文件名：

```ts
/public-path/0dcbbaa701328a3c262cfd45869e351f.png 

```

您可以通过查询参数（如`name`，`ext`，`path`，`hash`）配置自定义文件名模板：

```ts
require("file?name=js/[hash].script.[ext]!./javascript.js"); 
// => js/0dcbbaa701328a3c262cfd45869e351f.script.js 

```

您可以在官方网站上找到文档：[`github.com/webpack/file-loader`](https://github.com/webpack/file-loader)。

## postcss-loader

有超过 200 个 PostCSS 插件可用于解决全局 CSS 问题，使用未来的 CSS，或改善 CSS 文件的可读性。可以在官方插件列表中发现的网址是：[`postcss.parts/`](http://postcss.parts/)。

`postcss-loader`使用 PostCSS JS 插件来转换样式：

```ts
const autoprefixer = require('autoprefixer'); 
//... 
config.module.loaders.push({ 
    test: /\.scss$/, 
    loader:  
      ExtractTextPlugin.extract('css?-autoprefixer!postcss!sass'), 
    include: path.resolve('src/assets/ecommerce.scss') 
  }); 

```

您可以在这里找到有关如何使用它的完整文档：[`github.com/postcss/postcss-loader`](https://github.com/postcss/postcss-loader)。

## raw-loader

此加载程序只是读取文件内容并将其作为字符串返回：

```ts
var fileContent = require("raw!./file.txt"); 
// => returns file.txt content as string 

```

在官方网站上查看：[`github.com/webpack/raw-loader`](https://github.com/webpack/raw-loader)。

## resolve-url-loader

通常，我们将此文件与其他加载程序一起使用。它基于原始源文件解析`url`语句中的相对路径：

```ts
var css = require('!css!resolve-url!./file.css'); 

```

在官方网站上查看链接：[`github.com/bholloway/resolve-url-loader`](https://github.com/bholloway/resolve-url-loader)。

## sass-loader

它加载 SASS 文件进行处理：

```ts
var css = require("!raw!sass!./file.scss"); 
// returns compiled css code from file.scss, resolves Sass imports 

```

在这里找到完整的文档：[`github.com/jtangelder/sass-loader`](https://github.com/jtangelder/sass-loader)。

## style-loader

使用 style-loader 的帮助，您可以忘记手动将 CSS 文件添加到 HTML 文件中。它通过注入样式标签将 CSS 添加到 DOM 中。这对开发非常有用，但我建议您在构建生产环境时将 CSS 内容提取到单独的文件或捆绑包中。有关完整信息的网址是：[`github.com/webpack/style-loader`](https://github.com/webpack/style-loader)。

## ts-loader

在使用此加载程序之前，您必须安装 TypeScript。它加载 TypeScript 文件并运行编译：

```ts
module.exports.module = { 
    loaders: [ 
      // all files with a `.ts` or `.tsx` extension  
      // will be handled by `ts-loader` 
      { test: /\.tsx?$/, loader: 'ts-loader' } 
    ] 
  } 
} 

```

访问官方网站以获取更多信息：[`github.com/TypeStrong/ts-loader`](https://github.com/TypeStrong/ts-loader)。

## url-loader

这个加载器类似于文件加载器，但如果文件大小小于限制，它只返回数据 URL：

```ts
require("url?limit=10000!./file.png"); 
// => DataUrl if "file.png" is smaller that 10kb 

```

在这里找到更多信息：[`github.com/webpack/url-loader`](https://github.com/webpack/url-loader)。

### 提示

您可以在`chapter_10/3.ecommerce-webpack-advanced`找到源代码。

# 用户身份验证

**身份验证**是向用户提供身份的过程。没有这个，我们无法为用户提供特定的服务来授予用户数据的权限。这对于安全敏感信息如信用卡详细信息来说是高风险的，因此我们需要安全地保存用户数据。

# 在应用程序中添加身份验证

Firebase 带来了简单的身份验证，因此我们可以将其与任何现有的登录服务器或清晰的基于云的解决方案集成。它支持来自 GitHub、Google、Twitter 和 Facebook 的第三方身份验证，以及通过电子邮件的内置身份验证。每个提供商都有他们自己的设置步骤。我将使用**密码身份验证提供商**，但您随时可以添加其他提供商。请在以下网页中找到官方文档：[`firebase.google.com/docs/auth`](https://firebase.google.com/docs/auth)。

# 启用身份验证提供程序

当我们创建我们的 Web 应用程序实例时，Firebase 禁用了所有提供程序，因此我们需要在使用之前启用一个。打开 Web 浏览器，导航到 Firebase 控制台，并进入我们的应用程序。点击左侧边栏上的**Auth**菜单项：

![启用身份验证提供程序](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-bts4-ng2-2e/img/Image00146.jpg)

点击**设置登录方法**进入。点击**电子邮件/密码**并在弹出对话框中激活提供程序：

![启用身份验证提供程序](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-bts4-ng2-2e/img/Image00147.jpg)

以下**OAuth 重定向域**部分仅保留我们列入白名单以启动我们应用程序身份验证的域：

![启用身份验证提供程序](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-bts4-ng2-2e/img/Image00148.jpg)

当我们注册我们的应用程序时，Firebase 添加了以下来源：

+   `localhost`，以便我们可以在本地开发和测试

+   `https://<your-project-id>.firebaseapp.com`，以便我们可以使用 Firebase 托管

如果您计划在其他授权来源中托管您的应用程序，您需要将它们全部添加到此处以启用来自其域的身份验证。

# AngularFirebase2 身份验证

**AngularFire2 身份验证**可以在不配置的情况下工作，但最好在使用之前进行配置。最好的地方是`app.module.ts`文件，我们在其中定义了`AppModule`：

```ts
/* 
 * Angular Firebase 
 */ 
import {AngularFireModule, AuthProviders, AuthMethods}  
    from 'angularfire2'; 
import * as firebase from 'firebase'; 

// Initialize Firebase 
export var firebaseConfig = { 
  apiKey: "AIzaSyDDrc42huFLZqnG-pAg1Ly9VnFtVx3m-Cg", 
  authDomain: "ecommerce-a99fc.firebaseapp.com", 
  databaseURL: "https://ecommerce-a99fc.firebaseio.com", 
  storageBucket: "ecommerce-a99fc.appspot.com", 
}; 
// Initialize Firebase Authentication 
 **const firebaseAuthConfig = {** 

 **provider: AuthProviders.Password,** 

 **method: AuthMethods.Redirect** 

 **}** 

@NgModule({ 
  imports: [HttpModule, 
 **AngularFireModule.initializeApp(firebaseConfig,** 

 **firebaseAuthConfig),** 

            BrowserModule, FormsModule, ReactiveFormsModule,  
            routing, CartModule, CategoryModule, ProductModule], 
  declarations: [AppComponent, NavbarComponent, FooterComponent,  
                WelcomeComponent, CheckoutViewComponent], 
  bootstrap: [AppComponent] 
}) 
export class AppModule { } 

```

在`firebaseAuthConfig`中，我们指示使用密码身份验证，Firebase 将重定向到登录页面进行登录。创建`auth`文件夹和其中的`auth.service.ts`文件。

## 身份验证服务

`AuthService`是一个适配器类，它隐藏了 Firebase 如何对用户进行身份验证的实现细节。它使用`FirebaseAuth`类为我们完成所有工作：

```ts
constructor(public auth$: FirebaseAuth) { 
    auth$.subscribe((state: FirebaseAuthState) => { 
        this.authState = state; 
    }); 
} 

```

我们应用程序的一些组件需要实时了解用户的身份验证状态，因此我订阅了从`FirebaseAuth`服务监听`FirebaseAuthState`事件。我们的类包括两个主要方法来管理用户的身份验证：

```ts
signIn(email: string, password: string):  
   firebase.Promise<FirebaseAuthState> { 
    return this.auth$.login({ 
        email: email, 
        password: password 
    }, { 
        provider: AuthProviders.Password, 
        method: AuthMethods.Password, 
    }); 
} 

signOut(): void { 
    this.auth$.logout(); 
} 

```

`signIn`方法期望用户凭据，如电子邮件和密码，以登录并在 Firebase promise 中返回`FirebaseAuthState`。`signOut`帮助我们从应用程序中注销

## SignInComponent

创建`sign-in.component.ts`文件来保存**SignInComponent**的代码。这是一个表单，用户在其中输入他/她的凭据并点击**登录**以将电子邮件和密码传递到身份验证服务。它监听 Firebase 返回的响应以将用户重定向到欢迎页面：

```ts
onSubmit(values:any): void { 
    this.submitted = true; 
    this.auth.signIn(values.email, values.password) 
        .then(() => this.postSignIn()) 
        .catch((error) => { 
            this.error = 'Username or password is incorrect'; 
            this.submitted = false; 
        }); 
} 

private postSignIn(): void { 
    this.router.navigate(['/welcome']); 
} 

```

该代码在电子邮件和密码组合不正确时显示错误消息。为了保护应用程序的路由免受未经授权的用户的访问，我们将使用名为 Guards 的 Angular 2 功能。

## Angular Guards

Angular 2 路由器提供了一个名为**Guard**的功能，它返回`Observable<boolean>`、`Promise<boolean>`或`boolean`来允许激活、停用或加载组件。它可以注册为依赖注入的函数或类。如果我们需要依赖注入功能，则类注册具有好处。要将 Guard 注册为类，我们需要实现 Angular 提供的接口之一。

有四个 Angular Guards 接口：

+   `CanActivate` Guard 检查路由是否可以被激活

+   `CanActivateChild` Guard 检查特定路由的子路由是否可以被激活

+   `CanDeactivate` Guard 检查路由是否可以被停用

+   `CanLoad` Guard 检查模块是否可以加载

因为我们的守卫代码将使用身份验证服务，所以我创建了`auth.guard.ts`文件和`AuthGuard`作为实现`CanActivate`接口的类：

```ts
export class AuthGuard implements CanActivate { 

    constructor(private auth: AuthService, private router: Router)  
    { } 

    canActivate(): Observable<boolean>|boolean { 
      return this.auth.auth$.map((authState: FirebaseAuthState)=>{ 
            if (authState) { 
                return true; 
            } else { 
                this.router.navigateByUrl('/login'); 
                return false; 
            } 
      }).first(); 
    } 
} 

```

Angular 路由器将调用接口的`canActivate`方法来决定是否可以通过监听`FirebaseAuthState`事件来激活路由。如果用户成功验证，该方法返回`true`，然后将激活路由中注册的组件。如果没有，则返回`false`并将用户重定向到登录页面。

## 在 Navbar 中注销

我认为如果我们的用户有选择从 Web 应用程序注销的选项是一个好主意。我们应该将身份验证服务注入`Navbar`组件，并创建注销方法来调用它以注销用户：

```ts
export class NavbarComponent { 
  constructor(private authService: AuthService,  
              private router: Router) { } 

  logout() { 
    this.authService.signOut(); 
    this.router.navigateByUrl("/login"); 
  } 
} 

```

正如您所记得的，我们在`AuthService`中有一个`authenticated`属性，它在用户登录或退出应用程序时更改状态。我们将使用它来管理标记中**Sign Out**和**Cart**组件的外观：

```ts
<div class="collapse navbar-toggleable-xs"  
  id="exCollapsingNavbar"> 
  <a class="navbar-brand" href="">Dream Bean</a> 

  <div class="nav navbar-nav"> 
    <a class="nav-item nav-link" (click)="logout()"  
       ***ngIf="authService.authenticated"** 

>Sign out</a> 
  </div> 

  <db-cart-menu ***ngIf="authService.authenticated"** 

></db-cart-menu> 
</div> 

```

当用户登录应用程序时，这两个组件变得可见。

## 更新 Firebase 数据库规则

现在，当我们在客户端保护我们的应用程序时，我们必须更改 Firebase 数据库规则，以便只有经过身份验证的用户才能访问数据：

```ts
{ 
  "rules": { 
 **".read": "auth != null",** 

    ".write": "auth != null", 
    "products": { 
      ".indexOn": ["categoryId", "title"] 
    } 
  } 
} 

```

## 玩的时间

打开终端并运行以下命令进行生产构建：

```ts
 **npm run build** 

```

成功完成后，我们可以将应用程序部署到 Firebase 托管上：

```ts
 **firebase login** 

 **firebase deploy** 

```

打开 Web 浏览器并导航到 Web 应用程序：`https://<your-project-id>.firebaseapp.com`。

任何组合的电子邮件和密码都会在屏幕上带来异常授权消息：

![玩的时间](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-bts4-ng2-2e/img/Image00149.jpg)

我们的应用程序没有注册表单，因此我们可以通过控制台直接将*测试用户*添加到 Firebase 中。打开 Firebase 控制台并导航到我们的应用程序。点击左侧边栏上的**Auth**链接以打开**Authentication**页面：

![玩的时间](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-bts4-ng2-2e/img/Image00150.jpg)

点击**添加用户**以打开弹出对话框：

![玩的时间](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-bts4-ng2-2e/img/Image00151.jpg)

填写空白字段并点击**添加用户**。现在我们有了注册的测试用户，我们可以回到我们的应用程序并使用电子邮件和密码成功登录。

### 提示

您可以在`chapter_10/ 4.ecommerce-firebase-auth`找到此源代码。

# ng2-bootstrap

有一个`ng2-bootstrap`库，它不依赖于 jQuery 和 Bootstrap JavaScript 文件。它具有一组用于 Bootstrap 版本 3 和 4 的原生 Angular 2 指令，因此尝试它不会花费任何费用。有关如何使用不同组件的更多信息，请访问官方网站：[`valor-software.com/ng2-bootstrap/index-bs4.html`](https://valor-software.com/ng2-bootstrap/index-bs4.html)。

首先，我们将清除项目中基于 bootstrap 的模块：

```ts
 **npm uninstall -save bootstrap bootstrap-loader jquery tether** 

```

然后，从`vendors.js`文件中删除 Bootstrap 4 模块：

```ts
// Bootstrap 4 
import "jquery"; 
import "bootstrap-loader"; 

```

现在，我们已经准备好安装，所以打开终端并安装`ng2-bootstrap`：

```ts
npm install ng2-bootstrap --save 

```

`ng2-bootstrap`模块必须导入到`AppModule`中。安装后，`ng2-bootstrap`支持 Bootstrap 版本 3，因此在使用之前必须将主题设置为 Bootstrap 4：

```ts
 **import {Ng2BootstrapModule, Ng2BootstrapConfig, Ng2BootstrapTheme}** 

 **from 'ng2-bootstrap';** 

 **Ng2BootstrapConfig.theme = Ng2BootstrapTheme.BS4;** 

@NgModule({ 
  imports: [ 
    AngularFireModule.initializeApp(firebaseConfig,  
      firebaseAuthConfig), AuthModule, 
    BrowserModule, FormsModule, ReactiveFormsModule, 
    routing, CartModule, CategoryModule, ProductModule,  
 **Ng2BootstrapModule],** 

  declarations: [AppComponent, NavbarComponent, FooterComponent, 
    WelcomeComponent, CheckoutViewComponent], 
  bootstrap: [AppComponent] 
}) 
export class AppModule { } 

```

最后，我们将在`index.html`中添加引用 CDN 上的 Bootstrap 4 CSS 链接：

```ts
<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-alpha.2/css/bootstrap.min.css" crossorigin="anonymous"> 

```

迁移计划已经很清楚：找到所有可以使用`ng2-bootstrap`的地方，并将基于 Bootstrap 4 的代码更改为相应的组件。

## 更新欢迎页面上的幻灯片播放

在欢迎页面上，我们使用幻灯片组件来循环播放图片作为轮播图。`ng2-bootstrap`有一个原生组件轮播图可以做同样的事情。使用新组件的主要好处是编写更少的标记代码：

```ts
<carousel> 
  <slide *ngFor="let category of slideCategories; let i=index"  
         [active]="category.active"> 
    <db-category-slide [category]="category"></db-category-slide> 
  </slide> 
</carousel> 

```

轮播图具有以下属性，我们可以用来管理幻灯片播放：

+   `interval`属性是以毫秒为单位延迟自动循环项目之间的时间量。默认情况下，此数量等于 5,000。如果将其更改为`false`，则轮播图将不会自动循环。

+   `noTransition`属性将禁用幻灯片之间的过渡。默认情况下为`false`。

+   `noPause`属性将禁用鼠标悬停时的轮播暂停。默认情况下为`false`。

+   `noWrap`属性将阻止连续循环。默认情况下设置为`false`。

## 更新导航栏中的下拉购物车

我们在导航栏中使用下拉组件来显示用户的购物车信息。让我们从`ng2-bootstrap`中更新此组件。

首先，我们需要将`DropdownModule`导入`CartModule`：

```ts
 **import {DropdownModule} from 'ng2-bootstrap';** 

@NgModule({ 
    imports: [CommonModule, FormsModule, ReactiveFormsModule,  
              RouterModule, DropdownModule], 
    declarations: [CartItemCountComponent, CartMenuComponent,  
                   CartViewComponent], 
    exports: [CartMenuComponent, CartViewComponent,  
              CartItemCountComponent], 
    providers: [CartService] 
}) 
export class CartModule {} 

```

之后，打开`cart-menu.component.html`并更新包裹购物车内容的标记代码：

```ts
<div class="nav navbar-nav float-xs-right"> 
    <div class="nav-item"> 
        <div dropdown> 
            <a href class="nav-link" id="cart-dropdown"  
               dropdownToggle> 
                Cart: {{cart.amount | currency:'USD':true: 
                        '1.2-2'}} ({{cart.count}} items) 
            </a> 
            <div class="dropdown-menu dropdown-menu-right"  
                 dropdownMenu aria-labelledby="cart-dropdown"> 
              <!-- cart content --> 
            </div> 
        </div> 
    </div> 
</div> 

```

任何基于`ng2-bootstrap`的下拉解决方案都应包括以下组件：

+   带有`dropdown`指令标记的下拉根元素

+   一个可选的标记为`dropdownToggle`的切换元素

+   一个包含用`dropdownMenu`标记的内容的下拉菜单

我们可以使用`isOpen`属性来管理下拉菜单的打开状态。

### 提示

你可以在`chapter_10/5.ecommerce-ng2-bootstrap`找到这个项目的源代码。

# Angular CLI

现在您已经了解了如何使用 SystemJS 或 Webpack 创建 Web 应用程序，并且了解到这不是一个简单的过程。请记住，属于不同模块加载程序的所有配置都太复杂了，有时您会花费太多时间在例行任务上。到目前为止，我们已经自己处理了所有事情，但是值得添加 Angular CLI 到脚手架中来处理繁琐的任务和构建 Angular 应用程序。

以下命令将安装 Angular CLI：

```ts
 **npm install -g angular-cli** 

```

运行以下命令以获取使用命令：

```ts
 **ng --help** 

```

我们将使用以下命令创建新的 Angular 项目：

```ts
 **ng new ecommerce** 

```

几分钟后，您将准备好使用安装的 NPM 模块启动 Angular 2 项目。进入项目文件夹并启动开发服务器：

```ts
 **cd ecommerce** 

 **ng serve** 

```

现在在 Web 浏览器中打开`localhost:4200`。当生成源代码和文件夹时，Angular CLI 遵循推荐的应用程序结构和样式指南。我们在开发项目时也遵循了相同的原则，以便可以顺利地将代码从上一个项目移动到新项目中。

停止服务器并安装以下模块：

```ts
 **npm i angularfire2 firebase @types/request ng2-bootstrap** 

```

在项目的根目录中找到`angular-cli.json`文件，并在`styles`和`scripts`中进行以下更改，以添加对我们的`ecommerce.scss`样式和`ng2-bootstrap`包的引用：

```ts
"styles": [ 
  "assets/ecommerce.scss" 
], 
"scripts": [ 
  "../node_modules/ng2-bootstrap/bundles/ng2-bootstrap.umd.js" 
], 

```

从上一个项目中复制`database.rules.json`，`firebase.json`和`firebase.import.json`文件，这样我们就可以使用 Firebase CLI 将项目部署到主机。

删除`src/app`文件夹中的所有文件，除了`index.ts`文件。将上一个项目的`src/app`文件夹中的所有文件复制到新项目中。

现在运行开发服务器，并在 Web 浏览器中打开或刷新`localhost:4200`，看看我们的项目是如何重新上线的。

从现在开始，您可以生成新的组件、路由、服务和管道，只需简单的命令，还可以运行测试和构建。请查看 Angular CLI 的官方网站以获取更多信息：[`cli.angular.io`](https://cli.angular.io)。

# 即时编译

我最担心的是我们应用的大小。看看 Webpack 在构建块文件时通常打印的统计数据：

![即时编译](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-bts4-ng2-2e/img/Image00152.jpg)

捆绑文件超过 4 兆字节。为什么应用这么庞大？

当应用程序在浏览器中加载时，Angular 会使用**即时**（**JIT**）编译器在运行时对其进行编译。该编译器是我们在引导应用程序时加载的代码的一部分。请注意，我们在基于 SystemJS 或 Webpack 模块加载器构建项目时使用了这种方法。该解决方案具有以下缺点：

+   性能惩罚，因为代码总是在使用之前编译

+   渲染惩罚，因为每个视图在显示之前都要编译

+   大小惩罚，因为代码包含 JIT 编译

+   代码质量惩罚，因为 JIT 编译在运行时发现错误

如果我们开始使用**提前编译**（**AOT**）编译，我们可以解决许多这些问题。

# AOT 编译

在 AOT 方法中，我们预先编译所有资源，因此无需将编译器下载到 Web 浏览器中。这有以下好处：

+   较小的应用程序大小，因为代码不包括编译器

+   炽热的渲染，因为浏览器代码和模板是预编译的

+   更少的资源请求，因为样式和模板被编译到代码中

+   更好的模板绑定错误检测在编译时

+   更少的注入攻击可能性，因为 Web 浏览器不需要评估预编译的模板和组件

那么，我们如何使用这种奇妙的方法呢？答案很简单：使用 Angular CLI。它支持 AOT 开箱即用，因此我们只需要将以下命令添加到`package.json`的脚本中：

```ts
"scripts": { 
  "start": "ng serve", 
  "lint": "tslint "src/**/*.ts"", 
  "test": "ng test", 
  "pree2e": "webdriver-manager update", 
  "e2e": "protractor", 
 **"prod:build": "ng build --prod --aot",** 

 **"prod:serve": "ng serve --prod --aot"** 

}, 

```

保存更改，打开终端并运行 AOT 构建：

```ts
 **npm run prod:build** 

```

在`gzip`压缩后，捆绑文件的大小小于 400 千字节：

![AOT 编译](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-bts4-ng2-2e/img/Image00153.jpg)

您可以使用 AOT 启动开发服务器，并检查应用程序在 Web 浏览器中的最终大小：

```ts
 **npm run prod:serve** 

```

### 提示

您可以在`chapter_10/6.ecommerce-aot-compilation`找到源代码。

# 读累了记得休息一会哦~

**公众号：古德猫宁李**

+   电子书搜索下载

+   书单分享

+   书友学习交流

**网站：**[沉金书屋 https://www.chenjin5.com](https://www.chenjin5.com)

+   电子书搜索下载

+   电子书打包资源分享

+   学习资源分享

# 总结

在本章中，我们学习了如何为帐户管理和身份验证创建客户端解决方案，并在 Firebase 上进行测试。我们介绍了 Webpack，并将我们的应用程序从 SystemJS 迁移过来。我们知道它会遍历项目的必需语句，以生成我们定义的捆绑包。后来，我们重新发现了我们的项目，并进行了更多的更改以使用 Webpack 插件。现在我们知道 Webpack 有一组内置插件，我们可以按组进行拆分，例如配置、输出、优化、依赖注入、本地化、调试等。

我们了解到，身份验证是向用户提供身份的过程，没有它，我们无法为用户提供特定的服务来授予用户数据的权限。我们了解到，Firebase 提供了与任何现有登录服务器的简单身份验证，或者使用清晰的基于云的解决方案。它支持来自 GitHub、Google、Twitter 和 Facebook 的第三方身份验证，以及通过电子邮件的内置身份验证。现在我们知道 AngularFire2 身份验证可以在没有配置的情况下工作。

`ng2-bootstrap`库具有一组用于 Bootstrap 版本 3 和 4 的原生 Angular 2 指令，并且不依赖于 jQuery 和 Bootstrap JavaScript 文件。我们很快将其集成到我们的项目中。

Angular CLI 有助于轻松创建应用程序，开箱即用地生成组件、路由、服务和管道。它支持提前编译，以显著减小应用程序的大小，并提高性能和安全性。

最后，我们通过构建我们在前几章中开始开发的项目来结束了。
