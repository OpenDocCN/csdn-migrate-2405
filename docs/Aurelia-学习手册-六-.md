# Aurelia 学习手册（六）

> 原文：[`zh.annas-archive.org/md5/31FCE017BF58226A6BEEA3734CAADF0F`](https://zh.annas-archive.org/md5/31FCE017BF58226A6BEEA3734CAADF0F)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 附录 A：使用 JSPM

**JSPM** ([`jspm.io/`](http://jspm.io/)) 是基于未来网络标准的、[`github.com/systemjs/systemjs`](https://github.com/systemjs/systemjs) 通用模块加载器的包管理器，这可能是目前最前瞻性的模块加载器。

在撰写本文的时刻，创建基于 JSPM 的 Aurelia 项目的最简单方法是使用合适的骨架。然而，Aurelia 团队计划在未来的 CLI 中添加创建基于 JSPM 的项目功能。

在这个附录中，我们将看到在撰写本文时使用`requirejs`的 CLI 基础项目和基于 JSPM 的项目骨架之间的区别。

### 注意

附录的目的是不详细介绍 JSPM 和 SystemJS。因此，我强烈建议如果你打算在你的项目中使用它们，你要更多地熟悉它们。

### 提示

使用基于 JSPM 的骨架重建的我们的联系人管理应用程序，可以在书籍资源中的`appendix-a\using-jspm`找到，并可在整个附录中作为参考。

# 入门

创建基于 JSPM 的应用程序的第一步是从[`github.com/aurelia/skeleton-navigation/releases/latest`](https://github.com/aurelia/skeleton-navigation/releases/latest)下载最新的骨架版本，并解压文件。在根目录中，你会发现每个可用的骨架都有一个独特的目录。我们将要查看的是名为`skeleton-esnext`的一个。

JSPM 骨架使用 Gulp 作为其构建系统。因此，如果你还没有安装它，首先打开一个控制台并运行以下命令来全局安装它：

```js
> npm install -g gulp

```

另外，我们还需要安装 JSPM 本身：

```js
> npm install -g jspm

```

一旦我们需要的工具安装完毕，让我们通过在项目目录中打开一个控制台并运行以下命令来恢复项目的构建系统的依赖项：

```js
> npm install

```

此命令将恢复运行和构建我们应用程序所需的所有依赖项，基本上就是`package.json`文件中的`devDependencies`部分的所有内容。

接下来，我们需要通过运行以下命令来恢复我们应用程序本身使用的库：

```js
> jspm install -y

```

此命令将使用 JSPM 恢复`package.json`文件中`jspm`部分的所有的`dependencies`。

到此为止，一切准备就绪。

# 运行任务

JSPM 骨架附带一套相当完整的 Gulp 任务。这些任务可以在`build/tasks`目录中找到。

你最可能想做的第一件事是运行来自骨架的示例应用程序。这可以通过在项目目录中打开一个控制台并运行以下命令来完成：

```js
> gulp watch

```

此命令将启动一个带监视器的开发 Web 服务器，每当源文件更改时都会刷新浏览器。

如果你想在不用监听文件和自动刷新浏览器的情况下运行应用程序，可以通过运行`serve`任务来实现：

```js
> gulp serve

```

## 运行单元测试

默认情况下，基于 JSPM 的骨架的单元测试可以在`test/unit`目录中找到。它通常还包含三个与单元测试相关的不同 Gulp 任务：

+   `test`：运行单元测试一次

+   `tdd`：运行单元测试一次，然后监视文件并当代码变化时重新运行测试

+   `cover`：使用 Istanbul（[`github.com/gotwarlost/istanbul`](https://github.com/gotwarlost/istanbul)）启用代码覆盖率运行单元测试一次。

例如，如果你想进行测试驱动开发并且让测试在编码过程中持续运行，你可以运行以下命令：

```js
> gulp tdd

```

由于骨架依赖于 Karma 来运行测试，所以在运行上述任何任务之前，你需要在你的环境中安装 Karma CLI：

```js
> npm install -g karma-cli

```

## 运行端到端测试

基于 JSPM 的骨架还包含一个`e2e`任务，它将启动在`test/e2e/src`目录中找到的端到端测试。

然而，由于端到端测试依赖于 Protractor，你首先需要通过运行正确的任务来更新 Selenium 驱动程序：

```js
> gulp webdriver-update

```

然后，由于端到端测试需要与应用程序本身交互，你需要启动应用程序：

```js
> gulp serve

```

最后，你可以打开第二个控制台并启动端到端测试：

```js
> gulp e2e

```

# 添加库

使用 JSPM 添加库只需运行正确的命令：

```js
> jspm install aurelia-validation

```

此命令将为项目安装`aurelia-validation`库。由于 JSPM 被设计为与 SystemJS 一起工作，它还将添加适当的条目到 SystemJS 映射配置中，该配置在`config.js`文件中，并由 SystemJS 用来将模块名称映射到 URL 或本地路径。

一旦这个命令完成，SystemJS 模块加载器将能够定位到`aurelia-validation`及其任何依赖项，所以你可以立即在你的应用程序中使用它。

在基于 JSPM 的应用程序中使用库类似于基于 CLI 的项目。如果你需要使用库的一些 JS 导出，只需在 JS 文件中导入它们：

```js
import {ValidationController} from 'aurelia-validation'; 

```

如果你想要导入其他资源，比如 CSS 文件，只需在适当的模板中`require`它：

```js
<require from="bootstrap/css/bootstrap.css"></require> 

```

# 打包

与 CLI 或基于 Webpack 的骨架相反，基于 JSPM 的骨架在开发环境中运行时不会自动打包应用程序。但它包含了一个专门的 Gulp 任务用于打包：

```js
> gulp bundle

```

此任务将根据打包配置创建一些捆绑包。它还将更新`config.js`文件中的 SystemJS 映射，所以加载器知道从每个正确的捆绑包中加载每个模块。

这意味着，如果你手动从开发环境部署应用程序，而不是使用自动构建系统，那么在部署后你需要解包你的应用程序：

```js
> gulp unbundle

```

此命令将重置`config.js`文件中的 SystemJS 映射到其原始的未捆绑状态。然而，当运行`watch`任务时，它会自动调用，所以你不需要手动经常运行它。

## 配置捆绑包

bundling 配置可以在`build/bundles.js`文件中找到。它看起来像这样：

`build/bundles.js`

```js
module.exports = { 
  "bundles": { 
    "dist/app-bundle": { 
      "includes": [ 
        "[**/*.js]", 
        "**/*.html!text", 
        "**/*.css!text" 
      ], 
      "options": { 
        "inject": true, 
        "minify": true, 
        "depCache": true, 
        "rev": true 
      } 
    }, 
    "dist/aurelia": { 
      "includes": [ 
        "aurelia-framework", 
        "aurelia-bootstrapper", 
        // Omitted snippet... 
      ], 
      "options": { 
        "inject": true, 
        "minify": true, 
        "depCache": false, 
        "rev": true 
      } 
    } 
  } 
}; 

```

默认情况下，此配置描述了两个包：

+   `app-build`：包含从`src`目录中所有的 JS 模块、模板和 CSS 文件。

+   `aurelia`：包含 Aurelia 库、Bootstrap、fetch polyfill 和 jQuery。

`app-build`包的 JS glob 模式`[**/*.js]`周围的括号，告诉打包器忽略依赖关系。如果没有这些括号，打包器将递归地遍历每个 JS 文件的每个`import`语句，并将所有依赖关系包含在包中。由于默认的打包配置将应用程序的资源放在第一个包中，所有外部依赖放在第二个包中，所以我们不想在`app-build`包中包含任何依赖关系，因此使用了括号。

当向您的应用程序添加外部库时，您需要将其添加到包的`includes`中，通常它会在`aurelia`包中，我通常将其重命名为`vendor-bundle`。如果您不这样做，SystemJS 的映射将引用未打包的库，并尝试从`jspm_packages`目录中加载它，这在生产环境中不是我们想要的结果。

除了其内容外，包的配置还有`options`。这些选项中最有用的大概是`rev`，当设置为`true`时，启用包版本控制。因此，每个包的名称将附上一个基于内容的哈希，SystemJS 映射也将用这些版本化的包名称更新。

# 总结

在 Aurelia 的大部分开发过程中，JSPM 一直是*事实上的*包管理器，SystemJS 是首选的模块加载器；也就是说，直到 CLI 发布为止。然而，JSPM 和 SystemJS 在 Aurelia 生态系统中仍然非常重要，大多数在 CLI 发布之前启动的项目都运行在这项技术上。


# 附录 B. 使用 Webpack

**Webpack** ([`webpack.github.io/`](https://webpack.github.io/)) 又是另一个流行的 Web 模块打包器。Aurelia 已经提供了使用 Webpack 的 ES next 和 Typescript 应用程序骨架。

此外，还有计划将 CLI 对 Webpack-based 项目的支持。然而，目前，骨架是基于 Webpack 创建 Aurelia 项目的最佳起点。

在本附录中，我们将看到在撰写本文档时使用`requirejs`的基于 CLI 的项目和从骨架开始的基于 Webpack 的项目之间的差异。

### 注意

本附录的目的并不是要覆盖 Webpack 本身。因此，我强烈建议如果你还不熟悉 Webpack，请在继续阅读之前先熟悉一下 Webpack。

### 提示

我们的联系人管理应用程序，使用 Webpack 骨架重建，可以在书籍的资源中的`appendix-b\using-webpack`找到，并可作为本附录的参考。

# 入门

为了创建一个基于 Webpack 的应用程序，第一步是下载[`github.com/aurelia/skeleton-navigation/releases/latest`](https://github.com/aurelia/skeleton-navigation/releases/latest)的骨架并解压文件。根目录包含每个可用骨架的独立目录。我们在这里要保留的是名为`skeleton-esnext-webpack`。

Webpack 骨架使用 NPM 作为其包管理器。因此，我们需要通过在项目目录中打开控制台并运行以下命令来安装项目的依赖项：

```js
> npm install

```

完成此操作后，示例应用程序即可运行。

# 运行任务

Webpack 骨架不使用 Gulp 作为其构建系统，而是简单地依赖于 NPM 任务。如果你查看`package.json`文件中的`scripts`部分，你会看到项目的任务列表及其相应的命令。以下是最常见的：

+   `start`：启动开发 Web 服务器。当第一次访问`index.html`时，应用程序被捆绑并提供，然后该过程监视源文件，以便在检测到更改时重新创建捆绑并刷新浏览器。`start`命令是`server`的别名，而`server`又是`server:dev`的别名。

+   `test`：运行单元测试。使用 Istanbul（[`github.com/gotwarlost/istanbul`](https://github.com/gotwarlost/istanbul)）启用代码覆盖。

+   `e2e`：运行端到端测试。此任务将启动应用程序，该应用程序将在端口 19876 上运行，以及 E2E 测试套件。

+   `build:prod`：为生产环境打包应用程序。捆绑包和`index.html`文件将被优化以适应生产环境，并将在`dist`文件夹中生成。此外，生产构建将在每个捆绑包的名称中添加基于内容的全局哈希，以便对它们进行版本控制。这与在 CLI-based 项目中在`aurelia_project/aurelia.json`中设置`rev`选项以启用捆绑修订的效果相同。

+   `server:prod`：启动一个 Web 服务器以提供生产捆绑包。它必须在`build:prod`之后运行。

# 添加库

外部库是通过 NPM 添加的，与基于 CLI 的项目一样。然而，为了使文件被包含在捆绑包中，外部库必须在 JS 文件中引用，因为 Webpack 通过分析应用程序中每个 JS 模块的`import`声明来确定必须包含在捆绑包中的内容。

你可以通过查看骨架的`main`模块来查看这个示例：

`src/main.js`

```js
// we want font-awesome to load as soon as possible to show the fa-spinner 
import '../styles/styles.css'; 
import 'font-awesome/css/font-awesome.css'; 
import 'bootstrap/dist/css/bootstrap.css'; 
import 'bootstrap'; 
//Omitted snippet... 

```

在骨架的示例应用程序中，所有全局资源，如应用程序的样式表、Font Awesome、Bootstrap 的样式表以及 Bootstrap 的 JS 文件都在`main.js`文件中被导入。这些导入将告诉 Webpack 将这些资源包含在应用程序捆绑包中。此外，Webpack 足够智能，可以分析 CSS 文件以找出它们的依赖关系。这意味着它知道如何处理导入的 CSS 文件、图片和字体文件。

# 捆绑

捆绑包本身是在`webpack.config.js`文件中配置的。默认情况下，骨架定义了三个入口捆绑包：

+   `aurelia-bootstrap`：包含 Aurelia 的启动器、默认的 polyfill、Aurelia 的浏览器平台抽象以及 Bluebird Promise 库。

+   `aurelia`：包含所有 Aurelia 的默认库

+   `app`：包含所有应用程序模块

除了直接列为其内容的模块外，一个捆绑包还将包含所有未包含在其他捆绑包中的其内容的依赖项。例如，在骨架的示例中，Bootstrap 的 JS 文件被包含在`app`捆绑包中，因为它们没有被包含在任何其他捆绑包中，并且包含在`app`捆绑包中的模块会导入它们。

如果你想要，例如，让`aurelia`捆绑包包含所有外部库，你应该将其添加到它的模块列表中：

`webpack.config.js`

```js
//Omitted snippet... 
const coreBundles = { 
  bootstrap: [ 
    //Omitted snippet... 
  ], 
  aurelia: [ 
    //Omitted snippet... 
    'aurelia-templating-binding', 
    'aurelia-templating-router', 
    'aurelia-templating-resources', 
    'bootstrap' 
  ] 
} 
//Omitted snippet... 

```

如果你在此时运行示例应用程序，Bootstrap 的 JS 文件应该现在会被包含在`aurelia`捆绑包中，而不是`app`捆绑包。

## 懒加载捆绑包

骨架的示例应用程序中定义的所有捆绑包都是入口捆绑包，这意味着这些捆绑包直接由`index.html`文件加载。所有这些代码都在应用程序启动之前一次性加载。

正如在第十章，*生产环境下的打包*中讨论的，根据应用程序的使用模式和结构，从性能角度来看，将应用程序的不同部分分别打包可能更好，并且只有在需要时才加载其中一些捆绑包。

懒加载包的配置是在`package.json`文件中完成的：

```js
{ 
  //Omitted snippet... 
  "aurelia": { 
 "build": { 
 "resources": [ 
 { 
 "bundle": "contacts", 
 "path": [ 
 "contacts/components/creation", 
 "contacts/components/details", 
 "contacts/components/edition", 
 "contacts/components/form", 
 "contacts/components/list", 
 "contacts/components/photo", 
 "contacts/models/address", 
 "contacts/models/contact", 
 "contacts/models/email-address", 
 "contacts/models/phone-number", 
 "contacts/models/social-profile", 
 "contacts/main" 
 ], 
 "lazy": true 
 } 
 ] 
 } 
 } 
  //Omitted snippet... 
} 

```

在这个例子中，我们将我们联系管理应用程序的`contacts`特性的所有组件和模型打包在一个独特的、懒加载的捆绑包中。有了这个配置，`contacts`捆绑包只有在用户导航到某个联系人路由组件时才会从服务器加载。

至于依赖项包含，懒加载的捆绑包将表现得就像一个入口捆绑包。除了在其配置中列出的模块外，懒加载的捆绑包还将包含所有没有包含在任何入口捆绑包中的依赖项。这意味着如果你只在一个模块中从外部库`import`东西（并且在这个应用程序中的其他地方没有用到），并且你没有将这个外部库包含在某个入口捆绑包中，这个库将被包含在你的懒加载捆绑包中。这是优化应用程序打包时需要考虑的一个重要因素。

## 基于环境的配置

Webpack 骨架使用一个名为`NODE_ENV`的环境变量来根据上下文定制打包过程。这个环境变量通过`package.json`中描述的任务设置为`development`、`test`或`production`。

如果你查看`webpack.config.js`文件，你会看到一个`switch`语句，它根据环境生成一个 Webpack 配置对象。这就是你可以根据环境定制打包的地方。

例如，如果你使用`aurelia-i18n`插件，你可能希望在构建应用程序时将`locales`目录复制到`dist`目录。最简单的方法是在生产和开发配置中都添加以下行：

`webpack.config.js`

```js
//Omitted snippet... 
config = generateConfig( 
  baseConfig, 
  //Omitted snippet... 
  require('@easy-webpack/config-copy-files') 
    ({patterns: [{ from: 'favicon.ico', to: 'favicon.ico' }]}),
  require('@easy-webpack/config-copy-files') 
 ({patterns: [{ from: 'locales', to: 'locales' }]}), 
  //Omitted snippet... 
); 
//Omitted snippet... 

```

另外，如果你想使用`aurelia-testing`插件，无论是用于单元测试中的组件测试器，还是用于调试目的的`view-spy`和`compile-spy`属性，你应该使用 NPM 安装它，并将其添加到`aurelia`捆绑包中，适用于`test`和`development`环境：

`webpack.config.js`

```js
//Omitted snippet... 
coreBundles.aurelia.push('aurelia-testing'); 
config = generateConfig( 
  baseConfig, 
  //Omitted snippet... 
); 
//Omitted snippet... 

```

配置 Webpack 可能一开始会感到复杂和令人畏惧。Webpack 骨架使用`easy-webpack`（[`github.com/easy-webpack/core`](https://github.com/easy-webpack/core)）来简化这个配置过程。使用`easy-webpack`的另一个巨大优势是，它强制执行社区标准，并且使得复用复杂的配置片段变得相当容易。

因此，你可以使用位于[`github.com/easy-webpack`](https://github.com/easy-webpack)或其他地方提供的众多配置模块之一，甚至是你自己的模块，来进一步定制 Webpack 的配置。

# 总结

尽管 Webpack 并非 Aurelia 的首选打包工具，但它已经得到了很好的支持。此外，无论使用 Webpack 还是 CLI 进行打包，Aurelia 应用程序本身的变化并不大，主要是围绕它的基础代码发生了变化。这使得从一个打包工具迁移到另一个打包工具变得更为简单。
