# KnockoutJS 基础知识（三）

> 原文：[`zh.annas-archive.org/md5/2823CCFFDCBA26955DFD8A04E5A226C2`](https://zh.annas-archive.org/md5/2823CCFFDCBA26955DFD8A04E5A226C2)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：Durandal – KnockoutJS 框架

通过六章，我们已经使用基本库构建了一个完整的前端应用程序。

我们使用了一些库来实现我们的目标：

+   **Bootstrap 3**：用于在 CSS3 中拥有坚实、响应式和跨浏览器的基本样式。

+   **jQuery**：用于操作 DOM 并通过 AJAX 与服务器端通信。

+   **Mockjax**：用于模拟 AJAX 通信。

+   **MockJSON**：创建虚假数据。

+   **KnockoutJS**：用于绑定数据并轻松同步 JavaScript 数据和视图。

我们还应用了一些设计模式来提高代码质量：

+   **揭示模式**：显示对象的公共接口并隐藏私有属性和方法。

+   **模块模式**：用于隔离我们的代码并使其可移植。

+   **依赖注入模式**：用于提高内聚性和减少耦合度。

最后，我们介绍了一个帮助我们管理项目依赖的库，RequireJS。

在小型项目中，您可以仅使用这些库。但是，当项目增长时，处理依赖关系变得更加困难。您需要的库和样式越多，维护它们就越困难。此外，维护视图模型也变得更加困难，因为它开始具有太多的代码行。拆分视图模型会导致编写更多的事件来通信，而事件会使代码更难调试。

要解决所有这些问题，Rob Eisenberg（[`eisenbergeffect.bluespire.com/`](http://eisenbergeffect.bluespire.com/)）及其团队创建了**Durandal**（[`durandaljs.com/`](http://durandaljs.com/)）。Durandal 是一个框架，它集成了你今后将学到的所有库和良好的实践。

在本章中，您将学习 Durandal 框架的基础知识，以便开始使用它。在本章中，您不会在购物车项目上工作。这将在下一章中继续。本章是关于了解 Durandal 如何工作以及它如何连接所有部件以快速轻松地创建 Web 应用程序。

需要提及的是，Durandal 一直是构建应用程序的最简单和最快的框架之一。当另一个名为 AngularJS（[`angularjs.org/`](https://angularjs.org/)）的良好框架宣布其 2.0 版本时，艾森伯格放弃了 Durandal 并成为 AngularJS 团队的一部分。这对 Durandal 和 KnockoutJS 社区来说是一个重大打击。但最近，艾森伯格离开了 AngularJS 2.0 项目，并宣布了 Durandal 的新版本。因此，我们可以说我们正在使用最佳框架之一来开发现代、跨浏览器且完全兼容的 Web 应用程序。

# 安装 Durandal

要安装 Durandal，请按照以下步骤操作：

1.  转到 [`durandaljs.com/downloads.html`](http://durandaljs.com/downloads.html)。

1.  下载最新版本的入门套件：[`durandaljs.com/version/latest/HTML%20StarterKit.zip`](http://durandaljs.com/version/latest/HTML%20StarterKit.zip)。

1.  将其解压缩到您的项目文件夹中。

1.  将其重命名为`durandal-cart`。

1.  将 Mongoose 服务器添加到项目中，或者使用你感觉舒适的服务器。

起始套件将为你提供一个非常好的起点，以了解 Durandal 的工作原理。在接下来的项目中，我们可以直接使用独立的 Durandal 库开始，但在这里，我们将仔细分析这个框架的各个部分。

要深入了解 Durandal，请下载`HTML Samples.zip`文件（[`durandaljs.com/version/latest/HTML%20Samples.zip`](http://durandaljs.com/version/latest/HTML%20Samples.zip)），但测试这些有趣的示例取决于你。以下是起始套件的内容：

+   起始套件包含三个文件夹和一个 HTML `index` 文件。

+   `app`文件夹包含应用程序本身。其中包含两个文件夹：`viewmodels`和`views`。

+   `viewmodels`文件夹包含应用程序需要的所有视图模型——通常每个页面一个视图模型。

+   `views`文件夹包含绑定到每个视图模型的 HTML——通常每个视图对应一个视图模型。但是，你可以组合视图（你会发现这才是 Durandal 的实际力量）。

+   `lib`文件夹包含 Durandal 框架和框架所依赖的所有库。

+   在`durandal/js`文件夹内，你会找到一个名为`plugins`的文件夹。你可以使用插件扩展 Durandal。你也可以使用组件和`bindingHandlers`扩展 KnockoutJS。

+   还有一个名为`transitions`的文件夹。在其中，你可以添加在两个页面之间进行过渡时触发的动画。默认情况下，只有一个（`entrance.js`），但你可以从互联网下载更多，或者自己构建。

+   `index.html`文件将是 JavaScript 应用程序的入口点。![安装 Durandal](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/knckt-ess/img/7074OS_07_01.jpg)

    Durandal 的文件夹结构

## Durandal 模式

在更深入了解 Durandal 之前，让我们先学习一些关于框架的模式和概念。

Durandal 是一个**单页应用程序**（**SPA**）框架。这意味着：

+   所有的 Web 应用程序都在一个页面上运行（首页）

+   没有完整页面刷新；只更新更改的部分

+   路由不再是服务器的责任。

+   AJAX 是与服务器端通信的基础

Durandal 遵循 Model-View-ViewModel（MVVM）模式：

+   实际上，它被称为 MV* 模式，因为我们可以用任何我们使用的东西替换 *：View-model（MVVM），Controller（MVC）或 Presenter（MVP）。按照惯例，Durandal 使用视图模型。

+   MVVM 模式将应用程序的视图与状态（逻辑）分离。

+   视图由 HTML 文件组成。

+   视图模型由绑定到视图的 JavaScript 文件组成。

+   Durandal 专注于视图和视图模型。模型不是框架的一部分。我们应该决定如何构建它们。

该框架使用**异步模块定义**（**AMD**）模式来管理依赖关系。它具有以下特点：

+   它使用 RequireJS 实现这一目的。

+   我们应该为每个文件定义一个模块。

+   模块的名称将是没有扩展名的文件的名称。

## index.html 文件

`index.html` 文件是应用程序的入口点。它应该有一个带有 ID `applicationHost` 的容器。应用程序将在此容器内运行，并且视图将被交换：

```js
<div id="applicationHost">
  <!-- application runs inside applicationHost container -->
</div>
```

你可以使用 `splash` 类定义一个 `splash` 元素。当应用程序完全加载时，它会显示。

```js
<div class="splash">
  <!-- this will be shown while application is starting -->
  <div class="message">
    Durandal Starter Kit
  </div>
  <i class="fa fa-spinner fa-spin"></i>
</div>
```

最后，使用 RequireJS 设置 Durandal 应用程序的入口点，就像我们在上一章中设置的一样。将 `main.js` 文件设置为 JavaScript 的入口点：

```js
<script src="img/require.js" data-main="app/main"></script>
```

## main.js 文件

`main.js` 文件包含 RequireJS 配置。在这里，我们可以看到 Durandal 使用哪些库来工作：

+   `text`: 这是一个 RequireJS 的扩展，用于加载非 JavaScript 文件。Durandal 使用 `text` 来加载模板。

+   `durandal`: 这是框架的核心。

+   `plugins`: 在这个文件夹中，我们可以找到并非所有应用程序都需要的框架部分。这些代码片段可以根据项目需要加载。

+   `transitions`: 这包含了我们可以在页面转换之间播放的不同动画。默认情况下，我们只有进入动画。

+   `knockout`: 这是用于绑定视图和视图模型的库。

+   `bootstrap`: 这是与 `bootstrap.css` 库相关的设计库。

+   `jQuery`: 这是 DOM 操作库。

你已经有了使用 RequireJS 的经验，因为你将应用程序文件转换为遵循 AMD 规范。这就是包含 RequireJS 配置的 `main.js` 文件应该如何看起来的：

```js
requirejs.config
({
  paths: {
    'text': '../lib/require/text',
    'durandal':'../lib/durandal/js',
    'plugins' : '../lib/durandal/js/plugins',
    'transitions' : '../lib/durandal/js/transitions',
    'knockout': '../lib/knockout/knockout-3.1.0',
    'bootstrap': '../lib/bootstrap/js/bootstrap',
    'jquery': '../lib/jquery/jquery-1.9.1'
  },
  shim: {
    'bootstrap': {
      deps: ['jquery'],
      exports: 'jQuery'
    }
  }
});
```

然后定义 `main` 模块。以与您在购物车项目中使用 RequireJS 相同的方式定义依赖项：

```js
define([
  'durandal/system', 
  'durandal/app', 
  'durandal/viewLocator'], function (system, app, viewLocator) {
    //main module code goes here
});
```

此模块是配置应用程序的地方。在入门套件项目中，有一个默认配置，可以帮助您了解在这一点上可以做什么：

+   激活调试（或不激活）：

    ```js
    system.debug(true);
    ```

+   设置应用程序标题。应用程序标题将默认与页面标题连接起来。

    ```js
    app.title = 'Durandal Starter Kit';
    ```

+   激活和配置插件：

    ```js
    app.configurePlugins({
      router: true,
      dialog: true
    });
    ```

+   启动应用程序：

    ```js
    app.start().then(function() {
      //This code is executed when application is ready.

      //We can choose use framework conventions
      viewLocator.useConvention();
      app.setRoot('viewmodels/shell', 'entrance');
    });
    ```

当您启动应用程序时，您可以选择遵循 Durandal 的约定。如果您选择默认遵循它们，Durandal 将通过查找 `views` 文件夹中的视图将视图模型与视图关联起来。它们应该具有与视图模型相同的名称。这意味着如果你有一个名为 `viewmodel/catalog.js` 的视图模型，它的关联视图将被称为 `views/catalog.js`。

![主 `main.js` 文件](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/knckt-ess/img/7074OS_07_02.jpg)

这是按照 Durandal 约定创建的文件结构，适用于中小型项目

这种约定适用于小型和中型项目。在大型项目中，建议不使用 Durandal 约定。如果我们选择不使用这些约定，Durandal 将在与视图模型相同的文件夹中查找视图。例如，如果视图模型称为`catalog/table.js`，则视图应命名为`catalog/table.html`。这使我们可以按功能组织视图和视图模型。

![main.js 文件](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/knckt-ess/img/7074OS_07_03.jpg)

通过不使用 Durandal 约定，我们按功能对文件进行分组，这对于大型和可扩展的项目是有益的

最后，指示框架哪个视图模型将启动应用程序。默认情况下，shell 视图模型会执行此操作。

# shell 视图模型

**Shell**是入口模块。它是包装其他模块的模块。它只加载一次，并且具有一直存在的 DOM 元素。

要定义视图模型，请使用 AMD 模式定义一个简单的 JavaScript 对象，如以下步骤所示：

1.  定义依赖关系，即路由器和 Durandal 应用程序：

    ```js
    define(['plugins/router', 'durandal/app'], function (router, app) {
      return {
        //We complete this in next points
      };
    });
    ```

1.  暴露`router`方法。`router`方法将给我们一个对象，使我们可以轻松显示导航栏。

    ```js
    return {
      router: router
    };
    ```

1.  暴露`search`方法。这是一个可选方法。它是入门套件应用程序的一部分。它管理全局搜索。

    ```js
    return {
      router: router,
      search: function() {
        //easy way to show a message box in Durandal
        app.showMessage('Search not yet implemented...');
      },
    };
    ```

1.  暴露`activate`方法。这是 Durandal 视图模型中的一个重要方法。`activate`方法在视图模型准备就绪时触发。在这里，您可以请求数据以将其绑定到视图。我们很快将看到有关 Durandal 生命周期方法的更多信息。

    ```js
    define(['plugins/router', 'durandal/app'], function (router, app) {
      return {
        router: router,
        search: function() { ... },
        activate: function () {
          router.map([{ 
            route: '', 
            title:'Welcome', 
            moduleId: 'viewmodels/welcome', 
            nav: true 
          }, {
            route: 'flickr', 
            moduleId: 'viewmodels/flickr', 
            nav: true 
          }]).buildNavigationModel();   
          return router.activate();
          }
        };
    });
    ```

## shell 视图

**shell 视图**包含导航栏：搜索栏和附加类称为`page-host`的元素。此元素将绑定到路由器，如下面的代码所示。您可以配置动画以使页面之间的过渡更加酷。

```js
<div>
  <nav class="navbar navbar-default navbar-fixed-top" role="navigation">
    <!-- nav content we will explain then -->
  </nav>
  <div class="page-host" data-bind="router: { transition:'entrance' }"></div>
</div>
```

# Durandal 生命周期

我们清楚地了解 Durandal 应用程序如何工作是很重要的。这是您的应用程序启动的模式图：

1.  `index.html`页面使用 RequireJS 请求`main.js`文件。

1.  `main.js`文件配置 require 并定义主模块，负责应用程序配置，并启动 shell 模块。

1.  shell 模块处理应用程序的全局上下文。它管理沿不同生命周期持续存在的组件。在入门套件应用程序中，它管理搜索栏。但是它也可以管理登录和注销功能，例如。shell 模块是配置所有路由的地方。

1.  最后，路由器配置沿着应用程序拥有的所有页面的导航。![Durandal 生命周期](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/knckt-ess/img/7074OS_07_04.jpg)

    Durandal 初始化生命周期

## 激活生命周期

**激活生命周期**控制页面的激活和停用。Durandal 允许我们使用预定义的方法访问周期的不同部分。让我们看一下 Durandal 方法：

+   `canDeactivate`: 当您尝试放弃页面时，应返回 true、false 或重定向对象。如果方法的结果为 true，则可以离开页面。如果是 false，则路由过程将被中断。如果返回重定向对象，则会重定向。

+   `canActivate`: 当您到达新页面时，可以评估是否能够查看此页面。例如，您可以检查是否已登录到您的页面，或者是否具有足够的管理员权限来查看页面。如果返回`canActivate` true，则可以查看该页面。如果返回 false，则路由过程将被中断。您还可以将用户重定向到另一个页面。

+   `deactivate`: 如果`canDeactivate`返回 true 并且您可以激活下一个视图，则会触发`deactivate`方法。在这里，如果需要的话，清除超时和事件是一个很好的地方。

+   `activate`: 如果`canActivate`返回 true 并且您可以停用上一个视图，则会触发`activate`方法。这是您应该加载所有数据、绑定您的元素并初始化事件的地方。![激活生命周期](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/knckt-ess/img/7074OS_07_05.jpg)

    激活生命周期

还有其他方法可以在我们的生命周期中使用：

+   `getView`: 使用此方法，您可以构建一个 observable 来定义视图模型绑定的视图路径。

+   `viewUrl`: 这返回一个表示附加到视图模型的视图路径的字符串。`viewUrl`和`getView`之间的区别在于前者是一个字符串，而后者是一个 observable。

+   `binding`: 在视图和视图模型之间的绑定开始之前调用此方法。

+   `bindingComplete`: 在绑定完成后立即调用。

+   `attached`: 当组合引擎将视图附加到 DOM 时调用。您可以使用此钩子使用 jQuery 选择器来操作元素。

+   `compositionComplete`: 这是组合引擎触发的最后一个钩子。在这里，您可以测量 DOM 元素。

+   `detached`: 当视图从 DOM 中分离时，将触发此钩子。我们可以在这里执行清理工作。

您可以在[`durandaljs.com/documentation/Interacting-with-the-DOM.html`](http://durandaljs.com/documentation/Interacting-with-the-DOM.html)了解更多关于组合生命周期的信息。

## Promise 模式

Durandal 使用 promises 来管理异步行为。一个明显的例子是`app.start()`方法，它在`main.js`文件中。

Promise 是一个包含在未来可以使用的值的对象，当获得此值的先决条件时可以使用。在这种情况下，直到获得`app.start()`方法的结果之后，`then`方法才不会被触发。

在内部，Durandal 使用 jQuery 的 promise 实现以最小化第三方依赖关系。然而，你使用的其他库可能需要 Q，或者你可能需要比 jQuery 提供的更高级的异步编程能力。在这些情况下，你将希望将 Q 的 promise 机制插入到 Durandal 中，以便你可以在整个过程中拥有一个统一的 promise 实现。要集成 Q 库，请按照以下步骤操作：

1.  将 `Q` 库添加到 RequireJS 配置中。

1.  将此代码添加到 `main.js` 文件中，在 `app.start()` 指令之前：

    ```js
    system.defer = function (action) {
      var deferred = Q.defer();
      action.call(deferred, deferred);
      var promise = deferred.promise;
      deferred.promise = function() {
        return promise;
      };
      return deferred;
    };
    ```

如果你正在使用 HTTP Durandal 插件，则如果你想使用 Q promises，这种方法将不够。你需要将 jQuery promise 包装成 Q promise，如下所示：

```js
http.get = function(url, query) {
  return Q.when($.ajax(url, { data: query }));
}
```

你可以在 [`durandaljs.com/documentation/Q.html`](http://durandaljs.com/documentation/Q.html) 阅读更多关于 Q 库的信息。

这是我们在 Durandal 中可用的基本 jQuery promise 接口：

+   `done(successFn)`: 如果 promise 成功解析，则将触发此事件。

+   `fail(failFn)`: 如果 promise 被拒绝，则将触发此事件。

+   `always()`: 这将在成功和失败两种情况下触发。

+   `then(succesFn,failFn)`: 这是 `done` 和 `fail` 方法的别名。

+   `when(valueOrFunction)`: 这将使用传递的值或函数创建一个 promise。

要了解更多关于 jQuery promises 的信息，请参考官方文档 [`api.jquery.com/promise/`](http://api.jquery.com/promise/)。

## 组合

**组合** 是 Durandal 中最强大的部分。虽然模块帮助将应用程序分解为小部分，但组合允许我们将它们全部再次连接起来。组合有两种类型，对象组合和视觉组合。

要应用视觉组合，你需要使用 compose 绑定。你可以将 KnockoutJS observables 与 compose 绑定结合使用以实现动态组合。Compose 绑定提供了一个完整的配置界面，以增强组件的灵活性和可重用性。

### 对象组合

你可以通过仅使用 RequireJS 和 AMD 模式来实现**对象组合**。最简单的情况是你有两个模块：A 和 B。B 模块需要 A 的功能，所以你在模块 B 中使用 RequireJS 请求模块 A，如下所示：

```js
//moduleA
define([],function(){
  var moduleA = {};

  //ModuleA code

  return moduleA;
});
//moduleB (in a different file)
define(['moduleA'],function(moduleA){
  //we can use ModuleA to extend moduleB, e.g:

  var moduleB = $.extend({}, moduleA);

  //Create moduleB unique functionality.
  return moduleB;
});
```

### 视觉组合

**视觉组合** 允许你将视图分解成小块并重新连接（或组合）它们，使它们可重用。这是 Durandal 中的一个核心和独特功能，并由 Composition 模块管理。组合视图的最常见方式是使用 compose 绑定处理程序。

让我们看看 shell 视图是如何组合的：

1.  使用 RequireJS 来查找 shell 模块。按照惯例，它知道它在 `shell.js` 文件中。

1.  视图定位器会为 shell 定位适当的视图：`shell.html`。

1.  视图引擎从 `shell.html` 中的标记创建视图。

1.  使用 KnockoutJS 将 shell 模块和 shell 视图进行数据绑定。

1.  将绑定外壳视图插入`applicationHost` div 中。

1.  “入口”过渡用于动画显示视图。![可视化组合](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/knckt-ess/img/7074OS_07_06.jpg)

    组合生命周期

现在看一下如何进行一些可视化组合。您可以将导航移动到其自己的视图，并使用导航视图组合外壳，按照以下步骤操作：

1.  打开`shell.html`文件。

1.  剪切`<nav></nav>`元素。

1.  将其粘贴到名为`navigation.html`的新文件中。

1.  在`shell.html`文件中添加一个`<div>`并绑定组合元素，如下所示：

    ```js
    <div>
      <div data-bind="compose: 'navigation.html'"></div>
      <div class="page-host" data-bind="router: { transition:'entrance' }"></div>
    </div>
    ```

您还可以创建一个名为`navigation.js`的视图模型，链接到视图：

```js
<div>
  <div data-bind="compose: 'viewmodel/navigation'"></div>
  <div class="page-host" data-bind="router: { transition:'entrance' }"></div>
</div>
```

您还可以选择将`compose`变量转换为在视图模型中生成的可观察变量：

```js
<div>
  <div data-bind="compose: navigationObservable"></div>
  <div class="page-host" data-bind="router: { transition:'entrance' }"></div>
</div>
```

这是有关组合绑定工作原理的简要介绍：

+   如果它是字符串值：

    +   如果它具有视图扩展名，则定位视图并将其注入到 DOM 中，并根据当前上下文进行绑定。

    +   如果它是模块 ID，则定位模块，定位其视图，并将它们绑定并注入到 DOM 中。

+   如果它是一个对象，则定位其视图并将其绑定并注入到 DOM 中。

+   如果它是一个函数，则使用新修饰符调用该函数，获取其返回值，找到该返回值的视图，并将它们绑定并注入到 DOM 中。

如果您想要自定义组合，可以直接将视图和模型数据传递给组合器绑定，如下所示：

```js
data-bind="compose: { model:someModelProperty, view:someViewProperty }"
```

这允许您将具有相同数据的不同视图组合为可观察的模型或视图。

您还可以使用 Knockout 注释组合视图：

```js
<!-- ko compose: activeItem--><!--/ko-->
```

您可以增加组合绑定的设置值：

+   `transition`：您可以在组合更改时指示过渡。

+   `cacheviews`：这不会从 DOM 中移除视图。

+   `activate`：这为此组合定义了激活函数。

+   `perserveContext`：如果将其设置为`false`，则会分离父上下文。当视图没有关联的模型时，这很有用。它提高了性能。

+   `activationData`：这是指附加到`activate`函数的数据。

+   `mode`：这可以是`inline`或`templated`。默认情况下，内联是模式。`templated`模式与`data-part`属性一起使用，通常与小部件一起使用。

+   `onError`：您可以绑定一个错误处理程序函数，以在组合失败时优雅地失败，如下面的代码所示：

    ```js
    div data-bind="compose: { model: model, onError: errorHandlerFunction }"></div>
    ```

您可以在 Durandal 文档中找到有关组合的完整说明，网址为[`durandaljs.com/documentation/Using-Composition.html`](http://durandaljs.com/documentation/Using-Composition.html)。

## 路由器

Durandal 提供了一个路由器插件，使导航快速简便。路由器与历史插件配合工作，处理浏览器中的导航状态。

要使用路由器插件：

1.  在`main.js`文件中激活插件：

    ```js
    app.configurePlugins({
      router: true,
    });
    ```

1.  在`shell.js`文件中进行配置：

    ```js
    router.map([{...},{...}]).buildNavigationModel();
    return router.activate();
    ```

以下是我们购物车应用程序的路由器示例：

```js
router.map([
  {route:[''/*default route*/,'catalog'], title:'catalog', moduleId:'viewmodels/catalog', nav: true},
  {route:'cart', title:'cart', moduleId:'viewmodels/cart', nav: true},
  {route:'product/:id', title:'Product detail', moduleId:'viewmodels/product-detail', nav:false},
  {route:'product/:id*action', moduleId:'viewmodels/product', nav:false, hash:'#product/:id'},
]).buildNavigationModel();
return router.activate();
```

看一下`shell.js`文件。路由器作为视图模型的一个元素传递。这使您能够根据当前路由更新导航。Durandal 提供了一个友好的界面来从`router`对象构建导航菜单。在 shell 激活挂钩中映射路由，然后使用路由器流畅 API 构建导航模型。

最后，返回包含来自 shell 激活挂钩的承诺的`router.activate()`方法。返回一个承诺意味着组合引擎将等待路由器准备好后再显示 shell。

让我们更详细地看一下路由映射。路由有不同的模式。至少，您应该提供一个路由和一个`moduleId`值。当 URL 哈希更改时，路由器将检测到并使用路由模式找到正确的路由。然后，它将加载具有`moduleId`值的模块。路由器将激活并组合视图。

有一些可选参数：

+   `nav`：当您调用`buildNavigationModel`方法时，它将只使用此属性设置为`true`的路由创建一个名为`navigationModel`的可观察数组。

+   `title`：这用于设置文档标题。

+   `hash`：使用此选项，您可以提供用于数据绑定到锚标记的自定义哈希。如果未提供哈希，则路由器将生成一个哈希。

有四种不同类型的路由：

+   **默认路由**设置为空字符串：

    ```js
    route.map([{route:''}]);
    ```

+   **静态路由**没有参数：

    ```js
    route.map([{route:'catalog'}]);
    ```

+   **参数化路由**是带参数的路由：

    +   使用冒号定义参数：

        ```js
        route.map([{route: 'product/:id'}]);
        ```

    +   可选参数在括号内：

        ```js
        route.map([{route: 'product(/:id)'}]);
        ```

+   **Splat 路由**用于构建子路由。我们可以使用星号来定义它们：

    ```js
    route.map({route:'product/:id*actions'});
    ```

+   **未知路由**由方法管理：`mapUnknownRoutes(module,view)`：

    ```js
    route.mapUnknowRoutes(notfound,'not-found');
    ```

如果您查看`navigation.html`文件，您将能够看到路由器的工作方式。

注意，对于`navigationModel`属性路由的`foreach`绑定是使用`buildNavigationModel`方法构建的。此数组的每个元素都有一个`isActive`标志，当路由处于活动状态时，该标志被设置为`true`。最后，有一个名为`isNavigating`的属性，允许您向用户发出导航页面之间正在进行的警告，如下所示：

```js
<ul class="nav navbar-nav" data-bind="foreach: router.navigationModel">
  <li data-bind="css: { active: isActive }">
    <a data-bind="attr: { href: hash }, text: title"></a>
    </li>
</ul>
<ul class="nav navbar-nav navbar-right">
  <li class="loader" data-bind="css: { active: router.isNavigating }">
    <i class="fa fa-spinner fa-spin fa-2x"></i>
  </li>
</ul>
```

如果你回到`shell.html`页面，你会看到你将路由器绑定到`page-host`元素。此绑定在`page-host`容器中显示活动路由。这只是 Durandal 组合功能的另一个演示。

### 路由参数

路由参数在路由中使用冒号设置。这些参数可以传递给每个模块的`canActivate`和`activate`方法。如果路由有查询字符串，则作为最后一个参数传递。

## 触发导航

这里列出了一些触发导航的方式：

+   使用锚标记：

    ```js
    <a data-bind="attrs:{href:'#/product/1'}">product 1</a>
    ```

+   使用`router.navigate(hash)`方法。这将触发导航到关联的模块。

    ```js
    router.navigate('#/product/1');
    ```

+   如果您想要添加一个新的历史记录条目但不调用模块，只需将第二个参数设置为`false`：

    ```js
    router.navigate('#/product/1',false);
    ```

+   如果您只想替换历史记录条目，请传递一个带有`replace`值`true`和`trigger`值`false`的 JSON 对象：

    ```js
    router.navigate('#/product/1',{ replace: true, trigger: false });
    ```

## 子路由器

在大型应用程序中，您必须能够处理数十个甚至数百个路由。您的应用程序可能只有一个主路由器，但也可能有多个子路由器。这为 Durandal 提供了处理深度链接场景并根据功能封装路由的方法。

通常，父级将使用星号(*)映射一个路由。子路由器将相对于该路由工作。让我们看一个例子：

1.  需要应用程序路由器。

1.  调用`createChildRouter()`。这将创建一个新的路由器。

1.  使用`makeRelative` API。配置基本的`moduleId`和`fromParent`属性。该属性使路由相对于父级的路由。

这就是它的工作原理：

```js
// product.js viewmodel
define(['plugins/router', 'knockout'], function(router, ko) {
  var childRouter = router.createChildRouter()
    .makeRelative({
      moduleId:'product',
      fromParent:true,
      dynamicHash: ':id'
    }).map([
      { route: 'create', moduleId: 'create', title: 'Create new product', type: 'intro', nav: true },
      { route: 'update', moduleId: 'update', title: 'Update product', type: 'intro', nav: true},
    ]).buildNavigationModel();
  return {
    //the property on the view model should be called router
    router: childRouter 
  };
});
```

首先，它捕获`product/:id*`动作模式。这将导致导航到`product.js`。应用程序路由器将检测到子路由的存在，并将控制委托给子路由。

当子路由与参数一起使用时，在`makeRelative`方法中激活`dynamicHash`属性。

## 事件

**事件**用于模块间通信。事件 API 集成到`app`模块中，非常简单：

+   **on**：订阅视图模型的事件

    ```js
    app.on('product:new').then(function(product){
      ...
    });
    ```

+   **off**：取消订阅视图模型的事件

    ```js
    var subscription = app.on('product:new').then(function(product){
      ...
    });
    subscription.off();
    ```

+   **触发器**：触发事件

    ```js
    app.trigger('product:new', newProduct);
    ```

你可以将所有事件名称传递给监听所有类型的事件：

```js
app.on('all').then(function(payload){
  //It will listen all events
});
```

在[`durandaljs.com/documentation/Leveraging-Publish-Subscribe.html`](http://durandaljs.com/documentation/Leveraging-Publish-Subscribe.html)阅读更多关于事件的内容。

## 小部件

**小部件**是 Durandal 组成中的另一个重要部分。它们就像视图模型，只有一个例外。视图模型可以是单例的，我们通常更喜欢它们是单例的，因为它们代表站点上的唯一页面。另一方面，小部件主要是用构造函数编写的，因此它们可以根据需要实例化多次。因此，当我们构建小部件时，我们不返回对象，就像视图模型中发生的那样。相反，我们返回一个构造函数，Durandal 实例化小部件。

将小部件保存在`app/widgets/{widget_name}`中。小部件应该有一个`viewmodel.js`文件和一个`view.html`文件。

我们将开发一个名为`accordion`的小部件来演示小部件的工作原理。此小部件将基于 Bootstrap 提供的 jQuery 折叠插件。

### 设置小部件

按照以下步骤创建一个插件： 

1.  将`bootstrap`库添加到项目中。要实现这一点，请将其添加到主模块的依赖项中：

    ```js
    define([
      'durandal/system', 
      'durandal/app', 
      'durandal/viewLocator',
      'bootstrap'
    ],  function (system, app, viewLocator, bs) {
      //Code of main.js module
    });
    ```

1.  安装插件。在`main.js`文件中注册小部件插件：

    ```js
    app.configurePlugins({
      widget: true
    });
    ```

1.  在`app`文件夹中创建一个名为 widget 的目录。

1.  添加一个名为`accordion`的子目录。

1.  在`accordion`目录下添加一个名为`viewmodel.js`的文件。

1.  在`accordion`目录中添加一个名为`view.html`的文件。

如果你不喜欢 Durandal 的约定，可以在[`durandaljs.com/documentation/api#module/widget`](http://durandaljs.com/documentation/api#module/widget)上阅读有关小部件配置的更多信息。

### 编写小部件视图

编写视图，请按照以下步骤进行：

1.  打开`app/widgets/expander/view.html`文件。

1.  编写此代码，按照 bootstrap3 折叠模板（[`getbootstrap.com/javascript/#collapse`](http://getbootstrap.com/javascript/#collapse)）：

    ```js
    <div class="panel-group" data-bind="foreach: { 
      data: settings.items }">
      <div class="panel panel-default">
        <div class="panel-heading" data-bind="">
          <h4 class="panel-title">
            <a data-toggle="collapse" data-bind="attr:{'data-target':'#'+id}">
              <span data-part="header" data-bind="html: $parent.getHeaderText($data)">
              </span>
            </a>
          </h4>
        </div>
        <div data-bind="attr:{id:id}" class="panel-collapse collapse">
          <div class="panel-body">
            <div data-part="item" data-bind="compose: $data"></div>
          </div>
        </div>
      </div>
    </div>
    ```

通过先编写视图，你可以确定需要在视图模型中创建哪些变量才能完成视图。在这种情况下，你将需要一个存储手风琴元素的项目数组。它将包含每个可折叠元素的 ID，在小部件内自动生成，标题文本和正文。

### 编写小部件视图模型

要编写小部件视图模型，请打开`accordion`小部件文件夹中的`viewmode.js`文件，并编写以下代码：

```js
define(['durandal/composition','jquery'], function(composition, $) {
  var ctor = function() { };

  //generates a simple unique id	
  var counter = 0;

  ctor.prototype.activate = function(settings) {
    this.settings = settings;
    this.settings.items.forEach(function(item){
      item.id=counter++;
    });
  };
  ctor.prototype.getHeaderText = function(item) {
    if (this.settings.headerProperty) {
      return item[this.settings.headerProperty];
    }

    return item.toString();
  };

  return ctor;
});
```

正如你所见，你返回了一个小部件的构造函数，而不是像页面一样返回一个视图模型本身。

在这种情况下，要管理生命周期，你只需定义`activate`方法来分配值和生成 ID。请记住，如果你想用代码添加一些 DOM 修改，那么附加方法将是一个不错的地方。

### 注册小部件

要注册小部件，只需在主模块（`main.js`）中注册即可：

```js
app.configurePlugins({
  widget: {
    kinds: ['accordion']
  }
});
```

# 使用 Durandal 构建页面

现在你已经学会了 Durandal 框架的所有基础知识，让我们创建一个包含我们的小部件和一些基本数据的新页面。

要在 Durandal 中定义新页面，始终按照相同步骤进行：

1.  在 shell 视图模型中定义路由：

    ```js
    router.map([
    { route: '', title:'Welcome', moduleId: 'viewmodels/welcome', nav: true },
    { route: 'flickr', moduleId: 'viewmodels/flickr', nav: true },
    { route: 'accordion', moduleId: 'viewmodels/accordion', nav: true }
    ]).buildNavigationModel();
    ```

1.  定义`views/accordion.html`文件。注意，在手风琴绑定内部，你可以定义`data-part`模板。在这里，你正在使用 Durandal 提供的组合能力。通过添加一个`add`按钮，你为小部件提供了添加新元素的可能性。

    ```js
    <div>
      <h2 data-bind="text:title"></h2>
      <div data-bind="accordion: {items:projects, headerProperty:'name'}">
        <div data-part="header">
          <span data-bind="text:name"></span>
        </div>
        <div data-part="item">
          <span data-bind="text:description"></span>
        </div>
      </div>
      <div class="btn btn-primary" data-bind="click:add">
        Add new project
      </div>
    </div>
    ```

1.  定义`viewmodels/accordion.js`文件。你已经将`projects`设置为可观察数组，并在`activate`方法中进行了初始化。视图模型提供了一个`add`函数，触发名为`accordion:add`的事件。这会发送带有新标签值的消息。小部件应监听此事件并执行操作。

    ```js
    define(['plugins/http', 'durandal/app', 'knockout'], function (http, app, ko) {
      return {
        title: 'Accordion',
        projects: ko.observableArray([]),
        activate: function () {
          this.projects.push(
          {name:'Project 1',description:"Description 1"});
          this.projects.push(
          {name:'Project 2',description:"Description 2"});
          this.projects.push(
          {name:'Project 3',description:"Description 3"});
        },
        add: function () {
          app.trigger('accordion:add',
          {name:'New Project',description:"New Description"});
        }
      };
    });
    ```

1.  在`widgets/accordion/viewmodel.js`文件中定义事件，更新`activate`方法：

    ```js
    ctor.prototype.activate = function(settings) {
      this.settings = settings;

      var _settings = this.settings;//save a reference to settings
      var items = this.settings.items();//get data from observable

      items.forEach(function(item){//manipulate data
        item.id=guid();
      });

      this.settings.items(items);//update observable with new data

      //listen to add event and save a reference to the listener
      this.addEvent = app.on('accordion:add').then(function(data){
        data.id = guid();
        _settings.items.push(data);
      });
    };
    ```

1.  定义分离的生命周期方法，以便在小部件不在屏幕上时关闭`add event`：

    ```js
    ctor.prototype.detached = function () {
      //remove the suscription 
      this.addEvent.off();
    }
    ```

1.  启动应用程序并测试小部件。

# 概要

在本章中，你已经了解了 Durandal。使用一个所有部件都完美连接的框架，而不是一堆库，可以帮助你避免一遍又一遍地重写相同的代码。这意味着，多亏了 Durandal，你可以轻松地遵循开发者的基本原则之一（不要重复自己 - DRY）。

你学到了一些有用的概念，比如如何安装和启动 Durandal 项目。你还了解了 Durandal 应用程序的生命周期是如何工作的。

Durandal 最强大的功能之一是组合。你可以非常轻松地组合界面，对开发者几乎是透明的。

你了解了 Durandal 如何管理承诺。默认情况下，它使用 jQuery 的承诺，但你发现很容易使用其他库，比如 Q。

最后，你开发了一个小部件，并将其集成到视图模型中。虽然视图模型是单例的，但小部件是可以多次实例化的元素。它们是 Durandal 组合的一个强大部分。

在下一章中，我们将逐步将我们的 KnockoutJS 购物车迁移到 Durandal 单页面应用程序。


# 第八章：使用 Durandal 开发 Web 应用程序 - 购物车项目

现在我们知道 Durandal 的工作原理，是时候将我们的旧应用程序迁移到使用我们的新框架了。在本章中，您将学习如何重用我们在书中使用的代码，并将部分代码适应新环境。 

# 介绍

在本章中，我们将开发一个全新的应用程序。但是，我们将重用上一章中开发的大部分代码。

只使用 Knockout 的缺点之一是随着应用程序的增长，我们的应用程序需要连接到许多库。我们在本书中开发的应用程序非常小，但足够复杂，我们还没有解决一个重要的问题，即路由。我们的应用程序始终位于同一页上。我们无法在订单和目录之间或购物车和目录之间导航。我们的整个应用程序都在同一页上，显示和隐藏组件。

Durandal 连接了您在本书中学到的一些库，并且使连接到新库变得容易。

在本章中，我们将看到一些非标准 UML 符号的模式。现今，敏捷方法不建议深入使用 UML，但这些类型的图表帮助我们更全面、更清晰地了解我们功能的结构和需求。此外，为了部署视图，我们将看到一些关于 HTML 如何完成的草图和模拟：

![Introduction](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/knckt-ess/img/7074OS_08_01.jpg)

我们应用程序的生命周期

# 设置项目

要启动新项目，我们将按照一些步骤进行，这将为我们开发项目提供一个良好的起点：

1.  创建一个与 Knockout 购物车相同的项目。

1.  在此项目内，复制 Durandal Starter Kit 项目的内容。

1.  现在我们的项目应该有三个文件夹：

    +   `app`：这包含了我们的应用程序。

    +   `css`：这包含样式表

    +   `lib`：这包含第三方库

1.  将以下库从 Knockout 购物车项目迁移到 Durandal 购物车项目：

    +   `icheck`

    +   `kovalidation`

    +   `mockjax`

    +   `mockjson`

1.  从 [`codeseven.github.io/toastr/`](http://codeseven.github.io/toastr/) 安装一个名为 Toastr 的新库。

1.  更新第 19 行的 `ko.validation.js` 文件，使用以下代码：

    ```js
    define(["knockout", "exports"], factory);
    ```

1.  将 `style.css` 文件从 Knockout 购物车移动到 Durandal 购物车项目的 `css` 文件夹中。

1.  将 `models` 文件夹移动到 `app` 文件夹内。

1.  将 `services` 文件夹移动到 `app` 文件夹内。

1.  创建一个名为 `bindings.js` 的文件，与 `main.js` 文件处于同一级别，并将所有绑定移到 `koBindings.js` 文件中。

1.  创建一个名为 `mocks.js` 的文件，与 `main.js` 文件处于同一级别，并将所有模拟移到 `mocks` 文件夹中。

1.  创建一个名为 `components.js` 的文件，与 `main.js` 文件处于同一级别，并将所有组件移到那里。

1.  更新 `knockout` 库。Durandal 起始套件附带版本 3.1，我们将使用 3.2 版本，这是我们在 Knockout 购物车项目中使用的版本。3.2 版本允许我们使用 `inputText` 绑定和组件。您可以在此链接中查看所有版本之间的区别：[`github.com/knockout/knockout/releases`](https://github.com/knockout/knockout/releases)。

1.  更新 `main.js` 文件：

    ```js
    requirejs.config({
      paths: {
        'text': '../lib/require/text',
        'durandal':'../lib/durandal/js',
        'plugins' : '../lib/durandal/js/plugins',
        'transitions' : '../lib/durandal/js/transitions',
        'knockout': '../lib/knockout/knockout-3.1.0.debug',
        'bootstrap': '../lib/bootstrap/js/bootstrap.min',
        'jquery': '../lib/jquery/jquery-1.9.1',
        'toastr': '../lib/toastr/toastr.min',
        'ko.validation': '../lib/kovalidation/ko.validation',
        'mockjax': '../lib/mockjax/jquery.mockjax',
        'mockjson': '../lib/mockjson/jquery.mockjson',
        'icheck': '../lib/icheck/icheck'
      },
      shim: {
        'bootstrap': {
          deps: ['jquery'],
          exports: 'jQuery'
        },
        mockjax: {
          deps:['jquery']
        },
        mockjson: {
          deps:['jquery']
        },
        'ko.validation':{
          deps:['knockout']
        },
        'icheck': {
          deps: ['jquery']
        }
      }
    });

    define([
      'durandal/system',
      'durandal/app',
      'durandal/viewLocator',
      'mocks',
      'bindings',
      'components',
      'bootstrap',
      'ko.validation',
      'icheck',
    ],  function (system, app, viewLocator,mocks,bindings,components) {
      //>>excludeStart("build", true);
      system.debug(true);
      //>>excludeEnd("build");

      app.title = 'Durandal Shop';

      app.configurePlugins({
        router:true,
        dialog: true
      });

      app.start().then(function() {
        //Replace 'viewmodels' in the moduleId with 'views' to locate the view.
        //Look for partial views in a 'views' folder in the root.
        viewLocator.useConvention();

        //Show the app by setting the root view model for our application with a transition.
        app.setRoot('viewmodels/shell', 'entrance');

        mocks();
        bindings.init();
        components.init();
      });
    });
    ```

1.  将项目设置在您喜欢的服务器上，或者将 Mongoose 可执行文件复制到 `index.html` 所在的文件夹中。

1.  使用新的 css 文件更新 `index.html`：

    ```js
    <link rel="stylesheet" href="lib/toastr/toastr.min.css" />
    <link rel="stylesheet" href="lib/icheck/skins/all.css" />
    <link rel="stylesheet" href="css/style.css" />
    ```

现在我们的项目已经准备好了，是时候逐步迁移我们的购物车了。

# 项目路由 – shell 视图模型

Durandal 给了我们在项目中管理路由的可能性。我们将把项目的不同部分分割成页面。这将提供更好的用户体验，因为我们将一次只关注一个任务。

我们将将应用程序拆分为四个部分：

+   目录

+   购物车

+   订单

+   产品 CRUD

这些部分将包含我们在 Knockout 应用程序中构建的几乎相同的代码。有时，我们需要适应一些小代码片段。

要创建这些新路由，我们将打开 `shell.js` 文件并更新路由器：

```js
router.map([
  { route: ['','/','catalog'], title:'Catalog', moduleId: 'viewmodels/catalog', nav: true },
  { route: 'new', title:'New product', moduleId: 'viewmodels/new', nav: true },
  { route: 'edit/:id', title:'Edit product',moduleId: 'viewmodels/edit', nav: false },
  { route: 'cart', title:'Cart', 
    moduleId: 'viewmodels/cart', nav: false },
  { route: 'order', title:'Order', moduleId: 'viewmodels/order', nav: true }
]).buildNavigationModel();
```

让我们回顾一下路由器的工作原理：

+   `route` 包含相对 URL。对于目录，有三个 URL 附加到此路由。它们是空路由 ('')，斜杠 ('/') 路由和目录。为了表示这三个路由，我们将使用一个数组。

+   `title` 将包含在 `<title>` 标签中附加的标题。

+   `moduleId` 将包含处理此路由的视图模型。如果我们使用约定，它将在 `views` 文件夹中查找视图，查找与视图模型同名的视图。在这种情况下，它会查找 `views/catalog.html`。如果我们选择不使用约定，Durandal 将在与视图模型相同的文件夹中查找。

+   如果 `nav` 为 true，则导航菜单中将显示一个链接。如果为 false，则路由器不会在导航菜单中显示链接。

# 导航和 shell 模板

正如我们在第七章中所做的，*Durandal – The KnockoutJS Framework*，我们将会将我们的 `shell.html` 视图分为两部分：`shell.html` 和 `navigation.html`。

## 目录模块

在 Knockout 购物车中，我们有一个管理应用程序所有部分的视图模型。在这里，我们将把那个大的视图模型拆分成几个部分。第一部分是目录。

这里是它应该如何工作的模式图：

![目录模块](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/knckt-ess/img/7074OS_08_02.jpg)

目录模块的工作流程

目录将仅包含包括搜索栏和带有其操作的表格的部分。这将使视图模型更小，因此更易于维护。

虽然文件将分成不同的文件夹，但目录本身是一个模块。它包含视图模型、视图以及一些仅在该模块内部工作的服务。其他组件将被引入，但它们将在应用程序生命周期中被更多模块共享。

1.  在 `viewmodels` 文件夹中创建一个名为 `catalog.js` 的文件，并定义一个基本的揭示模式骨架以开始添加功能：

    ```js
    define([],function(){
      var vm = {};
      //to expose data just do: vm.myfeature = ...
      return vm;
    });
    ```

1.  在 `views` 文件夹中创建一个名为 `catalog.html` 的文件：

    ```js
    <div></div>
    ```

仅仅通过这样做，我们的模块就已经准备好工作了。让我们完成代码。

### 目录视图

我们将使用组合来创建这个模板。记住，组合是 Durandal 的一个强大特性之一。为了完成这个功能，我们将创建三个包含根视图不同部分的新模板。通过这样做，我们将我们的视图更加易于维护，因为我们将模板的不同部分隔离在不同的文件中，这些文件更小且易于阅读。

![目录视图](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/knckt-ess/img/7074OS_08_03.jpg)

目录视图的草图

按照以下步骤创建模板：

1.  打开 `catalog.html` 文件并创建基本模板：

    ```js
    <div class="container-fluid">
      <div class="row">
        <div class="col-xs-12">
          <h1>Catalog</h1>
          <div data-bind="compose: 'catalog-searchbar.html'"></div>
          <div data-bind="compose: 'catalog-details.html'"></div>
          <div data-bind="compose:'catalog-table.html'"></div>
        </div>
      </div>
    </div>
    ```

1.  创建一个名为 `catalog-searchbar.html` 的视图。我们用根视图的名称为子视图添加前缀，所以如果你的编辑器按名称对文件进行排序，它们将全部显示在一起。我们也可以将它们全部组合在一个文件夹中。我们可以选择我们感觉最舒适的方式：

    ```js
    <input type="checkbox" data-bind="icheck:showSearchBar"/>
      Show Search options<br/><br/>
    <div class="input-group" data-bind="visible:showSearchBar">
      <span class="input-group-addon">
        <i class="glyphicon glyphicon-search"></i> Search
      </span>
      <input type="text" class="form-control" data-bind="value:searchTerm, valueUpdate: 'keyup', executeOnEnter:filterCatalog" placeholder="Press enter to search...">
    </div>
    <hr/>
    ```

1.  现在是时候定义名为 `catalog-details.html` 的视图了；它将包含操作和购物车详情：

    ```js
    <div class="row cart-detail">
      <div class="col-lg-2 col-md-4 col-sm-4 col-xs-4">
        <strong>
          <i class="glyphicon glyphicon-shopping-cart"></i> 
            Items in the cart:
        </strong>
        <span data-bind="text:CartService.cart().length"></span>
      </div>
      <div class="col-lg-2 col-md-4 col-sm-4 col-xs-4">
        <strong>
          <i class="glyphicon glyphicon-usd"></i> 
          Total Amount:
        </strong>
        <span data-bind="text:CartService.grandTotal"></span>
      </div>
      <div class="col-lg-8 col-md-4  col-sm-4 col-xs-4 text-right">
        <button data-bind="click:refresh" class="btn btn-primary btn-lg">
          <i class="glyphicon glyphicon-refresh"></i> Refresh
        </button>
        <a href="#/cart" class="btn btn-primary btn-lg">
          <i class="glyphicon glyphicon-shopping-cart"></i> 
          Go To Cart
        </a>
      </div>
    </div>
    ```

1.  最后，我们将定义包含我们在 Knockout 购物车项目中构建的表格的 `catalog-table.html`。某些 `data-bind` 元素应该被更新，而页脚需要被移除：

    ```js
    <table class="table">
      <thead>
      <tr>
        <th>Name</th>
        <th>Price</th>
        <th>Stock</th>
        <th></th>
      </tr>
      </thead>
      <tbody data-bind="{foreach:filteredCatalog}">
      <tr data-bind="style:{color:stock() < 5?'red':'black'}">
        <td data-bind="text:name"></td>
        <td data-bind="{currency:price}"></td>
        <td data-bind="{text:stock}"></td>
        <td>
          <add-to-cart-button params="{cart: $parent.CartService.cart, item: $data}">
          </add-to-cart-button>
          <button class="btn btn-info" data-bind="{click:$parent.edit}">
            <i class="glyphicon glyphicon-pencil"></i>
          </button>
          <button class="btn btn-danger" data-bind="{click:$parent.remove}">
            <i class="glyphicon glyphicon-remove"></i>
          </button>
        </td>
      </tr>
      </tbody>
      <!-- FOOTER HAS BEEN REMOVED -->
    </table>
    ```

### 目录视图模型

现在是时候定义我们可以在我们的模板中识别的所有组件了。我们应该开始定义我们可以在模板中定位到的基本数据：

```js
vm.showSearchBar = ko.observable(true);
vm.searchTerm = ko.observable("");
vm.catalog = ko.observableArray([]);
vm.filteredCatalog = ko.observableArray([]);
```

一旦我们定义了这些变量，我们意识到需要 Knockout 依赖。将其添加到依赖项数组中，并且也作为 `module` 函数的一个参数：

```js
define(['knockout'],function(ko){ ... })
```

现在我们应该定义 `filterCatalog` 方法。这是我们在 Knockout 项目中的视图模型中拥有的相同方法：

```js
vm.filterCatalog = function () {
  if (!vm.catalog()) {
    vm.filteredCatalog([]);
  }
  var filter = vm.searchTerm().toLowerCase();
  if (!filter) {
    vm.filteredCatalog(vm.catalog());
  }
  //filter data
  var filtered = ko.utils.arrayFilter(vm.catalog(), function (item) {
    var fields = ["name"]; //we can filter several properties
    var i = fields.length;
    while (i--) {
      var prop = fields[i];
      if (item.hasOwnProperty(prop) && ko.isObservable(item[prop])) {
        var strProp = ko.utils.unwrapObservable( item[prop]).toLocaleLowerCase();
        if (item[prop]() && (strProp.indexOf(filter) !== -1)) {
          return true;
        }
      }
    }
    return false;
  });
  vm.filteredCatalog(filtered);
};
```

`add-to-cart-button` 组件在 Knockout 项目中被定义，我们不需要触碰该组件的任何代码。这是一个很好的组件及其潜力的明确例证。

要编辑目录中的产品，我们需要导航到编辑路由。这会创建与路由插件的依赖关系。我们应该在我们的模块中添加 `plugins/router` 依赖关系。

```js
vm.edit = function(item) {
  router.navigate('#/edit/'+item.id());
}
```

要从目录中移除产品，我们需要从服务器和购物车中将其移除。要与服务器通信，我们将使用 `services/product.js` 文件，而要与购物车通信，我们将在一个名为 `services/cart` 的文件中创建一个新服务。定义 `remove` 方法：

```js
vm.remove = function(item) {
  app
    .showMessage(
      'Are you sure you want to delete this item?',
      'Delete Item',
      ['Yes', 'No']
    ).then(function(answer){
      if(answer === "Yes") {
        ProductService.remove(item.id()).then(function(response){
          vm.refresh();
            CartService.remove(item);
        })
      }
    });
}
```

首先我们使用 Durandal 的消息组件。它非常有用于处理模态对话框。我们将询问用户是否应删除产品。如果是，则我们将从服务器中删除它，然后刷新我们的视图模型，并且从购物车中删除产品，因为它不再可用。

我们应该添加一个依赖项到`durandal/app`，并且依赖于`ProductService`和`CartService`。

`ProductService`在 Knockout 项目中被定义。如果我们保持模型和服务非常简单，它们将变得可移植，并且非常适应不同的项目。

现在是实现`refresh`方法的时候了。我们将调用`ProductService.all()`方法，并显示一条消息，让用户知道产品已加载。我们将返回此方法生成的承诺。

```js
vm.refresh = function () {
  return ProductService.all().then(function(response){
    vm.catalog([]);
    response.data.forEach(function(item){
      vm.catalog.push(new Product(item.id,item.name,item.price,item.stock));
    });
    var catalog = vm.catalog();
    CartService.update(catalog);
    vm.catalog(catalog);
    vm.filteredCatalog(vm.catalog());
    LogService.success("Downloaded "+vm.catalog().length+" products", "Catalog loaded");
  });
};
```

在这里，我们使用了在 Knockout 项目中使用的相同模型来表示产品。我们看到了很多代码，但大部分是在书中较早完成的，所以我们只需要将它们从一个项目移到另一个项目中。

最后一步是激活我们的视图模型。什么时候应该激活视图模型？当我们的产品来自服务器并且准备好展示时：

```js
vm.activate = function() {
  if(vm.catalog().length === 0) {
    app.on("catalog:refresh").then(function(){
      vm.refresh();
    });
    return vm.refresh();
  } else {
    return true;
  }
}
```

第一次加载应用程序时，我们会检查目录是否有产品。如果有，我们只需返回目录已准备就绪。如果目录为空，我们会创建一个事件，让其他服务通知目录它应该更新。然后我们刷新目录以获取新数据。

这是我们`catalog`视图模型的最终结果；当然，我们仍然需要实现日志服务和购物车服务：

```js
define(['knockout','durandal/app','plugins/router', 'services/log','services/product','services/cart', 'models/product','models/cartproduct'
],function(ko, app, router, LogService, ProductService, CartService, Product, CartProduct){
  var vm = {};
  vm.showSearchBar=ko.observable(true);
  vm.searchTerm = ko.observable("");
  vm.catalog = ko.observableArray([]);
  vm.filteredCatalog = ko.observableArray([]);
  vm.CartService = CartService;

  vm.filterCatalog = function () {...};
  vm.edit = function(item) {...}
  vm.remove = function(item) {...}
  vm.refresh = function () {...}
  vm.activate = function() {...}
  return vm;
});
```

## 购物车服务

购物车服务将管理所有模块的购物车数据。服务在会话期间具有持久数据，因此它们可以帮助我们在视图模型之间共享数据。在这种情况下，购物车服务将与购物车共享一些页面：目录、购物车和订单。

购物车服务将对在`cart`可观察对象上执行的操作做出反应。`add`操作由`add-to-cart-button`组件管理，但是将这个行为集成到这里会很有趣。代码重构可以是一个很好的练习。在这个例子中，我们将保留组件，并实现其他方法。

购物车服务还将购物车的总金额存储在`grandTotal`可观察对象中。

购物车服务也更新购物车。这很有用，因为当目录更新时，购物车中存储的产品引用与目录中的新产品不同，所以我们需要更新这些引用。它还更新了目录，通过减少购物车中每个产品的单位来减少库存。我们之所以这样做是因为服务器发送给我们它所拥有的数据。服务器不知道我们现在正在购物。也许我们决定不购物，所以我们购物车中的产品不被注册为已售出。这就是为什么我们需要在从服务器获取产品后更新客户端中的单位的原因。这是购物车服务的代码：

```js
define(['knockout','durandal/app' ,'models/cartproduct'],function(ko,app, CartProduct){
  var service = {};
  service.cart = ko.observableArray([]);
  service.add = function(data){
    if(!data.hasStock()) {
      LogService.error("This product has no stock available");
      return;
    }
    var item = null;
    var tmpCart = service.cart();
    var n = tmpCart.length;

    while(n--) {
      if (tmpCart[n].product.id() === data.id()) {
        item = tmpCart[n];
      }
    }

    if (item) {
      item.addUnit();
    } else {
      item = new CartProduct(data,1);
      tmpCart.push(item);
      item.product.decreaseStock(1);
    }

    service.cart(tmpCart);
  };
  service.subtract = function(data) {
    var item = service.find(data);
    item.removeUnit();
  }
  service.grandTotal = ko.computed(function(){
    var tmpCart = service.cart();
    var total = 0;
    tmpCart.forEach(function(item){
      total+= (item.units() * item.product.price());
    });
    return total;
  });
  service.find = function (data) {
    var tmp;
    service.cart().forEach(function(item){
      if (item.product.id() === data.id()) {
        tmp = item;
      }
    });
    return tmp;
  }
  service.remove = function (data) {
    var tmp = service.find(data);
    var units = tmp.product.stock()+tmp.units();
    tmp.product.stock(units);
    service.cart.remove(tmp);
  };
  service.update = function (catalog){
    var cart = service.cart();
    var newCart = [];
    for(var i =0;i<catalog.length;i++){
      for(var j=0;j<cart.length;j++){
        var catalogItem = catalog[i];
        var cartItem = cart[j];
        if(cartItem.product.id() === catalogItem.id()){
          catalogItem.stock(catalogItem.stock() - cartItem.units());
          newCart.push(new CartProduct(catalogItem,cartItem.units()));
        }
      }
    }
    service.cart(newCart);
  }
  return service;
});
```

## 日志服务

日志服务允许我们显示消息以通知用户我们的应用程序中正在发生的情况。为此，我们使用一个称为 Toastr 的库。我们可以直接在应用程序上使用 Toastr，但是一个好的做法是始终封装库以分离我们不应该触及的代码。此外，将库包装在另一个库中使其易于扩展和定制库的行为。在这种情况下，我们还添加了在控制台中记录消息的功能：

```js
define(["toastr"],function(toastr){
  //TOASTR CONFIG
  toastr.options.positionClass = 'toast-bottom-right';

  var error = function(text,title,log) {
    toastr.error(title,text);
    if (log) {
      console.error(title,text);
    }
  };
  var success = function(text,title,log) {
    toastr.success(title,text);
    if (log) {
      console.log(title,text);
    }
  };
  var warning = function(text,title,log) {
    toastr.warning(title,text);
    if (log) {
      console.warn(title,text);
    }
  };
  var info = function(text,title,log) {
    toastr.info(atitle,text);
    if (log) {
      console.info(title,text);
    }
  };
  return {
    error:error,
    success:success,
    warning:warning,
    info:info
  }
});
```

## 将产品添加到目录

添加功能与此路由相关：

```js
{ route: 'new', title:'New product', moduleId: 'viewmodels/new', nav: true }
```

要创建这个模块，我们需要创建添加视图和添加视图模型。为此，请创建两个文件，名为`views/new`和`viewmodels/new.js`，并重复我们在目录模块中使用的模板。

![将产品添加到目录](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/knckt-ess/img/7074OS_08_04.jpg)

添加产品的工作流程

### 添加产品视图

创建或更新产品更多或更少是相同的。不同之处在于当我们编辑一个产品时，字段具有数据，当我们添加一个新产品时，此产品的字段为空。这可能使我们想知道也许我们可以隔离视图。

让我们将`new.html`文件定义如下：

```js
<div data-bind="compose:'edit.html'"></div>
```

这意味着`new.html`文件由`edit.html`文件组成。我们只需要定义一个模板来管理两者。很棒，是吗？

![添加产品视图](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/knckt-ess/img/7074OS_08_05.jpg)

添加新产品的草图

### 编辑视图

我们只需要复制并粘贴我们在 Knockout 项目中使用的编辑表单。我们已经更新了布局，但是我们使用了相同的表单。

```js
<div class="container-fluid">
  <div class="row">
    <div class="col-xs-6 col-xs-offset-3">
      <form class="form-horizontal" role="form" data-bind="with:product">
        <div class="modal-header">
          <h3 data-bind="text:$parent.title"></h3>
        </div>
        <div class="modal-body">
          <div class="form-group">
            <div class="col-sm-12">
              <input type="text" class="form-control" placeholder="Name" data-bind="textInput:name">
            </div>
          </div>
          <div class="form-group">
            <div class="col-sm-12">
              <input type="text" class="form-control" placeholder="Price" data-bind="textInput:price">
            </div>
          </div>
          <div class="form-group">
            <div class="col-sm-12">
              <input type="text" class="form-control" placeholder="Stock" data-bind="textInput:stock">
            </div>
          </div>
        </div>
        <div class="modal-footer">
          <div class="form-group">
            <div class="col-sm-12">
              <a href="#/catalog"></a>
              <button type="submit" class="btn btn-default" data-bind="{click:$parent.edit, enable:!errors().length}">
                <i class="glyphicon glyphicon-plus-sign"></i>
                <span data-bind="text:$parent.btn"></span>
              </button>
            </div>
          </div>
        </div>
      </form>
    </div>
  </div>
</div>
```

有一些东西应该动态创建，比如布局的标题和按钮名称。`edit`方法将指定产品服务的哪个方法来处理产品——`ProductService.create`或`ProductService.save`。

### 添加产品视图模型

添加产品视图模型编码在`viewmodels/new.js`文件中。它将创建一个新产品。如果一切顺利，我们会通知用户并导航到目录。为了在目录中显示新产品，我们触发`catalog:refresh`事件：

```js
define(["durandal/app","plugins/router","services/log","services/uuid","services/product","models/product"
],function(app, router,LogService,uuid, ProductService,Product){
  var vm = {};
  vm.title = "New product";
  vm.btn = "Add product";
  vm.edit = function() {
    ProductService.create(vm.product.toObj()).then(function(response){
      LogService.success("Product added","New product "+vm.product.name()+" added");
      router.navigate("#/catalog");
      app.trigger("catalog:refresh");
    });
  };
  vm.activate = function () {
    vm.product = new Product();
  };
  return vm;
});
```

在我们的模拟的第一个版本中，如果我们添加了一个新项目，我们的目录没有得到更新。它返回了我们一开始得到的同样五个产品。我们打算改进我们的模拟库，使其更加逼真。

### 使模拟变得真实

让我们来看看我们的`mocks.js`文件，特别是获取产品模拟的部分：

```js
$.mockjax({
  url: "/products",
  type: "GET",
  dataType: "json",
  responseTime: 750,
  responseText: $.mockJSON.generateFromTemplate({
    "data|5-5": [{
      "id|1-100": 0,
      "name": "@PRODUCTNAME",
      "price|10-500": 0,
      "stock|1-9": 0
    }]
  })
});
```

让我们将其重构为：

```js
$.mockjax({
  url: "/products",
  type: "GET",
  dataType: "json",
  responseTime: 750,
  responseText: updatedCatalog()
});
```

现在我们要创建`updatedCatalog`函数。我们在开始时生成产品数组，然后始终使用这个副本进行操作：

```js
var catalog = $.mockJSON.generateFromTemplate({
  "data|5-5": [{
    "id|1-100": 0,
    "name": "@PRODUCTNAME",
    "price|10-500": 0,
    "stock|1-9": 0
  }]
});
var updatedCatalog = function () {
  return catalog;
}
```

在旧版本的模拟中，当我们得到一个产品时，我们使用模板随机生成一个产品。现在我们将回到真实的产品。我们将沿着目录进行迭代，并返回具有选定 ID 的产品。此外，我们还将更新模拟对象。我们将创建一个响应函数来查找产品并生成正确的响应，而不是编写响应文本：

```js
function findById(id){
  var product;
  catalog.data.forEach(function(item){
    if (item.id === id) {
      product = item;
    }
  });
  return product;
};
$.mockjax({
  url: /^\/products\/([\d]+)$/,
  type: "GET",
  dataType: "json",
  responseTime: 750,
  response: function(settings){
    var parts = settings.url.split("/");
    var id = parseInt(parts[2],10);
    var p = findById(id);
    this.responseText = {
      "data": p
    }
  }
});
```

我们应该更新`POST`和`PUT`模拟数据以向模拟目录添加产品并更新已存在的产品：

```js
var lastId= 101; //Max autogenarated id is 100
$.mockjax({
  url: "/products",
  type:"POST",
  dataType: "json",
  responseTime: 750,
  response: function(settings){
    settings.data.id = lastId;
    lastId++;
    catalog.data.push(settings.data);
    this.responseText = {
      "data": {
        result: "true",
          text: "Product created"
      }
    }
  }
});
$.mockjax({
  url: "/products",
  type:"PUT",
  dataType: "json",
  responseTime: 750,
  response: function (settings) {
    var p = findById(settings.data.id);
    p.name = settings.data.name;
    p.price = settings.data.price;
    p.stock = settings.data.stock;
    this.responseText = {
      "data": {
        result: "true",
        text: "Product saved"
      }
    }
  }
});
```

当调用`DELETE`方法时，我们还应该从模拟数据中移除产品：

```js
$.mockjax({
  url: /^\/products\/([\d]+)$/,
  type:"DELETE",
  dataType: "json",
  responseTime: 750,
  response: function(settings){
    var parts = settings.url.split("/");
    var id = parseInt(parts[2],10);
    var p = findById(id);
    var index = catalog.data.indexOf(p);
    if (index > -1) {
      catalog.data.splice(index, 1);
    }
    this.responseText = {
      "data": {
        result: "true",
        text: "Product deleted"
      }
    }
  }
});
```

最后，我们应该将订单模拟数据移动到这个文件中，以便与目录共享。当执行订单时，目录中的库存应该更新：

```js
$.mockjax({
  type: 'PUT',
  url: '/order',
  responseTime: 750,
  response: function (settings){
    var cart = settings.data.order();
    cart.forEach(function(item){
      var elem = findById(item.product.id());
      elem.stock -= item.units();
    });
    this.responseText = {
      "data": {
        orderId:uuid(),
        result: "true",
        text: "Order saved"
      }
    };
  }
});
```

订单模拟数据将生成一个用于识别订单的唯一 ID。这必须发送回给用户以便未来识别订单。在我们的应用程序中，这标志着我们项目生命周期的结束。

这是我们用于生成唯一 ID 的`uuid`函数：

```js
var uuid = (function uuid() {
  function s4() {
    return Math.floor((1 + Math.random()) * 0x10000)
    .toString(16)
    .substring(1);
  }
  return function() {
    return s4() + s4() + '-' + s4() + '-' + s4() + '-' + s4() + '-' + s4() + s4() + s4();
  };
})();
```

我们可以将该函数保留在模拟模块中，或者创建一个新的服务来处理唯一 ID 的生成。

现在我们的模拟数据以更现实的方式响应应用程序。

### 编辑视图模型

回到我们的模块，现在我们需要创建`edit.js`视图模型。它将与`new.js`文件有相同的结构，但在这种情况下，激活将会获取要编辑的产品。然后我们将保存产品，并且模拟数据将在（假的）服务器上更新它：

```js
define(["durandal/app","plugins/router","services/log","services/uuid","services/product","models/product"
],function(app, router,LogService,uuid,ProductService,Product){
  var vm = {};
  vm.title = "Edit Product";
  vm.btn = "Edit product";
  vm.activate = function(id) {
    return ProductService.get(id).then(function(response){
      var p = response.data;
      if (p) {
        vm.product = new Product(p.id, p.name, p.price, p.stock);
      } else {
        LogService.error("We didn't find product with id: "+id)
        router.navigate('#/catalog');
      }
    });
  };
  vm.edit = function() {
    ProductService.save(vm.product.toObj()).then( function(response){
      LogService.success("Product saved","Product "+vm.product.name()+" saved");
      router.navigate("#/catalog");
      app.trigger("catalog:refresh");
    });
  };
  return vm;
});
```

我们应该注意，在添加产品和编辑产品中，模型都经过了验证。我们在 Knockout 项目中已经这样做了，现在我们在这个项目中重用它。这不是很神奇吗？

## 购物车模块

购物车模块将管理显示购物车的部分。就像我们在 Knockout 项目中所做的那样，我们应该能够更新产品的数量。如果不再需要商品，我们将删除它们。并且只有在购物车中有商品时才激活此视图，因为如果购物车为空，去访问购物车是没有意义的。在这种情况下，我们将被重定向到目录。

![购物车模块](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/knckt-ess/img/7074OS_08_06.jpg)

购物车工作流

### 购物车视图

购物车使用与我们在 Knockout 项目中使用的相同的模板。当然，我们对它进行了一些调整，使其在屏幕上居中显示：

```js
<div class="container-fluid">
  <div class="row">
    <div class="col-xs-8 col-xs-offset-2">
      <h1>Cart</h1>
      <div class="list-group" data-bind="foreach:cart">
        <div data-bind="compose: 'cart-item.html'"></div>
      </div>
      <button class="btn btn-primary btn-sm" 
        data-bind="enable:cart().length,click:toOrder">
		Confirm Order
      </button>
    </div>
  </div>
</div>
```

就像我们处理购物车商品一样，我们也在这里组合视图。`cart-item.html`文件拥有和 Knockout 项目中相同的代码。只需注意现在`addUnit`和`removeUnit`由父组件调用：

```js
<div class="list-group-item" style="overflow: hidden">
  <button type="button" class="close pull-right" data-bind="click:$parent.removeProduct">
    <span>&times;</span>
  </button>
  <h4 class="" data-bind="text:product.name"></h4>
  <div class="input-group cart-unit">
    <input type="text" class="form-control" data-bind="textInput:units" readonly/>
    <span class="input-group-addon">
      <div class="btn-group-vertical">
        <button class="btn btn-default btn-xs add-unit" data-bind="click:$parent.addUnit">
          <i class="glyphicon glyphicon-chevron-up"></i>
        </button>
        <button class="btn btn-default btn-xs remove-unit" data-bind="click:$parent.removeUnit">
          <i class="glyphicon glyphicon-chevron-down"></i>
        </button>
      </div>
    </span>
  </div>
</div>
```

![购物车视图](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/knckt-ess/img/7074OS_08_07.jpg)

购物车视图模拟

### 购物车视图模型

购物车视图模型将与购物车服务通信，并更新购物车的状态。看看我们是如何在模块之间使用购物车服务共享信息的。这是因为我们已将服务创建为对象，并且它是一个单例。一旦加载，它将在应用程序生命周期内持续存在：

```js
define([
  'durandal/app','plugins/router','services/log',"services/cart"
],function(app, router, LogService, CartService){
  var vm={};
  vm.cart = CartService.cart;
  vm.addUnit = function(data){
    CartService.add(data.product);
  };
  vm.removeUnit = function(data) {
    if (data.units() === 1) {
      remove(data);
    } else {
      CartService.subtract(data);
    }

  };
  vm.removeProduct = function(data) {
    remove(data);
  };
  vm.toOrder = function() {
    router.navigate('#/order');
  }
  vm.canActivate = function () {
    var result = (vm.cart().length > 0);

    if(!result) {
      LogService.error("Select some products before", "Cart is empty");
      return {redirect:'#/catalog'};
    }

    return result;
  }
  function remove(data) {
    app
    .showMessage(
      'Are you sure you want to delete this item?',
      'Delete Item',
      ['Yes', 'No']
    ).then(function(answer){
     if(answer === "Yes") {
       CartService.remove(data.product);
       LogService.success("Product removed");
     } else {
       LogService.success("Deletion canceled");
     }
   });
  }
  return vm;
});
```

在 Durandal 中，有两种组件之间通信的方式，服务和事件。要在视图模型之间共享信息，最佳实践是使用服务。如果要从一个服务向视图模型或视图模型之间发送消息，则应使用事件。这是因为服务可以在模块内被引用，可以显式调用它们。此外，我们无法从其他视图模型或服务中访问视图模型，这就是为什么我们需要使用事件向它们发送消息的原因。

## 订单模块

此模块将管理我们订单的确认。要完成订单，我们需要输入个人数据。只有在购物车中有商品时，我们才能访问订单页面。一旦我们确认订单，我们将收到服务器发送的订单 ID 消息。产品库存将更新，我们将能够继续购物。

![订单模块](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/knckt-ess/img/7074OS_08_08.jpg)

订单工作流程

### 订单视图

订单视图将是我们在 Knockout 项目中构建的相同订单视图。这次我们将使用组合使视图更简单。

`order.html` 文件将包含页面的结构，我们将构建一些部分来组成整个视图。这些部分将是：

+   `order-cart-detail.html`：这将包含只读购物车

+   `order-contact-data.html`：这将包含个人数据

+   `order-buttons.html`：这将包含页面的操作按钮

`order.html` 文件将包含这段代码：

```js
<h1>Confirm order</h1>
<div class="col-xs-12 col-sm-6">
  <div class="modal-header">
    <h3>Order</h3>
  </div>
  <div data-bind="compose:'order-cart-detail.html'"></div>
</div>
<div class="col-xs-12 col-sm-6">
  <div data-bind="compose:'order-contact-data.html'"></div>
  <div data-bind="compose:'order-buttons.html'"></div>
</div>
```

`order-cart.html` 文件将包含只读购物车。这是在 Knockout 购物车项目中的 `order.html` 模板中找到的相同标记。

```js
<table class="table">
  <thead>
  <tr>
    ...
  </tr>
  </thead>
  <tbody data-bind="foreach:cart">
    ...
  </tbody>
  <tfoot>
  <tr>
    <td colspan="3"></td>
    <td class="text-right">
      Total:<span data-bind="currency:grandTotal"></span>
    </td>
  </tr>
  </tfoot>
</table>
```

`order-contact.html` 文件将包含在视图 `order.html` Knockout 购物车项目中的表单：

```js
<form class="form-horizontal" role="form" data-bind="with:customer">
  <div class="modal-header">
    <h3>Customer Information</h3>
  </div>
  <div class="modal-body">
    ...
  </div>
</form>
```

最后，`order-buttons.html` 文件中有确认订单的按钮。当然，你可以在我们在 Knockout 购物车项目中构建的 `order.html` 文件中找到它。我们尽可能地重用代码。

```js
<div class="col-xs-12">
  <button class="btn btn-sm btn-primary" data-bind="click:finishOrder, enable:!customer.errors().length">
    Buy & finish
  </button>
  <span class="text-danger" data-bind="visible:customer.errors().length">
    Complete your personal data to receive the order.
  </span>
</div>
```

![订单视图](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/knckt-ess/img/7074OS_08_09.jpg)

订单草图

### 订单视图模型

订单视图将检查我们的购物车是否为空以允许激活。验证由客户模型管理。这个模型是在 Knockout 购物车项目中构建的。其余的代码部分来自我们在 Knockout 购物车项目中的大视图模型：

```js
define(["knockout","durandal/app","plugins/router","services/log", "services/cart","models/customer","services/order" ], function(ko, app, router, LogService, CartService, Customer, OrderService){
  var vm = {};

  vm.countries = ko.observableArray(['United States','United Kingdom']);
  vm.cart = CartService.cart;
  vm.grandTotal = CartService.grandTotal;
  vm.customer = new Customer();
  vm.finishOrder = function () {
    OrderService.save({
      customer: vm.customer,
      order: vm.cart
    }).then(function(response){
      app.showMessage(
        "Your order id is: <strong>"+response.data.orderId+"</strong>",
        'Order processed successfully'
      ).then(function(){
        LogService.success("Order completed");
        CartService.cart([]);
        router.navigate("#/catalog");
        app.trigger("catalog:refresh");
      });
    });
  }

  vm.canActivate = function () {
    var result = (vm.cart().length > 0);

    if(!result) {
      LogService.error("Select some products before","Cart is empty");
    }

    return {redirect:'#/catalog'};
  }

  return vm;
});
```

最后，我们的项目完成了，我们重新使用了大部分旧代码。迁移项目后，我们可以看到 Durandal 给我们带来的优势。还要注意，我们并没有充分利用 Durandal 和 Knockout 的潜力。我们可以迭代这个项目，一遍又一遍地改进所有部分。我们可以创建完美的隔离组件。我们可以将目录分割成更小的部分，并添加更多功能，如订购和分页。但是，这个项目给我们提供了 Durandal 能力的快速全局概述。

# 按功能分组代码 - 管理大项目

正如您在 `main.js` 文件中所见，我们正在使用 Durandal 约定。这意味着我们所有的视图模型都位于 `viewmodels` 文件夹中，而所有的视图都位于 `views` 文件夹中。当我们有一个大项目时，将所有文件放在同一个文件夹中可能会难以管理。

在这种情况下，我们从 `main.js` 文件中删除了 `viewLocator.useConvention();` 语句。这作为 Durandal 的一个指示，表明所有的视图都在与视图模型相同的文件夹中。

我们将按特性对项目进行分组。我们将在我们的项目中定义这些特性：

+   catalog

+   cart

+   order

+   product

+   shell

它们将包含每个特性的代码。服务、模型和其他组件将与我们使用约定时一样。看看这些文件夹是什么样子的：

![按特性分组代码 - 管理大型项目](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/knckt-ess/img/7074OS_08_10.jpg)

文件按特性分组

我们需要更新一些代码。第一步是更新主文件夹，设置 shell 模块的新 ID：

```js
app.setRoot('shell/shell', 'entrance');
```

然后我们应该对 shell 模块内的路由器做同样的事情：

```js
router.map([
  { route: ['','/','catalog'], title:'Catalog', moduleId: 'catalog/catalog', nav: true },
  { route: 'new', title:'New product', moduleId: 'product/new', nav: true },
  { route: 'edit/:id', title:'Edit product', moduleId: 'product/edit', nav: false },
  { route: 'cart', title:'Cart', moduleId: 'cart/cart', nav: false },
  { route: 'order', title:'Order', moduleId: 'order/order', nav: true }
]).buildNavigationModel();
```

最后，我们需要更新组合路径。它们应该是完整路径。这意味着当我们有以下代码时：

```js
<div data-bind="compose:'catalog-details.html'"/></div>
```

现在我们将会有以下代码：

```js
<div data-bind="compose:'catalog/catalog-details.html"/></div>
```

我们的代码将准备就绪。

注意，现在很容易找到我们正在工作的代码所在的位置。通常，我们会在一个特性上工作，并且将所有这个特性的代码放在同一个地方更加方便。此外，我们可以更好地看到我们是否正确地隔离了我们的特性。如果我们注意到我们在特性文件夹之外工作得太多，也许这意味着你正在做错事。

要查看本章的代码，您可以从 GitHub 下载：

+   Durandal 项目使用约定，来自 [`github.com/jorgeferrando/durandal-cart/tree/chapter8part1`](https://github.com/jorgeferrando/durandal-cart/tree/chapter8part1)。

+   Durandal 项目将文件按特性分组，来自 [`github.com/jorgeferrando/durandal-cart/tree/master`](https://github.com/jorgeferrando/durandal-cart/tree/master)。

# 摘要

最终，我们开发了一个完整的应用程序，引导我们使用 Durandal 创建单页面应用程序。

在这本书中，您已经学会了使用 JavaScript 代码的最佳实践。这些实践和模式，比如揭示模式或模块模式，在所有的框架和库中都被使用。

构建独立且小的代码片段有助于我们轻松地将代码从一个环境迁移到另一个环境。在仅仅一个章节中，我们已经将我们的应用程序从一个基本的 Knockout 应用程序迁移到了一个 Durandal 应用程序。

现在我们已经掌握了 Knockout 和 Durandal 的良好技能，我们可以尝试自己改进这个应用程序。

我们可以创建一个用户模块，使用户能够登录，只允许管理员编辑和删除目录中的项目。或者，我们可以对我们的产品进行分页，并按价格排序。我们已经掌握了成功开发所有这些功能所需的所有技能。我们只需按照您在本书中学到的步骤来完成这些开发任务。

我希望你像我一样喜欢这本书。我想告诉你，你需要努力学习更多关于 JavaScript、Knockout、Durandal 以及当今互联网上存在的所有奇妙的 JavaScript 框架。学习最佳实践，遵循最佳模式，保持你的代码简单和稳固。
