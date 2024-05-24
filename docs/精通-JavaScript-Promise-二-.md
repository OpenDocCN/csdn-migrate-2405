# 精通 JavaScript Promise（二）

> 原文：[`zh.annas-archive.org/md5/9D521BCA2BC828904B069DC1B0B0683B`](https://zh.annas-archive.org/md5/9D521BCA2BC828904B069DC1B0B0683B)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：Angular.js 中的承诺

在上一章，我们学习了 Node.js 及其实现。我们还看到了 Node.js 如何用来放大实时网络，以及如何使用承诺来提供更高效的 app。

在本章中，我们探讨了承诺实现的另一面，即在 Angular.js 中的承诺。

随着我们的学习深入，我们将了解什么是 Angular.js，它为什么被创建，它能给我们带来哪些好处，最后，我们将学习如何在 Angular.js 中实现承诺（promises）。

让我们从 Angular.js 的介绍和设置开始。将提供一些示例代码和运行示例。然后我们将转到 Angular.js 中的承诺。

# Angular.js 的演变

自从单页网络应用程序诞生以来，人们已经找到了编写此类应用程序代码的许多方法。单页网络应用程序的使用之所以迅速增加，是因为它们更快、平台无关、轻便，适用于所有类型的设备，并能自动调整到所有屏幕尺寸。这是工程师希望开发单页网络应用程序，并且更愿意使用简化日常工作的库和框架的主要原因。

Angular.js 的创建是基于相同的概念。Angular.js 的核心是采用声明式编程概念，指出用户界面应用来连接软件服务，而我们可以使用命令式编程来定义业务逻辑。

Angular.js 的框架扩展了经典的 HTML（HTML5），以将内容紧密结合。它使用了一种双向数据绑定技术，有助于自动同步模型和视图。有了这些特性，Angular.js 与 DOM 无关，这有助于提高性能和耦合模块的安全标准。

Angular.js 最显著的非功能性属性是其维护者——谷歌的大脑。

谷歌是 Angular.js 开发、维护和发布不同版本背后的力量。

Angular.js 最初于 2009 年发布，旨在提供客户端**MVC**（模型-视图-控制器）实现，以简化应用程序的开发和测试。此外，它还提供了一个工具集，用于创建富互联网应用程序和现代实时网络应用程序的工具。

![Angular.js 的演变](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-prms/img/5500OS_07_01.jpg)

# Angular.js 文档的结构

Angular.js 使用基础文档的 HTML 文件进行实现。其语法非常简单且容易记忆。页面的结构是一个带有`ng`的简单 HTML 文件。这被称为 Angular.js 指令，它可以与 HTML 一起使用，也可以作为独立的文档链接。

要开始使用 Angular.js，你需要添加几行代码，它就可以运行起来。要使用 Angular.js，请执行以下步骤：

1.  添加`ng`指令；你只需要添加这段简单的代码就可以开始使用 Angular.js：

    ```js
    <html ng-app="opdsys">
    ```

1.  在文件中添加库：

    ```js
    <script type="text/JavaScript" src="img/angular.min.js"></script>
    ```

1.  现在，在 HTML 标签内定义变量，如下所示：

    ```js
    <tr ng-repeat= "reservations in reservation| archive" >
    ```

1.  最后，你可以通过调用变量来使用它：

    ```js
    <td>  {{reservations.id}} < /td>
    ```

# 开始学习 Angular.js

想要下载 Angular.js，请前往[`angularjs.org/`](https://angularjs.org/)并点击**下载**按钮。以下对话框将出现：

![开始学习 Angular.js](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-prms/img/5500OS_07_02.jpg)

选择稳定和压缩构建，然后点击**下载**。这个文件是紧凑的，去除了所有的空白，以便更快地加载。你需要将这个文件保存到你的工作目录中，因为你将在本章的后续部分需要它。

# 创建你的第一个 Angular.js 文件

我们将使用下载的文件将其包含在我们的 HTML 中。从那里，它将展示 Angular.js 是一个双向绑定的框架，并实时显示结果。

## 第一步 - 创建 HTML 5 文档

创建一个这样的文件：

```js
<html>
<head>
  <title></title>
</head>
<body>

</body>
</html>
```

## 第二步 - 向其中添加 JavaScript 文件

创建一个包含以下代码的 JavaScript 文件：

```js
<html>
<head>
  <title> OPD System</title>
  <script type="text/javascript" src='angular.min.js' ></script>
</head>
<body> </body>
```

在前面的代码中添加 Angular.js 指令：

```js
<html ng-app >
<head>
  <title>OPD System</title>
  <script type="text/javascript" src='angular.min.js' ></script>
</head>
<body>
</body>
```

就这样；你现在有一个可以进一步使用的工作 Angular.js 文件了。

# 如何在你本地机器上使用 Angular.js

你有几种方法可以在你的本地机器上体验 Angular.js。一种方法是使用你本地下载的服务器。XAMPP 或 Node.js 服务器可以是你执行 Angular.js 代码的最佳选择。

你可以从[`www.apachefriends.org/download.html`](https://www.apachefriends.org/download.html)下载 XAMPP 服务器并在你的 PC 上安装它。安装完成后，你只需将你的 Angular.js 文件/文件夹拖放到`htdocs`文件夹中，并通过简单地访问`http://localhost/source/`来访问这些文件，其中`source`应该是`htdocs`内的文件夹名称。

使用 Node.js，只需将以下代码粘贴到文本文件中并将其保存为`app.js`：

```js
//sample node server from official site at https://nodejs.org/
var http = require('http');
http.createServer(function (req, res) {
  res.writeHead(200, {'Content-Type': 'text/plain'});
  res.end('Hello World\n');
}).listen(1337, '127.0.0.1');
console.log('Server running at http://127.0.0.1:1337/');
```

将此文件保存到您驱动器上的任何文件夹中。现在，通过在 Windows 机器的**运行**实用程序中键入`cmd`来打开命令提示符，并转到包含`app.js`文件的文件夹。

一旦你到达那里，请输入以下行并按**Enter**：

```js
> node app.js

```

你将看到屏幕上的响应如下：

```js
Server running at http://127.0.0.1:1337/

```

一旦你得到这个响应，你的服务器就可以使用了。将你的 Angular.js 文件放在`app.js`文件所在的同一文件夹中，并使用浏览器访问它，如下所示：

`http://127.0.0.1:1337/source/`

这里，`source`是包含`app.js`文件的文件夹。

# 你对服务器有什么偏好？

你可以使用其中任何一个服务器，因为它们都是开源的，并且都具有对 Angular.js 很好的适应性。选择哪一个完全取决于你。为了让你更容易理解，我选择了 Node.js，因为它非常方便且易于维护，并且性能输出更高。

# Angular.js 的关键元素

在我们深入了解 Angular.js 中如何实现承诺之前，我们将首先查看 Angular.js 的关键元素以及它们是如何为我们工作的。

在本节中，您将学习 Angular.js 的关键元素。所获得的技能将在本章后续部分中使用。您将能够根据需要将 Angular.js 中的承诺概念应用于 Angular.js 并编写自己的自定义承诺。

我们将讨论的最常见元素是：

+   提供作用域数据

+   过滤输出

+   控制作用域

+   路由视图

## 提供作用域数据

我们将对前端 HTML、CSS 和 JavaScript 进行操作，以在浏览器中显示结果。我们还将从[`getbootstrap.com/getting-started/#download`](http://getbootstrap.com/getting-started/#download)获取 bootstrap，以在代码中进行美容修饰：

1.  文件结构必须如以下图片中所定义。为了展示代码如何工作，我们将使用 Node.js 服务器。名为 public 的文件夹需要部署在`app.js`所在的文件夹中。一旦服务器启动，导航到`http://127.0.0.1:3000`，您将在那里看到运行的应用程序。![提供作用域数据](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-prms/img/5500OS_07_03.jpg)

1.  我们将为地铁站的可用服务创建一个应用程序。让我们称这个站为 Stratford，从这里我们将查看哪个地铁服务可用。

1.  在`js/controller`文件夹中创建一个名为`app.js`的文件。这个文件将看起来像这样：

    ```js
    function AppCtrl ($scope) {
      $scope.serviceName = {
        "CRTL": {
            "code": "CRTL",
            "name": "Central Line Service",
            "currentLocation": "Oxford Circus",

        },

        "JUBL": {
            "code": "JUBL",
            "name": "Jubblie Line Service",
            "currentLocation": "westham",

        },

        "DLR": {
            "code": "DLR",
            "name": "Docland Ligt railway",
            "currentLocation": " westham",

        },

      };
    }
    ```

1.  现在，在 public 文件夹的根目录下创建一个 HTML 文件，命名为`index.html`，并添加以下代码：

    ```js
    <html ng-app>
    <head>
      <title>Services listing </title>
      <script type="text/javascript" src="img/angular.min.js"></script>
      <script type="text/javascript" src="img/app.js"></script>
      <link rel="stylesheet" type="text/css" href="css/bootstrap.min.css">
      <link rel="stylesheet" type="text/css" href="css/bootstrap-responsive.min.css">
    </head>
    <body>
      < ul ng-repeat="services in services">
        <li>{{serviceName.code}}</li>
        <li>{{serviceName.name}}</li>
      </ul> </body>
    </html>
    ```

现在，当您在浏览器中刷新时，它会显示离开 Stratford 车站的服务。然而，这是如何实现的呢？

在 HTML 文档的顶部，有一个`ng`指令将创建 Angular.js 应用程序，然后我们可以包含 JavaScript 文件；一个是 Angular.js 的压缩文件，另一个是我们创建的 JavaScript 文件，它提供作用域以便 HTML 显示它。这一切都是由于一个变量声明`$scope`。

`$scope`负责在提供的范围内绑定数据并提供输出。这有助于 Angular.js 在其独特的范围内执行计算，这就是全部！

## 数据过滤

有时，我们需要以特定格式显示应用程序中的数据。在 Angular.js 中，这就像简单地为我们要过滤的元素提供一些操作符一样简单。

用于此目的的操作符是管道符号，`|`。一旦我们添加了一个管道符号，Angular.js 就知道我们想要过滤掉一些东西。让我们看看两个最重要的过滤器：

为了在页面输出中将文本转换为大写，请考虑以下代码：

```js
<html ng-app>
<head>
  <title>Services listing </title>
  <script type="text/javascript" src="img/angular.min.js"></script>
  <script type="text/javascript" src="img/app.js"></script>
  <link rel="stylesheet" type="text/css" href="css/bootstrap.min.css">
  <link rel="stylesheet" type="text/css" href="css/bootstrap-responsive.min.css">
</head>
<body>
  <div class="container" ng-controller="AppCtrl">
    <h1>Services from Stratford station</h1>
    <ul>
      <li ng-repeat="service in service">{{serviceName.code}}
       - {{serviceName.name | uppercase}}</li>
    </ul>

  </div>
</body>
</html>
```

过滤数据的最有帮助的功能是获取整个对象作为 JSON。这不仅有助于调试模式，而且还用于验证提供的数据以查看格式是否正确。

考虑以下代码，它不仅会过滤出作为 JSON 对象的数据，而且在显示输出之前还会验证它：

```js
<html ng-app>
<head>
  <title>Services listing </title>
  <script type="text/javascript" src="img/angular.min.js"></script>
  <script type="text/javascript" src="img/app.js"></script>
  <link rel="stylesheet" type="text/css" href="css/bootstrap.min.css">
  <link rel="stylesheet" type="text/css" href="css/bootstrap-responsive.min.css">
</head>
<body>
  <div class="container" ng-controller="AppCtrl">
    <h1>Services from Stratford station</h1>
    <ul>
      <li ng-repeat="service in service">{{serviceName.code}}
       - {{serviceName | json}}</li>
    </ul>

  </div>
</body>
</html>
```

这将返回整个 JavaScript 对象作为 JSON。现在，您可以通过获取您的手脏，挖掘 JavaScript 代码并添加`alert()`，来验证数据或进入调试模式。

## 控制作用域

我们还可以向特定流提供一个完整的函数，而不是一个单一的变量；这将帮助我们无需太多麻烦地在任何应用程序的不同部分之间进行互联。考虑以下 JavaScript 代码，它显示了我们如何向特定流提供一个完整的函数：

```js
function AppCtrl ($scope) {
  $scope.serviceName = {
    "CRTL": {
      "code": "CRTL",
      "name": "Central Line Service",
      "currentLocation": "Oxford Circus",

    },

    "JUBL": {
      "code": "JUBL",
      "name": "Jubblie Line Service",
      "currentLocation": "westham",

    },

    "DLR": {
      "code": "DLR",
      "name": "Docland Ligt railway",
      "currentLocation": " westham",

    },

  };

  $scope.curretStation = null;

  $scope.setAirport = function (code) {
    $scope.curretStation = $scope.service[code];
  };
}
```

在最后三行中，我们添加了一个函数，它将被完全传递给 HTML 输出中的调用`ng`指令。HTML 代码看起来像这样：

```js
<html ng-app>
<head>
  <title>Services listing </title>
  <script type="text/javascript" src="img/angular.min.js"></script>
  <script type="text/javascript" src="img/app.js"></script>
  <link rel="stylesheet" type="text/css" href="css/bootstrap.min.css">
  <link rel="stylesheet" type="text/css" href="css/bootstrap-responsive.min.css">
</head>
<body>
  <div class="container" ng-controller="AppCtrl">
    <h1>Services from Stratford station</h1>
    <ul>
      <li ng-repeat="Services in ServicesName">
        <a href="" ng-click="setAirport(Services.code)">{{Services.code}} - {{Services.code}}</a>
      </li>
    </ul>

    <p ng-show="currentStation">Current Services: {{currentStationname}}</p>
  </div>
</body>
</html>
```

请注意，我们写的代码非常整洁，更新非常少。我们可以在`body`标签完成之前的最后几行实现许多所需的更改；您将注意到我们是如何通过 Angular.js 传递一个完整的函数的。

## 路由视图

传统的网站由许多通过`href`标签链接在一起的页面组成。他们的内容很难阅读，并且比以往任何时候都需要更多的维护。随着单页 Web 应用程序的出现，信息立即出现在浏览器中，因为视图可以通过从一个链接路由到另一个链接，而不需要重复访问服务器，或不需要等待页面加载。

![路由视图](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-prms/img/5500OS_07_04.jpg)

从我们的示例中，我们将添加另一个文件作为一个模块，并将其放在 JS 文件夹的根目录下。代码看起来像这样：

```js
angular.module('services', [])
  .config(airlineRouter);

function airlineRouter ($routeProvider) {
  $routeProvider
    .when('/', {templateUrl: 'partials/destinations.html',
      controller: 'DestinationsCtrl'})
    .when('/Services/:airportCode', {
      templateUrl: 'partials/stations.html',
      controller: 'ServiceCtrl'
    })
    .when('/service', {
      template: '<h3>Flights</h3> {{Services | json}}',
      controller: 'FlightsCtrl'})
    .when('/reservations', {
      template: '<h3>Your Reservations</h3> {{Services | json}}',
      controller: 'ReservationsCtrl'});
}
```

这将在不经过服务器的情况下，在浏览器中动态生成视图。我们需要添加更多的文件以增加动态性。我们将添加一个名为`partials`的文件夹，在该文件夹中我们放置了两个名为`services`和`destination`的文件。

`destination.html`文件将看起来像这样：

```js
<div class="pull-left span6">
  <h3>All Destinations</h3>
  <ul>
    <li ng-repeat="destinationin destinations">
      <a href="" ng-click="setDestinations (service.code)">{{name.code}} - {{destination.name}}</a>
    </li>
  </ul>

</div>
<div class="span5" ng-include src="img/sidebarURL"></div>
```

`services.html`文件将看起来像这样：

```js
<div ng-show="CurrentServices">
  <h3>{{CurrentServices.name}}</h3>

  <h4>Destinations</h4>

  <ul>
    <li ng-repeat="destination in CurrentServices.destinations">
      <a ng-href="#/airports/{{destination}}">{{destination}}</a>
    </li>
  </ul>
</div>
```

在根目录下的 public 文件夹中编辑`index.html`文件后，视图将看起来像这样：

```js
<html ng-app="ServiceCtrl">
<head>
  <title>Demo</title>
  <script type="text/javascript" src="img/angular.min.js"></script>
  <script type="text/javascript" src="img/app.js"></script>
  <script type="text/javascript" src="img/destinations.js"></script>
  <script type="text/javascript" src="img/services.js"></script>
  <script type="text/javascript" src="img/reservations.js"></script>
  <script type="text/javascript" src="img/station.js"></script>
  <script type="text/javascript" src="img/app.js"></script>
  <link rel="stylesheet" type="text/css" href="css/bootstrap.min.css">
  <link rel="stylesheet" type="text/css" href="css/bootstrap-responsive.min.css">
</head>
<body>
  <div class="container" ng-controller="AppCtrl">
    <h1>AngulAir</h1>

    <ul class="nav nav-pills">
      <li ng-class="destinationsActive">
        <a href="#">Destinations</a>
      </li>
      <li ng-class="servicesActive">
        <a href="#/services">services</a>
      </li>
      <li ng-class="reservationsActive">
        <a href="#/reservations">Reservations</a>
      </li>
    </ul>

    <div ng-view></div>
  </div>
</body>
</html>
```

# 在 Angular.js 中实现承诺。

承诺的全部内容在于如何将异步行为应用于应用程序的某一部分或整个应用程序。有许多其他的 JavaScript 库也存在承诺的概念，但在 Angular.js 中，它比其他任何客户端应用程序都要高效。

在 Angular.js 中，承诺有两种口味，一个是`$q`，另一个是 Q。它们之间有什么区别？我们将在接下来的部分详细探讨。现在，我们将看看对 Angular.js 来说承诺意味着什么。

在 Angular.js 中实现承诺有多种可能的方式。最常见的是使用`$q`参数，这是受 Chris Kowal 的 Q 库启发的。主要的是，Angular.js 使用这个来提供异步方法的实现。

在 Angular.js 中，服务的顺序是从上到下，从`$q`开始，它被认为是最高层；在其中，还嵌入了许多其他子类，例如`$q.reject()`或`$q.resolve()`。与 Angular.js 中的一切承诺相关的都必须遵循`$q`参数。

从`$q.when()`方法开始，它看起来像是立即创建一个方法，但实际上它只是规范化了一个可能或不创建承诺对象的值。`$q.when()`的用法基于传递给它的值。如果传递的值是一个承诺，`$q.when()`会执行它的任务；如果它不是一个承诺值，`$q.when()`会创建它。

# 在 Angular.js 中使用承诺的架构

由于 Chris Kowal 的 Q 库是全局承诺回调返回的提供者和灵感来源，Angular.js 也使用它来实现承诺。Angular.js 中的许多服务默认返回类型都是面向承诺的。这包括`$interval`、`$http`和`$timeout`。然而，Angular.js 中有个适当的承诺使用机制。看看下面的代码，了解承诺如何在 Angular.js 中自我映射：

```js
var promise = AngularjsBackground();
promise.then(
  function(response) {
    // promise process 
  },
  function(error) {
    // error reporting 
  },
  function(progress) {
    // send progress

});
```

在 Angular.js 中提到的所有服务都返回一个承诺对象。它们在接收参数方面可能有所不同，但它们都以带有多个键的单个承诺对象作为回应。例如，当你提供四个名为`data`、`status`、`header`和`config`的参数时，`$http.get`返回一个单一对象。

```js
$http.get('/api/tv/serials/sherlockHolmes ')
  .success(function(data, status, headers, config) {
    $scope.movieContent = data;
});
```

如果我们在这里使用承诺的概念，相同的代码将被重写为：

```js
var promise = $http.get('/api/tv/serials/sherlockHolmes ')
promise.then(
  function(payload) {
    $scope.serialContent = payload.data;
});
```

之前的代码比这之前的代码更简洁，也更容易维护，这使得使用 Angular.js 的工程师更容易适应。

# 将回调作为承诺的处理方式

在 Angular.js 中实现承诺定义了您对承诺作为回调处理的使用。实现不仅定义了如何在 Angular.js 中使用承诺，还定义了应采取哪些步骤使服务成为“承诺返回”。这表明您异步地执行某事，一旦您的任务完成，您必须触发`then()`服务，要么结束您的任务，要么将其传递给另一个`then()`方法：`/异步 _ 任务.then().then().done()`。

更简单地说，您可以这样做来实现承诺作为回调的处理方式：

```js
angular.module('TVSerialApp', [])
  .controller('GetSerialsCtrl', 
    function($log, $scope, TeleService) {
      $scope.getserialListing = function(serial) {
        var promise = 
          TeleService.getserial('SherlockHolmes');
        promise.then(
          function(payload) { 
            $scope.listingData = payload.data;
          },
          function(errorPayload) {
            $log.error('failure loading serial', errorPayload);
        });
      };
  })
  .factory('TeleService', function($http) {
    return {

      getserial: function(id) {
        return $http.get(''/api/tv/serials/sherlockHolmes' + id);
      }
    }
  });
```

# 盲目传递参数和嵌套承诺

无论你使用哪个承诺服务，你都必须非常确定你传递了什么，以及这如何影响你的承诺函数的整体工作。盲目传递参数可能会导致控制器混淆，因为它必须处理自己的结果同时处理其他请求。比如说我们正在处理`$http.get`服务，你盲目地给它传递了太多的负载。由于它必须在并行中处理自己的结果，可能会导致混淆，从而可能引发回调地狱。然而，如果你想要后处理结果，你必须处理一个额外的参数，称为`$http.error`。这样，控制器就不用处理自己的结果，像 404 和重定向这样的调用将被保存。

你也可以通过构建自己的承诺并使用以下代码返回你选择的结果和你想要的有效负载来重现前面的场景：

```js
factory('TVSerialApp', function($http, $log, $q) {
 return {
    getSerial: function(serial) {
      var deferred = $q.defer();
      $http.get('/api/tv/serials/sherlockHolmes' + serial)
        .success(function(data) { 
          deferred.resolve({
            title: data.title,
            cost: data.price});
        }).error(function(msg, code) {
            deferred.reject(msg);
            $log.error(msg, code);
        });
        return deferred.promise;
    }
  }
});
```

通过构建自定义承诺，你有许多优点。你可以控制输入和输出调用，记录错误消息，将输入转换为所需的输出，并通过使用`deferred.notify(mesg)`方法共享状态。

# 延迟对象或组合的承诺

由于在 Angular.js 中自定义承诺有时可能难以处理，最坏的情况下可能会出现故障，承诺提供了另一种实现方式。它要求你在`then`方法中转换你的响应，并以一种自主的方式返回转换后的结果给调用方法。考虑我们在上一节中使用的相同代码：

```js
this.getSerial = function(serial) {
    return $http.get('/api/tv/serials/sherlockHolmes'+ serial)
        .then(
                function (response) {
                    return {
                        title: response.data.title,
                        cost:  response.data.price

                    });
                 });
};
```

我们从前面方法中产生的输出将是一个链式、承诺式且转换过的。你再次可以使用输出用于另一个输出，将其链式到另一个承诺，或简单地显示结果。

控制器可以转换为以下代码行：

```js
$scope.getSerial = function(serial) {
  service.getSerial(serial) 
  .then(function(serialData) {
    $scope.serialData = serialData;
  });
};
```

这显著减少了代码行数。同时，这也帮助我们维持了服务级别，因为`then()`中的自动安全机制可以帮助它转换为失败的承诺，并保持其余代码不变。

# 处理嵌套调用

在`success`函数中使用内部返回值时，承诺代码可以感觉到你忽略了一件最明显的事情：错误控制器。缺失的错误可能导致你的代码停止运行或陷入无法恢复的灾难。如果你想克服这个问题，只需抛出错误。怎么做？请看下面的代码：

```js
this.getserial = function(serial) {
    return $http.get('/api/tv/serials/sherlockHolmes' + serial)
        .then(
            function (response) {
                return {
                    title: response.data.title,
                    cost:  response.data.price
                });
            },
            function (httpError) {
                // translate the error
                throw httpError.status + " : " + 
                    httpError.data;
            });
};
```

现在，无论代码进入何种错误情况，它都会返回一个字符串，而不是一串`$http`状态或配置详情。这也可以拯救你的整个代码进入停滞模式，并帮助你在调试。另外，如果你附上了日志服务，你可以精确地定位出错的地点。

# Angular.js 中的并发

我们都希望在单一时间槽中获得最大输出，通过请求多个服务调用并从它们获取结果。Angular.js 通过其`$q.all`服务提供此功能；您可以同时调用许多服务，如果您想要将它们全部或任意组合在一起，您只需要`then()`将它们按照您想要的顺序组合在一起。

首先获取数组的有效载荷：

```js
[ 
  { url: 'myUr1.html' },
  { url: 'myUr2.html' },
  { url: 'myUr3.html' }
]
```

现在这个数组将被以下代码使用：

```js
service('asyncService', function($http, $q) {
     return {
       getDataFrmUrls: function(urls) {
         var deferred = $q.defer();
         var collectCalls = [];
         angular.forEach(urls, function(url) {
           collectCalls.push($http.get(url.url));
         });

         $q.all(collectCalls)
         .then(
           function(results) {
           deferred.resolve(
             JSON.stringify(results)) 
         },
         function(errors) {
           deferred.reject(errors);
         },
         function(updates) {
           deferred.update(updates);
         });
         return deferred.promise;
       }
     };
});
```

通过为每个 URL 执行`$http.get`来创建一个 promise，并将其添加到数组中。`$q.all`函数接受一个 promise 数组的输入，然后将所有结果处理成一个包含每个答案的对象的单个 promise。这将被转换为 JSON 并传递给调用者函数。

结果可能像这样：

```js
[
  promiseOneResultPayload,
  promiseTwoResultPayload,
  promiseThreeResultPayload
]
```

# 成功和错误的组合

`$http`返回一个 promise；您可以根据这个 promise 定义它的成功或错误。许多人认为这些函数是 promise 的标准部分——但实际上，它们并不是看起来那样。

使用 promise 意味着你在调用`then()`。它有两个参数——成功回调函数和失败回调函数。

想象一下这个代码：

```js
$http.get("/api/tv/serials/sherlockHolmes")
.success(function(name) {
    console.log("The tele serial name is : " + name);
})
.error(function(response, status) {
    console.log("Request failed " + response + " status code: " + status);
};
```

这可以重写为：

```js
$http.get("/api/tv/serials/sherlockHolmes")
.success(function(name) {
    console.log("The tele serial name is : " + name);
})
.error(function(response, status) {
    console.log("Request failed " + response + " status code: " + status);
};

$http.get("/api/tv/serials/sherlockHolmes")
.then(function(response) {
    console.log("The tele serial name is :" + response.data);
}, function(result) {
    console.log("Request failed : " + result);
};
```

可以使用`success`或`error`函数，具体取决于情境的选择，但使用`$http`有一个好处——它很方便。`error`函数提供了响应和状态，而`success`函数提供了响应数据。

这并不是 promise 的标准部分。任何人都可以向 promise 添加自己的这些函数版本，如下面的代码所示：

```js
//my own created promise of success function

promise.success = function(fn) { 
    promise.then(function(res) {
        fn(res.data, res.status, res.headers, config);
    });
    return promise;
};

//my own created promise of error function

promise.error = function(fn) {  
    promise.then(null, function(res) {
        fn(res.data, res.status, res.headers, config);
    });
    return promise;
};
```

# 安全方法

所以，讨论的真正问题是与`$http`一起使用什么？成功还是错误？记住，编写 promise 没有标准方式；我们必须考虑许多可能性。

如果您更改代码，使 promise 不是从`$http`返回的，那么当我们从缓存加载数据时，如果您期望成功或错误，您的代码将会断裂。

因此，最佳做法是尽可能使用`then`。这不仅会概括编写 promise 的整体方法，还会减少代码中的预测元素。

# 路由您的 promise

Angular.js 具有路由 promise 的最佳特性。当您同时处理多个 promise 时，这个特性很有帮助。以下是如何通过以下代码实现路由的：

```js
$routeProvider
  .when('/api/', {
      templateUrl: 'index.php',
      controller: 'IndexController'
  })
  .when('/video/', {
      templateUrl: 'movies.php',
      controller: 'moviesController'
  })
```

正如您所观察到的，我们有两个路由：`api`路由带我们到索引页，使用`IndexController`，视频路由带我们到电影页。

```js
app.controller('moviesController', function($scope, MovieService) {  
    $scope.name = null;

    MovieService.getName().then(function(name) {
        $scope.name = name;
    });
});
```

有一个问题，直到`MovieService`类从后端获取名称，该名称是`null`。这意味着如果我们的视图绑定到名称，首先它是空的，然后才设置。

这就是路由器出现的地方。路由器解决了将名称设置为`null`的问题。我们可以这样做到：

```js
var getName = function(MovieService) {  
       return MovieService.getName();
   };

$routeProvider
  .when('/api/', {
      templateUrl: 'index.php',
      controller: 'IndexController'
  })
  .when('/video/', {
      templateUrl: 'movies.php',
      controller: 'moviesController'
  })
```

在添加解析后，我们可以重新访问控制器的代码：

```js
app.controller('MovieController', function($scope, getName) {

    $scope.name = name;

});
```

您还可以为您的承诺定义多个解决方法，以获得最佳可能的输出：

```js
$routeProvider
  .when('/video', {
      templateUrl: '/MovieService.php',
      controller: 'MovieServiceController',
      // adding one resole here
      resolve: {
          name: getName,
          MovieService: getMovieService,
          anythingElse: getSomeThing
      }
      // adding another resole here
       resolve: {
          name: getName,
          MovieService: getMovieService,
          someThing: getMoreSomeThing
      }
  })
```

# 总结

在本章中，我们学习了如何在 Angular.js 中实现承诺，它是如何发展的，以及承诺如何帮助创建为实时网络应用而设计的应用程序。我们还看到了 Q 库的功能以及 Angular.js 中使用承诺的实现代码，并学习了如何在我们下一个应用程序中使用它们。

Angular.js 中承诺的规范非常接近 ECMAScript 6 提出的规范，但是当 Angular.js 完全采用承诺作为自己的规范时，可能会有所变化。它将定义自己的一套规则来使用承诺，这可能与规范本身不同。

在下一章中，我们将探讨如何在 jQuery 中实现承诺，以及将会是怎样的机制以及它将带来哪些好处。


# 第八章：jQuery 中的承诺（Promises）

在上一章中，我们学习了承诺（promises）是如何在 Angular.js 中实现的，以及它们如何在快速发展的实时 Web 应用行业中提供好处的。在本章中，我们将探讨另一个非常著名且实用的 JavaScript 库，用于前端 Web/移动应用开发。

jQuery 是众多常用的 JavaScript 库之一，它被认为是维护性最强、最先进且易于采用的库之一。jQuery 也有助于缩短冗长的代码行，使其变得更简洁、更易理解。这一工具帮助 jQuery 获得了超出想象的普及度。在本章中，我们将回顾 jQuery 的发展历程，它是如何演进的，如何使用它以及承诺（promises）是如何在 jQuery 的成熟过程中发挥作用的。让我们从简要回顾 jQuery 的发展历程开始。

# 它从哪里开始？

在 JavaScript 中编写代码的古典方式相当繁琐。由于该语言没有很多固定的规则，编写出的 JavaScript 代码变得难以实现和修改。开发人员选择函数和变量名称的方式使得简单函数变得不易阅读，因此在类似性质的另一个项目中不值得使用。此外，JavaScript 被认为是计算机世界中第二流的编程语言，因此没有多少人认真使用它。

2006 年 8 月，jQuery 的诞生照亮了 JavaScript 世界。jQuery 的创造者约翰·雷西格（John Resig）在他的博客文章中宣布 jQuery 1.0 正式发布。这是人们开始真正认真对待 JavaScript 并确信其可信度的第一次。虽然 JavaScript 从 90 年代初就已经存在（如第一章所述），但它经历了很多起伏。最终，随着 Firefox 浏览器和 jQuery 的发布，JavaScript 终于获得了一些可信度。

# 幕后 – jQuery 是如何工作的？

jQuery 基于一个简单的原则：写得更少，做得更多。在几行 jQuery 代码中，你将能够完成比传统编写代码方式更多的任务。jQuery 在短时间内使许多任务变得容易完成。它还使代码更整洁、更易读，这在 JavaScript 中是前所未有的。

jQuery 出现后，JavaScript 开始发生了戏剧性的变化。许多新的实现开始出现在屏幕上，采用更加成熟的方法，但 jQuery 获得的地位是无法比拟的，至今仍然如此。

说到这里，让我们回到我们的主题：jQuery 幕后是如何工作的？

一切围绕着美元符号（$）。jQuery 库提供了 jQuery() 函数，该函数允许你像 CSS 选择器一样选择元素。例如：

```js
var itemsList = jQuery query("ul");
```

或者：

```js
var itemsList = $("ul");
```

在前一行中，`$`符号是 jQuery 的表示。在 JavaScript 中，变量名可以是任何东西，但必须不以数字开头，且不能包含连字符。这样使用`$`对于规则来说更方便，也更容易记住。你也可以找到像这样的函数：

```js
window.jQuery = window.$ = jQuery;
```

在这里，`$`符号出现在函数的最后。你会在 jQuery 源代码中注意到同样的情况。

这个机制是当你调用`$()`并给它提供一个选择器时，你实际上正在创建一个新的 jQuery 对象。在 JavaScript 中，函数也是对象，这意味着`$()`不仅嵌入了一个单一的对象，而且它可能包含方法、变量和多个对象。所以，你可以使用`$.support`来获取当前环境的信息，或者你也可以使用`$.ajax`来进行 AJAX 调用以发起 AJAX 请求。

# 你的文档准备好提交了吗？

有时，当你在文档还未完成时提交它，而你不知道它还需要进一步处理，这种情况可能会发生。这样的事件将触发一系列事件，最终使你的页面或应用程序进入服务失败模式。

使用 jQuery，这种情况很少发生，因为它提供了`$(document).ready()`方法，该方法将帮助完成文档的处理。一个简单的例子可以在这里看到：

```js
$(document).ready(function() {
  console.log('ready!');
});
```

函数将执行，并在文档准备好时传递给`.ready()`。我们使用`$(document)`从页面的文档创建一个 jQuery 对象。然后我们在这个对象上调用`.ready()`函数，把它传递给我们想要执行的函数。

# 如何使用 jQuery

正如我们在第七章中看到的，*Angular.js 中的 Promises*，与 Angular.js 相关的文档是链接在 HTML 页面中调用函数的 JavaScript 文件；jQuery 中使用了相同的结构。

jQuery 是一个链接在 HTML 文件开头的 JavaScript 文件。这可以通过两种方式实现：从 Web 上的位置调用文件，或者将 JavaScript 文件下载到你的本地硬盘上然后嵌入代码。无论哪种方式都可以工作，但我们更倾向于从硬盘上使用它。

以下代码行显示了当我们想要从远程位置链接文件时：

```js
<head>
<script src="img/jquery-1.9.min.js"></script>
</head>
```

或者，我们可以将文件下载到我们的本地硬盘上，并像这样更改语法：

```js
<head>
<script src="img/jquery-1.9.min.js"></script>
</head>
```

在这里，`src="js"`表示 JavaScript 文件存在的本地文件夹。

总之，你可以选择使用已经写好的 jQuery，通过在 HTML 文件头部嵌入 URL 来使用它，或者你可以下载它并进行自己的修改。无论哪种方式，你的输出都会在浏览器的屏幕上生成。

# 语法：

jQuery 的真正力量在于其自定义的语法，这将帮助选择 HTML 元素并执行一些操作。它的语法相当直接且容易记住，而且非常整洁。以下是 jQuery 语法的示例：

```js
$(selector).action ()
```

美元符号（`$`）定义了你是否将使用 jQuery，而`selector`查询是用来查找 HTML 元素的，`action`定义将在选定的元素上执行什么类型的操作。

以下是一些使用 jQuery 语法的示例，解释了 jQuery 是如何工作的：

+   `$(this).hide()`：隐藏当前元素

+   `$("p").hide()`：隐藏所有`<p>`元素

+   `$(".test").hide()`：隐藏所有具有`class="test"`的元素

+   `$("#test").hide()`：隐藏具有`id="test"`的元素

这些是 jQuery 提供的成百上千种方法中的几个示例。对于方法和 API 的完整参考，以下是所有 jQuery 需求的链接：[`api.jquery.com/`](https://api.jquery.com/)。

# jQuery 中的缓存

让我们简要讨论一下与 jQuery 相关的缓存，以及作为一个概念的缓存。

缓存的概念与互联网本身一样古老，至少与现代互联网一样古老。开发者使用它来存储重复的数据，以减少服务器调用成本或记住用户与服务器之间的连接。

缓存通过将图像写入并把会话信息发送到用户硬盘上的特殊位置——临时存储，以多种方式提高 web 应用的性能。通常，这个位置是专门在本地硬盘上创建的，专门处理这类数据。

比如说你正在通过浏览器浏览一个在线购物车。在最初的时刻，网站被加载到你的临时记忆中。这包括添加产品的图片和其他元信息，这标志着该特定网站的初始缓存。现在，假设你决定购买一个产品并登录到购物车的用户区域。这将会在一个名为 cookie 的小文本文件中缓存你的信息，该文件持有关于你是谁以及记住你正在与哪个 web 服务器对话的信息。这是一个将你的信息缓存到临时位置的流程，以减少服务器调用，优化导航，并让服务器记住你的身份。

jQuery 在缓存需要缓存的元素方面有什么提供呢？让我们来看看。

jQuery 中的缓存是通过 data 函数提供的，它与你在 jQuery 中调用的任何其他函数相同。这个函数本身允许你将随机数据绑定到随机选择器。大多数开发者使用它来操作 DOM 元素，但它的应用并不仅限于于此。你可以在给定的时间槽内添加多个选择器，以绑定多个引用，因为函数会自动处理；就是这么简单和容易。然而，元素和它们的处理程序是如何保持在内存中的呢？

jQuery 遵循“名称对应值”的方法来编写和处理内存中的元素。其独特之处在于，元素的名称对于许多条目来说可以相同，但它们必须指向不同的 DOM 元素。这样，通过值引用就变得重要了，并且引用特定元素对于使用它的程序来说会更快、更容易遍历。

现在，要向数据函数添加元素，我们将遵循与此类似的语法：

```js
$("#Textbox_").data("im_textbox1", value)
```

从这里，你可以看到我们将选择器与`data()`函数绑定，并在函数内部提供了两个参数作为名称及其相应的值。这样，我们可以绑定尽可能多的选择器来缓存它们。

但是，故事有一个转折。你可以使用`data()`在缓存中写入，但它不会自动删除数据。你必须从临时内存中手动删除它。你可以像这样调用`removeData()`方法：

```js
$("#Textbox_").removeData(value)
```

当然，你可以通过编写某种 cron/定时任务函数来自动化`removeData()`的函数调用。然而，这需要巧妙的工程设计和大量的干燥运行，因为此操作可能会从临时存储中永久删除任何重要数据，所以建议非常谨慎地使用此类定时任务。

总的来说，jQuery 中的缓存是一个基本组成部分，没有它，你无法优化应用程序的流程和数据遍历。使用 jQuery 缓存还可以优化服务器调用的数量，并提高你代码的性能。

# 示例

在我们开始本章的主要内容之前，我们需要了解如何编写可以使用 jQuery 查询的文件。这将使我们更好地理解代码级别的运作，并将使我们能够熟练地在 jQuery 中使用承诺。

让我们从选择器开始。

## 选择器

选择器使我们能够选择和操作 HTML。我们可以使用它们来查找基于它们 ID 的 HTML 元素：类、类型、属性、值等等。这些选择器与 CSS 中的选择器类似，但带有 jQuery 的特色。这里的特色是所有选择器都以美元符号`$`开头，后面跟着圆括号和点，如下面的代码所示：

```js
<!DOCTYPE html>
<html>
   <head>
      <title> Selector in action </title>
      <script src="img/jquery-1.9.0.js"></script>
      <script>
         $(document).ready(function(){
             $("button").click(function(){
                 $("p").hide(); // this will able to select paragraph element from HTML
             });
         });
      </script>
   </head>
   <body>
      <h2>I am a heading </h2> <!-- this is the place from where the  paragraph is selected -->
      <p>I am a paragraph.</p>
      <button>I am a button </button>
   </body>
</html>
```

看看前面的代码。`</script>`标签后面的脚本标签是选择器定义自己并进行请求处理的地方。一旦页面加载完成，它将带有一个按钮说“我是一个段落”，当你点击它时，按钮的名称将从“我是一个段落”更改为“我是一个按钮”。这一切都是在没有页面更改的情况下发生的，因为 jQuery 能够实时地与 HTML 元素交互并在同一页面上显示结果。这是 jQuery 众多开发者每天都在使用的有益特性之一。这种绑定、即时计算是 jQuery 成为许多开发者选择的原因。

## 事件方法

jQuery 有许多事件驱动的接口。当您触发某个事件时，这些接口将被调用。有许多事件，如鼠标点击、鼠标双击、键盘按键、鼠标悬停和触摸。jQuery 使它们变得简单；你只需要写几行代码，其余的处理将由 jQuery 库完成。请看以下示例：

```js
<!DOCTYPE html>
<html>
   <head>
      <script src="img/jquery-1.9.0.js"></script>
      <script>
         $(document).ready(function(){
             $("h1").click(function(){
                 $(this).hide();
             });
         });
      </script>
   </head>
   <body>
      <h1> Click me to make me disappear </h1>
   </body>
</html>
```

当我点击屏幕上出现的文本时，页面会发生什么？有人猜测吗？是的，当我把`h1`标签的值传递给 jQuery 函数时，它会消失，当它感觉到鼠标被点击时，它会隐藏它。这是我们通常在表单或文本区域中玩占位符的方式，但现在，表单已经内置了这种能力。

说了这么多，是时候转向我们章节的重点了。

# jQuery 之前的 JavaScript 和之后的 JavaScript

曾经有一段时间，一个简单的鼠标点击可以通过一个简单的函数`element.onClick = functionName`来捕获。这对当时来说很好，直到另一个想要监听同一个点击事件的函数出现。这个问题通过从 DOM 函数中添加`addListenerEvent`函数来解决。这个函数尽可能多地添加了监听器函数，我们通常采用这种方法。

然而，这样的情况是注定要再次发生的，因为我们现在面临着与 AJAX 调用相同的问题。AJAX 使用一个单一的回调函数，不仅是 jQuery 的`$ajax()`，还有具有类似问题的`XMLHttpRequest`对象。

# 解决方案——在 jQuery 中引入承诺

对于前面问题的解决方案最终在 jQuery 1.5 中以延迟对象的形式提供。在 jQuery 中引入延迟概念之前，典型的 AJAX 调用是这样的：

```js
$.ajax({
  url: "/testURL.com",
  Success: TheSuccessFunction,
  Error: TheErrorFunction
});
```

你能猜出这个函数的输出是什么吗？是的，一个单独的`XMLHttpRequest`对象，这对于那些仍然维护着在 jQuery 1.5 之前构建的应用的人来说是相当预期的。

那么，jQuery 1.5 中引入了什么重大变化呢？首先，它是基于一个 common JavaScript 规范，定义了常见的接口，可以根据需要进行扩展，其次，它们非常全局化，你可以将这些功能用在类似的服务中，比如 Node.js。

在 jQuery 1.5 中添加了延迟对象之后，之前的代码被重写成了这样：

```js
var promise = $.ajax({
  url: "/testURL.com"
});
promise.done(TheSuccessFunction);
promise.fail(TheErrorFunction);
```

如果您想要编写前述代码的更简洁版本，可以按照以下方式实现：

```js
var promise = $.ajax({
  url: "/testURL.com"
});

promise.then(TheSuccessFunction,TheErrorFunction);
```

同样，通过在 jQuery 中引入承诺，带来了许多其他进步。在以下部分中，我们将详细了解 jQuery 是如何实现其承诺的。

# jQuery 中的延迟

像在承诺的任何其他实现中一样，`Deferred`在 jQuery 中也有其重要性和价值。力量在于概念的实现，这是简单而强大的。在 jQuery 中，`deferred`有两个重要的方法，用于与三个重要事件链接以附加回调。这些方法是`resolve`和`reject`，可以附加回调的事件是`done()`、`fail()`和`always()`。让我们通过一个例子来看一下：

```js
<!DOCTYPE html>
<html>
   <head>
      <script src="img/jquery-1.9.0.js"></script>
      <script>
         var deferred = $.Deferred();

         deferred.done(function(value) {
         alert(value);
         });

         deferred.resolve("hello $.deferred ");

      </script>
   </head>
   <body>
      <h1> $.deferred was just displayed </h1>
   </body>
</html>
```

在这里要记住的是，无论`deferred`是否解决，回调总是会被执行，但是当你调用`reject`方法时，失败的回调将被执行。说到这一点，我们前面的例子可以像这样：

```js
<!DOCTYPE html>
<html>
   <head>
      <script src="img/jquery-1.9.0.js"></script>
      <script>
         var deferred = $.Deferred();

         deferred.resolve("hello resolve");

         deferred.done(function(value) {
           alert(value);
         });

      </script>
   </head>
   <body>
      <h1> sample example of Deferred  object.  </h1>
   </body>
</html>
```

如果我们要总结`$.Deferred`对象是什么；我们可以说是只是一个有方法的承诺，这将允许其所有者要么解决要么拒绝它。

# $.Deferred().promise() in jQuery

`Deferred`的闪亮之星之一就是它的承诺。这个方法能做什么？嗯，它返回一个对象，并且几乎与`Deferred`相同的接口。但是，有一个陷阱。它只是为了附加回调，而不是解决或拒绝。

这是一个在某些其他情况下非常有用的功能，比如说你想调用一个 API。这将没有能力解决或拒绝延迟。这样的代码最终会失败，因为这里的承诺没有方法。

尝试执行这段代码，将其保存为`test.html`然后运行文件：

```js
<!DOCTYPE html>
<html>
   <head>
      <script src="img/jquery-1.9.0.js"></script>
      <script>
         function getPromise(){
             return $.Deferred().promise();
         }

         try{
             getPromise().resolve("a");
         }
         catch(err){
         alert(err);
         }
      </script>
   </head>
   <body>
      <h1> you have seen the error.  </h1>
   </body>
</html>
```

你会得到一个错误，像这样：

![$.Deferred().promise() in jQuery](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-prms/img/5500OS_08_01.jpg)

所以，像前面提到的那样，它返回一个对象，并且几乎与`Deferred`相同的接口。然而，它只是为了附加回调，而不是解决或拒绝；这是我们之前谈论的陷阱。现在，我们如何解决它？很简单。你可以将承诺作为另一个函数的返回值；让我们尝试以下代码：

```js
<!DOCTYPE html>
<html>
   <head>
      <script src="img/jquery-1.9.0.js"></script>
      <script>
         var post = $.ajax({
             url: "/localhost/json/", 
             data: {json: JSON.stringify({firstMovieName: "Terminator", secondMovieName: "Terminator 2"})} ,
             type: "POST"
         });

         post.done(function(p){
             alert(p.firstMovieName +  " saved.");
         });

         post.fail(function(){
             alert("error! b/c this URL is not functioning");
         });

      </script>
   </head>
   <body>
      <h1> you have seen the error.  </h1>
   </body>
</html>
```

当你运行前面的代码时，它会在页面的警告对话框中给出一个错误，如果 URL 变量中传递的 URL 是真实的，它不应该这样做。为了理解，让我们假设 URL 是正确的，它保存了值，结果会像这样：

![$.Deferred().promise() in jQuery](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-prms/img/5500OS_08_02.jpg)

前面代码和那一段代码只有一个区别——你可以添加尽可能多的回调，代码的语法干净，因为它显示我们不想在方法中有一个额外的参数。因此，你可以要求 jQuery 中的承诺执行一些操作。

# jQuery 中的承诺投射

在某些情况下，我们只需要显示一个承诺的名字。当您只想查看元素可以是什么或者您想对对象执行哪些操作时，这将非常有用。使用 jQuery，我们可以通过使用`pipe()`函数轻松实现。

考虑这个我们正在投射结果的代码，结果是一个演员：

```js
<!DOCTYPE html>
<html>
   <head>
      <script src="img/jquery-1.9.0.js"></script>
      <script>
         var post = $.post("/echo/json/",
          {
              json: JSON.stringify({firstName: "Arnold", lastName: "Schwarzenegger"})
          }
         ).pipe(function(p){ 
          return "Name Saved >> " + p.firstName + "  " + p.lastName;
         });

         post.done(function(r){ alert(r); });
      </script>
   </head>
   <body>
      <h1> you have seen the result .  </h1>
   </body>
</html>
```

代码的结果将是一个全名，阿诺德·施瓦辛格，在浏览器的警告对话框中显示：

![jQuery 中的承诺投影](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-prms/img/5500OS_08_03.jpg)

如你所见，结果的投影是一个用作对象的演员名字。所以，我们不是一个人 deferred，我们有一个`Name Saved >> Arnold Schwarzenegger`的 deferred。

`pipe`函数也可以用来从方法调用深处返回对象。我们可以挖掘出一个演员的名字和他的 IMDB 评分，如下面的代码所示：

```js
<!DOCTYPE html>
<html>
   <head>
      <script src="img/jquery-1.9.0.js"></script>
      <script>
         function getActorById(customerId){
             return $.post("/echo/json/", {
                     json: JSON.stringify({firstName: "Arnold", lastName: "Schwarzenegger", rating: "8.0"})
             }).pipe(function(p){
                 return p.rating;
             });
         }

         function getRating(rating){
             return $.post("/echo/json/", {
                     json: JSON.stringify({
                         rating: "8.0" })
             }).pipe(function(p){
                 return p.rating;
             });
         }

         function getActorRatingById(id){
             return getActorById)
                    .pipe(getRating);  
         }

         getActorRatingById(123)
             .done(function(a){
                 alert("The rating of Actor is " + a); 
             });

      </script>
   </head>
   <body>
      <h1> you have seen the result .  </h1>
   </body>
</html>
```

当你运行这段代码时，它将在浏览器上给你一个警告输出，看起来像这样：

![jQuery 中的承诺投影](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-prms/img/5500OS_08_04.jpg)

借助`pipe()`方法，我们将深入探讨回调和在传递给函数`getActorById()`时正确参数的传递；我们能够得到我们期望的结果显示。类似地，你也可以在回调内部使用`pipe()`来拒绝`deferred`。

使用`pipe`的另一种方法是递归 deferred。比如说，你在 API 调用的后端有一个异步操作，你需要轮询所有的响应集合才能使用它们。你可以请`pipe()`帮助你。

考虑以下代码，这将帮助收集 API 响应并让你知道是否已经收集了所有的响应：

```js
<!DOCTYPE html>
<html>
   <head>
      <script src="img/jquery-1.9.0.js"></script>
      <script>
         function getStatus(){
             var d = $.Deferred();
             $.post(
                 "/echo/json/",
                 {
                     json: JSON.stringify( {status: Math.floor(Math.random()*4+1)} ),
                     delay: 1
                 }
             ).done(function(s){
                 d.resolve(s.status);
             }).fail(d.reject); 
             return d.promise();
         }

         function pollApiCallDone(){
             //do something
             return getStatus()
                     .pipe(function(s){
                         if(s === 1 || s == 2) {
                             return s;  
                         }

                         return pollApiCallDone();
                     });
         }

         $.blockUI({message: "Please wait while we are  Loading the results"});

         pollApiCallDone()
             .pipe(function(s){ 
                     switch(s){
                     case 1:
                         return "completed";
                     case 2:
                         return "not completed";
                     }  
             })
             .done(function(s){
                 $.unblockUI();
                 alert("The status of collection of API call is   >>> " + s);
             });

      </script>
   </head>
   <body>
      <h1> you have seen the result .  </h1>
   </body>
</html>
```

请注意，我们没有为计算结果提供任何硬编码值，而是每次刷新时使用`math.random()`来计算结果。这只是一个机制，你可以用它来轮询数据，验证它，然后按需使用。

所以，我们看到了`pipe()`方法在编写整洁和可维护的代码方面的好处。这也让我们看到了我们如何在较长的时间内使用`deferred`，同时仍然在 jQuery 的庇护下。

# 使用$.when 联合承诺

`$.when`是另一个可以接受多个承诺并返回一个主 deferred 对象的方法。这个主对象可以在所有承诺都被解决时解决，或者如果任何承诺被拒绝，它将被拒绝。你可能有一个序列，如`when().then().done()`，或者你可以添加多个`when()`方法，后面跟着`then()`和`done()`。

让我们来看一个用`$when()`的代码示例：

```js
<!DOCTYPE html>
<html>
   <head>
      <script src="img/jquery-1.9.0.js"></script>
      <script>
         function getActorByRating(id){
         var d = $.Deferred();
         $.post(
           "/echo/json/",
           {json: JSON.stringify({firstName: "Arnold", lastName: "Schwarzenegger", rating: "8.0"})}
         ).done(function(p){
           d.resolve(p);
         }).fail(d.reject); 
         return d.promise();
         }

         function getActorById(rating){
         return $.post("/echo/json/", {
               json: JSON.stringify({
                   rating: "8.0"})
         }).pipe(function(p){
           return p.rating;
         });
         }

         $.when(getActorByRating(123), getActorById("123456789"))
         .done(function(person, rating){
           alert("The name is " + person.firstName + " and the rating is " + rating);
         });
      </script>
   </head>
   <body>
      <h1> you have seen the result .  </h1>
   </body>
</html>
```

当你执行前面的代码时，它将生成如下输出：

![使用$.when 联合承诺](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js-prms/img/5500OS_08_05.jpg)

注意，在代码的最后，`$.when`函数返回一个新的主 deferred 对象，我们在一个`done()`回调中使用了两个结果。

我们还改变了`getActorByRating()`方法，因为 AJAX 调用的承诺，包含内容负载，在结果中的第一个元素以及状态代码。

然而，这并不是结束；你也可以用`$.when`和管道使用。让我们看看：

```js
<!DOCTYPE html>
<html>
   <head>
      <script src="img/jquery-1.9.0.js"></script>
      <script>
         function getActor(id){
           var d = $.Deferred();
           $.post(
               "/echo/json/",
               {json: JSON.stringify({firstName: "Arnold", lastName: "Schwarzenegger", rating: "8.0"})}
           ).done(function(p){
               d.resolve(p);
           }).fail(d.reject); 
           return d.promise();
         }

         function getPersonByRating(rating){
           return $.post("/echo/json/", {
                   json: JSON.stringify({
                       rating: "8.0" })
           }).pipe(function(p){
               return p.rating;
           });
         }

         $.when(getActor(123), getPersonByRating("123456789"))
           .pipe(function(person, rating){
               return $.extend(person, {rating: rating});
           })
           .done(function(person){
               alert("The name is " + person.firstName + " and the rating is " + person.rating);
           });

      </script>
   </head>
   <body>
      <h1> you have seen the result .  </h1>
   </body>
</html>
```

从之前的代码中，你可以很容易地看出`when()`和`pipe()`是如何组合在一起产生结果的。通过总结之前的代码，我们可以认为我们代码的顺序就像`when()`、`pipe()`和`done()`。`done()`方法是最后一个里程碑，它已经编译并在我们的屏幕上展示了结果。

我们也可以将`when()`用作操作符。记住在 JavaScript 中，每个方法都可以是一个变量。让我们看看如何使用这段代码：

```js
<!DOCTYPE html>
<html>
   <head>
      <script src="img/jquery-1.9.0.js"></script>
      <script>
         function getActor(id){
           var d = $.Deferred();
           $.post(
               "/echo/json/",
               {json: JSON.stringify({firstName: "Arnold", lastName: "Schwarzenegger", rating: "8.0"}),
                delay: 4}
           ).done(function(p){
               d.resolve(p);
           }).fail(d.reject); 
           return d.promise();
         }

         function getActorByRating(rating){
           return $.post("/echo/json/", {
                    json: JSON.stringify({
                                   rating: "8.0"
                                    }),
                    delay: 2
           }).pipe(function(p){
               return p.rating;
           });
         }

         function load(){
           $.blockUI({message: "Loading..."});
           var loading = getActor(123)
              .done(function(c){
                  $("span#firstName").html(c.firstName)
              });

           var loadingRating = getActorByRating("8.0")
               .done(function(rating){
                   $("span#rating").html(rating)
                                   });

           $.when(loading, loadingRating)
            .done($.unblockUI);
         }

         load();

      </script>
   </head>
   <body>
      <h1> you have seen the result .  </h1>
   </body>
</html>
```

所以从之前的代码中，你可以清楚地看到我们如何以多种不同的方式使用`when()`。我们可以通过添加更多实现和解决复杂问题的最佳案例来增加它的多样性。

# 你自己的$.Deferred 过程

你可以根据需要自定义 deferred 对象。这很简单，可以通过调用`jQuery.Deferred()`方法来实现。我们还可以定义自己的流程和流动顺序，并按需安排输出。我们可以使用`setInterval()`来设置延迟，并使用`setTimeout()`来决定何时结束序列。变量声明的范围决定了 deferred 对象是本地处理还是全局处理。如果 deferred 对象被分配给一个局部变量，我们可以调用 deferred 对象的`resolve()`、`promise()`和`notify()`事件。

让我们来看看这个例子：

```js
var myCustomPromise = process();
myCustomPromise.done(function() {
    $('#result').html('done.');
});
myCustomPromise.progress(function() {
    $('#result').html($('#result').html() + '.');
});

function process() {
    var deferred = $.Deferred();

    MyTimerCall = setInterval(function() {
        deferred.notify();
    }, 1000);

    setTimeout(function() {
        clearInterval(MyTimerCall);
        deferred.resolve();
    }, 10000);

    return deferred.myCustomPromise();
}
```

所以，从之前的代码中，我们能够实现一个流程的骨架。这可以通过使其更简洁，或者通过添加一些组合方法，如`then()`、`when()`等来简化。

让我们来看看这段紧凑的代码：

```js
var MyTimerCall;

(function process() {
  $('#result').html('waiting…');
  var deferred = $.Deferred();

  MyTimerCall = setInterval(function() {
    deferred.notify();
  }, 1000);

  setTimeout(function() {
     clearInterval(MyTimerCall);
     deferred.resolve();
  }, 10000);

  return deferred.promise();
})().then(function() { $('#result').html('done.'); },
        null,
        function() { $('#result').html($('#result').html() + '.'); });
```

这样更加简洁，易于扩展。这一节的学习要点是，你也可以选择 jQuery 中的自定义 deferred。它简单、可维护，并且可以根据你的需要进行扩展。

# jQuery 中的 promise 的出现

到目前为止，我们已经学习了如何在 jQuery 中使用 promise，什么是 deferred 对象，以及如何使用这个概念来实现某些任务。为什么要使用它？答案很简单，它有很多能力来最大化我们的输出，并在更短的时间内构建应用程序。然而，它实际上能为我们做什么呢？让我们来看看。

我们可以调用`done()`和`fail()`函数无数次，每次都可以有不同的回调。也许我们有一个回调函数可以停止我们的动画，或者一个执行新 AJAX 调用的函数，等等：

```js
var promise = $.ajax({
  url: "/echo/"
});

promise.done(StopFadeFunction);
promise.done(FormAjaxFunction);
promise.done(ShowIErrorFunction);
promise.fail(GetErrorFunction);
```

无论 AJAX 调用是否完成，我们仍然可以调用`done()`和`fail()`函数，回调立即执行。所以，声明的变量并不是什么大问题。当调用完成后，它将最终进入成功状态或失败状态，并且这个状态不会改变。

我们可以组合 promise。比如说，我们需要同时执行两个 AJAX 调用，并且需要在两者都成功完成后执行一个函数，如下面的代码所示：

```js
$.when() function.
var promise1 = $.ajax("/echo1");
var promise2 = $.ajax("/echo2");
$.when(promise1, promise2).done(function(Obj1, Obj2) {
  // place object handler here
});
```

从 jQuery 1.8 开始，我们可以连续地链式调用`then()`函数：

```js
var promiseOne = $.ajax("/echo1");

function getSomthing () {
    return $.ajax("/echo2");
}
promiseOne.then(getSomthing).then(function(customeServerScript){
    // Both promises are resolved
});
```

# 总结

所以，随着这一章的结束，让我们回顾一下我们迄今为止所涵盖的主题。

我们已经看到了 jQuery 是如何开始成形的，以及它是如何成为现代网页开发的一个基本元素。我们已经学会了如何构建基本的 jQuery 文档以及如何调用嵌入 HTML 文件中的函数。我们已经了解了为什么我们开始在 jQuery 中使用延迟和承诺，以及它是如何帮助我们实现基于网络平台和便携设备的尖端应用程序的。我们已经看到了许多工作示例，以更好地理解并澄清任何疑问。jQuery 中的承诺主题非常庞大，但我们试图尽可能地总结，为那些之前没有使用过这个属性的人打下坚实的基础，并帮助那些已经开始使用它的人。

在下一章中，我们将了解如何将所有结合的 JavaScript 及其属性整合在一起，以使世界变得更紧密，并在未来使我们的生活变得更容易。


# 第九章：JavaScript - 未来已来

在之前的章节中，我们重点关注了如何精通地将承诺的概念应用于不同的 JavaScript 库，以及如何在未来的项目中取得最大的优势。然而，这不仅仅是关于 JavaScript。

尽管承诺很大，它们的实现可以带来许多好处，但这不是 JavaScript 的终点。实际上，JavaScript 在未来几年里能给我们带来比我们能想到的更多的东西。它是现代时代的进步语言，并且其受欢迎程度日益增加。JavaScript 还能给我们提供什么？我们将在本章中尝试找出答案。

让我们从 ECMAScript 6 开始。

# ECMAScript 6（ECMA 262）

ECMAScript 语言规范已进入第六版。自从其第一个版本于 1997 年发布以来，ECMAScript 已成为世界上广泛采用的一般目的编程语言之一。它以其能够嵌入自身到网络浏览器中以及其能够使用服务器端和嵌入式应用程序的能力而闻名。

许多人认为第六版是自 1997 年 ECMAScript 成立以来最详细、最广泛涵盖的更新。

我们将讨论 ECMA 262 的第六版；这是一个草案版本，旨在更好地支持大型应用、库的创建，以及将 ECMAScript 作为其他语言的编译目标。

# harmony:generators

`harmony:generators`是一等公民面包丁，将作为对象表示，这将封装悬挂的执行上下文（即，函数激活）。到目前为止，这些仍在审查中，可能会发生变化，所以我们只是考虑这些以获得关于它们的知识。

几个高级示例将有助于更好地理解一旦获得批准后和谐形状会是什么样子。

由于这些是未经批准的草案，我们将使用来自 ECMAScript 母网站的示例。

本节中将使用的参考代码可以在[`wiki.ecmascript.org/doku.php?id=harmony:generators`](http://wiki.ecmascript.org/doku.php?id=harmony:generators)找到。

## 斐波那契数列

斐波那契数的“无限”序列是：

```js
Function* Fibonacci () {
    let [prev, curr] = [0, 1];
    For (;;) {
        [prev, curr] = [curr, prev + curr];
        yield curr;
    }
}
```

生成器可以在循环中迭代：

```js
for (n of fibonacci()) {
    // truncate the sequence at 1000
    if (n > 1000)
        break;
    print(n);
}
```

生成器如以下代码所示是迭代器：

```js
let seq = fibonacci();
print(seq.next()); // 1
print(seq.next()); // 2
print(seq.next()); // 3
print(seq.next()); // 5
print(seq.next()); // 8
```

前面的片段是非常高级的语法，它们很可能会被修改。生成器将是和谐的关键元素和显著添加，但完全实现它们需要时间。

# MEAN 栈

尽管 MEAN 堆栈不是一个新概念，但它为我们提供了 JavaScript 的一切基础。它提供了基于 Node.js 的 JavaScript 基础网络服务器，基于 MongoDB 的数据库，其中也使用 JavaScript 作为核心语言，Express.js 作为 Node.js 网络应用程序框架，以及 Angular.js 作为可以让你以更先进、更现代的方式扩展 HTML 的前端元素。

这些概念已经存在一段时间，但它们有超越想象的潜力。想象一个全面规模的金融应用程序，或者一个基于 MEAN 堆栈的整个银行系统，或者控制工业。硬件将利用这个堆栈的服务，但这种情况将在不久的将来发生，现在还不晚，但仍需要时间来完全实施这个堆栈。

我之所以这样说，是因为企业界仍然不愿意采用 MEAN 标准或向其过渡，原因是这些开源产品的成熟度和财务支持水平。此外，他们还需要升级现有的基础设施。无论出于什么原因，当今的网络应用程序都大量使用这个堆栈来编写轻量级和可扩展的应用程序。让我们把 MEAN 堆栈作为 JavaScript 未来的第一个项目。

# 实时通信在 JavaScript 中

另一个被认为将是 JavaScript 未来的强大功能是两个套接字之间的实时通信。在 JavaScript 之前，套接字编程已经存在很长时间，以至于每种主要编程语言都有其使用套接字读写数据的版本，但与 JavaScript 相比，这还是一个需要在这个阶段做大量工作的新概念。有几种方法可以在 JavaScript 中实现实时套接字编程，但目前最成熟的方法是使用 Socket.IO。

它基本上实现了一种双向基于事件的实时通信，从而使两个实体之间的通信成为可能。它支持各种平台，包括网络浏览器、便携式设备、移动设备以及具有通信功能的其他任何设备。它的实施相当容易且可靠，具有高质量和高速度。

我们能用这个实现什么？嗯，可能性很多，这取决于你如何尝试基于 Socket.IO 提供的支持。在这一点上，你可以为企业智能或市场预测或趋势识别编写实时分析，或者你可以使用它的二进制流功能，从地球的一部分实时流媒体传输到另一部分，或者你可以用它来远程监控你的场所。所有这些实施方法现在已经可用，通过聪明地使用这些功能，这些想法可以变为现实。

结论是 Socket.IO 是您可以依赖的最健壮的实时通信库之一。从当前趋势来看，我们可以有把握地说，设备之间的实时通信可能是 JavaScript 在未来最大的优势之一。这并不一定必须通过 Socket.IO 实现；任何有潜力的库都将占据主导地位。这是关于 JavaScript 在未来几年将如何给我们留下深刻印象的概念。

# 物联网

不久前，硬件与设备和机器的接口还只限于某些成熟和发达的编程语言，没有人会考虑 JavaScript 能否与这些成熟语言站在同一条线上。这种现状局限于 C++或 Java 或其他高级语言，但这种情况已经不再存在了。

随着对 JavaScript 的关注，开发者和工程师们现在正试图在硬件接口中使用 JavaScript 的力量。他们通过编写智能代码和使用已经使用某种程度通信的库来克服 JavaScript 的问题。

这样一个努力叫做树莓派。我们来谈谈树莓派及其目的，然后我们再看看 JavaScript 是如何使用它的。

树莓派是一种设计简单的信用卡式计算机，用于以非常简单和有效的方式学习编程。它带有一个你可以称之为没有外设连接的计算机的主板。你必须连接鼠标、键盘和屏幕才能使其运行。它有一个安装在 SD 卡上的操作系统，可供实验使用。这是一种便携式设备，你可以连接任何设备，或者使用它编程其他设备。它拥有计算机必须具备的所有基本元素，但以非常简单、便携和易于处理的方式实现。

现在，JavaScript 与树莓派有什么关系呢？嗯，JavaScript 现在无处不在，所以它的实现也已经开始了，使用 Pijs.io 为树莓派提供支持。

就像你可以用其他任何语言为树莓派编写代码一样，你也可以使用 JavaScript 为你的手持计算机编写应用程序。这个 JavaScript 库将允许你使用 JavaScript 与硬件交互并为你的需求编程设备。你可以查看该库在[`pijs.io/`](http://pijs.io/)。

如前所述，硬件接口不仅限于树莓派；其他任何实施方法都必须做同样的事情。这些线路的核心是展示 JavaScript 变得多么强大以及它被广泛接受的程度。现在，人们正在考虑用它来编程他们的设备，无论这些设备属于他们的日常使用还是商业使用。JavaScript 在计算机硬件接口方面的未来非常光明，并且正在快速增长。

# 计算机动画和 3D 图形

1996 年，在一部革命性的电影《玩具总动员》中，引入了一个全新的概念**计算机生成的图像**（**CGI**）。这部电影在动画和计算机图形方面树立了新的标准。这部电影的成功不仅仅是因为它的剧本，还得益于用来建造它的技术。

在当前时代，计算机动画领域从许多方面得到了发展，并且仍在以快速的速度增长。那么 JavaScript 与所有这些进展有什么关系呢？嗯，JavaScript 前所未有的准备好通过 Web 在计算机动画和 3D 图形中发挥作用。

WebGL 是一个开源的 JavaScript API，用于渲染 2D 和 3D 图像和对象。WebGL 的力量在于它通过采用浏览器及其引擎的标准，扩展到几乎每一个浏览器。它非常适应性强，可以用于任何现代网络浏览器渲染所需的图像。

凭借 WebGL，现在可以编写无需额外插件即可运行的互动性和尖端游戏。它还将在未来帮助我们在浏览器中看到动画计算机建模，而不是使用沉重、昂贵且庞大的软件。它还将帮助我们在移动中可视化信息。所以，你可以看到股价上涨和下跌对其他你投资过的股票的影响。

到目前为止，WebGL 已经得到了包括苹果的 Safari、微软的 IE 11 及其后续版本 Edge 浏览器、谷歌的 Chrome 浏览器以及 Mozilla 的 Firefox 在内的所有行业关键角色的支持。另外，请注意，WebGL 是 Mozilla 的 Vladimir Vukićević的创意，他在 2011 年发布了其初始版本。

我们可以得出结论，JavaScript 已经在动画和 3D 图形领域播下了种子，在不久的将来，这不仅有助于 JavaScript 获得信任，还将使许多开发者和工程师在面对当前语言包的限制时，能够更容易地学习新的语言。有了统一的语言，输出的应用程序将更有趣。

# NoSQL 数据库

曾经有一段时间，了解关系数据库管理系统（RDBMS）是所有开发者的必备知识，特别是那些从事数据库驱动应用程序开发的人。人们期望你了解主键是什么，连接是什么，如何规范化数据库，以及实体-关系图是什么。然而，这种情况正在逐渐消失，在今天的世界中，一个新的概念 NoSQL 正在兴起，其中大量数据驱动的应用程序仍在使用。

在前进之前，让我们谈谈为什么工程师们正在关注非关系型数据库（RDBMS）技术。原因很简单。数据驱动的应用程序以惊人的方式增长，它们在每天的每个小时都在全球产生数以 terabytes 的数据。处理这些数据并获得所需的结果并非易事。**数据库管理员**（**DBAs**）编写一个查询并执行它，从分布式的数据库存储库中获取数据，他们必须等待几小时才能知道结果是否显示在他们的屏幕上，或者由于操作符放置不当而使所有努力付之东流。这是由于 RDBMS 的设计方式，但在当今的现代世界中，这种延迟和计算时间会让你付出巨大的代价和声誉。

那么还有其他选择吗？非关系型数据库！在本章的前一部分，我们已经看到 MongoDB 在 MEAN 堆栈中发挥了关键作用。然而，在这里再给 MongoDB 多写几行是值得的，因为它是我们在 JavaScript 未来增长方面的候选人。

那么 MongoDB 是什么呢？它是一个面向文档的非关系型数据库，具有跨平台的适应性，支持类似于 JSON 的文档。截至 2015 年 2 月，它是世界上第四受欢迎的数据库管理系统，被认为是世界上最受欢迎的数据存储。

我们为什么把 MongoDB 列入我们未来 JavaScript 增长的候选人名单中呢？仅仅因为它基于 JavaScript，你可以在其控制台中用纯 JavaScript 编写脚本。这使得它成为一种基于 JavaScript 的高度可适应的数据库技术。它的发展方式不仅会取代当前的 RDBMS 场景，而且与 MEAN 堆栈的其他部分或硬件接口或网络或与 Socket.IO 结合时，也会产生奇妙的效果。

无论以何种形式，MongoDB 都将帮助其余的应用程序在未来增长，并将现有的 RDBMS 转变为更易于访问和快速响应的引擎。

# 总结

在本章中，我们了解到 JavaScript 是一个改变游戏规则的语言，它有着光明的未来。JavaScript 具有巨大的潜力和适应性，这将成为计算机科学几乎所有领域下一个级别的使用。可能性是无限的，天空是 JavaScript 的极限。在不久的将来，由于其适应性、接受度以及成千上万的开发者和坚定承诺的大型软件公司的贡献，JavaScript 将主导其他编程语言。

至此，我们结束了这本书。

让我们回顾一下在这本书中学到的内容。在开始时，我们深入探讨了 JavaScript 是什么以及它的起源，JavaScript 的结构以及不同浏览器是如何使用它的。我们还看到了不同的编程模型以及 JavaScript 正在使用的模型。

然后，我们的旅程转向了本书的核心——Promises.js。我们学到了很多关于承诺基本知识，这使我们走向了这个概念的高级用法。我们接着从不同的技术角度了解了它，并展示了代码以消除任何模糊之处。

所以，总的来说，这本书不仅关于 JavaScript 中的承诺，而且涵盖了 JavaScript 和承诺的历史、实现和用法。有了这本书，你不仅可以成为承诺的大师，还可以保持独特的理解水平，从而以更多、更亮的方式实现这个概念。

学习愉快！
