# NodeJS MongoDB Web 开发（三）

> 原文：[`zh.annas-archive.org/md5/2FC862C6AE287FE2ADCD470958CE8295`](https://zh.annas-archive.org/md5/2FC862C6AE287FE2ADCD470958CE8295)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：创建一个 RESTful API

现在你的应用程序已经完成并准备好展示给世界，你可以开始考虑让它变得更受欢迎。如果你想允许外部系统以一种方式访问你的数据，使它们可以大规模地向你的网站插入数据，而不需要用户访问实际的网站呢？

一个几乎立刻想到的例子是，另一个网站的用户，比如[www.facebook.com](http://www.facebook.com)，可以上传一张图片到 Facebook，并且它会自动上传到你的网站上。

使这种情景成为可能的唯一方法是**通过**提供一个 API 给你的数据，并且给外部开发者访问一套工具的代码，使他们可以执行操作而不需要与实际的网页进行交互。

在这一章中，我们将回顾以下主题：

+   介绍 RESTful API

+   安装一些基本工具

+   创建一个基本的 API 服务器和示例 JSON 数据

+   响应`GET`请求

+   使用`POST`和`PUT`更新数据

+   使用`DELETE`删除数据

+   从 Node.js 消费外部 API

# 什么是 API？

**应用程序编程接口**（**API**）是一个系统提供的一组工具，使不相关的系统或软件有能力相互交互。通常，当开发人员编写将与封闭的外部软件系统交互的软件时，他们会使用 API。外部软件系统提供 API 作为所有开发人员可以使用的一套标准工具。许多流行的社交网络网站提供开发人员访问 API 的权限，以构建支持这些网站的工具。最明显的例子是 Facebook 和 Twitter。它们都有一个强大的 API，为开发人员提供了直接处理数据和构建插件的能力，而不需要被授予完全访问权限，作为一般的安全预防措施。

正如你在本章中所看到的，提供自己的 API 不仅相当简单，而且还赋予你提供用户访问你的数据的权力。你还可以放心地知道，你完全控制着你可以授予的访问级别，你可以使哪些数据集只读，以及可以插入和更新哪些数据。

# 什么是 RESTful API？

**表述性状态转移**（**REST**）是一种通过 HTTP 进行 CRUD 的花哨方式。这意味着，当你使用 REST API 时，你有一种统一的方式，使用简单的 HTTP URL 和一组标准的 HTTP 动词来创建、读取和更新数据。REST API 的最基本形式将在 URL 上接受 HTTP 动词之一，并作为响应返回某种数据。

通常，REST API 的`GET`请求总是会返回某种数据，比如 JSON、XML、HTML 或纯文本。对 RESTful API URL 的`POST`或`PUT`请求将接受数据以创建或更新。RESTful API 的 URL 被称为端点，当使用这些端点时，通常说你在消费它们。在与 REST API 交互时使用的标准 HTTP 动词包括：

+   `GET`：这是检索数据

+   `POST`：这是提交新记录的数据

+   `PUT`：这是提交数据以更新现有记录

+   `PATCH`：这是提交日期以更新现有记录的特定部分

+   `DELETE`：这会删除特定记录

通常，RESTful API 端点以一种模仿数据模型并具有语义 URL 的方式进行定义。这意味着，例如，要请求模型列表，你将访问`/models`的 API 端点。同样，要通过其 ID 检索特定模型，你将在端点 URL 中包含它，如`/models/:Id`。

一些示例 RESTful API 端点 URL 如下：

+   `GET http://myapi.com/v1/accounts`：这将返回一个账户列表

+   `GET http://myapi.com/v1/accounts/1`：这将返回一个单一账户

通过`Id: 1`

+   `POST http://myapi.com/v1/accounts`：这将创建一个新账户

（数据作为请求的一部分提交）

+   `PUT http://myapi.com/v1/accounts/1`: 这将更新现有的帐户

通过`Id: 1`提交的帐户（作为请求的一部分提交的数据）

+   `GET http://myapi.com/v1/accounts/1/orders`: 这将返回帐户`Id: 1`的订单列表

+   `GET http://myapi.com/v1/accounts/1/orders/21345`: 这将返回帐户`Id: 1`的单个订单的详细信息，订单`Id: 21345`

URL 端点匹配此模式并不是必需的；这只是常见的约定。

# 介绍 Postman REST Client

在开始之前，有一些工具可以使您在直接使用 API 时更加轻松。其中一个工具就是称为 Postman REST Client 的工具，它是一个可以直接在浏览器中运行或作为独立的打包应用程序运行的 Google Chrome 应用程序。使用此工具，您可以轻松地向任何您想要的端点发出任何类型的请求。该工具提供了许多有用且强大的功能，非常易于使用，而且最重要的是，免费！

# 安装说明

Postman REST Client 可以以两种不同的方式安装，但都需要安装并在您的系统上运行 Google Chrome。安装该应用程序的最简单方法是访问 Chrome 网络商店[`chrome.google.com/webstore/category/apps`](https://chrome.google.com/webstore/category/apps)。

搜索 Postman REST Client，将返回多个结果。有常规的 Postman REST Client，它作为内置到浏览器中的应用程序运行，还有一个单独的 Postman REST Client（打包应用程序），它作为独立应用程序在您的系统中运行，并在自己的专用窗口中运行。继续安装您的首选项。如果您将应用程序安装为独立的打包应用程序，将会在您的停靠栏或任务栏上添加一个启动图标。如果您将其安装为常规浏览器应用程序，可以通过在 Google Chrome 中打开一个新标签页，转到应用程序，并找到 Postman REST Client 图标来启动它。

安装并启动应用程序后，您应该看到类似以下截图的输出：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/webdev-mongo-node/img/e209a66f-205d-4b6f-9152-451bac3c6017.png)

# Postman REST Client 的快速介绍

使用 Postman REST Client，我们能够向任何我们想要的端点提交 REST API 调用，以及修改请求的类型。然后，我们可以完全访问从 API 返回的数据，以及可能发生的任何错误。要测试 API 调用，请在“在此输入请求 URL”字段中输入您最喜欢的网站的 URL，并将其旁边的下拉菜单保留为`GET`。这将模仿您访问网站时浏览器执行的标准`GET`请求。单击蓝色的发送按钮。请求被发送，并且响应显示在屏幕的下半部分。

在下面的截图中，我向[`kroltech.com`](http://kroltech.com)发送了一个简单的`GET`请求，并返回了 HTML。 

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/webdev-mongo-node/img/031838ab-08cc-417a-953b-2e7e02b08ead.png)

如果我们将此 URL 更改为我的网站的 RSS 源 URL，您可以看到返回的 XML：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/webdev-mongo-node/img/1a46abbf-4451-4c57-88c8-da53ae7b65ac.png)

XML 视图具有更多功能，因为它公开了右侧的侧边栏，让您一览 XML 数据的树结构。不仅如此，您现在还可以看到我们迄今为止所做的请求的历史记录，沿左侧边栏。当我们执行更高级的`POST`或`PUT`请求并且不想在测试端点时重复数据设置时，这将非常有用。

这是一个示例 API 端点，我向其提交了一个`GET`请求，返回其响应中的 JSON 数据：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/webdev-mongo-node/img/73ef80fc-6eaa-45f2-a52d-d7113694ca57.png)

使用 Postman Client 向返回 JSON 的端点发出 API 调用的一个非常好的功能是，它以非常好的格式解析和显示 JSON，并且数据中的每个节点都是可展开和可折叠的。

这个应用程序非常直观，所以确保你花一些时间玩耍和尝试不同类型的调用不同的 URL。

# 使用 JSONView 谷歌浏览器扩展程序

还有一个工具我想和你谈谈（虽然非常小），但实际上是一个非常重要的事情。`JSONView` 谷歌浏览器扩展程序是一个非常小的插件，它将立即通过浏览器将任何 `JSONView` 直接转换为更可用的 JSON 树（就像在 Postman 客户端中一样）。这是在安装 `JSONView` 之前指向返回 JSON 的 URL 的示例：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/webdev-mongo-node/img/25cb7b1f-43fd-4a44-9381-869432df87ec.png)

在安装了 `JSONView` 之后，这就是相同的 URL：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/webdev-mongo-node/img/fb010a96-c449-4d0d-8ea3-fb00adeb656e.png)

你应该像安装 Postman REST Client 一样安装 `JSONView` 谷歌浏览器扩展程序：访问 Chrome 网上应用店，搜索 `JSONView`。

现在你已经有了能够轻松处理和测试 API 端点的工具，让我们来看看如何编写自己的端点并处理不同的请求类型。

# 创建一个基本的 API 服务器

让我们使用 Express 创建一个超级基本的 Node.js 服务器，我们将使用它来创建我们自己的 API。然后，我们可以使用 Postman REST Client 发送测试到 API，看看它是如何工作的。在一个新的项目工作空间中，首先安装我们需要的 `npm` 模块，以便让我们的服务器运行起来：

```js
    $ npm init
    $ npm install --save express body-parser underscore
```

现在，这个项目的 `package.json` 文件已经初始化并安装了模块，让我们创建一个基本的服务器文件来引导 Express 服务器。创建一个名为 `server.js` 的文件，并插入以下代码块：

```js
const express = require('express'), 
    bodyParser = require('body-parser'), 
    _ = require('underscore'), 
    json = require('./movies.json'), 
    app = express(); 

app.set('port', process.env.PORT || 3500); 

app.use(bodyParser.urlencoded({ extended: false })) 
app.use(bodyParser.json()); 

let router = new express.Router(); 
// TO DO: Setup endpoints ... 
app.use('/', router); 

const server = app.listen(app.get('port'), ()=>{ 
    console.log(`Server up: http://localhost:${app.get('port')}`); 
}); 
```

这对你来说应该看起来很熟悉。在 `server.js` 文件中，我们引入了 express、body-parser 和 underscore 模块。我们还引入了一个名为 `movies.json` 的文件，接下来我们将创建它。

在我们引入模块之后，我们使用最少量的配置来设置 Express 服务器的标准配置，以支持 API 服务器所需的最少配置。请注意，我们没有设置 Handlebars 作为视图渲染引擎，因为我们不打算使用这个服务器来渲染任何 HTML，只是纯粹的 JSON 响应。

# 创建示例 JSON 数据

让我们创建一个临时数据存储的示例 `movies.json` 文件（尽管我们为了演示目的构建的 API 实际上不会在应用程序的生命周期之外保留数据）：

```js
[{ 
    "Id": "1", 
    "Title": "Aliens", 
    "Director": "James Cameron", 
    "Year": "1986", 
    "Rating": "8.5" 
}, 
{ 
    "Id": "2", 
    "Title": "Big Trouble in Little China", 
    "Director": "John Carpenter", 
    "Year": "1986", 
    "Rating": "7.3" 
}, 
{ 
    "Id": "3", 
    "Title": "Killer Klowns from Outer Space", 
    "Director": "Stephen Chiodo", 
    "Year": "1988", 
    "Rating": "6.0" 
}, 
{ 
    "Id": "4", 
    "Title": "Heat", 
    "Director": "Michael Mann", 
    "Year": "1995", 
    "Rating": "8.3" 
}, 
{ 
    "Id": "5", 
    "Title": "The Raid: Redemption", 
    "Director": "Gareth Evans", 
    "Year": "2011", 
    "Rating": "7.6" 
}] 
```

这只是一个非常简单的 JSON 电影列表。随意用你喜欢的内容填充它。启动服务器以确保你没有收到任何错误（请注意，我们还没有设置任何路由，所以如果你尝试通过浏览器加载它，它实际上不会做任何事情）：

```js
    $ node server.js
    Server up: http://localhost:3500
```

# 响应 GET 请求

添加简单的 `GET` 请求支持非常简单，你已经在我们构建的应用程序中见过这个。这是一些响应 `GET` 请求并返回简单 JavaScript 对象作为 JSON 的示例代码。在我们有 `// TO DO: Setup endpoints ...` 注释等待的 `routes` 部分插入以下代码：

```js
router.get('/test', (req, res)=>{ 
    var data = { 
        name: 'Jason Krol', 
        website: 'http://kroltech.com' 
    }; 
    res.json(data); 
}); 
```

就像我们在第五章中设置了 `viewModel` 一样，*使用 Handlebars 进行模板化*，我们创建一个基本的 JavaScript 对象，然后可以直接使用 `res.json` 发送作为 JSON 响应，而不是 `res.render`。让我们稍微调整一下这个函数，并将它更改为响应根 URL（即 `/`）路由的 `GET` 请求，并从我们的 `movies` 文件返回 JSON 数据。在之前添加的 `/test` 路由之后添加这个新路由：

```js
router.get('/', (req, res)=>res.json(json)); 
```

在 Express 中，`res`（响应）对象有一些不同的方法来将数据发送回浏览器。这些方法最终都会回退到基本的`send`方法，其中包括`header`信息，`statusCodes`等。`res.json`和`res.jsonp`将自动将 JavaScript 对象格式化为 JSON，然后使用`res.send`发送它们。`res.render`将以字符串形式呈现模板视图，然后也使用`res.send`发送它。

有了这段代码，如果我们启动`server.js`文件，服务器将监听`/`URL 路由的`GET`请求，并响应我们电影集合的 JSON 数据。让我们首先使用 Postman REST 客户端工具进行测试：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/webdev-mongo-node/img/d4a24349-089d-4720-b0ab-4d714a59e095.png)

`GET`请求很好，因为我们可以很容易地通过浏览器拉取相同的 URL 并获得相同的结果：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/webdev-mongo-node/img/d767d05b-f1aa-490f-a2ba-7e921f3e4c42.png)

然而，我们将使用 Postman 进行剩余的端点测试，因为使用浏览器发送`POST`和`PUT`请求有点困难。

# 接收数据 - POST 和 PUT 请求

当我们希望允许使用我们的 API 插入或更新数据时，我们需要接受来自不同 HTTP 动词的请求。在插入新数据时，`POST`动词是接受数据并知道它是用于插入的首选方法。让我们看一下接受`POST`请求和数据的代码，将记录插入到我们的集合中，并返回更新的 JSON。

在之前为`GET`添加的路由之后插入以下代码块：

```js
router.post('/', (req, res)=>{ 
    // insert the new item into the collection 
    if(req.body.Id && req.body.Title && req.body.Director && req.body.Year && req.body.Rating) { 
        json.push(req.body); 
        res.json(json); 
    } else { 
        res.json(500, { error: 'There was an error!' }); 
    } 
}); 
```

在`POST`函数中，我们首先要做的是检查确保所需字段与实际请求一起提交。假设我们的数据检查通过，并且所有必需字段都被考虑在内（在我们的情况下，每个字段），我们将整个`req.body`对象按原样插入数组中，使用数组的`push`函数。如果请求中没有提交任何必需字段，我们将返回一个 500 错误消息。让我们使用 Postman REST 客户端向相同的端点提交一个`POST`请求。（不要忘记确保你的 API 服务器正在使用 node `server.js`运行。）：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/webdev-mongo-node/img/edc4584d-4582-4d35-bd86-cae7b3268bb4.png)

首先，我们提交了一个没有数据的`POST`请求，所以你可以清楚地看到返回的 500 错误响应：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/webdev-mongo-node/img/daaa2ebd-7dfa-4776-abb6-b49a1d6e2571.png)

接下来，我们在 Postman 中使用`x-www-form-urlencoded`选项提供了实际数据，并提供了每个名称/值对的一些新的自定义数据。你可以从结果中看到状态是 200，这是成功的，并且更新的 JSON 数据作为结果返回。在浏览器中重新加载主`GET`端点，可以看到我们原始的电影集合中添加了新的电影：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/webdev-mongo-node/img/232bb26a-3061-4a1b-9d5c-806a814d39b9.png)

`PUT`请求几乎以完全相同的方式工作，除了传统上，数据的`Id`属性处理方式有点不同。在我们的例子中，我们将要求`Id`属性作为 URL 的一部分，并且不接受它作为提交的数据参数（因为通常`update`函数不会改变正在更新的对象的实际`Id`）。在之前添加的`POST`路由之后，插入以下代码用于`PUT`路由：

```js
router.put('/:id', (req, res)=>{ 
    // update the item in the collection 
    if(req.params.id && req.body.Title && req.body.Director && req.body.Year && req.body.Rating) { 
        _.each(json, (elem, index)=>{ 
            // find and update: 
            if (elem.Id === req.params.id) { 
                elem.Title = req.body.Title; 
                elem.Director = req.body.Director; 
                elem.Year = req.body.Year; 
                elem.Rating = req.body.Rating; 
            } 
        }); 

        res.json(json); 
    } else { 
        res.json(500, { error: 'There was an error!' }); 
    } 
}); 
```

这段代码再次验证了提交的数据中是否包含所需的字段。然后，它执行一个`_.each`循环（使用`underscore`模块）来查看电影集合，并找到其`Id`参数与 URL 参数中的`Id`匹配的项目。假设有匹配项，那么相应对象的个别字段将使用请求中发送的新值进行更新。一旦循环完成，更新后的 JSON 数据将作为响应发送回来。同样，在`POST`请求中，如果缺少任何必需的字段，将返回一个简单的 500 错误消息。以下截图展示了成功的`PUT`请求更新现有记录：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/webdev-mongo-node/img/0c7e516c-e684-49f3-b85b-6481333dca58.png)

在 Postman 的响应中，包括将值`1`作为`Id`参数放入 URL 中，作为`x-www-form-urlencoded`值提供要更新的个别字段，最后作为`PUT`发送，显示我们电影集合中的原始项目现在是原始的 Alien（而不是 Aliens，它的续集，正如我们最初的情况）。

# 删除数据 - DELETE

我们在不同的 REST API HTTP 动词的旋风之旅中的最后一站是`DELETE`。发送`DELETE`请求应该做的事情应该不会让人感到意外。让我们添加另一个接受`DELETE`请求并从我们的电影集合中删除项目的路由。以下是处理`DELETE`请求的代码，应该放在先前`PUT`的现有代码块之后：

```js
router.delete('/:id', (req, res)=>{ 
    let indexToDel = -1; 
    _.each(json, (elem, index)=>{ 
        if (elem.Id === req.params.id) { 
            indexToDel = index; 
        } 
    }); 
    if (~indexToDel) { 
        json.splice(indexToDel, 1); 
    } 
    res.json(json); 
}); 
```

这段代码将循环遍历电影集合，并通过比较`Id`的值找到匹配的项目。如果找到匹配项，匹配项目的数组`index`将保持，直到循环结束。使用`array.splice`函数，我们可以删除特定索引处的数组项。一旦通过删除请求的项目更新了数据，JSON 数据将被返回。请注意，在以下截图中，返回的更新后的 JSON 实际上不再显示我们删除的原始第二项：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/webdev-mongo-node/img/d16f1ce3-2968-47fe-9bf2-b64f1256f94c.png)

JavaScript 中的`~`使用！这是一点点 JavaScript 黑魔法！在 JavaScript 中，波浪号（`~`）将对一个值进行位翻转。换句话说，它将取一个值并返回该值的负值加一，即`~n === -(n+1)`。通常，波浪号与返回`-1`作为假响应的函数一起使用。通过在`-1`上使用`~`，您将其转换为`0`。如果您在 JavaScript 中对`-1`执行布尔检查，它将返回`true`。您会发现`~`主要与`indexOf`函数和`jQuery`的`$.inArray()`一起使用；两者都将`-1`作为`false`响应。

本章中定义的所有端点都非常基础，其中大多数在生产环境中不应该出现！每当您有一个接受除`GET`请求以外的任何内容的 API 时，您都需要确保执行非常严格的验证和身份验证规则。毕竟，您基本上是直接向用户提供对您数据的访问权限。

# 从 Node.js 中使用外部 API

毫无疑问，总有一天您想要直接从 Node.js 代码中使用 API。也许您自己的 API 端点需要首先从某个与之无关的第三方 API 中获取数据，然后再发送响应。无论原因是什么，通过使用一个名为`request`的流行和知名的`npm`模块，可以相对容易地发送请求到外部 API 端点并接收响应。`request`模块是由 Mikeal Rogers 编写的，目前是第三受欢迎（也是最可靠的）`npm`模块，仅次于`async`和`underscore`。

请求基本上是一个超级简单的 HTTP 客户端，所以到目前为止你用 Postman REST Client 所做的一切基本上都是`Request`可以做的，只是结果数据在你的 Node 代码中可用，以及响应状态码和/或错误（如果有的话）。

# 使用请求来消耗 API 端点

让我们做一个巧妙的技巧，实际上消耗我们自己的端点，就好像它是某个第三方外部 API 一样。首先，我们需要确保我们已经安装了`request`并且可以在我们的应用程序中包含它：

```js
    $ npm install --save request
```

接下来，编辑`server.js`，确保你包含`request`作为一个必需的模块

在文件的开头：

```js
const express = require('express'), 
    bodyParser = require('body-parser'), 
    _ = require('underscore'), 
    json = require('./movies.json'), 
    app = express(), 
    request = require('request'); 
```

现在，让我们在现有路由之后添加一个新的端点，这将是通过对`/external-api`发出`GET`请求在我们的服务器中可访问的一个端点。然而，这个端点实际上将消耗另一个服务器上的另一个端点，但是出于这个例子的目的，另一个服务器实际上是我们当前正在运行的相同服务器！

`request`模块接受一个带有许多不同参数和设置的选项对象，但对于这个特定的例子，我们只关心其中的一些。我们将传递一个具有我们要消耗的端点的 URL 设置的对象。在发出请求并收到响应后，我们希望执行一个内联的`callback`函数。

在`server.js`中现有的`routes`列表之后放置以下代码块：

```js
router.get('/external-api', (req, res)=>{ 
    request.get({ 
            uri: `http://localhost:${(process.env.PORT || 3500)}` 
        }, (error, response, body)=>{ 
            if (error) { throw error; } 

            var movies = []; 
            _.each(JSON.parse(body), (elem, index)=>{ 
                movies.push({ 
                    Title: elem.Title, 
                    Rating: elem.Rating 
                }); 
            }); 
            res.json(_.sortBy(movies, 'Rating').reverse()); 
        }); 
}); 
```

`callback`函数接受三个参数：`error`，`response`和`body`。`response`对象就像 Express 处理的任何其他响应一样，具有各种参数。第三个参数`body`是我们真正感兴趣的。它将包含我们调用的端点请求的实际结果。在这种情况下，它是我们之前定义的主`GET`路由返回的 JSON 数据，其中包含我们自己的电影列表。重要的是要注意，从请求返回的数据是作为字符串返回的。我们需要使用`JSON.parse`将该字符串转换为实际可用的 JSON 数据。

我们操纵了从请求返回的数据以满足我们的需求。在这个例子中，我们拿到了电影的主列表，只返回了一个由每部电影的`Title`和`Rating`组成的新集合，并按照最高分数对结果进行排序。

通过将浏览器指向`http://localhost:3500/external-api`来加载这个新的端点，你可以看到新转换的 JSON 输出显示在屏幕上。

让我们看一个更真实的例子。假设我们想为我们收藏中的每部电影显示一系列相似的电影，但我们想在[www.imdb.com](http://www.imdb.com)等地方查找这些数据。下面是一个示例代码，它将向 IMDB 的 JSON API 发送一个`GET`请求，特别是针对单词`aliens`，并返回按`Title`和`Year`列出的相关电影。继续在`external-api`的先前路由之后放置这个代码块：

```js
router.get('/imdb', (req, res)=>{ 
    //console.log("err1") 
    request.get({ 
            uri: 'http://sg.media-imdb.com/suggests/a/aliens.json' 
        }, (err, response, body)=>{ 
            let data = body.substring(body.indexOf('(')+1); 
            data = JSON.parse(data.substring(0,data.length-1)); 
            let related = []; 
            _.each(data.d, (movie, index)=>{ 
                related.push({ 
                    Title: movie.l, 
                    Year: movie.y, 
                    Poster: movie.i ? movie.i[0] : '' 
                }); 
            }); 

            res.json(related); 
        }); 
}); 
```

如果我们在浏览器中查看这个新的端点，我们可以看到从我们的`/imdb`端点返回的 JSON 数据实际上是从一些其他 API 端点检索和返回数据：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/webdev-mongo-node/img/fef410ca-67ab-4945-b33a-8473a3893aaa.png)

我正在使用的 IMDB 的 JSON 端点实际上并不是来自他们的 API，而是当你在主搜索框中输入时他们在主页上使用的。这实际上并不是使用他们的数据的最合适的方式，但更多的是一个示例。实际上，要使用他们的 API（就像大多数其他 API 一样），你需要注册并获取一个 API 密钥，这样他们才能正确地跟踪你每天或每小时请求了多少数据。出于这个原因，大多数 API 都需要你使用私钥。

# 摘要

在本章中，我们简要介绍了 API 的一般工作原理，语义 URL 路径和参数的 RESTful API 方法，以及如何创建一个简单的 API。

我们使用 Postman REST Client 与 API 交互，通过消耗端点和测试不同类型的请求方法（`GET`，`POST`，`PUT`等）来进行测试。您还学会了如何使用第三方节点模块`request`来消耗外部 API 端点。

在下一章中，我们将重新访问我们的原始应用程序，通过在 Node.js 中引入测试来实施最佳实践。我们将研究流行的测试框架，并为应用程序编写测试，以证明我们的代码按预期工作。


# 第九章：测试您的代码

到目前为止，我们在编写代码时基本上是凭着感觉在进行。我们实际上无法知道代码是否有效，直到在实际浏览器中测试它。

在本章中，我们将涵盖以下主题：

+   使用 Mocha 测试框架运行测试

+   使用 Chai.js 断言库编写测试

+   使用 Sinon 和 Proxyquire 进行间谍和存根

+   编写您的第一个测试

+   测试您的应用程序

测试对于确保您的代码正常运行非常重要，但它们也非常适用于防止由于您对某些无辜的代码进行了微小更改而突然出现新的意外错误。

# 行业工具

让我们首先看一下我们将用于运行和编写测试的各种工具和库。在我们实际开始编写真正的测试之前，我们需要掌握三个主要概念。

第一个是测试运行器，或者我们用来运行测试套件的框架。

大多数框架都遵循**测试驱动开发**（**TDD**），其过程依赖以下步骤：

1.  它定义了一个单元测试。

1.  它实现了该单元。

1.  它执行测试并验证测试是否通过。

第二个概念是断言库本身——我们用来编写测试的语言。使用断言语言的特殊版本来逐步设计和构建功能块，以期望的行为为指导，称为**行为驱动开发**（**BDD**）。

对于 TDD 和 BDD，我们可以使用 Mocha 测试框架；但是，我们将使用一个名为`Chai.js`的特殊断言库来编写断言。

最后，我们将看一下间谍和存根的概念，它们是我们代码的某些部分的虚假代表，当我们需要跟踪函数调用以确保预期的行为时，我们会依赖它们。

# 使用 Mocha 框架运行测试

在为应用程序编写测试时，通常会按模块特定的批次编写它们。这些批次被称为套件或规范。每个套件通常包含一批以几乎与应用程序本身相似的方式组织的测试。对于 Node，这个想法也是一样的，我们编写的每个测试套件都将针对一个单独的模块。您将需要测试的模块，并为模块的每个部分编写一系列测试。

由于您将有许多不同的测试文件来测试应用程序的每个组件，您需要一种快速执行所有测试的方法。这就是测试运行器的作用。我们决定使用的测试运行器称为 Mocha。您可以像安装其他`npm`包一样全局安装 Mocha，如下所示：

```js
    $ npm install -g mocha
```

在 Linux 或 OS X 上安装时可能需要安全权限，可以简单地在`npm`之前使用`sudo`。

一旦安装完成，Mocha 命令行工具就可以使用了。只需在命令行中执行`mocha`，就会使用一些默认选项执行测试运行。

测试运行器将查找名为`test`的文件夹和其中的任何`.js`文件。在我们的情况下，我们实际上还没有设置任何测试，因此仅执行`mocha`将不会有任何效果；相反，它会抛出以下错误：

```js
 cannot resolve path
```

当 Mocha 测试运行器找到`.js`文件时，它会像执行任何其他 Node 文件一样执行它们，只是它会在文件中查找一些特定的关键字。

以下是典型测试块的一些示例代码：

```js
const expect = require('chai').expect; 
describe('The code', ()=>{ 
    beforeEach(()=>{ 
        // optional preparation for each test 
    }); 
    afterEach(()=>{ 
        // optional cleanup after each test 
    }); 

    it('should test something', ()=>{ 
        const something = 1; 
        // here we "expect" some condition to declare our test 
        // in this case, we expect the variable to exist 
        // more on the assertion syntax a little later 
        expect(something).to.exist; 
    }); 
    it('should test something_else', ()=>{ 
        const something_else = false; 
        // now we test a different variable against its value 
        // and expect that value to equal false 
        expect(something_else).to.equal(false); 
    }); 
}); 
```

Mocha 首先要扫描文件的是`describe`块。`describe`块是定义单行中特定测试用例组的一种方式。您可以在`test`文件中有许多`describe`块，并且每个`describe`块可以有许多具体测试。此外，`describe`块可以嵌套得很深，以更好地组织您的测试。

一旦找到一个`describe`块，其中还会执行一些其他项目。会检查`beforeEach`和`afterEach`块，看是否有任何需要在每次测试执行之前执行的预测试工作。同样，在测试之间需要进行任何清理工作也可以在`afterEach`块中处理。

这两个块都是可选的，因此不是必需的。如果您需要实例化一个对象进行测试，您可以使用`beforeEach`块。这样，无论测试可能对对象进行了什么更改，都将被重置，并且不会无意中影响任何其他测试。同样，您在测试期间对任何其他相关对象所做的任何更改都可以在`afterEach`块中重置。

在`describe`块内，使用`it`语句定义单独的测试。在每个`it`语句中，通常认为包括一个单独的`expect`来断言实际测试（尽管您可以包括尽可能多的`expect`函数调用，但由于只有一个`it`，它仍然被认为是单个测试）。

在编写测试套件时，我们使用 BDD 风格的语法，这样我们的测试就可以像用户故事一样阅读。使用前面的测试片段，您可以将测试读作`代码应该测试某事`和`代码应该测试其他事情`。实际上，如果我们运行前面的测试，我们会看到以下输出：

```js
      The code
         should test something
         should test something_else

      2 passing (5ms)
```

# 使用 Chai.js 进行断言测试

正如您在前面的单元测试示例中看到的，我们使用特殊块来定义我们的测试组，但在定义实际的单独测试时使用了不同的语言。这些测试被称为**断言**，我们选择使用`Chai.js`库。这纯粹是个人偏好，因为存在许多不同的断言库。每个库基本上都是做同样的事情，只是在编写测试的语法和风格上略有不同。由于`Chai.js`是项目特定的并且基于个人偏好，我们将其安装为项目依赖项（而不是全局安装）。此外，由于我们的测试实际上并不是应用程序运行所必需的，我们将在`package.json`文件的`devDependencies`列表中包含`Chai.js`。

在开发者的机器上执行`npm install`将会将所有包安装到正常的依赖项下，以及`package.json`中的`devDependencies`。当环境变为生产环境时，我们需要执行`npm install --prod`来指定环境。

这将帮助`npm`在`package.json`中将包安装到依赖项而不是`devDependencies`下。为了将`Chai.js`作为`devDependency`包含在我们的项目中，我们将在执行`npm`安装时使用`--save-dev`标志而不是`--save`：

```js
    $ npm install --save-dev chai
```

# 开始使用 Chai

Chai 本身有几种不同风格的 API 可以在编写测试时使用。我们将使用 BDD API 来编写测试，它使用`expect`和`should`。还有一个更多的 TDD 风格的 assert API。使用`expect`/`should`的 BDD 风格的好处是可以链式调用断言方法来提高测试的可读性。

您可以通过访问以下维基百科页面了解更多关于 BDD 和 TDD 的信息：

[`en.wikipedia.org/wiki/Behavior-driven_development`](http://en.wikipedia.org/wiki/Behavior-driven_development)

使用`Chai.js`的 BDD 断言 API 提供了许多方法，比如`to`、`be`、`is`等等。它们没有测试能力，但可以提高断言的可读性。所有的获取器都列在[`chaijs.com/api/bdd/`](http://chaijs.com/api/bdd/)上。

所有这些获取器都将遵循一个`expect()`语句，并且可以与`not`结合，以便在需要时将断言取反。

前面的获取器与`chai`断言方法相结合，比如`ok`，`equal`，`within`等，以确定测试的结果。所有这些方法都列在[`chaijs.com/api/assert/`](http://chaijs.com/api/assert/)中。

让我们开始构建简单的断言。`chai`提供了三种不同的断言风格：`expect`，`should`和`assert`。考虑以下简单的例子：

```js
const chai = require('chai'); 
const expect = chai.expect; 
const should = chai.should(); 
const assert = chai.assert; 
const animals = { pets: [ 'dog', 'cat', 'mouse' ] }; 
const foo = 'bar'; 

expect(foo).to.be.a('string').and.equal('bar'); 
expect(animals).to.have.property('pets').with.length(4); 
animals.should.have.property('pets').with.length(4); 
assert.equal(foo, 'bar', 'Foo equal bar'); 
```

正如你所看到的，`expect`/`should`函数是基于自描述语言链的。两者在声明方式上有所不同——`expect`函数提供了链的起点，而`should`接口则扩展了`Object.prototype`。

`assert`接口提供了简单但强大的 TDD 风格断言。除了前面的例子产生的深度相等断言，还有异常测试和实例可用。要进行更深入的学习，请参考 Chai 文档[`chaijs.com/api`](http://chaijs.com/api)。

# 使用 Sinon.js 进行间谍和存根

如果没有一种简单的方法来监视函数并知道它们何时被调用，测试代码将变得非常困难。此外，当调用你的函数之一时，知道传递给它的参数和返回的内容也是很好的。在测试中，`spy`是一个特殊的占位符函数，当你想要检查特定的函数是否/何时被调用时，它会替换现有的函数。当调用函数时，间谍会跟踪一些属性，并且它们还可以通过原始函数的预期功能。`Sinon.js`库提供了`spy`和`stub`功能，并且非常全面。要了解这个强大框架提供的不同选项的完整列表，我强烈建议你花一些时间阅读文档[`sinonjs.org/docs`](http://sinonjs.org/docs)。

由于我们将在测试中使用`Sinon.js`，我们应该将其安装为另一个`devDependency`，与我们使用`Chai.js`时完全相同。此外，我们还应该安装`sinon-chai`助手，它提供了额外的`chai`断言动词，专门用于与 Sinon 一起使用：

```js
    $ npm install --save-dev sinon sinon-chai
```

包含`sinon-chai`允许我们编写特殊的断言，比如`to.be.calledWith`，这在仅使用`chai`时是无法使用的。

想象一下，你有一个简单地将两个数字相加并返回总和的函数：

```js
let sum = (a, b) => {
    return a + b;
}
let doWork = () => {
    console.log("asdasd")
    const x = 1,
        y = 2;
    console.log(sum(x, y));
} 
```

在为`doWork`函数编写测试时，我们希望断言`sum`函数是否被调用。我们并不一定关心函数做什么，或者它是否起作用；我们只是想确保——因为`doWork`依赖于`sum`——它实际上调用了`function()`函数。在这种情况下，我们唯一能确定的方式是如果我们有一种方法来监视`sum`函数并知道它是否被调用。使用`spy`，我们可以做到这一点：

```js
const chai = require('chai');
const expect = chai.expect; 
const sinon = require("sinon"); 
const sinonChai = require("sinon-chai"); 
chai.use(sinonChai); 

describe('doWork', ()=>{ 
    let sum; 

    it('should call sum', ()=>{ 
        sum = sinon.spy(); 
        doWork(); 
        expect(sum).to.be.calledWith(1,2); 
    }); 
}); 
```

在前面的场景中，`sum`函数被替换为`spy`函数。因此它的实际功能将不再存在。如果我们想要确保`sum`函数不仅被监视，而且仍然按照我们的期望工作，我们需要在`sinon.spy()`后面添加`.andCallThrough()`：

```js
describe('doWork', ()=>{ 
    let sum; 
    console.log = sinon.spy(); 

    it('should call sum', ()=>{ 
        sum = sinon.spy().andCallThrough(); 
        doWork(); 
        expect(sum).to.be.calledWith(1,2); 
        expect(console.log).to.be.calledWith(3); 
    }); 
}); 
```

请注意，通过在我们的`sum`间谍上包含`andCallThrough`，我们不仅能够监视它并断言它是否被调用，还能够监视`console.log`函数并断言它是否被调用并返回`sum`返回的正确值。

`spy`通常只是一个函数的观察者，并且只报告函数是否被调用，而`stub`允许你在测试执行期间为函数提供自定义功能。测试存根被称为预编程行为函数，用于测试应用程序中作为模块依赖项的包装样板代码。

将`stub`视为超级间谍，它报告与`spy`相同的事情，但也执行您想要的特定任务。使用相同的示例，让我们将`sum`函数存根为始终返回相同的值：

```js
it('should console.log sum response', ()=>{ 
    // replace the existing sum function with a new stub, 
    // a generic function that does exactly what we specify 
    // in this case always just return the number 2 
    sum = sinon.stub(()=>{ 
        return 2; 
    });

    // lets replace the standard console.log function 
    // with a spy 
    console.log = sinon.spy(); 
    // call our doWork function (which itself uses console.log) 
    doWork(); 
    // and if doWork executed the way its supposed to, console.log 
    // should have been called and the parameter 2 passed to it 
    expect(console.log).to.be.calledWith(2); 
}); 
```

当函数执行可能产生意外结果，并且您只想为测试目的强制响应时，存根函数是很好的。当您进行 TDD 并且正在针对尚未编写的函数进行测试时，存根也很方便。

# 使用 Proxyquire 存根节点模块

在同一模块内编写测试时，间谍和存根非常有用，但是当您需要监视或存根另一个 Node 模块中所需的模块时，情况就会变得有点棘手。幸运的是，有一个名为**Proxyquire**的工具，它将允许您存根从您的代码中所需的模块。

检查以下代码示例：

```js
// google.js 
const request = require('request'),
  sinon = require("sinon"),
  log = sinon.spy();

module.exports =()=>{ 
    request('http://www.google.com', (err, res, body)=>{ 
        log(body); 
    }); 
} 
```

您可以看到我们需要`request`模块。`request`模块接受两个参数，其中一个是`callback`函数。事情开始变得棘手的地方就在这里。在这种情况下，我们将如何实现间谍和/或存根？此外，我们如何防止我们的测试明确地发出网络调用以获取`google.com`？如果我们运行测试时`google.com`宕机（哈！）会怎么样？

为了能够监视`request`模块，我们需要一种拦截实际`require`并附加我们自己的存根版本的`request`的方法。`request`模块实际上是一个您想要存根的模块的很好的例子，因为`request`用于进行网络调用，这是您希望确保您的测试永远不会真正执行的操作。您不希望您的测试依赖外部资源，例如网络连接或依赖从实际请求返回的数据。

使用 Proxyquire，我们实际上可以设置我们的测试，以便它们拦截`require`模块，并用我们自己的存根替换执行的内容。以下是针对我们之前创建的模块编写的测试文件的示例：

```js
//google.spy.js
const sinon = require("sinon"),
proxyquire = require('proxyquire'),
log = sinon.spy(), 
requestStub = sinon.stub().callsArgWith(1, null, null, 'google.com'), 
google = proxyquire('./google', { 'request': requestStub }); 

describe('google module', ()=>{ 
    beforeEach(()=>{ 
        google(); 
    }); 
    it('should request google.com', ()=>{ 
        expect(reqstub).to.be.called(); 
    }); 
    it('should log google body', ()=>{ 
        expect(callback).to.be.calledWith(null, null, 'google.com'); 
    }); 
}); 
```

测试套件的第一件事是设置一个`spy`和一个通用的`stub`函数，该函数将用作`request`模块。然后，我们包括我们的`google`模块，但我们使用`proxyquire`而不是典型的`require`模块。使用`proxyquire`，我们传递模块的路径，方式与`require`相同，只是第二个参数是在该模块中所需的模块，以及要在其位置使用的`stub`函数。

在每个测试之前，我们将执行原始的`google`模块，并断言我们的`stub`实际上被调用。此外，我们断言`log`间谍被调用，并且使用从`request`模块返回的任何数据。由于我们控制该模块，因此我们可以测试确实，当请求发送到`http://google.com`时，返回了字符串`google.com`（我们确切知道这不是真的--不仅如此，我们还知道从未发送网络调用到`www.google.com`）。 

我们正在使用`stub`的特殊功能，该功能允许我们执行特定参数到存根函数，假设它是`callback`函数。在这里，我们使用`callsArgWith`，并将参数`index`（从零开始）包括为第一个参数；在这种情况下，传递给请求的两个参数中的一个，第一个（索引 0）是 URL 本身，第二个（索引 1）是`callback`函数。使用`callsArgWith`，我们可以执行`callback`函数并具体提供其参数，例如`null`，`null`和一个字符串。像`Sinon.js`和`Chai.js`一样，`proxyquire`也需要作为`devDependency`包含在我们的项目中。

```js
    $ npm install --save-dev proxyquire
```

# 编写并运行您的第一个测试

到目前为止，我们看到的所有测试代码都只是演示和示例，我们实际上还没有运行任何测试。让我们设置应用程序的基本结构，以便我们可以开始编写真正的测试。

首先要做的是设置一个文件夹结构，用来存放所有的测试。考虑以下步骤：

1.  在应用程序项目文件夹的根目录中，创建一个名为`tests`的文件夹。

1.  在`tests`文件夹中，创建三个更多的文件夹，分别为`controllers`、`models`和`server`。

```js
/(existing app root) 
tests/ 
----/controllers/ 
----/models/ 
----/server/ 
```

# 编写一个测试助手

在我们开始为应用程序编写测试之前，有一些额外的开销需要我们准备好以准备进行测试。为了处理这些开销，我们将编写一个`testhelper`文件，它将被包含并与我们通过 Mocha 执行的每个测试文件一起运行。

在`tests`文件夹中创建一个名为`testhelper.js`的文件，并插入以下代码块：

```js
const chai = require('chai'), 
    sinon = require('sinon'), 
    sinonChai = require('sinon-chai'); 

global.expect = chai.expect; 
global.sinon = sinon; 
chai.use(sinonChai); 
```

这是我们通常需要在每一个测试文件的顶部包含的代码；但是，通过将其包含在一个单独的文件中，我们可以指示 Mocha 自动要求每个运行的测试文件包含这个文件。文件本身只包括`chai`和`sinon`模块，并定义了一些全局变量作为我们测试编写的快捷方式。此外，它指示`chai`使用`sinonChai`模块，以便我们的语法得到扩展，我们可以编写 Sinon 特定的 Chai 断言。实际运行我们的测试套件的命令如下：

```js
    $ mocha -r tests/testhelper.js -R spec tests/**/*.test.js
```

记住我们之前全局安装了 Mocha，这样我们就可以从任何地方执行`mocha`命令。

根据前面命令中测试的路径，假设该命令将从应用项目文件夹的根目录执行。`-r`标志指示 Mocha 要求`testhelper.js`模块。`-R`标志是定义测试报告输出样式的选项。我们选择使用`spec`样式，它以嵌套缩进样式列出我们的报告，每个`describe`和`it`语句，以及通过测试的绿色复选标记。最后一个参数是我们`test`文件的路径；在这种情况下，我们提供了通配符，以便所有的测试都会运行。

Mocha 有几种不同的报告样式可供选择。这包括点（每个测试重复一个点）、列表、进度（百分比条）、JSON 和 spec。其中比较有趣的，尽管有点无用，是`-R nyan`报告样式。

让我们写一个快速的样本测试，以确保我们的项目设置正确。在`tests`文件夹中，创建一个名为`mocha.test.js`的新文件，并包含以下代码：

```js
describe('Mocha', ()=>{
    'use strict';

    beforeEach(()=>{});

    describe('First Test', ()=>{
        it('should assert 1 equals 1', ()=>{
            expect(1).to.eql(1);
        });
    });
});

```

前面的测试非常简单，只是断言`1`等于`1`。保存这个文件，再次运行`Mocha`测试命令，你应该会得到以下输出：

```js
    $ mocha -r tests/testhelper.js -R spec tests/mocha.test.js
    Mocha
      First Test
         should assert 1 equals 1

    1 passing (5ms)

```

你可能会觉得记住和执行`Mocha`的那个冗长而复杂的命令很烦人和令人沮丧。幸运的是，有一个相当简单的解决方案。编辑应用程序中的`package.json`文件，并添加以下部分：

```js
"scripts": { 
    "start": "node server.js", 
    "test": "mocha -r tests/testhelper.js -R spec 
      tests/**/*.test.js" 
  }, 
```

通过在`package.json`文件中进行这个调整，现在你可以简单地在命令行中执行`npm test`作为一个快速简便的快捷方式。这是`package.json`文件的一个标准约定，所以任何开发人员都会知道如何简单地执行`npm test`：

```js
    $ npm test
    > chapter9@0.0.0 test /Users/jasonk/repos/nodebook/chapter9
    > mocha -r tests/testhelper.js -R spec tests/**/*.test.js

    Mocha
      First Test
         should assert 1 equals 1

    1 passing (5ms)

```

现在我们的项目已经设置好了，可以正确运行和执行测试，让我们开始为应用程序编写一些真正的测试。

# 测试应用程序

在解决了所有这些背景信息之后，让我们专注于为我们构建的应用程序编写一些真正的测试。在接下来的几节中，我们将为应用程序的路由、服务器、模型和控制器编写测试。

# 测试路由

让我们慢慢开始，先看看我们应用程序中最基本的文件之一，`routes.js`文件。这个文件只是定义了应用程序应该响应的路由数量。这将是最容易编写测试的文件之一。

由于`routes.js`文件位于我们主应用程序中的`server`文件夹中，让我们将其相应的测试文件放在类似的位置。在`tests/server`文件夹中，创建一个名为`routes.test.js`的文件。由于`routes.test.js`文件将测试我们的`routes.js`文件的功能，我们需要它`require`相同的模块。

在`test/server/routes.test.js`中包含以下代码：

```js
const home = require('../../controllers/home'), 
    image = require('../../controllers/image'), 
    routes = require('../../server/routes'); 
```

请注意，路径不同，因为我们从`test/server`文件夹中`require`模块，但我们还需要`require`特定于应用程序的模块。另外，请注意，除了我们原始的`routes.js`文件需要的模块之外，我们还需要`require` `routes`模块本身。否则，如果没有包含它，我们将无法测试模块的功能。接下来，让我们设置测试套件的结构并创建一些`spy`。在`tests/server/routes.test.js`中的先前代码之后包括这个新的代码块：

```js
describe('Routes',()=>{ 
    let app = { 
        get: sinon.spy(), 
        post: sinon.spy(), 
        delete: sinon.spy() 
    }; 
    beforeEach(()=>{ 
        routes.initialize(app); 
    }); 

    // to do: write tests... 
}); 
```

如果您还记得，`routes`模块的`initialize`函数接受一个参数，即`app`对象。在我们的测试中，我们将`app`定义为一个简单的匿名对象，有三个函数-- `get`、`post`和`delete`；每个都是一个`spy`。我们包括一个`beforeEach`块，在每次测试运行之前执行`initialize`函数。

现在，让我们包括一些测试。首先，我们将测试`GET`端点是否正确配置。在`// to do: write tests...`注释之后，放置以下代码块：

```js
describe('GETs',()=>{ 
    it('should handle /', function(){ 
        expect(app.get).to.be.calledWith('/', home.index); 
    }); 
    it('should handle /images/:image_id', ()=>{ 
        expect(app.get).to.be.calledWith('/images/:image_id', 
         image.index); 
    }); 
}); 
```

然后，测试`POST`端点：

```js
describe('POSTs', ()=>{
    it('should handle /images', ()=>{
        expect(app.post).to.be.calledWith('/images', image.create);
    });
    it('should handle /images/:image_id/like', ()=>{
        expect(app.post).to.be.calledWith('/images/:image_id/like', image.like);
    });
    it('should handle /images/:image_id/comment', ()=>{
        expect(app.post).to.be.calledWith('/images/:image_id/comment', image.comment);
    });
}); 
```

最后，测试`DELETE`端点：

```js
describe('DELETEs', ()=>{
    it('should handle /images/:image_id', ()=>{
        expect(app.delete).to.be.calledWith('/images/:image_id', image.remove);
    });
}); 
```

这些测试都断言了同一件事，即`app`对象的相应`get`、`post`或`delete`函数是否针对每个路由使用了正确的参数。我们能够针对参数进行测试，因为我们使用的`app`对象是一个`spy`。

如果您运行`mocha`命令来执行测试套件，您应该会看到以下输出：

```js
    $ npm test
    Routes
        GETs
           should handle /
           should handle /images/:image_id
        POSTs
           should handle /images
           should handle /images/:image_id/like
           should handle /images/:image_id/comment
        DELETEs
           should handle /images/:image_id

      6 passing (14ms)
```

# 测试服务器

测试`server.js`文件将与我们的其他文件略有不同。该文件作为我们应用程序的根运行，因此它不导出任何我们可以直接测试的模块或对象。由于我们使用`server.js`启动服务器，我们需要模拟从我们的代码启动服务器。我们将创建一个名为`server`的函数，它将使用`proxyquire`需要`server.js`文件，并对它需要的每个模块进行存根。执行`server()`函数将与从命令行执行`node server.js`完全相同。文件中的所有代码都将通过该函数执行，然后我们可以使用`proxyquire`中的`stub`对每个调用进行测试。

在`tests/server/`文件夹中创建名为`server.test.js`的文件，并插入以下代码块：

```js
let proxyquire, expressStub, configStub, mongooseStub, app, 
    server = function() { 
        proxyquire('../../server', { 
            'express': expressStub, 
            './server/configure': configStub, 
            'mongoose': mongooseStub 
        }); 
    }; 

describe('Server',()=>{ 
    beforeEach(()=>{
        proxyquire = require('proxyquire'),
        app = {
            set: sinon.spy(),
            get: sinon.stub().returns(3300),
            listen: sinon.spy()
        },
        expressStub = sinon.stub().returns(app),
        configStub = sinon.stub().returns(app),
        mongooseStub = {
            connect: sinon.spy(),
            connection: {
                on: sinon.spy()
            }
        };

        delete process.env.PORT;
    }); 

    // to do: write tests... 
}); 
```

在为我们的服务器运行每个测试之前，我们重置服务器的所有主要组件的存根。这些存根包括`app`对象、`express`、`config`和`mongoose`。我们对这些模块进行存根，因为我们想要对它们进行`spy`（并且我们使用存根是因为其中一些需要返回我们将在文件中使用的对象）。现在我们已经准备好了所有的`spy`和我们的`app`对象框架，我们可以开始测试我们代码的主要功能。

我们需要检查以下条件是否通过：

创建一个应用程序

+   视图目录已设置

+   端口已设置并且可以配置和/或设置为默认值

+   应用程序本身已配置（`config`已调用）

+   Mongoose 连接到数据库 URI 字符串

+   应用程序本身已启动

用以下代码块替换之前代码中的`// to do: write tests...`注释：

```js
describe('Bootstrapping', ()=>{
    it('should create the app', ()=>{
        server();
        expect(expressStub).to.be.called;
    });
    it('should set the views', ()=>{
        server();
        expect(app.set.secondCall.args[0]).to.equal('views');
    });
    it('should configure the app', ()=>{
        server();
        expect(configStub).to.be.calledWith(app);
    });
    it('should connect with mongoose', ()=>{
        server();
        expect(mongooseStub.connect).to.be.calledWith(sinon.match.string);
    });
    it('should launch the app', ()=>{
        server();
        expect(app.get).to.be.calledWith('port');
        expect(app.listen).to.be.calledWith(3300, sinon.match.func);
    });
}); 
```

在前面的一组测试中，我们测试了服务器的引导，这些都是最初在`server.js`中运行的所有功能。测试的名称相当不言自明。我们检查`app`对象的各种方法，确保它们被调用和/或传递了正确的参数。对于测试，我们希望测试特定类型的参数是否被调用，而不是参数值的确切内容；我们使用 Sinon 的匹配元素，这使得我们的测试可以更加通用。我们不希望在测试中硬编码 MongoDB URI 字符串，因为这只是我们需要维护的另一个地方--尽管如果您希望测试非常严格（即确切地断言传递了确切的 URI 字符串），您完全可以这样做。

在第二组测试中，我们希望确保端口已设置，默认为`3300`，并且可以通过使用节点环境变量进行更改：

```js
describe('Port', ()=>{
    it('should be set', ()=>{
        server();
        expect(app.set.firstCall.args[0]).to.equal('port');
    });
    it('should default to 3300', ()=>{
        server();
        expect(app.set.firstCall.args[1]).to.equal(3300);
    });
    it('should be configurable', ()=>{
        process.env.PORT = '5500';
        server();
        expect(app.set.firstCall.args[1]).to.equal('5500');
    });
}); 
```

有了这些测试，再次运行`npm test`命令，您应该会得到以下输出：

```js
    $ npm test 
    Server
        Bootstrapping
           should create the app (364ms)
           should set the views
           should configure the app
           should connect with mongoose
           should launch the app
        Port
           should be set
           should default to 3300
           should be configurable

```

# 测试模型

在测试我们的模型时，我们希望包括`model`模块本身，然后针对它编写测试。这里最简单的解决方案是创建一个测试`model`对象，然后断言该模型具有我们期望的所有字段，以及我们可能创建的任何虚拟属性。

创建`tests/models/image.test.js`文件，并插入以下代码：

```js
let ImageModel = require('../../models/image'); 

describe('Image Model',()=>{ 
    var image; 

    it('should have a mongoose schema',()=>{ 
        expect(ImageModel.schema).to.be.defined; 
    }); 

    beforeEach(()=>{ 
        image = new ImageModel({ 
            title: 'Test', 
            description: 'Testing', 
            filename: 'testfile.jpg' 
        }); 
    }); 

    // to do: write tests... 
}); 
```

首先，我们使用`require`包含`ImageModel`（注意`require`语句的路径）。我们运行的第一个测试是确保`ImageModel`具有一个 mongoose 模式属性。在这个测试之后，我们定义了`beforeEach`块，我们将依赖于这个块进行我们余下的测试。在每个测试之前，我们都希望实例化一个新的`ImageModel`对象，以便我们可以进行测试。我们可以在`beforeEach`块中执行此操作，以确保我们在每个测试中都处理一个新的对象，并且它没有被先前运行的任何测试所污染。还要注意的是，第一个测试和`beforeEach`块的顺序实际上并不重要，因为`beforeEach`块将在其父`describe`函数中的每个测试之前运行，无论它是以何种顺序定义的。

包括以下一组测试，替换占位符`// to do: write tests...`的注释：

```js
describe('Schema', ()=>{
    it('should have a title string', ()=>{
        expect(image.title).to.be.defined;
    });
    it('should have a description string', ()=>{
        expect(image.description).to.be.defined;
    });
    it('should have a filename string', ()=>{
        expect(image.filename).to.be.defined;
    });
    it('should have a views number default to 0', ()=>{
        expect(image.views).to.be.defined;
        expect(image.views).to.equal(0);
    });
    it('should have a likes number default to 0', ()=>{
        expect(image.likes).to.be.defined;
        expect(image.likes).to.equal(0);
    });
    it('should have a timestamp date', ()=>{
        expect(image.timestamp).to.be.defined;
    });
}); 
```

在这里，我们将检查确保我们期望的`ImageModel`实例具有的每个属性都已定义。对于已设置默认值的属性，我们还检查确保默认值也已设置。

接下来，我们将对我们期望`ImageModel`具有的`virtuals`进行测试，并验证它们是否按预期工作：

```js
describe('Virtuals', ()=>{
    describe('uniqueId', ()=>{
        it('should be defined', ()=>{
            expect(image.uniqueId).to.be.defined;
        });
        it('should get filename without extension', ()=>{
            expect(image.uniqueId).to.equal('testfile');
        });
    });
}); 
```

在测试`uniqueId`虚拟属性时，它应该返回`image`模型的文件名，但不包括扩展名。由于`beforeEach`定义了我们的`image`模型，文件名为`testfile.jpg`，我们可以通过测试断言`uniqueId`返回的值等于`testfile`（不包括扩展名的文件名）。

运行我们的模型测试应该提供以下结果：

```js
    $ npm test
    Image Model
         should have a mongoose schema
        Schema
           should have a title string
           should have a description string
           should have a filename string
           should have a views number default to 0
           should have a likes number default to 0
           should have a timestamp date
        Virtuals
          uniqueId
             should be defined
             should get filename without extension

```

# 测试控制器

最后，让我们来看看`image`控制器，特别是对主要的`index`函数进行测试。由于`index`函数需要做很多工作并执行许多不同的任务，测试文件将大量使用存根和间谍。在任何测试之前，我们需要声明一些全局变量供我们的测试使用，并设置所有我们的`stub`、间谍和占位符对象以供`proxyquire`使用。然后，我们使用`proxyquire`来引入实际的图像控制器。创建一个名为`tests/controllers/image.test.js`的文件，并插入以下代码：

```js
let proxyquire = require('proxyquire'), 
    callback = sinon.spy(), 
    sidebarStub = sinon.stub(), 
    fsStub = {}, 
    pathStub = {}, 
    md5Stub = {}, 
    ModelsStub = { 
        Image: { 
            findOne: sinon.spy() 
        }, 
        Comment: { 
            find: sinon.spy() 
        } 
    }, 
    image = proxyquire('../../controllers/image', { 
        '../helpers/sidebar': sidebarStub, 
        '../models': ModelsStub, 
        'fs': fsStub, 
        'path': pathStub, 
        'md5': md5Stub 
    }), 
    res = {}, 
    req = {}, 
    testImage = {}; 
```

通过这段代码，我们定义了许多全局变量，如间谍、存根或空占位符 JavaScript 对象。一旦我们的`stub`准备好了，我们将调用`proxyquire`来包含我们的`image`控制器（确保`image`控制器中的所需模块实际上被我们各种`stub`和间谍替换）。现在，所有我们的全局变量、`stub`和间谍都准备好了，让我们包含一些测试。

在上述代码块之后包含以下代码：

```js
describe('Image Controller', function(){ 
    beforeEach(()=>{ 
        res = { 
            render: sinon.spy(), 
            json: sinon.spy(), 
            redirect: sinon.spy() 
        }; 
        req.params = { 
            image_id: 'testing' 
        }; 
        testImage = { 
            _id: 1, 
            title: 'Test Image', 
            views: 0, 
            likes: 0, 
            save: sinon.spy() 
        }; 
    }); 
    // to do: write tests... 
}); 
```

再次，我们将使用`beforeEach`块为我们的测试构建一些设置。这会在`res`对象的每个函数上设置间谍，包括 render、JSON 和 redirect（这些函数在`image`控制器中都被使用）。我们通过设置`req.params`对象的`image_id`属性来伪造查询字符串参数。最后，我们将创建一个测试`image`对象，该对象将被我们的假 mongoose`image`模型存根使用，以模拟从 MongoDB 返回的数据库对象：

```js
describe('Index',()=>{ 
        it('should be defined', ()=>{
            expect(image.index).to.be.defined;
        });
        it('should call Models.Image.findOne', ()=>{
            ModelsStub.Image.findOne = sinon.spy();
            image.index(req, res);
            expect(ModelsStub.Image.findOne).to.be.called;
        });
        it('should find Image by parameter id', ()=>{
            ModelsStub.Image.findOne = sinon.spy();
            image.index(req, res);
            expect(ModelsStub.Image.findOne).to.be.calledWith(
                { filename: { $regex: 'testing' } },
                 sinon.match.func
            );
        }); 
    // to do: write more tests... 
}); 
```

我们运行的第一个测试是确保`index`函数实际存在。在`index`函数中，发生的第一个动作是通过`Models.Image.findOne`函数找到`image`模型。为了测试该函数，我们首先需要将其设置为`spy`。我们之所以在这里而不是在`beforeEach`中这样做，是因为我们可能希望在每个测试中`findOne`方法的行为略有不同，所以我们不希望为所有测试设置严格的规则。

为了模拟`GET`调用被发布到我们的服务器，并且我们的图像`index`控制器函数被调用，我们可以手动触发该函数。我们使用`image.index(req, res)`并传入我们的假请求和响应对象（在`beforeEach`函数中定义为全局变量并存根）。

由于`ModelsStub.Image.findOne`是一个间谍，我们可以测试它是否被调用，然后分别测试它是否被调用时使用了我们期望的参数。在`findOne`的情况下，第二个参数是一个回调函数，我们不关心或不想测试包含的非常具体的函数，而只是确保包含了一个实际的函数。为此，我们可以使用 Sinon 的匹配器 API，并指定一个 func 或函数作为第二个参数。

这组`tests`测试了当找到图像并从`findOne`函数返回时执行的代码。

```js
describe('with found image model', ()=>{
    beforeEach(function(){
        ModelsStub.Image.findOne =
            sinon.stub().callsArgWith(1,null,testImage);
    });
    it('should incremement views by 1 and save', ()=>{
        image.index(req, res);
        expect(testImage.views).to.equal(1);
        expect(testImage.save).to.be.called;
    });
    it('should find related comments', ()=>{
        image.index(req, res);
        expect(ModelsStub.Comment.find).to.be.calledWith(
            {image_id: 1},
            {},
            { sort: { 'timestamp': 1 }},
            sinon.match.func
        );
    });
    it('should execute sidebar', ()=>{
        ModelsStub.Comment.find =
            sinon.stub().callsArgWith(3, null, [1,2,3]);
        image.index(req, res);
        expect(sidebarStub).to.be.calledWith(
            {image: testImage, comments: [1,2,3]}, sinon.match.func);
    });
    it('should render image template with image and comments', ()=>{
        ModelsStub.Comment.find = sinon.stub().callsArgWith(3, null, [1,2,3]);
        sidebarStub.callsArgWith(1, {image: testImage, comments: [1,2,3]});
        image.index(req, res);
        expect(res.render).to.be.calledWith('image', {image: testImage, comments: [1,2,3]});
    });
}); 
```

在这里你会注意到的第一件事是，在这些测试中`findOne`不再是一个间谍，而是一个存根，它将手动触发作为第二个参数提供的回调函数。被触发的回调函数将包含我们的测试`image`模型。通过这个存根，我们模拟了通过`findOne`实际进行了数据库调用，并且返回了一个有效的`image`模型。然后，我们可以测试在主回调中执行的其余代码。我们使用`Comment.find`调用进行类似的设置。

当执行`sidebarStub`时，我们使用`callsArgWith` Sinon 函数，该函数触发最初包含的回调函数。在该回调函数中，我们将假的`viewModel`作为参数包含进去。

一旦`sidebarStub`完成其工作，我们期望`res.render`已被调用，并且我们指定了我们期望它被调用的确切参数。

运行`image`控制器的测试应该产生以下输出：

```js
    $ npm test
    Image Controller
        Index
           should be defined
           should call Models.Image.findOne
           should find Image by parameter id
          with found image model
             should incremement views by 1 and save
             should find related comments
             should execute sidebar
             should render image template with image and comments

```

# 间谍和存根一切！

如果有疑问，编写测试时最安全的做法是对所有内容进行间谍，对其他所有内容进行存根。总会有时候你希望一个函数自然执行；在这种情况下，不要动它。最终，您永远不希望您的测试依赖于任何其他系统，包括数据库服务器、其他网络服务器、其他 API 等。您只想测试您自己的代码是否有效，仅此而已。如果您的代码预期调用 API，请对实际调用进行间谍，并断言您的代码尝试进行调用。同样，通过存根伪造服务器的响应，并确保您的代码正确处理响应。

检查代码中的依赖项最简单的方法是停止任何其他服务的运行（本地节点应用程序等），甚至可能禁用网络连接。如果您的测试超时或在意外的地方失败，很可能是因为您错过了需要在途中进行间谍或存根的函数。

在编写测试时不要陷入兔子洞。很容易被带入并开始测试可以安全假定正在工作的功能。一个例子是编写测试以确保第三方模块的正确执行。如果不是您编写的模块，请不要测试它。不要担心编写测试来证明模块是否按照其应有的方式工作。

要了解有关编写 JavaScript 特定的 TDD 的更多信息，我强烈建议您阅读 Christian Johansen 的巨著：*Test-Driven JavaScript Development*。这本书内容丰富，涵盖了与 TDD 相关的大量信息。在某些圈子里，TDD 确实是一种生活方式，它将定义您编写代码的风格。

# 自动化一切

没有 Gulp，测试自动化从未如此简单。Gulp 是一个开源的 JavaScript 库，提供高效的构建创建过程，并充当任务运行器。我们将使用 Gulp 通过终端中的单个命令来自动化我们的单元测试。

让我们首先使用以下命令安装所有必需的软件包：

```js
npm install gulp-cli -g
npm install gulp --save-dev
touch test/gulpfile.js
gulp --help
```

请注意，您可能需要 root 访问权限来安装`gulp-cli`的全局软件包。在这种情况下使用`sudo`，例如`sudo npm install gulp-cli -g`。我们使用`--save-dev`在本地安装 Gulp 并将其保存为`package.json`中的开发依赖项。

此外，我们在`test`目录中创建了一个 Gulp 文件。现在，要`test`我们应用程序的目录并确保我们有以下文件结构：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/webdev-mongo-node/img/bfbb4d48-2f9a-4c71-88bc-07ea63285012.png)

安装所需的软件包并创建了 Gulp 文件后，让我们开始编写一些代码，如下所示：

```js
var gulp = require('gulp');
gulp.task('default', function() {
console.log("Lets start the automation!")
});
```

返回终端，运行 Gulp，您将收到以下输出：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/webdev-mongo-node/img/49d043ab-3d77-48be-a95a-61d6320c1b97.png)

Gulp 更快，更简单；为什么呢？Gulp 使用 node.js 流将数据块通过一系列管道插件传递。这加速了内存中的处理操作，并在任务的最后执行写操作。

让我们准备扩大学习 Gulp 的范围，并自动化我们在前几节中涵盖的单元测试。我们将首先安装其他所需的 npm 软件包。请注意，我们需要在`project`文件夹中安装它们，而不是在`test`文件夹中。因此，让我们使用`cd..`回到上一步，并确保您位于项目的根目录，然后运行以下命令：

```js
npm install gulp-mocha --save-dev
```

`gulp-mocha`是运行`mocha`测试文件的插件。现在，让我们修改我们的 Gulp 文件并添加一些 es6 调料，如下所示：

```js
const gulp = require('gulp');
const gulpMocha = require('gulp-mocha')
gulp.task('test-helper',()=>gulp.src('./testhelper.js'))
gulp.task('test-server', ['test-helper'],()=>{
return gulp.src('./server/server.test.js')
.pipe(gulpMocha())
});
```

现在，运行`gulp test-server`以获得以下输出：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/webdev-mongo-node/img/d8408a50-aebd-4165-863a-12f562c73aee.png)

让我们讨论上述代码的工作原理。首先，我们创建了`test-helper`任务，它在内存中读取`testhelper.js`文件，除了存储测试`server.test.js`所需的全局变量之外什么也不做。

我们使用 mocha 作为一个框架来编写测试用例。`gulpMocha`插件通过读取`server.test.js`文件并将输出传输到终端来在内存中运行测试用例。要详细了解`gulp-mocha`，请访问[`github.com/sindresorhus/gulp-mocha`](https://github.com/sindresorhus/gulp-mocha)链接。

注意如何写入依赖项的语法结构（如果需要）。让我们通过编写一个额外的任务来澄清添加依赖的方式：

```js
gulp.task('test-routes', ['test-helper', 'test-server'],()=>{
return gulp.src('./server/routes.test.js')
.pipe(gulpMocha())
});
```

这次我们将运行`gulp test-routes`。

现在，可能会有一个关于管理这么多任务的问题。Gulp 也提供了一种解决方案，可以一次性自动化所有任务。让我们向文件中添加以下片段：

```js
gulp.task('build', ['test-helper', 'test-server','test-routes'])
```

运行上述命令；Gulp `build`和单元测试的自动化都已经完成。此外，我们可以添加所有的控制器和相应的模型，以实现基于项目的测试用例自动化。

# 总结

这绝对是一个关于测试的速成课程，但基础已经奠定，我希望你对可以用来编写自己的测试的工具链有一个扎实的理解。相信这套强大的工具组合，你将很快编写出牢固的代码！

编写测试的最终目标是实现 100%的代码覆盖率，并且为你编写的每一行代码都存在单元测试。从这里开始，真正的测试是转向 TDD，这要求你在任何代码存在之前先编写测试。显然，对不存在的代码进行测试将会失败，所以你需要编写尽量少的代码来使其通过，并重复这个过程！

在下一章中，我们将看看一些云端托管选项，以便让你的应用程序在线上运行起来。


# 第十章：使用基于云的服务部署

不可避免地，您会希望您一直在构建的应用程序在线并且对世界可用，无论您是想在开发过程中在线托管您的应用程序，还是在应用程序完成并准备投入生产时。目前有许多不同的托管选项可供 Node.js 和基于 MongoDB 的应用程序使用，在本章中，我们将介绍一些不同的热门服务的部署方式。

在这一章中，我们将涵盖以下内容：

+   云与传统 Web 托管

+   Git 源代码控制的介绍

+   使用 Nodejitsu 部署应用程序

+   使用 Heroku 部署应用程序

+   使用 Amazon Web Services 部署应用程序

+   使用 Microsoft Azure 部署应用程序

+   对 DigitalOcean 的简要介绍

# 云与传统托管

如果您之前有网站托管的经验，我将称之为传统托管，您可能对使用 FTP 上传网页文件到托管提供商的过程非常熟悉。在传统 Web 托管中，服务提供商通常为每个用户提供共享空间，每个用户都配置有自己的公共文件夹，用于存放网页文件。在这种情况下，每个客户都托管相同类型的网站，他们的文件都存储在同一台 Web 服务器上并由其提供服务。

传统的 Web 托管成本相对较低，因为单个 Web 服务器可以托管成百上千个个人网站。传统托管通常存在扩展性问题，因为如果您的网站需要更多的资源，它需要被迁移到另一台服务器（具有更多硬件），并且在此迁移过程中可能会出现潜在的停机时间。作为一个副作用，如果与您的网站位于同一服务器上的网站对硬件要求特别高，那么该服务器上的每个网站都可能会受到影响。

使用基于云的托管，每个网站或服务的实例都托管在自己的虚拟专用服务器（VPS）上。当客户上传其网站的副本时，该网站在其自己的隔离环境中运行，并且该环境专门设计用于仅运行该网站。虚拟专用服务器是服务器的实例，通常都同时在同一硬件上运行。由于其隔离性质，VPS 的扩展性非常好，因为只需更改硬件分配的设置，服务器就会重新启动。如果您的 VPS 托管在与其他 VPS 相同的硬件上，并且它们正在经历高流量峰值，您的网站不会因 VPS 的隔离性质而受到影响。

# 基础设施即服务与平台即服务

云的美妙之处在于可以获得的服务级别和数量变化很大。对于运行您的 Web 应用程序的基本托管计划，您可以使用许多被视为平台即服务（PaaS）的服务。这是一种为您提供托管和运行 Web 应用程序的平台。随着规模和复杂性的增加，您可以转向提供整个基于云的数据中心的基础设施即服务（IaaS）提供商。

您可以通过阅读一篇详细的文章了解 IaaS、PaaS 和软件即服务（SaaS）之间的区别，该文章可在[`www.rackspace.com/knowledge_center/whitepaper/understanding-the-cloud-computing-stack-saas-paas-iaas`](http://www.rackspace.com/knowledge_center/whitepaper/understanding-the-cloud-computing-stack-saas-paas-iaas)上找到。

基于云的托管成本可能会有很大的变化，因为它们非常可扩展。您的成本可能会在一个月内发生剧烈波动，这取决于您对资源的需求（即，在一个月中需求更高的时间和/或像 HackerNews 或 Reddit 这样的大型社交媒体的点击）。另一方面，如果您对服务器的需求非常小，您通常可以免费获得云托管！

传统的 Web 托管服务提供商包括 GoDaddy、Dreamhost、1&1、HostGator 和 Network Solutions。热门的基于云的托管选项包括 Nodejitsu（PaaS）、Heroku（PaaS）、Amazon Web Services（IaaS）、Microsoft Azure（IaaS）和 Digital Ocean。

# Git 简介

对于传统的托管提供商，连接到服务器并上传文件的标准方法是使用**文件传输协议**（**FTP**）。您可以使用任何标准的 FTP 软件进行连接，并将文件副本推送到服务器，这些更改将在访问您的网站 URL 时立即反映在线。对于基于云的托管提供商，标准通常是使用 Git 源代码控制。Git 是一种源代码控制技术，允许您跟踪项目源代码的更改和历史，以及提供与多个开发人员轻松协作的简便方法。目前最受欢迎的 Git 在线代码存储库提供商是[www.github.com](http://www.github.com)。

我们将使用 Git 来跟踪我们的应用项目源代码，并将我们的代码推送到各种云托管提供商。当您使用 Git 推送代码时，您实际上是将所有或仅更改版本的代码传输到在线存储库（例如，Git 和[www.github.com](http://www.github.com)相对容易进入，但可能看起来令人生畏和复杂）。如果您对 Git 和/或[`GitHub.com`](https://GitHub.com)不熟悉，我强烈建议您花点时间通过查看以下指南来熟悉：

+   [`help.github.com/articles/set-up-git`](https://help.github.com/articles/set-up-git)

+   [`gist.github.com/andrewpmiller/9668225`](https://gist.github.com/andrewpmiller/9668225)

指南将带您了解以下概念：

+   下载和安装 Git

+   在[`github.com`](https://github.com)注册帐户

+   使用[`github.com`](https://github.com)对您的计算机进行身份验证并创建您的第一个存储库

+   将项目源代码提交到存储库

一旦您将项目源代码配置为本地 Git 存储库，并且所有代码都提交到主分支，就可以继续阅读以下各节。

# 部署您的应用程序

现在，您已经将项目设置为本地 GitHub 存储库，是时候将该代码上线了！接下来的各节将分别介绍将应用程序部署到几个不同的热门基于云的托管提供商的过程。

请随意探索和尝试每个提供商，因为大多数都有免费或相对便宜的计划。每个提供商都有其优势和劣势，所以我将由您决定哪个适合您的特定需求。我们介绍的服务没有特定的顺序。

为了本章的目的，我将一贯地将我的应用命名为`imgploadr`；但是，您的应用名称需要不同和独特。在本章中，无论我何时提到`imgploadr`，您都应该用您自己应用的独特名称替换它。

# Nodejitsu

要开始使用 Nodejitsu，请访问[www.nodejitsu.com](http://www.nodejitsu.com)并首先注册一个免费帐户。在提供您的电子邮件地址、用户名和密码后，您将看到一个定价计划页面，您可以在该页面配置您的服务。如果您只想创建免费帐户并进行实验，只需单击“不，谢谢”按钮，注册过程就完成了。然后，只需单击右上角的“登录”按钮即可登录并转到您的应用程序仪表板。

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/webdev-mongo-node/img/c7398050-dfa5-4944-99b2-a69b657b3c89.png)

将您的应用程序部署到 Nodejitsu 将需要一个新的命令行界面工具；具体来说，是`jitsu` CLI。单击大蓝色的使用 jitsu 部署应用程序按钮将带您到此工具的[www.github.com](http://www.github.com)存储库。您可以跳过这一步，只需使用以下`npm`命令手动安装 CLI：

```js
    $ sudo npm install -g-g install jitsu
```

安装`npm`包时，有时需要使用`sudo`命令来全局安装（使用`-g`标志）。取决于您所使用的机器的访问级别，您可能需要或者不需要包括`sudo`。

现在`jitsu` CLI 已安装，您可以使用这个方便的工具来登录到您的 Nodejitsu 帐户，创建一个应用程序，并部署您的项目代码。首先，让我们登录：

```js
$ jitsu login 
info:    Welcome to Nodejitsu 
info:    jitsu v0.13.18, node v0.10.26 
info:    It worked if it ends with Nodejitsu ok 
info:    Executing command login 
help:    An activated nodejitsu account is required to login 
help:    To create a new account use the jitsu signup command 
prompt: username:  jkat98 
prompt: password: 
info:    Authenticated as jkat98 
info:    Nodejitsu ok 
```

您可以看到，在成功提供用户名和密码后，您现在已经通过 Nodejitsu 进行了身份验证，准备好开始了。

在我们实际部署应用程序之前，我们需要在 Nodejitsu 仪表板中配置 MongoDB 数据库。切换回浏览器，在 Nodejitsu 应用程序仪表板上，通过单击数据库选项卡切换部分。

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/webdev-mongo-node/img/135e760f-d109-4013-8f8f-94fd238cc1eb.png)

通过单击大的 MongoHQ 按钮，让我们选择 MongoHQ 来满足我们的需求。您将被提示为新数据库命名，然后它将在屏幕底部的“您的数据库”部分列出。我们需要的重要部分是连接字符串，旁边有一个方便的复制链接，可以将其复制到剪贴板。

编辑`server.js`文件，并更新`mongoose.connect`行以使用您为 Nodejitsu 数据库复制的新连接字符串：

```js
[/server.js] 
mongoose.connect('YOUR_NODEJITSU_CONNECTION_STRING_HERE'); 
mongoose.connection.on('open', ()=>{ 
    console.log('Mongoose connected.'); 
}); 
```

唯一剩下的就是打开终端，切换到项目主目录，并执行以下命令来打包您的应用程序并将其推送到 Nodejitsu：

```js
$ jitsu deploy 
info:    Welcome to Nodejitsu jkat98 
info:    jitsu v0.13.18, node v0.10.26 
info:    It worked if it ends with Nodejitsu ok 
info:    Executing command deploy 
warn:  
warn:    The package.json file is missing required fields: 
warn: 
warn:      Subdomain name 
warn: 
warn:    Prompting user for required fields. 
warn:    Press ^C at any time to quit. 
warn: 
prompt: Subdomain name:  (jkat98-imgploadr) imgploadr 
warn:    About to write /Users/jasonk/repos/nodebook/imgploadr/package.json 
... (a lot of npm install output) ... 
info:    Done creating snapshot 0.0.1 
info:    Updating app myapp 
info:    Activating snapshot 0.0.1 for myapp 
info:    Starting app myapp 
info:    App myapp is now started 
info:    http://imgploadr.nodejitsu.com on Port 80 
info:    Nodejitsu ok
```

执行`jitsu deploy`后，CLI 首先会提示您确认在[www.nodejitsu.com](http://www.nodejitsu.com)域名下的子域名是什么。随意更改为您喜欢的内容（它将检查确认可用性）。然后，它会对您的`package.json`文件进行一些微小的修改，具体包括使用您提供的任何值包括`subdomain`选项。最后，它会上传您的源代码并执行远程`npm install`操作。假设一切顺利，应用程序应该已部署，并且 URL 的确认应该输出到屏幕上。随意在浏览器中打开该 URL 以查看在线应用程序！

现在，您还可以看到应用程序在应用程序仪表板中列出：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/webdev-mongo-node/img/40844f95-248b-4505-93e8-5dc413ba1d82.jpg)

现在应用程序已成功上传，通过其 URL 启动它，并尝试上传一个新图像进行测试运行。您应该注意到的第一件事是，尝试上传图像失败，并显示一个相当无用的错误（您可以通过从应用程序仪表板的日志选项卡访问以下错误）：

```js
400 Error: ENOENT, open 
'/opt/run/snapshot/package/public/upload/temp/72118-89rld0.png 
```

这个错误远非有用！基本上，这里发生的是应用程序试图上传并保存图像到实际上并不存在的`temp`文件夹！我们需要向我们的应用程序添加一小段代码来检查这种情况，并在必要时创建文件夹。

编辑`server/configure.js`文件，并在`routes(app);`和`return app;`之间插入以下代码片段：

```js
// Ensure the temporary upload folders exist 
        fs.mkdir(path.join(__dirname, '../public/upload'), 
         (err)=>{ 
            console.log(err); 
            fs.mkdir(path.join(__dirname, 
'../public/upload/temp'),  
                (err)=>{ 
                    console.log(err); 
                }); 
        }); 
```

在这里，我们使用文件系统`fs`模块来创建父`upload`文件夹和`temp`子文件夹。也不要忘记在文件顶部`require` `fs`模块：

```js
const connect = require('connect'), 
    path = require('path'), 
    routes = require('./routes'), 
    exphbs = require('express3-handlebars'), 
    moment = require('moment'), 
    fs = require('fs'); 
```

有一个名为`node-mkdirp`的`npm`模块，它将执行递归的`mkdir`，基本上实现了我们在前面示例中调用的双重`mkdir`。我之所以没有包括它，是为了简洁起见，不包括额外的安装模块、要求它并不必要地使用它的指示。更多信息可以在[`www.npmjs.org/package/mkdirp`](https://www.npmjs.org/package/mkdirp)找到。

在对代码进行了上述更改后，你需要再次部署你的应用程序。只需执行另一个`jitsu deploy`，你的代码的新副本将被上传到你的实例：

```js
$ jitsu deploy 
```

再次打开你的应用程序 URL，这次你应该能够与应用程序进行交互并成功上传新的图片！恭喜，你已成功部署了你的应用程序，现在它正在使用 Nodejitsu 托管服务在线运行！

# Heroku

另一个流行的基于云的 Node.js 应用程序托管提供商是[www.Heroku.com](http://www.Heroku.com)。Heroku 与其他提供商的一个不同之处在于其提供的强大附加组件的数量。任何你能想象到的你的应用程序需要的服务都可以作为附加组件使用，包括数据存储、搜索、日志和分析、电子邮件和短信、工作和排队、监控和媒体。这些附加组件可以快速而轻松地添加到你的服务中，并集成到你的应用程序中。

与 Nodejitsu 一样，Heroku 允许你注册一个免费帐户，并在其*沙箱*定价计划范围内工作。这些计划是免费的，但在带宽、处理能力等方面有限。大多数，如果不是全部，附加组件通常也提供某种免费的沙箱或基于试用的计划。与 Nodejitsu 一样，我们将在 Heroku 应用程序中使用的附加组件之一是 MongoHQ，一个基于云的 MongoDB 服务提供商。

首先，去[`heroku.com`](http://heroku.com)注册一个免费帐户。虽然注册不需要信用卡，但是为了在你的应用程序中包含任何附加组件，你必须在文件中提供信用卡（即使你不选择扩展服务，也不会被收费）。注册后，点击确认电子邮件中的链接并提供密码；你将看到你的应用程序仪表板。

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/webdev-mongo-node/img/eed40703-a4d0-4d18-8035-9968d35e4bb7.png)

请注意，你需要做的第一件事是下载 Heroku Toolbelt（与 Nodejitsu 的`jitsu` CLI 类似）。点击下载按钮下载并安装 Toolbelt。Toolbelt 是一个专门用于创建和部署应用程序到 Heroku 的 CLI，并提供了`heroku`命令。

安装 Toolbelt 后，打开命令行终端并切换到项目的根目录。然后执行以下命令

登录 Heroku：

```js
    $ heroku login
    Enter your Heroku credentials.
    Email: jkat98@gmail.com
    Password (typing will be hidden):
    Authentication successful.

```

现在你已经登录，可以直接向 Heroku 发出命令了

帐户并使用这些命令来创建应用程序，安装附加组件并部署你的项目。

你需要做的第一件事是创建一个新的应用程序。通过在命令行中执行`heroku create`来完成：

```js
    $ heroku create
    Creating secret-shore-2839... done, stack is cedar
    http://secret-shore-2839.herokuapp.com/ | git@heroku.com:secret-
 shore-2839.git

```

创建应用程序后，Heroku 会随机分配一个唯一的名称；在我的情况下是`secret-shore-2839`（不过不用担心，这很容易改变）：

```js
    $ heroku apps:rename imgploadr --app secret-shore-2839
    Renaming secret-shore-2839 to imgploadr... done
    http://imgploadr.herokuapp.com/ | git@heroku.com:imgploadr.git
    Don't forget to update your Git remotes on any local checkouts.

```

让我们接下来解决最后一部分。Heroku 依赖于你机器上的 Git 源代码控制，以便将你的项目源代码推送到服务器，而不像 Nodejitsu 那样使用自己的文件传输机制。假设你之前按照关于 Git 和[www.github.com](http://www.github.com)的说明进行了操作，你的项目源代码应该已经准备就绪并提交到主分支，准备好了。接下来我们需要做的是在你的机器上为 Git 添加一个指向 Heroku 的新远程。

让我们从`git init`开始，在当前工作目录中初始化`git`，然后执行以下命令为 Heroku 创建一个新的远程：

```js
    $ git remote add heroku git@heroku.com:imgploadr.git
```

在将源代码推送到 Heroku 帐户之前，我们需要处理一些事情。

在您的 Heroku 服务器上运行应用程序之前，需要一个特殊的文件。这个文件称为`Procfile`，它专门包含启动应用程序所需的命令。在项目的根目录中创建一个名为`Procfile`（无扩展名）的新文件，并包含以下行：

```js
    web: node server.js 
```

就是这样！有了那个文件，Heroku 将使用该命令启动您的应用程序。现在您已经设置了`Procfile`并且您的项目源代码已准备就绪，只剩下一件事要做--安装 MongoHQ 附加组件并配置您的应用程序以使用它：

```js
    $ heroku addons:create mongohq --app imgploadr
    Adding mongohq on imgploadr... done, v3 (free)
    Use 'heroku addons:docs mongohq' to view documentation.
```

添加了 MongoHQ 附加组件后，您现在可以配置数据库本身并检索连接字符串（就像您之前在 Nodejitsu 中所做的那样）。访问您的[`heroku.com`](http://heroku.com)应用程序仪表板，它应该看起来像以下截图：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/webdev-mongo-node/img/4991395a-bda2-4621-980b-56564bf02f32.png)

应用程序的仪表板屏幕是获取应用程序快照和快速查看当前成本的好地方。由于我正在为我的应用程序和附加组件使用沙箱和/或免费计划，我的当前预计月费用为$0.00。但是，如果您需要更多的功能，您可以快速轻松地扩展您的应用程序。请注意，您也可以快速轻松地将您的月费用飙升到天际！（将所有内容扩展到最大，我能够将我的预计费用提高到大约每月$60,000！）。

要配置您的 MongoHQ 数据库，只需在应用程序仪表板的附加组件部分下点击 MongoHQ 链接：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/webdev-mongo-node/img/6ae6d0cd-0d61-4134-8027-2e0245c59c21.jpg)

点击 Collections 标签下方的带有齿轮图标的 Admin 标签。点击 Users 标签，并提供应用程序将用于连接 MongoHQ 数据库的用户名和密码。这将创建具有安全密码的`imgploadrdb`用户名。添加新用户后，切换回概述标签并复制 Mongo URI 字符串。

就像在 Nodejitsu 中一样，编辑项目中的`server.js`文件，并用刚刚复制的新 URI 替换`mongoose.connect`字符串。编辑字符串，并根据您刚刚创建的新用户帐户的情况，用适当的值替换`<username>`和`<password>`。`server.jsmongoose.connect`代码应如图所示：

```js
mongoose.connect('mongodb://imgploadrdb:password@kahana.mongohq.co
 m:10089/app26'); 
mongoose.connection.on('open', ()=>{ 
    console.log('Mongoose connected.'); 
});
```

由于您刚刚对项目的源代码进行了更改，因此需要记住将这些更改提交到 Git 存储库的主分支，以便它们可以上传到 Heroku。执行以下命令，将这些更改永久提交到您的源代码并将代码上传到 Heroku 服务器：

```js
    $ git commit -am "Update mongoose connection string"
    $ git push heroku master
    Initializing repository, done.
    Counting objects: 50, done.
    Delta compression using up to 8 threads.
    Compressing objects: 100% (43/43), done.
    Writing objects: 100% (50/50), 182.80 KiB | 0 bytes/s, done.
    Total 50 (delta 3), reused 0 (delta 0)
    ... npm install output ...
    To git@heroku.com:imgploadr.git
     * [new branch]      master -> master

```

将应用程序启动的最后一步是创建服务器的实例（基本上相当于打开它）。要做到这一点，执行以下命令：

```js
    $ heroku ps:scale web=1 --app imgploadr
    Scaling dynos... done, now running web at 1:1X.
    $ heroku open
    Opening imgploadr... done

```

成功！希望您的浏览器已启动并且您的网站正在运行。继续，尝试上传一张图片！由于我们在 Nodejitsu 部署期间发现的错误，这个应用程序的更新版本应该可以正常工作。

虽然使用 Heroku 部署似乎比 Nodejitsu 更复杂，这可能是因为它使用 Git 源代码控制来促进项目文件的传输。此外，由于 Heroku 在扩展和附加组件的功能方面非常灵活，因此 Toolbelt CLI 更加强大。

# 亚马逊网络服务

虽然 Nodejitsu 和 Heroku 可以被认为是开发人员级别的服务提供商，因为它们是 PaaS，但亚马逊网络服务（和微软 Azure）将被认为是企业级服务，因为它们更像是 IaaS。AWS 和 Azure 提供的选项和服务的数量是令人震惊的。这绝对是顶级服务，像我们这样托管应用程序就像用火箭筒打苍蝇一样！

AWS 确实提供了自己的 NoSQL 数据库，称为 DynamoDB，但是对于我们的目的，我们希望继续使用 MongoDB 并在我们的应用程序中使用 Mongoose。为此，我们可以使用第三方 MongoDB 提供商。如果你还记得，当我们最初设置 Nodejitsu 时，列出的一个 MongoDB 提供商是 MongoLab。MongoLab 提供**MongoDB 作为服务**，这意味着我们可以使用它的服务来托管我们的 MongoDB 数据库，但使用 AWS 的所有功能来托管我们的 Node.js 应用程序（这与 Nodejitsu 和 Heroku 已经发生的情况并没有太大不同；它们只是更好地简化了这个过程）。请记住，AWS 是一个 IaaS 提供商，所以你也可以创建另一个服务器实例并自己安装 MongoDB，并将其用作数据源。但是，这略微超出了本章的范围。

# 创建 MongoLab 帐户和数据库

为了在 AWS 中使用 MongoLab，我们首先需要在[`mlab.com/`](https://mlab.com/)上注册一个新帐户并创建 AWS 数据库订阅。注册新帐户并使用他们通过电子邮件发送给你的链接进行激活后，你可以创建你的第一个数据库订阅。

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/webdev-mongo-node/img/9bd62362-3612-43b7-88d0-ff9e03c301de.png)

从你的主仪表板上，点击创建新按钮（带闪电图标）

闪电图标）。

从创建新订阅页面，配置以下设置：

+   云提供商：亚马逊网络服务

+   位置：你喜欢的任何地区

+   计划：选择单节点（开发）

+   选择沙盒（共享/免费）

+   MongoDB 版本：`2.4.x`

+   数据库名称：`anything_you_want`（我选择了`imgploadr`）

+   确认价格为每月$0

+   点击创建新的 MongoDB 部署

回到你的主仪表板，你现在应该看到你的新数据库已经创建并准备就绪。我们需要做的下一件事是创建一个用户帐户，我们的应用程序将用它来连接服务器。点击主仪表板上列出的数据库，然后选择用户选项卡。提供一个新的用户名和密码。添加新用户帐户后，复制位于屏幕顶部的 URI（只有在添加用户后才会出现）以`mongodb://`开头。

现在你有了新的 URI 连接字符串，我们需要更新`server.js`以在`mongoose.connect`中包含这个新的连接字符串。编辑文件并使用以下代码进行更新：

```js
mongoose.connect('mongodb://imgploadrdb:password@ds061248.mongolab
 .com:61248/imgploadr'); 
mongoose.connection.on('open', ()=>{ 
    console.log('Mongoose connected.'); 
}); 
```

确保用 MongoLab 仪表板上创建的用户帐户的适当信息替换`<username>`和`<password>`。

将我们的应用程序代码更新为指向新的 MongoLab 数据库连接字符串后，我们需要将项目文件压缩，以便可以通过 AWS 仪表板上传。从你计算机的文件浏览器中，找到包含所有应用程序源代码文件的项目根目录，选择它们所有，右键单击它们以添加到存档或 ZIP 文件中。ZIP 文件的名称可以是任何你选择的。需要注意的一点是，你不应该在这个 ZIP 文件中包含`node_modules`文件夹（最简单的解决方案可能是直接删除整个文件夹）。如果你需要更多信息，AWS 在线文档有一个关于创建 ZIP 文件的很好的介绍（[`docs.aws.amazon.com/elasticbeanstalk/latest/dg/using-features.deployment.source.html`](https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/using-features.deployment.source.html)）。

一旦你的源代码已经更新为使用新的 MongoLab 连接字符串，并且你已经创建了整个项目的 ZIP 文件（不包括`node_modules`文件夹），你就可以创建新的 AWS 应用程序并部署你的应用程序了。

# 创建和配置 AWS 环境

如果您还没有亚马逊帐户，您需要一个才能使用他们的 AWS 服务。将浏览器指向[`aws.amazon.com`](http://aws.amazon.com)，然后点击注册（即使您已经有亚马逊帐户）。在随后的屏幕上，您可以使用现有的亚马逊帐户登录或注册一个新帐户。注册并登录后，您将看到 AWS 提供的整套云服务。

我们感兴趣的主要服务是弹性 Beanstalk（位于部署和管理下，带有绿色图标）：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/webdev-mongo-node/img/1bbff13f-5a46-4007-8623-7fb52c338d51.jpg)

从此屏幕，点击右上角的创建新应用程序链接。随后的屏幕将引导您完成一个多步向导过程，在其中您将配置应用程序所在的环境。在适当的情况下配置以下设置：

+   应用程序信息：

+   应用程序名称：`任何你想要的`

+   环境类型：

+   环境层：`Web 服务器`

+   预定义配置：`Node.js`

+   环境类型：`负载均衡`，`自动扩展`

+   应用程序版本：

+   上传您自己的（选择之前创建的 ZIP 文件）

+   环境信息：

+   环境名称：`任何你想要的`

+   环境 URL：`任何你想要的`（这是您应用程序的子域）

+   配置详情：

+   实例类型：`t1.micro`

其余字段可以留空或使用它们的默认值

+   环境标签：跳过此步骤；对于此应用程序是不必要的

最后一步是审查配置设置，然后启动环境（点击蓝色的 Launch 按钮）。

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/webdev-mongo-node/img/c084bb2c-9f8f-4c84-9c31-0ec876a31f7f.png)

弹性 Beanstalk 可能需要几分钟来配置和启动您的环境

应用程序，所以您可能需要耐心等待。环境正式启动并且应用程序在线后，继续打开您的应用程序（点击页面顶部的链接）并进行测试运行。假设一切按计划进行，您的应用程序应该已经启动并且应该正常运行！

# 微软 Azure

微软的 Azure 服务与亚马逊的 AWS 非常相似。两者都可以被视为企业级服务，并且都提供了极大的灵活性和功能，具有非常流畅的用户界面。令人惊讶的是，尽管它是微软产品，您也可以使用 Azure 启动 Linux 环境的实例，以及托管您的 Node.js 和 MongoDB 应用程序。

您需要的第一件事，就像任何其他服务一样，是在[`azure.microsoft.com`](http://azure.microsoft.com)注册帐户。如果您有一个现有的 Microsoft Live 登录，您可以使用它；否则，您可以相当容易地注册一个新帐户。一旦您登录到 Azure 服务，您将首先看到的是您的主要仪表板。左边的图标是 Azure 提供的各种服务和选项。

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/webdev-mongo-node/img/1e6ff7d5-9fb1-45cd-9820-6b1e4f130ae7.png)

点击左下角的+NEW 图标将呈现给您

可以用来添加任何新服务的主要对话框。对于我们的目的，我们希望

添加网站：

1.  选择计算、网站和从库中选择。

1.  从众多的库选项中选择 Node JS Empty Site。这将创建必要的环境，以便您有一个可以放置应用程序的地方。

1.  在随后的屏幕上，提供您应用程序的 URL。

1.  将其余字段保留为默认值。

1.  点击对勾图标完成设置过程，您的网站将被创建。

1.  下一步是设置数据库服务器。与 AWS 或 Nodejitsu 类似，我们将再次选择 MongoLab 作为我们的数据库服务提供商。

1.  再次点击+NEW 图标，选择 Store，并浏览列表，直到找到并选择 MongoLab。

1.  点击下一个箭头并浏览各种计划。对于我们的需求，我们将保留 Sandbox 选项（因为它是免费的）。

1.  为您的数据库提供一个名称；在我的情况下，我输入了`imgploadrdb`。

1.  再次单击下一步以查看和确认计划和每月价格（应为每月$0.00）。

1.  最后，单击复选标志图标以购买这个新的订阅计划。

几秒钟后，您应该会回到仪表板，在那里您将看到网站和数据库应用服务的条目：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/webdev-mongo-node/img/fb1656ca-1da9-4573-889b-d0efd47375c2.png)

现在数据库已经创建并准备就绪，我们需要在应用程序中包含其连接字符串，然后才能上传我们的代码：

1.  单击数据库行以选择它并转到其概述。

1.  屏幕底部将包含一些图标，其中一个标有连接信息（并且有一个看起来像>i 的图标）。单击该图标，会弹出一个模态窗口，其中包含您的新 MongoLab 数据库服务器的连接字符串 URI。

1.  将该 URI 复制到剪贴板。

1.  编辑本地应用程序中的`server.js`，并用刚刚复制的新字符串替换`mongoose.connect`连接字符串。无需更新`username`和`password`，因为 Azure 已经使用以下代码为您处理了这个问题：

```js
mongoose.connect('mongodb://your_specific_azure_
                  mongolab_uri'); 
mongoose.connection.on('open', ()=>{ 
    console.log('Mongoose connected.'); 
});
```

一旦更改完成，保存文件，并不要忘记使用 Git 更新您的本地 Git 存储库，因为在下一节中我们将使用 Git 将您的代码推送到 Azure（就像我们之前在 Heroku 上做的那样）：

```js
    $ git commit -am "Azure connection string"
```

回到 Azure 仪表板，在所有项目列表中单击 Web Site（或使用左侧工具栏上的图标筛选网站）。从概述屏幕中，找到朝向底部的集成源控制部分，并单击设置从源控制进行部署的链接。以下屏幕截图显示了此时您应该看到的内容：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/webdev-mongo-node/img/29b5fb99-253e-447f-b760-bd49458a4fa5.png)

选择本地 Git 存储库，然后通过单击下一个箭头图标继续。

接下来的屏幕将呈现如何将本地代码推送到刚刚为您的 Azure 网站创建的远程 Git 存储库的说明。要点是添加一个指向 Azure 存储库的新 Git 远程（就像我们之前在 Heroku 上做的那样），然后推送您的代码：

```js
    $ git remote add azure SPECIFIC_URL_FOR_YOUR_SERVER
    $ git push azure master  
```

当您的代码开始在`git push`命令之后推送时，您应该注意到 Azure 仪表板中的 Git 信息屏幕会实时更新。从命令行中，您将看到大量远程`npm install`输出。完成后，Azure 仪表板中的部署历史将更新，显示最后一次活动部署的信息。

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/webdev-mongo-node/img/4b10af1f-3a09-42c9-8a3e-a5a4640d65f1.png)

现在，您的代码已部署到 Azure 网站，并且您的网站连接字符串指向您的 MongoLab Azure 应用服务，您已经准备好测试网站运行情况了。通过将浏览器指向[`yourappname.azurewebsites.net`](http://yourappname.azurewebsites.net)来启动它。Azure 做了很多正确的事情（UI/UX），并且提供了一些非常强大的选项和扩展功能！快速浏览网站仪表板（上述屏幕截图），您会发现有很多事情正在进行。

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/webdev-mongo-node/img/bfa39f54-7930-4030-9a86-f10cbfb1c16f.png)

有许多不同的配置选项，以及健康监控和一般信息（FTP 设置，网站 URL，使用度量等），所以请随意查看和探索。

# Digital Ocean

我想要提到并简要介绍的最后一个服务是 Digital Ocean - [`digitalocean.com`](http://digitalocean.com)。Digital Ocean 是一个真正的**虚拟专用服务器**（**VPS**）服务提供商，是一个让您尽可能*接近底层*的服务的很好的例子。这意味着 Digital Ocean 实际上并没有其他我们看到的服务所提供的所有花里胡哨的功能。然而，Digital Ocean 提供的是对您所创建的 Linux 服务器实例的直接、未经过滤的访问，在这种情况下被称为**Droplets**。

Digital Ocean 允许您快速启动新的 Linux 虚拟服务器实例。他们提供非常有竞争力的价格，如果您需要快速获取 Linux 服务器，因为您只需要短时间内的一个，或者您想要启动自己的 Linux 服务器，用于托管生产环境，那么他们是一个很好的选择。唯一的*缺点*（如果我不得不这样说的话）是您必须对 Linux 非常熟悉，特别是对服务器管理和相关责任。

您可以在新的 Droplet 上使用 Git 非常容易地克隆您的项目，但新 Droplet 的实际原始性的一个例子是，Git 不会默认安装在服务器上。您需要在克隆存储库之前手动安装 Git。取决于您在创建新 Droplet 时决定克隆哪个镜像，您可能还需要安装和配置 Node.js 以及 MongoDB。幸运的是，Digital Ocean 在创建新服务器时提供了许多预定义的服务器供您选择，其中包括**MongoDB，Express，Angular**和**Node.js**（**MEAN**）堆栈。除此之外，实际上启动您的应用程序只会在您当前登录的会话期间运行；一旦您退出登录，您的应用程序就会关闭。您需要进一步管理服务器，配置您的应用程序以作为服务运行。

Digital Ocean 允许您直接使用网站内的控制台访问工具连接到您的服务器，或者通过在自己的计算机上的终端直接使用 SSH 连接：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/webdev-mongo-node/img/551b8d9d-c20d-48d3-b477-6e98e6307c0f.jpg)

我之所以提到 Digital Ocean，是因为很多人会觉得这种原始的力量非常令人耳目一新，并且希望自己动手配置和维护他们的服务器。Digital Ocean 是一个很棒的服务，但并不适合每个人。我之所以特别想谈论它，是因为我觉得它完善了我们迄今为止所涵盖的服务列表。

# 总结

我们已经涵盖了基于云的托管服务提供商的整个范围，并介绍了配置您的服务和部署项目代码。Nodejitsu 和 Heroku 是更多面向开发人员的优秀服务，并通过非常易于访问和流畅的用户界面赋予他们很大的权力。亚马逊和微软，作为行业巨头，代表了您可以期望的企业级服务提供商的实力和复杂性。Digital Ocean 是一个无花俏、*接近底层*的基于云的 VPS 提供商，牺牲了花里胡哨的功能，以换取对服务器的原始和直接访问。

我们涵盖的所有托管选项都很棒，但并不是唯一的选择。它们只是一个样本，但它们展示了云的力量！在几分钟内，几乎没有成本，您就可以配置一个环境，并让您的网站在线运行！

在下一章中，我们将介绍单页应用程序的概念以及流行的客户端开发框架和工具。


# 第十一章：流行的 Node.js Web 框架

在本书中，我们专注于使用 Express.js 作为我们的首选 Web 框架，主要是因为它是 Node.js 最流行的 Web 开发框架之一。它已经存在了相当长的时间，并且被广泛使用。然而，还有许多可供选择的替代框架，我想向您介绍。其中一些框架比 Express.js 更强大和稳健，而另一些则与之相当，或者功能稍微少一些。

在本章中，我们将简要介绍以下框架：

+   Koa

+   Meteor

+   Sails

+   Flatiron

+   total.js

+   loopback

+   Hapi

最后，我们将使用 Hapi 中的一个框架来构建一个服务器 API。这个服务器 API 将在下一章中由 Angular 4 构建的客户端应用程序使用。构建这个 Web 应用程序的整个目的是研究如何根据项目选择框架，以及不同的框架有不同的特点，但都建立在 Node.js 的共同平台上。

# Koa

**Koa**是由创建 Express.js 的同一团队设计的新的 Web 框架。Koa 的目标是更小、更有表现力，以及更坚固的 Web 应用程序基础。Express 框架的创建者 T J Holowaychuk 也是 Koa 的创建者，你可以看到它将大部分的功能都集中在生成器上，这是其他流行编程语言中的特性，比如 Python、C#和 Ruby。生成器是在 ECMAScript 6 中引入到 JavaScript 中的。生成器可以防止在 Node.js 开发过程中常见的回调地狱。Koa 具有轻量级的架构，因此它不包含任何中间件；相反，它将实现某些功能的选择留给开发人员。

有关 Koa 和示例实现的更多信息可以在其网站以及[`github.com/koajs/koa`](https://github.com/koajs/koa)上找到。

# Meteor

**Meteor**是一个简单而完整的 Web 框架，旨在让任何技能水平的开发人员能够在较短的时间内构建强大的 Web 应用程序。

它具有一个方便的 CLI 工具，可以快速搭建新项目。

Meteor 提供了一些核心项目/库，例如 blaze、DDP、livequery 等，具有统一的构建系统。这简化了整个开发过程，并提供了一致的开发者体验。

Meteor 旨在通过在服务器端提供分布式数据协议和在客户端端提供透明的反应式渲染来构建实时应用程序。有关更多详细信息，请访问[`meteor.com/features`](http://meteor.com/features)。

该框架的另一个显著特点是其广泛的包系统，名为**atmosphere**，其中包含了大多数常见应用程序的模块

用例。

它正在迅速获得关注，并且每天都变得越来越受欢迎。目前，它的 GitHub 存储库已经拥有超过 38,000 个星标！

有关 Meteor 的更多信息可以在其网站以及其官方 GitHub 存储库[`github.com/meteor/meteor`](https://github.com/meteor/meteor)上找到。

# Sails

**Sails**是另一个用于使用 Node.js 构建 Web 应用程序的出色的 MVC 框架

有时会将自己与 Ruby on Rails 进行比较。与 Meteor 不同，Sails 是数据库无关的，因此您选择哪种数据存储方式并不重要。Sails 包括一些方便的脚手架工具，例如自动生成 RESTful API 的工具。`Socket.io`，

一个用于 Node.js 的实时通信框架，内置在 Sails 中，因此，在应用程序中包含实时功能应该是轻而易举的。Sails 具有一些不错的生产级自动化功能，通常需要由诸如 Grunt.js 或 Gulp 之类的工具来处理（包括前端 CSS 和 JavaScript 的最小化和捆绑）。Sails 还包括应用程序的基本安全性和基于角色的身份验证，如果您需要该级别的功能。与 Express 相比，Sails 可以被认为是一个更全面的企业级框架，因为它几乎具有像 Rails 这样的流行框架的每个功能。Sails 网站位于[`sailsjs.com`](http://sailsjs.com)。

有关 Sails 的更多信息可以在其网站上找到，以及其官方 GitHub 存储库[`github.com/balderdashy/sails`](https://github.com/balderdashy/sails)。

# Flatiron

**Flatiron**是另一个 Node.js MVC Web 应用程序框架。Flatiron 与其他框架的不同之处在于其基于包的方法。由于它赋予了决定框架应该包含多少或多少的权力和自由，开发人员可以挑选并选择他们想要使用并包含在项目中的包。它通过提供一个强大的 ODM 来处理大部分基本数据管理职责和 CRUD，从而为您处理大部分繁重的工作。

有关 Flatiron 的更多信息可以在其网站上找到，以及其官方 GitHub 存储库[`github.com/flatiron/flatiron`](https://github.com/flatiron/flatiron)。

# total.js

另一个 Node.js HMVC 框架是 total.js。正如其名称所示，它提供了从 Web 应用程序到 IOT 应用程序的全面解决方案。你说一个功能，`total.js`都有；这就是`total.js`的特点。它支持大量功能，如图像处理、工作者、生成器、静态文件处理、站点地图、缓存机制、SMTP 等等。

减少使用第三方模块的需求。它在过去三年中得到了强大的社区支持，并且再次成为一个可以在功能开发的各个方面超越其他框架的强大竞争者。

关注所有更新的链接：[`www.totaljs.com/`](https://www.totaljs.com/)。

# LoopBack

IBM 和 StrongLoop 设计了最强大的现代 Node 框架之一，名为**LoopBack**。启动 API 服务器所需的工作量很小。LoopBack 内部有一个名为 API 资源管理器的客户端，它记录 API 并同时提供 API 测试。它是 Sails 框架的强有力竞争者，具有就绪的结构，并且在需要时完全可配置。它具有**访问控制列表**（**ACL**）、移动客户端 SDK、基于约定的配置编码，当然还有 IBM 支持的团队，将长期维护项目。

您可以在以下链接开始使用 LoopBack：[`loopback.io/`](https://loopback.io/)。

# Hapi

**Hapi**是沃尔玛在线移动网站背后团队的成果。构建该网站的团队开发了一套丰富的 Node.js 实用程序和库，可以在**Spumko umbrella**下找到。考虑到沃尔玛网站在任何给定日子都会收到大量流量，沃尔玛实验室的团队在涉及 Node.js 开发和最佳实践时无疑是游刃有余。Hapi 是从现实世界的试错中诞生的 Web 框架。Hapi 网站位于[`hapijs.com`](http://hapijs.com)。

有关 Hapi 的更多信息可以在其网站上找到，以及其官方 GitHub 存储库[`github.com/spumko/hapi`](https://github.com/spumko/hapi)。在下一节中，我们将在 Hapi 框架中实现一组 API。

# 启动 Hapi.js

在之前的章节中，我们学习并实现了 Express 框架。Express 社区将其称为最简档的框架，因此它提供了性能优势。对于构建任何应用程序，选择正确的框架是应用程序可扩展性的最重要因素之一。在 Hapi 的情况下，它具有不同的路由机制，通过其可配置的代码模式提高了应用程序的性能。开发人员始终建议考虑框架提供的所有优势和劣势，以及应用程序的功能实现和长期目标。让我们通过一个小型原型来了解 Hapi 框架。

以下步骤提供了使用电话簿示例逐步学习 Hapi 框架实现的经验。建议在阅读时进行编码以获得更好的学习效果。

# 搭建 Hapi 应用程序

创建一个名为 phone book-API 的目录，并通过``cd phonebook-api``导航到该目录。使用`npm init`初始化一个 node 项目，并完成`npm`提供的问卷调查。使用以下命令安装 Hapi 框架：

```js
npm install hapi --save
```

# 设置服务器

首先要编写的文件必须是一个`server`文件，所以让我们创建一个``server.js``。使用`hapi`框架启动`server`所需的最小代码如下：

```js
const hapi = require('hapi');
const server = new hapi.Server();
server.connection({
    host: 'localhost',
    port: 8000,
    routes: { cors: true }
});
// Start the server
server.start((err) => {
    if (err) {
        throw err;
    }
    console.log('Server running at:', server.info.uri);
});
```

在审查了前面的代码之后，我们可以观察到`hapi`通过首先配置所有必需的数据来启动其服务器。它以主机和端口作为输入，然后最终启动服务器。如果我们将其与 express 进行比较，express 首先需要一个回调作为输入，然后才是监听部分。

# 创建 API

下一个重要的步骤是创建路由。在任何框架中实现路由时，始终建议遵循模块化，以便长期维护代码。话虽如此，让我们创建一个`routes.js`文件。由于我们不打算使用诸如 MongoDB 或 MySQL 之类的数据库，让我们为支持数据源创建一个名为`phonebook.json`的`json`文件。让我们在`json`文件中创建以下数据：

```js
{
 "list": [
 {
   "phone_no": 1212345678,
   "name": "Batman"
 },
 {
   "phone_no": 1235678910,
   "name": "Superman"
 },
 {
   "phone_no": 9393939393,
   "name": "Flash"
 }]
}
```

我们的 API 目录结构如下：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/webdev-mongo-node/img/2d90008a-d7e7-4d24-920d-5f60e0a7a65d.png)

# 创建基于配置的架构

`hapi`的配置代码模式随处可见，甚至用于创建路由。让我们通过在下面的片段中添加一个简单的`GET`方法和它的处理程序来理解它：

```js
let phonebook = require('./phonebook');
module.exports = [{
    method: 'GET',
    path: '/phone/list',
    config: {
        handler(request, reply) {
            reply({
                message: "phonebook of superheroes",
                data: phonebook.list
            });
        }
    }
}]
```

上面的片段显示了创建路由所需的最小配置。它包括`request`方法，可以是`'GET'`、`'POST'`等；用于 URL 导航目的的 URL 路径；以及包含请求处理程序的`config`属性。此处理程序用于在收到请求时编写各种业务逻辑。

现在，在`server.js`中包含路由文件，并在服务器启动之前将路由分配给`hapi`服务器。因此，总结一下，在`server.js`中有以下代码：

```js
const hapi = require('hapi');
const server = new hapi.Server();
const routes = require('./routes');
server.connection({
    host: 'localhost',
    port: 8000,
    routes: { cors: true }
});
//Add the routes
server.route(routes);
// Start the server
server.start((err) => {
    if (err) {
        throw err;
    }
    console.log('Server running at:', server.info.uri);
});
```

让我们在浏览器中访问路由并查看响应：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/webdev-mongo-node/img/03d443fd-2f95-4ea8-9e34-0fbe3fdf1d23.jpeg)

同样，我们可以添加、更新和删除电话簿中的条目。我们的`routes.js`将如下所示：

```js
let phonebook = require('./phonebook');
module.exports = [{
    method: 'GET',
    path: '/phone/list',
    config: {
        handler(request, reply) {
            reply({
                message: "phonebook of superheroes",
                data: phonebook.list
            });
        }
    }
}, {
    method: 'POST',
    path: '/phone/add',
    config: {
        handler(request, reply) {
            let payload = request.payload;
            phonebook.list.unshift(payload);
            reply({
                message: "Added successfully",
                data: phonebook.list
            });
        }
    }
}, {
    method: 'PUT',
    path: '/phone/{phno}',
    config: {
        handler(request, reply) {
            let payload = request.payload;
            let phno = request.params.phno;
            var notFound = [];
            for (let i = phonebook.list.length - 1; i >= 0; i--) {
                if (phonebook.list[i].phone_no == phno) {
                    phonebook.list[i].name = payload.name;
                    reply(phonebook.list);
                    return;
                } else {
                    notFound.push(i);
                }
            }
            if (notFound.length == phonebook.list.length) {
                reply('not Found');
                return;
            }
        }
    }
}, {
    method: 'DELETE',
    path: '/phone/{phno}',
    config: {
        handler(request, reply) {
            let phno = request.params.phno;
            var notFound = [];
            for (let i = phonebook.list.length - 1; i >= 0; i--) {
                if (phonebook.list[i].phone_no == phno) {
                    phonebook.list.splice(i, 1);
                    reply({
                        message: "Delete successfully",
                        data: phonebook.list
                    });
                    return;
                } else {
                    notFound.push(i);
                }
            }
            if (notFound.length == phonebook.list.length) {
                reply('not Found');
                return;
            }
        }
    }
}];
```

我们需要使用浏览器扩展来测试前面的 REST API。POSTMAN 是 REST API 调用的流行扩展之一。请参考第八章，了解 POSTMAN 的详细信息。

哇！我们的服务器 API 已经准备就绪。在下一章中，我们将通过创建一个前端应用程序来使用这些 API 调用。

# 概要

尽管我们在本书中专门使用了 Express.js，但在使用 Node.js 创建 Web 应用程序时还有许多其他选项可供选择。我们研究了

本章介绍了其中一些选项，包括 Meteor、Sails、Hapi、Koa 和 Flatiron。每个框架都有其自身的优势和劣势，以及对 Web 应用程序所需的标准功能的独特方法。

就是这样，伙计们！我希望使用 Node.js 和 MongoDB 构建 Web 应用程序的不同方面能够带领读者以渐进的方式学习和开发一个令人惊叹的想法。嗯，这只是个开始。我建议您关注您自己应用程序中将要使用的所有技术或库的开发者社区。

使用 Node.js 进行 Web 开发的美妙之处在于如何完成单个任务没有意见的短缺。MVC 框架也不例外，从本章可以看出，有很多功能强大且功能丰富的框架可供选择。
