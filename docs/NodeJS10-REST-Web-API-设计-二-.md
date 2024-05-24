# NodeJS10 REST Web API 设计（二）

> 原文：[`zh.annas-archive.org/md5/557690262B22107951CBB4677B02B662`](https://zh.annas-archive.org/md5/557690262B22107951CBB4677B02B662)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：Restful API 设计指南

在上一章中，我们实现了一个目录模块，该模块公开了目录应用程序中项目数据操作的函数。这些函数利用了`express.js` **request**对象来解析传入的数据，并执行适当的数据库操作。每个函数都使用相关的状态码和响应主体有效载荷填充了**response**对象（如果需要）。最后，我们将每个函数绑定到一个路由，接受 HTTP 请求。

现在，是时候更仔细地查看路由的 URL 和每个操作返回的 HTTP 状态码了。

在本章中，我们将涵盖以下主题：

+   端点 URL 和 HTTP 状态码最佳实践

+   可扩展性和版本控制

+   链接数据

# 端点 URL 和 HTTP 状态码最佳实践

每个 RESTful API 操作都是针对 URL 的 HTTP 请求和适当的 HTTP 方法的组合。

执行时，每个操作将返回一个状态码，指示调用是否成功。成功的调用由 HTTP 2XX 状态码表示，而未正确执行的操作则用错误的状态码表示——如果错误发生在客户端，则为 4XX，或者当服务器无法处理有效请求时为 5xx。

拥有明确定义的 API 对于其采用至关重要。这样的规范不仅应完全列举每个操作的状态码，还应指定预期的数据格式，即其支持的媒体类型。

以下表格定义了 Express.js 路由器将如何公开 API 操作，并应作为其参考规范：

| 方法 | URI | 媒体类型 | 描述 | 状态码 |
| --- | --- | --- | --- | --- |
| GET | /catalog | application/json | 返回目录中的所有项目。 | 200 OK500 Internal Server Error |
| GET | /catalog/{categoryId} | application/json | 返回所选类别的所有项目。如果类别不存在，则返回 404。 | 200 OK,404 NOT FOUND500 Internal Server Error |
| GET | /item/{itemId} | application/json | 返回所选 itemId 的单个项目。如果没有这样的项目，则返回 404。 | 200 OK,404 NOT FOUND500 Internal Server Error |
| POST | /item/ | application/json | 创建新项目；如果具有相同标识符的项目存在，则将更新。创建项目时，将返回**Location**标头。它提供了可以访问新创建项目的 URL。 | 201 Created200 OK500 Internal Server Error |
| PUT | /item/{itemId} | application/json | 更新现有项目；如果提供的标识符不存在项目，则创建项目。创建项目时，将返回**Location**标头。它提供了可以访问新创建项目的 URL。 | 201 Created200 OK500 Internal Server Error |
| DELETE | /item/{itemId} | application/json | 删除现有项目；如果提供的标识符不存在项目，则返回 404。 | 200 OK,404 NOT FOUND500 Internal Server Error |

目录应用程序处理两种类型的实体：项目和类别。每个项目实体包含它所属的类别集合。正如你所看到的，类别只是我们应用程序中的一个逻辑实体；只要至少有一个项目引用它，它就会存在，并且当没有项目引用它时就会停止存在。这就是为什么应用程序只为项目类型的资源公开路由来公开数据操作功能，而类别的操作基本上是只读的。仔细观察暴露项目数据操作操作的 URL，我们可以看到一个清晰的模式，将 URL 与 REST 基本原则对齐——一个资源由一个单一的 URL 公开，并支持由请求的 HTTP 方法确定的资源操作。总之，以下是一个良好定义的 API 应该遵循的普遍接受的规则。它们在语义上与每个资源操作相关联：

+   当**新**资源被创建时，服务使用**201 已创建**状态码，后跟指定新创建资源的 URL 的位置标头。

+   创建资源的操作可以被实现为优雅地拒绝已经使用唯一标识符的资源的创建；在这种情况下，操作应该用适当的状态码**409 冲突**指示不成功的调用，或者更一般的**400 错误请求**。然而，通用状态码应该始终跟随一个有意义的解释，说明出了什么问题。在我们的实现中，我们选择了一种不同的方法——如果资源存在，我们会从创建操作中更新资源，并通过返回**200 OK**状态码通知调用者资源已被更新，而不是**201 已创建**。

+   **更新**操作类似于创建操作；然而，它总是期望资源标识符作为参数，如果存在具有此标识符的资源，它将使用 HTTP PUT 请求中提供的新状态对其进行更新。**200 OK**状态码表示成功的调用。实现可以决定使用**404 未找到**状态码拒绝处理不存在的资源，或者使用传递的标识符创建新资源。在这种情况下，它将返回**201 已创建**状态码，后跟指定新创建资源的 URL 的位置标头。我们的 API 使用了第二个选项。

+   成功的**删除**可以用**204 无内容**状态和进一步的有效载荷来表示，但大多数用户代理会期望**2xx**HTTP 状态后跟一个主体。因此，为了与大多数代理保持兼容，我们的 API 将用**200 OK**状态码表示成功的删除，后跟 JSON 有效载荷：`{'状态'：'成功删除'}`。状态码**404 未找到**将表示提供的标识符不存在的资源。

+   一般规则是，**5XX**不应该表示应用程序状态错误，而应该表示更严重的错误，比如应用程序服务器或数据库故障。

+   最佳实践是，`更新`和`创建`操作应该作为资源的整个状态返回有效载荷。例如，如果使用最少的属性创建资源，所有未指定的属性将获得默认值；响应主体应该包含对象的完整状态。对于更新也是一样；即使更新操作部分更新资源状态，响应也应该返回完整状态。这可能会节省用户代理额外的 GET 请求，如果他们需要检查新状态的话。

现在我们已经定义了一些关于操作应该如何行为的一般建议，是时候在 API 的新版本中实现它们了。

# 可扩展性和版本控制

我们已经在第三章*构建典型的 Web API*中定义了一些基本的版本规则。让我们将它们应用到我们在上一章中实施的 MongoDB 数据库感知模块。我们的起点将是使 API 的当前消费者能够继续在不同的 URL 上使用相同的版本。这将使他们向后兼容，直到他们采用并成功测试新版本。

保持 REST API 的稳定性不仅仅是将一个端点从一个 URI 移动到另一个 URI 的问题。进行重定向然后拥有行为不同的 API 是没有意义的。因此，我们需要确保移动端点的行为保持不变。为了确保我们不改变先前实施的行为，让我们将当前行为从`catalog.js`模块移动到一个新模块，将文件重命名为`catalogV1.js`。然后，将其复制到`catalogV2.js`模块，我们将在其中引入所有新功能；但在这之前，我们必须将版本 1 从`/, /{categoryId}, /{itemId}`重定向到`/v1, /v1/{categoryId}, /v1/{itemId}`：

```js
const express = require('express');
const router = express.Router();

const catalogV1 = require('../modules/catalogV1');
const model = require('../model/item.js');

router.get('/v1/', function(request, response, next) {
  catalogV1.findAllItems(response);
});

router.get('/v1/item/:itemId', function(request, response, next) {
  console.log(request.url + ' : querying for ' + request.params.itemId);
  catalogV1.findItemById(request.params.itemId, response);
});

router.get('/v1/:categoryId', function(request, response, next) {
  console.log(request.url + ' : querying for ' + request.params.categoryId);
  catalogV1.findItemsByCategory(request.params.categoryId, response);
});

router.post('/v1/', function(request, response, next) {
  catalogV1.saveItem(request, response);
});

router.put('/v1/', function(request, response, next) {
  catalogV1.saveItem(request, response);
});

router.delete('/v1/item/:itemId', function(request, response, next) {
  catalogV1.remove(request, response);
});

router.get('/', function(request, response) {
  console.log('Redirecting to v1');
  response.writeHead(301, {'Location' : '/catalog/v1/'});
  response.end('Version 1 is moved to /catalog/v1/: ');
});

module.exports = router;
```

由于我们的 API 的第 2 版尚未实施，对`/`执行`GET`请求将导致接收到`301 Moved Permanently`的 HTTP 状态，然后重定向到`/v1/`。这将通知我们的消费者 API 正在发展，并且他们很快将需要决定是继续使用版本 1，通过显式请求其新 URI，还是准备采用版本 2。

继续尝试吧！启动修改后的节点应用程序，并从 Postman 向`http://localhost:3000/catalog`发出 GET 请求：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/rst-webapi-dsn-node10/img/8476e742-7eb8-4e0b-8417-74cb895bf664.png)

您将看到您的请求被重定向到新路由位置`http://localhost:3000/catalog/v1`。

现在我们已经完成了目录的第 1 版，是时候考虑我们可以在第 2 版中添加的进一步扩展了。目录服务目前支持列出类别中的所有商品和按 ID 获取商品。是时候充分利用 MongoDB 了，作为一个面向文档的数据库，并实现一个函数，使我们的 API 消费者能够根据商品的任何属性查询商品。例如，列出具有与查询参数匹配的属性的特定类别的所有商品，如价格或颜色，或按商品名称搜索。RESTful 服务通常公开面向文档的数据。但是，它们的使用不仅限于文档。在下一章中，我们将扩展目录，使其还可以存储二进制数据——可以链接到每个商品的图像。为此，我们将在第六章的*使用任意数据*部分中使用 MongoDB 的二进制格式**二进制 JSON**（**BSON**）。

回到搜索扩展，我们已经使用了`Mongoose.js`模型的`find()`和`findOne()`函数。到目前为止，我们在 JavaScript 代码中静态地使用它们来提供要搜索的文档属性的名称。然而，`find()`的这个过滤参数只是一个 JSON 对象，其中键是文档属性，值是要在查询中使用的属性的值。这是我们将在第 2 版中添加的第一个新函数。它通过任意属性和其值查询 MongoDB：

```js
exports.findItemsByAttribute = function (key, value, response) {
      var filter = {};
      filter[key] = value;
      CatalogItem.find(filter, function(error, result) {
          if (error) {
              console.error(error);
              response.writeHead(500, contentTypePlainText);
              response.end('Internal server error');
              return;
          } else {
              if (!result) {
                  if (response != null) {
                     response.writeHead(200, contentTypeJson);
                     response.end({});
                  }
                  return;
              }
              if (response != null){
                  response.setHeader('Content-Type', 'application/json');
                  response.send(result);
              }
          }
      });
    }
```

这个函数调用模型上的 find，并将提供的属性和值作为参数。我们将把这个函数绑定到路由器的`/v2/item/` GET 处理程序。

最后，我们的目标是有`/v2/item/?currency=USD`，它只返回以美元货币出售的商品记录，由传递的 GET 参数的值指示。这样，如果我们修改模型并添加额外的属性，比如颜色和尺寸，我们可以查询具有相同颜色或任何其他商品属性的所有商品。

当在查询字符串中没有提供参数时，我们将保留返回所有可用项目的旧行为，但我们还将解析查询字符串以获取第一个提供的`GET`参数，并将其用作`findItemsByAttribute()`函数中的过滤器：

```js
router.get('/v2/items', function(request, response) {
    var getParams = url.parse(request.url, true).query;
    if (Object.keys(getParams).length == 0) {
      catalogV2.findAllItems(response);
    } else {
      var key = Object.keys(getParams)[0];
      var value = getParams[key];
      catalogV2.findItemsByAttribute(key, value, response);
    }
});
```

也许这个函数中最有趣的部分是 URL 解析。正如你所看到的，我们继续使用相同的旧策略来检查是否提供了任何`GET`参数。我们解析 URL 以获取查询字符串，然后我们使用内置的`Object.keys`函数来检查解析的键/值列表是否包含元素。如果是，我们取第一个元素并提取其值。键和值都传递给`findByAttribute`函数。

您可能希望通过多个`GET`参数提供的搜索支持来进一步改进版本 2。我将把这留给你作为一个练习。

# 发现和探索 RESTful 服务

发现 RESTful 服务的主题有着悠久而复杂的历史。HTTP 规范规定资源应该是自描述的，并且应该通过 URI 唯一标识。依赖资源应该通过其自己的唯一 URI 链接到依赖项。发现 RESTful 服务意味着从一个服务导航到另一个服务，跟随它提供的链接。

在 2009 年，发明了一种名为**Web Application Discovery Language**（**WADL**）的规范。它旨在记录从 Web 应用程序公开的每个 URI，以及它支持的 HTTP 方法和它所期望的参数。还描述了 URI 的响应媒体类型。这对于文档目的非常有用，这就是 WADL 文件在 RESTful 服务供应方面能为我们提供的一切。

不幸的是，目前还没有一个 Node.js 模块可以自动生成给定 express 路由的 WADL 文件。我们将不得不手动创建一个 WADL 文件来演示它如何被其他客户端用于发现。

以下清单显示了描述`/catalog, /catalog/v2/{categoryId}`处可用资源的示例 WADL 文件：

```js
<?xml version="1.0" encoding="UTF-8"?>
<application   >
   <grammer>
      <include href="items.xsd" />
      <include href="error.xsd" />
   </grammer>
   <resources base="http://localhost:8080/catalog/">
      <resource path="{categoryId}">
         <method name="GET">
            <request>
               <param name="category" type="xsd:string" style="template" />
            </request>
            <response status="200">
               <representation mediaType="application/xml" element="service:item" />
               <representation mediaType="application/json" />
            </response>
            <response status="404">
               <representation mediaType="text/plain" element="service:item" />
            </response>
         </method>
      </resource>
      <resource path="/v2/{categoryId}">
         <method name="GET">
            <request>
               <param name="category" type="xsd:string" style="template" />
            </request>
            <response status="200">
               <representation mediaType="application/xml" element="service:item" />
               <representation mediaType="application/json" />
            </response>
            <response status="404">
               <representation mediaType="text/plain" element="service:item" />
            </response>
         </method>
      </resource>
   </resources>
</application>
```

正如你所看到的，WADL 格式非常简单直接。它基本上描述了每个资源的 URI，提供了关于它使用的媒体类型以及在该 URI 处预期的状态码的信息。许多第三方 RESTful 客户端都理解 WADL 语言，并可以根据给定的 WADL 文件生成请求消息。

让我们在 Postman 中导入 WADL 文件。点击导入按钮并选择你的 WADL 文件：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/rst-webapi-dsn-node10/img/76025807-8835-49ba-9603-bc52076d0565.png)

在 Postman 中导入一个 WADL 文件以获得服务的存根。这是 Postman 的一个截图。这里个别设置并不重要。图片的目的只是为了展示窗口的外观。

正如你所看到的，导入 WADL 文件的结果是，我们有一个准备好测试 REST 服务的项目。WADL 文件中定义的所有路由现在都方便地作为右侧菜单上的单独请求实体可用。除了 WADL 标准之外，目前 swagger 文档格式也被广泛采用，并已成为描述 RESTful 服务的非正式标准，因此我们也可以使用它来简化服务的采用和发现。在下一章中，我们将把这些描述文件绑定到我们的服务上。这是生产准备阶段的重要步骤。

# 链接数据

每个目录应用程序都支持与该项目绑定的图像或一组图像。为此，在下一章中，我们将看到如何在 MongoDB 中处理二进制对象。然而，现在是决定如何在项目文档中语义链接二进制数据的时候了。以这样的方式扩展模型架构，使其包含文档中二进制数据的 base64 表示，绝非明智之举，因为在一个格式中混合文字编码和二进制数据从来都不是一个好主意。这增加了应用程序的复杂性，并使其容易出错。

```js
{
  "_id": "5a4c004b0eed73835833cc9a",
  "itemId": "1",
  "itemName": "Sports Watch",
  "price": 100,
  "currency": "EUR",
  "categories": [
    "Watches",
    "Sports Watches"
  ],
  "image":" 
iVBORw0KGgoAAAANSUhEUgAAAJEAAACRCAMAAAD0BqoRAAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAAAyJpVFh0WE1MOmNvbS5hZG9iZS54bXAAAAAAADw/eHBhY2tldCBiZWdpbj0i77u/IiBpZD0iVzVNME1wQ2VoaUh6cmVTek5UY3prYzlkIj8+IDx4OnhtcG1ldGEgeG1sbnM6eD0iYWRvYmU6bnM6bWV0YS8iIHg6eG1wdGs9IkFkb2JlIFhNUCBDb3JlIDUuMC1jMDYwIDYxLjEzNDc3NywgMjAxMC8wMi8xMi0xNzozMjowMCAgICAgICAgIj4gPHJkZjpSREYgeG1sbnM6cmRmPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5LzAyLzIyLXJkZi1zeW50YXgtbnMjIj4gPHJkZjpEZXNuzjcmlwdGlvbiByZGY6YWJvdXQ9IiIgeG1sbnM6eG1wPSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvIiB4bWxuczp4bXBNTT0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wL21tLyIgeG1sbnM6c3RSZWY9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC9zVHlwZS9SZXNvdXJjZVJlZiMiIHhtcDpDcmVhdG9yVG9vbD0iQWRvYmUgUGhvdG9zaG9wIENTNSBNYWNpbnRvc2giIHhtcE1NOkluc3RhbmNlSUQ9InhtcC5paWQ6MjMwNjQ1NDdFNjJCMTFERkI5QzU4OTFCMjJCQzEzM0EiIHhtcE1NOkRvY3VtZW50SUQ9InhtcC5kaWQ6MjMwNjQ1NDhFNjJCMTFERkI5QzU4OTFCMjJCQzEzM0EiPiA8eG1wTU06RGVyaXZlZEZyb20gc3RSZWY6aW5zdGFuY2VJRD0ieG1wLmlpZDoyMzA2NDU0NUU2MkIxMURGQjlDNTg5MUIyMkJDMTMzQSIgc3RSZWY6ZG9jdW1lbnRJRD0ieG1wLmRpZDoyMzA2NDU0NkU2MkIxMURGQjlDNTg5MUIyMkJDMTMzQSIvPiA8L3JkZjpEZXNjcmlwdGlvbj4gPC9yZGY6UkRGPiA8L3g6eG1wbWV0YT4gPD94cGFja2V0IGVuZD0iciI/Px5Xq1XXhWFY1+v151/b3ij5tI/GPEVP0e8U/SPAABPLjHnaJ6XvAAAAAElFTkSuQmCC 
"} 
```

想象一下，如果所有这些项目都将图像二进制表示作为 JSON 属性的值返回，那么一个非过滤查询的结果会变得多么庞大，即使只有几百个项目。为了避免这种情况，我们将返回每个项目的图像，其 URL 在逻辑上与资源的 URL 链接在一起—`/catalog/v2/item/{itemId}/image`。

这样，如果为一个项目分配了图像，它将被提供在一个已知的位置。然而，这种方法并没有在语义上将二进制项目与其对应的资源链接起来，因为当访问`/catalog/v2/item/{itemId}`时，没有迹象表明它是否分配了图像。为了解决这个问题，让我们在项目路由的响应中使用自定义的 HTTP 头部：

```js
GET http://localhost:3000/catalog/v2/item/1 HTTP/1.1 
Host: localhost:3000 
Connection: Keep-Alive 
User-Agent: Apache-HttpClient/4.1.1 (java 1.5) 

HTTP/1.1 200 OK 
X-Powered-By: Express 
Content-Type: application/json; charset=utf-8 
Content-Length: 152 
Image-Url: http://localhost:3000/catalog/v2/item/1/image
ETag: W/"98-2nJj2mZdLV2YDME3WYCyEwIXfuA" 
Date: Thu, 01 Feb 2018 13:50:43 GMT 
Connection: keep-alive 

{
  "_id": "5a4c004b0eed73835833cc9a",
  "itemId": "1",
  "itemName": "Sports Watch",
  "price": 100,
  "currency": "EUR",
  "__v": 0,
  "categories": [
    "Watches",
    "Sports Watches"
  ]
}
```

当在响应中存在时，`Image-Url`头部指示该项目有一个额外的资源与之绑定，并且头部值提供了它可用的地址。使用这种方法，我们在语义上将一个二进制资源链接到我们的文档。

在下一章中，我们将实现处理目录中项目的任意项目的路由。

# 总结

在本章中，我们详细讨论了资源应该如何通过 RESTful API 公开；我们密切关注了 URL 最佳实践，并研究了 HTTP 状态代码的适当使用，指示我们操作的每个状态。

我们涵盖了版本控制和可扩展性的主题，我们使用`301 Moved Permanently`状态代码自动将 API 调用重定向到不同的 URL。

最后，我们找出了如何将我们的资源项目与任意二进制表示的数据语义链接起来。


# 第六章：实现一个完整的 RESTful 服务

到目前为止，我们已经创建了我们的 RESTful 服务的第二个版本，并且通过不同的 URL 公开了这两个版本，确保向后兼容。我们为其数据库层实现了单元测试，并讨论了如何适当地使用 HTTP 状态码。在本章中，我们将通过为服务的第二个版本提供处理非文档二进制数据的功能，并相应地将其链接到相关的文档来扩展该实现。

我们将研究一种方便的方式来向消费者呈现大型结果集。为此，我们将引入分页以及进一步的过滤功能到我们的 API 中。

有些情况下，应该考虑将数据响应缓存起来。我们将研究它的好处和缺点，并在必要时决定启用缓存。

最后，我们将深入探讨 REST 服务的发现和探索。

总之，以下是应该进一步实现的内容，以将目录数据服务转变为一个完整的 RESTful 服务：

+   处理任意数据

+   在现实世界中处理关联数据

+   分页和过滤

+   缓存

+   发现和探索

# 处理任意数据

MongoDB 使用 BSON（二进制 JSON）作为主要数据格式。它是一种二进制格式，将键/值对存储在一个称为**文档**的单个实体中。例如，一个样本 JSON，`{"hello":"world"}`，在 BSON 中编码后变成`\x16\x00\x00\x00\x02hello\x00\x06\x00\x00\x00world\x00\x00`。

BSON 存储的是数据而不是文字。例如，如果一张图片要作为文档的一部分，它不需要被转换成 base64 编码的字符串；相反，它将直接以二进制数据的形式存储，而不像普通的 JSON 通常会将这样的数据表示为 base64 编码的字节，但这显然不是最有效的方式。

Mongoose 模式通过模式类型**buffer**使得能够以 BSON 格式存储二进制内容。它可以存储二进制内容（图片、ZIP 归档等）高达 16MB。相对较小的存储容量背后的原因是为了防止在传输过程中过度使用内存和带宽。

**GridFS**规范解决了 BSON 的这一限制，并使您能够处理大于 16MB 的数据。GridFS 将数据分成存储为单独文档条目的块。默认情况下，每个块的大小最多为 255KB。当从数据存储中请求数据时，GridFS 驱动程序检索所有必需的块，并按照组装的顺序返回它们，就好像它们从未被分割过一样。这种机制不仅允许存储大于 16MB 的数据，还使消费者能够以部分方式检索数据，这样就不必完全加载到内存中。因此，该规范隐含地支持流支持。

GridFS 实际上提供了更多功能——它支持存储给定二进制数据的元数据，例如其格式、文件名、大小等。元数据存储在一个单独的文件中，并且可以用于更复杂的查询。有一个非常有用的 Node.js 模块叫做`gridfs-stream`。它可以方便地在 MongoDB 中进行数据的流入和流出，就像所有其他模块一样，它被安装为一个`npm`包。因此，让我们全局安装它并看看它的使用方法；我们还将使用`-s`选项来确保项目的`package.json`中的依赖项得到更新：

```js
    npm install -g -s gridfs-stream
```

要创建一个`Grid`实例，你需要打开到数据库的连接：

```js
const mongoose = require('mongoose')
const Grid = require('gridfs-stream');

mongoose.connect('mongodb://localhost/catalog');
var connection = mongoose.connection;
var gfs = Grid(connection.db, mongoose.mongo);   
```

通过`createReadStream()`和`createWriteStream()`函数来进行流的读取和写入。流入数据库的每一部分数据都必须设置一个`ObjectId`属性。`ObjectId`唯一标识二进制数据条目，就像它在 MongoDB 中标识任何其他文档一样；使用这个`ObjectId`，我们可以通过这个标识符从 MongoDB 集合中找到或删除它。

让我们扩展目录服务，添加用于获取、添加和删除分配给项目的图像的功能。为简单起见，该服务将支持每个项目一个图像，因此将有一个负责添加图像的单个函数。每次调用时，它都将覆盖现有图像，因此适当的名称是`saveImage`：

```js
exports.saveImage = function(gfs, request, response) {

    var writeStream = gfs.createWriteStream({
            filename : request.params.itemId,
            mode : 'w'
        });

        writeStream.on('error', function(error) {
            response.send('500', 'Internal Server Error');
            console.log(error);
            return;
        })

        writeStream.on('close', function() {
            readImage(gfs, request, response);
        });

    request.pipe(writeStream);
}
```

如您所见，我们只需创建一个 GridFS 写流实例即可刷新 MongoDB 中的数据。它需要一些选项，这些选项提供了 MongoDB 条目的`ObjectId`以及一些附加的元数据，例如标题以及写入模式。然后，我们只需调用请求的 pipe 函数。管道将导致将数据从请求刷新到写入流中，以此方式将其安全存储在 MongoDB 中。存储后，与`writeStream`关联的`close`事件将发生，这时我们的函数将读取数据库中存储的任何内容，并在 HTTP 响应中返回该图像。

检索图像是另一种方式——使用选项创建`readStream`，`_id`参数的值应为任意数据的`ObjectId`，可选文件名和读取模式：

```js
function readImage(gfs, request, response) {

  var imageStream = gfs.createReadStream({
      filename : request.params.itemId,
      mode : 'r'
  });

  imageStream.on('error', function(error) {
    console.log(error);
    response.send('404', 'Not found');
    return;
  });

  response.setHeader('Content-Type', 'image/jpeg');
  imageStream.pipe(response);
}
```

在将读取流传输到响应之前，必须设置适当的`Content-Type`标头，以便可以将任意数据以适当的图像媒体类型`image/jpeg`呈现给客户端。

最后，我们从我们的模块中导出一个函数，用于从 MongoDB 中获取图像。我们将使用该函数将其绑定到从数据库中读取图像的 express 路由：

```js
exports.getImage = function(gfs, itemId, response) {
     readImage(gfs, itemId, response);
};
```

从 MongoDB 中删除任意数据也很简单。您必须从两个内部 MongoDB 集合`fs.files`和`fs.files.chunks`中删除条目，其中存放着所有文件：

```js
exports.deleteImage = function(gfs, mongodb, itemId, response) {
  console.log('Deleting image for itemId:' + itemId);

    var options = {
            filename : itemId,
    };

    var chunks = mongodb.collection('fs.files.chunks');
    chunks.remove(options, function (error, image) {
        if (error) {
            console.log(error);
            response.send('500', 'Internal Server Error');
            return;
       } else {
           console.log('Successfully deleted image for item: ' + itemId);
       }
    });

    var files = mongodb.collection('fs.files');
    files.remove(options, function (error, image) {
        if (error) {
            console.log(error);
            response.send('500', 'Internal Server Error');
            return;
        }

        if (image === null) {
            response.send('404', 'Not found');
            return;
        } else {
           console.log('Successfully deleted image for primary item: ' + itemId);
           response.json({'deleted': true});
        }
    });
}

```

让我们将新功能绑定到适当的项目路由并进行测试：

```js
router.get('/v2/item/:itemId/image',
  function(request, response){
    var gfs = Grid(model.connection.db, mongoose.mongo);
    catalogV2.getImage(gfs, request, response);
});

router.get('/item/:itemId/image',
  function(request, response){
    var gfs = Grid(model.connection.db, mongoose.mongo);
    catalogV2.getImage(gfs, request, response);
});

router.post('/v2/item/:itemId/image',
  function(request, response){
    var gfs = Grid(model.connection.db, mongoose.mongo);
    catalogV2.saveImage(gfs, request, response);
});

router.post('/item/:itemId/image',
  function(request, response){
    var gfs = Grid(model.connection.db, mongoose.mongo);
    catalogV2.saveImage(gfs, request.params.itemId, response);
});

router.put('/v2/item/:itemId/image',
  function(request, response){
    var gfs = Grid(model.connection.db, mongoose.mongo);
    catalogV2.saveImage (gfs, request.params.itemId, response);
});

router.put('/item/:itemId/image',
function(request, response){
  var gfs = Grid(model.connection.db, mongoose.mongo);
  catalogV2.saveImage(gfs, request.params.itemId, response);
});

router.delete('/v2/item/:itemId/image',
function(request, response){
  var gfs = Grid(model.connection.db, mongoose.mongo);
  catalogV2.deleteImage(gfs, model.connection,
  request.params.itemId, response);
});

router.delete('/item/:itemId/image',
function(request, response){
  var gfs = Grid(model.connection.db, mongoose.mongo);
  catalogV2.deleteImage(gfs, model.connection,  request.params.itemId, response);
});
```

由于在撰写本文时，版本 2 是我们 API 的最新版本，因此其提供的任何新功能都应在`/catalog`和`/v2/catalog`两个位置都可用。

让我们启动 Postman 并将图像发布到现有项目，假设我们有一个 ID 为 14 的项目`/catalog/v2/item/14/image`：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/rst-webapi-dsn-node10/img/7ea0b135-ca19-4e61-b44e-aa82e7959b6a.png)

使用 Postman 分配图像给项目的 Post 请求。这是 Postman 的屏幕截图。这里个别设置并不重要。图像的目的只是为了展示窗口的外观。

请求处理后，二进制数据存储在网格数据存储中，并且图像在响应中返回。

# 链接

在上一章的链接数据部分，我们定义了如果目录中的项目分配了图像，则将使用名为 Image-URL 的 HTTP 标头进行指示。

让我们修改目录 V2 中的`findItemById`函数。我们将使用 GridFS 的现有功能来检查所选项目是否绑定了图像；如果项目分配了图像，则其 URL 将在响应中可用，并带有 Image-Url 标头：

```js
exports.findItemById = function (gfs, request, response) {
    CatalogItem.findOne({itemId: request.params.itemId}, function(error, result) {
        if (error) {
            console.error(error);
            response.writeHead(500,    contentTypePlainText);
            return;
        } else {
            if (!result) {
                if (response != null) {
                    response.writeHead(404, contentTypePlainText);
                    response.end('Not Found');
                }
                return;
            }

            var options = {
                filename : result.itemId,
            };
            gfs.exist(options, function(error, found) {
                if (found) {
                    response.setHeader('Content-Type', 'application/json');
                    var imageUrl = request.protocol + '://' + request.get('host') + request.baseUrl + request.path + '/image';
                    response.setHeader('Image-Url', imageUrl);
                    response.send(result);
                } else {
                    response.json(result);
                }
            });
        }
    });
}
```

到目前为止，我们将项目与其图像链接起来；但是，这使我们的数据部分链接，因为从项目到其图像有一个链接，但反之则没有。让我们改变这一点，并通过修改`readImage`函数向图像响应提供一个名为 Item-Url 的标头：

```js
function readImage(gfs, request, response) {

  var imageStream = gfs.createReadStream({
      filename : request.params.itemId,
      mode : 'r'
  });

  imageStream.on('error', function(error) {
    console.log(error);
    response.send('404', 'Not found');
    return;
  });

  var itemImageUrl = request.protocol + '://' + request.get('host') + request.baseUrl+ request.path;
  var itemUrl = itemImageUrl.substring(0, itemImageUrl.indexOf('/image'));
  response.setHeader('Content-Type', 'image/jpeg');
  response.setHeader('Item-Url', itemUrl);

  imageStream.pipe(response);
}
```

现在请求`http://localhost:3000/catalog/v2/item/3/`处的项目将以 JSON 格式返回编码的项目：

```js
GET http://localhost:3000/catalog/v2/item/3/image HTTP/1.1 
Accept-Encoding: gzip,deflate 
Host: localhost:3000 

HTTP/1.1 200 OK 
X-Powered-By: Express 
Content-Type: application/json; charset=utf-8 
Image-Url: http://localhost:3000/catalog/v2/item/3/image 
Content-Length: 137 
Date: Tue, 03 Apr 2018 19:47:41 GMT 
Connection: keep-alive 

{
   "_id": "5ab827f65d61450e40d7d984",
   "itemId": "3",
   "itemName": "Sports Watch 11",
   "price": 99,
   "currency": "USD",
   "__v": 0,
   "categories": ["Watches"]
}
```

查看响应标头，我们发现`Image-Url`标头及其值，`http://localhost:3000/catalog/v2/item/3/image`提供了与项目关联的图像的 URL。

请求该图像将产生以下结果：

```js
GET http://localhost:3000/catalog/v2/item/3/image HTTP/1.1 
Host: localhost:3000 
Connection: Keep-Alive 

HTTP/1.1 200 OK 
X-Powered-By: Express 
Content-Type: image/jpeg 
Item-Url: http://localhost:3000/catalog/v2/item/3 
Connection: keep-alive 
Transfer-Encoding: chunked 

<BINARY DATA>
```

这一次，响应提供了与项目链接的图像的有效载荷和一个特殊的标题**Item-Url**。它的值——`http://localhost:3000/catalog/v2/item/3`——是项目资源可用的地址。现在，如果项目图像出现在图像搜索结果中，与图像链接的项目的 URL 也将成为结果的一部分。通过这种方式，我们在不修改或损害有效载荷的情况下，语义上链接了这两个数据。

# 实现分页和过滤

一旦部署到网络上，每个服务都可以提供给大量的消费者使用。他们不仅会用它来获取数据，还会用它来插入新数据。在某个时候，这将不可避免地导致数据库中有大量的数据可用。为了保持服务的用户友好性并保持合理的响应时间，我们需要确保以合理的方式提供大量数据，以确保在请求`/catalog` URI 时不需要返回几十万个项目。

Web 数据消费者习惯于具有各种分页和过滤功能。在本章的前面，我们实现了`findIfindItemsByAttribute()`函数，它可以通过项目的任何属性进行过滤。现在，是时候引入分页功能，以便通过 URI 参数在`resultset`中进行导航。

`mongoose.js`模型可以利用不同的插件模块来提供额外的功能。这样一个插件模块是`mongoose-paginate`。Express 框架还提供了一个名为`express-paginate`的分页中间件。它提供了与 Mongoose 结果页面的链接和导航：

1.  在开始开发分页机制之前，我们应该安装这两个有用的模块：

```js
npm install -g -s express-paginate
npm install -g -s mongoose-paginate
```

1.  下一步将是在我们的应用程序中创建`express-paginate`中间件的实例：

```js

expressPaginate = require('express-paginate'); 
```

1.  通过调用其`middleware()`函数在应用程序中初始化分页中间件。它的参数指定了默认限制和每页结果的最大限制：

```js
app.use(expressPaginate.middleware(limit, maxLimit); 
```

1.  然后，在创建模型之前，将`mongoose-pagination`实例作为插件提供给`CatalogItem`模式。以下是`item.js`模块如何导出它以及模型：

```js
var mongoose = require('mongoose');
var mongoosePaginate = require('mongoose-paginate');
var Schema = mongoose.Schema;

mongoose.connect('mongodb://localhost/catalog');

var itemSchema = new Schema ({
    "itemId" : {type: String, index: {unique: true}},
    "itemName": String,
    "price": Number,
    "currency" : String,
    "categories": [String]
});
console.log('paginate');
itemSchema.plugin(mongoosePaginate);
var CatalogItem = mongoose.model('Item', itemSchema);

module.exports = {CatalogItem : CatalogItem, connection : mongoose.connection};
```

1.  最后，调用模型的`paginate()`函数以分页方式获取请求的条目：

```js

CatalogItem.paginate({}, {page:request.query.page, limit:request.query.limit},
    function (error, result){
        if(error) {
            console.log(error);
            response.writeHead('500',
               {'Content-Type' : 'text/plain'});
            response.end('Internal Server Error');
         } else {
           response.json(result);
         }
});
```

第一个参数是 Mongoose 应该用于其查询的过滤器。第二个参数是一个对象，指定了请求的页面和每页的条目。第三个参数是一个回调处理函数，通过其参数提供结果和任何可用的错误信息：

+   `error`：这指定了查询是否成功执行

+   `result`：这是从数据库中检索到的数据

`express-paginate`中间件通过丰富 Express 处理程序函数的`request`和`response`对象，实现了`mongoose-paginate`模块在 Web 环境中的无缝集成。

`request`对象获得了两个新属性：`query.limit`，它告诉中间件页面上的条目数，以及`query.page`，它指定了请求的页面。请注意，中间件将忽略大于初始化中指定的`maxLimit`值的`query.limit`值。这可以防止消费者覆盖最大限制，并使您完全控制应用程序。

以下是目录模块第二个版本中`paginate`函数的实现：

```js
exports.paginate = function(model, request, response) {
    var pageSize = request.query.limit;
    var page = request.query.page;
    if (pageSize === undefined) {
        pageSize = 100;
    }
    if (page === undefined) {
        page = 1;
    }

    model.paginate({}, {page:page, limit:pageSize},
            function (error, result){
                if(error) {
                    console.log(error);
                    response.writeHead('500',
                        {'Content-Type' : 'text/plain'});
                    response.end('Internal Server Error');
                }
                else {
                    response.json(result);
                }
            });
}
```

以下是查询包含 11 个项目的数据集并且每页限制为五个项目时的响应：

```js
{
  "docs": [
    {
      "_id": "5a4c004b0eed73835833cc9a",
      "itemId": "1",
      "itemName": "Sports Watch 1",
      "price": 100,
      "currency": "EUR",
      "__v": 0,
      "categories": [
        "Watches",
        "Sports Watches"
      ]
    },
    {
      "_id": "5a4c0b7aad0ebbce584593ee",
      "itemId": "2",
      "itemName": "Sports Watch 2",
      "price": 100,
      "currency": "USD",
      "__v": 0,
      "categories": [
        "Sports Watches"
      ]
    },
    {
      "_id": "5a64d7ecfa1b585142008017",
      "itemId": "3",
      "itemName": "Sports Watch 3",
      "price": 100,
      "currency": "USD",
      "__v": 0,
      "categories": [
        "Watches",
        "Sports Watches"
      ]
    },
    {
      "_id": "5a64d9a59f4dc4e34329b80f",
      "itemId": "8",
      "itemName": "Sports Watch 4",
      "price": 100,
      "currency": "EUR",
      "__v": 0,
      "categories": [
        "Watches",
        "Sports Watches"
      ]
    },
    {
      "_id": "5a64da377d25d96e44c9c273",
      "itemId": "9",
      "itemName": "Sports Watch 5",
      "price": 100,
      "currency": "USD",
      "__v": 0,
      "categories": [
        "Watches",
        "Sports Watches"
      ]
    }
  ],
  "total": 11,
  "limit": "5",
  "page": "1",
  "pages": 3
}
```

`docs`属性包含所有作为结果一部分的项目。它的大小与所选的限制值相同。`pages`属性提供了总页数；在这个例子中，它的值是 3，因为 11 个项目被安排在三页中，每页包含五个项目。`Total`属性给出了项目的总数。

启用分页的最后一步是修改`/v2/`路由，开始使用新创建的函数：

```js
  router.get('/v2/', function(request, response) {
    var getParams = url.parse(request.url, true).query;
    if (getParams['page'] !=null) {
      catalogV2.paginate(model.CatalogItem, request, response);
    } else {
      var key = Object.keys(getParams)[0];
      var value = getParams[key];
      catalogV2.findItemsByAttribute(key, value, response);
    }
});
```

我们将使用 HTTP `302 Found`状态为默认路由`/catalog`。这样，所有传入的请求都将被重定向到`/v2/`：

```js
router.get('/', function(request, response) {
  console.log('Redirecting to v2');
  response.writeHead(302, {'Location' : '/catalog/v2/'});
  response.end('Version 2 is is available at /catalog/v2/: ');
});
```

在这里使用适当的重定向状态代码对于任何 RESTful web 服务的生命周期至关重要。返回`302 Found`，然后进行重定向，确保 API 的使用者始终可以在该位置获得最新版本。此外，从开发的角度来看，使用重定向而不是代码重复也是一个很好的实践。

当你处于两个版本之间时，应始终考虑使用 HTTP `301 Moved Permanently`状态来显示先前版本已经移动到何处，以及 HTTP `302 Found`状态来显示当前版本的实际 URI。

现在，回到分页，由于请求的页面和限制数字是作为`GET`参数提供的，我们不希望将其与过滤功能混淆，因此对它们进行了明确的检查。只有在请求中有页面或限制`GET`参数时，才会使用分页。否则，将进行搜索。

最初，我们设置了 100 个结果的最大限制和 10 个默认限制，因此，在尝试新的分页功能之前，请确保将更多的项目插入到数据库中。这将使测试结果更加明显。

现在，让我们试一试。请求`/catalog?limit=3`将返回一个只包含两个项目的列表，如下所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/rst-webapi-dsn-node10/img/6b2e6d8b-69e4-42c8-bb2e-69c36f6841cc.png)

启用分页结果。这是 Postman 的屏幕截图。这里个别设置并不重要。图片的目的只是展示窗口的外观。

如示例所示，总页数为四。数据库中存储的项目总数为 11。由于我们在请求中没有指定页面参数，分页隐式返回了第一页。要导航到下一页，只需在 URI 中添加`&page=2`。

另外，尝试更改`limit`属性，请求`/catalog/v2?limit=4`。这将返回前四个项目，并且响应将显示总页数为三。

# 缓存

当我们讨论罗伊·菲尔丁定义的 REST 原则时，我们提到缓存是一个相当敏感的话题。最终，我们的消费者在执行查询时会期望得到最新的结果。但是，从统计的角度来看，Web 中公开的数据更有可能被阅读而不是被更新或删除。

因此，合理的是一些公共 URL 暴露的资源成为数百万请求的对象，考虑从服务器中卸载部分负载到缓存中。HTTP 协议允许我们缓存一些响应一段时间。例如，当在短时间内收到多个请求时，查询给定组的目录中的所有项目，例如`/catalog/v2`，我们的服务可以利用特殊的 HTTP 头，强制 HTTP 服务器缓存响应一段时间。这将防止对底层数据库服务器的冗余请求。

通过特殊的响应头在 HTTP 服务器级别进行缓存。HTTP 服务器使用`Cache-Control`头来指定给定响应应该缓存多长时间。缓存需要失效之前的时间段通过其`max-age`属性设置，其值以秒为单位提供。当然，有一个很好的 Node.js 模块提供了一个用于缓存的中间件函数，称为`express-cache-control`。

# 在 Express 应用程序中提供 Cache-Control 头

让我们使用 NPM 包管理器安装它；再次，我们将全局安装它，并使用`-s`选项，这将自动更新`package.json`文件，添加新的`express-cache-control`依赖项：

```js
    npm install -g -s express-cache-control
```

使用`express-cache-control`中间件启用缓存需要三个简单的步骤：

1.  获取模块：

```js
      CacheControl = require("express-cache-control") 
```

1.  创建`CacheControl`中间件的实例：

```js
 var cache = new CacheControl().middleware;
```

1.  将中间件实例绑定到要启用缓存的路由：

```js
router.get('/v2/', cache('minutes', 1), function(request, response) {
    var getParams = url.parse(request.url, true).query;
    if (getParams['page'] !=null || getParams['limit'] != null) {
      catalogV2.paginate(model.CatalogItem, request, response);
    } else {
      var key = Object.keys(getParams)[0];
      var value = getParams[key];
      catalogV2.findItemsByAttribute(key, value, response);
    }
});
```

通常，提供许多结果条目的常见 URI 应该是缓存的主题，而不是为具体条目提供数据的 URI。在我们的应用程序中，只有`/catalog` URI 将使用缓存。`max-age`属性必须根据您的应用程序的负载进行选择，以最小化不准确的响应。

让我们通过在 Postman 中请求`/catalog/v2`来测试我们的更改：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/rst-webapi-dsn-node10/img/08a4cf06-049a-4d43-9bd8-d46b50488a85.png)

Cache-control 头部指示缓存已启用。这是 Postman 的屏幕截图。这里不重要的是单独的设置。图片的目的只是为了展示窗口的外观。

正如预期的那样，`express-cache-control`中间件已经完成了它的工作——`Cache-Control`头现在包含在响应中。`must-revalidate`选项确保在`max-age`间隔过期后使缓存内容无效。现在，如果您对特定项目发出另一个请求，您会发现响应不使用`express-cache-control`中间件，这是因为它需要在每个单独的路由中显式提供。它不会在相互衍生的 URI 中使用。

针对任何路由`/v1/`的`GET`请求的响应将不包含`Cache-Control`头部，因为它仅在我们的 API 的第 2 版中受支持，并且`Cache-Control`中间件仅在主目录路由`/catalog/v2/`或`/catalog`中使用。

# 摘要

恭喜！在本章中，您成功地将一个样本 REST 启用的端点转换为一个完整的支持过滤和分页的 RESTful Web 服务。该服务提供任意和 JSON 数据，并且已准备好应对高负载场景，因为它在关键部分启用了缓存。应该引起您注意的一件事是在公共 API 的新旧版本之间进行重定向时，适当使用 HTTP 状态代码。

实现适当的 HTTP 状态对于 REST 应用程序非常重要，因此我们使用了相当奇特的状态，例如`301 Moved Permanently`和`302 Found`。在下一章中，我们将介绍授权概念到我们的应用程序中。


# 第七章：为生产准备 RESTful API

在上一章中，我们实现了一个完整的目录 RESTful API；然而，一个完全功能的 API 和一个可投入生产的 API 之间存在差异。在本章中，我们将介绍 API 应该如何进行全面的文档记录和测试。在投入生产之前，任何软件都必须完成这些关键要求。

总之，在本章中，我们将涵盖以下主题：

+   记录 RESTful API

+   使用 Mocha 测试 RESTful API

+   微服务革命

# 记录 RESTful API

到目前为止，我们部分地介绍了 RESTful web 服务 API 是如何由`wadl`描述和由`swagger`规范记录的。现在是时候充分利用它们，在我们的目录应用程序的 express.js 路由中公开它们的自描述元数据。这样，消费者和最终用户将有单独的 URL 来获取他们需要轻松采用服务的元数据。让我们从 wadl 定义开始。以下是`wadl`如何完全描述一个操作的方式：

```js
  <resources base="http://localhost:8080/catalog/"> 
        <resource path="/catalog/item/{itemId}">
            <method name="GET">
                <request>
                    <param name="category" type="xsd:string" style="template"/>
                </request>
                <response status="200">
                    <representation mediaType="application/json" />
                </response>
                <response status="404">
                    <representation mediaType="text/plain" />
                </response>
                <response status="500">
                    <representation mediaType="text/plain" />
                </response>
            </method>
            <method name="PUT">
                <request>
                    <param name="itemId" type="xsd:string" style="template"/>
                </request>
                <response status="200">
                    <representation mediaType="application/json" />
                </response>
                <response status="201">
                    <representation mediaType="application/json" />
                </response>
                <response status="404">
                    <representation mediaType="text/plain" />
                </response>
                <response status="500">
                    <representation mediaType="text/plain" />
                </response>
            </method>
            <method name="POST">
                <request>
                    <param name="itemId" type="xsd:string" 
                     style="template"/>
                </request>
                <response status="200">
                    <representation mediaType="application/json" />
                </response>
                <response status="201">
                    <representation mediaType="application/json" />
                </response>
                <response status="404">
                    <representation mediaType="text/plain" />
                </response>
                <response status="500">
                    <representation mediaType="text/plain" />
                </response>
            </method>
            <method name="DELETE">
                <request>
                    <param name="itemId" type="xsd:string" 
                     style="template"/>
                </request>
                <response status="200">
                    <representation mediaType="application/json" />
                </response>
                <response status="404">
                    <representation mediaType="text/plain" />
                </response>
                <response status="500">
                    <representation mediaType="text/plain" />
                </response>
            </method>
        </resource>
      </resources>
```

每个路由都彻底描述了它所暴露的所有操作；这样，它们将被符合`wadl`规范的客户端索引和发现。一旦你描述了所有的操作，只需将`wadl`文件存储在你的`express.js`项目的`static`目录中，并从应用程序中公开它：`app.use('/catalog/static', express.static('static'));`

在本地启动应用程序后，你的`wadl`文件将准备好在`http://localhost:3000/catalog/static/catalog.wadl`上为客户端提供服务。

让我们试试并将其导入到 Postman 中：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/rst-webapi-dsn-node10/img/f8ad76fb-4325-4b5b-96f6-190768f907c7.png)

将 wadl 文件导入到 Postman。这是 Postman 的截图。这里个别设置并不重要。图片的目的只是展示窗口的外观。

静态地提供`wadl`文件将有助于你的应用程序被搜索引擎索引；这进一步增加了你的 API 的采用率。

然而，`wadl`正逐渐失去地位，而`swagger`则更受青睐。JavaScript REST-enabled 应用程序的发展导致了对非 XML 标准的 RESTful 服务发现的需求。这就是为什么`swagger`成为事实上的标准的原因，不仅用于记录 RESTful 服务，还用于其广泛采用的发现格式。虽然 XML-aware 平台仍然依赖于`wadl`，但 JavaScript 和其他非 XML 本地平台在`swagger`规范上有很大依赖，不仅用于描述，还用于发现和消费，其采用速度正在迅速增加。因此，你应该考虑使用`swagger`描述你的 API，以确保它能够轻松地被任何平台采用。以下是`swagger`方言中如何完全描述一个操作的方式：

```js
{
    "swagger": "2.0",
    "info": {
      "title": "Catalog API Documentation",
      "version": "v1"
    },
    "paths": {"/catalog/item/{itemId}": {
        "get": {
          "operationId": "getItemV2",
          "summary": "Get an existing item",
          "produces": ["application/json"],
          "responses": {
            "200": {
              "description": "200 OK",
              "examples": {
                "application/json": {
                    "_id": "5a4c004b0eed73835833cc9a",
                    "itemId": "1",
                    "itemName": "Sports Watch",
                    "price": 100,
                    "currency": "EUR",
                    "__v": 0,
                    "categories": [ "Watches", "Sports Watches"]
                  }
              }
            },
            "404": {"description": "404 Not Found"},
            "500": {"description": "500 Internal Server Error"}
          }
        },
        "post": {
          "404": {"description": "404 Not Found"},
          "500": {"description": "500 Internal Server Error"},
          "operationId": "postItemV2",
          "summary": "Creates new or updates existing item",
          "produces": ["application/json"],
          "responses": {
            "200": {
              "itemId": 19,
              "itemName": "Sports Watch 19",
              "price": 100,
              "currency": "USD",
              "__v": 0,
              "categories": [
                "Watches",
                "Sports Watches"
              ]
            },
            "201": {
              "itemId": 19,
              "itemName": "Sports Watch 19",
              "price": 100,
              "currency": "USD",
              "__v": 0,
              "categories": [ "Watches", "Sports Watches"]
            },
            "500": "text/html"
          }
        },
        "put": {
          "404": {"description": "404 Not Found"},
          "500": {"description": "500 Internal Server Error"},
          "operationId": "putItemV2",
          "summary": "Creates new or updates existing item",
          "produces": ["application/json"],
          "responses": {
            "200": {
              "itemId": 19,
              "itemName": "Sports Watch 19",
              "price": 100,
              "currency": "USD",
              "__v": 0,
              "categories": [ "Watches","Sports Watches"]
            },
            "201": {
              "itemId": 19,
              "itemName": "Sports Watch 19",
              "price": 100,
              "currency": "USD",
              "__v": 0,
              "categories": ["Watches", "Sports Watches"]
            },
            "500": "text/html"
          }
        },
        "delete": {
          "404": {"description": "404 Not Found"},
          "500": {"description": "500 Internal Server Error"},
          "operationId": "deleteItemV2",
          "summary": "Deletes an existing item",
          "produces": ["application/json"],
          "responses": {"200": {"deleted": true },
            "500": "text/html"}
        }
      }
   }
  consumes": ["application/json"]
  }
 }
```

最后，在`swagger.json`文件中描述了所有 API 的操作后，它应该被静态地公开，类似于`wadl`文件。由于应用程序已经有了静态目录的路由，只需将`swagger.json`文件放在那里，它就可以为消费者提供服务并促进发现。`Swagger`主要是一个文档工具，但主要面向开发者；因此，它需要一个使文档易于阅读和理解的前端。有一个`npm`模块——`swagger-ui`——为我们提供了默认的 swagger 前端。我们将在我们的应用程序中采用它，所以让我们使用包管理器来安装它——`npm install swagger-ui`。安装完成后，只需要求模块的一个实例以及静态`swagger.json`文件的一个实例，并在一个单独的路由中使用它们：

```js
const swaggerUi = require('swagger-ui-express');
const swaggerDocument = require('./static/swagger.json');

app.use('/catalog/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));
```

在浏览器中启动你的应用程序并请求`http://localhost:3000/catalog/api-docs/`：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/rst-webapi-dsn-node10/img/5f3a352d-f327-4759-9979-621b2388988d.png)

正如你所看到的，swagger-ui 模块为你提供了标准的 swagger 前端。

记住，作为开发者，保持你的 API 文档的完整和最新是你的责任。

# 使用 Mocha 测试 RESTful API

你是否注意到`app.js` express 应用程序是用`express-generator`创建的，实际上是一个导出 express 实例的`node.js`模块？如果你有，你一定会问自己为什么需要这样做。嗯，将 express 实例导出为模块使其能够进行单元测试。我们已经在第四章中使用了`mocha`框架，*使用 NoSQL 数据库*，在那里我们为`CatalogItem`模块开发了一个单元测试。我们将再次使用`mocha`，并为 API 公开的每个操作包装一个单元测试。要对 express 应用程序进行单元测试，我们需要执行以下操作：

1.  需要一个带有路由的`express.js`应用程序实例，利用其作为模块导出

1.  在单元测试环境中启动`express.js`实例

1.  通过测试库调用其操作并断言结果

1.  最后，执行`npm test`命令来触发单元测试

在继续实施 mocha 测试之前，我们需要一个库来从单元测试中发送 HTTP 请求；我们将利用`chai`模块。它提供了方便的函数来发送 HTTP 请求，还捆绑了`should.js`断言库来验证预期结果。要安装`chai`，只需执行`npm install chai`，然后执行`npm install chai-http`来安装其 HTTP 插件，我们就可以开始单元测试了！

与任何其他 mocha 测试一样，我们将不得不执行以下步骤：

1.  描述每个测试用例

1.  准备测试装置；这次，我们将使用`chai-http`来调用 REST 操作

1.  断言返回的结果

涵盖创建、访问和删除资源操作的基本单元测试如下：

```js
var expressApp = require('../../app');
var chai = require('chai');
var chaiHttp = require('chai-http');
var mongoose = require('mongoose');
var should = chai.should();

mongoose.createConnection('mongodb://localhost/catalog-test');

chai.use(chaiHttp);

describe('/get', function() {
  it('get test', function(done) {
    chai.request(expressApp)
      .get('/catalog/v2')
      .end(function(error, response) {
        should.equal(200  , response.status);
        done();
      });
    });
  });

describe('/post', function() {
     it('post test', function(done) {
       var item ={
          "itemId":19,
          "itemName": "Sports Watch 10",
          "price": 100,
          "currency": "USD",
          "__v": 0,
          "categories": [
              "Watches",
              "Sports Watches"
          ]
      };
     chai.request(expressApp)
           .post('/catalog/v2')
           .send(item )
           .end(function(err, response){
               should.equal(201, response.status)
             done();
           });
     });
   });

   describe('/delete', function() {
        it('delete test', function(done) {
          var item ={
             "itemId":19,
             "itemName": "Sports Watch 10",
             "price": 100,
             "currency": "USD",
             "__v"cd .: 0,
             "categories": [
                 "Watches",
                 "Sports Watches"
             ]
         };
        chai.request(expressApp)
              .delete('/catalog/v2/item/19')
              .send(item )
              .end(function(err, response){
                  should.equal(200, response.status)
                done();
              });
        });
      });
```

将此文件存储在项目的测试目录中；默认情况下，该目录在`package.json`中被定义为测试目录，因此要运行单元测试，只需执行`npm test`：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/rst-webapi-dsn-node10/img/5d631466-3680-4d73-a8f4-84fea9173b23.png)

恭喜！现在你的 API 已经覆盖了单元测试，注意测试并没有模拟任何东西！它们正在运行 express 应用程序；当应用程序变得生产时，它们将以完全相同的方式运行，确保稳定性和向后兼容性！目前，单元测试仅断言状态码。花一些时间并进一步扩展它们，以便对响应主体进行断言。这将是一个很好的练习。

# 微服务革命

RESTful API 疯狂开始并且几乎每个人都决定 RESTful API 是正确的方式，是不是？随着`Linux`容器的出现，结果表明转向 REST 方法只是一半的路。目前，每个人都从容器中受益。它们提供了更好、更快、更便宜的开发和运营模式，但是微服务只是 RESTful 服务的另一个炒作术语吗？嗯，不，完全不是；RESTful 服务只是微服务的基础。

微服务是小型和独立的进程，公开了一个简单的接口，允许与它们进行通信并构建复杂的应用程序，而不依赖于库工件。这些服务类似于小型构建块，高度解耦并专注于执行小任务，促进了系统构建的模块化方法。

虽然 REST 强调资源及其自然处理，但微服务架构强调简单性、故障安全性和隔离性。RESTful API 没有每个操作的单独状态；要么整个 API 可用，要么完全不可用。微服务试图解决这个问题，提供了在单独的容器上托管每个操作，或者容器的子集，确保最大的容错能力和灵活性。

微服务预期提供单一简单的操作，没有更多。这使开发人员可以按照他们想要的方式对它们进行分组和使用。处理策略、治理、安全和监控通常不在微服务处理范围内，主要是因为它们需要某种上下文。总的来说，将上下文绑定到服务会增加其依赖性并使其可重用性降低；这就是为什么微服务将上下文留给 API 管理网关的原因，它允许您创建微服务的组合，然后将策略绑定到它，并监视网关上的每个活动。这种分布式开发模型使程序员能够快速构建一系列微服务，而无需考虑治理和安全等复杂主题。

微服务世界是一个改变游戏规则的世界，受益于 Linux 容器。目前，类似于 AWS 和 Azure 的所有基于云的服务都提供微服务托管。

# 摘要

在本章中，我们稍微偏离了与`Express.js`相关的主题。相反，我们集中讨论了如何通过提供最新的 API 文档以及 API 本身来使我们的代码基础投入生产。我们让我们的应用程序投资于预防措施，以确保通过实施更复杂的单元测试来实现向后兼容性。最后，我们决定展望未来，这一切都与微服务有关。确保您将这一热门话题保持在您的技能清单中；它将不可避免地在不久的将来发展，您对它了解得越多，就越好！


# 第八章：消费 RESTful API

为了演示与我们的 API 相关的一些更高级的主题，我们将实现一个非常简单的 Web 客户端。这将帮助我们涵盖这些主题，并且可以作为目录消费者的参考实现。对于这个前端客户端，我们将使用著名的 JavaScript 库 jQuery。利用它将帮助我们涵盖以下内容：

+   使用 jQuery 消费 RESTful 服务

+   内容交付网络

+   在线故障排除和识别问题

+   跨域资源共享策略

+   客户端处理不同的 HTTP 状态码

# 使用 jQuery 消费 RESTful 服务

JQuery 是一个快速、轻量级和强大的 JavaScript 库；它通过在 DOM 三加载后直接访问 HTML 元素来消除与 DOM 相关的复杂性。要在 HTML 文档中使用 jQuery，您必须导入它：

`<script type="text/javascript" src="img/jquery-3.3.1.min.js "></script>`

假设在 HTML 文档的某处，有一个定义为`<input type="button" id="btnDelete" value="Delete"/>`的按钮。

使用 JQuery 为此按钮分配一个点击事件的函数意味着我们需要执行以下操作：

1.  在 HTML 文档中导入 jquery 库

1.  确保 HTML 文档的 DOM 文档完全加载

1.  使用 ID 属性定义的标识符访问按钮

1.  将处理程序函数作为`click`事件的参数提供：

```js
$(document).ready(function() {
    $('#btn').click(function () {
       alert('Clicked');
    });
});
```

`$('#identifier')`表达式直接访问 DOM 三中的元素，`$`表示引用一个对象，括号内的值，前缀为`#`指定了它的标识符。只有在整个文档加载后，jQuery 才能访问元素；这就是为什么元素应该在`${document).ready()`块范围内访问。

同样，您可以通过标识符`txt`访问文本输入的值：

```js
  $(document).ready(function() {
    var textValue = $('#txt').val();
    });
  });
```

`$(document)`对象在 jQuery 中预定义，并表示 HTML 页面的整个 DOM 文档。类似地，jQuery 预定义了一个用于启用 AJAX 通信的函数，即向 HTTP 端点发送 HTTP 请求。这个函数被命名为**异步 JavaScript + XML-** AJAX，这是一种事实标准，使 JavaScript 应用程序能够与启用 HTTP 的后端进行通信。如今，**JSON**被广泛使用；然而，AJAX 的命名转换仍然被用作异步通信的术语，无论数据格式如何；这就是为什么 jQuery 中的预定义函数被称为`$.ajax(options, handlers)`。

要使用`$.ajax`函数发送 http 请求，通过提供端点 URL、请求的 http 方法和其内容类型来调用它；结果将在回调函数中返回。以下示例显示了如何从我们的目录请求标识为 3 的项目：

```js
  $.ajax({
      contentType: 'application/json',
      url: 'http://localhost:3000/catalog/v2/item/3',
      type: 'GET',
      success: function (item, status, xhr) {
          if (status === 'success') {
              //the item is successfully retrieved load & display its details here
          }
      }
      ,error: function (xhr, options, error) {
        //Item was not retrieved due to an error handle it here
      }
    });
  });
```

将数据发布到端点相当相似：

```js
  $.ajax({
    url: "http://localhost:3000/catalog/v2/",
    type: "POST",
    dataType: "json",
    data: JSON.stringify(newItem),
     success: function (item, status, xhr) {
       if (status === 'success') {
         //item was created successfully
       }
     },
     error: function(xhr, options, error) {
       //Error occurred while creating the iteam
     }
   });

```

只需使用适当的选项`type`设置为 POST，`dateType`设置为 JSON。这些将指定以 JSON 格式向端点发送 POST 请求。对象的有效负载作为`data`属性的值提供。

调用`delete`方法非常相似：

```js
      $.ajax({
        contentType: 'application/json',
        url: 'http://localhost:3000/catalog/v2/item/3',
        type: 'DELETE',
        success: function (item, status, xhr) {
            if (status === 'success') {
              //handle successful deletion
            }
        }        
        ,error: function (xhr, options, error) {
            //handle errors on delete
        }
      });
```

对于这本书的范围来说，对 jQuery 的基本理解就足够了。现在，让我们把所有这些粘合在一起，创建两个 HTML 页面；这样，我们将处理在我们的目录中创建、显示和删除项目，首先是显示项目并允许删除的页面。该页面使用`GET`请求从目录加载项目，然后以表格方式在 HTML 页面中显示项目的属性：

```js
<html>
<head><title>Item</title></head>
<body>
    <script type="text/javascript" src="img/jquery-3.3.1.min.js "></script>
  <script>
  $(document).ready(function() {
    $('#btnDelete').click(function () {
      $.ajax({
        contentType: 'application/json',
        url: 'http://localhost:3000/catalog/v2/item/3',
        type: 'DELETE',
        success: function (item, status, xhr) {
            if (status === 'success') {
              $('#item').text('Deleted');
              $('#price').text('Deleted');
              $('#categories').text('Deleted');
            }
        }
        ,error: function (xhr, options, error) {
          alert('Unable to delete item');
        }
      });
    });
    $.ajax({
      contentType: 'application/json',
      url: 'http://localhost:3000/catalog/v2/item/3',
      type: 'GET',
      success: function (item, status, xhr) {
          if (status === 'success') {
            $('#item').text(item.itemName);
            $('#price').text(item.price + ' ' + item.currency);
            $('#categories').text(item.categories);
          }
      }
      ,error: function (xhr, options, error) {
        alert('Unable to load details');
      }
    });
  });
  </script>
  <div>
    <div style="position: relative">
      <div style="float:left; width: 80px;">Item: </div>
      <div><span id="item"/>k</div>
    </div>
    <div style="position: relative">
      <div style="float:left; width: 80px;">Price: </div>
      <div><span id="price"/>jjj</div>
    </div>
    <div style="position: relative">
      <div style="float:left; width: 80px;">Categories: </div>
      <div><span id="categories"/>jjj</div>
    </div>
    <div><input type="button" id="btnDelete" value="Delete"/></div>
  </div>
</body>
</html>
```

处理创建的页面非常相似。但是，它提供了文本输入，而不是用于加载项目属性的 span 标签，视图页面将显示加载项目属性的数据。JQuery 提供了一个简化的访问模型来访问输入控件，而不是 DOM——只需按如下方式访问输入元素：

```js
<html>
<head><title>Item</title></head>
<body>
  <script type="text/javascript" src="img/jquery-3.3.1.min.js "></script>
  <script>
  $(document).ready(function() {
    $('#btnCreate').click(function(){
      var txtItemName = $('#txtItem').val();
      var txtItemPrice = $('#txtItemPrice').val();
      var txtItemCurrency = $('#txtItemCurrency').val();
      var newItem = {
        itemId: 4,
        itemName: txtItemName,
        price: txtItemPrice,
        currency: txtItemCurrency,
        categories: [
          "Watches"
        ]
      };
      $.ajax({
        url: "http://localhost:3000/catalog/v2/",
        type: "POST",
        dataType: "json",
        data: JSON.stringify(newItem),
        success: function (item, status, xhr) {
              alert(status);
            }
      });
    })
  });
  </script>
  <div>
    <div style="position: relative">
      <div style="float:left; width: 80px;">Id: </div>
      <div><input type="text" id="id"/></div>

      <div style="float:left; width: 80px;">Item: </div>
      <div><input type="text" id="txtItem"/></div>
    </div>
    <div style="position: relative">
      <div style="float:left; width: 80px;">Price: </div>
      <div><input type="text" id="price"/></div>
    </div>
    <div style="position: relative">
      <div style="float:left; width: 80px;">Categories: </div>
      <div><input type="text" id="categories"/></div>
    </div>
    <div><input type="button" id="btnCreate" value="Create"/></div>
  </div>
</body>
</html>
```

让我们试试，通过在所选的浏览器中直接从文件系统打开我们的静态页面，加载视图页面中的现有项目。看起来我们似乎有某种问题，因为没有显示任何内容。使用浏览器的开发者套件启用客户端调试也没有提供更多信息：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/rst-webapi-dsn-node10/img/6c54635c-5e0f-44c1-9111-0f58c85da144.png)

它指出内容部分被阻止；但是，目前还不太清楚这是由于后端错误，还是客户端出了问题。我们将在下一节中看看如何排除这种问题。

# 在线故障排除和问题识别

有时客户端和服务器之间的交互失败，而这些失败的原因通常需要分析；否则，它们的根本原因将不为人知。我们发现我们的客户端应用程序无法加载，因此无法显示现有项目的数据。让我们尝试通过在客户端和服务器之间设置`http`隧道来调查其根本原因。这将是一种 MiM（中间人）调查，因为我们将监听一个端口并将传入请求重定向到另一个端口，以查看服务器是否返回正确的响应，或者它的管道是否在中间某处中断。有各种 TCP 隧道可用；我一直在使用 GitHub 上可用的一个简单的开源隧道，网址是[`github.com/vakuum/tcptunnel`](https://github.com/vakuum/tcptunnel)。其作者还维护着一个单独的网站，您可以在该网站上下载最常见操作系统的预构建二进制文件；网址是[`www.vakuumverpackt.de/tcptunnel/`](http://www.vakuumverpackt.de/tcptunnel/)。

在构建或下载隧道的副本之后，启动如下：

`./tcptunnel --local-port=3001 --remote-port=3000 --remote-host=localhost --log`

这将启动应用程序监听端口 3001，并将每个传入请求转发到位置端口 3000；`--log`选项指定应在控制台中记录通过隧道传递的所有数据流。最后，修改 HTML 页面以使用端口 3001 而不是 3000，然后让我们看看在端口`3001`上发出新的 GET 请求获取 id 为 3 的项目后，隧道会显示我们什么：`http://localhost:3001/catalog/v2/item/3`：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/rst-webapi-dsn-node10/img/a3df9739-15a8-4bb8-90d2-4087c09b1d2d.png)

令人惊讶的是，隧道显示服务器正常响应`200 OK`和相关有效负载。因此，问题似乎不在服务器端。

嗯，既然错误显然不在服务器端，让我们尝试深入调查客户端发生了什么。如今，所有流行的浏览器都有所谓的 Web 开发者工具。它们提供对`http`日志、动态渲染的代码、HTML 文档的 DOM 树等的访问。让我们使用 Mozilla Firefox 调用我们的 RESTful GET 操作，看看它的 Web 控制台会记录我们的请求的什么信息。打开 Mozilla Firefox 菜单，选择`Web Developer`，然后选择`Browser Console`：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/rst-webapi-dsn-node10/img/e4eec8a4-25a7-4a10-85b7-d6482497eaf7.png)

啊哈！看起来我们找到了：`跨域请求被阻止：同源策略不允许读取远程资源...`。

这个错误在客户端级别阻止了服务器端的响应。在下一节中，我们将看看这实际上意味着什么。

# 跨域资源共享

跨站点 HTTP 请求是指引用要从与最初请求它们的域不同的域加载的资源的请求。在我们的情况下，我们从我们的文件系统启动了客户端，并请求了来自网络地址的资源。这被认为是潜在的**跨站点脚本**请求，根据**W3C 推荐**在[`w3.org/cors/TR/cors`](http://w3.org/cors/TR/cors)中应该小心处理。这意味着如果请求外部资源，则应该在标头中明确指定请求来源的域—其来源，只要不允许一般外部资源加载。这种机制可以防止跨站脚本（XSS）攻击，它是基于 HTTP 标头的。

以下 HTTP 请求标头指定了客户端端如何处理外部资源：

+   `Origin`定义了请求的来源

+   `Access-Control-Request-Method`定义了用于请求资源的 HTTP 方法

+   `Access-Control-Request-Header`定义了与外部资源请求结合使用的任何标头

在服务器端，以下标头指示响应是否符合 CORS 启用的客户端请求：

+   `Access-Control-Allow-Origin`：此标头要么（如果存在）通过重复指定请求者的主机来指定，要么可以通过返回通配符'*'来指定允许所有远程来源

+   `Access-Control-Allow-Methods`：此标头指定服务器允许从跨站点域接受的 HTTP 方法

+   `Access-Control-Allow-Headers`：此标头指定服务器允许从跨站点域接受的 HTTP 标头

还有一些`Access-Control-*`标头可用于进一步细化处理传入的 XSS 请求，或者根据凭据和请求的最大年龄来确定是否提供服务，但基本上，最重要的是允许的来源、允许的方法和允许的标头。

有一个节点模块在服务器端处理`CORS`配置；通过`npm install -g cors`进行安装，并且可以通过中间件模块轻松在我们的应用程序中启用。只需在所有公开的路由中使用它，通过将其传递给应用程序：

```js
app.use(cors());
```

在启用了`cors`中间件后使用隧道，可以看到服务器现在通过将"Access-Control-Allow-Origin'标头设置为'*'"优雅地处理来自不同来源的请求：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/rst-webapi-dsn-node10/img/2db6ec99-1e04-47b4-9594-6e62b00af25e.png)

# 内容交付网络

当我们将 jQuery 库导入我们的客户端应用程序时，我们直接引用了其优化的源自其供应商的位置，如`<script type="text/javascript" src="img/jquery-3.3.1.min.js "/>`。

现在，想象一下，由于某种原因，这个网站要么暂时关闭，要么永久关闭；这将使我们的应用程序无法使用，因为导入功能将无法正常工作。

内容交付网络在这些情况下会提供帮助。它们作为库或其他静态媒体内容的存储库，确保所需的资源在没有停机时间的情况下可用，即使与其供应商出现问题。最受欢迎的 JavaScript CDN 之一是[`cdnjs.com/`](https://cdnjs.com/)；它提供了最常见的 JS 库。我们将把我们的客户端切换到从这个 CDN 而不是从其供应商网站引用 jquery 库。

虽然直接下载 JS 库并将其放置在 node.js 项目的静态目录中几乎没有什么问题，但这可能导致本地更改和修复直接在库依赖项中。这很容易导致不兼容的更改，并且可能会阻止您的应用程序轻松切换到将来的新版本。只要您的依赖项是开源的，您应该努力通过贡献修复或报告错误来改进它们，而不是在自己的本地分支中进行修复。但是，如果不幸遇到一个您可以轻松解决的错误，您可以分叉库以更快地解决问题。但是，始终考虑向社区贡献修复。一旦被接受，切换回官方版本；否则，下次遇到另一个问题时，您会发现自己处于困境之中，如果从分叉版本报告，社区将更难追踪。这就是开源的美丽之处，这就是为什么您应该始终考虑使用 JavaScript API 的内容交付网络。它们将为您提供您在应用程序生命周期的任何时候可能需要的稳定性和支持。

# 在客户端处理 HTTP 状态代码。

我们花了相当多的时间来解决 RESTful 服务应该如何优雅地表示每个状态，包括错误状态。一个定义良好的 API 应该要求其消费者优雅地处理所有错误，并根据需要提供尽可能多的状态信息，而不仅仅是声明“发生了错误”。这就是为什么它应该查找返回的状态代码，并清楚区分客户端请求，比如`400 Bad Request`或`415 Unsupported media types`，这些请求是由于错误的有效负载、错误的媒体类型或身份验证相关错误，比如`401 Unauthorized`。

错误响应的状态代码可以在 jQuery 回调函数的`error`回调中获得，并应该用于向请求提供详细信息：

```js
 $.ajax({
        url: "http://localhost:3000/catalog/v2/",
        type: "POST",
        dataType: "json",
        data: JSON.stringify(newItem),
        success: function (item, status, jqXHR) {
            alert(status);
        },
        error: function(jqXHR, statusText, error) {
            switch(jqXHR.status) {
               case 400: alert('Bad request'); break;
               case 401: alert('Unauthroizaed'); break;
               case 404: alert('Not found'); break;
               //handle any other client errors below
               case 500: alert('Internal server error); break;
               //handle any other server errors below
            }
        }
      });
```

错误请求由错误回调函数处理。它提供`jqXHR` - `XmlHttpRequest` JavaScript*—*对象作为其第一个参数。它携带了所有请求/响应相关的信息，如状态代码和标头。使用它来确定所请求的服务器返回了什么，以便您的应用程序可以更细致地处理不同的错误。

# 摘要

在本章中，我们使用了 jQuery 库实现了一个简单的基于 Web 的客户端。我们利用这个客户端来演示跨域资源共享策略的工作原理，并使用了中间人手段来解决线上问题。最后，我们看了一下客户端应该如何处理错误。这一章使我们离旅程的终点又近了一步，因为我们得到了我们服务的第一个消费者。在下一章中，我们将带您走完将服务带入生产之前的最后一步——选择其安全模型。


# 第九章：保护应用程序

一旦在生产环境中部署，应用程序将面临大量请求。不可避免地，其中一些将是恶意的。这就需要明确授予访问权限，只有经过身份验证的用户才能访问服务，即，对已选择的消费者进行身份验证，以便他们能够访问您的服务。大多数消费者只会使用服务进行数据提供。然而，少数消费者需要能够提供新的或修改现有的目录数据。为了确保只有适当的消费者能够执行`POST`、`PUT`和`DELETE`请求，我们将不得不在应用程序中引入授权的概念，该授权将仅授予明确选择的用户修改权限。

数据服务可能提供敏感的私人信息，例如电子邮件地址；HTTP 协议作为一种文本协议，可能不够安全。通过它传输的信息容易受到**中间人**攻击，这可能导致数据泄露。为了防止这种情况，应使用**传输层安全**（**TLS**）。HTTPS 协议加密传输的数据，确保只有具有正确解密密钥的适当消费者才能使用服务提供的数据。

在本章中，我们将看看 Node.js 如何实现以下安全功能：

+   基本身份验证

+   基于护照的基本身份验证

+   基于护照的第三方身份验证

+   授权

+   传输层安全

# 身份验证

应用程序在成功针对受信任存储验证其身份后，将用户视为已经通过身份验证。这样的受信任存储可以是任何一种特别维护的数据库，存储应用程序的凭据（基本身份验证），或者是第三方服务，该服务检查给定的身份是否与其自己的受信任存储匹配（第三方身份验证）。

# 基本身份验证

HTTP 基本身份验证是目前最流行和直接的身份验证机制之一。它依赖于请求中的 HTTP 头，提供用户的凭据。可选地，服务器可能会回复一个头部，强制客户端进行身份验证。以下图显示了在进行基本身份验证时客户端和服务器的交互：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/rst-webapi-dsn-node10/img/80234492-f661-416f-8aeb-6aceb911f172.png)

每当向由 HTTP 基本身份验证保护的端点发送 HTTP 请求时，服务器都会以 HTTP `401 Unauthorized`状态代码进行回复，并且可选地附带`WWW-Authenticate`头。此头部强制客户端发送另一个请求，其中包含`Authorization`头，该头指定身份验证方法为`basic`。此请求后跟一个 base64 编码的键/值对，提供要进行身份验证的用户名和密码。可选地，服务器可以使用`realm`属性向客户端指定消息。

该属性指定具有相同`realm`值的资源应支持相同的身份验证方式。在上图中，`realm`消息是`MyRealmName`。客户端通过发送具有`Basic YWRtaW46YWRtaW4`值的`Authentication`头来进行身份验证，指定使用`Basic`身份验证，然后是 base64 编码的值。在图中，base64 解码的文字`YWRtaW46YWRtaW4`代表`admin:admin`文字。如果成功验证了这样的用户名/密码组合，HTTP 服务器将用所请求项目的 JSON 有效负载进行响应。如果身份验证失败，服务器将以`401 Unauthorized`状态代码进行响应，但这次不包括`WWW-Authenticate`头。

# 护照

现在有很多身份验证方法可供选择。也许最流行的方法是基本身份验证，每个用户都有自己的用户名和密码，以及第三方身份验证，用户可以使用他们已经存在的外部公共服务账户进行身份识别，例如个人社交服务，如 LinkedIn、Facebook 和 Twitter。

选择 Web API 的最合适的身份验证类型主要取决于其消费者。显然，使用 API 获取数据的应用程序不太可能使用个人社交账户进行身份验证。当 API 直接由人类使用前端直接使用时，这种方法更加合适。

实现一个能够轻松切换不同身份验证方法的解决方案是一个复杂且耗时的任务。事实上，如果在应用程序的初始设计阶段没有考虑到这一点，这几乎是不可能的。

**Passport**是专为 Node.js 设计的身份验证中间件，特别适用于身份验证方式需要轻松切换的用例。它具有模块化架构，可以使用特定的身份验证提供者，称为**策略**。该策略负责实现所选择的身份验证方法。

有很多身份验证策略可供选择，例如常规的基本身份验证策略或基于社交平台的策略，用于 Facebook、LinkedIn 和 Twitter 等服务。请参考官方 Passport 网站[`www.passportjs.org/`](http://www.passportjs.org/)，获取可用策略的完整列表。

# Passport 的基本身份验证策略

现在是时候看看如何利用 Passport 的策略了；我们将从基本身份验证策略开始；现在我们知道基本身份验证的工作原理，这是一个合乎逻辑的选择。

像往常一样，我们将使用 NPM 包管理器安装相关模块。我们需要`passport`模块，它提供了允许您插入不同身份验证策略的基本功能，以及由`passport-http`模块提供的基本身份验证的具体策略：

```js
  npm install passport
  npm install passport-http
```

接下来，我们需要实例化 Passport 中间件和基本身份验证策略。`BasicStrategy`以回调函数作为参数，检查提供的用户名/密码组合是否有效。最后，将 passport 的 authenticate 方法作为中间件函数提供给 express 路由，确保未经身份验证的请求将以适当的“401 未经授权”状态被拒绝：

```js
const passport = require('passport');
const BasicStrategy = require('passport-http').BasicStrategy;

passport.use(new BasicStrategy(function(username, password, done) {
  if (username == 'user' && password=='default') {
    return done(null, username);
  }
}));

router.get('/v1/', 
  passport.authenticate('basic', { session: false }), 
     function(request,    response, next) {
       catalogV1.findAllItems(response);
});
router.get('/v2/', 
  passport.authenticate('basic', { session: false }), 
     function(request,    response, next) {
       catalogV1.findAllItems(response);
});

router.get('/', 
  passport.authenticate('basic', { session: false }), 
     function(request,    response, next) {
       catalogV1.findAllItems(response);
});
```

`BasicStrategy`构造函数以处理程序函数作为参数。它使我们能够访问客户端提供的用户名和密码，以及 Passport 中间件的“done（）”函数，该函数通知 Passport 用户是否已成功验证。调用“done（）”函数并将`user`作为参数以授予身份验证，或者将`error`参数传递给它以撤销身份验证：

```js
passport.use(new BasicStrategy(
function(username, password, done) {
  AuthUser.findOne({username: username, password: password}, 
    function(error, user) {
      if (error) {
        return done(error);
      } else {
        if (!user) {
          console.log('unknown user');
          return done(error);
        } else {
          console.log(user.username + ' 
          authenticated successfully');
          return done(null, user);
        }
      }
    });  
  })
); 
```

最后，在路由器中间件中使用`passort` `authenticate（）`函数将其附加到特定的 HTTP 方法处理程序函数。

在我们的情况下，我们指定不希望在会话中存储任何身份验证细节。这是因为，在使用基本身份验证时，没有必要在会话中存储任何用户信息，因为每个请求都包含提供登录详细信息的`Authorization`标头。

# Passport 的 OAuth 策略

OAuth 是第三方授权的开放标准，它定义了一种委托协议，用于对抗第三方认证提供者。OAuth 使用特殊令牌，一旦发行，就用于标识用户，而不是用户凭据。让我们更仔细地看一下 OAuth 的工作流程，以一个示例场景为例。场景中的主要角色是-一个**用户**与一个**Web 应用程序**进行交互，该应用程序从**后端**系统中提供某种数据的 RESTful 服务。Web 应用程序将其授权委托给一个单独的**第三方授权服务器**。

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/rst-webapi-dsn-node10/img/850a429e-216a-4152-9434-422b7dbbb9fd.png)

1.  用户请求一个需要进行身份验证以与后端服务建立通信的 Web 应用程序。这是初始请求，因此用户仍未经过身份验证，因此他们被重定向到一个登录页面，要求提供相关第三方账户的凭据。

1.  成功认证后，认证服务器向 Web 应用程序发放授权代码。这个授权代码是由提供者发行的客户端 ID 和秘密的组合。它们应该从 Web 应用程序发送到认证服务器，并且用于交换具有有限生命周期的访问令牌。

1.  Web 应用程序使用认证令牌进行身份验证，直到它过期。之后，它必须使用授权代码请求新的令牌。

Passport.js 通过一个单独的策略模块隐藏了这个过程的复杂性，自动化了 OAuth 的工作流程。它可以在`npm`存储库中找到。

```js
npm install passport-oauth
```

创建策略的实例并为其提供请求令牌和认证的 URL，以及您的个人消费者密钥和您选择的秘密短语。

```js
var passport = require('passport')
  , OAuthStrategy = require('passport-oauth').OAuthStrategy;

passport.use('provider', new OAuthStrategy({
    requestTokenURL: 'https://www.provider.com/oauth/request_token',
    accessTokenURL: 'https://www.provider.com/oauth/access_token',
    userAuthorizationURL: 'https://www.provider.com/oauth/authorize',
    consumerKey: '123-456-789',
    consumerSecret: 'secret'
    callbackURL: 'https://www.example.com/auth/provider/callback'
  }, function(token, tokenSecret, profile, done) {  
    //lookup the profile and authenticate   and call done
  }
));
```

Passport.js 提供了包装不同提供者的单独策略，如 linkedin 或 github。它们确保您的应用程序与发放令牌的 URL 保持最新。一旦您确定要支持的提供者，就应该为它们检查特定的策略。

# Passport 的第三方认证策略

如今，几乎每个人都至少拥有一个个人公共社交媒体账户，如 Twitter、Facebook 和 LinkedIn。最近，让访问者通过点击一个图标来绑定他们的社交服务账户到一个服务内部自动生成的账户，已经变得非常流行。

这种方法非常方便，适用于通常至少有一个账户保持登录状态的网页用户。如果他们当前没有登录，点击图标将重定向他们到他们的社交服务登录页面，成功登录后，又会发生另一个重定向，确保用户获取他们最初请求的内容。但是，当涉及通过 Web API 公开数据时，这种方法并不是一个真正的选择。

公开的 API 无法预测它们是由人还是应用程序使用。此外，API 通常不会直接由人使用。因此，当您作为 API 作者确信公开的数据将直接通过互联网浏览器的前端手动请求的最终用户直接使用时，第三方认证是唯一的选择。一旦他们成功登录到他们的社交账户，唯一的用户标识符将被存储在会话中，因此您的服务需要能够适当地处理这样的会话。

要使用 Passport 和 Express 存储用户登录信息的会话支持，必须在初始化 Passport 及其会话中间件之前初始化 Express 会话中间件：

```js
app.use(express.session()); 
app.use(passport.initialize()); 
app.use(passport.session()); 
```

然后，指定 Passport 应将哪个用户的详细信息序列化/反序列化到会话中。为此，Passport 提供了`serializeUser()`和`deserializeUser()`函数，它们在会话中存储完整的用户信息：

```js
passport.serializeUser(function(user, done) { done(null, user); }); passport.deserializeUser(function(obj, done) { done(null, obj); });
```

初始化 Express 和 Passport 中间件的会话处理的顺序很重要。Express 会话应该首先传递给应用程序，然后是 Passport 会话。

启用会话支持后，您必须决定依赖哪种第三方身份验证策略。基本上，第三方身份验证是通过第三方提供商创建的插件或应用程序启用的，例如社交服务网站。我们将简要介绍如何创建一个允许通过 OAuth 标准进行身份验证的 LinkedIn 应用程序。

通常，这是通过与社交媒体应用程序关联的公钥和密钥（令牌）对来完成的。创建 LinkedIn 应用程序很容易——您只需登录[`www.linkedin.com/secure/developer`](http://www.linkedin.com/secure/developer)并填写简要的应用程序信息表。您将获得一个秘钥和一个令牌来启用身份验证。执行以下步骤来启用 LinkedIn 身份验证：

1.  安装`linkedin-strategy`模块—`npm install linkedin-strategy`

1.  获取 LinkedIn 策略的实例，并在启用会话支持后通过`use()`函数将其初始化为 Passport 中间件：

```js
      var passport = require('passport')
        , LinkedInStrategy = require('passport-
        linkedin').Strategy;

        app.use(express.session());
        app.use(passport.initialize());
        app.use(passport.session());

      passport.serializeUser(function(user, done) {
        done(null, user);
      });

      passport.deserializeUser(function(obj, done) {
        done(null, obj);
      });

        passport.use(new LinkedInStragety({
          consumerKey: 'api-key',
          consumerSecret: 'secret-key',
          callbackURL: "http://localhost:3000/catalog/v2"
        },
          function(token, tokenSecret, profile, done) {
            process.nextTick(function () {
              return done(null, profile);
            });
          })
        ); 
```

1.  明确指定 LinkedIn 策略应该作为每个单独路由的 Passport 使用，确保启用会话处理：

```js
      router.get('/v2/', 
        cache('minutes',1), 
        passport.authenticate('linked', { session: true}), 
        function(request, response) {
          //...
        }
      });
```

1.  提供一种方式让用户通过暴露注销 URI 来注销，利用`request.logout`：

```js
      router.get('/logout', function(req, res){
      request.logout();
        response.redirect('/catalog');
      });

```

提供的第三方 URL 和服务数据可能会发生变化。在提供第三方身份验证时，您应始终参考服务政策。

# 授权

到目前为止，目录数据服务使用基本身份验证来保护其路由免受未知用户的侵害；然而，目录应用程序应该只允许少数白名单用户修改目录中的项目。为了限制对目录的访问，我们将引入授权的概念，即，一组经过身份验证的用户，允许适当的权限。

当调用 Passport 的`done()`函数来验证成功的登录时，它以`user`用户的实例作为参数。`done()`函数将该用户模型实例添加到`request`对象中，并通过`request.user`属性提供对其的访问，以便在成功验证后执行授权检查。我们将利用该属性来实现一个在成功验证后执行授权检查的函数。

```js
function authorize(user, response) {
  if ((user == null) || (user.role != 'Admin')) {
    response.writeHead(403, { 'Content-Type' : 
    'text/plain'});
    response.end('Forbidden');
    return;
  }
} 
```

HTTP 403 Forbidden 状态码很容易与 405 Not allowed 混淆。然而，405 Not Allowed 状态码表示请求的资源不支持特定的 HTTP 动词，因此只能在该上下文中使用。

`authorize()`函数将关闭`response`流，返回`403 Forbidden`状态码，表示已识别登录用户但权限不足。这将撤销对资源的访问。此函数必须在执行数据操作的每个路由中使用。

以下是一个`post`路由实现授权的示例：

```js
app.post('/v2', 
  passport.authenticate('basic', { session: false }), 
    function(request, response) {
      authorize(request.user, response);
      if (!response.closed) {
        catalogV2.saveItem(request, response);
      }
    }
); 
```

调用`authorize()`后，我们通过检查`response`对象的 closed 属性的值来检查其输出是否仍然允许写入。一旦`response`对象的 end 函数被调用，closed 属性将返回`true`，这正是当用户缺少管理员权限时`authorize()`函数所做的。因此，我们可以在我们的实现中依赖 closed 属性。

# 传输层安全

网上公开的信息很容易成为不同类型的网络攻击的对象。通常仅仅把所谓的“坏人”挡在门外是不够的。有时，他们甚至不会费心获得认证，而是更喜欢进行**中间人**（**MiM**）攻击，假装是消息的最终接收者，并窃听传输数据的通信渠道，甚至更糟糕的是在数据流动时修改数据。

作为一种基于文本的协议，HTTP 以人类可读的格式传输数据，这使得它很容易成为 MiM 攻击的受害者。除非以加密格式传输，否则我们服务的所有目录数据都容易受到 MiM 攻击的威胁。在本节中，我们将把我们的传输方式从不安全的 HTTP 协议切换到安全的 HTTPS 协议。

HTTPS 由非对称加密，也称为**公钥加密**，来保护。它基于数学相关的一对密钥。用于加密的密钥称为**公钥**，用于解密的密钥称为**私钥**。其思想是自由提供加密密钥给必须发送加密消息的合作伙伴，并用私钥执行解密。

两个方，*A* 和 *B* 之间的典型的公钥加密通信场景如下：

1.  Party *A* 组成一条消息，用 *B* 方的公钥加密，然后发送

1.  Party *B* 用自己的私钥解密消息并处理它

1.  Party *B* 组成一个响应消息，用 *A* 方的公钥加密，然后发送

1.  Party *A* 用自己的私钥解密响应消息

现在我们知道公钥加密是如何工作的，让我们通过 HTTPS 客户端-服务器通信的示例来了解一下：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/rst-webapi-dsn-node10/img/46046c17-c975-4e14-aecc-b94764bc16a3.png)

客户端对 SSL 安全端点发送初始请求。服务器对该请求做出响应，发送其公钥以用于加密进一步的传入请求。然后，客户端必须检查接收到的密钥的有效性并验证其身份。在成功验证服务器的公钥之后，客户端必须将自己的公钥发送回服务器。最后，在密钥交换过程完成后，两个方可以开始安全地通信。

HTTPS 依赖于信任；因此，有一种可靠的方式来检查特定的公钥是否属于特定的服务器是至关重要的。公钥在 X.509 证书中交换，具有分层结构。这种结构使客户端能够检查给定的证书是否是由受信任的根证书生成的。客户端应该只信任由已知的**证书颁发机构**（**CA**）颁发的证书。

在将我们的服务切换到使用 HTTPS 传输之前，我们需要一个公钥/私钥对。由于我们不是证书颁发机构，我们将不得不使用 OpenSSL 工具为我们生成测试密钥。

OpenSSL 可以在[`www.openssl.org/`](http://www.openssl.org/)下载，那里提供了所有流行操作系统的源代码分发。OpenSSL 可以按照以下方式安装：

1.  二进制分发可供 Windows 下载，Debian 和 Ubuntu 用户可以通过执行以下命令使用打包的分发：

```js
sudo apt-get install openssl
```

Windows 用户需要设置一个环境变量 OPENSSL_CNF，指定`openssl.cnf`配置文件的位置，通常位于安装存档的共享目录中。

1.  现在让我们用 OpenSSL 生成一个测试的键/值对：

```js
opensslreq -x509 -nodes -days 365 -newkey rsa:2048-keyoutcatalog.pem -out catalog.crt
```

OpenSSL 将提示生成证书所需的一些细节，例如国家代码、城市和完全合格的域名。之后，它将在`catalog.pem`文件中生成一个私钥，并在`catalog.crt`文件中生成一个有效期为一年的公钥证书。我们将使用这些新生成的文件，所以将它们复制到目录数据服务目录中的一个名为`ssl`的新子目录中。

现在我们拥有了修改我们的服务以使用 HTTPS 所需的一切：

1.  首先，我们需要切换并使用 HTTPS 模块而不是 HTTP，并指定要使用的端口以启用 HTTPS 通信：

```js
var https = require('https');
var app = express();
app.set('port', process.env.PORT || 3443); 
```

1.  然后，我们需要将`catalog.cem`文件中的私钥和`catalog.crt`中的证书读入数组中：

```js
var options = {key : fs.readFileSync('./ssl/catalog.pem'),
                cert : fs.readFileSync('./ssl/catalog.crt')
}; 
```

1.  最后，我们将包含密钥对的数组传递给创建服务器的 HTTPS 实例，并通过指定的端口开始监听：

```js
https.createServer(options, app).listen(app.get('port'));
```

这就是为 Express 应用程序启用 HTTPS 所需做的一切。保存您的更改，并尝试在浏览器中请求`https://localhost:3443/catalog/v2`。您将看到一个警告消息，告诉您正在连接的服务器正在使用由不受信任的证书颁发机构颁发的证书。这是正常的，因为我们自己生成了证书，而且我们肯定不是 CA，所以只需忽略该警告。

在将服务部署到生产环境之前，您应始终确保使用由受信任的 CA 颁发的服务器证书。

# 自测问题

回答以下问题：

+   HTTP 基本身份验证是否安全防范中间人攻击？

+   传输层安全性有哪些好处？

# 摘要

在本章中，您学会了如何通过启用身份验证和授权手段来保护暴露的数据。这是任何公开可用数据服务的关键方面。此外，您还学会了如何使用服务和用户之间的安全层传输协议来防止中间人攻击。作为这类服务的开发人员，您应该始终考虑应用程序应支持的最合适的安全功能。

希望这是一个有用的经验！您获得了足够的知识和实际经验，这应该使您更加自信地理解 RESTful API 的工作原理以及它们的设计和开发方式。我强烈建议您逐章阅读代码演变。您应该能够进一步重构它，使其适应您自己的编码风格。当然，它的一些部分可以进一步优化，因为它们经常重复。这是一个故意的决定，而不是良好的实践，因为我想强调它们的重要性。您应该始终努力改进您的代码库，使其更易于维护。

最后，我想鼓励您始终关注您在应用程序中使用的`Node.js`模块的发展。Node.js 拥有一个迅速增长的非凡社区。那里总是有一些令人兴奋的事情发生，所以确保您不要错过。祝你好运！
