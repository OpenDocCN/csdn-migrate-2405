# JavaScript JSON 秘籍（二）

> 原文：[`zh.annas-archive.org/md5/7BFA16E9EEE620D98CFF9D2379355647`](https://zh.annas-archive.org/md5/7BFA16E9EEE620D98CFF9D2379355647)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：使用 MongoDB 的 JSON

在本章中，我们将介绍以下食谱：

+   设置 MongoDB

+   为 Node.js 安装 MongoDB 数据库驱动程序

+   为 Node.js 安装 express 模块

+   使用 Node.js 连接 MongoDB 数据库

+   使用 Node.js 在 MongoDB 中创建文档

+   使用 Node.js 在 MongoDB 中搜索文档

+   使用 Node.js 在 MongoDB 中更新文档

+   使用 Node.js 在 MongoDB 中删除文档

+   使用 REST 搜索 MongoDB

+   使用 REST 在 MongoDB 中创建文档

+   使用 REST 更新 MongoDB 中的文档

+   使用 REST 在 MongoDB 中删除文档

# 简介

在本章中，我们将介绍如何使用 MongoDB 作为 Web 应用程序的后端存储。虽然不是完全专注于 JSON，但正如你所见，本章的食谱将帮助你管理使用 MongoDB 在 Node.js 中直接创建、读取、更新和删除文档，然后使用为 Node.js 和 MongoDB 构建的 REST 服务器，这样你就可以从网络客户端（如 Web 应用程序）管理文档。

# 设置 MongoDB

安装 MongoDB 取决于平台；在 Linux 上，你可能可以使用像 apt 这样的包安装器，而在 Windows 和 Mac OS X（以及如果你有没有包含 MongoDB 包的包管理器的 Linux 发行版）上，可以使用网页下载。

## 如何做到…

1.  在 Mac OS X 和 Windows 上，只需前往[`www.mongodb.org/`](http://www.mongodb.org/)并点击下载链接。在撰写本文时，MongoDB 处于 2.6.7 版本；有一个 3.0 版本的候选发布，我们在这里不再进一步讨论。

    Mongo 还提供了针对几种常见 Linux 发行版的包，包括 Debian 和 Fedora。还有一个适用于 FreeBSD 的包。

1.  一旦你下载并安装了 Mongo，你需要为 MongoDB 提供一个存储数据库的地方。

    这取决于平台；在 Windows 上，它是`c:\data\db.`

1.  一旦你这样做，你可以通过运行`mongod`来启动数据库服务器。你可能还想将 MongoDB 客户端和服务器二进制文件的路径添加到你的路径中，这样你就可以从命令行轻松访问它们。

1.  当你运行 MongoDB 服务器时，你应该会看到一堆类似于这样的日志消息：

    ```js
    C:\Program Files\MongoDB 2.6 Standard\bin\mongod.exe --help for help and startup options
    2015-02-15T13:10:07.909-0800 [initandlisten] MongoDB starting : pid=13436 port=27017 dbpath=\data\db\ 64-bit host=KF6GPE-SURFACE
    2015-02-15T13:10:07.911-0800 [initandlisten] targetMinOS: Windows 7/Windows Server 2008 R2
    2015-02-15T13:10:07.913-0800 [initandlisten] db version v2.6.7
    2015-02-15T13:10:07.914-0800 [initandlisten] git version: a7d57ad27c382de82e9cb93bf983a80fd9ac9899
    2015-02-15T13:10:07.915-0800 [initandlisten] build info: windows sys.getwindowsversion(major=6, minor=1, build=7601, pla
    tform=2, service_pack='Service Pack 1') BOOST_LIB_VERSION=1_49
    2015-02-15T13:10:07.917-0800 [initandlisten] allocator: system
    2015-02-15T13:10:07.920-0800 [initandlisten] options: {}
    2015-02-15T13:10:07.930-0800 [initandlisten] journal dir=\data\db\journal
    2015-02-15T13:10:07.931-0800 [initandlisten] recover : no journal files present, no recovery needed
    2015-02-15T13:10:07.967-0800 [initandlisten] waiting for connections on port 27017
    ```

    你可能会注意到服务器正在运行的主机名（在这个例子中，`KF6GPE-SURFACE`）和端口号，默认应该是`27017`。

1.  要直接连接到 MongoDB 服务器，你可以在命令行上运行`mongo`，像这样：

    ```js
    C:\>mongo
    MongoDB shell version: 2.6.7
    connecting to: test
    >
    ```

1.  要退出`mongo`二进制文件，请按*Ctrl* + *C*或输入`exit`。

## 它是如何工作的…

双击可执行安装程序和 Linux 包将安装 mongod 二进制文件，即数据库，以及 Mongo 命令行客户端。

# 安装 MongoDB 数据库驱动程序（重复）

你需要为 Node.js 安装数据库驱动程序，这样 Node.js 就可以直接与 MongoDB 服务器通信。

## 如何做到…

要获取数据库驱动程序，只需前往你拥有 Node.js 文件的项目的目录，并运行以下命令：

```js
npm install mongodb

```

这个命令将下载数据库驱动程序并为 Node.js 安装它们。

# 为 Node.js 安装 express 模块

Node.js 的 express 模块使得使用 Node.js 构建表示状态转移（REST）服务器应用程序变得容易。REST 是一种在网络编程中使用的强大范式，它使用 HTTP 方法`GET`、`POST`、`PUT`和`DELETE`来管理 Web 服务的文档管理的创建、读取、更新和删除（通常缩写为 CRUD）操作。

使用 REST，URL 是表示你想要操纵什么的名词，HTTP 方法是动词，对那些名词执行动作。

在接下来的食谱中，我们将使用 Node.js 的 express 模块构建一个 RESTful 服务器，该服务器从 Mongo 返回文档，并支持基本的 CRUD 操作。在开始之前，你需要安装三个额外的模块。

## 如何去做…

你将使用`npm`，Node.js 的包管理器，来安装跨对象资源模块以支持跨域脚本，express 模块，以及 express 使用的 body-parser 模块。为此，在你的项目目录中运行以下命令：

```js
npm install cors
npm install express
npm install body-parser

```

你还需要一个基本的应用程序，或者骨架，用于你的 REST 服务器，它包括 REST 服务器之间的 URL 路由、HTTP 方法以及执行必要数据库操作的函数。这个骨架包括使用 express 模块的两个 Node.js 脚本和一个 HTML 文档。

第一个 Node.js 脚本是 REST 服务器本身，位于`rest-server.js`中，它看起来像这样：

```js
var express = require('express'),
  documents = require('./routes/documents'),
  cors = require('cors'),
  bodyParser = require('body-parser');

var app = express();

app.use(cors());
var jsonParser = bodyParser.json();

app.get('/documents', documents.findAll);
app.get('/documents/:id', documents.findById);
app.post('/documents', jsonParser, documents.addDocuments);
app.put('/documents/:id', jsonParser, documents.updateDocuments);
app.delete('/documents/:id', jsonParser, 
documents.deleteDocuments);

app.listen(3000);
console.log('Listening on port 3000...');
```

## 它是如何工作的…

包管理器安装每个模块，如有需要，从源代码构建它们。你需要所有三个模块：CORS 模块以支持跨域脚本请求、express 模块用于 REST 服务器框架，最后，body-parser 模块将客户端对象体从 JSON 转换为 JavaScript 对象。

骨架脚本包括 express 模块、我们的*路由*文件，它将定义处理每个 REST 用例的函数、CORS 模块以及 express 需要的 body-parser 模块来解释客户端发送的对象体。

一旦包含这些，它定义了一个名为`app`的 express 模块实例，并用 CORS 对其进行配置。这是必要的，因为默认情况下，浏览器不会对页面的内容来源不同的域名服务器发起 AJAX 请求，以防止服务器被攻陷并注入恶意 JavaScript 的跨站脚本攻击。CORS 模块为服务器设置必要的头，以便让我们可以使用上一章中的旧 Node.js 服务器在端口`1337`上提供内容，并让我们的内容访问在此不同端口上运行的 REST 服务器。

接下来，我们获取一个对 body-parser 的 JSON 解析器的引用，我们将用它来解析客户端为插入和更新请求发送的对象体。之后，我们用处理顶级文档 URL 的手动器配置 Express 应用服务器实例，该 URL 用于通过 REST 访问我们的 MongoDB 文档。在这个 URL 上有五种可能的操作：

+   对 URL `/documents`的 HTTP GET simply returns a list of all the documents in the database

+   对 URL `/documents/<id>`的 HTTP GET 返回具有给定 ID 的数据库中的文档

+   对`/documents`的 HTTP POST，带有 JSON 格式的文档，将该文档保存到数据库中

+   对`/documents/<id>`的 HTTP PUT，带有 JSON 格式的文档，更新具有给定 ID 的文档，使其包含客户端传递的内容

+   对`/documents/<id>`的 HTTP DELETE 删除具有给定 ID 的文档

最后，脚本在端口`3000`上启动服务器，并记录服务器已启动的事实。

当然，我们需要在文档对象中定义函数；我们是在文件`routes/documents.js`中完成的，该文件最初应看起来像这样：

```js
var mongo = require('mongodb');

var mongoServer = mongo.Server,
    database = mongo.Db,
    objectId = require('mongodb').ObjectID;

var server = new mongoServer('localhost', 27017, 
{auto_reconnect: true});
var db = new database('test', server);

db.open(function(err, db) {
  if(!err) {
    console.log("Connected to 'test' database");
    db.collection('documents', 
    {strict:true}, 
    function(err, collection) {
      if (err) {
        console.log("Inserting sample data...");
        populate();
      }
    });
  }
});

exports.findById = function(req, res) {
  res.send('');
};

exports.findAll = function(req, res) {
  res.send('');
};

exports.addDocuments = function(req, res) {
  res.send('');
};

exports.updateDocuments = function(req, res) {
  res.send('');
};

exports.deleteDocuments = function(req, res) {
  res.send('');
};

var populate = function() {
var documents = [
  {
    call: 'kf6gpe',
    lat: 37,
    lng: -122  }
];
db.collection('documents', function(err, collection) {
  collection.insert(wines, {safe:true}, 
  function(err, result) {});
  });
};
```

上述代码首先通过导入本地 MongoDB 驱动程序开始，设置变量以保存服务器实例、数据库实例和一个转换器接口，该接口将字符串转换为 MongoDB 对象 ID。接下来，它创建一个服务器实例，连接到我们的服务器实例（必须运行才能成功），并获得对我们数据库的引用。最后，它打开到数据库的连接，如果数据库为空，则在数据库中插入一些示例数据。（这个代码在阅读本章的前两个食谱后会更清晰，所以如果现在有些困惑，只需继续阅读，您会做得很好的！）

`routes/documents.js`文件的其余部分定义了处理我们在这`rest-server.js`脚本中连接的每个 REST 用例的函数。我们将在食谱中逐步完善每个函数。

最后，我们需要一个 HTML 文档来访问 REST 服务器。我们的文档看起来像这样：

```js
<!DOCTYPE html>
<html>
<head>
<script type="text/javascript"
  src="img/jquery-1.11.2.min.js"></script>
</head>
<body>

<p>Hello world</p>
<p>
<div id="debug"></div>
</p>
<p>
<div id="json"></div>
</p>
<p>
<div id="result"></div>
</p>

<button type="button" id="get" onclick="doGet()">Get</button><br/>
<form>
  Id: <input type="text" id="id"/>
  Call: <input type="text" id="call"/>
  Lat: <input type="text" id="lat"/>
  Lng: <input type="text" id="lng"/>
<button type="button" id="insert" 
    onClick="doUpsert('insert')">Insert</button>
<button type="button" id="update" 
onClick="doUpsert('update')">Update</button>
<button type="button" id="remove" 
onClick="doRemove()">Remove</button>
</form>
</body>
</html>
```

我们在脚本中使用一些 jQuery 来使字段访问更加容易（您将在即将到来的 REST 插入、更新、删除和查询食谱中看到脚本）。HTML 本身由三个`div`标签组成，分别用于调试、显示原始 JSON 和每个 REST 操作的结果，以及一个表单，让您输入创建、更新或删除记录所需的字段。

## 也见

关于卓越的 Node.js express 模块的更多信息，请参见[`expressjs.com/`](http://expressjs.com/)。

MongoDB 是一个强大的文档数据库，这里涵盖的内容远远不够。更多信息，请上网搜索，或查看 PacktPub 网站上的以下资源：

+   *Instant MongoDB* by *Amol Nayak*。

+   *MongoDB Cookbook* by *Amol Nayak*。

# 使用 Node.js 连接到 MongoDB 数据库

在你 Node.js 应用程序能够与 MongoDB 实例做任何事情之前，它必须通过网络连接到它。

## 如何做到这一点...

MongoDB 的 Node.js 驱动包含了所有必要的网络代码，用于与本地或远程机器上运行的 MongoDB 建立和断开连接。

你需要在代码中包含对原生驱动的引用，并指定要连接的数据库的 URL。

下面是一个简单的例子，它连接到数据库然后立即断开连接：

```js
var mongo = require('mongodb').MongoClient;

var url = 'mongodb://localhost:27017/test';

mongo.connect(url, function(error, db) {
  console.log("mongo.connect returned " + error);
  db.close();
});
```

让我们逐行分解这个问题。

## 它是如何工作的…

第一行包括了 Node.js 应用程序中 Mongo 的本地驱动实现，并提取了它定义的`MongoClient`对象的引用。这个对象包含了与数据库通过网络交互所需的基本接口，定义了`connect`和`close`方法。

下一行定义了一个字符串`url`，它包含了要连接的数据库的 URL。这个 URL 的格式很简单：它以`mongodb`方案开始，以表示它是 MongoDB 服务器的 URL。接下来是主机名和端口（在这个例子中，我们连接到本地主机的默认端口，即`27017`）。最后，我们来到你想要连接的数据库的名称：在我们的例子中，是`test`。

如果你使用 MongoDB 的用户访问控制来控制对数据库的访问，你还需要指定一个用户名和密码。你这样做的方式和你对任何其他 URL 的做法一样，像这样：

```js
mongodb://user:password@host:port/database
```

当然，是否保护你的数据库取决于你的网络结构和部署；通常来说，这样做是个好主意。

我们将这个 URL 传递给 mongo 对象的`connect`方法，同时提供一个函数，当连接成功建立，或者连接失败时，MongoDB 原生驱动会回调这个函数。驱动会以两个参数调用回调函数：第一个是出现错误时的错误代码（成功时为`null`），第二个是一个包含对你指定的数据库连接的数据库对象引用（如果建立连接时出现错误，则可能为`null`）。

我们的回调函数非常直接；它打印一个包含传递给它的错误代码值的消息，然后我们使用`close`断开与数据库的连接。

### 提示

当你使用完数据库对象时，总是调用其`close`方法，以确保原生驱动能够成功清理自身并从数据库断开连接。如果你不这么做，你可能会导致数据库连接泄露。

## 参见 also

关于为 Node.js 设计的 MongoDB 原生驱动的更多信息，请参阅[`docs.mongodb.org/ecosystem/drivers/node-js/`](http://docs.mongodb.org/ecosystem/drivers/node-js/)。

# 使用 Node.js 在 MongoDB 中创建文档

MongoDB 数据库通过*集合*来组织其文档，这些集合通常是相关联的一组文档（例如表示相同种类信息的文档）。由于这个原因，您与文档交互的主要界面是通过一个集合。让我们看看如何获取一个集合并向其中添加一个文档。

### 提示

集合在关系型数据库中类似于一个表，但并没有规定集合中的所有文档必须具有相同的字段或每个字段相同的类型。可以将其视为一个用于分组类似文档的抽象概念。

## 怎么做...

以下是一个函数，它使用 Node.js 在我们的测试数据库中名为`documents`的集合中插入两个静态条目：

```js
var mongo = require('mongodb').MongoClient;

var url = 'mongodb://localhost:27017/test';

var insert = function(collection, callback) {
  var documents = 
    [{ 
        call: 'kf6gpe-7', lat: 37.0, lng: -122.0 
      },
      {
        call: 'kf6gpe-9', lat: 38.0, lng: -123.0
      }];
  // Insert some documents
  collection.insert(documents, 
    function(error, result) {
      console.log('Inserted ' +result.length + ' documents ' + 
        'with result: ');
      console.log(result);
      callback(result);
  });
};

mongo.connect(url, function(error, db) {
  console.log('mongo.connect returned ' + error);

  // Get the documents collection
  var collection = db.collection('documents');
  insert(collection, function(result) {
    db.close();
  });
});
```

我把代码分成两部分，以便使回调结构更清晰：实际执行插入的`insert`函数和连接回调，该回调调用插入函数。

让我们仔细看看。

## 它是如何工作的...

代码的开始方式是一样的，通过获取一个对`MongoClient`对象的引用，它用这个对象与数据库通信。连接代码基本上也是一样的；URL 是一样的，唯一的改变是对数据库的`collection`方法的调用，传递我们感兴趣的集合的名称。`collection`方法返回一个`collection`对象，该对象提供了我们对文档集合执行 CRUD 操作的方法。

`insert`函数做几件事情。它接收一个您想要操作的集合和一个回调函数，当插入操作完成或失败时，它将调用这个回调函数。

首先，它定义了要在数据库中插入的一对静态条目。请注意，这些只是普通的旧 JavaScript 对象；基本上，任何您可以表示为 JavaScript 对象的东西，您都可以存储在 MongoDB 中。接下来，它调用集合的`insert`方法，传递要存储的对象和一个回调函数，驱动程序在尝试插入后调用该函数。

驱动程序再次调用回调函数，传递一个错误值（在成功时为`null`）和作为它们被插入到集合中的 JavaScript 对象。我们的回调函数将结果日志记录到控制台，并调用回调插入函数的回调，关闭数据库。

插入的记录看起来是什么样子呢？以下是从我的控制台获取的示例，确保我们正在运行 MongoDB：

```js
PS C:\Users\rarischp\Documents\Node.js\mongodb> node .\example.js
mongo.connect returned null
Inserted 2 documents with result:
[ { call: 'kf6gpe-7',
    lat: 37,
    lng: -122,
    _id: 54e2a0d0d00e5d240f22e0c0 },
  { call: 'kf6gpe-9',
    lat: 38,
    lng: -123,
    _id: 54e2a0d0d00e5d240f22e0c1 } ]
```

请注意，这些对象有相同的字段，但它们还有一个额外的`_id`字段，这是对象在数据库中的唯一标识符。在下一节中，您将学习如何针对该字段进行查询。

## 还有更多内容

如果你多次将同一个对象插入数据库，会发生什么？试试看！你会发现数据库中有该对象的多个副本；字段不用于指定唯一性（例外是`_id`字段，它在整个数据库中是唯一的）。注意你不能自己指定一个`_id`字段，除非您确信它是唯一的。要更新现有元素，请使用更新方法，我在本章的*使用 Node.js 在 MongoDB 中更新文档*菜谱中描述了该方法。

默认情况下，MongoDB 的插入操作很快，可能会失败（比如说，如果网络存在临时问题，或者服务器暂时过载）。为了保证安全，你可以将`{ safe: true }`作为插入操作的第二个参数，或者等待操作成功，或者在操作失败时返回一个错误。

## 也见

参考[`docs.mongodb.org/manual/reference/method/db.collection.insert/`](http://docs.mongodb.org/manual/reference/method/db.collection.insert/)获取有关如何将文档插入 MongoDB 集合的文档。

# 使用 Node.js 在 MongoDB 中搜索文档

如果你不能搜索文档，那么能够插入文档也帮助不大。MongoDB 允许你指定一个模板进行匹配，并返回匹配该模板的对象。

与插入和更新操作一样，你将处理一个文档集合，调用集合的`find`方法。

## 如何做到...

这是一个例子，它找到 test 集合中所有`kf6gpe-7`的文档，并将它们打印到控制台：

```js
var mongo = require('mongodb').MongoClient;

var url = 'mongodb://localhost:27017/test';

mongo.connect(url, function(error, db) {
  console.log("mongo.connect returned " + error);

  var cursor = collection.find({call: 'kf6gpe-7'});
  cursor.toArray(function(error, documents) {
    console.log(documents);

    db.close();
  });
});
```

## 它是如何工作的...

连接到数据库后，我们在集合中调用`find`，它返回一个游标，您可以使用它遍历找到的值。`find`方法接受一个 JavaScript 对象，作为模板指示您想要匹配的字段；我们的例子匹配名为`call`的字段等于`kf6gpe-7`的记录。

我们不是遍历游标，而是通过使用游标的`toArray`方法，将找到的所有值转换成一个单一的数组。这对于我们的例子来说是可以的，因为结果并不多，但是在具有很多项的数据库上这样做要小心！一次性从数据库中获取比你实际需要更多的数据，会使用到应该分配给应用程序其他部分的 RAM 和 CPU 资源。最好是遍历集合，或者使用分页，我们接下来会讨论。

## 还有更多内容

游标有几种方法可供您遍历搜索结果：

+   `hasNext`方法如果游标还有其他可以返回的项，则返回`true`。

+   `next`方法返回游标中的下一个匹配项。

+   `forEach`迭代器接收一个函数，按顺序对游标的每个结果调用该函数。

遍历游标时，最好使用带有`hasNext`的 while 循环并调用 next，或者使用`forEach`；不要只是将结果转换为数组并在列表上循环！这样做需要数据库一次性获取所有记录，可能会非常占用内存。

有时，可能仍然有太多的项目需要处理；您可以使用游标方法`limit`和`skip`来限制返回的条目数量。`limit`方法将搜索限制为您传递的参数数量的条目；`skip`方法跳过您指定的条目数量。

实际上，find 方法实际上接受两个参数：一个 JavaScript 对象是请求的准则，一个可选的 JavaScript 对象定义了结果集的投影，以新的 JavaScript 对象形式返回。

条件可以是精确匹配条件，正如你在上一个例子中看到的那样。你还可以使用特殊操作`$gt`和`$lt`进行匹配，这些操作允许你按基数顺序过滤给定字段。例如，你可能这样写：

```js
var cursor = collection.find({lng: { $gt: 122 } });
```

这将返回所有`lng`字段值大于 122 的记录。

投影是一个你感兴趣的从数据库接收的字段列表，每个字段设置为`true`或`1`。例如，以下代码返回只包含`call`和`_id`字段的 JavaScript 对象：

```js
var cursor = collection.find(
{call: 'kf6gpe-7'}, 
{call: 1, _id: 1});
```

## 参见

参见[`docs.mongodb.org/manual/reference/method/db.collection.find/`](http://docs.mongodb.org/manual/reference/method/db.collection.find/)关于 MongoDB find 方法的文档，该方法是原生驱动程序使 Node.js 应用程序可用的。

# 使用 Node.js 在 MongoDB 中更新文档

在集合中更新一个文档很容易；只需使用集合的`update`方法并传递您想要更新的数据。

## 如何做到…

这是一个简单的例子：

```js
var mongo = require('mongodb').MongoClient;

var url = 'mongodb://localhost:27017/test';

var update = function(collection, callback) {
  collection.update({ call:'kf6gpe-7' }, 
    { $set: { lat: 39.0, lng: -121.0, another: true } }, 
    function(error, result) {
      console.log('Updated with error ' + error);
      console.log(result);
      callback(result);
    });
};

mongo.connect(url, function(error, db) {
  console.log("mongo.connect returned " + error);

  // Get the documents collection
  var collection = db.collection('documents');
  update(collection, function(result) {
    db.close();
  });
});
```

这个模式与`insert`方法相同；`update`是一个异步方法，它调用一个带有错误代码和结果的回调。

## 它是如何工作的…

`update`方法采用一个模板来匹配文档，并用传递给`$set`的 JavaScript 对象的值更新第一个匹配的文档。注意，你也可以向文档中添加新字段，就像我们在这里做的那样；我们添加了一个名为`another`的新字段，其值为`true`。

您可以通过传递文档的 ID 来指定与特定文档的精确匹配，该 ID 位于传递给 update 的模板的`_id`字段中。传递给`update`的模板是一个标准的查询模板，就像你会传递给`find`的那样。

## 还有更多…

默认情况下，`update`更新第一个匹配的文档。如果您想要它更新与您的模板匹配的所有文档，请在更新中传递一个可选的第三个参数，即 JavaScript 对象`{ multi: true }`。您还可以让`update`执行*upsert*，即在匹配成功时进行更新，如果匹配不成功则进行插入。为此，在更新的第三个参数中传递 JavaScript 对象`{ upsert: true }`。这些可以组合使用以匹配多个文档和执行 upsert；如果没有找到，则传递。

```js
{
  multi: true,
  upsert: true
}
```

类似于插入操作，您还可以在这个选项的参数中传递`safe: true`，以确保在返回之前 update 尝试成功，但这样做会牺牲性能。

`update`方法将更新的文档数作为其结果传递给您的回调。

## 也见

参见 MongoDB 原生驱动程序文档中的 update 部分[`github.com/mongodb/node-mongodb-native`](https://github.com/mongodb/node-mongodb-native)或 MongoDB update 方法文档[`docs.mongodb.org/manual/reference/method/db.collection.update/`](http://docs.mongodb.org/manual/reference/method/db.collection.update/)。

# 使用 Node.js 在 MongoDB 中删除文档

在某个时候，您可能希望使用 Node.js 在集合中删除文档。

## 如何做到...

您使用`remove`方法来实现，该方法会从您指定的集合中移除匹配的文档。以下是调用`remove`方法的示例：

```js
var remove = function(collection, callback) {
  collection.remove({ call: 'kf6gpe-7'},
    function(error, result)
    {
      console.log('remove returned ' + error);
      console.log(result);
      callback(result);
    });
};
```

## 如何工作…

这段代码移除了字段`call`值为`kf6gpe-7`的文档。正如您可能猜到的那样，`remove`的搜索条件可以是您会传递给 find 的任何东西。`remove`方法会移除*所有*与您的搜索条件匹配的文档，所以要小心！调用`remove({})`会移除当前集合中的所有文档。

`remove`方法返回从集合中删除的项目的数量。

## 也见

关于 MongoDB 的 remove 方法，请参阅其文档[`docs.mongodb.org/manual/reference/method/db.collection.remove/`](http://docs.mongodb.org/manual/reference/method/db.collection.remove/)。

# 使用 REST 搜索 MongoDB

到目前为止，您可能想知道在使用 MongoDB 时 JSON 扮演什么角色。当您使用像 mongo-rest 这样的 RESTful 接口访问 MongoDB 数据库实例时，文档会使用 JSON 传输到客户端。让我们看看如何从 MongoDB 获取文档列表。

## 如何做到...

使用 Node.js、MongoDB 和 REST 需要几个步骤。

1.  确保您已经按照介绍中的讨论设置了 REST 服务器。您需要创建`rest-server.js`、`routes/documents.js`和`mongo-rest-example.html`这些文件，其中包含我们 RESTful 应用的 UI，并用 Node.js 同时运行 REST 服务器和文档服务器。

1.  其次，确保您正在运行 MongoDB。

1.  接下来，为了处理 REST `GET`请求，我们需要在`documents.js`中定义函数`exports.findAll`，它应该如下所示：

    ```js
    exports.findAll = function(req, res) {
      db.collection('documents', function(err, collection) {
        collection.find().toArray(function(err, items) {
          res.send(items);
        });
      });
    };
    ```

1.  之后，我们需要`mongo-rest-example.html`文件中的`doGet`脚本，它对 REST 服务器上的数据库文档发起 AJAX `GET`请求。这段代码向服务器的`/documents/` URL 发起 AJAX `GET`请求，将返回的 JSON 放入具有`id`为 json 的`div`中，并构建一个 HTML 表格，每个结果文档的结果有一行，提供每个文档的 ID、呼号、纬度和经度等列：

    ```js
    function doGet() { 
      $.ajax({
        type: "GET",
        url: "http://localhost:3000/documents/",
        dataType: 'json',
      })
    .done(function(result) {
        $('#json').html(JSON.stringify(result));
        var resultHtml = 
    '<table><thead>' + 
    '<th><td><b>id</b></td><td><b>call</b></th>' + 
    '<tbody>';
        resultHtml += '<td><b>lat</b></td><td><b>lng</b></td></tr>';

          $.each(result), function(index, item)
          {
            resultHtml += '<tr>';
            resultHtml += '<td>' + item._id + '</td>';
            resultHtml += '<td>' + item.call + '</td>';
            resultHtml += '<td>' + item.lat + '</td>';
            resultHtml += '<td>' + item.lng + '</td>';
            resultHtml += "</tr>";
          };
        $resultHtml += '</tbody></table>';

        $('#result').html(resultHtml);
      })
    }
    ```

## 它是如何工作的…

`findAll`方法是对数据库的直接查询，它使用`find`在我们的集合中匹配所有的文档。你可以扩展它以接受一个查询模板作为 URL 参数，然后将该参数作为 URL 编码的参数传递给 GET URL。

你还可以添加其他参数，例如限制和跳过的参数，如果你处理的数据量很大，你应该考虑这样做。请注意，Express 模块知道它需要将 JavaScript 对象 JSON 编码以 JSON 的形式发送给客户端。

`doGet` JavaScript 代码更简单；它是一个纯粹的 AJAX 调用，后面跟着一个循环，将返回的 JSON 数组解包为对象，并将每个对象作为表格中的一行呈现。

## 还有更多

一个好的 REST 接口还提供了一个通过 ID 查询特定项目的接口，因为通常你希望查询集合，在其中找到一些有趣的内容，然后可能需要对这个特定的 ID 做些什么。我们定义了`findById`方法来接收来自 URL 的 ID，将 ID 转换为 MongoDB 对象`id`，然后仅对该 ID 执行`find`，如下所示：

```js
exports.findById = function(req, res) {
  var id = new objectId(req.params.id);
  db.collection('documents', function(err, collection) {
    collection.findOne({'_id':id}, function(err, item) {
      res.send(item);
    });
  });
};
```

# 使用 REST 在 MongoDB 中创建文档

原则上，使用 REST 创建文档是简单的：在客户端创建 JavaScript 对象，将其编码为 JSON，并`POST`到服务器。让我们看看这个在实际中是如何工作的。

## 如何做到…

这有两部分：客户端部分和服务器部分。

1.  在客户端，我们需要一种方式来获取我们新 MongoDB 文档的数据。在我们的例子中，它是 HTML 页面上的表单字段，我们将它们包装起来，并使用客户端（在 HTML 中）的`doUpsert`方法`POST`到服务器：

    ```js
    function doUpsert(which)
    {
    Var id = $('#id').val();
    var value = {};
      value.call = $('#call').val();
      value.lat = $('#lat').val();
      value.lng = $('#lng').val();

      $('#debug').html(JSON.stringify(value));

    var reqType = which == 'insert' ? "POST" : 'PUT';
      var reqUrl = 'http://localhost:3000/documents/' + 
    (which == 'insert' ? '' : id);

      $.ajax({
        type: reqType,
        url: reqUrl,
        dataType: 'json',
        headers: { 'Content-Type' : 'application/json' },
        data: JSON.stringify(value)
      })
    .done(function(result) {
        $('#json').html(JSON.stringify(result));
    var resultHtml = which == 'insert' ? 'Inserted' : "Updated";
        $('#result').html(resultHtml);
      });
    }
    ```

1.  服务器接受提交的文档，自动使用 body-parser 模块将其从 JSON 转换，并在 documents.js 文件中执行数据库插入：

    ```js
    exports.addDocuments = function(req, res) {
      var documents = req.body;
      db.collection('documents', {safe:true}, 
    function(err, collection) {
    collection.insert(documents, function(err, result) {
     if (err) {
    res.send({'error':'An error has occurred'});
    } else {
     console.log('Success: ' + JSON.stringify(result[0]));
    res.send(result[0]);
            }
        });
     });
    };
    ```

## 它是如何工作的…

客户端代码被 UI 中的插入和更新按钮共同使用，这就是它比你可能最初想的要复杂一点的原因。然而，在 REST 中，插入和更新之间的唯一区别是 URL 和 HTTP 方法（`POST`与`PUT`），因此使用一个方法来处理两者是合理的。

客户端代码首先使用 jQuery 从表单中获取字段值，然后将请求类型设置为`POST`以进行更新。接下来，它构建 REST URL，这应该只是基本文档的 URL，因为新文档没有 ID。最后，它使用`POST`将文档的 JSON 发送到服务器。服务器代码很简单：取请求的一部分作为对象体，并将其插入到数据库的文档集合中，将插入的结果返回给客户端（这是一个很好的模式，以防客户端是新创建文档的 ID 用于任何事情）。

在服务器端，因为我们在使用 body-parser 模块的`jsonParser`实例注册`POST`请求的处理程序时，JSON 解码是自动处理的。

```js
app.post('/documents', jsonParser, documents.addDocuments);
```

### 提示

如果你在路由注册时忘记传递 JSON 解析器，请求体字段甚至不会被定义！所以如果你在使用 Express 向数据库插入空文档，一定要检查这一点。

# 使用 REST 在 MongoDB 中更新文档

更新与插入相同，不同之处在于它需要一个文档 ID，并且客户端使用 HTTP `POST`请求而不是`PUT`请求来信号更新请求。

## 如何做到...

客户端代码与上一个食谱完全相同；只有服务器代码会更改，因为它需要从 URL 中提取 ID 并执行更新而不是插入：

```js
exports.updateDocuments = function(req, res) {
  var id = new objectId(req.params.id);
  var document = req.body;
  db.collection('documents', function(err, collection) {
    collection.update({'_id':id}, document, {safe:true}, 
      function(err, result) {
        if (err) {
          console.log('Error updating documents: ' + err);
          res.send({'error':'An error has occurred'});
        } else {
          console.log('' + result + ' document(s) updated');
          res.send(documents);
        }
    });
  });
};
```

让我们更详细地看看。

## 它是如何工作的...

回到前面食谱中的客户端实现，你看到对于更新，我们在 URL 中包含了 ID。`updateDocuments`方法从请求参数中获取 ID，并将其转换为 MongoDB 对象`id`对象，然后调用`update`，客户端通过`POST`请求传递的文档。

# 使用 REST 在 MongoDB 中删除文档

与更新一样，删除需要一个对象`id`，我们将它在 URL 中传递给 HTTP `DELETE`请求。

## 如何做到...

`doRemove`方法从表单中的`id`字段获取对象`id`，并向由基本 URL 加上对象`id`组成的 URL 发送一个`DELETE`消息：

```js
function doRemove()
{
  var id = $('#id').val();

  if(id == "")'') 
  {
    alert("Must provide an ID to delete!");
    return;
  }

  $.ajax({
    type: 'DELETE',
    url: "http://localhost:3000/documents/" + id  })
  .done(function(result) {
    $('#json').html(JSON.stringify(result));
    var resultHtml = "Deleted";
    $('#result').html(resultHtml);
  });
  }
```

服务器上的删除消息处理程序从 URL 中提取 ID，然后执行`remove`操作：

```js
exports.deleteDocuments = function(req, res) {
  var id = new objectId(req.params.id);
  db.collection('documents', function(err, collection) {
    collection.remove({'_id':id}, {safe:true}, 
    function(err, result) {
      if (err) {
        res.send({'error':'An error has occurred - ' + err});
      } else {
        console.log('' + result + ' document(s) deleted');
        res.send({ result: 'ok' });
      }
    });
  });
};
```

## 它是如何工作的...

在客户端，流程与更新流程相似；我们从`id`表单元素中获取 ID，如果它是 null，它将弹出错误对话框而不是执行 AJAX post。我们使用 HTTP `DELETE`方法进行 AJAX post，在 URL 中将`id`作为文档名称传递给服务器。

在服务器端，我们从请求参数中获取 ID，将其转换为 MongoDB 本地对象 ID，然后将其传递给集合的`remove`方法以删除文档。然后将成功或错误返回给客户端。


# 第六章：使用 JSON 与 CouchDB 配合

在上一章中，我们研究了如何使用 JSON 与 MongoDB 配合，MongoDB 是一个流行的 NoSQL 数据库。在本章中，我们继续这一主题，向您展示如何使用 JSON 与 CouchDB 配合，CouchDB 又是另一个流行的 NoSQL 数据库。在这里，你会发现有关以下方面的食谱：

+   安装和设置 CouchDB 和 Cradle

+   使用 Node.js 和 Cradle 连接到 CouchDB 文档

+   使用 Node.js 和 Cradle 创建 CouchDB 数据库

+   使用 Node.js 和 Cradle 在 CouchDB 中创建文档

+   使用 Node.js 和 Cradle 设置数据视图

+   使用 Node.js 和 Cradle 在 CouchDB 中搜索文档

+   使用 Node.js 和 Cradle 在 CouchDB 中更新文档

+   使用 Node.js 和 Cradle 在 CouchDB 中删除文档

+   使用 REST 枚举 CouchDB 记录

+   使用 REST 搜索 CouchDB

+   使用 REST 在 CouchDB 中更新或创建文档

+   使用 REST 在 CouchDB 中删除文档

# 简介

CouchDB 是一个高可用性、可扩展的文档数据库。与 MongoDB 一样，它也是一个 NoSQL 数据库；不同的是，你不是将数据组织成通过 ID 相关联的表，而是将文档放入数据库中。与 MongoDB 不同，CouchDB 有一个有趣的特性，即 *视图*。

你将具有特定的 map 和 reduce 函数的文档放入数据库中，这些函数遍历数据以提供通过索引提供的特定数据视图。视图是缓存的，这使得构建高性能查询变得容易，这些查询返回数据子集或计算的数据（如报告）。

你与 CouchDB 交互的主要方式是通过 REST 接口；即使在本章中讨论的 Cradle 驱动程序，也是利用 REST 接口在幕后进行文档的创建、更新和删除。你还可以用 REST 接口进行查询，无论是通过文档 ID，还是将索引查询转换为视图。

在本章中，我们将研究如何使用 Cradle 模块将 CouchDB 与 Node.js 集成，以及如何从 Web 端对 CouchDB 进行 REST 查询。

# 安装和设置 CouchDB 和 Cradle

CouchDB 提供了主要平台的点击即可运行安装程序。

## 如何进行…

首先，你需要安装服务器。为此，请访问 [`couchdb.apache.org/`](http://couchdb.apache.org/) 并下载适合您平台的安装程序。在安装 Cradle 之前，一定要运行安装程序。

接下来，在命令行上运行以下命令来安装 Cradle：

```js
npm install cradle

```

最后，你需要在 CouchDB 服务器上启用跨资源请求，以允许在 Web 上进行这些请求。为此，请编辑 `/etc/couchdb/default.ini` 文件，并更改以下行：

```js
enable_cors = false
```

以下行：

```js
enable_cors = true
```

你还需要指示你将接受 CORS 请求的哪些源服务器；要启用对所有域名的跨资源请求，请在 `/etc/couchdb/default.ini` 中 `[cors]` 部分添加以下行：

```js
origins = *
```

如果你想要更具体一点，你可以提供一个由逗号分隔的域名列表，来自这些域名的 HTML 内容和脚本将被加载。

最后，你必须启动（或重新启动）CouchDB 服务器。在 Windows 上，假设你没有将其作为服务安装，就去你安装它的 `bin` 目录下运行 `couchdb.bat`；在 Linux 和 Mac OS X 上，杀死并重新启动 CouchDB 服务器进程。

## 它是如何工作的…

Cradle 模块是整合 CouchDB 和 Node.js 的流行方式，尽管如果你愿意，你也可以使用 Node.js 的 request 模块直接进行 REST 请求。

## 也见

关于 CouchDB 的更多信息，请参见 Apache CouchDB 维基百科上的页面：[`docs.couchdb.org/en/latest/contents.html`](http://docs.couchdb.org/en/latest/contents.html)。

# 使用 Node.js 和 Cradle 连接 CouchDB 数据库

尽管 CouchDB 提供了 RESTful 接口，但严格来说，在使用 CouchDB 之前并不需要一定要建立一个数据库连接；Cradle 模块使用连接的概念来管理其内部状态，你仍然需要创建一个连接对象。

## 怎样做到…

下面是如何在你的 Node.js 应用程序中包含 Cradle 模块并初始化它，获取对特定数据库的引用的方法：

```js
var cradle = require('cradle');
var db = new(cradle.Connection)().database('documents');
```

## 它是如何工作的…

这段代码首先包含了 Cradle 模块，然后创建了一个新的 Cradle `Connection` 对象，将其数据库设置为 `documents` 数据库。这初始化了 Cradle，使其使用默认的 CouchDB 主机（localhost）和端口（5984）。如果你需要覆盖主机或端口，可以通过将主机和端口作为 `Connection` 构造函数的第一个和第二个参数来这样做，像这样：

```js
var connection = new(cradle.Connection)('http://example.com', 
  1234);
```

# 使用 Node.js 和 Cradle 创建 CouchDB 数据库

在使用 CouchDB 中的数据库之前，你必须先创建它。

## 怎样做到…

一旦你获得了你想要使用的数据库的句柄，你应该检查它是否存在，如果不存在，则创建它：

```js
db.exists(function (err, exists) {
if (err) {
  console.log('error', err);
} elseif (!exists) {
{
  db.create();
}
});
```

## 它是如何工作的…

`exists` 方法检查数据库是否存在，如果发生错误，调用你提供的回调函数，并带有一个指示数据库是否存在或不存在的标志。如果数据库不存在，你可以使用 `create` 方法来创建它。

这是 Cradle 的一个常见模式，因为 RESTful 接口本质上是非同步的。你会将你想要执行的方法的参数和回调函数传递给它。

### 提示

初学者常犯的一个错误是认为可以调用这些方法而不带回调函数，然后立即执行一些依赖于之前结果的操作。这是行不通的，因为原始操作还没有发生。考虑对同一记录进行插入和更新。插入是异步完成的；如果你尝试同步执行更新，将没有东西可以更新！

## 还有更多…

如果你想销毁一个数据库，你可以使用 `destroy` 方法，它也接受一个回调函数，就像 create 一样。这会销毁数据库中的所有记录，就像你想象的那么彻底，所以要小心使用！

# 使用 Node.js 和 Cradle 在 CouchDB 中创建文档

Cradle 模块提供了`save`方法来将新文档保存到数据库中。你传递要保存的文档和一个当操作完成或失败时调用的回调函数。

## 如何做到这一点...

下面是如何使用`save`保存一个简单记录的方法：

```js
var item =  {
  call: 'kf6gpe-7',
  lat: 37,
  lng: -122
};

db.save(item, function (error, result) {
  if (error) {
    console.log(error);
    // Handle error
  } else {
    var id = result.id;
    var rev = result.rev;
    }
  });
```

## 它是如何工作的…

`save`方法返回一个 JavaScript 对象给你的回调函数，其中包含新创建文档的 ID 和一个内部修订号，以及一个名为 ok 的字段，该字段应该是 true。正如你在标题为《使用 Node.js 在 CouchDB 中更新记录》的食谱中看到的，为了更新一个文档，你需要存储文档的修订版和 ID；否则，你最终会创建一个新的文档或记录保存失败。一个示例结果可能看起来像这样：

```js
{ ok: true,
  id: '80b20994ecdd307b188b11e223001e64',
  rev: '1-60ba89d42cc4bbc1301164a6ae5c3935' }
```

# 如何在 CouchDB 中使用 Node.js 和 Cradle 设置数据视图

你可以通过它们的 ID 查询 CouchDB 的文档，但当然，大多数时候，你会希望发出更复杂的查询，比如将记录中的字段与特定值匹配。CouchDB 允许你定义*视图*，这些视图由集合中的任意键和从视图中派生的对象组成。当你指定一个视图时，你是在指定两个 JavaScript 函数：一个`map`函数将键映射到集合中的项目，然后一个可选的`reduce`函数遍历键和值以创建最终集合。在本食谱中，我们将使用视图的`map`函数通过单个字段创建记录的索引。

## 如何做到这一点...

下面是使用 CouchDB 为数据库添加一个简单视图的方法：

```js
db.save('_design/stations', {
  views: {
    byCall: {
      map: function(doc) {
        if (doc.call) {
          emit(doc.call, doc);
        }
      }
    }
  }
});
```

这为我们的数据库定义了一个单一视图，即`byCall`视图，它由一个呼号到数据库中文档的映射组成。

## 它是如何工作的…

视图是一种强大的方法，可以引用数据库中的文档，因为你可以根据数据库中的每个文档构建任意简单或复杂的文档。

我们的示例创建了一个单一视图`byCall`，存储在`views`目录下（你应该把视图放在这里），由每个记录的呼号字段组成，然后重复记录。CouchDB 定义了`emit`函数，让你为你的视图创建键值对；在这里，我们使用`call`字段作为每个值的关键字，文档本身作为值。你完全可以轻松地定义一个 JavaScript 对象中的字段子集，或者在 JavaScript 字段上计算某物，并发出那个东西。你可以定义多个视图，每个视图在`views`字段中是一个单独的`map`函数。

CouchDB 缓存视图，并根据数据库的变化按需更新它们，将视图数据存储为 B-树，因此在运行时更新和查询视图非常快。正如你在下一个示例中看到的，搜索特定键的视图简单到只需将键传递给视图。

视图在 CouchDB 中只是存储在特定位置的文档，使用函数而不是数据值。内部实现上，CouchDB 在存储视图时编译视图的函数，并在存储发生插入和删除等更改时运行它们。

## 也请参阅

+   关于 CouchDB 视图概念的更多信息，请参阅 CouchDB 维基百科中的[`wiki.apache.org/couchdb/Introduction_to_CouchDB_views`](http://wiki.apache.org/couchdb/Introduction_to_CouchDB_views)。

+   CouchDB 视图 API 文档在[`wiki.apache.org/couchdb/HTTP_view_API`](http://wiki.apache.org/couchdb/HTTP_view_API)。

# 使用 Node.js 和 Cradle 在 CouchDB 中搜索文档

在 CouchDB 中搜索文档就是查询特定视图以获取特定键的问题。Cradle 模块定义了`view`函数来实现这一点。

## 如何进行...

您将传递要执行查询的视图的 URL，然后将您正在搜索的键作为键参数传递，像这样：

```js
var call = "kf6gpe-7";
db.view('stations/byCall/key="' + call + '"', 
  function (error, result) {
    if (result) {
      result.forEach(function (row) {
        console.log(row);
});
```

除了传递您所寻找的视图和键外，您必须传递一个处理结果的回调函数。

## 它是如何工作的…

在这里，我们在`byCall`视图中搜索调用信号为`kf6gpe-7`。回想一下上一个食谱，视图由`call`字段中的调用信号映射到记录组成；当我们使用数据库的`view`方法发出视图请求时，它在那个映射中查找键匹配`kf6gpe-7`的记录，并返回由匹配记录组成的数组结果。该方法使用数组的`forEach`方法遍历数组中的每个元素，一次将每个元素写入控制台。

## 还有更多内容

您可以向视图传递多个参数。最明显的是`key`参数，它让您传递一个键以进行匹配。还有`keys`参数，它让您传递一个键的数组。您还可以传递`startkey`和`endkey`，以查询一个键范围的视图。如果您需要限制结果，您可以使用`limit`和`skip`参数来限制结果数量，或跳过前*n*个匹配的结果。

如果您知道一个文档的 ID，您还可以使用 Cradle 的`get`方法直接获取该对象：

```js
db.get(id, function(error, doc) {
  console.log(doc);
});
```

## 也请参阅

关于您可以对视图执行的查询操作的详细信息，请参阅 CouchDB 维基百科中的[`wiki.apache.org/couchdb/HTTP_view_API#Querying_Options`](http://wiki.apache.org/couchdb/HTTP_view_API#Querying_Options)。

# 使用 Node.js 和 Cradle 在 CouchDB 中更新文档

Cradle 模块定义了`merge`方法，以便让您更新现有文档。

## 如何进行...

以下是一个示例，我们通过指定其 ID 将记录的调用从`kf6gpe-7`更改为`kf6gpe-9`，然后使用新数据执行合并：

```js
var call = "kf6gpe-7";

db.merge(id, {call: 'kf6gpe-9'}, function(error, doc) {
  db.get(id, function(error, doc) {
    console.log(doc);
  });
});
```

从函数中，你可以看到`merge`接收要合并记录的 ID 和一个 JavaScript 对象，该对象包含要替换或添加到现有对象的字段。你还可以传递一个回调函数，当合并操作完成时由 merge 调用。在出错的情况下，错误值将为非零，文档作为第二个参数返回。在这里，我们只是将修订后的文档的内容记录到控制台。

# 使用 Node.js 和 Cradle 在 CouchDB 中删除文档

要删除一个记录，你使用 Cradle 模块的`remove`方法，并传递你想要删除的文档的 ID。

## 如何进行...

下面是一个删除记录的例子：

```js
db.remove(id);
```

通过 ID 删除文档会移除具有指定 ID 的文档。

## 还有更多...

如果你有多个文档要删除，你可以像以下代码那样遍历所有文档，逐一删除每个文档：

```js
db.all(function(err, doc) {
  for(var i = 0; i < doc.length; i++) {
    db.remove(doc[i].id, doc[i].value.rev, function(err, doc) {
      console.log('Removing ' + doc._id);
    });
  }
});
```

这是`remove`的一个更复杂的使用方式；它需要文档的 ID、文档的版本以及一个回调函数，该函数会将每个被移除文档的 ID 记录到控制台。

# 使用 REST 枚举 CouchDB 记录

REST 语义规定，要获取对象集合的完整内容，我们只需向集合的根发送一个`GET`请求。我们可以从启用了 CORS 的 CouchDB 中使用 jQuery 用一个调用完成这个操作。

## 如何进行...

这里有一些 HTML、jQuery 和 JavaScript 代码，它枚举了 CouchDB 视图中的所有项目，并在内嵌表格中显示了每个对象的一些字段：

```js
<!DOCTYPE html>
<html>
<head>
<script src="img/"></script>
<script src="img/"></script>
</head>
<body>

<p>Hello world</p>
<p>
  <div id="debug"></div>
</p>
<p>
  <div id="json"></div>
</p>
<p>
  <div id="result"></div>
</p>

<button type="button" id="get" onclick="doGet()">Get</button><br/>
<form>
  Id: <input type="text" id="id"/>
  Rev: <input type="text" id="rev"/>
  Call: <input type="text" id="call"/>
  Lat: <input type="text" id="lat"/>
  Lng: <input type="text" id="lng"/>
  <button type="button" id="insert" 
    onClick="doUpsert('insert')">Insert</button>
  <button type="button" id="update" 
    onClick="doUpsert('update')">Update</button>
  <button type="button" id="remove" 
    onClick="doRemove()">Remove</button>
</form><br/>

<script>

function doGet() { 
  $.ajax({
    type: "GET",
    url: 
"http://localhost:5984/documents/_design/stations/_view/byCall",
    dataType:"json",
  })
  .done(function(result) {
    $('#json').html(JSON.stringify(result));
    var resultHtml = '<table><tr><td><b>id</b></td>';
    resultHtml += '<td><b>revision</b></td><td><b>call</b></td>';
    resultHtml += '<td><b>lat</b></td><td><b>lng</b></td></tr>';
    for(var i = 0; i < result.rows.length; i++)
    {
      var item = result.rows[i]
      resultHtml += "<tr>";
      resultHtml += "<td>" + item.id + "</td>";
      resultHtml += "<td>" + item.value._rev + "</td>";
      resultHtml += "<td>" + item.value.call + "</td>";
      resultHtml += "<td>" + item.value.lat + "</td>";
      resultHtml += "<td>" + item.value.lng + "</td>";
      resultHtml += "</tr>";
    }
    $('#result').html(resultHtml);
});
}
</script>
</html>
```

## 它是如何工作的…

HTML 结构很简单；它包含了 jQuery，然后定义了三个`div`区域来显示请求的结果。之后，它定义了一个表单，包含文档的 ID、版本、呼号、纬度和经度字段，并添加了获取记录列表、执行插入或更新以及移除记录的按钮。

我们需要定义`byCall`视图才能使其工作（参见食谱*使用 Node.js 在 CouchDB 中设置数据视图*，了解如何使用 Node.js 设置数据视图）。这段代码对视图的基本 URL 执行一个 HTTP GET 请求，并取回的 JavaScript 对象（由 jQuery 从 JSON 解析而来）进行格式化，使其成为一个表格。（注意我们本可以附加一个特定的键到 URL 上，以获取单一的 URL）。

REST 响应的格式与使用 Cradle 查询集合的响应略有不同；你看到的是 CouchDB 的实际响应，而不是由 Cradle 处理的成果。以原始形式来看，它看起来像这样：

```js
{"total_rows":1,"offset":0,
  "rows":[
    {"id":"80b20994ecdd307b188b11e223001e64",
"key":"kf6gpe-7",
      "value":{
"_id":"80b20994ecdd307b188b11e223001e64",
"_rev":"1-60ba89d42cc4bbc1301164a6ae5c3935",
"call":"kf6gpe-7","lat":37,"lng":-122
      }
    }
  ]
} 
```

具体来说，`total_rows`字段表示集合中结果有多少行；`offset`字段表示在返回的第一行之前在集合中跳过了多少行，然后`rows`数组包含了映射视图生成的每个键值对。`rows`字段有一个 ID 字段，它是生成该映射条目的唯一 ID，由映射操作生成的键，以及由映射操作生成的记录。

请注意，如果你对数据库的基本 URL 执行一个`GET`请求，你会得到一些不同的事物；不是数据库中的所有记录，而是有关数据库的信息：

```js
{"db_name":"documents",
"doc_count":5,
"doc_del_count":33,
"update_seq":96,
"purge_seq":0,
"compact_running":false,
"disk_size":196712,
"data_size":6587,
"instance_start_time":"1425000784214001",
"disk_format_version":6,
"committed_update_seq":96
}
```

这些字段可能因您运行的 CouchDB 版本而异。

## 参见

有关 CouchDB 的 HTTP REST 接口的信息，请参阅位于[`wiki.apache.org/couchdb/HTTP_Document_API`](http://wiki.apache.org/couchdb/HTTP_Document_API)的文档。

# 使用 REST 搜索 CouchDB

使用 REST 搜索 CouchDB 时，使用一个带有映射的视图来创建你的索引，你插入一次，然后是一个 GET HTTP 请求。

## 如何做到...

我们可以修改之前的`doGet`函数，以搜索特定的呼号，如下所示：

```js
function doGet(call) { 
  $.ajax({
    type: "GET",
    url: 
"http://localhost:5984/documents/_design/stations/_view/byCall" + 
       (call != null & call != '') ? ( '?key=' + call ) : '' ),
    dataType:"json",
  })
  .done(function(result) {
    $('#json').html(JSON.stringify(result));
    var resultHtml = '<table><tr><td><b>id</b></td>';
    resultHtml += '<td><b>revision</b></td><td><b>call</b></td>';
    resultHtml += '<td><b>lat</b></td><td><b>lng</b></td></tr>';
    for(var i = 0; i < result.rows.length; i++)
    {
      var item = result.rows[i]
      resultHtml += "<tr>";
      resultHtml += "<td>" + item.id + "</td>";
      resultHtml += "<td>" + item.value._rev + "</td>";
      resultHtml += "<td>" + item.value.call + "</td>";
      resultHtml += "<td>" + item.value.lat + "</td>";
      resultHtml += "<td>" + item.value.lng + "</td>";
      resultHtml += "</tr>";
    }
    $('#result').html(resultHtml);
  });
}
```

## 它是如何工作的…

相关的行是传递给`doGet`的参数调用，以及我们构造的 URL，我们通过`GET`请求发送到该 URL。注意我们如何检查 null 或空调用以获取整个集合；你的代码可能希望做些不同的事情，比如报告一个错误，特别是如果集合很大的话。

### 提示

请注意，视图必须在这样做之前存在。我喜欢使用 Node.js 在最初更新我的数据库时创建我的视图，并在更改时更新视图，而不是将视图嵌入客户端，因为对于大多数应用程序来说，有很多客户端，没有必要让存储重复更新相同的视图。

# 使用 REST 在 CouchDB 中更新或插入文档

当你想要执行一个更新或插入操作时，Cradle 并没有 REST 等效的合并功能；相反，插入操作由 HTTP `POST`请求处理，而更新操作则由`PUT`请求处理。

## 如何做到...

以下是一些 HTML 和一个`doUpsert`方法，它查看你 HTML 页面上的表单元素，如果数据库中尚不存在文档，则创建新文档，或者如果已存在文档并且你传递了 ID 和修订字段，则更新现有文档：

```js
<!DOCTYPE html>
<html>
<head>
<script src="img/"></script>
<script src="img/"></script>
</head>
<body>

<p>Hello world</p>
<p>
  <div id="debug"></div>
</p>
<p>
  <div id="json"></div>
</p>
<p>
  <div id="result"></div>
</p>

<button type="button" id="get" onclick="doGet()">Get</button><br/>
<form>
  Id: <input type="text" id="id"/>
  Rev: <input type="text" id="rev"/>
  Call: <input type="text" id="call"/>
  Lat: <input type="text" id="lat"/>
  Lng: <input type="text" id="lng"/>
  <button type="button" id="insert" 
    onClick="doUpsert('insert')">Insert</button>
  <button type="button" id="update" 
    onClick="doUpsert('update')">Update</button>
  <button type="button" id="remove" 
    onClick="doRemove()">Remove</button>
</form><br/>

<script>

function doUpsert();
{	
  var value = {};
  var which = null;
  id = $('#id').val();

  if (id != '') {
    which = 'insert';
  }

  value.call = $('#call').val();
  value.lat = $('#lat').val();
  value.lng = $('#lng').val();

  if (which != 'insert') {
    value._rev = $('#rev').val();
    value._id = id;
  }

  $('#debug').html(JSON.stringify(value));

  var reqType = which == 'insert' ? "POST" : "PUT";
  var reqUrl = "http://localhost:5984/documents/" + 
    (which == 'insert' ? '' : id);

  $.ajax({
    type: reqType,
    url: reqUrl,
    dataType:"json",
    headers: { 'Content-Type' : 'application/json' },
    data: JSON.stringify(value)
  })
  .done(function(result) {
    $('#json').html(JSON.stringify(result));
    var resultHtml = which == 'insert' ? "Inserted" : "Updated";
    $('#result').html(resultHtml);
  })
}
</script>
</html>
```

## 它是如何工作的…

`doUpsert`方法首先定义一个空 JavaScript 对象，这是我们将其填充并通过`PUT`或`POST`请求发送到服务器的对象。然后我们提取表单字段的值；如果`id`字段设置了 ID，我们假设这是更新操作，而不是插入操作，并且还捕获了名为`rev`的修订字段的值。

如果没有设置 ID 值，它是一个插入操作，我们将请求类型设置为`POST`。如果它是更新，我们将请求类型设置为`PUT`，向 CouchDB 表明这是一个更新。

接下来，我们构造 URL；更新文档的 URL 必须包括要更新的文档的 ID；这就是 CouchDB 知道要更新哪个文档的方式。

最后，我们执行一个我们之前定义类型的 AJAX 请求（`PUT`或`POST`）。当然，我们将发送给服务器的 JavaScript 文档进行 JSON 编码，并包含一个指示发送的文档是 JSON 的头部。

返回的值是一个 JSON 文档（由 jQuery 转换为 JavaScript 对象），包括插入文档的 ID 和修订版，类似于这样：

```js
{ "ok":true,
  "id":"80b20994ecdd307b188b11e223001e64",
  "rev":"2-e7b2a85adef5e721634bdf9a5707eb42"}
```

### 提示

请注意，您更新文档的请求必须包括文档的当前修订版和 ID，否则`PUT`请求将因 HTTP 409 错误而失败。

# 使用 REST 在 CouchDB 中删除文档

您通过向要删除的文档发送带有 ID 和修订版的 HTTP `DELETE`请求来表示 RESTful 删除。

## 如何做到…

使用之前的食谱中的 HTML，这是一个脚本，它从表单字段中提取 ID 和修订版，进行一些简单的错误检查，并向服务器发送具有指示 ID 和修订版的文档的删除请求：

```js
function doRemove()
{	
  id = $('#id').val();
  rev = $('#rev').val();
  if (id == '') 
  {
    alert("Must provide an ID to delete!");
    return;
  }
  if (rev == '')
  {
    alert("Must provide a document revision!");
    return;
  }

  $.ajax({
    type: "DELETE",
    url: "http://localhost:5984/documents/" + id + '?rev=' + rev,
  })
  .done(function(result) {
    $('#json').html(JSON.stringify(result));
    var resultHtml = "Deleted";
    $('#result').html(resultHtml);
  })
}
```

## 它是如何工作的…

代码首先从表单元素中提取 ID 和修订版，如果任何一个为空则弹出错误对话框。接下来，构建一个 AJAX HTTP `DELETE`请求。URL 是文档的 URL - 数据库和文档 ID，修订版作为名为`rev`的参数传递。假设您正确指定了 ID 和修订版，您将得到与更新相同的响应：被删除文档的 ID 和修订版。 如果失败，您将得到一个 HTTP 错误。


# 第七章．以类型安全的方式使用 JSON

在本章中，我们将在第一章，*在客户端读写 JSON*的食谱基础上，向您展示如何使用 C#、Java 和 TypeScript 在您的应用程序中使用强类型。您将找到以下食谱：

+   如何使用 Json.NET 反序列化对象

+   如何使用 Json.NET 处理日期和时间对象

+   如何使用 gson 为 Java 反序列化对象

+   如何使用 Node.js 与 TypeScript

+   如何使用 TypeScript 注解简单类型

+   如何使用 TypeScript 声明接口

+   如何使用 TypeScript 声明带有接口的类

+   使用 json2ts 从您的 JSON 生成 TypeScript 接口

# 简介

有些人说强类型是弱智的标志，但事实是，编程语言中的强类型可以帮助你避免一整类错误，其中你错误地假设一个对象实际上属于另一种类型。像 C#和 Java 这样的语言提供强类型正是出于这个原因。

幸运的是，C#和 Java 的 JSON 序列化器支持强类型，一旦您弄清楚了对象表示，只想将 JSON 映射到您已经定义的类的实例时，这尤其方便。在第一章中，*在客户端读写 JSON*，您看到了如何将 C#或 Java 类转换为 JSON，以及如何将 JSON 转换为未命名的对象；在本章中，我们使用 Json.NET 对 C#和 gson 对 Java 将 JSON 转换为您应用程序中定义的类的实例。

最后，我们来看看 TypeScript，这是 JavaScript 的一个扩展，提供了类型在编译时的检查，编译成普通的 JavaScript 以供与 Node.js 和浏览器一起使用。我们将查看如何为 Node.js 安装 TypeScript 编译器，如何使用 TypeScript 注解类型和接口，以及如何使用 Timmy Kokke 的网页自动从 JSON 对象生成 TypeScript 接口。

# 如何使用 Json.NET 反序列化对象

在本食谱中，我们将向您展示如何使用 Newtonsoft 的 Json.NET 将 JSON 反序列化为类的实例。我们将使用 Json.NET，这是我们在第一章，*在客户端读写 JSON*中提到的，因为尽管这适用于现有的.NET JSON 序列化器，但我还想要您了解关于 Json.NET 的其他内容，我们将在接下来的两个食谱中讨论。

## 准备阶段

首先，您需要确保您的项目中有一个对 Json.NET 的引用。最简单的方法是使用 NuGet；启动 NuGet，搜索 Json.NET，然后点击**安装**，如下面的屏幕截图所示：

![准备阶段](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-json-cb/img/B04206_07_01.jpg)

你还需要在需要这些类的任何文件中，在文件的顶部使用`using`指令引用`Newonsoft.Json`命名空间：

```js
usingNewtonsoft.Json;
```

## 如何做到…

下面是一个示例，提供了简单类的实现，将 JSON 字符串转换为此类的实例，然后将实例转换回 JSON：

```js
using System;
usingNewtonsoft.Json;

namespaceJSONExample
{

  public class Record
  {
    public string call;
    public double lat;
    public double lng;
  }

  class Program
  {
    static void Main(string[] args)
      {
        String json = @"{ 'call': 'kf6gpe-9', 
        'lat': 21.9749, 'lng': 159.3686 }";

        var result = JsonConvert.DeserializeObject<Record>(
          json, newJsonSerializerSettings
            {
        MissingMemberHandling = MissingMemberHandling.Error
          });
        Console.Write(JsonConvert.SerializeObject(result));

        return;
        }
  }
}
```

## 如何工作…

为了以类型安全的方式反序列化 JSON，我们需要有一个与我们的 JSON 具有相同字段的类。在第一行定义的`Record`类这样做，定义了`call`、`lat`和`lng`字段。

`Newtonsoft.Json`命名空间提供了`JsonConvert`类，带有静态方法`SerializeObject`和`DeserializeObject`。`DeserializeObject`是一个泛型方法，接受应返回的对象的类型作为类型参数，以及 JSON 解析的 JSON 和可选参数指示 JSON 解析的选项。我们传递`MissingMemberHandling`属性作为设置，用枚举值`Error`表示，如果字段缺失，解析器应抛出异常。在解析类之后，我们再次将其转换为 JSON，并将结果 JSON 写入控制台。

## 还有更多…

如果你跳过传递`MissingMember`选项或传递`Ignore`（默认值），你可以在 JSON 中的字段名与你的类之间存在不匹配，这可能不是你进行类型安全转换所想要的。你还可以传递`NullValueHandling`字段，其值为`Include`或`Ignore`。如果为`Include`，包含具有空值的字段；如果为`Ignore`，则忽略具有空值的字段。

## 请参阅

Json.NET 的完整文档在[`www.newtonsoft.com/json/help/html/Introduction.htm`](http://www.newtonsoft.com/json/help/html/Introduction.htm)。

使用.NET 序列化器也可以进行类型安全的 JSON 支持；语法相似。有关示例，请参阅[JavaScriptSerializer 类](https://msdn.microsoft.com/en-us/library/system.web.script.serialization.javascriptserializer(v=vs.110).aspx)的文档。

# 使用 Json.NET 处理日期和时间对象

JSON 中的日期对人们来说是个问题，因为 JavaScript 的日期是从纪元开始以来的毫秒数，这通常对人们来说是难以阅读的。不同的 JSON 解析器处理方式不同；Json.NET 有一个很好的`IsoDateTimeConverter`，它将日期和时间格式化为 ISO 格式，使得在其他平台（除了 JavaScript）上进行调试或解析时人类可读。你也可以通过创建新的转换器对象并使用转换器对象将一个值类型转换为另一个值类型，将此方法扩展到转换 JSON 属性中的任何格式化数据。

## 如何做到…

只需在调用`JsonConvert.Serialize`时包含一个新的`IsoDateTimeConverter`对象，像这样：

```js
string json = JsonConvert.SerializeObject(p, 
newIsoDateTimeConverter());
```

## 如何工作…

这导致序列器调用`IsoDateTimeConverter`实例，以任何日期和时间对象实例化，返回如下的 ISO 字符串：

```js
2015-07-29T08:00:00
```

## 还有更多…

请注意，这可以被 Json.NET 解析，但不是 JavaScript；在 JavaScript 中，您希望使用像这样的函数：

```js
Function isoDateReviver(value) {
  if (typeof value === 'string') {
  var a = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2}(?:\.\d*)?)(?:([\+-])(\d{2})\:(\d{2}))?Z?$/
  .exec(value);
  if (a) {
     var utcMilliseconds = Date.UTC(+a[1], 
          +a[2] - 1, 
          +a[3], 
          +a[4], 
          +a[5], 
          +a[6]);
        return new Date(utcMilliseconds);
    }
  }
return value;
}
```

第三行的相当复杂的正则表达式匹配 ISO 格式的日期，提取每个字段。如果正则表达式找到匹配项，它将提取每个日期字段，然后使用`Date`类的 UTC 方法创建新的日期。

### 提示

请注意，整个正则表达式——`/`字符之间的所有内容——应该位于同一行，且没有空格。然而，这个页面有点长！

## 另见

关于 Json.NET 如何处理日期和时间的更多信息，请参阅[`www.newtonsoft.com/json/help/html/SerializeDateFormatHandling.htm`](http://www.newtonsoft.com/json/help/html/SerializeDateFormatHandling.htm)上的文档和示例。

# 使用 gson 为 Java 反序列化对象

与 Json.NET 一样，gson 提供了一种指定您要反序列化的 JSON 对象目标类的方法。实际上，这正是您在第一章*客户端的 JSON 读写*中使用的食谱*读写 JSON*中使用的相同方法。

## 准备中

您需要将 gson JAR 文件包含在您的应用程序中，就像任何其他外部 API 一样。

## 如何做到…

您使用的方法与使用 gson 进行类型不安全的 JSON 解析时使用的`fromJson`方法相同，只是您将类对象作为第二个参数传递给 gson，像这样：

```js
// Assuming we have a class Record that looks like this:
/*
class Record {
  private String call;
  private float lat;
  private float lng;
    // public API would access these fields
}
*/

Gson gson = new com.google.gson.Gson(); 
String json = "{ \"call\": \"kf6gpe-9\", 
\"lat\": 21.9749, \"lng\": 159.3686 }";
Record result = gson.fromJson(json, Record.class);
```

## 如何工作…

`fromGson`方法总是接受一个 Java 类；在第一章*客户端的 JSON 读写*中，我们要反序列化的类是`JsonElement`，它处理 JSON 的一般动态性。在本食谱的示例中，我们直接转换为一个简单的 Java 对象，我们的应用程序可以使用，而无需使用 gson 提供的`JsonElement`的反引用和类型转换接口。

## 还有更多…

gson 库也可以处理嵌套类型和数组。您还可以通过将字段声明为`transient`来隐藏字段，使其不被序列化或反序列化，这是有意义的，因为瞬态字段不会被序列化。

## 另见

gson 及其支持反序列化类实例的文档在[`sites.google.com/site/gson/gson-user-guide#TOC-Object-Examples`](https://sites.google.com/site/gson/gson-user-guide#TOC-Object-Examples)。

# 如何使用 TypeScript 与 Node.js

使用 TypeScript 与 Visual Studio 配合使用很容易；它是 Visual Studio 2013 Update 2 之后的任何版本的 Visual Studio 安装的一部分。为 Node.js 获取 TypeScript 编译器同样简单——只需一个`npm install`。

## 如何做到…

在带有`npm`的命令行中，运行以下命令：

```js
npm install –g typescript

```

`npm`选项`–g`告诉`npm`将 TypeScript 编译器全局安装，这样它就可以供你写的每一个 Node.js 应用程序使用了。一旦你运行这个命令，`npm`就会下载并为你所在的平台安装 TypeScript 编译器的二进制文件。

## 更多内容…

一旦你运行这个命令来安装编译器，你就可以在命令行上使用 TypeScript 编译器`tsc`了。用`tsc`编译一个文件和写源代码并保存为一个以`.ts`结尾的文件一样简单，然后在该文件上运行`tsc`。例如，假设以下 TypeScript 代码保存在名为`hello.ts`的文件中：

```js
function greeter(person: string) {
  return "Hello, " + person;
}

var user: string = "Ray";

console.log(greeter(user));
```

在命令行运行`tschello.ts`会生成以下的 JavaScript 代码：

```js
function greeter(person) {
  return "Hello, " + person;
}

var user = "Ray";

console.log(greeter(user));
```

试试看！

正如我们在下一节所看到的，`greeter`的函数声明包含了一个 TypeScript 注解；它声明参数`person`为`string`。在`hello.ts`的底部添加以下一行：

```js
console.log(greeter(2));
```

现在，再次运行`tschello.ts`命令；你会得到一个错误，像这样的一个：

```js
C:\Users\rarischp\Documents\node.js\typescript\hello.ts(8,13): error TS2082: Supplied parameters do not match any signature of call target:
        Could not apply type 'string' to argument 1 which is of type 'number'.
C:\Users\rarischp\Documents\node.js\typescript\hello.ts(8,13): error TS2087: Could not select overload for 'call' expression.
```

这个错误表明我试图用错误类型的值调用`greeter`，传了一个数字给期望字符串的`greeter`。在下一个菜谱中，我们将查看 TypeScript 支持为简单类型提供的哪些类型注解。

## 参见 also

TypeScript 的官方网站，包括教程和参考文档，位于[`www.typescriptlang.org/`](http://www.typescriptlang.org/)。

# 如何使用 TypeScript 注解简单类型

TypeScript 中的类型注解是简单地附加在变量或函数后面的冒号和装饰器。支持与 JavaScript 相同的原始类型，以及我们接下来要讨论的声明接口和类。

## 如何做到…

以下是一个简单的变量声明和两个函数声明的例子：

```js
function greeter(person: string): string {
  return "Hello, " + person;
}

function circumference(radius: number) : number {
  var pi: number = 3.141592654;
  return 2 * pi * radius;
}

var user: string = "Ray";

console.log(greeter(user));
console.log("You need " + 
circumference(2) + 
  " meters of fence for your dog.");
```

这个例子展示了如何注解函数和变量。

## 它是如何工作的…

变量——作为独立变量或函数参数——使用冒号后跟类型进行装饰。例如，第一个函数`greeter`接受一个参数`person`，必须是字符串。第二个函数`circumference`接受一个半径，必须是数字，并在其作用域中声明了一个变量`pi`，必须是数字并且有值`3.141592654`。

你像在 JavaScript 中一样以正常方式声明函数，然后在函数名后面加上类型注解，再次使用冒号和类型。所以，`greeter`返回一个字符串，`circumference`返回一个数字。

## 更多内容…

TypeScript 定义了以下基本类型装饰器，它们映射到其底层的 JavaScript 类型：

+   `array`：这是一个复合类型。例如，你可以像下面这样写一个字符串列表：

    ```js
    var list:string[] = [ "one", "two", "three"];
    ```

+   `boolean`：这个类型装饰器可以包含`true`和`false`这两个值。

+   `number`：这个类型装饰器类似于 JavaScript 本身，可以是任何浮点数。

+   `string`：这个类型装饰器是字符串。

+   `enum`：枚举，使用`enum`关键字编写，像这样：

    ```js
    enumColor { Red = 1, Green, Blue };
    var c : Color = Color.Blue;
    ```

+   `any`：这个类型表示变量可以是任何类型。

+   `void`：这个类型表示值没有类型。你将使用`void`来表示一个不返回任何内容的函数。

## 参见

要查看 TypeScript 类型的列表，请参阅 TypeScript 手册中的[TypeScript 类型](http://www.typescriptlang.org/Handbook)。

# 如何使用 TypeScript 声明接口

接口*定义了事物的行为，而没有定义实现*。在 TypeScript 中，接口通过描述它所拥有的字段来命名一个复杂类型。这被称为结构子类型化。

## 如何做到…

声明接口有点像声明一个结构或类；你在接口中定义字段，每个字段都有自己的类型，像这样：

```js
interface Record {
  call: string;
  lat: number;
  lng: number;
}

Function printLocation(r: Record) {
  console.log(r.call + ': ' + r.lat + ', ' + r.lng);
}

var myObj = {call: 'kf6gpe-7', lat: 21.9749, lng: 159.3686};

printLocation(myObj);
```

## 它是如何工作的…

在 TypeScript 中，`interface`关键字定义了一个接口；如我前面所提到的，接口包含它声明的字段和它们的类型。在这个列表中，我定义了一个普通的 JavaScript 对象`myObj`，然后调用了我之前定义的接受一个`Record`的函数`printLocation`。当用`myObj`调用`printLocation`时，TypeScript 编译器检查字段和类型，只有当对象符合接口时，才允许调用`printLocation`。

## 还有更多…

小心！TypeScript 只能提供编译时类型检查。你认为下面的代码会做什么呢？

```js
interface Record {
  call: string;
  lat: number;
  lng: number;
}

Function printLocation(r: Record) {
  console.log(r.call + ': ' + r.lat + ', ' + r.lng);
}

var myObj = {call: 'kf6gpe-7', lat: 21.9749, lng: 159.3686};
printLocation(myObj);

var json = '{"call":"kf6gpe-7","lat":21.9749}';
var myOtherObj = JSON.parse(json);
printLocation(myOtherObj);
```

首先，这个代码用`tsc`编译是没有问题的。当你用 node 运行它时，你会看到以下内容：

```js
kf6gpe-7: 21.9749, 159.3686
kf6gpe-7: 21.9749, undefined
```

发生了什么？TypeScript 编译器不会为你的代码添加运行时类型检查，所以你不能对一个非字面创建的运行时对象强加一个接口。在这个例子中，因为 JSON 中缺少了`lng`字段，函数无法打印它，而是打印了`undefined`的值。

这并不意味着你不应该使用 TypeScript 与 JSON 一起使用，然而。类型注解对所有代码的读者都有用，无论是编译器还是人。你可以使用类型注解来表明你作为开发者的意图，并且代码的读者可以更好地理解你所写的代码的设计和限制。

## 参见

关于接口的更多信息，请参阅 TypeScript 文档中的[接口](http://www.typescriptlang.org/Handbook#interfaces)部分。

# 如何使用 TypeScript 声明带有接口的类

接口让你可以指定行为而不指定实现；类让你可以将实现细节封装在一个接口后面。TypeScript 类可以封装字段或方法，就像其他语言中的类一样。

## 如何做到…

下面是一个我们的记录结构示例，这次作为一个带有接口的类：

```js
class RecordInterface {
  call: string;
  lat: number;
  lng: number;

  constructor(c: string, la: number, lo: number) {}
  printLocation() {}

}

class Record implements RecordInterface {
  call: string;
  lat: number;
  lng: number;

  constructor(c: string, la: number, lo: number) {
    this.call = c;
    this.lat = la;
    this.lng = lo;
  }

  printLocation() {
    console.log(this.call + ': ' + this.lat + ', ' + this.lng);
  }
}

var myObj : Record = new Record('kf6gpe-7', 21.9749, 159.3686);

myObj.printLocation();
```

## 它是如何工作的…

再次，`interface`关键字定义了一个接口，正如前一部分所展示的。你之前没见过的`class`关键字实现了一个类；可选的`implements`关键字表明这个类实现了接口`RecordInterface`。

请注意，实现接口的类必须具有与接口规定的相同的所有字段和方法；否则，它不符合接口的要求。因此，我们的`Record`类包括了`call`、`lat`和`lng`字段，类型与接口中的相同，以及构造方法和`printLocation`方法。

构造方法是一种特殊的方法，当你使用`new`创建类的新实例时会被调用。请注意，与常规对象不同，创建类的正确方式是使用构造函数，而不是仅仅将它们构建为字段和值的集合。我们在列表的倒数第二行这样做，将构造函数参数作为函数参数传递给类构造函数。

## 参见

你可以用类做很多事情，包括定义继承和创建公有和私有的字段和方法。关于 TypeScript 中类的更多信息，请参阅[`www.typescriptlang.org/Handbook#classes`](http://www.typescriptlang.org/Handbook#classes)的文档。

# 使用 json2ts 从你的 JSON 生成 TypeScript 接口

这个最后的食谱更像是一个提示而不是一个食谱；如果你有一些使用其他编程语言开发或手工编写的 JSON，你可以通过使用 Timmy Kokke 的 json2ts 网站轻松地为包含 JSON 的对象创建一个 TypeScript 接口。

## 如何做到…

只需访问[`json2ts.com`](http://json2ts.com)，将你的 JSON 代码粘贴到出现的文本框中，然后点击生成 TypeScript 按钮。你会看到一个新文本框出现，展示了 TypeScript 接口的定义，你可以将这个定义保存为一个文件，并在你的 TypeScript 应用程序中包含它。

## 它是如何工作的…

下面的图表展示了一个简单的例子：

![它是如何工作的…](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-json-cb/img/B04206_07_02.jpg)

你可以将这个 TypeScript 保存为一个自己的文件，一个`definition`文件，后缀为`.d.ts`，然后使用`import`关键字包含模块，像这样：

```js
import module = require('module');
```


# 第八章：使用 JSON 进行二进制数据传输

在本章中，我们将讨论 JSON 和二进制数据之间的交集。在这里，您会找到以下菜谱：

+   使用 Node.js 将二进制数据编码为 base64 字符串

+   使用 Node.js 从 base64 字符串解码二进制数据

+   在浏览器中使用 JavaScript 将二进制数据编码为 base64 字符串

+   使用 Json.NET 将数据编码为 BSON

+   使用 Json.NET 解码 BSON 数据

+   使用`DataView`访问`ArrayBuffer`

+   使用`ArrayBuffer`进行 base64 的编码和解码

+   使用 express 模块构建的 Node.js 服务器上压缩对象体内容

# 引言

使用 JSON 时考虑二进制表示通常有两个原因：要么是因为你需要将在应用程序的一个部分与另一个部分之间传输二进制数据，要么是因为你担心传输的 JSON 数据的大小。

在第一种情况下，你实际上有点束手无策，因为现有的 JSON 规范没有为二进制数据提供容器格式，因为 JSON 在本质上是一种基于文本的数据表示。你可以选择将二进制数据编码为另一种格式，如 base64，将二进制数据表示为可打印的字符串，或者使用支持二进制数据的 JSON 扩展，如二进制 JSON（BSON）。

BSON 使用 JSON 的语义，但以二进制形式表示数据。因此，同样的基本结构是可用的：一个（可能嵌套的）键值对映射，其中值可以是其他键值对、数组、字符串，甚至是二进制数据。然而，代替使用纯文本编码，该格式是二进制的，这产生了更小的数据大小并支持原生二进制对象（您可以在[`bsonspec.org/`](http://bsonspec.org/)了解更多关于 BSON 的信息）。BSON 的缺点是它不是原生支持 JavaScript，而且作为一种二进制格式，不容易进行检查。为了激发你的兴趣，我将在本章讨论如何使用流行的 Json.NET 库与 BSON 一起使用。

第二个方法是取任何二进制数据，并将其编码为与文本兼容的格式。Base64 就是这样一种编码机制，多年来在互联网上用于各种目的，并且在现代浏览器和 Node.js 中都有支持。在本章中，我展示了使用现代浏览器接口和 Node.js 与 base64 相互转换的菜谱。请注意，这意味着数据膨胀，因为将二进制信息表示为文本会增加传输的数据大小。

人们在考虑为他们的应用程序使用 JSON 时经常表达的一个担忧是，JSON 包的大小与二进制格式（如 BSON、协议缓冲区或手工调优的二进制表示）相比。虽然 JSON 可能比二进制表示大，但您获得了可读性（特别有助于调试）、清晰的语义，以及大量可用的库和实施实例。减少空白字符和使用简短的关键字名称可以帮助减小 JSON 的大小，压缩也可以——在我最近的一个项目中，我的测试显示，使用标准的 HTTP 压缩对 JSON 进行压缩，比全部二进制表示节省的内存更多，当然在服务器和客户端实现起来也更简单。

请记住，为了节省内存而转换为二进制格式——无论是 BSON、压缩还是自定义格式——都会抵消 JSON 的一个最有用的属性，即其自文档化属性。

# 使用 Node.js 将二进制数据编码为 base64 字符串

如果您有二进制数据需要编码以作为 JSON 传递给客户端，您可以将其转换为 base64，这是在互联网上表示八位值的一种常见方式，仅使用可打印字符。Node.js 提供了`Buffer`对象和`base64`编码器和解码器来完成这项任务。

## 如何做到…

首先，您会分配一个缓冲区，然后将其转换为字符串，指示您想要的字符串应该是 base64 编码的，如下所示：

```js
var buffer = newBuffer('Hello world');
var string = buffer.toString('base64');
```

## 它是如何工作的…

`Node.js`的`Buffer`类包装了一组八位字节，位于 Node.js V8 运行时堆之外。当您需要在 Node.js 中处理纯二进制数据时，它会用到。我们示例的第一行创建了一个缓冲区，用字符串`Hello world`填充它。

`Buffer`类包含`toString`方法，该方法接受一个参数，即编码缓冲区的手段。这里，我们传递了`base64`，表示我们希望`s`包含`b`的`base64`表示，但我们可以同样容易地传递以下值之一：

+   `ascii`：这个值表示应该移除高位比特，并将每个八位字节剩余的 7 位转换为其 ASCII 等效值。

+   `utf8`：这个值表示它应该作为多字节 Unicode 编码。

+   `utf16le`：这些是 2 个或 4 个字节的小端 Unicode 字符。

+   `hex`：这个值是将每个八位字节编码为两个字符，八位字节的`hex`值。

## 也见

有关 Node.js 的`Buffer`类的文档，请参阅[`nodejs.org/api/buffer.html`](https://nodejs.org/api/buffer.html)。

# 从 base64 字符串解码二进制数据使用 Node.js

在 Node.js 中，没有`Buffer.toString`的逆操作；相反，您直接将 base64 数据传递给缓冲区构造函数，并附上一个标志，表示数据是 base64 编码的。

## 准备

如果你想要像这里显示的那样运行示例，你需要安装`buffertools`模块，以获取`Buffer.compare`方法。为了获得这个模块，请在命令提示符下运行`npm`：

```js
npm install buffertools

```

如果你只是要使用 Node.js 的`Buffer`构造函数来解码 base64 数据，你不需要做这个。

## 如何做到…

在这里，我们将我们的原始缓冲区与另一个用原始 base64 初始化的缓冲区进行比较，这是为了第一个消息：

```js
require('buffertools').extend();

var buffer = new Buffer('Hello world');
var string = buffer.toString('base64');
console.log(string);

var another = new Buffer('SGVsbG8gd29ybGQ=', 'base64');
console.log(b.compare(another) == 0);
```

## 它是如何工作的…

代码的第一行包含了`buffertools`模块，它扩展了`Buffer`接口。这只是为了在最后一行使用缓冲区工具的`Buffer.compare`方法，不是因为 base64 需要自我解码。

接下来的两行创建了一个`Buffer`对象并获取其`base64`表示，接下来的行将这个表示输出到控制台。

最后，我创建了第二个`Buffer`对象，用一些 base64 数据初始化它，传递 base64 以表示初始化数据应该被解码到缓冲区中。我在最后一行比较这两个缓冲区。注意，缓冲区工具的`compare`方法是一个序数比较，意味着如果两个缓冲区包含相同的数据，它返回 0，如果第一个包含小于数据的序数排序，它返回-1，如果第一个包含序数排序更大的数据，它返回 1。

## 也见

关于`buffertools`模块及其实现的信息，请参阅[`github.com/bnoordhuis/node-buffertools#`](https://github.com/bnoordhuis/node-buffertools#)。

# 在浏览器中使用 JavaScript 对二进制数据进行 base64 字符串编码

JavaScript 的基本实现不包括 base64 编码或解码。然而，所有现代浏览器都包括了`atob`和`btoa`方法来分别解码和编码 base64 数据。这些方法是 window 对象的方法，由 JavaScript 运行时定义。

## 如何做到…

这只是方法调用的简单：

```js
var encodedData = window.btoa("Hello world"); 
var decodedData = window.atob(encodedData);
```

## 它是如何工作的…

`btoa`函数接收一个字符串并返回该字符串的 base64 编码。它是 window 对象的方法，并调用原生浏览器代码。`atob`函数做相反的事情，接收一个包含 base64 的字符串并返回一个包含二进制数据的字符串。

## 也见

关于`btoa`和`atob`的总结，请参阅 Mozilla 开发者网站上的[`developer.mozilla.org/en-US/docs/Web/API/WindowBase64/Base64_encoding_and_decoding`](https://developer.mozilla.org/en-US/docs/Web/API/WindowBase64/Base64_encoding_and_decoding)（注意虽然这些文档来自 Mozilla，但这些`window`的方法由大多数现代浏览器定义）。

# 使用 Json.NET 对数据进行 BSON 编码

BSON 编码是如果你在连接的每一边都有一个编码器和解码器的实现，那么它是 JSON 的一个合理替代方案。不幸的是，目前还没有适合 JavaScript 的好编码器和解码器，但是有包括.NET 和 C++在内的许多其他平台上的实现。让我们看看如何使用 Json.NET 在 C#中对 BSON 进行编码。

## 准备开始

首先，你需要让你的应用程序能够访问 Json.NET 程序集。正如你在上一章中看到的，在食谱*如何使用 Json.NET 反序列化一个对象*中，最容易的方法是使用 NuGet。如果你还没有这么做，按照那个食谱的步骤将 Json.NET 程序集添加到你的解决方案中。

## 如何做到…

使用 Json.NET 来编码 BSON 相对简单，一旦你有了想要编码的类：

```js
public class Record {
  public string Callsign { get; set; }
  public double Lat { get; set; }
  public double Lng { get; set; }
} 
…
var r = new Record {
  Callsign = "kf6gpe-7",
  Lat = 37.047,
  Lng = 122.0325
};

var stream = new MemoryStream();
using (var writer = new Newtonsoft.Json.Bson.BsonWriter(ms))
{
  var serializer = new Newonsoft.Json.JsonSerializer();
  serializer.Serialize(writer, r);
}
```

## 它是如何工作的…

最容易的方法是从一个具有你想要转换的场的类开始，正如你为其他类型的 JSON 安全转换所做的那样。在这里，我们为了这个目的定义了一个简单的`Record`类，然后创建一个记录来编码。

接下来，我们创建一个`MemoryStream`来包含编码后的数据，以及一个`BsonWriter`对象来将数据写入内存流。当然，任何实现.NET 流接口的东西都可以与`BsonWriter`实例一起使用；如果你愿意，你可以写入文件而不是内存流。在那之后，我们创建一个实际的序列化器来完成工作，`JsonSerializer`的一个实例，并使用它本身来序列化我们使用编写器创建的记录。我们将实际的序列化包裹在一个 using 块中，这样在操作结束时，写入器使用的资源（但不是流）会立即被.NET 运行时清理。

## 参见 also

关于 BsonWriter 类的文档可以从 NewtonSoft 处获得，网址为[`www.newtonsoft.com/json/help/html/T_Newtonsoft_Json_Bson_BsonWriter.htm`](http://www.newtonsoft.com/json/help/html/T_Newtonsoft_Json_Bson_BsonWriter.htm)。

# 使用 Json.NET 从 BSON 中解码数据

使用 Json.NET，解码 BSON 与编码相反；给定一个描述要解码数据的类和一个二进制数据块，调用一个读取器来读取数据。

## 准备开始

当然，为了做到这一点，你需要在你项目中有一个 Json.NET 程序集的引用。参见第七章*使用类型安全的方式使用 JSON*中的食谱*如何使用 Json.NET 反序列化一个对象*，了解如何使用 NuGet 在你的应用程序中添加 Json.NET 的引用。

## 如何做到…

从一个流开始，你将使用`BsonReader`和`JsonSerializer`来反序列化 BSON。假设数据是 BSON 数据的`byte[]`：

```js
MemoryStream ms = new MemoryStream(data);
using (var reader = new Newtonsoft.Json.Bson.BsonReader(ms))
{
  var serializer = new Newtonsoft.Json.JsonSerializer();
  var r = serializer.Deserialize<Record>(reader);

  // use r
}
```

## 它是如何工作的…

我们从传入的数据中创建`MemoryStream`，然后使用`BsonReader`实际从流中读取数据。读取工作由`JsonSerializer`完成，它使用读取器将数据反序列化为`Record`类的新实例。

## 还有更多…

你可能没有代表反序列化数据的类的应用；这在开发初期很常见，当时你仍在定义数据传输的语义。你可以使用`Deserialize`方法反序列化一个`JsonObject`实例，然后使用`JsonObject`的接口获取各个字段值。关于`JsonObject`的信息，请参阅 Json.NET 文档[`www.newtonsoft.com/json/help/html/T_Newtonsoft_Json_JsonObjectAttribute.htm`](http://www.newtonsoft.com/json/help/html/T_Newtonsoft_Json_JsonObjectAttribute.htm)。

## 参见

`BsonReader`的文档在[`www.newtonsoft.com/json/help/html/T_Newtonsoft_Json_Bson_BsonReader.htm`](http://www.newtonsoft.com/json/help/html/T_Newtonsoft_Json_Bson_BsonReader.htm)。

# 使用`DataView`访问`ArrayBuffer`

有时，你不想与 JSON 一起工作，而是想与纯二进制数据一起工作。JavaScript 提供了`DataView`抽象，它让你可以在一个数组缓冲区的内存上进行类型化的访问，比如从一个`XMLHttpRequest`对象获得的内存。

## 准备中

开始之前，你需要你的数据在一个`ArrayBuffer`中，比如`XMLHttpRequest`对象返回的那个。有了这个，你可以创建一个`DataView`，然后使用那个`DataArray`，在数据视图上创建一个类型数组，以提取你感兴趣的字节。让我们看一个例子。

## 如何做到…

这是一个简单的示例：

```js
var req = new XMLHttpRequest();
req.open("GET", url, true);
req.responseType = "arraybuffer";
req.onreadystatechange = function () {
  if (req.readyState == req.DONE) {
    var arrayResponse = req.response;
    var dataView = new DataView(arrayResponse);
    var ints = new Uint32Array(dataView.byteLength / 4);

    // process each int in ints here.

    }
}
req.send();
```

## 它是如何工作的…

首先要注意到的是`XMLHttpRequest`对象的`responseType`。在这个例子中，我们将它设置为`arraybuffer`，表示我们想要一个以`ArrayBuffer`类实例表示的原始字节缓冲区。我们发起请求，在完成处理程序上创建`DataView`的响应。

`DataView`是一个抽象对象，从这个对象中我们可以创建不同的视图来读写`ArrayBuffer`对象中的二进制数据。

`DataView`支持将`ArrayBuffer`对象视为以下内容：

+   `Int8Array`: 这是一个 8 位补码有符号整数数组

+   `Uint8Array`: 这是一个 8 位无符号整数数组

+   `Int16Array`: 这是一个 16 位补码有符号整数数组

+   `Uint16Array`: 这是一个 16 位无符号整数数组

+   `Int32Array`: 这是一个 32 位补码有符号整数数组

+   `Uint32Array`: 这是一个 32 位无符号整数数组

+   `Float32Array`: 这是一个 32 位浮点数数组

+   `Float64Array`: 这是一个 64 位浮点数数组

除了从一个`DataView`构造这些数组之外，你还可以从一个`DataView`访问单个 8 位、16 位、32 位整数或 32 位或 64 位浮点数，使用相应的获取函数，传递你想获取的偏移量。例如，`getInt8`返回指定位置的`Int8`，而`getFloat64`获取你指定偏移量处的相应的 64 位浮点数。

## 参见

尽管 `ArrayBuffer` 和 `DataView` 并不仅限于 Microsoft Internet Explorer，但 Microsoft 的 MSDN 网站上的文档非常清晰。有关 `DataView` 方法的信息，请参阅 [`msdn.microsoft.com/en-us/library/br212463(v=vs.94).aspx`](https://msdn.microsoft.com/en-us/library/br212463(v=vs.94).aspx)，或者参见 [`msdn.microsoft.com/library/br212485(v=vs.94).aspx`](https://msdn.microsoft.com/library/br212485(v=vs.94).aspx) 以获取关于类型数组的概述。

# 使用 ArrayBuffer 进行 base64 编码和解码

如果你打算使用 `ArrayBuffer` 和 `DataView` 为你 的二进制数据，并将二进制数据作为 base64 字符串携带，你可以使用由 Mozilla 编写的函数，位于 [`developer.mozilla.org/en-US/docs/Web/API/WindowBase64/Base64_encoding_and_decoding#Solution_.232_.E2.80.93_rewriting_atob%28%29_and_btoa%28%29_using_TypedArrays_and_UTF-8`](https://developer.mozilla.org/en-US/docs/Web/API/WindowBase64/Base64_encoding_and_decoding#Solution_.232_.E2.80.93_rewriting_atob%28%29_and_btoa%28%29_using_TypedArrays_and_UTF-8) 进行如此操作。他们提供了 `strToUTF8Arr` 和 `UTF8ArrToStr` 函数来执行 UTF-8 编码和解码，以及 `base64EncArr` 和 `base64DecToArr` 函数来在 base64 字符串和数组缓冲区之间进行转换。

## 如何做到…

这是一个相互转换示例，它将文本字符串编码为 UTF-8，然后将文本转换为 base64，然后显示 base64 结果，最后将 base64 转换为 UTF-8 数据的 `ArrayBuffer`，然后再将 UTF-8 转换回普通字符串：

```js
var input = "Base 64 example";

var inputAsUTF8 = strToUTF8Arr(input);

var base64 = base64EncArr(inputAsUTF8);

alert(base64);

var outputAsUTF8 = base64DecToArr(base64);

var output = UTF8ArrToStr(outputAsUTF8);

alert(output);
```

## 它是如何工作的…

Mozilla 在他们的网站文件中定义了四个函数：

+   `base64EncArr` 函数将字节 `ArrayBuffer` 编码为 base64 字符串

+   `base64DecToArr` 函数将 base64 字符串解码为字节 `ArrayBuffer`

+   `strToUTF8Arr` 函数将字符串编码为 `ArrayBuffer` 中的 UTF-8 编码字符数组

+   `UTF8ArrToStr` 函数接受 `ArrayBuffer` 中的 UTF-8 编码字符数组，并返回它所编码的字符串

# 压缩 Node.js 服务器中使用 express 模块构建的对象体内容

如果你在使用 JSON 时有空间方面的主要考虑，让你在考虑二进制表示时，你应该认真考虑使用压缩。压缩可以带来与二进制表示相似的节省，在大多数服务器和 HTTP 客户端中使用 `gzip` 实现，并且可以在调试完你的应用程序后作为透明层添加。在这里，我们讨论为流行的基于 Node.js 的 express 服务器发送的 JSON 和其他对象添加对象体压缩。

## 准备好了

首先，你需要确保已经安装了 express 和 compress 模块：

```js
npm install express
npm install compression

```

如果你想要它在你的工作区中的所有 Node.js 应用程序中可用，你也可以 `npm install –g` 它。

## 如何做到…

在你服务器的入口点初始化 `express` 模块时，需要 require 压缩，并告诉 `express` 使用它：

```js
var express = require('express')
var compression = require('compression')
var app = express()
app.use(compression())

// further express setup goes here.
```

关于如何使用`express`模块来设置服务器的更多信息，请参阅第五章中的菜谱“为 Node.js 安装 express 模块”，*使用 JSON 与 MongoDB*.

## 它是如何工作的…

HTTP 头支持客户端指示它是否能够解压缩通过 HTTP 发送的对象体，并且现代浏览器都接受`gzipped`对象体。通过在基于 express 的服务器中包含 compress，你使得客户端可以请求压缩后的 JSON 作为其 Web API 请求的一部分，并且响应中也返回压缩后的 JSON。在大多数情况下，大多数客户端不需要进行任何更改，尽管如果你正在编写带有自己 HTTP 实现的本地客户端，你可能需要查阅文档以确定如何通过 HTTP 启用`gzip`解压缩。

代码首先需要引入 express 模块和压缩模块，然后配置 express 模块，在客户端请求压缩时，可选地使用压缩功能来发送响应。
