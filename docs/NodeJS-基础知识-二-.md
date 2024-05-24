# NodeJS 基础知识（二）

> 原文：[`zh.annas-archive.org/md5/41C152E6702013095E0E6744245B8C51`](https://zh.annas-archive.org/md5/41C152E6702013095E0E6744245B8C51)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：配置

随着我们的应用程序变得越来越大，我们开始失去对配置做什么的视野；我们可能也会陷入这样一种情况：我们的代码在 12 个不同的地方运行，每个地方都需要一些代码来做一些其他事情，例如连接到不同的数据库。然后，对于这 12 个环境，我们有三个版本：生产、暂存和开发。突然间，情况变得非常复杂。这就是为什么我们需要能够从更高层次配置我们的代码，这样我们就不会在这个过程中破坏任何东西。

# JSON 文件

有几种方法可以配置我们的应用程序。我们将首先看一种简单的 JSON 文件。

如果我们查看默认支持的扩展名，我们可以看到我们可以将 JSON 直接导入到我们的代码中，如下所示：

```js
[~/examples/example-16]$ node
> require.extensions
{ '.js': [Function],
'.json': [Function],
'.node': [Function: dlopen] }

```

让我们创建一个简单的服务器，使用配置文件而不是硬编码文件：

首先，我们必须创建配置文件：

```js
{
    "host": "localhost",
    "port": 8000
}
```

有了这个，我们现在可以创建我们的服务器了：

```js
var Config = require('./config.json'),
    Http = require('http');
Http.createServer(function(request, response) {

}).listen(Config.port, Config.host, function() {
    console.log('Listening on port', Config.port, 'and host', Config.host);
});
```

现在，我们只需要更改`config`文件，而不是更改代码来更改服务器运行的端口。

但是我们的`config`文件有点太通用了；我们不知道主机或端口是什么，以及它们与什么相关。

在配置时，键需要更具体，这样我们才知道它们被用于什么，除非应用程序直接给出了上下文。例如，如果应用程序只提供纯静态内容，那么使用更通用的键可能是可以接受的。

为了使这些配置键更具体，我们可以将它们全部包装在一个服务器对象中：

```js
{
    "server": {
        "host": "localhost",
        "port": 8000
    }
}
```

现在，为了了解服务器的端口，我们需要使用以下代码：

```js
Config.server.port
```

一个可能有用的例子是连接到数据库的服务器，因为它们可以接受端口和主机作为参数：

```js
{
    "server": {
        "host": "localhost",
        "port": 8000
    },
    "database": {
        "host": "db1.example.com",
        "port": 27017
    }
}
```

# 环境变量

我们可以通过使用环境变量来配置我们的应用程序的另一种方式。

这些可以由你运行应用程序的环境或使用的命令来定义。

在 Node.js 中，你可以使用`process.env`来访问环境变量。使用`env`时，你不希望过多地污染这个空间，所以最好是给键加上与你自己相关的前缀——你的程序或公司。例如，`Config.server.host`变成了`process.env.NAME_SERVER_HOST`；原因是我们可以清楚地看到与你的程序相关的内容和不相关的内容。

使用环境变量来配置我们的服务器，我们的代码将如下所示：

```js
var Http = require('http'),
    server_port,
    server_host;

server_port = parseInt(process.env.FOO_SERVER_PORT, 10);
server_host = process.env.FOO_SERVER_HOST;

Http.createServer(function(request, response) {

}).listen(server_port, server_host, function() {
    console.log('Listening on port', server_port, 'and host', server_host);
});
```

为了使用我们的变量运行这段代码，我们将使用：

```js
[~/examples/example-17]$ FOO_SERVER_PORT=8001 \
FOO_SERVER_HOST=localhost node server.js
Listening on port 8001 and host localhost

```

你可能注意到我不得不对`FOO_SERVER_PORT`使用`parseInt`；这是因为以这种方式传递的所有变量本质上都是字符串。我们可以通过执行`typeof process.env.FOO_ENV`来看到这一点：

```js
[~/examples/example-17]$ FOO_ENV=1234 node
> typeof process.env.FOO_ENV
'string'
> typeof parseInt( process.env.FOO_ENV, 10 )
'number'

```

尽管这种配置非常简单易于创建和使用，但可能不是最佳方法，因为如果变量很多，很难跟踪它们，并且它们很容易被遗漏。

# 参数

配置可以通过作为进程启动时传递给 Node.js 的参数来完成，你可以使用`process.argv`来访问这些参数，`argv`代表参数向量。

`process.argv`返回的数组始终会在索引`0`处有一个`node`。例如，如果你运行`node server.js`，那么`process.argv`的值将是`[ 'node', '/example/server.js' ]`。

如果你向 Node.js 传递一个参数，它将被添加到`process.argv`的末尾。

如果你运行`node server.js --port=8001`，`process.argv`将包含`[ 'node', '/example/server.js', '--port=8001' ]`，非常简单，对吧？

尽管我们可以有所有这些配置，但我们应该始终记住，配置可以被简单地排除，即使这种情况发生，我们仍希望我们的应用程序能够运行。通常情况下，当你有配置选项时，你应该提供默认的硬编码值作为备份。

密码和私钥等参数永远不应该有默认值，但通常标准的链接和选项应该有默认值。在 Node.js 中很容易给出默认值，你只需要使用 `OR` 运算符。

```js
value = value || 'default';
```

基本上，这样做的作用是检查值是否为`falsy`；如果是，则使用默认值。你需要注意那些你知道可能是`falsy`的值，布尔值和数字肯定属于这个范畴。

在这些情况下，你可以使用一个检查 `null` 值的 `if` 语句，如下所示：

```js
if ( value == null ) value = 1
```

# 总结

配置就介绍到这里。在本章中，你学会了三种创建动态应用程序的方法。我们学到了应该以一种可以识别值的变化和它们对应用程序的影响的方式命名配置键。我们还学会了如何使用环境变量和 `argv` 将简单参数传递给我们的应用程序。

有了这些信息，我们可以继续在下一章中连接和利用数据库。

为 Bentham Chang 准备，Safari ID bentham@gmail.com 用户编号：2843974 © 2015 Safari Books Online，LLC。此下载文件仅供个人使用，并受到服务条款的约束。任何其他使用都需要版权所有者的事先书面同意。未经授权的使用、复制和/或分发严格禁止并违反适用法律。保留所有权利。


# 第六章：Level DB 和 NoSQL

在本章中，我们将介绍两种可以与 Node.js 一起使用的数据库变体；一种提供了非常轻量级和简单的功能集，而另一种则为我们提供了更灵活和通用的功能集。在本章中，我们将介绍 LevelDB 和 MongoDB

# Level DB

Node.js 的一个很棒的地方是我们在前端和后端都使用相同的语言，NoSQL 数据库也是如此。它们中的大多数从一开始就支持 JSON；这对于使用 Node.js 的任何人来说都很棒，因为不需要花时间制作关系模型，将其转换为类似 JSON 的结构，将其传递到浏览器，对其进行操作，然后再反转这个过程。

使用原生支持 JSON 的数据库，您可以立即开始工作并投入使用。

Google 为我们提供了一个简单的入口到一个可以安装并准备使用的 NoSQL 数据库，只需一个命令即可：

```js
[~/examples/example-18]$ npm install level

```

您将看到这将安装`LevelDOWN`和`LevelUP`。

`LevelDOWN`是`LevelDB`的低级绑定，`LevelUP`是对其的简单封装。

`LevelDB`在设置方面非常简单。一旦安装完成，我们只需创建一个`LevelUP`实例，并将其传递到我们希望存储数据库的位置：

```js
var LevelUP = require( 'level' ),
    db = new LevelUP( './example-db');
```

现在我们有了一种快速简单的存储数据的方法。

由于`LevelDB`只是一个简单的键/值存储，它默认使用字符串键和字符串值。如果这是您希望存储的所有信息，这是很有用的。您还可以将其用作简单的缓存存储。它有一个非常简单的 API，此阶段我们只关注四种方法：`put`、`get`、`del`和`createReadStream`；大多数方法的作用都很明显：

| 方法 | 用途 | 参数 |
| --- | --- | --- |
| put | 插入键值对 | 键，值，回调函数（错误） |
| get | 获取键值对 | 键，回调函数（错误，值） |
| del | 删除键值对 | 键，回调函数（错误） |
| createReadStream | 获取多个键值对 |   |

一旦我们创建了数据库，要插入数据，我们只需要做以下操作：

```js
db.put( 'key', 'value', function( error ) {
    if ( error ) return console.log( 'Error!', error )

    db.get( 'key', function( error, value ) {
        if ( error ) return console.log( 'Error!', error )

        console.log( "key =", value )
    });
});
```

如果运行代码，我们将看到我们插入并检索到了我们的值：

```js
[~/examples/example-18]$ node index.js
key = value

```

这不是我们简单的 JSON 结构；但是，它只是一个字符串。要使我们的存储保存 JSON，我们只需要将值编码作为选项传递给数据库，如下所示：

```js
var LevelUP = require( 'level' ),
    db = new LevelUP( './example-db', {
        valueEncoding: 'json'
    });
```

现在我们可以存储 JSON 数据：

```js
db.put( 'jsonKey', { inner: 'value' }, function ( error ) {
    if ( error ) return console.log( 'Error!', error )

    db.get( 'jsonKey', function( error, value ) {
        if ( error ) return console.log( 'Error!', error )

        console.log( "jsonKey =", value )
    });
});
```

然而，字符串可以存储为 JSON，我们仍然可以将字符串作为值传递，并且也可以检索它。

运行此示例将显示以下内容：

```js
[~/examples/example-18]$ node index.js
key = value
jsonKey = { inner: 'value' }

```

现在，我们已经掌握了简单的方法，现在我们可以继续使用`createReadStream`。

此函数返回一个对象，可以与 Node.js 内置的`ReadableStream`进行比较。对于数据库中的每个键/值对，它将发出一个`data`事件；它还会发出其他事件，如`error`和`end`。如果`error`没有事件监听器，那么它将传播，从而终止整个进程（或域），如下所示：

```js
db.put( 'key1', { inner: 'value' }, function( error ) {
    if ( error ) return console.log( 'Error!', error )

    var stream = db.createReadStream( );

    stream
    .on( 'data', function( pair ) {
        console.log( pair.key, "=", pair.value );
    })
    .on( 'error', function( error ) {
        console.log( error );
    })
    .on( 'end', function( ) {
        console.log( 'end' );
    });
});
```

运行此示例：

```js
[~/examples/example-20]$ node index.js
key1 = { inner: 'value' }
end

```

如果我们在数据库中放入更多数据，将会发出多个`data`事件：

```js
[~/examples/example-20]$ node index.js
key1 = { inner: 'value' }
key2 = { inner: 'value' }
end

```

# MongoDB

正如您所看到的，使用 Node.js 的数据库可以非常简单。如果我们想要更完整的东西，我们可以使用另一个名为**MongoDB**的 NoSQL 数据库——另一个非常受欢迎的基于文档的数据库。

对于这组示例，您可以使用托管数据库，使用提供者如 MongoLab（他们提供免费的开发层级），或者您可以按照[`docs.mongodb.org/manual/installation`](http://docs.mongodb.org/manual/installation)上的说明在本地设置数据库。

一旦您有一个要连接的数据库，我们就可以继续。

MongoDB 有几个可以与 Node.js 一起使用的模块，最受欢迎的是 Mongoose；但是，我们将使用核心的 MongoDB 模块：

```js
[~/examples/example-21]$ npm install mongodb

```

要使用我们的数据库，我们首先需要连接到它。我们需要为客户端提供一个连接字符串，一个带有`mongodb`协议的通用 URI。

如果您有一个本地的 mongo 数据库在没有凭据的情况下运行，您将使用：

```js
mongodb://localhost:27017/database
```

默认端口是`27017`，所以你不需要指定它；但是为了完整起见，它已经包含在内。

如果你正在使用 MongoLab，他们会提供给你一个连接字符串；它应该是这种格式：

```js
mongodb://<dbuser>:<dbpassword>@<ds>.mongolab.com:<port>/<db>

```

连接到我们的数据库实际上非常简单。我们只需要提供驱动程序一个连接字符串，然后我们就可以得到一个数据库：

```js
var MongoDB = require('mongodb'),
    MongoClient = MongoDB.MongoClient;

connection = "mongodb://localhost:27017/database"

MongoClient.connect( connection, function( error, db ) {
    if( error ) return console.log( error );

    console.log( 'We have a connection!' );
});
```

MongoDB 中的每组数据都存储在一个集合中。一旦我们有了数据库，我们就可以获取一个集合来运行操作：

```js
var collection = db.collection( 'collection_name' );
```

在一个集合中，我们有一些简单的方法，拥有很大的力量，为我们提供了一个完整的 CRUD“API”。

MongoDB 中的每个文档都有一个 ID，它是`ObjectId`的一个实例。他们用于此 ID 的属性是`_id`。

要保存一个文档，我们只需要调用`save`，它接受一个对象或对象数组。集合中的单个对象称为文档：

```js
var doc = {
    key: 'value_1'  
};
collection.save( doc, { w: 1 }, function( ) {
    console.log( 'Document saved' )
});
```

如果我们使用带有 ID 的文档调用`save`函数，那么该文档将被更新而不是插入：

```js
var ObjectId = MongoDB.ObjectId
// This document already exists in my database
var doc_id = {
    _id: new ObjectId( "55b4b1ffa31f48c6fa33a62a" ),
    key: 'value_2'
};
collection.save( doc_id, { w: 1 }, function( ) {
    console.log( 'Document with ID saved' );
});
```

现在我们在数据库中有了文档，我们可以查询它们，如下所示：

```js
collection.find( ).toArray( function( error, result ) {
    console.log( result.length + " documents in our database!" )
});
```

如果`find`没有提供回调函数，它将返回一个游标；这使我们能够使用`limit`、`sort`和`toArray`等方法。

你可以向`find`传递一个查询来限制返回的内容。为了通过其 ID 查找对象，我们需要使用类似于以下的东西：

```js
collection.find(
    { _id: new ObjectId( "55b4b1ffa31f48c6fa33a62a" ) },
    function( error, documents ) {
        console.log( 'Found document', documents[ 0 ] );
    }
);
```

我们还可以通过任何其他可能使用的属性进行过滤：

```js
collection.find(
    { key: 'value' },
    function( error, documents ) {
        console.log( 'Found', documents.length, 'documents' );  
    }
);
```

如果你以前使用过 SQL，你一定会注意到缺少操作符，比如`OR`、`AND`或`NOT`。但是，你不需要担心，因为 mongo 提供了许多等价物。

你可以在这里看到完整的列表：[`docs.mongodb.org/manual/reference/operator/query/`](http://docs.mongodb.org/manual/reference/operator/query/)。

所有操作符都以美元符号开头，例如`$and`、`$or`、`$gt`和`$lt`。

你可以查看文档以查看使用这些的具体语法。

要使用`$or`条件，你需要将其包含在其中，就好像它是一个属性一样：

```js
collection.find(
    {
        $or: [
            { key: 'value' },
            { key: 'value_2' }
        ]
    },
    function( error, documents ) {
        console.log( 'Found', documents.length, 'documents' );  
    }
);
```

使用诸如 MongoDB 这样的数据库使我们能够更有力地检索数据并创建更具功能的软件。

# 摘要

现在我们有可以存储数据的地方。一方面，我们有一个简单的键/值存储，为我们提供了一种非常方便的存储数据的方式；另一方面，我们有一个功能丰富的数据库，为我们提供了一整套查询操作符。

这两个数据库将在接下来的章节中帮助我们，因为我们将更接近创建我们的全栈应用程序。

在下一章中，我们将介绍`Socket.IO`，这是一个建立在 WebSockets 之上的实时通信框架。

为 Bentham Chang 准备，Safari ID 为 bentham@gmail.com 用户编号：2843974 © 2015 Safari Books Online，LLC。此下载文件仅供个人使用，并受到服务条款的约束。任何其他使用都需要版权所有者的事先书面同意。未经授权的使用、复制和/或分发严格禁止并违反适用法律。保留所有权利。


# 第七章：Socket.IO

简单的 HTTP 非常适合不需要实时数据的情况，但是当我们需要在事件发生时得知情况时怎么办。例如，如果我们正在创建一个具有聊天界面或类似功能的网站呢？

这就是 Web sockets 发挥作用的时候。Web sockets 通常被称为 WebSockets，是全双工或双向低延迟通信通道。它们通常被用于消息应用程序和游戏，其中需要在服务器和客户端之间中继消息。有一个非常方便的`npm`模块叫做`socket.io`，它可以为任何 Node.js 应用程序添加 Web sockets。

要安装它，我们只需要运行：

```js
[~/examples/example-27] npm install socket.io

```

Socket.IO 可以非常简单地设置以监听连接。首先，我们希望能够提供一个静态的 html 页面来运行客户端代码：

```js
var Http = require( 'http' ),
    FS = require( 'fs' );

var server = Http.createServer( handler );

server.listen( 8080 );

function handler( request, response ) {
    var index = FS.readFileSync( 'index.html' );
    index = index.toString( );

    response.writeHead(200, {
        'Content-Type': 'text/html',
        'Content-Length': Buffer.byteLength( index )
    });
    response.end( index );
}
```

现在，让我们在同一目录中创建一个名为`index.html`的 HTML 文件：

```js
<html>
    <head>
        <title>WS Example</title>
    </head>
    <body>
        <h2>WS Example</h2>
        <p id="output"></p>
        <!-- SocketIO Client library -->
        <script src="img/socket.io.js"></script>
        <script type="application/javascript">
            /* Our client side code will go here */
        </script>
    </body>
</html>
```

让我们运行我们的示例，并确保我们得到我们的页面，我们应该能够在屏幕上看到**WS Example**。现在，要为我们的应用程序添加 socket 支持，我们只需要要求`socket.io`并指定要使用`IOServer`进行监听的`http`服务器：

```js
var IOServer = require( 'socket.io' );
var io = new IOServer( server );
```

现在，每当有一个新的 socket 连接在`8080`上，我们将在`io`上收到一个`connection`事件：

```js
io.on( 'connection', function( socket ) {
    console.log( 'New Connection' );
});
```

让我们向客户端添加一些代码。Socket.IO 为我们提供了一个客户端库，并通过端点`/socket.io/socket.io.js`公开了这一点。这已经包含在前面的`index.html`文件中。

### 提示

所有客户端代码都包含在`index.html`文件的第二个`script`标签中。

要与服务器建立连接，我们只需要调用`io.connect`并传递位置。这将为我们返回一个 socket，我们可以用它与服务器通信。

我们在这里使用了 Socket.IO 提供的客户端，因为它会检测 WebSockets 是否可用，如果可能的话会使用它们。否则，它将利用其他方法，如轮询，以确保它可以在任何地方工作，而不仅仅是在现代浏览器上：

```js
var socket = io.connect( 'http://localhost:8080' );
```

我们将使用一个`p`元素来将消息记录到屏幕上。我们可以使用这段代码来做到这一点，然后我们只需要调用`logScreen`：

```js
var output = document.getElementById( 'output' );

function logScreen( text ) {
    var date = new Date( ).toISOString( );
    line = date + " " + text + "<br/>";
    output.innerHTML =  line + output.innerHTML
}
```

一旦建立连接，就像在服务器端一样，会发出一个`connection`事件，我们可以使用`on`来监听这个事件：

```js
socket.on( 'connection', function( ){
    logScreen( 'Connection!' );
});
```

现在，一旦我们导航到`http://localhost:8080`，我们就可以运行我们的服务器。您应该能够看到**Connection!**显示出来：

![Socket.IO](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-ess/img/B04729_07_01.jpg)

要在服务器端接收消息，我们只需要监听`message`事件。现在，我们将简单地将消息回显：

```js
socket.on( 'connection', function( ){
    socket.on( 'message', function ( message ) {
        socket.send( message );
    });
});
```

在客户端，我们只需要调用`send`来发送消息，我们希望在连接事件中执行此操作。双方的`api`非常相似，正如你所看到的：

```js
socket.send( 'Hello' );
```

在客户端，我们还希望监听消息并将其记录到屏幕上：

```js
socket.on( 'message', logScreen );
```

一旦我们重新启动服务器并刷新页面，我们应该能够看到屏幕上出现一个额外的**Hello**消息。

```js
[~/examples/example-27]$ node index.js
Hello
```

这是因为服务器现在可以向客户端发送数据包。这也意味着我们可以随时更新客户端。例如，我们可以每秒向客户端发送一个更新：

```js
socket.on( 'connection', function( ){
    function onTimeout( ) {
        socket.send( 'Update' );
    }
    setInterval( onTimeout, 1000 );
});
```

现在，当我们重新启动服务器时，我们应该能够每秒看到一个更新消息。

您可能已经注意到，您无需刷新网页即可重新打开连接。这是因为`socket.io`会透明地保持我们的连接“活动”，并在需要时重新连接。这消除了使用 sockets 的所有痛苦，因为我们没有这些麻烦。

# 房间

Socket.IO 还有房间的概念，多个客户端可以被分组到不同的房间中。要模拟这一点，您只需要在多个选项卡中导航到`http://localhost:8080`。

一旦客户端连接，我们需要调用`join`方法告诉 socket 要加入哪个房间。如果我们希望做一些特定用户的群聊之类的事情，我们需要在数据库中有一个房间标识符或创建一个。现在我们只是让每个人加入同一个房间：

```js
socket.on( 'connection', function( ){
    console.log( 'New Connection' );
    var room = 'our room';
    socket.join( room, function( error ) {
        if ( error ) return console.log( error );

        console.log( 'Joined room!' );
    });
});
```

每次我们打开一个标签页，我们都应该看到一个消息，告诉我们已经加入了一个房间：

```js
[~/examples/example-27]$ node index.js
New Connection
Joined room!
New Connection
Joined room!
New Connection
Joined room

```

有了这个，我们可以向整个房间广播消息。每次有人加入时让我们这样做。在加入回调中：

```js
socket
    .to( room )
    .emit(
        'message',
        socket.id + ' joined the room!'
    );
```

如果你在浏览器中查看，每次连接时其他客户端都会收到通知，有人加入了：

```js
x3OwYOkOCSsa6Qt5AAAF joined the room!
mlx-Cy1k3szq8W8tAAAE joined the room!
Connection!
Connecting
```

这很棒，我们现在几乎可以直接在浏览器之间通信了！

如果我们想离开一个房间，我们只需要调用`leave`，在调用该函数之前我们将进行广播：

```js
socket
    .to( room )
    .emit(
        'message',
        socket.id + ' is leaving the room'
    );
socket.leave( room );
```

在运行时，您不会看到来自另一个客户端的任何消息，因为您立即离开了：但是，如果您对此进行延迟，您可能会看到另一个客户端进入和离开：

```js
leave = function( ) {
    socket
        .to( room )
        .emit(
            'message',
            socket.id + ' is leaving the room'
        );
    socket.leave( room );
};

setTimeout( leave, 2000 );
```

# 认证

对于认证，我们可以使用与 HTTP 服务器相同的方法，并且我们可以接受 JSON Web Token

在这些示例中，为了简单起见，我们将只有一个单一的 HTTP 路由来登录。我们将签署一个 JWT，稍后我们将通过检查签名来进行身份验证

我们需要安装一些额外的`npm`模块；我们将包括`chance`，以便我们可以生成一些随机数据。

```js
[~/examples/example-27] npm install socketio-jwt jsonwebtoken chance

```

首先，我们需要一个到`login`的路由。我们将修改我们的处理程序以监视`/login`的 URL：

```js
if ( request.url === '/login' ) {
    return generateToken( response )
}
```

我们的新函数`generateToken`将使用`chance`创建一个 JSON Web Token，并且我们还需要一个令牌的密钥：

```js
var JWT = require( 'jsonwebtoken' ),
    Chance = require( 'chance' ).Chance( );

var jwtSecret = 'Our secret';

function generateToken( response ) {

    var payload = {
        email: Chance.email( ),
        name: Chance.first( ) + ' ' + Chance.last( )
    }

    var token = JWT.sign( payload, jwtSecret );

    response.writeHead(200, {
        'Content-Type': 'text/plain',
        'Content-Length': Buffer.byteLength( token )
    })
    response.end(token);
}
```

现在，每当我们请求`http://localhost:8080/login`时，我们将收到一个可以使用的令牌：

```js
[~]$ curl -X GET http://localhost:8080/login
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJlbW
joiR2VuZSBGbGVtaW5nIiwiaWF0IjoxNDQxMjcyMjM0
e1Y

```

我们可以将其输入到[`jwt.io/`](http://jwt.io/)的调试器中并查看内容：

```js
{
  "email": "jefoconeh@ewojid.io",
  "name": "Gene Fleming",
  "iat": 1441272234
}
```

太棒了，我们有一个令牌和一个为我们生成的随机用户。现在，我们可以用这个来验证我们的用户。Socket.IO 在服务器上有一个方法来做到这一点，我们只需要向其传递一个处理程序类型函数。这就是`socketio-jwt`的作用，我们向其传递我们的密钥，它将确保它是一个真实的令牌，非常简单：

```js
var SocketIOJWT = require( 'socketio-jwt' );

io.use( SocketIOJWT.authorize({
    secret: jwtSecret,
    handshake: true }));
```

现在，当我们尝试从客户端连接到我们的服务器时，它永远不会发出`connect`事件，因为我们的客户端没有经过身份验证。这正是我们想要的。

我们首先想要包装我们的 Socket.IO 代码（稍后我们将调用它）；我们还想给它一个`token`参数：

```js
function socketIO ( token ) {

    var socket = io.connect( 'http://localhost:8080' );

    var output = document.getElementById( 'output' );

    function logScreen( text ) {
        var date = new Date( ).toISOString( );
        line = date + " " + text + "<br/>";
        output.innerHTML =  line + output.innerHTML
    }

    logScreen( 'Connecting' );

    socket.on( 'connect', function( ){
        logScreen( 'Connection!' );
        socket.send( 'Hello' );

    });
    socket.on( 'message', logScreen );

}
```

接下来，我们将创建一个`login`函数，这将请求登录 URL，然后将响应传递给`socketIO`函数，如下所示：

```js
function login( ) {
{
   var request = new XMLHttpRequest();
    request.onreadystatechange = function() {

            if (
            request.readyState !== 4 ||
            request.status !== 200
            ) return

           socketIO( request.responseText );
    }
    request.open( "GET", "/login", true );
    request.send( null );
}
```

然后我们想调用登录函数：

```js
login( );
```

我们可以通过更改`connect`调用以传递查询字符串来将令牌传递给服务器：

```js
var socket = io.connect( 'http://localhost:8080', {
    query: 'token=' + token
});
```

现在，当我们运行服务器并导航到我们的客户端时，我们应该能够连接 - 太棒了！由于我们已经经过身份验证，我们还可以针对每个用户响应个性化消息，在我们的服务器端`connection`事件处理程序内，我们将向客户端发出消息。

我们的 socket 将有一个名为`decoded_token`的新属性；使用这个属性，我们将能够查看我们令牌的内容：

```js
var payload = socket.decoded_token;
var name = payload.name;

socket.emit( 'message', 'Hello ' + name + '!' );
```

一旦我们加入房间，我们可以告诉其他也加入的客户端：

```js
socket
    .to( room )
    .emit(
        'message',
        name + ' joined the room!'
    );
```

# 总结

Socket.IO 为我们的应用程序带来了惊人的功能。我们现在可以立即与其他人通信，无论是个别通信还是在房间中广播。通过识别用户的能力，我们可以记录消息或该用户的历史，准备通过 RESTful API 提供。

我们现在已经准备好构建实时应用程序了！

为 Bentham Chang 准备，Safari ID bentham@gmail.com 用户编号：2843974 © 2015 Safari Books Online，LLC。此下载文件仅供个人使用，并受到服务条款的约束。任何其他使用都需要版权所有者的事先书面同意。未经授权的使用、复制和/或分发严格禁止并违反适用法律。保留所有权利。


# 第八章：创建和部署包

现在我们已经拥有了创建 Node.js 应用程序和服务器所需的所有组件，我们现在将更多地关注分享我们的模块并为生态系统做出贡献。

所有 npm 上的包都是由社区中的某个人上传、维护和贡献的，所以让我们看看我们如何自己做同样的事情。

# 创建 npm 包

我们可以从以下步骤开始：

首先我们需要创建一个用户：

```js
[~]$ npm add user 
Username: <username>
Password:
Email: (this IS public) <email>

```

一旦我们有了一个用户，我们就为 npm 打开了大门。

现在，让我们创建一个包：

```js
[~/examples/example-22]$ npm init
{
 "name": "njs-e-example-package",
 "version": "1.0.0",
 "description": "",
 "main": "index.js",
 "scripts": {
 "test": "echo \"Error: no test specified\" && exit 1"
 },
 "author": "",
 "license": "ISC"
}

```

要发布这个包，我们只需要运行`npm publish`：

```js
[~/examples/example-22]$ npm publish
+ njs-e-example-package@1.0.0

```

您可以看到我们已经成功发布了我们的包，您可以查看我发布的包：

[`www.npmjs.com/package/njs-e-example-package`](https://www.npmjs.com/package/njs-e-example-package)

为了发布它，您将不得不给您的包取一个别的名字；否则，我们将会有冲突。

现在我们可以运行以下命令：

```js
[~/examples/example-21]$ npm install njs-e-example-package
njs-e-example-package@1.0.0 node_modules/njs-e-example-package

```

然后我们就会有这个包！这不是很酷吗？

如果我们再次尝试发布，将会出现错误，因为版本`1.0.2`已经发布，如下截图所示：

![创建 npm 包](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-ess/img/B04729_08_01.jpg)

要增加我们的包版本，我们只需要执行：

```js
[~/examples/example-22]$ npm version patch
v1.0.1

```

现在我们可以再次发布：

```js
[~/examples/example-22]$ npm publish
+ njs-e-example-package@1.0.1

```

您可以转到 npm 上的包页面，您会看到版本号和发布计数已经更新。

Node.js 中的版本控制遵循`semver`模式，由主要、次要和补丁版本组成。当增加补丁版本时，这意味着 API 保持不变，但在幕后修复了一些东西。如果增加了次要版本，这意味着发生了不破坏 API 的更改，例如添加了一个方法。如果更新了主要版本，这意味着发生了破坏 API 的更改；例如删除了一个方法或方法签名发生了变化。

有时，项目中有一些你不希望被其他人推出去的东西。这可能是原始源代码、一些证书，或者一些开发密钥。就像使用`git`一样，我们有一个叫做`.npmignore`的忽略文件。

默认情况下，如果没有`.npmignore`但有`.gitignore`，npm 将忽略`.gitignore`文件匹配的内容。如果您不喜欢这种行为，那么您可以创建一个空的`.npmignore`文件。

`.npmignore`文件遵循与`.gitignore`相同的规则，规则如下：

+   空行或以`#`开头的行将被忽略

+   标准的 glob 模式有效

+   您可以用斜杠`/`结束模式以指定目录

+   您可以通过在模式前加上感叹号`!`来否定一个模式

例如，如果我们有一个包含密钥的证书目录：

```js
[~/examples/example-22]$ mkdir certificates
[~/examples/example-22]$ touch certifticates/key.key

```

我们可能不希望这被发布，所以在我们的忽略文件中我们将有：

```js
certificates/

```

我们也不希望有任何我们搁置的`key`文件，所以我们也添加了这个：

```js
*.key

```

现在，让我们发布：

```js
[~/examples/example-22]$ npm version patch
v1.0.2
[~/examples/example-22]$ npm publish
+ njs-e-example-package@1.0.2

```

现在，让我们安装我们的包：

```js
[~/examples/example-23]$ npm install njs-e-example-package@1.0.2

```

现在，当我们列出目录中的内容时，我们不会看到所有的证书都被传播出去：

```js
[~/examples/example-23]$ ls node_modules/njs-e-example-package
package.json

```

这很好，但是如果我们想保护整个包而不仅仅是一些证书呢？

我们只需要在`package.json`文件中将`private`设置为`true`，这样当我们运行`npm publish`时，它将阻止 npm 发布模块：

我们的`package.json`应该看起来像这样：

```js
{
  "name": "example-23",
  "version": "1.0.0",
  "description": "",
  "main": "index.js",
  "scripts": {
    "test": "echo \"Error: no test specified\" && exit 1"
  },
  "author": "",
  "license": "UNLICENSED",
  "dependencies": {
    "njs-e-example-package": "¹.0.2"
  },
  "private": true
}
```

现在，当我们运行`npm publish`时：

```js
[~/examples/example-23]$ npm publish
npm ERR! This package has been marked as private

```

太棒了，这正是我们想要看到的。

# 总结

看起来我们离准备好所有关于 Node.js 的事情都越来越近了。我们现在知道如何设置、调试、开发和分发我们的软件。

在下一章中，我们将介绍我们需要了解的另一个概念：单元测试。

为 Bentham Chang 准备，Safari ID 为 bentham@gmail.com 用户编号：2843974 © 2015 Safari Books Online，LLC。此下载文件仅供个人使用，并受到服务条款的约束。任何其他用途均需版权所有者的事先书面同意。未经授权的使用、复制和/或分发严格禁止并违反适用法律。保留所有权利。


# 第九章：单元测试

我们已经走了这么远，但还没有做任何测试！这不太好，是吗？通常，如果不是总是，测试是软件开发中的一个主要关注点。在本章中，我们将介绍 Node 的单元测试概念。

Node.js 有许多测试框架，在本章中我们将介绍 Mocha。

# 安装 mocha

为了确保`mocha`在所有地方都安装了，我们需要全局安装它。这可以使用`npm install`的`-g`标志来完成：

```js
[~/examples/example-24]$ npm install -g mocha

```

现在，我们可以通过终端控制台使用 Mocha。

通常，我们将所有测试代码放在项目的`test`子目录中。我们只需要运行`mocha`，假设我们首先编写了一些测试，就可以运行我们的代码。

与许多（如果不是所有）单元测试框架一样，Mocha 使用断言来确保测试正确运行。如果抛出错误并且没有处理，那么测试被认为是失败的。断言库的作用是在传递意外值时抛出错误，因此这很有效。

Node.js 提供了一个简单的断言模块，让我们来看一下：

```js
[~/examples/example-24]$ node
> assert = require( 'assert' )
> expected = 1
> actual = 1
> assert.equal( actual, expected )
> actual = 1
> assert.equal( actual, expected )
AssertionError: 2 == 1

```

正如我们所看到的，如果断言不通过，就会抛出错误。但是，提供的错误消息并不是很方便；为了解决这个问题，我们也可以传递错误消息：

```js
> assert.equal( actual, expected, 'Expected 1' )
AssertionError: Expected 1

```

有了这个，我们就可以创建一个测试。

Mocha 提供了许多创建测试的方法，这些方法称为*接口*，默认的称为 BDD。

您可以在[`mochajs.org/#interfaces`](http://mochajs.org/#interfaces)上查看所有接口。

**BDD**（行为驱动开发）接口可以与 Gherkin 进行比较，其中我们指定一个功能和一组场景。它提供了帮助定义这些集合的方法，`describe`或`context`用于定义一个功能，`it`或`specify`函数用于定义一个场景。

例如，如果我们有一个函数，用于连接某人的名和姓，测试可能看起来像下面这样：

```js
var GetFullName = require( '../lib/get-full-name' ),
    assert = require( 'assert' );

describe( 'Fetch full name', function( ) {

    it( 'should return both a first and last name', function( ) {
        var result = GetFullName( { first: 'Node', last: 'JS' } )
        assert.equal( result, 'Node JS' );
    })
})
```

我们还可以为此添加一些其他测试；例如，如果没有传递对象，则会引发错误：

```js
it( 'should throw an error when an object was not passed', function( ) {
    assert.throws(
        function( ) {
            GetFullName( null );
        },
        /Object expected/
    )
})
```

您可以在[`mochajs.org/`](http://mochajs.org/)上探索更多 mocha 特定的功能。

# Chai

除了许多测试框架之外，还有许多断言框架，其中之一称为**Chai**。完整的文档可以在[`chaijs.com/`](http://chaijs.com/)找到。

不要使用 Node.js 提供的内置断言模块，我们可能想要使用 Chai 等模块来扩展我们的可能性。

Chai 有三组接口，should，expect 和 assert。在本章中，我们将介绍 expect。

使用 expect 时，您使用自然语言描述您想要的内容；例如，如果您想要某物存在，可以说`expect( x ).to.exist`而不是`assert( !!x )`：

```js
var Expect = require( 'chai' ).expect
var Assert = require( 'assert' )

var value = 1

Expect( value ).to.exist
assert( !!value )
```

使用自然语言使得阅读您的测试变得更加清晰。

这种语言可以链接在一起；我们有`to`，`be`，`been`，`is`，`that`，`which`，`and`，`has`，`have`，`with`，`at`，`of`和`same`，这些可以帮助我们构建句子，比如：

```js
Expect( value ).to.be.ok.and.to.equal( 1 )
```

但是，这些词只是用于可靠性，它们不会修改结果。还有很多其他词可以用来断言事物，比如`not`，`exists`，`ok`等等。您可以在[`chaijs.com/api/bdd/`](http://chaijs.com/api/bdd/)上查看它们。

chai 的一些用法示例包括：

```js
Expect( true ).to.be.ok
Expect( false ).to.not.be.ok
Expect( 1 ).to.exists
Expect( [ ] ).to.be.empty
Expect( 'hi' ).to.equal( 'hi' )
Expect( 4 ).to.be.below( 5 )
Expect( 5 ).to.be.above( 4 )
Expect( function() {} ).to.be.instanceOf( Function )
```

# 存根方法

*如果它看起来像一只鸭子，游泳像一只鸭子，嘎嘎叫像一只鸭子，那么它可能就是一只鸭子*。

在编写测试时，您只想测试代码的“单元”。通常这将是一个方法，为其提供一些输入，并期望得到某种输出，或者如果它是一个`void`函数，则期望不返回任何内容。

有了这个想法，你必须把你的应用程序看作处于沙盒状态，不能与外部世界交流。例如，它可能无法与数据库通信或进行任何外部请求。如果你要（通常应该）实现持续集成和部署，这种假设是很好的。这也意味着在测试的机器上除了 Node.js 和测试框架之外，没有外部要求，这些可能只是你的软件包的一部分。

除非你要测试的方法非常简单，没有任何外部依赖，否则你可能会想要`mock`你知道它将执行的方法。一个很好的模块就是 Sinon.js；它允许你创建`stubs`和`spies`，以确保正确的数据从其他方法返回，并确保它们首先被调用。

`sinon`提供了许多辅助功能，如前所述，其中之一就是**spy**。spy 主要用于包装一个函数，以查看其输入和输出。一旦 spy 被应用到一个函数上，对外界来说，它的行为完全相同。

```js
var Sinon = require( 'sinon' );

var returnOriginal = function( value ) {
    return value;
}

var spy = Sinon.spy( returnOriginal );

result = spy( 1 );
console.log( result ); // Logs 1
```

我们可以使用 spy 来检查函数是否被调用：

```js
assert( spy.called )
```

或者每次调用时传递了什么参数：

```js
assert.equal( spy.args[ 0 ][ 0 ], 1 )
```

如果我们用一个对象和一个要替换的方法提供了`spy`，那么在完成后我们可以恢复原始的方法。我们通常会在测试的`tear down`中这样做：

```js
var object = {
    spyOnMe: function( value ) {
        return value;
    }
}
Sinon.spy( object, 'spyOnMe' )

var result = object.spyOnMe( 1 )
assert( result.called )
assert.equal( result.args[ 0 ][ 0 ], 1 )

object.spyOnMe.restore( )
```

我们还有一个`stub`函数，它继承了`spy`的所有功能，但是完全替换了原始函数，而不是调用它。

这样我们就可以定义行为，例如，它返回什么：

```js
var stub = Sinon.stub( ).returns( 42 )
console.log( stub( ) ) // logs 42
```

我们还可以为一组传递的参数定义返回值：

```js
var stub = Sinon.stub( )
stub.withArgs( 1, 2, 3 ).returns( 42 )
stub.withArgs( 3, 4, 5 ).returns( 43 )

console.log( stub( 1, 2, 3 ) ) // logs 42
console.log( stub( 3, 4, 5 ) ) // logs 43
```

假设我们有这组方法：

```js
function Users( ) {

}
Users.prototype.getUser = function( id ) {
    return Database.findUser( id );
}
Users.prototype.getNameForUser = function( id ) {
    var user = this.getUser( id );
    return user.name;
}
module.exports = Users
```

现在，我们只关心用户被返回的情况，因为如果找不到用户，`getUser`函数将抛出错误。知道这一点，我们只想测试当找到用户时它返回他们的名字。

这是一个完美的例子，我们想要`stub`一个方法的时候：

```js
var Sinon = require( 'sinon' );
var Users = require( '../lib/users' );
var Assert = require( 'assert' );

it( 'should return a users name', function( ) {

    var name = 'NodeJS';
    var user = { name: name };

    var stub = Sinon.stub( ).returns( user );

    var users = new Users( );
    users.getUser = stub;

    var result = users.getNameForUser( 1 );

    assert.equal( result, name, 'Name not returned' );
});
```

我们可以通过作用域传递函数，而不是替换函数，用传递的对象替换 this；两种方式都可以。

```js
var result = users.getNameForUser.call(
    {
        getUser: stub
    },
    1
);
```

# 摘要

我们现在可以轻松创建一个 Node.js 应用所需的一切。测试只是其中一个对于任何成功的软件都是必不可少的事情。我们介绍了使用 mocha 作为测试框架和 chai 作为断言框架。

在下一章中，我们将介绍如何在 Node.js 中使用另一种语言，CoffeeScript！

为 Bentham Chang 准备，Safari ID bentham@gmail.com 用户编号：2843974 © 2015 Safari Books Online，LLC。此下载文件仅供个人使用，并受到服务条款的约束。任何其他用途均需版权所有者的事先书面同意。未经授权的使用、复制和/或分发严格禁止并违反适用法律。保留所有权利。


# 第十章：使用不仅仅是 JavaScript

在整本书中，我们只使用了 JavaScript。嗯，它不就是叫 Node.js 吗？

但这并不意味着我们不能使用其他语言。只要它编译成 JavaScript，我们就可以使用，只要它编译成 JavaScript，我们就可以使用。

这里有一个常见语言的大列表可用：[`github.com/jashkenas/coffeescript/wiki/list-of-languages-that-compile-to-JS`](https://github.com/jashkenas/coffeescript/wiki/list-of-languages-that-compile-to-JS)。

如果您错过了强类型语言，或者只是想要稍微不同的语法，那么肯定会有一个选项适合您。

一些常见的语言包括`CoffeeScript`和`TypeScript`，它们与 Node.js 一起工作得很好，因为它们都编译成 JavaScript。在本章中，我们将介绍`CoffeeScript`的用法。`TypeScript`的用法类似；然而，语法遵循与 C#和 Java 类似的路径。

# CoffeeScript

安装和开始使用其他语言非常简单。让我们来看看 CoffeeScript：

我们需要全局安装 CoffeeScript，这样我们就可以使用类似`node`的命令：

```js
[~] npm install -g coffee-script

```

现在我们可以运行`coffee`：

```js
[~] coffee
>

```

语法与 JavaScript 非常相似：

```js
[~] coffee
> 1 + 1
2
> console.log( 'Hello' )
Hello

```

我们使用`.coffee`而不是`.js`扩展名。

首先，我们将创建一个 CoffeeScript 文件：

```js
/* index.coffee */
console.log( 'Hello CoffeeScript!' )
```

然后要运行它，我们只需要使用`coffee`命令，类似于`node`命令：

```js
[~/examples/example-25] coffee index.coffee
Hello CoffeScript!

```

要将我们的`.coffee`文件编译成`.js`，我们可以使用`-c`。编译后，我们可以直接在 Node.js 中运行它们：

```js
[~/examples/example-25] coffee -c index.coffee
[~/examples/example-25] node index.js
Hello CoffeeScript!

```

如果我们有一堆 CoffeeScript 想要一次性编译成 JavaScript，我们可以使用`coffee -c -o ./lib` .`/src`。这将获取`./src`中的所有`.coffee`文件，将它们编译成`.js`，然后输出到`./lib`。

您需要为其他用户编译所有文件，以便他们可以在他们的 JavaScript 代码旁边使用我们的 CoffeeScript 代码。另一种选择是将 CoffeeScript 作为依赖项并将注册文件`require`到您的应用程序中，如下所示：

```js
/* index.js */
require( 'coffee-script/register' );
require( './other.coffee' );
```

如果您不希望编译您的 CoffeeScript，或者您正在使用需要 JavaScript 文件的工具，如 Gulp 或 Grunt，您可能需要这样做。

### 提示

要查看 JavaScript 和 CoffeeScript 之间的等价物，您可以使用该网站[`js2.coffee/`](http://js2.coffee/)，它提供了一种简单的比较两者的方法。

CoffeeScript 基本上就是 JavaScript；然而，它的目标是可读性和简单性。简单性也意味着它试图限制 JavaScript 的不好的部分，并暴露出好的部分。

对于初学者（和专家）来说，使用 CoffeeScript 通常是很好的，因为它使用英语而不是计算机语言。例如，我们可以使用英语单词`is`而不是`===`（三个等号）来检查两个值是否相等。因此，`x === y`变成了`x is y`，这意味着在阅读时不需要翻译。

除了`is`之外，还有其他关键字，如`isnt`，`not`，`or`，`and`，`yes`和`no`。

使用这些关键字而不是符号操作符可以为读者和程序员提供清晰度。CoffeeScript 的格式与 Python 类似，函数和代码块的声明方式；缩进表示块的结束和开始。

# 代码块和函数

在 JavaScript 中，您通常会使用大括号将块组合在一起，如下例所示：

```js
if ( true ) 
{
  console.log( 'It was true!' ) 
}
```

在 CoffeeScript 中，您将省略所有大括号，实际上所有括号都被省略了：

```js
if true 
  console.log( 'It was true!' )
```

在声明函数时也是如此，注意我们使用的是*箭头*而不是关键字`function`。参数列表只在需要命名参数时才需要：

```js
func = ->
  console.log( 'I executed' )
```

CoffeeScript 尝试尽可能多地假设，同时仍然给程序员足够的控制。

您可能还注意到，当声明函数时，我没有使用`var`关键字。这是因为它是隐式声明的，您可以通过将上述代码编译成 JavaScript 来看到。

```js
var func;
func = function()
{
  return console.log('I executed');
};
```

你可以看到在这个编译后的代码中，函数中的最后一个语句是返回值，这意味着我们不需要声明返回值，只需假设最后一个值被返回。这使得创建单行函数非常简单，例如：

```js
add = ( a, b ) -> a + b 
```

与 JavaScript 不同，你可以为函数提供默认参数，这可以与 C#进行比较；然而，它不仅限于常量，因为它本质上执行函数内的语句：

```js
keys = { }
func = ( key, date = new Date ) ->
  keys[ key ] = date
```

你可以通过编译上面的函数来看到这一点：

```js
var func, keys;
keys = {};
func = function(key, date) 
{
  if (date == null)
  {
    date = new Date();
  }
  return keys[key] = date;
};
```

基本上，CoffeeScript 所做的就是检查值是否为`null`或`undefined`。

# 存在运算符

你可以使用存在运算符来检查一个值是否为`null`或`undefined`，该运算符用于检查值是否*存在*。通过在变量后使用问号符号来表示；如果值存在则语句为真，否则为假。

在表达式中使用这个：

```js
date = null 
if not date?
  date = new Date( )
console.log( date )
```

你也可以将其作为简写运算符使用，例如：

```js
date ?= new Date( )
console.log( date ) 
```

上面两个代码示例的行为完全相同，实际上编译后会得到相同的代码：

```js
var date;
date = null;
if (date == null) 
{
  date = new Date();
}
```

你也可以使用存在运算符来确保在访问其属性之前存在一个值。例如，如果你想从日期中获取时间，或者如果日期不存在则获取`-1`：

```js
getTime = ( date = null ) -> date?.getTime( ) ? -1 
```

给`date`赋予`null`值表明我们不介意是否传递了值：

当一个对象不存在且使用了运算符时，返回的值是`undefined`，这意味着我们可以再次使用相同的运算符来返回一个默认值。

# 对象和数组

除了 CoffeeScript 试图做出的所有假设，它确实试图消除 JavaScript 中所有不必要的语法。另一个例子是在定义数组和对象时，使用新行声明一个新项。例如，通常你会这样定义一个数组：

```js
array = [
  1,
  2,
  3
]
```

这仍然有效；然而，在 CoffeeScript 中你可以省略分隔每个项的逗号：

```js
array = [
  1
  2
  3
]
```

你也可以将这两种风格混合在一起：

```js
array = [
  'a', 'b', 'c'
  1, 2, 3
  true, false
]
```

你也可以对对象做同样的操作，比如：

```js
object = {
  foo: 1
  bar: 2
}
```

对于对象，你甚至可以省略花括号，使用缩进来显示对象中的差异：

```js
object = 
  foo: 1
  bar: 2
  foobar: 
    another: 3
    key: 4
```

在 CoffeeScript 中循环数组，你只需要使用`for…in`循环，例如：

```js
for value, index in array
  console.log( value, index ) 
  continue if typeof value is 'string'
  console.log( 'Value was not a string' )
```

如果你不想使用项目的索引，你可以简单地不要求它：

```js
for value in array
  console.log( value )
```

与 JavaScript 循环一样，你可以使用`break`和`continue`来控制流程。

在 CoffeeScript 中循环对象可以使用`for…of`循环，这与 JavaScript 提供的`for…of`循环有些不同：

```js
for key, value of object 
  console.log( key, value ) 
```

与`for…in`循环一样，如果你不想要值，可以排除它：

```js
for key of object 
  console.log( key )
```

对于两种类型的循环，命名是无关紧要的：

```js
for key, value of object 
    # Note that this will let dates and arrays through ( etc )
    continue unless value instanceof Object 
    for nestedKey, nestedValue of value
      console.log(nestedKey, nestedValue )
```

# 类

与 JavaScript 不同，CoffeeScript 提供了一种自然的方式来声明类和继承。

要在 JavaScript 中定义一个类，你需要先声明一个函数：

```js
function User( username ) {
  this.username = username;
}
```

然后你会声明`prototype`方法：

```js
User.prototype.getUsername = function( ) {
  return this.username;
}
```

如果你有一个`static`方法，你可以在函数上定义它，而不是在原型上：

```js
User.createUser = function( username ) {
  return new User( username );
}
```

在 CoffeeScript 中，你可以使用`class`关键字并给类命名。然后你可以声明构造函数、静态方法和实例（原型）方法：

```js
class User
  @createUser: ( username ) ->
    return new User( username )

  constructor: ( username ) ->
    this.username = username
  getUsername: ->
    return this.username
```

通常，你会将所有的`static`方法放在构造函数上面，这样它们就与实例方法分开了。这避免了混淆，你可能已经注意到我用`@`前缀声明了静态方法`createUser`，这是在 CoffeeScript 中定义静态方法的方式。然而，你也可以使用传统的 JavaScript 方法`User.createUser = ->`，两种方式都可以在这里工作。

当实例被创建或*构造*时运行的代码被称为构造函数。这与许多其他语言使用的术语相同，所以应该很熟悉。构造函数本质上就是一个函数。

所有实例方法的声明方式与对象的属性类似。

随着类的出现，还有另一个符号，即`@`符号。当在实例上使用时，您可以使用它来引用`this`关键字。例如，`getUsername`方法可以编写为：

```js
getUsername: ->
  return @username
```

或者，如果我们想要删除返回语句并将其变成一行：

```js
getUsername: -> @username 
```

`@`符号也可以在参数列表中使用，以声明我们希望将实例属性设置为传递的值。例如，如果我们有一个`setUsername`方法，我们可以这样做：

```js
setUsername: ( username ) ->
  @username = username
```

或者我们可以这样做：

```js
setUsername: ( @username ) ->
```

这两种方法将编译为相同的 JavaScript 代码。

考虑到我们可以在参数列表中使用`@`符号，我们可以重构我们的构造函数为：

```js
constructor: ( @username ) ->
```

使用 CoffeeScript 类的另一个优势是我们可以定义继承。要做到这一点，我们所需要做的就是使用`extends`关键字，这与其他语言类似。

在这些示例中，我们希望有两个*类*，`Person`和`Robot`，它们扩展了基本的`User`类。

对于我们的人，我们希望能够为他们提供一个名字和年龄，以及`User`类所需的用户名。

首先，我们需要声明我们的类：

```js
class Person extends User
```

然后声明我们的`constructor`。在我们的`constructor`中，我们将调用`super`函数，这将执行父类`User`的构造函数，并且我们希望将用户名传递给它，如下所示：

```js
  constructor: ( username, @name, @age ) ->
    super( username )
```

然后我们添加两个方法，`getName`和`getAge`：

```js
  getName: -> @name
  getAge: -> @age
```

接下来，我们将对`Robot`做同样的事情，只是这次我们只需要一个`username`和`@usage`：

```js
class Robot extends User
  constructor: ( username, @usage ) –>
    super( username )
  getUsage: -> @usage 
```

现在我们可以创建我们的类的实例并进行比较，如下所示：

![类](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-ess/img/B04729_10_01.jpg)

# 总结

CoffeeScript 试图对您的代码进行*良好*的假设。这有助于消除 JavaScript 开发人员遇到的一些问题。例如，`==`和`===`之间的区别。

您可以在[`coffeescript.org/`](http://coffeescript.org/)了解有关 CoffeeScript 特定语法的更多信息。

在本章中，我们已经介绍了利用另一种语言。这可以帮助初学者减轻对 JavaScript 风格或语法的困扰。对于习惯于更多语言特性的人来说，这是一个很大的优势，因为它有助于消除人们通常遇到的陷阱。

为 Bentham Chang 准备，Safari ID 为 bentham@gmail.com 用户编号：2843974 © 2015 Safari Books Online，LLC。此下载文件仅供个人使用，并受到服务条款的约束。任何其他用途均需版权所有者的事先书面同意。未经授权的使用、复制和/或分发严格禁止并违反适用法律。保留所有权利。
