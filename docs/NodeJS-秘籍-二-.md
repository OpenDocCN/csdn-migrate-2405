# NodeJS 秘籍（二）

> 原文：[`zh.annas-archive.org/md5/B8CF3F6C144C7F09982676822001945F`](https://zh.annas-archive.org/md5/B8CF3F6C144C7F09982676822001945F)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：与数据库交互

在本章中，我们将涵盖：

+   写入 CSV 文件

+   连接并向 MySQL 服务器发送 SQL

+   使用 MongoDB 存储和检索数据

+   使用 Mongoskin 存储和检索数据

+   使用 Cradle 将数据存储到 CouchDB

+   使用 Cradle 从 CouchDB 检索数据

+   使用 Cradle 访问 CouchDB 更改流

+   使用 Redis 存储和检索数据

+   使用 Redis 实现 PubSub

# 介绍

随着我们代码的复杂性和目标的要求增加，我们很快意识到需要一个地方来存储我们的数据。

然后我们必须问一个问题：存储我们的数据的最佳方式是什么？答案取决于我们正在处理的数据类型，因为不同的挑战需要不同的解决方案。

如果我们正在做一些非常简单的事情，我们可以将我们的数据保存为一个平面的 CSV 文件，这样做的好处是使用户能够在电子表格应用程序中查看 CSV 文件。

如果我们处理的是具有明显关系特性的数据，例如会计数据，其中交易的两个方面之间存在明显的关系，那么我们会选择关系数据库，比如流行的 MySQL。

在许多情况下，关系数据库成为了几乎所有数据场景的事实标准。这导致了对本来松散相关的数据（例如网站内容）施加关系的必要性，试图将其挤入我们的关系心理模型中。

然而，近年来，人们已经开始从关系数据库转向 NoSQL，一种非关系范式。推动力是我们要根据数据最适合我们的技术，而不是试图将我们的数据适应我们的技术。

在本章中，我们将探讨各种数据存储技术，并举例说明它们在 Node 中的使用。

# 写入 CSV 文件

平面文件结构是最基本的数据库模型之一。列可以是固定长度，也可以使用分隔符。逗号分隔值（CSV）约定符合分隔的平面文件结构数据库的概念。虽然它被称为 CSV，但 CSV 这个术语也被广泛应用于任何基本的分隔结构，每行一个记录（例如，制表符分隔的值）。

我们可以通过使用多维数组和`join`方法来遵循一个脆弱的方法来构建 CSV 结构：

```js
var data = [['a','b','c','d','e','f','g'], ['h','i','j','k','l','m','n']];
var csv = data.join("\r\n");  /* renders:  a,b,c,d,e,f,g 
                                                             h,i,j,k,l,m,n   */

```

然而，这种技术的局限性很快变得明显。如果我们的字段中包含逗号怎么办？现在一个字段变成了两个，从而破坏了我们的数据。此外，我们只能使用逗号作为分隔符。

在这个示例中，我们将使用第三方的`ya-csv`模块以 CSV 格式存储数据。

## 准备工作

让我们创建一个名为`write_to_csv.js`的文件，我们还需要检索`ya-csv`。

```js
npm install ya-csv 

```

## 如何做...

我们需要`ya-csv`模块，调用它的`createCsvFileWriter`方法来实例化一个 CSV 文件写入器，并循环遍历我们的数组，调用 CSV 文件写入器的`writeRecord`方法：

```js
var csv = require('ya-csv'); 
var writer = csv.createCsvFileWriter('data.csv'); 

var data = [['a','b','c','d','e','f','g'], ['h','i','j','k','l','m','n']]; 

data.forEach(function(rec) { 
  writer.writeRecord(rec); 
});

```

让我们来看看我们保存的文件，`data.csv:`

```js
"a","b","c","d","e","f","g"
"h","i","j","k","l","m","n"

```

## 它是如何工作的...

写入和读取 CSV 文件的困难之处在于边缘情况，比如嵌入在文本中的逗号或引号。`ya-csv`为我们处理了这些边缘情况。

我们使用`createCsvFileWriter`将`ya-csv`的`CsvWriter`的实例加载到`writer`变量中。

然后我们简单地循环遍历每个数组作为`rec`，将其传递给`ya-csv`的`CsvWriter`的`writeRecord`方法。在幕后，它会重新构造每个数组并将其传递给`fs.WriteStream`的实例。

这个示例取决于我们在代码中使用基本的数据结构。多维对象必须被转换成正确的格式，因为`writeRecord`只能处理数组。

## 还有更多...

我们能否轻松地自己创建这个功能？毫无疑问。然而，`ya-csv`为我们提供了一个 API，可以无缝地定制我们的 CSV 文件的元素，并实现更复杂的 CSV 解析功能。

### 自定义 CSV 元素

如果我们将我们的配方文件保存为 `write_to_custom_csv.js`，并将一个 `options` 对象传递给 `createCsvFileWriter`，我们可以改变我们的 CSV 文件构造方式：

```js
var writer = csv.createCsvFileWriter('custom_data.csv', { 
    'separator': '~', 
    'quote': '|', 
    'escape': '|' 
});

```

注意 `escape` 选项。这将设置防止意外关闭 CSV 字段的字符。让我们将其插入到我们的数组中，看看 `ya-csv` 如何处理它：

```js
var data = [['a','b','c','d','e|','f','g'], ['h','i','j','k','l','m','n']];

```

运行我们的新代码后，让我们看看 `custom_data.csv`：

```js
|a|~|b|~|c|~|d|~|e|||~|f|~|g|
|h|~|i|~|j|~|k|~|l|~|m|~|n|

```

看看我们在 `e` 字段中的管道字符后面添加了另一个管道以进行转义。

### 读取 CSV 文件

我们还可以使用 `ya-csv` 从 CSV 文件中读取，其内置解析器将每个 CSV 记录转换回数组。让我们制作 `read_from_csv.js`。

```js
var csv = require('ya-csv'); 
var reader = csv.createCsvFileReader('data.csv'); 
var data = []; 

reader.on('data', function(rec) { 
  data.push(rec); 
}).on('end', function() { 
  console.log(data); 
}); 

```

如果我们希望解析替代分隔符和引号，我们只需将它们传递到 `createCsvFileReader` 的 `options` 对象中：

```js
var reader = csv.createCsvFileReader('custom_data.csv', { 
    'separator': '~', 
    'quote': '|', 
    'escape': '|' 
});

```

### 操作 CSV 作为流

`ya-csv` 与 CSV 文件交互作为流。这可以减少操作内存，因为流允许我们在加载时处理小块信息，而不是首先将整个文件缓冲到内存中。

```js
var csv = require('ya-csv'); 
var http = require('http'); 

http.createServer(function (request, response) { 
     response.write('['); 
      csv.createCsvFileReader('big_data.csv') 
      .on('data', function(data) { 
        response.write(((this.parsingStatus.rows > 0) ? ',' : '') + JSON.stringify(data)); 
      }).on('end', function() { 
        response.end(']'); 
      }); 
}).listen(8080);

```

## 参见

+   *在本章中讨论了连接并向 MySQL 服务器发送 SQL*

+   *在本章中讨论了使用 Mongoskin 存储和检索数据*

+   *使用 Cradle 将数据存储到 CouchDB* 在本章中讨论

+   *在本章中讨论了使用 Redis 存储和检索数据*

# 连接并向 MySQL 服务器发送 SQL

自 1986 年以来，结构化查询语言一直是标准，也是关系数据库的主要语言。MySQL 是最流行的 SQL 关系数据库服务器，经常出现在流行的 LAMP（Linux Apache MySQL PHP）堆栈中。

如果关系数据库在新项目的目标中概念上相关，或者我们正在将基于 MySQL 的项目从另一个框架迁移到 Node，第三方 `mysql` 模块将特别有用。

在这个任务中，我们将发现如何使用 Node 连接到 MySQL 服务器并在网络上执行 SQL 查询。

## 准备工作

让我们获取 `mysql`，这是一个纯 JavaScript（而不是 C++ 绑定）的 MySQL 客户端模块。

```js
npm install mysql 

```

我们需要一个 MySQL 服务器进行连接。默认情况下，`mysql` 客户端模块连接到 `localhost`，因此我们将在本地运行 MySQL。

在 Linux 和 Mac OSX 上，我们可以使用以下命令查看 MySQL 是否已安装：

```js
whereis mysql 

```

我们可以使用以下命令查看它是否正在运行：

```js
ps -ef | grep mysqld 

```

如果已安装但未运行，我们可以执行：

```js
sudo service mysql start 

```

如果 MySQL 没有安装，我们可以使用系统的相关软件包管理器（homebrew、apt-get/synaptic、yum 等），或者如果我们在 Windows 上使用 Node，我们可以前往 [`dev.mysql.com/downloads/mysql`](http://dev.mysql.com/downloads/mysql) 并下载安装程序。

一旦我们准备好，让我们创建一个文件并将其命名为 `mysql.js`。

## 如何做...

首先，我们需要第三方的 `mysql` 驱动程序，并创建与服务器的连接：

```js
var mysql = require('mysql'); 
var client = mysql.createClient({ 
  user: 'root', 
  password: 'OURPASSWORD' ,
//debug: true
});

```

我们需要连接的数据库。让我们保持有趣，创建一个 `quotes` 数据库。我们可以通过将 SQL 传递给 `query` 方法来实现：

```js
client.query('CREATE DATABASE quotes');
client.useDatabase('quotes');

```

我们还调用了 `useDatabase` 方法来连接到数据库，尽管我们可以通过 `client.query('USE quotes')` 实现相同的效果。现在我们将创建一个同名的表。

```js
client.query('CREATE TABLE quotes.quotes (' + 
             'id INT NOT NULL AUTO_INCREMENT, ' + 
             'author VARCHAR( 128 ) NOT NULL, ' + 
             'quote TEXT NOT NULL, PRIMARY KEY (  id )' + 
             ')');

```

如果我们运行我们的代码超过一次，我们会注意到一个未处理的错误被抛出，程序失败。这是因为 `mysql` 驱动程序发出了一个错误事件，反映了 MySQL 服务器的错误。它抛出了一个未处理的错误，因为 `quotes` 数据库（和表）无法创建，因为它们已经存在。

我们希望我们的代码足够灵活，可以在必要时创建数据库，但如果不存在则不会抛出错误。为此，我们将捕获客户端实例发出的任何错误，过滤掉数据库/表存在的错误：

```js
var ignore = [mysql.ERROR_DB_CREATE_EXISTS, 
                      mysql.ERROR_TABLE_EXISTS_ERROR]; 

client.on('error', function (err) { 
  if (ignore.indexOf(err.number) > -1) { return; } 
  throw err; 
}); 

```

我们将在`client.query`方法调用之前放置我们的错误捕获器。最后，在我们的代码末尾，我们将向表中插入我们的第一条引用，并发送一个`COM_QUIT`数据包（使用`client.end`）到 MySQL 服务器。这将只在所有排队的 SQL 被执行后关闭连接。

```js
client.query('INSERT INTO  quotes.quotes (' + 
              'author, quote) ' + 
             'VALUES ("Bjarne Stroustrup", "Proof by analogy is fraud.");');

client.end();

```

## 它是如何工作的...

`createClient`方法建立与服务器的连接，并为我们返回一个客户端实例以便与之交互。我们可以将其作为一个`options`对象传递，该对象可能包含`host, port, user, password, database, flags`和`debug`。除了`user`和`password`之外，对于我们的目的来说，默认选项都是可以的。如果我们取消注释`debug`，我们可以看到被发送到服务器和从服务器接收的原始数据。

`client.query`将 SQL 发送到我们的数据库，然后由 MySQL 服务器执行。使用它，我们`CREATE`一个名为`quotes`的`DATABASE`，还有一个名为`quotes`的`TABLE`。然后我们将我们的第一条记录（C++的发明者的引用）插入到我们的数据库中。

`client.query`将每个传递给它的 SQL 语句排队，与我们的其他代码异步执行语句，但在 SQL 语句队列中是顺序执行的。当我们调用`client.end`时，连接关闭任务将被添加到队列的末尾。如果我们想要忽略语句队列，并立即结束连接，我们将使用`client.destroy`。

我们的`ignore`数组包含两个数字，`1007`和`1050 — 我们从`mysql`对象中获取这些数字，该对象包含 MySQL 错误代码。我们希望忽略 MySQL 在表或数据库已经存在时发生的错误，否则我们只能运行`mysql.js`一次。第一次运行后，它会崩溃，因为数据库和表已经存在。忽略这些代码意味着我们可以隐式地设置我们的数据库，并且只有一个文件，而不是一个用于设置和一个用于插入代码的单独的应用程序。

在`error`事件监听器中，我们检查`err.number`是否在我们的`ignore`数组中。如果是，我们简单地`return`，从而忽略错误并优雅地继续执行。如果错误是其他性质的，我们将继续执行抛出错误的通常行为。

## 还有更多...

我们不仅将数据发送到 MySQL，还会检索数据。此外，SQL 查询通常是从用户输入生成的，但如果不采取预防措施，这可能会被利用。

### 使用和清理用户输入

与其他使用字符串连接构建 SQL 语句的语言一样，我们必须防止 SQL 注入攻击的可能性，以保持服务器的安全。基本上，我们必须清理（即转义）任何用户输入，以消除不需要的 SQL 操纵的可能性。

我们将复制`mysql.js`并将其命名为`insert_quotes.js`。为了以简单的方式实现用户输入的概念，我们将从命令行中提取参数，但是数据清理的原则和方法适用于任何输入方法（例如，通过请求的查询字符串）。

我们的基本 API 将是这样的：

```js
node quotes.js "Author Name" "Quote Text Here" 

```

引号是将命令行参数分隔的必要条件，但为了简洁起见，我们不会实现任何验证检查。

### 提示

**命令行解析模块：optimist**

对于更高级的命令行功能，请查看优秀的`optimist`模块，网址为[`www.github.com/substack/node-optimist`](https://www.github.com/substack/node-optimist)。

为了接收作者和引用，我们将两个引用参数加载到一个新的`params`对象中。

```js
var params = {author: process.argv[2], quote: process.argv[3]};

```

我们的第一个参数在`process.argv`数组中是`2`，因为`0`和`1`分别是`node`和`quotes.js`。

现在让我们稍微修改我们的`INSERT`语句：

```js
if (params.author && params.quote) {             
  client.query('INSERT INTO  quotes.quotes (' + 
                'author, quote) ' + 
                'VALUES (?, ?);', [ params.author, params.quote ]); 
}
client.end(); 

```

我们将这个放在主要的`client.end`调用之前。`mysql`模块可以无缝地为我们清理用户输入。我们只需使用问号（？）作为占位符，然后将我们的值（按顺序）作为数组传递到`client.query`的第二个参数中。

### 从 MySQL 服务器接收结果

让我们通过输出所有作者的引用来进一步扩展`insert_quotes.js`，无论是否提供了引用。我们将`insert_quotes.js`简单保存为`quotes.js`。

在我们的`INSERT`查询下面，但在最终的`client.end`之上，我们将添加以下代码：

```js
if (params.author) { 
  client.query('SELECT *  FROM quotes WHERE ' + 
    'author LIKE ' + client.escape(params.author)) 
    .on('row', function (rec) { 
      console.log('%s: %s \n', rec.author, rec.quote); 
    }); 
}
client.end();

```

在这种情况下，我们使用了另一种方法来清理用户输入，即`client.escape`。这与前一种方法的效果完全相同，但只转义单个输入。通常，如果有多个变量，前一种方法更可取。

可以通过传递回调函数或监听`row`事件来访问`SELECT`语句的结果。`row`事件监听器允许我们逐行与 MySQL 服务器数据流交互。

我们可以安全地调用`client.end`，而不必将其放在我们的`SELECT`查询的`end`事件中，因为`client.end`只有在所有查询完成时才会终止连接。

## 另请参阅

+   *在本章中讨论的使用 MongoDB 存储和检索数据*

+   *在本章中讨论的使用 Redis 存储和检索数据*

# 使用 MongoDB 存储和检索数据

MongoDB 是一种 NoSQL 数据库提供，坚持性能优于功能的理念。它专为速度和可扩展性而设计。它实现了一个基于文档的模型，不需要模式（列定义），而不是关系工作。文档模型适用于数据之间关系灵活且最小潜在数据丢失是速度增强的可接受成本的情况（例如博客）。

虽然它属于 NoSQL 家族，但 MongoDB 试图处于两个世界之间，提供类似 SQL 的语法，但以非关系方式运行。

在这个任务中，我们将实现与之前的配方相同的`quotes`数据库，但使用 MongoDB 而不是 MySQL。

## 准备工作

我们将要在本地运行一个 MongoDB 服务器。可以从[`www.mongodb.org/downloads`](http://www.mongodb.org/downloads)下载。

让我们以默认的调试模式启动 MongoDB 服务`mongod`：

```js
mongod --dbpath [a folder for the database] 

```

这使我们能够观察`mongod`与我们的代码交互的活动，如果我们想要将其作为持久后台服务启动，我们将使用。

```js
mongod --fork --logpath [p] --logappend dbpath [p] 

```

其中`[p]`是我们想要的路径。

### 提示

有关启动和正确停止`mongod`的更多信息，请访问[`www.mongodb.org/display/DOCS/Starting+and+Stopping+Mongo`](http://www.mongodb.org/display/DOCS/Starting+and+Stopping+Mongo)。

要从 Node 与 MongoDB 交互，我们需要安装`mongodb`本机绑定驱动程序模块。

```js
npm install mongodb 

```

我们还将为基于 MongoDB 的项目创建一个新文件夹，其中包含一个新的`quotes.js`文件。

## 操作步骤...

我们必须要求`mongodb`驱动程序，启动一个 MongoDB 服务器实例，并创建一个客户端，加载引用数据库并连接到 MongoDB 服务器。

```js
var mongo = require('mongodb'); 
var server = new mongo.Server("localhost", 27017); 
var client = new mongo.Db('quotes', server);

var params = {author: process.argv[2], quote: process.argv[3]};

```

请注意，我们还插入了我们的`params`对象，以从命令行读取用户输入。

现在我们打开到我们的`quotes`数据库的连接，并加载（或创建如果需要）我们的`quotes`集合（在 SQL 中，表将是最接近的类似概念）。

```js
client.open(function (err, client) { 
  if (err) { throw err; } 
  var collection = new mongo.Collection(client, 'quotes');
  client.close();
});

```

接下来，我们将根据用户定义的作者和引用插入一个新文档（在 SQL 术语中，这将是一条记录）。

我们还将在控制台上输出指定作者的任何引用。

```js
client.open(function (err, client) { 
  if (err) { throw err; } 

  var collection = new mongo.Collection(client, 'quotes'); 

  if (params.author && params.quote) { 
    collection.insert({author: params.author, quote: params.quote}); 
  }

 if (params.author) { 

    collection.find({author: params.author}).each(function (err, doc) { 
      if (err) { throw err; } 
      if (doc) { console.log('%s: %s \n', doc.author, doc.quote); return; } 
      client.close(); 
    }); 

    return; 
  }

client.close();

});

```

我们可以在以下截图中看到我们基于 MongoDB 的引用应用程序的运行情况：

![操作步骤...](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-cb/img/7188-04-01.jpg)

## 工作原理...

当我们创建一个新的`mongo.Db`实例时，我们将数据库的名称作为第一个参数传递进去。如果数据库不存在，MongoDB 会智能地创建这个数据库。

我们使用`Db`实例的`open`方法，我们将其命名为`client`，以打开与数据库的连接。一旦连接建立，我们的回调函数就会被执行，我们可以通过`client`参数与数据库进行交互。

我们首先创建一个`Collection`实例。`Collection`类似于 SQL 表，它包含了所有我们的数据库字段。但是，与字段值按列分组不同，集合包含多个文档（类似记录），其中每个字段都包含字段名和其值（文档非常类似于 JavaScript 对象）。

如果`quote`和`author`都被定义了，我们就调用我们的`Collection`实例的`insert`方法，传入一个对象作为我们的文档。

最后，我们使用`find`，它类似于`SELECT` SQL 命令，传入一个指定作者字段和所需值的对象。`mongodb`驱动程序提供了一个方便的方法（each），可以与`find`方法链接。`each`执行传递给它的回调，对于每个找到的文档都会执行。`each`的最后一个循环将`doc`作为`null`传递，这方便地表示 MongoDB 已经返回了所有记录。

只要`doc`是真实的，我们就传递每个找到的`doc`的`author`和`quote`属性。一旦`doc`是`null`，我们允许解释器通过不从回调中提前返回来发现回调的最后部分，`client.close`。

在`client.open`回调的最后，第二个也是最后一个`client.close`只有在没有通过命令行定义参数时才会被调用。

## 还有更多...

让我们看看一些其他有用的 MongoDB 功能。

### 索引和聚合

索引会导致 MongoDB 从所选字段创建一个值列表。索引字段可以加快查询速度，因为可以使用更小的数据集来交叉引用和从更大的数据集中提取数据。我们可以将索引应用到作者字段，并看到性能的提升，特别是当我们的数据增长时。此外，MongoDB 有各种命令允许我们对数据进行聚合。我们可以分组、计数和返回不同的值。

### 注意

对于更高级的需求或更大的数据集，map/reduce 函数可以进行聚合。CouchDB 也使用 map/reduce 来生成视图（存储的查询），参见*使用 Cradle 从 CouchDB 检索数据*。

让我们创建并输出在我们的数据库中找到的作者列表，并将我们的代码保存到一个名为`authors.js`的文件中。

```js
var mongo = require('mongodb'); 
var server = new mongo.Server("localhost", 27017); 
var client = new mongo.Db('quotes', server); 

client.open(function (err, client) { 
  if (err) { throw err; } 
  var collection = new mongo.Collection(client, 'quotes');  
  collection.ensureIndex('author', {safe: true}, function (err) { 
    if (err) { throw err; } 
    collection.distinct('author', function (err, result) { 
        if (err) { throw err; } 
        console.log(result.join('\n')); 
        client.close(); 
      });  
    }); 

});

```

通常情况下，我们打开了与我们的`quotes`数据库的连接，获取了我们的`quotes`集合。使用`ensureIndex`只有在索引不存在时才会创建一个索引。我们传入`safe:true`，这样 MongoDB 会返回任何错误，并且我们的回调函数可以正常工作。在回调函数中，我们在我们的`collection`上调用`distinct`方法，传入`author`。结果作为数组传递，我们使用换行符将数组`join`成一个字符串并输出到控制台。

### 更新修改器、排序和限制

我们可以让一个假设的用户指示他们是否受到引用的启发（例如**Like**按钮），然后我们可以使用`sort`和`limit`命令来输出前十个最具启发性的引用。

实际上，这将通过某种用户界面来实现（例如，在浏览器中），但我们将再次使用命令行来模拟用户交互；让我们创建一个名为`quotes_votes.js`的新文件。

首先，为了对引用进行投票，我们需要引用它，这可以通过唯一的`_id`属性完成。因此在`quotes_votes.js`中，让我们写：

```js
var mongo = require('mongodb'); 
var server = new mongo.Server("localhost", 27017); 
var client = new mongo.Db('quotes', server); 
var params = {id: process.argv[2], voter: process.argv[3]}; 
client.open(function (err, client) { 
  if (err) { throw err; } 
  var collection = new mongo.Collection(client, 'quotes');  

//vote handling to go here

 collection.find().each(function (err, doc) { 
      if (err) { throw err; } 
      if (doc) { console.log(doc._id, doc.quote); return; } 
      client.close(); 
    }); 
});

```

现在当我们用`node`运行`quotes_votes.js`时，我们将看到一个 ID 和引用列表。要为引用投票，我们只需复制一个 ID 并将其用作我们的命令行参数。因此，让我们按照以下代码所示进行投票处理：

```js
  if (params.id) { 
    collection.update({_id : new mongo.ObjectID(params.id)}, 
      {$inc: {votes: 1}}, {safe: true}
      function (err) { 
        if (err) { throw err; } 

        collection.find().sort({votes: -1}).limit(10).each(function (err, doc) { 
          if (err) { throw err; } 
          if (doc) { 
            var votes = (doc.votes) || 0; 
            console.log(doc.author, doc.quote, votes); 
            return; 
          } 
          client.close(); 
        }); 
      }); 
    return; 
  }

```

MongoDB 的 ID 必须编码为 BSON（二进制 JSON）ObjectID。否则，`update`命令将查找`param.id`作为字符串，找不到它。因此，我们创建一个`new mongo.ObjectID(param.id)`来将`param.id`从 JavaScript 字符串转换为 BSON ObjectID。

`$inc` 是一个 MongoDB 修饰符，在 MongoDB 服务器内执行递增操作，从根本上允许我们外包计算。要使用它，我们传递一个文档（对象），其中包含要递增的键和要增加的数量。所以我们传递 `votes` 和 `1`。

`$inc` 如果不存在将创建 `votes` 字段，并将其递增一（我们也可以使用负数递减）。接下来是要传递给 MongoDB 的选项。我们将 `safe` 设置为 `true`，这告诉 MongoDB 检查命令是否成功，并在失败时发送任何错误。为了使回调正确工作，必须传递 `safe:true`，否则错误不会被捕获，回调会立即发生。

### 提示

**Upserting**

我们可以设置的另一个有用的选项是 `upsert:true`。这是 MongoDB 的一个非常方便的功能，可以更新记录，如果记录不存在则插入。

在 `update` 回调中，我们运行一系列 `find.sort.limit.each. find`，不带任何参数，这将返回所有记录。`sort` 需要键和一个正数或负数 `1`，表示升序或降序。`limit` 接受一个最大记录数的整数，`each` 循环遍历我们的记录。在 `each` 回调中，我们输出 `doc` 的每个 `author, quote` 和 `votes`，当没有剩余的 `docs` 时关闭连接。

## 另请参阅

+   *连接并向 MySQL 服务器发送 SQL* 在本章中讨论

+   *使用 Mongoskin 存储和检索数据* 在本章中讨论

+   *使用 Cradle 将数据存储到 CouchDB* 在本章中讨论

# 使用 Mongoskin 存储和检索数据

Mongoskin 是一个方便的库，提供了一个高级接口，用于在不阻塞现有 `mongodb` 方法的情况下与 `mongodb` 进行交互。

对于这个示例，我们将使用 Mongoskin 在 MongoDB 中重新实现 `quotes` 数据库。

## 准备工作

我们需要 `mongoskin` 模块。

```js
npm install mongoskin 

```

我们还可以创建一个新的文件夹，带有一个新的 `quotes.js` 文件。

## 如何做...

我们将需要 `mongoskin` 并使用它来创建一个 `client` 和一个 `collection` 实例。我们不需要创建一个 `server` 实例，也不需要像前一个示例中那样手动打开客户端，`mongoskin` 会处理这一切。

```js
var mongo = require('mongoskin');
var client = mongo.db('localhost:27017/quotes');
var collection = client.collection('quotes');
var params = {author: process.argv[2], quote: process.argv[3]};

```

与前一个示例一样，我们已经为用户输入定义了我们的 `params` 对象。

`mongoskin` 不需要我们使用 JavaScript 可能出现错误的 `new` 关键字，它提供了一个构建器方法（`mongo.db`），允许我们使用熟悉的 URI 模式定义我们的主机、端口和数据库名称。

### 提示

有关为什么 `new` 前缀可能被认为是错误的，请参阅 [` www. yuiblog.com/blog/2006/11/13/javascript-we-hardly-new-ya/`](http:// www. yuiblog.com/blog/2006/11/13/javascript-we-hardly-new-ya/)。 

由于我们不需要手动 `open` 我们的 `client（mongoskin` 会为我们打开它），所以我们可以直接实现我们的 `insert` 和 `find` 操作：

```js
if (params.author && params.quote) { 
  collection.insert({author: params.author, quote: params.quote}); 
} 
if (params.author) { 
  collection.findEach({}, function (err, doc) { 
    if (err) { throw err; } 
    if (doc) { console.log('%s: %s \n', doc.author, doc.quote); return; } 
    client.close(); 
  }); 
  return; 
} 
client.close();

```

然后我们就完成了。

## 它是如何工作的...

我们使用 Mongoskin 的 `db` 方法透明地连接到我们的数据库，并立即能够获取我们的集合。

与之前的示例一样，我们检查 `author` 和 `quote` 命令行参数，然后调用 `mongodb insert` 方法，该方法通过 `mongoskin` 模块本身就可用。

在检查作者之后，我们使用 `mongoskin` 的 `findEach` 方法。`findEach` 方法包装了前一个示例中使用的 `collection.find.each`。

在 `findEach` 中，我们将每个 `doc` 的 `author` 和 `quote` 属性输出到控制台。当没有文档剩下时，我们明确地 `close` 了 `client` 连接。

## 还有更多...

Mongoskin 在使我们的生活更轻松方面做得非常出色。让我们看看另一个简化与 MongoDB 交互的 Mongoskin 功能。

### 集合绑定

Mongoskin 提供了一个 `bind` 方法，使集合作为 `client` 对象的属性可用。所以如果我们这样做：

```js
client.bind('quotes');

```

我们可以通过 `client.quotes` 访问引用集合。

这意味着我们可以丢弃`collection`变量并改用绑定。`bind`方法还接受一个方法对象，然后应用于绑定的集合。例如，如果我们定义了一个名为`store`的方法，我们将按以下方式访问它：

```js
client.quotes.store(params.author, params.quote);

```

因此，让我们创建一个名为`quotes_bind.js`的新文件，以使用集合绑定方法重新实现 Mongoskin 中的`quotes.js`。

我们将从我们的顶级变量开始：

```js
var mongo = require('mongoskin');
var client = mongo.db('localhost:27017/quotes');
var params = {author: process.argv[2], quote: process.argv[3]};

```

由于我们将通过`bind`访问我们的集合，因此我们不需要`collection`变量。

现在让我们为插入定义一个`store`方法和一个用于显示引用的`show`方法：

```js
client.bind('quotes', { 
  store: function (author, quote) { 
    if (quote) { this.insert({author: author, quote: quote}); } 
  }, 
  show: function (author, cb) { 
    this.findEach({author: author}, function (err, doc) { 
      if (err) { throw err; } 
      if (doc) { console.log('%s: %s \n', doc.author, doc.quote); return; } 
      cb(); 
    }); 
  } 
});

```

然后我们的逻辑与我们的新绑定方法进行交互：

```js
client.quotes.store(params.author, params.quote); 

if (params.author) { 
  client.quotes.show(params.author, function () { 
    client.close(); 
  }); 
  return; 
} 

client.close();

```

Mongoskin 的`bind`方法将复杂的数据库操作无缝地抽象成易于使用的点符号格式。

### 注意

我们将一些`params`检查功能嵌入到我们的`store`方法中，只有在引用存在时才调用`insert`。在我们所有的示例中，我们只需要检查第二个参数（`params.quote`），我们不能有`params.quote`而没有`params.author`。在之前的示例中，这两个参数都进行了检查，以演示在其他情况下它可能如何工作（例如，如果我们通过 POST 请求接收到我们的参数）。

## 另请参阅

+   *在本章中讨论了使用 MongoDB 存储和检索数据*

+   *在本章中讨论了使用 Cradle 将数据存储到 CouchDB*

+   *在本章中讨论了使用 Cradle 从 CouchDB 检索数据*

# 使用 Cradle 将数据存储到 CouchDB

为了实现出色的性能速度，MongoDB 对 ACID（原子性一致性隔离持久性）合规性有一定的放松。然而，这意味着数据可能会变得损坏的可能性（尤其是在操作中断的情况下）。另一方面，CouchDB 在复制和同步时是符合 ACID 的，数据最终变得一致。因此，虽然比 MongoDB 慢，但它具有更高的可靠性优势。

CouchDB 完全通过 HTTP REST 调用进行管理，因此我们可以使用`http.request`来完成与 CouchDB 的所有工作。尽管如此，我们可以使用 Cradle 以一种简单、高级的方式与 CouchDB 进行交互，同时还可以获得自动缓存的速度增强。

在这个示例中，我们将使用 Cradle 将著名的引用存储到 CouchDB 中。

## 准备工作

我们需要安装和运行 CouchDB，可以前往[`wiki.apache.org/couchdb/Installation`](http://wiki.apache.org/couchdb/Installation)获取有关如何在特定操作系统上安装的说明。

安装完成后，我们可以检查 CouchDB 是否正在运行，并通过将浏览器指向[`localhost:5984/_utils`](http://localhost:5984/_utils)来访问 Futon 管理面板。

我们还需要`cradle`模块。

```js
npm install cradle@0.6.3 

```

然后我们可以在其中创建一个新的`quotes.js`文件的新文件夹。

## 如何做...

首先，我们需要`cradle`并加载我们的引用数据库，如果需要的话创建它。我们还将定义一个错误处理函数和我们的`params`对象，以便轻松进行命令行交互：

```js
var cradle = require('cradle'); 
var db = new(cradle.Connection)().database('quotes'); 
var params = {author: process.argv[2], quote: process.argv[3]};
function errorHandler(err) { 
  if (err) { console.log(err); process.exit(); } 
//checkAndSave function here

```

在我们可以写入数据库之前，我们需要知道它是否存在：

```js
db.exists(function (err, exists) { 
  errorHandler(err); 
  if (!exists) { db.create(checkAndSave); return; } 
  checkAndSave(); 
});

```

请注意，我们将`checkAndSave`作为`db.create`的回调传入，以下函数位于`db.exists`调用之上：

```js
function checkAndSave(err) { 
  errorHandler(err); 

  if (params.author && params.quote) { 
    db.save({author: params.author, quote: params.quote}, errorHandler); 

  } 

} 

```

我们在`checkAndSave`中处理的`err`参数将从`db.create`中传入。

## 工作原理...

CouchDB 通过 HTTP 请求进行管理，但 Cradle 提供了一个接口来进行这些请求。当我们调用`db.exists`时，Cradle 会向`http://localhost:5984/quotes`发送一个 HEAD 请求，并检查回复状态是否为`404 Not Found`或`200 OK`。我们可以使用命令行程序的`curl`和`grep`执行相同的检查，如下所示：

```js
curl -Is http://localhost:5984/quotes | grep -c "200 OK" 

```

如果数据库存在，则会输出`1`，如果不存在，则会输出`0`。如果我们的数据库不存在，我们调用`cradle`的`db.create`方法，该方法会向 CouchDB 服务器发送一个 HTTP PUT 请求。在`curl`中，这将是：

```js
curl -X PUT http://localhost:5984/quote 

```

我们将我们的`checkAndSave`函数作为`db.create`的回调传入，或者如果数据库存在，我们将它从`db.exists`的回调中调用。这是必要的。我们不能将数据保存到不存在的数据库中，我们必须等待 HTTP 响应，然后才知道它是否存在（或者是否已创建）。

`checkAndSave`查找命令行参数，然后相应地保存数据。例如，如果我们从命令行运行以下命令：

```js
node quotes.js "Albert Einstein" "Never lose a holy curiosity." 

```

`checkAndSave`会意识到有两个参数传递给`author`和`quote`，然后将它们传递给`db.save`。Cradle 然后会 POST 以下内容，`Content-Type`设置为`application/json:`

```js
{"author": "Albert Einstein", "quote": "Never lose a holy curiosity"}

```

除此之外，Cradle 还添加了一个缓存层，在我们的示例中几乎没有用处，因为缓存数据在应用程序退出时会丢失。然而，在服务器实现中，缓存将在快速高效地响应类似请求时变得非常有用。

## 还有更多...

Couch 代表**Cluster Of Unreliable Commodity Hardware**，让我们简要看一下 CouchDB 的集群方面。

### 使用 BigCouch 扩展 CouchDB

扩展是关于使您的应用程序对预期需求做出响应的，但不同的项目具有不同的特点。因此，每个扩展项目都需要个性化的方法。

如果一个 Web 服务主要建立在数据库交互上，那么在响应服务需求变化时，扩展数据库层将成为一个优先考虑的问题。扩展 CouchDB（或其他任何东西）可能是一个非常深入的过程，对于专门的项目来说是必要的。

然而，开源的 BigCouch 项目具有以透明和通用的方式扩展 CouchDB 的能力。使用 BigCouch，我们可以在服务器之间扩展 CouchDB，但与之交互就像它在一个服务器上一样。BigCouch 可以在[`www. github.com/cloudant/bigcouch`](https://www. github.com/cloudant/bigcouch)找到。

## 另请参阅

+   *在本章中讨论的使用 Cradle 从 CouchDB 检索数据*

+   *在本章中讨论的使用 MongoDB 存储和检索数据*

+   *在本章中讨论的使用 Redis 存储和检索数据*

# 使用 Cradle 从 CouchDB 检索数据

CouchDB 不使用与 MySQL 和 MongoDB 相同的查询范式。相反，它使用预先创建的视图来检索所需的数据。

在这个例子中，我们将使用 Cradle 根据指定的作者获取一个引用数组，并将我们的引用输出到控制台。

## 准备工作

与前一个配方*使用 Cradle 将数据存储到 CouchDB*一样，我们需要在系统上安装 CouchDB，以及`cradle`。我们还可以从该配方中获取`quotes.js`文件，并将其放在一个新的目录中。

## 如何做...

我们正在从之前的任务中的`quotes.js`文件中进行工作，在那里如果我们的数据库存在，我们调用`checkAndSave`，或者如果它不存在，我们就从`db.create`的回调中调用它。让我们稍微修改`checkAndSave`，如下面的代码所示：

```js
function checkAndSave(err) { 
  errorHandler(err); 
  if (params.author && params.quote) { 
    db.save({author: params.author, quote: params.quote}, outputQuotes); 
    return; 
  } 

  outputQuotes(); 
} 

```

我们在`checkAndSave`的末尾添加了一个新的函数调用`outputQuotes`，并且也作为`db.save`的回调。`outputQuotes`将访问一个名为视图的特殊 CouchDB `_design`文档。

在我们查看`outputQuotes`之前，让我们来看看另一个我们将要创建的新函数，名为`createQuotesView`。它应该放在`errorHandler`的下面，但在代码的其余部分之上，如下所示：

```js
function createQuotesView(err) { 
  errorHandler(err); 
  db.save('_design/quotes', { 
    views: { byAuthor: { map: 'function (doc) { emit(doc.author, doc) }'}} 
  }, outputQuotes); 
}

```

`createQuotesView`还从`db.save`的回调参数中调用`outputQuotes`函数。`outputQuotes`现在从三个地方调用：`checkAndSave`的`db.save`回调，`checkAndSave`的末尾，以及`createQuotesView`的`db.save`回调。

让我们来看看`outputQuotes:`

```js
function outputQuotes(err) { 
  errorHandler(err); 

  if (params.author) { 
    db.view('quotes/byAuthor', {key: params.author}, 
    function (err, rowsArray) { 
      if (err && err.error === "not_found") { 
        createQuotesView(); 
        return; 
      } 
      errorHandler(err); 

      rowsArray.forEach(function (doc) { 
        console.log('%s: %s \n', doc.author, doc.quote); return; 
      }); 
    }); 
  } 
}

```

`outputQuotes`在`checkAndSave`之前，但在`createQuotesView`之后。

## 它是如何工作的...

查询 CouchDB 数据库的关键是视图。有两种类型的视图：永久视图和临时视图。在`createQuotesView`中，我们使用`db.save`定义了一个永久视图，将文档 ID 设置为`_design/quotes`。然后我们定义了一个包含名为`byAuthor`的对象的`views`字段，该对象包含一个名为`map`的键，其值是一个格式化的字符串函数。

临时视图将存储一个 ID 为`quotes/_temp_view`。然而，这些只应该用于测试，它们在计算上非常昂贵，不应该用于生产。

映射函数是字符串格式化的，因为它通过 HTTP 请求传递给 CouchDB。CouchDB 的`map`函数不是在 Node 中执行的，它们在 CouchDB 服务器内运行。`map`函数定义了我们希望通过 CouchDB 服务器的`emit`函数在数据库上运行的查询。`emit`的第一个参数指定要查询的字段（在我们的例子中是`doc.author`），第二个指定查询的结果输出（我们想要整个`doc`）。如果我们想要搜索 Albert Einstein，我们将发出 GET 请求：`http://localhost:5984/quotes/_design/quotes/_view/byAuthor?key="Albert Einstein"`。

Cradle 为这个请求提供了一个简写方法`db.view`，它出现在我们的`outputQuotes`函数中。`db.view`允许我们简单地传递`quotes/byAuthor`和一个包含`key`参数（即我们的查询）的第二个对象，从根本上为我们填充了特殊的下划线路由。

`db.view`解析传入的 JSON 并通过其回调的第二个参数提供它，我们将其命名为`rowsArray`。我们使用`forEach`循环数组，最后通过控制台输出`author`和`quote`，就像以前的配方一样。

然而，在循环数组之前，我们需要检查我们的视图是否实际存在。视图只需要生成一次。之后，它们将存储在 CouchDB 数据库中。因此，我们不希望每次运行应用程序时都创建一个视图。因此，当我们调用`db.view`时，我们会查看`db.view`回调中是否发生`not_found`错误。如果我们的视图找不到，我们就调用`createQuotesView`。

总的来说，这个过程大致是这样的：

![工作原理...](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-cb/img/7188_04_02.jpg)

## 还有更多...

CouchDB 非常适合立即上手。然而，在将 CouchDB 支持的应用程序部署到网络之前，我们必须注意某些安全考虑。

### 创建管理员用户

CouchDB 不需要初始授权设置，这对开发来说是可以的。然而，一旦我们将 CouchDB 暴露给外部世界，互联网上的任何人都有权限编辑我们的整个数据库：数据设计、配置、用户等。

因此，在部署之前，我们希望设置用户名和密码。我们可以通过`_config` API 实现这一点：

```js
curl -X PUT http://localhost:5984/_config/admins/dave -d '"cookit"' 

```

我们已经创建了管理员用户`dave`并将密码设置为`cookit`。现在，未经身份验证将拒绝对某些调用的权限，包括创建或删除数据库，修改设计文档（例如视图），或访问`_config` API。

例如，假设我们想查看所有管理员用户，我们可以说：

```js
curl http://localhost:5984/_config/admins 

```

CouchDB 将回复：

```js
{"error":"unauthorized", "reason":"You are not a server admin."} 

```

但是，如果我们包括身份验证信息：

```js
curl http://dave:cookit@localhost:5984/_config/admins 

```

我们得到了我们唯一的管理员用户以及他密码的哈希值：

```js
{"dave":"-hashed-42e68653895a4c0a5c67baa3cfb9035d01057b0d,44c62ca1bfd4872b773543872d78e950"} 

```

使用这种方法远程管理 CouchDB 数据库并不是没有安全漏洞。它强迫我们将密码以明文形式通过非安全的 HTTP 发送。理想情况下，我们需要将 CouchDB 托管在 HTTPS 代理后面，这样密码在发送时就会被加密。参见第七章中讨论的*设置 HTTPS 服务器*配方，实施安全、加密和身份验证

如果 CouchDB 在 HTTPS 后面，`cradle`可以连接到它如下：

```js
var db = new (cradle.Connection)({secure:true, 
									     auth: { username: 'dave', 
									                 password: 'cookit' }})
		            .database('quotes'); 

```

我们在创建连接时传递一个`options`对象。`secure`属性告诉`cradle`我们正在使用 SSL，`auth`包含一个包含登录详细信息的子对象。

或者，我们创建一个 Node 应用程序，用于与本地 CouchDB 实例进行身份验证（以便不将密码发送到外部 HTTP 地址），并充当外部请求和 CouchDB 之间的中间层。

### 将所有修改操作锁定到管理员用户

即使设置了管理员用户，未经身份验证的用户仍然有权限修改现有数据库。如果我们只在 CouchDB 服务器端写入（但从服务器或客户端读取），我们可以使用验证函数锁定非管理员用户的所有写操作。

验证函数是用 JavaScript 编写的，并在 CouchDB 服务器上运行（类似于映射函数）。一旦定义了验证函数，它就会针对应用到的数据库的所有用户输入执行。函数中出现三个对象作为参数：新文档（`newDoc`），先前存储的文档（`savedDoc`）和用户上下文（`userCtx`），其中包含经过身份验证的用户信息。

在验证函数中，我们可以检查和限定这些对象，调用 CouchDB 的`throw`函数来拒绝未能满足我们要求的操作请求。

让我们创建一个名为`database_lockdown.js`的新文件，并开始连接到我们的数据库：

```js
var cradle = require('cradle'); 
var db = new (cradle.Connection)({auth: 
									     { username: 'dave', 
										  password: 'cookit' }})
     		            .database('quotes'); 

```

我们向新的 cradle 连接传递一个`options`对象。它包含了认证信息，如果我们根据上一小节*创建管理员用户*设置了新的管理员用户，那么现在将需要创建一个验证函数。

让我们创建我们的验证函数，并将其保存为`_design`文档：

```js
var admin_lock = function (newDoc, savedDoc, userCtx) { 
  if (userCtx.roles.indexOf('_admin') === -1) { 
    throw({unauthorized : 'Only for admin users'}); 
  } 
} 
  db.save('_design/_auth', { 
    views: {}, 
    validate_doc_update: admin_lock.toString() 
  }); 

```

一旦我们执行：

```js
node database_lockdown.js 

```

现在所有与写操作相关的操作都需要授权。

与视图一样，我们将验证函数存储在具有`_design/`前缀 ID 的文档中。ID 的另一部分可以是任何内容，但我们将其命名为`_auth`，这反映了当验证函数提供此类目的时的传统做法。但是，字段名称必须称为`validate_doc_update`。

默认情况下，Cradle 假定传递给`db.save`的任何`_design`文档都是一个视图。为了防止 Cradle 将我们的`validate_update_doc`字段包装成视图，我们将一个空对象指定给`views`属性。

`validate_update_doc`必须传递一个字符串格式的函数，因此我们在`admin_lock`变量下定义我们的函数，并在传递到`db.save`时对其调用`toString`。

`admin_lock`永远不会被 Node 执行。这是一种在传递给 CouchDB 之前构建我们的函数的美学方法。

当数据库发生操作时，我们的`admin_lock`函数（它成为 CouchDB 的`validate_update_doc`函数）要求 CouchDB 检查请求操作的用户是否具有`_admin`用户角色。如果没有，它告诉 CouchDB 抛出未经授权的错误，从而拒绝访问。

### 将 CouchDB HTTP 接口暴露给远程连接

默认情况下，CouchDB 绑定到`127.0.0.1`。这确保只有本地连接可以连接到数据库，从而在安全执行之前确保安全性。一旦我们在 HTTPS 后设置了至少一个管理员用户，我们可以将 CouchDB 绑定到`0.0.0.0`，这样 REST 接口可以通过任何 IP 地址访问。这意味着远程用户可以通过我们服务器的公共 IP 地址或更可能通过我们服务器的域名访问我们的 CouchDB HTTP 接口。我们可以使用`_config`设置绑定地址如下：

```js
curl -X PUT https://u:p@localhost:5984/_config/httpd/bind_address -d '"0.0.0.0"' 

```

其中`u`和`p`分别是管理员用户名和密码。

## 另见

+   *在本章中讨论的使用 Cradle 将数据存储到 CouchDB*

+   *在本章中讨论的使用 MongoDB 存储和检索数据*

+   *在* 第七章 *中讨论的设置和 HTTPS Web 服务器*，实施安全、加密和身份验证

# 使用 Cradle 访问 CouchDB 更改流

CouchDB 最引人注目的功能之一是`_changes` API。通过它，我们可以通过 HTTP 查看对数据库的所有更改。

例如，要查看对我们的`quotes`数据库所做的所有更改，我们可以向`http://localhost:5984/quotes/_changes`发出 GET 请求。更好的是，如果我们想要连接到实时流，我们可以添加查询参数`?feed=continuous`。

Cradle 为`_changes` API 提供了一个吸引人的接口，我们将在本食谱中探讨。

## 准备好了

我们需要一个可用的 CouchDB 数据库以及一种写入它的方法。我们可以使用*使用 Cradle 将数据存储到 CouchDB*中使用的`quotes.js`示例，所以让我们将其复制到一个新目录中，然后在旁边创建一个名为`quotes_stream.js`的文件。

如果我们遵循了前一篇食谱*创建管理员用户*和*将所有修改操作锁定为管理员用户*部分中的步骤，我们需要修改`quotes.js`的第二行，以便继续向我们的数据库中插入引用：

```js
var db = new (cradle.Connection)({ auth: { username: 'dave', 
									                 password: 'cookit' }})
		      .database('quotes'); 

```

`dave`和`cookit`是示例用户名和密码。

## 如何做...

我们需要`cradle`并连接到我们的`quotes`数据库。我们的流适用于预先存在的数据库，因此我们不会检查数据库是否存在。

```js
var cradle = require('cradle');
var db = new (cradle.Connection)().database('quotes');

```

接下来，我们调用`cradle`的`changes`方法，并监听其`response`事件，然后监听传入的`response`发射器的`data`事件：

```js
db.changes().on('response', function (response) {

  response.on('data', function (change) {
    var changeIsObj = {}.toString.call(change) === '[object Object]';
    if (change.deleted !changeIsObj) { return; }
    db.get(change.id, function (err, doc) { 
      if (!doc) {return;}
      if (doc.author && doc.quote) { 
        console.log('%s: %s \n', doc.author, doc.quote); 
      } 
    }); 
  });

});

```

为了测试我们的`changes`流实现，我们将打开两个终端。在一个终端中，我们将运行以下命令：

```js
node quotes_stream.js 

```

在另一个终端窗口中，我们可以使用`quotes.js`添加一些引用：

```js
node quotes.js "Yogi Berra" "I never said most of the things I said"
node quotes.js "Woody Allen" "I'd call him a sadistic hippophilic necrophile, but that would be beating a dead horse"
node quotes.js "Oliver Wendell Holmes" "Man's mind, once stretched by a new idea, never regains its original dimensions" 

```

![如何做...](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-cb/img/7188-04-03.jpg)

每当在左侧终端中添加新引用时，它会出现在右侧。

在添加任何新引用之前，`quotes_stream.js`被打开，并立即显示了在*使用 Cradle 将数据存储到 CouchDB*食谱中添加的`Albert Einstein`引用。之后，随着添加的新引用，它们也会出现在流中。

## 它是如何工作的...

`changes`方法可以传递一个回调，它简单地返回到目前为止的所有更改，然后退出。如果我们没有将回调传递给`changes`，它会将`?feed=continuous`参数添加到 HTTP CouchDB REST 调用中，并返回`EventEmitter`。然后，CouchDB 将返回一个流式的 HTTP 响应给 Cradle，作为`response`事件的`response`参数发送。`response`参数也是`EventEmitter`，我们通过`data`事件监听更改。

在每个`data`事件上，回调处理`change`参数。每个更改都会触发两个数据事件，一个是 JSON 字符串，另一个是包含等效 JSON 数据的 JavaScript 对象。在继续之前，我们检查`change`参数的类型是否为对象（`changeIsObj`）。`change`对象保存了我们数据库条目的元数据。它有一个序列号（`change.seq`），一个修订号（`change.changes[0].rev`），有时包含一个已删除的属性（`changes.deleted`），并且始终有一个`id`属性。

如果找到`deleted`属性，我们需要提前`return`，因为`db.get`无法获取已删除的记录。否则，我们将`change.id`传递给`db.get`，这将提供对文档 ID 的访问。`doc`被传递到`db.get`的回调中。我们只想输出关于我们的引用的更改，因此我们检查`author`和`quote`字段，并将它们记录到控制台。

## 另请参阅

+   *使用 Cradle 将数据存储到 CouchDB*在本章中讨论

+   *使用 Cradle 从 CouchDB 检索数据*在本章中讨论

+   *使用 Redis 实现 PubSub*在本章中讨论

# 使用 Redis 存储和检索数据

**Redis**是一个非传统的数据库，被称为数据结构服务器，在操作内存中具有极快的性能。

Redis 非常适用于某些任务，只要数据模型相对简单，且数据量不会太大以至于淹没服务器的 RAM。Redis 擅长的示例包括网站分析、服务器端会话 cookie 和实时提供已登录用户列表。

以我们的主题精神，我们将使用 Redis 重新实现我们的引用数据库。

## 准备好了

我们将使用`node_redis`客户端。

```js
npm install redis

```

我们还需要安装 Redis 服务器，可以从[`www.redis.io/download`](http://www.redis.io/download)下载，并附有安装说明。

让我们还创建一个新的目录，其中包含一个新的`quotes.js`文件。

## 如何做...

让我们创建`redis`模块，创建一个连接，并监听`redis client`发出的`ready`事件，不要忘记将命令行参数加载到`params`对象中。

```js
var redis = require('redis'); 
var client = redis.createClient(); 
var params = {author: process.argv[2], quote: process.argv[3]};

client.on('ready', function () { 
  //quotes insertion and retrieval code to go here...
});

```

接下来，我们将通过命令行检查`author`和`quote`。如果它们被定义，我们将在我们的`ready`事件回调中将它们作为哈希（对象结构）插入 Redis 中：

```js
if (params.author && params.quote) { 
  var randKey = "Quotes:" + (Math.random() * Math.random()) 
                           .toString(16).replace('.', ''); 

  client.hmset(randKey, {"author": params.author, 
                                        "quote": params.quote}); 

  client.sadd('Author:' + params.author, randKey); 
}

```

我们不仅将数据添加到了 Redis 中，还在飞行中构建了一个基本的索引，使我们能够在下一段代码中按作者搜索引用。

我们检查第一个命令行参数，作者的存在，并输出该作者的引用。

```js
  if (params.author) { 
    client.smembers('Author:' + params.author, function (err, keys) { 
      keys.forEach(function (key) { 
        client.hgetall(key, function (err, hash) { 
          console.log('%s: %s \n', hash.author, hash.quote); 
        }); 
      }); 
      client.quit(); 
    }); 
    return; 
  } 
  client.quit(); 

}); // closing brackets of the ready event callback function

```

## 它是如何工作的...

如果通过命令行指定了`author`和`quote`，我们继续并生成一个以`Quote:`为前缀的随机键。因此，每个键看起来都像`Quote:08d780a57b035f`。这有助于我们在调试中识别键，并且在 Redis 键前缀中使用名称是常见的约定。

我们将这个键传递给`client.hmset`，这是 Redis `HMSET`命令的包装器，它允许我们创建多个哈希。与原始的`HMSET`不同，`client.hmset`还接受 JavaScript 对象（而不是数组）来创建多个键分配。使用标准的 Redis 命令行客户端`redis-cli`，我们需要这样说：

```js
HMSET author "Steve Jobs" quote "Stay hungry, stay foolish." 

```

我们可以通过使用包含键和值的数组来保持这种格式，但是对象对于 JavaScript 开发者来说更友好和更熟悉。

每次我们使用`client.hmset`存储新引用时，我们通过`client.sadd`的第二个参数将该引用的`randKey`添加到相关的作者集合中。`client.sadd`允许我们向 Redis 集合（集合类似于字符串数组）中添加成员。我们的`SADD`命令的键是基于预期作者的。因此，在上面使用的 Steve Jobs 引用中，传递给`client.sadd`的键将是`Author:Steve Jobs`。

接下来，如果指定了作者，我们使用`client.smembers`执行`SMEMBERS`。这将返回我们存储在特定作者集合中的所有引用的键。

我们使用`forEach`循环遍历这些键，将每个键传递给`client.hgetall`。Redis `HGETALL`返回我们之前传递给`client.hmset`的哈希（对象）。然后将每个作者和引用记录到控制台，并且一旦所有 Redis 命令都已执行，`client.quit`就会优雅地退出我们的脚本。

在`ready`事件的结尾处也包括了`client.quit`，在没有指定命令行参数的情况下会发生这种情况。

## 还有更多...

Redis 是速度狂人的梦想，但我们仍然可以进行优化。

### 加速 node Redis 模块

默认情况下，`redis`模块使用纯 JavaScript 解析器。然而，Redis 项目提供了一个 Node `hiredis`模块：一个 C 绑定模块，它绑定到官方 Redis 客户端 Hiredis。Hiredis 比 JavaScript 解析器更快（因为它是用 C 编写的）。

如果安装了`hiredis`模块，`redis`模块将与`hiredis`模块进行接口。因此，我们可以通过简单安装`hiredis`来获得性能优势：

```js
npm install hiredis 

```

### 通过流水线化命令来克服网络延迟

Redis 可以一次接收多个命令。`redis`模块有一个`multi`方法，可以批量发送汇总的命令。如果每个命令的延迟（数据传输所需的时间）为 20 毫秒，对于 10 个组合命令，我们可以节省 180 毫秒（10 x 20 - 20 = 180）。

如果我们将`quotes.js`复制到`quotes_multi.js`，我们可以相应地进行修改：

```js
//top variables, client.ready...

 if (params.author && params.quote) { 
    var randKey = "Quote:" + (Math.random() * Math.random()) 
                  .toString(16).replace('.', ''); 

    client.multi() 
      .hmset(randKey, {"author": params.author, 
                                    "quote": params.quote}) 
      .sadd('Author:' + params.author, randKey) 
      .exec(function (err, replies) { 
        if (err) { throw err; }; 
        if (replies[0] == "OK") { console.log('Added...\n'); } 
      }); 
  } 

//if params.author, client.smembers, client.quit

```

我们可以看到我们的原始 Redis 命令已经突出显示，只是它们已经与`client.multi`链接在一起。一旦所有命令都添加到`client.multi`，我们调用它的`exec`方法。最后，我们使用`exec`的回调来验证我们的数据是否成功添加。

我们没有为流水线提供`SMEMBERS`。必须在引语添加后调用`SMEMBERS`，否则新引语将不会显示。如果`SMEMBERS`与`HMSET`和`SADD`结合使用，它将与它们一起异步执行。不能保证新引语将对`SMEMBERS`可用。实际上，这是不太可能的，因为`SMEMBERS`比`SADD`更复杂，所以处理时间更长。

## 另请参阅

+   *在本章中讨论了使用 Mongoskin 存储和检索数据*

+   *连接并向 MySQL 服务器发送 SQL*在本章中讨论

+   *在本章中讨论了使用 Redis 实现 PubSub*

# 使用 Redis 实现 PubSub

Redis 公开了发布-订阅消息模式（与 CouchDB 的`changes`流不那么相似），可以用于监听特定数据更改事件。这些事件的数据可以在进程之间传递，例如，立即使用新鲜数据更新 Web 应用程序。

通过 PubSub，我们可以向特定频道发布消息，然后任何数量的订阅者都可以接收到该频道。发布机制不在乎谁在听或有多少人在听，它会继续聊天。

在这个配方中，我们将创建一个发布过程和一个订阅过程。对于发布，我们将扩展我们的`quotes.js`文件，从上一个配方*使用 Redis 存储和检索数据*，并为订阅机制编写新文件的代码。

## 准备就绪

让我们创建一个新目录，从上一个配方中复制`quotes.js`，并将其重命名为`quotes_publish.js`。我们还将创建一个名为`quotes_subscribe.js`的文件。我们需要确保 Redis 正在运行。如果它没有全局安装和运行，我们可以导航到 Redis 解压到的目录，并从`src`文件夹运行`./redis-server`。

## 如何做...

在`quotes_publish.js`中，我们在第一个条件语句内添加了一行额外的代码，就在我们的`client.sadd`调用之后。

```js
  if (params.author && params.quote) { 
    var randKey = "Quote:" + (Math.random() * Math.random()) 
                                               .toString(16).replace('.', '');               
    client.hmset(randKey, {"author": params.author, 
                           "quote": params.quote}); 

    client.sadd('Author:' + params.author, randKey); 

    client.publish(params.author, params.quote); 

  }

```

这意味着每次我们添加一个作者和引语时，我们都会将引语发布到以作者命名的频道。我们使用`quotes_subscribe.js`订阅频道，所以让我们编写代码。

首先，它必须要求`redis`模块并创建一个客户端：

```js
var redis = require('redis');
var client = redis.createClient();

```

我们将提供订阅多个频道的选项，再次使用命令行作为我们的基本输入方法。为此，我们将循环遍历`process.argv:`

```js
process.argv.slice(2).forEach(function (authorChannel, i) { 

    client.subscribe(authorChannel, function () { 
      console.log('Subscribing to ' + authorChannel + ' channel'); 
    }); 

});

```

现在我们正在订阅频道，我们需要监听消息：

```js
client.on('message', function (channel, msg) { 
	console.log("\n%s: %s", channel, msg); 
});

```

我们可以通过首先运行`quotes_subscribe.js`来测试我们的 PubSub 功能，并指定一些作者：

```js
node quotes_subscribe.js "Sun Tzu" "Steve Jobs" "Ronald Reagan" 

```

然后我们打开一个新的终端，并通过`quotes_publish.js`运行几个作者和引语。

```js
node quotes_publish.js "Ronald Reagan" "One picture is worth 1,000 denials."

node quotes_publish.js "Sun Tzu" "Know thy self, know thy enemy. A thousand battles, a thousand victories."

node quotes_publish.js "David Clements" "Redis is a speed freak's dream"

node quotes_publish.js "Steve Jobs" "Design is not just what it looks like and feels like. Design is how it works." 

```

让我们看看它的运行情况：

![如何做...](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-cb/img/7188-04-04.jpg)

只有我们订阅的频道才会出现在`quotes_subscribe.js`终端上。

## 它是如何工作的...

我们通过`client.publish`访问 Redis 的`PUBLISH`命令，在`quotes_publish.js`中设置频道名称为作者名称。

在`quotes_subscribe.js`中，我们循环遍历通过命令行给出的任何参数。（我们对`process.argv.slice(2)`应用`forEach`。这会删除`process.argv`数组的前两个元素，这些元素将保存命令（`node`）和我们脚本的路径。将每个相关参数传递给`client.subscribe`，告诉 Redis 我们希望`SUBSCRIBE`到该频道。

当由于订阅而到达消息时，`redis`模块的`client`将发出`message`事件。我们监听此事件，并将传入的`channel`和`msg`（将分别是`author`和`quote`）传递给`console.log`。

## 还有更多...

最后，我们将看一下 Redis 安全性。

### Redis 身份验证

我们可以在 Redis 的`redis.conf`文件中设置身份验证，该文件位于我们安装 Redis 的目录中。要在`redis.conf`中设置密码，我们只需添加（或取消注释）`requirepass ourpassword`。

然后，我们确保我们的 Redis 服务器指向配置文件。如果我们是从`src`目录运行它，我们将使用以下命令初始化：

```js
./redis-server ../redis.conf 

```

如果我们想快速设置密码，我们可以说：

```js
echo "requirepass ourpassword" | ./redis-server - 

```

我们可以使用 Redis 命令`CONFIG SET`从 Node 中设置密码：

```js
client.config('SET', 'requirepass', 'ourpassword');

```

要在 Node 中与 Redis 服务器进行身份验证，我们可以使用`redis`模块的`auth`方法，在任何其他调用之前（即在`client.ready`之前）。

```js
client.auth('ourpassword');

```

密码必须在任何其他命令之前发送。`redis`模块的`auth`函数通过将密码推送到`redis`模块的内部操作来处理重新连接等问题。基本上，我们可以在我们的代码顶部调用`auth`，然后再也不用担心该脚本的身份验证。

### 保护 Redis 免受外部连接

如果不需要将 Redis 绑定到`127.0.0.1`以阻止所有外部流量。

我们可以通过配置文件来实现这一点，例如`redis.conf`，并添加（或取消注释）：

```js
bind 127.0.0.1

```

然后，如果从`src`文件夹运行，初始化我们的 Redis 服务器：

```js
./redis-server ../redis.conf 

```

或者，我们可以这样做：

```js
echo "bind 127.0.0.1" | ./redis-server - 

```

或者在 Node 中使用`redis`模块的`config`方法：

```js
client.config('set', 'bind', '127.0.0.1');

```

### 注意

如果我们通过软件包管理器安装了 Redis，它可能已经配置为阻止外部连接。

## 另请参阅

+   *在本章中讨论的使用 Cradle 访问 CouchDB 更改流*

+   *在本章中讨论的使用 Redis 存储和检索数据*


# 第五章：超越 AJAX：使用 WebSocket

在本章中，我们将涵盖：

+   创建 WebSocket 服务器

+   使用`socket.io`实现无缝回退

+   通过`socket.io`传输的回调

+   创建实时小部件

# 介绍

HTTP 并不适用于许多开发人员今天创建的实时网络应用程序。因此，已经发现了各种各样的解决方法来模拟服务器和客户端之间的双向，不间断的通信的想法。

WebSocket 不会模仿这种行为，它们提供了这种行为。WebSocket 通过剥离 HTTP 连接来工作，使其成为持久的类似 TCP 的交换，从而消除了 HTTP 引入的所有开销和限制。

当浏览器和服务器都支持 WebSocket 时，HTTP 连接被剥离（或升级）。浏览器通过 GET 标头与服务器通信来发现这一点。只有较新的浏览器（IE10+，Google Chrome 14，Safari 5，Firefox 6）支持 WebSocket。

WebSocket 是一个新协议。JavaScript 与 Node 框架通常足够灵活和低级，可以从头开始实现协议，或者无法实现的话，可以编写 C/C++模块来处理更晦涩或革命性的逻辑。幸运的是，我们不需要编写自己的协议实现，开源社区已经提供了。

在本章中，我们将使用一些第三方模块来探索 Node 和 WebSocket 强大组合的潜力。

# 创建 WebSocket 服务器

对于这个任务，我们将使用非核心的`websocket`模块来创建一个纯 WebSocket 服务器，该服务器将接收并响应来自浏览器的 WebSocket 请求。

## 准备就绪

我们将为我们的项目创建一个新文件夹，其中将包含两个文件：`server.js`和`client.html. server.js`。它们提供了服务器端的 websocket 功能并提供`client.html`文件。对于服务器端的 WebSocket 功能，我们还需要安装`websocket`模块：

```js
npm install websocket 

```

### 注意

有关`websocket`模块的更多信息，请参见[`www.github.com/Worlize/WebSocket-Node`](https://www.github.com/Worlize/WebSocket-Node)。

## 如何做...

WebSocket 是 HTTP 升级。因此，WebSocket 服务器在 HTTP 服务器之上运行。因此，我们将需要`http`和`websocket`服务器，另外我们还将加载我们的`client.html`文件（我们将很快创建）和`url`模块：

```js
var http = require('http');
var WSServer = require('websocket').server;
var url = require('url');
var clientHtml = require('fs').readFileSync('client.html');

```

现在让我们创建 HTTP 服务器，并将其提供给一个新的 WebSocket 服务器：

```js
var plainHttpServer = http.createServer(function (request, response) {
    response.writeHead(200, {'Content-type' : 'text/html'});
    response.end(clientHtml);
  }).listen(8080);

var webSocketServer = new WSServer({httpServer: plainHttpServer});

var accept = [ 'localhost', '127.0.0.1' ];

```

### 注意

我们将我们的 HTTP 服务器绑定到端口 8080，因为绑定到低于 1000 的端口需要 root 访问权限。这意味着我们的脚本必须以 root 权限执行，这是一个坏主意。有关如何安全地绑定到 HTTP 端口（80）的更多信息，请参见第十章，*搞定它*。

我们还创建了一个新的数组，称为`accept`。我们在 WebSocket 服务器内部使用它来限制哪些起始站点可以连接。在我们的示例中，我们只允许来自 localhost 或 127.0.0.1 的连接。如果我们正在进行实时主机，我们将在`accept`数组中包括指向我们服务器的任何域。

现在我们有了`webSocketServer`实例，我们可以侦听其`request`事件并做出相应的响应：

```js
webSocketServer.on('request', function (request) {
  request.origin = request.origin || '*'; //no origin? Then use * as wildcard.
  if (accept.indexOf(url.parse(request.origin).hostname) === -1) {
    request.reject();
    console.log('disallowed ' + request.origin);
    return;
  }

  var websocket = request.accept(null, request.origin);

  websocket.on('message', function (msg) {
    console.log('Recieved "' + msg.utf8Data + '" from ' + request.origin);
    if (msg.utf8Data === 'Hello') {
      websocket.send('WebSockets!');
    }
  });

  websocket.on('close', function (code, desc) {
   console.log('Disconnect: ' + code + ' - ' + desc);
  });

});

```

在我们的`request`事件回调中，我们有条件地接受请求，然后监听`message`和`close`事件，如果来自客户端的消息是`Hello`，则用**WebSockets!**做出响应。

现在对于客户端，我们将放置以下 HTML 结构：

```js
<html>
<head>
</head>
<body>
<input id=msg><button id=send>Send</button>
<div id=output></div>

<script>
//client side JavaScript will go here
</script>

</body>
</html>

```

我们的`script`标签的内容应如下所示：

```js
<script>
(function () {
  var ws = new WebSocket("ws://localhost:8080"),
    output = document.getElementById('output'),
    send = document.getElementById('send');

  function logStr(eventStr, msg) {
    return '<div>' + eventStr + ': ' + msg + '</div>';
  }  

  send.addEventListener('click', function () 
      var msg = document.getElementById('msg').value;
      ws.send(msg);
      output.innerHTML += logStr('Sent', msg);
  });

  ws.onmessage = function (e) {
    output.innerHTML += logStr('Recieved', e.data);
  };

  ws.onclose = function (e) {
    output.innerHTML += logStr('Disconnected', e.code + '-' + e.type);
  };

  ws.onerror = function (e) {
    output.innerHTML += logStr('Error', e.data);
  };  

}());

</script>

```

如果我们使用`node server.js`初始化我们的服务器，然后将我们的（支持 WebSocket 的）浏览器指向`http://localhost:8080`，在文本框中输入`Hello`，然后单击**发送**。终端控制台将输出：

```js
Recieved "Hello" from http://localhost:8080 

```

我们的浏览器将显示**Hello**已发送和**WebSockets!**已接收，如下面的屏幕截图所示：

![如何做...](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-cb/img/7188_05_01.jpg)

我们可以使用我们的文本框发送任何我们想要的字符串到我们的服务器，但只有**Hello**会得到响应。

## 它是如何工作的...

在`server.js`中，当我们需要`websocket`模块的`server`方法时，我们将构造函数加载到`WSServer`中（这就是为什么我们将第一个字母大写）。我们使用`new`初始化`WSServer`，并传入我们的`plainHttpServer`，将其转换为一个启用了 WebSocket 的服务器。

HTTP 服务器仍然会提供普通的 HTTP 请求，但当它接收到 WebSocket 连接握手时，`webSocketServer`会开始建立与客户端的持久连接。

一旦`client.html`文件在浏览器中加载（由`server.js`中的 HTTP 服务器提供），并且内联脚本被执行，WebSocket 升级请求就会发送到服务器。

当服务器收到 WebSocket 升级请求时，`webSocketServer`会触发一个`request`事件，我们会使用我们的`accept`数组来仔细检查，然后决定是否响应。

我们的`accept`数组保存了一个白名单，允许与我们的 WebSocket 服务器进行接口交互的主机。只允许已知来源使用我们的 WebSocket 服务器，我们可以获得一些安全性。

在`webSocketServer request`事件中，使用`url.parse`解析`request.origin`以检索`origin` URL 的主机名部分。如果在我们的`accept`白名单中找不到主机名，我们就调用`request.reject`。

如果我们的源主机通过了，我们就从`request.accept`创建一个`websocket`变量。`request.accept`的第一个参数允许我们定义一个自定义子协议。我们可以使用多个具有不同子协议的`request.accepts`创建一个 WebSocket 数组，这些子协议代表不同的行为。在初始化客户端时，我们将传递一个包含该子协议的额外参数（例如，`new WebSocket("ws://localhost:8080", 'myCustomProtocol')`）。但是，我们传递`null`，因为对于我们的目的，不需要这样的功能。第二个参数允许我们通知`request.accept`我们希望允许的主机（还有第三个参数可用于传递 cookie）。

对于从客户端接收的每条消息，`WebSocket`都会发出一个`message`事件。这是我们将接收到的数据记录到`console`并检查传入消息是否为`Hello`的地方。如果是，我们使用`WebSocket.send`方法向客户端回复**WebSockets!**。

最后，我们监听`close`事件，通知`console`连接已经被终止。

## 还有更多...

WebSockets 对于高效、低延迟的实时 Web 应用有很大潜力，但兼容性可能是一个挑战。让我们看看 WebSockets 的其他用途，以及让 WebSockets 在 Firefox 中工作的技巧。

### 支持旧版 Firefox 浏览器

Firefox 6 到 11 版本支持 WebSockets。但是，它们使用供应商前缀，因此我们的`client.html`将无法在这些 Firefox 版本上运行。

为了解决这个问题，我们只需在`client.html`文件中的脚本前面添加以下内容：

```js
window.WebSocket = window.WebSocket || window.MozWebSocket;

```

如果`WebSocket` API 不存在，我们尝试`MozWebSocket`。

### 创建基于 Node 的 WebSocket 客户端

`websocket`模块还允许我们创建一个 WebSocket 客户端。我们可能希望将 Node 与现有的 WebSocket 服务器进行接口，这主要是为浏览器客户端（如果不是，最好创建一个简单的 TCP 服务器。参见第八章，*集成网络范式*）。

因此，让我们在`client.html`中使用 Node 实现相同的功能。我们将在同一目录中创建一个新文件，命名为`client.js`：

```js
var WSClient = require('websocket').client;

new WSClient()

  .on('connect', function (connection) {
    var msg = 'Hello';

    connection.send(msg);
    console.log('Sent: ' + msg);

    connection.on('message', function (msg) {
      console.log("Received: " + msg.utf8Data);
    }).on('close', function (code, desc) {
      console.log('Disconnected: ' + code + ' - ' + desc);
    }).on('error', function (error) {
      console.log("Error: " + error.toString());
    });

  })
  .on('connectFailed', function (error) {
    console.log('Connect Error: ' + error.toString());
  })
  .connect('ws://localhost:8080/', null, 'http://localhost:8080');

```

为了简洁起见，我们只是简单地将我们的`msg`变量硬编码，尽管我们可以使用`process.stdin`或`process.argv`来输入自定义消息。我们使用`websocket`模块的`client`方法初始化一个新的客户端。然后我们立即开始监听`connect`和`connectFailed`事件。

在两个`on`方法之后，我们链接`connect`方法。第一个参数是我们的 WebSocket 服务器，第二个是协议（记住，在我们的配方中，对于`request.accept`，我们有一个空协议），第三个定义了`request.origin`的值。

来源保护旨在防止仅从浏览器中起作用的攻击。因此，尽管我们可以在浏览器之外制造来源，但它并不构成同样的威胁。最大的威胁来自于对高流量站点进行 JavaScript 注入攻击，这可能导致大量未经授权的连接来自意外来源，从而导致**拒绝服务**。请参阅第七章, *实施安全、加密和认证*。

## 另请参阅

+   *在本章中讨论了使用 socket.io 进行无缝回退*

+   *提供静态文件* 第一章, 创建 Web 服务器

# 使用 socket.io 进行无缝回退

旧版浏览器不支持 WebSocket。因此，为了提供类似的体验，我们需要回退到各种浏览器/插件特定的技术，以模拟 WebSocket 功能，以最大程度地利用已弃用浏览器的能力。

这显然是一个雷区，需要数小时的浏览器测试，有时还需要对专有协议（例如 IE 的`Active X htmlfile`对象）有高度具体的了解。

`socket.io`为服务器和客户端提供了类似 WebSocket 的 API，以在各种浏览器中（包括旧版 IE 5.5+和移动端 iOS Safari、Android 浏览器）创建最佳实时体验。

除此之外，它还提供了便利功能，比如断开连接发现，允许自动重新连接，自定义事件，命名空间，通过网络调用回调（参见下一个配方*通过 socket.io 传输回调*），以及其他功能。

在这个配方中，我们将重新实现先前的任务，以实现高兼容性的 WebSocket 类型应用程序。

## 准备工作

我们将创建一个新的文件夹，其中包含新的`client.html`和`server.js`文件。我们还将安装`socket.io`模块：

```js
npm install socket.io 

```

## 如何做...

与`websocket`模块一样，`socket.io`可以附加到 HTTP 服务器（尽管对于`socket.io`来说并不是必需的）。让我们创建`http`服务器并加载`client.html`。在`server.js`中，我们写道：

```js
var http = require('http');
var clientHtml = require('fs').readFileSync('client.html');

var plainHttpServer = http.createServer(function (request, response) {
    response.writeHead(200, {'Content-type' : 'text/html'});
    response.end(clientHtml);
  }).listen(8080);

```

现在是`socket.io`部分（仍在`server.js`中）：

```js
var io = require('socket.io').listen(plainHttpServer);

io.set('origins', ['localhost:8080', '127.0.0.1:8080']) ;

io.sockets.on('connection', function (socket) {
  socket.on('message', function (msg) {
    if (msg === 'Hello') {
      socket.send('socket.io!');
    }
  });
});

```

这是服务器端，现在让我们创建我们的`client.html`文件：

```js
<html>
<head>
</head>
<body>
<input id=msg><button id=send>Send</button>
<div id=output></div>

<script src="img/socket.io.js"></script>
<script>
(function () {
  var socket = io.connect('ws://localhost:8080'),
    output = document.getElementById('output'),
    send = document.getElementById('send');

  function logStr(eventStr, msg) {
    return '<div>' + eventStr + ': ' + msg + '</div>';
  } 
  socket.on('connect', function () {
    send.addEventListener('click', function () {
      var msg = document.getElementById('msg').value;
      socket.send(msg);
      output.innerHTML += logStr('Sent', msg);
    });

    socket.on('message', function (msg) {
      output.innerHTML += logStr('Recieved', msg);
    });

  });

}());
</script>
</body>
</html>

```

最终产品基本上与上一个配方相同，只是它还可以在不兼容 WebSocket 的旧浏览器中无缝运行。我们输入`Hello`，按下**发送**按钮，服务器回复**socket.io!**。

## 它是如何工作的...

我们不再将 HTTP 服务器传递给选项对象，而是简单地将其传递给`listen`方法。

我们使用`io.set`来定义我们的来源白名单，`socket.io`为我们完成了繁重的工作。

接下来，我们监听`io.sockets`上的`connection`事件，这为我们提供了一个客户端的`socket`（就像`request.accept`在上一个配方中生成了我们的`WebSocket`连接一样）。

在`connection`中，我们监听`socket`上的`message`事件，检查传入的`msg`是否为`Hello`。如果是，我们会回复`socket.io!`。

当`socket.io`初始化时，它开始通过 HTTP 提供客户端代码。因此，在我们的`client.html`文件中，我们从`/socket.io/socket.io.js`加载`socket.io.js`客户端脚本。

客户端的`socket.io.js`提供了一个全局的`io`对象。通过调用它的`connect`方法并提供我们服务器的地址，我们可以获得相关的`socket`。

我们向服务器发送我们的`Hello msg`，并通过`#output div`元素告诉服务器我们已经这样做了。

当服务器收到`Hello`时，它会回复`socket.io!`，这会触发客户端的`message`事件回调。

现在我们有了`msg`参数（与我们的`msg Hello`变量不同），其中包含来自服务器的消息，因此我们将其输出到我们的`#output div`元素。

## 还有更多...

`socket.io`建立在标准的 WebSocket API 之上。让我们探索一些`socket.io`的附加功能。

### 自定义事件

`socket.io`允许我们定义自己的事件，而不仅仅是`message, connect`和`disconnect`。我们以相同的方式监听自定义事件（使用`on`），但使用`emit`方法来初始化它们。

让我们从服务器向客户端`emit`一个自定义事件，然后通过向服务器发出另一个自定义事件来响应客户端。

我们可以使用与我们的配方相同的代码，我们将更改的唯一部分是`server.js`中`connection`事件监听器回调的内容（我们将其复制为`custom_events_server.js`）和`client.html`中`connect`事件处理程序的内容（我们将其复制为`custom_events_client.html`）。

因此，对于我们的服务器代码：

```js
//require http, load client.html, create plainHttpServer
//require and initialize socket.io, set origin rules

io.sockets.on('connection', function (socket) {
  socket.emit('hello', 'socket.io!');
  socket.on(''helloback, function (from) {
    console.log('Received a helloback from ' + from);
  });
});

```

我们的服务器发出一个`hello`事件，向新连接的客户端发送`socket.io!`，并等待来自客户端的`helloback`事件。

因此，我们相应地修改`custom_events_client.html`中的 JavaScript：

```js
//html structure, #output div, script[src=/socket.io/socket.io.js] tag
socket.on('connect', function () {
  socket.on('hello', function (msg) {
    output.innerHTML += '<div>Hello ' + msg + '</div>';
    socket.emit('helloback', 'the client');
  });
});

```

当我们收到`hello`事件时，我们记录到我们的`#output div`（其中将显示`Hello socket.io!`），并向服务器`emit`一个`helloback`事件，将客户端作为预期的`from`参数传递。

### 命名空间

使用`socket.io`，我们可以描述命名空间或路由，然后在客户端通过`io.connect`访问它们的 URL：

```js
io.connect('ws://localhost:8080/namespacehere');

```

**命名空间**允许我们在共享相同上下文的同时创建不同的范围。在`socket.io`中，命名空间用作为多个目的共享单个 WebSocket（或其他传输）连接的一种方式。请参阅[`en.wikipedia.org/wiki/Namespace`](http://en.wikipedia.org/wiki/Namespace)和[`en.wikipedia.org/wiki/Namespace_(computer_science)`](http://en.wikipedia.org/wiki/Namespace_(computer_science))。

通过一系列`io.connect`调用，我们能够定义多个 WebSocket 路由。但是，这不会创建多个连接到我们的服务器。`socket.io`将它们多路复用（或组合）为一个连接，并在服务器内部管理命名空间逻辑，这样成本就会低得多。

我们将通过将代码从第三章“使用 AJAX 在浏览器和服务器之间传输数据”中讨论的*数据序列化*的配方升级为基于`socket.io`的应用程序来演示命名空间。

首先，让我们创建一个文件夹，称之为`namespacing`，并将原始的`index.html, server.js, buildXml.js`和`profiles.js`文件复制到其中。`Profiles.js`和`buildXml.js`是支持文件，所以我们可以不管它们。

我们可以简化我们的`server.js`文件，删除与`routes`和`mimes`有关的所有内容，并将`http.createServer`回调减少到其最后的`response.end`行。我们不再需要 path 模块，因此我们将删除它，并最终将我们的服务器包装在`socket.io listen`方法中：

```js
var http = require('http');
var fs = require('fs');
var profiles = require('./profiles');
var buildXml = require('./buildXml');
var index = fs.readFileSync('index.html');
var io = require('socket.io').listen(
    http.createServer(function (request, response) {
      response.end(index);
    }).listen(8080)
  );

```

为了声明我们的命名空间及其连接处理程序，我们使用`of`如下：

```js
io.of('/json').on('connection', function (socket) {
  socket.on('profiles', function (cb) {
    cb(Object.keys(profiles));
  });

  socket.on('profile', function (profile) {
    socket.emit('profile', profiles[profile]);
  });
});

io.of('/xml').on('connection', function (socket) {
  socket.on('profile', function (profile) {
    socket.emit('profile', buildXml(profiles[profile]));
  });
});

```

在我们的`index.html`文件中，我们包括`socket.io.js`，并连接到命名空间：

```js
<script src=socket.io/socket.io.js></script>
<script>
(function () {  // open anonymous function to protect global scope
  var formats = {
    json: io.connect('ws://localhost:8080/json'),
    xml: io.connect('ws://localhost:8080/xml')
  };
formats.json.on('connect', function () {
  $('#profiles').html('<option></option>');
   this.emit('profiles', function (profile_names) {
      $.each(profile_names, function (i, pname) {
       $('#profiles').append('<option>' + pname + '</option>');
      });
   });
});

$('#profiles, #formats').change(function () {
  var socket = formats[$('#formats').val()];  
  socket.emit('profile', $('#profiles').val());
});

formats.json.on('profile', function(profile) {
    $('#raw').val(JSON.stringify(profile));
    $('#output').html('');
    $.each(profile, function (k, v) {
          $('#output').append('<b>' + k + '</b> : ' + v + '<br>');
        });
});

formats.xml.on('profile', function(profile) {
      $('#raw').val(profile);
      $('#output').html('');
       $.each($(profile)[1].nextSibling.childNodes,
          function (k, v) {
            if (v && v.nodeType === 1) {
              $('#output').append('<b>' + v.localName + '</b> : '
		     + v.textContent + '<br>');
            }
          });  
}());

```

一旦连接，服务器将使用`profile_names`数组发出`profiles`事件，我们的客户端接收并处理它。我们的客户端向相关命名空间发出自定义`profile`事件，并且每个命名空间套接字都会监听来自服务器的`profile`事件，并根据其格式进行处理（由命名空间确定）。

命名空间允许我们分离关注点，而无需使用多个`socket.io`客户端（由于多路复用）。与 WebSocket 中的子协议概念类似，我们可以将某些行为限制在某些命名空间中，从而使我们的代码更易读，并减轻多方面实时 Web 应用程序中涉及的心理复杂性。

## 另请参阅

+   *在本章中讨论的创建 WebSocket 服务器*

+   *在本章中讨论的通过 socket.io 传输回调*

+   *在本章中讨论的创建实时小部件*

# 通过 socket.io 传输回调

使用`socket.io`，我们可以通过 WebSockets（或相关的回退）执行回调函数。该函数在客户端定义，但在服务器端调用（反之亦然）。这可以是在客户端和服务器之间共享处理资源和功能的非常强大的方式。

在这个配方中，我们将创建一种让服务器调用客户端函数的方法，该函数可以对一个数字进行平方，并且让客户端调用一个将句子的 Base64 编码（[`en.wikipedia.org/wiki/Base64`](http://en.wikipedia.org/wiki/Base64)）发送回客户端的服务器端函数。

## 准备工作

我们只需要创建一个新文件夹，其中包括新的`client.html`和`server.js`文件。

## 如何做...

在我们的服务器上，与以前一样，我们加载我们的`http`模块和`client.html`文件，创建我们的 HTTP 服务器，附加`socket.io`，并设置`origins`策略。

```js
var http = require('http');
var clientHtml = require('fs').readFileSync('client.html');

var plainHttpServer = http.createServer(function (request, response) {
    response.writeHead(200, {'Content-type' : 'text/html'});
    response.end(clientHtml);
  }).listen(8080);

var io = require('socket.io').listen(plainHttpServer);
io.set('origins', ['localhost:8080', '127.0.0.1:8080']);

```

接下来，在我们的`connection`事件处理程序中，我们监听来自客户端的自定义事件`give me a number`，并从服务器`emit`一个自定义事件`give me a sentence`。

```js
io.sockets.on('connection', function (socket) {

  socket.on('give me a number', function (cb) {
    cb(4);
  });

  socket.emit('give me a sentence', function (sentence) {
    socket.send(new Buffer(sentence).toString('base64'));
  });

});

```

在我们的`client.html`文件中：

```js
<html>
<head> </head>
<body>
<div id=output></div>
<script src="img/socket.io.js"></script>
<script>
  var socket = io.connect('http://localhost:8080'),
    output = document.getElementById('output');

  function square(num) {
    output.innerHTML = "<div>" + num + " x " + num + " is "
						   + (num * num) + "</div>";
  }

  socket.on('connect', function () {  
    socket.emit('give me a number', square);

    socket.on('give me a sentence', function (cb) {
      cb('Ok, here is a sentence.');
    });

   socket.on('message', function (msg) {
      output.innerHTML += '<div>Recieved: ' + msg + '</div>';
    });
  });

</script>
</body> </html>

```

## 它是如何工作的...

连接后立即，服务器和客户端都会相互`emit`一个自定义的`socket.io`事件。

有关自定义`socket.io`事件，请参阅上一个配方*与 socket.io 无缝回退*的*还有更多..*部分。

对于客户端和服务器，当我们将函数作为`emit, socket.io`的第二个参数传递时，`socket.io`会在相应的事件监听器的回调中创建一个特殊的参数（`cb`）。在这种情况下，`cb`不是实际的函数（如果是，它将在调用它的上下文中简单运行），而是一个内部的`socket.io`函数，它将参数传递回到电线的另一侧的`emit`方法。然后`emit`将这些参数传递给它的回调函数，从而在本地上下文中执行函数。

我们知道这些函数在自己的上下文中运行。如果服务器端的`give me a sentence`回调在客户端上执行，它将失败，因为浏览器中没有`Buffer`对象。如果`give me a number`在服务器上运行，它将失败，因为 Node 中没有 DOM（文档对象模型）（也就是说，没有 HTML，因此没有`document`对象和`document.getElementById`方法）。

## 还有更多...

`socket.io`可以成为更高级专业化框架的良好基础。

### 使用 Nowjs 共享函数

Nowjs 将`socket.io`的回调功能推断为更简单的 API，允许我们通过客户端上的全局`now`对象和服务器上的`everyone.now`对象共享函数。让我们获取`now`模块：

```js
npm install now 

```

设置 Nowjs 让人不寒而栗：

```js
var http = require('http');
var clientHtml = require('fs').readFileSync('now_client.html');

var plainHttpServer = http.createServer(function (request, response) {
    response.writeHead(200, {'Content-type' : 'text/html'});
    response.end(clientHtml);
  }).listen(8080);

var everyone = require('now').initialize(plainHttpServer);
everyone.set('origins', ['localhost:8080', '127.0.0.1:8080']);

```

`clientHtml`文件加载`now_client.html`，而不是`io`，我们有`everyone`，而不是调用`listen`，我们调用`initialize`。到目前为止，其他一切都是一样的（当然，需要`now`而不是`socket.io`）。

我们将使用`now`重新实现我们的配方，以完成我们放置的服务器。

```js
everyone.now.base64 = function(sentence, cb) {
  cb(new Buffer(sentence).toString('base64'));
}

everyone.on('connect', function () {
  this.now.square(4);
});

```

让我们将服务器保存为`now_server.js`，在`now_client.html`中编写以下代码：

```js
<html>
<head></head>
<body>
<div id=output></div>
<script src="img/now.js"></script>
<script>  
var output = document.getElementById('output');
now.square = function (num) {
  output.innerHTML = "<div>" + num + " x " + num + " is " + (num * num) + "</div>";
}

now.ready(function () {  
  now.base64('base64 me server side, function (msg) {
    output.innerHTML += '<div>Recieved: ' + msg + '</div>';
  });
});
</script>
</body></html>

```

NowJS 使函数共享变得微不足道。在服务器端，我们只需在`everyone.now`上设置我们的`base64`方法，这样`base64`就可以在所有客户端上使用。

然后我们监听`connect`事件，当它发生时，我们调用`this.now.square`。在这个上下文中，`this`是我们客户端的 socket，所以`this.now.square`调用`now_client.html`中包含的`now.square`方法。

在我们的客户端中，我们不是加载`socket.io.js`，而是包含`now.js`，其路由在服务器初始化时公开。这为我们提供了全局的`now`对象，我们在其中设置我们的`square`函数方法。

一旦建立连接（使用`now.ready`检测），我们使用回调调用`now.base64`从服务器到客户端拉取数据。

## 另请参阅

+   *与 socket.io 无缝回退*在本章中讨论

+   *在本章中讨论创建实时小部件*

+   *通过 AJAX 进行浏览器-服务器传输在* 第三章 *中讨论，与数据序列化一起工作*

# 创建一个实时小部件

socket.io 的配置选项和深思熟虑的方法使其成为一个非常灵活的库。让我们通过制作一个实时小部件来探索`socket.io`的灵活性，该小部件可以放置在任何网站上，并立即与远程`socket.io`服务器进行接口，以开始提供当前网站上所有用户的不断更新的总数。我们将其命名为“实时在线计数器（loc）”。

我们的小部件是为了方便用户使用，应该需要非常少的知识才能使其工作，因此我们希望有一个非常简单的接口。通过`script`标签加载我们的小部件，然后使用预制的`init`方法初始化小部件将是理想的（这样我们可以在初始化之前预定义属性，如果有必要的话）。

## 准备就绪

我们需要创建一个新的文件夹，其中包含一些新文件：`widget_server.js，widget_client.js，server.js`和`index.html`。

在开始之前，让我们还从`npm`获取`socket.io-client`模块。我们将使用它来构建我们的自定义`socket.io`客户端代码。

```js
npm install socket.io-client 

```

## 如何做...

让我们创建`index.html`来定义我们想要的界面类型，如下所示：

```js
<html>
<head>
<style>
#_loc {color:blue;} /* widget customization */
</style>
</head>
<body>
<h1> My Web Page </h1>
<script src=http://localhost:8081/loc/widget_server.js></script>
<script> locWidget.init(); </script>
</body></html>

```

我们希望向`/loc/widget_server.js`公开一个路由，其中包含我们的 loc 小部件。在幕后，我们的小部件将保存在`widget_client.js`中。

所以让我们做一下：

```js
  window.locWidget = {
    style : 'position:absolute;bottom:0;right:0;font-size:3em',
    init : function () {
      var socket = io.connect('http://localhost:8081', {resource: 'loc'}),
        style = this.style;
      socket.on('connect', function () {
        var head = document.getElementsByTagName('head')[0],
          body = document.getElementsByTagName('body')[0],
          loc = document.getElementById('_lo_count');
        if (!loc) {
          head.innerHTML = '<style>#_loc {' + style + '}</style>'
            + head.innerHTML;

          body.innerHTML +=
            '<div id=_loc>Online: <span id=_lo_count></span></div>';

          loc = document.getElementById('_lo_count');
        }

        socket.on('total', function (total) {
          loc.innerHTML = total;
        });
      });
    }
  }

```

我们需要从多个域测试我们的小部件，因此我们将实现一个快速的 HTTP 服务器（`server.js`）来提供`index.html`，以便我们可以通过`http://127.0.0.1:8080`和`http://localhost:8080`访问它，这样我们就可以获得多个域。

```js
var http = require('http');
var fs = require('fs');
var clientHtml = fs.readFileSync('index.html');

http.createServer(function (request, response) {
    response.writeHead(200, {'Content-type' : 'text/html'});
    response.end(clientHtml);
}).listen(8080);

```

最后，我们的小部件服务器，在`widget_server.js`中编写：

```js
var io = require('socket.io').listen(8081);
var sioclient = require('socket.io-client');
var widgetScript = require('fs').readFileSync('widget_client.js');
var url = require('url');

var totals = {};

io.configure(function () {
  io.set('resource', '/loc');
  io.enable('browser client gzip');
});

sioclient.builder(io.transports(), function (err, siojs) {
  if (!err) {
    io.static.add('/widget.js', function (path, callback) {
      callback(null, new Buffer(siojs + ';' + widgetScript));
    });
  }
});

io.sockets.on('connection', function (socket) {
  var origin = (socket.handshake.xdomain)
    ? url.parse(socket.handshake.headers.origin).hostname
    : 'local';

  totals[origin] = (totals[origin]) || 0;
  totals[origin] += 1;
  socket.join(origin);

  io.sockets.to(origin).emit('total', totals[origin]);
  socket.on('disconnect', function () {
    totals[origin] -= 1;
    io.sockets.to(origin).emit('total', totals[origin]);
  });
});

```

为了测试，我们需要两个终端，在一个终端中执行：

```js
node widget_server.js 

```

在另一个终端中执行：

```js
node server.js 

```

如果我们将浏览器指向`http://localhost:8080`，打开一个新的标签页或窗口并导航到`http://localhost:8080`。同样，我们将看到计数器增加一个。如果我们关闭任一窗口，它将减少一个。我们还可以导航到`http://127.0.0.1:8080`以模拟一个独立的来源。该地址上的计数器与`http://localhost:8080`上的计数器是独立的。

## 它是如何工作的...

`widget_server.js`是这个配方的核心。我们首先需要`socket.io`并调用`listen`方法。与之前的任务不同，我们不是将其作为`httpServer`实例传递，而是将其传递给端口号`8081`。如果我们将`ws://localhost:8081`视为许多客户端小部件连接到的远程服务器，这将有所帮助。

下一个要求是`socket.io-client`，我们将其加载到我们的`sioclient`变量中。

通过`sioclient`，我们可以访问`sioclient.builder`方法来生成一个`socket.io.js`文件。将其连接到`widgetScript`以有效地创建一个包含`socket.io.js`和`widget_client.js`的单个 JavaScript 文件。我们将 HTTP 路由命名为此文件`widget.js`。将`socket.io.js`文件连接到我们的`widgetScript`时，我们在两者之间放置一个分号，以确保脚本不会相互干扰。

我们向`builder`方法传递了两个参数，第一个是传输数组。这些是创建实时效果的各种方法（例如 WebSockets，AJAX（xhr）轮询）。数组中较早出现的传输方法更受青睐。数组是使用`transports`方法生成的。由于我们在配置期间没有设置任何传输，因此提供了默认传输数组。第二个参数是回调。在这里，我们可以通过`siojs`参数获取生成的`socket.io.js`文件。

我们的小部件纯粹是 JavaScript 的事务，可以插入到任何网站的任何 HTML 页面中。`socket.io`有一个内部 HTTP 服务器用于提供 JavaScript 客户端文件。我们使用`io.static.add`（一旦我们有了生成的`socket.io.js`）将一个新的路由推送到`socket.io`的内部 HTTP 服务器上，而不是创建一个 HTTP 服务器来提供我们的客户端小部件代码。`io.static.add`的第二个参数是一个回调函数，其中又有一个传递给它的函数名为`callback`。

`callback`是`socket.io`的一部分，它将内容添加到新定义的路由。第一个参数可以指向一个文字文件，但我们正在动态生成代码，所以我们传递`null`。对于第二个参数，我们将`siojs`与`widgetScript`传递给`Buffer`，然后创建我们的路由。

通过更改`resource`属性以更改到`socket.io`的内部 HTTP 服务器路由的路由，`io.set`帮助我们为我们的小部件进行品牌推广。因此，我们的组合`widget.js`路由将不再出现在`/socket.io/widget.js`，而是将出现在`/loc/widget.js`。

为了从客户端连接到我们配置的静态资源路由，我们必须在`widget_client.js`中向`io.connect`传递一个`options`对象。请注意斜杠前缀的缺失。斜杠前缀在服务器端是强制性的，但对于客户端来说是必须省略的。

现在舞台已经为实际的套接字操作做好了准备。我们通过在`io.sockets`上监听`connection`事件来等待连接。在事件处理程序内部，我们使用了一些尚未讨论的`socket.io`特性。

当客户端发起 HTTP 握手请求并且服务器肯定地响应时，WebSocket 就形成了。`socket.handshake`包含握手的属性。

`socket.handshake.xdomain`告诉我们握手是否是从同一服务器发起的。在检索`socket.handshake.headers.origin`的`hostname`之前，我们将检查跨服务器握手。

相同域名握手的来源要么是`null`，要么是`undefined`（取决于它是本地文件握手还是本地主机握手）。后者会导致`url.parse`出错，而前者则不理想。因此，对于相同域名握手，我们只需将我们的`origin`变量设置为`local`。

我们提取（并简化）`origin`，因为它允许我们区分使用小部件的网站，从而实现特定于网站的计数。

为了计数，我们使用我们的`totals`对象，并为每个新的`origin`添加一个初始值为`0`的属性。在每次连接时，我们将`1`添加到`totals[origin]`，并监听我们的`socket`以获取`disconnect`事件，从`totals[origin]`中减去`1`。

如果这些值仅用于服务器使用，我们的解决方案将是完整的。但是，我们需要一种方法来向客户端通信总连接数，但仅限于他们所在的网站。

`socket.io`自版本 7 以来有一个方便的新功能，它允许我们使用`socket.join`方法将套接字分组到房间中。我们让每个套接字加入以其`origin`命名的房间，然后我们使用`io.sockets.to(origin).emit`方法指示`socket.io`只向属于原始`sites`房间的套接字`emit`。

在`io.sockets connection`事件和`socket disconnect`事件中，我们向相应的套接字`emit`我们特定的`totals`，以便更新每个客户端连接到用户所在网站的总连接数。

`widget_client.js`简单地创建一个名为`#_loc`的`div`，并使用它更新从`widget_server.js`接收到的任何新的`totals`。

## 还有更多...

让我们看看如何使我们的应用程序更具可扩展性，以及 WebSocket 的另一个用途。

### 为可扩展性做准备

如果我们要为成千上万的网站提供服务，我们需要可扩展的内存存储，Redis 将是一个完美的选择。它在内存中运行，但也允许我们跨多个服务器进行扩展。

### 注意

我们需要安装 Redis，以及 `redis` 模块。更多信息请参见第四章，与数据库交互

我们将修改我们的 `totals` 变量，使其包含一个 Redis 客户端而不是一个 JavaScript 对象：

```js
var totals = require('redis').createClient();

```

现在我们修改我们的 `connection` 事件处理程序如下：

```js
io.sockets.on('connection', function (socket) {
  var origin = (socket.handshake.xdomain)
    ? url.parse(socket.handshake.headers.origin).hostname
    : 'local';
  socket.join(origin);

  totals.incr(origin, function (err, total) {
    io.sockets.to(origin).emit('total', total);  
  });

  socket.on('disconnect', function () {
    totals.decr(origin, function (err, total) {
      io.sockets.to(origin).emit('total', total); 
    });
  });
});

```

我们不再将 `totals[origin]` 加一，而是使用 Redis 的 `INCR` 命令来增加一个名为 `origin` 的 Redis 键。如果键不存在，Redis 会自动创建它。当客户端断开连接时，我们会执行相反的操作，并使用 `DECR` 调整 `totals`。

### WebSockets 作为开发工具

在开发网站时，我们经常在编辑器中更改一些小东西，上传我们的文件（如果需要），刷新浏览器，然后等待看到结果。如果浏览器在我们保存与网站相关的任何文件时自动刷新会怎么样？我们可以通过 `fs.watch` 和 WebSockets 实现这一点。`fs.watch` 监视一个目录，在文件夹中的任何文件发生更改时执行回调（但它不监视子文件夹）。

### 注意

`fs.watch` 是依赖于操作系统的。到目前为止，`fs.watch` 也一直存在着历史性的 bug（主要是在 Mac OS X 下）。因此，在进一步改进之前，`fs.watch` 更适合于开发环境而不是生产环境（您可以通过查看这里的已打开和已关闭的问题来监视 `fs.watch` 的运行情况：[`github.com/joyent/node/issues/search?q=fs.watch)`](https://github.com/joyent/node/issues/search?q=fs.watch)）。

我们的开发工具可以与任何框架一起使用，从 PHP 到静态文件。对于一个通用的服务器，让我们从第一章中的 *提供静态文件* 这个配方中测试我们的工具。我们将文件（包括 `content` 文件夹）从该配方复制到一个新文件夹中，我们可以将其命名为 `watcher`。

对于我们工具的服务器端对应部分，我们将创建 `watcher.js`：

```js
var fs = require('fs');
var io = require('socket.io').listen(8081);
var sioclient = require('socket.io-client');

var watcher = [';(function () {',
               '  var socket = io.connect(\'ws://localhost:8081\');',
               '  socket.on(\'update\', function () {',
               '    location.reload()',
               '  });',
               '}())'].join('');

sioclient.builder(io.transports(), function (err, siojs) {
  if (!err) {
    io.static.add('/watcher.js', function (path, callback) {
      callback(null, new Buffer(siojs + watcher));
    });
  }
});

fs.watch('content', function (e, f) {
  if (f[0] !== '.') {
    io.sockets.emit('update');
  }
});

```

这段代码大部分都很熟悉。我们创建了一个 `socket.io` 服务器（在不同的端口上以避免冲突），生成了一个连接的 `socket.io.js` 加上客户端 `watcher` 代码文件，并将其添加到 `socket.io` 的静态资源中。由于这是我们自己开发使用的一个快速工具，我们的客户端代码被写成一个字符串赋值给 `watcher` 变量。

最后一段代码调用了 `fs.watch` 方法，其中回调接收事件名称（`e`）和文件名（`f`）。

我们检查文件名是否不是隐藏的点文件。在保存事件期间，一些文件系统或编辑器会更改目录中的隐藏文件，从而触发多个回调，发送多个消息，速度很快，这可能会对浏览器造成问题。

要使用它，我们只需将其放置在每个页面中作为脚本（可能使用服务器端模板）。然而，为了演示目的，我们只需将以下代码放入 `content/index.html` 中：

```js
<script src=http://localhost:8081/socket.io/watcher.js></script>

```

一旦我们启动了 `server.js` 和 `watcher.js`，我们就可以将浏览器指向 `http://localhost:8080`，并从第一章中看到熟悉的激动人心的 **Yay!**。我们所做的任何更改和保存（无论是对 `index.html, styles.css, script.js` 进行更改，还是添加新文件）几乎会立即在浏览器中反映出来。我们可以做的第一个更改是摆脱 `script.js` 中的警报框，以便更流畅地看到更改。

## 另见

+   *创建 WebSocket 服务器* 在本章中讨论

+   *使用 socket.io 实现无缝回退* 在本章中讨论

+   *使用 Redis 存储和检索数据* 在第四章中讨论
