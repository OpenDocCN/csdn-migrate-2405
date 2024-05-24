# MongoDB 秘籍（三）

> 原文：[`zh.annas-archive.org/md5/9F335F41611FE256D46F623124D9DAEC`](https://zh.annas-archive.org/md5/9F335F41611FE256D46F623124D9DAEC)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：高级操作

在本章中，我们将涵盖以下内容：

+   原子查找和修改操作

+   在 Mongo 中实现原子计数器

+   实现服务器端脚本

+   在 MongoDB 中创建和追踪封顶集合游标

+   将普通集合转换为封顶集合

+   在 Mongo 中存储二进制数据

+   使用 GridFS 在 Mongo 中存储大数据

+   从 Java 客户端将数据存储到 GridFS

+   从 Python 客户端将数据存储到 GridFS

+   使用 oplog 在 Mongo 中实现触发器

+   在 Mongo 中使用平面（2D）地理空间索引进行查询

+   在 Mongo 中使用球形索引和 GeoJSON 兼容数据

+   在 Mongo 中实现全文搜索

+   将 MongoDB 集成到 Elasticsearch 进行全文搜索

# 介绍

在第二章中，*命令行操作和索引*，我们看到了如何从 shell 执行基本操作来查询、更新和插入文档，还看到了不同类型的索引和索引创建。在本章中，我们将看到 Mongo 的一些高级功能，如 GridFS、地理空间索引和全文搜索。我们还将看到其他配方，包括封顶集合的介绍和使用以及在 MongoDB 中实现服务器端脚本。

# 原子查找和修改操作

在第二章中，*命令行操作和索引*，我们有一些配方解释了我们在 MongoDB 中执行的各种 CRUD 操作。有一个概念我们没有涵盖到，那就是原子查找和修改文档。修改包括更新和删除操作。在这个配方中，我们将介绍 MongoDB 的`findAndModify`操作的基础知识。在下一个配方中，我们将使用这种方法来实现一个计数器。

## 准备就绪

查看第一章中的*安装单节点 MongoDB*和*安装和启动服务器*的配方，并启动 MongoDB 的单个实例。这是这个配方的唯一先决条件。启动 mongo shell 并连接到已启动的服务器。

## 如何操作…

1.  我们将在`atomicOperationsTest`集合中测试一个文档。从 shell 执行以下操作：

```sql
> db.atomicOperationsTest.drop()
> db.atomicOperationsTest.insert({i:1})

```

1.  从 mongo shell 执行以下操作并观察输出：

```sql
> db.atomicOperationsTest.findAndModify({
 query: {i: 1},
 update: {$set : {text : 'Test String'}},
 new: false
 }
)

```

1.  这次我们将执行另一个操作，但参数略有不同；观察此操作的输出：

```sql
> db.atomicOperationsTest.findAndModify({
 query: {i: 1},
 update: {$set : {text : 'Updated String'}}, fields: {i: 1, text :1, _id:0},
 new: true
 }
)

```

1.  这次我们将执行另一个更新，将会插入文档，如下所示：

```sql
>db.atomicOperationsTest.findAndModify({
 query: {i: 2},
 update: {$set : {text : 'Test String'}},
 fields: {i: 1, text :1, _id:0},
 upsert: true,
 new: true
 }
)

```

1.  现在，按照以下方式查询集合并查看当前存在的文档：

```sql
> db.atomicOperationsTest.find().pretty()

```

1.  最后，我们将按以下方式执行删除：

```sql
>db.atomicOperationsTest.findAndModify({
 query: {i: 2},
 remove: true,
 fields: {i: 1, text :1, _id:0},
 new: false
 }
)

```

## 工作原理…

如果我们在 MongoDB 中首先查找文档，然后再更新它，结果可能不如预期。在查找和更新操作之间可能存在交错的更新，这可能已更改文档状态。在某些特定用例中，比如实现原子计数器，这是不可接受的，因此我们需要一种方法来原子地查找、更新和返回文档。返回的值是在更新应用之前或之后的值，由调用客户端决定。

现在我们已经执行了前一节中的步骤，让我们看看我们实际做了什么，以及作为参数传递给`findAndModify`操作的 JSON 文档中的所有这些字段的含义。从第 3 步开始，我们将一个包含字段`query`、`update`和`new`的文档作为参数传递给`findAndModify`函数。

`query`字段指定用于查找文档的搜索参数，`update`字段包含需要应用的修改。第三个字段`new`，如果设置为`true`，告诉 MongoDB 返回更新后的文档。

在第 4 步中，我们实际上向作为参数传递的文档添加了一个名为**fields**的新字段，用于从返回的结果文档中选择一组有限的字段。此外，`new`字段的值为`true`，表示我们希望更新的文档，即在执行更新操作之后的文档，而不是之前的文档。

第 5 步包含一个名为`upsert`的新字段，该字段执行 upsert（更新+插入）文档。也就是说，如果找到具有给定查询的文档，则更新该文档，否则创建并更新一个新文档。如果文档不存在并且发生了 upsert，那么将参数`new`的值设置为`false`将返回`null`。这是因为在执行更新操作之前没有任何内容存在。

最后，在第 7 步中，我们使用了`remove`字段，其值为`true`，表示要删除文档。此外，`new`字段的值为`false`，这意味着我们期望被删除的文档。

## 另请参阅

原子`FindandModify`操作的一个有趣的用例是在 Mongo 中开发原子计数器。在下一个配方中，我们将看到如何实现这个用例。

# 在 Mongo 中实现原子计数器

原子计数器是许多用例的必需品。Mongo 没有原子计数器的内置功能；然而，可以使用一些其很酷的功能很容易地实现。事实上，借助先前描述的`findAndModify()`命令，实现起来非常简单。参考之前的配方*原子查找和修改操作*，了解 Mongo 中的原子查找和修改操作是什么。

## 准备就绪

查看第一章中的配方*安装单节点 MongoDB*，开始 Mongo 的单个实例。这是此配方的唯一先决条件。启动 mongo shell 并连接到已启动的服务器。

## 如何操作…

1.  从 mongo shell 中执行以下代码：

```sql
> function getNextSequence(counterId) {
 return db.counters.findAndModify(
 {
 query: {_id : counterId},
 update: {$inc : {count : 1}},
 upsert: true,
 fields:{count:1, _id:0},
 new: true
 }
 ).count
}

```

1.  现在从 shell 中调用以下命令：

```sql
> getNextSequence('Posts Counter')
> getNextSequence('Posts Counter')
> getNextSequence('Profile Counter')

```

## 工作原理…

该函数就是在用于存储所有计数器的集合上执行的`findAndModify`操作。计数器标识符是存储的文档的`_id`字段，计数器的值存储在`count`字段中。传递给`findAndModify`操作的文档接受查询，该查询唯一标识存储当前计数的文档，即使用`_id`字段的查询。更新操作是一个`$inc`操作，将通过 1 递增`count`字段的值。但是如果文档不存在怎么办？这将发生在对计数器的第一次调用。为了处理这种情况，我们将将`upsert`标志设置为`true`。`count`的值将始终从 1 开始，没有办法接受任何用户定义的序列起始数字或自定义递增步长。为了满足这样的要求，我们将不得不将具有初始化值的文档添加到计数器集合中。最后，我们对计数器值递增后的状态感兴趣；因此，我们将`new`字段的值设置为`true`。

在调用此方法三次（就像我们做的那样）后，我们应该在计数器集合中看到以下内容。只需执行以下查询：

```sql
>db.counters.find()
{ "_id" : "Posts Counter", "count" : 2 }
{ "_id" : "Profile Counter", "count" : 1 }

```

使用这个小函数，我们现在已经在 Mongo 中实现了原子计数器。

## 另请参阅

我们可以将这样的通用代码存储在 Mongo 服务器上，以便在其他函数中执行。查看配方*实现服务器端脚本*，了解如何在 Mongo 服务器上存储 JavaScript 函数。这甚至允许我们从其他编程语言客户端调用此函数。

# 实现服务器端脚本

在这个配方中，我们将看到如何编写服务器存储的 JavaScript，类似于关系数据库中的存储过程。这是一个常见的用例，其他代码片段需要访问这些常见函数，我们将它们放在一个中心位置。为了演示服务器端脚本，该函数将简单地添加两个数字。

这个配方有两个部分。首先，我们看看如何从客户端 JavaScript shell 中的集合加载脚本，其次，我们将看到如何在服务器上执行这些函数。

### 注意

文档明确提到不建议使用服务器端脚本。安全性是一个问题，尽管如果数据没有得到适当的审计，因此我们需要小心定义哪些函数。自 Mongo 2.4 以来，服务器端 JavaScript 引擎是 V8，可以并行执行多个线程，而不是 Mongo 2.4 之前的引擎，每次只能执行一个线程。

## 准备工作

查看第一章中的配方*安装单节点 MongoDB*，*安装和启动服务器*并启动 Mongo 的单个实例。这是这个配方的唯一先决条件。启动一个 mongo shell 并连接到已启动的服务器。

## 如何做...

1.  创建一个名为`add`的新函数，并将其保存到集合`db.system.js`中，如下所示。当前数据库应该是 test：

```sql
> use test
> db.system.js.save({ _id : 'add', value : function(num1, num2) {return num1 + num2}})

```

1.  现在这个函数已经定义，加载所有函数如下：

```sql
> db.loadServerScripts()

```

1.  现在，调用`add`并查看是否有效：

```sql
> add(1, 2)

```

1.  现在我们将使用这个函数，并在服务器端执行它：从 shell 执行以下操作：

```sql
> use test
> db.eval('return add(1, 2)')

```

1.  执行以下步骤（可以执行前面的命令）：

```sql
> use test1
> db.eval('return add(1, 2)')

```

## 它是如何工作的...

集合`system.js`是一个特殊的 MongoDB 集合，用于存储 JavaScript 代码。我们使用该集合中的`save`函数添加一个新的服务器端 JavaScript。`save`函数只是一个方便的函数，如果文档不存在则插入文档，如果文档已存在则更新文档。目标是向该集合添加一个新文档，即使您可以使用`insert`或`upsert`来添加。

秘密在于`loadServerScripts`方法。让我们看看这个方法的代码：`this.system.js.find().forEach(function(u){eval(u._id + " = " + u.value);});`

它使用`eval`函数评估 JavaScript，并为`system.js`集合中每个文档的`value`属性中定义的函数分配一个与文档的`_id`字段中给定的名称相同的变量。

例如，如果集合`system.js`中存在以下文档，`{ _id : 'add', value : function(num1, num2) {return num1 + num2}}`，那么文档的`value`字段中给定的函数将分配给当前 shell 中名为`add`的变量。文档的`_id`字段中给定了值`add`。

这些脚本实际上并不在服务器上执行，但它们的定义存储在服务器的一个集合中。JavaScript 方法`loadServerScripts`只是在当前 shell 中实例化一些变量，并使这些函数可用于调用。执行这些函数的是 shell 的 JavaScript 解释器，而不是服务器。集合`system.js`在数据库的范围内定义。一旦加载，这些函数就像在 shell 中定义的 JavaScript 函数一样，在 shell 的范围内都是可用的，而不管当前活动的数据库是什么。

就安全性而言，如果 shell 连接到启用了安全性的服务器，则调用`loadServerScripts`的用户必须具有读取数据库中集合的权限。有关启用安全性和用户可以拥有的各种角色的更多详细信息，请参阅第四章中的食谱*在 Mongo 中设置用户*，*管理*。正如我们之前所看到的，`loadServerScripts`函数从`system.js`集合中读取数据，如果用户没有权限从该集合中读取数据，则函数调用将失败。除此之外，从加载后的 shell 中执行的函数应该具有适当的权限。例如，如果函数在任何集合中插入/更新数据，则用户应该对从函数访问的特定集合具有读取和写入权限。

在服务器上执行脚本可能是人们期望的服务器端脚本，而不是在连接的 shell 中执行。在这种情况下，函数在服务器的 JavaScript 引擎上进行评估，安全检查更为严格，因为长时间运行的函数可能会持有锁，对性能产生不利影响。在服务器端调用 JavaScript 代码执行的包装器是`db.eval`函数，接受要在服务器端评估的代码以及参数（如果有）。

在评估函数之前，写操作会获取全局锁；如果使用参数`nolock`，则可以跳过这一步。例如，可以按照以下方式调用前面的`add`函数，而不是调用`db.eval`并获得相同的结果。我们另外提供了`nolock`字段，指示服务器在评估函数之前不要获取全局锁。如果此函数要在集合上执行写操作，则`nolock`字段将被忽略。

```sql
> db.runCommand({eval: function (num1, num2) {return num1 + num2}, args:[1, 2],nolock:true})

```

如果服务器启用了安全性，则调用用户需要具有以下四个角色：`userAdminAnyDatabase`、`dbAdminAnyDatabase`、`readWriteAnyDatabase`和`clusterAdmin`（在管理数据库上）才能成功调用`db.eval`函数。

编程语言确实提供了一种调用这种服务器端脚本的方法，使用`eval`函数。例如，在 Java API 中，类`com.mongodb.DB`有一个方法`eval`来调用服务器端的 JavaScript 代码。当我们想要避免数据不必要的网络流量并将结果传递给客户端时，这种服务器端执行非常有用。然而，在数据库服务器上有太多的逻辑可能会很快使事情难以维护，并严重影响服务器的性能。

### 注意

截至 MongoDB 3.0.3，`db.eval()`方法已被弃用，建议用户不要依赖该方法，而是使用客户端脚本。有关更多详细信息，请参阅[`jira.mongodb.org/browse/SERVER-17453`](https://jira.mongodb.org/browse/SERVER-17453)。

# 在 MongoDB 中创建和追踪固定大小集合的游标

固定大小的集合是固定大小的集合，其中文档被添加到集合的末尾，类似于队列。由于固定大小的集合有一个固定的大小，如果达到限制，旧的文档将被删除。

它们按插入顺序自然排序，任何需要按时间顺序检索的检索都可以使用`$natural`排序顺序进行检索。这使得文档检索非常快速。

下图给出了一个有限大小的集合的图形表示，足以容纳最多三个相等大小的文档（对于任何实际用途来说都太小，但用于理解是很好的）。正如我们在图像中所看到的，该集合类似于循环队列，其中最旧的文档将被新添加的文档替换，如果集合变满。可追加的游标是特殊类型的游标，类似于 Unix 中的 tail 命令，它们遍历集合，类似于普通游标，但同时等待集合中的数据是否可用。我们将在本节详细介绍有限集合和可追加游标。

![在 MongoDB 中创建和追加有限集合游标](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-cb/img/B04831_05_01.jpg)

## 准备工作

查看第一章中的配方*安装单节点 MongoDB*，*安装和启动服务器*并启动 Mongo 的单个实例。这是本配方的唯一先决条件。启动 MongoDB shell 并连接到已启动的服务器。

## 操作步骤...

这个配方有两个部分：在第一部分中，我们将创建一个名为`testCapped`的有限集合，并尝试对其执行一些基本操作。接下来，我们将在这个有限集合上创建一个可追加游标。

1.  如果已存在具有此名称的集合，请删除该集合。

```sql
> db.testCapped.drop()

```

1.  现在按以下方式创建一个有限集合。请注意，此处给定的大小是为集合分配的字节数，而不是它包含的文档数量：

```sql
> db.createCollection('testCapped', {capped : true, size:100})

```

1.  现在我们将按以下方式在有限集合中插入 100 个文档：

```sql
> for(i = 1; i < 100; i++) {
db.testCapped.insert({'i':i, val:'Test capped'})
 }

```

1.  现在按以下方式查询集合：

```sql
> db.testCapped.find()

```

1.  尝试按以下方式从集合中删除数据：

```sql
> db.testCapped.remove()

```

1.  现在我们将创建并演示一个可追加游标。建议您将以下代码片段输入/复制到文本编辑器中，并随时准备执行。

1.  要在集合中插入数据，我们将使用以下代码片段。在 shell 中执行此代码片段：

```sql
> for(i = 101 ; i < 500 ; i++) {
 sleep(1000)
 db.testCapped.insert({'i': i, val :'Test Capped'})
}

```

1.  要追加有限集合，我们使用以下代码片段：

```sql
> var cursor = db.testCapped.find().addOption(DBQuery.Option.tailable).addOption(DBQuery.Option.awaitData)
while(cursor.hasNext()) {
 var next = cursor.next()
 print('i: ' + next.i + ', value: ' + next.val)
}

```

1.  打开一个 shell 并连接到正在运行的 mongod 进程。这将是第二个打开并连接到服务器的 shell。在此 shell 中复制并粘贴第 8 步中提到的代码，然后执行它。

1.  观察插入的记录如何显示为它们插入到有限集合中。

## 工作原理...

我们将使用`createCollection`函数显式创建一个有限集合。这是创建有限集合的唯一方法。`createCollection`函数有两个参数。第一个是集合的名称，第二个是一个包含两个字段`capped`和`size`的 JSON 文档，用于通知用户集合是否被限制以及集合的大小（以字节为单位）。还可以提供一个额外的`max`字段来指定集合中的最大文档数。即使指定了`max`字段，也需要`size`字段。然后我们插入和查询文档。当我们尝试从集合中删除文档时，我们会看到一个错误，即不允许从有限集合中删除文档。它只允许在添加新文档并且没有空间可容纳它们时才能删除文档。

接下来我们看到的是我们创建的可追溯游标。我们启动两个 shell，其中一个是以 1 秒的间隔插入文档的普通插入。在第二个 shell 中，我们创建一个游标并遍历它，并将从游标获取的文档打印到 shell 上。然而，我们添加到游标的附加选项使得有所不同。添加了两个选项，`DBQuery.Option.tailable`和`DBQuery.Option.awaitData`。这些选项用于指示游标是可追溯的，而不是正常的，其中最后的位置被标记，我们可以恢复到上次离开的位置，其次是在没有数据可用时等待更多数据一段时间，以及当我们接近游标的末尾时立即返回而不是返回。`awaitData`选项只能用于可追溯游标。这两个选项的组合使我们感觉类似于 Unix 文件系统中的 tail 命令。

有关可用选项的列表，请访问以下页面：[`docs.mongodb.org/manual/reference/method/cursor.addOption/`](http://docs.mongodb.org/manual/reference/method/cursor.addOption/)。

## 还有更多…

在下一个配方中，我们将看到如何将普通集合转换为固定集合。

# 将普通集合转换为固定集合

本配方将演示将普通集合转换为固定集合的过程。

## 准备就绪

查看第一章中的*安装单节点 MongoDB*和*安装和启动服务器*的配方，并启动 Mongo 的单个实例。这是本配方的唯一先决条件。启动 mongo shell 并连接到已启动的服务器。

## 如何做…

1.  执行以下操作以确保您在`test`数据库中：

```sql
> use test

```

1.  按照以下方式创建一个普通集合。我们将向其添加 100 个文档，将以下代码片段输入/复制到 mongo shell 上并执行。命令如下：

```sql
for(i = 1 ; i <= 100 ; i++) {
 db.normalCollection.insert({'i': i, val :'Some Text Content'})
}

```

1.  按照以下方式查询集合以确认其中包含数据：

```sql
> db.normalCollection.find()

```

1.  现在，按照以下方式查询集合`system.namespaces`，并注意结果文档：

```sql
> db.system.namespaces.find({name : 'test.normalCollection'})

```

1.  执行以下命令将集合转换为固定集合：

```sql
> db.runCommand({convertToCapped : 'normalCollection', size : 100})

```

1.  查询集合以查看数据：

```sql
> db.normalCollection.find()

```

1.  按照以下方式查询集合`system.namespaces`，并注意结果文档：

```sql
> db.system.namespaces.find({name : 'test.normalCollection'})

```

## 它是如何工作的…

我们创建了一个包含 100 个文档的普通集合，然后尝试将其转换为具有 100 字节大小的固定集合。命令将以下 JSON 文档传递给`runCommand`函数，`{convertToCapped: <普通集合的名称>, size: <固定集合的字节大小>}`。此命令创建一个具有指定大小的固定集合，并将文档以自然顺序从普通集合加载到目标固定集合中。如果固定集合的大小达到所述限制，旧文档将以 FIFO 顺序删除，为新文档腾出空间。完成后，创建的固定集合将被重命名。在固定集合上执行查找确认，最初在普通集合中存在的 100 个文档并不都存在于固定集合中。在执行`convertToCapped`命令之前和之后对`system.namespaces`集合进行查询，显示了`collection`属性的变化。请注意，此操作获取全局写锁，阻止此数据库中的所有读取和写入操作。此外，对于转换后的固定集合，不会创建原始集合上存在的任何索引。

## 还有更多…

Oplog 是 MongoDB 中用于复制的重要集合，是一个有上限的集合。有关复制和 oplogs 的更多信息，请参阅第四章中的*理解和分析 oplogs*，*管理*中的配方。在本章的后面的一个配方中，我们将使用这个 oplog 来实现类似于关系数据库中的插入/更新/删除触发器的功能。

# 在 Mongo 中存储二进制数据

到目前为止，我们看到了如何在文档中存储文本值、日期和数字字段。有时还需要在数据库中存储二进制内容。考虑用户需要在数据库中存储文件的情况。在关系数据库中，BLOB 数据类型最常用于满足这一需求。MongoDB 也支持将二进制内容存储在集合中的文档中。问题在于文档的总大小不应超过 16MB，这是写作本书时文档大小的上限。在这个配方中，我们将把一个小图像文件存储到 Mongo 的文档中，并在以后检索它。如果您希望存储在 MongoDB 集合中的内容大于 16MB，则 MongoDB 提供了一个名为**GridFS**的开箱即用的解决方案。我们将在本章的另一个配方中看到如何使用 GridFS。

## 准备工作

查看第一章中的*安装单节点 MongoDB*配方，*安装和启动服务器*并启动 MongoDB 的单个实例。还有一个用于将二进制内容写入文档的程序是用 Java 编写的。有关 Java 驱动程序的更多详细信息，请参阅第三章中的*使用 Java 客户端执行查询和插入操作*，*使用 Java 客户端实现 Mongo 中的聚合*和*使用 Java 客户端在 Mongo 中执行 MapReduce*的配方，*编程语言驱动程序*。打开一个 mongo shell 并连接到监听端口`27017`的本地 MongoDB 实例。对于这个配方，我们将使用项目`mongo-cookbook-bindata`。这个项目可以从 Packt 网站下载的源代码包中获取。需要在本地文件系统上提取文件夹。打开一个命令行 shell 并转到提取的项目的根目录。应该是找到文件`pom.xml`的目录。

## 如何做…

1.  在操作系统 shell 中，`mongo-cookbook-bindata`项目的当前目录中存在`pom.xml`，执行以下命令：

```sql
$ mvn exec:java -Dexec.mainClass=com.packtpub.mongo.cookbook.BinaryDataTest

```

1.  观察输出；执行应该成功。

1.  切换到连接到本地实例的 mongo shell 并执行以下查询：

```sql
> db.binaryDataTest.findOne()

```

1.  滚动文档并记下文档中的字段。

## 工作原理…

如果我们滚动查看打印出的大型文档，我们会看到字段`fileName`，`size`和`data`。前两个字段分别是字符串和数字类型，我们在文档创建时填充了这些字段，并保存了我们提供的文件名和以字节为单位的大小。数据字段是 BSON 类型 BinData 的字段，我们在其中看到数据以 Base64 格式编码。

以下代码行显示了我们如何填充添加到集合中的 DBObject：

```sql
DBObject doc = new BasicDBObject("_id", 1);
doc.put("fileName", resourceName);
doc.put("size", imageBytes.length);
doc.put("data", imageBytes);
```

如上所示，使用两个字段`fileName`和`size`来存储文件名和文件大小，分别为字符串和数字类型。数据字段作为字节数组添加到`DBObject`中，它会自动存储为文档中的 BSON 类型 BinData。

## 另请参阅

在这个配方中，我们看到的是直接的，只要文档大小小于 16MB。如果存储的文件大小超过这个值，我们必须求助于像 GridFS 这样的解决方案，这在下一个配方*使用 GridFS 在 Mongo 中存储大数据*中有解释。

# 使用 GridFS 在 Mongo 中存储大数据

MongoDB 中的文档大小可以达到 16 MB。 但这是否意味着我们不能存储超过 16 MB 大小的数据？ 有些情况下，您更喜欢将视频和音频文件存储在数据库中，而不是在文件系统中，因为有许多优势，比如存储与它们一起的元数据，从中间位置访问文件时，以及在 MongoDB 服务器实例上启用复制时为了高可用性而复制内容。 GridFS 可以用来解决 MongoDB 中的这些用例。 我们还将看到 GridFS 如何管理超过 16 MB 的大容量，并分析其用于在幕后存储内容的集合。 为了测试目的，我们不会使用超过 16 MB 的数据，而是使用一些更小的数据来查看 GridFS 的运行情况。

## 准备工作

查看第一章中的配方*安装单节点 MongoDB*，*安装和启动服务器*并启动 Mongo 的单个实例。 这是此配方的唯一先决条件。 启动 Mongo shell 并连接到已启动的服务器。 另外，我们将使用 mongofiles 实用程序从命令行将数据存储在 GridFS 中。

## 如何做...

1.  下载该书的代码包，并将图像文件`glimpse_of_universe-wide.jpg`保存到本地驱动器（您可以选择任何其他大文件作为事实，并使用我们执行的命令提供适当的文件名）。 为了举例，图像保存在主目录中。 我们将把我们的步骤分为三个部分。

1.  在服务器运行并且当前目录为主目录的情况下，从操作系统的 shell 中执行以下命令。 这里有两个参数。 第一个是本地文件系统上文件的名称，第二个是将附加到 MongoDB 中上传内容的名称。

```sql
$ mongofiles put -l glimpse_of_universe-wide.jpg universe.jpg

```

1.  现在让我们查询集合，看看这些内容实际上是如何在幕后的集合中存储的。 打开 shell，执行以下两个查询。 确保在第二个查询中，您确保不选择数据字段。

```sql
> db.fs.files.findOne({filename:'universe.jpg'})
> db.fs.chunks.find({}, {data:0})

```

1.  现在我们已经从操作系统的本地文件系统中将文件放入了 GridFS，我们将看到如何将文件获取到本地文件系统。 从操作系统 shell 中执行以下操作：

```sql
$ mongofiles get -l UploadedImage.jpg universe.jpg

```

1.  最后，我们将删除我们上传的文件。 从操作系统 shell 中，执行以下操作：

```sql
$ mongofiles delete universe.jpg

```

1.  再次使用以下查询确认删除：

```sql
> db.fs.files.findOne({filename:'universe.jpg'})
> db.fs.chunks.find({}, {data:0})

```

## 工作原理...

Mongo 分发包带有一个名为 mongofiles 的工具，它允许我们将大容量上传到 Mongo 服务器，该服务器使用 GridFS 规范进行存储。 GridFS 不是一个不同的产品，而是一个标准规范，由不同的 MongoDB 驱动程序遵循，用于存储大于 16 MB 的数据，这是最大文档大小。 它甚至可以用于小于 16 MB 的文件，就像我们在我们的示例中所做的那样，但实际上没有一个很好的理由这样做。 没有什么能阻止我们实现自己的存储这些大文件的方式，但最好遵循标准。 这是因为所有驱动程序都支持它，并且在需要时进行大文件的分割和组装。

我们从 Packt Publishing 网站下载的图像，并使用 mongofiles 上传到 MongoDB。 执行此操作的命令是`put`，`-l`选项给出了我们要上传的本地驱动器上的文件的名称。 最后，名称`universe.jpg`是我们希望它在 GridFS 上存储的文件的名称。

成功执行后，我们应该在控制台上看到以下内容：

```sql
connected to: 127.0.0.1
added file: { _id: ObjectId('5310d531d1e91f93635588fe'), filename: "universe.jpg
", chunkSize: 262144, uploadDate: new Date(1393612082137), md5: 
d894ec31b8c5add
d0c02060971ea05ca", length: 2711259 }
done!

```

这给我们一些上传的细节，上传文件的唯一`_id`，文件的名称，块大小，这是这个大文件被分成的块的大小（默认为 256 KB），上传日期，上传内容的校验和以及上传的总长度。这个校验和可以事先计算，然后在上传后进行比较，以检查上传的内容是否损坏。

在测试数据库的 mongo shell 中执行以下查询：

```sql
> db.fs.files.findOne({filename:'universe.jpg'})

```

我们看到我们在`mongofiles`的`put`命令中看到的输出与上面在`fs.files`集合中查询的文档相同。这是当向 GridFS 添加数据时，所有上传的文件细节都会放在这个集合中。每次上传都会有一个文档。应用程序以后还可以修改此文档，以添加自己的自定义元数据以及在添加数据时添加到我的 Mongo 的标准细节。如果文档是用于图像上传，应用程序可以很好地使用此集合来添加诸如摄影师、图像拍摄地点、拍摄地点以及图像中个人的标签等细节。

文件内容是包含这些数据的内容。让我们执行以下查询：

```sql
> db.fs.chunks.find({}, {data:0})

```

我们故意从所选结果中省略了数据字段。让我们看一下结果文档的结构：

```sql
{
_id: <Unique identifier of type ObjectId representing this chunk>,
file_id: <ObjectId of the document in fs.files for the file whose chunk this document represent>,
n:<The chunk identifier starts with 0, this is useful for knowing the order of the chunks>,
data: <BSON binary content  for the data uploaded for the file>
}
```

对于我们上传的文件，我们有 11 个最大为 256 KB 的块。当请求文件时，`fs.chunks`集合通过来自`fs.files`集合的`_id`字段的`file_id`和字段`n`（块的序列）进行搜索。当第一次使用 GridFS 上传文件时，为了快速检索使用文件 ID 按块序列号排序的块，这两个字段上创建了唯一索引。

与`put`类似，`get`选项用于从 GridFS 检索文件并将其放在本地文件系统上。命令的不同之处在于使用`get`而不是`put`，`-l`仍然用于提供此文件在本地文件系统上保存的名称，最后的命令行参数是 GridFS 中存储的文件的名称。这是`fs.files`集合中`filename`字段的值。最后，`mongofiles`的`delete`命令简单地从`fs.files`和`fs.chunks`集合中删除文件的条目。删除的文件名再次是`fs.files`集合中`filename`字段中的值。

使用 GridFS 的一些重要用例是当存在一些用户生成的内容，比如一些静态数据上的大型报告，这些数据不经常更改，而且频繁生成成本很高。与其每次都运行它们，不如运行一次并存储，直到检测到静态数据的更改；在这种情况下，存储的报告将被删除，并在下一次请求数据时重新执行。文件系统可能并不总是可用于应用程序写入文件，这种情况下这是一个很好的替代方案。有些情况下，人们可能对存储的一些中间数据块感兴趣，这种情况下可以访问包含所需数据的数据块。您可以获得一些不错的功能，比如数据的 MD5 内容，它会自动存储并可供应用程序使用。

既然我们已经了解了 GridFS 是什么，让我们看看在哪些情况下使用 GridFS 可能不是一个很好的主意。通过 GridFS 从 MongoDB 访问内容的性能和直接从文件系统访问的性能不会相同。直接文件系统访问将比 GridFS 更快，建议对要开发的系统进行**概念验证**（**POC**）以测量性能损失，并查看是否在可接受的范围内；如果是，那么性能上的折衷可能是值得的。此外，如果您的应用服务器前端使用 CDN，您实际上可能不需要在 GridFS 中存储静态数据的大量 IO。由于 GridFS 将数据存储在多个集合中的多个文档中，因此无法以原子方式更新它们。如果我们知道内容小于 16MB，这在许多用户生成的内容中是情况，或者上传了一些小文件，我们可以完全跳过 GridFS，并将内容存储在一个文档中，因为 BSON 支持在文档中存储二进制内容。有关更多详细信息，请参考上一个教程*在 Mongo 中存储二进制数据*。

我们很少使用 mongofiles 实用程序来从 GridFS 存储、检索和删除数据。虽然偶尔可能会使用它，但我们大多数情况下会从应用程序执行这些操作。在接下来的几个教程中，我们将看到如何连接到 GridFS，使用 Java 和 Python 客户端存储、检索和删除文件。

## 还有更多...

虽然这与 Mongo 不太相关，但 Openstack 是一个**基础设施即服务**（**IaaS**）平台，提供各种计算、存储、网络等服务。其中一个名为**Glance**的镜像存储服务支持许多持久存储来存储图像。Glance 支持的存储之一是 MongoDB 的 GridFS。您可以在以下网址找到有关如何配置 Glance 使用 GridFS 的更多信息：[`docs.openstack.org/trunk/config-reference/content/ch_configuring-openstack-image-service.html`](http://docs.openstack.org/trunk/config-reference/content/ch_configuring-openstack-image-service.html)。

## 另请参阅

您可以参考以下教程：

+   *从 Java 客户端将数据存储到 GridFS*

+   从 Python 客户端将数据存储到 GridFS

# 从 Java 客户端将数据存储到 GridFS

在上一个教程中，我们看到了如何使用 MongoDB 自带的命令行实用程序 mongofiles 来将数据存储到 GridFS，以管理大型数据文件。要了解 GridFS 是什么，以及在幕后用于存储数据的集合，请参考上一个教程*在 Mongo 中使用 GridFS 存储大型数据*。

在本教程中，我们将看看如何使用 Java 客户端将数据存储到 GridFS。该程序将是 mongofiles 实用程序的一个大大简化版本，只关注如何存储、检索和删除数据，而不是试图提供像 mongofiles 那样的许多选项。

## 准备工作

有关本教程所需的所有必要设置，请参阅第一章中的教程*安装单节点 MongoDB*，*安装和启动服务器*。如果您对 Java 驱动程序有更多详细信息感兴趣，请参考第三章中的教程*使用 Java 客户端在 Mongo 中实现聚合*和*使用 Java 客户端在 Mongo 中执行 MapReduce*。打开一个 mongo shell 并连接到监听端口`27017`的本地 mongod 实例。对于本教程，我们将使用项目`mongo-cookbook-gridfs`。该项目可在 Packt 网站上提供的源代码包中找到。需要在本地文件系统上提取该文件夹。打开操作系统的终端并转到提取的项目的根目录。这应该是找到文件`pom.xml`的目录。还要像上一个教程一样，在本地文件系统上保存文件`glimpse_of_universe-wide.jpg`，该文件可以在 Packt 网站上提供的书籍可下载包中找到。

## 如何做…

1.  我们假设 GridFS 的集合是干净的，没有先前上传的数据。如果数据库中没有重要数据，您可以执行以下操作来清除集合。在删除集合之前，请小心行事。

```sql
> use test
> db.fs.chunks.drop()
> db.fs.files.drop()

```

1.  打开操作系统 shell 并执行以下操作：

```sql
$ mvn exec:java -Dexec.mainClass=com.packtpub.mongo.cookbook.GridFSTests -Dexec.args="put ~/glimpse_of_universe-wide.jpg universe.jpg"

```

1.  我需要上传的文件放在主目录中。在`put`命令之后，您可以选择给出图像文件的文件路径。请记住，如果路径中包含空格，则整个路径需要在单引号内给出。

1.  如果前面的命令成功运行，我们应该期望在命令行输出以下内容：

```sql
Successfully written to universe.jpg, details are:
Upload Identifier: 5314c05e1c52e2f520201698
Length: 2711259
MD5 hash: d894ec31b8c5addd0c02060971ea05ca
Chunk Side in bytes: 262144
Total Number Of Chunks: 11

```

1.  一旦前面的执行成功，我们可以从控制台输出确认，然后从 mongo shell 执行以下操作：

```sql
> db.fs.files.findOne({filename:'universe.jpg'})
> db.fs.chunks.find({}, {data:0})

```

1.  现在，我们将从 GridFS 获取文件到本地文件系统，执行以下操作来执行此操作：

```sql
$ mvn exec:java -Dexec.mainClass=com.packtpub.mongo.cookbook.GridFSTests -Dexec.args="get '~/universe.jpg' universe.jpg"

```

确认文件是否存在于所述位置的本地文件系统上。我们应该看到以下内容打印到控制台输出，以指示成功的写操作：

```sql
Connected successfully..
Successfully written 2711259 bytes to ~/universe.jpg

```

1.  最后，我们将从 GridFS 中删除文件：

```sql
$ mvn exec:java -Dexec.mainClass=com.packtpub.mongo.cookbook.GridFSTests -Dexec.args="delete universe.jpg"

```

1.  成功删除后，我们应该在控制台中看到以下输出：

```sql
Connected successfully..
Removed file with name 'universe.jpg' from GridFS

```

## 它是如何工作的...

类`com.packtpub.mongo.cookbook.GridFSTests`接受三种类型的操作：`put`将文件上传到 GridFS，`get`从 GridFS 获取内容到本地文件系统，`delete`从 GridFS 删除文件。

该类最多接受三个参数，第一个是操作，有效值为`get`，`put`和`delete`。第二个参数与`get`和`put`操作相关，是本地文件系统上要写入下载内容的文件的名称，或者用于上传的内容的源。第三个参数是 GridFS 中的文件名，不一定与本地文件系统上的文件名相同。但是，对于`delete`，只需要 GridFS 上的文件名，该文件将被删除。

让我们看一下该类中与 GridFS 特定的一些重要代码片段。

在您喜欢的 IDE 中打开类`com.packtpub.mongo.cookbook.GridFSTests`，查找方法`handlePut`，`handleGet`和`handleDelete`。这些方法是所有逻辑的地方。我们将首先从`handlePut`方法开始，该方法用于将文件内容从本地文件系统上传到 GridFS。

无论我们执行什么操作，我们都将创建`com.mongodb.gridfs.GridFS`类的实例。在我们的情况下，我们将其实例化如下：

```sql
GridFS gfs = new GridFS(client.getDB("test"));
```

该类的构造函数接受`com.mongodb.DB`类的数据库实例。创建 GridFS 实例后，我们将调用其上的`createFile`方法。此方法接受两个参数，第一个是`InputStream`，用于提供要上传的内容的字节，第二个参数是 GridFS 上的文件名，该文件将保存在 GridFS 上。但是，此方法不会在 GridFS 上创建文件，而是返回`com.mongodb.gridfs.GridFSInputFile`的实例。只有在调用此返回对象中的`save`方法时，上传才会发生。此`createFile`方法有几个重载的变体。有关更多详细信息，请参阅`com.mongodb.gridfs.GridFS`类的 Javadocs。

我们的下一个方法是`handleGet`，它从 GridFS 上保存的文件中获取内容到本地文件系统。与`com.mongodb.DBCollection`类似，`com.mongodb.gridfs.GridFS`类具有用于搜索的`find`和`findOne`方法。但是，与接受任何 DBObject 查询不同，GridFS 中的`find`和`findOne`接受文件名或要在`fs.files`集合中搜索的文档的 ObjectID 值。同样，返回值不是 DBCursor，而是`com.mongodb.gridfs.GridFSDBFile`的实例。该类具有各种方法，用于获取 GridFS 文件中存在的内容的字节的`InputStream`，将文件或`OutputStream`写入文件的方法`writeTo`，以及一个`getLength`方法，用于获取文件中的字节数。有关详细信息，请参阅`com.mongodb.gridfs.GridFSDBFile`类的 Javadocs。

最后，我们来看看`handleDelete`方法，它用于删除 GridFS 上的文件，是最简单的方法。GridFS 对象上的方法是`remove`，它接受一个字符串参数：要在服务器上删除的文件的名称。此方法的`return`类型是`void`。因此，无论 GridFS 上是否存在内容，如果为此方法提供了一个不存在的文件的名称，该方法都不会返回值，也不会抛出异常。

## 另请参阅

您可以参考以下配方：

+   *在 Mongo 中存储二进制数据*

+   *从 Python 客户端将数据存储到 GridFS*

# 从 Python 客户端将数据存储到 GridFS

在配方*使用 GridFS 在 Mongo 中存储大数据*中，我们看到了 GridFS 是什么，以及如何使用它来在 MongoDB 中存储大文件。在上一个配方中，我们看到了如何从 Java 客户端使用 GridFS API。在这个配方中，我们将看到如何使用 Python 程序将图像数据存储到 MongoDB 中的 GridFS。

## 准备好

有关本配方的所有必要设置，请参考第一章中的配方*使用 Java 客户端连接到单个节点*，*安装和启动服务器*。如果您对 Python 驱动程序的更多详细信息感兴趣，请参考以下配方：*使用 PyMongo 执行查询和插入操作*和*使用 PyMongo 执行更新和删除操作*在第三章中，*编程语言驱动程序*。从 Packt 网站的可下载捆绑包中下载并保存图像`glimpse_of_universe-wide.jpg`到本地文件系统，就像我们在上一个配方中所做的那样。

## 如何做…

1.  通过在操作系统 shell 中输入以下内容来打开 Python 解释器。请注意，当前目录与放置图像文件`glimpse_of_universe-wide.jpg`的目录相同：

```sql
$ python

```

1.  按如下方式导入所需的包：

```sql
>>>import pymongo
>>>import gridfs

```

1.  一旦打开了 Python shell，就按如下方式创建`MongoClient`和数据库对象到测试数据库：

```sql
>>>client = pymongo.MongoClient('mongodb://localhost:27017')
>>>db = client.test

```

1.  要清除与 GridFS 相关的集合，请执行以下操作：

```sql
>>> db.fs.files.drop()
>>> db.fs.chunks.drop()

```

1.  创建 GridFS 的实例如下：

```sql
>>>fs = gridfs.GridFS(db)

```

1.  现在，我们将读取文件并将其内容上传到 GridFS。首先，按如下方式创建文件对象：

```sql
>>>file = open('glimpse_of_universe-wide.jpg', 'rb')

```

1.  现在按如下方式将文件放入 GridFS

```sql
>>>fs.put(file, filename='universe.jpg')

```

1.  成功执行`put`后，我们应该看到上传文件的 ObjectID。这将与此文件的`fs.files`集合的`_id`字段相同。

1.  从 Python shell 执行以下查询。它应该打印出包含上传详细信息的`dict`对象。验证内容

```sql
>>> db.fs.files.find_one()

```

1.  现在，我们将获取上传的内容并将其写入本地文件系统中的文件。让我们获取表示要从 GridFS 中读取数据的`GridOut`实例，如下所示：

```sql
>>> gout = fs.get_last_version('universe.jpg')

```

1.  有了这个实例，让我们按如下方式将数据写入本地文件系统中的文件。首先，按如下方式打开本地文件系统上的文件句柄以进行写入：

```sql
>>> fout = open('universe.jpg', 'wb')

```

1.  然后，我们将按如下方式向其写入内容：

```sql
>>>fout.write(gout.read())
>>>fout.close()
>>>gout.close()

```

1.  现在在本地文件系统的当前目录上验证文件。将创建一个名为`universe.jpg`的新文件，其字节数与源文件相同。通过在图像查看器中打开它来进行验证。

## 工作原理…

让我们看一下我们执行的步骤。在 Python shell 中，我们导入了两个包，`pymongo`和`gridfs`，并实例化了`pymongo.MongoClient`和`gridfs.GridFS`实例。类`gridfs.GridFS`的构造函数接受一个参数，即`pymongo.Database`的实例。

我们使用`open`函数以二进制模式打开文件，并将文件对象传递给 GridFS 的`put`方法。还传递了一个名为`filename`的额外参数，这将是放入 GridFS 的文件的名称。第一个参数不需要是文件对象，而是任何定义了`read`方法的对象。

一旦`put`操作成功，`return`值就是`fs.files`集合中上传文档的 ObjectID。对`fs.files`的查询可以确认文件已上传。验证上传的数据大小是否与文件大小匹配。

我们的下一个目标是将文件从 GridFS 获取到本地文件系统。直觉上，人们会想象如果将文件放入 GridFS 的方法是`put`，那么获取文件的方法将是`get`。确实，该方法的确是`get`，但是它只会基于`put`方法返回的`ObjectId`进行获取。因此，如果您愿意按`ObjectId`获取，`get`就是您的方法。但是，如果您想按文件名获取，要使用的方法是`get_last_version`。它接受我们上传的文件名，并且此方法的返回类型是`gridfs.gridfs_file.GridOut`类型。该类包含`read`方法，它将从 GridFS 中上传的文件中读取所有字节。我们以二进制模式打开一个名为`universe.jpg`的文件进行写入，并将从`GridOut`对象中读取的所有字节写入其中。

## 另请参阅

您可以参考以下配方：

+   *在 Mongo 中存储二进制数据*

+   *从 Java 客户端将数据存储到 GridFS*

# 使用 oplog 在 Mongo 中实现触发器

在关系型数据库中，触发器是在数据库表上执行`insert`、`update`或`delete`操作时被调用的代码。触发器可以在操作之前或之后被调用。MongoDB 中并没有内置实现触发器，如果您需要在应用程序中任何`insert`/`update`/`delete`操作执行时得到通知，您需要自己在应用程序中管理。一种方法是在应用程序中有一种数据访问层，这是唯一可以从集合中查询、插入、更新或删除文档的地方。但是，这也存在一些挑战。首先，您需要在应用程序中明确编写逻辑以满足此要求，这可能是可行的，也可能是不可行的。如果数据库是共享的，并且多个应用程序访问它，事情会变得更加困难。其次，访问需要严格管理，不允许其他来源的插入/更新/删除。

或者，我们需要考虑在靠近数据库的层中运行某种逻辑。跟踪所有写操作的一种方法是使用 oplog。请注意，无法使用 oplog 跟踪读操作。在本配方中，我们将编写一个小型的 Java 应用程序，该应用程序将尾随 oplog 并获取在 Mongo 实例上发生的所有`insert`、`update`和`delete`操作。请注意，此程序是用 Java 实现的，并且在任何其他编程语言中同样有效。关键在于实现的逻辑，实现的平台可以是任何。此外，只有在 mongod 实例作为副本集的一部分启动时，此触发器类功能才能被调用，而不是在数据被插入/更新或从集合中删除之前。

## 准备工作

有关此示例的所有必要设置，请参考第一章中的示例*作为副本集的一部分启动多个实例*，*安装和启动服务器*。如果您对 Java 驱动程序的更多细节感兴趣，请参考第三章中的以下示例*使用 Java 客户端执行查询和插入操作*和*使用 Java 客户端执行更新和删除操作*。这两个示例的先决条件是我们这个示例所需要的一切。

如果您不了解或需要复习，请参考本章中的示例*在 MongoDB 中创建和跟踪封顶集合游标*，了解有关封顶集合和可跟踪游标的更多信息。最后，尽管不是强制性的，第四章中的*管理*解释了 oplog 的深度，解释了*理解和分析 oplog*中的 oplog。这个示例不会像我们在第四章中所做的那样深入解释 oplog。打开一个 shell 并将其连接到副本集的主服务器。

对于这个示例，我们将使用项目`mongo-cookbook-oplogtrigger`。该项目可以从 Packt 网站下载的源代码包中获取。需要在本地文件系统上提取文件夹。打开命令行 shell 并转到提取的项目的根目录。这应该是找到文件`pom.xml`的目录。还需要`TriggerOperations.js`文件来触发我们打算捕获的数据库中的操作。

## 操作步骤…

1.  打开操作系统 shell 并执行以下操作：

```sql
$ mvn exec:java -Dexec.mainClass=com.packtpub.mongo.cookbook.OplogTrigger -Dexec.args="test.oplogTriggerTest"

```

1.  Java 程序启动后，我们将打开 shell，当前目录中存在文件`TriggerOperations.js`，mongod 实例监听端口`27000`作为主服务器：

```sql
$ mongo --port 27000 TriggerOperations.js --shell

```

1.  连接到 shell 后，执行我们从 JavaScript 中加载的以下函数：

```sql
test:PRIMARY> triggerOperations()

```

1.  观察在控制台上打印出的输出，Java 程序`com.packtpub.mongo.cookbook.OplogTrigger`正在使用 Maven 执行。

## 工作原理…

我们实现的功能对于许多用例非常方便，但首先让我们看一下更高层次上做了什么。Java 程序`com.packtpub.mongo.cookbook.OplogTrigger`是一个在 MongoDB 中插入、更新或删除集合中的新数据时触发的东西。它使用 oplog 集合，这是 Mongo 中复制的支柱，来实现这个功能。

我们刚刚编写的 JavaScript 作为一个数据的生产、更新和删除的源。您可以选择打开`TriggerOperations.js`文件，看一下它是如何实现的。它执行的集合位于测试数据库中，称为`oplogTriggerTest`。

当我们执行 JavaScript 函数时，应该看到类似以下内容打印到输出控制台：

```sql
[INFO] <<< exec-maven-plugin:1.2.1:java (default-cli) @ mongo-cookbook-oplogtriger <<<
[INFO]
[INFO] --- exec-maven-plugin:1.2.1:java (default-cli) @ mongo-cookbook-oplogtriger ---
Connected successfully..
Starting tailing oplog...
Operation is Insert ObjectId is 5321c4c2357845b165d42a5f
Operation is Insert ObjectId is 5321c4c2357845b165d42a60
Operation is Insert ObjectId is 5321c4c2357845b165d42a61
Operation is Insert ObjectId is 5321c4c2357845b165d42a62
Operation is Insert ObjectId is 5321c4c2357845b165d42a63
Operation is Insert ObjectId is 5321c4c2357845b165d42a64
Operation is Update ObjectId is 5321c4c2357845b165d42a60
Operation is Delete ObjectId is 5321c4c2357845b165d42a61
Operation is Insert ObjectId is 5321c4c2357845b165d42a65
Operation is Insert ObjectId is 5321c4c2357845b165d42a66
Operation is Insert ObjectId is 5321c4c2357845b165d42a67
Operation is Insert ObjectId is 5321c4c2357845b165d42a68
Operation is Delete ObjectId is 5321c4c2357845b165d42a5f
Operation is Delete ObjectId is 5321c4c2357845b165d42a62
Operation is Delete ObjectId is 5321c4c2357845b165d42a63
Operation is Delete ObjectId is 5321c4c2357845b165d42a64
Operation is Delete ObjectId is 5321c4c2357845b165d42a60
Operation is Delete ObjectId is 5321c4c2357845b165d42a65
Operation is Delete ObjectId is 5321c4c2357845b165d42a66
Operation is Delete ObjectId is 5321c4c2357845b165d42a67
Operation is Delete ObjectId is 5321c4c2357845b165d42a68

```

Maven 程序将持续运行，永远不会终止，因为 Java 程序不会。您可以按*Ctrl* + *C*停止执行。

让我们分析一下 Java 程序，这是内容的核心所在。首先假设这个程序要工作，必须设置一个副本集，因为我们将使用 Mongo 的 oplog 集合。Java 程序创建了一个连接到副本集成员的主服务器，连接到本地数据库，并获取了`oplog.rs`集合。然后，它所做的就是找到 oplog 中的最后一个或几乎最后一个时间戳。这样做是为了防止在启动时重放整个 oplog，而是标记 oplog 末尾的一个点。以下是找到这个时间戳值的代码：

```sql
DBCursor cursor = collection.find().sort(new BasicDBObject("$natural", -1)).limit(1);
int current = (int) (System.currentTimeMillis() / 1000);
return cursor.hasNext() ? (BSONTimestamp)cursor.next().get("ts") : new BSONTimestamp(current, 1);
```

oplog 按照自然逆序排序，以找到其中最后一个文档中的时间。由于 oplog 遵循先进先出模式，将 oplog 按降序自然顺序排序等同于按时间戳降序排序。

完成后，像以前一样找到时间戳，我们通常查询操作日志集合，但增加了两个额外的选项：

```sql
DBCursor cursor = collection.find(QueryBuilder.start("ts")
          .greaterThan(lastreadTimestamp).get())
          .addOption(Bytes.QUERYOPTION_TAILABLE)
          .addOption(Bytes.QUERYOPTION_AWAITDATA);
```

查询找到所有大于特定时间戳的文档，并添加两个选项，`Bytes.QUERYOPTION_TAILABLE`和`Bytes.QUERYOPTION_AWAITDATA`。只有在添加前一个选项时才能添加后一个选项。这不仅查询并返回数据，还在执行到游标末尾时等待一段时间以获取更多数据。最终，当没有数据到达时，它终止。

在每次迭代期间，还要存储上次看到的时间戳。当游标关闭且没有更多数据可用时，我们再次查询以获取新的可追溯游标实例时会使用这个时间戳。这个过程将无限期地继续下去，基本上我们以类似于在 Unix 中使用`tail`命令追踪文件的方式追踪集合。

操作日志文档包含一个名为`op`的字段，其值为`i`，`u`和`d`，分别表示插入，更新和删除的操作。字段`o`包含插入或删除对象的 ID（`_id`）（在插入和删除的情况下）。在更新的情况下，文件`o2`包含`_id`。我们所做的就是简单地检查这些条件，并打印出插入/删除或更新的操作和文档的 ID。

有一些需要注意的事情如下。显然，已删除的文档在集合中将不可用，因此，如果您打算进行查询，`_id`将不会真正有用。此外，在使用我们获得的 ID 更新后选择文档时要小心，因为操作日志中的某些其他操作可能已经对同一文档执行了更多的更新，而我们应用程序的可追溯游标尚未达到那一点。这在高容量系统中很常见。同样，对于插入，我们也有类似的问题。我们可能使用提供的 ID 查询的文档可能已经被更新/删除。使用此逻辑跟踪这些操作的应用程序必须意识到这些问题。

或者，查看包含更多详细信息的操作日志。比如插入的文档，执行的`update`语句等。操作日志集合中的更新是幂等的，这意味着它们可以应用任意次数而不会产生意外的副作用。例如，如果实际的更新是将值增加 1，那么操作日志集合中的更新将具有`set`运算符，并且最终值将被期望。这样，相同的更新可以应用多次。然后，您将使用的逻辑必须更复杂，以实现这样的情况。

此外，这里没有处理故障转移。这对于基于生产的系统是必要的。另一方面，无限循环在第一个游标终止时立即打开一个新的游标。在再次查询操作日志之前，可以引入一个睡眠持续时间，以避免用查询过度压倒服务器。请注意，此处提供的程序不是生产质量的代码，而只是使用了许多其他系统用于获取有关 MongoDB 中集合的新数据插入，删除和更新的通知技术的简单演示。

MongoDB 直到 2.4 版本之前都没有文本搜索功能，之前所有的全文搜索都是使用 Solr 或 Elasticsearch 等外部搜索引擎处理的。即使现在，尽管 MongoDB 中的文本搜索功能已经可以投入生产使用，许多人仍然会使用外部专用的搜索索引器。如果决定使用外部全文索引搜索工具而不是利用 MongoDB 内置的工具，这也不足为奇。在 Elasticsearch 中，将数据流入索引的抽象称为“river”。Elasticsearch 中的 MongoDB river 会在 Mongo 中的集合添加数据时将数据添加到索引中，其构建逻辑与我们在 Java 中实现的简单程序中看到的逻辑相同。

# 使用地理空间索引在 Mongo 中进行平面 2D 地理空间查询

在这个配方中，我们将看到什么是地理空间查询，然后看看如何在平面上应用这些查询。我们将在一个测试地图应用程序中使用它。

地理空间查询可以在创建了地理空间索引的数据上执行。有两种类型的地理空间索引。第一种称为 2D 索引，是两者中较简单的一种，它假定数据以*x,y*坐标的形式给出。第二种称为 3D 或球面索引，相对更复杂。在这个配方中，我们将探索 2D 索引，并对 2D 数据执行一些查询。我们将要处理的数据是一个 25 x 25 的网格，其中一些坐标表示公交车站、餐厅、医院和花园。

![使用地理空间索引在 Mongo 中进行平面 2D 地理空间查询](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-cb/img/B04831_05_02.jpg)

## 准备工作

有关此配方的所有必要设置，请参阅第一章中的配方*使用 Java 客户端连接单个节点*，*安装和启动服务器*。下载数据文件`2dMapLegacyData.json`，并将其保存在本地文件系统上以备导入。打开一个连接到本地 MongoDB 实例的 mongo shell。

## 如何做…

1.  从操作系统 shell 执行以下命令将数据导入到集合中。文件`2dMapLegacyData.json`位于当前目录中。

```sql
$ mongoimport -c areaMap -d test --drop 2dMapLegacyData.json

```

1.  如果我们在屏幕上看到类似以下内容，我们可以确认导入已成功进行：

```sql
connected to: 127.0.0.1
Mon Mar 17 23:58:27.880 dropping: test.areaMap
Mon Mar 17 23:58:27.932 check 9 26
Mon Mar 17 23:58:27.934 imported 26 objects

```

1.  成功导入后，从打开的 mongo shell 中，通过执行以下查询验证集合及其内容：

```sql
> db.areaMap.find()

```

这应该让你感受到集合中的数据。

1.  下一步是在这些数据上创建 2D 地理空间索引。执行以下命令创建 2D 索引：

```sql
$ db.areaMap.ensureIndex({co:'2d'})

```

1.  创建了索引后，我们现在将尝试找到离一个人所站的地方最近的餐厅。假设这个人对美食不挑剔，让我们执行以下查询，假设这个人站在位置(12, 8)，如图所示。此外，我们只对最近的三个地方感兴趣。

```sql
$ db.areaMap.find({co:{$near:[12, 8]}, type:'R'}).limit(3)

```

1.  这应该给我们三个结果，从最近的餐厅开始，随后的结果按距离递增给出。如果我们看一下之前给出的图像，我们可能会对这里给出的结果表示同意。

1.  让我们给查询添加更多选项。个人需要步行，因此希望结果中的距离受到限制。让我们使用以下修改重新编写查询：

```sql
$ db.areaMap.find({co:{$near:[12, 8], $maxDistance:4}, type:'R'})

```

1.  观察这次检索到的结果数量。

## 工作原理…

让我们现在看看我们做了什么。在继续之前，让我们定义一下两点之间的距离是什么意思。假设在笛卡尔平面上我们有两点(x[1], y[1])和(x[2], y[2])，它们之间的距离将使用以下公式计算：

*√(x[1] – x[2])² + (y[1] – y[2])²*

假设两点分别为(2, 10)和(12, 3)，距离将是：√(2 – 12)² + (10 – 3)² = √(-10)² + (7)² = √149 =12.207。

在了解了 MongoDB 在幕后如何进行距离计算的计算方法之后，让我们从第 1 步开始看看我们做了什么。

我们首先将数据正常导入到`test`数据库中的一个集合`areaMap`中，并创建了一个索引`db.areaMap.ensureIndex({co:'2d'})`。索引是在文档中的字段`co`上创建的，其值是一个特殊值`2d`，表示这是一种特殊类型的索引，称为 2D 地理空间索引。通常，在其他情况下，我们会给出值`1`或`-1`，表示索引的顺序。

有两种类型的索引。第一种是 2D 索引，通常用于跨度较小且不涉及球面的平面。它可能是建筑物的地图，一个地区，甚至是一个小城市，其中地球的曲率覆盖的土地部分并不真正重要。然而，一旦地图的跨度增加并覆盖全球，2D 索引将不准确地预测值，因为需要考虑地球的曲率在计算中。在这种情况下，我们将使用球形索引，我们将很快讨论。

创建 2D 索引后，我们可以使用它来查询集合并找到一些接近查询点的点。执行以下查询：

```sql
> db.areaMap.find({co:{$near:[12, 8]}, type:'R'}).limit(3)

```

它将查询类型为 R 的文档，这些文档的类型是`restaurants`，并且接近坐标（12,8）。此查询返回的结果将按照与所查询点（在本例中为（12,8））的距离递增的顺序排列。限制只是将结果限制为前三个文档。我们还可以在查询中提供`$maxDistance`，它将限制距离小于或等于提供的值的结果。我们查询的位置不超过四个单位，如下所示：

```sql
> db.areaMap.find({co:{$near:[12, 8], $maxDistance:4}, type:'R'})

```

# Mongo 中的球形索引和 GeoJSON 兼容数据

在继续本食谱之前，我们需要查看之前的食谱*使用地理空间索引在 Mongo 中进行平面 2D 地理空间查询*，以了解 MongoDB 中的地理空间索引是什么，以及如何使用 2D 索引。到目前为止，我们已经在 MongoDB 集合中以非标准格式导入了 JSON 文档，创建了地理空间索引，并对其进行了查询。这种方法完全有效，实际上，直到 MongoDB 2.4 版本之前，这是唯一可用的选项。MongoDB 2.4 版本支持一种额外的方式来存储、索引和查询集合中的文档。有一种标准的方式来表示地理空间数据，特别是用于 JSON 中的地理数据交换，并且 GeoJSON 的规范在以下链接中详细说明：[`geojson.org/geojson-spec.html`](http://geojson.org/geojson-spec.html)。我们现在可以以这种格式存储数据。

此规范支持各种地理图形类型。但是，对于我们的用例，我们将使用类型`Point`。首先让我们看看我们之前使用非标准格式导入的文档是什么样子的，以及使用 GeoJSON 格式的文档是什么样子的。

+   非标准格式的文档：

```sql
{"_id":1, "name":"White Street", "type":"B", co:[4, 23]}

```

+   GeoJSON 格式的文档：

```sql
{"_id":1, "name":"White Street", "type":"B", co:{type: 'Point', coordinates : [4, 23]}}

```

对于我们的特定情况来说，它看起来比非标准格式更复杂，我同意。然而，当表示多边形和其他线时，非标准格式可能必须存储多个文档。在这种情况下，只需更改`type`字段的值，就可以将其存储在单个文档中。有关更多详细信息，请参阅规范。

## 准备工作

这个食谱的先决条件与上一个食谱的先决条件相同，只是要导入的文件将是`2dMapGeoJSONData.json`和`countries.geo.json`。从 Packt 网站下载这些文件，并将它们保存在本地文件系统中，以便稍后导入它们。

### 注意

特别感谢 Johan Sundström 分享世界数据。世界的 GeoJSON 取自[`github.com/johan/world.geo.json`](https://github.com/johan/world.geo.json)。该文件经过处理，以便在 Mongo 中进行导入和索引创建。2.4 版本不支持 MultiPolygon，因此所有 MultiPolygon 类型的形状都被省略了。然而，这个缺点似乎在 2.6 版本中得到了修复。

## 如何做…

1.  按照以下方式将 GeoJSON 兼容数据导入新集合。这包含了 26 个类似于我们上次导入的文档，只是它们是使用 GeoJSON 格式进行格式化的。

```sql
$ mongoimport -c areaMapGeoJSON -d test --drop 2dMapGeoJSONData.json
$ mongoimport -c worldMap -d test --drop countries.geo.json

```

1.  在这些集合上创建一个地理空间索引，如下所示：

```sql
> db.areaMapGeoJSON.ensureIndex({"co" : "2dsphere"})
> db.worldMap.ensureIndex({geometry:'2dsphere'})

```

1.  我们现在将首先查询`areaMapGeoJSON`集合，如下所示：

```sql
> db.areaMapGeoJSON.find(
{  co:{
 $near:{
 $geometry:{
 type:'Point',
 coordinates:[12, 8]
 }
 }
 },
 type:'R'
}).limit(3)

```

1.  接下来，我们将尝试找到所有落在由点(0, 0)、(0, 11)、(11, 11)和(11, 0)之间的正方形内的餐馆。请参考上一个食谱介绍中给出的图形，以清晰地看到点和预期结果。

1.  编写以下查询并观察结果：

```sql
> db.areaMapGeoJSON.find(
{  co:{
 $geoIntersects:{
 $geometry:{
 type:'Polygon',
 coordinates:[[[0, 0], [0, 11], [11, 11], [11, 0], [0, 0]]]
 }
 }
 },
 type:'R'
})

```

检查它是否包含预期的坐标(2, 6)、(10, 5)和(10, 1)处的三家餐馆。

1.  接下来，我们将尝试执行一些操作，找到完全位于另一个封闭多边形内的所有匹配对象。假设我们想找到一些位于给定正方形街区内的公交车站。可以使用`$geoWithin`操作符来解决这类用例，实现它的查询如下：

```sql
> db.areaMapGeoJSON.find(
 {co:{
 $geoWithin:{
 $geometry:{ type: 'Polygon', coordinates : [[ [3, 9], [3, 24], [6, 24], [6, 9], [3, 9]] ]}
 }
 },
 type:'B'
 }
)

```

1.  验证结果；我们应该在结果中有三个公交车站。参考上一个食谱介绍中的地图图像，以获取查询的预期结果。

1.  当我们执行上述命令时，它们只是按距离升序打印文档。但是，我们在结果中看不到实际的距离。让我们执行与第 3 点中相同的查询，并额外获取计算出的距离如下：

```sql
> db.runCommand({ 
 geoNear: "areaMapGeoJSON",
 near: [ 12, 8 ],
 spherical: true,
 limit:3,
 query:{type:'R'}
 }
)

```

1.  查询返回一个文档，其中包含一个名为 results 的字段内的数组，其中包含匹配的文档和计算出的距离。结果还包含一些额外的统计信息，包括最大距离，结果中距离的平均值，扫描的总文档数以及以毫秒为单位的所用时间。

1.  最后，我们将在世界地图集合上查询，找出提供的坐标位于哪个国家。从 mongo shell 执行以下查询：

```sql
> db.worldMap.find(
 {geometry:{
 $geoWithin:{
 $geometry:{
 type:'Point',
 coordinates:[7, 52]
 }
 }
 }
 }
 ,{properties:1, _id:0}
)

```

1.  我们可以对`worldMap`集合执行的所有可能操作都很多，而且并非所有操作都在这个食谱中都能实际覆盖到。我鼓励你尝试使用这个集合并尝试不同的用例。

## 它是如何工作的...

从 MongoDB 2.4 版本开始，JSON 中存储地理空间数据的标准方式也得到了支持。请注意，我们看到的传统方法也得到了支持。但是，如果你是从头开始的，建议出于以下原因采用这种方法。

+   这是一个标准的，任何了解规范的人都可以轻松理解文档的结构

+   它使存储复杂形状、多边形和多条线变得容易。

+   它还让我们可以使用`$geoIntersect`和其他一组新的操作符轻松查询形状的交集

为了使用 GeoJSON 兼容的文档，我们将 JSON 文档导入到`areaMapGeoJSON`集合中，并按以下方式创建索引：

```sql
> db.areaMapGeoJSON.ensureIndex({"co" : "2dsphere"})

```

集合中的数据与我们在上一个食谱中导入到`areaMap`集合中的数据类似，但结构不同，与 JSON 格式兼容。这里使用的类型是 2Dsphere 而不是 2D。2Dsphere 类型的索引还考虑了球面表面的计算。请注意，我们正在创建地理空间索引的字段`co`不是坐标数组，而是一个符合 GeoJSON 的文档本身。

我们查询`$near`操作符的值不是坐标数组，而是一个带有`$geometry`键的文档，其值是一个具有坐标的 GeoJSON 兼容文档。无论我们使用的查询是什么，结果都是相同的。参考本食谱中的第 3 点和上一个食谱中的第 5 点，以查看查询中的差异。使用 GeoJSON 的方法看起来更复杂，但它有一些优势，我们很快就会看到。

重要的是要注意，我们不能混合两种方法。尝试在`areaMap`集合上执行我们刚刚执行的 GeoJSON 格式的查询，尽管我们不会收到任何错误，但结果是不正确的。

我们在本示例的第 5 点中使用了`$geoIntersects`运算符。这只有在数据库中以 GeoJSON 格式存储文档时才可能。查询简单地找到我们的情况下与我们创建的任何形状相交的所有点。我们使用 GeoJSON 格式创建多边形如下：

```sql
{
  type:'Polygon',
  coordinates:[[[0, 0], [0, 11], [11, 11], [11, 0], [0, 0]]]
}
```

这些坐标是正方形的，按顺时针方向给出四个角，最后一个坐标与第一个坐标相同，表示它是完整的。执行的查询与`$near`相同，除了`$near`运算符被`$geoIntersects`替换，`$geometry`字段的值是我们希望在`areaMapGeoJSON`集合中找到相交点的多边形的 GeoJSON 文档。如果我们看一下得到的结果，并查看介绍部分或上一个示例中的图形，它们确实是我们期望的。

我们还在第 12 点看到了`$geoWithin`运算符，当我们想要找到点或者在另一个多边形内部时，这是非常方便的。请注意，只有完全在给定多边形内部的形状才会被返回。假设，类似于我们的`worldMap`集合，我们有一个`cities`集合，其中的坐标以类似的方式指定。然后，我们可以使用一个国家的多边形来查询在`cities`集合中位于其中的所有多边形，从而给出城市。显然，一个更简单和更快的方法是在城市文档中存储国家代码。或者，如果城市集合中有一些数据缺失，而且国家不存在，可以使用城市多边形内的任意一点（因为一个城市完全位于一个国家内），并在`worldMap`集合上执行查询来获取它的国家，这是我们在第 12 点中演示的。

我们之前看到的一些组合可以很好地用于计算两点之间的距离，甚至执行一些几何操作。

一些功能，比如获取存储在集合中的 GeoJSON 多边形图形的质心，甚至是多边形的面积，都不是开箱即用的，应该有一些实用函数来帮助计算这些坐标。这些功能很好，通常是必需的，也许在将来的版本中我们可能会有一些支持；这些操作需要开发人员自己实现。此外，没有直接的方法来查找两个多边形之间是否有重叠，它们的坐标在哪里重叠，重叠的面积等等。我们看到的`$geoIntersects`运算符告诉我们哪些多边形与给定的多边形、点或线相交。

尽管与 Mongo 无关，但 GeoJSON 格式不支持圆，因此无法使用 GeoJSON 格式在 Mongo 中存储圆。有关地理空间运算符的更多详细信息，请参考以下链接[`docs.mongodb.org/manual/reference/operator/query-geospatial/`](http://docs.mongodb.org/manual/reference/operator/query-geospatial/)。

# 在 Mongo 中实现全文搜索

我们中的许多人（我可以毫不夸张地说所有人）每天都使用 Google 在网上搜索内容。简单来说：我们在 Google 页面的文本框中提供的文本用于搜索它所索引的网页。搜索结果然后以一定顺序返回给我们，这个顺序是由 Google 的页面排名算法确定的。我们可能希望在我们的数据库中有类似的功能，让我们搜索一些文本内容并给出相应的搜索结果。请注意，这种文本搜索与查找作为句子的一部分的文本不同，后者可以很容易地使用正则表达式来完成。它远远超出了那个范围，可以用来获取包含相同单词、类似发音的单词、具有相似基本单词，甚至是实际句子中的同义词的结果。

自 MongoDB 2.4 版本以来，引入了文本索引，它让我们可以在文档的特定字段上创建文本索引，并在这些单词上启用文本搜索。在这个示例中，我们将导入一些文档，并在它们上创建文本索引，然后查询以检索结果。

## 准备工作

测试需要一个简单的单节点。参考第一章的*安装单节点 MongoDB*一节，了解如何启动服务器。但是，不要立即启动服务器。在启动过程中将提供一个额外的标志来启用文本搜索。从 Packt 网站下载文件`BlogEntries.json`，并将其保存在本地驱动器上以备导入。

## 操作步骤…

1.  启动 MongoDB 服务器监听端口`27017`，如下所示。一旦服务器启动，我们将按以下方式在集合中创建测试数据。将文件`BlogEntries.json`放在当前目录中，我们将使用`mongoimport`创建`userBlog`集合，如下所示：

```sql
$ mongoimport -d test -c userBlog --drop BlogEntries.json

```

1.  现在，通过在操作系统 shell 中输入以下命令，从 mongo shell 连接到`mongo`进程：

```sql
$ mongo

```

1.  连接后，按照以下步骤对`userBlog`集合中的文档有所了解：

```sql
> db.userBlog.findOne()

```

1.  我们感兴趣的字段是`blog_text`，这是我们将创建文本搜索索引的字段。

1.  按照以下步骤在文档的`blog_text`字段上创建文本索引：

```sql
> db.userBlog.ensureIndex({'blog_text':'text'})

```

1.  现在，在 mongo shell 中对集合执行以下搜索：

```sql
$ db.userBlog.find({$text: {$search : 'plot zoo'}})

```

查看所得到的结果。

1.  执行另一个搜索，如下所示：

```sql
$ db.userBlog.find({$text: {$search : 'Zoo -plot'}})

```

## 工作原理…

现在让我们看看它是如何工作的。文本搜索是通过一个称为反向索引的过程来完成的。简单来说，这是一个机制，将句子分解为单词，然后这些单词分别指向它们所属的文档。然而，这个过程并不是直接的，所以让我们高层次地逐步看看这个过程中发生了什么：

1.  考虑以下输入句子，`I played cricket yesterday`。第一步是将这个句子分解为标记，它们变成了[`I`, `played`, `cricket`, `yesterday`]。

1.  接下来，从拆分的句子中删除停用词，我们将得到这些词的子集。停用词是一组非常常见的词，它们被排除在外是因为将它们索引化没有意义，因为它们在搜索查询中使用时可能会影响搜索的准确性。在这种情况下，我们将得到以下单词[`played`, `cricket`, `yesterday`]。停用词是与语言相关的，对于不同的语言将会有不同的停用词。

1.  最后，这些单词被转换为它们的基本词，这种情况下将会是[`play`, `cricket`, `yesterday`]。词干提取是将一个词减少到其词根的过程。例如，所有的单词`play`, `playing`, `played`, 和 `plays`都有相同的词根词`play`。有很多算法和框架用于将一个词提取为其词根形式。参考维基百科[`en.wikipedia.org/wiki/Stemming`](http://en.wikipedia.org/wiki/Stemming)页面，了解更多关于词干提取和用于此目的的算法的信息。与消除停用词类似，词干提取算法是与语言相关的。这里给出的例子是针对英语的。

如果我们查看索引创建过程，它是如下创建的`db.userBlog.ensureIndex({'blog_text':'text'})`。JSON 参数中给定的键是要在其上创建文本索引的字段的名称，值将始终是表示要创建的索引是文本索引的文本。创建索引后，在高层次上，前面的三个步骤在每个文档中所创建的索引字段的内容上执行，并创建反向索引。您还可以选择在多个字段上创建文本索引。假设我们有两个字段，`blog_text1`和`blog_text2`；我们可以将索引创建为`{'blog_text1': 'text', 'blog_text2':'text'}`。值`{'$**':'text'}`在文档的所有字段上创建索引。

最后，我们通过调用以下命令执行了搜索操作：`db.userBlog.find({$text: {$search : 'plot zoo'}})`。

此命令在集合`userBlog`上运行文本搜索，使用的搜索字符串是`plot zoo`。这会按任意顺序在文本中搜索值`plot`或`zoo`。如果我们查看结果，我们会看到有两个匹配的文档，并且文档按得分排序。得分告诉我们所搜索的文档的相关性如何，得分越高，相关性越大。在我们的情况下，一个文档中同时包含单词 plot 和 zoo，因此得分比另一个文档高。

要在结果中获取得分，我们需要稍微修改查询，如下所示：

```sql
db.userBlog.find({$text:{$search:'plot zoo'}}, {score: { $meta: "textScore"}})

```

现在我们在`find`方法中提供了一个额外的文档，询问文本匹配的计算得分。结果仍然没有按得分降序排序。让我们看看如何按得分排序：

```sql
db.userBlog.find({$text:{$search:'plot zoo'}}, { score: { $meta: "textScore" }}).sort({score: { $meta: "textScore"}})

```

正如我们所看到的，查询与以前相同，只是我们添加了额外的`sort`函数，它将按得分降序对结果进行排序。

当搜索执行为`{$text:{$search:'Zoo -plot'}`时，它会搜索包含单词`zoo`但不包含单词`plot`的所有文档，因此我们只得到一个结果。`-`符号用于否定，并且将包含该单词的文档排除在搜索结果之外。但是，不要期望通过在搜索中只给出`-plot`来找到所有不包含单词 plot 的文档。

如果我们查看作为搜索结果返回的内容，它包含了整个匹配的文档。如果我们对整个文档不感兴趣，而只对其中的一些文档感兴趣，我们可以使用投影来获取文档的所需字段。例如，以下查询`db.userBlog.find({$text: {$search : 'plot zoo'}},{_id:1})`将与在`userBlog`集合中查找包含单词 zoo 或 plot 的所有文档相同，但结果将包含所得文档的`_id`字段。

如果多个字段用于创建索引，则文档中的不同字段可能具有不同的权重。例如，假设`blog_text1`和`blog_text2`是集合的两个字段。我们可以创建一个索引，其中`blog_text1`的权重高于`blog_text2`，如下所示：

```sql
db.collection.ensureIndex(
  {
    blog_text1: "text", blog_text2: "text"
  },
  {
    weights: {
      blog_text1: 2,
      blog_text2: 1,
    },
    name: "MyCustomIndexName"
  }
)
```

这使得`blog_text1`中的内容的权重是`blog_text2`的两倍。因此，如果一个词在两个文档中被找到，但是在第一个文档的`blog_text1`字段和第二个文档的`blog_text2`中出现，那么第一个文档的得分将比第二个文档更高。请注意，我们还使用`MyCustomIndexName`字段提供了索引的名称。

我们还从语言键中看到，这种情况下的语言是英语。MongoDB 支持各种语言来实现文本搜索。语言在索引内容时很重要，因为它们决定了停用词，并且词干提取也是特定于语言的。

访问链接[`docs.mongodb.org/manual/reference/command/text/#text-search-languages`](http://docs.mongodb.org/manual/reference/command/text/#text-search-languages)以获取 Mongo 支持的文本搜索语言的更多详细信息。

那么，在创建索引时如何选择语言呢？默认情况下，如果没有提供任何内容，索引将被创建，假定语言是英语。但是，如果我们知道语言是法语，我们将如下创建索引：

```sql
db.userBlog.ensureIndex({'text':'text'}, {'default_language':'french'})

```

假设我们最初是使用法语创建索引的，`getIndexes`方法将返回以下文档：

```sql
[
  {
    "v" : 1,
    "key" : {
      "_id" : 1
    },
    "ns" : "test.userBlog",
    "name" : "_id_"
  },
  {
    "v" : 1,
    "key" : {
      "_fts" : "text",
      "_ftsx" : 1
    },
    "ns" : "test.userBlog",
    "name" : "text_text",
    "default_language" : "french",
    "weights" : {
      "text" : 1
    },
    "language_override" : "language",
    "textIndexVersion" : 1
  }
]
```

但是，如果每个文档的语言不同，这在博客等场景中非常常见，我们有一种方法。如果我们查看上面的文档，`language_override`字段的值是 language。这意味着我们可以使用此字段在每个文档的基础上存储内容的语言。如果没有，该值将被假定为默认值，在前面的情况下为`french`。因此，我们可以有以下内容：

```sql
{_id:1, language:'english', text: ….}  //Language is English
{_id:2, language:'german', text: ….}  //Language is German
{_id:3, text: ….}      //Language is the default one, French in this case
```

## 还有更多...

要在生产中使用 MongoDB 文本搜索，您需要 2.6 或更高版本。还可以将 MongoDB 与 Solr 和 Elasticsearch 等其他系统集成。在下一个配方中，我们将看到如何使用 mongo-connector 将 Mongo 集成到 Elasticsearch 中。

## 另请参阅

+   有关`$text`运算符的更多信息，请访问[`docs.mongodb.org/manual/reference/operator/query/text/`](http://docs.mongodb.org/manual/reference/operator/query/text/)

# 将 MongoDB 集成到 Elasticsearch 进行全文搜索

MongoDB 已经集成了文本搜索功能，就像我们在上一个配方中看到的那样。但是，有多种原因会导致人们不使用 Mongo 文本搜索功能，而是退回到 Solr 或 Elasticsearch 等传统搜索引擎，以下是其中的一些原因：

+   文本搜索功能在 2.6 版本中已经准备就绪。在 2.4 版本中，它是以测试版引入的，不适用于生产用例。

+   像 Solr 和 Elasticsearch 这样的产品是建立在 Lucene 之上的，它在搜索引擎领域已经证明了自己。Solr 和 Elasticsearch 也是相当稳定的产品。

+   您可能已经对 Solr 和 Elasticsearch 等产品有所了解，并希望将其作为全文搜索引擎，而不是 MongoDB。

+   您可能会发现在 MongoDB 搜索中缺少一些特定功能，而您的应用程序可能需要这些功能，例如 facets。

设置专用搜索引擎确实需要额外的工作来将其与 MongoDB 实例集成。在这个配方中，我们将看到如何将 MongoDB 实例与搜索引擎 Elasticsearch 集成。

我们将使用 mongo-connector 进行集成。这是一个开源项目，可以在[`github.com/10gen-labs/mongo-connector`](https://github.com/10gen-labs/mongo-connector)上找到。

## 准备工作

有关使用 Python 客户端连接单节点的配方，请参阅第一章中的*安装和启动服务器*。pip 工具用于获取 mongo-connector。但是，如果您在 Windows 平台上工作，之前没有提到安装 pip 的步骤。访问网址[`sites.google.com/site/pydatalog/python/pip-for-windows`](https://sites.google.com/site/pydatalog/python/pip-for-windows)以获取 Windows 版的 pip。

开始单实例所需的先决条件是我们在这个配方中所需要的。然而，为了演示目的，我们将作为一个节点副本集启动服务器。

从 Packt 网站下载文件`BlogEntries.json`，并将其保存在本地驱动器上，准备导入。

从以下 URL 下载您的目标平台的 elastic search：[`www.elasticsearch.org/overview/elkdownloads/`](http://www.elasticsearch.org/overview/elkdownloads/)。提取下载的存档，并从 shell 中转到提取的`bin`目录。

我们将从 GitHub.com 获取 mongo-connector 源代码并运行它。为此需要 Git 客户端。在您的计算机上下载并安装 Git 客户端。访问 URL[`git-scm.com/downloads`](http://git-scm.com/downloads)并按照说明在目标操作系统上安装 Git。如果您不愿意在操作系统上安装 Git，则有另一种选择，可以让您将源代码作为存档下载。

访问以下 URL[`github.com/10gen-labs/mongo-connector`](https://github.com/10gen-labs/mongo-connector)。在这里，我们将获得一个选项，让我们将当前源代码作为存档下载，然后我们可以在本地驱动器上提取它。以下图片显示了下载选项位于右下角：

![准备就绪](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-cb/img/B04831_05_03.jpg)

### 注意

请注意，我们也可以使用 pip 以非常简单的方式安装 mongo-connector，如下所示：

```sql
pip install mongo-connector

```

但是，PyPi 中的版本非常旧，不支持许多功能，因此建议使用存储库中的最新版本。

与之前的配方类似，在那里我们在 Mongo 中看到了文本搜索，我们将使用相同的五个文档来测试我们的简单搜索。下载并保留`BlogEntries.json`文件。

## 如何做…

1.  在这一点上，假设 Python 和 PyMongo 已安装，并且为您的操作系统平台安装了 pip。我们现在将从源代码获取 mongo-connector。如果您已经安装了 Git 客户端，我们将在操作系统 shell 上执行以下操作。如果您决定将存储库下载为存档，则可以跳过此步骤。转到您想要克隆连接器存储库的目录，并执行以下操作：

```sql
$ git clone https://github.com/10gen-labs/mongo-connector.git
$ cd mongo-connector
$ python setup.py install

```

1.  上述设置还将安装将被此应用程序使用的 Elasticsearch 客户端。

1.  我们现在将启动单个 mongo 实例，但作为副本集。从操作系统控制台执行以下操作：

```sql
$  mongod --dbpath /data/mongo/db --replSet textSearch --smallfiles --oplogSize 50

```

1.  启动 mongo shell 并连接到已启动的实例：

```sql
$ mongo

```

1.  从 mongo shell 开始初始化副本集如下：

```sql
> rs.initiate()

```

1.  副本集将在几分钟内初始化。与此同时，我们可以继续启动`elasticsearch`服务器实例。

1.  在提取的`elasticsearch`存档的`bin`目录中执行以下命令：

```sql
$ elasticsearch

```

1.  我们不会涉及 Elasticsearch 设置，我们将以默认模式启动它。

1.  一旦启动，输入以下 URL 到浏览器`http://localhost:9200/_nodes/process?pretty`。

1.  如果我们看到以下 JSON 文档，给出了进程详细信息，我们已成功启动了`elasticsearch`。

```sql
{
 "cluster_name" : "elasticsearch",
 "nodes" : {
 "p0gMLKzsT7CjwoPdrl-unA" : {
 "name" : "Zaladane",
 "transport_address" : "inet[/192.168.2.3:9300]",
 "host" : "Amol-PC",
 "ip" : "192.168.2.3",
 "version" : "1.0.1",
 "build" : "5c03844",
 "http_address" : "inet[/192.168.2.3:9200]",
 "process" : {
 "refresh_interval" : 1000,
 "id" : 5628,
 "max_file_descriptors" : -1,
 "mlockall" : false
 }
 }
 }
}

```

1.  一旦`elasticsearch`服务器和 mongo 实例启动并运行，并且安装了必要的 Python 库，我们将启动连接器，该连接器将在启动的 mongo 实例和`elasticsearch`服务器之间同步数据。出于这个测试的目的，我们将在`test`数据库中使用`user_blog`集合。我们希望在文档中实现文本搜索的字段是`blog_text`。

1.  从操作系统 shell 启动 mongo-connector 如下。以下命令是在 mongo-connector 的目录中执行的。

```sql
$ python mongo_connector/connector.py -m localhost:27017 -t http://localhost:9200 -n test.user_blog --fields blog_text -d mongo_connector/doc_managers/elastic_doc_manager.py

```

1.  使用`mongoimport`实用程序将`BlogEntries.json`文件导入集合如下。该命令是在当前目录中执行的`.json`文件。

```sql
$ mongoimport -d test -c user_blog BlogEntries.json --drop

```

1.  打开您选择的浏览器，并在其中输入以下 URL：`http://localhost:9200/_search?q=blog_text:facebook`。

1.  您应该在浏览器中看到类似以下内容的内容：![如何做…](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-cb/img/B04831_05_04.jpg)

## 它是如何工作的…

Mongo-connector 基本上是尾随 oplog 以查找它发布到另一个端点的新更新。在我们的情况下，我们使用了 elasticsearch，但也可以是 Solr。您可以选择编写一个自定义的 DocManager，它将插入连接器。有关更多详细信息，请参阅维基[`github.com/10gen-labs/mongo-connector/wiki`](https://github.com/10gen-labs/mongo-connector/wiki)，自述文件[`github.com/10gen-labs/mongo-connector`](https://github.com/10gen-labs/mongo-connector)也提供了一些详细信息。

我们给连接器提供了选项`-m`，`-t`，`-n`，`--fields`和`-d`，它们的含义如下表所述：

| 选项 | 描述 |
| --- | --- |
| `-m` | 连接器连接到以获取要同步的数据的 MongoDB 主机的 URL。 |
| `-t` | 要将数据与之同步的系统的目标 URL。在本例中是 elasticsearch。URL 格式将取决于目标系统。如果选择实现自己的 DocManager，则格式将是您的 DocManager 理解的格式。 |
| `-n` | 这是我们希望与外部系统保持同步的命名空间。连接器将在 oplog 中寻找这些命名空间的更改以获取数据。如果要同步多个命名空间，则值将以逗号分隔。 |
| `--fields` | 这些是将发送到外部系统的文档字段。在我们的情况下，索引整个文档并浪费资源是没有意义的。建议只向索引中添加您希望添加文本搜索支持的字段。在结果中还包括标识符`_id`和源的命名空间，正如我们在前面的屏幕截图中所看到的。然后可以使用`_id`字段来查询目标集合。 |
| `-d` | 这是要使用的文档管理器，在我们的情况下，我们使用了 elasticsearch 的文档管理器。 |

有关更多支持的选项，请参阅 GitHub 上连接器页面的自述文件。

一旦在 MongoDB 服务器上执行插入操作，连接器就会检测到其感兴趣的集合`user_blog`中新添加的文档，并开始从新文档中发送要索引的数据到 elasticsearch。为了确认添加，我们在浏览器中执行查询以查看结果。

Elasticsearch 将抱怨索引名称中有大写字符。mongo-connector 没有处理这个问题，因此集合的名称必须是小写。例如，名称`userBlog`将失败。

## 还有更多...

我们没有对 elasticsearch 进行任何额外的配置，因为这不是本教程的目标。我们更感兴趣的是集成 MongoDB 和 elasticsearch。您需要参考 elasticsearch 文档以获取更高级的配置选项。如果需要与 elasticsearch 集成，elasticsearch 中还有一个称为 rivers 的概念可以使用。Rivers 是 elasticsearch 从另一个数据源获取数据的方式。对于 MongoDB，可以在[`github.com/richardwilly98/elasticsearch-river-mongodb/`](https://github.com/richardwilly98/elasticsearch-river-mongodb/)找到 river 的代码。此存储库中的自述文件中有关于如何设置的步骤。

在本章中，我们看到了一个名为*在 Mongo 中使用 oplog 实现触发器*的教程，介绍了如何使用 Mongo 实现类似触发器的功能。这个连接器和 elasticsearch 的 MongoDB river 依赖于相同的逻辑，以在需要时从 Mongo 中获取数据。

## 另请参阅

+   您可以在[`www.elasticsearch.org/guide/en/elasticsearch/reference/`](http://www.elasticsearch.org/guide/en/elasticsearch/reference/)找到更多的 elasticsearch 文档。


# 第六章：监控和备份

在本章中，我们将查看以下教程：

+   注册 MMS 并设置 MMS 监控代理

+   在 MMS 控制台中管理用户和组

+   在 MMS 中监视实例并设置警报

+   在 MMS 中设置监控警报

+   使用现成的工具备份和恢复 Mongo 中的数据

+   配置 MMS 备份服务

+   在 MMS 备份服务中管理备份

# 介绍

在生产中，监控和备份是任何关键任务关键软件的重要方面。主动监控让我们在系统中发生异常事件时采取行动，这些事件可能危及数据一致性、可用性或系统性能。如果没有主动监控系统，问题可能在对系统产生重大影响后才会显现出来。我们在第四章中涵盖了与管理相关的教程，这两个活动都是其中的一部分；但是，它们需要一个单独的章节，因为要涵盖的内容很广泛。在本章中，我们将看到如何使用**Mongo Monitoring Service**（**MMS**）监控 MongoDB 集群的各种参数并设置警报。我们将研究一些使用现成工具和 MMS 备份服务备份数据的机制。

# 注册 MMS 并设置 MMS 监控代理

MMS 是一个基于云或本地的服务，可以让您监视 MongoDB 集群。本地版本仅适用于企业订阅。它为管理员提供了一个中心位置，让管理员监视服务器实例的健康状况以及实例所在的服务器。在本教程中，我们将看到软件要求是什么，以及如何为 Mongo 设置 MMS。

## 准备工作

我们将启动一个`mongod`的单个实例，用于监视目的。参考第一章中的*安装单节点 MongoDB*的步骤，启动 MongoDB 实例并从 Mongo shell 连接到它。用于将 mongo 实例的统计信息发送到监控服务的监控代理使用 Python 和 pymongo。参考第一章中的*使用 Python 客户端连接到单节点*的步骤，了解如何安装 Python 和 pymongo，MongoDB 的 Python 客户端。

## 操作步骤…

如果您还没有 MMS 帐户，请登录[`mms.mongodb.com/`](https://mms.mongodb.com/)并注册一个帐户。注册并登录后，您应该看到以下页面：

![操作步骤…](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-cb/img/B04831_06_01.jpg)

单击**监控**下的**开始**按钮。

1.  一旦到达菜单中的**下载代理**选项，请单击适当的操作系统平台以下载代理。选择适当的操作系统平台后，按照给定的说明进行操作。也记下**apiKey**。例如，如果选择了 Windows 平台，我们将看到以下内容：![操作步骤…](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-cb/img/B04831_06_02.jpg)

1.  安装完成后，打开`monitoring-agent.config`文件。它将位于安装代理时选择的配置文件夹中。

1.  在文件中查找关键的`mmsApiKey`，并将其值设置为在第 1 步中记录的 API 密钥。

1.  一旦服务启动（我们必须在 Windows 上转到`services.msc`，可以通过在运行对话框中输入`services.msc`（Windows + *R*）并手动启动服务来完成）。服务将被命名为**MMS Monitoring Agent**。在网页上，点击**验证代理**按钮。如果一切顺利，启动的代理将被验证，并显示成功消息。

1.  下一步是配置主机。这个主机是从代理的角度看到的，在组织或个人基础设施上运行。下面的屏幕显示了用于添加主机的屏幕。主机名是内部主机名（客户网络上的主机名），云上的 MMS 不需要访问 MongoDB 进程。收集这些 mongodb 进程的数据并将数据发送到 MMS 服务的是代理。![如何操作...](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-cb/img/B04831_06_03.jpg)

一旦添加了主机的详细信息，请单击**验证主机**按钮。验证完成后，单击**开始监视**按钮。

我们已经成功设置了 MMS 并向其添加了一个将被监视的主机。

## 它是如何工作的...

在这个教程中，我们设置了一个 MMS 代理和监视一个独立的 MongoDB 实例。安装和设置过程非常简单。我们还添加了一个独立的实例，一切都很好。

假设我们已经设置并运行了一个副本集（参考第一章中的教程*作为副本集的一部分启动多个实例*，*安装和启动服务器*，了解如何启动副本集的更多细节），三个成员正在监听端口`27000`，`27001`和`27002`。参考*如何操作...*部分中的第 6 点，我们设置了一个独立的主机。在**主机类型**的下拉菜单中选择**副本集**，在**内部主机名**中，给出副本集的任何成员的有效主机名（在我的情况下，给出了**Amol-PC**和端口**27001**，这是一个辅助实例）；所有其他实例将被自动发现，并在主机下可见，如下所示：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-cb/img/B04831_06_05.jpg)

我们没有看到在集群上启用安全性时应该做什么，这在生产环境中非常常见，我们有副本集或分片设置。如果启用了身份验证，我们需要 MMS 代理收集统计信息的正确凭据。在添加新主机时（*如何操作...*部分的第 6 点），我们给出的**DB 用户名**和**DB 密码**应该具有至少`clusterAdmin`和`readAnyDatabase`角色。

## 还有更多...

在这个教程中，我们看到了如何设置 MMS 代理并从 MMS 控制台创建帐户。但是，我们可以作为管理员为 MMS 控制台添加组和用户，授予各种用户在不同组上执行各种操作的权限。在下一个教程中，我们将对 MMS 控制台中的用户和组管理进行一些解释。

# 在 MMS 控制台中管理用户和组

在上一个教程中，我们看到了如何设置 MMS 帐户并设置 MMS 代理。在这个教程中，我们将对如何设置组和用户访问 MMS 控制台进行一些解释。

## 准备工作

有关设置代理和 MMS 帐户，请参阅上一个教程。这是本教程的唯一先决条件。

## 如何操作...

1.  首先，转到屏幕左侧的**管理** | **用户**，如下所示：![如何操作...](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-cb/img/B04831_06_06.jpg)

在这里，您可以查看现有用户并添加新用户。单击前图中右上角的**添加用户**（圈起来的）按钮，您应该看到以下弹出窗口，允许您添加新用户：

![如何操作...](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-cb/img/B04831_06_08.jpg)

前面的屏幕将用于添加用户。注意各种可用角色。

1.  同样，转到**管理** | **我的组**，通过单击**添加组**按钮查看和添加新组。在文本框中，输入组的名称。请记住，您输入的组名应该在全球范围内可用。所给组的名称应在 MMS 的所有用户中是唯一的，而不仅仅是您的帐户。

1.  创建新组后，所有组的顶部左侧将显示一个下拉菜单，如下所示：![如何做…](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-cb/img/B04831_06_07.jpg)

1.  您可以使用此下拉菜单在组之间切换，该菜单应显示所选组相关的所有详细信息和统计信息。

### 注意

请记住，一旦创建了一个组，就无法删除。因此在创建时要小心。

## 工作原理…

我们在配方中所做的任务非常简单，不需要太多的解释，除了一个问题。何时以及为什么要添加一个组？当我们想要通过不同的环境或应用程序对 MongoDB 实例进行分隔时。每个组都将运行一个不同的 MMS 代理。当我们想要为应用程序的不同环境（开发、QA、生产等）创建单独的监控组时，就需要创建一个新组，并且每个组对用户有不同的权限。也就是说，同一个代理不能用于两个不同的组。在配置 MMS 代理时，我们为其提供一个唯一的 API 密钥。要查看组的 API 密钥，请从屏幕顶部的下拉菜单中选择适当的组（如果您的用户只能访问一个组，则看不到下拉菜单），然后转到**管理** | **组设置**，如下一个截图所示。**组 ID**和**API 密钥**都将显示在页面顶部。

![工作原理…](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-cb/img/B04831_06_09.jpg)

请注意，并非所有用户角色都会看到此选项。例如，只读用户只能个性化其个人资料，大多数其他选项将不可见。

# 在 MMS 上监视实例并设置警报

前面的几个配方向我们展示了如何设置 MMS 帐户，设置代理，添加主机以及管理用户对 MMS 控制台的访问。MMS 的核心目标是监视主机实例，这一点尚未讨论。在这个配方中，我们将对我们在第一个配方中添加到 MMS 的主机执行一些操作，并从 MMS 控制台监视它。

## 准备工作

按照配方*注册 MMS 并设置 MMS 监控代理*，这基本上就是这个配方所需的一切。您可以选择独立实例或副本集，两种方式都可以。此外，打开一个 mongo shell 并从中连接到主实例（它是一个副本集）。

## 如何做…

1.  首先登录 MMS 控制台，然后单击左侧的**部署**。然后再次单击子菜单中的**部署**链接，如下截图所示：![如何做…](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-cb/img/B04831_06_10.jpg)

单击其中一个主机名以查看显示各种统计信息的大量图表。在这个配方中，我们将分析其中大部分。

1.  打开为本书下载的捆绑包。在第四章中，*管理*，我们使用了一个 JavaScript 来使服务器忙于一些操作，名为`KeepServerBusy.js`。这次我们将使用相同的脚本。

1.  在操作系统 shell 中，使用当前目录中的`.js`文件执行以下操作。在我的情况下，shell 连接到主端口`27000`：

```sql
$ mongo KeepServerBusy.js --port 27000 --quiet

```

1.  一旦启动，保持运行并在开始监视 MMS 控制台上的图表之前给予 5 到 10 分钟。

## 工作原理…

在第四章中，*管理*，我们看到了一个配方，*mongostat 和 mongotop 实用程序*，演示了如何使用这些实用程序来获取当前操作和资源利用率。这是一种相当基本和有用的监视特定实例的方法。然而，MMS 为我们提供了一个地方来监视 MongoDB 实例，具有非常易于理解的图表。MMS 还为我们提供了`mongostat`和`mongotop`无法提供的历史统计信息。

在我们继续分析指标之前，我想提一下，在 MMS 监控的情况下，数据不会在公共网络上查询或发送。只有统计数据通过代理以安全通道发送。代理的源代码是开源的，如果需要，可以进行检查。mongod 服务器不需要从公共网络访问，因为基于云的 MMS 服务从不直接与服务器实例通信。是 MMS 代理与 MMS 服务通信。通常，一个代理足以监视多个服务器，除非您计划将它们分成不同的组。此外，建议在专用机器/虚拟机上运行代理，并且不与任何 mongod 或 mongos 实例共享，除非它是您正在监视的不太关键的测试实例组。

让我们在控制台上查看一些这些统计数据；我们从与内存相关的统计数据开始。下图显示了驻留内存、映射内存和虚拟内存。

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-cb/img/B04831_06_11.jpg)

正如我们所看到的，数据集的驻留内存为 82 MB，这是非常低的，它是 mongod 进程实际使用的物理内存。当前值明显低于可用的空闲内存，并且通常会随着时间的推移而增加，直到达到使用了大部分可用物理内存的程度。这由 mongod 服务器进程自动处理，即使机器上有可用内存，我们也不能强制它使用更多内存。

另一方面，映射内存大约是数据库的总大小，并由 MongoDB 进行映射。这个大小可以（通常）比可用的物理内存大得多，这使得 mongod 进程能够在内存中寻址整个数据集，即使它并不在内存中。MongoDB 将映射和加载数据的责任转移到底层操作系统。每当访问一个内存位置并且它在 RAM 中不可用（即驻留内存），操作系统会将页面加载到内存中，如果需要的话，会驱逐一些页面为新页面腾出空间。什么是内存映射文件？让我们尝试用一个超级精简的版本来看看。假设我们有一个 1 KB（1024 字节）的文件，而 RAM 只有 512 字节，显然我们无法将整个文件加载到内存中。但是，您可以要求操作系统将此文件映射到可用的 RAM 页面中。假设每个页面是 128 字节，那么总文件大小为 8 页（128 * 8 = 1024）。但是操作系统只能加载四个页面，我们假设它加载了前 4 个页面（达到 512 字节）。当我们访问第 200 个字节时，它是可以在内存中找到的，因为它在第 2 页上。但是如果我们访问第 800 个字节，逻辑上在第 7 页上，而这一页没有加载到内存中怎么办？操作系统会从内存中取出一页，并加载包含第 800 个字节的第 7 页。作为一个应用程序，MongoDB 给人的印象是所有东西都加载到了内存中，并且通过字节索引进行访问，但实际上并非如此，操作系统在背后为我们做了透明的工作。由于访问的页面不在内存中，我们必须去磁盘加载它到内存中，这就是所谓的**页面错误**。

回到图表中显示的统计数据，虚拟内存包含所有内存使用，包括映射内存以及任何额外使用的内存，比如与每个连接相关的线程堆栈的内存。如果启用了日志记录，这个大小肯定会比映射内存的两倍还要多，因为日志记录也会有一个单独的内存映射用于数据。因此，我们有两个地址映射相同的内存位置。这并不意味着页面会被加载两次。这只是意味着可以使用两个不同的内存位置来寻址相同的物理内存。非常高的虚拟内存可能需要一些调查。没有预先确定的太高或太低的定义；通常在你对系统的性能感到满意的正常情况下，这些值会被监视。然后应该将这些基准值与系统性能下降时看到的数字进行比较，然后采取适当的行动。

正如我们之前所看到的，当访问的内存位置不在常驻内存中时，会导致页面错误，从而使操作系统从内存中加载页面。这种 IO 活动肯定会导致性能下降，太多的页面错误会严重影响数据库性能。下面的屏幕截图显示了每分钟发生的相当多的页面错误。然而，如果使用的是固态硬盘而不是旋转硬盘，那么来自驱动器的寻道时间的影响可能不会显著。

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-cb/img/B04831_06_12.jpg)

当物理内存不足以容纳数据集并且操作系统需要将数据从磁盘加载到内存时，通常会发生大量页面错误。请注意，此统计数据显示在 Windows 平台上，并且对于非常琐碎的操作可能会显得很高。这个值是硬页错误和软页错误的总和，实际上并不能真正反映系统的好坏。在基于 Unix 的操作系统上，这些数字会有所不同。在撰写本书时，有一个 JIRA（[`jira.mongodb.org/browse/SERVER-5799`](https://jira.mongodb.org/browse/SERVER-5799)）正在开放，报告了这个问题。

你可能需要记住的一件事是，在生产系统中，MongoDB 与 NUMA 架构不兼容，即使可用内存似乎足够高，你可能会看到大量页面错误发生。有关更多详细信息，请参阅网址[`docs.mongodb.org/manual/administration/production-notes/`](http://docs.mongodb.org/manual/administration/production-notes/)。

还有一个额外的图表，提供了一些关于未映射内存的细节。正如我们在本节前面看到的，有三种类型的内存：映射内存、常驻内存和虚拟内存。映射内存始终小于虚拟内存。如果启用了日志记录，虚拟内存将是映射内存的两倍以上。如果我们看一下本节前面给出的图像，我们会发现映射内存为 192MB，而虚拟内存为 532MB。由于启用了日志记录，内存是映射内存的两倍以上。启用日志记录时，相同的数据页在内存中被映射两次。请注意，该页只被物理加载一次，只是可以使用两个不同的地址访问相同的位置。让我们找出虚拟内存（532MB）和两倍映射内存（384MB）之间的差异（2 * 192 = 384）。这些数字之间的差异是 148MB（532-384）。

我们在这里看到的是未映射内存的部分。这个值与我们刚刚计算的值相同。

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-cb/img/B04831_06_13.jpg)

如前所述，非映射内存的高低值并没有明确定义，但是当值达到 GB 时，我们可能需要进行调查；可能打开的连接数很高，我们需要检查是否有客户端应用程序在使用后没有关闭连接。有一个图表显示了打开的连接数，如下所示：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-cb/img/B04831_06_14.jpg)

一旦我们知道连接数，并且发现它与预期计数相比太高，我们将需要找到打开连接到该实例的客户端。我们可以从 shell 中执行以下 JavaScript 代码来获取这些详细信息。不幸的是，在撰写本书时，MMS 没有这个功能来列出客户端连接的详细信息。

```sql
testMon:PRIMARY> var currentOps = db.currentOp(true).inprog;
 currentOps.forEach(function(c) {
 if(c.hasOwnProperty('client')) {
 print('Client: ' + c.client + ", connection id is: " + c.desc);
 }
 //Get other details as needed 
 });

```

`db.currentOp`方法返回结果中所有空闲和系统操作。然后我们遍历所有结果并打印出客户端主机和连接详细信息。`currentOp`结果中的典型文档如下。您可以选择调整前面的代码，根据需要包含更多详细信息：

```sql
 {
 "opid" : 62052485,
 "active" : false,
 "op" : "query",
 "ns" : "",
 "query" : {
 "replSetGetStatus" : 1,
 "forShell" : 1
 },
 "client" : "127.0.0.1:64460",
 "desc" : "conn3651",
 "connectionId" : 3651,
 "waitingForLock" : false,
 "numYields" : 0,
 "lockStats" : {
 "timeLockedMicros" : {

 },
 "timeAcquiringMicros" : {

 }
 }
 }

```

在第四章中，我们看到了一个名为* mongostat 和 mongotop 实用程序*的配方，用于获取数据库被锁定的时间百分比以及每秒执行的更新、插入、删除和获取操作的数量。您可以参考这些配方并尝试它们。我们使用了与当前用于使服务器繁忙的相同的 JavaScript。

在 MMS 控制台中，我们有图表显示以下详细信息：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-cb/img/B04831_06_15.jpg)

第一个`opcounters`显示在特定时间点执行的操作数量。这应该类似于我们使用`mongostat`实用程序看到的内容。右侧的内容显示了数据库被锁定的时间百分比。下拉菜单列出了数据库名称。我们可以选择要查看统计信息的适当数据库。同样，这个统计数据可以使用`mongostat`实用程序来查看。唯一的区别是，使用命令行实用程序，我们可以看到当前时间的统计数据，而在这里我们也可以看到历史统计数据。

在 MongoDB 中，索引存储在 B 树中，下图显示了 B 树索引被访问、命中和未命中的次数。最低限度，RAM 应该足够容纳索引以实现最佳性能。因此，在这个度量标准中，未命中应该为 0 或非常低。未命中的次数过高会导致索引的页面错误，如果查询没有被覆盖，可能会导致相应数据的额外页面错误，也就是说，所有数据无法从索引中获取，这对性能来说是一个双重打击。在查询时的一个好的做法是使用投影，并且只从文档中获取必要的字段。每当我们选择的字段存在于索引中时，这对于查询是有帮助的，这种情况下查询变成了覆盖查询，所有必要的数据只从索引中获取。要了解更多关于覆盖索引的信息，请参考第二章中的*创建索引和查看查询计划*这个章节。

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-cb/img/B04831_06_16.jpg)

对于繁忙的应用程序，如果卷非常大，多个写入和读取操作争夺锁定，操作排队。直到 MongoDB 的 2.4 版本，锁定是在数据库级别进行的。因此，即使在另一个集合上进行写入，对该数据库中的任何集合进行读取操作也会被阻塞。这种排队操作会影响系统的性能，并且是数据可能需要分片以扩展系统的良好指标。

### 提示

请记住，没有定义高或低的值；它是应用程序到应用程序基础上的可接受值。

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-cb/img/B04831_06_18.jpg)

MongoDB 立即从日志中刷新数据，并定期将数据文件刷新到磁盘。以下指标给出了在给定时间点每分钟的刷新时间。如果刷新占据了相当大的时间百分比，我们可以安全地说写操作正在形成性能瓶颈。

![工作原理...](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-cb/img/B04831_06_17.jpg)

## 还有更多...

在这篇文章中，我们看到了如何监视 MongoDB 实例/集群。然而，设置警报以在某些阈值值被超过时收到通知，这是我们还没有看到的。在下一篇文章中，我们将看到如何通过一个示例警报来实现这一点，当页面错误超过预定值时会通过电子邮件发送警报。

## 另请参阅

+   监视硬件，如 CPU 使用率，非常有用，MMS 控制台也支持。然而，需要安装 munin-node 才能启用 CPU 监视。请参考页面[`mms.mongodb.com/help/monitoring/configuring/`](http://mms.mongodb.com/help/monitoring/configuring/)设置 munin-node 和硬件监视。

+   要更新监控代理，请参考页面[`mms.mongodb.com/help/monitoring/tutorial/update-mms/`](http://mms.mongodb.com/help/monitoring/tutorial/update-mms/)。

# 在 MMS 中设置监控警报

在上一篇文章中，我们看到了如何从 MMS 控制台监视各种指标。这是一个很好的方式，可以在一个地方看到所有的统计数据，并了解 MongoDB 实例和集群的健康状况。然而，不可能持续 24/7 监视系统，对于支持人员来说必须有一些机制在某些阈值超过时自动发送警报。在这篇文章中，我们将设置一个警报，每当页面错误超过 1000 时就会触发。

## 准备工作

参考上一篇文章，设置使用 MMS 监视 Mongo 实例。这是本篇文章的唯一先决条件。

## 操作步骤...

1.  单击左侧菜单中的**活动**选项，然后单击**警报设置**。在**警报设置**页面上，单击**添加警报**。

1.  为**主机**添加一个新的警报，如果页面错误超过给定数量，即每分钟 1000 个页面错误。在这种情况下，通知选择为电子邮件，警报发送间隔为 10 分钟。![操作步骤...](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-cb/img/B04831_06_20.jpg)

1.  单击**保存**以保存警报。

## 工作原理...

这些步骤非常简单，我们成功地设置了当页面错误超过每分钟 1000 次时的 MMS 警报。正如我们在上一篇文章中看到的，没有固定值被归类为高或低。这是可以接受的，需要在您的环境中的测试阶段对系统进行基准测试。与页面错误类似，还有大量可以设置的警报。一旦触发警报，将按照我们设置的每 10 分钟发送一次，直到不满足发送警报的条件为止。在这种情况下，如果页面错误数量低于 1000 或有人手动确认了警报，那么将不会再发送进一步的警报。

如下面的屏幕截图所示，警报已打开，我们可以确认警报：

![工作原理...](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-cb/img/B04831_06_21.jpg)

单击**确认**后，将弹出以下窗口，让我们选择确认的持续时间：

![工作原理...](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-cb/img/B04831_06_30.jpg)

这意味着在这种特定情况下，直到所选时间段过去，将不会再发送警报。

单击左侧的**活动**菜单选项即可查看打开的警报。

## 另请参阅

+   访问网址[`www.mongodb.com/blog/post/five-mms-monitoring-alerts-keep-your-mongodb-deployment-track`](http://www.mongodb.com/blog/post/five-mms-monitoring-alerts-keep-your-mongodb-deployment-track)了解一些应该为您的部署设置的重要警报

# 使用现成的工具备份和恢复 Mongo 中的数据

在本教程中，我们将使用`mongodump`和`mongorestore`等实用程序进行一些基本的备份和恢复操作，以备份和恢复文件。

## 准备工作

我们将启动一个 mongod 的单个实例。请参阅第一章中的*安装单节点 MongoDB*教程，*安装和启动服务器*，以启动一个 mongo 实例并从 mongo shell 连接到它。我们需要一些要备份的数据。如果您的 test 数据库中已经有一些数据，那就很好。如果没有，请使用以下命令从代码包中的`countries.geo.json`文件创建一些数据：

```sql
$ mongoimport  -c countries -d test --drop countries.geo.json

```

## 如何做…

1.  有了`test`数据库中的数据，执行以下操作（假设我们要将数据导出到当前目录中名为`dump`的本地目录）：

```sql
$ mongodump -o dump -oplog -h localhost -port 27017

```

验证`dump`目录中是否有数据。所有文件将是`.bson`文件，每个文件对应相应数据库文件夹中的一个集合。

1.  现在让我们使用以下命令将数据导入 mongo 服务器。这里假设我们在当前目录中有一个名为`dump`的目录，并且其中有所需的`.bson`文件：

```sql
mongorestore --drop -h localhost -port 27017 dump -oplogReplay

```

## 它是如何工作的…

只需执行几个步骤即可导出和恢复数据。现在让我们看看它到底是做什么的，以及这个实用程序的命令行选项是什么。`mongodump`实用程序用于将数据库导出到`.bson`文件中，然后可以稍后用于恢复数据库中的数据。导出实用程序为每个数据库导出一个文件夹，除了本地数据库，然后每个文件夹中将有一个`.bson`文件。在我们的情况下，我们使用了`-oplog`选项来导出 oplog 的一部分，数据将导出到`oplog.bson`文件中。类似地，我们使用`mongorestore`实用程序将数据导入到数据库中。我们在导入和重放内容之前通过提供`--drop`选项显式要求删除现有数据，并重放 oplog 中的内容（如果有）。

`mongodump`实用程序简单地查询集合并将内容导出到文件中。集合越大，恢复内容所需的时间就越长。因此，在进行转储时建议防止写操作。在分片环境中，应关闭平衡器。如果在系统运行时进行转储，则使用`-oplog`选项导出 oplog 的内容。然后可以使用此 oplog 将数据恢复到特定时间点。以下表格显示了`mongodump`和`mongorestore`实用程序的一些重要选项，首先是`mongodump`：

| 选项 | 描述 |
| --- | --- |
| `--help` | 显示所有可能的支持选项以及这些选项的简要描述。 |
| `-h`或`--host` | 要连接的主机。默认情况下，它是端口`27017`上的 localhost。如果要连接到独立实例，则可以将主机名设置为`<主机名>:<端口号>`。对于副本集，格式将是`<副本集名称>/<主机名>:<端口>,….<主机名>:<端口>`，其中逗号分隔的主机名和端口列表称为**种子列表**。它可以包含副本集中所有或部分主机名。 |
| `--port` | 目标 MongoDB 实例的端口号。如果在之前的`-h`或`--host`选项中提供了端口号，则这并不重要。 |
| `-u`或`--username` | 提供要导出数据的用户的用户名。由于数据是从所有数据库中读取的，因此至少期望用户在所有数据库中具有读取权限。 |
| `-p`或`--password` | 与用户名一起使用的密码。 |
| `--authenticationDatabase` | 存储用户凭据的数据库。如果未指定，则使用`--db`选项中指定的数据库。 |
| `-d`或`--db` | 要备份的数据库。如果未指定，则导出所有数据库。 |
| `-c`或`--collection` | 要导出的数据库中的集合。 |
| `-o`或`--out` | 要导出文件的目录。默认情况下，实用程序将在当前目录中创建一个 dump 文件夹，并将内容导出到该目录。 |
| `--dbpath` | 如果我们不打算连接到数据库服务器，而是直接从数据库文件中读取。值是数据库文件所在目录的路径。在直接从数据库文件中读取时，服务器不应该处于运行状态，因为导出会锁定数据文件，如果服务器正在运行，这是不可能的。在获取锁时，将在目录中创建一个锁文件。 |
| `--oplog` | 启用此选项后，还会导出自导出过程开始时的 oplog 数据。如果不启用此选项，导出的数据将不会代表一个时间点，如果写操作同时进行，因为导出过程可能需要几个小时，它只是对所有集合进行查询操作。导出 oplog 可以恢复到某个时间点的数据。如果在导出过程中阻止写操作，则无需指定此选项。 |

同样，对于`mongorestore`实用程序，以下是选项的含义：`--help`，`-h`或`--host`，`--port`，`-u`或`--username`，`-p`或`--password`，`--authenticationDatabase`，`-d`或`--db`，`-c`或`--collection`。

| 选项 | 描述 |
| --- | --- |
| `--dbpath` | 如果我们不打算连接到数据库服务器，而是直接写入数据库文件，请使用此选项。值是数据库文件所在目录的路径。在直接写入数据库文件时，服务器不应该处于运行状态，因为恢复操作会锁定数据文件，如果服务器正在运行，这是不可能的。在获取锁时，将在目录中创建一个锁文件。 |
| `--drop` | 在从导出的转储数据中恢复数据之前删除集合中的现有数据。 |
| `--oplogReplay` | 如果在允许对数据库进行写操作的情况下导出了数据，并且在导出过程中启用了`--oplog`选项，则将在数据上重放导出的 oplog，以使数据库中的所有数据达到相同的时间点。 |
| `--oplogLimit` | 此参数的值是表示时间的秒数。此选项与`oplogReplay`命令行选项一起使用，用于告诉恢复实用程序重放 oplog，并在此选项指定的限制处停止。 |

你可能会想，“为什么不复制文件并备份呢？”这样做效果很好，但与此相关的问题有几个。首先，除非禁用写操作，否则无法获得点时间备份。其次，备份所使用的空间非常大，因为复制还会复制数据库的 0 填充文件，而`mongodump`只会导出数据。

话虽如此，文件系统快照是备份的常用做法。需要记住的一件事是，在进行快照时，日志文件和数据文件需要在同一个快照中以保持一致性。

如果您使用**亚马逊网络服务**（**AWS**），强烈建议您将数据库备份上传到 AWS S3。您可能知道，AWS 提供极高的数据冗余性，存储成本非常低。

从 Packt Publishing 网站下载脚本`generic_mongodb_backup.sh`，并使用它来自动创建备份并上传到 AWS S3。

# 配置 MMS 备份服务

MMS 备份是 MongoDB 的一个相对较新的功能，用于实时增量备份 MongoDB 实例、副本集和分片，并为您提供实例的时点恢复。该服务可用作本地部署（在您的数据中心）或云端。但是，我们将演示云端服务，这是 Community 和 Basic 订阅的唯一选项。有关可用选项的更多详细信息，您可以访问 MongoDB 在[`www.mongodb.com/products/subscriptions`](https://www.mongodb.com/products/subscriptions)上提供的不同产品。

## 准备就绪

Mongo MMS 备份服务仅适用于 Mongo 2.0 及以上版本。我们将启动一个我们将备份的单个服务器。MMS 备份依赖于 oplog 进行连续备份，由于 oplog 仅在副本集中可用，因此服务器需要作为副本集启动。有关如何安装 Python 和 Mongo 的 Python 客户端 PyMongo 的更多信息，请参阅第一章中的*使用 Python 客户端连接到单个节点*、*安装和启动服务器*。

## 操作步骤如下：

如果您还没有 MMS 帐户，请登录[`mms.mongodb.com/`](https://mms.mongodb.com/)并注册一个帐户。有关屏幕截图，请参阅本章中的*注册 MMS 并设置 MMS 监控代理*。

1.  启动 Mongo 的单个实例，并替换您的机器上适当文件系统路径的值：

```sql
$ mongod --replSet testBackup --smallfiles --oplogSize 50 --dbpath /data/mongo/db

```

请注意，`smallfiles`和`oplogSize`仅用于测试目的，并且不应在生产中使用。

1.  启动一个 shell，连接到第 1 步中的实例，并按以下方式启动副本集：

```sql
> rs.initiate()

```

副本集将在一段时间内启动并运行。

1.  返回到`mms.mongodb.com`的浏览器。点击**+添加主机**按钮添加新主机。将类型设置为副本集，主机名设置为您的主机名，端口设置为默认端口`27017`。有关**添加主机**过程的屏幕截图，请参阅*注册 MMS 并设置 MMS 监控代理*。

1.  一旦成功添加主机，请点击左侧的**备份**选项，然后点击**开始设置**注册 MMS 备份。

1.  可以使用短信或 Google Authenticator 进行注册。如果智能手机上有 Android、iOS 或 Blackberry OS，Google Authenticator 是一个不错的选择。对于印度等国家，Google Authenticator 是唯一可用的选项。

1.  假设 Google Authenticator 尚未配置，并且我们计划使用它，我们需要在智能手机上安装该应用。转到您的移动操作系统平台的相应应用商店并安装 Google Authenticator 软件。

1.  安装了手机软件后，返回浏览器。在选择 Google Authenticator 后，您应该看到以下屏幕：![操作步骤](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-cb/img/B04831_06_22.jpg)

1.  通过扫描 Google Authenticator 应用程序中的 QR 码开始设置新帐户。如果条形码扫描有问题，您可以选择在屏幕右侧手动输入给定的密钥。

1.  一旦成功扫描或输入密钥，您的智能手机应该显示一个每 30 秒更改一次的 6 位数字。在屏幕上的**认证代码**框中输入该数字。

### 注意

重要的是不要在手机上删除 Google Authenticator 中的此帐户，因为这将在将来我们希望更改与备份相关的任何设置时使用。一旦设置完成，QR 码和密钥将不再可见。您将需要联系 MongoDB 支持以重置配置。

1.  一旦认证完成，您应该看到的下一个屏幕是账单地址和账单详细信息，比如您注册的卡。所有低于 5 美元的费用都将免除，因此在收费之前，您应该可以尝试一个小的测试实例。

1.  一旦信用卡详细信息保存，我们将继续进行设置。我们将安装一个备份代理。这是一个与监控代理分开的代理。选择适当的平台，并按照其安装说明进行操作。记下代理的配置文件将放置的位置。

1.  一个新的弹出窗口将包含平台的存档/安装程序的指令/链接以及安装步骤。它还应该包含`apiKey`。记下 API 密钥；我们将在下一步中需要它。

1.  安装完成后，打开代理安装的`config`目录中的`local.config`文件（在代理安装期间显示/修改的位置），并粘贴/输入在上一步中记下的`apiKey`。

1.  一旦代理配置并启动，点击**验证代理**按钮。

1.  一旦代理成功验证，我们将开始添加一个要备份的主机。下拉菜单应该显示我们添加的所有副本集和分片。选择适当的副本集，并将**同步源**设置为主实例，因为这是我们独立实例中唯一的实例。**同步源**仅用于初始同步过程。每当我们有一个合适的副本集和多个实例时，我更喜欢使用次要作为同步过程实例。![如何做…](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-cb/img/B04831_06_23.jpg)

由于实例未启动安全性，将**DB 用户名**和**DB 密码**字段留空。

1.  如果您希望跳过特定数据库或集合的备份，请单击**管理排除的命名空间**按钮。如果没有提供任何内容，默认情况下将备份所有内容。集合名称的格式将是`<数据库名称>.<集合名称>`。或者，它可以只是数据库名称，在这种情况下，该数据库中的所有集合都不符合备份条件。

1.  一旦细节都没问题，点击**开始**按钮。这应该完成在 MMS 上为副本集设置备份过程的设置。

### 提示

我执行的安装步骤是在 Windows 操作系统上，服务在这种情况下需要手动启动。按下 Windows + *R*，输入`services.msc`。服务的名称是 MMS 备份代理。

## 工作原理…

这些步骤非常简单，这就是我们为 Mongo MMS 备份设置服务器所需做的一切。之前提到的一个重要事项是，一旦设置了备份，MMS 备份在任何操作中都使用多因素身份验证，并且为 MongoDB 在 Google Authenticator 中设置的帐户不应删除。没有办法恢复用于设置验证器的原始密钥。您将不得不清除 Google Authenticator 设置并设置一个新密钥。要做到这一点，点击屏幕左下角的**帮助和支持**链接，然后点击**如何重置我的双因素身份验证？**。

单击链接后，将打开一个新窗口并要求输入用户名。将向注册的电子邮件 ID 发送一封电子邮件，该电子邮件允许您重置双因素身份验证。

![工作原理…](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-cb/img/B04831_06_31.jpg)

如前所述，oplog 用于将当前 MongoDB 实例与 MMS 服务同步。但是，对于初始同步，将使用实例的数据文件。在设置副本集的备份时，我们提供要使用的实例。由于这是一个资源密集型操作，在繁忙的系统上，我更喜欢使用次要实例，以便不会通过 MMS 备份代理向主实例添加更多的查询。一旦实例完成初始同步，主实例的 oplog 将被用于持续获取数据。代理会定期向 admin 数据库中的`mms.backup`集合写入数据。

MMS 备份的备份代理与 MMS 监控代理不同。虽然在同一台机器上同时运行它们没有限制，但在生产环境中进行这样的设置之前，您可能需要评估一下。最保险的做法是让它们在不同的机器上运行。在生产环境中，不要在同一台机器上运行这两个代理与 mongod 或 mongos 实例。不建议在同一台机器上运行代理和 mongod 实例的原因有几个重要的原因：

+   代理的资源利用率取决于其监视的集群大小。我们不希望代理使用大量资源影响生产实例的性能。

+   代理可能同时监视许多服务器实例。由于只有一个代理实例，我们不希望在数据库服务器维护和重启期间出现故障。

使用 SSL 构建的 MongoDB 社区版或使用 SSL 选项进行通信的企业版必须执行一些额外的步骤。第一步是在为备份设置副本集时检查**我的部署支持 MongoDB 连接的 SSL**标志（见第 15 步）。请注意截图底部的复选框应该被选中。其次，打开 MMS 配置的`local.config`文件，并查找以下两个属性：

```sql
sslTrustedServerCertificates=
sslRequireValidServerCertificates=true
```

第一个是 PEM 格式的认证机构证书的完全限定路径。此证书将用于验证通过 SSL 运行的 mongod 实例呈现的证书。如果要禁用证书验证，则可以将第二个属性设置为`false`，但这并不是一个推荐的选项。就从代理向 MMS 服务发送的数据而言，无论您的 MongoDB 实例是否启用 SSL，通过 SSL 发送的数据都是安全的。备份数据中心中的数据在静态状态下是未加密的。

如果在 mongod 实例上启用了安全性，则需要提供用户名和密码，这将被 MMS 备份代理使用。在为副本集设置备份时提供用户名和密码，如第 15 步所示。由于代理需要读取 oplog，可能需要对所有数据库进行初始同步并将数据写入`admin`数据库，因此用户需要具有以下角色：`readAnyDatabase`，`clusterAdmin`，`admin`和`local`数据库上的`readWrite`，以及`userAdminAnyDatabase`。这适用于版本 2.4 及以上。在 v2.4 之前的版本中，我们期望用户对所有数据库具有读取权限，并对 admin 和 local 数据库具有读/写权限。

在为备份设置副本集时，您可能会遇到错误，如`Insufficient oplog size: The oplog window must be at least 1 hours over the last 24 hours for all active replica set members. Please increase the oplog.`。虽然您可能认为这总是与 oplog 大小有关，但当副本集中有一个处于恢复状态的实例时，也会出现这种情况。这可能会让人感到误导，因此在为副本集设置备份时，请注意查看是否有正在恢复的节点。根据 MMS 支持，似乎不允许为具有一些正在恢复节点的备份设置副本集，并且这可能会在将来得到修复。

# 在 MMS 备份服务中管理备份

在上一篇文章中，我们看到了如何设置 MMS 备份服务，并为备份设置了一个简单的单成员副本集。尽管单成员副本集根本没有意义，但由于独立实例无法在 MMS 中设置备份，因此需要它。在本篇文章中，我们将深入探讨在为备份设置的服务器上可以执行的操作，例如启动、停止或终止备份；管理排除列表；管理备份快照和保留；以及恢复到特定时间点的数据。

## 准备就绪

前面的步骤就是这个步骤所需的一切。预计已经完成了必要的设置，因为我们将在这个步骤中使用与备份相同的服务器。

## 操作步骤...

服务器已经运行，让我们向其导入一些数据。可以是任何数据，但我们选择使用上一章中使用的`countries.geo.json`文件。它应该在从 Packt 网站下载的捆绑软件中可用。

首先将数据导入到`test`数据库中名为`countries`的集合中。使用以下命令来执行。当前目录中有`countries.geo.json`文件时，执行以下导入命令：

```sql
$ mongoimport  -c countries -d test --drop countries.geo.json

```

我们已经看到了在设置副本集备份时如何排除命名空间。现在我们将看到在为副本集备份完成后如何排除命名空间。点击左侧的**备份**菜单选项，然后点击**副本集状态**，这在点击**备份**时会默认打开。点击显示副本集的行右侧的**齿轮**按钮。它应该看起来像这样：

![操作步骤...](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-cb/img/B04831_06_24.jpg)

1.  如前面的图片所示，点击**编辑排除的命名空间**，然后输入要排除的集合名称。假设我们要在`test`数据库中排除`applicationLogs`集合，输入`test.applicationLogs`。

1.  保存后，您将被要求输入当前在您的 Google Authenticator 上显示的令牌代码。

1.  成功验证代码后，`test.applicationLogs`命名空间将被添加到排除备份的命名空间列表中。

1.  现在我们将看到如何管理快照调度。快照是数据库在特定时间点的状态。要管理快照频率和保留策略，请点击前一个截图中显示的**齿轮**按钮，然后点击**编辑快照调度**。

1.  正如我们在下一张图片中所看到的，我们可以设置快照的拍摄时间和保留期限。我们将在下一节中更多讨论这个问题。对此的任何更改都需要多因素身份验证来保存更改。![操作步骤...](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-cb/img/B04831_06_25.jpg)

1.  现在我们将看到如何使用 MMS 备份恢复数据。在任何时候，当我们想要恢复数据时，点击**备份**和**副本集状态**/**分片集群状态**，然后点击**集合/集群名称**。

点击后，我们将看到保存在此集合中的快照。应该看起来像这样：

![操作步骤...](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-cb/img/B04831_06_26.jpg)

我们已经圈出了屏幕上的一些部分，我们将逐一看到。

1.  要恢复到快照拍摄时的时间点，请点击网格的**操作**列中的**恢复此快照**链接。![操作步骤...](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-cb/img/B04831_06_27.jpg)

1.  前面的图片向我们展示了如何通过 HTTPS 或 SCP 导出数据。我们现在选择 HTTPS，然后点击**验证**。我们将在下一节中了解 SCP。

1.  输入通过短信接收或在 Google Authenticator 上看到的令牌，然后点击**完成请求**以输入认证代码。

1.  成功验证后，点击**恢复作业**。这是一次性下载，让您可以下载`tar.gz`存档。点击**下载**链接以下载`tar.gz`存档。![操作步骤...](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-cb/img/B04831_06_28.jpg)

1.  下载存档后，解压以获取其中的数据库文件。

1.  停止 mongod 实例，用提取出的文件替换数据库文件，并重新启动服务器以获取快照拍摄时的数据。请注意，如果所有数据都被排除在备份之外，数据库文件将不包含该集合的数据。

1.  现在我们将看到如何使用 MMS 备份获取特定时间点的数据。

1.  点击**副本集状态**/**分片集群状态**，然后点击要恢复的集群/集合。

1.  在屏幕右侧，点击**恢复**按钮。

1.  这应该列出可用的快照，或者您可以输入自定义时间。勾选**使用自定义时间点**。单击**日期**字段，选择日期和时间，以便在小时和分钟中恢复数据，然后单击**下一步**。请注意，**时间点**功能只能恢复到过去 24 小时的时间点。

在这里，您将被要求指定格式为 HTTPS 或 SCP。后续步骤与我们上次做的类似，从第 14 步开始。

## 它是如何工作的...

设置副本集的备份后，我们向数据库导入了随机数据。这个数据库的备份将由 MMS 完成，稍后我们将使用这个备份来恢复数据库。我们看到了如何在步骤 2-5 中排除要备份的命名空间。

查看快照和保留策略设置，我们可以看到我们可以选择快照拍摄的时间间隔和保留的天数（步骤 9）。我们可以看到，默认情况下，快照每 6 小时拍摄一次，保存 2 天。在一天结束时拍摄的快照保存一周。在一周和一个月结束时拍摄的快照分别保存 4 周和 13 个月。快照可以每 6、8、12 和 24 小时拍摄一次。然而，您需要了解长时间间隔后拍摄快照的另一面。假设最后一张快照是在 18 小时拍摄的；获取那时的数据进行恢复非常容易，因为它存储在 MMS 备份服务器上。然而，我们需要 21:30 时的数据进行恢复。由于 MMS 备份支持时间点备份，它将使用 18:00 时的基本快照，然后在 21:30 时拍摄快照后对其进行更改。这类似于如何在数据上重放 oplog。这种重放是有成本的，因此获取时间点备份比从快照获取数据略微昂贵。在这里，我们需要重放 3.5 小时的数据，从 18:00 时到 21:30 时。想象一下，如果快照设置为每 12 小时拍摄一次，我们的第一张快照是在 00:00 时拍摄的，那么我们每天都会在 00:00 时和 12:00 时拍摄快照。要将数据恢复到 21:30 时，以 12:00 时为最后一个快照，我们将不得不重放 9.5 小时的数据。这要昂贵得多。

更频繁的快照意味着更多的存储空间使用，但恢复数据库到特定时间点所需的时间更少。与此同时，较少频繁的快照需要更少的存储空间，但以恢复数据到特定时间点为代价的时间更长。您需要在这两者之间做出决定并进行权衡，即空间和恢复时间。对于每日快照，我们可以选择保留 3 到 180 天。同样，对于每周和每月的快照，保留期可以分别选择 1 到 52 周和 1 到 36 个月。

在第 9 步的屏幕截图中，有一个列显示快照的到期时间。对于第一张拍摄的快照，到期时间是 1 年，而其他快照在 2 天后到期。到期时间如我们在上一段讨论的那样。更改到期值时，旧的快照不会受到影响或根据更改的时间进行调整。然而，根据修改后的保留和频率设置拍摄的新快照将会受到影响。

我们看到了如何下载转储（从第 10 步开始），然后使用它来恢复数据库中的数据。这非常简单，不需要太多解释，除了一些事情。首先，如果数据是用于分片，将会有多个文件夹，每个分片一个文件夹，每个文件夹都有数据库文件，与我们在副本集的情况下看到的不同，那里我们有一个包含数据库文件的单个文件夹。最后，让我们看看当我们选择 SCP 作为选项时的屏幕：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-cb/img/B04831_06_29.jpg)

SCP 是安全复制的缩写。文件将通过安全通道复制到计算机的文件系统中。给定的主机需要具有公共 IP，该 IP 将用于 SCP。当我们希望从 MMS 获取的数据传递到云上运行 Unix OS 的机器时，这是非常有意义的，例如，AWS 虚拟实例之一。与其在本地机器上使用 HTTPS 获取文件，然后重新上传到云上的服务器，不如在目标目录块中指定需要复制数据的位置，主机名和凭据。还有几种身份验证的方式。密码是一种简单的方式，还有一个额外的选项是 SSH 密钥对。如果您必须配置云上主机的防火墙以允许通过 SSH 端口的传入流量，公共 IP 地址将显示在屏幕底部（在我们的截图中为`64.70.114.115/32`或`4.71.186.0/24`）。您应该将它们列入白名单，以允许通过端口`22`进行安全复制请求的传入流量。

## 另请参阅

我们已经看到了使用 MMS 运行备份，该备份使用 oplogs 来实现这一目的。在第五章 *高级操作*中有一个名为*在 Mongo 中使用 oplog 实现触发器*的配方，该配方使用 oplog 来实现类似触发器的功能。这个概念是 MMS 备份服务使用的实时备份的基础。
