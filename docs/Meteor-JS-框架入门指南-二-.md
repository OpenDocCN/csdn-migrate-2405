# Meteor JS 框架入门指南（二）

> 原文：[`zh.annas-archive.org/md5/A6A998711E02B953FECB90E097CD1168`](https://zh.annas-archive.org/md5/A6A998711E02B953FECB90E097CD1168)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：数据，Meteor 风格！

我们已经接近完成借阅图书馆应用程序的开发，而无需过多担心我们的数据是如何被存储的。Meteor 的数据缓存和同步方法故意构建，以使应用程序这部分尽可能简单，这样你就可以集中精力编写伟大的程序，而不是花很多时间处理数据库连接、查询和缓存。

然而，我们确实想回顾一下方法，并确保我们有一个坚实的基础，了解 Meteor 如何处理数据，这样我们就可以进行一些常见的优化，并且更快地构建我们的应用程序。

在本章中，你将学习以下主题：

+   MongoDB 和文档导向存储

+   广播变化——Meteor 如何使你的网络应用具有反应性

+   配置发布者——如何优化和保护你的数据

# 文档导向存储

Meteor 使用 MongoDB 的一个版本（minimongo）来存储来自你模型的所有数据。它能够使用任何其他 NoSQL/文档导向数据库，但 MongoDB 随 Meteor 安装包默认提供。这个特点使得你的程序更简单、更容易编写，并且非常适合快速、轻量级的数据存储。

## 那么，为什么不使用关系型数据库呢？

传统上，数据是使用关系模型进行存储的。关系模型，以及它所有的相关规则、关系、逻辑和语法，是现代计算的一个不可或缺且极其有价值的部分。关系型数据库那种严格结构，对每个记录、关系和关联的精确要求，为我们提供了快速搜索、可扩展性以及深入分析的可能性。

然而，那种精确性并不总是必要的。例如，在我们的借阅图书馆的情况下，一个完整的关系型数据库可能是杀鸡用牛刀。实际上，在某些情况下，拥有一个灵活的数据存储系统更为有效，这个系统你可以快速扩展，而不需要大量的重编码。

例如，如果你想要向你的`list`对象添加一个新属性，只是简单地添加新属性，让数据库去操心，而不是必须重构你的数据库代码、添加新列、更新你所有的 SQL 语句和触发器，并确保所有之前的记录都有这个新属性，要简单得多。

文档导向存储就此发挥作用。在文档导向存储系统中，你的数据存储由一系列键值对文档组成。那个文档的结构是怎样的？数据存储其实并不关心。它可能包含几乎任何东西，只要每个记录有一个唯一的键，以便它可以被检索到。

所以，在一个文档条目中，你可能会有一个非常简单的文档。也许是一个键值对。

```js
{name:phone_number}
```

然后在另一个文档条目（在同一个数据存储中），你可能会有一个复杂的对象，有嵌套数组、嵌套对象等等。

```js
{ people: [
  {firstname:"STEVE", lastname:"Scuba", phones :[
    {type:cell, number:8888675309},
    {type:home, number:8005322002}]
  },
  {firstname:...
    ...
  }]
}
```

毕竟，它可能是威廉·莎士比亚的全集。真的不重要。只要数据存储能够为那个文档分配一个唯一的键，它就可以被存储。

正如您可能已经猜到的那样，缺乏结构*可以*使查询、排序和操作那些文档的效率降低。但没关系，因为我们的主要关注点是编码的便利性和开发速度，而不是效率。

此外，由于我们的应用程序只有几个核心功能，我们可以快速确定我们将最经常使用的查询，并将文档架构围绕那个进行优化。这使得在某些情况下，面向文档的数据库实际上比传统的关系数据库表现得*更好*。

### 提示

市场上有一些相当复杂的面向文档的存储解决方案，有些人认为它们与标准的关系数据库一样有效，甚至更有效，但这个讨论超出了本书的范围。

鉴于面向文档的存储系统的灵活性，它非常适合快速更改，Meteor 提供的基础库使我们不必担心连接或结构。我们只需要对如何检索、添加和修改这些文档有高层次的理解，其余的都可以留给 Meteor。

## MongoDB

MongoDB——这个词是对“humongous”（巨大）的玩弄——是一个开源的 NoSQL（不仅仅是 SQL）数据库。它提供了如索引、链接和原子操作等复杂功能，但它的核心仍然是一个面向文档的存储解决方案。

### 提示

想要了解更多关于 MongoDB 的信息，请访问官方网站 [`www.mongodb.org`](http://www.mongodb.org)。

使用简单命令，我们可以查看哪些记录（哪些文档）可用，将那些记录转换成 JavaScript 对象，然后保存那些更改后的对象。把 MongoDB 记录想象成实际文本文档：

1.  查找并打开文档进行编辑（Meteor 等效：`lists.find (...)`）。

1.  修改文档（Meteor 等效：`lists.update({...})`）。

1.  保存文档（自动通过`.update()`函数完成）。

没那么简单，如果你想要成为 MongoDB 领域的专家，还有很多语法你需要学习，但你可以清晰地看到这种简单、干净的面向文档的方法：查找/创建一个记录，进行更改，并将记录保存/更新到数据存储中。

我们需要讨论一个最后一个概念，以帮助您更好地理解 MongoDB 是如何工作的。它被称为数据库，但把它想象成文档的集合更容易。集合是索引化的，可以快速访问，但它仍然是一个集合，而不是关系表/实体的组。就像你会在硬盘上想象一个文件夹，你把所有的文本文档都放在里面，把 MongoDB 想象成一个文档的集合，所有这些文档都可以访问并且可以“打开”，更改和保存。

## 使用直接命令

为了更好地了解 MongoDB 如何工作，让我们在命令行中玩得开心一些。

1.  首先，确保您的应用程序正在运行（打开一个终端窗口，`cd`到`~/Documents/Meteor/LendLib`目录，并执行`meteor`命令）。接下来，打开浏览器访问`http://localhost:3000`。

1.  现在，您可能想打开一个*额外的*终端窗口，`cd`到`~/Documents/Meteor/LendLib`目录，并运行以下命令：

    ```js
    meteor mongo

    ```

    您应该看到以下类似屏幕截图的消息：

    ![使用直接命令](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/gtst-mtr-js-fw/img/0823OS_05_12.jpg)

您现在已连接到您借阅图书馆应用程序的运行 MongoDB 数据库。让我们用几个命令四处看看。

1.  首先，让我们打开帮助屏幕。输入以下命令并按*Enter*：

    ```js
    > help

    ```

1.  您将获得一个命令列表，以及每个命令的简要说明。其中一个特别能让我们看到*更多*命令：`db.help()`。这将为我们提供数据库相关命令的列表。在您的终端窗口中输入以下内容，然后按*Enter*：

    ```js
    > db.help()

    ```

    不要被可能的命令数量吓到。除非您想成为 MongoDB 专家，否则您不需要了解所有这些。您只需要知道几个，但四处看看永远不会伤害任何人，所以让我们继续。

1.  如前所述，文档存储在 MongoDB 中的一个逻辑分组中，称为集合。我们可以亲眼看到这一点，并直接在终端窗口中查看我们的 lists 集合。要查看所有可用集合的列表，请输入以下内容：

    ```js
    > db.getCollectionNames()

    ```

1.  在您的响应中，您将找到您借阅图书馆集合的名称：`lists`。让我们继续查看`lists`集合。输入以下内容：

    ```js
    >  db.getCollection('lists')

    ```

1.  嗯，这并不是很有趣。我们得到的只是`meteor.lists`。我们希望能够对该集合执行一些查询。所以这次，让我们将集合分配给一个变量。

    ```js
    > myLists = db.getCollection('lists')

    ```

    看来我们得到了与上次相同的结果，但我们得到的远不止这些。现在，我们将`lists`集合分配给变量`myLists`。因此，我们可以在终端窗口中运行与我们在 Meteor 代码中相同的命令。

1.  让我们获取`Clothes`列表，该列表目前没有任何项目，但仍然存在。输入以下命令：

    ```js
    >  Clothes = myLists.findOne({Category:"Clothes"})

    ```

    这将返回一些非常基本的 JSON。如果您仔细看，将能够看到空的项目数组，表示为`"items" : [ ]`。您还会注意到一个`_id`键值，旁边有一个长数字，类似于以下内容：

    ```js
    "_id" : "520e4f45-8469-47b9-8621-b41e60723de0",
    ```

    我们没有添加那个`_id`。MongoDB 为我们创建了它。这是一个唯一键，因此如果我们知道它，我们就可以更改该文档，而不会干扰其他文档。我们实际上在我们借阅图书馆应用程序的多个位置使用这个。

如果您在`~/Documents/Meteor/LendLib/LendLib.js`中查看，您将看到以下用于向列表添加项目的函数：

```js
function addItem(list_id,item_name){
  if (!item_name&&!list_id)
    return;
  lists.update({_id:list_id},
  {$addToSet:{items:{Name:item_name}}}); 
}
```

注意，当我们调用`lists.update()`函数时，我们通过`_id`来识别我们要更新的文档。这确保了我们不会意外地更新多个文档。例如，如果你给两个列表赋予相同的类别名称（例如，"DVDs"），并使用类别作为选择器`({Category:"DVDs"}`），你将对这两个类别列表采取行动。如果你 instead 使用`_id`，它将只更新具有匹配`_id`的唯一文档。

回到终端，现在我们的`lists`集合有了变量`myLists`，我们将`Clothes`变量赋予了代表"Clothes"列表的`lists`集合中的文档。

注意一下目前`Clothes`列表在浏览器中的样子。

![使用直接命令](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/gtst-mtr-js-fw/img/0823OS_05_01.jpg)

让我们继续将我们最喜欢的衬衫添加到`Clothes`列表中。我们将在终端窗口直接执行此操作。输入以下命令：

```js
>myLists.update({_id:Clothes._id},{$addToSet:{items:{Name:"Favorite Shirt"}}})

```

这个命令使用`Clothes._id`作为选择器更新`myLists`，并调用`$addToSet`，添加一个名为`Name:"Favorite Shirt"`的项目。Meteor 更新需要几秒钟，但很快您就会看到您最喜欢的衬衫已添加到列表中。

![使用直接命令](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/gtst-mtr-js-fw/img/0823OS_05_02.jpg)

如果您重新运行`Clothes`赋值命令`Clothes = myLists.findOne({Category:"Clothes"})`，您现在会看到`items`数组有一个您最喜欢的衬衫的条目。

我们可以同样轻松地更新或删除一个项目，使用不同的参数调用`.update()`函数（`$pull`用于删除，`$set`用于更新）。

### 提示

对于代码示例，请参阅`LendLib.js`中的`removeItem()`和`updateLendee()`函数。

要深入了解 MongoDB 命令，请访问[`mongodb.org`](http://mongodb.org)并点击**TRY IT OUT**。

既然我们已经浏览了一些可以直接实施的命令，让我们重新审视一下我们的`LendLib.js`代码，讨论一下追踪我们集合变化的响应式代码。

# 广播变化

使用发布/订阅模型，Meteor 不断寻找集合和`Session`变量的变化。发生变化时，会触发一个变化事件（或发布）。回调函数监听（或订阅）正在广播的事件，当它订阅的特定事件发布时，函数中的代码将被激活。或者，数据模型可以与 HTML/Handlebars 模板的某些部分直接绑定，这样当发生变化时，HTML 将被重新渲染。

## 发布的事件

那么，何时发布事件呢？如前所述，当模型发生更改时会广播事件。换句话说，当集合或变量被修改时，Meteor 发布适当的变化事件。如果将文档添加到集合中，将触发一个事件。如果已存在于集合中的文档被修改并保存回集合中，将触发一个事件。最后，如果`Session`变量被更改，将触发一个事件。函数和模板正在监听（订阅）特定事件，并将适当地处理数据的更改。

如果您回想起来自第三章，*为什么 Meteor 如此棒！*，这是模型-视图-视图模型模式在起作用。在一个反应式上下文中，函数和模板会响应模型的更改。反过来，视图中的动作将通过视图模型逻辑创建对模型的更改：

![已发布的事件](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/gtst-mtr-js-fw/img/0823OS_05_03.jpg)

Meteor 的 MVVM 是一种干净、简洁的开发模式：

1.  设置订阅以监控模型更改（模型=集合、文档和`Session`变量）。

1.  创建逻辑来处理视图事件（视图事件=按钮点击、文本输入等）。

1.  更改模型，当逻辑需要时（更改=已发布的事件）。

一圈又一圈地转，按钮点击导致模型更改，然后触发一个事件，模板监听这个事件。根据模型更改更新视图。洗发水，冲洗。重复。

# 配置发布者

到目前为止，我们一直在使用`autopublish`。这意味着，我们没有为任何事件或集合编写特定的发布事件。这对于测试来说很好，但我们希望对发布的事件和文档有更多的控制，以便我们可以提高性能和安全性。

如果我们有一个大数据集，我们可能不希望每次都返回整个集合。如果使用`autopublish`，将返回整个集合，这可能会减慢速度，或者可能会暴露我们不想暴露的数据。

## 关闭 autopublish

是时候关闭`autopublish`了。如果您正在运行 Meteor 应用程序，请通过打开您运行`meteor`命令的终端窗口来暂时停止它。您可以按*Ctrl* + *C*键停止它。一旦它停止，请输入以下命令：

```js
> meteor remove autopublish

```

这移除了`autopublish`库，这个库负责 Meteor 内部所有事件的自动发布。

### 提示

通常建议从您的项目中移除`autopublish`。`autopublish`用于开发和调试，当您准备认真使用应用程序时应关闭。

通过关闭此功能，您实际上使您的应用程序什么也不做！恭喜您！您可以通过重新启动 Meteor 服务（输入`meteor`命令并按*Enter*键），然后打开/导航到`http://localhost:3000`来查看您的惊人进步。您将看到以下屏幕截图：

![关闭 autopublish](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/gtst-mtr-js-fw/img/0823OS_05_04.jpg)

分类/列表消失了！你甚至可以在控制台进行检查。输入以下命令：

```js
> lists.find().count()

```

你应该看到一个`6`的计数，但你会发现计数是`0`：

![关闭 autopublish](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/gtst-mtr-js-fw/img/0823OS_05_05.jpg)

这是怎么回事呢？实际上，原因很简单。因为移除了`autopublish`库，服务器不再广播我们模型的任何更改。

我们为什么要这么做呢？破坏我们应用的目的是什么？啊！因为我们想要让我们的应用更高效。我们不是自动获取每个记录，而是只获取我们需要的记录，以及这些记录的最小数据字段集。

## 列出分类

在`LendLib.js`中，在`if(Meteor.isServer)`块内，创建以下`Meteor.publish`函数：

```js
Meteor.publish("Categories", function() {
 return lists.find({},{fields:{Category:1}}); 
});

```

这告诉服务器发布一个`"Categories"`事件。每当函数内部变量发生变化时，它都会发布这个事件。在这个例子中，是`lists.find()`。每当对`lists.find()`的结果产生影响的变化发生时，Meteor 将触发/发布一个事件。

如果你注意到了，`lists.find()`调用并不是空的。有一个选择器：`{fields:{Category:1}}`。这个选择器告诉`lists.find()`调用只返回`fields:`指定的内容。并且只指定了一个字段——`{Category:1}`。

这段 JSON 代码告诉选择器我们想要获取`Category`字段（`1`=真，`0`=假）。因为提到的唯一字段是`1`（真），Meteor 假定你希望排除所有其他属性。如果你有任何字段设置为`0`（假），Meteor 会假定你希望包括所有你没有提到的其他字段。

### 提示

有关`find()`函数的更多信息，请查阅 MongoDB 文档：[`www.mongodb.org/display/DOCS/Advanced+Queries`](http://http://www.mongodb.org/display/DOCS/Advanced+Queries)。

所以，如果你保存这个更改，你的浏览器会刷新，然后...显示没有任何变化！

为什么这么做呢？正如你可能会猜到的，移除`autopublish`库不仅仅是去除了`publish`事件。它还去除了监听器/订阅者。我们没有为`Categories`事件通道设置任何订阅者。因此我们需要添加一个订阅者事件，以便能够接收到`Categories`通道的信息。

在`if (Meteor.isClient)`函数的最顶部，在开括号内输入以下代码行：

```js
Meteor.subscribe("Categories");

```

保存这个更改，你现在将看到`Categories`回到了它们应该在的位置。

![列出分类](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/gtst-mtr-js-fw/img/0823OS_05_06.jpg)

在我们庆祝之前，先点击**服装**分类。

![列出分类](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/gtst-mtr-js-fw/img/0823OS_05_07.jpg)

我们最喜欢的衬衫不见了！正如你现在可能已经猜到的，这是因为我们设置的发布事件非常具体。在`Categories`通道中发布的唯一字段是`Category`字段。包括我们的`items`（以及因此我们的最喜欢的衬衫）在内的所有其他字段都没有被广播。

让我们再检查一下。在浏览器中点击**+**按钮，在**Clothes**类别中输入`Red Hooded Sweatshirt`，然后按*Enter*。新条目会出现一瞬间，然后就会消失。这是因为本地缓存和服务器同步。

当你输入一个新的`item`时，本地缓存包含一个副本。那个`item`暂时对您的客户端可见。然而，当与服务器同步时，服务器更新只发布`Category`字段，所以当服务器模型更新本地模型时，`item`就不再包括在内。

再试一次，只是为了好玩。在你的终端窗口中，停止 Meteor 服务(*Ctrl* + *C*)。现在，在浏览器中，在**Clothes**类别中输入另一个`item`（我们用`Pumped Up Kicks`）。因为服务已经停止，所以没有与服务器的同步，所以您使用本地缓存，您的`item`就在那里。

![列出类别](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/gtst-mtr-js-fw/img/0823OS_05_08.jpg)

现在重新启动你的服务器。您的客户端将与服务器同步，然后你的`item`又消失了。

![列出类别](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/gtst-mtr-js-fw/img/0823OS_05_13.jpg)

## 列出项目

这不行，因为我们想要看到我们的`items`。所以，让我们把`items`加回来，并在选择一个`Category`时获取适当的`items`列表。在`LenLib.cs`中，在我们第一个`Meteor.publish()`函数下面的`if(Meteor.isServer)`块中，添加以下函数：

```js
Meteor.publish("listdetails", function(category_id){
 return lists.find({_id:category_id}); 
});

```

这个`publish`函数将在`"listdetails"`通道上发布。任何监听器/订阅者都将提供变量`category_id`，以便我们的`find()`函数返回一个更轻的记录集。

请注意，到目前为止，我们的客户端还没有发生变化（您的`items`仍然不可见）。那是因为我们需要创建一个`subscribe`函数。

在我们的第一个`Meteor.subscribe()`函数下面，添加以下函数：

```js
Meteor.subscribe("Categories");

Meteor.autosubscribe(function() {
 Meteor.subscribe("listdetails", Session.get('current_list')); 
});

```

保存您的更改，然后查看您的**Clothes**收藏！

![列出项目](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/gtst-mtr-js-fw/img/0823OS_05_09.jpg)

让我们花一分钟揭开这里面的奥秘，弄清楚刚才发生了什么。请注意，订阅使用了`Session.get('current_list')`。这个变量是在发布函数中传递的。换句话说，`Session`变量`current_list`中的值将作为`find()`函数选择器中的`category_id`使用。

如果你记得第四章，*模板*，我们已经设置了一个点击事件处理程序，用来监听`Category`的变化。例如，当你点击**Clothes**时，一个事件会被触发，`LendLib.js`中的`selectCategory()`函数处理该事件，并改变我们的`Session`变量。

```js
function selectCategory(e,t){
  Session.set('current_list',this._id); 
}
```

那个 `Session.set()` 触发了一个发布事件。我们将 `Meteor.subscribe()` 函数包裹在 `Meteor.autosubscribe()` 函数中，以便为 `"listdetails"` 通道提供 `Meteor.subscribe()` 函数。我们这样做是因为 `Session.set()` 事件将触发 `Meteor.autosubscribe()`，而那里正好有一个 `Meteor.subscribe()` 函数，专门为 `"listdetails"` 通道服务。

换句话说：

1.  `Session.set()` 触发一个事件。

1.  `Meteor.subscribe()` 监听这个事件，因为它使用了 `Session` 变量。

1.  流星在 `"listdetails"` 通道上重置了订阅监听器（因为它被包裹在 `Meteor.autosubscribe()` 中）。

1.  流星看到新的订阅监听器并触发了一个初始事件。

1.  `Meteor.subscribe()` 函数接收到这个事件，传入 `category_id` 变量，由于模型变化，UI 进行了刷新。

## 检查你的简化数据

现在显示与我们开始本章时没有区别。但在显示之下，模型要精简得多。选择 **服装** 类别，在浏览器控制台中运行以下命令：

```js
> lists.findOne({Category:"DVDs"})

```

展开对象，你会看到没有列出任何项目。

![检查你的简化数据](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/gtst-mtr-js-fw/img/0823OS_05_10.jpg)

之所以没有项目，是因为我们的 `Session` 变量 `current_list` 被设置为 `Clothes`，而不是 `DVDs`。`find()` 函数只获取 `current_list` 的完整记录。

现在在浏览器控制台中输入以下命令并按 *Enter*：

```js
> lists.findOne({Category:"Clothes"})

```

展开对象，你会看到你的三个项目在一个数组中。

![检查你的简化数据](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/gtst-mtr-js-fw/img/0823OS_05_11.jpg)

点击各个地方，为类别添加项目，添加新类别，并检查客户端可见的底层数据模型。你会发现你的列表现在明显可见性降低，因此更加安全和私密。这可能对你个人的借贷图书馆应用来说不会有问题，但随着我们在下一章中扩展这个应用，让多个人可以使用，简化和私密的数据将真正提高性能。

# 总结

在本章中，你已经了解了 MongoDB 是什么，面向文档的数据库是如何工作的，以及在命令行中进行了直接查询，熟悉了 Meteor 的默认数据存储系统。你还通过移除 `autopublish` 简化了你的应用，并且对内置于 Meteor 中的发布/订阅设计模式有了扎实的理解。

在下一章中，你将真正加强应用的安全性，允许多用户跟踪和控制他们自己的项目列表，并且你将了解如何通过使用文件夹进一步简化客户端和服务器代码。


# 第六章：应用程序和文件夹结构

为了让你能够直接开始，Meteor 创建了一组默认库、默认文件夹结构和默认权限。这个默认配置非常适合快速开发、测试和学习。然而，它并不适合生产环境。

在这一章，我们将讨论你可能想要对默认配置进行的更改，以便你的应用性能更优、更安全、更容易管理。具体来说，你将学习到：

+   将你的应用程序的客户端、服务器和公共文件分离

+   启用数据库安全和用户登录

+   定制显示结果以保护隐私

# 客户端和服务器文件夹

到目前为止，我们把所有的 JavaScript 代码都放在了一个文件中：`LendLib.js`。

在 `LendLib.js` 中，我们有两个部分，由 `if` 语句分隔。面向客户端的代码位于 `if (Meteor.isClient) {...}` 块中，而服务器端代码位于 `if (Meteor.isServer) {...}` 块中。

这种结构对于一个非常简单的应用程序来说是可以的，但当我们编写一个更复杂的应用程序，或者我们有 multiple 人在同一个应用程序上工作时，尝试用条件语句共享一个文件很快就会变成一场噩梦。

另外，Meteor 会读取我们应用程序文件夹中的任何和所有文件，并尝试将 JavaScript 应用到客户端和服务器。如果我们想使用面向客户端的 JavaScript 库（例如，Twitter Bootstrap 或 jQuery），这就会造成一种奇怪的情况。如果我们把库放到根目录，Meteor 就会尝试在客户端和服务器上都实现这个文件。这要么因为我们在服务器上加载了它不需要的文件而造成性能问题，要么因为服务器不知道如何处理显示对象（服务器不显示任何东西）而产生错误。

相反，如果文件中包含面向客户端和服务器的服务器端代码，客户端可能会尝试实现该代码，这可能会造成各种问题，或者至少会让代码对客户端可见，这可能很快就会成为一个安全问题。有些文件和代码我们就是不想让客户端看到或访问。

让我们看看客户端代码被服务器处理的一个例子，然后把那部分代码移到一个只有客户端会尝试执行它的地方。在 `~/Documents/Meteor/` 中创建一个名为 `LendLibClient.js` 的新文件。打开 `LendLib.js` 并剪下以下高亮显示的代码块中的整个客户端代码块：

```js
var lists = new Meteor.Collection("lists");

if (Meteor.isClient) { 
...
}

if (Meteor.isServer){...
```

### 提示

你应该剪掉了大约 186 行代码。确保你找到了闭合的 `}` 括号！

现在把刚刚剪切的代码粘贴到 `LendLibClient.js` 中，然后保存对两个文件的更改。你会注意到这并没有对你的正在运行的应用程序产生任何视觉上的变化。那是因为 Meteor 正在处理这两个文件，而 `if` 条件阻止了服务器执行代码。

但让我们看看当我们移除`if`条件时会发生什么。在`LendLibClient.js`中，删除包含`if (Meteor.isClient) {`条件的第一行。同时，确保你也删除`if`条件的闭合括号（`}`）的最后一行。保存`LendLibClient.js`，然后去看看 Meteor 正在运行的控制台。

你会看到以下错误信息，或类似的内容：

```js
app/LendLibClient.js:21
   Meteor.subscribe("Categories");
          ^
TypeError: Object #<Object> has no method 'subscribe'
    at app/LendLibClient.js:21:11
...
Exited with code: 1
Your application is crashing. Waiting for file change.
```

移除`if`条件创造了一种情况，Meteor 的服务器部分试图运行面向客户端的代码。它不知道如何处理它，所以应用程序崩溃了。我们将通过使用文件夹结构来解决这个问题。

如果你还记得，当我们实现 Twitter Bootstrap 时，我们创建了`client`文件夹。Meteor 识别出`client`文件夹，并且将独占地运行在此文件夹中找到的任何 JavaScript 文件，作为面向客户端的代码，而不会在服务器端运行。

将`LendLibClient.js`文件从`~/Documents/Meteor/LendLib/`移动（剪切+粘贴，拖放，或使用`mv`命令）到`~/Documents/Meteor/LendLib/client/`。这将立即修复我们的崩溃应用程序，Meteor 再次快乐！你会在控制台看到以下内容：

```js
=> Modified -- restarting.
```

因为我们把`LendLibClient.js`移动到了`client`文件夹，所以不再需要`if`条件。由于文件位置，Meteor 知道该代码只打算在客户端运行，所以它不会尝试在服务器上运行它。

### 提示

你可能想刷新你的浏览器，指向`http://localhost:3000`。

这是因为你的应用程序崩溃了。悔改你的邪恶行为，刷新你的页面。

现在让我们对服务器端代码也做同样的事情。创建一个名为`server`的新文件夹。你可以通过 Finder 窗口，或者直接在命令行中如下操作：

```js
$ mkdir ~/Documents/Meteor/LendLib/server

```

我们知道我们应该直接在新生成的`server`文件夹中创建我们的 JavaScript 文件，但我们也是病态的好奇，喜欢破坏事物，所以我们打算创建一个可能引起问题的地方。

在`~/Documents/Meteor/LendLib`文件夹中创建一个名为`LendLibServer.js`的新文件。从`LendLib.js`中剪切`if (Meteor_is.server) { … }`块，粘贴到`LendLibServer.js`中，然后保存两个文件。

### 提示

此时，`LendLib.js`中应该只剩下一行代码了：

```js
var lists = new Meteor.Collection("lists");
```

与客户端代码的移动一样，在此阶段不会发生任何不良反应，因为我们仍然有`if`条件。让我们移除它，让应用程序崩溃继续！

在`LendLibServer.js`中，删除包含`if (Meteor.isServer) {`的第一行和包含闭合括号（`}`）的最后一行。

保存你的更改，让我们看看混乱场面！

![客户端和服务器文件夹](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/gtst-mtr-js-fw/img/0823OS_06_01.jpg)

嗯。没有崩溃。应用程序仍然运行良好。真是让人失望...

让我们检查一下浏览器控制台：

![客户端和服务器文件夹](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/gtst-mtr-js-fw/img/0823OS_06_02.jpg)

是的！我们*确实*做了坏事！这个行为（不幸的是）没有干扰或影响应用程序的其他部分，原因有两个：

+   是客户端（浏览器）抛出了错误。这不会影响服务器应用程序。

+   `LendLibServer.js`中的唯一代码是服务器代码。如果这段代码在客户端出错了，那也没关系，因为本来就不应该在客户端运行。

最终用户永远不知道错误的存在，但我们知道，所以让我们来修复它。将`LendLibServer.js`移动到`~/Documents/Meteor/LendLib/server/`目录下。错误将消失，我们小小的 Meteor 王国将再次一切安好。

## 公共文件夹

客户端文件夹（`client`）只能被客户端处理，服务器文件夹（`server`）只能被服务器处理，这是很逻辑的。但我们还需要考虑一个额外的因素，那就是**资源文件**（如图片、文本/内容文件等）。

资源文件仅在运行时需要。我们在任何逻辑或处理上都不依赖于它们，所以如果我们能将它们移开，Meteor 编译器就可以忽略它们，这能加快我们应用程序的处理和交付速度。

这就是`public`文件夹发挥作用的地方。当 Meteor 在为客户端和服务器编译 CSS 或 JavaScript 时，它会忽略`public`文件夹内的任何内容。然后，在所有的编译工作完成后，它会使用`public`文件夹来访问可能需要传递给客户端的任何内容。

让我们为我们的应用程序添加一个背景图片。慷慨和英俊的先生在[subtlepatterns.com](http://subtlepatterns.com)有很多选择，而且都是免费的，所以我们从中选择一个。我们将使用 Texturetastic Gray，因为它似乎符合我们的主题。访问[`subtlepatterns.com/texturetastic-gray/`](http://subtlepatterns.com/texturetastic-gray/)并下载图片。

### 小贴士

您可以使用任何背景图片。只需按照以下步骤操作您自定义的背景图片，并在我们声明`background-image`时将图片名称替换到 CSS 中。

在我们可以使用下载的背景之前，我们需要对`LendLib.css`做一次快速更改，并创建一个公共文件夹。

打开`LendLib.css`（除非您已将其移动到`client`文件夹中，这完全可以），并添加以下 CSS 声明：

```js
body {
 background-image: url(/texturetastic_gray.png); 
}

```

保存这个更改。现在还不会发生任何事情（译者注：暂时不变），我们稍后再处理。在`~/Documents/Meteor/LendLib`目录下创建一个名为`public`的文件夹。现在，打开下载的压缩包`texturetastic_gray.zip`，并将`texturetastic_gray.png`从压缩包中复制到我们刚创建的`public`文件夹中：

![公共文件夹](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/gtst-mtr-js-fw/img/0823OS_06_03.jpg)

背景已经更换成了您的背景图片，现在我们拥有了一个更炫酷的界面！

这个文件被安全地保存在`public`文件夹中，所以 Meteor 编译器不需要处理它，但当需要服务于客户端以供显示时，它仍然可用并准备就绪。

### 小贴士

还存在其他文件夹，它们有不同的效果和目的。有关完整解释，请参阅 Meteor 文档中的[`docs.meteor.com/#structuringyourapp`](http://docs.meteor.com/#structuringyourapp)。

# 安全和账户

此时，我们的借阅图书馆应用程序完全是我们想要它做的。它记录了所有我们的物品以及我们借出物品给谁。如果我们把这个应用程序投入使用，然而，应用程序本身存在一些我们需要解决的安全问题。

首先，阻止某人访问我们的应用程序并从他们借阅的物品中删除他们的名字有什么阻止他们呢？那个恶棍 STEVE 可能会永远保留我们的线性压缩扳手，如果他有意的话，而我们将无法证明他是否还拥有它。

我们不能让这种盗窃和不诚实的行为不受惩罚！STEVE 必须为此负责！所以，我们需要实现安全措施。具体来说，我们需要执行两个操作：

+   只允许物品所有者在 UI 中进行编辑

+   确保数据库安全，防止通过网络控制台进行更改。

## 删除 insecure

实现这两个目标的第一步是删除 Meteor 中的`insecure`库。默认情况下，`insecure`库是包含在内的，这样我们就可以在制定安全策略并编写大部分代码之前构建我们的应用程序，而不用担心安全问题。

是时候了，我们知道我们希望实现的安全方面，所以让我们继续摆脱那个库。停止 Meteor 应用程序（在终端窗口中按*Ctrl* + *C*），然后输入以下命令（您需要位于`LendLib`目录中）：

```js
>meteor remove insecure

```

这将生成以下消息：

```js
insecure: removed
```

我们的应用程序现在很安全。实际上*太*安全了。重新启动 Meteor（在终端中输入`meteor`并按*Enter*键），然后在浏览器窗口中使用`http://localhost:3000`导航到我们的应用程序。一旦你到了那里，试着添加一个新项目；添加一个借阅者，或者甚至删除一个项目。我们将尝试把我们的最爱衬衫借给我们的性感美国女友，但是什么也不会发生；没有删除，没有添加，没有更改。现在什么都不起作用了！如果你打开浏览器控制台，你会发现每次尝试更新数据库都会显示**更新失败：访问被拒绝**的消息：

![Removing insecure](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/gtst-mtr-js-fw/img/0823OS_06_04.jpg)

这个消息发生是因为我们禁用了 insecure 包。换句话说，不再允许匿名更改。因为我们还没有登录账户，我们所有的请求都是匿名的，因此将会失败。

## 添加管理员账户

为了重新启用更新功能，我们需要能够创建一个管理员账户，给管理员账户权限进行更改，并给用户提供一个找回丢失密码的方法。

我们首先需要添加三个内置的 Meteor 包。停止 Meteor 应用程序，在终端窗口中输入以下三个命令：

```js
$ meteor add accounts-base
$ meteor add accounts-password
$ meteor add email

```

这些命令将为我们的 Meteor 应用程序添加管理账户所需的包。

Meteor 还提供一个 UI 包，可以自动为我们的账户创建登录逻辑，这样我们就不用编写任何自定义的账户 UI 代码。既然如此，我们顺便添加这个包：

```js
$ meteor add accounts-ui

```

既然我们已经添加了`accounts-ui`包，我们只需要快速配置要显示的字段，并更新我们的 HTML 模板。打开`LendLibClient.js`，在文件的底部添加以下代码：

```js
Accounts.ui.config({
 passwordSignupFields: 'USERNAME_AND_OPTIONAL_EMAIL' 
});

```

这告诉`accounts-ui`包我们希望在注册表单中显示`username`和`email`字段，其中`email`字段是可选的（我们需要它来恢复丢失的密码）。

现在打开`LendLib.html`，在`<body>`标签的直接下方输入以下代码：

```js
<body>
  <div style="float: right; margin-right:20px;">
 {{loginButtons align="right"}}
 </div>
  <div id="lendlib">
```

这段 HTML 代码将在我们屏幕的右上角添加一个登录链接和上下文菜单框。让我们看看它的实际效果。保存所有更改，启动您的 Meteor 应用，在浏览器中导航到`http://localhost:3000`。注意以下屏幕截图的右上角：

![添加管理员账户](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/gtst-mtr-js-fw/img/0823OS_06_05.jpg)

点击**登录**，然后点击弹出窗口右下角的**创建账户**：

![添加管理员账户](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/gtst-mtr-js-fw/img/0823OS_06_06.jpg)

填写创建账户表单，确保为管理员输入一个用户名和一个有效的电子邮件地址，以便在需要时可以恢复您的密码。输入并确认您的新密码，然后点击**创建账户**：

![添加管理员账户](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/gtst-mtr-js-fw/img/0823OS_06_07.jpg)

你现在将作为管理员登录，我们可以继续配置权限：

![添加管理员账户](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/gtst-mtr-js-fw/img/0823OS_06_08.jpg)

## 授予管理员权限

现在我们已经有了管理员账户，让我们允许该账户在 UI 中进行任何必要的更改，同时取消管理员账户未登录时在浏览器控制台进行更改的能力。

我们原始的`LendLib.js`文件目前里面只有一行代码。我们将向其中添加一些账户检查代码，确保只有管理员账户可以进行更改。

将以下代码添加到`LendLib.js`并保存您的更改：

```js
/*checks to see if the current user making the request to update is the admin user */

function adminUser(userId) {
 var adminUser = Meteor.users.findOne({username:"admin"});
 return (userId && adminUser && userId === adminUser._id);
}

lists.allow({
 insert: function(userId, doc){
 return adminUser(userId);
 },
 update: function(userId, docs, fields, modifier){
 return adminUser(userId);
 },
 remove: function (userId, docs){
 return adminUser(userId);
 }
});

```

`adminUser`函数在多个地方使用，因此创建一个公共函数是有意义的，该函数仅检查发出请求的`userId`是否与管理员账户的`_id`相同。

`lists.allow`设置了允许操作的条件，每个操作都有一个返回`true`以允许和`false`以拒绝的函数。例如，如果我们永远不想让任何人（包括管理员账户）删除类别，我们可以将`remove`函数检查设置为总是返回`false`。

目前，我们只是想让操作根据管理员账户是否登录并发起请求而有条件地执行，因此我们将每个函数设置为`return adminUser(userId);`。

在我们的浏览器中，我们现在可以测试我们的权限。添加一个新的类别（任何您喜欢的，但我们将会添加`玻璃器皿`），添加一个新项目，更改一个所有者，等等——只要您以管理员身份登录，所有操作都应该被允许。

让我们确保访问确实与我们的管理员账户相关联。通过点击右上角**管理员**旁边的**登出**按钮，然后点击**登出**按钮，退出应用程序：

![授予管理员权限](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/gtst-mtr-js-fw/img/0823OS_06_09.jpg)

现在，在浏览器控制台中，输入以下命令（或等效于您添加的类别）：

```js
> lists.remove({Category:"glassware"})

```

您将收到一个**访问被拒绝**的消息：

![授予管理员权限](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/gtst-mtr-js-fw/img/0823OS_06_10.jpg)

以管理员身份重新登录，再次运行该命令。这次分类将被删除。通过在`lists`级别设置权限和允许的操作，使用`lists.allow()`，我们使某人无法在不以管理员身份登录的情况下进行更改。现在，用户界面和浏览器控制台都受到了 STEVE，那个扳手小偷的邪恶阴谋的保障！

# 自定义结果

当我们考虑到应用程序的安全性和可用性时，还有一个我们需要考虑的问题。如果我们能够使多个用户可以使用借阅图书馆，而每个用户只能看到属于他们的物品，那会怎样呢？如果我们这样做，我们就可以阻止人们看到别人拥有什么样的东西，同时我们也可以让每个人跟踪自己的物品。我们最初的目标是为自己创建一个应用程序，但是稍作修改，我们就可以让任何人使用它，他们会觉得我们很棒，也许会请我们吃午饭！

## 修改 Meteor.publish()

为了准备让多个人使用我们的应用程序，我们需要确保没有人能看到别人的东西。这是在`Meteor.publish()`声明中为`Categories`完成的。逻辑上，如果我们限制用户可以看到的类别，这种限制将会传递到可见的项目，因为项目是在类别中找到的。

打开`LendLibServer.js`，修改大约在第 6 行附近找到的`find({})`块：

```js
Meteor.publish("Categories", function() {
  return lists.find({owner:this.userId},{fields:{Category:1}});
});
```

添加选择器`owner:this.userId`将检查我们`lists`存储库中的每个列表，并返回每个当前登录用户是列表所有者的每个实例的类别。保存此更改，您会发现所有当前的类别都消失了！

![修改 Meteor.publish()](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/gtst-mtr-js-fw/img/0823OS_06_11.jpg)

这是因为我们已经在应用程序中创建的列表没有任何所有者，而且我们以管理员身份登录。当我们尝试修改现有项目时，我们将遇到类似的问题，因为没有列表有任何所有者。

我们有几种方法可以解决这个问题，包括手动将管理员账户作为所有者添加，让管理员账户看到所有未认领的列表，或者直接重新开始。由于我们只借出了一件物品（可恶，STEVE！我们还我们的扳手！），现在是一个很好的时间清空我们的数据库，并在我们忘记谁有它之前重新添加我们的线性压缩扳手。

作为管理员登录到浏览器控制台，输入以下命令：

```js
>lists.remove({})

```

这将删除我们所有的列表，一旦我们给新创建的列表添加了所有者，我们就可以重新开始了。

### 提示

如果你也想清除所有用户，你可以通过停止 Meteor 应用程序，然后在终端窗口中运行`meteor reset`，然后再重新启动 Meteor 应用程序来完成。要小心！没有警告，也没有后悔药！

## 添加所有者权限

给任何新类别添加所有者是相当简单的。我们只需要更新我们的`lists.insert()`函数，并添加所有者字段。打开`LendLibClient.js`，找到`Templates.categories.events`声明。在`'keyup #add-category'`事件的事件代理中，你会看到`lists.insert()`函数的调用。按照以下方式修改该调用：

```js
if (catVal)
{
  lists.insert({Category:catVal,owner:this.userId});
  Session.set('adding_category', false);
}
```

每当添加一个新的列表时，我们不仅在添加一个类别字段，而是在添加一个所有者字段。这使得我们的`Meteor.publish()`代码能够正确地为我们创建的任何新列表工作。

让我们先恢复“工具”类别，输入项目“线性压缩扳手”，并将借阅者设为`STEVE`：

![添加所有者权限](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/gtst-mtr-js-fw/img/0823OS_06_12.jpg)

这样，我们就可以重新运行，并且在每个列表中都隐藏了一个所有者属性。当允许其他人创建和维护他们自己的列表时，这个属性就变得重要了。

## 启用多个用户

好的，现在一切都准备就绪，我们可以拥有一个定制化的、私有的个人物品视图，但目前只有管理员账户可以添加列表或项目，并将借阅者分配给一个项目。

我们将通过回到`LendLib.js`，并添加一些逻辑来检查当前登录的用户是否拥有列表，或者是否是管理员来解决这个问题。在`LendLib.js`中的`lists.allow()`代码块里，加入以下内容：

```js
lists.allow({
  insert: function(userId, doc){
    return (adminUser(userId) || (userId && doc.owner === userId)); 
  },
  update: function(userId, docs, fields, modifier){
    return adminUser(userId) ||
 _.all(docs, function(doc) {
 return doc.owner === userId;
 });
  },
  remove: function (userId, docs){
    return adminUser(userId) ||
 _.all(docs, function(doc) {
 return doc.owner === userId;
 });
  }
});
```

在`insert`中，我们检查当前`doc.owner`是否是登录的用户。在`update`和`remove`中，我们遍历所有要更新的记录（使用`_.all()`），并检查`doc.owner`是否是登录的用户。

现在你可能想要保存你的更改，并在`http://localhost:3000`上创建一个新的账户。尽情添加类别和项目吧。你可以随意在用户之间切换，并且可以添加尽可能多的用户和列表。

你会注意到，一个人的列表对另一个人是不可见的，因此也没有人能够操纵或删除另一个人的列表和记录。当 STEVE 最终得到你的应用程序时，他只能看到自己的东西（顺便说一下，这些都是不值得借的东西！）：

![启用多个用户](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/gtst-mtr-js-fw/img/0823OS_06_13.jpg)

# 总结

在这一章节中，你已经学习了 Meteor 是如何编译和搜索 JavaScript 和 CSS 代码的，以及如何优化搜索。你已经学会了如何保护你的服务器代码，并保持运行流畅和高效。你已经学会了如何通过使用 Meteor 内置的 Accounts 包来保护你的数据库，并且你已经关闭了你的应用程序中的所有主要安全漏洞。最后，你启用了多个账户，这样任何人都可以使用你的借阅图书馆来跟踪他们的物品，而且你这样做并没有损害最终用户的隐私。

在下一章节中，你将学习如何将 Meteor 应用程序部署到一个生产环境中，并学习开始编写快速、健壮且适用于生产的 Meteor 应用程序的技术。


# 第七章：打包和部署

我们的应用程序看起来很棒。我们已经使它变得安全，易于使用，并且通过添加多重登录，现在任何人都可以使用借阅图书馆跟踪他们的物品。

在最后一章中，我们将介绍 Meteor 出色的包系统，这将加快未来的代码项目，并且我们会讨论部署应用程序的选项。你会学会如何：

+   添加和配置第三方包，如 jQuery，Backbone 和 Bootstrap

+   捆绑您的整个应用程序，以便可以部署

+   使用 Meteor 的公共服务器部署您的应用程序

+   将您的应用程序部署到自定义服务器

# 第三方包

**Meteor**正在为主要的 JavaScript 和预处理库添加包。这些包很智能，不仅包含基础的 JavaScript 或预处理库，而且它们还配置为直接与 Meteor 代码库交互。

这意味着对于您来说，添加您最喜欢的库几乎不需要任何努力，并且您可以确信它将与您的 Meteor 应用程序协同工作。

## 列出可用包

要查看带有简要说明的所有可用包列表，只需在终端中输入以下命令，然后按*Enter*：

```js
$ meteor list

```

这将为您提供安装的 Meteor 版本的的所有包的列表。

正如您所看到的，有很多最受欢迎的框架，包括 jQuery，Backbone，underscore 和 Twitter 的 Bootstrap！我们花了很多时间手动下载 Bootstrap，创建客户端文件夹，并提取 Bootstrap 文件。这是一个手动安装框架的好练习，但现在我们将学习如何作为包来安装它。

首先，让我们移除现有的 Bootstrap 安装。导航到`~/Documents/Meteor/LendLib/client/`并删除`bootstrap`目录。你的 Meteor 应用是否正在运行无关紧要（记住，Meteor 是动态更新的）。要么启动它，然后导航到`http://localhost:3000`，或者如果它已经在运行，直接导航那里。你会发现我们所有的漂亮格式都消失了！

![列出可用包](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/gtst-mtr-js-fw/img/0823OS_07_01.jpg)

现在我们将添加官方的 Meteor Bootstrap 包。再次强调，因为 Meteor 是动态更新的，除非我们想停止，否则我们不需要停止 Meteor 应用。要么打开一个新的终端窗口，或者暂时停止您的 Meteor 应用，并确保您在`~/Documents/Meteor/LendLib`文件夹中。一旦在那里，输入以下命令：

```js
$ meteor add bootstrap

```

您将收到一个非常简短的消息：

```js
bootstrap: UX/UI framework from Twitter

```

如果您使用了第二个终端窗口，只需打开浏览器（您甚至不必刷新页面）。如果您停止了您的 Meteor 应用程序，再次启动它，并导航到`http://localhost:3000`。您将能够看到 Bootstrap 格式现在已返回，一切都很正常：

![列出可用包](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/gtst-mtr-js-fw/img/0823OS_07_02.jpg)

真的就是这么简单。在你的终端中使用一个命令，你就可以向你的项目中添加一个库或框架，而无需担心链接、下载，并确保文件在正确的位置。只需运行`meteor add...`，然后就可以出发了！

### 小贴士

你可以通过在终端中输入以下命令来获取你已经在使用的包的列表：`meteor list --using`。

由于 Meteor 正在如此快速地添加包，保持你的 Meteor 安装最新是个好主意。时不时地在终端中运行以下命令：

```js
$ meteor update

```

如果你是最新的版本，它会告诉你，你正在运行哪个版本。如果有新版本，它会下载并为你安装它。

# 捆绑你的应用程序

遵循 Meteor 一贯的风格，将你的应用程序捆绑以便可以部署是极其简单的。如果应用程序正在运行，请停止它，确保你处于你的应用程序文件夹中（对于借贷图书馆来说，它是`~/Documents/Meteor/LendLib`），然后在终端中输入以下命令：

```js
$ meteor bundle lendlib.tgz

```

这需要一点时间来运行，但完成后你将在`LendLib`文件夹中得到一个`lendlib.tgz`的 tar 压缩包，然后你可以将其部署到你希望的任何地方。这是一个完整的包/捆绑。你部署这个捆绑的机器只需要安装了 Node.js 和 MongoDB 即可。你需要的其他所有东西都包含在捆绑包中。

# 部署到 Meteor 的服务器

Meteor 团队把部署工作又推进了一步，超出了甚至是一个付费产品，更不用说是一个免费产品的预期。Meteor 允许你直接在他们的部署服务器上部署你的应用程序。为你的应用选择一个名字（我们将使用`packt.lendlib`，但你需要想出自己的名字）并在终端中输入以下命令：

```js
$ meteor deploy [your app name].meteor.com

```

所以，在我们的案例中，我们输入了`meteor deploy` `packt.lendlib.meteor.com`。控制台会在捆绑、上传和部署应用程序时给出状态更新。完成后，它会给你一个类似于以下的消息：

```js
Now serving at [your app name].meteor.com

```

如果你在浏览器中导航到那个 URL（例如，[`packt.lendlib.meteor.com`](http://packt.lendlib.meteor.com)），你就会看到你的应用程序已经部署并运行起来了！

![部署到 Meteor 的服务器](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/gtst-mtr-js-fw/img/0823OS_07_03.jpg)

### 小贴士

在开始使用应用程序或向他人介绍之前，你可能想要创建一个`admin`登录账户。你不想让那个狡猾的`STEVE`控制你的应用！

## 更新 Meteor 的服务器

如果你做了改动，或者你发现了一个错误，并且你想更新在 Meteor 服务器上的应用程序代码，会怎样呢？正如你大概猜到的，这非常简单。只需重新运行你的`deploy`命令：

```js
$ meteor deploy [your app name].meteor.com

```

这不仅更新了您的应用程序，而且还保留了您的数据，因此如果您已经输入了大量信息，您不需要从头开始。很酷，对吧？Meteor 团队真正知道是什么让开发变得有趣，他们不遗余力地提供了一个您可以编码、玩耍并立即获得应用程序反馈的环境。

## 使用您自己的主机名

但是等等，还有更多！您甚至可以使用自己的主机名与部署在 Meteor 服务器上的应用程序。使用您的主机提供商设置一个指向`origin.meteor.com`的 CNAME，然后您可以部署到该主机名。例如，如果我们有一个子域`meteor.too11.com`作为 CNAME 指向`origin.meteor.com`，我们将在终端中运行以下命令：

```js
$ meteor deploy meteor.too11.com

```

如果你设置了正确的 CNAME，这将就像你直接部署到`[你的应用名称].meteor.com`一样进行部署，并且将使用你自定义的域名可用！

### 提示

咨询您的主机提供商关于设置 CNAME 路由。这因提供商而异，但做起来相当简单。

# 部署到自定义服务器

在撰写本文时，将 Meteor 应用程序部署到托管服务或个人计算机是一项相当繁重的任务。部署过程中存在版本问题，而且大多数托管服务仍处于支持 Meteor 捆绑包的早期阶段。

话说回来，我们将通过部署到自定义服务器的一个 Meteor 应用程序，并留给您探索托管服务（如 Heroku 或 AppFog）。

## 服务器设置

你从哪个服务器托管你的应用程序需要两样东西：

+   Node.js，版本 0.8 或更高版本

+   MongoDB（最新版本）

要安装 Node.js，请访问[`nodejs.org/`](http://nodejs.org/)并按照 Linux 或 Mac OS X 安装说明操作。

要安装 MongoDB，请访问[`docs.mongodb.org/manual/installation/`](http://docs.mongodb.org/manual/installation/)并按照您相应操作系统的说明操作。安装完成后，请确保设置一个名为`lendlib`的数据库。

一旦安装和配置了这两个产品，您将有一个 MongoDB 的默认位置。这将是类似于`mongodb://localhost:27017/lendlib`的东西。您需要在未来的一个步骤中使用该 URI，所以请确保记下或准备好供参考。

另外，你可以在远程服务器上设置 MongoDB，或者使用像 MongoHQ 这样的托管服务。（[`www.mongohq.com`](https://www.mongohq.com)）。如果您使用远程服务，设置一个新数据库，并记下您需要的 URI。以下是来自 MongoHQ 的一个示例：

![服务器设置](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/gtst-mtr-js-fw/img/0823OS_07_04.jpg)

## 部署您的捆绑包

如果你还记得，我们在这个章节开始时创建了一个 tarball。现在我们需要解压这个 tarball，然后进行一些修改，之后我们的应用就可以启动了。将`lendlib.tgz`复制到你的服务器上，在用于部署的目录中（例如`~/Sites/LendLib`）。一旦`lendlib.tgz`在正确的位置，你可以使用以下命令解压 tarball：

```js
$ tar –zxvf lendlib.tgz && rm lendlib.tgz

```

这将解压 tarball，你将得到一个名为`bundle`的新文件夹。

### 可选 – 不同平台

如果你开发应用的机器和你要部署到的机器不一样，你可能需要重新构建原生包。为此，进入`node_modules`目录：

```js
$ cd bundle/server/node_modules

```

一旦在那里，删除`fibers`目录：

```js
$ rm –r fibers

```

现在使用`npm`重新构建`fibers`：

```js
$ npm install fibers

```

这将安装特定于你部署平台的最新`fibers`版本。如果你开发的机器和部署的机器运行的是同一个平台，你不需要这样做。

## 运行你的应用

现在你的 bundle 已经被正确解压，你准备启动你的应用。启动应用你需要以下信息：

+   根 URL（例如，`http://lendlib.mydomain.com`或`http://localhost`）

+   你希望应用运行的端口（例如，`80`）

+   你的 MongoDB URI（例如，`mongodb://<user>:<password>@alex.mongohq.com:10022/lendlib`）

一旦你做出了决定并收集了这些信息，为你的应用启动 Node.js。导航到你的`root`文件夹（我们的文件夹是`~/Sites/LendLib`）并输入以下内容：

```js
$ PORT=80 ROOT_URL=http://localhost MONGO_URL=mongodb://<user>:<password>@alex.mongohq.com:10022/lendlib node bundle/main.js

```

让我们分解一下：

+   `PORT`设置了端口变量，这样 NodeJS 就知道你希望服务应用程序的哪个端口

+   `ROOT_URL`设置了`rootUrl`变量，这样 NodeJS 就知道请求是为你的应用程序指定的主机名

+   `MONGO_URL`告诉 NodeJS 在哪里可以找到我们的 MongoDB

+   `node`是调用的命令

+   `bundle/main.js`是 NodeJS 调用的起始 JavaScript 文件

如果你的所有信息都正确，应用将会运行，你可以使用浏览器来测试它：

![运行你的应用](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/gtst-mtr-js-fw/img/0823OS_07_05.jpg)

你还可以更深入地了解部署，比如设置环境变量，以守护进程/服务的形式运行你的应用，甚至使用远程服务器公开托管你的应用。我们到目前为止所做的一切应该足以让你开始，并让你在使用 Meteor 的生产环境的道路上越走越远。

# 总结

你现在已经成为 Meteor 专家了！认真的。你知道如何从零开始构建一个 Meteor 应用。你理解 Meteor 背后的设计模式和数据库原理，你可以为你的应用进行定制、优化和保障，让它做任何你想要的事情。你还可以将 Meteor 部署到多个环境。你已经迈出了编写高效、稳定且可靠的 web 应用的正确道路。

因为 Meteor 非常新，所以拥有与你现在一样多的关于 Meteor 的实际操作知识的人非常少。按照定义，这使你成为了专家。现在，如何运用你的专业知识取决于你自己。建议在你的下一个开发项目中使用 Meteor，通过代码贡献、在论坛上回答问题以及制作你自己的教程来为 Meteor 社区做贡献。

Meteor 是一项突破性技术，越来越受到关注，而你现在拥有使用这项突破性技术来推进你的个人和职业开发项目的知识与经验，这使你能够保持领先，让你的开发者生活更加充实。
