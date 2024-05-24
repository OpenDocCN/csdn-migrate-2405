# CouchDB 和 PHP Web 开发初学者指南（三）

> 原文：[`zh.annas-archive.org/md5/175c6f9b2383dfb7631db24032548544`](https://zh.annas-archive.org/md5/175c6f9b2383dfb7631db24032548544)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：使用设计文档进行视图和验证

> 到目前为止，我们的应用程序与使用 MySQL 或其他关系数据库时并没有太大的不同。但是，在本章中，我们将真正发挥 CouchDB 的作用，通过它来处理以前在关系数据库中可能是痛点的许多事情。

在本章中，我们将：

+   定义设计文档

+   了解视图以及如何使用它们来查询数据

+   发现 MapReduce 函数的威力

+   使用 CouchDB 的 `validation` 函数

让我们不浪费时间，直接谈论设计文档。

# 设计文档

**设计文档** 是 CouchDB 的特殊功能之一，你可能没有从数据库中预期到。表面上，设计文档看起来和普通文档一样。它们有标准字段：`_id` 和 `_rev`，可以创建、读取、更新和删除。但与普通文档不同的是，它们包含 JavaScript 形式的应用代码，并且具有特定的结构。这些 JavaScript 可以驱动验证，使用 `map` 和 `reduce` 函数显示视图，以及更多功能。我们将简要介绍每个功能以及如何使用它们。

## 一个基本的设计文档

一个基本的设计文档可能看起来类似于以下内容：

```php
{
—_id— : —_design/application—,
"_rev" : "3-71c0b0bd73a9c9a45ea738f1e9612798",
"views" : {
"example" : {
"map" : "function(doc){ emit(doc._id, doc)}"
}
}
}

```

`_id` 和 `_rev` 应该看起来很熟悉，但与迄今为止的其他文档不同，`_id` 有一个可读的名称：`_design/example`。设计文档通过名称中包含 `_design` 来标识。因此，您需要遵循这种格式。

从 `_id` 和 `_rev` 过渡后，您会注意到键视图。视图是设计文档的重要组成部分，让我们更多地谈谈它们。

## 视图

**视图** 是 CouchDB 提供给我们的用于索引、查询和报告数据库文档的工具。如果您在 MySQL 经验之后阅读本书，那么视图将替代典型的 SQL `SELECT` 语句。

现在您对视图有了一些了解，您会注意到在前面的设计文档中，我们创建了一个名为 `test` 的视图。

### 映射函数

在 `example` 键内，我们放置了一个名为 `map` 的函数。Map 函数是 JavaScript 函数，用于消耗文档，然后将它们从原始结构转换为应用程序可以使用的新的键/值对。了解 Map 函数至关重要。因此，让我们看一下 `map` 函数的最简单实现，以确保我们都在同一个页面上。

```php
－example－ : {
－map－ : －function(doc){ emit(doc._id, doc)}－
}

```

当调用示例 `map` 函数时，CouchDB 将尝试索引数据库中的每个文档，并使用 `doc` 参数以 JSON 格式将它们传递给这个函数。然后，我们调用一个名为 `emit` 的函数，它接受一个键和一个值，从中键和值将保存到一个数组中，并在索引完成后返回。

`emit` 函数的键和值可以是文档中的任何字段。在这个例子中，我们将 `doc._id` 作为键，`doc` 作为值传递给 `emit` 函数。`doc._id` 可能是被索引的文档的 `_id` 字段，`doc` 是以 JSON 格式表示的整个文档。

在下一节中，我们将使用视图来处理我们的数据。为了确保您完全理解视图对我们的数据做了什么，请确保您在 `verge` 数据库中至少创建了五到六篇帖子。

# 行动时间 — 创建临时视图

CouchDB 为我们提供了临时视图，供我们在开发或尝试测试视图结果时使用。让我们使用 Futon 创建一个临时视图，以便我们可以处理一些数据。

1.  打开浏览器，转到 Futon (`http://localhost:5984/_utils/`)。

1.  确保您已登录到 `admin` 帐户，通过检查右侧列的底部。

1.  通过单击 `verge` 进入我们的 `verge` 数据库。

1.  点击下拉框，选择**临时视图...**。![进行操作的时间-创建临时视图](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_08_005.jpg)

1.  这个表单将允许我们玩弄视图并实时测试它们与数据。![进行操作的时间-创建临时视图](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_08_010.jpg)

1.  让我们编辑**Map Function**文本区域中的代码，使其与我们之前查看的示例代码匹配：

```php
function(doc) {
emit(doc._id, doc)
}

```

1.  点击**运行**以查看`map`函数的结果。![进行操作的时间-创建临时视图](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_08_015.jpg)

1.  让我们确保我们只能通过检查`doc.type`是否等于`post:`来看到帖子。

```php
function(doc) {
if (doc.type == 'post') {
emit(doc._id, doc);
}
}

```

1.  再次点击**运行**，你会看到相同的结果。

## 刚刚发生了什么？

我们刚刚学习了如何在 CouchDB 中创建一个临时视图，以便我们可以测试之前查看的`map`函数。使用 Futon 给我们的临时视图界面，我们运行了我们的示例`map`函数，并显示了一系列键/值对。

最后，我们稍微加强了我们的`map`函数，以确保我们只查看`type`等于`post`的文档。现在，这个改变对我们的`map`函数没有任何影响，但是一旦我们添加了一个不同类型的文档，情况就会改变。如果你记得的话，这是因为 CouchDB 将文档存储在一个扁平的数据存储中；这意味着当我们添加新的文档类型时，我们希望具体指出我们要处理哪些文档。因此，通过在我们的代码中添加`if`语句，我们告诉 CouchDB 忽略那些`type`未设置为`post`的文档。

# 进行操作的时间-创建用于列出帖子的视图

你可能已经注意到了临时视图页面上的警告，内容如下：

```php
**Warning: Please note that temporary views that we'll create are not suitable for use in production and will respond much slower as your data increases. It's recommended that you use temporary views in experimentation and development, but switch to a permanent view before using them in an application.** 

```

让我们听从这个警告，创建一个设计文档，这样我们就可以开始将所有这些构建到我们的应用程序中。

1.  打开你的浏览器到 Futon。

1.  导航到我们正在使用的临时视图页面：（`http://localhost:5984/_utils/database.html?verge/_temp_view`）。

1.  让我们让我们的函数更有用一些，将我们的键改为`doc.user`。

```php
function(doc) {
if (doc.type == 'post') {
emit(doc.user, doc);
}
}

```

1.  点击**运行**以查看结果。![进行操作的时间-创建用于列出帖子的视图](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_08_020.jpg)

1.  现在我们的视图中有我们想要在应用程序中使用的代码，点击**另存为...**以保存此视图并为我们创建一个设计文档。

1.  将显示一个窗口，要求我们给设计文档和视图命名。将`_design/application`输入为**设计文档**名称，`posts_by_user`输入为**视图名称**，然后点击**保存**。![进行操作的时间-创建用于列出帖子的视图](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_08_025.jpg)

## 刚刚发生了什么？

我们从临时视图中创建了一个设计文档，以便我们的应用程序可以使用它。这一次，我们将键从`doc._id`更改为`doc.user`，以便我们可以选择具有特定用户名的文档，这将在几分钟内有所帮助。然后，我们将这个临时视图保存为一个名为`posts_by_user`的视图，并将其保存到一个名为`_design/application`的新设计文档中。

你可以使用 Futon 的界面轻松检查我们的设计文档是否成功创建。

1.  打开你的浏览器，进入 Futon 中的`verge`数据库（`http://localhost:5984/_utils/database.html?verge`）。

1.  点击视图下拉框，选择**设计文档**。

1.  你只会在这里看到一个文档，那就是我们新创建的设计文档，名为`_design/application`。

1.  点击文档，你会看到完整的设计文档。![刚刚发生了什么？](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_08_030.jpg)

趁热打铁，让我们快速看看如何使用 Futon 来测试设计文档及其视图：

1.  打开你的浏览器到 Futon，并确保你正在查看`verge`数据库（`http://localhost:5984/_utils/database.html?verge`）。

1.  点击视图下拉框，你会看到应用程序（我们设计文档的名称）。点击名为`posts_by_user`的视图。

1.  您将看到视图的结果，以及当前与之关联的代码。![刚刚发生了什么？](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_08_035.jpg)

从这个页面，您可以点击结果并查看文档详细信息。您甚至可以通过简单地输入新代码并点击**保存**来更改视图的代码。

玩弄这些简单视图很有趣，但让我们深入一点，看看我们实际上如何使用这些视图来查询我们的文档。

### 查询 map 函数

我们可以在我们的`map`查询中使用各种选项。我将涉及最常见的一些选项，但您可以通过查看 CouchDB 的 wiki 找到更多：[`wiki.apache.org/couchdb/HTTP_view_API#Querying_Options`](http://wiki.apache.org/couchdb/HTTP_view_API#Querying_Options)。

最常见的查询选项是：

+   `reduce`

+   `startkey`

+   `endkey`

+   `key`

+   `limit`

+   `skip`

+   `descending`

+   `include_docs`

让我们使用一些这些选项与我们的`posts_by_user`视图，看看我们可以得到什么样的结果。

# 行动时间-查询 posts_by_user 视图

请记住，设计文档仍然是一个文档，这意味着我们可以像查询常规文档一样查询它。唯一的区别是我们需要使用稍微不同的 URL 模式来命中正确的文件。

1.  打开终端。

1.  使用一个`curl`语句通过传递`johndoe`的关键字（或者您数据库中帖子数量较多的其他用户）来查询我们的设计文档，然后通过`python mjson.tool`使其变得更漂亮：

```php
**curl http://127.0.0.1:5984/verge/_design/application/_view/posts_by_user?key=%22johndoe%22 | python -mjson.tool** 

```

1.  终端将返回类似以下的内容：

```php
{
"offset": 0,
"rows": [
{
"id": "352e5c2d51fb1293c44a2146d4003aa3",
"key": "johndoe",
"value": {
"_id": "352e5c2d51fb1293c44a2146d4003aa3",
"_rev": "3-ced38337602bd6c0587dc2d9792f6cff",
"content": "I don\\'t like peanut butter.",
"date_created": "Wed, 28 Sep 2011 13:44:09 -0700",
"type": "post",
"user": "johndoe"
}
},
{
"id": "d3dd453dbfefab8c8ea62a7efe000fad",
"key": "johndoe",
"value": {
"_id": "d3dd453dbfefab8c8ea62a7efe000fad",
"_rev": "2-07c7502eecb088aad5ee8bd4bc6371d1",
"content": "I do!\r\n",
"date_created": "Mon, 17 Oct 2011 21:36:18 -0700",
"type": "post",
"user": "johndoe"
}
}
],
"total_rows": 4
}

```

## 刚刚发生了什么？

我们刚刚使用了一个`curl`语句来查询我们应用程序设计文档中的`posts_by_user`视图。我们将`johndoe`作为我们的视图搜索的关键字传递，CouchDB 用它来返回只匹配该关键字的文档。然后我们使用`python mjson.tool`，这样我们就可以以友好的方式看到我们的输出。

让我们再玩一会儿，通过几个快速场景来讨论一下，确定我们如何使用 map 的`query`选项来解决它们。

1.  如果您真的只想检索我们的`map`函数为`johndoe`返回的第一篇帖子，您可以通过在查询字符串的末尾添加`limit=1`来实现这一点：

```php
**curl 'http://127.0.0.1:5984/verge/_design/application/_view/posts_by_user?key=%22johndoe%22&limit=1'| python -mjson.tool** 

```

1.  您的终端将返回以下输出。请注意，这次您只会得到一篇帖子：

```php
{
"offset": 0,
"rows": [
{
"id": "352e5c2d51fb1293c44a2146d4003aa3",
"key": "johndoe",
"value": {
"_id": "352e5c2d51fb1293c44a2146d4003aa3",
"_rev": "3-ced38337602bd6c0587dc2d9792f6cff",
"content": "I don\\'t like peanut butter.",
"content": "I don\\'t like peanut butter.",
"date_created": "Wed, 28 Sep 2011 13:44:09 -0700",
"type": "post",
"user": "johndoe"
}
}
],
"total_rows": 4
}

```

1.  现在，如果我们想要看到我们的`map`函数为`johndoe`返回的最后一篇帖子，您可以通过在我们的语句末尾添加`descending=true`以及`limit=1`来实现这一点，以获取最新的帖子，如下所示：

```php
**curl 'http://127.0.0.1:5984/verge/_design/application/_view/posts_by_user?key=%22johndoe%22&limit=1&descending=true'| python -mjson.tool** 

```

1.  您的命令行将精确返回您要查找的内容：由`johndoe`创建的最后一篇帖子。

```php
{
"offset": 2,
"rows": [
{
"id": "d3dd453dbfefab8c8ea62a7efe000fad",
"key": "johndoe",
"value": {
"_id": "d3dd453dbfefab8c8ea62a7efe000fad",
"_rev": "2-07c7502eecb088aad5ee8bd4bc6371d1",
"content": "I do!\r\n",
"date_created": "Mon, 17 Oct 2011 21:36:18 -0700",
"type": "post",
"user": "johndoe"
}
}
],
"total_rows": 4
}

```

通过这些示例，您应该清楚地知道我们可以链式和组合我们的`query`选项以各种方式检索数据。我们可以玩一会儿查询视图，但让我们继续尝试将`posts_by_user`视图构建到我们的应用程序中，以便我们可以在用户的个人资料上显示用户的帖子。

### 在我们的应用程序中使用视图

我们已经完成了查询数据库所需的大部分繁重工作；我们只需要向我们的应用程序添加几行代码。

# 行动时间-在帖子类中添加对 get_posts_by_user 的支持

1.  在文本编辑器中打开`classes/post.php`。

1.  创建一个名为`get_posts_by_user`的新的`public`函数，它将接受`$username`作为参数。

```php
public function get_posts_by_user($username) {
}

```

1.  现在，让我们创建一个新的`Bones`实例，以便我们可以查询 CouchDB。让我们还实例化一个名为`$posts`的数组，在这个函数的最后返回它。

```php
public function get_posts_by_user($username) {
**$bones = new Bones();
$posts = array();
return $posts;** 
}

```

1.  接下来，让我们通过传递`$username`作为关键字来查询我们的视图，并使用`foreach`函数来遍历所有结果到一个名为`$_post`的变量中。

```php
public function get_posts_by_user($username) {
$bones = new Bones();
$posts = array();
**foreach ($bones->couch- >get('_design/application/_view/posts_by_user?key="' . $username . '"&descending=true')->body->rows as $_post) {
}** 
return $posts;
}

```

1.  最后，让我们使用`$_post`变量中的数据创建和填充一个新的`Post`实例。然后，让我们将`$post`添加到`$posts`数组中。

```php
public function get_posts_by_user($username) {
$bones = new Bones();
$posts = array();
foreach ($bones->couch- >get('_design/application/_view/posts_by_user?key="' . $username . '"')->body->rows as $_post) {
**$post = new Post();
$post->_id = $_post->id;
$post->date_created = $_post->value->date_created;
$post->content = $_post->value->content;
$post->user = $_post->value->user;
array_push($posts, $post);
}** 
return $posts;
}

```

## 刚刚发生了什么？

我们创建了一个名为`get_posts_by_user`的函数，并将其放在我们的`Post`类中。这个函数接受一个名为`$username`的参数。`get_posts_by_user`函数使用`get_posts_by_user`视图将帖子列表返回到一个通用类中，我们遍历每个文档，创建单独的`Post`对象，并将它们推入数组中。您会注意到，我们必须使用`$_post->value`来获取帖子文档。请记住，这是因为我们的视图返回一个键和值的列表，每个文档一个，我们整个文档都存在于`value`字段中。

简而言之，这个函数使我们能够传入用户的用户名，并检索由传入用户创建的帖子数组。

# 行动时间——将帖子添加到用户资料

现在我们已经完成了所有繁重的工作，获取了用户的帖子，我们只需要再写几行代码，就可以让它们显示在用户资料中。让我们首先在`index.php`文件中添加一些代码，接受路由中的用户名，将其传递给`get_posts_by_user`函数，并将数据传递给资料视图：

1.  打开`index.php`，找到`/user/:username`路由，并添加以下代码，将我们的`get_posts_by_user`函数返回的帖子传递给一个变量，以便我们的视图访问：

```php
get('/user/:username', function($app) {
$app->set('user', User::find_by_username($app- >request('username')));
$app->set('is_current_user', ($app->request('username') == User::current_user() ? true : false));
**$app->set('posts', Post::get_posts_by_user($app- >request('username')));** 
$app->render('user/profile');
});

```

1.  打开`views/user/profile.php`，并在**创建新帖子**文本区域的下面添加以下代码，以便我们可以在用户资料页面上显示帖子列表：

```php
<h2>Posts</h2>
**<?php foreach ($posts as $post): ?>
<div class="post-item row">
<div class="span7">
<strong><?php echo $user->name; ?></strong>
<p>
<?php echo $post->content; ?>
</p>
<?php echo $post->date_created; ?>
</div>
<div class="span1">
<a href=#">(Delete)</a>
</div>
<div class="span8"></div>
</div>** 
<?php endforeach; ?>

```

1.  最后，为了支持我们添加的一些新代码，让我们更新我们的`public/css/master.css`文件，使资料看起来漂亮整洁。

```php
.post-item {padding: 10px 0 10px 0;}
.post-item .span8 {margin-top: 20px; border-bottom: 1px solid #ccc;}
.post-item .span1 a {color:red;}

```

## 发生了什么？

我们刚刚在`index.php`文件中添加了一些代码，这样当用户导航到用户的资料时，我们的应用程序将从路由中获取用户名，传递给`get_posts_by_user`函数，并将该函数的结果传递给一个名为`posts`的变量。然后，在`views/user/profile.php`页面中，我们循环遍历帖子，并使用 Bootstrap 的 CSS 规则使其看起来漂亮。最后，我们在我们的`master.css`文件中添加了几行代码，使一切看起来漂亮。

在本节中，我们还在每篇帖子旁边添加了一个(删除)链接，目前还没有任何功能。我们将在本章后面再连接它。

打开我们的浏览器，让我们检查一下，确保一切都正常工作。

1.  打开您的浏览器，以一个用户的身份登录。

1.  点击**我的个人资料**查看用户资料。

1.  现在，您应该能够看到包含用户所有帖子的完整资料。![发生了什么？](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_08_040.jpg)

1.  让我们测试一下，确保我们的列表正常工作，输入一些文本到文本区域中，然后点击**提交**。

1.  您的个人资料已刷新，您的新帖子应该显示在列表的顶部。![发生了什么？](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_08_045.jpg)

随意在这里暂停一下，以几个不同的用户身份登录，并创建大量的帖子！

完成后，让我们继续讨论`map`函数的伴侣：**reduce**。

### Reduce 函数

**Reduce**允许您处理`map`函数返回的键/值对，然后将它们分解为单个值或更小的值组。为了让我们的工作更容易，CouchDB 带有三个内置的`reduce`函数，分别是`_count, _sum`和`_stats`。

+   `_count:` 它返回映射值的数量

+   `_sum:` 它返回映射值的总和

+   `_stats:` 它返回映射值的数值统计，包括总和、计数、最小值和最大值

由于`reduce`函数对于新开发者来说可能不是 100%直观，让我们直截了当地在我们的应用程序中使用它。

在下一节中，我们将为我们的`get_posts_by_user`视图创建一个`reduce`函数，显示每个用户创建的帖子数量。看一下我们现有的设计文档，显示了`reduce`函数的样子：

```php
{
"_id": "_design/application",
"_rev": "3-71c0b0bd73a9c9a45ea738f1e9612798",
"language": "javascript",
"views": {
"posts_by_user": {
"map": "function(doc) {emit(doc.user, doc)}",
**"reduce": "_count"** 
}
}
}

```

在这个例子中，`reduce`函数将`map`函数中的所有用户名分组，并返回每个用户名在列表中出现的次数。

# 执行操作-在 Futon 中创建 reduce 函数

使用 Futon 向视图添加`reduce`函数非常容易。

1.  打开你的浏览器，进入 Futon 中的`verge`数据库（`http://localhost:5984/_utils/database.html?verge`）。

1.  点击视图下拉框，你会看到应用程序（我们设计文档的名称）。你可以点击名为`posts_by_user`的视图。

1.  点击**查看代码**，这样你就可以看到**Map**和**Reduce**的文本区域。

1.  在**Reduce**文本区域输入`_count`，然后点击**保存**。

1.  你可以通过点击**保存**按钮下面的**Reduce**复选框来验证你的`reduce`函数是否正常工作。

1.  你应该看到类似以下的屏幕截图：![执行操作-在 Futon 中创建 reduce 函数](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_08_047.jpg)

## 刚刚发生了什么？

我们刚刚使用 Futon 更新了我们的视图以使用`_count reduce`函数。然后，我们通过点击**Reduce**复选框在同一视图中测试了`reduce`函数。你会注意到我们的`reduce`函数也返回了一个键/值对，键等于用户名，值等于他们创建的帖子的数量。

# 执行操作-为我们的应用程序添加支持以使用 reduce 函数

现在我们已经创建了`reduce`函数，让我们向我们的应用程序添加一些代码来检索这个值。

1.  打开`classes/post.php`。

1.  现在我们已经创建了一个`reduce`函数，我们需要确保`get_posts_by_user`函数在不使用`reduce`函数的情况下使用该视图。我们将通过在查询字符串中添加`reduce=false`来实现这一点。这告诉视图不要运行`reduce`函数。

```php
public function get_posts_by_user($username) {
$bones = new Bones();
$posts = array();
**foreach ($bones->couch- >get('_design/application/_view/posts_by_user?key="' . $username . '"&descending=true&reduce=false')->body->rows as $_post) {** 

```

1.  创建一个名为`get_post_count_by_user`的新的`public`函数，它将接受`$username`作为参数。

```php
public function get_post_count_by_user($username) {
}

```

1.  让我们添加一个调用我们的视图，模仿我们的`get_posts_by_user`函数。但是，这一次，我们将在查询字符串中添加`reduce=true`。一旦我们从视图中获得结果，就遍历数据以获取位于第一个返回行的值中的值。

```php
public function get_post_count_by_user($username) {
**$bones = new Bones();
$rows = $bones->couch- >get('_design/application/_view/posts_by_user?key="' . " $username . '"&reduce=true')->body->rows;
if ($rows) {
return $rows[0]->value;
} else {
return 0;
}** 
}

```

1.  打开`index.php`，找到`/user/:username`路由。

1.  添加代码将`get_post_count_by_user`函数的值传递给我们的视图可以访问的变量。

```php
get('/user/:username', function($app) {
$app->set('user', User::get_by_username($app- >request('username')));
$app->set('is_current_user', ($app->request('username') == User::current_user() ? true : false));
$app->set('posts', Post::get_posts_by_user($app- >request('username')));
**$app->set('post_count', Post::get_post_count_by_user($app- >request('username')));** 
$app->render('user/profile');
});

```

1.  最后，打开用户资料（`views/user/profile.php`）并在我们的`post`列表顶部显示$post_count 变量。

```php
<h2>Posts (<?php echo $post_count; ?>)</h2>

```

## 刚刚发生了什么？

我们通过更新现有的`get_posts_by_user`函数开始本节，并告诉它不要运行`reduce`函数，只运行`map`函数。然后，我们创建了一个名为`get_post_count_by_user`的函数，它访问了我们的`posts_by_user`视图。但是，这一次，我们告诉它通过在调用中传递`reduce=true`来运行`reduce`函数。当我们从`reduce`函数接收到值时，我们进入第一行的值并返回它。我们只看一个行，因为我们只传入一个用户名，这意味着只会返回一个值。

然后我们从用户资料路由调用`get_post_count_by_user`并将其传递给`user/profile.php`视图。在视图中，我们在帖子列表的顶部输出了`$post_count`。

通过这么少的代码，我们为我们的资料添加了一个很酷的功能。让我们测试一下看看`$post_count`显示了什么。

1.  打开你的浏览器，通过`http://localhost/verge/user/johndoe`进入 John Doe 的用户资料。

1.  请注意，我们现在在`post`列表的顶部显示了帖子的数量。![刚刚发生了什么？](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_08_048.jpg)

### 更多关于 MapReduce

使用`map`和`reduce`函数一起通常被称为**MapReduce**，当它们一起使用时，它们可以成为数据分析的强大方法。不幸的是，我们无法在本书中介绍各种案例研究，但我会在本章末尾包含一些进一步学习的参考资料。

## 验证

在本节中，我们将揭示并讨论 CouchDB 的另一个非常独特的属性-其内置的文档函数支持。这个功能允许我们对我们的数据进行更严格的控制，并可以保护我们免受一些可能在 Web 应用程序中发生的严重问题。

请记住，我们的`verge`数据库可以被任何用户读取，这对我们来说还不是一个问题。但是，例如，如果有人找出了我们的数据库存储位置怎么办？他们可以很容易地在我们的数据库中创建和删除文档。

为了充分说明这个问题，让我们添加一个功能，允许我们的用户删除他们的帖子。这个简单的功能将说明一个潜在的安全漏洞，然后我们将用 CouchDB 的`validation`函数来修补它。

# 行动时间-为我们的类添加对$_rev 的支持

直到这一点，我们在 CouchDB 文档中看到了`_rev`键，但我们实际上并没有在我们的应用程序中使用它。为了能够对已经存在的文档采取任何操作，我们需要传递`_rev`以及`_id`，以确保我们正在处理最新的文档。

让我们通过向我们的`base`类添加一个`$_rev`变量来为此做好准备。

1.  在您的工作目录中打开`classes/base.php`，并添加`$_rev`变量。

```php
abstract class Base
{
protected $_id;
**protected $_rev;** 
protected $type;

```

1.  不幸的是，现在每次调用`to_json`函数时，无论是否使用，`_rev`都将始终包含在内。如果我们向 CouchDB 发送一个`null _rev`，它将抛出错误。因此，让我们在`classes/base.php`的`to_json`函数中添加一些代码，如果没有设置值，就取消设置我们的`_rev`变量。

```php
public function to_json() {
**if (isset($this->_rev) === false) {
unset($this->_rev);
}** 
return json_encode(get_object_vars($this));
}

```

## 刚刚发生了什么？

我们将`$_rev`添加到我们的`base`类中。直到这一点，我们实际上并没有需要使用这个值，但在处理现有文档时，这是一个要求。在将`$_rev`添加到`base`类之后，我们不得不修改我们的`to_json`函数，以便在没有设置值时取消设置`$_rev`。

# 行动时间-在我们的应用程序中添加删除帖子的支持

现在我们在`base`类中有访问`_rev`变量的支持，让我们添加支持，以便我们的应用程序可以从用户个人资料中删除帖子。

1.  让我们从打开`classes/post.php`并向`get_posts_by_user`函数添加一行代码开始，以便我们可以使用`_rev`。

```php
public function get_posts_by_user($username) {
$bones = new Bones();
$posts = array();
foreach $bones->couch- >get('_design/application/_view/posts_by_user?key="' . $username . '"&descending=true&reduce=false')->body->rows as $_post) {
$post = new Post();
$post->_id = $_post->value->_id;
**$post->_rev = $_post->value->_rev;** 
$post->date_created = $_post->value->date_created;

```

1.  接下来，让我们在`classes/post.php`文件中创建一个简单的`delete`函数，以便我们可以删除帖子。

```php
public function delete() {
$bones = new Bones();
try {
$bones->couch->delete($this->_id, $this->_rev);
}
catch(SagCouchException $e) {
$bones->error500($e);
}
}

```

1.  现在我们有了删除帖子的后端支持，让我们在我们的`index.php`文件中添加一个接受`_id`和`_rev`的路由。通过这个路由，我们可以触发从我们的个人资料页面删除帖子。

```php
get('/post/delete/:id/:rev', function($app) {
$post = new Post();
$post->_id = $app->request('id');
$post->_rev = $app->request('rev'
$post->delete();
$app->set('success', 'Your post has been deleted');
$app->redirect('/user/' . User::current_user());
});

```

1.  最后，让我们更新我们的`views/user/profile.php`页面，以便用户点击`delete`链接时，会命中我们的路由，并传递必要的变量。

```php
<?php foreach ($posts as $post): ?>
<div class="post-item row">
<div class="span7">
<strong><?php echo $user->name; ?></strong>
<p>
<?php echo $post->content; ?>
</p>
<?php echo $post->date_created; ?>
</div>
<div class="span1">
**<a href="<?php echo $this->make_route('/post/delete/' . $post->_id . '/' . $post->_rev)?>" class="delete">
(Delete)
</a>** 
</div>
<div class="span8"></div>
</div>
<?php endforeach; ?>

```

## 刚刚发生了什么？

我们刚刚添加了支持用户从其个人资料中删除帖子。我们首先确保在`get_posts_by_user`函数中将`_rev`返回到我们的帖子对象中，以便在尝试删除帖子时可以传递它。接下来，我们在我们的`post`类中创建了一个接受`$id`和`$rev`作为属性并调用 Sag 的`delete`方法的`delete`函数。然后，我们创建了一个名为`/post/delete`的新路由，允许我们向其传递`_id`和`_rev`。在这个路由中，我们创建了一个新的`Post`对象，为其设置了`_id`和`_rev`，然后调用了`delete`函数。然后我们设置了`success`变量并刷新了个人资料。

最后，我们通过将`$post->_id`和`$post->_rev`传递给`/post/delete`路由，使用户个人资料中的`delete`链接可操作。

太棒了！现在我们可以点击网站上任何帖子旁边的**删除**，它将从数据库中删除。让我们试一试。

1.  打开浏览器，转到`http://localhost/verge`。

1.  以任何用户身份登录，转到他们的用户资料。

1.  点击**（删除）**按钮。

1.  页面将重新加载，您的帖子将神奇地消失！

这段代码从技术上讲确实按照我们的计划工作，但是如果您玩了几分钟删除帖子，您可能会注意到我们这里有一个问题。现在，任何用户都可以从任何个人资料中删除帖子，这意味着我可以转到您的个人资料并删除您的所有帖子。当然，我们可以通过隐藏**删除**按钮来快速解决这个问题。但是，让我们退一步，快速思考一下。

如果有人找到（或猜到）用户帖子的`_id`和`_rev`，并将其传递给`/post/delete`路由，会发生什么？帖子将被删除，因为我们没有任何用户级别的验证来确保试图删除文档的人实际上是文档的所有者。

让我们首先在数据库级别解决这个问题，然后我们将逆向工作，并在界面中正确隐藏**删除**按钮。

### CouchDB 对验证的支持

CouchDB 通过设计文档中的`validate_doc_update`函数为文档提供验证。如果操作不符合我们的标准，此函数可以取消文档的创建/更新/删除。验证函数具有定义的结构，并且可以直接适用于设计文档，如下所示：

```php
{
"_id": "_design/application",
"_rev": "3-71c0b0bd73a9c9a45ea738f1e9612798",
"language": "javascript",
**"validate_doc_update": "function(newDoc, oldDoc, userCtx) { //JavaScript Code }",** 
"views": {
"posts_by_user": {
"map": "function(doc) {emit(doc.user, doc)}",
"reduce": "_count"
}
}
}

```

让我们看看`validate_doc_update`函数，并确保我们清楚这里发生了什么。

```php
function(newDoc, oldDoc, userCtx) { //JavaScript Code }

```

+   `newDoc:`它是您要保存的文档

+   `oldDoc:`它是现有的文档（如果有的话）

+   `userCtx:`它是用户对象和他们的角色

现在我们知道我们可以使用哪些参数，让我们创建一个简单的`validate`函数，确保只有文档的创建者才能更新或删除该文档。

# 行动时间-添加一个验证函数，以确保只有创建者可以更新或删除他们的文档

添加`validate`函数可能有点奇怪，因为与视图不同，在 Futon 中没有一个很好的界面供我们使用。添加`validate_doc_update`函数的最快方法是将其视为文档中的普通字段，并将代码直接输入值中。这有点奇怪，但这是调整设计文档的最快方法。在本章的末尾，如果您想更清晰地了解如何管理设计文档，我会给您一些资源。

1.  打开浏览器，转到 Futon（`http://localhost:5984/_utils/`）。

1.  确保您已登录到`admin`帐户，方法是检查右下角列是否显示**欢迎**。

1.  通过单击`verge`转到我们的`verge`数据库。

1.  点击我们的`_design/application`设计文档。

1.  点击**添加字段**，并将此字段命名为`validate_doc_update`。

1.  在**值**文本区域中，添加以下代码（格式和缩进无关紧要）：

```php
function(newDoc, oldDoc, userCtx) {
if (newDoc.user) {
if(newDoc.user != userCtx.name) {
throw({"forbidden": "You may only update this document with user " + userCtx.name});
}
}
}

```

1.  点击**保存**，您的文档将被更新以包括验证函数。

## 刚刚发生了什么？

我们刚刚使用 Futon 更新了我们的`_design/application`设计文档。我们使用简单的界面创建了`validate_doc_update`函数，并将验证代码放在值中。代码可能看起来有点混乱；让我们快速浏览一下。

1.  首先，我们检查要保存的文档是否使用此`if`语句附加了一个用户变量：

```php
if (newDoc.user).

```

1.  然后，我们检查文档上的用户名是否与当前登录用户的用户名匹配：

```php
if(newDoc.user != userCtx.name).

```

1.  如果事实证明文档确实与用户相关联，并且尝试保存的用户不是已登录用户，则我们使用以下代码行抛出禁止错误（带有状态码`403`的 HTTP 响应），并说明为什么无法保存文档：

```php
throw({"forbidden": "You may only update this document with user " + userCtx.name});

```

值得注意的是，一个设计文档只能有一个`validate_doc_update`函数。因此，如果你想对不同的文档进行不同类型的验证，那么你需要做如下操作：

```php
function(newDoc, oldDoc, userCtx) {
if (newDoc.type == "post") {
// validation logic for posts
}
if (newDoc.type == "comment") {
// validation logic for comments
}
}

```

我们可以用验证函数做更多的事情。事实上，我们经常使用的`_users`数据库通过`validate_doc_update`函数驱动所有用户验证和控制。

现在，让我们测试一下我们的`validation`函数。

1.  打开你的浏览器，转到`http://localhost/verge`。

1.  以一个不同于`John Doe`的用户登录。

1.  通过访问：`http://localhost/verge/user/johndoe`，转到`John Doe`的个人资料。

1.  尝试点击`(Delete)`按钮。

1.  你的浏览器将向你显示以下消息：![刚刚发生了什么？](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_08_050.jpg)

太棒了！CouchDB 为我们抛出了一个`403`错误，因为它知道我们没有以`John Doe`的身份登录，而我们试图删除他的帖子。如果你想进一步调查，你可以再次以`John Doe`的身份登录，并验证当你以他的身份登录时是否可以删除他的帖子。

我们可以放心地知道，无论用户使用什么接口，Sag、curl，甚至通过 Futon，CouchDB 都会确保用户必须拥有文档才能删除它。

我们可以为这个验证错误添加一个更优雅的错误消息，但这种错误很少发生，所以现在让我们继续。让我们只是在用户个人资料中添加一些简单的逻辑，这样用户就没有能力删除其他用户的帖子。

# 行动时间-当不在当前用户的个人资料页面时隐藏删除按钮

对用户隐藏删除按钮对我们来说实际上非常容易。虽然这种方法不能取代我们之前的验证函数，但对我们来说，这是一种友好的方式，可以防止用户意外尝试删除其他人的帖子。

1.  在文本编辑器中打开 view/user/profile.php。

1.  找到我们创建帖子的循环，并在我们的删除按钮周围添加这段代码。

```php
<div class="span1">
<?php if ($is_current_user) { ?>
<a href="<?php echo $this->make_route('/post/delete/' . $post-
>
_id . '/' . $post->_rev)?>" class="delete">(Delete)
</a>
<?php } ?>
</div>

```

## 刚刚发生了什么？

我们刚刚使用了我们简单的变量`$is_current_user`，当用户查看其他人的个人资料时，隐藏了删除按钮，并在查看自己的个人资料时显示了它。这与我们在本章早期用于显示和隐藏创建帖子文本区域的技术相同。

如果你的用户现在去另一个用户的个人资料，他们将无法看到删除他们帖子的选项。即使他们以某种方式找到了帖子的`_id`和`_rev`，并且能够触发删除帖子，`validation`函数也会阻止他们。

# 总结

在本章中，我们经历了很多，但我只能触及一些绝对值得进一步研究的要点。

## 想要更多例子吗？

学习`MapReduce`函数和设计文档的高级技术可能需要一整本书的篇幅。事实上，已经有一整本书在讲这个！如果你想了解更多关于真实用例场景以及如何处理一对多和多对多关系的内容，那就看看*Bradley Holt*的一本书，名为《在 CouchDB 中编写和查询 MapReduce Views》。

## 在 Futon 中使用设计文档太难了！

你并不是唯一一个认为在 Futon 中使用设计文档太难的人。

有一些工具可能值得一试：

+   **CouchApp** ([`couchapp.org/`](http://couchapp.org/))：这是一个实用程序，可以让你创建在 CouchDB 内部运行的完整的 JavaScript 应用程序。然而，它管理设计文档的方式也可以在开发 PHP 应用程序时让你的生活更轻松。

+   **LoveSeat** ([`www.russiantequila.com/wordpress/?p=119`](http://www.russiantequila.com/wordpress/?p=119))：这是一个轻量级的编辑器，可以在 Mono 下工作，这意味着它可以在任何操作系统上运行。它允许你非常容易地管理你的文档和设计文档。

# 摘要

在本章中，我们深入研究了 CouchDB，并利用了它的一些独特特性来使我们的应用程序更简单。更具体地说，我们讨论了设计文档以及 CouchDB 如何使用它们，使用 Futon 创建视图和设计文档。我们了解了视图，以及如何使用选项查询它们，例如 SQL，如何在视图中使用 MapReduce 查询我们的帖子，在我们的应用程序中使用视图动态显示每个用户的帖子列表和计数，还学习了如何在 CouchDB 中构建验证并将其用于保护我们的应用程序。

在下一章中，我们将进一步完善我们的应用程序，并添加一些有趣的功能，例如使用 JQuery 改善用户体验，添加分页，使用 Gravatars 等等！


# 第九章：为您的应用程序添加花里胡哨的功能

> 我们为我们的应用程序添加了许多实用功能。但是，还有一些缺少的功能，有些人可能认为是“很好有”的，并且对我们来说很重要，以便我们的应用程序具有良好的用户体验。

在本章中，我们将：

+   将 jQuery 添加到项目中并使用它简化删除按钮

+   通过使用 CouchDB 视图和 jQuery 为用户帖子添加基本分页

+   通过使用 Gravatar 的 Web 服务为我们所有的用户添加个人资料图片

这些功能是有趣的小添加，它们也会让您看到当您将其他库与 CouchDB 和 PHP 结合使用时可能发生的事情。

# 将 jQuery 添加到我们的项目中

尽管这本书主要是关于在 PHP 中编写应用程序，但是在构建优秀的应用程序时，JavaScript 已经成为开发人员工具包中几乎必不可少的工具。我们已经在 CouchDB 视图中使用了 JavaScript，但是在本章中，我们将使用 JavaScript 进行其最常见的用例-改善用户体验。为了使我们能够编写更简单的 JavaScript，我们将使用一个名为**jQuery**的流行库。如果您以前没有使用过 jQuery，您会惊喜地发现它在简化 JavaScript 中的常见和复杂操作方面有多么简化。

## 安装 jQuery

幸运的是，将 jQuery 添加到任何项目中都非常简单。我们可以从[`www.jquery.com`](http://www.jquery.com)下载它，但是，因为我们想要专注于速度，我们实际上可以在不将任何内容安装到我们的存储库中的情况下使用它。

# 行动时间-将 jQuery 添加到我们的项目中

由于使用 jQuery 的人数激增，谷歌建立了一个内容传递网络，为我们提供 jQuery 库，而无需在我们的项目中需要任何东西。让我们告诉我们的`layout.php`文件在哪里找到 jQuery。

打开`layout.php`文件，并在`body`部分的末尾之前添加以下代码：

```php
<script type="text/javascript" src= "//ajax.googleapis.com/ajax/libs/jquery/1.7.2/jquery.min.js">
</script>
</body>
</html>

```

## 刚刚发生了什么？

我们只是在`layout.php`文件的`body`标记的末尾之前添加了一行代码。这就是使用 jQuery 与我们的项目所需的全部！您可能想知道为什么我们决定将我们的 jQuery 库放在文件的底部。最简单的解释是，当浏览器加载代码时，它会逐行加载。通过将 JavaScript 放在页面底部，它可以更快地加载其他元素，例如 CSS 和 HTML 标记，从而给用户一种快速加载的印象。

# 行动时间-创建 master.js 并连接 Boostrap 的 JavaScript 文件

随着我们的应用程序的增长，我们希望能够将我们的 JavaScript 添加到外部文件中。让我们创建一个名为`master.js`的文件，它将保存我们应用程序的所有 JavaScript，然后连接我们在第六章中下载的 Bootstrap 的 JavaScript 文件，*建模用户*。

1.  在`public/js`文件夹中创建一个名为`master.js`的新文件。

1.  打开`layout.php`文件，并在`body`部分的末尾之前添加以下代码：

```php
<script type="text/javascript" src= "//ajax.googleapis.com/ajax/libs/jquery /1.7.2/jquery.min.js">
**<script type="text/javascript" src= "//ajax.googleapis.com/ajax/libs/jquery /1.7.2/jquery.min.js">
</script>
<script type="text/javascript" src="<?php echo $this- >make_route('/js/bootstrap.min.js') ?>">
</script>
<script type="text/javascript" src="<?php echo $this- >make_route('/js/master.js') ?>">
</script>** 
</body>
</html>

```

## 刚刚发生了什么？

我们创建了一个名为`master.js`的空文件，这是我们应用程序的所有 JavaScript 将存储的地方。接下来，我们再次调整了我们的`layout.php`文件，允许我们包括我们在第六章中下载的`boostrap.min.js`文件，以及我们新创建的`master.js`文件。

### 注意

在编写 JavaScript 时，加载文件的顺序很重要。在本章后面编写 jQuery 时，对于我们的浏览器首先加载 jQuery 文件很重要，这样它就知道 jQuery 是什么以及语法是如何工作的。

# 使用 jQuery 改进我们的网站

现在我们有了 jQuery，让我们立即使用它来稍微改进我们的网站。您可以以许多不同的方式编写 jQuery 和 JavaScript 代码，但是在本书中，我们将坚持绝对基础知识，并尽量保持简单。

## 修复我们的删除帖子操作以实际使用 HTTP 删除

你可能已经在上一章的早期注意到的一件事是，当我们从用户的个人资料中编写帖子删除时，我们实际上使用了`GET HTTP`方法而不是`DELETE`方法。这是因为很难触发`DELETE`路由而不使用 JavaScript。因此，在接下来的部分中，我们将改进删除过程，使其按照以下方式工作：

1.  用户点击帖子上的“删除”。

1.  从 jQuery 到我们的应用程序发出了一个`DELETE AJAX`请求。

1.  我们的应用程序将删除帖子文档，并向 jQuery 报告一切都如预期般进行。

1.  帖子将从视图中淡出，而无需用户刷新页面。

这将是对我们用户资料的一个很好的改进，因为我们不需要每次执行操作时重新加载页面。

# 行动时间-通过使用 AJAX 删除帖子来改善我们的用户体验

让我们通过向我们的`master.js`文件添加一些代码，使我们能够使用 JavaScript 删除帖子，来初步了解一下 jQuery。如果 jQuery 的语法一开始对您不太熟悉，请不要感到不知所措；坚持下去，我相信您会对结果感到非常满意。

1.  打开`public/js/master.js`，确保 jQuery 代码在页面加载完成后运行，通过在我们的文件中添加`$(document).ready`事件。这段代码意味着一旦页面加载完成，此函数内的任何 JavaScript 代码都将运行：

```php
$(document).ready(function() {
});

```

1.  现在，让我们添加一个事件，将`click`事件绑定到我们 HTML 中具有`delete`类的任何按钮。`function(event)`括号内的所有代码将在每次点击我们的删除帖子按钮时运行：

```php
$(document).ready(function() {
**$('.delete').bind('click', function(event){** 
});
});

```

1.  让我们阻止链接像通常情况下那样将我们带到新页面，使用一个叫做`event.preventDefault()`的代码。然后，让我们将点击链接的`href`属性保存到一个叫做`location`的变量中，这样我们就可以在我们的 AJAX 调用中使用它：

```php
$(document).ready(function() {
$('.delete').bind( 'click', function(event){
**event.preventDefault();
var location = $(this).attr('href');** 
});
});

```

1.  最后，让我们创建一个基本的 AJAX 请求，将调用我们的应用程序并为我们删除帖子：

```php
$(document).ready(function() {
$('.delete').bind( 'click', function(){
event.preventDefault();
var location = $(this).attr('href');
**$.ajax({
type: 'DELETE',
url: location,
context: $(this),
success: function(){
$(this).parent().parent().fadeOut();
},
error: function (request, status, error) {
alert('An error occurred, please try again.'); }
});** 
});
});

```

## 刚刚发生了什么？

我们刚刚学会了如何在几行代码中使用 JavaScript 进行 AJAX 请求。我们首先将我们的代码包装在一个`$(document).ready`函数中，该函数在页面完全加载后运行。然后，我们添加了一个捕获我们应用程序中任何`删除帖子`链接点击的函数。最后，脚本中最复杂的部分是我们的 AJAX 调用。让我们通过一点来讨论一下，以便它有意义。jQuery 有一个名为`$.ajax`的函数，它有各种选项（所有选项都可以在这里查看：[`api.jquery.com/jQuery.ajax/)`](http://api.jquery.com/jQuery.ajax/)）。让我们逐个讨论我之前给出的代码片段中使用的每个选项，并确保您知道它们的含义。

+   `type: 'DELETE'`表示我们要使用`DELETE HTTP`方法进行请求。

+   `url: location`表示我们将使用点击链接的`href`属性进行请求。这将确保正确的帖子被删除。

+   `context: $(this)`是将用于所有 AJAX 回调的对象。因此，在此示例中，此调用的`success`选项中的所有代码将使用点击链接作为所有调用的上下文。

+   `success: function()`在我们的 AJAX 请求完成时调用。我们将以下代码放在此函数中：`$(this).parent().parent().fadeOut()`；这意味着我们将从点击链接的两个 HTML 级别向上查找。这意味着我们将查找帖子的`<div class="post-item row">`，然后将其淡出视图。

+   `error: function (request, status, error)`在您的代码中发生错误时运行。现在，我们只是显示一个警报框，这不是最优雅的方法，特别是因为我们没有提供发生了什么的细节给用户。这暂时对我们有效，但如果您想要一些额外的分数，可以尝试一下这个函数，看看是否可以使它更加优雅。

太棒了！我们刚刚添加了一些代码，这将真正改善用户的体验。随着您的应用程序的增长，并且您为其添加更多功能，请确保牢记 jQuery 的`AJAX`方法，这肯定会让事情变得更容易。

### 更新我们的路由以使用 DELETE HTTP 方法

现在我们正确地使用`DELETE`作为我们的 AJAX 调用的`HTTP`方法，我们需要更新我们的路由，这样我们的代码就知道如何处理路由了。

1.  打开`index.php`，查找我们在上一章中创建的`post/delete/:id/:rev`路由：

```php
get('/post/delete/:id/:rev', function($app) {
$post = new Post();
$post->_id = $app->request('id');
$post->_rev = $app->request('rev');
$post->delete();
$app->set('success', 'Your post has been deleted');
$app->redirect('/user/' . User::current_user());
});

```

1.  让我们通过将`get`更改为`delete`来更改路由以使用`delete`方法。然后，删除`success`变量和重定向代码，因为我们将不再需要它们：

```php
delete('/post/delete/:id/:rev', function($app) {
$post = new Post();
$post->_id = $app->request('id');
$post->_rev = $app->request('rev');
$post->delete();
});

```

#### 让我们来测试一下！

在测试这个功能时，确保停下来欣赏所有技术的协同工作，以解决一个相当复杂的问题。

1.  转到`http://localhost/verge/login`，并以`johndoe`的身份登录应用程序。

1.  单击“我的个人资料”。

1.  单击您的帖子旁边的“(删除)”。

1.  删除的帖子将从视图中消失，其他帖子将在页面上升。

# 使用 jQuery 添加简单的分页

随着我们的应用程序的增长，帖子将开始填满用户的个人资料。如果我们的应用程序变得成功，并且人们开始使用它，会发生什么？每次加载页面时，将打印数百个帖子到个人资料视图中。这样的情况绝对会使您的应用程序陷入瘫痪。

考虑到这一点，我们将在我们的个人资料页面上创建一些分页。我们的简单分页系统将按以下方式工作：

1.  默认情况下，我们将在页面上显示 10 个帖子。当用户想要查看更多时，他们将单击“加载更多”链接。

1.  当单击“显示更多”链接时，jQuery 将找出要跳过多少项，并告诉 Bones 要检索哪些文档。

1.  Bones 将使用 Sag 调用 CouchDB，并通过`posts_by_user`视图获取更多帖子。

1.  Bones 将结果加载到包含我们帖子需要格式化的 HTML 布局的部分视图中。这个 HTML 将返回给 jQuery 在我们的页面上显示。

这里有很多事情要做，但这种功能在大多数应用程序中都很常见。所以，让我们跳进去，看看我们是否能把这一切都拼凑起来。

# 采取行动-将帖子从 profile.php 中取出并放入它们自己的部分视图

列出帖子的代码直接位于`profile.php`页面内，这在目前为止都还好。然而，在某一时刻，我们将希望能够通过`Javascript`回调显示帖子，如果我们不小心，这可能意味着重复的代码或不一致的布局。让我们通过将我们的代码移动到一个可以轻松重用的部分视图中来保护自己。

1.  在 views/user 中创建一个名为`_posts.php`的新文件。

1.  复制并粘贴从`views/user/profile.php`列出帖子的`foreach`代码，并将其粘贴到我们的新文件`_posts.php`中。`_posts.php`的最终结果应该如下所示：

```php
<?php foreach ($posts as $post): ?>
<div class="post-item row">
<div class="span7">
<strong><?php echo $user->name; ?></strong>
<p>
<?php echo $post->content; ?>
</p>
<?php echo $post->date_created; ?>
</div>
<div class="span1">
<?php if ($is_current_user) { ?>
<a href="<?php echo $this->make_route('/post/delete/' . $post->_id . '/' . $post->_rev)?>" class="delete">
(Delete)
</a>
<?php } ?>
</div>
<div class="span8"></div>
</div>
<?php endforeach; ?>

```

1.  现在，让我们从`views/user/profile.php`中删除相同的`foreach`语句，并将其替换为对新创建的`_posts`文件的`include`调用。然后让我们在我们的列表的`h2`元素内添加一个`span`，这样我们就可以很容易地通过 jQuery 访问它。

```php
**<h2>
Posts (<span id="post_count"><?php echo $post_count; ?></span>)
</h2>
<div id="post_list">
<?php include('_posts.php'); ?>
</div>** 

```

## 刚刚发生了什么？

我们将`profile.php`中列出的所有帖子的代码移到了一个名为`_posts.php`的新部分中。我们在文件名前加上下划线，没有其他原因，只是为了让我们在查看源代码时知道它与普通视图不同。所谓的部分视图，是指它是要加载到另一个页面中的，单独存在时可能没有任何作用。在表面上，我们的应用程序将与我们将代码移动到部分视图之前完全相同。

然后我们修改了`profile.php`中的代码，以便使用 jQuery 更容易。我们在`h2`元素内添加了一个 ID 为`post_count`的`span`元素。这个`span`元素只包含总帖子数。我们很快就会用到它，以便告诉我们是否已经将我们需要的所有帖子加载到我们的列表中。然后我们用 ID 为`post_list`的`div`包装了我们的帖子列表。我们将使用这个标识符来从我们的分页控件中将新帖子追加到列表中。

## 为分页添加后端支持

我们不需要另一个用于分页的函数。让我们只是改进`Post`类的`get_posts_by_user`函数。我们只需要添加`skip`和`limit`选项，然后将它们传递给 CouchDB 中的`posts_by_user`视图。将`skip`传递给此视图将使我们能够跳过结果中的某些记录，而`limit`将允许我们一次只显示一定数量的帖子。通过结合这两个变量，我们将支持分页！

# 行动时间——调整我们的 get_posts_by_user 函数以跳过和限制帖子

既然我们知道该怎么做，让我们立即进入编辑`classes/post.php`文件，并调整我们的`get_posts_by_user`函数，以便我们可以将`$skip`和`$limit`作为参数添加进去。

1.  通过打开名为`classes/post.php`的文件来打开`Post`类。

1.  找到我们的`get_posts_by_user`函数，并添加带有默认值`0`的`$skip`和带有默认值`10`的`$limit`。

```php
**public function get_posts_by_user($username, $skip = 0, $limit = 10) {** 
$bones = new Bones();
$posts = array();
...
}

```

1.  更新我们对 Sag 的`get`调用，以便将`$skip`和`$limit`的值传递给查询。

```php
public function get_posts_by_user($username, $skip = 0, $limit = 10) {
$bones = new Bones();
$posts = array();
**foreach ($bones->couch-> get('_design/application/_view/posts_by_user?key="' . $username . '"&descending=true&reduce=false&skip=' . $skip . '&limit=' . $limit)->body->rows as $_post) {** 
...
}

```

1.  现在我们已经更新了我们的函数以包括`skip`和`limit`，让我们在`index.php`中创建一个类似于`user/:username`路由的新路由，但是接受`skip`的路由变量来驱动分页。在这个路由中，我们将返回部分`_posts`，而不是整个布局：

```php
get('/user/:username/:skip', function($app) {
$app->set('user', User::get_by_username($app-> request('username')));
$app->set('is_current_user', ($app->request('username') == User::current_user() ? true : false));
$app->set('posts', Post::get_posts_by_user($app-> request('username'), $app->request('skip')));
$app->set('post_count', Post::get_post_count_by_user($app-> request('username')));
$app->render('user/_posts', false);
});

```

## 刚刚发生了什么？

我们刚刚为`get_posts_by_user`函数添加了额外的`$skip`和`$limit`选项。我们还设置了当前调用，使其在不更改任何内容的情况下也能正常运行，因为我们为每个变量设置了默认值。我们现有的用户资料中的调用现在也将显示前 10 篇文章。

然后我们创建了一个名为`/user/:username/:skip`的新路由，其中`skip`是我们在查询时要跳过的项目数。这个函数中的其他所有内容与`/user/:username`路由中的内容完全相同，只是我们将结果返回到我们的部分中，并且布局为`false`，因此没有布局包装。我们这样做是为了让 jQuery 可以调用这个路由，它将简单地返回需要添加到页面末尾的帖子列表。

### 让我们来测试一下！

通过直接通过浏览器玩弄它来确保我们的`/user/:username/:skip`路由按预期工作。

1.  前往`http://localhost/verge/user/johndoe/0`（或任何有相当数量帖子的用户）。

1.  您的浏览器将使用`views/user/_posts.php`作为模板返回一个大的帖子列表。请注意，它显示了 10 篇总帖子，从最近的帖子开始。让我们来测试一下！

1.  现在，让我们尝试跳过前 10 篇文章（就像我们的分页器最终会做的那样），并通过访问`http://localhost/verge/user/johndoe/10`来检索接下来的 10 篇文章！让我们来测试一下！

1.  我们的代码希望能够很好地工作。我在这个帐户上只有 12 篇帖子，所以这个视图跳过了前 10 篇帖子，显示了最后两篇。

这一切都按我们的预期进行，但是我们的代码还有一些清理工作要做。

# 行动时间-重构我们的代码，使其不冗余

虽然我们的代码运行良好，但您可能已经注意到我们在`/user/:username`和`/user/:username/:skip`中有几乎相同的代码。我们可以通过将所有冗余代码移动到一个函数中并从每个路由中调用它来减少代码膨胀。让我们这样做，以便保持我们的代码整洁的习惯。

1.  打开`index.php`，并创建一个名为`get_user_profile`的函数，它以`$app`作为参数，并将其放在`/user/:username`路由的上方。

```php
function get_user_profile($app) {
}

```

1.  将`/user/:username/:skip`中的代码复制到此函数中。但是，这一次，我们不仅仅`传递$app->request('skip')`，让我们检查它是否存在。如果存在，让我们将其传递给`get_posts_by_user`函数。如果不存在，我们将只传递`0`。

```php
function get_user_profile($app) {
**$app->set('user', User::get_by_username($app-> request('username')));
$app->set('is_current_user', ($app->request('username') == User::current_user() ? true : false));
$app->set('posts', Post::get_posts_by_user($app-> request('username'), ($app->request('skip') ? $app-> request('skip') : 0)));
$app->set('post_count', Post::get_post_count_by_user($app-> request('username')));
}** 

```

1.  最后，让我们清理我们的两个 profile 函数，使它们都只调用`get_user_profile`函数。

```php
get('/user/:username', function($app) {
**get_user_profile($app);** 
$app->render('user/profile');
});
get('/user/:username/:skip', function($app) {
**get_user_profile($app);** 
$app->render('user/_posts', false);
});

```

## 刚刚发生了什么？

我们通过将大部分逻辑移动到一个名为`get_user_profile`的新函数中，简化了用户配置文件路由。两个路由之间唯一不同的功能是`request`变量`skip`。因此，我们在对`Posts::get_posts_by_user`函数的调用中放置了一个快捷的`if`语句，如果存在`skip`请求变量，就会传递`skip`请求变量；但如果不存在，我们将只传递`0`。添加这个小功能片段使我们能够在两个不同的路由中使用相同的代码。最后，我们将全新的函数插入到我们的路由中，并准备享受代码的简洁。一切仍然与以前一样工作，但现在更容易阅读，并且将来更新也更容易。

重构和持续清理代码是开发过程中要遵循的重要流程；以后你会为自己做这些而感激的！

# 行动时间-为分页添加前端支持

我们几乎已经完全支持分页。现在我们只需要向我们的项目添加一点 HTML 和 JavaScript，我们就会有一个很好的体验。

1.  让我们从`master.css`文件中添加一行 CSS，这样我们的**加载更多**按钮看起来会很漂亮。

```php
#load_more a {padding: 10px 0 10px 0; display: block; text-align: center; background: #e4e4e4; cursor: pointer;}

```

1.  现在我们已经有了 CSS，让我们在`profile.php`视图中的`post`列表底部添加我们的**加载更多**按钮的 HTML。

```php
<h2>
Posts (<span id="post_count"><?php echo $post_count; ?></span>)
</h2>
<div id="post_list">
<?php include('_posts.php'); ?>
</div>
**<div id="load_more" class="row">
<div class="span8">
<a id="more_posts" href="#">Load More...</a>
</div>
</div>**

```

1.  现在，让我们打开`master.js`，并在`$(document).ready`函数的闭合括号内创建一个函数。这个函数将针对 ID 为`more_posts`的任何元素的`click`事件。

```php
**$('#more_posts').bind( 'click', function(event){
event.preventDefault();
});** 
});

```

1.  为了调用`/user/:username/:skip`路由，我们需要使用一个名为`window.location.pathname`的 JavaScript 函数来获取页面的当前 URL。然后，我们将在字符串的末尾添加帖子项目的数量，以便跳过当前页面上显示的帖子数量。

```php
$('#more_posts').bind( 'click', function(event){
event.preventDefault();
**var location = window.location.pathname + "/" + $('.post-item') .size();** 
});

```

1.  现在我们已经有了位置，让我们填写剩下的 AJAX 调用。这一次，我们将使用`GET HTTP`方法，并使用 ID 为`post_list`的帖子列表作为我们的上下文，这将允许我们在`success`事件中引用它。然后，让我们只添加一个通用的`error`事件，以便在发生错误时通知用户发生了错误。

```php
$('#more_posts').bind( 'click', function(event){
event.preventDefault();
var location = window.location.pathname + "/" + $('#post_list').children().size();
**$.ajax({
type: 'GET',
url: location,
context: $('#post_list'),
success: function(html){
// we'll fill this in, in just one second
},
error: function (request, status, error) {
alert('An error occurred, please try again.');
}
});** 
});

```

1.  最后，让我们用一些代码填充我们的`success`函数，将从我们的 AJAX 调用返回的 HTML 附加到`post_list div`的末尾。然后，我们将检查是否有其他帖子要加载。如果没有更多帖子要加载，我们将隐藏**加载更多**按钮。为了获取帖子数量，我们将查看我们使用`post_count`作为 ID 创建的`span`，并使用`parseInt`将其转换为整数。

```php
$('#more_posts').bind( 'click', function(event){
event.preventDefault();
var location = window.location.pathname + "/" + $('#post_list').children().size();
$.ajax({
type: 'GET',
url: location,
context: $('#post_list'),
success: function(html){
**$(this).append(html);
if ($('#post_list').children().size() <= " parseInt($('#post_count').text())) {
$('#load_more').hide();
}** 
},
error: function (request, status, error) {
alert('An error occurred, please try again.');
}
});
});

```

## 刚刚发生了什么？

在这一部分，我们完成了分页！我们首先创建了一个快速的 CSS 规则，用于我们的**加载更多**链接，使其看起来更友好，并添加了在个人资料页面上出现所需的 HTML。我们通过调用一个 AJAX 函数到当前用户个人资料的 URL，并将当前存在的帖子数量附加到`#post_list div`中来完成分页。通过将这个数字传递给我们的路由，我们告诉我们的路由将这个数字传递并忽略所有这些项目，因为我们已经显示了它们。

接下来，我们添加了一个`success`函数，使用`_posts`部分的布局返回我们路由的 HTML。这个 HTML 将被附加到`#post_list div`的末尾。最后，我们检查了是否有更多的项目要加载，通过比较`#post_list`的大小与我们的`reduce`函数返回到我们个人资料顶部的帖子数量`#post_count span`。如果这两个值相等，这意味着没有更多的帖子可以加载，我们可以安全地隐藏**加载更多**链接。

# 行动时间-修复我们的删除帖子功能以适应分页

当我们添加分页时，我们还破坏了通过 AJAX 加载的帖子的删除功能。这是因为我们使用`bind`事件处理程序将`click`事件绑定到我们的链接，这只会在页面加载时发生。因此，我们需要考虑通过 AJAX 加载的链接。幸运的是，我们可以使用 jQuery 的`live`事件处理程序来做到这一点。

1.  打开`master.js`，并将`delete`帖子代码更改为使用`live`而不是`bind`：

```php
**$('.delete').live( 'click', function(event){** 
event.preventDefault();
var location = $(this).attr('href');

```

1.  如果您开始删除帖子列表中的一堆项目，它目前不会使用 JavaScript 更改与用户帐户相关联的帖子数量。在这里，让我们修改`success`函数，以便它还更新我们帖子列表顶部的帖子数量：

```php
$('.delete').live( 'click', function(event){
event.preventDefault();
var location = $(this).attr('href');
$.ajax({
type: 'DELETE',
url: location,
context: $(this),
success: function(html){
$(this).parent().parent().parent().fadeOut();
**$('#post_count').text(parseInt($('#post_count').text()) - 1);** 
},
error: function (request, status, error) {
alert('An error occurred, please try again.');
}
});
});

```

## 刚刚发生了什么？

我们刚刚更新了我们的删除按钮，使用`live`事件处理程序而不是`bind`事件处理程序。通过使用`live`，jQuery 允许我们定义一个选择器，并将规则应用于所有当前和将来匹配该选择器的项目。然后，我们使我们的`#post_count`元素动态化，以便每次删除帖子时，帖子计数相应地更改。

### 测试我们完整的分页系统

我们的分页最终完成了。让我们回去测试一切，确保分页按预期工作。

1.  转到`http://localhost/verge/login`，并以`johndoe`的身份登录应用程序。

1.  点击**我的个人资料**。

1.  滚动到页面底部，点击**加载更多**。接下来的 10 篇帖子将返回给你。

1.  如果您的帐户中帖子少于 20 篇，**加载更多**按钮将从页面中消失，向您显示您已经加载了所有帖子。

1.  尝试点击通过 AJAX 加载的列表中的最后一篇帖子，它将消失，就像应该的那样！

太棒了！我们的分页系统正如我们所希望的那样工作；我们能够删除帖子，我们的帖子计数每次删除帖子时都会更新。

# 使用 Gravatars

在这一点上，我们的个人资料看起来有点无聊，只有一堆文本，因为我们没有支持将图像上传到我们的系统中。出于时间考虑，我们将在本书中避免这个话题，也是为了我们用户的利益。让用户每次加入服务时都上传新的个人资料图像存在相当大的摩擦。相反，有一个服务可以让我们的生活变得更轻松：**Gravatar**（[`www.gravatar.com`](http://www.gravatar.com)）。Gravatar 是一个网络服务，允许用户将个人资料图像上传到一个单一位置。从那里，其他应用程序可以使用用户的电子邮件地址作为图像的标识符来获取个人资料图像。

# 行动时间-向我们的应用程序添加 Gravatars

通过我们的用户类添加对 Gravatars 的支持就像添加几行代码一样简单。之后，我们将在我们的应用程序中添加`gravatar`函数。

1.  打开`user/profile.php`，并添加一个名为`gravatar`的`public`函数，它接受一个名为 size 的参数；我们将给它一个默认值`50`。

```php
public function gravatar($size='50') {
}

```

1.  为了获取用户的 Gravatar，我们只需要创建用户电子邮件地址的`md5`哈希，这将作为`gravatar_id`。然后，我们使用我们的`$size`变量设置大小，并将所有这些附加到 Gravatar 的网络服务 URL。

```php
public function gravatar($size='50') {
return 'http://www.gravatar.com/avatar/?gravatar_id=' .md5(strtolower($this->email)).'&size='.$size;
}

```

1.  就是这样！我们现在在我们的应用程序中有了 Gravatar 支持。我们只需要在任何我们想要看到个人资料图片的地方开始添加它。让我们首先在`views/user/profile.php`文件的**用户信息**部分顶部添加一个大的 Gravatar。

```php
<div class="span4">
<div class="well sidebar-nav">
<ul class="nav nav-list">
<li><h3>User Information</h3></li>
**<li><img src="<?php echo $user->gravatar('100'); ?>" /></li>** 
<li><b>Username:</b> <?php echo $user->name; ?></li>
<li><b>Email:</b> <?php echo $user->email; ?></li>
</ul>
</div>
</div>

```

1.  接下来，让我们更新`views/user/_posts.php`文件中的帖子列表，这样我们就可以很好地显示我们的 Gravatars。

```php
<?php foreach ($posts as $post): ?>
<div class="post-item row">
**<div class="span7">
<div class="span1">
<img src="<?php echo $user->gravatar('50'); ?>" />
</div>
<div class="span5">
<strong><?php echo $user->name; ?></strong>
<p>
<?php echo $post->content; ?>
</p>
<?php echo $post->date_created; ?>
</div>
</div>** 
<div class="span1">
<?php if ($is_current_user) { ?>
<a href="<?php echo $this->make_route('/post/delete/' . $post->_id . '/' . $post->_rev)?>" class="deletes">(Delete)</a>
<?php } ?>
</div>
<div class="span8"></div>
</div>
<?php endforeach; ?>

```

## 刚刚发生了什么？

我们在我们的`User`类中添加了一个名为`gravatar`的函数，它接受一个名为`$size`的参数，默认值为 50。从那里，我们对对象的电子邮件地址和`$size`进行了`md5`哈希，并将其附加到 Gravatar 的网络服务的末尾。结果是一个链接到一个漂亮且易于显示的 Gravatar 图像。

有了我们的 Gravatar 系统，我们将它添加到了`views/user/profile.php`和`views/user/_posts.php`页面中。

## 测试我们的 Gravatars

我们的 Gravatars 应该在我们的个人资料页面上运行。如果用户的电子邮件地址没有关联的图像，将显示一个简单的占位图像。

1.  转到`http://localhost/user/johndoe`，你会在每篇帖子和**用户信息**部分看到 Gravatar 的占位符。![测试我们的 Gravatars](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_09_025.jpg)

1.  现在，让我们通过访问[`www.gravatar.com`](http://www.%20gravatar.com)并点击**注册**来将 Gravatar 与你的电子邮件关联起来。![测试我们的 Gravatars](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_09_030.jpg)

1.  输入你的电子邮件，然后点击**注册**。你将收到一封验证邮件到你的地址，所以去检查一下，然后点击激活链接。![测试我们的 Gravatars](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_09_035.jpg)

1.  接下来，你将被带到一个页面，显示你当前的账户和与你的账户关联的图像。你还没有任何与你的账户关联的东西，所以点击**点击这里添加一个！**![测试我们的 Gravatars](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_09_040.jpg)

1.  在你上传了图像到账户并添加了你想要使用的任何电子邮件地址之后，你可以回到与你的电子邮件地址关联的个人资料（对我来说是`http://localhost/user/tim`），你将看到一个 Gravatar！![测试我们的 Gravatars](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_09_045.jpg)

## 将所有内容添加到 Git

我希望在本章的过程中，你已经将你的代码提交到了 Git；如果你还没有，这是提醒你。确保及早并经常这样做！

# 总结

希望你喜欢这一章！虽然这些功能对我们的应用程序的工作并不是“使命关键”的功能，但随着应用程序的发展，这些是用户会要求的功能。

具体来说，我们学会了如何安装 jQuery 并使用它来帮助创建一些基本的 JavaScript，并用它来使帖子的删除和分页更加清晰。接下来，我们添加了 Gravatar 图像到个人资料和帖子列表中，使我们的个人资料更加有趣。

就是这样！我们的应用程序已经准备好投入使用。在下一章中，我们将保护应用程序的最后部分并部署所有内容，这样世界就可以看到你所建立的东西。


# 第十章：部署您的应用程序

> 在我们的应用程序上线并准备好供用户注册并创建帖子之前，我们还有一些步骤要完成。

在本章中，我们将做以下事情来让我们的应用程序运行起来：

+   我们将在 Cloudant 上建立一个帐户，用于存放我们应用的 CouchDB 数据库，并为我们的应用做好准备

+   我们将在我们的项目中添加一个配置类，使用环境变量来驱动我们应用程序的设置

+   我们将创建一个 PHP Fog 帐户来托管我们的应用程序

+   我们将配置 Git 连接到 PHP Fog 的 Git 存储库并部署我们的应用程序

正如您可能期望的那样，在本章中，我们将进行大量的帐户设置和代码调整。

# 在我们开始之前

对于任何应用程序或数据库部署，都有各种各样的选择。每个选项都有其优势和劣势。我想给你一些知识，而不是立即设置服务，以防有一天你想改用其他服务。

在过去的几年里，云已经成为技术行业中最常用和滥用的术语之一。要完全理解云这个术语，您需要阅读大量的研究论文和文章。但是，简单来说，云这个术语描述了从传统的单租户专用托管转变为可扩展的多租户和多平台主机。CouchDB 本身就是一个可扩展的数据库的完美例子，可以实现云架构。我们的应用程序也是云解决方案的一个很好的候选，因为我们没有本地存储任何东西，也没有任何特殊的依赖。

考虑到这一点，我们将使用云服务来托管我们的应用程序和数据库。其中一个额外的好处是，我们将能够让我们的应用程序免费运行，并且只有在我们的应用程序成功后才需要开始付费。这一点真的不错！

让我们快速讨论一下我们将如何处理我们的应用程序和 CouchDB 托管以及我们可用的选项。

## 应用程序托管

在云中托管 Web 应用程序时，有无数种方法可以实现。由于我们不是服务器设置专家，我们希望使用一种设置较少但回报较高的系统。考虑到这一点，我们将使用**平台即服务（PaaS）**。有很多 PaaS 解决方案，但目前，对于 PHP 开发人员来说，最好的选择是 Heroku 和 PHP Fog。

**Heroku** ([`www.heroku.com`](http://www.heroku.com)) 是将 PaaS 推向聚光灯下的创新者。他们使用 Cedar 堆栈支持 PHP 应用程序。但是，由于它不是一个特定于 PHP 的堆栈，对于我们来说，可能更明智选择另一个提供商。

**PHP Fog** ([`www.phpfog.com`](http://www.phpfog.com)) 在我看来，是一个非常专注于 PHP 开发的 PaaS，因为他们非常专注于 PHP。他们支持各种 PHP 应用框架，提供 MySQL 托管（如果您的应用需要），总体上，他们致力于为 PHP 开发人员提供一个稳固的开发环境。

考虑到这一切，PHP Fog 将是我们选择的应用托管解决方案。

## CouchDB 托管

与应用程序托管相比，CouchDB 托管的解决方案要少得多，但幸运的是，它们都是非常稳固的产品。我们将讨论的两种服务是 Cloudant 和 IrisCouch。

**Cloudant** ([`www.cloudant.com`](http://www.cloudant.com)) 是云中 CouchDB 最强大的解决方案之一。他们提供了我们在本书中使用过的熟悉工具，如 Futon 和命令行，还能够根据数据增长的需要进行扩展。Cloudant 特别独特的地方在于，当你的应用程序需要一些特殊功能时，他们提供定制解决方案，而且 Cloudant 是 CouchDB 本身的主要贡献者之一。

**Iris Couch** ([`www.iriscouch.com`](http://www.iriscouch.com)) 也允许在云中免费托管 CouchDB。不幸的是，他们刚刚开始提供 Couchbase 服务器作为他们的基础设施，这是建立在 CouchDB 核心之上的。虽然我非常喜欢 Couchbase 及其对核心 CouchDB 技术的增强，但我们的任务是在本书中只使用 CouchDB。但是，如果你将来需要 Couchbase 的增强功能，那么值得考虑一下 Iris Couch。

因为我以前使用过 Cloudant 并知道它能处理什么，我们将在这个项目中使用它。

总的来说，本章中我们将执行的设置与其他竞争性服务相对类似。因此，如果你决定以后转换，你应该能够很好地处理它，而不会有太多问题。

# 使用 Cloudant 进行数据库托管

在本节中，我们将设置一个 Cloudant 服务器，并准备让我们的应用程序连接到它。需要做的设置很少，而且希望这些步骤对我们在本书初期设置 CouchDB 数据库时所采取的步骤来说是熟悉的。

## 开始使用 Cloudant

创建 Cloudant 账户非常简单，但让我们一起走一遍，以确保我们都在同一页面上。

1.  首先去[`cloudant.com/sign-up/`](http://https://cloudant.com/sign-up/)，你会看到注册页面。![开始使用 Cloudant](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_10_005.jpg)

1.  Cloudant 只需要一些基本信息来创建你的账户。首先输入一个用户名。这将被用作你的唯一标识符和你的 Cloudant 账户的链接。我建议选择像你的名字或公司名这样的东西。

1.  填写页面上的其余信息，当你准备好时，点击页面底部的注册按钮！

你已经完成了，现在你应该看到你的 Cloudant 仪表板。从这里，你可以管理你的账户并创建新的数据库。

![开始使用 Cloudant](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_10_020.jpg)

## 创建一个 _users 数据库

现在我们有了全新的 Cloudant 账户，但我们还没有任何数据库。更糟糕的是，我们甚至还没有我们的`_users`数据库。我们只需要创建一个新的`_users`数据库，Cloudant 会处理剩下的。我们技术上可以通过 Cloudant 的界面完成这个过程，但让我们使用命令行，因为它更加通用。

1.  打开终端。

1.  运行以下命令，并替换两个用户名和一个密码的实例，这样 Cloudant 就知道你是谁以及你要使用的账户是什么：

```php
**curl -X PUT https://username:password@username.cloudant.com/_users** 

```

终端会通过返回成功消息来告诉你数据库已经创建：

```php
**{"ok":true}** 

```

太棒了！你的`_users`数据库现在已经创建。记住，我们还需要另一个叫做`verge`的数据库来存储我们的所有数据。让我们接下来创建`verge`数据库。

## 创建一个 verge 数据库

你需要在你的账户中创建另一个数据库，这次叫做`verge`。

## 来吧，英雄——自己试试看

现在，你应该很容易自己创建另一个数据库。按照我们创建`_users`数据库时所采取的相同步骤来尝试一下，但是将数据库名称改为`verge`。

如果你感到困惑，我马上会向你展示命令行语句。好的，进行得怎么样？让我们回顾一下创建`verge`数据库所需执行的步骤。

1.  打开终端。

1.  你应该运行以下命令，并替换两个用户名实例和一个密码实例，这样 Cloudant 就会知道你是谁，以及你要使用的账户是什么：

```php
**curl -X PUT https://username:password@username.cloudant.com/verge** 

```

当你看到一个熟悉的成功消息时，终端应该已经让你放心一切都进行得很顺利，如下所示：

```php
**{"ok":true}** 

```

## 在 Cloudant 上使用 Futon

通过命令行管理内容可能有点繁琐。幸运的是，Cloudant 还带来了我们的老朋友——Futon。要在 Cloudant 上使用 Futon，按照以下步骤进行：

1.  登录，并转到你的仪表板。![在 Cloudant 上使用 Futon](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_10_025.jpg)

1.  点击你的数据库名称之一；在这个例子中，让我们使用`verge`。![在 Cloudant 上使用 Futon](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_10_030.jpg)

+   这是数据库详细页面——当文档出现在你的数据库中时，它们将显示在这个页面上。

1.  点击 Futon 中的查看按钮继续。

看起来熟悉吗？这就是我们在本地一直在使用的伟大的 Futon。

![在 Cloudant 上使用 Futon](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_10_032.jpg)

## 配置权限

现在我们的生产数据库已经上线，非常重要的是我们要配置权限以在我们的生产服务器上运行。如果我们不保护我们的数据库，那么我们的用户很容易就能读取，这是我们不想卷入的事情。

幸运的是，Cloudant 已经为我们解决了所有这些问题，具体做法如下：

+   因为我们已经创建了一个账户，数据库不再处于`Admin Party`模式

+   默认情况下，Cloudant 使`_users`数据库对我们的`admin`账户可管理，但其他账户无法访问它

我们很幸运，Cloudant 一直支持我们！但是，如果你决定自己部署 CouchDB 实例，一定要回头看看第三章，“使用 CouchDB 和 Futon 入门”，并按照我们用来保护本地环境的步骤进行操作。

然而，我们需要更新我们的`verge`数据库，以便用户可以在该数据库中读取、创建和写入。

1.  登录到你的 Cloudant 账户，并转到你的仪表板。[`cloudant.com/#!/dashboard`](http://https://cloudant.com/#!/dashboard)。

1.  点击`verge`数据库。

1.  点击**权限**来管理数据库权限。

1.  通过选中**读取、创建**和**写入**下的复选框来更新**其他人**的**权限**。确保不要选中**管理员**，这样普通用户就无法更改我们的数据库结构和设计文档。最终结果应该类似于以下截图：![配置权限](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_10_035.jpg)

# 配置我们的项目

现在我们已经设置好了我们的生产数据库，我们的代码需要知道如何连接到它。我们可以只是修改我们在`Bones`库中硬编码的值，每次想要在本地开发或部署到生产环境时来回更改。但是，请相信我，你不想经历这样的麻烦，更重要的是，我们不想在我们的代码中存储任何用户名或密码；为此，我们将使用环境变量。**环境变量**是一组动态命名的值，允许你从应用程序的托管环境中定义变量。让我们创建一个类，使我们能够使用环境变量，这样我们的代码就不会包含敏感信息，我们的应用程序也容易配置。

# 行动时间——创建一个配置类

由于我们迄今为止编写的代码，插入一个简单的配置类实际上对我们来说非常容易。让我们一起来创建它。

1.  首先在我们的`lib`文件夹内创建一个名为`configuration.php`的新配置文件（`lib/configuration.php`）。

1.  现在，让我们为名为`Configuration`的类创建脚手架。

```php
<?php
class Configuration {
}

```

1.  让我们继续并创建一些描述性的配置变量。我们可以添加更多，但现在让我们只添加我们现在需要的。

```php
<?php
class Configuration {
**private $db_server = ';
private $db_port = '';
private $db_database = '';
private $db_admin_user = '';
private $db_admin_password = '';** 
}

```

1.  现在，复制你需要访问本地 CouchDB 实例的登录信息；我的看起来类似于以下内容：

```php
<?php
class Configuration {
**private $db_server = '127.0.0.1';
private $db_port = '5984';
private $db_database = 'verge';
private $db_admin_user = 'tim';
private $db_admin_password = 'test';** 
}

```

1.  让我们使用一个特殊的`__get`函数来检查并查看是否设置了环境变量，并返回该值，而不是默认值。如果没有，它将只返回我们在这个类中定义的默认值。

```php
<?php
class Configuration {
private $db_server = '127.0.0.1';
private $db_port = '5984';
private $db_database = 'verge';
private $db_admin_user = 'tim';
private $db_admin_password = 'test';
**public function __get($property) {
if (getenv($property)) {
return getenv($property);
} else {
return $this->$property;
}
}** 
}

```

## 刚刚发生了什么？

我们刚刚创建了一个名为`configuration.php`的简单配置类，并创建了一个名为`Configuration`的类的框架。接下来，我们为数据库的配置创建了一些变量，我们将其设置为`public`，因为我们可能需要在各种地方使用这些变量。然后，我们用访问本地 CouchDB 实例的信息填充了这些变量的默认值。然后，我们添加了这个类的魔力。我们创建了一个`__get`函数，它覆盖了类的标准`get`操作。这个函数使用`getenv`函数来检查服务器，看看环境变量中是否设置了该变量（我们将很快介绍如何做到这一点）。如果有一个同名的环境变量，我们将把它返回给调用函数；如果没有，我们将简单地返回默认值。

`Configuration`类是一个很好而简单的类，它可以在不过分复杂的情况下完成我们需要的一切。接下来，让我们确保我们的应用程序知道如何访问和使用这个类。

# 行动时间-将我们的配置文件添加到 Bones

将新的配置类添加到我们的应用程序中非常容易。现在，我们只需要将它添加到 Bones 的`__construct()`中，然后我们就可以在整个项目中开始使用这个类了。

1.  打开`lib/bones.php`，并查看文件开头，告诉我们的库在哪里查找其他`lib`文件。我们需要在这里添加我们的配置类。

```php
require_once ROOT . '/lib/bootstrap.php';
require_once ROOT . '/lib/sag/src/Sag.php';
**require_once ROOT . '/lib/configuration.php';** 

```

1.  让我们确保在 Bones 的公共变量中定义`$config`，这样我们在其他文件中也可以使用它们。

```php
class Bones {
private static $instance;
public static $route_found = false;
public $route = '';
public $method = '';
public $content = '';
public $vars = array();
public $route_segments = array();
public $route_variables = array();
public $couch;
**public $config;** 

```

1.  让我们看一下文件中稍后的`__construct()`方法。在这个方法中（就在实例化 Sag 之前），让我们创建一个`Configuration`类的新实例。

```php
public function __construct() {
...
**$this->config = new Configuration();** 
$this->couch = new Sag('127.0.0.1','5984');
$this->couch->setDatabase('verge');
}

```

1.  现在我们的代码知道了配置类，我们只需要把变量放在正确的位置，就可以运行起来了。让我们告诉 Sag 如何使用配置类连接到 CouchDB。

```php
public function __construct() {
$this->route = $this->get_route();
$this->route_segments = explode('/', trim($this->route, '/'));
$this->method = $this->get_method();
$this->config = new Configuration();
**$this->couch = new Sag($this->config->db_server, $this->config->db_port);
$this->couch->setDatabase($this->config->db_database);** 
}

```

1.  还有一些地方需要更新我们的代码，以便使用配置类。记住，我们在`classes/user.php`中有`admin`用户名和密码，用于创建和查找用户。让我们首先看一下`classes/user.php`中的注册函数，清理一下。一旦我们插入我们的配置类，该函数应该类似于以下内容：

```php
public function signup($password) {
$bones = new Bones();
$bones->couch->setDatabase('_users');
**$bones->couch->login($bones->config->db_admin_user, $bones->config->db_admin_password);** 

```

1.  我们需要调整的最后一个地方是`classes/user.php`文件末尾的`get_by_username`函数，以使用`config`类。

```php
public static function get_by_username($username = null) {
$bones = new Bones();
**$bones->couch->login($bones->config->db_admin_user, $bones->config->db_admin_password);** 
$bones->couch->setDatabase('_users');

```

1.  我们刚刚删除了`index.php`顶部定义的`ADMIN_USER`和`ADMIN_PASSWORD`的所有引用。我们不再需要这些变量，所以让我们切换到`index.php`，并从文件顶部删除`ADMIN_USER`和`ADMIN_PASSWORD`。

## 刚刚发生了什么？

我们刚刚写完了我们应用程序的最后几行代码！在这一部分中，我们确保 Bones 完全可以访问我们最近创建的`lib/configuration.php`配置文件。然后，我们创建了一个公共变量`$config`，以确保我们在应用程序的任何地方都可以访问我们的配置类。将我们的配置类存储在`$config`变量中后，我们继续查看我们的代码中那些硬编码了数据库设置的地方。

## 将更改添加到 Git

因为我们刚刚写完了我们的代码的最后几行，我要确保你已经完全提交了我们的所有代码到 Git。否则，当我们不久部署我们的代码时，你的所有文件可能都不会到达生产服务器。

1.  打开终端。

1.  使用通配符添加项目中的任何剩余文件。

```php
**git add .** 

```

1.  现在，让我们告诉 Git 我们做了什么。

```php
**git commit m 'Abstracted out environment specific variables into lib/configuration.php and preparing for launch of our site 1.0!'** 

```

# 使用 PHP Fog 进行应用程序托管

我们的代码已经更新完毕，准备部署。我们只需要一个地方来实际部署它。正如我之前提到的，我们将使用 PHP Fog，但请随意探索其他可用的选项。大多数 PaaS 提供商的设置和部署过程都是相同的。

## 设置 PHP Fog 账户

设置 PHP Fog 账户就像我们设置 Cloudant 账户一样简单。

1.  首先，访问[`www.phpfog.com/signup`](http://https://www.phpfog.com/signup)。![设置 PHP Fog 账户](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_10_045.jpg)

1.  填写每个字段创建一个账户。完成后，点击“注册”。你将被引导创建你的第一个应用程序。![设置 PHP Fog 账户](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_10_050.jpg)

1.  你会注意到有各种各样的起始应用程序和框架，可以让我们快速创建 PHP 应用程序的脚手架。我们将使用我们自己的代码，所以点击“自定义应用程序”。![设置 PHP Fog 账户](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_10_060.jpg)

1.  我们的应用程序几乎创建完成了，我们只需要给 PHP Fog 提供更多信息。

1.  你会注意到 PHP Fog 要求输入 MySQL 的密码。由于我们在这个应用程序中没有使用 MySQL，我们可以输入一个随机密码或其他任何字符。值得一提的是，如果将来有一天你想在项目中使用 MySQL 来存储一些关系数据，只需点击几下，就可以在同一应用程序环境中进行托管。记住，如果正确使用，MySQL 和 CouchDB 可以成为最好的朋友！

1.  接下来，PHP Fog 会要求输入你的域名。每个应用程序都会有一个托管在[phpfogapp.com](http://phpfogapp.com)上的短 URL。这对我们来说在短期内是完全可以接受的，当我们准备使用完整域名推出我们的应用程序时，我们可以通过 PHP Fog 的“域名”部分来实现。在为应用程序创建域名时，PHP Fog 要求它是唯一的，所以你需要想出自己的域名。你可以使用类似`yourname-verge.phpfogapp.com`的形式，或者你可以特别聪明地创建一个以你最喜欢的神话生物命名的应用程序。这是一个常见的做法，这样在你还在修复错误和准备推出时，没有人会随机找到你的应用程序。![设置 PHP Fog 账户](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_10_065.jpg)

1.  当你准备好时，点击“创建应用程序”，你的应用程序将被创建。![设置 PHP Fog 账户](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_10_070.jpg)

1.  就是这样！你的应用程序已经准备就绪。你会注意到 PHP Fog 会在短暂的时间内显示“状态：准备应用...”，然后会变成“状态：运行”。![设置 PHP Fog 账户](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_10_072.jpg)

## 创建环境变量

我们的 PHP Fog 应用程序已经启动运行，我们在将代码推送到服务器之前需要进行最后一项配置。记得我们在配置项目时设置的所有环境变量吗？好吧，我们需要在 PHP Fog 中设置它们，这样我们的应用程序就知道如何连接到 Cloudant 了。

为了管理你的环境变量，你需要首先转到你项目的“应用程序控制台”，这是你创建第一个应用程序后留下的地方。

点击“环境变量”，你将进入“环境变量管理”部分。

![创建环境变量](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_10_075.jpg)

你会注意到 PHP Fog 为我们创建的 MySQL 数据库的环境变量已经设置好了。我们只需要输入 Cloudant 的环境变量。名称需要与我们在本章前面定义的配置类中的名称相同。

让我们从添加我们的`db_server`环境变量开始。我的`db_server`位于`https://timjuravich:password@timjuravich.cloudant.com`，所以我将这些详细信息输入到**名称**和**值**文本字段中。

![创建环境变量](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_10_080.jpg)

让我们继续为配置文件中的每个变量进行此过程。回顾一下，这里是您需要输入的环境变量：

+   `db_server:` 这将是您的 Cloudant URL，同样，我的是`https://timjuravich:password@timjuravich.cloudant.com`

+   `db_port:` 这将设置为`5984`

+   `db_database:` 这是将存储所有内容的数据库，应设置为`verge`

+   `db_admin_user:` 这是`admin`用户的用户名。在我们的情况下，这是设置为 Cloudant 管理员用户名的值

+   `db_admin_password:` 这是上述`admin`用户的密码

当您完成所有操作后，点击**保存更改**，您的环境变量将被设置。有了这个，我们就可以部署到 PHP Fog 了。

## 部署到 PHP Fog

部署到 PHP Fog 是一个非常简单的过程，因为 PHP Fog 使用 Git 进行部署。很幸运，我们的项目已经使用 Git 设置好并准备就绪。我们只需要告诉 PHP Fog 我们的 SSH 密钥，这样它就知道如何识别我们。

### 将我们的 SSH 密钥添加到 PHP Fog

PHP Fog 使用 SSH 密钥来识别和验证我们，就像 GitHub 一样。由于我们在本书的早期已经创建了一个，所以我们不需要再创建一个。

1.  您可以从右上角点击**我的帐户**开始，然后在下一页上点击**SSH 密钥**。您将看到以下页面，您可以在其中输入您的 SSH 密钥:![将我们的 SSH 密钥添加到 PHP Fog](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_10_082.jpg)

1.  输入**昵称**的值。您应该使用简单但描述性的内容，比如`Tim's Macbook`。将来，您会因为保持这种组织而感激自己，特别是如果您开始与其他开发人员合作开发这个项目。

您需要获取公钥以填入公钥文本框。幸运的是，我们可以在终端中用一个简单的命令来做到这一点。

1.  打开终端。

1.  运行以下命令，您的公钥将被复制到剪贴板。

```php
**pbcopy< ~/.ssh/id_rsa.pub** 

```

1.  将公钥复制到剪贴板后，只需点击文本框，粘贴值进去。

1.  最后，在表单底部有一个复选框，上面写着**给此密钥写入访问权限**。如果您希望计算机能够将代码推送到 PHP Fog（我们希望能够这样做），则需要勾选此复选框。

1.  点击**保存 SSH 密钥**，我们就可以继续进行部署应用程序的最后步骤了。

### 连接到 PHP Fog 的 Git 存储库

由于我们已经设置好并准备好使用的 Git 存储库，我们只需要告诉 Git 如何连接到 PHP Fog 上的存储库。让我们通过向我们的工作目录添加一个名为`phpfog`的远程存储库来完成这个过程。

#### 从 Php Fog 获取存储库

当我们在 PHP Fog 上创建应用程序时，我们还创建了一个独特的 Git 存储库，我们的应用程序由此驱动。在本节中，我们将获取此存储库的位置，以便告诉 Git 连接到它。

1.  登录到您的 PHP Fog 帐户。

1.  转到您的应用程序的应用控制台。

1.  点击**源代码**。

1.  在**源代码**页面上，您将看到一个部分，上面写着**克隆您的 git 存储库**。我的里面有以下代码（您的应该类似）:

```php
**git clone git@git01.phpfog.com:timjuravich-verge.phpfogapp.com** 

```

1.  因为我们已经有一个现有的 Git 存储库，所以我们不需要克隆他们的，但是我们需要应用程序的 Git 存储库的位置来进行下一步配置。使用这个例子，存储库位置将是`git@git01.phpfog.com:timjuravich-verge.phpfogapp.com`。将其复制到剪贴板上。

#### 从 Git 连接到存储库

现在我们知道了 PHP Fog 的 Git 存储库，我们只需要告诉我们的本地机器如何连接到它。

1.  打开终端。

1.  将目录更改为您的`工作`文件夹。

```php
**cd /Library/WebServer/Documents/verge** 

```

1.  现在，让我们将 PHP Fog 的存储库添加为一个名为`phpfog`的新远程存储库。

```php
**git remote add phpfog git@git01.phpfog.com:verge.phpfogapp.com** 

```

1.  清除跑道，我们准备启动这个应用程序！

### 部署到 PHP Fog

这就是我们一直在等待的时刻！让我们将我们的应用程序部署到 PHP Fog。

1.  打开终端。

1.  将目录更改为您的`working`文件夹。

```php
**cd /Library/WebServer/Documents/verge** 

```

1.  我们希望忽略 PHP Fog 的 Git 存储库中的内容，因为我们已经构建了我们的应用程序。因此，这一次，我们将在调用的末尾添加`--force`。

```php
**git push origin master --force** 

```

我希望这不会太令人失望，但恭喜，您的应用程序已经上线了！这是不是很简单？从现在开始，每当您对代码进行更改时，您只需要将其提交到 Git，输入命令`git push phpfog master`，并确保通过`git push origin master`将您的代码推送到 GitHub。

如果您开始对您的实时应用程序进行一些操作，您可能会感到沮丧，因为您的本地机器上的数据并不适合您查看。您很幸运；在下一节中，我们将使用 CouchDB 强大的复制功能将本地数据库推送到我们的生产数据库。

# 将本地数据复制到生产环境

复制的内部工作原理和背景信息将不会在本节中详细介绍，但您可以在 Packt Publishing 网站上的名为*复制您的数据*的奖励章节中找到完整的演练。

为了给您一个快速概述，**复制**是 CouchDB 在服务器之间传输数据的方式。复制由每个文档中的`_rev`字段驱动，`_rev`字段确保您的服务器知道哪个版本具有正确的数据可供使用。

在本节中，我们将复制`_users`和`verge`数据库，以便我们所有的本地数据都可以在生产服务器上使用。如果您的应用程序已经上线了几分钟甚至几天，您不必担心，因为复制的最大好处是，如果有人已经在使用您的应用程序，那么他们的所有数据将保持完整；我们只是添加我们的本地数据。

# 执行操作-将本地 _users 数据库复制到 Cloudant

让我们使用 Futon 将我们的本地`_users`数据库复制到我们在 Cloudant 上创建的`_users`数据库。

1.  在浏览器中打开 Futon，单击**复制器**，或者您可以直接导航到`http://localhost:5984/_utils/replicator.html`。

1.  确保您以`管理员`身份登录；如果没有，请单击**登录**，以`管理员`身份登录。

1.  在**从中复制更改**的下拉列表中选择`_users`数据库。

1.  在**To**部分中单击**远程数据库**单选按钮。![执行操作-将本地 _users 数据库复制到 Cloudant](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_10_085.jpg)

1.  在**远程数据库**文本字段中，输入 Cloudant 数据库的 URL 以及凭据。 URL 的格式看起来类似于`https://username:password@username.cloudant.com/_users`。![执行操作-将本地 _users 数据库复制到 Cloudant](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_10_090.jpg)

1.  单击**复制**，CouchDB 将推送您的本地数据库到 Cloudant。

1.  您将看到 Futon 的熟悉结果。![执行操作-将本地 _users 数据库复制到 Cloudant](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_10_095.jpg)

## 刚刚发生了什么？

我们刚刚使用 Futon 将我们的本地`_users`数据库复制到了我们在 Cloudant 上托管的`_users`生产数据库。这个过程与我们之前做的完全相同，但是我们在**To**部分使用了**远程数据库**，并使用了数据库的 URL 以及我们的凭据。复制完成后，我们收到了一个冗长且令人困惑的报告，但要点是一切都进行得很顺利。让我们继续复制我们的`verge`数据库。

### 注意

值得一提的是，如果你尝试从命令行复制`_users`数据库，你将不得不在调用中包含用户名和密码。这是因为我们完全将用户数据库锁定为匿名用户。函数看起来类似于以下内容：

curl -X POST http://user:password@localhost:5984/_replicate -d '{"source":"_users",*"target":"https://username:password@username.cloudant.com/_users"}'* -H*"Content-Type:* application/json"

## 试一试英雄——将本地的 verge 数据库复制到 Cloudant

你认为你能根据我刚给你的提示找出将本地`verge`数据库复制到 Cloudant 上的`verge`数据库的命令吗？在游戏的这个阶段几乎不可能搞砸任何事情，所以如果第一次没有搞定，不要害怕尝试几次。

试一试。完成后，继续阅读，我们将讨论我使用的命令。

一切进行得如何？希望你能轻松搞定。如果你无法让它工作，这里有一个你可以使用的命令示例：

```php
curl -X POST http://user:password@localhost:5984/_replicate -d '{"source":"verge","target":"https://username:password@username .cloudant.com/verge"}' -H "Content-Type: application/json"

```

在这个例子中，我们使用我们的本地 CouchDB 实例将本地的`verge`数据库复制到目标 Cloudant`verge`数据库。对于本地数据库，我们可以简单地将名称设置为`verge`，但对于目标数据库，我们必须传递完整的数据库位置。

当你的所有数据都在生产服务器上并且在线时，你可以登录为你在本地创建的任何用户，并查看你创建的所有内容都已经准备好供全世界查看。这并不是你旅程的结束；让我们快速谈谈接下来的事情。

# 接下来是什么？

在我送你离开之前，让我们谈谈你的应用在野外的前景，以及你可以做些什么来使这个应用更加强大。

## 扩展你的应用

幸运的是，在利用 PHPFog 和 Cloudant 时，扩展你的应用应该是非常容易的。实际上，你唯一需要做的最紧张的事情就是登录 PHPFog 并增加我们的 Web 进程，或者登录 Cloudant 并升级到更大的计划。他们处理所有的艰苦工作；你只需要学会如何有效地扩展。这是无法超越的！

要了解更多关于有效扩展的信息，请浏览 PHPFog 和 Cloudant 的帮助文档，它们详细介绍了不同的扩展方式和需要避免的问题领域。

值得再次提到的是，我们在本章中并没有完全涵盖复制。要全面了解复制，请务必查看题为*复制数据*的奖励章节，该章节可在 Packt Publishing 网站上找到。

## 下一步

我希望你继续开发和改进 Verge，使其成为非常有用的东西，或者，如果不是，我希望你利用这本书学到的知识构建更伟大的东西。

如果你决定继续在 Verge 上构建功能，这个应用还有很多可以做的事情。例如，你可以：

+   添加用户之间相互关注的功能

+   允许用户过滤和搜索内容

+   添加一个消息系统，让用户可以相互交流

+   自定义 UI，使其成为真正独特的东西

我将继续在 GitHub 上的 Verge 存储库中逐步添加这样的功能和更多功能：[`github.com/timjuravich/verge`](http://https://github.com/timjuravich/verge)。所以，请确保关注存储库的更新，并在需要时进行分叉。

再次感谢你在这本书中花费的时间，请随时在 Twitter 上联系我`@timjuravich`，如果你有任何问题。

开心开发！

# 总结

在本章中，我们学会了如何与世界分享我们的应用。具体来说，我们注册了 Cloudant 和 PHP Fog 的帐户，并成功部署了我们的应用。你所要做的就是继续编码，将这个应用变成一些了不起的东西。
