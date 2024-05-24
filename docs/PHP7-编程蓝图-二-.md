# PHP7 编程蓝图（二）

> 原文：[`zh.annas-archive.org/md5/27faa03af47783c6370aa5ff8894925f`](https://zh.annas-archive.org/md5/27faa03af47783c6370aa5ff8894925f)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：使用 Elasticsearch 构建具有搜索功能的简单博客

在本章中，我们将创建一个简单的博客，可以创建和删除帖子。然后我们将致力于为我们的博客添加一些功能，例如以下内容：

+   实现一个非常简单的带有 CRUD 和管理员功能的博客

+   工作和安装 Elasticsearch 和 Logstash

+   尝试使用 Elasticsearch 的 PHP 客户端

+   学习构建与 Elasticsearch 一起工作的工具

+   为我们的数据库构建搜索缓存

+   基于我们的 Elasticsearch 信息构建图表

# 创建 CRUD 和管理员系统

首先，让我们构建我们的帖子的 SQL。数据库表至少应该包含帖子标题、帖子内容、帖子日期以及修改和发布日期。

这是 SQL 应该看起来的样子：

```php
CREATE TABLE posts( 
id INT(11) PRIMARY KEY AUTO INCREMENT, 
post_title TEXT, 
post_content TEXT, 
post_date DATETIME, 
modified DATETIME, 
published DATETIME 
); 

```

现在让我们创建一个函数来读取数据。一个典型的博客网站有评论和与博客文章相关的一些额外的 SEO 元数据。但在本章中，我们不会创建这部分。无论如何，向评论数据添加表格并在另一个表格中添加有关每篇文章的 SEO 元数据应该是相当简单的。

让我们从创建管理员系统开始。我们需要登录，所以我们将创建一个简单的登录-注销脚本：

```php
//admin.php 
<form action="admin.php" method="post"> 
Username: <input type="text" name="username"><br /> 
Password: <input type="text" name="username"><br /> 
<input type="submit" name="submit"> 
</form> 
<?php 
$db = new mysqli(); //etc 

Function checkPassword($username, $password) { 
//generate hash 
    $bpassword = password_hash($password); 

//clean up username for sanitization 
$username = $db->real_escape_string($username); 

    $query = mysqli_query("SELECT * FROM users WHERE password='".$bpassword."' AND username = '". $username. "'"); 
if($query->num_rows() > 0) { 
return true; 
     } 
return false; 
} 

if(isset$_POST[' assword']) && isset ($_POST['username']) ) { 
If(checkPassword($_POST['username'], $_POST['password'])) { 
$_SESSION['admin'] = true; 
$_SESSION['logged_in'] = true; 
$_SESSION['expires'] = 3600; //1 hour 
      $_SESSION['signin_time'] = time(); //unix time 
      header('Location: admin_crud_posts.php'); 
} 
else { 
       //lead the user out 
header('Location: logout.php'); 
    } 
   } 
} 

```

当您登录到`admin.php`时，您设置了会话，然后被重定向到 CRUD 页面。

管理员 CRUD 页面的脚本如下：

```php
<?php 
$db = new mysqli(); //etc 
function delete($post_id) { 
   $sql_query = "DELETE FROM posts WHERE id= '". $post_id."'"; 
  $db->query($sql_query); 

} 

function update($postTitle, $postContent, $postAuthor, $postId) { 
$sql_query = "UPDATE posts  
   SET  title = '".$postTitle. "',  
   post_content = '". $postContent. "',  
   post_author='". $postAuthor."'   
   WHERE id = '".$postId."'"; 
   $db->query($sql_query); 
} 

function create($postTitle, $postContent, $postAuthor) { 

$insert_query = "INSERT INTO posts (null , 
    '" . $postTitle."', 
    '". $postContent."', 
   '" $postAuthor."')";  

$db->query($insert_query); 

} 

$query = "SELECT * FROM posts"; 
$result = $db->query($query); 

//display 
?> 
<table> 
<tr> 
<td>Title</td> 
<td>Content</td> 
<td>Author</td> 
<td>Administer</td> 
</tr> 
while($row = $db->fetch_array($query,MYSQLI_ASSOC)) { 
  $id = $row['id']; 
echo '<tr>'; 

echo '<td>' .$row['title'] . '</td>'; 

echo '<td>' . $row['content'] . '</td>';   

echo '<td>' . $row['author'] . '</td>'; 

echo '<td><a href="edit.php?postid='.$id.'">Edit</a>'; 
echo '<a href="delete.php?postid='.$id.'">Delete</a>'.</td>';' 
echo '</tr>'; 
} 
echo "</table>"; 

?> 

```

在上面的脚本中，我们只是简单地定义了一些函数来处理 CRUD 操作。要显示数据，我们只需简单地循环遍历数据库并在表格中输出它。

编辑和删除页面，这些是用户界面和用于编辑或删除帖子的功能所需的脚本，如下所示：

`edit.php`：

```php
<?php 
function redirect($home) { 
header('Location: '. $home); 
} 
if(!empty($_POST)) { 
   $query = 'UPDATE posts SET title='" .  $_POST['title']. "', content='". $_POST['content']."' WHERE id = ".$_POST['id']; 
   $db->query($query); 
   redirect('index.php'); 
} else { 
  $id = $_GET['id']; 
  $q = "SELECT * FROM posts WHERE id= '".$_GET['id'] . "'" 
?> 
<form action="edit.php" method="post"> 

<input name="post_title type="text" value=" ="<?php echo  $_POST[ 
title'] ?>"> 

<input type="text" value="<?php echo $_POST['content'] ?>"> 

<input type="hidden" value="<?php echo $_GET['id'] ?>"> 

</form> 
<?php 
} 
?> 

```

让我们创建实际的删除帖子功能。以下是`delete.php`的样子：

```php
<?php 

function redirect($home) { 
    header('Location: '. $home); 
} 
if(isset ($_GET['postid'])) { 
    $query = "DELETE FROM  posts WHERE id = '".$_GET['post_id']."'"; 
$db->query($query); 
redirect('index.php'); 
} 

```

我们的 PHP 记录器 Monolog 将使用 Logstash 插件将帖子添加到 Elasticsearch 中。

我们将设置一个 Logstash 插件，首先检查文档是否存在，如果不存在，则插入。

要更新 Elasticsearch，我们需要执行**upsert**，如果记录存在，则更新相同的记录，如果不存在，则创建一个新的记录。

此外，我们已经实现了一种方法，可以从我们的 CRUD 中删除帖子，但实际上并没有从数据库中删除它，因为我们需要它来进行检索。

对于需要执行的每个操作，我们只需使用`$_GET['id']`来确定在单击时我们要执行什么操作。

像任何博客一样，我们需要一个首页供用户显示可阅读的帖子：

`index.php`：

```php
<html> 
<?php 
$res = $db->query("SELECT * FROM posts LIMIT 10"); 
foreach$posts as $post { 
<h1><?phpecho $post[]?> 
?> 
} 
?> 

```

在上面的代码中，我们广泛使用了简写的`php`标记，这样我们就可以专注于页面布局。请注意它是如何在 PHP 模式中来回穿梭的，但看起来就像我们只是在使用模板，这意味着我们可以看到 HTML 标记的一般轮廓，而不会过多涉及 PHP 代码的细节。

## 填充帖子表

没有任何数据，我们的博客就是无用的。因此，为了演示目的，我们将使用一个种子脚本来自动填充我们的表格数据。

让我们使用一个用于生成虚假内容的流行库**Faker**，它可以在[`github.com/fzaninotto/Faker`](https://github.com/fzaninotto/Faker)上找到。

使用 Faker，您只需通过提供其`autoload.php`文件的所需路径来加载它，并使用 composer 进行加载（`composer require fzaninotto/faker`）。

生成虚假内容的完整脚本如下：

```php
<?php 
require "vendor/autoload"; 
$faker = FakerFactory::create(); 
for($i=0; $i < 10; $i++) { 
  $id = $i; 
  $post = $faker->paragraph(3, true); 
  $title  = $faker->text(150);  
  $query = "INSERT INTO posts VALUES (".$id.",'".$title."','".$post . "','1')" 
} 

?> 

```

现在让我们开始熟悉 Elasticsearch，这是我们博客文章的数据库搜索引擎。

## 什么是 Elasticsearch？

**Elasticsearch**是一个搜索服务器。它是一个带有 HTTP Web 界面和无模式 JSON 文档的全文搜索引擎。这意味着我们使用 JSON 存储新的可搜索数据。输入这些文档的 API 使用 HTTP 协议。在本章中，我们将学习如何使用 PHP 并构建一个功能丰富的搜索引擎，可以执行以下操作：

+   设置 Elasticsearch PHP 客户端

+   将搜索数据添加到 Elasticsearch 进行索引

+   学习如何使用关键字进行相关性

+   缓存我们的搜索结果

+   使用 Elasticsearch 与 Logstash 存储 apache 日志

+   解析 XML 以存储到 Elasticsearch

## 安装 Elasticsearch 和 PHP 客户端

创建用于消费 Elasticsearch 的 Web 界面。

就您需要知道的而言，Elasticsearch 只需要通过使用最新的 Elasticsearch 源代码进行安装。

安装说明如下：

1.  转到[`www.elastic.co/`](https://www.elastic.co/)并下载与您的计算机系统相关的源文件，无论是 Mac OSX、Linux 还是 Windows 机器。

1.  下载文件到计算机后，应运行设置安装说明。

1.  例如，对于 Mac OSX 和 Linux 操作系统，您可以执行以下操作：

+   安装 Java 1.8。

+   通过 curl（在命令行中）下载 Elasticsearch：

```php
**curl -L -O 
      https://download.elastic.co/elasticsearch/release/org/elasticsearch
      /distribution/tar/elasticsearch/2.1.0/elasticsearch-2.1.0.tar.gz**

```

+   解压缩存档并切换到其中：

```php
**tar -zxvf elasticsearch-2.1.0.tar.gz**
**cd /path/to/elasticsearch/archive**

```

+   启动它：

```php
**cd bin**
**./elasticsearch**

```

在 Mac OSX 上安装 Elasticsearch 的另一种方法是使用 homebrew，它可以在[`brew.sh/`](http://brew.sh/)上找到。然后，使用以下命令使用 brew 进行安装：

```php
**brew install elasticsearch**

```

1.  对于 Windows 操作系统，您只需要按照向导安装程序进行点击，如下截图所示：![安装 Elasticsearch 和 PHP 客户端](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-bp/img/image_04_001.jpg)

1.  安装完成后，您还需要安装**Logstash 代理**。Logstash 代理负责从各种输入源向 Elasticsearch 发送数据。

1.  您可以从 Elasticsearch 网站下载它，并按照计算机系统的安装说明进行安装。

1.  对于 Linux，您可以下载一个`tar`文件，然后您只需要使用 Linux 的另一种方式，即使用软件包管理器，即`apt-get`或`yum`，具体取决于您的 Linux 版本。

您可以通过安装**Postman**并进行`GET 请求`到`http://localhost:9200`来测试 Elasticsearch：

1.  通过打开 Google Chrome 并访问[`www.getpostman.com/`](https://www.getpostman.com/)来安装 Postman。您可以通过转到附加组件并搜索 Postman 来在 Chrome 上安装它。

1.  安装 Postman 后，您可以注册或跳过注册：![安装 Elasticsearch 和 PHP 客户端](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-bp/img/image_04_002.jpg)

1.  现在尝试进行`GET 请求`到`http://localhost:9200`：![安装 Elasticsearch 和 PHP 客户端](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-bp/img/image_04_003.jpg)

1.  下一步是在您的 composer 中尝试使用 Elasticsearch 的 PHP 客户端库。以下是如何做到这一点：

1.  首先，在您的`composer.json`文件中包含 Elasticsearch：

```php
      { 
      "require":{ 
      "elasticsearch/elasticsearch":"~2.0" 
      } 
      } 

```

1.  获取 composer：

```php
      curl-s http://getcomposer.org/installer | php 
      phpcomposer.phar install --no-dev 

```

1.  通过将其包含在项目中来实例化一个新的客户端：

```php
      require'vendor/autoload.php'; 

      $client =Elasticsearch\ClientBuilder::create()->build(); 

```

现在让我们尝试索引一个文档。为此，让我们创建一个使用 PHP 客户端的 PHP 文件，如下所示：

```php
$params=[ 
    'index'=> 'my_index', 
    'type'=> 'my_type', 
    'id'=> 'my_id', 
    'body'=>['testField'=> 'abc'] 
]; 

$response = $client->index($params); 
print_r($response); 

```

我们还可以通过创建以下代码的脚本来检索该文档：

```php
$params=[ 
    'index'=> 'my_index', 
    'type'=> 'my_type', 
    'id'=> 'my_id' 
]; 

$response = $client->get($params); 
print_r($response); 

```

如果我们正在执行搜索，代码如下：

```php
$params=[ 
    'index'=> 'my_index', 
    'type'=> 'my_type', 
    'body'=>[ 
        'query'=>[ 
            'match'=>[ 
                'testField'=> 'abc' 
] 
] 
] 
]; 

$response = $client->search($params); 
print_r($response); 

```

简而言之，Elasticsearch PHP 客户端使得更容易将文档插入、搜索和从 Elasticsearch 获取文档。

### 构建一个 PHP Elasticsearch 工具

上述功能可用于使用 Elasticsearch PHP 客户端创建基于 PHP 的用户界面，以插入、查询和搜索文档。

这是一个简单的引导（HTML CSS 框架）表单：

```php
<div class="col-md-6"> 
<div class="panel panel-info"> 
<div class="panel-heading">Create Document for indexing</div> 
<div class="panel-body"> 
<form method="post" action="new_document" role="form"> 
<div class="form-group"> 
<label class="control-label" for="Title">Title</label> 
<input type="text" class="form-control" id="newTitle" placeholder="Title"> 
</div> 
<div class="form-group"> 
<label class="control-label" for="exampleInputFile">Post Content</label> 
<textarea class="form-control" rows="5" name="post_body"></textarea> 
<p class="help-block">Add some Content</p> 
</div> 
<div class="form-group"> 
<label class="control-label">Keywords/Tags</label> 
<div class="col-sm-10"> 
<input type="text" class="form-control" placeholder="keywords, tags, more keywords" name="keywords"> 
</div> 
<p class="help-block">You know, #tags</p> 
</div> 
<button type="submit" class="btnbtn-default">Create New Document</button> 
</form> 
</div> 
</div> 
</div> 

```

这是表单应该看起来的样子：

![构建 PHP Elasticsearch 工具](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-bp/img/image_04_004.jpg)

当用户提交内容的详细信息时，我们需要捕捉用户输入的内容、关键词或标签。PHP 脚本将输入输入到 MySQL，然后输入到我们的脚本，然后将其推送到我们的 Elasticsearch 中：

```php
public function insertData($data) { 
  $sql = "INSERT INTO posts ('title', 'tags', 'content') VALUES('" . $data['title] . "','" . $data['tags'] . "','" .$data['content'] . ")"; 
mysql_query($sql); 
} 

insertData($_POST); 

```

现在让我们也尝试将此文档发布到 Elasticsearch：

```php
$params=[ 
    'index'=> 'my_posts', 
    'type'=>'posts', 
    'id'=>'posts', 
    'body'=>[ 
       'title'=>$_POST['title'], 
       'tags' => $_POST['tags'], 
       'content' => $_POST['content'] 
] 
]; 

$response = $client->index($params); 
print_r($response); 

```

## 将文档添加到我们的 Elasticsearch

Elasticsearch 使用索引将每个数据点存储到其数据库中。从我们的 MySQL 数据库中，我们需要将数据发布到 Elasticsearch。

让我们讨论 Elasticsearch 中索引实际上是如何工作的。它比 MySQL 的传统搜索更快的原因在于它搜索索引而不是搜索每个条目。

Elasticsearch 中的索引工作原理是什么？它使用**Apache Lucene**创建一种称为**倒排索引**的东西。倒排索引意味着它查找搜索项而无需扫描每个条目。基本上意味着它有一个查找表，列出了系统中输入的所有单词。

ELK 堆栈的架构概述如下：

![将文档添加到我们的 Elasticsearch](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-bp/img/image_04_005.jpg)

在上图中，我们可以看到**输入源**，通常是日志或其他数据源，进入**Logstash**。然后从**Logstash**进入**Elasticsearch**。

一旦数据到达**Elasticsearch**，它会经过一些标记和过滤。**标记**是将字符串分解为不同部分的过程。**过滤**是当一些术语被分类到单独的索引中时。例如，我们可能有一个 Apache 日志索引，然后还有另一个输入源，比如**Redis**，推送到另一个可搜索的索引中。

可搜索的索引是我们之前提到的反向索引。可搜索的索引基本上是通过将每个术语存储并引用其原始内容到索引中来实现的。这类似于索引数据库中所做的操作。当我们创建主键并将其用作搜索整个记录的索引时，这是相同的过程。

您可以在集群中有许多节点执行此索引操作，所有这些都由 Elasticsearch 引擎处理。在上图中，节点标记为**N1**到**N4**。

### 查询 Elasticsearch

现在我们了解了每个部分，那么我们如何查询 Elasticsearch 呢？首先，让我们介绍 Elasticsearch。当您开始运行 Elasticsearch 时，您应该向`http://localhost:9200`发送 HTTP 请求。

我们可以使用 Elasticsearch web API 来实现这一点，它允许我们使用 RESTful HTTP 请求将记录插入到 Elasticsearch 服务器中。这个 RESTful API 是将记录插入到 Elasticsearch 的唯一方法。

### 安装 Logstash

Logstash 只是所有传递到 Elasticsearch 的消息经过的中央日志系统。

要设置 Logstash，请按照 Elasticsearch 网站上提供的指南进行操作：

[`www.elastic.co/guide/en/logstash/current/getting-started-with-logstash.html`](https://www.elastic.co/guide/en/logstash/current/getting-started-with-logstash.html)。

Elasticsearch 和 Logstash 一起工作，将不同类型的索引日志输入 Elasticsearch。

我们需要在两个数据点之间创建一种称为**传输**或中间件。为此，我们需要设置 Logstash。它被称为 Elasticsearch 的**摄入工作马**，还有更多。它是一个数据收集引擎，将数据从数据源管道传输到目的地，即 Elasticsearch。Logstash 基本上就像一个简单的数据管道。

我们将创建一个 cron 作业，这基本上是一个后台任务，它将从我们的帖子表中添加新条目并将它们放入 Elasticsearch 中。

熟悉管道概念的 Unix 和 Linux 用户，|，将熟悉管道的工作原理。

Logstash 只是将我们的原始日志消息转换为一种称为**JSON**的格式。

### 提示

**JSON**，也称为**JavaScript 对象表示法**，是在 Web 服务之间传输数据的流行格式。它很轻量，许多编程语言，包括 PHP，都有一种方法来编码和解码 JSON 格式的消息。

### 设置 Logstash 配置

Logstash 配置的输入部分涉及正确读取和解析日志数据。它由输入数据源和要使用的解析器组成。这是一个示例配置，我们将从`redis`输入源中读取：

```php
input { 
redis { 
key =>phplogs 
data_type => ['list'] 
  } 
} 

```

但首先，为了能够推送到`redis`，我们应该安装并使用`phpredis`，这是一个允许 PHP 将数据插入`redis`的扩展库。

### 安装 PHP Redis

安装 PHP Redis 应该很简单。它在大多数 Linux 平台的软件包存储库中都有。您可以阅读有关如何安装它的文档[`github.com/phpredis/phpredis`](https://github.com/phpredis/phpredis)。

安装完成后，您可以通过创建以下脚本并运行它来测试您的 PHP Redis 安装是否正常工作：

```php
<?php 
$redis = new Redis() or die("Cannot load Redis module."); 
$redis->connect('localhost'); 
$redis->set('random', rand(5000,6000)); 
echo $redis->get('random'); 

```

在上面的例子中，我们能够启动一个新的 Redis 连接，然后设置一个名为`random`的键，其值在`5000`和`6000`之间。最后，我们通过调用`echo $redis->get('random')`来输出我们刚刚输入的数据。

有了这个，让我们使用名为**Monolog**的 PHP 日志库来创建真正的 PHP 代码，将日志存储在 Redis 中。

让我们创建一个`composer.json`，供日志项目使用。

在终端中，让我们运行初始化 composer：

```php
composer init 

```

它将在之后交互式地询问一些问题，然后应该创建一个`composer.json`文件。

现在通过输入以下内容来安装 Monolog：

```php
composer require monolog/monolog
```

让我们设置从我们的 MySQL 数据库中读取数据，然后将其推送到 Elasticsearch 的 PHP 代码：

```php
<?php 
require'vendor/autoload.php' 

useMonolog\Logger; 
useMonolog\Handler\RedisHandler; 
useMonolog\Formatter\LogstashFormatter; 
usePredis\Client; 

$redisHandler=newRedisHandler(newClient(),'phplogs'); 
$formatter =newLogstashFormatter('my_app'); 
$redisHandler->setFormatter($formatter); 

// Create a Logger instance  
$logger =newLogger('logstash_test', array($redisHandler)); 
$logger->info('Logging some infos to logstash.'); 

```

在上面的代码中，我们创建了一个名为`phplogs`的`redisHandler`。然后，我们设置`LogstashFormatter`实例以使用应用程序名称`my_app`。

在脚本的末尾，我们创建一个新的`logger`实例，将其连接到`redisHandler`，并调用`logger`的`info()`方法来记录数据。

Monolog 将格式化程序的职责与实际日志记录分开。`logger`负责创建消息，而格式化程序将消息格式化为适当的格式，以便 Logstash 能够理解。Logstash 将其传输到 Elasticsearch，Logstash 将其索引的日志数据存储在 Elasticsearch 索引中，以便以后进行查询。

这就是 Elasticsearch 的美妙之处。只要有 Logstash，您可以选择不同的输入源供 Logstash 处理，Elasticsearch 将在 Logstash 推送数据时保存数据。

### 编码和解码 JSON 消息

现在我们知道如何使用 Monolog 库，我们需要将其集成到我们的博客应用程序中。我们将通过创建一个 cronjob 来实现这一点，该 cronjob 将检查当天是否有新的博客文章，并通过使用 PHP 脚本将它们存储在 Elasticsearch 中。

首先，让我们创建一个名为`server_scripts`的文件夹，将所有 cronjobs 放在其中：

```php
$ mkdir ~/server_scripts 
$ cd ~/server_scripts 

```

现在，这是我们的代码：

```php
<?php 
$db_name = 'test'; 
$db_pass = 'test123'; 
$db_username = 'testuser' 
$host = 'localhost'; 
$dbconn = mysqli_connect(); 
$date_now = date('Y-m-d 00:00:00'); 
$date_now_end = date('Y-m-d 00:00:00',mktime() + 86400); 
$res = $dbcon->query("SELECT * FROM posts WHERE created >= '". $date_now."' AND created < '". $date_now_end. "'"); 

while($row = $dbconn->fetch_object($res)) { 
  /* do redis queries here */ 

} 

```

使用 Logstash，我们可以从我们的`redis`数据中读取并让它完成工作，然后使用以下 Logstash 的输出插件代码输出它：

```php
output{ 
elasticsearch_http{ 
host=> localhost 
} 
} 

```

## 在 Elasticsearch 中存储 Apache 日志

监控日志是任何 Web 应用程序的重要方面。大多数关键系统都有一个称为仪表板的东西，这正是我们将在本节中使用 PHP 构建的东西。

作为本章的额外内容，让我们谈谈另一个日志主题，服务器日志。有时，我们希望能够确定服务器在某个特定时间的性能。

Elasticsearch 的另一项功能是存储 Apache 日志。对于我们的应用程序，我们可以添加这个功能，以便更多了解我们的用户。

例如，如果我们对监视用户使用的浏览器以及用户访问我们网站时来自何处感兴趣，这可能会很有用。

为了做到这一点，我们只需使用 Apache 输入插件设置一些配置，如下所示：

```php
input { 
file { 
path => "/var/log/apache/access.log" 
start_position => beginning  
ignore_older => 0  
    } 
} 

filter { 
grok { 
match => { "message" => "%{COMBINEDAPACHELOG}"} 
    } 
geoip { 
source => "clientip" 
    } 
} 

output { 
elasticsearch {} 
stdout {} 
} 

```

当您从 Elasticsearch 安装 Kibana 时，可以创建**Kibana**仪表板；但是，这需要最终用户已经知道如何使用该工具来创建各种查询。

然而，有必要使高层管理人员能够更简单地查看数据，而无需知道如何创建 Kibana 仪表板。

为了使我们的最终用户不必学习如何使用 Kibana 和创建仪表板，我们将在请求仪表板页面时简单地查询**ILog**信息。对于图表库，我们将使用一个名为**Highcharts**的流行库。但是，为了获取信息，我们需要创建一个简单的查询，以 JSON 格式返回一些信息给我们。

处理 Apache 日志，我们可以使用 PHP Elasticsearch 客户端库来创建。这是一个简单的客户端库，允许我们查询 Elasticsearch 以获取我们需要的信息，包括命中次数。

我们将为我们的网站创建一个简单的直方图，以显示在我们的数据库中记录的访问次数。

例如，我们将使用 PHP Elasticsearch SDK 来查询 Elasticsearch 并显示 Elasticsearch 结果。

我们还必须使直方图动态化。基本上，当用户想要在某些日期之间进行选择时，我们应该能够设置 Highcharts 来获取数据点并创建图表。如果您还没有查看过 Highcharts，请参考[`www.highcharts.com/`](http://www.highcharts.com/)。

将 Apache 日志存储在 Elasticsearch 中

### 获取过滤数据以显示在 Highcharts 中

像任何图表用户一样，我们有时需要过滤我们在图表中看到的内容的能力。我们不应该依赖 Highcharts 为我们提供控件来过滤我们的数据，而是应该能够通过改变 Highcharts 将呈现的数据来进行过滤。

在以下 Highcharts 代码中，我们为我们的页面添加了以下容器分隔符；首先，我们使用 JavaScript 从我们的 Elasticsearch 引擎获取数据：

```php
<script> 

$(function () {  
client.search({ 
index: 'apachelogs', 
type: 'logs', 
body: { 
query: { 
       "match_all": { 

       }, 
       {  
         "range": { 
             "epoch_date": { 
               "lt": <?php echo mktime(0,0,0, date('n'), date('j'), date('Y') ) ?>, 

               "gte": <?php echo mktime(0,0,0, date('n'), date('j'), date('Y')+1 ) ?> 
          } 
         } 
       }  
          } 
       } 
}).then(function (resp) { 
var hits = resp.hits.hits; 
varlogCounts = new Array(); 
    _.map(resp.hits.hits, function(count) 
    {logCounts.push(count.count)}); 

  $('#container').highcharts({ 
chart: { 
type: 'bar' 
        }, 
title: { 
text: 'Apache Logs' 
        }, 
xAxis: { 
categories: logDates 
        }, 
yAxis: { 
title: { 
text: 'Log Volume' 
            } 
        }, 
   plotLines: [{ 
         value: 0, 
         width: 1, 
         color: '#87D82F' 
         }] 
   }, 
   tooltip: { 
   valueSuffix: ' logs' 
    }, 
   plotOptions: { 
   series: { 
         cursor: 'pointer', 
         point: { 
   }, 
   marker: { 
   lineWidth: 1 
       } 
     } 
   }, 
   legend: { 
         layout: 'vertical', 
         align: 'right', 
         verticalAlign: 'middle', 
         borderWidth: 0 
      }, 
   series: [{ 
   name: 'Volumes', 
   data: logCounts 
       }] 
      });  

}, function (err) { 
console.trace(err.message); 
    $('#container').html('We did not get any data'); 
}); 

}); 
   </script> 

   <div id="container" style="width:100%; height:400px;"></div> 

```

这是使用 JavaScript 的 filter 命令进行的，然后将数据解析到我们的 Highcharts 图表中。您还需要使用 underscore 进行过滤功能，这将有助于确定我们要向用户呈现哪些数据。

让我们首先构建过滤我们的 Highcharts 直方图的表单。

这是 CRUD 视图中搜索过滤器的 HTML 代码将是这样的：

```php
<form> 
<select name="date_start" id="dateStart"> 
<?php 
$aWeekAgo = date('Y-m-d H:i:s', mktime( 7 days)) 
    $aMonthAgo = date(Y-m-d H:i:s', mktime( -30));    
//a month to a week 
<option value="time">Time start</option> 
</select> 
<select name="date_end" id="dateEnd"> 
<?php 
    $currentDate= date('Y-m-d H:i:s');        
$nextWeek = date('', mktime(+7 d)); 
    $nextMonth = date( ,mktime (+30)); 
?> 
<option value=""><?php echo substr($currentData,10);?> 
</option> 
<button id="filter" name="Filter">Filter</button> 
</form> 

```

为了实现图表的快速重新渲染，我们必须在每次单击过滤按钮时使用普通的 JavaScript 附加一个监听器，然后简单地擦除包含我们的 Highcharts 图表的`div`元素的信息。

以下 JavaScript 代码将使用 jQuery 和 underscore 更新过滤器，并在第一个条形图中使用相同的代码：

```php
<script src="https://code.jquery.com/jquery-2.2.4.min.js" integrity="sha256-BbhdlvQf/xTY9gja0Dq3HiwQF8LaCRTXxZKRutelT44=" crossorigin="anonymous"></script> 

<script src="txet/javascript"> 
$("button#filter").click {  
dateStart = $('input#dateStart').val().split("/"); 
dateEnd = $('input#dateEnd').val().split("/"); 
epochDateStart = Math.round(new Date(parseInt(dateStart[])]), parseInt(dateStart[1]), parseInt(dateStart[2])).getTime()/1000); 
epochDateEnd = Math.round(new Date(parseInt(dateEnd [])]), parseInt(dateEnd [1]), parseInt(dateEnd[2])).getTime()/1000); 

       }; 

client.search({ 
index: 'apachelogs', 
type: 'logs', 
body: { 
query: { 
       "match_all": { 

       }, 
       {  
         "range": { 
             "epoch_date": { 
               "lt": epochDateStart, 

               "gte": epochDateEnd 
          } 
         } 
       }  
          } 
       } 
}).then(function (resp) { 
var hits = resp.hits.hits; //look for hits per day fromelasticsearch apache logs 
varlogCounts = new Array(); 
    _.map(resp.hits.hits, function(count) 
    {logCounts.push(count.count)}); 

$('#container').highcharts({ 
chart: { 
type: 'bar' 
        }, 
title: { 
text: 'Apache Logs' 
        }, 
xAxis: { 
categories: logDates 
        }, 
yAxis: { 
title: { 
text: 'Log Volume' 
            } 
        } 

   }); 
}); 
</script> 

```

在上述代码中，我们已经包含了`jquery`和 underscore 库。当单击按钮以聚焦某些日期时，我们通过表单设置`$_GET['date']`，然后 PHP 使用一个简单的技巧获取信息，即通过简单地刷新包含图表的`div`，然后要求 Highcharts 重新渲染数据。

为了使这更酷一些，我们可以使用 CSS 动画效果，使其看起来像我们正在聚焦相机。

这可以通过 jQuery CSS 变换技术来实现，然后将其调整回正常大小并重新加载新的图表：

```php
$("button#filter").click( function() { 
   //..other code 
  $("#container").animate ({ 
width: [ "toggle", "swing" ], 
height: [ "toggle", "swing" ] 
}); 

}); 

```

现在我们已经学会了如何使用 JavaScript 进行过滤，并允许使用过滤样式过滤 JSON 数据。请注意，过滤是一个相对较新的 JavaScript 函数；它是在**ECMAScript 6**中引入的。我们已经使用它来创建高层管理人员需要能够为其自己的目的生成报告的仪表板。

我们可以使用 underscore 库，它具有过滤功能。

我们将只加载 Elasticsearch 中的最新日志，然后，如果我们想要执行搜索，我们将创建一种过滤和指定要在日志中搜索的数据的方法。

让我们创建 Apache 日志的 Logstash 配置，以便 Elasticsearch 进行处理。

我们只需要将输入 Logstash 配置指向我们的 Apache 日志位置（通常是`/var/log/apache2`目录中的文件）。

这是 Apache 的基本 Logstash 配置，它读取位于`/var/log/apache2/access.log`的 Apache 访问日志文件：

```php
input {    file { 
path => '/var/log/apache2/access.log' 
        } 
} 

filter { 
grok { 
    match =>{ "message" => "%{COMBINEDAPACHELOG}" } 
  } 
date { 
match => [ "timestamp" , "dd/MMM/yyyy:HH:mm:ss Z" ] 
  } 
} 

```

它使用称为 grok 过滤器的东西，它匹配任何类似于 Apache 日志格式的内容，并将时间戳匹配到`dd/MMM/yyyy:HH:mm:ss Z`日期格式。

如果您将 Elasticsearch 视为彩虹的终点，将 Apache 日志视为彩虹的起点，那么 Logstash 就像是将日志从两端传输到 Elasticsearch 可以理解的格式的彩虹。

**Grokking**是用来描述将消息格式重新格式化为 Elasticsearch 可以解释的内容的术语。这意味着它将搜索一个模式，并过滤匹配该模式的内容，特别是它将在 JSON 中查找日志的时间戳和消息以及其他属性，这是 Elasticsearch 存储在其数据库中的内容。

## 用于查看 Elasticsearch 日志的仪表板应用

现在让我们为我们的博客创建一个仪表板，以便我们可以查看我们在 Elasticsearch 中的数据，包括帖子和 Apache 日志。我们将使用 PHP Elasticsearch SDK 来查询 Elasticsearch 并显示 Elasticsearch 结果。

我们将只加载 Elasticsearch 中的最新日志，然后，如果我们想要执行搜索，我们将创建一种过滤和指定要在日志中搜索的数据的方法。

这是搜索过滤表单的样子：

![用于查看 Elasticsearch 日志的仪表板应用](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-bp/img/image_04_007.jpg)

在`search.php`中，我们将创建一个简单的表单来搜索 Elasticsearch 中的值：

```php
<form action="search_elasticsearch.php" method="post"> 
<table> 
   <tr> 
<td>Select time or query search term 
<tr><td>Time or search</td> 
<td><select> 
    <option value="time">Time</option> 
     <option value="query">Query Term</option> 
<select> 
</td>  
</tr> 
<tr> 
<td>Time Start/End</td> 
  <td><input type="text" name="searchTimestart" placeholder="YYYY-MM-DD HH:MM:SS" > /  
  <input type="text" name="searchTimeEnd" placeholder="YYYY-MM-DD HH:MM:SS" > 
</td> 
</tr> 
<tr> 
<td>Search Term:</td><td><input name="searchTerm"></td> 
</tr> 
<tr><td colspan="2"> 
<input type="submit" name="search"> 
</td></tr> 
</table> 
</form> 

```

当用户点击**提交**时，我们将向用户显示结果。

我们的表单应该简单地显示出我们当天对于 Apache 日志和博客文章的记录。

这是我们在命令行中使用 curl 查询`ElasticSearch`信息的方式：

```php
**$ curl http://localhost:9200/_search?q=post_date>2016-11-15**

```

现在我们将从 Elasticsearch 获得一个 JSON 响应：

```php
{"took":403,"timed_out":false,"_shards":{"total":5,"successful":5,"failed":0},"hits":{"total":1,"max_score":0.01989093,"hits":[{"_index":"posts","_type":"post","_id":"1","_score":0.01989093,"_source":{ 
  body: { 
    "user" : "kimchy", 
    "post_date" : "2016-11-15T14:12:12", 
    "post_body" : "trying out Elasticsearch" 
  }  
}}]}} 

```

我们也可以使用 REST 客户端（一种在 Firefox 中查询 RESTful API 的方式）来查询数据库，只需指定`GET`方法和路径，并在 URL 中设置`q`变量为您想要搜索的参数：

![用于查看 Elasticsearch 日志的仪表板应用](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-bp/img/image_04_008.jpg)

## 带有结果缓存的简单搜索引擎

要安装 PHP Redis，请访问[`github.com/phpredis/phpredis`](https://github.com/phpredis/phpredis)。

每次用户搜索时，我们可以将他们最近的搜索保存在 Redis 中，如果已经存在，就直接呈现这些结果。实现可能如下所示：

```php
<?php 
$db = new mysqli(HOST, DB_USER, DB_PASSWORD, DB_NAME); //define the connection details 

if(isset($_POST['search'])) {  

$hashSearchTerm = md5($_POST['search']); 
    //get from redis and check if key exist,  
    //if it does, return search result    
    $rKeys = $redis->keys(*); 

   if(in_array($rKeys, $hashSearchTerm){  
         $searchResults =  $redis->get($hashSearchTerm); 
         echo "<ul>"; 
         foreach($searchResults as $result) { 
                 echo "<li> 
     <a href="readpost.php?id=" . $result ['postId']. "">".$result['postTitle'] . "</a> 
        </li>" ; 
         echo "</ul>"; 
        } 
   } else { 
     $query = "SELECT * from posts WHERE post_title LIKE '%".$_POST['search']."%' OR post_content LIKE '%".$_POST['search']."%'"; 

     $result = $db->query($query); 
     if($result->num_rows() > 0) { 
     echo "<ul>;" 
     while ($row = $result->fetch_array(MYSQL_BOTH))  
       { 
       $queryResults = [ 
       'postId' => $row['id'], 
       'postTitle' => $row['post_title']; 
        ]; 

        echo "<li> 
     <a href="readpost.php?id=" . $row['id']. "">".$row['post_title'] . "</a> 
        </li>" ; 
       } 
     echo "</ul>"; 

     $redis->setEx($hashSearchTerm, 3600, $queryResults); 

     } 
   } 
} //end if $_POST 
else { 
  echo "No search term in input"; 
} 
?> 

```

Redis 是一个简单的字典。它在数据库中存储一个键和该键的值。在前面的代码中，我们使用它来存储用户搜索结果的引用，这样下次执行相同的搜索时，我们可以直接从 Redis 数据中获取。

在前面的代码中，我们将搜索词转换为哈希，以便可以轻松地识别为通过的相同查询，并且可以轻松地存储为键（应该只有一个字符串，不允许空格）。如果在哈希后在 Redis 中找到键，那么我们将从 Redis 中获取它，而不是从数据库中获取它。

Redis 可以通过使用`$redis->setEx`方法保存键并在*X*秒后使其过期。在这种情况下，我们将其存储 3,600 秒，相当于一个小时。

## 缓存基础

缓存的概念是将已经搜索过的项目返回给用户，这样对于其他正在搜索相同搜索结果的用户，应用程序就不再需要从 MySQL 数据库中进行完整的数据库提取。

拥有缓存的坏处是您必须执行缓存失效。

### Redis 数据的缓存失效

**缓存失效**是指当您需要过期和删除缓存数据时。这是因为您的缓存在一段时间后可能不再是实时的。当然，在失效后，您需要更新缓存中的数据，这发生在有新的数据请求时。缓存失效过程可以采用以下三种方法之一：

+   **清除**是指立即从缓存数据中删除内容。

+   **刷新**意味着获取新数据并覆盖已有数据。这意味着即使缓存中有匹配项，我们也将使用新信息刷新该匹配项。

+   **封禁**基本上是将先前缓存的内容添加到封禁列表中。当另一个客户端获取相同信息并在检查黑名单时，如果已存在，缓存的内容将被更新。

我们可以在后台连续运行 cron 作业，以更新该搜索的每个缓存结果为新的结果。

这是在 crontab 中每 15 分钟运行的后台 PHP 脚本可能的样子：

```php
0,15,30,45 * * * * php /path/to/phpfile 

```

要让 Logstash 将数据放入 Redis 中，我们只需要执行以下操作：

```php
# shipper from apache logs to redis data 
output { 
redis { host => "127.0.0.1" data_type => "channel" key => "logstash-%{@type}-%{+yyyy.MM.dd.HH}" } 
} 

```

这是删除缓存数据的 PHP 脚本的工作原理：

```php
functiongetPreviousSearches() { 
return  $redis->get('searches'); //an array of previously searched searchDates 
} 

$prevSearches = getPreviousSearches(); 

$prevResults = $redis->get('prev_results');  

if($_POST['search']) { 

  if(in_array($prevSEarches)&&in_array($prevResults[$_POST['search']])) { 
if($prevSEarches[$_POST['search'])] { 
            $redis->expire($prevSearches($_POST['searchDate'])) { 
         Return $prevResults[$_POST['search']]; 
} else { 
         $values =$redis->get('logstash-'.$_POST['search']); 
             $previousResults[] = $values; 
         $redis->set('prev_results', $previousResults); 

          } 

} 
     }   
  } 

```

在前面的脚本中，我们基本上检查了之前搜索的`searchDate`，如果有，我们将其设置为过期。

如果它也出现在`previousResults`数组中，我们将把它给用户；否则，我们将执行一个新的`redis->get`命令来获取搜索日期的结果。

## 使用浏览器的 localStorage 作为缓存

缓存存储的另一个选项是将其保存在客户端浏览器中。这项技术被称为**localStorage**。

我们可以将其用作用户的简单缓存，并存储搜索结果，如果用户想搜索相同的内容，我们只需检查 localStorage 缓存。

### 提示

`localStorage`只能存储 5MB 的数据。但考虑到常规文本文件只有几千字节，这已经相当多了。

我们可以利用`elasticsearch.js`客户端而不是 PHP 客户端来向 Elasticsearch 发出请求。浏览器兼容版本可以从[`www.elastic.co/guide/en/elasticsearch/client/javascript-api/current/browser-builds.html`](https://www.elastic.co/guide/en/elasticsearch/client/javascript-api/current/browser-builds.html)下载。

我们还可以使用 Bower 来安装`elasticsearch.js`客户端：

```php
bower install elasticsearch 

```

为了达到我们的目的，我们可以利用 jQuery Build 通过创建一个使用 jQuery 的客户端：

```php
var client = new $.es.Client({ 
hosts: 'localhost:9200' 
}); 

```

现在我们应该能够使用 JavaScript 来填充`localStorage`。

由于我们只是在客户端进行查询和显示，这是完美的匹配！

请注意，我们可能无法使用客户端脚本记录搜索的数据。但是，我们可以将搜索查询历史保存为包含先前搜索的项目键的模型。

基本的 JavaScript `searchQuery`对象将如下所示：

```php
varsearchQuery = { 
search: {queryItems: [ { 
'title: 'someName',  
  'author': 'Joe',  
   'tags': 'some tags'}  
] }; 
}; 

```

我们可以通过运行以下 JavaScript 文件来测试客户端是否工作：

```php
client.ping({ 
requestTimeout: 30000, 

  // undocumented params are appended to the query string 
hello: "elasticsearch" 
}, function (error) { 
if (error) { 
console.error('elasticsearch cluster is down!'); 
  } else { 
console.log('All is well'); 
  } 
}); 

```

通过以下方式，搜索结果可以缓存在`localStorage`中：

```php
localStorage.setItem('results',JSON.stringify(results)); 

```

我们将使用从`elasticsearch`中找到的数据填充结果，然后只需检查之前是否进行了相同的查询。

我们还需要保持数据的新鲜。假设大约需要 15 分钟，用户会感到无聊并刷新页面以查看新信息。

同样，我们检查过去是否显示过搜索结果：

```php
var searches = localStorage.get('searches'); 
if(searches != mktime( date('H'), date('i')-15) ) { 
  //fetch again 
varsearchParams = { 
index: 'logdates', 
body:  
query: { 
match: { 
date: $('#search_date').value; 

} 
client.search(); 
} else { 
  //output results from previous search; 
prevResults[$("#search_date").val()]; 
} 

```

现在，每当我们过期搜索条件，比如大约 15 分钟后，我们将简单地清除缓存并放入 Elasticsearch 找到的新搜索结果。

## 使用流处理

在这里，我们将利用 PHP 的 Monolog 库，然后流式传输数据而不是推送完整的字符串。使用流的好处是它们可以轻松地管道到 Logstash 中，然后将其作为索引数据存储到 Elasticsearch 中。Logstash 还具有创建数据流和流式传输数据的功能。

我们甚至可以在不使用 Logstash 的情况下直接输入我们的数据，使用一种称为流的东西。有关流的更多信息，请参阅[`php.net/manual/en/book.stream.php`](http://php.net/manual/en/book.stream.php)。

例如，以下是将一些数据推送到 Elasticsearch 的方法：`http://localhost/dev/streams/php_input.php`：

```php
curl -d "Hello World" -d "foo=bar&name=John" http://localhost/dev/streams/php_input.php 

```

在`php_input`中，我们可以放入以下代码：

```php
readfile('php://input') 

```

我们将获得`Hello World&foo=bar&name=John`，这意味着 PHP 能够使用 PHP 输入流获取第一个字符串作为流。

要玩转 PHP 流，让我们手动使用 PHP 创建一个流。PHP 开发人员通常在处理输出缓冲时已经有一些处理流数据的经验。

输出缓冲的想法是收集流直到完整，然后将其显示给用户。

当流尚未完成并且我们需要等待数据的结束字符以完全传输数据时，这是特别有用的。

我们可以将流推送到 Elasticsearch！这可以通过使用 Logstash 输入插件来处理流来实现。这就是 PHP 如何输出到流的方式：

```php
<?php 
require 'vendor/autoload.php'; 
$client = new Elasticsearch\Client(); 
ob_start(); 
$log['body'] = array('hello' => 'world', 'message' => 'some test'); 
$log['index'] = 'test'; 
$log['type'] = 'log'; 
echo json_encode($log);  
//flush output of echo into $data 
$data = ob_get_flush(); 
$newData = json_decode($data); //turn back to array 
$client->index($newData); 

```

## 使用 PHP 存储和搜索 XML 文档

我们还可以处理 XML 文档并将其插入到 Elasticsearch 中。为此，我们可以将数据转换为 JSON，然后将 JSON 推送到 Elasticsearch 中。

首先，您可以查看以下 XML 转 JSON 转换器：

如果您想检查 XML 是否已正确转换为 JSON，请查看[`codebeautify.org/xmltojson`](http://codebeautify.org/xmltojson)上的**XML TO JSON Converter**工具；从那里，您可以轻松查看如何将 XML 导出为 JSON：

![使用 PHP 存储和搜索 XML 文档](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-bp/img/image_04_009.jpg)

## 使用 Elasticsearch 搜索社交网络数据库

在本节中，我们将简单地使用我们的知识将其应用于使用 PHP 构建的现有社交网络。

假设我们有用户希望能够搜索他们的社交动态。这就是我们构建完整的自动下拉搜索系统的地方。

每当用户发布帖子时，我们需要能够将所有数据存储在 Elasticsearch 中。

然而，在我们的搜索查询中，我们将匹配搜索结果与用户提取的实际单词。如果它不与每个查询逐字匹配，我们将不显示它。

我们首先需要构建动态信息流。SQL 模式如下所示：

```php
CREATE TABLE feed ( 
Id INT(11) PRIMARY KEY, 
Post_title TEXT, 
post_content TEXT, 
post_topics TEXT, 
post_time DATETIME, 
post_type VARCHAR(255), 
posted_by INT (11) DEFAULT '1'  
) ; 

```

`Post_type`将处理帖子的类型 - 照片、视频、链接或纯文本。

因此，如果用户添加了一种图片类型，它将被保存为图像类型。当某人搜索帖子时，他们可以按类型进行筛选。

每当用户保存新照片或新帖子时，我们还将数据存储到 Elasticsearch 中，如下所示：

```php
INSERT INTO feed (`post_title`, `post_content`, `post_time`, `post_type`) VALUES ('some title', 'some content', '2015-03-20 00:00:00', 'image', 1); 

```

现在我们需要在用户插入前面的新帖子时制作一个输入表单。我们将构建一个可以上传带标题的照片或只添加文本的表单：

```php
<h2>Post something</h2> 

<form type="post" action="submit_status.php" enctype="multipart/form-data"> 
Title:<input name="title" type="text" /> 
Details: <input name="content" type="text"> 
Select photo:  
<input type="file" name="fileToUpload" id="fileToUpload"> 
<input type="hidden" value="<?php echo $_SESSION['user_id'] ?>" name="user_id"> 
<input name="submit" type="submit"> 

</form> 

```

`submit_status.php`脚本将包含以下代码以保存到数据库中：

```php
<?php 
use Elasticsearch\ClientBuilder; 

   require 'vendor/autoload.php'; 

$db = new mysqli(HOST, DB_USER, DB_PASSWORD, DATABASE); 

 $client = ClientBuilder::create()->build(); 
if(isset($_POST['submit'])) { 
  $contentType = (!empty($_FILES['fileToUpload'])) ? 'image' : ' 

$db->query("INSERT INTO feed (`post_title`, `post_content`, `post_time`, `post_type`, `posted_by`)  
VALUES ('". $_POST['title'] ."','" . $_POST['content'] . "','" . date('Y-m-d H:i:s'). "','" . $contentType . "','" . $_POST['user_id']); 

//save into elasticsearch 
$params = [ 
    'index' => 'my_feed', 
    'type' => 'posts', 
    'body' => [  
      'contenttype' => $contentType, 
      'title'  => $_POST['title'], 
      'content' => $_POST['content'],         
      'author' => $_POST['user_id'] 
    ] 
]; 
       $client->index($params); 
  } 

 ?> 

```

### 显示随机搜索引擎结果

前面的动态信息流数据库表是每个人都会发布的表。我们需要启用随机显示信息流中的内容。我们可以将帖子插入到信息流中而不是存储。

通过从 Elasticsearch 搜索并随机重新排列数据，我们可以使我们的搜索更有趣。在某种程度上，这确保了使用我们的社交网络的人能够在其信息流中看到随机的帖子。

要从帖子中搜索，我们将不直接查询 SQL，而是搜索 Elasticsearch 数据库中的数据。

首先，让我们弄清楚如何将数据插入名为`posts`的 Elasticsearch 索引中。打开 Elasticsearch 后，我们只需执行以下操作：

```php
$ curl-XPUT 'http://localhost:9200/friends/'-d '{ 
"settings":{ 
"number_of_shards":3, 
"number_of_replicas":2 
} 
}' 

```

我们可能也想搜索我们的朋友，如果我们有很多朋友，他们不会全部出现在动态中。所以，我们只需要另一个用于搜索的索引，称为`friends`索引。

在 Linux 命令行中运行以下代码将允许我们创建一个新的`friends`索引：

```php
$ curl-XPUT 'http://localhost:9200/friends/'-d '{ 
"settings":{ 
"number_of_shards":3, 
"number_of_replicas":2 
} 
}' 

```

因此，我们现在可以使用`friends`索引存储关于我们朋友的数据。

```php
$ curl-XPUT 'http://localhost:9200/friends/posts/1'-d '{ 
"user":"kimchy", 
"post_date":"2016-06-15T14:12:12", 
"message":"fred the friend" 
}' 

```

通常我们会寻找朋友的朋友，当然，如果有任何朋友符合搜索条件，我们会向用户展示。

## 总结

在本章中，我们讨论了如何创建一个博客系统，尝试了 Elasticsearch，并能够做到以下几点：

+   创建一个简单的博客应用程序并将数据存储在 MySQL 中

+   安装 Logstash 和 Elasticsearch

+   使用 curl 练习与 Elasticsearch 一起工作

+   使用 PHP 客户端将数据导入 Elasticsearch

+   使用 Highcharts 从 Elasticsearch 中的图表信息（点击数）

+   使用`elasticsearch.js`客户端查询 Elasticsearch 获取信息

+   在浏览器中使用 Redis 和 localStorage 进行缓存处理


# 第五章：创建 RESTful Web 服务

本章的目标是实现一个 RESTful Web 服务，用于管理用户配置文件。每个用户将具有一些基本的联系信息（例如用户名、名字和姓氏）、用于认证的密码和个人资料图片。

这项服务将使用 Slim 微框架实现，这是一个小巧轻便的框架，作为 PHP 5.5 及更新版本的开源库（MIT 许可）提供（当然我们将使用 PHP 7）。为了持久性，将使用 MongoDB 数据库。这提供了一个完美的机会来探索 PHP 的 MongoDB 扩展，它取代了旧的（同名，但完全不同）在 PHP 7 中被移除的 Mongo 扩展。

在本章中，我们将涵盖以下内容：

+   RESTful Web 服务的基础知识，最重要的是常见的 HTTP 请求和响应方法

+   安装和使用 Slim 框架，以及 PSR-7 标准的基础知识

+   使用 Slim 框架和 MongoDB 存储设计和实现实际示例 RESTful Web 服务

+   如何使用 PSR-7 流和在 MongoDB 数据库中使用 GridFS 存储大文件

# RESTful 基础知识

在本节中，我们将重述 RESTful Web 服务的基础知识。您将了解 REST Web 服务的基本架构目标以及**超文本传输协议**（**HTTP**）的最常见协议语义，通常用于实现此类服务。

## REST 架构

**表现状态转移**这个术语是由 Roy Fielding 在 2000 年创造的，描述了一种分布式系统的架构风格，原则上独立于任何具体的通信协议。实际上，大多数 REST 架构都是使用**超文本传输协议**来实现的，简称 HTTP。

每个 RESTful Web 服务的关键组件是资源。每个资源应满足以下要求：

+   **可寻址性**：每个资源必须由**统一资源标识符**（**URI**）进行标识，这在 RFC 3986 中得到了标准化。例如，具有用户名`johndoe`的用户可能具有 URI`http://example.com/api/users/johndoe`。

+   **无状态性**：参与者之间的通信是无状态的；这意味着 REST 应用程序通常不使用用户会话。相反，每个请求都需要包含服务器需要满足请求的所有信息。

+   **统一接口**：每个资源必须可通过一组标准方法访问。当使用 HTTP 作为传输协议时，您通常会使用 HTTP 方法来查询或修改资源的状态。本章的下一节包含对最常见的 HTTP 标准方法和响应代码的简要概述。

+   **资源和表示的解耦**：每个资源可以有多个表示。例如，REST 服务可能同时提供用户配置文件的 JSON 和 XML 表示。通常，客户端会指定服务器应该以哪种格式响应，服务器将选择最符合客户端指定要求的表示。这个过程称为**内容协商**。

在本章中，您将学习如何在一个小型的 RESTful Web 服务中实现所有这些架构原则。您将实现几种不同类型的资源，具有不同的表示，并学习如何使用不同的 HTTP 方法和响应代码来查询和修改这些资源。此外，您还将学习如何利用高级的 HTTP 功能（例如丰富的缓存控制头集）。

## 常见的 HTTP 方法和响应代码

HTTP 定义了一组标准方法（或*动词*），客户端可以在请求中使用，以及服务器可以在响应中使用的状态代码。在 REST 架构中，不同的请求方法用于查询或修改由请求 URI 标识的资源的服务器端状态。这些请求方法和响应状态代码在 RFC 7231 中标准化。**表 1**和**表 2**显示了最常见的请求方法和状态代码的概述。

请求方法`GET`，`HEAD`和`OPTIONS`被定义为*安全*。服务器在处理这些类型的请求时不应修改自己的状态。此外，安全方法和`PUT`和`DELETE`方法都被定义为*幂等*。幂等性意味着重复的相同请求应具有与单个请求相同的效果-例如，对`/api/users/12345` URI 的多个`DELETE`请求仍应导致删除该资源。

表 1，常见的 HTTP 请求方法：

| **HTTP 方法** | **描述** |
| --- | --- |
| `GET` | 用于查询由 URI 标识的资源的状态。服务器将以查询的资源表示形式做出响应。 |
| `HEAD` | 就像`GET`一样，只是服务器返回响应头，而不是实际的资源表示。 |
| `POST` | `POST`请求可以在其请求体中包含资源表示。服务器应将此对象存储为请求 URI 标识的资源的新子资源。 |
| `PUT` | 就像`POST`一样，`PUT`请求也在其请求体中包含资源表示。服务器应确保具有给定 URI 和表示的资源存在，并且如果需要应创建一个资源。 |
| `DELETE` | 删除指定 URI 的资源。 |
| `OPTIONS` | 客户端可以使用它来查询给定资源允许哪些操作。 |

表 2：常见的 HTTP 响应状态代码：

| **状态代码** | **描述** |
| --- | --- |
| `200 OK` | 请求已成功处理；响应消息通常包含所请求资源的表示。 |
| `201 Created` | 像`200 OK`一样，但另外明确指出请求创建了一个新资源。 |
| `202 Accepted` | 请求已被接受处理，但尚未被处理。当服务器异步处理耗时请求时，这是有用的。 |
| `400 Bad Request` | 服务器无法解释客户端的请求。当请求包含无效的 JSON 或 XML 数据时可能会出现这种情况。 |
| `401 Unauthorized` | 客户端需要在访问此资源之前进行身份验证。响应可以包含有关所需身份验证的更多信息，并且请求可以使用适当的凭据重复。 |
| `403 Forbidden` | 当客户端经过身份验证，但未被授权访问特定资源时可以使用。 |
| `404 Not Found` | 当 URI 指定的资源不存在时使用。 |
| `405 Method Not Allowed` | 请求方法不允许指定的资源。 |
| `500 Internal Server Error` | 服务器在处理请求时发生错误。 |

# 使用 Slim 框架的第一步

在本节中，您将首先使用 Composer 安装框架，然后构建一个小型示例应用程序，该应用程序将向您展示框架的基本原则。

## 安装 Slim

Slim 框架可以很容易地使用 Composer 安装。它需要至少版本 5.5 的 PHP，但也可以很好地与 PHP 7 一起使用。首先通过 Composer 初始化一个新项目：

```php
**$ composer init .**

```

这将为我们的项目创建一个新的项目级`composer.json`文件。现在，您可以将 slim/slim 包添加为依赖项：

```php
**$ composer require slim/slim**

```

## 一个小样本应用程序

现在，您可以在您的 PHP 应用程序中开始使用 Slim 框架。为此，在您的 Web 服务器文档根目录中创建一个`index.php`文件，并包含以下内容：

```php
<?php 
use \Slim\App; 
use \Slim\Http\Request; 
use \Slim\Http\Response; 

require "vendor/autoload.php"; 

$app = new App(); 
$app->get("/", function(Request $req, Response $res): Response { 
    return $res->withJson(["message" => "Hello World!"]); 
}); 
$app->run(); 

```

让我们来看看 Slim 框架在这里是如何工作的。这里的中心对象是`$app`变量，它是`Slim\App`类的一个实例。然后可以使用这个应用实例来注册路由。每个路由都是一个将 HTTP 请求路径映射到处理 HTTP 请求的简单回调函数。这些处理函数需要接受一个请求和一个响应对象，并需要返回一个新的响应对象。

在测试这个应用程序之前，你可能需要配置你的 Web 服务器将所有请求重写到你的`index.php`文件。如果你正在使用 Apache 作为 Web 服务器，可以在你的文档根目录中使用一个简单的`.htaccess`文件来完成这个操作：

```php
RewriteEngine on 
RewriteCond %{REQUEST_FILENAME} !-f 
RewriteCond %{REQUEST_FILENAME} !-d 
RewriteRule ^([^?]*)$ /index.php [NC,L,QSA] 

```

这个配置将重写所有 URL 的请求到你的`index.php`文件。

你可以使用浏览器测试你的（尽管仍然非常简单的）API。如果你更喜欢命令行，我可以推荐使用 HTTPie 命令行工具。HTTPie 是基于 Python 的，你可以使用操作系统的软件包管理器或 Python 自己的软件包管理器 pip 轻松安装它：

```php
**apt-get install httpie**
**# Alternatively:**
**pip install --upgrade httpie**

```

然后你可以在命令行上使用`HTTPie`轻松执行 RESTful HTTP 请求，并获得语法高亮的输出。查看以下图例，了解在与示例应用程序一起使用 HTTPie 时的示例输出：

![一个小样例应用](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-bp/img/image_05_001.jpg)

使用 Slim 示例应用程序的 HTTPie 的示例输出

### 接受 URL 参数

Slim 路由也可以包含路径中的参数。在你的`index.php`中，在最后一个`$app->run()`语句之前添加以下路由：

```php
$app->get( 
    '/users/{username}', 
    function(Request $req, Response $res, array $args): Response { 
        return $res->withJson([ 
          'message' => 'Hello ' . $args['username' 
        ]); 
    } 
); 

```

正如你所看到的，任何路由规范都可以包含花括号中的任意参数。然后路由处理函数可以接受一个包含 URL 中所有路径参数的关联数组的第三个参数（例如前面示例中的用户名参数）。

## 接受带有消息体的 HTTP 请求

到目前为止，你只使用了 HTTP `GET`请求。当然，Slim 框架也支持 HTTP 协议定义的任何其他类型的请求方法。然而，`GET`和例如`POST`请求之间的一个有趣的区别是，一些请求（如`POST`、`PUT`等）可以包含请求体。

请求体由结构化数据组成，按照预定义的编码序列化为字符串。当向服务器发送请求时，客户端使用 Content-Type HTTP 头告诉服务器请求体使用的编码。常见的编码包括以下内容：

+   `application/x-www-form-urlencoded` 通常由浏览器在提交 HTML 表单时使用

+   `application/json` 用于 JSON 编码

+   `application/xml` 或 `text/xml` 用于 XML 编码

幸运的是，Slim 框架支持所有这些编码，并自动确定解析请求体的正确方法。你可以使用以下简单的路由处理程序进行测试：

```php
$app->post('/users', function(Request $req, Response $res): Response { 
    $body = $req->getParsedBody(); 
    return $response->withJson([ 
        'message' => 'creating user ' . $body['username'] 
    ]); 
}); 

```

注意使用`Request`类提供的`getParsedBody()`方法。这个方法将使用请求体，并根据请求中存在的 Content-Type 头自动使用正确的解码方法。

现在你可以使用之前介绍的任何内容编码来将数据`POST`到这个路由。可以使用以下 curl 命令进行简单测试：

```php
**$ curl -d '&username=martin&firstname=Martin&lastname=Helmich' http://localhost/users** 
**$ curl -d '{"username":"martin","firstname":"Martin","lastname":"Helmich"}' -H'Content-Type: application/json' http://localhost/users**
**$ curl -d '<user><username>martin</username><firstname>Martin</firstname><lastname>Helmich</lastname></user>' -H'Content-Type: application/xml'**

```

所有这些请求将从你的 Slim 应用程序中产生相同的响应，因为它们包含完全相同的数据，只是使用了不同的内容编码。

## PSR-7 标准

Slim 框架的主要特性之一是 PSR-7 兼容性。PSR-7 是由 PHP 框架互操作性组（FIG）定义的 PHP 标准推荐（PSR），描述了一组标准接口，可以由 PHP 编写的 HTTP 服务器和客户端库实现，以增加这些产品之间的可操作性（或者用简单的英语来说，使这些库可以相互使用）。

PSR-7 定义了框架可以实现的一组 PHP 接口。下图说明了 PSR-7 标准定义的接口。您甚至可以通过使用 Composer 获取`psr/http-messages`包在您的项目中安装这些接口：

![PSR-7 标准](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-bp/img/image_05_002.jpg)

PSR-7 标准定义的接口

您在之前的示例中使用的`Slim\Http\Request`和`Slim\Http\Response`类已经实现了这些 PSR-7 接口（`Slim\Http\Request`类实现了`ServerRequestInterface`，`Slim\Http\Response`实现了`ResponseInterface`）。

当您想要将两个不同的 HTTP 库一起使用时，这些标准化的接口变得特别有用。作为一个有趣的例子，考虑一个 PSR-7 兼容的 HTTP 服务器框架，比如与一个 PSR-7 兼容的客户端库一起使用，例如**Guzzle**（如果要使用 Composer 安装，请使用包键`guzzlehttp/guzzle`）。您可以使用这两个库，并轻松地将它们连接在一起，实现一个非常简单的反向代理：

```php
$httpClient = new \GuzzleHttp\Client(); 

$app = new \Slim\App(); 
$app->any('{path:.*}', 
    function( 
        ServerRequestInterface $req, 
        ResponseInterface $response 
    ) use ($client): ResponseInterface { 
        return $client->send( 
            $request->withUri( 
                $request->getUrl()->withHost('your-upstream-server.local') 
            ) 
        ); 
    } 
); 

```

这里到底发生了什么？Slim 请求处理程序将`ServerRequestInterface`的实现作为第一个参数传递（记住；这个接口继承了常规的`RequestInterface`），并且需要返回一个`ResponseInterface`的实现。方便的是，`GuzzleHttp\Client`的`send()`方法也接受`RequestInterface`并返回`ResponseInterface`。因此，您可以简单地重用您在处理程序中收到的请求对象，并将其传递到 Guzzle 客户端中，并且还可以重用 Guzzle 客户端返回的响应对象。Guzzle 的`send()`方法实际上返回`GuzzleHttp\Psr7\Response`类的实例（而不是`Slim\Http\Response`）。这是完全可以接受的，因为这两个类都实现了相同的接口。此外，前面的示例使用了 PSR-7 接口定义的方法来修改请求 URI 的主机部分。

### 提示

**不可变对象** 您可能会对前面示例中的`withUri`和`withHost`方法感到好奇。为什么 PSR-7 接口没有声明`setUri`或`setHost`等方法？答案是所有 PSR-7 实现都设计为不可变。这意味着对象在创建后不打算被修改。所有以`with`开头的方法（实际上 PSR-7 定义了很多）都旨在返回原始对象的副本，其中一个属性被修改。因此，基本上，您将传递原始对象的克隆，而不是使用 setter 方法修改对象：

`// 使用可变对象（不受 PSR-7 支持）`

`$uri->setHost('foobar.com');`

`// 使用不可变对象`

`$uri = $uri->withHOst('foobar.com');`

## 中间件

中间件是 Slim 框架和类似库中最重要的功能之一。它允许您在将 HTTP 请求传递给实际请求处理程序之前修改 HTTP 请求，在从请求处理程序返回后修改 HTTP 响应，或者完全绕过请求处理程序。这有很多可能的用例：

+   您可以在中间件中处理身份验证和授权。身份验证包括从给定的请求参数中识别用户（也许 HTTP 请求包含授权头或包含会话 ID 的 cookie），授权涉及检查经过身份验证的用户是否实际被允许访问特定资源。

+   您可以通过计算特定用户的请求次数并在实际请求处理程序之前返回错误响应代码来为您的 API 实现速率限制。

+   总的来说，所有在请求被请求处理程序处理之前丰富请求的各种操作。

中间件也是可链接的。框架可以管理任意数量的中间件组件，并且传入的请求将通过所有注册的中间件。每个中间件项必须作为函数可调用，并接受 `RequestInterface`、`ResponseInterface` 和表示下一个中间件实例（或请求处理程序本身）的函数。

以下代码示例显示了一个向应用程序添加（诚然非常简单的）HTTP 身份验证的中间件：

```php
**$app->add(function (Request $req, Response $res, callable $next): Response {**
**    $auth = $req->getHeader('Authorization');**
**    if (!$auth) {**
**        return $res->withStatus(401);**
**    }**
**    if (substr($auth, 0, 6) !== 'Basic ' ||**
**        base64_decode(substr($auth, 6)) !== 'admin:secret') {**
**        return $res->withStatus(401);**
**    }**
**    return $next($req, $res);**
**}**

$app->get('/users/{username}', function(Request $req, Response $res): Response {
    // Handle the request
});

$app->get('/users/{username}', function(Request $req, Response $res): Response { 
    // Handle the request 
}); 

```

`$app->add()` 函数可用于注册中间件，该中间件将在任何请求上被调用。正如你所看到的，中间件函数本身看起来类似于常规请求处理程序，唯一的区别是第三个参数 `$next`。每个请求可以通过潜在的不确定数量的中间件。`$next` 函数使得中间件组件可以控制请求是否应该传递给链中的下一个中间件组件（或注册的请求处理程序本身）。然而，需要注意的是，中间件不必在任何时候调用 `$next` 函数。在上面的例子中，未经授权的 HTTP 请求甚至不会通过实际的请求处理程序，因为处理身份验证的中间件在没有有效身份验证时根本不调用 `$next`。

这就是 PSR-7 起作用的地方。由于 PSR-7，您可以开发和分发中间件，并且它们将与实现 PSR-7 的所有框架和库一起工作。这保证了库之间的互操作性，并确保存在可以广泛重用的库的共享生态系统。简单的互联网搜索 `PSR-7 中间件` 将产生大量几乎可以立即使用的库。

# 实现 REST 服务

在本章中，您将开始实现实际的用户配置文件服务。作为第一步，我们将设计服务的 RESTful API，然后继续实现设计的 API 端点。

## 设计服务

现在是时候开始实现本章中要实现的实际任务了。在本章中，您将使用 Slim 框架和 MongoDB 开发一个 RESTful Web 服务，以访问和读取用户配置文件。简而言之，在设计 REST Web 服务时，您应该考虑要向用户提供的资源的第一步。

### 提示

**保持 RESTful** 请确保围绕使用 `POST`、`PUT` 和 `DELETE` 等 HTTP 动词修改状态的资源进行设计。我经常看到围绕过程而不是资源开发的 HTTP API，最终导致 URL，例如 `POST /users/create` 或 `POST /users/update`，更像是基于 RPC 的 API 设计。

以下表格显示了本章中将使用的资源和操作。有一些中心资源：

+   `/profiles` 是所有已知配置文件的集合。它是只读的 - 意味着只允许 `GET`（和 `HEAD`）操作 - 并包含所有用户配置文件的集合。您的 API 的用户应该能够通过一组约束来过滤集合或将返回的集合限制为给定长度。过滤和限制都可以作为可选查询参数实现：

```php
      GET /profiles?firstName=Martin&limit=10 

```

+   `/profiles/{username}` 是代表单个用户的资源。对此资源的 `GET` 请求将返回该用户的配置文件，而 `PUT` 请求将创建配置文件或更新已存在的配置文件，`DELETE` 请求将删除配置文件。

+   `/profiles/{username}/image` 代表用户的配置文件图像。可以使用 `PUT` 操作设置它，使用 `GET` 操作读取它，并使用 `DELETE` 操作删除它。

| **路由** | **目的** |
| --- | --- |
| `GET /profiles` | 列出所有用户，可选择按搜索参数过滤 |
| `GET /profiles/{username}` | 返回单个用户 |
| `PUT /profiles/{username}` | 创建具有给定用户名的新用户，或更新已存在的具有该用户名的用户 |
| `DELETE /profiles/{username}` | 删除用户 |
| `PUT /profiles/{username}/image` | 为用户存储新的个人资料图片 |
| `GET /profiles/{username}/image` | 检索用户的个人资料图片 |
| `DELETE /profiles/{username}/image` | 删除个人资料图片 |

可能会出现的一个问题是，为什么这个例子使用`PUT`请求来创建新的个人资料，而不是`POST`。我经常看到`POST`与*创建对象*相关联，`PUT`与*更新对象*相关联 - 这是对 HTTP 标准的错误解释。请注意，我们将用户名作为个人资料的 URI 的一部分。这意味着当为具有给定用户名的新用户创建个人资料时，您已经知道资源在创建后将具有哪个 URI。

这正是`PUT`资源的作用 - 确保具有给定表示的资源存在于给定的 URI 中。优点是您可以依赖`PUT`请求是幂等的。这意味着对`/profiles/martin-helmich`的十几个相同的`PUT`请求不会造成任何伤害，而对`/profiles/`的十几个相同的`POST`请求很可能会创建十几个不同的用户资料。

## 启动项目

在开始实现 REST 服务之前，您可能需要处理一些系统要求。为了简单起见，我们将在这个例子中使用一组链接的 Docker 容器。首先创建一个新的容器，使用官方的 MongoDB 镜像运行一个 MongoDB 实例：

```php
 ****$ docker run --name profiles-db -d mongodb**** 

```

对于应用程序容器，您可以使用官方的 PHP 镜像。但是，由于 MongoDB PHP 驱动程序不是标准 PHP 分发的一部分，您需要通过**PECL**安装它。为此，您可以创建一个自定义的**Dockerfile**来构建您的应用程序容器：

```php
FROM php:7-apache 

RUN apt-get update && \ 
    apt-get install -y libssl-dev && \ 
    pecl install mongodb && \ 
    docker-php-ext-enable mongodb 
RUN a2enmod rewrite 

```

接下来，构建您的容器并运行它。将其链接到已经运行的 MongoDB 容器：

```php
**$ docker build -t packt-chp5 .**
**$ docker run --name profiles-web --link profiles-db:db \**
**-v $PWD:/var/www/html -p 80:80 packt-chp5**

```

这将创建一个新的 Apache 容器，其中运行 PHP 7，并将当前工作目录映射到 Web 服务器的文档根目录。`-p 80:80`标志允许通过浏览器或命令行客户端使用`http://localhost`访问 Apache 容器。

就像本章的第一个例子一样，我们将使用 Composer 来管理项目的依赖关系和自动类加载。您可以从以下`composer.json`文件开始：

```php
{ 
    "name": "packt-php7/chp5-rest-example", 
    "type": "project", 
    "authors": [{ 
        "name": "Martin Helmich", 
        "email": "php7-book@martin-helmich.de" 
    }], 
    "require": { 
        "php": ">=7.0", 
        "slim/slim": "³.1", 
        "mongodb/mongodb": "¹.0", 
        "phpunit/phpunit": "⁵.1", 
        "ext-mongodb": "*" 
    }, 
    "autoload": { 
        "psr-4": { 
            "Packt\\Chp5": "src/" 
        } 
    } 
} 

```

创建`composer.json`文件后，使用`composer install`安装项目的依赖项。如果您没有在符合所有指定约束的环境中运行 Composer，可以在 Composer 命令中添加`--ignore-platform-reqs`标志。

在这个例子中，我们将使用 Composer 的 PSR-4 自动加载器，以`Packt\Chp5`作为基本命名空间，所有类都位于`src/`目录中。这意味着类如`Packt\Chp5\Foo\Bar`需要在文件`src/Foo/Bar.php`中定义。

## 使用 MongoDB 构建持久层

在这个例子中，我们将采取的第一步是构建应用程序域的面向对象模型 - 用户个人资料。在第一步中，这将不会过于复杂。让我们从定义一个`Profile`类开始，具有以下属性：

+   唯一标识用户并可用作登录用户名的用户名

+   给定的名字和姓氏

+   用户关心的兴趣和爱好列表

+   用户的生日

+   用户密码的哈希值，在以后用户在编辑自己的个人资料之前进行身份验证时会很有用（并防止他们编辑其他人的个人资料）

这可以作为一个简单的 PHP 类来实现。请注意，该类目前完全是不可变的，因为它的属性只能使用构造函数设置。此外，此类不包含任何持久性逻辑（意味着从数据库获取数据或将其放回）。遵循*关注点分离*，建模数据并将其持久化到数据库中是两个不同的关注点，应该在不同的类中处理。

```php
declare(strict_types = 1); 
namespace Packt\Chp5\Model; 

class Profile 
{ 
    private $username; 
    private $givenName; 
    private $familyName; 
    private $passwordHash; 
    private $interests; 
    private $birthday; 

    public function __construct( 
        string $username, 
        string $givenName, 
        string $familyName, 
        string $passwordHash, 
        array $interests = [], 
        DateTime $birthday = null 
    ) { 
        $this->username     = $username; 
        $this->givenName    = $givenName; 
        $this->familyName   = $familyName; 
        $this->passwordHash = $passwordHash; 
        $this->interests    = $interests; 
        $this->birthday     = $birthday; 
    } 

    // getter methods omitted for brevity 
} 

```

现在，您可以在应用程序中建模用户配置文件-但是您还不能对其进行任何操作。我们的第一个目标将是将`Profile`类的实例存储在 MongoDB 数据库后端。这将在`Packt\Chp5\Service\ProfileService`类中完成：

```php
declare(strict_types = 1); 
namespace Packt\Chp5\Service; 

use MongoDB\Collection; 
use Packt\Chp5\Model\Profile; 

class ProfileService 
{ 
    private $profileCollection; 

    public function __construct(Collection $profileCollection) 
    { 
        $this->profileCollection = $profileCollection; 
    } 
} 

```

`ProfileService`将`MongoDB\Collection`类的实例作为依赖项传递到其构造函数中。这个类由`mongodb/mongodb` Composer 包提供，并且模型一个单一的 MongoDB 集合（虽然不完全正确，但集合是 MongoDB 等同于 MySQL 表）。同样，我们遵循关注点分离：建立与数据库的连接不是`ProfileService`的关注点，将在不同的地方处理。

让我们首先在此服务中实现一个方法，该方法可以将新用户配置文件添加到数据库中。这样的方法的合适名称是`insertProfile`：

```php
 **   public function insertProfile(Profile $profile): Profile**
**    {**
**        $record = $this->profileToRecord($profile);**
**        $this->profileCollection->insertOne($profile);**
**        return $profile;**
**    }**

    private function profileToRecord(Profile $profile): array 
    { 
        return [ 
            'username'     => $profile->getUsername(), 
            'passwordHash' => $profile->getPasswordHash(), 
            'familyName'   => $profile->getFamilyName(), 
            'givenName'    => $profile->getGivenName(), 
            'interests'    => $profile->getInterests(), 
            'birthday'     => $profile->getBirthDay()->format('Y-m-d') 
        ]; 
    } 
} 

```

请注意，此代码示例包含一个私有方法`profileToRecord()`，它将`Profile`类的实例转换为一个普通的 PHP 数组，该数组将作为文档存储在集合中。这段代码被提取到自己的方法中，因为以后将有用作可重用的函数。实际的插入是由集合的`insertOne`方法执行的，该方法将一个简单的 PHP 数组作为参数。

作为下一步，让我们通过使用另一个方法`updateProfile`来扩展配置文件服务，该方法可以-您猜对了-更新现有配置文件：

```php
    public function updateProfile(Profile $profile): Profile 
    { 
        $record = $this->profileToRecord($profile); 
        $this->profileCollection->findOneAndUpdate( 
            ['username' => $profile->getUsername()], 
            ['$set' => $record] 
        ); 
        return $profile; 
    } 

```

传递给`findOneAndUpdate`方法的第一个参数是 MongoDB 查询。它包含一组约束，文档应该匹配（在本例中，文档的`username`属性等于`$profile->getUsername()`返回的任何值）。

就像 SQL 查询一样，这些查询可以变得任意复杂。例如，以下查询将匹配所有名为`Martin`且出生于 1980 年 1 月 1 日后的用户，并且喜欢开源软件或科幻文学。您可以在[`docs.mongodb.com/manual/reference/operator/query/`](https://docs.mongodb.com/manual/reference/operator/query/)找到 MongoDB 查询选择运算符的完整参考。

```php
[ 
  'givenName' => 'Martin', 
  'birthday' => [ 
    '$gte' => '1980-01-01' 
  ], 
  'interests' => [ 
    '$elemMatch' => [ 
      'Open Source', 
      'Science Fiction' 
    ] 
] 

```

`findOneAndUpdate()`的第二个参数包含一组更新操作，这些操作将应用于与给定查询匹配的第一个找到的文档。在此示例中，`$set`运算符包含一个属性值数组，该数组将在匹配的文档上进行更新。就像查询一样，这些更新语句可能会变得更加复杂。以下内容将更新所有匹配的用户的名字为`Max`，并将音乐添加到他们的兴趣列表中：

```php
[ 
  '$set' => [ 
    'givenName' => 'Max', 
  ], 
  '$addToSet' => [ 
    'interests' => ['Music'] 
  ] 
] 

```

使用一个简单的测试脚本，您现在可以测试此配置文件服务。为此，您需要建立与 MongoDB 数据库的连接。如果您之前使用了 Docker 命令，则您的 MongoDB 服务器的主机名将简单地是`db`：

```php
declare(strict_types = 1); 
$manager = new \MongoDB\Driver\Manager('mongodb://db:27017'); 
$collection = new \MongoDB\Collection($manager, 'database-name', 'profiles'); 

$profileService = new \Packt\Chp5\Service\ProfileService($collection); 
$profileService->insertProfile(new \Packt\Chp5\Model\Profile( 
    'jdoe', 
    'John', 
    'Doe', 
    password_hash('secret', PASSWORD_BCRYPT), 
    ['Open Source', 'Science Fiction', 'Death Metal'], 
    new \DateTime('1970-01-01') 
)); 

```

添加和更新用户配置文件很好，但配置文件服务还不支持从数据库加载这些配置文件。为此，您可以使用更多方法扩展您的`ProfileService`。从一个简单检查给定用户名的配置文件是否存在的`hasProfile`方法开始：

```php
public function hasProfile(string $username): bool 
{ 
    return $this->profileCollection->count(['username' => $username]) > 0; 
} 

```

`hasProfile`方法简单地检查数据库中是否存储了给定用户名的配置文件。为此，使用了集合的`count`方法。该方法接受一个 MongoDB 查询对象，并将返回匹配此约束的所有文档的计数（在本例中，具有给定用户名的所有文档的数量）。当具有给定用户名的配置文件已经存在时，`hasProfile`方法将返回 true。

继续实现`getProfile`方法，该方法从数据库加载用户配置文件并返回相应的`Profile`类的实例：

```php
public function getProfile(string $username): Profile 
{ 
    $record = $this->profileCollection->findOne(['username' => $username]); 
    if ($record) { 
        return $this->recordToProfile($record); 
    } 
    throw new UserNotFoundException($username); 
} 

private function recordToProfile(BSONDocument $record): Profile 
{ 
    return new Profile( 
        $record['username'], 
        $record['givenName'], 
        $record['familyName'], 
        $record['passwordHash'], 
        $record['interests']->getArrayCopy(), 
        new \DateTime($record['birthday']); 
    ); 
} 

```

`getProfile`方法使用集合的`findOne`方法（偶然接受相同的查询对象），该方法返回与约束匹配的第一个文档（或 null，当找不到文档时）。当找不到具有给定用户名的配置文件时，将抛出`Packt\Chp5\Exception\UserNotFoundException`。这个类的实现留给读者作为练习。然后将找到的文档传递给私有的`recordToProfile`方法，该方法反转了您之前已经实现的`profileToRecord`方法。请注意，所有 MongoDB 查询方法都不会返回普通数组作为文档，而总是返回`MongoDB\Model\BSONDocument`类的实例。您可以像使用常规数组一样使用它们，但在类型提示函数参数或返回值时可能会遇到问题。

## 添加和检索用户

现在您已成功实现了配置文件 REST 服务的持久性逻辑，您现在可以开始实现实际的 REST Web 服务。

在之前的示例中，我们已经使用简单的回调函数作为 Slim 框架的请求处理程序：

```php
$app->get('/users', function(Request $req, Response $res): Response { 
    return $response->withJson(['foo' => 'bar']); 
}); 

```

这对于快速入门是完全可以的，但随着应用程序的增长，将会变得难以维护。为了以更可扩展的方式构建应用程序，您可以利用 Slim 请求处理程序不必是匿名函数的事实，而实际上可以是任何可调用的东西。在 PHP 中，您还可以通过实现`__invoke`方法使对象可调用。您可以使用这个来实现一个请求处理程序，它可以是一个具有自己属性的有状态类。

然而，在实现请求处理程序之前，让我们先看一下 Web 服务的响应。由于我们选择了 JSON 作为我们的主要表示格式，您经常需要将`Profile`类的实例转换为 JSON 对象 - 当然也需要反过来。为了保持这种转换逻辑的可重用性，建议将此功能实现为一个单独的单元。为此，您可以实现一个`ProfileJsonMapping` trait，如下例所示：

```php
namespace Packt\Chp5\Mapper; 

trait ProfileJsonMapping 
{ 
    private function profileToJson(Profile $profile): array 
    { 
        return [ 
            'username'   => $profile->getUsername(), 
            'givenName'  => $profile->getGivenName(), 
            'familyName' => $profile->getFamilyName(), 
            'interests'  => $profile->getInterests(), 
            'birthday'   => $profile->getBirthday()->format('Y-m-d') 
        ]; 
    } 

    private function profileFromJson(string $username, array $json): Profile 
    { 
        return new Profile( 
            $username, 
            $json['givenName'], 
            $json['familyName'], 
            $json['passwordHash'] ?? password_hash($json['password']), 
            $json['interests'] ?? [], 
            new \DateTime($json['birthday']) 
        ); 
    } 
} 

```

表示逻辑已经处理好了，现在您可以继续实现获取单个用户配置文件的路由。在这个示例中，我们将在`Packt\Chp5\Route\ShowUserRoute`类中实现这个路由，并使用之前显示的`ProfileJsonMapping` trait：

```php
namespace Packt\Chp5\Route; 
// imports omitted for brevity 

class ShowProfileRoute 
{ 
    use ProfileJsonMapping; 
    private $profileService; 

    public function __construct(ProfileService $profileService) 
    { 
        $this->profileService = $profileService; 
    } 

    public function __invoke(Request $req, Response $res, array $args): Response 
    { 
        $username = $args['username']; 
        if ($this->profileService->hasProfile($username)) { 
            $profile = $this->profileService->getProfile($username); 
            return $res->withJson($this->profileToJson($profile)); 
        } else { 
            return $res 
                ->withStatus(404) 
                ->withJson(['msg' => 'the user ' . $username . ' does not exist']); 
        } 
    } 
} 

```

正如您所看到的，这个类中的`__invoke`方法与您在之前的示例中看到的回调请求处理程序具有相同的签名。此外，这个路由类使用了您在上一节中实现的`ProfileService`。实际处理程序首先检查是否存在具有给定用户名的配置文件，并在请求的配置文件不存在时返回**404 Not Found**状态码。否则，`Profile`实例将被转换为普通数组，并作为 JSON 字符串返回。

您现在可以在您的`index.php`中初始化您的 Slim 应用程序，如下所示：

```php
use MongoDB\Driver\Manager; 
use MongoDB\Collection; 
use Packt\Chp5\Service\ProfileService; 
use Packt\Chp5\Route\ShowProfileRoute; 
use Slim\App; 

$manager        = new Manager('mongodb://db:27017'); 
$collection     = new Collection($manager, 'database-name', 'profiles'); 
**$profileService = new ProfileService($collection);** 

$app = new App(); 
**$app->get('/profiles/{username}', new 
ShowProfileRoute($profileService));** 
$app->run(); 

```

如果您的数据库仍然包含来自上一节的一些测试数据，您现在可以通过使用 HTTPie 等工具来测试此 API。

![添加和检索用户](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-bp/img/image_05_003.jpg)

使用 REST API 访问用户配置文件

对于创建新用户配置文件（以及更新现有配置文件），您现在可以创建一个新的请求处理程序类。由于对`/profiles/{username}`的`PUT`请求将创建一个新配置文件或更新已经存在的配置文件，新的请求处理程序将需要同时做这两件事：

```php
namespace Packt\Chp5\Route; 
// Imports omitted for brevity 

class PutProfileRoute 
{ 
    use ProfileJsonMapping; 
    private $profileService; 

    public function __construct(ProfileService $profileService) 
    { 
        $this->profileService = $profileService; 
    } 

    public function __invoke(Request $req, Response $res, array $args): Response 
    { 
        $username      = $args['username']; 
        $profileJson   = $req->getParsedBody(); 
        $alreadyExists = $this->profileService->hasProfile($username); 

        $profile = $this->profileFromJson($username, $profileJson); 
        if ($alreadyExists) { 
            $profile = $this->profileService->updateProfile($profile); 
            return $res->withJson($this->profileToJson($profile)); 
        } else { 
            $profile = $this->profileService->insertProfile($profile); 
            return $res->withJson($this->profileToJson($profile))->withStatus(201); 
        } 
    } 
} 

```

在这个例子中，我们使用`Request`类的`getParsedBody`方法来检索解析后的消息体。幸运的是，这个方法足够智能，可以查看请求的`Content-Type`头，并自动选择适当的解析方法（在`application/json`请求的情况下，将使用`json_decode`方法来解析请求体）。

在检索解析后的消息体之后，使用`ProfileJsonMapping`特性中定义的`profileFromJson`方法来从这个主体创建`Profile`类的实际实例。根据这个用户名是否已经存在配置文件，然后我们可以使用`ProfileService`类中实现的方法插入或更新用户配置文件。请注意，根据是创建新配置文件还是更新现有配置文件，将返回不同的 HTTP 状态代码（当创建新配置文件时为`201 Created`，否则为`200 OK`）。

### 提示

**验证呢？** 您会注意到目前，您可以将任何东西作为主体参数传递，请求处理程序将尝试将其保存为用户配置文件，即使缺少必要的属性或主体不包含有效的 JSON。PHP 7 的新类型安全功能将为您提供一些安全性，因为 - 由于启用了`declare(strict_types=1)`的严格类型，当输入主体中缺少某些字段时，它们将简单地抛出`TypeError`。输入验证的更彻底的实现将在*验证输入*部分进行讨论：

```php
// As both parameters have a "string" type hint, strict typing will 
// cause PHP to throw a TypeError when one of the two parameters should 
// be null 
$profile = new Profile( 
    $jsonObject['familyName'], 
    $jsonObject['givenName'] 
); 

```

您现在可以在您的`index.php`中的新路由中连接这个类：

```php
$app = new App(); 
$app->get('/profiles/{username}', new 
ShowProfileRoute($profileService)); 
**$app->put('/profiles/{username}', new 
PutProfileRoute($profileService));** 
$app->run(); 

```

之后，您可以尝试使用 HTTPie 创建一个新的用户配置文件：

```php
$ http PUT http://localhost/profiles/jdoe givenName=John familyName=Doe \ 
password=secret birthday=1970-01-01 

```

您还可以尝试通过简单重复相同的 PUT 请求并使用不同的参数来更新创建的配置文件。HTTP 响应代码（`201 Created`或`200 OK`）允许您确定是创建了新配置文件还是更新了现有配置文件。

## 列出和搜索用户

您的 API 的当前状态允许用户读取、创建和更新特定用户配置文件。但是，网络服务仍然缺少搜索配置文件集合或列出所有已知用户配置文件的功能。对于列出配置文件，您可以使用一个新函数`getProfiles`来扩展`ProfileService`类：

```php
namespace Packt\Chp5\Service\ProfileService; 
// ... 

class ProfileService 
{ 
    // ... 

 **public function getProfiles(array $filter = []): Traversable**
 **{** 
 **$records = $this->profileCollection->find($filter);** 
 **foreach ($records as $record) {** 
 **yield $this->recordToProfile($record);** 
 **}** 
 **}** 
} 

```

如果您不熟悉这种语法：前一个函数是一个**生成器**函数。`yield`语句将导致函数返回`Generator`类的一个实例，它本身实现了`Traversable`接口（这意味着您可以使用`foreach`循环对其进行迭代）。当处理大型数据集时，这种构造特别方便。由于`find`函数本身也返回一个`Traversable`，您可以从数据库中流式传输匹配的配置文件文档，惰性地将它们映射到用户对象，并将数据流传递到请求处理程序中，而无需将整个对象集合放入内存中。

作为对比，考虑以下实现，它使用普通数组而不是生成器。您会注意到，由于使用了`ArrayObject`类，即使方法的接口保持不变（返回`Traversable`），这个实现在`ArrayObject`实例中存储了所有找到的配置文件实例的列表，而之前的实现一次只处理一个对象：

```php
public function getProfiles(array $filter = []): Traversable 
{ 
    $records  = $this->profileCollection->find($filter); 
    $profiles = new ArrayObject(); 

    foreach ($records as $record) { 
        $profiles->append($this->recordToProfile($record)); 
    } 

    return $profiles; 
} 

```

由于 MongoDB API 直接接受结构良好的查询对象来匹配文档，而不是自定义的基于文本的语言（是的，我在看你，SQL），因此您不必担心传统基于 SQL 的系统（并非总是，但通常是）容易受到的注入攻击。这允许我们的`getProfiles`函数接受`$filter`参数中的查询对象，我们只需将其传递给`find`方法。

接下来，您可以通过添加新的参数来扩展`getProfiles`函数，以对结果集进行排序：

```php
public function getProfiles( 
    array  $filter        = [], 
 **string $sorting       = 'username',** 
 **bool   $sortAscending = true** 
): Traversable { 
    $records = $this->profileCollection->find($filter, ['sort' => [ 
 **$sorting => $sortAscending ? 1 : -1** 
 **]]);** 

    // ... 
} 

```

使用这个新函数，很容易实现一个新的类`Packt\Chp5\Route\ListProfileRoute`，您可以使用它来查询整个用户集合：

```php
namespace Packt\Chp5\Route; 

class ListProfileRoute 
{ 
    use ProfileJsonMapping; 

    private $profileService; 

    public function __construct(ProfileService $profileService) 
    { 
        $this->profileService = $profileService; 
    } 

    public function __invoke(Request $req, Response $res): Response 
    { 
        $params = $req->getQueryParams(); 

        $sort = $params['sort'] ?? 'username'; 
        $asc  = !($params['desc'] ?? false); 
        $profiles     = $this->profileService->getProfiles($params, $sort, $asc); 
        $profilesJson = []; 

        foreach ($profiles as $profile) { 
            $profilesJson[] = $this->profileToJson($profile); 
        } 

        return $response->withJson($profilesJson); 
    } 
} 

```

在那之后，您可以在`index.php`文件中为 Slim 应用程序注册新的请求处理程序：

```php
$app = new App(); 
**$app->get('/profiles', new ListProfileRoute($profileService));** 
$app->get('/profiles/{username}', new ShowProfileRoute($profileService)); 
$app->put('/profiles/{username}', new PutProfileRoute($profileService)); 
$app->run(); 

```

## 删除配置文件

到目前为止，删除用户配置文件应该是一个简单的任务。首先，您需要在`ProfileService`类中添加一个新的方法：

```php
class ProfileService 
{ 
    // ... 

 **public function deleteProfile(string $username)** 
 **{** 
 **$this->profileCollection->findOneAndDelete(['username' =>
 $username]);** 
 **}** 
} 

```

MongoDB 集合的`findOneAndDelete`方法确实实现了它承诺的功能。此函数的第一个参数是一个 MongoDB 查询对象，就像您在前几节中已经使用过的那样。由此查询对象匹配的第一个文档将从集合中删除。

在那之后，您可以实现一个新的请求处理程序类，该类使用配置文件服务来删除配置文件（如果存在）。当尝试删除一个不存在的用户时，请求处理程序将以正确的状态代码“404 未找到”做出响应：

```php
namespace Packt\Chp5\Route; 
// Imports omitted... 

class DeleteProfileRoute 
{ 

    /** @var ProfileService */ 
    private $profileService; 

    public function __construct(ProfileService $profileService) 
    { 
        $this->profileService = $profileService; 
    } 

    public function __invoke(Request $req, Response $res, array $args): Response 
    { 
        $username = $args['username']; 
        if ($this->profileService->hasProfile($username)) { 
            $this->profileService->deleteProfile($username); 
            return $res->withStatus(204); 
        } else { 
            return $res 
                ->withStatus(404) 
                ->withJson(['msg' => 'user "' . $username . '" does not exist']); 
        } 
    } 
} 

```

您会注意到我们的示例代码库中现在有一些重复的代码。

`ShowProfileRoute`和`DeleteProfileRoute`都需要检查给定用户名的用户配置文件是否存在，如果不存在，则返回“404 未找到”响应。

这是使用中间件的一个很好的用例。如前一节所述，中间件可以通过自身发送响应到 HTTP 请求，或将请求传递给下一个中间件组件或实际的请求处理程序。这使您可以实现中间件，从路由参数中获取用户名，检查该用户是否存在配置文件，并在该用户不存在时返回错误响应。如果该用户确实存在，则可以将请求传递给请求处理程序：

```php
namespace Packt\Chp5\Middleware 

class ProfileMiddleware 
{ 
    private $profileService; 

    public function __construct(ProfileService $profileService) 
    { 
        $this->profileService = $profileService; 
    } 

    public function __invoke(Request $req, Response $res, callable $next): Response 
    { 
        $username = $request->getAttribute('route')->getArgument('username'); 
        if ($this->profileService->hasProfile($username)) { 
            $profile = $this->profileService->getProfile($username); 
            return $next($req->withAttribute('profile', $profile)); 
        } else { 
            return $res 
                ->withStatus(404) 
                ->withJson(['msg' => 'user "' . $username . '" does not exist'); 
        } 
    } 
} 

```

所有 PSR-7 请求都可以具有可以使用`$req->withAttribute($name, $value)`设置的任意属性，并且可以使用`$req->getAttribute($name)`检索。这允许中间件将任何类型的值传递给实际的请求处理程序 - 这正是`ProfileMiddleware`通过将`profile`属性附加到请求来实现的。然后，实际的请求处理程序可以通过简单调用`$req->getAttribute('profile')`来检索已加载的用户配置文件。

中间件的注册方式与常规请求处理程序类似。每次使用`$app->get(...)`或`$app->post(...)`注册新的请求处理程序时，此方法将返回路由配置的实例，您可以为其分配不同的中间件。在您的`index.php`文件中，您可以像这样注册您的中间件：

```php
**$profileMiddleware = new ProfileMiddleware($profileService);** 

$app = new App(); 
$app->get('/profiles', new ListProfileRoute($profileService)); 
$app->get('/profiles/{username}', new ShowProfileRoute($profileService)) 
 **->add($profileMiddleware);** 
$app->delete('/profiles/{username}', new DeleteProfileRoute($profileService)) 
 **->add($profileMiddleware);** 
$app->put('/profiles/{username}', new PutProfileRoute($profileService)); 
$app->run(); 

```

在为`GET /profiles/{username}`和`DELETE /profiles{username}`路由注册中间件之后，您可以修改相应的路由处理程序，简单地使用配置文件请求属性并删除错误检查：

```php
class ShowProfileRoute 
{ 
    // ... 

    public function __invoke(Request $req, Response $res): Response 
    { 
 **$profile = $req->getAttribute('profile');** 
        return $res->withJson($this->profileToJson($profile)); 
    } 
} 

```

`DeleteProfileRoute`类也是如此：

```php
class DeleteProfileRoute 
{ 
    // ... 

    public function __invoke(Request $req, Response $res): Response 
    { 
 **$profile = $req->getAttribute('profile');** 
        $this->profileService->deleteProfile($profile->getUsername()); 
        return $res->withStatus(204); 
    } 
} 

```

## 验证输入

在实现`PUT /profiles/{username}`路由时，您可能已经注意到我们并没有那么关注用户输入的验证。在某种程度上，我们实际上可以使用 PHP 7 的新严格类型来验证用户输入。您可以通过在代码的第一行使用`declare(strict_types = 1)`语句来激活严格类型。考虑以下示例：

```php
return new Profile( 
    $username, 
    $json['givenName'], 
    $json['familyName'], 
    $json['passwordHash'] ?? password_hash($json['password']), 
    $json['interests'] ?? [], 
    $json['birthday'] ? new \DateTime($json['birthday']) : NULL 
); 

```

例如，假设`Profile`类的`$givenName`参数被类型提示为`string`，当`$json['givenName']`未设置时，前面的语句将抛出`TypeError`。然后，您可以使用`try`/`catch`语句捕获此错误，并返回适当的**400 Bad Request** HTTP 响应：

```php
try { 
    $this->jsonToProfile($req->getParsedBody()); 
} catch (\TypeError $err) { 
    return $response 
        ->withStatus(400) 
        ->withJson(['msg' => $err->getMessage()]); 
} 

```

然而，这只提供了基本的错误检查，因为您只能验证数据类型，无法断言逻辑约束。此外，这种方法会提供糟糕的用户体验，因为错误响应只会包含第一个触发的错误。

为了实现更复杂的验证，您可以向应用程序添加另一个中间件（在这里使用中间件是一个很好的选择，因为它允许您将验证逻辑的关注点封装在一个单独的类中）。让我们称这个类为`Packt\Chp5\Middleware\ProfileValidationMiddleware`：

```php
namespace Packt\Chp5\Middleware; 

class ProfileValidationMiddleware 
{ 
    private $profileService; 

    public function __construct(ProfileService $profileService) 
    { 
        $this->profileService = $profileService; 
    } 

    public function __invoke(Request $req, Response $res, callable $next): Response 
    { 
        $username      = $request->getAttribute('route')->getArgument('username'); 
        $profileJson   = $req->getParsedBody(); 
        $alreadyExists = $this->profileService->hasProfile($username); 

        $errors = []; 

        if (!isset($profileJson['familyName'])) { 
            $errors[] = 'missing property "familyName"'; 
        }  

        if (!isset($profileJson['givenName'])) { 
            $errors[] = 'missing property "givenName"'; 
        }  

        if (!$alreadyExists && 
            !isset($profileJson['password']) && 
            !isset($profileJson['passwordHash']) 
        ) { 
            $errors[] = 'missing property "password" or "passwordHash"; 
        } 

        if (count($errors) > 0) { 
            return $res 
                ->withStatus(400) 
                ->withJson([ 
                    'msg' => 'request body does not contain a valid user profile', 
                    'errors' => $errors 
                ]); 
        } else { 
            return $next($req, $res); 
        } 
    } 
} 

```

声明验证中间件类之后，您可以在您的`index.php`文件中注册它：

```php
$profileMiddleware = new ProfileMiddleware($profileService); 
**$validationMiddleware = new ProfileValidationMiddleware($profileService);** 

$app = new App(); 
$app->get('/profiles', new ListProfileRoute($profileService)); 
$app->get('/profiles/{username}', new ShowProfileRoute($profileService)) 
    ->add($profileMiddleware); 
$app->delete('/profiles/{username}', new DeleteProfileRoute($profileService)) 
    ->add($profileMiddleware); 
$app->put('/profiles/{username}', new PutProfileRoute($profileService)) 
 **->add($validationMiddleware);** 
$app->run(); 

```

# 流和大文件

到目前为止，我们的 Web 服务可以对用户个人资料执行基本操作。在本章中，我们将扩展用户个人资料服务，以处理用户的个人资料图像。在本章的过程中，您将学习如何使用 PHP 流处理甚至非常大的文件。

## 配置图像上传

基本上，在 RESTful 应用程序中，您可以将图像视为任何其他资源。您可以使用`POST`和/或`PUT`操作创建和更新它，并使用`GET`检索它。唯一的区别是资源的选择表示。不再使用`application/json`作为 Content-Type 进行 JSON 编码，而是使用具有 JPEG 或 PNG 表示的资源，其相应的`image/jpeg`或`image/png`内容类型。

在这一点上，了解 PSR-7 标准如何对 HTTP 请求和响应主体进行建模将是有用的。从技术上讲，每个消息（请求和响应）主体只是一个字符串，这些可以被建模为简单的 PHP 字符串。这对于您在过去几节中处理的消息来说是可以的，但在处理更大的消息时（比如图像），可能会出现问题。这就是为什么 PSR-7 将所有消息主体都建模为用户可以从中读取（对于请求主体）或写入（对于响应主体）的流。您可以将流中的数据传输到文件或另一个网络流中，而无需将整个内容适应 PHP 进程的内存中。

接下来，我们将实现用户的个人资料图像作为一个新的资源。用户的个人资料图像将具有 URI `/profiles/{username}/image`。加载用户的图像将是一个简单的`GET`请求（返回一个带有适当的`Content-Type: image/jpeg`或`image/png`头和图像二进制内容的响应主体）。更新图像将使用`PUT`请求，带有 Content-Type 头和图像内容作为消息主体。

首先实现一个新的请求处理程序类，在其中从请求流中读取块并将其写入文件：

```php
namespace Packt\Chp5\Route; 

class PutImageRoute 
{ 
    private $imageDir; 

    public function __construct(string $imageDir) 
    { 
        $this->imageDir = $imageDir; 
    } 

    public function __invoke(Request $req, Response $res): Response 
    { 
        if (!is_dir($this->imageDir)) { 
            mkdir($this->imageDir); 
        } 

        $profile    = $req->getAttribute('profile'); 
        $fileName   = $this->imageDir . '/' . $profile->getUsername(); 
 **$fileHandle = fopen($fileName, 'w');** 
 **while (!$req->getBody()->eof()) {** 
 **fwrite($fileHandle, $req->getBody()->read(4096));** 
 **}** 
 **fclose($fileHandle);** 
        return $res->withJson(['msg' => 'image was saved']); 
    } 
} 

```

这个请求处理程序使用`fopen(...)`打开一个文件句柄进行写入，然后以 4 KB 的块读取请求体，并将其写入打开的文件。这种解决方案的优势在于，无论您保存的文件是 4 KB 还是 400 MB，都不会真正有影响。因为您一次只读取输入的 4 KB 块，所以内存使用量会保持相对恒定，与输入大小无关。

### 提示

**关于可扩展性** 在本地文件系统中存储文件并不是非常可扩展的，应该只被视为一个示例。为了保持可扩展性，您可以将图像目录放在网络存储上（例如 NFS），或者使用其他分布式存储解决方案。在接下来的部分中，*使用 GridFS 存储* 您还将学习如何使用 GridFS 以可扩展的方式存储文件。

接下来，在您的 Slim 应用程序中注册请求处理程序：

```php
$profileMiddleware = new ProfileMiddleware($profileService); 
$validationMiddleware = new ProfileValidationMiddleware($profileService); 

$app = new App(); 
// ... 
**$app->put('/profiles/{username}/image', new PutImageRoute(__DIR__ . '/images'))**
 **->add($profileMiddleware);** 
$app->run(); 

```

为了测试这个路由，在您的计算机上找到一个任意大小的图像文件，并在命令行上使用以下 curl 命令（记住；由于我们正在为新路由使用`profileMiddleware`，因此您需要为此指定实际存在于数据库中的用户个人资料）：

```php
**curl --data-binary @very-big-image.jpeg -H 'Content-Type: image/jpeg' -X PUT 
-v http://localhost/profiles/jdoe/image**

```

运行此命令后，您应该在项目文件夹的`images/`目录中找到一个`jdoe`文件，其内容与原始文件完全相同。

将用户的个人资料图片返回给用户的工作方式类似。为此，实现一个名为`Packt\Chp5\Route\ShowImageRoute`的新请求处理程序：

```php
namespace Packt\Chp5\Route; 

class ShowImageRoute 
{ 
    /** @var string */ 
    private $imageDir; 

    public function __construct(string $imageDir) 
    { 
        $this->imageDir = $imageDir; 
    } 

    public function __invoke(Request $req, Response $res, array $args): Response 
    { 
        $profile     = $req->getAttribute('profile'); 
        $filename    = $this->imageDir . '/' . $profile->getUsername(); 
        $fileHandle  = fopen($filename, 'r'); 
        $contentType = mime_content_type($filename); 

        return $res 
            ->withStatus(200) 
            ->withHeader('Content-Type', $contentType) 
            ->withBody(new Body($fileHandle)); 
    } 
} 

```

在这里，我们使用`mime_content_type`方法来加载上传文件的实际内容类型。需要内容类型，因为 HTTP 响应需要包含 Content-Type 标头，浏览器才能正确显示图像。

此外，我们使用`Slim\Http\Body`类，这使得实现更加容易：这个类实现了 PSR-7 `StreamInterface`，并且可以使用打开的流（例如，可能是打开的文件处理程序）进行初始化。然后，Slim 框架将负责将此文件的内容传递给用户。

此请求处理程序也可以在`index.php`中注册：

```php
$app = new \Slim\App(); 
// ... 
**$app->get('/profiles/{username}/image', new
ShowImageRoute(__DIR__ . '/images'))** 
 **->add($profileMiddleware);** 
$app->put('/profiles/{username}/image', new PutImageRoute(__DIR__ . '/images')) 
    ->add($profileMiddleware); 
$app->run(); 

```

如果在实现`PUT`路由后上传了测试图像，现在可以使用相同的用户个人资料测试`GET`路由。由于 curl 命令只会返回一个大的二进制数据块，因此最好在您选择的浏览器中访问`http://localhost/profiles/jdoe/image`。

## 使用 GridFS 存储

将用户上传的文件存储在服务器的本地文件系统中对于小型站点是一个可行的解决方案。但是，一旦您感到需要对应用程序进行水平扩展，您就需要研究分布式文件系统。例如，您可以用 NFS 文件系统挂载的网络设备替换用户图像文件夹。由于在本章中您已经大量使用了 MongoDB，在本节中您将了解 GridFS。GridFS 是一种在 MongoDB 数据库中存储 - 可能非常大的 - 文件的规范。

GridFS 规范很简单。您将需要两个集合 - `fs.files`和`fs.chunks`。前者将用于存储文件元数据，而后者将存储文件的实际内容。由于 MongoDB 文档默认限制为 16 MB，每个存储的文件将被分割成几个（默认为）255 KB 的*块*。文件文档将具有以下形式：

```php
{ 
  "_id": <object ID> 
  "length": <file size in bytes>, 
  "chunkSize": <size of each chunk in bytes, default 261120>, 
  "uploadDate": <timestamp at which the file was saved>, 
  "md5": <MD5 checksum of the file, as hex string>, 
  "filename": <the file's name>, 
  "contentType": <MIME type of file contents>, 
  "aliases": <list of alternative file names>, 
  "metadata": <arbitrary metadata> 
} 

```

块文档将具有以下形式：

```php
{ 
  "_id": <chunk ID>, 
  "files_id": <object ID of the file this chunk belongs to>, 
  "n": <index of the chunk within the file>, 
  "data": <binary data, of the file's chunk length> 
} 

```

请注意，GridFS 只是关于如何在 MongoDB 数据库中存储文件的建议，您可以自由地在 MongoDB 存储中实现任何其他类型的文件存储。但是，GridFS 是一个被广泛接受的标准，很可能您会发现几乎每种语言都有 GridFS 的实现。因此，如果您想使用 PHP 应用程序将文件写入 GridFS 存储，然后使用 Python 程序从那里读取文件，您会发现这两种运行时都有标准实现，可以直接使用，而无需重新发明轮子。

在 PHP 7 中，您可以使用`helmich/gridfs`库来访问 GridFS。您可以使用 Composer 获取它：

```php
**composer require helmich/gridfs**

```

GridFS 围绕存储桶展开。每个存储桶可以包含任意数量的文件，并在两个 MongoDB 集合中内部存储它们，`<bucket name>.files`和`<bucket name>.chunks`。

首先，通过使用`Helmich\GridFS\Bucket`类在您的`index.php`中修改应用程序引导程序，为用户个人资料图片创建一个新的存储桶。每个存储桶可以使用`BucketOptions`实例进行初始化，在其中您可以配置几个存储桶选项，例如存储桶名称。

创建存储桶后，您可以将其作为依赖项传递给`ShowImageRoute`和`PutImageRoute`类：

```php
$manager = new \MongoDB\Driver\Manager('mongodb://db:27017'); 
$database = new \MongoDB\Database($manager, 'database-name'); 

**$bucketOptions = (new \Helmich\GridFS\Options\BucketOptions)**
 **->withBucketName('profileImages');**
**$bucket = new \Helmich\GridFS\Bucket($database, $bucketOptions);** 
$profiles = $database->selectCollection('profiles'); 

// ... 

**$app->get('/profiles/{username}/image', new 
ShowImageRoute($bucket))** 
    ->add($profileMiddleware); 
**$app->put('/profiles/{username}/image', new 
PutImageRoute($bucket))** 
    ->add($profileMiddleware); 
$app->run(); 

```

`PutImageRoute`和`ShowImageRoute`现在作为依赖项传递了一个 GridFS 桶。现在，您可以调整这些类，将上传的文件写入该桶。让我们从调整`PutImageRoute`类开始：

```php
**use Helmich\GridFS\BucketInterface;** 

class PutImageRoute 
{ 
 **private $bucket;** 

    public function __construct(BucketInterface $bucket) 
    { 
 **$this->bucket = $bucket** 
    } 

    // ... 
} 

```

GridFS 桶的接口在`BucketInterface`中描述，我们在这个例子中使用。现在，您可以修改`PutImageRoute`的`__invoke`方法，将上传的个人资料图片存储在桶中：

```php
public function __invoke(Request $req, Response $res, array $args): Response 
{ 
    $profile       = $req->getAttribute('profile'); 
    $contentType   = $req->getHeader('content-type')[0]; 
    $uploadOptions = (new \Helmich\GridFS\Options\UploadOptions) 
      ->withMetadata(['content-type' => $contentType]); 

    $stream = $req->getBody()->detach(); 
    $fileId = $this->bucket->uploadFromStream( 
        $profile->getUsername(), 
        $stream, 
        $uploadOptions 
    ); 
    fclose($stream); 
    return $res->withJson(['msg' => 'image was saved']); 
} 

```

在这个例子中，我们使用了`$req->getBody()->detach()`方法来从请求体中获取实际的底层输入流。然后将该流传递到桶的`uploadFromStream`方法中，以及文件名（在这种情况下，简单地是用户名）和一个`UploadOptions`对象。`UploadOptions`对象定义了文件上传的配置选项；其中，您可以指定将存储在`<bucketname>.files`集合中的 GridFS 自身元数据旁边存储的任意元数据。

现在，剩下的就是调整`ShowProfileRoute`以使用 GridFS 桶。首先，修改类的构造函数以接受`BucketInterface`作为参数，就像我们在`PutProfileRoute`中所做的那样。然后，您可以调整`__invoke`方法，从 GridFS 桶中下载请求的个人资料图片：

```php
public function __invoke(Request $req, Response $res, array $args): Response 
{ 
    $profile = $req->getAttribute('profile'); 
    $stream = $this->bucket->openDownloadStreamByName($profile->getUsername()); 
    $file = $stream->file(); 

    return $res 
        ->withStatus(200) 
        ->withHeader('content-type', $file['metadata']['content-type']) 
        ->withBody(new \Helmich\GridFS\Stream\Psr7\DownloadStreamAdapter($stream)); 
} 

```

在这个例子中，我们使用了 Bucket 的`openDownloadStreamByName`方法来通过文件名在桶中查找文件，并返回一个流对象，从中我们可以下载文件。

打开的下载流是`Helmich\GridFS\Stream\DownloadStream`接口的实现。不幸的是，您不能直接在 HTTP 响应中使用此接口。但是，您可以使用`Helmich\GridFS\Stream\Psr7\DownloadStreamAdapter`接口从 GridFS 流创建一个符合 PSR-7 标准的流，您可以在 HTTP 响应中使用。

# 总结

在本章中，您已经了解了 RESTful Web 服务的基本架构原则，以及如何使用 Slim 框架自己构建一个。我们还看了一下 PSR-7 标准，它允许您在 PHP 中编写可在框架之间移植并且高度可重用的 HTTP 组件。最后，您还学会了如何使用 PHP 的新 MongoDB 扩展来直接访问存储的集合，以及与其他高级抽象（如 GridFS 标准）结合使用。

您新学到的 Slim 知识和对 PSR-7 标准的理解将使您受益于接下来的章节，您将在其中使用 Ratchet 框架构建一个实时聊天应用程序，然后使用 PSR-7 将 Ratchet 与 Slim 框架集成。
