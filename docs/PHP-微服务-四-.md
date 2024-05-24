# PHP 微服务（四）

> 原文：[`zh.annas-archive.org/md5/32377e38e7a2e12adc56f6a343e595a0`](https://zh.annas-archive.org/md5/32377e38e7a2e12adc56f6a343e595a0)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：从单块到微服务

在本章中，我们将探讨在必须将单块应用程序转换为微服务时可以遵循的一些可能策略，以及一些示例。如果我们已经有一个庞大而复杂的应用程序，这个过程可能会有点困难，但幸运的是，有一些众所周知的策略可以遵循，以避免在整个过程中出现问题。

# 重构策略

将单块应用程序转换为微服务的过程是为了重构代码，以使您的应用程序现代化。这应该是逐步进行的。试图一步将整个应用程序转换为微服务可能会导致问题。逐渐地，它将创建一个基于微服务的新应用程序，最终，您当前的应用程序将消失，因为它将被转换为小的微服务，使原始应用程序变为空或者也可能成为一个微服务。

## 停止潜水

当您的应用程序已经是一个洞时，您必须停止潜水。换句话说，停止让您的单块应用程序变得更大。这是当您必须实现一个新功能时，需要创建一个新的微服务并将其连接到单块应用程序，而不是继续在单块中开发新功能。

为此，当实现新功能时，我们将有当前的单块、新功能，以及另外两个东西：

+   **路由器：**这负责处理 HTTP 请求；换句话说，这就像一个网关，知道需要将每个请求发送到哪里，无论是旧的单体还是新功能。

+   **粘合代码：**这负责将单块应用程序连接到新功能。新功能通常需要访问单块应用程序以获取数据或任何必要的功能：![停止潜水](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-msvc/img/B06142_09_01.jpg)

停止潜水策略

关于粘合代码，有 3 种不同的可能性可以从新功能访问应用程序到单块：

+   在单体侧创建一个 API，供新功能使用

+   直接连接单块数据库

+   在功能方面有一个与单块数据库同步的副本

正如您所看到的，这种策略是在当前的单块应用程序中开始开发微服务的一种不错的方式。此外，新功能可以独立于单块进行扩展、部署和开发，从而改进您的应用程序。然而，这并不能解决问题，只是避免让当前问题变得更大，所以让我们再看看另外两种策略。

## 分离前端和后端

另一种策略是将逻辑呈现部分与数据访问层分开。一个应用程序通常至少有 3 个不同的部分：

+   **呈现层：**这是用户界面，换句话说，是网站的 HTML 语言

+   **业务逻辑层：**这由用于实现业务规则的组件组成

+   **访问数据层：**这包含访问数据库的组件

通常呈现层和业务逻辑以及访问数据层之间有一个分离。业务层具有一个 API，其中有一个或多个封装业务逻辑组件的门面。从这个 API，可以将单块分成 2 个较小的应用程序。

分割后，呈现层调用业务逻辑。看下面的例子：

![分离前端和后端](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-msvc/img/B06142_09_02.jpg)

分离前端和后端策略

这种分割有两个不同的优势：

+   它允许您扩展和开发两个不同和独立的应用程序

+   它为您提供了一个可以供未来微服务使用的 API

这种策略的问题在于它只是一个临时解决方案，它可以转变为一个或两个单体应用程序，因此让我们看看下一个策略，以便移除剩余的单体应用程序。

## 提取服务

最后的策略是从结果单体应用程序中隔离模块。我们可以逐步从中提取模块，并从每个模块创建一个微服务。一旦我们提取了所有重要的模块，结果单体应用程序也将成为一个微服务，甚至可能消失。总体思路是创建将成为未来微服务的功能的逻辑组。

单体应用程序通常有许多潜在的模块可以提取。优先级必须通过首先选择更容易的模块，然后选择最有益的模块来设置。更容易的模块将为您提供必要的经验，以将模块提取为微服务，以便稍后处理重要的模块。

以下是一些提示，以帮助您选择最有益的模块：

+   经常变化的模块

+   需要与单体应用程序不同资源的模块

+   需要昂贵硬件的模块

寻找现有的粗粒度��界是有用的，它们更容易且更便宜转换为微服务。

### 如何提取模块

现在，让我们看看如何提取一个模块，我们将使用一个示例来使解释更容易理解一些。想象一下，您的单体应用是一个博客系统。正如您可以想象的那样，核心功能是用户创建的帖子，每个帖子都支持评论。从我们的简要描述中可以看出，您可以定义应用程序的不同模块，并决定哪个最重要。

一旦您清楚了应用程序的描述和功能，就可以继续使用用于从单体应用程序中提取模块的一般步骤：

1.  在模块和单体代码之间创建一个接口。最佳解决方案是双向 API，因为单体应用程序将需要来自模块的数据，而模块将需要来自单体应用程序的数据。这个过程并不容易，您可能需要更改单体应用程序的代码，以使 API 正常工作。

1.  一旦实现了粗粒度接口，将模块转换为独立的微服务。

例如，想象一下`POST`模块是要被提取的候选模块，它们的组件被`Users`和`Comments`模块使用。正如第一步所说，需要实现一个粗粒度的 API。第一个接口是由`Users`用来调用`POST`模块的入口 API，第二个接口是由`POST`用来调用`Comments`的。

在提取的第二步中，将模块转换为独立的微服务。一旦完成，生成的微服务将是可扩展和独立的，因此可以使其增长，甚至从头开始编写。

逐步，单体应用程序将变得更小，您的应用程序将拥有更多的微服务。

# 教程：从单体应用到微服务

在本章的示例中，我们将不使用框架，并且将不使用 MVC 架构编写代码，以便专注于本章的主题，并学习如何将单体应用程序转换为微服务。

没有比实践更好的学习方法了，因此让我们看一个完整的博客平台示例，这是我们在前一节中定义的。

### 提示

博客平台示例可以从我们的 PHP 微服务存储库中下载，因此，如果您想跟随我们的步骤，可以通过下载并按照本指南进行操作。

我们的示例是一个基本的博客平台，具有最低限度的功能，可以通过本教程。这是一个允许以下操作的博客系统：

+   注册新用户

+   用户登录

+   管理员可以发布新文章

+   注册用户可以发布新评论

+   管理员可以创建新类别

+   管理员可以创建新文章

+   管理员可以管理评论

+   所有用户都可以看到文章

因此，将单块应用程序转换为微服务的第一步是熟悉当前应用程序。在我们的想象中，当前应用程序可以分为以下微服务：

+   用户

+   文章

+   评论

+   类别

在这个例子中很清楚，但在一个真实的例子中，应该深入研究，以便按照我们在本章中之前解释的优先级将项目划分为小的微服务，这些微服务将通过执行特定功能来完成任务。

## 停止潜水

现在我们知道如何按照之前解释的策略进行操作，想象一下我们想要在我们的博客平台中添加一个新功能，即在用户之间发送私人消息。

为了弄清楚这一点，我们需要知道新的发送私人消息功能将具有哪些功能，以便找到粘合代码和从新微服务获取信息（路由）的请求所在的位置。

因此，新微服务的功能可以如下：

+   向用户发送消息

+   阅读你的消息

正如你所看到的，这些功能非常基本，但请记住，这只是为了让你熟悉在单块应用程序中创建新微服务的过程。

我们将创建私人消息微服务，并且当然，我们将再次使用 Lumen。为了快速创建骨架，在终端上运行以下命令：

```php
**composer create-project --prefer-dist laravel/lumen private_messages**

```

上述命令将创建一个带有 Lumen 安装的文件夹。

在第二章中，我们解释了如何创建 Docker 容器。现在，你有机会运用你学到的一切，在 Docker 环境中实现单块和不同的新微服务。根据前面的章节，你应该能够自己做到这一点。

我们的新功能需要一个存储私人消息的地方，所以现在我们将创建私人消息微服务将使用的表。这可以在单独的数据库中创建，甚至可以在同一个应用程序的数据库中创建。请记住，如果情况允许，微服务可以共享同一个数据库，但想象一下，这个微服务将会有很多流量，所以对我们来说，最好的解决方案是将其放在一个单独的数据库中。

创建一个新的数据库或连接应用程序数据库并执行以下查询：

```php
    CREATE TABLE `messages` (
      `id` INT NOT NULL AUTO_INCREMENT,
      `sender_id` INT NULL,
      `recipient_id` INT NULL,
      `message` TEXT NULL,
      PRIMARY KEY (`id`));
```

一旦我们创建了表，就需要将新的微服务连接到它，所以打开`.env.example`文件并修改以下行：

```php
    DB_CONNECTION=mysql
    DB_HOST=localhost
    DB_PORT=3306
    DB_DATABASE=**private_messages**
    DB_USERNAME=root
    DB_PASSWORD=root
```

如果你的数据库不同，请在上述代码中进行更改。

将`.env.example`文件重命名为`.env`，并将`$app->run();`代码更改为`public/index.php`文件中的以下代码；这将允许你调用这个微服务：

```php
    $app->run(
      $app->make('request')
    );
```

现在，你可以通过在 Postman 上进行 GET 调用`http://localhost/private_messages/public/`来检查你的微服务是否正常工作。记得对你的开发基础设施进行所有必要的更改。

你将收到一个带有安装的 Lumen 版本的 200 状态码。

在我们的微服务中，我们至少需要包括以下调用：

+   GET `/messages/user/id`：这是获取用户的消息所需的

+   POST `/message/sender/id/recipient/id`：这是向用户发送消息所需的

因此，现在我们将在`/private_messages/app/Http/routes.php`上创建路由，通过在`routes.php`文件的末尾添加以下行：

```php
    $app->get('messages/user/{userId}',
              'MessageController@getUserMessages');
    $app->post('messages/sender/{senderId}/recipient/{recipientId}',
               'MessageController@sendMessage');
```

下一步是在`/app/Http/Controllers/MessageController.php`上创建一个名为`MessageController`的控制器，并包含以下内容：

```php
    <?php

    namespace App\Http\Controllers;

    use Illuminate\Http\Request;

    class MessageController extends Controller
    {
      public function getUserMessages(Request $request, $userId) {
        // getUserMessages code
      }

      public function sendMessage(Request $request, $senderId,
                                  $recipientId) {
        // sendMessage code
      }
    }
```

现在，我们必须告诉 Lumen 需要使用数据库，所以取消注释`/bootstrap/app.php`中的以下行：

```php
    $app->withFacades();
    $app->withEloquent();
```

现在，我们可以创建这两个功能：

```php
    public function getUserMessages(Request $request, $userId) 
    {
 **$messages = Message::where('recipient_id',$userId)->get();**
 **return response()->json($messages);**
    }

    public function sendMessage(Request $request, $senderId,
                                $recipientId) 
    {
      **$message = new Message();**
 **$message->fill([
        'sender_id'    => $senderId,
        'recipient_id' => $recipientId,
        'message'      => $request->input('message')]);**
 **$message->save();**
 **return response()->json([]);**
    }
```

一旦我们的方法完成，微服务就完成了。因此，现在我们必须将单块应用程序连接到私人消息微服务。

我们需要在单体应用程序的`header.php`文件中为注册用户创建一个新按钮：

```php
    <?php if (empty($arrUser['username'])) : ?>
      <li role="presentation"><a href="login.php">Log in</a></li>
      <li role="presentation"><a href="signup.php">Sign up</a></li>
    <?php else : ?>
      <?php if ($arrUser['type'] === 'admin') : ?>
        <li role="presentation">
          <a href="admin/index.php">Admin Panel</a>
        </li>
      <?php endif; ?>
 **<li role="presentation">
        <a href="messages.php">Messages</a>
      </li>**
      <li role="presentation">
        <a href="index.php?logout=true">Log out</a>
      </li>
    <?php endif; ?>
```

然后，我们需要在`root`文件夹中创建一个名为`messages.php`的新文件，其中包含以下代码：

```php
    <?
      include_once 'libraries.php';

      $url = "http://localhost/private_messages/public/messages
              /user/".$arrUser['id'];
      $ch = curl_init();
      curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
      curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
      curl_setopt($ch, CURLOPT_URL,$url);
      $result=curl_exec($ch);
      curl_close($ch);
      $messages = json_decode($result, true);
```

正如你所看到的，我们正在调用微服务以获取用户消息列表。此外，我们需要获取用户列表以填充发送消息的用户选择器。这段代码可以被视为粘合代码，因为需要将微服务数据与单体数据匹配。我们将使用以下粘合代码：

```php
    $arrUsers = array();
    $query = "SELECT id, username FROM `users` ORDER BY username ASC";
    $result = mysql_query ($query, $dbConn);
    while ( $row = mysql_fetch_assoc ($result)) {
      array_push( $arrUsers,$row );
    }
```

现在我们可以构建 HTML 代码来显示用户消息和发送消息所需的表单：

```php
 **include_once 'header.php';
    ?>**
    <p class="bg-success">
 **<?php if ($_GET['sent']) { ?>
        The message was sent!
      <?php } ?>**
    </p>
    <h1>Messages</h1>
    <?php foreach($messages as $message) { ?>
      <div class="panel panel-primary">
        <div class="panel-heading">
          <h3 class="panel-title">
            Message from **<?php echo $arrUsers[$message['sender_id']]
                           ['username'];?>**           </h3>
        </div>
        <div class="panel-body">
 **<?php echo $message['message']; ?>**        </div>
      </div>
 **<?php } ?>**    <h1>Send message</h1>
      <div>
        <form action="messages.php" method="post">
          <div class="form-group">
            <label for="category_id">Recipient</label>
            <select class="form-control" name="recipient">
              <option value="">Select User</option>
              <option value="">------------------------</option>
 **<?php foreach($arrUsers as $user) { ?>**                <option value="**<?php echo $user['id']; ?>**">
 **<?php echo $user['username']; ?>**
                </option>
 **<?php } ?>**            </select>
          </div>
          <div class="form-group">
            <label for="name">
              Message
            </label>
            <br />
            <input name="message" type="text" value=""
             class="form-control" />
          </div>
          <input name="sender" type="hidden" 
           value="<?php echo $arrUser['id']; ?>" />

          <div class="form-group">
            <input name="submit" type="submit" value="Send message" 
             class="btn btn-primary" />
          </div>

        </form>
      </div>
 **<?php include_once 'footer.php'; ?>**

```

请注意，有一个用于发送消息的表单，因此我们必须添加一些代码来调用微服务以发送消息。在`$messages = json_decode($result, true);`行后添加以下代码：

```php
    if (!empty($_POST['submit'])) {
      if (!empty($_POST['sender'])) {
        $sender = $_POST['sender'];
      }
      if (!empty($_POST['recipient'])) {
        $recipient = $_POST['recipient'];
      }
      if (!empty($_POST['message'])) {
        $message = $_POST['message'];
      }

      if (empty($sender)) {
        $error['sender'] = 'Sender not found';
      }
      if (empty($recipient)) {
        $error['recipient'] = 'Please select a recipient';
      }
      if (empty($message)) {
        $error['message'] = 'Please complete the message';
      }

      if (empty($error)) {
        $url = 'http://localhost/private_messages/public/messages
                /sender/'.$sender.'/recipient/'.$recipient;

        $handler = curl_init();
        curl_setopt($handler, CURLOPT_URL, $url);
        curl_setopt($handler, CURLOPT_POST,true);
        curl_setopt($handler, CURLOPT_RETURNTRANSFER,true);
        curl_setopt($handler, CURLOPT_POSTFIELDS, "message=".$message);
        $response = curl_exec ($handler);

        curl_close($handler);

        header( 'Location: messages.php?sent=true' );
        die;
      }
    }
```

就是这样。我们的第一个微服务已经包含在单体应用程序中。这就是在当前的单体应用程序中添加新功能时的操作方式。

## 前端和后端分离

如前所述，第二种策略是将表示层与业务逻辑隔离开来。这可以通过创建一个包含所有业务逻辑和数据访问的完整微服务来实现，也可以通过将表示层与业务层隔离开来实现，就像**模型-视图-控制器**（**MVC**）结构一样。

这并不是使用单体应用程序的问题的完整解决方案，因为这将导致我们有两个单体应用程序，而不是一个。

要做到这一点，我们应该首先在`root`文件夹中创建一个新的`Controller.php`文件。我们可以将这个类称为`Controller`，它将包含视图需要的所有方法。例如，`Article`视图需要`getArticle`，`postComment`和`getArticleComments`：

```php
    <?php

    class Controller
    {
      public function connect () {
        $db_con = mysql_pconnect(DB_SERVER,DB_USER,DB_PASS);
        if (!$db_con) {
          return false;
        }
        if (!mysql_select_db(DB_NAME, $db_con)) {
          return false;
        }
        return $db_con;
      }

      public function **getArticle**($id)
      {
        $dbConn = $this->connect();

        $query = "SELECT articles.id, articles.title, articles.extract,
                         articles.text, articles.updated_at, 
                         categories.value as category,
                         users.username FROM `articles`
                  INNER JOIN 
                  `categories` ON categories.id = articles.category_id
                  INNER JOIN
                  `users` ON users.id = articles.user_id
                  WHERE articles.id = " . $id . " LIMIT 1";
        $result = mysql_query ($query, $dbConn);
        return mysql_fetch_assoc ($result);
      }

      public function **getArticleComments**($id)
      {
        $dbConn = $this->connect();

        $arrComments = array();
        $query = "SELECT comments.id, comments.comment, users.username
                  FROM `comments` INNER JOIN `users`
                  ON comments.user_id = users.id
                  WHERE comments.status = 'valid'
                  AND comments.article_id = " . $id . "
                  ORDER BY comments.id DESC";

        $result = mysql_query ($query, $dbConn);
        while ($row = mysql_fetch_assoc($result)) {
          array_push($arrComments,$row);
        }

        return $arrComments;
      }

      public function **postComment**($comment,$user_id,$article_id)
      {
        $dbConn = $this->connect();

        $query = "INSERT INTO `comments` (comment, user_id, article_id)
                  VALUES ('$comment','$user_id','$article_id')";
        mysql_query($query, $dbConn);
      }
    }
```

文章视图应包含`Controller.php`文件中包含的方法。看一下以下代码：

```php
    <?
      include_once 'libraries.php';
 **include_once 'Controller.php';**
 **$controller = new Controller();**

      if ( !empty($_POST['submit']) ) {

        // Validation
        if (!empty($_POST['comment'])) {
          $comment = $_POST['comment'];
        }
        if (!empty($_GET['id'])) {
          $article_id = $_GET['id'];
        }
        if (!empty($arrUser['id'])) {
          $user_id = $arrUser['id'];
        }

        if (empty($comment)) {
          $error['comment'] = true;
        }
        if (empty($article_id)) {
          $error['article_id'] = true;
        }
        if (empty($user_id)) {
          $error['user_id'] = true;
        }
        if ( empty($error) ) {

 **$controller->postComment($comment,$user_id,$article_id);**
          header ( 'Location: article.php?id='.$article_id);
          die;
        }
      }

 **$article = $controller->getArticle($_GET['id']);**
 **$comments = $controller->getArticleComments($_GET['id']);**

      include_once 'header.php';
    ?>

    <h1>Article</h1>

    <div class="panel panel-primary">
      <div class="panel-heading">
        <h3 class="panel-title">
 **<?php echo $article['title']; ?>**
        </h3>
      </div>
      <div class="panel-body">
        <span class="label label-primary">Published</span> by
        <b>**<?php echo $article['username']; ?>**</b> in
        <i>**<?php echo $article['category']; ?>**</i>
        <b>**<?php echo date_format(date_create($article
                                              ['fModificacion']),
                                  'd/m/y h:m'); ?>**         </b>
        <hr/>
 **<?php echo $article['text']; ?>**      </div>
    </div>

    <h2>Comments</h2>
 **<?php foreach ($comments as $comment) { ?>** 
      <div class="panel panel-warning">
        <div class="panel-heading">
          <h3 class="panel-title">**<?php echo $comment['username']; ?>**                                   said</h3>
        </div>
        <div class="panel-body">
 **<?php echo $comment['comment']; ?>**        </div>
      </div>
 **<?php } ?>** 
    <div>
 **<?php if ( !empty( $arrUser ) ) { ?>** 
        <form action="article.php?id=**<?php echo $_GET['id']; ?>**"
              method="post">
          <div class="form-group">
            <label for="user">Post a comment</label>
            <textarea class="form-control" rows="3" cols="50"
                      name="comment" id="comment"> 
            </textarea>
          </div>

          <div class="form-group">
            <input name="submit" type="submit" value="Send"
                   class="btn btn-primary" />
          </div>
        </form>

 **<?php } else { ?>**        <p>
          Please sign up to leave a comment on this article. 
          <a href="signup.php">Sign up</a> or
          <a href="login.php">Log in</a>
        </p>
 **<?php } ?>**    </div>

    <?php include_once 'footer.php'; ?>
```

这些是我们应该遵循的步骤，以便将业务逻辑层与视图隔离开来。

### 提示

如果你愿意，可以将所有视图文件（`header.php`，`footer.php`，`index.php`，`article.php`等）放入一个名为`views`的文件夹中，以便在同一个文件夹中组织它们。

一旦我们将所有视图与业务逻辑隔离开来，我们将在控制器中包含所有方法，而不是在表示层中包含它们。正如我们之前所说，这只是一个临时解决方案，因此我们将寻找真正的解决方案，以将模块提取为微服务。

## 提取服务

在这种策略中，我们必须选择要隔离的第一个模块，以便从中制作一个微服务。在这种情况下，我们将从`Categories`模块开始做。

类别在管理员面板上使用最多。可以在其中创建、修改和删除类别，然后在创建新文章时选择它们，并在文章中显示以指示文章类别。

提取过程并不容易；我们必须确保我们知道模块被使用的所有地方。为了做到这一点，我们将创建一个双向 API 或在控制器中创建所有类别方法，然后将它们隔离在一个微服务中。

打开`admin/categories.php`文件，我们必须做与前端和后端分离相同的事情--找到所有引用类别的地方，并在控制器上创建一个新方法。看一下这个：

```php
    <?

      session_start ();

      require_once 'config.php';
      require_once 'connection.php';
      require_once 'isUser.php';

 **include_once '../Controller.php';**
 **$controller = new Controller();**
      $dbConn = connect();

      /* Omitted code */

      if (!empty($_GET['del'])) {
 **$controller->deleteCategory($_GET['del']);**

        header( 'Location: categories.php?dele=true' );
        die;
      }

      if (!empty($_POST['submit'])) {
        if (!empty($_POST['name'])) {
          $name = $_POST['name'];
        }
        if (empty($name)) {
          $error['name'] = 'Please enter category name';
        }
        if (empty($error)) {
 **$controller->createCategory($name);**
          header( 'Location: categories.php?add=true' );
          die;
        }
      }

      if (!empty($_POST['submitEdit'])) {

        /* Ommited code */

        if (empty($error)) {
 **$controller->updateCategory($id, $name);**
          header( 'Location: categories.php?edit=true' );
          die;
        }
      }

 **$arrCategories = $controller->getCategories();**

      if (!empty($_GET['id'])) {
 **$row = $controller->getCategory($_GET['id']);**
      }

      include_once 'header.php';

    ?>
    <!-- Omitted HTML code -->

```

`controller.php`文件必须包含类别方法：

```php
    public function createCategory($name)
    {
      $dbConn = $this->connect();

      $query = "INSERT INTO `categories` (value) VALUES ('$name')";
      mysql_query($query, $dbConn);
    }

    public function updateCategory($id,$name)
    {
      $dbConn = $this->connect();

      $query = "UPDATE `categories` set value = '$name'
                WHERE id = $id";
      mysql_query($query, $dbConn);
    }

    public function deleteCategory($id)
    {
      $dbConn = $this->connect();

      $query = "DELETE FROM `categories` WHERE id = ".$id;
      mysql_query($query, $dbConn);
    }

    public function getCategories()
    {
      $dbConn = $this->connect();

      $arrCategories = array();

      $query = "SELECT id, value FROM `categories` ORDER BY value ASC";
      $resultado = mysql_query ($query, $dbConn);

      while ($row = mysql_fetch_assoc ($resultado)) {
        array_push( $arrCategories,$row );
      }

      return $arrCategories;
    }

    public function getCategory($id)
    {
      $dbConn = $this->connect();

      $query = "SELECT id, value FROM `categories` WHERE id = ".$id;
      $resultado = mysql_query ($query, $dbConn);
      return mysql_fetch_assoc ($resultado);
    }
```

在`admin/articles.php`文件中有更多关于类别的引用，因此打开它并在`require_once`行后添加以下行：

```php
    include_once '../Controller.php';
    $controller = new Controller();
```

这些行将允许您在`articles.php`文件中使用`controller.php`文件中包含的类别方法。将用于获取类别的代码修改为以下代码：

```php
    $arrCategories = $controller->getCategories();
```

最后，需要对文章视图进行一些更改。这是用于显示文章的视图，并且在创建文章时包含所选的类别。

要获取文章，执行的查询如下：

```php
    SELECT articles.id, articles.title, articles.extract,
           articles.text, articles.updated_at,
           categories.value as category,
           users.username FROM `articles`
 **INNER JOIN `categories` ON categories.id = articles.category_id** 
    INNER JOIN `users` ON users.id = articles.user_id 
    WHERE articles.id = " . $id . " LIMIT 1;
```

如您所见，查询需要类别表。如果要为类别微服务使用不同的数据库，您将需要从查询中删除突出显示的行，选择查询中的`articles.category_id`，然后使用创建的方法获取类别名称。因此，查询将如下所示：

```php
    SELECT articles.id, articles.title, articles.extract,
           articles.text, articles.updated_at, articles.category_id,
           users.username FROM `articles` 
    INNER JOIN `users` ON users.id = articles.user_id 
    WHERE articles.id = " . $id . " LIMIT 1;
```

以下是从提供的类别 ID 获取类别名称的代码：

```php
    public function getArticle($id)
    {
      $dbConn = $this->connect();

      $query = "SELECT articles.id, articles.title, articles.extract,
                       articles.text, articles.updated_at,
                       articles.category_id,
                       users.username FROM `articles`
                INNER JOIN `users` ON users.id = articles.user_id
                WHERE articles.id = " . $id . " LIMIT 1;";

      $result = mysql_query ($query, $dbConn);

      $data = mysql_fetch_assoc($result);
 **$data['category'] = $this->getCategory($data['category_id']);**
 **$data['category'] = $data['category']['value'];**
      return $data;
    }
```

一旦我们进行了所有这些更改，就可以将类别表隔离到不同的数据库中，因此我们可以从`controller.php`文件中创建的方法创建一个类别微服务：

+   `public function createCategory($name)`

+   `public function updateCategory($id,$name)`

+   `public function deleteCategory($id)`

+   `public function getCategories()`

+   `public function getCategory($id)`

正如您所想象的那样，这些函数用于创建类别微服务的`routes.php`文件。因此，让我们创建一个新的微服务，就像我们使用停止潜水策略一样。

通过执行以下命令创建新的类别微服务：

```php
**composer create-project --prefer-dist laravel/lumen categories**

```

上述命令将在名为 categories 的文件夹中安装 Lumen，因此我们可以开始创建新类别微服务的代码。

现在我们有两个选项--第一个是使用位于当前数据库上的相同表--我们可以将新微服务指向当前数据库。第二个选项是在新数据库中创建一个新表，因此新微服务将使用自己的数据库。

如果要在新数据库中创建一个新表，可以按照以下步骤进行：

+   将当前类别表导出到 SQL 文件中。它将保留当前存储的数据。

+   将 SQL 文件导入新数据库。它将在新数据库中创建导出的表和数据。

### 提示

导出/导入过程可以使用 SQL 客户端执行，也可以通过控制台执行`mysqldump`。

一旦新表被导入到新数据库，或者您决定使用当前数据库，就需要设置`.env.example`文件，以便将新微服务连接到正确的数据库，因此打开它并在其中放入正确的参数：

```php
    DB_CONNECTION=mysql
    DB_HOST=localhost
    DB_PORT=3306
    DB_DATABASE=**categories**
    DB_USERNAME=root
    DB_PASSWORD=root
```

不要忘记将`.env.example`文件重命名为`.env`，并在`public/index.php`中更改`$app->run()`行，就像我们之前所做的那样，更改为以下代码：

```php
 **$app->run(**
 **$app->make('request')**
 **);**

```

还要取消注释`/bootstrap/app.php`中的以下行：

```php
    $app->withFacades();
    $app->withEloquent();
```

现在我们准备在`routes.php`文件中添加必要的方法。我们必须添加单体应用程序`Controller.php`中的类别方法，并将它们转换为路由：

+   `public function createCategory($name)`: 这是用于创建新类别的 POST 方法。因此，它可能类似于`$app->post('category', 'CategoryController@createCategory');`。

+   `public function updateCategory($id,$name)`: 这是一个 PUT 方法，用于编辑现有的类别。因此，它可能类似于`app->put('category/{id}', 'CategoryController@updateCategory');`。

+   `public function deleteCategory($id)`: 这是用于删除现有类别的 DELETE 方法。因此，它可能类似于`app->delete('category/{id}', 'CategoryController@deleteCategory');`。

+   `public function getCategories()`: 这是用于获取所有现有类别的 GET 方法。因此，它可能类似于`app->get('categories', 'CategoryController@getCategories');`。

+   `public function getCategory($id)`: 这也是一个 GET 方法，但它只获取一个单一的类别。因此，它可能类似于`app->get('category/{id}', 'CategoryController@getCategory');`。

因此，一旦我们在`routes.php`文件中添加了所有路由，就是创建类别模型的时候了。要做到这一点，在`/app/Model`中创建一个新文件夹和一个文件`/app/Model/Category.php`，就像这样：

```php
    <?php

      namespace App\Model;

      use Illuminate\Database\Eloquent\Model;

      class Category extends Model {
        protected $table = 'categories';
        protected $fillable = ['value'];
        public $timestamps = false;
      }
```

创建模型后，创建一个`/app/Http/Controllers/CategoryController.php`文件，其中包含必要的方法：

```php
    <?php

      namespace App\Http\Controllers;

      use App\Model\Category;
      use Illuminate\Http\Request;

      class CategoryController extends Controller
      {
        public function **createCategory**(Request $request) {
          $category = new Category();
          $category->fill(['value' => $request->input('value')]);
          $category->save();

          return response()->json([]);
        }

        public function **updateCategory**(Request $request, $id) {
          $category = Category::find($id);
          $category->value = $request->input('value');
          $category->save();

          return response()->json([]);
        }

        public function **deleteCategory**(Request $request, $id) {
          $category = Category::find($id);
          $category->delete();

          return response()->json([]);
        }

        public function **getCategories**(Request $request) {
          $categories = Category::get();

          return $categories;
        }

        public function **getCategory**(Request $request, $id) {
          $category = Category::find($id);

          return $category;
        }
      }
```

现在，我们已经完成了我们的类别微服务。您可以在 Postman 中尝试一下，以检查所有方法是否有效。例如，可以通过 Postman 使用`http://localhost/categories/public/categories` URL 调用`getCategories`方法。

一旦我们创建了新的类别微服务并且正常工作，就是时候断开类别模块并将单体应用程序连接到微服务了。

返回到单体应用程序并查找所有对类别方法的引用。我们必须通过调用新的微服务来替换它们。我们将使用原生 curl 调用进行这些调用，但是您应该考虑使用 Guzzle 或类似的包，就像我们在之前的章节中所做的那样。

为此，首先我们应该在`Controller.php`文件中创建一个函数来进行调用。可以是这样的：

```php
    function call($url, $method, $field = null)
    {
      $ch = curl_init();
      if(($method == 'DELETE') || ($method == 'PUT')) {
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
      }
      curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
      curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
      curl_setopt($ch, CURLOPT_URL,$url);
      if ($method == 'POST') {
        curl_setopt($ch, CURLOPT_POST,true);
      }
      if($field) {
        curl_setopt($ch, CURLOPT_POSTFIELDS, 'value='.$field);
      }
      $result=curl_exec($ch);
      curl_close($ch);
      return json_decode($result, true);
    }
```

上述代码将用于在每次调用类别微服务时重用代码。

转到`/admin/categories.php`文件并用以下代码替换`controller->createCategory($name);`行：

```php
     $controller->call('http://localhost/categories/public/category', 
                       'POST', $name);
```

在上述代码中，您可以检查我们正在使用 POST 调用创建类别方法，并将值参数设置为`$name`变量。

在`/admin/categories.php`文件中，找到并用以下代码替换`controller->updateCategory($id, $name);`行：

```php
 $controller->call('http://localhost/categories/public/category/'.$id,
                   'PUT', $name);
```

在同一文件中，找到并用以下代码替换`$controller->deleteCategory($_GET['del']);`：

```php
    $controller->call('http://localhost/categories/public
                       /category/'.$_GET['del'], 'DELETE');
```

在同一文件中，再次以及在`/admin/articles.php`文件中，找到并用以下代码替换`$arrCategories = $controller->getCategories();`：

```php
$arrCategories = $controller->call('http://localhost/categories
                                    /public/categories', 'GET');
```

最后一个位于`/admin/categories.php`文件中。找到并用以下代码替换`row = $controller->getCategory($_GET['id']);`行：

```php
$row = $controller->call('http://localhost/categories
                          /public/category/'.$_GET['id'], 'GET');
```

一旦我们完成了在单体应用程序中用新的类别微服务调用替换所有类别方法，我们可以删除对单体类别模块的所有引用。

转到`Controller.php`文件并删除以下函数，因为它们不再需要，因为它们引用了单体类别模块：

+   `public function deleteCategory($id)`

+   `public function createCategory($name)`

+   `public function updateCategory($id,$name)`

+   `public function getCategories()`

+   `public function getCategory($id)`

最后，如果您为类别微服务创建了新的数据库，可以通过执行以下查询来删除位于单体应用程序数据库中的类别表：

```php
    DROP TABLE categories;
```

我们已经从单体应用程序中提取了类别服务。下一步将是选择另一个模块，再次按照相同步骤进行，并重复此过程，直到单体应用程序消失或成为微服务为止。

在第七章中，*安全*我们谈到了微服务中的安全性。为了练习您所学到的知识，请查看本章中的所有代码，并找出我们示例中的弱点。

# 摘要

在本章中，您学习了转换单体应用程序为微服务的策略，并为每个步骤使用了示例代码。从现在开始，您已经准备好告别单体应用程序，并进行转换，以开始使用微服务。


# 第十章：可扩展性策略

您的应用程序已准备就绪。现在是计划未来的时候了。在本章中，我们将为您全面介绍如何检查应用程序可能的瓶颈以及如何计算应用程序的容量。在本章结束时，您将具备创建自己的可扩展性计划的基本知识。

# 容量规划

**容量规划**是确定应用程序所需的基础设施资源的过程，以满足应用程序未来的工作负载需求。该过程确保您在需要时有足够的资源可用，从而将成本降至最低。如果您知道应用程序的使用方式和当前资源的限制，您可以推断数据并大致了解未来的需求。为您的应用程序创建容量规划具有一些好处，其中我们可以突出以下好处：

+   **最小化成本并避免过度配置的浪费**：您的应用程序将仅使用所需的资源，因此，例如，当您只使用 8GB 时，为数据库拥有 64GB RAM 服务器是没有意义的。

+   **预防瓶颈并节省时间**：您的容量计划突出显示基础设施的每个元素何时达到峰值，为您提供有关瓶颈可能出现的提示。

+   **提高业务生产力**：如果您有一个详细的计划，指出基础设施的每个元素的限制，并知道每个元素何时达到其限制，那么您就有了空余时间来专注于其他业务任务。您将有一套指令，以便在需要增加应用程序容量的确切时刻遵循。当您遇到瓶颈并不知道该怎么办时，就不会再有疯狂的时刻了。

+   **用作业务目标的映射**：如果您的应用程序对您的业务至关重要，此文档可用于突出一些业务目标。例如，如果业务想要达到 1,000 个用户，您的基础设施需要支持它们，标记一些需要满足此要求的投资。

## 了解您的应用程序的限制

了解您的应用程序的限制的主要目的是在开始出现问题之前知道我们在任何给定时间点还有多少容量。我们需要做的第一件事是创建我们应用程序组件的清单。尽可能详细地制作清单；这将帮助您了解项目中所有工具。在我们的示例应用程序中，不同组件的清单可能类似于以下内容：

+   自动发现服务：

+   Hashicorp Consul

+   遥测服务：

+   Prometheus

+   战斗微服务：

+   代理：NGINX

+   应用引擎：PHP 7 FPM

+   数据存储：Percona

+   缓存存储：Redis

+   位置微服务：

+   代理：NGINX

+   应用引擎：PHP 7 FPM

+   数据存储：Percona

+   缓存存储：Redis

+   秘密微服务：

+   代理：NGINX

+   应用引擎：PHP 7 FPM

+   数据存储：Percona

+   缓存存储：Redis

+   用户微服务：

+   代理：NGINX

+   应用引擎：PHP 7 FPM

+   数据存储：Percona

+   缓存存储：Redis

一旦我们将应用程序减少到基本组件，我们需要分析并确定每个组件的使用情况以及适当测量中的最大容量。

某些组件可能有多个���联的测量，例如数据存储层（在我们的案例中为 Percona）。对于此组件，我们可以测量 SQL 事务数量、使用的存储量、CPU 负载等。在前几章中，我们添加了一个遥测服务；您可以使用此服务从每个组件中收集基本统计信息。

您可以为应用程序的每个组件记录的一些基本统计信息如下：

+   CPU 负载

+   内存使用

+   网络使用

+   IOPS

+   磁盘利用率

在某些软件中，您需要收集一些特定的测量。例如，在数据库上，您可以检查以下内容：

+   每秒事务数

+   缓存命中率（如果启用了查询缓存）

+   用户连接

下一步是确定应用程序的自然增长。如果没有进行特殊操作（如 PPC 广告活动和新功能），则可以将此测量定义为应用程序的增长。这个测量可以是新用户的数量或活跃用户的数量，例如。想象一下，您将应用程序部署到生产环境，并停止添加新功能或进行营销活动。如果过去一个月新用户的数量增加了 7%，那么这个数量就是您的应用程序的自然增长。

一些企业/项目具有季节性趋势，这意味着在特定日期，您的应用程序的使用量会增加。想象一下，您是一个礼品零售商，您的大部分销售可能是在情人节或年底（黑色星期五，圣诞节）左右完成的。如果这是您的情况，请分析您拥有的所有数据以建立季节性数据。

现在您已经了解了应用程序的一些基本统计数据，是时候计算所谓的剩余空间了。剩余空间可以定义为在资源耗尽之前您拥有的资源量。可以用以下公式计算：

![了解应用程序的限制](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-msvc/img/B06142_10_01.jpg)

剩余空间公式

从上述公式中可以看出，计算特定组件的剩余空间非常简单。在我们举例之前，让我们解释每个变量：

+   **理想使用率：** 这是一个百分比，描述了我们计划使用的应用程序特定组件的容量。理想使用率永远不应该达到 100%，因为当接近资源限制时，可能会出现无法保存数据库中数据等奇怪的行为。我们建议将此量设置在 60%至 75%之间，为高峰时刻留出足够的额外空间。

+   **最大容量：** 这是指我们研究对象组件的最大容量。例如，一个能够处理最多 250 个并发连接的 Web 服务器。

+   **当前使用率：** 这是指我们正在研究的组件的当前使用率。

+   **增长：** 这是指我们应用程序的自然增长的百分比。

+   **优化：** 这是可选变量，描述了在特定时间内我们可以实现的优化量。例如，如果您当前的数据库每秒可以处理 35 个查询，经过一些优化后，您可以实现每秒 50 个查询。在这种情况下，优化量为 15。

假设您正在计算我们的一个 NGINX 可以处理的每秒请求的剩余空间。对于我们的应用程序，我们已经决定将理想使用率设置为 60%（0.6）。根据我们的测量和从负载测试中提取的数据（稍后在本章中解释），我们知道每秒请求的最大数量（RPS）为 215。在我们当前的统计数据中，我们的 NGINX 服务器今天提供了最高 193 RPS，并且我们已经计算出了下一年的增长至少为 11 RPS。

我们想要测量的时间段是 1 年，我们认为我们可以在这段时间内实现最大容量 250 RPS，因此我们的剩余空间值将如下所示：

*剩余空间= 0.6 * 215 - 123 - (11 - 35) = 30 RPS*

这个计算意味着什么？由于结果是正数，这意味着我们有足够的预留空间。如果我们将结果除以增长和优化的总和，我们可以计算出我们达到资源限制之前还有多少时间。

由于我们的时间段是 1 年，我们可以计算出我们达到资源限制之前还有多少时间，如下所示：

*Headroom 时间= 30 rpm / 24 = 1.25 年*

您可能已经推断出，我们的 NGINX 服务器还有 1.25 年才能达到 RPS 的极限。在本节中，我们向您展示了如何计算特定组件的余量；现在轮到您为您的每个组件和每个组件可用的不同指标进行计算了。

## 可用性数学

**可用性**可以定义为网站在特定时间段内的可用性，例如一周，一天，一年等。根据您的应用程序对您或您的业务的重要性，停机时间可能等于丢失的收入。正如您可以想象的那样，可用性可能成为应用程序由客户/用户使用并且他们需要您的服务的任何时间的情况下最重要的指标。

我们对可用性有了理论概念。现在是时候做一些数学运算了，拿出你的计算器。根据早期的一般定义，可用性可以计算为您的应用程序可以被用户/客户使用的时间除以时间范围（我们正在测量的特定时间段）。

假设我们想要测量我们的应用程序在一周内的可用性。一周内，我们有`10,080`分钟：

* 7 天 x 每天 24 小时 x 每小时 60 分钟= 7 * 24 * 60 = **10,080 分钟***

现在，假设您的应用程序在那周发生了一些故障，并且您的应用程序的可用分钟数减少到`10,000`。要计算我们示例的可用性，我们只需要进行一些简单的数学运算：

* 10,000 / 10,080 = 0.9920634921*

可用性通常以百分比（％）表示，因此我们需要将结果转换为百分比：

* 0.9920634921 * 100 = 99.20634921％〜**99.21***

我们的应用程序在一周内的可用性为`99.21％`。不算太糟糕，但离我们的目标结果还差得远，即尽可能接近`100％`。大多数情况下，可用性百分比被称为**数量的九**，并且它们越接近`100％`，就越难以维护应用程序的可用性。为了让您了解达到`100％`可用性将有多困难，这里有一些可用性和可能停机时间的示例：

+   99.21％（我们的示例）：

+   每周：1 小时 19 分钟 37.9 秒

+   每月：5 小时 46 分钟 15.0 秒

+   每年：69 小时 14 分钟 59.9 秒

+   99.5％：

+   每周：50 分钟 24.0 秒

+   每月：3 小时 39 分钟 8.7 秒

+   每年：43 小时 49 分钟 44.8 秒

+   99.9％：

+   每周：10 分钟 4.8 秒

+   每月：43 分钟 49.7 秒

+   每年：8 小时 45 分钟 57.0 秒

+   99.99％：

+   每周：1 分钟 0.5 秒

+   每月：4 分钟 23.0 秒

+   每年：52 分钟 35.7 秒

+   99.999％：

+   每周：6.0 秒

+   每月：26.3 秒

+   每年：5 分钟 15.6 秒

+   99.9999％：

+   每周：0.6 秒

+   每月：2.6 秒

+   每年：31.6 秒

+   99.99999％：

+   每周：0.1 秒

+   每月：0.3 秒

+   每年：3.2 秒

正如您所看到的，接近`100％`的可用性变得越来越困难，停机时间变得更紧。但是，您如何减少停机时间或至少确保尽力保持低水平呢？这个问题没有简单的答案，但我们可以给您一些建议，告诉您可以做的不同事情：

+   最坏的情况将发生，因此您应该经常模拟故障，以便随时准备应对应用程序的大灾难。

+   找出应用程序可能的瓶颈。

+   测试，到处都是测试，当然，要保持它们更新。

+   记录任何事件，任何指标，您可以测量或保存为日志的任何内容，并保存以供将来参考。

+   了解您的应用程序的限制。

+   至少要有一些良好的开发实践，至少要分享应用程序构建的知识。在所有这些实践中，您可以执行以下操作之一：

+   对于任何热修复或功能，需要第二次批准

+   成对编程

+   创建持续交付管道。

+   制定备份计划并确保您的备份安全并随时可用。

+   记录所有内容，任何小的更改或设计，并始终保持文档最新。

现在您已经全面了解了“可用性”意味着什么，以及每个速率的最大停机时间。如果您向用户/客户提供 SLA（服务级别协议），请注意，您将会对应用程序的可用性做出承诺，您将需要履行这个承诺。

# 负载测试

负载测试可以定义为在应用程序中施加需求（负载）以测量其响应的过程。这个过程可以帮助您确定应用程序或基础设施的最大容量，并且可以突出显示应用程序或基础设施的瓶颈或问题元素。进行负载测试的正常方式是首先在应用程序中进行“正常”条件下的测试，也就是在应用程序中进行正常负载的测试。在正常条件下测量系统的响应可以让您拥有一个基线，您将用它来与未来的测试进行比较。

让我们看一些您可以用于负载测试的最常见工具。有些简单易用，而其他一些更复杂和强大。

## Apache JMeter

Apache JMeter 应用程序是一个用 Java 构建的开源软件，旨在进行负载测试和性能测量。起初，它是为 Web 应用程序设计的，但随着时间的推移，它扩展到测试其他功能。

Apache JMeter 的一些最有趣的功能如下：

+   支持不同的应用程序/服务器/协议：HTTP(S)、SOAP/Rest、FTP、LDAP、TCP 和 Java 对象。

+   与第三方持续集成工具轻松集成：它具有用于 Maven、Gradle 和 Jenkins 的库。

+   命令行模式（非 GUI/无头模式）：这使您可以在安装了 Java 的任何操作系统上进行测试。

+   多线程框架：这允许您通过许多线程进行并发样本，并通过单独的线程组同时对不同功能进行采样。

+   高度可扩展：它可以通过库或插件等进行扩展。

+   完整的测试 IDE：它允许您创建、记录和调试您的测试计划。

正如您所看到的，这个项目是一个有趣的工具，您可以在负载测试中使用。在接下来的部分中，我们将向您展示如何构建一个简单的测试场景。不幸的是，我们的书中没有足够的空间来涵盖所有功能，但至少您将了解未来更复杂测试的基础知识。

### 安装 Apache JMeter

由于是用 Java 开发的，这个应用程序可以在安装了 Java 的任何操作系统上使用。让我们在开发机器上安装它。

第一步是满足主要要求——您需要一个 JVM 6 或更高版本来使应用程序工作。您可能已经在您的计算机上安装了 Java，但如果不是这种情况，您可以从 Oracle 页面下载最新的 JDK。

要检查您的 Java 运行时版本，您只需要在您的操作系统中打开终端并执行以下命令：

```php
**java -version**

```

上述命令将告诉您在您的计算机上可用的版本。

一旦我们确定了正确的版本，我们只需要转到官方的 Apache JMeter 页面（[`jmeter.apache.org`](http://jmeter.apache.org)）并下载最新的 ZIP 或 TGZ 格式的二进制文件。一旦二进制文件完全下载到您的计算机上，您只需要解压下载的 ZIP 或 TGZ，Apache JMeter 就可以使用了。

### 使用 Apache JMeter 执行负载测试

打开您解压缩 Apache JMeter 二进制文件的文件夹。在那里，您可以找到一个`bin`文件夹和一些不同操作系统的脚本。如果您使用 Linux/UNIX 或 Mac OS，您可以���行`jmeter.sh`脚本来打开应用程序的 GUI。如果您使用 Windows，有一个`jmeter.bat`可执行文件，您可以用它来打开 GUI：

![使用 Apache JMeter 执行负载测试](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-msvc/img/B06142_10_02.jpg)

Apache JMeter GUI

Apache JMeter GUI 允许您构建不同的测试计划，正如您在前面的截图中所看到的，即使不阅读手册，界面也非常容易理解。让我们用 GUI 构建一个测试计划。

### 提示

一个测试计划可以被描述为 Apache JMeter 将按特定顺序运行的一系列步骤。

为了创建我们的测试计划的第一步，需要在**测试计划**节点下添加一个**线程组**。在 Apache JMeter 中，线程组可以被定义为并发用户的模拟。按照给定的步骤创建一个新的组：

1.  右键单击**测试计划**节点。

1.  在上下文菜单中，选择**添加 | 线程（用户） | 线程组**。

前面的步骤将在我们的**测试计划**节点中创建一个子元素。选择它，以便我们可以对我们的组进行一些调整。参考以下截图：

![使用 Apache JMeter 执行负载测试](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-msvc/img/B06142_10_03-1.jpg)

线程组设置

如前面的截图所示，每个线程组都允许您指定测试的用户数量和测试的持续时间。主要可用的选项如下所示：

+   **样本错误后要采取的操作：**这个选项允许您控制测试在抛出样本错误时的行为。最常用的选项是**继续**行为。

+   **线程数（用户数）：**这个字段允许您指定要用来击打您的应用程序的并发用户数量。

+   **ramp-up 周期（以秒为单位）：**这个字段用于告诉 Apache JMeter 可以用多少时间来创建您在前一个字段中指定的所有线程。例如，如果您将此��段设置为 60 秒，并且**线程数（用户数）**设置为 6，Apache JMeter 将花费 60 秒来启动所有 6 个线程，每 10 秒一个。

+   **循环计数和永远：**这些字段允许您在特定次数的执行后停止测试。

其余选项都是不言自明的，在我们的示例中，我们将只使用上述字段。

假设您想使用 25 个线程（就像用户），并将 ramp-up 设置为 100 秒。数学会告诉您，每 4 秒将创建一个新的线程，直到有 25 个线程在运行（100/25 = 4）。这两个字段允许您设计您的测试，以便在合适的时间开始缓慢增加击打您的应用程序的用户数量。

一旦我们定义了我们的线程/用户，就是时候添加一个请求了，因为没有请求，我们的测试将无法进行。要添加一个请求，您只需要选择线程组节点，右键单击上下文菜单，然后选择**添加 | 取样器 | HTTP 请求**。前面的操作将在我们的线程组中添加一个新的子节点。选择新节点，Apache JMeter 将向您显示一个类似于以下截图的表单：

![使用 Apache JMeter 执行负载测试](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-msvc/img/B06142_10_04.jpg)

HTTP 请求选项

如前面的截图所示，我们可以设置要用我们的测试击打的主机。在我们的情况下，我们决定在端口 8083 上用`GET`请求击打`localhost`的`/api/v1/secret/`路径。随意探索高级选项或添加自定义参数。Apache JMeter 非常灵活，几乎涵盖了每种可能的场景。

在这一点上，我们已经建立了一个基本的测试，现在是时候看看结果了。让我们探索一些有趣的方法来收集测试的信息。为了查看和分析我们测试的每次迭代的结果，我们需要添加一个**监听器**。要做到这一点，就像在之前的步骤中一样，右键单击**线程组**，然后导航到**添加 | 监听器 | 在表中查看结果**。这个操作将在我们的测试中添加一个新的节点，一旦我们开始测试，结果将出现在应用程序中。

如果您在**线程组**中选择了**永远**选项，则需要手动停止测试。您可以使用绿色播放旁边显示的红色十字图标来停止。此按钮将停止等待每个线程结束其操作的测试。如果单击停止图标，Apache JMeter 将立即终止所有线程。

让我们试一试，点击绿色播放图标开始测试。点击**查看结果表**节点，您将看到测试结果的所有结果出现：

![使用 Apache JMeter 执行负载测试](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-msvc/img/B06142_10_05.jpg)

Apache JMeter 表中的结果

如前面的屏幕截图所示，Apache JMeter 为每个请求记录了不同的数据，例如发送/返回的字节数，状态或请求延迟等。当您更改负载量时，所有这些数据都很有趣。使用此监听器，您甚至可以导出数据，以便使用外部工具分析结果。

如果您没有外部工具来分析数据，但是您想要一些基本的统计数据来与您的应用程序暴露给不同负载进行比较，您可以添加另一个有趣的监听器。与之前一样，打开**线程组**的右键上下文菜单，导航到`添加` | **监听器** | `摘要报告`。此监听器将为您提供一些基本统计数据，供您用于比较结果：

![使用 Apache JMeter 执行负载测试](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-msvc/img/B06142_10_06.jpg)

Apache JMeter 摘要报告

如前面的屏幕截图所示，此监听器为我们提供了一些测量的平均值。

使用表格显示结果是可以的。但是众所周知，一张图片胜过千言万语，因此让我们添加一些图形监听器，以便您完成负载测试报告。右键单击**线程组**，在上下文菜单中转到**添加** | **监听器** | **响应时间图**。您将看到一个类似于以下的屏幕：

![使用 Apache JMeter 执行负载测试](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-msvc/img/B06142_10_07.jpg)

Apache JMeter 响应时间图

随意对默认设置进行一些更改。例如，您可以减少**间隔（毫秒）**。如果再次运行测试，测试生成的所有数据将用于生成一个漂亮的图表，如下图所示：

![使用 Apache JMeter 执行负载测试](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-msvc/img/B06142_10_08-1.jpg)

响应时间图

从我们的测试结果生成的图表中可以看出，线程（用户）的增加导致响应时间的增加。你认为这意味着什么？如果你说我们的测试基础设施需要扩大以适应负载的增加，那么你的回答是正确的。

Apache JMeter 具有多个选项来创建您的负载测试。我们只向您展示了如何创建基本测试以及如何查看结果。现在轮到您探索所有可用的不同选项来创建高级测试，并发现哪些功能更适合您的项目。让我们看看您可以用于负载测试的其他工具。

## 使用 Artillery 进行负载测试

**Artillery**是一个开源工具包，您可以使用它对应用程序进行负载测试，它类似于 Apache JMeter。除其他功能外，我们可以强调此工具的以下优点：

+   支持多种协议，HTTP(S)或 WebSockets 可以直接使用

+   易于与实时报告软件或 DataDog 和 InfluxDB 等服务集成

+   高性能，因此可以在普通硬件/服务器上使用

+   非常容易扩展，因此可以根据您的需求进行调整

+   具有详细性能指标的不同报告选项

+   非常灵活，因此您可以测试几乎任何可能的场景

### 安装 Artillery

Artillery 是基于 node.js 构建的，因此主要要求是在您将用于执行测试的计算机上安装此运行时。

我们喜欢容器化技术，但不幸的是，在 Docker 上使用 artillery 没有简单的方法，除非进行一些不干净的操作。无论如何，我们建议您使用专用的 VM 或服务器进行负载测试。

要使用 Artillery，您需要在您的 VM/server 中安装 node.js，这个软件非常容易安装。我们不打算解释如何创建本地 VM（您可以使用 VirtualBox 或 VMWare 创建一个），我们只会向您展示如何在 RHEL/CentOS 上安装它。对于其他操作系统和选项，您可以在 node.js 文档中找到详细信息（[`nodejs.org/en/download/`](https://nodejs.org/en/download/)）。

打开您的 RHEL/CentOS 虚拟机或服务器的终端，并下载 LTS 版本的设置脚本：

```php
**curl --silent -location  https://rpm.nodesource.com/setup_6.x | bash -**

```

一旦上一个命令完成，您需要以 root 身份执行下一个命令，如下所示：

```php
**yum -y install nodejs**

```

执行上述命令后，您的 VM/server 将安装并准备好 Node.js。现在是时候使用 Node.js 包管理器`npm`命令全局安装 Artillery 了。在您的终端中，执行以下命令以全局安装 Artillery：

```php
**npm install -g artillery**

```

一旦上一个命令完成，您就可以使用 Artillery 了。

我们可以做的第一件事是检查 Artillery 是否已正确安装并可用。输入以下命令进行检查：

```php
**artillery dino**

```

上述命令将向您显示一个可爱的恐龙，这意味着 Artillery 已经准备好使用了。

### 使用 Artillery 执行负载测试

Artillery 是一个非常灵活的工具包。您可以从控制台运行测试，也可以使用描述测试场景的 YAML 或 JSON 文件运行它们。请注意，在我们的以下示例中，我们使用`microservice_secret_nginx`作为我们要测试的主机，您需要将此主机调整为您本地环境的 IP 地址。让我们来看看这个工具；在我们的负载测试 VM/server 中运行以下命令：

```php
**artillery quick --duration 30 --rate 5 -n 1  
http://microservice_secret_nginx/api/v1/secret/**

```

上述命令将在 30 秒的时间内进行快速测试。在此期间，Artillery 将创建五个虚拟用户；每个用户将对提供的 URL 进行一次 GET 请求。一旦执行了上述命令，Artillery 将开始测试并每 10 秒打印一些统计信息。在测试结束时（30 秒），此工具将向您显示一个类似于以下的小报告：

```php
**Complete report @ 2016-12-17T16:09:34.140Z
  Scenarios launched:  150
  Scenarios completed: 150
  Requests completed:  150
  RPS sent: 4.87
  Request latency:
    min: 578.1
    max: 1223.7
    median: 781.5
    p95: 1146.5
    p99: 1191.1
  Scenario duration:
    min: 583.2
    max: 1226.8
    median: 786.1
    p95: 1150
    p99: 1203.8
  Scenario counts:
    0: 150 (100%)
  Codes:
    200: 150**

```

上述报告非常易于理解，并为您提供了基础设施和应用程序的绩效概述。

在我们开始分析 Artillery 报告之前，您需要了解的一个基本概念是场景的概念。简而言之，**场景**是您想要测试的一系列任务或操作，它们是相关的。想象一下，您有一个电子商务应用程序；一个测试场景可以是用户在完成购买之前执行的所有步骤。考虑以下示例：

1.  用户加载主页。

1.  用户搜索产品。

1.  用户向购物篮中添加产品。

1.  用户去结账。

1.  用户进行购买。

所有提到的操作都可以转换为对您的应用程序的请求，模拟用户操作，这意味着一个场景是一组请求。

现在我们清楚了这个概念，我们可以开始分析 Artillery 输出的报告。在我们的示例中，我们只有一个场景，只有一个请求（`GET`）到`http://microservice_secret_nginx/api/v1/secret/`。这个测试场景由五个虚拟用户执行，他们在 30 秒内只发出一个`GET`请求。一个简单的数学计算，`5 * 1 * 30`，给出了我们测试的场景总数（`150`），这与我们的情况下的请求总数相同。`RPS sent`字段给出了我们的测试服务器在测试期间平均每秒发送的请求。这不是一个非常重要的字段，但它可以让您了解测试的执行情况。

让我们来看看 Artillery 给出的`Request latency`和`Scenario duration`统计数据。您需要知道的第一件事是，这些组的所有测量都是以毫秒为单位的。

在`Request latency`的情况下，数据向我们展示了应用程序处理我们发送的请求所用的时间。两个重要的统计数据是 95%（`p95`）和 99%（`p99`）。您可能已经知道，百分位数是统计学中用于指示给定百分比观察值落在其下的值的度量。从我们的示例中，我们可以看到 95%的请求在 1146.5 毫秒或更短的时间内被处理，或者 99%的请求在 1191.1 毫秒或更短的时间内被处理。

在我们的示例中，`Scenario duration`中显示的统计数据与`Request latency`几乎相同，因为每个场景只包含一个请求。如果您创建了更复杂的场景，每个场景包含多个请求，那么这两组数据将有所不同。

### 创建 Artillery 脚本

正如我们之前告诉过您的，Artillery 允许您创建 YAML 或 JSON 文件来进行负载测试场景。让我们将我们的快速示例转换为一个 YAML 文件，这样您就可以将其保存在存储库中以备将来执行。

要做到这一点，您只需要在我们的测试容器中创建一个名为`test-secret.yml`的文件，内容如下：

```php
**config:
 target: 'http://microservice_secret_nginx/'
 phases:
 - duration: 30
 arrivalRate: 5

scenarios:
 - flow:
 - get:
 url: "api/v1/secret/"**

```

正如您在上文中所看到的，它与我们的`artillery quick`命令类似，但现在您可以将它们存储在您的代码存储库中，以便反复针对您的应用程序运行。

您可以使用`artillery run test-secret.yml`命令运行您的测试，结果应该与快速命令生成的结果类似。

Docker 容器镜像只包含所需的最小软件，因此您可能无法在我们的负载测试镜像中找到文本编辑器。在本书的这一部分，您将能够创建一个 Docker 卷并将其附加到我们的测试容器，以便您可以共享文件。

### 高级脚本编写

这个工具包的一个突出特点是能够创建自定义脚本，但您不仅仅局限于发送静态请求。该工具允许您使用外部 CSV 文件、解析 JSON 响应或脚本中的内联值来随机化请求。

假设您想要测试负责在您的应用程序中创建新帐户的 API 端点，而不是使用 YAML 文件，您正在使用 JSON 脚本。您可以使用外部 CSV 文件与以下调整一起在测试中使���用户数据：

```php
    "config": {
      "payload": {
        "path": "./relative/path/to/test-data.csv",
        "fields": ["name", "surname", "email"]
      }
    }
    // ... omitted config ...//
    "scenarios": [
      {
        "flow": [
          {
            "post": {
              "url": "/api/v1/user",
              "json": {
                "name": {{ name }}, 
                "surname": {{ surname }},
                "email": {{ email }}
              }
            }
          }
        ]
      }
    ]
```

`config`字段将告诉 Artillery 我们的 CSV 文件的位置以及 CSV 中使用的不同列。设置好外部文件后，我们可以在场景中使用这些数据。在我们的示例中，Artillery 将从`test-data.csv`中随机选择行，并使用这些数据生成对`/api/v1/user`的 post 请求。`payload`中的字段将创建我们可以使用的变量，比如`{{ variableName }}`。

创建这种类型的脚本似乎很容易，但是在创建脚本的过程中，您可能需要一些调试信息来了解您的脚本在做什么。如果您想查看每个请求的详细信息，可以按照以下方式运行您的脚本：

```php
**DEBUG=http artillery run test-secret.yml**

```

如果您想要查看响应，可以按照以下方式运行负载测试脚本：

```php
**DEBUG=http:response artillery run myscript.yaml**

```

不幸的是，本书中没有足够的空间来详细介绍 Artillery 中的所有可用选项。但是，我们想向您展示一个有趣的工具，您可以使用它进行负载测试。如果您需要更多信息，甚至如果您想要为项目做出贡献，您只需要访问项目的页面（[`artillery.io`](https://artillery.io)）。

## 使用 siege 进行负载测试

Siege 是一个有趣的多线程 HTTP(s)负载测试和基准测试工具。与其他工具相比，它似乎小而简单，但它高效且易于使用，例如，对您最新更改进行快速测试。此工具允许您使用可配置数量的并发虚拟用户命中 HTTP(S)端点，并且可以在三种不同模式下使用：回归、互联网模拟和暴力。

Siege 是为 GNU/Linux 开发的，但已成功移植到 AIX、BSD、HP-UX 和 Solaris。如果您想要编译它，在大多数 System V UNIX 变体和大多数较新的 BSD 系统上都不应该有任何问题。

### 在 RHEL、CentOS 和类似的操作系统上安装 siege

如果您使用启用了额外存储库的 CentOS，您可以使用一个简单的命令安装 EPEL 存储库：

```php
**sudo yum install epel-release**

```

一旦您有了 EPEL 存储库，您只需要执行`sudo yum install siege`就可以在您的操作系统中使用此工具。

有时，例如当您不使用 Centos 时，`sudo yum install epel-release`命令不起作用，您的发行版是 RHEL 或类似的发行版。在这些情况下，您可以使用以下命令手动安装 EPEL 存储库：

```php
**wget https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm
sudo rpm -Uvh epel-release-latest-7*.rpm**

```

一旦 EPEL 存储库在您的操作系统中可用，您可以使用以下命令`安装 siege`：

```php
**sudo yum install siege**

```

### 在 Debian 或 Ubuntu 上安装 siege

在 Debian 或 Ubuntu 上安装 siege 非常简单，只需使用官方存储库。如果您有这些操作系统的最新版本之一，您只需要执行以下命令：

```php
**sudo apt-get update
sudo apt-get install siege**

```

上述命令将更新您的系统并安装`siege`软件包。

### 在其他操作系统上安装 siege

如果您的操作系统在之前的步骤中没有涵盖，您可以通过编译源代码来完成，互联网上有很多说明您需要做什么的教程。

### 快速 siege 示例

让我们快速创建一个文本到我们的一个端点。在这种情况下，我们将在 30 秒内使用 50 个并发用户测试我们的端点。打开您安装了 siege 的机器的终端，并输入以下命令。随意更改命令以正确的主机或端点：

```php
**siege -c50 -d10 -t30s http://localhost:8083/api/v1/secret/**

```

上述命令在以下几点中得到解释：

+   `-c50`：创建 50 个并发用户

+   `-d10`：每个模拟用户之间的延迟为 1 到 10 秒之间的随机秒数

+   `-t30s`：运行测试的时间；在我们的情况下为 30 秒

+   `http://localhost:8083/api/v1/secret/`：要测试的端点

一旦您按下*Enter*，`siege`命令将开始向服务器发送请求，并且您将获得类似以下的输出：

```php
**filloa:~ psolar$ siege -c50 -d10 -t30s  http://localhost:8083/api/v1/secret/**
**** SIEGE 3.1.3
** Preparing 50 concurrent users for battle.
The server is now under siege...
HTTP/1.1 200   0.50 secs:     577 bytes ==> GET  /api/v1/secret/
/** ... omitted lines ... **/
Lifting the server siege...      done.**

```

大约 30 秒后，siege 将停止请求并向您显示一些统计信息，例如以下内容：

```php
**Transactions:                149 hits
Availability:                100.00 %
Elapsed time:                29.91 secs
Data transferred:            0.08 MB
Response time:               3.33 secs
Transaction rate:            4.98 trans/sec
Throughput:                  0.00 MB/sec
Concurrency:                 16.57
Successful transactions:     149
Failed transactions:         0
Longest transaction:         5.89
Shortest transaction:        0.50**

```

从上述结果中，我们可以得出结论，我们所有的请求都没有问题，没有一个请求失败，平均响应时间为 3.33 秒。正如您所看到的，这个工具更简单，可以在日常基础上使用，以检查您的应用程序从哪个并发用户级别开始出现错误，或者在您检查其他指标时将应用程序置于压力之下。

# 可扩展性计划

**可扩展性计划**是一份描述应用程序的所有不同组件以及在需要时扩展应用程序所需步骤的文件。可扩展性计划是一份实时文件，因此您需要经常审查并保持更新。

由于可扩展性计划更多地是一个内部文件，其中包含您需要做出关于应用程序可扩展性的正确决策的所有信息，因此没有准备好填写的主模板。我们建议使用可扩展性计划作为您的指南，包括您的容量计划的所有内容，甚至可以将如何雇佣新员工添加到此文档中。

您的可扩展性计划中可能包括以下部分：

+   应用程序及其组件的概述

+   云提供商或您将部署应用程序的地点的比较

+   您的容量计划和应用程序的理论极限的总结

+   可扩展性阶段或步骤

+   配置时间和成本

+   组织可扩展性步骤

前面的部分只是一个建议，随时可以添加或删除任何部分以适应您的业务计划。

以下是容量计划的一些部分概述。假设我们的示例微服务应用程序已准备就绪，并且希望从最低资源开始扩展。首先，我们可以将我们应用程序中的不同元素描述为基本清单，从而使我们的应用程序得以发展：

+   战斗微服务

+   NGINX

+   PHP 7 fpm

+   位置微服务

+   NGINX

+   PHP 7 fpm

+   秘密微服务

+   NGNIX

+   PHP 7 fpm

+   用户微服务

+   NGINX

+   PHP 7 fpm

+   数据存储层

+   数据库：Percona

正如您所看到的，我们已经描述了我们应用程序所需的每个组件，并开始在所有微服务之间共享数据层。我们没有添加任何缓存层；此外，我们也没有添加任何自动发现和遥测服务（我们将在接下来的步骤中添加额外功能）。

一旦我们满足了最低要求，让我们来看看我们的可扩展性计划中可以有哪些不同步骤。

## 第 0 步

在这一步中，即使应用程序尚未准备好投入生产，我们将在一台机器上满足所有我们的要求，因为您的应用程序无法在机器出现问题时生存。以下特征的单个服务器将足够：

+   8 GB RAM

+   500 GB 磁盘

基本操作系统将是 RHEL 或 CentOS，并安装以下软件：

+   带有多个虚拟主机设置的 NGINX

+   Git

+   Percona

+   PHP 7 fpm

在这一步中，配置时间可能需要几个小时。我们不仅需要启动服务器，还需要设置所需服务（NGINX、Percona 等）。使用诸如 Ansible 之类的工具可以帮助我们快速和可重复地进行配置。

## 第 1 步

在这一点上，您正在为生产环境准备应用程序，选择虚拟机或容器（在我们的情况下，我们决定使用容器以获得灵活性和性能），将单个服务器配置拆分为专用于每个所需服务的多个服务器，如我们之前的要求，并添加自动发现和遥测服务。

在这一步，您可以找到我们应用程序架构的简要描述：

+   自动发现

+   带有 ContainerPilot 的 Hashicorp Consul 容器

+   遥测

+   带有 ContainerPilot 的 Prometheus 容器

+   战斗微服务

+   带有 ContainerPilot 的 NGINX 容器

+   带有 ContainerPilot 的 PHP 7 fpm 容器

+   位置微服务

+   带有 ContainerPilot 的 NGINX 容器

+   带有 ContainerPilot 的 PHP 7 fpm 容器

+   秘密微服务

+   带有 ContainerPilot 的 NGINX 容器

+   带有 ContainerPilot 的 PHP 7 fpm 容器

+   用户微服务

+   带有 ContainerPilot 的 NGINX 容器

+   带有 ContainerPilot 的 PHP 7 fpm 容器

+   数据存储层

+   带有 ContainerPilot 的 Percona 容器

在这一步中，配置时间将从前一步的几小时减少到几分钟。我们已经有了一个自动发现服务（HashiCorp Consul），并且由于 ContainerPilot，我们的每个不同组件将在自动发现注册中注册自己，并自动设置。几分钟内，我们可以完成所有容器的配置和设置。

## 第 2 步

在您的可扩展性规划的这一步中，您将为所有应用程序微服务添加缓存层，以减少请求数量并提高整体性能。为了提高性能，我们决定使用 Redis 作为我们的缓存引擎，因此您需要在每个微服务上创建一个 Redis 容器。这一步的配置时间将与上一步相似，但以分钟为单位。

## 第 3 步

在这一步中，您将把存储层移动到每个微服务中，使用 ContainerPilot 和 Consul 自动设置 Master-Slave 模式的三个 Percona 容器。

这一步的配置时间将与上一步相似，以分钟为单位。

## 第 4 步

在可扩展性计划的这一步中，您将研究应用程序的负载和使用模式。您将在 NGINX 容器前面添加负载均衡器，以获得更大的灵活性。由于这个新层，我们可以进行 A/B 测试或蓝/绿部署，以及其他功能。在这种情况下，您可以使用一些有趣的开源工具，如 Fabio 代理和 Traefik。

这一步的预配时间将与上一步相似，以分钟为单位。

## 第 5 步

在这最后一步中，您将再次检查应用程序基础设施，使其保持最新，并在必要时进行水平扩展。

这一步的预配时间将与上一步相似，以分钟为单位。

正如我们之前告诉过您的，可扩展性计划是一个动态文件，因此您需要经常进行修订。想象一下，几个月后会有一种新的数据库软件问世，它非常适合高负载；您可以审查您的可扩展性计划，并将这个新数据库引入您的基础设施。请随意添加您认为对应用程序的可扩展性重要的所有信息。

# 总结

在本章中，我们向您展示了如何检查应用程序的限制，这可以让您了解可能会遇到的瓶颈。我们还向您展示了创建容量和可扩展性计划所需的基本概念。我们还向您展示了一些对应用程序进行负载测试的选项。您应该有足够的知识，使您的应用程序能够应对高负载使用，或者至少了解您应用程序的薄弱点。


# 第十一章：最佳实践和约定

这一章将教你在其他开发人员中脱颖而出。这是通过以风格开发和执行本书中学到的策略，并遵循具体的标准来实现的。

# 代码版本控制最佳实践

随着时间的推移，你的应用程序将不断发展，最终你会想知道你将如何处理任何微服务的 API。你可以尽量减少更改并对你的 API 的用户透明，或者你可以创建不同版本的代码。最佳解决方案是对你的代码（API）进行版本控制。

代码版本控制的众所周知和常用的方式如下：

+   **URL**：在这种方法中，你在请求的 URL 中添加 API 的版本。例如，`https://phpmicroservices.com/api/v2/user`的 URL 表示我们正在使用我们 API 的`v2`。我们在本书中的示例中使用了这种方法。

+   **自定义请求头**：在这种方法中，我们不在 URL 中指定版本。相反，我们使用 HTTP 头来指定我们想要使用的版本。例如，我们可以对`https://phpmicroservices.com/api/user`进行 HTTP 调用，但附加一个额外的头部`"api-version: 2"`。在这种情况下，我们的服务器将检查 HTTP 头并使用我们 API 的`v2`。

+   **接受头**：这种方法与前一种方法非常相似，但是我们将使用`Accept`头而不是自定义头。例如，我们将对`https://phpmicroservices.com/api/user`进行调用，但我们的 Accept 头将是`"Accept: application/vnd.phpmicroservices.v2+json"`。在这种情况下，我们指示我们想要版本 2，并且数据将以 JSON 格式呈现。

正如你可以想象的那样，在你的代码中实现版本控制的最简单方法是在 URL 中使用版本代码，但不幸的是，这并不被认为是最佳选项。大多数开发人员认为最佳的代码版本控制方式是使用 HTTP 头来指定你想要使用的版本。我们建议使用最适合你的项目的方法。分析谁将使用你的 API 以及如何使用，你将发现你需要使用的版本控制方法。

# 缓存最佳实践

缓存是一个可以存储临时数据的地方；它用于提高应用程序的性能。在这里，你可以找到一些小贴士来帮助你处理缓存。

## 性能影响

向你的应用程序添加缓存层总是会产生性能影响，你需要进行测量。无论你在应用程序的哪个位置添加缓存层，你都需要测量影响，以了解新的缓存层是否是一个好选择。首先，在没有缓存层的情况下进行一些度量，一旦你有了一些统计数据，启用缓存层并进行比较。有时你会发现，缓存层的好处变成了一个管理上的困扰。你可以使用我们在前几章中谈到的一些监控服务来监控性能影响。

## 处理缓存未命中

缓存未命中是指请求未保存在缓存中，应用程序需要从服务/应用程序中获取数据。确保你的代码可以处理缓存未命中和随之而来的更新。为了跟踪缺失缓存命中率，你可以使用任何监控软件或甚至日志系统。

## 分组请求

尽可能地尝试将你的缓存请求分组。想象一下，你的前端需要从缓存服务器中获取五个不同的元素来渲染一个页面。你可以尝试将请求分组，而不是进行五次调用，从而节省时间。

想象一下，你正在使用 Redis 作为缓存层，并希望将一些值保存在`foo`和`bar`变量中。看一下以下代码：

```php
    $redis->set('foo', 'my_value');
    /** Some code **/
    $redis->set('bar', 'another_value');
```

而不是这样做，你可以在一个事务中完成两个集合：

```php
    $redis->mSet(['foo' => 'my_value', 'bar' => 'another_value']);
```

上述示例将在一个提交中完成两个集合，节省时间并提高应用程序的性能。

## 缓存中存储的元素大小

将大型项目存储在缓存中比存储小型项目更有效。如果你开始缓存大量小项目，整体性能将会降低。在这种情况下，序列化大小、时间、缓存提交时间和容量使用将会增加。

## 监控你的缓存

如果你决定添加一个缓存层，至少要监控它。保持一些关于你的缓存的统计数据将有助于你了解它的表现如何（缓存命中率），或者它是否达到了容量限制。大多数缓存软件都是稳定而强大的，但这并不意味着如果你不加管理就不会遇到任何问题。

## 仔细选择你的缓存算法

大多数缓存引擎支持不同的算法。每种算法都有其优点和问题。我们建议你深入分析你的需求，并在确定它是你用例的正确算法之前，不要使用你选择的缓存引擎的默认模式。

# 性能最佳实践

如果你正在阅读这本书，很可能是因为你对 Web 开发感兴趣，而在过去几年中，Web 应用程序（如 API）的性能变得越来越重要。以下是一些统计数据，以便让你有一个概念：

+   亚马逊多年前报告称，每增加 100 毫秒的加载时间，他们的销售额就会减少 1%。

+   谷歌发现，将页面大小从 100 KB 减少到 80 KB 会使他们的流量减少 25%。

+   57%的在线消费者在等待页面加载 3 秒后会放弃一个网站。

+   80%的放弃网站的人不会回来。大约 50%的这些人会告诉其他人他们的负面经历。

正如你所看到的，你的应用程序的性能可能会影响你的用户甚至你的收入。在本节中，我们将为你提供一些改善 Web 应用程序整体性能的建议。

## 最小化 HTTP 请求

每个 HTTP 请求都有一个有效负载。因此，提高性能的一种简单方法是减少 HTTP 请求的数量。你需要在开发的每个方面都牢记这个想法。尽量减少 APIs/后端中对其他服务的最小外部调用。在前端，你可以合并文件以满足只有一个请求。你只需要在请求的数量和每个请求的大小之间取得平衡。

想象一下，你的前端的 CSS 被分成了几个不同的文件；而不是每次加载一个文件，你可以将它们合并成一个或几个文件。

你可以通过 HTTP 请求进行另一个快速而小的更改，那就是尽量避免在你的 CSS 文件中使用`@import`函数。使用链接标签而不是`@import`函数将允许你的浏览器并行下载 CSS 文件。

## 最小化 HTML、CSS 和 JavaScript

作为开发人员，我们试图以对我们来说更容易阅读的格式编写代码--一种人类友好的格式。通过这种方式开发，我们增加了我们的纯文本文件的大小，其中包括不必要的字符。不必要的字符可能包括空格、注释和换行符。

我们并不是说你需要编写混淆的代码，但是一旦你准备好了一切，为什么不删除不必要的字符呢？

想象一下，你的一个 JavaScript 文件（`myapp.js`）的内容如下：

```php
    /**
    * This is my JS APP
    */
    var myApp = {
      // My app variable
      myVariable : 'value1',

      // Main action of my JS app
      doSomething : function () {
        alert('Doing stuff');
      }
    };
```

在最小化之后，你的代码可以保存到一个不同的文件（`myapp.min.js`），它可能如下所示：

```php
    var myApp={myVariable:"value1",doSomething:function()
      {alert("Doing stuff")}};
```

在新的代码中，我们将文件大小减少了大约 60%，节省了大量空间。请注意，我们的存储库将同时拥有文件的两个版本：人类可读的版本用于进行更改，以及我们将在前端加载的最小化版本。

您可以使用在线工具进行最小化，或者您可以将`gulp`或`grunt`等工具集成到您的流程中。设置这些工具后，它们将跟踪某些特定文件（CSS、JS 和其他文件）的更改，一旦您对这些文件中的任何一个进行保存，工具将最小化内容。使用最小化工具的另一个隐藏的好处是，大多数工具还会检查代码或重命名变量以使其更小。

## 图像优化

在 Web 开发中最常用的资源之一可能就是图像。它们让您的网站看起来很棒，但也可能使您的网站变得非常缓慢。主要建议是将图像数量保持最少，但如果您需要保留图像，至少在将它们发送给用户之前尝试优化它们。在本节中，我们将向您展示一些可以优化图像的方法，从而提高应用程序的性能。

### 使用精灵图

精灵图是由多个图像组成的图像；稍后，您可以使用此图像并仅显示您感兴趣的部分。想象一下，您有一个漂亮的网站，在每个页面上都有一些社交图标（Facebook、Twitter、Instagram 等）。您可以将它们合并在一起，并使用 CSS 仅显示您想要的每个图标的部分，而不是为每个社交图标都有一个图像。这样做，您将只需加载一次所有社交图标，从而减少请求次数。

我们建议保持您的精灵图小，并只包含其中最常用和共享的图像。

### 使用无损图像压缩

并非所有图像格式都适合 Web，因为某些格式要么太大，要么不支持压缩。当今 Web 上使用最多的三种图像类型如下：

+   **JPG**：这是最常用的无损压缩方法之一

+   **PNG**：这是具有无损数据压缩的最佳格式

+   **GIF**：这是一种老式格式，每个图像支持最多 8 位像素，并以其动画效果而闻名

目前 Web 的推荐格式是**PNG**。它得到了浏览器的良好支持，易于创建，支持压缩，并且为您提供了改善网站性能所需的所有功能。

### 缩放图像

如果您使用图像而不是数据 URI，则应以其原始尺寸发送图像。您应该避免使用 CSS 调整图像大小，并将具有正确尺寸的图像发送到浏览器。唯一建议使用 CSS 缩放图像的情况是在流体图像（响应式设计）中。

您可以使用像 Imagick 或 GD 这样的 PHP 库轻松缩放图像。使用这些库和几行代码，您可以在几秒钟内缩放图像。通常情况下，您不会即时缩放图像。大多数情况下，一旦图像上传到您的应用程序，批处理过程会处理图像，创建应用程序所需的不同尺寸。

想象一下，您可以将任何尺寸的图像上传到您的应用程序，但在前端只显示最大宽度为`350`px 的图像。您可以使用 Imagick 轻松缩放以前存储的图像：

```php
    $imagePath = '/tmp/my_uploaded_image.png';
    $myImage   = new Imagick($imagePath);

    $myImage->resizeImage(350, 0, Imagick::FILTER_LANCZOS, 1);

    $myImage->writeImage('/tmp/my_uploaded_image_350.png');

```

上述代码将加载`my_uploaded_image.png`文件，并使用 Lanczos 滤镜将图像调整为宽度为`350`px（请参阅 PHP Imagick 文档，了解您可以使用的所有可用滤镜）。

这是一种方法，另一种（也许更有效的）常见方法是按需调整图像大小（即在客户端首次请求时），然后将调整大小的图像存储在缓存或永久存储中。

### 使用数据 URI

另一种快速减少 HTTP 请求次数的方法是将图像嵌入数据 URI 中。这样，您将在代码中将图像作为字符串，避免了对图像的请求，这种方法最适合静态页面。生成这种 URI 的最佳方式是使用外部或在线工具。

以下示例将向您展示它在您的 HTML 中的外观：

```php
    <img src="data:image/jpeg;base64,/9j/4AAQSkZJRgABAQEAYABgA..."
     alt="My Image">
```

### 缓存，缓存，还有更多的缓存

Web 性能完全取决于尽快提供数据，如果我们的应用程序已经发送的数据仍然有效，为什么要再次发送呢？默认情况下，现代浏览器会尝试减少它们对同一站点发出的请求数量，因此它们会在内部缓存中保留一些资产/资源的副本以供将来使用。由于这种行为，如果您正在浏览网站，我们不会在您在各个部分之间移动时一次又一次地尝试加载所有资产。

您可以通过指定每个请求响应来帮助浏览器，使用以下`Cache-Control` HTTP 标头：

+   **max-age=[秒]**：这设置了响应被视为新鲜的最长时间。此指令是相对于请求的时间。

+   s-maxage=[秒]：这类似于 max-age，但适用于共享缓存。

+   **public**：此标记将响应标记为可缓存。

+   **private**：此标记允许您将响应存储到一个用户。不允许共享缓存存储响应。

+   **no-cache**：此标记指示缓存将请求提交给原始服务器进行验证。

+   **no-store**：此标记指示缓存不保留响应的副本。

+   **must-revalidate**：此标记告诉缓存它们必须遵循您提供的有关响应的任何新信息。

+   **proxy-revalidate**：这类似于 must-revalidate，但适用于代理缓存。

主要建议是将静态资产标记为至少一周或长寿命资产的一天到期。对于频繁更改的资产，建议将到期日期设置为两天或更短。根据其生命周期调整资产的缓存到期日期。

想象一下，您有一张图片，每 6 小时更改一次；在这种情况下，您不应该将到期日期设置为一周，最好的选择将是大约 6 小时。

### 避免不良请求

没有比坏请求更令人讨厌的了，因为这种请求会严重降低应用程序的性能。您可能知道，浏览器对于同一主机可以同时管理的并发连接数量是有限的。如果您的网站发出了大量请求，这些可用连接插槽的列表可能已满，剩下的请求将被排队。

想象一下，您的浏览器最多可以管理 10 个并发连接，而您的 Web 应用程序却发出了 20 个请求。并非所有请求都可以同时处理，其中一些请求被排队。现在，如果您的应用程序正在尝试获取一个不存在的资产会发生什么？在这种情况下，浏览器将浪费时间（和插槽）等待不存在的资产被提供，但这永远不会发生。

作为建议，密切关注您的浏览器开发人员工具（一组内置于浏览器中的 Web 调试工具，可用于调试和分析您的站点）。这些工具可以帮助您发现问题请求，甚至可以检查每个请求使用的时间。在大多数浏览器中，您可以按下*F12*键打开嵌入式开发人员工具，但是，如果您的浏览器按下此键不打开工具，请查看浏览器的文档。

### 使用内容交付网络（CDN）

内容交付网络在旨在快速响应并从最近的服务器响应的服务器上托管您的资产的副本。这样，如果您将请求从您的服务器转移到 CDN 服务器，您的 Web 服务器将处理更少的请求，从而提高应用程序的性能。

想象一下，如果您在前端使用 jQuery；如果您将代码更改为从官方 CDN 加载库，则用户在其浏览器缓存中拥有该库的概率会增加。

我们的主要建议是至少为您的 CSS、JavaScript 和图像使用 CDN。

# 依赖管理

您有多个 PHP 库、框架、组件和工具可供在项目中使用。直到几年前，PHP 没有一种现代的管理项目依赖关系的方式。此刻我们有 Composer，一个灵活的项目，已经成为依赖管理的事实标准。

您可能对 Composer 很熟悉，因为我们在整本书中都在使用这个工具来在`vendor`文件夹中安装新库。此时，您可能会想知道是否应该提交`vendor`文件夹的依赖关系。没有快速的答复，但一般的建议是不要，您不应该将`vendor`文件夹提交到您的存储库中。

提交供应商文件夹的主要缺点可以总结如下：

+   增加您的存储库的大小

+   复制了您的依赖关系的历史记录

正如我们之前告诉过你的，不提交供应商是主要的建议，但如果你真的需要这样做，这里有一些建议：

+   使用标记的发布（不是开发版本），以便 Composer 获取压缩的源代码

+   在您的配置文件中使用`--prefer-dist`标志或将`preferred-install`设置为`dist`

+   将`/vendor/**/.git`规则添加到您的`.gitignore`文件中

# 语义版本

在您开始的任何项目中，您应该在主分支上使用语义版本。语义版本是一组规则，您可以遵循这些规则来标记您应用程序的代码在您的版本控制软件中。通过遵循这些规则，您将了解您的生产环境的当前状态。在您的代码中使用标签的另一个好处是，它允许我们在不同版本之间移动或以一种简单快捷的方式进行回滚。

拥有带有发布标签的源代码的另一个优势是，它允许您使用发布分支，从而使您能够更好地规划和控制对代码所做的更改。

## 语义版本如何工作

在语义版本中，您的代码标记为**`vX.Y.Z`**形式的标签，这意味着您代码的版本。您的每个标签部分都有特定的含义：

+   **X（主要）**：此版本号的增加表示正在进行重大改变；它们足够重要，与当前版本不兼容

+   **Y（次要）**：此版本号的增加表示我们正在向项目添加新功能

+   **Z（补丁）**：此版本号的增加表示我们向源代码添加了一个补丁

发布标签的更新通常由将代码推送到生产环境的开发人员进行。请记住在部署代码之前更新发布标签。

## 语义版本在行动

想象一下，您开始在别人的项目中，主分支被标记为`v1.2.3`。让我们看一些例子。

### 我们被告知要向项目添加一个新功能

在进行实时项目时，会收到新功能的请求。在这种情况下，我们明显正在增加次要版本号，因为我们正在添加新代码，这与实际基础代码不兼容。在我们的情况下，如果我们的主分支是`v1.2.3`，新版本标签将是`v1.3.0`。我们增加了次要版本号，同时重置了补丁号，因为我们正在添加新代码。

### 我们被告知我们的项目中有一个错误

在日常工作中，您将修复代码中的错误。在这种情况下，我们正在处理的是一个小改变，主要功能是解决我们的问题，因此我们需要增加补丁版本。在我们的例子中，如果当前生产版本是`v1.2.3`，新版本标签将是`v1.2.4`。我们只增加了补丁号，因为我们的修复不涉及其他更大的改变。

### 我们被要求进行重大改变

现在想象一下，我们被要求对我们的源代码进行重大更改；一旦应用了我们的更改，我们的源代码的某些部分将与以前的版本不兼容。例如，想象一下，您正在使用`library_a`，我们改用`library_b`，它们是互斥的。在这种情况下，我们正在处理一个非常重大的变化，这表明我们需要增加我们的主要版本号，同时还需要重置次要和补丁号。例如，如果我们的生产代码标记为`v1.2.3`，则应用更改后的新版本代码将为`v2.0.0`。

正如您所看到的，进行语义版本控制将帮助您保持源代码的清洁，并使得通过查看版本号就能知道正在进行哪种类型的代码更改。

# 错误处理

当我们因为应用程序执行期间发生了某些事情而抛出异常时，我们应该向我们的用户或消费者提供更多关于发生了什么的信息。通过添加可描述的标准代码，也称为状态代码，可以实现这一点。在响应中使用这些标准代码将帮助您（和您的同事）快速了解应用程序中是否出现了问题。查看以下列表，了解在 API 中使用的正确和最常见的 HTTP 状态代码。

## 客户端请求成功

如果您的应用程序需要通知 API 客户端请求成功，通常会回复以下 HTTP 状态代码之一：

+   **200 - 正常**：请求成功完成

+   **201 - 已创建**：成功创建了客户端指定的 URI

+   **202 - 已接受**：已接受处理，但服务器尚未完成处理

+   **204 - 无内容**：请求已完成，响应中没有发送任何信息

## 请求重定向

当您的应用程序需要回复请求被重定向时，您将使用以下 HTTP 状态代码之一：

+   **301 - 永久移动**：所请求的资源在服务器上不存在。服务器发送一个位置标头给客户端，将其重定向到新的 URL。客户端在将来的请求中继续使用新的 URL。

+   **302 - 暂时移动**：所请求的资源已暂时移动。服务器发送一个位置标头给客户端，将其重定向到新的 URL。客户端在将来的请求中继续使用旧的 URL。

+   **304 - 未修改**：用于响应`If-Modified-Since`请求标头。它表示自指定日期以来所请求的文档未被修改，客户端应使用缓存副本。

## 客户端请求不完整

如果您需要向 API 客户端发送的信息是关于不完整或错误的请求，您将返回以下 HTTP 代码之一：

+   **400 - 错误的请求**：服务器在客户端的请求中检测到语法错误。

+   **401 - 未经授权**：请求需要用户身份验证。服务器发送 WWW-Authenticate 标头以指示所请求资源的身份验证类型和领域。

+   **402 - 需要付款**：这是为将来保留的。

+   **403 - 禁止**：禁止访问所请求的资源。客户端不应重复请求。

+   **404 - 未找到**：所请求的文档在服务器上不存在。

+   **405 - 方法不允许**：客户端使用的请求方法是不可接受的。服务器发送“允许”标头，说明可以接受哪些方法来访问所请求的资源。

+   **408 - 请求超时**：客户端未能在服务器使用的请求超时期内完成其请求。但是，客户端可以重新请求。

+   **410 - 已消失**：所请求的资源已永久从服务器中消失。

+   413 - 请求实体太大：服务器拒绝处理请求，因为其消息主体太大。服务器可以关闭连接以阻止客户端继续请求。

+   **414 - 请求 URI 太长**：服务器拒绝处理请求，因为指定的 URI 太长。

+   **415 - 不支持的媒体类型**：服务器拒绝处理请求，因为它不支持消息正文的格式。

## 服务器错误

在应用程序不幸需要通知 API 客户端存在问题时，您将返回以下 HTTP 代码之一：

+   **500 - 内部服务器错误**：服务器配置设置或外部程序导致错误。

+   **501 - 未实现**：服务器不支持满足请求所需的功能。

+   **502 - 错误的网关**：服务器遇到上游服务器或代理的无效响应。

+   **503 - 服务不可用**：服务暂时不可用。服务器可以发送`Retry-After`头来指示服务何时可能再次可用。

+   **504 - 网关超时**：网关或代理已超时。

# 编码实践

您的代码是应用程序的核心；因此，您希望以正确、清晰和高效的方式编写它。在本节中，我们将为您提供一些改进代码的提示。

## 处理字符串

行业标准之一是在应用程序的所有级别中使用 UTF-8 格式。如果您忽略了这个建议，您将在整个项目的生命周期中处理编码问题。在撰写本书时，PHP 不支持低级别的 Unicode，因此在处理字符串时需要小心，特别是在处理 UTF-8 时。以下建议仅适用于使用 UTF-8 的情况。

在 PHP 中，基本的字符串操作，如赋值或连接，在 UTF-8 中不需要任何特殊处理；在其他情况下，您可以使用核心函数来处理字符串。大多数情况下，这些函数都有一个对应的函数（以`mb_*`为前缀）来处理 Unicode。例如，在 PHP 核心中，您可以找到`substr()`和`mb_substr()`函数。每当您操作 Unicode 字符串时，都必须使用多字节函数。想象一下，如果您需要获取 UTF-8 字符串的一部分；如果您使用`substr()`而不是`mb_substr()`，有很大的机会得到您不期望的结果。

## 单引号与双引号

单引号字符串不会被 PHP 解析，因此您的字符串中有什么并不重要，PHP 将原样返回字符串。在双引号字符串的情况下，它们会被 PHP 引擎解析，并且字符串中的任何变量都将被评估。对于双引号字符串，转义字符（例如 t 或 n）也将被评估。

在现实应用中，使用其中一种方法的性能差异可能会被忽略，但在高负载应用中，性能可能会有所不同。我们建议保持一致，如果需要变量和转义字符被评估，请只使用双引号。在其他情况下，请使用单引号。

## 空格与制表符

开发人员之间存在着使用空格和使用制表符来缩进他们的代码的战争。每种方法都有其自身的好处和不便，但 PHP FIG 建议使用四个空格。只使用空格可以避免与差异、补丁、历史和注释相关的问题。

## 正则表达式

在 PHP 中，您有两种选项来编写您的正则表达式：PCRE 和 POSIX 函数。主要建议使用 PCRE 函数（以`preg_*`为前缀），因为在 PHP 5.3 中，POSIX 函数族已被弃用。

## 连接和对数据库的查询

在 PHP 中，您有多种连接到数据库的方式，但在所有这些方式中，连接的推荐方式是使用 PDO。使用 PDO 的好处之一是它具有标准接口，可以连接到多个不同的数据库，使您能够在不太麻烦的情况下更改数据存储。当您对数据库进行查询时，如果不想出现任何问题，请确保始终使用预处理语句。这样，您将避免大部分 SQL 注入攻击。

## 使用===运算符

PHP 是一种松散类型的编程语言，当您比较变量时，这种灵活性会带来一些注意事项。如果使用`===`运算符，PHP 会确保您进行严格比较，避免错误的结果。请注意，`===`比`is_null()`和`is_bool()`函数略快。

# 使用发布分支的工作

一旦我们的项目遵循语义版本控制，我们就可以开始在版本控制系统（例如 Git）中使用发布和发布分支。使用发布和发布分支可以让我们更好地计划和组织我们对代码的更改。

与发布版的工作基于语义版本控制，因为每个发布分支通常是从最新的主分支版本创建的（例如 v1.2.3）。

使用发布分支的主要好处如下：

+   帮助您遵循严格的方法将代码推送到生产环境

+   帮助您轻松计划和控制对代码的更改

+   尝试避免将不需要的代码拖入生产环境的常见问题

+   允许您阻止特殊分支（例如 dev 或 stage）以避免未经 pull 请求的提交

请注意，这只是一个建议；每个项目都是不同的，这种工作流程可能不适合您的项目。

## 快速示例

要在项目中使用发布版，您需要使用一个发布分支和另一个临时分支来对代码进行更改。对于以下示例，请想象我们的项目将主分支标记为 v1.2.3。

第一步是检查我们是否已经有一个发布分支，我们将在其上进行工作。如果不是这种情况，您需要从主分支创建一个新的发布分支：

+   首先，我们需要决定我们的下一个版本号；我们将使用从语义版本控制中学到的所有内容。

+   一旦我们知道我们的下一个版本号，我们将从主分支创建一个发布分支。下一个命令将向您展示如何获取最新的主分支并创建并推送一个新的发布分支：

```php
 **git checkout master
      git fetch
      git pull origin master
      git checkout -b release/v1.3.0
      git push origin release/v1.3.0**

```

+   在上述步骤之后，我们的存储库将拥有一个干净的发布分支，准备好使用。

此时，我们的发布分支已准备就绪。这意味着任何代码修改都将在从我们的发布分支创建的临时分支中进行：

+   假设我们需要向项目添加一个新功能，因此我们需要从发布分支创建一个临时分支：

```php
 **git checkout release/v1.3.0
      git fetch
      git pull origin release/v1.3.0
      git checkout -b feature/my_new_feature**

```

+   一旦我们有了`feature/my_new_feature`，我们可以将所有更改提交到这个新分支。一旦所有更改都已提交并准备就绪，我们可以将`feature/my_new_feature`与发布分支合并。

上述步骤可以重复任意次数，直到您为发布计划的所有任务完成为止。

一旦完成了所有发布任务并且所有更改都已经获得批准，您可以将发布分支与主分支合并。一旦完成与主分支的合并，请记得更新发布标签。

我们可以用以下提醒笔记总结我们的示例：

+   新的发布分支始终是从主分支创建的

+   临时分支始终是从发布分支创建的

+   尽量避免将其他临时分支与当前临时分支合并

+   尽量避免将非计划分支与发布分支合并

在上述工作流程中，我们建议使用以下分支前缀来了解与分支关联的更改类型：

+   `release/*`: 这个前缀表示所有包含的更改将在将来的发布中部署，版本号相同

+   `feature/*`: 这个前缀表示添加到分支的任何更改都是新功能

+   `hotfix/*`: 这个前缀表示包含的更改是为了修复错误/问题而提交的

通过这种方式工作，将更难将不需要的代码推送到生产环境。请随意根据您的需求调整前述工作流程。

# 总结

在本章中，我们为您介绍了一些关于您项目中可以使用的常见最佳实践和约定的要点。它们都是建议，但它们使得项目与其他项目脱颖而出。
