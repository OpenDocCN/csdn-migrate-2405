# PHP YII Web 应用开发（三）

> 原文：[`zh.annas-archive.org/md5/6008a5c78f9d1deb914065f1c36d5b5a`](https://zh.annas-archive.org/md5/6008a5c78f9d1deb914065f1c36d5b5a)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：添加 RSS 网络订阅

在上一章中，我们添加了用户在问题上留下评论的功能，并显示这些评论的列表，利用小部件架构使我们能够在整个应用程序中轻松和一致地显示该列表。在本章中，我们将建立在此功能的基础上，并将这些评论列表公开为 RSS 数据订阅。此外，我们将使用另一个开源框架 Zend 框架中现有的订阅功能，以演示 Yii 应用程序如何轻松地与其他框架和库集成。

# 功能规划

本章的目标是使用从用户生成的评论创建 RSS 订阅。我们应该允许用户订阅跨所有项目的评论订阅，以及订阅单个项目的订阅。幸运的是，我们之前构建的小部件功能已经具有返回所有项目的最新评论列表以及限制数据到一个特定项目的能力。因此，我们已经编写了访问必要数据的适当方法。本章的大部分内容将集中在将这些数据放入正确的格式以发布为 RSS 订阅，并在我们的应用程序中添加链接以允许用户订阅这些订阅。

以下是我们将完成的一系列高级任务列表，以实现这些目标：

+   下载并安装 Zend 框架到 Yii 应用程序中

+   在控制器类中创建一个新的操作，以响应订阅请求并以 RSS 格式返回适当的数据

+   更改我们的 URL 结构以便使用

+   将我们新创建的订阅添加到项目列表页面以及每个单独项目的详细页面

# 一点背景-内容联合，RSS 和 Zend 框架

网络内容联合已经存在多年，但在过去几年才获得了巨大的流行。网络内容联合是指以标准化格式发布信息，以便其他网站可以轻松使用，并且可以轻松被阅读应用程序消费。许多新闻网站长期以来一直在电子联合他们的内容，但互联网上博客的大规模爆炸已经将内容联合（称为订阅）变成了几乎每个网站都期望的功能。我们的 TrackStar 应用程序也不例外。

**真正简单的联合**（**RSS**）是一种 XML 格式规范，为网络内容联合提供了一个标准。还有其他可以使用的格式，但由于 RSS 在大多数网站中的压倒性流行，我们将专注于以这种格式提供我们的订阅。

Zend 被称为“PHP 公司”。他们提供的产品之一是 Zend 框架，用于帮助应用程序开发。该框架提供了可以并入其他框架应用程序的组件。Yii 足够灵活，可以让我们使用其他框架的部分。我们将只使用 Zend 框架库的一个组件，称为`Zend_Feed`，这样我们就不必编写所有底层的“管道”代码来生成我们的 RSS 格式的网络订阅。有关 Zend_Feed 的更多信息，请访问[`www.zendframework.com/manual/en/zend.feed.html`](http://www.zendframework.com/manual/en/zend.feed.html)。

# 安装 Zend 框架

由于我们使用 Zend 框架来帮助支持我们的 RSS 需求，因此我们首先需要下载并安装该框架。要下载框架文件，请访问[`www.zend.com/community/downloads`](http://www.zend.com/community/downloads)。由于我们只会使用该框架的一个组件，因此最小版本的框架就足够了。我们使用的是 1.1.12 版本。

当您扩展下载的框架文件时，您应该看到以下高级目录和文件结构：

+   `INSTALL.txt`

+   `LICENSE.txt`

+   `README.txt`

+   `bin/`

+   `library/`

为了在我们的 Yii 应用程序中使用这个框架，我们需要移动应用程序目录结构中的一些文件。让我们在应用程序的`/protected`目录下创建一个名为`vendors/`的新目录。然后，将 Zend Framework 目录`/library/Zend`移动到这个新创建的目录下。一切就位后，确保`protected/vendors/Zend/Feed.php`存在于 TrackStar 应用程序中。

# 使用 Zend_Feed

**Zend_Feed**是 Zend Framework 的一个小组件，它封装了创建 Web 源的所有复杂性，提供了一个简单易用的接口。它将帮助我们在很短的时间内建立一个工作的、经过测试的、符合 RSS 标准的数据源。我们所需要做的就是按照 Zend_Feed 期望的格式对我们的评论数据进行格式化，它会完成其余的工作。

我们需要一个地方来存放处理我们的数据源请求的代码。我们可以为此创建一个新的控制器，但为了保持简单，我们将只是在我们的主`CommentController.php`文件中添加一个新的操作方法来处理请求。我们将整个方法列在这里，然后逐步讨论它的功能。

```php
Open up CommentController.php and add the following public method:
/**
   * Uses Zend Feed to return an RSS formatted comments data feed
   */
  public function actionFeed()
  {
    if(isset($_GET['pid'])) 
    {
      $comments = Comment::model()->with(array(
                'issue'=>array(
                  'condition'=>'project_id=:projectId', 
                  'params'=>array(':projectId'=>intval($_GET['pid'])),
                )))->recent(20)->findAll();      
    }
    else   
      $comments = Comment::model()->recent(20)->findAll();  

    //convert from an array of comment AR class instances to an name=>value array for Zend
    $entries=array(); 

    foreach($comments as $comment)
    {

        $entries[]=array(
                'title'=>$comment->issue->name,     
                'link'=>CHtml::encode($this->createAbsoluteUrl('issue/view',array('id'=>$comment->issue->id))),  
                'description'=> $comment->author->username . ' says:<br>' . $comment->content,
                'lastUpdate'=>strtotime($comment->create_time),   
                'author'=>CHtml::encode($comment->author->username),
         );
    }  

    //now use the Zend Feed class to generate the Feed
    // generate and render RSS feed
    $feed=Zend_Feed::importArray(array(
         'title'   => 'Trackstar Project Comments Feed',
         'link'    => $this->createAbsoluteUrl(''),
         'charset' => 'UTF-8',
         'entries' => $entries,      
     ), 'rss');

    $feed->send();

  }
```

这一切都相当简单。首先，我们检查输入请求查询字符串是否存在`pid`参数，这表明特定项目 ID。请记住，我们希望可选地允许数据源将内容限制为与单个项目相关的评论。接下来，我们使用与上一章中用于填充小部件的相同方法来检索最多 20 条最近的评论列表，可以是跨所有项目，或者如果指定了项目 ID，则特定于该项目。

您可能还记得，这个方法返回一个`Comment` AR 类实例的数组。我们遍历这个返回的数组，并将数据转换为`Zend_Feed`组件接受的格式。`Zend_Feed`接受一个简单的数组，其中包含元素本身是包含每个评论条目数据的数组。每个单独的条目都是一个简单的`name=>value`对的关联数组。为了符合特定的 RSS 格式，我们的每个单独的条目必须至少包含一个标题、一个链接和一个描述。我们还添加了两个可选字段，一个称为`lastUpdate`，`Zend_Feed`将其转换为 RSS 字段`pubDate`，另一个用于指定作者。

我们利用了一些额外的辅助方法，以便以正确的格式获取数据。首先，我们使用控制器的`createAbsoluteUrl()`方法，而不仅仅是`createUrl()`方法，以生成一个完全合格的 URL。使用`createAbsoluteUrl()`将生成类似于以下的链接：

`http://localhost/trackstar/index.php?r=issue/view&id=5`而不仅仅是`/index.php?r=issue/view&id=5`

此外，为了避免由 PHP 的`DOMDocument::createElement()`方法生成的`unterminated entity reference`等错误，该方法被`Zend_Feed`用于生成 RSS XML，我们需要使用我们方便的辅助函数`CHtml::encode`将所有适用的字符转换为 HTML 实体。因此，我们对链接进行编码，以便像`http://localhost/trackstar/index.php?r=issue/view&id=5`这样的 URL 将被转换为`http://localhost/trackstar/index.php?r=issue/view&amp;id=5`。

我们还需要对将以 RSS 格式呈现的其他数据执行此操作。描述和标题字段都生成为`CDATA`块，因此在这些字段上不需要使用编码。

一旦所有条目都被正确填充和格式化，我们就使用 Zend_Feed 的`importArray()`方法，该方法接受一个数组来构造 RSS 源。最后，一旦从输入条目数组构建了源类并返回，我们就调用该类的`send()`方法。这将返回适当格式的 RSS XML 和适当的标头给客户端。

我们需要在`CommentController.php`文件和类中进行一些配置更改，然后才能使其正常工作。我们需要在评论控制器中包含一些 Zend 框架文件。在`CommentController.php`的顶部添加以下语句：

```php
Yii::import('application.vendors.*');
require_once('Zend/Feed.php');
require_once('Zend/Feed/Rss.php');
```

最后，修改`CommentController::accessRules()`方法，允许任何用户访问我们新添加的`actionFeed()`方法：

```php
public function accessRules()
  {
    return array(
      array('allow',  // allow all users to perform 'index' and 'view' actions
 **'actions'=>array('index','view','feed'),**
        'users'=>array('*'),
      ),
```

事实上就是这样。如果我们现在导航到`http://localhost/trackstar/index.php?r=comment/feed`，我们就可以查看我们的努力成果。由于浏览器对 RSS feed 的显示方式不同，您的体验可能与下面的截图有所不同。如果在 Firefox 浏览器中查看，您应该看到以下截图：

![使用 Zend_Feed](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/webapp-dev-yii-php/img/8727_09_01.jpg)

然而，在 Chrome 浏览器中查看时，我们看到原始的 XML 被显示出来，如下面的截图所示：

![使用 Zend_Feed](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/webapp-dev-yii-php/img/8727_09_02.jpg)

这可能取决于您的版本。您可能还会被提示选择要安装的可用 RSS 阅读器扩展，例如 Google Reader 或 Chrome 的 RSS Feed Reader 扩展。

# 创建用户友好的 URL

到目前为止，在我们的开发过程中，我们一直在使用 Yii 应用程序 URL 结构的默认格式。这种格式在第二章中讨论过，*入门*，在*回顾我们的请求路由*一节中使用了查询字符串的方法。我们有主要参数“r”，代表*路由*，后面跟着 controllerID/actionID 对，然后是特定 action 方法需要的可选查询字符串参数。我们为我们的新 feed 创建的 URL 也不例外。它是一个又长又笨重，可以说是丑陋的 URL。肯定有更好的方法！事实上确实如此。

我们可以通过使用所谓的*路径*格式使先前提到的 URL 看起来更清晰、更易理解，这种格式消除了查询字符串，并将`GET`参数放入 URL 的路径信息部分：

以我们的评论 feed URL 为例，我们将不再使用`http://localhost/trackstar/index.php?r=comment/feed`，而是使用`http://localhost/trackstar/index.php/comment/feed/`。

而且，我们不需要为每个请求指定入口脚本。我们还可以利用 Yii 的请求路由配置选项来消除指定 controllerID/actionID 对的需要。我们的请求可能看起来像这样：

`http://localhost/trackstar/commentfeed`

另外，通常情况下，特别是在 feed 的 URL 中，最后会指定`.xml`扩展名。因此，如果我们能够修改我们的 URL，使其看起来像下面这样，那就太好了：

`http://localhost/trackstar/commentfeed.xml`

这大大简化了用户的 URL，并且也是 URL 被主要搜索引擎正确索引的绝佳格式（通常称为“搜索引擎友好的 URL”）。让我们看看如何使用 Yii 的 URL 管理功能来修改我们的 URL 以匹配这种期望的格式。

## 使用 URL 管理器

Yii 中内置的 URL 管理器是一个应用程序组件，可以在`protected/config/main.php`文件中进行配置。让我们打开该文件，并在 components 数组中添加一个新的 URL 管理器组件声明：

```php
'urlManager'=>array(
    'urlFormat'=>'path',
 ),    
```

只要我们坚持使用默认的并将组件命名为`urlManager`，我们就不需要指定组件的类，因为在`CWebApplication.php`框架类中预先声明为`CUrlManager.php`。

通过这个简单的添加，我们的 URL 结构已经在整个站点中改变为路径格式。例如，以前，如果我们想要查看 ID 为 1 的特定问题，我们使用以下 URL 进行请求：

`http://localhost/trackstar/index.php?r=issue/view&id=1`

现在，通过这些更改，我们的 URL 看起来是这样的：

`http://localhost/trackstar/index.php/issue/view/id/1`

您会注意到我们所做的更改已经影响了应用程序中生成的所有 URL。要查看这一点，再次访问我们的订阅，转到`http://localhost/trackstar/index.php/comment/feed/`。我们注意到，所有我们的问题链接都已经被重新格式化为这个新的结构。这都归功于我们一贯使用控制器方法和其他辅助方法来生成我们的 URL。我们只需在一个配置文件中更改 URL 格式，这些更改就会自动传播到整个应用程序。

我们的 URL 看起来更好了，但我们仍然有入口脚本`index.php`，并且我们还不能在我们的订阅 URL 的末尾添加`.xml`后缀。因此，让我们隐藏`index.php`文件作为 URL 的一部分，并设置请求路由以理解对`commentfeed.xml`的请求实际上意味着对`CommentController::actionFeed()`的请求。让我们先解决后者。

### 配置路由规则

Yii URL 管理器允许我们指定规则来定义 URL 的解析和创建方式。规则由定义路由和模式组成。模式用于匹配 URL 的路径信息部分，以确定使用哪个规则来解析或创建 URL。模式可以包含使用语法 `ParamName:RegExp` 的命名参数。在解析 URL 时，匹配的规则将从路径信息中提取这些命名参数，并将它们放入 `$_GET` 变量中。当应用程序创建 URL 时，匹配的规则将从 `$_GET` 中提取命名参数，并将它们放入创建的 URL 的路径信息部分。如果模式以 `/*` 结尾，这意味着可以在 URL 的路径信息部分附加额外的 `GET` 参数。

要指定 URL 规则，将`CUrlManager`文件的`rules`属性设置为规则数组，格式为`pattern=>route`。

例如，让我们看看以下两条规则：

```php
'urlManager'=>array(
  'urlFormat'=>'path',
  'rules'=>array(
  'issues'=>'issue/index',
  'issue/<id:\d+>/*'=>'issue/view',
  ),
)
```

这段代码中指定了两条规则。第一条规则表示，如果用户请求 URL `http://localhost/trackstar/index.php/issues`，则应该被视为 `http://localhost/trackstar/index.php/issue/index`，在构建 URL 时也是一样的。因此，例如，如果我们在应用程序中使用控制器的 `createUrl('issue/index')` 方法创建 URL，它将生成 `/trackstar/index.php/issues` 而不是 `/trackstar/index.php/issue/index`。

第二条规则包含一个命名参数`id`，使用`<ParamName:RegExp>`语法指定。它表示，例如，如果用户请求 URL `http://localhost/trackstar/index.php/issue/1`，则应该被视为 `http://localhost/trackstar/index.php/issue/view/id/1`。在构建这样的 URL 时也是一样的。

路由也可以被指定为一个数组本身，以允许设置其他属性，比如 URL 后缀以及路由是否应该被视为区分大小写。当我们为我们的评论订阅指定规则时，我们将利用这些属性。

让我们将以下规则添加到我们的`urlManager`应用程序组件配置中：

```php
'urlManager'=>array(
        'urlFormat'=>'path',   
 **'rules'=>array(   'commentfeed'=>array('comment/feed', 'urlSuffix'=>'.xml', 'caseSensitive'=>false),**
      ), 
), 
```

在这里，我们使用了`urlSuffix`属性来指定我们期望的 URL`.xml`后缀。

现在我们可以通过以下 URL 访问我们的订阅：

`http://localhost/trackstar/index.php/commentFeed.xml`

#### 从 URL 中删除入口脚本

现在我们只需要从 URL 中删除`index.php`部分。这可以通过以下两个步骤完成：

1.  修改 Web 服务器配置，将所有不对应现有文件或目录的请求重定向到`index.php`。

1.  将`urlManager`组件的`showScriptName`属性设置为`false`。

第一步处理了应用程序如何路由请求，而后者处理了应用程序中 URL 的创建方式。

由于我们使用 Apache HTTP 服务器，我们可以通过在应用程序根目录中创建一个`.htaccess`文件并向该文件添加以下指令来执行第一步：

```php
# Turning on the rewrite engine is necessary for the following rules and features.
# FollowSymLinks must be enabled for this to work.
<IfModule mod_rewrite.c>
  Options +FollowSymlinks
  RewriteEngine On
</IfModule>

# Unless an explicit file or directory exists, redirect all request to Yii entry script
<IfModule mod_rewrite.c>
  RewriteCond %{REQUEST_FILENAME} !-f
  RewriteCond %{REQUEST_FILENAME} !-d
  RewriteRule . index.php
</IfModule>
```

### 注意

这种方法仅适用于 Apache HTTP 服务器。如果使用不同的 Web 服务器，您将需要查阅 Web 服务器重写规则。还要注意，这些信息可以放在主 Apache 配置文件中，作为使用`.htaccess`文件方法的替代方法。

有了这个`.htaccess`文件，我们现在可以通过导航到`http://localhost/trackstar/commentfeed.xml`（或`http://localhost/trackstar/commentFeed.xml`，因为我们将大小写敏感性设置为 false）来访问我们的源。

然而，即使有了这个，如果我们在应用程序中使用控制器方法或`CHtml`助手方法之一来创建我们的 URL，比如在控制器类中执行`$this->createAbsoluteUrl('comment/feed');`，它将生成以下 URL，其中 URL 中仍然包含`index.php`：

`http://localhost/trackstar/index.php/commentfeed.xml`

为了指示它在生成 URL 时不使用条目脚本名称，我们需要在`urlManager`组件上设置该属性。我们在`main.php`配置文件中再次执行此操作，如下所示：

```php
'urlManager'=>array(
    'urlFormat'=>'path',   
    'rules'=>array(
       'commentfeed'=>array('comment/feed', 'urlSuffix'=>'.xml', 'caseSensitive'=>false),
  ), 
 **'showScriptName'=>false,**
 ),   
```

为了处理 URL 中项目 ID 的添加，我们需要将评论源数据限制为与特定项目相关联的评论，为此我们需要添加另一条规则，如下所示：

```php
'urlManager'=>array(
        'urlFormat'=>'path',   
        'rules'=>array(   
 **'<pid:\d+>/commentfeed'=>array('comment/feed', 'urlSuffix'=>'.xml', 'caseSensitive'=>false),**
         'commentfeed'=>array('comment/feed', 'urlSuffix'=>'.xml', 'caseSensitive'=>false),
      ), 
      'showScriptName'=>false,
),
```

这个规则还使用了`<Parameter:RegEx>`语法来指定一个模式，以允许在 URL 的`commentfeed.xml`部分之前指定项目 ID。有了这个规则，我们可以将我们的 RSS 源限制为特定项目的评论。例如，如果我们只想要与项目#`2`相关联的评论，URL 格式将是：

`http://localhost/trackstar/2/commentfeed.xml`

# 添加订阅链接

现在我们已经创建了我们的源并改变了 URL 结构，使其更加用户友好和搜索引擎友好，我们需要添加用户订阅源的功能。其中一种方法是在我们想要添加 RSS 源链接的页面渲染之前添加以下代码。让我们在项目列表页面以及特定项目详细信息页面都这样做。我们将从项目列表页面开始。这个页面由`ProjectController::actionIndex()`方法渲染。修改该方法如下：

```php
public function actionIndex()
{
    $dataProvider=new CActiveDataProvider('Project');

 **Yii::app()->clientScript->registerLinkTag(**
 **'alternate',**
 **'application/rss+xml',**
 **$this->createUrl('comment/feed'));**

    $this->render('index',array(
      'dataProvider'=>$dataProvider,
    ));
}
```

这里显示的突出显示的代码将添加以下内容到渲染的 HTML 的`<head>`标签中：

```php
<link rel="alternate" type="application/rss+xml" href="/commentfeed.xml" />
```

在许多浏览器中，这将自动生成一个小的 RSS 源图标在地址栏中。以下截图显示了 Safari 地址栏中这个图标的样子：

![添加订阅链接](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/webapp-dev-yii-php/img/8727_09_03.jpg)

我们进行类似的更改，以将此链接添加到特定项目详细信息页面。这些页面的渲染由`ProjectController::actionView()`方法处理。修改该方法如下：

```php
public function actionView($id)
  {
    $issueDataProvider=new CActiveDataProvider('Issue', array(
      'criteria'=>array(
         'condition'=>'project_id=:projectId',
         'params'=>array(':projectId'=>$this->loadModel($id)->id),
       ),
       'pagination'=>array(
         'pageSize'=>1,
       ),
     ));

 **Yii::app()->clientScript->registerLinkTag(**
 **'alternate',**
 **'application/rss+xml',**
 **$this->createUrl('comment/feed',array('pid'=>$this->loadModel($id)->id)));**

    $this->render('view',array(
      'model'=>$this->loadModel($id),
      'issueDataProvider'=>$issueDataProvider,
    ));

  }
```

这几乎与我们添加到索引方法中的内容相同，只是我们正在指定项目 ID，以便我们的评论条目仅限于与该项目相关联的条目。类似的图标现在将显示在我们项目详细信息页面的地址栏中。单击这些图标允许用户订阅这些评论源。

### 注意

`registerLinkTag()`方法还允许您在第四个参数中指定媒体属性，然后您可以进一步指定其他支持的属性作为`name=>value`对的数组，作为第五个参数。有关使用此方法的更多信息，请参见[`www.yiiframework.com/doc/api/1.1/CClientScript/#registerLinkTag-detail`](http://www.yiiframework.com/doc/api/1.1/CClientScript/#registerLinkTag-detail)。

# 摘要

本章展示了如何轻松地将 Yii 与其他外部框架集成。我们特别使用了流行的 Zend Framework 来进行演示，并能够快速地向我们的应用程序添加符合 RSS 标准的 Web 订阅。虽然我们特别使用了`Zend_Feed`，但我们真正演示了如何将 Zend Framework 的任何组件集成到应用程序中。这进一步扩展了 Yii 已经非常丰富的功能，使 Yii 应用程序变得非常功能丰富。

我们还了解了 Yii 中的 URL 管理功能，并在整个应用程序中改变了我们的 URL 格式，使其更加用户和搜索引擎友好。这是改进我们应用程序外观和感觉的第一步，这是我们到目前为止非常忽视的事情。在下一章中，我们将更仔细地研究 Yii 应用程序的展示层。样式、主题以及通常使事物看起来好看将是下一章的重点。


# 第十章：让它看起来不错

在上一章中，我们通过使我们的 URL 对用户和搜索引擎爬虫更具吸引力，为我们的应用程序增添了一些美感。在本章中，我们将更多地关注我们应用程序的外观和感觉，涵盖 Yii 中布局和主题的主题。我们将专注于一个人采取的方法和可用的工具，以帮助设计 Yii 应用程序的前端，而不是设计本身。因此，本章将更多地关注如何使您的应用程序看起来不错，而不是花费大量时间专门设计我们的 TrackStar 应用程序以实际看起来不错。

# 功能规划

本章旨在专注于前端。我们希望为我们的网站创建一个可重用且能够动态实现的新外观。我们还希望在不覆盖或删除当前设计的情况下实现这一点。最后，我们将深入研究 Yii 的国际化功能，以更好地了解如何适应来自不同地理区域的用户。

以下是我们需要完成的高级任务列表，以实现这些目标：

+   通过创建新的布局、CSS 和其他资产文件来为我们的应用程序创建一个新的前端设计

+   使用 Yii 的国际化和本地化功能来帮助将应用程序的一部分翻译成新语言

# 使用布局进行设计

您可能已经注意到的一件事是，我们在不添加任何显式导航以访问此功能的情况下向我们的应用程序添加了大量功能。我们的主页尚未从我们构建的默认应用程序更改。我们的新应用程序创建时的导航项与我们创建新应用程序时的导航项相同。我们需要更改我们的基本导航，以更好地反映应用程序中存在的基本功能。

到目前为止，我们尚未完全涵盖我们的应用程序如何使用负责显示内容的所有视图文件。我们知道我们的视图文件负责显示我们的数据和承载响应每个页面请求的返回的 HTML。当我们创建新的控制器操作时，我们经常创建新的视图来处理这些操作方法返回的内容的显示。这些视图中的大多数都非常特定于它们支持的操作方法，并且不会跨多个页面使用。但是，有一些东西，例如主菜单导航，可以在整个站点的多个页面上使用。这些类型的 UI 组件更适合驻留在所谓的布局文件中。

Yii 中的**布局**是用于装饰其他视图文件的特殊视图文件。布局通常包含跨多个视图文件共同的标记或其他用户界面组件。当使用布局来呈现视图文件时，Yii 会将视图文件嵌入布局中。

## 指定布局

可以指定布局的两个主要位置。一个是`CWebApplication`本身的`$layout`属性。这默认为`protected/views/layouts/main.php`。与所有应用程序设置一样，这可以在主配置文件`protected/config/main.php`中被覆盖。例如，如果我们创建了一个新的布局文件`protected/views/layouts/newlayout.php`，并希望将此新文件用作我们的应用程序范围的布局文件，我们可以修改我们的主`config.php`文件来设置布局属性如下：

```php
return array(
  ...
  'layout'=>'newlayout',
```

文件名不带`.php`扩展名，并且相对于`CWebApplication`的`$layoutPath`属性指定，该属性默认为`Webroot/protected/views/layouts`（如果此位置不适合您的应用程序需求，则可以类似地覆盖它）。

另一个指定布局的地方是通过设置控制器类的`$layout`属性。这允许更细粒度地控制每个控制器的布局。这是在生成初始应用程序时指定的方式。使用`yiic`工具创建我们的初始应用程序时，自动创建了一个控制器基类`Webroot/protected/components/Controller.php`，所有其他控制器类都是从这个类继承的。打开这个文件会发现`$layout`属性已经设置为`column1`。在更细粒度的控制器级别设置布局文件将覆盖`CWebApplication`类中的设置。

## 应用和使用布局

在调用`CController::render()`方法时，布局文件的使用是隐含的。也就是说，当您调用`render()`方法来渲染一个视图文件时，Yii 将把视图文件的内容嵌入到控制器类中指定的布局文件中，或者嵌入到应用程序级别指定的布局文件中。您可以通过调用`CController::renderPartial()`方法来避免对渲染的视图文件应用任何布局装饰。

如前所述，布局文件通常用于装饰其他视图文件。布局的一个示例用途是为每个页面提供一致的页眉和页脚布局。当调用`render()`方法时，幕后发生的是首先将调用发送到指定视图文件的`renderPartial()`。这个输出存储在一个名为`$content`的变量中，然后可以在布局文件中使用。因此，一个非常简单的布局文件可能如下所示：

```php
<!DOCTYPE html>
<html>
<head>
<title>Title of the document</title>
</head>
<body>
  <div id="header">
    Some Header Content Here
  </div>

  <div id="content">
    <?php echo $content; ?>
  </div>

  <div id="footer">
      Some Footer Content Here
  </div>
</body>
</html>
```

实际上让我们试一试。创建一个名为`newlayout.php`的新文件，并将其放在布局文件的默认目录`/protected/views/layouts/`中。将前面的 HTML 内容添加到此文件中并保存。现在我们将通过修改我们的站点控制器来使用这个新布局。打开`SiteController.php`并通过在这个类中显式添加它来覆盖基类中设置的布局属性，如下所示：

```php
class SiteController extends Controller
{

  public $layout='newlayout';
```

这将把布局文件设置为`newlayout.php`，但仅适用于这个控制器。现在，每当我们在`SiteController`中调用`render()`方法时，将使用`newlayout.php`布局文件。

`SiteController`负责渲染的一个页面是登录页面。让我们来看看该页面，以验证这些更改。如果我们导航到`http://localhost/trackstar/site/login`（假设我们还没有登录），我们现在看到类似以下截图的东西：

![应用和使用布局](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/webapp-dev-yii-php/img/8727_10_01.jpg)

如果我们简单地注释掉我们刚刚添加的`$layout`属性并再次刷新登录页面，我们将回到使用原始的`main.php`布局，并且我们的页面现在将恢复到之前的样子。

# 解构 main.php 布局文件

到目前为止，我们的应用程序页面都使用`main.php`布局文件来提供主要的布局标记。在开始对我们的页面布局和设计进行更改之前，最好先仔细查看一下这个主要布局文件。您可以从本章的可下载代码中完整查看它，或者在[`gist.github.com/3781042`](https://gist.github.com/3781042)上查看独立文件。

第一行到第五行可能会让你觉得有些熟悉：

```php
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html  xml:lang="en" lang="en">
<head>
  <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
  <meta name="language" content="en" />
```

这些行定义了一个标准的 HTML 文档类型声明，后面是一个开始的`<html>`元素，然后是我们的`<head>`元素的开始。在`<head>`标记内，我们首先有一个`<meta>`标记来声明标准的`XHTML-compliant uft-8`字符编码，然后是另一个`<meta>`标记，指定`English`作为网站编写的主要语言。

## 介绍 Blueprint CSS 框架

以下几行以注释`<!—blueprint CSS framework -->`开头，可能对您来说不太熟悉。Yii 的另一个很棒的地方是，在适当的时候，它利用其他最佳框架，Blueprint CSS 框架就是一个例子。

Blueprint CSS 框架是在我们最初创建应用程序时使用`yiic`工具时作为副产品包含在应用程序中的。它包含在内是为了帮助标准化 CSS 开发。Blueprint 是一个 CSS 网格框架。它有助于标准化您的 CSS，提供跨浏览器兼容性，并在 HTML 元素放置方面提供一致性，有助于减少 CSS 错误。它提供了许多屏幕和打印友好的布局定义，并通过提供您所需的所有 CSS 来快速启动设计，使您的设计看起来不错并且位置正确。有关 Blueprint 框架的更多信息，请访问[`www.blueprintcss.org/`](http://www.blueprintcss.org/)。

因此，以下代码行是 Blueprint CSS 框架所必需的和特定的：

```php
<!-- blueprint CSS framework -->
<link rel="stylesheet" type="text/css" href="<?php echo Yii::app()->request->baseUrl; ?>/css/screen.css" media="screen, projection" />
<link rel="stylesheet" type="text/css" href="<?php echo Yii::app()->request->baseUrl; ?>/css/print.css" media="print" />
<!--[if lt IE 8]>
<link rel="stylesheet" type="text/css" href="<?php echo Yii::app()->request->baseUrl; ?>/css/ie.css" media="screen, projection" />
<![endif]-->
```

调用`Yii::app()->request->baseUrl;`在这里用于获取应用程序的相对 URL。

### 了解 Blueprint 安装

Yii 绝不要求使用 Blueprint。但是，由于默认应用程序生成包括该框架，了解其安装和使用将是有益的。

Blueprint 的典型安装首先涉及下载框架文件，然后将其三个`.css`文件放入 Yii 应用程序的主`css`目录中。如果我们在 TrackStar 应用程序的主`Webroot/css`目录下查看，我们已经看到包含了这三个文件：

+   `ie.css`

+   `print.css`

+   `screen.css`

所以幸运的是，基本安装已经完成。为了利用该框架，先前的`<link>`标签需要放置在每个网页的`<head>`标签下。这就是为什么这些声明是在布局文件中进行的。

接下来的两个`<link>`标签如下：

```php
<link rel="stylesheet" type="text/css" href="<?php echo Yii::app()->request->baseUrl; ?>/css/main.css" />
<link rel="stylesheet" type="text/css" href="<?php echo Yii::app()->request->baseUrl; ?>/css/form.css" />
```

这些`<link>`标签定义了一些自定义的`css`定义，用于提供布局声明，除了 Blueprint 文件中指定的声明之外。您应该始终将任何自定义定义放在 Blueprint 提供的定义下面，以便您的自定义声明优先。

## 设置页面标题

根据每个页面设置特定且有意义的页面标题对于搜索引擎索引您网站页面和希望将您网站特定页面加为书签的用户来说非常重要。我们主要布局文件中的下一行指定了浏览器中的页面标题：

```php
<title><?php echo CHtml::encode($this->pageTitle); ?></title>
```

请记住，在视图文件中，`$this`指的是最初呈现视图的控制器类实例。`$pageTitle`属性在 Yii 的`CController`基类中定义，并将默认为动作名称，后跟控制器名称。这在特定控制器类中甚至在每个特定视图文件中都可以轻松自定义。

## 定义页面页眉

通常情况下，网站被设计为在许多页面上重复具有一致的页眉内容。我们主要布局文件中的接下来几行定义了页面页眉的区域：

```php
<body>
<div class="container" id="page">

  <div id="header">
    <div id="logo"><?php echo CHtml::encode(Yii::app()->name); ?></div>
  </div><!-- header -->
```

第一个带有`container`类的`<div>`标签是 Blueprint 框架所必需的，以便将内容显示为网格。

### 注意

再次，使用 Blueprint CSS Grid 框架或任何其他 CSS 框架并不是 Yii 的要求。它只是为了帮助您在需要时快速启动设计布局。

接下来的三行布置了我们在这些页面上看到的主要内容的第一部分。它们显示了应用程序的名称。到目前为止，它一直显示文本**My Web Application**。我相信这让你们中的一些人感到疯狂。尽管我们以后可能会更改为使用标志图像，但让我们继续将其更改为我们应用程序的真实名称**TrackStar**。

我们可以在 HTML 中直接硬编码这个名称。然而，如果我们修改应用程序配置以反映我们的新名称，这些更改将在整个网站的任何地方传播，无论`Yii::app()->name`在哪里使用。我相信你现在可以轻松地在睡梦中做出这个简单的改变。只需打开主`config.php`文件`/protected/config/main.php`，在那里我们定义了应用程序配置设置，并将`name`属性的值从`'name'=>'My Web Application'`更改为新值`'name'=>'TrackStar'`。

保存文件，刷新浏览器，主页的标题现在应该看起来类似于以下截图：

![定义页面标题](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/webapp-dev-yii-php/img/8727_10_02.jpg)

我们立即注意到在上一个截图中已经在两个地方进行了更改。恰好我们的主页内容的视图文件`/protected/views/site/index.php`也使用了应用程序名称属性。由于我们在应用程序配置文件中进行了更改，我们的更改在两个地方都得到了反映。

由于名称属性是您可能决定在某个时候更改的内容，因此也定义应用程序`id`属性是一个好习惯。这个属性被框架用来创建唯一的签名键作为访问会话变量、缓存数据和其他令牌的前缀。如果没有指定`id`属性，则将使用`name`属性。因此更改它可能会使这些数据无效。让我们也为我们的应用程序定义一个`id`属性。这是添加到`protected/config/main.php`中的，就像我们为`name`属性所做的那样。我们可以使用与我们的名称相同的值：

```php
'id'=>'TrackStar',
```

## 显示菜单导航项

主站点的导航控件通常在 Web 应用程序的多个页面上重复出现，并且将其放在布局中使得重复使用非常容易。我们主要布局文件中的下一个标记和代码块定义了顶级菜单项：

```php
<div id="mainmenu">
  <?php $this->widget('zii.widgets.CMenu',array(
    'items'=>array(
      array('label'=>'Home', 'url'=>array('/site/index')),
      array('label'=>'About', 'url'=>array('/site/page', 'view'=>'about')),
      array('label'=>'Contact', 'url'=>array('/site/contact')),
      array('label'=>'Login', 'url'=>array('/site/login'), 'visible'=>Yii::app()->user->isGuest),
      array('label'=>'Logout ('.Yii::app()->user->name.')', 'url'=>array('/site/logout'), 'visible'=>!Yii::app()->user->isGuest)
    ),
  )); ?>
</div><!-- mainmenu -->
```

在这里，我们看到 Zii 组件之一称为`CMenu`正在被使用。我们在第八章中介绍了 Zii，*添加用户评论*。为了唤起你的记忆，Zii 扩展库是 Yii 开发团队开发的一组扩展。这个库与核心 Yii 框架一起打包。任何这些扩展都可以在 Yii 应用程序中轻松使用，只需通过使用路径别名引用所需的扩展类文件，形式为`zii.path.to.ClassName`。根别名`zii`由应用程序预定义，其余路径相对于这个框架目录。由于这个 Zii 菜单扩展位于您的文件系统上的`YiiRoot/zii/widgets/CMenu.php`，所以我们可以在应用程序代码中简单地使用`zii.widgets.CMenu`来引用它。

`CMenu`接受一个提供菜单项的关联数组。每个项目数组包括一个将要显示的`label`，一个该项目应链接到的 URL，以及一个可选的第三个值`visible`，它是一个`boolean`值，指示是否应该显示该菜单项。在这里，当定义**登录**和**注销**菜单项时使用了这个。我们只希望**登录**菜单项在用户尚未登录时显示为可点击链接。反之，我们只希望**注销**菜单链接在用户已经登录时显示。数组中的 visible 元素的使用允许我们根据用户是否已登录动态显示这些链接。使用`Yii::app()->user->isGuest`是为了这个目的。如果用户未登录，则返回`true`，如果用户已登录，则返回`false`。我相信你已经注意到，**登录**选项在您登录时会变成应用程序主菜单中的**注销**选项，反之亦然。

让我们更新我们的菜单，为用户提供导航到我们特定的 TrackStar 功能的方法。首先，我们不希望匿名用户能够访问任何真正的功能，除了登录。因此，我们需要确保登录页面更多或更少地成为匿名用户的主页。此外，已登录用户的主页应该只是他们项目的列表。我们将通过进行以下更改来实现这一点：

1.  将我们应用程序的默认主页 URL 更改为项目列表页面，而不仅仅是`site/index`。

1.  将默认控制器`SiteController`中的默认操作更改为登录操作。这样，任何访问顶级 URL `http://localhost/trackstar/` 的匿名用户都将被重定向到登录页面。

1.  修改我们的`actionLogin()`方法，如果用户已经登录，则将用户重定向到项目列表页面。

1.  将**主页**菜单项更改为**项目**，并将 URL 更改为项目列表页面。

这些都是我们需要做出的简单更改。从顶部开始，我们可以在主应用程序`config.php`文件中更改主页 URL 应用程序属性。打开`protected/config/main.php`并将以下`name=>value`对添加到返回的数组中：

```php
'homeUrl'=>'/trackstar/project',
```

这就是需要做出的所有更改。

对于下一个更改，打开`protected/controllers/SiteController.php`并将以下内容添加到控制器类的顶部：

```php
public $defaultAction = 'login';
```

这将默认操作设置为登录。现在，如果您访问应用程序的顶级 URL `http://localhost/trackstar/`，您应该被带到登录页面。唯一的问题是，无论您是否已经登录，您都将继续从这个顶级 URL 被带到登录页面。让我们通过实施上一个列表的第 3 步来解决这个问题。在`SiteController`中的`actionLogin()`方法中添加以下代码：

```php
public function actionLogin()
{

  if(!Yii::app()->user->isGuest) 
     {
          $this->redirect(Yii::app()->homeUrl);
     }
```

这将把所有已登录用户重定向到应用程序的`homeUrl`，我们刚刚将其设置为项目列表页面。

最后，让我们修改`CMenu`小部件的输入数组，以更改**主页**菜单项的规范。在`main.php`布局文件中更改该代码块，并用以下内容替换`array('label'=>'Home', 'url'=>array('/site/index')),`这一行：

```php
array('label'=>'Projects', 'url'=>array('/project')),
```

通过这个替换，我们之前概述的所有更改都已经就位。现在，如果我们以匿名用户身份访问 TrackStar 应用程序，我们将被引导到登录页面。如果我们点击**项目**链接，我们仍然会被引导到登录页面。我们仍然可以访问**关于**和**联系**页面，这对于匿名用户来说是可以的。如果我们登录，我们将被引导到项目列表页面。现在，如果我们点击**项目**链接，我们将被允许查看项目列表。

## 创建面包屑导航

回到我们的`main.php`布局文件，跟随菜单小部件之后的三行代码定义了另一个 Zii 扩展小部件，称为`CBreadcrumbs`：

```php
<?php $this->widget('zii.widgets.CBreadcrumbs', array(
  'links'=>$this->breadcrumbs,
)); ?><!-- breadcrumbs -->
```

这是另一个 Zii 小部件，可用于显示指示当前页面位置的链接列表，相对于整个网站中的其他页面。例如，格式为**项目 >> 项目 1 >> 编辑**的链接导航列表表示用户正在查看项目 1 的编辑页面。这对用户找回起点（即所有项目的列表）以及轻松查看他们在网站页面层次结构中的位置非常有帮助。这就是为什么它被称为**面包屑**。许多网站在其设计中实现了这种类型的 UI 导航组件。

要使用此小部件，我们需要配置其`links`属性，该属性指定要显示的链接。此属性的预期值是定义从起始点到正在查看的特定页面的`面包屑`路径的数组。使用我们之前的示例，我们可以将`links`数组指定如下：

```php
array(
  'Projects'=>array('project/index'),
  'Project 1'=>array('project/view','id'=>1),
  'Edit',
  )
```

`breadcrumbs`小部件默认情况下会根据应用程序配置设置`homeUrl`自动添加顶级**主页**链接。因此，从前面的代码片段生成的面包屑将如下所示：

**主页 >> 项目 >> 项目 1 >> 编辑**

由于我们明确将应用程序的`$homeUrl`属性设置为项目列表页面，所以在这种情况下我们的前两个链接是相同的。布局文件中的代码将链接属性设置为呈现视图的控制器类的`$breadcrumbs`属性。您可以在使用 Gii 代码生成工具创建控制器文件时为我们自动生成的几个视图文件中明确看到这一点。例如，如果您查看`protected/views/project/update.php`，您将在该文件的顶部看到以下代码片段：

```php
$this->breadcrumbs=array(
  'Projects'=>array('index'),
  $model->name=>array('view','id'=>$model->id),
  'Update',
);
```

如果我们在网站上导航到该页面，我们将看到主导航栏下方生成的以下导航面包屑：

![创建面包屑导航](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/webapp-dev-yii-php/img/8727_10_03.jpg)

## 指定被布局装饰的内容

布局文件中的下一行显示了被该布局文件装饰的视图文件的内容放置位置：

```php
<?php echo $content; ?>
```

这在本章的前面已经讨论过。当您在控制器类中使用`$this->render()`来显示特定的视图文件时，隐含了使用布局文件。这个方法的一部分是将呈现的特定视图文件中的所有内容放入一个名为`$content`的特殊变量中，然后将其提供给布局文件。因此，如果我们再次以项目更新视图文件为例，`$content`的内容将是包含在文件`protected/views/project/update.php`中的呈现内容。

## 定义页脚

与*页眉*区域一样，通常情况下网站被设计为在许多页面上重复显示一致的*页脚*内容。我们的`main.php`布局文件的最后几行定义了每个页面的一致`页脚`：

```php
<div id="footer">
    Copyright &copy; <?php echo date('Y'); ?> by My Company.<br/>
    All Rights Reserved.<br/>
    <?php echo Yii::powered(); ?>
</div><!-- footer -->
```

这里没有什么特别的，但我们应该继续更新它以反映我们特定的网站。我们可以将前面的代码片段中的`My Company`简单地更改为`TrackStar`，然后完成。刷新网站中的页面现在将显示我们的页脚，如下面的截图所示：

![定义页脚](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/webapp-dev-yii-php/img/8727_10_04.jpg)

# 嵌套布局

尽管我们在页面上看到的原始布局确实使用了文件`protected/layouts/main.php`，但这并不是全部。当我们的初始应用程序创建时，所有控制器都被创建为扩展自位于`protected/components/Controller.php`的基础控制器。如果我们偷看一下这个文件，我们会看到布局属性被明确定义。但它并没有指定主布局文件。相反，它将`column1`指定为所有子类的默认布局文件。您可能已经注意到，当新应用程序创建时，还为我们生成了一些布局文件，全部位于`protected/views/layouts/`目录中：

+   `column1.php`

+   `column2.php`

+   `main.php`

因此，除非在子类中明确覆盖，否则我们的控制器将`column1.php`定义为主要布局文件，而不是`main.php`。

你可能会问，为什么我们要花那么多时间去了解`main.php`呢？嗯，事实证明，`column1.php`布局文件本身也被`main.php`布局文件装饰。因此，不仅可以通过布局文件装饰普通视图文件，而且布局文件本身也可以被其他布局文件装饰，形成嵌套布局文件的层次结构。这样可以极大地提高设计的灵活性，也极大地减少了视图文件中的重复标记的需要。让我们更仔细地看看`column1.php`，看看是如何实现这一点的。

该文件的内容如下：

```php
<?php $this->beginContent('//layouts/main'); ?>
<div id="content">
  <?php echo $content; ?>
</div><!-- content -->
<?php $this->endContent(); ?>
```

在这里，我们看到了一些以前没有见过的方法的使用。基本控制器方法`beginContent()`和`endContent()`被用来用指定的视图装饰封闭的内容。这里指定的视图是我们的主布局页面`'//layouts/main'`。`beginContent()`方法实际上使用了内置的 Yii 小部件`CContentDecorator`，其主要目的是允许嵌套布局。因此，`beginContent()`和`endContent()`之间的任何内容都将使用在`beginContent()`调用中指定的视图进行装饰。如果未指定任何内容，它将使用在控制器级别指定的默认布局，或者如果在控制器级别未指定，则使用应用程序级别的默认布局。

### 注意

在前面的代码片段中，我们看到视图文件被双斜杠`'//'`指定。在这种情况下，将在应用程序的视图路径下搜索视图，而不是在当前活动模块的视图路径下搜索。这迫使它使用主应用程序视图路径，而不是模块的视图路径。模块是下一章的主题。

其余部分就像普通的布局文件一样。当呈现此`column1.php`布局文件时，特定视图文件中的所有标记都将包含在变量`$content`中，然后此布局文件中包含的其他标记将再次包含在变量`$content`中，以供最终呈现主父布局文件`main.php`使用。

让我们通过一个示例来走一遍。以登录视图的呈现为例，即`SiteController::actionLogin()`方法中的以下代码：

```php
$this->render('login');
```

在幕后，正在执行以下步骤：

1.  呈现特定视图文件`/protected/views/site/login.php`中的所有内容，并通过变量`$content`将该内容提供给控制器中指定的布局文件，在这种情况下是`column1.php`。

1.  由于`column1.php`本身被布局`main.php`装饰，所以在`beingContent()`和`endContent()`调用之间的内容再次被呈现，并通过`$content`变量再次提供给`main.php`文件。

1.  布局文件`main.php`被呈现并返回给用户，包含了登录页面的特定视图文件的内容以及“嵌套”布局文件`column1.php`的内容。

当我们最初创建应用程序时，自动生成的另一个布局文件是`column2.php`。您可能不会感到惊讶地发现，该文件布局了一个两列设计。我们可以在项目页面中看到这个布局的使用，其中右侧显示了一个小子菜单**操作**小部件。该布局的内容如下，我们可以看到也使用了相同的方法来实现嵌套布局。

```php
<?php $this->beginContent('//layouts/main'); ?>
<div class="span-19">
  <div id="content">
    <?php echo $content; ?>
  </div><!-- content -->
</div>
<div class="span-5 last">
  <div id="sidebar">
  <?php
    $this->beginWidget('zii.widgets.CPortlet', array(
      'title'=>'Operations',
    ));
    $this->widget('zii.widgets.CMenu', array(
      'items'=>$this->menu,
      'htmlOptions'=>array('class'=>'operations'),
    ));
    $this->endWidget();
  ?>
  </div><!-- sidebar -->
</div>
<?php $this->endContent(); ?>
```

# 创建主题

主题提供了一种系统化的方式来定制 Web 应用程序的设计布局。 MVC 架构的许多好处之一是将演示与其他“后端”内容分离。主题通过允许您在运行时轻松而显着地改变 Web 应用程序的整体外观和感觉，充分利用了这种分离。 Yii 允许极其简单地应用主题，以提供 Web 应用程序设计的更大灵活性。

## 在 Yii 中构建主题

在 Yii 中，每个主题都表示为一个目录，包含视图文件、布局文件和相关资源文件，如图像、CSS 文件和 JavaScript 文件。主题的名称与其目录名称相同。默认情况下，所有主题都位于相同的`WebRoot/themes`目录下。当然，与所有其他应用程序设置一样，可以配置默认目录为其他目录。要这样做，只需修改`themeManager`应用程序组件的`basePath`属性和`baseUrl`属性。

主题目录下的内容应该以与应用程序基本路径下相同的方式进行组织。因此，所有视图文件都位于`views/`目录下，布局视图文件位于`views/layouts/`下，系统视图文件位于`views/system/`下。例如，如果我们创建了一个名为`custom`的新主题，并且想要用这个主题下的新视图替换`ProjectController`的更新视图，我们需要创建一个新的`update.php`视图文件，并将其保存在我们的应用项目中，路径为`themes/custom/views/project/update.php`。

## 创建主题

让我们试试看，给我们的 TrackStar 应用程序做一点小改变。我们需要给我们的新主题命名，并在`Webroot/themes`目录下创建一个同名的目录。我们将发挥我们的极端创造力，将我们的新主题命名为`newtheme`。

在`Webroot/themes/newtheme`位置创建一个新目录来保存这个新主题。然后在这个新创建的目录下，创建另外两个新目录，分别叫做`css/`和`views/`。前者不是主题系统所必需的，但有助于我们组织 CSS。后者是必需的，如果我们要对默认视图文件进行任何修改，而我们是要修改的。因为我们要稍微改变`main.php`布局文件，所以在这个新创建的`views/`目录下需要再创建一个名为`layouts/`的目录（记住目录结构需要与默认的`Webroot/protected/views/`目录中的相同）。

现在让我们做一些改变。由于我们的视图文件标记已经引用了`Webroot/css/main.css`文件中当前定义的`css`类和`id`名称，所以最快的路径到应用程序的新外观是以此为起点，并根据需要进行更改。当然，这不是必需的，因为我们可以在新主题中重新创建应用程序的每个视图文件。但是为了保持简单，我们将通过对为我们创建应用程序时自动生成的`main.css`文件以及主要布局文件`main.php`进行一些更改来创建我们的新主题。

首先，让我们复制这两个文件并将它们放在我们的新主题目录中。将文件`Webroot/css/main.css`复制到新位置`Webroot/themes/newtheme/css/main.css`，并将文件`Webroot/protected/views/layouts/main.php`复制到新位置`Webroot/themes/newtheme/views/layouts/main.php`。

现在我们可以打开新复制的`main.css`文件，删除内容，并添加必要的样式来创建我们的新主题。为了我们的示例，我们将使用本章可下载代码中提供的 CSS，或者在[`gist.github.com/3779729`](https://gist.github.com/3779729)上提供的独立文件。

您可能已经注意到，一些更改引用了我们项目中尚不存在的图像文件。我们在 body 声明中添加了一个`images/background.gif`图像引用，`#mainmenu` ID 声明中引用了一个新的`images/bg2.gif`图像，以及`#header` ID 声明中引用了一个新的`images/header.jpg`图像。这些都可以在可下载的源代码中找到。我们将把这些新图像放在`css/`目录中的一个图像目录中，即`Webroot/themes/newtheme/css/images/`。

这些更改生效后，我们需要对新主题中的`main.php`布局文件进行一些小的调整。首先，我们需要修改`<head>`元素中的标记，以正确引用我们的新`main.css`文件。目前，`main.css`文件是通过以下行引入的：

```php
<link rel="stylesheet" type="text/css" href="<?php echo Yii::app()->request->baseUrl; ?>/css/main.css" />
```

这引用了应用程序请求的`baseUrl`属性来构建到 CSS 文件的相对路径。然而，我们想要使用我们新主题中的`main.css`文件。为此，我们可以依靠主题管理器应用程序组件，默认定义使用 Yii 内置的`CThemeManager.php`类。我们访问主题管理器的方式与访问其他应用程序组件的方式相同。因此，我们应该使用主题管理器定义的基本 URL，它知道应用程序在任何给定时间使用的主题。修改前面提到的`/themes/newtheme/views/layouts/main.php`中的代码如下：

```php
<link rel="stylesheet" type="text/css" href="<?php echo Yii::app()->theme->baseUrl; ?>/css/main.css" />
```

一旦我们配置应用程序使用我们的新主题（这是我们尚未完成的），这个`baseUrl`将解析为我们的主题目录所在的相对路径。

我们需要做的另一个小改变是从头部中移除应用程序标题的显示。由于我们修改了 CSS 以使用新的图像文件来提供我们的头部和标志信息，我们不需要在这个部分显示应用程序名称。因此，在`/themes/newtheme/views/layouts/main.php`中，我们只需要改变以下代码：

```php
<div id="header">
  <div id="logo"><?php echo CHtml::encode(Yii::app()->name); ?></div>
</div><!-- header -->
```

将上述代码修改如下：

```php
<div id="header"></div><!-- header image is embedded into the #header declaration in main.css -->
```

我们已经放置了一个注释来提醒我们头部图像的定义位置。

现在一旦我们配置应用程序使用我们的新主题，它将首先在主题目录中查找`main.php`布局文件，如果存在的话就使用该文件。

## 配置应用程序使用主题

好的，有了我们现在创建并放置好的`newtheme`主题，我们需要告诉应用程序使用这个主题。这样做非常容易。只需通过改变主应用程序配置文件来修改主应用程序的`theme`属性设置。到目前为止，我们已经成为了这样做的老手。只需在`/protected/config/main.php`文件中的返回数组中添加以下`name=>value`对：

```php
'theme'=>'newtheme',
```

一旦保存了这个更改，我们的应用程序现在使用我们新创建的主题，并且有了全新的外观。当我们查看登录页面时，也就是我们的默认主页（如果没有登录），我们现在看到了以下截图中所示的内容：

![配置应用程序使用主题](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/webapp-dev-yii-php/img/8727_10_05.jpg)

当然，这并不是一个巨大的改变。我们保持了改动相当小，但它们确实展示了创建新主题的过程。应用程序首先会在这个新主题中查找视图文件，如果存在的话就使用它们，否则会从默认位置获取。你可以看到给应用程序赋予新的外观和感觉是多么容易。你可以为每个季节或基于不同的心情创建一个新主题，然后根据需要快速轻松地改变应用程序以适应季节或心情。

# 将网站翻译成其他语言

在结束本章之前，我们将讨论 Yii 中的国际化（`i18n`）和本地化（`l10n`）。**国际化**指的是以一种可以适应各种语言而无需进行基础工程更改的方式设计软件应用程序的过程。**本地化**指的是将国际化的软件应用程序适应特定地理位置或语言的过程，通过添加与地区相关的格式化和翻译文本。Yii 以以下方式支持这些功能：

+   它为几乎每种语言和地区提供了地区数据

+   它提供了辅助翻译文本消息字符串和文件的服务

+   它提供了与地区相关的日期和时间格式化

+   它提供了与地区相关的数字格式化

## 定义地区和语言

**区域**是指定义用户语言、国家和可能与用户位置相关的任何其他用户界面首选项的一组参数。它通常由一个语言标识符和一个区域标识符组成的复合`ID`来标识。例如，`en_us`的区域 ID 代表美国地区的英语。为了保持一致，Yii 中的所有区域 ID 都标准化为小写的`LanguageID`或`LanguageID_RegionID`格式（例如，`en`或`en_us`）。

在 Yii 中，区域数据表示为`CLocale`类的实例或其子类。它提供特定于区域的信息，包括货币和数字符号、货币、数字、日期和时间格式，以及月份、星期几等日期相关名称。通过区域 ID，可以通过使用静态方法`CLocale::getInstance($localeID)`或使用应用程序来获取相应的`CLocale`实例。以下示例代码使用应用程序组件基于`en_us`区域标识符创建一个新实例：

```php
Yii::app()->getLocale('en_us');
```

Yii 几乎为每种语言和地区提供了区域数据。这些数据来自通用区域数据存储库（[`cldr.unicode.org/`](http://cldr.unicode.org/)），存储在根据各自区域 ID 命名的文件中，并位于 Yii 框架目录`framework/i18n/data/`中。因此，在上一个示例中创建新的`CLocale`实例时，用于填充属性的数据来自文件`framework/i18n/data/en_us.php`。如果您查看此目录，您将看到许多语言和地区的数据文件。

回到我们的例子，如果我们想要获取特定于美国地区的英语月份名称，我们可以执行以下代码：

```php
$locale = Yii::app()->getLocale('en_us');
print_r($locale->monthNames);
```

其输出将产生以下结果：

![定义区域和语言](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/webapp-dev-yii-php/img/8727_10_08.jpg)

如果我们想要意大利语的相同月份名称，我们可以执行相同的操作，但创建一个不同的`CLocale`实例：

```php
$locale = Yii::app()->getLocale('it');
print_r($locale->monthNames);
```

现在我们的输出将产生以下结果：

![定义区域和语言](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/webapp-dev-yii-php/img/8727_10_09.jpg)

第一个实例基于数据文件`framework/i18n/data/en_us.php`，后者基于`framework/i18n/data/it.php`。如果需要，可以配置应用程序的`localeDataPath`属性，以指定一个自定义目录，您可以在其中添加自定义区域设置数据文件。

## 执行语言翻译

也许`i18n`最受欢迎的功能是语言翻译。如前所述，Yii 提供了消息翻译和视图文件翻译。前者将单个文本消息翻译为所需的语言，后者将整个文件翻译为所需的语言。

翻译请求包括要翻译的对象（文本字符串或文件）、对象所在的源语言以及要将对象翻译为的目标语言。Yii 应用程序区分其目标语言和源语言。**目标**语言是我们针对用户的语言（或区域），而**源**语言是指应用程序文件所写的语言。到目前为止，我们的 TrackStar 应用程序是用英语编写的，也是针对英语用户的。因此，到目前为止，我们的目标语言和源语言是相同的。Yii 的国际化功能，包括翻译，仅在这两种语言不同时适用。

### 执行消息翻译

通过调用以下应用程序方法执行消息翻译：

```php
Yii::t(string $category, string $message, array $params=array ( ), string $source=NULL, string $language=NULL)
```

该方法将消息从源语言翻译为目标语言。

在翻译消息时，必须指定类别，以便允许消息在不同类别（上下文）下进行不同的翻译。类别`Yii`保留用于 Yii 框架核心代码使用的消息。

消息也可以包含参数占位符，这些占位符在调用`Yii::t()`时将被实际参数值替换。以下示例描述了错误消息的翻译。这个消息翻译请求将在原始消息中用实际的`$errorCode`值替换`{errorCode}`占位符：

```php
Yii::t('category', 'The error: "{errorCode}" was encountered during the last request.',     array('{errorCode}'=>$errorCode));
```

翻译消息存储在称为**消息源**的存储库中。消息源表示为`CMessageSource`的实例或其子类的实例。当调用`Yii::t()`时，它将在消息源中查找消息，并在找到时返回其翻译版本。

Yii 提供以下类型的消息源：

+   **CPhpMessageSource**：这是默认的消息源。消息翻译存储为 PHP 数组中的键值对。原始消息是键，翻译后的消息是值。每个数组表示特定类别消息的翻译，并存储在一个单独的 PHP 脚本文件中，文件名为类别名。相同语言的 PHP 翻译文件存储在以区域 ID 命名的相同目录下。所有这些目录都位于由`basePath`指定的目录下。

+   **CGettextMessageSource**：消息翻译存储为`GNU Gettext`文件。

+   **CDbMessageSource**：消息翻译存储在数据库表中。

消息源作为应用程序组件加载。Yii 预先声明了一个名为`messages`的应用程序组件，用于存储用户应用程序中使用的消息。默认情况下，此消息源的类型是`CPhpMessageSource`，用于存储 PHP 翻译文件的基本路径是`protected/messages`。

一个示例将有助于将所有这些内容整合在一起。让我们将**登录**表单上的表单字段标签翻译成一个我们称为`Reversish`的虚构语言。**Reversish**是通过将英语单词或短语倒转来书写的。所以这里是我们登录表单字段标签的 Reversish 翻译：

| 英文 | Reversish |
| --- | --- |
| 用户名 | Emanresu |
| 密码 | Drowssap |
| Remember me next time | Emit txen em rebmemer |

我们将使用默认的`CPhpMessageSource`实现来存储我们的消息翻译。所以我们需要做的第一件事是创建一个包含我们翻译的 PHP 文件。我们将把区域 ID 设置为`rev`，并且现在只是称为类别`default`。我们需要在消息基本目录下创建一个遵循格式`/localeID/CategoryName.php`的新文件。所以我们需要在`/protected/messages/rev/default.php`下创建一个新文件，然后在该文件中添加以下翻译数组：

```php
<?php
return array(
    'Username' => 'Emanresu',
    'Password' => 'Drowssap',
    'Remember me next time' => 'Emit txen em rebmemer',
);
```

接下来，我们需要将应用程序目标语言设置为 Reversish。我们可以在应用程序配置文件中执行此操作，以便影响整个站点。只需在`/protected/config/main.php`文件中的返回数组中添加以下`name=>value`对：

```php
'language'=>'rev',
```

现在我们需要做的最后一件事是调用`Yii::t()`，以便我们的登录表单字段标签通过翻译发送。这些表单字段标签在`LoginForm::attributeLabels()`方法中定义。用以下代码替换整个方法：

```php
/**
   * Declares attribute labels.
   */
  public function attributeLabels()
  {
    return array(
      'rememberMe'=>Yii::t('default','Remember me next time'),
      'username'=>Yii::t('default', 'Username'),
      'password'=>Yii::t('default', 'Password'),
    );
  }
```

现在，如果我们再次访问我们的**登录**表单，我们将看到一个新的 Reversish 版本，如下面的截图所示：

![执行消息翻译](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/webapp-dev-yii-php/img/8727_10_06.jpg)

### 执行文件翻译

Yii 还提供了根据应用程序的目标区域设置使用不同文件的能力。文件翻译是通过调用应用程序方法 `CApplication::findLocalizedFile()` 来实现的。该方法接受文件的路径，并将在具有与目标区域 ID 相同名称的目录下查找具有相同名称的文件。目标区域 ID 要么作为方法的显式输入指定，要么作为应用程序配置中指定的内容。

让我们试一试。我们真正需要做的就是创建适当的翻译文件。我们将继续翻译登录表单。因此，我们创建一个新的视图文件 `/protected/views/site/rev/login.php`，然后添加我们的翻译内容。同样，这太长了，无法完整列出，但您可以在可下载的代码文件或独立内容中查看 [`gist.github.com/3779850`](https://gist.github.com/3779850)。

我们已经在主配置文件中为应用程序设置了目标语言，并在调用 `render('login')` 时，获取本地化文件的调用将在幕后为我们处理。因此，有了这个文件，我们的登录表单现在看起来如下截图所示：

![执行文件翻译](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/webapp-dev-yii-php/img/8727_10_07.jpg)

# 总结

在这一章中，我们已经看到 Yii 应用程序如何让您快速轻松地改进设计。我们介绍了布局文件的概念，并介绍了如何在应用程序中使用这些文件来布置需要在许多不同的网页上以类似方式实现的内容和设计。这也向我们介绍了 `CMenu` 和 `CBreadcrumbs` 内置小部件，它们在每个页面上提供了非常易于使用的 UI 导航结构。

然后，我们介绍了 Web 应用程序中主题的概念以及如何在 Yii 中创建它们。我们看到主题允许您轻松地为现有的 Web 应用程序提供新的外观，并允许您重新设计应用程序，而无需重建任何功能或“后端”。

最后，我们通过 `i18n` 和语言翻译的视角来看应用程序的面貌变化。我们学会了如何设置应用程序的目标区域，以启用本地化设置和语言翻译。

在本章和之前的章节中，我们已经多次提到“模块”，但尚未深入了解它们在 Yii 应用程序中的具体内容。这将是下一章的重点。


# 第十一章：使用 Yii 模块

到目前为止，我们已经为我们的 TrackStar 应用程序添加了许多功能。如果你回想一下第七章，“用户访问控制”，我们介绍了用户访问控制，根据用户角色层次结构限制某些功能。这在按项目基础限制对一些管理功能的访问上非常有帮助。例如，在特定项目中，您可能不希望允许团队的所有成员删除项目。我们使用基于角色的访问控制实现，将用户分配到项目中的特定角色，然后根据这些角色允许/限制对功能的访问。

然而，我们尚未解决的是应用程序整体的管理需求。像 TrackStar 这样的 Web 应用程序通常需要具有完全访问权限的特殊用户。一个例子是能够管理系统中每个用户的所有 CRUD 操作，而不管项目如何。我们应用程序的*完整管理员*应该能够登录并删除或更新任何用户、任何项目、任何问题，管理所有评论等。此外，通常情况下，我们构建适用于整个应用程序的额外功能，例如能够向所有用户留下站点范围的系统消息，管理电子邮件活动，打开/关闭某些应用程序功能，管理角色和权限层次结构本身，更改站点主题等。由于向管理员公开的功能可能与向普通用户公开的功能差异很大，因此将这些功能与应用程序的其余部分分开是一个很好的主意。我们将通过在 Yii 中构建所有我们的管理功能来实现这种分离，这被称为**模块**。

# 功能规划

在这一章中，我们将专注于以下细粒度的开发任务：

+   创建一个新模块来容纳管理功能

+   为管理员添加系统范围消息的能力，以在项目列表页面上查看

+   将新主题应用于模块

+   创建一个新的数据库表来保存系统消息数据

+   为我们的系统消息生成所有 CRUD 功能

+   将对新模块内的所有功能的访问限制为管理员用户

+   在项目列表页面上显示新的系统消息

# 使用模块

Yii 中的**模块**非常类似于包含在较大应用程序中的整个小型应用程序。它具有非常相似的结构，包含模型、视图、控制器和其他支持组件。但是，模块本身不能作为独立应用程序部署；它们必须驻留在一个应用程序中。

模块在以模块化方式构建应用程序方面非常有用。大型应用程序通常可以分成离散的应用程序功能，可以使用模块分别构建。网站功能，如添加用户论坛或用户博客，或站点管理员功能，是一些可以从主要站点功能中分割出来的示例，使它们可以在将来的项目中轻松重复使用。我们将使用一个模块来在我们的应用程序中创建一个独特的位置，以容纳我们的管理功能。

## 创建一个模块

使用我们的好朋友 Gii 创建一个新模块非常简单。在我们的 URL 更改就位后，该工具现在可以通过`http://localhost/trackstar/gii`访问。导航到那里，并在左侧菜单中选择**模块生成器**选项。您将看到以下截图：

![创建一个模块](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/webapp-dev-yii-php/img/8727_11_01.jpg)

我们需要为模块提供一个唯一的名称。由于我们正在创建一个 admin 模块，我们将非常有创意地给它命名为`admin`。在**Module ID**字段中输入这个名称，然后单击**Preview**按钮。如下截图所示，它将向您展示它打算生成的所有文件，允许您在创建它们之前预览每个文件：

![创建模块](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/webapp-dev-yii-php/img/8727_11_02.jpg)

单击**Generate**按钮，让它创建所有这些文件。您需要确保您的`/protected`文件夹对 Web 服务器进程是可写的，以便它可以自动创建必要的目录和文件。以下截图显示了成功生成模块的情况：

![创建模块](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/webapp-dev-yii-php/img/8727_11_03.jpg)

让我们更仔细地看看模块生成器为我们创建了什么。在 Yii 中，模块被组织为一个目录，其名称与模块的唯一名称相同。默认情况下，所有模块目录都位于`protected/modules`下。每个模块目录的结构与我们主应用程序的结构非常相似。这个命令为我们做的事情是为 admin 模块创建目录结构的骨架。由于这是我们的第一个模块，顶级目录`protected/modules`被创建，然后在其下创建了一个`admin/`目录。以下截图显示了执行`module`命令时创建的所有目录和文件：

![创建模块](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/webapp-dev-yii-php/img/8727_11_16.jpg)

模块必须有一个`module`类，该类直接或从`CWebModule`的子类扩展。模块类名称是通过组合模块 ID（即我们创建模块`admin`时提供的名称）和字符串`Module`来创建的。模块 ID 的第一个字母也被大写。所以在我们的情况下，我们的 admin 模块类文件名为`AdminModule.php`。模块类用作存储模块代码中共享信息的中心位置。例如，我们可以使用`CWebModule`的`params`属性来存储模块特定的参数，并使用其`components`属性在模块级别共享应用程序组件。这个模块类的作用类似于应用程序类对整个应用程序的作用。所以`CWebModule`对我们的模块来说就像`CWebApplication`对我们的应用程序一样。

## 使用模块

就像成功创建消息所指示的那样，在我们可以使用新模块之前，我们需要配置主应用程序的`modules`属性，以便包含它供使用。在我们向应用程序添加`gii`模块时，我们就已经这样做了，这使我们能够访问 Gii 代码生成工具。我们在主配置文件`protected/config/main.php`中进行了这些更改。以下突出显示的代码指示了必要的更改：

```php
'modules'=>array(
      'gii'=>array(
            'class'=>'system.gii.GiiModule',
            'password'=>'iamadmin',
      ),
 **'admin',**
   ),
```

保存这些更改后，我们的新`admin`模块已经准备好供使用。我们可以通过访问`http://localhost/trackstar/admin/default/index`来查看为我们创建的简单索引页面。用于访问我们模块中页面的请求路由结构与我们主应用程序页面的结构类似，只是我们还需要在路由中包含`moduleID`目录。我们的路由将具有一般形式`/moduleID/controllerID/actionID`。因此，URL 请求`/admin/default/index`正在请求`admin`模块的默认控制器的索引方法。当我们访问这个页面时，我们会看到类似以下截图的内容：

![使用模块](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/webapp-dev-yii-php/img/8727_11_05.jpg)

## 模块布局

我们会注意到，在上一章中创建的主题 `newtheme` 也被应用到了我们的模块上。原因是我们的模块控制器类扩展了 `protected/components/Controller.php`，它将其布局指定为 `$layout='//layouts/column1'`。关键在于这个定义前面的双斜杠。这指定我们使用主应用程序路径而不是特定模块路径来查找布局文件。因此，我们得到的布局文件与我们的应用程序的其余部分相同。如果我们将其改为单斜杠而不是双斜杠，我们会看到我们的 `admin` 模块根本没有应用布局。请尝试一下。原因是现在，只有单斜杠，即 `$layout='/layouts/column1'`，它正在在模块内寻找布局文件而不是父应用程序。请继续进行此更改，并在我们继续进行时保持单斜杠定义。

您可以在模块中几乎可以单独配置所有内容，包括布局文件的默认路径。Web 模块的默认布局路径是 `/protected/modules/[moduleID]/views/layouts`，在我们的情况下是 `admin`。我们可以看到在这个目录下没有文件，因此没有默认布局可应用于模块。

由于我们指定了一个主题，我们的情况稍微复杂一些。我们还可以在这个主题中管理所有模块视图文件，包括模块布局视图文件。如果我们这样做，我们需要添加到我们的主题目录结构以适应我们的新模块。目录结构非常符合预期。它的一般形式是 `/themes/[themeName]/views/[moduleID]/layouts/` 用于布局文件，`/themes/[themeName]/views/[moduleID]/[controllerID]/` 用于控制器视图文件。

为了帮助澄清这一点，让我们来看一下 Yii 在尝试决定为我们的新 `admin` 模块使用哪些视图文件时的决策过程。如前所述，如果我们在布局视图文件之前使用双斜杠（"//"）指定，它将查找父应用程序以找到布局文件。但让我们看看当我们使用单斜杠并要求它在模块内找到适当的布局文件时的情况。在单斜杠的情况下，当在我们的 `admin` 模块的 `DefaultController.php` 文件中发出 `$this->render('index')` 时，正在发生以下情况：

1.  由于调用了 `render()`，而不是 `renderPartial()`，它将尝试用布局文件装饰指定的 `index.php` 视图文件。由于我们的应用程序当前配置为使用名为 `newtheme` 的主题，它将首先在此主题目录下查找布局文件。我们的新模块的 `DefaultController` 类扩展了我们的应用程序组件 `Controller.php`，它将 `column1` 指定为其 `$layout` 属性。这个属性没有被覆盖，所以它也是 `DefaultController` 的布局文件。最后，由于这一切都发生在 `admin` 模块内部，Yii 首先寻找以下布局文件：

`/themes/newtheme/views/admin/layouts/column1.php`

（请注意在此目录结构中包含 `moduleID`。）

1.  这个文件不存在，所以它会回到模块的默认位置查找。如前所述，默认布局目录对每个模块都是特定的。所以在这种情况下，它将尝试定位以下布局文件：

`/protected/modules/admin/views/layouts/column1.php`

1.  这个文件也不存在，所以将无法应用布局。现在它将尝试渲染指定的 `index.php` 视图文件而不使用布局。然而，由于我们已经为这个应用程序指定了特定的 `newtheme` 主题，它将首先寻找以下视图文件：

`/themes/newtheme/views/admin/default/index.php`

1.  这个文件也不存在，所以它会再次在这个模块（`AdminModule`）的默认位置内寻找这个控制器（`DefaultController.php`），即`/protected/modules/admin/views/default/index.php`。

这解释了为什么页面`http://localhost/trackstar/admin/default/index`在没有任何布局的情况下呈现（在我们使用单斜杠作为布局文件声明的前缀时，`$layout='/layouts/column1'`）。为了现在完全分开和简单，让我们将我们的视图文件管理在模块的默认位置，而不是在`newtheme`主题下。此外，让我们将我们的`admin`模块应用与我们原始应用程序相同的设计，即在应用新主题之前应用的应用程序外观。这样，我们的`admin`页面将与我们的正常应用程序页面有非常不同的外观，这将帮助我们记住我们处于特殊的管理部分，但我们不必花时间设计新的外观。

### 应用布局

首先让我们为我们的模块设置一个默认布局值。我们在模块类`/protected/modules/AdminModule.php`的`init()`方法中设置模块范围的配置设置。因此，打开该文件并添加以下突出显示的代码：

```php
class AdminModule extends CWebModule
{
  public function init()
  {
    // this method is called when the module is being created
    // you may place code here to customize the module or the application

    // import the module-level models and components
    $this->setImport(array(
      'admin.models.*',
      'admin.components.*',
    ));

 **$this->layout = 'main';**

  }
```

这样，如果我们没有在更细粒度的级别上指定布局文件，比如在控制器类中，所有模块视图都将由模块默认布局目录`/protected/modules/admin/views/layouts/`中的`main.php`布局文件装饰。

现在当然，我们需要创建这个文件。从主应用程序中复制两个布局文件`/protected/views/layouts/main.php`和`/protected/views/layouts/column1.php`，并将它们都放在`/protected/modules/admin/views/layouts/`目录中。在将这些文件复制到新位置后，我们需要对它们进行一些小的更改。

首先让我们修改`column1.php`。在调用`beginContent()`时删除对`//layouts/main`的显式引用：

```php
**<?php $this->beginContent(); ?>**
<div id="content">
  <?php echo $content; ?>
</div><!-- content -->
<?php $this->endContent(); ?>
```

在调用`beginContent()`时不指定输入文件将导致它使用我们模块的默认布局，我们刚刚设置为我们新复制的`main.php`文件。

现在让我们对`main.php`布局文件进行一些更改。我们将在应用程序标题文本中添加**管理控制台**，以强调我们处于应用程序的一个独立部分。我们还将修改菜单项，添加一个链接到**管理**首页，以及一个链接返回到主站点。我们可以从菜单中删除**关于**和**联系**链接，因为我们不需要在**管理**部分重复这些选项。文件的添加如下所示：

```php
...
<div class="container" id="page">

  <div id="header">
 **<div id="logo"><?php echo CHtml::encode(Yii::app()->name) . " Admin Console"; ?></div>**
  </div><!-- header -->

  <div id="mainmenu">
    <?php $this->widget('zii.widgets.CMenu',array(
      'items'=>array(
 **array('label'=>'Back To Main Site', 'url'=>array('/project')),**
 **array('label'=>'Admin', 'url'=>array('/admin/default/index')),**
        array('label'=>'Login', 'url'=>array('/site/login'), 'visible'=>Yii::app()->user->isGuest),
        array('label'=>'Logout ('.Yii::app()->user->name.')', 'url'=>array('/site/logout'), 'visible'=>!Yii::app()->user->isGuest)
      ),
    )); ?>
  </div><!-- mainmenu -->
```

我们可以保持文件的其余部分不变。现在，如果我们访问我们的`admin`模块页面`http://localhost/trackstar/admin/default/index`，我们会看到以下截图：

应用布局

如果我们点击**返回主站点**链接，我们会看到我们被带回了主应用程序的新主题版本。

# 限制管理员访问

你可能已经注意到的一个问题是，任何人，包括访客用户，都可以访问我们的新`admin`模块。我们正在构建这个管理模块来暴露应用程序功能，这些功能只能让具有管理权限的用户访问。因此，我们需要解决这个问题。

幸运的是，我们已经在应用程序中实现了 RBAC 访问模型，在第七章中，*用户访问控制*。现在我们需要做的就是扩展它，包括一个新的管理员角色，并为该角色提供新的权限。

如果您还记得第七章中的内容，*用户访问控制*，我们使用了 Yii 的`console`命令来实现我们的 RBAC 结构。我们需要添加到其中。因此，打开包含该`console`命令的文件`/protected/commands/shell/RbacCommand.php`，并在我们创建`owner`角色的地方添加以下代码：

```php
//create a general task-level permission for admins
 $this->_authManager->createTask("adminManagement", "access to the application administration functionality");   
 //create the site admin role, and add the appropriate permissions   
$role=$this->_authManager->createRole("admin"); 
$role->addChild("owner");
$role->addChild("reader"); 
$role->addChild("member");
$role->addChild("adminManagement");
//ensure we have one admin in the system (force it to be user id #1)
$this->_authManager->assign("admin",1);
```

这将创建一个名为`adminManagement`的新任务和一个名为`admin`的新角色。然后，它将添加`owner`、`reader`和`member`角色以及`adminManagement`任务作为子级，以便`admin`角色从所有这些角色继承权限。最后，它将分配`admin`角色给我们系统中的第一个用户，以确保我们至少有一个管理员可以访问我们的管理模块。

现在我们必须重新运行命令以更新数据库的这些更改。要这样做，只需使用`rbac`命令运行`yiic`命令行工具：

```php
**% cd Webroot/trackstar/protected**
**% ./yiic rbac**

```

### 注意

随着添加了这个额外的角色，我们还应该更新在提示时显示的消息文本，以继续指示将创建第四个角色。我们将把这留给读者来练习。这些更改已经在可下载的代码文件中进行了更改，供您参考。

有了这些对我们的 RBAC 模型的更改，我们可以在`AdminModule::beforeControllerAction()`方法中添加对`admin`模块的访问检查，以便除非用户处于`admin`角色，否则不会执行`admin`模块中的任何内容：

```php
public function beforeControllerAction($controller, $action)
{
  if(parent::beforeControllerAction($controller, $action))
  {
    // this method is called before any module controller action is performed
    // you may place customized code here
 **if( !Yii::app()->user->checkAccess("admin") )**
 **{**
 **throw new CHttpException(403,Yii::t('application','You are not authorized to perform this action.'));**
 **}**
 **return true;**
  }
  else
    return false;
}
```

有了这个，如果一个尚未被分配`admin`角色的用户现在尝试访问**管理**模块中的任何页面，他们将收到一个 HTTP 403 授权错误页面。例如，如果您尚未登录并尝试访问**管理**页面，您将收到以下结果：

![限制管理员访问](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/webapp-dev-yii-php/img/8727_11_06.jpg)

对于任何尚未分配给`admin`角色的用户也是如此。

现在我们可以有条件地将**管理**部分的链接添加到我们主应用程序菜单中。这样，具有管理访问权限的用户就不必记住繁琐的 URL 来导航到**管理**控制台。提醒一下，我们的主应用程序菜单位于应用程序的主题默认应用程序布局文件`/themes/newtheme/views/layouts/main.php`中。打开该文件并将以下突出显示的代码添加到菜单部分：

```php
<div id="mainmenu">
  <?php $this->widget('zii.widgets.CMenu',array(
    'items'=>array(
      array('label'=>'Projects', 'url'=>array('/project')),
      array('label'=>'About', 'url'=>array('/site/page', 'view'=>'about')),
      array('label'=>'Contact', 'url'=>array('/site/contact')),
 **array('label'=>'Admin', 'url'=>array('/admin/default/index'), 'visible'=>Yii::app()->user->checkAccess("admin")),**
      array('label'=>'Login', 'url'=>array('/site/login'), 'visible'=>Yii::app()->user->isGuest),
      array('label'=>'Logout ('.Yii::app()->user->name.')', 'url'=>array('/site/logout'), 'visible'=>!Yii::app()->user->isGuest)
    ),
  )); ?>
</div><!-- mainmenu -->
```

现在，当以具有`admin`访问权限的用户（在我们的情况下，我们将其设置为`user id = 1`，“**用户一**”）登录到应用程序时，我们将在顶部导航中看到一个新的链接，该链接将带我们进入我们新添加的站点**管理**部分。

![限制管理员访问](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/webapp-dev-yii-php/img/8727_11_07.jpg)

# 添加系统范围的消息

**模块**可以被视为一个小型应用程序本身，向模块添加功能实际上与向主应用程序添加功能的过程相同。让我们为管理员添加一些新功能；我们将添加管理用户首次登录到应用程序时显示的系统范围消息的功能。

## 创建数据库表

通常情况下，对于全新的功能，我们需要一个地方来存储我们的数据。我们需要创建一个新表来存储我们的系统范围消息。对于我们的示例，我们可以保持这个非常简单。这是我们表的定义：

```php
CREATE TABLE `tbl_sys_message` 
( 
  `id` INTEGER NOT NULL PRIMARY KEY AUTO_INCREMENT,
  `message` TEXT NOT NULL, 
  `create_time` DATETIME,
  `create_user_id` INTEGER,
  `update_time` DATETIME,
  `update_user_id` INTEGER  
) 
```

当然，当添加这个新表时，我们将创建一个新的数据库迁移来管理我们的更改。

```php
**% cd Webroot/trackstar/protected**
**% ./yiic migrate create_system_messages_table**

```

这些命令在`protected/migrations/`目录下创建一个新的迁移文件。这个文件的内容可以从可下载的代码或可在[`gist.github.com/3785282`](https://gist.github.com/3785282)上找到的独立代码片段中获取。（我们没有包括类名；请记住，您的文件名和相应的类将具有不同的时间戳前缀。）

一旦这个文件就位，我们就可以运行我们的迁移来添加这个新表：

```php
**% cd Webroot/trackstar/protected**
**% ./yiic migrate**

```

## 创建我们的模型和 CRUD 脚手架

现在我们已经创建了表，下一步是使用我们喜爱的工具 Gii 代码生成器生成`model`类。我们将首先使用**Model Generator**选项创建`model`类，然后使用**Crud Generator**选项创建基本的脚手架，以便快速与这个模型进行交互。前往 Gii 工具表单以创建新的模型(`http://localhost/trackstar/gii/model`)。这一次，由于我们是在模块的上下文中进行操作，我们需要明确指定模型路径。填写表单中的值，如下面截图所示（当然，你的**Code Template**路径值应该根据你的本地设置具体而定）：

![创建我们的模型和 CRUD 脚手架](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/webapp-dev-yii-php/img/8727_11_08.jpg)

注意，我们将**Model Path**文本框更改为`application.modules.admin.models`。点击**Generate**按钮生成**Model Class**值。

现在我们可以以类似的方式创建 CRUD 脚手架。我们之前所做的和现在要做的唯一真正的区别是我们要指定`model`类的位置在`admin`模块中。从 Gii 工具中选择**Crud Generator**选项后，填写**Model Class**和**Controller ID**表单字段，如下截图所示：

![创建我们的模型和 CRUD 脚手架](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/webapp-dev-yii-php/img/8727_11_09.jpg)

这告诉工具我们的`model`类在`admin`模块下，我们的控制器类以及与此代码生成相关的所有其他文件也应该放在`admin`模块中。

首先点击**Preview**按钮，然后点击**Generate**完成创建。下面的截图显示了此操作创建的所有文件列表：

![创建我们的模型和 CRUD 脚手架](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/webapp-dev-yii-php/img/8727_11_10.jpg)

## 添加到我们新功能的链接

让我们在主`admin`模块导航中添加一个新的菜单项，链接到我们新创建的消息功能。打开包含我们模块主菜单导航的文件`/protected/modules/admin/views/layouts/main.php`，并向菜单小部件添加以下`array`项：

```php
array('label'=>'System Messages', 'url'=>array('/admin/sysMessage/idex')),
```

如果我们在`http://localhost/trackstar/admin/sysMessage/create`查看新的系统消息，我们会看到以下内容：

![添加到我们新功能的链接](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/webapp-dev-yii-php/img/8727_11_11.jpg)

我们新系统消息功能的自动生成控制器和视图文件是使用主应用程序的两列布局文件创建的。如果你查看`SysMessageController.php`类文件，你会看到布局定义如下：

```php
public $layout='//layouts/column2';
```

注意前面的双斜杠。所以我们可以看到我们新添加的 admin 功能没有使用我们`admin`模块的布局文件。我们可以修改`controller`类以使用我们现有的单列布局文件，或者我们可以在我们的模块布局文件中添加一个两列布局文件。后者会稍微容易一些，而且看起来也更好，因为所有的视图文件都被创建为在第二个右侧列中显示它们的子菜单项（即链接到所有 CRUD 功能）。我们还需要修改我们新创建的模型类和相应的表单，以删除一些不需要的表单字段。以下是我们需要做的全部内容：

1.  将主应用程序中的两列布局复制到我们的模块中，即将`/protected/views/layouts/column2.php`复制到`/protected/modules/admin/views/layouts/column2.php`。

1.  在新复制的`column2.php`文件的第一行，将`//layouts/main`作为`beginContent()`方法调用的输入删除。

1.  修改`SysMessage`模型类以扩展`TrackstarActiveRecord`。（如果你记得的话，这会自动更新我们的`create_time/user`和`update_time/user`属性。）

1.  修改`SysMessageController`控制器类，以使用模块目录中的新`column2.php`布局文件，而不是主应用程序中的文件。自动生成的代码已经指定了`$layout='//layouts/column2'`，但我们需要将其简单地改为`$layout='/layouts/column2'`。

1.  由于我们正在扩展`TrackstarActiveRecord`，我们可以从自动生成的 sys-messages 创建表单中删除不必要的字段，并从模型类中删除它们的相关规则。例如，从`modules/admin/views/sysMessage/_form.php`中删除以下表单字段：

```php
<div class="row">
    <?php echo $form->labelEx($model,'create_time'); ?>
    <?php echo $form->textField($model,'create_time'); ?>
    <?php echo $form->error($model,'create_time'); ?>
  </div>

  <div class="row">
    <?php echo $form->labelEx($model,'create_user_id'); ?>
    <?php echo $form->textField($model,'create_user_id'); ?>
    <?php echo $form->error($model,'create_user_id'); ?>
  </div>

  <div class="row">
    <?php echo $form->labelEx($model,'update_time'); ?>
    <?php echo $form->textField($model,'update_time'); ?>
    <?php echo $form->error($model,'update_time'); ?>
  </div>

  <div class="row">
    <?php echo $form->labelEx($model,'update_user_id'); ?>
    <?php echo $form->textField($model,'update_user_id'); ?>
    <?php echo $form->error($model,'update_user_id'); ?>
  </div> 
```

1.  然后从`SysMessage::rules()`方法中更改这两条规则：

```php
array('create_user, update_user', 'numerical', 'integerOnly'=>true), and array('create_time, update_time', 'safe'),
```

重要的是只为用户可以输入的那些字段指定规则。对于已定义规则的字段，可以从`POST`或`GET`请求中以批量方式设置，并且保留不希望用户访问的字段的规则可能会导致安全问题。

我们应该做的最后一次更改是更新我们简单的访问规则，以反映只有`admin`角色的用户才能访问我们的操作方法的要求。这主要是为了说明目的，因为我们已经在`AdminModule::beforeControlerAction`方法中使用我们的 RBAC 模型方法处理了访问。实际上，我们可以完全删除`accessRules()`方法。但是，让我们更新它们以反映要求，以便您可以看到使用访问规则方法将如何工作。在`SysMessageController::accessRules()`方法中，将整个内容更改为以下内容：

```php
public function accessRules()
{
  return array(
    array('allow',  // allow only users in the 'admin' role access to our actions
      'actions'=>array('index','view', 'create', 'update', 'admin', 'delete'),
      'roles'=>array('admin'),
    ),
    array('deny',  // deny all users
      'users'=>array('*'),
    ),
  );
}
```

好的，有了所有这些，现在如果我们访问`http://localhost/trackstar/admin/sysMessage/create`来访问我们的新消息输入表单，我们将看到类似以下截图的内容：

![添加到我们的新功能的链接](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/webapp-dev-yii-php/img/8727_11_12.jpg)

填写此表单，消息为`Hello Users! This is your admin speaking...`，然后单击**Create**。应用程序将重定向您到这条新创建消息的详细列表页面，如下截图所示：

![添加到我们的新功能的链接](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/webapp-dev-yii-php/img/8727_11_13.jpg)

## 向用户显示消息

现在我们的系统中有一条消息，让我们在应用程序主页上向用户显示它。

### 导入新的模型类以进行应用程序范围的访问

为了从应用程序的任何地方访问新创建的模型，我们需要将其作为应用程序配置的一部分导入。修改`protected/config/main.php`以包括新的`admin module models`文件夹：

```php
// autoloading model and component classes
'import'=>array(
  'application.models.*',
  'application.components.*',
 **'application.modules.admin.models.*',**
),
```

### 选择最近更新的消息

我们将限制显示只有一条消息，并且我们将根据表中的`update_time`列选择最近更新的消息。由于我们想要将其添加到主项目列表页面，我们需要修改`ProjectController::actionIndex()`方法。通过添加以下突出显示的代码来修改该方法：

```php
public function actionIndex()
  {
      $dataProvider=new CActiveDataProvider('Project');

      Yii::app()->clientScript->registerLinkTag(
          'alternate',
          'application/rss+xml',
          $this->createUrl('comment/feed'));

 **//get the latest system message to display based on the update_time column**
 **$sysMessage = SysMessage::model()->find(array(**
 **'order'=>'t.update_time DESC',**
 **));**
 **if($sysMessage !== null)**
 **$message = $sysMessage->message;**
 **else**
 **$message = null;**

      $this->render('index',array(
        'dataProvider'=>$dataProvider,
 **'sysMessage'=>$message,**
      ));
  }
```

现在我们需要修改我们的视图文件来显示这个新的内容。将以下代码添加到`views/project/index.php`，就在`<h1>Projects</h1>`标题文本上方：

```php
<?php if($sysMessage !== null):?>
    <div class="sys-message">
        <?php echo $sysMessage; ?>
    </div>
<?php endif; ?>
```

现在当我们访问我们的项目列表页面（即我们应用程序的主页）时，我们可以看到它显示如下截图所示：

![选择最近更新的消息](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/webapp-dev-yii-php/img/8727_11_14.jpg)

### 添加一点设计调整

好的，这做到了我们想要的，但是这条消息对用户来说并不是很突出。让我们通过向我们的主 CSS 文件(`/themes/newtheme/css/main.css`)添加一小段代码来改变这一点：

```php
div.sys-message
{
  padding:.8em;
  margin-bottom:1em;
  border:3px solid #ddd;
  background:#9EEFFF;
  color:#FF330A;
  border-color:#00849E;
}
```

有了这个，我们的消息现在在页面上真的很突出。以下截图显示了具有这些更改的消息：

![添加一点设计调整](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/webapp-dev-yii-php/img/8727_11_15.jpg)

有人可能会认为这个设计调整有点过分。用户可能会因为不得不整天盯着这些消息颜色而感到头疼。与其淡化颜色，不如使用一点 JavaScript 在 5 秒后淡出消息。由于我们将在用户访问这个**主页**时每次显示消息，防止他们盯着它太久可能会更好。

我们将简化操作，并利用 Yii 随附的强大 JavaScript 框架 jQuery。**jQuery**是一个开源的 JavaScript 库，简化了 HTML **文档对象模型**（**DOM**）和 JavaScript 之间的交互。深入了解 jQuery 的细节超出了本书的范围。值得访问其文档以更加了解其特性。由于 Yii 随附了 jQuery，您可以在视图文件中简单地注册 jQuery 代码，Yii 将为您包含核心 jQuery 库。

我们还将使用应用程序助手组件`CClientScript`来为我们在生成的网页中注册 jQuery JavaScript 代码。它将确保它已被放置在适当的位置，并已被正确标记和格式化。

因此，让我们修改之前添加的内容，包括一个 JavaScript 片段来淡出消息。用以下内容替换我们刚刚添加到`views/project/index.php`的内容：

```php
<?php if($sysMessage != null):?>
    <div class="sys-message">
        <?php echo $sysMessage; ?>
    </div>
<?php
  Yii::app()->clientScript->registerScript(
     'fadeAndHideEffect',
     '$(".sys-message").animate({opacity: 1.0}, 5000).fadeOut("slow");'
  );
endif; ?>
```

现在，如果我们重新加载主项目列表页面，我们会看到消息在 5 秒后淡出。有关您可以轻松添加到页面的酷炫 jQuery 效果的更多信息，请查看[`api.jquery.com/category/effects/`](http://api.jquery.com/category/effects/)上提供的 JQuery API 文档。

最后，为了确信一切都按预期工作，您可以添加另一条系统范围的消息。由于这条更新时间更近的消息将显示在项目列表页面上。

# 总结

在本章中，我们介绍了 Yii 模块的概念，并通过使用一个模块来创建站点的管理部分来演示了它的实用性。我们演示了如何创建一个新模块，如何更改模块的布局和主题，如何在模块内添加应用程序功能，甚至如何利用现有的 RBAC 模型，将授权访问控制应用于模块内的功能。我们还演示了如何使用 jQuery 为我们的应用程序增添一些 UI 效果。

通过添加这个管理界面，我们现在已经把应用程序的所有主要部分都放在了适当的位置。虽然应用程序非常简单，但我们觉得现在是时候为其准备投入生产了。下一章将重点介绍如何为我们的应用程序准备生产部署。


# 第十二章：投产准备

尽管我们的应用程序缺乏大量的功能功能，我们（虽然是想象中的）截止日期正在临近，我们（同样是想象中的）客户对将应用程序投入生产环境感到焦虑。尽管我们的应用程序在生产中真正见到天日可能还需要一些时间，但现在是时候让应用程序“准备投产”了。在我们的最后一个开发章节中，我们将做到这一点。

# 功能规划

为了实现我们的应用程序为生产环境做好准备的目标，我们将专注于以下细粒度的任务：

+   实现 Yii 的应用程序日志记录框架，以确保我们记录关于关键生产错误和事件的信息

+   实现 Yii 的应用程序错误处理框架，以确保我们在生产中正确处理错误，并了解这在生产环境和开发环境中的工作方式有所不同

+   实现应用程序数据缓存以帮助提高性能

# 日志记录

日志记录是一个在应用程序开发的这个后期阶段应该被讨论的话题。在软件应用程序的故障排除中，信息、警告和严重错误消息是非常宝贵的，尤其是对于那些在生产环境中由真实用户使用的应用程序。

作为开发人员，我们都熟悉这个故事。您已经满足了您正在构建的应用程序的所有功能要求。所有单元和功能测试都通过了。应用程序已经通过了 QA 的批准，每个人都对它准备投产感到很满意。但是一旦它投入使用，并且承受着真实用户的真实生产负载，它的行为就会出乎意料。一个良好的日志记录策略可能会成为快速解决问题和回滚数周甚至数月的辛苦工作之间的区别。

Yii 提供了灵活和可扩展的日志记录功能。记录的数据可以根据日志级别和消息类别进行分类。使用级别和类别过滤器，日志消息可以进一步路由到不同的目的地，例如写入磁盘上的文件，存储在数据库中，发送给管理员作为电子邮件，或在浏览器窗口中显示。

## 消息记录

我们的应用程序实际上一直在每个请求时记录许多信息消息。当初始应用程序被创建时，它被配置为处于*调试*模式，而在此模式下，Yii 框架本身会记录信息消息。我们实际上看不到这些消息，因为默认情况下它们被记录到内存中。因此，它们只在请求的生命周期内存在。

应用程序是否处于调试模式由根目录`index.php`文件中的以下行控制：

```php
defined('YII_DEBUG') or define('YII_DEBUG',true);
```

为了查看被记录的内容，让我们在我们的`SiteController`类中快速创建一个动作方法来显示这些消息：

```php
public function actionShowLog()
{
  echo "Logged Messages:<br><br>";
CVarDumper::dump(Yii::getLogger()->getLogs());
}
```

在这里，我们使用 Yii 的`CVarDumper`辅助类，这是`var_dump`或`print_r`的改进版本，因为它能够正确处理递归引用对象。

如果我们通过发出请求`http://localhost/trackstar/site/showLog`来调用此动作，我们会看到类似以下截图的内容：

![消息记录](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/webapp-dev-yii-php/img/8727_12_01.jpg)

如果我们注释掉在`index.php`中定义的全局应用程序调试变量，并刷新页面，我们会注意到一个空数组；也就是说，没有记录任何内容。这是因为这种系统级别的调试信息级别的日志记录是通过调用`Yii::trace`来实现的，只有在应用程序处于特殊的调试模式时才会记录这些消息。

我们可以使用两种静态应用程序方法之一在 Yii 应用程序中记录消息：

+   `Yii::log($message, $level, $category);`

+   `Yii::trace($message, $category);`

正如前面提到的，这两种方法之间的主要区别在于`Yii::trace`仅在应用程序处于调试模式时记录消息。

### 类别和级别

在使用`Yii::log()`记录消息时，我们需要指定它的类别和级别。**类别**是一个字符串，用于为被记录的消息提供额外的上下文。这个字符串可以是任何你喜欢的，但许多人使用的约定是一个格式为`xxx.yyy.zzz`的字符串，类似于路径别名。例如，如果在我们的应用程序的`SiteController`类中记录了一条消息，我们可以选择使用类别`application.controllers.SiteController`。

除了指定类别，使用`Yii::log`时，我们还可以指定消息的级别。级别可以被认为是消息的严重程度。您可以定义自己的级别，但通常它们具有以下值之一：

+   **跟踪**：这个级别通常用于跟踪应用程序在开发过程中的执行流程。

+   **信息**：这是用于记录一般信息。如果没有指定级别，则这是默认级别。

+   **概要**：这是用于性能概要功能，稍后在本章中描述。

+   **警告**：这是用于警告消息。

+   **错误**：这是用于致命错误消息。

### 添加登录消息日志

例如，让我们向我们的用户登录方法添加一些日志记录。我们将在方法开始时提供一些基本的调试信息，以指示方法正在执行。然后，我们将在成功登录时记录一条信息，以及在登录失败时记录一条警告信息。根据以下突出显示的代码修改我们的`SiteController::actionLogin()`方法（整个方法在可下载的代码中已经存在，或者您可以从[`gist.github.com/3791860`](https://gist.github.com/3791860)下载独立的方法）。

```php
public function actionLogin()
{
 **Yii::trace("The actionLogin() method is being requested", "application.controllers.SiteController");**
    …

    // collect user input data
    if(isset($_POST['LoginForm']))
    {
      …  
if($model->validate() && $model->login()) 
      {
 **Yii::log("Successful login of user: " . Yii::app()->user->id, "info", "application.controllers.SiteController");**
        $this->redirect(Yii::app()->user->returnUrl);
 **}**
 **else**
 **{**
 **Yii::log("Failed login attempt", "warning", "application.controllers.SiteController");**
 **}**

    }
    …
}
```

如果我们现在成功登录（或进行了失败的尝试）并访问我们的页面查看日志，我们看不到它们（如果您注释掉了调试模式声明，请确保您已经将应用程序重新放回调试模式进行此练习）。同样，原因是，默认情况下，Yii 中的日志实现只是将消息存储在内存中。它们在请求完成时消失。这并不是非常有用。我们需要将它们路由到一个更持久的存储区域，这样我们就可以在生成它们的请求之外查看它们。

## 消息路由

正如我们之前提到的，默认情况下，使用`Yii::log`或`Yii::trace`记录的消息被保存在内存中。通常，如果这些消息在浏览器窗口中显示，保存到一些持久存储（如文件中），在数据库中，或作为电子邮件发送，它们会更有用。Yii 的*消息路由*允许将日志消息路由到不同的目的地。

在 Yii 中，消息路由由`CLogRouter`应用组件管理。它允许您定义日志消息应路由到的目的地列表。

为了利用这个消息路由，我们需要在`protected/config/main.php`配置文件中配置`CLogRouter`应用组件。我们通过设置它的 routes 属性与所需的日志消息目的地进行配置。

如果我们打开主配置文件，我们会看到一些配置已经提供（再次感谢使用`yiic webapp`命令最初创建我们的应用程序）。以下内容已在我们的配置中定义：

```php
'log'=>array
  'class'=>'CLogRouter',
  'routes'=>array(
    array(
      'class'=>'CFileLogRoute',
      'levels'=>'error, warning',
    ),
    // uncomment the following to show log messages on web pages
    /*
    array(
      'class'=>'CWebLogRoute',
    ),
    */
  ),
),
```

`log`应用组件配置为使用框架类`CLogRouter`。当然，如果您有日志要求没有完全满足基础框架实现，您也可以创建和使用自定义子类；但在我们的情况下，这将工作得很好。

在先前配置中类定义之后的是`routes`属性的定义。在这种情况下，只指定了一个路由。这个路由使用了 Yii 框架的消息路由类`CFileLogRoute`。`CFileLogRoute`消息路由类使用文件系统保存消息。默认情况下，消息被记录在应用运行时目录下的一个文件中，即`/protected/runtime/application.log`。实际上，如果您一直在跟着我们并且有自己的应用程序，您可以查看这个文件，会看到框架记录的几条消息。`levels`规定只有日志级别为`error`或`warning`的消息才会被路由到这个文件。在先前代码中被注释掉的部分指定了另一个路由`CWebLogRoute`。如果使用，这将把消息路由到当前请求的网页上。以下是 Yii 1.1 版本当前可用的消息路由列表：

+   `CDbLogRoute`：将消息保存在数据库表中

+   `CEmailLogRoute`：将消息发送到指定的电子邮件地址

+   `CFileLogRoute`：将消息保存在应用程序的`runtime`目录下的文件中，或者您选择的任何其他目录中

+   `CWebLogRoute`：在当前网页末尾显示消息

+   `CProfileLogRoute`：在当前网页末尾显示分析消息

我们在`SiteController::actionLogin()`方法中添加的日志记录使用了`Yii::trace`来记录一条消息，然后使用`Yii::log`来记录另外两条消息。使用`Yii::trace`时，日志级别会自动设置为`trace`。当使用`Yii::log`时，如果登录成功，我们指定为`info`日志级别，但如果登录尝试失败，则为`warning`级别。让我们修改日志路由配置，将`trace`和`info`级别的消息写入到一个新的、单独的文件`infoMessages.log`中，该文件与我们的`application.log`文件在同一目录中。另外，让我们配置它将警告消息写入到浏览器。为此，我们将对配置进行以下更改（已突出显示）：

```php
'log'=>array(
  'class'=>'CLogRouter',
  'routes'=>array(
    array(
      'class'=>'CFileLogRoute',
 **'levels'=>'error',**
 **),**
 **array(**
 **'class'=>'CFileLogRoute',**
 **'levels'=>'info, trace',**
 **'logFile'=>'infoMessages.log',**
 **),**
 **array(**
 **'class'=>'CWebLogRoute',**
 **'levels'=>'warning',**
 **),**

```

现在，在保存这些更改后，让我们尝试不同的场景。首先，尝试成功的登录。这样做将把我们的两条登录消息写入到我们的新的`/protected/runtime/infoMessages.log`文件中，一条是 trace，另一条是记录成功登录。成功登录后，查看该文件会显示以下内容（完整列表被截断以节省一些树木）：

```php
.....
**2012/06/15 00:31:52 [trace] [application.controllers.SiteController] The actionLogin() method is being requested**
2012/06/15 00:31:52 [trace] [system.web.CModule] Loading "user" application component
2012/06/15 00:31:52 [trace] [system.web.CModule] Loading "session" application component
2012/06/15 00:31:52 [trace] [system.web.CModule] Loading "db"                                                                                                                                                                                                                                                                                                                                                                                                                             application component
2012/06/15 00:31:52 [trace] [system.db.CDbConnection] Opening DB connection
.....
**2012/06/15 00:31:52 [info] [application.controllers.SiteController] Successful login of user: 1**
.....
```

如您所见，其中有很多内容，不仅仅是我们的两条消息！但我们的两条确实显示出来了；它们在先前的列表中是加粗的。现在我们将所有的 trace 消息路由到这个新文件中，所有框架的 trace 消息也会显示在这里。这实际上非常有信息量，真的有助于您了解请求在框架中的生命周期。在幕后有很多事情发生。当将此应用程序移至生产环境时，我们显然会关闭这种冗长的日志记录。在非调试模式下，我们只会看到我们的单个`info`级别消息。但在追踪错误和弄清楚应用程序在做什么时，这种详细级别的信息非常有用。知道它在需要时/如果需要时存在是非常令人安心的。

现在让我们尝试失败的登录尝试场景。如果我们现在注销并再次尝试登录，但这次指定不正确的凭据以强制登录失败，我们会看到我们的**警告**级别显示在返回的网页底部，就像我们配置的那样。以下屏幕截图显示了显示此警告：

![消息路由](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/webapp-dev-yii-php/img/8727_12_02.jpg)

使用`CFileLogRouter`消息路由器时，日志文件存储在`logPath`属性下，并且文件名由`logFile`方法指定。这个日志路由器的另一个很棒的功能是自动日志文件轮换。如果日志文件的大小大于`maxFileSize`属性中设置的值（以千字节为单位），则会执行轮换，将当前日志文件重命名为带有`.1`后缀的文件。所有现有的日志文件都向后移动一个位置，即`.2`到`.3`，`.1`到`.2`。属性`maxLogFiles`可用于指定要保留多少个文件。

### 注意

如果在应用程序中使用`die;`或`exit;`来终止执行，日志消息可能无法正确写入其预期的目的地。如果需要显式终止 Yii 应用程序的执行，请使用`Yii::app()->end()`。这提供了应用程序成功写出日志消息的机会。此外，`CLogger`组件具有一个`$autoDump`属性，如果设置为`true`，将允许实时将日志消息写入其目的地（即在调用`->log()`时）。由于潜在的性能影响，这应仅用于调试目的，但可以是一个非常有价值的调试选项。

# 处理错误

正确处理软件应用程序中不可避免发生的错误非常重要。这又是一个话题，可以说应该在编写应用程序之前就已经涵盖了，而不是在这个晚期阶段。幸运的是，由于我们一直在依赖 Yii 框架内的工具来自动生成我们的核心应用程序骨架，我们的应用程序已经在利用 Yii 的一些错误处理功能。

Yii 提供了一个基于 PHP 5 异常的完整错误处理框架，这是通过集中的点处理程序中的异常情况的内置机制。当主 Yii 应用程序组件被创建来处理传入的用户请求时，它会注册其`CApplication::handleError()`方法来处理 PHP 警告和通知，并注册其`CApplication::handleException()`方法来处理未捕获的 PHP 异常。因此，如果在应用程序执行期间发生 PHP 警告/通知或未捕获的异常，其中一个错误处理程序将接管控制并启动必要的错误处理过程。

### 注意

错误处理程序的注册是在应用程序的构造函数中通过调用 PHP 函数`set_exception_handler`和`set_error_handler`来完成的。如果您不希望 Yii 处理这些类型的错误和异常，可以通过在主`index.php`入口脚本中将全局常量`YII_ENABLE_ERROR_HANDLER`和`YII_ENABLE_EXCEPTION_HANDLER`定义为 false 来覆盖此默认行为。

默认情况下，应用程序将使用框架类`CErrorHandler`作为负责处理 PHP 错误和未捕获异常的应用程序组件。这个内置应用程序组件的任务之一是使用适当的视图文件显示这些错误，这取决于应用程序是在*调试*模式还是*生产*模式下运行。这允许您为这些不同的环境自定义错误消息。在开发环境中显示更详细的错误信息以帮助解决问题是有意义的。但允许生产应用程序的用户查看相同的信息可能会影响安全性。此外，如果您在多种语言中实现了您的站点，`CErrorHandler`还会选择用于显示错误的首选语言。

在 Yii 中，您引发异常的方式与通常引发 PHP 异常的方式相同。在需要时，可以使用以下一般语法引发异常：

```php
throw new ExceptionClass('ExceptionMessage');
```

Yii 提供的两个异常类是：

+   `CException`

+   `CHttpException`

`CException`是一个通用的异常类。`CHttpException`表示一个 HTTP 错误，并且还携带一个`statusCode`属性来表示 HTTP 状态码。在浏览器中，错误的显示方式取决于抛出的异常类。

## 显示错误

正如之前提到的，当`CErrorHandler`应用组件处理错误时，它会决定在显示错误时使用哪个视图文件。如果错误是要显示给最终用户的，就像使用`CHttpException`时一样，其默认行为是使用一个名为`errorXXX`的视图，其中`XXX`代表 HTTP 状态码（例如，400、404 或 500）。如果错误是内部错误，只应显示给开发人员，它将使用一个名为`Exception`的视图。当应用程序处于调试模式时，将显示完整的调用堆栈以及源文件中的错误行。

然而，当应用程序运行在生产模式下时，所有错误都将使用`errorXXX`视图文件显示。这是因为错误的调用堆栈可能包含不应该显示给任何最终用户的敏感信息。 

当应用程序处于生产模式时，开发人员应依靠错误日志提供有关错误的更多信息。当发生错误时，错误级别的消息将始终被记录。如果错误是由 PHP 警告或通知引起的，消息将被记录为`php`类别。如果错误是由未捕获的`exception`引起的，类别将是`exception.ExceptionClassName`，其中异常类名是`CHttpException`或`CException`的一个或子类。因此，可以利用前一节讨论的日志记录功能来监视生产应用程序中发生的错误。当然，如果发生致命的 PHP 错误，您仍然需要检查由 PHP 配置设置定义的错误日志，而不是 Yii 的错误日志。

默认情况下，`CErrorHandler`按以下顺序搜索相应视图文件的位置：

+   `WebRoot/themes/ThemeName/views/system`：当前活动主题下的系统视图目录

+   `WebRoot/protected/views/system`：应用程序的默认系统视图目录

+   `YiiRoot/framework/views`：Yii 框架提供的标准系统视图目录

您可以通过在应用程序或主题的系统视图目录下创建自定义错误视图文件来自定义错误显示。

Yii 还允许您定义一个特定的控制器动作方法来处理错误的显示。这实际上是我们的应用程序配置的方式。当我们通过一些示例时，我们会看到这一点。

我们使用 Gii Crud Generator 工具创建 CRUD 脚手架时为我们生成的一些代码已经利用了 Yii 的错误处理。其中一个例子是`ProjectController::loadModel()`方法。该方法定义如下：

```php
public function loadModel($id)
  {
    $model=Project::model()->findByPk($id);
    if($model===null)
      throw new CHttpException(404,'The requested page does not exist.');
    return $model;
  }
```

我们看到它正在尝试基于输入的`id`查询字符串参数加载相应的项目模型 AR 实例。如果它无法定位请求的项目，它会抛出一个`CHttpException`，以通知用户他们请求的页面（在本例中是项目详细信息页面）不存在。我们可以通过明确请求我们知道不存在的项目来在浏览器中测试这一点。由于我们知道我们的应用程序没有与`id`为`99`相关联的项目，因此请求`http://localhost/trackstar/project/view/id/99`将导致返回以下页面：

![显示错误](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/webapp-dev-yii-php/img/8727_12_03.jpg)

这很好，因为页面看起来像我们应用程序中的任何其他页面，具有相同的主题、页眉、页脚等。

实际上，这不是呈现此类型错误页面的默认行为。 我们的初始应用程序配置为使用特定的控制器操作来处理此类错误。 我们提到这是处理应用程序中错误的另一种选项。 如果我们查看主配置文件`/protected/config/main.php`，我们会看到以下应用程序组件声明：

```php
'errorHandler'=>array(
  // use 'site/error' action to display errors
    'errorAction'=>'site/error',
),
```

这配置了我们的错误处理程序应用组件使用`SiteController::actionError()`方法来处理所有打算显示给用户的异常。 如果我们查看该操作方法，我们会注意到它正在呈现`protected/views/site/error.php`视图文件。 这只是一个普通的控制器视图文件，因此它还将呈现任何相关的应用程序布局文件，并将应用适当的主题。 通过这种方式，我们能够在发生某些错误时为用户提供非常友好的体验。

要查看默认行为是什么，而不添加此配置，请暂时注释掉先前的配置代码行（在`protected/config/main.php`中），然后再次请求不存在的项目。 现在我们看到以下页面：

![显示错误](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/webapp-dev-yii-php/img/8727_12_04.jpg)

由于我们没有明确定义任何遵循先前概述的自定义错误页面，这是 Yii 框架本身的`framework/views/error404.php`文件。

继续并恢复对配置文件的更改，以再次使用`SiteController::actionError()`方法进行错误处理。

现在让我们看看这与抛出`CException`类相比如何。 让我们注释掉当前抛出 HTTP 异常的代码行，并添加一个新行来抛出这个其他异常类。 对`protected/controllers/ProjectController.php`文件进行突出显示的更改：

```php
public function loadModel($id)
  {
    $model=Project::model()->findByPk($id);
    if($model===null)
 **//throw new CHttpException(404,'The requested page does not exist.');**
 **throw new CException('This is an example of throwing a CException');**
    return $model;
  }
```

现在，如果我们请求一个不存在的项目，我们会看到一个非常不同的结果。 这次我们看到一个由系统生成的错误页面，其中包含完整的堆栈跟踪错误信息转储，以及发生错误的特定源文件：

![显示错误](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/webapp-dev-yii-php/img/8727_12_05.jpg)

它显示了抛出`CException`类的事实，以及描述**这是抛出 CException 的示例**，源文件，发生错误的文件中的特定行，然后是完整的堆栈跟踪。

因此，抛出这个不同的异常类，以及应用程序处于调试模式的事实，会产生不同的结果。 这是我们希望显示以帮助排除问题的信息类型，但前提是我们的应用程序在私人开发环境中运行。 让我们暂时注释掉根`index.php`文件中的调试设置，以查看在“生产”模式下如何显示：

```php
// remove the following line when in production mode
//defined('YII_DEBUG') or define('YII_DEBUG',true);
```

如果我们刷新对不存在的项目的请求，我们会看到异常显示为面向最终用户友好的 HTTP 500 错误，如下截图所示：

![显示错误](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/webapp-dev-yii-php/img/8727_12_06.jpg)

因此，我们看到在“生产”模式下不会显示任何敏感代码或堆栈跟踪信息。

# 缓存

**缓存**数据是帮助提高生产 Web 应用程序性能的一种很好的方法。 如果有特定内容不希望在每个请求时都更改，那么使用缓存来存储和提供此内容可以减少检索和处理数据所需的时间。

Yii 在缓存方面提供了一些不错的功能。 要利用 Yii 的缓存功能，您首先需要配置一个缓存应用程序组件。 这样的组件是几个子类之一，它们扩展了`CCache`，这是具有不同缓存存储实现的缓存类的基类。

Yii 提供了许多特定的缓存组件类实现，利用不同的方法存储数据。以下是 Yii 在版本 1.1.12 中提供的当前缓存实现的列表：

+   `CMemCache`：使用 PHP memcache 扩展。

+   `CApcCache`：使用 PHP APC 扩展。

+   `CXCache`：使用 PHP XCache 扩展。

+   `CEAcceleratorCache`：使用 PHP EAccelerator 扩展。

+   `CDbCache`：使用数据库表存储缓存数据。默认情况下，它将在运行时目录下创建并使用 SQLite3 数据库。您可以通过设置其`connectionID`属性来显式指定要使用的数据库。

+   `CZendDataCache`：使用 Zend Data Cache 作为底层缓存介质。

+   `CFileCache`：使用文件存储缓存数据。这对于缓存大量数据（如页面）特别合适。

+   `CDummyCache`：提供一致的缓存接口，但实际上不执行任何缓存。这种实现的原因是，如果您面临开发环境不支持缓存的情况，您仍然可以执行和测试需要在可用时使用缓存的代码。这使您可以继续编写一致的接口代码，并且当实际实现真正的缓存组件时，您将不需要更改编写用于写入或检索缓存中的数据的代码。

+   `CWinCache`：`CWinCache`基于 WinCache 实现了一个缓存应用程序组件。有关更多信息，请访问[`www.iis.net/expand/wincacheforphp`](http://www.iis.net/expand/wincacheforphp)。

所有这些组件都是从同一个基类`CCache`继承，并公开一致的 API。这意味着您可以更改应用程序组件的实现，以使用不同的缓存策略，而无需更改任何使用缓存的代码。

## 缓存配置

正如前面提到的，Yii 中使用缓存通常涉及选择其中一种实现，然后在`/protected/config/main.php`文件中配置应用程序组件以供使用。配置的具体内容当然取决于具体的缓存实现。例如，如果要使用 memcached 实现，即`CMemCache`，这是一个分布式内存对象缓存系统，允许您指定多个主机服务器作为缓存服务器，配置它使用两个服务器可能如下所示：

```php
array(
    ......
    'components'=>array(
        ......
        'cache'=>array(
            'class'=>'system.caching.CMemCache',
            'servers'=>array(
                array('host'=>'server1', 'port'=>12345, 'weight'=>60),
                array('host'=>'server2', 'port'=>12345, 'weight'=>40),
            ),
        ),
    ),
);
```

为了让读者在跟踪 Star 开发过程中保持相对简单，我们将在一些示例中使用文件系统实现`CFileCache`。这应该在任何允许从文件系统读取和写入文件的开发环境中都是 readily available。

### 注意

如果由于某种原因这对您来说不是一个选项，但您仍然想要跟随代码示例，只需使用`CDummyCache`选项。正如前面提到的，它实际上不会在缓存中存储任何数据，但您仍然可以根据其 API 编写代码，并在以后更改实现。

`CFileCache`提供了基于文件的缓存机制。使用这种实现时，每个被缓存的数据值都存储在一个单独的文件中。默认情况下，这些文件存储在`protected/runtime/cache/`目录下，但可以通过在配置组件时设置`cachePath`属性来轻松更改这一点。对于我们的目的，这个默认值是可以的，所以我们只需要在`/protected/config/main.php`配置文件的`components`数组中添加以下内容，如下所示：

```php
// application components
  'components'=>array(
    …
 **'cache'=>array(**
 **'class'=>'system.caching.CFileCache',**
 **),**
     …  
),
```

有了这个配置，我们可以在运行的应用程序中的任何地方通过`Yii::app()->cache`访问这个新的应用程序组件。

## 使用基于文件的缓存

让我们尝试一下这个新组件。还记得我们在上一章作为管理功能的一部分添加的系统消息吗？我们不必在每次请求时从数据库中检索它，而是将最初从数据库返回的值存储在我们的缓存中，以便有限的时间内不必从数据库中检索数据。

让我们向我们的`SysMessage`（`/protected/modules/admin/models/SysMessage.php`）AR 模型类添加一个新的公共方法来处理最新系统消息的检索。让我们将这个新方法同时设置为`public`和`static`，以便应用程序的其他部分可以轻松使用这个方法来访问最新的系统消息，而不必显式地创建`SysMessage`的实例。

将我们的方法添加到`SysMessage`类中，如下所示：

```php
/**
   * Retrieves the most recent system message.
   * @return SysMessage the AR instance representing the latest system message.
   */

public static function getLatest()
{

  //see if it is in the cache, if so, just return it
  if( ($cache=Yii::app()->cache)!==null)
  {
    $key='TrackStar.ProjectListing.SystemMessage';
    if(($sysMessage=$cache->get($key))!==false)
      return $sysMessage;
  }
  //The system message was either not found in the cache, or   
//there is no cache component defined for the application
//retrieve the system message from the database 
  $sysMessage = SysMessage::model()->find(array(
    'order'=>'t.update_time DESC',
  ));
  if($sysMessage != null)
  {
    //a valid message was found. Store it in cache for future retrievals
    if(isset($key))
      $cache->set($key,$sysMessage,300);    
      return $sysMessage;
  }
  else
      return null;
}
```

我们将在接下来的一分钟内详细介绍。首先，让我们更改我们的应用程序以使用这种新方法来验证缓存是否正常工作。我们仍然需要更改`ProjectController::actionIndex()`方法以使用这个新创建的方法。这很容易。只需用调用这个新方法替换从数据库生成系统消息的代码。也就是说，在`ProjectController::actionIndex()`中，只需更改以下代码：

```php
$sysMessage = SysMessage::model()->find(array('order'=>'t.update_time DESC',));
```

到以下内容：

```php
$sysMessage = SysMessage::getLatest();
```

现在在项目列表页面上显示的系统消息应该利用文件缓存。我们可以检查缓存目录以进行验证。

如果我们对文件缓存的默认位置`protected/runtime/cache/`进行目录列表，我们确实会看到创建了一些文件。两个文件的名称都相当奇怪（您的可能略有不同）`18baacd814900e9b36b3b2e546513ce8.bin`和`2d0efd21cf59ad6eb310a0d70b25a854.bin`。

一个保存我们的系统消息数据，另一个是我们在前几章中配置的`CUrlManager`的配置。默认情况下，`CUrlManager`将使用缓存组件来缓存解析的 URL 规则。您可以将`CUrlManager`的`cacheId`参数设置为`false`，以禁用此组件的缓存。

如果我们以文本形式打开`18baacd814900e9b36b3b2e546513ce8.bin`文件，我们可以看到以下内容：

```php
a:2:{i:0;O:10:"SysMessage":12:{s:18:" :" CActiveRecord _ _md";N;s:19:" :" CActiveRecord _ _new";b:0;s:26:" :" CActiveRecord _ _attributes";a:6:{s:2:"id";s:1:"2";s:7:"message";s:56:"This is a second message from your system administrator!";s:11:"create_time";s:19:"2012-07-31 21:25:33";s:14:"create_user_id";s:1:"1";s:11:"update_time";s:19:"2012-07-31 21:25:33";s:14:"update_user_id";s:1:"1";}s:23:" :"18CActiveRecord _18_related";a:0:{}s:17:" :" CActiveRecord _ _c";N;s:18:" 18:" CActiveRecord _ _:"  _pk";s:1:"2";s:21:" :" CActiveRecord _ _alias";s:1:"t";s:15:" :" CModel _ _errors";a:0:{}s:19:" :" CModel _ _validators";N;s:17:" :" CModel _ _scenario";s:6:"update";s:14:" :" CComponent _ _e";N;s:14:" :" CComponent _ _m";N;}i:1;N;}
```

这是我们最近更新的`SysMessage` AR 类实例的序列化缓存值，这正是我们希望看到的。因此，我们看到缓存实际上是在工作的。

现在让我们更详细地重新审视一下我们的新`SysMessage::getLatest()`方法的代码。代码的第一件事是检查所请求的数据是否已经在缓存中，如果是，则返回该值：

```php
//see if it is in the cache, if so, just return it
if( ($cache=Yii::app()->cache)!==null)
{
  $key='TrackStar.ProjectListing.SystemMessage';
  if(($sysMessage=$cache->get($key))!==false)
    return $sysMessage;
}
```

正如我们所提到的，我们配置了缓存应用组件，可以通过`Yii::app()->cache`在应用程序的任何地方使用。因此，它首先检查是否已定义这样的组件。如果是，它尝试通过`$cache->get($key)`方法在缓存中查找数据。这做的更多或更少是您所期望的。它尝试根据指定的键从缓存中检索值。键是用于映射到缓存中存储的每个数据片段的唯一字符串标识符。在我们的系统消息示例中，我们只需要一次显示一条消息，因此可以使用一个相当简单的键来标识要显示的单个系统消息。只要对于我们想要缓存的每个数据片段保持唯一，键可以是任何字符串值。在这种情况下，我们选择了描述性字符串`TrackStar.ProjectListing.SystemMessage`作为存储和检索缓存系统消息时使用的键。

当此代码首次执行时，缓存中尚没有与此键值关联的任何数据。因此，对于此键的`$cache->get()`调用将返回`false`。因此，我们的方法将继续执行下一部分代码，简单地尝试从数据库中检索适当的系统消息，使用 AR 类：

```php
$sysMessage = SysMessage::model()->find(array(
  'order'=>'t.update_time DESC',
));
```

然后我们继续以下代码，首先检查我们是否从数据库中得到了任何返回。如果是，它会在返回值之前将其存储在缓存中；否则，将返回`null`：

```php
if($sysMessage != null)
{
  if(isset($key))
    $cache->set($key,$sysMessage->message,300);    
    return $sysMessage->message;
}
else
    return null;
```

如果返回了有效的系统消息，我们使用`$cache->set()`方法将数据存储到缓存中。这个方法的一般形式如下：

```php
set($key,$value,$duration=0,$dependency=null)
```

将数据放入缓存时，必须指定一个唯一的键以及要存储的数据。键是一个唯一的字符串值，如前所述，值是希望缓存的任何数据。只要可以序列化，它可以是任何格式。持续时间参数指定了一个可选的**存活时间**（**TTL**）要求。这可以用来确保缓存的值在一段时间后被刷新。默认值为`0`，这意味着它永远不会过期。（实际上，Yii 在内部将持续时间的值`<=0`翻译为一年后过期。所以，不完全是*永远*，但肯定是很长时间。）

我们以以下方式调用`set()`方法：

```php
$cache->set($key,$sysMessage->message,300);  
```

我们将键设置为之前定义的`TrackStar.ProjectListing.SystemMessage`；要存储的数据是我们返回的`SystemMessage` AR 类的消息属性，即我们的`tbl_sys_message`表的消息列；然后我们将持续时间设置为`300`秒。这样，缓存中的数据将在每 5 分钟后过期，届时将再次查询数据库以获取最新的系统消息。当我们设置数据时，我们没有指定依赖项。我们将在下面讨论这个可选参数。

## 缓存依赖项

依赖参数允许采用一种替代和更复杂的方法来决定缓存中存储的数据是否应该刷新。您的缓存策略可能要求根据特定用户发出请求、应用程序的一般模式、状态或文件系统上的文件是否最近已更新等因素使数据无效，而不是声明缓存数据的过期时间。此参数允许您指定此类缓存验证规则。

依赖项是`CCacheDependency`或其子类的实例。Yii 提供了以下特定的缓存依赖项：

+   `CFileCacheDependency`：如果指定文件的最后修改时间自上次缓存查找以来发生了变化，则缓存中的数据将无效。

+   `CDirectoryCacheDependency`：与文件缓存依赖项类似，但是它检查给定指定目录中的所有文件和子目录。

+   `CDbCacheDependency`：如果指定 SQL 语句的查询结果自上次缓存查找以来发生了变化，则缓存中的数据将无效。

+   `CGlobalStateCacheDependency`：如果指定的全局状态的值发生了变化，则缓存中的数据将无效。全局状态是一个跨多个请求和多个会话持久存在的变量。它通过`CApplication::setGlobalState()`来定义。

+   `CChainedCacheDependency`：这允许您将多个依赖项链接在一起。如果链中的任何依赖项发生变化，缓存中的数据将变得无效。

+   `CExpressionDependency`：如果指定的 PHP 表达式的结果发生了变化，则缓存中的数据将无效。

为了提供一个具体的例子，让我们使用一个依赖项，以便在`tbl_sys_message`数据库表发生更改时使缓存中的数据过期。我们将不再任意地在五分钟后使我们的缓存系统消息过期，而是在需要时精确地使其过期，也就是说，当表中的系统消息的`update_time`列发生更改时。我们将使用`CDbCacheDependency`实现这一点，因为它旨在根据 SQL 查询结果的更改来使缓存数据无效。

我们改变了对`set()`方法的调用，将持续时间设置为`0`，这样它就不会根据时间过期，而是传入一个新的依赖实例和我们指定的 SQL 语句，如下所示：

```php
$cache->set($key, $sysMessage, 0, new CDbCacheDependency('SELECT MAX(update_time) FROM tbl_sys_message'));
```

### 注意

将 TTL 时间更改为`0`并不是使用依赖的先决条件。我们可以将持续时间留在`300`秒。这只是规定了另一个规则，使缓存中的数据无效。数据在缓存中只有效 5 分钟，但如果表中有更新时间更晚的消息，也就是更新时间，数据也会在此时间限制之前重新生成。

有了这个设置，缓存只有在查询语句的结果发生变化时才会过期。这个例子有点牵强，因为最初我们是为了避免完全调用数据库而缓存数据。现在我们已经配置它，每次尝试从缓存中检索数据时都会执行数据库查询。然而，如果缓存的数据集更复杂，涉及更多的开销来检索和处理，一个简单的 SQL 语句来验证缓存的有效性可能是有意义的。具体的缓存实现、存储的数据、过期时间，以及这些依赖形式的任何其他数据验证，都将取决于正在构建的应用程序的具体要求。知道 Yii 有许多选项可用于满足我们多样化的需求是很好的。

## 查询缓存

查询缓存的方法在数据库驱动应用程序中经常需要，Yii 提供了更简单的实现，称为**查询缓存**。顾名思义，查询缓存将数据库查询的结果存储在缓存中，并在后续请求中节省查询执行时间，因为这些请求直接从缓存中提供。为了启用查询，您需要确保`CDbConnection`属性的`queryCacheID`属性引用有效缓存组件的`ID`属性。它默认引用`'cache'`，这就是我们从前面的缓存示例中已经配置的。

要使用查询缓存，我们只需调用`CDbConnection`的`cache()`方法。这个方法接受一个持续时间，用来指定查询在缓存中保留的秒数。如果持续时间设置为`0`，缓存就被禁用了。您还可以将`CCacheDependency`实例作为第二个参数传入，并指定多少个后续查询应该被缓存为第三个参数。这第三个参数默认为`1`，这意味着只有下一个 SQL 查询会被缓存。

因此，让我们将以前的缓存实现更改为使用这个很酷的查询缓存功能。使用查询缓存，我们的`SysMessage::getLatest()`方法的实现大大简化了。我们只需要做以下操作：

```php
    //use the query caching approach
    $dependency = new CDbCacheDependency('SELECT MAX(update_time) FROM tbl_sys_message');
    $sysMessage = SysMessage::model()->cache(1800, $dependency)->find(array(
      'order'=>'t.update_time DESC',
    ));
    return $sysMessage;
```

在这里，我们与以前的基本方法相同，但我们不必处理缓存值的显式检查和设置。我们调用`cache()`方法来指示我们要将结果缓存 30 分钟，或者通过指定依赖项，在此时间之前刷新值，如果有更近期的消息可用。

## 片段缓存

前面的例子演示了数据缓存的使用。这是我们将单个数据存储在缓存中。Yii 还提供了其他方法来存储视图脚本的一部分生成的页面片段，甚至整个页面本身。

片段缓存是指缓存页面的一部分。我们可以在视图脚本中利用片段缓存。为此，我们使用`CController::beginCache()`和`CController::endCache()`方法。这两种方法用于标记应该存储在缓存中的渲染页面内容的开始和结束。就像使用数据缓存方法时一样，我们需要一个唯一的键来标识被缓存的内容。一般来说，在视图脚本中使用片段缓存的语法如下：

```php
...some HTML content...
<?php
if($this->beginCache($id))
{
// ...content you want to cache here
$this->endCache();
}
?>
...other HTML content...
```

当有缓存版本可用时，`beginCache()`方法返回`false`，并且缓存的内容将自动插入到该位置；否则，if 语句内的内容将被执行，并且在调用`endCache()`时将被缓存。

### 声明片段缓存选项

在调用`beginCache()`时，我们可以提供一个数组作为第二个参数，其中包含定制片段缓存的缓存选项。事实上，`beginCache()`和`endCache()`方法是`COutputCache`过滤器/小部件的便捷包装。因此，缓存选项可以是`COutputCache`类的任何属性的初始值。

在缓存数据时，指定的最常见选项之一是持续时间，它指定内容在缓存中可以保持有效的时间。这类似于我们在缓存系统消息时使用的“持续时间”参数。在调用`beginCache()`时，可以指定`duration`参数如下：

```php
$this->beginCache($key, array('duration'=>3600))
```

这种片段缓存方法的默认设置与数据缓存的默认设置不同。如果我们不设置持续时间，它将默认为 60 秒，这意味着缓存的内容将在 60 秒后失效。在使用片段缓存时，您可以设置许多其他选项。有关更多信息，请参考`COutputCache`的 API 文档以及 Yii 权威指南的片段缓存部分，该指南可在 Yii 框架网站上找到：[`www.yiiframework.com/doc/guide/1.1/en/caching.fragment`](http://www.yiiframework.com/doc/guide/1.1/en/caching.fragment)

### 使用片段缓存

让我们在 TrackStar 应用程序中实现这一点。我们将再次专注于项目列表页面。您可能还记得，在项目列表页面的底部有一个列表，显示了用户在与每个项目相关的问题上留下的评论。这个列表只是指示谁在哪个问题上留下了评论。我们可以使用片段缓存来缓存这个列表，比如说两分钟。应用程序可以容忍这些数据略微过时，而两分钟对于等待更新的评论列表来说并不长。

为了做到这一点，我们需要对列表视图文件`protected/views/project/index.php`进行更改。我们将调用整个最近评论小部件的内容包裹在这个片段缓存方法中，如下所示：

```php
<?php
$key = "TrackStar.ProjectListing.RecentComments";
if($this->beginCache($key, array('duration'=>120))) {
   $this->beginWidget('zii.widgets.CPortlet', array(
    'title'=>'Recent Comments',
  ));  
  $this->widget('RecentCommentsWidget');
  $this->endWidget();
  $this->endCache(); 
}
?>
```

有了这个设置，如果我们第一次访问项目列表页面，我们的评论列表将被存储在缓存中。然后，如果我们在两分钟内快速（在两分钟之前）向项目中的问题之一添加新评论，然后切换回项目列表页面，我们不会立即看到新添加的评论。但是，如果我们不断刷新页面，一旦缓存中的内容过期（在这种情况下最多两分钟），数据将被刷新，我们的新评论将显示在列表中。

### 注意

您还可以简单地在先前缓存的内容中添加`echo time();` PHP 语句，以查看它是否按预期工作。如果内容正确缓存，时间显示将在缓存刷新之前不会更新。在使用文件缓存时，请记住确保您的`/protected/runtime/`目录对 Web 服务器进程是可写的，因为这是缓存内容默认存储的位置。

我们可以通过声明缓存依赖项而不是固定持续时间来避免这种情况。片段缓存也支持缓存依赖项。因此，我们可以将之前看到的`beginCache()`方法调用更改为以下内容：

```php
if($this->beginCache($key, array('dependency'=>array(
      'class'=>'system.caching.dependencies.CDbCacheDependency',
      'sql'=>'SELECT MAX(update_time) FROM tbl_comment')))) {
```

在这里，我们使用了`CDbCacheDependency`方法来缓存内容，直到对我们的评论表进行更新。

## 页面缓存

除了片段缓存之外，Yii 还提供了选项来缓存整个页面请求的结果。页面缓存方法类似于片段缓存方法。然而，由于整个页面的内容通常是通过将额外的布局应用于视图来生成的，我们不能简单地在布局文件中调用`beginCache()`和`endCache()`。原因是布局是在对`CController::render()`方法进行调用后应用的，内容视图被评估之后。因此，我们总是会错过从缓存中检索内容的机会。

因此，要缓存整个页面，我们应该完全跳过生成页面内容的操作执行。为了实现这一点，我们可以在控制器类中使用`COutputCache`类作为操作过滤器。

举个例子，让我们使用页面缓存方法来缓存每个项目详细页面的页面结果。TrackStar 中的项目详细页面是通过请求格式为`http://localhost/trackstar/project/view/id/[id]`的 URL 来呈现的，其中`[id]`是我们请求详细信息的特定项目 ID。我们要做的是设置一个页面缓存过滤器，将为每个请求的 ID 单独缓存此页面的整个内容。当我们缓存内容时，我们需要将项目 ID 合并到键值中。也就是说，我们不希望请求项目＃1 的详细信息，然后应用程序返回项目＃2 的缓存结果。`COutputCache`过滤器允许我们做到这一点。

打开`protected/controllers/ProjectController.php`并修改现有的`filters()`方法如下：

```php
public function filters()
{
  return array(
    'accessControl', // perform access control for CRUD operations
 **array(**
 **'COutputCache + view',  //cache the entire output from the actionView() method for 2 minutes**
 **'duration'=>120,**
 **'varyByParam'=>array('id'),**
 **),**
  );
}
```

此过滤器配置利用`COutputCache`过滤器来缓存应用程序从调用`ProjectController::actionView()`生成的整个输出。如您可能还记得的那样，在`COutputCache`声明之后添加的`+ view`参数是我们包括特定操作方法的标准方式，以便过滤器应用。持续时间参数指定了 120 秒（两分钟）的 TTL，之后页面内容将被重新生成。

`varyByParam`配置是一个非常好的选项，我们之前提到过。这个功能允许自动处理变化，而不是将责任放在开发人员身上，为被缓存的内容想出一个独特的键策略。例如，在这种情况下，通过指定与输入请求中的`GET`参数对应的名称列表。由于我们正在缓存按`project_id`请求的项目的页面内容，因此使用此 ID 作为缓存内容的唯一键生成的一部分是非常合理的。通过指定`'varyByParam'=>array('id')`，`COutputCache`会根据输入查询字符串参数`id`为我们执行此操作。在使用`COutputCache`缓存数据时，还有更多可用的选项来实现这种自动内容变化策略。截至 Yii 1.1.12，以下变化功能可用：

+   **varyByRoute**：通过将此选项设置为`true`，特定的请求路由将被合并到缓存数据的唯一标识符中。因此，您可以使用请求的控制器和操作的组合来区分缓存的内容。

+   **varyBySession**：通过将此选项设置为`true`，将使用唯一的会话 ID 来区分缓存中的内容。每个用户会话可能会看到不同的内容，但所有这些内容仍然可以从缓存中提供。

+   **varyByParam**：如前所述，这使用输入的`GET`查询字符串参数来区分缓存中的内容。

+   **varyByExpression**：通过将此选项设置为 PHP 表达式，我们可以使用此表达式的结果来区分缓存中的内容。

因此，在我们的`ProjectController`类中配置了上述过滤器，对于特定项目详细信息页面的每个请求，在重新生成并再次存储在缓存之前，都会在缓存中存储两分钟。您可以通过首先查看特定项目，然后以某种方式更新该项目来测试这一点。如果在两分钟的缓存持续时间内进行更新，您的更新将不会立即显示。

缓存整个页面结果是提高网站性能的好方法，但显然并不适用于每个应用程序中的每个页面。即使在我们的示例中，为项目详细信息页面缓存整个页面也不能正确使用分页实现我们的问题列表。我们使用这个作为一个快速示例来实现页面缓存，但并不总是适用于每种情况。数据、片段和页面缓存的结合允许您调整缓存策略以满足应用程序的要求。我们只是触及了 Yii 中所有可用缓存选项的表面。希望这激发了您进一步探索完整的缓存景观的兴趣。

# 一般性能调优提示

在准备应用程序投入生产时，还有一些其他事项需要考虑。以下部分简要概述了在调整基于 Yii 的 Web 应用程序性能时需要考虑的其他领域。

## 使用 APC

启用 PHP APC 扩展可能是改善应用程序整体性能的最简单方法。该扩展缓存和优化 PHP 中间代码，并避免在每个传入请求中解析 PHP 脚本所花费的时间。

它还为缓存内容提供了一个非常快速的存储机制。启用 APC 后，可以使用`CApcCache`实现来缓存内容、片段和页面。

## 禁用调试模式

我们在本章的前面讨论了调试模式，但再次提及也无妨。禁用调试模式是另一种提高性能和安全性的简单方法。如果在主`index.php`入口脚本中定义常量`YII_DEBUG`为`true`，Yii 应用程序将在调试模式下运行。许多组件，包括框架本身的组件，在调试模式下运行时会产生额外的开销。

另外，正如在第二章中提到的，*入门*，当我们第一次创建 Yii 应用程序时，大多数 Yii 应用程序文件不需要，也不应该放在公共可访问的 Web 目录中。Yii 应用程序只有一个入口脚本，通常是唯一需要放在 Web 目录中的文件。其他 PHP 脚本，包括所有 Yii 框架文件，都应该受到保护。这就是主应用程序目录的默认名称为`protected/`的原因。为了避免安全问题，建议不要公开访问它。

## 使用 yiilite.php

当启用 PHP APC 扩展时，可以用名为`yiilite.php`的不同 Yii 引导文件替换`yii.php`。这有助于进一步提高 Yii 应用程序的性能。`yiilite.php`文件随每个 Yii 版本发布。它是合并了一些常用的 Yii 类文件的结果。合并文件中删除了注释和跟踪语句。因此，使用`yiilite.php`将减少被包含的文件数量，并避免执行跟踪语句。

### 注意

请注意，没有 APC 的情况下使用`yiilite.php`可能会降低性能。这是因为`yiilite.php`包含一些不一定在每个请求中使用的类，并且会花费额外的解析时间。还观察到，在某些服务器配置下，即使启用了 APC，使用`yiilite.php`也会更慢。判断是否使用`yiilite.php`的最佳方法是使用代码包中包含的“Hello World”演示运行基准测试。

## 使用缓存技术

正如我们在本章中描述和演示的，Yii 提供了许多缓存解决方案，可以显著提高 Web 应用程序的性能。如果生成某些数据需要很长时间，我们可以使用数据缓存方法来减少数据生成的频率；如果页面的某部分保持相对静态，我们可以使用片段缓存方法来减少其渲染频率；如果整个页面保持相对静态，我们可以使用页面缓存方法来节省整个页面请求的渲染成本。

## 启用模式缓存

如果应用程序使用**Active Record**（**AR**），你可以在生产环境中启用模式缓存以节省解析数据库模式的时间。这可以通过将`CDbConnection::schemaCachingDuration`属性配置为大于零的值来实现。

除了这些应用程序级别的缓存技术，我们还可以使用服务器端缓存解决方案来提升应用程序的性能。我们在这里描述的 APC 缓存的启用属于这个范畴。还有其他服务器端技术，比如 Zend Optimizer、eAccelerator 和 Squid 等。

这些大部分只是在你准备将 Yii 应用程序投入生产或者为现有应用程序排除瓶颈时提供一些良好的实践指南。一般的应用程序性能调优更多的是一门艺术而不是科学，而且 Yii 框架之外有许多因素影响整体性能。Yii 自问世以来就考虑了性能，并且继续远远超过许多其他基于 PHP 的应用程序开发框架（详见[`www.yiiframework.com/performance/`](http://www.yiiframework.com/performance/)）。当然，每个 Web 应用程序都需要进行调整以增强性能，但选择 Yii 作为开发框架肯定会让你的应用程序从一开始就具备良好的性能基础。

有关更多详细信息，请参阅 Yii 权威指南中的*性能调优*部分[`www.yiiframework.com/doc/guide/1.1/en/topics.performance`](http://www.yiiframework.com/doc/guide/1.1/en/topics.performance)。

# 总结

在本章中，我们将注意力转向对应用程序进行更改，以帮助提高其在生产环境中的可维护性和性能。我们首先介绍了 Yii 中可用的应用程序日志记录策略，以及如何根据不同的严重级别和类别记录和路由消息。然后我们转向错误处理，以及 Yii 如何利用 PHP 5 中的基础异常实现来提供灵活和健壮的错误处理框架。然后我们了解了 Yii 中可用的一些不同的缓存策略。我们了解了在不同粒度级别上对应用程序数据和内容进行缓存的方法。对于特定变量或单个数据片段的数据缓存，对页面内的内容区域进行片段缓存，以及对整个渲染输出进行完整页面缓存。最后，我们提供了一系列在努力改善 Yii 驱动的 Web 应用程序性能时要遵循的良好实践。

恭喜！我们应该为自己鼓掌。我们已经从构思到生产准备阶段创建了一个完整的网络应用程序。当然，我们也应该为 Yii 鼓掌，因为它在每一个转折点都帮助我们简化和加快了这个过程。我们的 TrackStar 应用程序已经相当不错；但就像所有这类项目一样，总会有改进和提高的空间。我们已经奠定了一个良好的基础，现在你拥有 Yii 的力量，你可以很快将其转变为一个更加易用和功能丰富的应用程序。此外，许多涵盖的示例也可以很好地应用到你可能正在构建的其他类型的网络应用程序上。我希望你现在对使用 Yii 感到自信，并且会在未来的项目中享受到这样做的好处。开心开发！
