# Laravel 应用开发蓝图（一）

> 原文：[`zh.annas-archive.org/md5/036252ba943f4598902eee3d22b931a1`](https://zh.annas-archive.org/md5/036252ba943f4598902eee3d22b931a1)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

《Laravel 应用程序开发蓝图》介绍了如何使用 Laravel 4 逐步开发 10 个不同的应用程序。您还将了解 Laravel 内置方法的基本和高级用法，这对您的项目将非常有用。此外，您还将学习如何使用内置方法扩展当前库并包含第三方库。

本书介绍了 Laravel PHP 框架，并打破了使用 PHP 编码会导致混乱代码的成见。它将带您了解一些清晰、实用的应用程序，帮助您充分利用 Laravel PHP 框架和 PHP 面向对象编程，同时避免混乱的代码。

您还将学习使用不同方法创建安全的 Web 应用程序，例如文件上传和处理、制作 RESTful Ajax 请求和表单处理。如果您想利用 Laravel PHP 框架的验证、文件处理和 RESTful 控制器在各种类型的项目中，那么这本书就是为您准备的。本书将讨论使用 Laravel PHP 框架快速编写安全应用程序所需的一切知识。

# 本书内容包括

第一章，“构建 URL 缩短网站”，提供了关于 Laravel 4 的基础概述。本章介绍了路由、迁移、模型和视图的基础知识。

第二章，“使用 Ajax 构建待办事项列表”，使用 Laravel PHP 框架和 jQuery 构建应用程序。在本章中，我们将向您展示 RESTful 控制器、RESTful 路由和验证请求类型的基础知识。

第三章，“构建图像分享网站”，涵盖了如何向项目添加第三方库，以及如何上传、调整大小、处理和显示图像。

第四章，“构建个人博客”，涵盖了如何使用 Laravel 编写一个简单的个人博客。本章涵盖了 Laravel 内置的身份验证、分页机制和命名路由功能。在本章中，我们还将详细介绍一些随 Laravel 提供的快速开发方法，例如轻松为路由创建 URL 的方法。

第五章，“构建新闻聚合网站”，主要关注扩展核心类的自定义功能的使用。还涵盖了迁移的使用以及验证、保存和检索数据的基础知识。

第六章，“创建照片库系统”，帮助我们使用 Laravel 编写一个简单的照片库系统。在本章中，我们将涵盖 Laravel 内置的文件验证、文件上传和**hasMany**数据库关系方法。我们还将介绍用于验证数据和上传文件的验证类。最后，我们将详细介绍 Laravel 的文件类用于处理文件。

第七章，“创建通讯系统”，涵盖了一个高级的通讯系统，将使用 Laravel 的队列和电子邮件库。本章还着重介绍了如何设置和触发排队任务，以及如何解析电子邮件模板并向订阅者发送大量电子邮件。

第八章，“构建问答 Web 应用程序”，主要关注中间表的使用原因、位置和用法。本章还涵盖了第三方身份验证系统的使用方法以及删除或重命名公共段的方法。

第九章，*构建 RESTful API - 电影和演员数据库*，重点介绍了使用 Laravel 编写简单的电影和演员 API 的 REST 基础知识。我们将在本章中创建一些 JSON 端点，并学习一些 Laravel 4 的技巧。此外，我们还将涵盖 RESTful 控制器、RESTful 路由以及使用迁移向数据库添加示例数据的基础知识。

第十章，*构建电子商务网站*，讨论了如何使用 Laravel 编写简单的电子商务应用程序。在本章中，我们将介绍 Laravel 内置的基本身份验证机制，以及数据库种子。我们还将详细介绍一些与 Laravel 4 一起使用的快速开发方法。我们还将介绍关于数据透视表的高级用法。我们的电子商务应用程序将是一个简单的书店。该应用程序将具有订单、管理和购物车功能。

# 您需要为本书做好准备

本书中编写的应用程序都基于 Laravel 4，因此您将需要符合 Laravel 4 标准要求列表中列出的内容，该列表将在[`four.laravel.com/docs#server-requirements`](http://four.laravel.com/docs#server-requirements)上提供。

章节要求如下：

+   PHP 5.3.7 或更高版本

+   MCrypt PHP 扩展

+   用 SQL 数据库存储数据

个别第三方软件包可能有额外的要求。如果在章节中使用了这些软件包，请参阅它们的要求页面。

# 本书适合对象

这本书非常适合刚接触 PHP 5 面向对象编程标准并希望使用 Laravel PHP 框架的开发人员。假设您已经有一些 PHP 经验，并且熟悉编写当前“老派”方法，比如不使用任何 PHP 框架。这本书也适合那些已经在使用 PHP 框架并寻找更好解决方案的人。

# 约定

在本书中，您将找到一些文本样式，用于区分不同类型的信息。以下是一些这些样式的示例，以及它们的含义解释。

文本中的代码单词显示如下：“我们可以通过使用`include`指令包含其他上下文。”

代码块设置如下：

```php
<?php
class Todo extends Eloquent
{
  protected $table = 'todos';

}
```

当我们希望引起您对代码块的特定部分的注意时，相关的行或项目将以粗体显示：

```php
  public function run()
  {
    Eloquent::unguard();
    $this->call('UsersTableSeeder');
    $this->command->info('Users table seeded!');
 **$this->call('AuthorsTableSeeder');**
 **$this->command->info('Authors table seeded!');**
  }

}
```

任何命令行输入或输出都以以下方式编写：

```php
**php artisan migrate**

```

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的单词，例如菜单或对话框中的单词，会以这样的方式出现在文本中：“然后，我们检查点击了**最佳答案**按钮的用户是问题的提问者还是应用程序的管理员。”

### 注意

警告或重要说明会出现在这样的框中。

### 提示

提示和技巧会以这种方式出现。


# 第一章：构建 URL 缩短网站

在整本书中，我们将使用 Laravel PHP 框架来构建不同类型的 Web 项目。

在本章中，我们将看到如何使用 Laravel 框架的基础知识构建 URL 缩短网站。涵盖的主题包括：

+   创建数据库并迁移我们的 URL 缩短器表

+   创建我们的表单

+   创建我们的链接模型

+   将数据保存到数据库

+   从数据库获取单个 URL 并重定向

# 创建数据库并迁移我们的 URL 缩短器表

迁移就像是应用程序数据库的版本控制。它们允许团队（或您自己）修改数据库模式，并提供有关当前模式状态的最新信息。要创建和迁移 URL 缩短器的数据库，请执行以下步骤：

1.  首先，我们必须创建一个数据库，并定义到 Laravel 的连接信息。为此，我们打开 `app/config` 下的 `database.php` 文件，然后填写所需的凭据。Laravel 默认支持 MySQL、SQLite、PostgreSQL 和 SQLSRV（Microsoft SQL Server）。在本教程中，我们将使用 MySQL。

1.  我们将不得不创建一个 MySQL 数据库。为此，打开您的 MySQL 控制台（或 phpMyAdmin），并写下以下查询：

```php
**CREATE DATABASE urls**

```

1.  上一个命令将为我们生成一个名为 `urls` 的新的 MySQL 数据库。成功生成数据库后，我们将定义数据库凭据。要做到这一点，打开 `app/config` 下的 `database.php` 文件。在该文件中，您将看到返回多个包含数据库定义的数组。

1.  `default` 键定义要使用的数据库驱动程序，每个数据库驱动程序键都保存各自的凭据。我们只需要填写我们将要使用的凭据。在我们的情况下，我确保默认键的值是 `mysql`。要设置连接凭据，我们将填写 `mysql` 键的值，其中包括我们的数据库名称、用户名和密码。在我们的情况下，由于我们有一个名为 `urls` 的 `database`，用户名为 `root`，没有密码，因此 `database.php` 文件中的 `mysql` 连接设置如下：

```php
'mysql' => array(
  'driver' => 'mysql',
  'host' => 'localhost',
  'database' => 'database',
  'username' => 'root',
  'password' => '',
  'charset' => 'utf8',
  'collation' => 'utf8_unicode_ci',
  'prefix' => '',
),
```

### 提示

您可以从您在 [`www.packtpub.com`](http://www.packtpub.com) 的帐户中下载您购买的所有 Packt 图书的示例代码文件。如果您在其他地方购买了本书，您可以访问 [`www.packtpub.com/support`](http://www.packtpub.com/support) 并注册，以便直接通过电子邮件接收文件。

1.  现在，我们将使用 **Artisan CLI** 来创建迁移。Artisan 是专为 Laravel 制作的命令行界面。它提供了许多有用的命令来帮助我们开发。我们将使用以下 `migrate:make` 命令在 Artisan 上创建一个迁移：

```php
**php artisan migrate:make create_links_table --table=links --create**

```

该命令有两部分：

+   第一个是 `migrate:make create_links_table`。命令的这一部分创建一个迁移文件，文件名类似于 `2013_05_01_194506_create_links_table.php`。我们将进一步检查该文件。

+   命令的第二部分是 `--table=links --create`。

+   `--table=links` 选项指向数据库名称。

+   `--create` 选项用于在我们给定 `--table=links` 选项的数据库服务器上创建表。

1.  如您所见，与 Laravel 3 不同，当您运行上一个命令时，它将同时创建迁移表和我们的迁移。您可以在 `app/database/migrations` 下访问迁移文件，其中包含以下代码：

```php
<?php
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;
class CreateLinksTable extends Migration {
  /**
  * Run the migrations.
  *
  * @return void
  */
  public function up()
  {
    Schema::create('links', function(Blueprint $table)
    {
      $table->increments('id');
    });
  }
  /**
  * Reverse the migrations.
  *
  * @return void
  */
  public function down()
  {
    Schema::drop('links');
  }
}
```

1.  让我们检查示例迁移文件。有两个公共函数声明为 `up()` 和 `down()`。当您执行以下 `migrate` 命令时，将执行 `up()` 函数的内容：

```php
**php artsian migrate**

```

此命令将执行所有迁移并在我们的情况下创建 `links` 表。

### 注意

如果在运行迁移文件时收到 `class not found` 错误，请尝试运行 `composer update` 命令。

1.  我们还可以回滚到上一个迁移，就像它从未执行过一样。我们可以使用以下命令完成：

```php
**php artisan migrate:rollback**

```

1.  在某些情况下，我们可能还想回滚我们创建的所有迁移。这可以通过以下命令完成：

```php
**php artisan migrate:reset**

```

1.  在开发阶段，我们可能会忘记添加/删除一些字段，甚至忘记创建一些表，我们可能希望回滚所有内容并重新迁移它们。这可以使用以下命令完成：

```php
**php artisan migrate:refresh**

```

1.  现在，让我们添加我们的字段。我们创建了两个额外的字段，称为`url`和`hash`。`url`字段将保存实际的 URL，而`hash`字段中的 URL 将被重定向到`hash`字段中的 URL 的缩短版本。迁移文件的最终内容如下所示：

```php
<?php
use Illuminate\Database\Migrations\Migration;
class CreateLinksTable extends Migration {
  /**
  * Run the migrations.
  *
  * @return void
  */
  public function up()
  {
    Schema::create('links', function(Blueprint $table)
    {
      $table->increments('id');
      $table->text('url');
      $table->string('hash',400);
    });
  }
  /**
  * Reverse the migrations.
  *
  * @return void
  */
  public function down()
  {
    Schema::drop('links');
  }
}
```

# 创建我们的表单

现在让我们制作我们的第一个表单视图。

1.  将以下代码保存为`form.blade.php`，放在`app/views`下。文件的扩展名是`blade.php`，因为我们将受益于 Laravel 4 内置的模板引擎**Blade**。在表单中可能有一些您尚不理解的方法，但不要担心。我们将在本章中涵盖有关此表单的所有内容。

```php
<!DOCTYPE html>
<html lang="en">
  <head>
    <title>URL Shortener</title>
    <link rel="stylesheet" href="/assets/css/styles.css" />
  </head>
  <body>
    <div id="container">
      <h2>Uber-Shortener</h2>
      {{Form::open(array('url'=>'/','method'=>'post'))}}

      {{Form::text('link',Input::old('link'),array('placeholder'=>'Insert your URL here and press enter!'))}}
      {{Form::close()}}
    </div>
  </body>
</html>
```

1.  现在将以下代码保存为`styles.css`，放在`public/assets/css`下：

```php
div#container{padding-top:100px;
  text-align:center;
  width:75%;
  margin:auto;
  border-radius:4px}
div#container h2{font-family:Arial,sans-serif;
  font-size:28px;
  color:#555}
div#container h3{font-family:Arial,sans-serif;
  font-size:28px}
div#container h3.error{color:#a00}
div#container h3.success{color:#0a0}
div#container input{display:block;
  width:90%;
  float:left;
  font-size:24px;
  border-radius:5px}
div#error,div#success{border-radius:3px;
  display:block;
  width:90%;
  padding:10px}
div#error{background:#ff8080;
  border:1px solid red}
div#success{background:#80ff80;
  border:1px solid #0f0}
```

这段代码将生成一个看起来像以下截图的表单：

![创建我们的表单](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrv-app-dev-bp/img/2111OS_01_01.jpg)

正如您所看到的，我们使用了一个 CSS 文件来整理表单，但是表单的实际部分位于`View`文件的底部，位于 ID 为 container 的`div`内部。

1.  我们使用了 Laravel 内置的`Form`类来生成一个表单，并使用了`Input`库的`old()`方法。现在让我们来看看代码：

+   `Form::open()`: 它创建一个`<form>`开放标签。在第一个提供的参数中，您可以定义表单的发送方式以及将要发送到哪里。它可以是控制器的操作，直接 URL 或命名路由。

+   `Form::text()`: 它创建一个类型为文本的`<input>`标签。第一个参数是输入的名称，第二个参数是输入的值，在第三个参数给定的数组中，您可以定义`<input>`标签的属性和其他属性。

+   `Input::old()`: 它将返回表单中的旧输入，在表单返回输入后。第一个参数是提交的旧输入的名称。在我们的情况下，如果表单在提交后返回（例如，如果表单验证失败），文本字段将填充我们的旧输入，我们可以在以后的请求中重用它。

+   `Form::close()`: 它关闭`<form>`标签。

# 创建我们的 Link 模型

为了从 Laravel 的 ORM 类`Eloquent`中受益，我们需要定义一个模型。将以下代码保存为`Link.php`，放在`app/models`下：

```php
<?php
class Link extends Eloquent {
  protected $table = 'links';
  protected $fillable = array('url','hash');
  public $timestamps = false;
}
```

Eloquent 模型非常容易理解。

+   变量`$table`用于定义模型的表名，但这并不是强制性的。即使我们不定义这个变量，它也会将模型名称的复数形式作为数据库表名。例如，如果模型名称是 post，它将默认查找 post 的表。这样，您可以为表使用任何模型名称。

+   受保护的`$fillable`变量定义了可以（批量）创建和更新的列。默认情况下，Laravel 4 会阻止使用`Eloquent`批量赋值所有列的值。例如，如果您有一个`users`表，并且您是唯一的用户/管理员，批量赋值将保护您的数据库免受其他用户的添加。

+   `$timestamps`变量检查模型是否应该默认尝试设置时间戳`created_at`和`updated_at`，分别在创建和更新查询时。由于我们不需要这些功能，我们将通过将值设置为`false`来禁用它。

我们现在需要定义这个视图，以显示我们是否可以导航到我们的虚拟主机的索引页面。您可以从`routes.php`中定义的控制器，或直接从`routes.php`中定义。由于我们的应用程序很小，直接从`routes.php`中定义它们应该就足够了。要定义这个，打开`app`文件夹下的`routes.php`文件，并添加以下代码：

```php
Route::get('/', function()	
{
  return View::make('form');
});
```

### 注意

如果您已经有一个以`Route::get('/', function()`开头的部分，您应该用先前的代码替换该部分。

Laravel 可以监听`get`、`post`、`put`和`delete`请求。由于我们的操作是一个`get`操作（因为我们将通过浏览器导航而不是发布），所以我们的路由类型将是`get`，因为我们想在根页面上显示视图，所以`Route::get()`方法的第一个参数将是`/`，我们将包装一个闭包函数作为第二个参数来定义我们想要做的事情。在我们的情况下，我们将返回`app/views`下放置的`form.blade.php`，所以我们只需输入`return View::make('form')`。这个方法从`views`文件夹返回`form.blade.php`视图。

### 注意

如果视图在子目录中，它将被称为`subfolder.form`。

# 将数据保存到数据库

现在我们需要编写一个路由来监听我们的`post`请求。为此，我们打开`app`文件夹下的`routes.php`文件，并添加以下代码：

```php
Route::post('/',function(){
  //We first define the Form validation rule(s)
  $rules = array(
    'link' => 'required|url'
  );
  //Then we run the form validation
  $validation = Validator::make(Input::all(),$rules);
  //If validation fails, we return to the main page with an error info
  if($validation->fails()) {
    return Redirect::to('/')
    ->withInput()
    ->withErrors($validation);
  } else {
    //Now let's check if we already have the link in our database. If so, we get the first result
    $link = Link::where('url','=',Input::get('link'))
    ->first();
    //If we have the URL saved in our database already, we provide that information back to view.
    if($link) {
      return Redirect::to('/')
      ->withInput()
      ->with('link',$link->hash);
      //Else we create a new unique URL
    } else {
      //First we create a new unique Hash
      do {
        $newHash = Str::random(6);
      } while(Link::where('hash','=',$newHash)->count() > 0);

      //Now we create a new database record
      Link::create(array('url' => Input::get('link'),'hash' => $newHash
      ));

      //And then we return the new shortened URL info to our action
      return Redirect::to('/')
      ->withInput()
      ->with('link',$newHash);
    }
  }
});
```

## 验证用户的输入

使用我们现在编写的`post`动作函数，我们将使用 Laravel 内置的`Validation`类验证用户的输入。这个类帮助我们防止无效的输入进入我们的数据库。

首先，我们定义一个`$rules`数组来设置每个字段的规则。在我们的情况下，我们希望链接具有有效的 URL 格式。然后我们可以使用`Validator::make()`方法运行表单验证，并将其赋值给`$validation`变量。让我们了解`Validator::make()`方法的参数：

+   `Validator::make()`方法的第一个参数接受一个输入和要验证的值的数组。在我们的情况下，整个表单只有一个名为 link 的字段，所以我们使用了`Input::all()`方法，该方法返回表单中的所有输入。

+   第二个参数接受要检查的验证规则。存储的`$validation`变量为我们提供了一些信息。例如，我们可以检查验证是否失败或通过（使用`$validation->fails()`和`$validation->passes()`）。这两种方法返回布尔结果，因此我们可以轻松地检查验证是否通过或失败。此外，`$validation`变量包含一个`messages()`方法，其中包含验证失败的信息。我们可以使用`$validation->messages()`捕获它们。

如果表单验证失败，我们将用户重定向回我们的索引页面（`return Redirect::to('/')`），该页面包含 URL 缩短器表单，并将一些闪存数据返回给表单。在 Laravel 中，我们通过向重定向的页面添加`withVariableName`对象来实现这一点。在这里使用`with`是强制的，这将告诉 Laravel 我们正在返回一些额外的东西。我们可以在重定向和制作视图时都这样做。如果我们正在制作视图并向最终用户显示一些内容，那么`withVariableName`将是变量，我们可以直接使用`$VariableName`调用它们，但如果我们正在重定向到一个带有`withVariableName`对象的页面，`VariableName`将是一个闪存会话数据，我们可以使用`Session`类（`Session::get('VariableName')`）来调用它。

在我们的示例中，为了返回错误，我们使用了一个特殊的`withErrors($validation)`方法，而不是返回`$validation->messages()`。我们也可以使用那个返回，但是`$errors`变量总是在视图上定义的，所以我们可以直接使用我们的`$validation`变量作为参数与`withErrors()`一起使用。`withInput()`方法也是一个特殊的方法，它将结果返回到表单。

```php
//If validation fails, we return to the main page with an error info
if($validation->fails()) {
  return Redirect::to('/')
  ->withInput()
  ->withErrors($validation);
}
```

如果用户在表单中忘记了一个字段，并且验证失败并显示带有错误消息的表单，使用`withInput()`方法，表单可以再次填充旧的输入。为了在 Laravel 中显示这些旧的输入，我们使用`Input`类的`old()`方法。例如，`Input::old('link')`将返回表单字段`link`的旧输入。

## 将消息返回给视图

为了将错误消息返回到表单中，我们可以将以下 HTML 代码添加到`form.blade.php`中：

```php
@if(Session::has('errors'))
<h3 class="error">{{$errors->first('link')}}</h3>
@endif
```

正如您可能已经猜到的那样，`Session::has('variableName')`返回一个布尔值，用于检查会话中是否有变量名。然后，使用 Laravel 的`Validator`类的`first('formFieldName')`方法，我们返回表单字段的第一个错误消息。在我们的情况下，我们正在显示`link`表单字段的第一个错误消息。

# 深入控制器和处理表单

在我们的示例中，验证检查部分的`else`部分在表单验证成功完成时执行，包含了链接的进一步处理。在这一部分，我们将执行以下步骤：

1.  检查链接是否已经在我们的数据库中。

1.  如果链接已经在我们的数据库中，返回缩短后的链接。

1.  如果链接不在我们的数据库中，为链接创建一个新的随机字符串（将在我们的 URL 中）。

1.  在我们的数据库中使用提供的数值创建一个新的记录。

1.  将缩短后的链接返回给用户。

现在，让我们深入了解代码。

1.  以下是我们代码的第一部分：

```php
// Now let's check if we already have the link in our database. If so, we get the first result
$link = Link::where('url','=',Input::get('link'))
->first();
```

首先，我们使用**Fluent Query Builder**的`where()`方法检查 URL 是否已经存在于我们的数据库中，并通过`first()`方法获取第一个结果，并将其赋给`$link`变量。您可以轻松地使用 Fluent 查询方法和 Eloquent ORM。如果这让您感到困惑，不用担心，我们将在后面的章节中进一步介绍。

1.  这是我们控制器方法代码的下一部分：

```php
//If we have the URL saved in our database already, we provide that information back to view.
if($link) {
  return Redirect::to('/')
  ->withInput()
  ->with('link',$link->hash);
```

如果我们在数据库中保存了 URL，`$link`变量将保存从数据库中获取的链接信息的对象。因此，通过简单的`if()`子句，我们可以检查是否有结果。如果有结果返回，我们可以使用`$link->columnname`来访问它。

在我们的情况下，如果查询有结果，我们将输入和链接重定向回表单。正如我们在这里使用的，`with()`方法也可以用两个参数而不是使用驼峰命名法——`withName('value')`与`with('name','value')`完全相同。因此，我们可以使用闪存数据名为链接`with('link',$link->hash)`来返回哈希码。为了显示这一点，我们可以将以下代码添加到我们的表单中：

```php
@if(Session::has('link'))
<h3 class="success">
  {{Html::link(Session::get('link'),'Click here for your shortened URL')}}</h3>
@endif
```

`Html`类帮助我们轻松编写 HTML 代码。`link()`方法需要以下两个参数：

+   第一个参数是`link`。如果我们直接提供一个字符串（在我们的例子中是哈希字符串），该类将自动识别它并从我们的网站创建内部 URL。

+   第二个参数是包含链接的字符串。

可选的第三个参数必须是一个数组，包含属性（例如 class、ID 和 target）作为二维数组。

1.  以下是我们代码的下一部分：

```php
//Else we create a new unique URL
} else {
  //First we create a new unique Hash
  do {
    $newHash = Str::random(6);
  } while(Link::where('hash','=',$newHash)->count() > 0);
```

如果没有结果（变量的 else 子句），我们将使用`Str`类的`random()`方法创建一个六个字符长的字母数字随机字符串，并使用 PHP 自己的 do-while 语句每次检查它是否是唯一的字符串。对于真实世界的应用，您可以使用另一种方法来缩短，例如将 ID 列中的条目转换为 base_62 并将其用作哈希值。这样，URL 将更清晰，这总是一个更好的做法。

1.  这是我们代码的下一部分：

```php
//Now we create a new database record
Link::create(array(
  'url' => Input::get('link'),
  'hash' => $newHash
));
```

一旦我们有了唯一的哈希，我们可以使用 Laravel 的 Eloquent ORM 的`create()`方法将链接和哈希值添加到数据库中。唯一的参数应该是一个二维数组，其中数组的键保存数据库列名，数组的值保存要插入为新行的值。

在我们的情况下，`url`列必须具有来自表单的`link`字段的值。我们可以使用 Laravel 的`Input`类的`get()`方法捕获来自`post`请求的这些值。在我们的情况下，我们可以使用`Input::get('link')`捕获来自`post`请求的`link`表单字段的值（我们可以使用`$_POST['link']`的混乱代码捕获），并像之前一样将哈希值返回给视图。

1.  这是我们代码的最后部分：

```php
//And then we return the new shortened URL info to our action return Redirect::to('/')
->withInput()
->with('link',$newHash);
```

现在，在输出中，我们被重定向到`oursite.dev/hashcode`。变量`$newHash`中存储了一个链接；我们需要捕获这个哈希码并查询我们的数据库，如果有记录，我们需要重定向到实际的 URL。

# 从数据库中获取单个 URL 并重定向

现在，在我们第一章的最后部分，我们需要从生成的 URL 中获取`hash`部分，如果有值，我们需要将其重定向到存储在我们数据库中的 URL。为此，请在`app`文件夹下的`routes.php`文件末尾添加以下代码：

```php
Route::get('{hash}',function($hash) {
  //First we check if the hash is from a URL from our database
  $link = Link::where('hash','=',$hash)
  ->first();
  //If found, we redirect to the URL
  if($link) {
    return Redirect::to($link->url);
    //If not found, we redirect to index page with error message
  } else {
    return Redirect::to('/')
    ->with('message','Invalid Link');
  }
})->where('hash', '[0-9a-zA-Z]{6}');
```

在前面的代码中，与其他路由定义不同，我们在名称`hash`周围添加了花括号，告诉 Laravel 它是一个参数；并且使用`where()`方法定义了名称参数的方式。第一个参数是变量的名称（在我们的情况下是`hash`），第二个参数是一个正则表达式，用于过滤参数。在我们的情况下，正则表达式过滤了一个精确的六个字符长的字母数字字符串。这样，我们可以过滤我们的 URL 并从一开始就保护它们，而且我们不必检查`url`参数是否有我们不想要的内容（例如，在 ID 列中输入字母而不是数字）。要从数据库中获取单个 URL 并重定向，我们执行以下步骤：

1.  在`Route`类中，我们首先进行搜索查询，就像在前面的部分中所做的那样，然后检查我们的数据库中是否有一个具有给定哈希的链接，并将其设置为名为`$link`的变量。

```php
//First we check if the hash is from an URL from our database
$link = Link::where('hash','=',$hash)
->first();
```

1.  如果有结果，我们将页面重定向到我们数据库的`url`列，该列包含用户应重定向到的链接。

```php
//If found, we redirect to the link
if($link) {
  return Redirect::to($link->url);
}
```

1.  如果没有结果，我们将使用`$message`变量将用户重定向回我们的索引页面，该变量保存了`Invalid Link`的值。

```php
//If not found, we redirect to index page with error message
} else {
  return Redirect::to('/')
  ->with('message','Invalid Link');
}
```

要在表单中显示`Invalid Link`消息，请在`app/views`下的`form.blade.php`文件中添加以下代码。

```php
@if(Session::has('message'))
<h3 class="error">{{Session::get('message')}}</h3>
@endif
```

# 总结

在本章中，我们通过制作一个简单的 URL 缩短网站，介绍了 Laravel 路由、模型、artisan 命令和数据库驱动的基本用法。一旦您完成了本章，您就可以使用迁移创建数据库表，使用 Laravel 表单构建器类编写简单的表单，使用`Validation`类验证这些表单，并使用 Fluent 查询构建器或 Eloquent ORM 处理这些表单并将新数据插入表中。在下一章中，我们将介绍这些强大功能的高级用法。


# 第二章：使用 Ajax 构建待办事项列表

在本章中，我们将使用 Laravel PHP 框架和 jQuery 来构建一个带有 Ajax 的待办事项列表。

在本章中，我们将向您展示**RESTful 控制器**、**RESTful 路由**和**请求类型**的基础知识。本章涵盖的主题列表如下：

+   创建和迁移待办事项列表的数据库

+   创建待办事项列表的模型

+   创建模板

+   使用 Ajax 向数据库插入数据

+   从数据库中检索列表

+   如何只允许 Ajax 请求

# 创建和迁移待办事项列表的数据库

正如您从上一章所知，迁移对于控制开发步骤非常有帮助。我们将在本章再次使用迁移。

要创建我们的第一个迁移，请输入以下命令：

```php
**php artisan migrate:make create_todos_table --table=todos --create**

```

当您运行此命令时，**Artisan**将生成一个迁移以生成名为`todos`的数据库表。

现在我们应该编辑迁移文件以创建必要的数据库表列。当您用文件管理器打开`app/database/`中的`migration`文件夹时，您会看到其中的迁移文件。

让我们按照以下方式打开并编辑文件：

```php
<?php
use Illuminate\Database\Migrations\Migration;
class CreateTodosTable extends Migration {

    /**
    * Run the migrations.
    *
    * @return void
    */
    public function up()
    {

        Schema::create('todos', function(Blueprint $table){
            $table->create();
            $table->increments("id");
            $table->string("title", 255);
            $table->enum('status', array('0', '1'))->default('0');
            $table->timestamps();
        });

    }

    /**
    * Reverse the migrations.
    *
    * @return void
    */
    public function down()
    {
        Schema::drop("todos");
    }

}
```

要构建一个简单的待办事项列表，我们需要五列：

+   `id`列将存储待办任务的 ID 编号

+   `title`列将存储待办任务的标题

+   `status`列将存储每个任务的状态

+   `created_at`和`updated_at`列将存储任务的创建和更新日期

如果您在迁移文件中写入`$table->timestamps()`，Laravel 的`migration`

类会自动创建`created_at`和`updated_at`列。正如您从第一章中所知，*构建 URL 缩短网站*，要应用迁移，我们应该运行以下命令：

```php
**php artisan migrate**

```

运行命令后，如果您检查数据库，您会看到我们的`todos`表和列已经创建。现在我们需要编写我们的模型。

# 创建一个待办事项模型

要创建一个模型，您应该用文件管理器打开`app/models/`目录。在该目录下创建一个名为`Todo.php`的文件，并编写以下代码：

```php
<?php
class Todo extends Eloquent
{
  protected $table = 'todos';

}
```

让我们来看一下`Todo.php`文件。

如您所见，我们的`Todo`类扩展了 Laravel 的**ORM**（**对象关系映射器**）数据库类`Eloquent`。

`protected $table = 'todos';`代码告诉`Eloquent`关于我们模型的表名。如果我们不设置`table`变量，`Eloquent`会接受小写模型名称的复数版本作为表名。因此，从技术上讲这并不是必需的。

现在，我们的应用程序需要一个模板文件，所以让我们创建它。

# 创建模板

Laravel 使用一个名为**Blade**的模板引擎来处理静态和应用程序模板文件。Laravel 从`app/views/`目录调用模板文件，因此我们需要在该目录下创建我们的第一个模板。

1.  创建一个名为`index.blade.php`的文件。

1.  文件包含以下代码：

```php
<html>
  <head>
    <title>To-do List Application</title>
    <link rel="stylesheet" href="assets/css/style.css">
    <!--[if lt IE 9]><scriptsrc="//html5shim.googlecode.com/svn/trunk/html5.js"></script><![endif]-->

  </head>
  <body>
    <div class="container">
      <section id="data_section" class="todo">
        <ul class="todo-controls">
        <li><img src="/assets/img/add.png" width="14px"onClick="show_form('add_task');" /></li>
        </ul>
          <ul id="task_list" class="todo-list">
          @foreach($todos as $todo)
            @if($todo->status)
              <li id="{{$todo->id}}" class="done"><a href="#" class="toggle"></a><span id="span_{{$todo->id}}">{{$todo->title}}</span> <a href="#"onClick="delete_task('{{$todo->id}}');"class="icon-delete">Delete</a> <a href="#"onClick="edit_task('{{$todo->id}}','{{$todo->title}}');"class="icon-edit">Edit</a></li>
            @else
              <li id="{{$todo->id}}"><a href="#"onClick="task_done('{{$todo->id}}');"class="toggle"></a> <span id="span_{{$todo->id}}">{{$todo->title}}</span><a href="#" onClick="delete_task('{{$todo->id}}');" class="icon-delete">Delete</a>
                <a href="#" onClick="edit_task('{{$todo->id}}','{{$todo->title}}');"class="icon-edit">Edit</a></li>
            @endif
          @endforeach
        </ul>
      </section>
      <section id="form_section">

      <form id="add_task" class="todo"
        style="display:none">
      <input id="task_title" type="text" name="title"placeholder="Enter a task name" value=""/>
      <button name="submit">Add Task</button>
      </form>

        <form id="edit_task" class="todo"style="display:none">
        <input id="edit_task_id" type="hidden" value="" />
        <input id="edit_task_title" type="text"name="title" value="" />
        <button name="submit">Edit Task</button>
      </form>

    </section>

    </div>
    <script src="http://code.jquery.com/jquery-latest.min.js"type="text/javascript"></script>
    <script src="assets/js/todo.js"type="text/javascript"></script>
  </body>
</html>
```

如果您是第一次编写 Blade 模板，上面的代码可能很难理解，所以我们将尝试解释一下。您会在文件中看到一个`foreach`循环。这个语句循环遍历我们的`todo`记录。

在本章中创建控制器时，我们将为您提供更多关于它的知识。

`if`和`else`语句用于区分已完成和待办任务。我们使用`if`和`else`语句来为任务设置样式。

我们还需要一个模板文件，用于动态向任务列表追加新记录。在`app/views/`文件夹下创建一个名为`ajaxData.blade.php`的文件。文件包含以下代码：

```php
@foreach($todos as $todo)
  <li id="{{$todo->id}}"><a href="#" onClick="task_done('{{$todo->id}}');" class="toggle"></a> <span id="span_{{$todo>id}}">{{$todo->title}}</span> <a href="#"onClick="delete_task('{{$todo->id}}');" class="icondelete">Delete</a> <a href="#" onClick="edit_task('{{$todo>id}}','{{$todo->title}}');" class="icon-edit">Edit</a></li>
@endforeach
```

此外，您会在静态文件的源路径中看到`/assets/`目录。当您查看`app/views`目录时，您会发现没有名为`assets`的目录。Laravel 将系统文件和公共文件分开。公共可访问文件位于`root`目录下的`public`文件夹中。因此，您应该在公共文件夹下创建一个`asset`文件夹。

我们建议使用这些类型的有组织的文件夹来开发整洁易读的代码。最后，您会发现我们是从 jQuery 的主网站调用的。我们还建议您以这种方式在应用程序中获取最新的稳定的 jQuery。

您可以根据自己的意愿为应用程序设置样式，因此我们不会在这里检查样式代码。我们将把我们的`style.css`文件放在`/public/assets/css/`下。

为了执行 Ajax 请求，我们需要 JavaScript 编码。这段代码发布了我们的`add_task`和`edit_task`表单，并在任务完成时更新它们。让我们在`/public/assets/js/`中创建一个名为`todo.js`的 JavaScript 文件。文件包含以下代码：

```php
function task_done(id){

  $.get("/done/"+id, function(data) {

    if(data=="OK"){

      $("#"+id).addClass("done");
    }

  });
}
function delete_task(id){

  $.get("/delete/"+id, function(data) {

    if(data=="OK"){
      var target = $("#"+id);

      target.hide('slow', function(){ target.remove(); });

    }

  });
}

function show_form(form_id){

  $("form").hide();

  $('#'+form_id).show("slow");

}
function edit_task(id,title){

  $("#edit_task_id").val(id);

  $("#edit_task_title").val(title);

  show_form('edit_task');
}
$('#add_task').submit(function(event) {

  /* stop form from submitting normally */
  event.preventDefault();

  var title = $('#task_title').val();
  if(title){
    //ajax post the form
    $.post("/add", {title: title}).done(function(data) {

      $('#add_task').hide("slow");
      $("#task_list").append(data);
    });

  }
  else{
    alert("Please give a title to task");
    }
});

$('#edit_task').submit(function() {

  /* stop form from submitting normally */
  event.preventDefault();

  var task_id = $('#edit_task_id').val();
  var title = $('#edit_task_title').val();
  var current_title = $("#span_"+task_id).text();
  var new_title = current_title.replace(current_title, title);
  if(title){
    //ajax post the form
    $.post("/update/"+task_id, {title: title}).done(function(data){
      $('#edit_task').hide("slow");
      $("#span_"+task_id).text(new_title);
    });
  }
  else{
    alert("Please give a title to task");
  }
});
```

让我们检查 JavaScript 文件。

# 使用 Ajax 将数据插入到数据库

在这个应用程序中，我们将使用**Ajax POST**方法将数据插入到数据库中。jQuery 是这类应用程序的最佳 JavaScript 框架。jQuery 还带有强大的选择器功能。

我们的 HTML 代码中有两个表单，所以我们需要使用 Ajax 提交它们来插入或更新数据。我们将使用 jQuery 的`post()`方法来实现。

我们将在`/public/assets/js`下提供我们的 JavaScript 文件，因此让我们在该目录下创建一个`todo.js`文件。首先，我们需要一个请求来添加新任务。JavaScript 代码包含以下代码：

```php
$('#add_task').submit(function(event) {
  /* stop form from submitting normally */
  event.preventDefault();
  var title = $('#task_title').val();
  if(title){
    //ajax post the form
    $.post("/add", {title: title}).done(function(data) {
      $('#add_task').hide("slow");
      $("#task_list").append(data);
    });
  }
  else{
    alert("Please give a title to task");
  }
});
```

如果用户记得为任务提供标题，这段代码将把我们的`add_task`表单发布到服务器。如果用户忘记为任务提供标题，代码将不会发布表单。发布后，代码将隐藏表单并向任务列表附加一个新记录。同时，我们将等待响应以获取数据。

因此，我们需要第二个表单来更新任务的标题。代码将通过 Ajax 实时更新任务的标题，并更改更新记录的文本。实时编程（或现场编码）是一种编程风格，程序员/表演者/作曲家在程序运行时增加和修改程序，而无需停止或重新启动，以在运行时断言表达式、可编程控制性能、组合和实验。由于编程语言的基本功能，我们相信实时编程的技术和美学方面值得在 Web 应用程序中探索。更新表单的代码应该如下：

```php
$('#edit_task').submit(function(event) {
  /* stop form from submitting normally */
  event.preventDefault();
  var task_id = $('#edit_task_id').val();
  var title = $('#edit_task_title').val();
  var current_title = $("#span_"+task_id).text();
  var new_title = current_title.replace(current_title, title);
  if(title){
    //ajax post the form
    $.post("/update/"+task_id, {title: title}).done(function(data){
      $('#edit_task').hide("slow");
      $("#span_"+task_id).text(new_title);
    });
  }
  else{
    alert("Please give a title to task");
  }
});
```

Laravel 具有 RESTful 控制器功能。这意味着您可以定义路由和控制器函数的 RESTful 基础。此外，可以为不同的请求类型（如**POST**、**GET**、**PUT**或**DELETE**）定义路由。

在定义路由之前，我们需要编写我们的控制器。控制器文件位于`app/controllers/`下；在其中创建一个名为`TodoController.php`的文件。控制器代码应该如下：

```php
<?php
class TodoController extends BaseController
{
  public $restful = true;
  public function postAdd() {
    $todo = new Todo();
    $todo->title = Input::get("title");
    $todo->save();      
    $last_todo = $todo->id;
    $todos = Todo::whereId($last_todo)->get();
    return View::make("ajaxData")->with("todos", $todos);
  }
  public function postUpdate($id) {        
    $task = Todo::find($id);
    $task->title = Input::get("title");
    $task->save();
    return "OK";        
  }
}
```

让我们检查代码。

正如您在代码中所看到的，RESTful 函数定义了诸如`postFunction`、`getFunction`、`putFunction`或`deleteFunction`之类的语法。

我们有两个提交表单，所以我们需要两个 POST 函数和一个 GET 方法来从数据库中获取记录，并在`foreach`语句中在模板中向访问者显示它们。

让我们检查前面的代码中的`postUpdate()`方法：

```php
public function postUpdate($id) {
  $task = Todo::find($id);
  $task->title = Input::get("title");
  $task->save();
  return "OK";
}
```

以下几点解释了前面的代码：

+   该方法需要一个名为`id`的记录来更新。我们提交的路由将类似于`/update/record_id`。

+   `$task = Todo::find($id);`是从数据库中查找具有给定`id`的记录的方法的一部分。

+   `$task->title = Input::get("title");`意味着获取名为`title`的表单元素的值，并将`title`列的记录更新为发布的值。

+   `$task->save();`应用更改并在数据库服务器上运行更新查询。

让我们检查`postAdd()`方法。这个方法的工作方式类似于我们的`getIndex()`方法。代码的第一部分在数据库服务器上创建一个新记录：

```php
public function postAdd() {
  $todo = new Todo();
  $todo->title = Input::get("title");
  $todo->save();      
  $last_todo = $todo->id;
  $todos = Todo::whereId($last_todo)->get();
  return View::make("ajaxData")->with("todos", $todos);
}
```

以下几点解释了前面的代码：

+   代码行`$last_todo = $todo->id;`获取了这条记录的 ID。它相当于`mysql_insert_id()`函数。

+   代码行`$todos = Todo::whereId($last_todo)->get();`从具有`id`列等于`$last_todo`变量的`todo`表中获取记录。

+   代码行`View::make("ajaxData") ->with("todos", $todos);`非常重要，以了解 Laravel 的视图机制：

+   代码行`View::make("ajaxData")`指的是我们的模板文件。你还记得我们在`/app/views/`下创建的`ajaxData.blade.php`文件吗？代码调用了这个文件。

+   代码行`->with("todos", $todos);`将最后一条记录分配给模板文件，作为名为`todos`的变量（第一个参数）。因此，我们可以使用`foreach`循环在模板文件中显示最后一条记录。

# 从数据库中检索列表

我们还需要一种方法来从我们的数据库服务器中获取现有数据。在我们的控制器文件中，我们需要如下所示的函数：

```php
public function getIndex() {
  $todos = Todo::all();
  return View::make("index")
    ->with("todos", $todos);
}
```

让我们来看一下`getIndex()`方法：

+   在代码中，`$todos = Todo:all()`表示从数据库中获取所有记录并将它们分配给`$todos`变量。

+   在代码中，`View::make("index")`定义了我们的模板文件。你还记得我们在`/app/views/`下创建的`index.blade.php`文件吗？代码调用了这个文件。

+   在代码中，`->with("todos", $todos);`将记录分配给模板文件。因此，我们可以使用`foreach`循环在模板文件中显示记录。

最后，我们将定义我们的路由。要定义路由，您应该在`apps`文件夹中打开`routes.php`文件。Laravel 有一个很好的功能，用于定义名为 RESTful 控制器的路由。您可以使用一行代码定义所有路由，如下所示：

```php
Route::controller('/', 'TodoController');
```

上述代码将所有应用程序基于根的请求分配给`TodoController`函数。如果需要，您也可以手动定义路由，如下所示：

```php
Route::method('path/{variable}', 'TheController@functionName');
```

# 如何仅允许 Ajax 请求

我们的应用程序甚至可以在没有 Ajax 的情况下接受所有 POST 和 GET 请求。但我们只需要允许`add`和`update`函数的 Ajax 请求。Laravel 的`Request`类为您的应用程序提供了许多检查 HTTP 请求的方法。其中一个函数名为`ajax()`。我们可以在控制器或路由过滤器下检查请求类型。

## 使用路由过滤器允许请求

路由过滤器提供了一种方便的方式来限制、访问或过滤给定路由的请求。Laravel 中包含了几个过滤器，这些过滤器位于`app`文件夹中的`filters.php`文件中。我们可以在这个文件下定义我们自定义的过滤器。我们将不在本章中使用这种方法，但我们将在后续章节中研究路由过滤器。用于 Ajax 请求的路由过滤器应该如下所示的代码所示：

```php
Route::filter('ajax_check', function()
{
  if (Request::ajax())
    {
      return true;
    }
});
```

将过滤器附加到路由也非常容易。检查以下代码中显示的示例路由：

```php
Route::get('/add', array('before' => 'ajax_check', function()
{
    return 'The Request is AJAX!';
}));
```

在前面的示例中，我们为具有`before`变量的路由定义了一个路由过滤器。这意味着我们的应用首先检查请求类型，然后调用控制器函数并传递数据。

## 使用控制器端允许请求

我们可以在控制器下检查请求类型。我们将在本节中使用这种方法。这种方法对于基于函数的过滤非常有用。为此，我们应该按照以下代码所示更改我们的`add`和`update`函数：

```php
public function postAdd() {
  if(Request::ajax()){
    $todo = new Todo();
    $todo->title = Input::get("title");
    $todo->save();
    $last_todo = $todo->id;
    $todos = Todo::whereId($last_todo)->get();
    return View::make("ajaxData")->with("todos", $todos);
  }
}
public function postUpdate($id) {
  if(Request::ajax()){
    $task = Todo::find($id);
    $task->title = Input::get("title");
    $task->save();
    return "OK"; 
  }
}
```

# 总结

在本章中，我们编写了添加新任务的代码，更新了它，并列出了任务。我们还需要更新每个状态并删除任务。为此，我们需要两个名为`getDone()`和`getDelete()`的函数。正如你从本章的前几节中所了解的那样，这些函数是 RESTful 的，并接受 GET 方法请求。因此，我们的函数应该如下所示的代码所示：

```php
public function getDelete($id) {
  if(Request::ajax()){
    $todo = Todo::whereId($id)->first();
    $todo->delete();
    return "OK";
  }
}
public function getDone($id) {
  if(Request::ajax()){
    $task = Todo::find($id);
    $task->status = 1;
    $task->save();
    return "OK";
  }
}
```

我们还需要更新`todo.js`文件。最终的 JavaScript 代码应该如下所示的代码所示：

```php
function task_done(id){
  $.get("/done/"+id, function(data) {
    if(data=="OK"){
      $("#"+id).addClass("done");
    }
  });
}
function delete_task(id){
  $.get("/delete/"+id, function(data) {
    if(data=="OK"){
      var target = $("#"+id);
      target.hide('slow', function(){ target.remove(); });
    }
  });
}
function show_form(form_id){
  $("form").hide();
  $('#'+form_id).show("slow");
}
function edit_task(id,title){
  $("#edit_task_id").val(id);
  $("#edit_task_title").val(title);
  show_form('edit_task');
}
$('#add_task').submit(function(event) {
/* stop form from submitting normally */
  event.preventDefault();
  var title = $('#task_title').val();
  if(title){
    //ajax post the form
    $.post("/add", {title: title}).done(function(data) {
      $('#add_task').hide("slow");
      $("#task_list").append(data);
    });
  }
  else{
    alert("Please give a title to task");
  }
});
$('#edit_task').submit(function(event) {
/* stop form from submitting normally */
  event.preventDefault();
  var task_id = $('#edit_task_id').val();
  var title = $('#edit_task_title').val();
  var current_title = $("#span_"+task_id).text();
  var new_title = current_title.replace(current_title, title);
  if(title){
    //ajax post the form
    $.post("/update/"+task_id, {title:title}).done(function(data) {
      $('#edit_task').hide("slow");
      $("#span_"+task_id).text(new_title);
    });
  }
  else{
    alert("Please give a title to task");
  }
});
```

# 总结

在本节中，我们试图了解如何在 Laravel 中使用 Ajax。在整个章节中，我们使用了模板化、请求过滤、路由和 RESTful 控制器的基础知识。我们还学会了如何从数据库中更新和删除数据。

在下一章中，我们将尝试检查 Laravel 的文件验证和文件处理方法。


# 第三章：构建一个图片分享网站

通过这一章，我们将创建一个照片分享网站。首先，我们将创建一个图像表。然后我们将介绍调整大小和分享图像的方法。

本章涵盖以下主题：

+   创建数据库并迁移图像表

+   创建一个照片模型

+   设置自定义配置值

+   安装第三方库

+   创建一个安全的文件上传表单

+   验证和处理表单

+   使用用户界面显示图像

+   列出图像

+   从数据库和服务器中删除图像

# 创建数据库并迁移图像表

成功安装 Laravel 4 并从`app/config/database.php`中定义数据库凭据后，创建一个名为`images`的数据库。为此，您可以从托管提供商的面板上创建一个新的数据库，或者如果您是服务器管理员，您可以简单地运行以下 SQL 命令：

```php
**CREATE DATABASE images**

```

成功为应用程序创建数据库后，我们需要创建一个`photos`表并将其安装到数据库中。为此，打开您的终端，导航到项目文件夹，并运行以下命令：

```php
php artisan migrate:make create_photos_table --table=photos –create
```

这个命令将为我们生成一个新的 MySQL 数据库迁移，用于创建一个名为 photos 的表。

现在我们需要定义数据库表中应该有哪些部分。对于我们的示例，我认为`id 列`，`图像标题`，`图像文件名`和`时间戳`应该足够了。因此，打开刚刚用前面的命令创建的迁移文件，并按照以下代码更改其内容：

```php
<?php
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class CreatePhotosTable extends Migration {

  /**
  * Run the migrations.
  * @return void
  */
  public function up()
    {
    Schema::create('photos', function(Blueprint $table)
    {
      $table->increments('id');
      $table->string('title',400)->default('');//the column that holds the image's name
      $table->string('image',400)->default('');//the column that holds the image's filename
      $table->timestamps();
    });
  }

  /**
  * Reverse the migrations.
  * @return void
  */
  public function down()
  {
    Schema::drop('photos');
  }
}
```

保存文件后，运行以下命令执行迁移：

```php
**php artsian migrate**

```

如果没有发生错误，您已经准备好进行项目的下一步了。

# 创建一个照片模型

如您所知，对于 Laravel 上的任何与数据库操作相关的事情，使用模型是最佳实践。我们将利用**Eloquent ORM**。

将以下代码保存为`app/models/`目录中的`images.php`：

```php
<?php
class Photo extends Eloquent {

  //the variable that sets the table name
  protected $table = 'photos';

  //the variable that sets which columns can be edited
  protected $fillable = array('title','image');

  //The variable which enables or disables the Laravel'stimestamps option. Default is true. We're leaving this hereanyways
  public $timestamps = true;
}
```

我们使用`protected $table`变量设置了表名。表的哪些列的内容可以被更新/插入将由`protected $fillable`变量决定。最后，模型是否可以添加/更新时间戳将由`public $timestamps`变量的值决定。只需设置这个模型（即使什么都不设置），我们就可以轻松地使用 Eloquent ORM 的所有优势。

我们的模型已经准备好了，现在我们可以继续下一步，开始创建我们的控制器以及上传表单。但在此之前，我们缺少一件简单的事情。图像应该上传到哪里？缩略图的最大宽度和高度是多少？要设置这些配置值（将其视为原始 PHP 的常量），我们应该创建一个新的配置文件。

# 设置自定义配置值

使用 Laravel，设置配置值非常容易。所有`config`值都在一个数组中，并且将被定义为`key=>value`对。

现在让我们创建一个新的配置文件。将此文件保存为`app/config`中的`image.php`：

```php
<?php

/**
 * app/config/image.php
*/

return array(

  //the folder that will hold original uploaded images
  'upload_folder' => 'uploads',

  //the folder that will hold thumbnails
  'thumb_folder' => 'uploads/thumbs',

  //width of the resized thumbnail
  'thumb_width' => 320,

  //height of the resized thumbnail
  'thumb_height' => 240

);
```

您可以根据自己的喜好设置任何其他设置。这取决于您的想象力。您可以使用 Laravel 内置的`Config`库的`get()`方法调用设置。示例用法如下所示：

```php
Config::get('filename.key')
```

在参数之间有一个点（`。`），它将字符串分成两部分。第一部分是`Config`的文件名，不包括扩展名，第二部分是配置值的键名。在我们的示例中，如果我们想要确定上传文件夹的名称，我们应该按照以下代码所示进行编写：

```php
Config::get('image.upload_folder')
```

前面的代码将返回任何值。在我们的示例中，它将返回`public`/`uploads`。

还有一件事：我们为我们的应用程序定义了一些文件夹名称，但我们没有创建它们。对于某些服务器配置，文件夹可能会在第一次尝试上传文件时自动创建，但如果您不创建它们，很可能会导致服务器配置错误。在`public`文件夹中创建以下文件夹，并使其可写：

+   `uploads/`

+   `uploads/thumbs`

现在我们应该为我们的图片站点制作一个上传表单。

# 安装第三方库

我们应该为我们的图片站点制作一个上传表单，然后为其创建一个控制器。但在这之前，我们将安装一个用于图像处理的第三方库，因为我们将从中受益。Laravel 4 使用**Composer**，因此安装包、更新包甚至更新 Laravel 都非常容易。对于我们的项目，我们将使用一个名为`Intervention`的库。必须按照以下步骤来安装该库：

1.  首先，确保您通过在终端中运行`php composer.phar self-update`来拥有最新的`composer.phar`文件。

1.  然后打开`composer.json`，并在`require`部分添加一个新值。我们库的值是`intervention/image: "dev-master"`。

目前，我们的`composer.json`文件的`require`部分如下所示：

```php
"require": {
  "laravel/framework": "4.0.*",
  "intervention/image": "dev-master"
}
```

您可以在[www.packagist.org](http://www.packagist.org)上找到更多 Composer 包。

1.  设置完值后，打开您的终端，导航到项目的`root`文件夹，并输入以下命令：

```php
**php composer.phar update**

```

这个命令将检查`composer.json`并更新所有依赖项（包括 Laravel 本身），如果添加了新的要求，它将下载并安装它们。

1.  成功下载库后，我们现在将激活它。为此，我们参考`Intervention`类的网站。现在打开你的`app/config/app.php`，并将以下值添加到`providers`键中：

```php
Intervention\Image\ImageServiceProvider
```

1.  现在，我们需要设置一个别名，以便我们可以轻松调用该类。为此，在同一文件的别名键中添加以下值：

```php
'Image' => 'Intervention\Image\Facades\Image',
```

1.  该类有一个相当容易理解的注释。要调整图像大小，运行以下代码就足够了：

```php
Image::make(Input::file('photo')->getRealPath())->resize(300, 200)->save('foo.jpg');
```

### 注意

有关`Intervention`类的更多信息，请访问以下网址：

[`intervention.olivervogel.net`](http://intervention.olivervogel.net)

现在，所有关于视图和表单处理的准备工作都已经完成；我们可以继续进行项目的下一步。

# 创建一个安全的文件上传表单

现在我们应该为我们的图片站点制作一个上传表单。我们必须制作一个视图文件，它将通过控制器加载。

1.  首先，打开`app/routes.php`，删除以 Laravel 开头的`Route::get()`行，并添加以下行：

```php
//This is for the get event of the index page
Route::get('/',array('as'=>'index_page','uses'=>'ImageController@getIndex'));
//This is for the post event of the index.page
Route::post('/',array('as'=>'index_page_post','before' =>'csrf', 'uses'=>'ImageController@postIndex'));
```

键`'as'`定义了路由的名称（类似于快捷方式）。因此，如果您为路由创建链接，即使路由的 URL 发生变化，您的应用链接也不会断开。`before`键定义了在动作开始之前将使用哪些过滤器。您可以定义自己的过滤器，或者使用内置的过滤器。我们设置了`csrf`，因此在动作开始之前将进行**CSRF**（跨站点请求伪造）检查。这样，您可以防止攻击者向您的应用程序注入未经授权的请求。您可以使用分隔符与多个过滤器；例如，`filter1|filter2`。

### 注意

您还可以直接从控制器定义 CSRF 保护。

1.  现在，让我们为控制器创建我们的第一个方法。添加一个新文件，其中包含以下代码，并将其命名为`ImageController.php`，放在`app/controllers/`中：

```php
<?php

class ImageController extends BaseController {

  public function getIndex()
  {
    //Let's load the form view
    return View::make('tpl.index');
  }

}
```

我们的控制器是 RESTful 的；这就是为什么我们的方法 index 被命名为`getIndex()`。在这个方法中，我们只是加载一个视图。

1.  现在让我们使用以下代码为视图创建一个主页面。将此文件保存为`frontend_master.blade.php`，放在`app/views/`中：

```php
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" 
"http://www.w3.org/TR/html4/loose.dtd">

<html lang="en">
  <head>
  <meta http-equiv="content-type"content="text/html; charset=utf-8">
  <title>Laravel Image Sharing</title>
  {{HTML::style('css/styles.css')}}
  </head>

  <body>
    {{--Your title of the image (and yeah, blade enginehas its own commenting, cool, isn't it?)--}}
    <h2>Your Awesome Image Sharing Website</h2>

    {{--If there is an error flashdata in session(from form validation), we show the first one--}}
    @if(Session::has('errors'))
      <h3 class="error">{{$errors->first()}}</h3>
    @endif

    {{--If there is an error flashdata in session whichis set manually, we will show it--}}
    @if(Session::has('error'))
      <h3 class="error">{{Session::get('error')}}</h3>
    @endif

    {{--If we have a success message to show, we printit--}}
    @if(Session::has('success'))
      <h3 class="error">{{Session::get('success')}}</h3>
    @endif

    {{--We yield (get the contents of) the section named'content' from the view files--}}
    @yield('content')

  </body>
</html>
```

要添加一个`CSS`文件（我们将在下一步中创建），我们使用`HTML`类的`style()`方法。我们的主页面产生一个名为`content`的部分，它将用`view files`部分填充。

1.  现在，让我们使用以下代码创建我们的`view file`部分。将此文件保存为`index.blade.php`，放在`app/views/tpl/`目录中：

```php
@extends('frontend_master')

@section('content')
  {{Form::open(array('url' => '/', 'files' => true))}}
  {{Form::text('title','',array('placeholder'=>'Please insert your title here'))}}
  {{Form::file('image')}}
  {{Form::submit('save!',array('name'=>'send'))}}
  {{Form::close()}}
@stop
```

在上述代码的第一行中，我们告诉 Blade 引擎，我们将使用`frontend_master.blade.php`作为布局。这是使用 Laravel 4 中的`@extends()`方法完成的。

### 注意

如果您来自 Laravel 3，`@layout`已更名为`@extends`。

借助 Laravel 的`Form`类，我们生成了一个带有`title`字段和`upload`字段的上传表单。与 Laravel 3 不同，要创建一个新的上传表单，我们不再使用`Form::open_for_files()`。它已与`open()`方法合并，该方法接受一个字符串或一个数组，如果要传递多个参数，则可以使用数组。我们将传递动作 URL 以及告诉它这是一个上传表单，因此我们传递了两个参数。`url`键用于定义表单将被提交的位置。`files`参数是布尔值，如果设置为`true`，它将使表单成为上传表单，因此我们可以处理文件。

为了保护表单并防止不必要的表单提交尝试，我们需要在表单中添加一个 CSRF 密钥`hidden`。多亏了 Laravel 的`Form`类，它会在表单打开标签后自动生成。您可以通过查看生成的表单的源代码来检查它。

自动生成的隐藏 CSRF 表单元素如下所示：

```php
<input name="_token" type="hidden" value="SnRocsQQlOnqEDH45ewP2GLxPFUy5eH4RyLzeKm3">
```

1.  现在让我们稍微整理一下表单。这与我们的项目没有直接关系，只是为了外观。将`styles.css`文件保存在`public/css/`（我们在主页面上定义的路径）中：

```php
/*Body adjustment*/
body{width:60%; margin:auto; background:#dedede}
/*The title*/
h2{font-size:40px; text-align:center; font-family:Tahoma,Arial,sans-serif}
/*Sub title (success and error messages)*/
h3{font-size:25px; border-radius:4px; font-family:Tahoma,Arial,sans-serif; text-align:center;width:100%}
h3.error{border:3px solid #d00; background-color:#f66; color:#d00 }
h3.success{border:3px solid #0d0; background-color:#0f0; color:#0d0}p{font-size:25px; font-weight: bold; color: black;font-family: Tahoma,Arial,sans-serif}ul{float:left;width:100%;list-style:none}li{float:left;margin-right:10px}
/*For the input files of the form*/
input{float:left; width:100%; border-radius:13px;font-size:20px; height:30px; border:10px 0 10px 0;margin-bottom:20px}
```

我们通过将其宽度设置为 60％，使其居中对齐，并给它一个灰色的背景来样式化主体。我们还使用`success`和`error`类以及`forms`格式化了`h2`和`h3`消息。

在样式化之后，表单将如下截图所示：

![创建安全的文件上传表单](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrv-app-dev-bp/img/2111OS_03_01.jpg)

现在我们的表单已经准备好了，我们准备进入项目的下一步。

# 验证和处理表单

在本节中，我们将验证提交的表单，并确保必填字段存在，并且提交的文件是一张图片。然后我们将上传图片到我们的服务器，处理图片，创建缩略图，并将图片信息保存到数据库中，如下所示：

1.  首先，我们需要定义表单验证规则。我们更喜欢将这些值添加到相关模型中，这样规则就可以重复使用，这可以防止代码变得臃肿。为此，请在`app/models/`目录中的`photo.php`文件中添加以下代码（在本章前面生成的模型中）类定义的最后一个右花括号（`}`）之前：

```php
//rules of the image upload form
public static $upload_rules = array(
  'title'=> 'required|min:3',
  'image'=> 'required|image'
);
```

我们将变量设置为`public`，这样它就可以在模型文件之外使用，并将其设置为静态，这样我们就可以直接访问变量。

我们希望`title`和`image`都是必填的，而`title`应至少包含三个字符。此外，我们希望检查`image`列的 MIME 类型，并确保它是一张图片。

### 注意

Laravel 的 MIME 类型检查需要安装`Fileinfo`扩展。因此，请确保在您的 PHP 配置中启用它。

1.  现在我们需要控制器的`post`方法来处理表单。在`app/controllers/`中的`ImageController.php`文件中添加此方法，放在最后一个右花括号（`}`）之前：

```php
public function postIndex()
{

  //Let's validate the form first with the rules which areset at the model
  $validation = Validator::make(Input::all(),Photo::$upload_rules);

  //If the validation fails, we redirect the user to theindex page, with the error messages 
  if($validation->fails()) {
    return Redirect::to('/')->withInput()->withErrors($validation);
  }
  else {

    //If the validation passes, we upload the image to thedatabase and process it
    $image = Input::file('image');

    //This is the original uploaded client name of theimage
    $filename = $image->getClientOriginalName();
    //Because Symfony API does not provide filename//without extension, we will be using raw PHP here
    $filename = pathinfo($filename, PATHINFO_FILENAME);

    //We should salt and make an url-friendly version of//the filename
    //(In ideal application, you should check the filename//to be unique)
    $fullname = Str::slug(Str::random(8).$filename).'.'.$image->getClientOriginalExtension();

    //We upload the image first to the upload folder, thenget make a thumbnail from the uploaded image
    $upload = $image->move(Config::get( 'image.upload_folder'),$fullname);

    //Our model that we've created is named Photo, thislibrary has an alias named Image, don't mix them two!
    //These parameters are related to the image processingclass that we've included, not really related toLaravel
    Image::make(Config::get( 'image.upload_folder').'/'.$fullname)->resize(Config::get( 'image.thumb_width'),null, true)->save(Config::get( 'image.thumb_folder').'/'.$fullname);

    //If the file is now uploaded, we show an error messageto the user, else we add a new column to the databaseand show the success message
    if($upload) {

      //image is now uploaded, we first need to add columnto the database
      $insert_id = DB::table('photos')->insertGetId(
        array(
          'title' => Input::get('title'),
          'image' => $fullname
        )
      );

      //Now we redirect to the image's permalink
      return Redirect::to(URL::to('snatch/'.$insert_id))->with('success','Your image is uploadedsuccessfully!');
    } else {
      //image cannot be uploaded
      return Redirect::to('/')->withInput()->with('error','Sorry, the image could not beuploaded, please try again later');
    }
  }
}
```

让我们逐行查看代码。

1.  首先，我们进行了表单验证，并从我们通过`Photo::$upload_rules`生成的模型中调用了我们的验证规则。

1.  然后，我们对文件名进行了加盐处理（添加额外的随机字符以增强安全性），并使文件名适合 URL。首先，我们使用 getClientOriginalName()方法获取上传的文件名，然后使用 getClientOriginalExtension()方法获取扩展名。我们使用 STR 类的 random()方法获得一个八个字符长的随机字符串对文件名进行了加盐处理。最后，我们使用 Laravel 的内置 slug()方法使文件名适合 URL。

1.  在所有变量准备就绪后，我们首先使用 move()方法将文件上传到服务器，该方法需要两个参数。第一个参数是文件将要传输到的路径，第二个参数是上传文件的文件名。

1.  上传后，我们为上传的图像创建了一个静态缩略图。为此，我们利用了之前实现的图像处理类 Intervention。

1.  最后，如果一切顺利，我们将标题和图像文件名添加到数据库，并使用 Fluent Query Builder 的 insertGetId()方法获取 ID，该方法首先插入行，然后返回列的 insert_id。我们还可以通过将 create()方法设置为变量并获取 id_column 名称，如$create->id，使用 Eloquent ORM 创建行。

1.  在一切都正常并且我们获得了`insert_id`之后，我们将用户重定向到一个新页面，该页面将显示缩略图、完整图像链接和一个论坛缩略图**BBCode**，我们将在接下来的部分中生成。

# 使用用户界面显示图像

现在，我们需要从控制器创建一个新的视图和方法来显示上传的图像的信息。可以按以下方式完成：

1.  首先，我们需要为控制器定义一个`GET`路由。为此，打开`app`文件夹中的`routes.php`文件，并添加以下代码：

```php
//This is to show the image's permalink on our website
Route::get('snatch/{id}',
  array('as'=>'get_image_information',
  'uses'=>'ImageController@getSnatch'))
  ->where('id', '[0-9]+');
```

我们在路由上定义了一个`id`变量，并使用正则表达式的`where()`方法首先进行了过滤。因此，我们不需要担心过滤 ID 字段，无论它是自然数还是其他。

1.  现在，让我们创建我们的控制器方法。在`app/controllers/`中的`ImageController.php`中最后一个右花括号(`}`)之前添加以下代码：

```php
public function getSnatch($id) {
  //Let's try to find the image from database first
  $image = Photo::find($id);
  //If found, we load the view and pass the image info asparameter, else we redirect to main page with errormessage
  if($image) {
    return View::make('tpl.permalink')->with('image',$image);
  } else {
    return Redirect::to('/')->with('error','Image not found');
  }
}
```

首先，我们使用 Eloquent ORM 的`find()`方法查找图像。如果它返回 false，那意味着找到了一行。因此，我们可以简单地使用一个简单的`if`子句来检查是否有结果。如果有结果，我们将使用`with()`方法将找到的图像信息作为名为`$image`的变量加载到我们的视图中。如果没有找到值，我们将返回到索引页面并显示错误消息。

1.  现在让我们创建包含以下代码的模板文件。将此文件保存为`permalink.blade.php`，放在`app/views/tpl/`中：

```php
@extends('frontend_master')
@section('content')
<table cellpadding="0" cellspacing="0" border="0"width="100percent">
  <tr>
    <td width="450" valign="top">
      <p>Title: {{$image->title}}</p>
    {{HTML::image(Config::get('image.thumb_folder').'/'.$image->image)}}
    </td>
      <td valign="top">
      <p>Direct Image URL</p>
      <input onclick="this.select()" type="text"width="100percent" value="{{URL::to(Config::get('image.upload_folder').'/'$image->image)}}" />

      <p>Thumbnail Forum BBCode</p>
      <input onclick="this.select()" type="text"width="100percent" value="[url={{URL::to('snatch/'$image->id)}}][img]{{URL::to(Config::get('image.thumb_folder')'/'.$image->image)}}[/img][/url]" />

      <p>Thumbnail HTML Code</p>
      <input onclick="this.select()" type="text"width="100percent"value="{{HTML::entities(HTML::link(URL::to('snatch/'.$image->id),HTML::image(Config::get('image.thumb_folder').'/'$image->image)))}}" />
    </td>
  </tr>
</table>
@stop
```

现在，您应该对此模板中使用的大多数方法都很熟悉了。还有一个名为`entities()`的新方法，属于`HTML`类，实际上是原始 PHP 的`htmlentities()`，但带有一些预检查，并且是 Laravel 的方式。

此外，因为我们将`$image`变量返回到视图中（这是我们使用 Eloquent 直接获得的数据库行对象），我们可以在视图中直接使用`$image->columnName`。

这将产生一个视图，如下图所示：

![使用用户界面显示图像](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrv-app-dev-bp/img/2111OS_03_02.jpg)

1.  我们为项目添加了永久链接功能，但是如果我们想要显示所有图像怎么办？为此，我们需要在系统中添加一个`'all pages'`部分。

# 列出图像

在本节中，我们将在系统中创建一个`'all images'`部分，该部分将具有页面导航（分页）系统。如下所示，需要遵循一些步骤：

1.  首先，我们需要从我们的`route.php`文件中定义其 URL。为此，打开`app/routes.php`并添加以下行：

```php
//This route is to show all images.
Route::get('all',array('as'=>'all_images','uses'=>'ImageController@getAll'));
```

1.  现在，我们需要一个名为`getAll()`的方法（因为它将是一个 RESTful 控制器，所以在开头有一个`get`方法）来获取值并加载视图。为此，请打开`app/controllers/ImageController.php`，并在最后一个右花括号（}）之前添加以下代码：

```php
public function getAll(){

  //Let's first take all images with a pagination feature
  $all_images = DB::table('photos')->orderBy('id','desc')->paginate(6);

  //Then let's load the view with found data and pass thevariable to the view
  return View::make('tpl.all_images')->with('images',$all_images);
}
```

首先，我们使用`paginate()`方法从数据库中获取了所有图像，这将使我们能够轻松获取分页链接。之后，我们加载了用户的视图，并显示了带有分页的图像数据。

1.  要正确查看这个，我们需要一个视图文件。将以下代码保存在名为`all_image.blade.php`的文件中，放在`app/views/tpl/`目录中：

```php
@extends('frontend_master')

@section('content')

@if(count($images))
  <ul>

    @foreach($images as $each)
      <li>
        <a href="{{URL::to('snatch/'$each->id)}}">{{HTML::image(Config::get('image.thumb_folder')'/'.$each->image)}}</a>
      </li>
    @endforeach
  </ul> 
  <p>{{$images->links()}}</p>
@else
  {{--If no images are found on the database, we will showa no image found error message--}}
  <p>No images uploaded yet, {{HTML::link('/','care to upload one?')}}</p>
@endif
@stop
```

我们首先用我们的内容部分扩展了`frontend_master.blade.php`文件。至于内容部分，我们首先检查是否返回了任何行。如果是，那么我们将它们全部循环在列表项标签（`<li>`）中，并附上它们的永久链接。`paginate`类提供的`links()`方法将为我们创建分页。

### 注意

您可以从`app/config/view.php`切换分页模板。

如果没有返回行，那意味着还没有图像，因此我们会显示一个警告消息，并附上一个指向新上传页面的链接（在我们的情况下是首页）。

如果有人上传了不允许或不安全的工作图像，怎么办？您肯定不希望它们出现在您的网站上，对吧？因此，您的网站应该有一个图像删除功能。

# 从数据库和服务器中删除图像

我们希望在我们的脚本中有一个删除功能，使用该功能我们将从数据库和上传的文件夹中删除图像。使用 Laravel，这个过程非常简单。

1.  首先，我们需要为该操作创建一个新路由。为此，请打开`app/routes.php`，并添加以下行：

```php
//This route is to delete the image with given ID
Route::get('delete/{id}', array
('as'=>'delete_image','uses'=>
'ImageController@getDelete'))
->where('id', '[0-9]+');
```

1.  现在，我们需要在`ImageController`中定义控制器方法`getDelete($id)`。为此，请打开`app/controllers/ImageController.php`，并在最后一个右花括号（`}`）之前添加以下代码：

```php
public function getDelete($id) {
  //Let's first find the image
  $image = Photo::find($id);

  //If there's an image, we will continue to the deletingprocess
  if($image) {
    //First, let's delete the images from FTP
    File::delete(Config::get('image.upload_folder').'/'$image->image);
    File::delete(Config::get('image.thumb_folder').'/'$image->image);

    //Now let's delete the value from database
    $image->delete();

    //Let's return to the main page with a success message
    return Redirect::to('/')->with('success','Image deleted successfully');

  } else {
    //Image not found, so we will redirect to the indexpage with an error message flash data.
    return Redirect::to('/')->with('error','No image with given ID found');
  }
}
```

让我们理解这段代码：

1.  首先，我们查看我们的数据库，如果我们已经有了给定 ID 的图像，则使用 Eloquent ORM 的`find()`方法将其存储在名为`$image`的变量中。

1.  如果`$image`的值不为 false，则数据库中有与图像匹配的图像。然后，我们使用 File 类的`delete()`方法删除文件。或者，您也可以使用原始 PHP 的 unlink()方法。

1.  在文件从文件服务器中删除后，我们将从数据库中删除图像的信息行。为此，我们使用了 Eloquent ORM 的`delete()`方法。

1.  如果一切顺利，我们应该重定向回主页，并显示成功消息，说明图像已成功删除。

### 注意

在实际应用中，您应该为此类操作创建一个后端界面。

# 总结

在本章中，我们使用 Laravel 的内置功能创建了一个简单的图像分享网站。我们学会了如何验证我们的表单，如何处理文件并检查它们的 MIME 类型，并设置自定义配置值。我们还学习了使用 Fluent 和 Eloquent ORM 的数据库方法。此外，对于图像处理，我们使用 Composer 从[packagist.org](http://packagist.org)安装了第三方库，并学会了如何更新它们。我们还使用页面导航功能列出了图像，并学会了如何从服务器中删除文件。在下一章中，我们将构建一个带有身份验证和仅限会员区域的个人博客网站，并将博客文章分配给作者。


# 第四章：构建个人博客

在本章中，我们将使用 Laravel 编写一个简单的个人博客。我们还将介绍 Laravel 内置的身份验证、分页机制和命名路由。我们将详细介绍一些快速开发方法，这些方法是 Laravel 自带的，比如创建路由 URL。本章将涵盖以下主题：

+   创建和迁移帖子数据库

+   创建一个帖子模型

+   创建和迁移作者数据库

+   创建一个仅限会员的区域

+   保存博客帖子

+   将博客帖子分配给用户

+   列出文章

+   对内容进行分页

# 创建和迁移帖子数据库

我们假设你已经在`app/config/database.php`文件中定义了数据库凭据。对于这个应用程序，我们需要一个数据库。你可以简单地创建并运行以下 SQL 命令，或者基本上你可以使用你的数据库管理界面，比如 phpMyAdmin：

```php
**CREATE DATABASE laravel_blog**

```

成功创建应用程序的数据库后，首先我们需要创建一个帖子表并将其安装在数据库中。要做到这一点，打开你的终端，导航到你的项目文件夹，并运行这个命令：

```php
**php artisan migrate:make create_posts_table --table=posts --create**

```

这个命令将在`app/database/migrations`下生成一个迁移文件，用于在我们的`laravel_blog`数据库中生成一个名为`posts`的新 MySQL 表。

为了定义我们的表列和规范，我们需要编辑这个文件。编辑迁移文件后，它应该看起来像这样：

```php
<?php

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class CreatePostsTable extends Migration {

  /**
   * Run the migrations.
   *
   * @return void
   */
  public function up()
  {
    Schema::create('posts', function(Blueprint $table)
    {
      $table->increments('id');
      $table->string('title');
      $table->text('content');
      $table->integer('author_id');
      $table->timestamps();
    });
  }

  /**
   * Reverse the migrations.
   *
   * @return void
   */
  public function down()
  {
    Schema::drop('posts');
  }
}
```

保存文件后，我们需要使用一个简单的`artisan`命令来执行迁移：

```php
**php artisian migrate**

```

如果没有错误发生，请检查`laravel_blog`数据库中的`posts`表和列。

# 创建一个帖子模型

如你所知，对于 Laravel 上的任何与数据库操作相关的事情，使用模型是最佳实践。我们将受益于 Eloquent ORM。

将这段代码保存在一个名为`Posts.php`的文件中，放在`app/models/`下：

```php
<?php
class Post extends Eloquent {

protected $table = 'posts';

protected $fillable = array('title','content','author_id');

public $timestamps = true;

public function Author(){

      return $this->belongsTo('User','author_id');
}

}
```

我们已经使用受保护的`$table`变量设置了数据库表名。我们还使用了`$fillable`变量设置可编辑的列，并使用了`$timestamps`变量设置时间戳，就像我们在之前的章节中已经看到并使用过的那样。在模型中定义的变量足以使用 Laravel 的 Eloquent ORM。我们将在本章的*将博客帖子分配给用户*部分介绍公共的`Author()`函数。

我们的帖子模型已经准备好了。现在我们需要一个作者模型和数据库来将博客帖子分配给作者。让我们研究一下 Laravel 内置的身份验证机制。

# 创建和迁移作者数据库

与大多数 PHP 框架相反，Laravel 有一个基本的身份验证类。身份验证类在快速开发应用程序方面非常有帮助。首先，我们需要一个应用程序的秘钥。应用程序的秘钥对于我们应用程序的安全非常重要，因为所有数据都是使用这个秘钥进行哈希加盐的。`artisan`命令可以用一个单一的命令行为我们生成这个秘钥：

```php
**php artisian key:generate**

```

如果没有错误发生，你将看到一条消息，告诉你秘钥已经成功生成。在生成秘钥后，如果你在打开 Laravel 应用程序时遇到问题，只需清除浏览器缓存，然后重试。接下来，我们应该编辑身份验证类的配置文件。为了使用 Laravel 内置的身份验证类，我们需要编辑位于`app/config/auth.php`的配置文件。该文件包含了身份验证设施的几个选项。如果你需要更改表名等，你可以在这个文件下进行更改。默认情况下，Laravel 自带`User`模型。你可以看到位于`app/models/`下的`User.php`文件。在 Laravel 4 中，我们需要定义`Users`模型中哪些字段是可填充的。让我们编辑位于`app/models/`下的`User.php`并添加"fillable"数组：

```php
<?php

use Illuminate\Auth\UserInterface;
use Illuminate\Auth\Reminders\RemindableInterface;

class User extends Eloquent implements UserInterface, RemindableInterface {

  /**
   * The database table used by the model.
   *
   * @var string
   */
  protected $table = 'users';

  /**
   * The attributes excluded from the model's JSON form.
   *
   * @var array
   */
  protected $hidden = array('password');

  //Add to the "fillable" array
   protected $fillable = array('email', 'password', 'name');

  /**
   * Get the unique identifier for the user.
   *
   * @return mixed
   */
  public function getAuthIdentifier()
  {
    return $this->getKey();
  }

  /**
   * Get the password for the user.
   *
   * @return string
   */
  public function getAuthPassword()
  {
    return $this->password;
  }

  /**
   * Get the e-mail address where password reminders are sent.
   *
   * @return string
   */
  public function getReminderEmail()
  {
    return $this->email;
  }

}
```

基本上，我们需要为我们的作者有三列。这些是： 

+   `email`：这一列存储作者的电子邮件

+   `password`：这一列存储作者的密码

+   `name`：这一列存储作者的名字和姓氏

现在我们需要几个迁移文件来创建`users`表并向我们的数据库添加作者。要创建一个迁移文件，可以给出以下命令：

```php
**php artisan migrate:make create_users_table --table=users --create**

```

打开最近创建的迁移文件，位于`app/database/migrations/`。我们需要编辑`up()`函数如下：

```php
  public function up()
  {
    Schema::create('users', function(Blueprint $table)
    {
      $table->increments('id');
      $table->string('email');
      $table->string('password');
      $table->string('name');
      $table->timestamps();
    });
  }
```

编辑迁移文件后，运行`migrate`命令：

```php
**php artisian migrate**

```

如你所知，该命令创建了`users`表及其列。如果没有错误发生，请检查`laravel_blog`数据库中的`users`表和列。

现在我们需要创建一个新的迁移文件，向数据库中添加一些作者。我们可以通过运行以下命令来实现：

```php
**php artisan migrate:make add_some_users**

```

打开迁移文件并编辑`up()`函数如下：

```php
  public function up()
  {
    User::create(array(
            'email' => 'your@email.com',
            'password' => Hash::make('password'),
            'name' => 'John Doe'
        ));
  }
```

我们在`up()`函数中使用了一个新的类，名为`Hash`。Laravel 有一个基于安全**Bcrypt**的哈希制造/检查类。Bcrypt 是一种被接受的、安全的哈希方法，用于重要数据，如密码。

我们在本章开头使用 artisan 工具创建应用程序密钥的类用于加盐。因此，要应用迁移，我们需要使用以下 artisan 命令进行迁移：

```php
**php artisian migrate**

```

现在，检查`users`表是否有记录。如果你检查`password`列，你会看到记录存储如下：

```php
**$2y$08$ayylAhkVNCnkfj2rITbQr.L5pd2AIfpeccdnW6.BGbA.1VtJ6Sdqy**

```

安全地存储用户的密码和关键数据非常重要。不要忘记，如果你更改应用程序密钥，所有现有的哈希记录将无法使用，因为`Hash`类在验证和存储给定数据时使用应用程序密钥作为盐键。

# 创建一个仅会员可访问的区域

我们的博客系统是基于会员的。因此，我们需要一些区域只能会员访问，以便添加新的博客文章。我们有两种不同的方法来实现这一点。第一种是路由过滤器方法，我们将在接下来的章节中详细介绍。第二种是基于模板的授权检查。这种方法是更有效地理解`Auth`类与**Blade 模板系统**的使用方式。

通过`Auth`类，我们可以通过一行代码来检查访问者的授权状态：

```php
Auth::check();
```

基于`Auth`类的`check()`函数总是返回`true`或`false`。这意味着我们可以在我们的代码中轻松地在`if/else`语句中使用该函数。如你从之前的章节所知，使用 blade 模板系统，我们能够在模板文件中使用这种类型的 PHP 语句。

在创建模板文件之前，我们需要编写我们的路由。我们的应用程序需要四个路由。它们是：

+   创建一个登录路由来处理登录请求

+   创建一个处理新文章请求的新文章路由

+   一个用于显示新文章表单和登录表单的管理路由

+   一个用于列出文章的索引路由

命名路由是 Laravel 框架的另一个令人惊叹的特性，用于快速开发。命名路由允许在生成重定向或 URL 时更舒适地引用路由。你可以按以下方式为路由指定名称：

```php
Route::get('all/posts', array('as' => 'posts', function()
{
    //
}));
```

你也可以为控制器指定路由名称：

```php
Route::get('all/posts', array('as' => 'allposts', , 'uses' => 'PostController@showPosts'));
```

由于命名路由，我们可以轻松地为我们的应用程序创建 URL：

```php
$url = URL::route('allposts');
```

我们也可以使用命名路由进行重定向：

```php
$redirect = Redirect::route('allposts');
```

打开路由配置文件，位于`app/routes.php`，并添加以下代码：

```php
Route::get('/', array('as' => 'index', 'uses' => 'PostsController@getIndex'));
Route::get('/admin', array('as' => 'admin_area', 'uses' => 'PostsController@getAdmin'));
Route::post('/add', array('as' => 'add_new_post', 'uses' => 'PostsController@postAdd'));
Route::post('/login', array('as' => 'login', 'uses' => 'UsersController@postLogin'));
Route::get('/logout', array('as' => 'logout', 'uses' => 'UsersController@getLogout'));
```

现在我们需要编写应用程序的控制器端和模板的代码。首先，我们可以从我们的管理区域开始编码。让我们在`app/views/`下创建一个名为`addpost.blade.php`的文件。我们的管理模板应该如下所示：

```php
<html>
<head>
<title>Welcome to Your Blog</title>
<link rel="stylesheet" type="text/css" href="/assets/css/style.css">
<!--[if lt IE 9]><script src="//html5shim.googlecode.com/svn/trunk/html5.js"></script><![endif]-->
</head>
<body>
@if(Auth::check())
<section class="container">
<div class="content">
<h1>Welcome to Admin Area, {{Auth::user()->name}} ! - <b>{{link_to_route('logout','Logout')}}</b></h1>
<form name="add_post" method="POST" action="{{URL::route('add_new_post')}}">
<p><input type="text" name="title" placeholder="Post Title" value=""/></p>
<p><textarea name="content" placeholder="Post Content"></textarea></p>
<p><input type="submit" name="submit" /></p>
</div>
</section>
@else
<section class="container">
<div class="login">
<h1>Please Login</h1>
<form name="login" method="POST" action="{{URL::route('login')}}">
<p><input type="text" name="email" value="" placeholder="Email"></p>
<p><input type="password" name="password" value="" placeholder="Password"></p>
<p class="submit"><input type="submit" name="commit" value="Login"></p>
</form>
</div>
</section>
@endif
</body>
</html>
```

正如你在代码中所看到的，我们在模板中使用`if`/`else`语句来检查用户的登录凭据。我们从本节的开头就已经知道，我们使用`Auth::check()`函数来检查用户的登录状态。此外，我们还使用了一种新的方法来获取当前登录用户的名称：

```php
Auth::user()->name;
```

我们可以使用`user`方法获取关于当前用户的任何信息：

```php
Auth::user()->id; 
Auth::user()->email;
```

模板代码首先检查访问者的登录状态。如果访问者已登录，则模板显示一个新文章表单；否则显示一个登录表单。

现在我们需要编写博客应用程序的控制器端。让我们从我们的用户控制器开始。在 `app/controller/` 下创建一个名为 `UsersContoller.php` 的文件。控制器的最终代码应如下所示：

```php
<?php

class UsersController extends BaseController{

  public function postLogin()
  {
    Auth::attempt(array('email' => Input::get('email'),'password' => Input::get('password')));
  return Redirect::route('add_new_post');

  }

  public function getLogout()
  {
    Auth::logout();
    return Redirect::route('index');
  }
}
```

控制器有两个函数：第一个是 `postLogin()` 函数。该函数基本上检查用户登录的表单数据，然后将访问者重定向到 `add_new_post` 路由以显示新文章表单。第二个函数处理注销请求，并重定向到 `index` 路由。

# 保存博客文章

现在我们需要为我们的博客文章创建一个控制器。因此，在 `app/controller/` 下创建一个名为 `PostsContoller.php` 的文件。控制器的最终代码应如下所示：

```php
<?php
class PostsController extends BaseController{

  public function getIndex()
  {

  $posts = Post::with('Author')-> orderBy('id', 'DESC')->get();
  return View::make('index')->with('posts',$posts);

  }
  public function getAdmin()
  {
  return View::make('addpost');
  }
  public function postAdd()
  {
  Post::create(array(
              'title' => Input::get('title'),
              'content' => Input::get('content'),
              'author_id' => Auth::user()->id
   ));
  return Redirect::route('index');
  }
}
```

## 将博客文章分配给用户

`postAdd()` 函数处理数据库上的新博客文章创建请求。正如您所看到的，我们可以使用先前提到的方法获取作者的 ID：

```php
Auth::user()->id
```

使用这种方法，我们可以为当前用户分配一个博客文章。正如您将看到的，我们在查询中有一个新方法：

```php
Post::with('Author')->
```

如果您记得，我们在我们的 `Posts` 模型中定义了一个公共的 `Author()` 函数：

```php
public function Author(){

      return $this->belongsTo('User','author_id');
}
```

`belongsTo()` 方法是一个 `Eloquent` 函数，用于创建表之间的关系。基本上，该函数需要一个必需的变量和一个可选的变量。第一个变量（必需）定义了目标 `Model`。第二个可选变量用于定义当前模型表的源列。如果不定义可选变量，`Eloquent` 类会搜索 `targetModelName_id` 列。在 `posts` 表中，我们将作者的 ID 存储在 `author_id` 列中，而不是在名为 `user_id` 的列中。因此，我们需要在函数中定义第二个可选变量。使用这种方法，我们可以将博客文章及其所有作者的信息传递到模板文件中。您可以将该方法视为某种 SQL 连接方法。

当我们想在查询中使用这些关系函数时，我们可以轻松地调用它们如下所示：

```php
Books::with('Categories')->with('Author')->get();
```

使用较少的变量管理模板文件很容易。现在我们只需要一个变量来传递模板文件，其中包含所有必要的数据。因此，我们需要第二个模板文件来列出我们的博客文章。这个模板将在我们博客的前端工作。

# 列出文章

在本章的前几节中，我们已经学会了在 blade 模板文件中使用 PHP `if/else` 语句。Laravel 将数据作为数组传递到模板文件中。因此，我们需要使用 `foreach` 循环将数据解析到模板文件中。我们还可以在模板文件中使用 `foreach` 循环。因此，在 `app/views/` 下创建一个名为 `index.blade.php` 的文件。代码应如下所示：

```php
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>My Awesome Blog</title>
<link rel="stylesheet" href="/assets/blog/css/styles.css" type="text/css" media="screen" />
<link rel="stylesheet" type="text/css" href="/assets/blog/css/print.css" media="print" />
<!--[if IE]><script src="http://html5shiv.googlecode.com/svn/trunk/html5.js"></script><![endif]-->
</head>
<body>
<div id="wrapper">
<header>
<h1><a href="/">My Awesome Blog</a></h1>
<p>Welcome to my awesome blog</p>
</header>
<section id="main">
<section id="content">
@foreach($posts as $post)
<article>
<h2>{{$post->title}}</h2>
<p>{{$post->content}}</p>
<p><small>Posted by <b>{{$post->Author->name}}</b> at <b>{{$post->created_at}}</b></small></p>
</article>

@endforeach          
</section>
</aside>
</section>
<footer>
<section id="footer-area">
<section id="footer-outer-block">
<aside class="footer-segment">
<h4>My Awesome Blog</h4>
</aside>
</section>
</section>
</footer>
</div>
</body>
</html>
```

让我们来看看代码。我们在模板文件中使用了 `foreach` 循环来解析所有博客文章数据。此外，我们还在 `foreach` 循环中看到了组合作者数据的使用。正如您可能记得的那样，我们在模型端使用 `belongsTo()` 方法获取作者信息。整个关系数据解析都在一个名为关系函数名称的数组中完成。例如，如果我们有一个名为 `Categories()` 的第二个关系函数，那么在控制器端查询将如下所示：

```php
$books = Books::with('Author')-> with('Categories')->orderBy('id', 'DESC')->get();
```

`foreach` 循环如下所示：

```php
@foreach($books as $book)

<article>
<h2>{{$book->title}}</h2>
<p>Author: <b>{{$book->Author->name}}</b></p>
<p>Category: <b>{{$book->Category->name}}</b></p>
</article>

@endforeach
```

# 对内容进行分页

`Eloquent` 的 `get()` 方法在控制器端的 `Eloquent` 查询中使用，从数据库中获取所有数据。通常，我们需要对内容进行分页，以便用户友好的前端或减少页面加载和优化。`Eloquent` 类有一个快速执行此操作的有用方法，称为 `paginate()`。该方法获取分页数据并在模板中生成分页链接，只需一行代码。打开 `app/controllers/PostsController.php` 文件，并将查询更改为如下所示：

```php
$posts = Post::with('Author')->orderBy('id', 'DESC')->paginate(5);
```

`paginate()` 方法使用给定的数字值对数据进行分页。因此，博客文章将每页分页为 `5` 篇博客文章。我们还需要更改我们的模板以显示分页链接。打开 `app/views/index.blade.php`，并在 `foreach` 循环之后添加以下代码：

```php
{{$posts->links()}}
```

模板中具有 ID 为 "main" 的部分应如下所示：

```php
<section id="main">
<section id="content">
@foreach($posts as $post)

<article>
<h2>{{$post->title}}</h2>
<p>{{$post->content}}</p>
<p><small>Posted by <b>{{$post->Author->name}}</b> at <b>{{$post->created_at}}</b></small></p>
</article>
@endforeach

</section>
{{$posts->links()}}
</section>
```

`links()` 函数将自动生成分页链接，如果有足够的数据进行分页。否则，该函数不显示任何内容。

# 摘要

在本章中，我们使用 Laravel 的内置函数和 Eloquent 数据库驱动程序创建了一个简单的博客。我们学习了如何对数据进行分页以及 Eloquent 的基本数据关系机制。同时，我们也介绍了 Laravel 的内置身份验证机制。在接下来的章节中，我们将学习如何处理更复杂的表格和关联数据。
