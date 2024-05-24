# Laravel 入门指南（一）

> 原文：[`zh.annas-archive.org/md5/e93ac8af650aa246eabea26267ef0d7b`](https://zh.annas-archive.org/md5/e93ac8af650aa246eabea26267ef0d7b)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第一章：Laravel 入门

欢迎来到 Laravel 入门。本书专门为您提供了开始使用 Laravel Web 开发框架所需的所有信息。您将学习 Laravel 的基础知识，开始构建您的第一个 Web 应用程序，并发现一些使用 Laravel 的技巧和窍门。

本指南包含以下部分：

*那么，Laravel 是什么？* - 了解 Laravel 实际上是什么，您可以用它做什么，以及为什么它如此出色。

*安装* - 本节将帮助您开始使用 Laravel 进行编程。我们将介绍安装和基本配置，以便我们可以开始我们的应用程序！

*快速入门：创建您的第一个 Web 应用程序* - 让我们开始制作我们自己的应用程序。在本节中，我们将开发一个接收表单输入然后相应更新数据库的基本应用程序。

*您需要了解的前 5 个功能* - 在这里，我们将更深入地了解我们在*快速入门*部分中涵盖的内容。我们将更多地了解 Eloquent、身份验证、过滤器、验证和包。

*您应该了解的人和地方* - Laravel 社区是其最有力的教育资产之一。本节为您提供了有用的链接到项目页面和论坛，以及一些有用的文章、教程、博客和 Laravel 超级贡献者的 Twitter 动态。

# 那么，Laravel 是什么？

Laravel 是一个用 PHP 编写的 MVC Web 开发框架。它旨在通过减少初始开发成本和持续维护成本来提高软件质量，并通过提供清晰的表达语法和一组核心功能来改善与应用程序的工作体验，从而节省您数小时的实现时间。

Laravel 的设计理念是使用约定优于配置。这意味着它会对你试图实现的目标做出智能的假设，因此在大多数情况下，你将能够用更少的代码实现你的目标。并非你将要处理的每个应用程序和数据库都是按照这些约定设计的。幸运的是，Laravel 足够灵活，可以与你的系统一起工作，无论它有多独特。

Laravel 的设计目标是在极简主义和功能性之间找到平衡点。更容易理解较小的代码库，而 Laravel 的所有实现解决方案都是以清晰、简单和优雅的方式进行的。长期以来，PHP 开发人员会发现 Laravel 的许多方面都很熟悉，因为它是 PHP 开发框架的演进。

Laravel 是为数不多的提供真正代码模块化的 PHP 框架之一。这是通过驱动程序和其包系统的组合实现的。驱动程序允许您轻松更改和扩展缓存、会话、数据库和身份验证功能。使用包，您可以打包任何类型的代码供自己重复使用或提供给 Laravel 社区的其他人使用。这非常令人兴奋，因为任何可以在 Laravel 中编写的东西都可以作为一个包进行打包，从简单的库到整个 Web 应用程序。Laravel 包网站允许您浏览社区构建的包，以及展示您自己的包。这是一个有价值的第三方库和子系统资源，可以极大地简化您的 Web 应用程序的开发。

Laravel 还提供了一套与数据库交互的尖端工具。数据库迁移使您能够轻松地以独立于平台的方式设计和修改数据库。然后可以针对 Laravel 支持的任何数据库类型（MySQL、PostgreSQL、MSSQL 和 SQLite）运行迁移，而不会出现兼容性问题。

Laravel 的 Fluent 查询构建器将不同数据库类型之间的差异抽象出来。使用它来构建和执行强大的查询。

Laravel 的 ActiveRecord 实现称为**Eloquent**。以面向对象的方式与数据库交互是现代标准。使用 Eloquent，我们可以创建、检索、更新和删除数据库记录，而无需编写一行 SQL。除此之外，Eloquent 还提供强大的关系管理，甚至可以自动处理分页。

Laravel 还附带了一个名为**Artisan**的命令行界面工具。使用 Artisan，开发人员可以与他们的应用程序交互，触发诸如运行迁移、运行单元测试和运行定时任务等操作。Artisan 也是完全可扩展的，因此您可以编写任何类型的功能。Laravel 易于管理的路由系统允许您轻松管理站点的 URL。通过使用内置的 HTML 助手，您可以在站点内创建链接，如果更改 URL，它们将自动更新，从而使维护站点的工作变得更加容易。

Blade 模板引擎通过提供美观的替代方案来清理视图中的内联 PHP，并包含强大的新功能。

# 安装

通过五个简单的步骤，您可以安装 Laravel 并在系统上设置它。

## 第 1 步 - 我需要什么？

在安装 Laravel 之前，您需要检查是否具有以下所需元素：

+   Laravel 需要一个 Web 服务器环境，并且可以在 Apache、IIS 和 Nginx 中轻松运行。Laravel 应该在支持 PHP 的任何服务器环境中运行。为了开发设置本地 Web 服务器的最简单方法是在 Windows 上安装 XAMPP，Mac OSX 上安装 MAMP，或者通过 Linux 上的软件包管理器安装带有 PHP5 的 Apache。

+   Laravel 是用 PHP 脚本语言编写的。目前，Laravel v3.2.5 需要最低 PHP v5.3 才能运行。

+   Laravel 要求您安装 FileInfo 和 Mcrypt 库。方便的是，它们几乎总是默认安装的。

+   对于我们的 QuickStart 应用程序，我们需要一个数据库。默认情况下，Laravel 支持 MySQL、MSSQL、PostgreSQL 和 SQLite。

## 第 2 步 - 下载 Laravel

下载 Laravel 的最简单方法是从[`laravel.com/download`](http://laravel.com/download)下载压缩包。

或者，您可以通过以下命令从[GitHub.com](http://GitHub.com)克隆其`git`存储库来下载 Laravel。

```php
**git clone git@github.com:laravel/laravel.git**

```

最好下载最新的稳定版本。

将压缩包的内容提取到存储 Web 应用程序的目录中。典型的位置包括`/Users/Shawn/Sites`，`c:\sites`和`/var/www/vhosts/`，具体取决于您的操作系统。

我们假设您的第一个 Laravel 安装在`c:\sites\myfirst\`中。

## 第 3 步 - 配置主机

让我们继续设置我们的 Web 服务器来托管我们的站点。我们需要为我们的示例应用程序选择一个主机名。这是我们的第一个应用程序，我们正在使用本地开发环境，所以让我们使用`http://myfirst.dev?`。

在 Linux 和 OSX 中，只需将以下行添加到您的`/etc/hosts`文件中：

```php
127.0.0.1 myfirst.dev
```

Windows 用户应将该行添加到其`c:\windows\system32\drivers\etc\hosts`文件中。

现在您应该能够 ping `myfirst.dev`并看到它解析为`127.0.0.1`。

## 第 4 步 - 设置您的 VirtualHost

现在我们有了一个主机名，我们需要告诉我们的 Web 服务器在哪里找到 Laravel 安装。将以下`VirtualHost`配置添加到您的 Apache Web 服务器配置中，并将`DocumentRoot`替换为您的 Laravel 安装的 public 目录的路径。

```php
<VirtualHost *:80>
  ServerName myfirst.dev
  DocumentRoot c:/sites/myfirst/public
</VirtualHost>
```

非常重要的一点是`DocumentRoot`指向 Laravel 的 public 目录。这有多个安全原因。短暂的服务器配置错误可能会暴露安全信息，例如您的数据库密码。

## 第 5 步 - 重新启动 Web 服务器并进行测试

现在您已经安装了 Laravel 文件，添加了主机声明，并更新了 Web 服务器配置，您已经准备好了！重新启动您的 Web 服务器软件，然后在浏览器中转到`http://myfirst.dev`。您应该看到 Laravel 的欢迎页面！

## 就是这样！

到这一点，您应该已经安装了 Laravel，并可以自由地玩耍并发现更多关于它的内容。

# 快速开始：创建您的第一个 Web 应用程序

在本节中，我们将构建一个用户管理工具。用户管理员是 Web 应用程序中最常见的组件之一。他们还使用了一些我们想要用 Laravel 探索的重要系统，包括数据库交互、表单和路由。

我们将从数据库中存储和检索记录，现在是您为此应用程序创建数据库的好时机。记住数据库名称、用户名和密码。

让我们开始吧。

## 步骤 1 - 数据库配置

有了数据库名称、用户名和密码，我们现在可以告诉 Laravel 如何连接到我们的数据库。

打开文件`application/config/database.php`并扫描内容。您将找到每个数据库驱动程序的示例配置。确定您将从可用选项（`sqlite`、`mysql`、`pgsql`和`sqlserv`）中使用哪个驱动程序，并将驱动程序的名称输入为默认数据库连接。

然后，在**Connections**部分添加您的数据库名称、用户名和密码。

好了！我们现在就要开始创建用户表了。

## 步骤 2 - 使用迁移创建用户表

通常情况下，您可以使用诸如 phpMyAdmin 或 Navicat 之类的工具创建用户表。但是，Laravel 为我们提供了一个漂亮的迁移系统，我们应该使用它，因为它可以改善我们的工作流程并减少部署错误。

**迁移**是用于模式修改的版本控制。迁移通过要求我们仅定义一次模式更改来减少我们面临的麻烦。之后，我们可以将更改部署到任意数量的系统，而不会出现人为错误的可能性。

### 注意

迁移对于与他人合作的项目特别有用。与使用源代码控制一样，迁移总是一个好主意。

对于迁移还不熟悉的开发人员可能会认为它们是不必要的，或者认为它们一开始增加了太多额外的工作。但是，请坚持下去，它们的价值将很快显现。

让我们从使用 Laravel 的命令行工具 Artisan 创建我们的迁移模板开始。

为了使用 Artisan，我们需要将包含 PHP 二进制文件的目录添加到我们的`PATH`环境变量中。这样可以让我们从任何地方执行 PHP 二进制文件，因为系统会知道在哪里找到它。您可以通过从命令行终端运行以下命令来测试：

```php
**# php -v** 

```

您应该看到一个很好的输出，告诉您正在运行哪个版本的 PHP。

如果您发现您的命令行界面不知道 PHP 二进制文件在哪里，您需要更新系统的`PATH`。您可以使用以下命令行在 OS X 和 Linux 上修改您的`PATH`变量：

```php
**# export PATH=/path/to/php/binary:$PATH**

```

Windows 用户需要右键单击开始菜单中的**计算机**，然后单击**属性**。单击**高级系统设置**，然后单击**环境变量**。在这里，您可以找到系统变量`PATH`并添加包含您的 PHP 二进制文件的目录。

现在 PHP 二进制文件已经在我们的路径中，让我们导航到我们的`project`文件夹。现在我们可以继续安装我们的迁移数据库表。执行以下命令：

```php
**# php artisan migrate:install**

```

您应该看到消息，**成功创建迁移表**。如果出现错误，请验证您的数据库连接信息是否正确。

接下来，让我们在`application/migrations`文件夹中创建一个新的迁移模板。

```php
**# php artisan migrate:makecreate_users_table**

```

迁移文件的格式是年、月、日、时间和你添加的文本，使其可以被人识别，比如`create_users_table`。我的看起来像`2012_08_16_112327_create_users_table.php`。文件名的结构很重要，因为它帮助 Laravel 理解应该以什么顺序运行迁移。通过使用命名迁移的约定，你将帮助你的团队更好地理解你的工作（反之亦然）。一个例子约定可能包括`create_users_table`、`add_fields_to_users_table`或`rename_blog_posts_table_to_posts`。

迁移文件包含一个具有我们之前输入的人类可读名称的单个类。该类有两个方法，`up()`和`down()`。

当迁移运行时，Laravel 会逐个读取每个迁移文件并运行其`up()`方法。如果你觉得出现了错误，你可以回滚迁移。回滚更改时，Laravel 会运行`down()`方法。`up()`方法用于对数据库进行所需的更改。`down()`方法用于撤销更改。

让我们来看看我们的`create_users_table migration`应该是什么样子的：

```php
classCreate_Users_Table
{

  /**
  * Make changes to the database.
  *
  * @return void
  */
  public function up()
  {
    Schema::table('users', function($table)
    {
      $table->create();

      $table->increments('id');

      $table->string('email');
      $table->string('real_name');
      $table->string('password');

      $table->timestamps();
    });
  }

  /**
  * Revert the changes to the database.
  *
  * @return void
  */
  public function down()
  {
    Schema::drop('users');
  }

}
```

让我们首先讨论我们的`up()`方法。我们的目标是创建`users`表并定义其中的字段。为了实现这个目标，我们将使用 Laravel 的`Schema`类。在创建或修改表时，我们使用`Schema`类的`table()`方法。

`Schema::table()`接受两个参数。第一个是你将要交互的表的名称，在这种情况下是`users`。第二个参数是一个包含你的表定义的闭包。闭包接收参数`$table`，这是我们将要与之交互来定义表的对象。

```php
$table->create();
```

这一行告诉 Laravel 需要创建表。如果我们省略这一行，`Schema`将生成`ALTER TABLE`语法而不是`CREATE TABLE`语法。

```php
$table->increments('id');
```

`increments()`方法告诉`Schema`指定的字段应该是自增的主键。在 Laravel 中，你应该使用简单的字段名，比如`id`、`email`和`password`。如果你不熟悉使用**对象关系映射**（**ORM**），你可能习惯于使用表名作为前缀创建相同的字段名。例如，`user_id`、`user_email`、`user_password`。定义字段名时使用表名作为前缀的目的是在使用查询构建器时简化查询生成。这已经不再必要，最好遵循更简单的约定，因为它会为你管理冗余的交互，省去了你不断编写样板代码的需要。

```php
$table->string('email');
$table->string('real_name');
$table->string('password');
```

接下来我们有一些字符串声明。这些将被创建为默认长度为`200`的`VARCHAR`字段。你可以通过传递表示预期长度的第二个参数来覆盖这些字段的长度。例如：

```php
$table->string('email', 300);
```

这一行创建了一个名为`email`的`VARCHAR`字段，长度为`300`。

### 注意

重要的是要注意，我们不应该减小`password`字段的大小，因为我们将需要这个长度来输出 Laravel 的`Hash`类。

```php
$table->timestamps();
```

最后，我们来看看`timestamps()`方法。这将创建两个`DATETIME`字段（`created_at`和`updated_at`）。为数据库中的每个表创建`timestamp`字段并不是不合理的，因为它们在以后的故障排除中可能非常有用。Eloquent ORM 将自动为我们管理这些`timestamp`字段。所以，我们现在可以暂时忘记它们。

`down()`方法应该撤销`up()`方法所做的任何更改。在这种情况下，`up()`方法创建了一个名为 users 的数据库表。因此，`down()`方法应该删除该表。

```php
Schema::drop('users');
```

这是通过`Schema::drop()`方法完成的。`drop()`接受一个参数，一个包含你希望删除的表名的字符串值。

就是这样！我们有了我们的第一个迁移。一旦您记住了常用方法，比如 `increments()`、`string()`、`decimal()`、`timestamps()` 和 `date()`，您将能够像使用首选的数据库管理工具修改数据库一样快速地进行迁移。但是，现在我们在版本化和协作情况下使用它们时，还能获得额外的好处。

现在，我们准备运行我们的迁移。从现在开始，运行迁移将始终以相同的方式进行。让我们试一试：

```php
**# php artisan migrate**

```

现在，我们应该看到消息，**迁移：2012_08_16_112327_create_users_table**。

测试我们的迁移非常重要。如果我们不测试我们的迁移，当我们需要回滚迁移并遇到错误时，它可能会在项目后期出现问题。正确的迁移测试验证了 `up()` 和 `down()` 方法都按预期运行。

要测试 `up()` 方法，请运行迁移并打开您首选的数据库管理应用程序。然后，验证一切是否如您所期望的那样。然后，通过回滚迁移并执行相同的操作来测试 `down()` 方法。现在通过以下命令回滚您的迁移：

```php
**# php artisan migrate:rollback**

```

理想情况下，您将收到迁移成功回滚的通知。仔细检查您的数据库是否不再包含 `users` 表。就是这样！这个迁移已经准备就绪。运行您的迁移最后一次，然后我们继续下一步。

```php
**# php artisan migrate**

```

## 第三步 - 创建一个 Eloquent 用户模型

现在我们已经创建了我们的 `users` 表，我们应该继续创建我们的用户模型。在 MVC 的上下文中，模型是代表各种类型数据交互的类。数据可以包括存储在数据库中的信息，如用户、博客文章和评论，或与许多其他类型的数据源进行交互，如文件、表单或 Web 服务。就本文档而言，我们主要将使用模型来表示我们在数据库中存储的数据。

模型位于 `application/models` 文件夹中。所以继续创建文件 `application/models/user.php`，其中包含以下代码：

```php
class User extends Eloquent
{

}
```

这就是我们需要的全部！这告诉 Laravel 我们的用户模型代表 users 表中的数据。等等！Laravel 是如何知道的呢？嗯，因为我们当然遵循了 Laravel 的约定！我们的数据库表 `users` 是复数形式，因为它表示存储多个用户记录。模型类名为 `User` 是单数形式，因为它代表 users 表中的单个用户记录。`User` 类名首字母大写，因为类名使用帕斯卡命名法的标准。如果您的数据库表名为 `user_profiles`，您的模型类名将是 `UserProfile`。

我们可以看到使用约定可以避免我们不得不进行大量配置。那么，如果我们必须使用不遵循约定的数据库表怎么办？没问题！我们只需手动定义表名。只需将以下行添加到 `User` 类中：

```php
public static $table = 'my_users_table';
```

这就是全部。现在，Laravel 知道在与这个模型交互时，应该使用名为 `my_users_table` 的表。在必要时，Laravel 中的大多数约定都可以通过配置进行覆盖。

有一件重要的事情我们应该添加到我们的用户模型中。我们正在存储用户的电子邮件地址、真实姓名和密码。我们希望确保用户的密码不是以明文存储的。我们需要在将密码存储到数据库之前对其进行哈希处理。为此，我们将创建一个 setter。

**setter** 是拦截属性赋值的方法。在这种情况下，我们将拦截密码属性的赋值，对接收到的值进行哈希处理，然后将哈希值存储在数据库中。

让我们看一些代码。

```php
class User extends Eloquent
{
  public function set_password($string)
  {
    $this->set_attribute('password', Hash::make($string));
  }
}
```

如您所见，声明 setter 的约定是使用 `set_` 前缀加上您想要拦截赋值的属性的名称。用户的密码将作为参数 `$string` 传递给 setter。

我们使用`set_attribute()`方法将用户密码的哈希版本存储到模型中。通常情况下，`set_attribute()`方法是不必要的。但是，我们不希望我们的 setter 陷入无休止的循环，因为我们不断尝试分配`$this->password`。`set_attribute()`方法接受两个参数。第一个是属性的名称，第二个是我们要分配给它的值。使用`set_attribute()`分配值时，不会调用 setter 方法，数据将直接在模型中进行修改。

我们使用 Laravel 的`Hash`类的`make()`方法来创建用户密码的盐哈希。

## 步骤 4 - 路由到闭包

在我们继续测试用户模型之前，我们需要了解一些关于 Laravel 中路由的知识。**路由**是将 URL 链接到应用程序中的函数的行为。在 Laravel 中，可以通过两种方式进行路由。您可以路由到闭包或控制器操作。由于我们稍后将更详细地讨论控制器，让我们先看看如何路由到闭包。在 Laravel 中，路由在`application/routes.php`中声明。这个文件将表示您站点的 URL 和包含站点应用逻辑的函数之间的连接。这非常方便，因为其他开发人员可以通过查看这个文件来了解请求是如何路由的。

以下是路由到闭包的一个简单示例：

```php
Route::get('test', function(){
  return "This is the test route.";
});
```

我们使用`Route::get()`方法来定义路由。`Route::get()`注册一个闭包，专门响应指定 URI 的`GET`请求。要为`POST`、`PUT`和`DELETE`请求注册闭包，您可以分别使用`Route::post()`、`Route::put()`和`Route::delete()`。这些方法对应于通常被称为**HTTP 动词**的内容。

通常，开发人员只与`GET`和`POST`请求进行交互。当用户单击链接或在地址栏中输入 URL 时，他们正在创建一个`GET`请求。当用户提交表单时，他们通常会创建一个`POST`请求。

`Route::get()`方法的第一个参数是路由的 URI（域名后的 URL 部分），第二个参数是包含所需应用逻辑的闭包。

让我们更新示例并测试路由。

### 注意

请注意，我们不是使用 echo 来输出字符串，而是返回它。这是因为无论您路由到闭包还是路由到控制器操作，您都应该始终返回响应。这使得 Laravel 能够以强大的方式处理许多情况。

现在，继续导航到`http://myfirst.dev/test`。您将看到消息，**这是测试路由**。

## 步骤 5 - 使用 Eloquent 创建用户

现在，让我们测试`User`模型，并在此过程中了解一些关于 Eloquent 的知识。在这个应用程序中，我们将以几种方式与`User`模型进行交互。我们将使用用户记录的`Create`、`Retrieve`、`Update`和`Delete`方法。这些常见方法被称为**CRUD 方法**。

Eloquent 通过消除手动为模型实现 CRUD 方法来简化开发。如果您曾经在没有 ORM 的情况下设计模型，您就已经意识到这一点可以为大型网站节省许多时间。

现在，让我们探索创建新用户记录的各种方法。我们将重新利用上一步的测试路由来帮助我们了解 Eloquent。使用以下代码更新路由声明：

```php
Route::get('test', function()
{
  $user = new User;

  $user->email = "test@test.com";
  $user->real_name = "Test Account";
  $user->password = "test";

  $user->save();

  return "The test user has been saved to the database.";});
```

让我们回顾一下：

```php
$user = new User;
```

首先，我们创建了我们的`User`模型的一个新实例，并将其存储在`$user`变量中：

```php
$user->email = "test@test.com";
$user->real_name = "Test Account";
$user->password = "test";
```

然后，我们在我们的`User`模型中设置一些属性。这些属性直接对应于我们的用户数据库表中的字段。

```php
$user->save();
```

接下来，我们告诉 Eloquent 我们要将这个模型的内容保存到数据库中。

```php
return "The test user has been saved to the database.";
```

最后，我们将这个字符串输出到浏览器，这样我们就知道一切都很好。

继续在浏览器中导航到`http://myfirst.dev/test`。您应该会看到确认消息，用户已保存到数据库中。

现在，看一下您的数据库`users`表的内容。您会看到一个填满我们数据的新记录。请注意，`timestamps`字段已经自动预填充给您。使用 Eloquent 创建新的数据库记录就是这么简单！

## 第 6 步 - 用户控制器

现在是时候创建我们的第一个控制器了。您已经学会了如何路由到一个闭包，您可以使用这种方法来创建一个完整的 Web 应用程序。那么，控制器是什么，为什么我们应该使用它们呢？

控制器是包含与公共域相关的应用逻辑的方法的容器。域简单地是目的的分类。在我们的 Web 应用程序的上下文中，我们将仅仅处理管理用户数据。因此，我们的域是`users`。我们的`users`控制器将包含控制我们应用程序流程并将数据库数据传递到视图进行格式化的应用逻辑。

由于控制器允许我们对逻辑进行分组，我们还可以对控制器应用配置，以影响其中所有的方法。我们稍后会更多地探讨这个概念。

让我们创建文件`application/controllers/users.php`，并填充它与我们控制器类的骨架：

```php
<?php

class Users_Controller extends Base_Controller
{

  public function action_index()
  {
    return "Welcome to the users controller.";
  }

}
```

我们的`users`控制器是一个类，其名称是由其中包含的方法的域构成的，并以`_Controller`为后缀。由于这个控制器的域是用户帐户，我们的控制器被命名为`Users_Controller`。`_Controller`后缀是必需的，因为它可以防止控制器类与系统中的其他类发生名称冲突。

### 注意

控制器的域在适用时应该始终是复数形式。

您会注意到我们的`Users_Controller`类扩展了 Laravel 的默认`Base_Controller`类。这是一个很好的做法，因为如果我们需要一些代码或配置来影响所有的控制器，我们只需编辑文件`application/controllers/base.php`并对`Base_Controller`类进行更改。扩展`Base_Controller`类的每个控制器都会受到影响。

您还会注意到，我们已经定义了一个名为`index`的控制器动作。**控制器动作**是控制器类中的一个方法，我们打算将其作为路由的目的地。您可以决定在控制器类中创建只能从该类中的其他方法调用的方法；这些方法不会被视为动作。

控制器动作的名称以前缀`action_`命名。这是一个重要的区别，因为我们不希望用户能够访问控制器中不是动作的方法。

现在，我们有了这个控制器，我们如何从浏览器访问`index`动作呢？目前还不能。我们还没有将任何 URL 路由到该控制器动作。所以，让我们这样做。打开`application/routes.php`并添加以下行：

```php
Route::controller('users');
```

正如您所看到的，我们可以用一个命令将整个控制器注册到路由器中。现在，我们可以通过`http://myfirst.dev/users/index`访问我们的`users`控制器的`index`动作。`index`动作也被视为控制器的默认动作，因此我们也可以在`http://myfirst.dev/users`访问我们的`index`动作。

需要注意的是，虽然路由到闭包很方便，但通常认为路由到控制器是更好的做法，原因有几点。控制器直到它们的路由被访问时才会加载到内存中，这有助于减少应用程序的内存占用。它们还通过清晰地指出开发人员可以在哪里找到路由代码来简化维护。控制器是从一个基类派生的，因此在一个类中进行更改并通过继承使该更改影响其他类是很简单的。最后，由于控制器是按目的分组的动作，通常很方便根据每个控制器分配过滤器。我们将在*你需要了解的前 5 个功能*部分更多地讨论过滤器。

## 第 7 步 - 创建用户索引视图

现在我们可以去`http://myfirst.dev/users`并访问我们控制器的`index`方法。这很酷，但是我们的`users`控制器的`index`页面需要显示系统中的用户列表。为了显示用户列表，我们需要创建一个视图。

**视图**是一个包含格式化数据（通常是 HTML）的文件。在视图中使用 PHP 变量、条件和循环来显示和格式化动态内容。

Laravel 提供了自己的模板系统，称为**Blade**。Blade 去除了 PHP 标记，并提供了常见任务的快捷方式，使得视图更清晰、更容易创建和维护。

让我们开始创建文件夹`application/views/users/`。这个文件夹将存储我们`users`控制器的所有视图。按照惯例，为每个需要视图的控制器在`application/views`下创建一个文件夹。然后，在`application/views/users/index.blade.php`创建视图文件。按照惯例，视图文件的命名应该与控制器中使用的动作相同。在这个例子中，我们使用的是 Blade。如果你不想使用 Blade，只需将文件命名为`index.php`。

让我们用以下 HTML 填充视图：

```php
<h1>Users</h1>

<ul>
  <li>Real Name - Email</li>
</ul>
```

这不够美观。但是，很容易理解。

现在，我们将对`users`控制器的`index`动作进行修改：

```php
public function action_index()
{
  return View::make('users.index');
} 
```

现在，我们将返回一个 View 对象，而不是之前返回一个字符串。让我们更仔细地看看这里发生了什么。

`View`类的`make()`方法是一个工厂方法，用于生成 View 对象。在这种情况下，我们传递参数`users.index`。这是 Laravel 内部用于引用视图文件的表示法。这个表示法由视图文件相对于`application/views`目录的路径和不带文件扩展名的文件名组成。例如，`application/views/users/index.php`会被写成`users.index`，`application/views/admin/users/create.php`会被写成`admin.users.create`。

### 注意

需要注意的是，我们返回了 View 对象，而不是使用 echo 将视图的渲染内容发送到浏览器。这是 Laravel 工作方式的一个重要方面。我们永远不会在路由闭包或控制器动作中使用 echo。相反，我们总是返回结果，并允许 Laravel 适当处理事情。

现在，当我们访问`http://myfirst.dev/users`时，我们将看到我们刚刚创建的视图！

## 第 8 步 - 从控制器传递数据到视图

我们可以通过 URL 访问并查看我们创建的视图文件，这很酷。但是，我们需要能够看到来自我们数据库的用户列表。为了实现这个目标，我们将首先从控制器动作查询`User`模型，然后将数据传递给视图。最后，我们将更新我们的视图以显示从控制器接收的用户数据。

让我们开始更新我们的`users`控制器的`index`动作：

```php
public function action_index()
{
  $users = User::all();

  return View::make('users.index')->with('users', $users);
}
```

让我们逐行看一下：

```php
$users = User::all();
```

首先，我们从 Eloquent 请求所有用户作为对象。如果我们的`users`表中没有行，`$users`将是一个空数组。否则，`$users`将是一个对象数组。这些对象是我们`User`类的实例化。

```php
return View::make('users.index')->with('users', $users);
```

然后，我们稍微修改了我们的`View`对象的创建。我们链式调用了一个名为`with()`的新方法。`with()`方法允许我们将数据从控制器传递到视图。这个方法接受两个参数。第一个参数是将在视图中创建的变量的名称。第二个参数将是该变量的值。

总结一下，我们已经查询了数据库中的所有用户，并将它们作为`User`对象数组传递给了视图。由于`users`是`with()`方法的第一个参数，所以`User`对象数组将在视图中作为变量`$users`可用。

## 第 9 步 - 将动态内容添加到视图中

现在我们的视图可以访问用户数据了，让我们更新视图，这样我们就可以真正看到这些用户了。

```php
<h1>Users</h1>

@if($users)
  <ul>
    @foreach($users as $user)
      <li>{{ $user->real_name }} - {{ $user->email }}</li>
    @endforeach
  </ul>
@else
  Looks like we haven't added any users, yet!
@endif
```

Blade 易于理解，并且产生了更加优雅的代码。`{{ }}`标签输出其中的表达式的结果，并替换了典型的 echo 命令。其他构造，如`if()`、`foreach()`和`for()`是一样的，但没有 PHP 标签，并且前面有一个`@`。

### 注意

Blade 不会产生显著的性能损耗，因为它会渲染到原始的 PHP 缓存中。只有在有更改时才会对 Blade 模板进行解析。

还需要注意的是，你仍然可以在 Blade 模板中自由使用 PHP 标签。

如你所见，我们使用一个 if 语句来检查`$users`数组是否包含数据。如果包含，我们就循环遍历用户并为每个用户显示一个新的列表项。如果`$users`数组不包含任何数据，我们就输出一条相应的消息。

就是这样！保存文件并在浏览器中重新加载，你会看到我们创建的测试账户。

### 注意

现在可能是一个很好的时机，通过`test`路由来玩弄 HTML 或添加新用户，以更好地了解一切是如何工作的。

## 第 10 步 - RESTful 控制器

我们已经提到 Laravel 的路由系统使你能够将`GET`、`POST`、`PUT`和`DELETE`请求路由到闭包。但我们还没有讨论如何将它们分别路由到控制器操作。

答案就是 RESTful 控制器！RESTful 控制器使你能够根据请求方法路由到不同的控制器操作。让我们配置我们的应用程序使用 RESTful 控制器。

由于我们所有的控制器类都是从`Base_Controller`类派生的，我们只需为其添加`$restful`配置，所有的控制器都会受到影响。

将你的`Base_Controller`类更新为如下所示：

```php
classBase_Controller extends Controller{
  public $restful = true;

  /**
  * Catch-all method for requests that can't be matched.
  *
  * @param  string    $method
  * @param  array     $parameters
  * @return Response
  */
  public function __call($method, $parameters)
  {
    return Response::error('404');
  }

}
```

现在，每个继承`Base_Controller`（包括我们自己的`Users_Controller`）的控制器都是 RESTful 控制器！

但是，等等。现在，当我们访问`http://myfirst.dev/users`时，我们会得到一个 404 错误。这是因为我们没有以 RESTful 的方式声明我们的操作。

编辑你的`Users_Controller`类并更改这一行：

```php
public function action_index()
```

改为：

```php
public function get_index()
```

你的`Users_Controller`类现在应该是这样的：

```php
classUsers_Controller extends Base_Controller
{

  public function get_index()
  {
    $users = User::all();

    return View::make('users.index')->with('users', $users);
  }

}
```

现在，当我们保存并在浏览器中重新加载页面时，它又可以正常工作了！我们添加到`index`方法的`get_ 前缀`与我们之前使用的`action_ 前缀`有着相同的作用。

除非一个方法被适当地前缀，否则 Laravel 不会将 URL 路由到它们。通过这种方式，我们可以确保只有控制器操作是可路由的，我们的 Web 应用程序用户不能通过简单地在浏览器中输入方法的名称来访问控制器中可能存在的其他方法。

当一个操作以`get_`前缀时，它只会响应`GET`请求。以`post_`前缀开头的操作只会响应`POST`请求。`put_`和`delete_`也是一样的。这给了我们更多的代码分离，并允许我们真正提高应用程序的可读性和可维护性。

## 第 11 步 - 创建一个添加用户的表单

现在是时候让我们的网站管理员有能力创建用户了。我们需要一个新的表单。让我们首先创建文件`application/views/users/create.php`，并填充以下表单 HTML：

```php
<h1>Create a User</h1>

<form method="POST">
  Real Name: <input type="text" name="real_name"/><br />
  Email: <input type="text" name="email"/><br />
  Password: <input type="password" name="password" /><br />
  <input type="submit" value="Create User"/>
</form>
```

然后，让我们为其创建一个控制器操作。在我们的`Users_Controller`中，让我们添加以下操作。

```php
public function get_create()
{
  return View::make('users.create');
}
```

现在，我们可以转到`http://myfirst.dev/users/create`并查看我们的表单。再次，它不太漂亮，但有时简单是最好的。

## 第 12 步 - 将 POST 请求路由到控制器操作

当我们提交表单时，它将向我们的应用程序发出`POST`请求。我们还没有创建任何操作来处理`POST`请求，因此如果现在提交它，我们将收到 404 错误。让我们继续在`Users_Controller`中创建一个新的操作：

```php
public function post_create()
{
  return "The form has been posted here.";
}
```

请注意，此方法与我们用于显示创建用户表单的`get_create()`方法具有相同的操作名称。唯一的区别是前缀不同。`get_create()`方法响应`GET`请求，而`post_create()`方法响应`POST`请求。在我们创建用户表单的情况下，`post_create()`方法接收表单提交的输入字段的内容。

继续提交创建用户表单，您将看到消息**表单已在此处发布**。

## 第 13 步 - 接收表单输入并保存到数据库

现在我们正在从表单接收数据，我们可以继续创建用户帐户。

让我们更新我们`Users_Controller`类中的`post_create()`函数以添加此功能：

```php
public function post_create()
{
  $user = new User;

  $user->real_name = Input::get('real_name');
  $user->email = Input::get('email');
  $user->password = Input::get('password');

  $user->save();

  return Redirect::to ('users');
}
```

在这里，我们以与我们在`test`路由中所做的方式创建新用户记录。唯一的区别是我们使用 Laravel 的`Input`类从表单中检索数据。无论数据来自`GET`请求的查询字符串还是`POST`请求的提交数据，都可以使用`Input::get()`方法来检索数据。

我们用输入数据填充`User`对象。然后我们保存新用户。

```php
return Redirect::to('users');
```

这里有一些新东西。我们不是返回一个字符串或`View`对象，而是使用`Redirect`类返回一个`Response`对象。路由闭包和控制器操作都应返回一个响应。该响应可以是一个字符串或`Response`对象。当返回一个`View`对象时，它将被呈现为一个字符串。`Redirect`类的`to()`方法明确告诉 Laravel 将用户重定向到其参数中指定的页面。在这个例子中，用户将被重定向到`http://myfirst.dev/users`。

我们在这里重定向用户，以便他们可以看到更新后的用户列表，其中将包括他们刚刚创建的用户。继续尝试一下！

## 第 14 步 - 使用 HTML 辅助程序创建链接

我们需要从用户索引视图到创建用户表单的链接，因为它目前无法从用户界面访问。继续并在文件`application/views/users/index.blade.php`中添加以下代码行的链接：

```php
{{ HTML::link('users/create', 'Create a User') }}
```

Laravel 的`HTML`类可用于创建各种 HTML 标记。您可能会问自己为什么不直接自己编写链接的 HTML。使用 Laravel 的 HTML 辅助类的一个非常好的理由是它提供了一个统一的接口来创建可能需要动态更改的标记。让我们看一个例子来澄清这一点。

假设我们希望该链接看起来像一个按钮，我们的设计师创建了一个名为`btn`的漂亮 CSS 类。我们需要更新对`HTML::link()`的调用以包括新的 class 属性：

```php
{{ HTML::link('users/create', 'Create a User', array('class' => 'btn')) }}
```

实际上，我们可以为该类包含任意数量的属性，并且它们都将得到适当处理。可以通过将变量传递给该方法来动态更新 HTML 元素分配的任何属性，而不是在内联中声明它。

```php
<?php $create_link_attributes = array('class' => 'btn'); ?>

{{ HTML::link('users/create', 'Create a User', $create_link_attributes) }}
```

## 第 15 步 - 使用 Eloquent 删除用户记录

现在我们可以添加用户，我们可能想要做一些清理。让我们在我们的`users`控制器中添加一个删除操作。

```php
public function get_delete($user_id)
{
  $user = User::find($user_id);

  if(is_null($user))
  {
    return Redirect::to('users');
  }

  $user->delete();

  return Redirect::to('users');
}
```

现在，让我们逐步进行。

```php
public function get_delete($user_id)
```

这是我们在控制器操作中第一次声明参数。为了删除用户，我们需要知道要删除哪个用户。由于我们使用了`Route::controller('users')`让 Laravel 自动处理我们控制器的路由，它会知道当我们访问 URL`http://myfirst.dev/users/delete/1`时，应该路由到删除操作，并将附加的 URI 段作为参数传递给方法。

如果您想从 URL 接收第二个参数（例如`http://myfirst.dev/users/delete/happy`），您可以将第二个参数添加到您的操作中，如下所示：

```php
public function get_delete($user_id, $emotion)
```

接下来，我们需要验证具有指定用户 ID 的用户是否实际存在。

```php
$user = User::find($user_id);
```

这一行告诉 Eloquent 查找 ID 与参数匹配的用户。如果找到用户，`$user`变量将被填充为我们`User`类的实例对象。如果没有找到，`$user`变量将包含一个空值。

```php
if(is_null($user))
{
  return Redirect::to('users');
}
```

在这里，我们正在检查我们的用户变量是否具有空值，表明请求的用户未找到。如果是这样，我们将重定向回`users`索引。

```php
$user->delete();
return Redirect::to('users');
```

接下来，我们删除用户并重定向回`users`索引。

当然，我们的工作还没有完成，直到我们更新我们的`application/views/users/index.php`文件，以便给我们每个用户都有删除链接。用以下代码替换列表项代码：

```php
<li>{{ $user->real_name }} - {{ $user->email }} - {{ HTML::link('users/delete/'.$user->id, 'Delete') }}</li>
```

重新加载`users`索引页面，现在你会看到删除链接。点击它，然后会惊恐地发现我们已经从数据库中无法修复地删除了数据。希望这不是什么重要的东西！

## 第 16 步 - 使用 Eloquent 更新用户

所以，我们可以添加和删除用户，但是如果我们打错字了想要修正怎么办？让我们更新我们的`users`控制器，使用必要的方法来显示更新表单，然后检索其中的数据以更新用户记录：

```php
public function get_update($user_id)
{
  $user = User::find($user_id);

  if(is_null($user))
  {
    return Redirect::to('users');
  }

  return View::make('users.update')->with('user', $user);
}
```

这里有我们的新`get_update()`方法。这个方法接受一个用户 ID 作为参数。就像我们在`get_delete()`方法中所做的那样，我们需要从数据库中加载用户记录以验证其是否存在。然后，我们将把该用户传递给更新表单。

```php
public function post_update($user_id)
{
  $user = User::find($user_id);

  if(is_null($user))
  {
    return Redirect::to('users');
  }

  $user->real_name = Input::get('real_name');
  $user->email = Input::get('email');

  if(Input::has('password'))
  {
    $user->password = Input::get('password');
  }

  $user->save();

  return Redirect::to('users');	
}
```

当用户提交我们的更新表单时，他们将被路由到`post_update()`。

您可能已经注意到了接收用户 ID 作为参数的方法的一个共同主题。每当我们要与用户模型交互时，我们都需要确保数据库记录存在并且模型已填充。我们必须始终首先加载它并验证它不是空的。

之后，我们为`real_name`和`email`属性分配新值。我们不希望每次提交更改时都更改用户的密码。因此，我们首先要验证密码字段是否为空。如果密码字段为空，Laravel 的`Input`类的`has()`方法将返回`false`，如果属性没有在表单提交中发送，或者为空。如果不为空，我们可以继续更新模型中的属性。

然后，我们保存对用户的更改，并重定向回`users`索引页面。

## 第 17 步 - 使用表单助手创建更新表单

现在，我们只需要创建`update`表单，我们就会有一个完整的管理系统！

继续创建视图`application/views/users/update.blade.php`，并用这个可爱的表单填充它：

```php
<h1>Update a User</h1>

{{ Form::open() }}

  Real Name: {{ Form::text('real_name', $user->real_name) }}<br />
  Email: {{ Form::text('email', $user->email) }}<br />
  Change Password: {{ Form::password('password') }}<br />

{{ Form::submit('Update User') }}

{{ Form::close() }}
```

这几乎与创建表单完全相同，只是我们稍微混合了一些东西。首先，您会注意到我们正在使用 Laravel 的`Form`类助手方法。这些助手方法，就像`HTML`类的助手方法一样，不是强制性的。但是，它们是建议使用的。它们提供了许多与`HTML`类的助手方法相同的优势。`Form`类的助手方法提供了一个统一的接口来生成最终的 HTML 标记。通过将数组作为参数传递，以编程方式更新 HTML 标记属性要比循环生成 HTML 自己更容易得多。

```php
Real Name: {{ Form::text('real_name', $user->real_name) }}
```

文本字段可以通过传入第二个参数进行预填充。在这个例子中，我们正在传递从控制器传递的`user`对象的`real_name`属性。然后以相同的方式预填充`email`字段。

```php
Change Password: {{ Form::password('password') }}
```

请注意，我们没有预填充`password`字段。这样做是没有意义的，因为我们不会在数据库中存储密码的可读版本。不仅如此，为了防止开发人员犯错，`Form::password()`方法根本没有预填充这个字段的功能。

有了这个，我们就有了一个完全可用的更新用户表单！

# 你需要了解的前 5 个功能

当您开始使用 Laravel 时，您会意识到它提供了各种各样的功能。我们花时间描述了在*快速入门*部分中没有涵盖的五个最重要的组件。掌握这五个组件的能力使您有能力使用 Laravel 制作令人惊叹的 Web 应用程序。

## 1 – Eloquent 关系

Eloquent 是 Laravel 的本地 ActiveRecord 实现。它是建立在 Laravel 的 Fluent 查询构建器之上的。由于 Eloquent 与 Fluent 的操作方式，复杂的查询和关系很容易描述和理解。

**ActiveRecord**是一种描述与数据库交互的面向对象方式的设计模式。例如，您的数据库的`users`表包含行，每行代表您网站的一个用户。您的`User`模型是一个扩展了 Eloquent 模型类的类。当您从数据库查询记录时，将创建一个`User`模型类的实例，并用数据库中的信息填充它。

![1 – Eloquent relationships](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrv-st/img/0908OS_01_01.jpg)

ActiveRecord 的一个明显优势是，您的数据和与数据相关的业务逻辑都存储在同一个对象中。例如，将用户的密码存储在模型中作为哈希是典型的，以防止以明文形式存储。还典型的是，在您的`User`类中存储创建这个密码哈希的方法。

ActiveRecord 模式的另一个强大之处在于定义模型之间的关系的能力。想象一下，您正在构建一个博客网站，您的用户是必须能够发布他们的作品的作者。使用 ActiveRecord 实现，您能够定义关系的参数。然后，维护这种关系的任务大大简化了。简单的代码是易于更改的代码。难以理解的代码是易于破坏的代码。

作为 PHP 开发人员，您可能已经熟悉数据库规范化的概念。如果您不熟悉，**规范化**是设计数据库的过程，以便存储的数据中减少冗余。例如，您不希望既有一个包含用户姓名的`users`表，又有一个包含作者姓名的博客文章表。相反，您的博客文章记录将使用用户 ID 引用用户。通过这种方式，我们避免了同步问题和大量的额外工作！

在规范化的数据库模式中，有许多建立关系的方式。

### 一对一关系

当一个关系以不允许更多记录相关的方式连接两条记录时，它是一个**一对一关系**。例如，*user*记录可能与*passport*记录有一对一关系。在这个例子中，*user*记录不允许链接到多个*passport*记录。同样，*passport*记录也不允许与多个用户记录相关联。

数据库会是什么样子？您的`users`表包含数据库中每个用户的信息。您的`passports`表包含护照号码和拥有护照的用户的链接。

![一对一关系](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrv-st/img/0908OS_01_02.jpg)

在这个例子中，每个用户最多只有一个护照，每个护照必须有一个所有者。`passports`表包含自己的`id`列，它用作主键。它还包含`user_id`列，其中包含护照所属用户的 ID。最后，`passports`表包含护照号码的列。

首先，让我们在`User`类中建模这种关系：

```php
class User extends Eloquent
{
  public function passport()
  {
    return $this->has_one('Passport');
  }
}
```

我们创建了一个名为`passport()`的方法，它返回一个关系。一开始返回关系可能看起来有点奇怪。但是，你很快就会喜欢它所提供的灵活性。

你会注意到我们使用了`has_one()`方法，并将模型的名称作为参数传递。在这种情况下，用户有一个护照。因此，参数是护照模型类的名称。这就足够让 Eloquent 理解如何为每个用户获取正确的护照记录。

现在，让我们看一下`Passport`类：

```php
class Passport extends Eloquent
{
  public function users()
  {
    return $this->belongs_to('User');
  }
}
```

我们以不同的方式定义了护照的关系。在`User`类中，我们使用了`has_one()`方法。在`Passport`类中，我们使用了`belongs_to()`。

及早识别差异是至关重要的，这样理解其他关系就更简单了。当数据库表包含外键时，可以说它属于另一个表中的记录。在这个例子中，我们的`passports`表通过外键`user_id`指向`users`表中的记录。因此，我们会说护照属于用户。由于这是一对一关系，用户有一个（`has_one()`）护照。

![一对一关系](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrv-st/img/0908OS_01_03.jpg)

假设我们想查看`id`为`1`的用户的护照号码。

```php
$user = User::find(1);

If(is_null($user))
{
  echo "No user found.";
  return;
}

If($user->passport)
{
  echo "The user's passport number is " . $user->passport->number;
}
else
{
  echo "This user has no passport.";
}
```

在这个例子中，我们认真检查确保我们的`user`对象是否如预期返回。这是一个必要的步骤，不应忽视。然后，我们检查用户是否有与之关联的护照记录。如果用户存在护照记录，相关对象将被返回。如果不存在，`$user->passport`将返回`null`。在前面的例子中，我们测试记录的存在并返回适当的响应。

### 一对多关系

**一对多**关系类似于一对一关系。在这种关系类型中，一个模型有许多其他关系，这些关系反过来属于前者。一个一对多关系的例子是专业体育队与其球员的关系。一个团队有很多球员。在这个例子中，每个球员只能属于一个团队。数据库表具有相同的结构。

![一对多关系](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrv-st/img/0908OS_01_04.jpg)

现在，让我们看一下描述这种关系的代码。

```php
class Team extends Eloquent
{
  public function players()
  {
    return $this->has_many('Player');
  }
}

class Player extends Eloquent
{
  public function team()
  {
    return $this->belongs_to('Team');
  }
}
```

这个例子几乎与一对一的例子相同。唯一的区别是团队的`players()`关系使用`has_many()`而不是`has_one()`。`has_one()`关系返回一个模型对象。`has_many()`关系返回一个模型对象数组。

让我们显示特定团队的所有球员：

```php
$team = Team::find(2);

if(is_null($team))
{
  echo "The team could not be found.";
}

if(!$team->players)
{
  echo "The team has no players.";
}

foreach($team->players as $player)
{
  echo "$player->name is on team $team->name. ";
}
```

同样，我们测试确保我们能找到我们的团队。然后，我们测试确保团队有球员。一旦我们确定了这一点，我们就可以循环遍历这些球员并输出他们的名字。如果我们在没有先测试并且团队有球员的情况下尝试循环遍历球员，我们会得到一个错误。

### 多对多关系

我们要讨论的最后一种关系类型是多对多关系。这种关系不同之处在于每个表中的每条记录都可能同时与另一个表中的每条记录相关联。我们在这两个表中都没有存储外键。相反，我们有一个第三个表，它存在 solely 用于存储我们的外键。让我们看一下模式。

![多对多关系](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrv-st/img/0908OS_01_05.jpg)

这里有一个学生表和一个课程表。一个学生可以注册多门课程，一门课程可以包含多名学生。学生和课程之间的连接存储在一个中间表中。

**中间表**是一个专门用于连接两个表的表，特别是用于多对多关系。命名中间表的标准约定是将两个相关表的名称结合起来，单数化，按字母顺序排列，并用下划线连接起来。这给我们提供了表名`course_student`。这个约定不仅被 Laravel 使用，严格遵循本文档中涵盖的命名约定是一个很好的主意，因为它们在 Web 开发行业中被广泛使用。

重要的是要注意，我们没有为中间表创建模型。Laravel 允许我们管理这些表，而无需与模型交互。这特别好，因为用业务逻辑对中间表建模是没有意义的。只有学生和课程是我们业务的一部分。它们之间的连接很重要，但只对学生和课程重要。它本身并不重要。

让我们定义这些模型，好吗？

```php
class Student extends Eloquent
{
  public function courses()
  {
    return $this->has_many_and_belongs_to('Course');
  }
}

class Course extends Eloquent
{
  public function students()
  {
    return $this->has_many_and_belongs_to('Student');
  }   
}
```

我们有两个模型，彼此具有相同类型的关系。`has_many_and_belongs_to`是一个很长的名字。但是，这是一个相当简单的概念。一门课程有很多学生。但它也属于（`belongs_to`）学生记录，反之亦然。这样，它们被认为是相等的。

让我们看看我们将如何在实践中与这些模型交互：

```php
$student = Student::find(1);

if(is_null($student))
{
    echo "The student can't be found.";
    exit;
}

if(!$student->courses)
{
    echo "The student $student->name is not enrolled in any courses.";
    exit;
}

foreach($student->courses as $course)
{
    echo "The student $student->name is enrolled in the course $course->name.";
}
```

在这里，您可以看到我们可以以与一对多关系相同的方式循环遍历课程。每当一个关系包括单词*many*时，您就知道您将收到一个模型数组。相反，让我们拉取一个课程，看看哪些学生是其中的一部分。

```php
$course = Course::find(1);

if(is_null($course))
{
    echo "The course can't be found.";
    exit;
}

if(!$course->students)
{
    echo "The course $course->name seems to have no students enrolled.";
    exit;
}

foreach($course->students as $student)
{
    echo "The student $student->name is enrolled in the course $course->name.";
}
```

从课程方面，关系函数的工作方式完全相同。

既然我们已经建立了这种关系，我们可以用它做一些有趣的事情。让我们看看如何将新学生注册到现有课程中：

```php
$course = Course::find(13);

if(is_null($course))
{
    echo "The course can't be found.";
    exit;
}

$new_student_information = array(
    'name' => 'Danielle'
);

$course->students()->insert($new_student_information);
```

在这里，我们通过使用`insert()`方法向我们的课程添加一个新学生。这种方法是特定于这种关系类型的，并创建一个新的学生记录。它还向`course_student`表添加一条记录，以链接课程和新学生。非常方便！

但是，等等。这是什么新的语法？

```php
$course->students()->insert($new_student_information);
```

请注意我们没有使用`$course->students->insert()`。我们对学生的引用是一个方法引用，而不是属性引用。这是因为 Eloquent 处理返回关系对象的方法与其他模型方法不同。

当您访问模型的不存在的属性时，Eloquent 会查看是否有与该属性名称匹配的函数。例如，如果我们尝试访问属性`$course->students`，Eloquent 将无法找到名为`$students`的成员变量。因此，它将寻找名为`students()`的函数。我们有这样一个函数。然后 Eloquent 将从该方法接收关系对象，处理它，并返回结果的学生记录。

如果我们将关系方法作为方法而不是属性访问，我们将直接收到关系对象。关系的类扩展了`Query`类。这意味着您可以像操作查询对象一样操作关系对象，只是现在它有了特定于关系类型的新方法。具体的实现细节在这一点上并不重要。重要的是要知道我们正在从`$course->students()`返回的关系对象上调用`insert()`方法。

想象一下，您有一个用户模型，它有许多关系，并且属于一个角色模型。角色代表不同的权限分组。示例角色可能包括客户、管理员、超级管理员和超级管理员。

很容易想象一个用于管理其角色的用户表单。它将包含许多复选框，每个潜在角色一个。复选框的名称是`role_ids[]`，每个值代表角色表中的角色 ID。

当提交该表单时，我们将使用`Input::get()`方法检索这些值。

```php
$role_ids = Input::get('role_ids');
```

`$role_ids`现在是一个包含值`1`、`2`、`3`和`4`的数组。

```php
$user->roles()->sync($role_ids);
```

`sync()`方法是特定于此关系类型的，并且非常适合我们的需求。我们告诉 Eloquent 将我们当前的`$user`连接到存在于`$role_ids`数组中的角色。

让我们更详细地看一下这里发生了什么。`$user->roles()`返回一个`has_many_and_belongs_to relationship`对象。我们在该对象上调用`sync()`方法。Eloquent 现在查看`$role_ids`数组，并将其视为此用户的角色的权威列表。然后，它会删除不应存在于`role_user`中的记录，并为应存在于中的任何角色添加记录。枢纽表

## 2–身份验证

Laravel 帮助您处理典型的登录和注销用户的任务，以及轻松访问当前认证用户的`user`记录。

首先，我们将要为我们的网站配置身份验证。身份验证配置文件可以在`application/config/auth.php`中找到。

在这里，我们提供了许多配置选项。首先，我们必须选择使用哪个`Auth`驱动程序。如果我们选择 Fluent 驱动程序，认证系统将使用表配置选项来查找用户，并在我们请求当前认证用户时返回哑对象（仅包含数据的对象）。如果我们使用 Eloquent 驱动程序，认证系统将使用模型选项中列出的模型来查询用户，并在我们请求当前认证用户时，Laravel 将返回该模型的实例。此外，您可以通过更改用户名和密码选项来选择 Laravel 将对其进行身份验证的字段。通常，您将使用 Eloquent 驱动程序。

让我们继续从*快速入门*部分开始的示例。我们已经有一个`User`模型，所以让我们将驱动程序选项设置为 Eloquent。我们认为使用电子邮件地址和密码登录很好，因此我们将用户名选项设置为`email`，并将密码选项设置为`password`。我们还将模型设置为`User`。

就是这样，我们已经全部配置好了。让我们实现登录！首先，让我们为身份验证创建一个新的控制器。我们将把它存储在`application/controllers/auth.php`中。

```php
<?php

class Auth_Controller extends Base_Controller
{

  public function get_login()
  {
    return View::make('auth.login');
  }

}
```

我们需要路由这个，并且由于我们通常不想转到`http://myfirst.dev/auth/login`，让我们手动设置一个路由。将此添加到您的`application/routes.php`中。

```php
Route::any('login', 'auth@login');
```

最后，在`application/views/auth/login.blade.php`中创建一个登录表单：

```php
{{ Form::open() }}
  Email: {{ Form::text('email', Input::old('email')) }}<br />
  Password: {{ Form::password('password') }}<br />
  {{ Form::submit('Login') }}
{{ Form::close() }}
```

就是这样！现在，让我们只需将浏览器导航到`http://myfirst.dev/login`。我们看到了我们漂亮的新登录表单！

现在，我们只需要能够提交我们的表单。让我们向我们的`Auth`控制器添加一个新的操作：

```php
public function post_login()
{
  $credentials = array(
    'username' => Input::get('email'),
    'password' => Input::get('password'),
  );

  if(Auth::attempt($credentials))
  {
    return "User has been logged in.";
  }
  else
  {
    return Redirect::back()->with_input();
  }
}
```

通过添加这个方法，我们现在有了一个可用的登录表单。随时随地尝试一下吧！

让我们看看如何验证用户的电子邮件和密码。首先，我们创建一个包含从登录表单接收的凭据的数组。请注意，我们使用`username`和`password`键来存储电子邮件和密码。尽管我们使用电子邮件进行身份验证，但 Laravel 始终使用`username`和`password`键接收身份验证凭据。这是因为`username`和`password`字段可以在`auth config`文件中进行配置。

然后，我们将凭据传递给`Auth::attempt()`方法。此方法会处理其余的过程。它将比较我们在数据库中的记录与我们传递的凭据。如果凭据匹配，它将在用户的浏览器中创建一个 cookie，并且用户将正式登录。如果身份验证尝试失败，我们将用户重定向回表单并重新填充`email`字段。

现在，让我们添加`logout`功能。将以下方法添加到您的`Auth`控制器中：

```php
public function get_logout()
{
  Auth::logout();

  return Redirect::to('');
}
```

最后，将以下行添加到您的`routes.php`文件中：

```php
Route::get('logout', 'auth@logout');
```

就是这样！现在，当我们访问`http://myfirst.dev/logout`时，我们将注销并重定向到我们站点的首页。

那么，我们如何知道某人是否已登录？Eloquent 和 Fluent `Auth`驱动程序包含两种处理方法，`check()`和`guest()`。让我们依次看看每个：

+   `Auth::check()`如果用户当前已登录，则返回`true`，否则返回`false`。

+   `Auth::guest()`是`Auth::check()`的相反。如果用户已登录，则返回`false`，否则返回`true`。

一旦确保用户已登录，您可以使用`Auth::user()`返回用户记录。如果您使用 Fluent 驱动程序，`Auth::user()`将返回一个包含用户表中适当值的哑对象。如果您使用 Eloquent 驱动程序，`Auth::user()`将返回`User`模型的实例。这非常强大。让我们看一个例子：

```php
@if(Auth::check())
  <strong>You're logged in as {{ Auth::user()->real_name }}</strong>
@endif
```

如您所见，Laravel 的身份验证系统是基于驱动程序的。在本例中，我们使用了 Eloquent 驱动程序。但是，您还可以创建自定义身份验证驱动程序。这使您有能力使用不同的方式对用户进行身份验证，并使用标准`Auth`类的 API 返回不同类型的数据。开发自定义驱动程序超出了本文档的范围。但是，这很简单而且强大。请务必查阅 Laravel 文档以获取更多信息。

## 3 - 过滤器

现在我们有了一个带有身份验证的用户管理站点，我们需要将站点上的一些页面限制为成功验证的用户。我们将使用过滤器来实现这一点。

**过滤器**是可以在路由代码之前或之后运行的函数。在路由代码之前运行的过滤器称为**before 过滤器**。同样命名得很好的是**after 过滤器**，它在路由代码之后运行。

过滤器通常用于强制进行身份验证。我们可以创建一个检测用户是否未登录的过滤器，然后将其重定向到登录表单。实际上，我们根本不需要创建此过滤器。Laravel 已经预先编写了此过滤器。您可以在您的`application/routes.php`中找到它。

让我们来看一下：

```php
Route::filter('auth', function()
{
  if (Auth::guest()) return Redirect::to('login');
});
```

您可以看到，过滤器是使用`Route::filter()`方法注册的。存储过滤器注册的典型位置是在您的`application/routes.php`文件中。

`Route::filter()`方法接受两个参数。第一个是包含过滤器名称的字符串。第二个是在激活过滤器时运行的匿名函数。

在这个例子中，匿名函数将使用`Auth::guest()`方法检查用户是否已登录。如果用户未登录，则过滤器将返回一个响应对象，告诉 Laravel 将用户重定向到登录页面。

重要的是要注意，虽然您可以从 before 过滤器返回响应对象，但是从 after 过滤器重定向是不可能的，因为此时为时已晚。

现在我们有了`auth`过滤器，我们如何告诉 Laravel 何时运行它？正确的算法是情景性的。

以下是将过滤器应用于路由函数的示例：

```php
Route::get('admin', array('before' => 'auth', function()
{
  return View::make('admin.dashboard');
}));
```

在这个例子中，我们希望为成功验证的用户提供管理员仪表板。您可能注意到我们的`Route::get()`声明已经改变。我们的第一个参数仍然是路由的 URI。但是，我们的第二个参数不再是匿名函数，而是一个数组。这个数组提供了一个方法来配置我们的路由注册。Laravel 知道当您传递一个键值对时，它应该被用作配置，当您传递一个匿名函数时，它应该被用作路由的目标函数。

在这个例子中，我们只使用一个用于配置路由的键值对。我们使用键`before`告诉 Laravel 我们的路由使用一个前置过滤器。与`before`键关联的值是过滤器的名称，在我们的匿名函数执行之前应该运行。

![3 - 过滤器](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrv-st/img/0908OS_01_06.jpg)

控制器是一组可路由的方法，它们相似，因此非常方便进行过滤。通常，适用于控制器中一个操作的相同一组过滤器也适用于其余操作。在控制器级别进行过滤比在每个路由声明中定义过滤器具有更大的灵活性和更少的冗余。让我们来看看如何保护我们的`users`控制器。

```php
class Users_Controller extends Base_Controller
{

  public function __construct()
  {
    parent::__construct();

    $this->filter('before', 'auth');
  }
```

在这里，我们只看`users`控制器的顶部部分。控制器的其余部分与我们在*快速入门*部分中创建的内容相同。

正如您可能已经注意到的那样，我们为`Users_Controller`类声明了一个构造函数。构造函数是一种在我们的类被实例化为对象后立即运行的方法。我们使用控制器类的构造函数来为该控制器的操作定义过滤器。还要注意，我们首先调用`parent::__construct()`方法。对于 Laravel 的`Controller`类来说，执行其构造函数非常重要，以便它可以初始化自身并准备好进行操作。

然后，我们告诉我们的控制器，对于其所有操作的每个请求，我们都希望运行`auth`之前的过滤器。现在，这个控制器完全受到您的身份验证实现的保护。在成功登录之前，您将无法访问该控制器中的操作。如果尝试访问控制器的操作之一，将被重定向到登录页面。

现在，由于 Laravel 的`Auth`类和其`auth`过滤器的结合，您现在拥有一个完全安全的管理员网站。

不幸的是，Laravel 过滤器功能的完整描述超出了本书的范围。幸运的是，Laravel 的文档是了解有关过滤器更多信息的好资源。

## 4 - 验证

Laravel 提供了一个充满功能的`Validator`类，可帮助验证表单、数据库模型或其他任何内容。`Validator`类允许您传递任何输入，声明自己的规则，并定义自己的自定义验证消息。

让我们看一个为我们创建用户操作实现的示例。

```php
public function post_create()
{
  // validate input
  $rules = array(
    'real_name' => 'required|max:50',
    'email'     => 'required|email|unique:users',
    'password'  => 'required|min:5',
  );

  $validation = Validator::make(Input::all(), $rules);

  if($validation->fails())
  {
    return Redirect::back()->with_input()->with_errors($validation);
  }

  // create a user
  $user = new User;

  $user->real_name = Input::get('real_name');
  $user->email = Input::get('email');
  $user->password = Input::get('password');

  $user->save();

  return Redirect::to_action('users@index');
}
```

首先，我们创建一个定义验证规则的数组。验证规则数组是键值对。每个键代表它将验证的字段名称，每个值是一个包含验证规则及其配置的字符串。验证规则由管道字符（`|`）分隔，验证规则的配置参数与规则名称之间用冒号（`:`）分隔。

`required`规则确保已接收到其字段的输入。`max`和`min`规则可以确保字符串的长度不超过或不短于特定长度。`min`和`max`的长度作为参数传递，因此与规则名称用冒号分隔。在`real_name`的例子中，我们确保它不超过 50 个字符。我们还希望确保用户的密码长度不少于五个字符。

由于我们使用电子邮件进行身份验证，我们应该确保它在我们的数据库中是唯一的地址。因此，对于我们的“电子邮件”字段，我们定义了“唯一”规则，并告诉它与`users`数据库表中的其他值进行比较。如果它找到与我们创建用户表单中的地址匹配的另一个电子邮件地址，它将返回一个错误。

接下来，我们使用`Validator::make()`方法创建验证对象。我们将表单的输入作为第一个参数，将我们的`$rules`数组作为第二个参数。

现在，我们可以通过使用`$validation->passes()`方法来检查验证是否通过，或者通过使用`$validation->fails()`方法来检查验证是否失败。

在这个例子中，如果我们的验证失败，我们将用户重定向回表单，并重新填充表单的输入数据以及来自我们的`$validation`对象的错误数据。有了这些错误数据，我们可以用错误填充我们的表单，这样我们的用户就知道我们的表单为什么没有验证通过。

视图对象有一个特殊的`$errors`变量，通常为空。当用户被重定向到另一个动作`with_errors($validation)`时，特殊的`$errors`变量将填充来自验证对象的错误。让我们看一个如何显示“电子邮件”字段的错误的例子：

```php
{{ $errors->first('email', '<span class="help-inline">:message</span>') }}
```

在这里，我们显示了未通过“电子邮件”字段的第一个验证规则的错误消息。我们的第二个参数是一个格式化字符串。错误消息将替换字符串中的:`message`符号。如果“电子邮件”字段没有验证错误，则不会返回任何格式化的字符串。这使得这个算法非常适合创建具有单独字段反馈的表单。

您可以在项目的`http://myfirst.dev/docs`中的 Laravel 文档中找到完整的验证规则列表。

在典型的 Web 应用程序中，验证发生在表单和数据模型上。表单验证确保从用户检索的数据符合某些标准。数据模型验证确保插入数据库的数据是充分的，维护了关系，维护了字段的唯一性等等。

我们的验证示例功能。但是，为了简洁起见，我们直接在控制器内部编写了它。存储表单验证规则的更合适的地方是在专门针对该表单的模型中。同样，存储数据库模型验证规则的更合适的地方是在 Eloquent 模型中。

## 5 - 捆绑

Laravel 框架的一个主要卖点是它处理模块化代码的方式。在 Laravel 中可以编写的任何功能都可以捆绑。控制器、模型、视图、库、过滤器、配置文件、路由和迁移都可以打包为一个捆绑，并且可以由您和您的团队重新使用，或者分发给其他人使用。您可能会兴奋地知道，Laravel 的应用程序文件夹被认为是其默认捆绑。没错，所有使用 Laravel 编写的 Web 应用程序代码都在一个捆绑中运行。

由于捆绑在 Laravel 中是一等公民，它们对各种应用程序非常有用。捆绑可以用于添加简单的供应商库或辅助函数。捆绑也经常用于打包整个 Web 应用程序子系统。例如，很有可能将博客捆绑包放入您的应用程序中，运行迁移以创建博客数据库表，然后自动开始工作的 URL `http://myfirst.dev/blog`和`http://myfirst.dev/admin/blog`。捆绑非常强大。

您可以在 Laravel 安装的根目录中的`bundles.php`文件中找到应用程序的捆绑配置。让我们现在看一下我们 Web 应用程序的`bundles.php`文件：

```php
return array(

  'docs' => array('handles' => 'docs'),

);
```

哦，看这里，我们已经安装了一个 bundle。文档 bundle 包含了 Laravel 文档的当前版本。这是因为文档 bundle 处理了文档路由，所以您可以转到`http://myfirst.dev/docs`并查看 Laravel 文档。您可以注释或删除配置文档 bundle 的行，以防止用户在您的生产站点上访问`docs`路由。

Laravel 有一个公共的在线 bundle 存储库，可以在[`bundles.laravel.com`](http://bundles.laravel.com)找到。用户可以自由地创建和添加他们自己的 bundles 到这个存储库。然后我们可以将他们的 bundles 安装到我们自己的应用程序中。

有几种方法可以安装 bundles。

使用 Artisan 安装 bundles 通常是从存储库安装 bundles 的首选方法。只需使用 Artisan 的`bundle:install`任务，您请求的 bundle 将从 Laravel bundle 存储库下载并安装到您的 bundles 目录中。让我们试试看。

```php
**# php artisan bundle:install swiftmailer**
**Fetching [swiftmailer]...done! Bundle installed.**

```

我们告诉 Artisan 我们想要从 bundle 存储库安装`swiftmailer` bundle。它下载了 bundle，现在我们有一个目录`bundles/swiftmailer`，其中包含`swiftmailer`供应商库以及 bundle 的`start.php`文件。`start.php`是负责加载 bundle 内容并使其准备好使用的文件；它在第一次启动 bundle 时运行。

您可以在没有 Artisan 的情况下完成相同的操作。bundle 存储库通过使用 GitHub 运行。因此，存储库中的所有 bundles 都可以在 GitHub 上找到。您可以轻松地转到[`github.com/taylorotwell/swiftmailer`](https://github.com/taylorotwell/swiftmailer)并将代码下载到您的 bundles 目录中。这与使用 Artisan 完成相同，只需要更多的努力。

安装完 bundle 后，必须将其添加到 bundle 配置文件中才能使用。让我们为我们的`swiftmailer` bundle 添加配置到我们的`bundles.php`文件并查看结果。

```php
return array(

  'docs' => array('handles' => 'docs'),
  'swiftmailer',

);
```

我们不需要添加任何额外的配置参数来使我们的`swiftmailer` bundle 工作。在我们的代码中，我们只需运行`Bundle::start('swiftmailer')`，然后开始使用它。或者，如果您希望自动启动一个 bundle，您可以简单地将自动配置添加到您的`bundles.php`文件中。

```php
return array(

  'docs' => array('handles' => 'docs'),
  'swiftmailer' => array('auto' => true),

);
```

现在，手动启动 bundle 是完全不必要的。它将在路由代码执行之前自动启动。

bundles 存在的核心目的是代码重用。在掌握 Laravel 的过程中，我们建议首先在没有 bundles 的情况下实现新代码。然后，一旦您发现需要重用该代码，您可能会更喜欢将代码捆绑起来并根据需要进行重构。这可以防止您在学习 bundles 如何组合以及在 Laravel 中首次实施代码时被拖慢。

在获得制作几个 bundles 的经验后，您会发现它们非常容易设计。在获得这种经验之前，您可能会发现自己在重构代码时消耗了宝贵的开发时间。

您现在已经了解了使用 Laravel 开发的所有最基本的组件。随着您不断提高技能，您将发现更高级的功能，例如控制反转容器、视图组件、事件等。Laravel 在 PHP 世界中提供了一个独特的平台。您有机会实现自己的软件架构设计，而无需破坏性地修改核心以支持它。我们强烈建议，如果您继续在设计模式方面继续教育，因为您现在正在一个真正支持实现自己独特架构的平台上工作。

# 您应该认识的人和地方

如果您需要帮助 Laravel，以下是一些人和地方，它们将非常有价值。

+   **官方主页**：[`laravel.com`](http://laravel.com)

+   **官方文档**：[`laravel.com/docs`](http://laravel.com/docs)

+   **官方 API 文档**：[`laravel.com/api`](http://laravel.com/api)

+   **GitHub 仓库**：[`github.com/laravel/laravel`](https://github.com/laravel/laravel)

## 文章和教程

有许多人在撰写和录制关于使用 Laravel 的教程和视频系列。以下是一些可以帮助你提高水平的教程：

+   *nettuts*在他们的免费和付费部分提供了许多关于 Laravel 的教程。他们以演示的质量而闻名（[`net.tutsplus.com/tag/laravel/`](http://net.tutsplus.com/tag/laravel/)）。

+   Laravel: Ins and Outs 是最近由 Laravel 社区发起的一个学习小组，包含了无法在其他地方找到的宝贵信息。加入我们，访问[`laravel.io`](http://laravel.io)，并关注我们的 Twitter 账号[`twitter.com/laravelio`](http://twitter.com/laravelio)。

+   *Feather Forums*的作者和长期贡献者 Jason Lewis 创建了一系列很好的 Laravel 教程，其中包括了如何参与 GitHub 项目的指南（[`jasonlewis.me/blog/laravel-tutorials`](http://jasonlewis.me/blog/laravel-tutorials)）。

+   备受尊敬的多才多艺的开发者 Matthew Machuga 有一些独一无二的 Laravel 视频系列，重点介绍了使用 Laravel 进行测试驱动开发（[`matthewmachuga.com/screencasts`](http://matthewmachuga.com/screencasts)）。

+   Dayle Rees 发布了一套流行的教程，涵盖了许多 Laravel 的基础知识（[`daylerees.com/category/laravel-tutorials/`](http://daylerees.com/category/laravel-tutorials/)）。

+   最后，我的自己的视频系列包括 Laravel 文件夹结构的演示，安全最佳实践的解释，以及关于建模表单的信息（[`heybigname.com/2012/03/12/a-walk-through-laravel-folder-structure/`](http://heybigname.com/2012/03/12/a-walk-through-laravel-folder-structure/)）。

## 社区

Laravel 有一个很棒的社区。具有多年经验的专业开发人员在论坛上贡献并在 IRC 频道上提供帮助。它们都是熟悉 Laravel 的好地方，也是你遇到问题时去的好地方。

作为软件开发专业人员的重要部分是让自己接触尽可能多的好解决方案。唯一可以合理实现这一点的方法是加入一个社区。通过定期阅读论坛并参与 IRC 频道，你将接触到许多新的想法，这是你自己无法想到的。

+   *Laravel 论坛*：[`forums.laravel.com`](http://forums.laravel.com)

+   *Laravel IRC*（实时聊天）：[`laravel.com/irc`](http://laravel.com/irc)

## Twitter

Twitter 是跟上 Laravel 新闻的好方法——信息在网络上传播得很快。以下是一些你会想要关注的账号。

+   *@taylorotwell*：他是 Laravel 的负责人，也是推动 PHP 成为严肃的开发平台的重要人物

+   *@laravelphp*：Laravel 的官方 Twitter 账号

+   *@laravelnews*：转发来自世界各地用户关于 Laravel 各个方面的新闻
