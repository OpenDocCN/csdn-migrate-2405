# Laravel 应用开发秘籍（一）

> 原文：[`zh.annas-archive.org/md5/d81d8d9e8c3a4da47310e721ff4953e5`](https://zh.annas-archive.org/md5/d81d8d9e8c3a4da47310e721ff4953e5)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

Laravel 已经成为最快增长的 PHP 框架之一。凭借其表达性的语法和出色的文档，很容易在很短的时间内获得一个完全运行的 Web 应用程序。此外，现代 PHP 功能的使用使得 Laravel 4 版本非常容易根据我们自己的需求进行定制，也使得我们可以轻松地创建一个高度复杂的网站。它是简单和先进的完美结合。

这本书只涵盖了 Laravel 所能做的一小部分。把它看作一个起点，有代码示例可以让事情运转起来。然后自定义它们，添加到它们，或者组合它们来创建您自己的应用程序。可能性是无限的。

关于 Laravel 最好的一点是社区。如果您遇到问题并且谷歌搜索没有帮助，总会有人愿意帮助。您可以在 IRC（Freenode 上的`#laravel`）或论坛（[`forums.laravel.io`](http://forums.laravel.io)）上找到乐于助人的社区成员，或者您可以联系 Twitter 上的许多 Laravel 用户。

愉快的 Laravel 之旅！

# 本书涵盖的内容

第一章，“设置和安装 Laravel”，涵盖了将 Laravel 设置和运行起来的各种方式。

第二章，“使用表单和收集输入”，展示了在 Laravel 中使用表单的多种方式。它涵盖了使用 Laravel 的表单类以及一些基本验证。

第三章，“验证您的应用程序”，演示了如何对用户进行身份验证。我们将看到如何使用 OAuth、OpenId 和各种社交网络进行身份验证。

第四章，“存储和使用数据”，涵盖了所有与数据相关的内容，包括如何使用除了 MySQL 数据库之外的数据源。

第五章，“使用控制器和路由处理 URL 和 API”，介绍了 Laravel 中的各种路由方法以及如何创建一个基本的 API。

第六章，“显示您的视图”，演示了在 Laravel 中视图的工作方式。我们还将整合 Twig 模板系统和 Twitter Bootstrap。

第七章，“创建和使用 Composer 包”，解释了如何在我们的应用程序中使用包，以及如何创建我们自己的包。

第八章，“使用 Ajax 和 jQuery”，提供了不同的示例，说明了如何在 Laravel 中使用 jQuery 以及如何进行异步请求。

第九章，“有效使用安全和会话”，涵盖了有关保护我们的应用程序以及如何使用会话和 cookie 的主题。

第十章，“测试和调试您的应用程序”，展示了如何在我们的应用程序中包含单元测试，使用 PHPUnit 和 Codeception。

第十一章，“部署和集成第三方服务到您的应用程序”，介绍了许多第三方服务以及我们如何将它们包含到我们的应用程序中。

# 你需要什么

这本书基本上需要一个工作的 LAMP 堆栈（Linux、Apache、MySQL 和 PHP）。Web 服务器是 Apache 2，可以在[`httpd.apache.org`](http://httpd.apache.org)找到。推荐的数据库服务器是 MySQL 5.6，可以从[`dev.mysql.com/downloads/mysql`](http://dev.mysql.com/downloads/mysql)下载。推荐的最低 PHP 版本是 5.4，可以在[`php.net/downloads.php`](http://php.net/downloads.php)找到。

对于一体化解决方案，还有一个 WAMP 服务器（[`www.wampserver.com/en`](http://www.wampserver.com/en)）或 XAMMP（[`www.apachefriends.org/en/xampp.html`](http://www.apachefriends.org/en/xampp.html)）适用于 Windows，或者 MAMP（[`www.mamp.info/en/mamp-pro`](http://www.mamp.info/en/mamp-pro)）适用于 Mac OS X。

# 本书适合对象

本书适用于具有中级 PHP 知识的人。了解另一个 PHP 框架或 Laravel 的第 3 版的基础知识也会有所帮助。对 MVC 结构和面向对象编程的一些了解也会有益处。

# 约定

本书中，您将找到许多不同类型信息的文本样式。以下是一些样式的示例，以及它们的含义解释。

文本中的代码单词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 用户名，显示如下：“然后，我们使用`artisan`命令为我们生成一个新密钥，并自动保存在正确的文件中”。

代码块设置如下：

```php
Route::get('accounts', function()
{
  $accounts = Account::all();
  return View::make('accounts')->with('accounts', $accounts);
});
```

任何命令行输入或输出都会以以下方式书写：

```php
  php artisan key:generate
```

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的单词，例如菜单或对话框中的单词，会以这种方式出现在文本中：“登录 Pagodabox 后，单击**新应用**选项卡”。

### 注意

警告或重要说明会以这样的方式出现在方框中。

### 提示

技巧会以这种方式出现。


# 第一章：设置和安装 Laravel

在本章中，我们将涵盖：

+   将 Laravel 安装为 git 子模块

+   在 Apache 中设置虚拟主机和开发环境

+   创建“干净”的 URL

+   配置 Laravel

+   使用 Sublime Text 2 与 Laravel

+   设置 IDE 以自动完成 Laravel 的命名空间

+   使用自动加载程序将类名映射到其文件

+   使用命名空间和目录创建高级自动加载程序

# 介绍

在本章中，我们将学习如何轻松地启动和运行 Laravel，并确保在进行任何核心更改时更新它变得简单。我们还将设置我们的开发和编码环境，以便非常高效，这样我们就可以专注于编写优秀的代码，而不必担心与我们的应用程序无关的问题。最后，我们将看一些方法，让 Laravel 自动为我们做一些工作，这样我们就能在很短的时间内扩展我们的应用程序。

# 将 Laravel 安装为 git 子模块

也许有一段时间，我们希望将我们的 Laravel 安装与我们的公共文件的其余部分分开。在这种情况下，将 Laravel 安装为 git 子模块将是一个解决方案。这将允许我们通过 git 更新我们的 Laravel 文件，而不影响我们的应用程序代码。

## 准备工作

要开始，我们应该让我们的开发服务器运行，并安装 git。在服务器的 web 目录中，创建一个`myapp`目录来保存我们的文件。安装将在命令行中完成。

## 操作步骤...

要完成这个步骤，请按照以下步骤进行：

1.  在您的终端或命令行中，导航到`myapp`的根目录。第一步是初始化 git 并下载我们的项目文件：

```php
**$ git init**
**$ git clone git@github.com:laravel/laravel.git**

```

1.  由于我们只需要`public`目录，所以移动到`/laravel`并删除其他所有内容：

```php
**$ cd laravel**
**$ rm –r app bootstrap vendor**

```

1.  然后，回到根目录，创建一个`framework`目录，并将 Laravel 添加为子模块：

```php
**$ cd ..**
**$ mkdir framework**
**$ cd framework**
**$ git init**
**$ git submodule add https://github.com/laravel/laravel.git**

```

1.  现在我们需要运行 Composer 来安装框架：

```php
**php composer.phar install**

```

### 提示

有关安装 Composer 的更多信息，请访问[`getcomposer.org/doc/00-intro.md`](http://getcomposer.org/doc/00-intro.md)。本书的其余部分将假定我们正在使用`composer.phar`，但我们也可以将其全局添加，并通过键入`composer`来简单调用它。

1.  现在，打开`/laravel/public/index.php`并找到以下行：

```php
**require __DIR__.'/../bootstrap/autoload.php';**
**$app = require_once __DIR__.'/../bootstrap/start.php';**

```

1.  将前面的行改为：

```php
**require __DIR__.'/../../framework/laravel/bootstrap/autoload.php';**
**$app = require_once __DIR__.'/../../framework/laravel/bootstrap/start.php';**

```

## 它是如何工作的...

对许多人来说，简单运行`git clone`就足以让他们的项目运行起来。然而，由于我们希望我们的框架作为一个子模块，我们需要将这些文件与我们的项目分开。

首先，从 GitHub 下载文件，由于我们不需要任何框架文件，我们可以删除除了我们的公共文件夹之外的所有内容。然后，在`framework`目录中创建我们的子模块，并下载所有内容。完成后，我们运行`composer install`来安装所有供应商包。

为了将框架连接到我们的应用程序，我们修改`/laravel/public/index.php`并将`require`路径更改为我们的框架目录。这将让我们的应用程序准确地知道框架文件的位置。

## 还有更多...

一个替代方案是将`public`目录移动到我们服务器的根目录。然后，在更新我们的`index.php`文件时，我们将使用`__DIR__ . '/../framework/laravel/bootstrap'`来正确包含所有内容。

# 在 Apache 中设置虚拟主机和开发环境

在开发我们的 Laravel 应用程序时，我们需要一个 web 服务器来运行所有内容。在 PHP 5.4 及更高版本中，我们可以使用内置的 web 服务器，但如果我们需要一些更多的功能，我们将需要一个完整的 web 堆栈。在这个步骤中，我们将在 Windows 上使用 Apache 服务器，但任何带有 Apache 的操作系统都将类似。

## 准备工作

这个步骤需要一个最新版本的 WAMP 服务器，可在[`wampserver.com`](http://wampserver.com)上找到，尽管基本原则适用于 Windows 上的任何 Apache 配置。

## 操作步骤...

要完成这个步骤，请按照以下步骤进行：

1.  打开 WAMP Apache `httpd.conf`文件。它通常位于`C:/wamp/bin/apache/Apach2.#.#/conf`。

1.  找到`#Include conf/extra/httpd-vhosts.conf`一行，并删除第一个`#`。

1.  转到`extra`目录，打开`httpd-vhosts.conf`文件，并添加以下代码：

```php
<VirtualHost *:80>
    ServerAdmin {your@email.com}
    DocumentRoot "C:/path/to/myapp/public"
    ServerName myapp.dev
    <Directory "C:/path/to/myapp/public">
        Options Indexes FollowSymLinks
        AllowOverride all
        # onlineoffline tag - don't remove
        Order Deny,Allow
        Deny from all
        Allow from 127.0.0.1
    </Directory>
</VirtualHost>
```

1.  重新启动 Apache 服务。

1.  打开 Windows 主机文件，通常在`C:/Windows/System32/drivers/etc`，并在文本编辑器中打开`hosts`文件。

1.  在文件底部添加一行`127.0.0.1 myapp.dev`。

## 它是如何工作的...

首先，在 Apache 配置文件`httpd.conf`中，我们取消注释允许文件包含`vhosts`配置文件的行。您可以直接在`httpd.conf`文件中包含代码，但这种方法可以使事情更有条理。

在`httpd-vhosts.conf`文件中，我们添加我们的 VirtualHost 代码。`DocumentRoot`告诉服务器文件的位置，`ServerName`是服务器将查找的基本 URL。由于我们只想在本地开发中使用这个，我们确保只允许通过 IP`127.0.0.1`访问本地主机。

在`hosts`文件中，我们需要告诉 Windows 为`myapp.dev` URL 使用哪个 IP。重新启动 Apache 和我们的浏览器后，我们应该能够转到`http://myapp.dev`并查看我们的应用程序。

## 还有更多...

虽然这个配方特定于 Windows 和 WAMP，但同样的想法可以应用于大多数 Apache 安装。唯一的区别将是`httpd.conf`文件的位置（在 Linux Ubuntu 中，它在`/etc/apache2`中）和 DocumentRoot 的`public`目录的路径（在 Ubuntu 中，它可能类似于`/var/www/myapp/public`）。Linux 和 Mac OS X 的`hosts`文件将位于`/etc/hosts`中。

# 创建“干净”的 URL

在安装 Laravel 时，我们将使用的默认 URL 是`http://{your-server}/public`。如果我们决定删除`/public`，我们可以使用 Apache 的`mod_rewrite`来更改 URL。

## 准备工作

对于这个配方，我们只需要一个新安装的 Laravel 和一切都在正确配置的 Apache 服务器上运行。

## 如何做...

要完成这个配方，请按照以下步骤操作：

1.  在我们应用程序的根目录中，添加一个`.htaccess`文件并使用此代码：

```php
<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteRule ^(.*)$ public/$1 [L]
</IfModule>
```

1.  转到`http://{your-server}`并查看您的应用程序。

## 它是如何工作的...

这段简单的代码将接受我们在 URL 中添加的任何内容并将其指向`public`目录。这样，我们就不需要手动输入`/public`。

## 还有更多...

如果我们决定将此应用程序移至生产环境，这不是完成任务的最佳方式。在那种情况下，我们只需将文件移出 Web 根目录，并将`/public`作为我们的根目录。

# 配置 Laravel

安装 Laravel 后，它几乎可以立即使用，几乎不需要配置。但是，有一些设置我们要确保更新。

## 准备工作

对于这个配方，我们需要一个常规的 Laravel 安装。

## 如何做...

要完成这个配方，请按照以下步骤操作：

1.  打开`/app/config/app.php`并更新这些行：

```php
'url' => 'http://localhost/,
'locale' => 'en',
'key' => 'Seriously-ChooseANewKey',
```

1.  打开`app/config/database.php`并选择您首选的数据库：

```php
'default' => 'mysql',
'connections' => array(
    'mysql' => array(
        'driver'    => 'mysql',
        'host'      => 'localhost',
        'database'  => 'database',
        'username'  => 'root',
        'password'  => '',
        'charset'   => 'utf8',
        'collation' => 'utf8_unicode_ci',
        'prefix'    => '',
        ),
    ),
```

1.  在命令行中，转到应用程序的根目录，并确保`storage`文件夹是可写的：

```php
**chmod –R 777 app/storage**

```

## 它是如何工作的...

大部分配置将在`/app/config/app.php`文件中进行。虽然设置 URL 并不是必需的，而且 Laravel 在没有设置的情况下也能很好地解决这个问题，但最好是尽量减少框架的工作量。接下来，我们设置我们的位置。如果我们选择在应用程序中提供**本地化**，这个设置将是我们的默认设置。然后，我们设置我们的应用程序密钥，因为最好不要保留默认设置。

接下来，我们设置将使用的数据库驱动程序。Laravel 默认提供四种驱动程序：mysql、sqlite、sqlsrv（MS SQL Server）和 pgsql（Postgres）。

最后，我们的`app/storage`目录将用于保存任何临时数据，例如会话或缓存，如果我们选择的话。为了允许这一点，我们需要确保应用程序可以写入该目录。

## 还有更多...

要轻松创建一个安全的应用程序密钥，删除默认密钥并将其留空。然后，在命令行中，转到应用程序根目录并键入：

```php
**php artisan key:generate**

```

这将创建一个独特且安全的密钥，并自动保存在您的配置文件中。

# 使用 Sublime Text 2 与 Laravel

用于编码的最受欢迎的文本编辑器之一是 Sublime Text。Sublime 具有许多功能，使编码变得有趣，通过插件，我们可以添加特定于 Laravel 的功能来帮助我们的应用程序。

## 准备工作

Sublime Text 2 是一款非常可扩展的流行代码编辑器，使编写代码变得轻松。可以从[`www.sublimetext.com/2`](http://www.sublimetext.com/2)下载评估版本。

我们还需要在 Sublime 中安装并启用 Package Control 包，可以在[`wbond.net/sublime_packages/package_control/installation`](http://wbond.net/sublime_packages/package_control/installation)找到。

## 操作步骤...

按照以下步骤进行操作：

1.  在菜单栏中，转到**首选项**然后**包控制**：![操作步骤...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrv-app-dev-cb/img/2827OS_01_01.jpg)

1.  选择**安装包**：![操作步骤...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrv-app-dev-cb/img/2827OS_01_02.jpg)

1.  搜索`laravel`以查看列表。选择**Laravel 4 Snippets**并让其安装。安装完成后，选择**Laravel-Blade**并安装它。

## 工作原理...

Sublime Text 2 中的 Laravel 片段大大简化了编写常见代码，并且几乎包括了我们在应用程序开发中所需的一切。例如，当创建路由时，只需开始输入`Route`，然后会弹出一个列表，允许我们选择我们想要的路由，然后自动完成我们需要的其余代码。

![工作原理...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrv-app-dev-cb/img/2827OS_01_03.jpg)

## 还有更多...

安装 Laravel-Blade 包对于使用 Laravel 自带的 Blade 模板系统非常有帮助。它可以识别文件中的 Blade 代码，并自动突出显示语法。

# 设置 IDE 以自动完成 Laravel 的命名空间

大多数**IDEs**（集成开发环境）在程序的一部分中具有某种形式的代码完成。为了使 Laravel 的命名空间自动完成，我们可能需要帮助它识别命名空间是什么。

## 准备工作

对于这个操作，我们将在 NetBeans IDE 中添加命名空间，但是在其他 IDE 中的过程类似。

## 操作步骤...

按照以下步骤完成此操作：

1.  下载列出 Laravel 命名空间的预制文件：[`gist.github.com/barryvdh/5227822`](https://gist.github.com/barryvdh/5227822)。

1.  在计算机的任何位置创建一个文件夹来保存此文件。为了我们的目的，我们将文件添加到`C:/ide_helper/ide_helper.php`：![操作步骤...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrv-app-dev-cb/img/2827OS_01_04.jpg)

1.  在使用 Laravel 框架创建项目后，转到**文件** | **项目属性** | **PHP 包含路径**：![操作步骤...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrv-app-dev-cb/img/2827OS_01_05.jpg)

1.  单击**添加文件夹...**，然后添加`C:/ide_helper`文件夹。

1.  现在，当我们开始输入代码时，IDE 将自动建议完成的代码：![操作步骤...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrv-app-dev-cb/img/2827OS_01_06.jpg)

## 工作原理...

一些 IDE 需要帮助理解框架的语法。为了让 NetBeans 理解，我们下载了所有 Laravel 类和选项的列表。然后，当我们将其添加到包含路径时，NetBeans 将自动检查文件并显示自动完成选项。

## 还有更多...

我们可以使用 Composer 自动下载和更新文档。有关安装说明，请访问[`github.com/barryvdh/laravel-ide-helper`](https://github.com/barryvdh/laravel-ide-helper)。

# 使用 Autoloader 将类名映射到其文件

使用 Laravel 的 ClassLoader，我们可以轻松地在我们的代码中包含任何自定义类库，并使它们随时可用。

## 准备工作

对于这个操作，我们需要设置一个标准的 Laravel 安装。

## 操作步骤...

要完成此操作，请按照以下步骤进行操作：

1.  在 Laravel 的`/app`目录中，创建一个名为`custom`的新目录，其中将保存我们的自定义类。

1.  在`custom`目录中，创建一个名为`MyShapes.php`的文件，并添加以下简单代码：

```php
<?php
class MyShapes {
    public function octagon() 
    {
        return 'I am an octagon';
    }
}
```

1.  在`/app/start`目录中，打开`global.php`并更新`ClassLoader`，使其看起来像这样：

```php
ClassLoader::addDirectories(array(

    app_path().'/commands',
    app_path().'/controllers',
    app_path().'/models',
    app_path().'/database/seeds',
    app_path().'/custom',

));
```

1.  现在我们可以在应用程序的任何部分使用该类。例如，如果我们创建一个路由：

```php
Route::get('shape', function()
{
    $shape = new MyShapes;
    return $shape->octagon();
});
```

## 它是如何工作的...

大多数情况下，我们会使用 Composer 向我们的应用程序添加包和库。但是，可能有一些库无法通过 Composer 获得，或者我们想要保持独立的自定义库。为了实现这一点，我们需要专门的位置来保存我们的类库；在这种情况下，我们创建一个名为`custom`的目录，并将其放在我们的`app`目录中。

然后我们添加我们的类文件，确保类名和文件名相同。这既可以是我们自己创建的类，也可以是我们需要使用的传统类。

最后，我们将目录添加到 Laravel 的 ClassLoader 中。完成后，我们将能够在应用程序的任何地方使用这些类。

## 另请参阅

+   使用命名空间和目录创建高级自动加载器

# 使用命名空间和目录创建高级自动加载器

如果我们想确保我们的自定义类不会与应用程序中的任何其他类发生冲突，我们需要将它们添加到命名空间中。使用 PSR-0 标准和 Composer，我们可以轻松地将这些类自动加载到 Laravel 中。

## 准备工作

对于这个配方，我们需要设置一个标准的 Laravel 安装。

## 如何做...

要完成这个配方，请按照以下步骤进行：

1.  在`/app`目录中，创建一个名为`custom`的新目录，并在`custom`中创建一个名为`Custom`的目录，在`Custom`中创建一个名为`Shapes`的目录。

1.  在`/app/custom/Custom/Shapes`目录中，创建一个名为`MyShapes.php`的文件，并添加以下代码：

```php
<?php namespace Custom\Shapes;

class MyShapes {
    public function triangle() 
    {
        return 'I am a triangle';
    }
}
```

1.  在应用程序的根目录中，打开`composer.json`文件并找到`autoload`部分。更新它使其看起来像这样：

```php
"autoload": {
    "classmap": [
    "app/commands",
        "app/controllers",
        "app/models",
        "app/database/migrations",
        "app/database/seeds",
        "app/tests/TestCase.php",
    ],
    "psr-0": {
        "Custom": "app/custom"
    }
}
```

1.  在命令行中运行`composer`上的`dump-autoload`：

```php
**php composer.phar dump-autoload**

```

1.  现在我们可以通过其命名空间调用该类。例如，如果我们创建一个路由：

```php
Route::get('shape', function()
{
    $shape = new Custom\Shapes\MyShapes;
    return $shape->triangle();
});
```

## 它是如何工作的...

命名空间是 PHP 的一个强大补充，它允许我们使用类而不必担心它们的类名与其他类名发生冲突。通过在 Laravel 中自动加载命名空间，我们可以创建一组复杂的类，而不必担心类名与其他命名空间发生冲突。

为了我们的目的，我们通过 composer 加载自定义类，并使用 PSR-0 标准进行自动加载。

## 还有更多...

为了进一步扩展我们的命名空间类的使用，我们可以使用**IoC**将其绑定到我们的应用程序。更多信息可以在 Laravel 文档中找到[`laravel.com/docs/ioc`](http://laravel.com/docs/ioc)。

## 另请参阅

+   使用自动加载器将类名映射到其文件的配方


# 第二章：使用表单和收集输入

在本章中，我们将涵盖：

+   创建一个简单的表单

+   收集表单输入以在另一页上显示

+   验证用户输入

+   创建一个文件上传器

+   验证文件上传

+   创建自定义错误消息

+   向表单添加“蜜罐”

+   使用 Redactor 上传图像

+   使用 Jcrop 裁剪图像

+   创建一个自动完成文本输入

+   制作一个验证码样式的垃圾邮件捕捉器

# 介绍

在本章中，我们将学习如何在 Laravel 中使用表单，以及如何完成一些典型的任务。我们将从一些简单的表单验证和文件上传开始，然后继续将一些前端工具，如 Redactor 和 jCrop，整合到 Laravel 中。

# 创建一个简单的表单

任何 Web 应用程序的最基本方面之一是表单。Laravel 提供了一种简单的方法来为我们的表单构建 HTML。

## 准备工作

要开始，我们需要一个全新的 Laravel 安装。

## 操作步骤...

要完成此示例，请按照以下步骤操作：

1.  在`app/views`文件夹中，创建一个新的`userform.php`文件。

1.  在`routes.php`中，创建一个路由来加载视图：

```php
Route::get(userform, function()
{
    return View::make('userform');
});
```

1.  在`userform.php`视图中，使用以下代码创建一个表单：

```php
<h1>User Info</h1>
<?= Form::open() ?>
<?= Form::label('username', 'Username') ?>
<?= Form::text('username') ?>
<br>
<?= Form::label('password', 'Password') ?>
<?= Form::password('password') ?>
<br>
<?= Form::label('color', 'Favorite Color') ?>
<?= Form::select('color', array('red' => 'red', 'green' =>'green', 'blue' => 'blue')) ?>
<br>
<?= Form::submit('Send it!') ?>
<?= Form::close() ?>
```

通过转到`http://{your-server}/userform`（其中`{your-server}`是您的服务器的名称）在 Web 页面中查看您的表单。

## 工作原理...

对于这个任务，我们使用 Laravel 内置的`Form`类创建了一个简单的表单。这使我们能够轻松地使用最少的代码创建表单元素，并且它符合 W3C（万维网联盟）标准。

首先，我们打开表单。Laravel 会自动创建`<form>`html，包括 action、method 和 accept-charset 参数。当没有传递选项时，默认操作是当前 URL，默认方法是`POST`，字符集取自应用配置文件。

接下来，我们创建普通文本和密码输入字段，以及它们的标签。标签中的第一个参数是文本字段的名称，第二个参数是要打印的实际文本。在表单构建器中，标签应该出现在实际表单输入之前。

表单选择需要第二个参数，即下拉框中值的数组。在本例中，我们使用`'key' => 'value'`语法创建一个数组。如果我们想创建选项组，我们只需要创建嵌套数组。

最后，我们创建了提交按钮并关闭了表单。

## 还有更多...

大多数 Laravel 的表单方法也可以包括默认值和自定义属性（类、ID 等）的参数。如果我们不想使用特定的方法，我们也可以对许多字段使用`Form::input()`。例如，我们可以使用`Form::input('submit', NULL, 'Send it!')`来创建一个提交按钮。

## 另请参阅

+   *收集表单输入以在另一页上显示*示例

# 收集表单输入以在另一页上显示

用户提交表单后，我们需要能够获取该信息并将其传递到另一页。这个示例展示了我们如何使用 Laravel 的内置方法来处理我们的 POST 数据。

## 准备工作

我们需要从*创建一个简单的表单*部分设置简单的表单。

## 操作步骤...

按照以下步骤完成此示例：

1.  创建一个路由来处理表单中的 POST 数据：

```php
Route::post('userform', function()
{
    // Process the data here
    return Redirect::to('userresults')-
        >withInput(Input::only('username', 'color'));
});

```

1.  创建一个重定向到的路由，并显示数据：

```php
Route::get('userresults', function()
{
    return 'Your username is: ' . Input::old('username')
        . '<br>Your favorite color is: '
        . Input::old('color');
});

```

## 工作原理...

在我们的简单表单中，我们将数据 POST 回相同的 URL，因此我们需要创建一个接受相同路径的`POST`路由。这是我们将对数据进行任何处理的地方，包括保存到数据库或验证输入。

在这种情况下，我们只是想将数据传递到下一页。有许多方法可以实现这一点。例如，我们可以使用`Input`类的`flashOnly()`方法：

```php
Route::post('userform', function()
{
    Input::flashOnly('username', 'color');
    return Redirect::to('userresults');
});
```

但是，我们使用了 Laravel 提供的一个快捷方式，只传递了我们要求的三个表单字段中的两个。

在下一页上，我们使用`Input::old()`来显示闪存输入。

## 另请参阅

+   *创建一个简单的表单*示例

# 验证用户输入

在大多数 Web 应用程序中，将需要某些必填的表单字段来处理表单。我们还希望确保所有电子邮件地址的格式正确，或者输入必须具有一定数量的字符。使用 Laravel 的`Validator`类，我们可以检查这些规则，并让用户知道是否有不正确的地方。

## 准备工作

对于这个食谱，我们只需要一个标准的 Laravel 安装。

## 如何做...

完成这个食谱，按照以下步骤进行：

1.  创建一个路由来保存表单：

```php
Route::get('userform', function()
{
    return View::make('userform');
});
```

1.  创建一个名为`userform.php`的视图并添加一个表单：

```php
<h1>User Info</h1>
<?php $messages =  $errors->all('<pstyle="color:red">:message</p>') ?>
<?php
foreach ($messages as $msg)
{
    echo $msg;
}
?>
<?= Form::open() ?>
<?= Form::label('email', 'Email') ?>
<?= Form::text('email', Input::old('email')) ?>
<br>
<?= Form::label('username', 'Username') ?>
<?= Form::text('username', Input::old('username')) ?>
<br>
<?= Form::label('password', 'Password') ?>
<?= Form::password('password') ?>
<br>
<?= Form::label('password_confirm', 'Retype your Password')?>
<?= Form::password('password_confirm') ?>
<br>
<?= Form::label('color', 'Favorite Color') ?>
<?= Form::select('color', array('red' => 'red', 'green' =>'green', 'blue' => 'blue'), Input::old('color')) ?>
<br>
<?= Form::submit('Send it!') ?>
<?php echo Form::close() ?>
```

1.  创建一个处理我们的`POST`数据并验证它的路由：

```php
Route::post('userform', function()
{
    $rules = array(
        'email' => 'required|email|different:username',
        'username' => 'required|min:6',
        'password' => 'required|same:password_confirm'
    );
    $validation = Validator::make(Input::all(), $rules);

    if ($validation->fails())
    {
        return Redirect::to('userform')-
            >withErrors($validation)->withInput();
    }

    return Redirect::to('userresults')->withInput();

});

```

1.  创建一个路由来处理成功的表单提交：

```php
Route::get('userresults', function()
{
    return dd(Input::old());
});
```

## 它是如何工作的...

在我们的表单页面中，我们首先检查是否有任何错误，并在找到错误时显示它们。在错误内部，我们可以为每个错误消息设置默认样式。我们还可以选择使用`$errors->get('email')`来检查并显示单个字段的错误。如果 Laravel 检测到闪存错误，`$errors`变量将自动创建。

接下来，我们创建我们的表单。在表单元素的最后一个参数中，我们获取`Input::old()`，如果验证失败，我们将使用它来存储先前的输入。这样，用户就不需要一直填写整个表单。

然后创建一个路由，表单被 POST 提交，并设置我们的验证规则。在这种情况下，我们对`email`，`username`和`password`使用必填规则，以确保这些字段中有内容输入。

`email`字段还使用`email`规则，该规则使用 PHP 的内置`FILTER_VALIDATE_EMAIL`过滤器的`filter_var`函数。`email`字段也不能与`username`字段相同。`username`字段使用大小验证来检查至少六个字符。然后`password`字段检查`password_confirm`字段的值，并确保它们相同。

然后，我们创建验证器并传入所有表单数据。如果其中任何规则不符合，我们将用户导航回表单，并返回任何验证错误消息以及原始表单输入。

如果验证通过，我们使用 Laravel 的`dd()`辅助函数转到下一个页面，该函数使用`var_dump()`在页面上显示表单值。

## 另请参阅

+   *创建一个简单的表单食谱*

# 创建一个文件上传程序

有时我们希望用户将文件上传到我们的服务器。这个食谱展示了 Laravel 如何通过 Web 表单处理文件上传。

## 准备工作

要创建一个文件上传程序，我们需要安装标准版本的 Laravel。

## 如何做...

完成这个食谱，按照以下步骤进行：

1.  在我们的`routes.php`文件中创建一个路由来保存表单：

```php
Route::get('fileform', function()
{
    return View::make('fileform');
});
```

1.  在我们的`app/views`目录中创建`fileform.php`视图：

```php
<h1>File Upload</h1>
<?= Form::open(array('files' => TRUE)) ?>
<?= Form::label('myfile', 'My File') ?>
<br>
<?= Form::file('myfile') ?>
<br>
<?= Form::submit('Send it!') ?>
<?= Form::close() ?>
```

1.  创建一个路由来上传和保存文件：

```php
Route::post('fileform', function()
{
    $file = Input::file('myfile');
    $ext = $file->guessExtension();
    if ($file->move('files', 'newfilename.' . $ext))
    {
        return 'Success';
    }
    else
    {
        return 'Error';
    }
});
```

## 它是如何工作的...

在我们的视图中，我们使用`Form::open()`并传入一个数组，其中包含`'files' => TRUE`，这会自动设置`Form`标签中的 enctype；然后我们添加一个表单字段来接受文件。在`Form::open()`中不使用任何其他参数，表单将使用默认的`POST`方法和当前 URL 的操作。`Form::file()`是我们接受文件的输入字段。

由于我们的表单正在提交到相同的 URL，我们需要创建一个路由来接受`POST`输入。`$file`变量将保存所有文件信息。

接下来，我们想要使用不同的名称保存文件，但首先我们需要获取上传文件的扩展名。因此，我们使用`guessExtension()`方法，并将其存储在一个变量中。大多数文件使用方法都可以在 Symfony 的文件库中找到。

最后，我们使用文件的`move()`方法将文件移动到其永久位置，第一个参数是我们将保存文件的目录；第二个是文件的新名称。

如果一切上传正确，我们显示`'Success'`，如果不是，我们显示`'Error'`。

## 另请参阅

+   *验证文件上传*食谱

# 验证文件上传

如果我们希望允许用户通过我们的网络表单上传文件，我们可能希望限制他们上传的文件类型。使用 Laravel 的`Validator`类，我们可以检查特定的文件类型，甚至限制上传到特定文件大小。

## 准备工作

对于这个配方，我们需要一个标准的 Laravel 安装和一个示例文件来测试我们的上传。

## 如何做...

按照以下步骤完成这个配方：

1.  在我们的`routes.php`文件中为表单创建一个路由：

```php
Route::get('fileform', function()
{
    return View::make('fileform');
});
```

1.  创建表单视图：

```php
<h1>File Upload</h1>
<?php $messages =  $errors->all('<p style="color:red">:message</p>') ?>
<?php
foreach ($messages as $msg)
{
    echo $msg;
}
?>
<?= Form::open(array('files' => TRUE)) ?>
<?= Form::label('myfile', 'My File (Word or Text doc)') ?>
<br>
<?= Form::file('myfile') ?>
<br>
<?= Form::submit('Send it!') ?>
<?= Form::close() ?>
```

1.  创建一个路由来验证和处理我们的文件：

```php
Route::post('fileform', function()
{
    $rules = array(
        'myfile' => 'mimes:doc,docx,pdf,txt|max:1000'
    );
    $validation = Validator::make(Input::all(), $rules);

    if ($validation->fails())
    {
return Redirect::to('fileform')->withErrors($validation)->withInput();
    }
    else
    {
        $file = Input::file('myfile');
        if ($file->move('files', $file->getClientOriginalName()))
        {
            return "Success";
        }
        else 
        {
            return "Error";
        }
    }
});
```

## 它是如何工作的...

我们首先创建一个用于保存我们的表单的路由，然后是表单的 html 视图。在视图顶部，如果我们在验证中得到任何错误，它们将在这里被输出。表单以`Form::open (array('files' => TRUE))`开始，这将为我们设置默认的操作、方法和`enctype`。

接下来，我们创建一个路由来捕获 POST 数据并验证它。我们将一个`$rules`变量设置为一个数组，首先检查特定的 MIME 类型。我们可以使用尽可能少或尽可能多的规则。然后我们确保文件小于 1000 千字节，或 1 兆字节。

如果文件无效，我们将用户导航回带有错误消息的表单。如果 Laravel 检测到闪存的错误消息，`$error`变量会自动在我们的视图中创建。如果它是有效的，我们尝试将文件保存到服务器。如果保存正确，我们将看到`"Success"`，如果不是，我们将看到`"Error"`。

## 还有更多...

文件的另一个常见验证是检查图像。为此，我们可以在我们的`$rules`数组中使用以下内容：

```php
'myfile' => 'image'
```

这将检查文件是否是`.jpg`、`.png`、`.gif`或`.bmp`文件。

## 另请参阅

+   *创建文件上传器*配方

# 创建自定义错误消息

如果验证失败，Laravel 内置了错误消息，但我们可能希望自定义这些消息，使我们的应用程序变得独特。这个配方展示了创建自定义错误消息的几种不同方法。

## 准备工作

对于这个配方，我们只需要一个标准的 Laravel 安装。

## 如何做...

要完成这个配方，请按照以下步骤：

1.  在`routes.php`中创建一个路由来保存表单：

```php
Route::get('myform', function()
{
    return View::make('myform');
});
```

1.  创建一个名为`myform.php`的视图并添加一个表单：

```php
<h1>User Info</h1>
<?php $messages =  $errors->all
    ('<p style="color:red">:message</p>') ?>
<?php
foreach ($messages as $msg) 
{
    echo $msg;
}
?>
<?= Form::open() ?>
<?= Form::label('email', 'Email') ?>
<?= Form::text('email', Input::old('email')) ?>
<br>
<?= Form::label('username', 'Username') ?>
<?= Form::text('username', Input::old('username')) ?>
<br>
<?= Form::label('password', 'Password') ?>
<?= Form::password('password') ?>
<br>
<?= Form::submit('Send it!') ?>
<?= Form::close() ?>
```

1.  创建一个路由来处理我们的 POST 数据并验证它：

```php
Route::post('myform', array('before' => 'csrf', function()
{
    $rules = array(
        'email'    => 'required|email|min:6',
        'username' => 'required|min:6',
        'password' => 'required'
    );

    $messages = array(
        'min' => 'Way too short! The :attribute must be atleast :min characters in length.',
        'username.required' => 'We really, really need aUsername.'
    );

    $validation = Validator::make(Input::all(), $rules,$messages);

    if ($validation->fails())
    {
        return Redirect::to('myform')->withErrors($validation)->withInput();
    }

    return Redirect::to('myresults')->withInput();
}));
```

1.  打开文件`app/lang/en/validation.php`，其中`en`是应用程序的默认语言。在我们的情况下，我们使用的是英语。在文件底部，更新`attributes`数组如下：

```php
'attributes' => array(
    'password' => 'Super Secret Password (shhhh!)'
),
```

1.  创建一个路由来处理成功的表单提交：

```php
Route::get('myresults', function()
{
    return dd(Input::old());
});
```

## 它是如何工作的...

我们首先创建一个相当简单的表单，由于我们没有向`Form::open()`传递任何参数，它将把数据 POST 到相同的 URL。然后我们创建一个路由来接受`POST`数据并验证它。作为最佳实践，我们还在我们的`post`路由之前添加了`csrf`过滤器。这将提供一些额外的安全性，防止跨站点请求伪造。

我们在`post`路由中设置的第一个变量将保存我们的规则。下一个变量将保存我们希望在出现错误时使用的任何自定义消息。有几种不同的方法来设置消息。

自定义的第一个消息是`min`大小。在这种情况下，它将显示相同的消息，用于任何验证错误，其中有一个`min`规则。我们可以使用`:attribute`和`:min`来保存表单字段名称和错误显示时的最小大小。

我们的第二个消息仅用于特定的表单字段和特定的验证规则。我们首先放置表单字段名称，然后是一个句号，然后是规则。在这里，我们正在检查用户名是否必填，并设置错误消息。

我们的第三个消息是在验证的语言文件中设置的。在`attributes`数组中，我们可以将我们的任何表单字段名称设置为显示我们想要的任何自定义文本。此外，如果我们决定自定义整个应用程序中的特定错误消息，我们可以在该文件的顶部更改默认消息。

## 还有更多...

如果我们查看`app/lang`目录，我们会看到许多翻译已经是 Laravel 的一部分。如果我们的应用程序是本地化的，我们可以选择任何语言设置自定义验证错误消息。

## 另请参阅

+   *创建一个简单的表单*教程

# 向表单添加蜜罐

网络的一个悲哀现实是存在“垃圾邮件机器人”，它们搜索网络并寻找要提交垃圾邮件的表单。帮助应对这一问题的一种方法是使用一种称为**蜜罐**的技术。在这个教程中，我们将创建一个自定义验证来检查垃圾邮件提交。

## 准备工作

对于这个教程，我们只需要一个标准的 Laravel 安装。

## 如何做...

要完成这个教程，请按照以下步骤进行：

1.  在`routes.php`中创建一个路由来保存我们的表单：

```php
Route::get('myform', function()
{
    return View::make('myapp');
});
```

1.  在我们的`app/view`目录中创建一个名为`myform.php`的视图，并添加表单：

```php
<h1>User Info</h1>
<?php $messages =  $errors->all('<p style ="color:red">:message</p>') ?>
<?php
foreach ($messages as $msg)
{
    echo $msg;
}
?>
<?= Form::open() ?>
<?= Form::label('email', 'Email') ?>
<?= Form::text('email', Input::old('email')) ?>
<br>
<?= Form::label('username', 'Username') ?>
<?= Form::text('username', Input::old('username')) ?>
<br>
<?= Form::label('password', 'Password') ?>
<?= Form::password('password') ?>
<?= Form::text('no_email', '', array('style' =>'display:none')) ?>
<br>
<?= Form::submit('Send it!') ?>
<?= Form::close() ?>
```

1.  在我们的`routes.php`文件中创建一个路由来处理`post`数据，并对其进行验证：

```php
Route::post('myform', array('before' => 'csrf', function()
{
    $rules = array(
        'email'    => 'required|email',
        'password' => 'required',
        'no_email' => 'honey_pot'
    );
    $messages = array(
        'honey_pot' => 'Nothing should be in this field.'
    );
    $validation = Validator::make(Input::all(), $rules,$messages);

    if ($validation->fails())
    {
        return Redirect::to('myform')->withErrors($validation)->withInput();
    }

    return Redirect::to('myresults')->withInput();
}));
```

1.  在我们的`routes.php`文件中，创建一个自定义验证：

```php
Validator::extend('honey_pot', function($attribute, $value,$parameters)
{
    return $value == '';
});
```

1.  创建一个简单的路由用于成功页面：

```php
Route::get('myresults', function()
{
    return dd(Input::old());
});
```

## 它是如何工作的...

我们首先创建一个相当简单的表单；因为我们没有向`Form::open()`传递任何参数，它将把数据 POST 到相同的 URL。在表单中，我们创建一个旨在为空的字段，但使用 CSS 隐藏它。通过将其命名为带有`email`一词的内容，许多垃圾邮件机器人会误以为它是一个`email`字段并尝试填充它。

然后，我们创建一个路由来接受`post`数据并对其进行验证，并在路由之前添加一个`csrf`过滤器。我们为我们的`no_email`字段添加一个自定义验证规则，以确保该字段保持为空。我们还在`$messages`数组中为该规则创建一个错误消息。

接下来，我们实际上在`routes`文件中创建我们的自定义验证规则。这个规则将从表单字段获取值，并在值为空时返回`TRUE`。

现在，如果一个机器人试图填写整个表单，它将无法验证，因为额外的字段设计为保持为空。

## 还有更多...

创建自定义验证的另一种选择是使用规则`size: 0`，这将确保`honey_pot`字段的长度正好为`0`个字符。然而，这种方法使验证检查变得简单得多。

我们可能还希望将任何蜜罐错误重定向到另一个没有表单的页面。这样，任何自动表单提交脚本都不会继续尝试提交表单。

# 使用 Redactor 上传图片

有一些不同的 JavaScript 库可以将表单的文本区域转换为所见即所得的编辑器。Redactor 是一个较新的库，但编码非常好，并在短时间内获得了相当大的流行。在这个教程中，我们将把 Redactor 应用到我们的 Laravel 表单中，并创建路由以允许通过 Redactor 上传图片。

## 准备工作

我们需要从[`github.com/dybskiy/redactor-js/tree/master/redactor`](https://github.com/dybskiy/redactor-js/tree/master/redactor)下载 Redactor 的副本。下载`redactor.min.js`并保存到`public/js`目录。下载`redactor.css`并保存到`public/css`目录。

## 如何做...

要完成这个教程，请按照以下步骤进行：

1.  在我们的`routes.php`文件中创建一个路由来保存带有`redactor`字段的表单：

```php
Route::get('redactor', function() 
{
    return View::make('redactor');
});
```

1.  在我们的`app/views`目录中创建一个名为`redactor.php`的视图：

```php
<!DOCTYPE html>
<html>
    <head>
        <title>Laravel and Redactor</title>
        <meta charset="utf-8">
        <link rel="stylesheet" href="css/redactor.css" />
        <script src="//ajax.googleapis.com/ajax/libs/jquery/1.10.2/jquery.min.js"></script>
        <script src="js/redactor.min.js"></script>
    </head>
    <body>
        <?= Form::open() ?>
        <?= Form::label('mytext', 'My Text') ?>
        <br>
        <?= Form::textarea('mytext', '', array('id' =>'mytext')) ?>
        <br>
        <?= Form::submit('Send it!') ?>
        <?= Form::close() ?>
        <script type="text/javascript">
            $(function() {
                $('#mytext').redactor({
                    imageUpload: 'redactorupload'
                });
            });
        </script>
    </body>
</html>
```

1.  创建一个处理图片上传的路由：

```php
Route::post('redactorupload', function()
{
    $rules = array(
        'file' => 'image|max:10000'
    );
    $validation = Validator::make(Input::all(), $rules);
    $file = Input::file('file');
    if ($validation->fails())
    {
        return FALSE;
    }
    else
    {
        if ($file->move('files', $file->
            getClientOriginalName()))
        {
            return Response::json(array('filelink' =>
               'files/' . $file->getClientOriginalName()));
        }
        else
        {
            return FALSE;
        }
    }
});

```

1.  创建另一个路由来显示我们的表单输入后。

```php
Route::post('redactor', function() 
{
    return dd(Input::all());
});
```

## 它是如何工作的...

创建完我们的表单路由后，我们创建视图来保存我们的表单 HTML。在页面的头部，我们加载 redactor CSS，jquery 库（使用 Google 的 CDN），和 redactor JavaScript 文件。

我们的表单只有一个字段，一个名为`mytext`的文本区域。在我们的脚本区域中，我们在文本区域字段上初始化 Redactor，并将`imageUpload`参数设置为一个接受图片上传的路由或控制器。我们的设置为`redactorupload`，所以我们为它创建一个接受`post`数据的路由。

在我们的`redactorupload`路由中，我们进行一些验证，如果一切正常，图像将上传到我们的图像目录。要在文本区域中显示图像，它需要一个带有文件链接的 JSON 数组作为键，图像路径作为值。为此，我们将使用 Laravel 内置的`Response::json`方法，并传入一个带有图像位置的数组。

在我们的表单页面上，如果图像验证和上传正确，Redactor 将在文本区域内显示图像。如果我们提交，我们将看到文本包括`<img>`标签和图像路径。

## 还有更多...

虽然这个示例是专门用于图像上传的，但非图像文件上传的工作方式非常类似。唯一的真正区别是文件上传路由还应该在 JSON 输出中返回文件名。

# 使用 Jcrop 裁剪图像

图像编辑和处理有时可能是我们应用程序中难以实现的事情。使用 Laravel 和 Jcrop JavaScript 库，我们可以使任务变得更简单。

### 提示

**下载示例代码**

您可以从您在[`www.packtpub.com`](http://www.packtpub.com)购买的所有 Packt 图书的帐户中下载示例代码文件。如果您在其他地方购买了这本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，以便直接将文件发送到您的电子邮件。

## 准备工作

我们需要从[`deepliquid.com/content/Jcrop_Download.html`](http://deepliquid.com/content/Jcrop_Download.html)下载 Jcrop 库并解压缩。将文件`jquery.Jcrop.min.js`放入我们的`public/js`目录，将`jquery.Jcrop.min.css`和`Jcrop.gif`文件放入我们的`public/css`目录。我们将使用 Google CDN 版本的 jQuery。我们还需要确保在服务器上安装了 GD 库，以便进行图像处理。在我们的`public`目录中，我们需要一个图像文件夹来存储图像，并且应该对其进行可写权限设置。

## 如何做...

按照以下步骤完成此示例：

1.  让我们在我们的`routes.php`文件中创建一个路由来保存我们的表单：

```php
Route::get('imageform', function()
{
    return View::make('imageform');
});
```

1.  在`app/views`中创建用于上传图像的表单，文件名为`imageform.php`：

```php
<h1>Laravel and Jcrop</h1>
<?= Form::open(array('files' => true)) ?>
<?= Form::label('image', 'My Image') ?>
<br>
<?= Form::file('image') ?>
<br>
<?= Form::submit('Upload!') ?>
<?= Form::close() ?>
```

1.  创建一个路由来处理图像上传和验证：

```php
Route::post('imageform', function()
{
    $rules = array(
        'image' => 'required|mimes:jpeg,jpg|max:10000'
    );

    $validation = Validator::make(Input::all(), $rules);

    if ($validation->fails())
    {
        return Redirect::to('imageform')->withErrors($validation);
    }
    else
    {
        $file = Input::file('image');
        $file_name = $file->getClientOriginalName();
        if ($file->move('images', $file_name))
        {
            return Redirect::to('jcrop')->with('image',$file_name);
        }
        else
        {
            return "Error uploading file";
        }
    }
});
```

1.  为我们的 Jcrop 表单创建一个路由：

```php
Route::get('jcrop', function()
{
    return View::make('jcrop')->with('image', 'images/'. Session::get('image'));
});
```

1.  在我们的`app/views`目录中创建一个表单，我们可以在其中裁剪图像，文件名为`jcrop.php`：

```php
<html>
    <head>
        <title>Laravel and Jcrop</title>
        <meta charset="utf-8">
        <link rel="stylesheet" href="css/jquery.Jcrop.min.css" />
        <script src="//ajax.googleapis.com/ajax/libs/jquery/1.10.2/jquery.min.js"></script>
        <script src="js/jquery.Jcrop.min.js"></script>
    </head>
    <body>
        <h2>Image Cropping with Laravel and Jcrop</h2>
        <img src="<?php echo $image ?>" id="cropimage">

        <?= Form::open() ?>
        <?= Form::hidden('image', $image) ?>
        <?= Form::hidden('x', '', array('id' => 'x')) ?>
        <?= Form::hidden('y', '', array('id' => 'y')) ?>
        <?= Form::hidden('w', '', array('id' => 'w')) ?>
        <?= Form::hidden('h', '', array('id' => 'h')) ?>
        <?= Form::submit('Crop it!') ?>
        <?= Form::close() ?>

        <script type="text/javascript">
            $(function() {
                $('#cropimage').Jcrop({
                    onSelect: updateCoords
                });
            });
            function updateCoords(c) {
                $('#x').val(c.x);
                $('#y').val(c.y);
                $('#w').val(c.w);
                $('#h').val(c.h);
            };
        </script>
    </body>
</html>
```

1.  创建一个处理图像并显示图像的路由：

```php
Route::post('jcrop', function()
{
    $quality = 90;

    $src  = Input::get('image');
    $img  = imagecreatefromjpeg($src);
    $dest = ImageCreateTrueColor(Input::get('w'),
        Input::get('h'));

    imagecopyresampled($dest, $img, 0, 0, Input::get('x'),
        Input::get('y'), Input::get('w'), Input::get('h'),
        Input::get('w'), Input::get('h'));
    imagejpeg($dest, $src, $quality);

    return "<img src='" . $src . "'>";
});

```

## 它是如何工作的...

我们从基本的文件上传开始；为了简化，我们只使用`.jpg`文件。我们使用验证来检查图像类型，以及确保文件大小在 10,000 千字节以下。文件上传后，我们将路径发送到我们的 Jcrop 路由。

在 Jcrop 路由的 HTML 中，我们创建一个带有隐藏字段的表单，该字段将保存裁剪的尺寸。JavaScript 函数`updateCoords`获取裁剪尺寸并更新这些隐藏字段的值。

当我们完成裁剪时，我们提交表单，我们的路由获取 POST 数据。图像通过 GD 库进行裁剪，基于发布的尺寸。然后我们覆盖图像并显示更新和裁剪后的文件。

## 还有更多...

虽然这个示例只涵盖了裁剪 jpg 图像，添加`gif`和`png`图像也不会很困难。我们只需要通过将文件名传递给 Laravel 并使用`File::extension()`来获取文件扩展名。然后，我们可以使用适当的 PHP 函数进行`switch`或`if`语句。例如，如果扩展名是`.png`，我们将使用`imagecreatefrompng()`和`imagepng()`。更多信息可以在[`www.php.net/manual/en/ref.image.php`](http://www.php.net/manual/en/ref.image.php)找到。

# 创建自动完成文本输入

在我们的网络表单上，可能会有时候我们想要有一个自动完成文本字段。这对于填充常见搜索词或产品名称非常方便。使用 jQueryUI 自动完成库以及 Laravel，这变得非常容易。

## 准备工作

在这个食谱中，我们将使用 jQuery 和 jQueryUI 的 CDN 版本；但是，如果我们想要本地拥有它们，我们也可以下载它们并将它们放在我们的`public/js`目录中。

## 如何做...

要完成这个食谱，请按照以下步骤进行：

1.  创建一个路由来保存我们的自动完成表单：

```php
Route::get('autocomplete', function()
{
    return View::make('autocomplete');
});
```

1.  在`app/views`目录中创建一个名为`autocomplete.php`的视图，其中包含我们表单的 HTML 和 JavaScript：

```php
<!DOCTYPE html>
<html>
    <head>
        <title>Laravel Autocomplete</title>
        <meta charset="utf-8">
        <link rel="stylesheet"href="//codeorigin.jquery.com/ui/1.10.2/themes/smoothness/jquery-ui.css" />
        <script src="//ajax.googleapis.com/ajax/libs/jquery/1.10.2/jquery.min.js"></script>
        <script src="//codeorigin.jquery.com/ui/1.10.2/jquery-ui.min.js"></script>
    </head>
    <body>
        <h2>Laravel Autocomplete</h2>

        <?= Form::open() ?>
        <?= Form::label('auto', 'Find a color: ') ?>
        <?= Form::text('auto', '', array('id' => 'auto'))?>
        <br>
        <?= Form::label('response', 'Our color key: ') ?>
        <?= Form::text('response', '', array('id' =>'response', 'disabled' => 'disabled')) ?>
        <?= Form::close() ?>

        <script type="text/javascript">
            $(function() {
                $("#auto").autocomplete({
                    source: "getdata",
                    minLength: 1,
                    select: function( event, ui ) {
                        $('#response').val(ui.item.id);
                    }
                });
            });
        </script>
    </body>
</html>
```

1.  创建一个路由，用于填充`autocomplete`字段的数据：

```php
Route::get('getdata', function()
{
    $term = Str::lower(Input::get('term'));
    $data = array(
        'R' => 'Red',
        'O' => 'Orange',
        'Y' => 'Yellow',
        'G' => 'Green',
        'B' => 'Blue',
        'I' => 'Indigo',
        'V' => 'Violet',
    );
    $return_array = array();

    foreach ($data as $k => $v) {
        if (strpos(Str::lower($v), $term) !== FALSE) {
            $return_array[] = array('value' => $v, 'id' =>$k);
        }
    }
    return Response::json($return_array);
});
```

## 它是如何工作的...

在我们的表单中，我们正在创建一个文本字段来接受用户输入，该输入将用于`autocomplete`。还有一个禁用的文本字段，我们可以用来查看所选值的 ID。如果您对特定值有一个数字的 ID，或者以非标准方式命名，这可能会很有用。在我们的示例中，我们使用颜色的第一个字母作为 ID。

当用户开始输入时，`autocomplete`会向我们添加的源发送一个`GET`请求，使用查询字符串中的单词`term`。为了处理这个，我们创建一个路由来获取输入，并将其转换为小写。对于我们的数据，我们使用一个简单的值数组，但在这一点上添加数据库查询也是相当容易的。我们的路由检查数组中的值，看看是否有任何与用户输入匹配的值，如果有，就将 ID 和值添加到我们将返回的数组中。然后，我们将数组输出为 JSON，供`autocomplete`脚本使用。

回到我们的表单页面，当用户选择一个值时，我们将 ID 添加到禁用的响应字段中。很多时候，这将是一个隐藏字段，我们可以在提交表单时传递它。

## 还有更多...

如果我们想要让我们的`getdata`路由只能从我们的自动完成表单或其他 AJAX 请求中访问，我们可以简单地将代码包装在`if (Request::ajax()) {}`中，或者创建一个拒绝任何非 AJAX 请求的过滤器。

# 制作类似 CAPTCHA 的垃圾邮件捕捉器

对抗自动填写网络表单的“机器人”的一种方法是使用 CAPTCHA 技术。这向用户显示一个带有一些随机字母的图像；用户必须在文本字段中填写这些字母。在这个食谱中，我们将创建一个 CAPTCHA 图像，并验证用户是否已正确输入。

## 准备工作

我们需要一个标准的 Laravel 安装，并确保我们的服务器上安装了 GD2 库，这样我们就可以创建一个图像。

## 如何做...

要完成这个食谱，请按照以下步骤进行：

1.  在我们的`app`目录中，创建一个名为`libraries`的目录，并在我们的`composer.json`文件中更新如下：

```php
"autoload": {
    "classmap": [
        "app/commands",
        "app/controllers",
        "app/models",
        "app/database/migrations",
        "app/database/seeds",
        "app/tests/TestCase.php",
        "app/libraries"
    ]
},
```

1.  在我们的`app/libraries`目录中，创建一个名为`Captcha.php`的文件，用于保存我们简单的`Captcha`类：

```php
<?php
class Captcha {
    public function make() 
    {
        $string = Str::random(6, 'alpha');
        Session::put('my_captcha', $string);

        $width      = 100;
        $height     = 25;
        $image      = imagecreatetruecolor($width,$height);
        $text_color = imagecolorallocate($image, 130, 130,130);
        $bg_color   = imagecolorallocate($image, 190, 190,190);

        imagefilledrectangle($image, 0, 0, $width, $height,$bg_color);        
        imagestring($image, 5, 16, 4, $string,$text_color);

        ob_start();
        imagejpeg($image);
        $jpg = ob_get_clean();
        return "data:image/jpeg;base64,". base64_encode($jpg);
    }
}
```

1.  在我们的应用程序根目录中，打开命令行界面以更新`composer`自动加载程序：

```php
**php composer.phar dump-autoload**

```

1.  在`routes.php`中创建一个路由来保存带有`captcha`的表单：

```php
Route::get('captcha', function() 
{
    $captcha = new Captcha;
    $cap = $captcha->make();
    return View::make('captcha')->with('cap', $cap);
});
```

1.  在`app/views`目录中创建我们的`captcha`视图，名称为`captcha.php`：

```php
<h1>Laravel Captcha</h1>
<?php
if (Session::get('captcha_result')) {
    echo '<h2>' . Session::get('captcha_result') . '</h2>';
}
?>
<?php echo Form::open() ?>
<?php echo Form::label('captcha', 'Type these letters:') ?>
<br>
<img src="<?php echo $cap ?>">
<br>
<?php echo Form::text('captcha') ?>
<br>
<?php echo Form::submit('Verify!') ?>
<?php echo Form::close() ?>
```

1.  创建一个路由来比较`captcha`值和用户输入：

```php
Route::post('captcha', function() 
{
    if (Session::get('my_captcha') !==Input::get('captcha')) {
        Session::flash('captcha_result', 'No Match.');
    } else {
        Session::flash('captcha_result', 'They Match!');
    }
    return Redirect::to('captcha');
});
```

## 它是如何工作的...

我们首先更新我们的`composer.json`文件，将我们的`libraries`目录添加到自动加载程序中。现在，我们可以将任何我们想要的类或库添加到该目录中，即使它们是自定义类或可能是一些旧代码。

为了保持简单，我们创建了一个简单的`Captcha`类，其中只有一个`make()`方法。在这个方法中，我们首先使用 Laravel 的`Str:random()`创建一个随机字符串，我们告诉它输出一个只包含字母的 6 个字符的字符串。然后我们将该字符串保存到会话中，以便以后用于验证。

使用字符串，我们创建了一个 100x25 像素的 jpg 图像，背景为灰色，文本为深灰色。我们不是将文件保存到服务器，而是使用输出缓冲区并将图像数据保存到一个变量中。这样，我们可以创建一个数据 URI 并发送回我们的路由。

接下来，我们需要运行 composer 的`dump-autoload`命令，这样我们的新类才能被应用程序使用。

在我们的`captcha`路由中，我们使用`Captcha`类来创建`captcha`数据 URI 并将其发送到我们的表单。对于我们的目的，表单将简单地显示图像并要求在文本字段中输入字符。

当用户提交表单时，我们将比较`Captcha`类创建的 Session 与用户输入。在这个示例中，我们只是检查这两个值是否匹配，但我们也可以创建一个自定义验证方法并将其添加到我们的规则中。然后我们设置一个会话来表示是否匹配，并将用户返回到 CAPTCHA 页面。


# 第三章：验证您的应用程序

在本章中，我们将涵盖：

+   设置和配置 Auth 库

+   创建一个身份验证系统

+   在登录后检索和更新用户信息

+   限制对某些页面的访问

+   设置 OAuth 与 HybridAuth 包

+   使用 OpenID 进行登录

+   使用 Facebook 凭据登录

+   使用 Twitter 凭据登录

+   使用 LinkedIn 登录

# 介绍

许多现代网络应用程序都包括用户注册和登录的方式。为了确保我们的应用程序和用户信息的安全，我们需要确保每个用户都经过适当的身份验证。Laravel 包括一个很棒的`Auth`类，使得这个任务非常容易完成。在本章中，我们将从设置我们自己的身份验证系统开始，然后转向在我们的 Laravel 应用程序中使用第三方身份验证。

# 设置和配置 Auth 库

要使用 Laravel 的身份验证系统，我们需要确保它设置正确。在这个食谱中，我们将看到一种常见的完成设置的方式。

## 准备工作

要设置身份验证，我们只需要安装 Laravel 并运行一个 MySQL 实例。

## 如何做…

要完成这个步骤，请按照以下步骤进行：

1.  进入您的`app/config/session.php`配置文件，并确保它设置为使用`native`：

```php
**'driver' => 'native'**

```

1.  `app/config/auth.php`配置文件的默认设置应该是可以的，但确保它们设置如下：

```php
'driver' => 'eloquent',
'model' => 'User',
'table' => 'users',
```

1.  在 MySQL 中，创建一个名为`authapp`的数据库，并确保在`app/config/database.php`配置文件中设置正确。以下是我们将使用的设置：

```php
'default' => 'mysql',

'connections' => array(

    'mysql' => array(
        'driver'   => 'mysql',
        'host'     => 'localhost',
        'database' => 'authapp',
        'username' => 'root',
        'password' => '',
        'charset'  => 'utf8',
        'prefix'   => '',
    ),
),
```

1.  我们将使用迁移和 Schema 构建器以及 Artisan 命令行来设置我们的`Users`表，因此我们需要创建我们的迁移表：

```php
**php artisan migrate:install**

```

1.  为我们的`Users`表创建迁移：

```php
**php artisan migrate:make create_users_table**

```

1.  在`app/database/migrations`目录中，将会有一个新文件，文件名是日期后跟着`create_users_table.php`。在那个文件中，我们创建我们的表：

```php
<?php

use Illuminate\Database\Migrations\Migration;

class CreateUsersTable extends Migration {

    /**
    * Run the migrations.
    *
    * @return void
    */
    public function up()
    {
        Schema::create('users', function($table)
        {
            $table->increments('id');
            $table->string('email');
            $table->string('password', 64);
            $table->string('name');
            $table->boolean('admin');
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
        Schema::drop('users');
    }

}
```

1.  在 Artisan 中运行迁移来创建我们的表，一切都应该设置好了：

```php
**php artisan migrate**

```

## 它是如何工作的…

身份验证使用会话来存储用户信息，因此我们首先需要确保我们的会话配置正确。有各种各样的方式来存储会话，包括使用数据库或 Redis，但是为了我们的目的，我们将只使用`native`驱动程序，它利用了 Symfony 的原生会话驱动程序。

在设置身份验证配置时，我们将使用 Eloquent ORM 作为我们的驱动程序，电子邮件地址作为我们的用户名，模型将是 User。Laravel 附带了一个默认的 User 模型，并且它在开箱即用时非常好用，所以我们将使用它。为了简单起见，我们将坚持使用表名的默认配置，即模型类名的复数形式，但是如果我们想要的话，我们可以自定义它。

一旦我们确保我们的数据库配置设置正确，我们就可以使用 Artisan 来创建我们的迁移。在我们的迁移中，我们将创建我们的用户表，并存储电子邮件地址、密码、姓名和一个布尔字段来存储用户是否是管理员。完成后，我们运行迁移，我们的数据库将设置好来构建我们的身份验证系统。

# 创建身份验证系统

在这个食谱中，我们将创建一个简单的身份验证系统。它可以直接使用，也可以扩展以包括更多的功能。

## 准备工作

我们将使用*设置和配置 Auth 库*食谱中创建的代码作为我们身份验证系统的基础。

## 如何做…

要完成这个步骤，请按照以下步骤进行：

1.  在我们的`routes.php`文件中创建一个路由来保存我们的注册表单：

```php
Route::get('registration', function()
{
    return View::make('registration');
});
```

1.  通过在`app/views`中创建一个名为`registration.php`的新文件来创建一个注册表单：

```php
<!DOCTYPE html>
<html>
    <head>
        <title>Laravel Authentication - Registration</title>
        <meta charset="utf-8">
    </head>
    <body>
        <h2>Laravel Authentication - Registration</h2>
        <?php $messages =  $errors->all('<p style="color:red">:message</p>') ?>
        <?php foreach ($messages as $msg): ?>
            <?= $msg ?>
        <?php endforeach; ?>

<?= Form::open() ?>
        <?= Form::label('email', 'Email address: ') ?>
        <?= Form::text('email', Input::old('email')) ?>
        <br>
        <?= Form::label('password', 'Password: ') ?>
        <?= Form::password('password') ?>
        <br>
        <?= Form::label('password_confirm','Retype Password: ') ?>
        <?= Form::password('password_confirm') ?>
        <br>
        <?= Form::label('name', 'Name: ') ?>
        <?= Form::text('name', Input::old('name')) ?>
        <br>
        <?= Form::label('admin', 'Admin?: ') ?>
        <?= Form::checkbox('admin','true',Input::old('admin')) ?>
        <br>
        <?= Form::submit('Register!') ?>
        <?= Form::close() ?>
    </body>
</html>
```

1.  创建一个路由来处理注册页面：

```php
Route::post('registration', array('before' => 'csrf',function()
{
    $rules = array(
        'email'    => 'required|email|unique:users',
        'password' => 'required|same:password_confirm',
        'name'     => 'required'
    );
    $validation = Validator::make(Input::all(), $rules);

    if ($validation->fails())
    {
        return Redirect::to('registration')->withErrors($validation)->withInput();
    }

    $user           = new User;
    $user->email    = Input::get('email');
    $user->password = Hash::make(Input::get('password'));
    $user->name     = Input::get('name');
    $user->admin    = Input::get('admin') ? 1 : 0;
    if ($user->save())
    {
        Auth::loginUsingId($user->id);
        return Redirect::to('profile');
    }
    return Redirect::to('registration')->withInput();
}));
```

1.  通过在`routes.php`中添加一个路由来为您的个人资料创建一个简单的页面：

```php
Route::get('profile', function()
{
    if (Auth::check())
    {
        return 'Welcome! You have been authorized!';
    }
    else
    {
        return 'Please <a href="login">Login</a>';
    }
});
```

1.  在`routes.php`中创建一个登录路由来保存登录表单：

```php
Route::get('login', function()
{
    return View::make('login');
});
```

1.  在我们的`app/views`目录中，创建一个名为`login.php`的文件：

```php
<!DOCTYPE html>
<html>
    <head>
        <title>Laravel Authentication - Login</title>
        <meta charset="utf-8">
    </head>
    <body>
        <h2>Laravel Authentication - Login</h2>
        <?= '<span style="color:red">' .Session::get('login_error') . '</span>' ?>

        <?= Form::open() ?>
        <?= Form::label('email', 'Email address: ') ?>
        <?= Form::text('email', Input::old('email')) ?>
        <br>
        <?= Form::label('password', 'Password: ') ?>
        <?= Form::password('password') ?>
        <br>
        <?= Form::submit('Login!') ?>
        <?= Form::close() ?>
    </body>
</html>
```

1.  在`routes.php`中创建一个路由来验证登录：

```php
Route::post('login', function()
{
    $user = array(
        'username' => Input::get('email'),
        'password' => Input::get('password')
    );

    if (Auth::attempt($user))
    {
        return Redirect::to('profile');
    }

    return Redirect::to('login')->with('login_error','Could not log in.');
});
```

1.  在`routes.php`中创建一个安全页面的路由：

```php
Route::get('secured', array('before' => 'auth', function()
{
    return 'This is a secured page!';
}));
```

## 工作原理...

首先，我们创建一个相当简单的注册系统。在我们的注册表单中，我们将要求输入电子邮件地址、密码、密码确认、姓名，以及用户是否是管理员的选项。在表单字段中，我们还添加了`Input::old()`；因此，如果表单验证不正确，我们可以重新填充字段，而无需用户重新输入所有信息。

然后我们的表单提交，添加 CSRF 过滤器，并进行一些验证。如果验证通过，我们就创建一个新的 User 模型实例，并添加表单中的字段。对于密码，我们使用`Hash::make()`来保护密码安全。由于我们的 admin 字段接受布尔值，我们检查 admin 复选框是否被选中；如果是，我们将值设置为`1`。

如果一切保存正确，我们可以通过将刚创建的用户 ID 传递给`Auth::loginUsingId()`来自动登录用户，并将他们重定向到 profile 页面。

profile 路由的第一件事是运行`Auth::check()`来查看用户是否真的已登录。如果没有，它将显示一个链接到登录页面。

登录页面是一个简单的表单，要求输入电子邮件 ID 和密码。提交后，我们将这两个值放入一个数组中，并将它们传递给`Auth::attempt()`，它将自动对我们的密码进行哈希处理，并在数据库中查找凭据。如果成功，`Auth`类将设置一个会话，并将用户重定向到 profile 页面。

如果用户尝试访问*安全*路由，系统将把他们重定向到登录页面。使用 Laravel 的`Redirect::intended()`，我们可以将他们重定向回他们最初尝试访问的页面。

## 另请参阅

+   *设置和配置 Auth 库*示例

# 在登录后检索和更新用户信息

用户登录后，我们需要获取关于他/她的信息。在这个示例中，我们将看到如何获取这些信息。

## 准备工作

我们将使用*设置和配置 Auth 库*和*创建身份验证系统*示例中创建的代码作为此示例的基础。

## 如何做...

要完成这个示例，请按照以下步骤进行：

1.  使用以下代码更新 profile 路由：

```php
Route::get('profile', function()
{
    if (Auth::check())
    {
        return View::make('profile')->with('user',Auth::user());
    }
    else
    {
        return Redirect::to('login')->with('login_error','You must login first.');
    }
});
```

1.  通过在`app/views`目录中创建一个名为`profile.php`的文件来创建我们的 profile 视图：

```php
<?php echo Session::get('notify') ?  "<p style='color:
    green'>" . Session::get('notify') . "</p>" : "" ?>
<h1>Welcome <?php echo $user->name ?></h1>
<p>Your email: <?php echo $user->email ?></p>
<p>Your account was created on: <?php echo $user
    ->created_at ?></p>
<p><a href="<?= URL::to('profile-edit') ?>">Edit your
    information</a></p>
```

1.  创建一个路由来保存我们的表单以编辑信息：

```php
Route::get('profile-edit', function()
{
    if (Auth::check())
    {
        $user = Input::old() ? (object) Input::old() :Auth::user();
        return View::make('profile_edit')->with('user',$user);
    }
});
```

1.  为我们的编辑表单创建一个视图：

```php
<h2>Edit User Info</h2>
<?php $messages =  $errors->all('<p style="color:red">:message</p>') ?>
<?php foreach ($messages as $msg): ?>
    <?= $msg ?>
<?php endforeach; ?>
<?= Form::open() ?>
<?= Form::label('email', 'Email address: ') ?>
<?= Form::text('email', $user->email) ?>
<br>
<?= Form::label('password', 'Password: ') ?>
<?= Form::password('password') ?>
<br>
<?= Form::label('password_confirm', 'Retype Password: ') ?>
<?= Form::password('password_confirm') ?>
<br>
<?= Form::label('name', 'Name: ') ?>
<?= Form::text('name',  $user->name) ?>
<br>
<?= Form::submit('Update!') ?>
<?= Form::close() ?>
```

1.  创建一个处理表单的路由：

```php
Route::post('profile-edit', function()
{
    $rules = array(
        'email'    => 'required|email',
        'password' => 'same:password_confirm',
        'name'     => 'required'
    );
    $validation = Validator::make(Input::all(), $rules);

    if ($validation->fails())
    {
        return Redirect::to('profile-edit')->withErrors($validation)->withInput();
    }

    $user = User::find(Auth::user()->id);
    $user->email = Input::get('email');
    if (Input::get('password')) {
        $user->password = Hash::make(Input::get('password'));
    }
    $user->name = Input::get('name');
    if ($user->save())
    {
        return Redirect::to('profile')->with('notify','Information updated');
    }
    return Redirect::to('profile-edit')->withInput();
});
```

## 工作原理...

为了获取用户的信息并允许他/她更新信息，我们首先重新设计我们的 profile 路由。我们创建一个 profile 视图，并将`Auth::user()`传递给变量`$user`。然后，在视图文件中，我们简单地输出我们收集到的任何信息。我们还创建了一个链接到一个页面，用户可以在该页面编辑他/她的信息。

我们的 profile 编辑页面首先检查用户是否已登录。如果是，我们希望填充`$user`变量。由于如果有验证错误，我们将重新显示表单，所以我们首先检查`Input::old()`中是否有任何内容。如果没有，这可能是页面的新访问，所以我们只使用`Auth::user()`。如果正在使用`Input::old()`，我们将将其重新转换为对象，因为它通常是一个数组，并在我们的`$user`变量中使用它。

我们的编辑视图表单与注册表单非常相似，只是如果我们已登录，表单已经被填充。

当表单提交时，它会经过一些验证。如果一切有效，我们需要从数据库中获取用户，使用`User::find()`和存储在`Auth::user()`中的用户 ID。然后我们将我们的表单输入添加到用户对象中。对于密码字段，如果它为空，我们可以假设用户不想更改它。因此，我们只有在已经输入了内容时才会更新密码。

最后，我们保存用户信息并将其重定向回个人资料页面。

## 还有更多...

我们数据库中的电子邮件值可能需要是唯一的。对于本步骤，我们可能需要快速检查用户表，并确保正在更新的电子邮件地址没有在其他地方使用。

## 另请参阅

+   *创建身份验证系统*的步骤

# 限制对某些页面的访问

在本步骤中，我们将探讨如何限制对应用程序中各种页面的访问。这样，我们可以使页面只对具有正确凭据的用户可见。

## 准备工作

我们将使用*设置和配置 Auth 库*和*创建身份验证系统*的步骤中创建的代码作为本步骤的基础。

## 如何做...

要完成这个步骤，请按照以下步骤进行：

1.  在我们的`filters.php`文件中创建一个检查已登录用户的过滤器。默认的 Laravel`auth`过滤器就可以了：

```php
Route::filter('auth', function()
{
    if (Auth::guest()) return Redirect::guest('login');
});
```

1.  在`filter.php`中创建一个用于检查用户是否为管理员的过滤器：

```php
Route::filter('auth_admin', function()
{
    if (Auth::guest()) return Redirect::guest('login');
    if (Auth::user()->admin != TRUE)
        return Redirect::to('restricted');
});
```

1.  创建一个我们限制给已登录用户的路由：

```php
Route::get('restricted', array('before' => 'auth',
    function()
{
    return 'This page is restricted to logged-in users!
        <a href="admin">Admins Click Here.</a>';
}));
```

1.  创建一个只限管理员访问的路由：

```php
Route::get('admin', array('before' => 'auth_admin',function()
{
    return 'This page is restricted to Admins only!';
}));
```

## 它是如何工作的...

过滤器是 Laravel 的一个强大部分，可以用来简化许多任务。Laravel 默认的`auth`过滤器只是简单地检查用户是否已登录，如果没有，则将其重定向到登录页面。在我们的`restricted`路由中，我们添加`auth`过滤器在函数执行之前运行。

我们的`auth_admin`过滤器用于确保用户已登录，并检查用户是否设置为`admin`。如果没有，他/她将被重定向回普通的受限页面。

# 使用 HybridAuth 包设置 OAuth

有时我们可能不想担心存储用户的密码。在这种情况下，OAuth 已经成为一个流行的选择，它允许我们基于第三方服务（如 Facebook 或 Twitter）对用户进行身份验证。本步骤将展示如何设置`HybridAuth`包以简化 OAuth。

## 准备工作

对于本步骤，我们需要一个标准的 Laravel 安装和一种访问命令行界面的方法，以便我们可以使用 Artisan 命令行实用程序。

## 如何做...

要完成这个步骤，请按照以下步骤进行：

1.  打开我们应用的`composer.json`文件，并将 HybridAuth 添加到`require`部分，使其看起来像这样：

```php
"require": {
    "laravel/framework": "4.0.*",
    "hybridauth/hybridauth": "dev-master"
},
```

1.  在命令行界面中，按以下方式更新 composer：

```php
**php composer.phar update**

```

1.  在`app/config`目录中，创建一个名为`oauth.php`的新文件：

```php
<?php
return array(
    "base_url"   => "http://path/to/our/app/oauth/auth",
    "providers"  => array (
        "OpenID" => array ("enabled" => true),
        "Facebook" => array (
            "enabled"  => TRUE,
            "keys"     => array ("id" => "APP_ID", "secret"=> "APP_SECRET"),
            "scope"    => "email",
        ),
        "Twitter" => array (
            "enabled" => true,
            "keys"    => array ("key" => "CONSUMER_KEY","secret" => "CONSUMER_SECRET")
        ),
        "LinkedIn" => array (
            "enabled" => true,
            "keys" => array ("key" => "APP_KEY", "secret"=> "APP_SECRET")
        )
    )
);
```

## 它是如何工作的...

我们首先要将 HybridAuth 包添加到我们的 composer 文件中。现在，当我们更新 composer 时，它将自动下载并安装该包。从那时起，我们可以在整个应用程序中使用该库。

我们的下一步是设置一个配置文件。该文件以一个 URL 开头，身份验证站点将向该 URL 发送用户。该 URL 应该路由到我们将运行 HybridAuth 并进行实际身份验证的路由或控制器。最后，我们需要添加我们要对抗进行身份验证的站点的凭据。可以在 HybridAuth 网站上找到完整的站点列表：[`hybridauth.sourceforge.net/userguide.html`](http://hybridauth.sourceforge.net/userguide.html)。

# 使用 OpenID 进行登录

如果我们不想在我们的应用程序中存储用户的密码，还有其他使用第三方的身份验证方法，比如 OAuth 和 OpenID。在本步骤中，我们将使用 OpenID 来登录我们的用户。

## 准备工作

对于本步骤，我们需要一个标准的 Laravel 安装，并完成*使用 HybridAuth 包设置 OAuth*的步骤。

## 如何做...

要完成这个步骤，请按照以下步骤进行：

1.  在我们的`app/config`目录中，创建一个名为`openid_auth.php`的新文件：

```php
<?php
return array(
    "base_url"   => "http://path/to/our/app/openid/auth",
    "providers"  => array (
        "OpenID" => array ("enabled" => TRUE)
    )
);
```

1.  在我们的`routes.php`文件中，创建一个路由来保存我们的登录表单：

```php
Route::get('login', function()
{
    return View::make('login');
});
```

1.  在我们的`app/views`目录中，创建一个名为`login.php`的新视图：

```php
<!DOCTYPE html>
<html>
    <head>
        <title>Laravel Open ID Login</title>
        <meta charset="utf-8">
    </head>
    <body>
        <h1>OpenID Login</h1>
        <?= Form::open(array('url' => 'openid', 'method' =>'POST')) ?>
        <?= Form::label('openid_identity', 'OpenID') ?>
        <?= Form::text('openid_identity', Input::old('openid_identity')) ?>
        <br>
        <?= Form::submit('Log In!') ?>
        <?= Form::close() ?>
    </body>
</html>
```

1.  在`routes.php`中，创建用于运行身份验证的路由：

```php
Route::any('openid/{auth?}', function($auth = NULL)
{
    if ($auth == 'auth') {
        try {
            Hybrid_Endpoint::process();
        } catch (Exception $e) {
            return Redirect::to('openid');
        }
        return;
    }

    try {
        $oauth = new Hybrid_Auth(app_path(). '/config/openid_auth.php');
        $provider = $oauth->authenticate('OpenID',array('openid_identifier' =>Input::get('openid_identity')));
        $profile = $provider->getUserProfile();
    }
    catch(Exception $e) {
        return $e->getMessage();
    }
    echo 'Welcome ' . $profile->firstName . ' ' . $profile->lastName . '<br>';
    echo 'Your email: ' . $profile->email . '<br>';
    dd($profile);
});
```

## 它是如何工作的...

我们首先创建一个 HybridAuth 库的配置文件，设置用户在身份验证后将被重定向的 URL，并启用 OpenID。

接下来，我们创建一个路由和一个视图，用户可以在其中输入他们想要使用的 OpenID URL。一个流行的 URL 是 Google 的 URL，所以我们建议使用 URL[`www.google.com/accounts/o8/id`](https://www.google.com/accounts/o8/id)，甚至可以自动将其设置为表单中的一个值。

提交表单后，我们应该被引导到 OpenID 网站的身份验证系统，然后重定向回我们的网站。在那里，我们可以显示用户的姓名和电子邮件 ID，并显示所有发送回来的信息。

## 还有更多...

有关 OpenID 提供的更多信息，请访问[`openid.net/developers/specs/`](http://openid.net/developers/specs/)。

# 使用 Facebook 凭据登录

如果我们不想担心存储用户的信息和凭据，我们可以使用 OAuth 来与另一个服务进行身份验证。其中一个最受欢迎的是使用 Facebook 进行登录。使用 Laravel 和 HybridAuth 库，我们可以轻松地实现与 Facebook 的 OAuth 身份验证。

## 准备工作

对于这个步骤，我们需要安装 HybridAuth 包，并按照*使用 HybridAuth 包设置 OAuth*的步骤进行设置。

## 如何做...

要完成这个步骤，请按照以下步骤进行：

1.  在[`developers.facebook.com`](https://developers.facebook.com)创建一个新的应用程序。

1.  获取 App ID 和 App Secret 密钥，在`app/config`目录中创建一个名为`fb_auth.php`的文件：

```php
<?php
return array(
    "base_url" => "http://path/to/our/app/fbauth/auth",
    "providers" => array (
        "Facebook" => array (
            "enabled"  => TRUE,
            "keys" => array ("id" => "APP_ID", "secret" =>"APP_SECRET"),
            "scope" => "email"
        )
    )
);
```

1.  在`routes.php`中创建一个用于我们的 Facebook 登录按钮的路由：

```php
Route::get('facebook', function()
{
    return "<a href='fbauth'>Login with Facebook</a>";
});
```

1.  创建一个路由来处理登录信息并显示它：

```php
Route::get('fbauth/{auth?}', function($auth = NULL)
{
    if ($auth == 'auth') {
        try {
            Hybrid_Endpoint::process();
        } catch (Exception $e) {
            return Redirect::to('fbauth');
        }
        return;
    }

    try {
        $oauth = new Hybrid_Auth(app_path(). '/config/fb_auth.php');
        $provider = $oauth->authenticate('Facebook');
        $profile = $provider->getUserProfile();
    }
    catch(Exception $e) {
        return $e->getMessage();
    }
    echo 'Welcome ' . $profile->firstName . ' '. $profile->lastName . '<br>';
    echo 'Your email: ' . $profile->email . '<br>';
    dd($profile);
});
```

## 它是如何工作的...

获取我们的 Facebook API 凭据后，我们需要创建一个包含这些凭据和回调 URL 的配置文件。我们还需要传递作用域，这是我们可能想要从用户那里获得的任何额外权限。在这种情况下，我们只是要获取他们的电子邮件 ID。

我们的 Facebook 登录页面是一个简单的链接到一个路由，我们在那里进行身份验证。然后用户将被带到 Facebook 进行登录和/或授权我们的网站，然后重定向回我们的`fbauth`路由。

在这一点上，我们只是显示返回的信息，但我们可能也想将信息保存到我们自己的数据库中。

## 还有更多...

如果我们在本地计算机上使用 MAMP 或 WAMP 进行测试，Facebook 允许我们使用 localhost 作为回调 URL。

# 使用 Twitter 凭据登录

如果我们不想担心存储用户的信息和凭据，我们可以使用 OAuth 来与另一个服务进行身份验证。一个常用的用于登录的服务是 Twitter。使用 Laravel 和 HybridAuth 库，我们可以轻松地实现与 Twitter 的 OAuth 身份验证。

## 准备工作

对于这个步骤，我们需要安装 HybridAuth 包，并按照*使用 HybridAuth 包设置 OAuth*的步骤进行设置。

## 如何做...

要完成这个步骤，请按照以下步骤进行：

1.  在[`dev.twitter.com/apps`](https://dev.twitter.com/apps)创建一个新的应用程序。

1.  获取 Consumer Key 和 Consumer Secret，并在`app/config`目录中创建一个名为`tw_auth.php`的文件：

```php
<?php
return array(
    "base_url"   => "http://path/to/our/app/twauth/auth",
    "providers"  => array (
        "Twitter" => array (
            "enabled" => true,
            "keys"    => array ("key" => "CONSUMER_KEY",
			     "secret" => "CONSUMER_SECRET")
        )
    )
);
```

1.  在`routes.php`中创建一个用于我们的 Twitter 登录按钮的路由：

```php
Route::get('twitter', function()
{
    return "<a href='twauth'>Login with Twitter</a>";
});
```

1.  创建一个路由来处理 Twitter 信息：

```php
Route::get('twauth/{auth?}', function($auth = NULL)
{
    if ($auth == 'auth') {
        try {
            Hybrid_Endpoint::process();
        } catch (Exception $e) {
            return Redirect::to('twauth');
        }
        return;
    }

    try {
        $oauth = new Hybrid_Auth(app_path(). '/config/tw_auth.php');
        $provider = $oauth->authenticate('Twitter');
        $profile = $provider->getUserProfile();
    }
    catch(Exception $e) {
        return $e->getMessage();
    }
    echo 'Welcome ' . $profile->displayName . '<br>';
    echo 'Your image: <img src="' . $profile->photoURL. '">';
    dd($profile);
});
```

## 它是如何工作的...

获取我们的 Twitter API 凭据后，我们需要创建一个包含这些凭据和回调 URL 的配置文件。

然后我们创建一个 Twitter 登录视图，这是一个简单的链接到一个路由，我们在那里进行身份验证。然后用户将被带到 Twitter 进行登录和/或授权我们的网站，然后重定向回我们的`twauth`路由。在这里，我们获取他们的显示名称和他们的 Twitter 图标。

在这一点上，我们只是显示返回的信息，但我们可能也想将信息保存到我们自己的数据库中。

## 还有更多...

如果我们在本地计算机上使用类似 MAMP 或 WAMP 的东西进行测试，Twitter 将不允许使用 localhost 作为回调 URL，但我们可以使用`127.0.0.1`代替。

# 使用 LinkedIn 进行登录

如果我们不想担心存储用户信息和凭据，我们可以使用 OAuth 来验证另一个服务。一个常用的用于登录的服务，特别是用于商业应用程序的服务，是 LinkedIn。使用 Laravel 和`HybridAuth`库，我们可以轻松地实现与 LinkedIn 的 OAuth 验证。

## 准备工作

对于这个步骤，我们需要安装并设置 HybridAuth 包，就像在*使用 HybridAuth 包设置 OAuth*步骤中一样。

## 如何做...

要完成这个步骤，请按照以下步骤进行操作：

1.  在[`www.linkedin.com/secure/developer`](https://www.linkedin.com/secure/developer)创建一个新的应用程序。

1.  获取 API 密钥和秘密密钥，在`app/config`目录中创建一个名为`li_auth.php`的文件：

```php
<?php
return array(
    "base_url"   => "http://path/to/our/app/liauth/auth",
    "providers"  => array (
        "LinkedIn" => array (
            "enabled" => true,
            "keys"    => array ("key" => "API_KEY","secret" => "SECRET_KEY")
        )
    )
);
```

1.  在`routes.php`中创建一个用于 LinkedIn 登录按钮的路由：

```php
Route::get('linkedin', function()
{
    return "<a href='liauth'>Login with LinkedIn</a>";
});
```

1.  创建一个处理 LinkedIn 信息的路由：

```php
Route::get('liauth/{auth?}', function($auth = NULL)
{
    if ($auth == 'auth') {
        try {
            Hybrid_Endpoint::process();
        } catch (Exception $e) {
            return Redirect::to('liauth');
        }
        return;
    }

    try {
        $oauth = new Hybrid_Auth(app_path(). '/config/li_auth.php');
        $provider = $oauth->authenticate('LinkedIn');
        $profile = $provider->getUserProfile();
    }
    catch(Exception $e) {
        return $e->getMessage();
    }
    echo 'Welcome ' . $profile->firstName . ' ' . $profile->lastName . '<br>';
    echo 'Your email: ' . $profile->email . '<br>';
    echo 'Your image: <img src="' . $profile->photoURL. '">';
    dd($profile);
});
```

## 它是如何工作的...

获得我们的 LinkedIn API 凭据后，我们需要创建一个包含这些凭据和回调 URL 的配置文件。

然后我们创建一个 LinkedIn 登录视图，其中包含一个简单的链接到一个路由，我们在这个路由中进行 LinkedIn 验证。用户将被带到 LinkedIn 网站进行登录和/或授权我们的网站，然后重定向回我们的`liauth`路由。在这里，我们获取他们的名字、姓氏、电子邮件 ID 和他们的头像。

在这一点上，我们只是显示返回的信息，但我们可能也想将信息保存到我们自己的数据库中。
