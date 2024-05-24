# Laravel 应用开发秘籍（三）

> 原文：[`zh.annas-archive.org/md5/d81d8d9e8c3a4da47310e721ff4953e5`](https://zh.annas-archive.org/md5/d81d8d9e8c3a4da47310e721ff4953e5)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：显示您的视图

在本章中，我们将涵盖：

+   创建和使用基本视图

+   将数据传递到视图

+   将视图加载到另一个视图/嵌套视图中

+   添加资产

+   使用 Blade 创建视图

+   使用 TWIG 模板

+   利用高级 Blade 用法

+   创建内容的本地化

+   在 Laravel 中创建菜单

+   与 Bootstrap 集成

+   使用命名视图和视图组件

# 介绍

在 Model-View-Controller 设置中，我们的**视图**保存所有的 HTML 和样式，以便我们可以显示我们的数据。在 Laravel 中，我们的视图可以使用常规的 PHP 文件，也可以使用 Laravel 的 Blade 模板。Laravel 还可以扩展到允许我们使用任何我们想要包含的模板引擎。

# 创建和使用基本视图

在这个步骤中，我们将看到一些基本的**视图**功能，以及我们如何在我们的应用程序中包含视图。

## 准备工作

对于这个步骤，我们需要一个标准的 Laravel 安装。

## 如何做...

按照以下步骤完成这个步骤：

1.  在`app/views`目录中，创建一个名为`myviews`的文件夹。

1.  在新的`myviews`目录中，创建两个文件：`home.php`和`second.php`。

1.  打开`home.php`并在 HTML 中添加以下代码：

```php
<!doctype html>
<html lang="en">
    <head>
        <meta charset="utf-8">
        <title>Home Page</title>
    </head>
    <body>
      <h1>Welcome to the Home page!</h1>
      <p>
        <a href="second">Go to Second Page</a>
      </p>
    </body>
</html>
```

1.  打开`second.php`文件并在 HTML 中添加以下代码：

```php
<!doctype html>
<html lang="en">
    <head>
        <meta charset="utf-8">
        <title>Second Page</title>
    </head>
    <body>
      <h1>Welcome to the Second Page</h1>
      <p>
        <a href="home">Go to Home Page</a>
      </p>
    </body>
</html>
```

1.  在我们的`app/routes.php`文件中，添加将返回这些视图的路由：

```php
Route::get('home', function()
{
  return View::make('myviews.home');
});
Route::get('second', function()
{
  return View::make('myviews.second');
});
```

1.  通过转到`http://{your-server}/home`（其中`your-server`是我们的 URL）并单击链接来测试视图。

## 它是如何工作的...

Laravel 中的所有视图都保存在`app/views`目录中。我们首先创建两个文件，用于保存我们的 HTML。在这个例子中，我们正在创建静态页面，每个视图都包含自己的完整 HTML 标记。

在我们的路由文件中，然后返回`View::make()`，并传入视图的名称。由于我们的视图在视图目录的子目录中，我们使用点表示法。

# 将数据传递到视图

在我们的 Web 应用程序中，我们通常需要显示来自数据库或其他数据存储的某种数据。在 Laravel 中，我们可以轻松地将这些数据传递到我们的视图中。

## 准备工作

对于这个步骤，我们需要完成*创建和使用基本视图*步骤。

## 如何做...

要完成这个步骤，请按照以下步骤进行：

1.  打开`routes.php`并将我们的主页和第二个路由替换为包含以下数据：

```php
Route::get('home', function()
{
  $page_title = 'My Home Page Title';
  return View::make('myviews.home')->with('title',$page_title);
});
Route::get('second', function()
{
  $view = View::make('myviews.second');
  $view->my_name = 'John Doe';
  $view->my_city = 'Austin';
  return $view;
});
```

1.  在`view/myviews`目录中，打开`home.php`并用以下代码替换代码：

```php
<!doctype html>
<html lang="en">
    <head>
        <meta charset="utf-8">
        <title>Home Page : <?= $title ?></title>
    </head>
    <body>
        <h1>Welcome to the Home page!</h1>
        <h2><?= $title ?></h2>
      <p>
        <a href="second">Go to Second Page</a>
      </p>
    </body>
</html>
```

1.  在`views/myviews`目录中，打开`second.php`文件，并用以下代码替换代码：

```php
<!doctype html>
<html lang="en">
    <head>
        <meta charset="utf-8">
        <title>Second Page</title>
    </head>
    <body>
      <h1>Welcome to the Second Page</h1>
        <p> You are <?= $my_name ?>, from <?= $my_city ?>
        </p>
      <p>
        <a href="home">Go to Home Page</a>
      </p>
    </body>
</html>
```

1.  通过转到`http://{your-server}/home`（其中`your-server`是我们的 URL）来测试视图，然后单击链接。

## 它是如何工作的...

如果我们想要将数据传递到我们的视图中，Laravel 提供了各种方法来实现这一点。我们首先通过将单个变量传递给视图来更新我们的第一个路由，通过将`with()`方法链接到`View::make()`。然后，在视图文件中，我们可以通过使用我们选择的任何名称来访问变量。

在我们的下一个路由中，我们将`View::make()`分配给一个变量，然后将值分配为对象的属性。然后我们可以在视图中将这些属性作为变量访问。要显示视图，我们只需返回对象变量。

## 还有更多...

向视图添加数据的另一种方法类似于我们第二个路由中的方法；但是我们使用数组而不是对象。因此，我们的代码看起来类似于以下内容：

```php
$view = View::make('myviews.second');
$view['my_name'] = 'John Doe';
$view['my_city'] = 'Austin';
return $view;
```

# 将视图加载到另一个视图/嵌套视图中

我们的网页往往会有类似的布局和 HTML 结构。为了帮助分离重复的 HTML，我们可以在 Laravel 中使用**嵌套视图**。

## 准备工作

对于这个步骤，我们需要完成*创建和使用基本视图*步骤。

## 如何做...

要完成这个步骤，请按照以下步骤进行：

1.  在`app/view`目录中，添加一个名为`common`的新文件夹。

1.  在`common`目录中，创建一个名为`header.php`的文件，并将以下代码添加到其中：

```php
<!doctype html>
<html lang="en">
    <head>
        <meta charset="utf-8">
        <title>My Website</title>
    </head>
    <body>
```

1.  在`common`目录中，创建一个名为`footer.php`的文件，并将以下代码添加到其中：

```php
<footer>&copy; 2013 MyCompany</footer>  
  </body>
</html>
```

1.  在`common`目录中，创建一个名为`userinfo.php`的文件，并添加以下代码：

```php
<p>You are <?= $my_name ?>, from <?= $my_city ?></p>
```

1.  在`routes.php`文件中，更新主页和第二个路由，包括以下嵌套视图：

```php
Route::get('home', function()
{
  return View::make('myviews.home')
      ->nest('header', 'common.header')
      ->nest('footer', 'common.footer');
});
Route::get('second', function()
{
  $view = View::make('myviews.second');
  $view->nest('header', 'common.header')->nest('footer','common.footer');
  $view->nest('userinfo', 'common.userinfo', array('my_name' => 'John Doe', 'my_city' => 'Austin'));
  return $view;
});
```

1.  在`views/myviews`目录中，打开`home.php`文件，并添加以下代码：

```php
<?= $header ?>
    <h1>Welcome to the Home page!</h1>
    <p>
      <a href="second">Go to Second Page</a>
    </p>
<?= $footer ?>
```

1.  在`views/myviews`目录中，打开`second.php`文件，并添加以下代码：

```php
<?= $header ?>
<h1>Welcome to the Second Page</h1>
  <?= $userinfo ?>
<p>
    <a href="home">Go to Home Page</a>
</p>
<?= $footer ?>
```

1.  通过转到`http://{your-server}/home`（其中`your-server`是我们的 URL），然后点击链接来测试视图。

## 它是如何工作的...

首先，我们需要将头部和页脚代码从我们的视图中分离出来。由于这些将在每个页面上都是相同的，我们在我们的`views`文件夹中创建一个子目录来保存我们的公共文件。第一个文件是我们的页眉，它将包含直到`<body>`标签的所有内容。第二个文件是我们的页脚，它将包含页面底部的 HTML。

我们的第三个文件是一个`userinfo`视图。如果我们有用户帐户和个人资料，我们经常希望在侧边栏或页眉中包含用户的数据。为了保持视图的一部分单独，我们创建了`userinfo`视图，并传递了一些数据给它。

对于我们的主页路由，我们将使用我们的主页视图，并嵌套头部和页脚。`nest()`方法中的第一个参数是我们将在主视图中使用的名称，第二个参数是视图的位置。在这个例子中，我们的视图在 common 子目录中，所以我们使用点表示法来引用它们。

在我们的主页视图中，为了显示嵌套视图，我们打印出了我们在路由中使用的变量名。

对于我们的第二个路由，我们嵌套了头部和页脚，但我们还想添加`userinfo`视图。为此，我们向`nest()`方法传入了第三个参数，这是我们要发送到视图的数据数组。然后，在我们的主视图中，当我们打印出`userinfo`视图时，它将自动包含这些变量。

## 另请参阅

+   *将数据传递到视图*的方法

# 添加资产

动态网站几乎需要使用 CSS 和 JavaScript。使用 Laravel 资产包提供了一种简单的方法来管理这些资产并将它们包含在我们的视图中。

## 准备工作

对于这个方法，我们需要使用*加载视图到另一个视图/嵌套视图*方法中创建的代码。

## 如何做到这一点...

要完成这个方法，按照以下步骤进行：

1.  打开`composer.json`文件，并将`asset`包添加到`require`部分，使其看起来类似于以下内容：

```php
"require": {
      "laravel/framework": "4.0.*",
      "teepluss/asset": "dev-master"
  },
```

1.  在命令行中，运行 composer update 来下载包，如下所示：

```php
**php composer.phar update**

```

1.  打开`app/config/app.php`文件，并在提供者数组的末尾添加`ServiceProvider`，如下所示：

```php
'Teepluss\Asset\AssetServiceProvider',
```

1.  在相同的文件中，在`aliases`数组中，添加包的别名，如下所示：

```php
'Asset' => 'Teepluss\Asset\Facades\Asset'
```

1.  在`app/filters.php`文件中，添加一个自定义过滤器来处理我们的资产，如下所示：

```php
Route::filter('assets', function()
{
  Asset::add('jqueryui', 'http://ajax.googleapis.com/ajax/libs/jqueryui/1.10.2/jquery-ui.min.js', 'jquery');
  Asset::add('jquery', 'http://ajax.googleapis.com/ajax/libs/jquery/1.10.2/jquery.min.js');
  Asset::add('bootstrap', 'http://netdna.bootstrapcdn.com/twitter-bootstrap/2.3.2/css/bootstrap-combined.min.css');
});

Update the home and second routes to use the filter
Route::get('home', array('before' => 'assets', function()
{
  return View::make('myviews.home')
      ->nest('header', 'common.header')
      ->nest('footer', 'common.footer');
}));
Route::get('second', array('before' => 'assets', function()
{
  $view = View::make('myviews.second');
  $view->nest('header', 'common.header')->nest('footer', 'common.footer');
  $view->nest('userinfo', 'common.userinfo', array('my_name' => 'John Doe', 'my_city' => 'Austin'));
  return $view;
}));
```

1.  在`views/common`目录中，打开`header.php`文件，并按照以下代码使用：

```php
<!doctype html>
<html lang="en">
    <head>
        <meta charset="utf-8">
        <title>My Website</title>
        <?= Asset::styles() ?>
    </head>
    <body>
```

1.  在`views/common`目录中，打开`footer.php`文件，并使用以下代码：

```php
<footer>&copy; 2013 MyCompany</footer> 
<?= Asset::scripts() ?>
  </body>
</html>
```

1.  通过转到`http://{your-server}/home`（其中`your-server`是我们的 URL），点击链接并查看页面源代码来测试视图，以查看包含的资产。

## 它是如何工作的...

`asset`包使向我们的 HTML 添加 CSS 和 JavaScript 文件变得非常容易。首先，我们需要在路由中“注册”每个资产。为了使事情变得更简单一些，我们将在一个在路由之前调用的过滤器中添加这些资产。这样，我们只需在一个地方编写代码，而且更改也会很容易。为了我们的目的，我们将使用来自 CDN 源的 jQuery、jQueryUI 和 bootstrap CSS。

`add()`方法的第一个参数是我们给资产的名称。第二个参数是资产的 URL；它可以是相对路径或完整的 URL。第三个可选参数是资产的依赖关系。在我们的例子中，jQueryUI 要求 jQuery 已经被加载，所以我们在第三个参数中传入了我们的 jQuery 资产的名称。

然后我们更新我们的路由以添加过滤器。如果我们在我们的过滤器中添加或删除任何资产，它将自动反映在我们的每个路由中。

由于我们使用了嵌套视图，我们只需要将资产添加到我们的页眉和页脚视图中。我们的 CSS 文件是通过`styles()`方法调用的，JavaScript 是通过`scripts()`方法调用的。Laravel 检查资产的文件扩展名，并自动将它们放在正确的位置。如果我们查看源代码，我们会注意到 Laravel 还确保在 jQueryUI 之前添加了 jQuery 脚本，因为我们将其设置为依赖项。

## 另请参阅

+   第五章中的*在路由上使用过滤器*食谱，*使用控制器和路由处理 URL 和 API*

# 使用 Blade 创建视图

PHP 有许多可用的模板库，Laravel 的 Blade 是其中之一。这个食谱将展示一个易于扩展的方法来使用 Blade 模板，并快速上手。

## 准备工作

对于这个食谱，我们需要一个标准的 Laravel 安装。

## 如何做...

要完成这个食谱，请按照以下步骤进行：

1.  在`routes.php`文件中，创建新的路由，如下所示：

```php
Route::get('blade-home', function()
{
  return View::make('blade.home');
});
Route::get('blade-second', function()
{
  return View::make('blade.second');
});
```

1.  在`views`目录中，创建一个名为`layout`的新文件夹。

1.  在`views/layout`目录中，创建一个名为`index.blade.php`的文件，并将以下代码添加到其中：

```php
<!doctype html>
<html lang="en">
    <head>
        <meta charset="utf-8">
        <title>My Site</title>
    </head>
    <body>
    <h1>
    @section('page_title')
      Welcome to 
    @show
    </h1>
    @yield('content')
    </body>
</html>
```

1.  在`views`目录中，创建一个名为`blade`的文件夹。

1.  在`views/blade`目录中，创建一个名为`home.blade.php`的文件，并将以下代码添加到其中：

```php
@extends('layout.index')

@section('page_title')
  @parent
    Our Blade Home
@endsection

@section('content')
  <p>
    Go to {{ HTML::link('blade-second', 'the Second Page.') }}
  </p>
@endsection
```

1.  在`views/blade`目录中，创建一个名为`second.blade.php`的文件，并将以下代码添加到其中：

```php
@extends('layout.index')

@section('page_title')
  @parent
    Our Second Blade Page
@endsection

@section('content')
  <p>
    Go to {{ HTML::link('blade-home', 'the Home Page.')}}
  </p>
@endsection
```

1.  通过转到`http://{your-server}/blade-home`（其中`your-server`是我们的 URL），然后单击链接，查看页面源代码，以查看包含的 Blade 布局。

## 它是如何工作的...

首先，我们创建两个简单的路由，它们将返回我们的 Blade 视图。通过使用点表示法，我们可以看到我们将把文件放在我们的`views`文件夹的`blade`子目录中。

我们的下一步是创建一个 Blade 布局视图。这将是我们页面的骨架，并将放在我们的`views`文件夹的布局子目录中，文件扩展名必须是`blade.php`。这个视图是简单的 HTML，有两个例外：`@section()`和`@yield()`区域。这些内容是我们的视图中将被替换或添加的内容。

在我们的路由视图中，我们首先声明要使用哪个 Blade 布局文件，对于我们的情况是`@extends('layout.index')`。然后我们可以添加和修改我们在布局中声明的内容部分。对于`page_title`部分，我们想要显示布局中的文本，但我们想要在末尾添加一些额外的文本。为了实现这一点，我们在内容区域的第一件事就是调用`@parent`，然后放入我们自己的内容。

在`@section('content')`中，布局中没有默认文本，所以一切都将被添加。使用 Blade，我们还可以使用`{{ }}`大括号来打印出我们需要的任何 PHP。在我们的情况下，我们使用 Laravel 的`HTML::link()`来显示一个链接。现在，当我们转到页面时，所有的内容区域都被放在了布局的正确位置。

# 使用 TWIG 模板

Laravel 的 Blade 模板可能很好，但有时我们需要另一个 PHP 模板库。一个流行的选择是 Twig。这个食谱将展示如何将 Twig 模板整合到我们的 Laravel 应用程序中。

## 准备工作

对于这个食谱，我们只需要一个标准的 Laravel 安装。

## 如何做…

按照以下步骤完成这个食谱：

1.  打开`composer.json`文件，并在`require`部分添加以下行：

```php
"rcrowe/twigbridge": "0.4.*"
```

1.  在命令行中，更新 composer 以安装包：

```php
**php composer.phar update**

```

1.  打开`app/config/app.php`文件，并在`providers`数组中添加 Twig ServiceProvider，如下所示：

```php
'TwigBridge\TwigServiceProvider'
```

1.  在命令行中，运行以下命令来创建我们的配置文件：

```php
**php artisan config:publish rcrowe/twigbridge**

```

1.  在`routes.php`中，创建一个路由如下：

```php
Route::get('twigview', function()
{
  $link = HTML::link('http://laravel.com', 'the Laravel site.');
  return View::make('twig')->with('link', $link);
**});**

```

1.  在`views`目录中，创建一个名为`twiglayout.twig`的文件，并将以下代码添加到其中：

```php
<!doctype html>
<html lang="en">
    <head>
        <meta charset="utf-8">
        <title>My Site</title>
    </head>
    <body>
    <h1>
        {% block page_title %}
            Welcome to
        {% endblock %}
    </h1>
    {% block content %}{% endblock %}
    </body>
</html>
```

1.  在`views`目录中，创建一个名为`twig.twig`的文件，并将以下代码添加到其中：

```php
{% extends "twiglayout.twig" %}

{% block page_title %}
	{{ parent() }}
	My Twig Page
{% endblock %}

{% block content %}
    <p>
		Go to {{ link|raw }}
	</p>
{% endblock %}
```

1.  通过转到`http://your-server/twigview`（其中`your-server`是我们的 URL）来测试视图，并查看页面源代码以查看包含的 twig 布局。

## 工作原理...

首先，我们将在我们的应用程序中安装`TwigBranch`包。该包还安装了`Twig`库。安装包后，我们使用`artisan`创建其配置文件，并添加其服务提供程序。

在我们的路由中，我们将使用与 Laravel 内置视图库相同的语法，并调用视图。我们还创建了一个简单的链接，将其保存到一个变量中，并将该变量传递到视图中。

接下来，我们创建我们的布局。所有 Twig 视图文件都必须具有`.twig`扩展名，因此我们的布局命名为`twiglayout.twig`。布局中包含一个标准的 HTML 框架，但我们添加了两个 Twig 内容块。`page_title`块具有一些默认内容，而`content`块为空。

对于我们路由的视图，我们首先通过扩展布局视图来开始。对于我们的`page_title`块，我们首先通过使用`{{ parent()}}`打印出默认内容，然后添加我们自己的内容。然后添加我们的内容块，并显示我们作为变量传递的链接。使用 Twig，我们不需要为我们的变量使用`$`，如果我们传入 HTML，Twig 会自动转义它。因此在我们的视图中，由于我们想要显示链接，我们需要确保添加原始参数。

现在，如果我们在浏览器中打开我们的页面，我们将看到所有内容都在正确的位置上。

# 利用高级的 Blade 用法

使用 Laravel 的 Blade 模板系统，我们可以访问一些强大的功能，使我们的开发速度更快。对于这个示例，我们将向我们的 blade 视图传递一些数据，并循环遍历它，以及一些条件语句。

## 准备工作

对于这个示例，我们将需要在*使用 Blade 创建视图*示例中创建的代码。

## 如何做...

按照以下步骤完成这个示例：

1.  打开`routes.php`文件，并按以下方式更新`blade-home`和`blade-second`路由：

```php
Route::get('blade-home', function()
{
  $movies = array(
    array('name' => 'Star Wars', 'year' => '1977', 'slug'=> 'star-wars'),
    array('name' => 'The Matrix', 'year' => '1999', 'slug' => 'matrix'),
    array('name' => 'Die Hard', 'year' => '1988', 'slug'=> 'die-hard'),
    array('name' => 'Clerks', 'year' => '1994', 'slug' => 'clerks')
  );
  return View::make('blade.home')->with('movies', $movies);
});
Route::get('blade-second/(:any)', function($slug)
{
  $movies = array(
    'star-wars' => array('name' => 'Star Wars', 'year' => '1977', 'genre' => 'Sci-Fi'),
    'matrix' => array('name' => 'The Matrix', 'year' => '1999', 'genre' => 'Sci-Fi'),
    'die-hard' => array('name' => 'Die Hard', 'year' => '1988', 'genre' => 'Action'),
    'clerks' => array('name' => 'Clerks', 'year' => '1994', 'genre' => 'Comedy')
  );
  return View::make('blade.second')->with('movie', $movies[$slug]);
});
```

1.  在`views/blade`目录中，使用以下代码更新`home.blade.php`文件：

```php
@extends('layout.index')

@section('page_title')
  @parent
    Our List of Movies
@endsection

@section('content')
  <ul>
    @foreach ($movies as $movie)
      <li>{{ HTML::link('blade-second/' . $movie['slug'],$movie['name']) }} ( {{ $movie['year'] }} )</li>
          @if ($movie['name'] == 'Die Hard')
                 <ul>
                   <li>Main character: John McClane</li>
                 </ul>
          @endif
    @endforeach
  </ul>
@endsection
```

1.  在`views/blade`目录中，使用以下代码更新`second.blade.php`文件：

```php
@extends('layout.index')

@section('page_title')
  @parent
     Our {{ $movie['name'] }} Page
@endsection

@section('content')
  @include('blade.info')
  <p>
    Go to {{ HTML::link('blade-home', 'the Home Page.') }}
  </p>
@endsection
```

1.  在`views/blade`目录中，创建一个名为`info.blade.php`的新文件，并将以下代码添加到其中：

```php
<h1>{{ $movie['name'] }}</h1>
<p>Year: {{ $movie['year'] }}</p>
<p>Genre: {{ $movie['genre'] }}</p>
```

1.  通过转到`http://{your-server}/blade-home`（其中`your-server`是我们的 URL）来测试视图，并单击链接以查看视图的工作。

## 工作原理...

对于这个示例，我们将向我们的 Blade 视图传递一些数据，循环遍历它，并添加一些条件语句。通常，我们会将其与数据库中的结果一起使用，但是为了我们的目的，我们将在我们的路由中创建一个简单的数据数组。

我们的第一个路由包含一个电影数组，其中包含它们的年份和我们可以用于 URL 的 slug。我们的第二个路由将创建一个包含 slug 作为键并接受 URL 中的 slug 的数组。然后，通过调用具有 slug 作为键的电影，我们将电影的详细信息传递到视图中。

在我们的第一个视图中，我们创建了一个`@foreach`循环，以遍历数组中的所有数据。我们还包含了一个简单的`@if`语句，用于检查特定的电影，然后打印出一些额外的信息。当我们循环遍历时，我们显示链接到第二个路由，并添加 slug。

第二个视图显示电影的名称，但是还通过在内容块中使用`@include()`包含另一个 Blade 视图。这样，所有数据也可以在包含的视图中使用；因此，对于我们的`info`视图，我们可以直接使用我们在路由中设置的相同变量。

# 创建内容的本地化

如果我们的应用程序将被不同国家或说不同语言的人使用，我们需要对内容进行本地化。Laravel 提供了一种简单的方法来实现这一点。

## 准备工作

对于这个教程，我们只需要一个标准的 Laravel 安装。

## 如何做...

对于这个教程，请按照以下步骤进行：

1.  在`app/lang`目录中，添加三个新目录（如果尚未存在）：`en`，`es`和`de`。

1.  在`en`目录中，创建一个名为`localized.php`的文件，并添加以下代码：

```php
<?php

return array(
  'greeting' => 'Good morning :name',
  'meetyou' => 'Nice to meet you!',
  'goodbye' => 'Goodbye, see you tomorrow.',
);
```

1.  在`es`目录中，创建一个名为`localized.php`的文件，并添加以下代码：

```php
<?php

return array(
  'greeting' => 'Buenos días :name',
  'meetyou' => 'Mucho gusto!',
  'goodbye' => 'Adiós, hasta mañana.',
);
```

1.  在`de`目录中，创建一个名为`localized.php`的文件，并添加以下代码：

```php
<?php

return array(
  'greeting' => 'Guten morgen :name',
  'meetyou' => 'Es freut mich!',
  'goodbye' => 'Tag. Bis bald.',
);
```

1.  在我们的`routes.php`文件中，创建四个路由如下：

```php
Route::get('choose', function()
{
  return View::make('language.choose');
});
Route::post('choose', function()
{
  Session::put('lang', Input::get('language'));
  return Redirect::to('localized');
});
Route::get('localized', function()
{
  $lang = Session::get('lang', function() { return 'en';});
  App::setLocale($lang);
  return View::make('language.localized');
});
Route::get('localized-german', function()
{
  App::setLocale('de');
  return View::make('language.localized-german');
});
```

1.  在`views`目录中，创建一个名为`language`的文件夹。

1.  在`views/language`中，创建名为`choose.php`的文件，并添加以下代码：

```php
<h2>Choose a Language:</h2>
<?= Form::open() ?>
<?= Form::select('language', array('en' => 'English', 'es' => 'Spanish')) ?>
<?= Form::submit() ?>
<?= Form::close() ?>
```

1.  在`views/language`目录中，创建一个名为`localized.php`的文件，并添加以下代码：

```php
<h2>
  <?= Lang::get('localized.greeting', array('name' => 'Lindsay Weir')) ?>
</h2>
<p>
  <?= Lang::get('localized.meetyou') ?>
</p>
<p>
  <?= Lang::get('localized.goodbye') ?>
</p>
<p>
  <?= HTML::link('localized-german', 'Page 2') ?>
</p>
```

1.  在`views/language`目录中，创建一个名为`localized-german.php`的文件，并添加以下代码：

```php
<h2>
  <?= Lang::get('localized.greeting', array('name' =>'Lindsay Weir')) ?>
</h2>
<p>
  <?= Lang::get('localized.meetyou') ?>
</p>
<p>
  <?= Lang::get('localized.goodbye') ?>
</p>
```

1.  在浏览器中，转到`http://{your-server}/choose`（其中`your-server`是我们的 URL），提交表单，并测试本地化。

## 它是如何工作的...

对于这个教程，我们首先在`app/lang`目录中设置我们的语言目录。我们将使用`en`作为英语文件，`es`作为西班牙语文件，`de`作为德语文件。在每个目录中，我们创建一个使用完全相同名称的文件，并添加一个数组，使用完全相同的键。

我们的第一个路由将是一个语言选择器页面。在此页面上，我们可以选择英语或西班牙语。当我们提交时，它将`POST`到路由，创建一个新会话，添加选择，并重定向到页面以显示所选语言的文本。

我们的本地化路由获取会话并将选择传递给`App::setLocale()`。如果没有设置会话，我们还有一个默认值为英语。

在我们的本地化视图中，我们使用`Lang::get()`打印出文本。在我们的语言文件的第一行中，我们还包含了`:name`占位符，因此当我们调用语言文件时，我们可以传递一个包含占位符名称的数组作为键。

我们的最后一个路由显示了我们如何在路由中静态设置语言默认值。

# 在 Laravel 中创建菜单

菜单是大多数网站的常见组成部分。在这个教程中，我们将使用 Laravel 的嵌套视图创建菜单，并根据我们所在的页面更改菜单项的默认“状态”。

## 准备工作

对于这个菜单，我们需要一个标准的 Laravel 安装。

## 如何做...

我们需要按照以下步骤完成这个教程：

1.  在`routes.php`文件中，创建三个路由如下：

```php
Route::get('menu-one', function()
{
  return View::make('menu-layout')
      ->nest('menu', 'menu-menu')
      ->nest('content', 'menu-one');
});
Route::get('menu-two', function()
{
  return View::make('menu-layout')
      ->nest('menu', 'menu-menu')
      ->nest('content', 'menu-two');
});
Route::get('menu-three', function()
{
  return View::make('menu-layout')
      ->nest('menu', 'menu-menu')
      ->nest('content', 'menu-three');
});
```

1.  在视图目录中，创建一个名为`menu-layout.php`的文件，并添加以下代码：

```php
<!doctype html>
<html lang="en">
    <head>
        <meta charset="utf-8">
        <title>Menu Example</title>
        <style>
            #container {
              width: 1024px; 
              margin: 0 auto; 
              border-left: 2px solid #ddd;
              border-right: 2px solid #ddd;
              padding: 20px;
            }
            #menu { padding: 0 }
            #menu li {
               display: inline-block;
               border: 1px solid #ddf;
               border-radius: 6px;
               margin-right: 12px;
               padding: 4px 12px;
            }
            #menu li a {
               text-decoration: none;
               color: #069;
            }
            #menu li a:hover { text-decoration: underline}
            #menu li.active { background: #069 }
            #menu li.active a { color: #fff }
        </style>
    </head>
    <body>
      <div id="container">
          <?= $menu ?>
          <?= $content ?>
      </div>
    </body>
</html>
```

1.  在`views`目录中，创建一个名为`menu-menu.php`的文件，并添加以下代码：

```php
<ul id="menu">
  <li class="<?= Request::segment(1) == 'menu-one' ?'active' : '' ?>">
    <?= HTML::link('menu-one', 'Page One') ?>
  </li>
  <li class="<?= Request::segment(1) == 'menu-two' ? 'active' : '' ?>">
      <?= HTML::link('menu-two', 'Page Two') ?>
  </li>
  <li class="<?= Request::segment(1) == 'menu-three' ?'active' : '' ?>">
      <?= HTML::link('menu-three', 'Page Three') ?>
  </li>
</ul>
```

1.  在`views`目录中，创建三个视图文件，分别命名为`menu-one.php`，`menu-two.php`和`menu-three.php`。

1.  对于`menu-one.php`，使用以下代码：

```php
<h2>Page One</h2>
<p>
  Lorem ipsum dolor sit amet.
</p>
```

1.  对于`menu-two.php`，使用以下代码：

```php
<h2>Page Two</h2>
<p>
  Suspendisse eu porta turpis
</p>
```

1.  对于`menu-three.php`，使用以下代码：

```php
<h2>Page Three</h2>
<p>
  Nullam varius ultrices varius.
</p>
```

1.  在浏览器中，转到`http://{your-server}/menu-one`（其中`your-server`是我们的 URL），并通过菜单链接进行点击。

## 它是如何工作的...

我们首先创建三个路由来保存我们的三个页面。每个路由将使用单个布局视图，并嵌入一个特定于路由的菜单视图和内容视图。

我们的布局视图是一个基本的 HTML 骨架，带有一些页面 CSS。由于我们想要突出显示当前页面的菜单项，一个类选择器被命名为`active`，并将添加到我们的菜单列表项中。

接下来，我们创建我们的菜单视图。我们使用无序列表，其中包含到每个页面的链接。为了在当前页面项目中添加`active`类，我们使用 Laravel 的`Request::segment(1)`来获取我们所在的路由。如果它与列表项相同，我们添加`active`类，否则留空。然后我们使用 Laravel 的`HTML::link()`来添加链接到我们的页面。

其他三个视图只是非常简单的内容，有一个标题和几个单词。现在，当我们在浏览器中查看页面时，我们会看到我们所在页面的菜单项被突出显示，而其他页面没有。如果我们单击链接，那个项目将被突出显示，其他项目将不会被突出显示。

# 与 Bootstrap 集成

Bootstrap CSS 框架最近变得非常流行。这个示例将展示我们如何在 Laravel 中使用这个框架。

## 准备工作

对于这个示例，我们需要一个标准的 Laravel 安装。我们还需要安装`assets`包，就像*添加资产*示例中演示的那样。可选地，我们可以下载 Bootstrap 文件并将其保存在本地。

## 如何做...

要完成这个示例，请按照以下步骤进行：

1.  在`routes.php`文件中，创建一个新的路由，如下所示：

```php
Route::any('boot', function()
{
  Asset::add('jquery', 'http://ajax.googleapis.com/ajax/libs/jquery/1.10.2/jquery.min.js');
  Asset::add('bootstrap-js', 'http://netdna.bootstrapcdn.com/twitter-bootstrap/2.3.2/js/bootstrap.min.js', 'jquery');
  Asset::add('bootstrap-css', 'http://netdna.bootstrapcdn.com/twitter-bootstrap/2.3.2/css/bootstrap-combined.min.css');
  $superheroes = array('Batman', 'Superman', 'Wolverine','Deadpool', 'Iron Man');
  return View::make('boot')->with('superheroes',$superheroes);
});
```

1.  在`views`目录中，创建一个名为`boot.php`的文件，并向其中添加以下代码：

```php
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>My Bootstrap Page</title>
    <?= Asset::styles() ?>
  </head>
  <body>
    <div class="container">
      <h1>Using Bootstrap with Laravel</h1>
      <ul class="nav nav-tabs">
        <li class="active"><a href="#welcome" data-toggle="tab">Welcome</a></li>
        <li><a href="#about" data-toggle="tab">About Us</a></li>
        <li><a href="#contact" data-toggle="tab">Contact</a></li>
      </ul>
        <div class="tab-content">
          <div class="tab-pane active" id="welcome">
            <h4>Welcome to our site</h4>
            <p>Here's a list of Superheroes:</p>
            <ul>
              <?php foreach($superheroes as $hero): ?>
                <li class="badge badge-info"><?= $hero ?></li>
              <?php endforeach; ?>
            </ul>
        </div>
          <div class="tab-pane" id="about">
            <h4>About Us</h4>
              <p>Cras at dui eros. Ut imperdiet pellentesque mi faucibus dapibus.Phasellus vitae lacus at massa viverra condimentum quis quis augue. Etiam pharetra erat id sem pretium egestas. Suspendisse mollis, dolor a sagittis hendrerit, urna velit commodo dui, id adipiscing magna magna ac ligula. Nunc in ligula nunc.</p>
          </div>
          <div class="tab-pane" id="contact">
            <h3>Contact Form</h3>
              <?= Form::open('boot', 'POST') ?>
                <?= Form::label('name', 'Your Name') ?>
                <?= Form::text('name') ?>
                <?= Form::label('email', 'Your Email') ?>
                <?= Form::text('email') ?>
                <br>
                <?= Form::button('Send', array('class' =>'btn btn-primary')) ?>

                <?= Form::close() ?>
          </div>
       </div>
    </div>
    <?= Asset::scripts() ?>
  </body>
</html>
```

1.  在浏览器中，转到`http://your-server/boot`（其中`your-server`是我们的 URL），并单击选项卡。

## 它是如何工作的...

对于这个示例，我们将创建一个单一的路由，并使用 Bootstrap 选项卡切换内容。为了使我们的路由响应任何请求，我们使用`Route::any()`并传入我们的闭包。要添加 CSS 和 JavaScript，我们可以使用一个过滤器，就像*添加资产*示例中的过滤器一样；然而，对于一个单一的路由，我们将把它包含在闭包中。因此，我们不必下载它们，我们将只使用 Bootstrap 和 jQuery 的 CDN 版本。

接下来，在我们的路由中，我们需要一些数据。这将是绑定数据库的好地方，但是出于我们的目的，我们将使用一个简单的数组，其中包含一些超级英雄的名字。然后将该数组传递到我们的视图中。

我们从一个 HTML 骨架开始查看，并在头部包含我们的样式，在关闭`</body>`标签之前包含脚本。在页面顶部，我们使用 Bootstrap 的导航样式和数据属性来创建我们的选项卡链接。然后在我们的正文中，我们使用三个不同的选项卡窗格，其 ID 对应于我们菜单中的`<a href>`标签。

当我们查看页面时，我们会看到第一个窗格显示，其他所有内容都被隐藏。通过单击其他选项卡，我们可以切换显示哪个选项卡窗格。

## 另请参阅

+   *添加资产*示例

# 使用命名视图和视图组件

这个示例将展示如何使用 Laravel 的命名视图和视图组件来简化一些我们路由代码。

## 准备工作

对于这个示例，我们将使用*在 Laravel 中创建菜单*示例中创建的代码。我们还需要在*添加资产*示例中安装`assets`包。

## 如何做...

要完成这个示例，请按照以下步骤进行：

1.  在`routes.php`文件中，添加一个名为`view`的文件，并向其中添加以下代码：

```php
View::name('menu-layout', 'layout');
```

1.  在`routes.php`中，添加一个视图组件，如下所示：

```php
View::composer('menu-layout', function($view)
{
  Asset::add('bootstrap-css', 'http://netdna.bootstrapcdn.com/twitter-bootstrap/2.2.2/css/bootstrap-combined.min.css');
    $view->nest('menu', 'menu-menu');
    $view->with('page_title', 'View Composer Title');
});
```

1.  在`routes.php`中，更新菜单路由如下：

```php
Route::get('menu-one', function()
{
  return View::of('layout')->nest('content', 'menu-one');
});
Route::get('menu-two', function()
{
  return View::of('layout')->nest('content', 'menu-two');
});
Route::get('menu-three', function()
{
  return View::of('layout')->nest('content', 'menu-three');
});
```

1.  在`views`目录中，使用以下代码更新`menu-layout.php`文件：

```php
<!doctype html>
<html lang="en">
    <head>
        <meta charset="utf-8">
        <title><?= $page_title ?></title>
        <?= Asset::styles() ?>
        <style>
          #container {
            width: 1024px; 
            margin: 0 auto; 
            border-left: 2px solid #ddd;
            border-right: 2px solid #ddd;
            padding: 20px;
          }
          #menu { padding: 0 }
          #menu li {
            display: inline-block;
            border: 1px solid #ddf;
            border-radius: 6px;
            margin-right: 12px;
            padding: 4px 12px;
          }
          #menu li a {
            text-decoration: none;
            color: #069;
          }
          #menu li a:hover { text-decoration: underline }
          #menu li.active { background: #069 }
          #menu li.active a { color: #fff }
        </style>
    </head>
    <body>
      <div id="container">
        <?= $menu ?>
        <?= $content ?>
      </div>
    </body>
</html>
```

1.  在浏览器中，转到`http://{your-server}/menu-one`（其中`your-server`是我们的 URL），并单击菜单链接。

## 它是如何工作的...

我们通过为我们的视图创建一个名称来开始这个示例。如果我们的视图文件名或目录结构很长或复杂，这将允许我们在我们的路由中创建一个简单的别名。这也将允许我们在将来更改我们的视图文件名；此外，如果我们在多个地方使用它，我们只需要更改一行。

接下来，我们创建一个视图组件。当您创建视图时，组件中的任何代码都将自动调用。在我们的示例中，每次创建视图时，我们都包含三个内容：包含 Bootstrap CSS 文件的资产，一个嵌套视图和一个传递给视图的变量。

对于我们的三个路由，我们将使用我们创建的名称，调用`View::of('layout')`，并将其嵌套在我们的内容中，而不是`View::make('menu-layout')`。由于我们的布局视图有一个 composer，它将自动嵌套我们的菜单，添加 CSS，并传递页面标题。

## 另请参阅

+   *在 Laravel 中创建菜单*示例


# 第七章：创建和使用 Composer 包

在本章中，我们将涵盖：

+   下载和安装包

+   使用生成器包设置应用程序

+   在 Laravel 中创建 Composer 包

+   将您的 Composer 包添加到 Packagist

+   将非 Packagist 包添加到 Composer

+   创建自定义 artisan 命令

# 介绍

Laravel 中的一个很棒的功能是我们可以轻松地使用包含其他人使用 bundles 制作的类库。在 Laravel 网站上，已经有许多有用的 bundles，其中一些自动化某些任务，而其他一些则可以轻松地与第三方 API 集成。

PHP 世界的最新补充是 Composer，它允许我们使用不特定于 Laravel 的库（或包）。

在本章中，我们将开始使用 bundles，并创建自己的 bundle 供其他人下载。我们还将看到如何将 Composer 整合到我们的 Laravel 安装中，以打开我们可以在应用程序中使用的各种 PHP 库。

# 下载和安装包

Laravel 最好的功能之一是它的模块化。大部分框架都是使用经过充分测试并在其他项目中广泛使用的库或**包**构建的。通过使用 Composer 进行依赖管理，我们可以轻松地包含其他包并将它们无缝地整合到我们的 Laravel 应用程序中。

对于这个配方，我们将在我们的应用程序中安装两个流行的包：Jeffrey Way 的 Laravel 4 生成器和`Imagine`图像处理包。

## 准备工作

对于这个配方，我们需要使用 Composer 进行 Laravel 的标准安装。

## 如何操作...

对于这个配方，我们将按照以下步骤进行：

1.  转到[`packagist.org/`](https://packagist.org/)。

1.  在搜索框中，搜索`way generator`，如下截图所示：![如何操作...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrv-app-dev-cb/img/2827OS_07_01.jpg)

1.  点击**way/generators**的链接：![如何操作...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrv-app-dev-cb/img/2827OS_07_02.jpg)

1.  在[`packagist.org/packages/way/generators`](https://packagist.org/packages/way/generators)查看详细信息，并注意获取包版本的**require**行。对于我们的目的，我们将使用**"way/generators": "1.0.*"**。

1.  在我们应用程序的根目录中，打开`composer.json`文件，并在`require`部分中添加包，使其看起来像这样：

```php
"require": {
       "laravel/framework": "4.0.*",
       "way/generators": "1.0.*"
},
```

1.  返回到[`packagist.org`](http://packagist.org)，并按照以下截图中显示的方式搜索`imagine`：![如何操作...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrv-app-dev-cb/img/2827OS_07_03.jpg)

1.  点击**imagine/imagine**的链接，并复制**dev-master**的 require 代码：![如何操作...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrv-app-dev-cb/img/2827OS_07_04.jpg)

1.  返回到我们的`composer.json`文件，并更新`require`部分以包括`imagine`包。现在它应该类似于以下代码：

```php
"require": {
      "laravel/framework": "4.0.*",
      "way/generators": "1.0.*",
      "imagine/imagine": "dev-master"
},
```

1.  打开命令行，在我们应用程序的根目录中，运行 Composer update 如下：

```php
php composer.phar update
```

1.  最后，我们将添加生成器服务提供者，因此打开`app/config/app.php`文件，并在 providers 数组中添加以下行：

```php
'Way\Generators\GeneratorsServiceProvider'
```

## 它是如何工作的...

要获取我们的包，我们首先转到[packagist.org](http://packagist.org)，并搜索我们想要的包。我们也可以点击**浏览包**链接。它将显示最近的包列表以及最受欢迎的包。点击我们想要的包后，我们将被带到详细页面，其中列出了各种链接，包括包的存储库和主页。我们还可以点击包的维护者链接，查看他们发布的其他包。

在下面，我们将看到包的各种版本。如果我们打开该版本的详细页面，我们将找到我们需要在`composer.json`文件中使用的代码。我们可以选择使用严格的版本号，为版本添加通配符，或者使用`dev-master`，这将安装包的主分支上更新的任何内容。对于`Generators`包，我们只会使用 1.0 版本，但允许对该版本进行任何次要修复。对于`imagine`包，我们将使用`dev-master`，因此无论版本号如何，都将下载其存储库的主分支中的内容。

然后我们在 Composer 上运行更新，它将自动下载并安装我们选择的所有包。最后，要在我们的应用程序中使用`Generators`，我们需要在应用程序的配置文件中注册服务提供者。

# 使用 Generators 包设置应用程序

`Generators`是一个流行的 Laravel 包，可以自动化相当多的文件创建。除了`controllers`和`models`之外，它还可以通过命令行界面生成`views`、`migrations`、`seeds`等等。

## 准备工作

对于这个示例，我们将使用由*Jeffrey Way*维护的 Laravel 4 Generators 包，该包在*下载和安装包*示例中安装。我们还需要一个正确配置的 MySQL 数据库。

## 操作步骤…

按照这个示例的步骤：

1.  在我们应用程序的根目录中打开命令行，并使用生成器按如下方式为我们的城市创建一个脚手架：

```php
**php artisan generate:scaffold cities --fields="city:string"**

```

1.  在命令行中，按如下方式为我们的超级英雄创建一个脚手架：

```php
**php artisan generate:scaffold superheroes --fields="name:string, city_id:integer:unsigned"**

```

1.  在我们的项目中，查看`app/database/seeds`目录，并找到名为`CitiesTableSeeder.php`的文件。打开它，并按如下方式向`$cities`数组中添加一些数据：

```php
<?php

class CitiesTableSeeder extends Seeder {

  public function run()
  {
    DB::table('cities')->delete();

    $cities = array(
         array(
                'id'         => 1,
                'city'       => 'New York',
                'created_at' => date('Y-m-d g:i:s',time())
              ),
         array(
                'id'         => 2,
                'city'       => 'Metropolis',
                'created_at' => date('Y-m-d g:i:s',time())
              ),
         array(
                'id'         => 3,
                'city'       => 'Gotham',
                'created_at' => date('Y-m-d g:i:s',time())
              )
    );

    DB::table('cities')->insert($cities);
  }
}
```

1.  在`app/database/seeds`目录中，打开`SuperheroesTableSeeder.php`并向其中添加一些数据：

```php
<?php

class SuperheroesTableSeeder extends Seeder {

  public function run()
  {
    DB::table('superheroes')->delete();

      $superheroes = array(
           array(
                 'name'       => 'Spiderman',
                 'city_id'    => 1,
                 'created_at' => date('Y-m-d g:i:s', time())
                 ),
           array(
                 'name'       => 'Superman',
                 'city_id'    => 2,
                 'created_at' => date('Y-m-d g:i:s', time())
                 ),
           array(
                 'name'       => 'Batman',
                 'city_id'    => 3,
                 'created_at' => date('Y-m-d g:i:s', time())
                 ),
           array(
                 'name'       => 'The Thing',
                 'city_id'    => 1,
                 'created_at' => date('Y-m-d g:i:s', time())
                 )
      );

    DB::table('superheroes')->insert($superheroes);
  }
}
```

1.  在命令行中，运行迁移，然后按如下方式对数据库进行种子处理：

```php
php artisan migrate
**php artisan db:seed**

```

1.  打开一个网页浏览器，转到`http://{your-server}/cities`。我们将看到我们的数据如下截图所示：![操作步骤…](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrv-app-dev-cb/img/2827OS_07_05.jpg)

1.  现在，导航到`http://{your-server}/superheroes`，我们将看到我们的数据如下截图所示：![操作步骤…](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrv-app-dev-cb/img/2827OS_07_06.jpg)

## 工作原理…

我们首先运行城市和超级英雄表的脚手架生成器。使用`--fields`标签，我们可以确定我们想要在表中的列，并设置数据类型等选项。对于我们的城市表，我们只需要城市的名称。对于我们的超级英雄表，我们希望得到英雄的名称以及他们居住的城市的 ID。

当我们运行生成器时，许多文件将自动为我们创建。例如，对于城市，我们将在我们的 models 中得到`City.php`，在 controllers 中得到`CitiesController.php`，在我们的 views 中得到一个`cities`目录，其中包括索引、显示、创建和编辑视图。然后我们得到一个名为`Create_cities_table.php`的迁移，一个`CitiesTableSeeder.php`种子文件，以及我们的`tests`目录中的`CitiesTest.php`。我们还将有我们的`DatabaseSeeder.php`文件和我们的`routes.php`文件更新以包含我们需要的一切。

为了向我们的表中添加一些数据，我们打开了`CitiesTableSeeder.php`文件，并更新了我们的`$cities`数组，其中包含我们想要添加的每一行的数组。我们对`SuperheroesTableSeeder.php`文件也做了同样的事情。最后，我们运行迁移和种子处理，我们的数据库将被创建，并且所有数据将被插入。

`Generators`包已经创建了我们需要操纵数据的视图和控制器，因此我们可以轻松地转到我们的浏览器并查看所有数据。我们还可以创建新行，更新现有行和删除行。

# 在 Laravel 中创建一个 Composer 包

使用 Laravel 的工作台，我们可以轻松创建一个可以由 Composer 使用和安装的包。我们还可以添加功能，使该包无缝集成到我们的 Laravel 应用程序中。在这个示例中，我们将创建一个简单的包，用于显示指定用户的 Vimeo 视频列表。

## 准备工作

对于这个示例，我们需要一个标准的 Laravel 安装。

## 如何做…

要完成这个示例，请按照以下步骤进行：

1.  在`app/config`目录中，打开`workbench.php`文件并使用以下信息进行更新：

```php
<?php

return array(

    'name' => 'Terry Matula',

    'email' => 'terrymatula@gmail.com',

);
```

1.  在命令行中，使用 artisan 来设置我们的包：

```php
**php artisan workbench matula/vimeolist --resources**

```

1.  找到将保存我们源文件的目录，并创建一个名为`Vimeolist.php`的文件。在这个示例中，我们将文件放在`workbench/matula/vimeolist/src/Matula/Vimeolist/`中：

```php
<?php namespace Matula\Vimeolist;

class Vimeolist
{
  private $base_url = 'http://vimeo.com/api/v2/{username}/videos.json';
  private $username;

  public function __construct($username = 'userscape') {
      $this->setUser($username);
      return $this;
  }

  /**
   * Set the username for our list
   *
   * @return void
   */
  public function setUser($username = NULL) {
      $this->username = is_null($username) ? $this->username : urlencode($username);
       return $this;
  }

  /**
   * Set up the url and get the contents
   *
   * @return json
   */
  private function getFeed() {
      $url  = str_replace('{username}', $this->username,$this->base_url);
      $feed = file_get_contents($url);
      return $feed;
  }

  /**
   * Turn the feed into an object
   *
   * @return object
   */
  public function parseFeed() {
       $json = $this->getFeed();
       $object = json_decode($json);
       return $object;
  }

  /**
   * Get the list and format the return
   *
   * @return array
   */
  public function getList() {
       $list = array();
       $posts = $this->parseFeed();
       foreach ($posts as $post) {
             $list[$post->id]['title']    = $post->title;
             $list[$post->id]['url']    = $post->url;
             $list[$post->id]['description'] = $post->description;
             $list[$post->id]['thumbnail'] = $post->thumbnail_small;
       }
       return $list;
  }
}
```

1.  在刚刚创建的文件所在的目录中，打开名为`VimeolistServiceProvider.php`的文件并更新它：

```php
<?php namespace Matula\Vimeolist;

use Illuminate\Support\ServiceProvider;

class VimeolistServiceProvider extends ServiceProvider {

  /**
   * Indicates if loading of the provider is deferred.
   *
   * @var bool
   */
  protected $defer = false;

  /**
   * Bootstrap the application events.
   *
   * @return void
   */
  public function boot()
  {
        $this->package('matula/vimeolist');
  }

  /**
   * Register the service provider.
   *
   * @return void
   */
  public function register()
  {
      $this->app['vimeolist'] = $this->app->share(function($app)
            {
             return new Vimeolist;
            });
  }

  /**
   * Get the services provided by the provider.
   *
   * @return array
   */
  public function provides()
  {
    return array('vimeolist');
  }
}
```

1.  在`app/config`目录中的`app.php`文件中，在`providers`数组中，添加我们的服务提供程序如下：

```php
'Matula\Vimeolist\VimeolistServiceProvider',
```

1.  在命令行中，运行以下命令：

```php
**php composer.phar dump-autoload**

```

1.  在`routes.php`中，添加一个显示数据的路由如下：

```php
Route::get('vimeo/{username?}', function($username = null) use ($app)
{
  $vimeo = $app['vimeolist'];
  if ($username) {
      $vimeo->setUser($username);
  }
  dd($vimeo->getList());
});
```

## 它是如何工作的…

我们的第一步是更新我们工作台的配置文件，以保存我们的姓名和电子邮件地址。然后，这将用于我们在 Laravel 中创建的任何其他包。

接下来，我们运行 artisan 命令来创建我们包所需的文件。通过使用`--resources`标志，它还将生成其他文件和目录，可以专门用于 Laravel。完成后，我们的工作台目录中将有一个包含所有包文件的新文件夹。在深入目录之后，我们将进入一个包含我们服务提供程序文件的目录，在这个目录中，我们将添加我们的类文件。

这个示例类将简单地从 Vimeo API 中获取用户的视频列表。我们有一些方法可以允许我们设置用户名，获取 API 端点的内容，将 JSON 转换为 PHP 对象，然后创建并返回一个格式化的数组。作为最佳实践，我们还应该确保我们的代码经过测试，并且我们可以将这些文件放在`test`目录中。

为了更好地与 Laravel 集成，我们需要更新服务提供程序。我们首先更新`register`方法并设置要传递给 Laravel 的`app`变量的名称，然后我们更新`provides`方法以返回包名称。接下来，我们需要更新我们的应用程序配置文件以实际注册服务提供程序。然后，一旦我们在 Composer 中运行`dump-autoload`命令，我们的新包将可供使用。

最后，我们创建一个与包交互的路由。我们将有一个可选参数，即用户名。我们还需要确保我们的路由中有`$app`变量。然后，当我们调用`$app['vimeolist']`时，服务提供程序将自动实例化我们的类，并允许我们访问 Vimeo 列表。对于我们的目的，我们只使用 Laravel 的`dd()`辅助函数来显示数据，但我们也可以将其传递给视图并使其看起来更好。

## 还有更多…

Laravel 还可以选择为我们的包创建一个门面，因此我们可以使用类似`$vimeo = Vimeolist::setUser()`的方式进行调用。还有许多其他可以在[`laravel.com/docs/packages`](http://laravel.com/docs/packages)文档中找到的包选项。

# 将您的 Composer 包添加到 Packagist

为了更容易地分发我们的包，我们应该将它们提交到网站[packagist.org](http://packagist.org)。在这个示例中，我们将看到如何在 GitHub 上设置我们的包并将其添加到 Packagist。

## 准备工作

对于这个示例，我们需要完成*Laravel 中创建 Composer 包*示例，并且我们还需要一个活跃的 GitHub 帐户。

## 如何做…

要完成这个示例，请按照以下步骤进行：

1.  在命令行中，移动到`workbench/matula/vimeolist`目录并设置我们的`git`仓库如下：

```php
git init
git add -A
git commit –m 'First Package commit'
```

1.  在[`github.com/new`](https://github.com/new)创建一个新的 GitHub 存储库，并将其命名为`vimeolist`。

1.  将我们的包添加到 GitHub：

```php
git remote add origin git@github.com:{username}/vimeolist.git
**git push –u origin master**

```

1.  前往[`packagist.org/login/`](https://packagist.org/login/)并使用您的 GitHub 帐户登录。

1.  单击以下截图中显示的绿色**提交包**按钮：![如何做...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrv-app-dev-cb/img/2827OS_07_07.jpg)

1.  在**存储库 URL**文本字段中，添加 GitHub 的只读 Git URL，如下截图所示：![如何做...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrv-app-dev-cb/img/2827OS_07_08.jpg)

1.  单击**检查**，如果一切正常，单击**提交**。

## 它是如何工作的...

我们首先在包的主目录中创建一个`git`存储库。然后我们在 GitHub 中为我们的文件创建一个存储库，将该远程存储库添加到我们的本地存储库，然后将我们的本地存储库推送到 GitHub。

在 Packagist 网站上，我们使用我们的 GitHub 帐户登录，并允许[packagist.org](http://packagist.org)访问。然后，我们使用来自我们存储库的 GitHub URL 在[`packagist.org/packages/submit`](https://packagist.org/packages/submit)提交我们的包。单击**检查**后，Packagist 将查看代码并将其格式化以供 Composer 使用。如果有任何错误，我们将收到提示需要做什么来修复它们。

如果一切正常，并且我们单击**提交**，我们的包将被列在 Packagist 网站上。

## 另请参阅

+   *在 Laravel 中创建一个 Composer 包*教程

# 向 Composer 添加一个非 Packagist 包

向我们的`composer.json`文件添加一行，并让 Composer 自动下载和安装一个包非常好，但它要求该包在[packagist.org](http://packagist.org)上可用。在这个教程中，我们将看到如何安装在 Packagist 上不可用的包。

## 准备工作

对于这个教程，我们将需要一个标准的 Laravel 安装。

## 如何做...

要完成这个教程，请按照以下步骤操作：

1.  在 GitHub 上，我们需要找到一个我们想要使用的包。在这个例子中，我们将使用在[`github.com/wesleytodd/Universal-Forms-PHP`](https://github.com/wesleytodd/Universal-Forms-PHP)找到的`UniversalForms`包。

1.  打开我们的主`composer.json`文件，并按以下方式更新`require`部分：

```php
"require": {
       "laravel/framework": "4.0.*",
       "wesleytodd/universal-forms": "dev-master"
  },
```

1.  在`composer.json`中，在`require`部分下，添加我们要使用的存储库：

```php
"repositories": [
     {
         "type": "vcs",
         "url": "https://github.com/wesleytodd/Universal-Forms-PHP"
     }
  ],
```

1.  在命令行中，按以下方式更新 Composer：

```php
**php composer.phar update**

```

1.  打开`app/config/app.php`文件，并使用以下行更新`providers`数组：

```php
'Wesleytodd\UniversalForms\Drivers\Laravel\UniversalFormsServiceProvider',
```

1.  在`routes.php`中，实例化该类，并在我们的路由上使用它，如下所示：

```php
$form_json = '{
       "action" : "uform",
       "method" : "POST",
       "fields" : [
             {
               "name" : "name",
               "type" : "text",
               "label" : "Name",
               "rules" : ["required"]
             },
             {
               "name" : "email",
               "type" : "email",
               "label" : "Email",
               "value" : "myemail@example.com",
               "rules" : ["required", "email"]
              },
              {
                "name" : "message",
                "type" : "textarea",
                "label" : "Message",
                "rules" : ["required", "length[30,0]"]
              }
       ]
}';

$uform = new Wesleytodd\UniversalForms\Drivers\Laravel\Form($form_json);

Route::get('uform', function() use ($uform)
{
  return $uform->render();
});

Route::post('uform', function() use ($uform)
{
  // validate
  $valid = $uform->valid(Input::all());
  if ($valid) {
       // Could also save to database
       dd(Input::all());
  } else {
       // Could redirect back to form
       dd($uform->getErrors());
  }
});
```

## 它是如何工作的...

我们的第一步是像其他 Composer 包一样添加所需包的行。但是，由于这个包在[packagist.org](http://packagist.org)上不可用，如果我们尝试更新 Composer，它将抛出错误。为了使其工作，我们需要添加一个 Composer 要使用的存储库。Composer 有许多不同的选项可用于使用其他存储库，它们可以在[`getcomposer.org/doc/05-repositories.md#vcs`](http://getcomposer.org/doc/05-repositories.md#vcs)找到。

接下来，我们更新 Composer，它将为我们安装包。由于这个包带有一个 Laravel 服务提供者，我们然后更新我们的配置文件以注册它。

现在我们可以在我们的应用程序中使用该包。对于我们的目的，我们将在路由之外实例化该类，并将其传递到路由的闭包中。然后我们可以像平常一样使用该库。这个特定的包将接受一个 JSON 字符串或文件，并自动为我们创建表单输出。

# 创建自定义 artisan 命令

Laravel 的 artisan 命令行工具使许多任务变得容易完成。如果我们想要创建自己的任务并使用 artisan 来运行它们，这个过程非常简单。在这个教程中，我们将看到如何创建一个 artisan 任务，自动在我们的`views`目录中创建一个 HTML5 骨架。

## 准备工作

对于这个教程，我们将需要一个标准的 Laravel 安装。

## 如何做...

要完成这个教程，请按照以下步骤操作：

1.  在命令行中，运行`artisan`命令来创建我们需要的文件：

```php
**php artisan command:make SkeletonCommand**

```

1.  在`app/commands`目录中，打开`SkeletonCommand.php`文件并按以下方式更新代码：

```php
<?php

use Illuminate\Console\Command;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Input\InputArgument;
use Illuminate\Filesystem\Filesystem as File;

class SkeletonCommand extends Command {

  /**
   * The console command name.
   *
   * @var string
   */
  protected $name = 'skeleton:make';

  /**
   * The console command description.
   *
   * @var string
   */
  protected $description = 'Creates an HTML5 skeleton view.';

   /**
     * File system instance
     *
     * @var File
     */
    protected $file;

  /**
   * Create a new command instance.
   *
   * @return void
   */
  public function __construct()
  {
    parent::__construct();
    $this->file = new File();
  }

  /**
   * Execute the console command.
   *
   * @return void
   */
  public function fire()
  {
        $view = $this->argument('view');
        $file_name = 'app/views/' . $view;
        $ext = ($this->option('blade')) ? '.blade.php' :'.php';
            $template = '<!DOCTYPE html>
            <html>
            <head>
               <meta charset=utf-8 />
               <title></title>
               <link rel="stylesheet" type="text/css"media="screen" href="css/style.css" />
                <script type="text/javascript" src="http://ajax.googleapis.com/ajax/libs/jquery/2.0.3/jquery.min.js">
                </script>
                  <!--[if IE]>
                        <script src="http://html5shiv.googlecode.com/svn/trunk/html5.js"></script>
                  <![endif]-->
            </head>
            <body>
            </body>
            </html>';

            if (!$this->file->exists($file_name)) {
               $this->info('HTML5 skeleton created!');
               return $this->file->put($file_name . $ext,$template) !== false;
        } else {
             $this->info('HTML5 skeleton created!');
             return $this->file->put($file_name . '-' .time() . $ext, $template) !== false;
        }

    $this->error('There was a problem creating yourHTML5 skeleton');
       return false;
  }

  /**
   * Get the console command arguments.
   *
   * @return array
   */
  protected function getArguments()
  {
      return array(
           array('view', InputArgument::REQUIRED, 'The name of the view.'),
      );
  }

  /**
   * Get the console command options.
   *
   * @return array
   */
  protected function getOptions()
  {
     return array(
     array('blade', null, InputOption::VALUE_OPTIONAL, 'Use Blade templating?', false),
     );
  }

} 
```

1.  在`app/start`目录中，打开`artisan.php`文件并添加以下行：

```php
Artisan::add(new SkeletonCommand);
```

1.  在命令行中，测试新命令：

```php
**php artisan skeleton:make MyNewView --blade=true**

```

## 它是如何工作的...

我们的第一步是使用 artisan 的`command:make`函数，并传入我们想要使用的命令的名称。运行后，我们会在`app/commands`目录中找到一个与我们选择的名称相同的新文件。

在我们的`SkeletonCommand`文件中，我们首先添加一个名称。这将是 artisan 要响应的命令。接下来，我们设置一个描述，当我们列出所有 artisan 命令时将显示。

对于这个命令，我们将访问文件系统，因此我们需要确保添加 Laravel 的`Filesystem`类，并在我们的构造函数中实例化它。然后，我们来到`fire()`方法。这是我们想要运行的所有代码的地方。为了我们的目的，我们使用一个单一参数来确定我们的`view`文件名将是什么，如果`--blade`参数设置为`true`，我们将把它变成一个`blade`文件。然后，我们创建一个包含我们的 HTML5 骨架的字符串，尽管我们也可以将其制作成一个单独的文件并引入文本。

然后使用模板创建新文件作为我们的 HTML，并在控制台中显示成功消息。


# 第八章：使用 Ajax 和 jQuery

在本章中，我们将涵盖：

+   从另一个页面获取数据

+   设置控制器以返回 JSON 数据

+   创建一个 Ajax 搜索功能

+   使用 Ajax 创建和验证用户

+   根据复选框选择过滤数据

+   创建一个 Ajax 通讯快讯注册框

+   使用 Laravel 和 jQuery 发送电子邮件

+   使用 jQuery 和 Laravel 创建可排序的表

# 介绍

许多现代 Web 应用程序依赖于 JavaScript 来添加动态用户交互。使用 jQuery 库和 Laravel 的内置功能，我们可以在我们自己的应用程序中轻松创建这些交互。

我们将从其他页面异步接收数据，然后发送可以保存在数据库中的数据。

# 从另一个页面获取数据

在我们的应用程序中，可能会有时候我们需要从另一个页面访问一些 HTML。使用 Laravel 和 jQuery，我们可以轻松实现这一点。

## 准备工作

对于这个步骤，我们只需要一个标准的 Laravel 安装。

## 如何做...

要完成这个步骤，请按照给定的步骤进行操作：

1.  打开`routes.php`文件：

```php
Route::get('getting-data', function()
{
  return View::make('getting-data');
});

Route::get('tab1', function()
{
  if (Request::ajax()) {
  return View::make('tab1');
}
  return Response::error('404');
});

Route::get('tab2', function()
{
  if (Request::ajax()) {
  return View::make('tab2');
}
  return Response::error('404');
});
```

1.  在`views`目录中，创建一个名为`tab1.php`的文件：

```php
<h1>CHAPTER 1 - Down the Rabbit-Hole</h1>
<p>
  Alice was beginning to get very tired of sitting by her sister on the bank,and of having nothing to do: once or twice she had peeped into the book her sister was reading, but it had no pictures or conversations in it, 'and what is the use of a book,' thought Alice 'without pictures or conversation?'
</p>
<p>
  So she was considering in her own mind (as well as she could, for the hot day made her feel very sleepy and stupid), whether the pleasure of making a daisy-chain would be worth the trouble of getting up and picking the daisies, when suddenly a White Rabbit with pink eyes ran close by her.
</p>
```

1.  在`views`目录中，创建一个名为`tab2.php`的文件：

```php
<h1>Chapter 1</h1>
<p>"TOM!"</p>
<p>No answer.</p>
<p>"TOM!"</p>
<p>No answer.</p>
<p>"What's gone with that boy,  I wonder? You TOM!"</p>
<p>No answer.</p>
<p>
  The old lady pulled her spectacles down and looked over them about the room; 
  then she put them up and looked out under them. She seldom or never looked 
  through them for so small a thing as a boy; they were her state pair, 
  the pride of her heart, and were built for "style," not service—she could 
  have seen through a pair of stove-lids just as well. She looked perplexed 
  for a moment, and then said, not fiercely, but still loud enough for the 
  furniture to hear:
</p>
<p>"Well, I lay if I get hold of you I'll—"</p>
<p>
  She did not finish, for by this time she was bending down and punching 
  under the bed with the broom, and so she needed breath to punctuate 
  the punches with. She resurrected nothing but the cat.
</p>
```

1.  在`views`目录中，创建一个名为`getting-data.php`的文件：

```php
<!DOCTYPE html>
<html>
<head>
  <meta charset=utf-8 />
  <title>Getting Data</title>
  <script type="text/javascript" src="//ajax.googleapis.com/ajax/libs/jquery/1.9.0/jquery.min.js"></script>
</head>
<body>
<ul>
  <li><a href="#" id="tab1" class="tabs">Alice In Wonderland</a></li>
  <li><a href="#" id="tab2" class="tabs">Tom Sawyer</a></li>
</ul>
<h1 id="title"></h1>
<div id="container"></div>
<script>
  $(function() {
  $(".tabs").on("click", function(e) {e.preventDefault();
  var tab = $(this).attr("id");
  var title = $(this).html();
  $("#container").html("loading…");
  $.get(tab, function(data) {
  $("#title").html(title);
  $("#container").html(data);
});
});
});
</script>
</body>
</html>
```

1.  在`http://{yourserver}/getting-data`页面查看页面，并单击链接以加载内容。

## 它是如何工作的...

我们首先设置我们的路由。我们的第一个路由将显示链接，当我们点击它们时，内容将加载到页面中。我们的下两个路由将保存要在主页面上显示的实际内容。为了确保这些页面不能直接访问，我们使用`Request::ajax()`方法来确保只接受 Ajax 请求。如果有人试图直接访问页面，它将把他们发送到错误页面。

我们的两个视图文件将包含一些书籍摘录。由于这将加载到另一个页面中，我们不需要完整的 HTML。然而，我们的主页面是一个完整的 HTML 页面。我们首先通过使用来自 Google 的**内容传送网络**（**CDN**）加载 jQuery。然后，我们有一个我们想要使用的书籍列表。为了使事情变得更容易一些，链接的 ID 将对应于我们创建的路由。

当有人点击链接时，脚本将使用 ID 并从具有相同名称的路由获取内容。结果将加载到我们的`container` div 中。

# 设置控制器以返回 JSON 数据

当我们使用 JavaScript 访问数据时，最简单的方法之一是使用 JSON 格式的数据。在 Laravel 中，我们可以从我们的控制器中返回 JSON，以供我们在另一个页面上的 JavaScript 使用。

## 准备工作

对于这个步骤，我们需要一个标准的 Laravel 安装。

## 如何做...

对于这个步骤，请按照给定的步骤进行操作：

1.  在`controllers`目录中，创建一个名为`BooksController.php`的文件：

```php
<?php

  class BooksController extends BaseController {

  public function getIndex()
{
  return View::make('books.index');
}

  public function getBooks()
{
  $books = array('Alice in Wonderland','Tom Sawyer','Gulliver\'s Travels','Dracula','Leaves of Grass');
  return Response::json($books);
}
}
```

1.  在`routes.php`中，注册书籍控制器

```php
Route::controller('books', 'BooksController');
```

1.  在`views`目录中，创建一个名为`books`的文件夹，在该文件夹中创建一个名为`index.php`的文件：

```php
<!DOCTYPE html>
<html>
<head>
  <meta charset=utf-8 />
  <title>Show Books</title>
  <script type="text/javascript" src="//ajax.googleapis.com/ajax/libs/jquery/1.9.0/jquery.min.js"></script>
</head>
<body>
<a href="#" id="book-button">Load Books</a>
<div id="book-list"></div>
<script>
$(function() {
$('#book-button').on('click', function(e) {e.preventDefault();
$('#book-list').html('loading...');
$.get('books/books', function(data) {var book_list = '';
$.each(data, function(){book_list += this + '<br>';
})
$("#book-list").html(book_list);
$('#book-button').hide();
});
});
});
</script>
</body>
</html>
```

## 它是如何工作的...

我们首先为我们的书籍列表创建一个 RESTful 控制器，它扩展了我们的`BaseController`类。我们的控制器有两个方法：一个用于显示列表，一个用于返回格式化的列表。我们的`getBooks()`方法使用数组作为我们的数据源，并且我们使用 Laravel 的`Response::json()`方法来自动为我们执行正确的格式化。

在我们的主页面上，我们在 JavaScript 中对页面进行`get`请求，接收 JSON，并循环遍历结果。当我们循环时，我们将书籍添加到 JavaScript 变量中，然后将列表添加到我们的`book-list` div 中。

## 还有更多...

我们的列表可以来自任何数据源。我们可以添加数据库功能，甚至调用 API。当我们使用 Laravel 的 JSON 响应时，该值将以正确的格式和正确的标头进行格式化。

# 创建一个 Ajax 搜索功能

如果我们想在应用程序中搜索信息，异步执行搜索可能会很有用。这样，用户就不必转到新页面并刷新所有资产。使用 Laravel 和 JavaScript，我们可以以非常简单的方式执行这个搜索。

## 准备工作

对于这个教程，我们需要一个正常安装的 Laravel。

## 如何操作...

要完成这个教程，请按照以下步骤进行：

1.  在`controllers`目录中，创建一个名为`SearchController.php`的文件：

```php
<?php

class SearchController extends BaseController {

  public function getIndex()
{
  return View::make('search.index');
}

  public function postSearch()
{
  $return = array();
  $term = Input::get('term');

  $books = array(array('name' => 'Alice in Wonderland', 'author' => 'Lewis Carroll'),array('name' => 'Tom Sawyer', 'author' => 'Mark Twain'),array('name' => 'Gulliver\'s Travels', 'author' =>'Jonathan Swift'),array('name' => 'The Art of War', 'author' => 'Sunzi'),array('name' => 'Dracula', 'author' => 'Bram Stoker'),array('name' => 'War and Peace', 'author' =>'LeoTolstoy'),);

foreach ($books as $book) {
if (stripos($book['name'], $term) !== FALSE) $return[] =$book;
}

return Response::json($return);
}
}
```

1.  在`routes.php`文件中，注册控制器：

```php
  Route::controller('search', 'SearchController');
```

1.  在`views`目录中，创建一个名为`search`的文件夹，在该文件夹中，创建一个名为`index.php`的文件：

```php
<!DOCTYPE html>
<html>
<head>
<meta charset=utf-8 />
<title>AJAX Search</title>
<script type="text/javascript" src="//ajax.googleapis.com/ajax/libs/jquery/1.9.0/jquery.min.js"></script>
</head>
<body>
<h1>Search</h1>
<form id="search-form">
<input name="search" id="term"> <input type="submit">
</form>
<div id="results"></div>
<script>
  $(function() {
  $("#search-form").on("submit", function(e) {e.preventDefault();
  var search_term = $("#term").val();
  var display_results = $("#results");
  display_results.html("loading...");
  var results = '';
  $.post("search/search", {term: search_term}, function(data) {if (data.length == 0) {results = 'No Results';
  } else {
  $.each(data, function() {
  results += this.name + ' by ' + this.author + '<br>';
});
}
display_results.html(results);
});
})
});
</script>
</body>
</html>
```

## 它是如何工作的...

我们首先创建一个包含两种方法的 RESTful 控制器：一个用于我们的主页面，一个用于处理搜索。在我们的主页面上，我们有一个单一的`text`字段和一个`submit`按钮。当表单提交时，我们的 JavaScript 将把表单发布到我们的搜索页面。如果有结果，它将循环遍历它们，并在我们的`results` div 中显示它们。

对于我们的`postSearch()`方法，我们使用一个数组作为我们的数据源。当进行搜索时，我们然后循环遍历数组，看看字符串是否与我们的标题匹配。如果是，该值将被添加到一个数组中，并将该数组作为 JSON 返回。

# 使用 Ajax 创建和验证用户

当用户来到我们的应用程序时，我们可能希望他们在不需要导航到另一个页面的情况下注册或登录。使用 Laravel 内的 Ajax，我们可以提交用户的表单并异步运行验证。

## 准备工作

对于这个教程，我们需要一个正常安装的 Laravel，以及一个正确配置的 MySQL 数据库。我们还需要向数据库添加一个用户表，可以使用以下代码完成：

```php
CREATE TABLE users (id int(10) unsigned NOT NULL AUTO_INCREMENT,email varchar(255) DEFAULT NULL,password char(60) DEFAULT NULL,PRIMARY KEY (id)) ENGINE=InnoDB DEFAULT CHARSET=utf8;
```

## 如何操作...

要完成这个教程，请按照给定的步骤进行：

1.  在`controllers`目录中，创建一个名为`UsersController.php`的文件：

```php
<?php
class UsersController extends BaseController {
  public function getIndex()
  {
  return View::make('users.index');
  }

  public function postRegister()
  {
  $rules = array('email' => 'required|email','password' => 'required|min:6');

  $validation = Validator::make(Input::all(), $rules);

  if ($validation->fails())
  {
  return Response::json($validation->errors()->toArray());
}
else
{
DB::table('users')->insert(array('email' => Input::get('email'),'password' => Hash::make(Input::get('password'))));
return Response::json(array('Registration is complete!'));
}
}
}
```

1.  在`routes.php`中注册控制器：

```php
 **Route::controller('users', 'UsersController');**

```

1.  在`views`目录中，创建一个名为`users`的文件夹，在该文件夹中，创建一个名为`index.php`的文件：

```php
<!doctype html>
<html lang="en">
  <head>
  <meta charset="utf-8">
  <title>User Register</title>
  <script type="text/javascript"src="http://ajax.googleapis.com/ajax/libs/jquery/1.9.0/jquery.min.js"></script>
  </head>
  <body>
  <form id="register">
  <label for="email">Your email:</label> 
  <input type="email" name="email" id="email"><br>
  <label for="password">Your password:</label> 
  <input type="password" name="password" id="password"><br>
  <input type="submit">
  </form>
  <div id="results"></div>
  <script>
  $(function(){
  $("#register").on("submit", function(e) {e.preventDefault();
  var results = '';
  $.post('users/register', {email: $("#email").val(), password:$("#password").val()}, function(data) {
  $.each(data, function(){results += this + '<br>';
});
  $("#results").html(results);
});
});
});
</script>
  </body>
</html>
```

## 它是如何工作的...

要开始这个教程，我们创建一个主页面，用于容纳用户注册表单。当表单提交时，它将发布到我们的`postRegister()`方法，并将任何结果返回到`results` div。

`postRegister()`方法首先设置我们验证的规则。在这种情况下，我们希望确保两个字段都有值，电子邮件必须有效，并且密码必须至少为 6 个字符。如果验证失败，我们将错误作为 JSON 编码的字符串发送回来，我们的主页面将显示错误。如果一切正常，我们将一切保存到数据库并返回成功消息。

## 还有更多...

如果我们不希望任何其他页面向我们的方法发布数据，我们可以添加一个`Request::ajax()`条件。这意味着只有 Ajax 调用才会被我们的方法处理。

# 根据复选框选择过滤数据

在向用户显示数据时，允许他们过滤数据可能会很方便。因此，我们不必让用户每次都点击提交并重新加载页面，我们可以使用 Ajax 来进行所有的过滤。对于这个教程，我们将制作一个书籍列表，并允许用户根据流派进行过滤。

## 准备工作

对于这个教程，我们需要一个标准的 Laravel 安装，配置为与数据库一起工作。我们需要通过运行以下 SQL 语句来设置一个要使用的表：

```php
DROP TABLE IF EXISTS books;
CREATE TABLE books (id int(10) unsigned NOT NULL AUTO_INCREMENT,name varchar(255) DEFAULT NULL,author varchar(255) DEFAULT NULL,genre varchar(255) DEFAULT NULL,PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

  INSERT INTO books VALUES ('1', 'Alice in Wonderland', 'Lewis Carroll', 'fantasy');
  INSERT INTO books VALUES ('2', 'Tom Sawyer', 'Mark Twain', 'comedy');
  INSERT INTO books VALUES ('3', 'Gulliver\'s Travels', 'Jonathan Swift', 'fantasy');
  INSERT INTO books VALUES ('4', 'The Art of War', 'Sunzi', 'philosophy');
  INSERT INTO books VALUES ('5', 'Dracula', 'Bram Stoker', 'horror');
  INSERT INTO books VALUES ('6', 'War and Peace', 'Leo Tolstoy', 'drama');
  INSERT INTO books VALUES ('7', 'Frankenstein', 'Mary Shelley', 'horror');
  INSERT INTO books VALUES ('8', 'The Importance of Being Earnest', 'Oscar Wilde', 'comedy');
  INSERT INTO books VALUES ('9', 'Peter Pan', 'J. M. Barrie', 'fantasy');
```

## 如何操作...

要完成这个教程，请按照以下步骤进行：

1.  在`controllers`目录中，创建一个名为`BooksController.php`的新文件：

```php
<?php
class BooksController extends BaseController {
  public function getIndex()
{
  return View::make('books.index');
}

  public function postBooks()
{
  if (!$genre = Input::get('genre')) {
  $books = Book::all();
  } else {
  $books = Book::whereIn('genre', $genre)->get();
}
return $books;
}
}
```

1.  在`routes.php`文件中注册`books`控制器：

```php
 **Route::controller('books', 'BooksController');**

```

1.  在`views`目录中，创建一个名为`books`的新文件夹，在该文件夹中，创建一个名为`index.php`的文件：

```php
<!doctype html>
<html lang="en">
  <head>
  <meta charset="utf-8">
  <title>Books filter</title>
  <scriptsrc="//ajax.googleapis.com/ajax/libs/jquery/1.10.2/jquery.min.js"></script>
  </head>
  <body>
  <form id="filter">
  Comedy: <input type="checkbox" name="genre[]" value="comedy"><br>
  Drama: <input type="checkbox" name="genre[]" value="drama"><br>
  Fantasy: <input type="checkbox" name="genre[]" value="fantasy"><br>
  Horror: <input type="checkbox" name="genre[]" value="horror"><br>
  Philosophy: <input type="checkbox" name="genre[]" value="philosophy"><br>
  </form>
  <hr>
  <h3>Results</h3>
  <div id="books"></div>
  <script>
  $(function(){
  $("input[type=checkbox]").on('click', function() {var books = '';
  $("#books").html('loading...');
  $.post('books/books', $("#filter").serialize(), function(data){$.each(data, function(){books += this.name + ' by ' + this.author + ' (' + this.genre + ')<br>';
});
$("#books").html(books);
});
});
});
</script>
</body>
</html>
```

1.  在`models`目录中，创建一个名为`Book.php`的文件：

```php
<?php
class Book extends Eloquent {
}
```

1.  在浏览器中，转到`http://{my-server}/books`，并点击一些复选框以查看结果。

## 它是如何工作的...

在我们的数据库设置好之后，我们从我们的主列表页面开始。这个页面有许多复选框，每个值对应于我们书籍表中的一个流派。当一个框被选中时，表单会异步提交到我们的`postBooks()`方法。我们使用这些结果，循环遍历它们，并在我们的`books`div 中显示它们。

我们的`postBooks()`方法首先确保实际提交了一个流派。如果没有，这意味着一切都未被选中，它将返回所有的书籍。如果有选中的内容，我们从数据库中获取与选中值匹配的所有内容。由于 Laravel 以 JSON 格式提供了原始返回的数据，我们然后返回结果，在我们的索引中，结果被正确显示。

# 创建一个 Ajax 新闻订阅框

让用户加入我们的电子邮件列表的一种方法是让他们通过我们的网站进行注册。在这个教程中，我们将使用 MailChimp 的 API 和一个模态窗口来显示一个注册表单，并通过 Ajax 调用发送它。

## 准备工作

对于这个教程，我们需要一个标准的 Laravel 安装。我们还将使用 MailChimp API 进行新闻订阅；可以在[www.mailchimp.com](http://www.mailchimp.com)创建免费帐户和 API 密钥。

## 如何做...

要完成这个教程，请按照给定的步骤进行操作：

1.  打开`composer.json`文件，并更新`require`部分以类似以下代码：

```php
  "require": {
  "laravel/framework": "4.0.*",
  "rezzza/mailchimp": "dev-master"
}
```

1.  在命令行窗口中，位于 artisan 文件的位置，使用以下命令更新 Composer：

```php
 **php composer.phar update**

```

1.  在`app/config`目录中，创建一个名为`mailchimp.php`的文件：

```php
<?php

return array('key' => '12345abcde-us1','list' => '123456789'
);
```

1.  在`views`目录中，创建一个名为`signup.php`的文件：

```php
<!doctype html>
<html lang="en">
  <head>
  <meta charset="utf-8">
  <title>Newsletter Signup</title>
  <link href="//netdna.bootstrapcdn.com/twitter-bootstrap/2.2.2/css/bootstrap-combined.min.css" rel="stylesheet">
  <script src="//ajax.googleapis.com/ajax/libs/jquery/1.9.0/jquery.min.js"></script>
  <script src="//netdna.bootstrapcdn.com/twitter-bootstrap/2.2.2/js/bootstrap.min.js"></script>
  </head>
  <body>
  <p>
  <a href="#signupModal" role="button" class="btn btn-info" data-toggle="modal">Newsletter Signup</a>
  </p>
  <div id="results"></div>
  <div id="signupModal" class="modal hide fade">
  <div class="modal-header">
  <button type="button" class="close" data-dismiss="modal" aria-hidden="true">&times;</button>
  <h3>Sign-up for our awesome newsletter!</h3>
  </div>
  <div class="modal-body">
  <p>
  <form id="newsletter_form">
  <label>Your First Name</label>
  <input name="fname"><br>
  <label>Last Name</label>
  <input name="lname"><br>
  <label>Email</label>
  <input name="email">
  </form>
  </p>
  </div>
  <div class="modal-footer">
  <a href="#" class="btn close" data-dismiss="modal">Close</a>
  <a href="#" class="btn btn-primary" id="newsletter_submit">Signup</a>
  </div>
  </div>
  <script>
  $(function(){
  $("#newsletter_submit").on('click', function(e){e.preventDefault();
  $("#results").html("loading...");
  $.post('signup-submit', $("#newsletter_form").serialize(), function(data){
  $('#signupModal').modal('hide');
  $("#results").html(data);
});
});
});
  </script>
  </body>
</html>
```

1.  在`routes.php`文件中，添加我们需要的路由，使用以下代码：

```php
Route::get('signup', function()
{
  return View::make('signup');
});

Route::post('signup-submit', function()
{
  $mc = new MCAPI(Config::get('mailchimp.key'));

  $response = $mc->listSubscribe('{list_id}',Input::get('email'),array('FNAME' => Input::get('fname'),'LNAME' => Input::get('lname')
)
);

if ($mc->errorCode){
return 'There was an error: ' . $mc->errorMessage;
} else {
return 'You have been subscribed!';
}
});
```

## 它是如何工作的...

我们首先通过使用 MailChimp SDK 的 composer 版本将 MailChimp 包安装到我们的应用程序中。然后我们需要创建一个配置文件来保存我们的 API 密钥和我们想要使用的列表 ID。

我们的注册页面将利用 jQuery 和 Bootstrap 进行处理和显示。由于我们只想在用户想要注册时显示表单，我们有一个单独的按钮，当点击时，将显示一个带有我们表单的模态窗口。表单将包括名字、姓氏和电子邮件地址。

当注册表单被提交时，我们序列化数据并将其发送到我们的`signup-submit`路由。一旦我们得到一个响应，我们隐藏模态窗口并在我们的页面上显示结果。

在我们的`signup-submit`路由中，我们尝试使用输入的信息订阅用户。如果我们得到一个响应，我们检查响应是否包含错误。如果有错误，我们将其显示给用户，如果没有，我们显示成功消息。

## 还有更多...

我们的`signup-submit`路由没有对表单输入进行任何验证。要包括验证，请查看*使用 Ajax 创建和验证用户*教程中的示例。

## 另请参阅

+   *使用 Ajax 创建和验证用户*教程

# 使用 Laravel 和 jQuery 发送电子邮件

当创建联系表单时，我们可以选择让用户异步发送表单。使用 Laravel 和 jQuery，我们可以在不需要用户转到不同页面的情况下提交表单。

## 准备工作

对于这个教程，我们需要一个标准的 Laravel 安装和正确配置我们的邮件客户端。我们可以在`app/config/mail.php`文件中更新我们的邮件配置。

## 如何做...

要完成这个教程，请按照给定的步骤进行操作：

1.  在`views`目录中，创建一个名为`emailform.php`的文件，如下所示：

```php
  <!doctype html>
  <html lang="en">
  <head>
  <meta charset="utf-8">
  <title></title>
  <script src="//ajax.googleapis.com/ajax/libs/jquery/1.10.2/jquery.min.js"></script>
  </head>
  <body>
  <div id="container">
  <div id="error"></div>
  <form id="email-form">
  <label>To: </label>
  <input name="to" type="email"><br>
  <label>From: </label>
  <input name="from" type="email"><br>
  <label>Subject: </label>
  <input name="subject"><br>
  <label>Message:</label><br>
  <textarea name="message"></textarea><br>
  <input type="submit" value="Send">
  </form>
  </div>
  <script>
  $(function(){
  $("#email-form").on('submit', function(e){e.preventDefault();
  $.post('email-send', $(this).serialize(), function(data){
  if (data == 0) {
  $("#error").html('<h3>There was an error</h3>');
  } else {
  if (isNaN(data)) {
  $("#error").html('<h3>' + data + '</h3>');
  } else {
  $("#container").html('Your email has been sent!');
}
}
});
});
});
</script>
</body>
</html>
```

1.  在`views`文件夹中，创建我们的电子邮件模板视图文件，命名为`ajaxemail.php`，并使用以下代码：

```php
<!DOCTYPE html>
<html lang="en-US">
<head>
<meta charset="utf-8">
</head>
<body>
<h2>Your Message:</h2>
<div><?= $message ?></div>
</body>
</html>
```

1.  在`routes.php`文件中，根据以下代码片段创建路由：

```php
  Route::get('email-form', function()
{
  return View::make('emailform');
});
  Route::post('email-send', function()
{
  $input = Input::all();

  $rules = array('to'      => 'required|email','from'    => 'required|email','subject' => 'required','message' => 'required'
);

  $validation = Validator::make($input, $rules);

  if ($validation->fails())
{
  $return = '';
  foreach ($validation->errors()->all() as $err) {
  $return .= $err . '<br>';
}
  return $return;
}

  $send = Mail::send('ajaxemail', array('message' =>Input::get('message')), function($message)
{
  $message->to(Input::get('to'))->replyTo(Input::get('from'))->subject(Input::get('subject'));
});

  return $send;
});
```

## 它是如何工作的...

对于这个教程，我们需要正确配置我们的电子邮件客户端。我们有许多选择，包括 PHP 的`mail()`方法，sendmail 和 SMTP。我们甚至可以使用第三方电子邮件服务，如 mailgun 或 postmark。

我们的电子邮件表单是一个常规的 HTML 表单，包括四个字段：`to`和`from`电子邮件地址，`subject`行和实际的电子邮件消息。当表单被提交时，字段被序列化并发布到我们的`email-send`路由。

`email-send`路由首先验证所有发布的输入。如果有任何验证错误，它们将作为字符串返回。如果一切正常，我们将发送我们的值到`Mail::send`方法，然后发送它。

回到我们的`e-mail-form`路由 JavaScript 中，我们检查`email-send`是否返回了`FALSE`，如果是，则显示错误。如果不是，我们需要检查响应是否是一个数字。如果不是一个数字，那意味着有验证错误，我们将它们显示出来。如果是一个数字，那意味着电子邮件发送成功，所以我们显示一个成功消息。

# 使用 jQuery 和 Laravel 创建可排序的表格

在处理大量数据时，将其显示在表格视图中可能会有所帮助。为了操纵数据，例如排序或搜索，我们可以使用数据表 JavaScript 库。这样，我们就不需要每次想要更改视图时都进行数据库调用。

## 准备工作

对于这个示例，我们需要一个标准的 Laravel 安装和一个正确配置的 MySQL 数据库。

## 如何做...

按照给定的步骤完成这个示例：

1.  在我们的数据库中，使用以下命令创建一个新表并添加一些示例数据：

```php
DROP TABLE IF EXISTS bookprices;
CREATE TABLE bookprices (id int(10) unsigned NOT NULL AUTO_INCREMENT,price float(10,2) DEFAULT NULL,book varchar(100) DEFAULT NULL,PRIMARY KEY (id)) ENGINE=InnoDB DEFAULT CHARSET=utf8;
  INSERT INTO bookprices VALUES ('1', '14.99', 'Alice in Wonderland');
  INSERT INTO bookprices VALUES ('2', '24.50', 'Frankenstein');
  INSERT INTO bookprices VALUES ('3', '29.80', 'War andPeace');
  INSERT INTO bookprices VALUES ('4', '11.08', 'Moby Dick');
  INSERT INTO bookprices VALUES ('5', '19.72', 'The Wizard of Oz');
  INSERT INTO bookprices VALUES ('6', '45.00', 'The Odyssey');
```

1.  在`app/models`目录中，创建一个名为`Bookprices.php`的文件，并包含以下代码片段：

```php
<?php
class Bookprices extends Eloquent {
}
```

1.  在`routes.php`文件中，按照以下代码添加我们的路由：

```php
Route::get('table', function()
{
  $bookprices = Bookprices::all();
  return View::make('table')->with('bookprices', $bookprices);
});
```

1.  在`views`目录中，创建一个名为`table.php`的文件，其中包含以下代码：

```php
<!doctype html>
<html lang="en">
  <head>
  <meta charset="utf-8">
  <title></title>
  <script src="//ajax.googleapis.com/ajax/libs/jquery/1.10.2/jquery.min.js"></script>
  <script src="//ajax.aspnetcdn.com/ajax/jquery.dataTables/1.9.4/jquery.dataTables.min.js"></script>
  <link rel="stylesheet" type="text/css" href="//ajax.aspnetcdn.com/ajax/jquery.dataTables/1.9.4/css/jquery.dataTables.css">
  </head>
  <body>
  <h1>Book List</h1>
  <table>
  <thead>
  <tr>
  <th>Price</th>
  <th>Name</th>
  </tr>
  </thead>
  <tbody>
  <?php foreach ($bookprices as $book): ?>
  <tr>
  <td><?php echo $book['price'] ?></td>
  <td><?php echo $book['book'] ?></td>
  </tr>
  <?php endforeach; ?>
  </tbody>
  </table>
  <script>
  $(function(){
  $("table").dataTable();
});
  </script>
  </body>
  </html>
```

## 它是如何工作的...

要开始这个示例，我们创建一个表来保存我们的图书价格数据。然后，我们将数据插入表中。接下来，我们创建一个`Eloquent`模型，以便我们可以与数据交互。然后将该数据传递到我们的视图中。

在我们的视图中，我们加载 jQuery 和`dataTables`插件。然后，我们创建一个表来保存我们的数据，然后循环遍历数据，将每条记录放入新行中。当我们将`dataTable`插件添加到我们的表中时，它将自动为每个列添加排序。

## 还有更多...

`Datatables`是一个强大的 jQuery 插件，用于操纵表格数据。有关更多信息，请查看[`www.datatables.net`](http://www.datatables.net)上的文档。
