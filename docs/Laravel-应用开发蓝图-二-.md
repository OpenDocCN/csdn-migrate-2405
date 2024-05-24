# Laravel 应用开发蓝图（二）

> 原文：[`zh.annas-archive.org/md5/036252ba943f4598902eee3d22b931a1`](https://zh.annas-archive.org/md5/036252ba943f4598902eee3d22b931a1)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：构建新闻聚合网站

在本章中，我们将创建一个新闻聚合网站。我们将解析多个源，对它们进行分类，为我们的网站激活/停用它们，并使用 PHP 的 SimpleXML 扩展在我们的网站上显示它们。本章将涵盖以下主题：

+   创建数据库并迁移 feeds 表

+   创建 feeds 模型

+   创建我们的表单

+   验证和处理表单

+   扩展核心类

+   读取和解析外部源

# 创建数据库并迁移 feeds 表

成功安装 Laravel 4 并从`app/config/database.php`定义数据库凭据后，创建一个名为`feeds`的数据库。

创建数据库后，打开终端，进入项目文件夹，并运行此命令：

```php
**php artisan migrate:make create_feeds_table --table=feeds --create**

```

这个命令将为我们生成一个名为`feeds`的新数据库迁移。现在导航到`app/database/migrations`，打开刚刚由前面的命令创建的迁移文件，并将其内容更改如下：

```php
<?php
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class CreateFeedsTable extends Migration {

  /**
   * Run the migrations.
   *
   * @return void
   */
  public function up()
  {
    Schema::create('feeds', function(Blueprint $table)
    {
      $table->increments('id');
      $table->enum('active', array('0', '1'));
      $table->string('title,100)->default('');
      $table->enum('category', array('News', 'Sports','Technology'));
      $table->string('feed',1000)->default('');
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
    Schema::drop('feeds');
  }

}
```

我们有一个`title`列用于在网站上显示标题，这更加用户友好。此外，我们设置了一个名为`active`的键，因为我们想要启用/禁用源；我们使用 Laravel 4 提供的新`enum()`方法进行设置。我们还设置了一个`category`列，也使用`enum()`方法进行分组源的设置。

保存文件后，运行以下命令执行迁移：

```php
**php artisan migrate**

```

如果没有错误发生，您已经准备好进行项目的下一步了。

# 创建 feeds 模型

如您所知，对于 Laravel 上的任何与数据库操作相关的事情，使用模型是最佳实践。我们将受益于 Eloquent ORM。

将此文件保存为`feeds.php`，放在`app/models/`下：

```php
<?php
Class Feeds Extends Eloquent{
    protected $table = 'feeds';
    protected $fillable = array('feed', 'title', 'active','category');
}
```

我们设置表名和可填充列的值。现在我们的模型已经准备好，我们可以继续下一步，开始创建我们的控制器和表单。

# 创建我们的表单

现在我们应该创建一个表单来保存记录到数据库并指定其属性。

1.  首先，打开终端并输入以下命令：

```php
**php artisan controller:make FeedsController**

```

这个命令将为您在`app/controllers`文件夹中生成一个`FeedsController.php`文件，并带有一些空白方法。

### 注意

由`artisan`命令自动填充的控制器中的默认方法不是 RESTful 的。

1.  现在，打开`app/routes.php`并添加以下行：

```php
**//We defined a RESTful controller and all its via route directly**
**Route::controller('feeds', 'FeedsController');**

```

我们可以使用一行代码定义控制器上声明的所有操作，而不是逐个定义所有操作。如果您的方法名称可以直接用作 get 或 post 操作，使用`controller()`方法可以节省大量时间。第一个参数设置控制器的 URI，第二个参数定义`controllers`文件夹中将被访问和定义的类。

### 注意

以这种方式设置的控制器自动是 RESTful 的。

1.  现在，让我们创建表单的方法。将以下代码添加到您的控制器文件中：

```php
  //The method to show the form to add a new feed
  public function getCreate() {
    //We load a view directly and return it to be served
    return View::make('create_feed');
      }
```

这里的过程非常简单；我们将方法命名为`getCreate()`，因为我们希望我们的`create`方法是 RESTful 的。我们只是加载了一个视图文件，我们将在下一步直接生成它。

1.  现在让我们创建我们的视图文件。将此文件保存为`create_feed.blade.php`，放在`app/views/`下：

```php
<!doctype html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Save a new ATOM Feed to Database</title>
</head>
<body>
  <h1>Save a new ATOM Feed to Database</h1>
  @if(Session::has('message'))
    <h2>{{Session::get('message')}}</h2>
  @endif
    {{Form::open(array('url' => 'feeds/create', 'method' => 'post'))}}
    <h3>Feed Category</h3>
  {{Form::select('category',array('News'=>'News','Sports'=>'Sports','Technology'=>'Technology'),Input::old('category'))}}
  <h3>Title</h3>
    {{Form::text('title',Input::old('title'))}}
    <h3>Feed URL</h3>
    {{Form::text('feed',Input::old('feed'))}}

    <h3>Show on Site?</h3>
{{Form::select('active',array('1'=>'Yes','2'=>'No'),Input::old('active'))}}
    {{Form::submit('Save!',array('style'=>'margin:20px 100% 0 0'))}}
    {{Form::close()}}
</body>
</html>
```

上述代码将生成一个简单的表单，如下所示：

![创建我们的表单](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrv-app-dev-bp/img/2111OS_05_01.jpg)

# 验证和处理表单

在本节中，我们将验证提交的表单，并确保字段有效且必填字段已填写。然后我们将数据保存到数据库中。

1.  首先，我们需要定义表单验证规则。我们更喜欢将验证规则添加到相关模型中，这样规则就可以重复使用，这可以防止代码变得臃肿。为此，在本章前面生成的`feeds.php`中的`app/models/`（我们生成的模型）中，类定义的最后一个`}`之前添加以下代码：

```php
//Validation rules
public static $form_rules = array(
  'feed'    => 'required|url|active_url',
  'title'  => 'required'
  'active'  => 'required|between:0,1',
  'category'  => 'required| in:News,Sports,Technology'
);
```

我们将变量设置为`public`，这样它可以在模型文件之外使用，并将其设置为`static`，这样我们可以直接访问这个变量。

我们希望 feed 是一个 URL，并且我们希望使用`active_url`验证规则来检查它是否是一个活动的 URL，这取决于 PHP 的`chkdnsrr()`方法。

我们的 active 字段只能获得两个值，`1`或`0`。由于我们将其设置为整数，我们可以使用 Laravel 的表单验证规则`between`来检查数字是否在`1`和`0`之间。

我们的 category 字段也具有`enum`类型，其值应该只是`News`、`Sports`或`Technology`。要使用 Laravel 检查确切的值，你可以使用验证规则`in`。

### 注意

并非所有的服务器配置都支持`chkdnsrr()`方法，所以确保它在你这边已安装，否则你可能只依赖于验证 URL 是否格式正确。

1.  现在我们需要一个控制器的 post 方法来处理表单。在最后一个`}`之前，将以下方法添加到`app/controllers/FeedsController.php`中：

```php
//Processing the form
public function postCreate(){

//Let's first run the validation with all provided input
  $validation = Validator::make(Input::all(),Feeds::$form_rules);
  //If the validation passes, we add the values to the database and return to the form 
  if($validation->passes()) {
    //We try to insert a new row with Eloquent
    $create = Feeds::create(array(
      'feed'    => Input::get('feed'),
      'title'  => Input::get('title'),
      'active'  => Input::get('active'),
      'category'  => Input::get('category')
    ));

    //We return to the form with success or error message due to state of the 
    if($create) {
      return Redirect::to('feeds/create')
        ->with('message','The feed added to the database successfully!');
    } else {
      return Redirect::to('feeds/create')
        ->withInput()
        ->with('message','The feed could not be added, please try again later!');
    }
  } else {
    //If the validation does not pass, we return to the form with first error message as flash data
    return Redirect::to('feeds/create')
        ->withInput()
        ->with('message',$validation->errors()->first());

  }
}
```

让我们逐一深入代码。首先，我们进行了表单验证，并从我们通过`Feeds::$form_rules`生成的模型中调用了我们的验证规则。

之后，我们创建了一个`if()`语句，并用它将代码分成两部分。如果表单验证失败，我们将使用`withInput()`特殊方法返回到表单，并使用`with()`方法添加一个 flash 数据消息字段。

如果表单验证通过，我们尝试使用 Eloquent 的`create()`方法向数据库添加新列，并根据`create`方法返回的结果返回到表单，显示成功或错误消息。

现在，我们需要为索引页面创建一个新的视图，它将显示所有 feed 的最后五个条目。但在此之前，我们需要一个函数来解析 Atom feeds。为此，我们将扩展 Laravel 的内置`Str`类。

# 扩展核心类

Laravel 有许多内置的方法，使我们的生活更轻松。但是，就像所有捆绑包一样，捆绑包本身可能不会满足任何用户，因为它是被引入的。因此，你可能希望使用自己的方法以及捆绑的方法。你总是可以创建新的类，但是如果你想要实现的一半已经内置了呢？例如，你想添加一个表单元素，但已经有一个`Form`类捆绑了。在这种情况下，你可能希望扩展当前的类，而不是创建新的类来保持代码整洁。

在这一部分，我们将使用名为`parse_atom()`的方法来扩展`Str`类，我们将编写这个方法。

1.  首先，你必须找到类文件所在的位置。我们将扩展`Str`类，它位于`vendor/laravel/framework/src/Illuminate/Support`下。请注意，你也可以在`app/config/app.php`的 aliases 键中找到这个类。

1.  现在在`app/folder`下创建一个名为`lib`的新文件夹。这个文件夹将保存我们的类扩展。因为`Str`类被分组到`Support`文件夹下，建议你也在`lib`下创建一个名为`Support`的新文件夹。

1.  现在在`app/lib/Support`下创建一个名为`Str.php`的新文件，你刚刚创建的：

```php
<?php namespace app\lib\Support;
class Str extends \Illuminate\Support\Str {
    //Our shiny extended codes will come here
  }
```

我们给它命名空间，这样我们就可以轻松地访问它。你可以直接使用`Str::trim()`，而不是像`\app\lib\Support\Str::trim()`那样使用它（你可以）。其余的代码解释了如何扩展库。我们提供了从`Illuminate`路径开始的类名，以直接访问`Str`类。

1.  现在打开位于`app/config/`下的`app.php`文件；注释掉以下行：

```php
'Str'             => 'Illuminate\Support\Str',
```

1.  现在，添加以下行：

```php
'Str'             => 'app\lib\Support\Str',
```

这样，我们用我们的类替换了自动加载的`Str`类，而我们的类已经扩展了原始类。

1.  现在为了在 autoruns 上进行标识，打开你的`composer.json`文件，并将这些行添加到 autoload 的`classmap`对象中：

```php
"app/lib",
"app/lib/Support"
```

1.  最后，在终端中运行以下命令：

```php
**php composer.phar dump-autoload**

```

这将寻找依赖项并重新编译常见类。如果一切顺利，你现在将拥有一个扩展的`Str`类。

### 注意

文件夹和类名在 Windows 服务器上也是区分大小写的。

# 读取和解析外部反馈

我们在服务器上已经对反馈的 URL 和标题进行了分类。现在我们要做的就是解析它们并展示给最终用户。这需要遵循一些步骤：

1.  首先，我们需要一个方法来解析外部 Atom 反馈。打开位于`app/lib/Support/`下的`Str.php`文件，并将此方法添加到类中：

```php
public static function parse_feed($url) {
    //First, we get our well-formatted external feed
    $feed = simplexml_load_file($url);
    //if cannot be found, or a parse/syntax error occurs, we return a blank array
    if(!count($feed)) {
      return array();
    } else {
      //If found, we return the newest five <item>s in the <channel>
      $out = array();
      $items = $feed->channel->item;
      for($i=0;$i<5;$i++) {
        $out[] = $items[$i];
      }
      //and we return the output
      return $out;
    }
  }
```

首先，我们使用 SimpleXML 的内置方法`simplexml_load_file()`在方法中加载 XML 反馈。如果没有找到结果或者反馈包含错误，我们就返回一个空数组。在 SimpleXML 中，所有对象及其子对象都与 XML 标签完全一样。所以如果有一个`<channel>`标签，就会有一个名为`channel`的对象，如果在`<channel>`内有`<item>`标签，那么在每个`channel`对象下面就会有一个名为`item`的对象。所以如果你想访问通道内的第一项，你可以这样访问：`$xml->channel->item[0]`。

1.  现在我们需要一个视图来显示内容。首先打开`app`下的`routes.php`，并删除默认存在的`get`路由：

```php
Route::get('/', array('as'=>'index', 'uses' =>'FeedsController@getIndex'));
```

1.  现在打开`FeedsController.php`，位于`app/controller/`下，并粘贴以下代码：

```php
public function getIndex(){
  //First we get all the records that are active category by category:
    $news_raw   = Feeds::whereActive(1)->whereCategory('News')->get();
    $sports_raw  = Feeds::whereActive(1)->whereCategory('Sports')->get();
    $technology_raw = Feeds::whereActive(1)->whereCategory('Technology')->get();

  //Now we load our view file and send variables to the view
  return View::make('index')
    ->with('news',$news_raw)
    ->with('sports',$sports_raw)
    ->with('technology',$technology_raw);
  }
```

在控制器中，我们逐个获取反馈的 URL，然后加载一个视图，并将它们逐个设置为每个类别的单独变量。

1.  现在我们需要循环每个反馈类别并显示其内容。将以下代码保存在名为`index.blade.php`的文件中，放在`app/views/`下：

```php
<!doctype html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Your awesome news aggregation site</title>
    <style type="text/css">
    body { font-family: Tahoma, Arial, sans-serif; }
    h1, h2, h3, strong { color: #666; }
    blockquote{ background: #bbb; border-radius: 3px; }
    li { border: 2px solid #ccc; border-radius: 5px; list-style-type: none; margin-bottom: 10px }
    a { color: #1B9BE0; }
    </style>
</head>
<body>
   <h1>Your awesome news aggregation site</h1>
   <h2>Latest News</h2>
    @if(count($news))
        {{--We loop all news feed items --}}
        @foreach($news as $each)
            <h3>News from {{$each->title}}:</h3>
            <ul>
            {{-- for each feed item, we get and parse its feed elements --}}
            <?php $feeds = Str::parse_feed($each->feed); ?>
            @if(count($feeds))
                {{-- In a loop, we show all feed elements one by one --}}
                @foreach($feeds as $eachfeed)
                    <li>
                        <strong>{{$eachfeed->title}}</strong><br />
                        <blockquote>{{Str::limit(strip_tags($eachfeed->description),250)}}</blockquote>
                        <strong>Date: {{$eachfeed->pubDate}}</strong><br />
                        <strong>Source: {{HTML::link($eachfeed->link,Str::limit($eachfeed->link,35))}}</strong>

                    </li>
                @endforeach
            @else
                <li>No news found for {{$each->title}}.</li>
            @endif
            </ul>
        @endforeach
    @else
        <p>No News found :(</p>
    @endif

    <hr />

    <h2>Latest Sports News</h2>
    @if(count($sports))
        {{--We loop all news feed items --}}
        @foreach($sports as $each)
            <h3>Sports News from {{$each->title}}:</h3>
            <ul>
            {{-- for each feed item, we get and parse its feed elements --}}
            <?php $feeds = Str::parse_feed($each->feed); ?>
            @if(count($feeds))
                {{-- In a loop, we show all feed elements one by one --}}
                @foreach($feeds as $eachfeed)
                    <li>
                        <strong>{{$eachfeed->title}}</strong><br />
                        <blockquote>{{Str::limit(strip_tags($eachfeed->description),250)}}</blockquote>
                        <strong>Date: {{$eachfeed->pubDate}}</strong><br />
                        <strong>Source: {{HTML::link($eachfeed->link,Str::limit($eachfeed->link,35))}}</strong>
                    </li>
                @endforeach
            @else
                <li>No Sports News found for {{$each->title}}.</li>
            @endif
            </ul>
        @endforeach
    @else
        <p>No Sports News found :(</p>
    @endif

    <hr />

    <h2>Latest Technology News</h2>
    @if(count($technology))
       {{--We loop all news feed items --}}
        @foreach($technology as $each)
            <h3>Technology News from {{$each->title}}:</h3>
            <ul>
            {{-- for each feed item, we get and parse its feed elements --}}
            <?php $feeds = Str::parse_feed($each->feed); ?>
            @if(count($feeds))
                {{-- In a loop, we show all feed elements one by one --}}
                @foreach($feeds as $eachfeed)
                    <li>
                        <strong>{{$eachfeed->title}}</strong><br />
                        <blockquote>{{Str::limit(strip_tags($eachfeed->description),250)}}</blockquote>
                        <strong>Date: {{$eachfeed->pubDate}}</strong><br />
                        <strong>Source: {{HTML::link($eachfeed->link,Str::limit($eachfeed->link,35))}}</strong>
                    </li>
                @endforeach
            @else
                <li>No Technology News found for {{$each->title}}.</li>
            @endif
            </ul>
        @endforeach
    @else
        <p>No Technology News found :(</p>
    @endif

</body>
</html>
```

1.  我们为每个类别写了相同的代码三次。此外，在`head`标签之间进行了一些样式处理，以便页面对最终用户看起来更漂亮。

我们用`<hr>`标签分隔了每个类别的部分。所有三个部分的工作机制都相同，除了源变量和分组。

我们首先检查每个类别是否存在记录（来自数据库的结果，因为我们可能还没有添加任何新闻源）。如果有结果，就使用 Blade 模板引擎的`@foreach()`方法循环遍历每条记录。

对于每条记录，我们首先显示反馈的友好名称（我们在保存时定义的），并使用我们刚刚创建的`parse_feed()`方法解析反馈。

在解析每个反馈后，我们查看是否找到了任何记录；如果找到了，我们再次循环它们。为了保持我们反馈阅读器的整洁，我们使用 PHP 的`strip_tags()`函数去除了所有 HTML 标签，并使用 Laravel 的`Str`类的`limit()`方法将它们限制在最多 250 个字符。

各个反馈项也有自己的标题、日期和源链接，所以我们也在反馈上显示了它们。为了防止链接破坏我们的界面，我们将文本限制在 35 个字符之间写在锚标签之间。

在所有编辑完成后，你应该得到如下输出：

![读取和解析外部反馈](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrv-app-dev-bp/img/2111OS_05_02.jpg)

# 摘要

在本章中，我们使用 Laravel 的内置函数和 PHP 的`SimpleXML`类创建了一个简单的反馈阅读器。我们学会了如何扩展核心库，编写自己的方法，并在生产中使用它们。我们还学会了在查询数据库时如何过滤结果以及如何创建记录。最后，我们学会了如何处理字符串，限制它们，并清理它们。在下一章中，我们将创建一个照片库系统。我们将确保上传的文件是照片。我们还将把照片分组到相册中，并使用 Laravel 的内置关联方法关联相册和照片。


# 第六章：创建照片库系统

在本章中，我们将使用 Laravel 编写一个简单的照片库系统。我们还将涵盖 Laravel 内置的文件验证、文件上传和**hasMany**数据库关系机制。我们将使用`validation`类来验证数据和文件。此外，我们还将涵盖用于处理文件的文件类。本章涵盖以下主题：

+   创建相册模型

+   创建图像模型

+   创建相册

+   创建照片上传表单

+   在相册之间移动照片

# 创建相册表并迁移

我们假设你已经在`app/config/`目录下的`database.php`文件中定义了数据库凭据。要构建一个照片库系统，我们需要一个包含两个表`albums`和`images`的数据库。要创建一个新数据库，只需运行以下 SQL 命令：

```php
**CREATE DATABASE laravel_photogallery**

```

成功创建应用程序的数据库后，我们首先需要创建`albums`表并将其安装到数据库中。为此，请打开终端，导航到项目文件夹，运行以下命令：

```php
**php artisan migrate:make create_albums_table --table=albums --create**

```

上述命令将在`app/database/migrations`下生成一个迁移文件，用于在我们的`laravel_photogallery`数据库中生成一个名为`posts`的新 MySQL 表。

为了定义我们的表列，我们需要编辑迁移文件。编辑后，文件应该包含以下代码：

```php
<?php

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class CreateAlbumsTable extends Migration {

  /**
  * Run the migrations.
  *
  * @return void
  */
  public function up()
    {
      Schema::create('albums', function(Blueprint $table)
      {
        $table->increments('id')->unsigned();
        $table->string('name');
        $table->text('description');
        $table->string('cover_image');
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
    Schema::drop('albums');
  }
}
```

保存文件后，我们需要再次使用简单的 artisan 命令来执行迁移：

```php
**php artisan migrate**

```

如果没有发生错误，请检查`laravel_photogallery`数据库的`albums`表及其列。

让我们检查以下列表中的列：

+   `id`：此列用于存储相册的 ID

+   `name`：此列用于存储相册的名称

+   `description`：此列用于存储相册的描述

+   `cover_image`：此列用于存储相册的封面图像

我们已成功创建了`albums`表，现在需要编写我们的**Album**模型。

## 创建相册模型

如你所知，对于 Laravel 上的任何与数据库操作相关的事情，使用模型是最佳实践。我们将受益于使用 Eloquent ORM。

将以下代码保存为`Album.php`，放在`app/models/`目录中：

```php
<?php
class Album extends Eloquent {

  protected $table = 'albums';

  protected $fillable = array('name','description','cover_image');

  public function Photos(){

    return $this->has_many('images');
  }
}
```

我们使用`protected $table`变量设置了数据库表名；我们还使用了`protected $fillable`变量设置了可编辑的列，这是我们在之前章节中已经见过和使用过的。模型中定义的变量足以使用 Laravel 的 Eloquent ORM。我们将在本章的*将照片分配给相册*部分中介绍`public Photos()`函数。

我们的**Album**模型已准备好；现在我们需要一个**Image**模型和一个分配照片到相册的数据库。让我们创建它们。

# 使用迁移类创建图像数据库

要为图像创建我们的迁移文件，打开终端，导航到项目文件夹，运行以下命令：

```php
**php artisan migrate:make create_images_table --table=images --create**

```

如你所知，该命令将在`app/database/migrations`中生成一个迁移文件。让我们编辑迁移文件；最终代码应该如下所示：

```php
<?php

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class CreateImagesTable extends Migration {

  /**
  * Run the migrations.
  *
  * @return void
  */
  public function up()
  {
    Schema::create('images', function(Blueprint $table)
    {
      $table->increments('id')->unsigned();
      $table->integer('album_id')->unsigned();
      $table->string('image');
      $table->string('description');
      $table->foreign('album_id')->references('id')->on('albums')->onDelete('CASCADE')->onUpdate('CASCADE');
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
    Schema::drop('images');
  }
}
```

编辑迁移文件后，运行以下迁移命令：

```php
**php artisan migrate**

```

如你所知，该命令创建了`images`表及其列。如果没有发生错误，请检查`laravel_photogallery`数据库的`users`表及其列。

让我们检查以下列表中的列：

+   `id`：此列用于存储图像的 ID

+   `album_id`：此列用于存储图像所属相册的 ID

+   `description`：此列用于存储图像的描述

+   `image`：此列用于存储图像的路径

我们需要解释一下这个迁移文件的另一件事。如你在迁移代码中所见，有一个`foreign`键。当我们需要链接两个表时，我们使用`foreign`键。我们有一个`albums`表，每个相册都会有图像。如果从数据库中删除相册，你也希望删除其所有图像。

# 创建一个 Image 模型

我们已经创建了`images`表。所以，你知道，我们需要一个模型来在 Laravel 上操作数据库表。为了创建它，将以下代码保存为 Image.php 在`app/models/`目录中：

```php
class Images extends Eloquent {

  protected $table = 'images';

  protected $fillable = array('album_id','description','image');

}
```

我们的**Image**模型已经准备好了；现在我们需要一个控制器来在我们的数据库上创建相册。让我们来创建它。

# 创建相册

正如你从本书的前几章中所了解的，Laravel 拥有一个很棒的 RESTful 控制器机制。我们将继续使用它来在开发过程中保持代码简单和简洁。在接下来的章节中，我们将介绍另一种很棒的控制器/路由方法，名为**资源控制器**。

为了列出、创建和删除相册，我们需要在我们的控制器中添加一些函数。为了创建它们，将以下代码保存为`AlbumsController.php`在`app/controllers/`目录中：

```php
<?php

class AlbumsController extends BaseController{

  public function getList()
  {
    $albums = Album::with('Photos')->get();
    return View::make('index')
    ->with('albums',$albums);
  }
  public function getAlbum($id)
  {
    $album = Album::with('Photos')->find($id);
    return View::make('album')
    ->with('album',$album);
  }
  public function getForm()
  {
    return View::make('createalbum');
  }
  public function postCreate()
  {
    $rules = array(

      'name' => 'required',
      'cover_image'=>'required|image'

    );

    $validator = Validator::make(Input::all(), $rules);
    if($validator->fails()){

      return Redirect::route('create_album_form')
      ->withErrors($validator)
      ->withInput();
    }

    $file = Input::file('cover_image');
    $random_name = str_random(8);
    $destinationPath = 'albums/';
    $extension = $file->getClientOriginalExtension();
    $filename=$random_name.'_cover.'.$extension;
    $uploadSuccess = Input::file('cover_image')
    ->move($destinationPath, $filename);
    $album = Album::create(array(
      'name' => Input::get('name'),
      'description' => Input::get('description'),
      'cover_image' => $filename,
    ));

    return Redirect::route('show_album',array('id'=>$album->id));
  }

  public function getDelete($id)
  {
    $album = Album::find($id);

    $album->delete();

    return Redirect::route('index');
  }
}
```

`postCreate()`函数首先验证表单提交的数据。我们将在下一节中介绍验证。如果数据验证成功，我们将重命名封面图像并使用新文件名上传它，因为代码会覆盖具有相同名称的文件。

`getDelete()`函数正在从数据库中删除相册以及分配的图像（存储在`images`表中）。请记住以下迁移文件代码：

```php
$table->foreign('album_id')->references('id')->on('albums')->onDelete('CASCADE')->onUpdate('CASCADE');
```

在创建我们的模板之前，我们需要定义路由。因此，打开`app`文件夹中的`routes.php`文件，并用以下代码替换它：

```php
<?php
Route::get('/', array('as' => 'index','uses' => 'AlbumsController@getList'));
Route::get('/createalbum', array('as' => 'create_album_form','uses' => 'AlbumsController@getForm'));
Route::post('/createalbum', array('as' => 'create_album','uses' => 'AlbumsController@postCreate'));
Route::get('/deletealbum/{id}', array('as' => 'delete_album','uses' => 'AlbumsController@getDelete'));
Route::get('/album/{id}', array('as' => 'show_album','uses' => 'AlbumsController@getAlbum'));
```

现在，我们需要一些模板文件来显示、创建和列出相册。首先，我们应该创建索引模板。为了创建它，将以下代码保存为`index.blade.php`在`app/views/`目录中：

```php
<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8">
    <title>Awesome Albums</title>
    <!-- Latest compiled and minified CSS -->
    <link href="//netdna.bootstrapcdn.com/bootstrap/3.0.0-rc1/css/bootstrap.min.css" rel="stylesheet">

    <!-- Latest compiled and minified JavaScript -->
    <script src="//netdna.bootstrapcdn.com/bootstrap/3.0.0-rc1/js/bootstrap.min.js"></script>
    <style>
      body {
        padding-top: 50px;
      }
      .starter-template {
        padding: 40px 15px;
      text-align: center;
      }
    </style>
  </head>
  <body>
    <div class="navbar navbar-inverse navbar-fixed-top">
      <div class="container">
      <button type="button" class="navbar-toggle"data-toggle="collapse" data-target=".nav-collapse">
        <span class="icon-bar"></span>
        <span class="icon-bar"></span>
        <span class="icon-bar"></span>
      </button>
      <a class="navbar-brand" href="/">Awesome Albums</a>
      <div class="nav-collapse collapse">
        <ul class="nav navbar-nav">
          <li><a href="{{URL::route('create_album_form')}}">Create New Album</a></li>
        </ul>
      </div><!--/.nav-collapse -->
    </div>
    </div>

      <div class="container">

        <div class="starter-template">

        <div class="row">
          @foreach($albums as $album)
            <div class="col-lg-3">
              <div class="thumbnail" style="min-height: 514px;">
                <img alt="{{$album->name}}" src="/albums/{{$album->cover_image}}">
                <div class="caption">
                  <h3>{{$album->name}}</h3>
                  <p>{{$album->description}}</p>
                  <p>{{count($album->Photos)}} image(s).</p>
                  <p>Created date:  {{ date("d F Y",strtotime($album->created_at)) }} at {{date("g:ha",strtotime($album->created_at)) }}</p>
                  <p><a href="{{URL::route('show_album', array('id'=>$album->id))}}" class="btn btn-big btn-default">Show Gallery</a></p>
                </div>
              </div>
            </div>
          @endforeach
        </div>

      </div><!-- /.container -->
    </div>

  </body>
</html>
```

## 为创建相册添加模板

正如你在以下代码中所看到的，我们更喜欢使用 Twitter 的 bootstrap **CSS**框架。这个框架允许你快速创建有用、响应式和多浏览器支持的界面。接下来，我们需要为创建相册创建一个模板。为了创建它，将以下代码保存为`createalbum.blade.php`在`app/views/`目录中：

```php
<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width,initial-scale=1.0">
    <title>Create an Album</title>
    <!-- Latest compiled and minified CSS -->
    <link href="//netdna.bootstrapcdn.com/bootstrap/3.0.0-rc1/css/bootstrap.min.css" rel="stylesheet">

    <!-- Latest compiled and minified JavaScript -->
    <script src="//netdna.bootstrapcdn.com/bootstrap/3.0.0-rc1/js/bootstrap.min.js"></script>
  </head>
  <body>
    <div class="navbar navbar-inverse navbar-fixed-top">
      <div class="container">
        <button type="button" class="navbar-toggle"data-toggle="collapse" data-target=".nav-collapse">
          <span class="icon-bar"></span>
          <span class="icon-bar"></span>
          <span lclass="icon-bar"></span>
        </button>
        <a class="navbar-brand" href="/">Awesome Albums</a>
        <div class="nav-collapse collapse">
          <ul class="nav navbar-nav">
            <li class="active"><ahref="{{URL::route('create_album_form')}}">CreateNew Album</a></li>
          </ul>
        </div><!--/.nav-collapse -->
      </div>
    </div>
    <div class="container" style="text-align: center;">
      <div class="span4" style="display: inline-block;margin-top:100px;">

        @if($errors->has())
          <div class="alert alert-block alert-error fade in"id="error-block">
             <?php
             $messages = $errors->all('<li>:message</li>');
            ?>
            <button type="button" class="close"data-dismiss="alert">×</button>

            <h4>Warning!</h4>
            <ul>
              @foreach($messages as $message)
                {{$message}}
              @endforeach

            </ul>
          </div>
        @endif

        <form name="createnewalbum" method="POST"action="{{URL::route('create_album')}}"enctype="multipart/form-data">
          <fieldset>
            <legend>Create an Album</legend>
            <div class="form-group">
              <label for="name">Album Name</label>
              <input name="name" type="text" class="form-control"placeholder="Album Name"value="{{Input::old('name')}}">
            </div>
            <div class="form-group">
              <label for="description">Album Description</label>
              <textarea name="description" type="text"class="form-control" placeholder="Albumdescription">{{Input::old('descrption')}}</textarea>
            </div>
            <div class="form-group">
              <label for="cover_image">Select a Cover Image</label>
              {{Form::file('cover_image')}}
            </div>
            <button type="submit" class="btnbtn-default">Create!</button>
          </fieldset>
        </form>
      </div>
    </div> <!-- /container -->
  </body>
</html>
```

该模板创建了一个基本的上传表单，并显示了从控制器端传递的验证错误。我们只需要再创建一个模板文件来列出相册图像。因此，为了创建它，将以下代码保存为`album.blade.php`在`app/views/`目录中：

```php
<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8">
    <title>{{$album->name}}</title>
    <!-- Latest compiled and minified CSS -->
    <link href="//netdna.bootstrapcdn.com/bootstrap/3.0.0-rc1/css/bootstrap.min.css" rel="stylesheet">

    <!-- Latest compiled and minified JavaScript -->
    <script src="//netdna.bootstrapcdn.com/bootstrap/3.0.0-rc1/js/bootstrap.min.js"></script>
    <style>
      body {
        padding-top: 50px;
      }
      .starter-template {
        padding: 40px 15px;
        text-align: center;
      }
    </style>
  </head>
  <body>
    <div class="navbar navbar-inverse navbar-fixed-top">
      <div class="container">
        <button type="button" class="navbar-toggle"data-toggle="collapse" data-target=".nav-collapse">
          <span class="icon-bar"></span>
          <span class="icon-bar"></span>
          <span class="icon-bar"></span>
        </button>
        <a class="navbar-brand" href="/">Awesome Albums</a>
        <div class="nav-collapse collapse">
          <ul class="nav navbar-nav">
            <li><a href="{{URL::route('create_album_form')}}">Create New Album</a></li>
          </ul>
        </div><!--/.nav-collapse -->
     </div>
    </div>
    <div class="container">

      <div class="starter-template">
        <div class="media">
          <img class="media-object pull-left"alt="{{$album->name}}" src="/albums/{{$album->cover_image}}" width="350px">
          <div class="media-body">
            <h2 class="media-heading" style="font-size: 26px;">Album Name:</h2>
            <p>{{$album->name}}</p>
          <div class="media">
          <h2 class="media-heading" style="font-size: 26px;">AlbumDescription :</h2>
          <p>{{$album->description}}<p>
          <a href="{{URL::route('add_image',array('id'=>$album->id))}}"><button type="button"class="btn btn-primary btn-large">Add New Image to Album</button></a>
          <a href="{{URL::route('delete_album',array('id'=>$album->id))}}" onclick="return confirm('Are yousure?')"><button type="button"class="btn btn-danger btn-large">Delete Album</button></a>
        </div>
      </div>
    </div>
    </div>
      <div class="row">
        @foreach($album->Photos as $photo)
          <div class="col-lg-3">
            <div class="thumbnail" style="max-height: 350px;min-height: 350px;">
              <img alt="{{$album->name}}" src="/albums/{{$photo->image}}">
              <div class="caption">
                <p>{{$photo->description}}</p>
                <p><p>Created date:  {{ date("d F Y",strtotime($photo->created_at)) }} at {{ date("g:ha",strtotime($photo->created_at)) }}</p></p>
                <a href="{{URL::route('delete_image',array('id'=>$photo->id))}}" onclick="return confirm('Are you sure?')"><button type="button" class="btnbtn-danger btn-small">Delete Image </button></a>
              </div>
            </div>
          </div>
        @endforeach
      </div>
    </div>

  </body>
</html>
```

正如你可能记得的，我们在模型端使用了`hasMany()` Eloquent 方法。在控制器端，我们使用以下函数：

```php
**$albums = Album::with('Photos')->get();**

```

该代码在数组中获取了属于相册的整个图像数据。因此，我们在以下模板中使用`foreach`循环：

```php
@foreach($album->Photos as $photo)
  <div class="col-lg-3">
    <div class="thumbnail" style="max-height: 350px;min-height: 350px;">
    <img alt="{{$album->name}}" src="/albums/{{$photo->image}}">
      <div class="caption">
        <p>{{$photo->description}}</p>
        <p><p>Created date:  {{ date("d F Y",strtotime($photo->created_at)) }} at {{ date("g:ha",strtotime($photo->created_at)) }}</p></p>
        <a href="{{URL::route('delete_image',array('id'=>$photo->id))}}" onclick="return confirm('Are yousure?')"><button type="button" class="btnbtn-danger btn-small">Delete Image</button></a>
      </div>
    </div>
  </div>
@endforeach
```

# 创建一个照片上传表单

现在我们需要创建一个照片上传表单。我们将上传照片并将它们分配到相册中。让我们首先设置路由；打开`app`文件夹中的`routes.php`文件，并添加以下代码：

```php
Route::get('/addimage/{id}', array('as' => 'add_image','uses' => 'ImagesController@getForm'));
Route::post('/addimage', array('as' => 'add_image_to_album','uses' => 'ImagesController@postAdd'));
Route::get('/deleteimage/{id}', array('as' => 'delete_image','uses' => 'ImagesController@getDelete'));
```

我们需要一个照片上传表单的模板。为了创建它，将以下代码保存为`addimage.blade.php`在`app/views/`目录中：

```php
<!doctype html>
  <html lang="en">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width,initial-scale=1.0">
    <title>Laravel PHP Framework</title>
    <!-- Latest compiled and minified CSS -->
    <link href="//netdna.bootstrapcdn.com/bootstrap/3.0.0-rc1/css/bootstrap.min.css" rel="stylesheet">

    <!-- Latest compiled and minified JavaScript -->
    <script src="//netdna.bootstrapcdn.com/bootstrap/3.0.0-rc1/js/bootstrap.min.js"></script>
  </head>
  <body>

    <div class="container" style="text-align: center;">
      <div class="span4" style="display: inline-block;margin-top:100px;">
        @if($errors->has())
          <div class="alert alert-block alert-error fade in"id="error-block">
            <?php
            $messages = $errors->all('<li>:message</li>');
            ?>
            <button type="button" class="close"data-dismiss="alert">×</button>

            <h4>Warning!</h4>
            <ul>
              @foreach($messages as $message)
                {{$message}}
              @endforeach

            </ul>
          </div>
        @endif
        <form name="addimagetoalbum" method="POST"action="{{URL::route('add_image_to_album')}}"enctype="multipart/form-data">
          <input type="hidden" name="album_id"value="{{$album->id}}" />
          <fieldset>
            <legend>Add an Image to {{$album->name}}</legend>
            <div class="form-group">
              <label for="description">Image Description</label>
              <textarea name="description" type="text"class="form-control" placeholder="Imagedescription"></textarea>
            </div>
            <div class="form-group">
              <label for="image">Select an Image</label>
              {{Form::file('image')}}
            </div>
            <button type="submit" class="btnbtn-default">Add Image!</button>
          </fieldset>
        </form>
      </div>
    </div> <!-- /container -->
  </body>
</html>
```

在创建模板之前，我们需要编写我们的控制器。因此，将以下代码保存为`ImageController.php`在`app/controllers/`目录中：

```php
<?php
class ImagesController extends BaseController{

  public function getForm($id)
  {
    $album = Album::find($id);
    return View::make('addimage')
    ->with('album',$album);
  }

  public function postAdd()
  {
    $rules = array(

      'album_id' => 'required|numeric|exists:albums,id',
      'image'=>'required|image'

    );

    $validator = Validator::make(Input::all(), $rules);
    if($validator->fails()){

      return Redirect::route('add_image',array('id' =>Input::get('album_id')))
      ->withErrors($validator)
      ->withInput();
    }

    $file = Input::file('image');
    $random_name = str_random(8);
    $destinationPath = 'albums/';
    $extension = $file->getClientOriginalExtension();
    $filename=$random_name.'_album_image.'.$extension;
    $uploadSuccess = Input::file('image')->move($destinationPath, $filename);
    Image::create(array(
      'description' => Input::get('description'),
      'image' => $filename,
      'album_id'=> Input::get('album_id')
    ));

    return Redirect::route('show_album',array('id'=>Input::get('album_id')));
  }
  public function getDelete($id)
  {
    $image = Image::find($id);
    $image->delete();
    return Redirect::route('show_album',array('id'=>$image->album_id));
  }
}
```

控制器有三个函数；第一个是`getForm()`函数。这个函数基本上显示了我们的照片上传表单。第二个函数验证并将数据插入数据库。我们将在下一节中解释验证和插入函数。第三个是`getDelete()`函数。这个函数基本上从数据库中删除图像记录。

## 验证照片

Laravel 拥有强大的验证库，在本书中已经多次提到。我们在控制器中验证数据如下：

```php
$rules = array(

  'album_id' => 'required|numeric|exists:albums,id',
  'image'=>'required|image'

);

$validator = Validator::make(Input::all(), $rules);
if($validator->fails()){

  return Redirect::route('add_image',array('id' =>Input::get('album_id')))
  ->withErrors($validator)
  ->withInput();
}
```

让我们来看一下代码。我们在`array`中定义了一些规则。在`rules`数组中有两个验证规则。第一个规则如下：

```php
'album_id' => 'required|numeric|exists:albums,id'
```

前面的规则意味着`album_id`字段是必需的（必须在表单中发布），必须是数值，并且必须存在于`albums`表的`id`列中，因为我们想要将图片分配给`albums`。第二条规则如下：

```php
'image'=>'required|image'
```

前面的规则意味着`image`字段是必需的（必须在表单中发布），其内容必须是图片。然后我们使用以下代码检查发布的表单数据：

```php
$validator = Validator::make(Input::all(), $rules);
```

验证函数需要两个变量。第一个是我们需要验证的数据。在这种情况下，我们使用`Input::all()`方法进行设置，这意味着我们需要验证发布的表单数据。第二个是`rules`变量。`rules`变量必须设置为一个数组，如下所示：

```php
$rules = array(

  'album_id' => 'required|numeric|exists:albums,id',
  'image'=>'required|image'

);
```

Laravel 的验证类带有许多预定义规则。您可以在[`laravel.com/docs/validation#available-validation-rules`](http://laravel.com/docs/validation#available-validation-rules)上看到所有可用验证规则的更新列表。

有时，我们需要验证特定的 MIME 类型，例如`JPEG、BMP、ORG 和 PNG`。您可以轻松地设置此类验证的验证规则，如下所示：

```php
'image' =>'required|mimes:jpeg,bmp,png'
```

然后我们使用以下代码检查验证过程：

```php
if($validator->fails()){

  return Redirect::route('add_image',array('id' =>Input::get('album_id')))
  ->withErrors($validator)
  ->withInput();
}
```

如果验证失败，我们将浏览器重定向到图片上传表单。然后，我们使用以下代码在模板文件中显示规则：

```php
@if($errors->has())
  <div class="alert alert-block alert-error fade in"id="error-block">
    <?php
    $messages = $errors->all('<li>:message</li>');
    ?>
    <button type="button" class="close"data-dismiss="alert">×</button>

    <h4>Warning!</h4>
    <ul>
      @foreach($messages as $message)
        {{$message}}
      @endforeach

    </ul>
  </div>
@endif
```

## 将照片分配给相册

`postAdd()`函数用于处理请求，在数据库中创建新的图片记录。我们使用以下先前提到的方法获取作者的 ID：

```php
Auth::user()->id
```

使用以下方法，我们将当前用户与博客文章进行关联。我们在查询中有一个新的方法，如下所示：

```php
Posts::with('Author')->…
```

我们在相册模型中定义了一个`public Photos()`函数，使用以下代码：

```php
public function Photos(){

  return $this->hasMany('images','album_id');
}
```

`hasMany()`方法是一个用于创建表之间关系的 Eloquent 函数。基本上，该函数有一个`required`变量和一个可选变量。第一个变量（`required`）用于定义目标模型。第二个可选变量用于定义当前模型表的源列。在这种情况下，我们将相册的 ID 存储在`images`表的`album_id`列中。因此，我们需要在函数中将第二个变量定义为`album_id`。如果您的 ID 不遵循约定，则第二个参数是必需的。使用这种方法，我们可以同时将相册信息和分配的图片数据传递给模板。

正如您在第四章*构建个人博客*中所记得的，我们可以在`foreach`循环中列出关系数据。让我们快速查看一下我们模板文件中的图像列表部分的代码，该文件位于`app/views/album.blade.php`中：

```php
@foreach($album->Photos as $photo)

  <div class="col-lg-3">
    <div class="thumbnail" style="max-height: 350px;min-height: 350px;">
    <img alt="{{$album->name}}" src="/albums/{{$photo->image}}">
      <div class="caption">
        <p>{{$photo->description}}</p>
        <p><p>Created date:  {{ date("d F Y",strtotime($photo->created_at)) }} at {{ date("g:ha",strtotime($photo->created_at)) }}</p></p>
        <a href="{{URL::route('delete_image',array('id'=>$photo->id))}}" onclick="return confirm('Are yousure?')"><button type="button" class="btnbtn-danger btn-small">Delete Image</button></a>
      </div>
    </div>
  </div>

@endforeach
```

# 在相册之间移动照片

在相册之间移动照片是管理相册图像的一个很好的功能。许多相册系统都具有此功能。因此，我们可以使用 Laravel 轻松编写它。我们需要一个表单和控制器函数来将此功能添加到我们的相册系统中。让我们首先编写控制器函数。打开位于`app/controllers/`中的`ImagesController.php`文件，并在其中添加以下代码：

```php
public function postMove()
{
  $rules = array(

    'new_album' => 'required|numeric|exists:albums,id',
    'photo'=>'required|numeric|exists:images,id'

  );

  $validator = Validator::make(Input::all(), $rules);
  if($validator->fails()){

    return Redirect::route('index');
  }
  $image = Image::find(Input::get('photo'));
  $image->album_id = Input::get('new_album');
  $image->save();
  return Redirect::route('show_album',array('id'=>Input::get('new_album')));
}
```

如您在前面的代码中所看到的，我们再次使用`Validation`类。让我们检查规则。第一个规则如下：

```php
'new_album' => 'required|numeric|exists:albums,id'
```

前面的规则意味着`new_album`字段是`required`（必须在表单中发布），必须是数值，并且存在于`albums`表的`id`列中。我们想要将图片分配给相册，所以图片必须存在。第二条规则如下：

```php
'photo'=>'required|numeric|exists:images,id'
```

前面的规则意味着`photo`字段是`required`（必须在表单中发布），必须是数值，并且存在于`images`表的`id`列中。

成功验证后，我们会更新`photos`字段的`album_id`列，并使用以下代码将浏览器重定向到显示新相册照片的页面：

```php
$image = Image::find(Input::get('photo'));
$image->album_id = Input::get('new_album');
$image->save();
return Redirect::route('show_album',array('id'=>Input::get('new_album')));
```

`Images`控制器的最终代码应如下所示：

```php
<?php

class ImagesController extends BaseController{

  public function getForm($id)
  {
    $album = Album::find($id);

    return View::make('addimage')
    ->with('album',$album);
  }

  public function postAdd()
  {
    $rules = array(

      'album_id' => 'required|numeric|exists:albums,id',
      'image'=>'required|image'

    );

    $validator = Validator::make(Input::all(), $rules);
    if($validator->fails()){

      return Redirect::route('add_image',array('id' =>Input::get('album_id')))
      ->withErrors($validator)
      ->withInput();
    }

    $file = Input::file('image');
    $random_name = str_random(8);
    $destinationPath = 'albums/';
    $extension = $file->getClientOriginalExtension();
    $filename=$random_name.'_album_image.'.$extension;
    $uploadSuccess = Input::file('image')->move($destinationPath, $filename);
    Image::create(array(
      'description' => Input::get('description'),
      'image' => $filename,
      'album_id'=> Input::get('album_id')
    ));

    return Redirect::route('show_album',array('id'=>Input::get('album_id')));
  }
  public function getDelete($id)
  {
    $image = Image::find($id);

    $image->delete();

    return Redirect::route('show_album',array('id'=>$image->album_id));
  }
  public function postMove()
  {
    $rules = array(
      'new_album' => 'required|numeric|exists:albums,id',
      'photo'=>'required|numeric|exists:images,id'
    );
    $validator = Validator::make(Input::all(), $rules);
    if($validator->fails()){

      return Redirect::route('index');
    }
    $image = Image::find(Input::get('photo'));
    $image->album_id = Input::get('new_album');
    $image->save();
    return Redirect::route('show_album',array('id'=>Input::get('new_album')));
  }
}
```

我们的控制器已经准备好了，所以我们需要在`app/routes.php`中设置更新后的表单路由。打开文件并添加以下代码：

```php
Route::post('/moveimage', array('as' => 'move_image', 'uses' => 'ImagesController@postMove'));
```

`app/routes.php`中的最终代码应如下所示：

```php
<?php
Route::get('/', array('as' => 'index', 'uses' =>
  'AlbumsController@getList'));
Route::get('/createalbum', array('as' => 'create_album_form',
  'uses' => 'AlbumsController@getForm'));
Route::post('/createalbum', array('as' => 'create_album',
  'uses' => 'AlbumsController@postCreate'));
Route::get('/deletealbum/{id}', array('as' => 'delete_album',
  'uses' => 'AlbumsController@getDelete'));
Route::get('/album/{id}', array('as' => 'show_album', 'uses' =>
  'AlbumsController@getAlbum'));
Route::get('/addimage/{id}', array('as' => 'add_image', 'uses' =>
  'ImagesController@getForm'));
Route::post('/addimage', array('as' => 'add_image_to_album',
  'uses' => 'ImagesController@postAdd'));
Route::get('/deleteimage/{id}', array('as' => 'delete_image',
'uses' => 'ImagesController@getDelete'));
Route::post('/moveimage', array('as' => 'move_image',
'uses' => 'ImagesController@postMove'));
```

## 创建更新表单

现在我们需要在模板文件中创建更新表单。打开位于`app/views/album.blade.php`中的模板文件，并将`foreach`循环更改如下：

```php
@foreach($album->Photos as $photo)
  <div class="col-lg-3">
    <div class="thumbnail" style="max-height: 350px;min-height: 350px;">
      <img alt="{{$album->name}}" src="/albums/{{$photo->image}}">
      <div class="caption">
        <p>{{$photo->description}}</p>
        <p>Created date:  {{ date("d F Y",strtotime($photo->created_at)) }}at {{ date("g:ha",strtotime($photo->created_at)) }}</p>
        <a href="{{URL::route('delete_image',array('id'=>$photo->id))}}" onclick="returnconfirm('Are you sure?')"><button type="button"class="btn btn-danger btn-small">Delete Image</button></a>
        <p>Move image to another Album :</p>
        <form name="movephoto" method="POST"action="{{URL::route('move_image')}}">
          <select name="new_album">
            @foreach($albums as $others)
              <option value="{{$others->id}}">{{$others->name}}</option>
            @endforeach
          </select>
          <input type="hidden" name="photo"value="{{$photo->id}}" />
          <button type="submit" class="btn btn-smallbtn-info" onclick="return confirm('Are you sure?')">Move Image</button>
        </form>
      </div>
    </div>
  </div>
@endforeach
```

# 摘要

在本章中，我们使用 Laravel 的内置函数和 Eloquent 数据库驱动创建了一个简单的相册系统。我们学会了如何验证数据，以及 Eloquent 中强大的数据关联方法 hasMany。在接下来的章节中，我们将学习如何处理更复杂的表格和关联数据以及关联类型。


# 第七章：创建一个通讯系统

在本章中，我们将介绍一个高级的通讯系统，它将使用 Laravel 的`queue`和`email`库。在本节之后，我们将学习如何设置和触发排队任务，以及如何解析电子邮件模板并向订阅者发送大量电子邮件。本章涵盖的主题有：

+   创建一个数据库并迁移订阅者的表

+   创建一个订阅者模型

+   创建我们的订阅表单

+   验证和处理表单

+   创建一个处理电子邮件的队列系统

+   使用 Email 类来处理队列中的电子邮件

+   测试系统

+   直接使用队列发送电子邮件

在本章中，我们将使用第三方服务，这将需要访问你的脚本，所以在继续之前，请确保你的项目可以在线访问。

# 创建一个数据库并迁移订阅者表

成功安装 Laravel 4 并从`app/config/database.php`中定义数据库凭据后，创建一个名为`chapter7`的数据库。

创建数据库后，打开你的终端，导航到你的项目文件夹，并运行以下命令：

```php
**php artisan migrate:make create_subscribers_table --table=subscribers –-create**

```

上述命令将为我们生成一个名为`subscribers`的新 MySQL 迁移。现在转到`app/database/`中的`migrations`文件夹，并打开刚刚由上述命令创建的迁移文件，并按照下面的代码更改其内容：

```php
<?php
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class CreateSubscribersTable extends Migration {

  /**
   * Run the migrations.
   *
   * @return void
   */
  public function up()
  {
    Schema::create('subscribers', function(Blueprint $table)
    {
      $table->increments('id');
      $table->string('email,100)->default('');
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
    Schema::drop('subscribers');
  }
}
```

对于本章，我们只需要`email`列，它将保存订阅者的电子邮件地址。我将这一列设置为最多 100 个字符长，数据类型为`VARCHAR`，并且不允许为空。

保存文件后，运行以下命令执行迁移：

```php
**php artisan migrate**

```

如果没有发生错误，你已经准备好进行项目的下一步了。

# 创建一个订阅者模型

为了从 Eloquent ORM 中受益，最佳实践是创建一个模型。

将以下代码保存在`app/models/`下的`subscribers.php`文件中：

```php
<?php
Class Subscribers Extends Eloquent{
  protected $table = 'subscribers';
  protected $fillable = array('email');
}
```

我们使用变量`$table`设置表名，并使用变量`$fillable`设置用户必须填写值的列。现在我们的模型已经准备好了，我们可以继续下一步，开始创建我们的控制器和表单。

# 创建我们的订阅表单

现在我们应该创建一个表单来保存记录到数据库并指定它的属性。

1.  首先，打开你的终端，输入以下命令：

```php
php artisan controller:make SubscribersController
```

这个命令将为你在`app/controllers`目录中生成一个`SubscribersController.php`文件，并在其中添加一些空方法。

### 注意

`artisan`命令生成的默认控制器方法不是 RESTful 的。

1.  现在，打开`app/routes.php`并添加以下代码：

```php
//We define a RESTful controller and all its via route//directly
Route::controller('subscribers', 'SubscribersController');
```

我们可以使用`controller()`方法一次性定义控制器上声明的所有操作，而不是逐个定义所有操作。如果你的方法名可以直接用作`get`或`post`操作，使用`controller()`方法可以节省大量时间。第一个参数设置控制器的**URI**（统一资源标识符），第二个参数定义了控制器文件夹中将要访问和定义的类。

### 注意

像这样设置的控制器自动是 RESTful 的。

1.  现在，让我们创建表单的控制器。删除自动生成的类中的所有方法，并在你的控制器文件中添加以下代码：

```php
//The method to show the form to add a new feed
public function getIndex() {
  //We load a view directly and return it to be served
  return View::make('subscribe_form');
}
```

首先，我们定义了这个过程。这里很简单；我们将方法命名为`getCreate()`，因为我们希望我们的`Create`方法是 RESTful 的。我们简单地加载了一个视图文件，我们将在下一步直接生成。

1.  现在让我们创建我们的视图文件。在这个例子中，我使用了 jQuery 的 Ajax POST 技术。将这个文件保存为`subscribe_form.blade.php`，放在`app/views/`下：

```php
<!doctype html>
<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8">
    <title>Subscribe to Newsletter</title>
    <style>
      /*Some Little Minor CSS to tidy up the form*/
      body{margin:0;font-family:Arial,Tahoma,sans-serif;text-align:center;padding-top:60px;color:#666;font-size:24px}
      input{font-size:18px}
      input[type=text]{width:300px}
      div.content{padding-top:24px;font-weight:700;font-size:24px}
      .success{color:#0b0}
      .error{color:#b00}
    </style>
  </head>
  <body>

    {{-- Form Starts Here --}}
    {{Form::open(array('url'=> URL::to('subscribers/submit'),'method' => 'post'))}}
    <p>Simple Newsletter Subscription</p>
    {{Form::text('email',null,array('placeholder'=>'Type your E-mail address here'))}}
    {{Form::submit('Submit!')}}

    {{Form::close()}}
    {{-- Form Ends Here --}}

    {{-- This div will show the ajax response --}}
    <div class="content"></div>
    {{-- Because it'll be sent over AJAX, We add thejQuery source --}}
    {{ HTML::script('http://code.jquery.com/jquery-1.8.3.min.js') }}
    <script type="text/javascript">
      //Even though it's on footer, I just like to make//sure that DOM is ready
      $(function(){
        //We hide de the result div on start
        $('div.content').hide();
        //This part is more jQuery Related. In short, we //make an Ajax post request and get the response//back from server
        $('input[type="submit"]').click(function(e){
          e.preventDefault();
          $.post('/subscribers/submit', {
            email: $('input[name="email"]').val()
          }, function($data){
            if($data=='1') {
              $('div.content').hide().removeClass('success error').addClass('success').html('You\'ve successfully subscribed to ournewsletter').fadeIn('fast');
            } else {
              //This part echos our form validation errors
              $('div.content').hide().removeClass('success error').addClass('error').html('There has been an error occurred:<br /><br />'+$data).fadeIn('fast');
            }
          });
        });
        //We prevented to submit by pressing enter or anyother way
        $('form').submit(function(e){
          e.preventDefault();
          $('input[type="submit"]').click();
        });
      });
    </script>
  </body>
</html>
```

上述代码将生成一个简单的表单，如下截图所示：

![创建我们的订阅表单](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrv-app-dev-bp/img/2111_07_01.jpg)

现在我们的表单已经准备好了，我们可以继续并处理表单。

# 验证和处理表单

现在我们有了表单，我们需要验证和存储数据。我们还需要检查请求是否是 Ajax 请求。此外，我们需要使用 Ajax 方法将成功的代码或错误消息返回到表单，以便最终用户可以理解后端发生了什么。

将数据保存在`SubscribersController.php`中的`app/controllers/`：

```php
//This method is to process the form
public function postSubmit() {

  //we check if it's really an AJAX request
  if(Request::ajax()) {

    $validation = Validator::make(Input::all(), array(
      //email field should be required, should be in an email//format, and should be unique
      'email' => 'required|email|unique:subscribers,email'
    )
    );

    if($validation->fails()) {
      return $validation->errors()->first();
    } else {

      $create = Subscribers::create(array(
        'email' => Input::get('email')
      ));

      //If successful, we will be returning the '1' so the form//understands it's successful
      //or if we encountered an unsuccessful creation attempt,return its info
      return $create?'1':'We could not save your address to oursystem, please try again later';
    }

  } else {
    return Redirect::to('subscribers');
  }
}
```

以下几点解释了前面的代码：

1.  使用`Request`类的`ajax()`方法，你可以检查请求是否是 Ajax 请求。如果不是 Ajax 请求，我们将被重定向回我们的订阅者页面（表单本身）。

1.  如果是有效的请求，那么我们将使用`Validation`类的`make()`方法运行我们的表单。在这个例子中，我直接编写了规则，但最佳实践是在模型中设置它们，并直接调用它们到控制器。规则`required`检查字段是否已填写。规则`email`检查输入是否是有效的电子邮件格式，最后，规则`unique`帮助我们知道值是否已经在行中或不在。

1.  如果表单验证失败，我们直接返回第一个错误消息。返回的内容将是 Ajax 的响应，将被回显到我们的表单页面中。由于错误消息是自动生成的有意义的文本消息，所以可以直接在我们的示例中使用。这条消息将显示所有验证错误。例如，它将回显字段是否不是有效的电子邮件地址，或者电子邮件是否已经提交到数据库中。

1.  如果表单验证通过，我们尝试使用 Laravel 的 Eloquent ORM 的`create()`方法将电子邮件添加到我们的数据库中。

# 为基本的电子邮件发送创建一个队列系统

Laravel 4 中的队列是该框架提供的最好的功能之一。想象一下你有一个长时间的过程，比如调整所有图片的大小，发送大量电子邮件，或者大量数据库操作。当你处理这些时，它们会花费时间。那么为什么我们要等待呢？相反，我们将把这些过程放入队列中。使用 Laravel v4，这是相当容易管理的。在本节中，我们将创建一个简单的队列，并循环遍历电子邮件，尝试向每个订阅者发送电子邮件，使用以下步骤：

1.  首先，我们需要一个队列驱动程序。这可以是**Amazon SQS**、**Beanstalkd**或**Iron IO**。我选择了 Iron IO，因为它目前是唯一支持 push 队列的队列驱动程序。然后我们需要从 packagist 获取包。将`"iron-io/iron_mq": "dev-master"`添加到`composer.json`的`require`键中。它应该看起来像以下代码：

```php
"require": {
     "laravel/framework": "4.0.*",
     "iron-io/iron_mq": "dev-master"
},
```

1.  现在，你应该运行以下命令来更新/下载新的包：

```php
**php composer.phar update**

```

1.  我们需要一个来自 Laravel 官方支持的队列服务的账户。在这个例子中，我将使用免费的**Iron.io**服务。

1.  首先，注册网站[`iron.io`](http://iron.io)。

1.  其次，在登录后，创建一个名为`laravel`的项目。

1.  然后，点击你的项目。有一个关键图标，会给你项目的凭据。点击它，它会提供给你`project_id`和`token`。

1.  现在导航到`app/config/queue.php`，并将默认的键驱动更改为 iron。

在我们打开的`queue`文件中，有一个名为`iron`的键，你将使用它来填写凭据。在那里提供你的`token`和`project_id`信息，对于`queue`键，输入`laravel`。

1.  现在，打开你的终端并输入以下命令：

```php
**php artisan queue:subscribe laravel
  http://your-site-url/queue/push**

```

1.  如果一切顺利，你将得到以下输出：

```php
**Queue subscriber added: http://your-site-url/queue/push**

```

1.  现在，当你在 Iron.io 项目页面上检查队列标签时，你会看到一个由 Laravel 生成的新的`push`队列。因为它是一个 push 队列，当队列到达时间时，队列会调用我们。

1.  现在我们需要一些方法来捕获`push`请求，对其进行编组并触发它。

1.  首先，我们需要一个`get`方法来触发`push`队列（模拟触发队列的代码）。

将以下代码添加到`app`文件夹中的`routes.php`文件中：

```php
       //This code will trigger the push request
       Route::get('queue/process',function(){
         Queue::push('SendEmail');
         return 'Queue Processed Successfully!';
       });
```

这段代码将向一个名为`SendEmail`的类发出`push`请求，我们将在后续步骤中创建该类。

1.  现在我们需要一个监听器来管理队列。将以下代码添加到`app`文件夹中的`routes.php`文件中：

```php
//When the push driver sends us back, we will have to
  //marshal and process the queue.
Route::post('queue/push',function(){
  return Queue::marshal();
});
```

这段代码将从我们的队列驱动程序获取`push`请求，然后将其放入队列并运行。

我们需要一个类来启动队列并发送电子邮件，但首先我们需要一个电子邮件模板。将代码保存为`test.blade.php`，并保存在`app/views/emails/`目录中：

```php
       <!DOCTYPE html>
       <html lang="en-US">
         <head>
           <meta charset="utf-8">
         </head>
         <body>
           <h2>Welcome to our newsletter</h2>
           <div>Hello {{$email}}, this is our test message fromour Awesome Laravel queue system.</div>
         /body>
       </html>
```

这是一个简单的电子邮件模板，将包装我们的电子邮件。

1.  现在我们需要一个类来启动队列并发送电子邮件。将这些类文件直接保存到`app`文件夹中的`routes.php`文件中：

```php
       //When the queue is pushed and waiting to be marshalled, we should assign a Class to make the job done 
       Class SendEmail {

         public function fire($job,$data) {

           //We first get the all data from our subscribers//database
           $subscribers = Subscribers::all(); 

           foreach ($subscribers as $each) {

             //Now we send an email to each subscriber
             Mail::send('emails.test',array('email'=>$each->email), function($message){

               $message->from('us@oursite.com', 'Our Name');

               $message->to($each->email);

             });
           }

           $job->delete();
         }
       }
```

我们在前面的代码中编写的`SendEmail`类将覆盖我们将分配的队列作业。`fire()`方法是 Laravel 自己的方法，用于处理队列事件。因此，当队列被管理时，`fire()`方法内的代码将运行。我们还可以在调用`Queue::push()`方法时将参数作为第二个参数传递给`job`。

借助 Eloquent ORM，我们使用`all()`方法从数据库中获取了所有订阅者方法，然后使用`foreach`循环遍历了所有记录。

在成功处理`job`之后，底部使用`delete()`方法，以便下一次队列调用时不会再次启动`job`。

在进一步深入代码之前，我们必须了解 Laravel 4 的新功能**Email 类**的基础知识。

# 使用 Email 类在队列内处理电子邮件

在进一步进行之前，我们需要确保我们的电子邮件凭据是正确的，并且我们已经正确设置了所有值。打开`app/config/`目录中的`mail.php`文件，并根据您的配置填写设置：

+   参数驱动程序设置要使用的电子邮件驱动程序；`mail`、`sendmail`和`smtp`是默认的邮件发送参数。

+   如果您正在使用`smtp`，您需要根据您的提供商填写`host`、`port`、`encryption`、`username`和`password`字段。

+   您还可以使用字段`from`设置默认的发件人地址，这样您就不必一遍又一遍地输入相同的地址。

+   如果您正在使用`sendmail`作为邮件发送驱动程序，您应该确保参数`sendmail`中的路径是正确的。否则，邮件将无法发送。

+   如果您仍在测试应用程序，或者您处于实时环境并希望测试更新而不会发送错误/未完成的电子邮件，您应该将`pretend`设置为`true`，这样它不会实际发送电子邮件，而是将它们保留在日志文件中供您调试。

当我们遍历所有记录时，我们使用了 Laravel 的新电子邮件发送器`Mail`类，它基于流行的组件`Swiftmailer`。

`Mail::send()`方法有三个主要参数：

+   第一个参数是电子邮件模板文件的路径，电子邮件将在其中包装

+   第二个参数是将发送到视图的变量

+   第三个参数是一个闭包函数，我们可以在其中设置标题`from`、`to`、`CC/BCC`和`attachments`

此外，您还可以使用`attach()`方法向电子邮件添加附件

# 测试系统

设置队列系统和`email`类之后，我们准备测试我们编写的代码：

1.  首先，确保数据库中有一些有效的电子邮件地址。

1.  现在通过浏览器导航并输入[`your-site-url/queue/process`](http://your-site-url/queue/process)。

1.  当您看到消息“队列已处理”时，这意味着队列已成功发送到我们的队列驱动程序。我想逐步描述这里发生的事情：

+   首先，我们使用包含`Queue::push()`的队列驱动程序进行 ping，并传递我们需要排队的参数和附加数据

+   然后，在队列驱动程序获取我们的响应后，它将向我们之前使用`queue:subscribe`artisan 命令设置的`queue`/`push`的 post 路由发出 post 请求

+   当我们的脚本从队列驱动程序接收到`push`请求时，它将调度并触发排队事件

+   触发后，类中的`fire()`方法将运行并执行我们分配给它的任务

1.  过一段时间，如果一切顺利，您将开始在收件箱中收到这些电子邮件。

# 直接使用队列发送电子邮件

在某些发送电子邮件的情况下，特别是如果我们正在使用第三方 SMTP，并且正在发送用户注册、验证电子邮件等，队列调用可能不是最佳解决方案，但如果我们可以在发送电子邮件时直接将其排队，那将是很好的。Laravel 的`Email`类也可以处理这个问题。如果我们使用相同的参数使用`Mail::queue()`而不是`Mail::send()`，则电子邮件发送将借助队列驱动程序完成，并且最终用户的响应时间将更快。

# 总结

在本章中，我们使用 Laravel 的`Form Builder`类和 jQuery 的 Ajax 提交方法创建了一个简单的新闻订阅表单。我们对表单进行了验证和处理，并将数据保存到数据库中。我们还学习了如何使用 Laravel 4 的`queue`类轻松排队长时间的处理过程。我们还介绍了使用 Laravel 4 进行电子邮件发送的基础知识。

在下一章中，我们将编写一个**问答**网站，该网站将具有分页系统、标签系统、第三方身份验证库、问题和答案投票系统、选择最佳答案的选项以及问题的搜索系统。


# 第八章：构建问答 Web 应用程序

在本章中，我们将创建一个问答 Web 应用程序。首先，我们将学习如何从 Laravel 中移除 public 段，以便能够使用一些共享主机解决方案。然后，我们将使用第三方扩展进行认证和访问权限处理。最后，我们将创建一个问题系统，允许评论和回答问题，一个标签系统，点赞和踩，以及选择最佳答案。我们将使用中间表来处理问题标签。我们还将在各个地方受益于 jQuery Ajax 请求。以下是本章将涉及的主题：

+   从 Laravel 4 中移除 public 段

+   安装 Sentry 2 和一个认证库，并设置访问权限

+   创建自定义过滤器

+   创建我们的注册和登录表单

+   创建我们的问题表和模型

+   使用一个中间表创建我们的标签表

+   创建和处理我们的问题表单

+   创建我们的问题列表页面

+   创建我们的问题页面

+   创建我们的答案表和资源

+   按标签搜索问题

# 从 Laravel 4 中移除 public 段

在一些现实情况下，你可能不得不坚持使用配置不良的共享 Web 主机解决方案，它们没有`www`、`public_html`或类似的文件夹。在这种情况下，你会想要从你的 Laravel 4 安装中移除 public 段。要移除这个 public 段，有一些简单的步骤要遵循：

1.  首先确保你有一个正在运行的 Laravel 4 实例。

1.  然后，将`public`文件夹中的所有内容移动到父文件夹中（其中包括`app`、`bootstrap`、`vendor`和其他文件夹），然后删除空的 public 文件夹。

1.  接下来，打开`index.php`文件（我们刚刚从 public 文件夹中移动过来），找到以下行：

```php
require __DIR__.'/../bootstrap/autoload.php';
```

用以下行替换上一行：

```php
require __DIR__.'/bootstrap/autoload.php';
```

1.  现在，在`index.php`文件中找到这行：

```php
$app = require_once __DIR__.'/../bootstrap/start.php';
```

用以下行替换上一行：

```php
$app = require_once __DIR__.'/bootstrap/start.php';
```

1.  现在，打开`bootstrap`文件夹下的`paths.php`文件，并找到这行：

```php
'public' => __DIR__.'/../public',
```

用以下行替换上一行：

```php
'public' => __DIR__.'/..',
```

1.  如果你使用虚拟主机，请不要忘记更改目录设置并重新启动你的 Web 服务器。

在前面的步骤中，我们首先将所有内容从`public`文件夹移动到`parent`文件夹，因为我们将不再使用`parent`段。然后我们修改了`index.php`文件，以识别`autoload.php`和`start.php`的正确路径，以便框架可以运行。如果一切顺利，当你刷新页面时不会看到任何问题，这意味着你已成功从 Laravel 4 安装中移除了 public 段。

### 注意

不要忘记，这种方法会使你的所有代码都可以在公共 Web 根目录中使用，这可能会给你的项目带来安全问题。在这种情况下，你应该避免使用这种方法，或者你应该找到一个更好的 Web 主机解决方案。

# 安装 Sentry 2 和一个认证库，并设置访问权限

在这一部分，我们将安装一个第三方库用于用户认证和访问权限，名为 Sentry 2，由**Cartalyst**提供。Cartalyst 是一个以开发者为中心的开源公司，专注于文档、社区支持和框架。在这一部分，我们将按照 Sentry 官方的 Laravel 4 安装步骤进行操作，还有一个简单的额外步骤，目前可以在[`docs.cartalyst.com/sentry-2/installation/laravel-4`](http://docs.cartalyst.com/sentry-2/installation/laravel-4)找到。

1.  首先，打开你的`composer.json`文件，并在`require`属性中添加以下行：

```php
"cartalyst/sentry": "2.0.*"
```

1.  然后，运行 composer update 命令来获取包：

```php
php composer.phar update
```

1.  现在，打开`app/config`下的`app.php`文件，并在`providers`数组中添加以下行：

```php
'Cartalyst\Sentry\SentryServiceProvider',
```

1.  现在，在`app.php`中的`aliases`数组中添加以下行：

```php
'Sentry' => 'Cartalyst\Sentry\Facades\Laravel\Sentry',
```

1.  现在，运行以下命令来安装所需的表（或用户）到数据库中：

```php
php artisan migrate --package=cartalyst/sentry
```

1.  接下来，我们需要将 Sentry 2 的配置文件发布到我们的`app`文件夹中，这样我们就可以管理节流或其他设置（如果需要的话）。从终端运行以下命令：

```php
php artisan config:publish cartalyst/sentry
```

1.  现在，我们应该修改默认的用户模型，以便能够在 Sentry 2 中使用它。打开`app/models`目录下的`User.php`文件，并用以下代码替换所有内容：

```php
<?php
class User extends Cartalyst\Sentry\Users\Eloquent\User {
}
```

1.  最后，我们应该创建我们的管理员用户。将以下代码添加到`app`文件夹下的`routes.php`文件中，并运行一次。之后注释或删除该代码。我们实际上为我们的系统分配了 ID=1 的管理员，具有名为`admin`的访问权限。

```php
/**
* This method is to create an admin once.
* Just run it once, and then remove or comment it out.
**/
Route::get('create_user',function(){

$user = Sentry::getUserProvider()->create(array(
  'email' => 'admin@admin.com',
  //password will be hashed upon creation by Sentry 2
  'password' => 'password',
  'first_name' => 'John',
  'last_name' => 'Doe',
  'activated' => 1,
  'permissions' => array (
    'admin' => 1
  )
));
return 'admin created with id of '.$user->id;
});
```

通过这样做，您已成功创建了一个以`admin@admin.com`作为电子邮件地址和`password`作为密码的用户。密码将在 Sentry 2 创建时自动进行哈希处理，因此我们无需在创建之前对密码进行哈希和盐处理。我们将管理员的名字设置为`John`，姓氏设置为`Doe`。此外，我们为刚刚生成的用户设置了一个名为`admin`的权限，以在请求处理之前检查访问权限。

您现在已经准备就绪。如果一切顺利，并且您检查您的数据库，您应该会看到由 Laravel 4 生成的迁移表（在 Laravel 3 中您必须在第一次迁移之前手动设置），以及由 Sentry 2 生成的表。在`users`表中，您应该会看到我们的闭包方法生成的用户条目。

现在我们的用户认证系统已经准备就绪，我们需要生成我们的过滤器，然后创建注册和登录表单。

# 创建自定义过滤器

自定义过滤器将帮助我们过滤请求，并在请求之前进行一些预检查。利用 Sentry 2 内置的方法，我们可以轻松定义自定义过滤器。但首先，我们需要定义一些在项目中将要使用的路由。

将以下代码添加到`app`文件夹下的`routes.php`文件中：

```php
//Auth Resource
Route::get('signup',array('as'=>'signup_form', 'before'=>
'is_guest', 'uses'=>'AuthController@getSignup'));
Route::post('signup',array('as'=>'signup_form_post', 'before' =>
'csrf|is_guest', 'uses' => 'AuthController@postSignup'));
Route::post('login',array('as'=>'login_post', 'before' =>
'csrf| is_guest', 'uses' => 'AuthController@postLogin'));
Route::get('logout',array('as'=>'logout', 'before'=>'
user', 'uses' => 'AuthController@getLogout'));
//---- Q & A Resources
Route::get('/',array('as'=>'index','uses'=>
'MainController@getIndex'));
```

在这些命名资源中，名称是在数组中用键`as`定义的，过滤器是用键`before`设置的。正如您所看到的，有一些`before`参数，比如`is_guest`和`user`。这些过滤器将在用户发出任何请求之前运行，甚至调用控制器。键`uses`设置了在调用资源时将执行的控制器。我们稍后将为这些控制器编写代码。因此，例如，用户甚至无法尝试提交登录表单。如果用户尝试这样做，我们的过滤器将在用户发出请求之前运行并进行过滤。

现在我们的路由已经准备就绪，我们可以添加过滤器。要添加过滤器，请打开`app`文件夹下的`filters.php`文件，并添加以下代码：

```php
/*
 |----------------------------------------------------------- 
 | Q&A Custom Filters
 |-----------------------------------------------------------
*/

Route::filter('user',function($route,$request){
  if(Sentry::check()) {
    //is logged in
  } else {
    return Redirect::route('index')
      ->with('error','You need to log in first');
  }
});

Route::filter('is_guest',function($route,$request){
  if(!Sentry::check()) {
    //is a guest
  } else {
    return Redirect::route('index')
      ->with('error','You are already logged in');
  }
});

Route::filter('access_check',function($route,$request,$right){
  if(Sentry::check()) {
    if(Sentry::getUser()->hasAccess($right)) {
      //logged in and can access
    } else {
      return Redirect::route('index')
        ->with('error','You don\'t have enough priviliges to access that page');
    }
  } else {
    return Redirect::route('index')
      ->with('error','You need to log in first');
  }
});
```

`Route::filter()`方法允许我们创建自己的过滤器。第一个参数是过滤器的名称，第二个参数是一个闭包函数，它本身至少需要两个参数。如果需要向过滤器提供参数，可以将其添加为第三个参数。

Sentry 2 的`check()`辅助函数返回一个布尔值，用于判断用户是否已登录。如果返回 true，表示用户已登录，否则正在浏览网页的用户尚未登录。在我们的自定义过滤器`user`和`is_guest`中，我们正是在检查这一点。您的过滤器的通过条件可以留空。但如果用户未满足过滤器的条件，可以采取适当的行动。在我们的示例中，我们将用户重定向到我们的`index`路由。

然而，我们的第三个过滤器`access_check`有点复杂。正如你所看到的，我们添加了一个名为`$right`的第三个参数，我们将通过调用过滤器传递它。这个过滤器检查两个条件。首先，它使用`Sentry::check()`方法检查用户是否已登录。然后，它使用`hasAccess()`方法检查用户是否有访问`$right`部分的权限（我们将在定义过滤器时看到）。但是这个方法首先需要一个当前登录的用户。为此，我们将使用 Sentry 2 的`getUser()`方法验证当前用户的信息。

在调用过滤器时传递参数，可以使用`filter_name:parameter1, parameter2`。在我们的示例中，我们将使用过滤器`access_check:admin`来检查用户是否是管理员。

在`before`参数中使用多个过滤器，可以在参数之间添加`|`字符。在我们的示例中，我们的登录提交和注册资源的过滤器被定义为`csrf|guest`（csrf 在 Laravel 的`filters.php`文件中是预定义的）。

# 创建我们的注册和登录表单

在创建我们的注册和登录表单之前，我们需要一个模板来设置这些部分。我将使用我为本章生成的自定义 HTML/CSS 模板，这个模板受到开源问答脚本**Question2Answer**的**Snow**主题的启发。

我们执行以下步骤来创建我们的注册和登录表单：

1.  首先，将提供的示例代码中`assets`文件夹中的所有内容复制到项目文件夹的根目录（`app`、`bootstrap`和其他文件夹所在的位置），因为我们在本章的第一节中删除了 public 文件夹部分。

1.  接下来，在`app/views`下的`template_masterpage.blade.php`文件中添加以下代码：

```php
<!DOCTYPE html>
<!--[if lt IE 7]> <html class="no-js lt-ie9 lt-ie8 lt-ie7">
<![endif]-->
<!--[if IE 7]> <html class="no-js lt-ie9 lt-ie8">
<![endif]-->
<!--[if IE 8]> <html class="no-js lt-ie9">
<![endif]-->
<!--[if gt IE 8]><!--> <html class="no-js">
<!--<![endif]-->

<head>
  <meta charset="utf-8" />
  <title>{{isset($title)?$title.' | ':''}} LARAVEL Q & A
  </title>
  {{ HTML::style('assets/css/style.css') }}
</head>
<body>

  {{-- We include the top menu view here --}}
  @include('template.topmenu')

  <div class="centerfix" id="header">
  <div class="centercontent">
    <a href="{{URL::route('index')}}">
      {{HTML::image('assets/img/header/logo.png')}}
    </a>
  </div>
  </div>
  <div class="centerfix" id="main" role="main">
  <div class="centercontent clearfix">
    <div id="contentblock">

    {{-- Showing the Error and Success Messages--}}
    @if(Session::has('error'))
    <div class="warningx wredy">
      {{Session::get('error')}}
    </div>
    @endif

    @if(Session::has('success'))
    <div class="warningx wgreeny">
      {{Session::get('success')}}
    </div>
    @endif

    {{-- Content section of the template --}}
    @yield('content')
    </div>
  </div>
  </div>
  {{-- JavaScript Files --}}
  {{ HTML::script('assets/js/libs.js') }}
  {{ HTML::script('assets/js/plugins.js') }}
  {{ HTML::script('assets/js/script.js') }}

  {{-- Each page's custom assets (if available) will be yielded here --}}
  @yield('footer_assets')

</body>
</html>
```

现在，让我们来看代码：

+   如果我们使用`title`属性加载视图，`<title>`标签将包含标题；否则它将只显示我们网站的名称。

+   `HTML`类的`style()`方法将帮助我们轻松地向我们的模板添加 CSS 文件。此外，`HTML`类的`script()`方法允许我们向输出的 HTML 文件添加 JavaScript。

+   我们使用 Blade 模板引擎的`@include()`方法将另一个文件包含到我们的`template_masterpage.blade.php`文件中。我们将在下一步中描述它的部分。

+   `URL`类的`route()`方法将返回一个命名路由的链接。这实际上非常方便，因为如果我们更改 URL 结构，我们不需要深入所有模板文件并编辑所有链接。

+   `HTML`类的`image()`方法允许我们向我们的模板添加`<img>`标签。

+   在过滤器中，我们使用`with()`方法和参数`error`重定向到路由页面。如果我们使用`with()`加载页面（`View::make()`），参数将是变量。但是因为我们已经将用户重定向到一个页面，通过`with()`传递的这些参数将是会话 flashdata，只能使用一次。为了检查这些会话是否设置，我们使用`Session`类的`has()`方法。`Session::has('sessionName')`将返回一个布尔值，以确定会话是否设置。如果设置了，我们可以使用`Session`类的`get()`方法在视图、控制器和其他地方使用它。

+   Blade 模板引擎的`@yield()`方法获取`@section()`中的数据，并将其解析到主模板页面。

1.  在上一节中，我们通过调用`@include()`方法包含了另一个视图，如`@include('template.topmenu')`。现在将以下代码保存为`topmenu.blade.php`，放在`app/views/template`下：

```php
{{-- Top error (about login etc.) --}}
@if(Session::has('topError'))
  <div class="centerfix" id="infobar">
    <div class="centercontent">{{ Session::get('topError') }}
    </div>
  </div>
@endif

{{-- Check if a user is logged in, login and logout has different templates --}}
@if(!Sentry::check())
<div class="centerfix" id="login">
  <div class="centercontent">
    {{Form::open(array('route'=>'login_post'))}}
    {{Form::email('email', Input::old('email'), array('placeholder'=>'E-mail Address'))}}
    {{Form::password('password', array('placeholder' => 'Password'))}}
    {{Form::submit('Log in!')}}
    {{Form::close()}}

    {{HTML::link('signup_form','Register',array(),array('class'=>'wybutton'))}}
  </div>
</div>
@else
  <div class="centerfix" id="login">
    <div class="centercontent">
      <div id="userblock">Hello again, {{HTML::link('#',Sentry::getUser()->first_name.' '.Sentry::getUser()->last_name)}}</div>
      {{HTML::linkRoute('logout','Logout',array(),array('class'=>'wybutton'))}}
    </div>
  </div>
@endif
```

现在，让我们来看代码：

+   在我们的模板中，有两个错误消息，其中第一个完全保留给将在顶部显示的登录区域。我将其命名为`error_top`。使用我们刚学到的`has()`和`get()`方法，我们检查是否存在错误，并显示它。

+   顶部菜单将取决于用户是否已登录。因此，我们使用 Sentry 2 的用户检查方法`check()`创建一个`if`子句来检查用户是否已登录。如果用户未登录（访客），我们将显示使用`Form`类制作的登录表单，否则我们将显示用户`infobar`，其中包含个人资料和**注销**按钮。

1.  现在，我们需要一个注册表单页面。我们之前已经在`app`文件夹下的`routes.php`文件中定义了它的方法：

```php
//Auth Resource
Route::get('signup',array('as'=>'signup_form', 'before' => 'is_guest', 'uses' => 'AuthController@getSignup'));
Route::post('signup',array('as' => 'signup_form_post', 'before' => 'csrf|is_guest', 'uses' => 'AuthController@postSignup'));
```

1.  根据我们创建的路由资源，我们需要一个名为`AuthController`的控制器，其中包含两个名为`getSignup()`和`postSignup()`的方法。现在让我们首先创建控制器。打开你的终端并输入以下命令：

```php
**php artisan controller:make AuthController**

```

1.  上一个命令将在`app/controllers`文件夹下创建一个名为`AuthController.php`的新文件，并带有一些默认方法。删除`AuthController`类内的现有代码，并添加以下代码到该类内，以创建注册表单：

```php
/**
  * Signup GET method
**/
public function getSignup() {
  return View::make('qa.signup')
    ->with('title','Sign Up!');
}
```

1.  现在我们需要一个视图文件来制作表单。将以下代码保存为`signup.blade.php`，放在`app/views/qa`文件夹下：

```php
@extends('template_masterpage')

@section('content')
  <h1 id="replyh">Sign Up</h1>
  <p class="bluey">Please fill all the credentials correctly to register to our site</p>
  {{Form::open(array('route'=>'signup_form_post'))}}
    <p class="minihead">First Name:</p>
    {{Form::text('first_name',Input::get('first_name'),array('class'=>'fullinput'))}}
    <p class="minihead">Last Name:</p>
    {{Form::text('last_name',Input::get('last_name'),array('class'=>'fullinput'))}}<p class="minihead">E-mail address:</p>
    {{Form::email('email',Input::get('email'),array('class'=>'fullinput'))}}
    <p class="minihead">Password:</p>
    {{Form::password('password','',array('class'=>'fullinput'))}}
    <p class="minihead">Re-password:</p>
    {{Form::password('re_password','',array('class'=>'fullinput'))}}
    <p class="minihead">Your personal info will not be shared with any 3rd party companies.</p>
    {{Form::submit('Register now!')}}
  {{Form::close()}}
@stop
```

如果你已经正确完成了所有步骤，当你导航到`chapter8.dev/signup`时，你应该会看到以下表单：

![创建我们的注册和登录表单](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrv-app-dev-bp/img/2111OS_08_01.jpg)

## 验证和处理表单

现在，我们需要验证和处理表单。我们首先需要定义我们的验证规则。将以下代码添加到`app/models`文件夹下的`user.php`文件中的`User`类中：

```php
public static $signup_rules = array(
  'first_name' => 'required|min:2',
  'last_name' => 'required|min:2',
  'email' => 'required|email|unique:users,email',
  'password' => 'required|min:6',
  're_password' => 'required|same:password'
);
```

前面代码中提到的规则将使所有字段都为`required`。我们将`first_name`和`last_name`列设置为`required`，并设置最小长度为两个字符。我们将`email`字段设置为有效的电子邮件格式，并且代码将检查`users`表（在安装 Sentry 2 时创建）中的唯一电子邮件地址。我们将`password`字段设置为`required`，并且其长度应至少为六个字符。我们还将`re_password`字段设置为与`password`字段匹配，以确保密码输入正确。

### 注意

Sentry 2 也可以在尝试登录用户时抛出唯一电子邮件检查异常。

在处理表单之前，我们需要一个虚拟的索引页面来在成功注册后返回用户。我们将通过以下步骤创建一个临时的索引页面：

1.  首先，运行以下命令来创建一个新的控制器：

```php
**php artisan controller:make MainController**

```

1.  然后，删除所有自动插入的方法，并在类内添加以下方法：

```php
public function getIndex() {
  return View::make('qa.index');
}
```

1.  现在，将此视图文件保存为`index.blade.php`，放在`app/views/qa`文件夹下：

```php
@extends('template_masterpage')

@section('content')
Heya!
@stop
```

1.  现在，我们需要一个控制器方法（我们在`routes.php`中定义的）来处理`signup`表单的`post`请求。为此，将以下代码添加到`app/controllers`文件夹下的`AuthController.php`文件中：

```php
/**
  * Signup Post Method
**/
public function postSignup() {

  //Let's validate the form first
  $validation = Validator::make(Input::all(),User::$signup_rules);

  //let's check if the validation passed
  if($validation->passes()) {

    //Now let's create the user with Sentry 2's create method
    $user = Sentry::getUserProvider()->create(array(
      'email' => Input::get('email'),
      'password' => Input::get('password'),
      'first_name' => Input::get('first_name'),
      'last_name' => Input::get('last_name'),
      'activated' => 1
    ));

    //Since we don't use an email validation in this example, let's log the user in directly
    $login = Sentry::authenticate(array('email'=>Input::get('email'),'password'=>Input::get('password')));

    return Redirect::route('index')
      ->with('success','You\'ve signed up and logged in successfully!');
    //if the validation failed, let's return the user 
    //to the signup form with the first error message
  } else {
    return Redirect::route('signup_form')
    ->withInput(Input::except('password','re_password'))
      ->with('error',$validation->errors()->first());
  }
}
```

现在，让我们来看看代码：

1.  首先，我们使用 Laravel 内置的表单验证类来检查表单项，使用我们在模型中定义的规则。

1.  我们使用`passes()`方法来检查表单验证是否通过。我们也可以使用`fails()`方法来检查相反的情况。

如果验证失败，我们将使用`withInput()`将用户返回到**注册**表单，并使用`Input::except()`过滤一些列，如`password`和`re_password`，以便这些字段的值不会返回。此外，通过使用`with`传递参数，将返回表单验证的错误消息。`$validation->errors()->first()`在表单验证步骤后返回第一个错误消息字符串。

![验证和处理表单](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrv-app-dev-bp/img/2111OS_08_02.jpg)

如果验证通过，我们将使用提供的凭据创建一个新用户。我们将`activated`列设置为`1`，这样在我们的示例中注册过程不需要电子邮件验证。

### 注意

Sentry 2 还使用 try/catch 子句来捕获错误。不要忘记查看 Sentry 2 的文档，了解如何捕获异常错误。

1.  由于我们没有使用电子邮件验证系统，我们可以简单地使用 Sentry 2 的`authenticate()`方法对用户进行身份验证和登录，就在注册后。第一个参数接受一个`email`和`password`的数组（与`key => value`匹配），可选的第二个参数接受一个布尔值作为输入，以检查用户是否要被记住（`记住我`按钮）。

1.  身份验证后，我们只需将用户重定向到我们的`index`路由，并显示成功消息，如下图所示：

## 处理登录和注销请求

现在我们的注册系统已经准备好了，我们需要处理登录和注销请求。由于我们的登录表单已经准备好了，我们可以直接进行处理。要处理登录和注销请求，我们执行以下步骤：

1.  首先，我们需要登录表单验证规则。将以下代码添加到`app/models`目录下的`User.php`文件中：

```php
public static $login_rules = array(
	'email'		=> 'required|email|exists:users,email',
	'password'	=> 'required|min:6'
);
```

1.  现在，我们需要一个控制器方法来处理登录请求。在`app/controllers`目录下的`AuthController.php`文件中添加以下代码：

```php
/**
 * Login Post Method Resource
**/
public function postLogin() {
  //let's first validate the form:
  $validation = Validator::make(Input::all(),User::$login_rules);

  //if the validation fails, return to the index page with first error message
  if($validation->fails()) {
    return Redirect::route('index')
      ->withInput(Input::except('password'))
      ->with('topError',$validation->errors()->first());
  } else {

    //if everything looks okay, we try to authenticate the user
    try {

      // Set login credentials
      $credentials = array('email' => Input::get('email'),'password' => Input::get('password'),);

      // Try to authenticate the user, remember me is set to false
      $user = Sentry::authenticate($credentials, false);
      //if everything went okay, we redirect to index route with success message
      return Redirect::route('index')
        ->with('success','You\'ve successfully logged in!');
    } catch (Cartalyst\Sentry\Users\LoginRequiredException $e) {
      return Redirect::route('index')
        -> withInput(Input::except('password'))
        ->with('topError','Login field is required.');
    } catch (Cartalyst\Sentry\Users\PasswordRequiredException $e) {
      return Redirect::route('index')
        -> withInput(Input::except('password'))
        ->with('topError','Password field is required.');
    } catch (Cartalyst\Sentry\Users\WrongPasswordException $e) {
      return Redirect::route('index')
        -> withInput(Input::except('password'))
        ->with('topError','Wrong password, try again.');
    } catch (Cartalyst\Sentry\Users\UserNotFoundException $e) {
      return Redirect::route('index')
        -> withInput(Input::except('password'))
        ->with('topError','User was not found.');
    } catch (Cartalyst\Sentry\Users\UserNotActivatedException $e) {
      return Redirect::route('index')
        -> withInput(Input::except('password'))
        ->with('topError','User is not activated.');
    }

    // The following is only required if throttle is enabled
    catch (Cartalyst\Sentry\Throttling\UserSuspendedException $e) {
    return Redirect::route('index')
      -> withInput(Input::except('password'))
      ->with('topError','User is suspended.');
    } catch (Cartalyst\Sentry\Throttling\UserBannedException $e) {
      return Redirect::route('index')
        -> withInput(Input::except('password'))
        ->with('topError','User is banned.');
    }
  }
}
```

现在，让我们来看看代码：

1.  首先，我们使用 Laravel 内置的表单验证类检查表单项，使用我们在模型中定义的规则。

1.  然后，我们使用表单验证类的`fails()`方法检查表单验证是否失败。如果表单验证失败，我们将用户返回到`index`路由，并显示第一个表单验证错误。

1.  上面代码中的`else`子句包含了如果表单验证通过将要执行的事件。在这里，我们使用 Sentry 2 的 try/catch 子句对用户进行身份验证，捕获所有的异常，并根据异常的类型返回错误消息。

在我们的示例应用程序中，我们不需要所有的异常，但是作为一个示例，我们尝试展示所有的异常，以防您需要在跟进时做一些不同的事情。

### 注意

所有这些 try/catch 异常都在 Sentry 2 的网站上有记录。

1.  如果 Sentry 2 没有抛出任何异常，我们将返回到带有成功消息的索引页面。

1.  现在，关于身份验证，唯一剩下的事情就是注销按钮。要创建一个，将以下代码添加到`app/controllers`目录下的`AuthController.php`文件中：

```php
/**
  * Logout method 
**/
public function getLogout() {
  //we simply log out the user
  Sentry::logout();

  //then, we return to the index route with a success message
  return Redirect::route('index')
    ->with('success','You\'ve successfully signed out');
}
```

现在让我们来看看代码：

1.  首先，我们调用 Sentry 2 的`logout()`方法，将用户注销。

1.  然后，我们只需将当前是访客的用户重定向到`index`路由，并显示成功消息，告诉他们已成功注销。

现在我们的身份验证系统已经准备好了，我们准备创建我们的问题表。

# 创建我们的问题表和模型

现在我们有一个完全可用的身份验证系统，我们准备创建我们的`questions`表。为了创建我们的`questions`表，我们将使用数据库迁移。

要创建一个迁移，请在终端中运行以下命令：

```php
**php artisan migrate:make create_questions_table --table= questions --create**

```

上面的命令将在`app/database/migrations`下创建一个新的迁移。

对于问题，我们将需要一个问题标题，问题详情，问题的提问者，问题的日期，问题被查看的次数，投票的总和以及问题的标签。

现在，打开您刚刚创建的迁移，并用以下代码替换其内容：

```php
Schema::create('questions', function(Blueprint $table)
{
  //Question's ID
  $table->increments('id');
  //title of the question
  $table->string('title',400)->default('');
  //asker's id
  $table->integer('userID')->unsigned()->default(0);
  //question's details
  $table->text('question')->default('');
  //how many times it's been viewed:
  $table->integer('viewed')->unsigned()->default(0);
  //total number of votes:
  $table->integer('votes')->default(0);
  //Foreign key to match userID (asker's id) to users
  $table->foreign('userID')->references('id')->on('users')->onDelete('cascade');
  //we will get asking time from the created_at column
  $table->timestamps();
});
```

对于标签，我们将使用一个数据透视表，这就是为什么它们不在我们当前的模式中。对于投票，在这个例子中，我们只是持有一个整数（可以是正数或负数）。在现实世界的应用中，您会想要使用第二个数据透视表来保留用户的投票，以防止重复投票，并获得更准确的结果。

1.  现在您的模式已经准备好了，请使用以下命令运行迁移：

```php
**php artisan migrate**

```

1.  成功迁移模式后，我们现在需要一个模型来从 Eloquent 中受益。将以下代码保存为`Question.php`，放在`app/models`目录下：

```php
<?php

class Question extends Eloquent {

  protected $fillable = array('title', 'userID', 'question', 'viewed', 'answered', 'votes');

}
```

1.  现在，我们需要数据库关系来匹配表。首先，将以下代码添加到`app/models`文件夹下的`User.php`文件中：

```php
public function questions() {
  return $this->hasMany('Question','userID');
}
```

1.  接下来，将以下代码添加到`app/models`文件夹下的`Question.php`文件中：

```php
public function users() {
  return $this->belongsTo('User','userID');
}
```

由于用户可能有多个问题，我们在我们的`User`模型中使用了`hasMany()`方法来进行关联。同样，由于所有的问题都是用户拥有的，我们使用`belongsTo()`方法来将问题与用户匹配。在这些方法中，第一个参数是模型名称，在我们的例子中是`Question`和`User`。第二个参数是该模型中用来匹配表的列名，在我们的例子中是`userID`。

# 创建我们的标签表和枢轴表

首先，我们应该理解为什么我们需要标签的枢轴表。在现实世界的情况下，一个问题可能有多个标签；同样，一个标签可能有多个问题。在这种情况下（多对多关系），两个表都可能有多个相互匹配的情况，我们应该创建并使用第三个枢轴表。

1.  首先，我们应该使用架构创建一个新的标签表。打开您的终端并运行以下命令来创建我们的枢轴表架构：

```php
**php artisan migrate:make create_tags_table --table= tags --create**

```

1.  现在我们需要填充表的内容。在我们的例子中，我们只需要标签名称和标签的友好 URL 名称。用以下代码替换架构的`up`函数内容：

```php
Schema::create('tags', function(Blueprint $table)
{
  //id is needed to match pivot
  $table->increments('id');

  //Tag's name
  $table->string('tag')->default('');
  //Tag's URL-friendly name
  $table->string('tagFriendly')->unique();

  //I like to keep timestamps
  $table->timestamps();
});
```

我们有`id`列来匹配问题和枢轴表中的标签。我们有一个字符串字段`tag`，它将是标签的标题，列`tagFriendly`是将显示为 URL 的内容。我还保留了时间戳，这样，将来它可以为我们提供标签创建的信息。

1.  最后，在您的终端中运行以下命令来运行迁移并安装表：

```php
**php artisan migrate**

```

1.  现在，我们需要一个`tags`表的模型。将以下文件保存为`Tag.php`，放在`app/models`文件夹下：

```php
<?php

class Tag extends Eloquent {

  protected $fillable = array('tag', 'tagFriendly');

}
```

1.  现在，我们需要创建我们的枢轴表。作为一个良好的实践，它的名称应该是`modelname1_modelname2`，并且内容按字母顺序排序。在我们的例子中，我们有`questions`和`tags`表，所以我们将枢轴表的名称设置为`question_tags`（这不是强制的，您可以给您的枢轴表任何名称）。正如您可能猜到的那样，它的架构将有两列来匹配两个表和这两个列的外键。您甚至可以向枢轴表添加额外的列。

要创建迁移文件，请在终端中运行以下命令：

```php
**php artisan migrate:make create_question_tags_table --table=question_tags --create**

```

1.  现在，打开我们在`app/database`的`migrations`文件夹中生成的架构，并用以下代码修改其`up()`方法的内容：

```php
Schema::create('question_tags', function(Blueprint $table)
{
  $table->increments('id');

  $table->integer('question_id')->unsigned()->default(0);
  $table->integer('tag_id')->unsigned()->default(0);

  $table->foreign('question_id')->references('id')->on('questions')->onDelete('cascade');
  $table->foreign('tag_id')->references('id')->on('tags')->onDelete('cascade');

  $table->timestamps();
});
```

我们需要两列，其名称结构应为`modelname_id`。在我们的迁移中，它们是`question_id`和`tag_id`。此外，我们已经设置了外键来匹配它们在我们的数据库中。

1.  现在，运行迁移并安装表：

```php
**php artisan migrate**

```

1.  现在，我们需要添加方法来描述 Eloquent 我们正在使用一个枢轴表。将以下代码添加到`app/models`文件夹下的`Question.php`文件中：

```php
public function tags() {
  return $this->belongsToMany('Tag','question_tags')->withTimestamps();
}
```

描述枢轴信息到标签模型，将以下代码添加到`app/models`文件夹下的`Tag.php`文件中：

```php
public function questions() {
  return $this->belongsToMany('Question','question_tags')->withTimestamps();
}
```

`belongsToMany()`方法中的第一个参数是模型名称，第二个参数是枢轴表的名称。使用`withTimestamps()`（它为我们带来了枢轴数据的创建和更新日期）是可选的。此外，如果我们有一些额外的数据要添加到枢轴表中，我们可以使用`withPivot()`方法来调用它。考虑以下示例代码：

```php
$this->belongsToMany('Question ', 'question_tags')->withPivot('column1', 'column2')->withTimestamps();
```

现在我们的枢轴表结构准备好了，在后面的章节中，我们可以轻松地获取问题的标签和所有标记为`$tagname`的问题。

# 创建和处理我们的问题表单

现在我们的结构准备好了，我们可以继续创建和处理我们的问题表单。

## 创建我们的问题表单

我们执行以下步骤来创建我们的问题表单：

1.  首先，我们需要为问题表单创建一个新的路由资源。打开`app`文件夹中的`routes.php`文件，并添加以下代码：

```php
Route::get('ask',array('as'=>'ask', 'before'=>'user', 
   'uses' => 'QuestionsController@getNew'));

Route::post('ask',array('as'=>'ask_post', 
  'before'=>'user|csrf', 'uses' => 
  'QuestionsController@postNew'));
```

1.  现在我们的资源已经定义，我们需要将资源添加到顶部菜单以进行导航。打开`app/views/template`目录下的`topmenu.blade.php`文件，并找到以下行：

```php
{{HTML::linkRoute('logout','Logout',array(), array('class'=>'wybutton'))}}
```

在以下行的上方添加上述行：

```php
{{HTML::linkRoute('ask','Ask a Question!', array(), array('class'=>'wybutton'))}}
```

1.  现在，我们需要控制器文件来处理资源。在您的终端中运行以下命令：

```php
**php artisan controller:make QuestionsController**

```

1.  接下来，打开`app/controllers`目录下新创建的`QuestionsController.php`文件，并删除类中的所有方法。然后添加以下代码：

```php
/**
  * A new question asking form
**/
public function getNew() {
  return View::make('qa.ask')
    ->with('title','New Question');
}
```

1.  现在，我们需要创建我们刚刚分配的视图。将以下代码保存为`ask.blade.php`，放在`app/views/qa`目录下：

```php
@extends('template_masterpage')

@section('content')

  <h1 id="replyh">Ask A Question</h1>
  <p class="bluey">Note: If you think your question's been answered correctly, please don't forget to click "✓" icon to mark the answer as "correct".</p>
  {{Form::open(array('route'=>'ask_post'))}}

  <p class="minihead">Question's title:</p>
  {{Form::text('title',Input::old('title'),array('class'=>'fullinput'))}}

  <p class="minihead">Explain your question:</p>
  {{Form::textarea('question',Input::old('question'),array('class'=>'fullinput'))}}

  <p class="minihead">Tags: Use commas to split tags (tag1, tag2 etc.). To join multiple words in a tag, use - between the words (tag-name, tag-name-2):</p>
  {{Form::text('tags',Input::old('tags'),array('class'=>'fullinput'))}}
  {{Form::submit('Ask this Question')}}
  {{Form::close()}}

@stop
@section('footer_assets')

  {{-- A simple jQuery code to lowercase all tags before submission --}}
  <script type="text/javascript">
    $('input[name="tags"]').keyup(function(){
      $(this).val($(this).val().toLowerCase());
    });
  </script>

@stop
```

除了我们之前创建的视图之外，在这个视图中，我们通过填充`footer_assets`部分向页脚添加了 JavaScript 代码，这是我们在主页面中之前定义的。

1.  如果您已经正确完成了所有操作，当您导航到`site.com/ask`时，您将看到一个类似以下截图的样式化表单：![创建我们的问题表单](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrv-app-dev-bp/img/2111OS_08_05.jpg)

现在我们的问题表单已经准备好，我们可以开始处理表单了。

## 处理我们的问题表单

为了处理表单，我们需要一些验证规则和控制器方法。

1.  首先，将以下表单验证规则添加到`app/models`目录下的`Question.php`文件中：

```php
public static $add_rules = array('title' => 'required|min:2','question' => 'required|min:10');
```

1.  成功保存问题后，我们希望向用户提供问题的永久链接，以便用户可以轻松访问问题。但是，为了做到这一点，我们首先需要定义一个创建此链接的路由。将以下行添加到`app`文件夹中的`routes.php`文件中：

```php
Route::get('question/{id}/{title}',array('as'=> 'question_details', 'uses' => 'QuestionsController@getDetails' ))-> where(array('id'=>'[0-9]+' , 'title' => '[0-9a-zA-Z\-\_]+'));
```

我们将两个参数设置到这个路由中，`id`和`title`。`id`参数必须是正整数，而`title`应该只包含字母数字字符、分数和下划线。

1.  现在，我们准备处理问题表单。将以下代码添加到`app/controllers`目录下的`QuestionsController.php`文件中：

```php
/**
 * Post method to process the form
**/
public function postNew() {

  //first, let's validate the form
  $validation = Validator::make(Input::all(), Question::$add_rules);

  if($validation->passes()) {
    //First, let's create the question
    $create = Question::create(array('userID' => Sentry::getUser()->id,'title' => Input::get('title'),'question' => Input::get('question')
    ));

    //We get the insert id of the question
    $insert_id = $create->id;

    //Now, we need to re-find the question to "attach" the tag to the question
    $question = Question::find($insert_id);

    //Now, we should check if tags column is filled, and split the string and add a new tag and a relation
    if(Str::length(Input::get('tags'))) {
      //let's explode all tags from the comma
      $tags_array = explode(',', Input::get('tags'));
      //if there are any tags, we will check if they are new, if so, we will add them to database
      //After checking the tags, we will have to "attach" tag(s) to the new question 
      if(count($tags_array)) {
        foreach ($tags_array as $tag) {
          //first, let's trim and get rid of the extra space bars between commas 
          //(tag1, tag2, vs tag1,tag2) 
          $tag = trim($tag);

          //We should double check its length, because the user may have just typed "tag1,,tag2" (two or more commas) accidentally
          //We check the slugged version of the tag, because tag string may only be meaningless character(s), like "tag1,+++//,tag2"
          if(Str::length(Str::slug($tag))) {
            //the URL-Friendly version of the tag
            $tag_friendly = Str::slug($tag);

            //Now let's check if there is a tag with the url friendly version of the provided tag already in our database:
            $tag_check = Tag::where('tagFriendly',$tag_friendly);

            //if the tag is a new tag, then we will create a new one
            if($tag_check->count() == 0) {
              $tag_info = Tag::create(array('tag' => $tag,'tagFriendly' => $tag_friendly));

              //If the tag is not new, this means There was a tag previously added on the same name to another question previously
              //We still need to get that tag's info from our database 
            } else {
              $tag_info = $tag_check->first();
            }
          }

          //Now the attaching the current tag to the question
          $question->tags()->attach($tag_info->id);
        }
      }
    }

    //lastly, we should return the user to the asking page with a permalink of the question
    return Redirect::route('ask')
      ->with('success','Your question has been created successfully! '.HTML::linkRoute('question_details','Click here to see your question',array('id'=>$insert_id,'title'=>Str::slug($question->title))));

  } else {
    return Redirect::route('ask')
      ->withInput()
      ->with('error',$validation->errors()->first());
  }
}
```

现在，让我们来看看代码：

1.  首先，我们运行表单验证类来检查数值是否有效。如果验证失败，我们将用户带回问题页面，并显示用户之前提供的旧输入以及第一个验证错误消息。

1.  如果验证通过，我们继续处理表单。我们首先创建并添加问题，向数据库添加一行，然后获取我们刚刚创建的行。为了获取当前用户的 ID，我们使用 Sentry 2 的`getUser()`方法的`id`对象，该方法返回当前登录用户的信息。

1.  创建问题后，我们检查`tags`字段的长度。如果字段不为空，我们将字符串在逗号处分割，并创建一个原始的`tags`数组。

1.  之后，我们循环遍历我们分割的每个标签，并使用 Laravel 4 的`String`类的`slug()`方法创建它们的友好 URL 版本。如果生成的版本长度大于 0，则是有效的标签。

1.  在找到所有有效的标签之后，我们检查数据库是否已经创建了标签。如果是，我们获取它的 ID。如果标签是系统中的新标签，那么我们就创建一个新的标签。这样，我们就避免了系统中不必要的多个标签。

1.  之后，我们使用`attach()`方法在中间表中创建一个新的标签关系。要附加一个新的关系，我们首先需要找到要附加的 ID，然后转到附加的模型并使用`attach()`方法。

1.  在我们的示例中，我们需要将问题附加到标签上。因此，我们找到需要附加的问题，使用多对多关系来显示标签将附加到问题，并将标签的`id`附加到问题上。

1.  如果一切顺利，您应该会被重定向回问题页面，并显示一个成功消息和问题的永久链接。

1.  另外，如果您检查`question_tags`表，您会看到填充的关系数据。

### 注意

始终验证和过滤来自表单的内容，并确保你不接受任何不需要的内容。

成功添加问题后，你应该会看到一个如下截图的页面：

![处理我们的问题表单](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrv-app-dev-bp/img/2111OS_08_06.jpg)

# 创建我们的问题列表页面

现在我们可以创建问题了，是时候用实际的问题数据填充我们的虚拟索引页面了。为此，打开`app/controllers`下的`MainController.php`文件，并用以下代码修改`getIndex()`函数：

```php
public function getIndex() {
  return View::make('qa.index')
    ->with('title','Hot Questions!')
    ->with('questions',Question::with('users','tags')->orderBy('id','desc')->paginate(2));
}
```

在这个方法中，我们加载了相同的页面，但添加了两个名为`title`和`questions`的变量。`title`变量是我们应用程序的动态标题，`questions`变量保存了最后两个问题，带有分页。如果使用`paginate($number)`而不是`get()`，你可以获得一个准备就绪的分页系统。此外，使用`with()`方法，我们直接预加载了`users`和`tags`关系，以获得更好的性能。

在视图中，我们将为问题提供一个简单的点赞/踩选项，以及一个标记为`$tag`的问题的路由链接。为此，我们需要一些新的路由。将以下代码添加到`app`文件夹下的`routes.php`文件中：

```php
//Upvoting and Downvoting
Route::get('question/vote/{direction}/{id}',array('as'=> 'vote', 'before'=>'user', 'uses'=> 'QuestionsController@getvote'))->where (array('direction'=>'(up|down)', 'id'=>'[0-9]+'));

//Question tags page
Route::get('question/tagged/{tag}',array('as'=>'tagged','uses'=>'QuestionsController@getTaggedWith'))->where('tag','[0-9a-zA-Z\-\_]+');
```

现在打开`app/views/qa`下的`index.blade.php`文件，并用以下代码修改整个文件：

```php
@extends('template_masterpage')

@section('content')
  <h1>{{$title}}</h1>

  @if(count($questions))

    @foreach($questions as $question)

      <?php
        //Question's asker and tags info
        $asker = $question->users;
        $tags = $question->tags;	 
      ?>

      <div class="qwrap questions">
        {{-- Guests cannot see the vote arrows --}}
        @if(Sentry::check())
          <div class="arrowbox">
            {{HTML::linkRoute('vote','',array('up', $question->id),array('class'=>'like', 'title'=>'Upvote'))}}
            {{HTML::linkRoute('vote','',array('down',$question->id),array('class'=>'dislike','title'=>'Downvote'))}}
          </div>
        @endif

        {{-- class will differ on the situation --}}
        @if($question->votes > 0)
          <div class="cntbox cntgreen">
        @elseif($question->votes == 0)
          <div class="cntbox">
        @else
          <div class="cntbox cntred">
        @endif
        <div class="cntcount">{{$question->votes}}</div>
        <div class="cnttext">vote</div>
        </div>

        {{--Answer section will be filled later in this chapter--}}
        <div class="cntbox">
          <div class="cntcount">0</div>
          <div class="cnttext">answer</div>
        </div>

        <div class="qtext">
          <div class="qhead">
            {{HTML::linkRoute('question_details',$question->title,array($question->id,Str::slug($question->title)))}}
          </div>
          <div class="qinfo"">Asked by <a href="#">{{$asker->first_name.' '.$asker->last_name}}</a> around {{date('m/d/Y H:i:s',strtotime($question->created_at))}}</div>
          @if($tags!=null)
            <ul class="qtagul">
              @foreach($tags as $tag)
                <li>{{HTML::linkRoute('tagged',$tag->tag,$tag->tagFriendly)}}</li>
              @endforeach
            </ul>
          @endif
        </div>
      </div>
    @endforeach

    {{-- and lastly, the pagination --}}
    {{$questions->links()}}

  @else
    No questions found. {{HTML::linkRoute('ask','Ask a question?')}}
  @endif

@stop
```

由于我们已经设置了关系，我们可以直接使用`$question->users`来访问提问者，或者`$question->tags`来直接访问问题的标签。

`links()`方法带来了 Laravel 内置的分页系统。该系统已准备好与 Bootstrap 一起使用。此外，我们可以从`app/config`下的`view.php`文件中修改其外观。

如果你一直跟到这里，当你导航到你的索引页面，在插入一些新问题后，你会看到一个如下截图的视图：

![创建我们的问题列表页面](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrv-app-dev-bp/img/2111OS_08_07.jpg)

现在，我们需要为点赞和踩按钮添加功能。

## 添加点赞和踩功能

点赞和踩按钮将出现在我们项目的几乎每个页面上，因此将它们添加到主页面是一个更好的做法，而不是在每个模板中多次添加和克隆它们。

为了做到这一点，打开`app/views`下的`template_masterpage.php`文件，并找到以下行：

```php
@yield('footer_assets')
```

在上一段代码下面添加以下代码：

```php
{{-- if the user is logged in and on index or question details page--}}
@if(Sentry::check() && (Route::currentRouteName() == 'index' || Route::currentRouteName() == 'question_details'))
  <script type="text/javascript">
    $('.questions .arrowbox .like, .questions .arrowbox .dislike').click(function(e){
      e.preventDefault();
      var $this = $(this);
      $.get($(this).attr('href'),function($data){
        $this.parent('.arrowbox').next('.cntbox').find('.cntcount').text($data);
      }).fail(function(){
        alert('An error has been occurred, please try again later');
      });
    });
  </script>
@endif
```

在前面的代码中，我们检查用户是否已登录，以及用户是否已导航到索引或详细页面。然后我们使用 JavaScript 防止用户点击链接，并修改点击事件为 Ajax `get()`请求。在下一段代码中，我们将用来自`Ajax()`请求的结果来填充投票的值。

现在我们需要编写投票更新方法，使其正常工作。为此，打开`app/controllers`下的`QuestionsController.php`文件，并添加以下代码：

```php
/**
  * Vote AJAX Request
**/
public function getVote($direction,$id) {

  //request has to be AJAX Request
  if(Request::ajax()) {

    $question = Question::find($id);

    //if the question id is valid
    if($question) {

      //new vote count
      if($direction == 'up') {
        $newVote = $question->votes+1;
      } else {
        $newVote = $question->votes-1;
      }

      //now the update
      $update = $question->update(array(
        'votes' => $newVote
      ));

      //we return the new number
      return $newVote;
    } else {
      //question not found
      Response::make("FAIL", 400);
    }
  } else {
    return Redirect::route('index');
  }
}
```

`getVote()`方法检查问题是否有效，如果有效，它会增加或减少一个投票计数。我们在这里没有验证参数`$direction`，因为我们已经在资源的正则表达式中预先过滤了，`$direction`的值应该是`up`或`down`。

### 注意

在现实世界的情况下，你甚至应该将投票存储在一个新的表中，并检查用户的投票是否唯一。你还应该确保用户只投一次票。

现在我们的索引页面已经准备就绪并运行，我们可以继续下一步了。

# 创建我们的问题页面

在详细页面中，我们需要向用户展示完整的问题。还会有一个答案的地方。为了创建我们的问题页面，我们执行以下步骤：

1.  首先，我们需要添加我们之前在路由中定义的详细方法。将以下代码添加到`app/controllers`下的`QuesionsController.php`文件中：

```php
/**
 * Details page
**/
public function getDetails($id,$title) {
  //First, let's try to find the question:
  $question = Question::with('users','tags')->find($id);

  if($question) {

    //We should increase the "viewed" amount
    $question->update(array(
      'viewed' => $question->viewed+1
    ));

    return View::make('qa.details')
      ->with('title',$question->title)
      ->with('question',$question);

  } else {
    return Redirect::route('index')
    ->with('error','Question not found');
  }
}
```

我们首先尝试使用标签和发布者的信息来获取问题信息。如果找到问题，我们将浏览次数增加一次，然后简单地加载视图，并将标题和问题信息添加到视图中。

1.  在显示视图之前，我们首先需要一些额外的路由来删除问题和回复帖子。要添加这些，将以下代码添加到`app`文件夹中的`routes.php`文件中：

```php
//Reply Question:
Route::post('question/{id}/{title}',array('as'=>'question_reply','before'=>'csrf|user', 'uses'=>'AnswersController@postReply'))->where(array('id'=>'[0-9]+','title'=>'[0-9a-zA-Z\-\_]+'));

//Admin Question Deletion
Route::get('question/delete/{id}',array('as'=>'delete_question','before'=>'access_check:admin','uses'=>'QuestionsController@getDelete'))->where('id','[0-9]+');
```

1.  现在控制器方法和视图中所需的路由已经准备好，我们需要视图来向最终用户显示数据。按照步骤，逐部分将所有提供的代码添加到`app/views/qa`目录下的`details.blade.php`文件中：

```php
@extends('template_masterpage')

@section('content')

<h1 id="replyh">{{$question->title}}</h1>
<div class="qwrap questions">
  <div id="rcount">Viewed {{$question->viewed}} time{{$question->viewed>0?'s':''}}.</div>

  @if(Sentry::check())
    <div class="arrowbox">
      {{HTML::linkRoute('vote',''array('up',$question->id),array('class'=>'like', 'title'=>'Upvote'))}}
      {{HTML::linkRoute('vote','',array('down',$question->id),array('class'=>'dislike','title'=>'Downvote'))}}
    </div>
  @endif

  {{-- class will differ on the situation --}}
  @if($question->votes > 0)
    <div class="cntbox cntgreen">
  @elseif($question->votes == 0)
    <div class="cntbox">
  @else
    <div class="cntbox cntred">
  @endif
      <div class="cntcount">{{$question->votes}}</div>
      <div class="cnttext">vote</div>
    </div>
```

在视图的第一部分，我们将视图文件扩展到我们的主页面`template_masterpage`。然后我们开始填写`content`部分的代码。我们使用命名路由创建了两个链接，用于投票和反对票，这将使用 Ajax 处理。此外，由于每种投票状态都有不同的样式（正面投票为绿色，负面投票为红色），我们使用`if`子句并修改了开放的`<div>`标签。

1.  现在将以下代码添加到`details.blade.php`中：

```php
  <div class="rblock">
    <div class="rbox">
      <p>{{nl2br($question->question)}}</p>
    </div>
    <div class="qinfo">Asked by <a href="#">{{$question->users->first_name.' '.$question->users->last_name}}</a> around {{date('m/d/Y H:i:s',strtotime($question->created_at))}}</div>

    {{--if the question has tags, show them --}}
    @if($question->tags!=null)
      <ul class="qtagul">
        @foreach($question->tags as $tag)
          <li>{{HTML::linkRoute('tagged',$tag->tag,$tag->tagFriendly)}}</li>
        @endforeach
      </ul>
    @endif
```

在这一部分，我们展示问题本身，并检查是否有标签。如果`tags`对象不为空（存在标签），我们为每个标签使用命名路由创建一个链接，以显示带有`$tag`标签的问题。

1.  现在将以下代码添加到`details.blade.php`中：

```php
    {{-- if the user/admin is logged in, we will have a buttons section --}}
    @if(Sentry::check())
      <div class="qwrap">
        <ul class="fastbar">
          @if(Sentry::getUser()->hasAccess('admin'))
            <li class="close">{{HTML::linkRoute('delete_question','delete',$question->id)}}</li>
          @endif
          <li class="answer"><a href="#">answer</a></li>
        </ul>
      </div>
    @endif
  </div>
  <div id="rreplycount">{{count($question->answers)}} answers</div>
```

在这一部分，如果最终用户是管理员，我们会显示回答和删除问题的按钮。

1.  现在将以下代码添加到`details.blade.php`中：

```php
  {{-- if it's a user, we will also have the answer block inside our view--}}
  @if(Sentry::check())
    <div class="rrepol" id="replyarea" style="margin-bottom:10px">
      {{Form::open(array('route'=>array('question_reply',$question->id,Str::slug($question->title))))}}
      <p class="minihead">Provide your Answer:</p>
      {{Form::textarea('answer',Input::old('answer'),array('class'=>'fullinput'))}}
      {{Form::submit('Answer the Question!')}}
      {{Form::close()}}
    </div>
  @endif

</div>
@stop
```

在这一部分，我们将向问题本身添加回答块，利用 Laravel 4 内置的`Form`类。这个表单只对已登录的用户可用（也对管理员可用，因为他们也是已登录用户）。我们使用`@stop`来完成这一部分的内容。

1.  现在将以下代码添加到`details.blade.php`中：

```php
@section('footer_assets')

  {{--If it's a user, hide the answer area and make a simple show/hide button --}}
  @if(Sentry::check())
    <script type="text/javascript">

    var $replyarea = $('div#replyarea');
    $replyarea.hide();

    $('li.answer a').click(function(e){
      e.preventDefault();

      if($replyarea.is(':hidden')) {
        $replyarea.fadeIn('fast');
      } else {
        $replyarea.fadeOut('fast');
      }
    });
    </script>
  @endif

  {{-- If the admin is logged in, make a confirmation to delete attempt --}}
  @if(Sentry::check())
    @if(Sentry::getUser()->hasAccess('admin'))
      <script type="text/javascript">
      $('li.close a').click(function(){
        return confirm('Are you sure you want to delete this? There is no turning back!');
      });
      </script>
    @endif
  @endif
@stop
```

在这一部分，我们填充`footer_assets`部分以添加一些 JavaScript 来向用户显示/隐藏答案字段，并在删除问题之前向管理员显示确认框。

如果所有步骤都已完成，您应该有一个如下截图所示的视图：

![创建我们的问题页面](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrv-app-dev-bp/img/2111OS_08_08.jpg)

最后，我们需要一个删除问题的方法。将以下代码添加到`app/controllers`目录下的`QuestionsController.php`文件中：

```php
/**
 * Deletes the question
**/

public function getDelete($id) {
  //First, let's try to find the question:
  $question = Question::find($id);

  if($question) {
    //We delete the question directly
    Question::delete();
    //We won't have to think about the tags and the answers,
    //because they are set as foreign key and we defined them cascading on deletion, 
    //they will be automatically deleted

    //Let's return to the index page with a success message
    return Redirect::route('index')
      ->with('success','Question deleted successfully!');
  } else {
    return Redirect::route('index')
      ->with('error','Nothing to delete!');
  }
}
```

由于我们已经设置了相关表在删除时级联删除，我们不必担心删除答案和标签。

现在我们准备发布答案，我们应该创建答案表并处理我们的答案。

# 创建我们的答案表和资源

我们的答案表将与当前的问题表非常相似，只是它将有更少的列。我们的答案也可以被投票，一个答案可以被问题的发布者或管理员标记为最佳答案。为了创建我们的答案表和资源，我们执行以下步骤：

1.  首先，让我们创建数据库表。在终端中运行以下命令：

```php
**php artisan migrate:make create_answers_table --table=answers --create**

```

1.  现在，打开迁移文件，它创建在`app/database/migrations`目录下，并用以下代码替换`up()`函数的内容：

```php
Schema::create('answers', function(Blueprint $table)
{
  $table->increments('id');

  //question's id
  $table->integer('questionID')->unsigned()->default(0);
  //answerer's user id
  $table->integer('userID')->unsigned()->default(0);
  $table->text('answer');
  //if the question's been marked as correct
  $table->enum('correct',array('0','1'))->default(0);
  //total number of votes:
  $table->integer('votes')->default(0);
  //foreign keys
  $table->foreign('questionID')->references('id')->on('questions')->onDelete('cascade');
  $table->foreign('userID')->references('id')->on('users')->onDelete('cascade');

  $table->timestamps();
});
```

1.  现在，为了从 Eloquent ORM 及其关系中受益，我们需要为`answers`表创建一个模型。将以下代码添加为`app/models`目录下的`Answer.php`文件：

```php
<?php

class Answer extends Eloquent {

  //The relation with users
  public function users() {
    return $this->belongsTo('User','userID');
  }

  //The relation with questions
  public function questions() {
    return $this->belongsTo('Question','questionID');
  }

  //which fields can be filled
  protected $fillable = array('questionID', 'userID', 'answer', 'correct', 'votes');

  //Answer Form Validation Rules
  public static $add_rules = array(
    'answer'	=> 'required|min:10'
  );

}
```

答案是用户和问题的子级，这就是为什么在我们的模型中，我们应该使用`belongsTo()`来关联他们的表。

1.  由于一个问题可能有多个答案，我们还应该从`questions`表到`answers`表添加一个关系（以获取关于问题的答案数据，您问题的所有答案，或我赞过的问题的所有答案）。为此，打开`app/models`目录下的`Question.php`文件，并添加以下代码：

```php
public function answers() {
  return $this->hasMany('Answer','questionID');
}
```

1.  最后，我们需要一个控制器来处理与答案相关的请求。在终端中运行以下命令以为答案创建一个控制器：

```php
**php artisan controller:make AnswersController**

```

这个命令将在`app/controllers`目录下创建一个`AnswersController.php`文件。

现在我们的答案资源已经准备好，我们可以处理答案了。

## 处理答案

在上一节中，我们成功地创建了一个带有标签的问题和我们的答案形式。现在我们需要处理答案并将它们添加到数据库中。有一些简单的步骤需要遵循：

1.  首先，我们需要一个控制器表单来处理答案并将其添加到表中。为此，请打开`app/controllers`目录下新创建的`AnswersController.php`文件，删除类内部的每个自动生成的方法，并在类定义内添加以下代码：

```php
/**
 * Adds a reply to the questions
**/
public function postReply($id,$title) {

  //First, let's check if the question id is valid
  $question = Question::find($id);

  //if question is found, we keep on processing
  if($question) {

    //Now let's run the form validation
    $validation = Validator::make(Input::all(), Answer::$add_rules);

    if($validation->passes()) {

      //Now let's create the answer
      Answer::create(array('questionID' => $question->id,'userID' => Sentry::getUser()->id,'answer' => Input::get('answer')
      ));

      //Finally, we redirect the user back to the question page with a success message
      return Redirect::route('question_details',array($id,$title))
        ->with('success','Answer submitted successfully!');

    } else {
      return Redirect::route('question_details',array($id,$title))
        ->withInput()
        ->with('error',$validation->errors()->first());
    }

  } else {
    return Redirect::route('index')
      ->with('error','Question not found');
  }

}
```

`postReply()`方法简单地检查问题是否有效，运行表单验证，将一个答案添加到数据库，并将用户返回到问题页面。

1.  现在在问题页面中，我们还需要包括答案和答案数量。但在此之前，我们需要先获取它们。有一些步骤需要完成。

1.  首先，打开`app/controllers`目录下的`QuestionsController.php`文件，并找到以下行：

```php
       $question = Question::with('users','tags')->find($id);
```

用以下行替换上一行：

```php
       $question = Question::with('users','tags','answers')->find($id);
```

1.  现在，在`app/controllers`目录下的`MainController.php`文件中找到以下行：

```php
      ->with('questions',Question::with('users','tags')-> orderBy('id','desc')->paginate(2));
```

用以下行替换上一行：

```php
     ->with('questions',Question::with('users', 'tags', 'answers')->orderBy('id','desc')->paginate(2));
```

1.  现在打开`app/views/qa`目录下的`index.blade.php`文件，并找到以下代码：

```php
      {{--Answer section will be filled later in this chapter--}}
      <div class="cntbox">
        <div class="cntcount">0</div>
        <div class="cnttext">answer</div>
      </div>
```

用以下代码替换上一段代码：

```php
       <?php
       //does the question have an accepted answer?
       $answers = $question->answers; 
       $accepted = false; //default false

       //We loop through each answer, and check if there is an accepted answer
       if($question->answers!=null) {
         foreach ($answers as $answer) {
           //If an accepted answer is found, we break       the loop
           if($answer->correct==1) {
             $accepted=true;
             break;
           }
         }
       }
       ?>
       @if($accepted)
         <div class="cntbox cntgreen">
       @else
         <div class="cntbox cntred">
       @endif
         <div class="cntcount">{{count($answers)}}</div>
         <div class="cnttext">answer</div>
       </div>
```

在这个修改中，我们添加了一个 PHP 代码和一个循环，检查每个答案是否被接受。如果是，我们就改变`div`的容器类。此外，我们还添加了一个显示答案数量的功能。

1.  接下来，我们需要定义路由资源来处理答案的点赞和踩和选择最佳答案。将以下代码添加到`app`文件夹下的`routes.php`文件中：

```php
       //Answer upvoting and Downvoting
       Route::get('answer/vote/{direction}}/{id}',array('as'=>'vote_answer', 'before'=>'user', 'uses'=>'AnswersController@getVote'))->where(array('direction'=>'(up|down)', 'id'=>'[0-9]+'));
```

1.  现在我们需要在问题详情页面中显示答案，以便用户可以看到答案。为此，请打开`app/views/qa`目录下的`details.blade.php`文件，并执行以下步骤：

1.  首先，找到以下行：

```php
       <div id="rreplycount">0 answers</div>
```

用以下行替换上一行：

```php
       <div id="rreplycount">{{count($question->answers)}} answers</div>
```

1.  现在找到以下代码：

```php
       </div>
       @stop

       @section('footer_assets')
```

在上一行上面添加以下代码：

```php
       @if(count($question->answers))
         @foreach($question->answers as $answer)

           @if($answer->correct==1)
             <div class="rrepol correct">
           @else
             <div class="rrepol">
    @endif
           @if(Sentry::check())
             <div class="arrowbox">
               {{HTML::linkRoute('vote_answer','',array('up', $answer->id),array('class'=>'like', 'title'=>'Upvote'))}}
               {{HTML::linkRoute('vote_answer','', array('down',$answer->id), array('class'=>'dislike','title'=>'Downvote'))}}

             </div>
           @endif

           <div class="cntbox">
             <div class="cntcount">{{$answer->votes}}</div>
             <div class="cnttext">vote</div>
           </div>

           @if($answer->correct==1)
             <div class="bestanswer">best answer</div>
           @else
             {{-- if the user is admin or the owner of the question, show the best answer button --}}
             @if(Sentry::check())
               @if(Sentry::getUser()->hasAccess('admin') || Sentry::getUser()->id == $question->userID)
                   <a class="chooseme" href="{{URL::route('choose_answer',$answer->id)}}"><div class="choosebestanswer">choose</div></a>
               @endif
             @endif
           @endif
           <div class="rblock">
             <div class="rbox">
               <p>{{nl2br($answer->answer)}}</p>
             </div>
             <div class="rrepolinf">
             <p>Answered by <a href="#">{{$answer->users->first_name.' '.$answer->users->last_name}}</a> around {{date('m/d/Y H:i:s',strtotime($answer->created_at))}}</p>
             </div>
           </div>
         </div>
         @endforeach
       @endif
```

答案的当前结构与我们在本章前面创建的问题结构非常接近。此外，我们有一个按钮可以选择最佳答案，只有提问者和管理员才能看到。

1.  现在，我们需要在同一个视图中添加一个确认按钮。为此，请将以下代码添加到`footer_assets`部分：

```php
       {{-- for admins and question owners --}}
       @if(Sentry::check())
         @if(Sentry::getUser()->hasAccess('admin') || Sentry::getUser()->id == $question->userID)
           <script type="text/javascript">
             $('a.chooseme').click(function(){
               return confirm('Are you sure you want to choose this answer as best answer?');
             });
           </script>
         @endif
       @endif
```

1.  现在，我们需要一个方法来增加或减少答案的投票数。将以下代码添加到`app/controllers`目录下的`AnswersController.php`文件中：

```php
/**
  * Vote AJAX Request
**/
public function getVote($direction, $id) {

  //request has to be AJAX Request
  if(Request::ajax()) {
    $answer = Answer::find($id);
    //if the answer id is valid
    if($answer) {
      //new vote count
      if($direction == 'up') {
        $newVote = $answer->votes+1;
      } else {
        $newVote = $answer->votes-1;
      }

      //now the update
      $update = $answer->update(array(
        'votes' => $newVote
      ));

      //we return the new number
      return $newVote;
    } else {
      //answer not found
      Response::make("FAIL", 400);
    }
  } else {
    return Redirect::route('index');
  }
}
```

`getVote()`方法与问题投票方法完全相同。这里唯一的区别是，影响的是答案而不是问题。

## 选择最佳答案

我们需要一个处理方法来选择最佳答案。为了选择最佳答案，我们执行以下步骤：

1.  打开`app/controllers`目录下的`AnswersController.php`文件，并添加以下代码：

```php
/**
  * Chooses a best answer
**/
public function getChoose($id) {

  //First, let's check if there is an answer with that given ID
  $answer = Answer::with('questions')->find($id);

  if($answer) {
    //Now we should check if the user who clicked is an admin or the owner of the question 
    if(Sentry::getUser()->hasAccess('admin') || $answer->userID == Sentry::getUser()->id) {
        //First we should unmark all the answers of the question from correct (1) to incorrect (0)
        Answer::where('questionID',$answer->questionID)
          ->update(array(
            'correct' => 0
          ));

        //And we should mark the current answer as correct/best answer
      $answer->update(array(
        'correct' => 1
      ));

      //And now let's return the user back to the questions page
      return Redirect::route('question_details',array($answer->questionID, Str::slug($answer->questions->title)))
          ->with('success','Best answer chosen successfully');
    } else {
      return Redirect::route('question_details',array($answer->questionID, Str::slug($answer->questions->title)))
        ->with('error','You don\'t have access to this attempt!');
    }

  } else {
    return Redirect::route('index')
      ->with('error','Answer not found');
  }

}
```

在上述代码中，我们首先检查答案是否有效。然后，我们检查点击**最佳答案**按钮的用户是否是问题的提问者或应用程序的管理员。之后，我们将问题的所有答案标记为未选中（清除问题的所有最佳答案信息），并将选择的答案标记为最佳答案。最后，我们返回带有成功消息的表单。

1.  现在，我们需要一个方法来删除答案。首先，我们需要一个路由。打开`app`目录下的`routes.php`文件，并添加以下代码：

```php
//Deleting an answer
Route::get('answer/delete/{id}',array('as'=>'delete_answer','before'=>'user', 'uses'=> 'AnswersController@getDelete'))->where('id','[0-9]+');
```

1.  接下来，在`app/views/qa`下的`details.blade.php`文件中找到以下代码：

```php
<p>Answered by <a href="#">{{$answer->users->first_name.' '.$answer->users->last_name}}</a> around {{date('m/d/Y H:i:s',strtotime($answer->created_at))}}</p>
```

在之前的代码下面添加以下代码：

```php
{{-- Only the answer's owner or the admin can delete the answer --}}
@if(Sentry::check())
  <div class="qwrap">
    <ul class="fastbar">
      @if(Sentry::getUser()->hasAccess('admin') || Sentry::getUser()->id == $answer->userID)
        <li class="close">{{HTML::linkRoute('delete_answer','delete',$answer->id)}}</li>
      @endif
    </ul>
  </div>
@endif
```

1.  现在，我们需要一个控制器方法来删除答案。在`app/controllers`下的`AnswersController.php`文件中添加以下代码：

```php
/**
 * Deletes an answer
**/
public function getDelete($id) {

  //First, let's check if there is an answer with that given ID
  $answer = Answer::with('questions')->find($id);

  if($answer) {
    //Now we should check if the user who clicked is an admin or the owner of the question 
    if(Sentry::getUser()->hasAccess('admin') || $answer->userID==Sentry::getUser()->id) {

      //Now let's delete the answer
      $delete = Answer::find($id)->delete();

      //And now let's return the user back to the questions page
      return Redirect::route('question_details',array($answer->questionID, Str::slug($answer->questions->title)))
        ->with('success','Answer deleted successfully');
    } else {
      return Redirect::route('question_details',array($answer->questionID, Str::slug($answer->questions->title)))
        ->with('error','You don\'t');
    }

  } else {
    return Redirect::route('index')
      ->with('error','Answer not found');
  }
}
```

如果你已经做了一切正确，我们详情页面的最终版本将会像下面的截图一样：

![选择最佳答案](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrv-app-dev-bp/img/2111OS_08_09.jpg)

现在一切准备就绪，可以提问、回答、标记最佳答案和删除，我们应用中只缺少一个功能，即标签搜索。正如你所知，我们已经将所有标签都做成了链接，所以现在我们应该处理它们的路由。

# 通过标签搜索问题

在我们的主页面和详情页面中，我们给所有标签都加了一个特殊链接。我们将执行以下步骤来通过标签搜索问题：

1.  首先，打开`app/controllers`下的`QuestionsController.php`文件，并添加以下代码：

```php
/**
  * Shows the questions tagged with $tag friendly URL
**/
public function getTaggedWith($tag) {

  $tag = Tag::where('tagFriendly',$tag)->first();

  if($tag) {
    return View::make('qa.index')
      ->with('title','Questions Tagged with: '.$tag->tag)
      ->with('questions',$tag->questions()->with('users','tags','answers')->paginate(2));
  } else {
    return Redirect::route('index')
      ->with('error','Tag not found');
  }
}
```

这段代码的作用是，首先使用列`tagFriendly`搜索标签，这会得到一个唯一的结果。因此，我们可以安全地使用`first()`返回第一个结果。然后我们检查标签是否存在于我们的系统中。如果没有，我们会返回用户到索引页面，并显示一个错误消息，说明未找到该标签。

如果找到了标签，我们使用我们定义的关系捕获所有使用该标签标记的问题，并使用急加载来加载用户、标签（所有问题的标签）和答案（尽管我们在这个页面上不显示答案，但我们需要它们的计数来在页面上显示）。我们的视图将与索引页面的视图完全相同。因此，我们直接使用了那个视图，而不是创建一个新的。

我们将分页限制保持为两，只是为了展示它的工作原理。

1.  最后，为了允许页面上的 JavaScript 资源（例如启用 Ajax 投票和取消投票），打开`app/views`下的`template_masterpage.php`文件，并找到以下行：

```php
@if(Sentry::check() && (Route::currentRouteName() == 'index' || Route::currentRouteName() == 'question_details'))
```

用以下代码替换之前的代码：

```php
@if(Sentry::check() && (Route::currentRouteName() == 'index' || Route::currentRouteName() == 'tagged' || Route::currentRouteName() == 'question_details'))
```

这样，我们甚至可以在具有名称为`tagged`的路由的页面上允许这些 Ajax 事件。

如果你已经做了一切正确，当你点击标签的名称时，会出现如下页面：

![通过标签搜索问题](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrv-app-dev-bp/img/2111OS_08_10.jpg)

# 摘要

在本章中，我们使用了 Laravel 4 的各种功能。我们学会了去除公共部分，使 Laravel 可以在一些共享主机解决方案上运行。我们还学会了 Sentry 2 的基础知识，这是一个强大的身份验证类。我们学会了如何使用多对多关系和中间表。我们还使用了 Eloquent ORM 来定义属于和拥有任何关系。我们使用资源来定义所有的 URL、表单操作和链接。因此，如果你需要更改应用程序的 URL 结构（比如你需要将你的网站更改为德语，而德语中的问题是“frage”），你只需要编辑`routes.php`。这样一来，你就不需要深入每个文件来修复链接。我们使用分页类来浏览记录，还使用了 Laravel 表单构建器类。

在下一章中，我们将使用我们到目前为止学到的一切来开发一个功能齐全的电子商务网站。
