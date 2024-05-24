# Vue2 和 Laravel5 全栈开发（二）

> 原文：[`zh.annas-archive.org/md5/e47ac4de864f495f2e21aebfb4a63e4f`](https://zh.annas-archive.org/md5/e47ac4de864f495f2e21aebfb4a63e4f)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：使用 Laravel 构建网络服务

在上一章中，我们已经启动并运行了 Homestead 开发环境，并开始为主要的 Vuebnb 项目提供服务。在本章中，我们将创建一个简单的网络服务，使 Vuebnb 的房间列表数据可以在前端显示。

本章涵盖的主题：

+   使用 Laravel 创建网络服务

+   编写数据库迁移和种子文件

+   创建 API 端点以使数据公开访问

+   从 Laravel 提供图像

# Vuebnb 房间列表

在第二章中，*Vuebnb 原型设计，您的第一个 Vue.js 项目*，我们构建了前端应用程序的列表页面原型。很快，我们将删除此页面上的硬编码数据，并将其转换为可以显示任何房间列表的模板。

在本书中，我们不会为用户创建他们自己的房间列表添加功能。相反，我们将使用包含 30 个不同列表的模拟数据包，每个列表都有自己独特的标题、描述和图像。我们将使用这些列表填充数据库，并配置 Laravel 根据需要将它们提供给前端。

# 网络服务

**网络服务**是在服务器上运行的应用程序，允许客户端（如浏览器）通过 HTTP 远程写入/检索数据到/从服务器。

网络服务的接口将是一个或多个 API 端点，有时会受到身份验证的保护，它们将以 XML 或 JSON 有效负载返回数据：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/4f1dd567-4848-4363-aeab-85ec53a9ac04.png)图 4.1。Vuebnb 网络服务

网络服务是 Laravel 的特长，因此为 Vuebnb 创建一个网络服务不难。我们将使用路由来表示我们的 API 端点，并使用 Laravel 无缝同步与数据库的 Eloquent 模型来表示列表：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/a0baa328-978a-4528-abc3-8ee6465f45a1.png)图 4.2。网络服务架构

Laravel 还具有内置功能，可以添加 REST 等 API 架构，尽管我们不需要这个简单的用例。

# 模拟数据

模拟列表数据在文件`database/data.json`中。该文件包括一个 JSON 编码的数组，其中包含 30 个对象，每个对象代表一个不同的列表。在构建了列表页面原型之后，您无疑会认出这些对象上的许多相同属性，包括标题、地址和描述。

`database/data.json`：

```php
[
  {
    "id": 1,
    "title": "Central Downtown Apartment with Amenities",
    "address": "...",
    "about": "...",
    "amenity_wifi": true,
    "amenity_pets_allowed": true,
    "amenity_tv": true,
    "amenity_kitchen": true,
    "amenity_breakfast": true,
    "amenity_laptop": true,
    "price_per_night": "$89"
    "price_extra_people": "No charge",
    "price_weekly_discount": "18%",
    "price_monthly_discount": "50%",
  },
  {
    "id": 2, ... }, ... ]
```

每个模拟列表还包括房间的几张图片。图像并不真正属于网络服务的一部分，但它们将存储在我们应用程序的公共文件夹中，以便根据需要提供服务。

图像文件不在项目代码中，而是在我们从 GitHub 下载的代码库中。我们将在本章后期将它们复制到我们的项目文件夹中。

# 数据库

我们的网络服务将需要一个用于存储模拟列表数据的数据库表。为此，我们需要创建一个模式和迁移。然后，我们将创建一个 seeder，它将加载和解析我们的模拟数据文件，并将其插入数据库，以便在应用程序中使用。

# 迁移

`迁移`是一个特殊的类，其中包含针对数据库运行的一组操作，例如创建或修改数据库表。迁移确保每次创建应用程序的新实例时，例如在生产环境中安装或在团队成员的机器上安装时，您的数据库都会被相同地设置。

要创建新的迁移，请使用`make:migration` Artisan CLI 命令。命令的参数应该是迁移将要执行的操作的蛇形描述。

```php
$ php artisan make:migration create_listings_table
```

现在您将在`database/migrations`目录中看到新的迁移。您会注意到文件名具有前缀时间戳，例如`2017_06_20_133317_create_listings_table.php`。时间戳允许 Laravel 确定迁移的正确顺序，以防需要同时运行多个迁移。

您的新迁移声明了一个扩展了`Migration`的类。它覆盖了两个方法：`up`用于向数据库添加新表、列或索引；`down`用于删除它们。我们很快将实现这些方法。

`2017_06_20_133317_create_listings_table.php`：

```php
<?php

use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class CreateListingsTable extends Migration
{
  public function up()
  {
    //
  }

  public function down()
  {
    //
  }
}
```

# 模式

**模式**是数据库结构的蓝图。对于诸如 MySQL 之类的关系数据库，模式将数据组织成表和列。在 Laravel 中，可以使用`Schema`外观的`create`方法声明模式。

现在我们将为一个表创建一个模式，用于保存 Vuebnb 列表。表的列将与我们的模拟列表数据的结构相匹配。请注意，我们为设施设置了默认的`false`值，并允许价格有一个`NULL`值。所有其他列都需要一个值。

模式将放在我们迁移的`up`方法中。我们还将填写`down`，调用`Schema::drop`。

`2017_06_20_133317_create_listings_table.php`：

```php
public function up()
{ Schema::create('listings', function (Blueprint $table) {
    $table->primary('id');
    $table->unsignedInteger('id');
    $table->string('title');
    $table->string('address');
    $table->longText('about');

    // Amenities
    $table->boolean('amenity_wifi')->default(false);
    $table->boolean('amenity_pets_allowed')->default(false);
    $table->boolean('amenity_tv')->default(false);
    $table->boolean('amenity_kitchen')->default(false);
    $table->boolean('amenity_breakfast')->default(false);
    $table->boolean('amenity_laptop')->default(false);

    // Prices
    $table->string('price_per_night')->nullable();
    $table->string('price_extra_people')->nullable();
    $table->string('price_weekly_discount')->nullable();
    $table->string('price_monthly_discount')->nullable();
  });
}

public function down()
{ Schema::drop('listings');
}
```

**外观**是一种面向对象的设计模式，用于在服务容器中创建对底层类的静态代理。外观不是为了提供任何新功能；它的唯一目的是提供一种更易记和易读的方式来执行常见操作。将其视为面向对象的辅助函数。

# 执行

现在我们已经设置了新的迁移，让我们使用这个 Artisan 命令来运行它：

```php
$ php artisan migrate
```

您应该在终端中看到类似以下的输出：

```php
Migrating: 2017_06_20_133317_create_listings_table
Migrated:  2017_06_20_133317_create_listings_table
```

要确认迁移是否成功，让我们使用 Tinker 来显示新表的结构。如果您从未使用过 Tinker，它是一个 REPL 工具，允许您在命令行上与 Laravel 应用程序进行交互。当您在 Tinker 中输入命令时，它将被评估为您的应用程序代码中的一行。

首先，打开 Tinker shell：

```php
$ php artisan tinker
```

现在输入一个 PHP 语句进行评估。让我们使用`DB`外观的`select`方法来运行一个 SQL`DESCRIBE`查询，以显示表结构：

```php
>>>> DB::select('DESCRIBE listings;');
```

输出非常冗长，所以我不会在这里重复，但您应该看到一个包含所有表细节的对象，确认迁移已经成功。

# 种子模拟列表

现在我们有了列表的数据库表，让我们用模拟数据填充它。为此，我们需要做以下事情：

1.  加载`database/data.json`文件

1.  解析文件

1.  将数据插入列表表中

# 创建一个 seeder

Laravel 包括一个我们可以扩展的 seeder 类，称为`Seeder`。使用此 Artisan 命令来实现它：

```php
$ php artisan make:seeder ListingsTableSeeder
```

当我们运行 seeder 时，`run`方法中的任何代码都会被执行。

`database/ListingsTableSeeder.php`：

```php
<?php

use Illuminate\Database\Seeder;

class ListingsTableSeeder extends Seeder
{
  public function run()
  {
    //
  }
}
```

# 加载模拟数据

Laravel 提供了一个`File`外观，允许我们简单地从磁盘打开文件，如`File::get($path)`。要获取模拟数据文件的完整路径，我们可以使用`base_path()`辅助函数，它将应用程序目录的根路径作为字符串返回。

然后，可以使用内置的`json_decode`方法将此 JSON 文件转换为 PHP 数组。一旦数据是一个数组，只要表的列名与数组键相同，就可以直接将数据插入数据库。

`database/ListingsTableSeeder.php`：

```php
public function run()
{
  $path = base_path() . '/database/data.json';
  $file = File::get($path);
  $data = json_decode($file, true);
}
```

# 插入数据

为了插入数据，我们将再次使用`DB`外观。这次我们将调用`table`方法，它返回一个`Builder`的实例。`Builder`类是一个流畅的查询构建器，允许我们通过链接约束来查询数据库，例如`DB::table(...)->where(...)->join(...)`等。让我们使用构建器的`insert`方法，它接受一个列名和值的数组。

`database/seeds/ListingsTableSeeder.php`：

```php
public function run()
{
  $path = base_path() . '/database/data.json';
  $file = File::get($path);
  $data = json_decode($file, true);
  DB::table('listings')->insert($data);
}
```

# 执行 seeder

要执行 seeder，我们必须从相同目录中的`DatabaseSeeder.php`文件中调用它。

`database/seeds/DatabaseSeeder.php`：

```php
<?php

use Illuminate\Database\Seeder;

class DatabaseSeeder extends Seeder
{
  public function run()
  {
    $this->call(ListingsTableSeeder::class);
  }
}
```

完成后，我们可以使用 Artisan CLI 来执行 seeder：

```php
$ php artisan db:seed
```

您应该在终端中看到以下输出：

```php
Seeding: ListingsTableSeeder
```

我们将再次使用 Tinker 来检查我们的工作。模拟数据中有 30 个列表，所以为了确认种子成功，让我们检查数据库中是否有 30 行：

```php
$ php artisan tinker >>>> DB::table('listings')->count(); 
# Output: 30
```

最后，让我们检查表的第一行，以确保其内容符合我们的预期：

```php
>>>> DB::table('listings')->get()->first();
```

以下是输出：

```php
=> {#732
 +"id": 1,
 +"title": "Central Downtown Apartment with Amenities",
 +"address": "No. 11, Song-Sho Road, Taipei City, Taiwan 105",
 +"about": "...",
 +"amenity_wifi": 1,
 +"amenity_pets_allowed": 1,
 +"amenity_tv": 1,
 +"amenity_kitchen": 1,
 +"amenity_breakfast": 1,
 +"amenity_laptop": 1,
 +"price_per_night": "$89",
 +"price_extra_people": "No charge",
 +"price_weekly_discount": "18%",
 +"price_monthly_discount": "50%"
}
```

如果你的看起来像这样，那么你已经准备好继续了！

# 列表模型

我们现在已经成功为我们的列表创建了一个数据库表，并用模拟列表数据进行了种子。现在我们如何从 Laravel 应用程序中访问这些数据呢？

我们看到`DB`外观让我们直接在数据库上执行查询。但是 Laravel 提供了一种更强大的方式通过**Eloquent ORM**访问数据。

# Eloquent ORM

**对象关系映射**（**ORM**）是一种在面向对象编程语言中在不兼容的系统之间转换数据的技术。MySQL 等关系数据库只能存储整数和字符串等标量值，这些值组织在表中。但是我们希望在我们的应用程序中使用丰富的对象，因此我们需要一种强大的转换方式。

Eloquent 是 Laravel 中使用的 ORM 实现。它使用**活动记录**设计模式，其中一个模型与一个数据库表绑定，模型的一个实例与一行绑定。

要在 Laravel 中使用 Eloquent ORM 创建模型，只需使用 Artisan 扩展`Illuminate\Database\Eloquent\Model`类：

```php
$ php artisan make:model Listing
```

这将生成一个新文件。

`app/Listing.php`：

```php
<?php

namespace App;

use Illuminate\Database\Eloquent\Model;

class Listing extends Model
{
  //
}
```

我们如何告诉 ORM 要映射到哪个表，以及要包含哪些列？默认情况下，`Model`类使用类名（`Listing`）的小写形式（`listing`）作为要使用的表名。并且默认情况下，它使用表中的所有字段。

现在，每当我们想要加载我们的列表时，我们可以在我们的应用程序的任何地方使用这样的代码：

```php
<?php

// Load all listings
$listings = \App\Listing::all();

// Iterate listings, echo the address
foreach ($listings as $listing) {
  echo $listing->address . '\n' ;
}

/*
 * Output:
 *
 * No. 11, Song-Sho Road, Taipei City, Taiwan 105
 * 110, Taiwan, Taipei City, Xinyi District, Section 5, Xinyi Road, 7
 * No. 51, Hanzhong Street, Wanhua District, Taipei City, Taiwan 108
 * ... */
```

# 转换

MySQL 数据库中的数据类型与 PHP 中的数据类型并不完全匹配。例如，ORM 如何知道数据库值 0 是表示数字 0 还是布尔值`false`？

Eloquent 模型可以使用`$casts`属性声明任何特定属性的数据类型。`$casts`是一个键/值数组，其中键是要转换的属性的名称，值是我们要转换为的数据类型。

对于列表表，我们将把设施属性转换为布尔值。

`app/Listing.php`：

```php
<?php

namespace App;

use Illuminate\Database\Eloquent\Model;

class Listing extends Model
{
  protected $casts = [
    'amenity_wifi' => 'boolean',
    'amenity_pets_allowed' => 'boolean',
    'amenity_tv' => 'boolean',
    'amenity_kitchen' => 'boolean',
    'amenity_breakfast' => 'boolean',
    'amenity_laptop' => 'boolean'
  ];
}
```

现在这些属性将具有正确的类型，使我们的模型更加健壮：

```php
echo gettype($listing->amenity_wifi());

// boolean
```

# 公共接口

我们 Web 服务的最后一部分是公共接口，允许客户端应用程序请求列表数据。由于 Vuebnb 列表页面设计为一次显示一个列表，所以我们至少需要一个端点来检索单个列表。

现在让我们创建一个路由，将匹配任何传入的 GET 请求到 URI`/api/listing/{listing}`，其中`{listing}`是一个 ID。我们将把这个路由放在`routes/api.php`文件中，路由会自动添加`/api/`前缀，并且默认情况下具有用于 Web 服务的中间件优化。

我们将使用`closure`函数来处理路由。该函数将有一个`$listing`参数，我们将其类型提示为`Listing`类的实例，也就是我们的模型。Laravel 的服务容器将解析此实例，其 ID 与`{listing}`匹配。

然后我们可以将模型编码为 JSON 并将其作为响应返回。

`routes/api.php`：

```php
<?php

use App\Listing; Route::get('listing/{listing}', function(Listing $listing) {
  return $listing->toJson();  
});
```

我们可以使用终端上的`curl`命令来测试这个功能是否有效：

```php
$ curl http://vuebnb.test/api/listing/1
```

响应将是 ID 为 1 的列表：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/9e447b42-228b-44ff-b6dc-a8e5d91f02bc.png)图 4.3。Vuebnb Web 服务的 JSON 响应

# 控制器

随着项目的进展，我们将添加更多的路由来检索列表数据。最佳实践是使用`controller`类来实现这个功能，以保持关注点的分离。让我们使用 Artisan CLI 创建一个：

```php
$ php artisan make:controller ListingController
```

然后我们将从路由中的功能移动到一个新的方法`get_listing_api`。

`app/Http/Controllers/ListingController.php`：

```php
<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Listing;

class ListingController extends Controller
{
  public function get_listing_api(Listing $listing) 
  {
    return $listing->toJson();
  }
}
```

对于`Route::get`方法，我们可以将字符串作为第二个参数传递，而不是`closure`函数。字符串应该是`[controller]@[method]`的形式，例如`ListingController@get_listing_web`。Laravel 将在运行时正确解析这个。

`routes/api.php`：

```php
<?php Route::get('/listing/{listing}', 'ListingController@get_listing_api');
```

# 图像

正如在本章开头所述，每个模拟列表都附带了房间的几张图片。这些图片不在项目代码中，必须从代码库中名为`images`的平行目录中复制。

将此目录的内容复制到`public/images`文件夹中：

```php
$ cp -a ../images/. ./public/images
```

一旦您复制了这些文件，`public/images`将有 30 个子文件夹，每个模拟列表一个。每个文件夹将包含四张主要图片和一个缩略图图片：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/1321f4d1-eb59-49c2-b034-d5766ad72788.png)图 4.4。公共文件夹中的图像文件

# 访问图像

`public`目录中的文件可以通过将它们的相对路径附加到站点 URL 直接请求。例如，默认的 CSS 文件`public/css/app.css`可以在`http://vuebnb.test/css/app.css`请求。

使用`public`文件夹的优势，以及我们将图像放在那里的原因，是避免创建任何访问它们的逻辑。然后前端应用程序可以直接在`img`标签中调用图像。

您可能认为我们的网络服务器以这种方式提供图像是低效的，您是对的。在本书的后面，当处于生产模式时，我们将从 CDN 提供图像。

让我们尝试在浏览器中打开一个模拟列表图片来测试这个论点：`http://vuebnb.test/images/1/Image_1.jpg`：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/18bb9373-46c0-4abe-bf95-b1f3b1139b7e.png)图 4.5。在浏览器中显示的模拟列表图像

# 图片链接

Web 服务的每个列表的负载应该包括指向这些新图像的链接，这样客户端应用程序就知道在哪里找到它们。让我们将图像路径添加到我们的列表 API 负载中，使其看起来像这样：

```php
{
  "id": 1,
  "title": "...",
  "description": "...",
  ... "image_1": "http://vuebnb.test/app/image/1/Image_1.jpg",
  "image_2": "http://vuebnb.test/app/image/1/Image_2.jpg",
  "image_3": "http://vuebnb.test/app/image/1/Image_3.jpg",
  "image_4": "http://vuebnb.test/app/image/1/Image_4.jpg"
}
```

缩略图图像直到项目后期才会被使用。

为了实现这一点，我们将使用我们模型的`toArray`方法来创建模型的数组表示。然后我们将能够轻松地添加新字段。每个模拟列表都有四张图片，编号为 1 到 4，所以我们可以使用`for`循环和`asset`助手来生成公共文件夹中文件的完全合格的 URL。

最后，通过调用`response`助手创建`Response`类的实例。我们使用`json`方法并传入我们的字段数组，返回结果。

`app/Http/Controllers/ListingController.php`：

```php
public function get_listing_api(Listing $listing) 
{
  $model = $listing->toArray();
  for($i = 1; $i <=4; $i++) {
    $model['image_' . $i] = asset( 'images/' . $listing->id . '/Image_' . $i . '.jpg' );
  }
  return response()->json($model);
}
```

`/api/listing/{listing}`端点现在已准备好供客户端应用程序使用。

# 总结

在本章中，我们使用 Laravel 构建了一个 Web 服务，使 Vuebnb 列表数据可以公开访问。

这涉及使用迁移和模式设置数据库表，然后使用路由向数据库中填充模拟列表数据。然后我们创建了一个公共接口，用于返回模拟数据作为 JSON 负载，包括指向我们模拟图像的链接。

在下一章中，我们将介绍 Webpack 和 Laravel Mix 构建工具，以建立一个全栈开发环境。我们将把 Vuebnb 原型迁移到项目中，并对其进行重构以适应新的工作流程。


# 第五章：将 Laravel 和 Vue.js 集成到 Webpack 中

在本章中，我们将把 Vuebnb 前端原型迁移到我们的主要 Laravel 项目中，实现 Vuebnb 的第一个全栈迭代。这个完全集成的环境将包括一个 Webpack 构建步骤，允许我们在继续构建前端时整合更复杂的工具和技术。

本章涵盖的主题：

+   Laravel 开箱即用前端应用程序简介

+   Webpack 的高级概述

+   如何配置 Laravel Mix 来编译前端资产

+   将 Vuebnb 原型迁移到全栈 Laravel 环境中

+   在 Vue.js 中使用 ES2015，包括为旧浏览器提供语法和 polyfills

+   将前端应用程序中的硬编码数据切换为后端数据

# Laravel 前端

我们认为 Laravel 是一个后端框架，但是一个新的 Laravel 项目也包括了前端应用程序的样板代码和配置。

前端开箱即用包括 JavaScript 和 Sass 资产文件，以及一个`package.json`文件，指定依赖项，如 Vue.js、jQuery 和 Bootstrap。

让我们看看这个样板代码和配置，以便我们了解 Vuebnb 前端应用程序在我们开始迁移时将如何适应我们的 Laravel 项目。

# JavaScript

JavaScript 资产保存在`resources/assets/js`文件夹中。该目录中有几个`.js`文件，以及一个子目录`component`，其中有一个`.vue`文件。我们将在另一章节中解释后者，所以现在我们将忽略它。

主 JavaScript 文件是`app.js`。在这个文件中，你会看到熟悉的 Vue 构造函数，但也会有一些不太熟悉的语法。第一行是一个`require`函数，用于导入一个相邻的文件`bootstrap.js`，它又加载其他库，包括 jQuery 和 Lodash。

`require`不是标准的 JavaScript 函数，必须在代码在浏览器中使用之前进行解析。

`resources/assets/js/app.js`：

```php
require('./bootstrap'); window.Vue = require('vue'); Vue.component('example', require('./components/Example.vue'));

const app = new Vue({ el: '#app'
});
```

# CSS

如果你以前没有听说过*Sass*，它是一种 CSS 扩展，使开发 CSS 更容易。默认的 Laravel 安装包括`resources/assets/sass`目录，其中包括两个样板 Sass 文件。

主 Sass 文件是`app.scss`。它的工作是导入其他 Sass 文件，包括 Bootstrap CSS 框架。

`resources/assets/sass/app.scss`：

```php
// Fonts
@import url("https://fonts.googleapis.com/css?family=Raleway:300,400,600");

// Variables
@import "variables";

// Bootstrap
@import "~bootstrap-sass/assets/stylesheets/bootstrap";
```

# 节点模块

Laravel 前端的另一个关键方面是项目目录根目录中的`package.json`文件。与`composer.json`类似，该文件用于配置和依赖管理，只不过是用于 Node 模块而不是 PHP。

`package.json`的属性之一是`devDependencies`，指定了开发环境中需要的模块，包括 jQuery、Vue 和 Lodash。

`package.json`：

```php
{ ... "devDependencies": {
    "axios": "⁰.17",
    "bootstrap-sass": "³.3.7",
    "cross-env": "⁵.1",
    "jquery": "³.2",
    "laravel-mix": "¹.4",
    "lodash": "⁴.17.4",
    "vue": "².5.3"
  }
}
```

# 视图

要在 Laravel 中提供前端应用程序，需要将其包含在视图中。唯一提供的开箱即用视图是位于`resources/views/welcome.blade.php`的`welcome`视图，用作样板首页。

`welcome`视图实际上不包括前端应用程序，用户需要自行安装。我们将在本章后面讨论如何做到这一点。

# 资产编译

`resources/assets`中的文件包括不能直接在浏览器中使用的函数和语法。例如，在`app.js`中使用的`require`方法，用于导入 JavaScript 模块，不是原生 JavaScript 方法，也不是标准 Web API 的一部分：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/9687148e-76da-46c2-8876-0ac1a022d93b.png)图 5.1. 浏览器中未定义`require`

需要一个构建工具来获取这些资产文件，解析任何非标准函数和语法，并输出浏览器可以使用的代码。前端资产有许多流行的构建工具，包括 Grunt、Gulp 和 Webpack：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/bf0b1519-498e-4862-89e3-418509ed2104.png)图 5.2. 资产编译过程

我们之所以要使用这个资产编译过程，是为了能够在不受浏览器限制的情况下编写我们的前端应用。我们可以引入各种方便的开发工具和功能，这些工具和功能将使我们更容易地编写代码和解决问题。

# Webpack

Webpack 是 Laravel 5.5 默认提供的构建工具，我们将在 Vuebnb 的开发中使用它。

Webpack 与其他流行的构建工具（如 Gulp 和 Grunt）不同之处在于，它首先是一个*模块打包工具*。让我们通过了解模块打包过程的工作原理来开始我们对 Webpack 的概述。

# 依赖

在前端应用中，我们可能会有第三方 JavaScript 库或甚至自己代码库中的其他文件的依赖关系。例如，Vuebnb 原型依赖于 Vue.js 和模拟列表数据文件：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/5a6df745-de9c-465b-b804-0dec5598bfc7.png)图 5.3。Vuebnb 原型依赖关系

除了确保任何共享的函数和变量具有全局范围，并且脚本按正确的顺序加载外，在浏览器中没有真正的方法来管理这些依赖关系。

例如，由于`node_modules/vue/dist/vue.js`定义了全局的`Vue`对象并且首先加载，我们可以在`app.js`脚本中使用`Vue`对象。如果不满足这两个条件中的任何一个，当`app.js`运行时，`Vue`将未被定义，导致错误：

```php
<script src="node_modules/vue/dist/vue.js"></script>
<script src="sample/data.js"></script>
<script src="app.js"></script>
```

这个系统有一些缺点：

+   全局变量引入了命名冲突和意外变异的可能性

+   脚本加载顺序是脆弱的，随着应用程序的增长很容易被破坏

+   我们无法利用性能优化，比如异步加载脚本

# 模块

解决依赖管理问题的一个方法是使用 CommonJS 或原生 ES 模块等模块系统。这些系统允许 JavaScript 代码模块化，并导入到其他文件中。

这里是一个 CommonJS 的例子：

```php
// moduleA.js module.exports = function(value) {
  return value * 2;
}

// moduleB.js
var multiplyByTwo = require('./moduleA'); console.log(multiplyByTwo(2));

// Output: 4
```

这里是一个原生 ES 模块的例子：

```php
// moduleA.js
export default function(value) {
  return value * 2;
}

// moduleB.js
import multiplyByTwo from './moduleA'; console.log(multiplyByTwo(2)); // Output: 4
```

问题在于 CommonJS 不能在浏览器中使用（它是为服务器端 JavaScript 设计的），而原生 ES 模块现在才开始得到浏览器支持。如果我们想在项目中使用模块系统，我们需要一个构建工具：Webpack。

# 打包

将模块解析为适合浏览器的代码的过程称为**打包**。Webpack 从**入口文件**开始打包过程。在 Laravel 前端应用中，`resources/assets/js/app.js`是入口文件。

Webpack 分析入口文件以找到任何依赖关系。在`app.js`的情况下，它会找到三个：`bootstrap`、`vue`和`Example.vue`。

`resources/assets/js/app.js`：

```php
require('./bootstrap'); window.Vue = require('vue'); Vue.component('example', require('./components/Example.vue'));

...
```

Webpack 将解析这些依赖关系，然后分析它们以找到它们可能具有的任何依赖关系。这个过程会一直持续，直到找到项目的所有依赖关系。结果是一个依赖关系图，在一个大型项目中，可能包括数百个不同的模块。

Webpack 将这些依赖关系图作为打包所有代码到单个适合浏览器的文件的蓝图：

```php
<script src="bundle.js"></script>
```

# 加载器

Webpack 之所以如此强大的部分原因是，在打包过程中，它可以使用一个或多个 Webpack 加载器来*转换*模块。

例如，*Babel*是一个编译器，将下一代 JavaScript 语法（如 ES2015）转换为标准的 ES5。Webpack Babel 加载器是最受欢迎的加载器之一，因为它允许开发人员使用现代特性编写他们的代码，但仍然在旧版浏览器中提供支持。

例如，在入口文件中，我们看到了 IE10 不支持的 ES2015 `const`声明。

`resources/assets/js/app.js`：

```php
const app = new Vue({ el: '#app'
});
```

如果使用了 Babel 加载器，`const`将在添加到包中之前被转换为`var`。

`public/js/app.js`：

```php
var app = new Vue({ el: '#app'
});
```

# Laravel Mix

Webpack 的一个缺点是配置它很繁琐。为了简化事情，Laravel 包含一个名为*Mix*的模块，它将最常用的 Webpack 选项放在一个简单的 API 后面。

Mix 配置文件可以在项目目录的根目录中找到。Mix 配置涉及将方法链接到`mix`对象，声明应用程序的基本构建步骤。例如，`js`方法接受两个参数，入口文件和输出目录，默认情况下应用 Babel 加载器。`sass`方法以类似的方式工作。

`webpack.mix.js`：

```php
let mix = require('laravel-mix'); mix.js('resources/assets/js/app.js', 'public/js')
  .sass('resources/assets/sass/app.scss', 'public/css');
```

# 运行 Webpack

现在我们对 Webpack 有了一个高层次的理解，让我们运行它并看看它是如何捆绑默认的前端资产文件的。

首先，确保您已安装所有开发依赖项：

```php
$ npm install
```

# CLI

通常情况下，Webpack 是从命令行运行的，例如：

```php
$ webpack [options]
```

与其自己找出正确的 CLI 选项，我们可以使用`package.json`中预定义的 Weback 脚本之一。例如，`development`脚本将使用适合创建开发构建的选项运行 Webpack。

`package.json`：

```php
"scripts": {
  ...
  "development": "cross-env NODE_ENV=development node_modules/webpack/bin/webpack.js --progress --hide-modules --config=node_modules/laravel-mix/setup/webpack.config.js",
  ...
}
```

# 首次构建

现在让我们运行`dev`脚本（`development`脚本的快捷方式）：

```php
$ npm run dev
```

运行后，您应该在终端中看到类似以下的输出：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/6ad468e2-6365-48eb-a310-d318e82f8f4d.png)图 5.4. Webpack 终端输出

这个输出告诉我们很多事情，但最重要的是构建成功了，以及输出了哪些文件，包括字体、JavaScript 和 CSS。请注意，输出文件路径是相对于`public`目录而不是项目根目录，所以`js/apps.js`文件将在`public/js/app.js`找到。

# JavaScript

检查输出的 JavaScript 文件`public/js/app.js`，我们会看到里面有大量的代码 - 大约 42,000 行！这是因为 jQuery、Lodash、Vue 和其他 JavaScript 依赖项都被捆绑到这个文件中。这也是因为我们使用了不包括缩小或丑化的开发构建。

如果您搜索文件，您会看到我们的入口文件`app.js`的代码已经按预期转换为 ES5：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/63bd67a1-8729-460c-b088-42e7291fc09b.png)图 5.5. 捆绑文件 public/js/app.js

# CSS

我们还有一个 CSS 捆绑文件`public/css/app.css`。如果您检查这个文件，您会发现导入的 Bootstrap CSS 框架已经包含在内，Sass 语法已经编译成普通的 CSS。

# 字体

你可能会觉得奇怪的是输出中有字体，因为 Mix 没有包含任何显式的字体配置。这些字体是 Bootstrap CSS 框架的依赖项，Mix 默认会将它们单独输出而不是打包成一个字体包。

# 迁移 Vuebnb

现在我们熟悉了默认的 Laravel 前端应用程序代码和配置，我们准备将 Vuebnb 原型迁移到主项目中。这个迁移将允许我们将所有源代码放在一个地方，而且我们可以利用这个更复杂的开发环境来构建 Vuebnb 的其余部分。

迁移将涉及：

1.  移除任何不必要的模块和文件

1.  将原型文件移动到 Laravel 项目结构中

1.  修改原型文件以适应新环境

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/2938293a-97c3-4d88-bdbd-1bcc5ee042b9.png)图 5.6. Vuebnb 原型迁移

# 移除不必要的依赖项和文件

让我们首先移除我们不再需要的 Node 依赖项。我们将保留`axis`，因为它将在后面的章节中使用，以及`cross-env`，因为它确保我们的 NPM 脚本可以在各种环境中运行。我们将摆脱其余的：

```php
$ npm uninstall bootstrap-sass jquery lodash --save-dev
```

这个命令会让你的开发依赖项看起来像这样。

`package.json`：

```php
"devDependencies": {
  "axios": "⁰.17",
  "cross-env": "⁵.1",
  "laravel-mix": "¹.4",
  "vue": "².5.3"
}
```

接下来，我们将移除我们不需要的文件。这包括几个 JavaScript 资产，所有的 Sass 以及`welcome`视图：

```php
$ rm -rf \
resources/assets/js/app.js \
resources/assets/js/bootstrap.js \
resources/assets/js/components/* \
resources/assets/sass \
resources/views/welcome.blade.php
```

由于我们正在移除所有 Sass 文件，我们还需要在 Mix 配置中移除`sass`方法。

`webpack.mix.js`：

```php
let mix = require('laravel-mix'); mix .js('resources/assets/js/app.js', 'public/js')
;
```

现在我们的前端应用程序没有杂乱的东西，我们可以将原型文件移动到它们的新家。

# HTML

现在让我们将原型项目中的`index.html`的内容复制到一个新文件`app.blade.php`中。这将允许模板作为 Laravel 视图使用：

```php
$ cp ../vuebnb-prototype/index.html ./resources/views/app.blade.php
```

我们还将更新主页 web 路由，指向这个新视图而不是欢迎页面。

`routes/web.php`:

```php
<?php Route::get('/', function () {
  return view('app');
});
```

# 语法冲突

使用原型模板文件作为视图会导致一个小问题，因为 Vue 和 Blade 共享相同的语法。例如，查看 Vue.js 在标题部分插入标题和列表地址的地方。

`resources/views/app.blade.php`:

```php
<div class="heading">
  <h1>{{ title }}</h1>
  <p>{{ address }}</p>
</div>
```

当 Blade 处理这个时，它会认为双大括号是它自己的语法，并且会生成一个 PHP 错误，因为`title`和`address`都不是定义的函数。

有一个简单的解决方案：通过在双大括号前加上`@`符号来让 Blade 知道忽略它们。这可以通过在前面加上`@`符号来实现。

`resources/views/app.blade.php`:

```php
<div class="heading">
  <h1>@{{ title }}</h1>
  <p>@{{ address }}</p>
</div>
```

在文件中的每一组双大括号中完成这些操作后，加载浏览器中的主页路由以测试新视图。没有 JavaScript 或 CSS，它看起来不太好，但至少我们可以确认它可以工作：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/d297a0df-877b-4072-a869-98891fd553f0.png)图 5.7。主页路由

# JavaScript

现在让我们将原型的主要脚本文件`app.js`移动到 Laravel 项目中：

```php
$ cp ../vuebnb-prototype/app.js ./resources/assets/js/
```

根据当前的 Mix 设置，这将成为 JavaScript 捆绑包的入口文件。这意味着视图底部的 JavaScript 依赖项可以被捆绑包替换。

`resources/views/app.blade.php`:

```php
<script src="node_modules/vue/dist/vue.js"></script>
<script src="sample/data.js"></script>
<script src="app.js"></script>
```

可以被替换为，

`resources/views/app.blade.php`:

```php
<script src="{{ asset('js/app.js') }}"></script>
```

# 模拟数据依赖项

让我们也将模拟数据依赖项复制到项目中：

```php
$ cp ../vuebnb-prototype/sample/data.js ./resources/assets/js/
```

目前，这个文件声明了一个全局变量`sample`，然后在入口文件中被引用。让我们通过用 ES2015 的`export default`替换变量声明来将这个文件变成一个模块。

`resources/assets/js/data.js`:

```php
export default {
 ...
}
```

现在我们可以在我们的入口文件顶部导入这个模块。请注意，Webpack 可以在导入语句中猜测文件扩展名，因此您可以省略`data.js`中的`.js`。

`resources/assets/js/app.js`:

```php
import sample from './data';

var app = new Vue({
  ...
});
```

虽然 Laravel 选择使用 CommonJS 语法来包含模块，即`require`，但我们将使用原生 ES 模块语法，即`import`。这是因为 ES 模块正在成为 JavaScript 标准的一部分，并且它更符合 Vue 使用的语法。

# 使用 Webpack 显示模块

让我们运行 Webpack 构建，确保 JavaScript 迁移到目前为止是有效的：

```php
$ npm run dev
```

如果一切顺利，您将看到 JavaScript 捆绑文件被输出：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/bc3060e9-abb3-4da4-b9fc-918d2bdecdaa.png)图 5.8。Webpack 终端输出

很好地知道模拟数据依赖项是如何添加的，而不必手动检查捆绑包以找到代码。我们可以通过告诉 Webpack 在终端输出中打印它处理过的模块来实现这一点。

在我们的`package.json`的`development`脚本中，设置了一个`--hide-modules`标志，因为一些开发人员更喜欢简洁的输出消息。让我们暂时将其移除，而是添加`--display-modules`标志，使脚本看起来像这样：

```php
"scripts": { ... "development": "cross-env NODE_ENV=development node_modules/webpack/bin/webpack.js --progress --display-modules --config=node_modules/laravel-mix/setup/webpack.config.js", ... }
```

现在再次运行构建，我们会得到更详细的终端输出：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/6df01ea4-90bf-477f-a649-b37a04ae4c36.png)图 5.9。带有 display-modules 标志的 Webpack 终端输出

这可以确保我们的`app.js`和`data.js`文件都包含在捆绑包中。

# Vue.js 依赖项

现在让我们将 Vue.js 作为我们入口文件的依赖项导入。

`resources/assets/js/app.js`:

```php
import Vue from 'vue';
import sample from './data';

var app = new Vue({
  ...
});
```

再次运行构建，我们现在会在终端输出中看到 Vue.js 在模块列表中，以及它引入的一些依赖项：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/8c460263-f2d3-40b6-8dd6-0ace4c0d1278.png)图 5.10。显示 Vue.js 的 Webpack 终端输出

你可能想知道`import Vue from 'vue'`是如何解析的，因为它似乎不是一个正确的文件引用。Webpack 默认会在项目的`node_modules`文件夹中检查任何依赖项，这样就不需要将`import Vue from 'node_modules/vue';`放在项目中了。

但是，它又是如何知道这个包的入口文件呢？看一下前面截图中的 Webpack 终端输出，你会看到它已经包含了`node_modules/vue/dist/vue.common.js`。它知道要使用这个文件，是因为当 Webpack 将节点模块添加为依赖项时，它会检查它们的`package.json`文件，并查找`main`属性，而在 Vue 的情况下是。

`node_modules/vue/package.json`：

```php
{ ... "main": "dist/vue.runtime.common.js", ... }
```

但是，Laravel Mix 会覆盖这一点，以强制使用不同的 Vue 构建。

`node_modules/laravel-mix/setup/webpack.config.js`：

```php
alias: {
  'vue$': 'vue/dist/vue.common.js'
}
```

简而言之，`import Vue from 'vue'`实际上与`import Vue from 'node_modules/vue/dist/vue.common.js'`是一样的。

我们将在第六章中解释不同的 Vue 构建，*使用 Vue.js 组件组合小部件*。

搞定了，我们的 JavaScript 已成功迁移。再次加载主页路由，我们现在可以更好地看到 Vuebnb 的列表页面，其中包括 JavaScript：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/b177096b-bc47-4952-b83d-8c01b30b73b9.png)图 5.11.带有 JavaScript 迁移的主页路由

# CSS

要迁移 CSS，我们将从原型中复制`style.css`到 Laravel 项目中。默认的 Laravel 前端应用程序使用 Sass 而不是 CSS，因此我们需要先为 CSS 资产创建一个目录：

```php
$ mkdir ./resources/assets/css
$ cp ../vuebnb-prototype/style.css ./resources/assets/css/
```

然后在我们的 Mix 配置中进行新的声明，使用`styles`方法获取一个 CSS 捆绑包。

`webpack.mix.js`：

```php
mix .js('resources/assets/js/app.js', 'public/js')
  .styles('resources/assets/css/style.css', 'public/css/style.css')
;
```

现在我们将在视图中链接到 CSS 捆绑包，更新链接的`href`。

`resources/views/app.blade.php`：

```php
<link rel="stylesheet" href="{{ asset('css/style.css') }}" type="text/css">
```

# 字体样式

我们还有 Open Sans 和 Font Awesome 样式表要包含。首先，使用 NPM 安装字体包：

```php
$ npm i --save-dev font-awesome open-sans-all
```

我们将修改我们的 Mix 配置，将我们的应用程序 CSS、Open Sans 和 Font Awesome CSS 捆绑在一起。我们可以通过将数组传递给`styles`方法的第一个参数来实现这一点。

`webpack.mix.js`：

```php
mix .js('resources/assets/js/app.js', 'public/js')
  .styles([
    'node_modules/open-sans-all/css/open-sans.css',
    'node_modules/font-awesome/css/font-awesome.css',
    'resources/assets/css/style.css'
```

```php
  ], 'public/css/style.css')
;
```

Mix 将在终端输出中附加有关 CSS 捆绑包的统计信息：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/c4a097b9-3772-4381-8d74-5433c0bc8d85.png)图 5.12.带有 CSS 的 Webpack 终端输出

记得从视图中删除对字体样式表的链接，因为现在它们将在 CSS 捆绑包中。

# 字体

Open Sans 和 Font Awesome 都需要一个 CSS 样式表和相关的字体文件。与 CSS 一样，Webpack 可以将字体捆绑为模块，但我们目前不需要利用这一点。相反，我们将使用`copy`方法，告诉 Mix 将字体从它们的主目录复制到`public`文件夹中，这样前端应用程序就可以访问它们了。

`webpack.mix.js`：

```php
mix .js('resources/assets/js/app.js', 'public/js')
  .styles([
    'node_modules/open-sans-all/css/open-sans.css',
    'node_modules/font-awesome/css/font-awesome.css',
    'resources/assets/css/style.css'
  ], 'public/css/style.css')
  .copy('node_modules/open-sans-all/fonts',  'public/fonts')
  .copy('node_modules/font-awesome/fonts',  'public/fonts')
;
```

再次构建后，您现在将在项目结构中看到一个`public/fonts`文件夹。

# 图像

我们现在将迁移图像，包括工具栏的标志和模拟数据标题图像：

```php
$ cp ../vuebnb-prototype/logo.png ./resources/assets/images/
$ cp ../vuebnb-prototype/sample/header.jpg ./resources/assets/images/
```

让我们再链上另一个`copy`方法，将它们包含在`public/images`目录中。

`webpack.mix.js`：

```php
mix .js('resources/assets/js/app.js', 'public/js')
  .styles([
    'node_modules/open-sans-all/css/open-sans.css',
    'node_modules/font-awesome/css/font-awesome.css',
    'resources/assets/css/style.css'
  ], 'public/css/style.css')
  .copy('node_modules/open-sans-all/fonts',  'public/fonts')
  .copy('node_modules/font-awesome/fonts',  'public/fonts')
  .copy('resources/assets/images', 'public/images')
;
```

我们还需要确保视图指向正确的图像文件位置。在工具栏中。

`resources/views/app.blade.php`：

```php
<div id="toolbar">
  <img class="icon" src="{{ asset('images/logo.png') }}">
  <h1>vuebnb</h1>
</div>
```

以及在模态框中。

`resources/views/app.blade.php`：

```php
<div class="modal-content">
  <img src="{{ asset('images/header.jpg') }}"/>
</div>
```

不要忘记需要更新入口文件中的`headerImageStyle`数据属性。

`resources/assets/js/app.js`：

```php
headerImageStyle: {
  'background-image': 'url(/images/header.jpg)'
},
```

虽然不完全是一张图片，我们也将迁移`favicon`。这可以直接放入`public`文件夹中：

```php
$ cp ../vuebnb-prototype/favicon.ico ./public
```

再次构建后，我们现在将完全迁移 Vuebnb 客户端应用程序原型：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/402bf3b1-0a52-4dd7-843e-7780f2577cbe.png)图 5.13.从 Laravel 提供的 Vuebnb 客户端应用程序原型

# 开发工具

我们可以利用一些方便的开发工具来改进我们的前端工作流程，包括：

+   监视模式

+   BrowserSync

# 监视模式

到目前为止，我们一直在每次进行更改时手动运行应用程序的构建，使用`npm run dev`。Webpack 还有一个观察模式，在这种模式下，当依赖项发生更改时，它会自动运行构建。由于 Webpack 的设计，它能够通过仅重新构建已更改的模块来高效地完成这些自动构建。

要使用观察模式，请运行`package.json`中包含的`watch`脚本：

```php
$ npm run watch
```

要测试它是否有效，请在`resources/assets/js/app.js`的底部添加以下内容：

```php
console.log("Testing watch");
```

如果观察模式正在正确运行，保存此文件将触发构建，并且您将在终端中看到更新的构建统计信息。然后刷新页面，您将在控制台中看到测试观察模式的消息。

要关闭观察模式，在终端中按*Ctrl* + *C*。然后可以随时重新启动。不要忘记在满意观察模式工作后删除`console.log`。

我假设您在本书的其余部分中都在使用*watch*，所以我不会再提醒您在更改后构建项目了！

# BrowserSync

另一个有用的开发工具是 BrowserSync。与观察模式类似，BrowserSync 监视文件的更改，当发生更改时，将更改插入浏览器。这样可以避免在每次构建后手动刷新浏览器。

要使用 BrowserSync，您需要安装 Yarn 软件包管理器。如果您在 Vagrant Box 中运行终端命令，那么您已经准备就绪，因为 Yarn 已预先安装在 Homestead 中。否则，请按照此处的 Yarn 安装说明进行安装：[`yarnpkg.com/en/docs/install`](https://yarnpkg.com/en/docs/install)。

BrowserSync 已与 Mix 集成，并且可以通过在 Mix 配置中调用`browserSync`方法来使用。传递一个带有应用程序 URL 作为`proxy`属性的选项对象，例如，`browserSync({ proxy: http://vuebnb.test })`。

我们将应用程序的 URL 存储为`.env`文件中的环境变量，因此让我们从那里获取它，而不是硬编码到我们的 Mix 文件中。首先，安装 NPM `dotenv`模块，它将`.env`文件读入 Node 项目中：

```php
$ npm i dotenv --save-devpm
```

在 Mix 配置文件的顶部要求`dotenv`模块，并使用`config`方法加载`.env`。然后环境变量将作为`process.env`对象的属性可用。

现在我们可以将一个带有`process.env.APP_URL`分配给`proxy`的选项对象传递给`browserSync`方法。我还喜欢使用`open: false`选项，这样可以防止 BrowserSync 自动打开一个标签页。

`webpack.mix.js`：

```php
require('dotenv').config();
let mix = require('laravel-mix'); mix ...
  .browserSync({ proxy: process.env.APP_URL, open: false
  })
;
```

BrowserSync 默认在自己的端口`3000`上运行。当您再次运行`npm run watch`时，在`localhost:3000`上打开一个新标签页。在对代码进行更改后，您会发现这些更改会自动反映在此 BrowserSync 标签页中！

请注意，如果您在 Homestead 框中运行 BrowserSync，可以在`vuebnb.test:3000`上访问它。

即使 BrowserSync 服务器在不同的端口上运行，我将继续在应用程序中引用 URL 而不指定端口，以避免任何混淆，例如，`vuebnb.test`而不是`localhost:3000`或`vuebnb.test:3000`。

# ES2015

`js` Mix 方法将 Babel 插件应用于 Webpack，确保任何 ES2015 代码在添加到捆绑文件之前被转译为浏览器友好的 ES5。

我们使用 ES5 语法编写了 Vuebnb 前端应用程序原型，因为我们直接在浏览器中运行它，没有任何构建步骤。但现在我们可以利用 ES2015 语法，其中包括许多方便的功能。

例如，我们可以使用一种简写方式将函数分配给对象属性。

`resources/assets/js/app.js`：

```php
escapeKeyListener: function(evt) {
  ...
}
```

可以更改为：

```php
escapeKeyListener(evt) {
  ...
}
```

在`app.js`中有几个这样的实例，我们可以更改。尽管在我们的代码中还没有其他使用 ES2015 语法的机会，但在接下来的章节中我们会看到更多。

# Polyfills

ES2015 提案包括新的语法，还包括新的 API，如`Promise`，以及对现有 API 的添加，如`Array`和`Object`。

Webpack Babel 插件可以转译 ES2015 语法，但新的 API 方法需要进行 polyfill。**Polyfill**是在浏览器中运行的脚本，用于覆盖可能缺失的 API 或 API 方法。

例如，`Object.assign`是一个新的 API 方法，在 Internet Explorer 11 中不受支持。如果我们想在前端应用程序中使用它，我们必须在脚本的顶部检查 API 方法是否存在，如果不存在，则使用 polyfill 手动定义它：

```php
if (typeof Object.assign != 'function') {
  // Polyfill to define Object.assign
}
```

说到这一点，`Object.assign`是合并对象的一种方便方法，在我们的前端应用程序中会很有用。让我们在我们的代码中使用它，然后添加一个 polyfill 来确保代码在旧版浏览器中运行。

查看我们入口文件`resources/assets/js/app.js`中的`data`对象。我们手动将`sample`对象的每个属性分配给`data`对象，给它相同的属性名。为了避免重复，我们可以使用`Object.assign`来简单地合并这两个对象。实际上，这并没有做任何不同的事情，只是更简洁的代码。

`resources/assets/js/app.js`:

```php
data: Object.assign(sample, { headerImageStyle: {
    'background-image': 'url(/images/header.jpg)'
  }, contracted: true, modalOpen: false
}),
```

为了 polyfill`Object.assign`，我们必须安装一个新的`core-js`依赖项，这是一个为大多数新的 JavaScript API 提供 polyfill 的库。我们稍后将在项目中使用一些其他`core-js`的 polyfill：

```php
$ npm i --save-dev core-js
```

在`app.js`的顶部，添加以下行以包含`Object.assign`的 polyfill：

```php
import "core-js/fn/object/assign";
```

构建完成后，刷新页面以查看是否有效。除非您可以在旧版浏览器（如 Internet Explorer）上测试，否则您很可能不会注意到任何区别，但现在您可以确保这段代码几乎可以在任何地方运行。

# 模拟数据

我们现在已经完全将 Vuebnb 原型迁移到了我们的 Laravel 项目中，并且我们已经添加了一个构建步骤。前端应用程序中的一切都像第二章中的一样工作，*Vuebnb 原型设计，您的第一个 Vue.js 项目*。

但是，我们仍然在前端应用程序中硬编码了模拟数据。在本章的最后部分，我们将删除这些硬编码的数据，并用后端数据替换它。

# 路由

目前，主页路由，即`*/*`，加载我们的前端应用程序。但是，我们迄今为止构建的前端应用程序并不是一个主页！我们将在以后的章节中构建它。

我们构建的是*listing*页面，应该在类似`/listing/5`的路由上，其中`5`是正在使用的模拟数据列表的 ID。

| 页面 | 路由 |
| --- | --- |
| 主页 | / |
| 列表页面 | /listing/{listing} |

让我们修改路由以反映这一点。

`routes/web.php`:

```php
<?php

use App\Listing; Route::get('/listing/{listing}', function ($id) {
  return view('app');
});
```

就像在我们的`api/listing/{listing}`路由中一样，动态段意味着要匹配我们模拟数据列表中的一个 ID。如果您还记得上一章，我们创建了 30 个模拟数据列表，ID 范围是 1 到 30。

如果我们现在在`闭包`函数的配置文件中对`Listing`模型进行类型提示，Laravel 的服务容器将传递一个与动态路由段匹配的 ID 的模型。

`routes/web.php`:

```php
Route::get('/listing/{listing}', function (Listing $listing) {
  // echo $listing->id // will equal 5 for route /listing/5
  return view('app');
});
```

一个很酷的内置功能是，如果动态段与模型不匹配，例如`/listing/50`或`/listing/somestring`，Laravel 将中止路由并返回 404。

# 架构

考虑到我们可以在路由处理程序中检索到正确的列表模型，并且由于 Blade 模板系统的存在，我们可以动态地将内容插入到我们的*app*视图中，一个明显的架构出现了：我们可以将模型注入到页面的头部。这样，当 Vue 应用程序加载时，它将立即访问模型：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/ced66f3d-6116-4340-99d0-a9785f410ac5.png)图 5.14。将内联列表模型插入页面的头部

# 注入数据

将模拟列表数据传递到客户端应用程序将需要几个步骤。我们将首先将模型转换为数组。然后可以使用`view`助手在模板中运行时使模型可用。

`routes/web.php`:

```php
Route::get('/listing/{listing}', function (Listing $listing) {
  $model = $listing->toArray();
  return view('app', [ 'model' => $model ]);
});
```

现在，在 Blade 模板中，我们将在文档的头部创建一个脚本。通过使用双花括号，我们可以直接将模型插入脚本中。

`resources/views/app.blade.php`：

```php
<head> ... <script type="text/javascript"> console.log({{ $model[ 'id' ] }}); </script>
</head>
```

现在，如果我们转到`/listing/5`路由，我们将在页面源代码中看到以下内容：

```php
<script type="text/javascript"> console.log(5); </script>
```

并且您将在控制台中看到以下内容：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/5b075b90-99d1-483b-ab29-0062fbf83768.png)图 5.15。注入模型 ID 后的控制台输出

# JSON

现在我们将整个模型编码为 JSON 放在视图中。JSON 格式很好，因为它可以存储为字符串，并且可以被 PHP 和 JavaScript 解析。

在我们的内联脚本中，让我们将模型格式化为 JSON 字符串并分配给`model`变量。

`resources/views/app.blade.php`：

```php
<script type="text/javascript"> var model = "{!! addslashes(json_encode($model)) !!}"; console.log(model); </script>
```

请注意，我们还必须在另一个全局函数`addslashes`中包装`json_encode`。这个函数将在需要转义的任何字符之前添加反斜杠。这是必要的，因为 JavaScript JSON 解析器不知道字符串中的引号是 JavaScript 语法的一部分，还是 JSON 对象的一部分。

我们还必须使用不同类型的 Blade 语法进行插值。Blade 的一个特性是，双花括号`{{ }}`中的语句会自动通过 PHP 的`htmlspecialchars`函数发送，以防止 XSS 攻击。不幸的是，这将使我们的 JSON 对象无效。解决方案是使用替代的`{!! !!}`语法，它不会验证内容。在这种情况下这样做是安全的，因为我们确定我们没有使用任何用户提供的内容。

现在，如果我们刷新页面，我们将在控制台中看到 JSON 对象作为字符串：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/b553cf66-4c47-41bd-aec4-bc08db5e1316.png)图 5.16。控制台中的 JSON 字符串模型

如果我们将日志命令更改为`console.log(JSON.parse(model));`，我们将看到我们的模型不是一个字符串，而是一个 JavaScript 对象：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/3eee0596-4d8d-4a4f-b1f4-38bcd82c946b.png)图 5.17。控制台中的对象模型

我们现在已经成功地将我们的模型从后端传递到前端应用程序！

# 在脚本之间共享数据

现在我们有另一个问题要克服。文档头部的内联脚本，其中包含我们的模型对象，与我们的客户端应用程序所在的脚本不同，这是需要的地方。

正如我们在前一节中讨论的，通常不建议使用多个脚本和全局变量，因为它们会使应用程序变得脆弱。但在这种情况下，它们是必需的。在两个脚本之间安全共享对象或函数的最佳方法是将其作为全局`window`对象的属性。这样，从您的代码中很明显，您有意使用全局变量：

```php
// scriptA.js window.myvar = 'Hello World';

// scriptB.js console.log(window.myvar); // Hello World
```

如果您向项目添加其他脚本，特别是第三方脚本，它们可能也会添加到`window`对象，并且可能会发生命名冲突的可能性。为了尽量避免这种情况，我们将确保使用非常特定的属性名称。

`resources/views/app.blade.php`：

```php
<script type="text/javascript"> window.vuebnb_listing_model = "{!! addslashes(json_encode($model)) !!}" </script>
```

现在，在前端应用程序的入口文件中，我们可以在脚本中使用这个`window`属性。

`resources/assets/js/app.js`：

```php
let model = JSON.parse(window.vuebnb_listing_model);

var app = new Vue({
  ...
});
```

# 替换硬编码的模型

现在我们可以在入口文件中访问我们的列表模型，让我们将其与`data`属性分配中的硬编码模型进行交换。

`resources/assets/js/app.js`：

```php
let model = JSON.parse(window.vuebnb_listing_model);

var app = new Vue({ el: '#app' data: Object.assign(model, {
    ...
  })
  ...
});
```

完成后，我们现在可以从`app.js`的顶部删除`import sample from './data';`语句。我们还可以删除示例数据文件，因为它们在项目中将不再使用：

```php
$ rm resources/assets/js/data.js resources/assets/images/header.jpg
```

# 设施和价格

如果您现在刷新页面，它将加载，但脚本将出现一些错误。问题在于设施和价格数据在前端应用程序中的结构与后端中的结构不同。这是因为模型最初来自我们的数据库，它存储标量值。在 JavaScript 中，我们可以使用更丰富的对象，允许我们嵌套数据，使其更容易处理和操作。

这是模型对象当前的外观。请注意，设施和价格是标量值：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/064fd314-22ec-49e0-b643-11027566d74b.png)图 5.18。列表模型当前的外观

这就是我们需要的样子，包括设施和价格作为数组：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/dc6c4b95-eaec-4ade-a5d3-b139eb7c53a8.png)图 5.19。列表模型应该的外观

为了解决这个问题，我们需要在将模型传递给 Vue 之前对其进行转换。为了让您不必过多考虑这个问题，我已经将转换函数放入了一个文件`resources/assets/js/helpers.js`中。这个文件是一个 JavaScript 模块，我们可以将其导入到我们的入口文件中，并通过简单地将模型对象传递给函数来使用它。

`resources/assets/js/app.js`：

```php
import Vue from 'vue';
import { populateAmenitiesAndPrices } from './helpers';

let model = JSON.parse(window.vuebnb_listing_model); model = populateAmenitiesAndPrices(model)</span>;
```

完成这些步骤并刷新页面后，我们应该在页面的文本部分看到新的模型数据（尽管图像仍然是硬编码的）：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/32f99369-737e-4291-9e7e-f446a63555f3.png)图 5.20。页面中的新模型数据与硬编码的图像

# 图像 URL

最后要做的事情是替换前端应用程序中的硬编码图像 URL。这些 URL 目前不是模型的一部分，因此需要在将其注入模板之前手动添加到模型中。

我们已经在第四章中做了一个非常类似的工作，*使用 Laravel 构建 Web 服务*，用于 API 列表路由。

`app/Http/Controllers/ListingController.php`：

```php
public function get_listing_api(Listing $listing) 
{ $model = $listing->toArray();
  for($i = 1; $i <=4; $i++) { $model['image_' . $i] = asset(
      'images/' . $listing->id . '/Image_' . $i . '.jpg'
    );
  }
  return response()->json($model);
}
```

实际上，我们的 web 路由最终将与这个 API 路由的代码相同，只是不返回 JSON，而是返回一个视图。

让我们分享共同的逻辑。首先将路由闭包函数移动到列表控制器中的一个新的`get_listing_web`方法。

`app/Http/Controllers/ListingController.php`：

```php
<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Listing;

class ListingController extends Controller
{
  public function get_listing_api(Listing $listing) 
  {
    ...
  }

  public function get_listing_web(Listing $listing) 
  {
    $model = $listing->toArray();
    return view('app', ['model' => $model]);
  }
}
```

然后调整路由以调用这个新的控制器方法。

`routes/web.php`：

```php
<?php Route::get('/listing/{listing}', 'ListingController@get_listing_web');
```

现在让我们更新控制器，使得*web*和 API 路由都将图像的 URL 添加到它们的模型中。我们首先创建一个新的`add_image_urls`方法，它抽象了在`get_listing_api`中使用的逻辑。现在路由处理方法都将调用这个新方法。

`app/Http/Controllers/ListingController.php`：

```php
<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Listing;

class ListingController extends Controller
{
  private function add_image_urls($model, $id) 
  {
    for($i = 1; $i <=4; $i++) {
      $model['image_' . $i] = asset(
        'images/' . $id . '/Image_' . $i . '.jpg'
      );
    }
    return $model;
  }

  public function get_listing_api(Listing $listing) 
  {
    $model = $listing->toArray();
    $model = $this->add_image_urls($model, $listing->id);
    return response()->json($model);
  }

  public function get_listing_web(Listing $listing) 
  {
    $model = $listing->toArray();
    $model = $this->add_image_urls($model, $listing->id);
```

```php
    return view('app', ['model' => $model]);
  }
}
```

完成后，如果我们刷新应用并打开 Vue Devtools，我们应该看到我们有图像 URL 作为`images`数据属性：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/2a17020d-30e8-4f25-ad17-192ecc32b947.png)图 5.21。如 Vue Devtools 中所示，图像现在是一个数据属性

# 替换硬编码的图像 URL

最后一步是使用后端的图像 URL，而不是硬编码的 URL。记住`images`是一个 URL 数组，我们将使用第一个图像作为默认值，即`images[0]`。

首先，我们将更新入口文件，

`resources/assets/js/app.js`：

```php
headerImageStyle: {
  'background-image': `url(${model.images[0]})`
}
```

然后是模态图像的视图。

`resources/views/app.blade.php`：

```php
<div class="modal-content">
  <img v-bind:src="images[0]"/>
</div>
```

完成重建和页面刷新后，您将在页面中看到模拟数据列表`#5`的内容：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/a3cc885a-d893-44b4-94a6-e7af8955cf40.png)图 5.22。带有模拟数据的列表页面

为了验证并欣赏我们的工作，让我们尝试另一个路由，例如`/listing/10`：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/24a89bd1-3055-499b-8510-b415b00df4cd.png)图 5.23。带有模拟数据的列表页面

# 总结

在本章中，我们熟悉了 Laravel 默认前端应用程序的文件和配置。然后我们将 Vuebnb 客户端应用程序原型迁移到我们的 Laravel 项目中，实现了 Vuebnb 的第一个全栈迭代。

我们还了解了 Webpack，看到它是如何通过将模块捆绑到浏览器友好的构建文件中来解决 JavaScript 依赖管理问题的。我们通过 Laravel Mix 在项目中设置了 Webpack，它提供了一个简单的 API 来处理常见的构建场景。

然后我们调查了一些工具，使得我们的前端开发过程更容易，包括 Webpack 的监视模式和 BrowserSync。

最后，我们看到如何通过将数据注入到文档头部，将数据从后端传递到前端应用程序。

在第六章中，*使用 Vue.js 组件组合小部件*，我们将介绍构建 Vue.js 用户界面的最重要和强大的工具之一：组件。我们将为 Vuebnb 构建一个图像轮播，并利用组件的知识将 Vuebnb 客户端应用程序重构为灵活的基于组件的架构。


# 第六章：使用 Vue.js 组件组合小部件

组件正在成为前端开发的一个重要方面，并且是大多数现代前端框架的一个特性，包括 Vue、React、Angular、Polymer 等。组件甚至通过一个称为**Web Components**的新标准成为 Web 的本地特性。

在本章中，我们将使用组件为 Vuebnb 创建一个图像轮播，允许用户查看房间列表的不同照片。我们还将重构 Vuebnb 以符合基于组件的架构。

本章涵盖的主题：

+   组件是什么以及如何使用 Vue.js 创建它们

+   通过 props 和 events 进行组件通信

+   单文件组件- Vue 中最有用的功能之一

+   使用插槽向组件添加自定义内容

+   完全从组件构建应用程序的好处

+   如何使用渲染函数跳过模板编译器

+   使用 Vue 的仅运行时构建来减小捆绑包大小

# 组件

当我们构建 Web 应用程序的模板时，我们可以使用 HTML 元素，如`div`，`table`和`span`。这种各种元素使得我们可以轻松创建页面上所需的任何结构。

如果我们可以通过例如`my-element`创建自定义元素，那该多好？这将允许我们创建专门为我们的应用程序设计的可重用结构。

*组件*是在 Vue.js 中创建自定义元素的工具。当我们注册一个组件时，我们定义一个模板，它呈现为一个或多个标准 HTML 元素：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/6e6ef921-1671-4a44-8e89-91c53b8bc046.png)图 6.1。组件促进可重用的标记，并呈现为标准 HTML

# 注册

有许多注册组件的方法，但最简单的方法是使用`component` API 方法。第一个参数是您要给组件的名称，第二个是配置对象。配置对象通常会包括一个`template`属性，以使用字符串声明组件的标记：

```php
Vue.component('my-component', { template: '<div>My component!</div>'
});

new Vue({ el: '#app'
});
```

注册了这样一个组件后，我们可以在项目中使用它：

```php
<div id="app">
  <my-component></my-component>
  <!-- Renders as <div>My component!</div> -->
</div>
```

# 数据

除了可重用的标记之外，组件还允许我们重用 JavaScript 功能。配置对象不仅可以包括一个模板，还可以包括自己的状态，就像 Vue 实例一样。实际上，每个组件都可以被视为 Vue 的迷你实例，具有自己的数据、方法、生命周期钩子等。

我们对待组件数据的方式与 Vue 实例略有不同，因为组件是可重用的。例如，我们可以像这样创建一个`check-box`组件库：

```php
<div id="app">
  <check-box></check-box>
  <check-box></check-box>
  <check-box></check-box>
</div>
<script> Vue.component('check-box', { template: '<div v-on:click="checked = !checked"></div>' data: { checked: false
    }
  }); </script>
```

现在，如果用户点击复选框`div`，则`checked`状态会同时从 true 切换到 false！这不是我们想要的，但这将会发生，因为组件的所有实例都引用相同的`data`对象，因此具有相同的状态。

为了使每个实例具有自己的唯一状态，`data`属性不应该是一个对象，而应该是一个返回对象的工厂函数。这样，每次组件被实例化时，它都链接到一个新的数据对象。实现这一点就像这样简单：

```php
data() {
  return { checked: false 
  }
}
```

# 图像轮播

让我们使用组件为 Vuebnb 前端应用程序构建一个新功能。正如您从之前的章节中记得的那样，我们的模拟数据列表中有四个不同的图像，并且我们正在将 URL 传递给前端应用程序。

为了让用户查看这些图像，我们将创建一个图像轮播。这个轮播将取代当前在单击列表标题时弹出的模态窗口中的静态图像。

首先打开应用视图。删除静态图像，并将其替换为自定义 HTML 元素`image-carousel`。

`resources/views/app.blade.php`：

```php
<div class="modal-content">
  <image-carousel></image-carousel>
</div>
```

组件可以在您的代码中通过 kebab-case 名称（如`my-component`）、PascalCase 名称（如`MyComponent`）或 camelCase 名称（如`myComponent`）来引用。Vue 将这些视为相同的组件。然而，在 DOM 或字符串模板中，组件应始终使用 kebab-case。Vue 不强制执行这一点，但页面中的标记在 Vue 开始处理之前会被浏览器解析，因此应符合 W3C 命名约定，否则解析器可能会将其删除。

现在让我们在入口文件中注册组件。这个新组件的模板将简单地是我们从视图中移除的图像标签，包裹在一个`div`中。我们添加这个包装元素，因为组件模板必须有一个单一的根元素，并且我们很快将在其中添加更多元素。

作为概念验证，组件数据将包括一个硬编码的图像 URL 数组。一旦我们学会如何将数据传递给组件，我们将删除这些硬编码的 URL，并用来自我们模型的动态 URL 替换它们。

`resources/assets/js/app.js`:

```php
Vue.component('image-carousel', { template: `<div class="image-carousel">
              <img v-bind:src="images[0]"/>
            </div>`,
  data() {
    return { images: [
        '/images/1/Image_1.jpg',
        '/images/1/Image_2.jpg',
        '/images/1/Image_3.jpg',
        '/images/1/Image_4.jpg'
      ]
    }
  }
});

var app = new Vue({
  ...
});
```

在测试这个组件之前，让我们对 CSS 进行调整。我们之前有一个规则，确保模态窗口内的图像通过`.modal-content img`选择器拉伸到全宽。让我们改用`.image-carousel`选择器，因为我们正在将图像与模态窗口解耦。

`resources/assets/css/style.css`:

```php
.image-carousel img {
  width: 100%;
}
```

在代码重建后，将浏览器导航到`/listing/1`，你应该看不到任何区别，因为组件应该以几乎与之前标记完全相同的方式呈现。

然而，如果我们检查 Vue Devtools，并打开到“组件”选项卡，你会看到我们现在在`Root`实例下嵌套了`ImageCarousel`组件。选择`ImageCarousel`，甚至可以检查它的状态：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/76c74b58-9265-42c3-9131-918c8cb0861d.png)图 6.2。Vue Devtools 显示 ImageCarousel 组件

# 更改图像

轮播图的目的是允许用户浏览一系列图像，而无需滚动页面。为了实现这一功能，我们需要创建一些 UI 控件。

但首先，让我们向我们的组件添加一个新的数据属性`index`，它将决定当前显示的图像。它将被初始化为 0，UI 控件稍后将能够增加或减少该值。

我们将把图像源绑定到位置为`index`的数组项。

`resources/assets/js/app.js`:

```php
Vue.component('image-carousel', { template: `<div class="image-carousel">
              <img v-bind:src="images[index]"/>
            </div>`,
  data() {
    return { images: [
        '/images/1/Image_1.jpg',
        '/images/1/Image_2.jpg',
        '/images/1/Image_3.jpg',
        '/images/1/Image_4.jpg'
      ], index: 0
    }
  }
});
```

页面刷新后，屏幕上看到的内容应该没有变化。但是，如果你将`index`的值初始化为`1`、`2`或`3`，当你重新打开模态窗口时，你会发现显示的是不同的图像：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/17bc76a6-6066-4702-8d8e-6beab3b10cde.png)图 6.3。将`index`设置为 2 会选择不同的 URL，显示不同的图像

# 计算属性

直接将逻辑写入我们的模板作为一个表达式是很方便的，例如`v-if="myExpression"`。但是对于无法定义为表达式的更复杂的逻辑，或者对于模板来说变得太冗长的情况怎么办呢？

在这种情况下，我们使用**计算属性**。这些属性是我们添加到 Vue 配置中的，可以被视为响应式方法，当依赖值发生变化时会重新运行。

在下面的示例中，我们在`computed`配置部分下声明了一个计算属性`message`。请注意，该函数依赖于`val`，也就是说，`message`的返回值将随着`val`的变化而不同。

当这个脚本运行时，Vue 将注意到`message`的任何依赖关系，并建立响应式绑定，这样，与普通方法不同，函数将在依赖关系发生变化时重新运行：

```php
<script>
  var app = new Vue({ el: '#app', data: { val: 1
    }, computed: {
      message() {
        return `The value is ${this.val}`
      }
    }   
  });

  setTimeout(function() { app.val = 2;
  }, 2000);
</script>
<div id="app">
  <!--Renders as "The value is 1"-->
  <!--After 2 seconds, re-renders as "The value is 2"-->
  {{ message }}
</div>
```

回到图像轮播，让我们通过将绑定到图像`src`的表达式抽象为计算属性，使模板更加简洁。

`resources/assets/js/app.js`:

```php
Vue.component('image-carousel', { template: `<div class="image-carousel">
              <img v-bind:src="image"/>
            </div>`,
  data() { ... }, computed: {
    image() {
      return this.images[this.index];
    }
  }
});
```

# 组合组件

组件可以像标准 HTML 元素一样嵌套在其他组件中。例如，如果`component A`在其模板中声明`component B`，则`component B`可以是`component A`的子级：

```php
<div id="app">
  <component-a></component-a>
</div>
<script> Vue.component('component-a', { template: `
      <div>
        <p>Hi I'm component A</p>
        <component-b></component-b>
      </div>`
  }); Vue.component('component-b', { template: `<p>And I'm component B</p>`
  });

  new Vue({ el: '#app'
  }); </script>
```

这将呈现为：

```php
<div id="app">
  <div>
    <p>Hi I'm component A</p>
    <p>And I'm component B</p>
  </div>
</div>
```

# 注册范围

虽然一些组件设计用于在应用程序的任何地方使用，但其他组件可能具有更具体的目的。当我们使用 API 注册组件，即`Vue.component`时，该组件是*全局*注册的，并且可以在任何其他组件或实例中使用。

我们还可以通过在根实例或另一个组件的`components`选项中声明来*本地*注册组件：

```php
Vue.component('component-a', { template: `
    <div>
      <p>Hi I'm component A</p>
      <component-b></component-b>
    </div>`, components: {
    'component-b': { template: `<p>And I'm component B</p>`
```

```php
    }
  }
});
```

# 轮播控件

为了允许用户更改轮播中当前显示的图像，让我们创建一个新的组件`CarouselControl`。该组件将呈现为一个浮动在轮播上的箭头，并将响应用户的点击。我们将使用两个实例，因为将有一个左箭头和一个右箭头，用于减少或增加图像索引。

我们将在`ImageCarousel`组件中本地注册`CarouselControl`。`CarouselControl`模板将呈现为一个`i`标签，通常用于显示图标。轮播图标的一个很好的图标是 Font Awesome 的*chevron*图标，它是一个优雅的箭头形状。目前，我们还没有办法区分左右，所以现在，两个实例都将有一个朝左的图标。

`resources/assets/js/app.js`：

```php
Vue.component('image-carousel', { template: ` <div class="image-carousel">
      <img v-bind:src="image">
      <div class="controls">
        <carousel-control></carousel-control>
        <carousel-control></carousel-control>
      </div>
    </div> `,
  data() { ... }, computed: { ... }, components: {
    'carousel-control': { template: `<i class="carousel-control fa fa-2x fa-chevron-left"></i>` }
  }
});
```

为了让这些控件在我们的图像轮播上漂亮地浮动，我们还会在我们的 CSS 文件中添加一些新的规则。

`resources/assets/css/style.css`：

```php
.image-carousel {
  height: 100%;
  margin-top: -12vh; position: relative;
  display: flex;
  align-items: center;
  justify-content: center;
}

.image-carousel .controls {
  position: absolute;
  width: 100%;
  display: flex;
  justify-content: space-between;
}

.carousel-control {
  padding: 1rem;
  color: #ffffff;
  opacity: 0.85 }

@media (min-width: 744px) {
  .carousel-control {
      font-size: 3rem;
  }
}
```

添加了该代码后，打开模态窗口查看我们迄今为止的工作成果：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/dbcc4ccc-a1b8-424e-81df-c859ebe02e2f.png)图 6.4。添加到图像轮播的轮播控件

# 与组件通信

组件的一个关键方面是它们是可重用的，这就是为什么我们给它们自己的状态以使它们独立于应用程序的其余部分。但是，我们可能仍然希望发送数据，或者将其发送出去。组件有一个用于与应用程序的其他部分通信的接口，我们现在将进行探讨。

# 属性

我们可以通过自定义 HTML 属性*prop*向组件发送数据。我们还必须在组件的配置中的数组`props`中注册此自定义属性。在下面的示例中，我们创建了一个 prop，`title`：

```php
<div id="app">
  <my-component title="My component!"></my-component>
  <!-- Renders as <div>My component!</div> -->
</div>
<script> Vue.component('my-component', { template: '<div>{{ title }}</div>', props: ['title']
  });

  new Vue({ el: '#app'
  });
</script>
```

prop 可以像组件的任何数据属性一样使用：您可以在模板中插值，将其用于方法和计算属性等。但是，您不应该改变 prop 数据。将 prop 数据视为从另一个组件或实例*借用*的数据-只有所有者应该更改它。

属性被代理到实例中，就像数据属性一样，这意味着你可以在组件的代码中将属性称为`this.myprop`。一定要将您的属性名称设置为与数据属性不同，以避免冲突！

# 单向数据流

由于 prop 必须在使用组件的模板中声明，因此 prop 数据只能从父级传递到子级。这就是为什么您不应该改变 prop 的原因-因为数据是向下流动的，更改不会反映在父级中，因此您将拥有不同版本的应该是相同状态的内容。

如果您确实需要告诉所有者更改数据，那么有一个单独的接口用于从子级向父级传递数据，我们稍后会看到。

# 动态 prop

我们可以使用`v-bind`指令将数据动态绑定到组件。当父级数据发生变化时，它将自动流向子级。

在下面的示例中，根实例中`title`的值在两秒后以编程方式更新。此更改将自动流向`MyComponent`，后者将以响应方式重新呈现以显示新值：

```php
<div id="app">
  <my-component :title="title"></my-component>
  <!-- Renders initially as <div>Hello World</div> -->
  <!-- Re-renders after two seconds as <div>Goodbye World</div> -->
</div>
<script> Vue.component('my-component', { template: '<div>{{ title }}</div>', props: [ 'title' ]
  });

  var app = new Vue({ el: '#app', data: { title: 'Hello World'
    }
  });

  setTimeout(() => { app.title = 'Goodbye World'
  }, 2000); </script>
```

由于在模板中经常使用`v-bind`指令，您可以省略指令名称作为简写：`<div v-bind:title="title">`可以缩写为`<div :title="title">`。

# 图片 URL

当我们创建`ImageCarousel`时，我们硬编码了图像 URL。通过 props，我们现在有了一种机制，可以从根实例向组件发送动态数据。让我们将根实例数据属性`images`绑定到一个 prop，也叫`images`，在我们的`ImageCarousel`声明中。

`resources/views/app.blade.php`：

```php
<div class="modal-content">
  <image-carousel :images="images"></image-carousel>
</div>
```

现在，删除`ImageCarousel`组件中的数据属性`images`，并将`images`声明为 prop。

`resources/assets/js/app.js`：

```php
Vue.component('image-carousel', { props: ['images'],
  data() {
    return { index: 0
    }
  },
  ...
}
```

根实例现在将负责图像 URL 的状态，图像轮播组件将负责显示它们。

使用 Vue Devtools，我们可以检查图像轮播组件的状态，现在包括`images`作为 prop 值而不是数据值：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/f4733eab-446b-46cd-a129-5fb17c0adf3b.png)图 6.5。图像 URL 是发送到 ImageCarousel 组件的 props

现在图像 URL 来自模型，我们可以访问其他列表路由，比如`/listing/2`，并再次在模态窗口中看到正确的图像显示。

# 区分轮播控件

`CarouselControl`组件应该有两种可能的状态：要么指向左，要么指向右。当用户点击时，前者将上升到可用图像，后者将下降。

这种状态不应该由内部确定，而应该从`ImageCarousel`传递下来。为此，让我们向`CarouselControl`添加一个 prop`dir`，它将采用一个字符串值，应该是`left`或`right`。

有了`dir`prop，我们现在可以将正确的图标绑定到`i`元素。这是通过一个计算属性完成的，它将 prop 的值附加到字符串`fa-chevron-`，结果要么是`fa-chevron-left`要么是`fa-chevron-right`。

`resources/assets/js/app.js`：

```php
Vue.component('image-carousel', { template: ` <div class="image-carousel">
      <img :src="image">
      <div class="controls">
        <carousel-control dir="left"></carousel-control>
        <carousel-control dir="right"></carousel-control>
      </div>
    </div> `,
  ... components: {
    'carousel-control': { template: `<i :class="classes"></i>`, props: [ 'dir' ], computed: {
        classes() {
          return 'carousel-control fa fa-2x fa-chevron-' + this.dir;
        }
      } }
  }
} 
```

现在我们可以看到轮播控制图标正确指向：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/a890fe8a-97f2-4cd0-87f5-c056108af4a1.png)图 6.6。轮播控制图标现在正确指向

# 自定义事件

我们的轮播控件显示得很好，但它们还没有做任何事情！当它们被点击时，我们需要它们告诉`ImageCarousel`要么增加要么减少它的`index`值，这将导致图像被更改。

动态 props 对于这个任务不起作用，因为 props 只能从父组件向子组件发送数据。当子组件需要向父组件发送数据时，我们该怎么办？

*自定义事件*可以从子组件发出，并由其父组件监听。为了实现这一点，我们在子组件中使用`$emit`实例方法，它将事件名称作为第一个参数，并为任何要随事件发送的数据附加任意数量的额外参数，例如`this.$emit('my-event', 'My event payload');`。

父组件可以在声明组件的模板中使用`v-on`指令来监听此事件。如果您使用方法处理事件，那么随事件发送的任何参数都将作为参数传递给此方法。

考虑这个例子，一个子组件`MyComponent`发出一个名为`toggle`的事件，告诉父组件，根实例，改变一个数据属性`toggle`的值：

```php
<div id="app">
  <my-component @toggle="toggle = !toggle"></my-component> {{ message }} </div>
<script> Vue.component('my-component', { template: '<div v-on:click="clicked">Click me</div>', methods: { clicked: function() {
        this.$emit('toggle');
      }
    }
  });

  new Vue({ el: '#app', data: { toggle: false
    }, computed: { message: function() {
        return this.toggle ? 'On' : 'Off';
      }
    }
  }); </script>
```

# 更改轮播图像

回到`CarouselControl`，让我们通过使用`v-on`指令和触发一个方法`clicked`来响应用户的点击。这个方法将反过来发出一个自定义事件`change-image`，其中将包括一个`-1`或`1`的有效负载，具体取决于组件的状态是`left`还是`right`。

就像`v-bind`一样，`v-on`也有一个简写。只需用`@`替换`v-on:`；例如，`<div @click="handler"></div>`相当于`<div v-on:click="handler"></div>`。

`resources/assets/js/app.js`：

```php
components: {
  'carousel-control': { template: `<i :class="classes" @click="clicked"></i>`, props: [ 'dir' ], computed: {
      classes() {
        return 'carousel-control fa fa-2x fa-chevron-' + this.dir;
      }
    }, methods: {
      clicked() {
        this.$emit('change-image', this.dir === 'left' ? -1 : 1);
      }
    }
  }
}
```

打开 Vue Devtools 到`Events`选项卡，并同时点击轮播控件。自定义事件将在此处记录，因此我们可以验证`change-image`是否被发出：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/c2505411-760b-4363-a19d-8f6938340b2b.png)图 6.7。屏幕截图显示自定义事件及其有效负载

`ImageCarousel`现在需要通过`v-on`指令监听`change-image`事件。该事件将由一个名为`changeImage`的方法处理，该方法将具有一个参数`val`，反映事件中发送的有效负载。然后，该方法将使用`val`来调整`index`的值，确保它在超出数组索引范围时循环到开始或结束。

`resources/assets/js/app.js`：

```php
Vue.component('image-carousel', { template: ` <div class="image-carousel">
      <img :src="image">
      <div class="controls">
        <carousel-control 
 dir="left" 
 @change-image="changeImage" ></carousel-control>
        <carousel-control 
 dir="right" 
 @change-image="changeImage" ></carousel-control>
      </div>
    </div> `,
  ... methods: {
    changeImage(val) {
      let newVal = this.index + parseInt(val);
      if (newVal < 0) {
        this.index = this.images.length -1;
      } else if (newVal === this.images.length) {
        this.index = 0;
      } else {
        this.index = newVal;
      }
    }
  },
  ...
}
```

完成后，图像轮播将正常工作：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/a6a518db-81ab-4501-9a2e-355fff9be282.png)图 6.8。图像轮播在更改图像后的状态

# 单文件组件

**单文件组件**（**SFCs**）是具有`.vue`扩展名的文件，包含单个组件的完整定义，并可以导入到您的 Vue.js 应用程序中。SFC 使创建和使用组件变得简单，并带有各种其他好处，我们很快会探讨。

SFC 类似于 HTML 文件，但最多有三个根元素：

+   `template`

+   `script`

+   `style`

组件定义放在`script`标签内，除了以下内容，其余与任何其他组件定义完全相同：

+   它将导出一个 ES 模块

+   它将不需要`template`属性（或`render`函数；稍后会详细介绍）

组件的模板将在`template`标签内声明为 HTML 标记。这应该是一个从编写繁琐的模板字符串中解脱出来的好消息！

`style`标签是 SFC 独有的功能，可以包含组件所需的任何 CSS 规则。这主要有助于组织 CSS。

这是声明和使用单文件组件的示例。

`MyComponent.vue`：

```php
<template>
  <div id="my-component">{{ title }}</div>
</template>
<script> export default {
    data() { title: 'My Component'
    }
  }; </script>
<style> .my-component {
    color: red;
  } </style>
```

`app.js`：

```php
import 'MyComponent' from './MyComponent.vue';

new Vue({ el: '#app', components: { MyComponent }
});
```

# 转换

要在应用程序中使用单文件组件，只需像使用 ES 模块一样导入它。*.vue*文件不是有效的 JavaScript 模块文件。就像我们使用 Webpack Babel 插件将 ES2015 代码转译为 ES5 代码一样，我们必须使用*Vue Loader*将*.vue*文件转换为 JavaScript 模块。

Vue Loader 已经默认配置了 Laravel Mix，因此在这个项目中我们无需做其他操作；我们导入的任何 SFC 都会正常工作！

要了解有关 Vue Loader 的更多信息，请查看[`vue-loader.vuejs.org/`](https://vue-loader.vuejs.org/)上的文档。

# 将组件重构为 SFC

我们的`resource/assets/js/app.js`文件现在几乎有 100 行。如果我们继续添加组件，它将变得难以管理，因此现在是时候考虑拆分它了。

让我们从重构现有组件为 SFC 开始。首先，我们将创建一个新目录，然后创建`.vue`文件：

```php
$ mkdir resources/assets/components
$ touch resources/assets/components/ImageCarousel.vue
$ touch resources/assets/components/CarouselControl.vue
```

从`ImageCarousel.vue`开始，第一步是创建三个根元素。

`resources/assets/components/ImageCarousel.vue`：

```php
<template></template>
<script></script>
<style></style>
```

现在，我们将`template`字符串移入`template`标签中，将组件定义移入`script`标签中。组件定义必须导出为模块。

`resources/assets/components/ImageCarousel.vue`：

```php
<template>
  <div class="image-carousel">
    <img :src="image">
    <div class="controls">
      <carousel-control 
        dir="left" 
        @change-image="changeImage" ></carousel-control>
      <carousel-control 
        dir="right" 
        @change-image="changeImage" ></carousel-control>
    </div>
  </div>
</template>
<script> export default { props: [ 'images' ],
    data() {
      return { index: 0
      }
    }, computed: {
      image() {
        return this.images[this.index];
      }
    }, methods: {
      changeImage(val) {
        let newVal = this.index + parseInt(val);
        if (newVal < 0) {
          this.index = this.images.length -1;
        } else if (newVal === this.images.length) {
          this.index = 0;
        } else {
          this.index = newVal;
        }
      }
    }, components: {
      'carousel-control': { template: `<i :class="classes" @click="clicked"></i>`, props: [ 'dir' ], computed: {
          classes() {
            return 'carousel-control fa fa-2x fa-chevron-' + this.dir;
          }
        }, methods: {
          clicked() {
            this.$emit('change-image', this.dir === 'left' ? -1 : 1);
          }
        }
      }
    }
  } </script>
<style></style>
```

现在我们可以将此文件导入到我们的应用程序中，并在根实例中本地注册它。如前所述，Vue 能够自动在 kebab-case 组件名称和 Pascal-case 组件名称之间切换。这意味着我们可以在`component`配置中使用对象简写语法，Vue 将正确解析它。

`resources/assets/js/app.js`：

```php
import ImageCarousel from '../components/ImageCarousel.vue';

var app = new Vue({
  ... components: { ImageCarousel }
});
```

在继续之前，请确保删除`app.js`中原始`ImageCarousel`组件定义的任何剩余代码。

# CSS

SFC 允许我们向组件添加样式，有助于更好地组织我们的 CSS 代码。让我们将为图像轮播创建的 CSS 规则移入这个新 SFC 的`style`标签中：

```php
<template>...</template>
<script>...</script>
<style> .image-carousel {
    height: 100%;
    margin-top: -12vh; position: relative;
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .image-carousel img {
    width: 100%;
  }

  .image-carousel .controls {
    position: absolute;
    width: 100%;
    display: flex;
    justify-content: space-between;
  } </style>
```

项目构建完成后，你应该发现它仍然是一样的。然而，有趣的是，CSS 最终出现在了构建中的位置。如果你检查`public/css/style.css`，你会发现它不在那里。

它实际上包含在 JavaScript 捆绑包中作为一个字符串：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/9a6e3bbf-577a-4800-b4bc-c5c0fe1243b2.png)图 6.9. CSS 存储为 JavaScript 捆绑文件中的字符串

要使用它，Webpack 的引导代码将在应用程序运行时将此 CSS 字符串内联到文档的头部：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/4260368f-354f-4695-8013-8ca5a8a38001.png)图 6.10. 文档头中的内联 CSS

内联 CSS 实际上是 Vue Loader 的默认行为。但是，我们可以覆盖这一行为，让 Webpack 将 SFC 样式写入它们自己的文件中。在 Mix 配置的底部添加以下内容。

`webpack.mix.js`：

```php
mix.options({ extractVueStyles: 'public/css/vue-style.css'
});
```

现在，一个额外的文件`public/css/vue-style.css`将被输出到构建中：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/45e46db4-744d-462d-ba87-afe089b1541a.png)图 6.11. 包括单文件组件样式的 Webpack 输出

我们需要在主样式表之后在视图中加载这个新文件。

`resources/views/app.blade.php`：

```php
<head> ... <link rel="stylesheet" href="{{ asset('css/style.css') }}" type="text/css">
  <link rel="stylesheet" href="{{ asset('css/vue-style.css') }}" type="text/css"> ... </head>
```

# CarouselControl

现在让我们将`CarouselControl`组件抽象成一个 SFC，并将`resources/assets/css/style.css`中的任何相关 CSS 规则移动过来。

`resources/assets/components/CarouselControl.vue`：

```php
<template>
  <i :class="classes" @click="clicked"></i>
</template>
<script> export default { props: [ 'dir' ], computed: {
      classes() {
        return 'carousel-control fa fa-2x fa-chevron-' + this.dir;
      }
    }, methods: {
      clicked() {
        this.$emit('change-image', this.dir === 'left' ? -1 : 1);
      }
    }
  } </script>
<style> .carousel-control {
    padding: 1rem;
    color: #ffffff;
    opacity: 0.85 }

  @media (min-width: 744px) {
    .carousel-control {
      font-size: 3rem;
    }
  } </style>
```

现在，这个文件可以被`ImageCarousel`组件导入。

`resources/assets/components/ImageCarousel.vue`：

```php
<template>...</style>
<script> import CarouselControl from '../components/CarouselControl.vue';

  export default {
    ... components: { CarouselControl }
  } </script>
<style>...</style>
```

完成后，我们现有的组件已经重构为 SFC。这并没有对我们应用程序的功能产生明显的影响（尽管稍微快一点，我稍后会解释），但随着我们的开发继续，这将使开发变得更容易。

# 内容分发

想象一下，你将要构建一个基于组件的 Vue.js 应用程序，它的结构类似于以下结构：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/62c38159-a04a-4e5c-8993-6a17f3a97de1.png)图 6.12. 基于组件的 Vue.js 应用程序

请注意，在上图的左分支中，`ComponentC`由`ComponentB`声明。然而，在右分支中，`ComponentD`由`ComponentB`的另一个实例声明。

根据你目前对组件的了解，如果`ComponentB`必须声明两个不同的组件，你会如何制作`ComponentB`的模板？也许它会包括一个`v-if`指令，根据从`ComponentA`传递下来的某个变量来使用`ComponentC`或`ComponentD`。这种方法可以工作，但是它会使`ComponentB`非常不灵活，在应用程序的其他部分限制了它的可重用性。

# 插槽

到目前为止，我们已经学到了组件的内容是由它自己的模板定义的，而不是由它的父级定义的，所以我们不会期望以下内容能够工作：

```php
<div id="app">
  <my-component>
    <p>Parent content</p>
  </my-component>
</div>
```

但是，如果`MyComponent`在它的模板中有一个*插槽*，它将起作用。插槽是组件内的分发出口，使用特殊的`slot`元素定义：

```php
Vue.component('my-component', { template: `
    <div>
      <slot></slot>
      <p>Child content</p>
    </div>`
});

new Vue({ el: '#app'
});
```

这将呈现为：

```php
<div id="app">
  <div>
    <p>Parent content</p>
    <p>Child content</p>
  </div>
</div>
```

如果`ComponentB`在它的模板中有一个插槽，就像这样：

```php
Vue.component('component-b', { 
 template: '<slot></slot>'
}); 
```

我们可以解决刚才提到的问题，而不必使用繁琐的`v-for`：

```php
<component-a>
  <component-b>
    <component-c></component-c>
  </component-b>
  <component-b>
    <component-d></component-d>
  </component-b>
</component-a>
```

重要的是要注意，在父模板中声明的组件内的内容是在父模板的范围内编译的。尽管它在子组件内呈现，但它无法访问子组件的任何数据。以下示例应该能够区分这一点：

```php
<div id="app">
  <my-component>
    <!--This works-->
    <p>{{ parentProperty }}</p>

    <!--This does not work. childProperty is undefined, as this content--> 
    <!--is compiled in the parent's scope-->
    <p>{{ childProperty }} </my-component>
</div>
<script> Vue.component('my-component', { template: `
      <div>
        <slot></slot>
        <p>Child content</p>
      </div>`,
    data() {
      return { childProperty: 'World'
      }
    }
  });

  new Vue({ el: '#app', data: { parentProperty: 'Hello'
    }
  }); </script>
```

# 模态窗口

我们根 Vue 实例中剩下的大部分功能都涉及模态窗口。让我们将这些抽象成一个单独的组件。首先，我们将创建新的组件文件：

```php
$ touch resources/assets/components/ModalWindow.vue
```

现在，我们将把视图中的标记移到组件中。为了确保轮播图与模态窗口保持解耦，我们将在标记中的`ImageCarousel`声明替换为一个插槽。

`resources/assets/components/ModalWindow.vue`：

```php
<template>
  <div id="modal" :class="{ show : modalOpen }">
    <button @click="modalOpen = false" class="modal-close">&times;</button>
    <div class="modal-content">
      <slot></slot>
    </div>
  </div>
</template>
<script></script>
<style></style>
```

现在，我们可以在视图中刚刚创建的洞中声明一个`ModalWindow`元素，并将`ImageCarousel`作为插槽的内容。

`resources/views/app.blade.php`：

```php
<div id="app">
  <div class="header">...</div>
  <div class="container">...</div>
  <modal-window>
    <image-carousel :images="images"></image-carousel>
  </modal-window>
</div>
```

我们现在将从根实例中移动所需的功能，并将其放置在`script`标签内。

`resources/assets/components/ModalWindow.vue`：

```php
<template>...</template>
<script> export default {
    data() {
      return { modalOpen: false
      }
    }, methods: {
      escapeKeyListener(evt) {
        if (evt.keyCode === 27 && this.modalOpen) {
          this.modalOpen = false;
        }
      }
    }, watch: {
      modalOpen() {
        var className = 'modal-open';
        if (this.modalOpen) { document.body.classList.add(className);
        } else { document.body.classList.remove(className);
        }
      }
    },
    created() { document.addEventListener('keyup', this.escapeKeyListener);
    },
    destroyed() { document.removeEventListener('keyup', this.escapeKeyListener);
    },
  } </script>
<style></style>
```

接下来在入口文件中导入`ModalWindow`。

`resources/assets/js/app.js`：

```php
import ModalWindow from '../components/ModalWindow.vue';

var app = new Vue({ el: '#app', data: Object.assign(model, { headerImageStyle: {
      'background-image': `url(${model.images[0]})`
    }, contracted: true
  }), components: { ImageCarousel, ModalWindow }
});
```

最后，让我们将任何与模态相关的 CSS 规则也移入 SFC 中：

```php
<template>...</template>
<script>...</script>
<style> #modal {
    display: none;
    position: fixed;
    top: 0;
    right: 0;
    bottom: 0;
    left: 0;
    z-index: 2000;
    background-color: rgba(0,0,0,0.85);
  }

  #modal.show {
    display: block;
  }

  body.modal-open {
    overflow: hidden;
    position: fixed;
  }

  .modal-close {
    cursor: pointer;
    position: absolute;
    right: 0;
    top: 0;
    padding: 0px 28px 8px;
    font-size: 4em;
    width: auto;
    height: auto;
    background: transparent;
    border: 0;
    outline: none;
    color: #ffffff;
    z-index: 1000;
    font-weight: 100;
    line-height: 1;
  }

  .modal-content {
    height: 100%;
    max-width: 105vh;
    padding-top: 12vh;
    margin: 0 auto;
    position: relative;
  } </style>
```

项目构建完成后，您会注意到模态窗口不会打开。我们将在下一节中修复这个问题。

如果您检查 Vue Devtools，您会看到现在组件层次结构中有一个`ModalWindow`组件：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/aa3d425e-e848-4b0a-87fa-a45c5e02f7a7.png)图 6.13。Vue Devtools 显示组件层次结构我们在 Vue Devtools 中的应用程序表示略有误导。它使得`ImageCarousel`看起来是`ModalWindow`的子组件。即使`ImageCarousel`由于插槽而在`ModalWindow`内部呈现，但这些组件实际上是同级的！

# Refs

在初始状态下，模态窗口使用`display: none` CSS 规则隐藏。要打开模态窗口，用户必须点击标题图像。然后，点击事件侦听器将设置根实例数据属性`modelOpen`为 true，这将反过来向模态窗口添加一个类，以覆盖`display: none`为`display: block`。

然而，在重构之后，`modalOpen`已经移动到`ModalWindow`组件中，连同其余的模态逻辑，因此模态打开功能目前已经失效。修复这个问题的一种可能的方法是让根实例管理模态的打开/关闭状态，将逻辑移回根实例。然后我们可以使用 prop 来通知模态何时需要打开。当模态关闭时（这发生在模态组件的范围内，关闭按钮所在的地方），它会向根实例发送事件以更新状态。

这种方法可以工作，但不符合使我们的组件解耦且可重用的精神；模态组件应该管理自己的状态。那么，我们如何才能让模态保持其状态，但让根实例（父级）改变它？事件不起作用，因为事件只能向上流动，而不能向下流动。

`ref`是一个特殊的属性，允许您直接引用子组件的数据。要使用它，声明`ref`属性并为其分配一个唯一值，例如`imagemodal`。

`resources/views/app.blade.php`：

```php
<modal-window ref="imagemodal"> ... </modal-window>
```

现在根实例可以通过`$refs`对象访问特定的`ModalWindow`组件数据。这意味着我们可以在根实例方法中更改`modalOpen`的值，就像我们可以从`ModalWindow`内部一样。

`resources/assets/js/app.js`：

```php
var app = new Vue({
  ... methods: {
    openModal() {
      this.$refs.imagemodal.modalOpen = true;
    },
  }
});
```

现在我们可以在标题图像的点击侦听器中调用`openModal`方法，从而恢复模态打开功能。

`resources/views/app.blade.php`：

```php
<div id="app">
  <div class="header">
    <div class="header-img" :style="headerImageStyle" @click="openModal">
      <button class="view-photos">View Photos</button>
    </div>
  </div> ... </div>
```

当使用组件的正常交互方法，即 prop 和事件，足以满足需求时，使用`ref`是一种反模式。`ref`通常只用于与页面正常流程之外的元素进行通信，就像模态窗口一样。

# 标题图像

现在让我们将标题图像抽象成一个组件。首先，创建一个新的`.vue`文件：

```php
$ touch resources/assets/components/HeaderImage.vue
```

现在移动到标记、数据和 CSS。注意以下修改：

+   必须发出事件`header-clicked`。这将用于打开模态窗口

+   图像 URL 作为 prop 传递，`image-url`，然后通过计算属性转换为内联样式规则

`resource/assets/components/HeaderImage.vue`：

```php
<template>
  <div class="header">
    <div class="header-img" 
      :style="headerImageStyle" 
      @click="$emit('header-clicked')"
    >
      <button class="view-photos">View Photos</button>
    </div>
  </div>
</template>
<script> export default { computed: {
      headerImageStyle() {
        return {
          'background-image': `url(${this.imageUrl})`
        };
      }
    }, props: [ 'image-url' ]
  } </script>
<style> .header {
    height: 320px;
  }

  .header .header-img {
    background-repeat: no-repeat;
    -moz-background-size: cover;
    -o-background-size: cover;
    background-size: cover;
    background-position: 50% 50%;
    background-color: #f5f5f5;
    height: 100%;
    cursor: pointer;
    position: relative;
  }

  .header .header-img button {
    font-size: 14px;
    padding: 7px 18px;
    color: #484848;
    line-height: 1.43;
    background: #ffffff;
    font-weight: bold;
    border-radius: 4px;
    border: 1px solid #c4c4c4;
  }

  .header .header-img button.view-photos {
    position: absolute;
    bottom: 20px;
    left: 20px;
  } </style>
```

一旦在`resources/assets/js/app.js`中导入了这个组件，就在主模板中声明它。确保绑定`image-url`prop 并处理点击事件。

`resources/views/app.blade.php`：

```php
<div id="app">
  <header-image 
    :image-url="images[0]" 
    @header-clicked="openModal" ></header-image>
  <div class="container">...</div> <modal-window>...</modal-window>
</div>
```

# 功能列表

让我们继续将 Vuebnb 重构为组件，并将设施和价格列表抽象出来。这些列表具有类似的目的和结构，因此创建一个单一的通用组件是有意义的。

让我们回顾一下当前列表的标记是什么样子的。

`resources/views/app.blade.php`：

```php
<div class="lists">
  <hr>
  <div class="amenities list">
    <div class="title"><strong>Amenities</strong></div>
    <div class="content">
      <div class="list-item" v-for="amenity in amenities">
        <i class="fa fa-lg" :class="amenity.icon"></i>
        <span>@{{ amenity.title }}</span>
      </div>
    </div>
  </div>
  <hr>
  <div class="prices list">
    <div class="title"><strong>Prices</strong></div>
    <div class="content">
      <div class="list-item" v-for="price in prices"> @{{ price.title }}: <strong>@{{ price.value }}</strong>
      </div>
    </div>
  </div>
</div>
```

两个列表之间的主要区别在于`<div class="content">...</div>`部分，因为在每个列表中显示的数据结构略有不同。设施有一个图标和一个标题，而价格有一个标题和一个值。我们将在这一部分使用插槽，以允许父级自定义每个内容。

但首先，让我们创建新的`FeatureList`组件文件：

```php
$ touch resources/assets/components/FeatureList.vue
```

我们将一个列表的标记移到其中，使用插槽替换列表内容。我们还将为标题添加一个 prop，并移入任何与列表相关的 CSS。

`resources/assets/components/FeatureList.vue`:

```php
<template>
  <div>
    <hr>
    <div class="list">
      <div class="title"><strong>{{ title }}</strong></div>
      <div class="content">
        <slot></slot>
      </div>
    </div>
  </div>
</template>
<script> export default { props: ['title']
  } </script>
<style> hr {
    border: 0;
    border-top: 1px solid #dce0e0;
  }
  .list {
    display: flex;
    flex-wrap: nowrap;
    margin: 2em 0;
  }

  .list .title {
    flex: 1 1 25%;
  }

  .list .content {
    flex: 1 1 75%;
    display: flex;
    flex-wrap: wrap;
  }

  .list .list-item {
    flex: 0 0 50%;
    margin-bottom: 16px;
  }

  .list .list-item > i {
    width: 35px;
  }

  @media (max-width: 743px) {
    .list .title {
      flex: 1 1 33%;
    }

    .list .content {
      flex: 1 1 67%;
    }

    .list .list-item {
      flex: 0 0 100%;
    }
  } </style>
```

继续将`FeatureList`导入`resources/assets/js/app.js`，并将其添加到本地注册的组件中。现在我们可以在主模板中使用`FeatureList`，每个列表都有一个单独的实例。

`resources/views/app.blade.php`:

```php
<div id="app"> ... <div class="container"> ... <div class="lists">
      <feature-list title="Amenities">
        <div class="list-item" v-for="amenity in amenities">
          <i class="fa fa-lg" :class="amenity.icon"></i>
          <span>@{{ amenity.title }}</span>
        </div>
      </feature-list>
      <feature-list title="Prices">
        <div class="list-item" v-for="price in prices"> @{{ price.title }}: <strong>@{{ price.value }}</strong>
        </div>
      </feature-list>
    </div>
  </div>
</div>
```

# 作用域插槽

`FeatureList`组件可以工作，但相当薄弱。大部分内容都通过插槽传递，因此似乎父级做了太多的工作，而子级做得太少。鉴于在组件的两个声明中都有重复的代码（`<div class="list-item" v-for="...">`），最好将这些代码委托给子级。

为了使我们的组件模板更加灵活，我们可以使用*作用域插槽*而不是常规插槽。作用域插槽允许您将*模板*传递给插槽，而不是传递渲染的元素。当这个模板在父级中声明时，它将可以访问子级提供的任何 props。

例如，一个带有作用域插槽的组件`child`可能如下所示：

```php
<div>
  <slot my-prop="Hello from child"></slot>
</div>
```

使用这个组件的父级将声明一个`template`元素，其中将有一个命名别名对象的`slot-scope`属性。在子级模板中添加到插槽的任何 props 都可以作为别名对象的属性使用：

```php
<child>
  <template slot-scope="props">
    <span>Hello from parent</span>
    <span>{{ props.my-prop }}</span>
  </template>
</child>
```

这将呈现为：

```php
<div>
  <span>Hello from parent</span>
  <span>Hello from child</span>
</div>
```

让我们通过包含一个带有`FeatureList`组件的作用域插槽的步骤。目标是能够将列表项数组作为 prop 传递，并让`FeatureList`组件对它们进行迭代。这样，`FeatureList`将拥有任何重复的功能。然后父级将提供一个模板来定义每个列表项的显示方式。

`resources/views/app.blade.php`:

```php
<div class="lists">
  <feature-list title="Amenities" :items="amenities">
    <!--template will go here-->
  </feature-list>
  <feature-list title="Prices" :items="prices">
    <!--template will go here-->
  </feature-list>   
</div>
```

现在专注于`FeatureList`组件，按照以下步骤操作：

1.  在配置对象的 props 数组中添加`items`

1.  `items`将是一个我们在`<div class="content">`部分内部迭代的数组。

1.  在循环中，`item`是任何特定列表项的别名。我们可以创建一个插槽，并使用`v-bind="item"`将该列表项绑定到插槽。（我们以前没有使用过没有参数的`v-bind`，但这将整个对象的属性绑定到元素。这对于设施和价格对象具有不同属性的情况很有用，现在我们不必指定它们。）

`resources/assets/components/FeatureList.vue`:

```php
<template>
  <div>
    <hr>
    <div class="list">
      <div class="title"><strong>{{ title }}</strong></div>
      <div class="content">
        <div class="list-item" v-for="item in items">
          <slot v-bind="item"></slot>
        </div>
      </div>
    </div>
  </div>
</template>
<script> export default { props: ['title', 'items']
  } </script>
<style>...</style>
```

现在我们将回到我们的视图。让我们先处理设施列表：

1.  在`FeatureList`声明中声明一个`template`元素。

1.  模板必须包含`slot-scope`属性，我们将其分配给一个别名`amenity`。这个别名允许我们访问作用域 props。

1.  在模板中，我们可以使用与以前完全相同的标记来显示我们的设施列表项。

`resources/views/app.blade.php`:

```php
<feature-list title="Amenities" :items="amenities">
  <template slot-scope="amenity">
    <i class="fa fa-lg" :class="amenity.icon"></i>
    <span>@{{ amenity.title }}</span>
  </template>
</feature-list>
```

这是包含价格的完整主模板。

`resources/views/app.blade.php`:

```php
<div id="app"> ... <div class="container"> ... <div class="lists">
      <feature-list title="Amenities" :items="amenities">
        <template slot-scope="amenity">
          <i class="fa fa-lg" :class="amenity.icon"></i>
          <span>@{{ amenity.title }}</span>
        </template>
      </feature-list>
      <feature-list title="Prices" :items="prices">
        <template slot-scope="price"> @{{ price.title }}: <strong>@{{ price.value }}</strong>
        </template>
      </feature-list>
    </div>
  </div>
</div>
```

尽管这种方法的标记与以前一样多，但它已经将更常见的功能委托给了组件，这使得设计更加健壮。

# 可展开的文本

我们在第二章中创建了功能，*原型 Vuebnb，你的第一个 Vue.js 项目*，允许关于文本在页面加载时部分收缩，并通过点击按钮展开到完整长度。让我们也将这个功能抽象成一个组件：

```php
$ touch resources/assets/components/ExpandableText.vue
```

将所有标记、配置和 CSS 移入新组件。请注意，我们在文本内容中使用了一个插槽。

`resources/assets/components/ExpandableText.vue`：

```php
<template>
  <div>
    <p :class="{ contracted: contracted }">
      <slot></slot>
    </p>
    <button v-if="contracted" class="more" @click="contracted = false"> + More
    </button>
  </div>
</template>
<script> export default {
    data() {
      return { contracted: true
      }
    }
  } </script>
<style> p {
    white-space: pre-wrap;
  }

  .contracted {
    height: 250px;
    overflow: hidden;
  } .about button.more {
    background: transparent;
    border: 0;
    color: #008489;
    padding: 0;
    font-size: 17px;
 font-weight: bold;
  } .about button.more:hover, 
 .about button.more:focus, 
 .about button.more:active {
    text-decoration: underline;
    outline: none;
  } </style>
```

一旦你在`resources/assets/js/app.js`中导入了这个组件，在主模板中声明它，记得在插槽中插入`about`数据属性。

`resource/views/app.blade.php`：

```php
<div id="app">
  <header-image>...</header-image>
  <div class="container">
    <div class="heading">...</div>
    <hr>
    <div class="about">
      <h3>About this listing</h3>
      <expandable-text>@{{ about }}</expandable-text>
    </div>
    ... </div>
</div>
```

做到这一点后，Vuebnb 客户端应用的大部分数据和功能都已经被抽象成了组件。让我们看看`resources/assets/js/app.js`，看看它变得多么简洁！

`resources/assets/js/app.js`：

```php
...

import ImageCarousel from '../components/ImageCarousel.vue';
import ModalWindow from '../components/ModalWindow.vue';
import FeatureList from '../components/FeatureList.vue';
import HeaderImage from '../components/HeaderImage.vue';
import ExpandableText from '../components/ExpandableText.vue';

var app = new Vue({ el: '#app', data: Object.assign(model, {}), components: { ImageCarousel, ModalWindow, FeatureList, HeaderImage, ExpandableText }, methods: {
    openModal() {
      this.$refs.imagemodal.modalOpen = true;
    }
  }
});
```

# 虚拟 DOM

现在让我们改变方向，讨论 Vue 如何渲染组件。看看这个例子：

```php
Vue.component('my-component', { template: '<div id="my-component">My component</div>'
});
```

为了让 Vue 能够将这个组件渲染到页面上，它将首先使用内部模板编译器库将模板字符串转换为 JavaScript 对象：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/31012e53-0217-44bf-b43c-e5c75c221a59.png)图 6.14。模板编译器如何将模板字符串转换为对象

一旦模板被编译，任何状态或指令都可以很容易地应用。例如，如果模板包括一个`v-for`，可以使用简单的 for 循环来复制节点并插入正确的变量。

之后，Vue 可以与 DOM API 交互，将页面与组件的状态同步。

# 渲染函数

与为组件提供字符串模板不同，你可以提供一个`render`函数。即使不理解语法，你可能也能从以下例子中看出，`render`函数生成了一个与前面例子中的字符串模板在语义上等价的模板。两者都定义了一个带有`id`属性为`my-component`的`div`，并且内部文本为`My component`：

```php
Vue.component('my-component'</span>, {
  render(createElement) {
    createElement('div', {attrs:{id:'my-component'}}, 'My component');
    // Equivalent to <div id="my-component">My component</div>
  }
})
```

渲染函数更高效，因为它们不需要 Vue 首先编译模板字符串。不过，缺点是，编写渲染函数不像标记语法那样简单或表达性强，一旦你有了一个大模板，将会很难处理。

# Vue Loader

如果我们能够在开发中创建 HTML 标记模板，然后让 Vue 的模板编译器在构建步骤中将它们转换为`render`函数，那将是两全其美的。

这正是当 Webpack 通过*Vue Loader*转换它们时发生在单文件组件中的情况。看一下下面的 JavaScript 捆绑包片段，你可以看到 Webpack 在转换和捆绑`ImageCarousel`组件后的情况：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/69fddd6b-68ae-49e6-ac7a-940ebb773a41.png)图 6.15。捆绑文件中的 image-carousel 组件

# 将主模板重构为单文件组件

我们应用的根实例的模板是*app*视图中`#app`元素内的内容。这样的 DOM 模板需要 Vue 模板编译器，就像任何字符串模板一样。

如果我们能够将这个 DOM 模板抽象成一个 SFC，那么我们所有的前端应用模板都将被构建为`render`函数，并且不需要在运行时调用模板编译器。

让我们为主模板创建一个新的 SFC，并将其命名为`ListingPage`，因为这部分应用是我们的列表页面：

```php
$ touch resources/assets/components/ListingPage.vue
```

我们将主模板、根配置和任何相关的 CSS 移到这个组件中。注意以下内容：

+   我们需要将模板放在一个包装的`div`中，因为组件必须有一个单一的根元素

+   现在我们可以删除`@`转义，因为这个文件不会被 Blade 处理

+   现在组件与我们创建的其他组件相邻，所以确保更改导入的相对路径

`resource/assets/components/ListingPage.vue`：

```php
<template>
  <div>
    <header-image 
      :image-url="images[0]" 
      @header-clicked="openModal" ></header-image>
    <div class="container">
      <div class="heading">
        <h1>{{ title }}</h1>
        <p>{{ address }}</p>
      </div>
      <hr>
      <div class="about">
        <h3>About this listing</h3>
        <expandable-text>{{ about }}</expandable-text>
      </div>
      <div class="lists">
        <feature-list title="Amenities" :items="amenities">
          <template slot-scope="amenity">
            <i class="fa fa-lg" :class="amenity.icon"></i>
            <span>{{ amenity.title }}</span>
          </template>
        </feature-list>
        <feature-list title="Prices" :items="prices">
          <template slot-scope="price"> {{ price.title }}: <strong>{{ price.value }}</strong>
          </template>
        </feature-list>
      </div>
    </div>
    <modal-window ref="imagemodal">
      <image-carousel :images="images"></image-carousel>
    </modal-window>
  </div>
</template>
<script> import { populateAmenitiesAndPrices } from '../js/helpers';

  let model = JSON.parse(window.vuebnb_listing_model); model = populateAmenitiesAndPrices(model);

  import ImageCarousel from './ImageCarousel.vue';
  import ModalWindow from './ModalWindow.vue';
  import FeatureList from './FeatureList.vue';
  import HeaderImage from './HeaderImage.vue';
  import ExpandableText from './ExpandableText.vue';

  export default {
    data() {
      return Object.assign(model, {});
    }, components: { ImageCarousel, ModalWindow, FeatureList, HeaderImage, ExpandableText }, methods: {
      openModal() {
        this.$refs.imagemodal.modalOpen = true;
      }
    }
  } </script>
<style> .about {
    margin: 2em 0;
  }

  .about h3 {
    font-size: 22px;
  } </style>
```

# 使用渲染函数挂载根级组件

现在我们主模板中的挂载元素将是空的。我们需要声明`Listing`组件，但我们不想在视图中这样做。

`resources/views/app.blade.php`：

```php
<body>
<div id="toolbar">
  <img class="icon" src="{{ asset('images/logo.png') }}">
  <h1>vuebnb</h1>
</div>
<div id="app">
  <listing></listing>
</div>
<script src="{{ asset('js/app.js') }}"></script>
</body>
```

如果我们这样做，就无法完全消除应用中的所有字符串和 DOM 模板，所以我们将保持挂载元素为空。

`resources/views/app.blade.php`：

```php
... <div id="app"></div> ...
```

我们现在可以在我们的根实例中声明`Listing`并使用渲染函数。

`resources/assets/js/app.js`：

```php
import "core-js/fn/object/assign";
import Vue from 'vue';

import ListingPage from '../components/ListingPage.vue';

var app = new Vue({ el: '#app', render: h => h(ListingPage)
});
```

为了避免走神，我不会在这里解释`render`函数的语法，因为这是我们在整本书中唯一要编写的函数。如果您想了解更多关于`render`函数的信息，请查看 Vue.js 文档[`vuejs.org/`](https://vuejs.org/)。

现在 Vuebnb 不再使用字符串或 DOM 模板，我们不再需要模板编译器功能。有一个特殊的 Vue 构建可以使用，不包括它！

# Vue.js 构建

运行 Vue.js 有许多不同的环境和用例。在一个项目中，您可能直接在浏览器中加载 Vue，在另一个项目中，您可能在 Node.js 服务器上加载它，以进行服务器渲染。因此，提供了不同的 Vue *构建*，以便您可以选择最合适的一个。

在 Vue NPM 包的*dist*文件夹中，我们可以看到八个不同的 Vue.js 构建：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/98257a32-3bf0-455f-bd0a-9ebee829d1e9.png)图 6.16。node_modules/vue/dist 文件夹中的各种构建

Vue.js 网站提供了一个表格来解释这八个不同的构建：

|  | UMD | CommonJS | ES Module |
| --- | --- | --- | --- |
| **完整** | vue.js | vue.common.js | vue.esm.js |
| **仅运行时** | vue.runtime.js | vue.runtime.common.js | vue.runtime.esm.js |
| **完整（生产环境）** | vue.min.js | - | - |
| **仅运行时（生产环境）** | vue.runtime.min.js | - | - |

# 模块系统

表格的列将构建分类为*UMD*、*CommonJS*或*ES Module*。我们在第五章中讨论了 CommonJS 和 ES 模块，但我们没有提到**UMD**（**通用模块定义**）。关于 UMD，您需要知道的主要是它是另一种模块模式，并且在浏览器中运行良好。如果您直接在`script`标签中链接到 Vue，UMD 就是最佳选择。

# 生产构建

表格的行分为两种类型：完整或运行时，以及带有或不带有生产环境。

*生产*构建用于部署的应用程序，而不是在开发中运行的应用程序。它已经被缩小，并且关闭或剥离了任何警告、注释或其他开发选项。目的是使构建尽可能小和安全，这是您在生产中想要的。

请注意，生产构建只有 UMD 版本，因为只有 UMD 可以直接在浏览器中运行。CommonJS 和 ES 模块需要与构建工具一起使用，比如 Webpack，它提供了自己的生产处理。

# 完整构建与仅运行时

正如我们所讨论的，Vue 包括一个模板编译器，用于在运行时将任何字符串或 DOM 模板转换为渲染函数。*完整*构建包括模板编译器，这是您通常会使用的。但是，如果您已经在开发中将模板转换为渲染函数，您可以使用*仅运行时*构建，它不包括编译器，大小约小 30％！

# 选择构建

对于 Vuebnb 来说，一个很好的构建是`vue.runtime.esm.js`，因为我们使用 Webpack，不需要模板编译器。我们也可以使用`vue.runtime.common.js`，但这与我们在项目的其他地方使用 ES 模块不一致。实际上，它们没有区别，因为 Webpack 会以相同的方式处理它们。

请记住，在我们的入口文件顶部包含了 Vue 的语句`import Vue from 'vue'`。最后的`'vue'`是 Webpack 运行时解析的 Vue 构建的*别名*。目前，这个别名在默认的 Mix 配置中定义，并设置为构建`vue.common.js`。我们可以通过在`webpack.mix.js`文件底部添加以下内容来覆盖该配置。

`webpack.mix.js`：

```php
...

mix.webpackConfig({ resolve: { alias: {
      'vue$': 'vue/dist/vue.runtime.esm.js'
    }
  }
});
```

在新的构建之后，我们应该期望看到由于模板编译器被移除而导致的较小的捆绑包大小。在下面的屏幕截图中，我展示了在单独的终端标签页中运行`dev`构建之前和之后的捆绑包：

图 6.17。应用运行时构建后捆绑包大小的差异

请记住，没有了模板编译器，我们不能再为我们的组件提供字符串模板。这样做将导致运行时错误。不过，这不应该是一个问题，因为我们有更强大的 SFC 选项。

# 摘要

在本章中，我们看到了如何使用组件来创建可重用的自定义元素。然后，我们注册了我们的第一个 Vue.js 组件，并用模板字符串来定义它们。

接下来，我们将使用 props 和自定义事件来进行组件通信。我们利用这些知识在列表页面模态窗口中构建了一个图像轮播。

在本章的下半部分，我们介绍了单文件组件，我们使用它来重构 Vuebnb 成为基于组件的架构。然后，我们学习了插槽如何帮助我们通过组合父级和子级内容来创建更多功能的组件。

最后，我们看到了如何使用仅运行时构建来使 Vue 应用程序的大小更小。

在下一章中，我们将通过构建主页并使用 Vue Router 来实现页面之间的导航而不重新加载，将 Vuebnb 打造成一个多页面应用程序。
