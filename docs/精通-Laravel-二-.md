# 精通 Laravel（二）

> 原文：[`zh.annas-archive.org/md5/d10bf45da1cebf8f2b06a9600172079d`](https://zh.annas-archive.org/md5/d10bf45da1cebf8f2b06a9600172079d)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：创建 RESTful API

如果有一个单一的核心功能可以展示 Laravel 的优越性，那就是快速轻松地创建 RESTful API 的能力。随着 Laravel 5 的到来，添加了几个新功能；然而，通过 Artisan 命令行工具创建应用程序模型和控制器的能力仍然是最有用的功能。

这个功能最初鼓励了我和其他许多人放弃诸如 CodeIgniter 之类的框架，因为在 Laravel 4 测试版时，它并没有原生具有相同的集成功能。Laravel 提供了基本的 CRUD 方法：创建，读取，更新，删除，并且还列出了所有内容。

通过 HTTP 到达 Laravel URL 的请求是通过它们的动词管理的，随后是`routes.php`文件，该文件位于`app/Http/routes.php`。请求处理有两种方式。一种方式是直接通过闭包处理请求，代码完全在`routes`文件中。另一种方式是将请求路由到控制器，其中将执行一个方法。

此外，使用的基本范式是约定优于配置，其中方法名称已准备好处理各种请求，而无需太多额外的努力。

# Laravel 中的 RESTful API

由 RESTful API 处理的 RESTful API 请求列表如下：

|   | HTTP VERB | Function | URL |
| --- | --- | --- | --- |
| 1 | `GET` | 列出所有住宿 | `/accommodations` |
| 2 | `GET` | 显示（读取）单个住宿 | `/accommodations/{id}` |
| 3 | `POST` | 创建新的住宿 | `/accommodations` |
| 4 | `PUT` | 完全修改（更新）住宿 | `/accommodations/{id}` |
| 5 | `PATCH` | 部分修改（更新）住宿 | `/accommodations/{id}` |
| 6 | `DELETE` | 删除住宿 | `/accommodations/{id}` |

大多数 RESTful API 最佳实践建议使用模型名称的复数形式。Laravel 的文档使用单数格式。大多数实践都同意一致的复数命名，即`/accommodations/{id}`指的是单个住宿，`/accommodations`指的是多个住宿，都使用复数形式，而不是混合的，但语法上正确的`/accommodation/{id}`（单数形式）和`/accommodations`（复数形式）。

# 基本 CRUD

为简单起见，我已经对每一行进行了编号。第一和第二项代表了 CRUD 的“读取”部分。

第一项是对模型名称的复数形式进行的`GET`调用，相当简单；它显示所有项目。有时，这被称为“列表”，以区别于单个记录的“读取”。因此，添加一个“列表”将扩展首字母缩写为 CRUDL。它们可以进行分页或需要授权。

第二项，也是`GET`调用，将模型的 ID 添加到 URL 的末尾，显示具有相应 ID 的单个模型。这也可能需要身份验证，但不需要分页。

第三项代表了 CRUD 的“创建”部分。它使用`POST`动词来创建一个新的模型。请注意，URL 格式与第一项相同；这展示了动词在区分操作中的重要性。

第四、第五和第六项使用了一些浏览器不支持的新的`HTTP`动词。无论这些动词是否受支持，JavaScript 库和框架（如 jQuery）都会以 Laravel 可以正确处理的方式发送动词。

第四项是 CRUD 的“更新”部分，使用`PUT`动词更新模型。请注意，它与第二项具有相同的 URL 格式，因为它需要知道要更新哪个模型。它也是幂等的，这意味着整个模型必须被更新。

第五项类似于第四项；它更新模型，但使用`PATCH`动词。这用于指示模型将被部分修改，这意味着一个或多个模型的属性必须被更改。

第六项删除一个单个模型，因此需要模型的 ID，使用不言自明的 `DELETE` 动词。

# 额外功能

Laravel 添加了两个通常不是标准 RESTful API 的额外方法。在模型 URL 上使用 `GET` 方法，添加 `create` 用于显示创建模型的表单。在带有 ID 的模型 URL 上使用 `GET` 方法，添加 `edit` 用于显示创建模型的表单。这两个功能对于提供将加载表单的 URL 非常有用，尽管这种类型的使用不是标准的 RESTful：

| HTTP VERB | Function | URL |   |
| --- | --- | --- | --- |
| `GET` | 这显示一个住宿创建表单 | `/accommodations/create` |   |
| `GET` | 这显示一个住宿修改/更新表单 | `/accommodations/{id}/edit` |   |

# 控制器创建

要为住宿创建一个控制器，使用以下 Artisan 命令：

```php
**$ php artisan make:controller AccommodationsController**

 **<?php namespace MyCompany\Http\Controllers;**

 **use MyCompany\Http\Requests;**
 **use MyCompany\Http\Controllers\Controller;**
 **use Illuminate\Http\Request;**

 **class AccommodationController extends Controller {**

 **/****
 *** Display a listing of the resource.**
 *** @return Response**
 ***/**
 **public function index()**
 **{**
 **}**

 **/****
 *** Show the form for creating a new resource.**
 *** @return Response**
 ***/**
 **public function create()**
 **{**
 **}**

 **/****
 *** Store a newly created resource in storage.**
 *** @return Response**
 ***/**
 **public function store()**
 **{**
 **}**

 **/****
 *** Display the specified resource.**
 *** @param  int  $id**
 *** @return Response**
 ***/**
 **public function show($id)**
 **{**
 **}**

 **/****
 *** Show the form for editing the specified resource.**
 *** @param  int  $id**
 *** @return Response**
 ***/**
 **public function edit($id)**
 **{**
 **}**

 **/****
 *** Update the specified resource in storage.**
 *****
 *** @param  int  $id**
 *** @return Response**
 ***/**
 **public function update($id)**
 **{**
 **}**

 **/****
 *** Remove the specified resource from storage.**
 *** @param  int  $id**
 *** @return Response**
 ***/**
 **public function destroy($id)**
 **{**
 **}**
 **}**

```

# 通过示例进行 CRUD(L)

我们之前看过这个控制器，但这里有一些示例。RESTful 调用的最简单示例将如下所示。

## cRudl – 读取

创建一个 `GET` 调用到 `http://www.hotelwebsite.com/accommmodations/1`，其中 `1` 将是房间的 ID：

```php
/**
 * Display the specified resource.
 *
 * @param  int  $id
 * @return Response
 */
public function show($id)
{
    return \MyCompany\Accommodation::findOrFail($id);
}
```

这将返回一个单个模型作为 JSON 编码对象：

```php
{
    "id": 1,
    "name": "Hotel On The Hill","description":"Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
    "location_id": 1,
    "created_at": "2015-02-08 20:13:10",
    "updated_at": "2015-02-08 20:13:10",
    "deleted_at": null
}
```

## crudL – 列表

创建一个 GET 调用到 `http://www.hotelwebsite.com/accommmodations`。

这与前面的代码类似，但略有不同：

```php
/** Display a listing of the resource.
    * @return Response
 */
public function index()
{
    return Accommodation::all();
}
```

这将返回所有模型，自动编码为 JSON 对象；没有其他要求。已添加格式，以便 JSON 结果更易读，但基本上整个模型都会返回：

```php
[{ 
    "id": 1,
    "name": "Hotel On The Hill","description":"Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
    "location_id": 1,
    "created_at": "2015-02-08 20:13:10",
    "updated_at": "2015-02-08 20:13:10",
    "deleted_at": null
} 
{   "id": 2,
    "name": "Patterson Place",
    "description": "Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
    "location_id": 2,
    "created_at": "2015-02-08 20:15:02",
    "updated_at": "2015-02-08 20:15:02",
    "deleted_at": null
},
{
    "id": 3,
    "name": "Neat and Tidy Hotel",
    "description": "Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
    "location_id": 3,
    "created_at": "2015-02-08 20:17:34",
    "updated_at": "2015-02-08 20:17:34",
    "deleted_at": null
}
]
```

### 提示

`deleted_at` 字段是软删除或回收站机制。对于未删除的情况，它要么是 `null`，要么是已删除的 `date`/`time` 时间戳。

### 分页

要添加分页，只需用 `paginate()` 替换 `all()`：

```php
public function index()
{
    return Accommodation::paginate();
}
```

现在结果看起来像这样。Eloquent 集合数组现在移动到 `date` 属性内：

```php
{"total":15,
"per_page":15,
"current_page":1,
"last_page":1,
"next_page_url":null,
"prev_page_url":null,
"from":1,
"to":15,
"data":[{"id":9,
"name":"Lovely Hotel",
"description":"Lovely Hotel Greater Pittsburgh",
….
```

## Crudl – 创建

创建一个 `POST` 调用到 `http://www.hotelwebsite.com/accommmodations`。

要创建一个新模型，将发送一个 `POST` 调用到 `/accommodations`。前端将发送一个 JSON 如下：

```php
{
    "name": "Lovely Hotel",
    "description": "Lovely Hotel Greater Pittsburgh",
    "location_id":1
}
```

`store` 函数可能看起来像这样：

```php
public function store()
{
    $input = \Input::json();
    $accommodation = new Accommodation;
    $accommodation->name = $input->get('name');
    $accommodation->description = $input->get('description');
    $accommodation->location_id = $input->get('location_id');
    $accommodation->save();
    return response($accommodation, 201)
;
}
```

### 提示

`201` 是 `created` 的 HTTP 状态码（`HTTP/1.1 201 created`）。

在这个例子中，我们将模型作为 JSON 编码对象返回。对象将包括插入的 ID：

```php
{
    "name":"Lovely Hotel",
    "description":"Lovely Hotel Greater Pittsburgh",
    "location_id":1,
    "updated_at":"2015-03-13 20:48:19",
    "created_at":"2015-03-13 20:48:19",
    "id":26
}
```

## crUdl – 更新

创建一个 `PUT` 调用到 `http://www.hotelwebsite.com/accommmodations/1`，其中 `1` 是要更新的 ID：

```php
/**
    * Update the specified resource in storage.
    *
    * @param  int  $id
    * @return Response
    */
    public function update($id)
    {
        $input = \Input::json();
        $accommodation = \MyCompany\Accommodation::findOrFail($id);
        $accommodation->name = $input->get('name');
        $accommodation->description = $input->get('description');
        $accommodation->location_id = $input->get('location_id');
        $accommodation->save();
        return response($accommodation, 200)
            ->header('Content-Type', 'application/json');
    }
```

要更新现有模型，代码与之前使用的完全相同，只是使用以下行来查找现有模型：

```php
$accommodation = Accommodation::find($id);
```

`PUT` 动词将发送到 `/accommodations/{id}`，其中 `id` 将是住宿表的数字 ID。

## cruDl – 删除

要删除一个模型，创建一个 `DELETE` 调用到 `http://www.hotelwebsite.com/accommmodation/1`，其中 `1` 是要删除的 ID：

```php
/**
 * Remove the specified resource from storage.
 *
 * @param  int  $id
 * @return Response
 */
public function destroy($id)
{
    $accommodation = Accommodation::find($id);
    $accommodation->delete();
    return response('Deleted.', 200)
;
}
```

### 提示

关于删除模型的适当状态码似乎存在一些分歧。

# 模型绑定

现在，我们可以使用一种称为*模型绑定*的技术来进一步简化代码：

```php
public function boot(Router $router)
{
    parent::boot($router);
    $router->model('accommodations', '\MyCompany\Accommodation');
}
```

在 `app/Providers/RouteServiceProvider.php` 中，添加接受路由作为第一个参数并将要绑定的模型作为第二个参数的 `$router->model()` 方法。

## 重新访问读取

现在，我们的 `show` 控制器方法看起来像这样：

```php
public function show(Accommodation $accommodation)
{
    return $accommodation;
}
```

当调用 `/accommodations/1` 时，例如，与该 ID 对应的模型将被注入到方法中，允许我们替换查找方法。

## 重新访问列表

同样，对于 `list` 方法，我们按照类型提示的模型注入如下：

```php
public function index(Accommodation $accommodation)
{
    return $accommodation;
}
```

## 更新重新访问

同样，`update` 方法现在看起来像这样：

```php
public function update(Accommodation $accommodation)
{
    $input = \Input::json();
    $accommodation->name = $input->get('name');
    $accommodation->description = $input->get('description');
    $accommodation->location_id = $input->get('location_id');
    $accommodation->save();
    return response($accommodation, 200)
    ->header('Content-Type', 'application/json');
}
```

## 删除重新访问

此外，`destroy` 方法看起来像这样：

```php
public function destroy(Accommodation $accommodation)
{
    $accommodation->delete();
    return response('Deleted.', 200)
        ->header('Content-Type', 'text/html');
}
```

# 超越 CRUD

如果软件应用的一个要求是能够搜索住宿，那么我们可以很容易地添加一个搜索函数。搜索函数将使用`name`字符串查找住宿。一种方法是将路由添加到`routes.php`文件中。这将把`GET`调用映射到`AccommodationsController`中包含的新的`search()`函数：

```php
Route::get('search', 'AccommodationsController@search');
Route::resource('accommodations', 'AccommodationsController');
```

### 提示

在这种情况下，`GET`方法比`POST`方法更可取，因为它可以被收藏并稍后调用。

现在，我们将编写我们的搜索函数：

```php
public function search(Request $request, Accommodation $accommodation)
{
    return $accommodation
        ->where('name',
          'like',
          '%'.$request->get('name').'%')
        ->get();
    }
```

这里有几种机制：

+   包含来自`GET`请求的变量的`Request`对象被类型提示，然后注入到搜索函数中

+   `Accommodation`模型被类型提示，然后注入到`search`函数中

+   在 Eloquent 模型`$accommodation`上调用了`where()`方法

+   从`request`对象中使用`name`参数

+   使用`get()`方法来执行实际的 SQL 查询

### 提示

请注意，查询构建器和 Eloquent 方法中的一些返回查询构建器的实例，而其他方法执行查询并返回结果。`where()`方法返回查询构建器的实例，而`get()`方法执行查询。

+   返回的 Eloquent 集合会自动编码为 JSON

因此，`GET`请求如下：

```php
http://www.hotelwebsite.com/search-accommodation?name=Lovely
```

生成的 JSON 看起来会像这样：

```php
[{"id":3,
"name":"Lovely Hotel",
"description":"Lovely Hotel Greater Pittsburgh",
"location_id":1,
"created_at":"2015-03-13 22:00:23",
"updated_at":"2015-03-13 22:00:23",
"deleted_at":null},
{"id":4,
"name":"Lovely Hotel",
"description":"Lovely Hotel Greater Philadelphia",
"location_id":2,
"created_at":"2015-03-11 21:43:31",
"updated_at":"2015-03-11 21:43:31",
"deleted_at":null}]
```

# 嵌套控制器

嵌套控制器是 Laravel 5 中的一个新功能，用于处理涉及关系的所有 RESTful 操作。例如，我们可以利用这个功能来处理住宿和客房之间的关系。

住宿和客房之间的关系如下：

+   一个住宿可以有一个或多个房间（一对多）

+   一个房间只属于一个住宿（一对一）

现在，我们将编写代码，使得我们的模型能够熟练处理 Laravel 的一对一和一对多关系。

## Accommodation 有许多 rooms

首先，我们将添加所需的代码到代表`accommodation`模型的`Accomodation.php`文件中：

```php
class Accommodation extends Model {
    public function rooms(){
        return $this->hasMany('\MyCompany\Accommodation\Room');
    }
}
```

`rooms()`方法创建了一种从住宿模型内部访问关系的简单方法。关系说明了“住宿*有许多*房间”。`hasMany`函数，当位于`Accommodation`类内部时，没有额外的参数，期望`Room`模型的表中存在一个名为`accommodation_id`的列，这在这种情况下是`rooms`。

## Room 属于 accommodation

现在，我们将添加`Room.php`文件所需的代码，该文件代表`Room`模型：

```php
class Room extends Model
{
    public function accommodation(){
        return $this->belongsTo('\MyCompany\Accommodation');
    }
}
```

这段代码说明了“一个房间*属于*一个住宿”。`Room`类中的*belongsTo*方法，没有额外的参数，期望`room`模型的表中存在一个字段；在这种情况下，名为`accommodation_id`的`rooms`。

### 提示

如果应用程序数据库中的表遵循了活动记录约定，那么大多数 Eloquent 关系功能将自动运行。所有参数都可以很容易地配置。

创建嵌套控制器的命令如下：

```php
**$php artisan make:controller AccommodationsRoomsController**

```

然后，以下行将被添加到`app/Http/routes.php`文件中：

```php
Route::resource('accommodations.rooms', 'AccommodationsRoomsController');
```

要显示创建的路由，应执行以下命令：

```php
**$php artisan route:list**

```

以下表列出了 HTTP 动词及其功能：

|   | HTTP 动词 | 功能 | URL |
| --- | --- | --- | --- |
| 1 | `GET` | 这显示了住宿和客房的关系 | `/accommodations/{accommodations}/rooms` |
| 2 | `GET` | 这显示了住宿和客房的关系 | `/accommodations/{accommodations}/rooms/{rooms}` |
| 3 | `POST` | 这创建了一个新的住宿和客房的关系 | `/accommodations/{accommodations}/rooms` |
| 4 | `PUT` | 这完全修改（更新）了住宿和客房的关系 | `/accommodations/{accommodations}/rooms/{rooms}` |
| 5 | `PATCH` | 部分修改（更新）住宿和房间关系 | `/accommodations/{accommodations}/rooms/{rooms}` |
| 6 | `DELETE` | 删除住宿和房间关系 | `/accommodations/{accommodations}/rooms/{rooms}` |

## 雄辩的关系

一个很好的机制用于直接在控制器内部说明雄辩关系，通过使用**嵌套关系**来执行，其中两个模型首先通过路由连接，然后通过它们的控制器方法的参数通过模型依赖注入连接。

## 嵌套更新

让我们调查`update`/`modify PUT`嵌套控制器命令。URL 看起来像这样：`http://www.hotelwebsite.com/accommodations/21/rooms/13`。

这里，`21`将是住宿的 ID，`13`将是房间的 ID。参数是类型提示的模型。这使我们可以轻松地更新关系，如下所示：

```php
public function update(Accommodation $accommodation, Room $room)
{
    $room->accommodation()->associate($accommodation);
    $room->save();
}
```

## 嵌套创建

同样，可以通过`POST`请求将嵌套的`create`操作执行到`http://www.hotelwebsite.com/accommodations/21/rooms`。`POST`请求的 body 是一个 JSON 格式的对象：

```php
{"roomNumber":"123"}
```

请注意，由于我们正在创建房间，因此不需要房间 ID：

```php
public function store(Accommodation $accommodation)
{
    $input = \Input::json();
    $room = new Room();
    $room->room_number = $input->get('roomNumber');
    $room->save();
    $accommodation->rooms()->save($room);
}
```

# 雄辩模型转换

模型以 JSON 格式返回，就像它们在数据库中表示的那样。通常，模型属性，其性质为布尔值，分别用`0`和`1`表示`true`和`false`。在这种情况下，更方便的是返回一个真正的`true`和`false`给 RESTful 调用的返回对象。

在 Laravel 4 中，这是使用**访问器**完成的。如果值是`$status`，则方法将定义如下：

```php
public function getStatusAttribute($value){
    //do conversion;
}
```

在 Laravel 5 中，由于有了一个称为模型转换的新功能，这个过程变得更加容易。要应用这种技术，只需将一个受保护的键和一个名为`$casts`的值数组添加到模型中，如下所示：

```php
class Room extends Model
{
    protected $casts = ['room_number'=>'integer','status'=>'boolean'];
    public function accommodation(){
        return $this->belongsTo('\MyCompany\Accommodation');
    }
}
```

在这个例子中，`room_number`是一个字符串，但我们想返回一个整数。状态是一个小整数，但我们想返回一个布尔值。在模型中对这两个值进行转换将以以下方式修改结果 JSON：

```php
{"id":1,
"room_number": "101",
"status": 1,
"created_at":"2015-03-14 09:25:59",
"updated_at":"2015-03-14 19:03:03",
"deleted_at":null,
"accommodation_id":2}
```

前面的代码现在将改变如下：

```php
{"id":1,
"room_number": 101,
"status": true,
"created_at":"2015-03-14 09:25:59",
"updated_at":"2015-03-14 19:03:03",
"deleted_at":null,
"accommodation_id":2}
```

# 路由缓存

Laravel 5 有一个新的机制用于缓存路由，因为`routes.php`文件很容易变得非常庞大，并且会迅速减慢请求过程。要启用缓存机制，输入以下`artisan`命令：

```php
**$ php artisan route:cache**

```

这将在`/storage/framework/routes.php`中创建另一个`routes.php`文件。如果该文件存在，则会使用它，而不是位于`app/Http/routes.php`中的`routes.php`文件。文件的结构如下：

```php
<?php

/*
|--------------------------------------------------------------------------
| Load The Cached Routes
|
…
*/

app('router')->setRoutes(
unserialize(base64_decode('TzozNDoiSWxsdW1pbmF0ZVxSb3V0aW5nXFJvdXRlQ29sbGVjdGlvbiI6NDp7czo5OiIAKgByb3V0ZXMiO2E6Njp7czozOiJHRVQiO2E6M
…
... VyQGluZGV4IjtzOjk6Im5hbWVzcGFjZSI7czoyNjoiTXlDb21wYWbXBhbnlcSHR0cFxDb250cm9sbGVyc1xIb3RlbENvbnRyb2xsZXJAZGVzdHJveSI7cjo4Mzg7fX0='))
);
```

请注意，这里使用了一个有趣的技术。路由被序列化，然后进行 base64 编码。显然，要读取路由，使用相反的方法，`base64_decode()`，然后`unserialize()`。

如果`routes.php`缓存文件存在，则每次对`routes.php`文件进行更改时，都必须执行路由缓存`artisan`命令。这将清除文件，然后重新创建它。如果以后决定不再使用这种机制，则可以使用以下`artisan`命令来消除该文件：

```php
**$ php artisan route:clear**

```

Laravel 对于构建几种完全不同类型的应用程序非常有用。在构建传统的 Web 应用程序时，控制器和视图之间通常有着紧密的集成。当构建可以在智能手机上使用的应用程序时，它也非常有用。在这种情况下，前端将使用另一种编程语言和/或框架为智能手机的操作系统创建。在这种情况下，可能只会使用控制器和模型。无论哪种情况，拥有一个良好文档化的 RESTful API 是现代软件设计的重要组成部分。

嵌套控制器帮助开发人员立即阅读代码——这是一种理解特定控制器处理“嵌套”或一个类与另一个相关联的概念的简单方法。

在控制器中对模型和对象进行类型提示也提高了可读性，同时减少了执行对象的基本操作所需的代码量。

此外，雄辩的模型转换为模型的属性提供了一种简单的方式，无需依赖外部包或繁琐的访问器函数，就像在 Laravel 4 中那样。

现在我们很清楚为什么 Laravel 正在成为许多开发人员的选择。学习并重复本章中所述的一些步骤将允许在一个小时内为一个中小型程序创建一个 RESTful API。

# 总结

RESTful API 为将来扩展程序提供了一种简单的方式，也与公司内部可能需要与应用程序通信的第三方程序和软件集成。RESTful API 是程序内部的最前端外壳，并提供了外部世界与应用程序本身之间的桥梁。程序的内部部分将是所有业务逻辑和数据库连接所在的地方，因此从根本上说，控制器只是连接路由和应用程序的工作。

Laravel 遵循 RESTful 最佳实践，因此文档化 API 对其他开发人员和第三方集成商来说应该足够容易理解。Laravel 5 为框架引入了一些功能，使代码更易读。

在未来的章节中，将讨论中间件。中间件在路由和控制器之间添加了各种“中间”层。中间件可以提供诸如身份验证之类的功能。中间件将丰富、保护并帮助将路由组织成逻辑和功能组。

我们还将讨论 DocBlock 注释。虽然 PHP 本身不支持注释，但可以通过 Laravel 社区包启用。然后，在控制器和控制器函数的 DocBlock 中，每个控制器的路由将自动创建，而无需实际修改`app/Http/routes.php`文件。这是 Laravel 轻松适应的另一个伟大的社区概念，就像 phpspec 和 Behat 一样。


# 第五章：使用表单生成器

在本章中，您将学习如何使用 Laravel 的表单生成器。表单生成器将被演示以便于构建以下元素：

+   表单（打开和关闭）

+   标签

+   输入（文本，HTML5 密码，HTML5 电子邮件等）

+   复选框

+   提交

+   锚标签（href 链接）

最后，我们将看到如何使用表单生成器为住宿预订软件表单创建月份、日期和年份选择元素的示例，以及如何创建一个宏来减少代码重复。

# 历史

Laravel 4 中的表单生成器包称为 HTML。这是用来帮助您创建 HTML 的，特别是那些还必须执行 Web 设计师职责但更喜欢使用 Laravel 门面和辅助方法的开发人员。例如，以下是 Laravel 门面`select()`方法的示例，其中语言的选项，例如英式和美式英语，在此示例中作为数组参数传递：

```php
Form::select('language', ['en-us' => 'English (US)','en-gb' => 'English (UK)']);
```

这可以作为标准 HTML 的替代方案，标准 HTML 需要更多重复的代码，如下面的代码所示：

```php
<select name="language">
    <option value="en-us">English (US)</option>
    <option value="en-gb">English (UK)</option>
</select>
```

由于框架不断发展，它们需要适应满足大多数用户的需求。此外，尽可能地，它们应该继续变得更加高效。在某些情况下，这意味着重写或重构框架的部分，添加功能，甚至*删除*它们。

尽管可能看起来奇怪，但删除功能有几个有效的原因。以下是删除包的原因列表：

+   减轻框架核心开发人员需要维护的包和功能的负担和数量。

+   减少下载和自动加载的包数量。

+   删除一个不必要的功能。

+   HTML 包已经从 Laravel 5 的核心中移除，现在是一个外部包。在这种情况下，任何之前的原因都可以被引用为移除这个包的原因。

+   HTML 有助于开发人员构建表单，如果前端开发人员也是后端或全栈开发人员，并且喜欢 Laravel 的做事方式，可以使用。然而，在其他情况下，Web 应用的 HTML 界面可以使用 JavaScript 框架或库来构建，例如 AngularJS 或 Backbone.js。在这种情况下，Laravel 表单包就不是必需的。另外，如前所述，Laravel 可以用来创建一个仅仅是 RESTful API 的应用程序。在这种情况下，将 HTML 包包含在框架核心中就不是必要的，因此仍然是辅助的。

在这种特殊情况下，某些 Laravel 包被移除以简化整体体验，并朝着更*基于组件*的方法迈进，这与 Symfony 中使用的方法类似。

# 安装 HTML 包

如果您希望在 Laravel 5 中使用 HTML 包，安装它是一个简单的过程。Laravel 社区的一群开发人员成立了一个名为 Laravel collective 的存储库，用于维护已从 Laravel 中移除的包。要安装 HTML 包，只需使用`composer`命令将包添加到应用程序中，如下所示：

```php
**$ composer require laravelcollective/html**

```

### 注意

请注意，`illuminate/HTML`包已被弃用。

这将安装 HTML 包，并且`composer.json`将显示您添加到`require`部分的包如下：

```php
"require": {
    "laravel/framework": "5.0.*",
    "laravelcollective/html": "~5.0",
  },
```

此时，包已安装。

现在，我们需要将`HTMLServiceProvider`添加到`config/app.php`文件中的提供者列表中：

```php
  'providers' => [
  ...
    'Collective\Html\HtmlServiceProvider',
  ...
  ],
```

最后，需要将`Form`和`Html`别名添加到`config/app.php`文件中，如下所示：

```php
'aliases' => [
   ...
        'Form' => 'Collective\Html\FormFacade',
        'Html' => 'Collective\Html\HtmlFacade',
   ...
  ],
```

# 使用 Laravel 构建网页

Laravel 构建 Web 内容的方法是灵活的。可以使用尽可能多或尽可能少的 Laravel 来创建 HTML。Laravel 使用`filename.blade.php`约定来说明文件应该由 blade 解析器解析，实际上将文件转换为普通的 PHP。Blade 的名称受到了.NET 的剃刀模板引擎的启发，因此对于曾经使用过它的人来说可能会很熟悉。Laravel 5 在`/resources/views/`目录中提供了一个表单的工作演示。当请求`/home`路由并且用户当前未登录时，将显示此视图。显然，这个表单并不是使用 Laravel 的表单方法创建的。

路由在`routes`文件中定义如下：

```php
Route::get('home', 'HomeController@index');
```

将讨论此路由如何使用中间件来检查如何执行用户身份验证，详见第七章，“使用中间件过滤请求”。

## 主模板

这是以下的`app`（或`master`）模板：

```php
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Laravel</title>

    <link href="/css/app.css" rel="stylesheet">

    <!-- Fonts -->
    <link href='//fonts.googleapis.com/css?family=Roboto:400,300' rel='stylesheet' type='text/css'>

    <!-- HTML5 shim and Respond.js for IE8 support of HTML5 elements and media queries -->
    <!-- WARNING: Respond.js doesn't work if you view the page via file:// -->
    <!--[if lt IE 9]>
        <script src="https://oss.maxcdn.com/html5shiv/3.7.2/html5shiv.min.js"></script>
        <script src="https://oss.maxcdn.com/respond/1.4.2/respond.min.js"></script>
    <![endif]-->
</head>
<body>
    <nav class="navbarnavbar-default">
        <div class="container-fluid">
            <div class="navbar-header">
                <button type="button" class="navbar-toggle collapsed" data-toggle="collapse" data-target="#bs-example-navbar-collapse-1">
                    <span class="sr-only">Toggle Navigation</span>
                    <span class="icon-bar"></span>
                    <span class="icon-bar"></span>
                    <span class="icon-bar"></span>
                </button>
                <a class="navbar-brand" href="#">Laravel</a>
            </div>

            <div class="collapse navbar-collapse" id="bs-example-navbar-collapse-1">
                <ul class="navnavbar-nav">
                    <li><a href="/">Home</a></li>
                </ul>

                <ul class="navnavbar-navnavbar-right">
                    @if (Auth::guest())
                        <li><a href="{{ route('auth.login') }}">Login</a></li>
                        <li><a href="/auth/register">Register</a></li>
                    @else
                        <li class="dropdown">
                            <a href="#" class="dropdown-toggle" data-toggle="dropdown" role="button" aria-expanded="false">{{ Auth::user()->name }} <span class="caret"></span></a>
                            <ul class="dropdown-menu" role="menu">
                                <li><a href="/auth/logout">Logout</a></li>
                            </ul>
                        </li>
                    @endif
                </ul>
            </div>
        </div>
    </nav>

    @yield('content')

    <!-- Scripts -->
    <script src="//cdnjs.cloudflare.com/ajax/libs/jquery/2.1.3/jquery.min.js"></script>
    <script src="//cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/3.3.1/js/bootstrap.min.js"></script>
</body>
</html>
```

Laravel 5 主模板是一个具有以下特点的标准 HTML5 模板：

+   如果浏览器旧于 Internet Explorer 9：

+   使用 HTML5 Shim 来自 CDN

+   使用 Respond.js JavaScript 代码来自 CDN 以适应媒体查询和 CSS3 特性

+   使用`@if (Auth::guest())`，如果用户未经过身份验证，则显示登录表单；否则，显示注销选项。

+   Twitter bootstrap 3.x 包含在 CDN 中

+   jQuery2.x 包含在 CDN 中

+   任何扩展此模板的模板都可以覆盖内容部分

## 示例页面

以下截图显示了登录页面：

![示例页面](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-lrv/img/B04559_05_01.jpg)

登录页面的源代码如下：

```php
@extends('app')
@section('content')
<div class="container-fluid">
    <div class="row">
        <div class="col-md-8 col-md-offset-2">
            <div class="panel panel-default">
                <div class="panel-heading">Login</div>
                <div class="panel-body">
                    @if (count($errors) > 0)
                        <div class="alert alert-danger">
                            <strong>Whoops!</strong> There were some problems with your input.<br><br>
                            <ul>
                                @foreach ($errors->all() as $error)
                                    <li>{{ $error }}</li>
                                @endforeach
                            </ul>
                        </div>
                    @endif

                    <form class="form-horizontal" role="form" method="POST" action="/auth/login">
                        <input type="hidden" name="_token" value="{{ csrf_token() }}">

                        <div class="form-group">
                            <label class="col-md-4 control-label">E-Mail Address</label>
                            <div class="col-md-6">
                                <input type="email" class="form-control" name="email" value="{{ old('email') }}">
                            </div>
                        </div>

                        <div class="form-group">
                            <label class="col-md-4 control-label">Password</label>
                            <div class="col-md-6">
                                <input type="password" class="form-control" name="password">
                            </div>
                        </div>

                        <div class="form-group">
                            <div class="col-md-6 col-md-offset-4">
                                <div class="checkbox">
                                    <label>
                                        <input type="checkbox" name="remember"> Remember Me
                                    </label>
                                </div>
                            </div>
                        </div>

                        <div class="form-group">
                            <div class="col-md-6 col-md-offset-4">
                                <button type="submit" lass="btn btn-primary" style="margin-right: 15px;">
                                    Login
                                </button>

                                <a href="/password/email">Forgot Your Password?</a>
                            </div>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    </div>
</div>
@endsection
```

## 从静态 HTML 到静态方法

此登录页面以以下内容开始：

```php
@extends('app')
```

显然，它使用面向对象的范例来说明将呈现`app.blade.php`模板。以下行覆盖了内容：

```php
@section('content')
```

在这个练习中，将使用表单构建器而不是静态 HTML。

### 表单标签

我们将把静态的`form`标签转换为`FormBuilder`方法。HTML 如下：

```php
<form class="form-horizontal" role="form" method="POST" action="/auth/login">
```

我们将使用的外观方法如下：

```php
Form::open();
```

在`FormBuilder.php`类中，`$reserved`属性定义如下：

```php
protected $reserved = ['method', 'url', 'route', 'action', 'files'];
```

我们需要传递给`open()`方法的属性是 class、role、method 和 action。由于 method 和 action 是保留字，因此需要以以下方式传递参数：

| Laravel 表单外观方法数组元素 | HTML 表单标签属性 |
| --- | --- |
| 方法 | 方法 |
| url | action |
| role | role |
| class | class |

因此，方法调用如下：

```php
{!! 
  Form::open(['class'=>'form-horizontal',
  'role =>'form',
  'method'=>'POST',
  'url'=>'/auth/login']) 
!!}
```

`{!! !!}`标签用于开始和结束表单构建器方法的解析。`form`方法`POST`首先放置在 HTML 表单标签的属性列表中。

### 提示

`action`属性实际上需要是一个`url`。如果使用`action`参数，则它指的是控制器动作。在这种情况下，`url`参数会生成`form`标签的`action`属性。

其他属性将传递给数组并添加到属性列表中。生成的 HTML 将如下所示：

```php
<form method="POST" action="http://laravel.example/auth/login" accept-charset="UTF-8" class="form-horizontal" role="form">

<input name="_token" type="hidden" value="wUY2hFSEWCzKHFfhywHvFbq9TXymUDiRUFreJD4h">
```

CRSF 令牌会自动添加，因为`form`方法是`POST`。

### 文本输入字段

要转换输入字段，使用外观。输入字段的 HTML 如下：

```php
<input type="email" class="form-control" name="email" value="{{ old('email') }}">
```

使用外观转换前面的输入字段如下：

```php
{!! Form::input('email','email',old('email'),['class'=>'form-control' ]) !!}
```

同样，文本字段变为：

```php
{!! Form::input('password','password',null,['class'=>'form-control']) !!}
```

输入字段具有相同的签名。当然，这可以重构如下：

```php
<?php $inputAttributes = ['class'=>'form-control'] ?>
{!! Form::input('email','email',old('email'),$inputAttributes ) !!}
...
{!! Form::input('password','password',null,$inputAttributes ) !!}
```

### 标签标签

`label`标签如下：

```php
<label class="col-md-4 control-label">E-Mail Address</label>
<label class="col-md-4 control-label">Password</label>
```

要转换`label`标签（`E-Mail Address`和`Password`），我们首先创建一个数组来保存属性，然后将此数组传递给标签，如下所示：

```php
$labelAttributes = ['class'=>'col-md-4 control-label'];
```

以下是表单标签代码：

```php
{!! Form::label('email', 'E-Mail Address', $labelAttributes) !!}
{!! Form::label('password', 'Password', $labelAttributes) !!}
```

### 复选框

要将复选框转换为外观，我们将转换为：

```php
<input type="checkbox" name="remember"> Remember Me
```

前面的代码转换为以下代码：

```php
{!! Form::checkbox('remember','') !!} Remember Me
```

### 提示

请记住，如果字符串中没有变量或其他特殊字符（如换行符），则应该用单引号发送 PHP 参数，而生成的 HTML 将使用双引号。

### 提交按钮

最后，提交按钮将被转换如下：

```php
<button type="submit" class="btn btn-primary" style="margin-right: 15px;">
    Login
</button>
```

转换后的前一行代码如下：

```php
    {!! 
        Form::submit('Login',
        ['class'=>'btn btn-primary', 
        'style'=>'margin-right: 15px;'])
     !!}
```

### 提示

请注意，数组参数提供了一种简单的方式来提供任何所需的属性，甚至那些不在标准 HTML 表单元素列表中的属性。

### 带有链接的锚标签

为了转换链接，使用了一个辅助方法。考虑以下代码行：

```php
<a href="/password/email">Forgot Your Password?</a>
```

转换后的前一行代码如下：

```php
{!! link_to('/password/email', $title = 'Forgot Your Password?', $attributes = array(), $secure = null) !!}
```

### 注意

`link_to_route()`方法可用于链接到一个路由。有关类似的辅助函数，请访问[`laravelcollective.com/docs/5.0/html`](http://laravelcollective.com/docs/5.0/html)。

### 关闭表单

为了结束表单，我们将把传统的 HTML 表单标签`</form>`转换为 Laravel 的`{!! Form::close() !!}`表单方法。

### 结果表单

将所有内容放在一起后，页面现在看起来是这样的：

```php
@extends('app')
@section('content')
<div class="container-fluid">
  <div class="row">
    <div class="col-md-8 col-md-offset-2">
      <div class="panel panel-default">
        <div class="panel-heading">Login</div>
          <div class="panel-body">
            @if (count($errors) > 0)
                <div class="alert alert-danger">
                    <strong>Whoops!</strong> There were some problems with your input.<br><br>
                    <ul>
                        @foreach ($errors->all() as $error)
                            <li>{{ $error }}</li>
                        @endforeach
                    </ul>
                </div>
            @endif
            <?php $inputAttributes = ['class'=>'form-control'];
                $labelAttributes = ['class'=>'col-md-4 control-label']; ?>
            {!! Form::open(['class'=>'form-horizontal','role'=>'form','method'=>'POST','url'=>'/auth/login']) !!}
                <div class="form-group">
                    {!! Form::label('email', 'E-Mail Address',$labelAttributes) !!}
                    <div class="col-md-6">
                    {!! Form::input('email','email',old('email'), $inputAttributes) !!}
                    </div>
                </div>
                <div class="form-group">
                    {!! Form::label('password', 'Password',$labelAttributes) !!}
                    <div class="col-md-6">
                        {!! Form::input('password','password',null,$inputAttributes) !!}
                    </div>
                </div>
                <div class="form-group">
                    <div class="col-md-6 col-md-offset-4">
                        <div class="checkbox">
                          <label>
                             {!! Form::checkbox('remember','') !!} Remember Me
                          </label>
                        </div>
                    </div>
                </div>
                <div class="form-group">
                    <div class="col-md-6 col-md-offset-4">
                        {!! Form::submit('Login',['class'=>'btn btn-primary', 'style'=>'margin-right: 15px;']) !!}
                        {!! link_to('/password/email', $title = 'Forgot Your Password?', $attributes = array(), $secure = null); !!}
                    </div>
                </div>
            {!! Form::close() !!}
          </div>
      </div>
    </div>
  </div>
</div>
@endsection
```

# 我们的例子

如果我们想要创建一个预订住宿的表单，我们可以轻松地从我们的控制器中调用一个路由：

```php
/**
 * Show the form for creating a new resource.
 *
 * @return Response
 */
public function create()
{
    return view('auth/reserve');
}
```

现在我们需要创建一个位于`resources/views/auth/reserve.blade.php`的新视图。

在这个视图中，我们可以创建一个表单来预订住宿，用户可以选择开始日期，其中包括月份和年份的开始日期，以及结束日期，也包括月份和年份的开始日期：

![我们的例子](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-lrv/img/B04559_05_02.jpg)

表单将如前所述开始，通过 POST 到`reserve-room`。然后，表单标签将放置在选择输入字段旁边。最后，日期、月份和年份选择表单元素将被创建如下：

```php
{!! Form::open(['class'=>'form-horizontal',
        'role'=>'form', 
        'method'=>'POST', 
        'url'=>'reserve-room']) !!}
        {!! Form::label(null, 'Start Date',$labelAttributes) !!}

        {!! Form::selectMonth('month',date('m')) !!}
        {!! Form::selectRange('date',1,31,date('d')) !!}
        {!! Form::selectRange('year',date('Y'),date('Y')+3) !!}

        {!! Form::label(null, 'End Date',$labelAttributes) !!}

        {!! Form::selectMonth('month',date('m')) !!}
        {!! Form::selectRange('date',1,31,date('d')) !!}
        {!! Form::selectRange('year',date('Y'),date('Y')+3,date('Y')) !!}

        {!! Form::submit('Reserve',
        ['class'=>'btn btn-primary', 
        'style'=>'margin-right: 15px;']) !!}
{!! Form::close() !!}
```

## 月份选择

首先，在`selectMonth`方法中，第一个参数是输入属性的名称，而第二个属性是默认值。这里，PHP 日期方法被用来提取当前月份的数字部分——在这种情况下是三月：

```php
**{!! Form::selectMonth('month',date('m')) !!}**

```

格式化后的输出如下：

```php
<select name="month">
    <option value="1">January</option>
    <option value="2">February</option>
    <option value="3" selected="selected">March</option>
    <option value="4">April</option>
    <option value="5">May</option>
    <option value="6">June</option>
    <option value="7">July</option>
    <option value="8">August</option>
    <option value="9">September</option>
    <option value="10">October</option>
    <option value="11">November</option>
    <option value="12">December</option>
</select>
```

## 日期选择

类似的技术也适用于选择日期，但是使用`selectRange`方法，将月份中的日期范围传递给该方法。同样，PHP 日期函数被用来将当前日期作为第四个参数传递给该方法：

```php
{!! Form::selectRange('date',1,31,date('d')) !!}
```

这里是格式化后的输出：

```php
<select name="date">
    <option value="1">1</option>
    <option value="2">2</option>
    <option value="3">3</option>
    <option value="4">4</option>
    ...
    <option value="28">28</option>
    <option value="29">29</option>
    <option value="30" selected="selected">30</option>
    <option value="31">31</option>
</select>
```

应该选择的日期是 30，因为今天是 2015 年 3 月 30 日。

### 提示

对于没有 31 天的月份，通常会使用 JavaScript 方法根据月份和/或年份修改天数。

## 年份选择

用于日期范围的相同技术也适用于年份的选择；再次使用`selectRange`方法。年份范围被传递给该方法。PHP 日期函数被用来将当前年份作为第四个参数传递给该方法：

```php
{!! Form::selectRange('year',date('Y'),date('Y')+3,date('Y')) !!}
```

这里是格式化后的输出：

```php
<select name="year">
    <option value="2015" selected="selected">2015</option>
    <option value="2016">2016</option>
    <option value="2017">2017</option>
    <option value="2018">2018</option>
</select>
```

这里，选择的当前年份是 2015 年。

## 表单宏

我们有相同的代码，用于生成我们的月份、日期和年份选择表单块两次：一次用于开始日期，一次用于结束日期。为了重构代码，我们可以应用 DRY（不要重复自己）原则并创建一个表单宏。这将允许我们避免两次调用表单元素创建方法，如下所示：

```php
<?php
Form::macro('monthDayYear',function($suffix='')
{
    echo Form::selectMonth(($suffix!=='')?'month-'.$suffix:'month',date('m'));
    echo Form::selectRange(($suffix!=='')?'date-'.$suffix:'date',1,31,date('d'));
    echo Form::selectRange(($suffix!=='')?'year-'.$suffix:'year',date('Y'),date('Y')+3,date('Y'));
}); 
?>
```

这里，月份、日期和年份生成代码被放入一个宏中，该宏位于 PHP 标签内，并且需要添加`echo`来打印结果。给这个宏方法取名为`monthDayYear`。调用我们的宏两次：每个标签后调用一次；每次通过`$suffix`变量添加不同的后缀。现在，我们的表单代码看起来是这样的：

```php
<?php
Form::macro('monthDayYear',function($suffix='')
{
    echo Form::selectMonth(($suffix!=='')?'month-'.$suffix:'month',date('m'));
    echo Form::selectRange(($suffix!=='')?'date-'.$suffix:'date',1,31,date('d'));
    echo Form::selectRange(($suffix!=='')?'year-'.$suffix:'year',date('Y'),date('Y')+3,date('Y'));
});
?>
{!! Form::open(['class'=>'form-horizontal',
                'role'=>'form',
                'method'=>'POST',
                'url'=>'/reserve-room']) !!}
    {!! Form::label(null, 'Start Date',$labelAttributes) !!}
    {!! Form::monthDayYear('-start') !!}
    {!! Form::label(null, 'End Date',$labelAttributes) !!}
    {!! Form::monthDayYear('-end') !!}
    {!! Form::submit('Reserve',['class'=>'btn btn-primary',
           'style'=>'margin-right: 15px;']) !!}
{!! Form::close() !!}
```

# 结论

在 Laravel 5 中选择包含 HTML 表单生成包可以减轻创建大量 HTML 表单的负担。这种方法允许开发人员使用方法，创建可重用的宏，并使用熟悉的 Laravel 方法来构建前端。一旦学会了基本方法，就可以很容易地复制和粘贴以前创建的表单元素，然后更改它们的元素名称和/或发送给它们的数组。

根据项目的大小，这种方法可能是正确的选择，也可能不是。对于非常小的应用程序，需要编写的代码量的差异并不明显，尽管，如`selectMonth`和`selectRange`方法所示，所需的代码量是 drastc 的。

这种技术与宏的使用结合起来，可以轻松减少复制重复的发生。此外，前端设计的一个主要问题是各种元素的类的内容可能需要在整个应用程序中进行更改。这意味着需要执行大量的查找和替换操作，需要对 HTML 进行更改，例如更改类属性。通过创建包含类等属性的数组，可以通过修改这些元素使用的数组来执行对整个表单的更改。

然而，在一个更大的项目中，表单的部分可能在整个应用程序中重复，明智地使用宏可以轻松减少需要编写的代码量。不仅如此，宏还可以将代码与多个文件中需要更改的更改隔离开来。在要选择月份、日期和年份的示例中，这在一个大型应用程序中可能会被使用多达 20 次。对所需的 HTML 块进行的任何更改可以简单地通过修改这个宏来反映在使用它的所有元素中。

最终，是否使用此包的选择将由开发人员和设计人员决定。由于想要使用替代前端设计工具的设计人员可能不喜欢也可能不熟练地使用包中的方法，因此可能不想使用它。

# 总结

在本章中，概述了 HTML Laravel composer 包的历史和安装。解释了主模板的构建，然后通过示例展示了表单组件，如各种表单输入类型。

最后，解释了在书中示例软件中使用的房间预订表单的构建，以及“不要重复自己”的表单宏创建技术。

在下一章中，我们将看一种使用注释来减少应用程序控制器创建路由所需时间的方法。


# 第六章：使用注解驯服复杂性

在上一章中，您学习了如何创建一个涉及从互联网接收请求、将其路由到控制器并处理的 RESTful API。在本章中，您将学习如何在 DocBlock 中使用注解，这是一种需要更少代码的路由执行方式，可以更快、更有组织地进行团队协作编程。

注解将被用于：

+   路由 HTTP 请求，如 GET、POST 和 PUT

+   将控制器转换为完全启用的 CRUDL 资源

+   监听从命令触发的事件

+   向控制器添加中间件以限制或过滤请求

注解是编程中使用的重要机制。注解是增强其他数据的元数据。由于这可能看起来有点混乱，所以我们需要首先了解元数据的含义。**元数据**是一个包含两部分的词：

+   **meta**：这是一个希腊词，意思是超越或包含。

+   **data**：这是一个拉丁词，意思是信息片段。

因此，元数据用于增强或扩展某物的含义。

# 其他编程语言中的注解

接下来，我们将讨论在计算机编程中使用的注解。我们将从 Java、C#和 PHP 中看几个例子，然后最后，看一下注解在 Laravel 中的使用。

## Java 中的注解

注解首次在 Java 版本 1.1 中提出，并在版本 1.2 中添加。以下是一个用于覆盖动物的`speak`方法的注解示例：

```php
Java 1.2
/**
 * @author      Jon Doe <jon@doe.com>
 * @version     1.6               (current version number)
 * @since       2010-03-31        (version package...)
 */
public void speak() {
}

public class Animal {
    public void speak() {
    }
} 
public class Cat extends Animal {
    @Override
    public void speak() {
        System.out.println("Meow.");
    }
 }
```

请注意，`@`符号用于向编译器发出此注解`@Override`很重要的信号。

## C#中的注解

在 C#中，注解称为属性，使用方括号而不是更常用的`@`符号：

```php
[AttributeUsageAttribute(AttributeTargets.Property|AttributeTargets.Field, AllowMultiple = false, Inherited = true)]
public sealed class AssociationAttribute : Attribute
```

## PHP 中的注解

其他 PHP 框架也使用注解。Symfony 广泛使用注解。在**Doctrine**中，这是 Symfony 的 ORM，类似于 Laravel 的 Eloquent，使用注解来定义关系。Symfony 还使用注解进行路由。**Zend Framework**（**ZF**）也使用注解。测试工具 Behat 和 PHPUnit 都使用注解。在 Behat 的以下示例中，使用注解指示应在测试套件之前执行此方法：

```php
/**
 * @BeforeSuite
 */
public static function prepare(SuiteEvent $event)
{
// prepare system for test suite
// before it runs
}
```

# DocBlock 注解

在前面的 Behat 示例中展示的注解使用示例相当有趣，因为它将注解放在了 DocBlock 内部。DocBlock 以斜杠和两个星号开头：

```php
/**
```

它包含*n*行以星号开头。

DocBlock 以单个星号和斜杠结束：

```php
 */
```

这种语法告诉解析器，除了普通注释之外，DocBlock 中还有一些有用的东西。

## Laravel 中的 DocBlock 注解

当 Laravel 5 正在开发时，最初添加了通过 DocBlock 注解支持路由和事件监听器。它的语法类似于 Symfony 和 Zend。

### Symfony

Symfony 的语法如下：

```php
/**
 * @Route("/accommodations/search")
 * @Method({"GET"})
 */

public function searchAction($id)
{
```

### Zend

Zend 的语法如下：

```php
/**
 * @Route(route="/accommodations/search")
 */

public function searchAction()
{
```

### Laravel

Laravel 的语法如下：

```php
/**
 * @Get("/hotels/search")
 */

public function search()
{
```

但是，DocBlock 注解试图解决什么类型的问题呢？

Doc-annotations 的一个用途是将它们添加到控制器中，从而将路由和中间件的控制移交给控制器。这将使控制器更具可移植性，甚至是与框架无关的，因为`routes.php`文件的作用会减少，甚至完全不存在。如下例所示，`routes.php`文件可能会变得非常庞大，这将导致复杂性甚至使文件难以管理：

```php
Route::patch('hotel/{hid}/room/{rid}','AccommodationsController@editRoom');
Route::post('hotel/{hid}/room/{rid}','AccommodationsController@reserve');
Route::get('hotel/stats,HotelController@Stats');
Route::resource('country', 'CountryController');
Route::resource(city', 'CityController');
Route::resource('state', 'StateController');
Route::resource('amenity', 'AmenitiyController');
Route::resource('country', 'CountryController');
Route::resource(city', 'CityController');
Route::resource('country', 'CountryController');
Route::resource('city', 'CityController');
Route::resource('horse', 'HorseController');
Route::resource('cow', 'CowController');
Route::resource('zebra', 'ZebraController');
Route::get('dragon/{id}', 'DragonController@show');
Route::resource('giraffe', 'GiraffeController');
Route::resource('zebrafish', 'ZebrafishController');
```

DocBlock 注解的想法是驯服这种复杂性，因为路由将被移动到控制器中。

在 Laravel 5.0 发布之前不久，由于社区的不满，该功能被移除。此外，由于一些开发人员可能不想使用这种方法，将此包从 Laravel 的核心中移出并打包是合适的。安装该包的方法类似于添加 HTML 包的方式。这个包也得到了 Laravel Collective 的支持。通过输入以下 composer 命令很容易添加注释：

```php
**$ composer require laravelcollective/annotations**

```

这将安装注释包，而`composer.json`将显示包添加到 require 部分，如下所示：

```php
"require": {
    "laravel/framework": "5.0.*",
    "laravelcollective/annotations": "~5.0",
  },
```

下一步将是创建一个名为`AnnotationsServiceProvider.php`的文件，并添加以下代码：

```php
<?php namespace App\Providers;

use Collective\Annotations\AnnotationsServiceProvider as ServiceProvider;

class AnnotationsServiceProvider extends ServiceProvider {

    /**
     * The classes to scan for event annotations.
     *
     * @var array
     */
    protected $scanEvents = [];

    /**
     * The classes to scan for route annotations.
     *
     * @var array
     */
    protected $scanRoutes = [];

    /**
     * The classes to scan for model annotations.
     *
     * @var array
     */
    protected $scanModels = [];

    /**
     * Determines if we will auto-scan in the local environment.
     *
     * @var bool
     */
    protected $scanWhenLocal = false;

    /**
     * Determines whether or not to automatically scan the controllers
     * directory (App\Http\Controllers) for routes
     *
     * @var bool
     */
    protected $scanControllers = false;

    /**
     * Determines whether or not to automatically scan all namespaced
     * classes for event, route, and model annotations.
     *
     * @var bool
     */
    protected $scanEverything = false;

}
```

接下来，`AnnotationsServiceProvider.php`文件将需要添加到`config/app.php`文件中。需要添加命名空间的类应添加到 providers 数组中，如下所示：

```php
'providers' => [
    // ...
    'App\Providers\AnnotationsServiceProvider'
  ];
```

# 使用 DocBlock 注释的资源控制器

现在，为了说明 Laravel 的 DocBlock 注释的使用，我们将检查以下步骤。

首先，我们将像往常一样创建住宿控制器：

```php
**$ php artisan make:controller AccommodationsController**

```

接下来，我们将将住宿控制器添加到注释服务提供程序要扫描的路由列表中：

```php
protected $scanRoutes = [
    'App\Http\Controllers\HomeController',
    'App\Http\Controllers\AccommodationsController'
];
```

现在，我们将向控制器添加 DocBlock 注释。在这种情况下，我们将指示解析器将此控制器用作住宿路由的资源控制器。要添加的代码如下：

```php
/**
* @Resource("/accommodations")
*/

```

由于整个控制器将被转换为资源，因此 DocBlock 注释应该在类定义之前插入。`AccommodationsController`类现在应该如下所示：

```php
<?php namespace MyCompany\Http\Controllers;

use Illuminate\Support\Facades\Response;
use MyCompany\Http\Requests;
use MyCompany\Http\Controllers\Controller;
use MyCompany\Accommodation;
use Illuminate\Http\Request;

/**
* @Resource("/accommodations")
*/
class AccommodationsController extends Controller {

    /**
     * Display a listing of the resource.
     *
     * @return Response
     */
    public function index(Accommodation $accommodation)
    {
        return $accommodation->paginate();
    }
```

### 注意

请注意，这里需要双引号：

```php
@Resource("/accommodations")
```

以下语法，使用单引号，将不正确并且不起作用：

```php
@Resource('/accommodations')
```

# 单方法路由

如果我们只想为单个方法添加一个路由，比如“搜索住宿”，那么一个注解将被添加到单个方法的上方；然而，这一次是在类的内部。为了处理 GET HTTP 请求动词，代码将如下所示：

```php
/**
 * Search for an accommodation
 * @Get("/search-accommodation")
 */
```

类将如下所示：

```php
<?php namespace MyCompany\Http\Controllers;

use Illuminate\Support\Facades\Response;
use MyCompany\Http\Requests;
use MyCompany\Http\Controllers\Controller;
use MyCompany\Accommodation;
use Illuminate\Http\Request;

class AccommodationsController extends Controller {

    /**
    * Search for an accommodation
    * @Get("/search-accommodation")
    */
    public function index(Accommodation $accommodation)
    {
        return $accommodation->paginate();
    }
```

# 扫描路由

接下来的步骤非常重要。Laravel 应用程序必须处理注释。为此，Artisan 用于扫描路由。

以下命令用于扫描路由。输出将显示`Routes scanned!`，如下所示：

```php
**$ php artisan route:scan**

**Routes scanned!**

```

此扫描的结果将在`storage/framework`目录中产生一个名为`routes.scanned.php`的文件。

以下代码将写入`storage/framework/routes.scanned.php`文件：

```php
$router->get('search-accommodation', [
  'uses' => 'MyCompany\Http\Controllers\AccommodationsController@search',
  'as' => NULL,
  'middleware' => [],
  'where' => [],
  'domain' => NULL,
]);
```

### 注意

请注意，`storage/framework/routes.scanned.php`文件不需要放入源代码控制中，因为它是生成的。

# 自动扫描

如果开发人员在构建控制器时必须执行 Artisan 路由扫描命令，那么这样做可能变得乏味。为了方便开发人员，在开发模式下，有一种方法可以让 Laravel 自动扫描`scanRoutes`数组中的控制器。

在`AnnotationsServiceProvider.php`文件中，将`scanWhenLocal`属性设置为`true`。

对于`$scanControllers`和`$scanEverything`也是如此；这两个布尔标志允许框架自动扫描`App\Http\Controllers`目录和任何有命名空间的类。

必须记住，这应该*只*在开发和开发机器上使用，因为它会给请求周期增加不必要的开销。将属性设置为`true`的示例如下所示：

```php
<?php namespace App\Providers;

use Collective\Annotations\AnnotationsServiceProvider as ServiceProvider;

class AnnotationsServiceProvider extends ServiceProvider {

    /**
     * The classes to scan for event annotations.
     *
     * @var array
     */
    protected $scanEvents = [];

    …

    /**
     * Determines if we will auto-scan in the local environment.
     *
     * @var bool
     */
    protected $scanWhenLocal = true;

    /**
     * Determines whether or not to automatically scan the controllers
     * directory (App\Http\Controllers) for routes
     *
     * @var bool
     */
    protected $scanControllers = true;

    /**
     * Determines whether or not to automatically scan all namespaced
     * classes for event, route, and model annotations.
     *
     * @var bool
     */
    protected $scanEverything = true;

}
```

启用这些选项将减慢框架的速度，但允许在开发阶段灵活性。

# 额外的注释

要将 ID 传递给路由，就像在显示单个住宿时一样，代码将如下所示：

```php
/**
* Display the specified resource.
* @Get("/accommodation/{id}")
*/
```

这个 DocBlock 注释将被放置在类内部的函数上方，这与之前的例子类似。

要将 ID 限制为一个或多个数字，可以使用`@Where`注释如下：

```php
@Where({"id": "\d+"})
```

如下所示，两个注释被合并在一起：

```php
/**
 * Display the specified resource.
 * @Get("/accommodation/{id}")
 * @Where({"id": "\d+"})
 */
```

要向示例添加中间件，限制请求仅限于经过身份验证的用户，可以使用`@Middleware`注释：

```php
/**
 * Display the specified resource.
 * @Get("/accommodation/{id}")
 * @Where({"id": "\d+"})
 * @Middleware("auth")
 */
```

## HTTP 动词

以下是可以使用注释的各种 HTTP 动词的列表，它们与 RESTful 标准相对应：

+   `@Delete`：此动词删除一个资源。

+   `@Get`：此动词显示一个资源或多个资源。

+   `@Options`：此动词显示选项列表。

+   `@Patch`：此动词修改资源的属性。

+   `@Post`：此动词创建一个新资源。

+   `@Put`：此动词修改资源。

### 其他注释

还有其他注释也可以在控制器中使用。这些注释如下：

+   `@Any`：对任何 HTTP 请求做出响应。

+   `@Controller`：为资源创建一个控制器。

+   `@Middleware`：这为资源添加中间件。

+   `@Route`：这使得路由可用。

+   `@Where`：根据特定条件限制请求。

+   `@Resource`：这使得资源可用。

# 在 Laravel 5 中使用注释

让我们回顾一下在 Laravel 中实现的路径，如下所示：

+   HTTP 请求被路由到控制器

+   命令是在控制器内部实例化的

+   事件被触发

+   事件被处理

![在 Laravel 5 中使用注释](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-lrv/img/B04559_06_01.jpg)

Laravel 的现代基于命令的发布-订阅路径。

使用注释，这个过程可以变得更加简单。首先，将创建一个预订控制器：

```php
$ php artisan make:controller ReservationsController
```

为了创建一个路由，允许用户创建一个新的预订，将使用 POST HTTP 动词。`@Post`注释将监听附加到`/bookRoom`网址的具有`POST`方法的请求。这将代替通常在`routes.php`文件中找到的路由：

```php
<?php namespace MyCompany\Http\Controllers;

use ...

class ReservationsController extends Controller {
/**
* @Post("/bookRoom")
*/
  public function reserve()
  {
  }
```

如果我们想要将请求限制为有效的 URL，则域参数将请求限制为特定的 URL。此外，auth 中间件要求对希望预订房间的任何请求进行身份验证：

```php
<?php namespace App\Http\Controllers;

use …
/**
* @Controller(domain="booking.hotelwebsite.com")
*/

class ReservationsController extends Controller {

/**
* @Post("/bookRoom")
* @Middleware("auth")
*/
  public function reserve()
  {
```

接下来，应该创建`ReserveRoom`命令。这个命令将在控制器内实例化：

```php
**$ php artisan make:command ReserveRoom**

```

ReserveRoom 命令的内容如下：

```php
<?php namespace MyCompany\Commands;

use MyCompany\Commands\Command;
use MyCompany\User;
use MyCompany\Accommodation\Room;
use MyCompany\Events\RoomWasReserved;

use Illuminate\Contracts\Bus\SelfHandling;

class ReserveRoomCommand extends Command implements SelfHandling {

  public function __construct()
  {
  }
  /**
   * Execute the command.
   */
  public function handle()
  {
  }
}
```

接下来，我们需要在预订控制器内部实例化`ReserveRoom`命令：

```php
<?php namespace MyCompany\Http\Controllers;

use MyCompany\Accommodation\Reservation;
use MyCompany\Commands\PlaceOnWaitingListCommand;
use MyCompany\Commands\ReserveRoomCommand;
use MyCompany\Events\RoomWasReserved;
use MyCompany\Http\Requests;
use MyCompany\Http\Controllers\Controller;
use MyCompany\User;
use MyCompany\Accommodation\Room;

use Illuminate\Http\Request;

class ReservationsController extends Controller {

/**
 * @Post("/bookRoom")
 * @Middleware("auth")
 */
  public function reserve()
  {	
    $this->dispatch(
    new ReserveRoom(\Auth::user(),$start_date,$end_date,$rooms)
    );
  }
```

现在我们将创建`RoomWasReserved`事件：

```php
**$ php artisan make:event RoomWasReserved**

```

要从`ReserveRoom`处理程序中实例化`RoomWasReserved`事件，我们可以利用`event()`辅助方法。在这个例子中，命令是自处理的，因此这样做很简单：

```php
<?php namespace App\Commands;

use App\Commands\Command;
use Illuminate\Contracts\Bus\SelfHandling;

class ReserveRoom extends Command implements SelfHandling {
    public function __construct(User $user, $start_date, $end_date, $rooms)
    {
    }
    public function handle()
    {
        $reservation = Reservation::createNew();
        event(new RoomWasReserved($reservation));
    }
}
```

由于用户需要收到房间预订电子邮件的详细信息，下一步是为`RoomWasReserved`事件创建一个电子邮件发送处理程序。为此，再次使用`artisan`来创建处理程序：

```php
**$ php artisan handler:event RoomReservedEmail –event=RoomWasReserved**

```

`RoomWasReserved`事件的`SendEmail`处理程序的方法只是构造函数和处理程序。发送电子邮件的工作将在处理程序方法内执行。`@Hears`注释被添加到其 DocBlock 中以完成这个过程：

```php
<?php namespace MyCompany\Handlers\Events;

use MyCompany\Events\RoomWasReserved;

use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Contracts\Queue\ShouldBeQueued;

class RoomReservedEmail {
  public function __construct()
  {
  }

  /**
   * Handle the event.
   * @Hears("\App\Events\RoomWasReserved")
   * @param  RoomWasReserved  $event
   */
  public function handle(RoomWasReserved $event)
  {
     //TODO: send email to $event->user
  }
}
```

只需将`RoomReservedEmail`添加到`scanEvents`数组中，以允许扫描该事件，如下所示：

```php
protected $scanEvents = [
   'App\Handlers\Events\RoomReservedEmail'
];
```

最后一步是导入。Artisan 用于扫描事件的注释并写入输出文件：

```php
**$ php artisan event:scan**

 **Events scanned!**

```

这是`storage/framework/events.scanned.php`文件的输出，显示了事件监听器：

```php
<?php $events->listen(array(0 => 'App\\Events\\RoomWasReserved',
), App\Handlers\Events\RoomReservedEmail@handle');
```

在存储目录中扫描的注释文件的最终视图如下。请注意它们是并列的：

```php
**storage/framework/events.scanned.php**
**storage/framework/routes.scanned.php**

```

### 提示

Laravel 使用`artisan`来缓存路由，但不用来扫描事件，因此以下命令会生成一个缓存文件：

```php
**$ php artisan route:cache**
**Route cache cleared!**
**Routes cached successfully!**

```

在运行`route:cache`之前必须先运行`route:scan`命令，因此按照这个顺序执行这两个命令非常重要：

```php
$ php artisan route:scan
Routes scanned!

$ php artisan route:cache
Route cache cleared!
Routes cached successfully!
```

此命令写入到：`storage/framework/routes.php`。

```php
<?php

app('router')->setRoutes(
  unserialize(base64_decode('TzozNDoiSWxsdW1pbmF0ZVxSb3V0aW5nXFd…'))
);
```

两个文件都会被创建，但只有编译后的`routes.php`文件在再次运行`php artisan route:scan`之前才会被使用。

## 优势

在 Laravel 中使用 DocBlock 注解进行路由有几个主要优势：

+   每个控制器保持独立。控制器不与单独的路由“绑定”，这使得共享控制器，并将其从一个项目移动到另一个项目变得更容易。对于只有少数控制器的简单项目来说，`routes.php`文件可能被视为不必要。

+   开发人员无需担心`routes.php`。与其他开发人员合作时，路由文件需要保持同步。通过 DocBlock 注解方法，`routes.php`文件被缓存，不放在源代码控制下；每个开发人员可以专注于自己的控制器。

+   路由注解将路由与控制器保持在一起。当控制器和路由分开时，当新程序员第一次阅读代码时，可能不会立即清楚每个控制器方法附加到哪些路由上。通过直接将路由放在函数上方的 DocBlock 中，这一点立即变得明显。

+   熟悉并习惯在 Symfony 和 Zend 等框架中使用注解的开发人员可能会发现在 Laravel 中使用注解是开发软件应用的一种非常方便的方式。此外，将 Laravel 作为首次 PHP 体验的 Java 和 C#开发人员会发现注解非常方便。

# 结论

是否在软件中使用注解的决定取决于开发人员。从 Laravel 核心中移除它的决定，以及 HTML 表单包，表明该框架变得越来越灵活，只有一组最小的包作为默认。这使得在 Laravel 5.1 发布长期支持（LTS）版本时，核心开发人员可以更加稳定和减少维护工作。

由于注解包是 Laravel Collective 的一部分，该团队将负责管理此包的支持，这保证了该功能的实用性将通过对存储库的贡献得到扩展和扩展。

此外，该包可以扩展以包括一个模板，该模板会自动创建与控制器同名的路由注解。这将在创建控制器和路由的过程中节省另一个步骤，这是软件开发过程中最重要但又单调的任务之一。

# 总结

在本章中，我们了解了注解的用法，它们在编程中的一般用法，它们在其他框架中的用法，以及它们如何被引入到 Laravel 注解 composer 包中。我们学会了如何通过使用注解来加快开发过程，以及如何自动扫描注解。在下一章中，我们将学习中间件，这是一种在路由和应用程序之间使用的机制。
