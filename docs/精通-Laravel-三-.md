# 精通 Laravel（三）

> 原文：[`zh.annas-archive.org/md5/d10bf45da1cebf8f2b06a9600172079d`](https://zh.annas-archive.org/md5/d10bf45da1cebf8f2b06a9600172079d)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：使用中间件过滤请求

在本章中，将详细讨论中间件，并提供来自住宿软件的示例。中间件是帮助将软件应用程序分隔成不同层的重要机制。为了说明这一原则，中间件在应用程序的最内部提供了保护层，可以将其视为内核。

在 Laravel 4 中，中间件被称为过滤器。这些过滤器用于路由中执行在控制器之前的操作，如身份验证，用户将根据特定标准进行过滤。此外，过滤器也可以在控制器之后执行。

在 Laravel 5 中，中间件的概念已经存在，但在 Laravel 4 中并不突出，现在已经被引入到实际请求工作流中，并可以以各种方式使用。可以将其视为俄罗斯套娃，其中每个套娃代表应用程序中的一层 - 拥有正确凭据将允许我们深入应用程序。

# HTTP 内核

位于`app/Http/Kernel.php`的文件是管理程序内核配置的文件。基本结构如下：

```php
<?php namespace App\Http;

use Illuminate\Foundation\Http\Kernel as HttpKernel;

class Kernel extends HttpKernel {

  /**
   * The application's global HTTP middleware stack.
   *
   * @var array
   */
  protected $middleware = [
  'Illuminate\Foundation\Http\Middleware\CheckForMaintenanceMode',
    'Illuminate\Cookie\Middleware\EncryptCookies',
    'Illuminate\Cookie\Middleware\AddQueuedCookiesToResponse',
    'Illuminate\Session\Middleware\StartSession',
    'Illuminate\View\Middleware\ShareErrorsFromSession',
    'Illuminate\Foundation\Http\Middleware\VerifyCsrfToken',
  ];

  /**
   * The application's route middleware.
   *
   * @var array
   */
  protected $routeMiddleware = [
    'auth' => 'App\Http\Middleware\Authenticate',
    'auth.basic' => 'Illuminate\Auth\Middleware\AuthenticateWithBasicAuth',
    'guest' => 'App\Http\Middleware\RedirectIfAuthenticated',
  ];

}
```

`$middleware`数组是中间件类及其命名空间的列表，并在每个请求时执行。`$routeMiddleware`数组是一个键值数组，作为*别名*列表，可与路由一起使用以过滤请求。

# 基本中间件结构

路由中间件类实现了`Middleware`接口：

```php
<?php namespace Illuminate\Contracts\Routing;

use Closure;

interface Middleware {

  /**
   * Handle an incoming request.
   *
   * @param  \Illuminate\Http\Request  $request
   * @param  \Closure  $next
   * @return mixed
   */
  public function handle($request, Closure $next);

}
```

在实现此基类的任何类中，必须有一个接受`$request`和`Closure`的`handle`方法。

中间件的基本结构如下：

```php
<?php namespace Illuminate\Foundation\Http\Middleware;

use Closure;
use Illuminate\Contracts\Routing\Middleware;
use Illuminate\Contracts\Foundation\Application;
use Symfony\Component\HttpKernel\Exception\HttpException;

class CheckForMaintenanceMode implements Middleware {

  /**
   * The application implementation.
   *
   * @var \Illuminate\Contracts\Foundation\Application
   */
  protected $app;

  /**
   * Create a new filter instance.
   *
   * @param  \Illuminate\Contracts\Foundation\Application  $app
   * @return void
   */
  public function __construct(Application $app)
  {
    $this->app = $app;
  }

  /**
   * Handle an incoming request.
   *
   * @param  \Illuminate\Http\Request  $request
   * @param  \Closure  $next
   * @return mixed
   */
  public function handle($request, Closure $next)
  {
    if ($this->app->isDownForMaintenance())
    {
      throw new HttpException(503);
    }
    return $next($request);
  }
}
```

在这里，`CheckForMaintenanceMode`中间件确实如其名称所示：`handle`方法检查应用程序是否处于应用模式。调用应用程序的`isDownForMaintenance`方法，如果返回`true`，则会返回 503 HTTP 异常并停止方法的执行。否则，将带有`$request`参数的`$next`闭包返回给调用类。

### 提示

诸如`CheckForMaintenanceMode`之类的中间件可以从`$middleware`数组中移除，并移入`$routeMiddleware`数组中，以便不需要在每个请求时执行，而只在从特定路由所需时执行。

# 路由中间件揭秘

在 Laravel 5 中存在两个基于路由的中间件类，位于`app/Http/Middleware/`中。其中一个类名为`Authenticate`。它提供基本身份验证并使用合同。

关于路由，中间件位于路由和控制器之间：

![路由中间件揭秘](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-lrv/img/B04559_07_01.jpg)

## 默认中间件 - Authenticate 类

一个名为`Authenticate.php`的类有以下代码：

```php
<?php namespace MyCompany\Http\Middleware;

use Closure;
use Illuminate\Contracts\Auth\Guard;

class Authenticate {
  /**
   * The Guard implementation.
   *
   * @var Guard
   */
  protected $auth;

  /**
   * Create a new filter instance.
   *
   * @param  Guard  $auth
   * @return void
   */
  public function __construct(Guard $auth)
  {
    $this->auth = $auth;
  }

  /**
   * Handle an incoming request.
   *
   * @param  \Illuminate\Http\Request  $request
   * @param  \Closure  $next
   * @return mixed
   */
  public function handle($request, Closure $next)
  {
    if ($this->auth->guest())
    {
      if ($request->ajax())
      {
        return response('Unauthorized.', 401);
      }
      else
      {
        return redirect()->guest('auth/login');
      }
    }
    return $next($request);
  }
}
```

首先要注意的是`Illuminate\Contracts\Auth\Guard`，它处理检查用户是否已登录的逻辑。它被注入到构造函数中。

## 合同

请注意，合同的概念是使用接口提供非具体类以将实际类与调用类分离的新方法。这提供了一个良好的分离层，并允许在需要时轻松切换底层类，同时保持方法的参数和返回类型。

## 处理

`handle`类是真正工作的地方。`$request`对象与`$next`闭包一起传入。接下来发生的事情非常简单但重要。代码询问当前用户是否是访客，即未经身份验证或登录。如果用户未登录，则该方法将不允许用户访问下一步。如果请求是通过 Ajax 到达的，则会向浏览器返回 401 消息。

如果请求不是通过 Ajax 请求到达的，代码会假定请求是通过标准页面请求到达的，并且用户被重定向到 auth/login 页面，允许用户登录应用程序。否则，如果用户已经认证（`guest()`不等于`true`），则将`$next`闭包与`$request`对象作为参数返回给软件应用程序。总之，只有在用户未经认证时才会停止应用程序的执行；否则，执行将继续。

要记住的重要一点是，在这种情况下，`$request`对象被返回给软件。

## 自定义中间件 - 记录

使用 Artisan 创建自定义中间件很简单。`artisan`命令如下：

```php
**$ php artisan make:middleware LogMiddleware**

```

我们的`LogMiddleware`类需要添加到`Http/Kernel.php`文件中的`$middleware`数组中，如下所示：

```php
protected $middleware = [
  'Illuminate\Foundation\Http\Middleware\CheckForMaintenanceMode',
  'Illuminate\Cookie\Middleware\EncryptCookies',
  'Illuminate\Cookie\Middleware\AddQueuedCookiesToResponse',
  'Illuminate\Session\Middleware\StartSession',
  'Illuminate\View\Middleware\ShareErrorsFromSession',
  'MyCompany\Http\Middleware\LogMiddleware'
];
```

`LogMiddleware`类是给中间件类的名称，用于记录使用网站的用户。该类只有一个方法，即`handle`。与认证中间件一样，它接受`$request`对象以及`$next`闭包：

```php
<?php namespace MyCompany\Http\Middleware;

use Closure;

class LogMiddleware {

  /**
   * Handle an incoming request.
   *
   * @param  \Illuminate\Http\Request  $request
   * @param  \Closure  $next
   * @return mixed
   */
  public function handle($request, Closure $next)
  {
    return $next($request);
  }
}
```

在这种情况下，我们只想简单地记录用户 ID 以及执行某个操作的日期和时间。将`$request`对象分配给`$response`对象，然后返回`$response`对象而不是`$next`。代码如下：

```php
public function handle($request, Closure $next)
{
  $response = $next($request);
  Log::create(['user_id'=>\Auth::user()->id,'created_at'=>date("Y- 
  m-d H:i:s")]);
  return $response;
}

```

### 记录模型

使用以下命令创建`Log`模型：

```php
**$php artisan make:model Log**

```

使用受保护的`$table`属性将`Log`模型设置为使用名为`log`而不是`logs`的表。接下来，通过将公共`$timestamps`属性设置为`false`，设置模型不使用时间戳。最后，通过将受保护的`$fillable`属性设置为要填充的字段数组，允许使用`create`函数同时填充`user_id`和`created_at`字段。在进行上述修改后，该类将如下所示：

```php
<?php namespace MyCompany;

use Illuminate\Database\Eloquent\Model;

class Log extends Model {
    protected $table = 'log';
    public $timestamps = false;
    protected $fillable = ['user_id','created_at'];
}
```

我们还可以将`Log`模型创建为多态模型，使其可以在多个上下文中使用，通过将以下代码添加到`Log`模型中：

```php
public function loggable()
{
     return $this->morphTo();
}
```

### 提示

有关此更多信息，请参阅 Laravel 文档。

### 记录模型迁移

需要调整`database/migrations/[date_time]_create_logs_table.php`迁移，以使用`log`表而不是`logs`。还需要创建两个字段：`user_id`，一个无符号的小整数，以及`created_at`，一个将模仿 Laravel 时间戳格式的`datetime`字段。代码如下：

```php
<?php

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class CreateLogsTable extends Migration {

  /**
   * Run the migrations.
   *
   * @return void
   */
  public function up()
  {
    Schema::create('log', function(Blueprint $table)
    {
      $table->smallInteger('user_id')->unsigned();
      $table->dateTime('created_at');
    });
  }

  /**
   * Reverse the migrations.
   *
   * @return void
   */
  public function down()
  {
    Schema::drop('log');
  }
}
```

## 可终止中间件

除了在请求到达或响应到达后执行操作之外，甚至可以在响应发送到浏览器后执行操作。该类添加了`terminate`方法并实现了`TerminableMiddleware`：

```php
use Illuminate\Contracts\Routing\TerminableMiddleware;

class StartSession implements TerminableMiddleware {

    public function handle($request, $next)
    {
        return $next($request);
    }

    public function terminate($request, $response)
    {
        // Store the session data...
    }
}
```

### 作为可终止的记录

我们可以在`terminate`函数中轻松地执行用户记录，因为记录可能是生命周期中的最后一个动作。代码如下：

```php
<?php namespace MyCompany\Http\Middleware;

use Closure;
use Illuminate\Contracts\Routing\TerminableMiddleware;
use MyCompany\Log;

class LogMiddleware implements TerminableMiddleware {
  /**
   * Handle an incoming request.
   *
   * @param  \Illuminate\Http\Request  $request
   * @param  \Closure  $next
   * @return mixed
   */
  public function handle($request, Closure $next)
  {
    return  $next($request);

  }
  /**
   * Terminate the request.
   *
   * @param  \Illuminate\Http\Request  $request
   * @param  \Illuminate\Http\Response $response
   */
  public function terminate($request, $response)
  {
    Log::create(['user_id'=>\Auth::user()- >id,'created_at'=>date("Y-m-d H:i:s")]);

  }
}
```

代码已放置到`terminate`方法中，因此它位于请求-响应路径之外，使得代码保持清晰。

# 使用中间件

如果我们希望用户在执行某个操作之前必须经过身份验证，我们可以将数组作为第二个参数传递，`middleware`作为键强制路由在`AccommodationsController`的`search`方法上调用`auth`中间件：

```php
Route::get('search-accommodation',
  ['middleware' => 'auth','AccommodationsController@search']);
```

在这种情况下，如果用户未经认证，将被重定向到登录页面。

## 路由组

路由可以分组以共享相同的中间件。例如，如果我们想保护应用程序中的所有路由，我们可以创建一个路由组，并只传入键值对`middleware`和`auth`。代码如下：

```php
Route::group(['middleware' => 'auth'], function()
{
  Route::resource('accommodations', 'AccommodationsController');
  Route::resource('accommodations.amenities', 'AccommodationsAmenitiesController');
  Route::resource('accommodations.rooms', 'AccommodationsRoomsController');
  Route::resource('accommodations.locations', 'AccommodationsLocationsController');
  Route::resource('amenities', 'AmenitiesController');
  Route::resource('rooms', 'RoomsController');
  Route::resource('locations', 'LocationsController');
})
```

这将保护路由组内的每个路由的每个方法。

## 路由组中的多个中间件

如果希望进一步保护非经过身份验证的用户，可以创建一个白名单，只允许特定范围的 IP 地址访问应用程序。

以下命令将创建所需的中间件：

```php
$ php artisan make:middleware WhitelistMiddleware
```

`WhitelistMiddleware`类如下所示：

```php
<?php namespace MyCompany\Http\Middleware;

use Closure;

class WhitelistMiddleware {
    private $whitelist = ['192.2.3.211'];
  /**
   * Handle an incoming request.
   *
   * @param  \Illuminate\Http\Request  $request
   * @param  \Closure  $next
   * @return mixed
   */
  public function handle($request, Closure $next)
  {
    if (in_array($request->getClientIp(),$this->whitelist)) {
      return $next($request);
    } else {
      return response('Unauthorized.', 401);
    }

  }
}
```

在这里，创建了一个私有的`$whitelist`数组，其中包含设置在公司内的 IP 地址列表。 然后，将请求的远程端口与数组中的值进行比较，并通过返回`$next`闭包来允许其继续。 否则，将返回未经授权的响应。

现在，需要将`whitelist`中间件与`auth`中间件结合使用。 要在路由组内使用`whitelist`中间件，需要为中间件创建别名，并将其插入到`app/Http/Kernel.php`文件的`$routeMiddleware`数组中。 代码如下：

```php
protected $routeMiddleware = [
  'auth' => 'MyCompany\Http\Middleware\Authenticate',
  'auth.basic' => 'Illuminate\Auth\Middleware\AuthenticateWithBasicAuth',
  'guest' => 'MyCompany\Http\Middleware\RedirectIfAuthenticated',
  'log' => 'MyCompany\Http\Middleware\LogMiddleware',
  'whitelist' => 'MyCompany\Http\Middleware\WhitelistMiddleware'
];
```

接下来，要将其添加到此路由组的中间件列表中，需要用数组替换字符串`auth`，其中包含`auth`和`whitelist`。 代码如下：

```php
Route::group(['middleware' => ['auth','whitelist']], function()
{
  Route::resource('accommodations', 'AccommodationsController');
  Route::resource('accommodations.amenities',
            'AccommodationsAmenitiesController');
  Route::resource('accommodations.rooms', 'AccommodationsRoomsController');
  Route::resource('accommodations.locations', 'AccommodationsLocationsController');
  Route::resource('amenities', 'AmenitiesController');
  Route::resource('rooms', 'RoomsController');
  Route::resource('locations', 'LocationsController');
});
```

现在，即使用户已登录，也将无法访问受保护的内容，除非 IP 地址在白名单中。

此外，如果只想要对某些路由进行白名单操作，可以嵌套路由组如下：

```php
Route::group(['middleware' => 'auth', function()
{
  Route::resource('accommodations', 'AccommodationsController');
  Route::resource('accommodations.amenities',
            'AccommodationsAmenitiesController');
  Route::resource('accommodations.rooms', 'AccommodationsRoomsController');
  Route::resource('accommodations.locations', 'AccommodationsLocationsController');
  Route::resource('amenities', 'AmenitiesController');
  Route::group(['middleware' => 'whitelist'], function()
  {
    Route::resource('rooms', 'RoomsController');
  });
  Route::resource('locations', 'LocationsController');
});
```

这将要求对`RoomsController`进行身份验证（`auth`）和白名单操作，而路由组内的所有其他控制器将仅需要身份验证。

# 中间件排除和包含

如果希望仅对某些路由执行身份验证或白名单操作，则应向控制器添加构造方法，并且可以使用类的`middleware`方法如下所示：

```php
<?php namespace MyCompany\Http\Controllers;

use MyCompany\Http\Requests;
use MyCompany\Http\Controllers\Controller;
use Illuminate\Http\Request;
use MyCompany\Accommodation\Room;

class RoomsController extends Controller {

  public function __construct()
  {
    $this->middleware('auth',['except' => ['index','show']);
  }
```

第一个参数是`Kernel.php`文件中`$routeMiddleware`数组的键。 第二个参数是键值数组。 选项要么是`except`，要么是`only`。 `except`选项显然是排除，而`only`选项是包含。 在上面的示例中，`auth`中间件将应用于除`index`或`show`方法之外的所有方法，这两个方法是两种读取方法（它们不修改数据）。 相反，如果`log`中间件应用于`index`和`show`，则将使用以下构造方法：

```php
  public function __construct()
  {
    $this->middleware('log',['only' => ['index','show']);
  }
```

如预期的那样，两种方法都如下所示，并且还添加了`whitelist`中间件：

```php
public function __construct()
{
  $this->middleware('whitelist',['except' => ['index','show']);
  $this->middleware('auth',['except' => ['index','show']);
  $this->middleware('log',['only' => ['index','show']);
}
```

此代码将要求对所有非读取操作进行身份验证和白名单 IP 地址，同时记录对`index`和`show`的任何请求。

# 结论

中间件可以巧妙地过滤请求并保护应用程序或 RESTful API 免受不必要的请求。 它还可以执行日志记录并重定向任何符合特定条件的请求。

中间件还可以为现有应用程序提供附加功能。 例如，Laravel 提供了`EncryptCookies`和`AddQueuedCookiesToResponse`中间件来处理 cookies，而`StartSession`和`ShareErrorsFromSession`处理会话。

`AddQueuedCookiesToResponse`中的代码不会过滤请求，而是向其添加内容：

```php
public function handle($request, Closure $next)
  {
    $response = $next($request);
    foreach ($this->cookies->getQueuedCookies() as $cookie)
    {
      $response->headers->setCookie($cookie);
    }
    return $response;
  }
```

# 总结

在本章中，我们看了中间件，这是一个对每个请求执行的任何功能或附加到某些路由的有用机制。 这是一种灵活的机制，并允许程序员*编码到接口*，因为任何实现`Middleware`接口的中间件类都必须包括`handle`方法。 通过这种结构不仅鼓励，而且要求遵循良好的开发原则。

在下一章中，我们将讨论 Eloquent ORM。


# 第八章：使用 Eloquent ORM 查询数据库

在之前的章节中，您学习了如何构建应用程序的基本组件。在本章中，将介绍 Eloquent ORM，这是使 Laravel 如此受欢迎的最佳功能之一。

在本章中，我们将涵盖以下主题：

+   基本查询语句

+   一对一，一对多和多对多关系

+   多态关系

+   急切加载

ORM，或对象关系映射，在最简单的意义上解释，将表转换为类，将其列转换为属性，并将其行转换为该类的实例。它在开发人员和数据库之间创建了一个抽象层，并允许更容易的编程，因为它使用熟悉的面向对象范式。

我们假设有一个带有以下结构的帖子表：

| **id** | **contents** | **author_id** |   |
| --- | --- | --- | --- |

为了说明这个例子，以下将是帖子表的表示：

```php
<?php
namespace MyBlog;

class Post {
}
```

要添加`id`，`contents`和`author_id`属性，我们将在类中添加以下代码：

```php
class Post {
    private $id;
    private $contents;
    private $author_id;

    public function getId()
    {
        return $this->id;
    }

    public function setId($id)
    {
        $this->id = $id;
    }

    public function getContents()
    {
        return $this->contents;
    }

    public function setContents($contents)
    {
        $this->contents = $contents;
    }

    public function getAuthorId()
    {
        return $this->author_id;
    }

    public function setAuthorId($author_id)
    {
        $this->author_id = $author_id;
    }

}
```

这给我们一个关于如何用类表示表的概述：`Post`类表示一个具有**posts**集合的实体。

如果遵循了活动记录模式，那么 Eloquent 可以自动管理所有类名、键名和它们的相关关系。Eloquent 的强大之处在于它能够让程序员使用面向对象的方法来管理类之间的关系。

# 基本操作

现在我们将讨论一些基本操作。使用 Eloquent 有几乎无数种方式，当然每个开发人员都会以最适合其项目的方式使用 Eloquent。以下技术是更复杂查询的基本构建块。

## 查找一个

最基本的操作之一是执行以下查询：

```php
select from rooms where id=1;
```

这是通过使用`find()`方法实现的。

使用`find`方法调用`Room`外观，该方法接受 ID 作为参数：

```php
MyCompany\Accommodation\Room::find($id);
```

由于 Eloquent 基于流畅的查询构建器，任何流畅的方法都可以混合和匹配。一些流畅的方法是可链接的，而其他方法执行查询。

`find()`方法实际上执行查询，因此它总是需要在表达式的末尾。

如果未找到模型的 ID，则不返回任何内容。要强制`ModelNotFoundException`，然后可以捕获它以执行其他操作，例如记录日志，添加`OrFail`如下：

```php
MyCompany\Accommodation\Room::findOrFail($id);
```

## where 方法

要查询除 ID 以外的属性（列），请使用以下命令：

```php
select from accommodations where name='Lovely Hotel';
```

使用`where`方法后跟`get()`方法：

```php
MyCompany\Accommodation::where('name','Lovely Hotel')->get();
```

`like`比较器可以如下使用：

```php
MyCompany\Accommodation::where('name','like','%Lovely%')->get();
```

## 链接函数

多个 where 方法可以链接如下：

```php
MyCompany\Accommodation::where('name','Lovely Hotel')- >where('city','like','%Pittsburgh%')->get();
```

上述命令产生以下查询：

```php
select * from accommodations where name ='Lovely Hotel' and description like '%Pittsburgh%'
```

请注意，如果`where`比较器是`=`（相等），则不需要第二个参数（比较器），并且比较的第二部分传递到函数中。还要注意，在两个`where`方法之间添加了`and`操作。要实现`or`操作，必须对代码进行以下更改：

```php
MyCompany\Accommodation::where('name','Lovely Hotel')- >orWhere('description','like','%Pittsburgh%')->get();
```

请注意，`or`被添加到`where`创建`orWhere()`。

## 查找所有

要找到所有房间，使用`all()`方法代替`find`。请注意，此方法实际上执行查询：

```php
MyCompany\Accommodation\Room::all();
```

为了限制房间的数量，使用`take`方法代替`find`。由于`take`是可链接的，需要使用`get`来执行查询：

```php
MyCompany\Accommodation\Room::take(10)->get();
```

要实现分页，可以使用以下查询：

```php
MyCompany\Accommodation\Room::paginate();
```

默认情况下，上述查询将返回一个 JSON 对象，如下所示：

```php
{"total":15,        "per_page":15,
"current_page":1,      "last_page":1,
"next_page_url":null,   "prev_page_url":null,
"from":1,        "to":15,
"data":
{"id":9,"name":"LovelyHotel","description":"Lovely Hotel Greater Pittsburgh","location_id":1,"created_at":null,"updated_at": "2015-03-13 22:00:23","deleted_at":null,"franchise_id":1},{"id":12, "name":"Grand Hotel","description":"Grand Hotel Greater Cleveland","location_id":2,"created_at":"2015-02- 0820:09:35","updated_at":"2015-02- 0820:09:35","deleted_at":null,"franchise_id":1}
...
```

属性，如`total`，`per_page`，`current_page`和`last_page`，用于为开发人员提供一种简单的实现分页的方法，而数据数组则返回在名为`data`的数组中。

# 优雅的关系

诸如一对一、一对多（或多对一）和多对多之类的关系对于数据库程序员来说是熟悉的。Laravel 的 Eloquent 已经将这些概念带入了面向对象的环境中。此外，Eloquent 还有更强大的工具，比如多态关系，其中实体可以与多个其他实体相关联。在接下来的示例中，我们将看到住宿、房间和便利设施之间的关系。

![Eloquent 关系

## 一对一

第一个关系是一对一。在我们的示例软件中，我们可以使用我们住宿中的房间的例子。一个房间可能只（至少很容易）属于一个住宿，所以房间*属于*住宿。在`Room` Eloquent 模型中，以下代码告诉 Eloquent 房间属于`accommodation`函数：

```php
class Room extends Eloquent {
     public function accommodation()
     {
         return $this->belongsTo('MyCompany\Accommodation');
     }
}
```

有时，数据库表不遵循活动记录模式，特别是如果程序员继承了遗留数据库。如果数据库使用了一个名为`bedroom`而不是`rooms`的表，那么类将添加一个属性来指示表名：

```php
class Room extends Eloquent {
    protected $table = 'bedroom';
}
```

当执行以下路由代码时，`accommodation`对象将以 JSON 对象的形式返回：

```php
Route::get('test-relation',function(){
    $room = MyCompany\Accommodation\Room::find(1);
    return $room->accommodation;
});
```

响应将如下：

```php
{"id":9,"name":"LovelyHotel","description":"Lovely Hotel Greater Pittsburgh","location_id":1,"created_at":null,"updated_at": "2015-03-13 22:00:23","deleted_at":null}
```

### 提示

一个常见的错误是使用以下命令：

```php
return $room->accommodation();
```

在这种情况下，程序员期望返回模型。这将返回实际的`belongsTo`关系，在 RESTful API 的上下文中，将会抛出错误：

```php
Object of class Illuminate\Database\Eloquent\Relations\BelongsTo could not be converted to string
```

这是因为 Laravel 可以将 JSON 对象转换为字符串，但不能转换为关系。

运行的 SQL 如下：

```php
select * from rooms where rooms.id = '1' limit 1
select * from accommodations where accommodations.id = '9' limit 1
```

Eloquent 倾向于使用多个简单的查询，而不是进行更大的连接。

首先找到房间。然后，添加`limit 1`，因为`find`只用于查找单个实体或行。一旦找到`accommodation_id`，下一个查询将找到具有相应 ID 的住宿并返回对象。如果遵循了活动记录模式，Eloquent 生成的 SQL 非常易读。

## 一对多

第二个关系是一对多。在我们的示例软件中，我们可以使用住宿有许多房间的例子。因为房间可能属于一个住宿，那么住宿有*许多房间*。在`Accommodation` Eloquent 模型中，以下代码告诉 Eloquent 住宿有许多房间。

```php
class Accommodation {
    public function rooms(){
        return $this->hasMany('\MyCompany\Accommodation\Room');
    }
}
```

在类似的路由中，运行以下代码。这次，将以 JSON 格式的对象数组返回一组`rooms`对象：

```php
Route::get('test-relation',function(){
    $accommodation = MyCompany\Accommodation::find(9);
    return $accommodation->rooms;
});
```

响应将是以下数组：

```php
[{"id":1,"room_number":0,"created_at":null,"updated_at":null, "deleted_at":null,"accommodation_id":9},{"id":3,"room_number": 12,"created_at":"2015-03-14 08:52:25","updated_at":"2015-03-14  08:52:25","deleted_at":null,"accommodation_id":9},{"id":6, "room_number":12,"created_at":"2015-03-14  09:03:36","updated_at":"2015-03-14  09:03:36","deleted_at":null,"accommodation_id":9},{"id": 14,"room_number":12,"created_at":"2015-03-14  09:26:36","updated_at":"2015-03- 1409:26:36","deleted_at":null,"accommodation_id":9}]
```

运行的 SQL 如下：

```php
select * from accommodations where accommodations.id = ? limit 1
select * from rooms where rooms.accommodation_id = '9' and  rooms.accommodation_id is not null
```

与之前一样，找到住宿。第二个查询将找到属于该住宿的房间。添加了一个检查以确认`accommodation_id`不为空。

## 多对多

在我们的示例软件应用程序中，便利设施和房间之间的关系是多对多的。每个房间可以有许多便利设施，比如互联网接入和按摩浴缸，每个便利设施都在许多房间之间共享：*住宿中的每个房间都可以并且应该有互联网接入！*以下代码使用`belongsToMany`关系，使便利设施可以属于许多房间：

```php
class Amenity {
  public function rooms(){
        return $this- >belongsToMany('\MyCompany\Accommodation\Room');
    }
}
```

告诉我们每个房间都有某个便利设施的测试路由写成如下：

```php
Route::get('test-relation',function(){
    $amenity = MyCompany\Accommodation\Amenity::find(3);
    return $amenity->rooms;
});
```

返回一个房间列表：

```php
[{"id":1,"room_number":0,"created_at":2015-03-14 08:10:45,"updated_at":null,"deleted_at":null, "accommodation_id":9},{"id":5,"room_number":12, "created_at":"2015-03-14 09:00:38","updated_at":"2015-03-14", 09:00:38","deleted_at":null,"accommodation_id":12},
...]
```

执行的 SQL 如下：

```php
select * from amenities where amenities.id = ? limit 1
select rooms.*, amenity_room.amenity_id as pivot_amenity_id, amenity_room.room_id as pivot_room_id from rooms inner join amenity_room on rooms.id = amenity_room.room_id where amenity_room.amenity_id = 3
```

我们回忆一下`belongToMany`关系，它返回具有特定便利设施的房间：

```php
class Amenity {
   public function rooms(){
        return $this- >belongsToMany('\MyCompany\Accommodation\Room');
    }
}
```

Eloquent 巧妙地给了我们相应的`belongsToMany`关系，以确定特定房间有哪些便利设施。语法完全相同：

```php
class Room {
     public function amenities(){
         return $this- >belongsToMany('\MyCompany\Accommodation\Amenity');
     }
 }
```

测试路由几乎相同，只是用`rooms`替换`amenities`：

```php
Route::get('test-relation',function(){
    $room = MyCompany\Accommodation\Room::find(1);
    return $room->amenities;
});
```

结果是 ID 为 1 的房间的便利设施列表：

```php
[{"id":1,"name":"Wifi","description":"Wireless Internet Access","created_at":"2015-03-1409:00:38","updated_at":"2015-03-14 09:00:38","deleted_at":null},{"id":2,"name": "Jacuzzi","description":"Hot tub","created_at":"2015-03-14 09:00:38","updated_at":null,"deleted_at":null},{"id":3,"name": "Safe","description":"Safe deposit box for protecting valuables","created_at":"2015-03-1409:00:38","updated_at": "2015-03-1409:00:38","deleted_at":null}]
```

使用的查询如下：

```php
select * from rooms where rooms.id = 1 limit 1
select amenities.*, amenity_room.room_id as pivot_room_id, amenity_room.amenity_id as pivot_amenity_id from amenities inner join amenity_room on amenities.id = amenity_room.amenity_id where amenity_room.room_id = '1'
```

查询，用`room_id`替换`amenity_id`，用`rooms`替换`amenities`，显然是并行的。

## 有许多通过

Eloquent 的一个很棒的特性是“has-many-through”。如果软件的需求发生变化，并且我们被要求将一些住宿分组到特许经营店中，该怎么办？如果应用程序用户想要搜索一个房间，那么属于该特许经营店的任何住宿中的任何房间都可以被找到。将添加一个特许经营店表，并在住宿表中添加一个可空列，名为 `franchise_id`。这将可选地允许住宿属于特许经营店。房间已经通过 `accommodation_id` 列属于住宿。

一个房间通过其 `accommodation_id` 键属于一个 `住宿`，而一个住宿通过其 `franchise_id` 键属于一个特许经营店。

Eloquent 允许我们通过使用 `hasManyThrough` 来检索与特许经营店相关联的房间：

```php
<?php namespace MyCompany;

use Illuminate\Database\Eloquent\Model;

class Franchise extends Model {

    public function rooms()
    {
        return $this- >hasManyThrough('\MyCompany\Accommodation\Room', '\MyCompany\Accommodation');
    }
}
```

`hasManyThrough` 关系将目标或“拥有”作为其第一个参数（在本例中是房间），将“通过”作为第二个参数（在本例中是住宿）。

作为短语陈述的逻辑是：*这个特许经营店通过其住宿拥有许多房间*。

使用先前的测试路由，代码编写如下：

```php
Route::get('test-relation',function(){
    $franchise = MyCompany\Franchise::find(1);
    return $franchise->rooms;
});
```

返回的房间是一个数组，正如预期的那样：

```php
[{"id":1,"room_number":0,"created_at":null,"updated_at":null,"deleted_at":null,"accommodation_id":9,"franchise_id":1}, {"id":3,"room_number":12,"created_at":"2015-03-14 08:52:25","updated_at":"2015-03-14 08:52:25","deleted_at":null,"accommodation_id":9, "franchise_id":1},{"id":6,"room_number":12,"created_at":"2015-03-14 09:03:36","updated_at":"2015-03-14 09:03:36","deleted_at":null,"accommodation_id":9, "franchise_id":1},
]
```

执行的查询如下：

```php
select * from franchises where franchises.id = ? limit 1
select rooms.*, accommodations.franchise_id from rooms inner join accommodations on accommodations.id = rooms.accommodation_id where accommodations.franchise_id = 1
```

# 多态关系

Eloquent 的一个很棒的特性是拥有一个关系是多态的实体的可能性。这个词的两个部分，*poly* 和 *morphic*，来自希腊语。由于 *poly* 意味着 *许多*，*morphic* 意味着 *形状*，我们现在可以很容易地想象一个关系有多种形式。

## 设施关系

在我们的示例软件中，一个设施是与房间相关联的东西，比如按摩浴缸。某些设施，比如有盖停车场或机场班车服务，也可能与住宿本身相关。我们可以为此创建两个中间表，一个叫做 `amenity_room`，另一个叫做 `accommodation_amenity`。另一种很好的方法是将两者合并成一个表，并使用一个字段来区分两种类型或关系。

为了做到这一点，我们需要一个字段来区分 *设施和房间* 和 *设施和房间*，我们可以称之为关系类型。Laravel 的 Eloquent 能够自动处理这一点。

Eloquent 使用后缀 `-able` 来实现这一点。在我们的示例中，我们将创建一个具有以下字段的表：

+   `id`

+   `name`

+   `description`

+   `amenitiable_id`

+   `amenitiable_type`

前三个字段是熟悉的，但添加了两个新字段。其中一个将包含住宿或房间的 ID。

### 设施表结构

例如，给定 ID 为 5 的房间，`amenitiable_id` 将是 `5`，而 `amenitiable_type` 将是 `Room`。给定 ID 为 5 的住宿，`amenitiable_id` 将是 `5`，而 `amenitiable_type` 将是 `Accommodation`：

| id | name | description | amenitiable_id | amenitiable_type |
| --- | --- | --- | --- | --- |
| 1 | 无线网络 | 网络连接 | 5 | 房间 |
| 2 | 有盖停车场 | 车库停车 | 5 | 住宿 |
| 3 | 海景 | 房间内海景 | 5 | 房间 |

### 设施模型

在代码方面，`Amenity` 模型现在将包含一个 "amenitiable" 函数：

```php
<?php
namespace MyCompany\Accommodation;

use Illuminate\Database\Eloquent\Model;

class Amenity extends Model
{
    public function rooms(){
        return $this->belongsToMany('\MyCompany\Accommodation\Room');
    }
    public function amenitiable()
    {
        return $this->morphTo();
    }
```

### 住宿模型

`住宿` 模型将更改 `amenities` 方法，使用 `morphMany` 而不是 `hasMany`：

```php
<?php namespace MyCompany;

use Illuminate\Database\Eloquent\Model;

class Accommodation extends Model {
    public function rooms(){
        return $this->hasMany('\MyCompany\Accommodation\Room');
    }

    public function amenities()
    {
        return $this- >morphMany('\MyCompany\Accommodation\Amenity', 'amenitiable');
    }
}
```

### 房间模型

`Room` 模型将包含相同的 `morphMany` 方法：

```php
<?php
namespace MyCompany\Accommodation;

use Illuminate\Database\Eloquent\Model;

class Room extends Model
{
    protected $casts = ['room_number'=>'integer'];
    public function accommodation(){
        return $this->belongsTo('\MyCompany\Accommodation');
    }
    public function amenities() {
        return $this- >morphMany('\MyCompany\Accommodation\Amenity', 'amenitiable');
    }

}
```

现在，当要求为房间或住宿请求设施时，Eloquent 将自动区分它们：

```php
$accommodation->amenities();
$room->amenities();
```

这些函数中的每一个都返回了房间和住宿的正确类型的设施。

## 多对多多态关系

然而，一些设施可能在房间和住宿之间共享。在这种情况下，使用多对多多态关系。现在中间表添加了几个字段：

| amenity_id | amenitiable_id | amenitiable_type |
| --- | --- | --- |
| 1 | 5 | 房间 |
| 1 | 5 | 住宿 |
| 2 | 5 | 房间 |
| 2 | 5 | 住宿 |

正如所示，ID 为 5 的房间和 ID 为 5 的住宿都有 ID 为 1 和 2 的设施。

## 具有关系

如果我们想选择与特许经营连锁店关联的所有住宿，使用`has()`方法，其中关系作为参数传递：

```php
MyCompany\Accommodation::has('franchise')->get();
```

我们将得到以下 JSON 数组：

```php
[{"id":9,"name":"LovelyHotel","description":"Lovely Hotel Greater Pittsburgh","location_id":1,"created_at":null,"updated_at": "2015-03-13 22:00:23","deleted_at":null,"franchise_id":1}, {"id":12,"name": "Grand Hotel","description":"Grand Hotel Greater Cleveland","location_id":2,"created_at": "2015-02-0820:09:35","updated_at": "2015-02-0820:09:35","deleted_at":null,"franchise_id":1}]
```

请注意，`franchise_id`的值为 1，这意味着住宿与特许经营连锁店相关联。可选地，可以在`has`中添加`where`，创建一个`whereHas`函数。代码如下：

```php
MyCompany\Accommodation::whereHas('franchise',
                  function($query){
      $query->where('description','like','%Pittsburgh%'); 
      })->get();
```

请注意，`whereHas`将闭包作为其第二个参数。

这将仅返回描述中包含`匹兹堡`的住宿，因此返回的数组将只包含这样的结果：

```php
[{"id":9,"name":"LovelyHotel","description":"Lovely Hotel Greater Pittsburgh","location_id":1,"created_at":null,"updated_at": "2015-03-13 22:00:23","deleted_at":null,"franchise_id":1}]
```

## 贪婪加载

Eloquent 提供的另一个很棒的机制是贪婪加载。如果我们想要返回所有的特许经营连锁店以及它们的所有住宿，我们只需要在我们的`Franchise`模型中添加一个`accommodations`函数，如下所示：

```php
    public function accommodations()
    {
        return $this->hasMany('\MyCompany\Accommodation');
    }
```

然后，通过向语句添加`with`子句，为每个特许经营连锁店返回住宿：

```php
MyCompany\Franchise::with('accommodations')->get();
```

我们还可以列出与每个住宿相关的房间，如下所示：

```php
MyCompany\Franchise::with('accommodations','rooms')->get();
```

如果我们想要返回嵌套在住宿数组中的房间，则应使用以下语法：

```php
MyCompany\Franchise::with('accommodations','accommodations.rooms') ->get();
```

我们将得到以下输出：

```php
[{"id":1,"accommodations":
[
{"id":9,
"name":"Lovely Hotel",
"description":"Lovely Hotel Greater Pittsburgh",
"location_id":1,
"created_at":null,
"updated_at":"2015-03-13 22:00:23",
"deleted_at":null,
"franchise_id":1,
"rooms":[{"id":1,"room_number":0,"created_at":null,"updated_at": null,"deleted_at":null,"accommodation_id":9},
]},
{"id":12,"name":"GrandHotel","description":"Grand Hotel Greater Cleveland","location_id":2,"created_at":"2015-02-08…
```

在这个例子中，`rooms`包含在`accommodation`中。

# 结论

Laravel 的 ORM 非常强大。事实上，有太多类型的操作无法在一本书中列出。最简单的查询可以用几个按键完成。

Laravel 的 Eloquent 命令被转换为流畅的命令，因此如果需要更复杂的操作，可以使用流畅的语法。如果需要执行非常复杂的查询，甚至可以使用`DB::raw()`函数。这将允许在查询构建器中使用精确的字符串。以下是一个例子：

```php
$users = DB::table('accommodation')
                     ->select(DB::raw('count(*) as number_of_hotels'))->get();
```

这将只返回酒店的数量：

```php
[{"number_of_hotels":15}]
```

学习设计软件，从领域开始，然后考虑该领域涉及的实体，将有助于开发人员以面向对象的方式思考。拥有实体列表会导致表的创建，因此实际的模式创建将在最后执行。这种方法可能需要一些时间来适应。理解 Eloquent 关系对于能够生成表达性、可读性的查询数据库语句至关重要，同时隐藏复杂性。

Eloquent 极其有用的另一个原因是在遗留数据库的情况下。如果 ORM 应用在表名不符合标准、键名不相同或列名不易理解的情况下，Eloquent 提供了开发人员工具，实际上帮助使表名和字段名同质化，并通过提供属性的 getter 和 setter 来执行关系。

例如，如果字段名为`fname1`和`fname2`，我们可以在我们的模型中使用一个获取属性函数，语法是`get`后跟应用中要使用的所需名称和属性。因此，在`fname1`的情况下，函数将被添加如下：

```php
public function getUsernameAttribute($value)
{
  return $this->attributes['fname1'];
}
```

这些函数是 Eloquent 的真正卖点。在本章中，您学会了如何通过使用实体模型在数据库中查找数据，通过添加`where`、关系、强大的约定（如多态关系）以及辅助工具（如分页）来限制结果。

# 摘要

在本章中，详细演示了 Eloquent ORM。Eloquent 是一个面向对象的包装器，用于实际发生在数据库和代码之间的事情。由于 Fluent 查询构建器很容易访问，因此熟悉查询的编写方式非常重要。这将有助于调试，并且还涵盖了 Eloquent 不足的复杂情况。在本章中，讨论了大部分 Eloquent 的概念。然而，还有许多其他可用的方法，因此鼓励进一步阅读。

在下一章中，除了其他主题，您将学习如何扩展数据库以在更大规模上表现更好。


# 第九章：扩展 Laravel

任何编程语言中构建的框架的特点是使用各种组件。正如我们在前几章中看到的，框架为软件开发人员提供了许多不同的预构建工具，以完成诸如身份验证、数据库交互和 RESTful API 创建等任务。

然而，就框架而言，可扩展性问题总是信息技术领域任何经理最担心的问题。与使用现有代码的任何库一样，总会有一定程度的开销，一定程度的膨胀，总会有比实际需要的更多的东西。

# 可扩展性问题

框架无法轻松扩展的原因有很多。让我们来看一下问题的简要列表：

+   一个问题是不必要的代码和与实际构建的应用程序无直接关系的包。例如，并非每个项目都需要身份验证，数据库驱动程序也不一定是 MySQL。框架核心的包必须监控兼容性问题。

+   设计模式、观点和学习曲线经常阻碍新团队成员快速熟悉。随着项目的扩大，日常开发需求也需要增长，软件开发团队必须不断招募那些对框架已经有一定了解或至少了解其基本概念的成员。

+   框架安全问题需要持续监控框架社区的网站或存储库，以收集有关所需的紧急安全更新的信息。甚至底层的 Web 服务器和操作系统本身也需要监控。在撰写本文时，Laravel 5.1 即将发布，它将需要 PHP 5.5，因为 PHP 5.4 将在 2015 年晚些时候宣布终止生命周期。

+   诸如 Eloquent 之类的 ORM 总是会增加一些开销，因为代码首先需要从 Eloquent 转换为流畅的查询构建器，然后再转换为 PDO 代码。显然，使用面向对象的方法来查询数据库是明智的选择，但它是有成本的。

# 走向企业

尽管可能会遇到一些障碍，Laravel 在未来的企业中仍将是一个强大的选择。PHP 7 将会非常快，而 Zend Framework 3 等框架已经宣布了他们在 PHP 7 优化方面的路线图。此外，通过使用**FastCGI 进程管理器**（**FPM**）、NGINX Web 服务器，并允许 PHP 的缓存机制正常工作，应用程序的可扩展性将继续在企业空间中得到更多的认可，因为它的复兴持续进行，新的开发人员也在为其核心做出贡献。

在本章中，您将学习如何让 Laravel 在企业环境中表现更好，其中可扩展性问题至关重要。首先，将讨论路由器缓存。然后，您将了解许多工具、技术，甚至是正在开发的以可扩展性为重点的新微框架。具体来说，我们将讨论从 Laravel 派生的官方微框架**Lumen**。最后，您将学习如何通过一种称为*读*和*写*的技术有效地使用数据库。

在代码库的大小方面，与 Zend 或 Symfony 相比，Laravel 的代码库是最小的之一，尽管它确实使用了一些 Symfony 组件。如前几章所述，不同的包被移除以减轻占用空间，这是从 Symfony 的基于组件的思想中得到的启示。例如，默认情况下不再包括 HTML、SSH 和注释包。

# 路由缓存

路由缓存有助于加快速度。在 Laravel 5 中，引入了一种缓存机制来加快执行速度。

这里显示了一个示例`routes.php`：

```php
Route::post('reserve-room', 'ReservationController@store');

Route::controllers([
  'auth' => 'Auth\AuthController',
  'password' => 'Auth\PasswordController',
]);
Route::post('/bookRoom','ReservationsController@reserve', ['middleware' => 'auth', 'domain'=>'booking.hotelwebsite.com']);

Route::resource('rooms', 'RoomsController');

Route::group(['middleware' => ['auth','whitelist']], function()
{

  Route::resource('accommodations', 'AccommodationsController');
  Route::resource('accommodations.amenities', 'AccommodationsAmenitiesController');
  Route::resource('accommodations.rooms', 'AccommodationsRoomsController');
  Route::resource('accommodations.locations', 'AccommodationsLocationsController');
  Route::resource('amenities', 'AmenitiesController');
  Route::resource('locations', 'LocationsController');
});
```

通过运行以下命令，Laravel 将缓存路由：

```php
**$ php artisan route:cache**

```

然后，将它们放入以下目录中：

```php
**/vendor/routes.php**

```

这是结果文件的一小部分：

```php
<?php

/*

| Load The Cached Routes
|--------------------------------------------------------------------------
|
| Here we will decode and unserialize the RouteCollection instance that
| holds all of the route information for an application. This allows
| us to instantaneously load the entire route map into the router.
|
*/

app('router')->setRoutes(
  unserialize(base64_decode('TzozNDoiSWxsdW1pbmF0ZVxSb3V0aW5nXF JvdXRlQ29sbGVjdGlvbiI6NDp7czo5OiIAKgByb3V0ZXMiO2E6Njp7czozOiJH RVQiO2E6NTA6e3M6MToiLyI7TzoyNDoiSWxsdW1pbmF0ZVxSb3V0aW5nXFJvdX RlIjo3OntzOjY6IgAqAHVyaSI7czoxOiIvIjtzOjEwOiIAKgBtZXRob2RzIjth OjI6e2k6MDtzOjM6IkdFVCI7aToxO3M6NDoiSEVBRCI7fX
...
Db250cm9sbGVyc1xBbWVuaXRpZXNDb250cm9sbGVyQHVwZGF0ZSI7cjoxNDQx O3M6NTQ6Ik15Q29tcGFueVxIyb2xsZXJzXEhvdGVsQ29udHJvbGxlckBkZXN0c m95IjtyOjE2MzI7fX0='))
);
```

如 DocBlock 所述，路由被编码为 base64，然后进行序列化：

```php
unserialize(base64_decode( … ));
```

这执行一些预编译。如果我们对文件的内容进行 base64 解码，我们将获得序列化的数据。以下代码是文件的一部分：

```php
O:34:"Illuminate\Routing\RouteCollection":4:{s:9:"*routes"; a:6:{s:3:"GET";a:50:{s:1:"/";O:24:"Illuminate\Routing\Route": 7:{s:6:"*uri";s:1:"/";s:10:"*methods";a:2:{i:0;s:3:"GET";i:1; s:4:"HEAD";}s:9:"*action";a:5:{s:4:"uses";s:50:"MyCompany \Http\Controllers\WelcomeController@index";s:10:"controller"; s:50:"MyCompany\Http\Controllers\WelcomeController@index"; s:9:"namespace";s:26:"MyCompany\Http\Controllers";s:6:"prefix"; N;s:5:"where";a:0:{}}s:11:"*defaults";a:0:{}s:9:"*wheres"; a:0:{}s:13:"*parameters";N;s:17:"*parameterNames";N; }s:4:"home";O:24:"Illumin…

"MyCompany\Http\Controllers\HotelController@destroy";r:1632;}}
```

如果`/vendor/routes.php`文件存在，则使用它，而不是位于`/app/Http/routes.php`的`routes.php`文件。如果在某个时候不再希望使用路由缓存文件，则使用以下`artisan`命令：

```php
**$ php artisan route:clear**

```

这个命令将删除缓存的`routes`文件，Laravel 将重新开始使用`/app/Http/routes.php`文件。

### 提示

需要注意的是，如果在`routes.php`文件中使用了任何闭包，缓存将失败。以下是路由中闭包的一个示例：

```php
Route::get('room/{$id}', function(){
  return Room::find($id);
});
```

出于任何原因，在`routes.php`文件中使用闭包是不可取的。为了能够使用路由缓存，将闭包中使用的代码移到控制器中。

## Illuminate 路由

所有这些工作都加快了请求生命周期中的一个重要部分，即路由。在 Laravel 中，路由类位于`illuminate/routing`命名空间中：

```php
<?php namespace Illuminate\Routing;
use Closure;
use LogicException;
use ReflectionFunction;
use Illuminate\Http\Request;
use Illuminate\Container\Container;
use Illuminate\Routing\Matching\UriValidator;
use Illuminate\Routing\Matching\HostValidator;
use Illuminate\Routing\Matching\MethodValidator;
use Illuminate\Routing\Matching\SchemeValidator;
use Symfony\Component\Routing\Route as SymfonyRoute;
use Illuminate\Http\Exception\HttpResponseException;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException; 
```

检查`use`操作符，可以清楚地看出路由机制由许多类组成。最重要的一行是：

```php
use Symfony\Component\Routing\Route as SymfonyRoute;
```

Laravel 使用 Symfony 的路由类。然而，Nikita Popov 编写了一个新的路由软件包。`FastRoute`是一个快速的请求路由器，比其他路由软件包更快，并解决了现有路由软件包的一些问题。这个组件是 Lumen 微框架的主要优势之一。

## Lumen

从苏打营销的角度来看，Lumen 可以被认为是 Laravel *Light*或 Laravel *Zero*。除了使用`FastRoute`路由软件包外，许多软件包已从 Lumen 中删除，使其变得最小化并减少其占用空间。

## Laravel 和 Lumen 之间的比较

在下表中列出了 Laravel 和 Lumen 中的软件包，并进行了比较。运行以下命令时，将安装这些软件包：

```php
$ composer update –-no-dev
```

前面的命令是在开发完成并且应用程序准备好部署到服务器时使用的。在这个阶段，诸如 PHPUnit 和 PHPSpec 之类的工具显然被排除在外。

软件包名称对齐，以说明这些软件包在 Laravel 和 Lumen 中的位置：

| Laravel 软件包 | Lumen 软件包 |
| --- | --- |
| - | `nikic/fast-route` |
| `illuminate/cache` | - |
| `illuminate/config` | `illuminate/config` |
| `illuminate/console` | `illuminate/console` |
| `illuminate/container` | `illuminate/container` |
| `illuminate/contracts` | `illuminate/contracts` |
| `illuminate/cookie` | `illuminate/cookie` |
| `illuminate/database` | `illuminate/database` |
| `illuminate/encryption` | `illuminate/encryption` |
| `illuminate/events` | `illuminate/events` |
| `illuminate/exception` | - |
| `illuminate/filesystem` | `illuminate/filesystem` |
| `illuminate/foundation` | - |
| `illuminate/hashing` | `illuminate/hashing` |
| `illuminate/http` | `illuminate/http` |
| `illuminate/log` | - |
| `illuminate/mail` | - |
| `illuminate/pagination` | `illuminate/pagination` |
| `illuminate/pipeline` | - |
| `illuminate/queue` | `illuminate/queue` |
| `illuminate/redis` | - |
| `illuminate/routing` | - |
| `illuminate/session` | `illuminate/session` |
| `illuminate/support` | `illuminate/support` |
| `illuminate/translation` | `illuminate/translation` |
| `illuminate/validation` | `illuminate/validation` |
| `illuminate/view` | `illuminate/view` |
| `jeremeamia/superclosure` | - |
| `league/flysystem` | - |
| `monolog/monolog` | `monolog/monolog` |
| `mtdowling/cron-expression` | `mtdowling/cron-expression` |
| `nesbot/carbon` | - |
| `psy/psysh` | - |
| `swiftmailer/swiftmailer` | - |
| `symfony/console` | - |
| `symfony/css-selector` | - |
| `symfony/debug` | - |
| `symfony/dom-crawler` | - |
| `symfony/finder` | - |
| `symfony/http-foundation` | `symfony/http-foundation` |
| `symfony/http-kernel` | `symfony/http-kernel` |
| `symfony/process` | - |
| `symfony/routing` | - |
| `symfony/security-core` | `symfony/security-core` |
| `symfony/var-dumper` | `symfony/var-dumper` |
| `vlucas/phpdotenv` | - |
| `classpreloader/classpreloader` | - |
| `danielstjules/stringy` | - |
| `doctrine/inflector` | - |
| `ext-mbstring` | - |
| `ext-mcrypt` | - |

在撰写本文时，使用非开发配置在 Laravel 5.0 中安装了 51 个包（显示在左列）。将此包数量与 Lumen 中安装的包数量进行比较（显示在右列）-只有 24 个。

前述的`nikic/fast-route`包是 Lumen 拥有而 Laravel 没有的唯一包。`symfony/routing`包是 Laravel 中的补充包。

## 精简应用程序开发

我们将使用一个示例，一个简单的面向公众的 RESTful API。这个 RESTful API 以 JSON 格式向任何用户显示一系列住宿的名称和地址，通过`GET`：

+   如果不需要使用密码，则不需要`ext/mcrypt`。

+   如果不需要进行日期计算，则不需要`nesbot/carbon`。由于没有 HTML 界面，因此不需要涉及测试应用程序的 HTML 的以下库，`symfony/css-selector`和`symfony/dom-crawler`。

+   如果不需要向用户发送电子邮件，则不需要`illuminate/mail`或`swiftmailer/swiftmailer`。

+   如果不需要与文件系统进行特殊交互，则不需要`league/flysystem`。

+   如果不是从命令行运行的命令，则不需要`symfony/console`。

+   如果不需要 Redis，则可以不使用`illuminate/redis`。

+   如果不需要不同环境的特定配置值，则不需要`vlucas/phpdotenv`。

### 提示

`vlucas/phpdotenv`包是`composer.json`文件中的一个建议包。

很明显，删除某些包的决定是经过慎重考虑的，以便根据最简单的应用程序需要简化 Lumen。

## 读/写

Laravel 还有另一个帮助其在企业中提高性能的机制：读/写。这与数据库性能有关，但功能如此易于设置，以至于任何应用程序都可以利用其有用性。

关于 MySQL，原始的 MyISAM 数据库引擎在插入、更新和删除期间需要锁定整个表。这在修改数据的大型操作期间造成了严重瓶颈，而选择查询等待访问这些表。随着 InnoDB 的引入，`UPDATE`、`INSERT`和`DELETE` SQL 语句只需要在行级别上锁定。这对性能产生了巨大影响，因为选择可以从表的各个部分读取，而其他操作正在进行。

MariaDB，一个 MySQL 分支，声称比传统的 MySQL 性能更快。将数据库引擎替换为 TokuDB 将提供更高的性能，特别是在大数据环境中。

加速数据库性能的另一种机制是使用主/从配置。在下图中，所有操作都在单个表上执行。插入和更新将锁定单行，选择语句将按分配执行。

![读/写](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-lrv/img/B04559_09_01.jpg)

传统数据库表操作

## 主表

主/从配置使用允许`SELECT`、`UPDATE`和`DELETE`语句的主表。这些语句修改表或向其写入。也可能有多个主表。每个主表都保持持续同步：对任何表所做的更改需要通知主表。

## 从表

从数据库表是主数据库表的从属。它依赖于主数据库表进行更改。SQL 客户端只能从中执行读操作（`SELECT`）。可能还有多个从数据库依赖于一个或多个主数据库表。主数据库表将其所有更改通知给所有从数据库。以下图表显示了主/从设置的基本架构：

![从数据库表](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-lrv/img/B04559_09_02.jpg)

主从（读/写设置）

这种持续的同步会给数据库结构增加一些开销；然而，它提供了重要的优势：

由于从数据库表只能执行`SELECT`语句，而主数据库表可以执行`INSERT`、`UPDATE`和`DELETE`语句，因此从数据库表可以自由接受许多`SELECT`语句，而无需等待涉及相同行的任何操作完成。

一个例子是货币汇率或股票价格表。这个表将实时不断地更新最新值，甚至可能每秒更新多次。显然，一个允许许多用户访问这些信息的网站可能会有成千上万的访问者。此外，用于显示这些数据的网页可能会为每个用户不断发出多个请求。

当有`UPDATE`语句需要同时访问相同数据时，执行许多`SELECT`语句会稍微慢一些。

通过使用主/从配置，`SELECT`语句将仅在从数据库表上执行。这个表只以极其优化的方式接收已更改的数据。

在纯 PHP 中使用诸如`mysqli`之类的库，可以配置两个数据库连接：

```php
$master=mysqli_connect('127.0.0.1:3306','dbuser','dbpassword','mydatabase');
$slave=mysqli_connect('127.0.0.1:3307','dbuser','dbpassword','mydatabase');
```

在这个简化的例子中，从数据库设置在同一台服务器上。在实际应用中，它很可能会设置在另一台服务器上，以利用独立的硬件。

然后，所有涉及*写*语句的 SQL 语句将在从数据库上执行，*读*将在主数据库上执行。

这将增加一些编程工作量，因为每个 SQL 语句都需要传入不同的连接：

```php
$result= mysqli_real_query($master,"UPDATE exchanges set rate='1.345' where exchange_id=2");
$result= mysqli_query($slave,"SELECT rate from exchanges where exchange_id=2");
```

在上面的代码示例中，应该记住哪些 SQL 语句应该用于主数据库，哪些 SQL 语句应该用于从数据库。

## 配置读/写

如前所述，用 Eloquent 编写的代码会转换为流畅的查询构建器代码。然后，该代码将转换为 PDO，这是各种数据库驱动程序的标准封装。

Laravel 通过其读/写配置提供了管理主/从配置的能力。这使程序员能够编写 Eloquent 和流畅的查询构建器代码，而不必担心查询是在主数据库表还是从数据库表上执行。此外，一个最初没有主/从配置的软件项目，后来需要扩展到主/从设置，只需要改变数据库配置的一个方面。数据库配置文件位于`config/database.php`。

作为`connections`数组的一个元素，将创建一个带有键`mysql`的条目，其配置如下：

```php
'connections' =>
'mysql' => [
    'read' => [
        'host' => '192.168.1.1',
```

```php
     'password'  => 'slave-Passw0rd', 
    ],
    'write' => [
        'host' => '196.168.1.2',
```

```php
    'username'  => 'dbhostusername'    
    ],
    'driver'    => 'mysql',
    'database'  => 'database',
    'username'  => 'dbusername',
    'password'  => 's0methingSecure',
    'charset'   => 'utf8',
    'collation' => 'utf8_unicode_ci',
    'prefix'    => '',
],
```

读和写分别代表从和主。由于参数级联，如果用户名、密码和数据库名称相同，则只需要列出主机名的 IP 地址。但是，任何值都可以被覆盖。在这个例子中，读取的密码与主数据库不同，写入的用户名与从数据库不同。

# 创建主/从数据库配置

要设置主/从数据库，请从命令行执行以下步骤。

1.  第一步是确定 MySQL 服务器绑定到哪个地址。为此，请找到包含 bind-address 参数的 MySQL 配置文件的行：

```php
**bind-address            = 127.0.0.1**

```

此 IP 地址将设置为主服务器使用的 IP 地址。

1.  接下来，取消注释包含`server-id`的 MySQL 配置文件中的行，该文件很可能位于`/etc/my.cn`或`/etc/mysql/mysql.conf.d/mysqld.cnf`。

1.  Unix 的`sed`命令可以轻松执行此操作：

```php
**$ sed -i s/#server-id/server-id/g  /etc/mysql/my.cnf**

```

### 提示

`/etc/mysql/my.cnf`字符串需要替换为正确的文件名。

1.  取消注释包含`server-id`的 MySQL 配置文件中的行：

```php
**$ sed -i s/#log_bin/log_bin/g  /etc/mysql/my.cnf**

```

### 提示

同样，`/etc/mysql/my.cnf`字符串需要替换为正确的文件名。

1.  现在，需要重新启动 MySQL。您可以使用以下命令执行此操作：

```php
**$ sudo service mysql restart**

```

1.  以下占位符应替换为实际值：

```php
**MYSQLUSER**
**MYSQLPASSWORD**
**MASTERDATABASE**
**MASTERDATABASEUSER**
**MASTERDATABASEPASSWORD**
**SLAVEDATABASE**
**SLAVEDATABASEUSER**
**SLAVEDATABASEPASSWORD**

```

## 设置主服务器

设置主服务器的步骤如下：

1.  授予从数据库用户权限：

```php
**$ echo  "GRANT REPLICATION SLAVE ON *.* TO 'DATABASEUSER'@'%' IDENTIFIED BY 'DATABASESLAVEPASSWORD';" | mysql -u MYSQLUSER -p"MYSQLPASSWORD"** 

```

1.  接下来，必须使用以下命令刷新权限：

```php
**$ echo  "FLUSH PRIVILEGES;" | mysql -u MYSQLUSER -p"MYSQLPASSWORD"** 

```

1.  接下来，使用以下命令切换到主数据库：

```php
**$ echo  "USE MASTERDATABASE;" | mysql -u MYSQLUSER -p"DATABASEPASSWORD"** 

```

1.  接下来，使用以下命令刷新表：

```php
**$ echo  "FLUSH TABLES WITH READ LOCK;" | mysql -u MYSQLUSER -p"MYSQLPASSWORD"** 

```

1.  使用以下命令显示主数据库状态：

```php
**$ echo  "SHOW MASTER STATUS;" | mysql -u MYSQLUSER -p"MYSQLPASSWORD"** 

```

注意输出中的位置和文件名：

```php
POSITION
FILENAME
```

1.  使用以下命令转储主数据库：

```php
**$ mysqldump -u root -p"MYSQLPASSWORD"  --opt "MASTERDATABASE" > dumpfile.sql**

```

1.  使用以下命令解锁表：

```php
**$ echo  "UNLOCK TABLES;" | mysql -u MYSQLUSER -p"MYSQLPASSWORD"** 

```

## 设置从服务器

设置从服务器的步骤如下：

1.  在从服务器上，使用以下命令创建从数据库：

```php
**$ echo  "CREATE DATABASE SLAVEDATABASE;" | mysql -u MYSQLUSER -p"MYSQLPASSWORD"** 

```

1.  使用以下命令导入从主数据库创建的转储文件：

```php
**$ mysql -u MYSQLUSER -p"MYSQLPASSWORD"  "MASTERDATABASE" < dumpfile.sql**

```

1.  现在，MySQL 配置文件使用 server-id 2：

```php
server-id            = 2
```

1.  在 MySQL 配置文件中，应取消注释两行，如下所示：

```php
**#log_bin			= /var/log/mysql/mysql-bin.log**
**expire_logs_days	= 10**
**max_binlog_size   = 100M**
**#binlog_do_db		= include_database_name**

```

1.  您将得到以下结果：

```php
log_bin			= /var/log/mysql/mysql-bin.log
expire_logs_days	= 10
max_binlog_size    = 100M
binlog_do_db		= include_database_name
```

1.  此外，需要在`binglog_do_db`下面添加以下行：

```php
relay-log                = /var/log/mysql/mysql-relay-bin.log
```

1.  现在，需要使用以下命令重新启动 MySQL：

```php
**$ sudo service mysql restart**

```

1.  最后，设置主密码。主日志文件和位置将设置为步骤 5 中记录的文件名和位置。运行以下命令：

```php
MASTER_PASSWORD='password', MASTER_LOG_FILE='FILENAME', MASTER_LOG_POS= POSITION;
```

# 总结

在本章中，您学会了如何通过路由缓存加快路由速度。您还学会了如何完全用 Lumen 替换 Laravel，这是完全源自 Laravel 的微框架。最后，我们讨论了 Laravel 如何使用读写配置充分利用主从配置。

Symfony 2.7 于 2015 年 5 月发布。这是一个长期支持版本。该版本将得到 36 个月的支持。在那之后不久，Taylor Otwell 决定创建 Laravel 的第一个 LTS 版本。这是 Laravel 牢固地定位在企业空间的第一个迹象。与 Symfony 和 Zend 的情况不同，Laravel 背后还没有正式的公司。然而，有一个庞大的社区包和服务生态系统，比如由 Jeffrey Way 运营的 Laracasts，他与 Taylor 密切合作提供官方培训视频。

此外，Taylor Otwell 还运行一个名为 Envoyer 的服务，该服务消除了 Laravel 部署的所有初始障碍，并为 Laravel 以及其他类型的现代 PHP 项目提供*零停机*部署。

随着 Laravel 5.1 LTS 的到来，Laravel 将会发生许多新的令人兴奋的事情。使用许多社区包的决定使 Taylor 和他的社区能够专注于框架的最重要方面，而无需重新发明轮子并维护许多冗余的包。此外，Laravel Collective 维护了已被弃用的包，即使最终从 Laravel 中删除的包也将继续得到多年的支持。

除了方便的服务，比如 Envoyer，下一章还将介绍一个最近出现的优秀自动化工具：Elixir。


# 第十章：使用 Elixir 构建、编译和测试

本章将涵盖以下主题：

+   安装 Node.js，Gulp 和 Elixir

+   运行 Elixir

+   使用 Elixir 合并 CSS 和 JavaScript 文件

+   设置通知

+   使用 Elixir 运行测试

+   扩展 Elixir

# 自动化 Laravel

在整本书中，已经构建了示例应用程序的许多部分。我们讨论了创建应用程序涉及的步骤。然而，关于帮助搭建、样板模板和为 CRUD 应用程序构建 RESTful API 的工具还有更多信息可用。直到最近，关于自动化开发过程和部署过程的一些部分并没有太多的资料。

在 PHP 领域，近年来出现了一个新的领域，即持续集成和构建工具的概念。持续集成和持续交付的流行使开发团队能够不断发布许多小的改进，每天多次发布他们的应用程序。在本章中，您将了解到 Laravel 具有一套新的工具集，可以使团队快速轻松地部署他们的软件版本，并自动构建和组合软件的许多组件。

持续集成和持续交付在开发过程中引起了相当大的变革，大大改变了软件构建的方式。然而，不久之前，标准的部署过程只涉及将代码放在服务器上。大多数早期采用 PHP 的人只是需要添加功能，比如*论坛*或*联系我们*表单的网页设计师。由于他们大多不是程序员，因此网页设计和图形设计中使用的大多数实践也被用于 PHP 部署。这些实践通常涉及使用诸如 FileZilla 之类的应用程序，将文件从左侧面板（用户的计算机）拖放到右侧（服务器的目录）。对于更有经验的人来说，使用终端仿真器（如 PuTTY）执行当时晦涩的 UNIX 命令。

使用不安全的文件传输端口 21，并且所有内容都未经压缩，只是简单地复制到服务器上。通常，所有文件都会被覆盖，而且部署大型网站的过程通常需要将近一个小时，因为有很多图片和文件。

最终，源代码控制系统变得普遍。在最近几年，SVN 和 Git 已成为大多数软件项目的行业标准。这些工具允许直接从代码仓库部署。

最近，composer 的到来为简单地将整个软件包包含到软件应用程序中添加功能创造了一种简单的方式。开发人员只需向配置文件添加一行代码即可轻松实现！

自动化开发和部署过程可能涉及许多步骤，以下是其中一些。

## 部署

以下是部署过程的一些功能：

+   复制与生产环境相关的某些配置设置

+   处理或编译使用快捷语法或预处理器编写的任何**层叠样式表**（**CSS**）或 JavaScript 文件

+   将各种资产（源代码或图像）复制到镜像、集群服务器或内容交付网络中

+   修改某些文件或目录的读/写/执行权限和/或所有权

+   将多个文件合并为一个文件，以减少执行多个 HTTP 调用所需的开销

+   减少文件中的无用空格和注释（缩小和/或混淆）以减小文件大小

+   将服务器上的现有文件与本地环境中的文件进行比较，以确定是否覆盖它们

+   对源代码进行标记和/或版本控制，以便可能进行代码回滚

## 开发或部署

以下是开发或部署过程的一些功能：

+   验证代码是否通过了编写的所有单元、功能和验收测试，以确保其质量

+   运行执行各种操作的脚本

+   执行任何迁移、种子播种或对数据库表的其他修改

+   从托管的源代码控制系统（如 GitHub）获取源代码控制

很明显，现代开发非常复杂。软件开发的更加困难的方面是在开发过程中不断重新创建生产或最终环境。

# 朝着自动化的方向

诸如文件监视器之类的工具可以在每次文件被修改时运行脚本或执行操作。此外，诸如 PHPStorm 之类的 IDE 将识别文件扩展名，并提供监视文件更改并允许开发人员执行某些操作的选项。虽然这种方法是可以接受的，但它并不是非常便携，每个开发人员都必须创建和共享一个包含 IDE 或文本编辑器中各种监视器的配置文件。这会产生依赖性，依赖于整个团队的一个单一 IDE。

此外，还可以创建其他方法，例如 Bash-shell 脚本，以在特定时间间隔运行。但是，使用这些脚本需要 UNIX-shell 编码知识。正如先前所示，像 artisan 这样的工具有助于自动化许多手动任务。但是，大多数默认的 artisan 命令是设计为手动执行的。

幸运的是，出现了两个使用 Node.js JavaScript 平台的工具：*Grunt*和*gulp*。Grunt 和 gulp 都取得了相当大的成功，但 gulp 最近变得更加流行。然而，对于可能不熟悉 JavaScript 语法的 PHP 开发人员来说，学习如何快速编写 gulp 任务并不容易。

考虑以下示例代码，摘自 gulp 的文档：

```php
gulp.task('scripts', ['clean'], function() {
  // Minify and copy all JavaScript (except vendor scripts)
  // with sourcemaps all the way down
  return gulp.src(paths.scripts)
    .pipe(sourcemaps.init())
      .pipe(coffee())
      .pipe(uglify())
      .pipe(concat('all.min.js'))
    .pipe(sourcemaps.write())
    .pipe(gulp.dest('build/js'));
});
```

# 从 Gulp 到 Elixir

幸运的是，Laravel 社区一直秉承着前瞻性思维，专注于减少复杂性。一个名为**Elixir**的官方社区工具已经出现，以便于使用 gulp。Gulp 是建立在 Node.js 之上的，而 Elixir 是建立在 gulp 之上的，创建了一个包装器：

![从 Gulp 到 Elixir](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-lrv/img/B04559_10_01.jpg)

### 注意

Laravel Elixir 不应与同名的动态功能语言混淆。另一个 Elixir 使用 Erlang 虚拟机，而 Laravel Elixir 使用 gulp 和 Node.js

# 入门

第一步是在开发计算机上安装 Node.js（如果尚未安装）。

### 注意

可以在以下网址找到说明：

[`nodejs.org`](https://nodejs.org)

## 安装 Node.js

对于像 Ubuntu 这样的基于 Debian 的操作系统，安装 Node.js 可能就像使用`apt`软件包管理器一样简单。从命令行使用以下命令：

```php
**$ sudo apt-get install -y nodejs**

```

请参考 Node.js 网站（[`nodejs.org`](https://nodejs.org)）上的正确操作系统的安装说明。

## 安装 Node.js 包管理器

下一步涉及安装 gulp，Elixir 将使用它来运行其任务。对于这一步，需要**Node.js 包管理器**（**npm**）。如果尚未安装`npm`，则应使用`apt`软件包安装程序。以下命令将用于安装`npm`：

```php
**$ sudo apt-get install npm**

```

npm 使用一个`json`文件来管理项目的依赖关系：`package.json`。该文件位于 Laravel 项目目录的根目录中，格式如下：

```php
{
  "devDependencies": {
    "gulp": "³.8.8",
    "laravel-elixir": "*"
  }
}
```

安装 gulp 和 Laravel Elixir 作为依赖项。

## 安装 Gulp

以下命令用于安装`gulp`：

```php
**$ sud onpm install --global gulp**

```

## 安装 Elixir

一旦安装了 Node.js、npm 和 gulp，下一步是安装 Laravel Elixir。通过运行`npm` install 而不带任何参数，`npm`将读取其配置文件并安装 Laravel Elixir：

```php
**$ npm install**

```

# 运行 Elixir

默认情况下，Laravel 包含一个`gulpfile.js`文件，该文件由 gulp 用于运行其任务。该文件包含一个`require`方法，用于包含运行任务所需的一切：

```php
var elixir = require('laravel-elixir');

/*
 |----------------------------------------------------------------
 | Elixir Asset Management
 |----------------------------------------------------------------
 |
 | Elixir provides a clean, fluent API for defining some basic gulp tasks
 | for your Laravel application. By default, we are compiling the Sass
 | file for our application, as well as publishing vendor resources.
 |
 */

elixir(function(mix) {
    mix.less('app.less');
});
```

第一个混合示例显示为：`app.less`。要运行 gulp，只需在命令行中输入`gulp`，如下所示：

```php
**$  gulp**

```

输出如下所示：

```php
**[21:23:38] Using gulpfile /var/www/laravel.example/gulpfile.js**
**[21:23:38] Starting 'default'...**
**[21:23:38] Starting 'less'...**
**[21:23:38] Running Less: resources/assets/less/app.less**
**[21:23:41] Finished 'default' after 2.35 s**
**[21:23:43] gulp-notify: [Laravel Elixir] Less Compiled!**
**[21:23:43] Finished 'less' after 4.27 s**

```

第一行表示已加载 gulp 文件。接下来的行显示每个任务的运行情况。`less`任务处理层叠样式表预处理器`Less`。

# 设置通知

如果您的开发环境是 Vagrant Box，则安装`vagrant-notify`将允许 Laravel Elixir 直接与主机交互，并在操作系统中直接显示本机消息。要安装它，应从主机操作系统运行以下命令：

```php
**$ vagrant plugin install vagrant-notify**

```

以下是通知的截图，显示 PHPUnit 测试失败了：

![设置通知](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-lrv/img/B04559_10_02.jpg)

安装说明取决于每个操作系统。

### 注意

有关更多信息，请访问[`github.com/fgrehm/vagrant-notify`](https://github.com/fgrehm/vagrant-notify)。

# 使用 Elixir 合并 CSS 和 JavaScript 文件

可能，部署过程中最重要的一步是合并和缩小 CSS 和 JavaScript 文件。缩小和合并五个 JavaScript 文件和三个 CSS 文件意味着不再有八个 HTTP 请求，而只有一个。此外，通过去除空格、换行符、注释和其他技术（例如缩短变量名）来缩小文件大小，文件大小将减少到原始大小的一小部分。尽管有这些优势，仍然有许多网站继续使用未缩小和未合并的 CSS 和 JavaScript 文件。

Elixir 提供了一种简单的方法来轻松合并和缩小文件。以下代码说明了这个示例：

```php
elixir(function(mix) {
    mix.scripts().styles();
});
```

`scripts()`和`styles()`两种方法将所有 JavaScript 和 CSS 文件合并为单个文件，分别为`all.js`和`all.css`。默认情况下，这两个函数期望文件位于`/resources/assets/js`和`/resources/assets/css`。

当 gulp 命令完成时，输出将如下所示：

```php
**[00:36:20] Using gulpfile /var/www/laravel.example/gulpfile.js**
**[00:36:20] Starting 'default'...**
**[00:36:20] Starting 'scripts'...**
**[00:36:20] Merging: resources/assets/js/**/*.js**
**[00:36:20] Finished 'default' after 246 ms**
**[00:36:20] Finished 'scripts' after 280 ms**
**[00:36:20] Starting 'styles'...**
**[00:36:20] Merging: resources/assets/css/**/*.css**
**[00:36:21] Finished 'styles' after 191 ms**

```

请注意输出方便地说明了扫描了哪些目录。内容被合并，但没有被缩小。这是因为在开发过程中，在缩小文件上进行调试太困难。如果只有某个文件需要合并，则可以将文件名作为第一个参数传递给函数：

```php
mix.scripts('app.js');
```

如果要合并多个文件，则可以将文件名数组作为第一个参数传递给函数：

```php
mix.scripts(['app.js','lib.js']);
```

在生产环境中，希望有缩小的文件。要让 Elixir 缩小 CSS 和 JavaScript，只需在 gulp 命令中添加`--production`选项，如下所示：

```php
**$ gulp --production**

```

这将产生所需的缩小输出。默认输出目录位于：

```php
/public/js
/public/css
```

# 使用 Laravel Elixir 编译

Laravel Elixir 非常擅长执行通常需要学习脚本语言的例行任务。以下各节将演示 Elixir 可以执行的各种编译类型。

## 编译 Sass 和 Less

层叠样式表预处理器`Less`和`Sass`出现是为了增强 CSS 的功能。例如，它不包含任何变量。`Less`和`Sass`允许前端开发人员利用变量和其他熟悉的语法特性。以下代码是标准 CSS 的示例。DOM 元素`p`和`li`（分别表示段落和列表项），以及具有`post`类的任何元素将具有`font-family` Arial，sans-serif 作为回退，并且颜色为黑色：

```php
p, li, .post {
  font-family: Arial, sans-serif;
  color: #000;
}
```

接下来，使用`Sass` CSS 预处理器，将字体族和文本颜色替换为两个变量：`$text-font`和`$text-color`。这样在需要更改时可以轻松维护。而且，这些变量可以共享。代码如下：

```php
$text-font:    Arial, sans-serif;
$text-color: #000;

p, li, .post {
  font: 100% $text-font;
  color: $text-color;
}
h2 {
  font: 2em $text-font;
  color: $text-color;
}
```

`Less`预处理器使用`@`而不是`$`；因此，它的语法看起来更像是注释而不是`php`变量：

```php
@text-font:    Arial, sans-serif;
@text-color: #000;

p, li, .post {
  font: 100% @text-font;
  color: @text-color;
}
h2 {
  font: 2em @text-font;
  color: @text-color;
}
```

还需要执行一个额外的步骤，因为它不会被浏览器引擎解释。增加的步骤是将`Less`或`Sass`代码编译成真正的 CSS。这在开发阶段会增加额外的时间；因此，Elixir 通过自动化流程来帮助。

在之前的 Laravel Elixir 示例中，`less`函数只接受文件名`app.less`作为其唯一参数。现在，示例应该更清晰一些。此外，`less`可以接受一个将被编译的参数数组。

`less`方法在`/resources/assets/less`中搜索，默认情况下输出将放在`public/css/`中：

```php
elixir(function(mix) {
    mix.less([
        'style.less',
        'style-rtl.less'
    ]);
});
```

## 编译 CoffeeScript

CoffeeScript 是一种编译成 JavaScript 的编程语言。与 Less 和 Sass 一样，它的目标是简化或扩展它所编译的语言的功能。在 CoffeeScript 的情况下，它通过减少按键次数来简化 Javascript。在下面的 JavaScript 代码中，创建了两个变量——一个数组和一个对象：

```php
var available, list, room;

room = 14;

available = true;

list = [101,102,311,421];

room = { 
  id: 1,
  number: 102,
  status: "available"
}
```

在下面的 CoffeeScript 代码中，语法非常相似，但不需要分号，也不需要`var`来创建变量。此外，缩进用于定义对象的属性。代码如下：

```php
room = 14

available = true 

list = [101,102,311,421]

room = 
  id: 1
  number: 102
  status: "available"
```

在这个 CoffeeScript 示例中，字符较少；然而，对于程序员来说，减少按键次数可以帮助提高速度和效率。要将 coffee 编译器添加到 Elixir 中，只需使用`coffee`函数，如下面的代码所示：

```php
elixir(function(mix) {
    mix.coffee([
        'app.coffee'
    ]);
});
```

## 编译器命令摘要

下表显示了预处理器、语言、函数以及每个函数期望源文件的位置。右侧的最后一列显示了结果合并文件的目录和/或名称。

| processor | Language | function | Source directory | Default Output Location |
| --- | --- | --- | --- | --- |
| Less | CSS | `less()` | `/resources/assets/less/file(s).less` | `/public/css/file(s).css` |
| Sass | CSS | `sass()` | `/resources/assets/sass/file(s).scss` | `/public/css/file(s).css` |
| N/A | CSS | `styles()` | `/resources/assets/css/` | `/public/css/all.css` |
| N/A | JavaScript | `scripts()` | `/resources/assets/js/` | `/public/js/all.js` |
| CoffeeScript | JavaScript | `coffee()` | `/resources/assets/coffee/` | `/public/js/app.js` |

> 使用不同的名称保存

可选地，每个方法都可以接受第二个参数，该参数将覆盖默认位置。要使用不同的目录（在本例中是一个名为`app`的目录），只需将该目录作为第二个参数添加：

```php
mix.scripts(null,'public/app/js').styles(null,'public/app/css');
```

在这个例子中，文件将保存在`public/app/js`和`public/app/css`。

## 把所有东西放在一起

最后，让我们把所有东西放在一起得出一个有趣的结论。由于 CoffeeScript 脚本和`less`和`sass`文件不是合并而是直接复制到目标中，我们首先将 CoffeeScript、`less`和`sass`文件保存到 Elixir 期望 JavaScript 和 CSS 文件的目录中。然后，我们指示 Elixir 将所有 JavaScript 和 CSS 文件合并和压缩成两个合并和压缩的文件。代码如下：

```php
elixir(function(mix) {
    mix.coffee(null,'resources/assets/js')
        .sass(null,'resources/assets/css')
        .less(null,'resources/assets/css')
        .scripts()
        .styles();
});
```

### 提示

非常重要的一点是，Elixir 会覆盖文件而不验证文件是否存在，因此需要为每个文件选择一个唯一的名称。命令完成后，`all.js`和`all.css`将合并和压缩在`public/js`和`public/css`目录中。

# 使用 Elixir 运行测试

除了编译和发送通知之外，Elixir 还可以用于自动化测试的启动。接下来的部分将讨论 Elixir 如何用于 PHPSpec 和 PHPUnit。

## PHPSpec

第一步是运行 PHPSpec 测试以自动化代码测试。通过将`phpSpec()`添加到我们的`gulpfile.js`中，PHPSpec 测试将运行：

```php
elixir(function(mix) {
    mix.less('app.less').phpSpec();
});
```

以下截图显示了输出。PHPSpec 输出被保留，因此测试输出非常有用：

![PHPSpec](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-lrv/img/B04559_10_03.jpg)

当 PHPSpec 测试失败时，结果很容易阅读：

![PHPSpec](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-lrv/img/B04559_10_04.jpg)

Laravel Elixir 输出的截图

在这个例子中，phpspec 在**it creates a reservation test**一行遇到了错误，如前面的截图所示。

## PHPUnit

同样，我们可以通过将`phpUnit`添加到任务列表中来将 PHPUnit 添加到我们的测试套件中，如下所示：

```php
elixir(function(mix) {
    mix.less('app.less').phpSpec().phpUnit();
});
```

## 创建自定义任务

Elixir 使我们能够创建自定义任务来几乎做任何事情。我们可以编写一个扫描控制器注释的自定义任务的一个例子。所有自定义任务都需要`gulp`和`laravel-elixir`。重要的是要记住所使用的编程语言是 JavaScript，因此语法可能或可能不熟悉，但很容易快速学习。如果命令将从命令行界面执行，那么我们还将导入 gulp-shell。代码如下：

```php
var gulp = require('gulp');
var elixir = require('laravel-elixir');
var shell = require('gulp-shell');

/*
 |----------------------------------------------------------------
 | Route Annotation Scanner
 |----------------------------------------------------------------
 |
 | We'll run route:scan Artisan to scan for changed files.
 | Output is written to storage/framework/routes.scanned.php
 | 
*/

 elixir.extend('routeScanning', function() {
                 gulp.task('routeScanning', function() {
                         return gulp.src('').
      pipe(shell('php artisan route:scan'));
                 });

     return this.queueTask('routeScanning');
 });
```

在这段代码中，我们首先扩展 Elixir 并给方法一个名称，例如`routeScanning`。然后，定义了一个 gulp 任务，`task`方法的第一个参数是命令的名称。第二个命令是包含将被执行和返回的代码的闭包。

最后，通过将命令的名称传递给`queueTask`方法，将任务排队执行。

将此脚本添加到我们的链中，如下所示：

```php
elixir(function(mix) {
    mix.routeScanning();
});
```

输出将如下所示：

```php
**$ gulp**
**[23:24:19] Using gulpfile /var/www/laravel.example/gulpfile.js**
**[23:24:19] Starting 'default'...**
**[23:24:19] Starting 'routeScanning'...**
**[23:24:19] Finished 'default' after 12 ms**
**[23:24:20] Finished 'routeScanning' after 1 s**

```

由于`pipe`函数允许命令链接，很容易添加一个通知，以警报通知系统，如下所示：

```php
var gulp = require('gulp');
var elixir = require('laravel-elixir');
var shell = require('gulp-shell');
var Notification = require('./commands/Notification');

 elixir.extend('routeScanning', function() {
                 gulp.task('routeScanning', function() {
                         return gulp.src('').
                             pipe(shell('php artisan route:scan')).
                             pipe(new Notification().message('Annotations scanned.'));
                 });
     return this.queueTask('routeScanning');

 });
```

在这里，`Notification`类被引入，并创建了一个新的通知，以将消息`Annotations scanned.`发送到通知系统。

运行代码会产生以下输出。请注意，已添加了`gulp-notify`：

```php
**$ gulp**
**[23:46:59] Using gulpfile /var/www/laravel.example/gulpfile.js**
**[23:46:59] Starting 'default'...**
**[23:46:59] Starting 'routeScanning'...**
**[23:46:59] Finished 'default' after 38 ms**
**PHP Warning:  Module 'xdebug' already loaded in Unknown on line 0**
**Routes scanned!**
**[23:47:00] gulp-notify: [Laravel Elixir] Annotations scanned**
**[23:47:00] Finished 'routeScanning' after 1.36 s**

```

# 设置文件监视器

显然，每次我们想要编译层叠样式表或扫描注释时运行 gulp 是很繁琐的。幸运的是，Elixir 内置了一个监视机制。要调用它，只需运行以下命令：

```php
**$ gulp watch**

```

这将允许将任务自动运行到`gulpfile.js`链中的任何任务在发生某些更改时。启用此功能的必要代码在注释任务中如下：

```php
 this.registerWatcher("routeScanning", "app/Http/Controllers/**/*.php");
```

上面的代码注册了一个监视器。第一个参数是`routeScanning`任务。第二个命令是将被监视以进行修改的目录模式。

由于我们知道路由注释将在控制器内部，我们可以设置路径仅在`app/Http/Controllers/`目录内查找。正则表达式样式语法将匹配位于控制器下的任何一个目录中具有`php`扩展名的文件。

现在，每当修改与模式匹配的文件时，`routeScanning`任务以及任何其他监视匹配相同模式的文件的任务都将被执行。

# 额外的 Laravel Elixir 任务

npm 网站提供了超过 75 个任务，涉及测试、JavaScript、CSS 等。`npm`网站位于[`npmjs.com`](http://npmjs.com)。

![额外的 Laravel Elixir 任务](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-lrv/img/B04559_10_05.jpg)

npm 网站的截图包含了许多有用的 Laravel Elixir 任务

# 总结

在本章中，您了解了 Elixir 不断增长的任务列表如何帮助全栈开发人员以及开发团队。一些任务与前端开发相关，例如编译、合并和压缩 CSS 和 JavaScript。其他任务与后端开发相关，例如行为驱动开发。将这些任务集成到日常开发工作流程中，将使整个团队能够理解在持续集成服务器中执行的步骤，其中 Elixir 将执行其任务，例如测试和编译，以准备将文件从开发转换为生产。

由于 Elixir 是建立在 gulp 之上的，随着 gulp 和 Elixir 社区的持续增长和新的贡献者继续为 Elixir 做出贡献，Elixir 的未来将继续丰富。
