# Angular6 和 Laravel5  Web 全栈开发实用指南（三）

> 原文：[`zh.annas-archive.org/md5/b37ef01c0005efc4aa3cccbea6646556`](https://zh.annas-archive.org/md5/b37ef01c0005efc4aa3cccbea6646556)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：使用 Laravel 构建 RESTful API - 第 2 部分

在本章中，我们将继续构建我们的 API。在 Laravel 中，我们还有很长的路要走。

我们将学习如何使用一些在每个 Web 应用程序中非常常见的功能，例如身份验证和 API 错误的自定义。

请记住，我们正在创建一个 RESTful API，与传统的应用程序（如 MVC）不同，我们的错误模型非常多样化，并且始终在使用 JSON 格式时返回。

在本章中，您将学习如何通过以下方式构建一个坚实的 RESTful API：

+   处理请求验证和错误消息

+   使用基于令牌的身份验证

+   处理 Laravel 资源

# 处理请求验证和错误消息

Laravel 框架为我们提供了许多显示错误消息的方法，默认情况下，Laravel 的**基础控制器类**使用`ValidatesRequests`特性，提供了验证传入 HTTP 请求的方法，包括许多默认规则，如必填、电子邮件格式、日期格式、字符串等等。

您可以在[`laravel.com/docs/5.6/validation#available-validation-rules`](https://laravel.com/docs/5.6/validation#available-validation-rules)了解更多有关可能的验证规则的信息。

使用请求验证非常简单，如下面的代码块所示：

```php
$validatedData = $request->validate([
'field name' => 'validation rule, can be more than one',
'field name' => 'validation rule',
'field name' => 'validation rule',
...
]);
```

例如，让我们看看如何使用 HTTP `POST`方法验证对`localhost:8081/api/bikes`的`bikes`端点的传入请求。

验证代码如下所示：

```php
$validatedData = $request->validate([
'make' => 'required',
'model' => 'required',
'year'=> 'required',
'mods'=> 'required'
]);
```

之前的操作失败是因为我们故意没有在我们的虚构请求中发送所需的文件。然而，返回消息中有一些有趣的东西：

+   HTTP 状态码：`422`

+   以下 JSON 响应错误消息：

```php
{
    "message": "The given data was invalid.",
    "errors": {
    "": [
    "The field is required."
    ]}
}
```

相当简单，对吧？Laravel 在幕后执行所有验证，并给我们提供了详细的错误消息。

但是，如果我们想控制所有的消息字段怎么办？答案是，我们可以使用`validator`门面和验证器实例进行手动验证。这是我们接下来要看的内容。

# HTTP 状态码

在我们进一步实现验证之前，让我们暂停一下，回顾一些 HTTP 状态码。正如我们之前看到的，我们有一个名为**不可处理的实体**的 422 HTTP 状态码。

以下表格显示了最常见和有用的错误代码：

| 代码 | 名称 | 描述 |
| --- | --- | --- |
| 200 | 正常 | 一切都好！ |
| 201 | 已创建 | 资源创建成功。 |
| 202 | 已接受 | 请求已被接受进行进一步处理，稍后将完成。 |
| 204 | 正常 | 资源删除成功删除。 |
| 302 | 重定向 | 常见的重定向响应；您可以在位置响应标头中获取 URI 的表示。 |
| 304 | 未修改 | 没有新数据返回。 |
| 400 | 错误请求 | 客户端错误。 |
| 401 | 未经授权 | 您未登录，例如，您未使用有效的访问令牌。 |
| 403 | 禁止 | 您已经经过身份验证，但无权进行您正在尝试的操作。 |
| 404 | 未找到 | 您请求的资源不存在。 |
| 405 | 方法不允许 | 不允许该请求类型，例如，/bikes 是一个资源，POST /bikes 是一个有效操作，但 PUT /bikes 不是。 |
| 409 | 冲突 | 资源已经存在。 |
| 422 | 不可处理的实体 | 验证失败。请求和格式有效，但请求无法处理。例如，当发送的数据未通过验证测试时会发生这种情况。 |
| 500 | 服务器错误 | 服务器发生错误，而不是消费者的错误。 |

您可以在[`www.restapitutorial.com/httpstatuscodes.html`](http://www.restapitutorial.com/httpstatuscodes.html)了解更多有关状态码的信息。

# 实现控制器验证

好吧，我们已经学习了很多理论，现在是时候写一些代码了。让我们在 API 控制器上实现`Validator`：

1.  打开`project/app/Http/Controllers/API/BikeController.php`，并在`use App\Bike`语句之后添加以下代码：

```php
use Validator;
```

1.  现在，在`store(Request $request)`方法中添加以下代码：

```php
$validator = Validator::make($request->all(), [
    'make' => 'required',
    'model' => 'required',
    'year'=> 'required',
    'mods'=> 'required',
    'builder_id' => 'required'
]);
if ($validator->fails()) {
    return response()->json($validator->errors(), 422);
}
```

请注意，在上面的代码中，我们使用响应 JSON 格式，并将错误和状态代码设置为`json()`方法的参数。

1.  我们将使用相同的代码块从*步骤 2*中为`update(Request request,request,id)`方法做同样的操作。

1.  打开`project/app/Http/Controllers/API/BuilderController.php`，并在`use App\Builder`语句之后添加以下代码：

```php
use Validator;
```

1.  现在，在`store(Request $request)`方法中添加以下代码：

```php
$validator = Validator::make($request->all(), 
    ['name' => 'required',
    'description' => 'required',
    'location'=> 'required'
]);
if ($validator->fails()) {
    return response()->json($validator->errors(), 422);
}
```

1.  我们将使用相同的代码块从*步骤 5*中为`update(Request request,request,id)`方法做同样的操作。

1.  打开`project/app/Http/Controllers/API/ItemController.php`，并在`use App\Item`语句之后添加以下代码：

```php
use Validator;
```

1.  现在，在`store(Request $request)`方法中添加以下代码：

```php
$validator = Validator::make($request->all(), [
    'type' => 'required',
```

```php

    'name' => 'required',
    'company'=> 'required',
    'bike_id'=> 'required'
]);
if ($validator->fails()) {
    return response()->json($validator->errors(), 422);
}
```

1.  我们将使用相同的代码块从*步骤 7*中为`update(Request request,request,id)`方法做同样的操作。

所有验证样板代码都放在了`store()`和`update()`方法中，所以现在是时候编写一些错误处理程序了。

# 添加自定义错误处理

默认情况下，Laravel 具有非常强大的错误处理引擎，但它完全专注于 MVC 开发模式，正如我们之前提到的。在接下来的几行中，我们将看到如何改变这种默认行为，并为我们的 API 添加一些特定的错误处理：

1.  打开`project/app/Exceptions/Handler.php`，并在`render($request, Exception, $exception)`函数中添加以下代码：

```php
// This will replace our 404 response from the MVC to a JSON response.
if ($exception instanceof ModelNotFoundException
    && $request->wantsJson() // Enable header Accept:
     application/json to see the proper error msg
) {
    return response()->json(['error' => 'Resource not found'], 404);
}
if ($exception instanceof MethodNotAllowedHttpException) {
    return response()->json(['error' => 'Method Not Allowed'], 405);
}
if ($exception instanceof UnauthorizedHttpException) {
    return response()->json(['error' => 'Token not provided'], 401);
}
// JWT Auth related errors
if ($exception instanceof JWTException) {
    return response()->json(['error' => $exception], 500);
}
if ($exception instanceof TokenExpiredException) {
    return response()->json(['error' => 'token_expired'], 
    $exception->getStatusCode());
} else if ($exception instanceof TokenInvalidException) {
    return response()->json(['error' => 'token_invalid'],
     $exception->getStatusCode());
}
return parent::render($request, $exception);
```

在上面的代码中，除了映射我们的 API 的主要错误之外，我们还需要为涉及 JWT 身份验证的操作添加一些自定义错误。别担心，在下一节中，我们将看到如何使用 JWT 来保护我们 API 的一些路由。

1.  现在，让我们在文件顶部添加以下代码，放在`ExceptionHandler`导入之后：

```php
use Illuminate\Database\Eloquent\ModelNotFoundException as ModelNotFoundException;
use Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException as UnauthorizedHttpException;
use Tymon\JWTAuth\Exceptions\JWTException as JWTException;
use Tymon\JWTAuth\Exceptions\TokenExpiredException as TokenExpiredException;
use Tymon\JWTAuth\Exceptions\TokenInvalidException as TokenInvalidException;
```

现在，我们将能够看到正确的消息，而不是来自 Laravel 的默认错误页面。

请注意，我们保留了默认的 Laravel 错误页面，并添加了自定义处理。非常重要的是，我们发送`header: accept: application / json`。这样，Laravel 就可以确定应该以 JSON 格式发送响应，而不是发送标准的错误页面。

1.  让我们进行简短的测试，看看当我们尝试访问受保护的 URL 时会发生什么。打开终端窗口，输入以下代码：

```php
curl -X GET "http://localhost:8081/api/bikes/3" -H "accept: application/json" -H "X-CSRF-TOKEN: "
```

结果将是一个 JSON，内容如下：

```php
{"message":"Unauthenticated."}
```

1.  现在，让我们尝试另一个错误，看看当我们尝试发送 POST 方法时会发生什么。在终端中输入以下代码：

```php
curl -X POST "http://localhost:8081/api/bikes/3" -H "accept: application/json" -H "X-CSRF-TOKEN: "
```

结果将是一个 JSON，内容如下：

```php
{"error":"Method Not Allowed"}
```

# 使用 Swagger UI 检查 API URL

在所有这些样板代码之后，现在是测试 API 并看到我们在本章中所做的所有工作生效的时候了：

1.  打开终端，输入以下命令：

```php
php artisan l5-swagger:generate
```

不要忘记使用以下命令进入`php-fpm`容器的 bash：`docker-compose exec php-fpm bash`。

1.  打开默认浏览器，转到`http://localhost:8081/api/documentation`。

我们将看到所有 API 都被正确记录的以下结果：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/hsn-flstk-web-dev-ng6-lrv5/img/7df5634d-5005-4518-9754-bb97a17237a0.png)Swagger UI

让我们检查一些操作。

# 获取所有记录

让我们看看如何使用 Swagger UI 上的`GET`方法从我们的 API 中检索自行车列表：

1.  点击**GET /api/bikes**以打开面板。

1.  点击**试一下**按钮。

1.  点击**执行**按钮。

我们将看到类似以下截图的内容：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/hsn-flstk-web-dev-ng6-lrv5/img/bcb715fa-74f3-4f43-b281-f0b3c3966cc2.png)GET 请求

# 按 ID 获取记录

让我们看看如何从我们的 API 中获取自行车列表：

1.  点击**GET /api/bikes/{id}**以打开面板。

1.  点击**试一下**按钮。

1.  在 ID 输入框中输入`3`。

1.  点击**执行**按钮。

将看到类似以下截图的内容：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/hsn-flstk-web-dev-ng6-lrv5/img/bce94ec5-ce96-40c1-b928-4a5bbad8415c.png)按 ID 请求获取

# 检查 API 响应错误

现在，是时候检查一些错误消息了：

1.  单击**PUT /api/bikes/{id}**打开面板。

1.  单击**尝试**按钮。

1.  在 ID 输入框中输入`1`。

1.  用以下代码替换`示例值`占位符：

```php
{
 "make": "Yamaha",
 "model": "V-Star",
 "year": "2001",
 "mods": "New exhaust system and Grips",
 "picture": "http://www.sample.com/my.bike.jpg"
 }
```

1.  单击`执行`按钮。

我们将看到类似以下截图的内容：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/hsn-flstk-web-dev-ng6-lrv5/img/c7248c7c-5d4c-4ae5-9c88-a4f589167a28.png)更新失败，带有错误消息

正如我们所观察到的，一切都如预期的那样发生了。

# 基于令牌的身份验证

让我们更深入地了解使用 Laravel 进行 API 身份验证。尽管 Laravel 是一个 MVC 框架，但我们可以使用基于令牌的身份验证功能。即使 Laravel 本身也有一个名为 Passport 的库。

Laravel Passport 是一个与 OAuth2 标准配合使用的库。这种模式确定了通过令牌对 Web 应用程序（API）执行应用程序身份验证的方法，而 JWT 侧重于通过令牌对用户进行身份验证。

Laravel Passport 比简单的 JWT 更大的抽象层，它主要设计为完全成熟且易于设置和使用作为 OAuth2 服务器。

这种情况的替代方案是使用诸如`tymon/jwt-auth`之类的库。

实际上，Laravel Passport 使用 JWT 进行身份验证，但这只是一个实现细节。`tymon/jwt-auth`更接近于简单的基于令牌的身份验证，尽管它仍然非常强大和有用。

对于我们正在构建的 API 类型，JWT 是我们实现的理想方法。

您可以在[`github.com/tymondesigns/jwt-auth`](https://github.com/tymondesigns/jwt-auth)上阅读有关`jwt-auth`的更多信息。

# 安装 tymon-jwt-auth

让我们学习如何安装和配置`tymon/jwt-auth`。

安装过程非常简单，但是由于`tymon/jwt-auth`库在不断发展，我们应该注意我们将使用的版本：

1.  打开`project/composer.json`文件，并在`Laravel/Tinker`之后添加以下行代码：

```php
"tymon/jwt-auth": "1.0.*"
```

1.  现在，是时候发布供应商包了。仍然在您的终端窗口和 Tinker 控制台中，输入以下命令：

```php
php artisan vendor:publish --provider="Tymon\JWTAuth\Providers\LaravelServiceProvider"
```

请注意，我们正在使用 Laravel 5.6 和`jwt-auth` 1.0，因此我们不需要执行任何额外的操作来加载 JWT 提供程序。`jwt-auth`文档有时看起来很混乱，非常令人困惑，但不要担心，只需按照我们的步骤进行操作，您就不会受到不匹配的文档的影响。

1.  让我们生成密钥。仍然在终端窗口中，输入以下命令：

```php
 php artisan jwt:secret
```

1.  上一个命令将在您的`.env`文件中生成一个密钥，并且看起来类似以下行：

```php
JWT_SECRET=McR1It4Bw9G8jU1b4XJhDMeZs4Q5Zwear
```

到目前为止，我们已经成功安装了`jwt-auth`，但是我们需要采取一些额外的步骤来使我们的 API 安全。

# 更新用户模型

现在，我们需要更新`User`模型，以便我们可以开始使用用户身份验证来保护 API 端点。

首先，我们需要在我们的`User`模型上实现`Tymon\JWTAuth\Contracts\JWTSubject`合同，这需要两种方法：`getJWTIdentifier()`和`getJWTCustomClaims()`。

打开`project/User.php`并用以下代码替换其内容：

```php
 <?php
 namespace  App;
 use  Illuminate\Notifications\Notifiable;
 use  Illuminate\Foundation\Auth\User  as  Authenticatable;
 use  Tymon\JWTAuth\Contracts\JWTSubject;
 /**
 * @SWG\Definition(
 * definition="User",
 * required={"name", "email", "password"},
 * @SWG\Property(
 * property="name",
 * type="string",
 * description="User name",
 * example="John Conor"
 * ),
 * @SWG\Property(
 * property="email",
 * type="string",
 * description="Email Address",
 * example="john.conor@terminator.com"
 * ),
 * @SWG\Property(
 * property="password",
 * type="string",
 * description="A very secure password",
 * example="123456"
 * ),
 * )
 */
 class  User  extends  Authenticatable  implements  JWTSubject
 {
     use  Notifiable;
     /**
     * The attributes that are mass assignable.
     *
     * @var array
     */
     protected  $fillable = [
         'name', 'email', 'password',
     ];
     /**
     * The attributes that should be hidden for arrays.
     *
     * @var array
     */
     protected  $hidden = [
         'password', 'remember_token',
     ];
     /**
     * Get JSON WEB TOKEN methods.
     *
     * @var array
     */
     public  function  getJWTIdentifier()
     {
         return  $this->getKey();
     } 
     public  function  getJWTCustomClaims()
     {
         return [];
     }  
     /**
     * Relationship.
     *
     * @var string
     */   
     public  function  bikes()
     {
         return  $this->hasMany(App\Bike);
     }
 }
```

# 设置身份验证守卫

现在，让我们对`config.auth.php`文件进行一些调整，以保护一些路由：

1.  打开`project/config/auth.php`并用以下代码替换 API 驱动程序：

```php
 'defaults' => [         'guard'  =>  'api',
        'passwords'  =>  'users',
 ],
 'guards'  => [
                'web'  => [
                        'driver'  =>  'session',
                        'provider'  =>  'users',
        ],        
 'api'  => [
                'driver'  =>  'jwt',
                'provider'  =>  'users',
        ],
 ],
```

1.  请注意，我们用`api`和`jwt`替换了默认的 Laravel 身份验证驱动程序。

# 创建 authController

对于我们的应用程序，我们将只使用一个控制器来包含我们的所有注册和登录操作，即注册，登录和注销。

在本书的后面，您将了解为什么我们在一个控制器中使用所有操作，而不是为每个操作创建一个控制器：

1.  打开您的终端窗口并输入以下命令：

```php
php artisan make:controller API/AuthController
```

1.  打开`project/app/Http/Controllers/API/AuthController.php`并用以下代码替换其内容：

```php
 <?php
 namespace  App\Http\Controllers\API;
 use  Illuminate\Http\Request;
 use  App\Http\Controllers\Controller;
 use  App\User;
 use  Validator;
 class  AuthController  extends  Controller
 {
     /**
     * Register a new user.
     *
     * @param \Illuminate\Http\Request $request
     * @return \Illuminate\Http\Response
     *
     * @SWG\Post(
     * path="/api/register",
     * tags={"Users"},
     * summary="Create new User",
     * @SWG\Parameter(
     * name="body",
     * in="body",
     * required=true,
     * @SWG\Schema(ref="#/definitions/User"),
     * description="Json format",
     * ),
     * @SWG\Response(
     * response=201,
     * description="Success: A Newly Created User",
     * @SWG\Schema(ref="#/definitions/User")
     * ),
     * @SWG\Response(
     * response=200,
     * description="Success: operation Successfully"
     * ),
     * @SWG\Response(
     * response=401,
     * description="Refused: Unauthenticated"
     * ),
    * @SWG\Response(
    * response="422",
    * description="Missing mandatory field"
    * ),
    * @SWG\Response(
    * response="404",
    * description="Not Found"
    * )
    * ),
    */
    public  function  register(Request  $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|string|email|max:255|unique:users',
            'name' => 'required',
            'password'=> 'required'
        ]);
        if ($validator->fails()) {
            return  response()->json($validator->errors(), 422);
            }
        $user = User::create([
        'name' => $request->name,
        'email' => $request->email,
        'password' => bcrypt($request->password),
        ]);
        $token = auth()->login($user);
        return  response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => auth()->factory()->getTTL() * 60
            ], 201);
        }
    /**
    * Log in a user.
    *
    * @param \Illuminate\Http\Request $request
    * @return \Illuminate\Http\Response
    *
    * @SWG\Post(
    * path="/api/login",
    * tags={"Users"},
    * summary="loggin an user",
    * @SWG\Parameter(
    * name="body",
    * in="body",
    * required=true,
    * @SWG\Schema(ref="#/definitions/User"),
    * description="Json format",
    * ),
    * @SWG\Response(
    * response=200,
    * description="Success: operation Successfully"
    * ),
    * @SWG\Response(
    * response=401,
    * description="Refused: Unauthenticated"
    * ),
    * @SWG\Response(
    * response="422",
    * description="Missing mandatory field"
    * ),
    * @SWG\Response(
    * response="404",
    * description="Not Found"
    * )
    * ),
    */
    public  function  login(Request  $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|string|email|max:255',
            'password'=> 'required'
        ]);
        if ($validator->fails()) {
            return  response()->json($validator->errors(), 422);
            }
        $credentials = $request->only(['email', 'password']);
        if (!$token = auth()->attempt($credentials)) {
            return  response()->json(['error' => 'Invalid
             Credentials'], 400);
        }
        $current_user = $request->email;
            return  response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'current_user' => $current_user,
            'expires_in' => auth()->factory()->getTTL() * 60
            ], 200);
            }
    /**
    * Register a new user.
    *
    * @param \Illuminate\Http\Request $request
    * @return \Illuminate\Http\Response
    *
    * @SWG\Post(
    * path="/api/logout",
    * tags={"Users"},
    * summary="logout an user",
    * @SWG\Parameter(
    * name="body",
    * in="body",
    * required=true,
    * @SWG\Schema(ref="#/definitions/User"),
    * description="Json format",
    * ),
    * @SWG\Response(
    * response=200,
    * description="Success: operation Successfully"
    * ),
    * @SWG\Response(
    * response=401,
    * description="Refused: Unauthenticated"
    * ),
    * @SWG\Response(
    * response="422",
    * description="Missing mandatory field"
    * ),
    * @SWG\Response(
    * response="404",
    * description="Not Found"
    * ),
    * @SWG\Response(
    * response="405",
    * description="Invalid input"
    * ),
    * security={
    * { "api_key":{} }
    * }
    * ),
    */
    public  function  logout(Request  $request){
        auth()->logout(true); // Force token to blacklist
        return  response()->json(['success' => 'Logged out
         Successfully.'], 200); }
}
```

在前面的代码中几乎没有什么新的内容——我们只是在`register`、`login`和`logout`函数中返回了 JSON 响应，正如我们在前面的行中所看到的。

1.  在`register()`函数中：

```php
 $token = auth()->login($user);
        return  response()->json([
                'access_token' => $token,
                'token_type' => 'bearer',
                'expires_in' => auth()->factory()->getTTL() * 60
 ], 201);
```

创建`user`后，我们返回了`201`的 HTTP 状态代码，带有`access_token`和到期日期。

1.  在`login()`函数中：

```php
 $current_user = $request->email;
        return  response()->json([
                'access_token' => $token,
                'token_type' => 'bearer',
                'current_user' => $current_user,
                'expires_in' => auth()->factory()->getTTL() * 60
 ], 200);
```

在`login()`函数中，我们根据用户的电子邮件地址返回了当前用户，一个`access_token`和到期日期。

1.  在`logout()`函数中：

```php
auth()->logout(true); // Force token to blacklist
    return  response()->json(['success' => 'Logged out
     Successfully.'], 200);
```

请注意，`logout()`函数中的`true`参数告诉`jwt-auth`永久使令牌无效。

# 创建用户路由

现在，是时候为注册、登录和注销操作创建新路由，并在我们的 API 中保护一些路由，就像本章开头讨论的那样。我们的用户可以与应用程序的部分内容进行交互，但是要访问其所有内容，必须创建用户并登录到应用程序。

打开`project/routes/api.php`并用以下代码替换其内容：

```php
 <?php
 use  Illuminate\Http\Request;
 use  App\Bike;
 use  App\Http\Resources\BikesResource;

 /*
 |--------------------------------------------------------------------------
 | API Routes
 |--------------------------------------------------------------------------
 |
 | Here is where you can register API routes for your application. These
 | routes are loaded by the RouteServiceProvider within a group whic
 | is assigned the "api" middleware group. Enjoy building your API!
 |
 */

 // Register Routes
 Route::post('register', 'API\AuthController@register');
 Route::post('login', 'API\AuthController@login');
 Route::post('logout', 'API\AuthController@logout');

 Route::apiResources([

     'bikes' => 'API\BikeController',

     'builders' => 'API\BuilderController',

     'items' => 'API\ItemController',

     'bikes/{bike}/ratings' => 'API\RatingController'

 ]);

Route::middleware('jwt.auth')->get('me', function(Request $request){
    return auth()->user();
});
```

最后一步是保护端点；我们在`project/routes/api.php`文件中或直接在控制器函数中执行此操作。我们将在控制器函数中执行此操作。

# 保护 API 路由

使用应用程序控制器保护我们的路由非常简单。我们只需要编辑`Controller`文件并添加以下代码。

打开`project/Http/Controllers/API/BikeController.php`并在`GET`方法之前添加以下代码：

```php
 /**
 * Protect update and delete methods, only for authenticated users.
 *
 * @return Unauthorized
 */
 public  function  __construct()
 {
        $this->middleware('auth:api')->except(['index']);
 }
```

前面的代码意味着我们正在使用`auth:api`中间件来保护所有骑手路由，除了`index()`方法。因此，我们的用户可以查看自行车列表，但是要查看自行车的详细信息并发布自行车，他们必须登录。稍后，在第九章，*创建服务和用户身份验证*，在 Angular 中，我们将详细讨论基于令牌的身份验证。

# 创建和登录用户

现在，是时候检查用户路由了。由于我们没有用户界面，我们将使用一个名为 Restlet Client 的 Chrome 扩展。它是免费且非常强大。

您可以在[`restlet.com/modules/client`](https://restlet.com/modules/client)了解更多信息并下载它：

1.  打开 Restlet 扩展并填写以下字段，如下屏幕截图所示：

注册端点

1.  结果将是以下响应：

创建响应

1.  现在，让我们使用新创建的用户登录。填写如下屏幕截图中显示的字段：

用户登录

结果将是以下响应：

用户登录响应

好了，我们的 API 身份验证已经准备就绪。稍后，在第九章，*创建服务和用户身份验证*，在 Angular 中，我们将详细讨论身份验证过程。

# 处理 Laravel 资源

在以前的一些 Laravel 版本中，可以使用一个名为 Fractal 的功能来处理 JSON web API，但是在这个新版本的 Laravel 中，我们有**资源**功能，这是一个处理 JSON web API 的非常强大的工具。

在这一部分，我们将看到如何使用资源功能，以便我们可以充分利用我们的 API。资源类是一种将数据从一种格式转换为另一种格式的方法。

在处理资源并将其转换为客户端响应时，我们基本上有两种类型：项目和集合。项目资源，正如你可能已经猜到的那样，基本上是我们模型的一对一表示，而集合是许多项目的表示。集合还可以具有元数据和其他导航信息，我们将在本节后面看到。

# 创建 BikesResource

因此，让我们创建我们的第一个资源：

1.  打开您的终端窗口，输入以下命令：

```php
php artisan make:resource BikesResource
```

上一个命令将生成以下文件：

`App\Http\Resource\BikesResource.php`。

1.  打开`App\Http\Resource\BikesResource.php`并添加以下代码：

```php
<?php
namespace App\Http\Resources;
use Illuminate\Http\Resources\Json\JsonResource;
use App\Builder;
class BikesResource extends JsonResource
{
    /**
    * Transform the resource into an array.
    *
    * @param \Illuminate\Http\Request $request
    * @return array
    */
    public function toArray($request)
    {
        return [
            'id' => $this->id,
            'make' => $this->make,
            'model' => $this->model,
            'year' => $this->year,
            'mods' => $this->mods,
            'picture' => $this->picture,
            'garages' => $this->garages,
            'items' => $this->items,
            'builder' => $this->builder,
            'user' => $this->user,
            'ratings' => $this->ratings,
            'average_rating' => $this->ratings->avg('rating'),
            // Casting objects to string, to avoid receive create_at             and update_at as object
            'created_at' => (string) $this->created_at,
            'updated_at' => (string) $this->updated_at
        ];
    }
}
```

请注意，我们在数组函数中包含了`bike`模型的所有关系。

# 创建 BuildersResource

现在，让我们使用`make`命令创建`BuildersResource`：

1.  打开您的终端窗口，输入以下命令：

```php
php artisan make:resource BuildersResource
```

1.  上一个命令将生成以下文件：

`App\Http\Resource\BuildersResource.php`。

1.  打开`App\Http\Resource\BuildersResource.php`并添加以下代码：

```php
<?php
namespace App\Http\Resources;
use Illuminate\Http\Resources\Json\JsonResource;
class BuildersResource extends JsonResource
{
    /**
    * Transform the resource into an array.
    *
    * @param \Illuminate\Http\Request $request
    * @return array
    */
    public function toArray($request)
    {
        return [
            'id' => $this->id,
            'name' => $this->name,
            'description' => $this->description,
            'location' => $this->location,
            'bike' => $this->bike,
            // Casting objects to string, to avoid receive create_at             and update_at as object
            'created_at' => (string) $this->created_at,
            'updated_at' => (string) $this->updated_at,
        ];
    }
}
```

# 创建 ItemsResource

现在，让我们使用`make`命令创建`ItemsResource`：

1.  打开您的终端窗口，输入以下命令：

```php
php artisan make:resource ItemsResource
```

1.  上一个命令将生成以下文件：

`App\Http\Resource\ItemsResource.php`。

1.  打开`App\Http\Resource\ItemsResource.php`并添加以下代码：

```php
<?php
namespace App\Http\Resources;
use Illuminate\Http\Resources\Json\JsonResource;
class ItemsResource extends JsonResource
{
    /**
    * Transform the resource into an array.
    *
    * @param \Illuminate\Http\Request $request
    * @return array
    */
    public function toArray($request)
    {
        return [
            'id' => $this->id,
            'type' => $this->type,
            'name' => $this->name,
            'company' => $this->company,
            'bike_id' => $this->bike_id,
            // Casting objects to string, to avoid receive create_at             and update_at as object
            'created_at' => (string) $this->created_at,
            'updated_at' => (string) $this->updated_at
        ];
    }
}
```

# 创建 ratingResource

现在，让我们创建一个新的`Resource`，这次是为了评分：

1.  打开您的终端窗口，输入以下命令：

```php
php artisan make:resource ratingResource
```

1.  上一个命令将生成以下文件：

`App\Http\Resource\RatingResource.php`。

1.  打开`App\Http\Resource\RatingResource.php`并添加以下代码：

```php
<?php
namespace App\Http\Resources;
use Illuminate\Http\Resources\Json\JsonResource;
use App\Bike;
class RatingResource extends JsonResource
{
    /**
    * Transform the resource into an array.
    *
    * @param \Illuminate\Http\Request $request
    * @return array
    */
    public function toArray($request)
    {
        return [
            'user_id' => $this->user_id,
            'bike_id' => $this->bike_id,
            'rating' => $this->rating,
            'bike' => $this->bike,
            'average_rating' => $this->bike->ratings->avg('rating'),
            // Casting objects to string, to avoid receive 
```

```php
             create_at and update_at as object
             'created_at' => (string) $this->created_at,
             'updated_at' => (string) $this->updated_at
         ];
     }
}
```

# 将资源添加到控制器

现在，我们需要对我们的控制器进行一些微小的更改，以便使用我们刚刚创建的资源。为了避免任何错误，我们将查看所有控制器的代码：

1.  通过用以下代码替换`App/Http/Controllers/API/BikeController.php`中的内容来编辑`Bike`控制器：

```php
<?php
namespace App\Http\Controllers\API;
use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use App\Bike;
use Validator;
use App\Http\Resources\BikesResource;
class BikeController extends Controller
{
    /**
    * Protect update and delete methods, only for authenticated
     users.
    *
    * @return Unauthorized
    */
    public function __construct()
    {
        $this->middleware('auth:api')->except(['index']);
    }
    /**
    * Display a listing of the resource.
    *
    * @return \Illuminate\Http\Response
    *
    * @SWG\Get(
    * path="/api/bikes",
    * tags={"Bikes"},
    * summary="List Bikes",
    * @SWG\Response(
    * response=200,
    * description="Success: List all Bikes",
    * @SWG\Schema(ref="#/definitions/Bike")
    * ),
    * @SWG\Response(
    * response="404",
    * description="Not Found"
    * ),
    * @SWG\Response(
    *          response="405",
    *          description="Invalid HTTP Method"
    * )
    * ),
    */
    public function index()
    {
        $listBikes = Bike::all();
        return $listBikes;
        // Using Paginate method We explain this later in the book
        // return BikesResource::collection(Bike::with('ratings')-
        >paginate(10));
    }
```

现在，让我们为`store`/`create`方法添加代码。在`index()`函数之后添加以下代码：

```php
/**
* Store a newly created resource in storage.
*
* @param \Illuminate\Http\Request $request
* @return \Illuminate\Http\Response
*
* @SWG\Post(
* path="/api/bikes",
* tags={"Bikes"},
* summary="Create Bike",
* @SWG\Parameter(
*          name="body",
*          in="body",
*          required=true,
*          @SWG\Schema(ref="#/definitions/Bike"),
*          description="Json format",
*      ),
* @SWG\Response(
* response=201,
* description="Success: A Newly Created Bike",
* @SWG\Schema(ref="#/definitions/Bike")
```

```php

* ),
* @SWG\Response(
* response=401,
* description="Refused: Unauthenticated"
* ),
* @SWG\Response(
* response="422",
* description="Missing mandatory field"
* ),
* @SWG\Response(
* response="404",
* description="Not Found"
* ),
* @SWG\Response(
     *          response="405",
     *          description="Invalid HTTP Method"
     * ),
     * security={
     *       { "api_key":{} }
     *      }
* ),
*/
public function store(Request $request)
{
    $validator = Validator::make($request->all(), [
        'make' => 'required',
        'model' => 'required',
        'year'=> 'required',
        'mods'=> 'required',
        'builder_id' => 'required'
        ]);
    if ($validator->fails()) {
        return response()->json($validator->errors(), 422);
    }
    // Creating a record in a different way
    $createBike = Bike::create([
        'user_id' => $request->user()->id,
        'make' => $request->make,
        'model' => $request->model,
        'year' => $request->year,
        'mods' => $request->mods,
        'picture' => $request->picture,
    ]);
    return new BikesResource($createBike);
}
```

为`Get` by `id`方法添加以下代码。在`store()`函数之后添加以下代码：

```php
/**
* Display the specified resource.
*
* @param int $id
* @return \Illuminate\Http\Response
*
* @SWG\Get(
* path="/api/bikes/{id}",
* tags={"Bikes"},
* summary="Get Bike by Id",
* @SWG\Parameter(
* name="id",
* in="path",
* required=true,
* type="integer",
* description="Display the specified bike by id.",
*      ),
* @SWG\Response(
* response=200,
* description="Success: Return the Bike",
* @SWG\Schema(ref="#/definitions/Bike")
* ),
* @SWG\Response(
* response="404",
* description="Not Found"
* ),
* @SWG\Response(
     *          response="405",
     *          description="Invalid HTTP Method"
     * ),
* security={
*       { "api_key":{} }
*   }
* ),
*/
public function show(Bike $bike)
{
    return new BikesResource($bike);
}
```

现在，让我们为`update`方法添加代码。在`show()`函数之后添加以下代码：

```php
/**
* Update the specified resource in storage.
*
* @param \Illuminate\Http\Request $request
* @param int $id
* @return \Illuminate\Http\Response
*
* @SWG\Put(
* path="/api/bikes/{id}",
* tags={"Bikes"},* summary="Update Bike",
* @SWG\Parameter(
* name="id",
* in="path",
* required=true,
* type="integer",
* description="Update the specified bike by id.",
*      ),
* @SWG\Parameter(
*          name="body",
*          in="body",
*          required=true,
*          @SWG\Schema(ref="#/definitions/Bike"),
*          description="Json format",
*      ),
* @SWG\Response(
* response=200,
* description="Success: Return the Bike updated",
* @SWG\Schema(ref="#/definitions/Bike")
* ),
* @SWG\Response(
* response="422",
* description="Missing mandatory field"
* ),
* @SWG\Response(
* response="404",
* description="Not Found"
* ),
* @SWG\Response(
     *          response="403",
     *          description="Forbidden"
     * ),
```

```php

* @SWG\Response(
     *          response="405",
     *          description="Invalid HTTP Method"
     * ),
     * security={
     *       { "api_key":{} }
     *      }
* ),
*/
public function update(Request $request, Bike $bike)
{
    // check if currently authenticated user is the bike owner
    if ($request->user()->id !== $bike->user_id) {
        return response()->json(['error' => 'You can only edit your
         own bike.'], 403);
    }
        $bike->update($request->only(['make', 'model', 'year',
         'mods',     'picture']));
    return new BikesResource($bike);
}
```

最后一个方法是删除所有记录。在`update()`函数之后添加以下代码：

```php
/**
* Remove the specified resource from storage.
*
* @param int $id
* @return \Illuminate\Http\Response
*
* @SWG\Delete(
* path="/api/bikes/{id}",
* tags={"Bikes"},
* summary="Delete bike",
* description="Delete the specified bike by id",
* @SWG\Parameter(
* description="Bike id to delete",
* in="path",
* name="id",
* required=true,
* type="integer",
* format="int64"
* ),
* @SWG\Response(
* response=404,
* description="Not found"
* ),
* @SWG\Response(
* response=204,
* description="Success: successful deleted"
* ),
* @SWG\Response(
     *          response="405",
     *          description="Invalid HTTP Method"
     * ),
     * security={
     *       { "api_key":{} }
     *      }
* )
*/
public function destroy($id)
{
    $deleteBikeById = Bike::findOrFail($id)->delete();
    return response()->json([], 204);
    }
}
```

然后我们将为`Builders`控制器做同样的事情。

1.  通过用以下代码替换`App/Http/Controllers/API/BuilderController.php`中的内容来编辑`Builder`控制器：

```php
<?php
namespace App\Http\Controllers\API;
use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use App\Builder;
use Validator;
use App\Http\Resources\BuildersResource;
class BuilderController extends Controller
{
    /**
    * Display a listing of the resource.
    *
    * @return \Illuminate\Http\Response
    *
    * @SWG\Get(
    * path="/api/builders",
    * tags={"Builders"},
    * summary="List Builders",
    * @SWG\Response(
    * response=200,
    * description="Success: List all Builders",
    * @SWG\Schema(ref="#/definitions/Builder")
    * ),
    * @SWG\Response(
    * response="404",
    * description="Not Found"
    * )
    * ),
    */
    public function index()
    {
        $listBuilder = Builder::all();
        return $listBuilder;
    }
```

现在，让我们为`store`/`create`方法添加代码。在`index()`函数之后添加以下代码：

```php
/**
* Store a newly created resource in storage.
*
* @param \Illuminate\Http\Request $request
* @return \Illuminate\Http\Response
*
* @SWG\Post(
* path="/api/builders",
* tags={"Builders"},
* summary="Create Builder",
* @SWG\Parameter(
*          name="body",
*          in="body",
*          required=true,
*          @SWG\Schema(ref="#/definitions/Builder"),
*          description="Json format",
*      ),
* @SWG\Response(
* response=201,
* description="Success: A Newly Created Builder",
* @SWG\Schema(ref="#/definitions/Builder")
* ),
* @SWG\Response(
* response="422",
* description="Missing mandatory field"
* ),
* @SWG\Response(
* response="404",
* description="Not Found"
* ),
* @SWG\Response(
     *          response="405",
     *          description="Invalid HTTP Method"
     * )
* ),
*/
public function store(Request $request)
{
    $validator = Validator::make($request->all(), [
        'name' => 'required',
        'description' => 'required',
        'location'=> 'required'
        ]);
    if ($validator->fails()) {
        return response()->json($validator->errors(), 422);
    }
    $createBuilder = Builder::create($request->all());
        return $createBuilder;
 }
```

让我们为`Get` by `id`方法添加代码。在`store()`函数之后添加以下代码：

```php
/**
* Display the specified resource.
*
* @param int $id
* @return \Illuminate\Http\Response
*
* @SWG\Get(
* path="/api/builders/{id}",
* tags={"Builders"},
* summary="Get Builder by Id",
* @SWG\Parameter(
* name="id",
* in="path",
* required=true,
* type="integer",
* description="Display the specified Builder by id.",
*      ),
* @SWG\Response(
* response=200,
* description="Success: Return the Builder",
* @SWG\Schema(ref="#/definitions/Builder")
* ),
* @SWG\Response(
* response="404",
* description="Not Found"
* ),
* @SWG\Response(
     *          response="405",
     *          description="Invalid HTTP Method"
     * )
* ),
*/
public function show(Builder $builder)
{
    // $showBuilderById = Builder::with('Bike')->findOrFail($id);
    // return $showBuilderById;
    return new BuildersResource($builder);
}
```

现在，让我们添加`update`方法的代码。在`show()`函数之后添加以下代码：

```php
/**
* Update the specified resource in storage.
*
* @param \Illuminate\Http\Request $request
* @param int $id
* @return \Illuminate\Http\Response
*
* @SWG\Put(
* path="/api/builders/{id}",
* tags={"Builders"},
* summary="Update Builder",
* @SWG\Parameter(
* name="id",
* in="path",
* required=true,
* type="integer",
* description="Update the specified Builder by id.",
*      ),
* @SWG\Parameter(
*          name="body",
*          in="body",
*          required=true,
*          @SWG\Schema(ref="#/definitions/Builder"),
*          description="Json format",
*      ),
* @SWG\Response(
* response=200,
* description="Success: Return the Builder updated",
* @SWG\Schema(ref="#/definitions/Builder")
* ),
* @SWG\Response(
* response="422",
* description="Missing mandatory field"
* ),
* @SWG\Response(
* response="404",
* description="Not Found"
* ),
* @SWG\Response(
     *          response="405",
     *          description="Invalid HTTP Method"
     * )
* ),
*/
public function update(Request $request, $id)
{
    $validator = Validator::make($request->all(), [
        'name' => 'required',
        'description' => 'required',
        'location'=> 'required'
        ]);
    if ($validator->fails()) {
        return response()->json($validator->errors(), 422);
    }
    $updateBuilderById = Builder::findOrFail($id);
    $updateBuilderById->update($request->all());
    return $updateBuilderById;
}
```

最后一个方法用于删除所有记录。在`update()`函数之后添加以下代码：

```php
/**
* Remove the specified resource from storage.
*
* @param int $id
* @return \Illuminate\Http\Response
*
* @SWG\Delete(
* path="/api/builders/{id}",
* tags={"Builders"},
* summary="Delete Builder",
* description="Delete the specified Builder by id",
* @SWG\Parameter(
* description="Builder id to delete",
* in="path",
* name="id",
* required=true,
* type="integer",
* format="int64"
* ),
* @SWG\Response(
* response=404,
* description="Not found"
* ),
* @SWG\Response(
     *          response="405",
     *          description="Invalid HTTP Method"
     * ),
* @SWG\Response(
* response=204,
* description="Success: successful deleted"
* ),
* )
*/
public function destroy($id)
{
    $deleteBikeById = Bike::find($id)->delete();
    return response()->json([], 204);
    }
}
```

1.  为了编辑`Rating`控制器，用以下代码替换`App/Http/Controllers/API/RatingController.php`中的内容：

```php
<?php
namespace App\Http\Controllers\API;
use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use App\Bike;
use App\Rating;
use App\Http\Resources\RatingResource;
class RatingController extends Controller
{
    /**
    * Protect update and delete methods, only for authenticated         users.
    *
    * @return Unauthorized
    */
    public function __construct()
    {
        $this->middleware('auth:api');
    }
    /**
    * Store a newly created resource in storage.
    *
    * @param \Illuminate\Http\Request $request
    * @return \Illuminate\Http\Response
    *
    * @SWG\Post(
    * path="/api/bikes/{bike_id}/ratings",
    * tags={"Ratings"},
    * summary="rating a Bike",
    * @SWG\Parameter(
    * in="path",
    * name="id",
    * required=true,
    * type="integer",
    * format="int64",
    *      description="Bike Id"
    *    ),
    * @SWG\Parameter(
    *      name="body",
    *      in="body",
    *      required=true,
    *      @SWG\Schema(ref="#/definitions/Rating"),
    *      description="Json format",
    *     ),
    * @SWG\Response(
    * response=201,
    * description="Success: A Newly Created Rating",
    * @SWG\Schema(ref="#/definitions/Rating")
    * ),
    * @SWG\Response(
    * response=401,
    * description="Refused: Unauthenticated"
    * ),
    * @SWG\Response(
    * response="422",
    * description="Missing mandatory field"
    * ),
    * @SWG\Response(
    * response="404",
    * description="Not Found"
    * ),
    * @SWG\Response(
       *     response="405",
       *   description="Invalid HTTP Method"
       * ),
    * security={
    *     { "api_key":{} }
    * }
    * ),
    */
    public function store(Request $request, Bike $bike)
    {
        $rating = Rating::firstOrCreate(
        [
        'user_id' => $request->user()->id,
        'bike_id' => $bike->id,
        ],
        ['rating' => $request->rating]
        );
        return new RatingResource($rating);
    }
}
```

干得好！现在，我们有必要的代码来继续进行 API JSON。在接下来的几章中，您将更详细地了解我们迄今为止所取得的成就。我们已经准备好了我们的 API。

# 总结

我们又完成了一章。我们学会了如何构建基于令牌的身份验证，如何仅保护已登录用户的端点，以及如何处理自定义错误消息。

我们还学会了如何使用 Laravel 资源返回 JSON API 格式。

我们正在进行中，但是我们需要构建所有的界面并实现 Angular 前端应用程序，以便我们的应用程序可以有一个愉快的视觉结果。

在下一章中，我们将看到如何将 Angular 以及一些更多的工具集成到我们的应用程序中。


# 第七章：使用 Angular CLI 构建渐进式 Web 应用程序

正如我们在第三章中提到的，*了解 Angular 6 的核心概念*，Angular 是基于 JavaScript 开发现代 Web 应用程序的主要框架之一。

在第六章中，*使用 Laravel 框架创建 RESTful API-2*，我们使用 Laravel 资源、eloquent 关系和基于令牌的身份验证完成了后端 API。现在，我们已经拥有连接前端应用程序到后端所需的一切；在我们这样做之前，让我们看看本章将学到什么。

在本章中，我们将看到`angular-cli.json`文件中发生的一些更改，该文件现在提供了对多个应用程序的改进支持。

我们还将看看如何使用`ng add`创建**渐进式 Web 应用程序**（**PWA**），以及如何将项目组织为模块。

在本章中，我们将涵盖以下内容：

+   使用 Angular CLI 启动 Web 应用程序

+   构建 PWA 的基线

+   创建样板组件

# 使用 Angular CLI 启动 Web 应用程序

当我们开始撰写本章时，Angular 框架已推出了最新版本：版本 6。在之前的章节中，我们已经评论了这个版本中存在的一些新功能。

新版本更加专注于开发工具（如 Angular CLI）而不是框架本身的演进。我们可以引用 Angular CLI 的新功能，如`ng update`和`ng add`命令，这些对于更新包和添加新包非常有用。

我们需要做的第一件事是更新机器上的 Angular CLI；打开您的终端窗口并输入以下命令：

```php
npm install -g @angular/cli
```

上述命令将在您的机器上全局安装 Angular CLI 6.0.0。

# 准备基线代码

现在，我们需要准备我们的基线代码，这个过程与之前的章节非常相似。按照以下步骤进行：

1.  复制`chapter-05`文件夹中的所有内容。

1.  将文件夹重命名为`chapter-07`。

1.  删除`storage-db`文件夹。

现在，让我们对`docker-compose.yml`文件进行一些更改，以适应新的数据库和服务器容器。

1.  打开`docker-compose.yml`并用以下内容替换其中的内容：

```php
version: "3.1"
services:
    mysql:
      image: mysql:5.7
      container_name: chapter-07-mysql
      working_dir:     /application
      volumes:
        - .:/application
        - ./storage-db:/var/lib/mysql
      environment:
        - MYSQL_ROOT_PASSWORD=123456
        - MYSQL_DATABASE=chapter-06
        - MYSQL_USER=chapter-07
        - MYSQL_PASSWORD=123456
      ports:
        - "8083:3306"
    webserver:
      image: nginx:alpine
      container_name: chapter-07-webserver
      working_dir: /application
      volumes:
        - .:/application-
        ./phpdocker/nginx/nginx.conf:/etc/nginx/conf.d/default.conf
      ports:
        - "8081:80"
    php-fpm:
      build: phpdocker/php-fpm
      container_name: chapter-07-php-fpm
      working_dir: /application
      volumes:
        - ./Server:/application
        - ./phpdocker/php-fpm/php-ini-overrides.ini:
          /etc/php/7.2/fpm/conf.d/99-overrides.ini
```

请注意，我们更改了容器名称、数据库和 MySQL 用户：

+   `container_name: chapter-07-mysql`

+   `container_name: chapter-07-webserver`

+   `container_name: chapter-07-php-fpm`

+   `MYSQL_DATABASE=chapter-07`

+   `MYSQL_USER=chapter-07`

另一个需要注意的重要点是`php-fpm`容器卷的配置，我们现在将其命名为`Server`，而不是在之前的章节中命名为`project`，根据以下突出显示的代码：

```php
php-fpm:
        build: phpdocker/php-fpm
        container_name: chapter-07-php-fpm
        working_dir: /application
        volumes:
        - ./Server:/application
        - ./phpdocker/php-fpm/php-ini-overrides.ini:/etc/php/7.2/fpm/conf.d/99-overrides.ini
```

1.  在`vs.code`中打开`chapter-07`并将项目文件夹重命名为`Server`。

正如您在之前的章节中看到的，Laravel 框架有一种明确定义其视图使用方式；这是由于 Laravel 构建在 MVC 标准之上。

此外，Laravel 使用一个名为 Vue.js 的 JavaScript 框架，可以在`./Server/resources/assets/js`文件夹中找到。

为了不混淆，我们将在一个名为`Client`的文件夹中创建我们的前端应用程序，与新命名的`Server`文件夹处于同一级别。

1.  在`chapter-07`文件夹的根目录下创建一个名为`Client`的新文件夹。

在这些更改结束时，您应该看到与以下屏幕截图相同的项目结构：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/hsn-flstk-web-dev-ng6-lrv5/img/c7c558f4-335d-416f-86dc-b410b0e60ecf.png)应用程序结构

这是保持应用程序与 API 解耦的最佳方法。通过这种方法，我们有一些优势：

+   前端代码与应用程序的其余部分隔离；我们可以将其托管在静态 Web 服务中，例如**亚马逊网络服务**（**AWS**）存储桶，或任何其他 Web 服务器。

+   应用部署可以分开进行，以便 API 独立于前端应用程序进行演进，反之亦然。

将我们对 Git 源代码所做的更改添加到源代码控制中。打开终端窗口，输入以下命令：

```php
git add .
git commit -m "Initial commit chapter 07"
```

# 使用 Angular CLI 搭建 Web 应用

让我们开始使用 Angular CLI 构建我们的前端应用程序的新版本：

1.  在项目根目录打开终端窗口，输入以下命令：

```php
ng new Client --style=scss --routing
```

1.  前面的命令将创建我们需要的所有样板代码，这次使用 SCSS 语法进行样式表和`--routing`标志来创建应用程序路由。

1.  在上一个命令结束时，我们的应用程序将具有以下结构：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/hsn-flstk-web-dev-ng6-lrv5/img/bfdd5946-7b1a-4f2c-a505-bbcd095c24c2.png)新的应用程序结构

1.  Angular 和 Angular CLI 版本 6 带来的变化之一是`angular.json`文件，之前的名称是`angular-cli.json`。它的结构非常不同，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/hsn-flstk-web-dev-ng6-lrv5/img/0c8a4da1-fd67-4049-9b2f-148c8ab77317.png)Angular JSON 文件

1.  至于应用程序文件，我们几乎有与之前相同的代码组织和文件，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/hsn-flstk-web-dev-ng6-lrv5/img/2135d742-4694-46f3-aa13-48b4a203df0a.png)新的 Angular 应用结构

在前面的截图中，请注意我们现在有一个名为`browserlist`的文件；它用于向 CSS 生成的代码添加特定于浏览器的前缀。

# 创建目录结构

为了方便我们的开发，我们将在应用程序中创建一些目录，这样我们的项目将准备好进行扩展。这意味着我们可以以有组织的方式添加任何我们想要的模块/功能。

这一步非常重要，因为有时项目内部的结构是固定的；不建议更改它。

在这一步中，我们将使用模块或页面的命名约定。我们将使用前一章中制作的 API 定义服务作为基线：

+   一个名为`home`的主页

+   一个名为`bike-list`的摩托车页面

+   一个名为`bike-details`的自行车详情页面

+   一个名为`builders-list`的构建者页面

+   一个名为`builder-details`的构建者详情页面

+   一个名为`register`的注册页面

+   一个名为`login`的登录页面

根据前述描述，我们的应用程序将具有以下页面或模块：

+   `bike`

+   `builder`

+   `register`

+   `login`

+   `home`

我们更喜欢在这个时候使用*模块*或*页面*的命名约定，而不是组件，以免与 Angular 提出的组件术语混淆，其中一切都基于组件。

最后，这只是一种不同的方式来指代应用程序结构。

1.  打开 VS Code，在`Client/src/app`中，创建一个名为`pages`的新文件夹。

1.  在 VS Code 中，进入`Client/src/app`，创建一个名为`layout`的新文件夹。

1.  在 VS Code 中，进入`Client/src/app`，创建一个名为`shared`的新文件夹。

让我们看看以下表中的文件夹名称的含义：

| 文件夹 | 描述 |
| --- | --- |
| `pages` | 包含应用程序的所有模块和页面；例如，`pages/bike/bike-component.html` 和 `pages/builder/builder-component.html`。 |
| `layout` | 包含所有布局组件；例如，`layout/nav/nav-component.html`，`layout/footer/footer-component.html`。 |
| `shared` | 包含共享服务、管道等；例如，所有应用程序页面或组件共享的服务。 |

因此，在第 3 步结束时，我们将拥有以下结构：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/hsn-flstk-web-dev-ng6-lrv5/img/60895152-3d84-4926-a56b-430492a0a601.png)文件夹结构

# 构建 PWA 的基线

正如我们之前讨论的，现在我们可以使用新的`ng add`命令来创建 PWA。但在此之前，让我们先了解一下 PWA 的概念。

PWA 是一套用于开发 Web 应用程序的技术，逐渐添加了以前只在原生应用中可能的功能。

用户的主要优势是他们不必在知道是否值得下载应用程序之前就下载应用程序。此外，我们可以列举以下优势：

+   **渐进式**：适用于任何用户，无论使用的是哪种浏览器

+   **响应式**：适用于任何设备：台式机、平板电脑和移动设备

+   **连接**：即使用户处于离线状态也能工作

+   **类似应用程序**：用户感觉自己就像在本机应用程序中

+   **更新**：无需下载应用程序更新；浏览器将自动检测并更新，如果有必要的话

+   **安全**：只有使用 HTTPs

+   **吸引力**：通过推送通知，用户可以保持持续参与

+   **可安装**：您可以通过单击一个图标将其添加到智能手机的主屏幕上

+   **SEO 友好**：搜索引擎可以找到应用程序的内容（这有利于用户和企业）

您可以在[`developers.google.com/web/progressive-web-apps/`](https://developers.google.com/web/progressive-web-apps/)上阅读更多关于渐进式 Web 应用程序的信息。

尽管 PWA 在构建本机应用程序方面仍然存在一些缺点，如下所示：

+   PWA 尚未完全控制设备的硬件；蓝牙、联系人列表和 NFC 是一些无法通过 PWA 访问的功能的例子。

+   尽管谷歌、微软和 Mozilla 对 PWA 抱有很高的期望，但苹果并没有。

+   Safari 仍然不支持两个重要功能：推送通知和离线操作。但苹果已经在考虑实现 PWA，尽管它可能没有太多选择。

对于所有的负面因素，这只是时间问题——想想看，Angular 团队已经为我们提供了使用 Angular CLI 创建 PWA 的支持。

# 使用 ng add 添加 PWA 功能

现在，让我们看看我们如何做到这一点。

在`chapter-06/Client`文件夹中打开您的终端窗口，并输入以下命令：

```php
ng add @angular/pwa
```

前面的命令将生成类似以下截图的输出：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/hsn-flstk-web-dev-ng6-lrv5/img/edaea9d8-5588-4ca6-b2f2-ab8f995f6288.png)Angular PWA 输出

# 了解 PWA 中的关键文件

让我们检查一些在我们的应用程序文件中进行的重要更改。前面的命令将在根文件夹中添加两个新文件。

`manifest.json`文件用于设置：

+   主题颜色

+   应用程序名称

+   默认显示模式

+   图标配置和大小

还可以设置描述标签、相关应用程序和平台。

一个`ngsw-config.json`文件（也称为 service worker 配置），用于设置 assetsGroup、dataGroups、navigationUrls 和 cache。

在`src/assets`中创建了一个名为`icons`的新文件夹；此图标将显示为移动电话屏幕上的应用程序书签。

以下文件已更新：

+   `angular.json`。

+   `package.json`添加：`@angular/pwa`和`@angular/service-worker`。

+   `app.module.ts`在生产中注册了 service-worker。这意味着我们可以通过使用生产命令来看到 service-worker 的工作；在本章的后面，我们将看到如何使用它。

+   `index.html`在`<head>`标签中添加了`manifest.json`文件和主题颜色。

# PWA 在行动

正如我们在第 4 步中提到的，Angular 引擎只在生产模式下将 service work 应用于应用程序；也就是说，只有在使用`ng build`命令时才会应用。

所以，让我们看看这在实践中是如何工作的。但首先，让我们看看是否一切都按预期发生了，包括应用程序的创建和`@angular/pwa`的安装：

1.  在`./Client`文件夹中打开您的终端窗口，并输入以下命令：

```php
npm start
```

请记住，`npm start`命令与`ng server`相同；您可以在`package.json`的`scripts`标签中检查所有`npm`别名。在那里，我们有以下别名：

```php
     "scripts": {
                "ng": "ng",
                "start": "ng serve",
                "build": "ng build",
                "test": "ng test",
                "lint": "ng lint",
                "e2e": "ng e2e"
        }
```

在前面的命令结束时，我们可以看到以下消息作为输出：

```php
** Angular Live Development Server is listening on localhost: 4200, open your browser on http://localhost:4200/ **
```

接下来是类似以下的输出：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/hsn-flstk-web-dev-ng6-lrv5/img/a012adee-a0d6-43bd-934f-34ad9bf16867.png)Angular 开发服务器输出

1.  打开您的默认浏览器，并导航到`http://localhost:4200/`。

现在，您可以看到欢迎屏幕：

！[](assets/a7fbd412-51b1-4cdb-9c88-506289d46502.png)Angular 欢迎屏幕

让我们检查`manifest.json`文件。几乎所有新的浏览器都有一个 Web 检查器，我们可以在其中调试任何网站或 Web 应用程序。对于下一个检查，我们将使用 Chrome 浏览器，但您可以使用您的默认或喜爱的浏览器。

1.  在浏览器中，点击“打开”以打开 Web 检查器。

1.  如果您在 Chrome 中，请点击**应用程序**菜单选项卡。

1.  点击左侧菜单上的**清单**，您应该会看到一个类似于以下截图的面板：

！[](assets/460f7169-fd5f-4d1f-9599-a10fac0d45d8.png)Web 检查器

正如您在上一张截图中所看到的，一切都如预期那样；我们的`manifest.json`文件可用，其中包含我们之前看到的所有配置。

请注意 Identity 标题右侧的“添加到主屏幕”链接；这意味着我们可以将此应用程序添加到手机主屏幕或浏览器应用程序的选项卡上。

1.  但是，如果您点击此链接，您将看到一个控制台错误，如下截图所示：

！[](assets/d46fcfb2-09a0-4348-8168-dc954049aba9.png)服务工作者控制台错误

这意味着我们没有服务工作者，这是真的。请记住，Angular 只会在生产中注入服务工作者，我们在幕后使用**`ng server` **。

此外，如果您点击服务工作者右侧菜单，您将看到一个空面板。

# 在生产模式下运行应用程序

现在，是时候在生产模式下检查我们的应用程序，了解服务是如何工作的：

1.  返回您的终端窗口，并使用以下命令停止 Angular 服务器：

```php
control + c
```

1.  仍然在终端中，键入`build`命令：

```php
ng build --prod
```

请注意，前面的`npm build`别名命令没有使用

`--prod`标志。所以，你需要使用`ng build --prod`

命令，或使用`--prod`标志更新`npm build`命令。

在上一个命令的末尾，我们可以看到`Client`目录中的另一个文件夹，名为`dist`。

# Angular 服务-工作者在行动

现在，是时候启动生成在`./Client/dist/Client`文件夹中的应用程序，以查看服务工作者的工作情况。现在不要担心这个路径；在本书的后面，我们会进行更改：

1.  在`./Client/dist/Client`文件夹中打开您的终端窗口，并键入以下命令：

```php
http-server -p 8080
```

请记住，我们在上一章中安装了 HTTP 服务器；如果您还没有这样做，请转到[`www.npmjs.com/package/http-server`](https://www.npmjs.com/package/http-server)并按照安装过程进行操作。

1.  在浏览器中打开`http://localhost:4200/`。

1.  在浏览器中，打开 Web 检查器面板，点击右侧菜单中的**应用程序**选项卡菜单。

您将看到以下内容：

！[](assets/53f31bc2-fe24-4cdd-8c5d-1d97b4e66922.png)Web 检查器应用程序面板

现在，我们已经正确配置并在我们的应用程序中运行服务工作者。

1.  返回浏览器，点击右侧菜单中的**清单**菜单。

1.  现在，点击“添加到**主屏幕**”链接。

恭喜！您已将我们的应用程序添加到您的应用程序面板中。如果您在 Chrome 中，您将看到以下内容：

！[](assets/9e864de1-a81c-4596-a7df-35daa91dfe05.png)应用程序图标

因此，如果您点击 Angular 图标，您将被重定向到`http://localhost:8080/`。

此刻，我们已经有了 PWA 的基础。

不要担心应用程序名称；我们使用的是`Client`，但在现实世界中，您可以选择自己的名称。

# 调试渐进式 Web 应用程序

现在，我们将介绍一个非常有用的工具，用于调试渐进式 Web 应用程序。这是 Chrome 导航器的一个扩展，称为 Lighthouse：

您可以在[`chrome.google.com/webstore/detail/lighthouse/blipmdconlkpinefehnmjammfjpmpbjk/related?hl=us-EN`](https://chrome.google.com/webstore/detail/lighthouse/blipmdconlkpinefehnmjammfjpmpbjk/related?hl=us-EN)获取有关 Lighthouse 的更多信息。

1.  打开 Chrome 浏览器，点击右侧的 Lighthouse 扩展，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/hsn-flstk-web-dev-ng6-lrv5/img/0ec10f1a-f289-4cd3-9b4e-89066a2a9b3e.png)Lighthouse 扩展

1.  点击**生成报告**按钮。

生成报告后，您将看到类似以下截图的结果：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/hsn-flstk-web-dev-ng6-lrv5/img/8650a77f-7a0a-41de-8a3a-2975a89977b1.png)Lighthouse 报告

Lighthouse 将分析五个主要项目：

+   性能

+   PWA

+   可访问性

+   最佳实践

+   **搜索引擎优化**（**SEO**）

请注意，即使没有任何内容，我们在每个类别中都有一个高分级别；现在让我们专注于 SEO 类别。

让我们看看如何改进 SEO。

1.  在左侧菜单中点击 SEO；您将看到以下截图：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/hsn-flstk-web-dev-ng6-lrv5/img/1c5e57f7-6892-4ffc-860e-c573aad58972.png)

上述警告告诉我们，我们的应用程序在`index.html`上没有 meta 描述标签。所以，让我们修复它。

在`./Client/src/index.html`中，在 viewport meta 标签之后添加以下代码：

```php
<metaname="description" content="Hands-On Full-Stack Web Development with Angular 6 and Laravel 5">
```

如果我们再次检查，我们将看到以下报告：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/hsn-flstk-web-dev-ng6-lrv5/img/be4b7199-46af-466d-a41b-51a2ef49cee9.png)

请注意，我们在 SEO 方面得分为 100%

这样，我们可以找到应用程序中的所有问题并正确地进行修正。

我们现在已经准备好让我们的应用程序消耗我们的 API，但是我们仍然有很多工作要做来构建前端应用程序。

在接下来的步骤中，我们将看看如何使用 Angular CLI 添加我们的组件。

# 创建样板 Angular 组件

正如我们之前所看到的，我们的应用程序有一些页面用于注册、登录以及摩托车列表、建造者列表和摩托车投票方案的可视化。在这一点上，我们将创建所有必要的代码来组成这些功能。

# 创建主页模块和组件

在接下来的几行中，我们将创建`home`模块和组件：

1.  在`./Client/src/app`中打开您的终端窗口，并键入以下命令：

```php
ng generate module pages/home --routing
```

正如我们之前所看到的，上述命令将生成三个新文件：

+   `src/app/pages/home/home-routing.module.ts`

+   `src/app/pages/home/home.modules.spec.ts`

+   `src/app/pages/home/home.module.ts`

现在，我们只需要生成`home`组件。

1.  仍然在终端中，键入以下命令：

```php
ng g c pages/home
```

在上一个命令结束时，您将在`pages`文件夹中看到以下结构：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/hsn-flstk-web-dev-ng6-lrv5/img/12d4473b-2b1d-4e5c-8a9b-deab577c4e1d.png)主页模块结构

请注意，我们创建了一个完整的模块/文件夹，就像我们之前解释的那样。现在，我们可以称新文件夹为`home`。我们需要将新创建的`home`模块导入到我们的主项目中；让我们看看如何做到这一点。

1.  打开`src/app/app.modules.ts`并添加以下代码行：

```php
// Application modules
import { HomeModule } from './pages/home/home.module';
@NgModule({
    declarations: [
    AppComponent
    ],
imports: [
    BrowserModule,
    AppRoutingModule,
    HomeModule,
    ServiceWorkerModule.register('/ngsw-worker.js', { enabled:         environment.production })
    ],
providers: [],
bootstrap: [AppComponent]
})
export class AppModule { }
```

# 创建摩托车模块和组件

现在，是时候创建另一个模块和组件了；让我们看看如何做到这一点：

1.  仍然在您的终端窗口中，在`./Client/src/app`中，键入以下命令：

```php
ng generate module pages/bikes --routing
```

正如我们之前所看到的，上述命令将生成三个新文件：

+   `src/app/pages/bikes/bikes-routing.module.ts`

+   `src/app/pages/bikes/bikes.modules.spec.ts`

+   `src/app/pages/bikes/bikes.module.ts`

现在，我们只需要生成`bike`组件。

1.  键入以下命令：

```php
ng g c pages/bikes
```

在上一个命令结束时，您将在`pages`文件夹中看到以下结构：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/hsn-flstk-web-dev-ng6-lrv5/img/bd231faf-fa52-4a06-a103-ffd4ce3f141d.png)摩托车模块结构

现在，我们可以称新文件夹为`bikes`（作为 Bikes 模块）。我们需要将新创建的`bikes`模块导入到我们的主项目中；让我们看看如何做到这一点。

1.  打开`src/app/app.modules.ts`并添加以下代码行：

```php
// Application modules
import { BikesModule } from './pages/bikes/bikes.module';
@NgModule({
    declarations: [
    AppComponent
    ],
imports: [
    BrowserModule,
    AppRoutingModule,
    HomeModule,
    BikesModule,
    ServiceWorkerModule.register('/ngsw-worker.js', { enabled:         environment.production })
    ],
providers: [],
    bootstrap: [AppComponent]
})
export class AppModule { }
```

请注意，我们正在将新创建的`BikesModule`注入为`app.module`的依赖项。

现在，是时候为 Builders、Login 和 Register 页面执行相同的操作了。

# 创建 builders 模块和组件

是时候使用 Angular CLI 创建`builders`模块了。让我们看看我们如何做到这一点：

1.  打开您的终端窗口并输入以下命令：

```php
ng generate module pages/builders --routing
```

正如您之前所看到的，上述命令将生成三个新文件：

+   `src/app/pages/builders/builders-routing.module.ts`

+   `src/app/pages/builders/builders.modules.spec.ts`

+   `src/app/pages/builders/builders.module.ts`

1.  仍然在您的终端窗口中，输入以下命令来生成组件：

```php
ng g c pages/builders
```

1.  将新创建的模块添加到应用程序模块中；打开`src/app/app.modules.ts`并添加以下代码：

```php
// Application modules
import { BikesModule } from './pages/bikes/bikes.module';
import { BuildersModule } from './pages/builders/builders.module';
@NgModule({
    declarations: [
    AppComponent
    ],
imports: [
    BrowserModule,
    AppRoutingModule,
      HomeModule,
    BikesModule,
    BuildersModule,
    ServiceWorkerModule.register('/ngsw-worker.js', { enabled:         environment.production })
    ],
providers: [],
    bootstrap: [AppComponent]
})
export class AppModule { }
```

# 准备 Auth 路由 - 登录、注册和注销组件

现在，我们可以创建 Auth 路由，包括`Login`和`Register`；同样，我们将使用 Angular CLI 的强大功能来创建新的模块和组件：

1.  打开您的终端窗口并输入以下命令：

```php
ng generate module pages/auth --routing
```

1.  仍然在您的终端窗口中，输入以下命令来生成组件：

```php
ng g c pages/auth/login
```

1.  将新创建的模块添加到应用程序模块中；打开`src/app/auth/auth.modules.ts`并添加以下代码：

```php
 import { LoginComponent } from  './login/login.component';

     @NgModule({

     imports: [

     CommonModule,

     AuthRoutingModule

     ],

     declarations: [LoginComponent]

 }) 
```

注意；这次，我们将`LoginComponent`添加到`auth.module.ts`中，

并没有将其添加到`app.module.ts`中。

现在，是时候在`auth.module`中创建`register`组件了。

1.  打开您的终端窗口并输入以下命令：

```php
ng g c pages/auth/register
```

1.  将新创建的模块添加到应用程序模块中；打开`src/app/auth/auth.modules.ts`并添加以下代码：

```php
import { RegisterComponent } from  './register/register.component';

    @NgModule({

    imports: [

    CommonModule,

    AuthRoutingModule

    ],

    declarations: [LoginComponent, RegisterComponent]

})
```

1.  打开您的终端窗口并输入以下命令：

```php
ng g c pages/auth/logout
```

1.  将新创建的模块添加到应用程序模块中；打开`src/app/auth/auth.modules.ts`并添加以下代码：

```php
import { LogoutComponent } from  './logout/logout.component';

@NgModule({

    imports: [

    CommonModule,

    AuthRoutingModule

    ],

    declarations: [LoginComponent, RegisterComponent, 
    LogoutComponent]

})
```

此时，我们的认证模块已经完成；也就是说，我们拥有了所有我们将使用的组件 - `register`、`login`和`logout`。但是我们仍然需要将新模块注入到主应用程序模块中。

1.  打开应用程序模块，打开`src/app/app.modules.ts`并添加以下代码：

```php
// Application modules
import { BikesModule } from './pages/bikes/bikes.module';
import { BuildersModule } from './pages/builders/builders.module';
import { AuthModule } from './pages/auth/auth.module';
@NgModule({
    declarations: [
    AppComponent
    ],
imports: [
    BrowserModule,
    AppRoutingModule,
    BikesModule,
    BuildersModule,
    AuthModule,
    ServiceWorkerModule.register('/ngsw-worker.js', { enabled:
environment.production })
    ],
    providers: [],
    bootstrap: [AppComponent]
    })
export class AppModule { }
```

在这一步结束时，您将拥有以下结构：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/hsn-flstk-web-dev-ng6-lrv5/img/400a32a2-e034-43dc-bad8-a74961bd3802.png)应用程序模块结构

# 创建布局组件

在本节的最后一步中，我们将为应用程序的主导航创建一个布局组件。请注意，这次我们只会创建组件本身，而不包括模块和路由。

仍然在您的终端窗口中，输入以下命令：

```php
ng g c layout/nav
```

上述命令将生成以下结构：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/hsn-flstk-web-dev-ng6-lrv5/img/58129ae7-59fc-4c64-9a89-87daa622b263.png)布局文件夹结构

# 摘要

恭喜；您刚刚完成了又一章，现在您拥有一个坚固的前端应用程序，准备接收所有需要的功能。

在本章中，我们使用 Angular 创建了一个渐进式 Web 应用程序，使用了代码组织的高级技术。您还学会了如何使用 Angular CLI 创建模块和组件。

在下一章中，我们将学习如何创建应用程序的组件和路由。
