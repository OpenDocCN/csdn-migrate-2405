# Vue3 示例（四）

> 原文：[`zh.annas-archive.org/md5/84EBE0BE98F4DE483EBA9EF82A25ED12`](https://zh.annas-archive.org/md5/84EBE0BE98F4DE483EBA9EF82A25ED12)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：使用 Vue 3、Laravel 和 Socket.IO 构建聊天应用

在之前的章节中，我们创建了仅通过 HTTP 通信的前端项目或全栈项目。前端和后端之间没有实时通信。如果我们需要从服务器端实时向客户端通信数据，或者反过来，实时通信有时是必要的。没有一些实时通信机制，就没有办法在客户端不发起请求的情况下从服务器端向客户端通信。这是我们可以很容易通过 Laravel 框架和 Socket.io 添加的功能。

在本章中，我们将研究以下主题：

+   使用 Laravel 创建 API 端点

+   设置 JWT 身份验证

+   创建前端以让用户聊天

Laravel 是用 PHP 编写的后端 Web 框架。它是一个包括处理 HTTP 请求、数据库操作和实时通信的全面后端框架。

在本章中，我们将看看如何让所有这些部分一起工作，以便我们可以使用 Vue 3、Laravel Echo Server 和 Redis 一起创建一个聊天应用。

# 技术要求

要完全理解本章，需要以下内容：

+   对 PHP 的基本理解

+   使用 Vue 组件创建基本应用的能力

+   使用 Axios HTTP 客户端发送和接收 HTTP 请求的能力

本章项目的代码可在[`github.com/PacktPublishing/-Vue.js-3-By-Example/tree/master/Chapter08`](https://github.com/PacktPublishing/-Vue.js-3-By-Example/tree/master/Chapter08)找到。

# 使用 Laravel 创建 API 端点

创建我们的聊天应用的第一步是使用 Laravel 创建后端应用。使用 Laravel 创建 API 是我们必须学习的主要内容。这是我们以前没有做过的事情。这也意味着我们必须使用 PHP 编写代码，因为 Laravel 是基于 PHP 的 Web 框架。因此，在阅读此代码之前，您应该学习一些基本的 PHP 语法。与 JavaScript 和其他面向对象的语言一样，它们共享类似的概念，如使用对象、数组、字典、循环、类和其他基本的面向对象编程概念。因此，在学习难度方面，它与 JavaScript 应该没有太大的不同。

## 安装所需的库

要使用 Laravel 创建我们的 API，我们不必自己创建所有文件，只需运行几个命令，就会自动为我们创建所有文件和配置设置。在创建 API 之前，我们必须运行 PHP。在 Windows 中，将 PHP 添加到我们的 Windows 安装的最简单方法是使用 XAMPP。我们可以通过访问[`www.apachefriends.org/download.html`](https://www.apachefriends.org/download.html)来下载和安装它。它也适用于 macOS 和 Linux。

安装完成后，我们可以使用**Composer**创建我们的 Laravel API。Composer 是 PHP 的包管理器，我们将在以后使用它来安装更多的库。创建项目的最简单方法是创建我们的项目文件夹，然后在转到文件夹后运行创建 Laravel 项目的命令：

1.  首先，我们创建一个名为`vue-example-ch8-chat-app`的项目文件夹，其中将分别放置前端和后端的文件夹。

1.  然后，在这个文件夹中，我们创建后端文件夹来存放我们的 Laravel 项目代码文件。

1.  现在我们转到命令行，然后进入`vue-example-ch8-chat-app`，然后运行`composer global require laravel/installer`。

这将安装 Laravel 安装程序，让我们创建 Laravel 项目。全局库的位置如下：

+   macOS: `$HOME/.composer/vendor/bin`

+   Windows: `%USERPROFILE%\AppData\Roaming\Composer\vendor\bin`

+   GNU / Linux 发行版: `$HOME/.config/composer/vendor/bin` 或 `$HOME/.composer/vendor/bin`

我们还可以运行`composer global about`来查找库文件的位置。

完成后，我们使用一个命令创建包含所有文件和配置文件的脚手架，并为我们安装所有所需的库。

我们通过命令行进入`vue-example-ch8-chat-app`文件夹，然后运行`laravel new backend`在后端文件夹中创建 Laravel 应用程序。Laravel 安装程序将运行并为我们的 Laravel 创建脚手架。此外，Composer 将安装我们运行 Laravel 所需的所有 PHP 库。完成所有这些后，我们应该拥有一个完整的 Laravel 安装，其中包含我们运行应用程序所需的所有文件和配置。

## 创建数据库和迁移文件

现在，随着 Laravel 应用程序的创建和所有相关库的安装，我们可以开始在 Laravel 应用程序上创建我们的 API。首先，我们通过创建一些迁移文件来创建我们的数据库。我们需要它们来创建`chats`和`messages`表。`chats`表包含聊天室数据。而`messages`表包含与聊天室相关联的聊天消息。它还将引用发送消息的用户。

我们不需要创建`users`表，因为在创建 Laravel 应用程序时会自动创建。几乎每个应用程序都需要保存用户数据，因此这是自动包含的。使用 Laravel 脚手架，我们可以创建具有用户名、电子邮件和密码的用户，并使用刚刚创建的用户的用户名和密码登录。Laravel 还具有发送电子邮件进行用户验证的功能，而无需添加任何代码。

创建迁移，我们运行以下命令：

```js
php artisan make:migration create_chats_table
php artisan make:migration create_messages_table
```

上述命令将为我们创建带有日期和时间前缀的迁移文件。所有迁移文件都在`database/migrations`文件夹中。因此，我们可以进入此文件夹并打开文件。在文件名为`create_chats_table`的文件中，我们添加以下代码：

```js
<?php
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
class CreateChatsTable extends Migration
{
    public function up()
    {
        Schema::create('chats', function (Blueprint $table)
        {
            $table->id();
            $table->string('name');
            $table->timestamp('created_at')->useCurrent();
            $table->timestamp('updated_at')->useCurrent();
        });
    }
    public function down()
    {
        Schema::dropIfExists('chats');
    }
}
```

上述代码将创建`chats`表。`up()`方法包含我们在运行迁移时要运行的代码。`down()`方法包含我们在要撤消迁移时要运行的方法。

在`up()`方法中，我们调用`Schema::create`来创建表。`::`符号表示该方法是静态方法。第一个参数是表名，第二个参数是一个回调函数，我们在其中添加创建表的代码。`$table`对象具有`id()`方法来创建`id`列。`string()`方法创建一个带有参数中列名的`string`列。`timestamp()`方法让我们创建一个带有给定列名的`timestamp`列。`useCurrent()`方法让我们将时间戳的默认值设置为当前日期和时间。

在`down()`方法中，我们有`Schema::dropIfExists()`方法来删除具有参数中给定名称的表，如果存在的话。

迁移文件必须具有从`Migration`类继承的类，才能用作迁移。

同样，在文件名为`create_message_table`的迁移文件中，我们编写以下内容：

```js
<?php
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
class CreateMessagesTable extends Migration
{
    public function up()
    {
        Schema::create('messages', function (Blueprint 
         $table) {
            $table->id();
            $table->unsignedBigInteger('user_id');
            $table->unsignedBigInteger('chat_id');
            $table->string('message');
            $table->timestamp('created_at')->useCurrent();
            $table->timestamp('updated_at')->useCurrent();
            $table->foreign('user_id')->references('id')-
              >on('users');
            $table->foreign('chat_id')->references('id')-
              >on('chats');
        });
    }
    public function down()
    {
        Schema::dropIfExists('messages');
    }
}
```

上述文件中有创建`messages`表的代码。这个表有更多的列。我们有与`chats`表中相同的`id`和`timestamp`列，但我们还有`user_id`无符号`integer`列来引用发布消息的用户的 ID，以及`chat_id`无符号`integer`列来引用`chats`表中的条目，将消息与创建它的聊天会话关联起来。

`foreign()`方法让我们指定`user_id`和`chat_id`列分别引用用户和`chats`表中的内容。

### 配置我们的数据库

在我们运行迁移之前，我们必须配置我们将用于存储后端数据的数据库。为此，我们通过复制`.env.example`文件并将其重命名为`.env`来在项目的`root`文件夹中创建`.env`文件。

`.env`文件有许多设置，我们需要运行我们的 Laravel 应用程序。为了配置我们将使用的数据库，我们运行以下命令，以便连接到 SQLite 数据库：

```js
DB_CONNECTION=sqlite
DB_DATABASE=C:\vue-example-ch8-chat-app\backend\db.sqlite
```

完整的配置文件在[`github.com/PacktPublishing/-Vue.js-3-By-Example/blob/master/Chapter08/backend/.env.example`](https://github.com/PacktPublishing/-Vue.js-3-By-Example/blob/master/Chapter08/backend/.env.example)。我们只需将其内容复制到同一文件夹中的`.env`文件中以使用该配置。

本章中，我们使用 SQLite 是为了简化，这样我们就可以专注于使用 Vue 3 创建聊天应用程序。然而，如果我们要构建生产应用程序，我们应该使用具有更好安全性和管理能力的生产级数据库。`DB_CONNECTION`环境变量具有我们想要使用的数据库类型，即 SQLite。在`DB_DATABASE`设置中，我们指定了数据库文件的绝对路径。Laravel 不会自动为我们创建这个文件，所以我们必须自己创建。要创建 SQLite 文件，我们可以使用 DB Browser for SQLite 程序。它支持 Windows、macOS 和 Linux，因此我们可以在所有流行的平台上运行它。您可以从[`sqlitebrowser.org/dl/`](https://sqlitebrowser.org/dl/)下载该程序。安装完成后，只需在左上角点击**New Database**，然后点击**File**菜单，再点击**Save**以保存数据库文件。

### 配置到 Redis 的连接

除了将 SQLite 用作我们应用程序的主要数据库之外，我们还需要配置与 Redis 的连接，以便我们可以使用 Laravel 的排队功能将数据广播到 Redis 服务器，然后由 Laravel Echo 服务器接收，以便事件将被发送到 Vue 3 前端。 Redis 配置的环境变量如下：

```js
BROADCAST_DRIVER=redis
QUEUE_CONNECTION=redis
QUEUE_DRIVER=sync
```

然后我们添加以下 Redis 配置：

```js
REDIS_HOST=127.0.0.1
REDIS_PASSWORD=null
REDIS_PORT=6379
```

第一组环境变量配置了队列将数据发送到的位置。`BROADCAST_DRIVER`设置为`redis`，以便我们将事件发送到 Redis。`QUEUE_CONNECTION`也必须设置为`redis`，出于同样的原因。`QUEUE_DRIVER`设置为`sync`，以便事件在广播后立即发送到队列。

## 运行迁移文件

现在我们已经创建了迁移并配置了要使用的数据库，我们运行`php artisan migrate`来运行迁移。运行迁移将向我们的 SQLite 数据库添加表。添加表后，我们可以添加种子数据，这样当我们想要重置数据库或者数据库为空时，我们就不必重新创建数据。要创建种子数据，我们在`database/seeders/DatabaseSeeder.php`文件中添加一些代码。在文件中，我们编写以下代码来添加我们数据库的文件：

```js
<?php
namespace Database\Seeders;
use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use App\Models\User;
use App\Models\Chat;
class DatabaseSeeder extends Seeder
{
    public function run()
    {
        $this->addUsers();
        $this->addChats();
        $this->addMessages();
    }
    private function addUsers()
    {
        for ($x = 0; $x <= 1; $x++) {
            DB::table('users')->insert([
                'name' => 'user'.$x,
                'email' => 'user'.$x.'@gmail.com',
                'password' => Hash::make('password'),
            ]);
        }
    }
  ...
}
```

我们有`addUsers()`方法将一些用户添加到`users`表中。我们创建一个循环，调用`DB::table('users')->insert`向`users`表中插入一些条目。`->`符号与 JavaScript 中的句号相同。它允许我们访问对象属性或方法。

在`insert()`方法中，我们传入一个带有我们要插入的键和值的关联数组或字典：

```js
    ...
    private function addChats()
    {
        for ($x = 0; $x <= 1; $x++) {
            DB::table('chats')->insert([
                'name' => 'chat '.$x,
            ]);
        }
    }
    ...
```

`addChats()`方法让我们添加聊天室条目。我们只需要插入名称。在`addMessages()`方法中，我们插入`messages`表的条目。我们获取要设置为`id`值的用户条目的值，该值来自`users`表中的现有条目。同样，我们对`chat_id`执行相同的操作，通过从`chats`表中获取条目并使用该条目的`id`值将其设置为`chat_id`的值。

```js
...
    private function addMessages()
    {
        for ($x = 0; $x <= 1; $x++) {
            DB::table('messages')->insert([
                'message' => 'hello',
                'user_id' => User::all()->get(0)->id,
                'chat_id' => Chat::all()->get($x)->id
            ]);
            DB::table('messages')->insert([
                'message' => 'how are you',
                'user_id' => User::all()->get(1)->id,
                'chat_id' => Chat::all()->get($x)->id
            ]);
        }
    }
...
```

一旦我们编写了 seeder，我们可能希望重新生成 Composer 的自动加载程序，以便使用我们的依赖项更新自动加载程序。我们可以通过运行`composer dump-autoload`来做到这一点。这在引用任何依赖项过时并且我们想要刷新引用以使其不过时时非常方便的。然后我们运行`php artisan db:seed`来运行 seeder 以将所有数据填充到表中。

要将数据重置为原始状态，我们可以通过运行`php artisan migrate:refresh –seed`来同时运行迁移和 seeder。我们也可以只清空数据库并重新运行所有迁移，通过运行`php artisan migrate:refresh`。

## 创建我们的应用逻辑

现在我们已经有了数据库结构和种子数据，我们可以继续创建我们的应用逻辑。我们创建一些控制器，这样我们就可以从前端接收请求。Laravel 控制器应该在`app/Http/Controllers`文件夹中。我们创建一个用于接收请求或操作`chats`表的控制器，另一个用于接收请求来操作`messages`表。Laravel 自带一个用于创建控制器的命令。首先，我们通过运行以下代码创建`ChatController.php`文件：

```js
php artisan make:controller Chat
```

然后我们应该将`app/Http/Controllers/ChatController.php`文件添加到我们的项目中。完整的代码在[`github.com/PacktPublishing/-Vue.js-3-By-Example/blob/master/Chapter08/backend/app/Http/Controllers/ChatController.php`](https://github.com/PacktPublishing/-Vue.js-3-By-Example/blob/master/Chapter08/backend/app/Http/Controllers/ChatController.php)。

一个 Laravel 控制器有一个继承自`Controller`类的类。在这个类里，我们有一些方法，这些方法将被映射到 URL，这样我们就可以运行这些方法并做我们想做的事情。每个方法都接受一个请求对象，其中包括请求数据，包括头部、URL 参数和主体。

`get()`方法查找单个`Chat`条目。`Chat`是`chats`表的模型类。在 Laravel 中，约定是类名对应于表名，通过去掉末尾的`s`然后将第一个字母转换为大写来转换表名。因此，`Chat`模型类用于操作`chats`表中的条目。Laravel 会自动进行映射，因此我们不必自己做任何事情。我们只需要记住这个约定，这样我们就不会被搞混。`find()`方法是一个我们用来通过 ID 获取单个条目的`static`方法。

在所有控制器函数中，我们可以返回一个字符串，一个关联数组，一个响应对象，或者从`query()`方法返回的结果作为响应返回。因此，当我们发出请求并调用`get`方法时，`Chat::find`方法的返回值将作为响应返回。

`getAll()`方法用于从`chats`表中获取所有条目。`all()`方法是一个静态方法，返回所有条目。

`create()`方法用于从请求数据创建条目。我们调用`Validate::make`静态方法为请求数据创建验证器。第一个参数是`$request->all()`，这是一个返回请求对象中所有项目的方法。第二个参数是一个关联数组，其中包含要验证的请求体的键。它的值是一个包含验证规则的字符串。`required`规则确保`name`被填写。`string`规则检查作为`name`键值的值是否为字符串。`max:255`规则是`name`值中我们可以拥有的最大字符数：

```js
...
    public function create(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255',
        ]);
        if($validator->fails()){
            return response()->json($validator->errors()-
              >toJson(), 400);
        }
        $chat = Chat::create([
            'name' => $request->get('name'),
        ]);
        return response()->json($chat, 201);
    }
...
```

我们使用`$validator->fails()`方法来检查验证是否失败。`$validator`是由`Validator::make`方法返回的对象。在`if`块中，我们调用`response()->json()`将错误以 400 状态码返回给用户。

否则，我们调用`Chat::create`来创建`chats`表条目。我们使用`$request->get`方法从请求体中获取`name`字段的值，使用我们想要获取的键。然后我们将其设置为我们传递给`create`方法的关联数组中`'name'`键的值。

我们对`update()`方法做类似的操作，只是我们调用`Chat::find`来通过其`id`值找到项目。然后我们将请求体中的`name`字段的值分配给返回的聊天对象的`name`属性。然后我们调用`$chat->save()`来保存最新值。然后我们通过调用`response()->json($chat)`返回响应，以将最新的聊天条目转换为 JSON：

```js
...
    public function update(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255',
        ]);
        if($validator->fails()){
            return response()->json($validator->errors()-
              >toJson(), 400);
        }
        $chat = Chat::find($request->id);
        $chat->name =  $request->get('name');
        $chat->save();
        return response()->json($chat);
    }
...
```

当我们向 API 发出*DELETE*请求以删除聊天室条目时，将调用`delete()`方法。我们再次调用`Chat::find`来查找具有给定 ID 的`chats`表中的条目。然后我们调用`$chat->delete()`来删除返回的条目。然后我们返回一个空响应：

```js
...
    public function delete(Request $request)
    {
        $chat = Chat::find($request->id);
        $chat->delete();
        return response(null, 200);
    }
...
```

我们有类似的逻辑`MessageController.php`，让我们保存聊天消息。我们有`UserController.php`文件，其中包含注册用户帐户时保存用户数据的代码。

重要：

这些文件可以在[`github.com/PacktPublishing/-Vue.js-3-By-Example/blob/master/Chapter08/backend/app/Http/Controllers/MessageController.php`](https://github.com/PacktPublishing/-Vue.js-3-By-Example/blob/master/Chapter08/backend/app/Http/Controllers/MessageController.php)和[`github.com/PacktPublishing/-Vue.js-3-By-Example/blob/master/Chapter08/backend/app/Http/Controllers/UserController.php`](https://github.com/PacktPublishing/-Vue.js-3-By-Example/blob/master/Chapter08/backend/app/Http/Controllers/UserController.php)找到。

## 公开控制器方法以供端点使用

接下来，我们必须将我们的控制器方法映射到我们将发出请求调用的 URL。我们通过向`routes/api.php`文件添加一些代码来实现这一点。为此，我们用以下代码替换文件中的内容：

```js
<?php
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuthController;
use App\Http\Controllers\UserController;
use App\Http\Controllers\ChatController;
use App\Http\Controllers\MessageController;
Route::post('register', [UserController::class, 'register']);
Route::group([
    'middleware' => 'api',
    'prefix' => 'auth'
], function () {
    Route::post('login', [AuthController::class, 'login']);
    Route::post('logout', [AuthController::class, 
     'logout']);
    Route::post('refresh', [AuthController::class, 
     'refresh']);
    Route::post('me', [AuthController::class, 'me']);
     });
...
    Route::get('{chat_id}', [MessageController::class, 
     'getAll']);
    Route::post('create', [MessageController::class, 
     'create']);
});
```

我们通过分别调用`Route::post`和`Route::get`方法，将控制器方法公开为客户端的 POST 和 GET 端点。

`jwt.verify`中间件是我们在运行路由的`controller`方法之前用来检查 JSON Web 令牌的方法。这样，只有在令牌有效时才会运行`controller()`方法。

然后我们必须创建`AuthController`来进行 JSON Web 令牌身份验证。

首先，我们运行以下命令：

```js
php artisan make:controller AuthController
```

然后在`app/Http/Controllers/AuthController.php`文件中，我们添加了用于获取当前用户数据、登录和注销的端点方法。该文件的代码位于[`github.com/PacktPublishing/-Vue.js-3-By-Example/blob/master/Chapter08/backend/app/Http/Controllers/AuthController.php`](https://github.com/PacktPublishing/-Vue.js-3-By-Example/blob/master/Chapter08/backend/app/Http/Controllers/AuthController.php)。

如果您没有`app/Http/Middleware/JwtMiddleware.php`文件，该文件的完整代码位于[`github.com/PacktPublishing/-Vue.js-3-By-Example/blob/master/Chapter08/backend/app/Http/Middleware/JwtMiddleware.php`](https://github.com/PacktPublishing/-Vue.js-3-By-Example/blob/master/Chapter08/backend/app/Http/Middleware/JwtMiddleware.php)。

它使我们能够在 Vue 客户端和此应用程序之间启用 JSON Web 令牌身份验证。

# 设置 JWT 身份验证

现在，我们必须设置 JSON Web 令牌身份验证与我们的 Laravel 应用程序，以便我们可以将我们的前端与后端分开托管。为此，我们使用了`tymon/jwt-auth`库。要安装它，我们运行以下命令：

```js
composer require tymon/jwt-auth
```

接下来，我们运行以下命令来发布软件包配置文件：

```js
php artisan vendor:publish --provider="Tymon\JWTAuth\Providers\LaravelServiceProvider"
```

上述命令将为我们添加所有必需的配置。现在我们应该在我们的应用程序中添加`config/jwt.php`。然后，我们通过运行以下命令生成秘密密钥以签署 JSON Web 令牌：

```js
php artisan jwt:secret
```

`secret`密钥将被添加到`.env`文件中，密钥为`JWT_SECRET`。

## 配置我们的身份验证

接下来，我们必须配置我们的身份验证，以便在成功发出需要身份验证的路由请求之前，我们可以验证我们的 JSON Web 令牌。在`config/auth.php`中，我们有以下代码：

```js
<?php
return [
    'defaults' => [
        'guard' => 'api',
        'passwords' => 'users',
    ],
    'guards' => [
        'web' => [
            'driver' => 'session',
            'provider' => 'users',
        ],
        'api' => [
            'driver' => 'jwt',
            'provider' => 'users',
        ],
    ],
    'providers' => [
        'users' => [
            'driver' => 'eloquent',
            'model' => App\Models\User::class,
        ],
    ],
    'passwords' => [
        'users' => [
            'provider' => 'users',
            'table' => 'password_resets',
            'expire' => 60,
            'throttle' => 60,
        ],
    ],
    'password_timeout' => 10800,
];
```

在`guards`部分，我们有一个`api`密钥，其值为一个关联数组，其中驱动程序键设置为`'jwt'`，提供者设置为`'users'`，以便我们使用`jwt-auth`库发行的 JSON Web 令牌对用户进行身份验证。

接下来，我们添加代码以启用 CORS，以便我们的 Vue.js 3 应用程序可以与其通信。

# 启用跨域通信

为了使我们能够在前端和后端之间进行跨域通信，我们安装了`fruitcake/laravel-cors`软件包。为此，我们运行以下命令：

```js
composer require fruitcake/laravel-cors
```

然后，在`app/Http/Kernel.php`中，我们应该有以下内容：

```js
<?php
namespace App\Http;
use Illuminate\Foundation\Http\Kernel as HttpKernel;
class Kernel extends HttpKernel
{
    protected $middleware = [
        \App\Http\Middleware\TrustProxies::class,
        \Fruitcake\Cors\HandleCors::class,
        \App\Http\Middleware\
           PreventRequestsDuringMaintenance::class,
        \Illuminate\Foundation\Http\Middleware\
           ValidatePostSize::class,
        \App\Http\Middleware\TrimStrings::class,
        \Illuminate\Foundation\Http\Middleware\
           ConvertEmptyStringsToNull::class,
        \Fruitcake\Cors\HandleCors::class,
    ];
...
        'password.confirm' =>  \Illuminate\Auth\Middleware\
           RequirePassword::class,
        'signed' => \Illuminate\Routing\Middleware\
           ValidateSignature::class,
        'throttle' => \Illuminate\Routing\Middleware\
           ThrottleRequests::class,
        'verified' => \Illuminate\Auth\Middleware\
           EnsureEmailIsVerified::class,
        'jwt.verify' => \App\Http\Middleware\
           JwtMiddleware::class,
    ];
}
```

我们在`$routesMiddleware`关联数组中写入以下代码，注册了`laravel-cors`包中提供的`HandleCors`中间件，并在`$routeMiddleware`关联数组中注册了`jwt.verify`中间件：

```js
'jwt.verify' => \App\Http\Middleware\JwtMiddleware::class,
```

这样，我们可以使用`jwt.verify`中间件来验证令牌。

完整的代码在[`github.com/PacktPublishing/-Vue.js-3-By-Example/blob/master/Chapter08/backend/app/Http/Kernel.php`](https://github.com/PacktPublishing/-Vue.js-3-By-Example/blob/master/Chapter08/backend/app/Http/Kernel.php)。

此外，我们安装`predis`包，这样我们就可以更轻松地与我们的 Redis 数据库进行通信。要安装`predis`包，我们运行以下命令：

```js
composer require predis/predis
```

然后，在`config/database.php`中，我们编写以下代码：

```js
<?php
use Illuminate\Support\Str;
return [
    ...    'redis' => [
        'client' => env('REDIS_CLIENT', 'predis'),
        'options' => [
            'cluster' => env('REDIS_CLUSTER', 'redis'),
            'prefix' => env('REDIS_PREFIX', Str::slug(   
            env('APP_NAME', 'laravel'), '_').'_database_'),
        ],
        ...
        'cache' => [
            'url' => env('REDIS_URL'),
            'host' => env('REDIS_HOST', '127.0.0.1'),
            'password' => env('REDIS_PASSWORD', null),
            'port' => env('REDIS_PORT', '6379'),
            'database' => env('REDIS_CACHE_DB', '1'),
        ],
    ],
];
```

我们在关联数组中配置了 Redis 数据库连接，以便我们可以连接到 Redis。

完整的文件在[`github.com/PacktPublishing/-Vue.js-3-By-Example/blob/master/Chapter08/backend/config/database.php`](https://github.com/PacktPublishing/-Vue.js-3-By-Example/blob/master/Chapter08/backend/config/database.php)。

现在我们已经为存储用户数据和他们的聊天消息创建了 API，我们将继续为 Laravel 应用程序添加实时通信功能，以便用户可以实时保存和获取聊天消息。

# 添加实时通信

现在我们已经完成了添加路由、身份验证和数据库配置和操作代码，我们准备添加让我们在前端和后端实时通信的代码。首先，我们需要在 Laravel 后端创建一个`event`类，这样我们就可以调用`event`函数来广播事件，就像我们在`MessageController`中所做的那样。

为此，我们运行`php artisan make:event MessageSent`命令来创建`MessageSent`事件类。该类现在应该在`backend/app/Events/MessageSent.php`文件中。创建文件后，我们用以下代码替换文件中的内容：

```js
<?php
namespace App\Events;
...
class MessageSent implements ShouldBroadcast
{
    use InteractsWithSockets, SerializesModels;
    public $user;
    public $message;
    public function __construct(User $user, Message 
      $message)
    {
        $this->user = $user;
        $this->message = $message;
    }
    public function broadcastOn()
    {
        return new Channel('chat');
    }
    public function broadcastAs()
    {
        return 'MessageSent';
    }
}
```

`__constructor()`方法是构造函数；我们获取`$user`和`$message`对象，然后将它们分配给同名的类变量。`broadcastOn()`方法返回`Channel`对象，它创建一个我们可以在前端监听的频道。`broadCastAs()`方法返回我们在聊天频道中监听的事件名称。我们将在前端使用这个来监听广播事件。一个`event`类应该实现`ShouldBroadcast`接口，以便可以从中广播事件。

`MessageSent.php`的完整代码位于[`github.com/PacktPublishing/-Vue.js-3-By-Example/blob/master/Chapter08/backend/app/Events/MessageSent.php`](https://github.com/PacktPublishing/-Vue.js-3-By-Example/blob/master/Chapter08/backend/app/Events/MessageSent.php)。

在`backend/routes/channels.php`文件中，我们应该有以下代码，以便所有用户都可以监听聊天频道：

```js
<?php
use Illuminate\Support\Facades\Broadcast;
Broadcast::channel('chat', function () {
    return true;
});
```

第一个参数是我们要订阅的频道的名称。回调是一个函数，如果用户可以监听事件则返回`true`，否则返回`false`。一个可选参数是`user`对象，以便我们可以检查用户是否可以监听给定事件。

此文件的完整代码位于[`github.com/PacktPublishing/-Vue.js-3-By-Example/blob/master/Chapter08/backend/routes/channels.php`](https://github.com/PacktPublishing/-Vue.js-3-By-Example/blob/master/Chapter08/backend/routes/channels.php)。

通信流程如下图所示：

![图 8.1 - 聊天应用程序架构图](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-ex/img/Figure_8.1_B14405.jpg)

图 8.1 - 聊天应用程序架构图

Vue 3 前端通过 HTTP 请求将要发送的消息发送到 Laravel 应用程序。Laravel 应用程序将消息保存到`messages`表中，并带有聊天会话和用户的 ID。它还通过队列向 Redis 服务器广播事件。然后 Laravel Echo 服务器监视 Redis，看是否有任何内容保存到 Redis 数据库。如果有任何新保存的内容，那么 Laravel Echo 服务器将其推送到 Vue 3 前端。Vue 3 前端通过使用 Laravel Echo 客户端和 Socket.IO 客户端监听 Laravel Echo 服务器上的事件来接收它。

# 与 Socket.IO 通信

为了使我们的后端应用通过 Socket.IO 与前端通信，我们需要使用 Laravel Echo Server。为此，我们首先需要全局安装 Laravel Echo Server 的`npm`包。我们可以通过运行`npm install –g laravel-echo-server`来安装它。然后我们将运行这个包来创建配置文件以设置通信。

为此，我们创建一个新文件夹，然后运行`laravel-echo-server init`来运行命令行向导，在文件夹中创建 Laravel Echo Server 配置文件。在这一点上，我们可以用默认设置回答所有问题。这是因为一旦向导完成，我们将编辑它创建的配置文件。

向导完成后，我们应该在文件夹中看到`laraval-echo-server.json`文件。现在我们打开它，并用以下代码替换其中的内容：

```js
{
 "authHost": "http://localhost:8000",
 "authEndpoint": "/broadcasting/auth",
 "clients": [
  {
   "appId": "APP_ID",
   "key": "c84077a4dabd8ab2a60e51b051c9d0ea"
  }
 ...
  },
  "sqlite": {
   "databasePath": "/database/laravel-echo-server.sqlite"
  },
  "publishPresence": true
 },
 "devMode": true,
 "host": "127.0.0.1",
 ...
 "http": true,
  "redis": true
 },
 "apiOriginAllow": {
  "allowCors": true,
  "allowOrigin": "*",
  "allowMethods": "GET, POST",
  "allowHeaders": "Origin, Content-Type, X-Auth-Token,     X-Requested-With, Accept, Authorization, X-CSRF-TOKEN,     X-Socket-Id"
 }
}
```

在上述代码中，我们有配置的 JSON 代码，以便 Laravel Echo Server 可以监听保存在 Redis 中的项目，然后通过 Socket.IO 客户端将 Redis 数据库中的内容发送到前端。`devMode`属性设置为`true`，以便我们可以看到所有发送的事件。主机具有 Laravel Echo Server 的主机 IP 地址。`port`属性设置为`6001`，因此此服务器将监听 6001 端口。此文件的另一个重要部分是`apiOriginAllow`属性。它设置为一个对象，其中`allowCors`设置为`true`，以便我们可以与前端进行跨域通信。

`allowOrigin`属性让我们设置允许监听发出的事件的域。`allowMethods`属性具有允许从前端接收的 HTTP 方法。`allowHeaders`属性具有允许从前端发送到 Laravel Echo Server 的 HTTP 请求标头列表。

`authHost`具有 Laravel 应用的基本 URL，以便它可以监听 Laravel 应用广播的事件。`authEndpoint`具有用于检查用户是否经过身份验证以便监听需要身份验证的事件的身份验证端点。

这个配置文件的另一个重要部分是数据库配置属性。数据库属性设置为``"redis"``，以便它将监听 Redis 服务器以保存项目。`databaseConfig`属性具有设置，让我们连接到 Redis 服务器。``"redis"``属性设置为一个对象，其中``port``属性设置为 Redis 服务器监听的`端口`。Redis 的默认端口是`6379`。`host`属性是 Redis 服务器的位置。`publishPresence`属性设置为`true`，以便 Redis 发布保存在其数据库中的项目。

完整的配置在[`github.com/PacktPublishing/-Vue.js-3-By-Example/blob/master/Chapter08/laravel-echo-server/laravel-echo-server.json`](https://github.com/PacktPublishing/-Vue.js-3-By-Example/blob/master/Chapter08/laravel-echo-server/laravel-echo-server.json)。

Redis 的最新版本仅适用于 Linux 或 macOS。要在 Ubuntu Linux 上安装 Redis，请运行以下命令安装 Redis 服务器：

```js
sudo apt update
sudo apt install redis-server
```

如果您使用的是 Windows 10，可以使用 Windows 子系统来安装 Ubuntu Linux 的副本，以便运行最新版本的 Redis。要在 Windows 10 上安装 Ubuntu，请执行以下操作：

1.  在**开始**菜单中键入`打开或关闭 Windows 功能`。

然后我们滚动到底部，点击**Windows 子系统用于 Linux**进行安装。它会要求您重新启动，您应该在继续之前这样做。

1.  计算机重新启动后，转到**Windows 商店**，搜索**Ubuntu**，然后您可以点击它并点击**获取**。

1.  安装完成后，您可以在**开始**菜单中键入`Ubuntu`并启动它。现在只需按照说明完成安装。

然后您可以运行上述两个命令来安装 Redis。

安装完 Redis 后，我们运行以下命令来运行 Redis 服务器：

```js
redis-server
```

现在我们项目的后端部分已经完成。现在我们运行`php artisan serve`和`php artisan queue:listen`来运行 Laravel 应用程序和队列工作程序。我们还必须运行 Laravel Echo Server，通过运行`laravel-echo-server start`来启动 Laravel Echo Server。

如果遇到任何问题，您可能需要清除缓存以确保最新的代码实际在运行。要做到这一点，您可以运行以下命令来清除所有缓存：

```js
php artisan config:cache
php artisan config:clear
php artisan route:cache
php artisan route:clear
```

如果缓存已清除，代码仍然无法正常工作，那么您可以返回检查代码。

现在我们已经为我们的 Laravel 应用程序添加了实时通信，我们准备继续创建前端，让用户注册帐户，登录并在聊天室中开始聊天。

# 创建前端以让用户聊天

现在我们已经完成并运行了后端代码，我们可以开始工作在前端。前端与前几章的内容并没有太大的不同。我们使用 Vue CLI 在`vue-example-ch8-chat-app`文件夹的`frontend`文件夹中创建我们的项目，然后我们可以开始编写我们的代码。

在“vue-example-ch8-chat-app / frontend”文件夹中，我们运行`vue create`，然后选择**选择版本**，然后选择启用**Vue Router**选项的**Vue 3**选项。一旦 Vue CLI 向导完成运行，我们就可以开始构建我们的前端。

## 安装 Vue 依赖项

除了 Vue 依赖项之外，我们还需要安装 Axios HTTP 客户端、Socket.IO 客户端和 Laravel Echo 客户端包，以通过 Laravel Echo 服务器分别进行 HTTP 请求和监听从服务器端发出的事件。要安装这些，我们运行以下命令：

```js
npm install axios socket.io-client laravel-echo
```

首先，在`src`文件夹中，我们创建`constants.js`文件并添加以下代码：

```js
export const APIURL = 'http://localhost:8000';
```

我们添加了`APIURL`常量，当我们向 API 端点发出请求时将使用它。在`src/main.js`中，我们用以下代码替换我们已有的代码：

```js
...
axios.interceptors.request.use((config) => {
  if (config.url.includes('login') || 
   config.url.includes('register')) {
    return config;
  }
  return {
    ...config, headers: {
      Authorization: `Bearer ${localStorage.getItem('token')}`,
    }
  }
}, (error) => {
  return Promise.reject(error);
});
axios.interceptors.response.use((response) => {
  const { data: { status } } = response;
  if (status === 'Token is Expired') {
    router.push('/login');
  }
  return response;
}, (error) => {
  return Promise.reject(error);
});
createApp(App).use(router).mount('#app')
```

在这个文件中有两件新事物。我们有 Axios 请求和响应拦截器，这样我们就可以在每次请求时应用相同的设置，而不必重复相同的代码。`axios.interceptors.request.use（）`方法接受一个回调，让我们根据需要返回一个新的`config`对象。

如果请求的 URL 不包括“登录”或“注册”，那么我们需要将令牌添加到`Authorization`标头中。这就是我们在传递给“use（）”方法的回调中所做的。我们将令牌添加到需要它们的端点的请求配置中。第二个回调是一个错误处理程序，我们只是返回一个拒绝的承诺，这样我们就可以在发出请求时处理它们。

类似地，我们有`axios.interceptor.response.use()`方法来检查每个响应，并使用第一个参数中的回调函数。我们检查响应体是否具有将`status`属性设置为`"Token is expired"`字符串，以便在收到此消息时重定向到登录页面并返回响应。否则，我们原样返回响应。第二个参数中的错误处理程序与请求拦截器相同。

## 创建我们的组件

接下来，我们创建我们的组件。我们从表单开始，让我们设置或编辑聊天室名称。为此，我们进入`src/components`文件夹并创建`ChatroomForm.vue`文件。然后，在文件中，我们编写以下代码：

```js
<template>
  <div>
    <h1>{{ edit ? "Edit" : "Add" }} Chatroom</h1>
    <form @submit.prevent="submit">
      <div class="form-field">
        <label for="name">Name</label>
        <br />
        <input v-model="form.name" type="text" name="name" 
          />
      </div>
      <div>
        <input type="submit" />
      </div>
    </form>
  </div>
</template>
...
```

该组件接受`edit`属性，其类型为布尔值，以及`id`属性，其类型为字符串。它有一个响应式属性，即`form`属性。它用于将输入值绑定到响应式属性。我们有`submit()`方法来检查名称是否已填写。如果是，则我们继续提交。如果`edit`属性为 true，则我们进行 PUT 请求以更新`chats`表中具有给定 ID 的现有条目。否则，我们在相同的表中创建一个具有给定名称值的新条目。完成后，我们重定向到具有聊天室列表的主页。

在`created`钩子中，我们检查`edit`响应式属性是否为 true。如果是，则我们获取具有给定 ID 的`chats`表中的条目，并将其设置为`form`响应式属性的值，以便我们可以在输入框中看到`form.name`属性的值：

```js
<script>
import axios from "axios";
import { APIURL } from "../constants";
export default {
  name: "ChatroomForm",
  ...
  async created() {
    if (this.edit) {
      const { data } = await 
       axios.get(`${APIURL}/api/chat/${this.id}`);
      this.form = data;
    }
  },
 };
</script>
```

接下来，在`src/components`文件夹中，我们创建`NavBar.vue`来创建一个渲染导航栏的组件。在文件内，我们编写以下代码：

```js
<template>
  <div>
    <ul>
      <li>
        <router-link to="/">Chatrooms</router-link>
      </li>
      <li><a href="#" @click="logOut">Logout</a></li>
    </ul>
  </div>
</template>
<script>
import axios from "axios";
import { APIURL } from "../constants";
export default {
  name: "NavBar",
  methods: {
    async logOut() {
      await axios.post(`${APIURL}/api/auth/logout`);
      localStorage.clear();
      this.$router.push("/login");
    },
  },
};
</script>
...
```

我们有一个`router-link`组件，可以转到**聊天室**页面。这是通过将`to`属性设置为`/`路由来实现的。我们还有一个链接，当我们点击它时调用`logout()`方法。`logout()`方法发出 POST 请求到`/api/auth/logOut`端点来使 JSON web token 失效。然后我们调用`localStorage.clear()`方法来清除本地存储。然后我们调用`this.$router.push`来重定向到登录页面。

在样式部分，我们为`ul`和`li`元素设置了一些样式，使`li`水平显示，并在它们之间设置了一些边距。我们还将`list-style-type`属性设置为`none`，以便从列表中移除项目符号：

```js
<style scoped>
ul {
  list-style-type: none;
}
ul li {
  display: inline;
  margin-right: 10px;
}
</style>
```

在`src/views`文件夹中，我们有页面组件，我们使用 Vue Router 将其映射到 URL，以便我们可以从浏览器访问这些组件。首先，在`src/views`文件夹中创建`AddChatroomForm.vue`组件文件，并添加以下代码：

```js
<template>
  <div>
    <NavBar></NavBar>
    <ChatroomForm></ChatroomForm>
  </div>
</template>
<script>
import ChatroomForm from "@/components/ChatroomForm";
import NavBar from "@/components/NavBar";
export default {
  components: {
    ChatroomForm,
    NavBar
  },
};
</script>
```

我们只需在`components`属性中注册`NavBar`和`ChatroomForm`组件，然后将它们添加到模板中。

接下来，我们创建`ChatRoom.vue`组件来显示我们的聊天消息，并在此文件中添加代码来监听从 Laravel 应用程序通过 Redis 数据库和 Laravel Echo 服务器发出的`laravel_database_chat`频道的`MessageSent`事件。在此文件中，我们编写以下代码：

```js
...
<script>
import axios from "axios";
import { APIURL } from "../constants";
import NavBar from "@/components/NavBar";
export default {
  name: "Chatroom",
  components: {
    NavBar,
  },
  beforeMount() {
    this.getChatMessages();
    this.addChatListener();
  },
  data() {
    return {
      chatMessages: [],
      message: "",
    };
  },
  ...};
</script>
```

然后，我们在同一文件中添加方法来获取和发送聊天消息，编写以下代码：

```js
...
<script>
...
export default {
  ...
  methods: {
    async getChatMessages() {
      const { id } = this.$route.params;
      const { data } = await 
        axios.get(`${APIURL}/api/message/${id}`);
      this.chatMessages = data;
      this.$nextTick(() => {
        const container = this.$refs.container;
        container.scrollTop = container.scrollHeight;
      });
    },
    async sendChatMessage() {
      const { message } = this;
      if (!message) {
        return;
      }
      const { id: chat_id } = this.$route.params;
        ...
        () => {
          this.getChatMessages();
        }
      );
    },
  },
</script>
```

`getChatMessages`方法从 API 获取聊天室的聊天消息，`sendChatMessage`方法通过向 API 发出 HTTP 请求提交聊天消息来向聊天室发送消息。然后，API 端点会通过 Laravel Echo 服务器将消息发送到队列，然后返回到此应用中使用的 Socket.IO 聊天客户端。我们调用`addChatListener`来监听服务器发送的`laravel_database_chat`事件，该事件调用`getChatMessages`以获取最新消息。

组件模板只是使用`v-for`指令来渲染`chatMessages`响应式属性的每个条目并将它们呈现出来。以下代码中的`form`元素用于让我们输入消息，然后通过发出 HTTP 请求将其提交到 Laravel。端点将消息保存到`messages`表，并且还会触发一个我们监听的事件，该事件通过 Redis 数据库和 Laravel Echo 服务器发送。前端只从实时通信的角度了解 Laravel Echo 服务器：

```js
<template>
  <div>
    <NavBar></NavBar>
    <h1>Chatroom</h1>
    <div id="chat-messages" ref="container">
      <div class="row" v-for="m of chatMessages" 
        :key="m.id">
        <div>
          <b>{{ m.user.name }} - {{ m.created_at }}</b>
        </div>
        <div>{{ m.message }}</div>
      </div>
    </div>
    <form @submit.prevent="sendChatMessage">
      <div class="form-field">
        <label for="message">Message</label>
        <br />
        <input v-model="message" type="text" name="message"
           />
      </div>
      <div>
        <input type="submit" />
      </div>
    </form>
  </div>
</template>
```

在`component`对象中，我们有`beforeMount`钩子来调用`getChatMessage`方法来获取聊天消息。`addChatListener()`方法使用 Socket.IO 客户端创建事件侦听器，让我们监听从 Laravel Echo 服务器发出的事件。在`getChatMessage()`方法中，我们调用`this.$nextTick()`方法并带有一个回调，以便我们在获取消息后始终滚动到包含消息的`div`标签的底部。我们在`$nextTick`回调中运行该代码，因为我们需要确保滚动代码在所有消息都呈现后运行。

`this.$nextTick()`方法让我们在响应式属性更新后等待组件重新渲染，然后再运行回调中的代码。

在`addChatListener()`方法中，我们订阅了`laravel_database_chat`频道，这与我们在 Laravel 应用程序中定义的聊天频道相同。我们可以通过观察 Laravel Echo Server 的输出来确保我们订阅了正确的频道。`.MessageSent`事件与我们在后端应用程序中定义的事件相同。事件名称前的点是必需的，以便它在正确的命名空间中监听到正确的事件。在我们传递给监听器的回调函数中，我们调用`this.getChatMessages()`来获取最新的消息。

聊天消息的容器高度设置为 300px，这样当我们有太多消息时，它不会太高。它还让我们在有足够的消息溢出容器时滚动到底部：

```js
<style scoped>
#chat-messages {
  height: 300px;
  overflow-y: scroll;
}
.row {
  display: flex;
  flex-wrap: wrap;
}
.row div:first-child {
  width: 30%;
}
</style>
```

接下来，在`src/views`文件夹中，我们通过编写以下代码创建`Chatrooms.vue`组件文件：

```js
<template>
  <div>
    <NavBar></NavBar>
    <h1>Chatrooms</h1>
    <button @click="createChatRoom">Create Chatroom
      </button>
    <table id="table">
      <thead>
        <tr>
          <th>Name</th>
          <th>Go</th>
          <th>Edit</th>
          <th>Delete</th>
...
  beforeMount() {
    this.getChatRooms();
  },
};
</script>
<style scoped>
#table {
  width: 100%;
...
</style>
```

我们渲染了一个包含我们可以进入、编辑名称或删除的聊天室列表的表格。该方法只是获取聊天室数据，并转到编辑具有给定 ID 的聊天室的路由，添加聊天室的路由，重定向到具有给定 ID 的聊天室页面的路由，以及删除聊天室的路由。当我们删除聊天室时，我们再次使用`getChatRooms()`方法获取最新条目，以便获取最新数据。

我们在`beforeMount`钩子中获取聊天室列表，以便在页面加载时看到表格条目。接下来，在相同的文件夹中，我们创建`EditChatroomForm.vue`文件并添加以下代码：

```js
<template>
  <div>
    <NavBar></NavBar>
    <ChatroomForm edit :id="$route.params.id">
      </ChatroomForm>
  </div>
</template>
<script>
import ChatroomForm from "@/components/ChatroomForm";
import NavBar from "@/components/NavBar";
export default {
  components: {
    ChatroomForm,
    NavBar,
  },
};
</script>
```

它与`AddChatroomForm.vue`文件具有相同的内容，但是`ChatroomForm`上的`edit`属性设置为`true`，`id`属性设置为从 Vue Router 获取的`id` URL 参数。

## 创建登录页面

接下来，我们通过创建`src/views/Login.vue`并添加以下代码来创建登录页面：

```js
<template>
  <div>
    <h1>Login</h1>
    <form @submit.prevent="login">
      <div class="form-field">
        <label for="email">Email</label>
        <br />
        <input v-model="form.email" type="email" name="email" />
      </div>
      <div class="form-field">
        <label for="password">Password</label>
        <br />
        <input v-model="form.password" type="password"            name="password" />
      </div>
      <div>
        <input type="submit" value="Log in" />
        <button type="button" @click="goToRegister">Register</            button>
      </div>
    </form>
  </div>
</template>
<script>
import axios from "axios";
import { APIURL } from "../constants";
export default {
  name: "Login",
  data() {
    return {
      form: {
        email: "",
        password: "",
      },
    };
  },
  methods: {
    async login() {
      const { email, password } = this.form;
      if (!email || !password) {
        alert("Email and password are required");
        return;
      }
      try {
        const {
          data: { access_token },
        } = await axios.post(`${APIURL}/api/auth/login`, {
          email,
          password,
        });
        localStorage.setItem("token", access_token);
        this.$router.push("/");
      } catch (error) {
        alert("Invalid username or password");
      }
    },
    goToRegister() {
      this.$router.push("/register");
    },
  },
};
</script>
```

模板只有一个登录表单，用于输入电子邮件和密码以便我们登录。当我们提交表单时，将调用`login()`方法。它首先检查所有字段是否填写正确，然后使用凭据向`/api/auth/login`路由发出 HTTP 请求，以查看我们是否可以登录。

表单还有一个`Register.vue`文件，用于转到**注册**页面，以便我们可以注册账户并加入聊天室。

我们需要创建的最后一个页面是用于容纳注册表单的页面。为了创建它，我们编写以下代码：

```js
<template>
  <div>
    <h1>Register</h1>
    <form @submit.prevent="register">
      <div class="form-field">
        <label for="email">Name</label>
        <br />
        <input v-model="form.name" type="text" name="name"
          />
      </div>
      <div class="form-field">
        <label for="email">Email</label>
        <br />
        <input v-model="form.email" type="email" 
          name="email" />
      </div>
      <div class="form-field">
        <label for="password">Password</label>
        <br />
          …
          name,
          email,
          password,
          password_confirmation: confirmPassword,
        });
        this.$router.push("/login");
      } catch (error) {
        alert("Invalid username or password");
      }
    },
  },
};
</script>
```

表格中有**姓名**、**电子邮件**、**密码**和**确认密码**字段，所有这些字段都是注册账户所必需的。当我们提交表格时，我们调用`register()`方法。我们对字段进行检查，以查看它们是否填写正确。调用`email`正则表达式上的`test()`方法来检查有效的电子邮件地址。如果有效，则`test()`方法返回`true`。否则，它返回`false`。我们还检查密码是否与`confirmPassword`变量相同。如果一切正常，我们就会发出 POST 请求来注册用户账户。

在`src/App.vue`中，我们用以下代码替换现有内容，以添加`router-view`组件，以便我们可以从`src/views`文件夹中看到路由组件：

```js
<template>
  <div>
    <router-view />
  </div>
</template>
<style scoped>
div {
  width: 70vw;
  margin: 0 auto;
}
</style>
<style>
.form-field input {
  width: 100%;
}
</style>
```

然后，在`src/router/index.js`文件中，我们用以下代码替换现有内容，以注册所有路由，并使用 Laravel Echo 库创建`Socket.io`事件来监听：

```js
...
window.io = require('socket.io-client');
const beforeEnter = (to, from, next) => {
  const hasToken = Boolean(localStorage.getItem('token'));
  if (!hasToken) {
    return next({ path: 'login' });
  }
  next();
}
const routes = [
  {
...
    path: '/edit-chatroom/:id',
    name: 'edit-chatroom/:id',
    component: EditChatroomForm,
    beforeEnter
  },
]
...
export default router
```

Laravel Echo 客户端与 Socket.IO 客户端一起使用，以便我们可以监听从 Laravel Echo 服务器广播的事件。`broadcaster`属性设置为`'socket.io'`，以便我们可以监听来自 Laravel Echo 服务器的事件。`host`属性设置为 Laravel Echo 服务器的 URL。

此外，我们还有`beforeEnter`导航守卫，我们在之前的章节中已经看到了，当我们需要限制路由仅在身份验证成功后才可用时。我们只需检查令牌是否存在。如果存在，我们调用`next`来继续下一个路由。否则，我们重定向到登录页面。

现在我们可以通过运行`npm run serve`来运行前端，就像我们在所有其他项目中所做的那样。现在我们应该看到类似以下屏幕截图的东西。以下屏幕截图显示了**聊天室**用户界面：

![图 8.2 – 聊天室的屏幕截图](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-ex/img/Figure_8.2_B14405.jpg)

图 8.2 – 聊天室的屏幕截图

以下屏幕截图是 Laravel Echo 服务器的工作情况。我们应该看到广播的事件名称以及发送的频道：

![图 8.3 – 当聊天事件发送到前端时，Redis 的输出](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-ex/img/Figure_8.3_B14405.jpg)

图 8.3 – 当聊天事件发送到前端时，Redis 的输出

以下屏幕截图是队列事件的日志：

![图 8.4 - Laravel 事件的输出](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-ex/img/Figure_8.4_B14405.jpg)

图 8.4 - Laravel 事件的输出

我们通过在`backend`文件夹中运行`php artisan queue:listen`来启动队列，该文件夹是 Laravel 项目所在的文件夹。

现在我们已经让聊天应用的前端工作了，我们使用 Laravel 和 Vue 创建了一个简单的聊天系统。

# 总结

在本章中，我们看了如何使用 Laravel 和 Vue 构建聊天应用。我们用 Laravel 构建了后端，并添加了控制器来接收请求。我们还使用了 Laravel 内置的队列系统将数据发送到前端。我们还在我们的 Laravel 应用中添加了 JSON Web Token 身份验证。

在前端，我们使用 Socket.IO 客户端来监听从 Laravel Echo 服务器发送的事件，该服务器通过 Redis 从 Laravel 获取数据。

现在我们已经通过 Vue 3 项目的各种难度，可以将我们在这里学到的东西应用到现实生活中。现实生活中的 Vue 应用几乎总是会向服务器发出 HTTP 请求。Axios 库使这变得容易。一些应用还会与服务器实时通信，就像本章中的聊天应用一样。

唯一的区别在于，在现实生活中的应用中，会有检查来查看用户是否经过身份验证并且被授权将数据发送到服务器。
