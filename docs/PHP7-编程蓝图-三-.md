# PHP7 编程蓝图（三）

> 原文：[`zh.annas-archive.org/md5/27faa03af47783c6370aa5ff8894925f`](https://zh.annas-archive.org/md5/27faa03af47783c6370aa5ff8894925f)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：构建聊天应用程序

在本章中，我们将使用**WebSocket**构建一个实时聊天应用程序。您将学习如何使用**Ratchet**框架使用 PHP 构建独立的 WebSocket 和 HTTP 服务器，以及如何在 JavaScript 客户端应用程序中连接到 WebSocket 服务器。我们还将讨论如何为 WebSocket 应用程序实现身份验证以及如何在生产环境中部署它们。

# WebSocket 协议

在本章中，我们将广泛使用 WebSocket。为了充分理解我们将要构建的聊天应用程序的工作原理，让我们首先看一下 WebSocket 的工作原理。

WebSocket 协议在**RFC 6455**中指定，并使用 HTTP 作为底层传输协议。与传统的请求/响应范式相比，在该范式中，客户端向服务器发送请求，服务器然后回复响应消息，WebSocket 连接可以保持打开很长时间，服务器和客户端都可以在 WebSocket 上发送和接收消息（或*数据帧*）。

WebSocket 连接始终由客户端（通常是用户的浏览器）发起。下面的清单显示了浏览器可能发送给支持 WebSocket 的服务器的示例请求：

```php
GET /chat HTTP/1.1 
Host: localhost 
**Upgrade: websocketConnection: upgrade** 
Origin: http://localhost 
**Sec-WebSocket-Key: de7PkO6qMKuGvUA3OQNYiw==** 
**Sec-WebSocket-Protocol: chat** 
**Sec-WebSocket-Version: 13**

```

就像常规的 HTTP 请求一样，请求包含一个请求方法（`GET`）和一个路径（`/chat`）。`Upgrade`和`Connection`头告诉服务器，客户端希望将常规 HTTP 连接升级为 WebSocket 连接。

`Sec-WebSocket-Key`头包含一个随机的、base64 编码的字符串，唯一标识这个单个 WebSocket 连接。`Sec-WebSocket-Protocol`头可以用来指定客户端想要使用的子协议。子协议可以用来进一步定义服务器和客户端之间的通信应该是什么样子的，并且通常是特定于应用程序的（在我们的情况下，是`chat`协议）。

当服务器接受升级请求时，它将以`101 Switching Protocols`响应作为响应，如下面的清单所示：

```php
HTTP/1.1 101 Switching Protocols 
Upgrade: websocket 
Connection: Upgrade 
Sec-WebSocket-Accept: BKb5cchTfWayrC7SKtvK5yW413s= 
Sec-WebSocket-Protocol: chat 

```

`Sec-WebSocket-Accept`头包含了来自请求的`Sec-WebSocket-Key`的哈希值（确切的哈希值在 RFC 6455 中指定）。响应中的`Sec-WebSocket-Protocol`头确认了服务器理解客户端在请求中指定的协议。

完成这个握手之后，连接将保持打开状态，服务器和客户端都可以从套接字发送和接收消息。

# 使用 Ratchet 的第一步

在本节中，您将学习如何安装和使用 Ratchet 框架。需要注意的是，Ratchet 应用程序的工作方式与部署在 Web 服务器上并且基于每个请求工作的常规 PHP 应用程序不同。这将要求您采用一种新的思考方式来运行和部署 PHP 应用程序。

## 架构考虑

使用 PHP 实现 WebSocket 服务器并不是一件简单的事情。传统上，PHP 的架构围绕着经典的请求/响应范式：Web 服务器接收请求，将其传递给 PHP 解释器（通常内置于 Web 服务器中或由进程管理器（如 PHP-FPM）管理），解析请求并将响应返回给 Web 服务器，然后 Web 服务器再响应客户端。PHP 脚本中数据的生命周期仅限于单个请求（这一原则称为**共享无状态**）。

这对于传统的 Web 应用程序非常有效；特别是共享无状态原则，因为这是 PHP 应用程序通常很好扩展的原因之一。然而，对于 WebSocket 支持，我们需要一种不同的范式。客户端连接需要保持打开状态很长时间（可能是几个小时，甚至几天），服务器需要在连接的整个生命周期内随时对客户端消息做出反应。

实现这种新范式的一个库是我们在本章中将要使用的`Ratchet`库。与常规的 PHP 运行时不同，它们存在于 Web 服务器中，Ratchet 将启动自己的 Web 服务器，可以为长时间运行的 WebSocket 连接提供服务。由于您将处理具有极长运行时间的 PHP 进程（服务器进程可能运行数天、数周或数月），因此您需要特别注意诸如内存消耗之类的事项。

## 入门

使用**Composer**可以轻松安装 Ratchet。它需要至少版本为 5.3.9 的 PHP，并且也与 PHP 7 兼容。首先，在项目目录的命令行上使用`composer init`命令初始化一个新项目： 

```php
**$ composer init .**

```

接下来，将 Ratchet 添加为项目的依赖项：

```php
**$ composer require cboden/ratchet**

```

此外，通过向生成的`composer.json`文件添加以下部分来配置 Composer 的自动加载器：

```php
'autoload': { 
  'PSR-4': { 
    'Packt\Chp6\Example': 'src/' 
  } 
} 

```

像往常一样，PSR-4 自动加载意味着 Composer 类加载器将在项目目录的`src/`文件夹中查找`Packt\Chp6\Example`命名空间的类。一个（假设的）`Packt\Chp6\Example\Foo\Bar`类需要在`src/Foo/Bar.php`文件中定义。

由于 Ratchet 实现了自己的 Web 服务器，您将不需要专用的 Web 服务器，如**Apache**或**Nginx**（目前）。首先创建一个名为`server.php`的文件，在其中初始化和运行 Ratchet Web 服务器：

```php
$app = new \Ratchet\App('localhost', 8080, '0.0.0.0'); 
$app->run() 

```

然后，您可以启动您的 Web 服务器（它将侦听您在`Ratchet\App`构造函数的第二个参数中指定的端口）使用以下命令：

```php
**$ php server.php**

```

如果您的计算机上没有准备好 PHP 7 安装，您可以使用以下命令快速开始使用**Docker**：

```php
**$ docker run --rm -v $PWD:/opt/app -p 8080:8080 php:7 php /opt/app/server.php**

```

这两个命令都将启动一个长时间运行的 PHP 进程，可以直接在命令行上处理 HTTP 请求。在后面的部分中，您将学习如何将应用程序部署到生产服务器上。当然，这个服务器实际上并没有做太多事情。但是，您仍然可以使用 CLI 命令或浏览器进行测试，如下面的屏幕截图所示：

![入门](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-bp/img/image_06_001.jpg)

使用 HTTPie 测试示例应用程序

让我们继续向我们的服务器添加一些业务逻辑。由 Ratchet 提供服务的 WebSocket 应用程序需要是实现`Ratchet\MessageComponentInterface`的 PHP 类。此接口定义了以下四种方法：

+   `onOpen(\Ratchet\ConnectionInterface $c)`将在新客户端连接到 WebSocket 服务器时调用

+   `onClose(\Ratchet\ConnectionInterface $c)`将在客户端从服务器断开连接时调用

+   `onMessage(\Ratchet\ConnectionInterface $sender, $msg)`将在客户端向服务器发送消息时调用

+   `onError(\Ratchet\ConnectionInterface $c, \Exception $e)`将在处理消息时发生异常时调用

让我们从一个简单的例子开始：一个 WebSocket 服务，客户端可以向其发送消息，它将以相同的消息但是反向的方式回复给同一个客户端。让我们称这个类为`Packt\Chp6\Example\ReverseEchoComponent`；代码如下：

```php
namespace Packt\Chp6\Example; 

use Ratchet\ConnectionInterface; 
use Ratchet\MessageComponentInterface; 

class ReverseEchoComponent implements MessageComponentInterface 
{ 
    public function onOpen(ConnectionInterface $conn) 
    {} 

    public function onClose(ConnectionInterface $conn) 
    {} 

    public function onMessage(ConnectionInterface $sender, $msg) 
    {} 

    public function onError(ConnectionInterface $conn, 
                            Exception $e) 
    {} 
} 

```

请注意，尽管我们不需要`MessageComponentInterface`指定的所有方法，但我们仍然需要实现所有这些方法，以满足接口。例如，如果在客户端连接或断开连接时不需要发生任何特殊的事情，则实现`onOpen`和`onClose`方法，但只需将它们留空即可。

为了更好地理解此应用程序中发生的情况，请向`onOpen`和`onClose`方法添加一些简单的调试消息，如下所示：

```php
public function onOpen(ConnectionInterface $conn) 
{ 
    echo "new connection from " . $conn->remoteAddress . "\n"; 
} 

public function onClose(ConnectionInterface $conn) 
{ 
    echo "connection closed by " . $conn->remoteAddress . "\n"; 
} 

```

接下来，实现`onMessage`方法。`$msg`参数将包含客户端发送的消息作为字符串，并且您可以使用`ConnectionInterface`类的`send()`方法将消息发送回客户端，如下面的代码片段所示：

```php
public function onMessage(ConnectionInterface $sender, $msg) 
{ 
    echo "received message '$msg' from {$conn->remoteAddress}\n"; 
    $response = strrev($msg); 
    $sender->send($response); 
} 

```

### 提示

您可能倾向于使用 PHP 7 的新类型提示功能来提示`$msg`参数为`string`。在这种情况下，这是行不通的，因为它会改变由`Ratchet\MessageComponentInterface`规定的方法接口，并导致致命错误。

然后，您可以使用以下代码在`server.php`文件中将您的 WebSocket 应用程序注册到`Ratchet\App`实例中：

```php
$app = new \Ratchet\App('localhost', 8080, '0.0.0.0'); 
**$app->route('/reverse', new Packt\Chp6\Example\ReverseEchoComponent);** 
$app->run(); 

```

## 测试 WebSocket 应用程序

为了测试 WebSocket 应用程序，我可以推荐**wscat**工具。它是一个用 JavaScript 编写的命令行工具（因此需要在您的计算机上运行 Node.js），可以使用`npm`进行安装，如下所示：

```php
**$ npm install -g wscat**

```

使用 WebSocket 服务器监听端口`8080`，您可以使用以下 CLI 命令使用`wscat`打开新的 WebSocket 连接：

```php
**$ wscat -o localhost --connect localhost:8080/reverse**

```

这将打开一个命令行提示符，您可以在其中输入要发送到 WebSocket 服务器的消息。还将显示从服务器接收到的消息。请参见以下屏幕截图，了解 WebSocket 服务器和 wscat 的示例输出：

![测试 WebSocket 应用程序](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-bp/img/image_06_002.jpg)

使用 wscat 测试 WebSocket 应用程序

## 玩转事件循环

在前面的示例中，您只在收到来自同一客户端的消息后才向客户端发送消息。这是在大多数情况下都能很好地工作的传统请求/回复通信模式。但是，重要的是要理解，当使用 WebSocket 时，您并不被强制遵循这种模式，而是可以随时向连接的客户端发送消息。

为了更好地了解您在 Ratchet 应用程序中拥有的可能性，让我们来看看 Ratchet 的架构。Ratchet 是建立在 ReactPHP 之上的；一个用于网络应用程序的事件驱动框架。React 应用程序的核心组件是**事件循环**。应用程序中触发的每个事件（例如，当新用户连接或向服务器发送消息时）都存储在队列中，事件循环处理存储在此队列中的所有事件。

ReactPHP 提供了不同的事件循环实现。其中一些需要安装额外的 PHP 扩展，如`libevent`或`ev`（通常，基于`libevent`、`ev`或类似扩展的事件循环提供最佳性能）。通常，像 Ratchet 这样的应用程序会自动选择要使用的事件循环实现，因此如果您不想要关心 ReactPHP 的内部工作，通常不需要担心。

默认情况下，Ratchet 应用程序会创建自己的事件循环；但是，您也可以将自己创建的事件循环注入到`Ratchet\App`类中。

所有 ReactPHP 事件循环都必须实现接口`React\EventLoop\LoopInterface`。您可以使用类`React\EventLoop\Factory`自动创建一个在您的环境中受支持的此接口的实现：

```php
$loop = \React\EventLoop\Factory::create(); 

```

然后，您可以将这个`$loop`变量传递到您的 Ratchet 应用程序中：

```php
$app = new \Ratchet\App('localhost', 8080, '0.0.0.0', $loop) 
$app->run(); 

```

直接访问事件循环允许您实现一些有趣的功能。例如，您可以使用事件循环的`addPeriodicTimer`函数注册一个回调，该回调将在周期性间隔内由事件循环执行。让我们在一个简短的示例中使用这个特性，通过构建一个名为`Packt\Chp6\Example\PingComponent`的新 WebSocket 组件：

```php
namespace Packt\Chp6\Example; 

use Ratchet\MessageComponentInterface; 
use React\EventLoop\LoopInterface; 

class PingCompoment extends MessageComponentInterface 
{ 
    private $loop; 
    private $users; 

    public function __construct(LoopInterface $loop) 
    { 
        $this->loop  = $loop; 
        $this->users = new \SplObjectStorage(); 
    } 

    // ... 
} 

```

在这个例子中，`$users`属性将帮助我们跟踪连接的用户。每当新客户端连接时，我们可以使用`onOpen`事件将连接存储在`$users`属性中，并使用`onClose`事件来移除连接：

```php
public function onOpen(ConnectionInterface $conn) 
{ 
 **$this->users->attach($conn);** 
} 

public function onClose(ConnectionInterface $conn) 
{ 
 **$this->users->detach($conn);** 
} 

```

由于我们的 WebSocket 组件现在知道了连接的用户，我们可以使用事件循环来注册一个定时器，定期向所有连接的用户广播消息。这可以很容易地在构造函数中完成：

```php
public function __construct(LoopInterface $loop) 
{ 
    $this->loop  = $loop; 
    $this->users = new \SplObjectStorage(); 

 **$i = 0;** 
 **$this->loop->addPeriodicTimer(5, function() use (&$i) {** 
 **foreach ($this->users as $user) {** 
 **$user->send('Ping ' . $i);** 
 **}** 
 **$i ++;** 
 **});** 
} 

```

传递给 `addPeriodicTimer` 的函数将每五秒钟被调用一次，并向每个连接的用户发送一个带有递增计数器的消息。修改您的 `server.php` 文件，将这个新组件添加到您的 Ratchet 应用程序中：

```php
$loop = \React\EventLoop\Factory::create(); 
$app = new \Ratchet\App('localhost', 8080, '0.0.0.0', $loop) 
**$app->route('/ping', new PingCompoment($loop));** 
$app->run(); 

```

您可以再次使用 wscat 测试这个 WebSocket 处理程序，如下截图所示：

![Playing with the event loop](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-bp/img/image_06_003.jpg)

定期事件循环计时器发送的周期性消息

这是一个很好的例子，说明了 WebSocket 客户端在没有明确请求的情况下从服务器接收更新。这提供了有效的方式，以几乎实时地向连接的客户端推送新数据，而无需重复轮询信息。

# 实现聊天应用程序

在这个关于使用 WebSocket 进行开发的简短介绍之后，让我们现在开始实现实际的聊天应用程序。聊天应用程序将由使用 Ratchet 构建的 PHP 服务器端应用程序和在用户浏览器中运行的基于 HTML 和 JavaScript 的客户端组成。

## 启动项目服务器端

如前一节所述，基于 ReactPHP 的应用程序在与事件循环扩展（如 `libevent` 或 `ev`）一起使用时将获得最佳性能。不幸的是，`libevent` 扩展与 PHP 7 不兼容。幸运的是，ReactPHP 也可以与 `ev` 扩展一起使用，其最新版本已经支持 PHP 7。就像在上一章中一样，我们将使用 Docker 来创建一个干净的软件堆栈。首先为您的应用程序容器创建一个 *Dockerfile*：

```php
FROM php:7 
RUN pecl install ev-beta && \ 
    docker-php-ext-enable ev 
WORKDIR /opt/app 
CMD ["/usr/local/bin/php", "server.php"] 

```

然后，您将能够从该文件构建一个镜像，并使用以下 CLI 命令从项目目录内启动容器：

```php
**$ docker build -t packt-chp6**
**$ docker run -d --name chat-app -v $PWD:/opt/app -p 8080:8080 
      packt-chp6**

```

请注意，只要您的项目目录中没有 `server.php` 文件，这个命令实际上是不会起作用的。

就像在前面的示例中一样，我们也将使用 Composer 进行依赖管理和自动加载。为您的项目创建一个新的文件夹，并创建一个 `composer.json` 文件，其中包含以下内容：

```php
{ 
    "name": "packt-php7/chp6-chat", 
    "type": "project", 
    "authors": [{ 
        "name": "Martin Helmich", 
        "email": "php7-book@martin-helmich.de" 
    }], 
    "require": { 
        "php": ">= 7.0.0", 
        "cboden/ratchet": "⁰.3.4" 
    }, 
    "autoload": { 
        "psr-4": { 
            "Packt\\Chp6": "src/" 
        } 
    } 
} 

```

通过在项目目录中运行 `composer install` 安装所有必需的软件包，并创建一个临时的 `server.php` 文件，其中包含以下内容：

```php
<?php 
require_once 'vendor/autoload.php'; 

$app = new \Ratchet\App('localhost', 8080, '0.0.0.0'); 
$app->run(); 

```

您已经在介绍示例中使用了 `Ratchet\App` 构造函数。关于这个类的构造函数参数有几点需要注意：

+   第一个参数 `$httpHost` 是您的应用程序将可用的 HTTP 主机名。这个值将被用作允许的来源主机。这意味着当您的服务器监听 `localhost` 时，只有在 `localhost` 域上运行的 JavaScript 才能连接到您的 WebSocket 服务器。

+   `$port` 参数指定了您的 WebSocket 服务器将监听的端口。端口 `8080` 现在足够了；在后面的部分，您将学习如何安全地配置您的应用程序以在 HTTP 标准端口 `80` 上可用。

+   `$address` 参数描述了 WebSocket 服务器将监听的 IP 地址。这个参数的默认值是 `'127.0.0.1'`，这将允许在同一台机器上运行的客户端连接到您的 WebSocket 服务器。当您在 Docker 容器中运行应用程序时，这是行不通的。字符串 `'0.0.0.0'` 将指示应用程序监听所有可用的 IP 地址。

+   第四个参数 `$loop` 允许您将自定义事件循环注入 Ratchet 应用程序。如果不传递此参数，Ratchet 将构造自己的事件循环。

您现在应该能够使用以下命令启动您的应用程序容器：

```php
**$ docker run --rm -v $PWD:/opt/app -p 8080:8080 packt-chp6**

```

### 提示

由于您的应用程序现在是一个单一的、长时间运行的 PHP 进程，对 PHP 代码库的更改在重新启动服务器之前不会生效。请记住，当您对应用程序的 PHP 代码进行更改时，使用 *Ctrl* + *C* 停止服务器，并使用相同的命令重新启动服务器（或使用 `docker restart chat-app` 命令）。

## 引导 HTML 用户界面

我们的聊天应用程序的用户界面将基于 HTML、CSS 和 JavaScript。为了管理前端依赖关系，在本例中我们将使用**Bower**。您可以使用以下命令（作为 root 用户或使用`sudo`）安装 Bower：

```php
**$ npm install -g bower**

```

继续创建一个新的`public/`目录，您可以在其中放置所有前端文件。在该目录中，放置一个带有以下内容的`bower.json`文件：

```php
{ 
    "name": "packt-php7/chp6-chat", 
    "authors": [ 
        "Martin Helmich <php7-book@martin-helmich.de>" 
    ], 
    "private": true, 
    "dependencies": { 
        "bootstrap": "~3.3.6" 
    } 
} 

```

创建`bower.json`文件后，您可以使用以下命令安装声明的依赖项（在本例中是**Twitter Bootstrap**框架）：

```php
**$ bower install**

```

这将下载 Bootstrap 框架及其所有依赖项（实际上只有 jQuery 库）到`bower_components/`目录中，然后您将能够在稍后的 HTML 前端文件中包含它们。

还有一个有用的方法是运行一个能够提供 HTML 前端文件的 Web 服务器。当您的 WebSocket 应用程序受限于`localhost`来源时，这一点尤为重要，它将只允许来自`localhost`域的 JavaScript 的请求（这不包括在浏览器中打开的本地文件）。一个快速简单的方法是使用`nginx` Docker 镜像。确保从`public/`目录中运行以下命令：

```php
**$ docker run -d --name chat-web -v $PWD:/var/www -p 80:80 nginx**

```

之后，您将能够在浏览器中打开`http://localhost`并查看来自`public/`目录的静态文件。如果您在该目录中放置一个空的`index.html`，Nginx 将使用该页面作为索引页面，无需显式请求其路径（这意味着`http://localhost`将向用户提供文件`index.html`的内容）。

## 构建一个简单的聊天应用程序

现在您可以开始实现实际的聊天应用程序。如前面的示例所示，您需要为此实现`Ratchet\MessageComponentInterface`。首先创建一个`Packt\Chp6\Chat\ChatComponent`类，并实现接口所需的所有方法：

```php
namespace Packt\Chp6\Chat; 

use Ratchet\MessageComponentInterface; 
use Ratchet\ConnectionInterface; 

class ChatComponent implements MessageComponentInterface 
{ 
    public function onOpen(ConnectionInterface $conn) {} 
    public function onClose(ConnectionInterface $conn) {} 
    public function onMessage(ConnectionInterface $from, $msg) {} 
    public function onError(ConnectionInterface $conn, \Exception $err) {} 
} 

```

聊天应用程序需要做的第一件事是跟踪连接的用户。为此，您需要维护所有打开连接的集合，在新用户连接时添加新连接，并在用户断开连接时将其移除。为此，在构造函数中初始化`SplObjectStorage`类的一个实例：

```php
**private $users;** 

public function __construct() 
{ 
 **$this->users = new \SplObjectStorage();** 
} 

```

然后在`onOpen`事件中将新连接附加到此存储中，并在`onClose`事件中将其移除：

```php
public function onOpen(ConnectionInterface $conn) 
{ 
 **echo "user {$conn->remoteAddress} connected.\n";** 
 **$this->users->attach($conn);** 
} 

public function onClose(ConnectionInterface $conn) 
{ 
 **echo "user {$conn->remoteAddress} disconnected.\n";** 
 **$this->users->detach($conn);**} 

```

现在每个连接的用户都可以向服务器发送消息。对于每条接收到的消息，组件的`onMessage`方法将被调用。为了实现一个真正的聊天应用程序，每条接收到的消息都需要被传递给其他用户，方便的是，您已经有了一个包含所有连接用户的`$this->users`集合，可以向他们发送接收到的消息：

```php
public function onMessage(ConnectionInterface $from, $msg) 
{ 
 **echo "received message '$msg' from user {$from->remoteAddress}\n";**
 **foreach($this->users as $user) {** 
 **if ($user != $from) {** 
 **$user->send($msg);** 
 **}** 
 **}**} 

```

然后在您的`server.php`文件中注册您的聊天组件：

```php
$app = new \Ratchet\App('localhost', 8080, '0.0.0.0'); 
**$app->route('/chat', new \Packt\Chp6\Chat\ChatComponent);** 
$app->run(); 

```

重新启动应用程序后，通过在两个单独的终端中使用 wscat 打开两个 WebSocket 连接来测试聊天功能。您在一个连接中发送的每条消息都应该在另一个连接中弹出。

![构建一个简单的聊天应用程序](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-bp/img/image_06_004.jpg)

使用两个 wscat 连接测试简陋的聊天应用程序

现在您已经有一个（诚然，仍然很简陋的）聊天服务器在运行，我们可以开始为聊天应用程序构建 HTML 前端。首先，一个静态的 HTML 文件对此来说完全足够了。首先在`public/`目录中创建一个空的`index.html`文件：

```php
<!DOCTYPE html>
<html> 
  <head> 
    <title>Chat application</title> 
 **<script src="bower_components/jquery/dist/jquery.min.js"></script>** 
 **<script src="bower_components/bootstrap/dist/js/bootstrap.min.js"></script>**
 **<link rel="stylesheet" href="bower_components/bootstrap/dist/css/bootstrap.min.css"/>** 
  </head> 
  <body> 
  </body> 
</html> 

```

在这个文件中，我们已经包含了我们将在本例中使用的前端库；Bootstrap 框架（一个 JavaScript 和一个 CSS 文件）和 jQuery 库（另一个 JavaScript 文件）。

由于你将为这个应用程序编写大量的 JavaScript 代码，因此在 HTML 页面的`<head>`部分中添加另一个`js/app.js`文件实例也是很有用的：

```php
<head> 
  <title>Chat application</title> 
  <script src="bower_components/jquery/dist/jquery.min.js"></script> 
  <script src="bower_components/bootstrap/dist/js/bootstrap.min.js"></script> 
 **<script src="js/app.js"></script>** 
  <link rel="stylesheet" href="bower_components/bootstrap/dist/css/bootstrap.min.css"/> 
</head> 

```

然后，你可以在`index.html`文件的`<body>`部分构建一个极简的聊天窗口。你只需要一个用于编写消息的输入字段，一个用于发送消息的按钮，以及一个用于显示其他用户消息的区域：

```php
<div class="container"> 
  <div class="row"> 
    <div class="col-md-12"> 
      <div class="input-group"> 
        <input class="form-control" type="text" id="message"  placeholder="Your message..." /> 
        <span class="input-group-btn"> 
          <button id="submit" class="btn btn-primary">Send</button> 
        </span> 
      </div> 
    </div> 
  </div> 
  <div class="row"> 
    <div id="messages"></div> 
  </div> 
</div> 

```

HTML 文件中包含一个输入字段（`id="message"`），用户可以在其中输入新的聊天消息，一个按钮（`id="submit"`）用于提交消息，以及一个（目前还是空的）部分（`id="messages"`），用于显示从其他用户接收到的消息。以下截图显示了这个页面在浏览器中的显示方式：

![构建一个简单的聊天应用](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-bp/img/image_06_005.jpg)

当然，所有这些都不会有任何作用，如果没有适当的 JavaScript 来实际使聊天工作。在 JavaScript 中，你可以使用`WebSocket`类打开一个 WebSocket 连接。

### 注意

**关于浏览器支持** WebSockets 在所有现代浏览器中都得到支持，而且已经有一段时间了。你可能会遇到需要支持较旧的 Internet Explorer 版本（9 及以下）的问题，这些版本不支持 WebSockets。在这种情况下，你可以使用`web-socket-js`库，它在内部使用 Flash 作为回退，而 Ratchet 也很好地支持 Flash。

在这个例子中，我们将把所有的 JavaScript 代码放在`public/`目录下的`js/app.js`文件中。你可以通过用 WebSocket 服务器的 URL 作为第一个参数来实例化`WebSocket`类来打开一个新的 WebSocket 连接：

```php
var connection = new WebSocket('ws://localhost:8080/chat'); 

```

就像服务器端组件一样，客户端 WebSocket 也提供了几个你可以监听的事件。方便的是，这些事件的名称与 Ratchet 使用的方法类似，`onopen`，`onclose`和`onmessage`，你都可以（也应该）在自己的代码中实现：

```php
connection.onopen = function() { 
    console.log('connection established'); 
} 

connection.onclose = function() { 
    console.log('connection closed'); 
} 

connection.onmessage = function(event) { 
    console.log('message received: ' + event.data); 
} 

```

## 接收消息

每个客户端连接在 Ratchet 服务器应用程序中都会有一个对应的`ConnectionInterface`实例。当你在服务器上调用连接的`send()`方法时，这将触发客户端的`onmessage`事件。

每次收到新消息时，这条消息应该显示在聊天窗口中。为此，你可以实现一个新的 JavaScript 方法`appendMessage`，它将在之前创建的消息容器中显示新消息：

```php
var appendMessage = function(message, sentByMe) { 
    var text = sentByMe ? 'Sent at' : 'Received at'; 
     var html = $('<div class="msg">' + text + ' <span class="date"></span>: <span 
    class="text"></span></div>'); 

    html.find('.date').text(new Date().toLocaleTimeString()); 
    html.find('.text').text(message); 

    $('#messages').prepend(html); 
} 

```

在这个例子中，我们使用了一个简单的 jQuery 构造来创建一个新的 HTML 元素，并用当前的日期和时间以及实际接收到的消息文本填充它。请注意，单个消息目前只包含原始消息文本，还不包含任何形式的元数据，比如作者或其他信息。我们稍后会解决这个问题。

### 提示

在这种情况下，使用 jQuery 创建 HTML 元素已经足够了，但在实际情况下，你可能会考虑使用专门的模板引擎，比如**Mustache**或**Handlebars**。由于这不是一本 JavaScript 书，我们将在这里坚持基础知识。

当收到消息时，你可以调用`appendMessage`方法：

```php
connection.onmessage = function(event) { 
    console.log('message received: ' + event.data); 
 **appendMessage(event.data, false);** 
} 

```

事件的数据属性包含整个接收到的消息作为一个字符串，你可以根据需要使用它。目前，我们的聊天应用程序只能处理纯文本聊天消息；每当你需要传输更多或结构化的数据时，使用 JSON 编码可能是一个不错的选择。

## 发送消息

要发送消息，你可以（不出所料地）使用连接的`send()`方法。由于你已经在 HTML 文件中有了相应的用户输入字段，现在只需要更多的 jQuery 就可以让我们的聊天的第一个版本运行起来：

```php
$(document).ready(function() { 
    $('#submit').click(function() { 
        var message = $('#message').val(); 

        if (message) { 
            console.log('sending message: "' + message + '"'); 
            connection.send(message); 

            appendMessage(message, true); 
        } 
    }); 
}); 

```

一旦 HTML 页面完全加载，我们就开始监听提交按钮的`click`事件。当按钮被点击时，输入字段中的消息将使用连接的`send()`方法发送到服务器。每次发送消息时，Ratchet 都会调用服务器端组件的`onMessage`事件，允许服务器对该消息做出反应并将其分发给其他连接的用户。

通常，用户希望在聊天窗口中看到他们自己发送的消息。这就是为什么我们调用之前实现的`appendMessage`，它将把发送的消息插入到消息容器中，就好像它是从远程用户接收的一样。

## 测试应用程序

当两个容器（Web 服务器和 WebSocket 应用程序）都在运行时，您现在可以通过在浏览器中打开 URL `http://localhost` 来测试您的聊天的第一个版本（最好是在两个不同的窗口中打开页面，这样您实际上可以使用应用程序与自己聊天）。

以下截图显示了测试应用程序时应该获得的结果示例：

![测试应用程序](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-bp/img/image_06_006.jpg)

使用两个浏览器窗口测试聊天应用程序的第一个版本

## 防止连接超时

当您将测试站点保持打开超过几分钟时，您可能会注意到最终 WebSocket 连接将被关闭。这是因为大多数浏览器在一定时间内没有发送或接收消息时（通常为五分钟）会关闭 WebSocket 连接。由于您正在处理长时间运行的连接，您还需要考虑连接问题-如果您的用户之一使用移动连接并在使用您的应用程序时暂时断开连接会怎么样？

最简单的缓解方法是实现一个简单的重新连接机制-每当连接关闭时，等待几秒然后再次尝试。为此，您可以在`onclose`事件中启动一个超时，在其中打开一个新连接：

```php
connection.onclose = function(event) { 
    console.error(e); 
    setTimeout(function() { 
        connection = new WebSocket('ws://localhost:8080/chat'); 
    }, 5000); 
} 

```

这样，每当连接关闭时（由于超时、网络连接问题或任何其他原因）；应用程序将在五秒的宽限时间后尝试重新建立连接。

如果您希望主动防止断开连接，您还可以定期通过连接发送消息以保持连接活动。这可以通过注册一个间隔函数来完成，该函数定期（在超时时间内的间隔内）向服务器发送消息：

```php
**var interval;** 

connection.onopen = function() { 
    console.log('connection established'); 
 **interval = setInterval(function() {** 
 **connection.send('ping');** 
 **}, 120000);** 
} 

connection.onclose = function() { 
    console.error(e); 
 **clearInterval(interval);** 
    setTimeout(function() { 
        connection = new WebSocket('ws://localhost:8080/chat'); 
    }, 5000); 
} 

```

这里有一些需要考虑的注意事项：首先，您应该在连接实际建立之后才开始发送保持活动的消息（这就是为什么我们在`onopen`事件中注册间隔），并且当连接关闭时也应该停止发送保持活动的消息（例如，当网络不可用时仍然可能发生），这就是为什么间隔需要在`onclose`事件中清除。

此外，您可能不希望保持活动的消息广播到其他连接的客户端；这意味着这些消息在服务器端组件中也需要特殊处理：

```php
public function onMessage(ConnectionInterface $from, $msg) 
{ 
 **if ($msg == 'ping') {** 
 **return;** 
 **}** 

    echo "received message '$msg' from user {$from->remoteAddress}\n"; 
    foreach($this->users as $user) { 
        if ($user != $from) { 
            $user->send($msg); 
        } 
    } 
} 

```

# 部署选项

正如您已经注意到的，Ratchet 应用程序不像您典型的 PHP 应用程序那样部署，而是实际上运行自己的 HTTP 服务器，可以直接响应 HTTP 请求。此外，大多数应用程序不仅仅会提供 WebSocket 连接，还需要处理常规的 HTTP 请求。

### 提示

本节旨在为您概述如何在生产环境中部署 Ratchet 应用程序。在本章的其余部分，为了简单起见，我们将继续使用基于 Docker 的开发设置（不使用负载平衡和花哨的进程管理器）。

这将带来一整套新问题需要解决。其中之一是可伸缩性：默认情况下，PHP 是单线程运行的，因此即使使用`libev`提供的异步事件循环，您的应用程序也永远无法扩展到多个 CPU。虽然您可以考虑使用`pthreads`扩展在 PHP 中启用线程（并进入一个全新的痛苦世界），但通常更容易的方法是简单地多次启动 Ratchet 应用程序，让它们侦听不同的端口，并使用 Nginx 等负载均衡器将 HTTP 请求和 WebSocket 连接分发给它们。

对于处理常规（非 WebSocket）HTTP 请求，您仍然可以使用常规的 PHP 进程管理器，如 PHP-FPM 或 Apache 的 PHP 模块。然后，您可以配置 Nginx 将这些常规请求分派给 FPM，将所有 WebSocket 请求分派给您运行的 Ratchet 应用程序之一。

![部署选项](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-bp/img/B05285_06_07.jpg)

使用 Nginx 负载均衡器部署和负载平衡 Ratchet 应用程序

为了实现这一点，您首先需要使应用程序侦听的端口可以为每个运行的进程单独配置。由于应用程序是通过命令行启动的，使端口可配置的最简单方法是使用命令行参数。您可以使用`getopt`函数轻松解析命令行参数。在此过程中，您还可以使侦听地址可配置。将以下代码插入到您的`server.php`文件中：

```php
**$options = getopt('l:p:', ['listen:', 'port:']);** 
**$port = $options['port'] ?? $options['p'] ?? 8080;** 
**$addr = $options['listen'] ?? $options['l'] ?? '127.0.0.1';** 

$app = new \Ratchet\App('localhost', $port, $addr); 
$app->route('/chat', new \Packt\Chp6\Chat\ChatComponent); 
$app->run(); 

```

接下来，您需要确保您的服务器实际上自动启动了足够数量的进程。在 Linux 环境中，**Supervisor**工具通常是一个不错的选择。在 Ubuntu 或 Debian Linux 系统上，您可以使用以下命令从系统的软件包存储库安装它：

```php
**$ apt-get install supervisor**

```

然后，在`/etc/supervisor/conf.d/`中放置一个配置文件，内容如下：

```php
[program:chat] 
numprocs=4 
command=php /path/to/application -port=80%(process_num)02d 
process_name=%(program_name)s-%(process_num)02d 
autostart=true 
autorestart=unexpected 

```

这将配置 Supervisor 在系统启动时启动四个聊天应用程序的实例。它们将侦听端口`8000`到`8003`，并在它们意外终止时由 Supervisor 自动重新启动-请记住：在 FPM 管理的环境中，PHP 致命错误可能相对无害，但在独立的 PHP 进程中，一个致命错误将使您的整个应用程序对所有用户不可用，直到有人重新启动该进程。因此，最好有一个像 Supervisor 这样的服务，可以自动重新启动崩溃的进程。

接下来，安装一个 Nginx web 服务器，用作四个运行的聊天应用程序的负载均衡器。在 Ubuntu 或 Debian 上，安装 Nginx 如下：

```php
**$ apt-get install nginx**

```

安装 Nginx 后，在目录`/etc/nginx/sites-enabled/`中放置一个名为`chat.conf`的配置文件，内容如下：

```php
upstream chat { 
    server localhost:8000; 
    server localhost:8001; 
    server localhost:8002; 
    server localhost:8003; 
} 
server { 
    listen 80; 
    server_name chat.example.com; 

    location /chat/ { 
        proxy_pass http://chat; 
        proxy_http_version 1.1; 
        proxy_set_header Upgrade $http_upgrade; 
        proxy_set_header Connection "upgrade"; 
    } 

    // Additional PHP-FPM configuration here 
    // ... 
} 

```

这个配置将配置所有四个应用程序进程作为 Nginx 负载均衡器的*上游*服务器。所有以`/chat/`路径开头的 HTTP 请求将被转发到服务器上运行的 Ratchet 应用程序之一。`proxy_http_version`和`proxy_set_header`指令是必要的，以便 Nginx 能够正确地在服务器和客户端之间转发 WebSocket 握手。

# 连接 Ratchet 和 PSR-7 应用程序

迟早，您的聊天应用程序还需要响应常规的 HTTP 请求（例如，一旦您想要添加具有登录表单和身份验证处理的身份验证层，这将变得必要）。

如前一节所述，PHP 中 WebSocket 应用程序的常见设置是让 Ratchet 应用程序处理所有 WebSocket 连接，并将所有常规 HTTP 请求定向到常规的 PHP-FPM 设置。但是，由于 Ratchet 应用程序实际上也包含自己的 HTTP 服务器，因此您也可以直接从 Ratchet 应用程序响应常规 HTTP 请求。

就像您使用`Ratchet\MessageComponentInterface`来实现 WebSocket 应用程序一样，您可以使用`Ratchet\HttpServerInterface`来实现常规 HTTP 服务器。例如，考虑以下类：

```php
namespace Packt\Chp6\Http; 

use Guzzle\Http\Message\RequestInterface; 
use Ratchet\ConnectionInterface; 
use Ratchet\HttpServerInterface; 

class HelloWorldServer implements HttpServerInterface 
{ 
    public function onOpen(ConnectionInterface $conn, RequestInterface $request = null) 
    {} 

    public function onClose(ConnectionInterface $conn) 
    {} 

    public function onError(ConnectionInterface $conn, \Exception $e) 
    {} 

    public function onMessage(ConnectionInterface $from, $msg) 
    {} 
} 

```

如您所见，`HttpServerInterface`定义的方法与`MessageCompomentInterface`类似。唯一的区别是现在还将`$request`参数传递到`onOpen`方法中。这个类是`Guzzle\Http\Message\RequestInterface`的一个实例（不幸的是，它不实现 PSR-7 `RequestInterface`），您可以从中获取基本的 HTTP 请求属性。

现在，您可以使用`onOpen`方法来对收到的 HTTP 请求发送常规 HTTP 响应：

```php
public function onOpen(ConnectionInterface $conn, RequestInterface $request = null) 
{ 
   $conn->send("HTTP/1.1 200 OK\r\n");
    $conn->send("Content-Type: text/plain\r\n"); 
    $conn->send("Content-Length: 13\r\n"); 
    $conn->send("\r\n"); 
    $conn->send("Hello World\n"); 
    $conn->close(); 
} 

```

如您所见，您需要在`onOpen`方法中发送整个 HTTP 响应（包括响应标头！）。这有点繁琐，但稍后我们会找到更好的方法，但目前这样就足够了。

接下来，在`server.php`中注册您的 HTTP 服务器，方式与注册新的 WebSocket 服务器相同：

```php
$app = new \Ratchet\App('localhost', $port, $addr); 
$app->route('/chat', new \Packt\Chp6\Chat\ChatComponent); 
**$app->route('/hello', new \Packt\Chp6\Http\HelloWorldServer, ['*']);** 
$app->run(); 

```

特别注意这里的第三个参数`['*']`：此参数将允许此路由的任何请求来源（不仅仅是`localhost`），因为大多数浏览器和命令行客户端甚至不会为常规 HTTP 请求发送来源标头。

重新启动应用程序后，您可以使用任何常规 HTTP 客户端（无论是命令行还是浏览器）测试新的 HTTP 路由。如下面的截图所示：

![桥接 Ratchet 和 PSR-7 应用程序](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-bp/img/image_06_008.jpg)

使用 cURL 测试 Ratchet HTTP 服务器

手动构建包括标头的 HTTP 响应是一项非常繁琐的任务-特别是如果在某个时刻，您的应用程序包含多个 HTTP 端点。因此，最好有一个框架来为您处理所有这些事情。

在上一章中，您已经使用了**Slim**框架，您也可以将其与 Ratchet 很好地集成。不幸的是，Ratchet 目前还不符合 PSR-7，因此您需要做一些工作来将 Ratchet 的请求接口转换为 PSR-7 实例，并将 PSR-7 响应返回到`ConnectionInterface`。

首先使用 Composer 将 Slim 框架安装到您的应用程序中：

```php
**$ composer require slim/slim**

```

本节的其余部分的目标是构建`HttpServerInterface`的新实现，该实现将 Slim 应用程序作为依赖项，并将所有传入的请求转发到 Slim 应用程序。

首先定义实现`HttpServerInterface`并接受`Slim\App`作为依赖项的`Packt\Chp6\Http\SlimAdapterServer`类：

```php
namespace Packt\Chp6\Http; 

use Guzzle\Http\Message\RequestInterface; 
use Ratchet\ConnectionInterface; 
use Ratchet\HttpServerInterface; 
use Slim\App; 

class SlimAdapterServer implements HttpServerInterface 
{ 
    private $app; 

    public function __construct(App $app) 
    { 
        $this->app = $app; 
    } 

    // onOpen, onClose, onError and onMessage omitted 
    // ... 
} 

```

您需要做的第一件事是将 Ratchet 传递到`onOpen`事件的`$request`参数映射到 PSR-7 请求对象（然后将其传递到 Slim 应用程序进行处理）。Slim 框架提供了其自己的实现：`Slim\Http\Request`类。首先将以下代码添加到您的`onOpen`方法中，将请求 URI 映射到`Slim\Http\Uri`类的实例：

```php
$guzzleUri = $request->getUrl(true); 
$slimUri = new \Slim\Http\Uri( 
    $guzzleUri->getScheme() ?? 'http', 
    $guzzleUri->getHost() ?? 'localhost', 
    $guzzleUri->getPort(), 
    $guzzleUri->getPath(), 
    $guzzleUri->getQuery() . '', 
    $guzzleUri->getFragment(), 
    $guzzleUri->getUsername(), 
    $guzzleUri->getPassword() 
); 

```

这将在 Slim URI 对象中映射 Guzzle 请求的 URI 对象。它们在很大程度上是兼容的，允许您将大多数属性简单地复制到`Slim\Http\Uri`类的构造函数中。只有`$guzzleUri->getQuery()`返回值需要通过与空字符串连接来强制转换为字符串。

继续构建 HTTP 请求标头对象：

```php
$headerValues = []; 
foreach ($request->getHeaders() as $name => $header) { 
    $headerValues[$name] = $header->toArray(); 
} 
$slimHeaders = new \Slim\Http\Headers($headerValues); 

```

构建请求 URI 和标头后，您可以创建`SlimRequest`类的实例：

```php
$slimRequest = new \Slim\Http\Request( 
    $request->getMethod(), 
    $slimUri, 
    $slimHeaders, 
    $request->getCookies(), 
    [], 
    new \Slim\Http\Stream($request->getBody()->getStream()); 
); 

```

然后，您可以使用此请求对象来调用作为依赖项传递给`SlimAdapterServer`类的 Slim 应用程序：

```php
$slimResponse = new \Slim\Http\Response(200); 
$slimResponse = $this->app->process($slimRequest, $slimResponse); 

```

`$this->app->process()`函数实际上会执行 Slim 应用程序。它类似于您在上一章中使用的`$app->run()`方法，但直接接受 PSR-7 请求对象，并返回一个用于进一步处理的 PSR-7 响应对象。

最后的挑战是现在使用`$slimResponse`对象，并将其中包含的所有数据返回给客户端。让我们从发送 HTTP 头部开始：

```php
$statusLine = sprintf('HTTP/%s %d %s', 
    $slimResponse->getProtocolVersion(), 
    $slimResponse->getStatusCode(), 
    $slimResponse->getReasonPhrase() 
); 
$headerLines = [$statusLine]; 

foreach ($slimResponse->getHeaders() as $name => $values) { 
    foreach ($values as $value) { 
        $headerLines[] = $headerName . ': ' . $value; 
    } 
} 

$conn->send(implode("\r\n", $headerLines) . "\r\n\r\n"); 

```

`$statusLine`包含 HTTP 响应的第一行（通常是`HTTP/1.1 200 OK`或`HTTP/1.1 404 Not Found`之类的内容）。嵌套的`foreach`循环用于从 PSR-7 响应对象中收集所有响应头，并将它们连接成一个字符串，该字符串可以用于 HTTP 响应（每个头部都有自己的一行，由**回车**（**CR**）和**换行**（**LF**）分隔）。双`\r\n`最终终止头部，并标记响应主体的开始，接下来您将输出它：

```php
$body = $slimResponse->getBody(); 
$body->rewind(); 

while (!$body->eof()) { 
    $conn->send($body->read(4096)); 
} 
$conn->close(); 

```

在您的`server.php`文件中，您现在可以实例化一个新的 Slim 应用程序，将其传递给一个新的`SlimAdapterServer`类，并在 Ratchet 应用程序中注册此服务器：

```php
**use Slim\App;** 
**use Slim\Http\Request;** 
**use Slim\Http\Response;** 
**$slim = new App();** 
**$slim->get('/hello', function(Request $req, Response $res): Response {** 
 **$res->getBody()->write("Hello World!");** 
 **return $res;** 
**});** 
**$adapter = new \Packt\Chp6\Http\SlimAdapterServer($slim);** 

$app = new \Ratchet\App('localhost', $port, $addr); 
$app->route('/chat', new \Packt\Chp6\Chat\ChatComponent); 
**$app->route('/hello', $adapter, ['*']);** 
$app->run(); 

```

将 Slim 框架集成到 Ratchet 应用程序中，可以让您使用同一个应用程序为 WebSocket 请求和常规 HTTP 请求提供服务。从一个持续运行的 PHP 进程中提供 HTTP 请求会带来一些有趣的新机会，尽管您必须谨慎使用。您需要担心诸如内存消耗（PHP 确实有**垃圾回收器**，但如果不注意，仍可能造成内存泄漏，导致 PHP 进程超出内存限制而崩溃），但在有高性能要求时，构建这样的应用可能是一个有趣的选择。

# 通过 Web 服务器访问您的应用程序

在我们的开发设置中，我们当前运行两个容器，应用程序容器本身监听端口`8080`，而 Nginx 服务器监听端口`80`，提供静态文件，如`index.html`和各种 CSS 和 JavaScript 文件。在生产设置中，通常不建议为静态文件和应用程序本身公开两个不同的端口。

因此，我们现在将配置我们的 Web 服务器容器，以便在存在静态文件时提供静态文件（例如`index.html`或 CSS 和 JavaScript 文件），并在没有实际文件存在的情况下将 HTTP 请求委托给应用程序容器。为此，首先创建一个 Nginx 配置文件，您可以将其放在项目目录的任何位置，例如`etc/nginx.conf`：

```php
map $http_upgrade $connection_upgrade { 
    default upgrade; 
    '' close; 
} 

server { 
    location / { 
        root /var/www; 
        try_files $uri $uri/index.html @phpsite; 
    } 

    location @phpsite { 
        proxy_http_version 1.1; 
        proxy_set_header X-Real-IP  $remote_addr; 
        proxy_set_header Host $host; 
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for; 
        proxy_set_header Upgrade $http_upgrade; 
        proxy_set_header Connection $connection_upgrade; 
        proxy_pass http://app:8080; 
    } 
} 

```

这种配置将导致 Nginx 在`/var/www`目录中查找文件（当使用 Docker 启动 Nginx Web 服务器时，您可以将本地目录简单地挂载到容器的`/var/www`目录中）。在那里，它将首先查找直接的文件名匹配，然后查找目录中的`index.html`，最后将请求传递给上游 HTTP 服务器。

### 提示

这种配置也适用于*部署选项*部分中描述的生产设置。当您运行多个应用程序实例时，您将需要在`proxy_pass`语句中引用一个专用的上游配置，其中包含多个上游应用程序。

创建配置文件后，您可以按以下方式重新创建 Nginx 容器（特别注意`docker run`命令的`--link`标志）：

```php
**$ docker rm -f chat-web** 
**$ docker run -d --name chat-web **--link chat-app:app** -v $PWD/public:/var/www -p 80:80 nginx**

```

# 添加身份验证

目前，我们的应用程序缺少一个至关重要的功能：任何人都可以在聊天中发布消息，也没有办法确定哪个用户发送了哪条消息。因此，在下一步中，我们将为我们的聊天应用程序添加一个身份验证层。为此，我们将需要一个登录表单和某种身份验证处理程序。

在这个例子中，我们将使用典型的基于会话的身份验证。成功验证用户名和密码后，系统将为用户创建一个新的会话，并将（随机且不可猜测的）会话 ID 存储在用户浏览器的 cookie 中。在后续请求中，身份验证层可以使用来自 cookie 的会话 ID 来查找当前经过身份验证的用户。

## 创建登录表单

让我们开始实现一个简单的用于管理会话的类。这个类将被命名为`Packt\Chp6\Authentication\SessionProvider`：

```php
namespace Packt\Chp6\Authentication; 

class SessionProvider 
{ 
    private $users = []; 

    public function hasSession(string $sessionId): bool 
    { 
        return array_key_exists($sessionId, $this->users); 
    } 

    public function getUserBySession(string $sessionId): string 
    { 
        return $this->users[$sessionId]; 
    } 

    public function registerSession(string $user): string 
    { 
        $id = sha1(random_bytes(64)); 
        $this->users[$id] = $user; 
        return $id; 
    } 
} 

```

这个会话处理程序非常简单：它只是简单地存储哪个用户（按名称）正在使用哪个会话 ID；可以使用`registerSession`方法注册新会话。由于所有 HTTP 请求将由同一个 PHP 进程提供，因此您甚至不需要将这些会话持久化到数据库中，而是可以简单地将它们保存在内存中（但是，一旦在负载平衡环境中运行多个进程，您将需要基于数据库的会话存储，因为您不能简单地在不同的 PHP 进程之间共享内存）。

### 提示

**关于真正随机的随机数**

为了生成一个密码安全的会话 ID，我们使用了在 PHP 7 中添加的`random_bytes`函数，现在建议使用这种方式来获取密码安全的随机数据（永远不要使用`rand`或`mt_rand`等函数）。 

在接下来的步骤中，我们将在新集成的 Slim 应用程序中实现一些额外的路由：

1.  `GET /`路由将提供实际的聊天 HTML 网站。直到现在，这是一个静态的 HTML 页面，直接由 Web 服务器提供。使用身份验证，我们将需要在这个网站上进行更多的登录（例如，当用户未登录时将其重定向到登录页面），这就是为什么我们将首页页面移到应用程序中。

1.  `GET /login`路由将提供一个登录表单，用户可以通过用户名和密码进行身份验证。提供的凭据将提交给...

1.  `POST /authenticate`路由。这个路由将验证用户提供的凭据，并在用户成功验证后启动一个新的会话（使用之前构建的`SessionProvider`类）。验证成功后，`/authenticate`路由将重定向用户回到`/`路由。

让我们开始在 Ratchet 应用程序中注册这三个路由，并将它们连接到之前创建的 Slim 适配器中的`server.php`文件中：

```php
$app = new \Ratchet\App('localhost', $port, $addr); 
$app->route('/chat', new \Packt\Chp6\Chat\ChatComponent); 
**$app->route('/', $adapter, ['*']);** 
**$app->route('/login', $adapter, ['*']);** 
**$app->route('/authenticate', $adapter, ['*']);** 
$app->run(); 

```

继续实现`/`路由。请记住，这个路由只是简单地提供您之前创建的`index.html`文件，但前提是存在有效的用户会话。为此，您需要检查 HTTP 请求中是否提供了带有会话 ID 的 HTTP cookie，然后验证是否存在具有此 ID 的有效用户会话。为此，请将以下代码添加到您的`server.php`中（如果仍然存在，请删除之前创建的`GET /hello`路由）。如下面的代码所示：

```php
**$provider = new \Packt\Chp6\Authentication\SessionProvider();** 
$slim = new \Slim\App(); 
**$slim->get('/', function(Request $req, Response $res) use ($provider): Response {** 
 **$sessionId = $req->getCookieParams()['session'] ?? '';** 
 **if (!$provider->hasSession($sessionId)) {** 
 **return $res->withRedirect('/login');** 
 **}** 
 **$res->getBody()->write(file_get_contents('templates/index.html'));** 
 **return $res** 
 **->withHeader('Content-Type', 'text/html;charset=utf8');** 
**});**

```

这个路由为您的用户提供`templates/index.html`文件。目前，这个文件应该位于您的设置中的`public/`目录中。在项目文件夹中创建`templates/`目录，并将`index.html`从`public/`目录移动到那里。这样，文件将不再由 Nginx Web 服务器提供，所有对`/`的请求将直接转发到 Ratchet 应用程序（然后要么提供索引视图，要么将用户重定向到登录页面）。

在下一步中，您可以实现`/login`路由。这个路由不需要特殊的逻辑：

```php
$slim->get('/login', function(Request $req, Response $res): Response { 
    $res->getBody()->write(file_get_contents('templates/login.html')); 
    return $res 
        ->withHeader('Content-Type', 'text/html;charset=utf8'); 
}); 

```

当然，要使这个路由实际工作，您需要创建`templates/login.html`文件。首先创建一个简单的 HTML 文档作为新模板：

```php
<!DOCTYPE html> 
<html lang="en"> 
<head> 
    <meta charset="UTF-8"> 
    <title>Chap application: Login</title> 
    <script src="bower_components/jquery/dist/jquery.min.js"></script> 
    <script src="bower_components/bootstrap/dist/js/bootstrap.min.js"></script> 
    <link rel="stylesheet" href="bower_components/bootstrap/dist/css/bootstrap.min.css"/> 
</head> 
<body> 
</body> 
</html> 

```

这将加载所有必需的 JavaScript 库和 CSS 文件，以便登录表单正常工作。在`<body>`部分，您可以添加实际的登录表单：

```php
<div class="row" id="login"> 
    <div class="col-md-4 col-md-offset-4"> 
        <div class="panel panel-default"> 
            <div class="panel-heading">Login</div> 
            <div class="panel-body"> 
                <form action="/authenticate" method="post"> 
                    <div class="form-group"> 
                        <label for="username">Username</label> 
                        <input type="text" name="username" id="username" placeholder="Username" class="form-control"> 
                    </div> 
                    <div class="form-group"> 
                        <label for="password">Password</label> 
                        <input type="password" name="password" id="password" placeholder="Password" class="form-control"> 
                    </div> 
                    <button type="submit" id="do-login" class="btn btn-primary btn-block"> 
                        Log in 
                    </button> 
                </form> 
            </div> 
        </div> 
    </div> 
</div> 

```

特别注意`<form>`标签：表单的 action 参数是`/authenticate`路由；这意味着所有输入到表单中的值将被传递到（尚未编写的）`/authenticate`路由处理程序中，您将能够验证输入的凭据并创建一个新的用户会话。

保存此模板文件并重新启动应用程序后，您可以通过简单地请求`/` URL（无论是在浏览器中还是使用诸如**HTTPie**或**curl**之类的命令行工具）来测试新的登录表单。由于您尚未拥有登录会话，因此应立即被重定向到登录表单。如下截图所示：

![创建登录表单](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-bp/img/image_06_009.jpg)

未经身份验证的用户现在将被重定向到登录表单

现在唯一缺少的是实际的`/authenticate`路由。为此，请在您的`server.php`文件中添加以下代码：

```php
$slim->post('/authenticate', function(Request $req, Response $res) use ($provider): Response { 
    $username = $req->getParsedBodyParam('username'); 
    $password = $req->getParsedBodyParam('password'); 

    if (!$username || !$password) { 
        return $res->withStatus(403); 
    } 

    if (!$username == 'mhelmich' || !$password == 'secret') { 
        return $res->withStatus(403); 
    } 

    $session = $provider->registerSession($username); 
    return $res 
        ->withHeader('Set-Cookie', 'session=' . $session) 
        ->withRedirect('/'); 
}); 

```

当然，在这个例子中，实际的用户身份验证仍然非常基本-我们只检查一个硬编码的用户/密码组合。在生产设置中，您可以在此处实现任何类型的用户身份验证（通常包括在数据库集合中查找用户并比较提交的密码哈希与用户存储的密码哈希）。

## 检查授权

现在，唯一剩下的就是扩展聊天应用程序本身，以仅允许经过授权的用户连接。幸运的是，WebSocket 连接开始时作为常规 HTTP 连接（在升级为 WebSocket 连接之前）。这意味着浏览器将在`Cookie` HTTP 标头中传输所有 cookie，然后您可以在应用程序中访问这些 cookie。

为了将授权问题与实际的聊天业务逻辑分开，我们将在一个特殊的装饰器类中实现所有与授权相关的内容，该类还实现了`Ratchet\MessageComponentInterface`接口并包装了实际的聊天应用程序。我们将称这个类为`Packt\Chp6\Authentication\AuthenticationComponent`。首先，通过实现一个接受`MessageComponentInterface`和`SessionProvider`作为依赖项的构造函数来实现这个类：

```php
namespace Packt\Chp6\Authentication; 

use Ratchet\MessageComponentInterface; 
use Ratchet\ConnectionInterface; 

class AuthenticationComponent implements MessageComponentInterface 
{ 
    private $wrapped; 
    private $sessionProvider; 

    public function __construct(MessageComponentInterface $wrapped, SessionProvider $sessionProvider) 
    { 
        $this->wrapped         = $wrapped; 
        $this->sessionProvider = $sessionProvider; 
    } 
} 

```

接下来，通过实现`MessageComponentInterface`定义的方法。首先，将所有这些方法实现为简单地委托给`$wrapped`对象上的相应方法：

```php
public function onOpen(ConnectionInterface $conn) 
{ 
    $this->wrapped->onOpen($conn); 
} 

public function onClose(ConnectionInterface $conn) 
{ 
    $this->wrapped->onClose($conn); 
} 

public function onError(ConnectionInterface $conn, \Exception $e) 
{ 
    $this->wrapped->onError($conn, $e); 
} 

public function onMessage(ConnectionInterface $from, $msg) 
{ 
    $this->wrapped->onMessage($from, $msg); 
} 

```

现在，您可以向以下新的`onOpen`方法添加身份验证检查。在这里，您可以检查是否设置了带有会话 ID 的 cookie，使用`SessionProvider`检查会话 ID 是否有效，并且仅在存在有效会话时接受连接（意思是：委托给包装组件）：

```php
public function onOpen(ConnectionInterface $conn) 
{ 
 **$sessionId = $conn->WebSocket->request->getCookie('session');** 
 **if (!$sessionId || !$this->sessionProvider->hasSession($sessionId)) {** 
 **$conn->send('Not authenticated');** 
 **$conn->close();** 
 **return;** 
 **}** 
 **$user = $this->sessionProvider->getUserBySession($sessionId);** 
 **$conn->user = $user;** 

    $this->wrapped->onOpen($conn); 
} 

```

如果未找到会话 ID 或给定的会话 ID 无效，则连接将立即关闭。否则，会话 ID 将用于从`SessionProvider`中查找关联的用户，并将其添加为连接对象的新属性。在包装组件中，您可以简单地再次访问`$conn->user`以获取对当前经过身份验证的用户的引用。

## 连接用户和消息

现在，您可以断言只有经过身份验证的用户才能在聊天中发送和接收消息。但是，消息本身尚未与任何特定用户关联，因此您仍然不知道实际发送消息的用户是谁。

到目前为止，我们一直使用简单的纯文本消息。由于每条消息现在需要包含比纯文本更多的信息，因此我们将切换到 JSON 编码的消息。每条聊天消息将包含一个从客户端发送到服务器的`msg`属性，服务器将添加一个填充有当前经过身份验证的用户名的`author`属性。这可以在您之前构建的`ChatComponent`的`onMessage`方法中完成，如下所示：

```php
public function onMessage(ConnectionInterface $from, $msg) 
{ 
    if ($msg == 'ping') { 
        return; 
    } 

 **$decoded = json_decode($msg);** 
 **$decoded->author = $from->user;** 
 **$msg = json_encode($decoded);** 

    foreach ($this->users as $user) { 
        if ($user != $from) { 
            $user->send($msg); 
        } 
    } 
} 

```

在这个例子中，我们首先对从客户端接收的消息进行 JSON 解码。然后，我们将向消息添加一个`"author"`属性，其中填写了经过身份验证的用户的用户名（请记住，`$from->user`属性是在您之前构建的`AuthenticationComponent`中设置的）。然后，将重新编码消息并发送给所有连接的用户。

当然，我们的 JavaScript 前端也必须支持这些新的 JSON 编码消息。首先，要更改`app.js` JavaScript 文件中的`appendMessage`函数，以接受结构化对象形式的消息，而不是简单的字符串：

```php
var appendMessage = function(message, sentByMe) { 
    var text = sentByMe ? 'Sent at' : 'Received at'; 
 var html = $('<div class="msg">' + text + ' <span class="date"></span> by <span class="author"></span>: <span class="text"></span></div>'); 

    html.find('.date').text(new Date().toLocaleTimeString()); 
 **html.find('.author').text(message.author);** 
    html.find('.text').text(message.msg); 

    $('#messages').prepend(html); 
}; 

```

`appendMessage`函数被 WebSocket 连接的`onmessage`事件和您的提交按钮监听器所使用。`onmessage`事件需要修改为首先对传入的消息进行 JSON 解码：

```php
connection.onmessage = function(event) { 
 **var msg = JSON.parse(event.data);** 
    appendMessage(**msg**, false); 
} 

```

此外，提交按钮监听器需要将 JSON 编码的数据发送到 WebSocket 服务器，并将结构化数据传递到修改后的`appendMessage`函数中：

```php
$(document).ready(function () { 
    $('#submit').click(function () { 
        var text = $('#message').val(); 
 **var msg = JSON.stringify({** 
 **msg: text** 
 **});** 
        connection.send(msg); 

        appendMessage({ 
 **author: "me",** 
 **message: text** 
        }, true); 
    }) 
}); 

```

# 总结

在本章中，您已经了解了 WebSocket 应用程序的基本原则以及如何使用 Ratchet 框架构建它们。与大多数 PHP 应用程序相比，Ratchet 应用程序部署为单个长时间运行的 PHP 进程，不需要像 FPM 或 Web 服务器这样的进程管理器。这需要一种完全不同的部署方式，我们在本章中也进行了研究，无论是用于开发还是用于高规模的生产环境。

除了简单地使用 Ratchet 提供 WebSockets 之外，我们还研究了如何使用 PSR-7 标准将 Ratchet 应用程序与其他框架集成（例如，您在第五章中已经使用过的 Slim 框架，*创建 RESTful Web 服务*)。

在第七章中，*构建异步微服务架构*，您将了解另一种通信协议，可以用来集成应用程序。虽然 WebSockets 仍然建立在 HTTP 之上，但下一章将介绍**ZeroMQ**协议-这与 HTTP 完全不同，并带来了一整套新的挑战需要解决。


# 第七章：构建异步微服务架构

在本章中，我们将构建一个由一组小型独立组件组成的应用程序，这些组件通过网络协议进行通信。通常，这些所谓的**微服务架构**是使用基于 HTTP 的通信协议构建的，通常以 RESTful API 的形式，我们已经在第五章中实现了*创建 RESTful Web 服务*。

在本章中，我们将探讨一种关注异步性、松散耦合和高性能的替代通信协议：**ZeroMQ**，而不是专注于 REST。我们将使用 ZeroMQ 为一个（完全虚构的）电子商务场景构建一个简单的**结账服务**，该服务将处理广泛的问题，从电子邮件消息、订单处理、库存管理等等。

# 目标架构

我们的微服务架构的中心服务将是结账服务。该服务将为许多电子商务系统共有的结账流程提供 API。对于每个结账流程，我们将需要以下输入数据：

+   一个可以包含任意数量的文章的**购物车**

+   客户的**联系数据**

然后，结账服务将负责执行实际的结账流程，其中涉及多个额外的服务，每个服务处理结账流程的单个步骤或关注点：

1.  我们虚构的电子商务企业将处理实物商品（或更抽象的商品，我们只能有限数量地存货）。因此，对于购物车中的每件商品，结账服务将需要确保所需数量的商品实际上有库存，并且如果可能的话，减少相应数量的可用库存。这将是**库存服务**的责任。

1.  成功完成结账流程后，用户需要通过电子邮件收到有关成功结账的通知。这将是**邮件服务**的责任。

1.  此外，在完成结账流程后，订单必须转发给一个开始为该订单发货的运输服务。

以下图表显示了本章所需的目标架构的高层视图：

### 注意

在本章中，重点将放在使用 ZeroMQ 实现不同服务之间的通信模式上。我们不会实现实际的业务逻辑，这需要实际工作（因为您完全可以用另一本书来填补这部分）。相反，我们将实现实际服务作为提供我们希望它们实现的 API 的简单存根，但只包含实际业务逻辑的原型实现。

![目标架构](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-bp/img/image_07_001.jpg)

我们应用的目标架构

图中所示接口旁边的标签（**RES**和**PUB**）是您将在本章中了解的不同 ZeroMQ 套接字类型。

# ZeroMQ 模式

在本章中，您将了解 ZeroMQ 支持的基本通信模式。如果这些听起来有点理论化，不要担心；您将在整个章节中自己实现所有这些模式。

## 请求/回复模式

ZeroMQ 库支持各种不同的通信模式。对于每种模式，您将需要不同的 ZeroMQ 套接字类型。最简单的通信模式是请求/回复模式，其中客户端打开一个 REQ 套接字并连接到监听 REP 套接字的服务器。客户端发送一个请求，然后服务器进行回复。

![请求/回复模式](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-bp/img/image_07_002.jpg)

ZeroMQ 请求/回复套接字

重要的是要知道，REQ 和 REP 套接字始终是*同步*的。每个 REQ 套接字一次只能向单个 REP 套接字发送请求，更重要的是，每个 REP 套接字也只能连接到单个 REQ 套接字。ZeroMQ 库甚至在协议级别强制执行这一点，并在 REQ 套接字尝试在回复当前请求之前接收新请求时触发错误。我们将在以后使用高级通信模式来解决这个限制。

## 发布/订阅模式

发布/订阅模式由一个 PUB 套接字组成，可以在其上发布消息。可以连接任意数量的 SUB 套接字到此套接字。当在 PUB 套接字上发布新消息时，它将转发到所有连接的 SUB 套接字。

![发布/订阅模式](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-bp/img/image_07_003.jpg)

发布/订阅套接字

PUB/SUB 架构中的每个订阅者都需要指定至少一个订阅 - 一个作为每条消息过滤器的字符串。发布者将根据订阅者过滤消息，以便每个订阅者只接收他们订阅的消息。

发布/订阅严格单向工作。发布者无法从订阅者那里接收消息，订阅者也无法将消息发送回发布者。然而，就像多个 SUB 套接字可以连接到单个 PUB 套接字一样，单个 SUB 套接字也可以连接到多个 PUB 套接字。

## 推/拉模式

推/拉模式与发布/订阅模式类似。PUSH 套接字用于向任意数量的 PULL 套接字发布消息（就像 PUB/SUB 一样，单个 PULL 套接字也可以连接到任意数量的 PUSH 套接字）。然而，与发布/订阅模式相反，发送到 PUSH 套接字的每条消息只会分发到连接的 PULL 套接字中的一个。这种行为使得 PUSH/PULL 模式非常适合实现工作池，例如，您可以使用它来将任务分发给任意数量的工作者以并行处理。同样，PULL 套接字也可以用于从任意数量的 PUSH 套接字收集结果（这可能是从工作池返回的结果）。

使用 PUSH/PULL 套接字将任务分发给工作池，然后使用第二个 PUSH/PULL 层从该池中收集结果到单个套接字中，也称为*扇出/扇入*。

![推/拉模式](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-bp/img/image_07_004.jpg)

使用 PUSH 和 PULL 套接字实现扇出/扇入架构

# 引导项目

像往常一样，我们将从为本章的项目进行引导开始。在 PHP 应用程序中使用 ZeroMQ 库，您将需要通过 PECL 安装的**php-zmq 扩展**。您还需要包含 ZeroMQ 库的 C 头文件的`libzmq-dev`软件包。您可以通过操作系统的软件包管理器安装它。以下命令将在 Ubuntu 和 Debian Linux 上都适用：

```php
**$ apt-get install libmzq-dev**
**$ pecl install zmq-beta**

```

像往常一样，我们将使用 composer 来管理我们的 PHP 依赖项，并使用 Docker 来管理所需的系统库。由于我们的应用程序将由多个在多个进程中运行的服务组成，我们将使用多个 composer 项目和多个 Docker 镜像。

如果您正在使用 Windows，并希望在不使用 Docker 的情况下本地运行 ZeroMQ/PHP 应用程序，您可以从 PECL 网站（[`pecl.php.net/package/zmq/1.1.3/windows`](https://pecl.php.net/package/zmq/1.1.3/windows)）下载 ZeroMQ 扩展。

我们所有的服务将使用相同的软件（安装了 ZeroMQ 扩展的 PHP）。我们将从实现库存服务开始，但您将能够在本示例中创建的所有服务中使用相同的 Docker 镜像（或至少相同的 Dockerfile）。首先，在项目目录中创建一个`inventory/Dockerfile`文件，内容如下：

```php
FROM php:7 
RUN apt-get update && apt-get install -y libzmq-dev 
RUN docker-php-ext-configure pcntl && \ 
    docker-php-ext-install pcntl && \ 
    pecl install ev-beta && docker-php-ext-enable ev && \ 
    pecl install zmq-beta && docker-php-ext-enable zmq 
WORKDIR /opt/app 
ONBUILD ADD . /opt/app 
CMD ["/usr/local/bin/php", "server.php"] 

```

您会注意到我们还安装了`pcntl`和`ev`扩展。您已经在第六章中使用过`ev`扩展，*构建聊天应用程序*。它提供了一个与我们稍后在本章中将使用的`react/zmq`库很好配合的异步事件循环。`pcntl`扩展提供了一些功能，将帮助您控制后续长时间运行的 PHP 进程的进程状态。

为了使生活更轻松，您还可以在项目目录中创建一个`docker-compose.yml`文件，以便使用 Docker compose 来管理应用程序中的众多容器。一旦您有了可以在容器中运行的第一个服务，我们将介绍这一点。

# 构建库存服务

我们将从实现库存服务开始，因为它将使用简单的请求/回复模式进行通信，而且没有其他依赖关系。

## 开始使用 ZeroMQ REQ/REP 套接字

首先在`inventory/`目录中创建服务的`composer.json`文件：

```php
{ 
  "name": "packt-php7/chp7-inventory", 
  "type": "project", 
  "authors": [{ 
    "name": "Martin Helmich", 
    "email": "php7-book@martin-helmich.de" 
  }], 
  "require": { 
    "php": ">= 7.0", 
    "ext-zmq": "*" 
  }, 
  "autoload": { 
    "psr-4": { 
      "Packt\\Chp7\\Inventory": "src/" 
    } 
  } 
} 

```

创建`composer.json`文件后，在`inventory/`目录中使用`composer install`命令来安装项目的依赖项。

让我们首先为库存创建一个`server.php`文件。就像第六章中的 Ratchet 应用程序一样，这个文件稍后将成为我们的主服务器进程 - 请记住，在这个例子中，我们甚至没有使用 HTTP 作为通信协议，因此没有 Web 服务器，也没有 FPM 涉及到任何地方。

每个 ZeroMQ 应用程序的起点是上下文。上下文存储了 ZeroMQ 库需要维护套接字和与其他套接字通信所需的各种状态。然后，您可以使用此上下文创建一个新的套接字，并将此上下文绑定到一个端口：

```php
$args = getopt('p:', ['port=']); 
$ctx = new ZMQContext(); 

$port = $args['p'] ?? $args['port'] ?? 5557; 
$addr = 'tcp://*:' . $port; 

$sock = $ctx->getSocket(ZMQ::SOCKET_REP); 
$sock->bind($addr); 

```

这段代码创建了一个新的 ZeroMQ REP 套接字（可以回复请求的套接字），并将此套接字绑定到可配置的 TCP 端口（默认为 5557）。现在您可以在此套接字上接收消息并回复它们：

```php
while($message = $sock->recv()) { 
    echo "received message '" . $message . "'\n"; 
    $sock->send("this is my response message"); 
} 

```

正如您所看到的，这个循环将无限期地轮询新消息，然后对其进行响应。套接字的`recv()`方法将阻塞脚本执行，直到接收到新消息（稍后您可以使用`react/zmq`库轻松实现非阻塞套接字，但现在这就足够了）。

为了测试您的 ZeroMQ 服务器，您可以在`inventory/`目录中创建第二个文件`client.php`，在其中可以使用 REQ 套接字向服务器发送请求：

```php
$args = getopt('h', ['host=']); 
$ctx = new ZMQContext(); 

$addr = $args['h'] ?? $args['host'] ?? 'tcp://127.0.0.1:5557'; 

$sock = $ctx->getSocket(ZMQ::SOCKET_REQ); 
$sock->connect($addr); 

$sock->send("This is my request"); 
var_dump($sock->recv()); 

```

当您的服务器脚本正在运行时，您可以简单地运行`client.php`脚本来连接到服务器的 REP 套接字，发送请求，并等待服务器的回复。就像 REP 套接字一样，REQ 套接字的`recv`方法也会阻塞，直到从服务器接收到回复。

如果您正在使用 Docker compose 来管理开发环境中的众多容器（目前只有一个，但将会有更多），请将以下部分添加到您的`docker-compose.yml`文件中：

```php
inventory: 
  build: inventory 
  ports: 
    - 5557 
  volumes: 
    - inventory:/usr/src/app 

```

在`docker-compose.yml`配置文件中添加库存服务后，您可以通过在命令行上运行以下命令来启动容器：

```php
**$ docker-compose up**

```

## 使用 JsonRPC 进行通信

现在我们有一个服务器，可以从客户端接收文本消息，然后将响应发送回该客户端。但是，为了构建一个可工作且易于维护的微服务架构，我们需要一种协议和格式，使这些消息可以遵循，并且所有服务都可以达成一致。在微服务架构中，这个共同点通常是 HTTP，其丰富的协议语义可用于轻松构建 REST Web 服务。但是，ZeroMQ 作为一种协议要低级得多，不涉及不同的请求方法、标头、缓存以及 HTTP 所附带的所有其他功能。

我们将库存服务实现为一个简单的**远程过程调用**（**RPC**）服务，而不是一个 RESTful 服务。一个快速简单的格式是 JSON-RPC，它使用 JSON 消息实现 RPC。使用 JSON-RPC，客户端可以使用以下 JSON 格式发送方法调用：

```php
{ 
  "jsonrpc": "2.0", 
  "method": "methodName", 
  "params": ["foo", "bar", "baz"], 
  "id": "some-random-id" 
} 

```

服务器随后可以使用以下格式响应此消息：

```php
{ 
  "jsonrpc": "2.0", 
  "id": "id from request", 
  "result": "the result value" 
} 

```

或者，当处理过程中发生错误时：

```php
{ 
  "jsonrpc": "2.0", 
  "id": "id from request", 
  "error": { 
    "message": "the error message", 
    "code": 1234 
  } 
} 

```

这个协议相对简单，我们可以很容易地在 ZeroMQ 之上实现它。为此，首先创建一个新的`Packt\Chp7\Inventory\JsonRpcServer`类。这个服务器将需要一个 ZeroMQ 套接字，还需要一个对象，该对象提供客户端应该能够使用 RPC 调用的方法：

```php
namespace Packt\Chp7\Inventory; 

class JsonRpcServer 
{ 
    private $socket; 
    private $server; 

    public function __construct(\ZMQSocket $socket, $server) 
    { 
        $this->socket = $socket; 
        $this->server = $server; 
    } 
} 

```

我们现在可以实现一个方法，接收来自套接字的消息，尝试将它们解析为 JSON-RPC 消息，并调用`$server`对象上的相应方法，并返回该方法的结果值：

```php
public function run() 
{ 
    while ($msg = $this->socket->recv()) { 
        $resp = $this->handleMessage($msg); 
        $this->socket->send($resp); 
    } 
} 

```

与前面的例子一样，这个方法将无限运行，并处理任意数量的请求。现在，让我们来看看`handleMessage`方法：

```php
private function handleMessage(string $req): string { 
    $json   = json_decode($req); 
    $method = [$this->server, $json->method]; 

    if (is_callable($method)) { 
        $result = call_user_func_array($method, $json->params ?? []); 
        return json_encode([ 
            'jsonrpc' => '2.0, 
            'id'      => $json->id, 
            'result'  => $result 
        ]); 
    } else { 
        return json_encode([ 
            'jsonrpc' => '2.0', 
            'id'      => $json->id, 
            'error'   => [ 
                'message' => 'uncallable method ' . $json->method, 
                'code'    => -32601 
            ] 
        ]); 
    } 
} 

```

这个方法检查`$this->server`对象是否有一个与 JSON-RPC 请求的`method`属性相同的可调用方法。如果是，将使用请求的`param`属性作为参数调用此方法，并将返回值合并到 JSON-RPC 响应中。

目前，这个方法仍然缺少一些基本的异常处理。一个未处理的异常，一个致命错误可以终止整个服务器进程，所以我们在这里需要特别小心。首先，我们需要确保传入的消息确实是一个有效的 JSON 字符串：

```php
private function handleMessage(string $req): string { 
    $json   = json_decode($req); 
 **if (json_last_error()) {** 
 **return json_encode([** 
 **'jsonrpc' => '2.0',** 
 **'id'      => null,** 
 **'error'   => [** 
 **'message' => 'invalid json: ' .
json_last_error_msg(),** 
 **'code'    => -32700** 
 **]** 
 **]);** 
 **}** 

    // ... 
} 

```

还要确保捕获可能从实际服务函数中抛出的任何异常。由于我们使用的是 PHP 7，记住常规的 PHP 错误现在也会被抛出，因此不仅要捕获异常，还要捕获错误。您可以通过在`catch`子句中使用`Throwable`接口来捕获异常和错误：

```php
if (is_callable($method)) { 
 **try {** 
        $result = call_user_func_array($method, $json->params ?? []); 
        return json_encode(/* ... */); 
 **} catch (\Throwable $t) {** 
 **return json_encode([** 
 **'jsonrpc' => '2.0',** 
 **'id'      => $json->id,** 
 **'error'   => [** 
 **'message' => $t->getMessage(),** 
 **'code'    => $t->getCode()** 
 **]** 
 **]);** 
 **}** 
} else { // ... 

```

您现在可以继续实现包含库存服务业务逻辑的实际服务。由于我们到目前为止花了相当多的时间处理低级协议，让我们回顾一下这个服务的要求：库存服务管理库存中的文章。在结账过程中，库存服务需要检查所需文章的数量是否有库存，并在可能的情况下，减少给定数量的库存数量。

我们将在`Packt\Chp7\Inventory\InventoryService`类中实现这个逻辑。请注意，我们将尝试保持示例简单，并简单地在内存中管理我们的文章库存。在生产环境中，您可能会使用数据库管理系统来存储文章数据：

```php
namespace Packt\Chp7\Inventory\InventoryService; 

class InventoryService 
{ 
    private $stock = [ 
        1000 => 123, 
        1001 => 4, 
        1002 => 12 
    ]; 

    public function checkArticle(int $articleNumber, int $amount = 1): bool 
    { 
        if (!array_key_exists($articleNumber, $this->stock)) { 
            return false; 
        } 
        return $this->stock[$articleNumber] >= $amount; 
    } 

    public function takeArticle(int $articleNumber, int $amount = 1): bool 
    { 
        if (!$this->checkArticle($articleNumber, $amount) { 
            return false; 
        } 

        $this->stock[$articleNumber] -= $amount; 
        return true; 
    } 
} 

```

在这个例子中，我们从文章编号`1000`到`1002`开始。`checkArticle`函数测试给定文章的所需数量是否有库存。`takeArticle`函数尝试减少所需数量的文章数量，如果可能的话。如果成功，函数返回`true`。如果所需数量不在库存中，或者根本不知道这篇文章，函数将返回`false`。

现在我们有一个实现 JSON-RPC 服务器的类，另一个类包含我们库存服务的实际业务逻辑。我们现在可以将这两个类放在我们的`server.php`文件中一起使用：

```php
$args = getopt('p:', ['port=']); 
$ctx = new ZMQContext(); 

$port = $args['p'] ?? $args['port'] ?? 5557; 
$addr = 'tcp://*:' . $port; 

$sock = $ctx->getSocket(ZMQ::SOCKET_REP); 
$sock->bind($addr); 

**$service = new \Packt\Chp7\Inventory\InventoryService();** 
**$server = new \Packt\Chp7\Inventory\JsonRpcServer($sock, $service);** 
**$server->run();**

```

为了测试这个服务，至少在您的结账服务的第一个版本运行起来之前，您可以调整在上一节中创建的`client.php`脚本，以便发送和接收 JSON-RPC 消息：

```php
// ... 

$msg = [ 
    'jsonrpc' => '2.0', 
    'method'  => 'takeArticle', 
    'params'  => [1001, 2] 
]; 

$sock->send(json_encode($msg)); 
$response = json_decode($sock->recv()); 

if (isset($response->error)) { 
    // handle error... 
} else { 
    $success = $reponse->result; 
    var_dump($success); 
} 

```

每次调用此脚本都会从库存中删除两件编号为＃1001 的物品。在我们的例子中，我们使用的是一个在本地管理的库存，始终初始化为此文章的四件物品，因此`client.php`脚本的前两次调用将返回 true 作为结果，而所有后续调用将返回 false。

# 使库存服务多线程化

目前，库存服务在单个线程中运行，并且使用阻塞套接字。这意味着它一次只能处理一个请求；如果在处理其他请求时收到新请求，客户端将不得不等待直到所有先前的请求都完成处理。显然，这不是很好的扩展。

为了实现一个可以并行处理多个请求的服务器，您可以使用 ZeroMQ 的**ROUTER**/**DEALER**模式。ROUTER 是一种特殊类型的 ZeroMQ 套接字，行为非常类似于常规的 REP 套接字，唯一的区别是可以并行连接多个 REQ 套接字。同样，DEALER 套接字是另一种类似于 REQ 套接字的套接字，唯一的区别是可以连接到多个 REP 套接字。这使您可以构建一个负载均衡器，它只包括一个 ROUTER 和一个 DEALER 套接字，将多个客户端的数据包传输到多个服务器。

![使库存服务多线程化](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-bp/img/image_07_005.jpg)

ROUTER/DEALER 模式

由于 PHP 不支持多线程（至少不是很好），在这个例子中我们将采用多进程。我们的多线程服务器将由一个处理 ROUTER 和 DEALER 套接字的主进程以及多个每个使用一个 REP 套接字的 worker 进程组成。要实现这一点，您可以使用`pcntl_fork`函数分叉多个 worker 进程。

### 提示

为了使`pcntl_fork`函数工作，您需要启用`pcntl`扩展。在几乎所有的发行版中，这个扩展默认是启用的；在您之前构建的 Dockerfile 中，它也被明确安装了。如果您自己编译 PHP，那么在调用`configure`脚本时，您将需要`--enable-pcntl`标志。

在这个例子中，我们的库存服务将由多个 ZeroMQ 套接字组成：首先是大量的 worker 进程，每个进程都监听一个 RES 套接字以响应请求，以及一个主进程，每个 ROUTER 和 DEALER 套接字都接受和分发这些请求。只有 ROUTER 套接字对外部服务可见，并且可以通过 TCP 到达；对于所有其他套接字，我们将使用 UNIX 套接字进行通信 - 它们更快，且无法通过网络到达。

首先实现一个 worker 函数；为此创建一个名为`server_multithreaded.php`的新文件：

```php
require 'vendor/autoload.php'; 

use Packt\Chp7\Inventory\InventoryService; 
use Packt\Chp7\Inventory\JsonRpcServer; 

function worker() 
{ 
    $ctx = new ZMQContext(); 

    $sock = $ctx->getSocket(ZMQ::SOCKET_REP); 
    $sock->connect('ipc://workers.ipc'); 

    $service = new InventoryService(); 

    $server = new JsonRpcServer($sock, $service); 
    $server->run(); 
} 

```

`worker()`函数创建一个新的 REP 套接字，并将此套接字连接到 UNIX 套接字`ipc://workers.ipc`（这将由主进程稍后创建）。然后运行您之前已经使用过的`JsonRpcServer`。

现在，您可以使用`pcntl_fork`函数启动任意数量（在本例中为四个）的这些 worker 进程：

```php
for ($i = 0; $i < 4; $i ++) { 
    $pid = pcntl_fork(); 
    if ($pid == 0) { 
        worker($i); 
        exit(); 
    } 
} 

```

如果您不熟悉`fork`函数：它会复制当前运行的进程。分叉的进程将继续在分叉时的相同代码位置运行。然而，在父进程中，`pcntl_fork()`的返回值将返回新创建进程的进程 ID。然而，在新进程中，这个值将是 0。在这种情况下，子进程现在成为我们的 worker 进程，而实际的主进程将在不退出的情况下通过循环。

在此之后，您可以通过创建一个 ROUTER 和一个 DEALER 套接字来启动实际的负载均衡器：

```php
$args = getopt('p:', ['port=']); 
$ctx = new ZMQContext(); 

$port = $args['p'] ?? $args['port'] ?? 5557; 
$addr = 'tcp://*:' . $port; 

$ctx = new ZMQContext(); 

//  Socket to talk to clients 
$clients = $ctx->getSocket(ZMQ::SOCKET_ROUTER); 
$clients->bind($addr); 

//  Socket to talk to workers 
$workers = $ctx->getSocket(ZMQ::SOCKET_DEALER); 
$workers->bind("ipc://workers.ipc"); 

```

ROUTER 套接字绑定到服务预期可到达的实际网络地址（在本例中，允许通过网络到达服务的 TCP 套接字）。另一方面，DEALER 套接字绑定到一个本地 UNIX 套接字，不会暴露给外部世界。UNIX 套接字`ipc://workers.ipc`的唯一目的是工作进程可以将其 REP 套接字连接到它。

创建了 ROUTER 和 DEALER 套接字后，您可以使用`ZMQDevice`类将来自 ROUTER 套接字的传入数据包传输到 DEALER 套接字，然后平均分配到所有连接的 REP 套接字。从 REP 套接字发送回来的响应数据包也将被分发回原始客户端：

```php
//  Connect work threads to client threads via a queue 
$device = new ZMQDevice($clients, $workers); 
$device->run(); 

```

以这种方式更改库存服务不需要修改客户端代码；负载均衡器正在监听的 ROUTER 套接字行为非常类似于 REP 套接字，并且任何 REQ 套接字都可以以完全相同的方式连接到它。

# 构建结账服务

现在我们有一个管理您小型虚构电子商务企业库存的服务。接下来，我们将实现实际结账服务的第一个版本。结账服务将提供一个用于完成结账流程的 API，使用由多个文章和基本客户联系数据组成的购物车。

## 使用 react/zmq

为此，结账服务将提供一个简单的 REP ZeroMQ 套接字（或在并发设置中的 ROUTER 套接字）。在接收结账订单后，结账服务将与库存服务通信，以检查所需物品是否可用，并通过购物车中的物品数量减少库存数量。如果成功，它将在 PUB 套接字上发布结账订单，其他服务可以监听。

如果购物车包含多个物品，结账服务将需要多次调用库存服务。在本例中，您将学习如何并行进行多个请求以加快执行速度。我们还将使用`react/zmq`库，该库为 ZeroMQ 库提供了异步接口，以及`react/promise`库，它将帮助您更好地处理异步应用程序。

首先在新的`checkout/`目录中创建一个新的`composer.json`文件，并使用`composer install`初始化项目：

```php
{ 
 **"name": "packt-php7/chp7-checkout",** 
  "type": "project", 
  "authors": [{ 
    "name": "Martin Helmich", 
    "email": "php7-book@martin-helmich.de" 
  }], 
  "require": { 
    "php": ">= 7.0", 
 **"react/zmq": "⁰.3.0",** 
 **"react/promise": "².2",** 
    "ext-zmq": "*", 
 **"ext-ev": "*"** 
  }, 
  "autoload": { 
    "psr-4": { 
 **"Packt\\Chp7\\Checkout": "src/"** 
    } 
  } 

```

这个文件类似于库存服务的`composer.json`；唯一的区别是 PSR-4 命名空间和额外的要求`react/zmq`，`react/promise`和`ext-ev`。如果您正在使用 Docker 进行开发设置，您可以直接从库存服务中复制现有的 Dockerfile。

继续在您的`checkout/`目录中创建一个`server.json`文件。与任何 React 应用程序一样（记得第六章中的 Ratchet 应用程序，*构建聊天应用程序*），您需要做的第一件事是创建一个事件循环，然后运行它：

```php
<?php 
use \React\ZMQ\Factory; 
use \React\ZMQ\Context; 

require 'vendor/autoload.php'; 

$loop = Factory::create(); 
$ctx  = new Context($loop); 

$loop->run(); 

```

请注意，我们现在使用`React\ZMQ\Context`类而不是`ZMQContext`类。React 上下文类提供相同的接口，但通过一些功能扩展了其基类，以更好地支持异步编程。

您现在可以启动此程序，它将无限运行，但目前还不会执行任何操作。由于结账服务应该提供一个 REP 套接字，客户端应该发送请求到该套接字，因此在运行事件循环之前，您应该继续创建并绑定一个新的 REP 套接字：

```php
// ... 
$ctx = new Context($loop); 

**$socket = $ctx->getSocket(ZMQ::SOCKET_REP);** 
**$socket->bind('tcp://0.0.0.0:5557');** 

$loop->run(); 

```

**ReactPHP**应用程序是异步的；现在，您可以在套接字上注册事件处理程序，而不是只调用`recv()`等待下一个传入消息，ReactPHP 的事件循环将在收到消息时立即调用它：

```php
// ... 

$socket = $ctx->getSocket(ZMQ::SOCKET_REP); 
$socket->bind('tcp://0.0.0.0:5557'); 
**$socket->on('message', function(string $msg) use ($socket) {** 
 **echo "received message $msg.\n";** 
 **$socket->send('Response text');** 
**});** 

$loop->run(); 

```

这种回调解决方案类似于您在开发客户端 JavaScript 代码时最常遇到的其他异步库。基本原则是相同的：`$socket->on(...)`方法只是注册一个事件监听器，可以在以后的任何时间点调用，每当收到新消息时。代码的执行将立即继续（与此相反，比较常规的`$socket->recv()`函数会阻塞，直到收到新消息），然后调用`$loop->run()`方法。这个调用启动了实际的事件循环，负责在收到新消息时调用注册的事件监听器。事件循环将一直阻塞，直到被中断（例如，通过命令行上的*Ctrl* + *C*触发的 SIGINT 信号）。

## 使用承诺

在处理异步代码时，通常只是时间的问题，直到您发现自己陷入了“回调地狱”。想象一下，您想发送两个连续的 ZeroMQ 请求（例如，首先询问库存服务给定的文章是否可用，然后实际上指示库存服务减少所需数量的库存）。您可以使用多个套接字和您之前看到的“消息”事件来实现这一点。然而，这很快就会变成一个难以维护的混乱：

```php
$socket->on('message', function(string $msg) use ($socket, $ctx) { 
    $check = $ctx->getSocket(ZMQ::SOCKET_REQ); 
    $check->connect('tcp://identity:5557'); 
    $check->send(/* checkArticle JSON-RPC here */); 
    $check->on('message', function(string $msg) use ($socket, $ctx) { 
        $take = $ctx->getSocket(ZMQ::SOCKET_REQ); 
        $take->connect('tcp://identity:5557'); 
        $take->send(/* takeArticle JSON-RPC here */); 
        $take->on('message', function(string $msg) use ($socket) { 
            $socket->send('success'); 
        }); 
    }); 
}); 

```

上述代码片段只是说明了这可能变得多么复杂的一个例子；在我们的情况下，您甚至需要考虑每个结账订单可能包含任意数量的文章，每篇文章都需要两个新请求到身份服务。

为了让生活更美好，您可以使用承诺来实现这个功能（有关该概念的详细解释，请参见下面的框）。`react/promise`库提供了良好的承诺实现，应该已经在您的`composer.json`文件中声明。

### 注意

**什么是承诺？** 承诺（有时也称为未来）是异步库中常见的概念。它们提供了一种替代常规基于回调的方法。

基本上，承诺是一个代表尚未可用的值的对象（例如，因为应该检索该值的 ZeroMQ 请求尚未收到回复）。在异步应用程序中，承诺可能随时变得可用（实现）。然后，您可以注册应该在承诺实现时调用的函数，以进一步处理承诺的已解析值：`$promise = $someService->someFunction();` `$promise->then(function($promisedValue) {` `    echo "Promise resolved: $promisedValue\n";` `});`

`then()`函数的每次调用都会返回一个新的承诺，这次是由传递给`then()`的回调返回的值。这使您可以轻松地将多个承诺链接在一起：

`$promise` `    ->then(function($value) use ($someService) {` `        $newPromise = $someService->someOtherFunc($value);` `        return $newPromise;` `    })` `    ->then(function ($newValue) {` `        echo "Promise resolved: $newValue\n";` `    });`

现在，我们可以通过编写一个用于与我们的库存服务通信的异步客户端类来利用这个原则。由于该服务使用 JSON-RPC 进行通信，我们现在将实现`Packt\Chp7\Checkout\JsonRpcClient`类。该类使用 ZeroMQ 上下文进行初始化，并且为了方便起见，还包括远程服务的 URL：

```php
namespace Packt\Chp7\Checkout; 

use React\Promise\PromiseInterface; 
use React\ZMQ\Context; 

class JsonRpcClient 
{ 
    private $context; 
    private $url; 

    public function __construct(Context $context, string $url) 
    { 
        $this->context = $context; 
        $this->url     = $url; 
    } 

    public function request(string $method, array $params = []): PromiseInterface 
    { 
    } 
} 

```

在这个例子中，该类已经包含一个`request`方法，该方法接受一个方法名和一组参数，并应返回`React\Promise\PromiseInterface`的实现。

在`request()`方法中，您现在可以打开一个新的 REQ 套接字并向其发送一个 JSON-RPC 请求：

```php
public function request(string $method, array $params = []): PromiseInterface 
{ 
 **$body = json_encode([** 
 **'jsonrpc' => '2.0',** 
 **'method'  => $method,** 
 **'params'  => $params,** 
 **]);** 
 **$sock = $this->context->getSocket(\ZMQ::SOCKET_REQ);** 
 **$sock->connect($this->url);** 
 **$sock->send($body);** 
} 

```

由于`request()`方法应该是异步工作的，您不能简单地调用`recv()`方法并阻塞，直到收到结果。相反，我们需要返回一个对响应值的承诺，以便稍后可以解决，每当在 REQ 套接字上收到响应消息时。为此，您可以使用`React\Promise\Deferred`类：

```php
$body = json_encode([ 
    'jsonrpc' => '2.0', 
    'method'  => $method, 
    'params'  => $params, 
]); 
**$deferred = new Deferred();** 

$sock = $this->context->getSocket(\ZMQ::SOCKET_REQ); 
$sock->connect($this->url); 
**$sock->on('message', function(string $response) use ($deferred) {** 
 **$deferred->resolve($response);** 
**});** 
$sock->send($body); 

**return $deferred->promise();**

```

这是承诺如何工作的一个典型例子：您可以使用`Deferred`类来创建并返回一个尚未可用的值的承诺。记住：传递给`$sock->on(...)`方法的函数不会立即被调用，而是在任何以后的时间点，当实际收到响应时。一旦发生这种事件，由请求函数返回的承诺将以实际的响应值解决。

由于响应消息包含 JSON-RPC 响应，您需要在满足对请求函数的调用者所做的承诺之前评估这个响应。由于 JSON-RPC 响应也可能包含错误，值得注意的是，您也可以拒绝一个承诺（例如，在等待响应时发生错误时）：

```php
$sock->on('message', function(string $response) use ($deferred) { 
 **$response = json_decode($response);** 
 **if (isset($response->result)) {** 
 **$deferred->resolve($response->result);** 
 **} elseif (isset($response->error)) {** 
 **$deferred->reject(new \Exception(** 
 **$response->error->message,** 
 **$response->error->code** 
 **);** 
 **} else {** 
 **$deferred->reject(new \Exception('invalid response'));** 
 **}** 
}); 

```

现在，您可以在您的`server.php`中使用这个 JSON-RPC 客户端类，以便在每个传入的结账请求上实际与库存服务进行通信。让我们从一个简单的例子开始，演示如何使用新类将两个连续的 JSON-RPC 调用链接在一起：

```php
$client = new JsonRpcClient($ctx, 'tcp://inventory:5557'); 
$client->request('checkArticle', [1000]) 
    ->then(function(bool $ok) use ($client) { 
        if ($ok) { 
            return $client->request('takeArticle', [1000]); 
        } else { 
            throw new \Exception("Article is not available"); 
        } 
    }) 
    ->then(function(bool $ok) { 
        if ($ok) { 
            echo "Successfully took 1 item of article 1000"; 
        } 
    }, function(\Exception $error) { 
        echo "An error occurred: ${error->getMessage()}\n"; 
    }); 

```

正如您所看到的，`PromiseInterface`的`then`函数接受两个参数（每个都是一个新函数）：第一个函数将在承诺以实际值解决时被调用；第二个函数将在承诺被拒绝时被调用。

如果传递给`then(...)`的函数返回一个新值，那么 then 函数将返回一个新的承诺。这个规则的一个例外是当回调函数本身返回一个新的承诺（在我们的情况下，在`then()`回调中再次调用了`$client->request`）。在这种情况下，返回的承诺将替换原始承诺。这意味着对`then()`函数的链接调用实际上是在第二个承诺上监听。

让我们在`server.php`文件中使用这个。与前面的例子相比，您需要考虑每个结账订单可能包含多个文章。这意味着您需要对库存服务执行多个`checkArticle`请求：

```php
**$client = new JsonRpcClient($ctx, 'tcp://inventory:5557');** 
$socket->on('message', function(string $msg) use ($socket, $client) { 
 **$request = json_decode($msg);** 
 **$promises = [];** 
 **foreach ($request->cart as $article) {** 
 **$promises[] = $client->request('checkArticle', [$article->articlenumber, $article->amount]);** 
    } 
}); 

```

在这个例子中，我们假设传入的结账订单是 JSON 编码的消息，看起来像下面的例子：

```php
{ 
  "cart": [ 
    "articlenumber": 1000, 
    "amount": 2 
  ] 
} 

```

在我们的`server.php`的当前版本中，我们多次调用 JSON-RPC 客户端，并将返回的承诺收集到一个数组中。然而，我们实际上还没有对它们做任何事情。现在，您可以对这些承诺中的每一个调用`then()`函数，其中包含一个回调，该回调将对每个文章进行调用，并传递一个布尔参数，指示这篇文章是否可用。然而，为了正确处理订单，我们需要知道结账订单中的所有文章是否都可用。所以你需要做的不是等待每个承诺单独完成，而是等待它们全部完成。这就是`React\Promise\all`函数的作用：这个函数以承诺列表作为参数，并返回一个新的承诺，一旦所有提供的承诺都被实现，它就会被实现：

```php
$request = json_decode($msg); 
$promises = []; 

foreach ($request->cart as $article) { 
    $promises[] = $client->request('checkArticle', [$article->articlenumber, $article->amount]); 
} 

**React\Promise\all($promises)->then(function(array $values) use ($socket) {** 
 **if (array_sum($values) == count($values)) {** 
 **echo "all required articles are available";** 
 **} else {** 
 **$socket->send(json_encode([** 
 **'error' => 'not all required articles are available'** 
 **]);** 
 **}**
**});**

```

如果库存服务中没有所有所需的文章，您可以提前用错误消息回答请求，因为没有必要继续下去。如果所有文章都可用，您将需要一系列后续请求来实际减少指定数量的库存。

### 提示

在这个例子中使用的`array_sum($values) == count($values)`构造是一个快速的解决方法，用来确保布尔值数组只包含 true 值。

接下来，您现在可以扩展您的服务器，以在所有`checkArticle`方法调用成功返回后运行第二组请求到库存服务。这可以通过使用`React\Promise\all`方法按照之前的方式完成：

```php
React\Promise\all($promises)->then(function(array $values) use ($socket, $request) { 
 **$promises = [];** 
 **if (array_sum($values) == count($values)) {** 
 **foreach ($request->cart as $article) {** 
 **$promises[] = $client->request('takeArticle', [$article->articlenumber, $article->amount]);** 
 **}** 
 **React\Promise\all($promises)->then(function() use ($socket) {** 
 **$socket->send(json_encode([** 
 **'result' => true** 
 **]);** 
 **}** 
    } else { 
        $socket->send(json_encode([ 
            'error' => 'not all required articles are available' 
        ]); 
    } 
}); 

```

为了实际测试这个新的服务器，让我们编写一个简短的测试脚本，尝试执行一个示例结账订单。为此，在您的`checkout/`目录中创建一个新的`client.php`文件：

```php
$ctx  = new ZMQContext(); 
$sock = $ctx->getSocket(ZMQ::SOCKET_REQ); 
$sock->connect('tcp://checkout:5557'); 
$sock->send(json_encode([ 
    'cart' => [ 
        ['articlenumber' => 1000, 'amount' => 3], 
        ['articlenumber' => 1001, 'amount' => 2] 
    ] 
])); 

$result = $sock->recv(); 
var_dump($result); 

```

要运行结账服务和测试脚本，可以在项目的根目录中使用新的结账服务扩展您的`docker-compose.yml`文件：

```php
**checkout:** 
 **build: checkout** 
 **volumes:** 
 **- checkout:/usr/src/app** 
 **links:** 
 **- inventory:inventory** 
inventory: 
  build: inventory 
  ports: 
    - 5557 
  volumes: 
    - inventory:/usr/src/app 

```

对于测试脚本，添加第二个 Compose 配置文件`docker-compose.testing.yml`：

```php
test: 
  build: checkout 
  command: php client.php 
  volumes: 
    - checkout:/usr/src/app 
  links: 
    - checkout:checkout 

```

之后，您可以使用以下命令行命令测试您的结账服务：

```php
**$ docker-compose up -d 
$ docker-compose -f docker-compose.testing.yml run --rm test**

```

以下屏幕截图显示了测试脚本和两个服务器脚本的示例输出（在此示例中，添加了一些额外的`echo`语句，使服务器更加详细）：

![使用承诺工作](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-bp/img/image_07_006.jpg)

结账和库存服务处理结账订单的示例输出

# 构建邮寄服务

接下来，我们将在我们的微服务架构中加入一个邮寄服务。在处理结账后，用户应该通过电子邮件收到有关结账状态的通知。

### 提示

如前所述，本章的重点是构建个别服务之间的通信模式。因此，在本节中，我们不会实现邮寄服务的实际邮寄功能，而是专注于该服务如何与其他服务通信。查看第三章*构建社交通讯服务*，了解如何使用 PHP 实际向其他收件人发送电子邮件。

理论上，您可以像实现库存服务一样实现邮寄服务-构建一个独立的 PHP 程序，监听 ZeroMQ REP 套接字，让结账服务打开一个 REQ 套接字，并向邮寄服务发送请求。但是，也可以使用发布/订阅模式来实现相同的功能。

使用发布/订阅模式，结账服务甚至不需要知道邮寄服务。相反，结账服务只需打开其他服务可以连接到的 PUB 套接字。在 PUB 套接字上发送的任何消息都会分发到所有连接的（订阅）服务。这允许您实现一个非常松散耦合的架构，也非常可扩展-您可以通过让更多和不同的服务订阅相同的 PUB 套接字来为您的结账流程添加新功能，而无需修改结账服务本身。

这是可能的，因为在邮寄服务的情况下，通信不需要是同步的-结账服务在继续流程之前不需要等待邮寄服务完成其操作，也不需要来自邮寄服务的任何数据。相反，消息可以严格单向流动-从结账服务到邮寄服务。

首先，您需要在结账服务中打开 PUB 套接字。为此，请修改结账服务的`server.php`，创建一个新的 PUB 套接字，并将其绑定到 TCP 地址：

```php
$socket = $ctx->getSocket(ZMQ::SOCKET_REP); 
$socket->bind('tcp://0.0.0.0:5557'); 

**$pubSocket = $ctx->getSocket(ZMQ::SOCKET_PUB);**
**$pubSocket->bind('tcp://0.0.0.0:5558');** 

$client = new JsonRpcClient($ctx, 'tcp://inventory:5557'); 

```

成功从库存服务中取得所需物品后，您可以在此套接字上发布消息。在这种情况下，我们将简单地在 PUB 套接字上重新发送原始消息：

```php
$socket->on('message', function(string $msg) use ($client, $pubSocket) { 
    // ... 
    React\Promise\all($promises)->then(function(array $values) use ($socket, $pubSocket, $request) { 
        $promises = []; 
        if (array_sum($values) == count($values)) { 
            // ... 
            React\Promise\all($promises)->then(function() use ($socket, $pubSocket, $request) { 
 **$pubSocket->send($request);** 
            $socket->send(json_encode([ 
                'result' => true 
            ]); 
        } else { 
            $socket->send(json_encode([ 
                'error' => 'not all required articles are available' 
            ]); 
        } 
    }); 
}); 

$loop->run(); 

```

现在，您已经在接受的结账订单上发布了一个 PUB 套接字，可以编写实际的邮寄服务，创建一个订阅此 PUB 套接字的 SUB 套接字。

为此，在项目目录中创建一个名为`mailing/`的新目录。从先前的示例中复制 Dockerfile，并创建一个新的`composer.json`文件，内容如下：

```php
{ 
 **"name": "packt-php7/chp7-mailing",** 
    "type": "project", 
    "authors": [{ 
        "name": "Martin Helmich", 
        "email": "php7-book@martin-helmich.de" 
    }], 
    "require": { 
        "php": ">= 7.0", 
        "react/zmq": "⁰.3.0" 
    }, 
    "autoload": { 
        "psr-4": { 
 **"Packt\\Chp7\\Mailing": "src/"** 
        } 
    } 
} 

```

与以前的示例相比，唯一的区别是新的包名称和不同的 PSR-4 自动加载命名空间。此外，您不需要`react/promise`库来进行邮寄服务。像往常一样，在`mailing/`目录中的命令行上运行`composer install`来下载所需的依赖项。

您现在可以在`mailing/`目录中创建一个新的`server.php`文件，其中创建一个新的 SUB 套接字，然后可以连接到结帐服务：

```php
require 'vendor/autoload.php'; 

$loop = \React\EventLoop\Factory::create(); 
$ctx  = new \React\ZMQ\Context($loop); 

$socket = $ctx->getSocket(ZMQ::SOCKET_SUB); 
$socket->subscribe(''); 
$socket->connect('tcp://checkout:5558'); 

$loop->run(); 

```

注意`$socket->subscribe()`调用。每个 SUB 套接字可以订阅给定的*主题*或*频道*。频道由一个字符串前缀标识，可以作为每个发布的消息的一部分提交。然后客户端只会接收与他们订阅的频道匹配的消息。如果您不关心一个 PUB 套接字上的不同频道，您可以通过调用`$socket->subscribe`并传递一个空字符串来订阅空频道，从而接收在 PUB 套接字上发布的所有消息。但是，如果您不调用 subscribe 方法，您将根本不会收到任何消息。

套接字连接后，您可以为`'message'`事件提供一个监听函数，在其中解码 JSON 编码的消息并相应地处理它：

```php
$socket->connect('tcp://checkout:5558'); 
**$socket->on('message', function(string $msg) {** 
 **$data = json_decode($msg);** 
 **if (isset($data->customer->email)) {** 
 **$email = $data->customer->email;** 
 **echo "sending confirmation email to $email.\n";** 
 **}** 
**});** 

$loop->run(); 

```

还要注意，PUB 和 SUB 套接字是严格单向的：您可以从 PUB 套接字向任意数量的订阅的 SUB 套接字发送消息，但您不能在同一个套接字上回复给发布者-至少不能。如果您真的需要某种反馈渠道，您可以让发布者在一个单独的 REP 或 SUB 套接字上监听，订阅者使用新的 REQ 或 PUB 套接字连接。以下图表说明了实现这样的反馈渠道的两种策略：

![构建邮寄服务](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-bp/img/image_07_007.jpg)

在发布/订阅架构中实现反馈通道的不同策略

要测试新的邮寄服务，您可以重用上一节中的`client.php`脚本。由于邮寄服务要求结帐订单包含电子邮件地址，您需要将其添加到消息正文中：

```php
$sock->send(json_encode([ 
    'cart' => [ 
        ['articlenumber' => 1000, 'amount' => 3], 
        ['articlenumber' => 1001, 'amount' => 2] 
    ], 
 **'customer' => [** 
 **'email' => 'john.doe@example.com'** 
    ] 
])); 

```

还要记得将新的邮寄服务添加到`docker-compose.yml`文件中：

```php
# ... 
checkout: 
  build: checkout 
  volumes: 
    - checkout:/usr/src/app 
  links: 
    - inventory:inventory 
**mailing:** 
 **build: mailing** 
 **volumes:** 
 **- mailing:/usr/src/app** 
 **links:** 
 **- checkout:checkout** 
inventory: 
  build: inventory 
  ports: 
    - 5557 
  volumes: 
    - inventory:/usr/src/app 

```

在`docker-compose.yml`中添加新服务后，启动所有服务并再次运行测试脚本：

```php
**$ docker-compose up -d inventory checkout mailing**
**$ docker-compose run --rm test**

```

之后，检查单独的容器的输出，以检查结帐订单是否被正确处理：

```php
**$ docker-compose logs**

```

# 构建邮寄服务

在我们的小型电子商务示例中，我们还缺少邮寄服务。在现实世界的场景中，这将是一个非常复杂的任务，您通常需要与外部方进行通信，也许需要与外部运输服务提供商的 API 集成。因此，我们现在将使用 PUSH 和 PULL 套接字以及任意数量的工作进程构建我们的邮寄服务作为工作池。

## 初学者的 PUSH/PULL

PUB 套接字将每条消息发布到所有连接的订阅者。ZeroMQ 还提供了 PUSH 和 PULL 套接字类型-它们的工作方式类似于 PUB/SUB，但在 PUSH 套接字上发布的每条消息只发送到潜在的多个连接的 PULL 套接字中的一个。您可以使用这个来实现一个工作池，将长时间运行的任务推送到其中，然后并行执行。

为此，我们需要一个使用 SUB 套接字订阅已完成结帐订单的主进程。同一进程需要提供一个 PUSH 套接字，以便各个工作进程可以连接到它。以下图表说明了这种架构：

![初学者的 PUSH/PULL](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-bp/img/image_07_008.jpg)

PUB/SUB 和 PUSH/PULL 的组合

像往常一样，首先在项目文件夹中创建一个新的`shipping/`目录。从以前的服务中复制 Dockerfile，创建一个新的`composer.json`文件，并使用`composer install`初始化项目：

```php
{ 
 **"name": "packt-php7/chp7-shipping",** 
    "type": "project", 
    "authors": [{ 
        "name": "Martin Helmich", 
        "email": "php7-book@martin-helmich.de" 
    }], 
    "require": { 
        "php": ">= 7.0.0", 
        "react/zmq": "⁰.3.0" 
    }, 
    "autoload": { 
        "psr-4": { 
 **"Packt\\Chp7\\Shipping": "src/"** 
        } 
    } 
} 

```

我们将从实现主进程开始。这个主进程需要做三件简单的事情：

+   打开一个 SUB 套接字，并将此套接字连接到结帐服务的 PUB 套接字。这将允许运输服务接收结帐服务接受的所有结帐订单。

+   打开一个 PUSH 套接字，并将此套接字绑定到一个新的 TCP 端口。这将允许工作进程连接并接收结帐订单。

+   将在 SUB 套接字上接收的每条消息转发到 PUSH 套接字。

为此，在您的`shipping/`目录中创建一个新的`master.php`文件，您可以在其中创建一个新的事件循环并创建两个所需的套接字：

```php
require 'vendor/autoload.php'; 

$loop = React\EventLoop\Factory::create(); 
$ctx  = new React\ZMQ\Context($loop); 

$subSocket = $ctx->getSocket(ZMQ::SOCKET_SUB); 
$subSocket->subscribe(''); 
$subSocket->connect('tcp://checkout:5558'); 

$pushSocket = $ctx->getSocket(ZMQ::SOCKET_PUSH); 
$pushSocket->bind('tcp://0.0.0.0:5557'); 

$loop->run(); 

```

为了实际处理在 SUB 套接字上接收的消息，注册一个监听器函数在`$subSocket`变量上，将每个接收到的消息发送到 PUSH 套接字：

```php
$pushSocket->bind('tcp://0.0.0.0:5557'); 

**$subSocket->on('message', function(string $msg) use ($pushSocket) {** 
 **echo 'dispatching message to worker';** 
 **$pushSocket->send($msg);** 
**});** 

$loop->run(); 

```

接下来，在`shipping/`目录中创建一个名为`worker.php`的新文件。在这个文件中，您将创建一个 PULL 套接字，用于接收主进程中打开的 PUSH 套接字上的消息：

```php
require 'vendor/autoload.php'; 

$loop = React\EventLoop\Factory::create(); 
$ctx  = new React\ZMQ\Context($loop); 

$pullSocket = $ctx->getSocket(ZMQ::SOCKET_PULL); 
$pullSocket->connect('tcp://shippingmaster:5557'); 

$loop->run(); 

```

再次，附加一个监听器函数到`$pullSocket`，以处理传入的消息：

```php
$pullSocket->connect('tcp://shippingmaster:5557'); 
**$pullSocket->on('message', function(string $msg) {** 
 **echo "processing checkout order for shipping: $msg\n";** 
 **sleep(5);** 
**});** 

$loop->run(); 

```

`sleep(5)`，在这个例子中，只是模拟执行可能需要更长时间的运输订单。与本章中一样，我们不会实现实际的业务逻辑，只需要演示各个服务之间的通信模式。

为了测试运输服务，现在将主进程和工作进程添加到您的`docker-compose.yml`文件中：

```php
# ... 

inventory: 
  build: inventory 
  volumes: 
    - inventory:/usr/src/app 

**shippingmaster:** 
 **build: shipping** 
 **command: php master.php** 
 **volumes:** 
 **- shipping:/usr/src/app** 
 **links:** 
 **- checkout:checkout** 
**shippingworker:** 
 **build: shipping** 
 **command: php worker.php** 
 **volumes:** 
 **- shipping:/usr/src/app** 
 **links:** 
 **- shippingmaster:shippingmaster**

```

之后，您可以启动所有容器，然后使用以下命令跟踪它们的输出：

```php
**$ docker-compose up -d**

```

默认情况下，Docker compose 将始终启动每个服务的一个实例。但是，您可以使用`docker-compose scale`命令启动每个服务的附加实例。这对于`shippingworker`服务来说是一个好主意，因为我们为该服务选择的 PUSH/PULL 架构实际上允许任意数量的该服务实例并行运行：

```php
**$ docker-compose scale shippingworker=4**

```

在启动了一些更多的`shippingworker`服务实例之后，您可以使用`docker-compose logs`命令附加到所有容器的日志输出。然后，使用第二个终端启动您在上一节中创建的客户端测试脚本：

```php
**$ docker-compose run --rm test**

```

当您多次运行此命令时，您将看到在后续调用的容器的不同实例中打印的运输工作进程中的调试输出。您可以在以下截图中看到一个示例输出：

![初学者的 PUSH/PULL](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-bp/img/image_07_009.jpg)

演示具有多个工作进程的工作推/拉架构的示例输出

## 扇出/扇入

除了将耗时的任务分配给多个工作进程外，您还可以使用 PUSH 和 PULL 套接字让工作进程将结果推送回主进程。这种模式称为**扇出/扇入**。对于本例，让`master.php`文件中的主进程监听一个单独的 PULL 套接字：

```php
$pushSocket = $ctx->getSocket(ZMQ::SOCKET_PUSH); 
$pushSocket->bind('tcp://0.0.0.0:5557'); 

**$pullSocket = $ctx->getSocket(ZMQ::SOCKET_PULL);** 
**$pullSocket->bind('tcp://0.0.0.0:5558');** 
**$pullSocket->on('message', function(string $msg) {** 
 **echo "order $msg successfully processed for shipping\n";** 
**});** 

$subSocket->on('message', function(string $msg) use ($pushSocket) { 
    // ... 
}); 

$loop->run(); 

```

在`worker.php`文件中，您现在可以使用新的 PUSH 套接字连接到此 PULL 套接字，并在成功处理结帐订单时发送消息：

```php
**$pushSocket = $ctx->getSocket(ZMQ::SOCKET_PUSH);**
**$pushSocket->connect('tcp://shippingmaster:5558');** 

$pullSocket = $ctx->getSocket(ZMQ::SOCKET_PULL); 
$pullSocket->connect('tcp://shippingmaster:5557'); 
$pullSocket->on('message', function(string $msg) use ($pushSocket) { 
    echo "processing checkout order for shipping: $msg\n"; 
    sleep(5); 
 **$pushSocket->send($msg);** 
}); 

$loop->run(); 

```

一旦处理完消息，这将立即将消息推送回主进程。请注意，PUSH/PULL 的使用方式与上一节中的方式相反-之前我们有一个 PUSH 套接字和多个 PULL 套接字；对于扇入，我们在主进程上有一个 PULL 套接字，而在工作进程上有多个 PUSH 套接字。

### 提示

**使用 bind()和 connect()**

在本节中，我们已经使用了 PUSH 和 PULL 套接字的`bind()`和`connect()`方法。通常，`bind()`用于让套接字监听新的 TCP 端口（或 UNIX 套接字），而`connect()`用于让套接字连接到另一个已经存在的套接字。通常情况下，您可以在任何套接字类型上使用`bind()`和`connect()`。在某些情况下，比如 REQ/REP，您会直觉地`bind()`REP 套接字，然后`connect()`REQ 套接字，但 PUSH/PULL 和 PUB/SUB 实际上都可以双向工作。您可以让 PULL 套接字连接到监听的 PUSH 套接字，但也可以让 PUSH 套接字连接到监听的 PULL 套接字。

以下截图显示了运输服务的主进程和工作进程并行处理多个结账订单的示例输出。请注意，实际处理是由不同的工作进程（在此示例中为`shippingworker_1`到`shippingworker_3`）完成的，但之后被"扇入"回主进程：

![扇出/扇入](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-bp/img/image_07_010.jpg)

扇出/扇入的实际操作

# 连接 ZeroMQ 和 HTTP

正如您在本章中所看到的，ZeroMQ 提供了许多不同的可能性，用于在不同的服务之间实现通信。特别是，发布/订阅和推/拉等模式在 PHP 的事实标准协议 HTTP 中并不容易实现。

另一方面，HTTP 更广泛地被采用，并提供了更丰富的协议语义集，处理诸如缓存或身份验证等问题已经在协议级别上。因此，特别是在提供外部 API 时，您可能更喜欢提供基于 HTTP 而不是基于 ZeroMQ 的 API。幸运的是，在两种协议之间进行桥接很容易。在我们的示例架构中，结账服务是唯一会被外部服务使用的服务。为了为结账服务提供更好的接口，我们现在将实现一个基于 HTTP 的结账服务包装器，可以以 RESTful 方式使用。

为此，您可以使用`react/http`包。该包提供了一个极简的 HTTP 服务器，就像`react/zmq`一样，它是异步工作的，并使用事件循环来处理请求。这意味着基于 react 的 HTTP 服务器甚至可以在同一个进程中，使用与结账服务已经提供的 REP ZeroMQ 套接字相同的事件循环来运行。首先，在项目目录中的`checkout/`文件夹中运行以下命令来安装`react/http`包：

```php
**$ composer require react/http**

```

在扩展结账服务以使用 HTTP 服务器之前，`server.php`脚本需要进行一些重构。当前，`server.php`创建了一个带有事件监听函数的 REP ZeroMQ 套接字，其中处理请求。由于我们的目标现在是添加一个触发相同功能的 HTTP API，我们需要将此逻辑提取到一个单独的类中。首先创建`Packt\Chp7\Checkout\CheckoutService`类：

```php
namespace Packt\Chp7\Checkout; 

use React\Promise\PromiseInterface; 

class CheckoutService 
{ 
    private $client; 

    public function __construct(JsonRpcClient $client) 
    { 
        $this->client = $client; 
    } 

    public function handleCheckoutOrder(string $msg): PromiseInterface 
    { 
    } 
} 

```

`handleCheckoutOrder`方法将保存之前直接在`server.php`文件中实现的逻辑。由于此方法稍后将被 ZeroMQ REP 套接字和 HTTP 服务器同时使用，因此此方法不能直接发送响应消息，而只能返回一个 promise，然后可以在`server.php`中使用：

```php
public function handleCheckoutOrder(string $msg): PromiseInterface 
{ 
    $request = json_decode($msg); 
    $promises = []; 

    foreach ($request->cart as $article) { 
        $promises[] = $this->client->request('checkArticle', [$article->articlenumber, $article->amount]); 
    } 

    return \React\Promise\all($promises) 
        ->then(function(array $values):bool { 
            if (array_sum($values) != count($values)) { 
                throw new \Exception('not all articles are in stock'); 
            } 
            return true; 
        })->then(function() use ($request):PromiseInterface { 
            $promises = []; 

            foreach ($request->cart as $article) { 
                $promises[] = $this->client->request('takeArticle', [$article->articlenumber, $article->amount]); 
            } 

            return \React\Promise\all($promises); 
        })->then(function(array $values):bool { 
            if (array_sum($values) != count($values)) { 
                throw new \Exception('not all articles are in stock'); 
            } 
            return true; 
        }); 
} 

```

一致使用 promise 并不关心返回消息实际上允许一些简化；而不是直接发送错误消息，您可以简单地抛出异常，这将导致此函数返回的*promise*被自动拒绝。

现有的`server.php`文件现在可以简化为几行代码：

```php
$client          = new JsonRpcClient($ctx, 'tcp://inventory:5557'); 
**$checkoutService = new CheckoutService($client);** 

$socket->on('message', function($msg) use ($ctx, $checkoutService, $pubSocket, $socket) { 
    echo "received checkout order $msg\n"; 

 **$checkoutService->handleCheckoutOrder($msg)->then(function() use ($pubSocket, $msg, $socket) {** 
 **$pubSocket->send($msg);** 
 **$socket->send(json_encode(['msg' => 'OK']));** 
 **}, function(\Exception $err) use ($socket) {** 
 **$socket->send(json_encode(['error' => $err->getMessage()]));** 
 **});** 
}); 

```

接下来，您可以开始处理 HTTP 服务器。为此，您首先需要一个简单的套接字服务器，然后将其传递到实际的 HTTP 服务器类中。这可以在运行事件循环之前的`server.php`中的任何时间点完成：

```php
**$httpSocket = new \React\Socket\Server($loop);** 
**$httpSocket->listen(8080, '0.0.0.0');** 
**$httpServer = new \React\Http\Server($httpSocket);** 

$loop->run(); 

```

HTTP 服务器本身有一个`'request'`事件，您可以为其注册一个监听函数（类似于 ZeroMQ 套接字的`'message'`事件）。监听函数作为参数传递了一个请求和一个响应对象。这些都是`React\Http\Request`和`React\Http\Response`类的实例：

```php
$httpServer->on('request', function(React\Http\Request $req, React\Http\Response $res) { 
    $res->writeHead(200); 
    $res->end('Hello World'); 
}); 

```

不幸的是，React HTTP 的`Request`和`Response`类与相应的 PSR-7 接口不兼容。但是，如果有需要，您可以相对容易地将它们转换，就像在第六章*构建聊天应用程序*中已经看到的那样，*桥接 Ratchet 和 PSR-7 应用程序*部分中。

在此监听函数中，您可以首先检查正确的请求方法和路径，并发送错误代码，否则：

```php
$httpServer->on('request', function(React\Http\Request $req, React\Http\Response $res) { 
 **if ($request->getPath() != '/orders') {** 
 **$msg = json_encode(['msg' => 'this resource does not exist']);** 
 **$response->writeHead(404, [** 
 **'Content-Type' => 'application/json;charset=utf8',** 
 **'Content-Length' => strlen($msg)** 
 **]);** 
 **$response->end($msg);** 
 **return;** 
 **}** 
 **if ($request->getMethod() != 'POST') {** 
 **$msg = json_encode(['msg' => 'this method is not allowed']);** 
 **$response->writeHead(405, [** 
 **'Content-Type' => 'application/json;charset=utf8',** 
 **'Content-Length' => strlen($msg)** 
 **]);** 
 **$response->end($msg);** 
 **return;** 
 **}** 
}); 

```

这就是问题所在。ReactPHP HTTP 服务器是如此异步，以至于当触发`request`事件时，请求正文尚未从网络套接字中读取。要获取实际的请求正文，您需要监听请求的`data`事件。但是，请求正文以 4096 字节的块读取，因此对于大型请求正文，数据事件实际上可能会被多次调用。读取完整的请求正文的最简单方法是检查`Content-Length`标头，并在数据事件处理程序中检查是否已经读取了确切数量的字节：

```php
$httpServer->on('request', function(React\Http\Request $req, React\Http\Response $res) { 
    // error checking omitted... 

 **$length = $req->getHeaders()['Content-Length'];** 
 **$body   = '';** 
 **$request->on('data', function(string $chunk) use (&$body) {** 
 **$body .= $chunk;** 
 **if (strlen($body) == $length) {** 
 **// body is complete!** 
 **}** 
 **});** 
}); 

```

当发送方在其请求中使用所谓的分块传输编码时，这是行不通的。但是，使用分块传输读取请求正文的工作方式类似；在这种情况下，退出条件不依赖于`Content-Length`标头，而是在读取第一个空块时。

在完整的请求正文被读取后，您可以将此正文传递给之前已经使用过的`$checkoutService`：

```php
$httpServer->on('request', function(React\Http\Request $req, React\Http\Response $res) use ($pubSocket, $checkoutService) { 
    // error checking omitted... 

    $length = $req->getHeaders()['Content-Length']; 
    $body   = ''; 

    $request->on('data', function(string $chunk) use (&$body, $pubSocket, $checkoutService) { 
        $body .= $chunk; 
        if (strlen($body) == $length) { 
 **$checkoutService->handleCheckoutOrder($body)** 
 **->then(function() use ($response, $body, $pubSocket) {**
 **$pubSocket->send($body);** 
 **$msg = json_encode(['msg' => 'OK']);** 
 **$response->writeHead(200, [** 
 **'Content-Type' => 'application/json',** 
 **'Content-Length' => strlen($msg)** 
 **]);** 
 **$response->end($msg);** 
 **}, function(\Exception $err) use ($response) {** 
 **$msg = json_encode(['msg' => $err->getMessage()]);** 
 **$response->writeHead(500, [** 
 **'Content-Type' => 'application/json',** 
 **'Content-Length' => strlen($msg)** 
 **]);** 
 **$response->end($msg);** 
 **});** 
        } 
    }); 
}); 

```

`CheckoutService`类的使用方式与以前完全相同。现在唯一的区别是如何将响应发送回客户端；如果原始请求是由 ZeroMQ REP 套接字接收的，则将相应的响应发送到发送请求的 REQ 套接字。现在，如果请求是由 HTTP 服务器接收的，则会发送具有相同内容的 HTTP 响应。

您可以使用 curl 或 HTTPie 等命令行工具测试新的 HTTP API：

```php
**$ http -v localhost:8080/orders
cart:='[{"articlenumber":1000,"amount":3}]' customer:='{"email":"john.doe@example.com"}'**

```

以下截图显示了使用前面的 HTTPie 命令测试新 API 端点时的示例输出：

![桥接 ZeroMQ 和 HTTP](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-bp/img/image_07_011.jpg)

测试新的 HTTP API

# 总结

在本章中，您已经了解了 ZeroMQ 作为一种新的通信协议以及如何在 PHP 中使用它。与 HTTP 相比，ZeroMQ 支持比简单的请求/响应模式更复杂的通信模式。特别是发布/订阅和推送/拉取模式，它们允许您构建松散耦合的架构，可以轻松扩展新功能并且可以很好地扩展。

您还学会了如何使用 ReactPHP 框架构建使用事件循环的异步服务，以及如何使用承诺使异步性可管理。我们还讨论了如何将基于 ZeroMQ 的应用程序与*常规*HTTP API 集成。

虽然以前的章节都集中在不同的网络通信模式上（第五章中的 RESTful HTTP，*创建 RESTful Web 服务*，第六章中的 WebSockets，*构建聊天应用程序*，以及现在的 ZeroMQ），我们将在接下来的章节中重新开始，并学习如何使用 PHP 构建用于自定义表达式语言的解析器。
