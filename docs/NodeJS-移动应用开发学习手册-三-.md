# NodeJS 移动应用开发学习手册（三）

> 原文：[`zh.annas-archive.org/md5/4B062FCE9E3A0F235CC690D228FCDE03`](https://zh.annas-archive.org/md5/4B062FCE9E3A0F235CC690D228FCDE03)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：使用 Socket.IO 和 ExpressJS 进行实时通信

在本章中，我们将涵盖以下配方：

+   理解 NodeJS 事件

+   理解 Socket.IO 事件

+   使用 Socket.IO 命名空间

+   定义并加入 Socket.IO 房间

+   为 Socket.IO 编写中间件

+   将 Socket.IO 与 ExpressJS 集成

+   在 Socket.IO 中使用 ExpressJS 中间件

# 技术要求

您需要一个 IDE，Visual Studio Code，Node.js 和 MongoDB。 您还需要安装 Git，以便使用本书的 Git 存储库。

本章的代码文件可以在 GitHub 上找到：

[`github.com/PacktPublishing/MERN-Quick-Start-Guide/tree/master/Chapter04`](https://github.com/PacktPublishing/MERN-Quick-Start-Guide/tree/master/Chapter04)

查看以下视频以查看代码的实际操作：

[`goo.gl/xfyDBn`](https://goo.gl/xfyDBn)

# 介绍

现代 Web 应用程序通常需要实时通信，其中数据不断从客户端流向服务器，反之亦然，几乎没有延迟。

HTML5 WebSocket 协议是为了满足这一要求而创建的。 WebSocket 使用单个 TCP 连接，即使服务器或客户端不发送任何数据，该连接也会保持打开。 这意味着，在客户端和服务器之间存在连接时，可以随时发送数据，而无需打开到服务器的新连接。

实时通信有多个应用场景，从构建聊天应用程序到多用户游戏，响应时间非常重要。

在本章中，我们将专注于学习如何使用 Socket.IO（[`socket.io`](https://socket.io)）构建实时 Web 应用程序，并理解 Node.js 的事件驱动架构。

Socket.IO 是实现实时通信最常用的库之一。 Socket.IO 在可能的情况下使用 WebSocket，但在特定 Web 浏览器不支持 WebSocket 时会退回到其他方法。 因为您可能希望使您的应用程序可以从任何 Web 浏览器访问，所以必须直接使用 WebSocket 可能看起来不是一个好主意。

# 理解 Node.js 事件

Node.js 具有事件驱动的架构。 Node.js 的大部分核心 API 都是围绕`EventEmitter`构建的。 这是一个允许`侦听器`订阅特定命名事件的 Node.js 模块，稍后可以由**发射器**触发。

您可以通过包含事件 Node.js 模块并创建`EventEmitter`的新实例来轻松定义自己的事件发射器：

```js
const EventEmitter = require('events') 
const emitter = new EventEmitter() 
emitter.on('welcome', () => { 
    console.log('Welcome!') 
}) 
```

然后，您可以使用`emit`方法触发`welcome`事件：

```js
emitter.emit('welcome') 
```

这实际上相当简单。 其中一个优点是您可以订阅多个侦听器到同一个事件，并且当使用`emit`方法时它们将被触发：

```js
emitter.on('welcome', () => { 
    console.log('Welcome') 
}) 
emitter.on('welcome', () => { 
    console.log('There!') 
}) 
emitter.emit('welcome') 
```

`EventEmitter` API 提供了几种有用的方法，可以让您更好地控制处理事件。 请查看官方 Node.js 文档，以查看有关 API 的所有信息：[`nodejs.org/api/events.html`](https://nodejs.org/api/events.html)。

# 准备工作

在这个配方中，您将创建一个类，它将扩展`EventEmitter`，并且将包含其自己的实例方法来触发附加到特定事件的侦听器。 首先，通过打开终端并运行以下命令来创建一个新项目：

```js
npm init
```

# 如何做...

创建一个类，它扩展`EventEmitter`并定义两个名为`start`和`stop`的实例方法。 当调用`start`方法时，它将触发附加到`start`事件的所有侦听器。 它将使用`process.hrtime`保持起始时间。 然后，当调用`stop`方法时，它将触发附加到`stop`事件的所有侦听器，并将自`start`方法调用以来的时间差作为参数传递：

1.  创建一个名为`timer.js`的新文件

1.  包括事件 NodeJS 模块：

```js
      const EventEmitter = require('events') 
```

1.  定义两个常量，我们将使用它们将`process.hrtime`的返回值从秒转换为纳秒，然后转换为毫秒：

```js
      const NS_PER_SEC = 1e9 
      const NS_PER_MS = 1e6 
```

1.  定义一个名为`Timer`的类，其中包含两个实例方法：

```js
      class Timer extends EventEmitter { 
          start() { 
              this.startTime = process.hrtime() 
              this.emit('start') 
          } 
          stop() { 
              const diff = process.hrtime(this.startTime) 
              this.emit( 
                  'stop', 
                  (diff[0] * NS_PER_SEC + diff[1]) / NS_PER_MS, 
              ) 
          } 
      } 
```

1.  创建先前定义的类的新实例：

```js
      const tasks = new Timer() 
```

1.  将一个事件监听器附加到`start`事件，它将有一个循环执行乘法。之后，它将调用`stop`方法：

```js
      tasks.on('start', () => { 
          let res = 1 
          for (let i = 1; i < 100000; i++) { 
              res *= i 
          } 
          tasks.stop() 
      }) 
```

1.  将一个事件监听器附加到`stop`事件，它将打印事件`start`执行所有附加监听器所花费的时间：

```js
      tasks.on('stop', (time) => { 
          console.log(`Task completed in ${time}ms`) 
      }) 
```

1.  调用`start`方法来触发所有`start`事件监听器：

```js
      tasks.start() 
```

1.  保存文件

1.  打开一个新的终端并运行：

```js
 node timer.js
```

# 它是如何工作的...

当执行`start`方法时，它使用`process.hrtime`来保留开始时间，该方法返回一个包含两个项目的数组，第一个项目是表示秒的数字，而第二个项目是表示纳秒的另一个数字。然后，它触发所有附加到`start`事件的事件监听器。

另一方面，当执行`stop`方法时，它使用之前调用`process.hrtime`的结果作为相同函数的参数，该函数返回时间差。这对于测量从调用`start`方法到调用`stop`方法的时间非常有用。

# 还有更多...

一个常见的错误是假设事件是异步调用的。确实，定义的事件可以在任何时候被调用。然而，它们仍然是同步执行的。看下面的例子：

```js
const EventEmitter = require('events') 
const events = new EventEmitter() 
events.on('print', () => console.log('1')) 
events.on('print', () => console.log('2')) 
events.on('print', () => console.log('3')) 
events.emit('print') 
```

上述代码的输出将如下所示：

```js
1 
2 
3 
```

如果你的事件中有一个循环在运行，下一个事件将不会被调用直到前一个完成执行。

事件可以通过简单地将`async`函数添加为事件监听器来变成异步的。这样做，每个函数仍然会按照从第一个定义的`listener`到最后一个的顺序被调用。然而，发射器不会等待第一个`listener`完成执行才调用下一个 listener。这意味着你不能保证输出总是按照相同的顺序，例如：

```js
events.on('print', () => console.log('1')) 
events.on('print', async () => console.log( 
    await Promise.resolve('2')) 
) 
events.on('print', () => console.log('3')) 
events.emit('print')  
```

上述代码的输出将如下所示：

```js
1 
3 
2 
```

异步函数允许我们编写非阻塞的应用程序。如果实现正确，您不会遇到上面的问题。

`EventEmitter`实例有一个名为`listeners`的方法，当执行时，提供一个事件名称作为参数，返回附加到该特定事件的监听器数组。我们可以使用这种方法以允许`async`函数按照它们被附加的顺序执行，例如：

```js
const EventEmitter = require('events') 
class MyEvents extends EventEmitter { 
    start() { 
        return this.listeners('logme').reduce( 
            (promise, nextEvt) => promise.then(nextEvt), 
            Promise.resolve(), 
        ) 
    } 
} 
const event = new MyEvents() 
event.on('logme', () => console.log(1)) 
event.on('logme', async () => console.log( 
    await Promise.resolve(2) 
)) 
event.on('logme', () => console.log(3)) 
event.start() 
```

这将按照它们被附加的顺序执行并显示输出：

```js
1 
2 
3 
```

# 理解 Socket.IO 事件

Socket.IO 是一个基于`EventEmitter`的事件驱动模块或库，正如您可能猜到的那样。Socket.IO 中的一切都与事件有关。当新连接建立到 Socket.IO 服务器时，将触发一个事件，并且可以发出事件以向客户端发送数据。

Socket.IO 服务器 API 与 Socket.IO 客户端 API 不同。然而，两者都使用事件来从客户端向服务器发送数据，反之亦然。

# Socket.IO 服务器事件

Socket.IO 使用单个 TCP 连接到单个路径。这意味着，默认情况下，连接是建立到 URL`http[s]://host:port/socket.io`。然而，在 Socket.IO 中，它允许您定义**命名空间**。这意味着不同的终点，但连接仍然保持单一 URL。

默认情况下，Socket.IO 服务器使用`"/"`或根命名空间

当然，您可以定义多个实例并监听不同的 URL。然而，为了本教程的目的，我们将假设只创建一个连接。

Socket.IO 命名空间具有以下事件，您的应用程序可以订阅：

+   `connect`或`connection`：当建立新连接时，将触发此事件。它将**socket 对象**作为第一个参数提供给监听器，表示与客户端的新连接

```js
      io.on('connection', (socket) => { 
          console.log('A new client is connected') 
      }) 
      // Which is the same as:
       io.of('/').on('connection', (socket) => { 
          console.log('A new client is connected') 
      }) 
```

Socket.IO 套接字对象具有以下事件：

+   `disconnecting`：当客户端即将从服务器断开连接时发出此事件。它向监听器提供一个指定断开连接原因的参数

```js
      socket.on('disconnecting', (reason) => { 
          console.log('Disconnecting because', reason) 
      }) 
```

+   `disconnected`：类似于断开连接事件。但是，此事件在客户端从服务器断开连接后触发：

```js
      socket.on('disconnect', (reason) => { 
          console.log('Disconnected because', reason) 
      }) 
```

+   `error`：当事件发生错误时触发此事件

```js
      socket.on('error', (error) => { 
          console.log('Oh no!', error.message) 
      }) 
```

+   `[eventName]`：一个用户定义的事件，当客户端发出具有相同名称的事件时将被触发。客户端可以发出一个提供参数中的数据的事件。在服务器上，事件将被触发，并且将接收客户端发送的数据

# Socket.IO 客户端事件

客户端不一定需要是一个网络浏览器。我们也可以编写一个 Node.js Socket.IO 客户端应用程序。

Socket.IO 客户端事件非常广泛，可以对应用程序进行很好的控制：

+   `connect`：当成功连接到服务器时触发此事件

```js
      clientSocket.on('connect', () => { 
          console.log('Successfully connected to server') 
      }) 
```

+   `connect_error`：当尝试连接或重新连接到服务器时出现错误时，会触发此事件

```js
      clientSocket.on('connect_error', (error) => { 
          console.log('Connection error:', error) 
      }) 
```

+   `connect_timeout:` 默认情况下，在发出`connect_error`和`connect_timeout`之前设置的超时时间为 20 秒。之后，Socket.IO 客户端可能会再次尝试重新连接到服务器：

```js
      clientSocket.on('connect_timeout', (timeout) => { 
          console.log('Connect attempt timed out after', timeout) 
      }) 
```

+   `disconnect`：当客户端从服务器断开连接时触发此事件。提供一个参数，指定断开连接的原因：

```js
      clientSocket.on('disconnect', (reason) => { 
          console.log('Disconnected because', reason) 
      }) 
```

+   `reconnect`：在成功重新连接尝试后触发。提供一个参数，指定在连接成功之前发生了多少次尝试：

```js
      clientSocket.on('reconnect', (n) => { 
          console.log('Reconnected after', n, 'attempt(s)') 
      }) 
```

+   `reconnect_attempt`或`reconnecting`：当尝试重新连接到服务器时会触发此事件。提供一个参数，指定当前尝试连接到服务器的次数：

```js
      clientSocket.on('reconnect_attempt', (n) => { 
          console.log('Trying to reconnect again', n, 'time(s)') 
      })  
```

+   `reconnect_error`：类似于`connect_error`事件。但是，只有在尝试重新连接到服务器时出现错误时才会触发：

```js
      clientSocket.on('reconnect_error', (error) => { 
          console.log('Oh no, couldn't reconnect!', error) 
      })  
```

+   `reconnect_failed:` 默认情况下，尝试的最大次数设置为`Infinity`。这意味着，这个事件很可能永远不会被触发。但是，我们可以指定一个选项来限制最大连接尝试次数。稍后我们会看到：

```js
      clientSocket.on('reconnect_failed', (n) => { 
    console.log('Couldn'nt reconnected after', n, 'times') 
      }) 
```

+   `ping`：简而言之，此事件被触发以检查与服务器的连接是否仍然存在：

```js
      clientSocket.on('ping', () => { 
          console.log('Checking if server is alive') 
      }) 
```

+   `pong`：在从服务器接收到`ping`事件后触发。提供一个参数，指定延迟或响应时间：

```js
      clientSocket.on('pong', (latency) => { 
          console.log('Server responded after', latency, 'ms') 
      }) 
```

+   `error`：当事件发生错误时触发此事件：

```js
      clientSocket.on('error', (error) => { 
          console.log('Oh no!', error.message) 
      }) 
```

+   `[eventName]`：当在服务器中发出事件时触发的用户定义的事件。服务器提供的参数将被客户端接收。

# 准备工作

在这个示例中，您将使用刚刚学到的有关事件的知识构建一个 Socket.IO 服务器和一个 Socket.IO 客户端。在开始之前，请创建一个新的`package.json`文件，内容如下：

```js
{ 
  "dependencies": { 
    "socket.io": "2.1.0" 
  } 
} 
```

然后，通过打开终端并运行以下命令来安装依赖项：

```js
npm install 
```

# 如何做...

将构建一个 Socket.IO 服务器来响应一个名为`time`的单个事件。当事件被触发时，它将获取服务器的当前时间，并发出另一个名为`"got time?"`的事件，提供两个参数，当前的`time`和一个指定请求次数的`counter`。

1.  创建一个名为`simple-io-server.js`的新文件

1.  包括 Socket.IO 模块并初始化一个新服务器：

```js
      const io = require('socket.io')() 
```

1.  定义连接将被建立的 URL 路径：

```js
      io.path('/socket.io') 
```

1.  使用根目录或`"/"`命名空间：

```js
      const root = io.of('/') 
```

1.  当建立新连接时，将`counter`变量初始化为`0`。然后，添加一个新的监听器到`time`事件，每次有新的请求时，将`counter`增加一次，并发出后来在客户端定义的`"got time?"`事件：

```js
      root.on('connection', socket => { 
          let counter = 0 
          socket.on('time', () => { 
              const currentTime = new Date().toTimeString() 
              counter += 1 
              socket.emit('got time?', currentTime, counter) 
          }) 
      }) 
```

1.  监听端口`1337`以获取新连接：

```js
      io.listen(1337) 
```

1.  保存文件

接下来，构建一个连接到我们服务器的 Socket.IO 客户端：

1.  创建一个名为`simple-io-client.js`的新文件

1.  包括 Socket.IO 客户端模块：

```js
      const io = require('socket.io-client') 
```

1.  初始化一个新的 Socket.IO 客户端，提供服务器 URL 和一个选项对象，在该对象中我们将定义 URL 中使用的路径，连接将在该路径上进行：

```js
      const clientSocket = io('http://localhost:1337', { 
          path: '/socket.io', 
      }) 
```

1.  为`connect`事件添加一个事件监听器。然后，当建立连接时，使用`for`循环，发出`time`事件 5 次：

```js
      clientSocket.on('connect', () => { 
          for (let i = 1; i <= 5; i++) { 
              clientSocket.emit('time') 
          } 
      }) 
```

1.  在`"got time?"`事件上添加一个事件监听器，该事件将期望接收两个参数，时间和一个指定了向服务器发出了多少次请求的计数器，然后在控制台上打印：

```js
      clientSocket.on('got time?', (time, counter) => { 
          console.log(counter, time) 
      }) 
```

1.  保存文件

1.  打开终端并首先运行 Socket.IO 服务器：

```js
    node simple-io-server.js
```

1.  打开另一个终端并运行 Socket.IO 客户端：

```js
    node simple-io-client.js
```

# 工作原理...

一切都与事件有关。Socket.IO 允许在服务器端定义客户端可以发出的事件。另一方面，它还允许在客户端端定义服务器可以发出的事件。

当服务器端发出用户定义的事件时，数据被发送到客户端。Socket.IO 客户端首先检查是否有该事件的监听器。然后，如果有监听器，它将被触发。当客户端端发出用户定义的事件时，同样的事情也会发生：

1.  在我们的 Socket.IO 服务器的**socket 对象**中添加了一个事件监听器`time`，可以由客户端发出

1.  在我们的 Socket.IO 客户端中添加了一个事件监听器`"got time?"`，可以由服务器端发出

1.  在连接时，客户端首先发出`time`事件

1.  随后，在服务器端触发`time`事件，该事件将提供两个参数，当前服务器的`time`和一个指定了请求次数的`counter`

1.  然后，在客户端端触发`"got time?"`事件，接收服务器提供的两个参数，`time`和`counter`。

# 使用 Socket.IO 命名空间

命名空间是一种分隔应用程序业务逻辑的方式，同时重用相同的 TCP 连接或最小化创建新 TCP 连接的需求，以实现服务器和客户端之间的实时通信。

命名空间看起来与 ExpressJS 的路由路径非常相似：

```js
/home 
/users 
/users/profile 
```

然而，正如前面的配方中提到的，这些与 URL 无关。默认情况下，在此 URL`http[s]://host:port/socket.io`创建单个 TCP 连接

在使用命名空间时，重用相同的事件名称是一个很好的做法。例如，假设我们有一个 Socket.IO 服务器，当客户端发出`getWelcomeMsg`事件时，我们用来发出`setWelcomeMsg`事件：

```js
io.of('/en').on('connection', (socket) => { 
    socket.on('getWelcomeMsg', () => { 
        socket.emit('setWelcomeMsg', 'Hello World!') 
    }) 
}) 
io.of('/es').on('connection', (socket) => { 
    socket.on('getWelcomeMsg', () => { 
        socket.emit('setWelcomeMsg', 'Hola Mundo!') 
    }) 
}) 
```

正如您所看到的，我们在两个不同的命名空间中为事件`getWelcomeMsg`定义了监听器：

+   如果客户端连接到英语或`/en`命名空间，当`setWelcomeMsg`事件被触发时，客户端将收到`"Hello World!"`

+   另一方面，如果客户端连接到西班牙语或`/es`命名空间，当`setWelcomeMsg`事件被触发时，客户端将收到`"Hola Mundo!"`

# 准备工作

在本配方中，您将看到如何使用包含相同事件名称的两个不同命名空间。在开始之前，请创建一个新的`package.json`文件，其中包含以下内容：

```js
{ 
  "dependencies": { 
    "socket.io": "2.1.0" 
  } 
} 
```

然后，通过打开终端并运行以下命令来安装依赖项：

```js
npm install
```

# 如何做...

构建一个 Socket.IO 服务器，该服务器将触发一个`data`事件，并发送一个包含两个属性`title`和`msg`的对象，该对象将用于填充所选语言的 HTML 内容。使用命名空间来分隔并根据客户端选择的语言（英语或西班牙语）发送不同的数据。

1.  创建一个名为`nsp-server.js`的新文件

1.  包括 Socket.IO npm 模块和创建 HTTP 服务器所需的模块：

```js
      const http = require('http') 
      const fs = require('fs') 
      const path = require('path') 
      const io = require('socket.io')() 
```

1.  使用`http`模块创建一个新的 HTTP 服务器，该服务器将作为 Socket.IO 客户端提供的 HTML 文件的服务：

```js
     const app = http.createServer((req, res) => { 
      if (req.url === '/') { 
               fs.readFile( 
               path.resolve(__dirname, 'nsp-client.html'), 
              (err, data) => { 
                  if (err) { 
                    res.writeHead(500) 
                    return void res.end() 
                   } 
                    res.writeHead(200) 
                    res.end(data) 
                } 
              ) 
          } else { 
              res.writeHead(403) 
             res.end() 
         } 
    }) 
```

1.  指定新连接将要进行的路径：

```js
      io.path('/socket.io') 
```

1.  对于`"/en"`命名空间，添加一个新的事件监听器`getData`，当触发时将在客户端发出一个`data`事件，并发送一个包含`title`和`msg`属性的对象，使用英语语言：

```js
     io.of('/en').on('connection', (socket) => { 
        socket.on('getData', () => { 
            socket.emit('data', { 
               title: 'English Page', 
               msg: 'Welcome to my Website', 
           }) 
        }) 
   }) 
```

1.  对于`"/es"`命名空间，做同样的事情。但是，发送到客户端的对象将包含西班牙语言中的`title`和`msg`属性：

```js
      io.of('/es').on('connection', (socket) => { 
          socket.on('getData', () => { 
              socket.emit('data', { 
                  title: 'Página en Español', 
                  msg: 'Bienvenido a mi sitio Web', 
              }) 
          }) 
      }) 
```

1.  监听端口`1337`以获取新连接，并将 Socket.IO 附加到底层 HTTP 服务器：

```js
      io.attach(app.listen(1337, () => { 
          console.log( 
              'HTTP Server and Socket.IO running on port 1337' 
          ) 
      })) 
```

1.  保存文件。

之后，创建一个 Socket.IO 客户端，将连接到我们的服务器，并根据从服务器接收到的数据填充 HTML 内容。

1.  创建一个名为`nsp-client.html`的新文件

1.  首先，将文档类型指定为 HTML5。在其旁边，添加一个`html`标签，并将语言设置为英语。在`html`标签内，还包括`head`和`body`标签：

```js
      <!DOCTYPE html> 
      <html lang="en"> 
      <head> 
          <meta charset="UTF-8"> 
          <title>Socket.IO Client</title> 
      </head> 
      <body> 
          <!-- code here --> 
      </body> 
      </html> 
```

1.  在`body`标签内，添加前三个元素：一个包含内容标题的标题（`h1`），一个包含来自服务器的消息的`p`标签，以及一个用于切换到不同命名空间的`button`。还包括 Socket.IO 客户端库。Socket.IO 服务器将在此 URL 上提供库文件：http[s]://host:port/socket.io/socket.io.js。然后，还包括`babel`独立库，它将把下一步的代码转换为可以在所有浏览器中运行的 JavaScript 代码：

```js
      <h1 id="title"></h1> 
      <section id="msg"></section> 
      <button id="toggleLang">Get Content in Spanish</button> 
       <script src="img/socket.io.js">  
       </script> 
        <script src="img/babel.min.js">
      </script> 
```

1.  在`body`内，在最后的`script`标签之后，添加另一个`script`标签，并将其类型设置为`"text/babel"`：

```js
      <script type="text/babel"> 
          // code here! 
      </script> 
```

1.  之后，在`script`标签内，添加以下 JavaScript 代码

1.  定义三个常量，它们将包含对`body`中创建的元素的引用：

```js
      const title = document.getElementById('title') 
      const msg = document.getElementById('msg') 
      const btn = document.getElementById('toggleLang') 
```

1.  定义一个 Socket.IO 客户端管理器。它将帮助我们使用提供的配置创建套接字：

```js
      const manager = new io.Manager( 
          'http://localhost:1337', 
          { path: '/socket.io' }, 
      ) 
```

1.  创建一个新的套接字，将连接到`"/en"`命名空间。我们将假设这是默认连接：

```js
      const socket = manager.socket('/en') 
```

1.  为`"/en"`和`"/es"`命名空间保留两个连接。保留连接将允许我们在不需要创建新的 TCP 连接的情况下切换到不同的命名空间：

```js
      manager.socket('/en') 
      manager.socket('/es') 
```

1.  添加一个事件监听器，一旦套接字连接，就会发出一个`getData`事件来请求服务器的数据：

```js
      socket.on('connect', () => { 
          socket.emit('getData') 
      }) 
```

1.  添加一个`data`事件的事件监听器，当客户端从服务器接收到数据时将被触发：

```js
      socket.on('data', (data) => { 
          title.textContent = data.title 
          msg.textContent = data.msg 
      }) 
```

1.  为`button`添加一个事件监听器。当单击时，切换到不同的命名空间：

```js
      btn.addEventListener('click', (event) => { 
          socket.nsp = socket.nsp === '/en' 
              ? '/es' 
              : '/en' 
          btn.textContent = socket.nsp === '/en' 
              ? 'Get Content in Spanish' 
              : 'Get Content in English' 
          socket.close() 
          socket.open() 
      }) 
```

1.  保存文件

1.  打开一个新的终端并运行：

```js
 node nsp-server.js
```

1.  在 Web 浏览器中，导航到：

```js
 http://localhost:1337/
```

# 让我们来测试一下...

要查看之前的工作效果，请按照以下步骤操作：

1.  一旦在 Web 浏览器中导航到`http://localhost:1337/`，单击`"Get Content in Spanish"`按钮，切换到西班牙语命名空间

1.  单击`"Get Content in English"`按钮，切换回英语命名空间

# 工作原理...

这是服务器端发生的事情：

1.  我们定义了两个命名空间，`"/en"`和`"/es"`，然后向**套接字对象**添加了一个新的事件监听器`getData`。

1.  当在任何两个定义的命名空间中触发`getData`事件时，它将发出一个数据事件，并向客户端发送一个包含标题和消息属性的对象

在客户端，在我们的 HTML 文档的`script`标签内：

1.  最初，为命名空间`"/en"`创建一个新的套接字：

```js
      const socket = manager.socket('/en')
```

1.  同时，我们为`"/en"`和`"/es"`命名空间创建了两个新的**套接字**。它们将充当保留连接：

```js
      manager.socket('/en')
      manager.socket('/es')
```

1.  之后，添加了一个事件监听器`connect`，在连接时向服务器发送请求

1.  然后，添加了另一个`data`事件的事件监听器，当从服务器接收到数据时触发

1.  在处理按钮的`onclick`事件的事件监听器内部，我们将`nsp`属性更改为切换到不同的命名空间。但是，为了实现这一点，我们必须首先断开**套接字**，然后调用`open`方法，再次使用新的命名空间建立新的连接

让我们看看关于保留连接的一个令人困惑的部分。当您在同一个命名空间中创建一个或多个**sockets**时，第一个连接会被重用，例如：

```js
const first = manager.socket('/home')
const second = manager.socket('/home') // <- reuses first connection
```

在客户端，如果没有保留连接，那么切换到以前未使用过的命名空间将导致创建一个新连接。

如果您感到好奇，请从`nsp-client.html`文件中删除这两行：

```js
manager.socket('/en')
manager.socket('/es')
```

之后，重新启动或再次运行 Socket.IO 服务器。您会注意到切换到不同命名空间时会有一个缓慢的响应，因为会创建一个新连接而不是重用。

有一种替代方法可以实现相同的目标。我们可以创建两个指向两个不同命名空间`"/en"`和`"/es"`的 socket。然后，我们可以为每个 socket 添加两个事件监听器 connect 和 data。然而，因为第一个和第二个 socket 将包含相同的事件名称，并且以相同的格式从服务器接收数据，我们将得到重复的代码。想象一下，如果我们必须为五个具有相同事件名称并以相同格式从服务器接收数据的不同命名空间做同样的事情，那将会有太多重复的代码行。这就是切换命名空间并重用相同的 socket 对象有帮助的地方。然而，可能存在两个或更多不同的命名空间具有不同事件名称的情况，对于不同类型的事件，最好为每个命名空间单独添加事件监听器。例如：

```js
const englishNamespace = manager.socket('/en')
const spanishNamespace = manager.socket('/es')
// They listen to different events
englishNamespace.on('showMessage', (data) => {})
spanishNamespace.on('mostrarMensaje', (data) => {})
```

# 还有更多...

在客户端，您可能已经注意到了一个我们以前没有使用过的东西，`io.Manager`。

# io.Manager

这使我们能够预定义或配置新连接将如何创建。在`Manager`中定义的选项，如 URL，将在初始化时传递给 socket。

在我们的 HTML 文件中，在`script`标签内，我们创建了`io.Manager`的一个新实例，并传递了两个参数；服务器 URL 和一个包含`path`属性的选项对象，该属性指示新连接将被创建的位置：

```js
const manager = new io.Manager( 
    'http://localhost:1337', 
    { path: '/socket.io' }, 
) 
```

要了解有关`io.Manager`API 的更多信息，请访问官方文档网站提供的 Socket.IO [`socket.io/docs/client-api/#manager`](https://socket.io/docs/client-api/#manager)。

稍后，我们使用了`socket`方法来初始化并创建一个提供的命名空间的新 Socket：

```js
const socket = manager.socket('/en') 
```

这样，就可以更容易地同时处理多个命名空间，而无需为每个命名空间配置相同的选项。

# 定义和加入 Socket.IO 房间

在命名空间内，您可以定义一个 socket 可以加入和离开的房间或通道。

默认情况下，房间会使用一个随机的不可猜测的 ID 来创建与连接的**socket**：

```js
io.on('connection', (socket) => { 
    console.log(socket.id) // Outputs socket ID 
}) 
```

在连接时，例如发出一个事件时：

```js
io.on('connection', (socket) => { 
    socket.emit('say', 'hello') 
}) 
```

底层发生的情况类似于这样：

```js
io.on('connection', (socket) => { 
    socket.join(socket.id, (err) => { 
        if (err) { 
            return socket.emit('error', err) 
        } 
        io.to(socket.id).emit('say', 'hello') 
    }) 
}) 
```

`join`方法用于将 socket 包含在房间内。在这种情况下，socket ID 是联合房间，连接到该房间的唯一客户端就是 socket 本身。

因为 socket ID 代表与客户端的唯一连接，并且默认情况下会创建具有相同 ID 的房间；服务器发送到该房间的所有数据将只被该客户端接收。然而，如果几个客户端或 socket ID 加入具有相同名称的房间，并且服务器发送数据；所有客户端都可以接收到。

# 准备工作

在这个示例中，您将看到如何加入一个房间并向连接到该特定房间的所有客户端广播消息。在开始之前，创建一个新的`package.json`文件，内容如下：

```js
{ 
  "dependencies": { 
    "socket.io": "2.1.0" 
  } 
} 
```

然后，通过打开终端并运行以下命令来安装依赖项：

```js
npm install
```

# 如何做...

构建一个 Socket.IO 服务器，当新的 socket 连接时，它将通知所有连接的客户端加入`"commonRoom"`房间。

1.  创建一个名为`rooms-server.js`的新文件

1.  包括 Socket.IO NPM 模块并初始化一个新的 HTTP 服务器：

```js
      const http = require('http') 
      const fs = require('fs') 
      const path = require('path') 
      const io = require('socket.io')() 
      const app = http.createServer((req, res) => { 
          if (req.url === '/') { 
              fs.readFile( 
                  path.resolve(__dirname, 'rooms-client.html'), 
                  (err, data) => { 
                     if (err) { 
                          res.writeHead(500) 
                          return void res.end() 
                      } 
                      res.writeHead(200) 
                      res.end(data) 
                  } 
              ) 
          } else { 
              res.writeHead(403) 
              res.end() 
          } 
      }) 
```

1.  指定新连接将被创建的路径：

```js
      io.path('/socket.io') 
```

1.  使用根命名空间来监听事件：

```js
      const root = io.of('/') 
```

1.  定义一个方法，用于向连接到`"commonRoom"`的所有套接字客户端发出`updateClientCount`事件，并提供连接的客户端数量作为参数：

```js
      const notifyClients = () => { 
          root.clients((error, clients) => { 
              if (error) throw error 
              root.to('commonRoom').emit( 
                  'updateClientCount', 
                  clients.length, 
              ) 
          }) 
      } 
```

1.  连接后，所有新连接的 Socket 客户端都将加入`commonRoom`。然后，服务器将发出`welcome`事件。之后，通知所有连接的套接字更新连接客户端的数量，并在客户端断开连接时执行相同的操作：

```js
      root.on('connection', socket => { 
          socket.join('commonRoom') 
          socket.emit('welcome', `Welcome client: ${socket.id}`) 
          socket.on('disconnect', notifyClients) 
          notifyClients() 
      }) 
```

1.  监听端口`1337`以进行新连接，并将 Socket.IO 附加到 HTTP 服务器：

```js
      io.attach(app.listen(1337, () => { 
          console.log( 
              'HTTP Server and Socket.IO running on port 1337' 
          ) 
      })) 
```

1.  保存文件。

之后，构建一个 Socket.IO 客户端，该客户端将连接到 Socket.IO 服务器并使用接收到的数据填充 HTML 内容：

1.  创建一个名为`rooms-client.html`的新文件

1.  添加以下代码：

```js
      <!DOCTYPE html> 
      <html lang="en"> 
      <head> 
          <meta charset="UTF-8"> 
          <title>Socket.IO Client</title> 
      </head> 
      <body> 
          <h1 id="title"> 
              Connected clients: 
              <span id="n"></span> 
          </h1> 
          <p id="welcome"></p> 
          <script src="img/socket.io.js">
          </script> 
          <script 
          src="img/babel.min.js">
          </script> 
          <script type="text/babel"> 
      // Code here 
          </script> 
      </body> 
      </html> 
```

1.  在脚本标签中，按以下步骤添加代码，从第 4 步开始

1.  定义两个常量，它们将引用两个 HTML 元素，我们将根据 Socket.IO 服务器发送的数据进行更新：

```js
      const welcome = document.getElementById('welcome') 
      const n = document.getElementById('n') 
```

1.  定义一个 Socket.IO 客户端管理器：

```js
      const manager = new io.Manager( 
          'http://localhost:1337', 
          { path: '/socket.io' }, 
      ) 
```

1.  使用 Socket.IO 服务器中使用的根命名空间：

```js
      const socket = manager.socket('/') 
```

1.  为`welcome`事件添加事件侦听器，该事件预期包含服务器发送的欢迎消息作为参数：

```js
      socket.on('welcome', msg => { 
          welcome.textContent = msg 
      }) 
```

1.  为`updateClientCount`事件添加事件侦听器，该事件预期包含一个参数，该参数将包含连接的客户端数量：

```js
      socket.on('updateClientCount', clientsCount => { 
          n.textContent = clientsCount 
      }) 
```

1.  保存文件

1.  打开一个新的终端并运行：

```js
 node rooms-server.js
```

1.  在 Web 浏览器中，导航到：

```js
http://localhost:1337/
```

1.  在不关闭上一个选项卡或窗口的情况下，再次在 Web 浏览器中导航到：

```js
http://localhost:1337/
```

1.  两个选项卡或窗口中连接的客户端数量应该增加到`2`

# 还有更多...

向多个客户端发送相同的消息或数据称为广播。我们已经看到的方法向所有客户端广播消息，包括生成请求的客户端。

还有其他几种广播消息的方法。例如：

```js
socket.to('commonRoom').emit('updateClientCount', data) 
```

这将向`commonRoom`中的所有客户端发出`updateClientCount`事件，但不包括发出请求的发送方或套接字。

有关完整列表，请查看 Socket.IO 发射速查表的官方文档：[`socket.io/docs/emit-cheatsheet/`](https://socket.io/docs/emit-cheatsheet/)

# 为 Socket.IO 编写中间件

Socket.IO 允许我们在服务器端定义两种类型的中间件函数：

+   **命名空间中间件**：注册一个函数，该函数将在每个新连接的 Socket 上执行，并具有以下签名：

```js
      namespace.use((socket, next) => { ... }) 
```

+   **Socket 中间件**：注册一个函数，该函数将在每个传入的数据包上执行，并具有以下签名：

```js
      socket.use((packet, next) => { ... }) 
```

它的工作方式类似于 ExpressJS 中间件函数。我们可以向`socket`或`packet`对象添加新属性。然后，我们可以调用`next`将控制传递给链中的下一个中间件。如果未调用`next`，则不会连接`socket`，或者接收到的`packet`。

# 准备工作

在这个示例中，您将构建一个 Socket.IO 服务器应用程序，在其中定义中间件函数以限制对某个命名空间的访问，以及根据某些条件限制对某个套接字的访问。在开始之前，请创建一个包含以下内容的新的`package.json`文件：

```js
{ 
  "dependencies": { 
    "socket.io": "2.1.0" 
  } 
} 
```

然后，通过打开终端并运行以下命令来安装依赖项：

```js
    npm install
```

# 如何做...

Socket.IO 服务器应用程序将期望用户已登录，以便他们能够连接到`/home`命名空间。使用 socket 中间件，我们还将限制对`/home`命名空间的访问权限：

1.  创建一个名为`middleware-server.js`的新文件

1.  包括 Socket.IO 库并初始化一个新的 HTTP 服务器：

```js
      const http = require('http') 
      const fs = require('fs') 
      const path = require('path') 
      const io = require('socket.io')() 
      const app = http.createServer((req, res) => { 
          if (req.url === '/') { 
              fs.readFile( 
                  path.resolve(__dirname, 'middleware-cli.html'), 
                  (err, data) => { 
                      if (err) { 
                          res.writeHead(500) 
                          return void res.end() 
                      } 
                      res.writeHead(200) 
                      res.end(data) 
                  } 
              ) 
          } else { 
              res.writeHead(403) 
              res.end() 
          } 
      }) 
```

1.  指定新连接将建立的路径：

```js
      io.path('/socket.io') 
```

1.  定义一个用户数组，我们将将其用作内存数据库：

```js
      const users = [ 
          { username: 'huangjx', password: 'cfgybhji' }, 
          { username: 'johnstm', password: 'mkonjiuh' }, 
          { username: 'jackson', password: 'qscwdvb' }, 
      ] 
```

1.  定义一个方法来验证提供的用户名和密码是否存在于用户数组中：

```js
      const userMatch = (username, password) => ( 
          users.find(user => ( 
              user.username === username && 
              user.password === password 
          )) 
      ) 
```

1.  定义一个命名空间中间件函数，该函数将检查用户是否已经登录。如果用户未登录，客户端将无法使用此中间件连接到特定命名空间：

```js
      const isUserLoggedIn = (socket, next) => { 
          const { session } = socket.request 
          if (session && session.isLogged) { 
              next() 
          } 
      } 
```

1.  定义两个命名空间，一个用于`/login`，另一个用于`/home`。`/home`命名空间将使用我们之前定义的中间件函数来检查用户是否已登录：

```js
      const namespace = { 
          home: io.of('/home').use(isUserLoggedIn), 
          login: io.of('/login'), 
      } 
```

1.  当一个新的 socket 连接到`/login`命名空间时，首先我们将为检查所有传入的数据包定义一个 socket 中间件函数，并禁止`johntm`用户名的访问。然后，我们将为输入事件添加一个事件监听器，该事件将期望接收一个包含用户名和密码的纯对象，如果它们存在于用户数组中，那么我们将设置一个会话对象，告诉用户是否已登录。否则，我们将向客户端发送一个带有错误消息的`loginError`事件：

```js
      namespace.login.on('connection', socket => { 
          socket.use((packet, next) => { 
              const [evtName, data] = packet 
              const user = data 
              if (evtName === 'tryLogin' 
                  && user.username === 'johnstm') { 
                  socket.emit('loginError', { 
                      message: 'Banned user!', 
                  }) 
              } else { 
                  next() 
              } 
          }) 
          socket.on('tryLogin', userData => { 
              const { username, password } = userData 
              const request = socket.request 
              if (userMatch(username, password)) { 
                  request.session = { 
                      isLogged: true, 
                      username, 
                  } 
                  socket.emit('loginSuccess') 
              } else { 
                  socket.emit('loginError', { 
                      message: 'invalid credentials', 
                  }) 
              } 
          }) 
      }) 
```

1.  监听端口 1337 以获取新连接并将 Socket.IO 附加到 HTTP 服务器：

```js
      io.attach(app.listen(1337, () => { 
          console.log( 
              'HTTP Server and Socket.IO running on port 1337' 
          ) 
      })) 
```

1.  保存文件

之后，构建一个 Socket.IO 客户端应用程序，它将连接到我们的 Socket.IO 服务器，并允许我们尝试登录和测试：

1.  创建一个名为`middleware-cli.html`的新文件

1.  添加以下代码：

```js
      <!DOCTYPE html> 
      <html lang="en"> 
      <head> 
          <meta charset="UTF-8"> 
          <title>Socket.IO Client</title> 
          <script src="img/socket.io.js">
          </script> 
          <script 
          src="img/babel.min.js">
          </script> 
      </head> 
      <body> 
          <h1 id="title"></h1> 
          <form id="loginFrm" disabled> 
            <input type="text" name="username" placeholder="username"/> 
              <input type="password" name="password" 
                placeholder="password" /> 
              <input type="submit" value="LogIn" /> 
              <output name="logs"></output> 
          </form> 
          <script type="text/babel"> 
              // Code here 
          </script> 
      </body> 
      </html> 
```

1.  在脚本标签内，从步骤 4 开始，添加以下代码

1.  定义三个常量，它们将引用我们将用于获取输入或显示输出的 HTML 元素：

```js
      const title = document.getElementById('home') 
      const error = document.getElementsByName('logErrors')[0] 
      const loginForm = document.getElementById('loginForm') 
```

1.  定义一个 Socket.IO 管理器：

```js
      const manager = new io.Manager( 
          'http://localhost:1337', 
          { path: '/socket.io' }, 
      ) 
```

1.  让我们定义一个命名空间常量，其中包含一个包含 Socket.IO 命名空间`/home`和`/login`的对象：

```js
      const namespace = { 
          home: manager.socket('/home'), 
          login: manager.socket('/login'), 
      } 
```

1.  为`/home`命名空间添加一个`connect`事件的事件监听器。只有当`/home`命名空间成功连接到服务器时才会触发：

```js
      namespace.home.on('connect', () => { 
          title.textContent = 'Great! you are connected to /home' 
          error.textContent = '' 
      }) 
```

1.  为`/login`命名空间添加一个`loginSuccess`事件的事件监听器。它将要求`/home`命名空间再次连接到服务器。如果用户已登录，则服务器将允许此连接：

```js
      namespace.login.on('loginSuccess', () => { 
          namespace.home.connect() 
      }) 
```

1.  为`/login`命名空间添加一个`loginError`事件的事件监听器。它将显示服务器发送的错误消息：

```js
      namespace.login.on('loginError', (err) => { 
          logs.textContent = err.message 
      }) 
```

1.  为登录表单的提交事件添加事件监听器。它将发出输入事件，提供一个包含在表单中填写的用户名和密码的对象：

```js
      form.addEventListener('submit', (event) => { 
          const body = new FormData(form) 
          namespace.login.emit('tryLogin', { 
              username: body.get('username'), 
              password: body.get('password'), 
          }) 
          event.preventDefault() 
      }) 
```

1.  保存文件

# 让我们来测试一下...

查看我们之前的工作的效果： 

1.  首先运行 Socket.IO 服务器。打开一个新的终端并运行：

```js
 node middleware-server.js
```

1.  在您的网络浏览器中，导航到：

```js
 http://localhost:1337
```

1.  您将看到一个带有两个字段`username`和`password`的登录表单

1.  尝试使用随机无效的凭据登录。将显示以下错误：

```js
      invalid credentials 
```

1.  接下来，尝试使用`johntm`作为`username`和任何`password`登录。将显示以下错误：

```js
      Banned user! 
```

1.  之后，使用另外两个有效凭据之一登录。例如，使用`jingxuan`作为用户名和`qscwdvb`作为密码。将显示以下标题：

```js
      Connected to /home 
```

# 将 Socket.IO 与 ExpressJS 集成

Socket.IO 与 ExpressJS 配合良好。事实上，可以在同一端口或 HTTP 服务器上运行 ExpressJS 应用程序和 Socket.IO 服务器。

# 准备工作

在这个示例中，我们将看到如何将 Socket.IO 与 ExpressJS 集成。您将构建一个 ExpressJS 应用程序，该应用程序将提供包含 Socket.IO 客户端应用程序的 HTML 文件。在开始之前，创建一个新的`package.json`文件，内容如下：

```js
{ 
  "dependencies": { 
    "express": "4.16.3", 
    "socket.io": "2.1.0" 
  } 
} 
```

然后，通过打开终端并运行来安装依赖项：

```js
npm install
```

# 如何做...

创建一个 Socket.IO 客户端应用程序，它将连接到您将要构建的 Socket.IO 服务器，并显示服务器发送的欢迎消息。

1.  创建一个名为`io-express-view.html`的新文件

1.  添加以下代码：

```js
      <!DOCTYPE html> 
      <html lang="en"> 
      <head> 
          <meta charset="UTF-8"> 
          <title>Socket.IO Client</title> 
          <script src="img/socket.io.js">
          </script> 
          <script 
           src="img/babel.min.js">
          </script> 
      </head> 
      <body> 
          <h1 id="welcome"></h1> 
          <script type="text/babel"> 
              const welcome = document.getElementById('welcome') 
              const manager = new io.Manager( 
                  'http://localhost:1337', 
                  { path: '/socket.io' }, 
              ) 
              const root = manager.socket('/') 
              root.on('welcome', (msg) => { 
                  welcome.textContent = msg 
              }) 
          </script> 
      </body> 
      </html> 
```

1.  保存文件

接下来，构建一个 ExpressJS 应用程序和一个 Socket.IO 服务器。ExpressJS 应用程序将在根路径`"/"`上提供先前创建的 HTML 文件：

1.  创建一个名为`io-express-server.js`的新文件

1.  初始化一个新的 Socket.IO 服务器应用程序和一个 ExpressJS 应用程序：

```js
      const path = require('path') 
      const express = require('express') 
      const io = require('socket.io')() 
      const app = express() 
```

1.  定义新连接将连接到 Socket.IO 服务器的 URL 路径：

```js
      io.path('/socket.io') 
```

1.  定义一个路由方法来提供包含我们的 Socket.IO 客户端应用程序的 HTML 文件：

```js
      app.get('/', (req, res) => { 
          res.sendFile(path.resolve( 
              __dirname, 
              'io-express-view.html', 
          )) 
      }) 
```

1.  定义一个命名空间`"/"`并发出一个带有欢迎消息的`welcome`事件：

```js
      io.of('/').on('connection', (socket) => { 
          socket.emit('welcome', 'Hello from Server!') 
      }) 
```

1.  将 Socket.IO 附加到 ExpressJS 服务器：

```js
      io.attach(app.listen(1337, () => { 
          console.log( 
              'HTTP Server and Socket.IO running on port 1337' 
          ) 
      })) 
```

1.  保存文件

1.  打开终端并运行：

```js
 node io-express-server.js
```

1.  在您的浏览器中访问：

```js
http://localhost:1337/
```

# 它是如何工作的...

Socket.IO 的`attach`方法期望接收一个 HTTP 服务器作为参数，以便将 Socket.IO 服务器应用程序附加到它上面。我们之所以能够将 Socket.IO 附加到 ExpressJS 服务器应用程序上，是因为`listen`方法返回 ExpressJS 连接的基础 HTTP 服务器。

总之，`listen`方法返回基础 HTTP 服务器。然后，它作为参数传递给`attach`方法。这样，我们可以与 ExpressJS 共享相同的连接。

# 还有更多...

到目前为止，我们已经看到我们可以在 ExpressJS 和 Socket.IO 之间共享相同的基础 HTTP 服务器。然而，这还不是全部。

我们定义 Socket.IO 路径的原因实际上在与 ExpressJS 一起工作时非常有用。看以下示例：

```js
const express = require('express') 
const io = require('socket.io')() 
const app = express() 
io.path('/socket.io')
 app.get('/socket.io', (req, res) => { 
    res.status(200).send('Hey there!') 
}) 
io.of('/').on('connection', socket => { 
    socket.emit('someEvent', 'Data from Server!') 
}) 
io.attach(app.listen(1337)) 
```

正如您所看到的，我们在 Socket.IO 和 ExpressJS 中使用相同的 URL 路径。我们接受新连接到`/socket.io`路径上的 Socket.IO 服务器，但我们也使用 GET 路由方法发送内容到`/socket.io`。

尽管上述示例实际上不会破坏您的应用程序，但请确保永远不要同时使用相同的 URL 路径来从 ExpressJS 提供内容并接受 Socket.IO 的新连接。例如，将上一个代码更改为以下内容：

```js
io.path('/socket.io')
 app.get('/socket.io/:msg', (req, res) => { 
    res.status(200).send(req.params.msg) 
}) 
```

当您访问`http://localhost:1337/socket.io/message`时，您可能期望您的浏览器显示`message`，但事实并非如此，您将看到以下内容：

```js
{"code":0,"message":"Transport unknown"} 
```

这是因为 Socket.IO 将首先解释传入的数据，它不会理解您刚刚发送的数据。此外，您的路由处理程序将永远不会被执行。

除此之外，Socket.IO 服务器还默认提供其自己的 Socket.IO 客户端，位于定义的 URL 路径下。例如，尝试访问[`localhost:1337/socket.io/socket.io.js`](http://localhost:1337/socket.io/socket.io.js)，您将能够看到 Socket.IO 客户端的最小化 JavaScript 代码。

如果您希望提供自己版本的 Socket.IO 客户端，或者如果它包含在您的应用程序的捆绑包中，您可以使用`serveClient`方法在 Socket.IO 服务器应用程序中禁用默认行为。

```js
io.serveClient(false) 
```

# 另请参阅

+   第二章，*使用 Express.js 内置中间件函数为静态资源提供服务*

# 在 Socket.IO 中使用 ExpressJS 中间件

Socket.IO 命名空间中间件的工作方式与 ExpressJS 中间件非常相似。事实上，Socket 对象还包含一个`request`和一个`response`对象，我们可以使用它们以与 ExpressJS 中间件函数相同的方式存储其他属性：

```js
namespace.use((socket, next) => { 
    const req = socket.request 
    const res = socket.request.res 
    next() 
}) 
```

因为 ExpressJS 中间件函数具有以下签名：

```js
const expressMiddleware = (request, response, next) => { 
    next() 
} 
```

我们可以安全地在 Socket.IO 命名空间中间件中执行相同的函数，传递必要的参数：

```js
root.use((socket, next) => { 
    const req = socket.request 
    const res = socket.request.res 
    expressMiddleware(req, res, next) 
}) 
```

然而，这并不意味着所有 ExpressJS 中间件函数都能直接使用。例如，如果 ExpressJS 中间件函数仅使用 ExpressJS 中可用的方法，它可能会失败或产生意外行为。

# 准备工作

在这个示例中，我们将看到如何将 ExpressJS 的`express-session`中间件集成到 Socket.IO 和 ExpressJS 之间共享会话对象。在开始之前，创建一个新的`package.json`文件，内容如下：

```js
{ 
  "dependencies": { 
    "express": "4.16.3", 
    "express-session": "1.15.6", 
    "socket.io": "2.1.0" 
  } 
} 
```

然后，通过打开终端并运行以下命令来安装依赖项：

```js
npm install
```

# 如何做...

构建一个 Socket.IO 客户端应用程序，它将连接到接下来您将构建的 Socket.IO 服务器。包括一个表单，用户可以在其中输入用户名和密码尝试登录。只有在用户登录后，Socket.IO 客户端才能连接到`/home`命名空间：

1.  创建一个名为`io-express-cli.html`的新文件

1.  添加以下 HTML 内容：

```js
      <!DOCTYPE html> 
      <html lang="en"> 
      <head> 
          <meta charset="UTF-8"> 
          <title>Socket.IO Client</title> 
          <script src="img/socket.io.js">  
          </script> 
          <script 
           src="img/babel.min.js">
          </script> 
      </head> 
      <body> 
          <h1 id="title"></h1> 
          <form id="loginForm"> 
            <input type="text" name="username" placeholder="username"/> 
              <input type="password" name="password" 
                placeholder="password" /> 
              <input type="submit" value="LogIn" /> 
              <output name="logErrors"></output> 
          </form> 
          <script type="text/babel"> 
              // Code here 
          </script> 
      </body> 
      </html> 
```

1.  在脚本标签中添加从第 4 步开始的下一步中的代码

1.  定义引用我们将使用的 HTML 元素的常量：

```js
      const title = document.getElementById('title') 
      const error = document.getElementsByName('logErrors')[0] 
      const loginForm = document.getElementById('loginForm') 
```

1.  定义一个 Socket.IO 管理器：

```js
      const manager = new io.Manager( 
          'http://localhost:1337', 
          { path: '/socket.io' }, 
      ) 
```

1.  定义两个命名空间，一个用于`/login`，另一个用于`/home`：

```js
      const namespace = { 
          home: manager.socket('/home'), 
          login: manager.socket('/login'), 
      } 
```

1.  为`welcome`事件添加一个事件监听器，该事件将在允许连接到`/home`命名空间时由服务器端触发：

```js
      namespace.home.on('welcome', (msg) => { 
          title.textContent = msg 
          error.textContent = '' 
      }) 
```

1.  为`loginSuccess`事件添加一个事件监听器，当触发时，将要求`/home`命名空间尝试重新连接到 Socket.IO 服务器：

```js
      namespace.login.on('loginSuccess', () => { 
          namespace.home.connect() 
      }) 
```

1.  为`loginError`事件添加一个事件监听器，当提供无效凭据时将显示错误：

```js
      namespace.login.on('loginError', err => { 
          error.textContent = err.message 
      }) 
```

1.  为`submit`事件添加一个事件监听器，当提交表单时将触发该事件。它将发出一个带有包含提供的`username`和`password`的数据的`enter`事件：

```js
      loginForm.addEventListener('submit', event => { 
          const body = new FormData(loginForm) 
          namespace.login.emit('enter', { 
              username: body.get('username'), 
              password: body.get('password'), 
          }) 
          event.preventDefault() 
      }) 
```

1.  保存文件。

在此之后，构建一个 ExpressJS 应用程序，该应用程序将在根路径`"/"`上提供 Socket.IO 客户端，并包含用于记录用户的逻辑的 Socket.IO 服务器：

1.  创建一个名为`io-express-srv.js`的新文件

1.  初始化一个新的 ExpressJS 应用程序和一个 Socket.IO 服务器应用程序。还包括`express-session` NPM 模块：

```js
      const path = require('path') 
      const express = require('express') 
      const io = require('socket.io')() 
      const expressSession = require('express-session') 
      const app = express() 
```

1.  定义新连接到 Socket.IO 服务器的路径：

```js
      io.path('/socket.io') 
```

1.  使用给定选项定义一个 ExpressJS 会话中间件函数：

```js
      const session = expressSession({ 
          secret: 'MERN Cookbook Secret', 
          resave: true, 
          saveUninitialized: true, 
      }) 
```

1.  定义一个 Socket.IO 命名空间中间件，该中间件将使用先前创建的会话中间件生成会话对象：

```js
      const ioSession = (socket, next) => { 
          const req = socket.request 
          const res = socket.request.res 
          session(req, res, (err) => { 
              next(err) 
              req.session.save() 
          }) 
      } 
```

1.  定义两个命名空间，一个用于`/home`，另一个用于`/login`：

```js
      const home = io.of('/home') 
      const login = io.of('/login') 
```

1.  定义一个内存数据库或包含`username`和`password`属性的对象数组。这些属性定义了允许登录的用户：

```js
      const users = [ 
          { username: 'huangjx', password: 'cfgybhji' }, 
          { username: 'johnstm', password: 'mkonjiuh' }, 
          { username: 'jackson', password: 'qscwdvb' }, 
      ] 
```

1.  在 ExpressJS 中包含会话中间件：

```js
      app.use(session) 
```

1.  为`/home`路径添加一个路由方法，用于提供我们之前创建的包含 Socket.IO 客户端的 HTML 文档：

```js
      app.get('/home', (req, res) => { 
          res.sendFile(path.resolve( 
              __dirname, 
              'io-express-cli.html', 
          )) 
      }) 
```

1.  在`/home` Socket.IO 命名空间中使用会话中间件。然后，检查每个新的 socket 是否已登录。如果没有，禁止用户连接到此命名空间：

```js
      home.use(ioSession) 
      home.use((socket, next) => { 
          const { session } = socket.request 
          if (session.isLogged) { 
              next() 
          } 
      }) 
```

1.  一旦连接到`/home`命名空间，也就是用户可以登录，就会发出一个带有欢迎消息的`welcome`事件，该消息将显示给用户：

```js
      home.on('connection', (socket) => { 
          const { username } = socket.request.session 
          socket.emit( 
              'welcome', 
              `Welcome ${username}!, you are logged in!`, 
          ) 
      }) 
```

1.  在`/login` Socket.IO 命名空间中使用会话中间件。然后，当客户端发出带有提供的用户名和密码的`enter`事件时，它会验证`users`数组中是否存在该配置文件。如果用户存在，则将`isLogged`属性设置为`true`，并将`username`属性设置为当前已登录的用户：

```js
      login.use(ioSession) 
      login.on('connection', (socket) => { 
          socket.on('enter', (data) => { 
              const { username, password } = data 
              const { session } = socket.request 
              const found = users.find((user) => ( 
                  user.username === username && 
                  user.password === password 
              )) 
              if (found) { 
                  session.isLogged = true 
                  session.username = username 
                  socket.emit('loginSuccess') 
              } else { 
                  socket.emit('loginError', { 
                      message: 'Invalid Credentials', 
                  }) 
              } 
          }) 
      }) 
```

1.  监听端口`1337`以获取新连接，并将 Socket.IO 服务器附加到该端口：

```js
      io.attach(app.listen(1337, () => { 
          console.log( 
              'HTTP Server and Socket.IO running on port 1337' 
          ) 
      })) 
```

1.  保存文件

1.  打开一个新的终端并运行：

```js
 node io-express-srv.js  
```

1.  在浏览器中访问：

```js
 http://localhost:1337/home
```

1.  使用有效的凭据登录。例如：

```js
      * Username: johntm
      * Password: mkonjiuh
```

1.  如果您成功登录，刷新页面后，您的 Socket.IO 客户端应用程序仍然能够连接到`/home`，并且每次都会看到欢迎消息

# 工作原理...

当在 ExpressJS 中使用会话中间件时，在修改会话对象后，响应结束时会自动调用`save`方法。然而，在 Socket.IO 命名空间中使用会话中间件时并非如此，这就是为什么我们需要手动调用`save`方法将会话保存回存储中的原因。在我们的情况下，存储是内存，会话会一直保存在那里直到服务器停止。

根据特定条件禁止访问某些命名空间是可能的，这要归功于 Socket.IO 命名空间中间件。如果控制权没有传递给`next`处理程序，那么连接就不会建立。这就是为什么在登录成功后，我们要求`/home`命名空间再次尝试连接。

# 另请参阅

+   第二章，*使用 ExpressJS 构建 Web 服务器*，*编写中间件函数*部分


# 第五章：使用 Redux 管理状态

在这一章中，我们将涵盖以下的配方：

+   定义动作和动作创建者

+   定义减速器函数

+   创建 Redux 存储

+   将动作创建者绑定到分派方法

+   拆分和组合减速器

+   编写 Redux 存储增强器

+   使用 Redux 进行时间旅行

+   了解 Redux 中间件

+   处理异步数据流

# 技术要求

您需要一个 IDE、Visual Studio Code、Node.js 和 MongoDB。您还需要安装 Git，以便使用本书的 Git 存储库。

本章的代码文件可以在 GitHub 上找到：

[`github.com/PacktPublishing/MERN-Quick-Start-Guide/tree/master/Chapter05`](https://github.com/PacktPublishing/MERN-Quick-Start-Guide/tree/master/Chapter05)

查看以下视频，看看代码是如何运行的：

[`goo.gl/mU9AjR`](https://goo.gl/mU9AjR)

# 介绍

Redux 是 JavaScript 应用程序的可预测状态容器。它允许开发人员轻松管理其应用程序的状态。使用 Redux，状态是不可变的。因此，可以在应用程序的下一个或上一个状态之间来回切换。Redux 遵循三个核心原则：

+   **唯一的真相来源**：应用程序的所有状态必须存储在一个单一存储中的单个对象树中

+   **状态是只读的**：您不能改变状态树。只有通过分派动作，状态树才能改变

+   **使用纯函数进行更改**：这些被称为减速器的函数接受先前的状态和一个动作，并计算一个新的状态。减速器绝不能改变先前的状态，而是始终返回一个新的状态

减速器的工作方式与`Array.prototype.reduce`函数非常相似。`reduce`方法对数组中的每个项目执行一个函数，以将其减少为单个值。例如：

```js
const a = 5 
const b = 10 
const c = [a, b].reduce((accumulator, value) => { 
    return accumulator + value 
}, 0) 
```

在对`累加器`进行`a`和`b`的减速时，得到的值是`15`，初始值为`0`。这里的减速器函数是：

```js
(accumulator, value) => { 
    return accumulator + value 
} 
```

Redux 减速器的编写方式类似，它们是 Redux 的最重要概念。例如：

```js
const reducer = (prevState, action) => newState 
```

在本章中，我们将专注于学习如何使用 Redux 管理简单和复杂的状态树。您还将学习如何处理异步数据流。

# 定义动作和动作创建者

减速器接受描述将执行的动作的`action`对象，并根据此`action`对象决定如何转换状态。

动作只是普通对象，它们只有一个必需的属性，需要存在，即动作类型。例如：

```js
const action = { 
    type: 'INCREMENT_COUNTER', 
} 
```

我们也可以提供额外的属性。例如：

```js
const action = { 
    type: 'INCREMENT_COUNTER', 
    incrementBy: 2, 
} 
```

动作创建者只是返回动作的函数，例如：

```js
const increment = (incrementBy) => ({ 
    type: 'INCREMENT_COUNTER', 
    incrementBy, 
}) 
```

# 准备工作

在这个配方中，您将看到如何使用`Array.prototype.reduce`来应用这些简单的 Redux 概念，以决定如何累积或减少数据。

我们暂时不需要 Redux 库来实现这个目的。

# 如何做...

构建一个小型的 JavaScript 应用程序，根据提供的动作来增加或减少计数器。

1.  创建一个名为`counter.js`的新文件

1.  将动作类型定义为常量：

```js
      const INCREMENT_COUNTER = 'INCREMENT_COUNTER' 
      const DECREMENT_COUNTER = 'DECREMENT_COUNTER' 
```

1.  定义两个动作创建者，用于生成`增加`和`减少`计数器的两种动作：

```js
      const increment = (by) => ({ 
          type: INCREMENT_COUNTER, 
          by, 
      }) 
      const decrement = (by) => ({ 
          type: DECREMENT_COUNTER, 
          by, 
      }) 
```

1.  将初始累加器初始化为`0`，然后通过传递多个动作来减少它。减速器函数将根据动作类型决定执行哪种动作：

```js
      const reduced = [ 
          increment(10), 
          decrement(5), 
          increment(3), 
      ].reduce((accumulator, action) => { 
          switch (action.type) { 
              case INCREMENT_COUNTER: 
            return accumulator + action.by 
              case DECREMENT_COUNTER: 
                  return accumulator - action.by 
              default: 
                  return accumulator 
          } 
      }, 0) 
```

1.  记录结果值：

```js
      console.log(reduced) 
```

1.  保存文件

1.  打开终端并运行：

```js
       node counter.js

```

1.  输出：`8`

# 它是如何工作的...

1.  减速器遇到的第一个动作类型是`increment(10)`，它将使累加器增加`10`。因为累加器的初始值是`0`，下一个当前值将是`10`

1.  第二个动作类型告诉减速器函数将累加器减少`5`。因此，累加器的值将是`5`。

1.  最后一个动作类型告诉减速器函数将累加器增加`3`。结果，累加器的值将是`8`。

# 定义减速器函数

Redux 减速器是纯函数。这意味着它们没有副作用。给定相同的参数，减速器必须始终生成相同形状的状态。例如，以下减速器函数：

```js
const reducer = (prevState, action) => { 
    if (action.type === 'INC') { 
        return { counter: prevState.counter + 1 } 
    } 
    return prevState 
} 
```

如果我们执行此函数并提供相同的参数，结果将始终相同：

```js
const a = reducer( 
   { counter: 0 }, 
   { type: 'INC' }, 
) // Value is { counter: 1 }  
const b = reducer( 
   { counter: 0 }, 
   { type: 'INC' }, 
) // Value is { counter: 1 } 
```

但是，请注意，即使返回的值具有相同的形状，这些是两个不同的对象。例如，比较上面的：

`console.log(a === b)`返回 false。

不纯的减速器函数会导致您的应用程序状态不可预测，并且难以重现相同的状态。例如：

```js
const impureReducer = (prevState = {}, action) => { 
    if (action.type === 'SET_TIME') { 
        return { time: new Date().toString() } 
    } 
    return prevState 
} 
```

如果我们执行此函数：

```js
const a = impureReducer({}, { type: 'SET_TIME' }) 
setTimeout(() => { 
    const b = impureReducer({}, { type: 'SET_TIME' }) 
    console.log( 
        a, // Output may be: {time: "22:10:15 GMT+0000"} 
        b, // Output may be: {time: "22:10:17 GMT+0000"} 
    ) 
}, 2000) 
```

如您所见，在 2 秒后第二次执行函数后，我们得到了不同的结果。为了使其纯净，您可以考虑将先前的不纯减速器重写为：

```js
const timeReducer = (prevState = {}, action) => { 
    if (action.type === 'SET_TIME') { 
        return { time: action.time } 
    } 
    return prevState 
} 
```

然后，您可以安全地在您的动作中传递一个时间属性来设置时间：

```js
const currentTime = new Date().toTimeString() 
const a = timeReducer( 
   { time: null }, 
   { type: 'SET_TIME', time: currentTime }, 
) 
const b = timeReducer( 
   { time: null }, 
   { type: 'SET_TIME', time: currentTime }, 
) 
console.log(a.time === b.time) // true 
```

这种方法使您的状态可预测，并且状态易于重现。例如，您可以重新创建一个场景，了解如果您为早上或下午的任何时间传递`time`属性，您的应用程序将如何运行。

# 准备工作

现在您已经了解了减速器的工作原理，本教程中，您将构建一个根据状态更改而表现不同的小型应用程序。

为此，您不需要安装或使用 Redux 库。

# 如何做...

构建一个应用程序，根据您的本地时间提醒您应该吃什么样的餐点。在一个单一的对象树中管理我们应用程序的所有状态。还提供一种模拟应用程序将在`00:00a.m`或`12:00p.m`时显示的方法：

1.  创建一个名为`meal-time.html`的新文件。

1.  添加以下代码：

```js
      <!DOCTYPE html> 
      <html lang="en"> 
      <head> 
          <meta charset="UTF-8"> 
          <title>Breakfast Time</title> 
          <script 
         src="img/babel.min.js">  
        </script> 
      </head> 
      <body> 
          <h1>What you need to do:</h1> 
          <p> 
              <b>Current time:</b> 
              <span id="display-time"></span> 
          </p> 
                <p id="display-meal"></p> 
                <button id="emulate-night"> 
              Let's pretend is 00:00:00 
          </button> 
          <button id="emulate-noon"> 
              Let's pretend is 12:00:00 
          </button> 
          <script type="text/babel"> 
              // Add JavaScript code here 
          </script> 
      </body> 
      </html> 
```

1.  在脚本标签中添加下一步中定义的代码，从第 4 步开始。

1.  定义一个变量`state`，它将包含所有状态树和稍后的下一个状态：

```js
      let state = { 
          kindOfMeal: null, 
          time: null, 
      } 
```

1.  创建一个引用 HTML 元素的引用，我们将用它来显示数据或添加事件监听器：

```js
      const meal = document.getElementById('display-meal') 
      const time = document.getElementById('display-time') 
      const btnNight = document.getElementById('emulate-night') 
      const btnNoon = document.getElementById('emulate-noon') 
```

1.  定义两种动作类型：

```js
      const SET_MEAL = 'SET_MEAL' 
      const SET_TIME = 'SET_TIME' 
```

1.  为用户应该有的餐点定义一个动作创建者：

```js
      const setMeal = (kindOfMeal) => ({ 
          type: SET_MEAL, 
          kindOfMeal, 
      }) 
```

1.  定义一个动作创建者，用于设置时间：

```js
      const setTime = (time) => ({ 
          type: SET_TIME, 
          time, 
      }) 
```

1.  定义一个减速器函数，当动作被分发时计算新的状态：

```js
      const reducer = (prevState = state, action) => { 
          switch (action.type) { 
              case SET_MEAL: 
                  return Object.assign({}, prevState, { 
                      kindOfMeal: action.kindOfMeal, 
                  }) 
              case SET_TIME: 
                  return Object.assign({}, prevState, { 
                      time: action.time, 
                  }) 
              default: 
                  return prevState 
          } 
      } 
```

1.  添加一个我们在状态改变时将调用的函数，以便更新我们的视图：

```js
      const onStateChange = (nextState) => { 
          const comparison = [ 
              { time: '23:00:00', info: 'Too late for dinner!' }, 
              { time: '18:00:00', info: 'Dinner time!' }, 
              { time: '16:00:00', info: 'Snacks time!' }, 
              { time: '12:00:00', info: 'Lunch time!' }, 
              { time: '10:00:00', info: 'Branch time!' }, 
              { time: '05:00:00', info: 'Breakfast time!' }, 
              { time: '00:00:00', info: 'Too early for breakfast!' }, 
          ] 
          time.textContent = nextState.time 
          meal.textContent = comparison.find((condition) => ( 
              nextState.time >= condition.time 
          )).info 
      } 
```

1.  定义一个分发函数，通过将当前状态和动作传递给减速器来生成新的状态树。然后，它将调用`onChangeState`函数来通知您的应用程序状态已经改变：

```js
      const dispatch = (action) => { 
          state = reducer(state, action) 
          onStateChange(state) 
      } 
```

1.  为按钮添加一个事件监听器，模拟时间为`00:00a.m`：

```js
      btnNight.addEventListener('click', () => { 
          const time = new Date('1/1/1 00:00:00') 
          dispatch(setTime(time.toTimeString())) 
      }) 
```

1.  为按钮添加一个事件监听器，模拟时间为`12:00p.m`：

```js
      btnNoon.addEventListener('click', () => { 
          const time = new Date('1/1/1 12:00:00') 
          dispatch(setTime(time.toTimeString())) 
      }) 
```

1.  脚本运行后，分发一个带有当前时间的动作，以便更新视图：

```js
      dispatch(setTime(new Date().toTimeString())) 
```

1.  保存文件。

# 让我们来测试一下...

查看您之前的工作成果：

1.  在您的网络浏览器中打开`meal-time.html`文件。您可以通过双击文件或右键单击文件并选择“使用...”来执行此操作。

1.  您应该能够看到您当前的本地时间和一条消息，说明您应该有什么样的餐点。例如，如果您的本地时间是`20:42:35 GMT+0800 (CST)`，您应该看到“晚餐时间！”

1.  点击按钮“让我们假装是 00:00:00”来查看如果时间是`00:00a.m`，您的应用程序将显示什么。

1.  同样，点击按钮“让我们假装是 12:00:00”来查看如果时间是`12:00p.m`，您的应用程序将显示什么。

# 它是如何工作的...

我们可以总结我们的应用程序如下，以了解它的工作原理：

1.  动作类型`SET_MEAL`和`SET_TIME`已被定义。

1.  定义了两个动作创建者：

1.  `setMeal`生成一个带有`SET_MEAL`动作类型和`kindOfMeal`属性的动作

1.  `setTime`生成一个带有`SET_TIME`操作类型和提供的参数的`time`属性的操作

1.  定义了一个 reducer 函数：

1.  对于操作类型`SET_MEAL`，计算一个新的状态，具有一个新的`kindOfMeal`属性

1.  对于操作类型`SET_TIME`，计算一个新的状态，具有一个新的`time`属性

1.  我们定义了一个函数，当状态树发生变化时将被调用。在函数内部，我们根据新状态更新了视图。

1.  定义了一个`dispatch`函数，它调用 reducer 函数，提供先前的状态和一个操作对象以生成一个新的状态。

# 创建一个 Redux 存储

在以前的教程中，我们已经看到了如何定义 reducers 和 actions。我们还看到了如何创建一个 dispatch 函数来分派操作，以便 reducers 更新状态。存储是一个提供了一个小 API 的对象，将所有这些放在一起。

redux 模块公开了`createStore`方法，我们可以使用它来创建一个存储。它具有以下签名：

```js
createStore(reducer, preloadedState, enhancer) 
```

最后两个参数是可选的。例如，创建一个只有一个 reducer 的 store 可能如下所示：

```js
const TYPE = { 
    INC_COUNTER: 'INC_COUNTER', 
    DEC_COUNTER: 'DEC_COUNTER', 
} 
const initialState = { 
    counter: 0, 
} 
const reducer = (state = initialState, action) => { 
    switch (action.type) { 
        case TYPE.INC_COUNTER:  
            return { counter: state.counter + 1 } 
        case TYPE.DEC_COUNTER:  
            return { counter: state.counter - 1 } 
        default:  
            return state 
    } 
} 
const store = createStore(reducer) 
```

调用`createStore`将公开四种方法：

+   `store.dispatch(action)`:其中 action 是一个包含至少一个名为`type`的属性的对象，指定操作类型

+   `store.getState()`:返回整个状态树

+   `store.subscribe(listener)`:其中 listener 是一个回调函数，每当状态树发生变化时都会触发。可以订阅多个监听器

+   `store.replaceReducer(reducer)`:用新的 reducer 函数替换当前的 Reducer 函数

# 准备工作

在这个教程中，您将重新构建您在上一个教程中构建的应用程序。但是，这一次您将使用 Redux。在开始之前，创建一个新的`package.json`文件，内容如下：

```js
{ 
    "dependencies": { 
        "express": "4.16.3", 
        "redux": "4.0.0" 
    } 
} 
```

然后，通过打开终端并运行来安装依赖项：

```js
npm install

```

# 如何做...

首先，构建一个小的 ExpressJS 服务器应用程序，其唯一目的是提供 HTML 文件和 Redux 模块：

1.  创建一个名为`meal-time-server.js`的新文件

1.  包括 ExpressJS 和`path`模块，并初始化一个新的 ExpressJS 应用程序：

```js
      const express = require('express') 
      const path = require('path') 
      const app = express() 
```

1.  在`/lib`路径上提供 Redux 库。确保路径指向`node_modules`文件夹：

```js
      app.use('/lib', express.static( 
          path.join(__dirname, 'node_modules', 'redux', 'dist') 
      )) 
```

1.  在根路径`/`上提供客户端应用程序：

```js
      app.get('/', (req, res) => { 
          res.sendFile(path.join( 
              __dirname, 
              'meal-time-client.html', 
          )) 
      }) 
```

1.  在端口`1337`上监听新的连接：

```js
      app.listen( 
          1337, 
          () => console.log('Web Server running on port 1337'), 
      ) 
```

1.  保存文件

现在，按照以下步骤使用 Redux 构建客户端应用程序：

1.  创建一个名为`meal-time-client.html`的新文件。

1.  添加以下代码：

```js
      <!DOCTYPE html> 
      <html lang="en"> 
      <head> 
          <meta charset="UTF-8"> 
          <title>Meal Time with Redux</title> 
          <script 
          src="img/babel.min.js">
         </script> 
          <script src="img/redux.js"></script> 
      </head> 
      <body> 
          <h1>What you need to do:</h1> 
          <p> 
              <b>Current time:</b> 
              <span id="display-time"></span> 
          </p> 
          <p id="display-meal"></p> 
          <button id="emulate-night"> 
              Let's pretend is 00:00:00 
          </button> 
          <button id="emulate-noon"> 
              Let's pretend is 12:00:00 
          </button> 
          <script type="text/babel"> 
              // Add JavaScript code here 
          </script> 
      </body> 
      </html> 
```

1.  在脚本标签内，从第 4 步开始添加下一步的代码。

1.  从 Redux 库中提取`createStore`方法：

```js
      const { createStore } = Redux 
```

1.  定义应用程序的初始状态：

```js
      const initialState = { 
          kindOfMeal: null, 
          time: null, 
      } 
```

1.  保留将用于显示状态或与应用程序交互的 HTML DOM 元素的引用：

```js
      const meal = document.getElementById('display-meal') 
      const time = document.getElementById('display-time') 
      const btnNight = document.getElementById('emulate-night') 
      const btnNoon = document.getElementById('emulate-noon') 
```

1.  定义两种操作类型：

```js
      const SET_MEAL = 'SET_MEAL' 
      const SET_TIME = 'SET_TIME' 
```

1.  定义两个操作创建者：

```js
      const setMeal = (kindOfMeal) => ({ 
          type: SET_MEAL, 
          kindOfMeal, 
      }) 
      const setTime = (time) => ({ 
          type: SET_TIME, 
          time, 
      }) 
```

1.  定义将在分派`SET_TIME`和/或`SET_TIME`操作类型时转换状态的 reducer：

```js
      const reducer = (prevState = initialState, action) => { 
          switch (action.type) { 
              case SET_MEAL: 
                  return {...prevState, 
                      kindOfMeal: action.kindOfMeal, 
                  } 
              case SET_TIME: 
                  return {...prevState, 
                      time: action.time, 
                  } 
              default: 
                  return prevState 
          } 
      } 
```

1.  创建一个新的 Redux 存储：

```js
      const store = createStore(reducer) 
```

1.  订阅一个回调函数以更改存储。每当存储更改时，此回调将被触发，并且它将根据存储中的更改更新视图：

```js
      store.subscribe(() => { 
          const nextState = store.getState() 
          const comparison = [ 
              { time: '23:00:00', info: 'Too late for dinner!' }, 
              { time: '18:00:00', info: 'Dinner time!' }, 
              { time: '16:00:00', info: 'Snacks time!' }, 
              { time: '12:00:00', info: 'Lunch time!' }, 
              { time: '10:00:00', info: 'Brunch time!' }, 
              { time: '05:00:00', info: 'Breakfast time!' }, 
              { time: '00:00:00', info: 'Too early for breakfast!' }, 
          ] 
          time.textContent = nextState.time 
          meal.textContent = comparison.find((condition) => ( 
              nextState.time >= condition.time 
          )).info 
      }) 
```

1.  为我们的按钮添加一个`click`事件的事件监听器，将分派`SET_TIME`操作类型以将时间设置为`00:00:00`：

```js
      btnNight.addEventListener('click', () => { 
          const time = new Date('1/1/1 00:00:00') 
          store.dispatch(setTime(time.toTimeString())) 
      }) 
```

1.  为我们的按钮添加一个`click`事件的事件监听器，将分派`SET_TIME`操作类型以将时间设置为`12:00:00`：

```js
      btnNoon.addEventListener('click', () => { 
          const time = new Date('1/1/1 12:00:00') 
          store.dispatch(setTime(time.toTimeString())) 
      }) 
```

1.  当应用程序首次启动时，分派一个操作以将时间设置为当前本地时间：

```js
      store.dispatch(setTime(new Date().toTimeString())) 
```

1.  保存文件

# 让我们来测试一下...

查看以前的工作成果：

1.  打开一个新的终端并运行：

```js
 node meal-time-server.js
```

1.  在您的网络浏览器中，访问：

```js

       http://localhost:1337/
```

1.  您应该能够看到您当前的本地时间和一条消息，说明您应该吃什么样的饭。例如，如果您的本地时间是`20:42:35 GMT+0800 (CST)`，您应该看到`晚餐时间！`

1.  单击按钮`“假设现在是 00:00:00”`，查看如果时间是`00:00a.m`，您的应用程序会显示什么。

1.  同样，点击“假装是 12:00:00”按钮，看看如果时间是 12:00p.m，你的应用程序会显示什么。

# 还有更多

你可以使用 ES6 扩展运算符来合并你的先前状态和下一个状态，例如，我们重写了前面食谱的减速器函数：

```js
const reducer = (prevState = initialState, action) => { 
    switch (action.type) { 
        case SET_MEAL: 
            return Object.assign({}, prevState, { 
                kindOfMeal: action.kindOfMeal, 
            }) 
        case SET_TIME: 
            return Object.assign({}, prevState, { 
                time: action.time, 
            }) 
        default: 
            return prevState 
    } 
} 
```

我们将它重写为以下形式：

```js
const reducer = (prevState = initialState, action) => { 
    switch (action.type) { 
        case SET_MEAL: 
            return {...prevState, 
                kindOfMeal: action.kindOfMeal, 
            } 
        case SET_TIME: 
            return {...prevState, 
                time: action.time, 
            } 
        default: 
            return prevState 
    } 
} 
```

这可以使代码更易读。

# 将动作创建者绑定到`dispatch`方法

动作创建者只是生成动作对象的函数，稍后可以使用`dispatch`方法来分派动作。例如，看下面的代码：

```js
const TYPES = { 
    ADD_ITEM: 'ADD_ITEM', 
    REMOVE_ITEM: 'REMOVE_ITEM', 
} 
const actions = { 
    addItem: (name, description) => ({ 
        type: TYPES.ADD_ITEM, 
        payload: { name, description }, 
    }), 
    removeItem: (id) => ({ 
        type: TYPES.REMOVE_ITEM, 
        payload: { id }, 
    }) 
} 
module.exports = actions 
```

稍后，在应用程序的其他地方，你可以使用`dispatch`方法来分派这些动作：

```js
dispatch(actions.addItem('Little Box', 'Cats')) 
dispatch(actions.removeItem(123)) 
```

然而，正如你所看到的，每次调用`dispatch`方法似乎是一个重复和不必要的步骤。你可以简单地将动作创建者包装在`dispatch`函数周围，就像这样：

```js
const actions = { 
    addItem: (name, description) => dispatch({ 
        type: TYPES.ADD_ITEM, 
        payload: { name, description }, 
    }), 
    removeItem: (id) => dispatch({ 
        type: TYPES.REMOVE_ITEM, 
        payload: { id }, 
    }) 
} 
module.exports = actions 
```

尽管这似乎是一个很好的解决方案，但存在一个问题。这意味着，你需要先创建存储，然后定义你的动作创建者，将它们绑定到`dispatch`方法。此外，由于它们依赖于`dispatch`方法的存在，很难将动作创建者维护在一个单独的文件中。Redux 模块提供了一个解决方案，一个名为`bindActionCreators`的辅助方法，它接受两个参数。第一个参数是一个具有键的对象，这些键代表一个动作创建者的名称，值代表一个返回动作的函数。第二个参数预期是`dispatch`函数：

```js
bindActionCreators(actionCreators, dispatchMethod) 
```

这个辅助方法将所有的动作创建者映射到`dispatch`方法。例如，我们可以将前面的例子重写为以下形式：

```js
const store = createStore(reducer) 
const originalActions = require('./actions') 
const actions = bindActionCreators( 
    originalActions, 
    store.dispatch, 
) 
```

然后，在应用程序的其他地方，你可以调用这些方法，而不需要将它们包装在`dispatch`方法周围：

```js
actions.addItem('Little Box', 'Cats') 
actions.removeItem(123) 
```

正如你所看到的，我们的绑定动作创建者现在看起来更像普通函数。事实上，通过解构`actions`对象，你可以只使用你需要的方法。例如：

```js
const { 
    addItem, 
    removeItem, 
} = bindActionCreators( 
    originalActions,  
    store.dispatch, 
) 
```

然后，你可以这样调用它们：

```js
addItem('Little Box', 'Cats') 
removeItem(123) 
```

# 准备好了

在这个食谱中，你将构建一个简单的待办事项应用程序，并使用你刚刚学到的关于绑定动作创建者的概念。首先，创建一个包含以下内容的新的`package.json`文件：

```js
{ 
    "dependencies": { 
        "express": "4.16.3", 
        "redux": "4.0.0" 
    } 
} 
```

然后，通过打开终端并运行来安装依赖项：

```js
npm install
```

# 如何做…

为了构建你的待办事项应用程序，在这个食谱的目的，只定义一个动作创建者，并使用`bindActionCreators`将它绑定到`dispatch`方法。

首先，构建一个小的 ExpressJS 应用程序，它将提供包含待办事项客户端应用程序的 HTML 文件，我们将在之后构建：

1.  创建一个名为`bind-server.js`的新文件

1.  添加以下代码：

```js
      const express = require('express') 
      const path = require('path') 
      const app = express() 
      app.use('/lib', express.static( 
          path.join(__dirname, 'node_modules', 'redux', 'dist') 
      )) 
      app.get('/', (req, res) => { 
          res.sendFile(path.join( 
              __dirname, 
              'bind-index.html', 
          )) 
      }) 
      app.listen( 
          1337, 
          () => console.log('Web Server running on port 1337'), 
      ) 
```

1.  保存文件

接下来，在 HTML 文件中构建待办事项应用程序：

1.  创建一个名为`bind-index.html`的新文件。

1.  添加以下代码：

```js
      <!DOCTYPE html> 
      <html lang="en"> 
      <head> 
          <meta charset="UTF-8"> 
          <title>Binding action creators</title> 
          <script 
           src="img/babel.min.js">
          </script> 
          <script src="img/redux.js"></script> 
      </head> 
      <body> 
          <h1>List:</h1> 
          <form id="item-form"> 
              <input id="item-input" name="item" /> 
          </form> 
          <ul id="list"></ul> 
          <script type="text/babel"> 
              // Add code here 
          </script> 
      </body> 
      </html> 
```

1.  在脚本标记内，从第 4 步开始，按照以下步骤添加代码。

1.  保留一个将在应用程序中使用的 HTML DOM 元素的引用：

```js
      const form = document.querySelector('#item-form') 
      const input = document.querySelector('#item-input') 
      const list = document.querySelector('#list') 
```

1.  定义你的应用程序的初始状态：

```js
      const initialState = { 
          items: [], 
      } 
```

1.  定义一个动作类型：

```js
      const TYPE = { 
          ADD_ITEM: 'ADD_ITEM', 
      } 
```

1.  定义一个动作创建者：

```js
      const actions = { 
          addItem: (text) => ({ 
              type: TYPE.ADD_ITEM, 
              text, 
          }) 
      } 
```

1.  定义一个减速器函数，每当分派`ADD_ITEM`动作类型时，将一个新项目添加到列表中。状态将只保留 5 个项目：

```js
      const reducer = (state = initialState, action) => { 
          switch (action.type) { 
              case TYPE.ADD_ITEM: return { 
                  items: [...state.items, action.text].splice(-5) 
              } 
              default: return state 
          } 
      } 
```

1.  创建一个存储，并将`dispatch`函数绑定到动作创建者：

```js
      const { createStore, bindActionCreators } = Redux 
      const store = createStore(reducer) 
      const { addItem } = bindActionCreators( 
          actions,  
          store.dispatch, 
      ) 
```

1.  订阅存储，每当状态改变时向列表中添加一个新项目。如果已经定义了一个项目，我们将重复使用它，而不是创建一个新项目：

```js
      store.subscribe(() => { 
          const { items } = store.getState() 
          items.forEach((itemText, index) => { 
              const li = ( 
                  list.children.item(index) || 
                  document.createElement('li') 
              ) 
              li.textContent = itemText 
              list.insertBefore(li, list.children.item(0)) 
          }) 
      }) 
```

1.  为表单添加一个`submit`事件的事件侦听器。这样，我们就可以获取输入值并分派一个动作：

```js
      form.addEventListener('submit', (event) => { 
          event.preventDefault() 
          addItem(input.value) 
      }) 
```

1.  保存文件。

# 让我们来测试一下…

要查看之前的工作成果：

1.  打开一个新的终端并运行：

```js
 node bind-server.js
```

1.  在浏览器中访问：

```js
     http://localhost:1337/
```

1.  在输入框中输入一些内容，然后按 Enter。列表中应该会出现一个新项目。

1.  尝试向列表中添加超过五个项目。显示的最后一个将被移除，视图上只保留五个项目。

# 分割和组合 reducer

随着应用程序的增长，你可能不希望在一个简单的 reducer 函数中编写应用程序状态的转换逻辑。你可能希望编写更小的 reducer，专门管理状态的独立部分。

举个例子，以下是一个 reducer 函数：

```js
const initialState = { 
    todoList: [], 
    chatMsg: [], 
} 
const reducer = (state = initialState, action) => { 
    switch (action.type) { 
        case 'ADD_TODO': return { 
            ...state, 
            todoList: [ 
                ...state.todoList, 
                { 
                    title: action.title, 
                    completed: action.completed, 
                }, 
            ], 
        } 
        case 'ADD_CHAT_MSG': return { 
            ...state, 
            chatMsg: [ 
                ...state.chatMsg, 
                { 
                    from: action.id, 
                    message: action.message, 
                }, 
            ], 
        } 
        default: 
            return state 
    } 
} 
```

你有两个属性来管理应用程序的两个不同部分的状态。一个管理待办事项列表的状态，另一个管理聊天消息的状态。你可以将这个 reducer 分割成两个 reducer 函数，每个函数管理状态的一个片段，例如：

```js
const initialState = { 
    todoList: [], 
    chatMsg: [], 
} 
const todoListReducer = (state = initialState.todoList, action) => { 
    switch (action.type) { 
        case 'ADD_TODO': return state.concat([ 
            { 
                title: action.title, 
                completed: action.completed, 
            }, 
        ]) 
        default: return state 
    } 
} 
const chatMsgReducer = (state = initialState.chatMsg, action) => { 
    switch (action.type) { 
        case 'ADD_CHAT_MSG': return state.concat([ 
            { 
                from: action.id, 
                message: action.message, 
            }, 
        ]) 
        default: return state 
    } 
} 
```

然而，因为`createStore`方法只接受一个 reducer 作为第一个参数，你需要将它们合并成一个单一的 reducer：

```js
const reducer = (state = initialState, action) => { 
    return { 
        todoList: todoListReducer(state.todoList, action), 
        chatMsg: chatMsgReducer(state.chatMsg, action), 
    } 
} 
```

通过这种方式，我们能够将 reducer 分割成更小的 reducer，专门管理状态的一个片段，然后将它们合并成一个单一的 reducer 函数。

Redux 提供了一个名为`combineReducers`的辅助方法，允许你以类似的方式组合 reducer，但不需要重复大量的代码；例如，我们可以像这样重新编写组合 reducer 的先前方式：

```js
const reducer = combineReducers({ 
    todoList: todoListReducer, 
    chatMsg: chatMsgReducer, 
}) 
```

`combineReducers`方法是一个*高阶 reducer*函数。它接受一个对象映射，指定键到特定`reducer`函数管理的状态片段，并返回一个新的 reducer 函数。例如，如果你运行以下代码：

```js
console.log(JSON.stringify( 
    reducer(initialState, { type: null }), 
    null, 2, 
)) 
```

你会看到生成的状态形状如下：

```js
{ 
    "todoList": [], 
    "chatMsg": [], 
} 
```

我们也可以尝试一下，看看我们组合的 reducer 是否工作，并且只管理分配给它们的状态部分。例如：

```js
console.log(JSON.stringify( 
    reducer( 
        initialState, 
        { 
            type: 'ADD_TODO', 
            title: 'This is an example', 
            completed: false, 
        }, 
    ), 
    null, 2, 
)) 
```

输出应该显示生成的状态如下：

```js
{ 
    "todoList": [ 
        { 
            "title": "This is an example", 
            "completed": false, 
        }, 
    ], 
    "chatMsg": [], 
} 
```

这表明每个 reducer 只管理分配给它们的状态片段。

# 准备工作

在这个教程中，你将重新创建待办事项应用程序，就像在之前的教程中一样。但是，你将添加其他功能，比如删除和切换待办事项。你将定义应用程序的其他状态，这些状态将由单独的 reducer 函数管理。首先，创建一个新的`package.json`文件，内容如下：

```js
{ 
    "dependencies": { 
        "express": "4.16.3", 
        "redux": "4.0.0" 
    } 
} 
```

然后，通过打开终端并运行以下命令来安装依赖项：

```js
npm install
```

# 如何做...

首先，构建一个小的 ExpressJS 服务器应用程序，它将为客户端应用程序提供服务，并安装在`node_modules`中的 Redux 库：

1.  创建一个名为`todo-time.js`的新文件

1.  添加以下代码：

```js
      const express = require('express') 
      const path = require('path') 
      const app = express() 
      app.use('/lib', express.static( 
          path.join(__dirname, 'node_modules', 'redux', 'dist') 
      )) 
      app.get('/', (req, res) => { 
          res.sendFile(path.join( 
              __dirname, 
              'todo-time.html', 
          )) 
      }) 
      app.listen( 
          1337, 
          () => console.log('Web Server running on port 1337'), 
      ) 
```

1.  保存文件

接下来，构建待办事项客户端应用程序。还包括一个单独的 reducer 来管理当前本地时间的状态和一个随机幸运数字生成器：

1.  创建一个名为`todo-time.html`的新文件

1.  添加以下 HTML 代码：

```js
      <!DOCTYPE html> 
      <html lang="en"> 
      <head> 
         <meta charset="UTF-8"> 
          <title>Lucky Todo</title> 
          <script 
           src="img/babel.min.js">
          </script> 
          <script src="img/redux.js"></script> 
      </head> 
      <body> 
          <h1>List:</h1> 
          <form id="item-form"> 
              <input id="item-input" name="item" /> 
          </form> 
          <ul id="list"></ul> 
          <script type="text/babel"> 
              // Add code here 
          </script> 
      </body> 
      </html> 
```

1.  在 script 标签内添加以下 JavaScript 代码，按照下面的步骤开始

1.  保留我们将用来显示数据或与应用程序交互的 HTML 元素的引用：

```js
      const timeElem = document.querySelector('#current-time') 
      const formElem = document.querySelector('#todo-form') 
      const listElem = document.querySelector('#todo-list') 
      const inputElem = document.querySelector('#todo-input') 
      const luckyElem = document.querySelector('#lucky-number') 
```

1.  从 Redux 库中获取`createStore`方法和辅助方法：

```js
      const { 
          createStore, 
          combineReducers, 
          bindActionCreators, 
      } = Redux 
```

1.  设置 action 类型：

```js
      const TYPE = { 
          SET_TIME: 'SET_TIME', 
          SET_LUCKY_NUMBER: 'SET_LUCKY_NUMBER', 
          ADD_TODO: 'ADD_TODO', 
          REMOVE_TODO: 'REMOVE_TODO', 
          TOGGLE_COMPLETED_TODO: 'TOGGLE_COMPLETED_TODO', 
      } 
```

1.  定义 action creators：

```js
      const actions = { 
          setTime: (time) => ({ 
              type: TYPE.SET_TIME, 
              time, 
          }), 
          setLuckyNumber: (number) => ({ 
              type: TYPE.SET_LUCKY_NUMBER, 
              number, 
          }), 
          addTodo: (id, title) => ({ 
              type: TYPE.ADD_TODO, 
              title, 
              id, 
          }), 
          removeTodo: (id) => ({ 
              type: TYPE.REMOVE_TODO, 
              id, 
          }), 
          toggleTodo: (id) => ({ 
              type: TYPE.TOGGLE_COMPLETED_TODO, 
              id, 
          }), 
      } 
```

1.  定义一个 reducer 函数来管理状态的一个片段，保存时间：

```js
      const currentTime = (state = null, action) => { 
          switch (action.type) { 
              case TYPE.SET_TIME: return action.time 
              default: return state 
          } 
      } 
```

1.  定义一个 reducer 函数来管理状态的一个片段，保存每次用户加载应用程序时生成的幸运数字：

```js
      const luckyNumber = (state = null, action) => { 
          switch (action.type) { 
              case TYPE.SET_LUCKY_NUMBER: return action.number 
              default: return state 
          } 
      } 
```

1.  定义一个 reducer 函数来管理状态的一个片段，保存待办事项的数组：

```js
      const todoList = (state = [], action) => { 
          switch (action.type) { 
              case TYPE.ADD_TODO: return state.concat([ 
                  { 
                      id: String(action.id), 
                      title: action.title, 
                      completed: false, 
                  } 
              ]) 
              case TYPE.REMOVE_TODO: return state.filter( 
                  todo => todo.id !== action.id 
              ) 
              case TYPE.TOGGLE_COMPLETED_TODO: return state.map( 
                  todo => ( 
                      todo.id === action.id 
                          ? { 
                              ...todo, 
                              completed: !todo.completed, 
                          } 
                          : todo 
                  ) 
              ) 
              default: return state 
          } 
      } 
```

1.  将所有的 reducer 合并成一个单一的 reducer：

```js
      const reducer = combineReducers({ 
          currentTime, 
          luckyNumber, 
          todoList, 
      }) 
```

1.  创建一个 store：

```js
      const store = createStore(reducer) 
```

1.  将所有的 action creators 绑定到 store 的`dispatch`方法上：

```js
      const { 
          setTime, 
          setLuckyNumber, 
          addTodo, 
          removeTodo, 
          toggleTodo, 
      } = bindActionCreators(actions, store.dispatch) 
```

1.  订阅一个监听器到 store，当状态改变时更新包含时间的 HTML 元素：

```js
      store.subscribe(() => { 
          const { currentTime } = store.getState() 
          timeElem.textContent = currentTime 
      }) 
```

1.  订阅一个监听器到 store，当状态改变时更新包含幸运数字的 HTML 元素：

```js
      store.subscribe(() => { 
          const { luckyNumber } = store.getState() 
          luckyElem.textContent = `Your lucky number is: ${luckyNumber}` 
      }) 
```

1.  订阅一个监听器到 store，当状态改变时更新包含待办事项列表的 HTML 元素。为`li` HTML 元素设置`draggable`属性，允许用户在视图上拖放项目：

```js
      store.subscribe(() => { 
          const { todoList } = store.getState() 
          listElem.innerHTML = '' 
          todoList.forEach(todo => { 
              const li = document.createElement('li') 
              li.textContent = todo.title 
              li.dataset.id = todo.id 
              li.setAttribute('draggable', true) 
              if (todo.completed) { 
                  li.style = 'text-decoration: line-through' 
              } 
              listElem.appendChild(li) 
          }) 
      }) 
```

1.  在列表 HTML 元素上添加一个`click`事件的事件监听器，以在点击项目时切换待办事项的`completed`属性：

```js
      listElem.addEventListener('click', (event) => { 
    toggleTodo(event.target.dataset.id) 
      }) 
```

1.  在列表 HTML 元素上添加一个`drag`事件的事件监听器，当拖动项目到列表之外时，将移除一个待办事项：

```js
      listElem.addEventListener('drag', (event) => { 
          removeTodo(event.target.dataset.id) 
      }) 
```

1.  在包含输入 HTML 元素的表单上添加一个`submit`事件的事件监听器，以分派一个新动作来添加一个新的待办事项：

```js
      let id = 0 
      formElem.addEventListener('submit', (event) => { 
          event.preventDefault() 
          addTodo(++id, inputElem.value) 
          inputElem.value = '' 
      }) 
```

1.  当页面首次加载时，分发一个动作来设置一个幸运数字，并定义一个每秒触发的函数，以更新应用程序状态中的当前时间：

```js
      setLuckyNumber(Math.ceil(Math.random() * 1024)) 
      setInterval(() => { 
          setTime(new Date().toTimeString()) 
      }, 1000) 
```

1.  保存文件

# 让我们来测试一下...

要查看之前的工作成果：

1.  打开一个新的终端并运行：

```js
 node todo-time.js
```

1.  在浏览器中，访问：

```js
      http://localhost:1337/
```

1.  在输入框中输入内容并按回车。列表中应该会出现一个新项目。

1.  点击其中一个您添加的项目，标记为已完成。

1.  再次点击其中一个标记为已完成的项目，将其标记为未完成。

1.  点击并拖动其中一个项目到列表之外，以将其从待办事项列表中移除。

# 它是如何工作的...

1.  定义了三个 reducer 函数，分别独立管理具有以下结构的状态切片：

```js
      { 
          currentTime: String, 
          luckyNumber: Number, 
          todoList: Array.of({ 
              id: Number, 
              title: String, 
              completed: Boolean, 
          }), 
      } 
```

1.  我们使用了 Redux 库中的`combineReducers`辅助方法，将这三个 reducer 组合成一个单一的 reducer

1.  然后，创建了一个存储，提供了组合的 reducer 函数

1.  为方便起见，我们订阅了三个监听函数，每当状态发生变化时，这些函数就会被触发，以更新用于显示状态数据的 HTML 元素

1.  我们还定义了三个事件监听器：一个用于检测用户提交包含输入 HTML 元素的表单以添加新的待办事项，另一个用于检测用户点击屏幕上显示的待办事项以切换其状态，最后一个事件监听器用于检测用户拖动列表中的元素以分派一个动作将其从待办事项列表中移除

# 编写 Redux 存储增强器

Redux 存储增强器是一个高阶函数，它接受一个存储创建函数，并返回一个新的增强存储创建函数。`createStore`方法是一个存储创建函数，具有以下签名：

```js
createStore = (reducer, preloadedState, enhancer) => Store 
```

而存储增强器函数具有以下签名：

```js
enhancer = (...optionalArguments) => ( 
createStore => (reducer, preloadedState, enhancer) => Store 
) 
```

现在可能看起来有点难以理解，但如果一开始不理解也不必担心，因为您可能永远不需要编写存储增强器。这个示例的目的只是帮助您以非常简单的方式理解它们的目的。

# 准备工作

在这个示例中，您将创建一个存储增强器，以扩展 Redux 的功能，允许在`Map`JavaScript 原生对象中定义 reducer 函数。首先，创建一个新的`package.json`文件，内容如下：

```js
{ 
    "dependencies": { 
        "redux": "4.0.0" 
    } 
} 
```

然后，通过打开终端并运行以下命令来安装依赖项：

```js
 npm install
```

# 如何做...

记住，`createStore`接受一个单一的 reducer 函数作为第一个参数。我们编写了一个存储增强器，允许`createStore`方法接受一个包含键值对的`Map`对象，其中键是将要管理的状态属性或切片，值是一个`reducer`函数。然后，使用`Map`对象定义了两个 reducer 函数来处理状态的两个切片，一个用于计数，另一个用于设置当前时间：

1.  创建一个名为`map-store.js`的新文件。

1.  包括 Redux 库：

```js
      const { 
          createStore, 
          combineReducers, 
          bindActionCreators, 
      } = require('redux') 
```

1.  定义一个存储增强函数，允许`createStore`方法接受一个`Map`对象作为参数。它将遍历`Map`的每个键值对，并将其添加到一个对象中，然后使用`combineReducers`方法来组合这些 reducer：

```js
      const acceptMap = () => createStore => ( 
          (reducerMap, ...rest) => { 
              const reducerList = {} 
              for (const [key, val] of reducerMap) { 
                  reducerList[key] = val 
              } 
              return createStore( 
                  combineReducers(reducerList), 
                  ...rest, 
              ) 
          } 
      ) 
```

1.  定义动作类型：

```js
      const TYPE = { 
          INC_COUNTER: 'INC_COUNTER', 
          DEC_COUNTER: 'DEC_COUNTER', 
          SET_TIME: 'SET_TIME', 
      } 
```

1.  定义动作创建者：

```js
      const actions = { 
          incrementCounter: (incBy) => ({ 
              type: TYPE.INC_COUNTER, 
              incBy, 
          }), 
          decrementCounter: (decBy) => ({ 
              type: TYPE.DEC_COUNTER, 
              decBy, 
          }), 
          setTime: (time) => ({ 
              type: TYPE.SET_TIME, 
              time, 
          }), 
      } 
```

1.  定义一个`map`常量，其中包含一个`Map`的实例：

```js
      const map = new Map() 
```

1.  向`map`对象添加一个新的 reducer 函数，使用`counter`作为键：

```js
      map.set('counter', (state = 0, action) => { 
          switch (action.type) { 
              case TYPE.INC_COUNTER: return state + action.incBy 
              case TYPE.DEC_COUNTER: return state - action.decBy 
              default: return state 
          } 
      }) 
```

1.  向`map`对象添加另一个 reducer 函数，使用`time`作为键：

```js
      map.set('time', (state = null, action) => { 
          switch (action.type) { 
              case TYPE.SET_TIME: return action.time 
              default: return state 
          } 
      }) 
```

1.  创建一个新的存储，将`map`作为第一个参数，并将**存储增强器**作为第二个参数，以扩展`createStore`方法的功能：

```js
      const store = createStore(map, acceptMap()) 
```

1.  将先前定义的动作创建者绑定到存储的`dispatch`方法：

```js
      const { 
          incrementCounter, 
          decrementCounter, 
          setTime, 
      } = bindActionCreators(actions, store.dispatch) 
```

1.  要在 NodeJS 中测试代码，使用`setInterval`全局方法来每秒重复调用一个函数。它将首先分派一个动作来设置当前时间，然后根据条件决定是增加还是减少计数器。之后，在终端中漂亮地打印出存储的当前值：

```js
      setInterval(function() { 
          setTime(new Date().toTimeString()) 
          if (this.shouldIncrement) { 
              incrementCounter((Math.random() * 5) + 1 | 0) 
          } else { 
              decrementCounter((Math.random() * 5) + 1 | 0) 
          } 
          console.dir( 
              store.getState(), 
              { colors: true, compact: false }, 
          ) 
          this.shouldIncrement = !this.shouldIncrement 
      }.bind({ shouldIncrement: false }), 1000) 
```

1.  保存文件。

1.  打开一个新的终端并运行：

```js
 node map-store.js
```

1.  当前状态将每秒显示一次，具有以下形式：

```js
      { 
          "counter": Number, 
          "time": String, 
      } 
```

# 它是如何工作的...

增强器将存储创建者组合成一个新的存储创建者。例如，以下行：

```js
const store = createStore(map, acceptMap()) 
```

可以写成：

```js
const store = acceptMap()(createStore)(map) 
```

实际上，这在某种程度上将原始的`createStore`方法包装到另一个`createStore`方法中。

组合可以解释为一组函数，这些函数被调用并接受前一个函数的结果参数。例如：

```js
const c = (...args) => f(g(h(...args))) 
```

这将函数`f`、`g`和`h`从右到左组合成一个单一的函数`c`。这意味着，我们也可以像这样写前一行代码：

```js
const _createStore = acceptMap()(createStore) 
const store = _createStore(map) 
```

这里`_createStore`是将`createStore`和您的存储增强器函数组合的结果。

# 使用 Redux 进行时间旅行

尽管您可能永远不需要编写存储增强器，但有一种特殊的存储增强器可能对调试您的 Redux 动力应用程序非常有用，它可以通过应用程序的状态进行时间旅行。您可以通过简单安装**Redux DevTools 扩展**（适用于 Chrome 和 Firefox）来启用应用程序的时间旅行：[`github.com/zalmoxisus/redux-devtools-extension`](https://github.com/zalmoxisus/redux-devtools-extension)。

# 准备工作

在这个示例中，我们将看到一个示例，演示如何利用这个功能，并分析应用程序的状态在浏览器上运行的时间内如何发生变化。首先，创建一个新的`package.json`文件，内容如下：

```js
{ 
    "dependencies": { 
        "express": "4.16.3", 
        "redux": "4.0.0" 
    } 
} 
```

然后，通过打开终端并运行来安装依赖项：

```js
npm install 
```

确保在您的网络浏览器中安装了 Redux DevTools 扩展。

# 如何做...

构建一个计数器应用程序，当应用程序在浏览器上运行时，它将随机增加或减少初始指定的计数器 10 次。然而，由于它发生得很快，用户将无法注意到自应用程序启动以来状态实际上已经改变了 10 次。我们将使用 Redux DevTools 扩展来浏览和分析状态随时间如何改变。

首先，构建一个小的 ExpressJS 服务器应用程序，该应用程序将为客户端应用程序提供服务，并安装在`node_modules`中的 Redux 库：

1.  创建一个名为`time-travel.js`的新文件

1.  添加以下代码：

```js
      const express = require('express') 
      const path = require('path') 
      const app = express() 
      app.use('/lib', express.static( 
          path.join(__dirname, 'node_modules', 'redux', 'dist') 
      )) 
      app.get('/', (req, res) => { 
          res.sendFile(path.join( 
              __dirname, 
              'time-travel.html', 
          )) 
      }) 
      app.listen( 
          1337, 
          () => console.log('Web Server running on port 1337'), 
      ) 
```

1.  保存文件

接下来，使用时间旅行功能构建您的计数器，Redux 动力应用程序：

1.  创建一个名为`time-travel.html`的新文件

1.  添加以下 HTML 代码：

```js
      <!DOCTYPE html> 
      <html lang="en"> 
      <head> 
          <meta charset="UTF-8"> 
          <title>Time travel</title> 
          <script 
           src="img/babel.min.js">
          </script> 
          <script src="img/redux.js"></script> 
      </head> 
      <body> 
          <h1>Counter: <span id="counter"></span></h1> 
          <script type="text/babel"> 
              // Add JavaScript Code here 
          </script> 
      </body> 
      </html> 
```

1.  在脚本标签中添加以下 JavaScript 代码，按照以下步骤开始，从第 4 步开始

1.  保留一个引用到`span` HTML 元素，每当状态改变时将显示计数器的当前值：

```js
      const counterElem = document.querySelector('#counter') 
```

1.  从 Redux 库中获取`createStore`方法和`bindActionCreators`方法：

```js
      const { 
          createStore, 
          bindActionCreators, 
      } = Redux 
```

1.  定义两种动作类型：

```js
      const TYPE = { 
          INC_COUNTER: 'INC_COUNTER', 
          DEC_COUNTER: 'DEC_COUNTER', 
      } 
```

1.  定义两个动作创建者：

```js
      const actions = { 
          incCounter: (by) => ({ type: TYPE.INC_COUNTER, by }), 
          decCounter: (by) => ({ type: TYPE.DEC_COUNTER, by }), 
      } 
```

1.  定义一个 reducer 函数，根据给定的动作类型转换状态：

```js
      const reducer = (state = { value: 5 }, action) => { 
          switch (action.type) { 
              case TYPE.INC_COUNTER: 
                  return { value: state.value + action.by } 
              case TYPE.DEC_COUNTER: 
                  return { value: state.value - action.by } 
              default: 
                  return state 
          } 
      } 
```

1.  创建一个新的存储，提供一个存储增强器函数，当安装 Redux DevTools 扩展时，它将在`window`对象上可用：

```js
      const store = createStore( 
          reducer, 
          ( 
              window.__REDUX_DEVTOOLS_EXTENSION__ && 
              window.__REDUX_DEVTOOLS_EXTENSION__() 
          ), 
      ) 
```

1.  将动作创建者绑定到存储的`dispatch`方法：

```js
      const { 
          incCounter, 
          decCounter, 
      } = bindActionCreators(actions, store.dispatch) 
```

1.  订阅一个监听函数到存储，每当状态改变时将更新`span` HTML 元素：

```js
      store.subscribe(() => { 
          const state = store.getState() 
          counterElem.textContent = state.value 
      }) 
```

1.  让我们创建一个`for`循环，当应用程序运行时，它会随机更新增加或减少计数器 10 次：

```js
      for (let i = 0; i < 10; i++) { 
          const incORdec = (Math.random() * 10) > 5 
          if (incORdec) incCounter(2) 
          else decCounter(1) 
      } 
```

1.  保存文件

# 让我们来测试一下...

要查看之前的工作效果：

1.  打开一个新的终端并运行：

```js
 node todo-time.js
```

1.  在您的浏览器中访问：

```js
      http://localhost:1337/
```

1.  打开浏览器的开发者工具，并查找 Redux 选项卡。您应该看到一个类似这样的选项卡：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mean-qk-st-gd/img/d6635f01-f201-44b1-91ba-76ee735152da.png)

Redux DevTools – Tab Window

1.  滑块允许您从应用程序的最后状态移动到最初状态。尝试将滑块移动到不同的位置：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mean-qk-st-gd/img/64146aed-2c98-42af-bfef-96fa08b2d098.png)

Redux DevTools – Moving Slider

1.  在移动滑块时，您可以在浏览器中看到计数器的初始值以及在 for 循环中如何改变这些值十次

# 还有更多

**Redux DevTools**具有一些功能，您可能会发现令人惊讶和有助于调试和管理应用程序状态。实际上，如果您遵循了之前的示例，我建议您返回我们编写的项目，并启用此增强器，尝试使用 Redux DevTools 进行实验。

Redux DevTools 的众多功能之一是 Log 监视器，它按时间顺序显示分派的动作以及转换状态的结果值：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mean-qk-st-gd/img/c1d3b8a0-3d7d-4f30-80a0-1c660b506e43.png)

Redux DevTools – Log Monitor

# 理解 Redux 中间件

可能最简单和最好的扩展 Redux 功能的方法是使用中间件。

Redux 库中有一个名为`applyMiddleware`的 store 增强函数，允许您定义一个或多个中间件函数。Redux 中的中间件工作方式很简单，它允许您包装 store 的`dispatch`方法以扩展其功能。与 store 增强函数一样，中间件是可组合的，并具有以下签名：

```js
middleware = API => next => action => next(action) 
```

在这里，`API`是一个包含来自 store 的`dispatch`和`getState`方法的对象，解构`API`，签名如下：

```js
middleware = ({ 
    getState, 
    dispatch, 
}) => next => action => next(action)  
```

让我们分析它是如何工作的：

1.  `applyMiddleware`函数接收一个或多个中间件函数作为参数。例如：

```js
      applyMiddleware(middleware1, middleware2) 
```

1.  每个中间件函数在内部都被保留为一个`Array`。然后，在内部使用`Array.prototype.map`方法，数组通过调用自身提供 store 的`dispatch`和`getState`方法的中间件`API`对象来映射每个中间件函数。类似于这样：

```js
      middlewares.map((middleware) => middleware(API)) 
```

1.  然后，通过组合所有中间件函数，使用`next`参数计算`dispatch`方法的新值。在执行的第一个中间件中，`next`参数指的是在应用任何中间件之前的原始`dispatch`方法。例如，如果应用了三个中间件函数，新计算的 dispatch 方法的签名将是：

```js
      dispatch = (action) => ( 
          (action) => ( 
              (action) => store.dispatch(action) 
          )(action) 
      )(action) 
```

1.  这意味着中间件函数可以中断链，并且如果未调用`next(action)`方法，则可以阻止某个动作的分派

1.  中间件`API`对象的 dispatch 方法允许您调用 store 的 dispatch 方法，并应用之前应用的中间件。这意味着，如果在使用此方法时不小心，可能会创建一个无限循环

最初可能不那么简单地理解其内部工作方式，但我向你保证，你很快就会理解。

# 准备工作

在这个示例中，您将编写一个中间件函数，当分派未定义的动作类型时，它将警告用户。首先，创建一个包含以下内容的新的`package.json`文件：

```js
{ 
    "dependencies": { 
        "redux": "4.0.0" 
    } 
} 
```

然后，通过打开终端并运行以下命令来安装依赖项：

```js
npm install
```

# 如何做…

当在 reducers 中从未定义过的 action 类型被使用时，Redux 不会警告你或显示错误。构建一个 NodeJS 应用程序，该应用程序将使用 Redux 来管理其状态。专注于编写一个中间件函数，该函数将检查分派的动作类型是否已定义，否则会抛出错误：

1.  创建一个名为`type-check-redux.js`的新文件。

1.  包括 Redux 库：

```js
      const { 
          createStore, 
          applyMiddleware, 
      } = require('redux') 
```

1.  定义一个包含允许的动作类型的对象：

```js
      const TYPE = { 
          INCREMENT: 'INCREMENT', 
          DECREMENT: 'DECREMENT', 
          SET_TIME: 'SET_TIME', 
      } 
```

1.  创建一个虚拟的 reducer 函数，无论调用哪种动作类型，它都会返回其原始状态。我们不需要它来实现这个示例的目的：

```js
      const reducer = ( 
          state = null, 
          action, 
      ) => state 
```

1.  定义一个中间件函数，该函数将拦截正在分派的每个操作，并检查操作类型是否存在于`TYPE`对象中。如果操作存在，则允许分派操作，否则，抛出错误并通知用户分派了无效的操作类型。另外，让我们在错误消息的一部分中提供用户有关允许的有效类型的信息：

```js
      const typeCheckMiddleware = api => next => action => { 
          if (Reflect.has(TYPE, action.type)) { 
              next(action) 
          } else { 
              const err = new Error( 
                  `Type "${action.type}" is not a valid` + 
                  `action type. ` + 
                  `did you mean to use one of the following` + 
                  `valid types? ` + 
                  `"${Reflect.ownKeys(TYPE).join('"|"')}"n`, 
              ) 
              throw err 
          } 
      } 
```

1.  创建一个存储并应用定义的中间件函数：

```js
      const store = createStore( 
          reducer, 
          applyMiddleware(typeCheckMiddleware), 
      ) 
```

1.  分派两种操作类型。第一个操作类型是有效的，并且存在于`TYPE`对象中。但是，第二个是一个从未定义的操作类型：

```js
      store.dispatch({ type: 'INCREMENT' }) 
      store.dispatch({ type: 'MISTAKE' }) 
```

1.  保存文件。

# 让我们来测试一下...

首先，打开一个新的终端并运行：

```js
    node type-check-redux.js 
```

终端输出应显示类似于此的错误：

```js
/type-check-redux.js:25 
                throw err 
                ^ 
Error: Type "MISTAKE" is not a valid action type. did you mean to use one of the following valid types? "INCREMENT"|"DECREMENT"|"SET_TIME" 
    at Object.action [as dispatch] (/type-check-redux.js:18:15) 
    at Object.<anonymous> (/type-check-redux.js:33:7) 
```

在这个示例中，堆栈跟踪告诉我们错误发生在第`18`行，指向我们的中间件函数。但是，下一个指向第`33`行，`store.dispatch({ type: 'MISTAKE' })`，这是一个好事，因为它可以帮助您准确跟踪分派了从未定义的某些操作的位置。

# 它是如何工作的...

这很简单，中间件函数检查被分派的操作的操作类型，以查看它是否存在作为`TYPE`对象常量的属性。如果存在，则中间件将控制传递给链中的下一个中间件。但是，在我们的情况下，没有下一个中间件，因此控制权被传递给存储的原始分派方法，该方法将应用减速器并转换状态。另一方面，如果未定义操作类型，则中间件函数通过不调用`next`函数并抛出错误来中断中间件链。

# 处理异步数据流

默认情况下，Redux 不处理异步数据流。有几个库可以帮助您完成这些任务。但是，为了本章的目的，我们将使用中间件函数构建我们自己的实现，以使`dispatch`方法能够分派和处理异步数据流。

# 准备工作

在这个示例中，您将构建一个 ExpressJS 应用程序，其中包含一个非常小的 API，用于测试应用程序在进行 HTTP 请求和处理异步数据流和错误时的情况。首先，创建一个新的`package.json`文件，内容如下：

```js
{ 
    "dependencies": { 
        "express": "4.16.3", 
        "node-fetch": "2.1.2", 
        "redux": "4.0.0" 
    } 
} 
```

然后通过打开终端并运行来安装依赖项：

```js
npm install  
```

# 如何做...

构建一个简单的 RESTful API 服务器，当进行 GET 请求时，将有两个端点或回答路径`/time`和`/date`。但是，在`/date`路径上，我们将假装存在内部错误，并使请求失败，以查看如何处理异步请求中的错误：

1.  创建一个名为`api-server.js`的新文件

1.  包括 ExpressJS 库并初始化一个新的 ExpressJS 应用程序：

```js
      const express = require('express') 
      const app = express() 
```

1.  对于`/time`路径，在发送响应之前模拟延迟`2s`：

```js
      app.get('/time', (req, res) => { 
          setTimeout(() => { 
              res.send(new Date().toTimeString()) 
          }, 2000) 
      }) 
```

1.  对于`/date`路径，在发送失败响应之前模拟延迟`2s`：

```js
      app.get('/date', (req, res) => { 
          setTimeout(() => { 
              res.destroy(new Error('Internal Server Error')) 
          }, 2000) 
      }) 
```

1.  监听端口`1337`以获取新连接

```js
      app.listen( 
          1337, 
          () => console.log('API server running on port 1337'), 
      ) 
```

1.  保存文件

至于客户端，使用 Redux 构建一个 NodeJS 应用程序，该应用程序将分派同步和异步操作。编写一个中间件函数，以使分派方法能够处理异步操作：

1.  创建一个名为`async-redux.js`的新文件

1.  包括`node-fetch`和 Redux 库：

```js
      const fetch = require('node-fetch') 
      const { 
          createStore, 
          applyMiddleware, 
          combineReducers, 
          bindActionCreators, 
      } = require('redux') 
```

1.  定义三种状态。每种状态表示异步操作的状态：

```js
      const STATUS = { 
          PENDING: 'PENDING', 
          RESOLVED: 'RESOLVED', 
          REJECTED: 'REJECTED', 
      } 
```

1.  定义两种操作类型：

```js
      const TYPE = { 
          FETCH_TIME: 'FETCH_TIME', 
          FETCH_DATE: 'FETCH_DATE', 
      } 
```

1.  定义操作创建者。请注意，前两个操作创建者中的值属性是一个异步函数。稍后定义的中间件函数将负责使 Redux 理解这些操作：

```js
      const actions = { 
          fetchTime: () => ({ 
              type: TYPE.FETCH_TIME, 
              value: async () => { 
                  const time = await fetch( 
                      'http://localhost:1337/time' 
                  ).then((res) => res.text()) 
                  return time 
              } 
          }), 
          fetchDate: () => ({ 
              type: TYPE.FETCH_DATE, 
              value: async () => { 
                  const date = await fetch( 
                      'http://localhost:1337/date' 
                  ).then((res) => res.text()) 
                  return date 
              } 
          }), 
          setTime: (time) => ({ 
              type: TYPE.FETCH_TIME, 
              value: time, 
          }) 
      } 
```

1.  定义一个通用函数，用于从操作对象中设置值，该函数将在您的减速器中使用：

```js
      const setValue = (prevState, action) => ({ 
          ...prevState, 
          value: action.value || null, 
          error: action.error || null, 
          status: action.status || STATUS.RESOLVED, 
      }) 
```

1.  定义应用程序的初始状态：

```js
      const iniState = { 
          time: { 
              value: null, 
              error: null, 
              status: STATUS.RESOLVED, 
          }, 
          date: { 
              value: null, 
              error: null, 
              status: STATUS.RESOLVED, 
          } 
      } 
```

1.  定义一个减速器函数。请注意，它只有一个减速器，处理状态的两个部分，即`time`和`date`：

```js
      const timeReducer = (state = iniState, action) => { 
          switch (action.type) { 
              case TYPE.FETCH_TIME: return { 
                  ...state, 
                  time: setValue(state.time, action) 
              } 
              case TYPE.FETCH_DATE: return { 
                  ...state, 
                  date: setValue(state.date, action) 
              } 
              default: return state 
          } 
      } 
```

1.  定义一个中间件函数，用于检查分发的动作类型是否具有`value`属性作为函数。如果是这样，假设`value`属性是一个异步函数。首先，我们分发一个动作来将状态设置为`PENDING`。然后，当异步函数解决时，我们分发另一个动作来将状态设置为`RESOLVED`，或者在出现错误时设置为`REJECTED`。

```js
      const allowAsync = ({ dispatch }) => next => action => { 
          if (typeof action.value === 'function') { 
              dispatch({ 
                  type: action.type, 
                  status: STATUS.PENDING, 
              }) 
              const promise = Promise 
                  .resolve(action.value()) 
                  .then((value) => dispatch({ 
                      type: action.type, 
                      status: STATUS.RESOLVED, 
                      value, 
                  })) 
                        .catch((error) => dispatch({ 
                      type: action.type, 
                      status: STATUS.REJECTED, 
                      error: error.message, 
                  })) 
              return promise 
          } 
          return next(action) 
      } 
```

1.  创建一个新的存储器，并应用你定义的中间件函数来扩展`dispatch`方法的功能：

```js
      const store = createStore( 
          timeReducer, 
          applyMiddleware( 
              allowAsync, 
          ), 
      ) 
```

1.  将动作创建器绑定到存储器的`dispatch`方法上：

```js
      const { 
          setTime, 
          fetchTime, 
          fetchDate, 
      } = bindActionCreators(actions, store.dispatch) 
```

1.  订阅一个函数监听器到存储器，并在每次状态发生变化时在终端显示状态树，以 JSON 字符串的形式。

```js
      store.subscribe(() => { 
          console.log('x1b[1;34m%sx1b[0m', 'State has changed') 
          console.dir( 
              store.getState(), 
              { colors: true, compact: false }, 
          ) 
      }) 
```

1.  分发一个同步动作来设置时间：

```js
      setTime(new Date().toTimeString()) 
```

1.  分发一个异步动作来获取并设置时间：

```js
      fetchTime() 
```

1.  分发另一个异步动作来获取并尝试设置日期。请记住，这个操作应该失败，这是故意的。

```js
      fetchDate() 
```

1.  保存文件。

# 让我们来测试一下...

要查看之前的工作成果：

1.  打开一个新的终端并运行：

```js
 node api-server.js
```

1.  在不关闭先前运行的 NodeJS 进程的情况下，打开另一个终端并运行：

```js
 node async-redux.js
```

# 工作原理是这样的...

1.  每当状态发生变化时，订阅的监听函数将在终端中漂亮地打印出当前状态树。

1.  第一个分发的动作是同步的。它将导致状态树的时间片段被更新，例如像这样：

```js
      time: { 
          value: "01:02:03 GMT+0000", 
          error: null, 
          status: "RESOLVED" 
      } 
```

1.  第二个被分发的动作是异步的。在内部，会分发两个动作来反映异步操作的状态，一个是在异步函数仍在执行时，另一个是在异步函数被执行完成时。

```js
      time: { 
          value: null, 
          error: null, 
          status: "PENDING" 
      } 
      // Later, once the operation is fulfilled: 
      time: { 
          value: "01:02:03 GMT+0000", 
          error: null, 
          status: "RESOLVED" 
      } 
```

1.  第三个被分发的动作也是异步的。在内部，它也会导致分发两个动作来反映异步操作的状态。

```js
      date: { 
          value: null, 
          error: null, 
          status: "PENDING" 
      } 
      // Later, once the operation is fulfilled: 
      date: { 
          value: null, 
          error: "request to http://localhost:1337/date failed, reason:   
             socket hang up", 
          status: "REJECTED" 
      } 
```

1.  请注意，由于操作是异步的，终端显示的输出可能不总是按照相同的顺序进行。

1.  注意，第一个异步操作被执行完成，并且状态标记为`RESOLVED`，而第二个异步操作被执行完成，并且其状态标记为`REJECTED`。

1.  状态`PENDING`，`RESOLVED`和`REJECTED`反映了 JavaScript Promise 可能具有的三种状态，并且它们不是强制性的名称，只是易于记忆。

# 还有更多...

如果你不想编写自己的中间件函数或存储增强器来处理异步操作，你可以选择使用 Redux 的许多现有库之一。其中两个最常用或最受欢迎的是这些：

+   Redux Thunk—[`github.com/gaearon/redux-thunk`](https://github.com/gaearon/redux-thunk)

+   Redux Saga—[`github.com/redux-saga/redux-saga`](https://github.com/redux-saga/redux-saga)
