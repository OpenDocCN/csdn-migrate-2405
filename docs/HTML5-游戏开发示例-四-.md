# HTML5 游戏开发示例（四）

> 原文：[`zh.annas-archive.org/md5/4F48ABC6F07BFC08A9422C3E7897B7CC`](https://zh.annas-archive.org/md5/4F48ABC6F07BFC08A9422C3E7897B7CC)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：使用 WebSockets 构建多人绘画和猜词游戏

> 在之前的章节中，我们构建了几个本地单人游戏。在本章中，我们将借助 WebSockets 构建一个多人游戏。WebSockets 使我们能够创建基于事件的服务器-客户端架构。所有连接的浏览器之间传递的消息都是即时的。我们将结合 Canvas 绘图、JSON 数据打包和在之前章节中学到的几种技术来构建绘画和猜词游戏。

在本章中，我们将学习以下主题：

+   尝试现有的多用户绘图板，通过 WebSockets 显示来自不同连接用户的绘画

+   安装由`node.js`实现的 WebSockets 服务器

+   从浏览器连接服务器

+   使用 WebSocket API 创建一个即时聊天室

+   在 Canvas 中创建一个多用户绘图板

+   通过集成聊天室和游戏逻辑进行绘画和猜词游戏的构建

以下屏幕截图显示了我们将在本章中创建的绘画和猜词游戏：

![使用 WebSockets 构建多人绘画和猜词游戏](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_08_01.jpg)

所以，让我们开始吧。

# 尝试现有的 WebSockets 网络应用程序

在我们开始构建 WebSockets 示例之前，我们将看一下现有的多用户绘图板示例。这个示例让我们知道如何使用 WebSockets 服务器立即在浏览器之间发送数据。

### 提示

**浏览器使用 WebSockets 的能力**

在撰写本书时，只有苹果 Safari 和 Google Chrome 支持 WebSockets API。Mozilla Firefox 和 Opera 因协议上的潜在安全问题而放弃了对 WebSockets 的支持。Google Chrome 也计划在安全漏洞修复之前放弃 WebSockets。

Mozilla 的以下链接解释了他们为什么禁用了 WebSockets：

[`hacks.mozilla.org/2010/12/websockets-disabled-in-firefox-4/`](http://hacks.mozilla.org/2010/12/websockets-disabled-in-firefox-4/)

# 尝试多用户绘图板的时间

执行以下步骤：

1.  在 Web 浏览器中打开以下链接：

1.  [`www.chromeexperiments.com/detail/multiuser-sketchpad/`](http://www.chromeexperiments.com/detail/multiuser-sketchpad/)

1.  您将看到一个多用户绘图板的介绍页面。右键单击**启动实验**选项，选择**在新窗口中打开链接**。

1.  浏览器会提示一个新窗口，显示绘图板应用程序。然后，我们重复上一步，再次打开绘图板的另一个实例。

1.  将两个浏览器并排放在桌面上。

1.  尝试在任一绘图板上画些东西。绘画应该会出现在两个绘图板上。此外，绘图板是与所有连接的人共享的。您还可以看到其他用户的绘画。

1.  以下屏幕截图显示了两个用户在绘图板上画的一个杯子：

![尝试多用户绘图板的时间](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_08_02.jpg)

## 刚刚发生了什么？

我们刚刚看到浏览器如何实时连接在一起。我们在绘图板上画了些东西，所有其他连接的用户都可以看到这些图画。此外，我们也可以看到其他人正在画什么。

该示例是使用 HTML5 WebSockets 功能与后端服务器制作的，以向所有连接的浏览器广播绘图数据。

绘画部分是建立在 Canvas 上的，我们已经在*第四章，使用 Canvas 和绘图 API 构建 Untangle 游戏*中介绍过。WebSocket API 使浏览器能够与服务器建立持久连接。后端是一个名为`node.js`的基于事件的服务器，我们将在本章中安装和使用。

# 安装 WebSocket 服务器

HTML5 的 WebSockets 提供了一个客户端 API，用于将浏览器连接到后端服务器。该服务器必须支持 WebSockets 协议，以保持连接持久。

## 安装 Node.JS WebSocket 服务器

在这一部分，我们将下载并安装一个名为`Node.JS`的服务器，我们可以在上面安装一个 WebSockets 模块。

# 安装 Node.JS 的时间

执行以下步骤：

1.  转到包含`Node.JS`服务器源代码的以下 URL：

1.  [`github.com/joyent/node`](https://github.com/joyent/node)

1.  单击页面上的**下载**按钮。它会提示一个对话框询问要下载哪种格式。只需选择 ZIP 格式。

1.  在工作目录中解压 ZIP 文件。

1.  在 Linux 或 Mac OSX 中，使用终端并切换到`node.js`文件所在的目录。

### 注意

`Node.JS`在 Linux 和 Mac 上可以直接使用。以下链接提供了一个安装程序，用于在 Windows 上安装`Node.JS`：

[`node-js.prcn.co.cc/`](http://node-js.prcn.co.cc/)

1.  运行以下命令：

```js
$ ./configure
$ sudo make install

```

使用`sudo make install`命令以 root 权限安装`Node.JS`，并以 root 访问权限安装所需的第三方库。以下链接讨论了如何在不使用`sudo`的情况下安装`Node.JS`：

### 提示

[`increaseyourgeek.wordpress.com/2010/08/18/install-node-js-without-using-sudo/`](http://increaseyourgeek.wordpress.com/2010/08/18/install-node-js-without-using-sudo/)

1.  `sudo make install`命令需要输入具有管理员特权的系统用户的密码。输入密码以继续安装。

1.  安装完成后，可以使用以下命令检查`node.js`是否已安装：

```js
$ node --version

```

1.  上述命令应该打印出`node.js`的版本号。在我的情况下，它是 0.5 预发布版：

```js
v0.5.0-pre

```

1.  接下来，我们将为`Node.JS`服务器安装 WebSockets 库。在浏览器中转到以下 URL：

1.  [`github.com/miksago/node-websocket-server`](http://https://github.com/miksago/node-websocket-server)

1.  单击页面上的**下载**按钮并下载 ZIP 文件。

1.  在一个目录中解压 ZIP 文件。我们稍后会需要这个包中的`lib`目录。

## 刚刚发生了什么？

我们刚刚下载并安装了`Node.JS`服务器。我们还下载了`node.js`服务器的 WebSockets 库。通过本章的示例，我们将在此服务器和 WebSockets 库的基础上构建服务器逻辑。

### 注意

`Node.js`服务器安装在 Unix 或 Linux 操作系统上运行良好。但是，在 Windows 上安装和运行`node.js`服务器需要更多步骤。以下链接显示了如何在 Windows 上安装`node.js`服务器：

[`github.com/joyent/node/wiki/Building-node.js-on-Cygwin-(Windows)`](http://https://github.com/joyent/node/wiki/Building-node.js-on-Cygwin-(Windows))

## 创建一个用于广播连接计数的 WebSockets 服务器

我们刚刚安装了带有 WebSockets 库的`node.js`服务器。现在，我们将构建一些内容来测试 WebSockets。现在想象一下，我们需要一个服务器来接受浏览器的连接，然后向所有用户广播连接计数。

# 执行以下操作创建一个发送连接总数的 WebSocket 服务器

执行以下步骤：

1.  创建一个名为`server`的新目录。

1.  将`node-websocket-server`包中的整个`lib`文件夹复制到`server`目录中。

1.  在`server`目录下创建一个名为`server.js`的新文件，并包含以下内容：

```js
var ws = require(__dirname + '/lib/ws/server');
var server = ws.createServer();
server.addListener("connection", function(conn){
// init stuff on connection
console.log("A connection established with id",conn.id);
var message = "Welcome "+conn.id+" joining the party. Total connection:"+server.manager.length;
server.broadcast(message);
});
server.listen(8000);
console.log("WebSocket server is running.");
console.log("Listening to port 8000.");

```

1.  打开终端并切换到服务器目录。

1.  输入以下命令以执行服务器：

```js
node server.js

```

1.  如果成功，应该得到以下结果：

```js
$ node server.js
WebSocket server is running.
Listening to port 8000.

```

## 刚刚发生了什么？

我们刚刚创建了一个简单的服务器逻辑，初始化了 WebSockets 库，并监听了连接事件。

## 初始化 WebSockets 服务器

在`Node.JS`中，不同的功能被打包到模块中。当我们需要特定模块中的功能时，我们使用`require`进行加载。我们加载 WebSockets 模块，然后在服务器逻辑中使用以下代码初始化服务器：

```js
var ws = require(__dirname + '/lib/ws/server');
var server = ws.createServer();

```

`__dirname`表示正在执行的服务器 JavaScript 文件的当前目录。我们将`lib`文件夹放在服务器逻辑文件的同一文件夹下。因此，WebSockets 服务器位于**当前目录** | **lib** | **ws** | **server**。

最后，我们需要为服务器分配一个端口来监听以下代码：

```js
server.listen(8000);

```

在上述代码片段中，`8000`是客户端连接到此服务器的端口号。 我们可以选择不同的端口号，但必须确保所选的端口号不会与其他常见服务器服务重叠。

### 注意

为了获取有关`node.js`服务器的全局范围对象和变量的更多信息，请访问以下链接的官方文档：

[`nodejs.org/docs/v0.4.3/api/globals.html`](http://nodejs.org/docs/v0.4.3/api/globals.html)

## 在服务器端监听连接事件

`node.js`服务器是基于事件的。 这意味着大多数逻辑是在触发某个事件时执行的。 我们在示例中使用的以下代码监听`connection`事件并处理它：

```js
server.addListener("connection", function(conn){
console.log("A connection established with id",conn.id);
…
});

```

`connection`事件带有一个连接参数。 我们在连接实例中有一个`id`属性，我们可以用它来区分每个连接的客户端。

以下表列出了两个常用的服务器事件：

| WebSockets node.js 的服务器端事件 | 描述 |
| --- | --- |
| `connection` | 当客户端建立新连接时触发事件 |
| `close` | 当连接关闭时触发事件 |

## 获取服务器端连接的客户端计数

我们可以通过访问服务器管理器来获取 WebSockets `node.js`服务器中连接的客户端数。 我们可以使用以下代码获取计数：

```js
var totalConnectedClients = server.manager.length;

```

## 向所有连接的浏览器广播消息

一旦服务器收到新的`connection`事件，我们就会向所有客户端广播连接的更新计数。 向客户端广播消息很容易。 我们只需要在`server`实例中使用`string`参数调用`broadcast`函数。

以下代码片段向所有连接的浏览器广播服务器消息：

```js
var message = "a message from server";
server.broadcast(message);

```

## 创建一个连接到 WebSocket 服务器并获取总连接数的客户端

我们在上一个示例中构建了服务器，现在我们将构建一个客户端，连接到我们的 WebSocket 服务器并从服务器接收消息。 该消息将包含来自服务器的总连接计数。

# 行动时间在 WebSocket 应用程序中显示连接计数

执行以下步骤：

1.  创建一个名为`client`的新目录。

1.  在`client`文件夹中创建一个名为`index.htm`的 HTML 文件。

1.  我们将在我们的 HTML 文件中添加一些标记。 将以下代码放入`index.htm`文件中：

```js
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>WebSockets demo for HTML5 Games Development: A Beginner's Guide</title>
<meta name="description" content="This is a WebSockets demo for the book HTML5 Games Development: A Beginner's Guide by Makzan">
<meta name="author" content="Makzan">
</head>
<body>
<script src="img/jquery-1.6.min.js"></script>
<script src="img/html5games.websocket.js"></script>
</body>
</html>

```

1.  创建一个名为`js`的目录，并将 jQuery JavaScript 文件放入其中。

1.  创建一个名为`html5games.websockets.js`的新文件，如下所示：

```js
var websocketGame = {
}
// init script when the DOM is ready.
$(function(){
// check if existence of WebSockets in browser
if (window["WebSocket"]) {
// create connection
websocketGame.socket = new WebSocket("ws://127.0.0.1:8000");
// on open event
websocketGame.socket.onopen = function(e) {
console.log('WebSocket connection established.');
};
// on message event
websocketGame.socket.onmessage = function(e) {
console.log(e.data);
};
// on close event
websocketGame.socket.onclose = function(e) {
console.log('WebSocket connection closed.');
};
}
});

```

1.  我们将测试代码。 首先，我们需要通过`node server.js`运行带有我们的`server.js`代码的节点服务器。

1.  接下来，在 Web 浏览器中的客户端目录中打开`index.htm`文件两次。

1.  检查服务器终端。 应该有类似以下的日志消息，指示连接信息和总连接数：

```js
$ node server.js
WebSocket server is running.
Listening to port 8000.
A connection established with id 3863522640
A connection established with id 3863522651

```

1.  然后，我们在浏览器中检查控制台面板。 一旦加载页面，我们就可以获得总连接数。 以下屏幕截图显示了客户端端的结果：

![行动时间在 WebSocket 应用程序中显示连接计数](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_08_03.jpg)

## 刚刚发生了什么？

我们刚刚构建了一个客户端，它与我们在上一节中构建的服务器建立了 WebSockets 连接。 然后，客户端将从服务器接收的任何消息打印到检查器中的控制台面板中。

## 建立 WebSocket 连接

在支持 WebSockets 的任何浏览器中，我们可以通过使用以下代码创建一个新的 WebSocket 实例来建立连接：

```js
var socket = new WebSocket(url);

```

`url`参数是一个带有 WebSockets URL 的字符串。 在我们的示例中，我们正在本地运行我们的服务器。 因此，我们使用的 URL 是`ws://127.0.0.1:8000`，其中 8000 表示我们正在连接的服务器的端口号。 这是 8000，因为当我们构建服务器端逻辑时，服务器正在监听端口 8000。

## WebSockets 客户端事件

与服务器类似，客户端端有几个 WebSockets 事件。以下表格列出了我们将用于处理 WebSockets 的事件：

| 事件名称 | 描述 |
| --- | --- |
| `onopen` | 当与服务器的连接建立时触发 |
| `onmessage` | 当从服务器接收到任何消息时触发 |
| `onclose` | 当服务器关闭连接时触发 |
| `onerror` | 当连接出现任何错误时触发 |

# 使用 WebSockets 构建聊天应用程序

我们现在知道有多少浏览器连接。假设我们想要构建一个聊天室，用户可以在各自的浏览器中输入消息，并立即将消息广播给所有连接的用户。

## 向服务器发送消息

我们将让用户输入消息，然后将消息发送到`node.js`服务器。然后服务器将消息转发到所有连接的浏览器。一旦浏览器接收到消息，它就会在聊天区域显示出来。在这种情况下，用户一旦加载网页就连接到即时聊天室。

# 采取行动 通过 WebSockets 向服务器发送消息

执行以下步骤：

1.  首先，编写服务器逻辑。

1.  打开`server.js`并添加以下突出显示的代码：

```js
server.addListener("connection", function(conn){
// init stuff on connection
console.log("A connection established with id",conn.id);
var message = "Welcome "+conn.id+" joining the party. Total connection:"+server.manager.length;
server.broadcast(message);
// listen to the message
conn.addListener("message", function(message){
console.log("Got data '"+message+"' from connection "+conn.id);
});
});

```

1.  现在转到`client`文件夹。

1.  打开`index.htm`文件，并在`body`部分中添加以下标记。它为用户提供了输入并发送消息到服务器的输入：

```js
<input type='text' id="chat-input">
<input type='button' value="Send" id="send">

```

1.  然后，将以下代码添加到`html5games.websocket.js` JavaScript 文件中。当用户单击`send`按钮或按**Enter**键时，它将消息发送到服务器：

```js
$("#send").click(sendMessage);
$("#chat-input").keypress(function(event) {
if (event.keyCode == '13') {
sendMessage();
}
});
function sendMessage()
{
var message = $("#chat-input").val();
websocketGame.socket.send(message);
$("#chat-input").val("");
}

```

1.  在测试我们的代码之前，检查服务器终端，看看 node 服务器是否仍在运行。按**Ctrl+C**终止它，然后使用`node server.js`命令再次运行它。

1.  在 Web 浏览器中打开`index.htm`。您应该看到一个带有**Send**按钮的输入文本字段，如下面的屏幕截图所示：![采取行动 通过 WebSockets 向服务器发送消息](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_08_04.jpg)

1.  尝试在输入文本字段中输入一些内容，然后单击**Send**按钮或按**Enter**。输入文本将被清除。

1.  现在，切换到服务器终端，我们将看到服务器打印我们刚刚发送的文本。您还可以将浏览器和服务器终端并排放置，以查看消息从客户端发送到服务器的实时性。以下屏幕截图显示了服务器终端上来自两个连接的浏览器的消息：

![采取行动 通过 WebSockets 向服务器发送消息](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_08_05.jpg)

## 刚刚发生了什么？

我们刚刚通过添加一个输入文本字段来扩展了我们的连接示例，让用户在其中输入一些文本并将其发送出去。文本作为消息发送到 WebSockets 服务器。然后服务器将在终端中打印接收到的消息。

## 从客户端向服务器发送消息

为了从客户端向服务器发送消息，我们在`WebSocket`实例中调用以下`send`方法：

```js
websocketGame.socket.send(message);

```

在我们的示例中，以下代码片段从输入文本字段中获取消息并将其发送到服务器：

```js
var message = $("#chat-input").val();
websocketGame.socket.send(message);

```

## 在服务器端接收消息

在服务器端，我们需要处理刚刚从客户端发送的消息。在 WebSocket `node.js`库中的连接实例中有一个名为`message`的事件。我们可以监听连接消息事件以接收来自每个客户端连接的消息。

以下代码片段显示了我们如何使用消息事件监听器在服务器终端上打印消息和唯一连接 ID：

```js
conn.addListener("message", function(message){
console.log("Got data '"+message+"' from connection "+conn.id);
});

```

### 注意

在服务器和客户端之间发送和接收消息时，只接受字符串。我们不能直接发送对象。但是，我们可以在传输之前将数据转换为 JSON 格式的字符串。我们将在本章后面展示发送数据对象的示例。

# 在服务器端广播每条接收到的消息以创建聊天室

在上一个示例中，服务器可以接收来自浏览器的消息。但是，服务器除了在终端中打印接收到的消息之外，什么也不做。因此，我们将向服务器添加一些逻辑，以广播消息。

# 执行广播消息到所有连接的浏览器的操作

执行以下步骤：

1.  打开服务器端逻辑的`server.js`文件。

1.  将以下突出显示的代码添加到消息事件监听器处理程序中：

```js
conn.addListener("message", function(message){
console.log("Got data '"+message+"' from connection "+conn.id);
var displayMessage = conn.id + " says: "+message;
server.broadcast(displayMessage);
});

```

1.  服务器端就是这样。转到`client`文件夹并打开`index.htm`文件。

1.  我们想在聊天历史区域显示聊天消息。将以下代码添加到 HTML 文件中：

```js
<ul id="chat-history"></ul>

```

1.  接下来，我们需要客户端 JavaScript 来处理从服务器接收的消息。我们用它将消息打印到控制台面板中，用以下突出显示的代码替换`onmessage`事件处理程序中的`console.log`代码：

```js
socket.onmessage = function(e) {
$("#chat-history").append("<li>"+e.data+"</li>");
};

```

1.  让我们测试我们的代码。通过**Ctrl + C**终止任何正在运行的 node 服务器。然后再次运行服务器。

1.  打开`index.htm`文件两次，将它们并排放置。在文本字段中输入一些内容，然后按**Enter**。消息将出现在所有打开的浏览器上。如果打开多个 HTML 文件实例，则消息应该出现在所有浏览器上。下面的截图显示了两个并排显示聊天历史记录的浏览器：

![执行广播消息到所有连接的浏览器的操作](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_08_06.jpg)

## 刚才发生了什么？

这是我们之前示例的延伸。我们讨论了服务器如何向所有连接的客户端广播连接计数。我们还讨论了客户端如何向服务器发送消息。在这个例子中，我们将这两种技术结合起来，让服务器将接收到的消息广播给所有连接的用户。

## 比较 WebSocket 和轮询方法

如果您曾经使用服务器端语言和数据库构建过网页聊天室，那么您可能会想知道 WebSocket 实现和传统实现之间有什么区别。

传统的聊天室方法通常使用**轮询**方法实现。客户端定期向服务器请求更新。服务器会用没有更新或更新的数据来响应客户端。然而，传统方法存在一些问题。客户端直到下一次向服务器请求之前，才能从服务器获取新的更新数据。这意味着数据更新会延迟一段时间，响应不够即时。如果我们想通过缩短轮询持续时间来改善这个问题，那么会利用更多的带宽，因为客户端需要不断向服务器发送请求。

下图显示了客户端和服务器之间的请求。它显示了许多无用的请求被发送，但服务器在没有新数据的情况下响应客户端：

![WebSocket 和轮询方法之间的比较](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_08_07.jpg)

还有一种更好的轮询方法叫做**长轮询**。客户端向服务器发送请求并等待响应。与传统的轮询方法不同，服务器不会以“没有更新”的方式响应，直到有需要推送给服务器的内容。在这种方法中，服务器可以在有更新时向客户端推送内容。一旦客户端从服务器收到响应，它会创建另一个请求并等待下一个服务器通知。下面的图显示了长轮询方法，客户端请求更新，服务器只在有更新时响应：

![WebSocket 和轮询方法之间的比较](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_08_13.jpg)

在 WebSockets 方法中，请求的数量远少于轮询方法。这是因为客户端和服务器之间的连接是持久的。一旦建立连接，只有在有任何更新时才会从客户端或服务器端发送请求。例如，当客户端想要向服务器更新某些内容时，客户端向服务器发送消息。服务器也只在需要通知客户端数据更新时才向客户端发送消息。在连接期间不会发送其他无用的请求。因此，利用的带宽更少。以下图显示了 WebSockets 方法：

![WebSockets 和轮询方法之间的比较](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_08_08.jpg)

## 小测验：WebSockets 相对于轮询方法的好处

使用基于事件的 WebSockets 方法实现多用户聊天室的好处是什么？这些好处如何使消息传递如此即时？

# 使用 Canvas 和 WebSockets 制作共享绘图白板

假设我们想要一个共享的素描本。任何人都可以在素描本上画东西，所有其他人都可以查看，就像我们在本章开头玩的素描本示例一样。我们学习了如何在客户端和服务器之间传递消息。我们将进一步发送绘图数据。

## 构建本地绘图素描本

在处理数据发送和服务器处理之前，让我们专注于制作一个绘图白板。我们将使用画布来构建一个本地绘图素描本。

# 行动时间：使用 Canvas 制作本地绘图白板

执行以下步骤：

1.  在本节中，我们只关注客户端。打开`index.htm`文件并添加以下`canvas`标记：

```js
<canvas id='drawing-pad' width='500' height='400'>
</canvas>

```

1.  我们将在画布上画一些东西，我们将需要相对于画布的鼠标位置。我们在*第四章，使用 Canvas 和 Drawing API 构建 Untangle 游戏*中做到了这一点。将以下样式添加到画布：

```js
<style>
canvas{position:relative;}
</style>

```

1.  然后，我们打开`html5games.websocket.js` JavaScript 文件来添加绘图逻辑。

1.  在 JavaScript 文件的顶部用以下变量替换`websocketGame`全局对象：

```js
var websocketGame = {
// indicates if it is drawing now.
isDrawing : false,
// the starting point of next line drawing.
startX : 0,
startY : 0,
}
// canvas context
var canvas = document.getElementById('drawing-pad');
var ctx = canvas.getContext('2d');

```

1.  在 jQuery 的`ready`函数中，我们添加以下鼠标事件处理程序代码。该代码处理鼠标按下、移动和松开事件：

```js
// the logic of drawing on canvas
$("#drawing-pad").mousedown(function(e) {
// get the mouse x and y relative to the canvas top-left point.
var mouseX = e.layerX || 0;
var mouseY = e.layerY || 0;
startX = mouseX;
startY = mouseY;
isDrawing = true;
});
$("#drawing-pad").mousemove(function(e) {
// draw lines when is drawing
if (websocketGame.isDrawing) {
// get the mouse x and y relative to the canvas top-left point.
var mouseX = e.layerX || 0;
var mouseY = e.layerY || 0;
if (!(mouseX == websocketGame.startX && mouseY == websocketGame.startY)) {
drawLine(ctx, websocketGame.startX, websocketGame.startY,mouseX,mouseY,1);
websocketGame.startX = mouseX;
websocketGame.startY = mouseY;
}
}
});
$("#drawing-pad").mouseup(function(e) {
websocketGame.isDrawing = false;
});

```

1.  最后，我们有以下函数来在画布上画一条线，给定起点和终点：

```js
function drawLine(ctx, x1, y1, x2, y2, thickness) {
ctx.beginPath();
ctx.moveTo(x1,y1);
ctx.lineTo(x2,y2);
ctx.lineWidth = thickness;
ctx.strokeStyle = "#444";
ctx.stroke();
}

```

1.  保存所有文件并打开`index.htm`文件。我们应该看到一个空白的空间，我们可以使用鼠标绘制一些东西。绘图尚未发送到服务器，因此其他人无法查看我们的绘图：

![行动时间：使用 Canvas 制作本地绘图白板](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_08_09.jpg)

## 刚刚发生了什么？

我们刚刚创建了一个本地绘图板。这就像一个白板，玩家可以通过拖动鼠标在画布上绘图。但是，绘图数据尚未发送到服务器；所有绘图只在本地显示。

`画线`函数与我们在*第四章*中使用的相同。我们还使用相同的代码来获取鼠标相对于画布元素的位置。但是，鼠标事件的逻辑与*第四章*不同。

### 在画布上绘制

当我们在计算机上画东西时，通常意味着我们点击画布并拖动鼠标（或笔）。直到鼠标按钮松开为止才画线。然后，用户再次点击另一个地方并拖动以绘制线条。

在我们的示例中，我们有一个名为`isDrawing`的布尔标志，用于指示用户是否正在绘图。`isDrawing`标志默认为 false。当鼠标按钮按下时，我们将标志设置为 true。当鼠标移动时，我们在鼠标按钮按下时的移动点和上一个点之间画一条线。然后，当鼠标按钮松开时，我们再次将`isDrawing`标志设置为 false。

这就是绘图逻辑的工作方式。

## 尝试一下：使用颜色绘图

我们能否通过添加颜色支持来修改绘图画板？再加上五个按钮，分别是红色、蓝色、绿色、黑色和白色？玩家可以在绘图时选择颜色。

## 将绘图广播到所有连接的浏览器

我们将进一步通过将我们的绘图数据发送到服务器，并让服务器将绘图广播到所有连接的浏览器。

# 通过 WebSockets 发送绘图的时间

执行以下步骤：

1.  首先，我们需要修改服务器逻辑。打开`server.js`文件并替换以下代码。它使用 JSON 格式的字符串进行广播，因此我们可以发送和接收数据对象：

```js
// Constants
var LINE_SEGMENT = 0;
var CHAT_MESSAGE = 1;
var ws = require(__dirname + '/lib/ws/server');
var server = ws.createServer();
server.addListener("connection", function(conn){
// init stuff on connection
console.log("A connection established with id",conn.id);
var message = "Welcome "+conn.id+" joining the party. Total connection:"+server.manager.length;
var data = {};
data.dataType = CHAT_MESSAGE;
data.sender = "Server";
data.message = message;
shared drawing whiteboardshared drawing whiteboardconnected browsers drawings, broadcastingserver.broadcast(JSON.stringify(data));
// listen to the message
shared drawing whiteboardshared drawing whiteboardconnected browsers drawings, broadcastingconn.addListener("message", function(message){
console.log("Got data '"+message+"' from connection "+conn.id);
var data = JSON.parse(message);
if (data.dataType == CHAT_MESSAGE) {
// add the sender information into the message data object
data.sender = conn.id;
}
server.broadcast(JSON.stringify(data));
});
});
server.listen(8000);
console.log("WebSocket server is running.");
console.log("Listening to port 8000.");

```

1.  在客户端，我们需要逻辑来对服务器做出相同的数据对象定义的响应。在**client** | **js**目录中打开`html5games.websocket.js` JavaScript 文件。

1.  将以下常量添加到`websocketGame`全局变量中。相同的常量与相同的值也在服务器端逻辑中定义。

```js
// Contants
LINE_SEGMENT : 0,
CHAT_MESSAGE : 1,

```

1.  在客户端处理消息事件时，我们将 JSON 格式的字符串转换回数据对象。如果数据是聊天消息，那么我们将其显示为聊天历史记录，否则我们将其绘制在画布上作为线段。用以下代码替换`onmessage`事件处理程序：

```js
socket.onmessage = function(e) {
// check if the received data is chat message or line segment
console.log("onmessage event:",e.data);
var data = JSON.parse(e.data);
if (data.dataType == websocketGame.CHAT_MESSAGE) {
$("#chat-history").append("<li>"+data.sender+" said: "+data.message+"</li>");
}
else if (data.dataType == websocketGame.LINE_SEGMENT) {
drawLine(ctx, data.startX, data.startY, data.endX, data.endY, 1);
}
};

```

1.  当鼠标移动时，我们不仅在画布上绘制线条，还将线条数据发送到服务器。将以下突出显示的代码添加到鼠标移动事件处理程序中：

```js
$("#drawing-pad").mousemove(function(e) {
// draw lines when is drawing
if (websocketGame.isDrawing) {
// get the mouse x and y relative to the canvas top-left point.
var mouseX = e.layerX || 0;
var mouseY = e.layerY || 0;
if (!(mouseX == websocketGame.startX && mouseY == websocketGame.startY)) {
drawLine(ctx,startX,startY,mouseX,mouseY,1);
// send the line segment to server
var data = {};
data.dataType = websocketGame.LINE_SEGMENT;
data.startX = startX;
data.startY = startY;
data.endX = mouseX;
data.endY = mouseY;
websocketGame.socket.send(JSON.stringify(data));
websocketGame.startX = mouseX;
websocketGame.startY = mouseY;
}
}
});

```

1.  最后，我们需要修改发送消息的逻辑。现在，当将消息发送到服务器时，我们将消息打包成一个对象并格式化为 JSON。将`sendMessage`函数更改为以下代码：

```js
function sendMessage() {
var message = $("#chat-input").val();
// pack the message into an object.
var data = {};
data.dataType = websocketGame.CHAT_MESSAGE;
data.message = message;
websocketGame.socket.send(JSON.stringify(data));
$("#chat-input").val("");
}

```

1.  保存所有文件并重新启动服务器。

1.  在两个浏览器实例中打开`index.htm`文件。

1.  首先，通过输入一些消息并发送它们来尝试聊天室功能。然后，在画布上画一些东西。两个浏览器应该显示与以下截图中相同的绘图：

![通过 WebSockets 发送绘图的时间](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_08_10.jpg)

## 刚刚发生了什么？

我们刚刚构建了一个多用户绘图画板。这类似于我们在本章开头尝试的绘图画板。我们通过发送一个复杂的数据对象作为消息，扩展了构建聊天室时所学到的内容。

## 定义一个数据对象来在客户端和服务器之间通信

为了正确地在服务器和客户端之间传递多个数据，我们必须定义一个数据对象，服务器和客户端都能理解。

数据对象中有几个属性。以下表格列出了这些属性以及我们为什么需要它们：

| 属性名称 | 我们为什么需要这个属性 |
| --- | --- |
| `dataType` | 这是一个重要的属性，帮助我们了解整个数据。数据要么是聊天消息，要么是绘图线段数据。 |
| `sender` | 如果数据是聊天消息，客户端需要知道谁发送了消息。 |
| `message` | 当数据类型是聊天消息时，我们肯定需要将消息内容本身包含到数据对象中。 |
| `startX` | 当数据类型是绘图线段时，我们包含线的起点的 x/y 坐标。 |
| `startY` |   |
| `endX` | 当数据类型是绘图线段时，我们包含线的终点的 x/y 坐标。 |
| `endY` |   |

此外，我们在客户端和服务器端都定义了以下常量。这些常量是用于`dataType`属性的：

```js
// Contants
LINE_SEGMENT : 0,
CHAT_MESSAGE : 1,

```

有了这些常量，我们可以通过以下可读的代码来比较`dataType`，而不是使用无意义的整数：

```js
if (data.dataType == websocketGame.CHAT_MESSAGE) {…}

```

## 将绘图线数据打包成 JSON 进行广播

在上一章中，当将 JavaScript 对象存储到本地存储中时，我们使用了`JSON.stringify`函数将其转换为 JSON 格式的字符串。现在，我们需要在服务器和客户端之间以字符串格式发送数据。我们使用了相同的方法将绘画线条数据打包成对象，并将其作为 JSON 字符串发送。

以下代码片段显示了我们如何在客户端打包线段数据并以 JSON 格式的字符串发送到服务器：

```js
// send the line segment to server
var data = {};
data.dataType = websocketGame.LINE_SEGMENT;
data.startX = startX;
data.startY = startY;
data.endX = mouseX;
data.endY = mouseY;
websocketGame.socket.send(JSON.stringify(data));

```

## 在从其他客户端接收到绘画线条后重新创建它们

JSON 解析通常成对出现，与`stringify`一起使用。当我们从服务器接收到消息时，我们必须将其解析为 JavaScript 对象。以下是客户端上的代码，它解析数据并根据数据更新聊天历史或绘制线条：

```js
var data = JSON.parse(e.data);
if (data.dataType == websocketGame.CHAT_MESSAGE) {
$("#chat-history").append("<li>"+data.sender+" said: "+data.message+"</li>");
}
else if (data.dataType == websocketGame.LINE_SEGMENT) {
drawLine(ctx, data.startX, data.startY, data.endX, data.endY, 1);
}

```

# 构建多人绘画和猜词游戏

在本章的早些时候，我们构建了一个即时聊天室。此外，我们刚刚构建了一个多用户草图本。那么，如何将这两种技术结合起来构建一个绘画和猜词游戏呢？绘画和猜词游戏是一种游戏，其中一个玩家被给予一个词来绘制。所有其他玩家不知道这个词，并根据绘画猜测这个词。绘画者和正确猜测词语的玩家将获得积分。

# 采取行动构建绘画和猜词游戏

我们将按照以下方式实现绘画和猜词游戏的游戏流程：

1.  首先，我们将在客户端添加游戏逻辑。

1.  在客户端目录中打开`index.htm`文件。在*发送*按钮之后添加以下重新启动按钮：

```js
<input type='button' value="Restart" id="restart">

```

1.  打开`html5games.websocket.js` JavaScript 文件。

1.  我们需要一些额外的常量来确定游戏进行过程中的不同状态。将以下突出显示的代码添加到文件顶部：

```js
// Constants
LINE_SEGMENT : 0,
CHAT_MESSAGE : 1,
GAME_LOGIC : 2,
// Constant for game logic state
WAITING_TO_START : 0,
GAME_START : 1,
GAME_OVER : 2,
GAME_RESTART : 3,

```

1.  此外，我们需要一个标志来指示此玩家负责绘制。将以下布尔全局变量添加到代码中：

```js
isTurnToDraw : false,

```

1.  当客户端从服务器接收到消息时，它会解析并检查是否是一条线条绘制的聊天消息。现在我们有另一种处理游戏逻辑的消息类型，名为`GAME_LOGIC`。游戏逻辑消息包含不同的数据，用于不同的游戏状态。将以下代码添加到`onmessage`事件处理程序中：

```js
else if (data.dataType == websocketGame.GAME_LOGIC) {
if (data.gameState == websocketGame.GAME_OVER) {
websocketGame.isTurnToDraw = false;
$("#chat-history").append("<li>"+data.winner+" wins! The answer is '"+data.answer+"'.</li>");
$("#restart").show();
}
if (data.gameState == websocketGame.GAME_START) {
// clear the canvas.
canvas.width = canvas.width;
// hide the restart button.
$("#restart").hide();
// clear the chat history
$("#chat-history").html("");
if (data.isPlayerTurn) {
isTurnToDraw = true;
$("#chat-history").append("<li>Your turn to draw. Please draw '"+data.answer+"'.</li>");
}
else {
$("#chat-history").append("<li>Game Started. Get Ready. You have one minute to guess.</li>");
}
}
}

```

1.  我们已经在客户端添加了游戏逻辑。客户端上有一些包含重新启动逻辑和防止非绘图玩家在画布上绘制的小代码。这些代码可以在代码包中找到。

1.  是时候转向服务器端了。

1.  在先前的示例中，服务器端只负责将任何传入的消息广播给所有连接的浏览器。这对于多人游戏来说是不够的。服务器将充当控制游戏流程和确定胜利的游戏主持人。因此，请删除`server.js`中的现有代码，并使用以下代码。更改部分已经突出显示：

```js
// Constants
var LINE_SEGMENT = 0;
var CHAT_MESSAGE = 1;
var GAME_LOGIC = 2;
// Constant for game logic state
var WAITING_TO_START = 0;
var GAME_START = 1;
var GAME_OVER = 2;
var GAME_RESTART = 3;
var ws = require(__dirname + '/lib/ws/server');
var server = ws.createServer();
// the current turn of player index.
var playerTurn = 0;
var wordsList = ['apple','idea','wisdom','angry'];
var currentAnswer = undefined;
var currentGameState = WAITING_TO_START;
var gameOverTimeout;
server.addListener("connection", function(conn){
// init stuff on connection
console.log("A connection established with id",conn.id);
var message = "Welcome "+conn.id+" joining the party. Total connection:"+server.manager.length;
var data = {};
data.dataType = CHAT_MESSAGE;
data.sender = "Server";
data.message = message;
server.broadcast(JSON.stringify(data));
// send the game state to all players.
var gameLogicData = {};
gameLogicData.dataType = GAME_LOGIC;
gameLogicData.gameState = WAITING_TO_START;
server.broadcast(JSON.stringify(gameLogicData));
// start the game if there are 2 or more connections
if (currentGameState == WAITING_TO_START && server.manager.length >= 2)
{
startGame();
}
// listen to the message
conn.addListener("message", function(message){
console.log("Got data '"+message+"' from connection "+conn.id);
var data = JSON.parse(message);
if (data.dataType == CHAT_MESSAGE)
{
// add the sender information into the message data object.
data.sender = conn.id;
multiplayer draw-and-guess gamemultiplayer draw-and-guess gamebuilding}
server.broadcast(JSON.stringify(data));
// check if the message is guessing right or wrong
if (data.dataType == CHAT_MESSAGE)
{
if (currentGameState == GAME_START && data.message == currentAnswer)
{
var gameLogicData = {};
gameLogicData.dataType = GAME_LOGIC;
gameLogicData.gameState = GAME_OVER;
gameLogicData.winner = conn.id;
gameLogicData.answer = currentAnswer;
server.broadcast(JSON.stringify(gameLogicData));
currentGameState = WAITING_TO_START;
// clear the game over timeout
clearTimeout(gameOverTimeout);
}
}
if (data.dataType == GAME_LOGIC && data.gameState == GAME_RESTART)
{
startGame();
}
});
});
function startGame()
{
// pick a player to draw
playerTurn = (playerTurn+1) % server.manager.length;
// pick an answer
var answerIndex = Math.floor(Math.random() * wordsList.length);
currentAnswer = wordsList[answerIndex];
// game start for all players
multiplayer draw-and-guess gamemultiplayer draw-and-guess gamebuildingvar gameLogicData1 = {};
gameLogicData1.dataType = GAME_LOGIC;
gameLogicData1.gameState = GAME_START;
gameLogicData1.isPlayerTurn = false;
server.broadcast(JSON.stringify(gameLogicData1));
// game start with answer to the player in turn
var index = 0;
server.manager.forEach(function(connection){
if (index == playerTurn)
{
var gameLogicData2 = {};
gameLogicData2.dataType = GAME_LOGIC;
gameLogicData2.gameState = GAME_START;
gameLogicData2.answer = currentAnswer;
gameLogicData2.isPlayerTurn = true;
server.send(connection.id, JSON.stringify(gameLogicData2));
}
index++;
});
// game over the game after 1 minute.
gameOverTimeout = setTimeout(function(){
var gameLogicData = {};
gameLogicData.dataType = GAME_LOGIC;
gameLogicData.gameState = GAME_OVER;
gameLogicData.winner = "No one";
gameLogicData.answer = currentAnswer;
server.broadcast(JSON.stringify(gameLogicData));
currentGameState = WAITING_TO_START;
},60*1000);
currentGameState = GAME_START;
}
server.listen(8000);
console.log("WebSocket server is running.");
console.log("Listening to port 8000.");

```

1.  我们将保存所有文件并重新启动服务器。然后，在两个浏览器实例中启动`index.htm`文件。一个浏览器收到来自服务器的消息，通知玩家绘制某物。另一个浏览器则通知玩家在一分钟内猜测其他人正在绘制什么。

1.  被告知绘制某物的玩家可以在画布上绘制。绘画将广播给其他连接的玩家。被告知猜测的玩家不能在画布上绘制任何东西。相反，玩家在文本字段中输入他们的猜测并发送到服务器。如果猜测正确，则游戏结束。否则，游戏将持续直到一分钟倒计时结束。

![采取行动构建绘画和猜词游戏](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_08_11.jpg)

## 刚刚发生了什么？

我们刚刚在 WebSockets 和 Canvas 中创建了一个多人绘画和猜词游戏。游戏和多用户草图本之间的主要区别在于，服务器现在控制游戏流程，而不是让所有用户绘制。

## 控制多人游戏的游戏流程

控制多人游戏的游戏流程比单人游戏要困难得多。我们可以简单地使用几个变量来控制单人游戏的游戏流程，但是我们必须使用消息传递来通知每个玩家特定的更新游戏流程。

首先，我们需要以下突出显示的常量`GAME_LOGIC`用于`dataType`。我们使用这个`dataType`来发送和接收与游戏逻辑控制相关的消息：

```js
// Constants
var LINE_SEGMENT = 0;
var CHAT_MESSAGE = 1;
var GAME_LOGIC = 2;

```

游戏流程中有几种状态。在游戏开始之前，连接的玩家正在等待游戏开始。一旦有足够的连接进行多人游戏，服务器向所有玩家发送游戏逻辑消息，通知他们开始游戏。

当游戏结束时，服务器向所有玩家发送游戏结束状态。然后，游戏结束，游戏逻辑暂停，直到有玩家点击重新开始按钮。一旦重新开始按钮被点击，客户端向服务器发送游戏重新开始状态，指示服务器准备新游戏。然后，游戏重新开始。

我们在客户端和服务器中将四个游戏状态声明为以下常量，以便它们理解：

```js
// Constant for game logic state
var WAITING_TO_START = 0;
var GAME_START = 1;
var GAME_OVER = 2;
var GAME_RESTART = 3;

```

服务器端的以下代码保存了一个指示哪个玩家轮到的索引：

```js
var playerTurn = 0;

```

发送到玩家（轮到他的回合）的数据与发送到其他玩家的数据不同。其他玩家只收到一个游戏开始信号的数据：

```js
var gameLogicData1 = {};
gameLogicData1.dataType = GAME_LOGIC;
gameLogicData1.gameState = GAME_START;
gameLogicData1.isPlayerTurn = false;

```

另一方面，玩家（轮到他画画）收到以下包含单词信息的数据：

```js
var gameLogicData2 = {};
gameLogicData2.dataType = GAME_LOGIC;
gameLogicData2.gameState = GAME_START;
gameLogicData2.answer = currentAnswer;
gameLogicData2.isPlayerTurn = true;

```

## 在服务器端枚举连接的客户端

我们可以使用`server manager`类中的`forEach`方法枚举所有连接的客户端。以下代码显示了用法。它循环遍历每个连接，并调用给定的`callback`函数，如下所示：

```js
server.manager.forEach(function);

```

例如，以下代码片段在服务器终端上打印所有连接的 ID：

```js
server.manager.forEach(function(connection){
console.log("This is connection",connection.id);
}
}

```

## 在服务器端向特定连接发送消息

在我们之前的示例中，我们使用广播向所有连接的客户端发送消息。除了向每个人发送消息，我们可以使用`send`方法将消息发送到特定的连接，如下所示：

```js
server.send(connectionID, message);

```

`send`方法需要两个参数。`connectionID`是目标连接的唯一 ID，`message`是我们要发送的字符串。

在我们从画画和猜图游戏中提取的以下代码中，我们向现在必须画画的玩家的浏览器发送特殊数据。我们使用`forEach`函数循环遍历连接，并检查连接是否轮到画画。然后，我们打包答案并将这些数据发送给目标连接，如下所示：

```js
server.manager.forEach(function(connection){
if (index == playerTurn)
{
var gameLogicData2 = {};
gameLogicData2.dataType = GAME_LOGIC;
gameLogicData2.gameState = GAME_START;
gameLogicData2.answer = currentAnswer;
gameLogicData2.isPlayerTurn = true;
server.send(connection.id, JSON.stringify(gameLogicData2));
}
index++;
});

```

## 改进游戏

我们刚刚创建了一个可玩的多人游戏。但是，还有很多需要改进的地方。在接下来的几节中，我们列出了游戏中的两个可能的改进。

### 在每个游戏中存储绘制的线条

在游戏中，画画者画线，其他玩家猜图。现在，想象两个玩家在玩，第三个玩家加入。由于没有任何地方存储绘制的线条，第三个玩家无法看到画画者画了什么。这意味着第三个玩家必须等到游戏结束才能玩。

## 尝试一下

我们如何让晚加入的玩家继续游戏而不丢失那些绘制的线条？我们如何为新连接的玩家重建绘图？在服务器上存储当前游戏的所有绘图数据怎么样？

### 改进答案检查机制

服务器端的答案检查与`currentAnswer`变量比较消息，以确定玩家是否猜对。如果情况不匹配，答案将被视为不正确。当答案是“apples”时，玩家猜“apple”时被告知错误，这看起来很奇怪。

## 尝试一下

我们如何改进答案检查机制？如果使用不同的大小写或者相似的单词来改进答案检查逻辑，会怎么样？

# 用 CSS 装饰猜画游戏

游戏逻辑基本上已经完成，游戏已经可以玩了。但是，我们忘记了装饰游戏以使其看起来更吸引人。我们将使用 CSS 样式来装饰我们的猜画游戏。

# 装饰游戏的时间

执行以下步骤：

1.  装饰只适用于客户端。打开`index.htm`文件。

1.  在头部添加以下 CSS 样式链接：

```js
<link href='http://fonts.googleapis.com/css?family=Cabin+Sketch: bold' rel='stylesheet' type='text/css'>
<link rel="stylesheet" type="text/css" media="all" href="css/drawguess.css">

```

1.  将所有标记放在`body`中的`id=game`的`section`内。此外，我们添加了一个游戏的`h1`标题，如下所示：

```js
<section id="game">
<h1>Draw & Guess</h1>
...
</section>

```

1.  在文本字段输入前添加一个**聊天或猜测：**，这样玩家就知道在哪里输入他们的猜测词。

1.  接下来，在`client`文件夹内创建一个名为`css`的目录。

1.  创建一个名为`drawguess.css`的新文件，并将其保存在`css`目录中。

1.  将以下样式放入 CSS 文件中：

```js
body {
background: #ccd6e1;
font-family: 'Cabin Sketch', arial, serif;
}
#game {
width: 500px;
margin: 0 auto;
}
#game h1 {
text-align: center;
margin-bottom: 5px;
text-shadow: 0px 1px 0px #fff;
}
#drawing-pad {
border: 10px solid #fffeff;
background: #f1f3ef;
box-shadow:0px 3px 5px #333;
}
#chat-history {
list-style: none;
padding: 0;
}
#chat-history li {
border-bottom: 1px dashed rgba(20,20,20,.2);
margin: 10px 0;
}

```

1.  保存所有文件，并在两个浏览器中再次打开`index.htm`文件以开始游戏。由于我们只改变了装饰代码，游戏现在应该看起来更好，如下面的截图所示：

![Time for action Decorating the game](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_08_12.jpg)

## 刚刚发生了什么？

我们刚刚为我们的游戏应用了样式，并嵌入了一个来自**Google Font Directory**的字体，看起来像是涂鸦文本。画布现在被设计成更像是一个带有粗边框和微妙阴影的画布。

# 总结

在这一章中，我们学到了很多关于将浏览器连接到 WebSockets 的知识。一个浏览器的消息和事件会几乎实时地广播到另一个浏览器。

具体来说，我们：

+   学会了 WebSockets 如何通过在现有的多人涂鸦板上绘制来提供实时事件。它显示了其他连接用户的绘画。

+   安装了一个带有 WebSocket 库的`Node.js`服务器。通过使用这个服务器，我们可以轻松地构建一个基于事件的服务器来处理来自浏览器的 WebSocket 请求。

+   讨论了服务器和客户端之间的关系。

+   构建了一个即时聊天室应用程序。我们学会了如何实现一个服务器脚本来将传入的消息广播到其他连接的浏览器。我们还学会了如何在客户端上显示从服务器接收到的消息。

+   构建了一个多用户绘图板。我们学会了如何将数据打包成 JSON 格式，以在服务器和浏览器之间传递消息。

+   通过整合聊天和绘图板来构建一个猜画游戏。我们还学会了如何在多人游戏中创建游戏逻辑。

现在我们已经学会了如何构建一个多人游戏，我们准备在下一章中借助物理引擎来构建物理游戏。


# 第九章：使用 Box2D 和 Canvas 构建物理汽车游戏

> 2D 物理引擎是游戏开发中的热门话题。借助物理引擎，我们可以通过定义环境和简单规则轻松创建可玩的游戏。以现有游戏为例，愤怒的小鸟游戏中的玩家将小鸟飞向敌人的城堡以摧毁它。在《切断绳子》中，糖果掉进怪物的嘴里以进入下一关。

在本章中，我们将学习以下主题：

+   安装 Box2D JavaScript 库

+   在物理世界中创建一个静态地面实体

+   在 Canvas 上绘制物理世界

+   在物理世界中创建一个动态方块

+   推进世界时间

+   为游戏添加车轮

+   创建物理汽车

+   通过键盘输入向汽车施加力

+   在 Box2D 世界中检查碰撞

+   重新启动游戏

+   为我们的汽车游戏添加关卡支持

+   用图形替换 Box2D 轮廓绘制

+   添加最后一点以使游戏有趣

以下屏幕截图显示了本章结束时我们将获得的内容。这是一个汽车游戏，玩家将汽车移向目的地点：

![使用 Box2D 和 Canvas 构建物理汽车游戏](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_09_16.jpg)

所以，让我们开始吧。

# 安装 Box2D JavaScript 库

现在，假设我们想创建一个汽车游戏。我们对汽车施加力使其向前移动。汽车在坡道上移动，然后飞过空中。之后，汽车落在目的地坡道上，游戏结束。物理世界的每个部分的每次碰撞都会影响这一运动。如果我们必须从头开始制作这个游戏，那么我们至少要计算每个部分的速度和角度。幸运的是，物理库帮助我们处理所有这些物理问题。我们所要做的就是创建物理模型并在画布中呈现它。

# 行动时间 安装 Box2D 物理库

执行以下步骤：

1.  我们将获得 Box2D JavaScript 库。原始的 Box2D JavaScript 库基于原型 JavaScript 库。原型库提供了类似于 jQuery 的函数，但 API 略有不同。由于 KJ（[`kjam.org/post/105`](http://kjam.org/post/105)）将其移植为适用于 jQuery 的版本，我们可以使用 jQuery 库，而我们的整本书都是基于它的。Box2D 库与起始代码可以在名为`box2d_game`的代码包中找到。

1.  现在，我们应该有以下设置：![行动时间 安装 Box2D 物理库](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_09_17.jpg)

### 提示

我们已经导入了必要的 JavaScript 文件。值得记住的是，如果您以后想使用此基础创建另一个物理游戏，Box2D JS 建议按照完全相同的顺序复制 JavaScript 导入代码，因为文件之间存在依赖关系。

1.  现在，我们将创建一个空世界来测试我们的 Box2D 库安装。打开`html5games.box2dcargame.js` JavaScript 文件，并将以下代码放入文件中以创建世界：

```js
// the global object that contains the variable needed for the car game.
var carGame = {
}
var canvas;
var ctx;
var canvasWidth;
var canvasHeight;
$(function() {
carGame.world = createWorld();
console.log("The world is created. ",carGame.world);
// get the reference of the context
canvas = document.getElementById('game');
ctx = canvas.getContext('2d');
canvasWidth = parseInt(canvas.width);
canvasHeight = parseInt(canvas.height);
});
function createWorld() {
// set the size of the world
var worldAABB = new b2AABB();
worldAABB.minVertex.Set(-4000, -4000);
worldAABB.maxVertex.Set(4000, 4000);
// Define the gravity
var gravity = new b2Vec2(0, 300);
// set to ignore sleeping object
var doSleep = false;
// finally create the world with the size, gravity, and sleep object parameter.
var world = new b2World(worldAABB, gravity, doSleep);
return world;
}

```

1.  在网络浏览器中打开`index.html`文件。我们应该看到一个灰色的画布，什么也没有。

我们还没有在画布中呈现物理世界。这就是为什么我们在页面上只看到一个空白画布。但是，我们已经在控制台日志中打印了新创建的世界。以下屏幕截图显示了控制台跟踪带有许多以`m_`开头的属性的世界对象。这些是世界的物理状态：

![行动时间 安装 Box2D 物理库](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_09_04.jpg)

## 刚刚发生了什么？

我们刚刚安装了 Box2D JavaScript 库，并创建了一个空世界来测试安装。

## 使用 b2World 创建新世界

`b2World`是 Box2D 环境中的核心类。我们所有的物理实体，包括地面和汽车，都是在这个世界中创建的。以下代码显示了如何创建一个世界：

```js
var world = new b2World(worldAABB, gravity, doSleep);

```

`b2World`类需要三个参数来初始化，这些参数在下表中列出并附有描述：

| 参数 | 类型 | 讨论 |
| --- | --- | --- |
| `worldAABB` | b2AABB | 代表世界的边界区域 |
| `gravity` | b2Vec2 | 代表世界的重力 |
| `doSleep` | Bool | 定义世界是否忽略休眠的物体 |

## 使用 b2AABB 定义边界区域

在物理世界中，我们需要很多边界区域。我们需要的第一个边界是世界边界。世界边界内的所有物体都将被计算，而边界外的物体将被销毁。

我们可以将`b2AABB`视为具有最低边界点和最高边界点的矩形。以下代码片段显示了如何使用`b2AABB`类。`minVertex`是边界的左上角点，而`maxVertex`是右下角点。以下世界定义了一个 8000x8000 的世界：

```js
var worldAABB = new b2AABB();
worldAABB.minVertex.Set(-4000, -4000);
worldAABB.maxVertex.Set(4000, 4000);

```

### 注意

Box2D 数学模型中的单位与我们在计算机世界中通常使用的不同。长度单位是米，而不是像素。此外，旋转单位是弧度。

## 设置世界的重力

我们必须定义世界的重力。重力由`b2Vec2`定义。`b2Vec2`是一个 1x2 矩阵的向量。我们可以将其视为 X 和 Y 轴的向量。因此，以下代码定义了向下 300 个单位的重力：

```js
var gravity = new b2Vec2(0, 300);

```

## 设置 Box2D 忽略休眠的物体

休眠的物体是一个不再移动或改变状态的动态物体。

物理库计算世界中所有物体的数学数据和碰撞。当世界中有更多物体需要在每一帧中计算时，性能会变慢。在创建物理世界时，我们需要设置库来忽略休眠的物体或计算所有物体。

在我们的游戏中，只有很少的物体，所以性能还不是问题。此外，如果以后我们创建的物体进入空闲或休眠状态，我们将无法再与它们交互。因此，在本例中，我们将此标志设置为 false。

### 提示

在撰写本书时，只有 Google Chrome 可以在画布中流畅运行 Box2D JavaScript 库。因此，建议在 Google Chrome 中测试游戏，直到其他网络浏览器可以流畅运行为止。

# 在物理世界中创建一个静态地面物体

现在世界是空的。如果我们要放置物体，那些物体将会掉下来，最终离开我们的视线。现在假设我们想在世界中创建一个静态地面物体，以便物体可以站在那里。我们可以在 Box2D 中做到这一点。

# 执行在世界中创建地面的操作

执行以下步骤：

1.  打开`html5games.box2dcargame.js` JavaScript 文件。

1.  将以下函数添加到 JavaScript 文件的末尾。它创建一个固定的物体作为游乐场：

```js
function createGround() {
// box shape definition
var groundSd = new b2BoxDef();
groundSd.extents.Set(250, 25);
groundSd.restitution = 0.4;
// body definition with the given shape we just created.
var groundBd = new b2BodyDef();
groundBd.AddShape(groundSd);
groundBd.position.Set(250, 370);
var body = carGame.world.CreateBody(groundBd);
return body;
}

```

1.  在创建世界后调用`createGround`函数如下：

```js
createGround();

```

1.  由于我们仍在定义逻辑，并且尚未以可视化的方式呈现物理世界，所以如果我们打开浏览器，我们将看不到任何东西。但是，如果有错误消息，尝试并检查控制台窗口是一个好习惯。

## 刚才发生了什么？

我们已经使用形状和物体定义创建了一个地面物体。这是一个我们将经常使用的常见过程，用来在世界中创建不同类型的物体。因此，让我们详细了解一下我们是如何做到的。

## 创建形状

形状定义了几何数据。在 Box2D 的 JavaScript 端口中，形状还定义了密度、摩擦和恢复等材料属性。形状可以是圆形、矩形或多边形。在前面的示例中使用的以下代码定义了一个框形状定义。在框形状中，我们必须通过设置`extents`属性来定义框的大小。`extents`属性接受两个参数：半宽和半高。这是一个半值，因此形状的最终面积是该值的四倍：

```js
// box shape definition
var groundSd = new b2BoxDef();
groundSd.extents.Set(250, 25);
groundSd.restitution = 0.4;

```

## 创建一个物体

在定义形状之后，我们可以使用给定的形状定义创建一个物体定义。然后，我们设置物体的初始位置，最后要求世界实例根据我们的物体定义创建一个物体。下面的代码显示了我们如何在世界中创建一个物体，给定形状定义：

```js
var groundBd = new b2BodyDef();
groundBd.AddShape(groundSd);
groundBd.position.Set(250, 370);
var body = carGame.world.CreateBody(groundBd);

```

没有质量的物体被视为静态物体，或固定物体。这些物体是不可移动的，不会与其他静态物体发生碰撞。因此，这些物体可以用作地面或墙壁，成为关卡环境。另一方面，动态物体将根据重力移动并与其他物体发生碰撞。我们稍后将创建一个动态箱子物体。

# 在画布中绘制物理世界

我们已经创建了一个地面，但它只存在于数学模型中。我们在画布上看不到任何东西，因为我们还没有在上面画任何东西。为了展示物理世界的样子，我们必须根据物理世界画一些东西。

# 行动时间将物理世界绘制到画布中

执行以下步骤：

1.  首先，打开`html5games.box2dcargame.js` JavaScript 文件。

1.  在页面加载事件处理程序中添加`drawWorld`函数调用，如下面的代码所示：

```js
$(function() {
// create the world
carGame.world = createWorld();
// create the ground
createGround();
// get the reference of the context
canvas = document.getElementById('game');
ctx = canvas.getContext('2d');
canvasWidth = parseInt(canvas.width);
canvasHeight = parseInt(canvas.height);
// draw the world
drawWorld(carGame.world, ctx);
});

```

1.  接下来，打开 Box2D JavaScript 示例代码中的`draw_world.js` JavaScript 文件。有两个名为`drawWorld`和`drawShapes`的函数。将下面的整个文件复制到我们的 JavaScript 文件的末尾：

```js
// drawing functions
function drawWorld(world, context) {
for (var b = world.m_bodyList; b != null; b = b.m_next) {
for (var s = b.GetShapeList(); s != null; s = s.GetNext()) {
drawShape(s, context);
}
}
}
// drawShape function directly copy from draw_world.js in Box2dJS library
function drawShape(shape, context) {
physics worldphysics worlddrawing, in canvascontext.strokeStyle = '#003300';
context.beginPath();
switch (shape.m_type) {
case b2Shape.e_circleShape:
var circle = shape;
var pos = circle.m_position;
var r = circle.m_radius;
var segments = 16.0;
var theta = 0.0;
var dtheta = 2.0 * Math.PI / segments;
// draw circle
context.moveTo(pos.x + r, pos.y);
for (var i = 0; i < segments; i++) {
var d = new b2Vec2(r * Math.cos(theta), r * Math.sin(theta));
var v = b2Math.AddVV(pos, d);
context.lineTo(v.x, v.y);
theta += dtheta;
}
context.lineTo(pos.x + r, pos.y);
// draw radius
context.moveTo(pos.x, pos.y);
var ax = circle.m_R.col1;
var pos2 = new b2Vec2(pos.x + r * ax.x, pos.y + r * ax.y);
context.lineTo(pos2.x, pos2.y);
break;
case b2Shape.e_polyShape:
var poly = shape;
var tV = b2Math.AddVV(poly.m_position, b2Math.b2MulMV(poly.m_R, poly.m_vertices[0]));
context.moveTo(tV.x, tV.y);
for (var i = 0; i < poly.m_vertexCount; i++) {
var v = b2Math.AddVV(poly.m_position, b2Math.b2MulMV(poly.m_R, poly.m_vertices[i]));
context.lineTo(v.x, v.y);
}
context.lineTo(tV.x, tV.y);
break;
}
context.stroke();
}

```

1.  现在重新在浏览器中打开游戏，我们应该在画布中看到地面物体的轮廓，如下面的屏幕截图所示：

![行动时间将物理世界绘制到画布中](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_09_05.jpg)

## 刚才发生了什么？

我们刚刚创建了一个函数，用于将世界中的每个形状绘制为带有深绿色轮廓的框。

以下代码显示了我们如何循环遍历世界中的每个形状进行绘制：

```js
function drawWorld(world, context) {
for (var b = world.m_bodyList; b != null; b = b.m_next) {
for (var s = b.GetShapeList(); s != null; s = s.GetNext()) {
drawShape(s, context);
}
}
}

```

### 注意

`drawJoint`函数和 Box2D JS 库中的相关代码也是如此。这个关节绘制函数对于我们的示例来说是可选的。添加关节绘制函数可以让我们看到连接两个物体之间的不可见关节。

现在我们将看一下`drawShape`函数。

在每个形状上，我们想在画布中绘制对象的轮廓。在绘制任何东西之前，我们将线条样式设置为深绿色。然后，我们检查形状是圆形、矩形框还是多边形。如果是圆形，我们就使用极坐标来绘制给定形状的半径的圆。如果是多边形，我们就按照以下方式绘制多边形的每一条边：

```js
function drawShape(shape, context) {
context.strokeStyle = '#003300';
context.beginPath();
switch (shape.m_type) {
case b2Shape.e_circleShape:
// Draw the circle in canvas bases on the physics object shape
break;
case b2Shape.e_polyShape:
// Draw the polygon in canvas bases on the physics object shape
break;
}
context.stroke();
}

```

# 在物理世界中创建一个动态框

现在想象我们把一个箱子放入世界中。箱子从空中掉下来，最后撞到地面。箱子会弹起一点，最后停在地面上。这与我们在上一节中创建的不同。在上一节中，我们创建了一个静态地面，它是不可移动的，不会受到重力的影响。现在我们将创建一个动态框。

# 行动时间将动态框放入世界中

执行以下步骤：

1.  打开我们的 JavaScript 逻辑文件，并将以下框创建代码添加到页面加载事件处理程序中。将代码放在`createGround`函数之后：

```js
// create a box
var boxSd = new b2BoxDef();
boxSd.density = 1.0;
boxSd.friction = 1.5;
boxSd.restitution = .4;
boxSd.extents.Set(40, 20);
var boxBd = new b2BodyDef();
boxBd.AddShape(boxSd);
boxBd.position.Set(50,210);
carGame.world.CreateBody(boxBd);

```

1.  现在我们将在浏览器中测试物理世界。我们应该看到一个箱子被创建在给定的初始位置。然而，箱子并没有掉下来；这是因为我们还有一些事情要做才能让它掉下来：

![行动时间将动态框放入世界中](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_09_06.jpg)

## 刚才发生了什么？

我们刚刚在世界中创建了一个动态物体。与不可移动的地面物体相比，这个箱子受到重力的影响，并且在碰撞过程中速度会发生变化。当一个物体包含有质量或密度的形状时，它是一个动态物体。否则，它是静态的。因此，我们为我们的箱子定义了一个密度。Box2D 会使它成为动态的，并根据密度和物体的大小自动计算质量。

## 使用恢复属性设置弹跳效果

恢复值在 0 和 1 之间。在我们的情况下，箱子掉在地面上。当地面和箱子的恢复值都为 0 时，箱子根本不会弹跳。当箱子或地面中的一个恢复值为 1 时，碰撞是完全弹性的。

### 提示

当两个物体发生碰撞时，碰撞的恢复值是两个物体的恢复值中的最大值。因此，如果一个恢复值为 0.4 的箱子掉在恢复值为 0.6 的地面上，这次碰撞会使用 0.6 来计算弹跳速度。

# 推进世界时间

箱子是动态的，但它不会掉下来。我们做错了什么吗？答案是否定的。我们已经正确设置了箱子，但是忘记在物理世界中推进时间。

在 Box2D 物理世界中，所有计算都是按照系统化的迭代进行的。世界根据当前步骤计算所有事物的物理变换。当我们将“步骤”移动到下一个级别时，世界会根据新状态再次进行计算。

# 进行操作 设置世界步骤循环

我们将通过以下步骤推进世界时间：

1.  为了推进世界步骤，我们必须定期调用世界实例中的`step`函数。我们使用`setTimeout`来不断调用`step`函数。将以下函数放入我们的 JavaScript 逻辑文件中：

```js
function step() {
world.Step(1.0/60, 1);
ctx.clearRect(0, 0, canvasWidth, canvasHeight);
drawWorld(carGame.world, ctx);
setTimeout(step, 10);
}

```

1.  接下来，我们将通过在文档准备好的事件处理程序中调用第一个`step`函数来启动世界。将以下突出显示的代码添加到加载处理程序函数中：

```js
$(function() {
…
// start advancing the step
step();
});

```

1.  我们将在浏览器中再次模拟世界。箱子被创建在初始化位置并正确地落在地面上。以下截图显示了箱子落在地面上的顺序：

![进行操作 设置世界步骤循环](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_09_07.jpg)

## 刚才发生了什么？

我们已经推进了世界的时间。现在物理库每 10 毫秒模拟一次世界。

`step`函数类似于我们在*第二章，使用基于 DOM 的游戏开发入门*中的`gameloop`函数。它定期执行以计算游戏的新状态。

# 为游戏添加车轮

现在我们在游戏中有一个箱子。现在想象我们创建两个圆形的车轮。然后，我们将拥有汽车的基本组件，车身和车轮。

# 进行操作 将两个圆放入世界中

我们将通过以下步骤向世界中添加两个圆：

1.  打开`html5games.box2dcargame.js` JavaScript 文件以添加车轮物体。

1.  在箱子创建代码之后添加以下代码。它调用了我们将编写的`createWheel`函数来创建一个圆形的物体：

```js
// create two wheels in the world
createWheel(carGame.world, 25, 230);
createWheel(carGame.world, 75, 230);

```

1.  现在让我们来处理`createWheel`函数。我们设计这个函数在给定的世界中以给定的 x 和 y 坐标创建一个圆形的物体。将以下函数放入我们的 JavaScript 逻辑文件中：

```js
function createWheel(world, x, y) {
// wheel circle definition
var ballSd = new b2CircleDef();
ballSd.density = 1.0;
ballSd.radius = 10;
ballSd.restitution = 0.1;
ballSd.friction = 4.3;
// body definition
var ballBd = new b2BodyDef();
ballBd.AddShape(ballSd);
ballBd.position.Set(x,y);
return world.CreateBody(ballBd);
}

```

1.  现在我们将在 Web 浏览器中重新加载物理世界。这次，我们应该看到类似以下截图的结果，其中有一个箱子和两个车轮从空中掉下来。这些物体与其他物体碰撞并在撞到墙壁时弹开：

![进行操作 将两个圆放入世界中](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_09_08.jpg)

## 刚才发生了什么？

在模拟物理世界时，箱子和车轮都会掉下来并相互碰撞以及与地面碰撞。

创建圆形物体类似于创建方形物体。唯一的区别是我们使用`CircleDef`类而不是方形形状定义。在圆形定义中，我们使用`radius`属性而不是`extents`属性来定义圆的大小。

# 创建一个物理汽车

我们已经准备好了汽车箱体和两个轮子箱体。我们离制作汽车只差一步。现在想象我们有一种胶水可以把车轮粘在车身上。然后，汽车和轮子就不会再分开，我们就会有一辆车。我们可以使用**关节**来实现这一点。在本节中，我们将使用`joint`将车轮和车身粘在一起。

# 执行连接框和两个圆的旋转关节的操作的时间

执行以下步骤：

1.  我们仍然只在逻辑部分工作。在文本编辑器中打开我们的 JavaScript 逻辑文件。

1.  在文档顶部添加以下全局变量，以引用汽车车身：

```js
var car;

```

1.  创建一个名为`createCarAt`的函数，它接受坐标作为参数。然后，我们将身体和轮子创建代码移到这个函数中。然后，添加以下突出显示的关节创建代码。最后，返回汽车车身：

```js
function createCarAt(x, y) {
// the car box definition
var boxSd = new b2BoxDef();
boxSd.density = 1.0;
boxSd.friction = 1.5;
boxSd.restitution = .4;
boxSd.extents.Set(40, 20);
// the car body definition
var boxBd = new b2BodyDef();
boxBd.AddShape(boxSd);
boxBd.position.Set(x,y);
var carBody = carGame.world.CreateBody(boxBd);
// creating the wheels
var wheelBody1 = createWheel(carGame.world, x-25, y+20);
var wheelBody2 = createWheel(carGame.world, x+25, y+20);
// create a joint to connect left wheel with the car body
var jointDef = new b2RevoluteJointDef();
jointDef.anchorPoint.Set(x-25, y+20);
jointDef.body1 = carBody;
jointDef.body2 = wheelBody1;
carGame.world.CreateJoint(jointDef);
// create a joint to connect right wheel with the car body
var jointDef = new b2RevoluteJointDef();
jointDef.anchorPoint.Set(x+25, y+20);
jointDef.body1 = carBody;
jointDef.body2 = wheelBody2;
carGame.world.CreateJoint(jointDef);
return carBody;
}

```

1.  然后，我们只需要创建一个具有初始位置的汽车。在创建世界之后，将以下代码添加到页面加载事件处理程序中：

```js
// create a car
car = createCarAt(50, 210);

```

1.  是时候保存文件并在浏览器中运行物理世界了。此时，车轮和车身不是分开的部分。它们像一辆车一样粘在一起，正确地掉在地面上，如下面的截图所示：

![执行连接框和两个圆的旋转关节的操作的时间](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_09_09.jpg)

## 刚才发生了什么？

关节对于在两个身体之间（或者在一个身体和世界之间）添加约束很有用。有许多种类型的关节，我们在这个例子中使用的是**旋转关节**。

## 使用旋转关节在两个身体之间创建一个锚点

旋转关节使用一个公共锚点将两个身体粘在一起。然后，这两个身体被粘在一起，只允许基于公共锚点旋转。下面截图的左侧显示了两个身体是如何连接的。在我们的代码示例中，我们将锚点设置为轮子的中心点。下面截图的右侧显示了我们如何设置关节。轮子因为旋转原点在中心而旋转。这种设置使得汽车和轮子看起来很真实：

![使用旋转关节在两个身体之间创建一个锚点](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_09_10.jpg)

还有其他类型的关节，它们以不同的方式很有用。关节在创建游戏环境中很有用，因为有几种类型的关节，每种关节类型都值得一试，你应该考虑如何使用它们。以下链接是 Box2D 手册，解释了每种类型的关节以及我们如何在不同的环境设置中使用它们：

[`www.box2d.org/manual.html#_Toc258082974`](http://www.box2d.org/manual.html#_Toc258082974)

# 通过键盘输入对汽车施加力

现在我们已经准备好了汽车。让我们用键盘移动它。

# 执行对汽车施加力的操作

执行以下步骤：

1.  在文本编辑器中打开`html5games.box2dcargame.js` JavaScript 文件。

1.  在页面加载事件处理程序中，我们在开头添加了以下`keydown`事件处理程序。它监听**X**键和**Z**键以在不同方向施加力：

```js
// Keyboard event
$(document).keydown(function(e) {
switch(e.keyCode) {
case 88: // x key to apply force towards right
var force = new b2Vec2(10000000, 0);
carGame.car.ApplyForce (force, carGame.car.GetCenterPosition());
break;
case 90: // z key to apply force towards left
var force = new b2Vec2(-10000000, 0);
carGame.car.ApplyForce (force, carGame.car.GetCenterPosition());
break;
}
});

```

1.  就是这样。保存文件并在浏览器中运行我们的游戏。当你按下**X**或**Z**键时，汽车就会开始移动。如果你一直按着键，世界就会不断给汽车施加力量，让它飞走：

![执行对汽车施加力的操作的时间](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_09_11.jpg)

## 刚才发生了什么？

我们刚刚创建了与我们的汽车车身的交互。我们可以通过按下**Z**和**X**键来左右移动汽车。现在游戏似乎变得有趣起来了。

## 对身体施加力

我们可以通过调用`ApplyForce`函数向任何身体施加力。以下代码显示了该函数的用法：

```js
body.ApplyForce(force, point);

```

这个函数接受两个参数，列在下表中：

| 参数 | 类型 | 讨论 |
| --- | --- | --- |
| `force` | `b2Vec2` | 要施加到物体上的力向量 |
| `point` | `b2Vec2` | 施加力的点 |

## 理解 ApplyForce 和 ApplyImpulse 之间的区别

除了`ApplyForce`函数，我们还可以使用`ApplyImpulse`函数移动任何物体。这两个函数都可以移动物体，但它们的移动方式不同。如果我们想改变物体的瞬时速度，那么我们可以在物体上使用`ApplyImpulse`一次，将速度改变为目标值。另一方面，我们需要不断地对物体施加力以增加速度。

例如，我们想要增加汽车的速度，就像踩油门一样。在这种情况下，我们对汽车施加力。如果我们正在创建一个需要启动球的球类游戏，我们可以使用`ApplyImpulse`函数向球体添加一个瞬时冲量。

## 试一试吧

你能想到另一种情况吗，我们需要对物体施加力或冲量吗？

## 向我们的游戏环境添加坡道

现在我们可以移动汽车。然而，环境还不够有趣。现在想象一下，有一些坡道供汽车跳跃，两个平台之间有一个间隙，玩家必须飞过汽车。使用不同的坡道设置玩起来会更有趣。

# 时间行动 创建具有坡道的世界

执行以下步骤：

1.  我们将打开游戏逻辑 JavaScript 文件。

1.  将当前的地面创建代码移入一个名为`createGround`的新函数中。然后，更改代码以使用给定的四个参数，如下所示：

```js
function createGround(x, y, width, height, rotation) {
// box shape definition
var groundSd = new b2BoxDef();
groundSd.extents.Set(width, height);
groundSd.restitution = 0.4;
// body definition with the given shape we just created.
var groundBd = new b2BodyDef();
groundBd.AddShape(groundSd);
groundBd.position.Set(x, y);
groundBd.rotation = rotation * Math.PI / 180;
var body = carGame.world.CreateBody(groundBd);
return body;
}

```

1.  现在我们有一个创建地面物体的函数。我们将用以下代码替换页面加载处理程序函数中的地面创建代码：

```js
// create the ground
createGround(250, 270, 250, 25, 0);
// create a ramp
createGround(500, 250, 65, 15, -10);
createGround(600, 225, 80, 15, -20);
createGround(1100, 250, 100, 15, 0);

```

1.  保存文件并在浏览器中预览游戏。我们应该看到一个坡道和一个目的地平台，如下截图所示。尝试控制汽车，跳过坡道，到达目的地而不掉下来。如果失败，刷新页面重新开始游戏：

![时间行动 创建具有坡道的世界](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_09_12.jpg)

## 刚才发生了什么？

我们刚刚将地面箱子创建代码封装到一个函数中，这样我们就可以轻松地创建一组地面物体。这些地面物体构成了游戏的级别环境。

此外，这是我们第一次旋转物体。我们使用`rotation`属性设置物体的旋转，该属性以弧度值为参数。大多数人可能习惯于度单位；我们可以使用以下公式从度获取弧度值：

```js
groundBd.rotation = degree * Math.PI / 180;

```

通过设置箱子的旋转，我们可以在游戏中设置不同坡度的坡道。

## 试一试吧 创建具有不同连接器的不同环境

现在我们已经设置了一个坡道，并且可以在环境中玩汽车。如何使用不同类型的连接器来设置游乐场？例如，使用滑轮连接器作为升降机怎么样？另一方面，包括一个带有中心连接器的动态板怎么样？

# 在 Box2D 世界中检查碰撞

Box2D 物理库会自动计算所有碰撞。现在想象一下，我们设置了一个地面物体作为目的地。玩家成功将汽车移动到目的地时获胜。由于 Box2D 已经计算了所有碰撞，我们所要做的就是获取检测到的碰撞列表，并确定我们的汽车是否撞到了目的地地面。

# 时间行动 检查汽车和目的地物体之间的碰撞

执行以下步骤：

1.  同样，我们从游戏逻辑开始。在文本编辑器中打开`html5games.box2dcargame.js` JavaScript 文件。

1.  我们在地面创建代码中设置了一个目标地面，并将其分配给`carGame`全局对象实例内的`gamewinWall`引用，如下所示：

```js
carGame.gamewinWall = createGround(1200, 215, 15, 25, 0);

```

1.  接下来，我们转向`step`函数。在每一步中，我们从世界中获取完整的接触列表，并检查是否有任何两个相互碰撞的对象是汽车和目标地面：

```js
function step() {
carGame.world.Step(1.0/60, 1);
ctx.clearRect(0, 0, canvasWidth, canvasHeight);
drawWorld(carGame.world, ctx);
setTimeout(step, 10);
//loop all contact list to check if the car hits the winning wall
for (var cn = carGame.world.GetContactList(); cn != null; cn = cn.GetNext()) {
var body1 = cn.GetShape1().GetBody();
var body2 = cn.GetShape2().GetBody();
if ((body1 == carGame.car && body2 == carGame.gamewinWall) ||
(body2 == carGame.car && body1 == carGame.gamewinWall))
{
console.log("Level Passed!");
}
}
}

```

1.  现在保存代码并再次在浏览器中打开游戏。这一次，我们必须打开控制台窗口，以跟踪当汽车撞到墙时是否获得**Level Passed!**输出。尝试完成游戏，我们应该在汽车到达目的地后在控制台中看到输出：

![执行检查汽车和目的地物体之间的碰撞](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_09_13.jpg)

## 刚刚发生了什么？

我们刚刚通过检查碰撞联系人创建了游戏获胜逻辑。当汽车成功到达目的地地面物体时，玩家获胜。

## 获取碰撞联系人列表

在每个步骤中，Box2D 计算所有碰撞并将它们放入`world`实例中的**contact list**中。我们可以使用`carGame.world.GetContactList()`函数获取联系人列表。返回的联系人列表是一个**链接列表**。我们可以通过以下 for 循环遍历整个链接列表：

```js
for (var cn = carGame.world.GetContactList(); cn != null; cn = cn.GetNext()) {
// We have shape 1 and shape 2 of each contact node.
// cn.GetShape1();
// cn.GetShape2();
}

```

当我们获得碰撞的形状时，我们检查该形状的主体是否是汽车或目的地主体。由于汽车形状可能在形状 1 或形状 2 中，`gamewinWall`也是如此，我们使用以下代码来检查两种组合：

```js
var body1 = cn.GetShape1().GetBody();
var body2 = cn.GetShape2().GetBody();
if ((body1 == carGame.car && body2 == carGame.gamewinWall) ||
(body2 == carGame.car && body1 == carGame.gamewinWall))
{
console.log("Level Passed!");
}

```

## 试试看英雄

我们在*第七章，使用本地存储存储游戏数据*中创建了一个游戏结束对话框。在这里使用该技术创建一个对话框，显示玩家通过了级别，怎么样？当我们向游戏添加不同的级别设置时，它也将作为级别过渡的工具。

# 重新开始游戏

您可能已经尝试在上一个示例中多次刷新页面，以使汽车成功跳到目的地。现在想象一下，我们可以按键重新初始化世界。然后，我们可以按照试错的方法直到成功。

# 按下 R 键重新启动游戏的时间

我们将**R**键指定为游戏的重新启动键：

1.  再次，我们只需要更改 JavaScript 文件。在文本编辑器中打开`html5games.box2dcargame.js` JavaScript 文件。

1.  我们将创建世界、坡道和汽车代码移入名为`restartGame`的函数中。它们最初位于页面加载处理程序函数中：

```js
function restartGame() {
// create the world
carGame.world = createWorld();
// create the ground
createGround(250, 270, 250, 25, 0);
// create a ramp
createGround(500, 250, 65, 15, -10);
createGround(600, 225, 80, 15, -20);
createGround(1100, 250, 100, 15, 0);
// create a destination ground
carGame.gamewinWall = createGround(1200, 215, 15, 25, 0);
// create a car
carGame.car = createCarAt(50, 210);
}

```

1.  然后，在页面加载事件处理程序中，我们调用`restartGame`函数来初始化游戏，如下所示：

```js
restartGame();

```

1.  最后，我们将以下突出显示的代码添加到`keydown`处理程序中，以在按下**R**键时重新启动游戏：

```js
$(document).keydown(function(e) {
switch(e.keyCode) {
case 88: // x key to apply force towards right
var force = new b2Vec2(10000000, 0);
carGame.car.ApplyForce (force, carGame.car.GetCenterPosition());
break;
case 90: // z key to apply force towards left
var force = new b2Vec2(-10000000, 0);
carGame.car.ApplyForce (force, carGame.car.GetCenterPosition());
break;
case 82: // r key to restart the game
restartGame();
break;
}
});

```

1.  当玩家通过级别时，怎么样重新开始游戏？将以下突出显示的代码添加到游戏获胜逻辑中：

```js
if ((cn.GetShape1().GetBody() == carGame.car && cn.GetShape2().GetBody() == carGame.gamewinWall) ||
(cn.GetShape2().GetBody() == carGame.car && cn.GetShape1().GetBody() == carGame.gamewinWall))
{
console.log("Level Passed!");
restartGame();
}

```

1.  现在是时候在浏览器中测试游戏了。尝试玩游戏并按**R**键重新启动游戏。

## 刚刚发生了什么？

我们重构我们的代码来创建一个`restartGame`函数。每次调用此函数时，世界都会被销毁并重新初始化。我们可以通过创建我们的世界变量的新世界实例来销毁现有世界并创建一个新的空世界，如下所示：

```js
carGame.world = createWorld();

```

## 试试看英雄 创建游戏结束墙

现在重新启动游戏的唯一方法是按重新启动键。在世界底部创建一个地面，检查任何下落的汽车怎么样？当汽车掉落并撞到底部地面时，我们知道玩家失败了，然后重新开始游戏。

# 为我们的汽车游戏添加级别支持

现在想象一下，当完成每个游戏时，我们可以升级到下一个环境设置。对于每个级别，我们将需要几个环境设置。

# 加载具有级别数据的游戏的时间

我们将重构我们的代码以支持从级别数据结构加载静态地面物体。让我们通过以下步骤来完成它：

1.  在文本编辑器中打开`html5games.box2dcargame.js` JavaScript 文件。

1.  我们将需要每个级别的地面设置。将以下代码放在 JavaScript 文件的顶部。这是一个级别数组。每个级别都是另一个对象数组，其中包含静态地面物体的位置、尺寸和旋转：

```js
carGame.levels = new Array();
carGame.levels[0] = [{"type":"car","x":50,"y":210,"fuel":20},
{"type":"box","x":250, "y":270, "width":250, "height":25, "rotation":0},
{"type":"box","x":500,"y":250,"width":65,"height":15, "rotation":-10},
{"type":"box","x":600,"y":225,"width":80,"height":15, "rotation":-20},
{"type":"box","x":950,"y":225,"width":80,"height":15, "rotation":20},
{"type":"box","x":1100,"y":250,"width":100,"height":15, "rotation":0},
{"type":"box","x":1100,"y":250,"width":100,"height":15, "rotation":0},
{"type":"win","x":1200,"y":215,"width":15,"height":25, "rotation":0}];
carGame.levels[1] = [{"type":"car","x":50,"y":210,"fuel":20},
{"type":"box","x":100, "y":270, "width":190, "height":15, "rotation":20},
{"type":"box","x":380, "y":320, "width":100, "height":15, "rotation":-10},
{"type":"box","x":666,"y":285,"width":80,"height":15, "rotation":-32},
{"type":"box","x":950,"y":295,"width":80,"height":15, "rotation":20},
{"type":"box","x":1100,"y":310,"width":100,"height":15, "rotation":0},
{"type":"win","x":1200,"y":275,"width":15,"height":25, "rotation":0}];
car gamecar gamelevels data, loadingcarGame.levels[2] = [{"type":"car","x":50,"y":210,"fuel":20},
{"type":"box","x":100, "y":270, "width":190, "height":15, "rotation":20},
{"type":"box","x":380, "y":320, "width":100, "height":15, "rotation":-10},
{"type":"box","x":686,"y":285,"width":80,"height":15, "rotation":-32},
{"type":"box","x":250,"y":495,"width":80,"height":15, "rotation":40},
{"type":"box","x":500,"y":540,"width":200,"height":15, "rotation":0},
{"type":"win","x":220,"y":425,"width":15,"height":25, "rotation":23}];

```

1.  然后，我们使用`carGame`对象实例中的以下变量来存储当前级别：

```js
var carGame = {
currentLevel: 0
}

```

1.  用以下代码替换`restartGame`函数。它将函数更改为接受一个`level`参数。然后，根据关卡数据创建地面或汽车：

```js
function restartGame(level) {
carGame.currentLevel = level;
// create the world
carGame.world = createWorld();
// create a ground in our newly created world
// load the ground info from level data
for(var i=0;i<carGame.levels[level].length;i++) {
var obj = carGame.levels[level][i];
// create car
if (obj.type == "car") {
carGame.car = createCarAt(obj.x,obj.y);
continue;
}
var groundBody = createGround(obj.x, obj.y, obj.width, obj.height, obj.rotation);
if (obj.type == "win") {
carGame.gamewinWall = groundBody;
}
}
}

```

1.  在页面加载处理程序函数中，我们通过提供`currentLevel`来更改`restartGame`函数的调用：

```js
restartGame(carGame.currentLevel);

```

1.  我们还需要在重启键处理程序中提供`currentLevel`值：

```js
case 82: // r key to restart the game
restartGame(carGame.currentLevel);
break;

```

1.  最后，在游戏获胜逻辑中更改以下突出显示的代码。当汽车撞到目的地时，我们升级游戏：

```js
if ((body1 == carGame.car && body2 == carGame.gamewinWall) ||
(body2 == carGame.car && body1 == carGame.gamewinWall))
{
console.log("Level Passed!");
restartGame(carGame.currentLevel+1);
}

```

1.  我们现在将在 Web 浏览器中运行游戏。完成关卡后，游戏应该重新开始下一关：

![Time for action Loading game with levels data](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_09_14.jpg)

## 刚刚发生了什么？

我们刚刚创建了一个数据结构来存储关卡。然后，我们根据给定的关卡号创建了游戏，并使用关卡数据构建了世界。

每个关卡数据都是一个对象数组。每个对象包含世界中每个地面物体的属性。这包括基本属性，如位置、大小和旋转。还有一个名为`type`的属性。它定义了物体是普通的箱子物体、汽车数据，还是获胜的目的地地面：

```js
carGame.levels[0] = [{"type":"car","x":50,"y":210,"fuel":20},
{"type":"box","x":250, "y":270, "width":250, "height":25, "rotation":0},
{"type":"box","x":500,"y":250,"width":65,"height":15,"rotation":-10},
{"type":"box","x":600,"y":225,"width":80,"height":15,"rotation":-20},
{"type":"box","x":950,"y":225,"width":80,"height":15,"rotation":20},
{"type":"box","x":1100,"y":250,"width":100,"height":15,"rotation":0},
{"type":"win","x":1200,"y":215,"width":15,"height":25,"rotation":0}];

```

在创建世界时，我们使用以下代码循环遍历关卡数组中的所有对象。然后根据类型创建汽车和地面物体，并引用游戏获胜的地面：

```js
for(var i=0;i<carGame.levels[level].length;i++) {
var obj = carGame.levels[level][i];
// create car
if (obj.type == "car") {
carGame.car = createCarAt(obj.x,obj.y);
continue;
}
var groundBody = createGround(obj.x, obj.y, obj.width, obj.height, obj.rotation);
if (obj.type == "win") {
carGame.gamewinWall = groundBody;
car gamecar gamelevels data, loading}
}

```

## 尝试创建更多关卡

现在我们已经为游戏设置了几个关卡。如何复制关卡数据以创建更有趣的关卡来玩？创建你自己的关卡并玩耍。就像一个孩子搭积木玩一样。

# 用图形替换 Box2D 轮廓绘图

我们已经创建了一个至少可以玩几个关卡的游戏。然而，它们只是一些轮廓框。我们甚至无法区分游戏中的目的地和其他地面物体。现在想象一下，目的地是一个赛车旗，有一辆汽车图形来代表它。这将使游戏目的更加清晰。

# 添加旗帜图形和汽车图形到游戏

执行以下步骤：

1.  首先，我们需要下载这个示例所需的图形。转到以下链接下载图形：

[`gamedesign.cc/html5games/1260_09_example_graphics.zip`](http://gamedesign.cc/html5games/1260_09_example_graphics.zip )

1.  在`images`文件夹中提取 ZIP 文件。

1.  现在是时候编辑`index.htm`文件了。在 body 中添加以下 HTML 标记：

```js
<div id="asset">
<img id="flag" src='images/flag.png'>
<img id="bus" src="img/bus.png">
<img id="wheel" src="img/wheel.png">
</div>

```

1.  我们想要隐藏包含我们`img`标签的资产 DIV。打开`cargame.css`文件，并添加以下 CSS 规则以使资产 DIV 不可见：

```js
#asset {
position: absolute;
top: -99999px;
}

```

1.  现在我们将进入逻辑部分。打开`html5games.box2dcargame.js` JavaScript 文件。

1.  在`createGround`函数中，我们添加一个名为`type`的新参数以传递类型。然后，如果是获胜的目的地地面，我们添加了突出显示的代码来分配`flag`图像的引用给地面形状的用户数据：

```js
function createGround(x, y, width, height, rotation, type) {
// box shape definition
var groundSd = new b2BoxDef();
groundSd.extents.Set(width, height);
groundSd.restitution = 0.4;
if (type == "win") {
groundSd.userData = document.getElementById('flag');
}
…
}

```

1.  在创建地面时，现在需要传递`type`属性。用以下代码替换地面创建代码：

```js
var groundBody = createGround(obj.x, obj.y, obj.width, obj.height, obj.rotation, obj.type);

```

1.  接下来，我们将`bus`图像标签的引用分配给汽车形状的用户数据。将以下突出显示的代码添加到汽车框定义创建中：

```js
// the car box definition
var boxSd = new b2BoxDef();
boxSd.density = 1.0;
boxSd.friction = 1.5;
boxSd.restitution = .4;
boxSd.extents.Set(40, 20);
boxSd.userData = document.getElementById('bus');

```

我们曾经通过 jQuery 的`$(selector)`方法获取元素的引用。jQuery 选择器返回一个带有额外 jQuery 数据包装的元素对象数组。如果我们想要获取原始文档元素引用，那么我们可以使用`document.getElementById`方法或`$(selector).get(0)`。由于`$(selector)`返回一个数组，`get(0)`给出列表中的第一个原始文档元素

1.  然后，我们需要处理车轮。我们将`wheel`图像标签分配给车轮的`userData`属性。将以下突出显示的代码添加到`createWheel`函数中：

```js
function createWheel(world, x, y) {
// wheel circle definition
var ballSd = new b2CircleDef();
ballSd.density = 1.0;
ballSd.radius = 10;
ballSd.restitution = 0.1;
ballSd.friction = 4.3;
ballSd.userData = document.getElementById('wheel');
…
}

```

1.  最后，我们必须在画布中绘制图像。用以下代码替换`drawWorld`函数。突出显示的代码是更改的部分：

```js
function drawWorld(world, context) {
for (var b = world.m_bodyList; b != null; b = b.m_next) {
for (var s = b.GetShapeList(); s != null; s = s.GetNext()) {
if (s.GetUserData() != undefined) {
// the user data contains the reference to the image
var img = s.GetUserData();
// the x and y of the image.
// We have to substract the half width/height
var x = s.GetPosition().x;
var y = s.GetPosition().y;
var topleftX = - $(img).width()/2;
var topleftY = - $(img).height()/2;
context.save();
context.translate(x,y);
context.rotate(s.GetBody().GetRotation());
context.drawImage(img, topleftX, topleftY);
context.restore();
} else {
drawShape(s, context);
}
}
}
}

```

1.  最后，保存所有文件并在 Web 浏览器中运行游戏。我们应该看到一个黄色的公共汽车图形，两个车轮和一个旗帜作为目的地。现在玩游戏，当公共汽车撞到旗帜时游戏应该进入下一关：

![Time for action Adding a flag graphic and a car graphic to the game](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_09_15.jpg)

## 刚才发生了什么？

我们现在以最少的图形呈现我们的游戏。至少，玩家可以轻松知道他们在控制什么，以及他们应该去哪里。

Box2D 库使用画布来渲染物理世界。因此，我们学到的所有关于画布的技术都可以应用在这里。在*第五章，构建*一个*Canvas Games Masterclass*中，我们学习了使用`drawImage`函数在画布中显示图像。我们使用这种技术在物理世界的画布上绘制旗帜图形。

## 在形状和物体中使用 userData

我们如何知道哪个物理体需要显示为旗帜图像？每个 Box2D 形状和物体中都有一个名为`userData`的属性。此属性用于存储与该形状或物体相关的任何自定义数据。例如，我们可以存储图形文件的文件名，或者直接存储图像标签的引用。

我们有一个图像标签列表，引用了游戏中需要的图形资源。然而，我们不想显示这些图像标签，它们只是用于加载和引用。我们通过以下 CSS 样式将这些资源图像标签隐藏在 HTML 边界之外。我们不使用`display:none`，因为我们无法获取根本没有显示的元素的宽度和高度。我们需要宽度和高度来正确定位物理世界中的图形：

```js
#asset {
position: absolute;
top: -99999px;
}

```

## 根据其物理体的状态在每帧绘制图形

从 Box2D 绘制只是用于开发，然后我们用我们的图形替换它。

以下代码检查形状是否分配了用户数据。在我们的示例中，用户数据用于引用该图形资源的`image`标签。我们获取图像标签并将其传递给画布上下文的`drawImage`函数进行绘制。

Box2D 中的所有盒形和圆形形状的原点都在中心。然而，在画布中绘制图像需要左上角点。因此，我们有 x/y 坐标和左上角 x/y 点的偏移量，这是图像宽度和高度的负一半：

```js
if (s.GetUserData() != undefined) {
// the user data contains the reference to the image
var img = s.GetUserData();
// the x and y of the image.
// We have to substract the half width/height
var x = s.GetPosition().x;
var y = s.GetPosition().y;
var topleftX = - $(img).width()/2;
var topleftY = - $(img).height()/2;
context.save();
context.translate(x,y);
context.rotate(s.GetBody().GetRotation());
context.drawImage(img, topleftX, topleftY);
context.restore();
}

```

## 在画布中旋转和平移图像

我们使用`drawImage`函数直接绘制图像与坐标。然而，在这里情况不同。我们需要旋转绘制的图像。这是通过在绘制之前旋转上下文，然后在绘制后恢复旋转来完成的。我们可以通过保存上下文状态，平移它，旋转它，然后调用`restore`函数来实现这一点。以下代码显示了我们如何在给定位置和旋转角度绘制图像。`topleftX`和`topleftY`是从图像中心原点到左上角点的偏移距离：

```js
context.save();
context.translate(x,y);
context.rotate(s.GetBody().GetRotation());
context.drawImage(img, topleftX, topleftY);
context.restore();

```

### 提示

我们不需要使物理体积与其图形完全相同。例如，如果我们有一个圆形的鸡，我们可以通过一个球体来在物理世界中表示它。使用简单的物理体可以大大提高性能。

## 尝试一下，将之前学到的技术应用到汽车游戏中

我们已经学会了使用 CSS3 过渡来为记分牌添加动画。将它应用到这个汽车游戏怎么样？此外，怎么样给汽车添加一些引擎声音？尝试应用我们通过这本书学到的知识，为玩家提供完整的游戏体验。

# 添加最后的修饰，使游戏更有趣

现在想象我们想要发布游戏。游戏逻辑基本上已经完成，但是在黑白环境下看起来相当丑陋。在本节中，我们将为游戏添加一些最后的修饰，使其更具吸引力。我们还将应用一些限制来限制 ApplyForce 的时间。这种限制使游戏更有趣，因为它要求玩家在对汽车施加过多力之前先考虑。

# 行动时间 装饰游戏并添加燃料限制

执行以下步骤：

1.  首先，我们需要一些起始画面、游戏获胜画面和每个级别的环境背景的背景图像。这些图形可以从名为`box2d_final_game`的代码包中找到。以下截图显示了本节中所需的图形：![行动时间 装饰游戏并添加燃料限制](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_09_18.jpg)

1.  打开`index.htm`文件，并用以下标记替换画布元素。它创建了两个更多的游戏组件，名为当前级别和剩余燃料，并将游戏组件分组到一个`game-container` DIV 中：

```js
<section id="game-container">
<canvas id="game" width='1300' height='600' class="startscreen"></canvas>
<div id="fuel" class="progressbar">
<div class="fuel-value" style="width: 100%;"></div>
</div>
<div id="level"></div>
</section>

```

1.  接下来，我们将从代码包中复制`cargame.css`文件。它包含了游戏的几个类样式定义。当我们应用新的样式表时，游戏应该看起来类似于以下截图中显示的游戏：

1.  现在我们将继续进行 JavaScript 部分。打开`html5games.box2dcargame.js`文件。

1.  使用以下额外变量更新`carGame`对象声明：

```js
var carGame = {
// game state constant
STATE_STARTING_SCREEN : 1,
STATE_PLAYING : 2,
STATE_GAMEOVER_SCREEN : 3,
state : 0,
fuel: 0,
fuelMax: 0,
currentLevel: 0
}

```

1.  现在我们有了起始画面。页面加载后不再立即开始游戏。我们显示起始画面，并等待玩家点击游戏画布。在页面`ready`函数中添加以下逻辑：

```js
// set the game state as "starting screen"
carGame.state = carGame.STATE_STARTING_SCREEN;
// start the game when clicking anywhere in starting screen
$('#game').click(function(){
if (carGame.state == carGame.STATE_STARTING_SCREEN)
{
// change the state to playing.
carGame.state = carGame.STATE_PLAYING;
// start new game
restartGame(carGame.currentLevel);
// start advancing the step
step();
}
});

```

1.  我们需要在页面`ready`函数的末尾删除原始的`step()`函数调用，因为我们在鼠标点击时调用它。

1.  接下来，我们需要处理玩家通过所有级别时的游戏获胜画面。在获胜旗帜碰撞检查逻辑中，我们用以下逻辑替换了原始的`restartGame`函数调用，该逻辑检查我们是显示下一个级别还是结束画面：

```js
if (currentLevel < 4)
{
restartGame(currentLevel+1);
}
else
{
// show game over screen
$('#game').removeClass().addClass('gamebg_won');
// clear the physics world
world = createWorld();
}

```

1.  然后，我们将处理游戏播放背景。我们为每个级别设置准备了每个游戏背景。我们将在`restartGame`函数中切换背景，该函数响应重构世界：

```js
$("#level").html("Level " + (level+1));
// change the background image to fit the level
$('#game').removeClass().addClass('gamebg_level'+level);

```

1.  现在游戏图形已经完成，我们不再需要物理对象轮廓绘制。我们可以在`drawWorld`函数中删除`drawShape(s, context)`的代码。

1.  最后，让我们添加一些限制。请记住，在我们的级别数据中，我们包括了一些神秘的燃料数据给汽车。它是一个指示器，指示汽车包含多少燃料。我们将使用这个燃料来限制玩家的输入。每次对汽车施加力时，燃料都会减少。一旦燃料用完，玩家就不能再施加额外的力。这种限制使游戏更有趣：

1.  使用以下逻辑更新**x**和**z**的`keydown`函数：

```js
case 88: // x key to apply force towards right
if (carGame.fuel > 0)
{
var force = new b2Vec2(10000000, 0);
carGame.car.ApplyForce (force, carGame.car.GetCenterPosition());
carGame.fuel--;
$(".fuel-value").width(carGame.fuel/carGame.fuelMax * 100 +'%');
}
break;
case 90: // z key to apply force towards left
if (carGame.fuel > 0)
{
var force = new b2Vec2(-10000000, 0);
carGame.car.ApplyForce (force, carGame.car.GetCenterPosition());
carGame.fuel--;
$(".fuel-value").width(carGame.fuel/carGame.fuelMax * 100 +'%');
}
break;

```

1.  此外，在重新开始游戏函数中的汽车创建逻辑中，我们初始化燃料如下：

```js
// create car
if (obj.type == "car")
{
carGame.car = createCarAt(obj.x,obj.y);
carGame.fuel = obj.fuel;
carGame.fuelMax = obj.fuel;
$(".fuel-value").width('100%');
continue;
}

```

1.  现在在浏览器中运行游戏。我们应该得到五个图形级别。以下截图显示了最后四个级别的外观：![行动时间 装饰游戏并添加燃料限制](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_09_22.jpg)

1.  通过所有级别后，我们得到以下获胜画面：

![行动时间 装饰游戏并添加燃料限制](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_09_20.jpg)

## 刚刚发生了什么？

我们刚刚用更多的图形装饰了我们的游戏。我们还为每个级别环境绘制了背景图像。以下截图说明了视觉地面如何表示逻辑物理框。与汽车和获胜旗帜不同，地面图形与物理地面无关。它只是一个背景图像，其图形位于各自的位置。我们可以使用这种方法，因为这些框永远不会移动：

![刚刚发生了什么？](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_09_21.jpg)

然后，我们可以为每个级别准备几种 CSS 样式，类名中带有级别编号，例如`.gamebg_level_1`和`.gamebg_level_2`。通过将每个类与每个级别的背景链接起来，我们可以在切换级别时更改背景，如下代码所示：

```js
$('#game').removeClass().addClass('gamebg_level'+level);

```

## 添加燃料以在施加力时增加约束

现在我们通过提供有限的燃料来限制玩家的输入。当玩家对汽车施加力时，燃料会减少。我们使用以下`keydown`逻辑来减少燃料并在燃料耗尽时阻止额外的力量：

```js
case 88: // x key to apply force towards right
if (carGame.fuel > 0)
{
var force = new b2Vec2(10000000, 0);
carGame.car.ApplyForce(force, carGame.car.GetCenterPosition());
carGame.fuel--;
$(".fuel-value").width(carGame.fuel/carGame.fuelMax * 100 +'%');
}

```

## 在 CSS3 进度条中呈现剩余燃料

在我们的游戏中，我们将剩余燃料呈现为进度条。进度条实际上是另一个`DIV`内部的`DIV`。以下标记显示了进度条的结构。外部`DIV`定义了最大值，内部`DIV`显示了实际值：

```js
<div id="fuel" class="progressbar">
<div class="fuel-value" style="width: 100%;"></div>
</div>

```

以下截图说明了进度条的结构：

![在 CSS3 进度条中呈现剩余燃料](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_09_23.jpg)

有了这个结构，我们可以通过将宽度设置为百分比值来显示特定的进度。我们使用以下代码根据燃料的百分比来更新进度条：

```js
$(".fuel-value").width(carGame.fuel/carGame.fuelMax * 100 +'%');

```

这是设置进度条并使用宽度样式控制的基本逻辑。此外，我们给进度条的背景添加了漂亮的渐变，如下截图所示：

![在 CSS3 进度条中呈现剩余燃料](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_09_24.jpg)

这是在样式表中完成的，使用以下 CSS3 渐变背景定义：

```js
.progressbar {
background: -webkit-gradient(linear, left top, left bottom, color-stop(0%,#8C906F), color-stop(48%,#8C906F), color-stop(51%,#323721), color-stop(54%,#55624F), color-stop(100%,#55624F));
}
.progressbar .fuel-value {
background: -webkit-gradient(linear, left top, left bottom, color-stop(0%,#A8D751), color-stop(48%,#A8D751), color-stop(51%,#275606), color-stop(54%,#4A8A49), color-stop(100%,#4A8A49));
}

```

# 总结

在本章中，我们学到了如何使用 Box2D 物理引擎在画布中创建汽车冒险游戏。

具体来说，我们涵盖了以下主题：

+   安装 JavaScript 移植的物理引擎

+   在物理世界中创建静态和动态物体

+   使用关节来设置汽车的约束和车轮

+   使用原型库获取键盘输入

+   通过向汽车添加力与其进行交互

+   在物理世界中检查碰撞作为级别目的地

+   将图像绘制为替换我们的物理游戏对象轮廓

我们还讨论了添加燃料条以限制玩家的输入，增加游戏乐趣。

我们现在已经学会了使用 Box2D 物理库来创建基于画布的物理游戏。

我们通过九章讨论了使用 CSS3 和 JavaScript 制作 HTML5 游戏的不同方面。我们学会了在 DOM 中构建传统的乒乓球游戏，在 CSS3 中构建卡片匹配游戏，并在画布中创建了一个解谜游戏。然后，我们探索了向游戏添加声音，并围绕它创建了一个迷你钢琴音乐游戏。接下来，我们讨论了使用本地存储保存和加载游戏状态。此外，我们尝试使用 WebSockets 构建了一个实时多人游戏。最后，在本章中，我们创建了一个带有物理引擎的汽车游戏。

在整本书中，我们构建了不同类型的游戏，并学习了一些制作 HTML5 游戏所需的基本技术。下一步是继续开发自己的游戏。为了帮助开发自己的游戏，有一些资源可以提供帮助。以下列表提供了一些 HTML5 游戏开发的有用链接：

## HTML5 游戏引擎

+   Impact ([`impactjs.com/`](http://impactjs.com/))

+   Rocket Engine ([`rocketpack.fi/engine/`](http://rocketpack.fi/engine/))

+   LimeJS ([`www.limejs.com/`](http://www.limejs.com/))

## 游戏精灵和纹理

+   Lost Garden（[`lunar.lostgarden.com/labels/free%20game%20graphics.html`](http://lunar.lostgarden.com/labels/free%20game%20graphics.html)）

+   来自 The_Protagonist's Domain 的一些免费精灵（[`www.freewebs.com/teh_pro/sprites.htm`](http://www.freewebs.com/teh_pro/sprites.htm)）

+   HasGraphics 精灵、纹理和瓦片集（[`hasgraphics.com/category/sprites/`](http://hasgraphics.com/category/sprites/)）

+   CG 纹理（[`cgtextures.com/`](http://cgtextures.com/)）

## 音效

+   PacDV（[`www.pacdv.com/sounds/`](http://www.pacdv.com/sounds/)）

+   FlashKit 音效（[`www.flashkit.com/soundfx/`](http://www.flashkit.com/soundfx/)）

+   FlashKit 声音循环（[`www.flashkit.com/loops/`](http://www.flashkit.com/loops/)）
