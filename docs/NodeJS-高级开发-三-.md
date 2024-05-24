# NodeJS 高级开发（三）

> 原文：[`zh.annas-archive.org/md5/b716b694adad5a9e5b2b3ff42950695d`](https://zh.annas-archive.org/md5/b716b694adad5a9e5b2b3ff42950695d)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：生成 newMessage 和 newLocationMessage

在上一章中，我们研究了 Socket.io 和 WebSockets，以实现服务器和客户端之间的双向通信。在本章中，我们将讨论如何生成文本和地理位置消息。我们研究了生成`newMessage`和`newLocationMessage`对象，然后为两种类型的消息编写了测试用例。

# 消息生成器和测试

在本节中，您将把`server.js`中的一些功能分解成一个单独的文件，并且我们还将设置我们的测试套件，以便我们可以验证这些实用函数是否按预期工作。

目前，我们的目标是创建一个帮助我们生成`newMessage`对象的函数。我们将不再需要每次都定义对象，而是只需将两个参数传递给一个函数，即名称和文本，它将生成对象，这样我们就不必做这项工作了。

# 使用实用函数生成 newMessage 对象

为了生成`newMessage`，我们将制作一个单独的文件，然后将其加载到`server.js`中，而不是定义对象。在`server`文件夹中，我们将创建一个名为`utils`的新目录。

在`utils`中，我们将创建一个名为`message.js`的文件。这将存储与消息相关的实用函数，而在我们的情况下，我们将创建一个名为`generateMessage`的新函数。让我们创建一个名为`generateMessage`的变量。这将是一个函数，并将使用我之前提到的两个参数，`from`和`text`：

```js
var generateMessage = (from, text) => {

};
```

然后它将返回一个对象，就像我们在`server.js`中作为第二个参数传递给 emit 的对象一样。现在我们需要做的就是`return`一个对象，指定`from`作为 from 参数，`text`作为 text 参数，以及`createdAt`，它将通过调用`new Date`并调用其`getTime`方法来生成：

```js
var generateMessage = (from, text) => { 
  return { 
    from, 
    text, 
    createdAt: new Date().getTime() 
  }; 
}; 
```

有了这个，我们的实用函数现在已经完成。我们需要做的就是在下面导出它，`module.exports`。我们将把它设置为一个对象，该对象具有一个`generateMessage`属性，该属性等于我们定义的`generateMessage`变量：

```js
var generateMessage = (from, text) => { 
  return { 
    from, 
    text, 
    createdAt: new Date().getTime() 
  }; 
}; 

module.exports = {generateMessage}; 
```

最终，我们将能够将其集成到`server.js`中，但在这样做之前，让我们先编写一些测试用例，以确保它按预期工作。这意味着我们需要安装 Mocha，并且还需要安装 Expect 断言库。然后我们将设置我们的`package.json`脚本并编写测试用例。

# 编写测试用例

首先，在终端中，我们将使用`npm install`安装两个模块。我们需要 Expect，这是我们的断言库，版本为`@1.20.2`，以及`mocha`来运行我们的测试套件，版本为`5.0.5`。然后，我们将使用`--save-dev`标志将它们添加为开发依赖项：

```js
npm install expect@1.20.2 mocha@5.0.5 --save-dev
```

让我们运行这个命令，一旦完成，我们就可以进入`package.json`并设置这些测试脚本。

它们将与我们在上一章的上一个项目中使用的测试用例相同。

在`package.json`中，我们现在有两个`dev`依赖项，在脚本中，我们可以通过删除旧的测试脚本来开始。我们将添加这两个脚本，`test`和`test-watch`：

```js
"scripts": {
  "start": "node server/server.js",
  "test": "echo "Error: no test specified" && exit 1",
  "test-watch": ""
},
```

# 添加 test-watch 脚本

让我们先填写基础知识。我们将把`test`设置为空字符串，然后是`test-watch`。我们知道，`test-watch`脚本只是调用`nodemon`，调用`npm test`脚本，`nodemom --exec`，然后在单引号内调用`npm test`：

```js
"scripts": {
  "start": "node server/server.js",
  "test": "",
  "test-watch": "nodemon --exec 'npm test'"
},
```

这将完成任务。现在当我们在这里运行`nodemon`时，我们实际上正在运行全局安装的`nodemon`；我们也可以在本地安装它来修复这个问题。

为了完成这个任务，我们要做的就是运行`npm install nodemon`，添加最新版本，即版本`1.17.2`，并使用`--save-dev`标志进行安装：

```js
npm install nodemon@1.17.2 --save-dev
```

现在当我们像这样安装 `nodemon` 时，我们的应用程序不再依赖于全局的 `nodemon` 安装。因此，如果其他人从 GitHub 获取这个应用程序，他们将能够开始而无需全局安装任何东西。

# 添加测试脚本

接下来是 `test` 脚本。它首先必须设置我们将要配置的环境变量；我们稍后会这样做。现在，我们要做的只是运行 `mocha`，传入我们要测试的文件的模式。

我们想要测试的文件在 `server` 目录中。它们可以在任何子目录中，所以我们将使用 `**`，而文件，无论它们的名称如何，都将以 `test.js` 结尾：

```js
"scripts": {
  "start": "node server/server.js",
  "test": "mocha server/**/*.test.js",
  "test-watch": "nodemon --exec 'npm test'"
},
```

有了这个设置，我们就完成了。现在我们可以运行我们的测试套件。

# 运行消息实用程序的测试套件

在终端中，如果我运行 `npm test`，我们将看到的是我们没有任何测试：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/df69226c-ef6e-4c23-aece-44589f81f192.png)

这里有 `server-test` 文件的 globbing 模式；它无法解析任何文件。我们可以通过简单地添加一个测试文件来解决这个问题。我将为消息实用程序添加一个测试文件，`message.test.js`。现在我们可以继续重新运行 `npm test` 命令。这一次它确实找到了一个文件，我们看到我们没有通过测试，这是一个很好的起点：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/7f043155-68af-43f7-aae5-66b040c5e59b.png)

在 `message.test.js` 中，我们需要为刚刚定义的消息函数添加一个测试。现在这个测试将验证我们得到的对象是否符合我们根据传入的参数所期望的。我们将一起设置测试文件的基本结构，然后你将编写单个测试用例。

首先，我们需要使用 `var expect = require('expect')` 加载 Expect。这将让我们对从我们的 `generateMessage` 函数返回的值进行断言：

```js
var expect = require('expect');
```

接下来我们要做的是添加一个 `describe` 块。在这里，我们将为函数 `generateMessage` 添加一个 `describe` 块，并在回调函数中添加该函数的所有测试用例：

```js
describe('generateMessage', () => {

});
```

在我们实际创建测试用例并填写之前，我们确实需要加载我们正在测试的模块。我将创建一个变量并使用 ES6 解构。我们将取出 `generateMessage`，然后我们可以使用 `require` 来引入它，指定本地路径 `./message`：

```js
var expect = require('expect');
var {generateMessage} = require('./message');

describe('generateMessage', () => {

});
```

它与我们当前所在的测试文件相同的目录中，所以没有理由进行任何目录移动。有了这个设置，我们现在可以添加单个测试用例，`it ('should generate the correct message object')`。这将是一个同步测试，因此无需提供 done。你只需要调用 `generateMessage` 传入两个值，`from` 和 `text`。你将得到响应，并将响应存储在变量中：

```js
describe('generateMessage', () => {
  it('should generate correct message object', () => {
    //store res in variable
  });
});
```

然后你将对响应进行一些断言。首先，断言 from 是正确的，断言 from 与你传入的值匹配。你还将断言文本匹配，最后你将断言 `createdAt` 值是一个数字：

```js
var expect = require('expect');
var {generateMessage} = require('./message');

describe('generateMessage', () => {
  it('should generate correct message object', () => {
    // store res in variable
    // assert from match
    // assert text match
    // assert createdAt is number
  });
});
```

它不管是什么数字；你将使用 `toBeA` 方法来检查类型并断言 `createdAt` 是数字。为了完成这个任务，我将首先定义一些变量。

首先，我将创建一个 from 变量来存储 from 的值。我将使用 `Jen`。我还将创建一个 `text` 变量来存储文本值，`Some message`。现在我想做的是创建我的最终变量，它将存储响应，即从 `generateMessage` 函数返回的 `message`，这正是我要调用的。我将调用 `generateMessage`，传入两个必要的参数，`from` 参数和 `text` 参数：

```js
describe('generateMessage', () => {
  it('should generate correct message object', () => {
    var from = 'Jen';
    var text = 'Some message';
    var message = generateMessage(from, text);
```

接下来，最后一件事，我们需要对返回的对象进行断言。我期望`message.createdAt`是一个使用`toBeA`和传入类型`number`的数字：

```js
describe('generateMessage', () => {
  it('should generate correct message object', () => {
    var from = 'Jen';
    var text = 'Some message';
    var message = generateMessage(from, text);

    expect(message.createdAt).toBeA('number');
```

这是你需要做的第一个断言，以验证属性是否正确。接下来，我们将期望该消息内部具有某些属性。我们将使用`toInclude`断言来做到这一点，尽管你可以创建两个单独的语句：一个用于`message.from`，另一个用于`message.text`。所有这些都是有效的解决方案。我将只使用`toInclude`并指定消息应该包含的一些内容：

```js
expect(message.createdAt).toBeA('number');
expect(message).toInclude({

});
```

首先，它应该有一个`from`属性等于`from`变量。我们可以继续使用 ES6 来定义；对于`text`，`text`应该等于`text`，我们将使用 ES6 来设置。我们甚至可以使用`from, text`来进一步简化这个过程：

```js
expect(message.createdAt).toBeA('number');
expect(message).toInclude({from, text});
```

有了这个，我们的测试用例现在已经完成，我们可以继续删除这些注释轮廓，你需要做的最后一件事是通过在终端运行`npm test`来运行测试套件。当我们这样做时，我们会得到什么？我们得到了我们在`generateMessage`下的一个测试，应该生成正确的消息对象，它确实通过了，这太棒了：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/f79e1123-da6d-446d-b698-e5c2eda9b07b.png)

现在我们有一些测试来验证我们的函数是否按预期工作，让我们继续将其集成到我们的应用程序中，方法是进入`server.js`，并用我们的新函数调用替换传递给 emit 函数的所有对象。

# 将实用函数集成到我们的应用程序中

这个过程的第一步是导入我们刚刚创建的函数。我将在`server.js`中创建一个常量来做到这一点。我们将使用 ES6 解构来获取`generateMessage`，并且我们将从`require`的调用中获取它。现在我们正在要求一个不同目录中的本地文件。我们将从`./`开始，进入`utils`目录，因为我们当前在`server`目录中，然后通过指定文件名`message`来获取它：

```js
const socketIO = require('socket.io');

const {generateMessage} = require('./utils/message');
```

现在我们可以访问`generateMessage`，而不是创建这些对象，我们可以调用`generateMessage`。在`socket.emit`中，我们将用参数`generateMessage ('Admin', 'Welcome to the chat app')`替换`Welcome to the chat app`和`Admin`变量：

```js
socket.emit('newMessage', generateMessage('Admin', 'Welcome to the chat app'));
```

我们有完全相同的功能，但现在我们使用一个函数来为我们生成该对象，这将使得扩展变得更容易。这也将使得更新消息内部的内容变得更容易。接下来，我们可以更改下面的*New user joined*。我们也将用对`generateMessage`的调用来替换这个。

这次也是来自`Admin`，所以第一个参数将是字符串`Admin`，第二个参数是文本`New user joined`：

```js
socket.emit('newMessage', generateMessage('Admin', 'Welcome to the chat app'));
```

这个也完成了，最后一个是实际从用户那里发送给用户的，这意味着我们有`message.from`和`message.text`；这些将是我们的参数。我们将使用这两个参数`message.from`和`message.text`调用`generateMessage`作为第二个参数：

```js
socket.on('createMessage', (message) => {
  console.log('createMessage', message);
  io.emit('newMessage', generateMessage('Admin', 'New user joined'));                                
```

有了这个，我们就完成了。这一部分剩下的最后一件事是测试它是否按预期工作。我将使用`nodemon`启动服务器，`node`和`mon`之间没有空格，`server/server.js`：

```js
nodemon server/server.js
```

一旦服务器启动，我们可以通过打开几个带有开发者工具的标签页来测试一下。

对于第一个标签页，我将访问`localhost:3000`。在控制台中，我们应该看到我们的新消息打印出来，即使它现在是由函数生成的，对象看起来是一样的，我们也可以通过打开第二个标签页并打开其开发者工具来测试其他一切是否按预期工作：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/1e0c1175-3c4c-4958-a83f-0109b0922d06.png)

这一次，第一个选项卡应该看到一个新消息，这里有一个`New user joined`的文本，仍然有效。如果我们从第二个选项卡发出自定义消息，它应该出现在第一个选项卡中。我将使用上箭头键运行我们之前的`createMessage`事件发射器之一。

我将触发这个函数，如果我去第一个选项卡，我们确实会收到消息，这太棒了：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/adfa80a5-d2de-4918-9ff2-f3a4d95a839e.png)

这应该有效，在第一个选项卡中打印，也会在第二个选项卡中打印，因为我们调用的是`io.emit`而不是广播方法。

现在一切都正常了，我们完成了；我们可以提交并结束这一部分。我将从终端调用`git status`。这里我们有新文件和修改过的文件，这意味着我们需要调用`git add .`。接下来，我们可以调用`git commit`并使用消息标志，`create generateMessage utility`：

```js
git commit -m 'create generateMessage utility'
```

我将把这个推送到 GitHub，这就是这个部分的全部内容。在下一节中，我们将看一下`Socket.io`的确认。

# 事件确认

在这一节中，你将学习如何使用事件确认。这是`Socket.io`中的一个很棒的功能。为了准确说明它们是什么以及为什么你想要使用它们，我们将快速浏览一下聊天应用程序的图表。这是我们应用程序中实际存在的两个事件，如果你还记得，第一个是 newMessage 事件，它由服务器发出，并由客户端监听，它发送 from、text 和 createdAt 属性，所有这些属性都是必需的，以便将消息呈现到屏幕上。

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/7644a516-1cea-4937-a566-8b47601df728.png)

我们要更新的事件是 createMessage 事件。这个事件由客户端发出，服务器监听：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/c844762f-db12-40b6-b6d6-ff93e3404b20.png)

我们再次从文本中发送一些数据。现在我们的 createMessage 事件存在的问题是数据只能单向流动。数据来自浏览器内的表单，然后发送到服务器，服务器就有点卡住了。当然，数据可能是有效的，from 和 text 字段可能设置正确。在这种情况下，我们可以发出 newMessage 事件，将其呈现给连接到服务器的每个浏览器，但是如果服务器接收到无效数据，它就无法让客户端知道出了什么问题。

我们需要一种确认我们收到请求并有选项发送一些数据的方法。在这种情况下，我们将为 createMessage 添加一个确认。如果客户端发出有效的请求，并且 from 和 text 属性有效，我们将确认它，发送回无错误消息。如果从客户端发送到服务器的数据无效，我们将确认它，发送回错误消息，这样客户端就知道需要做什么才能发送有效的请求。现在结果看起来会有点像这样，服务器到客户端的数据流将通过回调完成：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/f788065b-0262-41bf-965b-6df284c1d5a8.png)

你的确认可以是任何你喜欢的。在我们的情况下，它可能是消息数据有效吗？如果你正在创建一个电子邮件应用程序，你可能只在成功发送电子邮件时向客户端发送确认。当有效数据通过管道发送时，你不需要发送数据，这就是当有效数据发送时我们要做的。我们只需要说，嘿，我们收到了那条消息，一切都很顺利，客户端可以对此做出响应。

既然我们已经完成了这一部分，让我们继续将其实现到我们的应用程序中。

# 设置确认

如果你已经有一个监听器，设置确认真的不难。你只需要快速更改监听器和发射器，一切都会按预期工作。

现在，在这种情况下，监听器恰好在服务器上，发射器将在客户端上，但确认也可以在另一个方向上工作。我可以从服务器发射一个事件，并且可以在客户端上确认它。

为了设置这个，我们将使用`socket.emit`在`index.js`中发射一个`createMessage`事件，并且我们将传递相同的参数。第一个是事件名称，`createMessage`，然后我们将传递一些有效的数据，一个具有这两个属性的对象。我们可以将`from`设置为`Frank`，并且我们可以将`text`属性设置为`Hi`：

```js
socket.emit('createMessage', {
  from: 'Frank',
  text: 'Hi'
});
```

现在有了这个，我们有了一个标准的事件发射器和一个标准的事件监听器。我可以继续使用`nodemon`启动应用程序，确保一切都按预期工作，`nodemon server/server.js`：

```js
nodemon server/server.js
```

一旦服务器启动，我们可以在浏览器中访问它，我也会打开开发者工具。然后我们将转到`localhost:3000`，你可以看到在终端中我们有`createMessage`显示出来，我们还有`newMessage`显示在这里。我们有`newMessage`用于我们的小`Welcome to the chat app`问候语，以及我们从`Frank`那里发射的`newMessage`：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/98585275-6297-4746-8a5a-459b8ce85cdc.png)

现在这里的目标是从服务器发送一个确认回到客户端，证明我们已经收到了数据。

# 从服务器发送确认到客户端

为了完成这个任务，我们必须对监听器和发射器进行更改。如果你只对其中一个进行更改，它将不会按预期工作。我们将从事件发射器开始。我们希望在从服务器发送确认到客户端时运行一些代码。

# 更新事件发射器

为了从服务器向客户端发送确认，我们将添加一个第三个参数，这将是一个回调函数。当确认到达客户端时，这个函数将被触发，我们可以做任何我们喜欢的事情。现在我们只是使用`console.log('Got it')`打印：

```js
socket.emit('createMessage', { 
  from: 'Frank', 
  text: 'Hi' 
}, function () { 
  console.log('Got it'); 
}); 
```

现在这就是我们需要做的最基本的事情，为客户端添加一个确认。

# 更新事件监听器

在服务器上也很简单；我们将在`callback`参数列表中添加第二个参数。第一个仍然是被发射的数据，但第二个将是一个我们将称之为`callback`的函数。我们可以在`socket.on`中的任何地方调用它来确认我们已经收到了请求：

```js
socket.on('createMessage', (message, callback) => {
  console.log('createMessage', message);
  io.emit('newMessage', generateMessage(message.from, message.text));
  callback();
```

当我们调用这个函数时，就像我们现在要调用它一样，它将会向前端发送一个事件，然后会调用`index.js`中的事件发射器中的函数。

这意味着如果我保存这两个文件，我们可以在浏览器中玩一下确认。我将刷新应用程序，我们会得到什么？我们得到了 Got it：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/8fd062aa-1af4-494f-a8c4-0937594e2184.png)

这意味着我们的数据成功传输到了服务器；我们可以通过在终端中看到`console.log`语句来证明这一点，服务器通过调用回调函数确认它已经收到了数据：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/1b37a8ea-3715-47c2-ba77-a991b4ce67a3.png)

在开发者工具中，Got it 打印出来了。

现在确认是非常有用的，但当你发送数据回去时，它们会更有用。例如，如果消息的数据无效，我们可能会想要发送一些错误回去，这是我们稍后将要做的事情。不过，现在我们可以通过发送任何我们想要的东西来玩一下确认。

通过向回调提供一个参数来发送数据回去，如果你想添加多个东西，只需指定一个对象，添加尽可能多的属性。不过，在我们的情况下，我们可以将一个字符串作为`callback`的唯一参数发送。我将把我的字符串设置为`This is from the server`：

```js
socket.on('createMessage', (message, callback) => {
  console.log('createMessage', message);
  io.emit('newMessage', generateMessage(message.from, message.text));
  callback('This is from the server.');
});
```

这个字符串将被传递到回调函数中，并最终出现在我们的`index.js`回调中。这意味着我可以为该值创建一个变量，我们可以称之为`data`或者其他你喜欢的名称，并且我们可以将其打印到屏幕上或者对其进行操作。现在我们只是打印到屏幕上：

```js
socket.emit('createMessage', {
  from: 'Frank',
  text: 'Hi'
}, function (data) {
  console.log('Got it', data);
});
```

如果我保存`index.js`，我们可以测试一切是否按预期工作。我将继续刷新应用程序，我们会看到什么？

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/4f9d2613-c564-4e64-b9ba-b9f5599c8cdc.png)

我们看到了“收到”，这意味着我们收到了确认，我们也看到了数据，从服务器发送到客户端的数据。

确认在实时应用程序中扮演着重要的角色。让我们回到电子邮件应用程序的例子，想象一下，当我发送电子邮件时，我键入了一些值，比如收件人和文本值。我希望得到一个确认，要么是电子邮件成功发送，要么是电子邮件未发送，这种情况下我想知道原因；也许是表单错误，我可以向用户显示一些错误消息，或者服务器正在维护中等等。

无论如何，确认允许请求监听器向请求发射器发送一些内容。现在我们知道如何使用确认，我们将把它们整合到我们的应用程序中。这将在下一节中进行，我们将在`index.html`文件中添加一个实际的表单字段，用户可以提交新消息并查看它们。

# 消息表单和 jQuery

在这一节中，你将向你的`index.html`文件中添加一个表单字段。这将在屏幕上呈现一个输入字段和一个按钮，用户将能够与之交互，而不是必须从开发者工具中调用`socket.emit`，这对于真实用户来说并不是一个可持续的选项。这只对我们开发人员有效。

现在，为了开始，我们将编辑`index.html`，然后我们将转到`index.js`。我们将添加一个监听器，等待表单提交，然后在该监听器回调中，我们将使用表单中键入的数据来触发`socket.emit`。我们还将花一些时间将所有传入的消息呈现到屏幕上。在本节结束时，我们将拥有一个丑陋但工作的聊天应用程序。

# 使用 jQuery 库

在我们做任何操作之前，我们将使用一个名为 jQuery 的库来进行 DOM 操作，这意味着我们希望能够处理我们呈现的 HTML，但我们希望能够从我们的 JavaScript 文件中进行操作。我们将使用 jQuery 来使跨浏览器兼容性更容易。为了获取这个库，我们将前往 Google Chrome，转到[jquery.com](http://jquery.com/)，然后你可以获取最新版本。版本对于这里并不重要，因为我们使用的是所有版本中可用的非常基本的功能：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/ddd476fc-950d-4a25-8a42-dc7c52cf7bc7.png)

我将获取最新版本 3.3.1。然后我将右键单击并在新标签中打开压缩的生产版本进行下载：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/a9539a35-4ea1-4cf5-baab-348758914222.png)

这里有我们想要加载到我们应用程序中的实际 JavaScript，这意味着我们可以右键单击某个空白区域，点击“另存为”，然后进入我们的项目文件夹，`桌面` | `node-chat-app` | `public` | `js`。在`js`文件夹中，我将创建一个名为`libs`的新目录，我们将在其中存储第三方 JavaScript。在这个目录中保存，关闭标签以及下载区域，现在我们可以继续加载到`index.html`中并添加我们的表单。

# 在 index.html 中添加表单字段

在这里，就在`socket.io`和`index.js`之间，我们要添加一个新的脚本标签来加载 jQuery。我们必须指定`src`属性，路径是`/js/libs`，后面跟着一个斜杠和文件名`jquery-3.3.1.min.js`：

```js
<script src="img/socket.io.js"></script>
<script src="img/jquery-3.3.1.min.js"></script>
<script src="img/index.js"></script>
```

现在让我们设置我们的`form`标签；这将把我们的表单字段呈现到浏览器上。如果你对这些标签不熟悉，那没关系，跟着做，我会一边解释。

# 设置表单标签

第一步，我们需要一个`form`标签；这会创建一个用户可以提交的表单。这正是我们要用来提交我们的消息的。在这个`form`标签上，我们要添加一个属性；就是`id`属性，它让我们给这个元素一个唯一的标识符，这样以后用 JavaScript 就很容易定位它：

```js
<form id>

</form>
```

记住，我们要给这个元素添加一个监听器。当表单被提交时，我们要在我们的 JavaScript 文件中做一些事情。特别是我们要做的是调用`socket.emit`。

我要把`id`设置为，引号内，`message-form`：

```js
<form id="message-form">

</form>
```

现在我们的表单标签完成了，我们可以在里面添加一些标签。首先，我们要添加一个`button`，它会出现在`form`的`底部`。这个`button`在点击时会提交`form`。我打开并关闭我的标签，然后在里面可以输入任何我想要出现在`button`上的文本。我要选择`Send`：

```js
<form id="message-form">
  <button>Send</button>
</form>
```

# 添加文本字段

现在我们的`button`就位了，唯一需要做的就是添加一个小文本字段。这将是用户输入消息的文本字段。这将需要我们使用一个`input`标签，而不是打开和关闭一个`input`标签，我们将使用自关闭的语法：

```js
<form id="message-form">
  <input/>
  <button>Send</button>
</form>
```

因为我们不需要像`button`或`form`那样在里面放任何东西，我们要给`input`添加很多属性，首先是`name`，我们要给这个字段一个唯一的名称，类似`message`就可以了。我们还要设置类型。`input`标签有很多不同的类型。类型可以包括复选框之类的，或者在我们的情况下，我们要在引号内使用的类型是`text`：

```js
<input name="message" type="text"/>
```

我们要添加到`input`的最后一个属性叫做`placeholder`。我们要把这个值设置为，引号内，一个字符串。在用户实际输入值之前，这个字符串会以浅灰色呈现在字段中。我要告诉用户这就是他们的`Message`的地方：

```js
<form id="message-form">
  <input name="message" type="text" placeholder="Message"/>
  <button>Send</button>
</form>
```

有了这个，我们实际上可以测试一下我们表单的渲染。

# 测试表单的渲染

我们可以通过启动服务器使用`nodemon`来进行测试：

```js
nodemon server/server.js
```

服务器已经启动，我要访问 Google Chrome，然后转到`localhost:3000`。你会注意到一些很酷的东西，我实际上还没有访问过这个 URL，但你可以看到连接已经发生了。Chrome 进行了一些懒加载，如果它认为你要去一个 URL，它实际上会发出请求；所以当我访问它时，它加载得更快。现在如果我访问`localhost:3000`，我们会得到什么？

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/fa4e5cb4-2f38-4897-99a8-068369aad5ea.png)

我们得到了我们的小表单，我们可以输入一个消息，比如`Test`，然后发送出去。现在默认情况下，表单非常老式。如果我试图提交这个表单，它实际上会进行完整的页面刷新，然后会把数据，比如我们的消息文本，作为查询字符串添加到 URL 上。这不是我们想要做的，我们想要在表单提交时运行一些自定义 JavaScript。所以我们要附加一个自定义事件监听器并覆盖默认行为。为了完成这个，我们需要使用 jQuery，并且需要选择这个`form`字段。

# 使用 jQuery 选择元素

在我们深入研究`index.js`之前，让我们简要谈一下如何使用`jQuery`来选择元素。`jQuery`，可以通过`jQuery`变量访问，将您的选择器作为其参数。然后，我们将添加一个字符串，我们可以选择我们的元素。例如，如果我们想在屏幕上选择所有段落标签，我们将在引号中输入`p`：

```js
jQuery('p');
```

这些与 CSS 选择器非常相似，如果您熟悉它们的话，如图所示，我们已经选择了我们的段落标签。

我还可以选择程序中的所有`div`，或者可以按 ID 或类选择元素，这就是我们要做的。为了通过 ID 选择元素，我们首先以井号（`#`）开始，然后输入名称。在我们的情况下，我们有一个名为`message-form`的`form`，如果我执行这个操作，我们确实会得到它：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/a3b37ba2-bfaf-485b-8833-c56ef7191a1e.png)

这将允许我们添加一个事件监听器。

# 将选择器元素添加到 index.js

在`index.js`中，我们将在底部附近添加完全相同的选择器，`jQuery`，使用我们的选择器`#message-form`进行调用。现在我们将添加一个事件监听器，事件监听器看起来与我们的`Socket.io`事件监听器非常相似。我们将调用`on`，并且我们将提供这两个参数，事件名称在引号内，`submit`，和一个`function`，当用户尝试提交`form`时将触发该`function`：

```js
jQuery('#message-form').on('submit', function(){

});
```

现在，与我们的`Socket.io`事件监听器不同，我们将在`function`中得到一个参数，一个`e`事件参数，并且我们需要访问它。我们需要访问这个事件参数，以覆盖导致页面刷新的默认行为。在这里，我们将调用`e.preventDefault`：

```js
jQuery('#message-form').on('submit', function(){
  e.preventDefault();
});
```

`preventDefault`方法可以阻止事件的默认行为，默认情况下，提交事件会经过页面刷新过程。

我们可以通过进入 Google Chrome，刷新页面来测试一切是否正常。我还将从 URL 中删除查询字符串。现在我们可以输入一些消息，比如`test`，点击发送，您会看到什么都没有发生。之所以什么都没有发生，是因为我们覆盖了默认行为，要使某些事情发生，我们只需要在`index.js`中调用`socket.emit`。我们将发出`createMessage`：

```js
jQuery('#message-form').on('submit', function(){
  e.preventDefault();

  socket.emit('createMessage', {

  });
});
```

然后，我们将继续提供我们的数据。现在，`from`字段的名称暂时只是大写的`User`。我们暂时将其保留为匿名，尽管稍后我们将对其进行更新。现在对于文本字段，这将来自`form`。我们将要添加一个选择器并获取值。让我们使用`jQuery`来做到这一点：

```js
  socket.emit('createMessage', { 
    from: 'User', 
    text: jQuery('')
  })
});
```

我们将再次调用`jQuery`，并且我们将选择`index.html`文件中的输入。我们可以通过其名称`name="message"`来选择它：

```js
<input name="message" type="text" placeholder="Message"/> 
```

为了完成这个任务，我们将在`index.js`中的`socket.emit`中打开括号，将`name`设置为`message`。这将选择任何具有`name`属性等于`message`的元素，这就是我们的一个元素，我们可以使用`.val`方法获取其值：

```js
  socket.emit('createMessage', { 
    from: 'User', 
    text: jQuery('[name=message]').val();
  })
});
```

由于我们在对象创建内部，不需要分号。有了这个，我们现在可以继续添加我们的回调函数以进行确认。目前它实际上并没有做任何事情，但这完全没问题。我们必须添加它以满足我们当前设置的确认：

```js
jQuery('#message-form').on('submit', function (e) {
  e.preventDefault();

  socket.emit('createMessage', {
    from: 'User',
   text: jQuery('[name=message]').val()
  }, function () {

  })
});
```

现在我们已经设置了事件监听器，让我们继续测试一下。

# 测试更新事件监听器

我将回到 Chrome，刷新页面，输入一些消息，比如`This should work`，当我们提交表单时，我们应该在这里看到它显示为新消息：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/745dcf89-0e1d-46ef-a43d-059101886cec.png)

我将发送它，你可以看到在终端内，我们有一个用户发送`This should work`，它也显示在 Chrome 中：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/ff37e724-ba40-4ed2-8df6-08a1e49a739e.png)

如果我打开第二个连接，情况也是如此，我将打开开发者工具，这样我们就可以看到幕后发生了什么。我将输入一些消息，比如`From tab 2`，发送出去：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/b6c66dd6-dde0-453a-9cd3-8ead6fd3cb2f.png)

我们应该在选项卡 1 中看到它，我们确实看到了：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/8a22faa0-6e61-4131-87a8-1a2cdf5fcfd6.png)

完美，一切都按预期工作。现在显然设置还没有完成；我们希望在发送消息后清除表单值，并且我们希望处理一些其他与用户界面相关的事情，但目前它运行得相当好。

有了一个基本的表单，我们要做的第二件事是将传入的消息渲染到屏幕上。现在再次看起来可能会很丑，但它会完成工作。

# 将传入的消息渲染到屏幕上

为了完成这个任务，我们必须在我们的`index.html`文件内创建一个地方，我们可以在其中渲染消息。再次，我们将给这个元素一个 ID，这样我们就可以在`index.js`内部轻松访问它，以便渲染这些消息。

# 创建一个有序列表来渲染消息

首先，我们要做的是创建一个有序列表，方法是创建一个`ol`标签，就像这样：

```js
<body>
  <p>Welcome to the chat app</p>
  <ol></ol>
```

这个列表将允许我们向其中添加项目，这些项目将是单独的消息。现在我们将给它一个`id`属性。在这种情况下，我将称之为`messages`：

```js
<ol id="messages"></ol>
```

现在这就是我们在`index.html`中需要做的全部，所有的重活将在`index.js`内部进行。当有新消息到达时，我们希望在有序列表内添加一些内容，以便将其渲染到屏幕上。

在`index.js`内部，当新消息到达时，我们可以通过修改回调函数来完成这个任务。

# 使用 jQuery 在 index.js 中创建元素

我们要做的第一件事是创建一个列表项，我们将再次使用 jQuery 来完成这个任务。我们将创建一个变量，这个变量将被称为`li`，然后我们将稍微不同地使用 jQuery：

```js
socket.on('newMessage', function (message) {
  console.log('newMessage', message);
  var li = jQuery();
});
```

我们不再使用`jQuery`来选择元素，而是使用`jQuery`来创建一个元素，然后我们可以修改该元素并将其添加到标记中，使其可见。在引号内，我们将打开和关闭一个`li`标签，就像我们在`index.html`中一样：

```js
socket.on('newMessage', function (message) {
  console.log('newMessage', message);
  var li = jQuery('<li></li>');
});
```

现在我们已经完成了这一步，我们必须继续设置它的文本属性，我将通过调用`li.text`来设置`li.text`，并传入我想要使用的值。

在这种情况下，文本将要求我们设置一个小模板字符串，在模板字符串内，我们将使用返回的数据。现在我们将使用`from`属性和`text`属性。让我们从`from`开始，然后添加一个小冒号和一个空格来将其与实际的`message`分开，最后，我们将在末尾注入`message.text`：

```js
var li = jQuery('<li></li>');
li.text(`${message.from}: ${message.text}`);
```

现在，我们已经创建了一个元素，但我们还没有将它渲染到 DOM 中。我们将使用`jQuery`来选择我们创建的全新元素，我们给它一个 ID 为`messages`，然后我们将通过调用`append`方法向其添加一些内容：

```js
var li = jQuery('<li></li>');
li.text(`${message.from}: ${message.text}`);

jQuery('#messeges').append
```

这将把它添加为其最后一个子元素，因此列表中已经有三个项目；最新的项目将显示在这三个项目下方，作为有序列表中的第四个项目。我们只需要调用`append`作为一个函数，传入我们的列表项：

```js
var li = jQuery('<li></li>');
li.text(`${message.from}: ${message.text}`);

jQuery('#messeges').append(li);
});
```

有了这个设置，我们就完成了。现在，如果你不熟悉`jQuery`，这可能有点令人不知所措，但我保证我们在这里使用的技术将贯穿整本书。到最后，你会更加舒适地选择和创建元素。

# 测试传入的消息

让我们继续在 Google Chrome 中测试。我将刷新标签 1，当我这样做时，你可以看到我们的两条消息，欢迎来到聊天应用显示出来，Frank 说 Hi：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/8ad84232-822d-4f69-9d40-42a821b92550.png)

现在欢迎来到聊天应用应该显示出来。Frank Hi 消息来自`index.js`中的`socket.emit`：

```js
socket.emit('createMessage', { 
  from: 'Frank', 
  text: 'Hi' 
}, function (data) { 
  console.log('Got it', data); 
}); 
```

我们实际上可以去掉它，我们不再需要自动发送消息，因为我们已经设置了一个`form`来完成这项工作。再次保存文件，刷新浏览器，这一次我们有了一个很好的设置，欢迎来到聊天应用：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/4b6c4e36-7bc6-439f-b553-469dbbe85937.png)

我将为我们的第二个标签做同样的事情。这一次我们会得到欢迎来到聊天应用，在第一个标签中我们会得到新用户加入；这太棒了：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/2c0342a2-a143-475b-9cd2-ab6b3bd8a2f6.png)

现在真正的测试将是从一个标签发送消息到另一个标签，“这应该发送到标签 2”。我将发送这条消息，当我点击这个按钮时，它将触发事件发送到服务器，服务器将把它发送给所有连接的人：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/5df3ee7d-73a7-4064-b55c-7b55a44b986e.png)

在这里，我可以看到“This should go to tab 2”被渲染出来，在我的第二个标签中也收到了这条消息：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/2bf72bc9-0838-4109-aa72-b64cfd615bf2.png)

现在我们的 UI 或实际用户体验还没有完成；自定义名称和时间戳即将到来，但我们已经有了一个很棒的开始。现在我们有一个表单，我们可以提交消息，并且我们可以在浏览器中看到所有传入的消息，这意味着我们不需要在开发者工具中再做任何关于发送或阅读消息的工作。就是这样，让我们继续通过做出一些工作变更来做出提交。

# 为消息表单做出提交

我将关闭服务器，清除输出，并运行`git status`，以便我们可以仔细检查所有的更改；一切看起来都很好：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/1c246efa-4f88-4d88-bec4-17b468d7a292.png)

我将使用`git add`命令将所有文件添加到仓库中，包括我的未跟踪的 jQuery 文件。然后我使用`git commit`进行`commit`。我将在这里使用`-m`标志，这次的好消息是`添加消息表单并在浏览器中显示传入消息`：

```js
git commit -m 'Add form for messages and show incoming messages in browser'
```

一旦我们完成这一步，我们就可以将其`push`到 GitHub 上。现在我们有了一些真实的、可见的、有形的东西可以使用，我要花一点时间部署到 Heroku，`git push heroku master`就可以搞定：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/bf7f1ecf-765a-48f4-a2e3-e344e1b27626.png)

一旦这个就绪，我们就可以在浏览器中访问它。正如你在我的控制台中看到的，`Socket.io`正在尝试重新连接到服务器。不幸的是，我们不会再次将其带回来，所以它会尝试更长时间。

我们在这里，正在验证部署，一切都正常运行。你可以运行`heroku open`或直接复制 URL。我将关闭我的两个本地主机标签，然后打开实际的 Heroku 应用。

在这里，我们得到了欢迎来到聊天应用的消息，我们也得到了我们的表单；一切看起来都很好。我将继续打开另一个浏览器，比如 Safari。我也会去聊天应用，然后把这些窗口并排放在一起。在 Safari 中，我会输入一条小消息，“这是在 Heroku 上实时的”，点击发送或按下*enter*键，它立即出现在另一个浏览器的另一个标签中。这是因为我们的实时 socket 服务器正在传输这些数据：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/54ddfc39-b0a9-40c7-9e68-8f8d39890d1c.png)

这可能发生在世界上的任何一台计算机上，你不需要在我的机器上，因为我们使用的是真实的 Heroku URL。现在在 Heroku 上一切都正常了，我们完成了。

# 地理位置

在本节中，您将开始地理位置的两部分系列的第一部分。我们不仅仅是互发文本，还将设置它，以便我可以将我的实际坐标，即我的经度和纬度，发送给连接到聊天应用程序的其他所有人。然后我们可以呈现一个链接，该链接可以指向任何我们喜欢的地方；在我们的情况下，我们将设置它以打开一个 Google 地图页面，其中标记了发送其位置的用户的实际位置。

现在，为了实际获取用户的位置，我们将使用地理位置 API，在客户端 JavaScript 中可用，并且实际上是一个非常受支持的 API。它在所有现代浏览器上都可用，无论是移动设备还是桌面设备，可以通过谷歌搜索“地理位置 API”找到文档，并查找 MDN 文档页面。

MDN 文档，或者 Mozilla 开发者网络，是我最喜欢的客户端技术文档，例如您的 Web API、CSS 和 HTML 指南：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/90af9d91-82b8-4986-a747-86839916d9f0.png)

现在，正如我所提到的，这是一个受支持的功能，除了较旧版本的 Internet Explorer 和 Opera Mini 浏览器外，您几乎可以在任何地方使用它。但是，所有主要的桌面和移动浏览器都将支持此功能，如果浏览器过旧，我们将设置一个小消息来告诉他们他们的浏览器不支持地理位置。如果您想了解更多关于地理位置的信息，或者探索我们在本节中未涵盖的功能，您可以参考此页面，尽管我们将使用地理位置提供的大多数功能。

# 将发送位置按钮添加到应用程序

首先，我们要做的是向我们的应用程序添加一个新按钮。它将与发送按钮并排，并且会显示类似“发送位置”的内容。当用户点击发送位置按钮时，我们将使用地理位置 API。通常，这将需要用户确认他们是否要与浏览器中的此标签共享其位置，弹出框将会出现，这将由浏览器触发，没有其他方法可以绕过这一点。

您需要确保用户确实希望共享他们的位置。一旦您获得了坐标，您将发出一个事件，该事件将发送到服务器，服务器将将其发送给所有其他连接的用户，我们将能够以一个良好的链接呈现该信息。

首先，我们将添加该按钮，这将是启动整个过程的按钮。在 Atom 中的`index.html`中，我们将在我们现有的`form`标签下方添加一个按钮。它将位于我们现有的表单之外。我们将添加`button`标签，并为其分配`send-location`的 ID。至于可见的`button`文本，我们可以使用`Send Location`作为我们的字符串，并保存文件：

```js
  <form id="message-form"> 
    <input name="message" type="text" placeholder="Message"/> 
    <button>Send</button> 
  </form> 
  <button id="send-location">Send Location</button> 
```

如果我们继续在浏览器中刷新应用程序，现在应该会看到我们的发送位置按钮显示出来：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/0ef04e95-11c7-460e-a0fd-903e4cbe19fd.png)

稍后我们将在添加默认样式时修复所有这些问题，但现在这确实完成了工作。

目前，单击此按钮不会执行任何操作，它与`form`没有关联，因此不会执行任何奇怪的`form`提交或页面重新加载。我们只需要向此按钮添加一个`click`监听器，就可以运行任何我们喜欢的代码。在我们的情况下，我们将运行地理位置代码。

# 给发送位置按钮添加点击监听器

我们将在 Atom 中的`index.js`中添加一个`click`监听器，并在底部附近添加一些代码。

现在我想做的第一件事是创建一个变量，我将把这个变量称为`locationButton`；这将存储我们的选择器。这是一个 jQuery 选择器，它指向我们刚刚创建的按钮，因为我们需要多次引用它，并且将它存储在一个变量中可以节省再次调用的需要。我们将像我们为其他选择器所做的那样调用`jQuery`，传入一个参数，一个字符串，我们通过 ID 选择了某个东西，这意味着我们必须以`#`开始，并且实际的 ID 是`send-location`：

```js
var locationButton = jQuery('#send-location');
```

现在我们已经准备就绪，可以做任何我们喜欢的事情。在我们的情况下，我们要做的是添加一个点击事件，并且我们希望当有人点击按钮时做一些事情。为了完成这个目标，我们将转到`locationButton.on`：

```js
var locationButton = jQuery('#send-location');
locationButton.on
```

这与执行`jQuery`相同，选择 ID`send-location`，这两者都会做同样的事情。第一个解决方案的好处是我们有一个可重用的变量，以后我们会引用它。对同一个选择器进行两次 jQuery 调用会浪费时间，因为它需要 jQuery 来操作 DOM，获取信息，这是很昂贵的。

`locationButton.on`将是我们的事件监听器。我们正在监听`click`事件，第一个参数是引号内的`click`事件，第二个参数像往常一样将是我们的`function`：

```js
var locationButton = jQuery('#send-location');
locationButton.on('click', function () {

});
```

当有人点击按钮时，这个函数将被调用。

# 检查对地理位置 API 的访问权限

现在我们要做的只是检查用户是否有访问地理位置 API 的权限。如果没有，我们希望继续打印一条消息。

我们将创建一个`if`语句。地理位置 API 存在于`navigator.geolocation`上，如果它不存在，我们想运行一些代码：

```js
var locationButton = jQuery('#send-location');
locationButton.on('click', function () {
  if(navigator.geolocation){

  }
});
```

所以我们要翻转它。如果`navigator`上没有地理位置对象，我们要做一些事情。我们将使用`return`来防止函数的其余部分执行，并且我们将调用在所有浏览器中都可用的`alert`函数，弹出一个默认的警报框，让你点击`OK`：

```js
if(navigator.geolocation){
  return.alert()
}
```

我们将使用这个，而不是一个更复杂的模态框。如果你使用类似 Bootstrap 或 Foundation 的东西，你可以实现它们内置的工具。

不过，现在我们将使用`alert`，它只需要一个参数（一个字符串，你的消息）`您的浏览器不支持地理位置`：

```js
var locationButton = jQuery('#send-location');
locationButton.on('click', function ()
  if (!navigator.geolocation) {
    return alert('Geolocation not supported by your browser.');
  }
```

现在，不支持此功能的用户将看到一条小消息，而不是想知道是否真的发生了什么。

# 获取用户的位置

为了实际获取用户的位置，我们将使用地理位置上可用的一个函数。为了访问它，我们将在`locationButton.on`函数中的`if`语句旁边添加`navigator.geolocation.getCurrentPosition`。`getCurrentPosition`函数是一个启动过程的函数。它将主动获取用户的坐标。在这种情况下，它将根据浏览器找到坐标，并且这需要两个函数。第一个是你的`success`函数，我们可以在这里添加我们的第一个回调。这将使用位置信息调用，我们将把这个参数命名为`position`：

```js
  navigator.geolocation.getCurrentPosition(function (position) { 
  } 
}); 
```

`getCurrentPosition`的第二个参数将是我们的错误处理程序，如果出现问题。我们将创建一个`function`，当我们无法使用`alert`获取位置时，我们将向用户发出一条消息。让我们继续调用`alert`第二次，打印一条消息，比如`无法获取位置`：

```js
  navigator.geolocation.getCurrentPosition(function (position) { 

  }, function() {
    alert('Unable to fetch location.');
  });
});
```

这将打印`if`有人被提示与浏览器共享位置，但他们点击了拒绝。我们将说`嘿，如果你不给我们那个权限，我们就无法获取位置`。

现在唯一剩下的情况是成功的情况。这是我们要“发出”事件的地方。但在这之前，让我们继续简单地将其记录到屏幕上，这样我们就可以窥探一下“位置”参数内部发生了什么：

```js
  navigator.geolocation.getCurrentPosition(function (position) {
    console.log(position);
      }, function () {
    alert('Unable to fetch location.');
  });
});
```

我将把这个记录到屏幕上，我们的服务器将重新启动，在 Google Chrome 中，我们可以打开开发者工具，刷新页面，然后点击“发送位置”按钮。现在这将在桌面和移动设备上运行。一些移动浏览器可能需要您使用 HTTPS，这是我们将为 Heroku 设置的内容，正如您所知，Heroku 的 URL 是安全的，这意味着它在本地主机上不起作用。您可以通过将应用程序部署到 Heroku 并在那里运行来测试移动浏览器。不过，现在我将能够点击“发送位置”。这将继续进行该过程；该过程最多可能需要一秒钟：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/95fc6021-4e94-4132-8aac-0c445c9736da.png)

现在您可以看到，我确实获得了我的地理位置。但我从未被询问是否要共享我的位置；那是因为我已经获得了许可。在右上角，我可以点击“清除这些设置以供将来访问”，这意味着我需要重新授权。如果我刷新页面并再次点击“发送位置”，您将看到这个小框，这可能会出现在您的页面上。您可以选择阻止它，如果我阻止它，它将打印“无法获取位置”；或者您可以接受它。

我将再次清除这些设置，刷新页面，这次我将接受位置共享，然后我们将在控制台中打印出地理位置：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/47a485e7-d9ed-43b7-aa3f-cfff1aabe748.png)

现在一旦我们得到它，我们就可以继续深入，对象本身非常简单，我们有一个时间戳，精确记录了我们获取数据的时间，如果您要跟踪用户的活动，这将非常有用，但我们不需要。我们还有我们的坐标，还有一些我们不打算使用的属性，比如“准确度”，“高度”，这些都不存在，还有其他相关的属性。我们还有“速度”，它是`null`。我们将从这个对象中使用的唯一两个是“纬度”和“经度”，它们确实存在。

这是我们想要传递给服务器的信息，以便服务器可以将其发送给其他人。这意味着我们将进入`position`对象，进入`coords`对象，并获取这两个。

# 在用户位置中添加坐标对象

让我们在 Atom 中继续进行，我们将调用`socket.emit`并`emit`一个全新的事件，一个我们尚未注册的事件。我们将称之为`createLocationMessage`：

```js
navigator.geolocation.getCurrentPosition(function (position) {
  socket.emit('createLocationMessage', {
  });
});
```

`createLocationMessage`事件不会采用标准文本；相反，它将采用那些“经度”和“纬度”坐标。我们将指定它们两个，从“纬度”开始；我们要将“纬度”设置为`position.coords.latitude`。这是我们在控制台内探索的变量，我们将对“经度”做同样的操作，将其设置为`position.coords.longitude`：

```js
navigator.geolocation.getCurrentPosition(function (position) {
  socket.emit('createLocationMessage', {
    latitude: position.coords.latitude,
    longitude: position.coords.longitude
  });
```

既然我们已经做好了准备，我们实际上可以继续在服务器上监听这个事件，当我们收到它时，我们要做的是将上述数据传递给所有连接的用户。

# 将坐标数据传递给连接的用户

让我们继续在`server.js`中注册一个新的事件监听器。我将删除旧的已注释掉的`broadcast`调用，因为在`createMessage`中不再需要。就在`createMessage`下面，我们将再次调用`socket.on`，指定一个监听器来监听这个事件`createLocationMessage`，就像我们在`index.js`中定义的那样。现在我们使用 ES6，因为我们在 Node 中，这意味着我们可以设置箭头函数。我们将有一个参数，这将是`coords`，然后我们可以继续完成箭头函数。

```js
  socket.on('createMessage', (message, callback) => { 
    console.log('createMessage', message); 
    io.emit('newMessage', generateMessage(message.from, message.text)); 
    callback('This is from the server.'); 

}); 

  socket.on('createLocationMessage', (coords) => { 

}); 
```

在这里，我们将能够运行任何我们喜欢的代码。目前我们要做的只是通过调用`emit`一个`newMessage`事件传递坐标，尽管在本章的后面，我们将会做得更好，设置谷歌地图的 URL。不过，现在我们要调用`io.emit`，`emit`一个`newMessage`事件，并通过调用`generateMessage`提供必要的数据：

```js
socket.on('createLocationMessage', (coords) => {
  io.emit('newMessage', generateMessage)
});
```

目前，`generateMessage`将采用一些虚假的用户名，我将输入`管理员`，并且我们将设置文本，目前我们只是将其设置为坐标。让我们使用模板字符串来设置它。我们将首先注入`纬度`，它在`coords.latitude`上可用，然后我们将继续添加逗号、空格，然后我们将注入`经度`，`coords.longitude`：

```js
socket.on('createLocationMessage', (coords) => {
  io.emit('newMessage', generateMessage('Admin', `${coords.latitude}, ${coords.longitude}`));
});
```

现在我们已经设置了这个调用，位置信息将在用户之间传递，我们可以继续证明这一点。

在浏览器中，我将刷新此页面，并且我还将打开第二个标签页。在第二个标签页中，我将点击“发送位置”。它不会提示我是否要共享我的位置，因为我已经告诉它我要与这个标签页共享我的位置。您可以看到我们有我们的管理员消息和我们的`纬度`和`经度`：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/c4cd2187-d6cf-48cd-a45d-11e04a1fdbce.png)

我们也在第二个标签页中有它。如果我拿到这些信息，我们实际上可以谷歌一下，证明它按预期工作。在本章的后面，我们将设置一个漂亮的链接，因此这些信息不可见；它会在那里，但用户实际上不需要知道坐标，他们真正想要的是地图的链接。这就是我们要设置的，但现在我们可以把这个放在谷歌上，谷歌会准确显示我们的位置，坐标确实是正确的。我在费城，这意味着这些本地主机标签的位置被正确获取。

# 呈现可点击链接，而不是文本坐标

到目前为止，我们已经让数据流动起来，现在我们要让它变得更有用。我们不再将“纬度”和“经度”信息呈现为文本，而是要呈现为可点击的链接。用户将能够点击该链接；当他们从他人那里收到位置时，它将把他们带到谷歌地图上，他们将能够准确查看其他用户的位置。这比简单输出文本“纬度”和“经度”要有用得多。

为了完成这个，我们需要调整如何传输坐标数据。我们发送数据的方式在`index.js`中仍然可以，我们仍然会`emit`，`createLocationMessage`。但是在`server.js`中，我们不再需要发出新消息，而是需要完全发出其他内容。我们将设置一个名为`newLocationMessage`的新事件，我们将`emit`它，然后在`index.js`中，我们将编写一个处理程序`newLocationMessage`，类似于`newMessage`但有明显不同。它不会呈现一些文本，而是帮助我们呈现一个链接。

# 整理 URL 结构

为了开始之前，我们必须确切地弄清楚我们将使用什么样的 URL 结构来获取数据，`纬度`和`经度`信息，在 Google 地图中正确显示。实际上有一种非常统一的设置 URL 的方式，这将使得这个过程非常容易。

为了向您展示我们将要使用的确切 URL，让我们继续打开一个新标签。URL 将转到`https://www.google.com/maps`。现在从这里我们将提供一个查询参数，查询参数将指定；它被称为`q`：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/8b1d69b0-0c11-4dd7-8938-7f9e30e4807b.png)

它将期望`纬度`和`经度`是由逗号分隔的值。现在我们实际上在`localhost:3000`标签中有这个。虽然逗号之间会有一点空间，但无论如何我们都可以复制该值，返回到另一个标签，粘贴进去，并删除空格。

有了这个，我们现在有一个可以在我们的应用程序中使用的 URL。现在当我按下*enter*，我们将在正确的位置看到地图，但您会注意到 URL 已经改变了。这完全没问题；只要我们将用户发送到这个 URL，它最终变成什么并不重要。我要按下*enter*；您可以立即看到我们得到了一个谷歌地图，当页面加载时，URL 确实会改变。

现在我们看到的与我们输入的完全不同，但实际的图钉，红色的图钉，它在几栋房子内是正确的。有了这个知识，我们可以生成一个遵循相同格式的 URL，在网站内部输出它，我们将有一个可点击的链接，别人可以查看别人的位置。

# 发出 newLoactionMessage

要开始，让我们继续进入 Atom 到`server.js`，而不是发出`newMessage`事件，我们将发出`newLocationMessage`：

```js
socket.on('createLocationMessage', (coords) => { 
  io.emit('newLocationMessage', generateMessage('Admin', `${coords.latitude}, ${coords.longitude}`)); 
});
```

现在我们在`index.js`中没有处理程序，但这完全没问题，我们稍后会在本节中设置。现在我们还需要改变我们发送的数据。目前，我们发送的是纯文本数据；我们想要生成一个 URL。我们实际上将创建一个完全独立的函数来生成位置消息，并且我们将称之为`generateLocationMessage`。

```js
io.emit('newLocationMessage', generateLocationMessage('Admin', `${coords.latitude}, ${coords.longitude}`));
```

现在这个函数将需要一些参数来生成数据；就像我们为`generateMessage`函数所做的那样，我们将从名称开始，然后转到这个函数特定的数据，那将是`纬度`和`经度`。

我要删除我们的模板字符串，我们将传入原始值。第一个值将是`coords.latitude`，第二个值将是`coords.longitude`。现在是第二个坐标值，但确实是第三个参数：

```js
io.emit('newLocationMessage', generateLocationMessage('Admin', coords.latitude, coords.longitude));
```

有了这个参数列表设置，我们实际上可以继续定义`generateLocation`。我们将能够导出它，在这个文件中要求它，然后一切都会按预期工作。让我们继续在添加到消息文件之前在顶部加载它。我们将同时加载`generateLocationMessage`和`generateMessage`：

```js
const {generateMessage, generateLocationMessage} = require('./utils/message');
```

让我们保存`server.js`并进入我们的`message`文件。

# 在 message.js 文件中添加 generateLocationMessage

现在我们即将创建的函数将看起来非常类似于这个，我们将输入一些数据，然后返回一个对象。最大的区别是我们也将生成该 URL。而不是`from`，`text`和`createdAt`，我们将有`from`，`URL`和`createdAt`。

我们可以创建一个新变量，我们可以称这个变量为`generateLocationMessage`，然后我们可以设置它等于一个接受这三个参数`from`，`latitude`和`longitude`的函数：

```js
var generateLocationMessage = (from, latitude, longitude)
```

现在我们可以完成箭头函数(`=>`)添加箭头和我们的花括号，里面我们可以开始通过返回空对象：

```js
var generateLocationMessage = (from, latitude, longitude) => {
  return {

  };
};
```

现在我们将设置来自属性的这三个属性，URL 属性和`createdAt`。这里`from`将很容易；就像我们为`generateMessage`所做的那样，我们只需引用参数。URL 将会有点棘手；现在我们将把它设置为一个空的模板字符串，我们稍后会回来。最后，`createdAt`，我们以前做过；我们将把它设置为通过获取`new Date`并调用`getTime`来获得时间戳：

```js
var generateLocationMessage = (from, latitude, longitude) => {
  return {
    from,
    from,
    url: ``,
    createdAt: new Date().getTime()
  };
};
```

现在对于 URL，我们需要使用刚刚在浏览器中输入的完全相同的格式，[`www.google.com/maps`](https://www.google.com/maps)。然后我们必须设置我们的查询参数，添加我们的问号和`q`参数，将其设置为`latitude`后跟一个逗号，然后是`longitude`。我们将注入`latitude`，添加一个逗号，然后注入`longitude`：

```js
var generateLocationMessage = (from, latitude, longitude) => { 
  return { 
    from, 
    url: `https://www.google.com/maps?q=${latitude},${longitude}`, 
    createdAt: new Date().getTime() 
  }; 
}; 
```

现在我们完成了！`generateLocationMessage`将按预期工作，尽管您稍后将编写一个测试用例。现在我们可以简单地导出它。我将导出`generateLocationMessage`，就像这样：

```js
var generateLocationMessage = (from, latitude, longitude) => { 
  return { 
    from, 
    url: `https://www.google.com/maps?q=${latitude},${longitude}`, 
    createdAt: new Date().getTime() 
  }; 
}; 

module.exports = {generateMessage, generateLocationMessage}; 
```

现在数据将通过调用`emit`从客户端流出，传入`generateLocationMessage`。我们将获取`latitude`和`longitude`。在`server.js`中，我们将使用我们刚刚在`generateLocationMessage`中定义的对象`emit` `newLocationMessage`事件：

```js
socket.on('createLocationMessage', (coords) => {
  io.emit('newLocationMessage', generateLocationMessage('Admin', coords.latitude, coords.longitude));
});
```

# 为`newLocationMessage`添加事件监听器

将最后一块拼图真正使所有这些工作起来的是为`newLocationMessage`事件添加一个事件监听器。在`index.js`中，我们可以调用`socket.on`来做到这一点。我们将传入我们的两个参数。首先是我们想要监听的事件名称`newLocationMessage`，第二个和最后一个参数是我们的`function`。一旦事件发生，这将被调用与`message`信息：

```js
socket.on('newLocationMessage', function (message) { 

}); 
```

现在我们有了这个，我们可以开始生成我们想要输出给用户的 DOM 元素，就像我们上面做的一样，我们将制作一个列表项，并在其中添加我们的锚标签，我们的链接。

我们将创建一个名为`list item`的变量，并使用`jQuery`创建一个新元素。作为第一个参数，我们将传入我们的字符串，并将其设置为列表项：

```js
socket.on('newLocationMessage', function (message) {
  var li = jQuery('<li></li>');
});
```

接下来，我们可以继续创建我们需要的第二个元素。我将创建一个变量，将这个变量称为`a`，用返回值再次设置为对`jQuery`的调用。这一次我们将创建锚标签。现在锚标签使用`a`标签，标签内的内容，那就是链接文本；在我们的情况下，我们将选择`My current location`：

```js
socket.on('newLocationMessage', function (message) {
  var li = jQuery('<li></li>');
  var a = jQuery('<a>My current location</a>');
});
```

现在我们将在锚标签上指定一个属性。这将是一个非动态属性，意味着它不会来自消息对象，这个将被称为`target`，我们将把`target`设置为`"_blank"`：

```js
var a = jQuery('<a target="_blank">My current location</a>');
```

当你将目标设置为`_blank`时，它告诉浏览器在新标签页中打开 URL，而不是重定向当前标签页。如果我们重定向当前标签页，我将被踢出聊天室。如果我点击了其中一个目标设置为`blank`的链接，我们将简单地打开一个新标签页来查看 Google 地图信息：

```js
socket.on('newLocationMessage', function (message) { 
  var li = jQuery('<li></li>'); 
  var a = jQuery('<a target="_blank">My current location</a>'); 

}); 
```

接下来，我们将设置这些属性的一些属性。我们将使用`li.text`设置文本。这将让我们设置人的名字以及冒号。在模板字符串中，我们将注入值`message.from`。在该值之后，我们将添加一个冒号和一个空格：

```js
var a = jQuery('<a target="_blank">My current location</a>');

li.text(`${message.from}: `);
```

接下来，我们将继续更新我们的锚标签，`a.attr`。你可以使用这种方法在你选择的 jQuery 元素上设置和获取属性。如果你提供一个参数，比如`target`，它会获取值，这种情况下它会返回字符串`_blank`。如果你指定两个参数，它实际上会设置值。在这里，我们可以将`href`的值设置为我们在`message.url`下的 URL：

```js
li.text(`${message.from}: `);
a.attr('href', message.url)
```

现在你会注意到，对于所有这些动态值，我不是简单地将它们添加到模板字符串中。相反，我使用这些安全方法，比如`li.text`和`a.attribute`。这可以防止任何恶意行为；如果有人试图注入 HTML，他们不应该使用这段代码进行注入。

有了这个，我们现在可以将锚标签附加到列表项的末尾，这将在我们使用`li.append`设置文本后添加它，并且我们将附加锚标签。现在我们可以使用完全相同的语句将所有这些添加到 DOM 中，以便在`newLocagtionMesaage`事件监听器中进行复制和粘贴：

```js
socket.on('newLocationMessage', function (message) {
  var li = jQuery('<li></li>');
  var a = jQuery('<a target="_blank">My current location'</a>);

  li.text(`${message.from}: `);
  a.attr('href', message.url);
  li.append(a);
  jQuery('#messages').append(li);
});
```

有了这个，我们就完成了。现在我要保存`index.js`并在浏览器中重新启动。我们做了很多改动，所以如果你有一些拼写错误也没关系；只要你能找到它们，就没什么大不了的。

我将在 Chrome 浏览器中刷新我的两个标签页；这将使用最新的客户端代码启动新的连接，并开始发送一个简单的消息从第二个标签到第一个标签。它在第二个标签中显示出来，如果我切换到第一个标签，我们会看到用户：测试。现在我可以点击“发送位置”，这将花费一到三秒钟来获取位置。然后它将通过`Socket.io`链，我们得到了什么？我们得到了链接“我的当前位置”显示给用户一：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/d5a7b4c9-9e97-44e3-a1c2-421e7aac51f2.png)

对于用户二也是一样。现在如果我点击那个链接，它应该在一个全新的标签页中打开，里面包含正确的 URL、`纬度`和`经度`信息。

就在这里，我们有了点击“发送位置”按钮的用户的位置。有了这个，我们有了一个很棒的地理位置功能。你所要做的就是点击按钮；它会获取你当前的位置，无论你在哪里，然后渲染一个可点击的链接，这样任何其他人都可以在 Google 地图中查看它。现在在我们离开之前，我希望你为这个全新的`generateLocationMessage`函数添加一个单独的测试用例。

# 为`generateLocationMessage`添加测试用例

在终端中，我可以关闭服务器并使用`clear`来清除输出。如果我使用`npm test`运行我们的测试套件，我们会看到我们有一个测试，并且它通过了：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/da8ce85e-06f6-43db-8b43-970298c45298.png)

你的工作是在`message.test.js`中添加第二个测试用例。

我们将一起开始。就在这里，我们将添加一个`describe`块，描述`generateLocationMessage`函数，你将负责在回调函数内添加一个测试用例：

```js
describe('generateLocationMessage', () => {

});
```

在这里，你将调用`it ('should generate correct location object')`。接下来，我们可以继续添加我们的函数，这将是一个同步测试，所以不需要添加`done`参数：

```js
describe('generateLocationMessage', () => {
  it('should generate correct location object', () => {

  });
});
```

现在，我们将编写一个与`generateMessage`事件非常相似的测试用例，尽管不是传递`from`和`text`，而是传递`from`、`latitude`和`longitude`。然后你将对返回的值进行一些断言。然后我们将运行测试用例，确保一切都通过了终端。

# 为测试用例添加变量

首先，我将创建两个变量。我将创建一个`from`变量，并将其设置为`Deb`之类的内容。然后我们可以继续创建一个`latitude`变量，我将其设置为`15`。然后我们可以创建一个`longitude`变量，将其设置为`19`之类的内容：

```js
describe('generateLocationMessage', () => {
  it('should generate correct location object', () => {
    var from = 'Deb';
    var latitude = 15;
    var longitude = 19;
  });
});
```

然后我将最终创建一个`url`变量。`url`变量将是最终结果，我期望得到的 URL。现在该 URL 将在引号内[`www.google.com/maps`](https://www.google.com/maps)，然后我们将根据我们要传入的信息添加适当的查询参数。如果纬度是`15`，我们期望在等号后得到`15`，如果经度是`19`，我们期望在逗号后得到`19`：

```js
describe('generateLocationMessage', () => {
  it('should generate correct location object', () => {
    var from = 'Deb';
    var latitude = 15;
    var longitude = 19;
    var url = 'https://www.google.com/maps?q=15,19';
  });
});
```

现在我们已经准备好了，我们可以调用我们的函数存储响应。我将创建一个名为`message`的变量，然后我们将调用`generateLocationMessage`，目前不需要，我们可以在下一秒钟内完成。然后我们将传入我们的三个参数`from`，`latitude`和`longitude`：

```js
describe('generateLocationMessage', () => {
  it('should generate correct location object', () => {
    var from = 'Deb';
    var latitude = 15;
    var longitude = 19;
    var url = 'https://www.google.com/maps?q=15,19';
    var message = generateLocationMessage(from, latitude, longitude);
  });
});
```

现在让我们继续并且也执行`generateLocationMessage`和`generateMessage`：

```js
var expect = require('expect');

var {generateMessage, generateLocationMessage} = require('./message');
```

现在唯一剩下的事情就是进行我们的断言。

# 为`generateLocationMessage`进行断言

我们将以类似的方式开始。我实际上要将这两行从`generateMessage`复制到`generateLocationMessage`的测试用例中：

```js
expect(message.createdAt).toBeA('number');
expect(message).toInclude({from, text});
```

我们期望`message.createdAt`属性是一个数字，它应该是，然后我们期望消息包含一个`from`属性等于`Deb`，我们期望它有一个`url`属性等于我们定义的`url`字符串：

```js
describe('generateLocationMessage', () => {
  it('should generate correct location object', () => {
    var from = 'Deb';
    var latitude = 15;
    var longitude = 19;
    var url = 'https://www.google.com/maps?q=15,19';
    var message = generateLocationMessage(from, latitude, longitude);

    expect(message.createdAt).toBeA('number');
    expect(message).toInclude({from, url});
  });
});
```

如果这两个断言都通过了，那么我们就知道从`generateLocationMessage`返回的对象是正确的。

# 运行`generateLocationMessage`的测试用例

我将在终端中重新运行测试套件，一切都应该如预期般工作：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/21812fff-2637-4f3a-8b45-0be53bdc281f.png)

就是这样了！我们已经设置好了地理位置，我们的链接已经呈现，我们可以继续进行。我将在终端中添加一个`commit`。我将运行`clear`命令来清除`Terminal`输出，然后我们将运行`git status`来查看所有更改的文件，然后我们可以使用`git commit`和`-am`标志为此添加一条消息，`Add geolocation support via geolocation api`：

```js
git commit -am 'Add geolocation support via geolocation api'
```

我将继续提交并将其推送到 GitHub，并且我们还可以花一点时间将其部署到 Heroku，使用`git push heroku master`。

这将部署我们最新的代码，其中包含地理位置信息。我们将能够运行此代码，因为我们将在 HTTPS 上运行，这将在 Chrome 移动浏览器等上运行。Google Chrome 的移动浏览器和其他移动浏览器对何时发送地理位置信息有相当严格的安全准则。它需要通过 HTTPS 连接，这正是我们现在所拥有的。我将在几个标签中打开我们的 Heroku 应用程序。我们将在标签一中打开它，然后在第二个标签中也打开它。我将点击“发送位置”按钮。我需要批准这一点，因为它是不同的 URL，是的，我希望他们能够使用我的位置。它将获取位置，发送位置，第一个标签获取链接。我点击链接，希望我们得到相同的位置。

# 总结

在本章中，我们致力于生成文本和位置消息。我们研究了生成`newMessage`对象，然后为其编写了一个测试用例。然后，我们学习了如何使用事件确认。然后我们添加了消息表单字段，并在屏幕上呈现了一个输入字段和一个按钮。我们还讨论了 jQuery 的概念，并使用它来选择和创建传入消息元素。

在地理位置部分，我们为用户提供了一个新按钮。这个新按钮允许用户发送他们的位置。我们为发送位置按钮设置了一个`click`监听器，这意味着每当用户点击它时，我们会根据他们对地理位置 API 的访问执行一些操作。如果他们没有访问地理位置 API，我们只是打印一条消息。如果他们有访问权限，我们会尝试获取位置。

在下一章中，我们将研究如何为我们的聊天页面设置样式，使其看起来更像一个真正的网络应用程序。


# 第七章：将我们的聊天页面设置为 Web 应用程序

在上一章中，您了解了 Socket.io 和 WebSockets，它们使服务器和客户端之间实现了双向通信。在本章中，我们将继续讨论如何为我们的聊天页面设置样式，使其看起来更像一个真正的 Web 应用程序。我们将研究时间戳和使用 Moment 方法格式化时间和日期。我们将创建和渲染`newMessage`和`newLocation`消息的模板。我们还将研究自动滚动，使聊天不那么烦人。

# 设置聊天页面的样式

在这一部分，我们将设置一些样式，使我们的应用看起来不那么像一个未经样式处理的 HTML 页面，而更像一个真正的 Web 应用程序。现在在下面的截图中，左边是 People 面板，虽然我们还没有连接它，但我们已经在页面中给它了一个位置。最终，这将存储连接到个人聊天室的所有人的列表，这将在稍后完成。

在右侧，主要区域将是消息面板：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/9a3f33b5-d119-46c8-8f60-fa0e1285ac9c.png)

现在个别的消息仍然没有样式，这将在稍后完成，但我们有一个放置所有这些东西的地方。我们有我们的页脚，这包括我们发送消息的表单，文本框和按钮，还包括我们的发送位置按钮。

现在为了完成所有这些，我们将添加一个我为这个项目创建的 CSS 模板。我们还将向我们的 HTML 添加一些类；这将让我们应用各种样式。最后，我们将对我们的 JavaScript 进行一些小的调整，以改善用户体验。让我们继续深入。

# 存储模板样式

我们要做的第一件事是创建一个新文件夹和一个新文件来存储我们的样式。这将是我们马上要获取的模板样式，然后我们将加载它到`index.html`中，这样在渲染聊天应用程序时就会使用这些样式。

现在我们要做的第一件事是在`public`中创建一个新文件夹，将这个文件夹命名为`css`。我们将向其中添加一个文件，一个名为`styles.css`的新文件。

现在在我们去获取任何样式之前，让我们将这个文件导入到我们的应用程序中，并为了测试和确保它工作，我们将编写一个非常简单的选择器，我们将使用`*`选择所有内容，然后在大括号内添加一个样式，将所有内容的`color`设置为`red`：

```js
* {
   color: red;
}
```

继续制作你的文件，就像这个一样，我们将保存它，然后在`index.html`中导入它。在`head`标签的底部跟随我们的`meta`标签，我们将添加一个`link`标签，这将让我们链接一个样式表。我们必须提供两个属性来完成这个操作，首先我们必须告诉 HTML 我们要链接到什么，通过指定`rel`或关系属性。在这种情况下，我们要链接一个`style sheet`，所以我们将提供它作为值。现在我们需要做的下一件事是提供`href`属性。这类似于`script`标签的`src`属性，它是要链接的文件的路径。在这种情况下，我们在`/css`中有一个`styles.css`文件：

```js
<head>
  <meta charset="utf-8">
  <link rel="stylesheet" href="/css/styles.css">
</head>
```

现在我们可以保存`index.html`，在浏览器中刷新页面或者首次加载页面，我们看到的是一个丑陋的页面：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/6d31f100-5cd6-410c-bb6c-8d752975e20a.png)

我们设法使它比以前更丑，但这很好，因为这意味着我们的样式表文件被正确导入了。

为了获取我们将在聊天应用程序中使用的实际模板，我们将访问一个 URL，[`links.mead.io/chat-css`](http://links.mead.io/chat-css)。这只是一个将重定向您到一个 Gist 的 bitly 链接，这里有两个选项，我们可以获取压缩的样式模板或未压缩的样式模板：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/4306879d-b4db-4cc9-ad71-c78af27bcbeb.png)

我将继续获取压缩的文件，可以通过高亮它或点击原始链接来获取，这将带我们到文件。我们将获取我们在那里看到的全部内容，然后转到 Atom 并将其粘贴到我们的`styles.css`文件中，显然删除之前的选择器。

现在我们已经完成了这一步，我们可以刷新页面，尽管我们不会看到太多改进。在`localhost:3000`中，我将刷新浏览器，显然事情已经有所不同：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/3c2a1846-aa3b-4702-907f-b8890f1494ae.png)

这是因为我们需要在我们的 HTML 中应用一些类，以便一切都能正确工作。

# 调整结构以对齐

我们需要调整结构，添加一些容器元素来帮助对齐。在 Atom 中，我们可以在短短几分钟内完成这项工作。这个模板是围绕一些关键类构建的。第一个类需要应用到`body`标签上，通过将`class`属性设置为，引号内的`chat`：

```js
<body class="chat">
```

这告诉样式表为这个聊天页面加载这些样式，我们将继续删除`Welcome to the chat app`，这已经不再需要了。现在我们要做的下一件事是创建一个`div`标签，这个`div`将包含我们在左侧看到的`People`列表。目前它是空的，但没关系，我们仍然可以继续创建它。

我们将创建一个`div`，并给这个`div`添加一个类，这个`class`将被设置为`chat__sidebar`：

```js
<body class ="chat">

  <div class="chat">

  </div>
```

这是一种在一些样式表模板中使用的命名约定，这实际上是一个偏好的问题，当你创建样式表时，你可以随意命名它，我碰巧称它为`chat__sidebar`。这是一个更大的聊天应用程序中的子元素。

现在在`div`标签中，我们将使用`h3`标签添加一个小标题，我们将给它一个标题`People`，或者你想给侧边栏列表起的任何名字，我们还将提供一个`div`，最终将包含个人用户，尽管我提到我们暂时不会将其连接起来。现在我们可以给它一个`id`，将其设置为`users`，这样我们稍后就可以定位它。这就是我们目前聊天侧边栏所需要的一切：

```js
<div class ="chat__sidebar">
  <h3>People</h3>
  <div id="user"></div>
</div>
```

接下来，我们要做的是创建一个`div`标签，这个`div`将包含主要区域，这意味着它不仅包含我们的聊天消息，还包含底部的小表单，以及侧边栏右侧的所有内容。

这也需要为一些样式创建一个自定义类，这个类叫做`chat__main`，在这里我们不仅要添加无序列表，还要添加我们的`form`和`button`。让我们继续拿出我们当前的标记，从无序列表到发送位置按钮，把它剪切出来，粘贴到`chat__main`中：

```js
<div class="chat__main">
  <ol id="messages"></ol>

  <form id="message-form">
    <input name="message" type="text" placeholder="Message"/>
    <button>Send</button>
  </form>
  <button id="send-location">Send Location</button>
</div>
```

现在我们还没有完成，还有一些需要调整的地方。首先，我们必须为我们的有序列表添加一个类，我们将把`class`设置为`chat__messages`，这将提供必要的样式，我们需要创建的最后一个`div`是底部的灰色条，其中包含`form`和`Send Location`按钮。我们将创建一个`div`来帮助对齐，并且我们将把`form`和`button`标签放在里面，通过剪切并粘贴到有序列表的`div`中：

```js
<div class="chat__main">
  <ol id="messages" class="chat__messages"></ol>

  <form id="message-form">
    <input name="message" type="text" placeholder="Message"/>
    <button>Send</button>
  </form>
  <button id="send-location">Send Location</button>
</div>
```

现在我们也需要在这里添加一个类，正如你可能已经猜到的那样，将`class`属性设置为字符串`chat__footer`：

```js
<div class="chat__footer">
  <form id="message-form">
    <input name="message" type="text" placeholder="Message"/>
    <button>Send</button>
  </form>
  <button id="send-location">Send Location</button>
</div>
```

现在我们所有的类都已经就位，我们可以转到浏览器，看看当我们刷新页面时会得到什么。

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/53cf8f51-0996-4d47-bb0a-6107bcca7226.png)

我们有我们样式化的聊天应用程序，我们仍然可以做以前能做的任何事情。我可以发送一条消息，`嘿，这应该仍然有效`，按*enter*，`嘿，这应该仍然有效`会显示在屏幕上：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/62ddfd76-dcec-4f81-b919-975b667317d1.png)

对于发送位置也是一样，我可以发送我的位置，这会发送到服务器，发送到所有客户端，我可以点击我的当前位置链接，位置会显示在 Google 地图上。我们保留了所有旧的功能，同时添加了一套漂亮的样式：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/789c941c-cddd-4baf-b710-d5bd55b0ff1b.png)

# 改进用户体验

现在在本节的第二部分中，我想对表单进行一些用户体验改进。

我们要做的一个改进是在成功发送消息后清除文本值。我们还将对发送位置做类似的操作。正如你可能已经注意到的，发送位置的地理位置调用实际上可能需要一秒或两秒的时间才能完成，我们将禁用此按钮，以防有人不知道发生了什么而进行垃圾邮件式的点击。我们还将更新文本，以便显示`正在发送位置`，这样某人就知道背景中正在发生一些事情。

为了完成这两件事，我们只需要修改`index.js`内的几行。在文件底部附近，我们有两个 jQuery 事件监听器，这两个都将被更改。

# 更改表单提交监听器

现在我们要改变的第一件事是表单提交监听器。在`socket.emit`中，我们从字段中获取值，这就是我们传递的值。接下来我们想要做的是在确认回调函数内清除该值。一旦服务器接收到请求，就没有理由继续保留它，所以我们可以添加相同的`jQuery`选择器，定位`name`属性等于`message`的字段。我们将继续通过再次调用`val`来清除它的值，但是不同于不提供参数获取值，我们将通过传递空字符串作为第一个参数来将值设置为空字符串：

```js
jQuery('#message-form').on('submit', function (e) {
  e.prevenDefault();

  var messageTextbox =

  socket.emit('createMessage', {
    from: 'User',
    text: jQuery('[name=message]').val()
 }, function () {
    jQuery('[name=message]').val('')
  });
});
```

你可以将值设置为任何你喜欢的东西，但在这种情况下，我们只想清除它，所以我们将使用以下方法调用。

我们两次使用相同的选择器以加快速度，我们将创建一个变量，我们将称该变量为`messageTextbox`，然后我们可以将其设置为我们刚刚创建的选择器，现在我们可以在任何需要访问该输入的地方引用`messageTextbox`。我们可以像这样引用它，`messageTextbox`，接下来，`messageTextbox`：

```js
var messageTextbox = jQuery('[name=message]'); 

socket.emit('createMessage', { 
  from: 'User', 
  text: messageTextbox.val() 
}, function() { 
  messageTextbox.val('') 
}); 
```

现在`createMessage`的监听器，位于`server.js`内，我们确实使用一个字符串调用回调函数。现在，我们将只是删除那个虚假的传递零参数的值，就像这样：

```js
socket.broadcast.emit('newMessage', generateMessage('Admin, 'New user joined'));

socket.on('createMessage', (message, callback) => {
  console.log('createMessage', message);
  io.emit('newMessage', generateMessage(message.form, message.text));
  callback();
});
```

这意味着确认函数仍然会被调用，但实际上我们不需要任何数据，我们只需要知道服务器何时响应。现在我们已经做好了，我们可以继续在`localhost:3000`内刷新，输入一条消息，`这是一条消息`，然后按下*enter*键，我们会得到清除的值，而且确实已经发送了：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/bddd95fd-11ce-469d-b628-ccda5ee99506.png)

如果我输入一条消息，`安德鲁`，然后点击发送按钮，同样的事情也会发生。

# 更新输入标签

现在我们要做的一件事是快速更新文本框的`input`标签。如果我刷新页面，我们当前并没有直接进入消息字段，这样做会很好。关闭自动完成也会很好，因为你可以看到，自动完成并不是一个有用的功能，里面的值通常都是垃圾。

在 Atom 内部，我们要做的是添加两个属性来自定义输入。第一个是`autofocus`，它不需要一个值，当 HTML 被渲染时，`autofocus`会自动对焦在输入上，第二个我们要添加的是`autocomplete`，我们将把它设置为字符串`off`：

```js
<div class="chat__footer">
<form id="message-form">
  <input name="message" type="text" placeholder="Message" autofocus autocomplete="off"/>
  <button>Send</button>
<form>
<button id="send-location">Send Location</button>
```

有了这个设置，我们可以保存`index.html`，回到 Chrome，刷新页面并测试一下。我会输入`test`，我们没有自动完成，这很好，我们关闭了它，如果我点击发送按钮，我确实还在发送消息。当我重新加载页面时，我也直接进入了文本框，我不需要做任何事情就可以开始输入。

# 自定义发送位置

接下来我们要做的是使用更多的 jQuery 来自定义发送位置按钮。现在我们对 jQuery 还不太熟悉，这也不是一个 jQuery 课程。这里的目标是改变按钮文本，并在进行过程时禁用它。当过程完成时，也就是位置被发送或未发送时，我们可以将按钮恢复到正常状态，但在地理位置调用发生时，我们不希望有人不断点击。

为了完成这个任务，我们将对`index.js`中的最终监听器进行一些调整，在我们的提交监听器旁边，我们有一个点击监听器。在这里，我们需要对按钮进行一些更改，我们定义的`locationButton`变量。我们将设置一个属性来禁用按钮。

为了完成这个任务，我们将引用选择器`locationButton`，并调用一个 jQuery 方法。

现在我们只会在确认他们甚至支持它之后禁用它，如果他们不支持这个功能，就没有理由去禁用它。在这里，`locationButton.attr`将让我们设置一个属性，我们将把`disabled`属性设置为值`disabled`。现在这个`disabled`也需要加上引号：

```js
var locationButton = jQuery('#send-location');
locationButton.on('click', function () {
  if (!navigator.geolocation) {
    return alert('Geolocation not supported by your browser.');
  }

  locationButton.attr('disabled', 'disabled');
```

现在我们已经禁用了按钮，我们可以实际测试一下，我们从未取消禁用它，所以在点击一次后它就会出现问题，但我们可以确认这行代码有效。在浏览器中，我将刷新一下，点击发送位置，你会立刻看到按钮被禁用了：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/c72cf1b4-68f0-40ff-94b9-981ea76ab097.png)

现在它会发送位置一次，但如果我再试图点击它，按钮就会被禁用，永远不会再次触发`click`事件。这里的目标是只在实际发生过程中禁用它，一旦像这样发送了，我们希望重新启用它，这样别人就可以发送更新的位置。

为了在 Atom 内部完成这个任务，我们将在成功处理程序和错误处理程序中添加一行 jQuery。如果事情进展顺利，我们将引用`locationButton`，并使用`removeAttr`来移除禁用属性。这只需要一个参数，属性的名称，在这种情况下，我们有一个字符串`disabled`：

```js
locationButton.attr('disabled', 'disabled');

navigator.geolocation.getCurrentPosition(function (position) {
  locationButton.removeAttr('disabled');
  socket.emit('createLocationMessage', {
    latitude: position.coords.latitude,
    longitude: position.coords.longitude
  });
```

这将移除我们之前定义的`disabled`属性，重新启用按钮。我们可以做完全相同的事情，简单地复制并粘贴下一行到`function`中。如果由于某种原因我们无法获取位置，也许用户拒绝了对地理位置的请求，我们仍然希望禁用该按钮，以便他们可以再次尝试：

```js
navigator.geolocation.getCurrentPosition(function (position){ 
  locationButton.removeAttr('disabled'); 
  socket.emit('createLocationMessage', { 
    latitude: position.coords.latitude, 
    longitude: position.coords.longitude 
  }); 
}, function(){ 
   locationButton.removeAttr('disabled');
   alert('Unable to fetch location'); 
}); 
```

现在我们已经设置好了，我们可以通过刷新浏览器并尝试发送我们的位置来测试该代码。我们应该看到按钮在一小段时间内被禁用，然后重新启用。我们可以点击它来证明它按预期工作，并且按钮已重新启用，这意味着我们可以在以后的时间再次点击它发送我们的位置。

# 更新按钮文本

现在我们要做的最后一件事是在过程发生时更新按钮文本。为了完成这个任务，在 Atom 中我们将使用过去使用过的`text`方法。

在`locationButton.attr`行中，我们将把`text`属性设置为`Sending location...`。现在，在`index.js`文件中，真正的按钮文本是`Send Location`，我将把`location`转换为小写以保持统一。

```js
var locationButton = jQuery('#send-location');
locationButton.on('click', function (){
  if (!navigator.geolocation){
    return alert('Geolocation not supported by your browser.');
  }
  locationButton.attr('disabled', 'disabled').text('Sending location...');
```

现在我们已经设置好了，我们正在更新过程发生时的文本，唯一剩下的事情就是通过将`text`设置为字符串`Send location`来将其调整回原始值，我们将在错误处理程序中做完全相同的事情，调用`text`传入字符串`Send location`：

```js
locationButton.attr('disabled', 'disabled').text('Sending location...'); 

navigator.geolocation.getCurrentPosition(function (position){ 
  locationButton.removeAttr('disabled').text('Send location'); 
  socket.emit('createLocationMessage', { 
    latitude: position.coords.latitude, 
    longitude: position.coords.longitude 
  }); 
}, function(){ 
    locationButton.removeAttr('disabled').text('Send location'); 
    alert('Unable to fetch location'); 
}); 
```

现在我们可以继续测试这是否按预期工作，这两行（成功和错误处理程序中）是相同的，无论成功与否，我们都会做同样的事情。

在 Chrome 中，我将再次刷新我的页面，我们将点击发送位置按钮，您可以看到按钮被禁用并且文本已更改，显示“正在发送位置...”：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/5a9f7e91-19f8-4de8-863f-b3c48283d145.png)

一旦过程完成并且位置实际上已发送，按钮将返回到其默认状态。

有了这个设置，我们现在比以前有了更好的用户体验。我们不仅拥有一套漂亮的样式，还为我们的表单和发送位置按钮提供了更好的 UI。这就是我们在本节中要停止的地方。

让我们继续通过关闭服务器，运行`git status`，运行`git add .`来快速提交所有这些文件，最后我们将继续运行`git commit`，并使用`-m`标志提供消息，`Add css for chat page`：

```js
**git commit -m 'Add css for chat page'**
```

我们可以使用`git push`将其推送到 GitHub，并且我现在不打算部署到 Heroku，尽管您可以部署并测试您的应用程序。

# Moment 中的时间戳和格式化

在整个课程中，我们已经相当多地使用了时间戳，在待办事项应用程序中生成了它们，并且在聊天应用程序中为所有消息生成了它们，但我们从未将它们格式化为可读的形式。这将是本节的主题，在下一节中我们将把它付诸实践。

到下一节结束时，我们将拥有一个格式化的消息区域，其中包括名称、时间戳和消息，并且我们也将为其提供一些更好的样式。现在在本节中，一切都将围绕时间和时间戳展开，我们不会对应用程序的前端进行任何更改，我们只是要学习 Node 中的时间是如何工作的。

# Node 中的时间戳

为了探索这一点，我们将创建一个新的`playground`文件，在 Atom 中我们将创建一个`playground`文件夹来存储这个文件，在`playground`文件夹中我们可以创建一个名为`time.js`的新文件。在这里，我们将玩转时间，并将在下一节将我们在这里学到的内容带入应用程序的前端。

我们对时间戳并不陌生，我们知道它们只是整数，无论是正数还是负数，像`781`这样的数字是一个完全有效的时间戳，就像几十亿或任何数字一样，所有都是有效的，甚至`0`也是一个完全有效的时间戳。现在所有这些数字都是相对于历史上的某一时刻的，这个时刻被称为 Unix 纪元，即 1970 年 1 月 1 日午夜 0 时 0 分 0 秒。这是存储在 UTC 中的，这意味着它与时区无关：

```js
// Jan 1st 1970 00:00:00 am

0
```

现在我的时间戳`0`实际上完美地代表了历史上的这一刻，而像 1000 这样的正数则表示未来，而像-1000 这样的负数则表示过去。时间戳-1000 将代表 1969 年 12 月 31 日 11 点 59 分 59 秒，我们已经从 1970 年 1 月 1 日过去了一秒。

现在，在 JavaScript 中，这些时间戳以毫秒存储自 Unix 纪元以来的时间，而在常规的 Unix 时间戳中，它们实际上是以秒存储的。由于我们在本课程中使用 JavaScript，我们将始终使用毫秒作为我们的时间戳值，这意味着像 1000 这样的时间戳代表了 1 月 1 日的一秒，因为一秒钟有 1000 毫秒。

像 10000 这样的值将是这一天的十秒，依此类推。现在对我们来说，问题从来不是获取时间戳，获取时间戳非常容易，我们只需要调用`new Date`调用它的`getTime`方法。然而，当我们想要格式化一个类似于之前的人类可读值时，情况将变得更加困难。

我们将要在我们的 Web 应用程序中打印一些不仅仅是时间戳的东西，我们将要打印一些像五分钟前这样的东西，让用户知道消息是五分钟前发送的，或者你可能想打印实际的日期，包括月份、日期、小时、分钟和上午或下午的值。无论你想打印什么，我们都需要谈一谈格式化，这就是默认的`Date`对象不足的地方。

是的，有一些方法可以让你从日期中获取特定的值，比如年份、月份或日期，但它们非常有限，定制起来是一个巨大的负担。

# 日期对象

要讨论确切的问题，让我们继续查看日期的文档，通过谷歌搜索`mdn date`，这将带我们到 Mozilla 开发者网络文档页面上的*Date*，这是一个非常好的文档集：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/a5e48e45-f523-4562-8de3-e78d4b060e5c.png)

在这个页面上，我们可以访问所有可用的方法，这些方法都类似于`getTime`，返回关于日期的特定信息：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/c353a7e9-2a2a-41e1-862f-cb4f97496086.png)

例如，如前面的屏幕截图所示，我们有一个`getDate`方法，返回月份的日期，一个从 1 到 31 的值。我们有像`getMinutes`这样的方法，返回时间戳的当前分钟数。所有这些都存在于`Date`中。

现在问题是这些方法非常不灵活。例如，在 Atom 中，我们有这个小日期，`1970 年 1 月 1 日 00:00:10`。这是 1 月的简写版本。现在我们可以获取实际的月份来展示给你，我们将创建一个名为`date`的变量。我们将创建`new Date`，然后我们将调用一个方法。我将使用`console.log`将值打印到屏幕上，我们将调用`date.getMonth`：

```js
// Jan 1st 1970 00:00:10 am

var date = new Date();
console.log(date.getMonth());
```

如文档中所定义的`getMonth`方法将返回一个基于 0 的月份值，从 0 到 11，其中 0 是一月，11 是十二月。在终端中，我将使用`nodemon`启动我们的应用程序，因为我们将经常重启它。Nodemon 在`playground`文件夹中而不是`server`文件夹中，文件本身称为`time.js`：

```js
**nodemon playground/time.js**
```

一旦它运行起来，我们看到我们得到了`2`，这是预期的：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/701c0e5c-0ba2-4507-8477-803d6720a833.png)

现在是 2018 年 3 月 25 日，而 3 月的`0`索引值将是`2`，尽管你通常认为它是 3。

现在前面的结果很好。我们有数字 2 来表示月份，但要获得实际的字符串 Jan 或 January 将会更加困难。没有内置的方法来获取这个值。这意味着如果你想要获得这个值，你将不得不创建一个数组，也许你称这个数组为`months`，并且存储所有这样的值：

```js
var date = new Date();
var months = ['Jan', 'Feb']
console.log(date.getMonth());
```

这将是很好的，对于月份可能看起来并不是那么重要，但是对于月份的日期，比如我们有的`1st`，我们只能得到数字 1。实际上将其格式化为 1st、2nd 或 3rd 将会更加困难。对于格式化日期，确实没有一个好的方法集。

当你想要一个相对时间字符串时，事情变得更加复杂，比如三分钟前。在 web 应用程序中打印这个信息会很好，打印实际的月份、日期和年份并不特别有用。如果我们能够说，嘿，这条消息是三小时前发送的，三分钟前发送的，或者三年前发送的，就像很多聊天应用程序所做的那样，那就太酷了。

# 使用 Moment 进行时间戳

现在当你涉及到这样的格式化时，你的第一反应通常是创建一些实用方法来帮助格式化日期。但是没有必要这样做，因为我们在这一部分要看的是一个名为**Moment**的了不起的时间库。Moment 几乎是其类别中唯一的库。它被普遍认为是处理时间和 JavaScript 的首选库，我从来没有在一个没有使用 Moment 的 Node 或前端项目上工作过，当你以任何方式处理日期时，它确实是必不可少的。

为了展示 Moment 为什么如此出色，我们首先要在终端内安装它。然后我们将玩弄它的所有功能，它有很多。我们可以通过运行`npm i`来安装它，我将使用当前版本`moment@`版本`2.21.0`，并且我还将使用`--save`标志将其添加为一个依赖项，这是我们在 Heroku 上以及本地都需要的一个依赖项：

```js
**npm i moment@2.21.0 --save**
```

一旦它安装好了，我可以使用`clear`来清除终端输出，然后我们可以继续重新启动`nodemon`。在`playground`文件夹内，是时候引入 Moment 并且看看它对我们能做什么。

首先，让我们试着解决我们之前尝试解决日期问题。我们想要打印月份的简写版本，比如 Jan、Feb 等。第一步将是将之前的代码注释掉，并在顶部加载之前的 Moment，需要它。我将创建一个名为`moment`的变量，并通过`require`来加载`moment`库：

```js
var moment = require('moment');

// Jan 1st 1970 00:00:10 am

//var date = new Date();
//var months = ['Jan', 'Feb']
//console.log(date.getMonth());
```

然后在这段代码旁边，我们将通过创建一个新的 moment 来开始。现在就像我们创建一个新的日期来获得一个特定的日期对象一样，我们将用 moment 做同样的事情。我将把这个变量称为`date`，并且我们将把它设置为调用`moment`的结果，之前我们加载的函数，不带任何参数：

```js
var moment = require('moment');

// Jan 1st 1970 00:00:10 am

//var date = new Date();
//var months = ['Jan', 'Feb']
//console.log(date.getMonth());

var date = moment();
```

这将创建一个代表当前时间点的新 moment 对象。从这里，我们可以尝试使用它非常有用的`format`方法来格式化东西。`format`方法是我喜欢 Moment 的主要原因之一，它使得打印任何你想要的字符串变得非常简单。现在在这种情况下，我们可以访问我们的`date`，然后我们将调用我刚才谈到的方法，`format`：

```js
var moment = require('moment');
var date = moment(); 
console.log(date.format());
```

在我们讨论传递给格式的内容之前，让我们继续运行它就像这样。当我们在终端内运行时，`nodemon`将会重新启动自己，然后我们就有了我们格式化后的日期：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/09dfe202-8b94-4d2e-9148-910bc280f381.png)

我们有年份、月份、日期和其他值。它仍然不是非常用户友好，但这是朝着正确方向迈出的一步。`format`方法的真正威力是当你在其中传递一个字符串时。

现在我们传递到格式方法中的是模式，这意味着我们可以访问一组特定的值，我们可以用来输出某些东西。我们将在接下来的一秒钟内探索所有可用的模式。现在，让我们继续使用一个；就是三个大写的`M`模式：

```js
var date = moment(); 
console.log(date.format('MMM'));
```

当 Moment 看到格式中的这个模式时，它将继续抓取月份的简写版本，这意味着如果我保存这个文件，并再次在终端中重新启动它。我们现在应该看到当前月份九月的简写版本，即`Mar`：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/7f448c25-b528-4178-a784-c7e91e0edb68.png)

这里我们得到了`Sep`，正如我们所期望的那样，我们能够通过使用格式方法来简单地实现这一点。现在格式返回一个字符串，其中只包含你指定的内容。在这里，我们只指定了我们想要月份的简写版本，所以我们得到的只是月份的简写版本。我们还可以添加另一个模式，四个 Y，它打印出完整的年份；在当前情况下，它将以数字形式打印出 2016：

```js
console.log(date.format('MMM YYYY')); 
```

我将继续节省时间，这里我们得到了`Mar 2018`：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/f4841c9e-078c-442a-aabb-c73d488643ad.png)

现在 Moment 有一套很棒的文档，所以你可以使用任何你喜欢的模式。

# Moment 文档

在浏览器中，我们可以通过访问[momentjs.com](http://momentjs.com/)来查看。Moment 的文档非常棒。它可以在文档页面上找到，并且为了开始弄清楚如何使用格式，我们将转到显示部分：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/42fd1a1c-2659-4e82-8f78-0fe72fb74169.png)

显示中的第一项是格式。有一些关于如何使用格式的示例，但真正有用的信息是我们在这里拥有的：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/391118ab-b11c-4efb-894c-a3aa20754a99.png)

这里有我们可以放入字符串中以我们喜欢的方式格式化日期的所有标记。在上面，你可以看到你可以使用尽可能多的这些标记来创建非常复杂的日期输出。现在我们已经探索了两个。我们探索了`MMM`，它就在月份标题下面定义，你可以看到有五种不同的表示月份的方式。

我们用于年份的`YYYY`模式也在这里定义了。有三种使用年份的方式。我们刚刚探索了其中一种。每个部分都有，年份、星期几、月份中的日期、上午/下午、小时、分钟、秒，所有这些都有定义，都可以像我们为当前值所做的那样放入格式中：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/aabd1d7f-6ccc-40dc-bc81-02384046a1c7.png)

现在，为了更深入地探索一下，让我们回到 Atom，并利用其中的一些功能。我们要尝试的是打印日期，如`Jan 1st 1970`，我们已经有了简写的月份和年份，但现在我们还需要将月份的日期格式化为 1st、2nd、3rd，而不是 1、2、3。

# 使用 Moment 格式化日期

为了做到这一点，如果我以前没有使用过 Moment，我会在文档中查找日期部分，然后查看可用的选项。我有打印 1 到 31 的 D 模式，打印我们想要的 1st、2nd、3rd 等的 Do 模式，以及对于小于 10 的值，打印带有 0 的数字的 DD 模式。 

现在在这种情况下，我们想使用 Do 模式，所以我们只需要在格式中输入它。我将打开终端和 Atom，这样我们就可以看到后台中的刷新，然后我们将输入：

```js
console.log(date.format('MMM Do YYYY')); 
```

保存文件，当它启动时，我们得到了`March 25th 2018`，这确实是正确的：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/778ba947-0c63-4da7-bbd9-6b78057a4fb2.png)

现在我们还可以添加其他字符，比如逗号：

```js
console.log(date.format('MMM Do, YYYY'));
```

逗号不是格式期望的一部分，所以它只是简单地通过，这意味着逗号会像我们输入的那样显示在 `March 25th, 2018` 中：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/ebb449d2-2791-4690-ae46-ab4b89d4df45.png)

以这种方式使用 `format` 给了我们很大的灵活性，以便我们可以打印日期。现在 `format` 只是众多方法中的一个。Moment 有很多方法可以做几乎任何事情，尽管我发现我在大多数项目中使用的方法基本相同。大多数情况下并不需要它们，尽管它们存在是因为它们在某些情况下很有用。

# 在 Moment 中的 Manipulate 部分

为了快速了解 Moment 还能做些什么，让我们回到文档并转到 Manipulate 部分：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/1f543e15-164e-4eb2-b000-386e09066ace.png)

在 Manipulate 下定义的前两个方法是 `add` 和 `subtract`。这让你可以轻松地添加和减去时间。我们可以调用 `add` 添加七天，我们可以调用 `subtract` 减去七个月，就像这个例子中所示的那样：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/f6c2f71b-2557-4069-957e-110252ce734d.png)

通过这个例子，你可以快速了解你可以添加和减去什么，年份、季度、月份、周数，几乎任何时间单位都可以被添加或减去。

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/8f677abb-6bc9-4411-bd7d-a1e66db606d1.png)

现在来看看这对时间戳的确切影响，我们可以添加和减去一些值。我将调用 `date.add`，然后我们将添加一年，将 `1` 作为值，`year` 作为单位：

```js
var date = moment();
date.add(1, 'years')
console.log(date.format('MMM Do, YYY'));
```

现在无论你使用单数还是复数版本都没关系，两者都会起同样的作用。在这里你可以看到我们在终端中得到了 `2019`：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/bbb1d15e-0df1-44ba-a8b4-382c79e6d877.png)

如果我将它改为单数形式，我也会得到相同的值。我们可以添加任意多的年份，我将继续添加 `100` 年：

```js
var date = moment();
date.add(100, 'year')
console.log(date.format('MMM Do, YYY'))
```

现在我们到了 `2118`：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/817d6368-31ce-4b36-a887-1014350bd131.png)

`subtract` 也是一样的。我们可以链接调用，也可以将其添加为单独的语句。我要像这样减去：

```js
date.add(100, 'year').subtract(9, 'months');
```

而我们现在是在九月，当我们减去 9 个月时，我们回到了六月：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/1117f12c-1fa8-4385-ae25-7eecc14f2671.png)

现在你会注意到我们从 `2118` 到 `2117`，因为减去那 9 个月需要我们改变年份。Moment 真的很擅长处理你扔给它的任何事情。现在我们将继续玩一下 `format`。我要添加一个我想要的输出，然后我们需要在文档内部找出要使用的模式。

现在写作的当前时间是 10:35，而且是上午，所以我有一个小写的上午。你的目标是打印一个这样的格式。现在显然，如果你运行代码时是 12:15，你会看到 12:15 而不是 10:35；只有格式很重要，实际值并不那么重要。现在当你尝试打印小时和分钟时，你会有很多选项。对于它们两个，你会有一个像 01 这样的填充版本，或者像 1 这样的未填充版本。

我希望你使用填充版本的分钟和未填充版本的小时，就像这样，6 和 01。如果你填充了小时，它看起来有点奇怪，如果你不填充分钟，它看起来就很糟糕。所以如果碰巧是上午 6:01，我们会想要打印出这样的东西。现在对于小时，你也可以选择使用 1 到 12 或 1 到 24，我通常使用 12 小时制，所以我会使用上午。

在我们开始之前，我要注释掉之前的代码，我希望你从头开始写。我将通过调用没有参数的 `moment` 来创建一个新变量 `date`，然后我们还将调用 `console.log` 中的 `format`，这样我们就可以将格式化的值打印到屏幕上，`date.format`：

```js
var date = moment();
console.log(date.format(''))
```

在引号内，我们将提供我们的模式，并从未填充的小时和填充的分钟开始。我们可以通过查看文档，返回到 Display，然后查看一下，来获取这两个模式。如果我们滚动到下一个，我们将遇到的第一个是 Hour，我们有很多选项：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/f836266a-224d-4adf-91c0-01008d912590.png)

我们有 24 小时制的选项，我们有 1 到 12；我们想要的是小写的 h，即 1 到 12 不填充。填充版本，即 hh，就在旁边，这不是我们想要的。我们将通过添加一个 h 来开始：

```js
var date = moment(); 
console.log(date.format('h')); 
```

我也要保存文件，然后在终端中查看：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/29f7e70c-cfb1-4cb1-ac86-4de5ca809c5b.png)

我们有`4`，看起来很好。接下来是填充的分钟，我们将继续找到紧挨着的模式。对于分钟，我们的选择要少得多，要么填充，要么不填充，我们要使用 mm。在我添加 mm 之前，我要添加一个冒号。这将以纯文本形式传递，意味着它不会被更改。我们将添加两个小写的 ms：

```js
console.log(date.format('h:mm')); 
```

然后我们可以保存`time.js`，确保在终端中打印出正确的内容，确实是这样，`4:22`显示出来了：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/12f27b35-dc2c-4dbc-a5a3-ed7814d0f806.png)

接下来要做的是获取小写的 am 和 pm 值。我们可以在 Google Chrome 中找到这个模式，就在小时之前：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/45ac7096-5808-4b55-b400-7cfbdac0151a.png)

在这里，我们可以使用大写 A 表示大写的 AM 和 PM，或者使用小写 a 表示小写的版本。我将在一个空格后面使用小写的`a`来使用小写的版本：

```js
var date = moment();
console.log(date.format('h:mm a'))
```

我可以保存文件，然后在终端中，我确实打印出了`4:24`，并且后面有`pm`：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/62454ab9-24db-4c05-b989-2c76c6b79e69.png)

一切看起来都很好。这就是本节的全部内容！在下一节中，我们将实际将 Moment 集成到我们的服务器和客户端中，而不仅仅是在`playground`文件中。

# 打印消息时间戳

在这一部分，您将格式化时间戳，并将它们与聊天消息一起显示在屏幕上。目前，我们显示了消息的发送者和文本，但`createdAt`时间戳没有被使用。

现在我们需要弄清楚的第一件事是，我们如何将时间戳转换为 Moment 对象，因为归根结底，我们想要调用`format`方法来按我们的喜好格式化它。为了做到这一点，你所要做的就是拿到你的时间戳。我们将创建一个名为`createdAt`的变量来表示这个值，并将其作为`moment`的第一个参数传递进去，这意味着我只需传入`createdAt`，就像这样：

```js
var createdAt = 1234; 
var date = moment(createdAt); 
```

当我这样做时，我们创建了一个具有与 format、add 和 subtract 相同方法的 moment，但它代表的是不同的时间点。默认情况下，它使用当前时间。如果传入一个时间戳，它就使用那个时间。现在这个数字`1234`，只是比 Unix 纪元晚了一秒，但如果我们运行文件，我们应该看到正确的东西打印出来。使用`nodemon`命令，在`playground`文件夹中，我们将运行`time.js`，并且我们会得到`5:30 am`，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/32fec2fc-4e5c-44c0-b210-a86f04340808.png)

这是预期的，因为它考虑了我们的本地时区。

# 从时间戳中获取格式化的值

现在我们已经做好了准备，我们已经拥有了实际获取这些时间戳并返回格式化值所需的一切。我们还可以使用 Moment 创建时间戳，它的效果与我们使用的`new Date().getTime`方法完全相同。

为了做到这一点，我们只需调用`moment.valueOf`。例如，我们可以创建一个名为`someTimestamp`的变量，将其设置为对`moment`的调用。我们将生成一个新的 moment，并调用它的`valueOf`方法。

这将继续返回自 Unix 纪元以来的毫秒时间戳，`console.log`。我们将记录`someTimestamp`变量，以确保它看起来正确，这里是我们的时间戳值：

```js
var someTimestamp = moment().valueOf(); 
console.log(someTimestamp);
```

# 更新 message.js 文件

我们要做的第一件事是调整我们的`message.js`文件。目前在`message.js`中，我们使用`new Date().getTime`生成时间戳。我们将切换到 Moment，不是因为它会改变任何东西，而是因为我希望在使用时间时保持一致使用 Moment。这将使维护和弄清楚发生了什么变得更容易。在`message.js`的顶部，我将创建一个名为`moment`的变量，将其设置为`require('moment')`：

```js
var moment = require('moment');

var generateMessage = (from, text) => {
  return {
    from,
    text,
    createAt: new Date().getTime()
  };
};
```

我们将继续用`valueOf`替换`createdAt`属性。我希望你继续做到这一点，调用`moment`，在`generateMessage`和`generateLocationMessage`中调用`valueOf`方法，然后继续运行测试套件，确保两个测试都通过。

我们需要做的第一件事是调整`generateMessage`的`createdAt`属性。我们将调用`moment`，调用`valueOf`获取时间戳，对`generateLocationMessage`也是同样的操作：

```js
var moment = require('moment');

var generateMessage = (from, text) => {
  return {
    from,
    text,
    createdAt: moment().valueOf()
  };
};

var generateLocationMessage = (from, latitude, longitude) => {
  return {
    from,
    url: `https://www.google.com/maps?q=${latitude},${longitude}`,
    createdAt: moment().valueOf()
  }
};
```

现在我们可以保存`message.js`。进入终端并使用以下命令运行我们的测试套件：

```js
**npm test**
```

我们得到了两个测试，它们仍然都通过了，这意味着我们得到的值确实是一个数字，就像我们的测试所断言的那样：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/0ac0eec6-3999-486a-8592-d06fd9ea1d99.png)

现在我们在服务器上集成了 Moment，我们将继续在客户端上做同样的事情。

# 在客户端集成 Moment

我们需要做的第一件事是加载 Moment。目前，我们在前端加载的唯一库是 jQuery。我们可以通过几种不同的方式来做到这一点；我将实际上从`node_modules`文件夹中获取一个文件。我们已经安装了 Moment，版本为 2.15.1，我们实际上可以获取我们在前端需要的文件，它位于`node_modules`文件夹中。

我们将进入`node_modules`，我们有一个非常长的按字母顺序排列的文件夹列表，我正在寻找一个名为`moment`的文件夹。我们将进入`moment`并获取`moment.js`。我将右键单击复制它，然后向上滚动到最顶部，关闭`node_modules`，然后将其粘贴到我们的`js` | `libs`目录中。现在我们有了`moment.js`，如果你打开它，它是一个非常长的库文件。不需要对该文件进行任何更改，我们只需要加载`index.js`。就在我们的 jQuery 导入旁边，我们将添加一个全新的`script`标签，然后设置`src`属性等于`/js/js/moment.js`，就像这样：

```js
<script src="img/socket.io.js"></script>
<script src="img/jquery-3.1.0.min.js"></script>
<script src="img/moment.js"></script>
<script src="img/index.js"></script>
```

现在我们已经有了这个设置，我们在客户端上就可以访问所有这些 Moment 函数，这意呈现出在`index.js`中可以正确格式化消息中返回的时间戳。在做任何更改之前，让我们使用以下命令启动我们的服务器：

```js
**nodemon server/server.js**
```

我们可以继续进入浏览器，转到`localhost:3000`并刷新，我们的应用程序正在按预期工作。如果我打开开发者工具，在控制台选项卡中，我们实际上可以使用 Moment。我们可以通过 moment 访问它，就像我们在 Node 中做的那样。我可以使用`moment`，调用`format`：`moment().format()`。

我们得到了我们的字符串：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/e5ea026a-c6bd-426b-a078-e17ae6a3d70b.png)

如果你成功导入了 Moment，你应该能够进行这个调用。如果你看到这个，那么你就准备好继续更新`index.js`了。

# 更新 newMessage 属性

如果你还记得，在 message 上我们有一个`createdAt`属性，分别用于`newMessage`和`newLocationMessage`。我们所需要做的就是获取该值，传递给`moment`，然后生成我们格式化的字符串。

我们可以创建一个名为`formattedTime`的新变量，并将其设置为调用`moment`传入时间戳`message.createdAt`的结果：

```js
socket.on('newMessage', function (message) {
  var formattedTime = moment(message.createAt)
```

现在我们可以继续做任何我们喜欢的事情。我们可以调用 format，传入我们在`time.js`中使用的完全相同的字符串，小时，分钟和上午/下午；`h:`，两个小写的`m`，后面跟着一个空格和一个小写的`a`：

```js
var formattedTime = moment(message.createdAt).format('h:mm a'); 
```

有了这个，我们现在有了格式化的时间，我们可以继续将其添加到`li.text`中。现在我知道我在客户端代码中使用模板字符串。我们很快就会删除这个，所以还不需要进行调整，因为我还没有在 Internet Explorer 或其他浏览器中进行测试，尽管应用程序的最终版本将不包括模板字符串。在`from`语句之后，我们将继续注入另一个值，即我们之前创建的`formattedTime`。因此，我们的消息应该是像 Admin 这样的名称，后面跟着时间和文本：

```js
socket.on('newMessage', function (message) {
  var formattedTime = moment(message.createAt).format('h:mm a');
  var li = jQuery('<li></li>');
  li.text('${message.from} ${formattedTime}: ${message.text}');
```

我将继续保存`index.js`，并刷新浏览器以加载客户端代码：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/560650fc-c7aa-4e9b-9b89-28fe85257516.png)

如前面的屏幕截图所示，我们看到 Admin 4:49 pm: 欢迎来到聊天应用程序，这就是正确的时间。我可以发送一条消息，`这是来自用户`，发送出去，我们可以看到现在是下午 4:50：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/b7c14c75-7f5b-41f5-baf1-4b772a65bcf2.png)

这是来自用户的消息，一切都很顺利。

# 更新 newLocationMessage 属性

现在对于发送位置，我们目前不使用 Moment；我们只更新了`newMessage`事件监听器。这意味着当我们打印位置消息时，我们没有时间戳。我们将修改`newLocationMessage`，你可以继续使用我们之前使用的相同技术来完成工作。现在在哪里实际上呈现格式化的时间，你可以简单地将其放在`li.text`中，就像我们在`newMessage`属性的情况下所做的那样。

过程中的第一步将是创建名为`formattedTime`的变量。我们实际上可以继续复制以下行：

```js
var formattedTime = moment(message.createdAt).format('h:mm a'); 
```

并将其粘贴在`var li = jQuery('<li></li>');`行的上面，就像这样：

```js
socket.on('newLocationMessage', function(message) {
  var formattedTime = moment(message.createAt).format('h:mm a');
```

我们想要做的事情与之前完全相同，我们想要获取`createdAt`字段，获取一个 moment 对象，并调用`format`。

接下来，我们必须修改显示的内容，显示这个`formattedTime`变量，并将其放在`li.text`语句中：

```js
socket.on('newLocationMessage', function(message) {
  var formattedTime = moment(message.createAt).format('h:mm a');
  var li = jquery('<li></li>');
  var a = jQuery('<a target="_blank">My current location</a>');

  li.text(`${message.from} ${formattedTime}: `);
```

现在我们可以继续刷新应用程序，我们应该看到我们的时间戳用于常规消息。我们可以发送一条常规消息，一切仍然正常：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/875b19b5-6d68-4414-bf4f-0d63f1be85f1.png)

然后我们可以发送一条我们刚刚更改的位置消息。它应该只需要一秒钟就可以运行起来，我们有我们当前的位置链接。我们有我们的名称和时间戳，这太棒了：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/f9bd9025-4a9b-4c66-a5a9-8323ba05af08.png)

这就是本节的全部内容。让我们继续进行提交以保存我们的更改。

尽管我们还没有完成消息区域，但所有数据都正确显示出来了。只是以一种不太令人愉悦的方式显示出来。不过，现在我们将进入终端并关闭服务器。我将运行`git status`，我们有新文件以及一些修改过的文件：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/cbf98a1b-c044-416b-bb21-cdf891e495d8.png)

然后，`git add .`将会处理所有这些。然后我们可以进行提交，`git commit`带有`-m`标志，这次的好消息是`使用 momentjs 格式化时间戳`：

```js
git commit -m 'Format timestamp using momentjs'
```

我将使用`git push`命令将其推送到 GitHub，然后我们就完成了。

在下一节中，我们将讨论一个模板引擎 Mustache.js。

# Mustache.js

现在我们的时间戳已经正确地呈现在屏幕上。我们将继续讨论一个叫做**Mustache.js**的模板引擎。这将使定义一些标记并多次呈现它变得更容易。在我们的情况下，我们的消息将具有相同的一组元素，以便正确呈现。我们将为用户的名称添加一个标题标记，将文本添加到段落中，所有这些都是一样的。

现在，我们不会像目前在 `index.js` 中那样，而是在 `index.html` 中创建一些模板、一些标记，并渲染它们，这意味着我们不需要手动创建和操作这些元素。这可能是一个巨大的负担。

# 将 mustache.js 添加到目录

现在，为了在实际创建任何模板或渲染它们之前开始，我们确实需要下载库。我们可以通过打开谷歌浏览器并搜索 `mustache.js` 来获取它，我们要找的是 GitHub 仓库，这种情况下恰好是第一个链接。你也可以访问 [mustache.github.io](http://mustache.github.io/) 并点击 JavaScript 链接以到达相同的位置：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/6c4e4823-618f-44cd-be84-d04b763563b2.png)

现在一旦你到了这里，我们需要获取库的特定版本。我们可以转到分支下拉菜单，从分支切换到标签。这将显示所有已发布的版本；我将在这里使用的版本是最新的 2.3.0。我会获取它，它会刷新仓库，我们要找的是一个名为 `mustache.js` 的文件。这是我们需要下载并添加到 `index.html` 中的库文件：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/919c3e60-a5d3-478a-a403-490897428d4b.png)

我可以点击&nbsp;Raw 来获取原始的 JavaScript 文件，并可以右键单击并点击&nbsp;另存为... 将其保存到项目中。我将进入桌面上的项目，`public` | `js` | `libs` 目录，然后在那里添加文件。

现在一旦你把文件放好了，我们可以通过在 `index.html` 中导入它来开始。在底部附近，我们目前有 `jquery` 和 `moment` 的 `script` 标签。这个看起来会很相似。它将是一个 `script` 标签，然后我们将添加 `src` 属性，以便加载新文件，`/js/libs`，最后是 `/mustache.js`：

```js
<script src="img/moment.js"></script>
<script src="img/mustache.js"></script>
```

现在有了这个，我们可以继续创建一个模板并渲染它。

# 创建和渲染 newMessage 的模板

创建一个模板并渲染它，这将让你对 Mustache 能做什么有一个很好的了解，然后我们将继续将其与我们的 `newMessage` 和 `newLocationMessage` 回调实际连接起来。为了在 `index.html` 中开始，我们将通过在 `chat__footer` div 旁边定义一个 `script` 标签来创建一个新模板。

现在在`script`标签内，我们将添加我们的标记，但在我们这样做之前，我们必须在`script`上提供一些属性。首先，这将是一个可重用的模板，我们需要一种访问它的方式，所以我们会给它一个 `id`，我会称这个为 `message-template`，我们要定义的另一个属性是一个叫做 `type` 的东西。`type` 属性让你的编辑器和浏览器知道 `script` 标签内存储了什么。我们将把 `type` 设置为，引号内，`text/template`：

```js
<script id = "message-template" type="text/template">

</script>
```

现在我们可以编写一些标记，它将按预期工作。让我们首先简单地创建一个段落标记。我们将在 `script` 标签内创建一个 `p` 标签，并在其中添加一些文本，`这是一个模板`，然后我们将关闭段落标记，就是这样，这是我们要开始的地方：

```js
<script id="message-template" type="text/template"> 
  <p>This is a template</p> 
</script>
```

我们有一个 message-template `script`标签。我们可以通过注释掉`newMessage`监听器内的所有代码，将其渲染到`index.js`中。我将注释掉所有那些代码，现在我们可以实现 Mustache.js 渲染方法。

# 实现 Mustache.js 渲染方法

首先，我们必须获取模板，创建一个名为`template`的变量来做到这一点，我们要做的就是使用我们刚刚提供的 ID`#message-template`来用`jQuery`选择它。现在我们需要调用`html`方法，它将返回`message-template`内的标记，也就是模板代码，这种情况下是我们的段落标签：

```js
socket.on('newMessage', function (message) {
  var template = jquery('#message-template').html();
```

一旦我们有了这个，我们可以实际上在 Mustache 上调用一个方法，这是因为我们添加了那个`script`标签。让我们创建一个名为`html`的变量；这是我们最终要添加到浏览器的东西，我们将其设置为对`Mustache.render`的调用。

现在`Mustache.render`接受你想要渲染的`template`：

```js
socket.on('newMessage', function (message) {
  var template = jquery('#message-template').html();
  var html = Mustache.render(template);
```

我们将继续渲染它，现在我们可以通过将其添加到`messages` ID 中将其显示在浏览器中，就像我们之前做的那样。我们将选择具有 ID 为 messages 的元素，调用`append`，并附加我们刚刚渲染的模板，我们可以在 HTML 中访问到它：

```js
socket.on('newMessage', function (message) {
  var template = jQuery('#message-template').html();
  var html = Mustache.render(template);

  jQuery('#messages').append(html);
```

现在有了这个设置，我们的服务器重新启动了，我们可以通过刷新浏览器来实际操作。我要刷新浏览器：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/9ec1c84b-571a-4278-b14d-61fe73dee8af.png)

我们得到了这是我们欢迎消息的模板，如果我输入其他内容，我们也会得到这是一个模板。不是很有趣，也不是很有用，但很酷的是 Mustache 让你注入值，这意味着我们可以设置模板中我们期望传入值的位置。

例如，我们有`text`属性。为了引用一个值，你可以使用双大括号的语法，就像这样：

```js
<script id="message-template" type="text/template">
  <p>{{text}}</p>
</script>
```

然后你可以继续输入名称，比如`text`。现在为了实际提供这个值，我们必须向 render 方法发送第二个参数。我们不仅仅传递模板，还要传递模板和一个对象：

```js
socket.on('newMessage', function (message) {
  var template = jquery('#message-template').html();
  var html = Mustache.render(template, {

  });
```

这个对象将拥有你可以渲染的所有属性。现在我们目前期望`text`属性，所以我们应该继续提供它。我将把`text`设置为`message.text`返回的值：

```js
var html = Mustache.render(template, { 
  text: message.text 
}); 
```

现在我们以动态方式渲染模板。模板作为可重用的结构，但数据总是会改变，因为它在调用 render 时被传递进来：

有了这个设置，我们可以继续刷新 Chrome，然后在这里我们看到“欢迎来到聊天应用”，如果我输入一条消息，它将显示在屏幕上，这太棒了：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/7f32c199-d48f-4f28-928b-74fe2fe30fc8.png)

# 获取所有显示的数据

现在，这个过程的下一步是让所有数据显示出来，我们有一个`from`属性和一个`createdAt`属性。我们实际上可以通过`formattedTime`访问到`createdAt`属性。

我们将取消注释`formattedTime`行，这是我们实际要转移到新系统的唯一行。我将把它添加到`newMessage`回调中：

```js
socket.on('newMessage', function (message) {
  var formattedTime = moment(message.createAt).format('h:mm a');
  var template = jQuery('#message-template').html();
  var html = Mustache.render(template, {

  });
```

因为我们仍然希望在渲染时使用`formattedTime`。在我们对模板做任何其他操作之前，让我们简单地传递这些值。我们已经传递了`text`值。接下来，我们可以传递`from`，它可以通过`message.from`访问，我们还可以传递一个时间戳。你可以随意命名该属性，我将继续称其为`createdAt`并将其设置为`formattedTime`：

```js
var html = Mustache.render(template, { 
  text: message.text, 
  from: message.from, 
  createdAt: formattedTime 
}); 
```

# 提供自定义结构

现在有了这个系统，所有的数据确实都被传递了。我们只需要实际使用它。在`index.html`中，我们可以使用所有这些，并且还将提供自定义结构。就像我们之前设置代码时一样，我们将使用我在此项目模板中定义的一些类。

# 添加列表项标签

我们将从使用`li`标签开始。我们将添加一个类，并将这个类命名为`message`。在其中，我们可以添加两个`div`。第一个`div`将是标题区域，我们在其中添加`from`和`createdAt`的值，第二个`div`将是消息的正文：

```js
<script id="message-template" type="text/template">
  <li class="message">
    <div></div>
    <div></div>
  </li>
</script>
```

对于第一个`div`，我们将提供一个类，这个类将等于`message__title`。这是消息标题信息将要放置的地方。我们将在这里开始，通过提供一个`h4`标签，为屏幕呈现一个漂亮的标题，我们将在`h4`内放置`from`数据，我们可以通过使用那些双花括号`{{from}}`来实现：

```js
<script id="message-template" type="text/template">
  <li class="message">
    <div class="message__title">
      <h4>{{from}}</h4>
    </div>
```

对于`span`，情况完全相同，这将在下一步发生。我们将添加一个`span`标签，在`span`标签内，我们将注入`createdAt`，添加我们的双花括号，并指定属性名称：

```js
<script id="message-template" type="text/template">
  <li class="message">
    <div class="message__title">
      <h4>{{from}}</h4>
      <span>{{createAt}}</span>
    </div>
```

# 添加消息正文标签

现在我们可以继续进行实际的消息正文。这将在我们的第二个`div`内进行，我们将为其指定一个类。第二个`div`的类将等于`message__body`，对于基本消息，即非基于位置的消息，我们将只需添加一个段落标签，并通过提供两个花括号后跟`text`来在其中呈现我们的文本：

```js
<script id="message-template" type="text/template"> 
  <li class="message"> 
    <div class="message__title"> 
      <h4>{{from}}</h4> 
      <span>{{createdAt}}</span> 
    </div> 
    <div class="message__body"> 
      <p>{{text}}</p> 
    </div> 
  </li> 
</script> 
```

有了这个系统，我们实际上有一个非常好的消息模板渲染系统。代码，标记，都在`message-template`内定义，这意味着它是可重用的，而且在`index.js`内。我们只需要一点点代码来把一切都连接起来。这是一个更可扩展的解决方案，比起像我们为`newLocationMessage`那样管理元素要容易得多。我将保存`index.js`，进入浏览器，然后刷新一下。

当我们这样做时，我们现在可以看到消息`This is some message`的样式很好。我将发送它；我们得到了名称，时间戳和文本的打印。它看起来比之前好多了：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/770a7137-9d6a-47d7-b5cb-e461af13f88c.png)

# 为 newLocation 消息创建模板

现在我们的发送位置消息看起来仍然很糟糕。如果我点击发送位置，需要几秒钟才能完成，然后就是这样！它没有样式，因为它没有使用模板。我们要做的是为`newLocationMessage`添加一个模板。我们将为模板设置标记，然后呈现它并传入必要的值。

在`index.html`内，我们可以通过创建第二个模板来开始这样做。第二个模板将与第一个非常相似。我们实际上可以通过复制并粘贴此模板来创建第二个模板。我们只需要将`id`属性从`message-template`更改为`location-message-template`：

```js
<script id="location-message-template" type="text/template">
  <li class="message">
    <div class="message__title">
    <h4>{{from}}</h4>
    <span>{{createAt}}</span>
  </div>
  <div class="message__body">
    <p>{{text}}</p>
  </div>
</li>
</script>
```

现在标题区域将是相同的。我们将有我们的`from`属性以及`createdAt`；正文将会改变。

而不是呈现带有文本的段落，我们将呈现带有链接的段落，使用锚标签。现在，我们将添加锚标签。然后在`href`属性内，我们将注入值。这将是从服务器传递到客户端的 URL。我们将添加等号，花括号，我们要添加的值是`url`：

```js
<div class="message__body">
  <p>
    <a href="{{url}}"
  </p>
</div>
```

接下来，我们将继续使用`target`属性，将其设置为`_blank`，这将在新标签页中打开链接。最后，我们可以关闭锚标签，并在其中添加链接的文本。这个链接的好文本可能是`我的当前位置`，就像我们现在的一样：

```js
<script id="location-message-template" type="text/template"> 
  <li class="message"> 
    <div class="message__title"> 
      <h4>{{from}}</h4> 
      <span>{{createdAt}}</span> 
    </div> 
    <div class="message__body"> 
      <p> 
        <a href="{{url}}" target="_blank">My current location</a> 
      </p> 
    </div> 
  </li> 
</script> 
```

这就是我们为模板需要做的全部。接下来，我们将在`index.js`中连接所有这些内容，这意味着在`newLocationMessage`中，你要做的事情与我们之前在`newMessage`中做的事情非常相似。你不再使用 jQuery 来渲染所有内容，而是要渲染模板，传入必要的数据、文本、URL 和格式化的时间戳。

# 渲染 newLocation 模板

我们要做的第一件事是注释掉我们不再需要的代码；那就是除了变量`formattedTime`之外的所有内容：

```js
socket.on('newLocationMessage', function (message) {
  var formattedTime = moment(message.createAt).format('h:mm a');
  // var li = jQuery('<li></li>');
  // var a = jQuery('<a target="_blank">My current location</a>');
  // 
  // li.text(`${message.from} ${formattedTime}: `);
  // a.attr('href', message.url);
  // li.append(a);
  // jQuery('#message').append(li);
});
```

接下来，我们将从 HTML 中获取模板，创建一个名为`template`的变量，并使用`jQuery`通过 ID 选择它。在引号内部，我们将添加我们的选择器。我们要通过 ID 选择，所以我们会添加这个。&nbsp;`#location-message-template`是我们提供的 ID，现在我们要调用`html`来获取它的内部 HTML：

```js
socket.on('newLocationMessage', function (message) {
  var formattedTime = moment(message.createAt).format('h:mm a');
  var template = jQuery('#location-message-template').html();
```

接下来，我们将实际渲染模板，创建一个名为`html`的变量来存储返回值。我们将调用`mustache.render`。这需要两个参数，你要渲染的模板和你要渲染到该模板中的数据。现在数据是可选的，但我们确实需要传递一些数据，所以我们也会提供那个。`template`是我们的第一个参数，第二个参数将是一个对象：

```js
socket.on('newLocationMessage', function (message) {
  var formattedTime = moment(message.createAt).format('h:mm a');
  var template = jQuery('#location-message-template').html();
  var html = Mustache.render(template, {

  });
```

我将从`from`设置为`message.from`开始，我们也可以用`url`做同样的事情，将其设置为`message.url`。对于`createdAt`，我们将使用`formattedTime`变量，`createdAt`设置为`formattedTime`，这在`newMessage`模板中已经定义：

```js
socket.on('newLocationMessage', function (message) {
  var formattedTime = moment(message.createAt).format('h:mm a');
  var template = jQuery('#location-message-template').html();
  var html = Mustache.render(template, {
    from: message.from,
    url: message.url,
    createdAt: formattedTime
  });
```

现在我们可以访问我们需要渲染的 HTML。我们可以使用 jQuery 选择器来选择 ID 为 messages 的元素，并且我们将调用 append 来添加一个新消息。我们要添加的新消息可以通过`html`变量获得：

```js
socket.on('newLocationMessage', function(message) { 
  var formattedTime = moment(message.createdAt).format('h:mm a'); 
  var template = jQuery('#location-message-template').html(); 
  var html = Mustache.render(template, { 
    from: message.from, 
    url: message.url, 
    createdAt: formattedTime 
  }); 

  jQuery('#messages').append(html);
}); 
```

既然我们已经完全转换了我们的函数，我们可以删除旧的注释掉的代码，保存文件，并在 Chrome 中测试一下。我将刷新页面以加载最新的代码，我会发送一条文本消息来确保它仍然有效，现在我们可以发送一个位置消息。我们应该在短短几秒内看到新数据的渲染，它确实按预期工作：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/588f4431-45f8-4da6-8a3d-e16c1e5d485b.png)

我们有名字、时间戳和链接。我可以点击链接，确保它仍然有效。

有了这个设置，我们现在有了一个更好的前端模板创建设置。我们不再需要在`index.js`中做繁重的工作，我们可以在`index.html`中做模板，只需传入数据，这是一个更可扩展的解决方案。

既然我们已经完成了这一切，我们可以关闭服务器并运行`git status`提交我们的更改。我们有一个新文件以及一些修改过的文件，`git add .`会为我们处理所有这些，然后我们可以进行提交，`git commit`带有`-am`标志。实际上，我们已经添加了，所以我们可以只使用`-m`标志，`Add mustache.js for message templates`：

```js
**git commit -m 'Add mustache.js for message templates'**
```

我将把这个推送到 GitHub，然后我们可以继续快速部署到 Heroku，使用`git push heroku master`。我要把这个推上去，只是为了确保所有模板在 Heroku 上的渲染与本地一样。部署应该只需要一秒钟。一旦部署完成，我们可以通过运行`heroku open`或者像以前一样获取 URL 来打开它。这里正在启动应用程序：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/ee9cc7c6-6ca7-4b02-879f-4e6640264c8a.png)

看起来一切都如预期那样进行。我要获取应用程序的 URL，切换到 Chrome，并打开它：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/3f3cf584-e3ba-4d58-bea7-d8c10f0fb2da.png)

现在我们正在实时查看我们的应用程序在 Heroku 中，消息数据如预期显示出来。发送位置时也应该是如此，发送位置消息应该使用新的设置，而它确实如预期般工作。

# 自动滚动

如果我们要构建一个前端，我们最好做到完美。在这一部分，我们将添加一个自动滚动功能。所以如果有新消息进来，它会在消息面板中可见。现在立即来看，这并不是问题。我输入一个`a`，按下*enter*，它就出现了。然而，当我们滚动列表到底部时，你会看到消息开始消失在底部的栏中：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/e37dee8f-f002-4f61-8a4a-c287e11454a9.png)

现在我确实可以向下滚动查看最近的消息，但如果能自动滚动到最近的消息就更好了。所以如果有新消息进来，比如`123`，我会自动滚动到底部。

显然，如果有人向上滚动阅读旧消息，我们会希望让他们留在那里；我们不会想要把他们滚动到底部，那会和一开始看不到新消息一样让人讨厌。这意味着我们将继续计算一个阈值。如果有人能看到最后一条消息，我们将在有新消息进来时滚动他们到底部。如果我在那条消息之前，我们将继续让他们保持原样，没有理由在他们查阅档案时把他们滚动到底部。

# 运行高度属性计算

为了做到这一点，我们将不得不进行计算，获取一些属性，主要是各种东西的高度属性。现在来谈谈这些高度属性，确切地弄清楚我们将如何进行这个计算，我已经准备了一个非常简短的部分。让我们继续深入。为了说明我们将如何进行这个计算，让我们看一下以下示例：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/c3a1643b-6242-48a0-893a-7c39fe046cc3.png)

我们有这个浅紫色的框，比深紫色的要高。这是整个消息容器。它可能包含的消息要比我们在浏览器中实际看到的要多得多。深紫色区域是我们实际看到的部分。当我们向下滚动时，深紫色区域会向下移动到底部，当我们向上滚动时，它会向上移动到顶部。

现在我们可以访问三个高度属性，这些属性将让我们进行必要的计算，以确定是否应该向用户滚动到底部。这些属性如下：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/b155c03b-f571-4b32-9dcf-3623782a6d28.png)

+   首先是`scrollHeight`。这是我们消息容器的整个高度，不管在浏览器中实际可见多少。这意味着如果我们在可见部分之前和之后有消息，它们仍然会在`scrollHeight`中计算。

+   接下来是`clientHeight`。这是可见高度容器。

+   最后，我们有`scrollTop`。这是我们向紫色容器滚动的像素数。

在当前情况下，我们想做什么？我们什么都不想做，用户实际上并没有滚动得那么远。如果每次有新消息进来就把他们带到底部，这对他们来说是一种负担。

在下一个场景中，我们再向下滚动一点：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/1b5ab944-51fd-4c61-8d9f-cc5ae40fa0e6.png)

`scrollTop`增加了，`clientHeight`保持不变，`scrollHeight`也是如此。现在如果我们继续向下滚动列表，最终我们会到达底部。目前，我们不应该做任何事情，但当我们到达底部时，计算看起来会有些不同：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/c99707bd-fdc8-4a2f-a1b1-4211bfb86e00.png)

在这里，您可以看到`scrollTop`值，即我们可以看到的前一个空间，加上`clientHeight`值等于`scrollHeight`。这将是我们方程的基础。如果`scrollTop`加上`clientHeight`等于`scrollHeight`，我们确实希望在新消息进来时将用户滚动到底部，因为我们知道他们已经在面板的底部。在这种情况下，我们应该怎么做？当新消息进来时，我们应该滚动到底部。现在有一个小小的怪癖：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/7d47ee10-2dd8-44cc-9b5a-589951c1f5b7.png)

我们将考虑到新的`messageHeight`，在我们的计算中添加`scrollTop`，`clientHeight`和`messageHeight`，将该值与`scrollHeight`进行比较。使用这个方法，我们将再次能够将用户滚动到底部。

让我们继续在 Atom 中连接这个。现在我们知道了如何运行这个计算，让我们继续在`index.js`中实际执行。我们将创建一个新的函数，它将为我们完成所有这些繁重的工作。它将根据用户的位置确定是否应该将用户滚动到底部。让我们在`index.js`的顶部创建一个函数。它不会接受任何参数，我们将把这个函数称为`scrollToBottom`：

```js
var socket = io();

function scrollToBottom () {

}
```

每次向聊天区域添加新消息时，我们将调用`scrollToBottom`，这意味着我们需要在`newMessage`和`newLocationMessage`中各调用一次。在`newLocationMessage`回调函数中，我可以调用`scrollToBottom`，不传入任何参数：

```js
socket.on('newMessage', function (message) {
  var formattedTime = moment(message.createAt).format('h:mm a');
  var template = jQuery('#message-template').html();
  var html = Mustache.render(template, {
    text: message.text,
    from: message.from,
    createdAt: formattedTime
  });

  jQuery('#message').append(html);
  scrollToBottom();
}); 
```

当我们附加`scrollToBottom`时，我会做同样的事情：

```js
socket.on('newLocationMessage', function (message) {
  var formattedTime = moment(message.createAt).format('h:mm a');
  var template = jQuery('#message-template').html();
  var html = Mustache.render(template, {
    from: message.from,
    url: message.url,
    createdAt: formattedTime
  });

  jQuery('#message').append(html);
  scrollToBottom();
}); 
```

现在我们需要做的就是将这个函数连接起来：

+   确定是否应该将它们滚动到底部，以及

+   如果有必要，将它们滚动到底部。

# 创建一个新变量将消息滚动到底部

首先，我们将选择消息容器，并创建一个新变量来存储它。我们实际上将创建相当多的变量来运行我们的计算，所以我将添加两个注释，`选择器`和`高度`。这将帮助我们分解这长长的变量列表。

我们可以创建一个变量，我们将把这个变量称为`messages`，然后我们将把`messages`设置为一个`jQuery`选择器调用。我们将选择所有 ID 等于`messages`的元素，这只是我们的一个元素：

```js
function scrollToBottom () {
  // Selectors
  var message = jQuery('#message');
```

现在我们已经准备好了消息，我们可以专注于获取这些高度。我们将继续获取`clientHeight`，`scrollHeight`和`scrollTop`。首先，我们可以创建一个名为`clientHeight`的变量，将其设置为`messages`，然后我们将调用`prop`方法，这给了我们一种跨浏览器的方法来获取属性。这是一个没有 jQuery 的 jQuery 替代方法。这确保它在所有浏览器中都能正常工作，无论他们如何调用`prop`。我们将继续提供，用引号括起来，`clientHeight`来获取`clientHeight`属性：

```js
function scrollToBottom () {
  // Selectors
  var message = jQuery('#message'); 
  // Heights
  var clientHeight = message.prop('clientHeight');
}
```

我们将为另外两个值做完全相同的事情两次。`scrollTop`将被设置为`messages.prop`获取`scrollTop`属性，最后`scrollHeight`。一个名为`scrollHeight`的新变量将存储该值，我们将把它设置为`messages.prop`，传入我们想要获取的属性`scrollHeight`：

```js
function scrollToBottom() { 
  //selectors 
  var messages = jQuery('#messages'); 
  //Heights 
  var clientHeight = messages.prop('clientHeight'); 
  var scrollTop = messages.prop('scrollTop'); 
  var scrollHeight = messages.prop('scrollHeight');
}
```

现在我们已经准备就绪，可以开始计算了。

# 确定计算

我们想要弄清楚`scrollTop`加上`clientHeight`是否大于或等于`scrollHeight`。如果是，那么我们就要滚动用户到底部，因为我们知道他们已经接近底部了，`if (clientHeight + scrollTop is >= scrollHeight)`：

```js
var scrollHeight = message.prop('scrollHeight');

if (clientHeight + scrollTop >= scrollHeight) {

}
```

如果是这样的话，我们将继续做一些事情。现在，我们将使用`console.log`在屏幕上打印一条小消息。我们将只打印`Should scroll`：

```js
if (clientHeight + scrollTop >= scrollHeight) {
  console.log('Should scroll');
}
```

现在我们的计算还没有完成，因为我们正在运行这个函数。在我们附加新消息之后，我们确实需要考虑到这一点。正如我们在 Atom 中看到的那样，如果我们可以看到最后一条消息，我们确实希望将它们滚动到底部；如果我在列表中更靠上，我们就不会将它们滚动。但是如果我离底部很近，前面几个像素，我们应该将它们滚动到底部，因为这很可能是他们想要的。

# 考虑新消息的高度

为了完成这个任务，我们必须考虑新消息的高度和上一条消息的高度。在 Atom 中，我们将首先添加一个选择器。

我们将创建一个名为`newMessage`的变量，这将存储最后一个列表项的选择器，在滚动到底部之前刚刚添加的选择器。我将使用`jQuery`来完成这个任务，但我们不需要创建一个新的选择器，实际上我们可以基于之前的选择器`messages`进行构建，然后调用其`children`方法：

```js
function scrollToBottom () {
  // Selectors
  var message = jQuery('#message'); 
  var newMessage = message.children();
```

这使您可以编写一个特定于消息子级的选择器，这意味着我们有了所有的列表项，因此我们可以在另一个上下文中选择我们的列表项，也许我们想选择所有的段落子级。但在我们的情况下，我们将使用`last-child`修饰符选择最后一个子级的列表项：

```js
var newMessage = messages.children('li:last-child');
```

现在我们只有一个项目，列表中的最后一个列表项，我们可以继续通过创建一个名为`newMessageHeight`的变量来获取其高度，就在`scrollHeight`变量旁边。我们将把它设置为`newMessage`，然后调用其`innerHeight`方法：

```js
var scrollHeight = messages.prop('scrolHeight');
var newMessageHeight = newMessage.innerHeight();
```

这将计算消息的高度，考虑到我们通过 CSS 应用的填充。

现在我们需要考虑第二个到最后一个消息的高度。为此，我们将创建一个名为`lastMessageHeight`的变量，并将其设置为`newMessage`，然后调用`prev`方法。这将使我们移动到上一个子元素，因此如果我们在最后一个列表项，现在我们在倒数第二个列表项，我们可以再次调用`innerHeight`来获取其高度：

```js
var newMessageHeight = newMessage.innerHeight();
var lastMessageHeight = newMessage.prev().innerHeight();
```

现在我们也可以在`if`语句中考虑这两个值。我们将把它们相加，`newMessageHeight`，我们还将考虑到`lastMessageHeight`，并将其加入我们的计算中：

```js
function scrollToBottom() { 
  //selectors 
  var messages = jQuery('#messages'); 
  //Heights 
  var clientHeight = messages.prop('clientHeight'); 
  var scrollTop = messages.prop('scrollTop'); 
  var scrollHeight = messages.prop('scrollHeight'); 
  var newMessageHeight = newMessage.innerHeight(); 
  var lastMessageHeight = newMessage.prev().innerHeight(); 

  if(clientHeight + scrollTop + newMessageHeight + lastMessageHeight >= scrollHeight) { 
    console.log('Should scroll'); 
  }
}
```

现在我们的计算完成了，我们可以测试一下是否一切都按预期工作。我们应该在应该滚动时看到`Should scroll`。

# 测试计算

在浏览器中，我将继续刷新，然后打开开发者工具，这样我们就可以查看我们的`console.log`语句。您会注意到在较小的屏幕上，样式会移除侧边栏。现在我要按*enter*几次。显然，我们不应该发送空消息，但现在我们可以，您会看到`Should scroll`正在打印：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/8172b50e-4ce4-401c-b428-cf25b08d83e5.png)

实际上不会滚动，因为我们的消息容器的高度实际上并没有超过浏览器空间给定的高度，但它确实满足条件。现在随着我们继续向下滚动，消息开始从屏幕底部消失，您会注意到消息前面的计数停止增加。每次打印`Should scroll`时计数都会增加，但现在即使我添加了新消息，它仍然停留在 2。

在这种情况下，我们可以滚动到底部并添加一条新消息`abc`。这应该会导致浏览器滚动，因为我们离底部很近。当我这样做时，`Should scroll`增加到 3，这太棒了。

如果我滚动到列表顶部，输入`123`并按*回车*键，应该不会滚动到 4，这是正确的。如果用户在顶部，我们不希望将其滚动到底部。

# 在必要时滚动用户

现在唯一剩下的事情就是在必要时实际滚动用户。这将发生在我们的`if`语句中，我们可以删除`console.log('Should scroll')`的调用，并将其替换为对`messages.scrollTop`的调用，这是设置`scrollTop`值的 jQuery 方法，我们将其设置为`scrollHeight`，这是容器的总高度。这意味着我们将移动到消息区域的底部：

```js
if(clientHeight + scrollTop + newMessageHeight + lastMessageHeight >= scrollHeight) {
  messages.scrollTop(scrollHeight);
}
```

在 Google Chrome 中，我们现在可以刷新页面以获取最新的`index.js`文件，然后我会按住*回车*键一小会儿。正如你所看到的，我们正在自动滚动列表。如果我添加新消息，它将正确显示。

如果我靠近顶部，新消息进来，比如`123`，我不会滚动到列表底部，这是正确的。现在，如果我不是在底部，但很接近，新消息进来，我会滚动到底部。但如果我稍微超过最后一条消息，我们将不会滚动到底部，这正是我们想要的。所有这些都是因为我们的计算。

# 提交与计算相关的更改

让我们在终端中用一个提交来结束这一切。如果我们运行`git status`，你会看到我们只有一个更改的文件。我可以使用`git commit -am`来进行提交，`如果用户接近底部，则滚动到底部`：

```js
**git commit -am 'Scroll to bottom if user is close to bottom'**
```

我将继续使用`git push`命令将其推送到 GitHub，这被认为是项目的第一部分结束。

# 总结

在本章中，我们研究了如何在 HTML 格式中为基本聊天应用程序添加样式。我们还讨论了时间戳和使用 Moment 方法格式化页面。之后，我们学习了 Mustache.js 的概念，创建和渲染消息模板。最后，我们了解了自动滚动和使用消息高度属性进行计算。有了这些，我们已经有了一个基本的聊天应用程序。

在下一章中，目标是添加聊天室和名称，所以我去注册页面。我输入我想加入的房间和我想使用的名称。然后我被带到一个聊天页面，但只针对特定的房间。因此，如果有两个房间，房间 1 的用户将无法与房间 2 的用户交谈，反之亦然。
