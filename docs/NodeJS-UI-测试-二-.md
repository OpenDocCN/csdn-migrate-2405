# NodeJS UI 测试（二）

> 原文：[`zh.annas-archive.org/md5/9825E0A7D182DABE37113602D3670DB2`](https://zh.annas-archive.org/md5/9825E0A7D182DABE37113602D3670DB2)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：操纵僵尸浏览器

现在我们有了待办 HTTP 应用程序，并且了解了 Mocha 测试框架的工作原理，我们准备开始使用 Zombie.js 创建测试。

如前所述，Zombie.js 允许您创建一个模拟的浏览器环境并对其进行操作。这些操作是用户在浏览器中通常做的事情，比如访问 URL，点击链接，填写和提交表单等。

本章涵盖以下内容：

+   访问 URL

+   填写和提交表单

+   检查浏览器中的错误

+   验证文档内容

+   理解 CSS 选择器语法

本章向您展示了如何设置一个与您的 Web 应用程序交互的 Zombie.js 浏览器。

**访问 URL**：首先，我们将从上次离开的地方继续进行应用测试。整个应用涉及用户，但在这部分中，我们主要将关注`Users`路由涉及的功能-渲染注册表单和实际在数据库中创建用户记录。

如前所述，我们离开了这个单一的测试文件：

```js
var assert  = require('assert'),
    Browser = require('zombie'),
    app     = require('../app')
    ;

describe('Users', function() {

  before(function(done) {
    app.start(3000, done);
  });

  after(function(done) {
    app.server.close(done);
  });

  describe('Signup Form', function() {

    it('should load the signup form', function(done) {
      var browser = new Browser();
      browser.visit("http://localhost:3000/users/new", function() {
        assert.ok(browser.success, 'page loaded');
        done();
      });
    });

  });
});
```

这个测试只是加载了用户注册表单，并测试浏览器是否认为它是成功的。让我们通过这个测试来完全理解发生了什么。

首先，我们通过实例化一个新的浏览器对象来创建一个新的浏览器：

```js
var browser = new Browser();
```

这样创建了一个 Zombie.js 浏览器，它代表一个独立的浏览器进程，主要工作是在请求之间保持状态：URL 历史记录，cookies 和本地存储。

浏览器还有一个主窗口，你可以使用`browser.visit()`在其中加载一个 URL，就像这样：

```js
browser.visit("http://localhost:3000/users/new");
```

这使得浏览器执行一个 HTTP `GET`请求来从该 URL 加载 HTML 页面。由于 Node.js 和 Zombie.js 进行异步 I/O 处理，这只会使 Zombie.js 开始加载页面。然后 Zombie.js 尝试获取 URL，解析 HTML 文档，并通过加载引用的 JavaScript 文件来解析所有依赖项。

一旦所有这些都完成了，我们可以通过将回调函数传递给`browser.wait()`方法来得到通知，就像这样：

```js
browser.visit("http://localhost:3000/users/new");
browser.wait(function() {
  console.log('browser page loaded');
});
```

我们不是使用`browser.wait`函数，而是直接将回调传递给`browser.visit()`调用，就像这样：

```js
browser.visit("http://localhost:3000/users/new",
  function(err, browser) {
    if (err) throw err;
    assert.ok(browser.success, 'page loaded');
    done();
  }
);
```

在这里，您传递一个回调函数，一旦出现错误或浏览器准备好，就会被调用。如果发生错误，它将作为第一个参数返回-我们检查是否存在错误，并在存在时抛出它，以便测试失败。

第二个参数包含浏览器对象，与我们已经有的浏览器对象相同。这意味着我们可以完全省略第二个参数，并使用之前的浏览器引用，就像这样：

```js
browser.visit("http://localhost:3000/users/new",
  function(err) {
    if (err) throw err;
    assert.ok(browser.success, 'page loaded');
    done();
  }
);
```

如果是同一个浏览器对象，你可能会问为什么要传递那个对象。它是为了支持这种调用形式：

```js
var Browser = require('zombie');

Browser.visit(("http://localhost:3000/users/new",
  function(err, browser) {
    if (err) throw err;
    assert.ok(browser.success, 'page loaded');
    done();
  }
);
```

请注意，这里我们正在使用大写的伪类`Browser`对象；我们没有实例化`browser`。相反，我们将这个工作留给`Browser`模块来做，并将它作为回调函数的第二个参数传递给我们。

### 注意

从现在开始，我们将更喜欢这种简洁的形式，而不是这里显示的其他形式。

# 浏览器何时准备好？

当我们要求浏览器访问一个 URL 时，它在完成时会回调我们，但是正如网页开发者所知，很难准确知道何时可以认为页面加载完全完成

浏览器对象有自己的事件循环，处理异步事件，如加载资源、事件、超时和间隔。页面加载和解析完成后，所有依赖项都会异步加载和解析-就像在真实浏览器中一样-使用这个事件循环。

其中一些依赖项可能包含将被加载、解析和评估的 JavaScript 文件。此外，HTML 文档可能包含一些额外的内联脚本，将被执行。如果其中任何脚本有一个等待文档准备就绪的回调，这些回调将在您的`browser.visit()`回调触发测试回调之前执行。这意味着，例如，如果您有在文档准备就绪时触发的 jQuery 代码，它将在您的回调之前运行。对于任何后续的 AJAX 回调也是如此。

要查看此操作，请尝试在`templates/layout.html`文件的关闭`</body>`标记之前立即添加以下代码：

```js
    <script>
      $(function() {
        $.get('/users/new', function() {
          console.log('LOADED NEW');
        });
      });
    </script>
```

然后更改`test/users.js`中的测试代码，以便在访问回调被触发时记录日志：

```js
it('should load the signup form', function(done) {
  Browser.visit("http://localhost:3000/users/new", function(err, browser) {
    if (err) throw err;
    console.log('VISIT IS DONE');
    assert.ok(browser.success, 'page loaded');
    done();
  });
});
```

为了分析这一点，我们将以调试模式运行我们的测试。在此模式下，Zombie.js 输出一些有用的信息，包括浏览器正在执行的 HTTP 请求活动。要启用此模式，请设置`DEBUG`环境变量，像这样：

```js
$ DEBUG=true node_modules/.bin/mocha test/users.js
```

现在您应该获得以下调试输出：

```js
Zombie: GET http://localhost:3000/users/new => 200
Zombie: GET http://localhost:3000/js/jquery.min.js => 200
Zombie: GET http://localhost:3000/js/jquery-ui-1.8.23.custom.min.js => 200
Zombie: GET http://localhost:3000/js/bootstrap.min.js => 200
Zombie: GET http://localhost:3000/js/todos.js => 200
Zombie: GET http://localhost:3000/users/new => 200
LOADED NEW
VISIT IS DONE
.

  ✔ 1 test complete (315ms)
```

### 注意

如果您是 Windows 用户，则最后一个命令将无法工作。在运行 Mocha 命令之前，您需要设置`DEBUG`环境变量：

```js
$ SET DEBUG=true
```

您还需要将正斜杠(`/`)替换为反斜杠(`\`)：

```js
$ node_modules\.bin\mocha test\users.js
```

正如您所看到的，`LOADED NEW`字符串在`VISIT IS DONE`字符串之前打印，这意味着浏览器在访问回调触发之前执行并完成了 AJAX 请求。您现在可能希望返回代码并删除这些额外的控制台日志。

## 访问 URL 时的选项

您还可以向浏览器传递一些选项，以修改它加载页面的一些操作和条件。这些选项以对象的形式传递给`Browser.visit()`调用的参数，就在回调之前，像这样：

```js
Browser.visit(<url>, <options>, <callback>);
```

以下是我们将详细讨论的最有用的选项：

+   调试

+   标题

+   maxWait

### 调试

正如我们所看到的，通过设置`DEBUG`环境变量，您可以从 Zombie.js 获得一些输出。通过将`debug`选项设置为`true`，也可以激活此功能，像这样：

```js
Browser.visit(url, {debug: true}, callback);
```

### 标题

您可以定义一组标头，以便在每个源自此访问的 HTTP 请求上发送。默认情况下，Zombie.js 发送这些标头值：

+   **用户代理**：Mozilla/5.0，Chrome/10.0.613.0，Safari/534.15，或 Zombie.js/1.4.1

+   **接受编码**：身份

+   **主机**：localhost:3000

+   **连接**：保持连接

`user-agent`标头定义了一个虚假的用户代理，有些类似于 Mozilla，Chrome 和 Safari 浏览器，但您可以在此设置中更改它，稍后会看到。

`accept-encoding`标头指定结果文档不应进行编码。

`host`标头是 HTTP 1.1 的必需项，指定了此请求所引用的主机名。

`connection: keep-alive`标头指定在请求完成后应保持与服务器的连接。这是一个内部选项，允许 Node 在许多 HTTP 连接中重用客户端套接字，这将略微加快您的测试速度。

要添加额外的标头值，如果您的应用程序需要任何标头值，请像这样指定它们：

```js
var options = {
  headers: {
    'x-test': 'Test 123',
    'x-test-2': 'Test 234'
  }
};
Browser.visit(url, options, callback);
```

请注意，这些值在加载依赖项时也将发送给每个请求，例如在 HTML 文档中引用的后续 CSS 和 JavaScript 文件。

### maxWait

默认情况下，调用`Browser.visit`时，Zombie.js 加载页面，解析页面，加载依赖项，并在浏览器中运行任何待处理的 JavaScript 代码。如果这需要超过 5 秒，将引发错误并使您的测试失败。如果由于任何原因，5 秒不足以完成所有这些操作，则可以通过像这样更改`maxWait`选项来增加限制：

```js
Browser.visit(url, {maxWait: '10s'}, callback);
```

您可以将值指定为字符串，如`10ms`，`100ms`，`7.5s`等。

# 检查元素的存在

当`Browser.visit()`回调被触发时，我们检查错误。我们还检查页面是否成功加载，如果 HTTP 响应状态码在 200 到 299 之间。这些 2XX 响应代码对应于`ok`请求状态，并且是服务器告知用户代理一切顺利进行的方式的一部分。

尽管收到了一个`ok`响应，我们不应该轻信服务器的话。我们可能已经收到了响应状态码和一个 HTML 文档，但不能确定我们是否得到了包含用户注册表标记的预期文档。

在我们的情况下，我们可能希望验证文档是否包含一个包含`New User`字符串的标题元素，并且新用户表单元素是否存在。以下是完整测试的代码：

```js
it('should load the signup form', function(done) {
  Browser.visit("http://localhost:3000/users/new", function(err, browser) {
    if (err) throw err;
    assert.ok(browser.success, 'page loaded');
 assert.equal(browser.text('h1'), 'New User');

 var form = browser.query('form');
 assert(form, 'form exists');
 assert.equal(form.method, 'POST', 'uses POST method');
 assert.equal(form.action, '/users', 'posts to /users');

 assert(browser.query('input[type=email]#email', form),
 'has email input');
 assert(browser.query('input[type=password]#password', form),
 'has password input');
 assert(browser.query('input[type=submit]', form),
 'has submit button');

    done();
  });
});
```

测试中的新行已经突出显示。现在让我们逐个查看它们。

```js
assert.equal(browser.text('h1'), 'New User');
```

在这里，`browser.text(<selector>)`被用来提取`h1`标签的文本内容（如果至少有一个存在）。

### 注意

如果选择器匹配多个 HTML 元素（如果在文档中有多个`h1`标签），`browser.text(<selector>)`将返回所有匹配节点的连接文本。

在这里，选择器只是标记名称，但您可以使用任何 Sizzle 有效的选择器。这些类似于 CSS3 选择器，也用于 jQuery。如果您对此不熟悉，不用担心，我们将在未来看到更多这方面的例子。

```js
var form = browser.query('form');
assert(form, 'form exists');
```

### 注意

浏览器（以及所有浏览器）将当前文档的表示存储在一个可访问的结构中，称为**文档对象模型**（**DOM**）。文档中的 HTML 标记由浏览器解析，并构建 DOM 树。可以使用 JavaScript 以编程方式遍历此 DOM。

在这里，我们使用`browser.query(<selector>)`方法来提取第一个表单元素。这个元素是一个 DOM 节点，就像您在浏览器中找到的那样，并且符合 DOM 规范。目前，我们只是测试它是否存在。之后，我们将检查一些属性是否正确：

```js
assert.equal(form.method, 'POST', 'uses POST method');
assert.equal(form.action, '/users', 'posts to /users');
```

在这里，我们正在验证表单方法是否为`POST`，以及当用户提交时，它是否实际上发布到`/users` URL。

接下来，我们验证是否存在创建用户所需的表单元素：

```js
assert(browser.query('input[type=email]#email', form),
  'has email input');
assert(browser.query('input[type=password]#password', form),
  'has password input');
assert(browser.query('input[type=submit]', form),
  'has submit button');
```

我们使用`browser.query(<selector>, <context>)`形式来检索第一个匹配的节点，但这次，我们将搜索限制在`<context>`的子集中，这在我们的情况下是我们的`form`节点。我们还在这里使用更复杂的选择器，将标记名称选择器（`form`）与 ID 选择器`#id`和属性选择器`[type=email]`结合使用。例如，第一个选择器`input[type=email]#email`选择具有类型`email`属性和值`email`的 ID 的输入。这样，我们断言这样的元素存在，因为如果不存在，`browser.query()`调用将返回`undefined`，破坏断言调用。

# 填写表单

一旦加载了包含用户订阅表单的页面，您就可以填写表单并将其提交回服务器。为此，我们将使用一个新的测试用例：

```js
it("should submit", function(done) {
  Browser.visit("http://localhost:3000/users/new", function(err, browser) {
    if (err) throw err;

    browser
      .fill('E-mail', 'me@email.com')
      .fill('Password', 'mypassword')
      .pressButton('Submit', function(err) {
        if (err) throw err;
        assert.equal(browser.text('h1'), 'Thank you!');
        assert(browser.query('a[href="/session/new"]'),
          'has login link');
        done();
      });

  });
});
```

在这里，我们重新访问用户创建表单，一旦表单加载完成，我们就使用`browser.fill(<field>, <value>)`方法填写电子邮件和密码填写。在这个表单中，`browser.fill()`接受几种类型的参数作为字段标识符。在这里，我们使用了字段之前的标签文本。如果查看空的用户创建表单的源代码，它将是：

```js
<form action="/users" method="POST">
  <p>
    <label for="email">E-mail</label>
    <input type="email" name="email" value="" id="email">
  </p>
  <p>
    <label for="password">Password</label>
    <input type="password" name="password" id="password" value="" required="">
  </p>
  <input type="submit" value="Submit">
</form>
```

我们在这里使用的两个标签标签都有一个`for`属性，指示它所关联的标签的`id`属性。这是 Zombie.js 用来匹配`browser.fill()`中的字段的方法。或者，我们还可以指定字段名称或 CSS 选择器，使以下填充指令等同于我们所拥有的：

```js
    browser
      .fill('#email', 'me@email.com')
      .fill('#password', 'mypassword')
```

然后，您可以在 shell 控制台上运行测试：

```js
$ ./node_modules/.bin/mocha test/users.js
```

只要 CouchDB 服务器可访问，这些测试就应该通过：

```js
  ..

  ✔ 2 tests complete (577ms)
```

但是，如果再次运行测试，它们应该失败。现在试试看：

```js
  ..

  ✖ 1 of 2 tests failed:

  1) Users Signup Form should submit:
     Error: Server returned status code 409
...
```

这是因为我们不允许使用相同电子邮件地址的两个用户，浏览器会产生 409 响应代码作为这种用户创建请求的结果。您可以在每次测试之前手动从数据库中删除用户文档，但为了完全解决这个问题，我们需要自动化这个过程。

首先，我们将介绍固定装置的概念。这是我们将为用户定义用户名和密码的地方，这将在其他测试中使用。然后，您需要创建一个文件，在`test/fixtures.json`下，目前包含以下数据：

```js
{
  "user" : {
    "email": "me@email.com",
    "password": "mypassword"
  }
}
```

然后，`users`测试文件将通过在顶部放置`require`来消耗此 JSON 文件：

```js
var fixtures = require('./fixtures');
```

然后，您还需要访问数据库，为此我们使用与路由监听器使用相同的库：

```js
var couchdb = require('../lib/couchdb'),
    dbName  = 'users',
    db      = couchdb.use(dbName);
```

现在我们需要在`Signup Form`测试描述范围内添加一个 before hook：

```js
before(function(done) {
  db.get(fixtures.user.email, function(err, doc) {
    if (err && err.status_code === 404) return done();
    if (err) throw err;
    db.destroy(doc._id, doc._rev, done);
  });
});
```

这将确保我们的数据库中没有这样的用户记录。

现在我们正在使用固定装置，让我们从测试代码中删除那些硬编码的用户名和密码字符串：

```js
it("should submit", function(done) {

  Browser.visit("http://localhost:3000/users/new", function(err, browser) {
    if (err) throw err;

    browser
      .fill('E-mail', fixtures.user.email)
      .fill('Password', fixtures.user.password)
      .pressButton('Submit', function(err) {
        if (err) throw err;
        assert.equal(browser.text('h1'), 'Thank you!');
        assert(browser.query('a[href="/session/new"]'),
          'has login link');
        done();
      });

  });
});
```

这将是整个组装的用户测试文件：

```js
var assert  = require('assert'),
    Browser = require('zombie'),
    app     = require('../app'),
    couchdb = require('../lib/couchdb'),
    dbName  = 'users',
    db      = couchdb.use(dbName),
    fixtures = require('./fixtures');

describe('Users', function() {

  before(function(done) {
    app.start(3000, done);
  });

  after(function(done) {
    app.server.close(done);
  });

  describe('Signup Form', function() {

    before(function(done) {
      db.get(fixtures.user.email, function(err, doc) {
        if (err && err.status_code === 404) return done();
        if (err) throw err;
        db.destroy(doc._id, doc._rev, done);
      });
    });

    it('should load the signup form', function(done) {
      Browser.visit("http://localhost:3000/users/new", function(err, browser) {
        if (err) throw err;
        assert.ok(browser.success, 'page loaded');
        assert.equal(browser.text('h1'), 'New User');

        var form = browser.query('form');

        assert(form, 'form exists');
        assert.equal(form.method, 'POST', 'uses POST method');
        assert.equal(form.action, '/users', 'posts to /users');

        assert(browser.query('input[type=email]#email', form),
          'has email input');
        assert(browser.query('input[type=password]#password', form),
          'has password input');
        assert(browser.query('input[type=submit]', form),
          'has submit button');

        done();
      });
    });

    it("should submit", function(done) {

      Browser.visit("http://localhost:3000/users/new", function(err, browser) {
        if (err) throw err;

        browser
          .fill('E-mail', fixtures.user.email)
          .fill('Password', fixtures.user.password)
          .pressButton('Submit', function(err) {
            if (err) throw err;
            assert.equal(browser.text('h1'), 'Thank you!');
            assert(browser.query('a[href="/session/new"]'),
              'has login link');
            done();
          });

      });
    });

  });
});
```

当重复运行此测试时，现在应该总是会收到成功消息。

# 测试登录表单

现在我们已经测试了用户创建流程，让我们测试一下该用户是否可以登录。

按照我们一直使用的测试文件模式，您需要创建一个文件，在`test/session.js`下，内容如下：

1.  首先，导入缺少的依赖项：

```js
var assert  = require('assert'),
    Browser = require('zombie'),
    app     = require('../app'),
    couchdb = require('../lib/couchdb'),
    dbName  = 'users',
    db      = couchdb.use(dbName),
    fixtures = require('./fixtures');

describe('Session', function() {

  before(function(done) {
    app.start(3000, done);
  });

  after(function(done) {
    app.server.close(done);
  });
```

这就结束了开幕式！

1.  现在我们准备开始描述登录表单：

```js
  describe('Log in form', function() {

    before(function(done) {
      db.get(fixtures.user.email, function(err, doc) {
        if (err && err.status_code === 404) {
 return db.insert(fixtures.user, fixtures.user.email, done);
 }
        if (err) throw err;
        done();
      });
    });
```

此`before`钩子将创建测试用户文档（如果不存在）（而不是在存在时删除）。

1.  接下来，我们将测试登录表单是否加载并包含相关元素：

```js

    it('should load', function(done) {
      Browser.visit("http://localhost:3000/session/new",
        function(err, browser) {
          if (err) throw err;
          assert.ok(browser.success, 'page loaded');
          assert.equal(browser.text('h1'), 'Log in');

          var form = browser.query('form');

          assert(form, 'form exists');
          assert.equal(form.method, 'POST', 'uses POST method');
          assert.equal(form.action, '/session', 'posts to /session');

          assert(browser.query('input[type=email]#email', form),
            'has email input');
          assert(browser.query('input[type=password]#password', form),
            'has password input');
          assert(browser.query('input[type=submit]', form),
            'has submit button');

          done();
        });
    });
```

这里与用户代码的唯一区别是标题字符串应为`登录`，而不是`新用户`。这是因为我们目前使用了这样一个最小的用户创建表单。

1.  接下来，我们正在测试登录表单是否实际有效：

```js
    it("should allow you to log in", function(done) {

      Browser.visit("http://localhost:3000/session/new",
        function(err, browser) {
          if (err) throw err;

          browser
            .fill('E-mail', fixtures.user.email)
            .fill('Password', fixtures.user.password)
            .pressButton('Log In', function(err) {
              if (err) throw err;

              assert.equal(browser.location.pathname, '/todos',
                'should be redirected to /todos');
              done();
            });

        });
    });

  });
});
```

在这里，我们正在加载并填写电子邮件和密码字段，然后单击**登录**按钮。单击按钮后，登录表单将被发布，会话将被启动，并且用户将被重定向到待办事项页面。

1.  现在从命令行运行此测试文件：

```js
$ ./node_modules/.bin/mocha test/session.js
  ․․

  ✔ 2 tests complete (750ms)
```

1.  此测试包括用户输入正确用户名和密码的情况，但如果不是这种情况会发生什么？让我们为此创建一个测试用例：

```js
it("should not allow you to log in with wrong password", function(done) {

  Browser.visit("http://localhost:3000/session/new",
    function(err, browser) {
      if (err) throw err;

      browser
        .fill('E-mail', fixtures.user.email)
        .fill('Password', fixtures.user.password +
          'thisisnotmypassword')
        .pressButton('Log In', function(err) {
          assert(err, 'expected an error');
          assert.equal(browser.statusCode, 403, 
            'replied with 403 status code');
          assert.equal(browser.location.pathname, '/session');
          assert.equal(browser.text('#messages .alert .message'),
            'Invalid password');
          done();
        });
    }
  );
});
```

在这里，我们正在加载并填写登录表单，但这次我们提供了错误的密码。单击**登录**按钮后，服务器应返回`403 状态码`，这将触发传递给我们回调函数的错误。然后，我们需要通过检查`browser.statusCode`属性来检查返回状态码，确保它是预期的 403 禁止代码。然后，我们还要验证用户是否没有被重定向到`/todo` URL，并且响应文档是否包含一个警报消息，说`无效密码`。

# 测试待办事项列表

现在我们已经完成了用户注册和会话启动，我们准备测试我们的应用程序的核心，即管理待办事项。我们将首先将应用程序测试的这一部分分离到一个自己的文件中，即`test/todos.js`，它可能以以下样板开始：

```js
var assert   = require('assert'),
    Browser  = require('zombie'),
    app      = require('../app'),
    couchdb  = require('../lib/couchdb'),
    dbName   = 'todos',
    db       = couchdb.use(dbName),
    fixtures = require('./fixtures'),
    login    = require('./login');

describe('Todos', function() {

  before(function(done) {
    app.start(3000, done);
  });

  after(function(done) {
    app.server.close(done);
  });

  beforeEach(function(done) {
    db.get(fixtures.user.email, function(err, doc) {
      if (err && err.status_code === 404) return done();
      if (err) throw err;
      db.destroy(doc._id, doc._rev, done);
    });
  });
});
```

在这里，我们有其他模块的类似样板代码，不同之处在于现在我们处理的是名为`todos`而不是`users`的数据库。另一个不同之处是我们希望每次测试都从一个干净的待办事项列表开始，因此我们添加了一个`beforeEach`钩子，用于删除测试用户的所有待办事项。

我们现在准备开始制定一些测试，但至少有一个繁琐的重复任务可以在早期避免：登录。我们应该假设每个测试都可以单独重现，并且测试的顺序并不重要——每个测试应该依赖于一个浏览器实例，模拟每个测试一个独立的用户会话。此外，由于所有待办事项操作都限定在用户和用户会话中必须初始化，我们需要将其抽象成自己的模块，放在`test/login.js`中：

```js
var Browser = require('zombie'),
    fixtures = require('./fixtures'),
    assert = require('assert'),
    couchdb = require('../lib/couchdb'),
    dbName  = 'users',
    db      = couchdb.use(dbName);

function ensureUserExists(next) {
  db.get(fixtures.user.email, function(err, user) {
    if (err && err.status_code === 404) {
      db.insert(fixtures.user, fixtures.user.email, next);
    }
    if (err) throw err;
    next();
  });
}

module.exports = function(next) {
  return function(done) {

    ensureUserExists(function(err) {
      if (err) throw err;
      Browser.visit("http://localhost:3000/session/new",
        function(err, browser) {
          if (err) throw err;

          browser
            .fill('E-mail', fixtures.user.email)
            .fill('Password', fixtures.user.password)
            .pressButton('Log In', function(err) {
              if (err) throw err;
              assert.equal(browser.location.pathname, '/todos');
              next(browser, done);
            });

        });
    });
  };
};
```

该模块确保在加载、填写和提交用户登录表单之前存在一个测试用户。之后，它将控制权交给`next`函数。

## 测试待办事项列表页面

现在我们准备在`todos`范围内添加更多的描述范围。其中一个范围是待办事项列表，其中将包含以下代码：

```js
  describe('Todo list', function() {

    it('should have core elements', login(function(browser, done) {
      assert.equal(browser.text('h1'), 'Your To-Dos');
      assert(browser.query('a[href="/todos/new"]'),
        'should have a link to create a new Todo');
      assert.equal(browser.text('a[href="/todos/new"]'), 'New To-Do');
      done();
    }));

    it('should start with an empty list', login(function(browser, done) {
      assert.equal(browser.queryAll('#todo-list tr').length, 0,
        'To-do list length should be 0');
      done();
    }));

    it('should not load when the user is not logged in', function(done) {
      Browser.visit('http://localhost:3000/todos', function(err, browser) {
        if (err) throw err;
        assert.equal(browser.location.pathname, '/session/new',
          'should be redirected to login screen');
        done();
      });
    });

  });
```

在这里，我们可以看到我们正在使用我们的`login`模块来抽象出会话初始化过程，确保我们的回调函数只有在用户登录后才会被调用。这里有三个测试。

在我们的第一个测试中，名为`应该具有核心元素`，我们只是加载空的待办事项列表，并断言我们已经放置了一些元素，例如包含`Your To-dos`文本的标题和创建新待办事项的链接。

在以下测试中，名为`应该以空列表开始`，我们只是测试待办事项列表是否包含零个元素。

在此范围的最后一个测试中，名为`当用户未登录时不应加载`，我们断言该列表对尚未初始化会话的用户是不可访问的，确保如果我们尝试加载`待办事项列表`URL，他会被重定向到`/session/new`。

## 测试待办事项创建

现在，我们需要测试待办事项是否真的可以创建。为此，请按照以下步骤进行：

1.  我们需要一个新的描述范围，我们将其命名为`待办事项创建表单`，这将是`Todos`的另一个子范围：

```js
  describe('Todo creation form', function() {
```

1.  现在我们可以测试一下，看看未登录的用户是否可以使用待办事项创建表单：

```js
    it('should not load when the user is not logged in', function(done) {
      Browser.visit('http://localhost:3000/todos/new', function(err, browser) {
        if (err) throw err;
        assert.equal(browser.location.pathname, '/session/new',
          'should be redirected to login screen');
        done();
      });
    });
```

在这里，我们正在验证，如果尝试在未登录的情况下加载待办事项创建表单，用户是否会被重定向到登录界面。

1.  如果用户已登录，我们将检查页面是否加载了一些预期的元素，例如标题和用于创建新待办事项的表单元素：

```js
    it('should load with title and form', login(function(browser, done) {
      browser.visit('http://localhost:3000/todos/new', function(err) {
        if (err) throw err;
        assert.equal(browser.text('h1'), 'New To-Do');

        var form = browser.query('form');
        assert(form, 'should have a form');
        assert.equal(form.method, 'POST', 'form should use post');
        assert.equal(form.action, '/todos', 'form should post to /todos');

        assert(browser.query('textarea[name=what]', form),
          'should have a what textarea input');
        assert(browser.query('input[type=submit]', form),
          'should have an input submit type');

        done();
      });
    }));
```

在这里，我们正在验证表单是否存在，它是否具有必要的属性来向`/todos` URL 发出`POST`请求，以及表单是否具有文本区输入和按钮。

1.  现在，我们还可以测试是否可以通过填写相应的表单并提交来成功创建待办事项：

```js
    it('should allow to create a todo', login(function(browser, done) {
      browser.visit('http://localhost:3000/todos/new', function(err) {
        if (err) throw err;

        browser
          .fill('What', 'Laundry')
          .pressButton('Create', function(err) {
            if (err) throw err;

            assert.equal(browser.location.pathname, '/todos',
              'should be redirected to /todos after creation');

            var list = browser.queryAll('#todo-list tr.todo');
            assert.equal(list.length, 1, 'To-do list length should be 1');
            var todo = list[0];
            assert.equal(browser.text('td.pos', todo), 1);
            assert.equal(browser.text('td.what', todo), 'Laundry');

            done();

          });
      });
    }));
```

在这里，我们最终要测试表单是否允许我们发布新项目，以及项目是否已创建。我们通过加载和填写待办事项创建表单来进行测试；验证我们已被重定向到待办事项列表页面；以及该页面是否包含我们刚刚创建的单个待办事项。

## 测试待办事项删除

现在我们已经测试了待办事项的插入，我们可以测试是否可以从列表中删除这些项目。我们将把这些测试放在一个名为`待办事项删除表单`的描述范围内，在其中我们将测试两件事：当只有一个待办事项存在时删除一个待办事项，以及当存在多个待办事项时删除一个待办事项。

### 注意

我们将这两个测试分开进行，因为先理解单个项目的测试，然后再进行更复杂的测试，以及分开测试我们是否在编程中常见的一次性错误。

以下是从一个项目列表中删除的代码：

```js
describe('Todo removal form', function() {

  describe('When one todo item exists', function() {

 beforeEach(function(done) {
 // insert one todo item
 db.insert(fixtures.todo, fixtures.user.email, done);
 });

    it("should allow you to remove", login(function(browser, done) {

      browser.visit('http://localhost:3000/todos', function(err, browser) {
        if (err) throw err;

        assert.equal(browser.queryAll('#todo-list tr.todo').length, 1);

        browser.pressButton('#todo-list tr.todo .remove form input[type=submit]',
          function(err) {
            if (err) throw err;
            assert.equal(browser.location.pathname, '/todos');
            // assert that all todos have been removed
            assert.equal(browser.queryAll('#todo-list tr').length, 0);
            done();
          }
        );

      });
    }));

  });
```

在运行测试之前，有一个`beforeEach`钩子，它会在测试用户的`todo`数据库中插入一个待办事项。这只是从`fixtures.todo`中取出的一个待办事项，这是我们需要添加到`test/fixtures.json`文件的属性：

```js
{
  "user" : {
    "email": "me@email.com",
    "password": "mypassword"
  },
 "todo": {
 "todos": [
 {
 "what": "Do the laundry",
 "created_at": 1346542066308
 }
 ]
 },
  "todos": {
    "todos": [
      {
        "what": "Do the laundry",
        "created_at": 1346542066308
      },
      {
        "what": "Call mom",
        "created_at": 1346542066308
      },
      {
        "what": "Go to gym",
        "created_at": 1346542066308
      }

    ]
  }

}
```

您可能会注意到，我们在这里利用机会添加一些额外的固定装置，这将有助于未来的测试。

继续分析测试代码，我们看到测试获取待办事项列表，然后验证待办事项的数量实际上是一个：

```js
assert.equal(browser.queryAll('#todo-list tr.todo').length, 1);
```

然后它继续尝试按下那个待办事项的移除按钮：

```js
browser.pressButton('#todo-list tr.todo .remove form input[type=submit]', …
```

选择器假设表格上有一个待办事项，我们之前已经验证过了。

### 注意

如果浏览器无法从给定的 CSS 选择器中找到按钮或提交元素，它将抛出错误，结束当前测试。

然后，在按下按钮并提交移除表单后，我们验证没有发生错误，浏览器被重定向回`/todos` URL，并且现在呈现的列表为空：

```js
assert.equal(browser.queryAll('#todo-list tr').length, 0);
```

现在我们已经测试了从一个一项列表中移除一项的工作情况，让我们创建一个更进化的测试，断言我们可以从三项列表中移除特定的项目：

```js
describe('When more than one todo item exists', function() {

  beforeEach(function(done) {
    // insert one todo item
    db.insert(fixtures.todos, fixtures.user.email, done);
  });

  it("should allow you to remove one todo item", login(
    function(browser, done) {

      browser.visit('http://localhost:3000/todos', function(err, browser) {
        if (err) throw err;

        var expectedList = [
          fixtures.todos.todos[0],
          fixtures.todos.todos[1],
          fixtures.todos.todos[2]
        ];

        var list = browser.queryAll('#todo-list tr');
        assert.equal(list.length, 3);

        list.forEach(function(todoRow, index) {
          assert.equal(browser.text('.pos', todoRow), index + 1);
          assert.equal(browser.text('.what', todoRow),
            expectedList[index].what);
        });

            browser.pressButton(
              '#todo-list tr:nth-child(2) .remove input[type=submit]',
              function(err) {
                if (err) throw err;

                assert.equal(browser.location.pathname, '/todos');

                // assert that the middle todo item has been removed
                var list = browser.queryAll('#todo-list tr');
                assert.equal(list.length, 2);

                // remove the middle element from the expected list
                expectedList.splice(1,1);

                // test that the rendered list is the expected list
                list.forEach(function(todoRow, index) {
                  assert.equal(browser.text('.pos', todoRow), index + 1);
                  assert.equal(browser.text('.what', todoRow),
                    expectedList[index].what);
                });

                done();
              }
            );

      });
    }
  ));

});
```

这个描述范围将与先前的描述范围处于同一级别，还会在`todo`数据库中插入一个文档，但这次文档包含了一个包含三个待办事项的列表，取自`fixtures.todos`属性（而不是先前使用的单数`fixtures.todo`属性）。

测试从访问`todo`列表页面开始，并构建预期待办事项列表，存储在名为`expectedList`的变量中。然后我们检索在 HTML 文档中找到的所有待办事项，并验证内容是否符合预期：

```js
list.forEach(function(todoRow, index) {
  assert.equal(browser.text('.pos', todoRow), index + 1);
  assert.equal(browser.text('.what', todoRow),
    expectedList[index].what);
});
```

一旦我们验证了所有预期的待办事项都已经就位并且顺序正确，我们继续通过以下代码点击列表中第二个项目的按钮：

```js
browser.pressButton(
  '#todo-list tr:nth-child(2) .remove input[type=submit]', ...
```

在这里，我们使用特殊的 CSS 选择器`nth-child`来选择第二个待办事项的行，然后获取其中用于移除提交按钮的代码，并最终按下它。

一旦按钮被按下，表单就会被提交，浏览器会回调，我们验证没有错误，我们被重定向回`/todos` URL，并且它包含了预期的列表。我们通过从先前使用的`expectedList`数组中移除第二个元素来做到这一点，并验证这正是当前页面显示的内容：

```js
var list = browser.queryAll('#todo-list tr');
assert.equal(list.length, 2);
expectedList.splice(1,1);

// test that the rendered list is the expected list
list.forEach(function(todoRow, index) {
  assert.equal(browser.text('.pos', todoRow), index + 1);
  assert.equal(browser.text('.what', todoRow),
    expectedList[index].what);
});
```

# 把所有东西放在一起

您可以手动逐个运行测试，但应该能够一次运行它们全部。为此，您只需要从 shell 命令行中调用：

```js
$ ./node_modules/.bin/mocha test/users.js test/session.js test/todos.js
```

现在我们需要更改`package.json`，以便您可以告诉**node package** **manager** (**npm**)如何运行测试：

```js
{
  "description": "To-do App",
  "version": "0.0.0",
  "private": true,
  "dependencies": {
    "union": "0.3.0",
    "flatiron": "0.2.8",
    "plates": "0.4.x",
    "node-static": "0.6.0",
    "nano": "3.3.0",
    "flatware-cookie-parser": "0.1.x",
    "flatware-session": "0.1.x"
  },
  "devDependencies": {
    "mocha": "1.4.x",
    "zombie": "1.4.x"
  },
  "scripts": {
    "test": "mocha test/users.js test/session.js test/todos.js",
    "start": "node app.js"
  },
  "name": "todo",
  "author": "Pedro",
  "homepage": ""
}
```

现在您可以使用以下命令运行您的测试：

```js
$ npm test
  .............

  ✔ 13 tests complete (3758ms)
```

# 摘要

Zombie.js 允许我们访问 URL，加载 HTML 文档，并使用 CSS 选择器检索 HTML 元素。它还允许我们轻松填写表单并提交它们，点击按钮并跟随链接，验证返回状态代码，并使用简洁方便的 API 以相同的方式分析响应文档。


# 第六章：测试交互

到目前为止，我们已经测试了在表单上填写文本字段，但还有其他更复杂的输入字段，您可以指示 Zombie 浏览器填写。

例如，您可能想要选择单选按钮元素，或从下拉列表框中选择一个项目，或者您可能想要从日期输入字段中选择特定日期。

与表单字段和其他元素交互时，您的应用程序可能会操纵文档，例如显示或隐藏某些元素。在本章结束时，您将了解如何使用 Zombie.js 验证使用 JavaScript 操纵文档的效果。

本章涵盖的主题有：

+   如何触发其他表单对象的更改

+   如何测试 DOM 操作

# 操作单选按钮

要测试单选按钮的使用，我们需要在应用程序的表单中添加一些单选按钮。我们将在待办事项创建表单中引入一个单选按钮，以指示是否应该安排闹钟。根据所选值，应该出现一个字段，允许我们设置待办事项的闹钟日期和时间。

1.  首先，我们需要更改`templates/todos/new.html`中的待办事项创建模板：

```js
<h1>New To-Do</h1>
<form id="new-todo-form" action="/todos" method="POST">

  <p>
    <label for="what">What</label>
    <textarea name="what" id="what" required></textarea>
  </p>

  <p>

    <label class="radio" for="alarm-false">
      <input type="radio" name="alarm" value="false" id="alarm-false" checked="checked" /> No Alarm
    </label>

    <label class="radio" for="alarm-true">
      <input type="radio" name="alarm" value="true" id="alarm-true" /> Use Alarm
    </label>

  </p>

  <div id="alarm-date-time" style="display:none">
    <label class="date" for="alarm-date">
      <input type="text" name="alarm-date" id="alarm-date" /> Date (YYYY/MM/DD)
    </label>
    <label class="time" for="alarm-time">
      <input type="text" name="alarm-time" id="alarm-time" /> Time (hh:mm)
    </label>
  </div>

  <input type="submit" value="Create" />
</form>
```

1.  这将向用户呈现待办事项创建表单中的一对新单选按钮：![操作单选按钮](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-ui-test/img/0526OS_06_01.jpg)

1.  现在我们还需要引入一些样式。在`public/css/todo.css`下创建一个自定义样式表：

```js
#alarm-date-time {
  position: relative;
  margin: 15px 0;
  padding: 39px 19px 14px;
  border: 1px solid #DDD;
  -webkit-border-radius: 4px;
  -moz-border-radius: 4px;
  border-radius: 4px;
  width: auto;
}

#alarm-date-time::after {
  content: "Alarm Date and time";
  position: absolute;
  top: -1px;
  left: -1px;
  padding: 3px 7px;
  font-size: 12px;
  font-weight: bold;
  background-color: whiteSmoke;
  border: 1px solid #DDD;
  color: #9DA0A4;
  -webkit-border-radius: 4px 0 4px 0;
  -moz-border-radius: 4px 0 4px 0;
  border-radius: 4px 0 4px 0;
}
```

1.  我们需要在`templates/layout.html`中的布局文件中引用以前的 CSS 文件：

```js
<html>
  <head>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
    <title id="title"></title>
    <link href="/css/bootstrap.min.css" rel="stylesheet" >
 <link href="/css/todo.css" rel="stylesheet" >
  </head>
  <body>

    <section role="main" class="container">

      <div id="messages"></div>

      <div id="main-body"></div>

    </section>

    <script src="img/jquery.min.js"></script> 
    <script src="img/jquery-ui-1.8.23.custom.min.js"></script> 
    <script src="img/bootstrap.min.js"></script>
    <script src="img/todos.js"></script>
  </body>
</html>
```

1.  接下来，当用户选择**闹钟**单选按钮时，我们需要使日期和时间表单字段出现。为此，我们需要在`public/js/todos.js`文件中引入一个事件监听器：

```js
$(function() {
  $('#todo-list').sortable({
    update: function() {
      var order = [];
      $('.todo').each(function(idx, row) {
        order.push($(row).find('.pos').text());
      });

      $.post('/todos/sort', {order: order.join(',')}, function() {
        $('.todo').each(function(idx, row) {
          $(row).find('.pos').text(idx + 1);
        });
      });

    }
  });

 function hideOrShowDateTime() {
 var ringAlarm = $('input[name=alarm]:checked',
 '#new-todo-form').val() === 'true';

 if (ringAlarm) {
 $('#alarm-date-time').slideDown();
 } else {
 $('#alarm-date-time').slideUp();
 }
 }

 $('#new-todo-form input[name=alarm]').change(hideOrShowDateTime);
 hideOrShowDateTime();

});
```

这个新的事件监听器将监听单选按钮的更改，然后相应地隐藏或显示闹钟日期和时间字段，当“闹钟”设置打开时，结果如下：

![操作单选按钮](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-ui-test/img/0526OS_06_02.jpg)

1.  我们还需要更改表单提交的路由监听器，以适应这些新字段：

```js
this.post('/', [loggedIn, function() {

  var req  = this.req,
      res  = this.res,
      todo = this.req.body
  ;

  if (! todo.what) {
    res.writeHead(200, {'Content-Type': 'text/html'});
    return res.end(layout(templates['new'], 'New To-Do',
      {error: 'Please fill in the To-Do description'}));
  }

 todo.alarm = todo.alarm === 'true';
 todo.alarm_date = Date.parse(todo['alarm-date'] + ' ' + todo['alarm-time']);
 delete todo['alarm-date'];
 delete todo['alarm-time'];

  todo.created_at = Date.now();

  insert(req.session.user.email, todo, function(err) {

    if (err) {
      res.writeHead(500);
      return res.end(err.stack);
    }

    res.writeHead(303, {Location: '/todos'});
    res.end();
  });

}]);
```

这段新代码处理了表单字段中提交的闹钟日期和闹钟时间，并将它们解析为时间戳。然后，包含在`todo`变量中的待办事项被转换为一个看起来像这样的文档：

```js
{ what: 'Deliver books to library',
  alarm: true,
  alarm_date: 1351608900000,
  created_at: 1350915191244 }
```

# 测试用户交互

为了测试这些新的表单字段及其组合行为，我们将使用`test/todos.js`中的测试文件，并增加`Todo creation form`范围：

1.  首先，我们测试这些单选按钮是否存在，并且默认情况下闹钟是否关闭：

```js
it('should not present the alarm date form fields when no alarm is selected',
  login(function(browser, done) {
     browser.visit('http://localhost:3000/todos/new', function(err) {
       if (err) throw err;

       browser.choose('No Alarm', function(err) {
         if (err) throw err;

         assert.equal(browser.query('#alarm-date-time').style.display, 'none');
         done();
       });
     });
  })
);
```

在这里，我们正在验证“闹钟”字段实际上有两个单选按钮，一个具有`false`值，另一个具有`true`值。然后我们还验证第一个是否被选中。

1.  我们还需要验证新的日期和时间表单字段的动画是否有效；包裹闹钟日期和时间输入字段的`div`元素在用户选择不使用闹钟时应该隐藏。当用户选择“使用闹钟”单选按钮时，`div`元素应该变为可见：

```js
it('should present the alarm date form fields when alarm', 
  login(function(browser, done) {
    browser.visit('http://localhost:3000/todos/new', function(err) {
      if (err) throw err;

      var container = browser.query('#alarm-date-time');

      browser.choose('No Alarm', function(err) {
        if (err) throw err;

        assert.equal(container.style.display, 'none');

        browser.choose('Use Alarm', function(err) {
          if (err) throw err;

          assert.equal(container.style.display, '');

          browser.choose('No Alarm', function(err) {
            if (err) throw err;

            assert.equal(container.style.display, 'none');

            done();
          });
        });
      });
    });
  })
);
```

在这里，我们打开和关闭使用闹钟设置，并验证容器`div`的样式相应更改。在 Zombie 中，所有用户交互函数（如`browser.choose()`，`browser.fill()`等）都允许您将回调函数作为最后一个参数传递。一旦浏览器事件循环空闲，将调用此函数，这意味着只有在任何动画之后才会调用您的函数。这真的很有用，因为您的测试代码不必显式等待动画完成。您可以确保在调用回调函数后 DOM 被操作。

### 注意

使用这种技术，您还可以测试任何用户交互。通过提供一个回调函数，当 Zombie 完成所有操作时调用该函数，您可以测试这些操作对文档的影响。

在我们的案例中，我们测试了成功更改`div`元素的样式属性，但您也可以使用这种技术测试其他交互。例如，正如我们将在下一章中看到的那样，我们可以测试内容是否根据某些用户操作而改变。

# 选择值

如果表单中有选择框，您还可以指示 Zombie 为您选择列表项。让我们更改我们的待办事项创建表单，以包括描述项目范围的额外选择框 - 项目是否与工作、家庭有关，或者是否是个人任务。

首先，我们需要在`templates/todos/new.html`中的待办事项创建表单中引入这个额外的字段，就在`What`文本区域字段之后：

```js
  <label for="scope">
    Scope
    <select name="scope" id="scope">
      <option value="" selected="selected">Please select</option>
      <option value="work">Work</option>
      <option value="personal">Personal</option>
      <option value="family">Family</option>
    </select>
  </label>
```

这将呈现包含额外的**Scope**标签和选择框的以下表单：

![选择值](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-ui-test/img/0526OS_06_03.jpg)

现在我们需要有一个测试来验证该表单是否包含`select`元素和`option`项。为此，让我们继续扩展`test/todos.js`文件，在`Todo creation form`描述范围内：

```js
it('should present the scope select box',
  login(function(browser, done) {
    browser.visit('http://localhost:3000/todos/new', function(err) {
      if (err) throw err;

      var select = browser.queryAll('form select[name=scope]');
      assert.equal(select.length, 1);

      var options = browser.queryAll('form select[name=scope] option');
      assert.equal(options.length, 4);

      options = options.map(function(option) {
        return [option.value, option.textContent];
      });

      var expectedOptions = [
        [null, 'Please select'],
        ['work', 'Work'],
        ['personal', 'Personal'],
        ['family', 'Family']
      ];

      assert.deepEqual(options, expectedOptions);

      done();

    });
  })
);
```

在这里，我们正在测试`select`元素是否存在，它是否有四个`option`项，以及每个项是否具有预期的值和文本。

现在我们需要更改待办事项列表以呈现这个新的范围字段。为此，我们需要在`templates/todos/index.html`文件中引入它：

```js
<h1>Your To-Dos</h1>

<a class="btn" href="/todos/new">New To-Do</a>

<table class="table">
  <thead>
    <tr>
      <th>#</th>
      <th>What</th>
 <th>Scope</th>
      <th></th>
    </tr>
  </thead>
  <tbody id="todo-list">
    <tr class="todo">
      <td class="pos"></td>
      <td class="what"></td>
 <td class="scope"></td>
      <td class="remove">
        <form action="/todos/delete" method="POST">
          <input type="hidden" name="pos" value="" />
          <input type="submit" name="Delete" value="Delete" />
        </form>
      </td>
    </tr>
  </tbody>
</table>
```

当在`routes/todos.js`文件的`GET /`路由监听器中呈现待办事项列表时，我们还需要填写值：

```js
this.get('/', [loggedIn, function() {

  var res = this.res;

  db.get(this.req.session.user.email, function(err, todos) {

    if (err && err.status_code !== 404) {
      res.writeHead(500);
      return res.end(err.stack);
    }

    if (! todos) todos = {todos: []};
    todos = todos.todos;

    todos.forEach(function(todo, idx) {
      if (todo) todo.pos = idx + 1;
    });

    var map = Plates.Map();
    map.className('todo').to('todo');
    map.className('pos').to('pos');
    map.className('what').to('what');
 map.className('scope').to('scope');
    map.where('name').is('pos').use('pos').as('value');

    var main = Plates.bind(templates.index, {todo: todos}, map);
    res.writeHead(200, {'Content-Type': 'text/html'});
    res.end(layout(main, 'To-Dos'));

  });
```

这将导致待办事项列表如下截图所示，其中呈现了每个待办事项的`scope`属性：

![选择值](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-ui-test/img/0526OS_06_04.jpg)

现在我们需要测试待办事项创建是否成功捕获了范围值。为此，我们将稍微更改名为`should allow to create a todo`的测试：

```js
it('should allow to create a todo', login(function(browser, done) {
  browser.visit('http://localhost:3000/todos/new', function(err) {
    if (err) throw err;

    browser
      .fill('What', 'Laundry')
 .select('scope', 'Personal')
      .pressButton('Create', function(err) {
        if (err) throw err;

        assert.equal(browser.location.pathname, '/todos',
          'should be redirected to /todos after creation');

        var list = browser.queryAll('#todo-list tr.todo');
        assert.equal(list.length, 1, 'To-do list length should be 1');
        var todo = list[0];
        assert.equal(browser.text('td.pos', todo), 1);
        assert.equal(browser.text('td.what', todo), 'Laundry');
 assert.equal(browser.text('td.scope', todo), 'personal');

        done();

      });
  });
}));
```

# 总结

Zombie 允许您操纵任何表单对象，包括文本字段、文本区域、选择框、复选框和单选按钮。

Zombie 不仅允许测试服务器响应，还允许模拟用户交互。如果您的应用程序在触发用户事件时动态更改文档（例如选择选项或单击元素），您可以使用 Zombie 和浏览器查询来验证行为是否符合预期。

即使存在用户触发的动画（例如淡入），Zombie 也不会在这些动画完成之前调用回调函数。

在下一章中，我们将分析如何使用 Zombie.js 来测试执行 AJAX 调用的用户交互。


# 第七章：调试

本章介绍了如何使用浏览器对象来检查应用程序的一些内部状态。

本章涵盖的主题包括：

+   启用调试输出

+   转储浏览器状态

默认情况下，Zombie 不会将内部事件输出到控制台，但您可以将 Zombie 运行时的`DEBUG`环境变量设置为`true`。如果您使用 UNIX shell 命令行，可以在启动测试套件时添加`DEBUG=true`，如下所示：

```js
$ DEBUG=true node_modules/.bin/mocha test/todos
```

如果您使用 Windows，可以按照以下方式设置和取消设置`DEBUG`环境变量：

```js
$ SET DEBUG=true
$ SET DEBUG=
```

通过启用此环境变量，Zombie 将输出其进行的每个 HTTP 请求，以及收到的 HTTP 状态代码：

```js
…
Zombie: GET http://localhost:3000/js/todos.js => 200
Zombie: 303 => http://localhost:3000/todos
Zombie: GET http://localhost:3000/todos => 200
Zombie: GET http://localhost:3000/js/jquery-1.8.2.js => 200
Zombie: GET http://localhost:3000/js/jquery-ui.js => 200
Zombie: GET http://localhost:3000/js/todos.js => 200
Zombie: GET http://localhost:3000/js/bootstrap.min.js => 200
…
```

### 注意

正如您所看到的，Zombie 还报告了所有`3xx-class`的 HTTP 重定向以及新的 URL 是什么。

这种输出可能有助于调试一些 URL 加载问题，但很难追踪特定 HTTP 请求所指的测试。

幸运的是，可以通过更改 Mocha 报告器来为测试输出带来一些澄清。Mocha 带有一种称为报告器的功能。到目前为止，我们使用的是默认报告器，它为每个测试报告一个有颜色的点。但是，如果您指定`spec`报告器，Mocha 会在测试开始之前和测试结束之后输出测试名称。

要启用`spec`报告器，只需将`-R spec`添加到 Mocha 参数中，如下所示：

```js
$ DEBUG=true node_modules/.bin/mocha -R spec test/todos
```

这样，您将获得类似以下的输出：

```js
...
      . should start with an empty list: Zombie: GET http://localhost:3000/session/new => 200
Zombie: GET http://localhost:3000/js/jquery-1.8.2.js => 200
Zombie: GET http://localhost:3000/js/jquery-ui.js => 200
Zombie: GET http://localhost:3000/js/bootstrap.min.js => 200
Zombie: GET http://localhost:3000/js/todos.js => 200
Zombie: 302 => http://localhost:3000/todos
Zombie: GET http://localhost:3000/todos => 200
Zombie: GET http://localhost:3000/js/jquery-1.8.2.js => 200
Zombie: GET http://localhost:3000/js/jquery-ui.js => 200
Zombie: GET http://localhost:3000/js/todos.js => 200
Zombie: GET http://localhost:3000/js/bootstrap.min.js => 200
      ✓ should start with an empty list (378ms)
      . should not load when the user is not logged in: Zombie: 303 => http://localhost:3000/session/new
Zombie: GET http://localhost:3000/session/new => 200
Zombie: GET http://localhost:3000/js/jquery-1.8.2.js => 200
Zombie: GET http://localhost:3000/js/jquery-ui.js => 200
Zombie: GET http://localhost:3000/js/bootstrap.min.js => 200
Zombie: GET http://localhost:3000/js/todos.js => 200
      ✓ should not load when the user is not logged in (179ms)
...
```

这不仅告诉您给定测试对应的资源加载情况，还告诉您运行该测试所花费的时间。

# 运行特定测试

如果您遇到特定测试的问题，您无需运行整个测试套件甚至整个测试文件。Mocha 接受`-g <expression>`命令行选项，并且只运行与该表达式匹配的测试。

例如，您可以仅运行描述中包含`remove`一词的测试，如下所示：

```js
$ DEBUG=true node_modules/.bin/mocha -R spec -g 'remove' test/todos

  Todos
    Todo removal form
      When one todo item exists
        ◦ should allow you to remove: Zombie: GET http://localhost:3000/session/new => 200
...
        ✓ should allow you to remove (959ms)
      When more than one todo item exists
        ◦ should allow you to remove one todo item: Zombie: GET http://localhost:3000/session/new => 200
...
        ✓ should allow you to remove one todo item (683ms)

  ✔ 2 tests complete (1780ms)
```

这样，您将只运行这些特定测试。

## 启用每个测试的调试输出

将`DEBUG`环境变量设置为`true`可启用所有测试的调试输出，但您也可以通过将`browser.debug`设置为`true`来指定要调试的测试。例如，更改`test/todos.js`文件，大约在第 204 行添加以下内容：

```js
...
      it("should allow you to remove", login(function(browser, done) {
 browser.debug = true;

      browser.visit('http://localhost:3000/todos', function(err, browser) {
...
```

这样，当运行以下测试时，您无需指定`DEBUG`环境变量：

```js
$ node_modules/.bin/mocha -R spec -g 'remove' test/todos

  Todos
    Todo removal form
      When one todo item exists
        . should allow you to remove: Zombie: GET http://localhost:3000/todos => 200
Zombie: GET http://localhost:3000/js/jquery.min.js => 200
Zombie: GET http://localhost:3000/js/jquery-ui-1.8.23.custom.min.js => 200
Zombie: GET http://localhost:3000/js/bootstrap.min.js => 200
Zombie: GET http://localhost:3000/js/todos.js => 200
Zombie: 303 => http://localhost:3000/todos
Zombie: GET http://localhost:3000/todos => 200
Zombie: GET http://localhost:3000/js/jquery.min.js => 200
Zombie: GET http://localhost:3000/js/jquery-ui-1.8.23.custom.min.js => 200
Zombie: GET http://localhost:3000/js/bootstrap.min.js => 200
Zombie: GET http://localhost:3000/js/todos.js => 200
        ✓ should allow you to remove (1191ms)
      When more than one todo item exists
        ✓ should allow you to remove one todo item (926ms)

  ✔ 2 tests complete (2308ms)
```

在这里，您可以看到，正如预期的那样，Zombie 仅为名为`should allow you to remove`的测试输出调试信息。

# 使用浏览器 JavaScript 控制台

除了浏览器发出的 HTTP 请求之外，Zombie 不会输出其他可能有趣或有用的内容，以便您调试应用程序。

一个很好的选择，提供了更多的灵活性和洞察力，是在真实浏览器中运行应用程序，并使用开发者工具和/或调试器。

在特定于 Zombie.js 的问题调试中，一个特别有用的替代方法是在浏览器代码中使用`console.log()`函数（在本应用程序的情况下，该代码位于`public/js`目录中）。

例如，假设您在处理待办事项创建表单时遇到问题：警报选项未正确触发警报选项窗格的显示和隐藏。为此，我们可以在`public/js/todos.js`文件中引入以下`console.log`语句，以检查`ringAlarm`变量的值：`hideOrShowDateTime()`函数。

```js
  {
    var ringAlarm = $('input[name=alarm]:checked',
      '#new-todo-form').val() === 'true';

 console.log('\ntriggered hide or show. ringAlarm is ', ringAlarm);

    if (ringAlarm) {
      $('#alarm-date-time').slideDown();
    } else {
      $('#alarm-date-time').slideUp();
    }
  }
```

这样，当您运行测试时，您将获得以下输出：

```js
$ node_modules/.bin/mocha -R spec -g 'alarm' test/todos

  Todos
    Todo creation form
      . should have an alarm option: 
triggered hide or show. ringAlarm is  false

triggered hide or show. ringAlarm is  false

triggered hide or show. ringAlarm is  false
      ✓ should have an alarm option (625ms)
      . should present the alarm date form fields when alarm: 
triggered hide or show. ringAlarm is  false

triggered hide or show. ringAlarm is  false

triggered hide or show. ringAlarm is  false

triggered hide or show. ringAlarm is  false

triggered hide or show. ringAlarm is  true

triggered hide or show. ringAlarm is  true

triggered hide or show. ringAlarm is  false

triggered hide or show. ringAlarm is  false
      ✓ should present the alarm date form fields when alarm (1641ms)

  ✔ 2 tests complete (2393ms)
```

使用这种技术，您可以在运行测试时检查应用程序的状态。

# 转储浏览器状态

您还可以通过在测试代码中调用`browser.dump()`函数来检查浏览器状态。

1.  例如，您可能想在`test/todos.js`文件中的`should present the alarm date form fields when alarm`测试中了解完整的浏览器状态。为此，在我们选择“无警报”选项后立即引入`browser.dump()`调用：

```js
...
    it('should present the alarm date form fields when alarm', 
      login(function(browser, done) {
        browser.visit('http://localhost:3000/todos/new', function(err) {
          if (err) throw err;

          var container = browser.query('#alarm-date-time');

          browser.choose('No Alarm', function(err) {
            if (err) throw err;

            assert.equal(container.style.display, 'none');

            browser.choose('Use Alarm', function(err) {
              if (err) throw err;

              assert.equal(container.style.display, '');

              browser.choose('No Alarm', function(err) {
                if (err) throw err;

 browser.dump();

                assert.equal(container.style.display, 'none');

                done();
              });
            });
          });
        });
      })
    );
...
```

1.  在文件中进行更改并运行此测试：

```js
$ node_modules/.bin/mocha -R spec -g 'alarm' test/todos

  Todos
    Todo creation form
      ✓ should have an alarm option (659ms)
      ◦ should present the alarm date form fields when alarm: Zombie: 1.4.1

URL: http://localhost:3000/todos/new
History:
  1\. http://localhost:3000/session/new
  2\. http://localhost:3000/todos
  3: http://localhost:3000/todos/new

sid=AIUjSvUl79S8Qz4Q8foRRAS7; Domain=localhost; Path=/
Cookies:
  true

Storage:

Eventloop:
  The time:   Mon Feb 18 2013 10:59:43 GMT+0000 (WET)
  Timers:     0
  Processing: 0
  Waiting:    0

Document:
  <html>
    <head>    <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
      <title id="title">New To-Do</title>
      <link href="/css/bootstrap.min.css" rel="stylesheet" />
      <link href="/css/todo.css" rel="stylesheet" />
  </head>
    <body>    <section role="main" class="container">      <div id="messages"></div>
        <div id="main-body">
          <h1>New To-Do</h1>
          <form id="new-todo-form" action="/todos" method="POST">          <p>            <label for="what">What</...

      ✓ should present the alarm date form fields when alarm (1426ms)

  ✔ 2 tests complete (2236ms)

```

进行`browser.dump()`调用时，您将在输出中获得以下内容：

+   当前 URL

+   历史记录，即此浏览器实例在创建后访问的所有 URL

+   离线存储，如果您使用任何

+   事件循环状态：如果它正在等待任何处理或计时器

+   HTML 文档的第一行，这可能足以调试当前状态

# 转储整个文档

如果您需要随时检查文档的全部内容，可以检查`browser.html()`的返回值。例如，如果您想在重新加载浏览器之前检查文档的状态，可以在`test/todo.js`文件中添加以下行，而不是`browser.dump()`：

```js
...
            browser.choose('Use Alarm', function(err) {
              if (err) throw err;

              assert.equal(container.style.display, '');

              browser.choose('No Alarm', function(err) {
                if (err) throw err;

                console.log(browser.html());

                assert.equal(container.style.display, 'none');

                done();
              });
            });
...
```

现在您可以运行测试并观察输出：

```js
$ node_modules/.bin/mocha -g 'alarm' test/todos
...
  <html style=""><head>

...
```

# 摘要

您的浏览器开发人员工具更适合调试浏览器应用程序。但是，如果遇到特定于 Zombie 的问题，有几种技术可能会对您有所帮助。

一种是启用 Zombie 调试输出。这将显示浏览器正在加载的资源以及显示在旁边的相应响应状态代码。

您可以运行特定的测试。在调试测试中的特定问题时，还可以通过使用`-g <pattern>`选项来限制 Mocha 仅运行该测试。

您可以在浏览器中运行的代码中使用`console.log`命令；输出将显示在控制台中。

您可以查看当前的浏览器状态。您可以通过使用`browser.dump`调用或将`browser.html`的结果记录到控制台来检查浏览器状态。

如果您需要在测试的某个阶段访问整个文档，还可以记录`browser.html()`的返回值。


# 第八章：测试 AJAX

在本书中，我们已经测试了在表单上填写文本字段、点击按钮以及生成的 HTML 文档。这使我们准备好测试传统的基于表单的请求-响应应用程序，但典型的现代应用程序通常比这更复杂，因为它们使用异步 HTTP 请求，以某种方式更新文档而无需刷新它。这是因为它们使用了 AJAX。

当我们呈现待办事项列表页面时，我们的应用程序会发出 AJAX 请求；用户可以拖动一个项目并将其放在新位置。我们放在`public/js/todos.js`文件中的代码捕捉到变化，并调用服务器`/todos/sort` URL，改变数据库中的项目顺序。

让我们看看如何使用 Zombie 来测试这个拖放功能。本章涵盖的主题包括：

+   使用 Zombie 触发 AJAX 调用

+   使用 Zombie 来测试 AJAX 调用的结果

在本节结束时，您将知道如何使用 Zombie 来测试使用 AJAX 的应用程序。

# 实现拖放

让我们在`test/todos.js`文件中添加一些测试。

1.  我们首先在`Todo list`作用域结束之前添加一个新的描述作用域：

```js
describe('When there are some items on the list', function() {
```

这个新的作用域允许我们在运行此作用域内的任何测试之前在数据库中设置一个待办事项列表。

1.  现在，让我们在新的作用域内添加这个新的`beforeEach`钩子：

```js
beforeEach(function(done) {
  // insert todo items
  db.insert(fixtures.todos, fixtures.user.email, done);
});
```

1.  然后我们通过登录开始测试：

```js
it('should allow me to reorder items using drag and drop',
  login(function(browser, done) {
```

1.  我们通过确保我们的项目列表页面中有三个待办事项来开始测试：

```js
var items = browser.queryAll('#todo-list tr');
assert.equal(items.length, 3, 'Should have 3 items and has ' +
  items.length);
```

1.  然后我们声明一个辅助函数，将帮助我们验证列表的内容：

```js
function expectOrder(order) {
  var itemTexts = browser.queryAll('#todo-list tr .what').map(
    function(node) {
      return node.textContent.trim();
    }   assert.equal(index + 1, itemPos);
  });
}
```

这个函数获取一个字符串数组，并断言页面中每个待办事项的`what`和`pos`字段的顺序是否符合预期。

1.  然后我们使用这个新的`expectOrder`函数来实际测试顺序是否符合预期：

```js
expectOrder(['Do the laundry', 'Call mom', 'Go to gym']);
```

您可能还记得，在`test/fixtures.json`文件中声明的待办事项的顺序是在`beforeEach`钩子加载的。

1.  接下来我们创建另一个辅助函数，将帮助我们制造和注入鼠标事件：

```js
function mouseEvent(name, target, x, y) {
  var event = browser.document.createEvent('MouseEvents');
  event.initEvent(name, true, true);
  event.clientX = event.screenX = x;
  event.clientY = event.screenY = y;
  event.which = 1;
  browser.dispatchEvent(item, event);
}
```

这个函数模拟用户鼠标事件，设置了`x`和`y`坐标，设置了鼠标按钮（`event.which = 1`），并将事件分派到浏览器中，指定事件发生在哪个项目上。

1.  接下来我们选择要拖动的待办事项；在这种情况下，我们拖动第一个：

```js
var item = items[0];
```

1.  然后我们使用`mouseEvent`辅助函数来注入一系列制造的事件：

```js
mouseEvent('mousedown', item, 50, 50);
mouseEvent('mousemove', browser.document, 51, 51);
mouseEvent('mousemove', browser.document, 51, 150);
mouseEvent('mouseup',  browser.document, 51, 150);
```

这些事件有几个重要方面，即事件的顺序、目标元素和鼠标坐标。让我们来分析一下。

这些是组成拖放的事件。首先我们按下鼠标按钮，稍微移动一下，然后再移动一些，最后释放鼠标按钮。这里我们使用的鼠标事件位置的`x`和`y`值并不重要，重要的是它们之间的相对差异，以便检测到拖动并开始拖动模式。

在第一个事件中，`mousedown`，我们使用了一个任意的坐标`50, 50`。在第二个事件中，`mousemove`，我们将这个坐标增加了一个像素；这开始了拖动。

第二个`mousemove`事件在 y 轴上继续拖动。看起来多余和冗余，但它是必需的，以便拖动检测起作用，使我们执行的拖动移动连续。

最后，我们有`mouseup`，用户释放鼠标。这个事件使用了与前一个`mousemove`相同的坐标，表示用户在拖动后放下了元素。

现在让我们分析事件中的目标元素：

`mouseEvent()`助手函数的第二个参数是目标元素。在第一个`mousedown`事件注入中，我们将目标定位到`item`变量中的待办事项，该变量引用我们要拖动的项目。这表明了我们将要拖动的项目，一旦拖动模式被激活。其余的三个事件将目标定位到浏览器文档，因为用户将在整个文档中拖动待办事项。

我们正在使用的鼠标坐标的进一步澄清：

Zombie 不会渲染项目，因此它不知道每个项目的位置。这是我们可以使用的唯一方法来指示我们正在拖动的元素。在这种情况下，x 和 y 坐标与此无关。

由于 Zombie 不会渲染元素，它不会保留每个元素的位置。事实上，它们都被放置在(0, 0)处，这意味着我们的`mouseup`事件将拖动的项目放置在最后一个项目之后。

如前所述，初始值和拖动距离是完全任意的，您会发现改变这些值仍然可以使测试工作。

1.  在将这些鼠标事件注入浏览器事件队列后，我们使用`browser.wait()`函数等待这些事件被完全处理：

```js
browser.wait(function(err) {
            if (err) throw err;
```

在这个阶段，浏览器已经改变了元素顺序，并发出了一个 AJAX 请求，将新的顺序发送到服务器。

1.  现在我们验证待办事项是否按新顺序排列：

```js
expectOrder(['Call mom', 'Go to gym', 'Do the laundry']);
```

1.  我们还验证浏览器是否执行了我们预期的 HTTP 请求：

```js
var lastRequest = browser.lastRequest;
assert.equal(lastRequest.url, 'http://localhost:3000/todos/sort');
assert.equal(lastRequest.method, 'POST');
```

### 注意

请注意，我们正在使用`browser.lastRequest()`函数来访问浏览器发出的最后一个 AJAX 请求。

如果您需要访问浏览器发出的每个 HTTP 请求，可以检查`browser.resources`对象。

现在我们知道浏览器发出了一个`HTTP POST`请求，命令服务器对待办事项进行排序，我们需要确保数据库中的待办事项已经正确更新。为了验证这一点，我们做了类似于人工测试人员的操作；我们使用`browser.reload()`重新加载页面，并验证是否顺序确实是预期的：

```js
browser.reload(function(err) {
  if (err) throw err;

  expectOrder(['Call mom', 'Go to gym', 'Do the laundry']);

  done();

});
```

# 摘要

使用 Zombie，您可以注入自定义事件来模拟一些复杂的用户操作。您还可以通过使用`browser.lastRequest()`来检测浏览器执行 HTTP 请求的 URL 和方法。
